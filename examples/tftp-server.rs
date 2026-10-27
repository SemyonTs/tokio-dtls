//! Async TFTP-over-DTLS 1.3 server with a served directory and RFC 2347–2349
//! option negotiation (blksize, tsize, timeout).
//!
//! ```sh
//! cargo run --example tftp-server -- 127.0.0.1:6969 ./public
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_dtls::{ConfigOptions, DtlsConnection};

// ---------- Shared extension config ----------
const ALPN: &[u8] = b"tftp/1";
const SNI: &str = "tftp.local";
const CID: &[u8] = &[0x54, 0x46, 0x54, 0x50, 0x00, 0x01, 0x02, 0x03];
const RSL: u16 = 1200;

// ---------- TFTP opcodes ----------
const OP_RRQ: u16 = 1;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6;

const DEFAULT_BLOCK: usize = 512;
const MAX_BLOCK: usize = 1024; // must stay under RSL − DTLS overhead
const DEFAULT_TIMEOUT_S: u64 = 5;

const ERR_NOT_FOUND: u16 = 1;
const ERR_ACCESS: u16 = 2;
const ERR_ILLEGAL: u16 = 4;
const ERR_OPT: u16 = 8;

fn build_config() -> Arc<dimpl13::Config> {
    Arc::new(
        dimpl13::Config::builder()
            .alpn_protocols(&[ALPN])
            .server_name(SNI)
            .connection_id(CID)
            .record_size_limit(RSL)
            // The client also uses `require_client_certificate = true`; leaving
            // the default makes both sides negotiate client auth, which the
            // demo accepts via `|_der| true`.
            .build()
            .expect("valid TFTP config"),
    )
}

// ---------- Entry point ----------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let bind_addr = args.next().unwrap_or_else(|| "127.0.0.1:6969".into());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()).into());
    }
    let root = root.canonicalize()?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(serve(&bind_addr, root))
}

async fn serve(bind_addr: &str, root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    tokio_dtls::warmup().await?;

    let config = build_config();
    let cert = Arc::new(
        dimpl13::certificate::generate_self_signed_certificate()
            .expect("generate server certificate"),
    );

    loop {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("bind {bind_addr} failed: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        println!("TFTP server on {bind_addr}, root = {}", root.display());

        let opts = ConfigOptions {
            dtls_config: Some(Arc::clone(&config)),
            dtls_cert: Some(Arc::clone(&cert)),
            handshake_timeout: Duration::from_secs(15),
            ..Default::default()
        };

        match DtlsConnection::accept_with(socket, |_der| true, opts).await {
            Ok(conn) => {
                println!("--- session: peer={} ---", conn.peer_addr());
                if let Some(p) = conn.negotiated_alpn() {
                    println!("  ALPN: {}", String::from_utf8_lossy(p));
                }
                if let Some(s) = conn.peer_server_name() {
                    println!("  SNI:  {s}");
                }
                if let Err(e) = handle_session(&conn, &root).await {
                    eprintln!("session failed: {e}");
                }
            }
            Err(e) => {
                eprintln!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------- TFTP session ----------

async fn handle_session(
    conn: &DtlsConnection,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // ---- Receive RRQ ----
    let request = match tokio::time::timeout(Duration::from_secs(10), conn.recv()).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            eprintln!("no RRQ within 10s, closing");
            let _ = conn.close().await;
            return Ok(());
        }
    };

    if request.len() < 4 || u16::from_be_bytes([request[0], request[1]]) != OP_RRQ {
        let _ = send_error(conn, ERR_ILLEGAL, "expected RRQ").await;
        return Ok(());
    }

    let mut parts = request[2..].split(|&b| b == 0);
    let filename = parts.next().filter(|f| !f.is_empty());
    let mode = parts.next();
    let Some(filename) = filename else {
        let _ = send_error(conn, ERR_ILLEGAL, "missing filename").await;
        return Ok(());
    };
    let filename = String::from_utf8_lossy(filename).into_owned();
    let mode = mode
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    if !mode.eq_ignore_ascii_case("octet") {
        let _ = send_error(conn, ERR_ILLEGAL, "only octet mode supported").await;
        return Ok(());
    }

    // Options: alternating key\0value\0
    let mut opts = Vec::new();
    loop {
        let Some(k) = parts.next() else { break };
        if k.is_empty() {
            break;
        }
        let Some(v) = parts.next() else {
            let _ = send_error(conn, ERR_OPT, "missing option value").await;
            return Ok(());
        };
        let k = String::from_utf8_lossy(k).to_ascii_lowercase();
        let v = String::from_utf8_lossy(v).into_owned();
        opts.push((k, v));
    }

    // ---- Resolve path inside root ----
    let Some(path) = safe_join(root, &filename) else {
        let _ = send_error(conn, ERR_ACCESS, "path traversal denied").await;
        return Ok(());
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            let _ = send_error(conn, ERR_NOT_FOUND, "file not found").await;
            return Ok(());
        }
    };

    // ---- Option negotiation ----
    let mut blksize = DEFAULT_BLOCK;
    let mut timeout_s = DEFAULT_TIMEOUT_S;
    let mut accepted: Vec<(&str, String)> = Vec::new();

    for (k, v) in &opts {
        match k.as_str() {
            "blksize" => {
                if let Ok(n) = v.parse::<usize>() {
                    let n = n.clamp(8, MAX_BLOCK);
                    blksize = n;
                    accepted.push(("blksize", n.to_string()));
                }
            }
            "timeout" => {
                if let Ok(n) = v.parse::<u64>() {
                    let n = n.clamp(1, 255);
                    timeout_s = n;
                    accepted.push(("timeout", n.to_string()));
                }
            }
            "tsize" => {
                accepted.push(("tsize", data.len().to_string()));
            }
            _ => { /* ignore unknown */ }
        }
    }

    if !accepted.is_empty() {
        // OACK
        let mut oack = Vec::new();
        oack.extend_from_slice(&OP_OACK.to_be_bytes());
        for (k, v) in &accepted {
            oack.extend_from_slice(k.as_bytes());
            oack.push(0);
            oack.extend_from_slice(v.as_bytes());
            oack.push(0);
        }
        conn.send(&oack).await?;
        // Wait for ACK 0
        let ack = tokio::time::timeout(Duration::from_secs(timeout_s), conn.recv()).await;
        match ack {
            Ok(Ok(a))
                if a.len() >= 4
                    && u16::from_be_bytes([a[0], a[1]]) == OP_ACK
                    && u16::from_be_bytes([a[2], a[3]]) == 0 => {}
            _ => {
                let _ = send_error(conn, ERR_ILLEGAL, "OACK not acked").await;
                return Ok(());
            }
        }
    }

    // ---- Data transfer ----
    println!(
        "RRQ {} → {} bytes, blksize={}, timeout={}s",
        filename,
        data.len(),
        blksize,
        timeout_s
    );

    let mut block: u16 = 1;
    let mut offset = 0usize;

    loop {
        let end = (offset + blksize).min(data.len());
        let chunk = &data[offset..end];

        let mut pkt = Vec::with_capacity(4 + chunk.len());
        pkt.extend_from_slice(&OP_DATA.to_be_bytes());
        pkt.extend_from_slice(&block.to_be_bytes());
        pkt.extend_from_slice(chunk);

        conn.send(&pkt).await?;

        let mut acked = false;
        for attempt in 0..3u32 {
            match tokio::time::timeout(Duration::from_secs(timeout_s), conn.recv()).await {
                Ok(Ok(ack)) if ack.len() >= 4 => {
                    if u16::from_be_bytes([ack[0], ack[1]]) == OP_ACK
                        && u16::from_be_bytes([ack[2], ack[3]]) == block
                    {
                        acked = true;
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                _ => {
                    if attempt < 2 {
                        println!("  block {block} timeout, retransmitting");
                        conn.send(&pkt).await?;
                    }
                }
            }
        }
        if !acked {
            let _ = send_error(conn, ERR_ILLEGAL, "ACK timeout").await;
            return Ok(());
        }

        offset = end;
        if chunk.len() < blksize {
            break;
        }
        block = block.wrapping_add(1);
    }

    println!("  transfer complete");
    let _ = conn.close().await;
    Ok(())
}

fn safe_join(root: &Path, name: &str) -> Option<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() {
        return None;
    }
    for comp in p.components() {
        use std::path::Component::*;
        if matches!(comp, ParentDir | RootDir | Prefix(_)) {
            return None;
        }
    }
    let joined = root.join(p);
    // Canonicalise to be sure we didn't escape root.
    let canon = joined.canonicalize().ok()?;
    if !canon.starts_with(root) {
        return None;
    }
    Some(canon)
}

async fn send_error(
    conn: &DtlsConnection,
    code: u16,
    msg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut p = Vec::with_capacity(4 + msg.len() + 1);
    p.extend_from_slice(&OP_ERROR.to_be_bytes());
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(msg.as_bytes());
    p.push(0);
    conn.send(&p).await?;
    let _ = conn.close().await;
    Ok(())
}
