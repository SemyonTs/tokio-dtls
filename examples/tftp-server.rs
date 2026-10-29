//! Async TFTP-over-DTLS 1.3 server with a served directory, using
//! [`DtlsServer`] for connection multiplexing on a single UDP socket.
//! Handles many concurrent peers, one DTLS session per peer address.
//!
//! ```sh
//! cargo run --example tftp-server -- 127.0.0.1:6969 ./public
//! ```
//!
//! `RUST_LOG=tokio_dtls=debug` for per-session tracing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio_dtls::{ConfigOptions, DtlsConnection, DtlsServer};

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
const RRQ_TIMEOUT_S: u64 = 10;

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
            .build()
            .expect("valid TFTP config"),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tracing to stderr; controlled by RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tokio_dtls=debug")),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut args = std::env::args().skip(1);
    let bind_addr = args.next().unwrap_or_else(|| "127.0.0.1:6969".into());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()).into());
    }
    let root = root.canonicalize()?;

    serve(&bind_addr, root).await
}

async fn serve(bind_addr: &str, root: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    tokio_dtls::warmup().await?;

    let config = build_config();
    let cert = Arc::new(
        dimpl13::certificate::generate_self_signed_certificate()
            .expect("generate server certificate"),
    );

    let opts = ConfigOptions {
        dtls_config: Some(config),
        dtls_cert: Some(cert),
        handshake_timeout: Duration::from_secs(15),
        ..Default::default()
    };

    let mut server = DtlsServer::bind(bind_addr, |_der| true, opts).await?;
    println!(
        "TFTP server (multiplexed) on {} root={}",
        server.local_addr(),
        root.display()
    );

    loop {
        let conn = match server.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let peer = conn.peer_addr();
        let active = server.session_count();
        let root = root.clone();

        tokio::spawn(async move {
            println!("--- session peer={peer} active={active} ---");
            if let Some(p) = conn.negotiated_alpn() {
                println!("  ALPN: {}", String::from_utf8_lossy(p));
            }
            if let Some(s) = conn.peer_server_name() {
                println!("  SNI:  {s}");
            }
            if let Err(e) = handle_session(&conn, &root).await {
                eprintln!("session {peer} failed: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Session handler
// ---------------------------------------------------------------------------

async fn handle_session(
    conn: &DtlsConnection,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // ---- 1. Receive RRQ ----
    let request = match tokio::time::timeout(Duration::from_secs(RRQ_TIMEOUT_S), conn.recv()).await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            eprintln!("recv RRQ: {e}");
            return Err(format!("recv RRQ: {e}").into());
        }
        Err(_) => {
            eprintln!("no RRQ within {RRQ_TIMEOUT_S}s, closing");
            let _ = conn.close().await;
            return Ok(());
        }
    };

    if request.len() < 4 || u16::from_be_bytes([request[0], request[1]]) != OP_RRQ {
        eprintln!("malformed RRQ (len={})", request.len());
        send_error(conn, ERR_ILLEGAL, "expected RRQ").await;
        return Ok(());
    }

    // ---- 2. Parse filename + mode ----
    let mut parts = request[2..].split(|&b| b == 0);
    let Some(filename_raw) = parts.next() else {
        eprintln!("RRQ missing filename");
        send_error(conn, ERR_ILLEGAL, "missing filename").await;
        return Ok(());
    };
    if filename_raw.is_empty() {
        eprintln!("RRQ filename is empty");
        send_error(conn, ERR_ILLEGAL, "missing filename").await;
        return Ok(());
    }
    let filename = String::from_utf8_lossy(filename_raw).into_owned();
    let mode = parts
        .next()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    if !mode.eq_ignore_ascii_case("octet") {
        eprintln!("RRQ {filename}: unsupported mode {mode:?}");
        send_error(conn, ERR_ILLEGAL, "only octet mode supported").await;
        return Ok(());
    }

    // ---- 3. Parse options (alternating key\0value\0) ----
    let mut opts = Vec::new();
    loop {
        let Some(k) = parts.next() else { break };
        if k.is_empty() {
            break;
        }
        let Some(v) = parts.next() else {
            eprintln!("RRQ {filename}: option {k:?} missing value");
            send_error(conn, ERR_OPT, "missing option value").await;
            return Ok(());
        };
        opts.push((
            String::from_utf8_lossy(k).to_ascii_lowercase(),
            String::from_utf8_lossy(v).into_owned(),
        ));
    }

    eprintln!("RRQ filename={filename} mode={mode} opts={opts:?}");

    // ---- 4. Resolve path inside root ----
    let path = match safe_join(root, &filename) {
        JoinOutcome::Ok(p) => p,
        JoinOutcome::Traversal => {
            eprintln!("RRQ {filename}: path traversal denied");
            send_error(conn, ERR_ACCESS, "path traversal denied").await;
            return Ok(());
        }
        JoinOutcome::NotFound => {
            eprintln!("RRQ {filename}: file not found");
            send_error(conn, ERR_NOT_FOUND, "file not found").await;
            return Ok(());
        }
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {} failed: {e}", path.display());
            send_error(conn, ERR_NOT_FOUND, "file read failed").await;
            return Ok(());
        }
    };

    // ---- 5. Option negotiation ----
    let mut blksize = DEFAULT_BLOCK;
    let mut timeout_s = DEFAULT_TIMEOUT_S;
    let mut accepted: Vec<(&'static str, String)> = Vec::new();

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
            "tsize" => accepted.push(("tsize", data.len().to_string())),
            _ => {}
        }
    }

    if !accepted.is_empty() {
        let mut oack = Vec::new();
        oack.extend_from_slice(&OP_OACK.to_be_bytes());
        for (k, v) in &accepted {
            oack.extend_from_slice(k.as_bytes());
            oack.push(0);
            oack.extend_from_slice(v.as_bytes());
            oack.push(0);
        }
        conn.send(&oack)
            .await
            .map_err(|e| format!("send OACK: {e}"))?;

        // Wait for ACK block 0.
        let result = tokio::time::timeout(Duration::from_secs(timeout_s), conn.recv()).await;
        match result {
            Ok(Ok(ack))
                if ack.len() >= 4
                    && u16::from_be_bytes([ack[0], ack[1]]) == OP_ACK
                    && u16::from_be_bytes([ack[2], ack[3]]) == 0 => {}
            Ok(Ok(ack)) => {
                eprintln!(
                    "RRQ {filename}: expected ACK 0, got op={} block={}",
                    if ack.len() >= 2 {
                        u16::from_be_bytes([ack[0], ack[1]])
                    } else {
                        0
                    },
                    if ack.len() >= 4 {
                        u16::from_be_bytes([ack[2], ack[3]])
                    } else {
                        0
                    },
                );
                send_error(conn, ERR_ILLEGAL, "OACK not acked").await;
                return Ok(());
            }
            Ok(Err(e)) => {
                eprintln!("RRQ {filename}: recv ACK0: {e}");
                return Err(format!("recv ACK0: {e}").into());
            }
            Err(_) => {
                eprintln!("RRQ {filename}: timeout waiting for ACK 0");
                send_error(conn, ERR_ILLEGAL, "OACK not acked").await;
                return Ok(());
            }
        }
    }

    eprintln!(
        "RRQ {filename} -> {} bytes, blksize={blksize}, timeout={timeout_s}s",
        data.len()
    );

    // ---- 6. Data transfer ----
    let mut block: u16 = 1;
    let mut offset = 0usize;
    loop {
        let end = (offset + blksize).min(data.len());
        let chunk = &data[offset..end];

        let mut pkt = Vec::with_capacity(4 + chunk.len());
        pkt.extend_from_slice(&OP_DATA.to_be_bytes());
        pkt.extend_from_slice(&block.to_be_bytes());
        pkt.extend_from_slice(chunk);

        let mut acked = false;
        for attempt in 0..3u32 {
            conn.send(&pkt)
                .await
                .map_err(|e| format!("send DATA {block}: {e}"))?;

            let result = tokio::time::timeout(Duration::from_secs(timeout_s), conn.recv()).await;
            match result {
                Ok(Ok(ack)) if ack.len() >= 4 => {
                    if u16::from_be_bytes([ack[0], ack[1]]) == OP_ACK
                        && u16::from_be_bytes([ack[2], ack[3]]) == block
                    {
                        acked = true;
                        break;
                    }
                    eprintln!(
                        "  block {block}: unexpected reply (len={}, op={})",
                        ack.len(),
                        if ack.len() >= 2 {
                            u16::from_be_bytes([ack[0], ack[1]])
                        } else {
                            0
                        },
                    );
                }
                Ok(Ok(ack)) => {
                    eprintln!("  block {block}: short reply (len={})", ack.len());
                }
                Ok(Err(e)) => {
                    eprintln!("  block {block}: recv error: {e}");
                    return Err(format!("recv ACK {block}: {e}").into());
                }
                Err(_) => {
                    if attempt < 2 {
                        eprintln!("  block {block} timeout, retransmitting");
                    }
                }
            }
        }
        if !acked {
            eprintln!("  block {block}: ACK timeout, aborting");
            send_error(conn, ERR_ILLEGAL, "ACK timeout").await;
            return Ok(());
        }

        offset = end;
        if chunk.len() < blksize {
            break;
        }
        block = block.wrapping_add(1);
    }

    eprintln!("  transfer complete");
    let _ = conn.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

enum JoinOutcome {
    Ok(PathBuf),
    NotFound,
    Traversal,
}

fn safe_join(root: &Path, name: &str) -> JoinOutcome {
    let p = Path::new(name);
    if p.is_absolute() {
        return JoinOutcome::Traversal;
    }
    for comp in p.components() {
        use std::path::Component::*;
        if matches!(comp, ParentDir | RootDir | Prefix(_)) {
            return JoinOutcome::Traversal;
        }
    }
    let joined = root.join(p);
    match joined.canonicalize() {
        Ok(canon) if canon.starts_with(root) => JoinOutcome::Ok(canon),
        Ok(_) => JoinOutcome::Traversal,
        Err(_) => JoinOutcome::NotFound,
    }
}

// ---------------------------------------------------------------------------
// ERROR packet
// ---------------------------------------------------------------------------

async fn send_error(conn: &DtlsConnection, code: u16, msg: &str) {
    eprintln!("SEND ERROR code={code} msg={msg}");
    let mut p = Vec::with_capacity(4 + msg.len() + 1);
    p.extend_from_slice(&OP_ERROR.to_be_bytes());
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(msg.as_bytes());
    p.push(0);
    if let Err(e) = conn.send(&p).await {
        eprintln!("send ERROR failed: {e}");
    }
    let _ = conn.close().await;
}
