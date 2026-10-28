//! Async TFTP-over-DTLS 1.3 client with RFC 2347–2349 option negotiation
//! (blksize, tsize, timeout), built on [`tokio_dtls::DtlsConnection`].
//!
//! Accepts one or more filenames and downloads them **concurrently**, each
//! over its own DTLS connection — the natural client-side counterpart to the
//! multiplexed server.
//!
//! ```sh
//! cargo run --example tftp-client -- 127.0.0.1:6969 README.md file2.bin
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio_dtls::{ConfigOptions, DtlsConnection};

// ---------- Shared extension config (must match server) ----------
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
const REQUEST_BLOCK: usize = 1024;
const REQUEST_TIMEOUT_S: u64 = 5;

const OVERALL_TIMEOUT: Duration = Duration::from_secs(60);

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
    let mut args = std::env::args().skip(1);
    let server = args.next().unwrap_or_else(|| "127.0.0.1:6969".into());
    let mut files: Vec<String> = args.collect();
    if files.is_empty() {
        files.push("README.md".into());
    }

    tokio_dtls::warmup().await?;

    let mut handles = Vec::new();
    for filename in files {
        let server = server.clone();
        handles.push(tokio::spawn(async move {
            match fetch_one(&server, &filename).await {
                Ok((data, blksize)) => {
                    println!(
                        "[{filename}] received {} bytes (blksize={blksize})",
                        data.len()
                    );
                    let out = format!("received_{}", filename.replace(['/', '\\'], "_"));
                    match std::fs::write(&out, &data) {
                        Ok(()) => println!("[{filename}] saved to {out}"),
                        Err(e) => eprintln!("[{filename}] write failed: {e}"),
                    }
                }
                Err(e) => eprintln!("[{filename}] failed: {e}"),
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn fetch_one(server: &str, filename: &str) -> Result<(Vec<u8>, usize), String> {
    let opts = ConfigOptions {
        dtls_config: Some(build_config()),
        dtls_cert: Some(Arc::new(
            dimpl13::certificate::generate_self_signed_certificate()
                .map_err(|e| format!("cert: {e}"))?,
        )),
        ..Default::default()
    };
    let conn = DtlsConnection::connect_with(server, |_der| true, opts)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    // Build and send RRQ with options.
    let mut rrq = Vec::new();
    rrq.extend_from_slice(&OP_RRQ.to_be_bytes());
    rrq.extend_from_slice(filename.as_bytes());
    rrq.push(0);
    rrq.extend_from_slice(b"octet\0");
    rrq.extend_from_slice(b"blksize\0");
    rrq.extend_from_slice(REQUEST_BLOCK.to_string().as_bytes());
    rrq.push(0);
    rrq.extend_from_slice(b"tsize\0");
    rrq.extend_from_slice(b"0\0");
    rrq.extend_from_slice(b"timeout\0");
    rrq.extend_from_slice(REQUEST_TIMEOUT_S.to_string().as_bytes());
    rrq.push(0);
    conn.send(&rrq)
        .await
        .map_err(|e| format!("send RRQ: {e}"))?;

    let mut blksize = DEFAULT_BLOCK;
    let mut expected_block: u16 = 1;
    let mut received: Vec<u8> = Vec::new();
    let mut done = false;

    // First response: OACK, DATA (block 1), or ERROR.
    loop {
        let pkt = match tokio::time::timeout(OVERALL_TIMEOUT, conn.recv()).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                let _ = conn.close().await;
                return Err(format!("recv: {e}"));
            }
            Err(_) => {
                let _ = conn.close().await;
                return Err("timeout waiting for first response".into());
            }
        };
        if pkt.len() < 4 {
            continue;
        }
        match u16::from_be_bytes([pkt[0], pkt[1]]) {
            OP_OACK => {
                let mut parts = pkt[2..].split(|&b| b == 0);
                while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    if k.is_empty() {
                        break;
                    }
                    if k.eq_ignore_ascii_case(b"blksize") {
                        if let Some(n) = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok()) {
                            blksize = n;
                        }
                    }
                }
                let mut ack = Vec::with_capacity(4);
                ack.extend_from_slice(&OP_ACK.to_be_bytes());
                ack.extend_from_slice(&0u16.to_be_bytes());
                conn.send(&ack).await.map_err(|e| format!("ACK 0: {e}"))?;
                break;
            }
            OP_DATA => {
                let block = u16::from_be_bytes([pkt[2], pkt[3]]);
                if block != 1 {
                    continue;
                }
                received.extend_from_slice(&pkt[4..]);
                let is_last = pkt.len() < 4 + blksize;
                let mut ack = Vec::with_capacity(4);
                ack.extend_from_slice(&OP_ACK.to_be_bytes());
                ack.extend_from_slice(&1u16.to_be_bytes());
                conn.send(&ack).await.map_err(|e| format!("ACK 1: {e}"))?;
                if is_last {
                    done = true;
                } else {
                    expected_block = 2;
                }
                break;
            }
            OP_ERROR => {
                let code = u16::from_be_bytes([pkt[2], pkt[3]]);
                let msg = String::from_utf8_lossy(&pkt[4..]);
                let _ = conn.close().await;
                return Err(format!("TFTP error {code}: {msg}"));
            }
            _ => {}
        }
    }

    while !done {
        let pkt = match tokio::time::timeout(OVERALL_TIMEOUT, conn.recv()).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                let _ = conn.close().await;
                return Err(format!("recv: {e}"));
            }
            Err(_) => {
                let _ = conn.close().await;
                return Err(format!("timeout waiting for block {expected_block}"));
            }
        };
        if pkt.len() < 4 {
            continue;
        }
        match u16::from_be_bytes([pkt[0], pkt[1]]) {
            OP_ERROR => {
                let code = u16::from_be_bytes([pkt[2], pkt[3]]);
                let msg = String::from_utf8_lossy(&pkt[4..]);
                let _ = conn.close().await;
                return Err(format!("TFTP error {code}: {msg}"));
            }
            OP_DATA => {
                let block = u16::from_be_bytes([pkt[2], pkt[3]]);
                if block != expected_block {
                    continue;
                }
                received.extend_from_slice(&pkt[4..]);
                let is_last = pkt.len() < 4 + blksize;

                let mut ack = Vec::with_capacity(4);
                ack.extend_from_slice(&OP_ACK.to_be_bytes());
                ack.extend_from_slice(&block.to_be_bytes());
                conn.send(&ack)
                    .await
                    .map_err(|e| format!("ACK {block}: {e}"))?;

                if is_last {
                    done = true;
                } else {
                    expected_block = expected_block.wrapping_add(1);
                }
            }
            _ => {}
        }
    }

    let _ = conn.close().await;
    Ok((received, blksize))
}
