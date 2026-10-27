//! Synchronous TFTP-over-DTLS 1.3 client with RFC 2347–2349 option
//! negotiation (blksize, tsize, timeout).
//!
//! ```sh
//! cargo run --example tftp-client -- 127.0.0.1:6969 README.md
//! ```

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl13::{Dtls, Output};

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
const UDP_BUF_LEN: usize = 2048;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let server: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:6969".into())
        .parse()?;
    let filename = args.next().unwrap_or_else(|| "README.md".into());

    println!("connecting to {server}");
    let (data, blksize) = tftp_get(server, &filename)?;
    println!("received {} bytes (blksize={blksize})", data.len());

    let out = format!("received_{}", filename.replace(['/', '\\'], "_"));
    std::fs::write(&out, &data)?;
    println!("saved to {out}");
    Ok(())
}

fn tftp_get(
    server: SocketAddr,
    filename: &str,
) -> Result<(Vec<u8>, usize), Box<dyn std::error::Error>> {
    let config = build_config();
    let cert = dimpl13::certificate::generate_self_signed_certificate()?;
    let mut dtls = Dtls::new_13(config, cert, Instant::now());
    dtls.set_active(true);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let mut out_buf = vec![0u8; UDP_BUF_LEN];
    let mut udp_buf = vec![0u8; UDP_BUF_LEN];
    let deadline = Instant::now() + OVERALL_TIMEOUT;

    let mut connected = false;
    let mut rrq_sent = false;
    let mut next_wake: Option<Instant> = None;

    // Transfer state
    let mut blksize: usize = DEFAULT_BLOCK;
    let mut expected_block: u16 = 1;
    let mut received: Vec<u8> = Vec::new();
    let mut oack_pending = false; // waiting for OACK vs. direct DATA

    while Instant::now() < deadline {
        // ---- Drain engine output ----
        loop {
            match dtls.poll_output(&mut out_buf) {
                Output::Packet(pkt) => {
                    socket.send(pkt)?;
                }
                Output::Timeout(t) => {
                    next_wake = Some(t);
                    break;
                }
                Output::Connected => connected = true,
                Output::PeerCert(_) => {}
                Output::KeyingMaterial(_, _) => {}
                Output::BufferTooSmall { needed } => out_buf.resize(needed, 0),
                Output::CloseNotify => {
                    if !received.is_empty() {
                        return Ok((received, blksize));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "server closed before response",
                    )
                    .into());
                }
                Output::ApplicationData(data) => {
                    if data.len() < 4 {
                        continue;
                    }
                    let op = u16::from_be_bytes([data[0], data[1]]);
                    match op {
                        OP_OACK => {
                            // Options: key\0value\0...
                            let mut parts = data[2..].split(|&b| b == 0);
                            while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                                if k.is_empty() {
                                    break;
                                }
                                if k.eq_ignore_ascii_case(b"blksize") {
                                    if let Ok(n) = std::str::from_utf8(v)
                                        .ok()
                                        .and_then(|s| s.parse::<usize>().ok())
                                        .ok_or(())
                                    {
                                        blksize = n;
                                    }
                                }
                            }
                            oack_pending = false;
                            // ACK block 0
                            let mut ack = Vec::with_capacity(4);
                            ack.extend_from_slice(&OP_ACK.to_be_bytes());
                            ack.extend_from_slice(&0u16.to_be_bytes());
                            dtls.send_application_data(&ack)?;
                        }
                        OP_DATA => {
                            let block = u16::from_be_bytes([data[2], data[3]]);
                            if block != expected_block {
                                continue;
                            }
                            received.extend_from_slice(&data[4..]);
                            let is_last = data.len() < 4 + blksize;

                            let mut ack = Vec::with_capacity(4);
                            ack.extend_from_slice(&OP_ACK.to_be_bytes());
                            ack.extend_from_slice(&block.to_be_bytes());
                            dtls.send_application_data(&ack)?;

                            if is_last {
                                let _ = dtls.close();
                                let _ = dtls.poll_output(&mut out_buf);
                                return Ok((received, blksize));
                            }
                            expected_block = expected_block.wrapping_add(1);
                        }
                        OP_ERROR => {
                            let code = u16::from_be_bytes([data[2], data[3]]);
                            let msg = String::from_utf8_lossy(&data[4..]);
                            return Err(format!("TFTP error {code}: {msg}").into());
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // ---- Send RRQ with options ----
        if connected && !rrq_sent {
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

            let accepted = dtls.send_application_data(&rrq)?;
            if accepted == rrq.len() {
                rrq_sent = true;
                oack_pending = true;
            }
        }

        // ---- Wait for packet / timer ----
        let now = Instant::now();
        let hint = next_wake.unwrap_or(now + Duration::from_millis(100));
        let wait = hint
            .saturating_duration_since(now)
            .clamp(Duration::from_millis(1), Duration::from_millis(200));
        socket.set_read_timeout(Some(wait))?;

        match socket.recv(&mut udp_buf) {
            Ok(len) => dtls.handle_packet(&udp_buf[..len])?,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                dtls.handle_timeout(Instant::now())?;
                next_wake = None;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let _ = oack_pending;
    Err(io::Error::new(io::ErrorKind::TimedOut, "TFTP transfer timed out").into())
}
