# tokio-dtls
[![tokio-dtls](https://img.shields.io/crates/v/tokio-dtls?label=tokio-dtls&logo=rust)](https://crates.io/crates/tokio-dtls)
[![Downloads](https://img.shields.io/crates/d/tokio-dtls?label=downloads)](https://crates.io/crates/tokio-dtls)
[![License](https://img.shields.io/crates/l/tokio-dtls?label=license)](https://crates.io/crates/tokio-dtls)
[![docs.rs](https://img.shields.io/docsrs/tokio-dtls?label=docs.rs)](https://docs.rs/tokio-dtls)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**tokio-dtls** — an asynchronous wrapper around [`dimpl13`](https://crates.io/crates/dimpl13) for **DTLS 1.3 only** in the Tokio environment. The crate hides the Sans-IO state machine of `dimpl13` behind a familiar asynchronous API: `connect` / `accept`, `send` / `recv`, `close`. Each [`DtlsConnection`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html) owns a Tokio background task that manages the engine and the UDP socket.

The crate **intentionally does not support DTLS 1.2**. The engine is always created via `Dtls::new_13`, and the public API provides no way to negotiate the older version. If the peer does not support DTLS 1.3, the handshake will fail.

## Supported DTLS 1.3 extensions

Four protocol extensions are exposed through `dimpl13::Config` and, where they have an observable result, through `DtlsConnection`:

| Extension | Direction | How to configure | How to read |
|---|---|---|---|
| **ALPN** (RFC 7301) | both | `Config::builder().alpn_protocols(&[b"h2", …])` | `DtlsConnection::negotiated_alpn()` |
| **SNI** (RFC 6066) | client → server | `Config::builder().server_name("example.com")` | `DtlsConnection::peer_server_name()` |
| **Connection ID** (RFC 9146) | both | `Config::builder().connection_id(&[…])` | transparent |
| **Record Size Limit** (RFC 8449) | both, asymmetrical | `Config::builder().record_size_limit(1200)` | transparent |

Details:

- **ALPN.** The client offers a list; the server picks one from its own preference list. Both sides return the selected protocol via `negotiated_alpn()`. If no protocol matches, the server aborts with `Error::Dtls(SecurityError::NoCommonAlpnProtocol)`. This is the correct RFC 7301 behavior.
- **SNI.** The client sends a server name; the server can read it via `peer_server_name()`. Always `None` on the client. tokio-dtls does **not** validate that the SNI matches the peer's certificate — that's the application's policy.
- **Connection ID.** Requires **both** sides to configure one; otherwise it is silently disabled and the wire format falls back to the standard record header. Transparent to `send` / `recv`. This is the mechanism that keeps a session alive across NAT rebinding.
- **Record Size Limit.** Each side advertises a maximum outgoing record size; the peer's limit is applied to our outgoing records. Default `16385` (`Config::default()`). Asymmetrical: it is enough for one side to set it. Useful for constrained networks or path-MTU-constrained tunnels.

The process-wide shared `Config` (used when `ConfigOptions::dtls_config` is `None`) advertises **no ALPN, no SNI, no Connection ID**, and the default Record Size Limit. **To enable any of these, build your own `Arc<Config>` once at startup** and pass it via [`ConfigOptions::dtls_config`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.ConfigOptions.html#structfield.dtls_config).

```rust
use std::sync::Arc;
use dimpl13::{certificate, Config};
use tokio_dtls::{ConfigOptions, DtlsConnection};

// Build once; clone the Arc for every connection.
let config = Arc::new(
    Config::builder()
        .alpn_protocols(&[b"h2".as_slice(), b"http/1.1".as_slice()])
        .server_name("example.com")               // client only
        .connection_id(&[0xDE, 0xAD, 0xBE, 0xEF]) // both sides
        .record_size_limit(1200)                  // both sides
        .build()?,
);
let cert = Arc::new(certificate::generate_self_signed_certificate()?);

let conn = DtlsConnection::connect_with(
    "127.0.0.1:4433",
    |_der| true, // replace with real certificate validation
    ConfigOptions {
        dtls_config: Some(Arc::clone(&config)),
        dtls_cert: Some(Arc::clone(&cert)),
        ..Default::default()
    },
).await?;

if let Some(proto) = conn.negotiated_alpn() {
    println!("negotiated ALPN: {}", String::from_utf8_lossy(proto));
}
```

### Quick example

```rust
use tokio_dtls::DtlsConnection;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let conn = DtlsConnection::connect(
    "127.0.0.1:4433",
    |_der| true, // replace with real certificate validation
).await?;

conn.send(b"hello").await?;
let data = conn.recv().await?;
println!("got: {:?}", data);
# Ok(())
# }
```

This example uses the process-wide shared `Config` — no ALPN, no SNI, no Connection ID, default Record Size Limit. For negotiated-parameter behavior, use `connect_with` / `accept_with` and a custom `Arc<Config>` (see above).

## Differences from `dimpl13`
- **Asynchrony.** `dimpl13` is a Sans-IO engine that you embed in your own event loop. `tokio-dtls` does this for you: it creates the socket, starts a background task, handles timers and packets, and exposes asynchronous methods.
- **Tokio integration.** It uses `tokio::net::UdpSocket`, `tokio::sync::mpsc`, and `tokio::time`. All operations (`send`, `recv`, `close`) are `async`.
- **One peer per socket with `accept`.** `accept` reads the first datagram to determine the peer address and **connects the socket to that peer**. Therefore, one socket serves one client. For many peers, you must either create a socket per connection or implement demultiplexing at the application level.
- **Shared config and certificate.** Process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. This removes the cost of `Config::builder().build()` and `generate_self_signed_certificate()` from every handshake. The shared config, however, offers none of the negotiated extensions above.
- **The `warmup` function.** It allows one-time initialization (`aws-lc-rs`, `rcgen`, provider validation — up to ~90 ms on some platforms) to be moved into a predictable application startup phase.
- **SRTP is not exported.** `dimpl13` exposes `Output::KeyingMaterial` (RFC 5764 / RFC 7714) for use with an SRTP stack; tokio-dtls intentionally drops that variant because it does not negotiate `use_srtp`. If you need DTLS-SRTP, use `dimpl13` directly.

If you need direct control over the Sans-IO engine, use the original [`dimpl13`](https://crates.io/crates/dimpl13).

### Certificate model
During the handshake, the engine emits `Output::PeerCert` with the peer's leaf certificate in DER. The crate uses the certificate to verify handshake message signatures, but **does not perform PKI validation**. The application validates the certificate according to its own policy (fingerprint, chain building, name/EKU checks, pinning, etc.).

## Asynchronous model
`DtlsConnection` is a cheap-to-clone handle to the background task. Cloning **does not create** a new connection; all clones share one session.

- `send` can be called from multiple clones simultaneously.
- `recv` is serialized internally; when used from multiple clones, messages will be interleaved arbitrarily, but they will not be lost or reordered.
- `close` is idempotent: it sends `close_notify`, waits for the engine task to complete, and if necessary forcibly aborts it after a timeout (5 s).
- `negotiated_alpn()` and `peer_server_name()` return snapshots taken at handshake completion. They are immutable for the connection's lifetime and can be read from any clone.

## Performance
By default, process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. The fast path — both values cached, default queue sizes — returns `Arc::clone` without waking the blocking pool. This removes from every handshake the cost of `Config::builder().build()` (crypto provider validation, ~3–5 ms) and `generate_self_signed_certificate()` (ECDSA key generation, ~2–5 ms), which would otherwise dominate a loopback handshake.

When you pass **both** `ConfigOptions::dtls_config` and `ConfigOptions::dtls_cert`, connection setup is a pure `Arc::clone` with no blocking-pool involvement — strictly faster than the shared-cache path, and the only way to enable ALPN / SNI / Connection ID / custom Record Size Limit.

Call [`warmup()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/fn.warmup.html) once at process startup to move the one-time cost (AWS-LC-RS initialization, the first `rcgen` key, provider validation — up to ~90 ms on some platforms) out of the first handshake into a predictable startup phase:

```rust
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
tokio_dtls::warmup().await?;
// ... start accepting / connecting ...
# Ok(())
# }
```

After warmup, `p50` handshake time on loopback is ~2.5 ms in sequential `connect` benchmarks. The remaining time is split between `Dtls::new_13` (private key parsing) and four Tokio task switches per handshake flight; neither is controlled by this crate.

## Error handling
The public API returns `Result<T, tokio_dtls::Error>`. Errors fall into two categories:

- **Fatal connection errors.** `Error::Dtls`, `Error::Io`, `Error::CertRejected`, `Error::HandshakeFailed`, `Error::TaskFailed`, etc. mean that the connection can no longer be used. The correct response is to discard the `DtlsConnection` and, if necessary, start a new handshake. The `dimpl13` engine has no recoverable error states. This includes ALPN mismatch on the server side: the server aborts with `Error::Dtls(SecurityError::NoCommonAlpnProtocol)`.
- **Backpressure and temporary conditions.** `Error::ChannelFull` (for `try_send` only) and `Ok(0)` from `send_application_data` on the engine side are not connection errors but a signal to "retry later". Asynchronous `send` uses backpressure via `mpsc::Sender::send`, so when the channel is full it simply waits instead of returning an error.

**Loss of incoming data.** If the consumer does not call `recv()` in time, the internal buffer between the engine task and `recv()` may overflow. In this case, incoming messages are dropped and the [`dropped_app_data()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html#method.dropped_app_data) counter is incremented. For a lossless stream, read `recv()` promptly or increase `ConfigOptions::channel_capacity`.

## Backpressure and queue sizes
`ConfigOptions` allows you to configure `max_queue_rx`, `max_queue_tx`, `channel_capacity`, and other parameters. If you need non-standard queue sizes, pass a custom `Arc<Config>` via `dtls_config` to avoid creating a new configuration for each connection.

tokio-dtls's defaults (`max_queue_rx = 256`, `max_queue_tx = 256`) trade per-connection memory for headroom on mid-throughput workloads. At 256 / 256, the upper bound is ~576 KB per connection (2 × 256 × 1150 B), and this memory is used only when the queues are fully loaded. For minimal per-connection memory (as low as ~46 KB at dimpl13's own `30 / 10` defaults), build your own `Config` and pass it via `dtls_config`.

## Examples

The `examples/` directory contains two working end-to-end demos. They exercise the full extension set described above — **ALPN, SNI, Connection ID, Record Size Limit** — over a real application protocol: TFTP with RFC 2347–2349 option negotiation (`blksize`, `tsize`, `timeout`).

| Example | Style | Uses | Demonstrates |
|---|---|---|---|
| [`examples/tftp-server.rs`](examples/tftp-server.rs) | async | `tokio_dtls::DtlsConnection` | `accept_with`, `recv`/`send`, graceful `close`, serving files from a directory |
| [`examples/tftp-client.rs`](examples/tftp-client.rs) | sync | `dimpl13::Dtls` | Sans-IO event loop with `poll_output` / `handle_packet` / `handle_timeout` |

Both binaries build an identical `Arc<dimpl13::Config>` — ALPN `"tftp/1"`, SNI `"tftp.local"`, an 8-byte Connection ID, and `record_size_limit(1200)` — so they interoperate with each other, and they also serve as a smoke test for the extension plumbing described above.

### Running the examples

Start the server in one terminal:

```sh
cargo run --example tftp-server -- 127.0.0.1:6969 ./public
```

The first argument is the bind address; the second is the directory to serve (must exist). The server accepts one DTLS session at a time, reuses the shared `Arc<Config>` / `Arc<DtlsCertificate>` via `ConfigOptions`, and logs the negotiated ALPN / SNI at the start of each session.

In another terminal, fetch a file:

```sh
cargo run --example tftp-client -- 127.0.0.1:6969 README.md
```

The client sends an RRQ with `blksize=1024`, `tsize=0`, and `timeout=5`, honours the server's OACK, transfers the file in DATA/ACK blocks, and writes the result to `received_<filename>` in the current directory.

### Why two different engines?

`tftp-server.rs` uses `tokio_dtls` (the async wrapper), while `tftp-client.rs` uses `dimpl13` directly (the Sans-IO engine). The pair is deliberately asymmetric so the two integration models can be compared side by side:

- **Server** — the `tokio_dtls` background task owns the socket, drives the timer wheel, and wakes the `recv` / `send` futures. The example body only implements the TFTP protocol.
- **Client** — the application drives the `dimpl13` state machine by hand: `poll_output` drains packets, timers, and events; `handle_packet` feeds incoming datagrams; `handle_timeout` advances the logical clock. This is the pattern to follow when embedding `dimpl13` into an existing event loop that is not Tokio.

Both examples use the same extension config (ALPN / SNI / Connection ID / Record Size Limit), so the DTLS-layer code is essentially identical — only the way the state machine is driven differs.

## Versioning and MSRV
- The crate follows `dimpl13` versioning and shares its cryptographic fixes.
- **MSRV**: Rust 1.88.0.
- **Status**:
  - Session resumption is not implemented (WebRTC performs a full handshake on ICE restart).
  - Renegotiation is not applicable in DTLS 1.3; use `KeyUpdate`.
  - SRTP keying material is not exported; use `dimpl13` directly if you need DTLS-SRTP.

## License
MPL-2.0. See `LICENSE`.