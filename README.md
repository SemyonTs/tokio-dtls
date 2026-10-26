# tokio-dtls
[![tokio-dtls](https://img.shields.io/crates/v/tokio-dtls?label=tokio-dtls&logo=rust)](https://crates.io/crates/tokio-dtls)
[![Downloads](https://img.shields.io/crates/d/tokio-dtls?label=downloads)](https://crates.io/crates/tokio-dtls)
[![License](https://img.shields.io/crates/l/tokio-dtls?label=license)](https://crates.io/crates/tokio-dtls)
[![docs.rs](https://img.shields.io/docsrs/tokio-dtls?label=docs.rs)](https://docs.rs/tokio-dtls)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**tokio-dtls** — an asynchronous wrapper around [`dimpl13`](https://crates.io/crates/dimpl13) for **DTLS 1.3 only** in the Tokio environment. The crate hides the Sans-IO state machine of `dimpl13` behind a familiar asynchronous API: `connect` / `accept`, `send` / `recv`, `close`. Each [`DtlsConnection`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html) owns a Tokio background task that manages the engine and the UDP socket.

The crate **intentionally does not support DTLS 1.2**. The engine is always created via `Dtls::new_13`, and the public API provides no way to negotiate the older version. If the peer does not support DTLS 1.3, the handshake will fail.

## Differences from `dimpl13`
- **Asynchrony.** `dimpl13` is a Sans-IO engine that you embed in your own event loop. `tokio-dtls` does this for you: it creates the socket, starts a background task, handles timers and packets, and exposes asynchronous methods.
- **Tokio integration.** It uses `tokio::net::UdpSocket`, `tokio::sync::mpsc`, and `tokio::time`. All operations (`send`, `recv`, `close`) are `async`.
- **One peer per socket with `accept`.** `accept` reads the first datagram to determine the peer address and **connects the socket to that peer**. Therefore, one socket serves one client. For many peers, you must either create a socket per connection or implement demultiplexing at the application level.
- **Shared config and certificate.** Process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. This removes the cost of `Config::builder().build()` and `generate_self_signed_certificate()` from every handshake.
- **The `warmup` function.** It allows one-time initialization (`aws-lc-rs`, `rcgen`, provider validation — up to ~90 ms on some platforms) to be moved into a predictable application startup phase.

If you need direct control over the Sans-IO engine, use the original [`dimpl13`](https://crates.io/crates/dimpl13).

### Certificate model
During the handshake, the engine emits `Output::PeerCert` with the peer's leaf certificate in DER. The crate uses the certificate to verify handshake message signatures, but **does not perform PKI validation**. The application validates the certificate according to its own policy (fingerprint, chain building, name/EKU checks, pinning, etc.).

## Asynchronous model
`DtlsConnection` is a cheap-to-clone handle to the background task. Cloning **does not create** a new connection; all clones share one session.

- `send` can be called from multiple clones simultaneously.
- `recv` is serialized internally; when used from multiple clones, messages will be interleaved arbitrarily, but they will not be lost or reordered.
- `close` is idempotent: it sends `close_notify`, waits for the engine task to complete, and if necessary forcibly aborts it after a timeout (5 s).

## Performance
By default, process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. The fast path — both values cached, default queue sizes — returns `Arc::clone` without waking the blocking pool. This removes from every handshake the cost of `Config::builder().build()` (crypto provider validation, ~3–5 ms) and `generate_self_signed_certificate()` (ECDSA key generation, ~2–5 ms), which would otherwise dominate a loopback handshake.

Call [`warmup()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/fn.warmup.html) once at process startup to move the one-time cost (AWS-LC-RS initialization, the first `rcgen` key, provider validation — up to ~90 ms on some platforms) out of the first handshake into a predictable startup phase:

After warmup, `p50` handshake time on loopback is ~2.5 ms in sequential `connect` benchmarks. The remaining time is split between `Dtls::new_13` (private key parsing) and four Tokio task switches per handshake flight; neither is controlled by this crate.

If you need non-standard queue sizes or your own certificate, build `Arc<Config>` / `Arc<DtlsCertificate>` yourself once and pass them via `ConfigOptions::dtls_config` / `ConfigOptions::dtls_cert`.

## Error handling
The public API returns `Result<T, tokio_dtls::Error>`. Errors fall into two categories:

- **Fatal connection errors.** `Error::Dtls`, `Error::Io`, `Error::CertRejected`, `Error::HandshakeFailed`, `Error::TaskFailed`, etc. mean that the connection can no longer be used. The correct response is to discard the `DtlsConnection` and, if necessary, start a new handshake. The `dimpl13` engine has no recoverable error states.
- **Backpressure and temporary conditions.** `Error::ChannelFull` (for `try_send` only) and `Ok(0)` from `send_application_data` on the engine side are not connection errors but a signal to "retry later". Asynchronous `send` uses backpressure via `mpsc::Sender::send`, so when the channel is full it simply waits instead of returning an error.

**Loss of incoming data.** If the consumer does not call `recv()` in time, the internal buffer between the engine task and `recv()` may overflow. In this case, incoming messages are dropped and the [`dropped_app_data()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html#method.dropped_app_data) counter is incremented. For a lossless stream, read `recv()` promptly or increase `ConfigOptions::channel_capacity`.

## Backpressure and queue sizes
`ConfigOptions` allows you to configure `max_queue_rx`, `max_queue_tx`, `channel_capacity`, and other parameters. If you need non-standard queue sizes, pass a custom `Arc<Config>` via `dtls_config` to avoid creating a new configuration for each connection.

The default queue sizes in `dimpl13` (`max_queue_rx = 30`, `max_queue_tx = 10`) minimize per-connection memory. At `256 / 256`, the upper bound is ~576 KB per connection (2 × 256 × 1150 B), and this memory is used only when the queues are fully loaded.

## Versioning and MSRV
- The crate follows `dimpl13` versioning and shares its cryptographic fixes.
- **MSRV**: Rust 1.88.0.
- **Status**:
  - Session resumption is not implemented (WebRTC performs a full handshake on ICE restart).
  - Renegotiation is not applicable in DTLS 1.3; use `KeyUpdate`.

## License
MPL-2.0. See `LICENSE`.

[RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
[RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714