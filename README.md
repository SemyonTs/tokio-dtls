# tokio-dtls
[![tokio-dtls](https://img.shields.io/crates/v/tokio-dtls?label=tokio-dtls&logo=rust)](https://crates.io/crates/tokio-dtls)
[![Downloads](https://img.shields.io/crates/d/tokio-dtls?label=downloads)](https://crates.io/crates/tokio-dtls)
[![License](https://img.shields.io/crates/l/tokio-dtls?label=license)](https://crates.io/crates/tokio-dtls)
[![docs.rs](https://img.shields.io/docsrs/tokio-dtls?label=docs.rs)](https://docs.rs/tokio-dtls)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**tokio-dtls** — an asynchronous wrapper around [`dimpl13`](https://crates.io/crates/dimpl13) for **DTLS 1.3 only** in the Tokio environment. The crate hides the Sans-IO state machine of `dimpl13` behind a familiar asynchronous API: `connect` / `accept`, `send` / `recv`, `close`. Each [`DtlsConnection`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html) owns a Tokio background task that manages the engine and the UDP socket, and a [`DtlsServer`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsServer.html) multiplexes many peers over a **single** UDP socket.

The crate **intentionally does not support DTLS 1.2**. The engine is always created via `Dtls::new_13`, and the public API provides no way to negotiate the older version. If the peer does not support DTLS 1.3, the handshake will fail.

## Supported DTLS 1.3 extensions

Five protocol features are exposed through `dimpl13::Config` and, where they have an observable result, through `DtlsConnection`:

| Feature | Direction | How to configure | How to read |
|---|---|---|---|
| **ALPN** (RFC 7301) | both | `Config::builder().alpn_protocols(&[b"h2", …])` | `DtlsConnection::negotiated_alpn()` |
| **SNI** (RFC 6066) | client → server | `Config::builder().server_name("example.com")` | `DtlsConnection::peer_server_name()` |
| **Connection ID** (RFC 9146) | both | `Config::builder().connection_id(&[…])` | transparent |
| **Record Size Limit** (RFC 8449) | both, asymmetrical | `Config::builder().record_size_limit(1200)` | transparent |
| **SRTP keying material** (RFC 5764 / RFC 7714) | both | `Config::builder().use_srtp(&[…])` | `DtlsConnection::keying_material()` |

Details:

- **ALPN.** The client offers a list; the server picks one from its own preference list. Both sides return the selected protocol via `negotiated_alpn()`. If no protocol matches, the server aborts with `Error::Dtls(SecurityError::NoCommonAlpnProtocol)`. This is the correct RFC 7301 behavior.
- **SNI.** The client sends a server name; the server can read it via `peer_server_name()`. Always `None` on the client. tokio-dtls does **not** validate that the SNI matches the peer's certificate — that's the application's policy.
- **Connection ID.** Requires **both** sides to configure one; otherwise it is silently disabled and the wire format falls back to the standard record header. Transparent to `send` / `recv`. This is the mechanism that keeps a session alive across NAT rebinding.
- **Record Size Limit.** Each side advertises a maximum outgoing record size; the peer's limit is applied to our outgoing records. Default `16385` (`Config::default()`). Asymmetrical: it is enough for one side to set it. Useful for constrained networks or path-MTU-constrained tunnels.
- **SRTP keying material.** Requires `use_srtp` on both sides. After the handshake, the engine emits `Output::KeyingMaterial(material, profile)` (RFC 5764 / RFC 7714). `DtlsConnection::keying_material().await` returns `Some((material, profile))` — see [Keying material (DTLS-SRTP)](#keying-material-dtls-srtp).

The process-wide shared `Config` (used when `ConfigOptions::dtls_config` is `None`) advertises **no ALPN, no SNI, no Connection ID, no SRTP**, and the default Record Size Limit. **To enable any of these, build your own `Arc<Config>` once at startup** and pass it via [`ConfigOptions::dtls_config`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.ConfigOptions.html#structfield.dtls_config).

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

This example uses the process-wide shared `Config` — no ALPN, no SNI, no Connection ID, no SRTP, default Record Size Limit. For negotiated-parameter behavior, use `connect_with` / `accept_with` and a custom `Arc<Config>` (see above).

## Keying material (DTLS-SRTP)

`dimpl13` emits `Output::KeyingMaterial(material, profile)` (RFC 5764 / RFC 7714) after a handshake in which `use_srtp` was negotiated. tokio-dtls forwards that variant and exposes it via [`DtlsConnection::keying_material`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html#method.keying_material):

```rust
use tokio_dtls::{DtlsConnection, SrtpProfile};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let conn = DtlsConnection::connect("127.0.0.1:4433", |_| true).await?;
if let Some((material, profile)) = conn.keying_material().await {
    println!("SRTP profile: {:?}, {} bytes", profile, material.len());
    // feed `material` + `profile` into your SRTP context
}
# Ok(())
# }
```

- `material` is the raw exported key material. For `SRTP_AES128_CM_HMAC_SHA1_80` this is **60 bytes** (`2 × (16 + 14)`); for `SRTP_AEAD_AES_128_GCM`, **56 bytes** (`2 × (16 + 12)`).
- `profile` is re-exported as [`SrtpProfile`](https://docs.rs/tokio-dtls/latest/tokio_dtls/enum.SrtpProfile.html) so callers do not need a direct `dimpl13` dependency.
- Byte layout follows RFC 5764 §4.2: `client_write_key || server_write_key || client_write_salt || server_write_salt`. Both sides export the same bytes.

**Without `use_srtp`, the engine never emits `KeyingMaterial`**, and `keying_material().await` returns `None` once the connection terminates. If you need DTLS-SRTP, configure it explicitly:

```rust
let config = Arc::new(
    dimpl13::Config::builder()
        .use_srtp(&[
            dimpl13::SrtpProfile::SRTP_AES128_CM_HMAC_SHA1_80,
            dimpl13::SrtpProfile::SRTP_AEAD_AES_128_GCM,
        ])
        .build()?,
);
```

## Multiplexing: `DtlsServer`

[`DtlsServer`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsServer.html) binds one `UdpSocket` and demultiplexes incoming datagrams by peer address, spawning a per-peer DTLS engine. Each accepted `DtlsConnection` is fully independent: its own handshake, its own certificate validator, its own ALPN/SNI/CID, its own keying material.

```rust
use tokio_dtls::{ConfigOptions, DtlsServer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut server = DtlsServer::bind(
    "0.0.0.0:4433",
    |_cert| true, // per-peer validator; replace with real validation
    ConfigOptions::default(),
).await?;

loop {
    let conn = server.accept().await?;
    tokio::spawn(async move {
        let _ = conn.send(b"hello").await;
        let _ = conn.recv().await;
    });
}
# Ok(())
# }
```

Key properties:

- **One socket, many peers.** No `SO_REUSEPORT`, no per-connection binds. Sessions are keyed by `SocketAddr`.
- **Independent handshakes.** A new `ClientHello` for a peer that already has a session in progress is routed to the existing session; when a session ends, its entry is removed and the next `ClientHello` from the same address starts a fresh one.
- **Bounded accept queue.** Handshake-complete connections are pushed into a fixed-capacity queue (currently 64). If it fills, further completed handshakes wait inside their per-session tasks; engines keep running, so no data is lost (within per-session buffers).
- **`session_count()`** returns the number of active peer sessions (handshaking or established).
- **Shutdown.** Dropping the `DtlsServer` stops the multiplexer task and closes the accept queue. Already-accepted `DtlsConnection` handles keep working; the shared socket lives as long as at least one of them is alive.

**When not to use `DtlsServer`.** If you already own a socket and prefer to `connect()` it yourself (e.g. you have a single-client service, or you implement your own demux layer), use `DtlsConnection::connect_with` / `accept_with` directly. Those take a `UdpSocket` you provide, or bind and connect a fresh one.

## Differences from `dimpl13`
- **Asynchrony.** `dimpl13` is a Sans-IO engine that you embed in your own event loop. `tokio-dtls` does this for you: it creates the socket, starts a background task, handles timers and packets, and exposes asynchronous methods.
- **Tokio integration.** It uses `tokio::net::UdpSocket`, `tokio::sync::mpsc`, and `tokio::time`. All operations (`send`, `recv`, `close`) are `async`.
- **Multiplexing.** `DtlsServer` demultiplexes many peers over one `UdpSocket`. For single-peer use, `DtlsConnection::accept` reads the first datagram to determine the peer address and **connects the socket to that peer** — one socket, one client. Prefer `DtlsServer` for multi-peer workloads.
- **Shared config and certificate.** Process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. This removes the cost of `Config::builder().build()` and `generate_self_signed_certificate()` from every handshake. The shared config, however, offers none of the negotiated extensions above and does not negotiate `use_srtp`.
- **The `warmup` function.** It allows one-time initialization (`aws-lc-rs`, `rcgen`, provider validation — up to ~90 ms on some platforms) to be moved into a predictable application startup phase.
- **Keying material.** `Output::KeyingMaterial` is forwarded to `DtlsConnection::keying_material()` when `use_srtp` is negotiated. `SrtpProfile` is re-exported for convenience.

If you need direct control over the Sans-IO engine, use the original [`dimpl13`](https://crates.io/crates/dimpl13).

### Certificate model
During the handshake, the engine emits `Output::PeerCert` with the peer's leaf certificate in DER. The crate uses the certificate to verify handshake message signatures, but **does not perform PKI validation**. The application validates the certificate according to its own policy (fingerprint, chain building, name/EKU checks, pinning, etc.).

With `DtlsServer`, the validator is invoked **per peer**, so each accepted `DtlsConnection` can enforce a different policy (or, more commonly, a per-server policy applied uniformly across all peers of that server).

## Asynchronous model
`DtlsConnection` is a cheap-to-clone handle to the background task. Cloning **does not create** a new connection; all clones share one session.

- `send` can be called from multiple clones simultaneously.
- `recv` is serialized internally; when used from multiple clones, messages will be interleaved arbitrarily, but they will not be lost or reordered.
- `close` is idempotent: it sends `close_notify`, waits for the engine task to complete, and if necessary forcibly aborts it after a timeout (5 s).
- `negotiated_alpn()`, `peer_server_name()`, and `keying_material()` return values captured at or after handshake completion. For `DtlsConnection` created via `connect*` / `accept*`, the handshake is guaranteed complete when the constructor returns. For `DtlsConnection` obtained from `DtlsServer::accept`, the same holds — `accept` yields only handshake-complete connections.

For `DtlsServer`:

- `bind` starts the multiplexer and returns immediately.
- `accept` yields the next handshake-complete `DtlsConnection`; it can be called from a single task (the `&mut self` receiver serializes it) or from multiple tasks via `&mut` splitting.
- `session_count()` returns the number of active peer sessions (handshaking or established).
- Dropping the server aborts the multiplexer; already-accepted connections continue to run.

## Performance
By default, process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. The fast path — both values cached, default queue sizes — returns `Arc::clone` without waking the blocking pool. This removes from every handshake the cost of `Config::builder().build()` (crypto provider validation, ~3–5 ms) and `generate_self_signed_certificate()` (ECDSA key generation, ~2–5 ms), which would otherwise dominate a loopback handshake.

When you pass **both** `ConfigOptions::dtls_config` and `ConfigOptions::dtls_cert`, connection setup is a pure `Arc::clone` with no blocking-pool involvement — strictly faster than the shared-cache path, and the only way to enable ALPN / SNI / Connection ID / custom Record Size Limit / SRTP.

Call [`warmup()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/fn.warmup.html) once at process startup to move the one-time cost (AWS-LC-RS initialization, the first `rcgen` key, provider validation — up to ~90 ms on some platforms) out of the first handshake into a predictable startup phase:

```rust
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
tokio_dtls::warmup().await?;
// ... start accepting / connecting ...
# Ok(())
# }
```

After warmup, `p50` handshake time on loopback is ~0.9 ms in sequential `connect` benchmarks. The remaining time is split between `Dtls::new_13` (private key parsing) and four Tokio task switches per handshake flight; neither is controlled by this crate.

`DtlsServer` adds one demultiplexer task and one per-peer task; the per-peer cost (channel, buffers, engine) is identical to a standalone `DtlsConnection`. Datagram dispatch is a `HashMap<SocketAddr, Sender>` lookup followed by `try_send`, so mux overhead is O(1) per packet and does not depend on the number of active peers.

## Error handling
The public API returns `Result<T, tokio_dtls::Error>`. Errors fall into two categories:

- **Fatal connection errors.** `Error::Dtls`, `Error::Io`, `Error::CertRejected`, `Error::HandshakeFailed`, `Error::TaskFailed`, etc. mean that the connection can no longer be used. The correct response is to discard the `DtlsConnection` and, if necessary, start a new handshake. The `dimpl13` engine has no recoverable error states. This includes ALPN mismatch on the server side: the server aborts with `Error::Dtls(SecurityError::NoCommonAlpnProtocol)`.
- **Backpressure and temporary conditions.** `Error::ChannelFull` (for `try_send` only) and `Ok(0)` from `send_application_data` on the engine side are not connection errors but a signal to "retry later". Asynchronous `send` uses backpressure via `mpsc::Sender::send`, so when the channel is full it simply waits instead of returning an error.

`DtlsServer::accept` returns `Error::Closed` once the server has been dropped. Individual session failures (rejected certificates, handshake timeouts, I/O errors) are surfaced inside the per-session tasks and do not terminate the server; the peer simply never appears in the accept queue.

**Loss of incoming data.** If the consumer does not call `recv()` in time, the internal buffer between the engine task and `recv()` may overflow. In this case, incoming messages are dropped and the [`dropped_app_data()`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html#method.dropped_app_data) counter is incremented. For a lossless stream, read `recv()` promptly or increase `ConfigOptions::channel_capacity`.

## Backpressure and queue sizes
`ConfigOptions` allows you to configure `max_queue_rx`, `max_queue_tx`, `channel_capacity`, and other parameters. If you need non-standard queue sizes, pass a custom `Arc<Config>` via `dtls_config` to avoid creating a new configuration for each connection.

tokio-dtls's defaults (`max_queue_rx = 256`, `max_queue_tx = 256`) trade per-connection memory for headroom on mid-throughput workloads. At 256 / 256, the upper bound is ~576 KB per connection (2 × 256 × 1150 B), and this memory is used only when the queues are fully loaded. For minimal per-connection memory (as low as ~46 KB at dimpl13's own `30 / 10` defaults), build your own `Config` and pass it via `dtls_config`.

When running `DtlsServer` with many peers, multiply this bound by the number of active sessions when sizing your process. Each peer has its own queues; there is no cross-peer sharing.

## Examples

The `examples/` directory contains two working end-to-end demos that exercise the full extension set described above — **ALPN, SNI, Connection ID, Record Size Limit** — over a real application protocol: TFTP with RFC 2347–2349 option negotiation (`blksize`, `tsize`, `timeout`).

| Example | Uses | Demonstrates |
|---|---|---|
| [`examples/tftp-server.rs`](examples/tftp-server.rs) | `tokio_dtls::DtlsServer` | **Multiplexing** many concurrent peers over one socket, per-session tasks, graceful `close`, serving files from a directory |
| [`examples/tftp-client.rs`](examples/tftp-client.rs) | `tokio_dtls::DtlsConnection` | **Concurrent downloads** — one independent DTLS connection per file, driven by `tokio::spawn` |

Both binaries build an identical `Arc<dimpl13::Config>` — ALPN `"tftp/1"`, SNI `"tftp.local"`, an 8-byte Connection ID, and `record_size_limit(1200)` — so they interoperate with each other, and they also serve as a smoke test for the extension plumbing described above.

### Running the examples

Start the server in one terminal:

```sh
cargo run --example tftp-server -- 127.0.0.1:6969 ./public
```

The first argument is the bind address; the second is the directory to serve (must exist). The server **multiplexes** all DTLS sessions on one UDP socket; each accepted session is handled in a `tokio::spawn`-ed task, and the negotiated ALPN / SNI are logged per session.

In another terminal, fetch one or more files:

```sh
cargo run --example tftp-client -- 127.0.0.1:6969 README.md
cargo run --example tftp-client -- 127.0.0.1:6969 big.bin small1.bin small2.bin small3.bin
```

The client sends an RRQ with `blksize=1024`, `tsize=0`, and `timeout=5`, honours the server's OACK, transfers the file in DATA/ACK blocks, and writes the result to `received_<filename>` in the current directory. With multiple filenames it opens **one DTLS connection per file** and downloads them concurrently.

To stress the multiplexer, run multiple clients in parallel:

```sh
for f in big.bin small1.bin small2.bin small3.bin; do
    cargo run --example tftp-client -- 127.0.0.1:6969 "$f" &
done
wait
```

The server will report several concurrent `--- session peer=… ---` blocks interleaved, and `session_count()` will reflect the active set.

### Why two flavours of client?

The client intentionally spawns one `DtlsConnection` per file rather than serialising downloads. This is the client-side counterpart to the server-side `DtlsServer`: it demonstrates that multiple independent DTLS sessions can be driven from the same application without sharing state, and it doubles as a load test for the multiplexer.

If you need a **sync** client (e.g. embedding `dimpl13` into a non-Tokio event loop), see the crate-level docs of `dimpl13` — the pattern is `poll_output` / `handle_packet` / `handle_timeout` in a loop, as the original pre-multiplexing version of this example did.

## Versioning and MSRV
- The crate follows `dimpl13` versioning and shares its cryptographic fixes.
- **MSRV**: Rust 1.88.0.
- **Status**:
  - Session resumption is not implemented (WebRTC performs a full handshake on ICE restart).
  - Renegotiation is not applicable in DTLS 1.3; use `KeyUpdate`.
  - **SRTP keying material** is exported via `DtlsConnection::keying_material()` when `use_srtp` is negotiated. `SrtpProfile` is re-exported as `tokio_dtls::SrtpProfile`.

## License
MPL-2.0. See `LICENSE`.