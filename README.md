# tokio-dtls
[![tokio-dtls](https://img.shields.io/crates/v/tokio-dtls?label=tokio-dtls&logo=rust)](https://crates.io/crates/tokio-dtls)
[![Downloads](https://img.shields.io/crates/d/tokio-dtls?label=downloads)](https://crates.io/crates/tokio-dtls)
[![License](https://img.shields.io/crates/l/tokio-dtls?label=license)](https://crates.io/crates/tokio-dtls)
[![docs.rs](https://img.shields.io/docsrs/tokio-dtls?label=docs.rs)](https://docs.rs/tokio-dtls)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://blog.rust-lang.org/)

**tokio-dtls** — an asynchronous wrapper around [`dimpl13`](https://crates.io/crates/dimpl13) for **DTLS 1.3 only** in the Tokio environment. The crate hides the Sans-IO state machine of `dimpl13` behind a familiar asynchronous API: `connect` / `accept`, `send` / `recv`, `close`. Each [`DtlsConnection`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html) owns a Tokio background task that manages the engine and the UDP socket, and a [`DtlsServer`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsServer.html) multiplexes many peers over a **single** UDP socket.

The crate **intentionally does not support DTLS 1.2**. The engine is always created via `Dtls::new_13`, and the public API provides no way to negotiate the older version. If the peer does not support DTLS 1.3, the handshake will fail.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `webpki` | off | Enables the [`webpki`](https://docs.rs/tokio-dtls/latest/tokio_dtls/webpki/index.html) module with a ready-made [`WebPkiVerifier`](https://docs.rs/tokio-dtls/latest/tokio_dtls/webpki/struct.WebPkiVerifier.html) based on [`rustls-webpki`](https://docs.rs/rustls-webpki). Without this feature, the crate has no WebPKI dependency and the application supplies its own [`CertValidator`](https://docs.rs/tokio-dtls/latest/tokio_dtls/type.CertValidator.html). |

```toml
# Default build: no PKI validation, application provides a validator.
tokio-dtls = "0.4"

# With the ready-made WebPKI validator.
tokio-dtls = { version = "0.4", features = ["webpki"] }
```

The `webpki` feature pulls in `rustls-webpki` with the `ring` crypto backend. If your workspace already uses `aws-lc-rs` and you want to avoid pulling in `ring`, enable the `aws-lc-rs` feature on `rustls-webpki` directly and disable `ring` in your `Cargo.toml`.

## Certificate validation

During the handshake, the engine emits `Output::PeerCert(leaf_der)` with the peer's **leaf** certificate in DER. The crate uses the certificate to verify handshake message signatures, but **does not perform PKI validation by default**. The application supplies a [`CertValidator`](https://docs.rs/tokio-dtls/latest/tokio_dtls/type.CertValidator.html) — an `Arc<dyn Fn(&[u8]) -> bool + Send + Sync>` — that receives the leaf DER and returns `true` to accept.

Three options are available:

| Approach | When to use | Feature |
|---|---|---|
| **Custom closure** | You have a specific policy (SPKI pin, allow-list of SANs, custom CA store, …) | — |
| **`PinnedCertValidator`** | Self-signed certificates (common in DTLS) | — |
| **`WebPkiVerifier`** | Full RFC 5280 chain validation against trust anchors or the Mozilla root store | `webpki` |

With `DtlsServer`, the validator is invoked **per peer**, so each accepted `DtlsConnection` can enforce a different policy (or, more commonly, a per-server policy applied uniformly across all peers of that server).

### Pinning self-signed certificates

[`PinnedCertValidator`](https://docs.rs/tokio-dtls/latest/tokio_dtls/cert/struct.PinnedCertValidator.html) compares the SHA-256 fingerprint of the peer's certificate against a known value. It does not perform any chain building and therefore works with certificates that are not CAs — which is exactly what `dimpl13::certificate::generate_self_signed_certificate()` produces.

```rust
use tokio_dtls::cert::PinnedCertValidator;
use tokio_dtls::{ConfigOptions, DtlsConnection};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// Read the expected peer certificate (DER) from disk, config, or env.
let expected_peer_cert_der = std::fs::read("peer-cert.der")?;
let pin = PinnedCertValidator::new(&expected_peer_cert_der);

let conn = DtlsConnection::connect_with(
    "127.0.0.1:4433",
    move |der| pin.verify(der),
    ConfigOptions::default(),
).await?;
# Ok(())
# }
```

The validator is cheap to clone, so a single `PinnedCertValidator` can serve many connections. `from_fingerprint([u8; 32])` builds a pin directly from a precomputed SHA-256 hash if you'd rather not ship the certificate.

### Using the `webpki` feature

Enable the feature:

```toml
tokio-dtls = { version = "0.4", features = ["webpki"] }
```

The `tokio_dtls::webpki` module provides a builder:

```rust
use tokio_dtls::webpki::WebPkiVerifier;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// 1. Public CA: system roots + intermediate + name check.
let validator = WebPkiVerifier::builder()
    .with_webpki_roots()
    .with_intermediate_pem(&std::fs::read("intermediate.pem")?)?
    .with_server_name("example.com".try_into()?)
    .build()?
    .into_validator();

// 2. Client certificate on the server side.
let validator = WebPkiVerifier::builder()
    .trust_anchor_pem(&std::fs::read("client-ca.pem")?)?
    .with_key_usage(rustls_webpki::KeyUsage::client_auth())
    .build()?
    .into_validator();
# let _ = validator;
# Ok(())
# }
```

The builder:

| Method | Purpose |
|---|---|
| `trust_anchor_der(Vec<u8>)` | Add a DER trust anchor. |
| `trust_anchor_pem(&[u8]) -> Result<Self, WebPkiError>` | Parse the first certificate from PEM and add it as an anchor. |
| `with_webpki_roots()` | Add the Mozilla root store (`webpki-roots`, pre-parsed; no per-handshake cost). |
| `with_intermediate_der(Vec<u8>)` | Add a DER intermediate for path building. |
| `with_intermediate_pem(&[u8]) -> Result<Self, WebPkiError>` | Parse the first certificate from PEM as an intermediate. |
| `with_server_name(ServerName<'static>)` | Require the leaf to be valid for this name (DNS/IP). |
| `with_key_usage(KeyUsage)` | Set `server_auth` (default) or `client_auth`. |
| `build() -> Result<WebPkiVerifier, WebPkiError>` | Fail early if no trust anchors were provided. |

`WebPkiVerifier` has two consumers:

- `into_validator() -> CertValidator` — the closure form expected by `connect_with` / `accept_with` / `DtlsServer::bind`. Rejections are logged at `tracing::debug`; the caller only sees `bool`.
- `verify(leaf_der) -> Result<(), WebPkiError>` — returns the full error (`NoTrustAnchors`, `InvalidAnchor`, `Pem`, `InvalidCertificate`, `Validation`, `NameMismatch`). Use this when you need detailed diagnostics in logs or tests.

### Important: `dimpl13` sends only the leaf certificate

`dimpl13` emits `Output::PeerCert(leaf_der)` and does **not** forward the intermediate certificates from the TLS `Certificate` message. This has two consequences:

1. If the peer's leaf is signed by an intermediate CA (the normal case for publicly trusted certificates), chain building will fail unless you add the intermediate(s) via `with_intermediate_der` / `with_intermediate_pem`.
2. For self-signed certificates, **use `PinnedCertValidator`** rather than `WebPkiVerifier`. `WebPkiVerifier` treats a self-signed leaf as its own trust anchor, which works but is semantically wrong (it pretends the leaf is a CA) and provides no advantage over pinning.

If `anchor_from_trusted_cert` cannot parse an anchor (e.g. it is not a CA certificate, or the DER is malformed), the verifier logs a `tracing::warn!` with the exact error and skips the anchor. Enabling `RUST_LOG=tokio_dtls=debug` makes this visible during development.

## Supported DTLS 1.3 extensions

Five protocol features are exposed through `dimpl13::Config` and, where they have an observable result, through `DtlsConnection`:

| Feature | Direction | How to configure | How to read |
|---|---|---|---|
| **ALPN** (RFC 7301) | both | `Config::builder().alpn_protocols(&[b"h2", …])` | `DtlsConnection::negotiated_alpn()` |
| **SNI** (RFC 6066) | client → server | `Config::builder().server_name("example.com")` | `DtlsConnection::peer_server_name()` |
| **Connection ID** (RFC 9146) | both | `Config::builder().connection_id(&[…])` | transparent |
| **Record Size Limit** (RFC 8449) | both, asymmetrical | `Config::builder().record_size_limit(1200)` | transparent |
| **SRTP keying material** (RFC 5764 / RFC 7714) | both | advertised by default via `SrtpProfile::ALL` | `DtlsConnection::keying_material()` |

Details:

- **ALPN.** The client offers a list; the server picks one from its own preference list. Both sides return the selected protocol via `negotiated_alpn()`. If no protocol matches, the server's engine aborts with a fatal alert. On the client side this surfaces as `Error::HandshakeFailed` **after `handshake_timeout`** — the alert is processed by the engine, but `dimpl13` does not surface it as an immediate `Err`, so `tokio-dtls` relies on the handshake timer to convert the silent failure into an application-visible error. This is the correct RFC 7301 behavior with the caveat that detection is not instantaneous.
- **SNI.** The client sends a server name; the server can read it via `peer_server_name()`. Always `None` on the client (SNI is a client-only signal). tokio-dtls does **not** validate that the SNI matches the peer's certificate — that's the application's policy.
- **Connection ID.** Requires **both** sides to configure one; otherwise it is silently disabled and the wire format falls back to the standard record header. Transparent to `send` / `recv`. This is the mechanism that keeps a session alive across NAT rebinding.
- **Record Size Limit.** Each side advertises a maximum outgoing record size; the peer's limit is applied to our outgoing records. Default `16385` (`Config::default()`). Asymmetrical: it is enough for one side to set it. Useful for constrained networks or path-MTU-constrained tunnels.
- **SRTP keying material.** `dimpl13` advertises `use_srtp` with `SrtpProfile::ALL` by default and exports keying material after a successful handshake in which SRTP was negotiated. See [Keying material (DTLS-SRTP)](#keying-material-dtls-srtp).

The process-wide shared `Config` (used when `ConfigOptions::dtls_config` is `None`) advertises **no ALPN, no SNI, no Connection ID**, and the default Record Size Limit. **To enable any of these, build your own `Arc<Config>` once at startup** and pass it via [`ConfigOptions::dtls_config`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.ConfigOptions.html#structfield.dtls_config). SRTP needs no explicit configuration — it is on by default.

```rust
use std::sync::Arc;
use dimpl13::{certificate, Config};
use tokio_dtls::cert::PinnedCertValidator;
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
let pin = PinnedCertValidator::new(&cert.certificate);

let conn = DtlsConnection::connect_with(
    "127.0.0.1:4433",
    move |der| pin.verify(der),
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

## Keying material (DTLS-SRTP)

`dimpl13` advertises SRTP (`use_srtp`) with all supported profiles ([`SrtpProfile::ALL`]) by default and emits `Output::KeyingMaterial(material, profile)` (RFC 5764 / RFC 7714) after a handshake in which SRTP was negotiated. `tokio-dtls` forwards that variant and exposes it via [`DtlsConnection::keying_material`](https://docs.rs/tokio-dtls/latest/tokio_dtls/struct.DtlsConnection.html#method.keying_material):

```rust
use tokio_dtls::{DtlsConnection, SrtpProfile};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let conn = DtlsConnection::connect("127.0.0.1:4433", |_| true).await?;
if let Some((material, profile)) = conn.keying_material().await {
    println!("SRTP profile: {profile:?}, {} bytes", material.len());
    // feed `material` + `profile` into your SRTP context
}
# Ok(())
# }
```

- `material` is the raw exported key material. Length depends on the selected profile:
  - `SrtpProfile::AES128_CM_SHA1_80` — **60 bytes** (`2 × (16 + 14)`).
  - `SrtpProfile::AEAD_AES_128_GCM` — **56 bytes** (`2 × (16 + 12)`).
  - `SrtpProfile::AEAD_AES_256_GCM` — **88 bytes** (`2 × (32 + 12)`).
- `profile` is re-exported as [`SrtpProfile`](https://docs.rs/tokio-dtls/latest/tokio_dtls/enum.SrtpProfile.html) so callers do not need a direct `dimpl13` dependency. The enum is `#[non_exhaustive]`; match with a trailing `_` arm.
- Byte layout follows RFC 5764 §4.2: `client_write_key || server_write_key || client_write_salt || server_write_salt`. Both sides export the same bytes.

**No explicit configuration is required.** `dimpl13` offers `use_srtp` in every handshake with `SrtpProfile::ALL`, so `keying_material().await` resolves to `Some((material, profile))` as soon as the handshake completes against a peer that also supports SRTP. It returns `None` only when the peer did not negotiate `use_srtp` (e.g. a non-WebRTC peer that ignored the extension), or when the engine exits without producing it.

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

## Asynchronous model

`DtlsConnection` is a cheap-to-clone handle to the background task. Cloning **does not create** a new connection; all clones share one session.

- `send` can be called from multiple clones simultaneously.
- `recv` is serialized internally; when used from multiple clones, messages will be interleaved arbitrarily, but they will not be lost or reordered.
- `close` is idempotent: it sends `close_notify`, waits for the engine task to complete, and if necessary forcibly aborts it after a timeout (5 s). Any application data queued via `send` before `close` is flushed to the wire first.
- `negotiated_alpn()`, `peer_server_name()`, and `keying_material()` return values captured at or after handshake completion. For `DtlsConnection` created via `connect*` / `accept*`, the handshake is guaranteed complete when the constructor returns. For `DtlsConnection` obtained from `DtlsServer::accept`, the same holds — `accept` yields only handshake-complete connections.

For `DtlsServer`:

- `bind` starts the multiplexer and returns immediately.
- `accept(&mut self)` yields the next handshake-complete `DtlsConnection`. It takes `&mut self`, so if you need to call `accept` from multiple tasks, wrap the server in `Arc<tokio::sync::Mutex<_>>`. In the common case (one accept loop + `tokio::spawn` per connection), `&mut self` is sufficient.
- `session_count()` returns the number of active peer sessions (handshaking or established).
- Dropping the server aborts the multiplexer; already-accepted connections continue to run.

## Differences from `dimpl13`

- **Asynchrony.** `dimpl13` is a Sans-IO engine that you embed in your own event loop. `tokio-dtls` does this for you: it creates the socket, starts a background task, handles timers and packets, and exposes asynchronous methods.
- **Tokio integration.** It uses `tokio::net::UdpSocket`, `tokio::sync::mpsc`, and `tokio::time`. All operations (`send`, `recv`, `close`) are `async`.
- **Multiplexing.** `DtlsServer` demultiplexes many peers over one `UdpSocket`. For single-peer use, `DtlsConnection::accept` reads the first datagram to determine the peer address and **connects the socket to that peer** — one socket, one client. Prefer `DtlsServer` for multi-peer workloads.
- **Shared config and certificate.** Process-global `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily on first use and reused. This removes the cost of `Config::builder().build()` and `generate_self_signed_certificate()` from every handshake. The shared config, however, offers none of the negotiated extensions above (SRTP is the exception — it is on by default).
- **The `warmup` function.** It allows one-time initialization (`aws-lc-rs`, `rcgen`, provider validation — up to ~90 ms on some platforms) to be moved into a predictable application startup phase.
- **Keying material.** `Output::KeyingMaterial` is forwarded to `DtlsConnection::keying_material()` when `use_srtp` is negotiated. `SrtpProfile` is re-exported for convenience.
- **Certificate validators.** Two ready-made validators (`PinnedCertValidator`, `WebPkiVerifier`) are provided, and the `CertValidator` type alias is available for custom policies.
- **Optional WebPKI validation.** With the `webpki` feature, `tokio_dtls::webpki::WebPkiVerifier` wraps `rustls-webpki` with an ergonomic builder and integrates with `CertValidator`. Without the feature, the crate has no WebPKI dependency; `dimpl13` itself leaves PKI validation entirely to the application.

If you need direct control over the Sans-IO engine, use the original [`dimpl13`](https://crates.io/crates/dimpl13).

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

After warmup, `p50` handshake time on loopback is ~0.9 ms in sequential `connect` benchmarks. The remaining time is split between `Dtls::new_13` (private key parsing) and four Tokio task switches per handshake flight; neither is controlled by this crate.

`DtlsServer` adds one demultiplexer task and one per-peer task; the per-peer cost (channel, buffers, engine) is identical to a standalone `DtlsConnection`. Datagram dispatch is a `HashMap<SocketAddr, Sender>` lookup followed by `try_send`, so mux overhead is O(1) per packet and does not depend on the number of active peers.

The `webpki` feature adds per-handshake verification cost: chain building and signature checks for every peer. With `with_webpki_roots()`, the root store itself is pre-parsed; only the leaf (and any intermediates you supplied) is processed per handshake. Trust anchors supplied as raw DER are re-parsed on every call — if you need hot-path performance, prefer `with_webpki_roots()` for public CAs and a single DER anchor for a fixed private CA.

## Error handling

The public API returns `Result<T, tokio_dtls::Error>`. Errors fall into two categories:

- **Fatal connection errors.** `Error::Dtls`, `Error::Io`, `Error::CertRejected`, `Error::HandshakeFailed`, `Error::TaskFailed`, etc. mean that the connection can no longer be used. The correct response is to discard the `DtlsConnection` and, if necessary, start a new handshake. The `dimpl13` engine has no recoverable error states.
- **Backpressure and temporary conditions.** `Error::ChannelFull` (for `try_send` only) and `Ok(0)` from `send_application_data` on the engine side are not connection errors but a signal to "retry later". Asynchronous `send` uses backpressure via `mpsc::Sender::send`, so when the channel is full it simply waits instead of returning an error.

`DtlsServer::accept` returns `Error::Closed` once the server has been dropped. Individual session failures (rejected certificates, handshake timeouts, I/O errors) are surfaced inside the per-session tasks and do not terminate the server; the peer simply never appears in the accept queue.

When a validator returns `false`, the engine aborts the handshake and the connection is closed with `Error::CertRejected`. With `webpki`, the underlying reason (`Validation`, `NameMismatch`, etc.) is available via `WebPkiVerifier::verify` — use it directly in tests or custom logging if you need to know **why** a certificate was rejected.

**Handshake failure detection.** When the peer sends a fatal alert that the underlying engine does not surface as an immediate `Err` (e.g. ALPN mismatch, `bad_certificate`), the client will not return an error the moment the alert arrives. Instead, `connect_with` returns `Error::HandshakeFailed` when `handshake_timeout` expires. The default is 30 s; if you want faster failure in such cases, set `ConfigOptions::handshake_timeout` to a smaller value. The engine task does not hang forever — the timer fires at `handshake_timeout`, not at an internal 24-hour ceiling.

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

Both binaries build an identical `Arc<dimpl13::Config>` — ALPN `"tftp/1"`, SNI `"tftp.local"`, an 8-byte Connection ID, and `record_size_limit(1200)` — so they interoperate with each other, and they also serve as a smoke test for the extension plumbing described above. Both use the trivial `|_der| true` validator; if you want to see `PinnedCertValidator` or `WebPkiVerifier` in action, swap it in at `DtlsServer::bind` / `DtlsConnection::connect_with`.

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

## Testing

The crate ships with **23 unit tests + 3 doc-tests**, all of which run on loopback (`127.0.0.1`) and never leave the local host:

```sh
cargo test
cargo test --features webpki
```

The WebPKI tests are feature-gated; the default test run does not compile or download any WebPKI dependency. Coverage:

- Lifecycle: `connect` / `accept` / `send` / `recv` / `close` / `wait_closed`, idempotent close, `try_send` after close.
- Extensions: ALPN (success + mismatch), SNI (read on the server), Connection ID, Record Size Limit.
- SRTP: `srtp_keying_material_matches` verifies that both sides export identical keying material and agree on the profile, and that the material length matches `SrtpProfile::keying_material_len()`.
- Multiplexing: three concurrent peers over one `DtlsServer`, `session_count()`.
- Certificate validation: `PinnedCertValidator` accept/reject, custom closure, `WebPkiVerifier` accept/reject/name-mismatch.
- Errors: invalid address, rejected certificate, handshake timeout on ALPN mismatch.
- Baseline: `warmup()` is idempotent, `ConfigOptions::default()` values.

## Versioning and MSRV

- **MSRV**: Rust 1.88.0.
- **Status**:
  - Session resumption is not implemented (WebRTC performs a full handshake on ICE restart).
  - Renegotiation is not applicable in DTLS 1.3; use `KeyUpdate`.
  - **SRTP keying material** is advertised by `dimpl13` by default and exported via `DtlsConnection::keying_material()`. `SrtpProfile` is re-exported as `tokio_dtls::SrtpProfile`.
  - **WebPKI certificate validation** is available behind the opt-in `webpki` feature. Without it, tokio-dtls has no WebPKI dependency.
  - **Pinning** (`PinnedCertValidator`) is always available with no extra dependency.

## License

MPL-2.0. See `LICENSE`.