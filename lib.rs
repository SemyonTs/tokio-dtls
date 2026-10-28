// tokio-dtls Copyright (c) 2026 Semyon Tsarev
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// project, You can obtain one at https://mozilla.org/MPL/2.0/.
//! # tokio-dtls
//!
//! Async **DTLS 1.3 only** wrapper around [`dimpl13`] for Tokio.
//!
//! ## DTLS 1.3 only
//!
//! This crate **intentionally does not support DTLS 1.2**. The underlying
//! engine is always constructed with `Dtls::new_13`, and the public API
//! exposes no option to negotiate an older version. If a peer does not
//! support DTLS 1.3, the handshake will fail.
//!
//! ## Negotiated parameters
//!
//! Four DTLS extensions are supported and exposed through [`dimpl13::Config`]:
//!
//! - **ALPN** (RFC 7301) — client and server exchange application protocols;
//!   the server picks one. Read the result from
//!   [`DtlsConnection::negotiated_alpn`] on both sides.
//! - **SNI** (RFC 6066) — the client advertises the server name. Read it from
//!   [`DtlsConnection::peer_server_name`] on the server side.
//! - **Connection ID** (RFC 9146) — enables NAT rebinding without losing the
//!   association. Only active if **both** sides configure one; otherwise it is
//!   silently disabled and the wire format falls back to the standard record
//!   header. Transparent to [`send`](DtlsConnection::send) /
//!   [`recv`](DtlsConnection::recv).
//! - **Record Size Limit** (RFC 8449) — each side advertises a maximum
//!   outgoing record size; the peer's limit is automatically applied to our
//!   outgoing records. Default is `16385` (`Config::default()`). Works
//!   asymmetrically: it is enough for one side to set it.
//!
//! ## Keying material (DTLS-SRTP)
//!
//! [`dimpl13`] emits `Output::KeyingMaterial(material, profile)`
//! (RFC 5764 / RFC 7714) for use with an SRTP stack. This crate forwards
//! that variant and exposes it via [`DtlsConnection::keying_material`].
//! The returned tuple is `(raw_keying_material, srtp_profile)`:
//!
//! - `material` is typically `2 * (key_len + salt_len)` bytes
//!   (`60` for AES-CM-128 / HMAC-SHA1-80).
//! - `profile` (re-exported as [`SrtpProfile`]) selects the SRTP
//!   cipher/suite in your SRTP stack.
//!
//! The default shared config does **not** negotiate `use_srtp`; configure
//! SRTP-related `Config` options explicitly via [`ConfigOptions::dtls_config`]
//! if your SRTP stack requires it. If `use_srtp` was not negotiated, the
//! engine never produces `KeyingMaterial` and
//! [`keying_material`](DtlsConnection::keying_material) will return `None`
//! once the connection terminates.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use tokio_dtls::DtlsConnection;
//! let conn = DtlsConnection::connect("127.0.0.1:4433", |_| true).await?;
//! if let Some((material, profile)) = conn.keying_material().await {
//!     println!("SRTP profile: {:?}, {} bytes", profile, material.len());
//!     // feed `material` + `profile` into your SRTP context
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Multiplexing
//!
//! [`DtlsServer`] binds one `UdpSocket` and demultiplexes incoming datagrams
//! by peer address, spawning a per-peer DTLS engine. Each accepted
//! [`DtlsConnection`] is independent: its own handshake, its own certificate
//! validator, its own keying material. The accept queue is bounded
//! (currently 64 handshake-complete connections); further handshakes block
//! until the application calls [`DtlsServer::accept`].
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use tokio_dtls::{ConfigOptions, DtlsServer};
//! let mut server = DtlsServer::bind(
//!     "0.0.0.0:4433",
//!     |_cert| true, // Replace with real validation!
//!     ConfigOptions::default(),
//! ).await?;
//! loop {
//!     let conn = server.accept().await?;
//!     tokio::spawn(async move {
//!         let _ = conn.send(b"hello").await;
//!         let _ = conn.recv().await;
//!     });
//! }
//! # }
//! ```
//!
//! ## Performance
//!
//! A process-wide `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily
//! on first use and reused for every subsequent connection. This removes the
//! per-connection cost of `Config::builder().build()` (crypto provider
//! validation — 6 ECDHE round-trips, ~0.7 ms measured on reference hardware)
//! and `generate_self_signed_certificate()` (ECDSA keygen, ~70 µs measured),
//! both of which would otherwise dominate a loopback handshake.
//!
//! Call [`warmup`] once at process startup to move the first-use cost
//! (AWS-LC-RS init + `rcgen` first key + provider validation — up to ~90 ms on
//! some platforms) out of the first handshake and into a predictable startup
//! phase:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! tokio_dtls::warmup().await?;
//! // ... start accepting / connecting ...
//! # Ok(())
//! # }
//! ```
//!
//! After warmup, `p50` handshake on loopback is ~0.9 ms in sequential
//! connect benchmarks (`cargo bench --bench handshake`). The remaining time
//! is split between `Dtls::new_13` (private-key parsing) and the four tokio
//! task-switches per handshake flight, neither of which is under this
//! crate's control.
//!
//! If you need custom queue sizes or your own certificate, build the
//! `Arc<Config>` / `Arc<DtlsCertificate>` yourself once and pass them via
//! [`ConfigOptions::dtls_config`] / [`ConfigOptions::dtls_cert`]. When both
//! are `Some`, connection setup is a pure `Arc::clone` with no blocking-pool
//! involvement — strictly faster than the shared-cache path.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use dimpl13::{Config, Dtls, DtlsCertificate, Output, certificate};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// SRTP protection profile selected via `use_srtp` (RFC 5764 / RFC 7714).
///
/// Re-exported from [`dimpl13`] so callers of
/// [`DtlsConnection::keying_material`] can match on it without depending on
/// `dimpl13` directly.
pub use dimpl13::SrtpProfile;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

const DEFAULT_QUEUE_RX: usize = 256;
const DEFAULT_QUEUE_TX: usize = 256;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_INITIAL_BUFFER_SIZE: usize = 2048;
const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BATCH_SENDS: usize = 128;
const MAX_APP_OUT_PENDING: usize = 4096;
const UDP_BUF_MIN: usize = 2048;
const SLEEP_MAX: Duration = Duration::from_secs(3600 * 24);
const SPIN_YIELD_BEFORE_SLEEP: u32 = 8;
const SPIN_SLEEP: Duration = Duration::from_micros(50);

/// Per-session inbound-packet queue capacity (multiplexed path).
const SESSION_PACKET_CHANNEL: usize = 128;
/// Accept queue capacity on [`DtlsServer`].
const ACCEPT_QUEUE: usize = 64;
/// Largest UDP datagram we will read from a shared socket.
const MUX_BUF_SIZE: usize = 65535;
/// Backoff when the multiplexer's `recv_from` errors.
const MUX_ERROR_BACKOFF: Duration = Duration::from_millis(10);

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by [`DtlsConnection`] and [`DtlsServer`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error on the underlying UDP socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error from the DTLS engine. Fatal: the connection must be discarded.
    #[error("DTLS engine error: {0}")]
    Dtls(#[from] dimpl13::Error),

    /// The connection was closed (locally or by the peer).
    #[error("connection closed")]
    Closed,

    /// The peer certificate was rejected by the validator.
    #[error("peer certificate rejected")]
    CertRejected,

    /// The handshake did not complete within the configured timeout.
    #[error("handshake failed or timed out")]
    HandshakeFailed,

    /// The background engine task failed unexpectedly.
    #[error("background task failed: {0}")]
    TaskFailed(String),

    /// The server address could not be parsed.
    #[error("invalid server address")]
    InvalidAddress,

    /// The self-signed certificate could not be generated.
    #[error("certificate generation failed: {0}")]
    CertGen(String),

    /// The outbound channel is full; the caller should retry.
    #[error("send channel full")]
    ChannelFull,
}

type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// HandshakeInfo (private)
// ---------------------------------------------------------------------------

/// Values captured at the moment the handshake completes.
///
/// Read via [`DtlsConnection::negotiated_alpn`] and
/// [`DtlsConnection::peer_server_name`]. Stored inside an `OnceLock` because
/// in the multiplexed path the connection handle is constructed *before* the
/// handshake completes; the engine task fills it in when `Output::Connected`
/// arrives.
#[derive(Debug, Clone, Default)]
struct HandshakeInfo {
    negotiated_alpn: Option<Vec<u8>>,
    peer_server_name: Option<String>,
}

impl HandshakeInfo {
    fn capture(dtls: &Dtls) -> Self {
        Self {
            negotiated_alpn: dtls.negotiated_alpn().map(|v| v.to_vec()),
            peer_server_name: dtls.peer_server_name().map(String::from),
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigOptions
// ---------------------------------------------------------------------------

/// Configuration for a [`DtlsConnection`] or [`DtlsServer`].
///
/// # Performance
///
/// By default, a process-wide `Arc<Config>` and `Arc<DtlsCertificate>` are
/// created lazily on first use and reused for every subsequent connection.
/// The fast path — both values already resolved (either provided here or
/// cached process-wide), default queue sizes — returns `Arc::clone` without
/// waking the blocking pool.
///
/// If you need custom queue sizes, ALPN protocols, SNI, Connection ID, a
/// custom Record Size Limit, or your own certificate, build the
/// `Arc<Config>` / `Arc<DtlsCertificate>` yourself and pass them via
/// [`dtls_config`](Self::dtls_config) / [`dtls_cert`](Self::dtls_cert).
#[derive(Debug, Clone)]
pub struct ConfigOptions {
    /// Maximum time to wait for handshake completion.
    ///
    /// Default: 30 s.
    pub handshake_timeout: Duration,

    /// Initial size of the `poll_output` buffer. Grows on `BufferTooSmall`.
    ///
    /// Default: 2048. Raise this if you use jumbo MTUs (> 2048 bytes).
    /// Also sets the minimum UDP receive buffer size.
    pub initial_buffer_size: usize,

    /// Maximum number of records in the DTLS receive queue.
    ///
    /// Only used when [`dtls_config`](Self::dtls_config) is `None` **and**
    /// the value differs from tokio-dtls's default (`256`). Otherwise the
    /// process-wide shared config's value applies (`256`).
    pub max_queue_rx: usize,

    /// Maximum number of records in the DTLS transmit queue.
    ///
    /// Only used when [`dtls_config`](Self::dtls_config) is `None` **and**
    /// the value differs from tokio-dtls's default (`256`). Otherwise the
    /// process-wide shared config's value applies (`256`).
    pub max_queue_tx: usize,

    /// Capacity of the internal handle ↔ engine channels.
    ///
    /// Default: 1024.
    pub channel_capacity: usize,

    /// Pre-built DTLS config. `None` = use the process-wide shared instance.
    ///
    /// **Recommended for production**: `Some(Arc::new(your_config))`. When
    /// both this and [`dtls_cert`](Self::dtls_cert) are `Some`, connection
    /// setup is a pure `Arc::clone` with no blocking-pool involvement — the
    /// fastest possible path.
    ///
    /// The shared default config advertises no ALPN protocols, no SNI, no
    /// Connection ID, and the default Record Size Limit. **You must pass a
    /// custom `Config` to enable any of those.**
    ///
    /// Configure via `dimpl13::Config::builder()`:
    ///
    /// - `.alpn_protocols(&[b"h2", b"http/1.1"])` — advertise ALPN on both
    ///   client and server.
    /// - `.server_name("example.com")` — client sends SNI.
    /// - `.connection_id(&[0xAA, 0xBB])` — RFC 9146 Connection ID.
    /// - `.record_size_limit(1200)` — RFC 8449 Record Size Limit.
    pub dtls_config: Option<Arc<Config>>,

    /// Pre-generated certificate. `None` = use the process-wide shared instance.
    pub dtls_cert: Option<Arc<DtlsCertificate>>,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            initial_buffer_size: DEFAULT_INITIAL_BUFFER_SIZE,
            max_queue_rx: DEFAULT_QUEUE_RX,
            max_queue_tx: DEFAULT_QUEUE_TX,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            dtls_config: None,
            dtls_cert: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Process-wide shared cache
// ---------------------------------------------------------------------------

static SHARED_CONFIG: OnceLock<Arc<Config>> = OnceLock::new();
static SHARED_CERT: OnceLock<Arc<DtlsCertificate>> = OnceLock::new();
static WARNED_CUSTOM_QUEUE: AtomicBool = AtomicBool::new(false);

/// Synchronous resolver — used from `spawn_blocking` and `warmup`.
fn resolve_config(opts: &ConfigOptions) -> Result<Arc<Config>> {
    if let Some(cfg) = &opts.dtls_config {
        return Ok(Arc::clone(cfg));
    }

    let is_default_queue =
        opts.max_queue_rx == DEFAULT_QUEUE_RX && opts.max_queue_tx == DEFAULT_QUEUE_TX;

    if is_default_queue {
        if let Some(cfg) = SHARED_CONFIG.get() {
            return Ok(Arc::clone(cfg));
        }
    } else if !WARNED_CUSTOM_QUEUE.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            max_queue_rx = opts.max_queue_rx,
            max_queue_tx = opts.max_queue_tx,
            "building a fresh Config per connection because max_queue_* differ \
             from the defaults; pass ConfigOptions::dtls_config = Some(Arc<Config>) \
             to cache it"
        );
    }

    let cfg = Arc::new(
        Config::builder()
            .max_queue_rx(opts.max_queue_rx)
            .max_queue_tx(opts.max_queue_tx)
            .build()?,
    );

    if is_default_queue {
        let _ = SHARED_CONFIG.set(Arc::clone(&cfg));
        Ok(SHARED_CONFIG.get().cloned().unwrap_or(cfg))
    } else {
        Ok(cfg)
    }
}

fn resolve_cert(opts: &ConfigOptions) -> Result<Arc<DtlsCertificate>> {
    if let Some(cert) = &opts.dtls_cert {
        return Ok(Arc::clone(cert));
    }
    if let Some(cert) = SHARED_CERT.get() {
        return Ok(Arc::clone(cert));
    }
    let cert = Arc::new(
        certificate::generate_self_signed_certificate()
            .map_err(|e| Error::CertGen(e.to_string()))?,
    );
    let _ = SHARED_CERT.set(Arc::clone(&cert));
    Ok(SHARED_CERT.get().cloned().unwrap_or(cert))
}

async fn resolve_shared(opts: &ConfigOptions) -> Result<(Arc<Config>, Arc<DtlsCertificate>)> {
    let is_default_queue =
        opts.max_queue_rx == DEFAULT_QUEUE_RX && opts.max_queue_tx == DEFAULT_QUEUE_TX;

    let config_ready = match &opts.dtls_config {
        Some(cfg) => Some(Arc::clone(cfg)),
        None if is_default_queue => SHARED_CONFIG.get().cloned(),
        None => None,
    };
    let cert_ready = match &opts.dtls_cert {
        Some(cert) => Some(Arc::clone(cert)),
        None => SHARED_CERT.get().cloned(),
    };

    if let (Some(cfg), Some(cert)) = (config_ready, cert_ready) {
        return Ok((cfg, cert));
    }

    let opts = opts.clone();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let config = resolve_config(&opts)?;
        let cert = resolve_cert(&opts)?;
        Ok((config, cert))
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("resolve task: {e}")))?
}

/// Pre-generates the process-wide shared [`Config`] and [`DtlsCertificate`].
///
/// Call this once at startup to move the one-time `aws-lc-rs` / `rcgen` /
/// crypto-provider-validation cost (~10–90 ms depending on platform) out of
/// the first handshake and into a predictable startup phase.
///
/// Safe to call from multiple tasks; the work is idempotent.
pub async fn warmup() -> Result<()> {
    let opts = ConfigOptions::default();
    tokio::task::spawn_blocking(move || -> Result<()> {
        resolve_config(&opts)?;
        resolve_cert(&opts)?;
        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("warmup task: {e}")))?
}

// ---------------------------------------------------------------------------
// CertValidator
// ---------------------------------------------------------------------------

/// Certificate validator callback.
///
/// Receives the peer's leaf certificate in DER format. Return `true` to accept.
pub type CertValidator = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

// ---------------------------------------------------------------------------
// Transport (private)
// ---------------------------------------------------------------------------

/// Abstracts over "owning a connected UDP socket" and "sharing a socket with
/// other sessions and receiving via a per-session mpsc channel".
enum Transport {
    Connected(UdpSocket),
    Shared {
        socket: Arc<UdpSocket>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
}

impl Transport {
    async fn send(&self, peer: SocketAddr, data: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Connected(s) => s.send(data).await,
            Transport::Shared { socket, .. } => socket.send_to(data, peer).await,
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Connected(s) => s.recv(buf).await,
            Transport::Shared { rx, .. } => match rx.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "transport closed",
                )),
            },
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Transport::Connected(s) => s.local_addr(),
            Transport::Shared { socket, .. } => socket.local_addr(),
        }
    }
}

// ---------------------------------------------------------------------------
// DtlsConnection
// ---------------------------------------------------------------------------

/// An established DTLS 1.3 connection.
///
/// This is a cheaply cloneable handle to a background task that owns the
/// Sans-IO engine and (possibly shared) UDP socket. Cloning the handle does
/// **not** create a new connection; all clones share the same underlying
/// session.
///
/// ## Concurrency
///
/// `send` can be called from multiple clones concurrently. `recv` serializes
/// internally; using it from multiple clones will interleave messages
/// arbitrarily but never lose or reorder them.
///
/// ## Negotiated parameters
///
/// [`negotiated_alpn`](Self::negotiated_alpn), [`peer_server_name`](Self::peer_server_name)
/// and [`keying_material`](Self::keying_material) are available once the
/// handshake has completed, which is guaranteed by the time
/// `connect*`/`accept*` returns.
#[derive(Clone)]
pub struct DtlsConnection {
    app_tx: mpsc::Sender<Vec<u8>>,
    app_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    close_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    dropped_app_data: Arc<AtomicU64>,
    handshake_info: Arc<OnceLock<HandshakeInfo>>,
    km_rx: watch::Receiver<Option<(Vec<u8>, SrtpProfile)>>,
}

impl DtlsConnection {
    /// Connects to a DTLS 1.3 server.
    ///
    /// `validator` is called when the server's certificate arrives. Return
    /// `true` to accept. In production this **must** perform real validation.
    pub async fn connect(
        server_addr: &str,
        validator: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::connect_with(server_addr, validator, ConfigOptions::default()).await
    }

    /// Connects with custom [`ConfigOptions`].
    pub async fn connect_with(
        server_addr: &str,
        validator: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
        opts: ConfigOptions,
    ) -> Result<Self> {
        let peer: SocketAddr = server_addr.parse().map_err(|_| Error::InvalidAddress)?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(peer).await?;
        tracing::debug!(%peer, local = ?socket.local_addr().ok(), "UDP socket connected");

        Self::spawn_and_wait(
            Transport::Connected(socket),
            peer,
            true,
            Arc::new(validator),
            opts,
            None,
        )
        .await
    }

    /// Accepts a DTLS 1.3 connection on a bound UDP socket.
    ///
    /// **For multi-peer use, prefer [`DtlsServer`]** — this method connects
    /// the socket to the first peer that sends a datagram, so only one peer
    /// can be served per socket.
    pub async fn accept(
        socket: UdpSocket,
        validator: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::accept_with(socket, validator, ConfigOptions::default()).await
    }

    /// Accepts with custom [`ConfigOptions`].
    pub async fn accept_with(
        socket: UdpSocket,
        validator: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
        opts: ConfigOptions,
    ) -> Result<Self> {
        let mut buf = vec![0u8; opts.initial_buffer_size.max(UDP_BUF_MIN)];
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let first_packet = buf[..len].to_vec();
        tracing::debug!(%peer, len, "received first packet, connecting socket to peer");

        socket.connect(peer).await?;

        Self::spawn_and_wait(
            Transport::Connected(socket),
            peer,
            false,
            Arc::new(validator),
            opts,
            Some(first_packet),
        )
        .await
    }

    /// Sends application data to the peer.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.send_vec(data.to_vec()).await
    }

    /// Sends application data without copying the caller's slice.
    pub async fn send_vec(&self, data: Vec<u8>) -> Result<()> {
        tracing::trace!(len = data.len(), "queueing application data");
        self.app_tx.send(data).await.map_err(|_| Error::Closed)
    }

    /// Non-blocking send. Returns [`Error::ChannelFull`] if the channel is
    /// full, [`Error::Closed`] if the connection is closed.
    pub fn try_send(&self, data: &[u8]) -> Result<()> {
        self.try_send_vec(data.to_vec())
    }

    /// Non-blocking send of an owned buffer.
    pub fn try_send_vec(&self, data: Vec<u8>) -> Result<()> {
        self.app_tx.try_send(data).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Error::ChannelFull,
            mpsc::error::TrySendError::Closed(_) => Error::Closed,
        })
    }

    /// Receives application data from the peer.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut rx = self.app_rx.lock().await;
        rx.recv().await.ok_or(Error::Closed)
    }

    /// Gracefully closes the connection.
    ///
    /// Idempotent. Sends `close_notify`, waits for the engine task to finish,
    /// force-aborts it if it takes longer than the internal close timeout
    /// (5 s).
    pub async fn close(&self) -> Result<()> {
        tracing::debug!("close requested");

        {
            let mut tx = self.close_tx.lock().await;
            if let Some(sender) = tx.take() {
                let _ = sender.send(());
            }
        }

        let mut rx = self.closed_rx.clone();
        let wait = async {
            loop {
                if *rx.borrow() {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        };

        match tokio::time::timeout(CLOSE_TIMEOUT, wait).await {
            Ok(()) => Ok(()),
            Err(_) => {
                tracing::warn!("close timed out, force-aborting engine");
                if let Some(handle) = self.task.lock().await.take() {
                    handle.abort();
                }
                let _ = self.closed_tx.send_replace(true);
                Err(Error::TaskFailed("close timed out".into()))
            }
        }
    }

    /// Waits until the connection is fully closed.
    pub async fn wait_closed(&self) {
        let mut rx = self.closed_rx.clone();
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Returns `true` once the connection is closed.
    pub fn is_closed(&self) -> bool {
        *self.closed_rx.borrow()
    }

    /// Returns the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the local address, if available.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Returns how many inbound application messages were dropped because
    /// the consumer did not keep up.
    pub fn dropped_app_data(&self) -> u64 {
        self.dropped_app_data.load(Ordering::Relaxed)
    }

    /// ALPN protocol selected during the handshake, or `None`.
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.handshake_info.get()?.negotiated_alpn.as_deref()
    }

    /// SNI host name sent by the peer, or `None`.
    pub fn peer_server_name(&self) -> Option<&str> {
        self.handshake_info.get()?.peer_server_name.as_deref()
    }

    /// Exported keying material (RFC 5705 / RFC 5764 / RFC 7714), or `None`.
    ///
    /// Returns `(material, profile)`:
    ///
    /// - `material` — the raw exported keying material. For SRTP this is
    ///   typically `2 * (key_len + salt_len)` bytes (`60` for AES-CM-128 /
    ///   HMAC-SHA1-80).
    /// - `profile` — the [`SrtpProfile`] selected via `use_srtp`, which your
    ///   SRTP stack needs to pick the matching cipher suite.
    ///
    /// The method awaits the material's arrival. It resolves immediately if
    /// the engine has already produced it (usually the case by the time
    /// `connect*`/`accept*` returns), and returns `None` if the engine exits
    /// without ever producing it (e.g. `use_srtp` was not negotiated).
    ///
    /// The default shared config does not negotiate `use_srtp`; configure
    /// your `Config` via [`ConfigOptions::dtls_config`] if your SRTP stack
    /// requires it.
    pub async fn keying_material(&self) -> Option<(Vec<u8>, SrtpProfile)> {
        let mut rx = self.km_rx.clone();
        loop {
            if let Some(v) = rx.borrow().clone() {
                return Some(v);
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Wrap `spawn_engine` + await handshake, for callers that want the
    /// connection only after the handshake completes.
    async fn spawn_and_wait(
        transport: Transport,
        peer: SocketAddr,
        is_client: bool,
        validator: CertValidator,
        opts: ConfigOptions,
        first_packet: Option<Vec<u8>>,
    ) -> Result<Self> {
        let (conn, ready_rx) = Self::spawn_engine(
            transport,
            peer,
            is_client,
            validator,
            opts,
            first_packet,
            None,
        )
        .await?;
        match ready_rx.await {
            Ok(Ok(())) => Ok(conn),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::HandshakeFailed),
        }
    }

    /// Spawn the engine task. Returns the handle and a `ready` oneshot that
    /// fires with `Ok(())` when the handshake completes, `Err(e)` on failure,
    /// or is dropped on task termination without ever completing.
    ///
    /// `on_exit` is dropped (and therefore fires) when the engine task
    /// terminates; used by [`DtlsServer`] for session cleanup.
    async fn spawn_engine(
        transport: Transport,
        peer: SocketAddr,
        is_client: bool,
        validator: CertValidator,
        opts: ConfigOptions,
        first_packet: Option<Vec<u8>>,
        on_exit: Option<oneshot::Sender<()>>,
    ) -> Result<(Self, oneshot::Receiver<Result<()>>)> {
        let (to_engine_tx, to_engine_rx) = mpsc::channel::<Vec<u8>>(opts.channel_capacity);
        let (from_engine_tx, from_engine_rx) = mpsc::channel::<Vec<u8>>(opts.channel_capacity);
        let (connected_tx, connected_rx) = oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = oneshot::channel::<()>();
        let (closed_tx, closed_rx) = watch::channel(false);
        let (km_tx, km_rx) = watch::channel::<Option<(Vec<u8>, SrtpProfile)>>(None);

        let local = transport.local_addr().ok();
        let dropped_app_data = Arc::new(AtomicU64::new(0));
        let handshake_info = Arc::new(OnceLock::new());

        let (config, cert) = resolve_shared(&opts).await?;

        let mut dtls = Dtls::new_13(config, (*cert).clone(), Instant::now());
        dtls.set_active(is_client);

        tracing::debug!(%peer, is_client, local = ?local, "DTLS 1.3 engine created");

        let task_closed_tx = closed_tx.clone();
        let task_dropped = Arc::clone(&dropped_app_data);
        let task_handshake_info = Arc::clone(&handshake_info);
        let task = tokio::spawn(async move {
            let result = run_engine(
                dtls,
                transport,
                peer,
                is_client,
                validator,
                opts,
                first_packet,
                to_engine_rx,
                from_engine_tx,
                connected_tx,
                close_rx,
                task_dropped,
                task_handshake_info,
                km_tx,
            )
            .await;

            match result {
                Ok(()) => tracing::debug!(%peer, "engine task finished"),
                Err(e) => tracing::error!(%peer, error = %e, "engine task failed"),
            }
            let _ = task_closed_tx.send(true);
            drop(on_exit);
        });

        let conn = Self {
            app_tx: to_engine_tx,
            app_rx: Arc::new(Mutex::new(from_engine_rx)),
            close_tx: Arc::new(Mutex::new(Some(close_tx))),
            task: Arc::new(Mutex::new(Some(task))),
            closed_tx,
            closed_rx,
            peer,
            local,
            dropped_app_data,
            handshake_info,
            km_rx,
        };

        Ok((conn, connected_rx))
    }
}

// ---------------------------------------------------------------------------
// DtlsServer — multiplexed single-socket server
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SessionEntry {
    id: u64,
    packet_tx: mpsc::Sender<Vec<u8>>,
}

struct MuxState {
    socket: Arc<UdpSocket>,
    sessions: StdMutex<HashMap<SocketAddr, SessionEntry>>,
    accept_tx: mpsc::Sender<DtlsConnection>,
    opts: ConfigOptions,
    validator: CertValidator,
    next_id: AtomicU64,
}

impl MuxState {
    /// Remove the session entry only if it still belongs to `id` — protects
    /// against a slow-exiting old session clobbering a newly-created one for
    /// the same peer address.
    fn remove_if_matches(&self, peer: SocketAddr, id: u64) {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(entry) = sessions.get(&peer) {
            if entry.id == id {
                sessions.remove(&peer);
            }
        }
    }
}

/// Multiplexed DTLS 1.3 server: one `UdpSocket`, many connections.
///
/// Incoming datagrams are routed by peer address. Each distinct peer gets its
/// own [`DtlsConnection`] (own engine, own handshake, own keying material).
/// When a session ends, its map entry is removed; if the same peer sends a
/// new `ClientHello`, a fresh session is started.
///
/// # Accept queue
///
/// Handshake-complete connections are pushed into a bounded queue
/// (capacity 64). If the queue fills, further completed handshakes block
/// inside their per-session tasks until [`accept`](Self::accept) drains the
/// queue. The engine keeps running throughout, so no data is lost by a
/// slow-accepting application (within the per-session buffers).
///
/// # Shutdown
///
/// Dropping the `DtlsServer` stops the multiplexer task and closes the accept
/// queue. Already-accepted [`DtlsConnection`] handles keep working; the
/// shared socket lives as long as at least one of them (or the server) is
/// alive. Sessions that complete their handshake after the server is dropped
/// will have their connection dropped and closed.
pub struct DtlsServer {
    state: Arc<MuxState>,
    accept_rx: mpsc::Receiver<DtlsConnection>,
    mux_task: JoinHandle<()>,
    local_addr: SocketAddr,
}

impl DtlsServer {
    /// Binds to `addr` and starts the multiplexer.
    ///
    /// `validator` is invoked per-peer; return `true` to accept that peer's
    /// certificate.
    pub async fn bind(
        addr: &str,
        validator: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
        opts: ConfigOptions,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_QUEUE);

        let state = Arc::new(MuxState {
            socket,
            sessions: StdMutex::new(HashMap::new()),
            accept_tx,
            opts,
            validator: Arc::new(validator),
            next_id: AtomicU64::new(0),
        });

        let mux_task = tokio::spawn(run_mux(Arc::clone(&state)));

        Ok(Self {
            state,
            accept_rx,
            mux_task,
            local_addr,
        })
    }

    /// Awaits the next completed handshake.
    ///
    /// Returns [`Error::Closed`] if the server has been dropped.
    pub async fn accept(&mut self) -> Result<DtlsConnection> {
        self.accept_rx.recv().await.ok_or(Error::Closed)
    }

    /// Returns the local address the socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Number of active peer sessions (handshaking or established).
    pub fn session_count(&self) -> usize {
        self.state
            .sessions
            .lock()
            .expect("sessions mutex poisoned")
            .len()
    }
}

impl Drop for DtlsServer {
    fn drop(&mut self) {
        // Stop reading new packets. Existing sessions keep running until
        // they terminate on their own (per-session tasks hold an Arc to
        // `MuxState` and the shared socket).
        self.mux_task.abort();
    }
}

async fn run_mux(state: Arc<MuxState>) {
    let mut buf = vec![0u8; MUX_BUF_SIZE];
    tracing::debug!(local = ?state.socket.local_addr().ok(), "mux loop starting");

    loop {
        match state.socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let packet = buf[..len].to_vec();
                handle_incoming(&state, peer, packet);
            }
            Err(e) => {
                tracing::error!(error = %e, "mux recv_from error");
                sleep(MUX_ERROR_BACKOFF).await;
            }
        }
    }
}

fn handle_incoming(state: &Arc<MuxState>, peer: SocketAddr, packet: Vec<u8>) {
    let entry = state
        .sessions
        .lock()
        .expect("sessions mutex poisoned")
        .get(&peer)
        .cloned();

    let packet = if let Some(entry) = entry {
        match entry.packet_tx.try_send(packet) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!(%peer, "session packet buffer full; dropping datagram");
                return;
            }
            Err(mpsc::error::TrySendError::Closed(pkt)) => {
                // Session ended; remove stale entry and start a new session.
                state.remove_if_matches(peer, entry.id);
                pkt
            }
        }
    } else {
        packet
    };

    spawn_new_session(state, peer, packet);
}

fn spawn_new_session(state: &Arc<MuxState>, peer: SocketAddr, first_packet: Vec<u8>) {
    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel(SESSION_PACKET_CHANNEL);

    state
        .sessions
        .lock()
        .expect("sessions mutex poisoned")
        .insert(peer, SessionEntry { id, packet_tx: tx });

    let state = Arc::clone(state);
    tokio::spawn(async move {
        if let Err(e) = session_main(Arc::clone(&state), peer, id, rx, first_packet).await {
            tracing::debug!(%peer, error = %e, "session ended with error");
        }
        state.remove_if_matches(peer, id);
    });
}

async fn session_main(
    state: Arc<MuxState>,
    peer: SocketAddr,
    _id: u64,
    rx: mpsc::Receiver<Vec<u8>>,
    first_packet: Vec<u8>,
) -> Result<()> {
    let transport = Transport::Shared {
        socket: Arc::clone(&state.socket),
        rx,
    };

    let (exit_tx, exit_rx) = oneshot::channel::<()>();

    let (conn, ready_rx) = DtlsConnection::spawn_engine(
        transport,
        peer,
        false,
        Arc::clone(&state.validator),
        state.opts.clone(),
        Some(first_packet),
        Some(exit_tx),
    )
    .await?;

    match ready_rx.await {
        Ok(Ok(())) => {
            // Handshake complete; push to accept queue. If the server has
            // been dropped, `accept_tx` is closed and `send` returns the
            // connection back — drop it, which shuts the engine down.
            if state.accept_tx.send(conn).await.is_err() {
                tracing::debug!(%peer, "accept queue closed; dropping accepted connection");
            }
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(Error::HandshakeFailed),
    }

    // Wait for the engine to terminate (user dropped the last clone, or
    // called `close()`), then let `spawn_new_session` clean up the map entry.
    let _ = exit_rx.await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_engine(
    mut dtls: Dtls,
    mut transport: Transport,
    peer: SocketAddr,
    is_client: bool,
    validator: CertValidator,
    opts: ConfigOptions,
    first_packet: Option<Vec<u8>>,
    mut from_handle_rx: mpsc::Receiver<Vec<u8>>,
    to_handle_tx: mpsc::Sender<Vec<u8>>,
    connected_tx: oneshot::Sender<Result<()>>,
    mut close_rx: oneshot::Receiver<()>,
    dropped_app_data: Arc<AtomicU64>,
    handshake_info: Arc<OnceLock<HandshakeInfo>>,
    km_tx: watch::Sender<Option<(Vec<u8>, SrtpProfile)>>,
) -> Result<()> {
    let mut out_buf = vec![0u8; opts.initial_buffer_size];
    let mut udp_buf = vec![0u8; opts.initial_buffer_size.max(UDP_BUF_MIN)];

    let mut next_timeout: Option<Instant> = Some(Instant::now());
    let mut connected = false;
    let mut connected_tx = Some(connected_tx);
    let handshake_deadline = Instant::now() + opts.handshake_timeout;

    let mut pending_app: Option<Vec<u8>> = None;
    let mut app_out_pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut spin_count: u32 = 0;

    tracing::debug!(%peer, is_client, "engine loop starting");

    if let Some(pkt) = first_packet {
        if let Err(e) = dtls.handle_packet(&pkt) {
            return Err(report_error(&mut connected_tx, Error::Dtls(e)));
        }
    }

    if let Err(e) = dtls.handle_timeout(Instant::now()) {
        return Err(report_error(&mut connected_tx, Error::Dtls(e)));
    }

    loop {
        flush_app_out(&to_handle_tx, &mut app_out_pending);

        if let Err(e) = drain_output(
            &mut dtls,
            &transport,
            peer,
            &mut out_buf,
            &mut next_timeout,
            &validator,
            &to_handle_tx,
            &mut app_out_pending,
            &mut connected,
            &mut connected_tx,
            &dropped_app_data,
            &handshake_info,
            &km_tx,
        )
        .await
        {
            return Err(report_error(&mut connected_tx, e));
        }

        if connected && connected_tx.is_some() {
            if let Some(tx) = connected_tx.take() {
                let _ = tx.send(Ok(()));
            }
        }

        if dtls.is_closed() {
            tracing::debug!(%peer, "engine reports closed");
            return Ok(());
        }

        if !connected && Instant::now() > handshake_deadline {
            tracing::error!(%peer, "handshake deadline exceeded");
            return Err(report_error(&mut connected_tx, Error::HandshakeFailed));
        }

        let pushed = match push_app_data(&mut dtls, &mut pending_app, &mut from_handle_rx) {
            Ok(n) => n,
            Err(e) => return Err(report_error(&mut connected_tx, e)),
        };
        if pushed > 0 || pending_app.is_some() {
            if let Err(e) = drain_output(
                &mut dtls,
                &transport,
                peer,
                &mut out_buf,
                &mut next_timeout,
                &validator,
                &to_handle_tx,
                &mut app_out_pending,
                &mut connected,
                &mut connected_tx,
                &dropped_app_data,
                &handshake_info,
                &km_tx,
            )
            .await
            {
                return Err(report_error(&mut connected_tx, e));
            }
        }

        if pending_app.is_some() {
            spin_count += 1;
            if spin_count < SPIN_YIELD_BEFORE_SLEEP {
                tokio::task::yield_now().await;
            } else {
                sleep(SPIN_SLEEP).await;
                spin_count = 0;
            }
            continue;
        }
        spin_count = 0;

        if pushed > 0 {
            continue;
        }

        let timer_deadline = next_timeout.unwrap_or_else(|| Instant::now() + SLEEP_MAX);

        tokio::select! {
            biased;

            _ = &mut close_rx => {
                tracing::debug!(%peer, "close requested, sending close_notify");
                let _ = dtls.close();
                let _ = drain_output(
                    &mut dtls,
                    &transport,
                    peer,
                    &mut out_buf,
                    &mut next_timeout,
                    &validator,
                    &to_handle_tx,
                    &mut app_out_pending,
                    &mut connected,
                    &mut connected_tx,
                    &dropped_app_data,
                    &handshake_info,
                    &km_tx,
                ).await;
                return Ok(());
            }

            result = transport.recv(&mut udp_buf) => {
                let len = match result {
                    Ok(n) => n,
                    Err(e) => return Err(report_error(&mut connected_tx, Error::Io(e))),
                };
                if len == udp_buf.len() {
                    tracing::warn!(
                        %peer,
                        buf_len = udp_buf.len(),
                        "incoming datagram may have been truncated; raise \
                         ConfigOptions::initial_buffer_size for jumbo MTUs"
                    );
                }
                if let Err(e) = dtls.handle_packet(&udp_buf[..len]) {
                    tracing::error!(%peer, error = ?e, "handle_packet failed");
                    return Err(report_error(&mut connected_tx, Error::Dtls(e)));
                }
            }

            _ = tokio::time::sleep_until(timer_deadline.into()) => {
                next_timeout = None;
                if let Err(e) = dtls.handle_timeout(Instant::now()) {
                    tracing::error!(%peer, error = ?e, "handle_timeout failed");
                    return Err(report_error(&mut connected_tx, Error::Dtls(e)));
                }
            }

            maybe = from_handle_rx.recv() => {
                match maybe {
                    Some(data) => pending_app = Some(data),
                    None => {
                        tracing::debug!(%peer, "handle dropped, exiting");
                        return Ok(());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn drain_output(
    dtls: &mut Dtls,
    transport: &Transport,
    peer: SocketAddr,
    out_buf: &mut Vec<u8>,
    next_timeout: &mut Option<Instant>,
    validator: &CertValidator,
    to_handle_tx: &mpsc::Sender<Vec<u8>>,
    app_out_pending: &mut VecDeque<Vec<u8>>,
    connected: &mut bool,
    connected_tx: &mut Option<oneshot::Sender<Result<()>>>,
    dropped_app_data: &AtomicU64,
    handshake_info: &OnceLock<HandshakeInfo>,
    km_tx: &watch::Sender<Option<(Vec<u8>, SrtpProfile)>>,
) -> Result<()> {
    loop {
        match dtls.poll_output(out_buf) {
            Output::Packet(pkt) => {
                tracing::trace!(len = pkt.len(), "sending DTLS packet");
                transport.send(peer, pkt).await?;
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                return Ok(());
            }
            Output::Connected => {
                tracing::debug!("handshake complete");
                *connected = true;
                let _ = handshake_info.set(HandshakeInfo::capture(dtls));
                if let Some(tx) = connected_tx.take() {
                    let _ = tx.send(Ok(()));
                }
            }
            Output::PeerCert(der) => {
                tracing::debug!(cert_len = der.len(), "validating peer certificate");
                if !(validator)(der) {
                    tracing::error!("peer certificate rejected by validator");
                    return Err(Error::CertRejected);
                }
            }
            Output::ApplicationData(data) => {
                tracing::trace!(len = data.len(), "forwarding application data");
                let msg = data.to_vec();
                match to_handle_tx.try_send(msg) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(msg)) => {
                        if app_out_pending.len() >= MAX_APP_OUT_PENDING {
                            dropped_app_data.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                pending = app_out_pending.len(),
                                "outbound app queue full; dropping message \
                                 (consumer too slow)"
                            );
                        } else {
                            app_out_pending.push_back(msg);
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {}
                }
            }
            Output::CloseNotify => {
                tracing::debug!("peer sent close_notify, responding");
                let _ = dtls.close();
            }
            Output::KeyingMaterial(km, profile) => {
                tracing::debug!(
                    len = km.len(),
                    profile = ?profile,
                    "received keying material"
                );
                let _ = km_tx.send(Some((km.to_vec(), profile)));
            }
            Output::BufferTooSmall { needed } => {
                if out_buf.len() < needed {
                    tracing::debug!(needed, current = out_buf.len(), "growing out_buf");
                    out_buf.resize(needed, 0);
                }
            }
            _ => {
                tracing::trace!("ignoring unhandled Output variant");
            }
        }
    }
}

fn push_app_data(
    dtls: &mut Dtls,
    pending_app: &mut Option<Vec<u8>>,
    from_handle_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<usize> {
    let mut pushed = 0;
    for _ in 0..MAX_BATCH_SENDS {
        let data = if let Some(d) = pending_app.take() {
            d
        } else {
            match from_handle_rx.try_recv() {
                Ok(d) => d,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        };
        match dtls.send_application_data(&data) {
            Ok(0) => {
                *pending_app = Some(data);
                break;
            }
            Ok(_n) => pushed += 1,
            Err(e) => return Err(Error::Dtls(e)),
        }
    }
    Ok(pushed)
}

fn flush_app_out(tx: &mpsc::Sender<Vec<u8>>, pending: &mut VecDeque<Vec<u8>>) {
    while let Some(msg) = pending.pop_front() {
        match tx.try_send(msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                pending.push_front(msg);
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                pending.clear();
                break;
            }
        }
    }
}

fn report_error(connected_tx: &mut Option<oneshot::Sender<Result<()>>>, err: Error) -> Error {
    if let Some(tx) = connected_tx.take() {
        let msg = err.to_string();
        let _ = tx.send(Err(err));
        Error::TaskFailed(msg)
    } else {
        err
    }
}
