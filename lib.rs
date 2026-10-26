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
//! ## Architecture
//!
//! Each [`DtlsConnection`] owns a background Tokio task that drives the
//! Sans-IO engine. The handle communicates with the task through two mpsc
//! channels (data to encrypt, decrypted data) plus signalling channels for
//! handshake completion and close.
//!
//! ## Performance
//!
//! A process-wide `Arc<Config>` and `Arc<DtlsCertificate>` are created lazily
//! on first use and reused for every subsequent connection. This removes the
//! per-connection cost of `Config::builder().build()` (crypto provider
//! validation — 6 ECDHE round-trips, ~3–5 ms) and
//! `generate_self_signed_certificate()` (ECDSA keygen, ~2–5 ms), which would
//! otherwise dominate a loopback handshake.
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
//! After warmup, `p50` handshake on loopback is ~2.5 ms in sequential
//! connect benchmarks. The remaining time is split between `Dtls::new_13`
//! (private-key parsing) and the four tokio task-switches per handshake
//! flight, neither of which is under this crate's control.
//!
//! If you need custom queue sizes or your own certificate, build the
//! `Arc<Config>` / `Arc<DtlsCertificate>` yourself once and pass them via
//! [`ConfigOptions::dtls_config`] / [`ConfigOptions::dtls_cert`].
//!
//! ## Example
//!
//! ```no_run
//! use tokio_dtls::DtlsConnection;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let conn = DtlsConnection::connect(
//!     "127.0.0.1:4433",
//!     |_cert| true, // Replace with real validation!
//! ).await?;
//!
//! conn.send(b"hello").await?;
//! let data = conn.recv().await?;
//! println!("got: {:?}", data);
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dimpl13::{certificate, Config, Dtls, DtlsCertificate, Output};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;

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

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by [`DtlsConnection`].
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
// ConfigOptions
// ---------------------------------------------------------------------------

/// Configuration for a [`DtlsConnection`].
///
/// # Performance
///
/// By default, a process-wide `Arc<Config>` and `Arc<DtlsCertificate>` are
/// created lazily on first use and reused for every subsequent connection.
/// The fast path — both values cached, default queue sizes — returns
/// `Arc::clone` without waking the blocking pool.
///
/// If you need custom queue sizes or your own certificate, build the
/// `Arc<Config>` / `Arc<DtlsCertificate>` yourself and pass them via
/// [`dtls_config`](Self::dtls_config) / [`dtls_cert`](Self::dtls_cert).
/// This avoids the per-connection `Config::builder().build()` and cert
/// generation entirely.
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
    /// the value differs from the default (`256`). Otherwise the process-wide
    /// shared config's value applies (256).
    pub max_queue_rx: usize,

    /// Maximum number of records in the DTLS transmit queue.
    ///
    /// Only used when [`dtls_config`](Self::dtls_config) is `None` **and**
    /// the value differs from the default (`256`). Otherwise the process-wide
    /// shared config's value applies (256).
    pub max_queue_tx: usize,

    /// Capacity of the internal handle ↔ engine channels.
    ///
    /// Default: 1024.
    pub channel_capacity: usize,

    /// Pre-built DTLS config. `None` = use the process-wide shared instance.
    ///
    /// Recommended for production: `Some(Arc::new(Config::builder()...build()?))`
    /// so the config is built once and shared across all connections.
    pub dtls_config: Option<Arc<Config>>,

    /// Pre-generated certificate. `None` = use the process-wide shared instance.
    ///
    /// Recommended for production: `Some(Arc::new(your_cert))`.
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
        // Another thread may have raced us; prefer the winner.
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

/// Resolve config and cert, preferring the synchronous fast path when both
/// are already cached and no per-connection overrides were requested.
///
/// The fast path avoids `spawn_blocking` + thread-pool wake (~30–50 µs per
/// call). The slow path runs on the blocking pool because the first call can
/// take 10–90 ms (`aws-lc-rs` init, `rcgen` keygen, provider validation).
async fn resolve_shared(opts: &ConfigOptions) -> Result<(Arc<Config>, Arc<DtlsCertificate>)> {
    // Fast path: both cached, no overrides, default queue sizes.
    if opts.dtls_config.is_none() && opts.dtls_cert.is_none() {
        let is_default_queue =
            opts.max_queue_rx == DEFAULT_QUEUE_RX && opts.max_queue_tx == DEFAULT_QUEUE_TX;
        if is_default_queue {
            if let (Some(cfg), Some(cert)) = (SHARED_CONFIG.get(), SHARED_CERT.get()) {
                return Ok((Arc::clone(cfg), Arc::clone(cert)));
            }
        }
    }

    // Slow path: build once on the blocking pool.
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
// DtlsConnection
// ---------------------------------------------------------------------------

/// An established DTLS 1.3 connection.
///
/// This is a cheaply cloneable handle to a background task that owns the
/// Sans-IO engine and the UDP socket. Cloning the handle does **not** create a
/// new connection; all clones share the same underlying session.
///
/// ## Concurrency
///
/// `send` can be called from multiple clones concurrently. `recv` serializes
/// internally; using it from multiple clones will interleave messages
/// arbitrarily but never lose or reorder them.
#[derive(Clone)]
pub struct DtlsConnection {
    app_tx: mpsc::Sender<Vec<u8>>,
    app_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    close_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<()>>>>,
    task: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    dropped_app_data: Arc<AtomicU64>,
}

impl DtlsConnection {
    /// Connects to a DTLS 1.3 server.
    ///
    /// `validator` is called when the server's certificate arrives. Return
    /// `true` to accept. In production this **must** perform real validation
    /// (chain, fingerprint, pinning, …).
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

        Self::spawn_engine(socket, peer, true, Arc::new(validator), opts, None).await
    }

    /// Accepts a DTLS 1.3 connection on a bound UDP socket.
    ///
    /// Consumes the first incoming datagram to learn the peer address, then
    /// **connects the socket to that peer** so subsequent `send`/`recv` work.
    ///
    /// Because the socket becomes connected, only one peer can be served per
    /// socket. Applications that need many peers should bind a socket per
    /// connection (or add a demultiplexer at a higher layer).
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

        Self::spawn_engine(
            socket,
            peer,
            false,
            Arc::new(validator),
            opts,
            Some(first_packet),
        )
        .await
    }

    /// Sends application data to the peer.
    ///
    /// Returns [`Error::Closed`] if the connection is already closed. Awaits
    /// when the internal send channel is full (backpressure).
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.send_vec(data.to_vec()).await
    }

    /// Sends application data without copying the caller's slice.
    ///
    /// Same as [`send`](Self::send) but takes ownership of the `Vec<u8>`.
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
    ///
    /// Returns [`Error::Closed`] when the peer closes the connection or the
    /// engine terminates.
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
    ///
    /// Returns immediately if already closed.
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
    ///
    /// Data is dropped only when the internal buffer between the engine task
    /// and the caller's `recv()` (see [`ConfigOptions::channel_capacity`] and
    /// the engine-side backlog) overflows. For a lossless stream, read
    /// `recv()` promptly or increase `channel_capacity`.
    pub fn dropped_app_data(&self) -> u64 {
        self.dropped_app_data.load(Ordering::Relaxed)
    }

    // -----------------------------------------------------------------------
    // Spawn
    // -----------------------------------------------------------------------

    async fn spawn_engine(
        socket: UdpSocket,
        peer: SocketAddr,
        is_client: bool,
        validator: CertValidator,
        opts: ConfigOptions,
        first_packet: Option<Vec<u8>>,
    ) -> Result<Self> {
        let (to_engine_tx, to_engine_rx) = mpsc::channel::<Vec<u8>>(opts.channel_capacity);
        let (from_engine_tx, from_engine_rx) = mpsc::channel::<Vec<u8>>(opts.channel_capacity);
        let (connected_tx, connected_rx) = oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = oneshot::channel::<()>();
        let (closed_tx, closed_rx) = watch::channel(false);

        let local = socket.local_addr().ok();
        let dropped_app_data = Arc::new(AtomicU64::new(0));

        // Resolve config and cert. Fast path returns cached Arcs without
        // touching the blocking pool; slow path runs on `spawn_blocking`.
        let (config, cert) = resolve_shared(&opts).await?;

        let mut dtls = Dtls::new_13(config, (*cert).clone(), Instant::now());
        dtls.set_active(is_client);

        tracing::debug!(%peer, is_client, local = ?local, "DTLS 1.3 engine created");

        let task_closed_tx = closed_tx.clone();
        let task_dropped = Arc::clone(&dropped_app_data);
        let task = tokio::spawn(async move {
            let result = run_engine(
                dtls,
                socket,
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
            )
            .await;

            match result {
                Ok(()) => tracing::debug!(%peer, "engine task finished"),
                Err(e) => tracing::error!(%peer, error = %e, "engine task failed"),
            }
            let _ = task_closed_tx.send(true);
        });

        // Wait for handshake.
        match connected_rx.await {
            Ok(Ok(())) => {
                tracing::debug!(%peer, "handshake completed");
            }
            Ok(Err(e)) => {
                task.abort();
                return Err(e);
            }
            Err(_) => {
                task.abort();
                return Err(Error::HandshakeFailed);
            }
        }

        Ok(Self {
            app_tx: to_engine_tx,
            app_rx: Arc::new(tokio::sync::Mutex::new(from_engine_rx)),
            close_tx: Arc::new(tokio::sync::Mutex::new(Some(close_tx))),
            task: Arc::new(tokio::sync::Mutex::new(Some(task))),
            closed_tx,
            closed_rx,
            peer,
            local,
            dropped_app_data,
        })
    }
}

// ---------------------------------------------------------------------------
// Engine loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_engine(
    mut dtls: Dtls,
    socket: UdpSocket,
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

    // ---- 1. First packet (server side) ----
    if let Some(pkt) = first_packet {
        if let Err(e) = dtls.handle_packet(&pkt) {
            return Err(report_error(&mut connected_tx, Error::Dtls(e)));
        }
    }

    // ---- 2. Kick off handshake (client sends ClientHello) ----
    if let Err(e) = dtls.handle_timeout(Instant::now()) {
        return Err(report_error(&mut connected_tx, Error::Dtls(e)));
    }

    loop {
        // ---- 2a. Flush any pending outbound-to-handle messages ----
        flush_app_out(&to_handle_tx, &mut app_out_pending);

        // ---- 2b. Drain engine output ----
        if let Err(e) = drain_output(
            &mut dtls,
            &socket,
            &mut out_buf,
            &mut next_timeout,
            &validator,
            &to_handle_tx,
            &mut app_out_pending,
            &mut connected,
            &mut connected_tx,
            &dropped_app_data,
        )
        .await
        {
            return Err(report_error(&mut connected_tx, e));
        }

        // ---- 2c. Notify handshake completion ----
        if connected {
            if let Some(tx) = connected_tx.take() {
                let _ = tx.send(Ok(()));
            }
        }

        // ---- 2d. Graceful close? ----
        if dtls.is_closed() {
            tracing::debug!(%peer, "engine reports closed");
            return Ok(());
        }

        // ---- 2e. Handshake deadline ----
        if !connected && Instant::now() > handshake_deadline {
            tracing::error!(%peer, "handshake deadline exceeded");
            return Err(report_error(&mut connected_tx, Error::HandshakeFailed));
        }

        // ---- 2f. Push pending app data ----
        let pushed = match push_app_data(&mut dtls, &mut pending_app, &mut from_handle_rx) {
            Ok(n) => n,
            Err(e) => return Err(report_error(&mut connected_tx, e)),
        };
        if pushed > 0 || pending_app.is_some() {
            if let Err(e) = drain_output(
                &mut dtls,
                &socket,
                &mut out_buf,
                &mut next_timeout,
                &validator,
                &to_handle_tx,
                &mut app_out_pending,
                &mut connected,
                &mut connected_tx,
                &dropped_app_data,
            )
            .await
            {
                return Err(report_error(&mut connected_tx, e));
            }
        }

        // ---- 2g. Backpressure spin ----
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

        // ---- 2h. More to push? ----
        if pushed > 0 {
            continue;
        }

        // ---- 2i. Block for I/O / timer / app / close ----
        let timer_deadline = next_timeout.unwrap_or_else(|| Instant::now() + SLEEP_MAX);

        tokio::select! {
            biased;

            _ = &mut close_rx => {
                tracing::debug!(%peer, "close requested, sending close_notify");
                let _ = dtls.close();
                let _ = drain_output(
                    &mut dtls,
                    &socket,
                    &mut out_buf,
                    &mut next_timeout,
                    &validator,
                    &to_handle_tx,
                    &mut app_out_pending,
                    &mut connected,
                    &mut connected_tx,
                    &dropped_app_data,
                ).await;
                return Ok(());
            }

            result = socket.recv(&mut udp_buf) => {
                let len = result?;
                if len == udp_buf.len() {
                    // Datagram may have been truncated at the recv boundary.
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

            // dimpl13 uses `std::time::Instant`; tokio's `sleep_until`
            // expects `tokio::time::Instant`. Convert at the call site.
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

/// Drain engine output: send packets, forward app data, run the validator.
#[allow(clippy::too_many_arguments)]
async fn drain_output(
    dtls: &mut Dtls,
    socket: &UdpSocket,
    out_buf: &mut Vec<u8>,
    next_timeout: &mut Option<Instant>,
    validator: &CertValidator,
    to_handle_tx: &mpsc::Sender<Vec<u8>>,
    app_out_pending: &mut VecDeque<Vec<u8>>,
    connected: &mut bool,
    connected_tx: &mut Option<oneshot::Sender<Result<()>>>,
    dropped_app_data: &AtomicU64,
) -> Result<()> {
    loop {
        match dtls.poll_output(out_buf) {
            Output::Packet(pkt) => {
                tracing::trace!(len = pkt.len(), "sending DTLS packet");
                socket.send(pkt).await?;
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                return Ok(());
            }
            Output::Connected => {
                tracing::debug!("handshake complete");
                *connected = true;
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
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Consumer gone; drop silently.
                    }
                }
            }
            Output::CloseNotify => {
                tracing::debug!("peer sent close_notify, responding");
                let _ = dtls.close();
            }
            Output::BufferTooSmall { needed } => {
                // Grow only, never shrink.
                if out_buf.len() < needed {
                    tracing::debug!(needed, current = out_buf.len(), "growing out_buf");
                    out_buf.resize(needed, 0);
                }
            }
            _ => {
                // KeyingMaterial (SRTP) or future variants.
                tracing::trace!("unhandled Output variant");
            }
        }
    }
}

/// Push queued application data into the DTLS engine.
///
/// Returns the number of messages successfully accepted. `Ok(0)` from the
/// engine means "transmit queue full" — the message is kept in
/// `pending_app` and retried after the next drain.
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
                // Transmit queue full; keep the message for the next drain.
                *pending_app = Some(data);
                break;
            }
            Ok(_n) => pushed += 1,
            Err(e) => {
                // Restore the message before propagating.
                *pending_app = Some(data);
                return Err(Error::Dtls(e));
            }
        }
    }
    Ok(pushed)
}

/// Flush `app_out_pending` into the mpsc channel.
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

/// Deliver an error to the pending handshake-waiter (if any), then return it
/// for logging by `run_engine`.
fn report_error(connected_tx: &mut Option<oneshot::Sender<Result<()>>>, err: Error) -> Error {
    if let Some(tx) = connected_tx.take() {
        let msg = err.to_string();
        let _ = tx.send(Err(err));
        Error::TaskFailed(msg)
    } else {
        err
    }
}