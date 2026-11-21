//! Encrypted transport: Noise XX handshake + secretstream over `AsyncRead + AsyncWrite`.
//!
//! Wire protocol (matching `@hyperswarm/secret-stream`):
//!
//! ```text
//! FRAMING: Every message is prefixed with a 3-byte little-endian uint24 length.
//!
//! NOISE XX HANDSHAKE:
//!   [3B len=32 ][32B Noise M1]                    initiator → responder
//!   [3B len=96 ][96B Noise M2]                    responder → initiator
//!   [3B len=64 ][64B Noise M3]                    initiator → responder
//!
//! ID HEADER EXCHANGE (both sides, immediately after handshake):
//!   [3B len=56 ][32B stream_id][24B secretstream_header]
//!
//! APPLICATION MESSAGES:
//!   [3B len=L+17][1B enc_tag][LB ciphertext][16B MAC]
//! ```

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{KeyInit, Mac};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::watch;
use tracing::debug;

use crate::crypto;
use crate::noise::{self, Keypair, NoiseError};
use crate::secretstream::{self, ABYTES, HEADERBYTES, KEYBYTES};

type Blake2bMac256 = Blake2bMac<U32>;

// ── Constants ────────────────────────────────────────────────────────────────

/// Size of the ID header body: 32-byte stream ID + 24-byte secretstream header.
const IDHEADERBYTES: usize = HEADERBYTES + 32;

/// Default maximum framed message body, matching the uint24 wire limit.
pub const DEFAULT_MAX_FRAME_LEN: usize = 0xFF_FF_FF;

/// Namespace constants for `hyperswarm/secret-stream`.
/// Index 0 = initiator, 1 = responder, 2 = send (unordered, unused for now).
static NS_SECRET_STREAM: LazyLock<[[u8; 32]; 3]> = LazyLock::new(|| {
    let ns = crypto::namespace("hyperswarm/secret-stream", &[0, 1, 2]);
    [ns[0], ns[1], ns[2]]
});

fn ns_initiator() -> &'static [u8; 32] {
    &NS_SECRET_STREAM[0]
}
fn ns_responder() -> &'static [u8; 32] {
    &NS_SECRET_STREAM[1]
}

struct StreamStats {
    raw_bytes_read: AtomicU64,
    raw_bytes_written: AtomicU64,
}

/// Cloneable raw-byte counters for a UDX-backed [`SecretStream`].
#[derive(Clone)]
pub struct SecretStreamStats {
    inner: Arc<StreamStats>,
}

impl SecretStreamStats {
    /// Number of encrypted application-frame bytes read from the raw stream.
    pub fn raw_bytes_read(&self) -> u64 {
        self.inner.raw_bytes_read.load(Ordering::Relaxed)
    }

    /// Number of encrypted application-frame bytes written to the raw stream.
    pub fn raw_bytes_written(&self) -> u64 {
        self.inner.raw_bytes_written.load(Ordering::Relaxed)
    }
}

// ── Keep-alive ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct KeepAliveState {
    /// Waker of the task reading the unsplit stream; it writes requested
    /// keep-alives.
    waker: Option<Waker>,
    /// A keep-alive frame was encrypted and is being written.
    in_flight: bool,
    /// A read or write failed; keep-alives can no longer be written.
    failed: bool,
    /// The periodic timer started by [`SecretStream::set_keep_alive`].
    timer: Option<tokio::task::AbortHandle>,
}

/// Keep-alive state owned by the stream (or its halves). Handles reach it
/// only through a `Weak`, so they never keep the transport open.
struct KeepAliveShared {
    state: Mutex<KeepAliveState>,
    /// A keep-alive was requested and not started yet. The only cost a
    /// normal write pays: one atomic load.
    pending: AtomicBool,
    /// Keep-alives fully written. Dropping the sender (with the stream)
    /// wakes every waiter.
    done: watch::Sender<u64>,
}

impl KeepAliveShared {
    fn lock(&self) -> MutexGuard<'_, KeepAliveState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, waker: &Waker) {
        let mut state = self.lock();
        if !state.waker.as_ref().is_some_and(|w| w.will_wake(waker)) {
            state.waker = Some(waker.clone());
        }
    }

    /// Claim a requested keep-alive for writing.
    fn take_pending(&self) -> bool {
        if !self.pending.load(Ordering::Acquire) {
            return false;
        }
        let mut state = self.lock();
        let taken = self.pending.swap(false, Ordering::AcqRel);
        state.in_flight |= taken;
        taken
    }

    fn finish(&self) {
        self.lock().in_flight = false;
        self.done.send_modify(|count| *count += 1);
    }

    fn fail(&self) {
        self.lock().failed = true;
        self.done.send_modify(|_| {});
    }

    /// A write error other than an oversized message breaks the stream.
    fn fail_on(&self, err: &SecretStreamError) {
        if !matches!(err, SecretStreamError::MessageTooLarge { .. }) {
            self.fail();
        }
    }
}

impl Drop for KeepAliveShared {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
    }
}

/// Where a keep-alive handle finds the stream: the shared state and, after
/// [`SecretStream::into_split`], the write half. Both only weakly.
struct KeepAliveSlot<W> {
    shared: Weak<KeepAliveShared>,
    /// Set once by `into_split`, under the shared state lock.
    writer: Mutex<Option<Weak<tokio::sync::Mutex<WriterInner<W>>>>>,
}

impl<W> KeepAliveSlot<W> {
    fn writer(&self) -> Option<Weak<tokio::sync::Mutex<WriterInner<W>>>> {
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn new_keep_alive<W>() -> (Arc<KeepAliveShared>, Arc<KeepAliveSlot<W>>) {
    let shared = Arc::new(KeepAliveShared {
        state: Mutex::new(KeepAliveState::default()),
        pending: AtomicBool::new(false),
        done: watch::Sender::new(0),
    });
    let slot = Arc::new(KeepAliveSlot {
        shared: Arc::downgrade(&shared),
        writer: Mutex::new(None),
    });
    (shared, slot)
}

/// Cloneable handle that writes keep-alive messages on a [`SecretStream`]
/// (Node `stream.sendKeepAlive()`).
///
/// Taken with [`SecretStream::keep_alive_handle`] or
/// [`SecretStreamWriteHalf::keep_alive_handle`]; a handle taken before
/// [`SecretStream::into_split`] keeps working on the write half. The handle
/// holds the stream only weakly: it never keeps the transport open.
pub struct SecretStreamKeepAlive<T> {
    slot: Arc<KeepAliveSlot<WriteHalf<T>>>,
}

impl<T> Clone for SecretStreamKeepAlive<T> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

impl<T: AsyncWrite + Unpin + Send> SecretStreamKeepAlive<T> {
    /// Write one empty encrypted message, using the stream's encryptor and
    /// write side, serialized with its normal writes.
    ///
    /// On an unsplit stream the handle cannot write: it asks the stream's
    /// owner, and the message is written (and this future resolves) only
    /// when the owner polls [`SecretStream::read`], [`SecretStream::write`]
    /// or [`SecretStream::shutdown`] again. A frame the transport took only
    /// in part stays queued and is finished by that next poll, before any
    /// other frame. Protomux takes the whole, unsplit stream and keeps a
    /// read pending, so there the message goes out at once; the swarm hands
    /// connections out unsplit too. After [`SecretStream::into_split`] the
    /// handle writes by itself through the write half.
    ///
    /// Resolves once the message is handed to the transport; fails with
    /// [`SecretStreamError::Closed`] when the stream was dropped or failed,
    /// including while waiting for the owner.
    pub async fn send_keep_alive(&self) -> Result<(), SecretStreamError> {
        let mut target = None;
        loop {
            let shared = self
                .slot
                .shared
                .upgrade()
                .ok_or(SecretStreamError::Closed)?;
            let wait = {
                let mut state = shared.lock();
                if state.failed {
                    return Err(SecretStreamError::Closed);
                }
                match self.slot.writer() {
                    Some(writer) => Err(writer),
                    None => {
                        let mut done = shared.done.subscribe();
                        let count = *done.borrow_and_update();
                        // A keep-alive already in flight answers this request too.
                        let target = *target.get_or_insert(count + 1);
                        if count >= target {
                            return Ok(());
                        }
                        if !state.in_flight {
                            shared.pending.store(true, Ordering::Release);
                        }
                        if let Some(waker) = state.waker.take() {
                            waker.wake();
                        }
                        Ok(done)
                    }
                }
            };
            drop(shared);
            match wait {
                Ok(mut done) => {
                    if done.changed().await.is_err() {
                        return Err(SecretStreamError::Closed);
                    }
                }
                // Split: write through the write half directly.
                Err(writer) => {
                    let writer = writer.upgrade().ok_or(SecretStreamError::Closed)?;
                    return writer.lock().await.send_keep_alive().await;
                }
            }
        }
    }

    /// Whether the stream was dropped or failed, so no keep-alive can be
    /// written any more.
    pub fn is_closed(&self) -> bool {
        let Some(shared) = self.slot.shared.upgrade() else {
            return true;
        };
        let state = shared.lock();
        state.failed
            || self
                .slot
                .writer()
                .is_some_and(|writer| writer.strong_count() == 0)
    }
}

/// Write an empty message whenever `interval` passes without a write.
///
/// Writes are seen through the raw byte counter, so a normal write pays
/// nothing for the timer. The counter is sampled four times per interval: a
/// keep-alive goes out between `interval` and `1.25 × interval` after the
/// last write (Node refreshes its timer on every write: exactly `interval`),
/// and exactly every `interval` on an idle stream.
async fn keep_alive_timer<T: AsyncWrite + Unpin + Send>(
    handle: SecretStreamKeepAlive<T>,
    stats: Arc<StreamStats>,
    interval: Duration,
) {
    const STEPS: u32 = 4;
    let mut ticks = tokio::time::interval((interval / STEPS).max(Duration::from_millis(1)));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks.tick().await;
    let mut seen = stats.raw_bytes_written.load(Ordering::Relaxed);
    let mut quiet = 0;
    loop {
        ticks.tick().await;
        if handle.is_closed() {
            return;
        }
        let written = stats.raw_bytes_written.load(Ordering::Relaxed);
        if written != seen {
            seen = written;
            quiet = 0;
            continue;
        }
        quiet += 1;
        if quiet < STEPS {
            continue;
        }
        if handle.send_keep_alive().await.is_err() {
            return;
        }
        seen = stats.raw_bytes_written.load(Ordering::Relaxed);
        quiet = 0;
        ticks.reset();
    }
}

/// A framed keep-alive message, possibly partly written.
struct OutFrame {
    buf: Vec<u8>,
    pos: usize,
}

impl OutFrame {
    fn keep_alive(encrypt: &mut secretstream::Push) -> Self {
        let encrypted = encrypt.next(&[]);
        let len = encrypted.len();
        let mut buf = Vec::with_capacity(3 + len);
        buf.extend_from_slice(&[len as u8, (len >> 8) as u8, (len >> 16) as u8]);
        buf.extend_from_slice(&encrypted);
        Self { buf, pos: 0 }
    }
}

/// Finish writing `out`, if any. The frame stays in `out` until it is fully
/// written, so a cancelled caller never leaves half a frame on the wire.
fn poll_flush_out<W: AsyncWrite + Unpin>(
    raw: &mut W,
    out: &mut Option<OutFrame>,
    stats: &StreamStats,
    keep_alive: &KeepAliveShared,
    cx: &mut Context<'_>,
) -> Poll<Result<(), SecretStreamError>> {
    let Some(frame) = out.as_mut() else {
        return Poll::Ready(Ok(()));
    };
    while frame.pos < frame.buf.len() {
        match ready!(Pin::new(&mut *raw).poll_write(cx, &frame.buf[frame.pos..])) {
            Ok(0) => {
                keep_alive.fail();
                return Poll::Ready(Err(
                    std::io::Error::from(std::io::ErrorKind::WriteZero).into()
                ));
            }
            Ok(n) => frame.pos += n,
            Err(err) => {
                keep_alive.fail();
                return Poll::Ready(Err(err.into()));
            }
        }
    }
    stats
        .raw_bytes_written
        .fetch_add(frame.buf.len() as u64, Ordering::Relaxed);
    *out = None;
    keep_alive.finish();
    Poll::Ready(Ok(()))
}

/// Cancel-safe frame reader: a partly read frame survives a dropped `read`
/// future (Protomux drops it whenever it has something to write).
#[derive(Default)]
struct FrameReader {
    header: [u8; 3],
    header_len: usize,
    body: Option<Vec<u8>>,
    body_len: usize,
}

impl FrameReader {
    /// Same results as [`read_frame`].
    fn poll_frame<R: AsyncRead + Unpin>(
        &mut self,
        raw: &mut R,
        cx: &mut Context<'_>,
        max_frame_len: usize,
    ) -> Poll<Result<Option<Vec<u8>>, SecretStreamError>> {
        loop {
            if let Some(body) = self.body.as_mut() {
                while self.body_len < body.len() {
                    let mut buf = ReadBuf::new(&mut body[self.body_len..]);
                    match ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf)) {
                        Ok(()) if !buf.filled().is_empty() => self.body_len += buf.filled().len(),
                        _ => {
                            self.body = None;
                            self.body_len = 0;
                            return Poll::Ready(Err(SecretStreamError::UnexpectedEof));
                        }
                    }
                }
                self.body_len = 0;
                return Poll::Ready(Ok(self.body.take()));
            }
            while self.header_len < self.header.len() {
                let mut buf = ReadBuf::new(&mut self.header[self.header_len..]);
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    self.header_len = 0;
                    return Poll::Ready(Ok(None));
                }
                self.header_len += n;
            }
            self.header_len = 0;
            let [a, b, c] = self.header;
            let len = a as usize | (b as usize) << 8 | (c as usize) << 16;
            if len > max_frame_len {
                return Poll::Ready(Err(SecretStreamError::MessageTooLarge {
                    len,
                    max: max_frame_len,
                }));
            }
            self.body = Some(vec![0u8; len]);
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
/// Errors returned by `SecretStream` and its framing helpers.
#[non_exhaustive]
pub enum SecretStreamError {
    /// An underlying I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Noise handshake negotiation failed.
    #[error("noise handshake failed: {0}")]
    Noise(#[from] NoiseError),

    /// Secretstream decryption failed.
    #[error("secretstream decryption failed: {0}")]
    Decrypt(#[from] secretstream::SecretstreamError),

    /// The handshake ended before completion.
    #[error("handshake did not complete")]
    HandshakeIncomplete,

    /// EOF was encountered while the handshake was still in progress.
    #[error("unexpected EOF during handshake")]
    UnexpectedEof,

    /// The ID header length was invalid.
    #[error("invalid ID header: expected {expected} bytes, got {got}")]
    InvalidIdHeader {
        /// The expected header length in bytes.
        expected: usize,
        /// The actual header length received.
        got: usize,
    },

    /// The remote stream ID did not match the expected identity.
    #[error("stream ID mismatch: remote peer sent wrong identity")]
    StreamIdMismatch,

    /// The framed message exceeded the configured maximum allowed length.
    #[error("message too large: {len} bytes exceeds maximum {max}")]
    MessageTooLarge {
        /// The length of the oversized message in bytes.
        len: usize,
        /// The configured maximum frame length in bytes.
        max: usize,
    },

    /// The stream was dropped or failed, so a keep-alive cannot be written.
    #[error("secret stream closed")]
    Closed,
}

// ── SecretStream ─────────────────────────────────────────────────────────────

/// An encrypted bidirectional stream.
///
/// Wraps any `AsyncRead + AsyncWrite` transport with a Noise XX handshake
/// followed by libsodium-compatible secretstream encryption.
pub struct SecretStream<T> {
    raw: T,
    encrypt: secretstream::Push,
    decrypt: secretstream::Pull,
    remote_public_key: [u8; 32],
    handshake_hash: [u8; 64],
    is_initiator: bool,
    stats: Arc<StreamStats>,
    max_frame_len: usize,
    reader: FrameReader,
    keep_alive: Arc<KeepAliveShared>,
    keep_alive_slot: Arc<KeepAliveSlot<WriteHalf<T>>>,
    /// A keep-alive frame being written.
    keep_alive_out: Option<OutFrame>,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> SecretStream<T> {
    /// Perform the Noise XX handshake + ID header exchange, returning a ready
    /// encrypted stream.
    ///
    /// - `is_initiator`: true for the connecting side, false for the accepting side.
    /// - `raw`: the underlying transport (e.g. `TcpStream`, UDX stream adapter).
    /// - `keypair`: the local Ed25519 static keypair.
    pub async fn new(
        is_initiator: bool,
        mut raw: T,
        keypair: Keypair,
    ) -> Result<Self, SecretStreamError> {
        let stats = Arc::new(StreamStats {
            raw_bytes_read: AtomicU64::new(0),
            raw_bytes_written: AtomicU64::new(0),
        });
        // ── Phase 1: Noise XX handshake ──────────────────────────────────
        let mut handshake = noise::Handshake::new(is_initiator, keypair);

        if is_initiator {
            // → M1
            let m1 = handshake.send().map_err(SecretStreamError::Noise)?;
            write_frame(&mut raw, &m1, DEFAULT_MAX_FRAME_LEN).await?;

            // ← M2
            let m2 = read_frame(&mut raw, DEFAULT_MAX_FRAME_LEN)
                .await?
                .ok_or(SecretStreamError::UnexpectedEof)?;
            handshake.recv(&m2).map_err(SecretStreamError::Noise)?;

            // → M3
            let m3 = handshake.send().map_err(SecretStreamError::Noise)?;
            write_frame(&mut raw, &m3, DEFAULT_MAX_FRAME_LEN).await?;
        } else {
            // ← M1
            let m1 = read_frame(&mut raw, DEFAULT_MAX_FRAME_LEN)
                .await?
                .ok_or(SecretStreamError::UnexpectedEof)?;
            handshake.recv(&m1).map_err(SecretStreamError::Noise)?;

            // → M2
            let m2 = handshake.send().map_err(SecretStreamError::Noise)?;
            write_frame(&mut raw, &m2, DEFAULT_MAX_FRAME_LEN).await?;

            // ← M3
            let m3 = read_frame(&mut raw, DEFAULT_MAX_FRAME_LEN)
                .await?
                .ok_or(SecretStreamError::UnexpectedEof)?;
            handshake.recv(&m3).map_err(SecretStreamError::Noise)?;
        }

        let hr = handshake
            .result()
            .ok_or(SecretStreamError::HandshakeIncomplete)?
            .clone();

        debug!(is_initiator, "noise handshake complete");

        // ── Phase 2: ID header exchange ──────────────────────────────────
        // Create encryptor → produces the 24-byte secretstream header.
        let tx_key: [u8; KEYBYTES] = hr.tx;
        let (encrypt, ss_header) = secretstream::Push::new(&tx_key);

        // Build local ID message: [32B stream_id][24B secretstream_header]
        let local_id = stream_id(&hr.handshake_hash, is_initiator);
        let mut id_msg = Vec::with_capacity(IDHEADERBYTES);
        id_msg.extend_from_slice(&local_id);
        id_msg.extend_from_slice(&ss_header);
        write_frame(&mut raw, &id_msg, DEFAULT_MAX_FRAME_LEN).await?;

        // Read remote ID message.
        let remote_msg = read_frame(&mut raw, DEFAULT_MAX_FRAME_LEN)
            .await?
            .ok_or(SecretStreamError::UnexpectedEof)?;
        if remote_msg.len() != IDHEADERBYTES {
            return Err(SecretStreamError::InvalidIdHeader {
                expected: IDHEADERBYTES,
                got: remote_msg.len(),
            });
        }

        // Validate remote stream ID.
        let remote_id = &remote_msg[..32];
        let expected_id = stream_id(&hr.handshake_hash, !is_initiator);
        if remote_id != expected_id {
            return Err(SecretStreamError::StreamIdMismatch);
        }

        // Initialize decryptor with remote's secretstream header.
        let remote_header: [u8; HEADERBYTES] = remote_msg[32..56]
            .try_into()
            // SAFETY: remote_msg.len() == IDHEADERBYTES (56) verified above; [32..56] is 24 bytes == HEADERBYTES.
            .expect("slice length verified above");
        let rx_key: [u8; KEYBYTES] = hr.rx;
        let decrypt = secretstream::Pull::new(&rx_key, &remote_header);

        debug!(is_initiator, "secret stream established");

        let (keep_alive, keep_alive_slot) = new_keep_alive();
        Ok(Self {
            raw,
            encrypt,
            decrypt,
            remote_public_key: hr.remote_public_key,
            handshake_hash: hr.handshake_hash,
            is_initiator,
            stats,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            reader: FrameReader::default(),
            keep_alive,
            keep_alive_slot,
            keep_alive_out: None,
        })
    }

    /// Create a SecretStream from pre-negotiated session keys (e.g. from Noise IK).
    ///
    /// Skips the Noise XX handshake but still performs the ID header exchange
    /// (stream identity + secretstream header). Used for relay connections and
    /// direct connections where Noise IK already established the session.
    pub async fn from_session(
        is_initiator: bool,
        mut raw: T,
        tx: [u8; 32],
        rx: [u8; 32],
        handshake_hash: [u8; 64],
        remote_public_key: [u8; 32],
    ) -> Result<Self, SecretStreamError> {
        let (encrypt, ss_header) = secretstream::Push::new(&tx);

        let local_id = stream_id(&handshake_hash, is_initiator);
        let mut id_msg = Vec::with_capacity(IDHEADERBYTES);
        id_msg.extend_from_slice(&local_id);
        id_msg.extend_from_slice(&ss_header);
        write_frame(&mut raw, &id_msg, DEFAULT_MAX_FRAME_LEN).await?;

        let remote_msg = read_frame(&mut raw, DEFAULT_MAX_FRAME_LEN)
            .await?
            .ok_or(SecretStreamError::UnexpectedEof)?;
        if remote_msg.len() != IDHEADERBYTES {
            return Err(SecretStreamError::InvalidIdHeader {
                expected: IDHEADERBYTES,
                got: remote_msg.len(),
            });
        }

        let remote_id = &remote_msg[..32];
        let expected_id = stream_id(&handshake_hash, !is_initiator);
        if remote_id != expected_id {
            return Err(SecretStreamError::StreamIdMismatch);
        }

        let remote_header: [u8; HEADERBYTES] = remote_msg[32..56]
            .try_into()
            // SAFETY: remote_msg.len() == IDHEADERBYTES (56) verified above; [32..56] is 24 bytes == HEADERBYTES.
            .expect("slice length verified above");
        let decrypt = secretstream::Pull::new(&rx, &remote_header);

        debug!(is_initiator, "secret stream established (from session)");

        let (keep_alive, keep_alive_slot) = new_keep_alive();
        Ok(Self {
            raw,
            encrypt,
            decrypt,
            remote_public_key,
            handshake_hash,
            is_initiator,
            stats: Arc::new(StreamStats {
                raw_bytes_read: AtomicU64::new(0),
                raw_bytes_written: AtomicU64::new(0),
            }),
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
            reader: FrameReader::default(),
            keep_alive,
            keep_alive_slot,
            keep_alive_out: None,
        })
    }

    /// Set the maximum encrypted message frame length for this stream.
    ///
    /// The default is [`DEFAULT_MAX_FRAME_LEN`]. This limit applies after the
    /// Noise and ID-header exchanges, which always use the wire maximum.
    pub fn with_max_frame_len(mut self, max_frame_len: usize) -> Self {
        self.max_frame_len = max_frame_len;
        self
    }

    /// Encrypt and send `data` as a single framed message.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), SecretStreamError> {
        // A requested keep-alive goes first, so frames never interleave.
        if self.keep_alive_out.is_some() || self.keep_alive.pending.load(Ordering::Acquire) {
            poll_fn(|cx| self.poll_keep_alive(cx)).await?;
        }
        let encrypted = self.encrypt.next(data);
        // encrypted = [enc_tag(1)][ciphertext][mac(16)] = data.len() + ABYTES bytes
        debug_assert_eq!(encrypted.len(), data.len() + ABYTES);
        if let Err(err) = write_frame(&mut self.raw, &encrypted, self.max_frame_len).await {
            self.keep_alive.fail_on(&err);
            return Err(err);
        }
        self.stats
            .raw_bytes_written
            .fetch_add((3 + encrypted.len()) as u64, Ordering::Relaxed);
        Ok(())
    }
    /// Gracefully close the write half, sending a FIN to the remote peer.
    pub async fn shutdown(&mut self) -> Result<(), SecretStreamError> {
        poll_fn(|cx| self.poll_keep_alive(cx)).await?;
        self.raw.shutdown().await.map_err(SecretStreamError::Io)
    }

    /// A cloneable handle that writes keep-alive messages on this stream
    /// (Node `stream.sendKeepAlive()`); it stays valid after
    /// [`into_split`](Self::into_split).
    pub fn keep_alive_handle(&self) -> SecretStreamKeepAlive<T> {
        SecretStreamKeepAlive {
            slot: Arc::clone(&self.keep_alive_slot),
        }
    }

    /// Start, or finish writing, a requested keep-alive.
    fn poll_keep_alive(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SecretStreamError>> {
        if self.keep_alive_out.is_none() && self.keep_alive.take_pending() {
            self.keep_alive_out = Some(OutFrame::keep_alive(&mut self.encrypt));
        }
        poll_flush_out(
            &mut self.raw,
            &mut self.keep_alive_out,
            &self.stats,
            &self.keep_alive,
            cx,
        )
    }

    /// Read one frame. A waiting read also writes requested keep-alives, so
    /// an owner that keeps a read pending (Protomux) needs no other hook.
    fn poll_read_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Vec<u8>>, SecretStreamError>> {
        self.keep_alive.register(cx.waker());
        if let Poll::Ready(Err(err)) = self.poll_keep_alive(cx) {
            return Poll::Ready(Err(err));
        }
        self.reader
            .poll_frame(&mut self.raw, cx, self.max_frame_len)
    }

    /// Read and decrypt the next framed message.
    ///
    /// Returns `Ok(None)` on clean EOF, `Ok(Some(plaintext))` for data messages.
    /// Empty messages (keepalives) are silently consumed and the next message
    /// is read.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, SecretStreamError> {
        loop {
            let opened = match poll_fn(|cx| self.poll_read_frame(cx)).await {
                Ok(Some(msg)) => open_frame(&mut self.decrypt, &self.stats, &msg),
                Ok(None) => return Ok(None),
                Err(err) => Err(err),
            };
            match opened {
                Ok(Some(plaintext)) => return Ok(Some(plaintext)),
                Ok(None) => continue,
                Err(err) => {
                    self.keep_alive.fail();
                    return Err(err);
                }
            }
        }
    }

    /// Remote peer's static Ed25519 public key.
    pub fn remote_public_key(&self) -> &[u8; 32] {
        &self.remote_public_key
    }

    /// BLAKE2b-512 hash of the Noise handshake transcript.
    pub fn handshake_hash(&self) -> &[u8; 64] {
        &self.handshake_hash
    }

    /// Whether this side initiated the connection.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Consume the wrapper, returning the underlying transport.
    pub fn into_inner(self) -> T {
        self.raw
    }

    /// Split the stream into owned read and write halves.
    ///
    /// The underlying transport is split with [`tokio::io::split`]; the
    /// decryptor (`Pull`) moves into the [`SecretStreamReadHalf`] and the
    /// encryptor (`Push`) moves into the [`SecretStreamWriteHalf`]. Because the
    /// two halves own disjoint cipher state, they can be driven from separate
    /// tasks concurrently without either half cancelling the other's in-flight
    /// framed read/write. Wire framing and cipher behavior are identical to the
    /// unsplit [`SecretStream::read`]/[`SecretStream::write`].
    pub fn into_split(
        self,
    ) -> (
        SecretStreamReadHalf<ReadHalf<T>>,
        SecretStreamWriteHalf<WriteHalf<T>>,
    ) {
        let (read_raw, write_raw) = tokio::io::split(self.raw);
        let mut encrypt = self.encrypt;
        let mut keep_alive_out = self.keep_alive_out;
        let writer = {
            let mut state = self.keep_alive.lock();
            // A requested keep-alive moves to the write half; its waiters
            // wake below and continue there.
            if keep_alive_out.is_none() && self.keep_alive.pending.swap(false, Ordering::AcqRel) {
                state.in_flight = true;
                keep_alive_out = Some(OutFrame::keep_alive(&mut encrypt));
            }
            let writer = Arc::new(tokio::sync::Mutex::new(WriterInner {
                raw: write_raw,
                encrypt,
                keep_alive_out,
                stats: Arc::clone(&self.stats),
                keep_alive: Arc::clone(&self.keep_alive),
                max_frame_len: self.max_frame_len,
            }));
            *self
                .keep_alive_slot
                .writer
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(&writer));
            writer
        };
        self.keep_alive.done.send_modify(|_| {});
        (
            SecretStreamReadHalf {
                raw: read_raw,
                decrypt: self.decrypt,
                stats: self.stats,
                max_frame_len: self.max_frame_len,
                reader: self.reader,
                keep_alive: self.keep_alive,
            },
            SecretStreamWriteHalf {
                inner: writer,
                keep_alive_slot: self.keep_alive_slot,
            },
        )
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> SecretStream<T> {
    /// Write an empty message whenever `interval` passes without a write,
    /// until the stream is dropped or fails (Node `stream.setKeepAlive(ms)`).
    /// `None` (or a zero interval) stops it. Needs a Tokio runtime.
    ///
    /// The empty message is a data message, so the transport acks and
    /// retransmits it and finds a dead peer by its retransmit timeout. On an
    /// unsplit stream the message is written by the task reading it.
    pub fn set_keep_alive(&self, interval: Option<Duration>) {
        let mut state = self.keep_alive.lock();
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        let Some(interval) = interval.filter(|interval| !interval.is_zero()) else {
            return;
        };
        let timer = tokio::spawn(keep_alive_timer(
            self.keep_alive_handle(),
            Arc::clone(&self.stats),
            interval,
        ));
        state.timer = Some(timer.abort_handle());
    }
}

impl SecretStream<libudx::UdxAsyncStream> {
    /// Take the notification for closure of the underlying UDX stream.
    pub fn take_close_notification(&mut self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        self.raw.take_close_notification()
    }

    /// A handle that destroys the underlying UDX stream from another owner,
    /// so a swarm can close connections it has already handed out
    /// (Node `swarm.suspend()` → `connection.destroy()`).
    pub fn abort_handle(&self) -> libudx::UdxStreamAbort {
        self.raw.abort_handle()
    }

    /// A handle that moves the underlying UDX stream to another peer and
    /// path (Node `rawStream.changeRemote`); the cipher state stays put.
    pub fn remote_handle(&self) -> libudx::UdxStreamRemote {
        self.raw.remote_handle()
    }

    /// Return cloneable counters that remain valid after the stream is handed
    /// to another owner.
    pub fn stats_handle(&self) -> SecretStreamStats {
        SecretStreamStats {
            inner: Arc::clone(&self.stats),
        }
    }
}

/// Owned read half of a [`SecretStream`], produced by [`SecretStream::into_split`].
///
/// Holds the decryptor and the read side of the underlying transport. Its
/// [`read`](SecretStreamReadHalf::read) mirrors [`SecretStream::read`] exactly
/// (same length-prefixed framing, same empty-keepalive handling, same AEAD
/// decryption).
pub struct SecretStreamReadHalf<R> {
    raw: R,
    decrypt: secretstream::Pull,
    stats: Arc<StreamStats>,
    max_frame_len: usize,
    reader: FrameReader,
    keep_alive: Arc<KeepAliveShared>,
}

impl<R: AsyncRead + Unpin + Send> SecretStreamReadHalf<R> {
    /// Read and decrypt the next framed message.
    ///
    /// Returns `Ok(None)` on clean EOF, `Ok(Some(plaintext))` for data
    /// messages. Empty messages (keepalives) are silently consumed and the next
    /// message is read. Identical framing/cipher semantics to
    /// [`SecretStream::read`].
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, SecretStreamError> {
        loop {
            let frame = poll_fn(|cx| {
                self.reader
                    .poll_frame(&mut self.raw, cx, self.max_frame_len)
            });
            let opened = match frame.await {
                Ok(Some(msg)) => open_frame(&mut self.decrypt, &self.stats, &msg),
                Ok(None) => return Ok(None),
                Err(err) => Err(err),
            };
            match opened {
                Ok(Some(plaintext)) => return Ok(Some(plaintext)),
                Ok(None) => continue,
                Err(err) => {
                    self.keep_alive.fail();
                    return Err(err);
                }
            }
        }
    }
}

/// Count a received frame and decrypt it; `Ok(None)` for an empty
/// (keep-alive) message, which is dropped as Node does.
fn open_frame(
    decrypt: &mut secretstream::Pull,
    stats: &StreamStats,
    msg: &[u8],
) -> Result<Option<Vec<u8>>, SecretStreamError> {
    stats
        .raw_bytes_read
        .fetch_add((3 + msg.len()) as u64, Ordering::Relaxed);
    if msg.len() < ABYTES {
        return Err(SecretStreamError::Decrypt(
            secretstream::SecretstreamError::CiphertextTooShort,
        ));
    }
    let (plaintext, _tag) = decrypt.next(msg)?;
    Ok((!plaintext.is_empty()).then_some(plaintext))
}

/// Owned write half of a [`SecretStream`], produced by [`SecretStream::into_split`].
///
/// Holds the encryptor and the write side of the underlying transport. Its
/// [`write`](SecretStreamWriteHalf::write) mirrors [`SecretStream::write`]
/// exactly.
pub struct SecretStreamWriteHalf<W> {
    /// Shared with keep-alive handles (weakly), which write through it.
    inner: Arc<tokio::sync::Mutex<WriterInner<W>>>,
    keep_alive_slot: Arc<KeepAliveSlot<W>>,
}

struct WriterInner<W> {
    raw: W,
    encrypt: secretstream::Push,
    keep_alive_out: Option<OutFrame>,
    stats: Arc<StreamStats>,
    keep_alive: Arc<KeepAliveShared>,
    max_frame_len: usize,
}

impl<W: AsyncWrite + Unpin> WriterInner<W> {
    async fn flush_keep_alive(&mut self) -> Result<(), SecretStreamError> {
        poll_fn(|cx| {
            poll_flush_out(
                &mut self.raw,
                &mut self.keep_alive_out,
                &self.stats,
                &self.keep_alive,
                cx,
            )
        })
        .await
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), SecretStreamError> {
        self.flush_keep_alive().await?;
        let encrypted = self.encrypt.next(data);
        // encrypted = [enc_tag(1)][ciphertext][mac(16)] = data.len() + ABYTES bytes
        debug_assert_eq!(encrypted.len(), data.len() + ABYTES);
        if let Err(err) = write_frame(&mut self.raw, &encrypted, self.max_frame_len).await {
            self.keep_alive.fail_on(&err);
            return Err(err);
        }
        self.stats
            .raw_bytes_written
            .fetch_add((3 + encrypted.len()) as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn send_keep_alive(&mut self) -> Result<(), SecretStreamError> {
        self.flush_keep_alive().await?;
        self.keep_alive_out = Some(OutFrame::keep_alive(&mut self.encrypt));
        self.flush_keep_alive().await
    }
}

impl<W: AsyncWrite + Unpin + Send> SecretStreamWriteHalf<W> {
    /// Encrypt and send `data` as a single framed message.
    ///
    /// Identical framing/cipher semantics to [`SecretStream::write`].
    pub async fn write(&mut self, data: &[u8]) -> Result<(), SecretStreamError> {
        self.inner.lock().await.write(data).await
    }

    /// Gracefully close the write half, sending a FIN to the remote peer.
    ///
    /// Identical to [`SecretStream::shutdown`].
    pub async fn shutdown(&mut self) -> Result<(), SecretStreamError> {
        let mut inner = self.inner.lock().await;
        inner.flush_keep_alive().await?;
        inner.raw.shutdown().await.map_err(SecretStreamError::Io)
    }
}

impl<T> SecretStreamWriteHalf<WriteHalf<T>> {
    /// A cloneable handle that writes keep-alive messages through this
    /// write half (Node `stream.sendKeepAlive()`).
    pub fn keep_alive_handle(&self) -> SecretStreamKeepAlive<T> {
        SecretStreamKeepAlive {
            slot: Arc::clone(&self.keep_alive_slot),
        }
    }
}

// ── FramedStream adapter ─────────────────────────────────────────────────────

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> crate::protomux::FramedStream
    for SecretStream<T>
{
    async fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        self.read().await.map_err(|e| match e {
            SecretStreamError::Io(io_err) => io_err,
            other => std::io::Error::other(other.to_string()),
        })
    }

    async fn write_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.write(data).await.map_err(|e| match e {
            SecretStreamError::Io(io_err) => io_err,
            other => std::io::Error::other(other.to_string()),
        })
    }
}

// ── Framing helpers ──────────────────────────────────────────────────────────

/// Write a length-prefixed frame: `[3B LE uint24 length][body]`.
///
/// Not flushed: `write_all` has handed the frame to the transport, and a
/// flush on `UdxAsyncStream` waits for the peer's ACK, which would make every
/// frame a round trip. `shutdown` still waits for everything to be ACKed.
async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
    max_frame_len: usize,
) -> Result<(), SecretStreamError> {
    let len = data.len();
    if len > max_frame_len {
        return Err(SecretStreamError::MessageTooLarge {
            len,
            max: max_frame_len,
        });
    }
    let header = [len as u8, (len >> 8) as u8, (len >> 16) as u8];
    w.write_all(&header).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed frame.
///
/// Returns `Ok(None)` on clean EOF (zero bytes read for the length header).
/// Returns `Err(UnexpectedEof)` if EOF occurs mid-message.
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_frame_len: usize,
) -> Result<Option<Vec<u8>>, SecretStreamError> {
    let mut header = [0u8; 3];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(SecretStreamError::Io(e)),
    }

    let len = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
    if len > max_frame_len {
        return Err(SecretStreamError::MessageTooLarge {
            len,
            max: max_frame_len,
        });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .map_err(|_| SecretStreamError::UnexpectedEof)?;

    Ok(Some(buf))
}

// ── Stream ID derivation ─────────────────────────────────────────────────────

/// Compute the 32-byte stream identity for one side of the connection.
///
/// Equivalent to Node.js:
/// ```js
/// sodium.crypto_generichash(out, isInitiator ? NS_INITIATOR : NS_RESPONDER, handshakeHash)
/// ```
///
/// This is a keyed BLAKE2b-256: data = namespace constant, key = handshake hash.
fn stream_id(handshake_hash: &[u8; 64], is_initiator: bool) -> [u8; 32] {
    let ns = if is_initiator {
        ns_initiator()
    } else {
        ns_responder()
    };
    let mut mac: Blake2bMac256 =
        // SAFETY: BLAKE2b accepts keys from 1..=64 bytes; handshake_hash is always 64 bytes.
        KeyInit::new_from_slice(handshake_hash).expect("64-byte key is valid for BLAKE2b");
    mac.update(ns);
    let output = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_constants_are_distinct() {
        let ns = &*NS_SECRET_STREAM;
        assert_ne!(ns[0], ns[1]);
        assert_ne!(ns[1], ns[2]);
        assert_ne!(ns[0], ns[2]);
    }

    #[test]
    fn stream_id_differs_by_role() {
        let hash = [0xABu8; 64];
        let id_i = stream_id(&hash, true);
        let id_r = stream_id(&hash, false);
        assert_ne!(id_i, id_r);
    }

    #[test]
    fn stats_handle_shares_raw_byte_counters() {
        let stats = SecretStreamStats {
            inner: Arc::new(StreamStats {
                raw_bytes_read: AtomicU64::new(0),
                raw_bytes_written: AtomicU64::new(0),
            }),
        };
        let retained = stats.clone();
        stats.inner.raw_bytes_read.fetch_add(42, Ordering::Relaxed);
        stats
            .inner
            .raw_bytes_written
            .fetch_add(7, Ordering::Relaxed);

        assert_eq!(retained.raw_bytes_read(), 42);
        assert_eq!(retained.raw_bytes_written(), 7);
    }

    #[test]
    fn frame_roundtrip() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let data = b"hello framing";
            let mut buf = Vec::new();
            write_frame(&mut buf, data, DEFAULT_MAX_FRAME_LEN)
                .await
                .unwrap();

            assert_eq!(buf.len(), 3 + data.len());
            assert_eq!(buf[0], data.len() as u8);
            assert_eq!(buf[1], 0);
            assert_eq!(buf[2], 0);

            let mut cursor = std::io::Cursor::new(buf);
            let result = read_frame(&mut cursor, DEFAULT_MAX_FRAME_LEN)
                .await
                .unwrap();
            assert_eq!(result.as_deref(), Some(data.as_slice()));
        });
    }

    #[test]
    fn frame_read_respects_configured_limit() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut cursor = std::io::Cursor::new(vec![65, 0, 0]);
            assert!(matches!(
                read_frame(&mut cursor, 64).await,
                Err(SecretStreamError::MessageTooLarge { len: 65, max: 64 })
            ));
        });
    }

    #[test]
    fn frame_eof_returns_none() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
            let result = read_frame(&mut cursor, DEFAULT_MAX_FRAME_LEN)
                .await
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[tokio::test]
    async fn handshake_and_exchange() {
        // Full in-process test using duplex streams (tokio::io::duplex).
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let kp_a = noise::generate_keypair();
        let kp_b = noise::generate_keypair();

        let (client_result, server_result) = tokio::join!(
            SecretStream::new(true, client_stream, kp_a),
            SecretStream::new(false, server_stream, kp_b),
        );

        let mut client = client_result.expect("client handshake failed");
        let mut server = server_result.expect("server handshake failed");

        // Send from client → server
        client.write(b"hello from client").await.unwrap();
        let msg = server.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"hello from client");

        // Send from server → client
        server.write(b"hello from server").await.unwrap();
        let msg = client.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"hello from server");

        // Multiple messages
        for i in 0..10 {
            let payload = format!("message {i}");
            client.write(payload.as_bytes()).await.unwrap();
            let msg = server.read().await.unwrap().expect("expected message");
            assert_eq!(msg, payload.as_bytes());
        }
    }

    #[tokio::test]
    async fn empty_message_roundtrip() {
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let (mut client, mut server) = tokio::try_join!(
            SecretStream::new(true, client_stream, noise::generate_keypair()),
            SecretStream::new(false, server_stream, noise::generate_keypair()),
        )
        .unwrap();

        // Empty messages are consumed as keepalives by read().
        // Send a real message after an empty one.
        client.write(b"").await.unwrap();
        client.write(b"after empty").await.unwrap();
        let msg = server.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"after empty");
    }

    #[tokio::test]
    async fn remote_public_key_matches() {
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let kp_a = noise::generate_keypair();
        let kp_b = noise::generate_keypair();
        let pk_a = kp_a.public_key;
        let pk_b = kp_b.public_key;

        let (client, server) = tokio::try_join!(
            SecretStream::new(true, client_stream, kp_a),
            SecretStream::new(false, server_stream, kp_b),
        )
        .unwrap();

        assert_eq!(*client.remote_public_key(), pk_b);
        assert_eq!(*server.remote_public_key(), pk_a);
        assert_eq!(client.handshake_hash(), server.handshake_hash());
    }

    #[tokio::test]
    async fn from_session_roundtrip() {
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let tx_key = [0x11u8; 32];
        let rx_key = [0x22u8; 32];
        let hash = [0xABu8; 64];
        let remote_pk = [0xCCu8; 32];

        let (client_result, server_result) = tokio::join!(
            SecretStream::from_session(true, client_stream, tx_key, rx_key, hash, remote_pk),
            SecretStream::from_session(false, server_stream, rx_key, tx_key, hash, remote_pk),
        );

        let mut client = client_result.expect("client from_session failed");
        let mut server = server_result.expect("server from_session failed");

        client.write(b"pre-keyed hello").await.unwrap();
        let msg = server.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"pre-keyed hello");

        server.write(b"pre-keyed reply").await.unwrap();
        let msg = client.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"pre-keyed reply");

        assert!(client.is_initiator());
        assert!(!server.is_initiator());
    }

    #[tokio::test]
    async fn into_split_roundtrip() {
        // Split both peers into read/write halves and exchange in both
        // directions concurrently. Proves the split preserves wire framing and
        // AEAD cipher behavior identically to the unsplit read()/write().
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let (client, server) = tokio::try_join!(
            SecretStream::new(true, client_stream, noise::generate_keypair()),
            SecretStream::new(false, server_stream, noise::generate_keypair()),
        )
        .unwrap();

        let (mut client_rd, mut client_wr) = client.into_split();
        let (mut server_rd, mut server_wr) = server.into_split();

        // client → server
        client_wr.write(b"hello from client").await.unwrap();
        let msg = server_rd.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"hello from client");

        // server → client
        server_wr.write(b"hello from server").await.unwrap();
        let msg = client_rd.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"hello from server");

        // Concurrent bidirectional bulk: writer and reader in separate tasks,
        // read_exact is never cancelled — the exact property the split provides.
        let writer = tokio::spawn(async move {
            for i in 0..100 {
                let payload = format!("bulk {i}");
                client_wr.write(payload.as_bytes()).await.unwrap();
            }
            client_wr.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut count = 0;
            while let Some(msg) = server_rd.read().await.unwrap() {
                assert_eq!(msg, format!("bulk {count}").as_bytes());
                count += 1;
            }
            count
        });
        writer.await.unwrap();
        assert_eq!(reader.await.unwrap(), 100);
    }

    #[tokio::test]
    async fn into_split_empty_keepalive() {
        // Empty messages are consumed as keepalives by the split read half,
        // matching SecretStream::read.
        let (client_stream, server_stream) = tokio::io::duplex(8192);

        let (client, server) = tokio::try_join!(
            SecretStream::new(true, client_stream, noise::generate_keypair()),
            SecretStream::new(false, server_stream, noise::generate_keypair()),
        )
        .unwrap();

        let (_client_rd, mut client_wr) = client.into_split();
        let (mut server_rd, _server_wr) = server.into_split();

        client_wr.write(b"").await.unwrap();
        client_wr.write(b"after empty").await.unwrap();
        let msg = server_rd.read().await.unwrap().expect("expected message");
        assert_eq!(msg, b"after empty");
    }

    async fn duplex_pair() -> (
        SecretStream<tokio::io::DuplexStream>,
        SecretStream<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, server) = tokio::join!(
            SecretStream::new(true, a, noise::generate_keypair()),
            SecretStream::new(false, b, noise::generate_keypair()),
        );
        (client.unwrap(), server.unwrap())
    }

    fn written<T>(stream: &SecretStream<T>) -> u64 {
        stream.stats.raw_bytes_written.load(Ordering::Relaxed)
    }

    /// 3-byte length + 1-byte tag + 16-byte MAC around an empty payload.
    const KEEP_ALIVE_FRAME: u64 = (3 + ABYTES) as u64;

    #[tokio::test]
    async fn keep_alive_between_messages_is_not_delivered() {
        let (mut client, mut server) = duplex_pair().await;
        let handle = client.keep_alive_handle();

        client.write(b"one").await.unwrap();
        let before = written(&client);
        // The pending read drives the requested keep-alive.
        tokio::select! {
            biased;
            sent = handle.send_keep_alive() => sent.unwrap(),
            _ = client.read() => panic!("nothing to read"),
        }
        assert_eq!(written(&client), before + KEEP_ALIVE_FRAME);
        client.write(b"two").await.unwrap();

        assert_eq!(server.read().await.unwrap().unwrap(), b"one");
        assert_eq!(server.read().await.unwrap().unwrap(), b"two");
        let frame = |len: usize| (3 + len + ABYTES) as u64;
        assert_eq!(
            server.stats.raw_bytes_read.load(Ordering::Relaxed),
            frame(3) + KEEP_ALIVE_FRAME + frame(3),
        );

        // A write alone also flushes a requested keep-alive first.
        let request = tokio::spawn({
            let handle = handle.clone();
            async move { handle.send_keep_alive().await }
        });
        while !client.keep_alive.pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        client.write(b"three").await.unwrap();
        request.await.unwrap().unwrap();
        assert_eq!(server.read().await.unwrap().unwrap(), b"three");
    }

    #[tokio::test]
    async fn keep_alive_handle_follows_split_and_releases_transport() {
        let (client, mut server) = duplex_pair().await;
        let handle = client.keep_alive_handle();
        let (read, mut write) = client.into_split();

        write.write(b"one").await.unwrap();
        handle.send_keep_alive().await.unwrap();
        write.keep_alive_handle().send_keep_alive().await.unwrap();
        write.write(b"two").await.unwrap();
        assert_eq!(server.read().await.unwrap().unwrap(), b"one");
        assert_eq!(server.read().await.unwrap().unwrap(), b"two");
        assert!(!handle.is_closed());

        drop(write);
        drop(read);
        assert!(handle.is_closed());
        assert!(matches!(
            handle.send_keep_alive().await,
            Err(SecretStreamError::Closed)
        ));
        // The handle does not hold the transport: the peer sees EOF.
        assert!(server.read().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn keep_alive_request_fails_when_stream_dropped() {
        let (client, mut server) = duplex_pair().await;
        let handle = client.keep_alive_handle();
        let request = tokio::spawn(async move { handle.send_keep_alive().await });
        while !client.keep_alive.pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        drop(client);
        assert!(matches!(
            request.await.unwrap(),
            Err(SecretStreamError::Closed)
        ));
        assert!(server.read().await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn keep_alive_timer_fires_when_idle_and_writes_refresh_it() {
        use tokio::time::{Instant, sleep_until, timeout_at};
        let (mut client, mut server) = duplex_pair().await;
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        client.set_keep_alive(Some(Duration::from_secs(5)));
        let base = written(&client);

        // The owner keeps a read pending, as Protomux does.
        let _ = timeout_at(at(4_900), client.read()).await;
        assert_eq!(written(&client), base, "nothing before 5 s");
        let _ = timeout_at(at(5_100), client.read()).await;
        assert_eq!(written(&client), base + KEEP_ALIVE_FRAME);
        let _ = timeout_at(at(9_900), client.read()).await;
        assert_eq!(written(&client), base + KEEP_ALIVE_FRAME);
        let _ = timeout_at(at(10_100), client.read()).await;
        assert_eq!(written(&client), base + 2 * KEEP_ALIVE_FRAME);

        // A write at 12 s pushes the next keep-alive past 15 s.
        let _ = timeout_at(at(12_000), client.read()).await;
        client.write(b"data").await.unwrap();
        let after_write = written(&client);
        let _ = timeout_at(at(16_900), client.read()).await;
        assert_eq!(
            written(&client),
            after_write,
            "the write refreshed the timer"
        );
        let _ = timeout_at(at(18_300), client.read()).await;
        assert_eq!(written(&client), after_write + KEEP_ALIVE_FRAME);

        assert_eq!(server.read().await.unwrap().unwrap(), b"data");

        // Turning it off stops the timer.
        client.set_keep_alive(None);
        let off = written(&client);
        let _ = timeout_at(at(40_000), client.read()).await;
        assert_eq!(written(&client), off);

        // Dropping the stream ends the timer task.
        client.set_keep_alive(Some(Duration::from_secs(5)));
        drop(client);
        sleep_until(at(60_000)).await;
        assert!(server.read().await.unwrap().is_none());
    }

    /// Write side that accepts at most `budget` more bytes, then returns
    /// `Pending` until released.
    #[derive(Default)]
    struct Gate {
        budget: Option<usize>,
        waker: Option<Waker>,
    }

    struct GatedStream {
        inner: tokio::io::DuplexStream,
        gate: Arc<Mutex<Gate>>,
    }

    fn limit(gate: &Mutex<Gate>, budget: Option<usize>) {
        let mut gate = gate.lock().unwrap();
        gate.budget = budget;
        if let Some(waker) = gate.waker.take() {
            waker.wake();
        }
    }

    impl AsyncRead for GatedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let len = {
                let mut gate = self.gate.lock().unwrap();
                match gate.budget {
                    Some(0) => {
                        gate.waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    Some(budget) => budget.min(buf.len()),
                    None => buf.len(),
                }
            };
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &buf[..len]))?;
            if let Some(budget) = self.gate.lock().unwrap().budget.as_mut() {
                *budget -= n;
            }
            Poll::Ready(Ok(n))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    type KeepAliveRequest = tokio::task::JoinHandle<Result<(), SecretStreamError>>;

    /// A client whose read wrote 5 bytes of a requested keep-alive, hit
    /// `Pending` on the transport and still returned the peer's message.
    async fn half_written_keep_alive() -> (
        SecretStream<GatedStream>,
        SecretStream<tokio::io::DuplexStream>,
        Arc<Mutex<Gate>>,
        KeepAliveRequest,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let gate = Arc::new(Mutex::new(Gate::default()));
        let gated = GatedStream {
            inner: a,
            gate: Arc::clone(&gate),
        };
        let (client, server) = tokio::join!(
            SecretStream::new(true, gated, noise::generate_keypair()),
            SecretStream::new(false, b, noise::generate_keypair()),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        server.write(b"hello").await.unwrap();
        let handle = client.keep_alive_handle();
        let request = tokio::spawn(async move { handle.send_keep_alive().await });
        while !client.keep_alive.pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        limit(&gate, Some(5));
        let before = written(&client);
        assert_eq!(client.read().await.unwrap().unwrap(), b"hello");
        assert_eq!(client.keep_alive_out.as_ref().map(|out| out.pos), Some(5));
        assert_eq!(written(&client), before, "a partial frame is not counted");
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !request.is_finished(),
            "waiter resolved before the frame was written"
        );
        (client, server, gate, request)
    }

    /// Await `future`, failing the test instead of hanging.
    async fn bounded<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("timed out")
    }

    #[tokio::test]
    async fn half_written_keep_alive_is_finished_by_the_next_write() {
        let (mut client, mut server, gate, request) = half_written_keep_alive().await;
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            limit(&gate, None);
        });
        // Blocks until released, then finishes the keep-alive before `data`.
        bounded(client.write(b"data")).await.unwrap();
        release.await.unwrap();
        bounded(request).await.unwrap().unwrap();
        assert!(client.keep_alive_out.is_none());

        assert_eq!(bounded(server.read()).await.unwrap().unwrap(), b"data");
        let frame = |len: usize| (3 + len + ABYTES) as u64;
        assert_eq!(
            server.stats.raw_bytes_read.load(Ordering::Relaxed),
            KEEP_ALIVE_FRAME + frame(4),
        );
    }

    #[tokio::test]
    async fn half_written_keep_alive_waiter_fails_when_stream_dropped() {
        let (client, _server, _gate, request) = half_written_keep_alive().await;
        drop(client);
        assert!(matches!(
            bounded(request).await.unwrap(),
            Err(SecretStreamError::Closed)
        ));
    }

    #[tokio::test]
    async fn shutdown_finishes_half_written_keep_alive_before_fin() {
        let (mut client, mut server, gate, request) = half_written_keep_alive().await;
        limit(&gate, None);
        bounded(client.shutdown()).await.unwrap();
        bounded(request).await.unwrap().unwrap();
        // A cut frame would end in `UnexpectedEof`, not a clean EOF.
        assert!(bounded(server.read()).await.unwrap().is_none());
        assert_eq!(
            server.stats.raw_bytes_read.load(Ordering::Relaxed),
            KEEP_ALIVE_FRAME
        );
    }
}
