use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::stream::{StreamEvent, StreamInner};

/// Terminal stream event deferred until bytes already copied into the caller's
/// buffer have been returned.
enum TerminalEvent {
    End,
    Error(io::ErrorKind),
}

/// Adapter that implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`]
/// over a [`super::stream::UdxStream`].
///
/// Created via [`super::stream::UdxStream::into_async_stream`]. Higher layers
/// (e.g. SecretStream) wrap this for encrypted I/O.
///
/// Writes are pipelined: `poll_write` queues data and returns as soon as it
/// is staged, applying back-pressure once about
/// [`SEND_BUFFER_MAX`](super::stream::SEND_BUFFER_MAX) bytes are queued or in
/// flight (the bound is checked against payload, so it can be exceeded by
/// the packet headers and MTU-probe padding of one write). `poll_flush`
/// resolves when the peer has ACKed everything; `poll_shutdown` queues the
/// FIN behind the data and resolves when it is ACKed. Dropping the stream
/// without `shutdown` abandons data the peer has not ACKed yet.
pub struct UdxAsyncStream {
    inner: Arc<Mutex<StreamInner>>,
    read_rx: mpsc::UnboundedReceiver<StreamEvent>,
    read_buf: Bytes,
    read_eof: bool,
    pending_terminal: Option<TerminalEvent>,
    processor: Option<tokio::task::JoinHandle<()>>,
    fin_queued: bool,
    close_rx: Option<oneshot::Receiver<()>>,
}

impl UdxAsyncStream {
    pub(crate) fn new(
        inner: Arc<Mutex<StreamInner>>,
        read_rx: mpsc::UnboundedReceiver<StreamEvent>,
        processor: Option<tokio::task::JoinHandle<()>>,
        close_rx: Option<oneshot::Receiver<()>>,
    ) -> Self {
        Self {
            inner,
            read_rx,
            read_buf: Bytes::new(),
            read_eof: false,
            pending_terminal: None,
            processor,
            fin_queued: false,
            close_rx,
        }
    }

    /// A handle that can destroy this stream from another owner.
    pub fn abort_handle(&self) -> super::stream::UdxStreamAbort {
        super::stream::UdxStreamAbort::new(Arc::clone(&self.inner))
    }

    /// A handle that migrates this stream to another peer from any task.
    pub fn remote_handle(&self) -> super::stream::UdxStreamRemote {
        super::stream::UdxStreamRemote::new(Arc::clone(&self.inner))
    }

    /// Take the one-shot notification sent when the underlying stream closes.
    pub fn take_close_notification(&mut self) -> Option<oneshot::Receiver<()>> {
        self.close_rx.take()
    }

    /// Asynchronously wait for the underlying stream to close.
    pub async fn closed(&self) {
        self.abort_handle().closed().await
    }

    /// Keepalive interval; see [`super::stream::UdxStream::set_keepalive`].
    pub fn set_keepalive(&self, interval: Option<std::time::Duration>) {
        self.lock().set_keepalive(interval);
    }

    fn lock(&self) -> MutexGuard<'_, StreamInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Ready once everything queued has been ACKed; an error once the stream died
/// with data still outstanding.
fn poll_all_acked(inner: &mut StreamInner, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if inner.all_acked() {
        return Poll::Ready(Ok(()));
    }
    if !inner.is_alive() {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "UDX stream closed",
        )));
    }
    inner.set_flush_waker(cx.waker());
    Poll::Pending
}

impl AsyncRead for UdxAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }

        let mut copied = 0usize;
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            let chunk = self.read_buf.split_to(n);
            buf.put_slice(&chunk);
            copied += n;
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }

        if let Some(terminal) = self.pending_terminal.take() {
            if copied > 0 {
                self.pending_terminal = Some(terminal);
                return Poll::Ready(Ok(()));
            }
            self.read_eof = true;
            return match terminal {
                TerminalEvent::End => Poll::Ready(Ok(())),
                TerminalEvent::Error(kind) => {
                    Poll::Ready(Err(io::Error::new(kind, "UDX stream failed")))
                }
            };
        }

        // Wait for the first event only when nothing has been copied yet;
        // once we have bytes, drain any queued packets to fill the caller's
        // buffer in one read instead of returning one packet at a time.
        while buf.remaining() > 0 {
            let event = if copied == 0 {
                match self.read_rx.poll_recv(cx) {
                    Poll::Ready(ev) => ev,
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match self.read_rx.try_recv() {
                    Ok(ev) => Some(ev),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => None,
                }
            };
            match event {
                Some(StreamEvent::Data(mut data)) => {
                    let n = data.len().min(buf.remaining());
                    let head = data.split_to(n);
                    buf.put_slice(&head);
                    copied += n;
                    if !data.is_empty() {
                        self.read_buf = data;
                        break;
                    }
                }
                Some(StreamEvent::Error(kind)) => {
                    if copied > 0 {
                        self.pending_terminal = Some(TerminalEvent::Error(kind));
                        break;
                    }
                    self.read_eof = true;
                    return Poll::Ready(Err(io::Error::new(kind, "UDX stream failed")));
                }
                Some(StreamEvent::End) | None => {
                    if copied > 0 {
                        self.pending_terminal = Some(TerminalEvent::End);
                        break;
                    }
                    self.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for UdxAsyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.lock();
        let max_payload = inner.max_payload();
        // A partial write is only worth a whole packet: wait for room
        // for one, then send full packets, so freed room is not spent
        // on 20-byte tails (silly window).
        let room = inner.send_buffer_room();
        let len = if buf.len() <= room {
            buf.len()
        } else {
            room / max_payload * max_payload
        };
        if len == 0 && !buf.is_empty() {
            if !inner.is_alive() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "UDX stream closed",
                )));
            }
            inner.set_write_waker(cx.waker());
            return Poll::Pending;
        }
        inner
            .queue_write(&buf[..len], None)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_all_acked(&mut self.lock(), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.is_alive() {
            return Poll::Ready(Ok(()));
        }
        if !this.fin_queued {
            // Not connected (firewall hook never fired): nothing to end.
            if inner.queue_end(None).is_err() {
                return Poll::Ready(Ok(()));
            }
            this.fin_queued = true;
        }
        poll_all_acked(&mut inner, cx)
    }
}

impl Unpin for UdxAsyncStream {}

impl Drop for UdxAsyncStream {
    /// The processor sends what is still queued, then DESTROY (C
    /// `udx_stream_destroy`; not on relay legs) and exits without waiting
    /// for ACKs: up to a send buffer of unacked data is lost if the network
    /// drops it. Call `shutdown()` first when delivery matters.
    fn drop(&mut self) {
        let _ = self.processor.take();
        let mut guard = self.lock();
        if let Some(tx) = &guard.notify_tx {
            let _ = tx.send(super::stream::StreamNotify::Dropped);
        } else {
            guard.terminate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn make_async_pair() -> (mpsc::UnboundedSender<StreamEvent>, UdxAsyncStream) {
        let stream = super::super::stream::UdxStream::new_with_runtime(1, None);
        let tx = stream.inner.lock().unwrap().read_tx.clone();
        (tx, stream.into_async_stream())
    }

    /// Multiple queued DATA packets must coalesce into a single `read()` up to
    /// the caller's buffer capacity, and a trailing END must be deferred to the
    /// next `read()` instead of dropping or hiding bytes.
    #[tokio::test]
    async fn poll_read_coalesces_queued_packets_and_defers_eof() {
        let (tx, mut reader) = make_async_pair();
        tx.send(StreamEvent::Data(Bytes::from_static(b"hello ")))
            .unwrap();
        tx.send(StreamEvent::Data(Bytes::from_static(b"world!")))
            .unwrap();
        tx.send(StreamEvent::End).unwrap();

        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello world!");

        let eof = reader.read(&mut buf).await.unwrap();
        assert_eq!(eof, 0);
    }

    /// A DATA packet followed immediately by an Error event must deliver the
    /// in-order bytes first and report the error on the following read.
    #[tokio::test]
    async fn poll_read_delivers_bytes_before_deferred_error() {
        let (tx, mut reader) = make_async_pair();
        tx.send(StreamEvent::Data(Bytes::from_static(b"partial")))
            .unwrap();
        tx.send(StreamEvent::Error(io::ErrorKind::ConnectionReset))
            .unwrap();

        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"partial");

        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    /// When queued packets exceed the caller buffer, leftover bytes stay in
    /// `read_buf` in exact order for the next `read()`.
    #[tokio::test]
    async fn poll_read_preserves_overflow_across_small_reads() {
        let (tx, mut reader) = make_async_pair();
        tx.send(StreamEvent::Data(Bytes::from_static(b"abcdef")))
            .unwrap();
        tx.send(StreamEvent::Data(Bytes::from_static(b"ghijkl")))
            .unwrap();
        tx.send(StreamEvent::End).unwrap();

        let mut out = Vec::new();
        let mut buf = [0u8; 4];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, b"abcdefghijkl");
    }
}
