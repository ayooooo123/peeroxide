use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::stream::{StreamEvent, StreamInner, build_data_packets, build_end_packet};

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
    read_buf: Vec<u8>,
    read_pos: usize,
    read_eof: bool,
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
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
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
        return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "UDX stream closed")));
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

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::End)) | Poll::Ready(None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdxAsyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let (prep, max_payload, len) = {
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
            let prep = inner
                .prepare_write(len)
                .map_err(|e| io::Error::other(e.to_string()))?;
            (prep, max_payload, len)
        };

        let packets = build_data_packets(&prep, &buf[..len], max_payload);
        self.lock().queue_write(packets, prep.remote_addr);
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
            let Ok(prep) = inner.prepare_end() else {
                return Poll::Ready(Ok(()));
            };
            inner.queue_write(vec![(prep.first_seq, build_end_packet(&prep))], prep.remote_addr);
            this.fin_queued = true;
        }
        poll_all_acked(&mut inner, cx)
    }
}

impl Unpin for UdxAsyncStream {}

impl Drop for UdxAsyncStream {
    /// The processor sends what is still queued, then exits without waiting
    /// for ACKs: up to a send buffer of unacked data is lost if the network
    /// drops it. Call `shutdown()` first when delivery matters.
    fn drop(&mut self) {
        let _ = self.processor.take();
        let guard = self.lock();
        if let Some(tx) = &guard.notify_tx {
            let _ = tx.send(super::stream::StreamNotify::Shutdown);
        }
    }
}
