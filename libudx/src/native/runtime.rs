use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use crate::error::{Result, UdxError};

/// Shared handle to a UDX runtime, held by sockets and streams.
///
/// External code only holds `Arc<RuntimeHandle>` — all methods are `pub(crate)`.
pub struct RuntimeHandle {
    pub(crate) live_streams: Mutex<HashMap<u32, watch::Receiver<bool>>>,
}

impl RuntimeHandle {
    pub(crate) fn new() -> Self {
        Self {
            live_streams: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn unregister_stream(&self, local_id: u32) {
        let mut streams = self.live_streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams
            .get(&local_id)
            .is_some_and(|closed| *closed.borrow() || closed.has_changed().is_err())
        {
            streams.remove(&local_id);
        }
    }

    pub(crate) fn create_stream_internal(
        self: &Arc<Self>,
        local_id: u32,
    ) -> Result<super::stream::UdxStream> {
        let mut streams = self.live_streams.lock().unwrap_or_else(|e| e.into_inner());
        if streams
            .get(&local_id)
            .is_some_and(|closed| !*closed.borrow() && closed.has_changed().is_ok())
        {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "stream ID already in use",
            )));
        }

        let stream =
            super::stream::UdxStream::new_with_runtime(local_id, Some(Arc::downgrade(self)));
        streams.insert(
            local_id,
            stream
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .close_observer(),
        );
        tracing::debug!(local_id, "stream created");
        Ok(stream)
    }

    pub(crate) fn create_random_stream_with<F>(
        self: &Arc<Self>,
        mut id_gen: F,
    ) -> Result<(u32, super::stream::UdxStream)>
    where
        F: FnMut() -> u32,
    {
        let mut streams = self.live_streams.lock().unwrap_or_else(|e| e.into_inner());
        let local_id = loop {
            let candidate = id_gen();
            if candidate == 0 {
                continue;
            }

            if streams
                .get(&candidate)
                .is_some_and(|closed| !*closed.borrow() && closed.has_changed().is_ok())
            {
                continue;
            }

            break candidate;
        };

        let stream =
            super::stream::UdxStream::new_with_runtime(local_id, Some(Arc::downgrade(self)));
        streams.insert(
            local_id,
            stream
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .close_observer(),
        );
        tracing::debug!(local_id, "random stream created");
        Ok((local_id, stream))
    }
}

/// Owns and drives the UDX protocol runtime.
///
/// Sockets and streams are created through this runtime. In the native
/// implementation the runtime is lightweight — it relies on the ambient
/// tokio executor for async I/O.
pub struct UdxRuntime {
    handle: Arc<RuntimeHandle>,
}

impl UdxRuntime {
    /// Create a new owning runtime.
    pub fn new() -> Result<Self> {
        Ok(Self {
            handle: Arc::new(RuntimeHandle::new()),
        })
    }

    /// Create a non-owning runtime that shares another runtime's handle.
    pub fn shared(handle: Arc<RuntimeHandle>) -> Self {
        Self { handle }
    }

    /// Return a shared handle to this runtime.
    pub fn handle(&self) -> Arc<RuntimeHandle> {
        Arc::clone(&self.handle)
    }

    /// Create a new unbound UDP socket.
    pub async fn create_socket(&self) -> Result<super::socket::UdxSocket> {
        Ok(super::socket::UdxSocket::new())
    }

    /// Create a new stream with the given local identifier.
    ///
    /// Fails with [`std::io::ErrorKind::AlreadyExists`] if `local_id` is occupied by a live stream.
    pub async fn create_stream(&self, local_id: u32) -> Result<super::stream::UdxStream> {
        self.handle.create_stream_internal(local_id)
    }

    /// Create a new stream with an atomically selected collision-free nonzero ID.
    pub async fn create_random_stream(&self) -> Result<(u32, super::stream::UdxStream)> {
        self.handle.create_random_stream_with(rand::random::<u32>)
    }

    #[cfg(test)]
    pub(crate) async fn create_random_stream_with<F>(
        &self,
        id_gen: F,
    ) -> Result<(u32, super::stream::UdxStream)>
    where
        F: FnMut() -> u32,
    {
        self.handle.create_random_stream_with(id_gen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn injected_stream_id_collision_retry() {
        let rt = UdxRuntime::new().expect("runtime");

        // Occupy ID 42
        let stream1 = rt.create_stream(42).await.expect("create stream 42");

        // Attempting to create another stream with ID 42 fails
        let err = rt.create_stream(42).await;
        assert!(err.is_err(), "occupied ID 42 must be rejected");

        // Explicit ID 0 remains supported; random allocation must skip it.
        let stream0 = rt.create_stream(0).await.expect("explicit stream 0");
        assert_eq!(stream0.local_id(), 0);
        assert!(
            rt.create_stream(0).await.is_err(),
            "occupied ID 0 must be rejected"
        );

        // Injected generator emits:
        // 1. 0 (invalid, skipped)
        // 2. 42 (collision with stream1, skipped)
        // 3. 42 (collision with stream1 again, skipped)
        // 4. 43 (free, succeeds)
        let sequence = std::sync::Mutex::new(vec![43, 42, 42, 0]);
        let (id, stream2) = rt
            .create_random_stream_with(|| sequence.lock().unwrap().pop().unwrap_or(999))
            .await
            .expect("should select 43 after skipping 0 and collisions on 42");

        assert_eq!(id, 43);
        assert_eq!(stream2.local_id(), 43);

        // ID 43 is now occupied
        let err43 = rt.create_stream(43).await;
        assert!(err43.is_err(), "ID 43 should now be occupied");

        // Shared runtime test: rt_shared shares the same handle
        let rt_shared = UdxRuntime::shared(rt.handle());
        let err_shared = rt_shared.create_stream(42).await;
        assert!(
            err_shared.is_err(),
            "shared runtime must see ID 42 occupied"
        );

        // Drop stream1: ID 42 becomes available
        drop(stream1);
        let stream1_recreated = rt_shared
            .create_stream(42)
            .await
            .expect("ID 42 re-available after drop");
        assert_eq!(stream1_recreated.local_id(), 42);
    }
}
