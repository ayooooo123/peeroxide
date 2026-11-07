#![deny(clippy::all)]

mod common;

use common::{create_bound_socket, create_runtime, with_timeout};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[tokio::test]
async fn firewall_hook_accepts_first_packet() {
    let _ = tracing_subscriber::fmt::try_init();

    with_timeout(Duration::from_secs(10), async {
        let rt = create_runtime();

        let (socket_a, addr_a) = create_bound_socket(&rt).await;
        let (socket_b, addr_b) = create_bound_socket(&rt).await;

        let id_a = 10u32;
        let id_b = 20u32;

        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let mut stream_a = rt.create_stream(id_a).await.expect("create stream_a");
        stream_a
            .set_firewall_hook(&socket_a, id_b, move |_, port, host| {
                assert_eq!((host, port), (addr_b.ip(), addr_b.port()));
                hook_calls.fetch_add(1, Ordering::SeqCst);
                true
            })
            .expect("set_firewall_hook");

        let stream_b = rt.create_stream(id_b).await.expect("create stream_b");
        stream_b
            .connect(&socket_b, id_a, addr_a)
            .await
            .expect("stream_b connect");

        let msg = b"hello from firewall hook test";
        stream_b.write(msg).await.expect("stream_b write");

        let data = stream_a
            .read()
            .await
            .expect("stream_a read")
            .expect("stream_a unexpected EOF");
        assert_eq!(&data[..], msg.as_ref());
        stream_b
            .write(b"second packet")
            .await
            .expect("second write");
        assert_eq!(
            stream_a.read().await.expect("second read").unwrap(),
            b"second packet"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[tokio::test]
async fn firewall_retries_after_rejection() {
    with_timeout(Duration::from_secs(10), async {
        let rt = create_runtime();
        let (receiver, addr) = create_bound_socket(&rt).await;
        let (sender, _) = create_bound_socket(&rt).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let mut target = rt.create_stream(11).await.expect("target");
        target
            .set_firewall_hook(&receiver, 22, move |_, _, _| {
                hook_calls.fetch_add(1, Ordering::SeqCst) != 0
            })
            .expect("firewall");
        let source = rt.create_stream(22).await.expect("source");
        source.connect(&sender, 11, addr).await.expect("connect");
        source.write(b"retry").await.expect("write");
        assert_eq!(target.read().await.expect("read").unwrap(), b"retry");
        assert!(calls.load(Ordering::SeqCst) >= 2);
    })
    .await;
}

/// A write staged before the hook has a peer must wait for it instead of
/// going out to the 0.0.0.0:0 sentinel (a relay's secret-stream header did).
#[tokio::test]
async fn write_before_hook_fires_is_delivered_after_it() {
    with_timeout(Duration::from_secs(10), async {
        let rt = create_runtime();
        let (socket_a, addr_a) = create_bound_socket(&rt).await;
        let (socket_b, _) = create_bound_socket(&rt).await;
        let stream_a = rt.create_stream(41).await.expect("stream a");
        stream_a
            .set_firewall_hook(&socket_a, 42, |_, _, _| true)
            .expect("firewall");
        let early = tokio::spawn(async move {
            stream_a
                .write(b"queued before the peer was known")
                .await
                .expect("early write");
            stream_a
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut stream_b = rt.create_stream(42).await.expect("stream b");
        stream_b
            .connect(&socket_b, 41, addr_a)
            .await
            .expect("connect b");
        stream_b.write(b"knock").await.expect("knock");
        assert_eq!(
            stream_b.read().await.expect("read").unwrap(),
            b"queued before the peer was known"
        );
        let mut stream_a = early.await.expect("early write task");
        assert_eq!(stream_a.read().await.expect("read").unwrap(), b"knock");
    })
    .await;
}

#[tokio::test]
async fn async_stream_reports_remote_destroy() {
    with_timeout(Duration::from_secs(10), async {
        let rt = create_runtime();
        let (socket_a, addr_a) = create_bound_socket(&rt).await;
        let (socket_b, addr_b) = create_bound_socket(&rt).await;
        let stream_a = rt.create_stream(31).await.expect("stream a");
        let stream_b = rt.create_stream(32).await.expect("stream b");
        stream_a
            .connect(&socket_a, 32, addr_b)
            .await
            .expect("connect a");
        stream_b
            .connect(&socket_b, 31, addr_a)
            .await
            .expect("connect b");
        let mut stream = stream_a.into_async_stream();
        let closed = stream.take_close_notification().expect("notification");
        stream_b.destroy().await.expect("destroy");
        closed.await.expect("close notification");
    })
    .await;
}
