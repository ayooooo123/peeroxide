//! Ignored loopback benchmark; configure UDX_WORKERS, UDX_CONNECTIONS and UDX_MIB.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use libudx::UdxRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Allocator;
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |value| value.parse().expect("numeric setting"))
}

#[test]
#[ignore = "bulk performance benchmark"]
fn bulk_transfer() {
    let workers = setting("UDX_WORKERS", 4);
    let connections = setting("UDX_CONNECTIONS", 4);
    let mib = setting("UDX_MIB", 256);
    let separate_peers = setting("UDX_SEPARATE_PEERS", 0) != 0;
    assert!(connections > 0 && mib >= connections);
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(180), async {
            let runtime = UdxRuntime::new().unwrap();
            let sender = runtime.create_socket().await.unwrap();
            let receiver = runtime.create_socket().await.unwrap();
            sender.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            receiver.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let send_addr = sender.local_addr().await.unwrap();
            let recv_addr = receiver.local_addr().await.unwrap();
            let bytes = mib * 1024 * 1024 / connections;
            let mut pairs = Vec::new();
            let mut peer_sockets = Vec::new();
            for index in 0..connections {
                let peer_socket = if separate_peers && index > 0 {
                    let socket = runtime.create_socket().await.unwrap();
                    socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
                    socket
                } else {
                    receiver.clone()
                };
                let peer_addr = if separate_peers {
                    peer_socket.local_addr().await.unwrap()
                } else {
                    recv_addr
                };
                let a_id = (index * 2 + 1) as u32;
                let b_id = a_id + 1;
                let a = runtime.create_stream(a_id).await.unwrap();
                let b = runtime.create_stream(b_id).await.unwrap();
                a.connect(&sender, b_id, peer_addr).await.unwrap();
                b.connect(&peer_socket, a_id, send_addr).await.unwrap();
                pairs.push((a.into_async_stream(), b.into_async_stream(), index as u8));
                peer_sockets.push(peer_socket);
            }
            ALLOCATIONS.store(0, Ordering::Relaxed);
            COUNTING.store(true, Ordering::Relaxed);
            let start = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for (mut a, mut b, value) in pairs {
                tasks.spawn(async move {
                    let buf = vec![value; 64 * 1024];
                    let mut sent = 0;
                    while sent < bytes {
                        let len = buf.len().min(bytes - sent);
                        a.write_all(&buf[..len]).await.unwrap();
                        sent += len;
                    }
                    a.flush().await.unwrap();
                    a
                });
                tasks.spawn(async move {
                    let mut buf = vec![0; 64 * 1024];
                    let mut received = 0;
                    while received < bytes {
                        let len = b.read(&mut buf).await.unwrap();
                        assert!(len > 0);
                        assert!(buf[..len].iter().all(|byte| *byte == value));
                        received += len;
                    }
                    assert_eq!(received, bytes);
                    b
                });
            }
            // Keep both halves alive until the final ACK has reached every writer.
            let mut streams = Vec::new();
            while let Some(result) = tasks.join_next().await {
                streams.push(result.unwrap());
            }
            let elapsed = start.elapsed().as_secs_f64();
            COUNTING.store(false, Ordering::Relaxed);
            println!("BULK workers={workers} connections={connections} bytes={} seconds={elapsed:.6} MiB_s={:.3} allocations={} separate_peers={separate_peers}", bytes * connections, bytes as f64 * connections as f64 / 1048576.0 / elapsed, ALLOCATIONS.load(Ordering::Relaxed));
            drop(streams);
        }).await.expect("bulk transfer timeout");
    });
}
