//! Ignored CPU-only secretstream benchmark; each task owns its cipher states.
use peeroxide_dht::secretstream::{Pull, Push};
use std::time::Instant;

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |value| value.parse().expect("numeric setting"))
}

#[test]
#[ignore = "secretstream CPU and memory benchmark"]
fn concurrent_secretstream() {
    let workers = setting("UDX_WORKERS", 4);
    let connections = setting("UDX_CONNECTIONS", 8);
    let mib = setting("UDX_MIB", 256);
    assert!(connections > 0 && mib >= connections);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..connections {
            tasks.spawn(async move {
                let key = [index as u8; 32];
                let header = [7; 24];
                let mut push = Push::with_header(&key, &header);
                let mut pull = Pull::new(&key, &header);
                let payload = vec![42; 64 * 1024];
                for _ in 0..(mib * 16 / connections) {
                    let ciphertext = push.next(&payload);
                    let (plaintext, _) = pull.next(&ciphertext).unwrap();
                    assert_eq!(plaintext, payload);
                    tokio::task::yield_now().await;
                }
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
        let bytes = (mib * 16 / connections) * connections * 64 * 1024;
        let elapsed = start.elapsed().as_secs_f64();
        println!("CIPHER workers={workers} connections={connections} bytes={bytes} seconds={elapsed:.6} MiB_s={:.3}", bytes as f64 / 1048576.0 / elapsed);
    });
}
