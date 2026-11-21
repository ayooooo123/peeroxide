//! A swarm that rejects a duplicate connection probes the one it keeps.
//!
//! hyperswarm keeps the existing connection when the new one loses the
//! tie-break and calls `existing.sendKeepAlive()` (`hyperswarm/index.js`
//! `_handleServerConnection`), so a dead kept connection is found by the
//! transport's retransmit timeout soon instead of lingering.
//!
//! - `rejected_duplicate_sends_keep_alive_on_kept_connection`: a client dials
//!   a swarm server twice with the same key. The server keeps the first
//!   connection (its key is the larger one and the first has carried no
//!   data), rejects the second and writes exactly one empty message on the
//!   first. Periodic keep-alive is off on both sides, so the only bytes the
//!   kept connection writes are that probe.

use std::net::SocketAddr;
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide::{JoinOpts, SwarmConfig, spawn as spawn_swarm};
use peeroxide_dht::hyperdht::{HyperDhtConfig, KeyPair, spawn};

/// 3-byte length + 1-byte tag + 16-byte MAC around an empty payload.
const KEEP_ALIVE_FRAME: u64 = 20;

fn local_dht(bootstrap: Vec<String>) -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.bootstrap = bootstrap;
    config.dht.port = 0;
    config.dht.host = "127.0.0.1".to_string();
    config.dht.firewalled = false;
    config.dht.ephemeral = Some(false);
    config.connection_keep_alive = None;
    config
}

#[tokio::test]
async fn rejected_duplicate_sends_keep_alive_on_kept_connection() {
    tokio::time::timeout(Duration::from_secs(30), run())
        .await
        .expect("test timed out")
        .expect("test failed");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let rt = UdxRuntime::new()?;
    let (_bs_join, bs, _bs_rx) = spawn(&rt, local_dht(vec![])).await?;
    let bootstrap = vec![format!("127.0.0.1:{}", bs.local_port().await?)];

    let mut config = SwarmConfig::default();
    config.dht = local_dht(bootstrap.clone());
    let (_task, server, mut server_conns) = spawn_swarm(config).await?;
    server
        .join([0x6b; 32], {
            let mut opts = JoinOpts::default();
            opts.client = false;
            opts
        })
        .await?;
    let server_pk = server.key_pair().public_key;
    let server_addr: SocketAddr =
        format!("127.0.0.1:{}", server.dht().local_port().await?).parse()?;

    let (_cli_join, client, _cli_rx) = spawn(&rt, local_dht(bootstrap)).await?;
    // The server keeps its own connection when its key is the larger one.
    let client_kp = loop {
        let kp = KeyPair::generate();
        if kp.public_key < server_pk {
            break kp;
        }
    };

    let mut first = client
        .connect_to(&client_kp, server_pk, server_addr, &rt)
        .await?;
    let kept = tokio::time::timeout(Duration::from_secs(10), server_conns.recv())
        .await?
        .ok_or("swarm handed out no connection")?;
    let kept_stats = kept.peer.stream.stats_handle();
    assert_eq!(kept_stats.raw_bytes_written(), 0);
    // The application keeps a read pending on the kept connection, as a
    // Protomux owner does; it must not see the keep-alive.
    let reader = tokio::spawn(async move {
        let mut kept = kept;
        kept.peer.stream.read().await
    });

    let second = client
        .connect_to(&client_kp, server_pk, server_addr, &rt)
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while kept_stats.raw_bytes_written() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no keep-alive on the kept connection"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(kept_stats.raw_bytes_written(), KEEP_ALIVE_FRAME);

    // The client gets the empty message on the first connection and drops
    // it; data still flows after it.
    let probe = tokio::time::timeout(Duration::from_millis(500), first.stream.read()).await;
    assert!(
        probe.is_err(),
        "the keep-alive must not be delivered: {probe:?}"
    );
    assert_eq!(
        first.stream.stats_handle().raw_bytes_read(),
        KEEP_ALIVE_FRAME
    );
    first.stream.write(b"still here").await?;
    assert_eq!(
        reader.await?.map_err(|e| e.to_string())?,
        Some(b"still here".to_vec())
    );

    // The rejected duplicate is closed by the server.
    if let Ok(mut second) = second {
        let end = tokio::time::timeout(Duration::from_secs(10), second.stream.read()).await?;
        assert!(
            !matches!(end, Ok(Some(_))),
            "rejected duplicate delivered data"
        );
    }

    server.destroy().await?;
    client.destroy().await?;
    bs.destroy().await?;
    Ok(())
}
