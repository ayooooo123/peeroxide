use std::fmt;
use std::time::Duration;

use rand::Rng;
use tokio::sync::mpsc;

use peeroxide_dht::hyperdht::{HyperDhtHandle, KeyPair};
use peeroxide_dht::messages::Ipv4Peer;

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(4).fold(String::new(), |mut s, b| {
        fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).ok();
        s
    })
}

/// 10-minute refresh interval, matching Node.js `REFRESH_INTERVAL`.
const REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// Up to 2-minute random jitter added to refresh interval.
const REFRESH_JITTER_MS: u64 = 120_000;

/// Poll interval while waiting for `HyperDhtHandle::current_relay_addresses()`
/// to populate after an eager server topic announced with `relays: []`.
const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Initial retry backoff when a server topic announce fails (e.g., while the
/// routing table is still warming up on startup).
const ANNOUNCE_RETRY_INITIAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerAnnounceState {
    Complete,
    MissingRelays,
    Failed,
}

pub(crate) enum DiscoveryEvent {
    PeerFound {
        public_key: [u8; 32],
        relay_addresses: Vec<Ipv4Peer>,
        topic: [u8; 32],
    },
    RefreshComplete {
        topic: [u8; 32],
        seq: u64,
    },
}

pub(crate) struct PeerDiscoveryConfig {
    pub topic: [u8; 32],
    pub is_server: bool,
    pub is_client: bool,
}

fn drain_latest_refresh(rx: &mut mpsc::UnboundedReceiver<u64>, initial: u64) -> u64 {
    let mut latest = initial;
    while let Ok(seq) = rx.try_recv() {
        if seq > latest {
            latest = seq;
        }
    }
    latest
}

pub(crate) async fn run_discovery(
    config: PeerDiscoveryConfig,
    dht: HyperDhtHandle,
    key_pair: KeyPair,
    relay_addresses: Vec<Ipv4Peer>,
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
    mut refresh_rx: mpsc::UnboundedReceiver<u64>,
) {
    let mut state = do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, 0).await;
    let mut retry_delay = ANNOUNCE_RETRY_INITIAL;

    loop {
        match state {
            ServerAnnounceState::Failed => {
                let delay = retry_delay.min(REFRESH_INTERVAL);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        state = do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, 0).await;
                        if state == ServerAnnounceState::Failed {
                            retry_delay = retry_delay.saturating_mul(2).min(REFRESH_INTERVAL);
                        } else {
                            retry_delay = ANNOUNCE_RETRY_INITIAL;
                        }
                    }
                    Some(req_seq) = refresh_rx.recv() => {
                        let seq = drain_latest_refresh(&mut refresh_rx, req_seq);
                        retry_delay = ANNOUNCE_RETRY_INITIAL;
                        state = do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, seq).await;
                    }
                    _ = &mut cancel_rx => break,
                }
            }
            ServerAnnounceState::MissingRelays => {
                // Re-announce the server topic as soon as the swarm's
                // background `hash(pk)` announce populates `current_relays`,
                // instead of leaving `relays: []` on the DHT for 10 minutes.
                let jitter_ms = rand::rng().random_range(0..REFRESH_JITTER_MS);
                let refresh_deadline =
                    tokio::time::Instant::now() + REFRESH_INTERVAL + Duration::from_millis(jitter_ms);
                let mut poll = tokio::time::interval(RELAY_POLL_INTERVAL);
                poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut cancelled = false;
                let mut relays_ready = false;
                let mut manual_seq: Option<u64> = None;

                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(refresh_deadline) => break,
                        _ = poll.tick() => {
                            if !dht.current_relay_addresses().is_empty() {
                                relays_ready = true;
                                break;
                            }
                        }
                        Some(req_seq) = refresh_rx.recv() => {
                            manual_seq = Some(drain_latest_refresh(&mut refresh_rx, req_seq));
                            break;
                        }
                        _ = &mut cancel_rx => {
                            cancelled = true;
                            break;
                        }
                    }
                }
                if cancelled {
                    break;
                }
                retry_delay = ANNOUNCE_RETRY_INITIAL;
                state = if let Some(seq) = manual_seq {
                    do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, seq).await
                } else if relays_ready {
                    announce_server_topic(&config, &dht, &key_pair, &relay_addresses).await
                } else {
                    do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, 0).await
                };
            }
            ServerAnnounceState::Complete => {
                retry_delay = ANNOUNCE_RETRY_INITIAL;
                let jitter_ms = rand::rng().random_range(0..REFRESH_JITTER_MS);
                let delay = REFRESH_INTERVAL + Duration::from_millis(jitter_ms);

                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        state = do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, 0).await;
                    }
                    Some(req_seq) = refresh_rx.recv() => {
                        let seq = drain_latest_refresh(&mut refresh_rx, req_seq);
                        state = do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx, seq).await;
                    }
                    _ = &mut cancel_rx => break,
                }
            }
        }
    }
}

async fn announce_server_topic(
    config: &PeerDiscoveryConfig,
    dht: &HyperDhtHandle,
    key_pair: &KeyPair,
    relay_addresses: &[Ipv4Peer],
) -> ServerAnnounceState {
    if !config.is_server {
        return ServerAnnounceState::Complete;
    }
    let topic_relays: Vec<Ipv4Peer> = if relay_addresses.is_empty() {
        dht.current_relay_addresses()
    } else {
        relay_addresses.to_vec()
    };
    match dht.announce(config.topic, key_pair, &topic_relays).await {
        Ok(result) => {
            tracing::debug!(
                closest = result.closest_nodes.len(),
                advertised_relays = topic_relays.len(),
                "announce complete"
            );
            if relay_addresses.is_empty() && topic_relays.is_empty() {
                ServerAnnounceState::MissingRelays
            } else {
                ServerAnnounceState::Complete
            }
        }
        Err(e) => {
            tracing::warn!(err = %e, "announce failed");
            ServerAnnounceState::Failed
        }
    }
}

async fn do_refresh(
    config: &PeerDiscoveryConfig,
    dht: &HyperDhtHandle,
    key_pair: &KeyPair,
    relay_addresses: &[Ipv4Peer],
    event_tx: &mpsc::UnboundedSender<DiscoveryEvent>,
    seq: u64,
) -> ServerAnnounceState {
    let server_state = announce_server_topic(config, dht, key_pair, relay_addresses).await;

    if config.is_client {
        match dht.lookup(config.topic).await {
            Ok(results) => {
                for result in results {
                    tracing::debug!(
                        from = %format!("{}:{}", result.from.host, result.from.port),
                        peer_count = result.peers.len(),
                        "lookup result"
                    );
                    for peer in result.peers {
                        tracing::debug!(
                            pk = %hex_short(&peer.public_key),
                            relay_count = peer.relay_addresses.len(),
                            relays = ?peer.relay_addresses.iter().map(|a| format!("{}:{}", a.host, a.port)).collect::<Vec<_>>(),
                            "discovered peer"
                        );
                        // Forward the peer's own advertised relays only. Do NOT
                        // fall back to `result.from` (the lookup-responder),
                        // because that node holds a ForwardEntry keyed on the
                        // topic, not on hash(peer.public_key). PEER_HANDSHAKE
                        // targets the latter, so using a topic-relay as a
                        // PEER_HANDSHAKE forwarder is guaranteed to fail with
                        // CLOSER_NODES → empty-reply. An empty relay list lets
                        // connect_with_nodes drop straight into its Phase 2
                        // FIND_NODE walk on hash(peer.public_key), which finds
                        // the nodes the sender actually self-announced to.
                        let _ = event_tx.send(DiscoveryEvent::PeerFound {
                            public_key: peer.public_key,
                            relay_addresses: peer.relay_addresses,
                            topic: config.topic,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!(err = %e, "lookup failed");
            }
        }
    }

    let _ = event_tx.send(DiscoveryEvent::RefreshComplete {
        topic: config.topic,
        seq,
    });
    server_state
}
