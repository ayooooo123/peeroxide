# peeroxide-dht

[![crates.io](https://img.shields.io/crates/v/peeroxide-dht.svg)](https://crates.io/crates/peeroxide-dht)
[![docs.rs](https://docs.rs/peeroxide-dht/badge.svg)](https://docs.rs/peeroxide-dht)
[![CI](https://github.com/Rightbracket/peeroxide/actions/workflows/ci.yml/badge.svg)](https://github.com/Rightbracket/peeroxide/actions/workflows/ci.yml)

Rust port of HyperDHT — Kademlia DHT with hole-punching, Noise-encrypted connections, and relay.

This crate implements the full HyperDHT protocol stack. It is wire-compatible with the Node.js implementation on the public Hyperswarm network.

Most users should use the higher-level `peeroxide` crate. Use `peeroxide-dht` directly for low-level DHT operations or building custom peer-to-peer applications.

### Protocol Layers

| Layer | Modules | Reference |
|---|---|---|
| Wire encoding | compact_encoding | compact-encoding |
| DHT RPC | rpc, io, query, routing_table | dht-rpc |
| Peer operations | hyperdht, hyperdht_messages | hyperdht |
| Noise XX handshake | noise, noise_wrap | noise-handshake |
| Encrypted streams | secret_stream, secretstream | @hyperswarm/secret-stream |
| NAT traversal | nat, holepuncher | hyperdht/lib/holepuncher.js |
| Relay | blind_relay, protomux | blind-relay |

### Quick Start

```rust
use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair};

let runtime = UdxRuntime::new()?;
let config = HyperDhtConfig::with_public_bootstrap();
let (_task, dht, _server_rx) = hyperdht::spawn(&runtime, config).await?;
dht.bootstrapped().await?;

let key_pair = KeyPair::generate();
let topic = peeroxide_dht::crypto::hash(b"my-app");
dht.announce(topic, &key_pair, &[]).await?;
```

### Features

- Key operations: `announce`, `lookup`, `find_peer`, `connect`, and mutable/immutable `put`/`get`.
- Pure Rust cryptography: Uses `ed25519-dalek`, `chacha20poly1305`, and `blake2`. No `libsodium` dependency.
- Interoperability: Validated through golden byte fixtures and live cross-language tests.

### Concurrency and resource limits

Connections own independent Noise and secretstream state; keep each connection's
cipher operations ordered. Randomized NAT punches share one active slot per DHT
and wait 20 seconds after completion, matching hyperdht's default resource budget.
The 256-socket birthday strategy and hyperswarm retry tiers are unchanged.
Busy attempts abort without a relay; with a relay they back off 10–20 seconds,
within the existing punch deadline. Cancelled reservations do not start a cooldown.

### Local fork: cross-egress LAN fallback

Handshake replies retain the request's reflexive `to` address for HyperDHT's
same-NAT test, rather than substituting a different relay's global NAT sample.
Beyond JS parity, a relayed handshake whose public hosts differ can race one
authenticated, advertised RFC 1918 endpoint against normal holepunching. This
requires a private local interface and `local_connection`; it does not probe
loopback, link-local, CGN or public candidates. The closest private prefix wins.
A one-shot DHT ping has a two-second deadline; the resulting stream still uses
the negotiated Noise keys. Failure leaves the normal path running.
Each peer gets at most one probe per 60 seconds, with ten total per node per
60 seconds across all topics and direct dials. No address-range scanning or
peer exchange is introduced. This deliberate fork extension supports sites
whose VLANs use different WAN/VPN egress but can route private addresses.

The ignored `secretstream_bench` test reports verified encrypt/decrypt throughput
for `UDX_WORKERS`, `UDX_CONNECTIONS` and aggregate `UDX_MIB`. Compare 1 and 4 workers
in release and dev profiles; time the built executable for CPU and peak RSS.

### Project

Part of the [peeroxide](https://github.com/Rightbracket/peeroxide) project.

### License

MIT OR Apache-2.0
