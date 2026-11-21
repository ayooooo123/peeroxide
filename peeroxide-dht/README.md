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

Handshake replies retain the request's reflexive `to` address for HyperDHT's
same-NAT test, rather than substituting a different relay's global NAT sample.

The ignored `secretstream_bench` test reports verified encrypt/decrypt throughput
for `UDX_WORKERS`, `UDX_CONNECTIONS` and aggregate `UDX_MIB`. Compare 1 and 4 workers
in release and dev profiles; time the built executable for CPU and peak RSS.

### Deviations from npm

- Relay control secret-streams cap a frame at 64 KiB (Node allows 16 MiB); the default for other streams is unchanged.
- A connection whose secret-stream header does not arrive within 15 seconds after the Noise handshake fails with `StreamEstablishment`; Node waits without a bound.
- Holepunch and Noise payloads size `error`, `firewall` and `round` as real varints. Node reserves one byte each and garbles values of 253 or more; valid values encode to identical bytes.
- `connect` opens each candidate's handshake reply with its own copy of the Noise initiator state, so a bogus reply only fails that candidate. Node shares one state across candidates, so one bad reply spoils the honest ones that follow.
- The client's holepunch (rounds, punch and landing) is bounded at 30 s; Node relies on the puncher's own timers.
- Local addresses go through `validate_local_addresses` on the client too (npm validates only on the server), and a holepunch payload also lists the puncher's validated local interfaces next to its NAT samples (npm sends only the samples).
- The connection keep-alive timer samples the stream's write counter four times per interval instead of being refreshed by every write, so after a write the next keep-alive goes out between 1× and 1.25× the interval (Node: exactly 1×); an idle stream still sends one every interval. On an unsplit `SecretStream` the keep-alive is written by the task polling `read` or `write` (Protomux keeps a read pending); Node writes it from the timer.

### Project

Part of the [peeroxide](https://github.com/Rightbracket/peeroxide) project.

### License

MIT OR Apache-2.0
