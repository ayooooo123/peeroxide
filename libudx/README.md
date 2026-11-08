# libudx

[![crates.io](https://img.shields.io/crates/v/libudx.svg)](https://crates.io/crates/libudx)
[![docs.rs](https://docs.rs/libudx/badge.svg)](https://docs.rs/libudx)
[![CI](https://github.com/Rightbracket/peeroxide/actions/workflows/ci.yml/badge.svg)](https://github.com/Rightbracket/peeroxide/actions/workflows/ci.yml)

Pure Rust implementation of the UDX reliable UDP transport protocol, wire-compatible with C libudx.

This crate provides ordered, reliable byte streams over UDP. It implements BBR congestion control, SACK-based loss recovery, and MTU path discovery. Built on tokio, it's designed for high-performance P2P networking and maintains wire compatibility with the [C libudx](https://github.com/holepunchto/libudx) implementation used by the Hyperswarm network.

## Quick Start

```rust
use libudx::{UdxRuntime, UdxSocket, UdxStream};

let runtime = UdxRuntime::new()?;
let socket = runtime.create_socket().await?;
socket.bind("0.0.0.0:0".parse().unwrap()).await?;

let stream = runtime.create_stream(1).await?;
stream.connect(&socket, 1, "127.0.0.1:9000".parse().unwrap()).await?;
stream.write(b"hello").await?;
```

## Key Types

- `UdxRuntime`: The central driver managing socket events and stream state.
- `UdxSocket`: A UDP socket wrapper for sending and receiving UDX packets.
- `UdxStream`: A handle to a reliable byte stream.
- `UdxAsyncStream`: An adapter implementing `AsyncRead` and `AsyncWrite` for tokio integration.

Cloned sockets share ownership. Dropping the last socket/stream handle closes the UDP
socket and aborts its receive loop; the receive task must not keep its own socket alive.
`close()`/`shutdown()` explicitly close the shared socket even while other handles remain.

`UdxStreamAbort::stats()` snapshots `(smoothed_rtt_ms, retransmitted_packets)`.
The retransmit count survives packet acknowledgement; RTT is zero before a
sample. Reading these values adds no timer or per-packet atomic bookkeeping.

## Features

- BBR congestion control
- SACK + fast retransmit
- Stream multiplexing over a single socket
- Stream relaying (`relay_to`)
- MTU probing and path discovery
- Heartbeat keepalive mechanism

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the UDX wire format specification, BBR
congestion control details, and protocol constants.

## Implementation Details

- Pure Rust with no C dependencies
- tokio async runtime
- Part of the [peeroxide](https://github.com/Rightbracket/peeroxide) workspace

## Performance checks

`tests/bulk_bench.rs` streams verified data through 1–8 connections sharing two
UDP sockets without retaining the transferred payload. It reports throughput and
allocation counts; use `/usr/bin/time -l` on macOS for process CPU and peak RSS:

```sh
UDX_WORKERS=4 UDX_CONNECTIONS=8 UDX_MIB=128 \
  cargo test -p libudx --release --test bulk_bench -- --ignored --nocapture
```

Build once with `--no-run`, then time the emitted test executable rather than
Cargo so compilation is excluded.

Compare the same workload with `UDX_WORKERS=1`. A socket has one receive task;
stream processors are independent, while ordering within a stream is preserved.
More workers do not eliminate contention in the kernel's shared UDP socket.
Set `UDX_SEPARATE_PEERS=1` to give each receiver its own UDP socket while keeping
the sender's socket shared, matching a multi-peer sender.

## License

MIT OR Apache-2.0
