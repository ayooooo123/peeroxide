# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The receive window follows what the reader has not taken: the window in ACK and data headers is the limit minus the payload held in order and out of order (C `recv_rwnd_max - get_read_buffer_size`, `udx.c:267-283`), and the receiver sends one extra ACK when a read makes the window at least half of the starting window larger than the value the peer last received. The JS wrapper never uses C's callback (`udx-native` 1.22.1 has no `get_read_buffer_size`), so a stock JS peer still advertises 4 MiB; a Rust receiver now stops such a peer at the window instead of growing its queue.
- In-order data is accepted up to twice the starting window, so a paused reader does not kill a stream that follows the tail loss probe, and out-of-order data is stored only up to the starting window in bytes. A packet past either limit is dropped and not acknowledged.
- The window maximum doubles, up to four times the starting window, when the reader takes a whole window inside the measurement period; a reader that waits keeps it.
- `UdxStream::write` resolves only when the peer acknowledges every byte, which with a peer that follows the window also means that it waits for that peer's reader; the doc comment says so.

### Fixed

- The receive-window counters no longer use `AtomicUsize::fetch_update`, which new compilers mark deprecated: a compare-exchange loop gives the same "stop at zero" result, so the crate builds without warnings on stable and on the minimum Rust version.

### Changed (review 2026-11-15)

- A stream closes by itself once both sides have ended and everything it sent is ACKed (C `close_stream` on `UDX_STREAM_ALL_ENDED`): `closed()`, `is_alive()` and the close notification report it while the owner still holds the stream. By then every write has completed and the peer's data and EOF are queued for the reader, which may not have read them yet; they stay readable after the close. DATA arriving after the peer's END is dropped (C `SHOULD_READ`). The side that ended first answers the peer's ACK of its END with one more ACK and then keeps a TIMEWAIT entry for its id for 5 s (C `stream_timewait`): a late DATA or END gets the final ACK from the stream's last socket to its last remote, other packets are ignored, and nothing reaches whatever had the id. A new stream may take an id in TIMEWAIT, as in C. Dropping or destroying a closed stream sends no DESTROY.
- Writes are cut into packets at send time (C `send_new_packet`): the payload size is that of the MTU when the packet leaves, so data queued before an MTU probe succeeds or before `change_remote` goes out at the new size (the new path's base MTU after `change_remote`, C udx.c:2634), for the current peer, with the current ACK. Small writes queued together share a packet, and the FIN rides on the last data packet when they leave together (DATA|END, as C sends). Sequence numbers are taken at send time; each write still completes in order once its last packet is cumulatively ACKed. An empty `UdxStream::write` completes with the next packet sent, as in C; an empty `poll_write` queues nothing.
- BBR, rate sampling and pacing now follow `udx_bbr.c` / `udx_rate.c` without the differences the previous release listed: the first flight is paced (25000-byte bucket, rate seeded from the initial window); `on_rto` keeps `full_bw_reached`; a transmit start after idle re-paces ProbeBW at gain 1 and ends a finished ProbeRTT dwell, and it runs when a packet leaves with nothing in flight; the rate sample takes the RACK RTT of the newest delivered packet, its interval from that packet's send time, and is discarded against the stream's RACK minimum RTT; ProbeRTT dwells 200 ms from the first ACK with at most 4 in flight plus a round, then restores `prior_cwnd` and returns to Startup unless the pipe was full; cycle phase and ACK-aggregation epochs run on `delivered_ts`; recovery and loss end when the cumulative ACK passes the first seq unsent at their start. Also as C: BBR runs on every ACK that finds data in flight, an isolated MTU-probe loss opens no recovery, the app-limited check reads bytes written and not yet ACKed, and an MTU change no longer rescales `cwnd`.
- As C: packets found lost by an ACK are retransmitted under the window before that ACK's BBR update (C `rack_detect_loss` ends with `send_packets`), so recovery starts with every lost packet resent; MTU probes are counted when sent and only while probing the current path, so an old-path probe lost after `change_remote` costs the new path nothing; a write landing on an idle stream behind a zero window sends a zero-window probe at once instead of after one RTO.

### Added

- `UdxStream::set_keepalive` / `UdxAsyncStream::set_keepalive` (C `udx_stream_set_keepalive`): idle heartbeat interval, default 5 s (the hyperdht value; was a fixed 1 s); `None` turns it off. With keepalive on, a stream that hears nothing from its peer for six intervals ends with `TimedOut`.
- Tail loss probe (C `udx_tlp_timeout`, RACK §7): a lost last packet is resent after about two RTTs instead of the ≥1 s RTO.
- Zero-window probe (C `udx_zwp_timeout`): a peer advertising a zero window is probed with a heartbeat at the RTO, then every two RTOs.
- `UdxRuntime::create_random_stream`: atomically selects and reserves a collision-free nonzero ID across shared runtimes.
- `UdxStreamAbort::closed` / `UdxAsyncStream::closed`: race-free close notification supporting multiple observers both before and after stream closure.
- `UdxStream::local_id`: accessor for the local stream identifier.
- `UdxStreamRemote` (`UdxStream::remote_handle` / `UdxAsyncStream::remote_handle`): `change_remote` moves a connected stream to another peer and socket with C libudx semantics (in-flight packets keep their destination, completion once they are ACKed, MTU search restarted, no MTU probes while changing); `remote_observed` resolves when the peer reaches us on the new path; `try_send` sends an unreliable message (Node `rawStream.trySend`).
- `UdxStreamRemote::recv_message`: receives the peer's unreliable messages (C `on_recv`, Node `rawStream.on('message')`); up to 64 unread ones are kept.
- RACK reorder window and reorder timer (C `rack_update_reo_wnd`, `udx_rack_reo_timeout`): a packet the peer receives out of order within a quarter of the minimum RTT is no longer resent nor counted as a loss; a real loss is found when the window ends, without waiting for another ACK.

### Changed (review 2026-11-14, second pass)

- RTT is sampled on every delivered packet, SACKed ones included (C `ack_packet`), and a sample longer than 5 s and than `srtt + 5 × rttvar` (a suspend) counts as that bound (C `clamp_rtt`).
- An RTO no longer doubles `rto`: the timer re-arms at twice `rto` and the stream gives up on the seventh firing without progress (C `udx_rto_timeout`); it used to give up on the sixth with `rto` doubling each time. RTO loss marking uses the RACK RTT and reorder window, as C.
- BBR follows `udx_bbr.c` more closely: the bandwidth filter ages its runners-up like `win_filter_f64.c`, discarded rate samples start no round, startup growth stops at the target once ten packets are delivered, the pacing rate is at least 1 byte/ms, seeded from the window at the first RTT sample and only grows until the pipe is full, and a sender with a retransmit waiting is not app-limited. The remaining differences are listed in `congestion/bbr.rs`.

### Fixed (review 2026-11-14, second pass)

- A packet SACKed and then cumulatively ACKed counted as delivered twice for BBR.
- A BBR pacing rate below 1 byte/ms rounded to 0, which meant "unpaced".

### Changed (review 2026-11-14)

- MTU values are IP packet sizes as in C (`effective_mtu` included): at the 1200 base an IPv4 packet carries 1152 payload bytes (IPv6 1132), probes are IP sizes starting with a 1200 confirmation probe, the search starts at the first ACK and tops out at a 1500-byte IP packet.
- Retransmissions (RTO and fast retransmit) leave through the paced send path under the congestion window, lost packets first; an RTO sets `cwnd` to the packets still in flight plus one (C `udx_rto_timeout`). The per-packet retransmit tasks are gone.
- A window-limited sender waits for an ACK, the RTO or a zero-window probe instead of polling every millisecond; a non-zero peer window always allows one packet (C `send_rwnd_in_packets`).
- ACKs and heartbeats carry the stream's next sequence number (C `udx_write_header`).
- Dropping a connected, non-relay `UdxAsyncStream` sends what is queued, then DESTROY (C `udx_stream_destroy`).
- A stream destroyed by its peer or ended by a timeout reports `ConnectionReset` / `TimedOut` to its reader once (`UdxStream::read` returns `Err`, `UdxAsyncStream::poll_read` an `io::Error`), as C closes it with that error; a clean FIN still reads as EOF.
- On Linux/Android a GSO send refused with `EMSGSIZE` is resent one datagram at a time and steps the MTU back below that size.

### Fixed (review 2026-11-14)

- Relay legs forwarding to each other no longer lock each other's stream (deadlock on a multi-thread runtime); a leg reads its target's published endpoint.
- A cumulative ACK beyond the first unsent sequence number is ignored (C udx.c:1738) instead of clearing the send buffer and completing writes.
- Out-of-order receive buffer bounded by the advertised window; SACK blocks kept incrementally (O(ranges) per packet); receive-side sequence comparisons wrap (a packet with `seq = u32::MAX` panicked debug builds).
- The socket receive loop continues after a recoverable receive error (C udx.c:1950).
- A panicking stream processor still terminates its stream.
- Per-stream incoming packet queue bounded (1024 packets, dropped when full).
- A stream holds the socket it sends on, so the socket keeps receiving after the caller drops its last handle (a holepunch socket after a relay-to-direct `change_remote`); C streams hold their `udx_socket_t`.

### Changed

- `UdxRuntime::create_stream(id)` rejects occupied live stream IDs.
- Socket stream registration rejects a different stream at an occupied ID while permitting same-stream idempotent registration.
- Firewall hooks can reject a packet without closing the listening stream.
- Firewall hooks stay armed after the stream connects and run for packets arriving on another socket than the stream's, as C `on_firewall` does; a connected stream only gates the packet.
- Common ACKs use stack storage; ordered receive events reuse a per-processor buffer, with reader wakeups outside the stream lock.
- Unreliable datagrams send immediately when the socket is writable, reserving allocation and a task for backpressure.
- Per-packet bookkeeping no longer walks every unacknowledged packet: `inflight()` is a counter, RACK loss detection reads a send-time-ordered queue, fast retransmit visits only the packets marked lost, and SACK processing skips blocks it has already applied. A seeder serving four loopback peers on Linux went from about 30 to 8 CPU-seconds per GiB with the changes below.
- On Linux and Android a paced burst to one peer leaves in one UDP GSO `sendmsg`, and the socket reads up to eight datagram buffers per call (`recvmmsg`, GRO) via `quinn-udp`. On macOS one stream sends its burst at a time, which removed kernel lock contention between worker threads (about 3x the CPU per packet with four peers).
- Sockets ask for 8 MiB kernel send and receive buffers (falling back to 4 and 2 MiB, as PearTube's JS `tuneUdxSocket`), so a full congestion window sent at once is not dropped by a 208 KiB default.
- A receiver ACKs in-order data once per receive burst, at most every 8 packets; out-of-order data and END are still ACKed at once. C libudx ACKs every packet; both peers now handle about a third fewer datagrams per MiB.

### Fixed

- Packets queued on a firewall-hooked stream before its first packet arrived were sent to `0.0.0.0:0` and lost for good (retransmits included); they now wait for the hook to commit a peer.
- Aborting a stream now stops its processor task; abort handles expose liveness for registry pruning.
- Stream retirement synchronously releases socket registrations and reserved IDs; stale handles cannot deregister a replacement or re-arm a closed stream.
- Destroying a relay leg is quiet, matching C libudx, so relay teardown does not destroy an upgraded endpoint.
- Stream termination releases send, retransmit and receive-reorder buffers even while an abort handle remains alive.
- A pacing pass counted the packets it had just registered twice against the congestion window, so it sent only about half the window.

## [1.7.4](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.7.3...libudx-v1.7.4) - 2026-11-02

### Fixed

- *(swarm)* let Node.js clients connect to a firewalled peeroxide server ([#31](https://github.com/Rightbracket/peeroxide/pull/31))

## [1.7.3](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.7.2...libudx-v1.7.3) - 2026-07-12

### Other

- full documentation audit (rustdoc + mdBook) ([#28](https://github.com/Rightbracket/peeroxide/pull/28))

## [1.7.2](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.3.1...libudx-v1.7.2) - 2026-07-12

### Other

- NAT holepunch hardening + blind-relay server implementation ([#27](https://github.com/Rightbracket/peeroxide/pull/27))

### Fixed

- Fixed a `process_incoming` ordering bug: the relay fast-path (packet forwarding once `UdxStream::relay_to` is configured) was checked before the firewall-hook gate, permanently starving hook-based 4-tuple address adoption whenever `relay_to` was pre-wired on both sides of a pairing before either side's first packet arrived. The relay-forwarding check now runs after the firewall-hook gate.

## [1.3.1](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.3.0...libudx-v1.3.1) - 2026-05-14

### Other

- release ([#20](https://github.com/Rightbracket/peeroxide/pull/20))

## [1.3.0](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.2.0...libudx-v1.3.0) - 2026-05-14

### Other

- release ([#19](https://github.com/Rightbracket/peeroxide/pull/19))

## [1.2.0](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.1.0...libudx-v1.2.0) - 2026-05-01

### Changed

- `UdxSocket` is now a cheap-clone `Arc` handle (`UdxSocketInner` holds all state internally). All clones share the same underlying socket; the recv loop is only torn down when the last clone is dropped. `UdxSocket::close(self)` consuming signature is unchanged. ([#12](https://github.com/Rightbracket/peeroxide/pull/12))

## [1.1.0](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.0.1...libudx-v1.1.0) - 2026-04-28

### Changed

- `UdxError` marked `#[non_exhaustive]` to allow future variants without a breaking change. ([#10](https://github.com/Rightbracket/peeroxide/pull/10))

## [1.0.1](https://github.com/Rightbracket/peeroxide/compare/libudx-v1.0.0...libudx-v1.0.1) - 2026-04-26

### Changed

- Added `#[forbid(unsafe_code)]` and `[package.metadata.docs.rs]` configuration.
- Fixed doc example to use `?` instead of `.unwrap()`.
- Increased network simulation test timeout from 120 s to 300 s for slower CI runners.
- Updated repository URL, badges, and README links after repo transfer to the `Rightbracket` org.

## [1.0.0](https://github.com/Rightbracket/peeroxide/releases/tag/v1.0.0) - 2026-04-25

Initial release. Pure Rust implementation of the UDX protocol with BBR
congestion control, wire-compatible with the existing Node.js network.

### Added

- Pure Rust UDX protocol implementation (replaced C FFI bindings)
- BBR congestion control (faithful port of C `udx_bbr.c`)
- Reliability: cumulative ACK, SACK, retransmission with RTO, fast retransmit
- RTT estimation (Jacobson/Karels per RFC 6298)
- Rate sampling for BBR bandwidth estimation
- Token bucket pacing
- MTU probing (base 1200, max 1500, step 32)
- Relay packet forwarding (header rewriting, DESTROY propagation)
- `UdxAsyncStream`: `AsyncRead + AsyncWrite + Unpin` adapter for tokio
- Multiplexing: multiple streams per socket with independent congestion state
- Heartbeat keepalive (1s interval)
- Graceful shutdown with buffered write drain

### Tested

- 53 unit tests passing
- 74 integration and network simulation tests (loss, delay, jitter, reorder, MTU clamping)
- Golden byte fixtures verified against Node.js libudx reference implementation

### Dependencies

- `tokio` — async runtime
- `tracing`, `thiserror` — logging and error handling

### Compatibility

- Wire-compatible with Node.js libudx
- Rust edition 2024, MSRV 1.85
- Dual-licensed: MIT OR Apache-2.0
