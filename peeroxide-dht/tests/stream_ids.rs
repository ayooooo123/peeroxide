#![deny(clippy::all)]

//! `alloc_stream_id` mints random ids like Node's `raw-stream-set.js`: a
//! stream's id is the only thing a packet needs to reach a listening stream,
//! so a predictable counter would let an off-path sender guess it.

use peeroxide_dht::hyperdht::alloc_stream_id;

#[test]
fn alloc_stream_id_is_random_not_a_counter() {
    let ids: Vec<u32> = (0..64).map(|_| alloc_stream_id()).collect();

    assert!(
        ids.iter().all(|&id| id != 0),
        "id 0 is the unknown-remote id: {ids:?}"
    );
    assert!(
        ids.windows(2).all(|w| w[1] != w[0].wrapping_add(1)),
        "consecutive ids: {ids:?}"
    );
}
