//! Persistent storage for DHT records published by server nodes.
//!
//! Provides the `Persistent` handler that backs the four record-storing
//! RPC verbs (`ANNOUNCE`, `UNANNOUNCE`, `MUTABLE_PUT`/`GET`, `IMMUTABLE_PUT`/`GET`)
//! with bounded LRU caches sized via `PersistentConfig`. `PersistentStats`
//! exposes per-cache record counts for operators monitoring a running node.
//!
//! The `PersistentConfig` type is part of the public API for callers that
//! run their own DHT node (e.g. the `peeroxide node` CLI). The handler itself
//! is plumbed inside [`crate::rpc::DhtHandle`] and not constructed directly
//! by typical consumers.

#![allow(missing_docs)]
#![deny(clippy::all)]

use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::compact_encoding::{State, decode_uint};
use crate::crypto::{
    NS_ANNOUNCE, NS_MUTABLE_PUT, NS_UNANNOUNCE, ann_signable, hash, mutable_signable,
    verify_detached,
};
use crate::hyperdht_messages::{
    HyperPeer, LookupRawReply, MutableGetResponse, decode_announce_from_bytes,
    decode_mutable_get_response_from_bytes, decode_mutable_put_request_from_bytes,
    encode_hyper_peer_to_bytes, encode_lookup_raw_reply_to_bytes,
    encode_mutable_get_response_to_bytes,
};
use crate::messages::Ipv4Peer;
use crate::peer::NodeId;

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").ok();
            s
        })
}

// ── Error codes ───────────────────────────────────────────────────────────────

const SEQ_REUSED: u64 = 16;
const SEQ_TOO_LOW: u64 = 17;
const MAX_RECORDS_PER_LOOKUP: usize = 20;
const MAX_RELAY_ADDRESSES: usize = 3;

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for the `Persistent` storage.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PersistentConfig {
    pub max_records: usize,
    pub max_record_age: Duration,
    pub max_per_key: usize,
    pub max_lru_size: usize,
    pub max_lru_age: Duration,
}

impl Default for PersistentConfig {
    fn default() -> Self {
        Self {
            max_records: 65536,
            max_record_age: Duration::from_secs(20 * 60),
            max_per_key: usize::MAX,
            max_lru_size: 65536,
            max_lru_age: Duration::from_secs(20 * 60),
        }
    }
}

// ── Incoming request / reply types ───────────────────────────────────────────

/// Incoming user-facing request forwarded from the DHT layer.
pub struct IncomingHyperRequest {
    pub command: u64,
    pub target: Option<[u8; 32]>,
    pub token: Option<[u8; 32]>,
    pub value: Option<Vec<u8>>,
    pub from: Ipv4Peer,
    pub id: Option<NodeId>,
}

/// What the handler wants to send back.
#[non_exhaustive]
pub enum HandlerReply {
    /// Reply with an optional value and token / closer nodes.
    Value(Option<Vec<u8>>),
    /// Reply with an optional value but *without* token / closer nodes.
    ValueNoToken(Option<Vec<u8>>),
    /// Reply with an error code.
    Error(u64),
    /// Do not reply at all (bad / incomplete request).
    Silent,
}

// ── RecordEntry ───────────────────────────────────────────────────────────────

struct RecordEntry {
    public_key: [u8; 32],
    record: Vec<u8>,
    inserted_at: Instant,
}

// ── RecordCache ───────────────────────────────────────────────────────────────

/// Two-generation cache for peer announcement records, keyed by topic hex.
pub struct RecordCache {
    fresh: HashMap<String, Vec<RecordEntry>>,
    stale: HashMap<String, Vec<RecordEntry>>,
    fresh_count: usize,
    stale_count: usize,
    max_size: usize,
    max_age: Duration,
}

impl RecordCache {
    pub fn new(max_size: usize, max_age: Duration, _max_per_key: usize) -> Self {
        Self {
            fresh: HashMap::new(),
            stale: HashMap::new(),
            fresh_count: 0,
            stale_count: 0,
            max_size,
            max_age,
        }
    }

    pub fn add(&mut self, key: &str, public_key: [u8; 32], record: Vec<u8>) {
        self.stale_count -= Self::remove_from(&mut self.stale, key, &public_key);
        self.fresh_count -= Self::remove_from(&mut self.fresh, key, &public_key);
        if self.fresh_count + self.stale_count >= self.max_size {
            self.stale = std::mem::take(&mut self.fresh);
            self.stale_count = self.fresh_count;
            self.fresh_count = 0;
        }
        self.fresh
            .entry(key.to_owned())
            .or_default()
            .push(RecordEntry {
                public_key,
                record,
                inserted_at: Instant::now(),
            });
        self.fresh_count += 1;
    }

    /// Remove the record for `(key, public_key)`.
    pub fn remove(&mut self, key: &str, public_key: &[u8; 32]) {
        self.fresh_count -= Self::remove_from(&mut self.fresh, key, public_key);
        self.stale_count -= Self::remove_from(&mut self.stale, key, public_key);
    }

    /// Get a random sample of up to `max` live records for `key`.
    pub fn get(&mut self, key: &str, max: usize) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut records = Vec::new();
        if let Some(bucket) = self.fresh.get_mut(key) {
            let before = bucket.len();
            bucket.retain(|entry| now.duration_since(entry.inserted_at) < self.max_age);
            self.fresh_count -= before - bucket.len();
            records.extend(bucket.iter().map(|entry| entry.record.clone()));
        }
        if let Some(bucket) = self.stale.get_mut(key) {
            let before = bucket.len();
            bucket.retain(|entry| now.duration_since(entry.inserted_at) < self.max_age);
            self.stale_count -= before - bucket.len();
            records.extend(bucket.iter().map(|entry| entry.record.clone()));
        }
        records.shuffle(&mut rand::rng());
        records.truncate(max);
        records
    }

    /// Evict all entries.
    pub fn destroy(&mut self) {
        self.fresh.clear();
        self.stale.clear();
        self.fresh_count = 0;
        self.stale_count = 0;
    }

    pub fn record_count(&self) -> usize {
        self.fresh_count + self.stale_count
    }

    pub fn topic_count(&self) -> usize {
        self.fresh
            .keys()
            .chain(self.stale.keys())
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn remove_from(
        entries: &mut HashMap<String, Vec<RecordEntry>>,
        key: &str,
        public_key: &[u8; 32],
    ) -> usize {
        let mut removed = 0;
        let empty = if let Some(bucket) = entries.get_mut(key) {
            let before = bucket.len();
            bucket.retain(|entry| &entry.public_key != public_key);
            removed = before - bucket.len();
            bucket.is_empty()
        } else {
            false
        };
        if empty {
            entries.remove(key);
        }
        removed
    }
}

// ── CacheEntry / LruCache ────────────────────────────────────────────────────

struct CacheEntry {
    value: Vec<u8>,
    inserted_at: Instant,
}

/// Two-generation TTL cache for mutable data, immutable data, and router state.
pub struct LruCache {
    latest: HashMap<String, CacheEntry>,
    oldest: HashMap<String, CacheEntry>,
    retained: HashMap<String, CacheEntry>,
    max_size: usize,
    max_age: Duration,
}

impl LruCache {
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            latest: HashMap::new(),
            oldest: HashMap::new(),
            retained: HashMap::new(),
            max_size,
            max_age,
        }
    }

    /// Get a live value, returning `None` if absent or expired.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(entry) = self.retained.get(key) {
            return Some(entry.value.clone());
        }
        let entry = self.latest.get(key).or_else(|| self.oldest.get(key))?;
        (self.max_age.is_zero() || Instant::now().duration_since(entry.inserted_at) < self.max_age)
            .then(|| entry.value.clone())
    }

    /// Get a live value and promote an old-generation hit.
    pub fn get_promoting(&mut self, key: &str) -> Option<Vec<u8>> {
        if let Some(entry) = self.retained.get(key) {
            return Some(entry.value.clone());
        }
        if let Some(entry) = self.oldest.remove(key) {
            if self.max_age.is_zero()
                || Instant::now().duration_since(entry.inserted_at) < self.max_age
            {
                let value = entry.value.clone();
                self.latest.insert(
                    key.to_owned(),
                    CacheEntry {
                        value: entry.value,
                        inserted_at: Instant::now(),
                    },
                );
                return Some(value);
            }
            return None;
        }
        let entry = self.latest.get_mut(key)?;
        if self.max_age.is_zero() || Instant::now().duration_since(entry.inserted_at) < self.max_age
        {
            entry.inserted_at = Instant::now();
            return Some(entry.value.clone());
        }
        None
    }

    /// Insert or replace an evictable value.
    pub fn set(&mut self, key: impl Into<String>, value: Vec<u8>) {
        let key = key.into();
        if self.retained.contains_key(&key) {
            return;
        }
        self.latest.remove(&key);
        self.oldest.remove(&key);
        if self.max_size == 0 {
            return;
        }
        if self.latest.len() + self.oldest.len() >= self.max_size {
            self.oldest = std::mem::take(&mut self.latest);
        }
        self.latest.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Insert or replace a local value that cache eviction must not remove.
    pub fn retain(&mut self, key: impl Into<String>, value: Vec<u8>) {
        let key = key.into();
        self.delete(&key);
        self.retained.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    pub fn delete(&mut self, key: &str) {
        self.latest.remove(key);
        self.oldest.remove(key);
        self.retained.remove(key);
    }

    pub fn destroy(&mut self) {
        self.latest.clear();
        self.oldest.clear();
        self.retained.clear();
    }

    pub fn len(&self) -> usize {
        self.latest.len() + self.oldest.len() + self.retained.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── PersistentStats ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PersistentStats {
    pub records: usize,
    pub record_topics: usize,
    pub mutables: usize,
    pub immutables: usize,
    pub router_entries: usize,
}

// ── Persistent ────────────────────────────────────────────────────────────────

/// Server-side persistent storage for HyperDHT commands.
pub struct Persistent {
    records: RecordCache,
    bumps: LruCache,
    refreshes: LruCache,
    mutables: LruCache,
    immutables: LruCache,
    /// Self-announce records keyed by hex target (Node `dht._router` records).
    router: LruCache,
}

impl Persistent {
    pub fn new(config: PersistentConfig) -> Self {
        Self {
            records: RecordCache::new(
                config.max_records,
                config.max_record_age,
                config.max_per_key,
            ),
            bumps: LruCache::new(config.max_lru_size, config.max_lru_age),
            refreshes: LruCache::new(config.max_lru_size, config.max_lru_age),
            mutables: LruCache::new(config.max_lru_size, config.max_lru_age),
            immutables: LruCache::new(config.max_lru_size, config.max_lru_age),
            router: LruCache::new(config.max_lru_size, config.max_lru_age),
        }
    }

    /// Serve `record` for a local listener on `target`, or forget it
    /// (Node `server.listen()` → `dht._router.set(target, { record })`).
    pub fn set_local_record(&mut self, target: &[u8; 32], record: Option<Vec<u8>>) {
        let key = to_hex(target);
        match record {
            Some(record) => self.router.retain(key, record),
            None => self.router.delete(&key),
        };
    }

    // ── FIND_PEER ─────────────────────────────────────────────────────────────

    /// Handle an incoming FIND_PEER request.
    pub fn on_find_peer(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => t,
            None => return HandlerReply::Silent,
        };

        HandlerReply::Value(self.router.get_promoting(&to_hex(target)))
    }

    // ── LOOKUP ────────────────────────────────────────────────────────────────

    /// Handle an incoming LOOKUP request.
    pub fn on_lookup(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };

        let key = to_hex(target);
        let mut peers: Vec<HyperPeer> = self
            .records
            .get(&key, MAX_RECORDS_PER_LOOKUP)
            .into_iter()
            .filter_map(|bytes| crate::hyperdht_messages::decode_hyper_peer_from_bytes(&bytes).ok())
            .collect();

        // Append self-announce from router if we haven't hit the max.
        if peers.len() < MAX_RECORDS_PER_LOOKUP {
            if let Some(record) = self.router.get_promoting(&key) {
                if let Ok(peer) = crate::hyperdht_messages::decode_hyper_peer_from_bytes(&record) {
                    peers.push(peer);
                }
            }
        }

        let bump_bytes = self.bumps.get_promoting(&key);
        let bump: u64 = bump_bytes
            .as_deref()
            .and_then(|b| {
                let mut s = State::from_buffer(b);
                decode_uint(&mut s).ok()
            })
            .unwrap_or(0);

        if peers.is_empty() && bump == 0 {
            return HandlerReply::Value(None);
        }

        let reply = LookupRawReply { peers, bump };
        match encode_lookup_raw_reply_to_bytes(&reply) {
            Ok(bytes) => HandlerReply::Value(Some(bytes)),
            Err(_) => HandlerReply::Value(None),
        }
    }

    // ── ANNOUNCE ──────────────────────────────────────────────────────────────

    /// Handle an incoming ANNOUNCE request.
    pub fn on_announce(&mut self, req: &IncomingHyperRequest, node_id: &[u8; 32]) -> HandlerReply {
        let target = match &req.target {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };
        let token = match &req.token {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };

        let value = match &req.value {
            Some(v) => v.clone(),
            None => return HandlerReply::Silent,
        };

        let msg = match decode_announce_from_bytes(&value) {
            Ok(m) => m,
            Err(_) => return HandlerReply::Silent,
        };

        // Refresh announces restore a saved record and are not signed.
        if msg.peer.is_none() {
            let refresh = match &msg.refresh {
                Some(refresh) => refresh,
                None => return HandlerReply::Silent,
            };
            let refresh_key = to_hex(hash(refresh));
            let stored = match self.refreshes.get_promoting(&refresh_key) {
                Some(stored) => stored,
                None => return HandlerReply::Silent,
            };
            let target_bytes = match stored.get(..32) {
                Some(target_bytes) => target_bytes,
                None => return HandlerReply::Silent,
            };
            let announce_self = match stored.get(32) {
                Some(announce_self) => *announce_self != 0,
                None => return HandlerReply::Silent,
            };
            let record = match stored.get(33..) {
                Some(record) => record,
                None => return HandlerReply::Silent,
            };
            let peer = match crate::hyperdht_messages::decode_hyper_peer_from_bytes(record) {
                Ok(peer) => peer,
                Err(_) => return HandlerReply::Silent,
            };
            let mut original_target = [0u8; 32];
            original_target.copy_from_slice(target_bytes);
            let target_key = to_hex(original_target);
            if announce_self {
                self.router.set(target_key.clone(), record.to_vec());
                self.records.remove(&target_key, &peer.public_key);
            } else {
                self.records
                    .add(&target_key, peer.public_key, record.to_vec());
            }
            self.refreshes.delete(&refresh_key);
            self.refreshes.set(to_hex(refresh), stored);
            return HandlerReply::ValueNoToken(None);
        }

        let peer = match &msg.peer {
            Some(p) => p.clone(),
            None => return HandlerReply::Silent,
        };

        let signature = match &msg.signature {
            Some(s) => *s,
            None => return HandlerReply::Silent,
        };

        // Encode peer for signature verification.
        let peer_encoded = match encode_hyper_peer_to_bytes(&peer) {
            Ok(b) => b,
            Err(_) => return HandlerReply::Silent,
        };

        let refresh_bytes: &[u8] = msg.refresh.as_ref().map(|r| r.as_slice()).unwrap_or(&[]);

        let signable = ann_signable(
            &target,
            &token,
            node_id,
            &peer_encoded,
            refresh_bytes,
            &NS_ANNOUNCE,
        );

        if !verify_detached(&signature, &signable, &peer.public_key) {
            return HandlerReply::Silent;
        }

        // Limit relay addresses.
        let mut stored_peer = peer.clone();
        stored_peer.relay_addresses.truncate(MAX_RELAY_ADDRESSES);

        let target_key = to_hex(target);
        let announce_self = hash(&stored_peer.public_key) == target;

        if announce_self {
            let encoded = match encode_hyper_peer_to_bytes(&stored_peer) {
                Ok(b) => b,
                Err(_) => return HandlerReply::Silent,
            };
            self.router.set(target_key.clone(), encoded);
            self.records.remove(&target_key, &stored_peer.public_key);
        } else {
            let encoded = match encode_hyper_peer_to_bytes(&stored_peer) {
                Ok(b) => b,
                Err(_) => return HandlerReply::Silent,
            };
            self.records
                .add(&target_key, stored_peer.public_key, encoded);

            // Update bump only when it advances and is close to the local clock.
            if msg.bump != 0 {
                let current_bump = self
                    .bumps
                    .get_promoting(&target_key)
                    .and_then(|b| decode_uint(&mut State::from_buffer(&b)).ok())
                    .unwrap_or(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_millis() as u64);
                if msg.bump > current_bump && msg.bump <= now.saturating_add(60_000) {
                    let mut bump_state = crate::compact_encoding::State::new();
                    crate::compact_encoding::preencode_uint(&mut bump_state, msg.bump);
                    bump_state.alloc();
                    crate::compact_encoding::encode_uint(&mut bump_state, msg.bump);
                    self.bumps.set(target_key.clone(), bump_state.buffer);
                }
            }
        }

        // Store refresh state under the raw refresh token. Refresh requests
        // hash their token to find this entry and then re-key it raw.
        if let Some(refresh) = &msg.refresh {
            let peer_bytes = encode_hyper_peer_to_bytes(&stored_peer).unwrap_or_default();
            let mut refresh_record = Vec::with_capacity(33 + peer_bytes.len());
            refresh_record.extend_from_slice(&target);
            refresh_record.push(u8::from(announce_self));
            refresh_record.extend_from_slice(&peer_bytes);
            self.refreshes.set(to_hex(refresh), refresh_record);
        }

        if msg.lookup {
            return match self.on_lookup(req) {
                HandlerReply::Value(value) => HandlerReply::ValueNoToken(value),
                HandlerReply::Silent => HandlerReply::ValueNoToken(None),
                _ => HandlerReply::ValueNoToken(None),
            };
        }

        HandlerReply::ValueNoToken(None)
    }

    // ── UNANNOUNCE ────────────────────────────────────────────────────────────

    /// Handle an incoming UNANNOUNCE request.
    pub fn on_unannounce(
        &mut self,
        req: &IncomingHyperRequest,
        node_id: &[u8; 32],
    ) -> HandlerReply {
        let target = match &req.target {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };
        let token = match &req.token {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };

        let value = match &req.value {
            Some(v) => v.clone(),
            None => return HandlerReply::Silent,
        };

        let msg = match decode_announce_from_bytes(&value) {
            Ok(m) => m,
            Err(_) => return HandlerReply::Silent,
        };

        let peer = match &msg.peer {
            Some(p) => p.clone(),
            None => return HandlerReply::Silent,
        };

        let signature = match &msg.signature {
            Some(s) => *s,
            None => return HandlerReply::Silent,
        };

        let peer_encoded = match encode_hyper_peer_to_bytes(&peer) {
            Ok(b) => b,
            Err(_) => return HandlerReply::Silent,
        };

        let refresh_bytes: &[u8] = msg.refresh.as_ref().map(|r| r.as_slice()).unwrap_or(&[]);

        let signable = ann_signable(
            &target,
            &token,
            node_id,
            &peer_encoded,
            refresh_bytes,
            &NS_UNANNOUNCE,
        );

        if !verify_detached(&signature, &signable, &peer.public_key) {
            return HandlerReply::Silent;
        }

        let target_key = to_hex(target);
        self.records.remove(&target_key, &peer.public_key);
        if hash(&peer.public_key) == target {
            self.router.delete(&target_key);
        }

        HandlerReply::ValueNoToken(None)
    }

    // ── MUTABLE_PUT ───────────────────────────────────────────────────────────

    /// Handle an incoming MUTABLE_PUT request.
    pub fn on_mutable_put(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };
        if req.token.is_none() {
            return HandlerReply::Silent;
        }

        let value = match &req.value {
            Some(v) => v.clone(),
            None => return HandlerReply::Silent,
        };

        let put = match decode_mutable_put_request_from_bytes(&value) {
            Ok(p) => p,
            Err(_) => return HandlerReply::Silent,
        };

        // Verify target == hash(publicKey).
        if hash(&put.public_key) != target {
            return HandlerReply::Silent;
        }

        // Verify signature.
        let signable = mutable_signable(&NS_MUTABLE_PUT, put.seq, &put.value);
        if !verify_detached(&put.signature, &signable, &put.public_key) {
            return HandlerReply::Silent;
        }

        let target_key = to_hex(target);

        // Check seq against existing stored value.
        if let Some(existing_bytes) = self.mutables.get_promoting(&target_key) {
            if let Ok(existing) = decode_mutable_get_response_from_bytes(&existing_bytes) {
                if existing.seq == put.seq && existing.value != put.value {
                    return HandlerReply::Error(SEQ_REUSED);
                }
                if existing.seq > put.seq {
                    return HandlerReply::Error(SEQ_TOO_LOW);
                }
            }
        }

        let response = MutableGetResponse {
            seq: put.seq,
            value: put.value,
            signature: put.signature,
        };

        match encode_mutable_get_response_to_bytes(&response) {
            Ok(encoded) => {
                self.mutables.set(target_key, encoded);
                HandlerReply::Value(None)
            }
            Err(_) => HandlerReply::Silent,
        }
    }

    // ── MUTABLE_GET ───────────────────────────────────────────────────────────

    /// Handle an incoming MUTABLE_GET request.
    pub fn on_mutable_get(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => t,
            None => return HandlerReply::Silent,
        };

        let value = match &req.value {
            Some(v) => v.clone(),
            None => return HandlerReply::Silent,
        };

        // Decode requested seq (compact uint).
        let requested_seq = {
            let mut s = State::from_buffer(&value);
            decode_uint(&mut s).unwrap_or(0)
        };

        let target_key = to_hex(target);
        if let Some(stored_bytes) = self.mutables.get_promoting(&target_key) {
            if let Ok(stored) = decode_mutable_get_response_from_bytes(&stored_bytes) {
                if stored.seq >= requested_seq {
                    return HandlerReply::Value(Some(stored_bytes));
                }
            }
        }

        HandlerReply::Value(None)
    }

    // ── IMMUTABLE_PUT ────────────────────────────────────────────────────────

    /// Handle an incoming IMMUTABLE_PUT request.
    pub fn on_immutable_put(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => *t,
            None => return HandlerReply::Silent,
        };
        if req.token.is_none() {
            return HandlerReply::Silent;
        }

        let value = match &req.value {
            Some(v) => v.clone(),
            None => return HandlerReply::Silent,
        };

        // Verify target == hash(value).
        if hash(&value) != target {
            return HandlerReply::Silent;
        }

        let target_key = to_hex(target);
        self.immutables.set(target_key, value);

        HandlerReply::Value(None)
    }

    // ── IMMUTABLE_GET ────────────────────────────────────────────────────────

    /// Handle an incoming IMMUTABLE_GET request.
    pub fn on_immutable_get(&mut self, req: &IncomingHyperRequest) -> HandlerReply {
        let target = match &req.target {
            Some(t) => t,
            None => return HandlerReply::Silent,
        };

        let target_key = to_hex(target);
        HandlerReply::Value(self.immutables.get_promoting(&target_key))
    }

    pub fn stats(&self) -> PersistentStats {
        PersistentStats {
            records: self.records.record_count(),
            record_topics: self.records.topic_count(),
            mutables: self.mutables.len(),
            immutables: self.immutables.len(),
            router_entries: self.router.len(),
        }
    }

    pub fn destroy(&mut self) {
        self.records.destroy();
        self.bumps.destroy();
        self.refreshes.destroy();
        self.mutables.destroy();
        self.immutables.destroy();
        self.router.destroy();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_persistent() -> Persistent {
        Persistent::new(PersistentConfig::default())
    }

    fn make_keypair() -> ([u8; 32], [u8; 64]) {
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&seed);
        secret[32..].copy_from_slice(&pk);
        (pk, secret)
    }

    fn dummy_peer() -> Ipv4Peer {
        Ipv4Peer {
            host: "127.0.0.1".to_string(),
            port: 1234,
        }
    }

    // ── RecordCache tests ─────────────────────────────────────────────────────

    #[test]
    fn record_cache_add_get() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        cache.add("topic1", [0xaau8; 32], b"record1".to_vec());
        let records = cache.get("topic1", 10);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"record1");
    }

    #[test]
    fn record_cache_replace_same_pubkey() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        cache.add("topic1", [0xaau8; 32], b"v1".to_vec());
        cache.add("topic1", [0xaau8; 32], b"v2".to_vec());
        let records = cache.get("topic1", 10);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"v2");
    }

    #[test]
    fn record_cache_remove() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        cache.add("topic1", [0xaau8; 32], b"record1".to_vec());
        cache.remove("topic1", &[0xaau8; 32]);
        let records = cache.get("topic1", 10);
        assert!(records.is_empty());
    }

    #[test]
    fn record_cache_ttl_expired() {
        let mut cache = RecordCache::new(100, Duration::from_nanos(1), 20);
        cache.add("topic1", [0xaau8; 32], b"record1".to_vec());
        // Sleep a tiny bit so TTL expires.
        std::thread::sleep(Duration::from_millis(2));
        let records = cache.get("topic1", 10);
        assert!(records.is_empty());
    }

    #[test]
    fn record_cache_has_no_per_topic_limit() {
        let mut cache = RecordCache::new(1000, Duration::from_secs(60), 3);
        for i in 0u8..5 {
            cache.add("topic1", [i; 32], vec![i]);
        }
        assert_eq!(cache.get("topic1", 10).len(), 5);
    }

    #[test]
    fn record_cache_returns_twenty_of_thirty_records() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        for i in 0u8..30 {
            cache.add("topic", [i; 32], vec![i]);
        }
        assert_eq!(cache.record_count(), 30);
        assert_eq!(cache.get("topic", MAX_RECORDS_PER_LOOKUP).len(), 20);
    }

    #[test]
    fn router_cache_stays_bounded() {
        let mut persistent = make_persistent();
        for i in 0u64..70_000 {
            persistent.router.set(format!("{i:064x}"), vec![0]);
        }
        assert!(persistent.stats().router_entries <= 65_536);
    }

    #[test]
    fn record_cache_destroy() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        cache.add("topic1", [0xaau8; 32], b"record1".to_vec());
        cache.destroy();
        assert!(cache.get("topic1", 10).is_empty());
    }

    // ── LruCache tests ────────────────────────────────────────────────────────

    #[test]
    fn lru_cache_set_get() {
        let mut cache = LruCache::new(100, Duration::from_secs(60));
        cache.set("k1", b"value".to_vec());
        assert_eq!(cache.get("k1"), Some(b"value".to_vec()));
    }

    #[test]
    fn lru_cache_miss() {
        let cache = LruCache::new(100, Duration::from_secs(60));
        assert_eq!(cache.get("nonexistent"), None);
    }

    #[test]
    fn lru_cache_delete() {
        let mut cache = LruCache::new(100, Duration::from_secs(60));
        cache.set("k1", b"value".to_vec());
        cache.delete("k1");
        assert_eq!(cache.get("k1"), None);
    }

    #[test]
    fn lru_cache_ttl() {
        let mut cache = LruCache::new(100, Duration::from_nanos(1));
        cache.set("k1", b"value".to_vec());
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(cache.get("k1"), None);
    }

    #[test]
    fn retained_record_does_not_expire_and_cannot_be_replaced() {
        let mut cache = LruCache::new(100, Duration::from_nanos(1));
        cache.retain("local", b"retained".to_vec());
        cache.set("local", b"remote".to_vec());
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(cache.get("local"), Some(b"retained".to_vec()));
        assert_eq!(cache.get_promoting("local"), Some(b"retained".to_vec()));
        cache.set("remote", b"evictable".to_vec());
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(cache.get("remote"), None);
    }

    #[test]
    fn lru_cache_promotes_old_generation_hits() {
        let mut cache = LruCache::new(1, Duration::from_secs(60));
        cache.set("old", b"old".to_vec());
        cache.set("new", b"new".to_vec());
        assert!(cache.oldest.contains_key("old"));
        assert_eq!(cache.get_promoting("old"), Some(b"old".to_vec()));
        assert!(cache.latest.contains_key("old"));
        assert!(!cache.oldest.contains_key("old"));
    }

    #[test]
    fn lru_cache_hot_reads_refresh_age() {
        // 150 ms reads against a 400 ms age: a busy machine has 250 ms of slack per read.
        let mut cache = LruCache::new(100, Duration::from_millis(400));
        cache.set("hot", b"hot".to_vec());
        cache.set("cold", b"cold".to_vec());
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(150));
            assert_eq!(cache.get_promoting("hot"), Some(b"hot".to_vec()));
        }
        assert_eq!(cache.get_promoting("cold"), None);
    }

    // ── on_lookup tests ───────────────────────────────────────────────────────

    #[test]
    fn on_lookup_no_target_is_silent() {
        let mut p = make_persistent();
        let req = IncomingHyperRequest {
            command: crate::hyperdht_messages::LOOKUP,
            target: None,
            token: None,
            value: None,
            from: dummy_peer(),
            id: None,
        };
        matches!(p.on_lookup(&req), HandlerReply::Silent);
    }

    #[test]
    fn on_lookup_empty_returns_none_value() {
        let mut p = make_persistent();
        let req = IncomingHyperRequest {
            command: crate::hyperdht_messages::LOOKUP,
            target: Some([0u8; 32]),
            token: None,
            value: None,
            from: dummy_peer(),
            id: None,
        };
        matches!(p.on_lookup(&req), HandlerReply::Value(None));
    }

    #[test]
    fn announce_lookup_returns_existing_peer() {
        let mut persistent = make_persistent();
        let target = [9u8; 32];
        let (existing_key, _) = make_keypair();
        let existing = HyperPeer {
            public_key: existing_key,
            relay_addresses: vec![],
        };
        persistent.records.add(
            &to_hex(target),
            existing_key,
            encode_hyper_peer_to_bytes(&existing).unwrap(),
        );

        let seed = [0x43u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&seed);
        secret[32..].copy_from_slice(&public_key);
        let peer = HyperPeer {
            public_key,
            relay_addresses: vec![],
        };
        let token = [4u8; 32];
        let peer_bytes = encode_hyper_peer_to_bytes(&peer).unwrap();
        let signature = crate::crypto::sign_detached(
            &ann_signable(&target, &token, &[0u8; 32], &peer_bytes, &[], &NS_ANNOUNCE),
            &secret,
        );
        let value = crate::hyperdht_messages::encode_announce_to_bytes(
            &crate::hyperdht_messages::AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
                lookup: true,
            },
        )
        .unwrap();
        let request = IncomingHyperRequest {
            command: crate::hyperdht_messages::ANNOUNCE,
            target: Some(target),
            token: Some(token),
            value: Some(value),
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(
            persistent.on_announce(&request, &[0u8; 32]),
            HandlerReply::ValueNoToken(Some(_))
        ));
    }

    #[test]
    fn refresh_chain_restores_original_target_only() {
        let mut persistent = make_persistent();
        let original_target = [1u8; 32];
        let other_target = [2u8; 32];
        let t2 = [4u8; 32];
        let t1 = hash(&t2);
        let r0 = hash(&t1);

        let seed = [0x43u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&seed);
        secret[32..].copy_from_slice(&public_key);
        let peer = HyperPeer {
            public_key,
            relay_addresses: vec![],
        };
        let token = [5u8; 32];
        let peer_bytes = encode_hyper_peer_to_bytes(&peer).unwrap();
        let signature = crate::crypto::sign_detached(
            &ann_signable(
                &original_target,
                &token,
                &[0u8; 32],
                &peer_bytes,
                &r0,
                &NS_ANNOUNCE,
            ),
            &secret,
        );
        let initial = IncomingHyperRequest {
            command: crate::hyperdht_messages::ANNOUNCE,
            target: Some(original_target),
            token: Some(token),
            value: Some(
                crate::hyperdht_messages::encode_announce_to_bytes(
                    &crate::hyperdht_messages::AnnounceMessage {
                        peer: Some(peer.clone()),
                        refresh: Some(r0),
                        signature: Some(signature),
                        bump: 0,
                        lookup: false,
                    },
                )
                .unwrap(),
            ),
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(
            persistent.on_announce(&initial, &[0u8; 32]),
            HandlerReply::ValueNoToken(None)
        ));
        persistent
            .records
            .remove(&to_hex(original_target), &public_key);

        let refresh = |target, token| IncomingHyperRequest {
            command: crate::hyperdht_messages::ANNOUNCE,
            target: Some(target),
            token: Some([6u8; 32]),
            value: Some(
                crate::hyperdht_messages::encode_announce_to_bytes(
                    &crate::hyperdht_messages::AnnounceMessage {
                        peer: None,
                        refresh: Some(token),
                        signature: None,
                        bump: 0,
                        lookup: false,
                    },
                )
                .unwrap(),
            ),
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(
            persistent.on_announce(&refresh(other_target, t1), &[0u8; 32]),
            HandlerReply::ValueNoToken(None)
        ));
        assert_eq!(
            persistent.records.get(&to_hex(original_target), 10).len(),
            1
        );
        assert!(persistent.records.get(&to_hex(other_target), 10).is_empty());
        persistent
            .records
            .remove(&to_hex(original_target), &public_key);
        assert!(matches!(
            persistent.on_announce(&refresh(other_target, t2), &[0u8; 32]),
            HandlerReply::ValueNoToken(None)
        ));
        assert!(matches!(
            persistent.on_announce(&refresh(other_target, [8u8; 32]), &[0u8; 32]),
            HandlerReply::Silent
        ));
    }

    // ── on_immutable_put/get round-trip ───────────────────────────────────────

    #[test]
    fn immutable_put_get_roundtrip() {
        let mut p = make_persistent();
        let data = b"hello world".to_vec();
        let target = hash(&data);

        let put_req = IncomingHyperRequest {
            command: crate::hyperdht_messages::IMMUTABLE_PUT,
            target: Some(target),
            token: Some([0xbbu8; 32]),
            value: Some(data.clone()),
            from: dummy_peer(),
            id: None,
        };
        let reply = p.on_immutable_put(&put_req);
        assert!(matches!(reply, HandlerReply::Value(None)));

        let get_req = IncomingHyperRequest {
            command: crate::hyperdht_messages::IMMUTABLE_GET,
            target: Some(target),
            token: None,
            value: None,
            from: dummy_peer(),
            id: None,
        };
        let reply = p.on_immutable_get(&get_req);
        if let HandlerReply::Value(Some(v)) = reply {
            assert_eq!(v, data);
        } else {
            panic!("expected Value(Some(...))");
        }
    }

    #[test]
    fn immutable_put_bad_hash_is_silent() {
        let mut p = make_persistent();
        let put_req = IncomingHyperRequest {
            command: crate::hyperdht_messages::IMMUTABLE_PUT,
            target: Some([0xffu8; 32]),
            token: Some([0xbbu8; 32]),
            value: Some(b"wrong".to_vec()),
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(p.on_immutable_put(&put_req), HandlerReply::Silent));
    }

    // ── on_mutable_put/get round-trip ─────────────────────────────────────────

    #[test]
    fn mutable_put_get_roundtrip() {
        let mut p = make_persistent();
        let (pk, sk) = make_keypair();
        let target = hash(&pk);
        let value = b"my value".to_vec();
        let seq: u64 = 1;

        let signable = mutable_signable(&NS_MUTABLE_PUT, seq, &value);
        let sig = crate::crypto::sign_detached(&signable, &sk);

        let put_msg = crate::hyperdht_messages::MutablePutRequest {
            public_key: pk,
            seq,
            value: value.clone(),
            signature: sig,
        };
        let put_bytes =
            crate::hyperdht_messages::encode_mutable_put_request_to_bytes(&put_msg).unwrap();

        let put_req = IncomingHyperRequest {
            command: crate::hyperdht_messages::MUTABLE_PUT,
            target: Some(target),
            token: Some([0u8; 32]),
            value: Some(put_bytes),
            from: dummy_peer(),
            id: None,
        };

        let reply = p.on_mutable_put(&put_req);
        assert!(matches!(reply, HandlerReply::Value(None)));

        // Get with seq=0 (any seq >= 0 matches).
        let mut seq_state = crate::compact_encoding::State::new();
        crate::compact_encoding::preencode_uint(&mut seq_state, 0u64);
        seq_state.alloc();
        crate::compact_encoding::encode_uint(&mut seq_state, 0u64);

        let get_req = IncomingHyperRequest {
            command: crate::hyperdht_messages::MUTABLE_GET,
            target: Some(target),
            token: None,
            value: Some(seq_state.buffer),
            from: dummy_peer(),
            id: None,
        };

        let reply = p.on_mutable_get(&get_req);
        if let HandlerReply::Value(Some(v)) = reply {
            let decoded =
                crate::hyperdht_messages::decode_mutable_get_response_from_bytes(&v).unwrap();
            assert_eq!(decoded.seq, seq);
            assert_eq!(decoded.value, value);
        } else {
            panic!("expected Value(Some(...))");
        }
    }

    #[test]
    fn mutable_put_seq_too_low() {
        let mut p = make_persistent();
        let (pk, sk) = make_keypair();
        let target = hash(&pk);

        let put_with_seq = |seq: u64| {
            let signable = mutable_signable(&NS_MUTABLE_PUT, seq, b"v");
            let sig = crate::crypto::sign_detached(&signable, &sk);
            let put_msg = crate::hyperdht_messages::MutablePutRequest {
                public_key: pk,
                seq,
                value: b"v".to_vec(),
                signature: sig,
            };
            crate::hyperdht_messages::encode_mutable_put_request_to_bytes(&put_msg).unwrap()
        };

        let req = |put_bytes: Vec<u8>| IncomingHyperRequest {
            command: crate::hyperdht_messages::MUTABLE_PUT,
            target: Some(target),
            token: Some([0u8; 32]),
            value: Some(put_bytes),
            from: dummy_peer(),
            id: None,
        };

        // Store seq=5.
        p.on_mutable_put(&req(put_with_seq(5)));

        // Try seq=3 → TOO_LOW.
        assert!(matches!(
            p.on_mutable_put(&req(put_with_seq(3))),
            HandlerReply::Error(17)
        ));
    }

    #[test]
    fn mutable_put_seq_reused() {
        let mut p = make_persistent();
        let (pk, sk) = make_keypair();
        let target = hash(&pk);

        let put_with_seq = |seq: u64| {
            let signable = mutable_signable(&NS_MUTABLE_PUT, seq, b"v");
            let sig = crate::crypto::sign_detached(&signable, &sk);
            let put_msg = crate::hyperdht_messages::MutablePutRequest {
                public_key: pk,
                seq,
                value: b"v".to_vec(),
                signature: sig,
            };
            crate::hyperdht_messages::encode_mutable_put_request_to_bytes(&put_msg).unwrap()
        };

        let req = |put_bytes: Vec<u8>| IncomingHyperRequest {
            command: crate::hyperdht_messages::MUTABLE_PUT,
            target: Some(target),
            token: Some([0u8; 32]),
            value: Some(put_bytes),
            from: dummy_peer(),
            id: None,
        };

        p.on_mutable_put(&req(put_with_seq(5)));
        assert!(matches!(
            p.on_mutable_put(&req(put_with_seq(5))),
            HandlerReply::Value(None)
        ));
    }

    #[test]
    fn on_announce_invalid_signature_is_silent() {
        let mut p = make_persistent();
        let (pk, _sk) = make_keypair();
        let node_id = [0x00u8; 32];
        let target = hash(&pk);

        let peer = crate::hyperdht_messages::HyperPeer {
            public_key: pk,
            relay_addresses: vec![],
        };

        // Use a bad signature.
        let ann = crate::hyperdht_messages::AnnounceMessage {
            peer: Some(peer),
            refresh: None,
            signature: Some([0xffu8; 64]),
            bump: 0,
            lookup: false,
        };
        let ann_bytes = crate::hyperdht_messages::encode_announce_to_bytes(&ann).unwrap();

        let req = IncomingHyperRequest {
            command: crate::hyperdht_messages::ANNOUNCE,
            target: Some(target),
            token: Some([0u8; 32]),
            value: Some(ann_bytes),
            from: dummy_peer(),
            id: Some(node_id),
        };

        assert!(matches!(
            p.on_announce(&req, &node_id),
            HandlerReply::Silent
        ));
    }

    #[test]
    fn unannounce_for_other_key_keeps_router_record() {
        let mut persistent = make_persistent();
        let (owner, _) = make_keypair();
        let target = hash(&owner);
        persistent.set_local_record(&target, Some(b"local".to_vec()));

        let seed = [0x43u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&seed);
        secret[32..].copy_from_slice(&public_key);
        let peer = HyperPeer {
            public_key,
            relay_addresses: vec![],
        };
        let token = [7u8; 32];
        let peer_bytes = encode_hyper_peer_to_bytes(&peer).unwrap();
        let signature = crate::crypto::sign_detached(
            &ann_signable(
                &target,
                &token,
                &[0u8; 32],
                &peer_bytes,
                &[],
                &NS_UNANNOUNCE,
            ),
            &secret,
        );
        let value = crate::hyperdht_messages::encode_announce_to_bytes(
            &crate::hyperdht_messages::AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
                lookup: false,
            },
        )
        .unwrap();
        let request = IncomingHyperRequest {
            command: crate::hyperdht_messages::UNANNOUNCE,
            target: Some(target),
            token: Some(token),
            value: Some(value),
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(
            persistent.on_unannounce(&request, &[0u8; 32]),
            HandlerReply::ValueNoToken(None)
        ));
        let find = IncomingHyperRequest {
            command: crate::hyperdht_messages::FIND_PEER,
            target: Some(target),
            token: None,
            value: None,
            from: dummy_peer(),
            id: None,
        };
        assert!(matches!(
            persistent.on_find_peer(&find),
            HandlerReply::Value(Some(value)) if value == b"local"
        ));
    }

    // ── stats tests ───────────────────────────────────────────────────────────

    #[test]
    fn lru_cache_len_empty() {
        let cache = LruCache::new(100, Duration::from_secs(60));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn lru_cache_len_after_set() {
        let mut cache = LruCache::new(100, Duration::from_secs(60));
        cache.set("k1", b"v1".to_vec());
        cache.set("k2", b"v2".to_vec());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn record_cache_record_count() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        assert_eq!(cache.record_count(), 0);
        cache.add("topic1", [0x01u8; 32], b"r1".to_vec());
        cache.add("topic1", [0x02u8; 32], b"r2".to_vec());
        cache.add("topic2", [0x03u8; 32], b"r3".to_vec());
        assert_eq!(cache.record_count(), 3);
    }

    #[test]
    fn record_cache_topic_count() {
        let mut cache = RecordCache::new(100, Duration::from_secs(60), 20);
        assert_eq!(cache.topic_count(), 0);
        cache.add("topic1", [0x01u8; 32], b"r1".to_vec());
        cache.add("topic2", [0x02u8; 32], b"r2".to_vec());
        assert_eq!(cache.topic_count(), 2);
        cache.add("topic1", [0x03u8; 32], b"r3".to_vec());
        assert_eq!(cache.topic_count(), 2);
    }

    #[test]
    fn persistent_stats_empty() {
        let p = make_persistent();
        let s = p.stats();
        assert_eq!(s.records, 0);
        assert_eq!(s.record_topics, 0);
        assert_eq!(s.mutables, 0);
        assert_eq!(s.immutables, 0);
        assert_eq!(s.router_entries, 0);
    }

    #[test]
    fn persistent_stats_after_immutable_put() {
        let mut p = make_persistent();
        let data = b"stats test data".to_vec();
        let target = hash(&data);
        let req = IncomingHyperRequest {
            command: crate::hyperdht_messages::IMMUTABLE_PUT,
            target: Some(target),
            token: Some([0u8; 32]),
            value: Some(data),
            from: dummy_peer(),
            id: None,
        };
        p.on_immutable_put(&req);
        let s = p.stats();
        assert_eq!(s.immutables, 1);
    }
}
