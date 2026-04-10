use std::cell::Cell;
use std::collections::VecDeque;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use hashbrown::{HashSet, HashTable};

use super::lock::CacheLock;
use super::{CacheStatsSnapshot, NUM_SHARDS};

#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("IdentityHasher only supports u64");
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

type IdentityBuildHasher = BuildHasherDefault<IdentityHasher>;

thread_local! {
    static STATS_SAMPLE_COUNTER: Cell<u64> = Cell::new(0);
}

pub(crate) struct S3Entry {
    key: Arc<[u8]>,
    value: Box<[u8]>,
    freq: AtomicU8,
}

fn bump_freq(freq: &AtomicU8) {
    let mut current = freq.load(Ordering::Relaxed);
    while current < 3 {
        match freq.compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

pub struct S3FifoShard {
    table: HashTable<Arc<S3Entry>>,
    small: VecDeque<(u64, Arc<[u8]>)>,
    main: VecDeque<(u64, Arc<[u8]>)>,
    ghost: VecDeque<u64>,
    ghost_set: HashSet<u64, IdentityBuildHasher>,
    small_cap: usize,
    main_cap: usize,
    ghost_cap: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl S3FifoShard {
    fn evict_small(&mut self) {
        let max_iters = self.small.len();
        for _ in 0..max_iters {
            let (hash, key) = match self.small.pop_front() {
                Some(t) => t,
                None => return,
            };

            let action = match self.table.find_entry(hash, |e| Arc::ptr_eq(&e.key, &key)) {
                Ok(occupied) => {
                    let freq = occupied.get().freq.load(Ordering::Relaxed);
                    if freq > 1 {
                        /* The counter restarts in M: evict_main() reads it as
                         * "hits since the entry entered M". */
                        occupied.get().freq.store(0, Ordering::Relaxed);
                        Some(true)
                    } else {
                        occupied.remove();
                        Some(false)
                    }
                }
                Err(_) => None,
            };

            match action {
                Some(true) => {
                    while self.main.len() >= self.main_cap {
                        self.evict_main();
                    }
                    self.main.push_back((hash, key));
                }
                Some(false) => {
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                    self.ghost_set.insert(hash);
                    self.ghost.push_back(hash);
                    while self.ghost.len() > self.ghost_cap {
                        if let Some(old) = self.ghost.pop_front() {
                            self.ghost_set.remove(&old);
                        }
                    }
                    return;
                }
                None => {
                    /* Queue nodes and table entries are created and removed
                     * together, so a popped node always resolves. */
                    debug_assert!(false, "small queue node without table entry");
                }
            }
        }
    }

    fn evict_main(&mut self) {
        loop {
            let (hash, key) = match self.main.pop_front() {
                Some(t) => t,
                None => return,
            };

            let action = match self.table.find_entry(hash, |e| Arc::ptr_eq(&e.key, &key)) {
                Ok(occupied) => {
                    let freq = occupied.get().freq.load(Ordering::Relaxed);
                    if freq > 0 {
                        occupied.get().freq.store(freq - 1, Ordering::Relaxed);
                        Some(true)
                    } else {
                        occupied.remove();
                        Some(false)
                    }
                }
                Err(_) => None,
            };

            match action {
                Some(true) => {
                    self.main.push_back((hash, key));
                }
                Some(false) => {
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                None => {
                    debug_assert!(false, "main queue node without table entry");
                    return;
                }
            }
        }
    }
}

#[repr(C, align(128))]
struct PaddedShard<L> {
    lock: L,
}

pub struct ShardedS3FifoCache<L: CacheLock<S3FifoShard>> {
    shards: Box<[PaddedShard<L>]>,
    hasher: ahash::RandomState,
    max_entries: usize,
    num_shards: usize,
    stats_sample_rate: u64,
}

impl<L: CacheLock<S3FifoShard>> ShardedS3FifoCache<L> {
    pub fn new(max_entries: usize) -> Self {
        Self::with_shards(max_entries, NUM_SHARDS)
    }

    pub fn with_stats_sample_rate(max_entries: usize, stats_sample_rate: u64) -> Self {
        Self::with_shards_and_stats_sample_rate(max_entries, NUM_SHARDS, stats_sample_rate)
    }

    pub fn with_shards(max_entries: usize, num_shards: usize) -> Self {
        Self::with_shards_and_stats_sample_rate(max_entries, num_shards, 1)
    }

    pub fn with_shards_and_stats_sample_rate(
        max_entries: usize,
        num_shards: usize,
        stats_sample_rate: u64,
    ) -> Self {
        assert!(
            num_shards.is_power_of_two(),
            "num_shards must be a power of 2"
        );
        assert!(
            num_shards >= 1 && num_shards <= 4096,
            "num_shards must be in [1, 4096]"
        );

        let per_shard = (max_entries + num_shards - 1) / num_shards;
        /* Both queues must hold at least one entry: eviction loops in put()
         * and evict_small() cannot make progress against a zero-capacity
         * main queue. */
        let per_shard = per_shard.max(2);
        let small_cap = (per_shard / 10).max(1);
        let main_cap = (per_shard - small_cap).max(1);
        let ghost_cap = main_cap;
        let hasher = ahash::RandomState::new();
        let stats_sample_rate = stats_sample_rate.max(1);

        let shards: Vec<PaddedShard<L>> = (0..num_shards)
            .map(|_| PaddedShard {
                lock: L::new(S3FifoShard {
                    table: HashTable::with_capacity(per_shard),
                    small: VecDeque::with_capacity(small_cap),
                    main: VecDeque::with_capacity(main_cap),
                    ghost: VecDeque::with_capacity(ghost_cap),
                    ghost_set: HashSet::with_capacity_and_hasher(
                        ghost_cap,
                        IdentityBuildHasher::default(),
                    ),
                    small_cap,
                    main_cap,
                    ghost_cap,
                    hits: AtomicU64::new(0),
                    misses: AtomicU64::new(0),
                    evictions: AtomicU64::new(0),
                }),
            })
            .collect();

        Self {
            shards: shards.into_boxed_slice(),
            hasher,
            max_entries,
            num_shards,
            stats_sample_rate,
        }
    }

    #[inline(always)]
    fn shard_idx(&self, hash: u64) -> usize {
        (hash as usize) & (self.num_shards - 1)
    }

    #[inline(always)]
    fn record_lookup_stat(&self, counter: &AtomicU64) {
        let sample_rate = self.stats_sample_rate;
        if sample_rate == 1 || Self::sample_this_lookup(sample_rate) {
            counter.fetch_add(sample_rate, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    fn sample_this_lookup(sample_rate: u64) -> bool {
        STATS_SAMPLE_COUNTER.with(|c| {
            let next = c.get().wrapping_add(1);
            if next >= sample_rate {
                c.set(0);
                true
            } else {
                c.set(next);
                false
            }
        })
    }

    pub fn get(&self, key: &[u8], buf: &mut [u8]) -> usize {
        let hash = self.hasher.hash_one(key);
        let shard = self.shards[self.shard_idx(hash)].lock.read();

        match shard.table.find(hash, |e| e.key.as_ref() == key) {
            Some(entry) => {
                let vlen = entry.value.len();
                if vlen <= buf.len() {
                    buf[..vlen].copy_from_slice(&entry.value);
                }
                bump_freq(&entry.freq);
                self.record_lookup_stat(&shard.hits);
                vlen
            }
            None => {
                self.record_lookup_stat(&shard.misses);
                0
            }
        }
    }

    pub fn put(&self, key: &[u8], value: &[u8]) {
        let hash = self.hasher.hash_one(key);
        let shard_idx = self.shard_idx(hash);

        let key_arc: Arc<[u8]> = Arc::from(key);
        let entry = Arc::new(S3Entry {
            key: Arc::clone(&key_arc),
            value: Box::from(value),
            freq: AtomicU8::new(0),
        });

        let mut shard = self.shards[shard_idx].lock.write();

        if shard.table.find(hash, |e| e.key.as_ref() == key).is_some() {
            return;
        }

        /* A removed hash may still occupy a ghost-queue slot; the stale copy
         * ages out when the queue is trimmed. */
        let goes_to_main = shard.ghost_set.remove(&hash);
        if goes_to_main {
            while shard.main.len() >= shard.main_cap {
                shard.evict_main();
            }
            shard.main.push_back((hash, key_arc));
        } else {
            while shard.small.len() >= shard.small_cap {
                shard.evict_small();
            }
            shard.small.push_back((hash, key_arc));
        }

        let h = &self.hasher;
        shard
            .table
            .insert_unique(hash, entry, |e| h.hash_one(e.key.as_ref()));
    }

    pub fn stats(&self) -> CacheStatsSnapshot {
        let (hits, misses, evictions, count) =
            self.shards
                .iter()
                .fold((0u64, 0u64, 0u64, 0usize), |(h, m, e, c), s| {
                    let g = s.lock.read();
                    (
                        h + g.hits.load(Ordering::Relaxed),
                        m + g.misses.load(Ordering::Relaxed),
                        e + g.evictions.load(Ordering::Relaxed),
                        c + g.table.len(),
                    )
                });
        CacheStatsSnapshot {
            hits,
            misses,
            evictions,
            count: count as u64,
            max_entries: self.max_entries as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndn_cache_v2::NUM_SHARDS;

    type PlCache = ShardedS3FifoCache<parking_lot::RwLock<S3FifoShard>>;

    fn make_cache(per_shard: usize) -> PlCache {
        ShardedS3FifoCache::new(per_shard * NUM_SHARDS)
    }

    fn shard_for(cache: &PlCache, key: &[u8]) -> usize {
        cache.shard_idx(cache.hasher.hash_one(key))
    }

    fn get_freq(cache: &PlCache, key: &[u8]) -> Option<u8> {
        let hash = cache.hasher.hash_one(key);
        let shard = cache.shards[cache.shard_idx(hash)].lock.read();
        shard
            .table
            .find(hash, |e| e.key.as_ref() == key)
            .map(|e| e.freq.load(Ordering::Relaxed))
    }

    #[test]
    fn freq_saturates_at_3() {
        let cache = make_cache(100);
        let key = b"saturate-test";
        let mut buf = [0u8; 256];

        cache.put(key, b"val");
        assert_eq!(get_freq(&cache, key), Some(0));

        for expected in [1, 2, 3, 3, 3] {
            cache.get(key, &mut buf);
            assert_eq!(get_freq(&cache, key), Some(expected));
        }

        for _ in 0..100 {
            cache.get(key, &mut buf);
        }
        assert_eq!(get_freq(&cache, key), Some(3));
    }

    #[test]
    fn promotion_requires_freq_gt_1() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        let target_shard = 0usize;
        let mut keys_in_shard: Vec<Vec<u8>> = Vec::new();
        for i in 0u64.. {
            let key = format!("promo-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                keys_in_shard.push(key);
                if keys_in_shard.len() > 20 {
                    break;
                }
            }
        }

        let freq1_key = &keys_in_shard[0];
        cache.put(freq1_key, b"v");
        cache.get(freq1_key, &mut buf);

        let freq2_key = &keys_in_shard[1];
        cache.put(freq2_key, b"v");
        cache.get(freq2_key, &mut buf);
        cache.get(freq2_key, &mut buf);

        for k in keys_in_shard[2..].iter() {
            cache.put(k, b"v");
        }

        assert!(
            cache.get(freq2_key, &mut buf) > 0,
            "freq=2 entry should have been promoted to M and survive"
        );
    }

    #[test]
    fn evict_m_reinserts_when_freq_gt_0() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        let target_shard = 0;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for i in 0u64.. {
            let key = format!("evictm-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                keys.push(key);
                if keys.len() > 50 {
                    break;
                }
            }
        }

        let kept_key = &keys[0];
        cache.put(kept_key, b"v");
        cache.get(kept_key, &mut buf);
        cache.get(kept_key, &mut buf);
        for k in keys[1..].iter() {
            cache.put(k, b"v");
        }

        assert!(cache.get(kept_key, &mut buf) > 0);
    }

    #[test]
    fn ghost_queue_sized_to_main() {
        let cache = make_cache(100);
        let shard = cache.shards[0].lock.read();
        assert_eq!(shard.ghost_cap, shard.main_cap);
        assert!(shard.ghost_cap > shard.small_cap);
    }

    #[test]
    fn ghost_hit_promotes_to_main_with_freq_0() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        let target_shard = 0;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for i in 0u64.. {
            let key = format!("ghost-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                keys.push(key);
                if keys.len() > 50 {
                    break;
                }
            }
        }

        let ghost_key = &keys[0];
        cache.put(ghost_key, b"v");

        for k in keys[1..].iter() {
            cache.put(k, b"v");
        }

        assert_eq!(cache.get(ghost_key, &mut buf), 0);

        let hash = cache.hasher.hash_one(ghost_key.as_slice());
        let shard = cache.shards[shard_for(&cache, ghost_key)].lock.read();
        let in_ghost = shard.ghost_set.contains(&hash);
        drop(shard);

        if !in_ghost {
            return;
        }

        cache.put(ghost_key, b"v");
        assert_eq!(get_freq(&cache, ghost_key), Some(0));

        let shard = cache.shards[shard_for(&cache, ghost_key)].lock.read();
        let in_main = shard
            .main
            .iter()
            .any(|(_, k)| k.as_ref() == ghost_key.as_slice());
        assert!(in_main, "ghost hit should route to main queue");
    }

    #[test]
    fn ghost_lookup_is_o1() {
        let cache = make_cache(10);
        let shard = cache.shards[0].lock.read();
        assert_eq!(shard.ghost_set.len(), 0);
    }

    #[test]
    fn evict_s_cascades() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        let target_shard = 0;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for i in 0u64.. {
            let key = format!("cascade-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                keys.push(key);
                if keys.len() > 50 {
                    break;
                }
            }
        }

        let shard = cache.shards[target_shard].lock.read();
        let small_cap = shard.small_cap;
        drop(shard);

        for k in keys.iter().take(small_cap) {
            cache.put(k, b"v");
            cache.get(k, &mut buf);
            cache.get(k, &mut buf);
        }

        let trigger_key = &keys[small_cap];
        cache.put(trigger_key, b"v");

        for k in keys.iter().take(small_cap) {
            assert!(
                cache.get(k, &mut buf) > 0,
                "freq=2 key should survive evictS cascade via promotion to M"
            );
        }
    }

    #[test]
    fn basic_get_put() {
        let cache: PlCache = ShardedS3FifoCache::new(1024);
        let mut buf = [0u8; 256];

        assert_eq!(cache.get(b"test", &mut buf), 0);
        cache.put(b"test", b"normalized");
        let len = cache.get(b"test", &mut buf);
        assert_eq!(&buf[..len], b"normalized");
    }

    #[test]
    fn scan_resistance() {
        let cache = make_cache(20);

        let target_shard = 0;
        let mut hot_keys: Vec<Vec<u8>> = Vec::new();
        let mut scan_keys: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 256];

        for i in 0u64.. {
            let key = format!("scanr-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                if hot_keys.len() < 10 {
                    hot_keys.push(key);
                } else if scan_keys.len() < 100 {
                    scan_keys.push(key);
                } else {
                    break;
                }
            }
        }

        for k in &hot_keys {
            cache.put(k, b"hot");
            cache.get(k, &mut buf);
            cache.get(k, &mut buf);
            cache.get(k, &mut buf);
        }

        for k in &scan_keys {
            cache.put(k, b"scan");
        }

        let survived = hot_keys
            .iter()
            .filter(|k| cache.get(k, &mut buf) > 0)
            .count();
        assert!(
            survived >= hot_keys.len() / 2,
            "scan resistance failed: only {}/{} hot keys survived a 100-key scan",
            survived,
            hot_keys.len()
        );
    }

    #[test]
    fn stats_sum_across_shards() {
        let cache = make_cache(100);
        let mut buf = [0u8; 256];

        let keys: Vec<Vec<u8>> = (0..200u64)
            .map(|i| format!("statskey-{:08}", i).into_bytes())
            .collect();
        for k in &keys {
            cache.put(k, b"v");
        }

        let hit_count = 50;
        for k in keys.iter().take(hit_count) {
            assert!(cache.get(k, &mut buf) > 0);
        }

        let miss_count = 30;
        for i in 0..miss_count {
            let k = format!("absent-{:08}", i).into_bytes();
            assert_eq!(cache.get(&k, &mut buf), 0);
        }

        let snap = cache.stats();
        assert_eq!(snap.hits, hit_count as u64, "hits should sum across shards");
        assert_eq!(
            snap.misses, miss_count as u64,
            "misses should sum across shards"
        );
        assert_eq!(snap.evictions, 0, "no evictions expected at this capacity");
        assert_eq!(
            snap.count,
            keys.len() as u64,
            "all inserted keys still resident"
        );
    }

    #[test]
    fn sampled_stats_scale_lookup_counts() {
        let cache: PlCache = ShardedS3FifoCache::with_stats_sample_rate(100 * NUM_SHARDS, 10);
        let mut buf = [0u8; 256];

        cache.put(b"sampled-hit", b"v");

        for _ in 0..20 {
            assert!(cache.get(b"sampled-hit", &mut buf) > 0);
        }
        for _ in 0..20 {
            assert_eq!(cache.get(b"sampled-miss", &mut buf), 0);
        }

        let snap = cache.stats();
        assert_eq!(snap.hits, 20);
        assert_eq!(snap.misses, 20);
    }

    #[test]
    fn promotion_resets_freq() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        let target_shard = 0usize;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for i in 0u64.. {
            let key = format!("promoreset-{:08}", i).into_bytes();
            if shard_for(&cache, &key) == target_shard {
                keys.push(key);
                if keys.len() > 2 {
                    break;
                }
            }
        }

        let promoted = &keys[0];
        cache.put(promoted, b"v");
        cache.get(promoted, &mut buf);
        cache.get(promoted, &mut buf);
        assert_eq!(get_freq(&cache, promoted), Some(2));

        cache.put(&keys[1], b"v");

        assert_eq!(
            get_freq(&cache, promoted),
            Some(0),
            "S->M promotion should reset the counter"
        );
        let hash = cache.hasher.hash_one(promoted.as_slice());
        let shard = cache.shards[target_shard].lock.read();
        assert!(
            shard.main.iter().any(|(h, _)| *h == hash),
            "promoted entry should be in the main queue"
        );
    }

    #[test]
    fn capacity_never_exceeded() {
        let cache = make_cache(10);
        let mut buf = [0u8; 256];

        for i in 0u64..5000 {
            let key = format!("churn-{:08}", i).into_bytes();
            cache.put(&key, b"v");
            for _ in 0..(i % 4) {
                cache.get(&key, &mut buf);
            }
            if i % 7 == 0 && i >= 100 {
                let old = format!("churn-{:08}", i - 100).into_bytes();
                cache.get(&old, &mut buf);
            }
        }

        for padded in cache.shards.iter() {
            let shard = padded.lock.read();
            assert!(shard.small.len() <= shard.small_cap);
            assert!(shard.main.len() <= shard.main_cap);
            assert!(shard.ghost.len() <= shard.ghost_cap);
            // A ghost hit removes the hash from the set but leaves a stale
            // queue copy behind, so the set can only be the smaller side.
            assert!(shard.ghost_set.len() <= shard.ghost.len());
            assert!(shard.table.len() <= shard.small_cap + shard.main_cap);
            assert_eq!(shard.table.len(), shard.small.len() + shard.main.len());
        }

        let snap = cache.stats();
        assert!(snap.count <= (10 * NUM_SHARDS) as u64);
    }

    #[test]
    fn tiny_cache_does_not_hang() {
        // One shard with the minimum clamped layout: small_cap=1, main_cap=1.
        let cache: PlCache = ShardedS3FifoCache::with_shards(2, 1);
        let mut buf = [0u8; 256];

        cache.put(b"a", b"v");
        cache.get(b"a", &mut buf);
        cache.get(b"a", &mut buf);
        cache.put(b"b", b"v"); // promotes "a" to M
        cache.put(b"c", b"v"); // demotes "b" to ghost
        cache.put(b"b", b"v"); // ghost hit: insert to a full M
        assert!(cache.get(b"b", &mut buf) > 0);

        // max_entries below the shard count exercises the per-shard clamp.
        let cache: PlCache = ShardedS3FifoCache::new(1);
        for i in 0u64..500 {
            let key = format!("tiny-{:08}", i).into_bytes();
            cache.put(&key, b"v");
            cache.get(&key, &mut buf);
            cache.get(&key, &mut buf);
            cache.put(&key, b"v");
            if i >= 10 {
                let old = format!("tiny-{:08}", i - 10).into_bytes();
                cache.put(&old, b"v"); // likely ghost hit on a tiny shard
            }
        }

        for padded in cache.shards.iter() {
            let shard = padded.lock.read();
            assert!(shard.table.len() <= shard.small_cap + shard.main_cap);
        }
    }

    #[test]
    fn concurrent_miss_storm() {
        let cache = make_cache(10);
        let key_space = 10 * NUM_SHARDS * 10; // 10x total capacity

        std::thread::scope(|scope| {
            for t in 0..8usize {
                let cache = &cache;
                scope.spawn(move || {
                    let mut buf = [0u8; 256];
                    for i in 0..key_space {
                        let idx = (i + t * 17) % key_space;
                        let key = format!("storm-{:08}", idx).into_bytes();
                        if cache.get(&key, &mut buf) == 0 {
                            cache.put(&key, b"v");
                        }
                    }
                });
            }
        });

        for padded in cache.shards.iter() {
            let shard = padded.lock.read();
            assert!(shard.small.len() <= shard.small_cap);
            assert!(shard.main.len() <= shard.main_cap);
            assert!(shard.table.len() <= shard.small_cap + shard.main_cap);
        }
        let snap = cache.stats();
        assert!(snap.hits + snap.misses > 0);
    }
}
