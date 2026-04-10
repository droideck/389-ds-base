// This exposes C-FFI capable bindings for the concread concurrently readable cache.
use concread::arcache::stats::{ARCacheWriteStat, ReadCountStat};
use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn, ARCacheWriteTxn};
use concread::cowcell::CowCell;
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

type CacheCharInner = ARCache<CString, CString>;

const CACHE_CHAR_TEST_MODE_ENV: &str = "NSSLAPD_CACHE_CHAR_TEST_MODE";
const CACHE_CHAR_TEST_MODE_QUIESCE_THREAD: &str = "quiesce-thread";
const CACHE_CHAR_TEST_LOOKBACK_ENV: &str = "NSSLAPD_CACHE_CHAR_TEST_LOOKBACK";
const CACHE_CHAR_TEST_QUIESCE_US_ENV: &str = "NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US";
const CACHE_CHAR_TEST_READ_STATS_SAMPLE_N_ENV: &str = "NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N";
const CACHE_CHAR_TEST_DEFAULT_LOOKBACK: u8 = 8;
const CACHE_CHAR_TEST_MIN_LOOKBACK: u8 = 4;
const CACHE_CHAR_TEST_DEFAULT_QUIESCE_US: u64 = 1000;
const CACHE_CHAR_TEST_MIN_QUIESCE_US: u64 = 1;
const CACHE_CHAR_TEST_DEFAULT_READ_STATS_SAMPLE_N: u64 = 10;
const CACHE_CHAR_TEST_MIN_READ_STATS_SAMPLE_N: u64 = 1;
const CACHE_CHAR_TEST_QUIESCE_THREAD_NAME: &str = "cache-char-concread-quiesce";

#[derive(Clone, Debug, Default)]
struct CacheStats {
    reader_hits: u64,      // Hits from read transactions (main + local)
    reader_includes: u64,  // Number of includes from read transactions
    write_hits: u64,       // Hits from write transactions
    write_inc_or_mod: u64, // Number of includes/modifications from write transactions
    freq_evicts: u64,      // Number of evictions from frequent set
    recent_evicts: u64,    // Number of evictions from recent set
    p_weight: u64,         // Current cache weight between recent and frequent.
    shared_max: u64,       // Maximum number of items in the shared cache.
    freq: u64,             // Number of items in the frequent set at this point in time.
    recent: u64,           // Number of items in the recent set at this point in time.
    all_seen_keys: u64,    // Number of total keys seen through the cache's lifetime.
}

impl CacheStats {
    fn new() -> Self {
        CacheStats::default()
    }

    fn update_from_read_stat(&mut self, stat: ReadCountStat) {
        self.update_from_read_stat_scaled(stat, 1);
    }

    fn update_from_read_stat_scaled(&mut self, stat: ReadCountStat, scale: u64) {
        self.reader_hits += (stat.main_hit + stat.local_hit) * scale;
        self.reader_includes += (stat.include + stat.local_include) * scale;
    }

    fn update_from_write_stat(&mut self, stat: &FFIWriteStat) {
        self.write_hits += stat.read_hits;
        self.write_inc_or_mod += stat.includes + stat.modifications;
        self.freq_evicts += stat.freq_evictions;
        self.recent_evicts += stat.recent_evictions;
        self.p_weight = stat.p_weight;
        self.shared_max = stat.shared_max;
        self.freq = stat.freq;
        self.recent = stat.recent;
        self.all_seen_keys = stat.all_seen_keys;
    }
}

fn update_cache_write_stats(stats: &CowCell<CacheStats>, write_stats: &FFIWriteStat) {
    if write_stats.shared_max == 0 {
        return;
    }

    let mut stats_write = stats.write();
    stats_write.update_from_write_stat(write_stats);
    stats_write.commit();
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheCharQuiesceConfig {
    lookback: u8,
    quiesce_us: u64,
    read_stats_sample_n: u64,
}

impl Default for CacheCharQuiesceConfig {
    fn default() -> Self {
        Self {
            lookback: CACHE_CHAR_TEST_DEFAULT_LOOKBACK,
            quiesce_us: CACHE_CHAR_TEST_DEFAULT_QUIESCE_US,
            read_stats_sample_n: CACHE_CHAR_TEST_DEFAULT_READ_STATS_SAMPLE_N,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CacheCharConfig {
    Legacy,
    QuiesceThread(CacheCharQuiesceConfig),
}

impl CacheCharConfig {
    fn from_env() -> Self {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup<F>(mut lookup: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        match lookup(CACHE_CHAR_TEST_MODE_ENV) {
            Some(mode) if mode.trim() == CACHE_CHAR_TEST_MODE_QUIESCE_THREAD => {
                CacheCharConfig::QuiesceThread(CacheCharQuiesceConfig {
                    lookback: parse_u8_config(
                        lookup(CACHE_CHAR_TEST_LOOKBACK_ENV),
                        CACHE_CHAR_TEST_DEFAULT_LOOKBACK,
                        CACHE_CHAR_TEST_MIN_LOOKBACK,
                    ),
                    quiesce_us: parse_u64_config(
                        lookup(CACHE_CHAR_TEST_QUIESCE_US_ENV),
                        CACHE_CHAR_TEST_DEFAULT_QUIESCE_US,
                        CACHE_CHAR_TEST_MIN_QUIESCE_US,
                    ),
                    read_stats_sample_n: parse_u64_config(
                        lookup(CACHE_CHAR_TEST_READ_STATS_SAMPLE_N_ENV),
                        CACHE_CHAR_TEST_DEFAULT_READ_STATS_SAMPLE_N,
                        CACHE_CHAR_TEST_MIN_READ_STATS_SAMPLE_N,
                    ),
                })
            }
            _ => CacheCharConfig::Legacy,
        }
    }
}

fn parse_u8_config(raw: Option<String>, default: u8, min: u8) -> u8 {
    raw.as_deref()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .map(|value| value.max(min))
        .unwrap_or(default)
}

fn parse_u64_config(raw: Option<String>, default: u64, min: u64) -> u64 {
    raw.as_deref()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.max(min))
        .unwrap_or(default)
}

#[derive(Debug, Default)]
pub struct FFIWriteStat {
    pub read_ops: u64,
    pub read_hits: u64,
    pub p_weight: u64,
    pub shared_max: u64,
    pub freq: u64,
    pub recent: u64,
    pub all_seen_keys: u64,
    pub includes: u64,
    pub modifications: u64,
    pub freq_evictions: u64,
    pub recent_evictions: u64,
    pub ghost_freq_revives: u64,
    pub ghost_rec_revives: u64,
    pub haunted_includes: u64,
}

impl<K> ARCacheWriteStat<K> for FFIWriteStat {
    fn cache_clear(&mut self) {
        self.read_ops = 0;
        self.read_hits = 0;
    }

    fn cache_read(&mut self) {
        self.read_ops += 1;
    }

    fn cache_hit(&mut self) {
        self.read_hits += 1;
    }

    fn p_weight(&mut self, p: u64) {
        self.p_weight = p;
    }

    fn shared_max(&mut self, i: u64) {
        self.shared_max = i;
    }

    fn freq(&mut self, i: u64) {
        self.freq = i;
    }

    fn recent(&mut self, i: u64) {
        self.recent = i;
    }

    fn all_seen_keys(&mut self, i: u64) {
        self.all_seen_keys = i;
    }

    fn include(&mut self, _k: &K) {
        self.includes += 1;
    }

    fn include_haunted(&mut self, _k: &K) {
        self.haunted_includes += 1;
    }

    fn modify(&mut self, _k: &K) {
        self.modifications += 1;
    }

    fn ghost_frequent_revive(&mut self, _k: &K) {
        self.ghost_freq_revives += 1;
    }

    fn ghost_recent_revive(&mut self, _k: &K) {
        self.ghost_rec_revives += 1;
    }

    fn evict_from_recent(&mut self, _k: &K) {
        self.recent_evictions += 1;
    }

    fn evict_from_frequent(&mut self, _k: &K) {
        self.freq_evictions += 1;
    }
}

pub struct ARCacheChar {
    inner: Arc<CacheCharInner>,
    stats: Arc<CowCell<CacheStats>>,
    runtime: CacheCharRuntime,
}

pub struct ARCacheCharRead<'a> {
    inner: ARCacheCharReadInner<'a>,
    cache: &'a ARCacheChar,
}

pub struct ARCacheCharWrite<'a> {
    inner: ARCacheWriteTxn<'a, CString, CString, FFIWriteStat>,
    cache: &'a ARCacheChar,
}

enum ARCacheCharReadInner<'a> {
    Legacy(ARCacheReadTxn<'a, CString, CString, ReadCountStat>),
    Sampled {
        inner: ARCacheReadTxn<'a, CString, CString, ReadCountStat>,
        scale: u64,
    },
    Unsampled(ARCacheReadTxn<'a, CString, CString, ()>),
}

enum ARCacheCharReadFinish {
    Legacy(ReadCountStat),
    Sampled { stats: ReadCountStat, scale: u64 },
    Unsampled,
}

impl<'a> ARCacheCharReadInner<'a> {
    fn get(&mut self, key: &CString) -> Option<&CString> {
        match self {
            Self::Legacy(inner) => inner.get(key),
            Self::Sampled { inner, .. } => inner.get(key),
            Self::Unsampled(inner) => inner.get(key),
        }
    }

    fn insert(&mut self, key: CString, val: CString) {
        match self {
            Self::Legacy(inner) => inner.insert(key, val),
            Self::Sampled { inner, .. } => inner.insert(key, val),
            Self::Unsampled(inner) => inner.insert(key, val),
        }
    }

    fn finish(self) -> ARCacheCharReadFinish {
        match self {
            Self::Legacy(inner) => ARCacheCharReadFinish::Legacy(inner.finish()),
            Self::Sampled { inner, scale } => ARCacheCharReadFinish::Sampled {
                stats: inner.finish(),
                scale,
            },
            Self::Unsampled(inner) => {
                drop(inner);
                ARCacheCharReadFinish::Unsampled
            }
        }
    }
}

enum CacheCharRuntime {
    Legacy,
    QuiesceThread(CacheCharQuiesceRuntime),
}

struct CacheCharQuiesceRuntime {
    read_stats_sample_n: u64,
    read_stats_counter: AtomicU64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CacheCharQuiesceRuntime {
    fn should_sample_read_stats(&self) -> bool {
        if self.read_stats_sample_n == 1 {
            return true;
        }

        let next = self
            .read_stats_counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        next % self.read_stats_sample_n == 0
    }
}

impl ARCacheChar {
    fn new(max: usize, read_max: usize) -> Option<Self> {
        Self::new_with_config(max, read_max, CacheCharConfig::from_env())
    }

    fn new_with_config(max: usize, read_max: usize, config: CacheCharConfig) -> Option<Self> {
        match config {
            CacheCharConfig::Legacy => Self::new_legacy(max, read_max),
            CacheCharConfig::QuiesceThread(config) => {
                Self::new_quiesce_thread(max, read_max, config)
            }
        }
    }

    fn new_legacy(max: usize, read_max: usize) -> Option<Self> {
        Self::build_inner(max, read_max, None).map(|inner| Self {
            inner: Arc::new(inner),
            stats: Arc::new(CowCell::new(CacheStats::new())),
            runtime: CacheCharRuntime::Legacy,
        })
    }

    fn new_quiesce_thread(
        max: usize,
        read_max: usize,
        config: CacheCharQuiesceConfig,
    ) -> Option<Self> {
        let inner = Arc::new(Self::build_inner(max, read_max, Some(config.lookback))?);
        let stats = Arc::new(CowCell::new(CacheStats::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_inner = Arc::clone(&inner);
        let worker_stats = Arc::clone(&stats);
        let worker_stop = Arc::clone(&stop);
        let interval = Duration::from_micros(config.quiesce_us);
        let thread = thread::Builder::new()
            .name(CACHE_CHAR_TEST_QUIESCE_THREAD_NAME.to_string())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    thread::park_timeout(interval);
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let write_stats = worker_inner.try_quiesce_stats(FFIWriteStat::default());
                    update_cache_write_stats(&worker_stats, &write_stats);
                }
            })
            .ok()?;

        Some(Self {
            inner,
            stats,
            runtime: CacheCharRuntime::QuiesceThread(CacheCharQuiesceRuntime {
                read_stats_sample_n: config.read_stats_sample_n,
                read_stats_counter: AtomicU64::new(0),
                stop,
                thread: Some(thread),
            }),
        })
    }

    fn build_inner(max: usize, read_max: usize, lookback: Option<u8>) -> Option<CacheCharInner> {
        let mut builder = ARCacheBuilder::new()
            .set_size(max, read_max)
            .set_reader_quiesce(false);
        if let Some(lookback) = lookback {
            builder = builder.set_look_back_limit(lookback);
        }
        builder.build()
    }

    fn begin_read(&self) -> ARCacheCharReadInner<'_> {
        match &self.runtime {
            CacheCharRuntime::Legacy => {
                ARCacheCharReadInner::Legacy(self.inner.read_stats(ReadCountStat::default()))
            }
            CacheCharRuntime::QuiesceThread(runtime) if runtime.should_sample_read_stats() => {
                ARCacheCharReadInner::Sampled {
                    inner: self.inner.read_stats(ReadCountStat::default()),
                    scale: runtime.read_stats_sample_n,
                }
            }
            CacheCharRuntime::QuiesceThread(_) => {
                ARCacheCharReadInner::Unsampled(self.inner.read())
            }
        }
    }

    fn shutdown_quiesce_thread(&mut self) {
        if let CacheCharRuntime::QuiesceThread(runtime) = &mut self.runtime {
            runtime.stop.store(true, Ordering::Release);
            if let Some(thread) = runtime.thread.take() {
                thread.thread().unpark();
                let _ = thread.join();
            }

            let write_stats = self.inner.try_quiesce_stats(FFIWriteStat::default());
            update_cache_write_stats(&self.stats, &write_stats);
        }
    }
}

impl Drop for ARCacheChar {
    fn drop(&mut self) {
        self.shutdown_quiesce_thread();
    }
}

#[no_mangle]
pub extern "C" fn cache_char_create(max: usize, read_max: usize) -> *mut ARCacheChar {
    if let Some(cache) = ARCacheChar::new(max, read_max) {
        Box::into_raw(Box::new(cache))
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn cache_char_free(cache: *mut ARCacheChar) {
    debug_assert!(!cache.is_null());
    unsafe {
        drop(Box::from_raw(cache));
    }
}

#[no_mangle]
pub extern "C" fn cache_char_stats(
    cache: *mut ARCacheChar,
    reader_hits: &mut u64,
    reader_includes: &mut u64,
    write_hits: &mut u64,
    write_inc_or_mod: &mut u64,
    shared_max: &mut u64,
    freq: &mut u64,
    recent: &mut u64,
    freq_evicts: &mut u64,
    recent_evicts: &mut u64,
    p_weight: &mut u64,
    all_seen_keys: &mut u64,
) {
    let cache_ref = unsafe {
        debug_assert!(!cache.is_null());
        &(*cache)
    };

    // Get stats snapshot
    let stats_read = cache_ref.stats.read();
    *reader_hits = stats_read.reader_hits;
    *reader_includes = stats_read.reader_includes;
    *write_hits = stats_read.write_hits;
    *write_inc_or_mod = stats_read.write_inc_or_mod;
    *freq_evicts = stats_read.freq_evicts;
    *recent_evicts = stats_read.recent_evicts;
    *p_weight = stats_read.p_weight;
    *shared_max = stats_read.shared_max;
    *freq = stats_read.freq;
    *recent = stats_read.recent;
    *all_seen_keys = stats_read.all_seen_keys;
}

// start read
#[no_mangle]
pub extern "C" fn cache_char_read_begin(cache: *mut ARCacheChar) -> *mut ARCacheCharRead<'static> {
    let cache_ref = unsafe {
        debug_assert!(!cache.is_null());
        &(*cache) as &ARCacheChar
    };
    let read_txn = Box::new(ARCacheCharRead {
        inner: cache_ref.begin_read(),
        cache: cache_ref,
    });
    Box::into_raw(read_txn)
}

#[no_mangle]
pub extern "C" fn cache_char_read_complete(read_txn: *mut ARCacheCharRead) {
    debug_assert!(!read_txn.is_null());

    unsafe {
        let read_txn_box = Box::from_raw(read_txn);
        match read_txn_box.inner.finish() {
            ARCacheCharReadFinish::Legacy(read_stats) => {
                let write_stats = read_txn_box
                    .cache
                    .inner
                    .try_quiesce_stats(FFIWriteStat::default());

                let mut stats_write = read_txn_box.cache.stats.write();
                stats_write.update_from_read_stat(read_stats);
                stats_write.update_from_write_stat(&write_stats);
                stats_write.commit();
            }
            ARCacheCharReadFinish::Sampled { stats, scale } => {
                let mut stats_write = read_txn_box.cache.stats.write();
                stats_write.update_from_read_stat_scaled(stats, scale);
                stats_write.commit();
            }
            ARCacheCharReadFinish::Unsampled => {}
        }
    }
}

#[no_mangle]
pub extern "C" fn cache_char_read_get(
    read_txn: *mut ARCacheCharRead,
    key: *const c_char,
) -> *const c_char {
    let read_txn_ref = unsafe {
        debug_assert!(!read_txn.is_null());
        &mut (*read_txn) as &mut ARCacheCharRead
    };

    let key_ref = unsafe { CStr::from_ptr(key) };
    let key_dup = CString::from(key_ref);

    // Return a null pointer on miss.
    read_txn_ref
        .inner
        .get(&key_dup)
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null())
}

#[no_mangle]
pub extern "C" fn cache_char_read_include(
    read_txn: *mut ARCacheCharRead,
    key: *const c_char,
    val: *const c_char,
) {
    let read_txn_ref = unsafe {
        debug_assert!(!read_txn.is_null());
        &mut (*read_txn) as &mut ARCacheCharRead
    };

    let key_ref = unsafe { CStr::from_ptr(key) };
    let key_dup = CString::from(key_ref);

    let val_ref = unsafe { CStr::from_ptr(val) };
    let val_dup = CString::from(val_ref);
    read_txn_ref.inner.insert(key_dup, val_dup);
}

#[no_mangle]
pub extern "C" fn cache_char_write_begin(
    cache: *mut ARCacheChar,
) -> *mut ARCacheCharWrite<'static> {
    let cache_ref = unsafe {
        debug_assert!(!cache.is_null());
        &(*cache) as &ARCacheChar
    };
    let write_txn = Box::new(ARCacheCharWrite {
        inner: cache_ref.inner.write_stats(FFIWriteStat::default()),
        cache: cache_ref,
    });
    Box::into_raw(write_txn)
}

#[no_mangle]
pub extern "C" fn cache_char_write_commit(write_txn: *mut ARCacheCharWrite) {
    debug_assert!(!write_txn.is_null());
    unsafe {
        let write_txn_box = Box::from_raw(write_txn);
        let current_stats = write_txn_box.inner.commit();

        let mut stats_write = write_txn_box.cache.stats.write();
        stats_write.update_from_write_stat(&current_stats);
        stats_write.commit();
    }
}

#[no_mangle]
pub extern "C" fn cache_char_write_rollback(write_txn: *mut ARCacheCharWrite) {
    debug_assert!(!write_txn.is_null());
    unsafe {
        drop(Box::from_raw(write_txn));
    }
}

#[no_mangle]
pub extern "C" fn cache_char_write_include(
    write_txn: *mut ARCacheCharWrite,
    key: *const c_char,
    val: *const c_char,
) {
    let write_txn_ref = unsafe {
        debug_assert!(!write_txn.is_null());
        &mut (*write_txn) as &mut ARCacheCharWrite
    };

    let key_ref = unsafe { CStr::from_ptr(key) };
    let key_dup = CString::from(key_ref);

    let val_ref = unsafe { CStr::from_ptr(val) };
    let val_dup = CString::from(val_ref);
    write_txn_ref.inner.insert(key_dup, val_dup);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl FnMut(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    fn cache_char_quiesce_config(read_stats_sample_n: u64, quiesce_us: u64) -> CacheCharConfig {
        CacheCharConfig::QuiesceThread(CacheCharQuiesceConfig {
            lookback: CACHE_CHAR_TEST_DEFAULT_LOOKBACK,
            quiesce_us,
            read_stats_sample_n,
        })
    }

    fn cache_stats_snapshot(cache: &ARCacheChar) -> CacheStats {
        (*cache.stats.read()).clone()
    }

    #[test]
    fn test_cache_basic() {
        let cache_ptr = cache_char_create(1024, 8);
        let read_txn = cache_char_read_begin(cache_ptr);

        let k1 = CString::new("Hello").unwrap();
        let v1 = CString::new("Hello").unwrap();

        assert!(cache_char_read_get(read_txn, k1.as_ptr()).is_null());
        cache_char_read_include(read_txn, k1.as_ptr(), v1.as_ptr());
        assert!(!cache_char_read_get(read_txn, k1.as_ptr()).is_null());

        cache_char_read_complete(read_txn);
        cache_char_free(cache_ptr);
    }

    #[test]
    fn test_cache_stats() {
        let cache = cache_char_create(100, 8);

        // Variables to store stats
        let mut reader_hits = 0;
        let mut reader_includes = 0;
        let mut write_hits = 0;
        let mut write_inc_or_mod = 0;
        let mut shared_max = 0;
        let mut freq = 0;
        let mut recent = 0;
        let mut freq_evicts = 0;
        let mut recent_evicts = 0;
        let mut p_weight = 0;
        let mut all_seen_keys = 0;

        // Do some operations
        let key = CString::new("stats_test").unwrap();
        let value = CString::new("value").unwrap();

        let write_txn = cache_char_write_begin(cache);
        cache_char_write_include(write_txn, key.as_ptr(), value.as_ptr());
        cache_char_write_commit(write_txn);

        let read_txn = cache_char_read_begin(cache);
        let _ = cache_char_read_get(read_txn, key.as_ptr());
        cache_char_read_complete(read_txn);

        // Get stats
        cache_char_stats(
            cache,
            &mut reader_hits,
            &mut reader_includes,
            &mut write_hits,
            &mut write_inc_or_mod,
            &mut shared_max,
            &mut freq,
            &mut recent,
            &mut freq_evicts,
            &mut recent_evicts,
            &mut p_weight,
            &mut all_seen_keys,
        );

        // Verify that stats were updated
        assert!(write_inc_or_mod > 0);
        assert!(all_seen_keys > 0);

        cache_char_free(cache);
    }

    #[test]
    fn test_cache_read_write_operations() {
        let cache = cache_char_create(100, 8);

        // Create test data
        let key = CString::new("test_key").unwrap();
        let value = CString::new("test_value").unwrap();

        // Test write operation
        let write_txn = cache_char_write_begin(cache);
        cache_char_write_include(write_txn, key.as_ptr(), value.as_ptr());
        cache_char_write_commit(write_txn);

        // Test read operation
        let read_txn = cache_char_read_begin(cache);
        let result = cache_char_read_get(read_txn, key.as_ptr());
        assert!(!result.is_null());

        // Verify the value
        let retrieved_value = unsafe { CStr::from_ptr(result) };
        assert_eq!(retrieved_value.to_bytes(), value.as_bytes());

        cache_char_read_complete(read_txn);
        cache_char_free(cache);
    }

    #[test]
    fn test_cache_miss() {
        let cache = cache_char_create(100, 8);
        let read_txn = cache_char_read_begin(cache);

        let missing_key = CString::new("nonexistent").unwrap();
        let result = cache_char_read_get(read_txn, missing_key.as_ptr());
        assert!(result.is_null());

        cache_char_read_complete(read_txn);
        cache_char_free(cache);
    }

    #[test]
    fn test_write_rollback() {
        let cache = cache_char_create(100, 8);

        let key = CString::new("rollback_test").unwrap();
        let value = CString::new("value").unwrap();

        // Start write transaction and rollback
        let write_txn = cache_char_write_begin(cache);
        cache_char_write_include(write_txn, key.as_ptr(), value.as_ptr());
        cache_char_write_rollback(write_txn);

        // Verify key doesn't exist
        let read_txn = cache_char_read_begin(cache);
        let result = cache_char_read_get(read_txn, key.as_ptr());
        assert!(result.is_null());

        cache_char_read_complete(read_txn);
        cache_char_free(cache);
    }

    #[test]
    fn cache_char_quiesce_config_parsing() {
        assert_eq!(
            CacheCharConfig::from_lookup(|_| None),
            CacheCharConfig::Legacy
        );

        assert_eq!(
            CacheCharConfig::from_lookup(lookup_from(&[(CACHE_CHAR_TEST_MODE_ENV, "unknown",)])),
            CacheCharConfig::Legacy
        );

        assert_eq!(
            CacheCharConfig::from_lookup(lookup_from(&[(
                CACHE_CHAR_TEST_MODE_ENV,
                CACHE_CHAR_TEST_MODE_QUIESCE_THREAD,
            )])),
            CacheCharConfig::QuiesceThread(CacheCharQuiesceConfig::default())
        );

        assert_eq!(
            CacheCharConfig::from_lookup(lookup_from(&[
                (
                    CACHE_CHAR_TEST_MODE_ENV,
                    CACHE_CHAR_TEST_MODE_QUIESCE_THREAD,
                ),
                (CACHE_CHAR_TEST_LOOKBACK_ENV, "16"),
                (CACHE_CHAR_TEST_QUIESCE_US_ENV, "250"),
                (CACHE_CHAR_TEST_READ_STATS_SAMPLE_N_ENV, "2"),
            ])),
            CacheCharConfig::QuiesceThread(CacheCharQuiesceConfig {
                lookback: 16,
                quiesce_us: 250,
                read_stats_sample_n: 2,
            })
        );

        assert_eq!(
            CacheCharConfig::from_lookup(lookup_from(&[
                (
                    CACHE_CHAR_TEST_MODE_ENV,
                    CACHE_CHAR_TEST_MODE_QUIESCE_THREAD,
                ),
                (CACHE_CHAR_TEST_LOOKBACK_ENV, "1"),
                (CACHE_CHAR_TEST_QUIESCE_US_ENV, "0"),
                (CACHE_CHAR_TEST_READ_STATS_SAMPLE_N_ENV, "0"),
            ])),
            CacheCharConfig::QuiesceThread(CacheCharQuiesceConfig {
                lookback: CACHE_CHAR_TEST_MIN_LOOKBACK,
                quiesce_us: CACHE_CHAR_TEST_MIN_QUIESCE_US,
                read_stats_sample_n: CACHE_CHAR_TEST_MIN_READ_STATS_SAMPLE_N,
            })
        );
    }

    #[test]
    fn cache_char_quiesce_read_stats_sampling() {
        let mut cache = Box::new(
            ARCacheChar::new_with_config(100, 8, cache_char_quiesce_config(2, 60_000_000)).unwrap(),
        );
        let cache_ptr = cache.as_mut() as *mut ARCacheChar;
        let key = CString::new("sampling_key").unwrap();
        let value = CString::new("sampling_value").unwrap();

        let write_txn = cache_char_write_begin(cache_ptr);
        cache_char_write_include(write_txn, key.as_ptr(), value.as_ptr());
        cache_char_write_commit(write_txn);

        for _ in 0..2 {
            let read_txn = cache_char_read_begin(cache_ptr);
            assert!(!cache_char_read_get(read_txn, key.as_ptr()).is_null());
            cache_char_read_complete(read_txn);
        }

        let stats = cache_stats_snapshot(&cache);
        assert_eq!(stats.reader_hits, 2);
        assert_eq!(stats.reader_includes, 0);

        cache.shutdown_quiesce_thread();
    }

    #[test]
    fn cache_char_quiesce_shutdown_final_quiesce() {
        let mut cache = Box::new(
            ARCacheChar::new_with_config(100, 8, cache_char_quiesce_config(1, 60_000_000)).unwrap(),
        );
        let cache_ptr = cache.as_mut() as *mut ARCacheChar;
        let key = CString::new("shutdown_key").unwrap();
        let value = CString::new("shutdown_value").unwrap();

        let read_txn = cache_char_read_begin(cache_ptr);
        assert!(cache_char_read_get(read_txn, key.as_ptr()).is_null());
        cache_char_read_include(read_txn, key.as_ptr(), value.as_ptr());
        cache_char_read_complete(read_txn);

        let before_shutdown = cache_stats_snapshot(&cache);
        assert_eq!(before_shutdown.all_seen_keys, 0);
        assert_eq!(before_shutdown.write_inc_or_mod, 0);
        assert!(before_shutdown.reader_includes > 0);

        cache.shutdown_quiesce_thread();

        let after_shutdown = cache_stats_snapshot(&cache);
        assert!(after_shutdown.all_seen_keys > 0);
        assert!(after_shutdown.write_inc_or_mod > 0);
    }
}
