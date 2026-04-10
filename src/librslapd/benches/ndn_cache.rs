use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_distr::Zipf;
use std::cell::Cell;
use std::env;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::Duration;

use concread::arcache::stats::ReadCountStat;
use concread::cowcell::CowCell;
use rslapd::cache::{ARCacheChar, FFIWriteStat};
use rslapd::ndn_cache_v2::dn_gen;
use rslapd::ndn_cache_v2::s3fifo::{S3FifoShard, ShardedS3FifoCache};

const CACHE_SIZE: usize = 100_000;
const WARMUP_OPS: usize = 200_000;
const CORPUS_SIZE: usize = 500_000;
const SWEEP_CORPUS_SIZE: usize = 1_000_000;
const OPS_PER_THREAD: usize = 5_000;
const SCAN_WINDOW: usize = 2_000;
const SCAN_INTERVAL: usize = 500;
const THREAD_COUNTS: &[usize] = &[1, 4, 16, 32, 64];
const CACHE_CAPACITY_SWEEP: &[usize] = &[1_000, 6_241, 20_000, 100_000, 124_830, 500_000];
const CACHE_SIZE_SWEEP_THREADS: &[usize] = &[1, 16, 64];
const DEFAULT_VARIANTS: &[BenchVariant] = &[
    BenchVariant::Concread,
    BenchVariant::ConcreadDirect,
    BenchVariant::S3Fifo,
];
const DEFAULT_SAMPLE_SIZE: usize = 30;
const DEFAULT_MEASUREMENT_SECS: u64 = 20;
const DEFAULT_WARMUP_SECS: u64 = 5;
const DEFAULT_CONCREAD_TUNED_LOOKBACK: u8 = 8;
const DEFAULT_CONCREAD_QUIESCE_US: u64 = 1_000;
const DEFAULT_CONCREAD_READ_STATS_SAMPLE_N: u64 = 10;

thread_local! {
    static CONCREAD_READ_STATS_SAMPLE_COUNTER: Cell<u64> = Cell::new(0);
}

#[derive(Clone, Copy, Debug)]
enum BenchVariant {
    Concread,
    ConcreadDirect,
    ConcreadDirectTuned,
    ConcreadDirectTunedStats,
    S3Fifo,
    S3FifoSampled10,
}

impl BenchVariant {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "concread" => Some(Self::Concread),
            "concread-direct" => Some(Self::ConcreadDirect),
            "concread-direct-tuned" => Some(Self::ConcreadDirectTuned),
            "concread-direct-tuned-stats" => Some(Self::ConcreadDirectTunedStats),
            "s3fifo" => Some(Self::S3Fifo),
            "s3fifo-sampled10" => Some(Self::S3FifoSampled10),
            _ => None,
        }
    }
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    let value = match env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{} must be a positive integer", name)),
        Err(_) => default,
    };
    assert!(value > 0, "{} must be greater than zero", name);
    value
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    let value = match env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{} must be a positive integer", name)),
        Err(_) => default,
    };
    assert!(value > 0, "{} must be greater than zero", name);
    value
}

fn parse_u8_env(name: &str, default: u8, min: u8) -> u8 {
    let value = parse_u64_env(name, default as u64);
    assert!(
        value >= min as u64 && value <= u8::MAX as u64,
        "{} must be in [{}, {}]",
        name,
        min,
        u8::MAX
    );
    value as u8
}

fn parse_usize_list_env(name: &str, default: &[usize]) -> Vec<usize> {
    match env::var(name) {
        Ok(value) => {
            let values: Vec<usize> = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| {
                    v.parse()
                        .unwrap_or_else(|_| panic!("{} contains non-integer value {:?}", name, v))
                })
                .collect();
            assert!(!values.is_empty(), "{} must not be empty", name);
            assert!(
                values.iter().all(|v| *v > 0),
                "{} values must be greater than zero",
                name
            );
            values
        }
        Err(_) => default.to_vec(),
    }
}

fn selected_thread_counts() -> Vec<usize> {
    parse_usize_list_env("NDN_RS_BENCH_THREADS", THREAD_COUNTS)
}

fn selected_capacity_sweep_threads() -> Vec<usize> {
    parse_usize_list_env("NDN_RS_BENCH_THREADS", CACHE_SIZE_SWEEP_THREADS)
}

fn selected_capacities() -> Vec<usize> {
    parse_usize_list_env("NDN_RS_BENCH_CAPACITIES", CACHE_CAPACITY_SWEEP)
}

fn selected_variants() -> Vec<BenchVariant> {
    match env::var("NDN_RS_BENCH_VARIANTS") {
        Ok(value) => {
            let variants: Vec<BenchVariant> = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| {
                    BenchVariant::parse(v)
                        .unwrap_or_else(|| panic!("unknown NDN_RS_BENCH_VARIANTS value {:?}", v))
                })
                .collect();
            assert!(
                !variants.is_empty(),
                "NDN_RS_BENCH_VARIANTS must not be empty"
            );
            variants
        }
        Err(_) => DEFAULT_VARIANTS.to_vec(),
    }
}

fn concread_tuned_lookback() -> u8 {
    parse_u8_env(
        "NDN_RS_BENCH_CONCREAD_TUNED_LOOKBACK",
        DEFAULT_CONCREAD_TUNED_LOOKBACK,
        4,
    )
}

fn concread_quiesce_interval() -> Duration {
    Duration::from_micros(parse_u64_env(
        "NDN_RS_BENCH_CONCREAD_QUIESCE_US",
        DEFAULT_CONCREAD_QUIESCE_US,
    ))
}

fn concread_read_stats_sample_rate() -> u64 {
    parse_u64_env(
        "NDN_RS_BENCH_CONCREAD_READ_STATS_SAMPLE_N",
        DEFAULT_CONCREAD_READ_STATS_SAMPLE_N,
    )
}

fn sample_concread_read_stats(sample_rate: u64) -> bool {
    if sample_rate == 1 {
        return true;
    }

    CONCREAD_READ_STATS_SAMPLE_COUNTER.with(|c| {
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

fn criterion_config() -> Criterion {
    let sample_size = parse_usize_env("NDN_RS_BENCH_SAMPLE_SIZE", DEFAULT_SAMPLE_SIZE);
    assert!(
        sample_size >= 10,
        "NDN_RS_BENCH_SAMPLE_SIZE must be at least 10"
    );

    Criterion::default()
        .sample_size(sample_size)
        .measurement_time(Duration::from_secs(parse_u64_env(
            "NDN_RS_BENCH_MEASUREMENT_SECS",
            DEFAULT_MEASUREMENT_SECS,
        )))
        .warm_up_time(Duration::from_secs(parse_u64_env(
            "NDN_RS_BENCH_WARMUP_SECS",
            DEFAULT_WARMUP_SECS,
        )))
}

trait BenchCache: Send + Sync {
    fn get(&self, key: &[u8], buf: &mut [u8]) -> usize;
    fn put(&self, key: &[u8], value: &[u8]);
    fn name(&self) -> &'static str;
}

type S3Cache = ShardedS3FifoCache<parking_lot::RwLock<S3FifoShard>>;
type ConcreadDirectCache = concread::arcache::ARCache<CString, CString>;

#[derive(Clone, Debug, Default)]
struct ConcreadBenchStats {
    reader_hits: u64,
    reader_includes: u64,
    write_hits: u64,
    write_inc_or_mod: u64,
    freq_evicts: u64,
    recent_evicts: u64,
    p_weight: u64,
    shared_max: u64,
    freq: u64,
    recent: u64,
    all_seen_keys: u64,
}

impl ConcreadBenchStats {
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

    fn checksum(&self) -> u64 {
        self.reader_hits
            .wrapping_add(self.reader_includes)
            .wrapping_add(self.write_hits)
            .wrapping_add(self.write_inc_or_mod)
            .wrapping_add(self.freq_evicts)
            .wrapping_add(self.recent_evicts)
            .wrapping_add(self.p_weight)
            .wrapping_add(self.shared_max)
            .wrapping_add(self.freq)
            .wrapping_add(self.recent)
            .wrapping_add(self.all_seen_keys)
    }
}

fn update_concread_write_stats(stats: &CowCell<ConcreadBenchStats>, write_stats: &FFIWriteStat) {
    let mut stats_write = stats.write();
    stats_write.update_from_write_stat(write_stats);
    stats_write.commit();
}

struct S3CacheWrapper {
    inner: S3Cache,
    name: &'static str,
}

impl S3CacheWrapper {
    fn sampled10(max: usize) -> Self {
        Self {
            inner: S3Cache::with_stats_sample_rate(max, 10),
            name: "s3fifo-sampled10",
        }
    }
}

impl BenchCache for S3Cache {
    fn get(&self, key: &[u8], buf: &mut [u8]) -> usize {
        ShardedS3FifoCache::get(self, key, buf)
    }
    fn put(&self, key: &[u8], value: &[u8]) {
        ShardedS3FifoCache::put(self, key, value)
    }
    fn name(&self) -> &'static str {
        "s3fifo"
    }
}

impl BenchCache for S3CacheWrapper {
    fn get(&self, key: &[u8], buf: &mut [u8]) -> usize {
        self.inner.get(key, buf)
    }
    fn put(&self, key: &[u8], value: &[u8]) {
        self.inner.put(key, value)
    }
    fn name(&self) -> &'static str {
        self.name
    }
}

struct ConcreadWrapper {
    ptr: *mut ARCacheChar,
}

unsafe impl Send for ConcreadWrapper {}
unsafe impl Sync for ConcreadWrapper {}

impl ConcreadWrapper {
    fn new(max: usize) -> Self {
        let ptr = rslapd::cache::cache_char_create(max, 0);
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl Drop for ConcreadWrapper {
    fn drop(&mut self) {
        rslapd::cache::cache_char_free(self.ptr);
    }
}

impl BenchCache for ConcreadWrapper {
    fn get(&self, key: &[u8], _buf: &mut [u8]) -> usize {
        let key_cstr = CString::new(key).unwrap();
        let read_txn = rslapd::cache::cache_char_read_begin(self.ptr);
        let result = rslapd::cache::cache_char_read_get(read_txn, key_cstr.as_ptr());
        let found = if result.is_null() {
            0
        } else {
            let val = unsafe { CStr::from_ptr(result) };
            val.to_bytes().len()
        };
        rslapd::cache::cache_char_read_complete(read_txn);
        found
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        let key_cstr = CString::new(key).unwrap();
        let val_cstr = CString::new(value).unwrap();
        let read_txn = rslapd::cache::cache_char_read_begin(self.ptr);
        rslapd::cache::cache_char_read_include(read_txn, key_cstr.as_ptr(), val_cstr.as_ptr());
        rslapd::cache::cache_char_read_complete(read_txn);
    }

    fn name(&self) -> &'static str {
        "concread"
    }
}

struct ConcreadDirectWrapper {
    inner: Arc<ConcreadDirectCache>,
    name: &'static str,
    stats: Option<Arc<CowCell<ConcreadBenchStats>>>,
    read_stats_sample_rate: u64,
    quiesce_stop: Option<Arc<AtomicBool>>,
    quiesce_thread: Option<JoinHandle<()>>,
}

impl ConcreadDirectWrapper {
    fn new(max: usize) -> Self {
        Self::configured(max, "concread-direct", true, None, None, None)
    }

    fn tuned(max: usize) -> Self {
        Self::configured(
            max,
            "concread-direct-tuned",
            false,
            Some(concread_tuned_lookback()),
            Some(concread_quiesce_interval()),
            None,
        )
    }

    fn tuned_stats(max: usize) -> Self {
        Self::configured(
            max,
            "concread-direct-tuned-stats",
            false,
            Some(concread_tuned_lookback()),
            Some(concread_quiesce_interval()),
            Some(concread_read_stats_sample_rate()),
        )
    }

    fn configured(
        max: usize,
        name: &'static str,
        reader_quiesce: bool,
        look_back_limit: Option<u8>,
        quiesce_interval: Option<Duration>,
        read_stats_sample_rate: Option<u64>,
    ) -> Self {
        let mut builder = concread::arcache::ARCacheBuilder::new()
            .set_size(max, 0)
            .set_reader_quiesce(reader_quiesce);
        if let Some(limit) = look_back_limit {
            builder = builder.set_look_back_limit(limit);
        }

        let inner = Arc::new(builder.build().expect("failed to build ARCache"));
        let stats =
            read_stats_sample_rate.map(|_| Arc::new(CowCell::new(ConcreadBenchStats::default())));
        let (quiesce_stop, quiesce_thread) = if let Some(interval) = quiesce_interval {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker_cache = Arc::clone(&inner);
            let worker_stats = stats.clone();
            let handle = std::thread::Builder::new()
                .name("ndn-cache-concread-quiesce".to_string())
                .spawn(move || {
                    while !worker_stop.load(Ordering::Acquire) {
                        std::thread::sleep(interval);
                        if let Some(stats) = &worker_stats {
                            let write_stats =
                                worker_cache.try_quiesce_stats(FFIWriteStat::default());
                            update_concread_write_stats(stats, &write_stats);
                        } else {
                            worker_cache.try_quiesce();
                        }
                    }

                    if let Some(stats) = &worker_stats {
                        let write_stats = worker_cache.try_quiesce_stats(FFIWriteStat::default());
                        update_concread_write_stats(stats, &write_stats);
                    } else {
                        worker_cache.try_quiesce();
                    }
                })
                .expect("failed to spawn concread quiesce thread");
            (Some(stop), Some(handle))
        } else {
            (None, None)
        };

        Self {
            inner,
            name,
            stats,
            read_stats_sample_rate: read_stats_sample_rate.unwrap_or(1),
            quiesce_stop,
            quiesce_thread,
        }
    }

    fn update_read_stats(&self, read_stats: ReadCountStat) {
        if let Some(stats) = &self.stats {
            let mut stats_write = stats.write();
            stats_write.update_from_read_stat_scaled(read_stats, self.read_stats_sample_rate);
            stats_write.commit();
        }
    }
}

impl Drop for ConcreadDirectWrapper {
    fn drop(&mut self) {
        if let Some(stop) = &self.quiesce_stop {
            stop.store(true, Ordering::Release);
        }
        if let Some(handle) = self.quiesce_thread.take() {
            handle.join().expect("concread quiesce thread panicked");
        }
        if let Some(stats) = &self.stats {
            black_box(stats.read().checksum());
        }
    }
}

impl BenchCache for ConcreadDirectWrapper {
    fn get(&self, key: &[u8], _buf: &mut [u8]) -> usize {
        let key_cstr = CString::new(key).unwrap();
        if self.stats.is_some() && sample_concread_read_stats(self.read_stats_sample_rate) {
            let mut read_txn = self.inner.read_stats(ReadCountStat::default());
            let found = match read_txn.get(&key_cstr) {
                Some(v) => v.to_bytes().len(),
                None => 0,
            };
            let read_stats = read_txn.finish();
            self.update_read_stats(read_stats);
            found
        } else {
            let mut read_txn = self.inner.read();
            match read_txn.get(&key_cstr) {
                Some(v) => v.to_bytes().len(),
                None => 0,
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        let key_cstr = CString::new(key).unwrap();
        let val_cstr = CString::new(value).unwrap();
        if self.stats.is_some() && sample_concread_read_stats(self.read_stats_sample_rate) {
            let mut read_txn = self.inner.read_stats(ReadCountStat::default());
            read_txn.insert(key_cstr, val_cstr);
            let read_stats = read_txn.finish();
            self.update_read_stats(read_stats);
        } else {
            let mut read_txn = self.inner.read();
            read_txn.insert(key_cstr, val_cstr);
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

struct Corpus {
    keys: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
}

impl Corpus {
    fn new(n: usize, seed: u64) -> Self {
        let pairs = dn_gen::generate_corpus(n, seed);
        let (keys, values): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        Self { keys, values }
    }
}

fn make_caches(max_entries: usize) -> Vec<Box<dyn BenchCache>> {
    selected_variants()
        .into_iter()
        .map(|variant| match variant {
            BenchVariant::Concread => {
                Box::new(ConcreadWrapper::new(max_entries)) as Box<dyn BenchCache>
            }
            BenchVariant::ConcreadDirect => Box::new(ConcreadDirectWrapper::new(max_entries)),
            BenchVariant::ConcreadDirectTuned => {
                Box::new(ConcreadDirectWrapper::tuned(max_entries))
            }
            BenchVariant::ConcreadDirectTunedStats => {
                Box::new(ConcreadDirectWrapper::tuned_stats(max_entries))
            }
            BenchVariant::S3Fifo => Box::new(S3Cache::new(max_entries)),
            BenchVariant::S3FifoSampled10 => Box::new(S3CacheWrapper::sampled10(max_entries)),
        })
        .collect()
}

fn generate_zipf_pattern(n_corpus: usize, n_ops: usize, alpha: f64, seed: u64) -> Vec<usize> {
    use rand::Rng;
    let mut rng = StdRng::seed_from_u64(seed);
    let dist = Zipf::new(n_corpus as u64, alpha).unwrap();
    (0..n_ops)
        .map(|_| {
            let sample: f64 = rng.sample(dist);
            (sample as usize).saturating_sub(1).min(n_corpus - 1)
        })
        .collect()
}

fn generate_scan_pattern(n_corpus: usize, n_ops: usize, seed: u64) -> (Vec<usize>, Vec<usize>) {
    use rand::Rng;
    let mut rng = StdRng::seed_from_u64(seed);
    let dist = Zipf::new(n_corpus as u64, 1.0).unwrap();

    let indices: Vec<usize> = (0..n_ops)
        .map(|_| {
            let s: f64 = rng.sample(dist);
            (s as usize).saturating_sub(1).min(n_corpus - 1)
        })
        .collect();

    let n_scans = n_ops / SCAN_INTERVAL;
    let scan_starts: Vec<usize> = (0..n_scans)
        .map(|_| rng.gen_range(0..n_corpus.saturating_sub(SCAN_WINDOW)))
        .collect();

    (indices, scan_starts)
}

fn generate_unique_keys(n: usize, seed: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    dn_gen::generate_corpus(n, seed + 0xDEAD)
}

fn warmup(cache: &dyn BenchCache, corpus: &Corpus, alpha: f64) {
    let pattern = generate_zipf_pattern(corpus.keys.len(), WARMUP_OPS, alpha, 99999);
    let mut buf = vec![0u8; 512];
    for &idx in &pattern {
        let key = &corpus.keys[idx];
        if cache.get(key, &mut buf) == 0 {
            cache.put(key, &corpus.values[idx]);
        }
    }
}

fn run_zipf_workload(
    cache: &Arc<dyn BenchCache>,
    corpus: &Arc<Corpus>,
    patterns: &Arc<Vec<Vec<usize>>>,
    n_threads: usize,
) -> u64 {
    let barrier = Arc::new(Barrier::new(n_threads));

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let c = Arc::clone(cache);
            let corp = Arc::clone(corpus);
            let b = Arc::clone(&barrier);
            let pattern = patterns[tid].clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 512];
                b.wait();
                for &idx in &pattern {
                    let key = &corp.keys[idx];
                    let len = c.get(key, &mut buf);
                    if len == 0 {
                        c.put(key, &corp.values[idx]);
                    }
                    black_box(len);
                }
                pattern.len() as u64
            })
        })
        .collect();

    handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .sum()
}

fn run_scan_workload(
    cache: &Arc<dyn BenchCache>,
    corpus: &Arc<Corpus>,
    patterns: &Arc<Vec<(Vec<usize>, Vec<usize>)>>,
    n_threads: usize,
) -> u64 {
    let barrier = Arc::new(Barrier::new(n_threads));

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let c = Arc::clone(cache);
            let corp = Arc::clone(corpus);
            let b = Arc::clone(&barrier);
            let (ref zipf_idx, ref scan_starts) = patterns[tid];
            let zipf_idx = zipf_idx.clone();
            let scan_starts = scan_starts.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 512];
                let mut total_ops: u64 = 0;
                let n_corpus = corp.keys.len();
                b.wait();

                for (op_i, &idx) in zipf_idx.iter().enumerate() {
                    if op_i > 0 && op_i % SCAN_INTERVAL == 0 {
                        let scan_i = op_i / SCAN_INTERVAL - 1;
                        if scan_i < scan_starts.len() {
                            let start = scan_starts[scan_i];
                            let end = (start + SCAN_WINDOW).min(n_corpus);
                            for s in start..end {
                                let key = &corp.keys[s];
                                let len = c.get(key, &mut buf);
                                if len == 0 {
                                    c.put(key, &corp.values[s]);
                                }
                                black_box(len);
                                total_ops += 1;
                            }
                        }
                    }

                    let key = &corp.keys[idx];
                    let len = c.get(key, &mut buf);
                    if len == 0 {
                        c.put(key, &corp.values[idx]);
                    }
                    black_box(len);
                    total_ops += 1;
                }
                total_ops
            })
        })
        .collect();

    handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .sum()
}

fn run_write_heavy_workload(
    cache: &Arc<dyn BenchCache>,
    corpus: &Arc<Corpus>,
    zipf_patterns: &Arc<Vec<Vec<usize>>>,
    unique_keys: &Arc<Vec<(Vec<u8>, Vec<u8>)>>,
    n_threads: usize,
) -> u64 {
    let barrier = Arc::new(Barrier::new(n_threads));
    let unique_offset = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let c = Arc::clone(cache);
            let corp = Arc::clone(corpus);
            let b = Arc::clone(&barrier);
            let pattern = zipf_patterns[tid].clone();
            let ukeys = Arc::clone(unique_keys);
            let uoff = Arc::clone(&unique_offset);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 512];
                let mut total_ops: u64 = 0;
                let mut rng_state: u64 = 77777 + tid as u64 * 333;
                let mut zipf_cursor: usize = 0;
                b.wait();

                for _ in 0..OPS_PER_THREAD {
                    rng_state ^= rng_state << 13;
                    rng_state ^= rng_state >> 7;
                    rng_state ^= rng_state << 17;

                    if (rng_state % 100) < 40 {
                        let ui = uoff.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let ui = ui % ukeys.len();
                        let (ref k, ref v) = ukeys[ui];
                        c.put(k, v);
                        black_box(0usize);
                    } else {
                        let idx = pattern[zipf_cursor % pattern.len()];
                        zipf_cursor += 1;
                        let key = &corp.keys[idx];
                        let len = c.get(key, &mut buf);
                        if len == 0 {
                            c.put(key, &corp.values[idx]);
                        }
                        black_box(len);
                    }
                    total_ops += 1;
                }
                total_ops
            })
        })
        .collect();

    handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .sum()
}

fn bench_zipf(c: &mut Criterion, alpha: f64) {
    let group_name = format!("zipf_{}", alpha.to_string().replace('.', "_"));
    let mut group = c.benchmark_group(&group_name);

    let corpus = Arc::new(Corpus::new(CORPUS_SIZE, 42));

    for n_threads in selected_thread_counts() {
        let patterns: Arc<Vec<Vec<usize>>> = Arc::new(
            (0..n_threads)
                .map(|tid| {
                    generate_zipf_pattern(
                        corpus.keys.len(),
                        OPS_PER_THREAD,
                        alpha,
                        1000 + tid as u64,
                    )
                })
                .collect(),
        );

        let total_ops = (OPS_PER_THREAD * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for cache_box in make_caches(CACHE_SIZE) {
            let cache_name = cache_box.name();
            warmup(cache_box.as_ref(), &corpus, alpha);
            let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

            group.bench_with_input(
                BenchmarkId::new(cache_name, n_threads),
                &n_threads,
                |b, &threads| {
                    let c = Arc::clone(&cache);
                    let corp = Arc::clone(&corpus);
                    let pats = Arc::clone(&patterns);
                    b.iter(|| run_zipf_workload(&c, &corp, &pats, threads));
                },
            );
        }
    }
    group.finish();
}

fn bench_zipf_0_7(c: &mut Criterion) {
    bench_zipf(c, 0.7);
}

fn bench_zipf_1_0(c: &mut Criterion) {
    bench_zipf(c, 1.0);
}

fn bench_zipf_1_3(c: &mut Criterion) {
    bench_zipf(c, 1.3);
}

fn bench_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");

    let corpus = Arc::new(Corpus::new(CORPUS_SIZE, 42));

    for n_threads in selected_thread_counts() {
        let patterns: Arc<Vec<(Vec<usize>, Vec<usize>)>> = Arc::new(
            (0..n_threads)
                .map(|tid| {
                    generate_scan_pattern(corpus.keys.len(), OPS_PER_THREAD, 2000 + tid as u64)
                })
                .collect(),
        );

        let scans_per_thread = OPS_PER_THREAD / SCAN_INTERVAL;
        let total_ops = ((OPS_PER_THREAD + scans_per_thread * SCAN_WINDOW) * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for cache_box in make_caches(CACHE_SIZE) {
            let cache_name = cache_box.name();
            warmup(cache_box.as_ref(), &corpus, 1.0);
            let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

            group.bench_with_input(
                BenchmarkId::new(cache_name, n_threads),
                &n_threads,
                |b, &threads| {
                    let c = Arc::clone(&cache);
                    let corp = Arc::clone(&corpus);
                    let pats = Arc::clone(&patterns);
                    b.iter(|| run_scan_workload(&c, &corp, &pats, threads));
                },
            );
        }
    }
    group.finish();
}

fn bench_write_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_heavy");

    let corpus = Arc::new(Corpus::new(CORPUS_SIZE, 42));
    let unique_keys = Arc::new(generate_unique_keys(200_000, 42));

    for n_threads in selected_thread_counts() {
        let zipf_patterns: Arc<Vec<Vec<usize>>> = Arc::new(
            (0..n_threads)
                .map(|tid| {
                    generate_zipf_pattern(corpus.keys.len(), OPS_PER_THREAD, 1.0, 3000 + tid as u64)
                })
                .collect(),
        );

        let total_ops = (OPS_PER_THREAD * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for cache_box in make_caches(CACHE_SIZE) {
            let cache_name = cache_box.name();
            warmup(cache_box.as_ref(), &corpus, 1.0);
            let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

            group.bench_with_input(
                BenchmarkId::new(cache_name, n_threads),
                &n_threads,
                |b, &threads| {
                    let c = Arc::clone(&cache);
                    let corp = Arc::clone(&corpus);
                    let zpats = Arc::clone(&zipf_patterns);
                    let ukeys = Arc::clone(&unique_keys);
                    b.iter(|| run_write_heavy_workload(&c, &corp, &zpats, &ukeys, threads));
                },
            );
        }
    }
    group.finish();
}

fn bench_hotkey(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotkey");
    let hot_key: &[u8] = b"cn=hot,ou=People,dc=example,dc=com";
    let hot_val: &[u8] = b"cn=hot,ou=people,dc=example,dc=com";
    let ops_per_thread: usize = 200_000;

    for n_threads in selected_thread_counts() {
        let total_ops = (ops_per_thread * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for cache_box in make_caches(CACHE_SIZE) {
            let cache_name = cache_box.name();
            cache_box.put(hot_key, hot_val);
            let mut buf = vec![0u8; 256];
            for _ in 0..16 {
                cache_box.get(hot_key, &mut buf);
            }
            let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

            group.bench_with_input(
                BenchmarkId::new(cache_name, n_threads),
                &n_threads,
                |b, &threads| {
                    let c = Arc::clone(&cache);
                    b.iter(|| {
                        let barrier = Arc::new(Barrier::new(threads));
                        let handles: Vec<_> = (0..threads)
                            .map(|_| {
                                let c = Arc::clone(&c);
                                let bar = Arc::clone(&barrier);
                                std::thread::spawn(move || {
                                    let mut buf = [0u8; 256];
                                    bar.wait();
                                    for _ in 0..ops_per_thread {
                                        black_box(c.get(hot_key, &mut buf));
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().expect("thread panicked");
                        }
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_shard_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("shard_sweep");

    let corpus = Arc::new(Corpus::new(CORPUS_SIZE, 42));
    let shard_counts: &[usize] = &[16, 64, 128, 256, 512];

    let n_threads = 32;
    let patterns: Arc<Vec<Vec<usize>>> = Arc::new(
        (0..n_threads)
            .map(|tid| {
                generate_zipf_pattern(corpus.keys.len(), OPS_PER_THREAD, 1.3, 4000 + tid as u64)
            })
            .collect(),
    );

    let total_ops = (OPS_PER_THREAD * n_threads) as u64;
    group.throughput(Throughput::Elements(total_ops));

    for &shards in shard_counts {
        let cache_box: Box<dyn BenchCache> = Box::new(S3Cache::with_shards(CACHE_SIZE, shards));
        warmup(cache_box.as_ref(), &corpus, 1.3);
        let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

        group.bench_with_input(
            BenchmarkId::new("s3fifo", shards),
            &n_threads,
            |b, &threads| {
                let c = Arc::clone(&cache);
                let corp = Arc::clone(&corpus);
                let pats = Arc::clone(&patterns);
                b.iter(|| run_zipf_workload(&c, &corp, &pats, threads));
            },
        );
    }
    group.finish();
}

mod memberof_sim {
    use super::*;

    const DEPTH: usize = 6;
    const BRANCH_FACTOR: usize = 5;
    const MEMBERS_PER_LEAF: usize = 50;
    const REORG_INTERVAL: usize = 200;
    const REORG_SCAN_SIZE: usize = 5000;

    pub struct GroupDag {
        pub group_dns: Vec<Vec<Vec<u8>>>,
        pub leaf_members: Vec<Vec<Vec<u8>>>,
        pub group_ndns: Vec<Vec<Vec<u8>>>,
        pub leaf_member_ndns: Vec<Vec<Vec<u8>>>,
        pub ancestor_chains: Vec<Vec<(usize, usize)>>,
        pub reorg_dns: Vec<Vec<u8>>,
        pub reorg_ndns: Vec<Vec<u8>>,
    }

    impl GroupDag {
        pub fn build() -> Self {
            let mut group_dns: Vec<Vec<Vec<u8>>> = Vec::new();
            let mut group_ndns: Vec<Vec<Vec<u8>>> = Vec::new();

            for level in 0..DEPTH {
                let count = BRANCH_FACTOR.pow(level as u32);
                let mut level_dns = Vec::with_capacity(count);
                let mut level_ndns = Vec::with_capacity(count);
                for idx in 0..count {
                    let dn = format!("cn=group-L{}-{:04},ou=groups,dc=example,dc=com", level, idx);
                    let ndn = dn.to_lowercase();
                    level_dns.push(dn.into_bytes());
                    level_ndns.push(ndn.into_bytes());
                }
                group_dns.push(level_dns);
                group_ndns.push(level_ndns);
            }

            let n_leaves = BRANCH_FACTOR.pow((DEPTH - 1) as u32);
            let mut leaf_members = Vec::with_capacity(n_leaves);
            let mut leaf_member_ndns = Vec::with_capacity(n_leaves);
            for leaf_idx in 0..n_leaves {
                let mut members = Vec::with_capacity(MEMBERS_PER_LEAF);
                let mut member_ndns = Vec::with_capacity(MEMBERS_PER_LEAF);
                for m in 0..MEMBERS_PER_LEAF {
                    let dn = format!(
                        "uid=user-{:04}-{:03},ou=People,dc=example,dc=com",
                        leaf_idx, m
                    );
                    let ndn = dn.to_lowercase();
                    members.push(dn.into_bytes());
                    member_ndns.push(ndn.into_bytes());
                }
                leaf_members.push(members);
                leaf_member_ndns.push(member_ndns);
            }

            let mut ancestor_chains = Vec::with_capacity(n_leaves);
            for leaf_idx in 0..n_leaves {
                let mut chain = Vec::with_capacity(DEPTH);
                chain.push((0, 0));
                let mut current_idx = leaf_idx;
                for level in (1..DEPTH).rev() {
                    let parent_idx = current_idx / BRANCH_FACTOR;
                    chain.push((level, current_idx));
                    current_idx = parent_idx;
                }
                chain.sort_by_key(|&(l, _)| l);
                ancestor_chains.push(chain);
            }

            let mut reorg_dns = Vec::with_capacity(REORG_SCAN_SIZE);
            let mut reorg_ndns = Vec::with_capacity(REORG_SCAN_SIZE);
            for i in 0..REORG_SCAN_SIZE {
                let dn = format!("uid=reorg-user-{:06},ou=Transfers,dc=example,dc=com", i);
                let ndn = dn.to_lowercase();
                reorg_dns.push(dn.into_bytes());
                reorg_ndns.push(ndn.into_bytes());
            }

            Self {
                group_dns,
                group_ndns,
                leaf_members,
                leaf_member_ndns,
                ancestor_chains,
                reorg_dns,
                reorg_ndns,
            }
        }

        pub fn n_leaves(&self) -> usize {
            self.leaf_members.len()
        }
    }

    pub fn generate_memberof_pattern(dag: &GroupDag, n_ops: usize, seed: u64) -> Vec<usize> {
        let mut state = if seed == 0 { 1 } else { seed };
        let n_leaves = dag.n_leaves();
        (0..n_ops)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state as usize) % n_leaves
            })
            .collect()
    }

    #[inline(always)]
    pub fn do_cascade(
        cache: &dyn BenchCache,
        dag: &GroupDag,
        leaf_idx: usize,
        buf: &mut [u8],
    ) -> usize {
        let mut ops = 0;
        let chain = &dag.ancestor_chains[leaf_idx];

        let member_idx = ops % MEMBERS_PER_LEAF;
        let user_key = &dag.leaf_members[leaf_idx][member_idx];
        let user_val = &dag.leaf_member_ndns[leaf_idx][member_idx];
        let len = cache.get(user_key, buf);
        if len == 0 {
            cache.put(user_key, user_val);
        }
        black_box(len);
        ops += 1;

        for &(level, idx) in chain {
            let group_key = &dag.group_dns[level][idx];
            let group_val = &dag.group_ndns[level][idx];
            let len = cache.get(group_key, buf);
            if len == 0 {
                cache.put(group_key, group_val);
            }
            black_box(len);
            ops += 1;

            if level == DEPTH - 1 {
                for m in 0..MEMBERS_PER_LEAF {
                    let mk = &dag.leaf_members[idx][m];
                    let mv = &dag.leaf_member_ndns[idx][m];
                    let len = cache.get(mk, buf);
                    if len == 0 {
                        cache.put(mk, mv);
                    }
                    black_box(len);
                    ops += 1;
                }
            } else {
                let child_start = idx * BRANCH_FACTOR;
                let child_end = (child_start + BRANCH_FACTOR).min(dag.group_dns[level + 1].len());
                for ci in child_start..child_end {
                    let ck = &dag.group_dns[level + 1][ci];
                    let cv = &dag.group_ndns[level + 1][ci];
                    let len = cache.get(ck, buf);
                    if len == 0 {
                        cache.put(ck, cv);
                    }
                    black_box(len);
                    ops += 1;
                }
            }
        }

        ops
    }

    pub fn run_memberof_workload(
        cache: &Arc<dyn BenchCache>,
        dag: &Arc<GroupDag>,
        patterns: &Arc<Vec<Vec<usize>>>,
        n_threads: usize,
    ) -> u64 {
        let barrier = Arc::new(Barrier::new(n_threads));

        let handles: Vec<_> = (0..n_threads)
            .map(|tid| {
                let c = Arc::clone(cache);
                let d = Arc::clone(dag);
                let b = Arc::clone(&barrier);
                let pattern = patterns[tid].clone();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 512];
                    let mut total_ops: u64 = 0;
                    b.wait();

                    for (op_i, &leaf_idx) in pattern.iter().enumerate() {
                        if op_i > 0 && op_i % REORG_INTERVAL == 0 {
                            for i in 0..REORG_SCAN_SIZE {
                                let rk = &d.reorg_dns[i];
                                let rv = &d.reorg_ndns[i];
                                let len = c.get(rk, &mut buf);
                                if len == 0 {
                                    c.put(rk, rv);
                                }
                                black_box(len);
                                total_ops += 1;
                            }
                        }

                        total_ops += do_cascade(c.as_ref(), &d, leaf_idx, &mut buf) as u64;
                    }
                    total_ops
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .sum()
    }
}

fn bench_memberof(c: &mut Criterion) {
    use memberof_sim::*;

    let mut group = c.benchmark_group("memberof_cascade");

    let dag = Arc::new(GroupDag::build());

    let ops_per_cascade = 1 + 5 * (1 + 4) + 20;
    let reorg_ops = (OPS_PER_THREAD / 500) * 2000;
    let n_cascades = OPS_PER_THREAD;

    for n_threads in selected_thread_counts() {
        let patterns: Arc<Vec<Vec<usize>>> = Arc::new(
            (0..n_threads)
                .map(|tid| generate_memberof_pattern(&dag, n_cascades, 6000 + tid as u64))
                .collect(),
        );

        let total_ops_est = ((ops_per_cascade * n_cascades + reorg_ops) * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops_est));

        for cache_box in make_caches(CACHE_SIZE) {
            let cache_name = cache_box.name();

            {
                let warmup_pattern = generate_memberof_pattern(&dag, 5000, 99);
                let mut buf = vec![0u8; 512];
                for &leaf_idx in &warmup_pattern {
                    memberof_sim::do_cascade(cache_box.as_ref(), &dag, leaf_idx, &mut buf);
                }
            }

            let cache: Arc<dyn BenchCache> = Arc::from(cache_box);

            group.bench_with_input(
                BenchmarkId::new(cache_name, n_threads),
                &n_threads,
                |b, &threads| {
                    let c = Arc::clone(&cache);
                    let d = Arc::clone(&dag);
                    let pats = Arc::clone(&patterns);
                    b.iter(|| run_memberof_workload(&c, &d, &pats, threads));
                },
            );
        }
    }
    group.finish();
}

fn bench_cache_size_sweep(c: &mut Criterion) {
    use memberof_sim::*;

    let mut group = c.benchmark_group("cache_capacity_sweep");
    let corpus = Arc::new(Corpus::new(SWEEP_CORPUS_SIZE, 42));

    for n_threads in selected_capacity_sweep_threads() {
        let patterns: Arc<Vec<Vec<usize>>> = Arc::new(
            (0..n_threads)
                .map(|tid| {
                    generate_zipf_pattern(corpus.keys.len(), OPS_PER_THREAD, 1.3, 7000 + tid as u64)
                })
                .collect(),
        );

        let total_ops = (OPS_PER_THREAD * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for max_entries in selected_capacities() {
            for cache_box in make_caches(max_entries) {
                let cache_name = cache_box.name();
                warmup(cache_box.as_ref(), &corpus, 1.3);
                let cache: Arc<dyn BenchCache> = Arc::from(cache_box);
                let label = format!("{}cap/{}t", max_entries, n_threads);

                group.bench_with_input(
                    BenchmarkId::new(format!("zipf_1_3/{}", cache_name), label),
                    &n_threads,
                    |b, &threads| {
                        let c = Arc::clone(&cache);
                        let corp = Arc::clone(&corpus);
                        let pats = Arc::clone(&patterns);
                        b.iter(|| run_zipf_workload(&c, &corp, &pats, threads));
                    },
                );
            }
        }
    }

    for n_threads in selected_capacity_sweep_threads() {
        let patterns: Arc<Vec<(Vec<usize>, Vec<usize>)>> = Arc::new(
            (0..n_threads)
                .map(|tid| {
                    generate_scan_pattern(corpus.keys.len(), OPS_PER_THREAD, 8000 + tid as u64)
                })
                .collect(),
        );

        let scans_per_thread = OPS_PER_THREAD / SCAN_INTERVAL;
        let total_ops = ((OPS_PER_THREAD + scans_per_thread * SCAN_WINDOW) * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops));

        for max_entries in selected_capacities() {
            for cache_box in make_caches(max_entries) {
                let cache_name = cache_box.name();
                warmup(cache_box.as_ref(), &corpus, 1.0);
                let cache: Arc<dyn BenchCache> = Arc::from(cache_box);
                let label = format!("{}cap/{}t", max_entries, n_threads);

                group.bench_with_input(
                    BenchmarkId::new(format!("scan/{}", cache_name), label),
                    &n_threads,
                    |b, &threads| {
                        let c = Arc::clone(&cache);
                        let corp = Arc::clone(&corpus);
                        let pats = Arc::clone(&patterns);
                        b.iter(|| run_scan_workload(&c, &corp, &pats, threads));
                    },
                );
            }
        }
    }

    let dag = Arc::new(GroupDag::build());
    let ops_per_cascade = 1 + 5 * (1 + 4) + 20;
    let reorg_ops = (OPS_PER_THREAD / 500) * 2000;
    let n_cascades = OPS_PER_THREAD;

    for n_threads in selected_capacity_sweep_threads() {
        let patterns: Arc<Vec<Vec<usize>>> = Arc::new(
            (0..n_threads)
                .map(|tid| generate_memberof_pattern(&dag, n_cascades, 9000 + tid as u64))
                .collect(),
        );

        let total_ops_est = ((ops_per_cascade * n_cascades + reorg_ops) * n_threads) as u64;
        group.throughput(Throughput::Elements(total_ops_est));

        for max_entries in selected_capacities() {
            for cache_box in make_caches(max_entries) {
                let cache_name = cache_box.name();

                {
                    let warmup_pattern = generate_memberof_pattern(&dag, 5000, 99);
                    let mut buf = vec![0u8; 512];
                    for &leaf_idx in &warmup_pattern {
                        memberof_sim::do_cascade(cache_box.as_ref(), &dag, leaf_idx, &mut buf);
                    }
                }

                let cache: Arc<dyn BenchCache> = Arc::from(cache_box);
                let label = format!("{}cap/{}t", max_entries, n_threads);

                group.bench_with_input(
                    BenchmarkId::new(format!("memberof_cascade/{}", cache_name), label),
                    &n_threads,
                    |b, &threads| {
                        let c = Arc::clone(&cache);
                        let d = Arc::clone(&dag);
                        let pats = Arc::clone(&patterns);
                        b.iter(|| run_memberof_workload(&c, &d, &pats, threads));
                    },
                );
            }
        }
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_zipf_0_7, bench_zipf_1_0, bench_zipf_1_3,
              bench_scan, bench_write_heavy, bench_memberof,
              bench_shard_sweep, bench_hotkey, bench_cache_size_sweep
}

criterion_main!(benches);
