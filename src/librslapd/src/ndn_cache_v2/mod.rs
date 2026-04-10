pub mod dn_gen;
pub mod lock;
pub mod s3fifo;

use std::os::raw::c_char;

pub const NUM_SHARDS: usize = 64;

pub enum NdnCacheV2 {
    S3FifoPl(s3fifo::ShardedS3FifoCache<parking_lot::RwLock<s3fifo::S3FifoShard>>),
}

pub const VARIANT_S3FIFO_PL: u32 = 2;

impl NdnCacheV2 {
    fn get(&self, key: &[u8], buf: &mut [u8]) -> usize {
        match self {
            NdnCacheV2::S3FifoPl(c) => c.get(key, buf),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        match self {
            NdnCacheV2::S3FifoPl(c) => c.put(key, value),
        }
    }

    fn stats(&self) -> CacheStatsSnapshot {
        match self {
            NdnCacheV2::S3FifoPl(c) => c.stats(),
        }
    }
}

pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub count: u64,
    pub max_entries: u64,
}

#[no_mangle]
pub extern "C" fn ndn_cache_v2_create(max_entries: usize, variant: u32) -> *mut NdnCacheV2 {
    let cache = match variant {
        VARIANT_S3FIFO_PL => NdnCacheV2::S3FifoPl(s3fifo::ShardedS3FifoCache::new(max_entries)),
        _ => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(cache))
}

#[no_mangle]
pub extern "C" fn ndn_cache_v2_free(cache: *mut NdnCacheV2) {
    if !cache.is_null() {
        unsafe {
            drop(Box::from_raw(cache));
        }
    }
}

#[no_mangle]
pub extern "C" fn ndn_cache_v2_get(
    cache: *mut NdnCacheV2,
    key: *const c_char,
    key_len: usize,
    buf: *mut c_char,
    buf_len: usize,
) -> usize {
    debug_assert!(!cache.is_null());
    debug_assert!(!key.is_null());
    let cache_ref = unsafe { &*cache };
    let key_slice = unsafe { std::slice::from_raw_parts(key as *const u8, key_len) };
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buf_len) };
    cache_ref.get(key_slice, buf_slice)
}

#[no_mangle]
pub extern "C" fn ndn_cache_v2_put(
    cache: *mut NdnCacheV2,
    key: *const c_char,
    key_len: usize,
    val: *const c_char,
    val_len: usize,
) {
    debug_assert!(!cache.is_null());
    debug_assert!(!key.is_null());
    debug_assert!(!val.is_null());
    let cache_ref = unsafe { &*cache };
    let key_slice = unsafe { std::slice::from_raw_parts(key as *const u8, key_len) };
    let val_slice = unsafe { std::slice::from_raw_parts(val as *const u8, val_len) };
    cache_ref.put(key_slice, val_slice);
}

#[no_mangle]
pub extern "C" fn ndn_cache_v2_get_stats(
    cache: *mut NdnCacheV2,
    hits: *mut u64,
    tries: *mut u64,
    size: *mut u64,
    max_size: *mut u64,
    evicts: *mut u64,
    count: *mut u64,
) {
    debug_assert!(!cache.is_null());
    let cache_ref = unsafe { &*cache };
    let snap = cache_ref.stats();
    unsafe {
        *hits = snap.hits;
        *tries = snap.hits + snap.misses;
        *size = snap.count;
        *max_size = snap.max_entries;
        *evicts = snap.evictions;
        *count = snap.count;
    }
}
