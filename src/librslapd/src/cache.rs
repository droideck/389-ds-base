// This exposes C-FFI capable bindings for the concread concurrently readable cache.
use concread::arcache::stats::{ReadCountStat, WriteCountStat};
use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn, ARCacheWriteTxn};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub struct ARCacheChar {
    inner: ARCache<CString, CString>,
}

pub struct ARCacheCharRead<'a> {
    inner: ARCacheReadTxn<'a, CString, CString, ()>,
    cache: &'a ARCacheChar, // Store reference to cache for quiescing
}

pub struct ARCacheCharWrite<'a> {
    inner: ARCacheWriteTxn<'a, CString, CString, ()>,
}

#[no_mangle]
pub extern "C" fn cache_char_create(max: usize, read_max: usize) -> *mut ARCacheChar {
    let inner = if let Some(cache) = ARCacheBuilder::new()
        .set_size(max, read_max)
        .set_reader_quiesce(false) // Disable automatic quiescing
        .build()
    {
        cache
    } else {
        return std::ptr::null_mut();
    };
    let cache: Box<ARCacheChar> = Box::new(ARCacheChar { inner });
    Box::into_raw(cache)
}

#[no_mangle]
pub extern "C" fn cache_char_free(cache: *mut ARCacheChar) {
    // Should we be responsible to drain and free everything?
    debug_assert!(!cache.is_null());
    unsafe {
        let _drop = Box::from_raw(cache);
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

    let read_txn = cache_ref.inner.read_stats(ReadCountStat::default());
    let read_stats = read_txn.finish();

    let write_txn = cache_ref.inner.write_stats(WriteCountStat::default());
    let write_stats = write_txn.commit();

    *reader_hits = read_stats.main_hit + read_stats.local_hit;
    *reader_includes = read_stats.include + read_stats.local_include;
    *write_hits = write_stats.read_hits;
    *write_inc_or_mod = write_stats.read_hits;

    *shared_max = write_stats.shared_max;
    *freq = write_stats.freq;
    *recent = write_stats.recent;
    *p_weight = write_stats.p_weight;
    *all_seen_keys = write_stats.all_seen_keys;

    *freq_evicts = 0;
    *recent_evicts = 0;
}

// start read
#[no_mangle]
pub extern "C" fn cache_char_read_begin(cache: *mut ARCacheChar) -> *mut ARCacheCharRead<'static> {
    let cache_ref = unsafe {
        debug_assert!(!cache.is_null());
        &(*cache) as &ARCacheChar
    };
    let read_txn = Box::new(ARCacheCharRead {
        inner: cache_ref.inner.read(),
        cache: cache_ref,
    });
    Box::into_raw(read_txn)
}

#[no_mangle]
pub extern "C" fn cache_char_read_complete(read_txn: *mut ARCacheCharRead) {
    debug_assert!(!read_txn.is_null());
    unsafe {
        let read_txn = Box::from_raw(read_txn);

        // After completing read operation, manually quiesce
        read_txn.cache.inner.try_quiesce();
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
        inner: cache_ref.inner.write(),
    });
    Box::into_raw(write_txn)
}

#[no_mangle]
pub extern "C" fn cache_char_write_commit(write_txn: *mut ARCacheCharWrite) {
    debug_assert!(!write_txn.is_null());
    let wr = unsafe { Box::from_raw(write_txn) };
    let _stats = (*wr).inner.commit();
}

#[no_mangle]
pub extern "C" fn cache_char_write_rollback(write_txn: *mut ARCacheCharWrite) {
    debug_assert!(!write_txn.is_null());
    unsafe {
        let _drop = Box::from_raw(write_txn);
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
    use crate::cache::*;

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
        let cache_ptr = cache_char_create(1024, 8);

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

        cache_char_stats(
            cache_ptr,
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

        // Basic sanity checks
        assert_eq!(shared_max, 1024);
        assert_eq!(freq, 0);
        assert_eq!(recent, 0);

        cache_char_free(cache_ptr);
    }
}
