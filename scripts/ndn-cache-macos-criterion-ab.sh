#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: bash scripts/ndn-cache-macos-criterion-ab.sh [main|sensitivity|context]

Runs Criterion NDN cache microbenchmarks from the repository root.

Modes:
  main         A/B legacy production FFI concread vs quiesce-thread concread.
  sensitivity Sweep quiesce-thread lookback and quiesce interval.
  context      Smaller context run for concread-direct-tuned-stats and s3fifo.

Environment overrides:
  NDN_AB_THREADS             default: 16,64
  NDN_AB_CAPACITIES          default: 6241,124830,500000
  NDN_AB_SAMPLE_SIZE         default: 30
  NDN_AB_MEASUREMENT_SECS    default: 20
  NDN_AB_WARMUP_SECS         default: 5
  NDN_AB_READ_STATS_SAMPLE_N default: 10
USAGE
}

repo_root() {
    local d="$PWD"
    while [[ "$d" != "/" ]]; do
        if [[ -f "$d/src/librslapd/Cargo.toml" && -d "$d/src/librslapd/benches" ]]; then
            echo "$d"
            return 0
        fi
        d="$(dirname "$d")"
    done
    echo "error: run from inside the 389-ds-base checkout" >&2
    return 1
}

run_bench() {
    local label="$1"
    shift
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"
    echo "==> $label"
    "$@" 2>&1 | tee "bench-logs/${label}-${stamp}.log"
}

main_ab() {
    mkdir -p bench-logs

    run_bench "ndn-cache-ffi-legacy" env -u NSSLAPD_CACHE_CHAR_TEST_MODE \
        -u NSSLAPD_CACHE_CHAR_TEST_LOOKBACK \
        -u NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US \
        -u NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N \
        NDN_RS_BENCH_VARIANTS=concread \
        NDN_RS_BENCH_THREADS="${NDN_AB_THREADS:-16,64}" \
        NDN_RS_BENCH_CAPACITIES="${NDN_AB_CAPACITIES:-6241,124830,500000}" \
        NDN_RS_BENCH_SAMPLE_SIZE="${NDN_AB_SAMPLE_SIZE:-30}" \
        NDN_RS_BENCH_MEASUREMENT_SECS="${NDN_AB_MEASUREMENT_SECS:-20}" \
        NDN_RS_BENCH_WARMUP_SECS="${NDN_AB_WARMUP_SECS:-5}" \
        cargo bench --manifest-path src/librslapd/Cargo.toml --bench ndn_cache -- \
        cache_capacity_sweep/memberof_cascade

    run_bench "ndn-cache-ffi-quiesce-thread" env \
        NSSLAPD_CACHE_CHAR_TEST_MODE=quiesce-thread \
        NSSLAPD_CACHE_CHAR_TEST_LOOKBACK="${NSSLAPD_CACHE_CHAR_TEST_LOOKBACK:-8}" \
        NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US="${NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US:-1000}" \
        NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N="${NDN_AB_READ_STATS_SAMPLE_N:-10}" \
        NDN_RS_BENCH_VARIANTS=concread \
        NDN_RS_BENCH_THREADS="${NDN_AB_THREADS:-16,64}" \
        NDN_RS_BENCH_CAPACITIES="${NDN_AB_CAPACITIES:-6241,124830,500000}" \
        NDN_RS_BENCH_SAMPLE_SIZE="${NDN_AB_SAMPLE_SIZE:-30}" \
        NDN_RS_BENCH_MEASUREMENT_SECS="${NDN_AB_MEASUREMENT_SECS:-20}" \
        NDN_RS_BENCH_WARMUP_SECS="${NDN_AB_WARMUP_SECS:-5}" \
        cargo bench --manifest-path src/librslapd/Cargo.toml --bench ndn_cache -- \
        cache_capacity_sweep/memberof_cascade
}

sensitivity() {
    mkdir -p bench-logs
    for lookback in 4 8 16 32; do
        for quiesce_us in 100 1000 10000; do
            run_bench "ndn-cache-ffi-quiesce-thread-lookback${lookback}-q${quiesce_us}us" env \
                NSSLAPD_CACHE_CHAR_TEST_MODE=quiesce-thread \
                NSSLAPD_CACHE_CHAR_TEST_LOOKBACK="$lookback" \
                NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US="$quiesce_us" \
                NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N="${NDN_AB_READ_STATS_SAMPLE_N:-10}" \
                NDN_RS_BENCH_VARIANTS=concread \
                NDN_RS_BENCH_THREADS="${NDN_AB_THREADS:-16,64}" \
                NDN_RS_BENCH_CAPACITIES="${NDN_AB_CAPACITIES:-124830}" \
                NDN_RS_BENCH_SAMPLE_SIZE="${NDN_AB_SAMPLE_SIZE:-20}" \
                NDN_RS_BENCH_MEASUREMENT_SECS="${NDN_AB_MEASUREMENT_SECS:-15}" \
                NDN_RS_BENCH_WARMUP_SECS="${NDN_AB_WARMUP_SECS:-5}" \
                cargo bench --manifest-path src/librslapd/Cargo.toml --bench ndn_cache -- \
                cache_capacity_sweep/memberof_cascade
        done
    done
}

context() {
    mkdir -p bench-logs
    run_bench "ndn-cache-context" env \
        NDN_RS_BENCH_VARIANTS=concread,concread-direct-tuned-stats,s3fifo-sampled10 \
        NDN_RS_BENCH_THREADS="${NDN_AB_THREADS:-16,64}" \
        NDN_RS_BENCH_CAPACITIES="${NDN_AB_CAPACITIES:-124830}" \
        NDN_RS_BENCH_SAMPLE_SIZE="${NDN_AB_SAMPLE_SIZE:-20}" \
        NDN_RS_BENCH_MEASUREMENT_SECS="${NDN_AB_MEASUREMENT_SECS:-15}" \
        NDN_RS_BENCH_WARMUP_SECS="${NDN_AB_WARMUP_SECS:-5}" \
        cargo bench --manifest-path src/librslapd/Cargo.toml --bench ndn_cache -- \
        cache_capacity_sweep/memberof_cascade
}

cd "$(repo_root)"
mode="${1:-main}"
case "$mode" in
    main) main_ab ;;
    sensitivity) sensitivity ;;
    context) context ;;
    -h|--help|help) usage ;;
    *)
        usage >&2
        exit 2
        ;;
esac
