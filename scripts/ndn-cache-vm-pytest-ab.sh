#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: bash scripts/ndn-cache-vm-pytest-ab.sh [fit|profiles]

Runs the production-shaped pytest A/B on a Linux VM with installed test deps.

Modes:
  fit       Compare the configured runs with the fit profile only.
  profiles Compare with small,fit,large profiles.

Runs (NDN_AB_RUNS entries):
  disabled        NDN cache off
  legacy          concread, production runtime
  quiesce-thread  concread with dedicated quiesce thread + lookback 8
  s3fifo          sharded S3-FIFO backend

Environment overrides:
  NDN_AB_THREADS          default: 16,32,64
  NDN_AB_REPS             default: 5
  NDN_AB_DURATION         default: 30
  NDN_AB_TIMEOUT          default: 14400
  NDN_AB_TASKSET          default: taskset -c 0-15
  NDN_AB_PYTEST           default: pytest
  NDN_AB_TESTS            default: hotkey + scan resistance + memberOf cascade node ids
  NDN_AB_RUNS             default: disabled,legacy,quiesce-thread,s3fifo
  NDN_AB_RESULTS_DIR      default: dirsrvtests/tests/data/bench_results
  NDN_AB_READ_STATS_SAMPLE_N default: 10

The script writes separate JSON and aggregate text files under:
  dirsrvtests/tests/data/bench_results/
  pytest-logs/
USAGE
}

repo_root() {
    local d="$PWD"
    while [[ "$d" != "/" ]]; do
        if [[ -f "$d/dirsrvtests/tests/suites/ndn_cache/test_memberof_bench.py" ]]; then
            echo "$d"
            return 0
        fi
        d="$(dirname "$d")"
    done
    echo "error: run from inside the 389-ds-base checkout" >&2
    return 1
}

run_pytest() {
    local label="$1"
    local backend="$2"
    local profiles="$3"
    shift 3
    local log_path="pytest-logs/ndn-cache-${label}-${STAMP}.log"

    echo "==> pytest $label backend=$backend profiles=$profiles"
    env "$@" \
        NDN_BENCH_BACKEND="$backend" \
        NDN_BENCH_CACHE_PROFILES="$profiles" \
        NDN_BENCH_THREADS="${NDN_AB_THREADS:-16,32,64}" \
        NDN_BENCH_REPS="${NDN_AB_REPS:-5}" \
        NDN_BENCH_DURATION="${NDN_AB_DURATION:-30}" \
        NDN_BENCH_TIMEOUT="${NDN_AB_TIMEOUT:-14400}" \
        bash -c "$TASKSET_PREFIX \"$PYTEST_BIN\" -v -p no:libfaketime $TEST_ARGS" \
        2>&1 | tee "$log_path"
}

archive_results() {
    local label="$1"
    local dest="${RESULTS_DIR}/phase3_memberof-${label}-${STAMP}.json"
    local aggregate="pytest-logs/ndn-cache-${label}-aggregate-${STAMP}.txt"

    if [[ ! -f "$RESULTS" ]]; then
        echo "error: expected result file was not written: $RESULTS" >&2
        return 1
    fi

    mv "$RESULTS" "$dest"
    python3 dirsrvtests/tests/suites/ndn_cache/aggregate_bench_results.py "$dest" \
        | tee "$aggregate"
}

mode="${1:-fit}"
case "$mode" in
    fit) profiles="fit" ;;
    profiles) profiles="small,fit,large" ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this runner is intended for the Linux VM, not macOS" >&2
    exit 2
fi

cd "$(repo_root)"

RESULTS_DIR="${NDN_AB_RESULTS_DIR:-dirsrvtests/tests/data/bench_results}"
mkdir -p pytest-logs "$RESULTS_DIR"

RESULTS="${RESULTS_DIR}/phase3_memberof.json"
STAMP="$(date +%Y%m%d-%H%M%S)"
PYTEST_BIN="${NDN_AB_PYTEST:-pytest}"
TASKSET_PREFIX="${NDN_AB_TASKSET:-taskset -c 0-15}"
TEST_ARGS="${NDN_AB_TESTS:-dirsrvtests/tests/suites/ndn_cache/test_memberof_bench.py::TestMemberOfBench::test_hotkey_multithreaded dirsrvtests/tests/suites/ndn_cache/test_memberof_bench.py::TestMemberOfBench::test_scan_resistance dirsrvtests/tests/suites/ndn_cache/test_memberof_bench.py::TestMemberOfBench::test_memberof_cascade_multithreaded}"

if [[ -f "$RESULTS" ]]; then
    mv "$RESULTS" "${RESULTS_DIR}/phase3_memberof-pre-ab-${STAMP}.json"
fi

IFS=',' read -r -a runs <<< "${NDN_AB_RUNS:-disabled,legacy,quiesce-thread,s3fifo}"
for run in "${runs[@]}"; do
    run="${run//[[:space:]]/}"
    case "$run" in
        disabled)
            rm -f "$RESULTS"
            run_pytest "disabled" "disabled" "$profiles" \
                -u NSSLAPD_CACHE_CHAR_TEST_MODE \
                -u NSSLAPD_CACHE_CHAR_TEST_LOOKBACK \
                -u NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US \
                -u NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N
            archive_results "disabled"
            ;;
        legacy)
            rm -f "$RESULTS"
            run_pytest "legacy" "concread" "$profiles" \
                -u NSSLAPD_CACHE_CHAR_TEST_MODE \
                -u NSSLAPD_CACHE_CHAR_TEST_LOOKBACK \
                -u NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US \
                -u NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N
            archive_results "legacy"
            ;;
        quiesce-thread)
            rm -f "$RESULTS"
            run_pytest "quiesce-thread" "concread" "$profiles" \
                NSSLAPD_CACHE_CHAR_TEST_MODE=quiesce-thread \
                NSSLAPD_CACHE_CHAR_TEST_LOOKBACK="${NSSLAPD_CACHE_CHAR_TEST_LOOKBACK:-8}" \
                NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US="${NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US:-1000}" \
                NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N="${NDN_AB_READ_STATS_SAMPLE_N:-10}"
            archive_results "quiesce-thread"
            ;;
        s3fifo)
            rm -f "$RESULTS"
            run_pytest "s3fifo" "s3fifo" "$profiles" \
                -u NSSLAPD_CACHE_CHAR_TEST_MODE \
                -u NSSLAPD_CACHE_CHAR_TEST_LOOKBACK \
                -u NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US \
                -u NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N
            archive_results "s3fifo"
            ;;
        "")
            ;;
        *)
            echo "error: unknown NDN_AB_RUNS entry: $run" >&2
            exit 2
            ;;
    esac
done

echo "==> done"
echo "Results dir: ${RESULTS_DIR}"
for run in "${runs[@]}"; do
    run="${run//[[:space:]]/}"
    [[ -z "$run" ]] && continue
    echo "${run} JSON: ${RESULTS_DIR}/phase3_memberof-${run}-${STAMP}.json"
done
