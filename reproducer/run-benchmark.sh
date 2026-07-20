#!/usr/bin/env bash
# Run benchmark shapes against BOTH running containers and append one
# section per shape to measurements.md (+ a machine-readable row per cell to
# results/matrix.csv).
#
# Usage:
#   ./run-benchmark.sh                 # the default shape (s1)
#   ./run-benchmark.sh --shape s6      # one shape (repeatable)
#   ./run-benchmark.sh --all-shapes    # every shape in shapes-manifest.json
#
# Method (per shape, per server, per variant):
#   - ldapsearch runs INSIDE the container (docker exec) so docker network
#     noise is excluded; the filter is read from the mounted
#     /repro/filter-<shape>.txt inside the container.
#   - Bind: 389-ds as cn=Directory Manager, OpenLDAP as the rootdn
#     (both bypass ACLs - parity). NOTE: client wall time includes
#     connect+bind+unbind, and the bind cost is asymmetric (389-ds verifies a
#     hashed root password, OpenLDAP compares a plaintext rootpw), so each
#     iteration also records per-server BIND etime medians and the
#     server-side search etime column is the primary comparison metric.
#   - Variants: attrs "1.1" (no attributes) and all attributes.
#   - RUNS runs each (default 10, minimum 2); run 1 is discarded;
#     median/min/max reported.
#   - Server-side numbers come from the access/stats logs, restricted to the
#     exact log window of this shape; if the window does not contain exactly
#     the expected operations, nothing is recorded.
#
# HARD gates (no timings recorded for a shape unless all pass):
#   - every run on every server returns EXACTLY the independently computed
#     expected DN set (count AND sorted-DN md5 from expected-dns-<shape>.txt,
#     written by generate-filter.py from the data, never from a server) -
#     any mismatch, including zero-vs-nonzero, is fatal
#   - each server's log window contains exactly 2*RUNS search RESULT lines
#
# Read-cap engagement (only when REPRO_CAP_BUILD=1, i.e. the installed
# 389-ds build carries the AND read cap): for shapes whose manifest
# expect_cap is true/false, one extra search runs with backend debug logging
# enabled (outside the timed window) and the cap diagnostic must / must not
# appear. Without it an S6 row would silently measure baseline-vs-baseline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$SCRIPT_DIR/results"
RUNS="${RUNS:-10}"
SUFFIX="dc=example,dc=com"
PASSWORD="${REPRO_DM_PASSWORD:-Reproducer123}"
CAP_PATTERN="under read cap"   # matches both historical wordings

die() { echo "error: $*" >&2; exit 1; }

# shellcheck source=repro-common.sh
source "$SCRIPT_DIR/repro-common.sh"

(( RUNS >= 2 )) || die "RUNS must be >= 2 (run 1 is discarded from all stats)"

SHAPES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --shape) [[ $# -ge 2 ]] || die "--shape needs a value"
                 SHAPES+=("$2"); shift 2 ;;
        --all-shapes) SHAPES=(ALL); shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ ${#SHAPES[@]} -gt 0 ]] || SHAPES=(s1)

[[ -f "$SCRIPT_DIR/shapes-manifest.json" ]] \
    || die "shapes-manifest.json missing - run generate-filter.py first"
[[ -f "$SCRIPT_DIR/data-manifest.json" ]] || die "data-manifest.json missing"
if [[ "${SHAPES[0]}" == ALL ]]; then
    SHAPES=()
    while IFS= read -r s; do SHAPES+=("$s"); done < <(python3 -c \
        "import json; print('\n'.join(json.load(open('$SCRIPT_DIR/shapes-manifest.json'))['shapes']))")
fi
for shape in "${SHAPES[@]}"; do
    [[ -f "$SCRIPT_DIR/filter-$shape.txt" && -f "$SCRIPT_DIR/expected-dns-$shape.txt" ]] \
        || die "filter/expected files for shape '$shape' missing - run generate-filter.py"
done

docker inspect -f '{{.State.Running}}' "$NAME_389DS" 2>/dev/null | grep -q true \
    || die "$NAME_389DS is not running (setup-389ds.sh)"
docker inspect -f '{{.State.Running}}' "$NAME_OPENLDAP" 2>/dev/null | grep -q true \
    || die "$NAME_OPENLDAP is not running (setup-openldap.sh)"
refuse_foreign "$NAME_389DS"
refuse_foreign "$NAME_OPENLDAP"
mkdir -p "$RESULTS"

# Capture versions LIVE (a patched RPM installed mid-investigation must not
# be stamped with the setup-time version).
docker exec "$NAME_389DS" rpm -q 389-ds-base > "$RESULTS/389ds-version.txt"
docker exec "$NAME_OPENLDAP" /usr/sbin/slapd -VV 2>&1 | head -1 > "$RESULTS/openldap-version.txt"

bench_variant() {  # $1 container, $2 bind dn, $3 variant (dnonly|allattrs), $4 filter file
    docker exec -i \
        -e BIND_DN="$2" -e PASSWORD="$PASSWORD" -e SUFFIX="$SUFFIX" \
        -e RUNS="$RUNS" -e VARIANT="$3" -e FILTER_FILE="/repro/$4" \
        "$1" bash -s <<'EOS'
set -euo pipefail
FILTER=$(cat "$FILTER_FILE")
for r in $(seq 1 "$RUNS"); do
    t0=$(date +%s%N)
    if [ "$VARIANT" = dnonly ]; then
        ldapsearch -x -H ldap://localhost:389 -D "$BIND_DN" -w "$PASSWORD" \
            -b "$SUFFIX" -s sub -o ldif-wrap=no "$FILTER" 1.1 \
            > /tmp/bench.out 2> /tmp/bench.err \
            || { echo "ldapsearch failed (run $r, $VARIANT)" >&2; cat /tmp/bench.err >&2; exit 1; }
    else
        ldapsearch -x -H ldap://localhost:389 -D "$BIND_DN" -w "$PASSWORD" \
            -b "$SUFFIX" -s sub -o ldif-wrap=no "$FILTER" \
            > /tmp/bench.out 2> /tmp/bench.err \
            || { echo "ldapsearch failed (run $r, $VARIANT)" >&2; cat /tmp/bench.err >&2; exit 1; }
    fi
    t1=$(date +%s%N)
    # A zero-match result is a legitimate outcome to REPORT (the expectation
    # gate decides pass/fail) - guard the pipelines so it cannot abort us.
    n=$(grep -c '^dn:' /tmp/bench.out || true)
    h=$({ grep '^dn:' /tmp/bench.out || true; } | LC_ALL=C sort | md5sum | cut -d' ' -f1)
    echo "$r,$(( (t1 - t0) / 1000 )),$n,$h"
done
EOS
}

check_cap_engagement() {  # $1 shape, $2 filter file, $3 expected (true|false)
    local count
    count=$(docker exec -i \
        -e PASSWORD="$PASSWORD" -e SUFFIX="$SUFFIX" \
        -e FILTER_FILE="/repro/$2" -e CAP_PATTERN="$CAP_PATTERN" \
        "$NAME_389DS" bash -s <<'EOS'
set -euo pipefail
dsc() { dsconf -D "cn=Directory Manager" -w "$PASSWORD" ldap://localhost:389 "$@"; }
sea() { ldapsearch -x -H ldap://localhost:389 -D "cn=Directory Manager" -w "$PASSWORD" "$@"; }
prev=$(sea -b cn=config -s base -o ldif-wrap=no nsslapd-errorlog-level \
        | awk 'tolower($1)=="nsslapd-errorlog-level:" {print $2}')
prev=${prev:-16384}
ERRLOG=$(ls /var/log/dirsrv/slapd-*/errors | head -1)
dsc config replace nsslapd-errorlog-level=524288 >/dev/null
off=$(wc -l < "$ERRLOG")
sea -b "$SUFFIX" -s sub "$(cat "$FILTER_FILE")" 1.1 > /dev/null
dsc config replace "nsslapd-errorlog-level=$prev" >/dev/null
tail -n +$((off + 1)) "$ERRLOG" | grep -c "$CAP_PATTERN" || true
EOS
)
    if [[ "$3" == true && "$count" -eq 0 ]]; then
        die "shape $1: expected the read cap to engage but no '$CAP_PATTERN' log line appeared - row would measure baseline-vs-baseline"
    fi
    if [[ "$3" == false && "$count" -gt 0 ]]; then
        die "shape $1: read cap engaged ($count log lines) but this shape must NOT be capped"
    fi
    echo ">> cap engagement check ($1): expected=$3 loglines=$count OK"
}

log_lines() {  # $1 container, $2 log path -> current line count
    docker exec "$1" bash -c "wc -l < '$2' 2>/dev/null || echo 0"
}

LOG_389=/var/log/dirsrv/slapd-repro/access
LOG_OL=/var/log/slapd-repro.log

for shape in "${SHAPES[@]}"; do
    ff="filter-$shape.txt"
    echo "== shape $shape =="

    echo ">> benchmarking $NAME_389DS (bind: cn=Directory Manager)..."
    OFF_389=$(log_lines "$NAME_389DS" "$LOG_389")
    bench_variant "$NAME_389DS" "cn=Directory Manager" dnonly "$ff" \
        > "$RESULTS/cur-$shape-389ds-dnonly.csv"
    bench_variant "$NAME_389DS" "cn=Directory Manager" allattrs "$ff" \
        > "$RESULTS/cur-$shape-389ds-allattrs.csv"
    docker exec "$NAME_389DS" bash -c "tail -n +$((OFF_389 + 1)) '$LOG_389'" \
        > "$RESULTS/cur-$shape-389ds-log.txt"

    echo ">> benchmarking $NAME_OPENLDAP (bind: rootdn)..."
    OFF_OL=$(log_lines "$NAME_OPENLDAP" "$LOG_OL")
    bench_variant "$NAME_OPENLDAP" "cn=Manager,dc=example,dc=com" dnonly "$ff" \
        > "$RESULTS/cur-$shape-openldap-dnonly.csv"
    bench_variant "$NAME_OPENLDAP" "cn=Manager,dc=example,dc=com" allattrs "$ff" \
        > "$RESULTS/cur-$shape-openldap-allattrs.csv"
    docker exec "$NAME_OPENLDAP" bash -c "tail -n +$((OFF_OL + 1)) '$LOG_OL'" \
        > "$RESULTS/cur-$shape-openldap-log.txt"

    if [[ "${REPRO_CAP_BUILD:-0}" == 1 ]]; then
        expect=$(python3 -c "
import json
v = json.load(open('$SCRIPT_DIR/shapes-manifest.json'))['shapes']['$shape']['expect_cap']
print({True: 'true', False: 'false', None: 'skip'}[v])")
        if [[ "$expect" != skip ]]; then
            check_cap_engagement "$shape" "$ff" "$expect"
        fi
    fi

    echo ">> computing stats + appending measurements.md..."
    python3 - "$SCRIPT_DIR" "$RUNS" "$shape" <<'EOPY'
import hashlib
import json
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

repro = Path(sys.argv[1])
runs = int(sys.argv[2])
shape = sys.argv[3]
results = repro / "results"
meas = repro / "measurements.md"

with open(repro / "shapes-manifest.json") as f:
    sman = json.load(f)["shapes"][shape]
with open(repro / "data-manifest.json") as f:
    dman = json.load(f)
exp_count = sman["expected_count"]
exp_md5 = sman["expected_md5"]


def file_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(name):
    rows = []
    for line in (results / f"cur-{shape}-{name}.csv").read_text().splitlines():
        r, us, n, h = line.strip().split(",")
        r, us, n = int(r), int(us), int(n)
        if us <= 0 or us > 600_000_000:
            sys.exit(f"{shape}/{name} run {r}: implausible wall time {us} us "
                     "(clock step?) - no timings recorded")
        rows.append((r, us, n, h))
    if len(rows) != runs:
        sys.exit(f"{shape}/{name}: expected {runs} runs, got {len(rows)}")
    return rows


data = {(srv, var): read_csv(f"{srv}-{var}")
        for srv in ("389ds", "openldap") for var in ("dnonly", "allattrs")}

# --- HARD gate: every run matches the INDEPENDENT expectation ---------------
failed = False
for (srv, var), rows in data.items():
    for r, _, n, h in rows:
        if n != exp_count or h != exp_md5:
            print(f"EXPECTATION FAILED {shape} {srv}/{var} run {r}: "
                  f"count {n} (expected {exp_count}), md5 {h} "
                  f"(expected {exp_md5})", file=sys.stderr)
            failed = True
if failed:
    sys.exit(f"{shape}: result sets do not match expected-dns-{shape}.txt - "
             "no timings recorded")

# --- client-side stats (drop run 1) ----------------------------------------
def client_stats(rows):
    us = [t for r, t, _, _ in rows if r != 1]
    return (statistics.median(us) / 1000.0, min(us) / 1000.0,
            max(us) / 1000.0)  # -> ms


# --- server-side stats ------------------------------------------------------
def parse_389(path):
    ops, binds = [], []
    for line in path.read_text().splitlines():
        if " RESULT " not in line:
            continue
        et = re.search(r"etime=([0-9.]+)", line)
        if "tag=97" in line:
            if et:
                binds.append(float(et.group(1)))
            continue
        if "tag=101" not in line:
            continue
        m = {k: re.search(k + r"=([0-9.]+)", line) for k in
             ("wtime", "optime", "nentries")}
        notes = re.search(r"notes=([A-Z,]+)", line)
        ops.append({
            "etime": float(et.group(1)) if et else None,
            "wtime": float(m["wtime"].group(1)) if m["wtime"] else None,
            "optime": float(m["optime"].group(1)) if m["optime"] else None,
            "nentries": int(m["nentries"].group(1)) if m["nentries"] else None,
            "notes": notes.group(1) if notes else "",
        })
    return ops, binds


def parse_ol(path):
    ops, binds = [], []
    for line in path.read_text().splitlines():
        et = re.search(r"etime=([0-9.]+)", line)
        if "RESULT tag=97" in line:
            if et:
                binds.append(float(et.group(1)))
            continue
        if "SEARCH RESULT" not in line:
            continue
        qt = re.search(r"qtime=([0-9.]+)", line)
        ne = re.search(r"nentries=(\d+)", line)
        ops.append({
            "etime": float(et.group(1)) if et else None,
            "qtime": float(qt.group(1)) if qt else None,
            "nentries": int(ne.group(1)) if ne else None,
            "notes": "",
        })
    return ops, binds


srv_ops, srv_binds = {}, {}
srv_ops["389ds"], srv_binds["389ds"] = parse_389(results / f"cur-{shape}-389ds-log.txt")
srv_ops["openldap"], srv_binds["openldap"] = parse_ol(results / f"cur-{shape}-openldap-log.txt")

for srv, ops in srv_ops.items():
    if len(ops) != 2 * runs:
        # A stray search in the window would silently blend the two variants'
        # medians; refuse to record anything rather than mislabel numbers.
        sys.exit(f"{shape}/{srv}: log window has {len(ops)} search RESULT "
                 f"lines, expected exactly {2 * runs} (a non-benchmark search "
                 f"landed in the window?) - no timings recorded")
    bad = {o["nentries"] for o in ops} - {exp_count}
    if bad:
        sys.exit(f"{shape}/{srv}: server log nentries {bad} != expected {exp_count}")


def chunk_ops(srv, half):
    """half=0 -> first RUNS ops (dnonly), half=1 -> last RUNS ops (allattrs);
    [1:] drops run 1 in each half."""
    return srv_ops[srv][half * runs:(half + 1) * runs][1:]


def srv_summary(srv, half):
    chunk = chunk_ops(srv, half)
    ets = [o["etime"] for o in chunk if o["etime"] is not None]
    med = statistics.median(ets) if ets else None
    notes = ",".join(sorted({o["notes"] for o in chunk if o["notes"]})) or "-"
    return med, notes


# --- append measurements.md --------------------------------------------------
header = ("# Measurements - large-filter reproducer\n\n"
          "Generated by run-benchmark.sh; do not hand-edit. "
          "Timings are under linux/amd64 emulation on Apple Silicon "
          "(both servers equally); the RATIO is the signal, not the "
          "absolute numbers. Client wall time includes connect+bind+unbind "
          "(bind cost is asymmetric between the servers - see the recorded "
          "bind medians); the server-side search etime column is the "
          "primary comparison metric.\n")
existing = meas.read_text() if meas.exists() else ""
iteration = existing.count("## Iteration") + 1

ver389 = (results / "389ds-version.txt").read_text().strip()
verol = (results / "openldap-version.txt").read_text().strip()
stamp = subprocess.run(["date", "-u", "+%Y-%m-%d %H:%M:%SZ"],
                       capture_output=True, text=True).stdout.strip()

lines = [
    "",
    f"## Iteration {iteration} - shape {shape} - {stamp}",
    "",
    f"- 389-ds: `{ver389}`",
    f"- OpenLDAP: `{verol}`",
    f"- data: {dman['entries']} entries (golden cohort: {dman['golden']['count']}), "
    f"seed {dman['seed']}, data.ldif md5 {file_md5(repro / 'data.ldif')}",
    f"- filter: {sman['filter_bytes']} bytes, nesting depth {sman['nesting_depth']}, "
    f"filter-{shape}.txt md5 {file_md5(repro / f'filter-{shape}.txt')}",
    f"- shape params: {json.dumps(sman['params'], sort_keys=True)}",
    f"- expectation: PASS - every run on both servers returned exactly the "
    f"{exp_count}-entry independently computed set (sorted-DN md5 {exp_md5})",
    f"- runs per cell: {runs} (run 1 discarded)",
    "",
    "| server | variant | client median (ms) | client min (ms) | "
    "client max (ms) | server etime median (s) | notes |",
    "|---|---|---|---|---|---|---|",
]
matrix_rows = []
for srv, label in (("389ds", "389-ds"), ("openldap", "OpenLDAP")):
    for half, var in ((0, "attrs=1.1"), (1, "all attrs")):
        med, mn, mx = client_stats(data[(srv, "dnonly" if half == 0 else "allattrs")])
        smed, notes = srv_summary(srv, half)
        smed_s = f"{smed:.3f}" if smed is not None else "n/a"
        lines.append(f"| {label} | {var} | {med:.1f} | {mn:.1f} | {mx:.1f} "
                     f"| {smed_s} | {notes} |")
        matrix_rows.append(f"{stamp},{shape},{srv},{var.replace(' ', '')},"
                           f"{med:.1f},{smed_s},{exp_count},"
                           f"\"{ver389 if srv == '389ds' else verol}\"")

extras = []
for srv, label in (("389ds", "389-ds"), ("openldap", "OpenLDAP")):
    if srv_binds[srv]:
        extras.append(f"{label} BIND etime median: "
                      f"{statistics.median(srv_binds[srv]):.6f} s "
                      f"(included in client wall, not in search etime)")
wts = [o["wtime"] for o in srv_ops["389ds"] if o.get("wtime") is not None]
opts = [o["optime"] for o in srv_ops["389ds"] if o.get("optime") is not None]
if wts and opts:
    extras.append(f"389-ds wtime median: {statistics.median(wts):.6f} s, "
                  f"optime median: {statistics.median(opts):.6f} s "
                  f"(per-op values in results/iterNN-{shape}-389ds-log.txt)")
qts = [o["qtime"] for half in (0, 1) for o in chunk_ops("openldap", half)
       if o.get("qtime") is not None]
if qts:
    extras.append(f"OpenLDAP qtime median: {statistics.median(qts):.6f} s "
                  f"(run 1 of each variant discarded)")
if extras:
    lines.append("")
    lines.extend(extras)

with open(meas, "a") as f:
    if not existing:
        f.write(header)
    f.write("\n".join(lines) + "\n")

matrix = results / "matrix.csv"
if not matrix.exists():
    matrix.write_text("stamp,shape,server,variant,client_median_ms,"
                      "server_etime_median_s,nentries,version\n")
with open(matrix, "a") as f:
    f.write("\n".join(matrix_rows) + "\n")

for src in results.glob(f"cur-{shape}-*"):
    shutil.copy(src, results / src.name.replace("cur-", f"iter{iteration:02d}-"))

med389 = client_stats(data[("389ds", "dnonly")])[0]
medol = client_stats(data[("openldap", "dnonly")])[0]
et389 = srv_summary("389ds", 0)[0]
etol = srv_summary("openldap", 0)[0]
et389_s = f"{et389:.3f}s" if et389 is not None else "n/a"
etol_s = f"{etol:.3f}s" if etol is not None else "n/a"
ratio_s = (f"{et389 / etol:.1f}x" if et389 is not None and etol else "n/a")
print(f"iteration {iteration} [{shape}]: nentries={exp_count}  "
      f"server etime {et389_s} vs {etol_s} (ratio {ratio_s}); "
      f"client median {med389:.1f} vs {medol:.1f} ms [attrs=1.1]")
print(f"appended to {meas}")
EOPY
done
