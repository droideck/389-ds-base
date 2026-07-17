# Investigation prompt — why is 389-ds ~4.6× slower than OpenLDAP on the large-filter search, and what is a possible fix?

You are investigating a reproduced performance gap in 389 Directory Server.
The environment is already built and running; do not rebuild it unless a step
below tells you to. Everything referenced here lives in `reproducer/` in the
389-ds-base checkout, and that directory is mounted at `/repro` inside both
containers.

## The reproduced behavior

One LDAP subtree search with a ~44 KB filter over 100,000 identical synthetic
entries, identical pairwise indexes, root-DN binds on both servers, identical
120-entry result set (verified by sorted-DN hash on every run):

| | server-side search etime (median) | client median |
|---|---|---|
| 389-ds 3.3.0 (git9ae4a45fd) | **0.61 s** | ~704 ms |
| OpenLDAP 2.6.13 (mdb) | **0.13 s** | ~170 ms |

This mirrors a customer report (~0.7 s vs ~0.05 s on their data). Absolute
numbers here are under linux/amd64 emulation on Apple Silicon — both servers
equally — so ratios are the signal. Full history: `reproducer/measurements.md`
(7 iterations). Reproducibility: iterations 5, 6, 7 agree within noise.

## Environment you have

- Container `repro-389ds`: privileged systemd container, instance `repro`,
  suffix `dc=example,dc=com`, bind `cn=Directory Manager` / `Reproducer123`.
  Access log `/var/log/dirsrv/slapd-repro/access` (buffering off, time-based
  rotation off), errors log alongside. Locally built RPMs are mounted
  read-only at `/rpms`.
- Container `repro-openldap`: Fedora 42, plain `slapd.conf` at
  `/etc/openldap/slapd-repro.conf` (mdb), bind
  `cn=Manager,dc=example,dc=com` / `Reproducer123`, stats log (incl.
  qtime/etime) at `/var/log/slapd-repro.log`.
- `docker exec -it <name> bash` to enter either.
- The benchmark filter is `reproducer/filter.txt` (43,983 bytes; shape in
  `reproducer/manifest.json`); the data generator manifest is
  `reproducer/data-manifest.json`. Schema and index tables:
  `reproducer/README.md`.
- `./run-benchmark.sh` (from `reproducer/`) appends a new iteration to
  `measurements.md` with hard parity gates (identical result-set hash, exact
  log-window accounting). It stamps live server versions and file checksums,
  so patched-server runs are recorded faithfully. `RUNS=N` overrides the
  default 10.

## Measured facts to start from (inputs, not conclusions)

From the iteration log and one-off component probes:

1. **Substring assertions are the dominant differential lever.** Growing the
   substring OR 200 → 600 (bundled with NOTs 24 → 60) moved 389-ds
   +355 ms while OpenLDAP moved +5 ms (iterations 3 → 4). No other lever
   found comes close.
2. **Big-OR width is nearly free on both sides.** 1,959 → 3,000 equality
   assertions on the indexed multi-valued attribute: 389-ds +21 ms,
   OpenLDAP +4 ms (iterations 2 → 3).
3. The iteration-4 bundle changed substrings and NOTs together; the
   NOT-vs-substring split has NOT been isolated. Worth separating with
   `generate-filter.py --substr N --nots M` variants.
4. **389-ds spends the time in the operation itself**: wtime ≈ 3 ms,
   optime ≈ etime ≈ 0.61 s. Returning attributes is negligible (all-attrs ≈
   dn-only; 120 entries).
5. **`notes=U` is present on every 389-ds benchmark search** (expected — the
   filter deliberately includes NOTs on two unindexed attributes), so at
   least one component evaluates unindexed. Whether that drives the cost is
   an open question.
6. OpenLDAP-side context from iteration 1 (already root-caused and designed
   out of the data): its integer range evaluation cost scales with the number
   of distinct index keys on one side of the bound, not with result width.
   Kept here only so you don't rediscover it.
7. Component-probe technique that produced these numbers (reusable): build a
   single-component filter (optionally AND-ed with `(uid=user0000001)` to
   isolate candidate-building from result return), write it to a file, then
   inside a container:
   `f=$(cat /tmp/probe.txt); t0=$(date +%s%N); ldapsearch -x -D <rootdn> -w Reproducer123 -b dc=example,dc=com -s sub "$f" 1.1 >/dev/null; t1=$(date +%s%N)`.

## Phase 1 — investigation

Goal: a defensible, evidence-backed explanation of where 389-ds spends the
~0.5 s that OpenLDAP does not, on this filter class.

Suggested angles (pick what the evidence supports, not all of them):

- **Bisect the filter shape** with `generate-filter.py` knobs (`--substr`,
  `--nots`, `--dups`, `--depth`, `--big-or`, `--target-bytes`) and per-component
  probes. Establish per-component-class marginal cost curves on both servers
  (points at N=50/200/600/1200 give slope and linearity). Isolate substrings
  vs NOTs first (fact 3).
- **Source-level walk of the 389-ds search path for this filter**: filter
  parse/normalize/optimize (`ldap/servers/slapd/filter.c` — `str2filter`,
  `slapi_filter_optimise`), candidate generation
  (`ldap/servers/slapd/back-ldbm/filterindex.c` — `filter_candidates`,
  `substring_candidates`, `keys2idl`; IDL union/intersection in
  `back-ldbm/idl_new.c` / `idl_set.c`), and the post-candidate re-evaluation
  (`ldap/servers/slapd/filterentry.c` — `slapi_filter_test`,
  `slapi_filter_test_ext`). For each hot construct, note
  whether work is per-filter-component, per-candidate, or
  per-component-per-candidate — the 120-candidate × ~700-component product is
  the first place a per-pair cost would show.
- **Runtime evidence inside the emulated container**: `perf` is unreliable
  under Rosetta; prefer (a) gdb/pstack thread sampling during a driven loop
  (run the benchmark search in a `while true` loop and sample
  `gdb -p $(pidof ns-slapd) -batch -ex 'thread apply all bt'` a dozen times —
  the hot frames repeat), (b) `strace -c -p` for syscall-level profile, or
  (c) targeted counters via temporary instrumentation in a locally rebuilt
  server (see the patch loop below). If sampling quality blocks you, say so
  and fall back to bisection + source analysis rather than fighting the
  emulator.
- **Compare against OpenLDAP's handling** of the same construct
  (`servers/slapd/filterentry.c`, back-mdb candidates) only as far as needed
  to name the architectural difference — the deliverable is a 389-ds
  explanation, not an OpenLDAP audit.

Keep the servers' configs untouched while measuring; all filter variation
goes through the generators so every experiment is reproducible and logged
(each `run-benchmark.sh` invocation self-records the filter checksum).

## Phase 2 — possible fix

Once the hot path is named with evidence:

1. Propose the smallest credible fix (algorithmic change, caching,
   normalization hoisting, IDL handling, etc. — whatever the evidence says),
   plus any alternatives considered and why they lost.
2. Patch loop: edit source in this checkout → `~/bin/389ds-container build`
   (RPMs land in `dist/rpms/`, which is already mounted at `/rpms` in
   `repro-389ds`) → inside the container:
   `dnf install -y $(find /rpms -name '*.rpm' ! -name '*debug*' ! -name '*devel*') && dsctl repro restart`
   → `./run-benchmark.sh`. The benchmark stamps the live RPM version, so
   before/after iterations are distinguishable in `measurements.md`.
   (Do NOT reuse or invoke `~/bin/389ds-container`'s own containers for
   serving; only its `build` subcommand is used here.)
3. Acceptance for a fix candidate:
   - 389-ds etime on the accepted filter materially down (direction: toward
     the OpenLDAP ratio; state what you achieved),
   - the parity gates still pass (identical 120-entry sorted-DN hash — a fix
     that changes results is wrong),
   - no regressions: run at least
     `~/bin/389ds-container test filter` and
     `~/bin/389ds-container test basic`,
   - performance on ordinary small-filter searches not degraded (spot-check
     a few simple searches before/after).
4. Deliverables: the evidence-backed diagnosis, the patch (commit formatted
   per `docs/agents/contributing.md`, referencing the upstream issue if one
   exists), before/after `measurements.md` iterations, and honest notes on
   limitations (emulation, synthetic data) plus what should be re-validated
   on native hardware.

## Ground rules

- The reproducer artifacts (schema, generators, setup scripts, benchmark)
  are the measurement instrument — change them only to add experiments, never
  to make the comparison friendlier, and keep every change re-runnable.
- Both containers must stay usable; if you must rebuild one, use its
  `setup-*.sh` script.
- Record every benchmark run through `run-benchmark.sh` so the iteration log
  stays the single source of truth.
