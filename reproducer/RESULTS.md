# Committed benchmark matrix

Curated conclusions from `results/matrix.csv`; raw per-run data and logs
stay in the gitignored `measurements.md` / `results/`. Median server-side
search etime in seconds (attrs=1.1 variant), 10 runs per cell, run 1
discarded; every recorded cell passed the independent-expectation gate
(both servers returned exactly the DN set in `expected-dns-<shape>.txt`,
computed from the data by `generate-filter.py`, never from a server).

## Environment

- Host: Apple Silicon, OrbStack; both containers `--platform linux/amd64`
  (emulation slows both servers equally - compare ratios and deltas, not
  absolute times against native hardware)
- Images: `quay.io/389ds/ci-images:test` (389-ds), `fedora:42` (OpenLDAP
  2.6.13, mdb backend, mirrored indexes; see README index table)
- 389-ds baseline build: `3.3.0.202607170507git53874e9fe` (the series'
  parent commit, pre-cap)
- 389-ds series build: `3.3.0.202607170613git3e12baa81` - built from a
  pre-amend snapshot of this series whose server code (`ldap/`,
  `dirsrvtests/`) is byte-identical to the final series; the later
  amends touched only reproducer harness files (this evidence file, the
  isolation shapes in generate-filter.py, README). Per-row build stamps:
  `results/matrix.csv`.
- Data: 100k entries, seed 42; per-iteration data/filter md5s in
  `measurements.md`
- Backend: new-IDL (default). Old-IDL is out of scope: the read cap is
  inert there (`idl_fetch_ext` drops the limit) and results are unchanged.
- Per-row build versions: `results/matrix.csv`

## Matrix

| Shape | Expected | 389 baseline | 389 series (read cap) | OpenLDAP 2.6 | Verdict |
|---|---|---|---|---|---|
| s1 (600-substring mega-AND) | 120 | 0.658 | 0.103 | 0.136 | cap win: on par with OpenLDAP |
| s1 + per-index rule (config remedy, baseline build) | 120 | 0.115 | - | - | the cap defaults an existing supported mechanism |
| s2-uid-125 (all-live uid OR) | 125 | 0.024 | 0.024 | 0.001 | |
| s2-uid-250 | 250 | 0.075 | 0.077 | 0.004 | |
| s2-uid-500 | 500 | 0.282 | 0.283 | 0.014 | |
| s2-uid-1000 (#6275 literal shape) | 1000 | 1.089 | 1.086 | 0.046 | unchanged: not a candidate-generation cost (see below) |
| s2-tag-125 (all-live multi-ID OR) | 713 | 0.123 | 0.120 | 0.006 | |
| s2-tag-250 | 1359 | 0.423 | 0.421 | 0.025 | |
| s2-tag-500 | 2813 | 1.732 | 1.718 | 0.079 | |
| s2-tag-1000 | 5415 | 6.638 | 6.514 | 0.259 | |
| s3 (AND with compound costly child) | 120 | 0.007 | 0.005 | 0.001 | cap via pass-down |
| s3b (OR of two bounded ANDs) | 39 | 0.006 | 0.008 | 0.000 | composition guard: no engagement, parity |
| s4-10 (SSSD-style few-branch OR) | 62 | 0.007 | 0.007 | 0.000 | |
| s4-400 | 2203 | 1.105 | 1.102 | 0.056 | |
| s5 (#811 broad-OC-OR then equality) | 1 | 0.001 | 0.002 | 0.000 | parity |
| s6 (cap's losing shape, bound 3641, fat key 16647) | 619 | 0.039 | 0.110 | 0.003 | honest loss: the bounded fallback costs more here |

## Read-cap engagement

On cap-capable builds, `run-benchmark.sh` (REPRO_CAP_BUILD=1) verified
per shape - outside the timed runs - that the cap diagnostic appears
where it must (s1, s3, s6) and does NOT appear where it must not (s2-*,
s3b, s4-*, s5). An s6 row is only recorded if the cap provably engaged,
so it cannot silently measure baseline-vs-baseline.

## The union-rewrite gate: superlinear ladder, refuted attribution

The planned `idl_set_union` flatten (issue #6275's suspected fix) was
gated on measurement. The baseline ladder IS superlinear -
0.024 / 0.075 / 0.282 / 1.089 s at 125/250/500/1000 all-live uid values
(~4x per doubling, i.e. ~quadratic in the branch count) and
0.123 / 0.423 / 1.732 / 6.638 s on the multi-ID reproTag profile - but a
build carrying the flatten (memcpy members into the result buffer, qsort,
dedupe: O(T log T) instead of the merge's O(result x k)) measured
**1.071 s** at s2-uid-1000 and **6.444 s** at s2-tag-1000: within noise
of the unmodified merge. The union is not the bottleneck, so per the
pre-registered gate the rewrite was dropped; only its correctness
coverage (filter_or_union_test.py) lands.

**Where the cost actually is** - attribution probe on the same server,
same k = 1000 branches, same 1000 index reads, single searches:

| Filter | nentries | etime |
|---|---|---|
| 1000-value OR, all values live | 1000 | 1.070 |
| 1000-value OR, 999 absent + 1 live | 1 | 0.007 |
| single (uid=...) control | 1 | 0.001 |

Parsing, optimizing, 1000 index reads, and the union together cost ~6 ms
(row 2 minus row 3). The remaining ~1.06 s of row 1 scales with the
result count times the filter size: every returned entry is evaluated
against the full 1000-branch OR by the mandatory filter test
(`grok_filter` never allows skipping it for ORs), which is O(result x k)
- the actual quadratic term in #6275's shape. A union rewrite cannot
touch it; a fix would have to bypass or shortcut the per-entry filter
test when the index-driven OR candidates are exact, or exit the OR
evaluation early per entry.

## Isolation ladders: AND, OR, and NOT separated

One variable per ladder, everything else fixed - each ladder returns the
IDENTICAL result set at every rung (same expected-DN md5), so a timing
change is attributable to exactly one mechanism.

**s7, AND only** (one bounding reproScore equality + N fat Megaword
substring assertions in infix/suffix placements; 23 results at every N):

| N substrings | 389 baseline | 389 series | engagement |
|---|---|---|---|
| 1 | 0.004 | 0.005 | 1 capped read logged |
| 4 | 0.006 | 0.004 | 4 |
| 16 | 0.016 | 0.005 | 16 |
| 64 | 0.056 | 0.009 | 64 |
| 16, equality written last | 0.016 | 0.005 | 16 |

Baseline grows linearly with N (~0.8 ms per fat component: the index
reads); the capped build stays flat. This is the cap's claim in
isolation. The equality-last row matches equality-first on both builds -
the optimizer hoists it, so written placement is irrelevant.

**s8, OR only** (top-level OR of N substrings, 3/4 fat + 1/4 absent;
16,647 results at every N; the cap never engages - verified):

| N substrings | 389 baseline | 389 series |
|---|---|---|
| 4 | 0.171 | 0.171 |
| 16 | 0.177 | 0.179 |
| 64 | 0.206 | 0.207 |

Identical across builds: the series does not touch top-level ORs. Growth
along the ladder is the extra components' reads (~0.6 ms each, matching
the s7 baseline slope). Contrast with the quadratic s2 ladders: here
every result entry matches the FIRST branch and the per-entry OR
evaluation short-circuits, while s2's distinct-value OR evaluates k/2
branches per entry on average - same union machinery, different
per-entry filter-test profile, reinforcing the attribution above.

**s9, NOT probes** (s7-and-4 plus M no-op NOTs - absent substrings,
absent indexed and unindexed equalities; 23 results, identical to
s7-and-4):

| Shape | 389 baseline | 389 series |
|---|---|---|
| s7-and-4 (M=0) | 0.006 | 0.004 |
| s9-not-8 | 0.007 | 0.005 |
| s9-not-32 | 0.009 | 0.009 |
| s9-notfirst (NOT-of-eq first, 16,647 results) | 0.214 | 0.223 |

NOT components are inert in candidate generation - a NOT is never
recursed into for index reads (only NOT-of-equality reads, on the
subtraction path) - and the ladder confirms it: a few ms of parse and
per-entry cost on BOTH builds equally, no cap interaction. The capped
build logs 4+3 and 4+11 "returned ALLIDS under read cap" lines on the
s9 rungs: the no-op NOT(substring) components are classified costly and
receive a capped limit, but return ALLIDS without reading any index -
the reason the diagnostic says "returned", not "degraded". s9-notfirst
exercises the isnot ALLIDS-subtraction path (the double-free fix's
path) at parity across builds; its fat substrings are read in full
because the ALLIDS base leaves no minimum to bound against, then the
16,647-ID minimum exceeds the floor - no engagement, by design.

## Honest losses and non-wins

- **s6** is constructed to make the cap lose: the score-OR bounds the
  candidate set to 3,641, the cap discards the fat substring read
  (16,647-ID keys > 4x bound), and the filter test then pays 3,641 entry
  evaluations to produce 619 results, where the uncapped baseline paid a
  cheap full read + near-empty intersection. See the matrix row for the
  measured price; the cap commit's contract states the bound
  (min(4000, lookthroughlimit) extra entry evaluations, worst case).
- **s2/s4 large ORs** are not improved by this series (see above); #6275
  stays open with the analysis.
