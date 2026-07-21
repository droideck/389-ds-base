# External large-filter performance study

This directory contains the reproducible, manifest-driven study for the complete
389 Directory Server large-filter optimization series. It generates its own
schema, indexed data, filters, and independently computed expected DN sets; runs
fresh 389 DS or OpenLDAP instances from already installed packages; and merges
independently collected result bundles.

**Current evidence status:** the full workload has been generated and all of its
payload hashes verified. The four-bundle macOS/OrbStack Phase A correctness
smoke passed for the asserted final study tip; its default merge and container
cleanup checks also passed. It is strictly non-release evidence: native Fedora
release timing remains pending, and no OrbStack elapsed value may be used as a
timing claim. See [RESULTS.md](RESULTS.md) for the exact generated identity/report
template and [FEDORA-RUNBOOK.md](FEDORA-RUNBOOK.md) for the native procedure.

## Scope and evidence boundary

This study is intentionally separate from the legacy [`../../reproducer/`](../../reproducer/)
tree and from upstream pytest. The legacy generators, static/container setup,
hot-install guidance, curated measurements, and result files are historical
context only. They are not inputs, an oracle, or evidence for this study, and no
legacy timing number is carried into `RESULTS.md`.

The new-to-legacy output-name mapping is:

| Legacy output | This study |
|---|---|
| `data.ldif` | `data.ldif` for 389 DS and `data-openldap.ldif` for packaged OpenLDAP |
| `filter-<shape>.txt` | `filters/<scenario>.filter` |
| `expected-dns-<shape>.txt` | `expected/<scenario>.dns` |
| `data-manifest.json` plus `shapes-manifest.json` | one authoritative `workload-manifest.json`, with the copied `study-spec.json` |

There are three distinct execution classes:

| Class | Required markers | Permitted use |
|---|---|---|
| Native Fedora | `host_class: fedora_native`, `correctness_only: false`, `release_timing_evidence: true` | Release timing, CPU/perf/profile analysis, p95, scaling, 389 DS/OpenLDAP comparison |
| macOS/OrbStack | `host_class: macos_orbstack_emulated`, `correctness_only: true`, `release_timing_evidence: false` | Generator, schema/index/import, exact-result, mechanism, cleanup, artifact, and end-to-end smoke validation |
| Optional focused pytest | separate test output, never a benchmark row | Functional contract validation when a suitable source/test environment exists |

Do not use Apple-Silicon-hosted emulation, cross-architecture containers, or
sanitizer builds for timing conclusions. The native timing runner requires a
non-container x86_64 Fedora host and refuses a sanitizer-linked server.

## Quick start: generate immutable workloads

Run from this directory. Generation uses only Python's standard library and is
atomic: the output path must not already exist, and a failure does not publish a
partial workload.

```bash
bin/generate-workload \
    --profile smoke \
    --output generated/smoke

bin/generate-workload \
    --profile full \
    --output generated/full
```

`smoke` creates a correctness-only 12,000-person workload while retaining the
612-entry principal cohort and all workload families. `full` creates the native
100,000-person workload with the exact 612-entry principal cohort. `tiny` exists
for fast generator/unit development but is not the requested end-to-end smoke
profile and is never release evidence.

Every generated workload contains:

```text
data.ldif
data-openldap.ldif
filters/*.filter
expected/*.dns
schema/99large-filter-study.ldif
schema/large-filter-study.schema
indexes/index-configurations.json
study-spec.json
workload-manifest.json
```

`workload-manifest.json` records every payload SHA-256, the deterministic seed,
filter and BER sizes, node/branch/assertion counts, expected counts and sorted-DN
SHA-256 values, logical outer cohorts, index variants, server support, and
mechanism expectations. Controlled outer cohorts are derived from the executed
filter AST and generation fails if the declared cohort or executed AST differs.
Family-selection controls include exact base-object probes, and approximate
comparisons carry a hashed two-probe semantics contract. Expected DNs come from
the generated data plus a syntax-aware filter AST, never from agreement between
servers. Two additional data-derived import oracles bind the live server to the
complete people DN set and the exact 612-entry principal outer cohort before any
timing can begin.

The locally verified full artifact is `full-62af05addd159340`: 100,000 people,
a 612-entry principal cohort, 118 scenarios, and 242 hashed payloads. Its primary
filter is 41,684 rendered bytes, 368 nodes, and intentionally returns zero DNs.
Its workload, raw-manifest, and canonical-manifest SHA-256 values are recorded
in `RESULTS.md`.

The standard-library harness unit suite is separate from upstream functional
pytest and can be rerun with:

```bash
python3 -m unittest discover -s tests -v
```

## Frozen native release matrix

[`workload/native-matrix-plan.json`](workload/native-matrix-plan.json) is the
machine-readable coverage contract for a full native release decision. It
freezes the per-run cadence, warm-cache/MDB protocol, required hardware perf
class, timed revision pairs and scenario groups, profile-required groups,
correctness-only controls, and release-conclusion policy. The merger loads this
file by default (or an explicitly predeclared replacement passed with
`--matrix-plan`), records its canonical SHA-256, and expands it into auditable
`matrix_completion` instances rather than inferring completeness from whichever
bundles happen to be present.

Every timed comparison instance in that plan must be backed by one complete,
protocol-matched `A1`, `B1`, `B2`, `A2` block. A standalone screen remains
useful for directional triage, but it cannot complete a planned comparison or
authorize a release conclusion.

## OrbStack correctness smoke

`bin/run-orbstack-smoke` is the macOS entry point. It requires Darwin with
OrbStack, uses `linux/amd64`, rejects an RPM filename whose embedded git SHA does
not match the requested revision, and labels every result with the strict
non-release triplet:

```yaml
host_class: macos_orbstack_emulated
correctness_only: true
release_timing_evidence: false
```

The triplet is repeated in the smoke summary, each bundle's artifact, run,
correctness, and raw-result manifests, every raw row, and the merged artifacts.
The wrapper validates all copies rather than trusting its own invocation.

The completed Phase A run used this exact command from the repository root:

```bash
performance/large-filter-study/bin/run-orbstack-smoke \
    --rpm-dir dist/rpms \
    --expected-source-sha e0161d0e61d0cdef22175418f0d4a1e126216a86 \
    --output performance/large-filter-study/results/orbstack-smoke-e0161d0e-attempt15
```

Use `--rpm-dir`, `--workload`, `--ds-image`, or `--openldap-image` to override
the defaults; `--retain` keeps owned containers, and `--dry-run` validates and,
when preflight succeeds, prints the plan without claiming a successful smoke.
The wrapper writes `389ds-lookup-on-baseline`, `389ds-lookup-off-subset`,
`389ds-lookup-on-presence-both`, and `openldap-parity-subset` bundles, merges
them without the unsafe flag, and writes `<output>/smoke-summary.json`.

That run completed with `status: pass` on an Apple M4 Pro host using OrbStack,
Fedora 42 `linux/amd64` containers, and Rosetta. All four bundle gates passed:

| Bundle | Scenarios | Raw rows |
|---|---:|---:|
| `389ds-lookup-on-baseline` | 40 | 40 |
| `389ds-lookup-off-subset` | 15 | 17 |
| `389ds-lookup-on-presence-both` | 2 | 2 |
| `openldap-parity-subset` | 24 | 26 |

The default safe merge passed with four source runs and 85 raw rows. It produced
zero release-eligible rows and zero entries in each of
`release_summaries`, `release_comparisons`, `release_scaling_tables`,
`openldap_contextual_comparisons`, and `unsafe_nonrelease_summaries`. Cleanup
also passed: all four owned containers were verified removed and the final
ownership-label query found zero remaining containers.

The three 389 DS bundles independently installed and cleanly verified this same
package set:

| Installed RPM | SHA-256 of input RPM |
|---|---|
| `389-ds-base-3.3.0.202607201823gite0161d0e6-1.fc42.x86_64` | `b2eee041b4b715ff533f81fa6239c6dd61af0a03c7dfd0cbe6101cd364550ff1` |
| `389-ds-base-libs-3.3.0.202607201823gite0161d0e6-1.fc42.x86_64` | `9895d949ae34ac89aec7b3785ef9d06ff0d9d295b70ff5914a79876637440c01` |
| `python3-lib389-3.3.0.202607201823gite0161d0e6-1.fc42.noarch` | `3af81f31bf73ddd2b32e6b4c325750c70ac3140e55a4ca094c5fbfa4aef89fe3` |

The package token `e0161d0e6` corroborates only the prefix of the asserted full
SHA `e0161d0e61d0cdef22175418f0d4a1e126216a86`; together with the operator
assertion, it is not independent proof of the full SHA. This successful smoke
validates correctness and artifact flow only. Native x86_64 Fedora timing is
still required before any performance, p95, CPU, profile, scaling, ratio, or
release conclusion can be reported.

For manual development inside an already prepared OrbStack Linux environment,
the lower-level equivalent is explicit correctness-only mode. Never omit or
change the host class for an OrbStack run:

```bash
sudo bin/run-study \
    --mode correctness-only \
    --host-class macos_orbstack_emulated \
    --server 389ds \
    --build-label final-e0161d0e-orbstack-smoke \
    --expected-source-sha final \
    --lookup on \
    --workload generated/smoke \
    --output results/manual-orbstack-final-lookup-on \
    --smoke-selected \
    --repeat 1 \
    --warmups 0 \
    --perf off \
    --profile off \
    --cleanup
```

The manual command still requires the server executable to belong to an
installed RPM. It exercises a fresh instance and artifact path but does not
turn emulated elapsed values into evidence.

## Native Fedora contract

The native entry point is `bin/run-fedora-study`. It assumes that the operator
has already installed the exact, normal unsanitized RPM to be measured. It does
not run `mock`, `rpmbuild`, `dnf builddep`, a source build, a worktree/build
wrapper, or a container build, and it never installs or replaces the server
package. Building the SRPM/RPM and installing it occur outside this study and
before the timing-host snapshot is handed to the runner.

Fedora 44 x86_64 is supported directly; the runner checks for native Fedora and
does not contain a Fedora 42-only gate. A Fedora 44 revision snapshot must carry
one version-release-matched four-package closure:

```text
389-ds-base
389-ds-base-libs
389-ds-base-robdb-libs
python3-lib389
```

Archive and install those four RPMs together. Do not combine a locally built
server RPM with repository versions of its companion packages.

Example for the same installed final RPM with lookup enabled:

```bash
sudo bin/run-fedora-study \
    --server 389ds \
    --build-label final-e0161d0e-lookup-on \
    --expected-source-sha final \
    --lookup on \
    --workload generated/full \
    --output results/final-e0161d0e-lookup-on \
    --scenario-group acceptance \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --perf auto \
    --profile auto \
    --schedule-design screen \
    --schedule-position final-on-screen \
    --cleanup
```

The `auto` modes in this example are suitable for an exploratory screen because
the bundle records what actually attached. If perf falls back to software
`task-clock`, the result remains useful elapsed/CPU evidence but cannot satisfy
the frozen release matrix's `hardware-events` requirement. Run the full release
matrix only on a host whose PMU supports every mandatory hardware event.

Run the final lookup-off row with the **same installed RPM**, changing only
`--build-label`, `--lookup`, `--output`, and the descriptive
`--schedule-position`. See the Fedora runbook for the complete role matrix,
clean-snapshot ABBA scheduling, packaged OpenLDAP command, presence/index
controls, and result transfer.

The minimum directional screen uses three invocations: Fedora 44 stable with
lookup unsupported, HEAD with lookup off, and the same exact HEAD package with
lookup on. Give each invocation `--schedule-design screen` and a descriptive
`--schedule-position`. Stable to HEAD-off is a whole-package screen containing
all intervening changes; it is not causal evidence for the bounded change.
HEAD-off to HEAD-on isolates the OR lookup switch within one binary. Causal
bounded-feature attribution is the exact pre-series artifact versus the exact
bounded-feature artifact in a complete structured ABBA block (`A1`, `B1`, `B2`,
`A2`) with one stable block ID.

`bin/run-full-fedora-screen` applies that same custom/off, identical custom/on,
then one-downgrade-to-stable sequence to all 116 timed scenarios and all six
required index configurations. A custom commit where the OR switch itself was
reverted is detected and run once with lookup unsupported. The command writes a
compact Markdown report and CSV tables, including a short filter-structure
description for every row. It does not build packages, and it does not promote
the fixed-order screen to ABBA release evidence. See the Fedora runbook for its
environment overrides and output layout.

## Revision roles

`--expected-source-sha` accepts a full 40-hex SHA or these exact role names.
OpenLDAP additionally accepts `fedora-package` or `packaged-openldap`.

| CLI role | Exact SHA | Study use |
|---|---|---|
| `pre-series` | `6e1e933745313622593d943e983ff710de8db732` | Required pre-series 389 DS reference |
| `modern-harness` | `72f489233e90688a18c11a3c71d42cc812e13fe9` | Harness/history reference; not a headline timing point |
| `bounded-feature` | `fde13723bfa682526bb472baa91ff0d5f1b4af47` | Required bounded substring/approximate reference; includes the NOT-first correction |
| `combined-diagnostic` | `7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6` | Optional combined pre-correctness-fix diagnostic snapshot |
| `dynamic-list-fix` | `038b8f58a305c1650ab0523a9d2658aabbc9848b` | Dynamic-list/lookthrough correctness control |
| `all-family-fix` | `09f92bfbe67f8769277e4e4ae5fef5cf069d71f4` | Flat-OR third-family discovery attribution |
| `largest-family-fix` | `9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a` | Largest-family ranking and deterministic-tie attribution |
| `lifecycle-tests` | `014fe6a3793898b508a6d6de9893937a7e1aa49d` | Validation-only commit; deduplicate if `ns-slapd` matches its production parent |
| `asan-harness` | `f29a3c6806c81d1cc0e5b77520b3b8d4b3d5d873` | Validation-only commit; deduplicate if `ns-slapd` matches its production parent |
| `final` | `e0161d0e61d0cdef22175418f0d4a1e126216a86` | Final post-fix tip; required lookup-off and lookup-on rows from one RPM |
| `final-study-tip` | `fa3987d01209bc60f599dda70ad4e5734ebc78c2` | Study-only child of `final`; package source remains `fa3987d0`, while final mechanism contracts use its declared production-equivalent `e0161d0e` revision |
| `historical` | `dd7d0db1a45a417f9c1546002758c25ca6e120d6` | Historical sibling reference only; never label it as the modern final build |

The runner treats a source SHA as an operator assertion unless installed RPM
metadata exposes the exact 40-hex token. A shorter matching git token is prefix
corroboration, not independent proof. In every case it records the immutable
package NEVRA, `rpm -qi`, `rpm -V`, executable SHA-256, ELF build ID,
content-derived direct-linked library closure, live backend-module closure,
combined behavioral runtime identity, and assertion basis. A label alone is
never proof of binary identity. The runner also content-addresses every
executable harness/gate/schema input, records the harness git HEAD/tree and
top-level invocation, and requires a clean committed study tree for native
timing.

After a normal `dscreate`/cleanup cycle, RPM can report exactly
`.....UG..  g /var/lock/dirsrv`: the shared ghost lock directory is deliberately
left as mode `0770`, `dirsrv:dirsrv`. The runner and merger narrowly accept that
recorded runtime ownership delta. No other `rpm -V` difference is allowlisted.

Do not enable `set -e` directly in an interactive login shell. Use a script, or
reset the parent with `set +e; set +u; set +o pipefail` and then use a subshell
`( set -euo pipefail; ... )`; otherwise an expected preflight failure can
terminate the login session.

## Runner flow

Each invocation follows one auditable path:

1. Enforce the native-versus-correctness execution boundary and resolve the
   operator-supplied revision role.
2. Before copying workload data or creating an instance, reject a missing
   executable, non-RPM executable, failed RPM verification, contradictory package
   git token, or sanitizer-linked native server and capture its immutable
   identity.
3. Record server package/binary/direct-linked and live-backend identity, the pinned
   `ldapsearch` client identity, committed harness identity/invocation,
   Fedora/kernel/CPU/topology/architecture/memory/storage/filesystem,
   cache and scheduling policy, and the operator assertion.
4. Validate the generated workload and every payload hash, then copy the
   complete hashed payload into the result bundle.
5. Create a unique fresh instance. For 389 DS this uses normal installed
   `dscreate`, copies the study schema, reconciles every workload-controlled
   index type exactly, records the complete live index inventory, configures
   lookup mode, imports with `dsconf`, and reindexes. For OpenLDAP it creates a
   private MDB directory/configuration and imports with packaged `slapadd`.
   Both implementations capture hashed raw and canonical live subschema
   inventories, prove exact syntax/matching/cardinality/object-class semantics,
   record index-build completion and lookup read-back, then search and hash all
   people plus the 612-entry principal cohort to prove the import.
6. Run exact-DN preflight and postflight diagnostics outside the timed window.
   Family-selection evidence comes from an isolated base-object FILTER trace;
   approximate comparison requires two isolated exact probes under the same
   contract hash. The stable lookup-construction and read-cap messages do not
   prove lookup probes or avoided index work; those require A/B/profile evidence.
   For 389 DS, the final controlled restart first proves the paired referral
   monitor and delayed role/COS vattr checks are complete. Every later
   diagnostic/timing/profile collection must remain inside one
   `CLOCK_MONOTONIC` 3600-second epoch and finish before its five-second safety
   deadline; a boundary crossing fails the run.
7. Disable verbose diagnostics, verify every server thread's requested affinity,
   perform warm-ups and measured searches,
   collect raw elapsed/server/CPU/RSS data and optional perf/profile artifacts,
   and retain every iteration. Principal rows run both `1.1` and normal
   attribute-list variants. Perf mode creates one independent perf-stat batch
   per measured search. Each planned profile uses one perf-record window around
   exactly 20 isolated searches; every one must independently pass the exact-DN
   oracle plus client and server result-code checks. The operation ledger and
   hashed profile/report artifacts are retained with the observed sampling
   class.
8. Write self-contained manifests, correctness records, diagnostics, raw rows,
   profiles, and logs, then remove the temporary instance unless `--retain` was
   requested.

An output directory is never silently overwritten. `INCOMPLETE` remains after a
failed run; `COMPLETE` is written only after a successful run and cleanup.

## Runner options

| Option | Meaning and constraints |
|---|---|
| `--mode native-timing\|correctness-only` | `run-study` defaults to correctness-only; `run-fedora-study` forces native timing |
| `--server 389ds\|openldap` | Select installed server implementation |
| `--build-label LABEL` | Required human-readable immutable label; include role/configuration |
| `--expected-source-sha VALUE` | Required exact SHA, documented role, or packaged-OpenLDAP token |
| `--operator-assertion TEXT` | Records who/what supplied the installed package |
| `--lookup on\|off\|unsupported\|auto` | 389 DS switch expectation; OpenLDAP accepts only `unsupported` or `auto` |
| `--workload DIR`, `--output DIR` | Validated workload and new result directory |
| `--scenario ID` | Repeatable exact scenario selection |
| `--scenario-group GROUP` | Repeatable group selection from `workload-manifest.json` |
| `--smoke-selected` | Select manifest smoke scenarios, skipping server/index-incompatible ones |
| `--index-config VALUE` | `baseline-no-presence`, `presence-sdn1`, `presence-sdn2`, `presence-both`, `without-sdn1-equality`, or `without-sdn2-equality` |
| `--backend mdb\|bdb` | MDB is primary; BDB is optional for 389 DS; OpenLDAP requires MDB |
| `--repeat N`, `--warmups N` | Defaults 20/3; native timing requires at least 15 measured repeats and exactly 2 or 3 warm-ups |
| `--cache-policy warm\|cold` | Keep warm and cold results separate; cold mode drops Linux page caches |
| `--host-class CLASS` | Mandatory in correctness-only mode; use exactly `macos_orbstack_emulated` for OrbStack; native mode records `fedora_native` itself |
| `--cpu CPU` | Pin and verify every server task plus the client on one CPU |
| `--perf auto\|on\|off` | `auto` attempts hardware counters and falls back to software `task-clock`; `on` requires every hardware event; repeat 20 produces 20 independent one-search batches per scenario/attribute stratum. The observed class/signature, not only this requested mode, defines the timing stratum |
| `--profile auto\|on\|off` | `auto` profiles native acceptance, presence, and combined-feature shapes and retries unsupported hardware sampling with software `cpu-clock`; each planned profile covers exactly 20 oracle-checked searches, and its observed class/signature defines the profile stratum |
| `--scenario-order manifest\|randomized`, `--order-seed N` | Stable within-run ordering control |
| `--schedule-design unspecified\|screen\|abba` | Declare the external ordering contract; only a complete structured `abba` block is release-ordering evidence |
| `--schedule-block ID` | Stable 1-128 character block identifier required for `abba`; use the identical ID at all four positions and do not pass it for a screen |
| `--schedule-position TEXT` | For `screen`, a descriptive position; for `abba`, exactly `A1`, `B1`, `B2`, or `A2` |
| `--allow-rpm-verify-differences` | Let diagnosis continue for non-allowlisted `rpm -V` differences; the merger cannot treat that package as proved release evidence |
| `--cleanup`, `--retain` | Cleanup is the default; retain the temporary instance only for diagnosis |

With no scenario selection, the runner selects the two principal acceptance
filters. Generated group names and members are authoritative in
`workload-manifest.json`.

## Result bundle and aggregation

A completed result directory contains at least:

| Path | Purpose |
|---|---|
| `workload-manifest.json` | Exact workload/schema/filter/expected-result comparison contract copied into the bundle |
| `workload/` | Complete copy of every payload named and hashed by the workload manifest, including data, filters, expected DNs, schema, index intent, and study spec |
| `artifact-manifest.json` | RPM, executable/build ID, direct-linked and live-backend closures, client, revision, committed harness identity, live import/setup evidence, and both runtime identity levels |
| `run-manifest.json` | Host/storage/filesystem, invocation, fresh-instance setup, live schema/index/import inventories, backend/lookup read-back, affinity, schedule, and completion state |
| `correctness.json` | Exact-result, pre/postflight, selection, dynamic-list, and approximate-semantic evidence |
| `raw-results.json` | Every warm-up/measured iteration plus strictly linked singleton perf batches |
| `diagnostics/` | Portable, hashed isolated untimed diagnostic windows |
| `profiles/` | Portable, hashed `perf stat`, `perf record`, and symbol-annotation artifacts |
| `logs/` | Retained server logs |
| `COMPLETE` | Successful completion marker |

Copy independently collected directories back without editing their contents,
then merge from this directory:

```bash
bin/merge-results \
    results/native/pre-series-a1 \
    results/native/final-on-b1 \
    results/native/final-on-b2 \
    results/native/pre-series-a2 \
    results/native/openldap-packaged \
    --output results/merged-native
```

The merger verifies workload, schema, filter, expected-result, import,
index/build, harness, runtime-closure, and native host compatibility hashes. It rejects an absent/invalid `COMPLETE`
marker, any `INCOMPLETE`/`CLEANUP-FAILED` marker, a non-complete run manifest,
conflicting run IDs, and incompatible timing environments; ignores byte-identical duplicate bundles;
and treats rows sharing an installed executable SHA-256 as executable aliases
while retaining all commit/build labels. Performance pooling additionally
requires the same content-derived behavioral runtime identity. Consequently the
test/sanitizer-only `014fe6a3` and `f29a3c68` commits cannot masquerade as
independent performance evidence when their supplied `ns-slapd` matches the
preceding production binary.

Requested `--perf` and `--profile` modes do not make unlike observations
comparable. Rows record actual perf collection classes such as
`hardware-events` and `software-task-clock`, and actual profile classes such as
`hardware-sampling` and `software-cpu-clock`, together with content-derived
collection signatures. These fields are part of the aggregation key, so an
`auto` hardware attachment is never pooled with an `auto` software fallback.
Only the actual `hardware-events` perf class satisfies the frozen full-release
matrix; a PMU-less VM can produce an exploratory screen, not a complete release
decision.

Correctness-only/emulated rows are excluded from release summaries by default.
`--unsafe-include-nonrelease` can display them only in a separately labelled
NON-RELEASE appendix; it cannot promote them into comparisons or acceptance
classifications.

The merger embeds the frozen plan and its hash in `merged-raw-results.json`, and
writes `matrix_completion`, `schedule_assessment`, and `release_conclusion` to
both merged JSON artifacts. The generated `RESULTS.md` reports their counts and
reasons. `matrix_completion` expands the plan into the full-workload contract,
each timed pair/scenario/attribute cell, and each correctness control. A missing
or ambiguous cell remains `pending`; a failed required correctness control is
`fail`; only complete protocol-matched evidence makes the matrix `complete`.

`release_conclusion` is `pass`/`eligible-for-release` only when the matrix and
ABBA schedule are complete and all ten acceptance gates pass. Any gate or
matrix failure yields `fail`/`do-not-release`; every other state is
`pending`/`withheld`. The independent generated status
`native-results-available` means only that at least one eligible native stratum
exists and does **not** certify full matrix completion.

For every required comparison, each of the four proving bundles must declare
`--schedule-design abba`, the same stable `--schedule-block`, and one unique
position from `A1`, `B1`, `B2`, and `A2`. Free-form legacy positions and
`--schedule-design screen` remain useful for directional triage but cannot
satisfy that ordering requirement or make `release_conclusion`
`eligible-for-release`.

## Cleanup and retention

Use the default `--cleanup` for all scheduled measurements. Each invocation
already creates a unique instance/database and copies final logs before removal.
Use `--retain` only for a failed diagnostic run, record that exception, and do
not reuse the retained instance for a timing row. Preserve completed result
directories and their `COMPLETE` marker read-only; preserve failed directories
with `INCOMPLETE`/`CLEANUP-FAILED` for diagnosis but do not merge them as release
evidence.

The timing host must never be hot-upgraded between revisions. Restore the clean
VM snapshot and have the operator install the next externally built RPM before
the next scheduled position. The benchmark itself must not build, install,
replace, or mutate server packages.
