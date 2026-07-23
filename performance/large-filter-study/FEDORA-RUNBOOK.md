# Fedora native large-filter study runbook

Use this runbook only on the dedicated native Fedora timing VM after the
operator has installed the exact normal, unsanitized RPM for the requested
revision. The benchmark validates and records that installed package, creates a
fresh server instance, imports and checks the workload, measures it, writes an
independent result directory, and removes the instance.

Native measurements have not yet been collected. Until eligible result bundles
are merged, [RESULTS.md](RESULTS.md) must remain `native-results-pending`.

Do not enable `set -e` or `set -u` directly in an interactive login shell: an
expected preflight failure can terminate that shell. Put strict commands in a
script, or first reset the parent with `set +e; set +u; set +o pipefail` and run
strict commands inside `( set -euo pipefail; ... )`, so failure returns to the
parent prompt.

## Non-negotiable timing-host boundary

The timing host must be a non-container x86_64 Fedora system running the RPM and
client natively. Do not use OrbStack, Docker, Podman, cross-architecture
emulation, an Apple-Silicon-hosted VM/container, or a sanitizer build.

Fedora 44 x86_64 is explicitly supported. The runner verifies that the native
host is Fedora; it does not impose a Fedora 42-only release check. Keep the exact
Fedora release fixed within each comparison block and record a release change as
a different timing environment.

Do not run any of the following on the timing host as part of this workflow:

- `mock`, `rpmbuild`, `dnf builddep`, `meson`, `ninja`, `make`, or a source-tree
  server build;
- git worktree/cherry-pick synthesis or a containerized `ns-slapd`;
- installation/replacement of the target RPM by the benchmark;
- a hot upgrade of an existing test instance between revisions.

The package builder/operator owns the separate SRPM/mock build and package
installation step. Restore a clean VM snapshot before each scheduled package
state, install the externally built RPM outside the benchmark, and only then
hand the VM to this runbook. Never label an old branch package, historical fork,
or cherry-picked synthetic state as the final build.

`bin/run-fedora-study` enforces Fedora, rejects detected containers and the
`LFSTUDY_EMULATED` marker, requires an RPM-owned executable, checks `rpm -V`, and
rejects sanitizer-linked native servers. It contains no package-build or
package-install path.

## 1. Provision the clean base snapshot

Install ordinary runtime/observation dependencies before freezing the timing
base snapshot. Do not use this command to replace the target 389 DS RPM after a
revision-specific snapshot has been prepared. The dependency roles are:

| Role | Packages |
|---|---|
| Harness, committed-tree identity, LDAP client, process and affinity capture | `python3 git openldap-clients binutils procps-ng util-linux` |
| Mandatory counters/profiles for the scheduled commands | `perf` |
| Packaged OpenLDAP snapshot only | `openldap-servers` |
| Operator-supplied Fedora 44 revision artifact | matching `389-ds-base`, `389-ds-base-libs`, `389-ds-base-robdb-libs`, and `python3-lib389` RPMs |

Matching debuginfo should also be installed externally when strong attribution
to internal profile symbols is required; the harness never installs it.

```bash
sudo dnf install \
    python3 \
    git \
    openldap-clients \
    perf \
    binutils \
    procps-ng \
    util-linux
```

For the separate packaged OpenLDAP comparison snapshot, also install the normal
Fedora server package:

```bash
sudo dnf install openldap-servers
```

The revision-specific 389 DS package must provide `ns-slapd`, `dscreate`,
`dsctl`, and `dsconf`; that package is the already-installed study artifact, not
a dependency for the harness to fetch. `openldap-clients` supplies the pinned
`ldapsearch`/`ldapmodify` client. `perf` is required when `--perf on` or
`--profile on` is used; `binutils` supplies `readelf`; `procps-ng` and
`util-linux` make host/process/affinity/storage/filesystem metadata complete;
`git` proves the exact clean committed harness tree used by every native row.

Keep the following constant across a comparison: physical/virtual machine,
vCPU topology, CPU affinity, CPU governor, memory allocation, storage device,
kernel, Fedora release, client executable, background load, and connection/cache
policy. Provision perf permissions before taking the clean snapshot. MDB is the
primary 389 DS backend; run BDB only as an explicitly requested focused subset
when the installed RPM supports it.

Before selecting the perf mode, probe both software and hardware counters:

```bash
sudo perf stat -e task-clock -- sleep 1
sudo perf stat -e cpu-clock -- sleep 1
sudo perf stat \
    -e cycles,instructions,branches,branch-misses,cache-misses \
    -- sleep 1
```

Use `--perf on` only when all mandatory hardware events work. `--perf auto`
records the failed hardware attempt and falls back to `task-clock`; automatic
profiling similarly retries with `cpu-clock`. Such a VM still provides elapsed,
process-CPU, and sampled-profile evidence, but cannot satisfy an acceptance gate
that requires instructions. Use a PMU-enabled timing host for the final release
decision.

The runner records the observed collection, not just the requested mode. Perf
classes include `hardware-events` and `software-task-clock`; profile classes
include `hardware-sampling` and `software-cpu-clock`. Their content-derived
signatures are timing-stratum keys, so two `--perf auto --profile auto` runs are
not pooled when one attached hardware counters/sampling and the other used a
software fallback. The frozen full-release matrix requires the actual
`hardware-events` perf class. A PMU-less host is therefore appropriate only for
an exploratory screen or diagnostics, even when all elapsed-time searches pass.

## 2. Stage the checkout, workload, and artifact destination

The checkout is used only for the committed Python harness and static study
files. It need not match the installed server source revision, but it must be
the same clean committed harness checkout for every row. The runner records its
HEAD, tree, per-input hashes, and combined harness content SHA-256; an uncommitted
study tree is rejected in native mode.

The examples use these operator-selected locations:

```bash
study_root=/srv/389-ds-base/performance/large-filter-study
workload_dir=/srv/large-filter-workloads/full
results_root=/mnt/large-filter-study-results

cd "$study_root"
```

`results_root` should be durable storage outside the snapshot rollback. Give
each invocation a new output directory; the runner refuses to overwrite a
non-empty path.

Generate the full workload once, before scheduling measurements:

```bash
bin/generate-workload \
    --profile full \
    --output "$workload_dir"
```

The full manifest must report 100,000 people, a 612-entry principal cohort,
`correctness_only: false`, and `release_timing_evidence: true`. Inspect it without
third-party tools:

```bash
python3 - "$workload_dir/workload-manifest.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest["profile"] == "full"
assert manifest["entry_counts"]["people"] == 100000
assert manifest["entry_counts"]["principal_cohort"] == 612
assert manifest["correctness_only"] is False
assert manifest["release_timing_evidence"] is True
print(manifest["workload_id"], manifest["workload_sha256"])
PY
```

The checked reference artifact for this runbook is
`full-62af05addd159340`, with workload SHA-256
`62af05addd1593408106f1ebdddac4067af82f8295cda9ee5a194555b6a68163`,
raw manifest SHA-256
`2ee3f029d2e05d756a1de3282d43a9af2388b777473b1a63c01bdd1f763eaad7`,
and canonical manifest SHA-256
`ac2c3e24a17a6494bf960e45b5119d1259154a8648d9bda51b2654d4f9e21591`.
Regeneration must reproduce all four identities before it can replace that
artifact.

Retain that exact workload directory and use it for every 389 DS and OpenLDAP
bundle entering one comparison. Do not regenerate or edit filters between ABBA
positions. The merger later rejects mismatched workload, schema, filter,
expected-DN, index-description, or scenario-contract hashes.

Freeze the workload manifest and predeclared gates before looking at final
results. Record both file-byte and canonical-JSON identities:

```bash
python3 - "$workload_dir/workload-manifest.json" workload/acceptance-gates.json <<'PY'
import hashlib
import json
import sys

for name in sys.argv[1:]:
    payload = open(name, "rb").read()
    value = json.loads(payload)
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    print(name, "raw", hashlib.sha256(payload).hexdigest())
    print(name, "canonical", hashlib.sha256(canonical).hexdigest())
PY
```

The gate file specifies the noise model, minimum improvement/regression floors,
nearest-rank p95 definition, correctness requirements, memory rule, and scaling
dimensions. Do not tune it after inspecting the native comparison.

## 3. Verify the installed package handoff

After the operator restores the appropriate clean snapshot and installs the
externally built RPM, run these read-only checks. They are an early operator
check; the runner repeats and records the authoritative identity capture.

```bash
command -v ns-slapd
command -v dscreate
command -v dsctl
command -v dsconf
command -v ldapsearch
command -v ldapmodify
command -v rpm

rpm -q \
    389-ds-base \
    389-ds-base-libs \
    389-ds-base-robdb-libs \
    python3-lib389

server_path=$(readlink -f "$(command -v ns-slapd)")
server_package=$(rpm -qf "$server_path")

rpm -q --qf '%{NEVRA}\n' "$server_package"
rpm -qi "$server_package"
rpm -V "$server_package"
sha256sum "$server_path"
readelf -n "$server_path"
ldd "$server_path"
```

On Fedora 44, archive and install all four matching RPMs together. Do not mix a
locally built `389-ds-base` with repository versions of any of its three
companion packages. The package NEVRAs may differ only in architecture where
expected (`python3-lib389` is normally `noarch`); their version-release must
match exactly.

Stop if an executable is missing, `rpm -qf` cannot identify its owner, `rpm -V`
is nonzero without a reviewed explanation, or linked sanitizer libraries are
present. One normal post-instance exception is handled automatically:
`dscreate` leaves the shared RPM ghost directory `/var/lock/dirsrv` as mode
`0770`, owner/group `dirsrv:dirsrv`, so RPM reports exactly
`.....UG..  g /var/lock/dirsrv`. The runner records the live metadata and the
merger accepts only that exact owner/group-only ghost difference. Any other
path, flag, mode, owner, or group remains dirty and timing-ineligible.
`--allow-rpm-verify-differences` exists for diagnosis of another deliberately
reviewed packaging exception; the resulting `rpm_verify.accepted: false` cannot
prove a release row to the merger. Record the exception and do not use the flag
merely to bypass a dirty package.

If RPM NEVRA or `rpm -qi` contains a `git<sha>` token, the runner requires that
token to agree with `--expected-source-sha`. Only an exact 40-hex token is
independent source proof; a shorter token is prefix corroboration plus the
operator assertion. The bundle records the immutable NEVRA, executable hash,
build ID, direct-linked runtime closure, live backend-module closure, and their
combined behavioral runtime identity. Do not report more source proof than the
metadata supplies.

## 4. Required revision and configuration matrix

The authoritative coverage contract is
[`workload/native-matrix-plan.json`](workload/native-matrix-plan.json). It
freezes the native cadence and environment, all timed pair/scenario rules,
profile-required groups, historical/fixed correctness controls, and the release
policy. `bin/merge-results` loads this file by default, records its canonical
SHA-256, and expands it into machine-verifiable completion instances. Do not
replace it after seeing results; `--matrix-plan` exists only for a separately
predeclared study contract.

These are the required release rows:

| Installed artifact | Exact SHA/package | Lookup | Required use |
|---|---|---|---|
| Pre-series 389 DS | `6e1e933745313622593d943e983ff710de8db732` | `unsupported` | Principal pair and baseline/scaling controls |
| Bounded-feature 389 DS | `fde13723bfa682526bb472baa91ff0d5f1b4af47` | `unsupported` | Bounded substring/approximate composition; includes NOT-first correction |
| Final 389 DS | `e0161d0e61d0cdef22175418f0d4a1e126216a86` | `off` | Full final matrix with lookup disabled |
| The same final 389 DS RPM | the same SHA, NEVRA, executable hash, build ID, linked closure, live backend closure, and behavioral identity | `on` | Full final matrix with lookup enabled |
| Fedora OpenLDAP | normal `openldap-servers` package | `unsupported` | Comparable schema/data/index/filter administrative-bind rows |

The final lookup-off and lookup-on rows must use the **same installed RPM**.
Only the runtime configuration switch, build label, schedule position, and
output directory differ. Their executable SHA, direct-linked closure, live
backend-module closure, and combined behavioral identity must all agree.
Executable hashes form alias groups, but differing behavioral identities may
never be pooled.

An RPM sourced at `fa3987d01209bc60f599dda70ad4e5734ebc78c2` is also
supported. That commit adds only this study directory on top of `e0161d0e`; the
runner therefore records `expected_source_sha=fa3987d0...` as package provenance
and `production_equivalent_revision=e0161d0e...` for final mechanism contracts.
Do not pass `final` for that RPM: the package token must still match the literal
`fa3987d0...` source SHA.

Optional attribution RPMs are accepted only when the operator supplies the
matching external build:

| CLI role | Exact SHA | Focus |
|---|---|---|
| `combined-diagnostic` | `7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6` | Pre-correctness diagnostic and immediate parent of `038b8f58`; not a release candidate |
| `dynamic-list-fix` | `038b8f58a305c1650ab0523a9d2658aabbc9848b` | Immediate dynamic-list/lookthrough correctness control |
| `all-family-fix` | `09f92bfbe67f8769277e4e4ae5fef5cf069d71f4` | Third-family discovery control |
| `largest-family-fix` | `9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a` | Largest-family ranking and deterministic tie control |

`014fe6a3793898b508a6d6de9893937a7e1aa49d` and
`f29a3c6806c81d1cc0e5b77520b3b8d4b3d5d873` change validation/sanitizer
collection, not timed server behavior. Retain their labels in artifact records
when supplied, but do not schedule independent timing rows if their installed
executable SHA-256 equals the `9c23a6e4` production parent. The merger groups
identical executable hashes automatically.

The harness checkout is independent of the installed server revision. Pin one
clean committed `large-filter-series` harness tip for the entire comparison;
each bundle records that exact commit and the content hashes of all relevant
study files. The harness tip is not a headline server build. No listed server
commit is a standalone true-root/no-hit revision; do not synthesize one.

### Minimal three-invocation screen

When the immediate question is only whether the installed changes show a
directional benefit, run the single operator command below while a custom RPM
whose version contains `git<hash>` is already installed:

```bash
bin/run-minimal-fedora-screen
```

It performs no Git operation, source/RPM build, RPM staging, perf collection,
or release-matrix merge. It runs:

1. the already-installed custom package with lookup off;
2. the same installed binary with lookup on; and
3. after both custom bundles complete, `dnf downgrade -y 389-ds-base` followed
   by the pre-fix Fedora package (identified by no `git<hash>` in its version)
   with lookup unsupported.

The pre-fix-to-custom-off result is a **whole-package directional screen**: it
contains every intervening package change and must not be described as the
causal benefit of the bounded substring/approximate change. Custom-off to
custom-on isolates the runtime OR lookup switch because it uses one installed
binary. Causal bounded-feature attribution instead compares the exact
pre-series artifact with the exact bounded-feature artifact in the complete
ABBA block described in sections 6 and 8. A screen position is deliberately
not release-ordering evidence.

### Full timed directional screen

To run the full back-to-back sequence — packaged OpenLDAP over the same
generated data, then installed-custom/off, identical-custom/on, downgrade, and
Fedora-stable — across the entire timed scenario/index matrix, run:

```bash
bin/run-full-fedora-screen
```

The command runs all 116 timed scenarios under their six required index
configurations for each state. The two remaining generated scenarios are
dynamic-list correctness controls, not timing comparisons, and are intentionally
excluded from this arbitrary-git-build screen. No RPM is built or staged. The
script uses bounded scenario batches and writes 40 self-contained raw bundles
for the normal openldap/off/on/stable sequence (30 with `LF_OPENLDAP=off`),
plus `REPORT.md`, `summary.csv`, `comparisons.csv`, `openldap-context.csv`,
and `screen-summary.json`. Every report row includes the manifest's short
description of the filter structure.

The OpenLDAP state requires the packaged `openldap-servers` and
`openldap-clients` RPMs (never a custom OpenLDAP build) and runs first, before
any 389 DS package operation. Its rows are a contextual comparison in the sense
of section 9: cross-server differences are unavoidable implementation
differences, so the report presents OpenLDAP medians and custom-to-openldap
ratios, never benefit percentages, and none of it is release evidence. The
formal matched cross-server instrument remains the
`final-on-vs-openldap-acceptance` ABBA block in section 9.

The command is resumable: rerun it with the same output directory. Matching
complete bundles are skipped, incomplete bundles are archived under
`incomplete/`, and an hourly referral-monitor boundary retries the affected
whole bundle once without admitting its contaminated measurements.

If the installed custom commit no longer contains the OR lookup configuration
switch, as expected for a true OR-feature revert, the script detects that from
the RPM's git commit and runs one `custom-unsupported` matrix instead of trying
invalid off/on states. That layout writes 20 raw bundles.

The defaults are 15 measured searches, two warm-ups, CPU 2, and perf/profile
collection off, so this works on the PMU-limited Fedora VM used for the minimal
screen. Optional overrides are `LF_REPEAT`, `LF_WARMUPS`, `LF_PREWARM_PASSES`,
`LF_OPENLDAP`, `LF_CPU`, `LF_PERF`, `LF_PROFILE`, and `LF_WORKLOAD`. For
example, a host with usable counters can request `LF_PERF=auto LF_PROFILE=auto
bin/run-full-fedora-screen`.

Every warm-cache native invocation begins with a state pre-warm: after server
setup and before any diagnostic or timed search, the runner executes
`LF_PREWARM_PASSES` (default 3) full-database `(objectClass=*)` scans with
`1.1` attributes. Screen states run as separate sequential invocations, so
without the pre-warm the later states always start on a warmer host and
same-binary comparisons inherit an order bias. The passes are recorded as
`state_prewarm` evidence in each run manifest, never as result rows, and the
pre-warm policy is part of the timing-environment signature, so rows produced
under the old protocol cannot silently pool with pre-warmed rows. The cold
cache policy is unaffected (`--prewarm` resolves to not-applicable there).

Like the minimal command, this is a directional screen. Its stable-to-custom
comparisons contain every intervening package change, and its fixed execution
order is not the formal ABBA release schedule.

Set `LF_EXPECTED_SOURCE` to the commit under review to make the preflight
assert that the installed RPM's embedded git hash is that commit; a mismatch
aborts before any state runs. When unset, the preflight only records the
observation in `provenance.json` at the output root and prints a prominent
warning (also kept in `logs/provenance-preflight.log`). The record includes
whether the observed commit is an ancestor of the harness checkout's HEAD and
`git describe --always --dirty` of the checkout that generates the workload;
REPORT.md and `screen-summary.json` surface the outcome.

When the generated workload contains the `drift-canary` scenario group, the
wrapper automatically appends the matching `drift-canary-<index-config>`
scenario to every bundle in every state, giving the statistical appendix ten
wall-clock-ordered canary medians per state. Workloads generated before the
canary and the sub-threshold `branch-count-{4,8}-*` rungs existed keep working
unchanged — the wrapper prints a warning and the appendix falls back to the
cross-state `branch-count-15-zero-candidate` anchor. To gain the new
scenarios, regenerate the workload into a fresh `LF_WORKLOAD` directory.
Regenerating changes the workload identity hash, so old-workload and
new-workload bundles cannot be co-merged by `bin/merge-results` (the workload
contract is a hard equality check) and the frozen
`workload/native-matrix-plan.json` identity remains bound to the original
118-scenario workload; compare the two generations side by side through their
screen reports instead.

Alongside the legacy outputs, the screen now also writes
`statistical-appendix.md` (per-stratum Mann-Whitney tests, the zero-candidate
CPU-versus-branch-count slope, and drift diagnostics) and appends to
REPORT.md: a provenance line, the off→on noise band computed from the
no-effect strata (the sub-threshold shapes where the lookup cannot engage),
in-cell markers on the off→on benefit column (`†` exceeds the band, `~`
within it, trailing `‡` for an elapsed-only or CPU-only move), an
`## Environment capture` section from each bundle's `environment.json`
sidecar, and an `## Attempt hygiene` section reconstructing retries from
`logs/` and `incomplete/`. All raw numbers, CSV columns, and
`screen-summary.json` fields are preserved; new columns and fields are only
appended. `bin/regenerate-screen-report RUN_DIR --output DIR` re-renders any
existing run directory (old runs included — missing inputs degrade to
"unavailable") without touching its files.

Because the harness identity hash covers `bin/` and `study/`, resuming an
output directory that was started under an older harness fails the
summarizer's outer-wrapper-only tolerance after the measurements complete.
Start post-upgrade reruns in a fresh output directory; old directories remain
fully readable through `bin/regenerate-screen-report`.

## 5. Run the primary native rows

All examples below use warm cache, 20 measured repetitions, three untimed
warm-ups, MDB, CPU 2, mandatory perf collection, and automatic principal
profiling. Adjust CPU only before the schedule starts and then keep it constant.
With `--repeat 20 --perf on`, each scenario/attribute stratum produces 20
independent one-search perf batches; at least 15 usable instruction batches are
required for instruction statistics.

Each scenario selected for profiling runs exactly 20 additional isolated
searches inside one perf-record window. Every profiled search must pass the
exact-DN oracle and both client and server result-code checks. The bundle stores
the 20-operation ledger, the hashed `perf.data`/report, and the observed profile
collection class/signature. These profile searches are attribution evidence;
they are not additional elapsed-time repetitions.

### Pre-series row

With the externally built pre-series RPM already installed in a clean snapshot:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label pre-series-6e1e9337-acceptance-a1 \
    --expected-source-sha pre-series \
    --lookup unsupported \
    --workload "$workload_dir" \
    --output "$results_root/pre-series-acceptance-a1" \
    --scenario-group acceptance \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design abba \
    --schedule-block pre-vs-final-on-acceptance \
    --schedule-position A1 \
    --cleanup
```

### Final lookup-on row

Restore the clean snapshot and have the operator install the final RPM outside
this benchmark. Then run:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label final-e0161d0e-lookup-on-acceptance-b1 \
    --expected-source-sha final \
    --lookup on \
    --workload "$workload_dir" \
    --output "$results_root/final-lookup-on-acceptance-b1" \
    --scenario-group acceptance \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design abba \
    --schedule-block pre-vs-final-on-acceptance \
    --schedule-position B1 \
    --cleanup
```

### Same final RPM, lookup off

From a restored clean snapshot containing that exact same final RPM:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label final-e0161d0e-lookup-off-acceptance-a1 \
    --expected-source-sha final \
    --lookup off \
    --workload "$workload_dir" \
    --output "$results_root/final-lookup-off-acceptance-a1" \
    --scenario-group acceptance \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design abba \
    --schedule-block final-off-vs-on-acceptance \
    --schedule-position A1 \
    --cleanup
```

`run-fedora-study` forces native timing mode. Do not pass an OrbStack host class;
native metadata is recorded as `fedora_native`, `correctness_only: false`, and
`release_timing_evidence: true`.

## 6. Use clean-snapshot ABBA scheduling

One runner invocation always creates a fresh server instance/database, imports
the full data, creates/reindexes the requested indexes, gates correctness and
mechanisms, measures, and cleans up. That does not replace clean package/OS
state between revisions. Restore the matching clean snapshot before **every**
ABBA position.

For a pre-series versus final-lookup-on comparison, schedule:

| Position | Snapshot/package | Structured schedule flags |
|---|---|---|
| A1 | clean pre-series RPM | `--schedule-design abba --schedule-block pre-vs-final-on-acceptance --schedule-position A1` |
| B1 | clean final RPM, lookup on | `--schedule-design abba --schedule-block pre-vs-final-on-acceptance --schedule-position B1` |
| B2 | restore clean final RPM again, lookup on | `--schedule-design abba --schedule-block pre-vs-final-on-acceptance --schedule-position B2` |
| A2 | restore clean pre-series RPM again | `--schedule-design abba --schedule-block pre-vs-final-on-acceptance --schedule-position A2` |

Repeat the exact commands in section 5 with new labels/output directories and
the corresponding schedule position. Do not reuse a retained instance. Keep the
four directories on durable storage so snapshot rollback cannot remove them.
The block identifier must be the same stable 1-128 character identifier in all
four invocations; changing it creates a different, incomplete block.

Run a second ABBA block where A is final lookup-off and B is final lookup-on.
Both sides restore the same clean final-RPM snapshot before each position. This
block isolates the switch without package/build differences. Use
`--schedule-design abba --schedule-block final-off-vs-on-acceptance` on all four
invocations and record `A1`, `B1`, `B2`, and `A2` with
`--schedule-position`. For longer matrices, alternate or predeclare randomized
blocks. `--scenario-order randomized` controls only scenario order inside one
invocation and is not a substitute for cross-build ABBA.

Schedule the direct packaged-OpenLDAP context in its own matched ABBA block as
well—for example, A as final lookup-on and B as packaged OpenLDAP—restoring the
corresponding clean snapshot at A1/B1/B2/A2. Keep the underlying Fedora host,
kernel, client, affinity, storage, memory, cache, and workload contract fixed;
only the declared server/package implementation may differ. Use one stable
block identifier such as `final-on-vs-openldap-acceptance` for all four
positions.

Apply that rule to **every timed comparison required by
`workload/native-matrix-plan.json`**, including bounded-feature attribution,
flat-family attribution, the final success-path check, and packaged OpenLDAP.
A block may cover several required scenarios when all four invocations select
the exact same scenario set and protocol. Each planned comparison cell must
still resolve to exactly one complete, matching block. One-off commands declared
with `--schedule-design screen` are exploratory and never satisfy this
requirement, regardless of repeat count or effect size.

Use separate result sets for cold cache. Do not compare a warm row with a cold
row or change the connection policy mid-matrix. The current runner records
`new-connection-per-search`.

### A/A same-configuration noise pass (diagnostic)

An A/A pass measures one identical binary and configuration twice as separate
sessions, giving an empirical noise yardstick for the same-hardware deltas the
screen reports. With the same custom RPM still installed (verify
`sha256sum /usr/bin/ns-slapd` is unchanged), re-run the custom-off state's ten
bundle invocations exactly as the full screen issued them — same section 5
`run-fedora-study` template, same `--lookup off`, the same
`--scenario-group`/`--scenario` batches and `--index-config` per bundle, the
same repeat/warm-up/CPU/cache flags, `--schedule-design screen`, and the same
`--schedule-position` values — into a **second** results directory, then merge
both sets:

```bash
bin/merge-results \
    "$first_screen/results/custom-off"/* \
    "$second_pass/custom-off"/* \
    --output "$results_root/aa-custom-off"
```

`RESULTS.md` gains an "A/A same-configuration deltas (diagnostic,
non-release)" section: per-stratum session medians (sessions ordered by
run-manifest `created_at`; earlier = A), signed deltas, and the |delta|
distribution (median/p95/max) usable as a noise yardstick. A/A output is a
diagnostic, never release evidence and never a gate input. Keep A/A merges in
their own output directory and do not feed the duplicate-session directories
into a release merge: the merger pools same-configuration rows across runs
(doubling n) by design.

### Reverse-order second pass (operator-level ABBA alternative)

The cheap alternative to a full clean-snapshot ABBA block is a second pass
with the states manually issued in reverse order (`stable → custom-on →
custom-off → openldap`), using the per-state section 4/5 invocations in that
order into a second directory. The screen script's internal order is fixed;
the reverse pass is operator-sequenced. Merging both passes labels the A/A
section's "Pass order across sessions" as `reverse`, which is descriptive
only: it never creates ABBA blocks, never satisfies
`workload/native-matrix-plan.json`, and changes no scheduler behavior.

### Harness identity across A/A sessions

Run manifests bind `harness_identity.content_sha256`, and the merger rejects
native release-candidate bundles carrying different harness hashes. Complete
both A/A sessions from one unchanged study checkout; if the harness was
upgraded in between, the pair cannot merge as native evidence — re-run the
first session under the new harness. Non-release bundles still merge, and the
A/A table then flags the pair with "harness differs".

## 7. Expand the scenario and index matrix

Repeatable `--scenario-group` selects manifest groups; repeatable `--scenario`
selects exact shapes. One invocation may contain several groups when all selected
scenarios use the same index configuration. The full baseline matrix should
cover:

```text
acceptance
candidate-scaling
branch-scaling
hit-position
fallbacks
multivalue-scaling
dn-normalization
decomposition
combined-substring
combined-approximate
branch-order
flat-family
dynamic-list-correctness
```

The dynamic-list group is correctness-only inside the native bundle and is not
timed. The combined approximate group enters the direct OpenLDAP table only if
native preflight confirms sufficiently equivalent semantics; otherwise report
it as a 389 DS parent/child result with the implementation difference recorded.

Index variants require distinct fresh-instance invocations. Use these exact
scenario/configuration pairs:

| Index configuration | Exact scenarios |
|---|---|
| `baseline-no-presence` | `presence-primary-none`, `presence-no-sdn2-none`, `candidate-index-all-equality` |
| `presence-sdn1` | `presence-primary-sdn1` |
| `presence-sdn2` | `presence-primary-sdn2` |
| `presence-both` | `presence-primary-both`, `presence-no-sdn2-both` |
| `without-sdn1-equality` | `candidate-index-without-sdn1` |
| `without-sdn2-equality` | `candidate-index-without-sdn2` |

For example, the final lookup-on `presence-both` boundary pair is:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label final-e0161d0e-lookup-on-presence-both \
    --expected-source-sha final \
    --lookup on \
    --workload "$workload_dir" \
    --output "$results_root/final-lookup-on-presence-both" \
    --scenario presence-primary-both \
    --scenario presence-no-sdn2-both \
    --index-config presence-both \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design screen \
    --schedule-position final-on-presence-both-screen \
    --cleanup
```

Run equivalent index-intent rows for lookup-off and packaged OpenLDAP where the
matrix requires them. Treat the observed final backend candidate count as a
mediator: the structural 612 logical outer cohort is not a promise that every
index variant produces a 612-ID backend list.

The mechanism preflight and postflight are outside the timed window and use only
existing production diagnostics. They check exact DNs and client/server result
codes, expected lookup-table construction, largest-family value, lookup-off
suppression, bounded-read cap messages, adverse/decline non-engagement,
candidate-list trace when uniquely observable, STAT index reads, and access-log
`notes=U` as recorded observations. Family selection uses a separate isolated
base-object FILTER probe; approximate semantics use two isolated base-scope
probes. A construction message does not prove that the evaluator probes/consumes
the table, and `notes=U` is not a candidate-count oracle. Establish those causes
with lookup-off/on A/B, isolated candidate traces, index controls, and hashed
profiles.

Retain every production candidate trace, including traces that cannot be
attributed to one exact operation. When any retained candidate trace remains
unattributed, keep the final candidate count `null` and record status
`not-directly-observable-unattributed-traces`. Never infer a count of `22`, a
maximum, or an ordering from trace candidates.

### Background-operation isolation

Every 389 DS invocation establishes a quiet collection epoch before any
diagnostic, timing, perf, or profile operation. The runner sets access-log level
`260` so internal work is visible and sets `nsslapd-referral-check-period` to
`3600`, verifies both values, then performs one final controlled
stop/cursor/start and verifies the readbacks again. Startup is not considered
quiet until two ordered barriers pass:

- the referral monitor's internal `objectClass=referral` STAT start and the
  later completion belong to the same internal operation identity; and
- the delayed three-second `vattr_check` search uses exactly
  `(&(objectclass=ldapsubentry)(|(objectclass=nsRoleDefinition)(objectclass=cosSuperDefinition)))`,
  has a later successful result for the same operation identity, and is followed
  by one second with no new root-internal lines.

The quiet epoch is anchored to `CLOCK_MONOTONIC` hour buckets, not wall-clock
time. Every collected operation records its start/end, the next 3600-second
boundary, and a five-second safety deadline. Crossing that deadline is a hard
failure: preserve the incomplete bundle, wait for the next bucket, and rerun or
split the invocation. Do not waive the boundary because an LDAP result happened
to be correct. Root maintenance operations and referral-monitor lines are never
allowed inside a collection window. A planned dynamic-list nested search is
accepted only when it remains on the target external connection; cross-
connection nested work is rejected. OpenLDAP records this 389 DS control as not
applicable and receives no timing inference from it.

## 8. Bounded-feature and attribution rows

The causal bounded-feature comparison is pre-series (A) versus bounded-feature
(B), not Fedora stable versus HEAD-off. Restore the corresponding clean package
snapshot for each position and use one complete ABBA block. With the
bounded-feature RPM already installed, the following command is its B1
position:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label bounded-feature-fde13723-combined-b1 \
    --expected-source-sha bounded-feature \
    --lookup unsupported \
    --workload "$workload_dir" \
    --output "$results_root/bounded-feature-combined-b1" \
    --scenario-group combined-substring \
    --scenario-group combined-approximate \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design abba \
    --schedule-block pre-vs-bounded-combined \
    --schedule-position B1 \
    --cleanup
```

Run the same combined groups at pre-series A1/A2 and bounded-feature B1/B2,
always with
`--schedule-design abba --schedule-block pre-vs-bounded-combined` and the
corresponding exact position. Run the combined groups separately on the final
RPM with lookup off and on. Use
`combined-diagnostic` only as an optional diagnostic row. Do not expand
`all-family-fix` and `largest-family-fix` through the combined matrix; their
attribution belongs in `flat-family`. This standalone command is a focused
screen; a release attribution claim requires its own complete matched ABBA
block:

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server 389ds \
    --build-label largest-family-fix-9c23a6e4-flat-family \
    --expected-source-sha largest-family-fix \
    --lookup on \
    --workload "$workload_dir" \
    --output "$results_root/largest-family-fix-flat-family" \
    --scenario-group flat-family \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design screen \
    --schedule-position largest-family-flat-screen \
    --cleanup
```

Use the same form with `all-family-fix` and final to isolate third-family
discovery, largest-family selection, unsupported-family fallback, and
deterministic equal-size ties. Run `dynamic-list-correctness` on the immediate
parent `7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6` when supplied,
`dynamic-list-fix`, and final; do not put its elapsed values in
principal/OpenLDAP comparisons. The parent's observed admin-limit/mechanism
failure is retained only as an expected historical control; `dynamic-list-fix`
and final must pass all four isolated operations and must not engage the old
bounded-read cap. Compare `largest-family-fix` with
final only on a small representative successful equality-OR, bounded-substring,
and combined subset to confirm the abort-path ownership cleanup did not regress
ordinary success paths.

## 9. Packaged OpenLDAP comparison

Use a clean native Fedora snapshot with the normal Fedora
`openldap-servers` package. Do not custom-build OpenLDAP. The runner creates a
private packaged-MDB instance, applies the equivalent synthetic schema and index
intent, imports `data-openldap.ldif`, and uses the same packaged `ldapsearch`
client and administrative bind class.

```bash
sudo "$study_root/bin/run-fedora-study" \
    --server openldap \
    --build-label openldap-fedora-package-acceptance-b1 \
    --expected-source-sha fedora-package \
    --lookup unsupported \
    --workload "$workload_dir" \
    --output "$results_root/openldap-fedora-package-acceptance-b1" \
    --scenario-group acceptance \
    --index-config baseline-no-presence \
    --backend mdb \
    --repeat 20 \
    --warmups 3 \
    --cache-policy warm \
    --cpu 2 \
    --perf on \
    --profile on \
    --schedule-design abba \
    --schedule-block final-on-vs-openldap-acceptance \
    --schedule-position B1 \
    --cleanup
```

This is the B1 position of the matched block from section 6. Collect final
lookup-on at A1/A2 and packaged OpenLDAP at B1/B2 under that same block ID.

Repeat the comparable scaling, presence, fallback, DN-normalization,
decomposition, combined-substring, and branch-order groups under the same
host/client/cache discipline. Do not force OpenLDAP to model 389 DS ACL
three-valued semantics. Keep 389 DS-specific proxy/ACL and dynamic-list controls
outside the direct ratio table, and record every unavoidable schema/index/
approximate-matching or diagnostic difference. An approximate ratio is eligible
only when both implementations pass the same positive-identical and
negative-dissimilar isolated base-scope probes under one semantic-contract hash;
otherwise exclude the ratio and report the implementation difference.

## 10. Optional focused pytest contract check

This is a separate, optional functional preflight when the source checkout and
test dependencies are already available. It is not part of the default runner,
must not run inside a timed block, and must not become a benchmark result row:

```bash
python3 -m pytest -q \
    dirsrvtests/tests/suites/filter/filter_bounded_substring_test.py \
    dirsrvtests/tests/suites/filter/filter_or_lookup_test.py \
    dirsrvtests/tests/suites/filter/filter_large_filter_interaction_test.py \
    dirsrvtests/tests/suites/filter/filter_large_filter_ownership_test.py \
    dirsrvtests/tests/suites/filter/filter_or_union_test.py
```

Native timing depends on the benchmark's own full-workload exact-DN gate and
mechanism preflight, not on pytest availability.

The separate standard-library harness unit suite discovers its current test
count at runtime. From the study root, rerun it with:

```bash
python3 -m unittest discover -s tests -v
```

That suite validates the harness contract; its pass count is not native timing
evidence.

## 11. Verify and retain each result bundle

After every invocation, require a completion marker and inspect the disposition.
The following strict check is for a full-release 389 DS bundle collected with
`--perf on --profile on`; it intentionally rejects a software-perf screen:

```bash
test -f "$results_root/final-lookup-on-acceptance-b1/COMPLETE"

python3 - "$results_root/final-lookup-on-acceptance-b1" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
records = {
    name: json.load(open(root / name, encoding="utf-8"))
    for name in (
        "artifact-manifest.json", "run-manifest.json",
        "correctness.json", "raw-results.json",
    )
}
for record in records.values():
    assert record["host_class"] == "fedora_native"
    assert record["correctness_only"] is False
    assert record["release_timing_evidence"] is True
    assert record["timing_claims_allowed"] is True
run = records["run-manifest.json"]
artifact = records["artifact-manifest.json"]
raw = records["raw-results.json"]
assert run["status"] == "complete" and run["correctness_status"] == "pass"
assert run["copied_workload_verified"] is True
assert run["harness_identity"]["git_evidence_status"] == "observed"
assert run["harness_identity"]["git_study_tree_clean"] is True
assert len(run["harness_identity"]["git_head"]) == 40
assert len(artifact["behavioral_runtime_identity_sha256"]) == 64
setup = run["server_setup"]
assert setup["lookup_mode_evidence"]["passed"] is True
assert setup["index_build_evidence"]["passed"] is True
assert setup["index_contract_evidence"][
    "all_workload_controlled_indexes_exact"
] is True
assert setup["effective_schema"]["custom_schema_verification"]["passed"] is True
assert setup["import_verification"]["passed"] is True
assert setup["import_verification"]["oracles"]["people"]["actual_count"] == 100000
assert setup["import_verification"]["oracles"]["principal_outer_cohort"][
    "actual_count"
] == 612
background = setup["background_referral_check_control"]
assert background["requested_seconds"] == 3600
assert background["pre_restart_readback"] == "3600"
assert background["post_restart_readback"] == "3600"
assert background["final_restart_method"] == "controlled-stop-cursor-start"
assert background["clock"] == "CLOCK_MONOTONIC"
assert background["safety_margin_seconds"] == 5.0
assert background["barrier"]["status"] == "observed-complete"
assert background["barrier"]["unmatched_referral_start_count"] == 0
vattr = background["post_restart_vattr_check_barrier"]
assert vattr["status"] == "observed-complete" and vattr["passed"] is True
assert vattr["delay_seconds"] == 3 and vattr["stability_seconds"] == 1.0
assert vattr["stability_no_new_root_internal_lines"] is True
access_control = background["access_log_internal_operation_control"]
assert access_control["requested"] == 260
assert access_control["post_restart_readback"] == "260"
assert setup["server_thread_affinity"]["status"] == "verified"
assert setup["server_thread_affinity_pre_timing_checks"]
assert all(
    check["status"] == "verified"
    for check in setup["server_thread_affinity_pre_timing_checks"].values()
)
rows = {row["row_id"]: row for row in raw["rows"]}
assert run["perf_collection_classes"] == ["hardware-events"]
for batch in raw["perf_batches"]:
    assert batch["operation_count"] == 1 and len(batch["row_ids"]) == 1
    assert batch["collection_class"] == "hardware-events"
    assert rows[batch["row_ids"][0]]["perf_batch_id"] == batch["batch_id"]
for profile in run["profiles"]:
    assert profile["status"] == "observed"
    assert profile["operation_count"] == 20
    assert len(profile["operations"]) == 20
    assert profile["collection_class"] in {
        "hardware-sampling", "software-cpu-clock",
    }
    assert all(
        operation["exact_result"]["passed"] is True
        and operation["server_result_evidence"]["passed"] is True
        for operation in profile["operations"]
    )
print(run["run_id"], run["workload_sha256"], len(raw["perf_batches"]))
PY
```

Retain the whole result directory, the exact generated workload, the exact RPM
file in the operator's external artifact store, and its SHA-256. Do not edit
manifests or raw rows. An `INCOMPLETE` or `CLEANUP-FAILED` directory is useful for
diagnosis but is not release evidence. If `--retain` was used, remove the
diagnostic instance through normal package tooling before restoring the clean
snapshot; never reuse it for timing.

Each bundle is self-contained for audit: alongside the root comparison copy of
`workload-manifest.json`, `workload/` contains every data, filter, expected-DN,
schema, index, and study-spec payload named by the manifest. Preserve that
payload copy; the merger verifies its bytes when present.

## 12. Merge independent directories

Copy or mount all completed directories into one analysis checkout. Merge only
bundles from a compatible timing environment:

```bash
cd "$study_root"

# This is one complete progress-audit block. Add all four positions from every
# other required native-matrix block before treating the merge as a release run.
bin/merge-results \
    "$results_root/pre-series-acceptance-a1" \
    "$results_root/final-lookup-on-acceptance-b1" \
    "$results_root/final-lookup-on-acceptance-b2" \
    "$results_root/pre-series-acceptance-a2" \
    --output "$results_root/merged-native-acceptance"
```

The output is atomic and contains `merged-raw-results.json`, a merged
`artifact-manifest.json`, and generated `RESULTS.md`. Omitting required blocks
is valid for a progress audit, but it deliberately leaves matrix completion and
the release recommendation pending. The merger:

- validates complete workload/schema/filter/expected/index/scenario contracts;
- rejects any bundle without a valid `COMPLETE` marker, with an
  `INCOMPLETE`/`CLEANUP-FAILED` marker, or whose run manifest is not complete;
- requires a compatible native host signature for release bundles;
- preserves every raw row and correctness disposition;
- excludes warm-ups, incorrect rows, non-RPM identities, emulated
  rows, and correctness-only rows from release summaries;
- validates one-search perf batches and their bidirectional row links, then
  derives instruction statistics only from unique independent batches;
- verifies observed perf/profile collection classes and signatures and keeps
  hardware and software-fallback strata separate;
- loads `workload/native-matrix-plan.json`, expands each timed
  pair/scenario/attribute cell and correctness control into
  `matrix_completion`, and requires one complete matching ABBA block for every
  required timed comparison;
- calculates median and nearest-rank p95 and emits all ten predeclared gates,
  including every missing/pending instance and reason;
- deduplicates identical run bundles, retains executable aliases, and pools
  performance only when the combined behavioral runtime identity matches.

Both merged JSON files contain the matrix-plan hash, `matrix_completion`,
`schedule_assessment`, and `release_conclusion`; generated `RESULTS.md` renders
their status, counts, and reasons. The conclusion becomes
`pass`/`eligible-for-release` only when the matrix and schedule are complete and
all ten gates pass. A gate or matrix failure produces
`fail`/`do-not-release`; otherwise the conclusion remains
`pending`/`withheld`. In particular, software `task-clock` fallback cannot
complete the matrix's hardware-PMU requirement.

If native signatures differ, merge each timing environment separately. Do not
use `--unsafe-include-nonrelease` for a release report; that option only adds a
clearly marked descriptive appendix and cannot promote OrbStack rows.

Transfer validated values and profile conclusions into the root study
[RESULTS.md](RESULTS.md), preserving its evidence boundary, hypotheses,
classification vocabulary, remaining uncertainties, and release recommendation.
The generated status `native-results-available` only reports that eligible
native rows exist; it is not a full-matrix completeness or release gate.
Standalone `screen` runs remain useful evidence in their explicitly exploratory
role, but they cannot make a required matrix instance or release conclusion
pass.

Every merge additionally appends an "A/A same-configuration deltas
(diagnostic, non-release)" section to `RESULTS.md` and an `aa_comparisons` key
to `merged-raw-results.json` (see section 6 for the operator recipe). Merges
without duplicate-configuration sessions simply report that none were
detected; bundles recorded before `created_at`/schedule stamping show `—` for
session timestamps and positions. Drift-canary strata are excluded from A/A
pairing (their within-session repeats are by design) and get their own
repeatability subsection.
