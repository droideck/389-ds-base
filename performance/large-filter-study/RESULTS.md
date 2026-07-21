# Complete large-filter series study results

Status: **native-results-pending**

No native Fedora timing bundle has been supplied or merged. No release timing,
p95, CPU, instruction, cache, RSS, profile, 389 DS/OpenLDAP ratio, acceptance,
regression, or release conclusion can be drawn yet. This file is the
predeclared report template to complete from validated native bundles.

No number from the legacy `reproducer/` reports is included here. Designed
workload dimensions such as 100,000 entries, a 612-entry logical cohort, and 355
DN assertions are study inputs, not measured performance results.

## Evidence boundary

| Evidence class | Required metadata | Status | Allowed interpretation |
|---|---|---|---|
| Native Fedora installed-RPM run | `host_class: fedora_native`; `correctness_only: false`; `release_timing_evidence: true` | **PENDING** | May enter release tables only after workload, package, correctness, host, and repeat gates pass |
| macOS/OrbStack Phase A validation | `host_class: macos_orbstack_emulated`; `correctness_only: true`; `release_timing_evidence: false` | **PASS: attempt15; four bundles; 85 raw rows** | Generator/schema/index/import/search/mechanism/artifact/merge/cleanup validation only; never timing evidence |
| Full workload generation/hash audit | deterministic full profile and every manifest payload hash | **PASS: 118 scenarios; 242 payloads** | Generator/oracle evidence only; no server or timing conclusion |
| Local study unit tests | test process only; no server timing row | **PASS on 2026-07-20** | Harness validation only; not an OrbStack smoke or release evidence |
| Optional focused pytest | separate test record | **PENDING/OPTIONAL** | Functional contract evidence only; never benchmark timing evidence |
| Legacy reproducer material | legacy formats and unavailable raw audit bundles | **EXCLUDED** | Historical context only; no value may be copied into this report |

The successful Phase A smoke is scoped to the separate correctness-only record
below. Its elapsed and CPU fields remain outside every native table. The default
merger was used without its unsafe descriptive-appendix option and emitted no
release summaries, comparisons, scaling tables, or OpenLDAP contextual timing.

## Phase A OrbStack correctness-only validation

Attempt15 completed successfully on an Apple M4 Pro host. It validates the
installed-artifact flow and the selected correctness/mechanism paths through
four real server bundles. It is not a native Fedora measurement and permits no
timing, CPU, profile, ratio, regression, acceptance, or release claim. The
authoritative record is
`results/orbstack-smoke-e0161d0e-attempt15/smoke-summary.json`.

| Field | Exact observation | Status/disposition |
|---|---|---|
| Run identity | `lfsmoke-37608-5c9209ece5`; created `2026-07-21T01:11:36.379527Z`; completed `2026-07-21T01:30:34.031625Z` | **PASS** |
| Evidence flags | `host_class: macos_orbstack_emulated`; `correctness_only: true`; `release_timing_evidence: false`; `timing_claims_allowed: false` | Correctness/artifact evidence only |
| Smoke workload | `smoke-69fb2ee3d5ceb1b9`; SHA-256 `69fb2ee3d5ceb1b9980f70c278944d34443fd1fd4caa74fa044c2c493575acfc` | **PASS** |
| `389ds-lookup-on-baseline` | 40 scenarios; 40 raw rows; lookup on; `baseline-no-presence` | **PASS** |
| `389ds-lookup-off-subset` | 15 scenarios; 17 raw rows; lookup off; `baseline-no-presence` | **PASS** |
| `389ds-lookup-on-presence-both` | 2 scenarios; 2 raw rows; lookup on; `presence-both` | **PASS** |
| `openldap-parity-subset` | 24 scenarios; 26 raw rows; lookup unsupported; `baseline-no-presence` | **PASS** |
| Four-bundle total | 81 selected scenario executions; 85 raw rows | **PASS** |
| Default merge | four source runs; 85 raw rows; `unsafe_include_nonrelease: false`; zero release-eligible rows | **PASS**; merged status remains `native-results-pending` |
| Default-merge release arrays | `release_summaries: 0`; `release_comparisons: 0`; `release_scaling_tables: 0`; `openldap_contextual_comparisons: 0`; `unsafe_nonrelease_summaries: 0` | **PASS**; no timing escaped the evidence boundary |
| 389 DS container isolation | three distinct fresh containers; identical image, installed NEVRAs, executable/build/runtime/backend/behavioral/harness identity, and clean strict `rpm -V` | **PASS** |
| Local RPM input revalidation | inventory identity `f7b5be1eb3a7996d8c816bab896e4dbb4f478cd88e046ebce678f5dd4a4286fe`; checked before each 389 DS container and after all runs (four checks) | **PASS** |
| Cleanup | remove policy; four of four containers verified absent; no labeled container IDs remain | **PASS** |

The asserted full 389 DS source revision is
`e0161d0e61d0cdef22175418f0d4a1e126216a86`. The RPM package token is only the
10-hex prefix `e0161d0e6`: it corroborates the assertion but does not
independently prove the full 40-hex SHA. The immutable RPM and live installed
identities below are therefore part of the Phase A evidence.

### Phase A 389 DS installed identity

The following identity was identical in all three distinct 389 DS containers,
and strict `rpm -V` was clean in each container.

| Identity field | Exact value |
|---|---|
| Installed NEVRAs | `389-ds-base-3.3.0.202607201823gite0161d0e6-1.fc42.x86_64`; `389-ds-base-libs-3.3.0.202607201823gite0161d0e6-1.fc42.x86_64`; `python3-lib389-3.3.0.202607201823gite0161d0e6-1.fc42.noarch` |
| Owning package/NEVRA | `389-ds-base-3.3.0.202607201823gite0161d0e6-1.fc42.x86_64` |
| Executable | `/usr/bin/ns-slapd` |
| Executable SHA-256 | `2b0eaa74af679ee320d6d0b088ea9819b8b9c9d73e0285622e55735c099ed596` |
| ELF build ID | `145d0611742e65ae1c370aaa670de9564ea7c953` |
| Direct-linked runtime closure SHA-256 | `5c9c30560195fe1577433e3967049fd5f7003aa1f6362865f6742f6f2d914fa2` |
| Live-backend runtime closure SHA-256 | `9c2fd5f1aee08783bc4535e629bda28d2cad6d5a1e19224594c0a411b2d620dd` |
| Behavioral runtime identity SHA-256 | `f2d5f97c78a863f4734715678b61274123ab28b9481a6c5a8ed3dba84555c67c` |
| Harness-content SHA-256 | `c29646eb0c71dbf8ff336da2738d2caf46618a8bccee7b8b72216bc6f7e32992` |
| `389-ds-base` RPM SHA-256 | `b2eee041b4b715ff533f81fa6239c6dd61af0a03c7dfd0cbe6101cd364550ff1` |
| `389-ds-base-libs` RPM SHA-256 | `9895d949ae34ac89aec7b3785ef9d06ff0d9d295b70ff5914a79876637440c01` |
| `python3-lib389` RPM SHA-256 | `3af81f31bf73ddd2b32e6b4c325750c70ac3140e55a4ca094c5fbfa4aef89fe3` |

### Phase A packaged OpenLDAP installed identity

| Identity field | Exact value |
|---|---|
| Installed NEVRAs | `openldap-servers-2.6.13-1.fc42.x86_64`; `openldap-clients-2.6.13-1.fc42.x86_64` |
| Owning package/NEVRA | `openldap-servers-2.6.13-1.fc42.x86_64` |
| Package verification | exact owning package; `rpm -V` clean |
| Executable | `/usr/bin/slapd` |
| Executable SHA-256 | `741cb41a5c8e8dc7f2d3989dd8f26464e59be36e5a58040906b9de29e6a7bb38` |
| ELF build ID | `0d55c011513a5c7aef4eb687a1d7a0d7932daa95` |
| Direct-linked runtime closure SHA-256 | `9986d85191cf7361accf23bb78a087e7b13dffe845e3da6be4a1eacbdeb3af43` |
| Live/static-backend runtime closure SHA-256 | `bc1925b5047e503385b119b5eeb7d2b4064c611c266330d05a20e4e7b5545e4b` |
| Behavioral runtime identity SHA-256 | `99d5c91b1190dec9c534085d0bd9befd6ebc7633f70f26c932fca9297042128f` |
| Harness-content SHA-256 | `c29646eb0c71dbf8ff336da2738d2caf46618a8bccee7b8b72216bc6f7e32992` |

### Phase A platform boundary

| Layer | Exact observation |
|---|---|
| Physical host | Apple M4 Pro; Darwin/macOS `arm64` |
| Container service | Docker context `orbstack`; OrbStack server `29.4.0`; server architecture `aarch64`; Rosetta enabled |
| OrbStack kernel | `7.0.11-orbstack-00360-gc9bc4d96ac70` |
| Guest probe | Fedora 42; `x86_64`; container platform `linux/amd64` |
| 389 DS image | `quay.io/389ds/ci-images:test`; image ID `sha256:aa3284e73f32483805d3eac4b4ee2d4b90a9259836982b5c15f161d5c319b785` |
| OpenLDAP image | `fedora:42`; image ID `sha256:99e203b80b1c3d8f7e161ec10a68fd02b081ef83a3963553e513c82846b97814` |

All native artifact, timing, p95, CPU, perf, profile, ratio, acceptance, and
release ledgers below remain `PENDING`. Nothing in this Phase A section may be
used as evidence that one server, revision, lookup mode, or index configuration
is faster, slower, improved, regressed, or equivalent to another.

## Result classification vocabulary

Once evidence exists, classify every comparison using exactly one of:

- **demonstrated improvement**;
- **no material change**;
- **regression**;
- **expected decline/fallback**;
- **unverified due to missing mechanism evidence**;
- **unavoidable implementation difference**.

`PENDING` below means no result exists and therefore no classification has been
assigned. Do not replace `PENDING` with a causal claim based only on filter
appearance, a lookup-construction message, the cap-path message, `notes=U`, or
returned `nentries`.

The merger's `native-results-available` status, once reached, means only that it
found eligible native rows. It does not establish matrix completeness or make a
release recommendation; the ledgers and gates below remain authoritative.

## Study identity

| Field | Required value | Observed value | Status |
|---|---|---|---|
| Server-series final tip | `e0161d0e61d0cdef22175418f0d4a1e126216a86` | `e0161d0e61d0cdef22175418f0d4a1e126216a86` in the source history used to prepare the study | source history verified; native timing RPM pending; Phase A assertion/prefix evidence recorded separately |
| Supported study-tip RPM source | `fa3987d01209bc60f599dda70ad4e5734ebc78c2`, declared production-equivalent to final `e0161d0e` without rewriting source provenance | Git diff from `e0161d0e` is confined to `performance/large-filter-study/**` | PASS source-tree relationship; native bundle pending |
| Benchmark harness commit | committed SHA containing this study directory | PENDING | PENDING |
| Full workload profile | 100,000 people; 612 principal entries | `full-62af05addd159340`; 118 scenarios; 242 hashed payloads | PASS generator/hash validation |
| Primary generated filter contract | 355 DN assertions; 368 nodes; zero exact results | 41,684 rendered bytes; 368 nodes; zero exact results | PASS generator/hash validation |
| Deterministic seed | `38920260720` | `38920260720` in generated manifest | PASS |
| Workload SHA-256 | identical across every merged bundle | `62af05addd1593408106f1ebdddac4067af82f8295cda9ee5a194555b6a68163` | generated; bundle match pending |
| Workload-manifest file SHA-256 | identical bytes copied by every runner | `2ee3f029d2e05d756a1de3282d43a9af2388b777473b1a63c01bdd1f763eaad7` | generated; bundle match pending |
| Canonical complete-manifest SHA-256 | identical merger comparison contract | `ac2c3e24a17a6494bf960e45b5119d1259154a8648d9bda51b2654d4f9e21591` | generated; bundle match pending |
| 389 DS schema SHA-256 | generated server schema | `a8534867c3ea19982008d997b76b1c4f324a84696dad19aa7422d1595ca983e1` | generated; native application pending |
| OpenLDAP schema SHA-256 | generated server schema | `0726d1ead7e599b9deb385fa3a9b716db845a48c5bd460858f9bc7c0d5ddb965` | generated; native application pending |
| Index-description SHA-256 | one generated index-configuration hash | `b96078e6eddee0bf487fa505e88ca04045f307895c5cf04aae694f6e22ba55c0` | generated; native effective-config check pending |
| Acceptance-gates file SHA-256 | frozen bytes before result inspection | `5254303b968c39338c602e122f7c43bb4454ac11dd52025ef7ea4a76cb2e5d6c` | frozen before native results |
| Acceptance-gates canonical JSON SHA-256 | merger-recorded gate identity | `0be205fc14a87571e07c3a082ce9a564331797ae78a3399d5acfd44ace4ec89c` | frozen before native results |
| Client executable SHA-256 | pinned within a comparison | PENDING | PENDING |
| Native host compatibility key | identical within a merged timing environment | PENDING | PENDING |

## Exact revision-role matrix

| CLI role | Exact commit/package | Purpose | Required timing disposition | Native bundle |
|---|---|---|---|---|
| `pre-series` | `6e1e933745313622593d943e983ff710de8db732` | Pre-series reference | Required principal/baseline/scaling reference | PENDING |
| `modern-harness` | `72f489233e90688a18c11a3c71d42cc812e13fe9` | Modern harness/history reference | Not a headline timing point | PENDING/not required |
| `bounded-feature` | `fde13723bfa682526bb472baa91ff0d5f1b4af47` | Bounded substring/approximate reads; includes NOT-first correction | Required combined-feature reference | PENDING |
| `combined-diagnostic` | `7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6` | Combined pre-correctness-fix snapshot | Optional diagnostic only | PENDING/optional |
| `dynamic-list-fix` | `038b8f58a305c1650ab0523a9d2658aabbc9848b` | Dynamic-list/lookthrough safety | Correctness control, not headline OpenLDAP timing | PENDING |
| `all-family-fix` | `09f92bfbe67f8769277e4e4ae5fef5cf069d71f4` | Discover all plausible equality families | Flat-family attribution | PENDING |
| `largest-family-fix` | `9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a` | Select largest eligible family with deterministic ties | Flat-family attribution and final success-path control | PENDING |
| `lifecycle-tests` | `014fe6a3793898b508a6d6de9893937a7e1aa49d` | Test-only lifecycle leak coverage | Preserve alias; deduplicate identical production binary | PENDING/not independently timed |
| `asan-harness` | `f29a3c6806c81d1cc0e5b77520b3b8d4b3d5d873` | Test/harness-only inlined ASan handling | Preserve alias; deduplicate identical production binary | PENDING/not independently timed |
| `final` | `e0161d0e61d0cdef22175418f0d4a1e126216a86` | Abort-path ID-list ownership fix and final study tip | Required same-RPM lookup-off/on plus representative success paths | PENDING |
| `final-study-tip` | `fa3987d01209bc60f599dda70ad4e5734ebc78c2` (production-equivalent role: `final` at `e0161d0e`) | Adds only this performance study; retain the literal RPM source SHA and apply final mechanism gates | May supply the same-RPM final lookup-off/on rows; merger reports source and production commits separately | PENDING |
| `historical` | `dd7d0db1a45a417f9c1546002758c25ca6e120d6` | Historical sibling investigation tip | Reference only; never the modern final build | PENDING/not required |
| Packaged OpenLDAP | normal Fedora `openldap-servers` package | Contextual comparable implementation | Required comparable rows | PENDING |

No listed follow-up is a standalone true-root no-hit revision. No artificial
cherry-pick state may be added to this table.

## Native installed artifact identity and binary deduplication

This is the native timing-evidence ledger; the Phase A identities above do not
populate it. Populate one row per supplied native installed package before using
its measurements.
An expected SHA is an operator assertion unless an exact 40-hex package token
proves it; a short matching prefix is only corroboration. Identical executable
SHA-256 values define aliases even when they carry several labels. Performance
pooling additionally requires the same direct-linked closure, live backend
closure, and combined behavioral runtime identity.

| Build label/aliases | Expected source SHA or package | Source identity basis | Owning RPM/NEVRA | `rpm -V` | Executable path | Executable SHA-256 | ELF build ID | Linked-runtime SHA-256 | Live-backend SHA-256 | Behavioral identity SHA-256 | Unsanitized | Dedupe/pooling decision |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pre-series | `6e1e933745313622593d943e983ff710de8db732` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| bounded-feature | `fde13723bfa682526bb472baa91ff0d5f1b4af47` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| final lookup off/on | `e0161d0e61d0cdef22175418f0d4a1e126216a86` | PENDING | PENDING | PENDING | PENDING | PENDING—must match | PENDING—must match | PENDING—must match | PENDING—must match | PENDING—must match | PENDING | one executable and behavioral identity, two configurations |
| packaged OpenLDAP | `fedora-package` | package identity | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| `9c23a6e4`, `014fe6a3`, `f29a3c68` aliases | exact SHAs above | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | alias on executable hash; pool only on behavioral identity |
| `7c0b4f65`, historical `dd7d0db1` aliases when supplied | exact SHAs above | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | preserve roles; apply both identity levels |

Record both closures and their RPM provenance in the merged artifact manifest.
Do not present executable aliases as independent binaries or pool aliases whose
behavioral runtime identities differ.

## Host and measurement protocol

| Field | Predeclared requirement | Observed |
|---|---|---|
| Host class | native non-container x86_64 Fedora | PENDING |
| Fedora release/kernel/architecture | constant within comparison | PENDING |
| CPU/model/affinity/governor | constant; recorded | PENDING |
| Memory/storage/background load | constant; recorded | PENDING |
| 389 DS primary backend | MDB | PENDING |
| OpenLDAP backend | packaged MDB | PENDING |
| Connection policy | new connection per search, unless a separate experiment is declared | PENDING |
| Primary attributes | `1.1`; principal pair also repeated with normal attribute list | PENDING |
| Warm cache | 2–3 untimed warm-ups; at least 15 measured runs, normally 20 | PENDING |
| Cold cache | separate strata only | PENDING |
| Schedule | clean-snapshot ABBA or predeclared randomized rounds | PENDING |
| Perf stat | one-search batches; instructions, cycles, branches, branch misses, cache misses; at least 15 usable independent batches | PENDING |
| Profiles | principal all-miss, presence-index, combined-feature shapes | PENDING |
| Memory | startup baseline and high-water delta | PENDING |

The runner enforces at least 15 native measured repeats. The merger's lower
structural minimum is not permission to schedule fewer native runs.

## Correctness gate ledger

Every timed row must have LDAP success, complete sorted-DN equality with the
independent expected file, the expected result count and SHA-256, and no new
administrative-limit result. A failed or incomplete gate makes the row timing
ineligible.

| Role/package | Lookup | Index config | Scenario | Expected count/hash | LDAP result | Returned count/hash | Exact parity | Mechanism gate | Release eligible |
|---|---|---|---|---|---|---|---|---|---|
| pre-series | unsupported | baseline-no-presence | principal with sDN2 equality | zero / empty-set SHA from manifest | PENDING | PENDING | PENDING | PENDING | PENDING |
| pre-series | unsupported | baseline-no-presence | principal without sDN2 equality | zero / same empty-set SHA | PENDING | PENDING | PENDING | PENDING | PENDING |
| final | off | baseline-no-presence | principal with sDN2 equality | zero / manifest | PENDING | PENDING | PENDING | lookup construction must be absent | PENDING |
| final | off | baseline-no-presence | principal without sDN2 equality | zero / manifest | PENDING | PENDING | PENDING | lookup construction must be absent | PENDING |
| final | on | baseline-no-presence | principal with sDN2 equality | zero / manifest | PENDING | PENDING | PENDING | construction largest 355; consumption still unproved | PENDING |
| final | on | baseline-no-presence | principal without sDN2 equality | zero / same manifest hash | PENDING | PENDING | PENDING | construction largest 355; consumption still unproved | PENDING |
| bounded-feature | unsupported | baseline-no-presence | combined substring gain/adverse and approximate | per manifest | PENDING | PENDING | PENDING | cap expectation per scenario | PENDING |
| final | off/on | all required index variants | presence/candidate-index controls | per manifest | PENDING | PENDING | PENDING | PENDING | PENDING |
| final | off/on | baseline-no-presence | scaling, hits, fallbacks, normalization, decomposition, branch order | per manifest | PENDING | PENDING | PENDING | PENDING | PENDING |
| `038b8f58` and final | on | baseline-no-presence | dynamic-list finite/unlimited controls | exactly two final stored DNs | PENDING | PENDING | PENDING | no admin-limit result | correctness-only row |
| `09f92bfb`, `9c23a6e4`, final | on | baseline-no-presence | flat family controls | per manifest | PENDING | PENDING | PENDING | selected-family expectation | PENDING |
| packaged OpenLDAP | unsupported | equivalent required variants | directly comparable scenarios | same generated expected sets | PENDING | PENDING | PENDING | implementation-specific diagnostics | PENDING |

When bundles exist, expand this ledger to one line for every actual scenario,
attribute variant, cache policy, and build/configuration stratum. Do not summarize
away a failed row.

## Candidate-count validation

The manifest's 612 is the logical outer cohort for the full principal data. It
is not automatically the final backend candidate list. Only an isolated,
single-search `build_candidate_list` trace with a fresh cursor is the candidate
oracle where that production diagnostic is available. Returned `nentries`,
`notes=U`, and per-key STAT counts are not substitutes.

| Role/config | Scenario | Logical outer cohort | Observed final backend candidates | Observation status/source | Exact final results | Interpretation |
|---|---|---:|---:|---|---|---|
| pre-series | principal with sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| pre-series | principal without sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| final lookup off | principal with sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| final lookup off | principal without sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| final lookup on | principal with sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| final lookup on | principal without sDN2 | 612 | PENDING | PENDING | zero expected | PENDING |
| final lookup on | presence sDN1 only | 612 structural | PENDING | PENDING | zero expected | PENDING |
| final lookup on | presence sDN2 only | 612 structural | PENDING | PENDING | zero expected | PENDING |
| final lookup on | presence both | 612 structural | PENDING | PENDING | zero expected | PENDING |
| packaged OpenLDAP | comparable principal pair/configs | 612 structural | PENDING or not observable | PENDING | zero expected | PENDING |

If the trace is unavailable, report `not directly observable`, retain structural
and decomposition validation, and do not add server instrumentation.

## Source-derived hypothesis register

These are hypotheses to test, not conclusions:

| ID | Hypothesis/uncertainty | Required discriminator | Status |
|---|---|---|---|
| H1 | In an unproxied Directory Manager all-miss search, the final build can construct the 355-family table yet decline probing/consumption and fall back to the classic OR walk. The stable diagnostic proves construction only. | Same-final-RPM lookup off/on CPU, instructions, branch-count/candidate-count scaling, and principal perf profiles | PENDING |
| H2 | Missing sDN1/sDN2 presence indexes can cause `notes=U`, but `notes=U` may be secondary or orthogonal to dominant per-entry equality work. Presence indexes can also change the candidate plan. | Four-way presence matrix, exact candidates, fixed-candidate control, CPU/instructions/profile with lookup off/on | PENDING |
| H3 | Removing the absent simple sDN2 equality branch may change approximate candidate generation, or may only remove a small equality family/remainder check. Logical OR appearance alone cannot decide. | Paired exact-result rows, isolated final candidates, notes, STAT/index reads, CPU/instructions, profiles in both servers | PENDING |
| H4 | The bounded-read cap message proves a bound and ALLIDS return but does not by itself prove expensive substring/approximate index work was truncated. | STAT/index-log or profile evidence plus gain/adverse A/B | PENDING |
| H5 | Lookup-on should improve branch-count/position behavior when the table is consumed, but construction cost remains visible at zero candidates and decline paths can legitimately retain classic behavior. | Candidate and branch scaling, hit position, zero-candidate construction, `m > k`, invalid remainder | PENDING |
| H6 | `09f92bfb` discovers a large third family after distractors; `9c23a6e4` selects the largest eligible family and preserves deterministic first-occurrence ties. | Flat-family mechanism/result controls on the exact revision sequence | PENDING |
| H7 | The final `e0161d0e` abort-path ownership change should not materially improve ordinary successful searches and must not regress them. | Representative success-path comparison with `9c23a6e4`, deduped by executable hash | PENDING |

## Mechanism preflight

| Role/config/scenario | Lookup construction | Reported largest family | Table consumption | Cap diagnostic | Avoided/truncated work evidence | Candidate trace | `notes=U` | Gate |
|---|---|---:|---|---|---|---|---|---|
| final lookup off, principal pair | must be absent | N/A | classic control | N/A | profile baseline | PENDING | PENDING | PENDING |
| final lookup on, principal pair | required | 355 | **not directly reported** | N/A | lookup-off/on + profile required | PENDING | PENDING | PENDING |
| pre-series, combined substring | unsupported | N/A | N/A | absent/unsupported | profile/STAT baseline | PENDING | PENDING | PENDING |
| bounded-feature, combined substring gain | as supported | PENDING | PENDING | required | profile/STAT corroboration required | PENDING | PENDING | PENDING |
| final lookup on, combined substring gain | required | 355 | not directly reported | required | profile/STAT corroboration required | PENDING | PENDING | PENDING |
| final, combined substring adverse | per lookup mode | 355 where on | PENDING | must not engage | adverse/no-gain profile | PENDING | PENDING | PENDING |
| flat third-family control | required on capable builds | 64 expected family | not directly reported | N/A | selected-family/result control | PENDING | PENDING | PENDING |
| flat ranking A16/B64 both orders | required on capable builds | 64 | not directly reported | N/A | selected-family/result control | PENDING | PENDING | PENDING |
| unsupported larger family fallback | next supported family expected | per manifest | expected decline/fallback possible | N/A | result/profile evidence | PENDING | PENDING | PENDING |

The mechanism result for H1 must remain **unverified due to missing mechanism
evidence** if profiles and scaling cannot distinguish actual consumption from a
classic walk. Never infer probes from the construction string.

## Primary native median and p95

All elapsed values are client seconds from measured warm-cache rows; p95 is
nearest-rank. CPU and instructions support, but do not replace, exact-result and
elapsed evidence.

The runner creates one independent perf-stat observation around each measured
search. Rows contain only their `perf_batch_id`; the merger validates the
bidirectional link, rejects multi-search or aggregate-free batches, and computes
instruction statistics from unique batches rather than duplicating a batch
value onto elapsed rows. A native stratum needs at least 15 usable independent
instruction batches.

| Server/build | Lookup | Principal variant | Attributes | n | Median elapsed | p95 | Median server CPU | Median instructions/search (singleton perf batches) | Noise fraction | Classification |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| 389 DS pre-series | unsupported | with sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS pre-series | unsupported | without sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS final | off | with sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS final | off | without sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS final | on | with sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS final | on | without sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Packaged OpenLDAP | unsupported | with sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Packaged OpenLDAP | unsupported | without sDN2 | `1.1` | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 389 DS pre-series/final modes | as above | paired principal rows | normal attributes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Packaged OpenLDAP | unsupported | paired principal rows | equivalent normal attributes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

## Full versus no-sDN2-equality attribution

Both generated filters have the same intentional empty exact result. The filter
without the simple sDN2 equality has one fewer equality component and one fewer
node; it is not the exact primary component count. Fill each evidence channel
separately.

| Server/build/mode | Exact result parity | Final candidate delta | `notes=U` delta | STAT/index-read delta | Median elapsed delta | CPU delta | Instructions delta | Profile delta | Attribution/classification |
|---|---|---:|---|---|---:|---:|---:|---|---|
| pre-series | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| final lookup off | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| final lookup on | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| packaged OpenLDAP | PENDING | PENDING/not observable | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

Only call the branch candidate-eliminating/planning behavior when an
operation-isolated candidate observation supports it. Otherwise attribute a
difference to equality-family/remainder evaluation or leave it unverified.

## Presence-index and `notes=U` matrix

Answer four questions independently: whether presence indexes remove
`notes=U`; change candidate count; change elapsed/CPU/instructions; and retain a
material effect after lookup is enabled.

| Server/build | Lookup | Filter | Presence config | Exact parity | `notes=U` | Final candidates | Median | p95 | CPU | Instructions | Lookup constructed | Classification |
|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| final | off | full principal | none | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | must be absent | PENDING |
| final | off | full principal | sDN1 only | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | must be absent | PENDING |
| final | off | full principal | sDN2 only | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | must be absent | PENDING |
| final | off | full principal | both | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | must be absent | PENDING |
| final | on | full principal | none | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | required | PENDING |
| final | on | full principal | sDN1 only | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | required | PENDING |
| final | on | full principal | sDN2 only | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | required | PENDING |
| final | on | full principal | both | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | required | PENDING |
| final | off/on | no-sDN2 variant | none | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | per mode | PENDING |
| final | off/on | no-sDN2 variant | both | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | per mode | PENDING |
| packaged OpenLDAP | unsupported | required full/pair variants | all equivalent intents | PENDING | implementation-specific | PENDING | PENDING | PENDING | PENDING | PENDING | unsupported | PENDING |

Use the fixed-candidate decomposition control before attributing a runtime
change purely to unindexed NOT-presence evaluation.

## Candidate-count scaling

The all-miss result remains exact while the 355-branch shape is fixed. The zero
point measures parsing/normalization/table construction and fixed overhead, not
per-entry probes.

| Server/build/mode | Candidate cohort | Observed candidates | Exact parity | n | Median | p95 | CPU | Instructions | Per-entry slope/interpretation | Classification |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|
| each required 389 DS mode and packaged OpenLDAP | 0 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 1 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 10 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 100 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 612 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 1,000 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required 389 DS mode and packaged OpenLDAP | 10,000 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

## Equality-branch scaling and lookup threshold

Keep the logical candidate cohort at 612 and DN length/distribution controlled.
The 15/16 pair isolates the lookup threshold.

| Server/build/mode | Distribution | Branches | Raw/unique keys | Lookup expected/observed | Exact parity | n | Median | p95 | CPU | Instructions | Scaling interpretation | Classification |
|---|---|---:|---|---|---|---:|---:|---:|---:|---:|---|---|
| each required mode | all absent | 15 | PENDING | below threshold/PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 16 | PENDING | threshold/PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 32 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 64 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 128 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 355 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 500 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all absent | 1,000 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | mostly live, mixed, duplicates | all branch points | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | zero candidate/table build | all branch points | PENDING | construction only | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

Report whether lookup-on all-miss cost continues to depend on branch count; this
is a central discriminator for H1.

## Hit position and assertion order

| Server/build/mode | Shape | Expected count | Exact parity | Median | p95 | CPU | Instructions | Position/order sensitivity | Classification |
|---|---|---:|---|---:|---:|---:|---:|---|---|
| each required mode | early hit | controlled equal count | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | middle hit | controlled equal count | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | late hit | controlled equal count | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | all-miss forward/reversed | zero | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | positive forward/reversed | controlled equal count | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

## Multi-valued sDN1 scaling and high-cardinality decline

| Server/build/mode | Values per candidate | Raw k | Unique normalized k | `m > k` | Exact parity | n | Median | p95 | CPU | Instructions | High-water delta | Classification |
|---|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|
| each required mode | 1 | 355 | PENDING | no | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | 4 | 355 | PENDING | no | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | 16 | 355 | PENDING | no | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | 64 | 355 | PENDING | no | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| capable 389 DS modes | at least 17 | 16 | 16 | yes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |

High-water memory is reported relative to the startup/setup baseline. It is not
leak proof and cannot replace sanitizer validation.

## DN normalization variants

Record table-build zero-candidate, 612-candidate positive, and 612-candidate
all-miss phases separately. Invalid assertions belong to the classic remainder;
report the valid normalized unique family after that split.

| Server/build/mode | DN mode | Phase | Valid/raw/unique family | Exact parity | n | Median | p95 | CPU | Instructions | Mechanism/normalization interpretation | Classification |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| each required mode | short canonical | zero/positive/all-miss | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | long canonical (~100–110 characters) | zero/positive/all-miss | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | case-different equivalent | zero/positive/all-miss | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | escaped comma equivalent | zero/positive/all-miss | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| each required mode | invalid remainder | zero/positive/all-miss | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |

## Decomposition controls

| Control | Components retained | Exact result/candidates | Pre-series median/CPU/instructions | Final off median/CPU/instructions | Final on median/CPU/instructions | Profile attribution | Classification |
|---|---|---|---|---|---|---|---|
| A | outer three equalities only | PENDING | PENDING | PENDING | PENDING | outer candidate generation | PENDING |
| B | A + one absent equality OR | PENDING | PENDING | PENDING | PENDING | small equality overhead | PENDING |
| C | A + 355-way sDN1 OR only | PENDING | PENDING | PENDING | PENDING | large equality family | PENDING |
| D | A + sDN2 equality + complex fallback | PENDING | PENDING | PENDING | PENDING | small family plus NOT fallback | PENDING |
| E | full primary | zero expected/PENDING candidates | PENDING | PENDING | PENDING | full interaction | PENDING |
| F | E without simple sDN2 equality | same zero expected/PENDING candidates | PENDING | PENDING | PENDING | candidate-plan versus evaluator delta | PENDING |
| G | A + complex fallback only | PENDING | PENDING | PENDING | PENDING | NOT-presence/fallback | PENDING |

Use profiles and operation-isolated candidate diagnostics; do not derive all
components solely by subtracting elapsed medians.

## Candidate-generation index controls

| Server/build/mode | Index intent | Exact parity | Candidate count | `notes=U` | STAT reads | Median/p95 | CPU/instructions | Interpretation | Classification |
|---|---|---|---:|---|---|---|---|---|---|
| required modes | all documented equality indexes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | baseline | PENDING |
| diagnostic modes | no sDN1 equality index | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | candidate-generation isolation | PENDING |
| diagnostic modes | no sDN2 equality index | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | candidate-generation isolation | PENDING |

Exclude an unbounded giant diagnostic from headline tables if it exceeds the
predeclared resource limit; retain its exact gate/status as diagnostic evidence.

## Family-discovery/ranking fix attribution

| Shape | Failure/reference revision | `09f92bfb` observed family/result | `9c23a6e4` observed family/result | Final observed family/result | Timing eligibility | Classification |
|---|---|---|---|---|---|---|
| A16 then B64 | PENDING | PENDING | 64 expected/PENDING | 64 expected/PENDING | after mechanism/result pass | PENDING |
| B64 then A16 | PENDING | PENDING | 64 expected/PENDING | 64 expected/PENDING | after mechanism/result pass | PENDING |
| A distractor + B distractor + C64 | PENDING | third family expected/PENDING | third family expected/PENDING | third family expected/PENDING | after mechanism/result pass | PENDING |
| larger unsupported family then supported family | PENDING | PENDING | next supported family expected/PENDING | same expected/PENDING | after mechanism/result pass | expected decline/fallback or PENDING |
| equal eligible families, A first | PENDING | PENDING | first occurrence expected/PENDING | same expected/PENDING | after mechanism/result pass | PENDING |
| equal eligible families, B first | PENDING | PENDING | first occurrence expected/PENDING | same expected/PENDING | after mechanism/result pass | PENDING |

Deduplicate timing rows if supplied RPMs resolve to the same executable hash.

## Dynamic-list/lookthrough correctness attribution

This is a correctness preflight only: 20 stored ordinary candidates, exactly two
final stored matches, 20 URL entries added after ordinary candidate generation,
lookthrough limit 30, and finite/supported-unlimited scan-limit variants.

| Revision | Scan-limit variant | Ordinary candidates | Augmented candidates | LDAP result | Exact two-DN parity | Admin-limit result | Server health | Classification |
|---|---|---:|---:|---|---|---|---|---|
| immediate parent `7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6` when supplied | finite/unlimited | 20 expected/PENDING | 40 expected/PENDING | historical failure expected/PENDING | historical failure expected/PENDING | expected old failure/PENDING | must recover/PENDING | expected historical control only |
| `038b8f58` | finite | 20 expected/PENDING | 40 expected/PENDING | success expected/PENDING | PENDING | must be absent | PENDING | PENDING |
| `038b8f58` | unlimited | 20 expected/PENDING | 40 expected/PENDING | success expected/PENDING | PENDING | must be absent | PENDING | PENDING |
| final `e0161d0e` | finite/unlimited | PENDING | PENDING | success expected/PENDING | PENDING | must be absent | PENDING | PENDING |

Do not place these elapsed values in the principal or OpenLDAP timing table.
The immediate parent's failure is supporting historical evidence; `038b8f58`
and final are authoritative hard-pass controls and must not show the old cap.

## Combined equality lookup and bounded substring/approximate reads

| Build/mode | Shape | Exact parity | Lookup construction/family | Cap observed | STAT/profile proof of avoided work | Candidate count | Median/p95 | CPU/instructions | Classification |
|---|---|---|---|---|---|---:|---|---|---|
| pre-series | substring gain | PENDING | unsupported | unsupported | baseline PENDING | PENDING | PENDING | PENDING | PENDING |
| bounded-feature | substring gain | PENDING | lookup unsupported | required/PENDING | required/PENDING | PENDING | PENDING | PENDING | PENDING |
| final lookup off | substring gain | PENDING | must be absent | required/PENDING | required/PENDING | PENDING | PENDING | PENDING | PENDING |
| final lookup on | substring gain | PENDING | largest 355 required | required/PENDING | both mechanisms required/PENDING | PENDING | PENDING | PENDING | PENDING |
| all applicable | substring adverse/selective | PENDING | per mode | must not engage | no-gain control PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |
| comparable 389 DS builds | approximate gain | PENDING | per mode | required where capable | required/PENDING | PENDING | PENDING | PENDING | PENDING |
| packaged OpenLDAP | comparable substring/approximate | PENDING | unsupported | implementation-specific | PENDING | PENDING | PENDING | PENDING | PENDING or unavoidable implementation difference |

The cap diagnostic alone is insufficient. Require corroborating STAT/index-log
or profile evidence before claiming avoided work or composition of both
optimizations.

## Branch-order permutations

| Family | Permutations | Exact parity | Candidate differences | Median/p95 differences | CPU/instruction differences | Mechanism differences | Classification |
|---|---|---|---|---|---|---|---|
| principal outer equalities | ABC, BCA, CBA | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| principal OR branches | DN/sDN2/fallback orders | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| 355 assertions | forward/reversed | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| combined substring | outer/costly/large-OR first | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| combined approximate | outer/costly/large-OR first | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

Keep simple-sDN2 removal as its own paired filter change, not another order row.

## Adverse, decline, and no-regression controls

| Control | Expected behavior | Compared builds/modes | Correctness | Median/p95 | CPU/instructions | Memory | Classification |
|---|---|---|---|---|---|---|---|
| 15-branch below threshold | no lookup construction; no regression | pre-series/final off/on | PENDING | PENDING | PENDING | PENDING | PENDING |
| Small equality OR | no material regression | required 389 DS builds | PENDING | PENDING | PENDING | PENDING | PENDING |
| Zero-candidate large filter | table-build overhead acceptable | final off/on | PENDING | PENDING | PENDING | PENDING | PENDING |
| Selective substring | cap should not engage | pre-series/bounded/final | PENDING | PENDING | PENDING | PENDING | PENDING |
| Explicit adverse substring | no unexplained regression | pre-series/bounded/final | PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |
| `m > unique k` | intentional lookup decline | capable 389 DS builds | PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |
| Invalid DN remainder | classic remainder retained | capable 389 DS builds | PENDING | PENDING | PENDING | PENDING | expected decline/fallback or PENDING |
| Final versus `9c23a6e4` successful equality OR | no material regression | exact externally supplied RPMs | PENDING | PENDING | PENDING | PENDING | PENDING |
| Final versus `9c23a6e4` bounded/combined success | no material regression | exact externally supplied RPMs | PENDING | PENDING | PENDING | PENDING | PENDING |

## Packaged OpenLDAP comparison

OpenLDAP is contextual performance evidence, not the correctness oracle. Use the
same generated expected sets, administrative bind class, logical data
distribution, base/scope, requested attributes, filter bytes, client, and cache
policy. Keep 389 DS-specific ACL/proxy/dynamic-list rows out of this table.

| Scenario/config | 389 DS build/mode | OpenLDAP NEVRA/hash | Schema/index equivalence | 389 DS median/p95 | OpenLDAP median/p95 | Ratio | CPU/instruction comparison | Profile attribution | Classification |
|---|---|---|---|---|---|---:|---|---|---|
| principal with sDN2, no presence | pre-series | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| principal with sDN2, no presence | final off | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| principal with sDN2, no presence | final on | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| principal without sDN2, no presence | required 389 DS modes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| presence-index boundaries | required comparable modes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| candidate/branch/multivalue/DN scaling | required comparable modes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| substring composition gain/adverse | required comparable modes | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| approximate composition | when semantics pass equivalence preflight | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING or unavoidable implementation difference |

Record unavoidable differences here before interpreting a ratio:

| Difference | Effect on direct comparability | Disposition |
|---|---|---|
| Approximate matching-rule equivalence | PENDING | PENDING |
| Presence/equality index implementation | PENDING | PENDING |
| Candidate diagnostics available | PENDING | PENDING |
| IDL union/intersection strategy | PENDING | PENDING |
| DN normalization implementation | PENDING | PENDING |
| NOT-presence handling | PENDING | PENDING |
| Result/logging accounting | PENDING | PENDING |

## Profile-based attribution

Populate with native profiles only. Percentages must identify the profile,
symbolization quality, and denominator; elapsed subtraction alone is not a
profile.

| Cost center/question | Pre-series evidence | Final off evidence | Final on evidence | OpenLDAP evidence | Controlled isolation | Conclusion/classification |
|---|---|---|---|---|---|---|
| Request parsing/filter duplication/normalization | PENDING | PENDING | PENDING | PENDING | zero-candidate branch scaling | PENDING |
| Candidate generation and IDL intersection | PENDING | PENDING | PENDING | PENDING | outer-only/index controls | PENDING |
| DN assertion-table construction | unsupported | absent | PENDING | unsupported | zero candidates | PENDING |
| Per-entry DN attribute/value normalization | PENDING | PENDING | PENDING | PENDING | multivalue/DN variants | PENDING |
| Equality-family traversal versus probes | PENDING | PENDING | PENDING | PENDING | off/on, candidate/branch/hit scaling | PENDING |
| Simple sDN2 equality branch | PENDING | PENDING | PENDING | PENDING | full/no-sDN2 pair | PENDING |
| NOT-presence/fallback evaluation | PENDING | PENDING | PENDING | PENDING | decomposition D/G, presence matrix | PENDING |
| Substring/approximate index reads | PENDING | PENDING | PENDING | PENDING | gain/adverse plus STAT | PENDING |
| Result handling/normal attributes | PENDING | PENDING | PENDING | PENDING | `1.1` versus normal attributes | PENDING |

## Predeclared acceptance gates

The authoritative values are in `workload/acceptance-gates.json`, whose hash
must be recorded before final inspection.

| Gate | Predeclared rule | Result |
|---|---|---|
| `exact-result-parity` | Every planned client/server result, complete DN set/count/SHA, and operation kind matches | PENDING |
| `no-new-result-or-admin-limit` | Paired controls introduce no result-code or admin-limit regression | PENDING |
| `principal-consumed-lookup-cost` | Consumed-profile evidence plus at least `max(30%, noise)` CPU and instruction reductions | PENDING |
| `branch-count-scaling` | Homogeneous 16→1000 endpoint slope improves by at least `max(20%, noise)` | PENDING |
| `adverse-and-small-shape-no-regression` | Median below `max(5%, noise)` and p95 below `max(10%, 1.5 × noise)` | PENDING |
| `table-build-and-memory-overhead` | Threshold CPU below `max(10%, noise)`; memory fails only above both 15% and 64 MiB | PENDING |
| `decline-path-parity` | Exact decline/fallback paths do not regress without an evidence-bound waiver | PENDING |
| `final-success-path-no-regression` | Final representative success paths do not regress from `9c23a6e4` | PENDING |
| `sdn2-pair-attribution` | Exact pair parity plus separate candidate, notes, STAT, timing, CPU, instruction, and profile channels | PENDING |
| `selection-fix-retention` | Exact 09/9c/final discovery, ranking, fallback, and tie observations are retained | PENDING |

## Required study questions

| Question | Evidence required | Answer |
|---|---|---|
| Is the final unproxied-DM all-miss lookup actually consumed, removing the candidate × branch classic pattern? | Same-RPM off/on scaling, CPU/instructions, profile | PENDING |
| What changes when simple sDN2 equality is removed? | Exact set, final candidates, notes, reads, CPU/instructions, profile per server | PENDING |
| How is pre-series time divided among parsing, candidates, construction, normalization, traversal, sDN2, and NOT fallback? | Decomposition and profiles | PENDING |
| Do presence indexes remove `notes=U`? | Four-way index matrix | PENDING |
| Do presence indexes remain material after lookup-on, and interact with sDN2 removal? | Boundary pairs and fixed-candidate control | PENDING |
| Does final lookup-on scale with candidates, branches, DN length, or values per entry? | Four scaling families | PENDING |
| Do early/middle/late hits become equivalent? | Controlled hit-position rows | PENDING |
| Do `09f92bfb` and `9c23a6e4` perform their intended discovery/ranking/tie/fallback behaviors? | Exact flat-family revision controls | PENDING |
| What explains any remaining OpenLDAP advantage? | Candidate/index/IDL/DN/evaluator/result profiles | PENDING |
| Do bounded reads and equality lookup compose with proof of actual avoided work? | Diagnostics plus STAT/profile A/B | PENDING |
| Do adverse/decline shapes avoid regression, and does `038b8f58` preserve dynamic correctness? | Adverse/decline and dynamic controls | PENDING |
| Is partial unindexing primary, secondary, or orthogonal? | Presence/index/candidate controls plus profiles | PENDING |
| Does final differ materially from `9c23a6e4` on success paths? | Deduped native success subset | PENDING |

## Remaining uncertainty

- No native package, host, workload, correctness, raw timing, perf, or profile
  artifact has been supplied.
- The Phase A OrbStack correctness-only smoke passed with the asserted final-tip
  RPM identity, but it supplies no native timing, perf, profile, ratio, or
  release evidence.
- Lookup-table construction is observable, but the exact all-miss
  probe/consumption decision has no stable direct production diagnostic.
- Final candidate count can be unavailable on builds without an isolated stable
  trace; that must be reported rather than inferred.
- The precise cause of `notes=U`, and whether it materially contributes after
  lookup-on, is unmeasured.
- Equivalent native approximate semantics across 389 DS and packaged OpenLDAP
  require preflight before a direct comparison.
- Perf availability, symbolization quality, and hardware noise are unknown until
  the native host is provisioned.
- Package metadata may not independently encode source SHA; the operator
  assertion and immutable RPM/binary identity must then remain explicit.

## Release recommendation

**PENDING — no release recommendation.**

Do not describe the study as complete, improved, regressed, or equivalent based
on generator tests, pytest, OrbStack correctness, diagnostics alone, or this
template. A recommendation requires the full native correctness gates, exact
package/binary identities, compatible ABBA result bundles, the primary and
adverse matrices, mechanism/profile attribution, packaged OpenLDAP context, and
application of the predeclared acceptance gates.
