# Large-filter performance reproducer — 389-ds vs OpenLDAP

Fully synthetic reproducer for a reported behavior: a single LDAP search with a
very large filter (~44 KB) is much slower on 389 Directory Server than on
OpenLDAP over equivalent data. No customer data is used; schema, data, and
filter are generated from scratch and are deterministic (seeded).

This directory only *builds the environment and records measurements*. It
deliberately contains no analysis of *why* the servers differ — the two
containers are left running for that investigation.

## One-command usage

```bash
cd reproducer
python3 generate-data.py --entries 100000 --seed 42   # data.ldif + data-manifest.json
python3 generate-filter.py --shapes all               # filter-<shape>.txt + expected-dns-<shape>.txt + shapes-manifest.json
./setup-389ds.sh                                      # container repro-389ds-<hash>
./setup-openldap.sh                                   # container repro-openldap-<hash>
./run-benchmark.sh --all-shapes                       # appends to measurements.md + results/matrix.csv
```

`generate-filter.py` defaults (600 substrings / 60 NOTs for the s1
mega-filter) are the accepted configuration from the iteration log
(measurements.md iteration 5): a 44 KB filter where 389-ds median etime is
≥ 0.5 s and OpenLDAP is ~4.6× faster on identical data.

Everything is re-runnable: the setup scripts recreate their container from
scratch, and `run-benchmark.sh` appends a new numbered iteration per shape to
`measurements.md` each time. Container names are derived from the checkout
path (`repro-389ds-<hash>`) and carry an ownership label
(`org.389ds.repro.source`); the scripts refuse to touch a container that
belongs to a different checkout or that they did not create. Override with
`REPRO_389DS_NAME`/`REPRO_OPENLDAP_NAME`; point `REPRO_RPMS_DIR` at another
checkout's `dist/rpms` to install a baseline build through this harness.

## Layout

| File | Purpose |
|---|---|
| `schema/99reproducer.ldif` | Custom schema, 389-ds format (drop into instance schema dir) |
| `schema/reproducer.schema` | Same schema, OpenLDAP `attributetype`/`objectclass` format |
| `generate-data.py` | Emits `data.ldif` + `data-manifest.json` (see `--help`) |
| `generate-filter.py` | Emits `filter-<shape>.txt` + `expected-dns-<shape>.txt` + `shapes-manifest.json`; builds each shape as a filter AST and derives BOTH the filter string and the expected DN set from it, evaluated against `data.ldif` (see `--help`) |
| `repro-common.sh` | Shared container naming + ownership-label helpers |
| `setup-389ds.sh` | Privileged systemd container from `quay.io/389ds/ci-images:test` + local RPMs (`../dist/rpms`, or `REPRO_RPMS_DIR`); dscreate, schema, indexes, online import, reindex, index + substring preflights |
| `setup-openldap.sh` | Container from `fedora:42`; slapd file config (mdb), schema, indexes, `slapadd -q`, slapd with stats logging, same preflights |
| `run-benchmark.sh` | Per shape: 10 timed runs per server per variant, fatal independent-expectation gate, appends `measurements.md` + `results/matrix.csv`; `REPRO_CAP_BUILD=1` also verifies read-cap engagement per shape |
| `RESULTS.md` | Curated, committed measurement matrix (hand-assembled from `results/matrix.csv`) |
| `measurements.md` | Generated raw results + iteration log (do not hand-edit) |
| `investigation-prompt.md` | Hand-off prompt for the follow-up investigation + fix work |

Generated (not checked in): `data.ldif`, `data-manifest.json`,
`filter-*.txt`, `expected-dns-*.txt`, `shapes-manifest.json`, `results/`,
`measurements.md`.

## Synthetic schema

Private OID arc `2.16.840.1.113730.999.*`. One AUXILIARY objectclass
`reproPerson` that MAYs all custom attributes. Entries are
`inetOrgPerson` + `reproPerson` in a flat tree under
`ou=people,dc=example,dc=com`.

Five DirectoryString attributes (one more than the nominal 3–4 because one
DirectoryString must stay unindexed as a NOT target), two IA5String, two
INTEGER with ordering, one DN-syntax, one Boolean. `reproTag` and
`reproMailAlt` are multi-valued.

## Index table (pairwise parity)

| Attribute | Syntax / matching | 389-ds index | OpenLDAP index | Note |
|---|---|---|---|---|
| objectClass | — | eq (default) | eq | |
| uid | — | eq (default) | eq | |
| cn | DirectoryString | eq,sub,pres (default) | eq,sub,pres | |
| reproTitle | DirectoryString caseIgnore | eq,sub,pres | eq,sub,pres | |
| reproDept | DirectoryString caseIgnore | eq,sub,pres | eq,sub,pres | |
| reproTag | DirectoryString caseIgnore, MV | eq | eq | big-OR target |
| reproRegion | DirectoryString caseIgnore | eq | eq | one value ≈50% of entries |
| reproMailAlt | IA5 caseIgnore, MV | eq | eq | |
| reproHostname | IA5 caseExact | eq | eq | |
| reproManager | DN | eq | eq | |
| reproScore | INTEGER | eq + `nsMatchingRule: integerOrderingMatch` | eq | see asymmetry note |
| reproLevel | INTEGER | eq + `nsMatchingRule: integerOrderingMatch` | eq | see asymmetry note |
| reproFlag | Boolean | **none** | **none** | deliberate; NOT target |
| reproNote | DirectoryString caseIgnore | **none** | **none** | deliberate; NOT target |

**Integer-ordering asymmetry:** 389-ds needs an explicit
`nsMatchingRule: integerOrderingMatch` on the index for range (`>=`/`<=`)
lookups to use ordered integer keys; OpenLDAP serves range filters on
INTEGER-syntax attributes from its plain `eq` index. There is no exact
config-for-config equivalent — this is the closest pairing, and it is
documented rather than hidden.

389-ds also ships other default indexes (sn, givenName, mail, …) that
OpenLDAP does not get here; none of them appear in the benchmark filter.

## Data shape (defaults: 100,000 entries, seed 42)

- `uid` unique, `cn` unique-ish (`<given> <surname> <i>`)
- `reproTag` multi-valued; each pool value shared by 1–10 entries (big-OR selectivity)
- `reproRegion`: `emea` ≈50% of entries (cheap-looking but broad component)
- `reproTitle` ~2010 distinct values, `reproDept` ~504, `reproNote` ~4000
- `reproScore` uniform 0..999 (narrow ranges; values 500/501 reserved for the
  golden cohort so the narrow range selects exactly the cohort), `reproLevel`
  uniform 0..999 (wide ranges). The score space is deliberately coarse:
  iteration 1 showed OpenLDAP range evaluation scales with distinct index
  keys, and ~100k distinct keys swamped everything else (see measurements.md)
- **Golden cohort** (~120 entries, every `entries/120`-th entry): engineered to
  satisfy *every* AND branch of the generated filter (region=emea, flag=FALSE,
  score packed into one narrow window, golden-only tags/dept/title/note,
  `cn=Golden User NNNNN`). This pins the result set: both servers must return
  exactly this cohort, deterministically and non-zero.

## Shape matrix

Each shape is emitted as its own `filter-<shape>.txt` with an independently
computed `expected-dns-<shape>.txt`. `expect_cap` is the read-cap engagement
expectation on a cap-capable 389-ds build (checked by `run-benchmark.sh`
when `REPRO_CAP_BUILD=1`).

| Shape | Filter | Purpose | expect_cap |
|---|---|---|---|
| `s1` | the 44 KB mega-AND below | the read cap's winning shape (accepted reproducer) | true |
| `s2-uid-{125,250,500,1000}` | all-live OR of N distinct `uid`s | #6275's literal shape (N singleton ID lists); the union-rewrite gate ladder | false |
| `s2-tag-{125,250,500,1000}` | all-live OR of N existing `reproTag`s | same ladder with a member-like multi-ID profile | false |
| `s3` | `(&(reproDept=golden)(|(sub)(sub)...))` | compound costly component capped via pass-down | true |
| `s3b` | OR of two `(&(eq~100..200)(fat sub))` ANDs | composition shape: pure-AND ancestry must refuse the cap | false |
| `s4-{10,400}` | `(&(objectClass=reproPerson)(|(N tag eqs)))` | SSSD-sudo analog; no substrings, cap never applies | false |
| `s5` | `(&(|(2 broad objectClass eqs))(reproHostname=unique))` | #811 order-dependency shape | false |
| `s6` | `(&(|(~37 reproScore eqs, bound ~3.6k))(cn=*megaword*))` | the cap's LOSING shape: bound just under the floor, fat key > 4× bound (16,647 IDs) — committed honestly | true |
| `s7-and-{1,4,16,64}` | `(&(reproScore=eq)(N fat Megaword substrings))` | ISOLATION, AND only: identical result at every rung, cost varies only with N | true |
| `s7-eqlast` | s7-and-16 with the equality written last | placement probe: optimizer hoists, timing must match s7-and-16 | true |
| `s8-orsub-{4,16,64}` | top-level OR of N substrings (3/4 fat, 1/4 absent) | ISOLATION, OR only: identical result at every rung; never capped | false |
| `s9-not-{8,32}` | s7-and-4 + M no-op NOTs | NOT probe: result identical to s7-and-4; NOTs must not change the cap picture | true |
| `s9-notfirst` | `(&(!(eq absent))(2 fat substrings))` | NOT-of-equality staying first at runtime (isnot ALLIDS-subtraction path) | false |

The `Megaword` cn token (every non-golden entry with `i % 6 == 3`,
16,647 entries at the default size) exists solely to give `s3`/`s3b`/`s6`
a substring key fat enough to exceed their caps.

## s1 filter shape (defaults: ~44 KB, one top-level AND)

1. Big OR of equality assertions on indexed `reproTag`; width auto-tuned to hit
   `--target-bytes` (~1,900 at 44 KB; pass `--big-or 3000` to force width
   instead). ~30% of values exist in the data (including all 40 golden tags),
   ~70% are well-formed but absent — they still cost parse/normalize.
2. OR of substring assertions on `cn`/`reproTitle`: prefix, infix, and
   leading-wildcard (default 200; accepted config uses 600 — the substring
   count is the strongest 389-ds-vs-OpenLDAP differential lever found in the
   iteration log).
3. NOT branches: simple NOT on indexed attrs, NOT over a nested OR, and
   NOTs on the two unindexed attrs (`reproFlag`, `reproNote`) (default 24;
   accepted config uses 60).
4. Presence: `(cn=*)`, `(objectClass=*)`, `(reproTitle=*)`, `(reproMailAlt=*)`.
5. Integer range pairs: narrow on `reproScore` (the golden window), wide on
   `reproLevel` (~half the DB).
6. Deep alternating `(&(|(...)))` chain, 12 levels, fan-out 2 (reduces to
   `(reproRegion=emea)` AND `(reproFlag=FALSE)`, both true for the golden
   cohort).
7. 20 exact-duplicate components repeated verbatim.
8. Extensible match (`cn:caseExactMatch:=`) behind `--extensible`, **off** in
   the baseline (OpenLDAP parity is imperfect).

`shapes-manifest.json` records per shape: component counts/params, nesting
depth, total length, and the expected result set (count + sorted-DN md5) so
any future filter can be shape-compared and any run can be gated.

## Assumptions and caveats

- **Both containers run `--platform linux/amd64`** (host is Apple Silicon +
  OrbStack). Emulation slows both servers equally; compare the *ratio*, not
  absolute times against the customer's report.
- **Benchmark binds are root DNs** (`cn=Directory Manager` /
  `cn=Manager,dc=example,dc=com`): ACI/ACL processing is bypassed on both
  sides by design.
- Searches run *inside* each container via `docker exec`; the filter is read
  from the mounted `filter.txt` (never passed through the host shell).
- Client wall time includes connect+bind+unbind, and the bind cost is
  **asymmetric**: 389-ds verifies the hashed root password (~50 ms under
  emulation) while OpenLDAP compares a plaintext `rootpw` (~0.1 ms). Each
  iteration records both BIND etime medians; the **server-side search etime
  column is the primary comparison metric**.
- Correctness is asserted against an *independent expectation*: every run on
  both servers must return exactly the DN set in `expected-dns-<shape>.txt`
  (count AND sorted-DN md5), which `generate-filter.py` computes from
  `data.ldif` — never from a server, so identical-but-wrong cannot pass. Each
  server's log window must also contain exactly the benchmark's operations,
  or nothing is recorded.
- 389-ds access log buffering is disabled (`nsslapd-accesslog-logbuffering:
  off`) so per-op `etime` is immediately visible; this can add small per-op
  overhead on the 389-ds side (affects log flushing, not search execution).
- 389-ds `notes=A/U` flags in results are recorded as-is; they are
  informative (unindexed/partially-indexed components are *intentional*),
  not a failure.
- OpenLDAP uses the deprecated-but-supported plain `slapd.conf(5)` file
  config for simplicity; `loglevel stats` plus `-d 256` writes stats lines
  (incl. `qtime`/`etime`) to `/var/log/slapd-repro.log`. slapd runs as root
  inside the container.
- No server-side performance tuning was applied to either server beyond the
  explicit index definitions above; everything else is stock defaults.
- Otherwise-identical LDIF is loaded into both servers (389-ds: online
  `dsconf backend import` + full reindex; OpenLDAP: offline `slapadd -q`).

## Re-entering the environment

```bash
docker ps --filter label=org.389ds.repro.source   # find this checkout's containers
docker exec -it repro-389ds-<hash> bash       # instance "repro"; logs in /var/log/dirsrv/slapd-repro/
docker exec -it repro-openldap-<hash> bash    # config /etc/openldap/slapd-repro.conf; log /var/log/slapd-repro.log
```

Both containers mount this directory at `/repro`. Root-DN password for both:
`Reproducer123` (override with `REPRO_DM_PASSWORD` before running the setup
scripts *and* the benchmark; no `%`, whitespace, or quotes — `%` breaks
dscreate's INF parser, the rest break generated config lines).

To try a different filter shape, re-run `generate-filter.py` with new
parameters (no reload needed — data is unchanged) and then `run-benchmark.sh`;
each invocation logs a new iteration in `measurements.md`. If you change
`generate-data.py` parameters, re-run both setup scripts to reload the data.
