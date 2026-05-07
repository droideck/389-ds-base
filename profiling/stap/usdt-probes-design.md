# Work-Queue and Worker-Thread USDT Probes

## Overview

USDT (User-level Statically Defined Tracing) probes are static markers compiled into the binary. With no tracer attached each probe is a single `nop`; arguments are not computed. When `bpftrace` or `stap` attaches, the kernel patches in a breakpoint at the probe address. The probe name is the contract, so tracing scripts survive minor refactors. SystemTap and bpftrace are packaged on Fedora and RHEL.

The 389-ds codebase has shipped 19 USDT probe points and three example `.stp` scripts under `profiling/stap/` for years, but the build was disabled by default and the RPM didn't pull in `systemtap-sdt-devel`. This commit:

- Flips `%bcond systemtap 1` so the default RPM build enables USDT.
- Adds `AC_CHECK_HEADER` for `<sys/sdt.h>` with a distro install hint so `--enable-systemtap` fails fast on a missing dep.
- Adds four new probes around the work-queue dispatcher in `connection.c`: `work_q__enqueue`, `work_q__dequeue`, `worker__busy`, `worker__idle`.
- Ships a new `probe_work_queue.stp` and updates `probe_do_search_detail.stp` for the dual-ELF layout.
- Adds tests at three layers (static `readelf`, live `bpftrace`, live `stap` script-runner).

Default-on in the RPM is safe because probes are zero-cost without a tracer; operators who don't want them in the binary can build with `rpmbuild --without systemtap`.

This is one observability tool among several. Most performance diagnosis comes from the access log (`wtime`/`optime`/`etime` are recorded per operation), from cn=monitor (connection and operation counters), or from external sampling of those over time. USDT covers the case where an operator has root and a tracer and needs per-op resolution or live cross-thread correlation that those static surfaces don't provide.

## Use cases

When access-log wtime analysis and cn=monitor polling don't give the granularity needed (typically a live incident where per-op handoff timing or cross-thread correlation matters), the shipped script `profiling/stap/probe_work_queue.stp` is the entry point. It pairs `work_q__enqueue` with `work_q__dequeue` on `(connid, opid)` to compute wait latencies, samples queue depth on every enqueue, and counts `worker__idle` events per thread. Run it as root against ns-slapd, drive workload from another shell, then `SIGINT` to print the `probe end { report() }` summary:

```
# stap profiling/stap/probe_work_queue.stp /usr/sbin/ns-slapd
^C
Distribution of work-queue depth at enqueue time (samples=2347)
max/avg/min: 4/1/0
value |-------------------------------------------------- count
    0 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   1834
    1 |@@@@@@@@@@@                                         421
    2 |@@                                                   78
    4 |                                                     14
    8 |                                                      0

Distribution of enqueue-to-dequeue wait latencies (microseconds) for 2347 samples
max/avg/min: 1842/47/2

Worker idle counts (per thread index):
  thread 1: 1421 idle waits
  thread 2: 1389 idle waits
  thread 3: 1397 idle waits
  thread 4: 1402 idle waits
```

Reading the output:

- The depth histogram is the fraction of ops that hit a non-empty queue. Most enqueues seeing depth 0 means the dispatcher is keeping up. A long tail at depth >> 0 means the worker pool is undersized for the offered load.
- The wait-latency histogram is the per-op handoff time. A long tail with shallow queue depth points at worker starvation (idle workers, slow handoff). A long tail with deep queue points at sustained load exceeding the pool.
- Idle counts per thread expose worker imbalance. A roughly flat distribution is normal. One thread parking 10x more than peers points at NSPR scheduling pathology or a long-lived connection pinning a single worker.

The `(connid, opid)` tuple emitted by `work_q__enqueue` matches the `conn=N op=M` pair on every RESULT line in the access log, so probe events can be cross-referenced with the access log directly. This is useful when `work_q__dequeue` fires promptly for an op but the RESULT line is late: the op was queued cleanly and is slow inside the backend (or the connection was sitting at `nsslapd-maxthreadsperconn`).

`bpftrace` reads the same probes by name (`usdt:/usr/sbin/ns-slapd:work_q__enqueue`, etc.) if a one-liner is more convenient than running the full script.

## Probes

| Probe | Args | Fired in |
|---|---|---|
| `work_q__enqueue` | `connid, opid, depth_after_enqueue` | `add_work_q()` |
| `work_q__dequeue` | `connid, opid, depth_at_dequeue`   | `connection_wait_for_new_work()` |
| `worker__busy`    | `connid, opid`                      | `connection_threadmain()` after pblock unpack |
| `worker__idle`    | `thread_idx`                        | `connection_threadmain()` before blocking on cv |

`thread_idx` is the worker's slot in `threads_indexes`.

## Lock discipline

Both queue-side probes snapshot args into stack locals under `work_q_lock`, then fire after unlock. Firing inside the lock would extend the critical section by whatever the tracer handler does. Firing after unlock with raw pointer reads would risk reading a recycled op_stack with `o_opid = 0`. Snapshot-locals gives bounded skew and no UAF surface.

## Dual-ELF layout

USDT probes are emitted into the object containing the source line. `connection.c` is in `ns_slapd_SOURCES`, so the four new probes live in `ns-slapd`. Existing probes from `log.c` and `opshared.c` are in `libslapd_la_SOURCES` and live in `libslapd.so`. `process("PATH").mark()` resolves marks against one ELF, so `.stp` scripts that trace both groups take two path arguments. `probe_do_search_detail.stp` does this.

## Bounding the wait-time map

`probe_work_queue.stp` keeps `enqueue_us[connid, opid]` to compute wait times: populated on enqueue, drained on the matching dequeue. Conns torn down between the two leave orphan entries.

The bound is one character: `global enqueue_us%`. The trailing `%` makes the map wrap: once `MAXMAPENTRIES` (default 2048) is hit, SystemTap evicts the oldest entry on each new insert. Other shipped scripts use the same idiom. Trade-off: with >= 2048 simultaneous in-flight ops some legitimate stamps get evicted before their dequeue arrives.

## Build

- Source: `./configure --enable-systemtap` (default off). `configure.ac` checks for `<sys/sdt.h>` and fails with a distro install hint.
- RPM: `%bcond systemtap 1` (on by default). Disable with `rpmbuild --without systemtap`.
- Runtime: nothing to configure.

## External impact

- `systemtap-sdt-devel` becomes a build dep of the default RPM build.
- Scripts targeting `usdt:ns-slapd:*` still work for `connection.c` probes. Scripts targeting `vslapd_log_*` or `op_shared_search__*` must point at `libslapd.so`.
- Tests: `dirsrvtests/tests/suites/systemtap/` verifies probes at three layers.
  - `usdt_probes_test.py` (tier1): parse `readelf -n`, run `stap -p1`.
  - `usdt_tracing_test.py` (tier2): attach bpftrace, assert probes fire with sane args.
  - `usdt_stap_scripts_test.py` (tier2): run each shipped `.stp` end-to-end, assert `Distribution of ...` lines have samples > 0.

  Tier-2 modules are gated by `USDT_TRACE_ACK=1`.

## Origin

GitHub issue: TBD

## Author

Simon Pichugin <spichugi@redhat.com>
