# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
"""End-to-end tests for shipped stap scripts under profiling/stap/."""
import concurrent.futures
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time

import ldap
import pytest

from lib389._constants import DEFAULT_SUFFIX, DN_DM, PW_DM
from lib389.idm.user import UserAccounts
from test389.topologies import topology_st as topo

from ._common import ns_slapd_path, libslapd_path, binary_has_sdt_notes

DEBUGGING = os.getenv("DEBUGGING", default=False)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG if DEBUGGING else logging.INFO)


_USDT_TRACE_ACK = os.environ.get('USDT_TRACE_ACK', '').lower() in ('1', 'true', 'yes')

pytestmark = [
    pytest.mark.tier2,
    pytest.mark.skipif(not _USDT_TRACE_ACK,
                       reason="set USDT_TRACE_ACK=1 to run live stap tests"),
    pytest.mark.skipif(not shutil.which("stap"),
                       reason="systemtap (stap) is not installed"),
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="stap requires root"),
]

PROFILING_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__),
                 "..", "..", "..", "..", "profiling", "stap")
)

_STAP_READY_MARKER = "Pass 5: starting run"

# Matches `samples=N` (work-queue) and `for N samples` (latency scripts).
_SAMPLES_RE = re.compile(r'samples=(\d+)|for\s+(\d+)\s+samples?\b')


@pytest.fixture(scope="module")
def usdt_topo(topo):
    binary = ns_slapd_path(topo)
    if not binary_has_sdt_notes(binary):
        pytest.skip("ns-slapd not built with --enable-systemtap")
    if not libslapd_path(topo):
        pytest.skip("libslapd.so not located under the instance prefix")
    return topo


@pytest.fixture
def workload_users(usdt_topo):
    inst = usdt_topo.standalone
    users = UserAccounts(inst, DEFAULT_SUFFIX)
    created = []
    for i in range(5):
        try:
            created.append(users.create_test_user(uid=900000 + i))
        except ldap.ALREADY_EXISTS:
            created.append(users.get(f"test_user_{900000 + i}"))
    yield created
    for u in created:
        try:
            u.delete()
        except ldap.NO_SUCH_OBJECT:
            pass


class _StapStderrReader(threading.Thread):
    """Drain stap stderr; signal once the pass-5 marker is seen."""
    def __init__(self, proc):
        super().__init__(daemon=True)
        self._proc = proc
        self._lines = []
        self.ready = threading.Event()

    def run(self):
        for line in iter(self._proc.stderr.readline, ""):
            self._lines.append(line)
            if _STAP_READY_MARKER in line:
                self.ready.set()
        self.ready.set()

    @property
    def stderr_text(self):
        return "".join(self._lines)


def _tail(text, n):
    return "\n".join(text.splitlines()[-n:])


def _run_stap_script(script_path, args, drive_load,
                     ready_timeout=60.0, drain_wait=1.5, exit_timeout=30.0):
    """Spawn stap, drive load after pass 5, SIGINT, return (stdout, stderr, rc)."""
    cmd = ["stap", "-v", script_path, *args]
    log.info("running: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    reader = _StapStderrReader(proc)
    reader.start()

    try:
        if not reader.ready.wait(timeout=ready_timeout):
            proc.kill()
            stdout, _ = proc.communicate()
            reader.join(timeout=2)
            pytest.fail(
                f"stap did not reach pass 5 within {ready_timeout}s.\n"
                f"stderr tail:\n{_tail(reader.stderr_text, 40)}"
            )
        if proc.poll() is not None:
            stdout, _ = proc.communicate()
            reader.join(timeout=2)
            pytest.fail(
                f"stap exited at pass 5 with code {proc.returncode}.\n"
                f"stderr tail:\n{_tail(reader.stderr_text, 40)}\n"
                f"stdout:\n{stdout}"
            )

        log.debug("stap is ready; driving workload")
        drive_load()
        time.sleep(drain_wait)

        log.debug("sending SIGINT to trigger probe end")
        proc.send_signal(signal.SIGINT)
        stdout, _ = proc.communicate(timeout=exit_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
        reader.join(timeout=2)
        pytest.fail(
            f"stap did not exit within {exit_timeout}s after SIGINT.\n"
            f"stderr tail:\n{_tail(reader.stderr_text, 40)}"
        )
    except BaseException:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        reader.join(timeout=2)
        raise

    reader.join(timeout=5)
    return stdout, reader.stderr_text, proc.returncode


def _sample_count_for_label(stdout, label_substr):
    """Sample count from the first line containing label_substr, or None."""
    for line in stdout.splitlines():
        if label_substr not in line:
            continue
        m = _SAMPLES_RE.search(line)
        if m:
            return int(m.group(1) or m.group(2))
        return None
    return None


def _drive_searches(inst, n=100):
    for _ in range(n):
        inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(objectClass=*)")


def _drive_searches_concurrent(inst, n=100, parallel=10):
    """Drive n searches over parallel fresh connections; persistent conns enter
    turbo mode and bypass the work queue."""
    url = f"ldap://localhost:{inst.port}"

    def one_search(_i):
        c = ldap.initialize(url)
        try:
            c.simple_bind_s(DN_DM, PW_DM)
            c.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, "(objectClass=*)")
        finally:
            try:
                c.unbind_s()
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
        list(ex.map(one_search, range(n)))


def _assert_distributions(stdout, labels):
    missing_lines = [l for l in labels if l not in stdout]
    assert not missing_lines, (
        f"missing report lines for: {missing_lines}\nstdout:\n{stdout}"
    )
    zero_or_unparsed = [
        (l, _sample_count_for_label(stdout, l)) for l in labels
        if (_sample_count_for_label(stdout, l) or 0) <= 0
    ]
    assert not zero_or_unparsed, (
        f"distributions with zero or unparseable sample counts:\n  " +
        "\n  ".join(f"{l}: samples={n}" for l, n in zero_or_unparsed) +
        f"\n\nstdout:\n{stdout}"
    )


def test_probe_work_queue_stp(usdt_topo, workload_users):
    """probe_work_queue.stp populates queue-depth, wait-latency, idle-counts under load.

    :id: fccc1ec3-b7af-4cae-a00a-628fc32d9160
    :setup: Standalone instance with --enable-systemtap, USDT_TRACE_ACK=1, stap, root
    :steps:
        1. Run probe_work_queue.stp against ns-slapd
        2. Drive 100 searches over 10 concurrent fresh connections
        3. SIGINT and capture report()
    :expectedresults:
        1. stap exits cleanly
        2. queue-depth and wait-latency distributions have samples > 0
        3. Worker idle counts section appears with per-thread lines
    """
    inst = usdt_topo.standalone
    script = os.path.join(PROFILING_DIR, "probe_work_queue.stp")
    stdout, stderr, rc = _run_stap_script(
        script, [ns_slapd_path(usdt_topo)],
        drive_load=lambda: _drive_searches_concurrent(inst, n=100, parallel=10),
    )
    log.debug("stdout:\n%s", stdout)
    assert rc == 0, f"stap exited {rc}\nstderr tail:\n{_tail(stderr, 40)}"

    _assert_distributions(stdout, [
        "Distribution of work-queue depth at enqueue time",
        "Distribution of enqueue-to-dequeue wait latencies",
    ])
    assert "Worker idle counts" in stdout, (
        f"missing 'Worker idle counts' section.\nstdout:\n{stdout}"
    )
    assert re.search(r'thread\s+\d+:\s+\d+\s+idle waits', stdout), (
        f"no per-thread idle counts reported.\nstdout:\n{stdout}"
    )


def test_probe_do_search_detail_stp(usdt_topo, workload_users):
    """probe_do_search_detail.stp aggregates four search-phase latencies.

    :id: 0b6c8f1b-a3e8-4d96-8468-c6de4aa7c58e
    :setup: Standalone instance with --enable-systemtap, USDT_TRACE_ACK=1, stap, root
    :steps:
        1. Run probe_do_search_detail.stp with @1=ns-slapd @2=libslapd.so
        2. Drive 100 searches
        3. SIGINT and parse report()
    :expectedresults:
        1. stap reaches pass 5 (probes armed)
        2. Searches complete and fire probes
        3. All four search-phase distributions report samples > 0; stap exits 0
    """
    inst = usdt_topo.standalone
    script = os.path.join(PROFILING_DIR, "probe_do_search_detail.stp")
    stdout, stderr, rc = _run_stap_script(
        script,
        [ns_slapd_path(usdt_topo), libslapd_path(usdt_topo)],
        drive_load=lambda: _drive_searches(inst, 100),
    )
    log.debug("stdout:\n%s", stdout)
    assert rc == 0, f"stap exited {rc}\nstderr tail:\n{_tail(stderr, 40)}"

    _assert_distributions(stdout, [
        "Distribution of do_search_full",
        "Distribution of do_search_prepared",
        "Distribution of do_search_complete",
        "Distribution of do_search_finalise",
    ])


def test_probe_op_shared_search_stp(usdt_topo, workload_users):
    """probe_op_shared_search.stp aggregates four phases of op_shared_search().

    :id: 55f7d66a-8cc1-49fe-97d7-971fd5748627
    :setup: Standalone instance with --enable-systemtap, USDT_TRACE_ACK=1, stap, root
    :steps:
        1. Run probe_op_shared_search.stp against libslapd.so
        2. Drive 100 searches
        3. SIGINT and parse report()
    :expectedresults:
        1. stap reaches pass 5 (probes armed)
        2. Searches complete and fire probes
        3. All four phase distributions report samples > 0; stap exits 0
    """
    inst = usdt_topo.standalone
    script = os.path.join(PROFILING_DIR, "probe_op_shared_search.stp")
    stdout, stderr, rc = _run_stap_script(
        script, [libslapd_path(usdt_topo)],
        drive_load=lambda: _drive_searches(inst, 100),
    )
    log.debug("stdout:\n%s", stdout)
    assert rc == 0, f"stap exited {rc}\nstderr tail:\n{_tail(stderr, 40)}"

    _assert_distributions(stdout, [
        "Distribution of op_shared_search_full",
        "Distribution of op_shared_search_prepared",
        "Distribution of op_shared_search_complete",
        "Distribution of op_shared_search_finalise",
    ])


def test_probe_log_access_detail_stp(usdt_topo, workload_users):
    """probe_log_access_detail.stp aggregates three access-log write phases.

    :id: 23d94e28-fc2a-4b07-b876-c0e4fe84d776
    :setup: Standalone instance with --enable-systemtap, USDT_TRACE_ACK=1, stap, root
    :steps:
        1. Run probe_log_access_detail.stp against libslapd.so
        2. Drive 100 searches
        3. SIGINT and parse report()
    :expectedresults:
        1. stap reaches pass 5 (probes armed)
        2. Searches complete and fire probes
        3. All three log-phase distributions report samples > 0; stap exits 0
    """
    inst = usdt_topo.standalone
    script = os.path.join(PROFILING_DIR, "probe_log_access_detail.stp")
    stdout, stderr, rc = _run_stap_script(
        script, [libslapd_path(usdt_topo)],
        drive_load=lambda: _drive_searches(inst, 100),
    )
    log.debug("stdout:\n%s", stdout)
    assert rc == 0, f"stap exited {rc}\nstderr tail:\n{_tail(stderr, 40)}"

    _assert_distributions(stdout, [
        "Distribution of log_access_full",
        "Distribution of log_access_prepared",
        "Distribution of log_access_complete",
    ])
