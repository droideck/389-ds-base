# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
"""Fleet-scale reproducer for memberOf deferred-update inconsistencies.

Reproduces the failure modes seen on large FreeIPA deployments running
389-ds with memberOfDeferredUpdate enabled: with deferred updates every
membership write becomes a task in an in-memory FIFO drained by a single
worker thread, the queue is not persisted, and memberOfLaunchFixup
defaults to off.  An unclean shutdown mid-backlog therefore loses queued
fanout tasks permanently.

The topology and configuration mirror FreeIPA without installing it:

- N suppliers in a full mesh, stood up one at a time with BDB cache
  autotuning disabled and explicit cache caps applied before the next
  instance is created (autotuned instances each size themselves as if
  they owned the host and exhaust /dev/shm during a 16-supplier standup)
- memberofgroupattr: member + two custom DN-syntax attributes
  (memberHostSim / memberUserSim), mirroring member/memberHost/memberUser
- memberOfDeferredUpdate: on, memberOfLaunchFixup left at its default (off)
- memberOf excluded from incremental replication but not from total init,
  exactly as FreeIPA configures its agreements
- HOSTS plain entries, groups holding them, and "rule" entries whose
  memberHostSim/memberUserSim values point at groups (nested fanout)

Workloads (run separately with -k, or in file order):

- W1: IPA-faithful single-value MOD_ADDs of members across suppliers,
  then kill -9 of one supplier mid-backlog.  Clients block until their
  own fanout task completes, so each add's client-observed latency is
  the time-to-back-link (lag probe).  The backlog window is created by
  the J-probe group DELETE itself: its fanout is one fat FIFO task, so
  every add issued while it runs has its task queued behind it, and the
  kill lands the moment the delete commits, while that fanout is
  mid-flight (proven post-restart by the orphan count).  After restart the
  killed supplier must show the startup fixup WARNING, permanently
  missing back-links (Type-A analogs), and orphaned memberOf values
  from the deleted group (Type-J analog).
- W2: one MOD_REPLACE with a new member prepended on a populated group.
  Every replica processes the replicated REPLACE independently, so the
  comparator defect (issue 7460) rewrites overlap members once per
  replica.  Churn is measured per supplier by entryUSN advancement of
  members whose membership did not change.
- W3: DELETE of a group holding all HOSTS entries.  The single worker
  executes the whole fanout while the deleting client and every other
  grouping-attribute writer spin-wait; the probe measures the delete
  duration, writer park times, and time until plain searches stall
  (thread-pool exhaustion).  Because the FIFO orders the writer tasks
  behind the delete task, no writer may complete before the delete
  client returns - that ordering is asserted instead of wall-clock
  thresholds.  An optional probe stops the instance mid-drain to
  exercise the systemd TimeoutStopSec race.

Environment knobs:

- MEMBEROF_REPRO_PROFILE     smoke (2 suppliers) | ci (4) | fidelity (16)
- MEMBEROF_REPRO_SUPPLIERS   overrides the supplier count directly
- MEMBEROF_REPRO_HOSTS       host entries to create (default 10000;
                             use >= 600 so the workload slices fit)
- MEMBEROF_REPRO_RULES       rule entries pointing at W1 groups (default 10)
- MEMBEROF_REPRO_W1_WRITERS  direct writers against the kill target (default 16)
- MEMBEROF_REPRO_W1_FEEDERS  writers spread over the other suppliers (default 4)
- MEMBEROF_REPRO_W1_MIN_BACKLOG  adds that must have landed before the
                             J-probe delete is issued (default 12)
- MEMBEROF_REPRO_W2_OVERLAP  overlap members in the REPLACE group
                             (default 100, capped at HOSTS/4)
- MEMBEROF_REPRO_W3_GROUP    members in the delete-hang group (default HOSTS)
- MEMBEROF_REPRO_W3_WRITERS  writers parked behind the delete (default threads+8)
- MEMBEROF_REPRO_W3_STOP     1 = stop the instance mid-drain (systemd hosts only)
- MEMBEROF_REPRO_THREADS     nsslapd-threadnumber (default scales with topology)
- MEMBEROF_REPRO_EXPECT      report (default) | stock | fixed - W2 assert policy
- MEMBEROF_REPRO_DRAIN_TIMEOUT  fleet drain wait in seconds (default scales)
- MEMBEROF_REPRO_DBCACHE     per-instance nsslapd-dbcachesize (default 128MB;
                             /dev/shm needs ~(DBCACHE + 40MB) * N)
- MEMBEROF_REPRO_ENTRYCACHE  per-backend nsslapd-cachememsize (default 512MB)

W1 asserts unconditionally: task loss on unclean shutdown is present on
both stock 2.8.0 and current upstream (the deferred machinery itself is
unchanged), so a failure means the reproducer did not reach a backlog,
not that the bug is fixed.  W2 depends on issue 7460, hence the EXPECT
knob: stock 2.8.0 churns, builds carrying 90735eb16 must not.

Sized for a Fedora/RHEL VM.  Smoke profile (2 suppliers, HOSTS=600) is
enough to validate the mechanics; fidelity (16 suppliers, HOSTS=90000)
approximates the customer deployment and runs for hours.
"""

import ldap
import logging
import os
import pytest
import re
import signal
import threading
import time
from ldap.filter import escape_filter_chars
from ldap.schema.models import AttributeType
from lib389 import DirSrv
from lib389._constants import (DEFAULT_SUFFIX, DN_DM, PW_DM, ReplicaRole,
                               SER_CREATION_SUFFIX, SER_PORT,
                               SER_SECURE_PORT, SER_SERVERID_PROP)
from lib389.agreement import Agreements
from lib389.backend import Backends
from lib389.config import LDBMConfig
from lib389.dirsrv_log import DirsrvErrorLog
from lib389.plugins import MemberOfPlugin, USNPlugin
from lib389.replica import Replicas, ReplicationManager
from lib389.schema import Schema, OBJECT_MODEL_PARAMS
from lib389.topologies import TopologyMain
from lib389.utils import generate_ds_params, get_default_db_lib

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


def _db_is_mdb():
    try:
        return get_default_db_lib() == "mdb"
    except Exception:
        return False


pytestmark = [
    pytest.mark.tier3,
    pytest.mark.skipif(_db_is_mdb(),
                       reason="memberOfDeferredUpdate is force-disabled on LMDB"),
]

_PROFILES = {'smoke': 2, 'ci': 4, 'fidelity': 16}
PROFILE = os.getenv('MEMBEROF_REPRO_PROFILE', 'smoke')
N_SUPPLIERS = int(os.getenv('MEMBEROF_REPRO_SUPPLIERS',
                            _PROFILES.get(PROFILE, 2)))
HOSTS = int(os.getenv('MEMBEROF_REPRO_HOSTS', '10000'))
RULES = int(os.getenv('MEMBEROF_REPRO_RULES', '10'))
W1_TARGET_WRITERS = int(os.getenv('MEMBEROF_REPRO_W1_WRITERS', '16'))
W1_FEEDERS = int(os.getenv('MEMBEROF_REPRO_W1_FEEDERS', '4'))
W1_MIN_BACKLOG = int(os.getenv('MEMBEROF_REPRO_W1_MIN_BACKLOG', '12'))
W1_BUILD_TIMEOUT = int(os.getenv('MEMBEROF_REPRO_W1_BUILD_TIMEOUT', '600'))
W2_OVERLAP = min(int(os.getenv('MEMBEROF_REPRO_W2_OVERLAP', '100')),
                 max(10, HOSTS // 4))
W3_SIZE = min(int(os.getenv('MEMBEROF_REPRO_W3_GROUP', str(HOSTS))), HOSTS)
W3_STOP_PROBE = os.getenv('MEMBEROF_REPRO_W3_STOP', '0') == '1'
EXPECT = os.getenv('MEMBEROF_REPRO_EXPECT', 'report')

# Every client whose op touched a grouping attribute occupies a server
# worker thread in the 100ms result-poll loop until the deferred worker
# reaches its task, and each incoming replication session can park up to
# maxthreadsperconn more.  The pool must leave headroom for the monitor
# searches or the probes go blind.
THREADNUMBER = int(os.getenv(
    'MEMBEROF_REPRO_THREADS',
    str(max(32, W1_TARGET_WRITERS + 5 * (N_SUPPLIERS - 1) + 8))))
W3_WRITERS = int(os.getenv('MEMBEROF_REPRO_W3_WRITERS', str(THREADNUMBER + 8)))
DRAIN_TIMEOUT = int(os.getenv('MEMBEROF_REPRO_DRAIN_TIMEOUT',
                              str(max(1200, HOSTS // 5))))

# BDB cache autotuning sizes every instance as if it owned the host, so
# an uncapped 16-supplier standup wants ~800MB of /dev/shm region files
# PER INSTANCE and dies with bdb_no_diskspace partway through creation.
# Caps are applied to each instance before the next one is created;
# budget roughly (DBCACHE + 40MB) * N of /dev/shm for the fleet.
DBCACHE = int(os.getenv('MEMBEROF_REPRO_DBCACHE', str(128 * 1024 * 1024)))
ENTRYCACHE = int(os.getenv('MEMBEROF_REPRO_ENTRYCACHE',
                           str(512 * 1024 * 1024)))

JGROUP_SIZE = min(4000, max(min(500, HOSTS // 2), HOSTS // 5))
PRIMER_SIZE = min(2000, max(100, HOSTS // 10))

FLEET_OU = f'ou=fleetrepro,{DEFAULT_SUFFIX}'
HOSTS_OU = f'ou=hosts,{FLEET_OU}'
HOST_DNS = [f'cn=h{i:06d},{HOSTS_OU}' for i in range(HOSTS)]

WARN_RE = '.*It is recommended to launch memberof fixup task.*'


def _dm_conn(inst, timeout=None):
    conn = ldap.initialize(f'ldap://{inst.host}:{inst.port}')
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    if timeout is not None:
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)
        conn.set_option(ldap.OPT_TIMEOUT, timeout)
    conn.simple_bind_s(DN_DM, PW_DM)
    return conn


def _safe_unbind(conn):
    try:
        conn.unbind_s()
    except ldap.LDAPError:
        pass


def _ensure_ou(conn, dn):
    ou_val = dn.split(',', 1)[0].split('=', 1)[1]
    try:
        conn.add_s(dn, [('objectClass', [b'top', b'organizationalUnit']),
                        ('ou', [ou_val.encode()])])
    except ldap.ALREADY_EXISTS:
        pass


def _count_filter(conn, base, filt):
    return len(conn.search_s(base, ldap.SCOPE_SUBTREE, filt, ['1.1']))


def _holder_filter(group_dn):
    return f'(memberOf={escape_filter_chars(group_dn)})'


def _holder_set(conn, group_dn):
    res = conn.search_s(HOSTS_OU, ldap.SCOPE_SUBTREE,
                        _holder_filter(group_dn), ['1.1'])
    return {dn.lower() for dn, _ in res}


def _member_set(conn, group_dn):
    res = conn.search_s(group_dn, ldap.SCOPE_BASE, '(objectClass=*)',
                        ['member'])
    vals = res[0][1].get('member', [])
    return {v.decode().lower() for v in vals}


def _entry_exists(conn, dn):
    try:
        conn.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)', ['1.1'])
        return True
    except ldap.NO_SUCH_OBJECT:
        return False


def _wait_count(conn, base, filt, expected, timeout, what):
    deadline = time.monotonic() + timeout
    count = -1
    while time.monotonic() < deadline:
        count = _count_filter(conn, base, filt)
        if count == expected:
            return
        time.sleep(2)
    pytest.fail(f'{what}: expected {expected}, still {count} '
                f'after {timeout}s')


def _quiesce_count(conn, base, filt, timeout, polls=3, interval=5):
    """Wait until the count is unchanged for `polls` consecutive samples."""
    deadline = time.monotonic() + timeout
    last = -1
    stable = 0
    while time.monotonic() < deadline:
        count = _count_filter(conn, base, filt)
        if count == last:
            stable += 1
            if stable >= polls:
                return count
        else:
            stable = 0
            last = count
        time.sleep(interval)
    return last


def _usn_snapshot(conn, group_dn):
    res = conn.search_s(HOSTS_OU, ldap.SCOPE_SUBTREE,
                        _holder_filter(group_dn), ['entryusn'])
    return {dn.lower(): int(attrs['entryusn'][0]) for dn, attrs in res}


def _usn_stable_snapshot(conn, group_dn, timeout=120, interval=5):
    """Snapshot entryUSNs once two consecutive samples are identical."""
    snap = _usn_snapshot(conn, group_dn)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(interval)
        again = _usn_snapshot(conn, group_dn)
        if again == snap:
            return snap
        snap = again
    return snap


def _add_sim_schema(inst):
    schema = Schema(inst)
    for name, oid in (('memberHostSim', '1.3.6.1.4.1.99999.389.1'),
                      ('memberUserSim', '1.3.6.1.4.1.99999.389.2')):
        # the full defaults dict is required: _add_schema_object only
        # sets the keys it is given, and python-ldap's __str__ needs
        # every model attribute present
        parameters = OBJECT_MODEL_PARAMS[AttributeType].copy()
        parameters.update({
            'names': (name,),
            'oid': oid,
            'desc': 'fleet reproducer DN-syntax grouping attribute',
            'syntax': '1.3.6.1.4.1.1466.115.121.1.12',
            'equality': 'distinguishedNameMatch',
            'x_origin': ('memberof fleet reproducer',),
        })
        try:
            schema.add_attributetype(parameters)
        except ValueError:
            pass


def _bulk_add_hosts(inst, loaders=4):
    # nsMemberOf up front keeps autoaddoc from generating objectClass
    # MODs on the hosts later: those MODs replicate (only memberOf is
    # excluded) and their echoes would advance entryUSNs under W2's feet.
    def load(dns):
        conn = _dm_conn(inst)
        try:
            for dn in dns:
                cn = dn.split(',', 1)[0].split('=', 1)[1]
                try:
                    conn.add_s(dn, [('objectClass',
                                     [b'top', b'device', b'nsMemberOf']),
                                    ('cn', [cn.encode()])])
                except ldap.ALREADY_EXISTS:
                    pass
        finally:
            _safe_unbind(conn)

    threads = []
    for i in range(loaders):
        t = threading.Thread(target=load, args=(HOST_DNS[i::loaders],),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def _fleet_barrier(repl, source, suppliers, timeout):
    for inst in suppliers:
        if inst is not source:
            repl.wait_for_replication(source, inst, timeout=timeout)


def _create_supplier(idx):
    """dscreate one supplier and cap its caches before the next one
    is created - autotuned instances each claim /dev/shm as if they
    owned the host."""
    params = generate_ds_params(idx, ReplicaRole.SUPPLIER)
    inst = DirSrv(verbose=bool(DEBUGGING))
    inst.allocate({SER_PORT: params[SER_PORT],
                   SER_SECURE_PORT: params[SER_SECURE_PORT],
                   SER_SERVERID_PROP: params[SER_SERVERID_PROP],
                   SER_CREATION_SUFFIX: DEFAULT_SUFFIX})
    if inst.exists():
        inst.delete()
    inst.create()
    inst.use_ldap_uri()
    inst.open()
    inst.config.set('nsslapd-accesslog-logbuffering', 'off')
    ldbm = LDBMConfig(inst)
    ldbm.set('nsslapd-cache-autosize', '0')
    ldbm.set('nsslapd-cache-autosize-split', '0')
    ldbm.set('nsslapd-dbcachesize', str(DBCACHE))
    Backends(inst).get('userRoot').set('nsslapd-cachememsize',
                                       str(ENTRYCACHE))
    inst.restart()
    return inst


@pytest.fixture(scope="module", params=[N_SUPPLIERS],
                ids=lambda n: f"suppliers{n}")
def fleet(request):
    if request.param < 2:
        pytest.skip("needs at least 2 suppliers")
    insts = []

    def fin():
        for inst in insts:
            try:
                inst.stop()
            except Exception:
                pass
            if not DEBUGGING and inst.exists():
                inst.delete()
    request.addfinalizer(fin)

    for i in range(request.param):
        insts.append(_create_supplier(i + 1))
    suppliers = insts
    s1 = suppliers[0]

    log.info('Meshing %d suppliers', len(suppliers))
    repl = ReplicationManager(DEFAULT_SUFFIX)
    repl.create_first_supplier(s1)
    for m in suppliers[1:]:
        repl.join_supplier(s1, m)
    for mo in suppliers:
        for mi in suppliers:
            if mo is not mi:
                repl.ensure_agreement(mo, mi)

    topo = TopologyMain(suppliers={inst.serverid: inst
                                   for inst in suppliers})

    for inst in suppliers:
        _add_sim_schema(inst)

    for inst in suppliers:
        memberof = MemberOfPlugin(inst)
        memberof.enable()
        memberof.set_autoaddoc('nsMemberOf')
        memberof.replace_groupattr('member')
        memberof.add_groupattr('memberHostSim')
        memberof.add_groupattr('memberUserSim')
        memberof.set_memberofdeferredupdate('on')
        # memberOfLaunchFixup deliberately left at its default (off)
        USNPlugin(inst).enable()
        inst.config.set('nsslapd-threadnumber', str(THREADNUMBER))
        inst.config.set('nsslapd-sizelimit', '-1')
        inst.config.set('nsslapd-auditlog-logging-enabled', 'on')
        be = Backends(inst).get('userRoot')
        for attr in ('member', 'memberOf', 'memberHostSim', 'memberUserSim'):
            try:
                be.add_index(attr, ['eq'])
            except (ldap.ALREADY_EXISTS, ValueError):
                pass
        for agmt in Agreements(inst).list():
            agmt.replace_many(
                ('nsDS5ReplicatedAttributeList',
                 '(objectclass=*) $ EXCLUDE memberOf'),
                ('nsDS5ReplicatedAttributeListTotal',
                 '(objectclass=*) $ EXCLUDE '))
        # The deferred park starves the consumer's replication results
        # (repl5_inc_waitfor_async_results times out and the session
        # dies), which is the customer's lag pathology - but the default
        # 300s backoff between sessions turns every death into minutes
        # of dead air.  Shrink the backoff so the barriers measure the
        # mechanism, not the retry schedule.
        replica = Replicas(inst).get(DEFAULT_SUFFIX)
        replica.replace_many(('nsds5ReplicaBackoffMin', '1'),
                             ('nsds5ReplicaBackoffMax', '10'))

    for inst in suppliers:
        inst.restart()

    s1 = suppliers[0]
    conn = _dm_conn(s1)
    try:
        _ensure_ou(conn, FLEET_OU)
        _ensure_ou(conn, HOSTS_OU)
    finally:
        _safe_unbind(conn)

    log.info('Loading %d host entries on %s', HOSTS, s1.serverid)
    t0 = time.monotonic()
    _bulk_add_hosts(s1)
    log.info('Host load took %.1fs', time.monotonic() - t0)

    _fleet_barrier(repl, s1, suppliers, timeout=max(600, HOSTS // 10))
    for inst in suppliers:
        conn = _dm_conn(inst, timeout=60)
        try:
            _wait_count(conn, HOSTS_OU, '(objectClass=device)', HOSTS,
                        timeout=max(300, HOSTS // 20),
                        what=f'host replication to {inst.serverid}')
        finally:
            _safe_unbind(conn)

    return topo


def test_w1_add_workload_kill_mid_backlog(fleet):
    """Deferred task loss on unclean shutdown produces permanent damage.

    :id: 3a9d61f2-8a5e-4f0b-9c3d-6d2f0d7c4b11
    :setup: N suppliers, full mesh, IPA-shaped memberOf config with
            deferred updates on and memberOf excluded from incremental
            replication
    :steps:
        1. Create an empty workload group and a populated J-probe group,
           plus rule entries pointing at both through the custom
           DN-syntax grouping attributes
        2. Wait for the J-probe back-links to exist on every supplier
        3. Run single-value MOD_ADDs of members: direct writers against
           the kill target plus feeders on the other suppliers,
           recording each add's client-observed latency
           (time-to-back-link), plus a primer group ADD on the target
        4. Once the workload is flowing, DELETE the J-probe group on
           the target: its fanout is one fat FIFO task and every add
           issued while it runs queues behind it
        5. kill -9 the target the moment the delete commits, then
           restart it
        6. Check the startup WARNING recommending a memberof fixup
        7. Let replication converge and all deferred queues drain (on
           unkilled suppliers the replicated J-probe delete must clean
           up completely)
        8. Count members whose back-link is permanently missing on the
           target (Type-A analogs) and entries still holding memberOf of
           the deleted group (Type-J analogs)
    :expectedresults:
        1. Success
        2. Success
        3. Adds succeed until the kill; latency samples show queue lag
        4. Delete commits while its fanout task is queued or running
        5. Instance restarts
        6. WARNING logged more times than before the kill
        7. All suppliers converge
        8. Target shows Type-A damage and, unless the fanout won the
           race against the kill, Type-J damage; an unkilled control
           supplier shows none
    """
    suppliers = list(fleet.ms.values())
    s1, target = suppliers[0], suppliers[1]
    repl = ReplicationManager(DEFAULT_SUFFIX)
    barrier_timeout = max(600, HOSTS // 10)

    w1_ou = f'ou=w1,{FLEET_OU}'
    rules_ou = f'ou=rules,{w1_ou}'
    w1group_dn = f'cn=w1group,{w1_ou}'
    jgroup_dn = f'cn=w1jgroup,{w1_ou}'
    primer_dn = f'cn=w1primer,{w1_ou}'
    jmembers = HOST_DNS[:JGROUP_SIZE]
    # The tail of HOST_DNS is reserved for W2's overlap slice so leaked
    # or late W1 fanout can never advance the entryUSNs W2 measures.
    pool = HOST_DNS[JGROUP_SIZE:HOSTS - (W2_OVERLAP + 1)]
    n_writers = W1_TARGET_WRITERS + W1_FEEDERS
    if len(pool) < n_writers * 4:
        pytest.fail(f'HOSTS={HOSTS} too small: {len(pool)} spare hosts for '
                    f'{n_writers} writers; raise MEMBEROF_REPRO_HOSTS')

    conn1 = _dm_conn(s1)
    _ensure_ou(conn1, w1_ou)
    _ensure_ou(conn1, rules_ou)
    conn1.add_s(w1group_dn, [('objectClass', [b'top', b'groupOfNames']),
                             ('cn', [b'w1group'])])
    t0 = time.monotonic()
    conn1.add_s(jgroup_dn, [('objectClass', [b'top', b'groupOfNames']),
                            ('cn', [b'w1jgroup']),
                            ('member', [dn.encode() for dn in jmembers])])
    log.info('J-probe group add (%d members) blocked the client for %.1fs',
             JGROUP_SIZE, time.monotonic() - t0)

    for i in range(RULES):
        rule_dn = f'cn=rule{i:03d},{rules_ou}'
        attr = 'memberHostSim' if i % 2 == 0 else 'memberUserSim'
        group = w1group_dn if i % 2 == 0 else jgroup_dn
        conn1.add_s(rule_dn, [('objectClass', [b'top', b'extensibleObject']),
                              ('cn', [f'rule{i:03d}'.encode()]),
                              (attr, [group.encode()])])
    _safe_unbind(conn1)

    _fleet_barrier(repl, s1, suppliers, timeout=barrier_timeout)
    for inst in suppliers:
        conn = _dm_conn(inst, timeout=60)
        try:
            _wait_count(conn, HOSTS_OU, _holder_filter(jgroup_dn),
                        JGROUP_SIZE, timeout=DRAIN_TIMEOUT,
                        what=f'J-probe back-links on {inst.serverid}')
        finally:
            _safe_unbind(conn)

    stop_evt = threading.Event()
    lag_samples = []
    lag_lock = threading.Lock()

    def writer(inst, dns, record_lag):
        conn = _dm_conn(inst)
        try:
            for dn in dns:
                if stop_evt.is_set():
                    break
                t = time.monotonic()
                try:
                    conn.modify_s(w1group_dn,
                                  [(ldap.MOD_ADD, 'member', [dn.encode()])])
                except ldap.LDAPError:
                    break
                if record_lag:
                    with lag_lock:
                        lag_samples.append(time.monotonic() - t)
        finally:
            _safe_unbind(conn)

    def add_primer():
        conn = _dm_conn(target)
        try:
            t = time.monotonic()
            conn.add_s(primer_dn,
                       [('objectClass', [b'top', b'groupOfNames']),
                        ('cn', [b'w1primer']),
                        ('member',
                         [dn.encode() for dn in HOST_DNS[:PRIMER_SIZE]])])
            log.info('primer fanout completed before the kill (%.1fs)',
                     time.monotonic() - t)
        except ldap.LDAPError as e:
            log.info('primer client saw %s (expected after kill)',
                     type(e).__name__)
        finally:
            _safe_unbind(conn)

    half = len(pool) // 2
    target_pool, feeder_pool = pool[:half], pool[half:]
    feeder_insts = [i for i in suppliers if i is not target]

    errlog = DirsrvErrorLog(target)
    warn_before = len(errlog.match(WARN_RE))

    threads = []
    primer_thread = threading.Thread(target=add_primer, daemon=True)
    delete_thread = None
    mon = _dm_conn(target, timeout=30)
    jgroup_committed = False
    try:
        for i in range(W1_TARGET_WRITERS):
            t = threading.Thread(
                target=writer,
                args=(target, target_pool[i::W1_TARGET_WRITERS], False),
                daemon=True)
            t.start()
            threads.append(t)
        for i in range(W1_FEEDERS):
            t = threading.Thread(
                target=writer,
                args=(feeder_insts[i % len(feeder_insts)],
                      feeder_pool[i::W1_FEEDERS], True),
                daemon=True)
            t.start()
            threads.append(t)
        primer_thread.start()

        members = 0
        deadline = time.monotonic() + W1_BUILD_TIMEOUT
        while time.monotonic() < deadline:
            members = len(_member_set(mon, w1group_dn))
            if members >= W1_MIN_BACKLOG:
                break
            if all(not t.is_alive() for t in threads):
                pytest.fail(f'writers exhausted their pools after only '
                            f'{members} adds; raise MEMBEROF_REPRO_HOSTS')
            time.sleep(0.2)
        else:
            pytest.fail(f'only {members} members added after '
                        f'{W1_BUILD_TIMEOUT}s; the add workload is not '
                        f'flowing')
        log.info('Workload flowing on %s (%d members); issuing the '
                 'J-probe delete', target.serverid, members)

        def delete_jgroup():
            conn = _dm_conn(target)
            try:
                conn.delete_s(jgroup_dn)
            except ldap.LDAPError as e:
                log.info('J-probe delete client saw %s (expected after '
                         'kill)', type(e).__name__)
            finally:
                _safe_unbind(conn)

        with open(target.pid_file(), 'r') as f:
            target_pid = int(f.readline().strip())
        assert target_pid > 0
        delete_thread = threading.Thread(target=delete_jgroup, daemon=True)
        delete_thread.start()
        gone_deadline = time.monotonic() + 15
        while time.monotonic() < gone_deadline:
            if not _entry_exists(mon, jgroup_dn):
                jgroup_committed = True
                break
            time.sleep(0.01)
        # No sampling between commit detection and the kill: every
        # millisecond here lets the worker chew further through the
        # J-probe fanout, and on fast hardware two searches are enough
        # for it to finish.  Whether the fanout was mid-flight is
        # decided post-restart from the orphan count.
        log.info('SIGKILL pid %d (%s)', target_pid, target.serverid)
        os.kill(target_pid, signal.SIGKILL)
    finally:
        stop_evt.set()
        for t in threads + [primer_thread]:
            if t.ident is not None:
                t.join(timeout=30)
        if delete_thread is not None:
            delete_thread.join(timeout=30)
        _safe_unbind(mon)

    log.info('J-probe at kill: committed=%s', jgroup_committed)

    target.restart()
    warn_after = warn_before
    warn_deadline = time.monotonic() + 60
    while time.monotonic() < warn_deadline:
        warn_after = len(errlog.match(WARN_RE))
        if warn_after > warn_before:
            break
        time.sleep(2)
    assert warn_after > warn_before, \
        'startup WARNING recommending memberof fixup not logged after kill'

    tconn = _dm_conn(target, timeout=60)
    try:
        jgroup_deleted = not _entry_exists(tconn, jgroup_dn)
    finally:
        _safe_unbind(tconn)

    # No wait_for_replication barrier here: post-SIGKILL the target's
    # replay sessions are ack-throttled by the deferred park on every
    # replicated grouping op (repl5_inc_waitfor_async_results timeouts
    # on the supplier side), so a marker round-trip can lag by tens of
    # minutes.  The measurement loop below waits on the specific
    # entries it samples instead.
    results = {}
    for inst in suppliers:
        conn = _dm_conn(inst, timeout=60)
        try:
            if jgroup_deleted and inst is not target:
                # the replicated delete must clean this supplier fully;
                # waiting for zero is also the drain barrier for the fat
                # delete-fanout task sitting in this supplier's FIFO
                _wait_count(conn, HOSTS_OU, _holder_filter(jgroup_dn), 0,
                            timeout=DRAIN_TIMEOUT,
                            what=f'J-probe cleanup on {inst.serverid}')
            _quiesce_count(conn, HOSTS_OU, _holder_filter(w1group_dn),
                           timeout=DRAIN_TIMEOUT)
            if inst is target:
                _quiesce_count(conn, HOSTS_OU, _holder_filter(jgroup_dn),
                               timeout=300)
            members = _member_set(conn, w1group_dn)
            holders = _holder_set(conn, w1group_dn)
            missing = members - holders
            orphans = _count_filter(conn, HOSTS_OU, _holder_filter(jgroup_dn))
            results[inst.serverid] = {
                'members': len(members),
                'missing': len(missing),
                'orphans': orphans,
            }
        finally:
            _safe_unbind(conn)

    if lag_samples:
        log.info('W1 lag (client-observed add latency): n=%d avg=%.2fs '
                 'max=%.2fs', len(lag_samples),
                 sum(lag_samples) / len(lag_samples), max(lag_samples))
    for sid, r in results.items():
        log.info('W1 %s: members=%d missing_backlinks=%d orphans=%d',
                 sid, r['members'], r['missing'], r['orphans'])

    tres = results[target.serverid]
    cres = results[s1.serverid]
    if tres['missing'] == 0 and tres['orphans'] == 0:
        pytest.fail('the kill raced an empty deferred queue - no damage '
                    'on the killed supplier; raise MEMBEROF_REPRO_HOSTS '
                    'to widen the J-probe fanout window')
    assert tres['missing'] > 0, \
        'no permanently missing back-links (Type-A) on the killed supplier'
    if jgroup_deleted and tres['orphans'] == 0:
        log.warning('J-probe fanout finished before the kill; Type-J '
                    'probe inconclusive this run (raise '
                    'MEMBEROF_REPRO_HOSTS for a wider window)')
    if not jgroup_deleted:
        log.warning('J-probe delete did not commit before the kill; '
                    'Type-J probe inconclusive this run')
    assert cres['missing'] == 0, \
        f'control supplier {s1.serverid} has missing back-links'
    if jgroup_deleted:
        assert cres['orphans'] == 0, \
            f'control supplier {s1.serverid} has orphaned memberOf values'


def test_w2_replace_churn_per_replica(fleet):
    """A group MOD_REPLACE with one new member rewrites overlap members per replica.

    :id: 5b7c02de-90ab-4a31-b9f4-7f4f2a6d9c22
    :setup: Same fleet as W1
    :steps:
        1. Create a group holding the overlap members and wait for
           back-links on every supplier
        2. Snapshot every overlap member's entryUSN on every supplier,
           requiring two identical consecutive samples so replication
           echoes from earlier activity cannot pollute the baseline
        3. MOD_REPLACE the member list with a new member prepended
        4. Wait for the new member's back-link on every supplier, then
           for entryUSN values to quiesce
        5. Count overlap members whose entryUSN advanced, per supplier
    :expectedresults:
        1. Success
        2. Success
        3. Success
        4. All members hold back-links on all suppliers (churn is
           del+re-add, not loss)
        5. Stock 2.8.0: overlap members rewritten on every supplier
           independently; with the issue 7460 fix: zero rewrites
    """
    suppliers = list(fleet.ms.values())
    s1 = suppliers[0]
    repl = ReplicationManager(DEFAULT_SUFFIX)

    w2_ou = f'ou=w2,{FLEET_OU}'
    w2group_dn = f'cn=w2group,{w2_ou}'
    overlap = HOST_DNS[-W2_OVERLAP:]
    new_member = HOST_DNS[-(W2_OVERLAP + 1)]

    conn1 = _dm_conn(s1)
    _ensure_ou(conn1, w2_ou)
    conn1.add_s(w2group_dn, [('objectClass', [b'top', b'groupOfNames']),
                             ('cn', [b'w2group']),
                             ('member', [dn.encode() for dn in overlap])])
    _fleet_barrier(repl, s1, suppliers, timeout=600)

    conns = {}
    for inst in suppliers:
        conns[inst.serverid] = _dm_conn(inst, timeout=60)
    try:
        for inst in suppliers:
            _wait_count(conns[inst.serverid], HOSTS_OU,
                        _holder_filter(w2group_dn), W2_OVERLAP,
                        timeout=DRAIN_TIMEOUT,
                        what=f'W2 back-links on {inst.serverid}')
        before = {sid: _usn_stable_snapshot(c, w2group_dn)
                  for sid, c in conns.items()}

        t0 = time.monotonic()
        conn1.modify_s(w2group_dn, [
            (ldap.MOD_REPLACE, 'member',
             [dn.encode() for dn in [new_member] + overlap])])
        log.info('W2 replace blocked the client for %.1fs',
                 time.monotonic() - t0)

        _fleet_barrier(repl, s1, suppliers, timeout=600)
        after = {}
        for inst in suppliers:
            sid = inst.serverid
            _wait_count(conns[sid], HOSTS_OU, _holder_filter(w2group_dn),
                        W2_OVERLAP + 1, timeout=DRAIN_TIMEOUT,
                        what=f'W2 post-replace back-links on {sid}')
            after[sid] = _usn_stable_snapshot(conns[sid], w2group_dn)
    finally:
        _safe_unbind(conn1)
        for c in conns.values():
            _safe_unbind(c)

    churn = {}
    churn_sample = {}
    for sid in before:
        advanced = [dn for dn, usn in before[sid].items()
                    if after[sid].get(dn, usn) > usn]
        churn[sid] = len(advanced)
        if advanced:
            churn_sample[sid] = advanced[0]
        log.info('W2 %s: %d of %d overlap members rewritten', sid,
                 churn[sid], W2_OVERLAP)

    # On churn, dump the audit-log blocks for one rewritten member so
    # the writer (modifiersName + changes) is identifiable post-run.
    for inst in suppliers:
        sid = inst.serverid
        if sid not in churn_sample:
            continue
        try:
            with open(inst.ds_paths.audit_log) as f:
                audit = f.read()
        except OSError as e:
            log.warning('W2 %s: cannot read audit log: %s', sid, e)
            continue
        rdn = churn_sample[sid].split(',', 1)[0]
        blocks = [b for b in audit.split('\n\n') if rdn in b]
        log.info('W2 %s: audit blocks for %s (%d total, last 3):\n%s',
                 sid, churn_sample[sid], len(blocks),
                 '\n---\n'.join(blocks[-3:]))

    if EXPECT == 'stock':
        for sid, n in churn.items():
            assert n > 0, f'{sid}: no churn - is this build carrying the ' \
                          f'issue 7460 fix? Set MEMBEROF_REPRO_EXPECT=fixed'
    elif EXPECT == 'fixed':
        for sid, n in churn.items():
            assert n == 0, f'{sid}: {n} overlap members rewritten on a ' \
                           f'build that should carry the issue 7460 fix'
    else:
        log.info('W2 EXPECT=report: churn per supplier: %s', churn)


def test_w3_group_delete_hang(fleet):
    """Deleting a large group stalls all grouping-attribute writers.

    :id: 9c1f4d70-2e8b-4c5a-8f1d-3b6a5e0d7f33
    :setup: Same fleet as W1
    :steps:
        1. Create a group holding the W3 member set and wait for
           back-links on every supplier
        2. DELETE the group from a dedicated connection (client blocks
           until the single worker finishes the whole fanout)
        3. Park writer connections doing grouping-attribute MOD_ADDs
           behind the delete task
        4. Probe with fresh read connections until searches stall
           (thread-pool exhaustion) and record the timeline
        5. Optionally stop the instance mid-drain to exercise the
           systemd TimeoutStopSec race, then check the on-disk
           memberOfNeedFixup marker and orphan count
        6. Otherwise wait for the drain, then verify FIFO ordering (no
           writer completed before the delete client returned), that
           writers completed, and that no back-links remain
    :expectedresults:
        1. Success
        2. Delete returns only after the whole fanout
        3. Writers park for the duration of the drain
        4. With writers exceeding the thread pool, searches stall
        5. A stop that exceeds TimeoutStopSec loses the queue and
           leaves the marker set
        6. Clean drain leaves no orphans and every successful writer
           finished after the delete client returned
    """
    suppliers = list(fleet.ms.values())
    s1 = suppliers[0]
    repl = ReplicationManager(DEFAULT_SUFFIX)
    w3_ou = f'ou=w3,{FLEET_OU}'
    w3group_dn = f'cn=w3group,{w3_ou}'
    w3members = HOST_DNS[:W3_SIZE]
    drain_timeout = max(DRAIN_TIMEOUT, W3_SIZE // 10)

    conn1 = _dm_conn(s1)
    _ensure_ou(conn1, w3_ou)
    t0 = time.monotonic()
    conn1.add_s(w3group_dn, [('objectClass', [b'top', b'groupOfNames']),
                             ('cn', [b'w3group']),
                             ('member', [dn.encode() for dn in w3members])])
    add_duration = time.monotonic() - t0
    log.info('W3 group add (%d members) blocked the client for %.1fs',
             W3_SIZE, add_duration)

    writer_groups = []
    for i in range(W3_WRITERS):
        gdn = f'cn=w3writer{i:03d},{w3_ou}'
        conn1.add_s(gdn, [('objectClass', [b'top', b'groupOfNames']),
                          ('cn', [f'w3writer{i:03d}'.encode()])])
        writer_groups.append(gdn)
    _safe_unbind(conn1)

    _fleet_barrier(repl, s1, suppliers, timeout=600)
    for inst in suppliers:
        conn = _dm_conn(inst, timeout=60)
        try:
            _wait_count(conn, HOSTS_OU, _holder_filter(w3group_dn), W3_SIZE,
                        timeout=drain_timeout,
                        what=f'W3 back-links on {inst.serverid}')
        finally:
            _safe_unbind(conn)

    delete_result = {}

    def delete_group():
        conn = _dm_conn(s1)
        t = time.monotonic()
        try:
            conn.delete_s(w3group_dn)
            delete_result['duration'] = time.monotonic() - t
        except ldap.LDAPError as e:
            delete_result['error'] = type(e).__name__
            delete_result['duration'] = time.monotonic() - t
        finally:
            delete_result['done_ts'] = time.monotonic()
            _safe_unbind(conn)

    writer_results = [None] * W3_WRITERS

    def parked_writer(idx):
        member = w3members[idx % len(w3members)]
        t = time.monotonic()
        try:
            conn = _dm_conn(s1)
            conn.modify_s(writer_groups[idx],
                          [(ldap.MOD_ADD, 'member', [member.encode()])])
            writer_results[idx] = ('ok', time.monotonic() - t,
                                   time.monotonic())
            _safe_unbind(conn)
        except ldap.LDAPError as e:
            writer_results[idx] = (type(e).__name__, time.monotonic() - t,
                                   time.monotonic())

    reader_stalls = []
    reader_stop = threading.Event()

    def reader_probe(delete_t0):
        while not reader_stop.is_set():
            t = time.monotonic()
            try:
                conn = _dm_conn(s1, timeout=5)
                conn.search_s(DEFAULT_SUFFIX, ldap.SCOPE_BASE,
                              '(objectClass=*)', ['1.1'])
                _safe_unbind(conn)
                ok = True
            except ldap.LDAPError:
                ok = False
            reader_stalls.append((time.monotonic() - delete_t0, ok))
            reader_stop.wait(2)

    delete_t0 = time.monotonic()
    dthread = threading.Thread(target=delete_group, daemon=True)
    dthread.start()
    time.sleep(0.5)
    wthreads = []
    for i in range(W3_WRITERS):
        t = threading.Thread(target=parked_writer, args=(i,), daemon=True)
        t.start()
        wthreads.append(t)
    rthread = threading.Thread(target=reader_probe, args=(delete_t0,),
                               daemon=True)
    rthread.start()

    stopped_mid_drain = False
    if W3_STOP_PROBE:
        if not s1.with_systemd():
            log.warning('W3 stop probe requested but %s is not '
                        'systemd-managed; skipping the stop probe',
                        s1.serverid)
        else:
            time.sleep(10)
            log.info('W3 stop probe: systemctl stop mid-drain')
            t = time.monotonic()
            s1.stop()
            stop_duration = time.monotonic() - t
            stopped_mid_drain = True
            log.info('W3 stop returned after %.1fs', stop_duration)
            dse_path = os.path.join(s1.ds_paths.config_dir, 'dse.ldif')
            with open(dse_path) as f:
                marker = re.search(r'(?im)^memberofneedfixup:\s*(\S+)',
                                   f.read())
            log.info('W3 on-disk memberOfNeedFixup after stop: %s',
                     marker.group(1) if marker else 'absent')
            s1.start()

    dthread.join(timeout=drain_timeout)
    if dthread.is_alive() and not stopped_mid_drain:
        reader_stop.set()
        pytest.fail(f'W3 delete still blocked after {drain_timeout}s; '
                    f'raise MEMBEROF_REPRO_DRAIN_TIMEOUT')
    for t in wthreads:
        t.join(timeout=120)
    reader_stop.set()
    rthread.join(timeout=10)

    log.info('W3 delete: %s', delete_result)
    parked = [r[1] for r in writer_results if r is not None]
    ok_writers = [r for r in writer_results if r is not None and r[0] == 'ok']
    if parked:
        log.info('W3 writers: n=%d ok=%d park min/avg/max = '
                 '%.1f/%.1f/%.1fs', len(parked), len(ok_writers),
                 min(parked), sum(parked) / len(parked), max(parked))
    stalls = [t for t, ok in reader_stalls if not ok]
    if stalls:
        log.info('W3 reader probe: first stall %.1fs after delete, '
                 '%d stalled samples of %d', stalls[0], len(stalls),
                 len(reader_stalls))
    else:
        log.info('W3 reader probe: no search stalls observed '
                 '(%d samples)', len(reader_stalls))

    conn = _dm_conn(s1, timeout=60)
    try:
        orphans = _quiesce_count(conn, HOSTS_OU, _holder_filter(w3group_dn),
                                 timeout=drain_timeout)
    finally:
        _safe_unbind(conn)
    log.info('W3 memberOf values of the deleted group remaining on %s: %d',
             s1.serverid, orphans)

    if stopped_mid_drain:
        log.info('W3 stop probe run: orphan count above is the Type-J '
                 'analog at scale; skipping clean-drain asserts')
        return
    assert 'duration' in delete_result and 'error' not in delete_result, \
        f'W3 delete failed: {delete_result}'
    assert orphans == 0, \
        f'{orphans} orphaned memberOf values after a clean drain'
    assert ok_writers, 'no writer completed after the drain'
    # The writers' tasks entered the FIFO after the delete task, so none
    # of them may complete before the delete client got its result -
    # regardless of hardware speed.
    early = [r for r in ok_writers
             if r[2] < delete_result['done_ts'] - 0.25]
    assert not early, \
        f'{len(early)} writers completed before the delete fanout ' \
        f'finished - deferred FIFO ordering did not engage'


if __name__ == '__main__':
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s %s" % CURRENT_FILE)
