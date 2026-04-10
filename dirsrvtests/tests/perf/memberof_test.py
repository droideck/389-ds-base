# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import os
import time
import logging
import statistics

import ldap
import ldif
import pytest

from lib389.config import BDB_LDBMConfig, Config, LMDB_LDBMConfig
from lib389.dbgen import dbgen_users, dbgen_groups
from lib389.idm.account import Accounts
from lib389.idm.group import Group, Groups
from lib389.idm.user import UserAccounts
try:
    from lib389.monitor import MonitorLDBM
except ImportError:
    MonitorLDBM = None
try:
    from lib389.monitor import MonitorMemberOf
except ImportError:
    MonitorMemberOf = None
from lib389.plugins import MemberOfPlugin, ManagedEntriesPlugin, AutoMembershipPlugin
from lib389.tasks import ImportTask
from lib389.utils import get_default_db_lib
from lib389._constants import DEFAULT_SUFFIX
from test389.topologies import topology_st as topo, set_timeout as set_topo_timeout

from create_data import RHDSDataLDIF

pytestmark = pytest.mark.tier3


@pytest.fixture(autouse=True, scope="module")
def _disable_topology_timeout():
    set_topo_timeout(0)
    yield
    set_topo_timeout(-1)


MEMBEROF_ATTR = 'memberOf'
USER_SELECTOR = '(uid=user*)'
GROUP_SELECTOR = '(cn=group*)'
TASK_TIMEOUT = 0

PERF_SCALE = float(os.environ.get('MOF_PERF_SCALE', '1.0'))

NDN_BENCH_BACKEND = os.environ.get('NDN_BENCH_BACKEND', '').strip()
NDN_ENTRY_AVG_SIZE = 168
NDN_CACHE_MINIMUM_CAPACITY = 1024 * 1024
CACHE_PROFILES = ('small', 'fit', 'large')


def _s(n, minimum=1):
    return max(minimum, int(n * PERF_SCALE))


def _smul(n, multiple):
    return max(multiple, (int(n * PERF_SCALE) // multiple) * multiple)


def _bench_cache_profiles():
    raw = os.environ.get('NDN_BENCH_CACHE_PROFILES')
    if not raw:
        return ('default',)
    if NDN_BENCH_BACKEND == 'disabled':
        return ('disabled',)
    profiles = []
    for profile in (p.strip().lower() for p in raw.split(',')):
        if not profile:
            continue
        if profile in CACHE_PROFILES:
            profiles.append(profile)
        else:
            log.warning('Unknown NDN_BENCH_CACHE_PROFILES value %r; '
                        'valid values are %s. Ignoring it.',
                        profile, CACHE_PROFILES)
    return tuple(profiles) if profiles else ('fit',)


def _estimated_nestgrps_entries(nof_users, nof_groups):
    return max(1, nof_users + nof_groups + 3)


def _cache_profile_bytes(profile, estimated_entries):
    dataset_entries = max(1, int(estimated_entries))
    if profile == 'small':
        profile_entries = max(1, dataset_entries // 4)
    elif profile == 'fit':
        profile_entries = max(1, int(dataset_entries * 0.90))
    elif profile == 'large':
        profile_entries = dataset_entries * 4
    else:
        raise ValueError('unknown cache profile: {}'.format(profile))
    return max(NDN_CACHE_MINIMUM_CAPACITY,
               profile_entries * NDN_ENTRY_AVG_SIZE)


def _ndn_monitor_stats(inst):
    if MonitorLDBM is None:
        return {}
    monitor = MonitorLDBM(inst)
    stats = {}
    for attr in ('maxNormalizedDnCacheSize',
                 'currentNormalizedDnCacheSize',
                 'currentNormalizedDnCacheCount'):
        try:
            if monitor.present(attr):
                stats[attr] = int(monitor.get_attr_val_utf8(attr))
        except Exception as e:
            log.warning('Unable to read %s from NDN monitor: %s', attr, e)
    return stats


def _configure_ndn_cache_profile(inst, cache_profile, nof_users, nof_groups):
    if cache_profile == 'default':
        return

    cfg = Config(inst)
    backend = NDN_BENCH_BACKEND or 'concread'
    estimated_entries = _estimated_nestgrps_entries(nof_users, nof_groups)
    dataset_bytes = estimated_entries * NDN_ENTRY_AVG_SIZE

    if backend == 'disabled':
        log.info('Configuring NDN cache backend=disabled profile=disabled')
        cfg.set('nsslapd-ndn-cache-enabled', 'off')
        inst.restart()
        return

    requested_bytes = _cache_profile_bytes(cache_profile, estimated_entries)
    log.info('Configuring NDN cache backend=%s profile=%s '
             'estimated_entries=%d dataset_bytes=%d requested_bytes=%d',
             backend, cache_profile, estimated_entries, dataset_bytes,
             requested_bytes)
    cfg.set('nsslapd-ndn-cache-enabled', 'on')
    cfg.set('nsslapd-ndn-cache-max-size', str(requested_bytes))
    cfg.set('nsslapd-ndn-cache-backend', backend)
    inst.restart()

    stats = _ndn_monitor_stats(inst)
    log.info('NDN cache profile=%s effective_max_bytes=%s '
             'current_size_bytes=%s current_count=%s',
             cache_profile,
             stats.get('maxNormalizedDnCacheSize'),
             stats.get('currentNormalizedDnCacheSize'),
             stats.get('currentNormalizedDnCacheCount'))


NESTGRPS_IMPORT_PARAMS = [
    (_s(20000), _smul(200, 20), 20, 10, 5),
    (_s(50000), _smul(500, 50), 50, 10, 10),
    (_s(100000), _smul(1000, 100), 100, 20, 20),
]

NESTGRPS_ADD_PARAMS = [
    (_s(20000), _smul(100, 20), 20, 10, 5),
    (_s(50000), _smul(200, 50), 50, 10, 10),
    (_s(100000), _smul(100, 20), 20, 10, 10),
]

REPLACE_MEMBER_LIST_PARAMS = [
    (_s(50000), _s(100, 20), 'on'),
    (_s(50000), _s(100, 20), 'off'),
]

LDIF2DB_DENSE_PARAMS = [
    (20, _s(2000), False, 'on', _s(3)),
    (20, _s(2000), True, 'on', _s(3)),
    (20, _s(2000), False, 'off', _s(3)),
    (20, _s(2000), True, 'off', _s(3)),
    (50, _s(5000), False, 'on', _s(3)),
    (50, _s(5000), True, 'on', _s(3)),
    (50, _s(5000), False, 'off', _s(3)),
    (50, _s(5000), True, 'off', _s(3)),
]

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def memberof_setup(topo, request):

    log.info('Enabling memberOf, managedEntries and autoMembers plugins')
    memberof = MemberOfPlugin(topo.standalone)
    managed_entries = ManagedEntriesPlugin(topo.standalone)
    automember = AutoMembershipPlugin(topo.standalone)
    memberof.enable()
    managed_entries.enable()
    automember.enable()

    log.info('Tune LDBM config for large bulk imports')
    if get_default_db_lib() == 'bdb':
        BDB_LDBMConfig(topo.standalone).replace_many(
            ('nsslapd-cache-autosize', '0'),
            ('nsslapd-db-locks', '100000'),
            ('nsslapd-dbcachesize', '10000000'),
        )
    else:
        LMDB_LDBMConfig(topo.standalone).replace('nsslapd-cache-autosize', '0')
    Config(topo.standalone).set('nsslapd-maxbersize', str(209715200))

    if NDN_BENCH_BACKEND:
        log.info('Configuring NDN cache backend = %s', NDN_BENCH_BACKEND)
        cfg = Config(topo.standalone)
        if NDN_BENCH_BACKEND == 'disabled':
            cfg.set('nsslapd-ndn-cache-enabled', 'off')
        else:
            cfg.set('nsslapd-ndn-cache-enabled', 'on')
            cfg.set('nsslapd-ndn-cache-backend', NDN_BENCH_BACKEND)

    topo.standalone.restart()

    def fin():
        log.info('Disabling memberOf, managedEntries and autoMembers plugins')
        if topo.standalone.status() is False:
            topo.standalone.start()
        memberof.disable()
        managed_entries.disable()
        automember.disable()
        topo.standalone.restart()

    request.addfinalizer(fin)


def _create_base_ldif(topo, import_base=False):

    ldif_dir = topo.standalone.get_ldif_dir()
    ldif_file = os.path.join(ldif_dir, 'perf.ldif')
    log.info('LDIF FILE is this: {}'.format(ldif_file))
    base_ldif = """dn: dc=example,dc=com
objectclass: top
objectclass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectclass: top
objectclass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=com
objectclass: top
objectclass: organizationalUnit
ou: groups
"""
    with open(ldif_file, "w") as fd:
        fd.write(base_ldif)
    os.chmod(ldif_file, 0o644)

    if import_base:
        log.info('Adding base entry to suffix to remove users/groups and leave only the OUs')
        import_task = ImportTask(topo.standalone)
        import_task.import_suffix_from_ldif(ldiffile=ldif_file, suffix=DEFAULT_SUFFIX)
        import_task.wait(timeout=TASK_TIMEOUT)
        assert import_task.get_exit_code() == 0, 'Online import failed'
        return None

    log.info('Return LDIF file')
    return ldif_file


def _run_fixup_memberof(topo):

    log.info('Running fixup memberOf task and measuring the time taken')
    memberof = MemberOfPlugin(topo.standalone)
    start = time.time()
    task = memberof.fixup(basedn=DEFAULT_SUFFIX)
    task.wait(timeout=TASK_TIMEOUT)
    end = time.time()
    assert task.get_exit_code() == 0, 'fixupMemberOf task failed'
    return int(end - start)


def _nested_import_add_ldif(topo, nof_users, nof_groups, grps_user, ngrps_user, nof_depth, is_import=False):

    if is_import:
        log.info('Import: Create base entry before adding users and groups')
        exp_entries = nof_users + nof_groups
        data_ldif = _create_base_ldif(topo, False)
        log.info('Create data LDIF file by appending users, groups and nested groups')
        with open(data_ldif, 'a') as file1:
            data = RHDSDataLDIF(stream=file1, users=nof_users, groups=nof_groups, grps_puser=grps_user,
                                nest_level=nof_depth, ngrps_puser=ngrps_user, basedn=DEFAULT_SUFFIX)
            data.do_magic()
        os.chmod(data_ldif, 0o644)

        start = time.time()
        log.info('Run importLDIF task to add entries to Server')
        import_task = ImportTask(topo.standalone)
        import_task.import_suffix_from_ldif(ldiffile=data_ldif, suffix=DEFAULT_SUFFIX)
        import_task.wait(timeout=TASK_TIMEOUT)
        end = time.time()
        assert import_task.get_exit_code() == 0, 'Online import failed'
        time_import = int(end - start)

        log.info('Check if number of entries created matches the expected entries')
        accounts = Accounts(topo.standalone, DEFAULT_SUFFIX)
        act_users = len(accounts.filter(USER_SELECTOR))
        act_groups = len(Groups(topo.standalone, DEFAULT_SUFFIX, rdn='ou=groups').filter(GROUP_SELECTOR))
        act_entries = act_users + act_groups
        log.info('Expected entries: {}, Actual entries: {} (users={}, groups={})'.format(
            exp_entries, act_entries, act_users, act_groups))
        assert act_entries == exp_entries
        return time_import

    log.info('Ldapadd: Create data LDIF file with users, groups and nested groups')
    ldif_dir = topo.standalone.get_ldif_dir()
    data_ldif = os.path.join(ldif_dir, 'perf_add.ldif')
    with open(data_ldif, 'w') as file1:
        data = RHDSDataLDIF(stream=file1, users=nof_users, groups=nof_groups, grps_puser=grps_user,
                            nest_level=nof_depth, ngrps_puser=ngrps_user, basedn=DEFAULT_SUFFIX)
        data.do_magic()

    with open(data_ldif, 'rb') as fp:
        parser = ldif.LDIFRecordList(fp)
        parser.parse()

    start = time.time()
    log.info('Add {} entries to Server'.format(len(parser.all_records)))
    for dn, attrs in parser.all_records:
        topo.standalone.add_ext_s(dn, list(attrs.items()), escapehatch='i am sure')
    end = time.time()
    cmd_time = int(end - start)
    log.info('Time taken to complete LDAPADD: {} secs'.format(cmd_time))
    return cmd_time


def _count_memberof_values(topo):
    entries = topo.standalone.search_ext_s(
        DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
        '({}=*)'.format(MEMBEROF_ATTR),
        [MEMBEROF_ATTR],
        escapehatch='i am sure',
    )
    return sum(len(e.data.get(MEMBEROF_ATTR, [])) for e in entries)


_DEFERRED_MONITOR_AVAILABLE = None


def _deferred_memberof_idle(topo):
    global _DEFERRED_MONITOR_AVAILABLE
    if MonitorMemberOf is None or _DEFERRED_MONITOR_AVAILABLE is False:
        return None
    try:
        status = MonitorMemberOf(topo.standalone).get_status()
    except (ValueError, ldap.NO_SUCH_OBJECT):
        if _DEFERRED_MONITOR_AVAILABLE is None:
            log.info('Deferred memberOf monitor entry not present on this '
                     'server build; falling back to count-based polling for '
                     'the rest of the run.')
        _DEFERRED_MONITOR_AVAILABLE = False
        return None
    _DEFERRED_MONITOR_AVAILABLE = True
    pending = int((status.get('TotalPending') or ['0'])[0])
    current = int((status.get('CurrentTasks') or ['0'])[0])
    return pending == 0 and current == 0


def _sync_memberof_attrs(topo, exp_memberof):
    """Poll until memberOf count reaches exp_memberof; return wall-clock seconds.

    Why: the prior loop slept a fixed 30s between checks and ran a full
    Accounts.filter() walk every iteration. After a fixup the count typically
    matches on the first try, so each extra iteration paid 30s of pure waste.

    Bounded by three escapes (any one fires => fail fast, don't hang the bench):
    - MOF_SYNC_TIMEOUT_SEC   (default 1800s = 30min) wall-clock cap.
    - MOF_SYNC_STALL_LOOPS   (default 8) consecutive same-count polls => stall.
    - 10h hard ceiling (legacy) so we always exit even if env vars are bogus.
    """
    log.info('_sync_memberof_attrs: Check if expected memberOf attributes are synced/created')
    start_wall = time.time()
    soft_deadline = start_wall + int(os.environ.get('MOF_SYNC_TIMEOUT_SEC', '1800'))
    hard_deadline = start_wall + 10 * 60 * 60
    stall_limit = int(os.environ.get('MOF_SYNC_STALL_LOOPS', '8'))
    delay = 1
    loop = 0
    act_memberof = -1
    last_count = -1
    stall_count = 0
    while True:
        idle = _deferred_memberof_idle(topo)
        if idle is False:
            log.info('Loop-{}, deferred memberOf queue not yet drained, sleeping {}s'.format(loop, delay))
        else:
            t0 = time.time()
            act_memberof = _count_memberof_values(topo)
            search_secs = int(time.time() - t0)
            log.info('Loop-{}, expected memberOf attrs: {}, synced: {}, search-time={} secs'.format(
                loop, exp_memberof, act_memberof, search_secs))
            if act_memberof == exp_memberof:
                break
            if act_memberof == last_count:
                stall_count += 1
                if stall_count >= stall_limit:
                    log.error('memberOf count stalled at {} for {} consecutive polls '
                              '(expected {}); aborting cell'.format(
                                  act_memberof, stall_count, exp_memberof))
                    pytest.fail('memberOf stalled at {} of {} after {} polls'.format(
                        act_memberof, exp_memberof, stall_count))
            else:
                stall_count = 0
                last_count = act_memberof

        now = time.time()
        if now > soft_deadline:
            log.error('memberOf sync exceeded MOF_SYNC_TIMEOUT_SEC ({}s); '
                      'last count {} of expected {}'.format(
                          int(now - start_wall), act_memberof, exp_memberof))
            pytest.fail('memberOf sync timeout: {} of {} after {}s'.format(
                act_memberof, exp_memberof, int(now - start_wall)))
        if now > hard_deadline:
            log.error('memberOf sync exceeded 10h hard ceiling')
            assert False

        time.sleep(delay)
        delay = min(30, delay * 2)
        loop += 1

    sync_time = int(time.time() - start_wall)
    log.info('Expected memberOf attrs: {}, Actual memberOf attrs: {}'.format(exp_memberof, act_memberof))
    return sync_time


@pytest.mark.parametrize("cache_profile", _bench_cache_profiles())
@pytest.mark.parametrize("nof_users, nof_groups, grps_user, ngrps_user, nof_depth",
                         NESTGRPS_IMPORT_PARAMS)
def test_nestgrps_import(topo, memberof_setup, nof_users, nof_groups,
                         grps_user, ngrps_user, nof_depth, cache_profile):
    """Import large users and nested groups with N depth and measure the time taken

    :id: 169a09f2-2c2d-4e42-8b90-a0bd1034f278
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Create LDIF file for given nof_users and nof_groups
            2. Import entries to server
            3. Check if entries are created
            4. Run fixupMemberOf task to create memberOf attributes
            5. Check if memberOf attributes are synced for all users and groups
            6. Compare the actual no of memberOf attributes to the expected
            7. Measure the time taken to sync memberOf attributes
    :expectedresults:
            1. LDIF file generated
            2. Online import succeeds
            3. Entry count matches nof_users + nof_groups
            4. fixupMemberOf task exits with code 0
            5. memberOf count converges to the expected value
            6. Counts match
            7. Elapsed time is logged
    """
    _configure_ndn_cache_profile(topo.standalone, cache_profile,
                                 nof_users, nof_groups)

    exp_memberof = (nof_users * grps_user) + (
        (nof_groups // grps_user) * (ngrps_user // nof_depth) * (nof_depth * (nof_depth + 1)) // 2)
    log.info('Create nested ldif file with users-{}, groups-{}, nested-{}'.format(nof_users, nof_groups, nof_depth))
    log.info('Import LDIF file and measure the time taken')
    import_time = _nested_import_add_ldif(topo, nof_users, nof_groups, grps_user, ngrps_user, nof_depth, True)

    log.info('Run fixup memberOf task and measure the time taken to complete the task')
    fixup_time = _run_fixup_memberof(topo)

    log.info('Check the total number of memberOf entries created for users and groups')
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)

    total_time = import_time + fixup_time + sync_memberof
    log.info('Time for import-{}secs, fixup task-{}secs, total time for memberOf sync: {}secs'.format(
        import_time, fixup_time, total_time))


@pytest.mark.parametrize("nof_users, nof_groups, grps_user, ngrps_user, nof_depth",
                         NESTGRPS_ADD_PARAMS)
def test_nestgrps_add(topo, memberof_setup, nof_users, nof_groups, grps_user, ngrps_user, nof_depth):
    """Import large users and nested groups with n depth and measure the time taken

    :id: 6eda75c6-5ae0-4b17-b610-d217d7ec7542
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Create LDIF file for given nof_users and nof_groups
            2. Add entries using LDAPADD
            3. Check if entries are created
            4. Check if memberOf attributes are synced for all users and groups
            5. Compare the actual no of memberOf attributes to the expected
            6. Measure the time taken to sync memberOf attributes
    :expectedresults:
            1. LDIF file generated
            2. All entries added without LDAP error
            3. Entry count matches nof_users + nof_groups
            4. memberOf count converges to the expected value
            5. Counts match
            6. Elapsed time is logged
    """

    exp_memberof = (nof_users * grps_user) + (
        (nof_groups // grps_user) * (ngrps_user // nof_depth) * (nof_depth * (nof_depth + 1)) // 2)
    log.info('Creating base_ldif file and importing it to wipe out all users and groups')
    _create_base_ldif(topo, True)
    log.info('Create nested ldif file with users-{}, groups-{}, nested-{}'.format(nof_users, nof_groups, nof_depth))
    log.info('Run LDAPADD to add entries to Server')
    add_time = _nested_import_add_ldif(topo, nof_users, nof_groups, grps_user, ngrps_user, nof_depth, False)

    log.info('Check the total number of memberOf entries created for users and groups')
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)
    total_time = add_time + sync_memberof
    log.info('Time for ldapadd-{}secs, total time for memberOf sync: {}secs'.format(add_time, total_time))


@pytest.mark.parametrize("nof_users, nof_groups, grps_user, ngrps_user, nof_depth",
                         NESTGRPS_IMPORT_PARAMS)
def test_mod_nestgrp(topo, memberof_setup, nof_users, nof_groups, grps_user, ngrps_user, nof_depth):
    """Import bulk entries, modify nested groups at N depth and measure the time taken

    :id: 4bf8e753-6ded-4177-8225-aaf6aef4d131
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Import bulk entries with nested group and create memberOf attributes
            2. Modify nested groups by adding new members at each nested level
            3. Check new memberOf attributes created for users and groups
            4. Compare the actual memberOf attributes with the expected
            5. Measure the time taken to sync memberOf attributes
    :expectedresults:
            1. Import + initial fixup succeed and memberOf reaches the baseline count
            2. Each user creation and add_member succeeds
            3. memberOf count converges to the post-modification expected value
            4. Counts match
            5. Elapsed time is logged
    """

    exp_memberof = (nof_users * grps_user) + (
        (nof_groups // grps_user) * (ngrps_user // nof_depth) * (nof_depth * (nof_depth + 1)) // 2)
    log.info('Create nested ldif file, import it and measure the time taken')
    import_time = _nested_import_add_ldif(topo, nof_users, nof_groups, grps_user, ngrps_user, nof_depth, True)
    log.info('Run fixup memberOf task and measure the time to complete the task')
    fixup_time = _run_fixup_memberof(topo)
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)
    total_time = import_time + fixup_time + sync_memberof
    log.info('Time for import-{}secs, fixup task-{}secs, total time for memberOf sync: {}secs'.format(
        import_time, fixup_time, total_time))

    log.info('Add {} users to existing nested groups at all depth level'.format(nof_groups))
    log.info('Add one user to each groups at different nest levels')
    users = UserAccounts(topo.standalone, DEFAULT_SUFFIX, rdn='ou=people')
    groups = Groups(topo.standalone, DEFAULT_SUFFIX, rdn='ou=groups')
    start = time.time()
    for usr in range(nof_groups):
        usrrdn = 'newcliusr{}'.format(usr)
        user = users.create(properties={
            'uid': usrrdn,
            'cn': usrrdn,
            'sn': usrrdn,
            'uidNumber': str(100000 + usr),
            'gidNumber': str(100000 + usr),
            'homeDirectory': '/home/{}'.format(usrrdn),
            'userPassword': 'Secret123',
        })
        groups.get('group{}'.format(usr)).add_member(user.dn)
    end = time.time()
    cmd_time = int(end - start)

    exp_memberof = (nof_users * grps_user) + nof_groups + (
        (nof_groups // grps_user) * (ngrps_user // nof_depth) * (nof_depth * (nof_depth + 1)))
    log.info('Check the total number of memberOf entries created for users and groups')
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)
    total_time = cmd_time + sync_memberof
    log.info('Time taken add new members to existing nested groups + memberOf sync: {} secs'.format(total_time))


@pytest.mark.parametrize("nof_users, nof_groups, grps_user, ngrps_user, nof_depth",
                         NESTGRPS_IMPORT_PARAMS)
def test_del_nestgrp(topo, memberof_setup, nof_users, nof_groups, grps_user, ngrps_user, nof_depth):
    """Import bulk entries, delete nested groups at N depth and measure the time taken

    :id: d3d82ac5-d968-4cd6-a268-d380fc9fd51b
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Import bulk users and groups with nested level N.
            2. Run fixup memberOf task to create memberOf attributes
            3. Delete nested groups at nested level N
            4. Check memberOf attributes deleted for users and groups
            5. Compare the actual memberOf attributes with the expected
            6. Measure the time taken to sync memberOf attributes
    :expectedresults:
            1. Online import succeeds and entry counts match
            2. fixupMemberOf task exits with code 0 and memberOf reaches the baseline count
            3. Each group delete succeeds
            4. memberOf count converges to the post-delete expected value
            5. Counts match
            6. Elapsed time is logged
    """

    exp_memberof = (nof_users * grps_user) + (
        (nof_groups // grps_user) * (ngrps_user // nof_depth) * (nof_depth * (nof_depth + 1)) // 2)
    log.info('Create nested ldif file, import it and measure the time taken')
    import_time = _nested_import_add_ldif(topo, nof_users, nof_groups, grps_user, ngrps_user, nof_depth, True)
    log.info('Run fixup memberOf task and measure the time to complete the task')
    fixup_time = _run_fixup_memberof(topo)
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)
    total_time = import_time + fixup_time + sync_memberof
    log.info('Time taken to complete add users + memberOf sync: {} secs'.format(total_time))

    log.info('Delete {} groups from nested groups at depth level-{}'.format(nof_depth, nof_depth))
    groups = Groups(topo.standalone, DEFAULT_SUFFIX, rdn='ou=groups')
    start = time.time()
    for nos in range(nof_depth, nof_groups, grps_user):
        groups.get('group{}'.format(nos)).delete()
    end = time.time()
    cmd_time = int(end - start)

    exp_memberof = exp_memberof - (nof_users + (nof_depth * (nof_groups // grps_user)))
    log.info('Check memberOf attributes after deleting groups at depth-{}'.format(nof_depth))
    sync_memberof = _sync_memberof_attrs(topo, exp_memberof)
    total_time = cmd_time + sync_memberof
    log.info('Time taken to delete and sync memberOf attributes: {}secs'.format(total_time))


REPLACE_BENCH_GROUP = 'mof_replace_bench_group'
REPLACE_BENCH_LDIF = 'mof_replace_bench.ldif'


def _import_users(topo, total):

    ldif_path = os.path.join(topo.standalone.get_ldif_dir(), REPLACE_BENCH_LDIF)
    dbgen_users(topo.standalone, 2 * total, ldif_path, DEFAULT_SUFFIX, generic=True)
    topo.standalone.stop()
    assert topo.standalone.ldif2db('userRoot', None, None, None, ldif_path), 'ldif2db failed'
    topo.standalone.start()
    dns = sorted(u.dn for u in Accounts(topo.standalone, DEFAULT_SUFFIX).filter('(uid=user*)'))
    assert len(dns) >= 2 * total, 'expected {} imported users, got {}'.format(2 * total, len(dns))
    return dns[:total], dns[total:2 * total]


def _reset_bench_group(topo, members):

    groups = Groups(topo.standalone, DEFAULT_SUFFIX)
    if groups.exists(REPLACE_BENCH_GROUP):
        groups.get(REPLACE_BENCH_GROUP).delete()
    return groups.create(properties={'cn': REPLACE_BENCH_GROUP, 'member': members})


def _cleanup_bench_state(topo):

    try:
        if topo.standalone.status() is False:
            topo.standalone.start()
        groups = Groups(topo.standalone, DEFAULT_SUFFIX)
        if groups.exists(REPLACE_BENCH_GROUP):
            groups.get(REPLACE_BENCH_GROUP).delete()
    except Exception as e:
        log.warning('Bench teardown: failed to drop {}: {}'.format(REPLACE_BENCH_GROUP, e))

    ldif_path = os.path.join(topo.standalone.get_ldif_dir(), REPLACE_BENCH_LDIF)
    try:
        if os.path.exists(ldif_path):
            os.remove(ldif_path)
    except OSError as e:
        log.warning('Bench teardown: failed to remove {}: {}'.format(ldif_path, e))


@pytest.mark.parametrize('nof_users, iters, ndn_cache', REPLACE_MEMBER_LIST_PARAMS)
def test_replace_member_list(topo, memberof_setup, nof_users, iters, ndn_cache, request):
    """Time MOD_REPLACE of a large member list, alternating between two disjoint sets.

    :id: 44aa5375-60ce-4d23-9d8f-58ae2ba04de8
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Import 2 * nof_users users and create the bench group with the first half
            2. Set nsslapd-ndn-cache-enabled per parametrization and restart
            3. One warmup MOD_REPLACE to populate caches
            4. Alternate MOD_REPLACE between the two sets for iters trials
            5. Report median / p95 / p99; fail if p95 exceeds MOF_BENCH_CEILING when set
    :expectedresults:
            1. Success
            2. Success
            3. Success
            4. Group holds nof_users members after the final replace
            5. Success (p95 within ceiling if set)
    """

    request.addfinalizer(lambda: _cleanup_bench_state(topo))

    log.info('Importing 2 x {} users via dbgen + ldif2db'.format(nof_users))
    set_a, set_b = _import_users(topo, nof_users)

    log.info('Priming {} with {} initial members'.format(REPLACE_BENCH_GROUP, nof_users))
    _reset_bench_group(topo, set_a)

    log.info('Setting nsslapd-ndn-cache-enabled={}'.format(ndn_cache))
    Config(topo.standalone).set('nsslapd-ndn-cache-enabled', ndn_cache)
    topo.standalone.restart()

    group = Groups(topo.standalone, DEFAULT_SUFFIX).get(REPLACE_BENCH_GROUP)

    log.info('Warmup: one throwaway MOD_REPLACE to populate caches')
    group.replace('member', set_b)

    trials = []
    current, other = set_a, set_b
    for i in range(iters):
        start = time.perf_counter()
        group.replace('member', current)
        elapsed = time.perf_counter() - start

        trials.append(elapsed)
        log.info('trial {}/{}: {:.3f}s'.format(i + 1, iters, elapsed))

        current, other = other, current

    members = group.get_attr_vals_utf8('member')
    assert members, 'group ended up with no members'
    assert len(members) == nof_users, (
        'expected {} members after final replace, got {}'.format(
            nof_users, len(members)))

    median = statistics.median(trials)
    p95 = statistics.quantiles(trials, n=20)[18]
    p99 = statistics.quantiles(trials, n=100)[98] if len(trials) >= 2 else max(trials)
    log.info(
        'N={} iters={} ndn_cache={} median={:.3f}s p95={:.3f}s p99={:.3f}s min={:.3f}s max={:.3f}s'.format(
            nof_users, iters, ndn_cache, median, p95, p99, min(trials), max(trials)))

    ceiling = os.environ.get('MOF_BENCH_CEILING')
    if ceiling is not None:
        ceiling = float(ceiling)
        assert p95 < ceiling, (
            'p95 {:.3f}s exceeded ceiling {:.3f}s (trials={})'.format(
                p95, ceiling, ['{:.3f}'.format(t) for t in trials]))


IMPORT_BENCH_LDIF = 'mof_dense_import_bench.ldif'
IMPORT_BENCH_GROUP_NAME = 'densegroup'


def _denormalize_member_lines(ldif_path):
    with open(ldif_path, 'r') as f:
        lines = f.readlines()
    with open(ldif_path, 'w') as f:
        for line in lines:
            if line.startswith('member: '):
                dn = line[len('member: '):].rstrip('\n')
                rdns = []
                for rdn in dn.split(','):
                    attr, _, value = rdn.partition('=')
                    rdns.append('{} = {}'.format(attr.strip().upper(), value.strip()))
                f.write('member: ' + ' , '.join(rdns) + '\n')
            else:
                f.write(line)


def _time_ldif2db(topo, ldif_path):
    if topo.standalone.status() is not False:
        topo.standalone.stop()
    start = time.perf_counter()
    assert topo.standalone.ldif2db('userRoot', None, None, None, ldif_path), 'ldif2db failed'
    elapsed = time.perf_counter() - start
    topo.standalone.start()
    return elapsed


@pytest.mark.parametrize(
    'nof_groups, members_per_group, denormalize, ndn_cache, iters',
    LDIF2DB_DENSE_PARAMS,
)
def test_ldif2db_dense_member_import(topo, memberof_setup, nof_groups,
                                     members_per_group, denormalize, ndn_cache, iters, request):
    """Time offline ldif2db of an LDIF dense in DN-syntax member values.

    :id: 65db7483-e8b4-4c33-bc6d-1c9d7467f8a4
    :feature: MemberOf Plugin
    :setup: Standalone instance, memberOf plugin enabled
    :steps: 1. Build LDIF via dbgen_groups (groups + their member entries)
            2. If denormalize, rewrite member values to whitespace-padded form
            3. For iters trials, stop the server, run ldif2db, restart
            4. Verify the last group holds members_per_group values
            5. Report median / p95 / p99 import times
            6. Fail if p95 exceeds MOF_IMPORT_BENCH_CEILING when set
    :expectedresults:
            1. LDIF generated
            2. Success
            3. Each ldif2db succeeds
            4. Member count matches expected
            5. Success
            6. Success (within ceiling if set)
    """

    ldif_path = os.path.join(topo.standalone.get_ldif_dir(), IMPORT_BENCH_LDIF)

    def fin():
        try:
            if os.path.exists(ldif_path):
                os.remove(ldif_path)
        except OSError as e:
            log.warning('ldif cleanup failed: {}'.format(e))
        if topo.standalone.status() is False:
            topo.standalone.start()
    request.addfinalizer(fin)

    log.info('Setting nsslapd-ndn-cache-enabled={}'.format(ndn_cache))
    Config(topo.standalone).set('nsslapd-ndn-cache-enabled', ndn_cache)
    topo.standalone.restart()

    log.info('Generating LDIF: groups={}, members/group={}, denormalize={}, ndn_cache={}'.format(
        nof_groups, members_per_group, denormalize, ndn_cache))
    dbgen_groups(topo.standalone, ldif_path, {
        'name': IMPORT_BENCH_GROUP_NAME,
        'parent': 'ou=groups,' + DEFAULT_SUFFIX,
        'suffix': DEFAULT_SUFFIX,
        'number': nof_groups,
        'numMembers': members_per_group,
        'createMembers': True,
        'memberParent': 'ou=people,' + DEFAULT_SUFFIX,
        'membershipAttr': 'member',
    })
    if denormalize:
        _denormalize_member_lines(ldif_path)
    log.info('LDIF size: {:.1f} MiB'.format(os.path.getsize(ldif_path) / (1024 * 1024)))

    trials = []
    for i in range(iters):
        elapsed = _time_ldif2db(topo, ldif_path)
        trials.append(elapsed)
        log.info('trial {}/{}: {:.3f}s (groups={}, members/group={}, denormalize={}, ndn_cache={})'.format(
            i + 1, iters, elapsed, nof_groups, members_per_group, denormalize, ndn_cache))

    last_dn = 'cn={}-{},ou=groups,{}'.format(IMPORT_BENCH_GROUP_NAME, nof_groups, DEFAULT_SUFFIX)
    stored = Group(topo.standalone, last_dn).get_attr_vals_utf8('member')
    assert len(stored) == members_per_group, (
        'last group: expected {} members, got {}'.format(members_per_group, len(stored)))

    median = statistics.median(trials)
    if len(trials) >= 20:
        p95 = statistics.quantiles(trials, n=20)[18]
    else:
        p95 = max(trials)
    if len(trials) >= 100:
        p99 = statistics.quantiles(trials, n=100)[98]
    else:
        p99 = max(trials)
    log.info(
        'ldif2db dense-member import: groups={} members/group={} denormalize={} ndn_cache={} '
        'iters={} median={:.3f}s p95={:.3f}s p99={:.3f}s min={:.3f}s max={:.3f}s'.format(
            nof_groups, members_per_group, denormalize, ndn_cache, iters,
            median, p95, p99, min(trials), max(trials)))

    ceiling = os.environ.get('MOF_IMPORT_BENCH_CEILING')
    if ceiling is not None:
        ceiling = float(ceiling)
        assert p95 < ceiling, (
            'p95 {:.3f}s exceeded ceiling {:.3f}s (trials={})'.format(
                p95, ceiling, ['{:.3f}'.format(t) for t in trials]))


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s {}".format(CURRENT_FILE))
