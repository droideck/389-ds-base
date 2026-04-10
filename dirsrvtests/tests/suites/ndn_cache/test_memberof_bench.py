#!/usr/bin/python3
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import json
import os
import random
import re
import subprocess
import threading
import time
import logging
from collections import OrderedDict

import pytest
import ldap

from lib389._constants import DEFAULT_SUFFIX
from test389.topologies import topology_st as topo

try:
    from test389.topologies import set_timeout as _set_framework_timeout
    try:
        _bench_framework_timeout = int(
            os.environ.get('NDN_BENCH_TIMEOUT', 4 * 60 * 60))
    except ValueError:
        _bench_framework_timeout = 4 * 60 * 60
    if _bench_framework_timeout > 0:
        _set_framework_timeout(_bench_framework_timeout)
except ImportError:
    pass
from lib389.config import Config
from lib389.dbgen import dbgen_users
from lib389.idm.account import Accounts
from lib389.idm.group import Groups
from lib389.idm.organizationalunit import OrganizationalUnits
from lib389.plugins import MemberOfPlugin
from lib389.tasks import ImportTask, ExportTask
from lib389.utils import ensure_str
from lib389.dseutils import get_ldapurl_from_serverid

pytestmark = pytest.mark.tier3

log = logging.getLogger(__name__)

N_USERS = int(os.environ.get('NDN_BENCH_FIXTURE_USERS', '10000'))
N_GROUPS = int(os.environ.get('NDN_BENCH_FIXTURE_GROUPS', '1000'))
NESTING_DEPTH = int(os.environ.get('NDN_BENCH_FIXTURE_DEPTH', '5'))
MEMBERSHIP_FANOUT = int(os.environ.get('NDN_BENCH_FIXTURE_FANOUT', '20'))
NDN_VARIANTS = ['disabled', 'concread', 's3fifo']

BENCH_OU = 'People'
GROUPS_OU = 'Groups'
NDN_MONITOR_DN = 'cn=monitor,cn=ldbm database,cn=plugins,cn=config'
NDN_ENTRY_AVG_SIZE = 168
NDN_CACHE_MINIMUM_CAPACITY = 1024 * 1024
CACHE_PROFILES = ('small', 'fit', 'large')
FIXTURE_LDIF = (f'memberof_bench_fixture_'
                f'{N_USERS}u_{N_GROUPS}g_d{NESTING_DEPTH}_f{MEMBERSHIP_FANOUT}.ldif')

BENCH_DEFAULT_DURATION_SEC = 30
BENCH_DEFAULT_THREAD_COUNTS = (1, 4, 16, 32, 64)
BENCH_DEFAULT_REPS = 1

all_results = []


def _bench_duration():
    raw = os.environ.get('NDN_BENCH_DURATION')
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            log.warning('Bad NDN_BENCH_DURATION=%r, using default', raw)
    return BENCH_DEFAULT_DURATION_SEC


def _bench_thread_counts():
    raw = os.environ.get('NDN_BENCH_THREADS')
    if raw:
        try:
            counts = tuple(int(x) for x in raw.split(',') if x.strip())
            if counts:
                return counts
        except ValueError:
            log.warning('Bad NDN_BENCH_THREADS=%r, using default', raw)
    return BENCH_DEFAULT_THREAD_COUNTS


def _bench_variants():
    raw = os.environ.get('NDN_BENCH_BACKEND')
    if raw:
        if raw in NDN_VARIANTS:
            return [raw]
        log.warning('Unknown NDN_BENCH_BACKEND=%r; valid values are %s. '
                    'Ignoring and running all variants.', raw, NDN_VARIANTS)
    return NDN_VARIANTS


def _bench_reps():
    raw = os.environ.get('NDN_BENCH_REPS')
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            log.warning('Bad NDN_BENCH_REPS=%r, using default', raw)
    return BENCH_DEFAULT_REPS


def _bench_cache_profiles():
    raw = os.environ.get('NDN_BENCH_CACHE_PROFILES')
    if raw:
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
        if profiles:
            return tuple(profiles)
    return ('fit',)


def _variant_cache_profiles(variant):
    if variant == 'disabled':
        return ('disabled',)
    return _bench_cache_profiles()


def _cache_profile_bytes(profile, estimated_entries):
    dataset_entries = max(1, int(estimated_entries))
    if profile == 'small':
        profile_entries = max(1, dataset_entries // 4)
    elif profile == 'fit':
        profile_entries = max(1, int(dataset_entries * 0.90))
    elif profile == 'large':
        profile_entries = dataset_entries * 4
    else:
        raise ValueError(f'unknown cache profile: {profile}')
    return max(NDN_CACHE_MINIMUM_CAPACITY,
               profile_entries * NDN_ENTRY_AVG_SIZE)


def _cache_result_fields(profile, requested_bytes, estimated_entries, stats):
    dataset_entries = max(1, int(estimated_entries))
    dataset_bytes = dataset_entries * NDN_ENTRY_AVG_SIZE
    return OrderedDict(
        cache_profile=profile,
        cache_requested_bytes=requested_bytes,
        cache_effective_max_bytes=stats.get('maxNormalizedDnCacheSize'),
        cache_current_size_bytes=stats.get('currentNormalizedDnCacheSize'),
        cache_current_count=stats.get('currentNormalizedDnCacheCount'),
        cache_dataset_entries=dataset_entries,
        cache_dataset_bytes=dataset_bytes,
    )


def open_ldapi_conn(inst):
    ldapurl, _ = get_ldapurl_from_serverid(inst.serverid)
    conn = ldap.initialize(ldapurl)
    conn.sasl_interactive_bind_s("", ldap.sasl.external())
    return conn


def get_ndn_stats(inst):
    conn = open_ldapi_conn(inst)
    try:
        res = conn.search_s(NDN_MONITOR_DN, ldap.SCOPE_BASE,
                            '(objectclass=*)')
        attrs = res[0][1]
        lower_map = {k.lower(): k for k in attrs}
        out = {}
        for want in ('normalizedDnCacheTries', 'normalizedDnCacheHits',
                     'NormalizedDnCacheEvictions', 'currentNormalizedDnCacheSize',
                     'maxNormalizedDnCacheSize', 'currentNormalizedDnCacheCount'):
            real_key = lower_map.get(want.lower())
            if real_key:
                out[want] = int(ensure_str(attrs[real_key][0]))
        return out
    except Exception as e:
        log.warning('get_ndn_stats failed: %s', e)
        return {}
    finally:
        conn.unbind_s()


def ndn_hit_ratio(pre, post):
    tries = post.get('normalizedDnCacheTries', 0) - pre.get('normalizedDnCacheTries', 0)
    hits = post.get('normalizedDnCacheHits', 0) - pre.get('normalizedDnCacheHits', 0)
    ratio = hits / tries if tries > 0 else 0.0
    return hits, tries, ratio


def get_rss_kb(pid):
    try:
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1])
    except Exception:
        return 0
    return 0


# First 15 bytes of the "cache-char-concread-quiesce" worker thread name,
# the comm(5) limit.
CONCREAD_QUIESCE_COMM_PREFIX = 'cache-char-conc'

CACHE_CHAR_TEST_ENV_VARS = (
    'NSSLAPD_CACHE_CHAR_TEST_MODE',
    'NSSLAPD_CACHE_CHAR_TEST_LOOKBACK',
    'NSSLAPD_CACHE_CHAR_TEST_QUIESCE_US',
    'NSSLAPD_CACHE_CHAR_TEST_READ_STATS_SAMPLE_N',
)


def _sync_concread_test_env(inst):
    """Mirror the NSSLAPD_CACHE_CHAR_TEST_* pytest environment into the
    instance's systemd EnvironmentFile.

    systemctl drops the caller's environment and lib389's direct-exec path
    starts ns-slapd with an empty environment, so exporting the variables
    in the pytest shell alone never reaches the server process.
    """
    env_file = os.path.join(inst.get_initconfig_dir(),
                            f'dirsrv-{inst.serverid}')
    try:
        with open(env_file) as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    kept = [line for line in lines
            if not any(line.lstrip().startswith(f'{var}=')
                       for var in CACHE_CHAR_TEST_ENV_VARS)]
    for var in CACHE_CHAR_TEST_ENV_VARS:
        value = os.environ.get(var)
        if value is not None:
            kept.append(f'{var}={value}')
    try:
        with open(env_file, 'w') as f:
            f.write('\n'.join(kept) + ('\n' if kept else ''))
    except OSError as e:
        log.warning('Could not write %s (%s); NSSLAPD_CACHE_CHAR_TEST_* '
                    'may not reach ns-slapd', env_file, e)


def _concread_quiesce_thread_present(pid):
    task_dir = f'/proc/{pid}/task'
    try:
        tids = os.listdir(task_dir)
    except OSError:
        return None
    for tid in tids:
        try:
            with open(os.path.join(task_dir, tid, 'comm')) as f:
                if f.read().strip().startswith(CONCREAD_QUIESCE_COMM_PREFIX):
                    return True
        except OSError:
            continue
    return False


def _verify_concread_mode(inst, variant):
    """Return the concread runtime ns-slapd actually started with.

    NSSLAPD_CACHE_CHAR_TEST_MODE only takes effect if the environment
    reaches the ns-slapd process through the restart. A silent mismatch
    would benchmark the wrong configuration, so fail loudly instead of
    producing mislabeled data.
    """
    if variant != 'concread':
        return None
    expected = ('quiesce-thread'
                if os.environ.get('NSSLAPD_CACHE_CHAR_TEST_MODE') == 'quiesce-thread'
                else 'legacy')
    present = _concread_quiesce_thread_present(inst.get_pid())
    if present is None:
        log.warning('Cannot inspect ns-slapd threads to verify the concread '
                    'mode; recording expected mode %s', expected)
        return expected
    actual = 'quiesce-thread' if present else 'legacy'
    if actual != expected:
        pytest.fail(f'concread mode mismatch: expected {expected!r} but '
                    f'ns-slapd is running {actual!r}; check that '
                    'NSSLAPD_CACHE_CHAR_TEST_MODE reaches the server process')
    return actual


def configure_variant(inst, variant, cache_size_bytes=None):
    _sync_concread_test_env(inst)
    if not inst.status():
        inst.start()
    config = Config(inst)
    if variant == 'disabled':
        config.set('nsslapd-ndn-cache-enabled', 'off')
    else:
        cache_bytes = cache_size_bytes
        if cache_bytes is None:
            cache_bytes = 20 * 1024 * 1024
        config.set('nsslapd-ndn-cache-enabled', 'on')
        config.set('nsslapd-ndn-cache-max-size', str(cache_bytes))
        config.set('nsslapd-ndn-cache-backend', variant)
    inst.restart()
    return _verify_concread_mode(inst, variant)


def _count_suffix_entries(inst):
    conn = open_ldapi_conn(inst)
    try:
        results = conn.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                '(objectclass=*)', ['dn'])
        return max(1, len(results))
    except Exception as e:
        fallback = max(1, N_USERS + N_GROUPS + 3)
        log.warning('Could not count suffix entries for cache sizing (%s); '
                    'using fallback estimate %d', e, fallback)
        return fallback
    finally:
        conn.unbind_s()


def _user_uid(idx):
    pad = len(str(N_USERS))
    return f'user{str(idx).zfill(pad)}'


def _user_dn(idx):
    return f'uid={_user_uid(idx)},ou={BENCH_OU},{DEFAULT_SUFFIX}'


def _group_dn(level, gidx):
    return f'cn=grp_L{level}_G{gidx},ou={GROUPS_OU},{DEFAULT_SUFFIX}'


def _ensure_ou(inst, ou_name):
    ou_dn = f'ou={ou_name},{DEFAULT_SUFFIX}'
    ous = OrganizationalUnits(inst, DEFAULT_SUFFIX)
    try:
        ous.create(properties={'ou': ou_name})
    except ldap.ALREADY_EXISTS:
        pass
    return ou_dn


def _build_group_dag(inst):
    groups_ou_dn = _ensure_ou(inst, GROUPS_OU)
    groups_coll = Groups(inst, groups_ou_dn, rdn=None)

    groups_by_level = {}
    n_level0 = 200

    log.info('Building level 0: %d leaf groups with %d user members each...',
             n_level0, MEMBERSHIP_FANOUT)
    groups_by_level[0] = []
    user_idx = 1
    for gidx in range(n_level0):
        # A dict keeps insertion order while deduplicating: once the
        # sequential users run out, random picks may repeat and a group
        # add with a duplicate member fails with TYPE_OR_VALUE_EXISTS.
        members = {}
        while user_idx <= N_USERS and len(members) < MEMBERSHIP_FANOUT:
            members[_user_dn(user_idx)] = None
            user_idx += 1
        target = min(MEMBERSHIP_FANOUT, N_USERS)
        while len(members) < target:
            members[_user_dn(random.randint(1, N_USERS))] = None
        grp = groups_coll.create(properties={
            'cn': f'grp_L0_G{gidx}',
            'member': list(members),
        })
        groups_by_level[0].append(grp)

    for level in range(1, NESTING_DEPTH):
        prev_groups = groups_by_level[level - 1]
        n_groups_at_level = max(1, len(prev_groups) // MEMBERSHIP_FANOUT)
        log.info('Building level %d: %d groups with %d group members each...',
                 level, n_groups_at_level, MEMBERSHIP_FANOUT)
        groups_by_level[level] = []

        for gidx in range(n_groups_at_level):
            start = gidx * MEMBERSHIP_FANOUT
            end = min(start + MEMBERSHIP_FANOUT, len(prev_groups))
            members = [prev_groups[i].dn for i in range(start, end)]

            if gidx > 0:
                cross_idx = (gidx - 1) * MEMBERSHIP_FANOUT
                if cross_idx < len(prev_groups):
                    cross_dn = prev_groups[cross_idx].dn
                    if cross_dn not in members:
                        members.append(cross_dn)

            if not members:
                members = [prev_groups[0].dn]

            grp = groups_coll.create(properties={
                'cn': f'grp_L{level}_G{gidx}',
                'member': members,
            })
            groups_by_level[level].append(grp)

    deepest_level = max(groups_by_level.keys())
    deepest_group = groups_by_level[deepest_level][0]
    log.info('Group DAG built. Deepest group: %s', deepest_group.dn)
    return groups_by_level, deepest_group.dn


@pytest.fixture(scope="module")
def memberof_inst(topo):
    inst = topo.standalone
    ldif_dir = inst.get_ldif_dir()
    cached_ldif = os.path.join(ldif_dir, FIXTURE_LDIF)

    if os.path.isfile(cached_ldif):
        log.info('Importing cached fixture LDIF: %s', cached_ldif)
        import_task = ImportTask(inst)
        import_task.import_suffix_from_ldif(ldiffile=cached_ldif,
                                            suffix=DEFAULT_SUFFIX)
        import_task.wait(timeout=300)

        memberof = MemberOfPlugin(inst)
        if not memberof.status():
            memberof.enable()
            inst.restart()

        deepest_level = NESTING_DEPTH - 1
        deepest_dn = _group_dn(deepest_level, 0)
        estimated_entries = _count_suffix_entries(inst)
        log.info('Fixture loaded from cache. Deepest group: %s. '
                 'Estimated NDN dataset entries: %d',
                 deepest_dn, estimated_entries)
        return inst, deepest_dn, estimated_entries

    gen_ldif = os.path.join(ldif_dir, 'memberof_bench_users.ldif')
    log.info('Generating %d users via dbgen...', N_USERS)
    dbgen_users(inst, N_USERS, gen_ldif, DEFAULT_SUFFIX,
                generic=True, parent=f'ou={BENCH_OU},{DEFAULT_SUFFIX}')

    log.info('Importing user LDIF...')
    import_task = ImportTask(inst)
    import_task.import_suffix_from_ldif(ldiffile=gen_ldif,
                                        suffix=DEFAULT_SUFFIX)
    import_task.wait(timeout=300)

    accounts = Accounts(inst, DEFAULT_SUFFIX)
    found = len(accounts.filter('(uid=user*)'))
    log.info('Import complete. Verified %d user entries.', found)
    assert found >= N_USERS, \
        f'Expected at least {N_USERS} users after import, found {found}'

    memberof = MemberOfPlugin(inst)
    if not memberof.status():
        memberof.enable()
        inst.restart()

    groups_by_level, deepest_dn = _build_group_dag(inst)

    log.info('Exporting fixture LDIF for future runs: %s', cached_ldif)
    export_task = ExportTask(inst)
    export_task.export_suffix_to_ldif(ldiffile=cached_ldif,
                                      suffix=DEFAULT_SUFFIX)
    export_task.wait(timeout=300)

    estimated_entries = _count_suffix_entries(inst)
    log.info('Fixture built. Estimated NDN dataset entries: %d',
             estimated_entries)
    return inst, deepest_dn, estimated_entries


def _run_threaded_load(inst, n_threads, duration_sec, op_fn):
    barrier = threading.Barrier(n_threads + 1)
    stop_event = threading.Event()
    per_thread_latencies = [[] for _ in range(n_threads)]
    per_thread_ops = [0] * n_threads
    per_thread_errs = [0] * n_threads

    def runner(tid):
        try:
            conn = open_ldapi_conn(inst)
        except Exception as e:
            log.error('Worker %d failed to connect: %s', tid, e)
            barrier.wait()
            return
        rng = random.Random(tid * 7919 + 1)
        latencies = per_thread_latencies[tid]
        barrier.wait()
        try:
            while not stop_event.is_set():
                t0 = time.perf_counter_ns()
                try:
                    op_fn(conn, rng, tid)
                except ldap.LDAPError as e:
                    per_thread_errs[tid] += 1
                    log.debug('Worker %d op error: %s', tid, e)
                    continue
                latencies.append(time.perf_counter_ns() - t0)
                per_thread_ops[tid] += 1
        finally:
            try:
                conn.unbind_s()
            except Exception:
                pass

    threads = [threading.Thread(target=runner, args=(i,), daemon=True)
               for i in range(n_threads)]
    for t in threads:
        t.start()

    barrier.wait()
    t0 = time.perf_counter()
    stop_event.wait(duration_sec)
    stop_event.set()
    for t in threads:
        t.join(timeout=30)
    wall_time = time.perf_counter() - t0

    all_latencies = sorted(l for lst in per_thread_latencies for l in lst)
    total_ops = sum(per_thread_ops)
    total_errs = sum(per_thread_errs)

    def pct(p):
        if not all_latencies:
            return 0
        idx = min(int(len(all_latencies) * p), len(all_latencies) - 1)
        return all_latencies[idx]

    return OrderedDict(
        wall_time_sec=round(wall_time, 3),
        total_ops=total_ops,
        total_errors=total_errs,
        ops_per_sec=round(total_ops / wall_time, 1) if wall_time > 0 else 0.0,
        p50_ms=round(pct(0.50) / 1_000_000, 3),
        p95_ms=round(pct(0.95) / 1_000_000, 3),
        p99_ms=round(pct(0.99) / 1_000_000, 3),
    )


_LDCLT_RATE_RE = re.compile(
    r'\(\s*([0-9]+(?:\.[0-9]+)?)\s*/\s*sec\s*\)',
    re.IGNORECASE,
)


def _parse_ldclt_rate(out):
    global_rate = None
    last_sample_rate = None
    for line in out.splitlines():
        m = _LDCLT_RATE_RE.search(line)
        if not m:
            continue
        try:
            rate = float(m.group(1))
        except ValueError:
            continue
        if 'global average rate' in line.lower():
            global_rate = rate
        elif 'average rate' in line.lower() or 'rate' in line.lower():
            last_sample_rate = rate
    return global_rate if global_rate is not None else last_sample_rate


def _ldclt_hotkey_search(inst, hot_dn, n_threads, duration_sec, interval=5):
    rounds = max(1, duration_sec // interval)
    cmd = [
        f'{inst.get_bin_dir()}/ldclt',
        '-h', inst.host,
        '-p', str(inst.port),
        '-D', inst.binddn,
        '-w', inst.bindpw,
        '-n', str(n_threads),
        '-N', str(rounds),
        '-I', str(interval),
        '-b', hot_dn,
        '-s', 'base',
        '-f', '(objectclass=*)',
        '-e', 'esearch',
    ]
    log.debug('ldclt cmd: %s', ' '.join(cmd))
    subprocess_timeout = rounds * interval + 90
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                      text=True,
                                      timeout=subprocess_timeout)
    except subprocess.CalledProcessError as e:
        log.error('ldclt exit=%d output=%s', e.returncode, e.output)
        return None, (e.output or '').splitlines()[-15:]
    except subprocess.TimeoutExpired as e:
        raw = e.output or b''
        if isinstance(raw, bytes):
            raw = raw.decode(errors='replace')
        log.error('ldclt timed out: %s', raw)
        return None, raw.splitlines()[-15:]

    rate = _parse_ldclt_rate(out)
    if rate is None:
        log.warning('Could not parse rate from ldclt output. Tail:\n%s',
                    '\n'.join(out.splitlines()[-15:]))
    return rate, out.splitlines()[-15:]


def _capture_server_errors(inst, n_lines=200):
    errlog = getattr(inst, 'errlog', None)
    if not errlog:
        return []
    try:
        with open(errlog) as f:
            return [line.rstrip('\n') for line in f.readlines()[-n_lines:]]
    except OSError:
        return []


def _results_dir():
    d = os.path.join(os.path.dirname(__file__), '..', '..', 'data',
                     'bench_results')
    os.makedirs(d, 0o755, exist_ok=True)
    return d


def _write_results(results):
    if not results:
        return
    path = os.path.join(_results_dir(), 'phase3_memberof.json')
    existing = []
    if os.path.isfile(path):
        try:
            with open(path) as f:
                loaded = json.load(f)
            if isinstance(loaded, list):
                existing = loaded
        except (json.JSONDecodeError, OSError) as e:
            log.warning('Could not parse existing %s (%s); overwriting',
                        path, e)
    combined = existing + results
    with open(path, 'w') as f:
        json.dump(combined, f, indent=2, default=str)
    log.info('Results written to %s (now %d entries)',
             path, len(combined))


class TestMemberOfBench:
    @pytest.mark.parametrize('variant', _bench_variants())
    def test_hotkey_multithreaded(self, memberof_inst, variant):
        inst, _, estimated_entries = memberof_inst
        ldclt_path = os.path.join(inst.get_bin_dir(), 'ldclt')
        if not os.path.isfile(ldclt_path):
            pytest.skip(f'ldclt not found at {ldclt_path}; install '
                        '389-ds-base-devel (or the package shipping ldclt) '
                        'and re-run')

        hot_dn = _user_dn(1)
        duration = _bench_duration()
        thread_counts = _bench_thread_counts()
        reps = _bench_reps()

        for profile in _variant_cache_profiles(variant):
            requested_bytes = None
            if variant != 'disabled':
                requested_bytes = _cache_profile_bytes(profile,
                                                       estimated_entries)
            log.info('test_hotkey_multithreaded variant=%s profile=%s '
                     'estimated_entries=%d requested_bytes=%s',
                     variant, profile, estimated_entries, requested_bytes)
            concread_mode = configure_variant(inst, variant, requested_bytes)

            warm_conn = open_ldapi_conn(inst)
            try:
                for _ in range(8):
                    warm_conn.search_s(hot_dn, ldap.SCOPE_BASE,
                                       '(objectclass=*)', ['objectclass'])
            finally:
                warm_conn.unbind_s()

            pid = inst.get_pid()
            for n_threads in thread_counts:
                for rep in range(reps):
                    pre_stats = get_ndn_stats(inst)
                    pre_rss = get_rss_kb(pid)
                    t0 = time.perf_counter()

                    ops_per_sec, ldclt_tail = _ldclt_hotkey_search(
                        inst, hot_dn,
                        n_threads=n_threads,
                        duration_sec=duration,
                    )

                    wall_time = time.perf_counter() - t0
                    post_stats = get_ndn_stats(inst)
                    post_rss = get_rss_kb(pid)
                    hits, tries, ratio = ndn_hit_ratio(pre_stats, post_stats)
                    evictions = (post_stats.get('NormalizedDnCacheEvictions', 0)
                                 - pre_stats.get('NormalizedDnCacheEvictions', 0))

                    tries_per_sec = (tries / wall_time) if wall_time > 0 else 0.0

                    result = OrderedDict(
                        test='hotkey_multithreaded',
                        variant=variant,
                        concread_mode=concread_mode,
                    )
                    result.update(_cache_result_fields(
                        profile, requested_bytes, estimated_entries,
                        post_stats))
                    result.update(OrderedDict(
                        n_threads=n_threads,
                        rep=rep,
                        duration_sec=duration,
                        hot_dn=hot_dn,
                        load_tool='ldclt',
                        wall_time_sec=round(wall_time, 3),
                        ops_per_sec=(round(ops_per_sec, 1)
                                     if ops_per_sec is not None else None),
                        ndn_hits=hits,
                        ndn_tries=tries,
                        ndn_tries_per_sec=round(tries_per_sec, 1),
                        ndn_hit_ratio=round(ratio, 4),
                        ndn_evictions=evictions,
                        rss_delta_kb=post_rss - pre_rss,
                    ))
                    if ops_per_sec is None:
                        result['ldclt_tail'] = ldclt_tail
                        result['server_errors_tail'] = _capture_server_errors(inst)

                    log.info('test_hotkey_multithreaded variant=%s profile=%s '
                             'threads=%d rep=%d/%d: ops/s=%s tries/s=%.1f '
                             'hit_ratio=%.4f evictions=%d current_count=%s',
                             variant, profile, n_threads, rep + 1, reps,
                             'NA' if ops_per_sec is None else f'{ops_per_sec:.1f}',
                             tries_per_sec, ratio, evictions,
                             post_stats.get('currentNormalizedDnCacheCount'))

                    all_results.append(result)

    @pytest.mark.parametrize('variant', _bench_variants())
    def test_scan_resistance(self, memberof_inst, variant):
        inst, _, estimated_entries = memberof_inst

        reps = _bench_reps()
        for profile in _variant_cache_profiles(variant):
            requested_bytes = None
            if variant != 'disabled':
                requested_bytes = _cache_profile_bytes(profile,
                                                       estimated_entries)
            log.info('test_scan_resistance variant=%s profile=%s '
                     'estimated_entries=%d requested_bytes=%s',
                     variant, profile, estimated_entries, requested_bytes)
            configure_variant(inst, variant, requested_bytes)

            groups_ou_dn = f'ou={GROUPS_OU},{DEFAULT_SUFFIX}'
            people_ou_dn = f'ou={BENCH_OU},{DEFAULT_SUFFIX}'

            conn = open_ldapi_conn(inst)
            try:
                results = conn.search_s(
                    groups_ou_dn, ldap.SCOPE_ONELEVEL,
                    '(cn=grp_L0_*)', ['dn'])
                hot_dns = [dn for dn, _ in results]
            except ldap.NO_SUCH_OBJECT:
                hot_dns = []
            finally:
                conn.unbind_s()

            if not hot_dns:
                pytest.skip('No L0 leaf groups discovered; fixture not built')

            for rep in range(reps):
                # Restart per rep so every prime/scan/reprime cycle starts
                # from a cold cache.
                concread_mode = configure_variant(inst, variant,
                                                  requested_bytes)
                conn = open_ldapi_conn(inst)
                try:
                    prime_rounds = 10
                    log.info('test_scan_resistance variant=%s rep=%d/%d: '
                             'priming %d hot DNs x %d rounds...',
                             variant, rep + 1, reps, len(hot_dns),
                             prime_rounds)
                    for _ in range(prime_rounds):
                        for dn in hot_dns:
                            conn.search_s(dn, ldap.SCOPE_BASE,
                                          '(objectclass=*)', ['cn'])
                    log.info('test_scan_resistance variant=%s: scanning all '
                             'users...', variant)
                    scan_t0 = time.perf_counter()
                    scan_results = conn.search_s(
                        people_ou_dn, ldap.SCOPE_ONELEVEL,
                        '(uid=user*)', ['uid'])
                    scan_wall = time.perf_counter() - scan_t0
                    log.info('test_scan_resistance: scan returned %d entries '
                             'in %.2fs', len(scan_results), scan_wall)

                    pre_stats = get_ndn_stats(inst)
                    pre_evict = pre_stats.get('NormalizedDnCacheEvictions', 0)
                    reprime_t0 = time.perf_counter()
                    for dn in hot_dns:
                        conn.search_s(dn, ldap.SCOPE_BASE,
                                      '(objectclass=*)', ['cn'])
                    reprime_wall = time.perf_counter() - reprime_t0
                    post_stats = get_ndn_stats(inst)
                finally:
                    conn.unbind_s()

                hits, tries, ratio = ndn_hit_ratio(pre_stats, post_stats)
                evictions = (post_stats.get('NormalizedDnCacheEvictions', 0)
                             - pre_evict)

                log.info('test_scan_resistance variant=%s rep=%d/%d: '
                         'reprime_hits=%d reprime_tries=%d hit_ratio=%.4f '
                         'wall=%.2fs evictions=%d',
                         variant, rep + 1, reps, hits, tries, ratio,
                         reprime_wall, evictions)

                result = OrderedDict(
                    test='scan_resistance',
                    variant=variant,
                    concread_mode=concread_mode,
                )
                result.update(_cache_result_fields(
                    profile, requested_bytes, estimated_entries, post_stats))
                result.update(OrderedDict(
                    rep=rep,
                    hot_set_size=len(hot_dns),
                    prime_rounds=prime_rounds,
                    scan_entries=len(scan_results),
                    scan_wall_sec=round(scan_wall, 3),
                    reprime_wall_sec=round(reprime_wall, 3),
                    reprime_ndn_hits=hits,
                    reprime_ndn_tries=tries,
                    reprime_ndn_hit_ratio=round(ratio, 4),
                    reprime_ndn_evictions=evictions,
                ))
                all_results.append(result)

    @pytest.mark.parametrize('variant', _bench_variants())
    def test_memberof_cascade_multithreaded(self, memberof_inst, variant):
        inst, deepest_dn, estimated_entries = memberof_inst

        groups_ou_dn = f'ou={GROUPS_OU},{DEFAULT_SUFFIX}'
        discover_conn = open_ldapi_conn(inst)
        try:
            results = discover_conn.search_s(
                groups_ou_dn, ldap.SCOPE_ONELEVEL,
                '(cn=grp_L0_*)', ['dn'])
            leaf_dns = [dn for dn, _ in results]
        except ldap.NO_SUCH_OBJECT:
            leaf_dns = [deepest_dn]
        finally:
            discover_conn.unbind_s()

        if not leaf_dns:
            leaf_dns = [deepest_dn]

        duration = _bench_duration()
        thread_counts = _bench_thread_counts()
        reps = _bench_reps()

        for profile in _variant_cache_profiles(variant):
            requested_bytes = None
            if variant != 'disabled':
                requested_bytes = _cache_profile_bytes(profile,
                                                       estimated_entries)
            log.info('test_cascade_multithreaded variant=%s profile=%s '
                     'estimated_entries=%d requested_bytes=%s',
                     variant, profile, estimated_entries, requested_bytes)
            concread_mode = configure_variant(inst, variant, requested_bytes)
            pid = inst.get_pid()

            for n_threads in thread_counts:
                for rep in range(reps):
                    leaf_for_thread = {
                        tid: leaf_dns[tid % len(leaf_dns)]
                        for tid in range(n_threads)
                    }
                    user_for_thread = {
                        tid: _user_dn(N_USERS - tid).encode()
                        for tid in range(n_threads)
                    }
                    toggle_for_thread = {tid: True for tid in range(n_threads)}

                    def cascade_op(conn, _rng, tid):
                        target = leaf_for_thread[tid]
                        user = user_for_thread[tid]
                        toggle = toggle_for_thread[tid]
                        try:
                            if toggle:
                                conn.modify_s(
                                    target,
                                    [(ldap.MOD_ADD, 'member', [user])])
                            else:
                                conn.modify_s(
                                    target,
                                    [(ldap.MOD_DELETE, 'member', [user])])
                        except (ldap.TYPE_OR_VALUE_EXISTS,
                                ldap.NO_SUCH_ATTRIBUTE):
                            pass
                        toggle_for_thread[tid] = not toggle

                    log.info('test_cascade_multithreaded variant=%s '
                             'profile=%s threads=%d rep=%d/%d: '
                             'warming up (5s)...',
                             variant, profile, n_threads, rep + 1, reps)
                    _run_threaded_load(inst, n_threads, 5, cascade_op)

                    pre_stats = get_ndn_stats(inst)
                    pre_rss = get_rss_kb(pid)

                    load = _run_threaded_load(inst, n_threads, duration,
                                              cascade_op)

                    post_stats = get_ndn_stats(inst)
                    post_rss = get_rss_kb(pid)
                    hits, tries, ratio = ndn_hit_ratio(pre_stats, post_stats)
                    evictions = (post_stats.get('NormalizedDnCacheEvictions', 0)
                                 - pre_stats.get('NormalizedDnCacheEvictions', 0))

                    result = OrderedDict(
                        test='cascade_multithreaded',
                        variant=variant,
                        concread_mode=concread_mode,
                    )
                    result.update(_cache_result_fields(
                        profile, requested_bytes, estimated_entries,
                        post_stats))
                    result.update(OrderedDict(
                        n_threads=n_threads,
                        rep=rep,
                        duration_sec=duration,
                        leaf_groups_used=min(n_threads, len(leaf_dns)),
                        ndn_hits=hits,
                        ndn_tries=tries,
                        ndn_hit_ratio=round(ratio, 4),
                        ndn_evictions=evictions,
                        rss_delta_kb=post_rss - pre_rss,
                    ))
                    result.update(load)

                    log.info('test_cascade_multithreaded variant=%s '
                             'profile=%s threads=%d rep=%d/%d: ops/s=%.1f '
                             'p50=%.3fms p95=%.3fms p99=%.3fms '
                             'hit_ratio=%.4f errors=%d current_count=%s',
                             variant, profile, n_threads, rep + 1, reps,
                             result['ops_per_sec'], result['p50_ms'],
                             result['p95_ms'], result['p99_ms'],
                             ratio, result['total_errors'],
                             post_stats.get('currentNormalizedDnCacheCount'))

                    all_results.append(result)


@pytest.fixture(scope="session", autouse=True)
def write_results_on_exit():
    yield
    _write_results(all_results)
