#!/usr/bin/python3
# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import pytest
import os
import time
import threading
import logging
from abc import abstractmethod

import ldap

from lib389.backend import Backends
from lib389.config import Config
from lib389.properties import TASK_WAIT
from test389.topologies import topology_st as topo

from lib389._constants import (
    DEFAULT_BENAME,
    DEFAULT_SUFFIX,
)

from lib389.utils import (
    ensure_str,
)
from lib389.dseutils import get_ldapurl_from_serverid

pytestmark = pytest.mark.tier3

THIS_DIR = os.path.dirname(__file__)
LDIF = os.path.join(THIS_DIR, '../data/50Kusers.ldif')
RESULT_DIR = f'{THIS_DIR}/../data/ndncache_test_results/r'
RESULT_FILE = f'{RESULT_DIR}/results_ndncache.'

NB_MEASURES = int(os.environ.get('NDN_NB_MEASURES', '2000'))
THREAD_COUNTS = [int(x) for x in os.environ.get(
    'NDN_THREADS', '1,4,8,16').split(',')]

NDN_MONITOR_DN = 'cn=monitor,cn=ldbm database,cn=plugins,cn=config'

BACKENDS = os.environ.get(
    'NDN_BACKENDS',
    'disabled,concread,s3fifo'
).split(',')

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


def open_conn(inst):
    ldapurl, _ = get_ldapurl_from_serverid(inst.serverid)
    conn = ldap.initialize(ldapurl)
    conn.sasl_interactive_bind_s("", ldap.sasl.external())
    return conn


def get_ndn_stats(conn):
    try:
        res = conn.search_s(NDN_MONITOR_DN, ldap.SCOPE_BASE, '(objectclass=*)')
        attrs = res[0][1]
        lower_map = {k.lower(): k for k in attrs}
        out = {}
        for want in ('normalizedDnCacheTries', 'normalizedDnCacheHits',
                     'NormalizedDnCacheEvictions', 'currentNormalizedDnCacheCount'):
            real_key = lower_map.get(want.lower())
            if real_key:
                out[want] = int(ensure_str(attrs[real_key][0]))
        return out
    except Exception:
        return {}


def ndn_delta(pre, post):
    hits = post.get('normalizedDnCacheHits', 0) - pre.get('normalizedDnCacheHits', 0)
    tries = post.get('normalizedDnCacheTries', 0) - pre.get('normalizedDnCacheTries', 0)
    evicts = post.get('NormalizedDnCacheEvictions', 0) - pre.get('NormalizedDnCacheEvictions', 0)
    ratio = hits / tries if tries > 0 else 0
    count = post.get('currentNormalizedDnCacheCount', 0)
    return hits, tries, evicts, ratio, count


NDN_CACHE_SIZE = int(os.environ.get('NDN_CACHE_SIZE', str(4 * 1024 * 1024)))


def configure_backend(inst, backend_name):
    config = Config(inst)
    max_threads = max(THREAD_COUNTS) if THREAD_COUNTS else 32
    config.set('nsslapd-threadnumber', str(max(max_threads * 2, 32)))
    if backend_name == 'disabled':
        config.set('nsslapd-ndn-cache-enabled', 'off')
    else:
        config.set('nsslapd-ndn-cache-enabled', 'on')
        config.set('nsslapd-ndn-cache-max-size', str(NDN_CACHE_SIZE))
        config.set('nsslapd-ndn-cache-backend', backend_name)
    config.set('nsslapd-accesslog-logbuffering', 'off')
    inst.restart()


class Scenario:
    def __init__(self):
        self.ldc = None
        self.results = {}
        self._desc = None
        self._name = None

    def preop(self):
        pass

    @abstractmethod
    def op(self):
        pass

    def postop(self):
        pass

    def __str__(self):
        return self._name

    def description(self):
        return self._desc

    _thread_local = threading.local()
    _op_idx_stride = 1000

    def _run_ops(self, conn, count, tid=0):
        self._thread_local.conn = conn
        self._thread_local.tid = tid
        self._thread_local.op_idx = tid * self._op_idx_stride
        completed = 0
        for _ in range(count):
            try:
                self.preop()
                self.op()
                self.postop()
                completed += 1
            except ldap.LDAPError:
                completed += 1
        return completed

    def _next_idx(self):
        idx = getattr(self._thread_local, 'op_idx', 0)
        self._thread_local.op_idx = idx + 1
        return idx

    @property
    def conn(self):
        return getattr(self._thread_local, 'conn', self.ldc)

    def measure(self, inst, conn, n_threads=1):
        name = str(self)
        self.ldc = conn

        try:
            self._run_ops(conn, 50)
        except ldap.LDAPError:
            pass
        log.info(f'  {name}: warmup done, measuring {NB_MEASURES} ops '
                 f'across {n_threads} client threads...')

        conns = [open_conn(inst) for _ in range(n_threads)]
        ops_per_thread = NB_MEASURES // n_threads
        thread_ops = [0] * n_threads
        errors = [None] * n_threads

        def worker(tid):
            thread_ops[tid] = self._run_ops(conns[tid], ops_per_thread, tid=tid)

        pre = get_ndn_stats(conn)

        t0 = time.perf_counter()
        threads = []
        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        elapsed = time.perf_counter() - t0

        for c in conns:
            c.unbind_s()

        post = get_ndn_stats(conn)
        hits, tries, evicts, ratio, count = ndn_delta(pre, post)

        total_ops = sum(thread_ops)
        ops_sec = total_ops / elapsed if elapsed > 0 else 0
        avg_ms = (elapsed / max(total_ops / n_threads, 1)) * 1000

        log.info(f'  {name}: {ops_sec:.1f} ops/sec  avg={avg_ms:.2f}ms  '
                 f'ndn_ratio={ratio:.3f} ({hits}/{tries})  '
                 f'evicts={evicts}  count={count}  '
                 f'normalizations_saved={hits}')

        return {
            'ops_sec': ops_sec,
            'avg_ms': avg_ms,
            'ndn_hits': hits,
            'ndn_tries': tries,
            'ndn_evicts': evicts,
            'ndn_ratio': ratio,
            'ndn_count': count,
        }


ALL_OUS = [
    'Technology', 'Engineering', 'Sales', 'Marketing',
    'Human Resources', 'Quality Assurance', 'Operations', 'Legal',
    'Customer Service', 'General Management', 'Information Technology',
    'Creative Services', 'Business Development', 'Product Management',
    'Asset Management', 'Board of Directors',
]


class ScenSubtreeRotating(Scenario):

    def __init__(self):
        super().__init__()
        self._name = 'subtree_search_rotating'
        self._desc = 'Subtree search rotating across all OUs'

    def op(self):
        ou = ALL_OUS[self._next_idx() % len(ALL_OUS)]
        self.conn.search_ext_s(
            base=f'ou={ou},ou=people,{DEFAULT_SUFFIX}',
            scope=ldap.SCOPE_SUBTREE,
            filterstr='(uid=*)',
            attrlist=['dn'])


class ScenBaseSearchRotating(Scenario):

    def __init__(self):
        super().__init__()
        self._name = 'base_search_rotating'
        self._desc = 'Base search rotating across user DNs in all OUs'
        self._user_dns = []

    def set_user_dns(self, inst):
        if self._user_dns:
            return
        conn = open_conn(inst)
        res = conn.search_s(f'ou=people,{DEFAULT_SUFFIX}',
                            ldap.SCOPE_SUBTREE, '(uid=*)', ['dn'])
        self._user_dns = [dn for dn, _ in res if dn.startswith('uid=')]
        conn.unbind_s()

    def op(self):
        dn = self._user_dns[self._next_idx() % len(self._user_dns)]
        self.conn.search_ext_s(
            base=dn, scope=ldap.SCOPE_BASE,
            filterstr='(objectclass=*)', attrlist=['dn'])


class ScenDnFilterRotating(Scenario):

    def __init__(self):
        super().__init__()
        self._name = 'dn_filter_rotating'
        self._desc = 'DN-syntax filter search rotating across users'
        self._user_dns = []

    def set_user_dns(self, inst):
        if self._user_dns:
            return
        conn = open_conn(inst)
        res = conn.search_s(f'ou=people,{DEFAULT_SUFFIX}',
                            ldap.SCOPE_SUBTREE, '(uid=*)', ['dn'])
        self._user_dns = [dn for dn, _ in res if dn.startswith('uid=')]
        conn.unbind_s()

    def op(self):
        idx = self._next_idx()
        user_dn = self._user_dns[idx % len(self._user_dns)]
        ou = ALL_OUS[idx % len(ALL_OUS)]
        self.conn.search_ext_s(
            base=f'ou={ou},ou=people,{DEFAULT_SUFFIX}',
            scope=ldap.SCOPE_SUBTREE,
            filterstr=f'(manager={user_dn})',
            attrlist=['dn'])


class ScenModifyRotating(Scenario):

    def __init__(self):
        super().__init__()
        self._name = 'modify_rotating'
        self._desc = 'Modify description rotating across user entries'
        self._user_dns = []

    def set_user_dns(self, inst):
        if self._user_dns:
            return
        conn = open_conn(inst)
        res = conn.search_s(f'ou=people,{DEFAULT_SUFFIX}',
                            ldap.SCOPE_SUBTREE, '(uid=*)', ['dn'])
        self._user_dns = [dn for dn, _ in res if dn.startswith('uid=')]
        conn.unbind_s()

    def op(self):
        idx = self._next_idx()
        dn = self._user_dns[idx % len(self._user_dns)]
        tid = getattr(self._thread_local, 'tid', 0)
        self.conn.modify_s(dn, [(ldap.MOD_REPLACE, 'description',
                                 [f'bench-{tid}-{idx}'.encode()])])


class ScenSearchUnindexedMember(Scenario):

    def __init__(self):
        super().__init__()
        self._name = 'search_unindexed_member'
        self._desc = 'Search non-indexed member in 1000 small groups'

    def op(self):
        self.conn.search_ext_s(
            base=f'ou=tinygroups,ou=groups,dc=example,dc=com',
            scope=ldap.SCOPE_SUBTREE,
            filterstr='(member=uid=Xgclements,ou=Quality Assurance,ou=people,dc=example,dc=com)',
            attrlist=['dn'])


SCENARIOS = [
    ScenSubtreeRotating(),
    ScenBaseSearchRotating(),
    ScenDnFilterRotating(),
    ScenModifyRotating(),
    ScenSearchUnindexedMember(),
]


def _setup_indexes(inst):
    backends = Backends(inst)
    backend = backends.get(DEFAULT_BENAME)
    indexes = backend.get_indexes()

    index = indexes.get('uid')
    index.ensure_attr_state({'nsIndexType': ['eq', 'pres']})

    try:
        indexes.create(properties={
            'cn': 'modifiersName',
            'nsSystemIndex': 'false',
            'nsIndexType': ['eq'],
        })
    except ldap.ALREADY_EXISTS:
        pass

    try:
        index = indexes.get('member')
        index.delete()
    except Exception:
        pass


@pytest.fixture(scope="module", params=BACKENDS)
def with_backend(topo, request):
    inst = topo.standalone
    backend_name = request.param

    _setup_indexes(inst)

    try:
        inst.tasks.importLDIF(suffix=DEFAULT_SUFFIX, input_file=LDIF,
                              args={TASK_WAIT: True})
    except ValueError as e:
        log.error(f'Import failed: {e}')
        assert False

    configure_backend(inst, backend_name)
    log.info(f'=== Backend: {backend_name} ===')
    return backend_name


all_results = []


@pytest.mark.parametrize('n_threads', THREAD_COUNTS)
def test_run_measure(topo, with_backend, n_threads):
    """Measure throughput and NDN cache effectiveness for each scenario
    at varying client concurrency levels.

    :id: 0581e348-9d4f-11f0-a8cb-c85309d5c3e3
    :setup: Standalone instance with 5K users
    :steps: 1. run each scenario N times across n_threads concurrent clients
            2. measure aggregate throughput (ops/sec)
            3. collect NDN cache stats (hits, tries, ratio, evictions)
    :expectedresults: no exception should occur
    """
    inst = topo.standalone
    conn = open_conn(inst)
    backend = with_backend

    for scen in SCENARIOS:
        if hasattr(scen, 'set_user_dns'):
            scen.set_user_dns(inst)
        result = scen.measure(inst, conn, n_threads=n_threads)
        if result:
            scen.results[(backend, n_threads)] = result
            all_results.append({
                'scenario': str(scen),
                'backend': backend,
                'threads': n_threads,
                **result,
            })
    conn.unbind_s()


def test_zz_log_results():
    """Print results summary comparing all backends.

    :id: b8131fee-9d50-11f0-a761-c85309d5c3e3
    :setup: None
    :steps: 1. display the results
    :expectedresults: no exception should occur
    """
    if not all_results:
        log.info('No results collected.')
        return

    os.makedirs(RESULT_DIR, 0o755, exist_ok=True)

    scenarios = []
    backends_seen = []
    thread_counts = []
    by_key = {}
    for r in all_results:
        s, b, t = r['scenario'], r['backend'], r['threads']
        if s not in scenarios:
            scenarios.append(s)
        if b not in backends_seen:
            backends_seen.append(b)
        if t not in thread_counts:
            thread_counts.append(t)
        by_key[(s, b, t)] = r

    disabled_label = 'disabled'

    log.info(f'\n{"=" * 140}')
    log.info(f'NDN CACHE BENCHMARK — {NB_MEASURES} ops/scenario')
    log.info(f'{"=" * 140}')

    for tc in sorted(thread_counts):
        log.info(f'\nTHROUGHPUT (ops/sec) — {tc} client threads:')
        header = f'{"scenario":<35}'
        for b in backends_seen:
            header += f'  {b:>16}'
        header += f'  {"best":>16}'
        log.info(header)
        log.info('-' * len(header))

        for scen in scenarios:
            line = f'{scen:<35}'
            best_backend = None
            best_ops = 0
            for b in backends_seen:
                r = by_key.get((scen, b, tc))
                if r:
                    line += f'  {r["ops_sec"]:>13.1f}/s'
                    if r['ops_sec'] > best_ops:
                        best_ops = r['ops_sec']
                        best_backend = b
                else:
                    line += f'  {"N/A":>16}'
            line += f'  {best_backend or "":>16}'
            log.info(line)

    for tc in sorted(thread_counts):
        log.info(f'\nNDN HIT RATIO — {tc} client threads:')
        header = f'{"scenario":<35}'
        for b in backends_seen:
            header += f'  {b:>16}'
        log.info(header)
        log.info('-' * len(header))

        for scen in scenarios:
            line = f'{scen:<35}'
            for b in backends_seen:
                r = by_key.get((scen, b, tc))
                if r:
                    line += f'  {r["ndn_ratio"]:>15.3f}'
                else:
                    line += f'  {"N/A":>16}'
            log.info(line)

    for tc in sorted(thread_counts):
        log.info(f'\nGAIN vs disabled — {tc} client threads:')
        header = f'{"scenario":<35}'
        for b in backends_seen:
            if b != disabled_label:
                header += f'  {b:>16}'
        log.info(header)
        log.info('-' * len(header))

        for scen in scenarios:
            line = f'{scen:<35}'
            base = by_key.get((scen, disabled_label, tc))
            for b in backends_seen:
                if b == disabled_label:
                    continue
                r = by_key.get((scen, b, tc))
                if r and base and base['ops_sec'] > 0:
                    gain = (r['ops_sec'] - base['ops_sec']) / base['ops_sec'] * 100
                    line += f'  {gain:>14.1f}%'
                else:
                    line += f'  {"N/A":>16}'
            log.info(line)

    log.info(f'\n{"=" * 140}')

    fname = _numbered_filename(RESULT_FILE)
    with open(fname, 'w') as f:
        cols = ['scenario', 'backend', 'threads', 'ops_sec', 'avg_ms',
                'ndn_hits', 'ndn_tries', 'ndn_evicts', 'ndn_ratio', 'ndn_count']
        f.write('\t'.join(cols) + '\n')
        for r in all_results:
            f.write('\t'.join(str(r.get(c, '')) for c in cols) + '\n')
    log.info(f'Results written to {fname}')


def _numbered_filename(prefix):
    idx = 1
    fname = f'{prefix}{idx}'
    while os.path.exists(fname):
        idx += 1
        fname = f'{prefix}{idx}'
    return fname
