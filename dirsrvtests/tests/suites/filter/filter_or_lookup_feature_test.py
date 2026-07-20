# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---


"""Strict feature contracts for the large equality-OR lookup evaluator.

Unlike the implementation-independent result tests in
``filter_or_lookup_test.py``, these tests require the lookup configuration
attribute and its stable debug summary.  They intentionally fail on a server
that does not contain the feature.
"""

import os
import re
from contextlib import contextmanager

import ldap
import pytest
from ldap.filter import escape_filter_chars
from ldap.schema.models import AttributeType

from lib389._constants import DEFAULT_SUFFIX
from lib389.extensibleobject import UnsafeExtensibleObjects
from lib389.idm.directorymanager import DirectoryManager
from lib389.idm.organizationalunit import OrganizationalUnits
from lib389.schema import OBJECT_MODEL_PARAMS, Schema
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo


pytestmark = pytest.mark.tier1

OR_LOOKUP_ATTR = 'nsslapd-enable-or-filter-lookup'
ERRORLOG_LEVEL_BACKLDBM = '524288'
ENG_LOG_PATTERN = '.*OR filter equality lookup engaged.*'
ENG_LOG_RE = re.compile(
    r'OR filter equality lookup engaged: (\d+) node\(s\), largest (\d+) branches')

FEATURE_ATTRS = ('olFeatureLookupA', 'olFeatureLookupB', 'olFeatureLookupC')


def escaped_equalities(attr, values):
    """Build equality components without an enclosing Boolean node."""
    return ''.join(
        f'({attr}={escape_filter_chars(ensure_str(value))})' for value in values)


def escaped_or_of(attr, values):
    """Build an equality OR while preserving filter-special characters."""
    return f'(|{escaped_equalities(attr, values)})'


def search_dns_result(conn, filterstr, base=DEFAULT_SUFFIX,
                      scope=ldap.SCOPE_SUBTREE):
    """Run an asynchronous search and require an LDAP search result."""
    msgid = conn.search_ext(base, scope, filterstr, ['1.1'])
    rtype, rdata, _, _ = conn.result3(msgid)
    assert rtype == ldap.RES_SEARCH_RESULT
    return sorted(ensure_str(dn).lower() for dn, _ in rdata if dn is not None)


def eng_summaries(inst):
    """Return all stable lookup-summary ``(nodes, largest)`` pairs."""
    summaries = []
    for line in inst.ds_error_log.match(ENG_LOG_PATTERN):
        match = ENG_LOG_RE.search(line)
        assert match is not None
        summaries.append((int(match.group(1)), int(match.group(2))))
    return summaries


@contextmanager
def backend_debug_log(inst):
    """Enable the back-ldbm log level needed for lookup summaries."""
    level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    debug_level = int(level or '0') | int(ERRORLOG_LEVEL_BACKLDBM)
    inst.config.set('nsslapd-errorlog-level', str(debug_level))
    try:
        yield
    finally:
        if level is None:
            inst.config.remove_all('nsslapd-errorlog-level')
        else:
            inst.config.set('nsslapd-errorlog-level', level)


@contextmanager
def lookup_disabled(inst):
    """Disable the required lookup feature and restore its original value."""
    original = inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR)
    assert original is not None
    try:
        inst.config.set(OR_LOOKUP_ATTR, 'off')
        assert inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR) == 'off'
        yield
    finally:
        if inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR) != original:
            inst.config.set(OR_LOOKUP_ATTR, original)


@pytest.fixture(scope='module')
def lookup_feature_data(topo):
    """Create the minimal schema and entries needed by feature contracts."""
    inst = topo.standalone
    schema = Schema(inst)
    added_attrs = []
    created = []
    container = None
    dns = {}
    try:
        for index, name in enumerate(FEATURE_ATTRS, start=101):
            params = OBJECT_MODEL_PARAMS[AttributeType].copy()
            params.update({
                'names': (name,),
                'oid': f'2.16.840.1.113730.3.8.999.6275.{index}',
                'desc': 'large equality OR lookup feature contract',
                'equality': 'caseIgnoreMatch',
                'syntax': '1.3.6.1.4.1.1466.115.121.1.15',
                'x_origin': ('large equality OR lookup feature test',),
            })
            schema.add_attributetype(params)
            added_attrs.append(name)

        container = OrganizationalUnits(inst, DEFAULT_SUFFIX).create(
            properties={'ou': 'olLookupFeatureData'})
        objects = UnsafeExtensibleObjects(inst, container.dn)

        def add_entry(key, properties):
            entry = objects.create(properties={
                'cn': f'ol-feature-{key}',
                **properties,
            })
            created.append(entry)
            dns[key] = entry.dn.lower()

        add_entry('family-a', {'olFeatureLookupA': 'a-hit'})
        add_entry('family-b', {'olFeatureLookupB': 'b-hit'})
        add_entry('family-both', {
            'olFeatureLookupA': 'a-hit',
            'olFeatureLookupB': 'b-hit',
        })
        add_entry('family-c', {'olFeatureLookupC': 'c-hit'})

        yield {
            'base': container.dn,
            'dns': dns,
        }
    finally:
        for entry in reversed(created):
            if entry.exists():
                entry.delete()
        if container is not None and container.exists():
            container.delete()
        for name in reversed(added_attrs):
            schema.remove_attributetype(name)


def test_or_lookup_config_threshold_and_runtime_toggle(topo,
                                                       lookup_feature_data):
    """Require the default-on switch, 15/16 threshold, and live toggling.

    :id: d89d4195-ae58-4928-84a6-dbec589baeb1
    :setup: Standalone instance with synthetic case-ignore attributes
    :steps:
        1. Search equivalent 15- and 16-branch equality OR filters
        2. Check the live default and the threshold summaries
        3. Disable lookup and repeat the 16-branch search
        4. Restore lookup and repeat without restarting
    :expectedresults:
        1. Both filters return the same exact DN set
        2. The feature is on and only 16 branches emit a largest-16 summary
        3. Results remain exact and no summary is emitted while disabled
        4. Results remain exact and the 16-branch summary returns immediately
    """
    inst = topo.standalone
    base = lookup_feature_data['base']
    dns = lookup_feature_data['dns']
    expected = sorted([dns['family-a'], dns['family-both']])
    values15 = ['a-hit'] + [f'a-threshold-miss-{i:02d}' for i in range(14)]
    values16 = values15 + ['a-threshold-miss-14']
    filter15 = escaped_or_of('olFeatureLookupA', values15)
    filter16 = escaped_or_of('olFeatureLookupA', values16)
    original = inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR)

    try:
        with backend_debug_log(inst):
            before15 = len(eng_summaries(inst))
            assert search_dns_result(
                inst, filter15, base=base,
                scope=ldap.SCOPE_ONELEVEL) == expected
            after15 = len(eng_summaries(inst))

            before16 = after15
            assert search_dns_result(
                inst, filter16, base=base,
                scope=ldap.SCOPE_ONELEVEL) == expected
            summaries = eng_summaries(inst)[before16:]

            assert original == 'on'
            assert after15 == before15
            assert summaries and all(largest == 16
                                     for _, largest in summaries)

            with lookup_disabled(inst):
                before = len(eng_summaries(inst))
                assert search_dns_result(
                    inst, filter16, base=base,
                    scope=ldap.SCOPE_ONELEVEL) == expected
                assert len(eng_summaries(inst)) == before

            assert inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR) == 'on'
            before = len(eng_summaries(inst))
            assert search_dns_result(
                inst, filter16, base=base,
                scope=ldap.SCOPE_ONELEVEL) == expected
            summaries = eng_summaries(inst)[before:]
            assert summaries and all(largest == 16
                                     for _, largest in summaries)
    finally:
        if (original is not None and
                inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR) != original):
            inst.config.set(OR_LOOKUP_ATTR, original)


def test_or_lookup_dominant_family_order_independent(topo,
                                                     lookup_feature_data):
    """Require selection of the 64-branch family in either source order.

    :id: 8e2110e6-c1f1-435c-8e5f-7f3922dd106d
    :setup: Standalone instance with three synthetic case-ignore attributes
    :steps:
        1. Search an OR containing 16 A branches followed by 64 B branches
        2. Search the same runs in the reverse source order
    :expectedresults:
        1. The exact A-or-B DN set returns and the summary reports largest 64
        2. The exact result and selected family size are unchanged
    """
    inst = topo.standalone
    base = lookup_feature_data['base']
    dns = lookup_feature_data['dns']
    expected = sorted([dns['family-a'], dns['family-b'], dns['family-both']])
    a_values = ['a-hit'] + [f'a-dominant-miss-{i:02d}' for i in range(15)]
    b_values = ['b-hit'] + [f'b-dominant-miss-{i:02d}' for i in range(63)]
    a_run = escaped_equalities('olFeatureLookupA', a_values)
    b_run = escaped_equalities('olFeatureLookupB', b_values)

    with backend_debug_log(inst):
        for filterstr in (f'(|{a_run}{b_run})', f'(|{b_run}{a_run})'):
            before = len(eng_summaries(inst))
            assert search_dns_result(
                inst, filterstr, base=base,
                scope=ldap.SCOPE_ONELEVEL) == expected
            summaries = eng_summaries(inst)[before:]
            assert summaries and all(largest == 64
                                     for _, largest in summaries)


def test_or_lookup_third_family_after_distractors(topo,
                                                  lookup_feature_data):
    """Require discovery of a 64-branch third family after distractors.

    :id: 9c9bde22-983b-4a17-af10-8cc9461939da
    :setup: Standalone instance with three synthetic case-ignore attributes
    :steps:
        1. Search an OR with one absent A, one absent B, and 64 C branches
        2. Inspect the operation summary
    :expectedresults:
        1. Exactly the live C entry returns
        2. The summary reports a largest family of 64 branches
    """
    inst = topo.standalone
    base = lookup_feature_data['base']
    dns = lookup_feature_data['dns']
    c_values = ['c-hit'] + [f'c-third-miss-{i:02d}' for i in range(63)]
    filterstr = ('(|(olFeatureLookupA=a-distractor)'
                 '(olFeatureLookupB=b-distractor)'
                 f'{escaped_equalities("olFeatureLookupC", c_values)})')

    with backend_debug_log(inst):
        before = len(eng_summaries(inst))
        assert search_dns_result(
            inst, filterstr, base=base,
            scope=ldap.SCOPE_ONELEVEL) == [dns['family-c']]
        summaries = eng_summaries(inst)[before:]
        assert summaries and all(largest == 64 for _, largest in summaries)


def test_or_lookup_true_root_all_miss(topo, lookup_feature_data):
    """Require lookup engagement for an unproxied root all-miss search.

    :id: 3fd00a80-65fd-4945-b5f9-dc146ac1b3ec
    :setup: Standalone instance and an independent Directory Manager bind
    :steps:
        1. Search a 16-branch all-miss family as Directory Manager
        2. Repeat with lookup disabled
        3. Run a base-object health search on the same connection
    :expectedresults:
        1. LDAP success, an exact empty result, and a largest-16 summary
        2. LDAP success, the same empty result, and no new summary
        3. The suffix entry returns exactly
    """
    inst = topo.standalone
    conn = DirectoryManager(inst).bind()
    filterstr = escaped_or_of(
        'olFeatureLookupA', [f'ol-root-miss-{i:02d}' for i in range(16)])
    try:
        with backend_debug_log(inst):
            before = len(eng_summaries(inst))
            assert search_dns_result(
                conn, filterstr, base=lookup_feature_data['base'],
                scope=ldap.SCOPE_ONELEVEL) == []
            summaries = eng_summaries(inst)[before:]
            assert summaries and all(largest == 16
                                     for _, largest in summaries)

            with lookup_disabled(inst):
                before = len(eng_summaries(inst))
                assert search_dns_result(
                    conn, filterstr, base=lookup_feature_data['base'],
                    scope=ldap.SCOPE_ONELEVEL) == []
                assert len(eng_summaries(inst)) == before

        assert search_dns_result(
            conn, '(objectClass=*)', base=DEFAULT_SUFFIX,
            scope=ldap.SCOPE_BASE) == [DEFAULT_SUFFIX.lower()]
    finally:
        conn.unbind_s()


if __name__ == '__main__':
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(['-s', CURRENT_FILE])
