# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---


"""Strict feature contracts for bounded costly-component index reads.

The semantic coverage in ``filter_bounded_substring_test.py`` is expected to
pass with or without the bounded-read implementation.  This module instead
requires that implementation's existing backend diagnostic and intentionally
fails on a clean server that does not provide the feature.
"""

import ldap
import os
import pytest

from lib389._constants import DEFAULT_SUFFIX
from lib389.backend import Backends, DatabaseConfig
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo

pytestmark = pytest.mark.tier1

TOTAL_USERS = 4300
GOLDEN_COUNT = 100
GOLDEN_SN = 'GoldenSn'

CAP_LOG_PATTERN = '.*returned ALLIDS under read cap.*'
ERRORLOG_LEVEL_BACKLDBM = '524288'


@pytest.fixture(scope="module")
def create_users(topo):
    """Import the deterministic fat-key dataset for this feature module."""
    inst = topo.standalone
    ldif_file = os.path.join(
        inst.get_ldif_dir(), 'filter_bounded_substring_feature.ldif')
    stride = TOTAL_USERS // GOLDEN_COUNT
    golden_uids = []

    with open(ldif_file, 'w') as ldif:
        ldif.write(f'dn: {DEFAULT_SUFFIX}\n'
                   'objectClass: top\n'
                   'objectClass: domain\n'
                   'dc: example\n\n'
                   f'dn: ou=People,{DEFAULT_SUFFIX}\n'
                   'objectClass: top\n'
                   'objectClass: organizationalUnit\n'
                   'ou: People\n\n')
        for i in range(TOTAL_USERS):
            uid = f'defuser{i:05d}'
            golden = (i % stride == 0) and len(golden_uids) < GOLDEN_COUNT
            word = 'Golden' if golden else 'Person'
            if golden:
                golden_uids.append(uid)
            ldif.write(f'dn: uid={uid},ou=People,{DEFAULT_SUFFIX}\n'
                       'objectClass: top\n'
                       'objectClass: person\n'
                       'objectClass: organizationalPerson\n'
                       'objectClass: inetOrgPerson\n'
                       f'uid: {uid}\n'
                       f'cn: Common Xanadu {word} {i:05d}\n'
                       f'sn: {GOLDEN_SN if golden else "OtherSn"}\n\n')

    os.chmod(ldif_file, 0o644)
    inst.stop()
    assert inst.ldif2db('userRoot', None, None, None, ldif_file)
    inst.start()
    # The module-scoped topology removes the imported instance and entries.
    return golden_uids


def search_dns_result(conn, filterstr, base=DEFAULT_SUFFIX,
                      scope=ldap.SCOPE_SUBTREE):
    """Run a search and return its result type and complete sorted DN set."""
    msgid = conn.search_ext(base, scope, filterstr, ['1.1'])
    result_type, result_data, _, _ = conn.result3(msgid)
    dns = sorted(ensure_str(dn).lower() for dn, _ in result_data)
    return result_type, dns


def expected_user_dns(uids):
    """Construct expected DNs independently from the fixture's uid list."""
    return sorted(f'uid={uid},ou=People,{DEFAULT_SUFFIX}'.lower()
                  for uid in uids)


def assert_search_dns(conn, filterstr, expected):
    """Assert LDAP success and the complete independently expected DN set."""
    result_type, dns = search_dns_result(conn, filterstr)
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == sorted(dn.lower() for dn in expected)


def enable_backend_debug(inst):
    """Enable the backend diagnostic bit and return the exact prior value."""
    old_value = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    level = int(old_value or '0') | int(ERRORLOG_LEVEL_BACKLDBM)
    inst.config.set('nsslapd-errorlog-level', str(level))
    return old_value


def restore_attr_value(obj, attr, old_value):
    """Restore both the former value and former absence of one attribute."""
    if old_value is None:
        obj.remove_all(attr)
    else:
        obj.replace(attr, old_value)


def cap_log_count(topo):
    """Return the number of bounded-read diagnostics in the error log."""
    return len(topo.standalone.ds_error_log.match(CAP_LOG_PATTERN))


def assert_health_search(conn):
    """Assert a complete successful base search after an override path."""
    result_type, dns = search_dns_result(
        conn, '(objectClass=*)', base=DEFAULT_SUFFIX, scope=ldap.SCOPE_BASE)
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == [DEFAULT_SUFFIX.lower()]


def test_cap_engages_and_logs(topo, create_users):
    """Require the bounded substring read and its existing diagnostic.

    :id: a0b90ca9-108a-4ae0-8a77-6905470259ac
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Enable the existing backend bounded-read diagnostic
        2. Search (&(sn=GoldenSn)(cn=*xanadu*))
        3. Check the error log for a new bounded-read diagnostic
    :expectedresults:
        1. The diagnostic log level is enabled
        2. LDAP succeeds with exactly the 100 golden DNs
        3. A new bounded-read diagnostic is emitted
    """
    inst = topo.standalone
    errorlog_level = enable_backend_debug(inst)
    try:
        before = cap_log_count(topo)
        assert_search_dns(
            inst, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))',
            expected_user_dns(create_users))
        assert cap_log_count(topo) > before
    finally:
        restore_attr_value(
            inst.config, 'nsslapd-errorlog-level', errorlog_level)


def test_nested_all_and_cap_diagnostic_with_override(topo, create_users):
    """Require nested pure-AND engagement and unlimited-override decline.

    :id: 46b09d46-66b8-415a-82eb-07437a93b3c7
    :setup: Standalone instance with broad cn substring and objectClass keys
    :steps:
        1. Enable the existing backend bounded-read diagnostic
        2. Search a selective equality plus a nested pure-AND subtree
        3. Set the global ID-list scan limit to unlimited
        4. Repeat the exact filter and run a base health search
        5. Restore both changed configuration values
    :expectedresults:
        1. The diagnostic log level is enabled without clearing other bits
        2. LDAP succeeds with the exact golden DNs and emits the diagnostic
        3. The supported override is applied
        4. LDAP returns the same DNs without a new diagnostic and is healthy
        5. Both original values are restored
    """
    inst = topo.standalone
    db_cfg = DatabaseConfig(inst)
    scanlimit = db_cfg.get_attr_val_utf8('nsslapd-idlistscanlimit')
    errorlog_level = enable_backend_debug(inst)
    expected = expected_user_dns(create_users)
    filterstr = (f'(&(sn={GOLDEN_SN})'
                 '(&(cn=*xanadu*)(objectClass=inetOrgPerson)))')

    try:
        before = cap_log_count(topo)
        assert_search_dns(inst, filterstr, expected)
        assert cap_log_count(topo) > before

        db_cfg.set([('nsslapd-idlistscanlimit', '-1')])
        before = cap_log_count(topo)
        assert_search_dns(inst, filterstr, expected)
        assert cap_log_count(topo) == before
        assert_health_search(inst)
    finally:
        try:
            db_cfg.set([('nsslapd-idlistscanlimit', scanlimit)])
        finally:
            restore_attr_value(
                inst.config, 'nsslapd-errorlog-level', errorlog_level)


def test_indexed_approx_cap_engages_and_logs(topo, create_users):
    """Require bounded-read engagement for an indexed approximate key.

    :id: 19e20315-3f23-440e-b79b-2d8ca7231a4f
    :setup: Standalone instance with 4300 users sharing a phonetic cn key
    :steps:
        1. Add nsIndexType approx to the cn index and reindex cn
        2. Enable the existing backend bounded-read diagnostic
        3. Search (&(sn=GoldenSn)(cn~=Xanadu))
        4. Check the error log for a new bounded-read diagnostic
    :expectedresults:
        1. The index is updated and reindex succeeds
        2. The diagnostic log level is enabled
        3. LDAP succeeds with exactly the 100 golden DNs
        4. A new bounded-read diagnostic is emitted
    """
    inst = topo.standalone
    backend = Backends(inst).get('userRoot')
    index = backend.get_index('cn')
    index.add('nsIndexType', 'approx')
    backend.reindex(attrs=['cn'], wait=True)

    errorlog_level = enable_backend_debug(inst)
    try:
        before = cap_log_count(topo)
        assert_search_dns(
            inst, f'(&(sn={GOLDEN_SN})(cn~=Xanadu))',
            expected_user_dns(create_users))
        assert cap_log_count(topo) > before
    finally:
        restore_attr_value(
            inst.config, 'nsslapd-errorlog-level', errorlog_level)
    # The module-scoped topology removes the added index configuration.


if __name__ == '__main__':
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
