# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---


"""Exact results for AND filters containing broad indexed components.

The deterministic data exercises substring and approximate filters together
with selective equality filters, supported scan-limit settings, dynamic-list
augmentation, paging, and tombstones.  Every query must keep the same LDAP
semantics regardless of which candidate-generation implementation is present.
"""

import ldap
import logging
import os
import pytest

from ldap.controls import SimplePagedResultsControl
from lib389._constants import DEFAULT_SUFFIX
from lib389.backend import Backends, DatabaseConfig
from lib389.config import LDBMConfig
from lib389.idm.group import Groups
from lib389.idm.user import UserAccount, UserAccounts
from lib389.plugins import USNPlugin
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo

pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Every cn shares the "Common Xanadu" words, producing a deliberately broad
# substring index key.  The golden users additionally carry a distinctive,
# equality-indexed sn and a "Golden" cn word.  Later tests add 20 more live
# Xanadu values; their sn values are distinct and do not change the golden
# cohort's exact-result assertions.
TOTAL_USERS = 4300
GOLDEN_COUNT = 100
GOLDEN_SN = 'GoldenSn'
OTHER_SN = 'OtherSn'

DYNAMIC_STATIC_COUNT = 20
DYNAMIC_MATCHING_STATIC = 2
DYNAMIC_URL_COUNT = 20
DYNAMIC_LOOKTHROUGH_LIMIT = 30
DYNAMIC_CONFIG_ATTRS = (
    'nsslapd-dynamic-lists-enabled',
    'nsslapd-dynamic-lists-attr',
    'nsslapd-dynamic-lists-oc',
    'nsslapd-dynamic-lists-url-attr',
)


@pytest.fixture(scope="module")
def create_users(topo):
    """Import TOTAL_USERS users; every stride-th one is golden."""
    inst = topo.standalone
    ldif_dir = inst.get_ldif_dir()
    ldif_file = os.path.join(ldif_dir, 'filter_bounded_substring.ldif')
    stride = TOTAL_USERS // GOLDEN_COUNT
    golden_uids = []
    with open(ldif_file, 'w') as f:
        # offline import replaces the backend contents, so the LDIF must
        # carry the suffix root and container too; the aci restores read
        # access for the non-Directory-Manager binds some tests use
        # (authenticated users only)
        f.write(f'dn: {DEFAULT_SUFFIX}\n'
                'objectClass: top\n'
                'objectClass: domain\n'
                'dc: example\n'
                'aci: (targetattr="*")(version 3.0; acl "filter test read"; '
                'allow (read, search, compare)(userdn="ldap:///all");)\n\n'
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
            f.write(f'dn: uid={uid},ou=People,{DEFAULT_SUFFIX}\n'
                    'objectClass: top\n'
                    'objectClass: person\n'
                    'objectClass: organizationalPerson\n'
                    'objectClass: inetOrgPerson\n'
                    f'uid: {uid}\n'
                    f'cn: Common Xanadu {word} {i:05d}\n'
                    f'sn: {GOLDEN_SN if golden else OTHER_SN}\n'
                    f'userPassword: password{i:05d}\n\n')
    os.chmod(ldif_file, 0o644)
    inst.stop()
    assert inst.ldif2db('userRoot', None, None, None, ldif_file)
    inst.start()
    # no per-entry cleanup: the module-scoped topology deletes and
    # recreates the instance for the next module
    return golden_uids


def search_dns_result(conn, filterstr, base=DEFAULT_SUFFIX,
                      scope=ldap.SCOPE_SUBTREE):
    """Run one search and return its result type and complete sorted DN set."""
    msgid = conn.search_ext(base, scope, filterstr, ['1.1'])
    result_type, result_data, _, _ = conn.result3(msgid)
    dns = sorted(ensure_str(dn).lower() for dn, _ in result_data)
    return result_type, dns


def expected_user_dns(uids):
    """Construct expected user DNs independently from a fixture's uid list."""
    return sorted(f'uid={uid},ou=People,{DEFAULT_SUFFIX}'.lower()
                  for uid in uids)


def assert_search_dns(conn, filterstr, expected, base=DEFAULT_SUFFIX,
                      scope=ldap.SCOPE_SUBTREE):
    """Assert LDAP success and the complete independently expected DN set."""
    result_type, dns = search_dns_result(conn, filterstr, base, scope)
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == sorted(dn.lower() for dn in expected)


def restore_attr_value(obj, attr, old_value):
    """Restore both the former value and former absence of one attribute."""
    if old_value is None:
        obj.remove_all(attr)
    else:
        obj.replace(attr, old_value)


def assert_health_search(conn):
    """Assert a complete successful base search after a risky operation."""
    result_type, dns = search_dns_result(
        conn, '(objectClass=*)', base=DEFAULT_SUFFIX, scope=ldap.SCOPE_BASE)
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == [DEFAULT_SUFFIX.lower()]


def test_bounded_and_with_saturated_substring(topo, create_users):
    """Verify a selective equality AND a broad substring stays exact.

    :id: acbd04b9-1d62-4205-bc10-c87ee72770e3
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(cn=*xanadu*))
        2. Set the global ID-list scan limit to unlimited and repeat
        3. Restore the original scan limit
    :expectedresults:
        1. LDAP succeeds with exactly the 100 golden DNs
        2. LDAP succeeds with the identical complete DN set
        3. The original setting is restored
    """
    inst = topo.standalone
    db_cfg = DatabaseConfig(inst)
    scanlimit = db_cfg.get_attr_val_utf8('nsslapd-idlistscanlimit')
    filterstr = f'(&(sn={GOLDEN_SN})(cn=*xanadu*))'
    expected = expected_user_dns(create_users)

    assert_search_dns(inst, filterstr, expected)
    try:
        db_cfg.set([('nsslapd-idlistscanlimit', '-1')])
        assert_search_dns(inst, filterstr, expected)
    finally:
        db_cfg.set([('nsslapd-idlistscanlimit', scanlimit)])


def test_bounded_and_with_substring_or(topo, create_users):
    """Verify an AND containing an OR of substring components (present and
    absent values) returns the exact result set

    :id: a10002f6-46f3-46d4-866b-8fd7f422ccd7
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(|(cn=*xanadu*)(cn=*absentxyz*)))
        2. Search (&(sn=GoldenSn)(|(cn=*absentxyz*)(cn=*common*)))
    :expectedresults:
        1. Exactly the 100 golden users are returned
        2. Exactly the 100 golden users are returned
    """
    expected = expected_user_dns(create_users)
    assert_search_dns(
        topo.standalone,
        f'(&(sn={GOLDEN_SN})(|(cn=*xanadu*)(cn=*absentxyz*)))', expected)
    assert_search_dns(
        topo.standalone,
        f'(&(sn={GOLDEN_SN})(|(cn=*absentxyz*)(cn=*common*)))', expected)


def test_bounded_and_substring_selects_subset(topo, create_users):
    """Verify a substring component that is more selective than the
    equality bound still narrows the result exactly

    :id: b8c7abbc-97ef-4d89-af02-fe4a705c8265
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=OtherSn)(cn=*golden*)); no non-golden cn has Golden
        2. Search (&(sn=GoldenSn)(cn=*person*)); no golden cn has Person
        3. Search (&(sn=GoldenSn)(cn=*golden*))
    :expectedresults:
        1. No entries are returned
        2. No entries are returned
        3. Exactly the 100 golden users are returned
    """
    expected = expected_user_dns(create_users)
    assert_search_dns(topo.standalone,
                      f'(&(sn={OTHER_SN})(cn=*golden*))', [])
    assert_search_dns(topo.standalone,
                      f'(&(sn={GOLDEN_SN})(cn=*person*))', [])
    assert_search_dns(topo.standalone,
                      f'(&(sn={GOLDEN_SN})(cn=*golden*))', expected)


def test_bounded_and_with_not_substring(topo, create_users):
    """Verify NOT-of-substring components inside a bounded AND return the
    exact result set

    :id: c5b49b1d-d029-45d5-802b-30d0d2d71f94
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(!(cn=*person*)))
        2. Search (&(sn=GoldenSn)(!(cn=*golden*)))
    :expectedresults:
        1. Exactly the 100 golden users are returned
        2. No entries are returned
    """
    expected = expected_user_dns(create_users)
    assert_search_dns(topo.standalone,
                      f'(&(sn={GOLDEN_SN})(!(cn=*person*)))', expected)
    assert_search_dns(topo.standalone,
                      f'(&(sn={GOLDEN_SN})(!(cn=*golden*)))', [])


def test_unbounded_substring_stays_exact(topo, create_users):
    """Verify standalone and substring-only AND searches stay exact.

    :id: 9594db07-0ab9-46a8-899f-e5180f0cb99f
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (cn=*xanadu*) alone
        2. Search (&(cn=*xanadu*)(cn=*golden*)) - substrings only
    :expectedresults:
        1. LDAP succeeds with exactly all 4300 user DNs
        2. LDAP succeeds with exactly the 100 golden DNs
    """
    all_users = expected_user_dns(f'defuser{i:05d}'
                                  for i in range(TOTAL_USERS))
    golden = expected_user_dns(create_users)
    assert_search_dns(topo.standalone, '(cn=*xanadu*)', all_users)
    assert_search_dns(topo.standalone,
                      '(&(cn=*xanadu*)(cn=*golden*))', golden)


def test_bounded_and_substring_empty_key(topo, create_users):
    """Verify a substring whose keys match nothing yields an empty result
    inside a bounded AND

    :id: 034fbd57-4927-4576-b783-528ec9546913
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(cn=*zqzqzq*))
    :expectedresults:
        1. No entries are returned
    """
    assert_search_dns(topo.standalone,
                      f'(&(sn={GOLDEN_SN})(cn=*zqzqzq*))', [])


def test_nested_all_and_override_parity(topo, create_users):
    """Verify a nested all-AND has exact global-override parity.

    :id: 5705c05c-58a8-4bfa-b662-7b7d98a16eaa
    :setup: Standalone instance with 4300 users sharing broad cn substring and
            objectClass equality index keys
    :steps:
        1. Search a selective equality plus a nested AND of a broad substring
           and a broad indexed objectClass equality
        2. Set the supported global ID-list scan limit to unlimited
        3. Repeat the same source filter and run a base health search
        4. Restore the scan limit
    :expectedresults:
        1. LDAP succeeds with the exact golden DN set
        2. The override is applied
        3. LDAP succeeds with the same exact DNs and the server remains healthy
        4. The original configuration value is restored
    """
    inst = topo.standalone
    db_cfg = DatabaseConfig(inst)
    scanlimit = db_cfg.get_attr_val_utf8('nsslapd-idlistscanlimit')
    expected = expected_user_dns(create_users)
    filterstr = (f'(&(sn={GOLDEN_SN})'
                 '(&(cn=*xanadu*)(objectClass=inetOrgPerson)))')

    try:
        assert_search_dns(inst, filterstr, expected)

        db_cfg.set([('nsslapd-idlistscanlimit', '-1')])
        assert_search_dns(inst, filterstr, expected)
        assert_health_search(inst)
    finally:
        db_cfg.set([('nsslapd-idlistscanlimit', scanlimit)])


def test_costly_first_order_stays_exact(topo, create_users):
    """Verify a broad substring written first still returns exact results.

    :id: d731c07f-69a4-4cae-9aed-fdc589b35916
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(cn=*xanadu*)(sn=GoldenSn))
    :expectedresults:
        1. Exactly the 100 golden users are returned
    """
    assert_search_dns(
        topo.standalone, f'(&(cn=*xanadu*)(sn={GOLDEN_SN}))',
        expected_user_dns(create_users))


def test_bounded_and_with_approx(topo, create_users):
    """Verify an approximate component inside a bounded AND returns the
    exact result set (cn has no approx index, and the phonetic match on
    the identical word Xanadu is deterministic for every entry)

    :id: bf35364e-6377-4c3e-b0e2-c1ffa27ee484
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(cn~=Xanadu))
    :expectedresults:
        1. Exactly the 100 golden users are returned
    """
    assert_search_dns(
        topo.standalone, f'(&(sn={GOLDEN_SN})(cn~=Xanadu))',
        expected_user_dns(create_users))


def test_bounded_and_with_approx_index(topo, create_users):
    """Verify an indexed approximate component returns the exact DN set.

    :id: 7c3a4d92-5b1e-4f0a-9c2d-8e6b1a24f7d3
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Add nsIndexType approx to the cn index and reindex cn
        2. Search (&(sn=GoldenSn)(cn~=Xanadu))
    :expectedresults:
        1. Index is updated and reindex succeeds
        2. LDAP succeeds with exactly the 100 golden DNs
    """
    inst = topo.standalone
    be = Backends(inst).get('userRoot')
    idx = be.get_index('cn')
    idx.add('nsIndexType', 'approx')
    be.reindex(attrs=['cn'], wait=True)

    assert_search_dns(
        inst, f'(&(sn={GOLDEN_SN})(cn~=Xanadu))',
        expected_user_dns(create_users))
    # the approx index stays; no later test uses approximate filters


def test_not_equality_with_costly_component(topo, create_users):
    """Verify NOT-of-equality combines exactly with broad substrings.

    :id: 65f8b4b5-4ffb-4857-aa4e-7cfcf37d07c1
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(!(uid=defuser00000))(sn=GoldenSn)(cn=*xanadu*));
           defuser00000 is golden
        2. Search (&(!(sn=OtherSn))(cn=*xanadu*))
    :expectedresults:
        1. Exactly the 99 golden users other than defuser00000 are returned
        2. Exactly the 100 golden users are returned
    """
    golden = expected_user_dns(create_users)
    expected_without_first = [
        dn for dn in golden if not dn.startswith('uid=defuser00000,')
    ]
    assert_search_dns(
        topo.standalone,
        f'(&(!(uid=defuser00000))(sn={GOLDEN_SN})(cn=*xanadu*))',
        expected_without_first)
    assert_search_dns(
        topo.standalone, f'(&(!(sn={OTHER_SN}))(cn=*xanadu*))', golden)


def test_user_unlimited_idlistscanlimit_preserves_results(topo, create_users):
    """Verify a per-user unlimited scan limit preserves exact results.

    :id: 2f9e8a41-6c05-4b7d-a3e8-91d4c5b0f26a
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Set nsIDListScanLimit -1 on a user entry, then bind as that user
        2. Search (&(sn=GoldenSn)(cn=*xanadu*)) over the user's connection
    :expectedresults:
        1. Bind succeeds (the reslimit is read at bind time)
        2. LDAP succeeds with exactly the 100 golden DNs
    """
    inst = topo.standalone
    user = UserAccount(inst, f'uid=defuser00001,ou=People,{DEFAULT_SUFFIX}')
    user.replace('nsIDListScanLimit', '-1')
    conn = user.bind('password00001')
    try:
        assert_search_dns(
            conn, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))',
            expected_user_dns(create_users))
    finally:
        conn.close()
        user.remove_all('nsIDListScanLimit')


def test_per_index_scanlimit_rule_preserves_results(topo, create_users):
    """Verify a per-index scan-limit rule preserves exact results.

    :id: 8d17b3c6-4e2a-49f5-b0c1-7a35d9e84f12
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Add nsIndexIDListScanLimit "limit=100000 type=sub flags=AND" to
           the cn index (runtime-effective, no reindex needed)
        2. Search (&(sn=GoldenSn)(cn=*xanadu*))
    :expectedresults:
        1. Rule is added
        2. LDAP succeeds with exactly the 100 golden DNs
    """
    inst = topo.standalone
    rule = 'limit=100000 type=sub flags=AND'
    idx = Backends(inst).get('userRoot').get_index('cn')
    try:
        idx.add('nsIndexIDListScanLimit', rule)
        assert_search_dns(
            inst, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))',
            expected_user_dns(create_users))
    finally:
        idx.remove('nsIndexIDListScanLimit', rule)


def test_lookthrough_limit_keeps_exact_intersection(topo, create_users):
    """Verify a selective AND stays below the user's lookthrough limit.

    :id: 5b62e9d0-3a8f-47c4-92e6-0cd1b7a4358e
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Create 60 users with sn=WaiverSn, 20 of them with a Xanadu cn
        2. Set nsLookThroughLimit 50 on a bind user, then bind as it
        3. Search (&(sn=WaiverSn)(cn=*xanadu*)) over the user's connection
    :expectedresults:
        1. Users are created
        2. Bind succeeds
        3. LDAP succeeds with exactly the 20 Xanadu-bearing user DNs
    """
    inst = topo.standalone
    users = UserAccounts(inst, DEFAULT_SUFFIX)
    expected = []
    for i in range(60):
        xanadu = i < 20
        word = 'Xanadu Marker' if xanadu else 'Plain'
        uid = f'waiveruser{i:02d}'
        users.create(properties={
            'uid': uid,
            'cn': f'Waiver {word} {i:02d}',
            'sn': 'WaiverSn',
            'uidNumber': str(3000 + i),
            'gidNumber': '3000',
            'homeDirectory': f'/home/{uid}',
        })
        if xanadu:
            expected.append(f'uid={uid},ou=People,{DEFAULT_SUFFIX}')
    # the cohort stays for the rest of the module: 20 more Xanadu postings
    # (4320) change no other test's assertions (golden selects on sn)

    bind_user = UserAccount(inst, f'uid=defuser00002,ou=People,{DEFAULT_SUFFIX}')
    bind_user.replace('nsLookThroughLimit', '50')
    conn = bind_user.bind('password00002')
    try:
        assert_search_dns(
            conn, '(&(sn=WaiverSn)(cn=*xanadu*))', expected)
    finally:
        conn.close()
        bind_user.remove_all('nsLookThroughLimit')


def test_dynamic_candidates_respect_lookthrough(topo, create_users):
    """Verify dynamic augmentation preserves lookthrough-limit semantics.

    The deterministic cohorts satisfy E + D < L <= S + D and S < L, where
    E=2 stored groups match the complete filter, S=20 stored groups share the
    member value, D=20 dynamic groups augment that member value, and L=30.
    Unlimited and finite ID-list scan settings must both return the same exact
    E-entry result without introducing an administrative-limit error.

    :id: b20ac53d-f832-4450-89de-bb48694451f5
    :setup: Standalone instance with the module's saturated cn substring key,
            20 stored groups, and 20 groupOfURLs dynamic entries
    :steps:
        1. Verify the existing member equality index and create the two exact
           ordinary, eighteen wider ordinary, and twenty dynamic entries
        2. Configure dynamic lists with member and memberURL while disabled
        3. Bind two users with L=30; give one an unlimited ID-list scan limit
           and the other a 10000-entry scan limit
        4. With dynamic lists disabled, assert the exact E, S, and D DN sets
        5. Enable dynamic lists and assert the exact S+D member DN set
        6. Run the unlimited control and assert LDAP success and exact DNs
        7. Run the finite-limit path and require the same successful exact DNs
        8. Run a base health search and restore all entry and server settings
    :expectedresults:
        1. The index and all deterministic entries exist
        2. Dynamic-list configuration succeeds
        3. Both binds succeed with E+D < L <= S+D and S < L
        4. The independently constructed E, S, and D sets match exactly
        5. Exactly all stored and dynamic member groups are returned
        6. LDAP succeeds with exactly the two expected stored group DNs
        7. LDAP also succeeds with the identical exact DN set
        8. The server remains healthy and every changed value is restored
    """
    assert (DYNAMIC_MATCHING_STATIC + DYNAMIC_URL_COUNT <
            DYNAMIC_LOOKTHROUGH_LIMIT <=
            DYNAMIC_STATIC_COUNT + DYNAMIC_URL_COUNT)
    assert DYNAMIC_STATIC_COUNT < DYNAMIC_LOOKTHROUGH_LIMIT
    assert DYNAMIC_STATIC_COUNT > 10

    inst = topo.standalone
    config = LDBMConfig(inst)
    groups = Groups(inst, DEFAULT_SUFFIX, rdn='ou=People')
    target_dn = f'uid=defuser00000,ou=People,{DEFAULT_SUFFIX}'
    control_user = UserAccount(
        inst, f'uid=defuser00003,ou=People,{DEFAULT_SUFFIX}')
    limited_user = UserAccount(
        inst, f'uid=defuser00004,ou=People,{DEFAULT_SUFFIX}')
    dynamic_config = {
        attr: config.get_attr_val_utf8(attr)
        for attr in DYNAMIC_CONFIG_ATTRS
    }
    user_limits = [
        (control_user, 'nsLookThroughLimit',
         control_user.get_attr_val_utf8('nsLookThroughLimit')),
        (control_user, 'nsIDListScanLimit',
         control_user.get_attr_val_utf8('nsIDListScanLimit')),
        (limited_user, 'nsLookThroughLimit',
         limited_user.get_attr_val_utf8('nsLookThroughLimit')),
        (limited_user, 'nsIDListScanLimit',
         limited_user.get_attr_val_utf8('nsIDListScanLimit')),
    ]
    created_groups = []
    static_dns = []
    dynamic_dns = []
    expected_dns = []
    control_conn = None
    limited_conn = None

    try:
        member_index = Backends(inst).get('userRoot').get_index('member')
        assert member_index.exists()
        assert 'eq' in {
            value.lower()
            for value in member_index.get_attr_vals_utf8('nsIndexType')
        }

        for i in range(DYNAMIC_STATIC_COUNT):
            if i < DYNAMIC_MATCHING_STATIC:
                cn = f'Common Xanadu Dynamic Budget Static {i:02d}'
            else:
                cn = f'Dynamic Budget Plain Static {i:02d}'
            group = groups.create(properties={
                'cn': f'dynamic-budget-static-{i:02d}',
                'objectClass': ['top', 'groupOfNames', 'extensibleObject'],
                'member': target_dn,
                'sn': 'DynamicBudgetSn',
                'description': cn,
            })
            created_groups.append(group)
            # cn is the saturated substring attribute; description keeps a
            # human-readable cohort label without changing filter semantics.
            group.replace('cn', [f'dynamic-budget-static-{i:02d}', cn])
            static_dns.append(group.dn.lower())
            if i < DYNAMIC_MATCHING_STATIC:
                expected_dns.append(group.dn.lower())

        for i in range(DYNAMIC_URL_COUNT):
            group = groups.create(properties={
                'cn': f'Dynamic Budget Plain URL {i:02d}',
                'objectClass': ['top', 'groupOfURLs', 'extensibleObject'],
                'memberURL': (f'ldap:///{target_dn}??base?'
                              '(objectClass=*)'),
                'sn': 'DynamicBudgetSn',
            })
            created_groups.append(group)
            dynamic_dns.append(group.dn.lower())

        static_dns.sort()
        dynamic_dns.sort()
        expected_dns.sort()

        config.replace('nsslapd-dynamic-lists-enabled', 'off')
        config.replace('nsslapd-dynamic-lists-attr', 'member')
        config.replace('nsslapd-dynamic-lists-oc', 'groupOfUrls')
        config.replace('nsslapd-dynamic-lists-url-attr', 'memberURL')

        control_user.replace('nsLookThroughLimit',
                             str(DYNAMIC_LOOKTHROUGH_LIMIT))
        control_user.replace('nsIDListScanLimit', '-1')
        limited_user.replace('nsLookThroughLimit',
                             str(DYNAMIC_LOOKTHROUGH_LIMIT))
        limited_user.replace('nsIDListScanLimit', '10000')
        control_conn = control_user.bind('password00003')
        limited_conn = limited_user.bind('password00004')

        filterstr = (f'(&(sn=DynamicBudgetSn)(member={target_dn})'
                     '(cn=*xanadu*))')
        result_type, ordinary_bound_dns = search_dns_result(
            inst, f'(member={target_dn})')
        assert result_type == ldap.RES_SEARCH_RESULT
        assert ordinary_bound_dns == static_dns

        result_type, ordinary_exact_dns = search_dns_result(
            control_conn, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert ordinary_exact_dns == expected_dns

        result_type, stored_dynamic_dns = search_dns_result(
            inst, '(&(objectClass=groupOfUrls)(memberURL=*))')
        assert result_type == ldap.RES_SEARCH_RESULT
        assert stored_dynamic_dns == dynamic_dns

        config.replace('nsslapd-dynamic-lists-enabled', 'on')
        result_type, augmented_dns = search_dns_result(
            inst, f'(member={target_dn})')
        assert result_type == ldap.RES_SEARCH_RESULT
        assert augmented_dns == sorted(static_dns + dynamic_dns)

        result_type, control_dns = search_dns_result(control_conn, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert control_dns == expected_dns

        limited_error = None
        limited_result_type = None
        limited_dns = []
        try:
            limited_result_type, limited_dns = search_dns_result(
                limited_conn, filterstr)
        except ldap.ADMINLIMIT_EXCEEDED as error:
            limited_error = error

        assert_health_search(limited_conn)
        assert limited_error is None, (
            'finite scan-limit dynamic-list search introduced '
            f'LDAP_ADMINLIMIT_EXCEEDED: {limited_error!r}'
        )
        assert limited_result_type == ldap.RES_SEARCH_RESULT
        assert limited_dns == expected_dns
    finally:
        cleanup_errors = []

        def cleanup(label, action):
            try:
                action()
            except Exception as error:
                cleanup_errors.append(f'{label}: {error}')

        if limited_conn is not None:
            cleanup('close finite-limit connection', limited_conn.close)
        if control_conn is not None:
            cleanup('close control connection', control_conn.close)
        for user, attr, old_value in user_limits:
            cleanup(
                f'restore {user.dn} {attr}',
                lambda user=user, attr=attr, old_value=old_value:
                restore_attr_value(user, attr, old_value))
        for attr, old_value in dynamic_config.items():
            cleanup(
                f'restore {attr}',
                lambda attr=attr, old_value=old_value:
                restore_attr_value(config, attr, old_value))
        for group in reversed(created_groups):
            cleanup(f'delete {group.dn}', group.delete)
        if cleanup_errors:
            raise AssertionError('; '.join(cleanup_errors))


def test_or_of_ands_stays_exact(topo, create_users):
    """Verify an OR of substring-bearing AND branches stays exact.

    :id: e4a0c7f8-92d3-4561-8b7a-6f1e0d29c53b
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (|(&(sn=GoldenSn)(cn=*xanadu*))(&(sn=GoldenSn)(cn=*common*)))
    :expectedresults:
        1. LDAP succeeds with exactly the 100 golden DNs
    """
    assert_search_dns(
        topo.standalone,
        f'(|(&(sn={GOLDEN_SN})(cn=*xanadu*))'
        f'(&(sn={GOLDEN_SN})(cn=*common*)))',
        expected_user_dns(create_users))


def test_paged_bounded_and(topo, create_users):
    """Verify a bounded AND under simple paged results returns the exact
    result set across pages

    :id: 1a8f5d23-7e46-4c90-b52d-38a6e0c174f9
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Run (&(sn=GoldenSn)(cn=*xanadu*)) with page size 30
        2. Collect all pages
    :expectedresults:
        1. Each page returns successfully
        2. The union of the pages is exactly the 100 golden users
    """
    inst = topo.standalone
    req = SimplePagedResultsControl(True, size=30, cookie='')
    collected = []
    pages = 0
    while True:
        msgid = inst.search_ext(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                f'(&(sn={GOLDEN_SN})(cn=*xanadu*))', ['uid'],
                                serverctrls=[req])
        result_type, rdata, _, rctrls = inst.result3(msgid)
        assert result_type == ldap.RES_SEARCH_RESULT
        collected.extend(ensure_str(dn).lower() for dn, _ in rdata)
        pages += 1
        pctrls = [c for c in rctrls
                  if c.controlType == SimplePagedResultsControl.controlType]
        assert pctrls
        if not pctrls[0].cookie:
            break
        req.cookie = pctrls[0].cookie
    assert pages >= 4
    assert sorted(collected) == expected_user_dns(create_users)


def test_tombstone_and_substring_keeps_order(topo, create_users):
    """Verify historical tombstone substring-index semantics stay exact.

    Tombstone creation removes the entry's cn index posting, so the written
    filter order yields an empty result for the combined tombstone/substr
    query while the tombstone-only query still identifies every deletion.

    :id: b96fdbde-b401-42fd-8349-6778ca984503
    :setup: Standalone instance; USN plugin makes deletes create tombstones
    :steps:
        1. Enable the USN plugin and restart
        2. Create 12 users whose cn carries the fat Xanadu words, then
           delete all 12
        3. Search (objectClass=nsTombstone) and collect uids
        4. Search (&(objectClass=nsTombstone)(cn=*xanadu*))
        5. Search the golden AND shape as sanity
    :expectedresults:
        1. Plugin is enabled
        2. The deletes leave tombstones
        3. Exactly the 12 created uids are tombstones
        4. LDAP succeeds with no entries because the cn postings were purged
        5. Exactly the 100 golden users are returned
    """
    inst = topo.standalone
    USNPlugin(inst).enable()
    inst.restart()

    users = UserAccounts(inst, DEFAULT_SUFFIX)
    created = []
    for i in range(12):
        uid = f'tombuser{i:02d}'
        user = users.create(properties={
            'uid': uid,
            'cn': f'Common Xanadu Tombstone {i:02d}',
            'sn': 'TombSn',
            'uidNumber': str(4000 + i),
            'gidNumber': '4000',
            'homeDirectory': f'/home/{uid}',
        })
        created.append((uid, user))
    for _, user in created:
        user.delete()

    # identity, not just count: exactly the 12 created uids are tombstones
    # (a standalone topology has no RUV tombstone; tolerate only that one)
    ruv_nsuniqueid = 'ffffffff-ffffffff-ffffffff-ffffffff'
    msgid = inst.search_ext(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                            '(objectClass=nsTombstone)',
                            ['uid', 'nsuniqueid'])
    result_type, result_data, _, _ = inst.result3(msgid)
    assert result_type == ldap.RES_SEARCH_RESULT
    tomb_uids = sorted(
        ensure_str(attrs['uid'][0])
        for _, attrs in result_data
        if ensure_str(attrs['nsuniqueid'][0]) != ruv_nsuniqueid
    )
    assert tomb_uids == sorted(uid for uid, _ in created)

    # Component order preserves the established tombstone-index behavior.
    filt = '(&(objectClass=nsTombstone)(cn=*xanadu*))'
    assert_search_dns(inst, filt, [])

    # live golden search is unaffected by any of the above
    assert_search_dns(
        inst, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))',
        expected_user_dns(create_users))


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
