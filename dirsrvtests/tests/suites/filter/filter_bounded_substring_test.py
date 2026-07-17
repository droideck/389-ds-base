# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---


"""
Result correctness for AND filters whose substring components read large
index ID lists. Candidate generation caps the index reads of substring and
approximate components relative to the bound the preceding components
established; a capped read yields ALLIDS, the AND intersection discards it,
and the filter test must still produce the exact result set.
"""

import ldap
import logging
import os
import pytest

from ldap.controls import SimplePagedResultsControl
from lib389._constants import DEFAULT_SUFFIX
from lib389.backend import Backends, DatabaseConfig
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

# Every cn shares the "Common Xanadu" words so their substring index keys
# hold more IDs than the read cap floor (4000); the golden users
# additionally carry a distinctive sn (equality-indexed) and a "Golden"
# cn word so an AND can bound candidates before the substring component.
#
# Fat-key accounting, so the >4000 margin stays auditable: 4300 base users
# (headroom over the floor: 300 IDs, 7.5% - if it erodes,
# test_cap_engages_and_logs fails loudly); the lookthrough-waiver test adds
# a 60-user cohort of which 20 carry Xanadu (4320 live postings from then
# on); the tombstone test's 12 users are purged from the substring index at
# tombstone creation. No test may add a referral entry: a referral in the
# backend puts an OR wrapper above the executed filter of external subtree
# searches, and the cap engages only under pure-AND ancestry.
TOTAL_USERS = 4300
GOLDEN_COUNT = 100
GOLDEN_SN = 'GoldenSn'
OTHER_SN = 'OtherSn'

CAP_LOG_PATTERN = '.*returned ALLIDS under read cap.*'
ERRORLOG_LEVEL_BACKLDBM = '524288'


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


def search_uids(topo, filterstr):
    """Return the sorted uid list the filter matches."""
    entries = topo.standalone.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                       filterstr, ['uid'])
    return sorted(ensure_str(e.getValue('uid')) for e in entries)


def cap_log_count(topo):
    """Return how many capped-read diagnostic lines the error log holds."""
    return len(topo.standalone.ds_error_log.match(CAP_LOG_PATTERN))


def test_bounded_and_with_saturated_substring(topo, create_users):
    """Verify an AND of a selective equality and a substring whose keys
    exceed the read cap returns the exact result set

    :id: acbd04b9-1d62-4205-bc10-c87ee72770e3
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(sn=GoldenSn)(cn=*xanadu*)) and collect uids
        2. Compare against the golden cohort
    :expectedresults:
        1. Search succeeds
        2. Exactly the 100 golden users are returned
    """
    result = search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))')
    assert result == sorted(create_users)


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
    golden = sorted(create_users)
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(|(cn=*xanadu*)(cn=*absentxyz*)))') == golden
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(|(cn=*absentxyz*)(cn=*common*)))') == golden


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
    assert search_uids(topo, f'(&(sn={OTHER_SN})(cn=*golden*))') == []
    assert search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*person*))') == []
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(cn=*golden*))') == sorted(create_users)


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
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(!(cn=*person*)))') == sorted(create_users)
    assert search_uids(topo, f'(&(sn={GOLDEN_SN})(!(cn=*golden*)))') == []


def test_unbounded_substring_stays_exact(topo, create_users):
    """Verify substring searches with no preceding bound are unaffected:
    a lone substring and the first component of a substring-only AND run
    uncapped (later components cap against the results collected so far)

    :id: 9594db07-0ab9-46a8-899f-e5180f0cb99f
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (cn=*xanadu*) alone
        2. Search (&(cn=*xanadu*)(cn=*golden*)) - substrings only
    :expectedresults:
        1. All 4300 users are returned
        2. Exactly the 100 golden users are returned
    """
    assert len(search_uids(topo, '(cn=*xanadu*)')) == TOTAL_USERS
    assert search_uids(
        topo, '(&(cn=*xanadu*)(cn=*golden*))') == sorted(create_users)


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
    assert search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*zqzqzq*))') == []


def test_cap_engages_and_logs(topo, create_users):
    """Verify the read cap actually engages for a bounded AND: the capped
    substring read degrades to ALLIDS and leaves a diagnostic line in the
    error log, while the result set stays exact

    :id: a0b90ca9-108a-4ae0-8a77-6905470259ac
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Enable the backend debug error log level
        2. Search (&(sn=GoldenSn)(cn=*xanadu*))
        3. Check the error log for the capped-read diagnostic
    :expectedresults:
        1. Log level is set
        2. Exactly the 100 golden users are returned
        3. A new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        result = search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))')
        assert result == sorted(create_users)
        assert cap_log_count(topo) > before
    finally:
        inst.config.set('nsslapd-errorlog-level', errorlog_level)


def test_costly_first_order_stays_exact(topo, create_users):
    """Verify a bounded AND written substring-first returns the exact
    result set (the filter optimizer hoists the equality ahead of the
    substring, so the cap applies regardless of the written order)

    :id: d731c07f-69a4-4cae-9aed-fdc589b35916
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Search (&(cn=*xanadu*)(sn=GoldenSn))
    :expectedresults:
        1. Exactly the 100 golden users are returned
    """
    assert search_uids(
        topo, f'(&(cn=*xanadu*)(sn={GOLDEN_SN}))') == sorted(create_users)


def test_unlimited_scanlimit_disables_cap(topo, create_users):
    """Verify an explicit nsslapd-idlistscanlimit of -1 (unlimited) wins
    over the read cap: the same bounded search reads the substring keys in
    full and logs no capped-read diagnostic

    :id: 82593ef9-7acf-465c-bfd7-5ba79d623dd8
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Enable the backend debug error log level
        2. Set nsslapd-idlistscanlimit to -1
        3. Search (&(sn=GoldenSn)(cn=*xanadu*))
        4. Check the error log for new capped-read diagnostics
    :expectedresults:
        1. Log level is set
        2. Limit is set
        3. Exactly the 100 golden users are returned
        4. No new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    db_cfg = DatabaseConfig(inst)
    scanlimit = db_cfg.get_attr_val_utf8('nsslapd-idlistscanlimit')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        db_cfg.set([('nsslapd-idlistscanlimit', '-1')])
        before = cap_log_count(topo)
        result = search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))')
        assert result == sorted(create_users)
        assert cap_log_count(topo) == before
    finally:
        db_cfg.set([('nsslapd-idlistscanlimit', scanlimit)])
        inst.config.set('nsslapd-errorlog-level', errorlog_level)


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
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(cn~=Xanadu))') == sorted(create_users)


def test_bounded_and_with_approx_index(topo, create_users):
    """Verify the cap applies to an INDEXED approximate component: with an
    approx index on cn, the shared phonetic key for Xanadu holds all 4300
    IDs, so the capped read returns ALLIDS and logs the diagnostic while
    the result stays exact (the unindexed case is covered by
    test_bounded_and_with_approx)

    :id: 7c3a4d92-5b1e-4f0a-9c2d-8e6b1a24f7d3
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Add nsIndexType approx to the cn index and reindex cn
        2. Enable the backend debug error log level
        3. Search (&(sn=GoldenSn)(cn~=Xanadu))
        4. Check the error log for the capped-read diagnostic
    :expectedresults:
        1. Index is updated and reindex succeeds
        2. Log level is set
        3. Exactly the 100 golden users are returned
        4. A new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    be = Backends(inst).get('userRoot')
    idx = be.get_index('cn')
    idx.add('nsIndexType', 'approx')
    be.reindex(attrs=['cn'], wait=True)

    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        result = search_uids(topo, f'(&(sn={GOLDEN_SN})(cn~=Xanadu))')
        assert result == sorted(create_users)
        assert cap_log_count(topo) > before
    finally:
        inst.config.set('nsslapd-errorlog-level', errorlog_level)
    # the approx index stays; no later test uses approximate filters


def test_not_equality_with_costly_component(topo, create_users):
    """Verify NOT-of-equality components combine exactly with capped
    substring components, in both component orders

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
    golden = sorted(create_users)
    assert search_uids(
        topo,
        f'(&(!(uid=defuser00000))(sn={GOLDEN_SN})(cn=*xanadu*))') == \
        [uid for uid in golden if uid != 'defuser00000']
    assert search_uids(topo, f'(&(!(sn={OTHER_SN}))(cn=*xanadu*))') == golden


def test_user_unlimited_idlistscanlimit_waives_cap(topo, create_users):
    """Verify a per-user nsIDListScanLimit of -1 (unlimited reslimit) wins
    over the read cap: the bound search reads the substring keys in full
    and logs no capped-read diagnostic

    :id: 2f9e8a41-6c05-4b7d-a3e8-91d4c5b0f26a
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Set nsIDListScanLimit -1 on a user entry, then bind as that user
        2. Enable the backend debug error log level
        3. Search (&(sn=GoldenSn)(cn=*xanadu*)) over the user's connection
        4. Check the error log for new capped-read diagnostics
    :expectedresults:
        1. Bind succeeds (the reslimit is read at bind time)
        2. Log level is set
        3. Exactly the 100 golden users are returned
        4. No new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    user = UserAccount(inst, f'uid=defuser00001,ou=People,{DEFAULT_SUFFIX}')
    user.replace('nsIDListScanLimit', '-1')
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    conn = user.bind('password00001')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        entries = conn.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                f'(&(sn={GOLDEN_SN})(cn=*xanadu*))', ['uid'])
        result = sorted(ensure_str(e.getValue('uid')) for e in entries)
        assert result == sorted(create_users)
        assert cap_log_count(topo) == before
    finally:
        conn.close()
        inst.config.set('nsslapd-errorlog-level', errorlog_level)
        user.remove_all('nsIDListScanLimit')


def test_per_index_scanlimit_rule_overrides_cap(topo, create_users):
    """Verify an explicit per-index nsIndexIDListScanLimit rule wins over
    the read cap: the matched rule's limit replaces the capped one inside
    index_get_allids, the substring keys are read in full, and no
    capped-read diagnostic is logged

    :id: 8d17b3c6-4e2a-49f5-b0c1-7a35d9e84f12
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Add nsIndexIDListScanLimit "limit=100000 type=sub flags=AND" to
           the cn index (runtime-effective, no reindex needed)
        2. Enable the backend debug error log level
        3. Search (&(sn=GoldenSn)(cn=*xanadu*))
        4. Check the error log for new capped-read diagnostics
    :expectedresults:
        1. Rule is added
        2. Log level is set
        3. Exactly the 100 golden users are returned
        4. No new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    rule = 'limit=100000 type=sub flags=AND'
    idx = Backends(inst).get('userRoot').get_index('cn')
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    try:
        idx.add('nsIndexIDListScanLimit', rule)
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        result = search_uids(topo, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))')
        assert result == sorted(create_users)
        assert cap_log_count(topo) == before
    finally:
        idx.remove('nsIndexIDListScanLimit', rule)
        inst.config.set('nsslapd-errorlog-level', errorlog_level)


def test_lookthrough_waiver_reads_component_in_full(topo, create_users):
    """Verify the lookthrough waiver behaviorally: when the AND bound
    already exceeds the operation's lookthrough limit, the substring
    component must be read in full because it is the only component able
    to narrow the candidate set below that limit. If the waiver broke, the
    capped read would be discarded and the 60-candidate set would hit
    LDAP_ADMINLIMIT_EXCEEDED at entry 51 instead of succeeding with 20.

    :id: 5b62e9d0-3a8f-47c4-92e6-0cd1b7a4358e
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Create 60 users with sn=WaiverSn, 20 of them with a Xanadu cn
        2. Set nsLookThroughLimit 50 on a bind user, then bind as it
        3. Search (&(sn=WaiverSn)(cn=*xanadu*)) over the user's connection
        4. Check the error log for new capped-read diagnostics
    :expectedresults:
        1. Users are created
        2. Bind succeeds
        3. Exactly the 20 Xanadu-bearing waiver users are returned, with no
           ADMINLIMIT_EXCEEDED
        4. No new capped-read diagnostic line was logged
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
            expected.append(uid)
    # the cohort stays for the rest of the module: 20 more Xanadu postings
    # (4320) change no other test's assertions (golden selects on sn)

    bind_user = UserAccount(inst, f'uid=defuser00002,ou=People,{DEFAULT_SUFFIX}')
    bind_user.replace('nsLookThroughLimit', '50')
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    conn = bind_user.bind('password00002')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        entries = conn.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                '(&(sn=WaiverSn)(cn=*xanadu*))', ['uid'])
        result = sorted(ensure_str(e.getValue('uid')) for e in entries)
        assert result == sorted(expected)
        assert cap_log_count(topo) == before
    finally:
        conn.close()
        inst.config.set('nsslapd-errorlog-level', errorlog_level)
        bind_user.remove_all('nsLookThroughLimit')


def test_or_of_ands_not_capped(topo, create_users):
    """Verify ANDs nested under an OR never engage the cap (pure-AND
    ancestry): each branch has a small bound and fat substring keys, but
    under a union a discarded component would genuinely add candidates and
    per-branch fallbacks would add up across the OR, so engagement is
    structurally refused. This test fails on the pre-ancestry cap (commit
    e2f1b74d9-era builds), where each AND frame engaged independently and
    logged - do not "fix" it in a backport by dropping the assertion.

    :id: e4a0c7f8-92d3-4561-8b7a-6f1e0d29c53b
    :setup: Standalone instance with 4300 users sharing fat cn substring keys
    :steps:
        1. Enable the backend debug error log level
        2. Search (|(&(sn=GoldenSn)(cn=*xanadu*))(&(sn=GoldenSn)(cn=*common*)))
        3. Check the error log for new capped-read diagnostics
    :expectedresults:
        1. Log level is set
        2. Exactly the 100 golden users are returned
        3. No new capped-read diagnostic line was logged
    """
    inst = topo.standalone
    errorlog_level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    try:
        inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
        before = cap_log_count(topo)
        result = search_uids(
            topo,
            f'(|(&(sn={GOLDEN_SN})(cn=*xanadu*))(&(sn={GOLDEN_SN})(cn=*common*)))')
        assert result == sorted(create_users)
        assert cap_log_count(topo) == before
    finally:
        inst.config.set('nsslapd-errorlog-level', errorlog_level)


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
        _, rdata, _, rctrls = inst.result3(msgid)
        for _, attrs in rdata:
            collected.append(ensure_str(attrs['uid'][0]))
        pages += 1
        pctrls = [c for c in rctrls
                  if c.controlType == SimplePagedResultsControl.controlType]
        assert pctrls
        if not pctrls[0].cookie:
            break
        req.cookie = pctrls[0].cookie
    assert pages >= 4
    assert sorted(collected) == sorted(create_users)


def test_tombstone_and_substring_keeps_order(topo, create_users):
    """Verify the cap's tombstone exemption with a sentinel that flips if
    the exemption breaks. Tombstone creation purges the entry's cn from
    the substring index, so the index-driven candidates of
    (&(objectClass=nsTombstone)(cn=*xanadu*)) are empty - today's
    order-dependent tombstone semantics (issue #2414 class). If candidate
    generation capped tombstone searches, the fat cn read (4320 live IDs
    against a bound of 12) would return ALLIDS, the AND would discard it,
    and the mandatory filter test would return the 12 tombstones (the
    ENTRIES retain their cn; only the index postings are purged) -
    flipping the empty assertion below.

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
        4. No entries are returned (purged index postings, no cap)
        5. Exactly the 100 golden users are returned
    """
    inst = topo.standalone
    USNPlugin(inst).enable()
    inst.restart()

    # 12 > FILTER_TEST_THRESHOLD (10): with 10 or fewer tombstone
    # candidates the intersection shortcut fires before the substring
    # component is walked and the sentinel could never discriminate
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
    entries = inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                            '(objectClass=nsTombstone)',
                            ['uid', 'nsuniqueid'])
    tomb_uids = sorted(ensure_str(e.getValue('uid'))
                       for e in entries
                       if ensure_str(e.getValue('nsuniqueid')) != ruv_nsuniqueid)
    assert tomb_uids == sorted(uid for uid, _ in created)

    # component order is load-bearing: the tombstone equality must come
    # first so the bound exists before the substring component is walked
    # (the filter optimizer refuses to reorder tombstone-flagged filters,
    # so the written order survives to candidate generation)
    filt = '(&(objectClass=nsTombstone)(cn=*xanadu*))'
    assert inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, filt) == []

    # live golden search is unaffected by any of the above
    assert search_uids(
        topo, f'(&(sn={GOLDEN_SN})(cn=*xanadu*))') == sorted(create_users)


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
