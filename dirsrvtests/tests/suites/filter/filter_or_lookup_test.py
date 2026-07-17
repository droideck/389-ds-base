# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---


"""
Result correctness for the per-entry equality-lookup fast path of large OR
filters (issue #6275). An OR of >= 16 same-attribute equality components is
evaluated per entry through a table of normalized assertion values instead
of the linear component walk; every table decision is re-verified through
the classic per-component access-check and match calls, so these tests pin
the exact result sets in the positive space (case/trim normalization,
INTEGER and DN syntaxes, multi-valued entries, paged/one-level/referral
shapes) and the negative space where the fast path must decline or be
by-passed (below threshold, presence/substring/extensible/subtyped/unknown
components, CoS-served attributes, DN big groups, config toggle) and the
ACL boundary (deny-attribute no-leak, ticket 48275 mixed allowed/denied
ORs, NOT-of-OR as a denied user, VLV).
"""

import ldap
import logging
import os
import pytest

from contextlib import contextmanager
from ldap.controls import SimplePagedResultsControl
from ldap.controls.simple import ManageDSAITControl
from ldap.controls.sss import SSSRequestControl
from ldap.controls.vlv import VLVRequestControl
from lib389._constants import DEFAULT_SUFFIX
from lib389.cos import CosPointerDefinition, CosTemplate
from lib389.idm.domain import Domain
from lib389.idm.user import UserAccount
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo

pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)

TOTAL_USERS = 400
GROUPS = 20            # sn=OlSn<i % GROUPS>
SMALL_GROUPS = 30      # 3 members each; even-numbered groups store the
                       # member DNs with an UPPERCASE uid (case-cross data)
BIG_GROUPS = 3         # 200 members each: above any table size these
                       # tests build, so the DN value-count guard declines
BIG_GROUP_MEMBERS = 200
PW = 'olpassword'

ENG_LOG_PATTERN = '.*OR filter equality lookup engaged.*'
ERRORLOG_LEVEL_BACKLDBM = '524288'
OR_LOOKUP_ATTR = 'nsslapd-enable-or-filter-lookup'

PEOPLE = f'ou=People,{DEFAULT_SUFFIX}'
GROUPS_OU = f'ou=Groups,{DEFAULT_SUFFIX}'


def user_uid(i):
    return f'oluser{i:05d}'


def user_dn(i, case_mangled=False):
    uid = user_uid(i).upper() if case_mangled else user_uid(i)
    return f'uid={uid},{PEOPLE}'


@pytest.fixture(scope="module")
def create_data(topo):
    """Import users, groups, and a subentry; return the uid list."""
    inst = topo.standalone
    ldif_dir = inst.get_ldif_dir()
    ldif_file = os.path.join(ldif_dir, 'filter_or_lookup.ldif')
    with open(ldif_file, 'w') as f:
        # offline import replaces the backend contents, so the LDIF must
        # carry the suffix root and containers too; the aci restores read
        # access for the non-Directory-Manager binds some tests use
        f.write(f'dn: {DEFAULT_SUFFIX}\n'
                'objectClass: top\n'
                'objectClass: domain\n'
                'dc: example\n'
                'aci: (targetattr="*")(version 3.0; acl "filter test read"; '
                'allow (read, search, compare)(userdn="ldap:///all");)\n\n'
                f'dn: {PEOPLE}\n'
                'objectClass: top\n'
                'objectClass: organizationalUnit\n'
                'ou: People\n\n'
                f'dn: {GROUPS_OU}\n'
                'objectClass: top\n'
                'objectClass: organizationalUnit\n'
                'ou: Groups\n\n')
        for i in range(TOTAL_USERS):
            uid = user_uid(i)
            extra = ''
            if i in (350, 351, 352):
                extra += (f'employeeNumber: olemp{i:05d}\n'
                          f'mail: {uid}@olmail.example.com\n')
            if i in (360, 361):
                extra += 'cn: olduptest\n'
            if i == 370:
                extra += 'cn;lang-en: olsubtypelang\n'
            if i == 371:
                extra += 'cn: OlCase MIXED Value\n'
            f.write(f'dn: uid={uid},{PEOPLE}\n'
                    'objectClass: top\n'
                    'objectClass: person\n'
                    'objectClass: organizationalPerson\n'
                    'objectClass: inetOrgPerson\n'
                    'objectClass: posixAccount\n'
                    f'uid: {uid}\n'
                    f'cn: OL User {i:05d}\n'
                    f'cn: olalt{i:05d}\n'
                    f'sn: OlSn{i % GROUPS}\n'
                    f'uidNumber: {20000 + i}\n'
                    f'gidNumber: {20000 + i}\n'
                    f'homeDirectory: /home/{uid}\n'
                    f'userPassword: {PW}\n'
                    f'{extra}\n')
        # multi-valued uid entry (two values of the table attribute)
        f.write(f'dn: uid=olmultia,{PEOPLE}\n'
                'objectClass: top\n'
                'objectClass: person\n'
                'objectClass: organizationalPerson\n'
                'objectClass: inetOrgPerson\n'
                'objectClass: posixAccount\n'
                'uid: olmultia\n'
                'uid: olmultib\n'
                'cn: OL Multi\n'
                'sn: OlMultiSn\n'
                'uidNumber: 29999\n'
                'gidNumber: 29999\n'
                'homeDirectory: /home/olmultia\n'
                f'userPassword: {PW}\n\n')
        # an LDAP subentry: excluded from ordinary search results unless
        # the filter names objectclass=ldapsubentry
        f.write(f'dn: cn=olsubentry,{DEFAULT_SUFFIX}\n'
                'objectClass: top\n'
                'objectClass: ldapsubentry\n'
                'objectClass: extensibleObject\n'
                'cn: olsubentry\n'
                'uid: olsubentryuid\n\n')
        # small groups; even-numbered ones store their member DNs with an
        # UPPERCASE uid RDN value (the referenced users exist lowercase)
        for g in range(SMALL_GROUPS):
            members = ''.join(
                f'member: {user_dn(3 * g + j, case_mangled=(g % 2 == 0))}\n'
                for j in range(3))
            f.write(f'dn: cn=olgroup{g:03d},{GROUPS_OU}\n'
                    'objectClass: top\n'
                    'objectClass: groupOfNames\n'
                    f'cn: olgroup{g:03d}\n'
                    f'{members}\n')
        # big groups: more member values than any table these tests build
        for g in range(BIG_GROUPS):
            members = ''.join(f'member: {user_dn(j)}\n'
                              for j in range(BIG_GROUP_MEMBERS))
            f.write(f'dn: cn=olbig{g},{GROUPS_OU}\n'
                    'objectClass: top\n'
                    'objectClass: groupOfNames\n'
                    f'cn: olbig{g}\n'
                    f'{members}\n')
    os.chmod(ldif_file, 0o644)
    inst.stop()
    assert inst.ldif2db('userRoot', None, None, None, ldif_file)
    inst.start()
    return [user_uid(i) for i in range(TOTAL_USERS)]


def or_of(attr, values):
    return '(|%s)' % ''.join(f'({attr}={v})' for v in values)


def ghosts(n, prefix='olghost'):
    """Absent-but-well-formed values to push an OR over the threshold."""
    return [f'{prefix}{i:05d}' for i in range(n)]


def search_uids(topo, filterstr, base=DEFAULT_SUFFIX, scope=ldap.SCOPE_SUBTREE):
    entries = topo.standalone.search_s(base, scope, filterstr, ['uid'])
    return sorted(ensure_str(e.getValue('uid')) for e in entries)


def search_dns(conn, filterstr, base=DEFAULT_SUFFIX, scope=ldap.SCOPE_SUBTREE):
    entries = conn.search_s(base, scope, filterstr, ['1.1'])
    return sorted(e.dn.lower() for e in entries)


def eng_count(topo):
    """How many fast-path engagement diagnostics the error log holds."""
    return len(topo.standalone.ds_error_log.match(ENG_LOG_PATTERN))


@contextmanager
def backend_debug_log(topo):
    """Raise the error log level so the engagement diagnostic is emitted."""
    inst = topo.standalone
    level = inst.config.get_attr_val_utf8('nsslapd-errorlog-level')
    inst.config.set('nsslapd-errorlog-level', ERRORLOG_LEVEL_BACKLDBM)
    try:
        yield
    finally:
        inst.config.set('nsslapd-errorlog-level', level)


@contextmanager
def or_lookup_disabled(topo):
    inst = topo.standalone
    inst.config.set(OR_LOOKUP_ATTR, 'off')
    try:
        yield
    finally:
        inst.config.set(OR_LOOKUP_ATTR, 'on')


def assert_parity(topo, conn, filterstr, base=DEFAULT_SUFFIX,
                  scope=ldap.SCOPE_SUBTREE, serverctrls=None):
    """The strongest oracle available: whatever the search returns (or
    raises), it must be identical with the fast path enabled and disabled."""
    def run():
        try:
            if serverctrls:
                res = conn.search_ext_s(base, scope, filterstr, ['1.1'],
                                        serverctrls=serverctrls)
            else:
                res = conn.search_s(base, scope, filterstr, ['1.1'])
            # lib389 connections return Entry objects
            return sorted(e.dn.lower() for e in res if e.dn)
        except ldap.LDAPError as e:
            return type(e).__name__

    with_fast_path = run()
    with or_lookup_disabled(topo):
        without_fast_path = run()
    assert with_fast_path == without_fast_path
    return with_fast_path


def test_or_big_same_attr_exact(topo, create_data):
    """Verify a large OR of uid equalities (live values, verbatim
    duplicates, and absent values) returns the exact result set and
    engages the lookup fast path

    :id: 7c1de2a8-40f6-4b91-9c35-d82e61f7a904
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Raise the error log level and count engagement diagnostics
        2. Search an OR of 120 live uids, 20 of them repeated, 60 absent
        3. Compare the result and the diagnostic count
    :expectedresults:
        1. Baseline count taken
        2. Exactly the 120 named users are returned, each once
        3. The engagement diagnostic was emitted
    """
    live = create_data[100:220]
    values = live + live[:20] + ghosts(60)
    with backend_debug_log(topo):
        before = eng_count(topo)
        assert search_uids(topo, or_of('uid', values)) == sorted(live)
        assert eng_count(topo) > before


def test_or_duplicate_branches(topo, create_data):
    """Verify an OR dominated by one duplicated component (many table
    entries collapsing onto one key) returns the exact result set

    :id: 2f4bb9e0-a913-45c7-8d62-03cf17e8ba56
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search an OR of 300 verbatim copies of (cn=olduptest) plus a
           few live cn values
    :expectedresults:
        1. Exactly the two olduptest users and the named users return
    """
    values = ['olduptest'] * 300 + ['olalt00005', 'olalt00006']
    expected = sorted([user_uid(360), user_uid(361),
                       user_uid(5), user_uid(6)])
    assert search_uids(topo, or_of('cn', values)) == expected


def test_or_case_and_trim(topo, create_data):
    """Verify assertion values differing in case or padded with spaces
    normalize onto the same table keys the linear walk would match

    :id: 5a0c47d1-6e28-4f9b-a1d5-92c8e04b7f13
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large uid OR whose live values are UPPERCASED
        2. Search a large uid OR with space-padded live values
        3. Search a large cn OR asserting a lowercase form of a stored
           mixed-case value
    :expectedresults:
        1. Exactly the named users are returned
        2. Exactly the named users are returned
        3. Exactly the mixed-case-value user is returned
    """
    live = create_data[10:40]
    upper = [v.upper() for v in live]
    assert search_uids(topo, or_of('uid', upper + ghosts(20))) == sorted(live)
    padded = [f' {v} ' for v in live]
    assert search_uids(topo, or_of('uid', padded + ghosts(20))) == sorted(live)
    values = ['olcase mixed value'] + [f'olalt{i:05d}' for i in range(20, 35)]
    expected = sorted([user_uid(371)] + [user_uid(i) for i in range(20, 35)])
    assert search_uids(topo, or_of('cn', values)) == expected


def test_or_multivalued_entry(topo, create_data):
    """Verify entries match through a non-first attribute value, both on
    a multi-valued cn and on a multi-valued uid

    :id: e93d05c2-71b8-49a4-bd06-4f1a28c9e750
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large cn OR naming only second cn values (olaltNNNNN)
        2. Search a large uid OR naming only the second uid value of the
           two-uid entry
    :expectedresults:
        1. Exactly the named users are returned
        2. The two-uid entry is returned
    """
    picked = list(range(200, 230))
    values = [f'olalt{i:05d}' for i in picked]
    assert search_uids(topo, or_of('cn', values)) == sorted(
        user_uid(i) for i in picked)
    result = topo.standalone.search_s(
        DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
        or_of('uid', ['olmultib'] + ghosts(20)), ['cn'])
    assert [e.dn for e in result] == [f'uid=olmultia,{PEOPLE}']


def test_or_integer_attr(topo, create_data):
    """Verify a large OR on an INTEGER-syntax attribute (uidNumber)
    matches through integer normalization, including leading zeros

    :id: b8e61f30-2c95-4da7-8e14-70d3a9c6f582
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search an OR of 40 live uidNumbers, some written with leading
           zeros, plus absent negative values
    :expectedresults:
        1. Exactly the named users are returned
    """
    picked = list(range(120, 160))
    values = []
    for n, i in enumerate(picked):
        values.append(f'000{20000 + i}' if n % 3 == 0 else f'{20000 + i}')
    values += ['-1', '-00042', '99999999']
    assert search_uids(topo, or_of('uidNumber', values)) == sorted(
        user_uid(i) for i in picked)


def test_or_dn_member(topo, create_data):
    """Verify a large OR on a DN-syntax attribute matches across case
    differences in either direction and tolerates an unparseable DN
    assertion among the components

    :id: 91c25e84-d0b7-4f36-a29c-58e1f4d07b63
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search an OR of member values: a lowercase assertion of a
           member stored UPPERCASE, an UPPERCASE assertion of a member
           stored lowercase, one unparseable-DN value, and 16 absent
           well-formed DNs
    :expectedresults:
        1. Exactly the groups holding those two members are returned
    """
    values = ([user_dn(6), user_dn(4, case_mangled=True), 'not a dn at all']
              + [f'uid=olghost{i:03d},{PEOPLE}' for i in range(16)])
    filt = or_of('member', values)
    entries = topo.standalone.search_s(GROUPS_OU, ldap.SCOPE_SUBTREE,
                                       filt, ['cn'])
    got = sorted(ensure_str(e.getValue('cn')) for e in entries)
    # user 6 is in olgroup002 (stored UPPERCASE) and every big group;
    # user 4 is in olgroup001 (stored lowercase) and every big group
    expected = sorted(['olgroup001', 'olgroup002',
                       'olbig0', 'olbig1', 'olbig2'])
    assert got == expected


def test_or_inside_and(topo, create_data):
    """Verify an OR evaluated under an enclosing AND (candidates broader
    than the OR's own matches) returns the exact result set

    :id: 0d7f92c6-3ab1-48e5-bc70-61e94d28a5f7
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search (&(sn=OlSn0)(|...30 uids across all sn groups...))
    :expectedresults:
        1. Exactly the OR's group-0 members are returned
    """
    in_group = [uid for i, uid in enumerate(create_data) if i % GROUPS == 0][:6]
    other = [uid for i, uid in enumerate(create_data) if i % GROUPS == 7][:24]
    filt = f'(&(sn=OlSn0){or_of("uid", in_group + other)})'
    assert search_uids(topo, filt) == sorted(in_group)


def test_or_referral_wrapper(topo, create_data):
    """Verify a large OR on a suffix containing a referral entry (the
    executed filter gains the (|(f)(objectclass=referral)) wrapper)
    returns the exact result set with and without ManageDsaIT

    :id: 4e8a1c59-f723-4b06-9d84-c2571e0af938
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Add a referral entry with ManageDsaIT and restart (the
           referral-presence flag is read at backend start)
        2. Search a large uid OR with ManageDsaIT
        3. Search the same OR without ManageDsaIT, collecting entries
        4. Remove the referral entry and restart
    :expectedresults:
        1. Referral entry is added
        2. Exactly the named users are returned
        3. Exactly the named users are returned among the entries
        4. Cleanup succeeds
    """
    inst = topo.standalone
    ref_dn = f'ou=OlRefOU,{DEFAULT_SUFFIX}'
    live = create_data[40:80]
    filt = or_of('uid', live + ghosts(20))
    dsait = ManageDSAITControl()
    inst.add_ext_s(ref_dn, [
        ('objectClass', [b'top', b'referral', b'extensibleObject']),
        ('ou', [b'OlRefOU']),
        ('ref', [b'ldap://example.invalid/ou=Elsewhere']),
    ], serverctrls=[dsait])
    inst.restart()
    try:
        res = inst.search_ext_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, filt,
                                ['uid'], serverctrls=[dsait])
        got = sorted(ensure_str(e.getValue('uid')) for e in res
                     if e.dn and e.getValue('uid'))
        assert got == sorted(live)
        # without ManageDsaIT the referral is returned separately; the
        # entry result set must be identical
        inst.set_option(ldap.OPT_REFERRALS, 0)
        try:
            res = inst.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, filt, ['uid'])
            got = sorted(ensure_str(e.getValue('uid')) for e in res
                         if e.dn and e.getValue('uid'))
            assert got == sorted(live)
        finally:
            inst.set_option(ldap.OPT_REFERRALS, 1)
    finally:
        inst.delete_ext_s(ref_dn, serverctrls=[dsait])
        inst.restart()


def test_or_onelevel_nonroot(topo, create_data):
    """Verify a one-level large OR as a regular user returns the exact
    result set: the executed filter carries injected parentid and
    referral components which must not take part in access checking

    :id: a67b30d9-84e2-4c15-bf08-93d7f61c2ae4
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Bind as a regular user
        2. Run a one-level search under ou=People with an OR of 40 live
           uids and 20 absent ones
    :expectedresults:
        1. Bind succeeds
        2. Exactly the named users are returned
    """
    live = create_data[300:340]
    conn = UserAccount(topo.standalone, user_dn(0)).bind(PW)
    try:
        entries = conn.search_s(PEOPLE, ldap.SCOPE_ONELEVEL,
                                or_of('uid', live + ghosts(20)), ['uid'])
        got = sorted(ensure_str(e.getValue('uid')) for e in entries)
        assert got == sorted(live)
    finally:
        conn.unbind_s()


def test_or_paged(topo, create_data):
    """Verify a paged large OR returns the exact union of pages (the
    lookup table is rebuilt per paged re-entry with the per-search dups)

    :id: c50e94f7-16d3-4ba8-92c6-e08a5d7b31f9
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Run an OR of 120 live uids as a paged search, page size 30
    :expectedresults:
        1. The union of the pages is exactly the 120 named users
    """
    inst = topo.standalone
    picked = create_data[150:270]
    filt = or_of('uid', picked)
    req = SimplePagedResultsControl(True, size=30, cookie='')
    collected = []
    while True:
        msgid = inst.search_ext(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE,
                                filt, ['uid'], serverctrls=[req])
        _, rdata, _, rctrls = inst.result3(msgid)
        for _, attrs in rdata:
            collected.append(ensure_str(attrs['uid'][0]))
        pctrls = [c for c in rctrls
                  if c.controlType == SimplePagedResultsControl.controlType]
        assert pctrls
        if not pctrls[0].cookie:
            break
        req.cookie = pctrls[0].cookie
    assert sorted(collected) == sorted(picked)


def test_or_after_online_mod(topo, create_data):
    """Verify a value added over LDAP (as opposed to offline import) is
    found by a large OR immediately, through the cached entry

    :id: 6b2df8a1-59c0-4e73-8f1d-a45e90c3d267
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Add a new cn value to a user over LDAP
        2. Search a large cn OR naming only that new value
        3. Remove the value again
    :expectedresults:
        1. Modify succeeds
        2. Exactly that user is returned
        3. Cleanup succeeds
    """
    user = UserAccount(topo.standalone, user_dn(42))
    user.add('cn', 'olfreshvalue')
    try:
        values = ['olfreshvalue'] + ghosts(20, prefix='olstale')
        assert search_uids(topo, or_of('cn', values)) == [user_uid(42)]
    finally:
        user.remove('cn', 'olfreshvalue')


def test_or_empty_assertion_value(topo, create_data):
    """Verify an empty assertion value among the components neither
    matches nor disturbs the other components

    :id: d1c8f2b5-07e9-4a64-b3d8-52c96e01a7f4
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large uid OR including a (uid=) component
    :expectedresults:
        1. Exactly the named users are returned
    """
    live = create_data[80:100]
    filt = '(|%s(uid=))' % ''.join(f'(uid={v})' for v in live + ghosts(10))
    assert search_uids(topo, filt) == sorted(live)


def test_or_mixed_remainder(topo, create_data):
    """Verify non-equality and other-attribute components mixed into a
    large uid OR still match: presence, substring, extensible, and mail
    components are never table members and take the linear remainder walk

    :id: 3fa96d07-b2e4-4c81-a9f5-16d80c73e2b9
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search an OR of 30 live uids plus (employeeNumber=*),
           (mail=oluser00351@olmail.example.com), (cn=ol user 0001*), and
           an extensible dn-syntax component naming no entry
    :expectedresults:
        1. The uid matches, the three employeeNumber owners, the mail
           owner, and the cn=OL User 0001N users are all returned exactly
    """
    live = list(range(0, 30))
    filt = ('(|'
            + ''.join(f'(uid={user_uid(i)})' for i in live)
            + '(employeeNumber=*)'
            + '(mail=oluser00351@olmail.example.com)'
            + '(cn=ol user 0001*)'
            + f'(member:distinguishedNameMatch:=uid=olghost1,{PEOPLE})'
            + ')')
    expected = sorted(set(
        [user_uid(i) for i in live]
        + [user_uid(i) for i in (350, 351, 352)]   # employeeNumber owners
        + [user_uid(351)]                          # mail owner
        + [user_uid(i) for i in range(10, 20)]))   # cn=OL User 0001N
    assert search_uids(topo, filt) == expected


def test_or_subtyped_branch_and_value(topo, create_data):
    """Verify subtype handling on both sides: a subtyped assertion
    component (cn;lang-en=...) is matched outside the table, and a value
    stored under a subtyped description (cn;lang-en) is matched by plain
    cn components

    :id: 84d05b1e-c976-4f28-a1d3-670e29c8f5a1
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large cn OR that includes (cn;lang-en=olsubtypelang)
        2. Search a large cn OR naming olsubtypelang as a plain cn value
    :expectedresults:
        1. The lang-en user is returned along with the plain matches
        2. The lang-en user is returned (base-type components match
           subtyped values)
    """
    plain = [f'olalt{i:05d}' for i in range(240, 260)]
    filt = ('(|' + ''.join(f'(cn={v})' for v in plain)
            + '(cn;lang-en=olsubtypelang))')
    expected = sorted([user_uid(i) for i in range(240, 260)] + [user_uid(370)])
    assert search_uids(topo, filt) == expected
    values = plain + ['olsubtypelang']
    assert search_uids(topo, or_of('cn', values)) == expected


def test_or_acl_deny_attr_no_leak(topo, create_data):
    """Verify a user denied read on uid gets no entries from a large uid
    OR: every component is undefined without access, and the fast path
    must not leak matches past the ACL boundary (CVE-2022-1949 class)

    :id: f2b74e09-8ad5-4c31-96e7-d03b58f1c2a6
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Add an aci denying uid read/search to one user and bind as it
        2. Search a large uid OR of live values
        3. Assert parity of the result with the fast path disabled
    :expectedresults:
        1. Bind succeeds
        2. No entries are returned
        3. Results are identical with and without the fast path
    """
    suffix = Domain(topo.standalone, DEFAULT_SUFFIX)
    deny = ('(targetattr="uid")(version 3.0; acl "ol deny uid"; '
            'deny (read, search, compare)'
            f'(userdn="ldap:///{user_dn(1)}");)')
    suffix.add('aci', deny)
    conn = UserAccount(topo.standalone, user_dn(1)).bind(PW)
    try:
        filt = or_of('uid', create_data[100:160])
        entries = conn.search_s(DEFAULT_SUFFIX, ldap.SCOPE_SUBTREE, filt, ['1.1'])
        assert entries == []
        assert assert_parity(topo, conn, filt) == []
    finally:
        conn.unbind_s()
        suffix.remove('aci', deny)


def test_or_acl_multi_hit_denied_parity(topo, create_data):
    """Verify an entry whose two attribute values hit two components of
    the OR while its attribute is denied for the bound user behaves
    identically with and without the fast path (the hit loop must ignore
    denied components and fall back, never synthesize a verdict)

    :id: 07e3c1f8-65a9-4d02-bc84-91f5e2d70a35
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Deny uid read on the two-uid entry only (targetfilter scoped)
           for the bind user
        2. Search an OR naming both of its uid values plus live values
        3. Assert parity of the result with the fast path disabled
    :expectedresults:
        1. ACI is added
        2. The two-uid entry is not returned; the live users are
        3. Results are identical with and without the fast path
    """
    suffix = Domain(topo.standalone, DEFAULT_SUFFIX)
    deny = ('(targetattr="uid")(targetfilter="(cn=OL Multi)")'
            '(version 3.0; acl "ol deny multi"; '
            'deny (read, search, compare)'
            f'(userdn="ldap:///{user_dn(2)}");)')
    suffix.add('aci', deny)
    conn = UserAccount(topo.standalone, user_dn(2)).bind(PW)
    try:
        live = create_data[20:40]
        filt = or_of('uid', ['olmultia', 'olmultib'] + live)
        got = assert_parity(topo, conn, filt)
        assert f'uid=olmultia,{PEOPLE}'.lower() not in got
        for uid in live:
            assert f'uid={uid},{PEOPLE}'.lower() in got
    finally:
        conn.unbind_s()
        suffix.remove('aci', deny)


def test_or_acl_mixed_allowed_denied(topo, create_data):
    """Verify ticket 48275 semantics at fast-path scale: entries matching
    an accessible component of the OR are returned even though another
    component's attribute is denied, and entries matching only the denied
    component are not returned

    :id: 58c1a9d4-3f70-4e26-8b95-d217e60c4af8
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Deny employeeNumber read for a bind user
        2. Search a large uid OR that also names an existing
           employeeNumber value, as that user
        3. Assert parity of the result with the fast path disabled
    :expectedresults:
        1. ACI is added
        2. Exactly the uid matches are returned: the employeeNumber
           owner (not named by any uid component) is absent
        3. Results are identical with and without the fast path
    """
    suffix = Domain(topo.standalone, DEFAULT_SUFFIX)
    deny = ('(targetattr="employeeNumber")(version 3.0; acl "ol deny emp"; '
            'deny (read, search, compare)'
            f'(userdn="ldap:///{user_dn(3)}");)')
    suffix.add('aci', deny)
    conn = UserAccount(topo.standalone, user_dn(3)).bind(PW)
    try:
        live = create_data[200:240]
        filt = ('(|' + ''.join(f'(uid={v})' for v in live)
                + '(employeeNumber=olemp00350))')
        got = assert_parity(topo, conn, filt)
        assert f'uid={user_uid(350)},{PEOPLE}'.lower() not in got
        assert sorted(got) == sorted(
            f'uid={v},{PEOPLE}'.lower() for v in live)
    finally:
        conn.unbind_s()
        suffix.remove('aci', deny)


def test_not_of_or_complement(topo, create_data):
    """Verify NOT of a large OR returns the exact complement: a table
    miss must evaluate defined-false (-1) so the NOT can negate it, never
    undefined

    :id: 19f7d3c0-b485-4a62-9e17-c30d86f2e5b9
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search (&(objectClass=posixAccount)(!(|...20 live uids...)))
    :expectedresults:
        1. Exactly all posixAccount entries except the 20 are returned
    """
    named = create_data[60:80]
    filt = f'(&(objectClass=posixAccount)(!{or_of("uid", named)}))'
    expected = sorted((set(create_data) - set(named)) | {'olmultia'})
    assert search_uids(topo, filt) == expected


def test_not_of_or_denied_user(topo, create_data):
    """Verify NOT of a large OR evaluates to undefined, not to a match,
    when the bound user has no access to the OR's attribute

    :id: 62a84f1b-90dc-4753-a6e8-1f4c72d09b3e
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Deny uid read for a bind user
        2. Search (&(objectClass=posixAccount)(!(|...20 live uids...)))
           as that user
        3. Assert parity of the result with the fast path disabled
    :expectedresults:
        1. ACI is added
        2. No entries are returned (undefined components do not negate
           into matches)
        3. Results are identical with and without the fast path
    """
    suffix = Domain(topo.standalone, DEFAULT_SUFFIX)
    deny = ('(targetattr="uid")(version 3.0; acl "ol deny uid not"; '
            'deny (read, search, compare)'
            f'(userdn="ldap:///{user_dn(4)}");)')
    suffix.add('aci', deny)
    conn = UserAccount(topo.standalone, user_dn(4)).bind(PW)
    try:
        named = create_data[60:80]
        filt = f'(&(objectClass=posixAccount)(!{or_of("uid", named)}))'
        got = assert_parity(topo, conn, filt)
        assert got == []
    finally:
        conn.unbind_s()
        suffix.remove('aci', deny)


def test_or_cos_vattr_fallback(topo, create_data):
    """Verify a CoS-served attribute in a large OR still matches through
    its virtual values (the fast path declines types served by a virtual
    attribute provider) while an OR on an unrelated attribute keeps
    engaging

    :id: 47d92e6a-1b05-4f83-bc29-8e60d1f74c52
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Create a CoS pointer definition serving postalCode to People
        2. Search a large postalCode OR naming the virtual value
        3. Raise the log level and run a large uid OR
        4. Remove the CoS entries
    :expectedresults:
        1. CoS is set up
        2. All user entries are returned (virtual value matches)
        3. The engagement diagnostic is emitted (unrelated type engages)
        4. Cleanup succeeds
    """
    inst = topo.standalone
    template = CosTemplate(inst, f'cn=olcostemplate,{DEFAULT_SUFFIX}')
    template.create(properties={'cn': 'olcostemplate',
                                'postalCode': 'olvirtualzip'})
    definition = CosPointerDefinition(inst, f'cn=olcosdef,{PEOPLE}')
    definition.create(properties={
        'cn': 'olcosdef',
        'cosTemplateDn': f'cn=olcostemplate,{DEFAULT_SUFFIX}',
        'cosAttribute': 'postalCode default operational'})
    try:
        values = ['olvirtualzip'] + ghosts(20, prefix='olzip')
        # the CoS definition entry itself sits under People and receives
        # the virtual value too, but has no uid - compare uid-bearing hits
        entries = topo.standalone.search_s(PEOPLE, ldap.SCOPE_SUBTREE,
                                           or_of('postalCode', values), ['uid'])
        got = sorted(ensure_str(e.getValue('uid')) for e in entries
                     if e.getValue('uid'))
        expected = sorted(create_data + ['olmultia'])
        assert got == expected
        with backend_debug_log(topo):
            before = eng_count(topo)
            live = create_data[0:30]
            assert search_uids(topo, or_of('uid', live)) == sorted(live)
            assert eng_count(topo) > before
    finally:
        definition.delete()
        template.delete()


def test_or_dn_big_group_m_guard(topo, create_data):
    """Verify groups with more member values than the OR has components
    (the DN value-count guard declines the fast path per entry) still
    match exactly

    :id: 76e08b52-4dc9-4f17-a3b6-29c58d10e7f4
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search an OR of 20 member DNs that all appear in the big
           groups (200 members each) and in some small groups
    :expectedresults:
        1. Exactly the big groups and the covering small groups return
    """
    values = [user_dn(i) for i in range(20)]
    entries = topo.standalone.search_s(GROUPS_OU, ldap.SCOPE_SUBTREE,
                                       or_of('member', values), ['cn'])
    got = sorted(ensure_str(e.getValue('cn')) for e in entries)
    # users 0..19 live in small groups 0..6 (3 members each) and every big
    expected = sorted([f'olgroup{g:03d}' for g in range(7)]
                      + [f'olbig{g}' for g in range(BIG_GROUPS)])
    assert got == expected


def test_or_ldapsubentry(topo, create_data):
    """Verify a large OR does not return LDAP subentries unless the
    filter names objectclass=ldapsubentry (issue #5170's subentry
    regression class)

    :id: 3b61e8d7-52f0-4c94-b8a3-06d97c2e14f5
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large uid OR including the subentry's uid value
        2. Repeat with an (objectclass=ldapsubentry) component added
    :expectedresults:
        1. Only the regular users are returned
        2. The subentry is returned too
    """
    live = create_data[0:20]
    values = live + ['olsubentryuid']
    assert search_uids(topo, or_of('uid', values)) == sorted(live)
    filt = ('(|' + ''.join(f'(uid={v})' for v in values)
            + '(objectclass=ldapsubentry))')
    assert search_uids(topo, filt) == sorted(live + ['olsubentryuid'])


def test_or_unknown_attr_branch(topo, create_data):
    """Verify an attribute type unknown to the schema among the
    components leaves the other components' matches intact (RFC 4511:
    unknown assertions are undefined, not errors)

    :id: 88f04a2c-97d6-4be1-a5c8-3e19d20b6f47
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Search a large uid OR including (olnosuchattribute=x)
    :expectedresults:
        1. Exactly the named users are returned
    """
    live = create_data[130:160]
    filt = ('(|' + ''.join(f'(uid={v})' for v in live)
            + '(olnosuchattribute=x))')
    assert search_uids(topo, filt) == sorted(live)


def test_or_below_threshold_and_toggle(topo, create_data):
    """Verify the fast path stays out of small ORs and honors the
    nsslapd-enable-or-filter-lookup switch, with identical results

    :id: 90b5c7e2-64af-4d18-92e0-7c3f5a8d1b06
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Raise the log level; search a 10-component uid OR
        2. Search a 40-component uid OR with the switch off
        3. Search the same OR with the switch back on
    :expectedresults:
        1. Exact results, no engagement diagnostic
        2. Exact results, no engagement diagnostic
        3. Exact results, the diagnostic is emitted
    """
    small = create_data[0:10]
    big = create_data[310:350]
    with backend_debug_log(topo):
        before = eng_count(topo)
        assert search_uids(topo, or_of('uid', small)) == sorted(small)
        assert eng_count(topo) == before
        with or_lookup_disabled(topo):
            before = eng_count(topo)
            assert search_uids(topo, or_of('uid', big)) == sorted(big)
            assert eng_count(topo) == before
        before = eng_count(topo)
        assert search_uids(topo, or_of('uid', big)) == sorted(big)
        assert eng_count(topo) > before


def test_or_vlv_sort_parity(topo, create_data):
    """Verify a large OR under server-side sort plus VLV behaves
    identically with and without the fast path, for the Directory Manager
    and for a user denied read on the attribute (VLV distinguishes
    ACL-undefined entries from plain non-matches)

    :id: e5a9d013-7fc2-4368-9b04-d61e82c7f0a9
    :setup: Standalone instance with 400 users, groups, and a subentry
    :steps:
        1. Run the OR with SSS(uid)+VLV controls as Directory Manager,
           asserting parity with the fast path off
        2. Deny uid read for a bind user and repeat as that user
    :expectedresults:
        1. Identical outcome with and without the fast path
        2. Identical outcome with and without the fast path
    """
    inst = topo.standalone
    live = create_data[100:140]
    filt = or_of('uid', live + ghosts(20))
    ctrls = [SSSRequestControl(criticality=True, ordering_rules=['uid']),
             VLVRequestControl(criticality=True, before_count=0,
                               after_count=9, offset=1, content_count=0)]
    assert_parity(topo, inst, filt, base=DEFAULT_SUFFIX,
                  serverctrls=ctrls)
    suffix = Domain(inst, DEFAULT_SUFFIX)
    deny = ('(targetattr="uid")(version 3.0; acl "ol deny uid vlv"; '
            'deny (read, search, compare)'
            f'(userdn="ldap:///{user_dn(5)}");)')
    suffix.add('aci', deny)
    conn = UserAccount(inst, user_dn(5)).bind(PW)
    try:
        assert_parity(topo, conn, filt, base=DEFAULT_SUFFIX,
                      serverctrls=ctrls)
    finally:
        conn.unbind_s()
        suffix.remove('aci', deny)


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
