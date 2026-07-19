# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

"""Interactions between large equality OR lookup and bounded costly reads.

The data is deliberately moderate but crosses the bounded-read floor: 4,200
entries share the broad substring and approximate keys, while an indexed AND
selects exactly 612 of them.  A 355-branch DN equality family then exercises
the per-entry lookup in the same operations.
"""

import ldap
import logging
import os
import pytest
import re

from contextlib import contextmanager
from ldap.controls import SimplePagedResultsControl
from ldap.filter import escape_filter_chars
from ldap.schema.models import AttributeType, ObjectClass
from lib389._constants import DEFAULT_SUFFIX
from lib389._mapped_object import DSLdapObject, DSLdapObjects
from lib389.backend import Backends
from lib389.idm.organizationalunit import OrganizationalUnits
from lib389.schema import OBJECT_MODEL_PARAMS, ObjectclassKind, Schema
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo


pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


TOTAL_ENTRIES = 4200
SELECTED_ENTRIES = 612
DN_BRANCHES = 355

TEST_OU = "LargeFilterInteraction"
TEST_BASE = f"ou={TEST_OU},{DEFAULT_SUFFIX}"

OUTER_A = "lfOuterA"
OUTER_B = "lfOuterB"
DN_ATTR = "lfDnValue"
SUBSTRING_ATTR = "lfSubstringValue"
APPROX_ATTR = "lfApproxValue"
FALLBACK_ATTR = "lfFallbackValue"
GUARD_ATTR = "lfGuardValue"
EXCLUDED_ONE = "lfExcludedOne"
EXCLUDED_TWO = "lfExcludedTwo"
AUX_OC = "lfInteractionAux"

OUTER_VALUE = "selected"
GUARD_VALUE = "guarded"
HIT_POSITIONS = (0, DN_BRANCHES // 2, DN_BRANCHES - 1)
HIT_COHORT_SIZE = SELECTED_ENTRIES // len(HIT_POSITIONS)
LIVE_DNS = tuple(
    f"cn=lf-live-target-{i},ou=References,{DEFAULT_SUFFIX}"
    for i in range(len(HIT_POSITIONS))
)

OR_LOOKUP_ATTR = "nsslapd-enable-or-filter-lookup"
ERRORLOG_LEVEL_BACKLDBM = 524288
LOOKUP_LOG_PATTERN = ".*OR filter equality lookup engaged.*"
LOOKUP_LOG_RE = re.compile(
    r"OR filter equality lookup engaged: (\d+) node\(s\), largest (\d+) branches"
)
CAP_LOG_PATTERN = ".*returned ALLIDS under read cap.*"


ATTRIBUTE_SPECS = (
    {"name": OUTER_A, "oid": "1.3.6.1.4.1.2312.999.2026.1",
     "desc": "large filter outer selector A",
     "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": OUTER_B, "oid": "1.3.6.1.4.1.2312.999.2026.2",
     "desc": "large filter outer selector B",
     "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": DN_ATTR, "oid": "1.3.6.1.4.1.2312.999.2026.3",
     "desc": "large filter DN equality value",
     "equality": "distinguishedNameMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.12"},
    {"name": SUBSTRING_ATTR, "oid": "1.3.6.1.4.1.2312.999.2026.4",
     "desc": "large filter substring value", "equality": "caseIgnoreMatch",
     "substr": "caseIgnoreSubstringsMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": APPROX_ATTR, "oid": "1.3.6.1.4.1.2312.999.2026.5",
     "desc": "large filter approximate value",
     "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": FALLBACK_ATTR, "oid": "1.3.6.1.4.1.2312.999.2026.6",
     "desc": "large filter absent fallback", "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": GUARD_ATTR, "oid": "1.3.6.1.4.1.2312.999.2026.7",
     "desc": "large filter fallback guard", "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": EXCLUDED_ONE, "oid": "1.3.6.1.4.1.2312.999.2026.8",
     "desc": "large filter unindexed presence sentinel one",
     "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
    {"name": EXCLUDED_TWO, "oid": "1.3.6.1.4.1.2312.999.2026.9",
     "desc": "large filter unindexed presence sentinel two",
     "equality": "caseIgnoreMatch",
     "syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
)

OBJECTCLASS_MAY = (
    OUTER_A, OUTER_B, DN_ATTR, SUBSTRING_ATTR, APPROX_ATTR, FALLBACK_ATTR,
    GUARD_ATTR, EXCLUDED_ONE, EXCLUDED_TWO,
)

INDEX_DEFINITIONS = (
    (OUTER_A, ["eq"]),
    (OUTER_B, ["eq"]),
    (DN_ATTR, ["eq"]),
    (SUBSTRING_ATTR, ["eq", "sub"]),
    (APPROX_ATTR, ["eq", "approx"]),
)


class LargeFilterEntry(DSLdapObject):
    """One deterministic synthetic interaction entry."""

    def __init__(self, instance, dn=None):
        super(LargeFilterEntry, self).__init__(instance, dn)
        self._rdn_attribute = "uid"
        self._must_attributes = ["uid", "cn", "sn"]
        self._create_objectclasses = [
            "top", "person", "organizationalPerson", "inetOrgPerson", AUX_OC
        ]
        self._protected = False


class LargeFilterEntries(DSLdapObjects):
    """Collection used to create interaction entries through lib389."""

    def __init__(self, instance, basedn):
        super(LargeFilterEntries, self).__init__(instance)
        self._objectclasses = [AUX_OC]
        self._filterattrs = ["uid"]
        self._childobject = LargeFilterEntry
        self._basedn = basedn


def entry_uid(index):
    return f"lf-interaction-{index:05d}"


def entry_dn(index):
    return f"uid={entry_uid(index)},{TEST_BASE}"


def ghost_dn(index):
    return f"cn=lf-ghost-{index:04d},ou=References,{DEFAULT_SUFFIX}"


def restore_single_value(obj, attr, old_value):
    """Restore both a former value and a former absent attribute."""
    if old_value is None:
        obj.remove_all(attr)
    else:
        obj.replace(attr, old_value)


@contextmanager
def backend_debug(inst):
    """Enable the backend diagnostic bit while preserving every other bit."""
    attr = "nsslapd-errorlog-level"
    old_value = inst.config.get_attr_val_utf8(attr)
    new_value = int(old_value or "0") | ERRORLOG_LEVEL_BACKLDBM
    inst.config.replace(attr, str(new_value))
    try:
        yield
    finally:
        restore_single_value(inst.config, attr, old_value)


@contextmanager
def lookup_disabled(inst):
    """Disable the equality lookup dynamically and restore exact state."""
    old_value = inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR)
    inst.config.replace(OR_LOOKUP_ATTR, "off")
    try:
        yield
    finally:
        restore_single_value(inst.config, OR_LOOKUP_ATTR, old_value)


def lookup_summaries(inst):
    """Return all stable equality-lookup summary ``(nodes, largest)`` pairs."""
    summaries = []
    for line in inst.ds_error_log.match(LOOKUP_LOG_PATTERN):
        match = LOOKUP_LOG_RE.search(line)
        assert match is not None
        summaries.append((int(match.group(1)), int(match.group(2))))
    return summaries


def cap_log_count(inst):
    return len(inst.ds_error_log.match(CAP_LOG_PATTERN))


def assert_new_dn_family(inst, before):
    """Assert the new summary includes 355 branches, not a node count.

    Ordinary subtree searches may build both executed and intended private
    filter duplicates, so the stable node count can legitimately be doubled.
    """
    new_summaries = lookup_summaries(inst)[before:]
    assert new_summaries
    assert any(largest == DN_BRANCHES for _, largest in new_summaries)


def search_dns(inst, filterstr, base=TEST_BASE, scope=ldap.SCOPE_SUBTREE):
    """Run a complete search and return the LDAP result type and exact DNs."""
    msgid = inst.search_ext(base, scope, filterstr, ["1.1"])
    result_type, result_data, _, _ = inst.result3(msgid)
    dns = sorted(ensure_str(dn).lower() for dn, _ in result_data if dn)
    return result_type, dns


def dn_or(assertions):
    return "(|%s)" % "".join(
        f"({DN_ATTR}={escape_filter_chars(value)})" for value in assertions
    )


def miss_assertions():
    return [ghost_dn(i) for i in range(DN_BRANCHES)]


def hit_assertions(position):
    """Put the sole live assertion at a requested table-walk position."""
    assertions = miss_assertions()
    assertions[position] = LIVE_DNS[HIT_POSITIONS.index(position)]
    return assertions


def combined_assertions():
    """Return 355 branches whose three live values cover all 612 selected."""
    assertions = miss_assertions()
    for position, value in zip(HIT_POSITIONS, LIVE_DNS):
        assertions[position] = value
    return assertions


def combined_filter(cost_component):
    """A 612-entry bound, a 355-branch lookup, and one costly component."""
    return (f"(&({OUTER_A}={OUTER_VALUE})"
            f"{dn_or(combined_assertions())}"
            f"{cost_component})")


@pytest.fixture(scope="module")
def interaction_data(topo):
    """Create schema, indexes, and all entries through live lib389 APIs."""
    inst = topo.standalone
    schema = Schema(inst)
    backend = Backends(inst).get("userRoot")
    old_lookup = inst.config.get_attr_val_utf8(OR_LOOKUP_ATTR)
    added_attrs = []
    added_indexes = []
    objectclass_added = False
    container = None

    try:
        inst.config.replace(OR_LOOKUP_ATTR, "on")

        for spec in ATTRIBUTE_SPECS:
            params = OBJECT_MODEL_PARAMS[AttributeType].copy()
            params.update({
                "names": (spec["name"],),
                "oid": spec["oid"],
                "desc": spec["desc"],
                "equality": spec["equality"],
                "substr": spec.get("substr"),
                "syntax": spec["syntax"],
                "single_value": 1,
                "x_origin": ("389-ds large filter tests",),
            })
            schema.add_attributetype(params)
            added_attrs.append(spec["name"])

        oc_params = OBJECT_MODEL_PARAMS[ObjectClass].copy()
        oc_params.update({
            "names": (AUX_OC,),
            "oid": "1.3.6.1.4.1.2312.999.2026.10",
            "desc": "auxiliary class for large filter interaction tests",
            "kind": ObjectclassKind.AUXILIARY.value,
            "sup": ("top",),
            "may": OBJECTCLASS_MAY,
            "x_origin": ("389-ds large filter tests",),
        })
        schema.add_objectclass(oc_params)
        objectclass_added = True

        for attr, index_types in INDEX_DEFINITIONS:
            backend.add_index(attr, index_types)
            added_indexes.append(attr)
        backend.reindex(attrs=added_indexes, wait=True)

        container = OrganizationalUnits(inst, DEFAULT_SUFFIX).create(
            properties={"ou": TEST_OU}
        )
        entries = LargeFilterEntries(inst, TEST_BASE)
        for i in range(TOTAL_ENTRIES):
            props = {
                "uid": entry_uid(i),
                "cn": f"Large Filter Common Xanadu Entry {i:05d}",
                "sn": f"Interaction{i:05d}",
                SUBSTRING_ATTR: f"Common Xanadu indexed value {i:05d}",
                APPROX_ATTR: "Xanadu",
            }
            if i < SELECTED_ENTRIES:
                props.update({
                    OUTER_A: OUTER_VALUE,
                    OUTER_B: OUTER_VALUE,
                    DN_ATTR: LIVE_DNS[i // HIT_COHORT_SIZE],
                    GUARD_ATTR: GUARD_VALUE,
                    # This makes C1's complex fallback false.  The second
                    # excluded attribute stays absent, and neither excluded
                    # attribute has a presence index.
                    EXCLUDED_ONE: "present",
                })
            entries.create(properties=props)

        yield {
            "selected_dns": sorted(
                entry_dn(i).lower() for i in range(SELECTED_ENTRIES)
            ),
            "hit_dns": {
                position: sorted(
                    entry_dn(i).lower()
                    for i in range(cohort * HIT_COHORT_SIZE,
                                   (cohort + 1) * HIT_COHORT_SIZE)
                )
                for cohort, position in enumerate(HIT_POSITIONS)
            },
            "backend": backend,
        }
    finally:
        try:
            if container is not None:
                container.delete(recursive=True)
        finally:
            try:
                for attr in reversed(added_indexes):
                    backend.del_index(attr)
            finally:
                try:
                    if objectclass_added:
                        schema.remove_objectclass(AUX_OC)
                    for attr in reversed(added_attrs):
                        schema.remove_attributetype(attr)
                finally:
                    restore_single_value(inst.config, OR_LOOKUP_ATTR,
                                         old_lookup)


def test_large_nested_dn_or_true_root_all_miss(topo, interaction_data):
    """A true-root all-miss lookup keeps the complex fallback exact.

    :id: 143f667f-75f9-44e7-a835-29cf1ea4a250
    :setup: Standalone instance with synthetic schema and 4,200 entries
    :steps:
        1. Search an indexed outer AND containing a 355-branch missing DN OR,
           a missing equality, and a guarded two-NOT fallback
        2. Repeat with equality lookup disabled dynamically
        3. Run a base-object health search
    :expectedresults:
        1. LDAP succeeds with no DNs and reports a 355-branch lookup family
        2. LDAP succeeds with the identical empty result
        3. LDAP succeeds and returns exactly the test container
    """
    inst = topo.standalone
    large_miss = dn_or(miss_assertions())
    filterstr = (
        f"(&({OUTER_A}={OUTER_VALUE})({OUTER_B}={OUTER_VALUE})"
        f"(|{large_miss}({FALLBACK_ATTR}=absent)"
        f"(&({GUARD_ATTR}={GUARD_VALUE})"
        f"(!({EXCLUDED_ONE}=*))(!({EXCLUDED_TWO}=*)))))"
    )

    with backend_debug(inst):
        before = len(lookup_summaries(inst))
        result_type, dns = search_dns(inst, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert dns == []
        assert_new_dn_family(inst, before)

        with lookup_disabled(inst):
            disabled_type, disabled_dns = search_dns(inst, filterstr)
        assert disabled_type == ldap.RES_SEARCH_RESULT
        assert disabled_dns == []

        health_type, health_dns = search_dns(
            inst, "(objectClass=*)", base=TEST_BASE,
            scope=ldap.SCOPE_BASE
        )
        assert health_type == ldap.RES_SEARCH_RESULT
        assert health_dns == [TEST_BASE.lower()]


@pytest.mark.parametrize(
    "position", HIT_POSITIONS,
    ids=["early", "middle", "late"],
)
def test_large_dn_or_early_middle_late_hits(topo, interaction_data, position):
    """The same normalized DN hit is exact at every table-walk position.

    :id: d563ea60-aacd-4949-a0ef-b2f29fd994aa
    :parametrized: yes
    :setup: Standalone instance with a 612-entry selected cohort
    :steps:
        1. Put the live DN assertion at the beginning, middle, or end of a
           355-branch family and search under the indexed outer AND
        2. Repeat with equality lookup disabled
    :expectedresults:
        1. LDAP succeeds with exactly the independently recorded 204 DNs and
           reports the existing 355-branch lookup summary
        2. The disabled path returns the same exact DNs
    """
    inst = topo.standalone
    expected = interaction_data["hit_dns"][position]
    filterstr = (f"(&({OUTER_A}={OUTER_VALUE})"
                 f"({OUTER_B}={OUTER_VALUE})"
                 f"{dn_or(hit_assertions(position))})")

    with backend_debug(inst):
        lookup_before = len(lookup_summaries(inst))
        result_type, dns = search_dns(inst, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert dns == expected
        assert_new_dn_family(inst, lookup_before)

        with lookup_disabled(inst):
            disabled_type, disabled_dns = search_dns(inst, filterstr)
        assert disabled_type == ldap.RES_SEARCH_RESULT
        assert disabled_dns == expected


@pytest.mark.parametrize(
    "cost_component,index_attr,override_rule",
    [
        (f"({SUBSTRING_ATTR}=*xanadu*)", SUBSTRING_ATTR,
         "limit=100000 type=sub flags=AND"),
        # Fine-grained scan-limit syntax does not accept type=approx.  A
        # flags-only rule on the approximate index is the supported explicit
        # equivalent and applies only to this custom attribute's AND reads.
        (f"({APPROX_ATTR}~=Xanadu)", APPROX_ATTR,
         "limit=100000 flags=AND"),
    ],
    ids=["substring", "approximate"],
)
def test_large_filter_lookup_and_substring_cap(
        topo, interaction_data, cost_component, index_attr, override_rule):
    """Lookup and bounded substring/approximate reads engage together.

    :id: ad85665d-9c66-4aa1-a52d-438eb3672692
    :parametrized: yes
    :setup: 4,200 broad postings, a 612-entry equality bound, and a 355 DN OR
    :steps:
        1. Search the combined filter with both mechanisms enabled
        2. Add a supported explicit per-index scan-limit override and repeat
        3. Remove the override, disable equality lookup, and repeat
    :expectedresults:
        1. LDAP succeeds with exactly 612 DNs and both diagnostics are emitted
        2. LDAP succeeds with the same DNs and no new cap diagnostic
        3. LDAP succeeds with the same DNs
    """
    inst = topo.standalone
    expected = interaction_data["selected_dns"]
    index = interaction_data["backend"].get_index(index_attr)
    assert index is not None
    filterstr = combined_filter(cost_component)

    with backend_debug(inst):
        lookup_before = len(lookup_summaries(inst))
        cap_before = cap_log_count(inst)
        result_type, dns = search_dns(inst, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert dns == expected
        assert_new_dn_family(inst, lookup_before)
        assert cap_log_count(inst) > cap_before

        rule_added = False
        try:
            index.add("nsIndexIDListScanLimit", override_rule)
            rule_added = True
            override_cap_before = cap_log_count(inst)
            override_type, override_dns = search_dns(inst, filterstr)
            assert override_type == ldap.RES_SEARCH_RESULT
            assert override_dns == expected
            assert cap_log_count(inst) == override_cap_before
        finally:
            if rule_added:
                index.remove("nsIndexIDListScanLimit", override_rule)

        with lookup_disabled(inst):
            disabled_type, disabled_dns = search_dns(inst, filterstr)
        assert disabled_type == ldap.RES_SEARCH_RESULT
        assert disabled_dns == expected


def test_lookup_engages_but_cap_declines_below_unsafe_or(
        topo, interaction_data):
    """An equality lookup may engage while an OR-ancestry cap declines.

    :id: 4cf11d97-4a79-42e7-b188-363646b5af12
    :setup: Standalone instance with the reusable interaction dataset
    :steps:
        1. Put the 355-branch DN family beside a substring-bearing AND under
           a root OR and run the search with backend diagnostics enabled
        2. Repeat with equality lookup disabled
    :expectedresults:
        1. LDAP succeeds with exactly 612 DNs, lookup reports 355 branches,
           and the bounded-read diagnostic does not increase
        2. LDAP succeeds with the identical exact DN set
    """
    inst = topo.standalone
    expected = interaction_data["selected_dns"]
    filterstr = (
        f"(|{dn_or(combined_assertions())}"
        f"(&({OUTER_A}={OUTER_VALUE})({OUTER_B}={OUTER_VALUE})"
        f"({SUBSTRING_ATTR}=*xanadu*)))"
    )

    with backend_debug(inst):
        lookup_before = len(lookup_summaries(inst))
        cap_before = cap_log_count(inst)
        result_type, dns = search_dns(inst, filterstr)
        assert result_type == ldap.RES_SEARCH_RESULT
        assert dns == expected
        assert_new_dn_family(inst, lookup_before)
        assert cap_log_count(inst) == cap_before

        with lookup_disabled(inst):
            disabled_type, disabled_dns = search_dns(inst, filterstr)
        assert disabled_type == ldap.RES_SEARCH_RESULT
        assert disabled_dns == expected


def test_complete_paging_with_lookup_and_cap(topo, interaction_data):
    """Complete paging preserves the combined path's exact DN set.

    :id: 9e47b6aa-8954-452f-90cd-b7c3a694aa67
    :setup: Standalone instance with the reusable interaction dataset
    :steps:
        1. Page through the combined DN-lookup and bounded-substring filter
           with a page size of 97 until the server returns an empty cookie
    :expectedresults:
        1. Every page succeeds, both diagnostics occur, and the union of all
           pages is exactly the independently recorded 612 DNs
    """
    inst = topo.standalone
    expected = interaction_data["selected_dns"]
    filterstr = combined_filter(f"({SUBSTRING_ATTR}=*xanadu*)")
    request = SimplePagedResultsControl(True, size=97, cookie="")
    collected = []
    pages = 0

    with backend_debug(inst):
        lookup_before = len(lookup_summaries(inst))
        cap_before = cap_log_count(inst)
        while True:
            msgid = inst.search_ext(
                TEST_BASE, ldap.SCOPE_SUBTREE, filterstr, ["1.1"],
                serverctrls=[request]
            )
            result_type, result_data, _, response_controls = inst.result3(msgid)
            assert result_type == ldap.RES_SEARCH_RESULT
            collected.extend(
                ensure_str(dn).lower() for dn, _ in result_data if dn
            )
            pages += 1

            paged_controls = [
                control for control in response_controls
                if control.controlType == SimplePagedResultsControl.controlType
            ]
            assert paged_controls
            if not paged_controls[0].cookie:
                break
            request.cookie = paged_controls[0].cookie

        assert pages >= 7
        assert sorted(collected) == expected
        assert_new_dn_family(inst, lookup_before)
        assert cap_log_count(inst) > cap_before


if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
