# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

"""Strict feature contracts for combined large-filter optimisations.

The result-only coverage in ``filter_large_filter_interaction_test.py`` is
valid on a clean server.  These companion tests require both the large
equality-OR lookup and bounded costly-component reads, including their stable
backend diagnostics.  They intentionally fail when those patches are absent.
"""

import ldap
import logging
import os
import pytest
import re

from contextlib import contextmanager
from ldap.controls import SimplePagedResultsControl
from lib389.utils import ensure_str
from test389.topologies import topology_st as topo

from .filter_large_filter_support import (
    APPROX_ATTR,
    DN_BRANCHES,
    OUTER_A,
    OUTER_B,
    OUTER_VALUE,
    SUBSTRING_ATTR,
    TEST_BASE,
    combined_assertions,
    combined_filter,
    dn_or,
    interaction_data,
    lookup_disabled,
    search_dns,
)


pytestmark = pytest.mark.tier1

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


ERRORLOG_LEVEL_BACKLDBM = 524288
LOOKUP_LOG_PATTERN = ".*OR filter equality lookup engaged.*"
LOOKUP_LOG_RE = re.compile(
    r"OR filter equality lookup engaged: (\d+) node\(s\), largest (\d+) branches"
)
CAP_LOG_PATTERN = ".*returned ALLIDS under read cap.*"


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


def lookup_summaries(inst):
    """Return all stable equality-lookup ``(nodes, largest)`` summaries."""
    summaries = []
    for line in inst.ds_error_log.match(LOOKUP_LOG_PATTERN):
        match = LOOKUP_LOG_RE.search(line)
        assert match is not None
        summaries.append((int(match.group(1)), int(match.group(2))))
    return summaries


def cap_log_count(inst):
    """Return the number of bounded-read diagnostics in the error log."""
    return len(inst.ds_error_log.match(CAP_LOG_PATTERN))


def assert_new_dn_family(inst, before):
    """Require a new lookup summary containing the 355-branch DN family."""
    new_summaries = lookup_summaries(inst)[before:]
    assert new_summaries
    assert any(largest == DN_BRANCHES for _, largest in new_summaries)


@pytest.fixture(scope="module")
def feature_data(interaction_data):
    """Expose the shared dataset without assuming either patch is present."""
    return interaction_data


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
def test_feature_combined_lookup_and_bounded_cap(
        topo, feature_data, cost_component, index_attr, override_rule):
    """Require lookup and bounded substring/approximate reads together.

    :id: 59f056a9-4fb5-415f-9a4e-64cb2742b055
    :parametrized: yes
    :setup: Both filter patches, broad postings, and a 355-branch DN OR
    :steps:
        1. Search the combined filter with backend diagnostics enabled
        2. Add an explicit per-index scan-limit override and repeat
        3. Remove the override, disable equality lookup, and repeat
    :expectedresults:
        1. LDAP returns exactly 612 DNs and both diagnostics are emitted
        2. LDAP returns the same DNs without a new cap diagnostic
        3. LDAP returns the same DNs while lookup is disabled
    """
    inst = topo.standalone
    expected = feature_data["selected_dns"]
    index = feature_data["backend"].get_index(index_attr)
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


def test_feature_lookup_engages_while_unsafe_or_declines_cap(
        topo, feature_data):
    """Require lookup engagement and cap decline below unsafe OR ancestry.

    :id: deea1d1d-9933-4e21-a422-d04ee7bd92d4
    :setup: Both filter patches and the shared large-filter dataset
    :steps:
        1. Put the DN family beside a substring-bearing AND under a root OR
        2. Search with backend diagnostics enabled
        3. Repeat with equality lookup disabled
    :expectedresults:
        1. The filter is constructed with unsafe OR ancestry for the cap
        2. LDAP returns exactly 612 DNs, lookup reports 355 branches, and no
           bounded-read diagnostic is emitted
        3. LDAP returns the identical exact DN set
    """
    inst = topo.standalone
    expected = feature_data["selected_dns"]
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


def test_feature_complete_paging_with_lookup_and_cap(
        topo, feature_data):
    """Require both diagnostics during complete paged-results traversal.

    :id: 87f13bae-a441-4ca6-b84a-cee9004fc306
    :setup: Both filter patches and the shared large-filter dataset
    :steps:
        1. Page through the combined DN-lookup and bounded-substring filter
           with a page size of 97 until the server returns an empty cookie
    :expectedresults:
        1. Every page succeeds, both diagnostics occur, and the union of all
           pages is exactly the independently recorded 612 DNs
    """
    inst = topo.standalone
    expected = feature_data["selected_dns"]
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
