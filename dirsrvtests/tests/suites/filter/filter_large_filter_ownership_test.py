# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2026 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

"""Focused ownership reproducer for a NOT-first candidate list.

The indexed range is populated and emptied through ordinary LDAP modifies so
the final GE read returns an empty candidate list after the leading NOT path
has installed its initial ALLIDS/complement state.
"""

import ldap
import os
import pytest

from test389.topologies import topology_st as topo

from .filter_large_filter_support import (
    NOT_FIRST_EMPTY_RANGE_FILTER,
    OWNERSHIP_TEST_BASE,
    ownership_workload,
    search_dns,
)


pytestmark = pytest.mark.tier1


@pytest.fixture(scope="module")
def ownership_data(topo):
    """Create the indexed range, populate it once, then remove its value."""
    with ownership_workload(topo.standalone):
        yield


def test_not_first_empty_range_ownership_and_health(topo, ownership_data):
    """A NOT-first empty-range AND returns exactly and leaves DS healthy.

    :id: 119d7c3b-0f3b-4841-a83a-782010559bc6
    :setup: Standalone instance with 16 people and an emptied integer index
    :steps:
        1. Search a NOT-first AND of an absent uid, objectClass=person, and
           the empty indexed range
        2. Run a base-object health search on the test container
    :expectedresults:
        1. LDAP succeeds with the exact empty result
        2. LDAP succeeds and returns exactly the container DN
    """
    inst = topo.standalone

    result_type, dns = search_dns(
        inst, NOT_FIRST_EMPTY_RANGE_FILTER,
        base=OWNERSHIP_TEST_BASE, scope=ldap.SCOPE_SUBTREE
    )
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == []

    health_type, health_dns = search_dns(
        inst, "(objectClass=*)",
        base=OWNERSHIP_TEST_BASE, scope=ldap.SCOPE_BASE
    )
    assert health_type == ldap.RES_SEARCH_RESULT
    assert health_dns == [OWNERSHIP_TEST_BASE.lower()]


if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
