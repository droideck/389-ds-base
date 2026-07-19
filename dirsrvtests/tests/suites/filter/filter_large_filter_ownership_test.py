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
import logging
import os
import pytest

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


TEST_OU = "LargeFilterOwnership"
TEST_BASE = f"ou={TEST_OU},{DEFAULT_SUFFIX}"
EMPTY_RANGE_ATTR = "lfEmptyRange"
AUX_OC = "lfOwnershipAux"
ENTRY_COUNT = 16

class OwnershipEntry(DSLdapObject):
    """One person used by the ownership reproducer."""

    def __init__(self, instance, dn=None):
        super(OwnershipEntry, self).__init__(instance, dn)
        self._rdn_attribute = "uid"
        self._must_attributes = ["uid", "cn", "sn"]
        self._create_objectclasses = [
            "top", "person", "organizationalPerson", "inetOrgPerson", AUX_OC
        ]
        self._protected = False


class OwnershipEntries(DSLdapObjects):
    """Collection used to create ownership entries through lib389."""

    def __init__(self, instance, basedn):
        super(OwnershipEntries, self).__init__(instance)
        self._objectclasses = [AUX_OC]
        self._filterattrs = ["uid"]
        self._childobject = OwnershipEntry
        self._basedn = basedn


def search_dns(inst, base, scope, filterstr):
    """Return the LDAP result type and complete normalized DN set."""
    msgid = inst.search_ext(base, scope, filterstr, ["1.1"])
    result_type, result_data, _, _ = inst.result3(msgid)
    dns = sorted(ensure_str(dn).lower() for dn, _ in result_data if dn)
    return result_type, dns


@pytest.fixture(scope="module")
def ownership_data(topo):
    """Create the indexed range, populate it once, then remove its value."""
    inst = topo.standalone
    schema = Schema(inst)
    backend = Backends(inst).get("userRoot")
    attr_added = False
    objectclass_added = False
    index_added = False
    container = None

    try:
        attr_params = OBJECT_MODEL_PARAMS[AttributeType].copy()
        attr_params.update({
            "names": (EMPTY_RANGE_ATTR,),
            "oid": "1.3.6.1.4.1.2312.999.2026.20",
            "desc": "emptied indexed range for NOT-first ownership test",
            "equality": "integerMatch",
            "ordering": "integerOrderingMatch",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.27",
            "single_value": 1,
            "x_origin": ("389-ds large filter tests",),
        })
        schema.add_attributetype(attr_params)
        attr_added = True

        oc_params = OBJECT_MODEL_PARAMS[ObjectClass].copy()
        oc_params.update({
            "names": (AUX_OC,),
            "oid": "1.3.6.1.4.1.2312.999.2026.21",
            "desc": "auxiliary class for NOT-first ownership test",
            "kind": ObjectclassKind.AUXILIARY.value,
            "sup": ("top",),
            "may": (EMPTY_RANGE_ATTR,),
            "x_origin": ("389-ds large filter tests",),
        })
        schema.add_objectclass(oc_params)
        objectclass_added = True
        backend.add_index(
            EMPTY_RANGE_ATTR, ["eq"],
            matching_rules=["integerOrderingMatch"]
        )
        index_added = True
        backend.reindex(attrs=[EMPTY_RANGE_ATTR], wait=True)

        container = OrganizationalUnits(inst, DEFAULT_SUFFIX).create(
            properties={"ou": TEST_OU}
        )
        entries = OwnershipEntries(inst, TEST_BASE)
        created = []
        for i in range(ENTRY_COUNT):
            uid = f"lf-ownership-{i:03d}"
            created.append(entries.create(properties={
                "uid": uid,
                "cn": f"Large Filter Ownership {i:03d}",
                "sn": f"Ownership{i:03d}",
            }))

        # Do not create this state in LDIF or by touching the database.  The
        # add makes the equality/range DB real; the delete leaves a known
        # empty indexed range for the reproducing search.
        created[0].add(EMPTY_RANGE_ATTR, "0")
        created[0].remove_all(EMPTY_RANGE_ATTR)

        preflight_type, preflight_dns = search_dns(
            inst, TEST_BASE, ldap.SCOPE_SUBTREE,
            f"({EMPTY_RANGE_ATTR}>=0)"
        )
        assert preflight_type == ldap.RES_SEARCH_RESULT
        assert preflight_dns == []

        yield
    finally:
        try:
            if container is not None:
                container.delete(recursive=True)
        finally:
            try:
                if index_added:
                    backend.del_index(EMPTY_RANGE_ATTR)
            finally:
                if objectclass_added:
                    schema.remove_objectclass(AUX_OC)
                if attr_added:
                    schema.remove_attributetype(EMPTY_RANGE_ATTR)


def test_not_first_empty_range_ownership_and_health(topo, ownership_data):
    """A NOT-first AND with an empty indexed range stays owned and healthy.

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
    filterstr = (
        f"(&(!(uid=lf-ownership-absent))(objectClass=person)"
        f"({EMPTY_RANGE_ATTR}>=0))"
    )

    result_type, dns = search_dns(
        inst, TEST_BASE, ldap.SCOPE_SUBTREE, filterstr
    )
    assert result_type == ldap.RES_SEARCH_RESULT
    assert dns == []

    health_type, health_dns = search_dns(
        inst, TEST_BASE, ldap.SCOPE_BASE, "(objectClass=*)"
    )
    assert health_type == ldap.RES_SEARCH_RESULT
    assert health_dns == [TEST_BASE.lower()]


if __name__ == "__main__":
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
