"""Authoritative revision roles and production-equivalence relationships.

The installed RPM source revision and the server-production revision are
deliberately separate identities.  A study-only commit may be the source of an
RPM while remaining production-equivalent to the last commit that changed
server behavior.  Artifact provenance must always retain the former; mechanism
and acceptance logic may use the latter only for aliases declared here.
"""

from __future__ import annotations

from typing import Any, Optional


REVISION_ROLES = {
    "pre-series": "6e1e933745313622593d943e983ff710de8db732",
    "modern-harness": "72f489233e90688a18c11a3c71d42cc812e13fe9",
    "bounded-feature": "fde13723bfa682526bb472baa91ff0d5f1b4af47",
    "combined-diagnostic": "7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6",
    "dynamic-list-fix": "038b8f58a305c1650ab0523a9d2658aabbc9848b",
    "all-family-fix": "09f92bfbe67f8769277e4e4ae5fef5cf069d71f4",
    "largest-family-fix": "9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a",
    "lifecycle-tests": "014fe6a3793898b508a6d6de9893937a7e1aa49d",
    "asan-harness": "f29a3c6806c81d1cc0e5b77520b3b8d4b3d5d873",
    "final": "e0161d0e61d0cdef22175418f0d4a1e126216a86",
    "final-study-tip": "fa3987d01209bc60f599dda70ad4e5734ebc78c2",
    "historical": "dd7d0db1a45a417f9c1546002758c25ca6e120d6",
}

FINAL_PRODUCTION_REVISION = REVISION_ROLES["final"]
FINAL_STUDY_TIP_REVISION = REVISION_ROLES["final-study-tip"]

# Git proves that FINAL_STUDY_TIP_REVISION adds only
# performance/large-filter-study/** on top of FINAL_PRODUCTION_REVISION.  Keep
# this map intentionally closed: an input artifact cannot declare an arbitrary
# source revision equivalent to a known production revision.
PRODUCTION_EQUIVALENT_REVISIONS = {
    FINAL_STUDY_TIP_REVISION: FINAL_PRODUCTION_REVISION,
}

PRODUCTION_EQUIVALENCE_BASIS = {
    FINAL_STUDY_TIP_REVISION: (
        "git diff e0161d0e..fa3987d0 is confined to "
        "performance/large-filter-study; installed RPM source identity remains "
        "fa3987d0 and observed executable/runtime hashes still govern pooling"
    ),
}


def production_equivalent_revision(revision: str) -> str:
    """Return the declared server-production revision for ``revision``."""
    normalized = revision.casefold()
    return PRODUCTION_EQUIVALENT_REVISIONS.get(normalized, normalized)


def analysis_revision_role(revision: str) -> Optional[str]:
    """Return the semantic study role without rewriting source provenance."""
    production = production_equivalent_revision(revision)
    for role, candidate in REVISION_ROLES.items():
        if role == "final-study-tip":
            continue
        if candidate == production:
            return role
    return None


def declared_production_equivalence(revision: str) -> Optional[dict[str, Any]]:
    """Describe a known source/production alias for artifact manifests."""
    source = revision.casefold()
    production = PRODUCTION_EQUIVALENT_REVISIONS.get(source)
    if production is None:
        return None
    return {
        "source_revision": source,
        "production_equivalent_revision": production,
        "basis": PRODUCTION_EQUIVALENCE_BASIS[source],
        "source_identity_preserved": True,
    }
