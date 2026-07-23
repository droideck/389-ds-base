"""Synthetic contract tests for the result merger."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Optional, Sequence


STUDY_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(STUDY_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDY_ROOT))

from study.merge import (  # noqa: E402
    MergeError,
    EXPECTED_SCHEMA_SEMANTIC_CONTRACT,
    _artifact_production_commit,
    _rpm_proved,
    _toggle_pair,
    _validate_backend_runtime_closure,
    assess_matrix_completion,
    assess_schedules,
    build_openldap_context,
    build_acceptance_gate_results,
    build_scaling_tables,
    canonical_json_bytes,
    load_bundle,
    merge_result_directories,
    nearest_rank,
)
from study.revisions import (  # noqa: E402
    analysis_revision_role,
    production_equivalent_revision,
)
from study.run_study import (  # noqa: E402
    PERF_EVENTS,
    perf_collection_identity,
    profile_collection_identity,
)


COMMIT_FINAL = "e0161d0e61d0cdef22175418f0d4a1e126216a86"
COMMIT_STUDY_TIP = "fa3987d01209bc60f599dda70ad4e5734ebc78c2"
COMMIT_BOUNDED = "fde13723bfa682526bb472baa91ff0d5f1b4af47"
COMMIT_09 = "09f92bfbe67f8769277e4e4ae5fef5cf069d71f4"
COMMIT_9C = "9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a"


EMPTY_DN_SHA256 = hashlib.sha256(b"").hexdigest()
FILTER_SHA256 = hashlib.sha256(b"(uid=absent)\n").hexdigest()
SCHEMA_389_SHA256 = hashlib.sha256(b"389 schema\n").hexdigest()
ALT_SCHEMA_389_SHA256 = hashlib.sha256(b"changed 389 schema\n").hexdigest()
SCHEMA_OPENLDAP_SHA256 = hashlib.sha256(b"openldap schema\n").hexdigest()
DATA_SHA256 = hashlib.sha256(b"dn: dc=example,dc=com\n\n").hexdigest()
PEOPLE_IMPORT_SHA256 = hashlib.sha256(
    b"synthetic sorted people DN oracle"
).hexdigest()
PRINCIPAL_IMPORT_SHA256 = hashlib.sha256(
    b"synthetic sorted principal-cohort DN oracle"
).hexdigest()
INDEX_DOCUMENT = {
    "servers": {
        "389ds": {"baseline": {"uid": ["eq"]}},
        "openldap": {"baseline": {"uid": ["eq"]}},
    },
    "variants": {
        "baseline-no-presence": {"add": {}, "remove": {}},
    },
}
INDEX_BYTES = (
    json.dumps(INDEX_DOCUMENT, indent=2, sort_keys=True) + "\n"
).encode("utf-8")
INDEX_SHA256 = hashlib.sha256(INDEX_BYTES).hexdigest()
INDEX_INTENT_SHA256 = hashlib.sha256(canonical_json_bytes({
    "uid": ["eq"],
})).hexdigest()


def synthetic_backend_closure(
        variant: str, executable_sha: str) -> dict[str, Any]:
    modules = [{
        "path": "/usr/lib64/dirsrv/plugins/libback-ldbm.so",
        "mapped_paths": ["/usr/lib64/dirsrv/plugins/libback-ldbm.so"],
        "sha256": hashlib.sha256(
            f"{variant}:libback-ldbm".encode("utf-8")
        ).hexdigest(),
        "rpm_owner": "389-ds-base-libs-0:3.0-1.fc43.x86_64",
        "rpm_owner_query_returncode": 0,
        "roles": ["389ds-ldbm-backend"],
    }, {
        "path": "/usr/lib64/liblmdb.so.0",
        "mapped_paths": ["/usr/lib64/liblmdb.so.0"],
        "sha256": hashlib.sha256(
            f"{variant}:liblmdb".encode("utf-8")
        ).hexdigest(),
        "rpm_owner": "lmdb-libs-0:0.9.33-2.fc43.x86_64",
        "rpm_owner_query_returncode": 0,
        "roles": ["database-engine"],
    }]
    material = {
        "format_version": 1,
        "server": "389ds",
        "backend": "mdb",
        "required_roles": ["389ds-ldbm-backend", "database-engine"],
        "live_executable_sha256": executable_sha,
        "modules": sorted(({
            "sha256": module["sha256"],
            "roles": module["roles"],
        } for module in modules), key=lambda module: (
            module["roles"], module["sha256"],
        )),
    }
    return {
        "format_version": 1,
        "status": "observed",
        "source": "linux-proc-pid-maps",
        "pid": 1234,
        "maps_path": "/proc/1234/maps",
        "server": "389ds",
        "backend": "mdb",
        "live_executable": {
            "path": "/usr/bin/ns-slapd",
            "sha256": executable_sha,
            "proc_exe_path": "/proc/1234/exe",
        },
        "required_roles": ["389ds-ldbm-backend", "database-engine"],
        "modules": modules,
        "static_backend_evidence": None,
        "identity_material": material,
        "identity_sha256": hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def synthetic_openldap_static_backend_closure(
        executable_sha: str) -> dict[str, Any]:
    pid = 4321
    executable_path = "/usr/sbin/slapd"
    owner = "openldap-servers-0:2.6.13-1.fc42.x86_64"
    raw_inventory = (
        "@(#) $OpenLDAP: slapd 2.6.13 $\n"
        "Included static backends:\n"
        "    config\n"
        "    ldif\n"
        "    monitor\n"
        "    mdb\n"
    )
    roles = ["database-engine", "openldap-db-backend"]
    modules = [{
        "path": executable_path,
        "mapped_paths": [f"/proc/{pid}/exe"],
        "sha256": executable_sha,
        "rpm_owner": owner,
        "rpm_owner_query_returncode": 0,
        "roles": list(roles),
    }]
    material = {
        "format_version": 1,
        "server": "openldap",
        "backend": "mdb",
        "required_roles": list(roles),
        "live_executable_sha256": executable_sha,
        "modules": [{
            "sha256": executable_sha,
            "roles": list(roles),
        }],
    }
    identity_sha = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return {
        "format_version": 1,
        "status": "observed",
        "source": "linux-proc-pid-maps",
        "pid": pid,
        "maps_path": f"/proc/{pid}/maps",
        "server": "openldap",
        "backend": "mdb",
        "live_executable": {
            "path": executable_path,
            "sha256": executable_sha,
            "proc_exe_path": f"/proc/{pid}/exe",
        },
        "required_roles": list(roles),
        "modules": modules,
        "static_backend_evidence": {
            "status": "observed",
            "source": "slapd--VVV",
            "live_executable": executable_path,
            "included_static_backends": ["config", "ldif", "mdb", "monitor"],
            "selected_backend": "mdb",
            "assigned_roles": list(roles),
            "inventory_sha256": hashlib.sha256(
                raw_inventory.encode("utf-8")
            ).hexdigest(),
            "raw": raw_inventory,
        },
        "identity_material": material,
        "identity_sha256": identity_sha,
    }
def synthetic_runtime_closure(
        executable_sha: str, variant: str) -> tuple[dict[str, Any], str]:
    material = {
        "format_version": 1,
        "artifacts": [{
            "sha256": hashlib.sha256(
                f"linked-library:{variant}".encode("utf-8")
            ).hexdigest(),
            "roles": ["direct-linked-library"],
        }, {
            "sha256": executable_sha,
            "roles": ["server-executable"],
        }],
    }
    material["artifacts"].sort(key=lambda item: (
        item["roles"], item["sha256"],
    ))
    return material, hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def synthetic_harness_identity(variant: str = "committed-study") -> dict[str, Any]:
    files = {
        "artifact-manifest.json": hashlib.sha256(
            f"artifact-manifest:{variant}".encode("utf-8")
        ).hexdigest(),
        "study/run_study.py": hashlib.sha256(
            f"run-study:{variant}".encode("utf-8")
        ).hexdigest(),
    }
    return {
        "format_version": 1,
        "content_sha256": hashlib.sha256(canonical_json_bytes({
            "format_version": 1,
            "files": files,
        })).hexdigest(),
        "files": files,
        "git_head": "1" * 40,
        "git_tree": "2" * 40,
        "git_status_porcelain": "",
        "git_study_tree_clean": True,
        "git_evidence_status": "observed",
        "git_scoped_path": "performance/large-filter-study",
    }


def synthetic_import_contracts() -> dict[str, Any]:
    return {
        "people": {
            "base_dn": "ou=people,dc=example,dc=com",
            "scope": "sub",
            "filter": "(objectClass=largeFilterStudyPerson)",
            "requested_attributes": ["1.1"],
            "expected_result_code": "LDAP_SUCCESS",
            "expected_count": 100_000,
            "expected_sha256": PEOPLE_IMPORT_SHA256,
        },
        "principal_outer_cohort": {
            "base_dn": "ou=people,dc=example,dc=com",
            "scope": "sub",
            "filter": "(&(sString1=asd)(sString2=ff)(sString3=vv))",
            "requested_attributes": ["1.1"],
            "expected_result_code": "LDAP_SUCCESS",
            "expected_count": 612,
            "expected_sha256": PRINCIPAL_IMPORT_SHA256,
        },
    }


def synthetic_import_verification() -> dict[str, Any]:
    oracles: dict[str, Any] = {}
    for oracle_id, contract in synthetic_import_contracts().items():
        oracles[oracle_id] = {
            "evidence_status": "observed",
            "oracle_id": oracle_id,
            "base_dn": contract["base_dn"],
            "scope": contract["scope"],
            "filter": contract["filter"],
            "requested_attributes": contract["requested_attributes"],
            "expected_result_code": "LDAP_SUCCESS",
            "expected_ldap_result_code": 0,
            "actual_ldap_result_code": 0,
            "expected_count": contract["expected_count"],
            "actual_count": contract["expected_count"],
            "expected_sha256": contract["expected_sha256"],
            "actual_sha256": contract["expected_sha256"],
            "passed": True,
        }
    return {
        "evidence_status": "observed",
        "passed": True,
        "oracles": oracles,
    }


def synthetic_lookup_mode_evidence(lookup_mode: str) -> dict[str, Any]:
    return {
        "attribute": "nsslapd-enable-or-filter-lookup",
        "requested": lookup_mode,
        "initial": lookup_mode,
        "actual_readback": lookup_mode,
        "passed": True,
        "evidence_status": "observed",
    }


def synthetic_background_referral_check_control() -> dict[str, Any]:
    bucket = 123
    boundary = (bucket + 1) * 3600
    deadline = boundary - 5
    established = deadline - 300
    policy = {
        "clock": "CLOCK_MONOTONIC",
        "interval_anchor": "kernel-monotonic-epoch",
        "requested_seconds": 3600,
        "safety_margin_seconds": 5.0,
        "collection_policy": "fail-before-or-at-deadline",
    }
    return {
        "attribute": "nsslapd-referral-check-period",
        "initial": "300",
        "requested_seconds": 3600,
        "pre_restart_readback": "3600",
        "post_restart_readback": "3600",
        "final_restart_applied": True,
        "clock": "CLOCK_MONOTONIC",
        "interval_anchor": "kernel-monotonic-epoch",
        "safety_margin_seconds": 5,
        "access_log_internal_operation_control": {
            "attribute": "nsslapd-accesslog-level",
            "initial": "256",
            "requested": 260,
            "pre_restart_readback": "260",
            "post_restart_readback": "260",
            "internal_operation_bit_enabled": True,
            "passed": True,
        },
        "post_restart_vattr_check_barrier": {
            "status": "observed-complete",
            "source_function": "vattr_check/vattr_check_thread",
            "delay_seconds": 3,
            "exact_filter": (
                "(&(objectclass=ldapsubentry)"
                "(|(objectclass=nsRoleDefinition)"
                "(objectclass=cosSuperDefinition)))"
            ),
            "paired_operation_count": 1,
            "start_line_count": 1,
            "completion_line_count": 1,
            "unmatched_start_count": 0,
            "stability_seconds": 1.0,
            "passed": True,
        },
        "barrier": {
            "status": "observed-complete",
            "paired_operation_count": 1,
            "start_line_count": 1,
            "completion_line_count": 1,
            "unmatched_referral_start_count": 0,
        },
        "barrier_covered_bucket": bucket,
        "quiet_window": {
            "bucket": bucket,
            "next_boundary_monotonic_seconds": boundary,
            "deadline_monotonic_seconds": deadline,
            "established_monotonic_seconds": established,
            "remaining_seconds": deadline - established,
            "policy": "fail-collection-before-or-at-deadline",
        },
        "policy_material": policy,
        "policy_sha256": hashlib.sha256(
            canonical_json_bytes(policy)
        ).hexdigest(),
        "evidence_status": "observed",
        "passed": True,
    }


def synthetic_index_build_evidence() -> dict[str, Any]:
    return {
        "evidence_status": "observed",
        "import": {
            "operation": "dsconf backend import userRoot <copied-data-ldif>",
            "returncode": 0,
            "stdout": "synthetic import complete",
            "stderr": "",
            "completed": True,
        },
        "reindex": {
            "operation": "dsconf backend index reindex --wait userRoot",
            "returncode": 0,
            "stdout": "synthetic reindex complete",
            "stderr": "",
            "completed": True,
            "waited_for_completion": True,
        },
        "passed": True,
    }


def synthetic_linked_libraries(
        runtime_closure_material: Mapping[str, Any]) -> dict[str, Any]:
    digests = [
        item["sha256"]
        for item in runtime_closure_material["artifacts"]
        if item["roles"] == ["direct-linked-library"]
    ]
    return {
        "status": "observed",
        "complete": True,
        "problems": [],
        "ldd_returncode": 0,
        "raw": "synthetic ldd output",
        "packages": [{
            "path": f"/usr/lib64/libsynthetic-{index}.so",
            "sha256": digest,
            "owner": "synthetic-libs-0:1-1.fc43.x86_64",
            "owner_query_returncode": 0,
        } for index, digest in enumerate(digests)],
    }


def synthetic_behavioral_identity(
        runtime_closure_sha: str, backend_closure_sha: str) -> str:
    return hashlib.sha256(canonical_json_bytes({
        "format_version": 1,
        "runtime_closure_sha256": runtime_closure_sha,
        "backend_runtime_closure_sha256": backend_closure_sha,
    })).hexdigest()


def synthetic_effective_schema() -> dict[str, Any]:
    contract = deepcopy(EXPECTED_SCHEMA_SEMANTIC_CONTRACT)
    contract_sha = hashlib.sha256(canonical_json_bytes(contract)).hexdigest()
    return {
        "evidence_status": "observed",
        "canonical_identity_sha256": hashlib.sha256(
            b"synthetic canonical live schema"
        ).hexdigest(),
        "custom_schema_verification": {
            "evidence_status": "observed",
            "passed": True,
            "semantic_contract": contract,
            "semantic_contract_sha256": contract_sha,
            "observed_semantics": contract,
            "definitions": {},
        },
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def workload_manifest(*, schema_389_sha: str = SCHEMA_389_SHA256) -> dict[str, Any]:
    files = {
        "data.ldif": DATA_SHA256,
        "expected/case.dns": EMPTY_DN_SHA256,
        "filters/case.filter": FILTER_SHA256,
        "indexes/index-configurations.json": INDEX_SHA256,
        "schema/389.ldif": schema_389_sha,
        "schema/openldap.schema": SCHEMA_OPENLDAP_SHA256,
    }
    manifest: dict[str, Any] = {
        "format_version": 1,
        "profile": "full",
        "host_intent": "native_fedora_timing",
        "correctness_only": False,
        "release_timing_evidence": True,
        "workload_id": "full-synthetic",
        "seed": 6275,
        "entry_counts": {"people": 100_000, "principal_cohort": 612},
        "dataset_import_oracles": synthetic_import_contracts(),
        "primary_contract": {
            "people": 100_000,
            "logical_outer_cohort": 612,
            "dn_branches": 355,
        },
        "files": files,
        "schema_files": {
            "389ds": "schema/389.ldif",
            "openldap": "schema/openldap.schema",
        },
        "index_config_file": "indexes/index-configurations.json",
        "scenario_groups": {"primary": ["case"]},
        "scenarios": {
            "case": {
                "filter_file": "filters/case.filter",
                "expected_file": "expected/case.dns",
                "expected_sha256": EMPTY_DN_SHA256,
                "expected_count": 0,
                "expected_result_code": "LDAP_SUCCESS",
                "base_dn": "dc=example,dc=com",
                "scope": "sub",
                "requested_attributes": ["1.1"],
                "index_variant": "baseline-no-presence",
                "parameters": {"candidate_count": 100},
                "dn_mode": "long-canonical-all-miss",
            }
        },
    }
    digest_input = {
        "format_version": manifest["format_version"],
        "profile": manifest["profile"],
        "seed": manifest["seed"],
        "host_intent": manifest["host_intent"],
        "files": manifest["files"],
    }
    manifest["workload_sha256"] = hashlib.sha256(
        canonical_json_bytes(digest_input)
    ).hexdigest()
    return manifest


def synthetic_background_quiet_collection(context: str) -> dict[str, Any]:
    setup = synthetic_background_referral_check_control()
    quiet = setup["quiet_window"]
    start = quiet["established_monotonic_seconds"] + 1
    end = start + 0.25
    return {
        "status": "passed",
        "context": context,
        "clock": "CLOCK_MONOTONIC",
        "bucket": quiet["bucket"],
        "start_monotonic_seconds": start,
        "end_monotonic_seconds": end,
        "duration_seconds": end - start,
        "next_boundary_monotonic_seconds": quiet[
            "next_boundary_monotonic_seconds"
        ],
        "deadline_monotonic_seconds": quiet["deadline_monotonic_seconds"],
        "safety_margin_seconds": 5,
        "passed": True,
    }


def synthetic_isolation(context: str) -> dict[str, Any]:
    return {
        "operation_count": 1,
        "cursor": {},
        "background_quiet_window": synthetic_background_quiet_collection(
            context
        ),
    }


def synthetic_not_applicable_quiet_collection(
        context: str, reason: str = "no server-attached collection") -> dict[str, Any]:
    return {
        "status": "not-applicable",
        "context": context,
        "reason": reason,
        "clock": "CLOCK_MONOTONIC",
        "bucket": None,
        "start_monotonic_seconds": None,
        "end_monotonic_seconds": None,
        "next_boundary_monotonic_seconds": None,
        "deadline_monotonic_seconds": None,
        "safety_margin_seconds": None,
        "duration_seconds": None,
        "passed": True,
    }


def _row(value: float, index: int, binary_sha: str) -> dict[str, Any]:
    return {
        "format_version": 1,
        "row_id": f"row-{index}",
        "scenario": "case",
        "phase": "measured",
        "server": "389ds",
        "executable_sha256": binary_sha,
        "client_elapsed_ns": int(value * 1_000_000_000),
        "server_etime_seconds": value * 0.9,
        "process_user_cpu_seconds": value / 3,
        "process_system_cpu_seconds": value / 6,
        "instructions": 1000 + index,
        "correctness_pass": True,
        "returned_sha256": EMPTY_DN_SHA256,
        "returned_count": 0,
        "ldap_result_code": "LDAP_SUCCESS",
        "server_result_code": "LDAP_SUCCESS",
        "server_result_evidence": {
            "evidence_status": "observed",
            "passed": True,
            "expected_ldap_result_code": "LDAP_SUCCESS",
            "actual_server_result_code": "LDAP_SUCCESS",
        },
        "background_quiet_window": synthetic_background_quiet_collection(
            f"synthetic row {index}"
        ),
        "expected_count": 0,
        "expected_sha256": EMPTY_DN_SHA256,
    }


def exact_result_evidence(
        *, passed: bool = True, result_code: Any = "LDAP_SUCCESS",
        expected_count: int = 0, expected_sha256: str = EMPTY_DN_SHA256,
        returned_count: Optional[int] = None,
        returned_sha256: Optional[str] = None) -> dict[str, Any]:
    return {
        "evidence_status": "observed",
        "passed": passed,
        "expected_count": expected_count,
        "returned_count": (
            expected_count if returned_count is None else returned_count
        ),
        "expected_sha256": expected_sha256,
        "returned_sha256": (
            expected_sha256 if returned_sha256 is None else returned_sha256
        ),
        "expected_ldap_result_code": "LDAP_SUCCESS",
        "ldap_result_code": result_code,
        "exact_count_match": passed,
        "exact_sha256_match": passed,
        "exact_dns_match": passed,
    }


def server_result_evidence(
        *, passed: bool = True, result_code: Any = "LDAP_SUCCESS") -> dict[str, Any]:
    return {
        "evidence_status": "observed",
        "passed": passed,
        "expected_ldap_result_code": "LDAP_SUCCESS",
        "actual_server_result_code": result_code,
    }


def make_bundle(
        parent: Path, name: str, *, run_id: str, binary_sha: str,
        label: str, commit: str,
        elapsed: Sequence[float] = tuple(range(1, 16)),
        native: bool = True, compatibility_key: str = "host-a",
        workload: Optional[Mapping[str, Any]] = None,
        lookup_mode: str = "on", perf_mode: str = "auto",
        profile_mode: str = "auto",
        backend_closure_variant: Optional[str] = None,
        runtime_closure_variant: Optional[str] = None,
        harness_variant: str = "committed-study") -> Path:
    root = parent / name
    root.mkdir()
    production_commit = production_equivalent_revision(commit)
    revision_role = analysis_revision_role(commit)
    manifest = dict(workload or workload_manifest())
    if not native:
        manifest["profile"] = "tiny"
        manifest["host_intent"] = "correctness_only"
        manifest["correctness_only"] = True
        manifest["release_timing_evidence"] = False
        digest_input = {
            "format_version": manifest["format_version"],
            "profile": manifest["profile"],
            "seed": manifest["seed"],
            "host_intent": manifest["host_intent"],
            "files": manifest["files"],
        }
        manifest["workload_sha256"] = hashlib.sha256(
            canonical_json_bytes(digest_input)
        ).hexdigest()
    _write_json(root / "workload-manifest.json", manifest)
    payload = root / "workload"
    (payload / "expected").mkdir(parents=True)
    (payload / "filters").mkdir()
    (payload / "indexes").mkdir()
    (payload / "schema").mkdir()
    (payload / "data.ldif").write_bytes(b"dn: dc=example,dc=com\n\n")
    (payload / "expected" / "case.dns").write_bytes(b"")
    (payload / "filters" / "case.filter").write_bytes(b"(uid=absent)\n")
    (payload / "indexes" / "index-configurations.json").write_bytes(INDEX_BYTES)
    schema_bytes = (
        b"389 schema\n"
        if manifest["files"]["schema/389.ldif"] == SCHEMA_389_SHA256
        else b"changed 389 schema\n"
    )
    (payload / "schema" / "389.ldif").write_bytes(schema_bytes)
    (payload / "schema" / "openldap.schema").write_bytes(b"openldap schema\n")
    (payload / "workload-manifest.json").write_bytes(
        (root / "workload-manifest.json").read_bytes()
    )
    workload_manifest_sha = hashlib.sha256(
        (root / "workload-manifest.json").read_bytes()
    ).hexdigest()
    backend_closure = synthetic_backend_closure(
        backend_closure_variant or binary_sha, binary_sha,
    )
    backend_closure_sha = backend_closure["identity_sha256"]
    runtime_closure_material, runtime_closure_sha = synthetic_runtime_closure(
        binary_sha, runtime_closure_variant or binary_sha,
    )
    behavioral_identity_sha = synthetic_behavioral_identity(
        runtime_closure_sha, backend_closure_sha,
    )
    effective_schema = synthetic_effective_schema()
    harness = synthetic_harness_identity(harness_variant)
    import_verification = synthetic_import_verification()
    lookup_evidence = synthetic_lookup_mode_evidence(lookup_mode)
    referral_control = synthetic_background_referral_check_control()
    index_build_evidence = synthetic_index_build_evidence()
    _write_json(root / "artifact-manifest.json", {
        "format_version": 1,
        "build_label": label,
        "expected_source_sha": commit,
        "production_equivalent_revision": production_commit,
        "revision_role": revision_role,
        "server": "389ds",
        "correctness_only": not native,
        "release_timing_evidence": native,
        "timing_claims_allowed": native,
        "workload_manifest_sha256": workload_manifest_sha,
        "runtime_closure_sha256": runtime_closure_sha,
        "backend_runtime_module_closure": backend_closure,
        "backend_runtime_closure_sha256": backend_closure_sha,
        "behavioral_runtime_identity_sha256": behavioral_identity_sha,
        "harness_identity": harness,
        "effective_schema": effective_schema,
        "import_verification": import_verification,
        "lookup_mode_evidence": lookup_evidence,
        "background_referral_check_control": referral_control,
        "index_build_evidence": index_build_evidence,
        "server_executable": {
            "executable_name": "ns-slapd",
            "executable_path": "/usr/bin/ns-slapd",
            "executable_sha256": binary_sha,
            "elf_build_id": {
                "status": "observed",
                "reason": None,
                "value": binary_sha[:40],
                "raw": "synthetic readelf output",
            },
            "linked_libraries": synthetic_linked_libraries(
                runtime_closure_material
            ),
            "runtime_closure_sha256": runtime_closure_sha,
            "runtime_closure_identity_material": runtime_closure_material,
            "owning_package": "389-ds-base-0:3.0-1.fc43.x86_64",
            "package_nevra": "389-ds-base-0:3.0-1.fc43.x86_64",
            "rpm_verify": {"accepted": True, "returncode": 0},
        },
    })
    _write_json(root / "run-manifest.json", {
        "format_version": 1,
        "run_id": run_id,
        "status": "complete",
        "mode": "native-timing" if native else "correctness-only",
        "server": "389ds",
        "expected_source_sha": commit,
        "production_equivalent_revision": production_commit,
        "revision_role": revision_role,
        "backend_requested": "mdb",
        "backend_actual": "mdb",
        "index_config": "baseline-no-presence",
        "workload_id": manifest["workload_id"],
        "workload_sha256": manifest["workload_sha256"],
        "workload_manifest_sha256": workload_manifest_sha,
        "correctness_only": not native,
        "release_timing_evidence": native,
        "timing_claims_allowed": native,
        "correctness_status": "pass",
        "harness_identity": harness,
        "selected_scenarios": list(manifest["scenarios"]),
        "scenario_order": list(manifest["scenarios"]),
        "repeat_count": len(elapsed),
        "warmup_count": 2,
        "raw_result_rows": len(elapsed) + 2,
        "lookup_mode_requested": lookup_mode,
        "lookup_mode_actual": lookup_mode,
        "perf_mode": perf_mode,
        "profile_mode": profile_mode,
        "runtime_closure_sha256": runtime_closure_sha,
        "backend_runtime_module_closure": backend_closure,
        "backend_runtime_closure_sha256": backend_closure_sha,
        "behavioral_runtime_identity_sha256": behavioral_identity_sha,
        "host": {
            "host_class": "fedora_native" if native else "macos_orbstack_emulated",
            "correctness_only": not native,
            "release_timing_evidence": native,
            "timing_claims_allowed": native,
            "compatibility_key": compatibility_key,
            "architecture": "x86_64",
            "system": "Linux",
            "fedora_release": "Fedora Linux 43 (Synthetic)",
            "cpu_model": "synthetic CPU",
            "storage": {
                "argv": [
                    "lsblk", "-J", "-o",
                    "NAME,TYPE,SIZE,MODEL,ROTA,TRAN,FSTYPE,FSVER,MOUNTPOINTS",
                ],
                "returncode": 0,
                "stdout": json.dumps({
                    "blockdevices": [{"name": "vda", "type": "disk"}],
                }),
                "stderr": "",
            },
            "filesystems": {
                "argv": [
                    "findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS",
                ],
                "returncode": 0,
                "stdout": json.dumps({
                    "filesystems": [{
                        "target": "/", "source": "/dev/vda3", "fstype": "xfs",
                    }],
                }),
                "stderr": "",
            },
        },
        "server_setup": {
            "canonical_index_intent_sha256": INDEX_INTENT_SHA256,
            "effective_schema": effective_schema,
            "import_verification": import_verification,
            "lookup_mode_evidence": lookup_evidence,
            "background_referral_check_control": referral_control,
            "index_build_evidence": index_build_evidence,
        },
        "startup_memory": {"rss_kib": 1000, "high_water_kib": 1000},
    })
    scenario_id = next(iter(manifest["scenarios"]))
    rows = [_row(value, index, binary_sha) for index, value in enumerate(elapsed)]
    for index, row in enumerate(rows, 1):
        row["iteration"] = index
    warmups = [
        _row(float(elapsed[0]), len(rows) + index, binary_sha)
        for index in range(1, 3)
    ]
    for index, row in enumerate(warmups, 1):
        row["row_id"] = f"warmup-{index}"
        row["phase"] = "warmup"
        row["iteration"] = index
    rows = rows + warmups
    for row in rows:
        row["scenario"] = scenario_id
        row.update({
            "build_label": label,
            "expected_source_sha": commit,
            "production_equivalent_revision": production_commit,
            "revision_role": revision_role,
            "host_class": "fedora_native" if native else "macos_orbstack_emulated",
            "host_compatibility_key": compatibility_key,
            "correctness_only": not native,
            "release_timing_evidence": native,
            "timing_claims_allowed": native,
            "workload_id": manifest["workload_id"],
            "workload_sha256": manifest["workload_sha256"],
            "workload_manifest_sha256": workload_manifest_sha,
            "filter_sha256": FILTER_SHA256,
            "expected_file_sha256": EMPTY_DN_SHA256,
            "schema_sha256": manifest["files"]["schema/389.ldif"],
            "index_intent_sha256": INDEX_INTENT_SHA256,
            "backend": "mdb",
            "lookup_mode": lookup_mode,
            "perf_mode": perf_mode,
            "profile_mode": profile_mode,
            "runtime_closure_sha256": runtime_closure_sha,
            "backend_runtime_closure_sha256": backend_closure_sha,
            "behavioral_runtime_identity_sha256": behavioral_identity_sha,
            "index_config": "baseline-no-presence",
            "attribute_variant": "attrs-1.1",
            "requested_attributes": ["1.1"],
            "cache_policy": "warm",
            "connection_policy": "new-connection-per-search",
        })
    _write_json(root / "raw-results.json", {
        "format_version": 1,
        "correctness_only": not native,
        "release_timing_evidence": native,
        "timing_claims_allowed": native,
        "rows": rows,
    })
    exact = exact_result_evidence()
    server_exact = server_result_evidence()
    _write_json(root / "correctness.json", {
        "format_version": 1,
        "correctness_only": not native,
        "release_timing_evidence": native,
        "timing_claims_allowed": native,
        "scenarios": [{
            "scenario": scenario_id,
            "correctness": "pass",
            "evidence_status": "observed",
            "expected_final_count": 0,
            "expected_final_sha256": EMPTY_DN_SHA256,
            "diagnostic_flights": {
                "preflight": {
                    "operation_isolated": True,
                    "isolation": synthetic_isolation(
                        "synthetic case preflight"
                    ),
                    "exact_result": dict(exact),
                    "server_result_evidence": dict(server_exact),
                },
                "postflight": {
                    "operation_isolated": True,
                    "isolation": synthetic_isolation(
                        "synthetic case postflight"
                    ),
                    "exact_result": dict(exact),
                    "server_result_evidence": dict(server_exact),
                },
            },
        }],
    })
    (root / "COMPLETE").write_text("completed synthetic run\n", encoding="utf-8")
    return root


def add_independent_perf_batches(bundle: Path, *, base_instructions: int = 10_000) -> None:
    raw_path = bundle / "raw-results.json"
    payload = json.loads(raw_path.read_text())
    batches = []
    measured_rows = [
        row for row in payload["rows"] if row.get("phase") == "measured"
    ]
    for index, row in enumerate(measured_rows):
        batch_id = f"{bundle.name}:perf:{index}"
        row["perf_batch_id"] = batch_id
        instructions = base_instructions + index * 100
        batches.append({
            "batch_id": batch_id,
            "status": "observed",
            "scenario": row["scenario"],
            "attribute_variant": row["attribute_variant"],
            "row_ids": [row["row_id"]],
            "operation_count": 1,
            "collection_scope": (
                "server-process aggregate over an independent measured batch"
            ),
            "count_semantics": (
                "batch aggregates normalized once by operation_count; "
                "not independent per-search counter samples"
            ),
            "event_counts": {"instructions": instructions},
            "event_counts_per_search": {"instructions": instructions},
            "server_cpu_seconds_per_search": 0.25 + index / 1000,
            "background_quiet_window": synthetic_background_quiet_collection(
                f"synthetic perf batch {index}"
            ),
        })
    payload["perf_batches"] = batches
    _write_json(raw_path, payload)


def upgrade_bundle_to_evidence_contract_v2(
        bundle: Path, *, hardware_perf: bool = False) -> None:
    """Upgrade one synthetic native bundle to the runner's modern contract."""
    artifact_path = bundle / "artifact-manifest.json"
    run_path = bundle / "run-manifest.json"
    raw_path = bundle / "raw-results.json"
    correctness_path = bundle / "correctness.json"
    artifact = json.loads(artifact_path.read_text())
    run = json.loads(run_path.read_text())
    raw = json.loads(raw_path.read_text())
    correctness = json.loads(correctness_path.read_text())

    required_packages = [
        "389-ds-base",
        "389-ds-base-libs",
        "389-ds-base-robdb-libs",
        "python3-lib389",
    ]
    package_evr = "0:3.3.0-1.fc44"
    source_rpm = "389-ds-base-3.3.0-1.fc44.src.rpm"
    package_closure = {
        "format_version": 1,
        "complete": True,
        "native_four_package_required": True,
        "required_packages": required_packages,
        "packages": [{
            "package_name": name,
            "nevra": (
                f"{name}-{package_evr}.noarch"
                if name == "python3-lib389"
                else f"{name}-{package_evr}.x86_64"
            ),
            "epoch_version_release": package_evr,
            "source_rpm": source_rpm,
            "rpm_verify": {
                "accepted": True,
                "clean": True,
                "returncode": 0,
            },
        } for name in required_packages],
    }
    package_closure_sha = hashlib.sha256(
        canonical_json_bytes(package_closure)
    ).hexdigest()

    policy_files = {
        relative: hashlib.sha256((STUDY_ROOT / relative).read_bytes()).hexdigest()
        for relative in (
            "workload/native-matrix-plan.json",
            "workload/acceptance-gates.json",
        )
    }
    harness = deepcopy(run["harness_identity"])
    harness["files"].update(policy_files)
    harness["content_sha256"] = hashlib.sha256(canonical_json_bytes({
        "format_version": harness["format_version"],
        "files": harness["files"],
    })).hexdigest()

    profile = {
        "scenario": "case",
        "status": "disabled",
        "evidence_status": "not-planned",
        "sampling_event": None,
        "software_fallback": False,
        "operation_count": 0,
        "operations": [],
        "profile_artifact": {
            "evidence_status": "not-produced",
            "path": "profiles/case.perf.data",
            "sha256": None,
            "size_bytes": None,
        },
        "lookup_consumption": {
            "status": "unresolved",
            "evidence_status": "not-observed",
            "sampled_symbols": [],
            "symbol_line_counts": {
                "vattr_test_filter_or_lookup": 0,
                "filter_or_lookup_probe": 0,
            },
        },
        "background_quiet_window": synthetic_not_applicable_quiet_collection(
            "case perf profile collection", "profiling disabled",
        ),
    }
    profile_identity = profile_collection_identity(profile)
    profile.update(profile_identity)

    if hardware_perf:
        perf_mode = "auto"
        perf_metadata = {
            "status": "observed",
            "events": list(PERF_EVENTS),
            "software_fallback": False,
            "unavailable_events": [],
            "event_counts": {event: 1 for event in PERF_EVENTS},
            "parse_warnings": [],
        }
    else:
        perf_mode = "off"
        perf_metadata = {
            "status": "disabled",
            "events": [],
            "software_fallback": False,
            "unavailable_events": [],
            "event_counts": {},
            "parse_warnings": [],
        }
    perf_identity = perf_collection_identity(perf_metadata)
    timing_environment_sha = hashlib.sha256(
        b"synthetic modern timing environment"
    ).hexdigest()

    artifact.update({
        "evidence_contract_version": 2,
        "installed_package_closure_sha256": package_closure_sha,
        "harness_identity": harness,
    })
    artifact["server_executable"].update({
        "owning_package": package_closure["packages"][0]["nevra"],
        "package_nevra": package_closure["packages"][0]["nevra"],
        "installed_package_closure": package_closure,
    })

    run.update({
        "evidence_contract_version": 2,
        "installed_package_closure_sha256": package_closure_sha,
        "harness_identity": harness,
        "perf_mode": perf_mode,
        "profile_mode": "off",
        "cache_policy": "warm",
        "connection_policy": "new-connection-per-search",
        "bind_class": "administrative",
        "timing_environment_sha256": timing_environment_sha,
        "profiles": [profile],
        "profile_collection_classes": [
            profile_identity["collection_class"]
        ],
        "profile_collection_signatures": [
            profile_identity["collection_signature"]
        ],
        "perf_collection_classes": [perf_identity["collection_class"]],
        "perf_collection_signatures": [
            perf_identity["collection_signature"]
        ],
    })
    run["configuration_contract"] = {
        "format_version": 1,
        "evidence_contract_version": 2,
        "server": "389ds",
        "lookup_mode": run["lookup_mode_actual"],
        "backend": run["backend_actual"],
        "index_config": run["index_config"],
        "cache_policy": "warm",
        "perf_mode": perf_mode,
        "profile_mode": "off",
        "profile_collection_classes": [
            profile_identity["collection_class"]
        ],
        "profile_collection_signatures": [
            profile_identity["collection_signature"]
        ],
        "perf_collection_classes": [perf_identity["collection_class"]],
        "perf_collection_signatures": [
            perf_identity["collection_signature"]
        ],
        "connection_policy": "new-connection-per-search",
        "bind_class": "administrative",
        "timing_environment_sha256": timing_environment_sha,
        "attribute_variants": {"case": {"attrs-1.1": ["1.1"]}},
    }

    perf_batches = []
    measured_rows = [
        row for row in raw["rows"] if row["phase"] == "measured"
    ]
    for row in raw["rows"]:
        row.update({
            "evidence_contract_version": 2,
            "perf_mode": perf_mode,
            "profile_mode": "off",
            "cache_policy": "warm",
            "connection_policy": "new-connection-per-search",
            "bind_class": "administrative",
            "timing_environment_sha256": timing_environment_sha,
            "profile_collection_class": profile_identity[
                "collection_class"
            ],
            "profile_collection_signature": profile_identity[
                "collection_signature"
            ],
        })
        if row["phase"] == "measured":
            row.update({
                "perf_collection_class": perf_identity["collection_class"],
                "perf_collection_signature": perf_identity[
                    "collection_signature"
                ],
            })
    if hardware_perf:
        for index, row in enumerate(measured_rows, 1):
            counts = {
                event: index * (event_index + 1) * 1000
                for event_index, event in enumerate(PERF_EVENTS)
            }
            batch_metadata = {
                **perf_metadata,
                "event_counts": counts,
            }
            batch_identity = perf_collection_identity(batch_metadata)
            if batch_identity != perf_identity:
                raise AssertionError("hardware perf identity unexpectedly varies")
            batch_id = f"{run['run_id']}:case:attrs-1.1:perf-stat:{index}"
            row["perf_batch_id"] = batch_id
            perf_batches.append({
                **batch_metadata,
                **batch_identity,
                "batch_id": batch_id,
                "scenario": "case",
                "attribute_variant": "attrs-1.1",
                "row_ids": [row["row_id"]],
                "operation_count": 1,
                "collection_scope": (
                    "server-process aggregate over an independent measured batch"
                ),
                "count_semantics": (
                    "batch aggregates normalized once by operation_count; "
                    "not independent per-search counter samples"
                ),
                "event_counts_per_search": counts,
                "event_units": {event: "count" for event in PERF_EVENTS},
                "server_cpu_seconds_per_search": 0.25 + index / 1000,
                "background_quiet_window": synthetic_background_quiet_collection(
                    f"synthetic modern perf batch {index}"
                ),
            })

    raw.update({
        "evidence_contract_version": 2,
        "perf_batches": perf_batches,
    })
    correctness["evidence_contract_version"] = 2
    _write_json(artifact_path, artifact)
    _write_json(run_path, run)
    _write_json(raw_path, raw)
    _write_json(correctness_path, correctness)


def mutate_harness_file_binding(
        bundle: Path, relative: str, digest: str) -> None:
    """Keep harness evidence internally valid while changing one bound file."""
    for manifest_name in ("artifact-manifest.json", "run-manifest.json"):
        path = bundle / manifest_name
        manifest = json.loads(path.read_text())
        harness = manifest["harness_identity"]
        harness["files"][relative] = digest
        harness["content_sha256"] = hashlib.sha256(canonical_json_bytes({
            "format_version": harness["format_version"],
            "files": harness["files"],
        })).hexdigest()
        _write_json(path, manifest)


def set_abba_schedule(
        bundle: Path, *, block_id: str, position: str,
        created_at: str, completed_at: str) -> None:
    run_path = bundle / "run-manifest.json"
    run = json.loads(run_path.read_text())
    run.update({
        "created_at": created_at,
        "completed_at": completed_at,
        "cache_policy": "warm",
        "connection_policy": "new-connection-per-search",
        "bind_class": None,
        "cpu_affinity": 2,
        "order_seed": 389,
        "perf_collection_classes": [],
        "perf_collection_signatures": [],
    })
    artifact = json.loads((bundle / "artifact-manifest.json").read_text())
    profiles = run.get("profiles")
    profiles = profiles if isinstance(profiles, list) else []
    profile_states = sorted(({
        "scenario": profile.get("scenario"),
        "status": profile.get("status"),
        "sampling_event": profile.get("sampling_event"),
        "software_fallback": profile.get("software_fallback") is True,
    } for profile in profiles if isinstance(profile, Mapping)),
        key=lambda value: str(value["scenario"]))
    material = {
        "format_version": 1,
        "evidence_contract_version": run.get("evidence_contract_version"),
        "server": run.get("server"),
        "source_revision": run.get("expected_source_sha"),
        "production_revision": run.get("production_equivalent_revision"),
        "executable_sha256": artifact["server_executable"][
            "executable_sha256"
        ],
        "installed_package_closure_sha256": run.get(
            "installed_package_closure_sha256"
        ),
        "runtime_closure_sha256": run.get("runtime_closure_sha256"),
        "backend_runtime_closure_sha256": run.get(
            "backend_runtime_closure_sha256"
        ),
        "behavioral_runtime_identity_sha256": run.get(
            "behavioral_runtime_identity_sha256"
        ),
        "lookup_mode": run.get("lookup_mode_actual"),
        "backend": run.get("backend_actual"),
        "index_config": run.get("index_config"),
        "cache_policy": run.get("cache_policy"),
        "perf_mode": run.get("perf_mode"),
        "perf_collection_classes": run.get("perf_collection_classes", []),
        "perf_collection_signatures": run.get(
            "perf_collection_signatures", []
        ),
        "profile_mode": run.get("profile_mode"),
        "profile_collection_states": profile_states,
        "connection_policy": run.get("connection_policy"),
        "bind_class": run.get("bind_class"),
        "repeat_count": run.get("repeat_count"),
        "warmup_count": run.get("warmup_count"),
        "cpu_affinity": run.get("cpu_affinity"),
        "scenario_order": run.get("scenario_order"),
        "order_seed": run.get("order_seed"),
        "selected_scenarios": run.get("selected_scenarios"),
    }
    fingerprint = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    schedule = {
        "format_version": 1,
        "design": "abba",
        "block_id": block_id,
        "position": position,
        "state": position[0],
        "release_ordering_eligible": True,
        "state_fingerprint": fingerprint,
        "state_fingerprint_material": material,
    }
    run.update({
        "schedule_design": "abba",
        "schedule_block_id": block_id,
        "schedule_position": position,
        "schedule_state": position[0],
        "schedule_state_fingerprint": fingerprint,
        "schedule": schedule,
    })
    _write_json(run_path, run)
    raw_path = bundle / "raw-results.json"
    raw = json.loads(raw_path.read_text())
    for row in raw["rows"]:
        row.update({
            "schedule_design": "abba",
            "schedule_block_id": block_id,
            "schedule_position": position,
            "schedule_state": position[0],
            "schedule_state_fingerprint": fingerprint,
        })
    _write_json(raw_path, raw)


def synthetic_gate_summary(
        scenario_id: str, lookup_mode: str, *,
        executable_sha: str = "a" * 64,
        behavioral_sha: str = "b" * 64,
        host_signature: str = "c" * 64,
        commit: str = COMMIT_FINAL,
        elapsed: float = 1.0,
        cpu: float = 0.5,
        instructions: float = 1000.0,
        candidate_count: Optional[int] = 612,
        mechanism: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    def metric(value: float) -> dict[str, Any]:
        return {
            "n": 15,
            "median": value,
            "p95_nearest_rank": value,
            "mad": 0.0,
        }

    default_mechanism: dict[str, Any] = {
        "required": False,
        "verified": True,
        "lookup_constructed_values": (
            [False] if lookup_mode in {"off", "disabled"} else [True]
        ),
        "lookup_largest_families": (
            [] if lookup_mode in {"off", "disabled"} else [355]
        ),
        "lookup_consumption_statuses": (
            [] if lookup_mode in {"off", "disabled"} else ["consumed"]
        ),
        "profile_sha256s": ["d" * 64],
        "profile_statuses": ["observed"],
        "candidate_counts": [612],
        "candidate_list_statuses": ["observed"],
        "candidate_list_observed_values": [True],
        "candidate_list_values": [612],
        "access_notes": ["U"],
        "access_notes_observed_values": [True],
        "stat_index_reads": [],
        "stat_index_reads_observed_values": [True],
        "cap_path_observed_values": [],
        "selected_attributes_direct": [],
        "selection_observations": [],
        "profile_attributed_waivers": [],
        "approximate_semantics_evidence": [],
    }
    if mechanism:
        default_mechanism.update(deepcopy(dict(mechanism)))
    return {
        "summary_id": hashlib.sha256(
            f"{scenario_id}:{lookup_mode}:{executable_sha}:{commit}".encode()
        ).hexdigest()[:16],
        "scenario_fingerprint": hashlib.sha256(
            scenario_id.encode("utf-8")
        ).hexdigest(),
        "scenario_ids": [scenario_id],
        "scenario_groups": [],
        "source_commits": [commit],
        "commit_labels": [commit[:8]],
        "executable_sha256": executable_sha,
        "runtime_closure_sha256": behavioral_sha,
        "backend_runtime_closure_sha256": "e" * 64,
        "behavioral_runtime_identity_sha256": behavioral_sha,
        "host_signature": host_signature,
        "configuration": {
            "server": "389ds",
            "lookup_mode": lookup_mode,
            "perf_mode": "auto",
            "backend": "mdb",
            "index_variant": "baseline-no-presence",
            "cache_policy": "warm",
            "attribute_mode": "attrs-1.1",
            "bind_class": "administrative",
            "connection_policy": "new-connection-per-search",
        },
        "scale": {"candidate_count": candidate_count},
        "release_ready": True,
        "n": 15,
        "elapsed": metric(elapsed),
        "server_etime": metric(elapsed * 0.9),
        "server_cpu": metric(cpu),
        "instructions": metric(instructions),
        "mechanism_evidence": default_mechanism,
    }


def evaluate_synthetic_gates(
        summaries: Sequence[Mapping[str, Any]], *,
        scenarios: Optional[Mapping[str, Any]] = None,
        scenario_groups: Optional[Mapping[str, Any]] = None,
        controls: Sequence[Mapping[str, Any]] = (),
        rows: Sequence[Mapping[str, Any]] = (),
        gates: Optional[Mapping[str, Any]] = None,
        bundles: Optional[Sequence[Any]] = None) -> dict[str, Mapping[str, Any]]:
    gate_contract = deepcopy(dict(gates or json.loads(
        (STUDY_ROOT / "workload" / "acceptance-gates.json").read_text()
    )))
    if bundles is None:
        bundles = [SimpleNamespace(
            workload={
                "scenarios": dict(scenarios or {}),
                "scenario_groups": dict(scenario_groups or {}),
            },
            run_manifest={},
            run_id="synthetic-gate-bundle",
            artifacts=[],
            release_candidate=False,
            host_signature=None,
        )]
    evaluated = build_acceptance_gate_results(
        bundles, rows, [], controls, summaries, gate_contract,
    )
    return {str(gate["gate_id"]): gate for gate in evaluated}


def synthetic_complete_matrix_contract() -> tuple[
        dict[str, Any], dict[str, Any], list[dict[str, Any]],
        list[dict[str, Any]], dict[str, Any]]:
    timed_ids = [f"timed-{index:03d}" for index in range(116)]
    dynamic_ids = ["dynamic-before-cap", "dynamic-after-cap"]
    workload = {
        "profile": "full",
        "scenarios": {
            scenario_id: {"index_variant": "baseline-no-presence"}
            for scenario_id in [*timed_ids, *dynamic_ids]
        },
        "scenario_groups": {
            "timed": timed_ids,
            "dynamic-list-correctness": dynamic_ids,
        },
    }
    revision_role = "final-candidate"
    plan = {
        "format_version": 1,
        "matrix_id": "synthetic-full-matrix",
        "timing_protocol": {
            "minimum_repeats_per_run": 15,
            "required_backend": "mdb",
            "required_cache_policy": "warm",
            "required_perf_collection_class": "hardware-events",
        },
        "all_timed_scenario_groups": ["timed"],
        "profile_required_groups": [],
        "timed_pair_rules": [{
            "id": "final-lookup-toggle",
            "scenario_groups_ref": "all_timed_scenario_groups",
            "a": {
                "server": "389ds",
                "revision_role": revision_role,
                "lookup_mode": "off",
            },
            "b": {
                "server": "389ds",
                "revision_role": revision_role,
                "lookup_mode": "on",
            },
        }],
        "correctness_control_rules": [{
            "id": "dynamic-list-control",
            "scenario_group": "dynamic-list-correctness",
            "server": "389ds",
            "revision_role": revision_role,
        }],
    }

    def summary(scenario_id: str, lookup_mode: str) -> dict[str, Any]:
        arm = "A" if lookup_mode == "off" else "B"
        return {
            "summary_id": f"{scenario_id}:{lookup_mode}",
            "scenario_ids": [scenario_id],
            "release_ready": True,
            "revision_roles": [revision_role],
            "source_run_ids": [f"{arm}1", f"{arm}2"],
            "configuration": {
                "server": "389ds",
                "lookup_mode": lookup_mode,
                "backend": "mdb",
                "cache_policy": "warm",
                "index_variant": "baseline-no-presence",
                "attribute_mode": "attrs-1.1",
                "perf_collection_class": "hardware-events",
            },
            "instructions": {"n": 15},
        }

    summaries = [
        summary(scenario_id, lookup_mode)
        for scenario_id in timed_ids
        for lookup_mode in ("off", "on")
    ]
    controls = [{
        "control_id": f"control:{scenario_id}",
        "scenario_id": scenario_id,
        "server": "389ds",
        "revision_roles": [revision_role],
        "passed": True,
        "complete": True,
        "oracle_passed": True,
    } for scenario_id in dynamic_ids]
    schedule = {
        "status": "complete",
        "blocks": [{
            "block_id": "final-lookup-toggle",
            "status": "pass",
            "run_ids_by_position": {
                "A1": "A1", "B1": "B1", "B2": "B2", "A2": "A2",
            },
        }],
    }
    return plan, workload, summaries, controls, schedule


class MergeTests(unittest.TestCase):
    def test_short_native_runs_cannot_pool_to_the_release_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundles = [
                make_bundle(
                    root, f"short-{index}", run_id=f"short-{index}",
                    binary_sha="1" * 64, label="final", commit=COMMIT_FINAL,
                    elapsed=[1.0] * 5,
                )
                for index in range(3)
            ]
            output = root / "merged"
            result = merge_result_directories(bundles, output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(result["status"], "native-results-pending")
            self.assertEqual(merged["release_summaries"], [])
            self.assertTrue(all(
                "at least 15 measured repeats" in " ".join(
                    bundle["disposition_reasons"]
                )
                for bundle in json.loads(
                    (output / "artifact-manifest.json").read_text()
                )["source_bundles"]
            ))

    def test_complete_abba_block_is_machine_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs = (
                ("A1", "A", "a" * 64, COMMIT_BOUNDED,
                 "2026-07-20T00:00:00Z", "2026-07-20T00:01:00Z"),
                ("B1", "B", "b" * 64, COMMIT_FINAL,
                 "2026-07-20T00:02:00Z", "2026-07-20T00:03:00Z"),
                ("B2", "B", "b" * 64, COMMIT_FINAL,
                 "2026-07-20T00:04:00Z", "2026-07-20T00:05:00Z"),
                ("A2", "A", "a" * 64, COMMIT_BOUNDED,
                 "2026-07-20T00:06:00Z", "2026-07-20T00:07:00Z"),
            )
            bundles = []
            for position, arm, binary, commit, created, completed in specs:
                bundle = make_bundle(
                    root, position, run_id=position, binary_sha=binary,
                    label=position, commit=commit, elapsed=[1.0] * 15,
                )
                set_abba_schedule(
                    bundle, block_id="bounded-vs-final", position=position,
                    created_at=created, completed_at=completed,
                )
                bundles.append(load_bundle(bundle))
            complete = assess_schedules(bundles)
            self.assertEqual(complete["status"], "complete")
            self.assertEqual(complete["valid_blocks"], ["bounded-vs-final"])
            incomplete = assess_schedules(bundles[:-1])
            self.assertEqual(incomplete["status"], "pending")
            self.assertIn(
                "missing positions: A2",
                incomplete["blocks"][0]["failures"],
            )

    def test_full_matrix_contract_reaches_complete(self) -> None:
        plan, workload, summaries, controls, schedule = (
            synthetic_complete_matrix_contract()
        )
        result = assess_matrix_completion(
            plan, workload, summaries, controls, schedule,
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["required_instance_count"], 119)
        self.assertEqual(result["pass_count"], 119)
        self.assertEqual(result["pending_count"], 0)
        self.assertEqual(result["fail_count"], 0)

    def test_full_matrix_contract_is_pending_when_summary_is_missing(
            self) -> None:
        plan, workload, summaries, controls, schedule = (
            synthetic_complete_matrix_contract()
        )
        missing_summary = summaries.pop()
        result = assess_matrix_completion(
            plan, workload, summaries, controls, schedule,
        )
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["pass_count"], 118)
        self.assertEqual(result["pending_count"], 1)
        self.assertEqual(result["fail_count"], 0)
        pending = [
            item for item in result["timed_pair_instances"]
            if item["status"] == "pending"
        ]
        self.assertEqual(len(pending), 1)
        self.assertIn(
            missing_summary["scenario_ids"][0], pending[0]["instance_id"],
        )

    def test_full_matrix_contract_fails_failed_correctness_control(
            self) -> None:
        plan, workload, summaries, controls, schedule = (
            synthetic_complete_matrix_contract()
        )
        controls[0]["passed"] = False
        result = assess_matrix_completion(
            plan, workload, summaries, controls, schedule,
        )
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["pass_count"], 118)
        self.assertEqual(result["pending_count"], 0)
        self.assertEqual(result["fail_count"], 1)
        failed = [
            item for item in result["correctness_control_instances"]
            if item["status"] == "fail"
        ]
        self.assertEqual(len(failed), 1)
        self.assertIn(controls[0]["scenario_id"], failed[0]["instance_id"])

    def test_unknown_stable_revision_has_no_inferred_direction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stable = make_bundle(
                root, "stable", run_id="stable", binary_sha="c" * 64,
                label="fedora-stable", commit="c" * 40,
                lookup_mode="unsupported", elapsed=[2.0] * 15,
            )
            final = make_bundle(
                root, "final", run_id="final", binary_sha="d" * 64,
                label="final", commit=COMMIT_FINAL, lookup_mode="off",
                elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([stable, final], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(len(merged["release_summaries"]), 2)
            self.assertEqual(merged["release_comparisons"], [])

    def test_actual_perf_collection_class_is_a_timing_stratum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hardware = make_bundle(
                root, "hardware", run_id="hardware", binary_sha="e" * 64,
                label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            software = make_bundle(
                root, "software", run_id="software", binary_sha="e" * 64,
                label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            for bundle, collection_class, signature in (
                    (hardware, "hardware-events", "1" * 64),
                    (software, "software-task-clock", "2" * 64)):
                raw_path = bundle / "raw-results.json"
                raw = json.loads(raw_path.read_text())
                for row in raw["rows"]:
                    row["perf_collection_class"] = collection_class
                    row["perf_collection_signature"] = signature
                _write_json(raw_path, raw)
            output = root / "merged"
            merge_result_directories([hardware, software], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(len(merged["release_summaries"]), 2)
            self.assertEqual({
                summary["configuration"]["perf_collection_class"]
                for summary in merged["release_summaries"]
            }, {"hardware-events", "software-task-clock"})
            self.assertEqual(merged["release_comparisons"], [])

    def test_evidence_contract_v2_bundle_loads_and_binds_authoritative_policy(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "modern", run_id="modern", binary_sha="e" * 64,
                label="study-tip", commit=COMMIT_STUDY_TIP,
                perf_mode="off", profile_mode="off",
                elapsed=[1.0] * 15,
            )
            upgrade_bundle_to_evidence_contract_v2(bundle)

            loaded = load_bundle(bundle)
            self.assertTrue(loaded.release_candidate)
            self.assertEqual(
                loaded.run_manifest["evidence_contract_version"], 2,
            )
            self.assertTrue(loaded.artifacts[0]["rpm_proved"])
            package_closure = loaded.artifact_manifest[
                "server_executable"
            ]["installed_package_closure"]
            self.assertEqual(
                [record["package_name"] for record in package_closure["packages"]],
                [
                    "389-ds-base", "389-ds-base-libs",
                    "389-ds-base-robdb-libs", "python3-lib389",
                ],
            )

            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(merged["policy_contract_status"], "pass")
            self.assertEqual(merged["matrix_plan_binding_failures"], [])
            self.assertEqual(
                merged["acceptance_gates_binding_failures"], [],
            )
            self.assertEqual(len(merged["release_summaries"]), 1)
            self.assertEqual(
                merged["release_summaries"][0]["configuration"][
                    "evidence_contract_version"
                ],
                2,
            )

    def test_evidence_contract_v2_rejects_cross_manifest_version_mutation(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "modern-version", run_id="modern-version",
                binary_sha="d" * 64, label="study-tip",
                commit=COMMIT_STUDY_TIP, perf_mode="off",
                profile_mode="off", elapsed=[1.0] * 15,
            )
            upgrade_bundle_to_evidence_contract_v2(bundle)
            artifact_path = bundle / "artifact-manifest.json"
            artifact = json.loads(artifact_path.read_text())
            artifact.pop("evidence_contract_version")
            _write_json(artifact_path, artifact)

            with self.assertRaisesRegex(
                    MergeError, "evidence contract versions disagree"):
                load_bundle(bundle)

    def test_evidence_contract_v2_withholds_mixed_package_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "modern-packages", run_id="modern-packages",
                binary_sha="c" * 64, label="study-tip",
                commit=COMMIT_STUDY_TIP, perf_mode="off",
                profile_mode="off", elapsed=[1.0] * 15,
            )
            upgrade_bundle_to_evidence_contract_v2(bundle)
            artifact_path = bundle / "artifact-manifest.json"
            run_path = bundle / "run-manifest.json"
            artifact = json.loads(artifact_path.read_text())
            run = json.loads(run_path.read_text())
            closure = artifact["server_executable"][
                "installed_package_closure"
            ]
            closure["packages"][2]["epoch_version_release"] = (
                "0:3.3.0-2.fc44"
            )
            closure_sha = hashlib.sha256(
                canonical_json_bytes(closure)
            ).hexdigest()
            artifact["installed_package_closure_sha256"] = closure_sha
            run["installed_package_closure_sha256"] = closure_sha
            _write_json(artifact_path, artifact)
            _write_json(run_path, run)

            loaded = load_bundle(bundle)
            self.assertFalse(loaded.release_candidate)
            self.assertFalse(loaded.artifacts[0]["rpm_proved"])
            self.assertTrue(any(
                "mixed builds" in reason
                for reason in loaded.disposition_reasons
            ))
            output = root / "merged-packages"
            merge_result_directories([bundle], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(merged["release_summaries"], [])

    def test_evidence_contract_v2_withholds_unbound_policy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "modern-policy", run_id="modern-policy",
                binary_sha="b" * 64, label="study-tip",
                commit=COMMIT_STUDY_TIP, perf_mode="off",
                profile_mode="off", elapsed=[1.0] * 15,
            )
            upgrade_bundle_to_evidence_contract_v2(bundle)
            mutate_harness_file_binding(
                bundle, "workload/native-matrix-plan.json", "0" * 64,
            )

            self.assertTrue(load_bundle(bundle).release_candidate)
            output = root / "merged-policy"
            merge_result_directories([bundle], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(merged["policy_contract_status"], "pending")
            self.assertEqual(
                len(merged["matrix_plan_binding_failures"]), 1,
            )
            self.assertIn(
                "workload/native-matrix-plan.json",
                merged["matrix_plan_binding_failures"][0],
            )
            self.assertEqual(
                merged["release_conclusion"]["recommendation"], "withheld",
            )

    def test_evidence_contract_v2_accepts_runner_hardware_perf_identity(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "modern-hardware", run_id="modern-hardware",
                binary_sha="a" * 64, label="study-tip",
                commit=COMMIT_STUDY_TIP, perf_mode="auto",
                profile_mode="off", elapsed=[1.0] * 15,
            )
            upgrade_bundle_to_evidence_contract_v2(
                bundle, hardware_perf=True,
            )

            loaded = load_bundle(bundle)
            self.assertTrue(loaded.release_candidate)
            output = root / "merged-hardware"
            merge_result_directories([bundle], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )
            self.assertEqual(len(merged["perf_batches"]), 15)
            self.assertEqual({
                batch["collection_class"] for batch in merged["perf_batches"]
            }, {"hardware-events"})
            summary = merged["release_summaries"][0]
            self.assertEqual(summary["instructions"]["n"], 15)
            self.assertEqual(
                summary["configuration"]["perf_collection_class"],
                "hardware-events",
            )

    def test_approximate_cross_server_ratios_require_matching_probe_evidence(self) -> None:
        probes = {
            "approx-positive": {
                "filter": "(cn~=example)",
                "expected_count": 0,
                "expected_sha256": EMPTY_DN_SHA256,
                "expected_result_code": "LDAP_SUCCESS",
            },
            "approx-negative": {
                "filter": "(!(cn~=example))",
                "expected_count": 0,
                "expected_sha256": EMPTY_DN_SHA256,
                "expected_result_code": "LDAP_SUCCESS",
            },
        }
        semantic_contract = {
            "normalization": "synthetic approximate-match equivalence",
            "probes": probes,
        }
        contract_sha = hashlib.sha256(
            canonical_json_bytes(semantic_contract)
        ).hexdigest()

        def summary(server: str, elapsed: float) -> dict[str, Any]:
            return {
                "summary_id": server,
                "scenario_fingerprint": "f" * 64,
                "scenario_ids": ["combined-approximate-gain"],
                "scenario_groups": ["combined-approximate"],
                "configuration": {
                    "server": server,
                    "backend": "mdb",
                    "lookup_mode": "on" if server == "389ds" else "unsupported",
                },
                "release_ready": True,
                "commit_labels": [server],
                "behavioral_runtime_identity_sha256": (
                    "b" * 64 if server == "389ds" else "c" * 64
                ),
                "runtime_closure_sha256": (
                    "d" * 64 if server == "389ds" else "e" * 64
                ),
                "backend_runtime_closure_sha256": (
                    "1" * 64 if server == "389ds" else "2" * 64
                ),
                "elapsed": {"median": elapsed},
                "server_cpu": {"median": elapsed / 2},
                "instructions": {"median": elapsed * 1000},
                "cross_server_comparison": {
                    "policy": "requires-native-equivalence-preflight",
                    "contract_sha256": contract_sha,
                    "semantic_contract": semantic_contract,
                    "required_probe_ids": ["approx-positive", "approx-negative"],
                    "probes": probes,
                    "default_eligibility": "excluded",
                },
                "mechanism_evidence": {
                    "approximate_semantics_evidence": [],
                },
            }

        ds = summary("389ds", 2.0)
        openldap = summary("openldap", 1.0)
        pending = build_openldap_context([ds, openldap])[0]
        self.assertFalse(pending["cross_server_timing_eligible"])
        self.assertIsNone(pending["elapsed_ratio_389ds_over_openldap"])
        self.assertEqual(pending["approximate_semantics_status"], "pending")

        def probe_record(probe_id: str) -> dict[str, Any]:
            declared = probes[probe_id]
            return {
                "evidence_status": "observed",
                "operation_isolated": True,
                "result_line_isolated": True,
                "declared_probe": declared,
                "exact_result": exact_result_evidence(),
                "server_result_evidence": server_result_evidence(),
            }

        evidence = {
            "status": "comparable",
            "evidence_status": "observed",
            "policy": "requires-native-equivalence-preflight",
            "contract_sha256": contract_sha,
            "semantic_contract": semantic_contract,
            "required_probe_ids": ["approx-positive", "approx-negative"],
            "probes": {probe_id: probe_record(probe_id) for probe_id in probes},
        }
        ds["mechanism_evidence"]["approximate_semantics_evidence"] = [evidence]
        openldap["mechanism_evidence"]["approximate_semantics_evidence"] = [evidence]
        comparable = build_openldap_context([ds, openldap])[0]
        self.assertTrue(comparable["cross_server_timing_eligible"])
        self.assertEqual(comparable["elapsed_ratio_389ds_over_openldap"], 2.0)
        self.assertEqual(comparable["approximate_semantics_status"], "comparable")

        forged = deepcopy(evidence)
        forged["probes"]["approx-positive"]["exact_result"][
            "returned_count"
        ] = 1
        ds["mechanism_evidence"]["approximate_semantics_evidence"] = [forged]
        rejected = build_openldap_context([ds, openldap])[0]
        self.assertFalse(rejected["cross_server_timing_eligible"])
        self.assertEqual(rejected["approximate_semantics_status"], "pending")

    def test_scaling_table_emitted_for_two_declared_points(self) -> None:
        gates = json.loads(
            (STUDY_ROOT / "workload" / "acceptance-gates.json").read_text()
        )

        def summary(value: int, elapsed: float) -> dict[str, Any]:
            metric = {
                "n": 15, "median": elapsed,
                "p95_nearest_rank": elapsed * 1.1, "mad": 0.01,
            }
            return {
                "scale": {"candidate_count": value},
                "scenario_groups": ["candidate-scaling"],
                "executable_sha256": "a" * 64,
                "runtime_closure_sha256": "b" * 64,
                "backend_runtime_closure_sha256": "c" * 64,
                "behavioral_runtime_identity_sha256": "d" * 64,
                "configuration": {"server": "389ds", "lookup_mode": "on"},
                "binary_id": "a" * 16,
                "runtime_identity_id": "d" * 16,
                "commit_labels": ["final"],
                "scenario_ids": [f"candidates-{value}"],
                "n": 15,
                "elapsed": metric,
                "server_etime": metric,
                "server_cpu": metric,
                "instructions": metric,
            }

        tables = build_scaling_tables(
            [summary(10, 0.1), summary(100, 0.2)], gates,
        )
        candidate_tables = [
            table for table in tables if table["dimension"] == "candidate_count"
        ]
        self.assertEqual(len(candidate_tables), 1)
        self.assertEqual(
            [point["value"] for point in candidate_tables[0]["points"]],
            [10, 100],
        )

    def test_nearest_rank_p95_and_median_statistics(self) -> None:
        self.assertEqual(nearest_rank(list(range(1, 21))), 19.0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "a" * 64
            bundle = make_bundle(
                root, "one", run_id="run-one", binary_sha=binary,
                label="pre-series", commit="6e1e933745313622593d943e983ff710de8db732",
                elapsed=list(range(1, 21)),
            )
            output = root / "merged"
            result = merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(result["status"], "native-results-available")
            self.assertFalse(merged["correctness_only"])
            self.assertTrue(merged["release_timing_evidence"])
            self.assertTrue(merged["timing_claims_allowed"])
            self.assertEqual(merged["host_class"], "fedora_native")
            self.assertEqual(merged["source_run_count"], 1)
            self.assertEqual(
                result["matrix_completion_status"], "pending",
            )
            self.assertEqual(
                merged["matrix_completion_status"], "pending",
            )
            summary = merged["release_summaries"][0]
            self.assertEqual(summary["n"], 20)
            self.assertEqual(summary["elapsed_median_seconds"], 10.5)
            self.assertEqual(summary["elapsed_p95_seconds"], 19.0)
            self.assertEqual(summary["server_cpu_median_seconds"], 5.25)
            self.assertIn(
                "Matrix completion: **pending**",
                (output / "RESULTS.md").read_text(),
            )

    def test_incompatible_workload_hashes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_bundle(
                root, "first", run_id="first", binary_sha="a" * 64,
                label="pre-series", commit="6e1e933745313622593d943e983ff710de8db732",
            )
            changed = workload_manifest(schema_389_sha=ALT_SCHEMA_389_SHA256)
            second = make_bundle(
                root, "second", run_id="second", binary_sha="b" * 64,
                label="initial-or-lookup", commit="7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6",
                workload=changed,
            )
            with self.assertRaisesRegex(MergeError, "schema|workload"):
                merge_result_directories([first, second], root / "merged")

    def test_complete_manifest_change_is_rejected_even_when_payload_hashes_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_bundle(
                root, "first", run_id="first", binary_sha="a" * 64,
                label="pre-series", commit="6e1e933745313622593d943e983ff710de8db732",
            )
            changed = workload_manifest()
            changed["scenarios"]["case"]["description"] = "metadata-only mutation"
            second = make_bundle(
                root, "second", run_id="second", binary_sha="b" * 64,
                label="initial-or-lookup", commit="7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6",
                workload=changed,
            )
            with self.assertRaisesRegex(MergeError, "complete workload manifest"):
                merge_result_directories([first, second], root / "merged")

    def test_incompatible_native_hosts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_bundle(
                root, "first", run_id="first", binary_sha="a" * 64,
                label="pre-series", commit="6e1e933745313622593d943e983ff710de8db732",
                compatibility_key="host-a",
            )
            second = make_bundle(
                root, "second", run_id="second", binary_sha="b" * 64,
                label="initial-or-lookup", commit="7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6",
                compatibility_key="host-b",
            )
            with self.assertRaisesRegex(MergeError, "incompatible host-mode"):
                merge_result_directories([first, second], root / "merged")

    def test_incomplete_and_cleanup_failed_bundles_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                ("missing-complete", "COMPLETE", "missing"),
                ("incomplete", "INCOMPLETE", "create"),
                ("cleanup-failed", "CLEANUP-FAILED", "create"),
            )
            for index, (name, marker, operation) in enumerate(cases):
                with self.subTest(marker=marker):
                    bundle = make_bundle(
                        root, name, run_id=name, binary_sha=f"{index + 4}" * 64,
                        label="final",
                        commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                    )
                    marker_path = bundle / marker
                    if operation == "missing":
                        marker_path.unlink()
                    else:
                        marker_path.write_text("synthetic failure marker\n", encoding="utf-8")
                    with self.assertRaisesRegex(MergeError, marker):
                        merge_result_directories(
                            [bundle], root / f"merged-{name}",
                        )

            bad_status = make_bundle(
                root, "bad-status", run_id="bad-status", binary_sha="7" * 64,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
            )
            run_manifest_path = bad_status / "run-manifest.json"
            run_manifest = json.loads(run_manifest_path.read_text())
            run_manifest["status"] = "cleanup-failed"
            _write_json(run_manifest_path, run_manifest)
            with self.assertRaisesRegex(MergeError, "status must be 'complete'"):
                merge_result_directories([bad_status], root / "merged-bad-status")

    def test_identical_executable_hash_dedupes_and_retains_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "c" * 64
            first = make_bundle(
                root, "first", run_id="first", binary_sha=binary,
                label="lifecycle-leak-tests", commit="014fe6a3793898b508a6d6de9893937a7e1aa49d",
            )
            second = make_bundle(
                root, "second", run_id="second", binary_sha=binary,
                label="asan-harness", commit="f29a3c6806c81d1cc0e5b77520b3b8d4b3d5d873",
            )
            output = root / "merged"
            merge_result_directories([first, second], output)
            artifacts = json.loads((output / "artifact-manifest.json").read_text())
            self.assertEqual(len(artifacts["binary_groups"]), 1)
            self.assertEqual(
                artifacts["binary_groups"][0]["commit_labels"],
                ["asan-harness", "lifecycle-leak-tests"],
            )
            self.assertEqual(
                artifacts["binary_groups"][0]["performance_identity_count"], 1,
            )
            self.assertEqual(
                len(artifacts["binary_groups"][0][
                    "behavioral_runtime_identity_groups"
                ]),
                1,
            )
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(len(merged["release_summaries"]), 1)
            self.assertEqual(merged["release_summaries"][0]["n"], 30)

    def test_abba_runs_pool_distinct_startup_memory_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            first = make_bundle(
                root, "abba-a1", run_id="abba-a1", binary_sha=binary,
                label="final-a1", commit=COMMIT_FINAL,
                elapsed=[1.0] * 15,
            )
            second = make_bundle(
                root, "abba-a2", run_id="abba-a2", binary_sha=binary,
                label="final-a2", commit=COMMIT_FINAL,
                elapsed=[2.0] * 15,
            )
            manifest_path = second / "run-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["startup_memory"] = {
                "rss_kib": 2000,
                "high_water_kib": 3000,
            }
            _write_json(manifest_path, manifest)

            output = root / "merged"
            merge_result_directories([first, second], output)
            merged = json.loads(
                (output / "merged-raw-results.json").read_text()
            )

            self.assertEqual(len(merged["release_summaries"]), 1)
            summary = merged["release_summaries"][0]
            self.assertEqual(summary["source_run_ids"], ["abba-a1", "abba-a2"])
            self.assertEqual(summary["n"], 30)
            self.assertEqual(summary["startup_rss_kib"], 1500.0)
            self.assertEqual(summary["startup_high_water_kib"], 2000.0)
            self.assertEqual(summary["startup_rss_kib_summary"]["n"], 2)
            self.assertEqual(summary["startup_high_water_kib_summary"]["n"], 2)
            self.assertEqual(summary["startup_rss_kib_by_run"], {
                "abba-a1": 1000.0,
                "abba-a2": 2000.0,
            })
            self.assertEqual(summary["startup_high_water_kib_by_run"], {
                "abba-a1": 1000.0,
                "abba-a2": 3000.0,
            })

    def test_distinct_backend_closures_do_not_pool_but_can_compare(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "8" * 64
            baseline = make_bundle(
                root, "baseline", run_id="baseline", binary_sha=binary,
                label="dominant-family-ranking",
                commit="9c23a6e424ae4917a2fbf9e5815a9c517b6cf36a",
                backend_closure_variant="backend-a", elapsed=[2.0] * 15,
            )
            candidate = make_bundle(
                root, "candidate", run_id="candidate", binary_sha=binary,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                backend_closure_variant="backend-b", elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([candidate, baseline], output)
            artifacts = json.loads((output / "artifact-manifest.json").read_text())
            self.assertEqual(len(artifacts["binary_groups"]), 1)
            binary_group = artifacts["binary_groups"][0]
            self.assertEqual(binary_group["performance_identity_count"], 2)
            self.assertEqual(
                len(binary_group["behavioral_runtime_identity_groups"]), 2,
            )
            self.assertEqual(
                binary_group["commit_labels"],
                ["dominant-family-ranking", "final"],
            )

            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(len(merged["release_summaries"]), 2)
            self.assertEqual({item["n"] for item in merged["release_summaries"]}, {15})
            self.assertEqual(len(merged["release_comparisons"]), 1)
            comparison = merged["release_comparisons"][0]
            self.assertEqual(
                comparison["baseline_runtime_closure_sha256"],
                comparison["candidate_runtime_closure_sha256"],
            )
            self.assertNotEqual(
                comparison["baseline_backend_runtime_closure_sha256"],
                comparison["candidate_backend_runtime_closure_sha256"],
            )
            self.assertNotEqual(
                comparison["baseline_behavioral_runtime_identity_sha256"],
                comparison["candidate_behavioral_runtime_identity_sha256"],
            )

    def test_static_openldap_backend_closure_is_strictly_audited(self) -> None:
        executable_sha = "7" * 64
        closure = synthetic_openldap_static_backend_closure(executable_sha)
        manifest = {
            "backend_runtime_module_closure": closure,
            "backend_runtime_closure_sha256": closure["identity_sha256"],
        }
        server_executable = {
            "executable_name": "slapd",
            "executable_path": "/usr/sbin/slapd",
            "executable_sha256": executable_sha,
            "owning_package": "openldap-servers-0:2.6.13-1.fc42.x86_64",
        }
        self.assertEqual(
            _validate_backend_runtime_closure(
                manifest, "synthetic static closure",
                server_executable=server_executable,
            ),
            closure["identity_sha256"],
        )

        def wrong_source(record: dict[str, Any]) -> None:
            record["source"] = "operator-assertion"

        def invalid_pid(record: dict[str, Any]) -> None:
            record["pid"] = 0

        def wrong_maps_path(record: dict[str, Any]) -> None:
            record["maps_path"] = "/tmp/maps"

        def live_executable_mismatch(record: dict[str, Any]) -> None:
            record["live_executable"]["sha256"] = "8" * 64

        def missing_static_proof(record: dict[str, Any]) -> None:
            record["static_backend_evidence"] = None

        def tampered_inventory(record: dict[str, Any]) -> None:
            record["static_backend_evidence"]["raw"] += "    perl\n"

        def invented_role(record: dict[str, Any]) -> None:
            record["modules"][0]["roles"].append("invented-backend-role")

        def malformed_mapped_path(record: dict[str, Any]) -> None:
            record["modules"][0]["mapped_paths"].append({"path": "/tmp/decoy"})

        def stale_identity_material(record: dict[str, Any]) -> None:
            record["identity_material"]["live_executable_sha256"] = "9" * 64

        def noncanonical_required_roles(record: dict[str, Any]) -> None:
            record["required_roles"].append("database-engine")

        def malformed_assigned_role(record: dict[str, Any]) -> None:
            record["static_backend_evidence"]["assigned_roles"] = [{}]

        def overassigned_static_role(record: dict[str, Any]) -> None:
            engine_module = {
                "path": "/usr/lib64/liblmdb.so.0",
                "mapped_paths": ["/usr/lib64/liblmdb.so.0"],
                "sha256": "6" * 64,
                "rpm_owner": "lmdb-libs-0:0.9.33-2.fc42.x86_64",
                "rpm_owner_query_returncode": 0,
                "roles": ["database-engine"],
            }
            record["modules"].append(engine_module)
            record["identity_material"]["modules"].append({
                "sha256": engine_module["sha256"],
                "roles": list(engine_module["roles"]),
            })
            record["identity_material"]["modules"].sort(
                key=lambda module: (module["roles"], module["sha256"])
            )

        def footer_backend_token(record: dict[str, Any]) -> None:
            static = record["static_backend_evidence"]
            static["raw"] = static["raw"].replace(
                "    mdb\n", "Unrelated diagnostics:\nmdb\n",
            )
            static["inventory_sha256"] = hashlib.sha256(
                static["raw"].encode("utf-8")
            ).hexdigest()

        cases = {
            "source": (wrong_source, "closure source is invalid"),
            "pid": (invalid_pid, "closure PID is invalid"),
            "maps-path": (wrong_maps_path, "closure maps path is invalid"),
            "live-executable": (
                live_executable_mismatch,
                "not bound to the installed executable identity",
            ),
            "missing-static-proof": (
                missing_static_proof,
                "executable carries backend roles without static proof",
            ),
            "tampered-inventory": (
                tampered_inventory,
                "static backend inventory bytes are inconsistent",
            ),
            "invented-role": (invented_role, "noncanonical roles"),
            "malformed-mapped-path": (
                malformed_mapped_path,
                "mapped paths are invalid",
            ),
            "stale-identity-material": (
                stale_identity_material,
                "identity material is noncanonical",
            ),
            "noncanonical-required-roles": (
                noncanonical_required_roles,
                "required roles are not canonical",
            ),
            "malformed-assigned-role": (
                malformed_assigned_role,
                "static backend roles are not bound to live slapd",
            ),
            "overassigned-static-role": (
                overassigned_static_role,
                "static backend roles are not bound to live slapd",
            ),
            "footer-backend-token": (
                footer_backend_token,
                "static backend inventory bytes are inconsistent",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                changed_manifest = deepcopy(manifest)
                mutate(changed_manifest["backend_runtime_module_closure"])
                with self.assertRaisesRegex(MergeError, expected_error):
                    _validate_backend_runtime_closure(
                        changed_manifest, f"synthetic static closure {name}",
                        server_executable=server_executable,
                    )

    def test_dynamic_backend_module_provenance_is_strictly_audited(self) -> None:
        executable_sha = "5" * 64
        closure = synthetic_backend_closure("strict-dynamic", executable_sha)
        manifest = {
            "backend_runtime_module_closure": closure,
            "backend_runtime_closure_sha256": closure["identity_sha256"],
        }
        server_executable = {
            "executable_name": "ns-slapd",
            "executable_path": "/usr/bin/ns-slapd",
            "executable_sha256": executable_sha,
            "owning_package": "389-ds-base-0:3.0-1.fc43.x86_64",
        }
        self.assertEqual(
            _validate_backend_runtime_closure(
                manifest, "synthetic dynamic closure",
                server_executable=server_executable,
            ),
            closure["identity_sha256"],
        )

        def unrelated_mapping(record: dict[str, Any]) -> None:
            module = next(
                module for module in record["modules"]
                if module["roles"] == ["database-engine"]
            )
            module["path"] = "/tmp/unrelated.so"
            module["mapped_paths"] = ["/tmp/unrelated.so"]

        def unrelated_resolved_path(record: dict[str, Any]) -> None:
            module = next(
                module for module in record["modules"]
                if module["roles"] == ["database-engine"]
            )
            module["path"] = "/tmp/unrelated.so"

        def boolean_format(record: dict[str, Any]) -> None:
            record["format_version"] = True

        def blank_owner(record: dict[str, Any]) -> None:
            record["modules"][0]["rpm_owner"] = "   "

        def boolean_owner_returncode(record: dict[str, Any]) -> None:
            record["modules"][0]["rpm_owner_query_returncode"] = False

        cases = {
            "unrelated-mapping": (
                unrelated_mapping,
                "role attribution does not match its mapped path basenames",
            ),
            "unrelated-resolved-path": (
                unrelated_resolved_path,
                "role attribution does not match its mapped path basenames",
            ),
            "boolean-format": (boolean_format, "not observed v1"),
            "blank-owner": (blank_owner, "lacks RPM owner"),
            "boolean-owner-returncode": (
                boolean_owner_returncode,
                "RPM ownership was not proved",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                changed_manifest = deepcopy(manifest)
                mutate(changed_manifest["backend_runtime_module_closure"])
                with self.assertRaisesRegex(MergeError, expected_error):
                    _validate_backend_runtime_closure(
                        changed_manifest, f"synthetic dynamic closure {name}",
                        server_executable=server_executable,
                    )
    def test_tampered_behavioral_runtime_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "tampered", run_id="tampered", binary_sha="9" * 64,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
            )
            run_path = bundle / "run-manifest.json"
            run_manifest = json.loads(run_path.read_text())
            run_manifest["behavioral_runtime_identity_sha256"] = "0" * 64
            _write_json(run_path, run_manifest)
            with self.assertRaisesRegex(
                    MergeError, "behavioral runtime identity mismatch"):
                merge_result_directories([bundle], root / "merged")

    def test_runtime_target_and_rows_must_match_executed_configuration(self) -> None:
        def run_server(
                _artifact: dict[str, Any], run: dict[str, Any],
                _raw: dict[str, Any]) -> None:
            run["server"] = "openldap"

        def run_backend(
                _artifact: dict[str, Any], run: dict[str, Any],
                _raw: dict[str, Any]) -> None:
            run["backend_actual"] = "bdb"

        def row_server(
                _artifact: dict[str, Any], _run: dict[str, Any],
                raw: dict[str, Any]) -> None:
            raw["rows"][0]["server"] = "openldap"

        def row_backend(
                _artifact: dict[str, Any], _run: dict[str, Any],
                raw: dict[str, Any]) -> None:
            raw["rows"][0]["backend"] = "bdb"

        def row_lookup(
                _artifact: dict[str, Any], _run: dict[str, Any],
                raw: dict[str, Any]) -> None:
            raw["rows"][0]["lookup_mode"] = "off"

        def executable_name(
                artifact: dict[str, Any], _run: dict[str, Any],
                _raw: dict[str, Any]) -> None:
            artifact["server_executable"]["executable_name"] = "slapd"

        cases = {
            "run-server": (run_server, "artifact/run server or actual backend"),
            "run-backend": (
                run_backend,
                "backend runtime closure target disagrees",
            ),
            "row-server": (row_server, "row server disagrees with run manifest"),
            "row-backend": (row_backend, "row backend disagrees with run manifest"),
            "row-lookup": (
                row_lookup, "row lookup mode disagrees with run manifest",
            ),
            "executable-name": (
                executable_name,
                "installed executable path is invalid",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="3" * 64,
                    label="final", commit=COMMIT_FINAL,
                )
                artifact_path = bundle / "artifact-manifest.json"
                run_path = bundle / "run-manifest.json"
                raw_path = bundle / "raw-results.json"
                artifact = json.loads(artifact_path.read_text())
                run = json.loads(run_path.read_text())
                raw = json.loads(raw_path.read_text())
                mutate(artifact, run, raw)
                _write_json(artifact_path, artifact)
                _write_json(run_path, run)
                _write_json(raw_path, raw)
                with self.assertRaisesRegex(MergeError, expected_error):
                    merge_result_directories([bundle], root / "merged")

    def test_same_binary_final_lookup_off_on_comparison_is_generated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "f" * 64
            commit = "e0161d0e61d0cdef22175418f0d4a1e126216a86"
            lookup_off = make_bundle(
                root, "off", run_id="final-off", binary_sha=binary,
                label="final", commit=commit, lookup_mode="off",
                elapsed=[5.0] * 15,
            )
            lookup_on = make_bundle(
                root, "on", run_id="final-on", binary_sha=binary,
                label="final", commit=commit, lookup_mode="on",
                elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([lookup_on, lookup_off], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(len(merged["release_summaries"]), 2)
            self.assertEqual(len(merged["release_comparisons"]), 1)
            comparison = merged["release_comparisons"][0]
            self.assertEqual(comparison["baseline_binary_id"], binary[:16])
            self.assertEqual(comparison["candidate_binary_id"], binary[:16])
            self.assertEqual(comparison["baseline_lookup_mode"], "off")
            self.assertEqual(comparison["candidate_lookup_mode"], "on")
            self.assertNotIn("lookup_mode", comparison["configuration"])
            self.assertEqual(
                comparison["baseline_configuration"]["backend"],
                comparison["candidate_configuration"]["backend"],
            )
            report = (output / "RESULTS.md").read_text()
            self.assertIn("baseline lookup", report)
            self.assertIn("candidate lookup", report)

    def test_study_tip_toggle_uses_final_role_without_forging_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "a" * 64
            lookup_off = make_bundle(
                root, "study-off", run_id="study-off", binary_sha=binary,
                label="final-study-tip", commit=COMMIT_STUDY_TIP,
                lookup_mode="off", elapsed=[5.0] * 15,
            )
            lookup_on = make_bundle(
                root, "study-on", run_id="study-on", binary_sha=binary,
                label="final-study-tip", commit=COMMIT_STUDY_TIP,
                lookup_mode="on", elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([lookup_off, lookup_on], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            summaries = merged["release_summaries"]
            off, on, reason = _toggle_pair(summaries, "case")
            self.assertEqual(reason, "")
            self.assertIsNotNone(off)
            self.assertIsNotNone(on)
            artifact = json.loads(
                (output / "artifact-manifest.json").read_text()
            )
            group = artifact["binary_groups"][0]
            self.assertEqual(group["source_commits"], [COMMIT_STUDY_TIP])
            self.assertEqual(group["production_commits"], [COMMIT_FINAL])
            self.assertEqual(group["revision_roles"], ["final"])

    def test_legacy_bundle_may_omit_redundant_revision_role(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "legacy-role", run_id="legacy-role",
                binary_sha="d" * 64, label="final", commit=COMMIT_FINAL,
            )
            run_path = bundle / "run-manifest.json"
            run = json.loads(run_path.read_text())
            del run["revision_role"]
            _write_json(run_path, run)
            raw_path = bundle / "raw-results.json"
            raw = json.loads(raw_path.read_text())
            for row in raw["rows"]:
                del row["revision_role"]
            _write_json(raw_path, raw)

            output = root / "merged"
            merge_result_directories([bundle], output)
            artifact = json.loads(
                (output / "artifact-manifest.json").read_text()
            )
            self.assertEqual(
                artifact["binary_groups"][0]["revision_roles"], ["final"],
            )

    def test_nested_artifact_cannot_inject_another_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "e" * 64
            bundle = make_bundle(
                root, "nested-forgery", run_id="nested-forgery",
                binary_sha=binary, label="final-study-tip",
                commit=COMMIT_STUDY_TIP,
            )
            artifact_path = bundle / "artifact-manifest.json"
            artifact = json.loads(artifact_path.read_text())
            artifact["unrelated_audit_note"] = {
                "server": "389ds",
                "expected_source_sha": COMMIT_BOUNDED,
                "production_equivalent_revision": COMMIT_BOUNDED,
                "revision_role": "bounded-feature",
                "executable_sha256": binary,
                "runtime_closure_sha256": artifact[
                    "runtime_closure_sha256"
                ],
                "backend_runtime_closure_sha256": artifact[
                    "backend_runtime_closure_sha256"
                ],
                "behavioral_runtime_identity_sha256": artifact[
                    "behavioral_runtime_identity_sha256"
                ],
            }
            _write_json(artifact_path, artifact)
            with self.assertRaisesRegex(
                    MergeError, "source revision contradicts the bundle root"):
                merge_result_directories([bundle], root / "merged")

    def test_openldap_package_token_is_not_a_production_commit(self) -> None:
        self.assertIsNone(_artifact_production_commit(
            {"production_equivalent_revision": None},
            "fedora-package", "openldap",
        ))

    def test_runtime_lock_ghost_ownership_delta_retains_rpm_proof(self) -> None:
        verify = {
            "returncode": 1,
            "stdout": ".....UG..  g /var/lock/dirsrv\n",
            "stderr": "",
            "clean": False,
            "accepted": True,
            "acceptance_policy": (
                "strict-clean-or-dirsrv-runtime-lock-ghost-ownership-v1"
            ),
            "accepted_via_runtime_ghost_allowlist": True,
            "allowed_differences": [{
                "flags": ".....UG..",
                "file_type": "g",
                "path": "/var/lock/dirsrv",
            }],
            "unexpected_differences": [],
            "runtime_lock_metadata": {
                "status": "observed",
                "path": "/var/lock/dirsrv",
                "is_directory": True,
                "is_symlink": False,
                "mode": "0770",
                "owner": "dirsrv",
                "group": "dirsrv",
            },
        }
        record = {
            "owning_package": "389-ds-base-3.3.0-1.fc44.x86_64",
            "package_nevra": "389-ds-base-3.3.0-1.fc44.x86_64",
            "rpm_verify": verify,
        }
        self.assertTrue(_rpm_proved(record))
        for name, mutate in {
            "extra-path": lambda value: value["allowed_differences"].append({
                "flags": ".......T.", "file_type": None,
                "path": "/usr/share/dirsrv/schema/30ns-common.ldif",
            }),
            "raw-extra-path": lambda value: value.update({
                "stdout": (
                    ".....UG..  g /var/lock/dirsrv\n"
                    "S.5....T.  c /etc/dirsrv/config/template-dse.ldif\n"
                ),
            }),
            "raw-warning": lambda value: value.update({
                "stderr": "rpm verification warning\n",
            }),
            "wrong-owner": lambda value: value["runtime_lock_metadata"].update({
                "owner": "root",
            }),
            "forged-clean": lambda value: value.update({"clean": True}),
        }.items():
            with self.subTest(name=name):
                changed = deepcopy(record)
                mutate(changed["rpm_verify"])
                self.assertFalse(_rpm_proved(changed))

    def test_bundle_cannot_forge_production_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "forged", run_id="forged", binary_sha="b" * 64,
                label="final-study-tip", commit=COMMIT_STUDY_TIP,
            )
            artifact_path = bundle / "artifact-manifest.json"
            artifact = json.loads(artifact_path.read_text())
            artifact["production_equivalent_revision"] = COMMIT_9C
            _write_json(artifact_path, artifact)
            with self.assertRaisesRegex(
                    MergeError, "contradicts the committed revision plan"):
                merge_result_directories([bundle], root / "merged")

    def test_pre_series_unsupported_to_final_on_comparison_is_generated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pre = make_bundle(
                root, "pre", run_id="pre-unsupported", binary_sha="1" * 64,
                label="pre-series",
                commit="6e1e933745313622593d943e983ff710de8db732",
                lookup_mode="unsupported", elapsed=[8.0] * 15,
            )
            final = make_bundle(
                root, "final", run_id="final-on", binary_sha="2" * 64,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                lookup_mode="on", elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([final, pre], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(len(merged["release_comparisons"]), 1)
            comparison = merged["release_comparisons"][0]
            self.assertEqual(comparison["baseline_labels"], ["pre-series"])
            self.assertEqual(comparison["candidate_labels"], ["final"])
            self.assertEqual(comparison["baseline_lookup_mode"], "unsupported")
            self.assertEqual(comparison["candidate_lookup_mode"], "on")
            self.assertEqual(
                {key: value for key, value in comparison["baseline_configuration"].items()
                 if key != "lookup_mode"},
                comparison["configuration"],
            )
            self.assertEqual(
                {key: value for key, value in comparison["candidate_configuration"].items()
                 if key != "lookup_mode"},
                comparison["configuration"],
            )

    def test_perf_modes_are_separate_strata_and_never_compared(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "3" * 64
            commit = "e0161d0e61d0cdef22175418f0d4a1e126216a86"
            perf_auto = make_bundle(
                root, "perf-auto", run_id="perf-auto", binary_sha=binary,
                label="final", commit=commit, perf_mode="auto",
                elapsed=[1.0] * 15,
            )
            perf_off = make_bundle(
                root, "perf-off", run_id="perf-off", binary_sha=binary,
                label="final", commit=commit, perf_mode="off",
                elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([perf_auto, perf_off], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(len(merged["release_summaries"]), 2)
            self.assertEqual(
                {summary["configuration"]["perf_mode"]
                 for summary in merged["release_summaries"]},
                {"auto", "off"},
            )
            self.assertEqual(merged["release_comparisons"], [])

    def test_instruction_statistics_use_unique_independent_perf_batches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "perf", run_id="perf", binary_sha="4" * 64,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                elapsed=[1.0] * 15,
            )
            add_independent_perf_batches(bundle, base_instructions=20_000)
            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            summary = merged["release_summaries"][0]
            self.assertEqual(summary["instructions"]["n"], 15)
            self.assertEqual(summary["instructions"]["median"], 20_700.0)
            self.assertEqual(len(summary["instruction_batch_ids"]), 15)
            self.assertEqual(
                summary["instructions_sample_semantics"],
                "one-independent-perf-batch-normalized-per-search",
            )
            self.assertEqual(len(merged["perf_batches"]), 15)
            self.assertIn(
                "15 independent perf batches/15 elapsed rows",
                summary["metric_coverage"]["instructions"],
            )

    def test_perf_batch_structure_and_bidirectional_links_are_strict(self) -> None:
        def forge_collection(payload: dict[str, Any]) -> None:
            batch = payload["perf_batches"][0]
            batch.update({
                "events": ["task-clock"],
                "software_fallback": True,
                "unavailable_events": [],
                "collection_class": "hardware-events",
                "collection_signature": "1" * 64,
            })
            linked = next(
                row for row in payload["rows"]
                if row["row_id"] == batch["row_ids"][0]
            )
            linked.update({
                "perf_collection_class": "hardware-events",
                "perf_collection_signature": "1" * 64,
            })

        mutations = {
            "missing-raw-aggregate": lambda payload: (
                payload["perf_batches"][0].pop("event_counts")
            ),
            "too-many-operations": lambda payload: (
                payload["perf_batches"][0].update({
                    "operation_count": 2,
                    "row_ids": [
                        payload["rows"][0]["row_id"],
                        payload["rows"][1]["row_id"],
                    ],
                    "event_counts": {"instructions": 40_000},
                    "event_counts_per_search": {"instructions": 20_000},
                }),
                payload["rows"][1].update({
                    "perf_batch_id": payload["perf_batches"][0]["batch_id"],
                }),
                payload["perf_batches"].pop(1),
            ),
            "duplicate-row-id": lambda payload: payload["perf_batches"][0].update({
                "row_ids": [payload["rows"][0]["row_id"]] * 2,
                "operation_count": 2,
            }),
            "broken-back-link": lambda payload: payload["rows"][0].update({
                "perf_batch_id": "different-batch",
            }),
            "forged-collection": forge_collection,
        }
        expected = {
            "missing-raw-aggregate": "missing aggregate\\(s\\): instructions",
            "too-many-operations": "operation_count must be 1..1",
            "duplicate-row-id": "row_ids must be unique",
            "broken-back-link": "does not bind back",
            "forged-collection": "declared perf collection class disagrees",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, "perf", run_id=name, binary_sha="5" * 64,
                    label="final",
                    commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                    elapsed=[1.0] * 15,
                )
                add_independent_perf_batches(bundle)
                raw_path = bundle / "raw-results.json"
                payload = json.loads(raw_path.read_text())
                mutate(payload)
                _write_json(raw_path, payload)
                with self.assertRaisesRegex(MergeError, expected[name]):
                    merge_result_directories([bundle], root / "merged")

    def test_all_explicit_gate_ids_are_emitted_and_missing_instances_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "one", run_id="one", binary_sha="6" * 64,
                label="final",
                commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                elapsed=[1.0] * 15,
            )
            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            declared = [
                gate["id"] for gate in json.loads(
                    (STUDY_ROOT / "workload" / "acceptance-gates.json").read_text()
                )["gates"]
            ]
            explicit = merged["acceptance_gate_results"]
            self.assertEqual([gate["gate_id"] for gate in explicit], declared)
            self.assertEqual(len(explicit), 10)
            by_id = {gate["gate_id"]: gate for gate in explicit}
            self.assertEqual(by_id["exact-result-parity"]["status"], "pass")
            self.assertEqual(
                by_id["principal-consumed-lookup-cost"]["status"], "pending",
            )
            self.assertGreater(
                by_id["selection-fix-retention"]["pending_count"], 0,
            )
            self.assertEqual(merged["acceptance_gate_overall_status"], "pending")
            report = (output / "RESULTS.md").read_text()
            self.assertIn("## Authoritative acceptance gates", report)
            self.assertIn("descriptive only", report)
            self.assertIn("### Pending and failed instance reasons", report)
            self.assertIn("required unique final lookup-off/on pair", report)

    def test_historical_dynamic_failure_is_supporting_and_fixed_controls_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario_id = "dynamic-list-lookthrough-finite"
            dynamic_workload = workload_manifest()
            scenario = dynamic_workload["scenarios"].pop("case")
            scenario["expected_diagnostics"] = {
                "bounded_read": {
                    "expectation": "revision-dependent-dynamic-safety",
                    "revision_expectations": {
                        "combined-diagnostic": "required-pre-fix-diagnostic",
                        "dynamic-list-fix": "forbidden",
                        "final": "forbidden",
                    },
                },
            }
            dynamic_workload["scenarios"][scenario_id] = scenario
            dynamic_workload["scenario_groups"] = {
                "dynamic-list-correctness": [scenario_id],
            }
            commits = {
                "parent": "7c0b4f65637627be53ecc0b4d52bc9f8ec6f3bf6",
                "fixed": "038b8f58a305c1650ab0523a9d2658aabbc9848b",
                "final": "e0161d0e61d0cdef22175418f0d4a1e126216a86",
            }
            bundles = []
            for index, (role, commit) in enumerate(commits.items(), 7):
                bundle = make_bundle(
                    root, role, run_id=role, binary_sha=str(index) * 64,
                    label=role, commit=commit, workload=dynamic_workload,
                    elapsed=[1.0] * 15,
                )
                raw_path = bundle / "raw-results.json"
                _write_json(raw_path, {
                    "format_version": 1,
                    "correctness_only": False,
                    "release_timing_evidence": True,
                    "timing_claims_allowed": True,
                    "rows": [],
                    "perf_batches": [],
                })
                run_path = bundle / "run-manifest.json"
                run_manifest = json.loads(run_path.read_text())
                run_manifest["selected_scenarios"] = [scenario_id]
                run_manifest["raw_result_rows"] = 0
                _write_json(run_path, run_manifest)
                historical = role == "parent"
                operations: dict[str, dict[str, Any]] = {}
                for field in (
                        "ordinary_candidates", "augmented_candidates",
                        "final_search", "post_control_health"):
                    failed = historical and field == "final_search"
                    operation = exact_result_evidence(
                        passed=not failed,
                        result_code=(
                            "LDAP_ADMINLIMIT_EXCEEDED" if failed
                            else "LDAP_SUCCESS"
                        ),
                    )
                    operation["server_result_evidence"] = server_result_evidence(
                        passed=not failed,
                        result_code=(
                            "LDAP_ADMINLIMIT_EXCEEDED" if failed
                            else "LDAP_SUCCESS"
                        ),
                    )
                    operation["operation_isolated"] = True
                    operation["isolation"] = synthetic_isolation(
                        f"synthetic {role} {field}"
                    )
                    if field == "final_search":
                        candidate_values = [1, 20, 22, 1]
                        relative_log = (
                            f"diagnostics/{scenario_id}.final.error.log"
                        )
                        log_bytes = "".join(
                            f"Candidate list has {value} ids\n"
                            for value in candidate_values
                        ).encode("utf-8")
                        log_path = bundle / relative_log
                        log_path.parent.mkdir(parents=True, exist_ok=True)
                        log_path.write_bytes(log_bytes)
                        operation["diagnostics"] = {
                            "cap_path_observed": historical,
                            "candidate_list_values": candidate_values,
                            "candidate_list_status": (
                                "not-directly-observable-unattributed-traces"
                            ),
                            "observed_final_candidate_count": None,
                            "candidate_list_observation": {
                                "status": "not-directly-observable",
                                "reason": "production traces lack conn/op identity",
                                "raw_trace_count": len(candidate_values),
                                "parser_status": "ambiguous-multiple-traces",
                            },
                        }
                        operation["diagnostic_artifacts"] = {
                            "error_log": relative_log,
                            "error_log_sha256": hashlib.sha256(
                                log_bytes
                            ).hexdigest(),
                            "error_log_size_bytes": len(log_bytes),
                        }
                    operations[field] = operation
                _write_json(bundle / "correctness.json", {
                    "format_version": 1,
                    "correctness_only": False,
                    "release_timing_evidence": True,
                    "timing_claims_allowed": True,
                    "scenarios": [{
                        "scenario": scenario_id,
                        "correctness": (
                            "expected-historical-failure" if historical else "pass"
                        ),
                        "historical_baseline": historical,
                        "evidence_status": (
                            "expected-historical-admin-limit-observed"
                            if historical else "observed"
                        ),
                        "expected_final_count": 0,
                        "expected_final_sha256": EMPTY_DN_SHA256,
                        "ldap_adminlimit_exceeded": historical,
                        **operations,
                    }],
                })
                bundles.append(bundle)

            output = root / "merged"
            merge_result_directories(bundles, output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            controls = {
                control["run_id"]: control
                for control in merged["correctness_controls"]
            }
            self.assertTrue(controls["parent"]["supporting_historical_failure"])
            self.assertFalse(controls["parent"]["oracle_passed"])
            self.assertEqual(controls["parent"]["dynamic_cap_status"], "pass")
            self.assertEqual(controls["fixed"]["dynamic_cap_status"], "pass")
            self.assertEqual(controls["final"]["dynamic_cap_status"], "pass")

            final_bundle = bundles[-1]
            correctness_path = final_bundle / "correctness.json"
            correctness = json.loads(correctness_path.read_text())
            diagnostics = correctness["scenarios"][0]["final_search"][
                "diagnostics"
            ]
            diagnostics["candidate_list_values"] = [777, 888]
            diagnostics["candidate_list_observation"]["raw_trace_count"] = 2
            diagnostics["candidate_list_observation"][
                "parser_status"
            ] = "ambiguous-multiple-traces"
            _write_json(correctness_path, correctness)
            with self.assertRaisesRegex(
                    MergeError,
                    "candidate-list traces differ from the dynamic error log"):
                merge_result_directories(bundles, root / "forged-json")

            diagnostics["candidate_list_values"] = [1, 20, 22, 1]
            diagnostics["candidate_list_observation"]["raw_trace_count"] = 4
            _write_json(correctness_path, correctness)
            log_path = (
                final_bundle / "diagnostics"
                / f"{scenario_id}.final.error.log"
            )
            original_log_bytes = log_path.read_bytes()
            log_path.write_bytes(
                original_log_bytes.replace(b"22 ids", b"99 ids")
            )
            with self.assertRaisesRegex(
                    MergeError, "declared artifact identity differs"):
                merge_result_directories(bundles, root / "forged-log")
            log_path.write_bytes(original_log_bytes)
            self.assertTrue(any(
                operation["status"] == "fail"
                for operation in controls["parent"]["exact_operations"]
            ))
            gates = {
                gate["gate_id"]: gate
                for gate in merged["acceptance_gate_results"]
            }
            self.assertEqual(gates["exact-result-parity"]["status"], "pass")
            dynamic_instance = next(
                item for item in gates["no-new-result-or-admin-limit"]["instances"]
                if item["instance_id"] == f"dynamic:{scenario_id}"
            )
            self.assertEqual(dynamic_instance["status"], "pass")
            self.assertEqual(
                dynamic_instance["classification"], "demonstrated improvement",
            )
            self.assertTrue(
                dynamic_instance["computed"]["historical_parent_failure_observed"]
            )

            fixed_path = bundles[1] / "correctness.json"
            fixed_manifest = json.loads(fixed_path.read_text())
            fixed_manifest["scenarios"][0]["final_search"]["diagnostics"][
                "cap_path_observed"
            ] = True
            _write_json(fixed_path, fixed_manifest)
            second_output = root / "merged-cap-mismatch"
            merge_result_directories(bundles, second_output)
            second = json.loads(
                (second_output / "merged-raw-results.json").read_text()
            )
            second_gates = {
                gate["gate_id"]: gate
                for gate in second["acceptance_gate_results"]
            }
            self.assertEqual(
                second_gates["no-new-result-or-admin-limit"]["status"], "fail",
            )

    def test_server_ldap_result_evidence_controls_release_and_exact_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "server-code", run_id="server-code", binary_sha="1" * 64,
                label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            raw_path = bundle / "raw-results.json"
            raw = json.loads(raw_path.read_text())
            raw["rows"][0]["server_result_code"] = 11
            raw["rows"][0]["server_result_evidence"][
                "actual_server_result_code"
            ] = 11
            _write_json(raw_path, raw)
            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertFalse(merged["rows"][0]["correctness"]["passed"])
            self.assertFalse(merged["rows"][0]["release_eligible"])
            exact = next(
                gate for gate in merged["acceptance_gate_results"]
                if gate["gate_id"] == "exact-result-parity"
            )
            self.assertEqual(exact["status"], "fail")

    def test_native_row_and_perf_collections_require_quiet_window_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "quiet-collections", run_id="quiet-collections",
                binary_sha="1" * 64, label="final", commit=COMMIT_FINAL,
                elapsed=[1.0] * 15,
            )
            add_independent_perf_batches(bundle)
            raw_path = bundle / "raw-results.json"
            raw = json.loads(raw_path.read_text())
            row_guard = raw["rows"][0]["background_quiet_window"]
            row_guard["end_monotonic_seconds"] = row_guard[
                "deadline_monotonic_seconds"
            ]
            row_guard["duration_seconds"] = (
                row_guard["end_monotonic_seconds"]
                - row_guard["start_monotonic_seconds"]
            )
            perf_guard = raw["perf_batches"][1]["background_quiet_window"]
            perf_guard["passed"] = False
            _write_json(raw_path, raw)

            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            rows = {row["row_id"]: row for row in merged["rows"]}
            self.assertFalse(rows["row-0"]["release_eligible"])
            self.assertIn(
                "background quiet-window collection crossed",
                " ".join(rows["row-0"]["release_exclusion_reasons"]),
            )
            self.assertTrue(rows["row-1"]["release_eligible"])
            batches = {
                batch["batch_id"]: batch for batch in merged["perf_batches"]
            }
            self.assertTrue(batches[f"{bundle.name}:perf:0"]["usable"])
            self.assertFalse(batches[f"{bundle.name}:perf:1"]["usable"])
            self.assertIn(
                "did not pass",
                batches[f"{bundle.name}:perf:1"][
                    "background_quiet_window_validation"
                ]["reason"],
            )

    def test_native_profile_requires_quiet_window_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "quiet-profile", run_id="quiet-profile",
                binary_sha="2" * 64, label="final", commit=COMMIT_FINAL,
                elapsed=[1.0] * 15,
            )
            run_path = bundle / "run-manifest.json"
            run = json.loads(run_path.read_text())
            profiles_dir = bundle / "profiles"
            profiles_dir.mkdir()
            profile_bytes = b"synthetic perf data\n"
            report_bytes = b"synthetic perf report without lookup symbols\n"
            (profiles_dir / "case.perf.data").write_bytes(profile_bytes)
            (profiles_dir / "case.perf.data.report.txt").write_bytes(
                report_bytes
            )
            run["profiles"] = [{
                "scenario": "case",
                "status": "observed",
                "evidence_status": "observed",
                "background_quiet_window": (
                    synthetic_background_quiet_collection(
                        "synthetic profile case"
                    )
                ),
                "exact_result": exact_result_evidence(),
                "server_result_evidence": server_result_evidence(),
                "profile_artifact": {
                    "evidence_status": "observed",
                    "path": "profiles/case.perf.data",
                    "sha256": hashlib.sha256(profile_bytes).hexdigest(),
                    "size_bytes": len(profile_bytes),
                },
                "report": {
                    "status": "observed",
                    "path": "profiles/case.perf.data.report.txt",
                    "sha256": hashlib.sha256(report_bytes).hexdigest(),
                    "size_bytes": len(report_bytes),
                },
                "lookup_consumption": {
                    "status": "unresolved",
                    "evidence_status": "observed",
                    "sampled_symbols": [],
                    "symbol_line_counts": {
                        "vattr_test_filter_or_lookup": 0,
                        "filter_or_lookup_probe": 0,
                    },
                },
            }]
            run["profiles"][0]["background_quiet_window"]["passed"] = False
            _write_json(run_path, run)

            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(merged["release_summaries"], [])
            self.assertFalse(merged["release_timing_evidence"])
            self.assertIn(
                "profile 0: background quiet-window collection did not pass",
                " ".join(merged["rows"][0]["release_exclusion_reasons"]),
            )

    def test_profile_not_applicable_guard_is_limited_to_no_attach_statuses(self) -> None:
        for status, release_expected in (
                ("disabled", True), ("unavailable", True), ("failed", False)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, status, run_id=status, binary_sha="4" * 64,
                    label="final", commit=COMMIT_FINAL,
                    elapsed=[1.0] * 15,
                )
                run_path = bundle / "run-manifest.json"
                run = json.loads(run_path.read_text())
                run["profiles"] = [{
                    "scenario": "case",
                    "status": status,
                    "evidence_status": "not-planned",
                    "background_quiet_window": (
                        synthetic_not_applicable_quiet_collection(
                            f"synthetic {status} profile"
                        )
                    ),
                }]
                _write_json(run_path, run)
                output = root / "merged"
                merge_result_directories([bundle], output)
                merged = json.loads(
                    (output / "merged-raw-results.json").read_text()
                )
                self.assertEqual(
                    merged["rows"][0]["release_eligible"], release_expected,
                )
                if not release_expected:
                    self.assertIn(
                        "unexpectedly not-applicable",
                        " ".join(
                            merged["rows"][0]["release_exclusion_reasons"]
                        ),
                    )

    def test_native_correctness_collections_require_quiet_window_guards(self) -> None:
        def break_diagnostic(bundle: Path) -> None:
            path = bundle / "correctness.json"
            manifest = json.loads(path.read_text())
            guard = manifest["scenarios"][0]["diagnostic_flights"][
                "preflight"
            ]["isolation"]["background_quiet_window"]
            guard["passed"] = False
            _write_json(path, manifest)

        def break_selection(bundle: Path) -> None:
            path = bundle / "correctness.json"
            manifest = json.loads(path.read_text())
            preflight = manifest["scenarios"][0]["diagnostic_flights"][
                "preflight"
            ]
            preflight["selection_probe"] = {
                "evidence_status": "observed",
                "operation_isolated": True,
                "isolation": synthetic_isolation(
                    "synthetic selection probe"
                ),
                "exact_result": exact_result_evidence(),
                "server_result_evidence": server_result_evidence(),
            }
            preflight["selection_probe"]["isolation"][
                "background_quiet_window"
            ]["passed"] = False
            _write_json(path, manifest)

        def break_dynamic(bundle: Path) -> None:
            path = bundle / "correctness.json"
            manifest = json.loads(path.read_text())
            record = manifest["scenarios"][0]
            for field in (
                    "ordinary_candidates", "augmented_candidates",
                    "final_search", "post_control_health"):
                record[field] = {
                    "operation_isolated": True,
                    "isolation": synthetic_isolation(
                        f"synthetic dynamic {field}"
                    ),
                }
            record["final_search"]["isolation"][
                "background_quiet_window"
            ]["passed"] = False
            _write_json(path, manifest)

        def break_approximate(bundle: Path) -> None:
            path = bundle / "artifact-manifest.json"
            artifact = json.loads(path.read_text())
            artifact["approximate_semantics_evidence"] = {
                "status": "comparable",
                "evidence_status": "observed",
                "probes": [{
                    "probe_id": "synthetic-approximate",
                    "operation_isolated": True,
                    "isolation": synthetic_isolation(
                        "synthetic approximate probe"
                    ),
                }],
            }
            artifact["approximate_semantics_evidence"]["probes"][0][
                "isolation"
            ]["background_quiet_window"]["passed"] = False
            _write_json(path, artifact)

        cases = {
            "diagnostic": (break_diagnostic, "preflight"),
            "selection": (break_selection, "selection probe"),
            "dynamic": (break_dynamic, "final_search"),
            "approximate": (break_approximate, "approximate-semantics probe"),
        }
        for name, (mutate, expected_reason) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="3" * 64,
                    label="final", commit=COMMIT_FINAL,
                    elapsed=[1.0] * 15,
                )
                mutate(bundle)
                output = root / "merged"
                merge_result_directories([bundle], output)
                merged = json.loads(
                    (output / "merged-raw-results.json").read_text()
                )
                self.assertFalse(merged["rows"][0]["release_eligible"])
                self.assertIn(
                    expected_reason,
                    " ".join(merged["rows"][0]["release_exclusion_reasons"]),
                )

    def test_declared_schedule_and_control_operations_are_fully_accounted(self) -> None:
        def declare_six_rows(bundle: Path) -> None:
            path = bundle / "run-manifest.json"
            manifest = json.loads(path.read_text())
            manifest["repeat_count"] = 6
            _write_json(path, manifest)

        def remove_postflight(bundle: Path) -> None:
            path = bundle / "correctness.json"
            manifest = json.loads(path.read_text())
            manifest["scenarios"][0]["diagnostic_flights"].pop("postflight")
            _write_json(path, manifest)

        mutations = {
            "missing-measured-row": declare_six_rows,
            "missing-postflight": remove_postflight,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="2" * 64,
                    label="final", commit=COMMIT_FINAL,
                )
                mutate(bundle)
                output = root / "merged"
                merge_result_directories([bundle], output)
                merged = json.loads(
                    (output / "merged-raw-results.json").read_text()
                )
                exact = next(
                    gate for gate in merged["acceptance_gate_results"]
                    if gate["gate_id"] == "exact-result-parity"
                )
                self.assertEqual(exact["status"], "pending")
                reasons = " ".join(
                    str(item["reason"]) for item in exact["instances"]
                    if item["status"] == "pending"
                )
                self.assertRegex(reasons, "rows|postflight|incomplete")

    def test_contradictory_timing_markers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "markers", run_id="markers", binary_sha="3" * 64,
                label="final", commit=COMMIT_FINAL,
            )
            run_path = bundle / "run-manifest.json"
            run = json.loads(run_path.read_text())
            run["timing_claims_allowed"] = False
            _write_json(run_path, run)
            with self.assertRaisesRegex(
                    MergeError, "contradictory timing_claims_allowed"):
                merge_result_directories([bundle], root / "merged")

    def test_native_release_requires_exact_live_schema_semantic_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "schema", run_id="schema", binary_sha="3" * 64,
                label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            run_path = bundle / "run-manifest.json"
            run = json.loads(run_path.read_text())
            verification = run["server_setup"]["effective_schema"][
                "custom_schema_verification"
            ]
            verification["semantic_contract"]["attribute_types"][
                "1.3.6.1.4.1.2312.999.2026.100.1"
            ]["equality"] = "caseExactMatch"
            verification["semantic_contract_sha256"] = hashlib.sha256(
                canonical_json_bytes(verification["semantic_contract"])
            ).hexdigest()
            _write_json(run_path, run)
            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(merged["release_summaries"], [])
            self.assertFalse(merged["release_timing_evidence"])
            self.assertIn(
                "semantic contract is invalid",
                " ".join(merged["rows"][0]["release_exclusion_reasons"]),
            )

    def test_artifact_and_run_runner_evidence_must_match(self) -> None:
        paths = {
            "harness_identity": ("harness_identity",),
            "import_verification": (
                "server_setup", "import_verification", "oracles", "people",
                "actual_count",
            ),
            "lookup_mode_evidence": (
                "server_setup", "lookup_mode_evidence", "actual_readback",
            ),
            "index_build_evidence": (
                "server_setup", "index_build_evidence", "reindex", "completed",
            ),
            "background_referral_check_control": (
                "server_setup", "background_referral_check_control",
                "barrier", "completion_line_count",
            ),
        }
        for field, path in paths.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, field, run_id=field, binary_sha="8" * 64,
                    label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
                )
                run_path = bundle / "run-manifest.json"
                run = json.loads(run_path.read_text())
                if field == "harness_identity":
                    run["harness_identity"]["git_head"] = "3" * 40
                else:
                    target = run
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = (
                        99_999 if field == "import_verification"
                        else "off" if field == "lookup_mode_evidence"
                        else 2 if field == "background_referral_check_control"
                        else False
                    )
                _write_json(run_path, run)
                output = root / "merged"
                merge_result_directories([bundle], output)
                merged = json.loads(
                    (output / "merged-raw-results.json").read_text()
                )
                self.assertEqual(merged["release_summaries"], [])
                self.assertIn(
                    f"artifact/run {field}",
                    " ".join(merged["rows"][0]["release_exclusion_reasons"]),
                )

    def test_native_release_requires_complete_runner_evidence(self) -> None:
        def harness_content(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for manifest in (artifact, run):
                manifest["harness_identity"]["files"][
                    "study/run_study.py"
                ] = "4" * 64

        def harness_git_head(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for manifest in (artifact, run):
                manifest["harness_identity"]["git_head"] = "not-a-git-head"

        def harness_dirty(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for manifest in (artifact, run):
                manifest["harness_identity"]["git_study_tree_clean"] = False
                manifest["harness_identity"]["git_status_porcelain"] = (
                    " M performance/large-filter-study/study/run_study.py\n"
                )

        def import_count(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["import_verification"],
                    run["server_setup"]["import_verification"]):
                record["oracles"]["people"]["actual_count"] = 99_999

        def import_hash(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["import_verification"],
                    run["server_setup"]["import_verification"]):
                oracle = record["oracles"]["principal_outer_cohort"]
                oracle["expected_sha256"] = "5" * 64
                oracle["actual_sha256"] = "5" * 64

        def lookup_readback(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["lookup_mode_evidence"],
                    run["server_setup"]["lookup_mode_evidence"]):
                record["actual_readback"] = "off"

        def index_incomplete(artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["index_build_evidence"],
                    run["server_setup"]["index_build_evidence"]):
                record["reindex"]["completed"] = False

        def referral_barrier(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["barrier"]["completion_line_count"] = 0

        def referral_boundary(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["quiet_window"][
                    "next_boundary_monotonic_seconds"
                ] += 1

        def referral_expired(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                quiet = record["quiet_window"]
                quiet["established_monotonic_seconds"] = quiet[
                    "deadline_monotonic_seconds"
                ]
                quiet["remaining_seconds"] = 0

        def referral_internal_logging(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["access_log_internal_operation_control"][
                    "internal_operation_bit_enabled"
                ] = False

        def vattr_missing(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record.pop("post_restart_vattr_check_barrier")

        def vattr_identity(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["post_restart_vattr_check_barrier"]["exact_filter"] = (
                    "(objectclass=*)"
                )

        def vattr_pairing(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["post_restart_vattr_check_barrier"][
                    "completion_line_count"
                ] = 0

        def vattr_stability(
                artifact: dict[str, Any], run: dict[str, Any]) -> None:
            for record in (
                    artifact["background_referral_check_control"],
                    run["server_setup"]["background_referral_check_control"]):
                record["post_restart_vattr_check_barrier"][
                    "stability_seconds"
                ] = 0.999

        def build_id(artifact: dict[str, Any], _run: dict[str, Any]) -> None:
            artifact["server_executable"]["elf_build_id"] = {
                "status": "not-present", "reason": "synthetic", "value": None,
            }

        def linked_incomplete(artifact: dict[str, Any], _run: dict[str, Any]) -> None:
            artifact["server_executable"]["linked_libraries"]["complete"] = False

        def linked_unbound(artifact: dict[str, Any], _run: dict[str, Any]) -> None:
            artifact["server_executable"]["linked_libraries"]["packages"][0][
                "sha256"
            ] = "6" * 64

        def rpm_verify_boolean(
                artifact: dict[str, Any], _run: dict[str, Any]) -> None:
            artifact["server_executable"]["rpm_verify"]["returncode"] = False

        def storage_failed(_artifact: dict[str, Any], run: dict[str, Any]) -> None:
            run["host"]["storage"]["returncode"] = 1

        def filesystems_empty(
                _artifact: dict[str, Any], run: dict[str, Any]) -> None:
            run["host"]["filesystems"]["stdout"] = json.dumps({
                "filesystems": [],
            })

        cases = {
            "harness-content": (
                harness_content, "content SHA-256 does not recompute",
            ),
            "harness-git-head": (
                harness_git_head, "observed 40-hex git identity",
            ),
            "harness-dirty": (
                harness_dirty, "clean scoped study tree",
            ),
            "import-count": (
                import_count, "100000-entry result contract",
            ),
            "import-hash": (
                import_hash, "bind the workload count/hash contract",
            ),
            "lookup-readback": (
                lookup_readback, "readback disagrees with run actual",
            ),
            "index-incomplete": (
                index_incomplete, "import/reindex did not complete",
            ),
            "referral-barrier": (
                referral_barrier, "paired barrier did not complete",
            ),
            "referral-boundary": (
                referral_boundary, "not aligned to the kernel monotonic epoch",
            ),
            "referral-expired": (
                referral_expired, "quiet window is expired",
            ),
            "referral-internal-logging": (
                referral_internal_logging,
                "does not prove internal operation access logging",
            ),
            "vattr-missing": (
                vattr_missing, "virtual-attribute check barrier is missing",
            ),
            "vattr-identity": (
                vattr_identity, "canonical delayed vattr check",
            ),
            "vattr-pairing": (
                vattr_pairing, "invalid paired-operation evidence",
            ),
            "vattr-stability": (
                vattr_stability, "required stability interval",
            ),
            "elf-build-id": (
                build_id, "observed ELF build ID",
            ),
            "rpm-verify-boolean": (
                rpm_verify_boolean, "installed-RPM artifact identity is not proved",
            ),
            "storage-capture": (
                storage_failed, "storage capture was not successful",
            ),
            "filesystems-capture": (
                filesystems_empty, "filesystems capture has no filesystems",
            ),
        }
        for name, (mutate, expected_reason) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="9" * 64,
                    label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
                )
                artifact_path = bundle / "artifact-manifest.json"
                run_path = bundle / "run-manifest.json"
                artifact = json.loads(artifact_path.read_text())
                run = json.loads(run_path.read_text())
                mutate(artifact, run)
                _write_json(artifact_path, artifact)
                _write_json(run_path, run)
                output = root / "merged"
                merge_result_directories([bundle], output)
                merged = json.loads(
                    (output / "merged-raw-results.json").read_text()
                )
                self.assertEqual(merged["release_summaries"], [])
                self.assertFalse(merged["release_timing_evidence"])
                self.assertIn(
                    expected_reason,
                    " ".join(merged["rows"][0]["release_exclusion_reasons"]),
                )

        hard_failures = {
            "linked-incomplete": (
                linked_incomplete,
                "captured direct-linked library evidence is incomplete",
            ),
            "linked-runtime-binding": (
                linked_unbound,
                "direct-linked closure contradicts captured package evidence",
            ),
        }
        for name, (mutate, expected_error) in hard_failures.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="9" * 64,
                    label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
                )
                artifact_path = bundle / "artifact-manifest.json"
                run_path = bundle / "run-manifest.json"
                artifact = json.loads(artifact_path.read_text())
                run = json.loads(run_path.read_text())
                mutate(artifact, run)
                _write_json(artifact_path, artifact)
                _write_json(run_path, run)
                with self.assertRaisesRegex(MergeError, expected_error):
                    merge_result_directories([bundle], root / "merged")

    def test_incompatible_native_harness_content_hashes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_bundle(
                root, "first-harness", run_id="first-harness",
                binary_sha="a" * 64, label="pre-series",
                commit="6e1e933745313622593d943e983ff710de8db732",
                harness_variant="harness-a",
            )
            second = make_bundle(
                root, "second-harness", run_id="second-harness",
                binary_sha="b" * 64, label="final", commit=COMMIT_FINAL,
                harness_variant="harness-b",
            )
            with self.assertRaisesRegex(
                    MergeError, "incompatible harness content hashes"):
                merge_result_directories([first, second], root / "merged")

    def test_runtime_closure_is_rehashed_and_contains_exact_executable(self) -> None:
        for name in ("wrong-executable-member", "stale-closure-hash"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="4" * 64,
                    label="final", commit=COMMIT_FINAL,
                )
                artifact_path = bundle / "artifact-manifest.json"
                artifact = json.loads(artifact_path.read_text())
                members = artifact["server_executable"][
                    "runtime_closure_identity_material"
                ]["artifacts"]
                if name == "wrong-executable-member":
                    next(
                        item for item in members
                        if "server-executable" in item["roles"]
                    )["sha256"] = "5" * 64
                else:
                    next(
                        item for item in members
                        if "direct-linked-library" in item["roles"]
                    )["sha256"] = "6" * 64
                _write_json(artifact_path, artifact)
                with self.assertRaisesRegex(
                        MergeError,
                        "executable member|direct-linked closure contradicts"):
                    merge_result_directories([bundle], root / "merged")

    def test_direct_linked_evidence_requires_strict_provenance(self) -> None:
        def no_packages(linked: dict[str, Any]) -> None:
            linked["packages"] = []

        def duplicate_path(linked: dict[str, Any]) -> None:
            duplicate = deepcopy(linked["packages"][0])
            duplicate["sha256"] = "6" * 64
            linked["packages"].append(duplicate)

        def noncanonical_path(linked: dict[str, Any]) -> None:
            linked["packages"][0]["path"] = "/usr/lib64/../tmp/libsynthetic.so"

        def boolean_ldd_returncode(linked: dict[str, Any]) -> None:
            linked["ldd_returncode"] = False

        def blank_owner(linked: dict[str, Any]) -> None:
            linked["packages"][0]["owner"] = "   "

        def boolean_owner_returncode(linked: dict[str, Any]) -> None:
            linked["packages"][0]["owner_query_returncode"] = False

        cases = {
            "no-packages": (no_packages, "direct-linked packages are missing"),
            "duplicate-path": (duplicate_path, "provenance is invalid"),
            "noncanonical-path": (noncanonical_path, "provenance is invalid"),
            "boolean-ldd-returncode": (
                boolean_ldd_returncode,
                "direct-linked library evidence is incomplete",
            ),
            "blank-owner": (blank_owner, "provenance is invalid"),
            "boolean-owner-returncode": (
                boolean_owner_returncode,
                "provenance is invalid",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = make_bundle(
                    root, name, run_id=name, binary_sha="4" * 64,
                    label="final", commit=COMMIT_FINAL,
                )
                artifact_path = bundle / "artifact-manifest.json"
                artifact = json.loads(artifact_path.read_text())
                mutate(artifact["server_executable"]["linked_libraries"])
                _write_json(artifact_path, artifact)
                with self.assertRaisesRegex(MergeError, expected_error):
                    merge_result_directories([bundle], root / "merged")

    def test_historical_label_without_observed_failure_cannot_support_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "claimed-history", run_id="claimed-history",
                binary_sha="7" * 64, label="final", commit=COMMIT_FINAL,
            )
            correctness_path = bundle / "correctness.json"
            correctness = json.loads(correctness_path.read_text())
            record = correctness["scenarios"][0]
            record["correctness"] = "expected-historical-failure"
            record["historical_baseline"] = True
            record["evidence_status"] = "expected-historical-failure"
            _write_json(correctness_path, correctness)
            output = root / "merged"
            merge_result_directories([bundle], output)
            merged = json.loads((output / "merged-raw-results.json").read_text())
            control = merged["correctness_controls"][0]
            self.assertFalse(control["supporting_historical_failure"])
            self.assertIn("no failing operation", " ".join(control["problems"]))
            exact = next(
                gate for gate in merged["acceptance_gate_results"]
                if gate["gate_id"] == "exact-result-parity"
            )
            self.assertEqual(exact["status"], "fail")

    def test_nonrelease_memory_rows_cannot_satisfy_memory_gate(self) -> None:
        memory_scenarios = [
            "multivalue-sdn1-1", "multivalue-sdn1-4",
            "multivalue-sdn1-16", "multivalue-sdn1-64",
            "principal-with-sdn2-equality",
        ]
        bundles = []
        rows = []
        for lookup_mode, run_id, peak in (
                ("off", "memory-off", 2_000),
                ("on", "memory-on", 200_000)):
            bundles.append(SimpleNamespace(
                workload={"scenarios": {
                    scenario_id: {} for scenario_id in memory_scenarios
                }, "scenario_groups": {}},
                run_manifest={
                    "selected_scenarios": memory_scenarios,
                    "scenario_order": memory_scenarios,
                    "repeat_count": 1,
                    "warmup_count": 0,
                    "lookup_mode_actual": lookup_mode,
                    "startup_memory": {"high_water_kib": 1_000},
                },
                run_id=run_id,
                artifacts=[{
                    "commit": COMMIT_FINAL,
                    "server": "389ds",
                    "rpm_proved": True,
                    "executable_sha256": "8" * 64,
                    "behavioral_runtime_identity_sha256": "9" * 64,
                }],
                release_candidate=False,
                host_signature="a" * 64,
            ))
            rows.extend({
                "run_id": run_id,
                "row_id": f"{run_id}:{scenario_id}",
                "scenario_id": scenario_id,
                "phase": "measured",
                "configuration": {"attribute_mode": "attrs-1.1"},
                "correctness": {"passed": True, "complete": True},
                "release_eligible": False,
                "metrics": {"high_water_kib": peak},
            } for scenario_id in memory_scenarios)
        gates = evaluate_synthetic_gates([], rows=rows, bundles=bundles)
        instance = next(
            item for item in gates["table-build-and-memory-overhead"]["instances"]
            if item["instance_id"] == "dedicated-multivalue-high-water"
        )
        self.assertEqual(instance["status"], "pending")
        self.assertIn("complete matched", instance["reason"])

    def test_toggle_pair_requires_exact_executable_equality(self) -> None:
        off = synthetic_gate_summary(
            "principal-with-sdn2-equality", "off", executable_sha="a" * 64,
        )
        on = synthetic_gate_summary(
            "principal-with-sdn2-equality", "on", executable_sha="b" * 64,
        )
        baseline, candidate, reason = _toggle_pair([off, on], off["scenario_ids"][0])
        self.assertIsNone(baseline)
        self.assertIsNone(candidate)
        self.assertIn("0 resolved pairs", reason)

    def test_principal_gate_requires_consumed_profile_and_uses_json_floor(self) -> None:
        off = synthetic_gate_summary(
            "principal-with-sdn2-equality", "off", cpu=1.0,
            instructions=1000.0,
        )
        unresolved_on = synthetic_gate_summary(
            "principal-with-sdn2-equality", "on", cpu=0.5,
            instructions=500.0,
            mechanism={"lookup_consumption_statuses": ["consumed", "declined"]},
        )
        unresolved = evaluate_synthetic_gates([off, unresolved_on])[
            "principal-consumed-lookup-cost"
        ]["instances"][0]
        self.assertEqual(unresolved["status"], "pending")

        modest_on = synthetic_gate_summary(
            "principal-with-sdn2-equality", "on", cpu=0.95,
            instructions=950.0,
        )
        default = evaluate_synthetic_gates([off, modest_on])[
            "principal-consumed-lookup-cost"
        ]["instances"][0]
        self.assertEqual(default["status"], "fail")
        custom_gates = json.loads(
            (STUDY_ROOT / "workload" / "acceptance-gates.json").read_text()
        )
        next(
            gate for gate in custom_gates["gates"]
            if gate["id"] == "principal-consumed-lookup-cost"
        )["numerical_floor_fraction"] = 0.04
        custom = evaluate_synthetic_gates(
            [off, modest_on], gates=custom_gates,
        )["principal-consumed-lookup-cost"]["instances"][0]
        self.assertEqual(custom["status"], "pass")

    def test_branch_ladder_requires_one_invariant_build_stratum(self) -> None:
        summaries = []
        for count in (16, 32, 64, 128, 355, 500, 1000):
            executable = ("f" if count == 32 else "e") * 64
            behavior = ("1" if count == 32 else "2") * 64
            scenario_id = f"branch-count-{count}-all-absent"
            summaries.extend([
                synthetic_gate_summary(
                    scenario_id, "off", executable_sha=executable,
                    behavioral_sha=behavior, elapsed=float(count),
                ),
                synthetic_gate_summary(
                    scenario_id, "on", executable_sha=executable,
                    behavioral_sha=behavior, elapsed=float(count) / 2,
                ),
            ])
        branch = evaluate_synthetic_gates(summaries)["branch-count-scaling"]
        instance = next(
            item for item in branch["instances"]
            if item["instance_id"] == "all-absent"
        )
        self.assertEqual(instance["status"], "pending")
        self.assertIn("one executable/runtime/host/configuration", instance["reason"])

    def test_sdn2_attribution_is_reachable_and_derived_from_observations(self) -> None:
        with_id = "decomposition-e-full-primary"
        without_id = "decomposition-f-full-no-sdn2"
        scenarios = {
            with_id: {"expected_sha256": EMPTY_DN_SHA256, "expected_count": 0},
            without_id: {"expected_sha256": EMPTY_DN_SHA256, "expected_count": 0},
        }
        summaries = [
            synthetic_gate_summary(with_id, "on", elapsed=1.0),
            synthetic_gate_summary(without_id, "on", elapsed=1.0),
        ]
        gate = evaluate_synthetic_gates(
            summaries, scenarios=scenarios,
        )["sdn2-pair-attribution"]
        instance = next(
            item for item in gate["instances"]
            if item["instance_id"] == "decomposition-full"
        )
        self.assertEqual(instance["status"], "pass")
        self.assertEqual(
            instance["computed"]["derived_attribution"],
            "no-material-difference",
        )
        self.assertNotIn("sdn2_attributions", instance["computed"])

        summaries[1]["mechanism_evidence"][
            "stat_index_reads_observed_values"
        ] = [False]
        missing = evaluate_synthetic_gates(
            summaries, scenarios=scenarios,
        )["sdn2-pair-attribution"]
        missing_instance = next(
            item for item in missing["instances"]
            if item["instance_id"] == "decomposition-full"
        )
        self.assertEqual(missing_instance["status"], "pending")

    def test_selection_gate_requires_exact_coupled_selection_evidence(self) -> None:
        scenario_id = "flat-family-third-after-distractors"
        summary = synthetic_gate_summary(
            scenario_id, "on", commit=COMMIT_09,
            mechanism={
                "selected_attributes_direct": ["sstring3"],
                "lookup_largest_families": [64],
                "selection_observations": [{
                    "selected_attribute": "sstring3",
                    "largest_families": [64],
                }],
            },
        )
        gate = evaluate_synthetic_gates([summary])["selection-fix-retention"]
        target = next(
            item for item in gate["instances"]
            if item["instance_id"] == f"{COMMIT_09[:8]}:{scenario_id}"
        )
        self.assertEqual(target["status"], "pass")
        summary["mechanism_evidence"]["lookup_largest_families"] = [16, 64]
        bad = evaluate_synthetic_gates([summary])["selection-fix-retention"]
        bad_target = next(
            item for item in bad["instances"]
            if item["instance_id"] == f"{COMMIT_09[:8]}:{scenario_id}"
        )
        self.assertEqual(bad_target["status"], "fail")

    def test_decline_waiver_must_bind_observed_profile_and_scenario(self) -> None:
        scenario_id = "synthetic-decline"
        scenario = {
            "expected_diagnostics": {
                "or_lookup": {"expectation": "forbidden"},
            },
        }
        off = synthetic_gate_summary(
            scenario_id, "off", elapsed=1.0,
            mechanism={"lookup_constructed_values": [False]},
        )
        on = synthetic_gate_summary(
            scenario_id, "on", elapsed=2.0,
            mechanism={
                "lookup_constructed_values": [False],
                "lookup_largest_families": [],
                "lookup_consumption_statuses": ["declined"],
                "profile_attributed_waivers": [{
                    "evidence_status": "observed",
                    "scenario": scenario_id,
                    "profile_sha256": "f" * 64,
                    "rationale": "synthetic unavoidable work",
                }],
            },
        )
        args = {
            "scenarios": {scenario_id: scenario},
            "scenario_groups": {"decline-paths": [scenario_id]},
        }
        unbound = evaluate_synthetic_gates([off, on], **args)[
            "decline-path-parity"
        ]
        target = next(
            item for item in unbound["instances"]
            if item["instance_id"] == scenario_id
        )
        self.assertEqual(target["status"], "fail")
        on["mechanism_evidence"]["profile_attributed_waivers"][0][
            "profile_sha256"
        ] = "d" * 64
        bound = evaluate_synthetic_gates([off, on], **args)["decline-path-parity"]
        bound_target = next(
            item for item in bound["instances"]
            if item["instance_id"] == scenario_id
        )
        self.assertEqual(bound_target["status"], "pass")
        self.assertEqual(
            bound_target["classification"],
            "unavoidable implementation difference",
        )

    def test_correctness_only_is_pending_and_excluded_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "correctness", run_id="correctness", binary_sha="d" * 64,
                label="candidate-abort-ownership", commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                native=False,
            )
            output = root / "merged"
            result = merge_result_directories([bundle], output)
            self.assertEqual(result["status"], "native-results-pending")
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(merged["release_summaries"], [])
            self.assertEqual(merged["release_comparisons"], [])
            self.assertFalse(merged["release_timing_evidence_present"])
            self.assertTrue(merged["correctness_only_evidence_present"])
            self.assertTrue(merged["correctness_only"])
            self.assertFalse(merged["release_timing_evidence"])
            self.assertFalse(merged["timing_claims_allowed"])
            self.assertEqual(merged["host_class"], "macos_orbstack_emulated")
            self.assertEqual(merged["source_run_ids"], ["correctness"])
            self.assertEqual(merged["source_run_count"], 1)
            self.assertFalse(
                merged["nonrelease_evidence_can_satisfy_performance_gates"]
            )
            artifact = json.loads((output / "artifact-manifest.json").read_text())
            self.assertFalse(artifact["release_timing_evidence_present"])
            self.assertTrue(artifact["correctness_only_evidence_present"])
            self.assertTrue(artifact["correctness_only"])
            self.assertFalse(artifact["release_timing_evidence"])
            self.assertFalse(artifact["timing_claims_allowed"])
            self.assertEqual(artifact["host_class"], "macos_orbstack_emulated")
            self.assertEqual(artifact["source_run_ids"], ["correctness"])
            self.assertEqual(artifact["source_run_count"], 1)
            report = (output / "RESULTS.md").read_text()
            self.assertIn("native-results-pending", report)
            self.assertIn("correctness passed: 17", report)
            self.assertNotIn("## Native release comparisons", report)

    def test_unsafe_override_remains_visibly_nonrelease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "correctness", run_id="correctness", binary_sha="e" * 64,
                label="candidate-abort-ownership", commit="e0161d0e61d0cdef22175418f0d4a1e126216a86",
                native=False,
            )
            output = root / "merged"
            merge_result_directories(
                [bundle], output, unsafe_include_nonrelease=True,
            )
            merged = json.loads((output / "merged-raw-results.json").read_text())
            self.assertEqual(merged["release_summaries"], [])
            self.assertEqual(len(merged["unsafe_nonrelease_summaries"]), 1)
            report = (output / "RESULTS.md").read_text()
            self.assertIn("NON-RELEASE / UNSAFE", report)
            self.assertIn("native-results-pending", report)


def set_bundle_created_at(
        bundle: Path, created_at: str, *,
        position: Optional[str] = None) -> None:
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["created_at"] = created_at
    if position is not None:
        manifest["schedule_design"] = "screen"
        manifest["schedule_position"] = position
    _write_json(manifest_path, manifest)


class AASameConfigTests(unittest.TestCase):
    """Additive A/A decomposition of already-pooled same-config strata."""

    def _merge(self, root: Path, bundles: Sequence[Path]):
        output = root / "merged"
        result = merge_result_directories(list(bundles), output)
        merged = json.loads((output / "merged-raw-results.json").read_text())
        report = (output / "RESULTS.md").read_text()
        return result, merged, report

    def test_aa_pair_detected_for_two_same_config_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            first = make_bundle(
                root, "aa-first", run_id="aa-first", binary_sha=binary,
                label="final-a", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            second = make_bundle(
                root, "aa-second", run_id="aa-second", binary_sha=binary,
                label="final-b", commit=COMMIT_FINAL, elapsed=[1.1] * 15,
            )
            set_bundle_created_at(
                first, "2026-07-22T01:00:00Z", position="custom-off-core",
            )
            set_bundle_created_at(
                second, "2026-07-23T01:00:00Z", position="custom-off-core",
            )
            result, merged, report = self._merge(root, [first, second])
        aa = merged["aa_comparisons"]
        self.assertEqual(result["aa_pair_count"], 1)
        self.assertEqual(aa["pair_count"], 1)
        self.assertEqual(aa["multi_session_stratum_count"], 1)
        pair = aa["pairs"][0]
        self.assertEqual(pair["session_a"]["run_id"], "aa-first")
        self.assertEqual(pair["session_a"]["session_label"], "A")
        self.assertEqual(pair["session_b"]["run_id"], "aa-second")
        self.assertAlmostEqual(
            pair["elapsed_median_delta_fraction"], 0.1, places=9,
        )
        self.assertEqual(pair["session_a"]["n"], 15)
        self.assertIs(pair["harness_identity_match"], True)
        self.assertEqual(
            pair["session_a"]["schedule_position"], "custom-off-core",
        )
        summary = merged["release_summaries"][0]
        self.assertEqual(pair["stratum_summary_id"], summary["summary_id"])
        distribution = aa["delta_distribution"]["elapsed_median"]
        self.assertEqual(distribution["n"], 1)
        self.assertAlmostEqual(
            distribution["median_abs_fraction"], 0.1, places=9,
        )
        self.assertAlmostEqual(
            distribution["max_abs_fraction"], 0.1, places=9,
        )
        self.assertIn(
            "## A/A same-configuration deltas (diagnostic, non-release)",
            report,
        )

    def test_aa_reporting_leaves_pooling_and_gates_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            first = make_bundle(
                root, "aa-a1", run_id="aa-a1", binary_sha=binary,
                label="final-a1", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            second = make_bundle(
                root, "aa-a2", run_id="aa-a2", binary_sha=binary,
                label="final-a2", commit=COMMIT_FINAL, elapsed=[2.0] * 15,
            )
            _, merged, report = self._merge(root, [first, second])
        self.assertEqual(len(merged["release_summaries"]), 1)
        summary = merged["release_summaries"][0]
        self.assertEqual(summary["source_run_ids"], ["aa-a1", "aa-a2"])
        self.assertEqual(summary["n"], 30)
        aa = merged["aa_comparisons"]
        self.assertIs(aa["release_evidence"], False)
        self.assertIs(aa["gate_input"], False)
        self.assertIn("acceptance_gate_overall_status", merged)
        self.assertIn("never release evidence", report)

    def test_aa_session_order_falls_back_to_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            bundles = [
                make_bundle(
                    root, name, run_id=name, binary_sha=binary,
                    label=f"final-{name}", commit=COMMIT_FINAL,
                    elapsed=[value] * 15,
                )
                for name, value in (("aa-zulu", 1.0), ("aa-alpha", 1.2))
            ]
            _, merged, report = self._merge(root, bundles)
        aa = merged["aa_comparisons"]
        self.assertEqual(aa["pair_count"], 1)
        pair = aa["pairs"][0]
        self.assertEqual(pair["session_a"]["run_id"], "aa-alpha")
        self.assertIsNone(pair["session_a"]["created_at"])
        self.assertIsNone(pair["session_a"]["schedule_position"])
        self.assertEqual(aa["pass_order"]["status"], "unknown")
        self.assertIn("| —", report)

    def test_aa_section_reports_none_for_single_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = make_bundle(
                root, "solo", run_id="solo", binary_sha="7" * 64,
                label="final", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            result, merged, report = self._merge(root, [bundle])
        self.assertEqual(result["aa_pair_count"], 0)
        self.assertEqual(merged["aa_comparisons"]["pairs"], [])
        self.assertIn(
            "No same-configuration multi-session pairs were detected",
            report,
        )

    def test_aa_different_lookup_or_binary_never_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            off = make_bundle(
                root, "toggle-off", run_id="toggle-off", binary_sha="7" * 64,
                label="final-off", commit=COMMIT_FINAL,
                elapsed=[1.0] * 15, lookup_mode="off",
            )
            on = make_bundle(
                root, "toggle-on", run_id="toggle-on", binary_sha="7" * 64,
                label="final-on", commit=COMMIT_FINAL,
                elapsed=[0.5] * 15, lookup_mode="on",
            )
            _, merged, _ = self._merge(root, [off, on])
            self.assertEqual(merged["aa_comparisons"]["pair_count"], 0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = make_bundle(
                root, "bin-a", run_id="bin-a", binary_sha="7" * 64,
                label="final-a", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            second = make_bundle(
                root, "bin-b", run_id="bin-b", binary_sha="8" * 64,
                label="final-b", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            _, merged, _ = self._merge(root, [first, second])
            self.assertEqual(merged["aa_comparisons"]["pair_count"], 0)

    def test_aa_three_sessions_emit_consecutive_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            bundles = []
            for index, value in enumerate((1.0, 1.1, 1.21)):
                bundle = make_bundle(
                    root, f"aa-{index}", run_id=f"aa-{index}",
                    binary_sha=binary, label=f"final-{index}",
                    commit=COMMIT_FINAL, elapsed=[value] * 15,
                )
                set_bundle_created_at(
                    bundle, f"2026-07-2{index + 1}T01:00:00Z",
                )
                bundles.append(bundle)
            _, merged, _ = self._merge(root, bundles)
        aa = merged["aa_comparisons"]
        self.assertEqual(aa["pair_count"], 2)
        first, second = aa["pairs"]
        self.assertEqual(
            (first["session_a"]["run_id"], first["session_b"]["run_id"]),
            ("aa-0", "aa-1"),
        )
        self.assertEqual(
            (second["session_a"]["run_id"], second["session_b"]["run_id"]),
            ("aa-1", "aa-2"),
        )
        self.assertEqual(second["session_b"]["session_label"], "C")
        self.assertEqual(
            aa["delta_distribution"]["elapsed_median"]["n"], 2,
        )

    def test_aa_reverse_order_pass_is_labeled(self) -> None:
        for stamps, expected in (
                ({"off-1": "T01", "on-1": "T02", "on-2": "T03",
                  "off-2": "T04"}, "reverse"),
                ({"off-1": "T01", "on-1": "T02", "off-2": "T03",
                  "on-2": "T04"}, "forward-repeat")):
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    binary = "7" * 64
                    bundles = []
                    for name, stamp in stamps.items():
                        lookup = "off" if name.startswith("off") else "on"
                        bundle = make_bundle(
                            root, name, run_id=name, binary_sha=binary,
                            label=f"final-{name}", commit=COMMIT_FINAL,
                            elapsed=[1.0] * 15, lookup_mode=lookup,
                        )
                        set_bundle_created_at(
                            bundle, f"2026-07-22{stamp}:00:00Z",
                        )
                        bundles.append(bundle)
                    _, merged, _ = self._merge(root, bundles)
                aa = merged["aa_comparisons"]
                self.assertEqual(aa["pair_count"], 2)
                self.assertEqual(aa["pass_order"]["status"], expected)

    def test_aa_cpu_delta_degrades_to_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            first = make_bundle(
                root, "cpu-a", run_id="cpu-a", binary_sha=binary,
                label="final-a", commit=COMMIT_FINAL, elapsed=[1.0] * 15,
            )
            second = make_bundle(
                root, "cpu-b", run_id="cpu-b", binary_sha=binary,
                label="final-b", commit=COMMIT_FINAL, elapsed=[1.1] * 15,
            )
            raw_path = second / "raw-results.json"
            payload = json.loads(raw_path.read_text())
            for row in payload["rows"]:
                row.pop("process_user_cpu_seconds", None)
                row.pop("process_system_cpu_seconds", None)
            _write_json(raw_path, payload)
            _, merged, report = self._merge(root, [first, second])
        pair = merged["aa_comparisons"]["pairs"][0]
        self.assertIsNotNone(pair["elapsed_median_delta_fraction"])
        self.assertIsNone(pair["server_cpu_median_delta_fraction"])
        self.assertEqual(
            merged["aa_comparisons"]["delta_distribution"][
                "server_cpu_median"
            ]["n"],
            0,
        )
        self.assertIn("| — |", report)

    def test_aa_nonrelease_pair_labels_harness_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            first = make_bundle(
                root, "nr-a", run_id="nr-a", binary_sha=binary,
                label="final-a", commit=COMMIT_FINAL,
                elapsed=[1.0] * 15, native=False,
                harness_variant="harness-a",
            )
            second = make_bundle(
                root, "nr-b", run_id="nr-b", binary_sha=binary,
                label="final-b", commit=COMMIT_FINAL,
                elapsed=[1.2] * 15, native=False,
                harness_variant="harness-b",
            )
            _, merged, report = self._merge(root, [first, second])
        pair = merged["aa_comparisons"]["pairs"][0]
        self.assertIs(pair["harness_identity_match"], False)
        self.assertIn("harness differs", report)

    def test_aa_canary_strata_excluded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = "7" * 64
            manifest = workload_manifest()
            manifest["scenario_groups"] = {"drift-canary": ["case"]}
            bundles = []
            for index, value in enumerate((1.0, 1.05, 1.02)):
                bundle = make_bundle(
                    root, f"canary-{index}", run_id=f"canary-{index}",
                    binary_sha=binary, label=f"final-{index}",
                    commit=COMMIT_FINAL, elapsed=[value] * 15,
                    workload=manifest,
                )
                set_bundle_created_at(
                    bundle, f"2026-07-22T0{index + 1}:00:00Z",
                    position=f"custom-off-bundle-{index}",
                )
                bundles.append(bundle)
            _, merged, report = self._merge(root, bundles)
        aa = merged["aa_comparisons"]
        self.assertEqual(aa["pair_count"], 0)
        canary = aa["drift_canary"]
        self.assertEqual(canary["stratum_count"], 1)
        runs = canary["strata"][0]["runs"]
        self.assertEqual(
            [run["run_id"] for run in runs],
            ["canary-0", "canary-1", "canary-2"],
        )
        self.assertEqual(
            canary["consecutive_delta_distribution"]["n"], 2,
        )
        self.assertIn("### Drift-canary repeatability", report)
        self.assertIn("custom-off-bundle-1", report)


if __name__ == "__main__":
    unittest.main()
