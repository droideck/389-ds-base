"""Validate and merge independently collected large-filter study results.

The merger is intentionally standard-library-only.  It treats correctness and
timing eligibility as separate questions: emulated/correctness-only bundles
remain useful audit evidence, but never enter release tables.  An explicit
unsafe flag can display their descriptive statistics in a separately labelled
appendix; it cannot turn them into release evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
import sys

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from .common import atomic_output_directory
from .platform_info import backend_module_roles, parse_openldap_static_backends
from .revisions import (
    PRODUCTION_EQUIVALENT_REVISIONS,
    REVISION_ROLES,
    analysis_revision_role,
    production_equivalent_revision,
)


STUDY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GATES = STUDY_ROOT / "workload" / "acceptance-gates.json"
DEFAULT_MATRIX_PLAN = STUDY_ROOT / "workload" / "native-matrix-plan.json"
DEFAULT_REVISION_PLAN = STUDY_ROOT / "artifact-manifest.json"
NATIVE_EVIDENCE_CONTRACT_VERSION = 2
AUTHORITATIVE_MATRIX_PLAN_SHA256 = (
    "cf3be533b23321a674686869086865a4715e12fdd75b6e7ce299637a8420c5f1"
)
AUTHORITATIVE_GATES_SHA256 = (
    "0be205fc14a87571e07c3a082ce9a564331797ae78a3399d5acfd44ace4ec89c"
)
HASH_KEYS = (
    "executable_sha256", "binary_sha256", "ns_slapd_sha256",
    "slapd_sha256",
)
NATIVE_HOST_CLASSES = frozenset({
    "native_fedora", "native-fedora", "fedora_native",
    "native_fedora_installed_rpm", "native-fedora-installed-rpm",
})
COMMIT_PRE = REVISION_ROLES["pre-series"]
COMMIT_BOUNDED = REVISION_ROLES["bounded-feature"]
COMMIT_7C = REVISION_ROLES["combined-diagnostic"]
COMMIT_038 = REVISION_ROLES["dynamic-list-fix"]
COMMIT_09 = REVISION_ROLES["all-family-fix"]
COMMIT_9C = REVISION_ROLES["largest-family-fix"]
COMMIT_FINAL = REVISION_ROLES["final"]
PERF_BATCH_MAX_OPERATIONS = 5
MINIMUM_NATIVE_REPEATS = 15
ALLOWED_NATIVE_WARMUPS = frozenset({2, 3})
NORMAL_PRIMARY_ATTRIBUTES = (
    "uid", "cn", "sString1", "sString2", "sString3", "sString4",
    "sDN1", "sDN2",
)
VATTR_CHECK_SOURCE_FUNCTION = "vattr_check/vattr_check_thread"
VATTR_CHECK_DELAY_SECONDS = 3
VATTR_CHECK_FILTER = (
    "(&(objectclass=ldapsubentry)"
    "(|(objectclass=nsRoleDefinition)(objectclass=cosSuperDefinition)))"
)
VATTR_CHECK_MINIMUM_STABILITY_SECONDS = 1.0
CANDIDATE_TRACE_RE = re.compile(rb"Candidate list has (\d+) ids")
DIRECTORY_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15"
DISTINGUISHED_NAME_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.12"
STUDY_SCHEMA_ATTRIBUTE_NAMES = (
    "sString1", "sString2", "sString3", "sString4",
    "sDN1", "sDN2", "sSub", "sApprox",
)
EXPECTED_SCHEMA_SEMANTIC_CONTRACT = {
    "format_version": 1,
    "attribute_types": {
        f"1.3.6.1.4.1.2312.999.2026.100.{number}": {
            "name": name,
            "syntax": (
                DISTINGUISHED_NAME_SYNTAX
                if name in {"sDN1", "sDN2"} else DIRECTORY_STRING_SYNTAX
            ),
            "equality": (
                "distinguishedNameMatch"
                if name in {"sDN1", "sDN2"} else "caseIgnoreMatch"
            ),
            "substring": (
                "caseIgnoreSubstringsMatch"
                if name in {"sString1", "sString2", "sString3", "sString4", "sSub"}
                else None
            ),
            "single_value": name != "sDN1",
        }
        for number, name in enumerate(STUDY_SCHEMA_ATTRIBUTE_NAMES, 1)
    },
    "object_classes": {
        "1.3.6.1.4.1.2312.999.2026.100.20": {
            "name": "largeFilterStudyPerson",
            "superior": "top",
            "kind": "AUXILIARY",
            "may": sorted(STUDY_SCHEMA_ATTRIBUTE_NAMES),
        },
    },
}


class MergeError(ValueError):
    """Raised when an input cannot support a truthful merged report."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except FileNotFoundError as error:
        raise MergeError(f"missing required input: {path}") from error
    except json.JSONDecodeError as error:
        raise MergeError(f"invalid JSON in {path}: {error}") from error


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _require_sha256(value: Any, context: str) -> str:
    if not _is_sha256(value):
        raise MergeError(f"{context} is not a lowercase SHA-256")
    return str(value)


def _nested(mapping: Mapping[str, Any], *path: str) -> Any:
    value: Any = mapping
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return None
        value = value[key]
    return value


def _first(mapping: Mapping[str, Any], paths: Iterable[Sequence[str]]) -> Any:
    for path in paths:
        value = _nested(mapping, *path)
        if value is not None:
            return value
    return None


def _bool_values(*sources: Mapping[str, Any], key: str) -> set[bool]:
    values: set[bool] = set()
    for source in sources:
        value = source.get(key)
        if isinstance(value, bool):
            values.add(value)
    return values


def _safe_payload_path(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise MergeError(f"{context} is missing a payload path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise MergeError(f"{context} has unsafe payload path {value!r}")
    return path.as_posix()


def _verified_bundle_artifact(
        root: Path, descriptor: Mapping[str, Any], context: str) -> bytes:
    relative = _safe_payload_path(descriptor.get("path"), context)
    expected_sha = _require_sha256(
        descriptor.get("sha256"), f"{context} SHA-256",
    )
    expected_size = descriptor.get("size_bytes")
    if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool) or expected_size < 0):
        raise MergeError(f"{context} size is invalid")
    payload = root
    for part in PurePosixPath(relative).parts:
        payload = payload / part
        if payload.is_symlink():
            raise MergeError(f"{context} path uses a symlink")
    if not payload.is_file():
        raise MergeError(f"{context} artifact is missing")
    resolved = payload.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise MergeError(f"{context} artifact escapes the bundle") from error
    content = resolved.read_bytes()
    if len(content) != expected_size or sha256_bytes(content) != expected_sha:
        raise MergeError(f"{context} declared artifact identity differs")
    return content


def _manifest_evidence_contract_version(
        root: Path, artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> Optional[int]:
    """Bind modern evidence rules to an explicit cross-manifest version."""
    artifact_version = artifact_manifest.get("evidence_contract_version")
    run_version = run_manifest.get("evidence_contract_version")
    if artifact_version is None and run_version is None:
        return None
    if artifact_version != run_version:
        raise MergeError(
            f"{root}: artifact/run evidence contract versions disagree"
        )
    if (
            not isinstance(run_version, int)
            or isinstance(run_version, bool)
            or run_version != NATIVE_EVIDENCE_CONTRACT_VERSION):
        raise MergeError(
            f"{root}: unsupported evidence contract version {run_version!r}"
        )
    if not isinstance(run_manifest.get("configuration_contract"), Mapping):
        raise MergeError(
            f"{root}: evidence contract v{run_version} requires the "
            "configuration contract"
        )
    return run_version


def _validate_profile_artifacts(
        root: Path, run_manifest: Mapping[str, Any], *, modern: bool,
        workload: Optional[Mapping[str, Any]] = None) -> None:
    profiles = run_manifest.get("profiles")
    if profiles is None:
        if modern:
            raise MergeError(f"{root}: evidence contract v2 requires profiles")
        return
    if not isinstance(profiles, list):
        raise MergeError(f"{root}: run profiles must be a list")
    seen: set[str] = set()
    observed_classes: set[str] = set()
    observed_signatures: set[str] = set()
    for index, profile in enumerate(profiles):
        context = f"{root}: profile {index}"
        if not isinstance(profile, Mapping):
            raise MergeError(f"{context} must be an object")
        scenario_id = profile.get("scenario")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise MergeError(f"{context} scenario is missing")
        if scenario_id in seen:
            raise MergeError(f"{root}: duplicate profile for {scenario_id}")
        seen.add(scenario_id)
        status = profile.get("status")
        event = profile.get("sampling_event")
        if status == "observed" and event == "default-hardware":
            collection_class = "hardware-sampling"
        elif status == "observed" and event == "cpu-clock":
            collection_class = "software-cpu-clock"
        elif status == "disabled":
            collection_class = "disabled"
        elif status == "unavailable":
            collection_class = "unavailable"
        elif isinstance(status, str) and status.startswith("skipped-"):
            collection_class = "skipped"
        else:
            collection_class = "failed"
        material = {
            "format_version": 1,
            "collection_class": collection_class,
            "status": str(status or "unrecorded"),
            "sampling_event": event,
            "software_fallback": profile.get("software_fallback") is True,
        }
        signature = sha256_bytes(canonical_json_bytes(material))
        if modern and (
                profile.get("collection_class") != collection_class
                or profile.get("collection_signature") != signature):
            raise MergeError(
                f"{context}: profile collection identity is inconsistent"
            )
        observed_classes.add(collection_class)
        observed_signatures.add(signature)
        if status != "observed":
            continue
        artifact = profile.get("profile_artifact")
        report = profile.get("report")
        if (
                not isinstance(artifact, Mapping)
                or artifact.get("evidence_status") != "observed"
                or not isinstance(report, Mapping)
                or report.get("status") != "observed"):
            raise MergeError(
                f"{context}: observed profile lacks observed artifact/report"
            )
        _verified_bundle_artifact(root, artifact, f"{context} perf.data")
        report_bytes = _verified_bundle_artifact(
            root, report, f"{context} perf report",
        )
        try:
            report_text = report_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise MergeError(f"{context}: perf report is not UTF-8") from error
        operations = profile.get("operations")
        operation_count = profile.get("operation_count")
        if modern and (
                operation_count != 20 or not isinstance(operations, list)
                or len(operations) != operation_count):
            raise MergeError(
                f"{context}: observed profile must prove 20 operations"
            )
        for operation_index, operation in enumerate(
                operations if isinstance(operations, list) else [], 1):
            if (
                    not isinstance(operation, Mapping)
                    or operation.get("operation_index") != operation_index
                    or operation.get("operation_isolated") is not True
                    or _nested(operation, "exact_result", "evidence_status")
                    != "observed"
                    or _nested(operation, "exact_result", "passed") is not True
                    or _nested(
                        operation, "server_result_evidence", "evidence_status"
                    ) != "observed"
                    or _nested(
                        operation, "server_result_evidence", "passed"
                    ) is not True):
                raise MergeError(
                    f"{context}: operation {operation_index} lacks exact/server proof"
                )
        symbols = (
            "vattr_test_filter_or_lookup", "filter_or_lookup_probe",
        )
        counts = {
            symbol: len(re.findall(
                rf"\b{re.escape(symbol)}\b", report_text,
            ))
            for symbol in symbols
        }
        sampled = [symbol for symbol, count in counts.items() if count]
        declared = profile.get("lookup_consumption")
        if not isinstance(declared, Mapping):
            raise MergeError(f"{context}: lookup-consumption record is missing")
        expected_status = "consumed" if sampled else "unresolved"
        if (
                declared.get("status") != expected_status
                or declared.get("evidence_status") != "observed"
                or declared.get("sampled_symbols") != sampled
                or declared.get("symbol_line_counts") != counts):
            raise MergeError(
                f"{context}: lookup-consumption annotation disagrees with report"
            )
        lookup_mode = run_manifest.get("lookup_mode_actual")
        if str(lookup_mode).casefold() in {"off", "disabled"} and sampled:
            raise MergeError(
                f"{context}: lookup-off profile sampled lookup-only symbols"
            )
    if modern:
        selected = run_manifest.get("selected_scenarios")
        dynamic_ids = set()
        if isinstance(workload, Mapping):
            groups = workload.get("scenario_groups")
            if isinstance(groups, Mapping) and isinstance(
                    groups.get("dynamic-list-correctness"), list):
                dynamic_ids = set(map(str, groups["dynamic-list-correctness"]))
        expected_profiles = (
            set(selected).difference(dynamic_ids)
            if isinstance(selected, list) else set()
        )
        if (
                not isinstance(selected, list)
                or any(not isinstance(value, str) for value in selected)
                or seen != expected_profiles):
            raise MergeError(
                f"{root}: profiles do not cover every selected scenario"
            )
        declared_classes = run_manifest.get("profile_collection_classes")
        declared_signatures = run_manifest.get(
            "profile_collection_signatures"
        )
        if (
                declared_classes != sorted(observed_classes)
                or declared_signatures != sorted(observed_signatures)):
            raise MergeError(
                f"{root}: run-level profile collection inventory disagrees"
            )


def _validate_dynamic_final_candidate_evidence(
        root: Path, operation: Any, context: str) -> None:
    """Bind dynamic final-search diagnostics to their captured error-log bytes."""
    if not isinstance(operation, Mapping):
        raise MergeError(f"{context}: dynamic final search is missing")
    diagnostics = operation.get("diagnostics")
    if not isinstance(diagnostics, Mapping):
        raise MergeError(f"{context}: dynamic final candidate diagnostics are missing")
    values = diagnostics.get("candidate_list_values")
    if (
            not isinstance(values, list)
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in values
            )):
        raise MergeError(f"{context}: candidate-list trace values are invalid")

    status = diagnostics.get("candidate_list_status")
    observed = diagnostics.get("observed_final_candidate_count")
    observation = diagnostics.get("candidate_list_observation")
    if values:
        if (
                status != "not-directly-observable-unattributed-traces"
                or observed is not None):
            raise MergeError(
                f"{context}: final candidate count must remain unobservable"
            )
        expected_parser_status = (
            "observed" if len(values) == 1 else "ambiguous-multiple-traces"
        )
        if (
                not isinstance(observation, Mapping)
                or observation.get("status") != "not-directly-observable"
                or not isinstance(observation.get("reason"), str)
                or not observation.get("reason", "").strip()
                or observation.get("raw_trace_count") != len(values)
                or observation.get("parser_status") != expected_parser_status):
            raise MergeError(
                f"{context}: candidate-list unobservability record is inconsistent"
            )
    elif (
            status != "not-observed"
            or observed is not None
            or observation is not None):
        raise MergeError(
            f"{context}: absent candidate-list trace record is inconsistent"
        )

    artifacts = operation.get("diagnostic_artifacts")
    if not isinstance(artifacts, Mapping):
        raise MergeError(f"{context}: diagnostic artifact references are missing")
    relative = _safe_payload_path(
        artifacts.get("error_log"), f"{context}: dynamic error log",
    )
    expected_sha = _require_sha256(
        artifacts.get("error_log_sha256"),
        f"{context}: dynamic error-log SHA-256",
    )
    expected_size = artifacts.get("error_log_size_bytes")
    if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0):
        raise MergeError(f"{context}: dynamic error-log size is invalid")

    payload = root
    for part in PurePosixPath(relative).parts:
        payload = payload / part
        if payload.is_symlink():
            raise MergeError(
                f"{context}: dynamic error-log path uses a symlink"
            )
    if not payload.is_file():
        raise MergeError(f"{context}: dynamic error-log artifact is missing")
    resolved = payload.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise MergeError(
            f"{context}: dynamic error-log artifact escapes the bundle"
        ) from error
    content = resolved.read_bytes()
    if len(content) != expected_size or sha256_bytes(content) != expected_sha:
        raise MergeError(
            f"{context}: dynamic error-log declared artifact identity differs"
        )
    parsed_values = [
        int(match) for match in CANDIDATE_TRACE_RE.findall(content)
    ]
    if parsed_values != values:
        raise MergeError(
            f"{context}: candidate-list traces differ from the dynamic error log"
        )


def _workload_digest(manifest: Mapping[str, Any]) -> str:
    digest_input = {
        "format_version": manifest.get("format_version"),
        "profile": manifest.get("profile"),
        "seed": manifest.get("seed"),
        "host_intent": manifest.get("host_intent"),
        "files": manifest.get("files"),
    }
    return sha256_bytes(canonical_json_bytes(digest_input))


def _configured_index_intents(
        manifest: Mapping[str, Any], source: Path,
        index_path: str) -> Dict[str, Dict[str, str]]:
    """Recompute every server/variant index-intent hash from copied bytes."""
    payload_path = source.parent / "workload" / index_path
    document = _load_json(payload_path)
    if not isinstance(document, Mapping):
        raise MergeError(f"{payload_path}: index configuration must be an object")
    servers = document.get("servers")
    variants = document.get("variants")
    if not isinstance(servers, Mapping) or not isinstance(variants, Mapping):
        raise MergeError(f"{payload_path}: index servers/variants are missing")
    result: Dict[str, Dict[str, str]] = {}
    for raw_server, raw_server_config in servers.items():
        if not isinstance(raw_server, str) or not isinstance(raw_server_config, Mapping):
            raise MergeError(f"{payload_path}: malformed server index record")
        raw_baseline = raw_server_config.get("baseline")
        if not isinstance(raw_baseline, Mapping):
            raise MergeError(f"{payload_path}: {raw_server} baseline is missing")
        baseline = {
            str(attribute): tuple(str(kind) for kind in kinds)
            for attribute, kinds in raw_baseline.items()
            if isinstance(kinds, list)
        }
        if len(baseline) != len(raw_baseline):
            raise MergeError(f"{payload_path}: malformed {raw_server} baseline")
        result[raw_server] = {}
        for raw_variant, raw_changes in variants.items():
            if not isinstance(raw_variant, str) or not isinstance(raw_changes, Mapping):
                raise MergeError(f"{payload_path}: malformed index variant")
            configured = dict(baseline)
            remove = raw_changes.get("remove", {})
            add = raw_changes.get("add", {})
            if not isinstance(remove, Mapping) or not isinstance(add, Mapping):
                raise MergeError(f"{payload_path}: malformed variant {raw_variant}")
            for attribute, kinds in remove.items():
                if not isinstance(kinds, list):
                    raise MergeError(f"{payload_path}: malformed removals in {raw_variant}")
                remaining = tuple(
                    kind for kind in configured.get(str(attribute), ())
                    if kind not in {str(value) for value in kinds}
                )
                if remaining:
                    configured[str(attribute)] = remaining
                else:
                    configured.pop(str(attribute), None)
            for attribute, kinds in add.items():
                if not isinstance(kinds, list):
                    raise MergeError(f"{payload_path}: malformed additions in {raw_variant}")
                configured[str(attribute)] = tuple(dict.fromkeys(
                    configured.get(str(attribute), ())
                    + tuple(str(value) for value in kinds)
                ))
            material = {
                attribute: list(configured[attribute])
                for attribute in sorted(configured)
            }
            result[raw_server][raw_variant] = sha256_bytes(
                canonical_json_bytes(material)
            )
    return result


def validate_workload_manifest(
        manifest: Mapping[str, Any], source: Path) -> Dict[str, Any]:
    """Validate generator hashes and return a comparison contract."""
    if manifest.get("format_version") != 1:
        raise MergeError(f"{source}: unsupported workload manifest format")
    files = manifest.get("files")
    if not isinstance(files, Mapping) or not files:
        raise MergeError(f"{source}: workload files hash inventory is empty")
    normalized_files: Dict[str, str] = {}
    for raw_path, raw_digest in files.items():
        path = _safe_payload_path(raw_path, f"{source}: workload file")
        normalized_files[path] = _require_sha256(
            raw_digest, f"{source}: workload file {path}",
        )

    declared_digest = _require_sha256(
        manifest.get("workload_sha256"), f"{source}: workload_sha256",
    )
    computed_digest = _workload_digest(manifest)
    if declared_digest != computed_digest:
        raise MergeError(
            f"{source}: workload_sha256 does not match the generator contract "
            f"({declared_digest} != {computed_digest})"
        )

    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, Mapping) or not scenarios:
        raise MergeError(f"{source}: workload has no scenarios")
    scenario_contracts: Dict[str, Dict[str, Any]] = {}
    filter_hashes: Dict[str, str] = {}
    expected_hashes: Dict[str, str] = {}
    for scenario_id, raw_scenario in scenarios.items():
        if not isinstance(scenario_id, str) or not isinstance(raw_scenario, Mapping):
            raise MergeError(f"{source}: malformed scenario record")
        filter_path = _safe_payload_path(
            raw_scenario.get("filter_file"),
            f"{source}: scenario {scenario_id} filter",
        )
        expected_path = _safe_payload_path(
            raw_scenario.get("expected_file"),
            f"{source}: scenario {scenario_id} expected result",
        )
        if filter_path not in normalized_files:
            raise MergeError(
                f"{source}: scenario {scenario_id} filter is absent from files"
            )
        if expected_path not in normalized_files:
            raise MergeError(
                f"{source}: scenario {scenario_id} expected result is absent from files"
            )
        expected_digest = _require_sha256(
            raw_scenario.get("expected_sha256"),
            f"{source}: scenario {scenario_id} expected_sha256",
        )
        if expected_digest != normalized_files[expected_path]:
            raise MergeError(
                f"{source}: scenario {scenario_id} expected hash disagrees "
                "with the workload file inventory"
            )
        filter_hashes[scenario_id] = normalized_files[filter_path]
        expected_hashes[scenario_id] = expected_digest
        scenario_contracts[scenario_id] = {
            "base_dn": raw_scenario.get("base_dn"),
            "expected_count": raw_scenario.get("expected_count"),
            "expected_result_code": raw_scenario.get("expected_result_code"),
            "expected_sha256": expected_digest,
            "filter_sha256": normalized_files[filter_path],
            "requested_attributes": raw_scenario.get("requested_attributes"),
            "scope": raw_scenario.get("scope"),
        }

    schema_files = manifest.get("schema_files")
    if not isinstance(schema_files, Mapping) or not schema_files:
        raise MergeError(f"{source}: workload schema_files is empty")
    schema_hashes: Dict[str, str] = {}
    for server, raw_path in schema_files.items():
        path = _safe_payload_path(raw_path, f"{source}: {server} schema")
        if path not in normalized_files:
            raise MergeError(f"{source}: schema {path} is absent from files")
        schema_hashes[str(server)] = normalized_files[path]

    index_path = _safe_payload_path(
        manifest.get("index_config_file"), f"{source}: index configuration",
    )
    if index_path not in normalized_files:
        raise MergeError(f"{source}: index configuration is absent from files")

    # A completed runner bundle is self-contained.  Verify the executed copy,
    # not similarly named files beside the result directory.
    checked_payloads = 0
    for relative_path, expected_digest in normalized_files.items():
        existing = source.parent / "workload" / relative_path
        if not existing.is_file() or existing.is_symlink():
            raise MergeError(
                f"{source}: self-contained workload payload is missing {relative_path}"
            )
        observed = hashlib.sha256(existing.read_bytes()).hexdigest()
        if observed != expected_digest:
            raise MergeError(
                f"{source}: payload hash mismatch for {relative_path}"
            )
        checked_payloads += 1

    copied_manifest = source.parent / "workload" / "workload-manifest.json"
    if (
            not copied_manifest.is_file() or copied_manifest.is_symlink()
            or copied_manifest.read_bytes() != source.read_bytes()):
        raise MergeError(
            f"{source}: executed workload manifest copy is missing or differs"
        )

    index_intent_sha256s = _configured_index_intents(
        manifest, source, index_path,
    )

    return {
        "workload_id": manifest.get("workload_id"),
        "workload_sha256": declared_digest,
        "workload_manifest_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "canonical_workload_manifest_sha256": sha256_bytes(canonical_json_bytes(manifest)),
        "files": normalized_files,
        "filter_hashes": filter_hashes,
        "expected_hashes": expected_hashes,
        "schema_hashes": schema_hashes,
        "index_config_sha256": normalized_files[index_path],
        "index_intent_sha256s": index_intent_sha256s,
        "scenario_contracts": scenario_contracts,
        "payload_files_verified": checked_payloads,
    }


def _workload_difference(left: Mapping[str, Any], right: Mapping[str, Any]) -> str:
    ordered = (
        ("workload_sha256", "workload"),
        ("schema_hashes", "schema"),
        ("filter_hashes", "filter"),
        ("expected_hashes", "expected-result"),
        ("index_config_sha256", "index-configuration"),
        ("scenario_contracts", "scenario contract"),
        ("workload_manifest_sha256", "complete workload manifest"),
        ("canonical_workload_manifest_sha256", "canonical workload manifest"),
    )
    differences = [label for key, label in ordered if left.get(key) != right.get(key)]
    return ", ".join(differences)


def _recursive_artifact_nodes(
        value: Any, inherited: Mapping[str, Any], path: str = "") -> list[Dict[str, Any]]:
    records: list[Dict[str, Any]] = []
    if isinstance(value, Mapping):
        context = dict(inherited)
        for key in (
            "label", "revision_label", "commit_label", "build_label", "revision_role",
            "commit", "source_commit", "git_commit", "expected_source_sha", "server",
            "production_equivalent_revision",
            "server_type", "implementation", "executable_name",
            "runtime_closure_sha256",
            "backend_runtime_closure_sha256",
            "behavioral_runtime_identity_sha256",
        ):
            if key in value and value[key] is not None:
                context[key] = value[key]
        found: Optional[str] = None
        for key in HASH_KEYS:
            if key in value:
                found = _require_sha256(value[key], f"artifact {path or '<root>'}.{key}")
                break
        if found is not None:
            record = dict(context)
            record.update(value)
            record["executable_sha256"] = found
            record["artifact_path"] = path or "<root>"
            records.append(record)
        for key, child in value.items():
            if isinstance(child, (Mapping, list)):
                child_path = f"{path}.{key}" if path else str(key)
                records.extend(_recursive_artifact_nodes(child, context, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            records.extend(_recursive_artifact_nodes(child, inherited, child_path))
    return records


def _revision_maps() -> tuple[Dict[str, str], Dict[str, int]]:
    if not DEFAULT_REVISION_PLAN.is_file():
        return {}, {}
    plan = _load_json(DEFAULT_REVISION_PLAN)
    by_commit: Dict[str, str] = {}
    order: Dict[str, int] = {}
    for index, revision in enumerate(plan.get("revisions", [])):
        if not isinstance(revision, Mapping):
            continue
        commit = revision.get("commit")
        label = revision.get("label")
        if isinstance(commit, str) and isinstance(label, str):
            by_commit[commit] = label
            order[commit] = index
    return by_commit, order


def _artifact_commit(record: Mapping[str, Any]) -> Optional[str]:
    value = _first(record, (
        ("commit",), ("source_commit",), ("git_commit",),
        ("expected_source_sha",),
    ))
    return value if isinstance(value, str) and value else None


def _artifact_production_commit(
        record: Mapping[str, Any], commit: Optional[str],
        server: Optional[str]) -> Optional[str]:
    """Derive a production identity from the closed committed alias map.

    A bundle may repeat the derived value for auditability, but it cannot
    create a new equivalence or redirect a known source revision.
    """
    declared = _first(record, (("production_equivalent_revision",),))
    expected = (
        production_equivalent_revision(commit)
        if (
            server == "389ds"
            and isinstance(commit, str)
            and re.fullmatch(r"[0-9a-fA-F]{40}", commit)
        )
        else None
    )
    if declared is not None:
        if not isinstance(declared, str) or not re.fullmatch(
                r"[0-9a-fA-F]{40}", declared):
            raise MergeError("artifact production-equivalent revision is invalid")
        declared = declared.casefold()
        if declared != expected:
            raise MergeError(
                "artifact production-equivalent revision contradicts the "
                "committed revision plan"
            )
    return expected


def _artifact_revision_role(
        record: Mapping[str, Any], commit: Optional[str],
        server: Optional[str]) -> Optional[str]:
    """Resolve a role while accepting format-v1 manifests that omit it."""
    declared = record.get("revision_role")
    if declared is not None and (
            not isinstance(declared, str) or not declared):
        raise MergeError("artifact revision role is invalid")
    expected = (
        analysis_revision_role(commit)
        if (
            server == "389ds"
            and isinstance(commit, str)
            and re.fullmatch(r"[0-9a-fA-F]{40}", commit)
        )
        else None
    )
    if declared is not None and expected is not None and declared != expected:
        raise MergeError(
            "artifact revision role contradicts the committed revision plan"
        )
    return expected or declared


def _artifact_label(record: Mapping[str, Any], commit_labels: Mapping[str, str]) -> str:
    value = _first(record, (
        ("label",), ("revision_label",), ("commit_label",), ("build_label",),
    ))
    if isinstance(value, str) and value:
        return value
    commit = _artifact_commit(record)
    if commit and commit in commit_labels:
        return commit_labels[commit]
    if commit:
        return commit[:12]
    name = record.get("executable_name")
    return str(name) if name else "unlabelled-artifact"


def _artifact_server(record: Mapping[str, Any]) -> Optional[str]:
    raw = _first(record, (
        ("server",), ("server_type",), ("implementation",),
        ("executable_name",),
    ))
    if not isinstance(raw, str):
        return None
    value = raw.casefold()
    if value in {"389ds", "389-ds", "ns-slapd", "dirsrv"}:
        return "389ds"
    if value in {"openldap", "slapd"}:
        return "openldap"
    return raw


def _runtime_lock_ghost_rpm_verify_proved(record: Mapping[str, Any]) -> bool:
    verify = _first(record, (
        ("rpm_verify",), ("package", "rpm_verify"),
    ))
    if not isinstance(verify, Mapping):
        return False
    returncode = verify.get("returncode")
    allowed = verify.get("allowed_differences")
    unexpected = verify.get("unexpected_differences")
    lock = verify.get("runtime_lock_metadata")
    stdout = verify.get("stdout")
    stderr = verify.get("stderr")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return False
    raw_lines = [
        line.strip()
        for text in (stdout, stderr)
        for line in text.splitlines()
        if line.strip()
    ]
    return (
        isinstance(returncode, int)
        and not isinstance(returncode, bool)
        and returncode == 1
        and verify.get("clean") is False
        and verify.get("accepted") is True
        and verify.get("accepted_via_runtime_ghost_allowlist") is True
        and verify.get("acceptance_policy")
        == "strict-clean-or-dirsrv-runtime-lock-ghost-ownership-v1"
        and len(raw_lines) == 1
        and re.fullmatch(
            r"\.\.\.\.\.UG\.\.\s+g\s+/var/lock/dirsrv", raw_lines[0],
        ) is not None
        and allowed == [{
            "flags": ".....UG..",
            "file_type": "g",
            "path": "/var/lock/dirsrv",
        }]
        and unexpected == []
        and isinstance(lock, Mapping)
        and lock.get("status") == "observed"
        and lock.get("path") == "/var/lock/dirsrv"
        and lock.get("is_directory") is True
        and lock.get("is_symlink") is False
        and lock.get("mode") == "0770"
        and lock.get("owner") == "dirsrv"
        and lock.get("group") == "dirsrv"
    )


def _installed_package_closure_status(
        executable: Mapping[str, Any], *, required: bool) -> tuple[bool, str]:
    """Validate the four matching 389 DS packages used by modern evidence."""
    if executable.get("executable_name") != "ns-slapd":
        return True, "389 DS package closure is not applicable"
    package_closure = executable.get("installed_package_closure")
    if package_closure is None:
        return (
            (False, "389 DS four-package closure is missing")
            if required else
            (True, "legacy evidence predates four-package closure capture")
        )
    required_names = [
        "389-ds-base", "389-ds-base-libs",
        "389-ds-base-robdb-libs", "python3-lib389",
    ]
    closure_packages = package_closure.get("packages") if isinstance(
        package_closure, Mapping
    ) else None
    if (
            not isinstance(package_closure, Mapping)
            or package_closure.get("complete") is not True
            or (
                required
                and package_closure.get("native_four_package_required")
                is not True
            )
            or package_closure.get("required_packages") != required_names
            or not isinstance(closure_packages, list)
            or len(closure_packages) != len(required_names)):
        return False, "389 DS four-package closure is incomplete"
    if [
            item.get("package_name")
            for item in closure_packages if isinstance(item, Mapping)
            ] != required_names:
        return False, "389 DS package closure names/order disagree"
    evrs: set[str] = set()
    source_rpms: set[str] = set()
    for item in closure_packages:
        if not isinstance(item, Mapping):
            return False, "389 DS package closure record is malformed"
        verify = item.get("rpm_verify")
        if (
                not isinstance(item.get("nevra"), str)
                or not isinstance(item.get("epoch_version_release"), str)
                or not isinstance(item.get("source_rpm"), str)
                or not isinstance(verify, Mapping)
                or verify.get("accepted") is not True):
            return False, "389 DS package closure identity is incomplete"
        evrs.add(str(item["epoch_version_release"]))
        source_rpms.add(str(item["source_rpm"]))
    if len(evrs) != 1 or len(source_rpms) != 1:
        return False, "389 DS package closure contains mixed builds"
    return True, "389 DS four-package closure is observed and matched"


def _rpm_proved(
        record: Mapping[str, Any], *,
        require_package_closure: bool = False) -> bool:
    accepted = _first(record, (
        ("rpm_verify", "accepted"), ("rpm", "verified"),
        ("package", "rpm_verify", "accepted"),
    ))
    verify_returncode = _first(record, (
        ("rpm_verify", "returncode"),
        ("package", "rpm_verify", "returncode"),
    ))
    owner = _first(record, (("owning_package",), ("package", "owner")))
    nevra = _first(record, (
        ("package_nevra",), ("rpm", "nevra"), ("package", "nevra"),
    ))
    base_proved = (
        accepted is True
        and (
            _zero_returncode(verify_returncode)
            or _runtime_lock_ghost_rpm_verify_proved(record)
        )
        and isinstance(owner, str) and bool(owner.strip())
        and isinstance(nevra, str) and bool(nevra.strip())
    )
    closure_proved, _ = _installed_package_closure_status(
        record, required=require_package_closure,
    )
    return base_proved and closure_proved


def _validate_backend_runtime_closure(
        manifest: Mapping[str, Any], source: str, *,
        server_executable: Mapping[str, Any]) -> str:
    closure = manifest.get("backend_runtime_module_closure")
    if not isinstance(closure, Mapping):
        raise MergeError(f"{source}: backend runtime module closure is missing")
    format_version = closure.get("format_version")
    if (
            not isinstance(format_version, int)
            or isinstance(format_version, bool)
            or format_version != 1
            or closure.get("status") != "observed"):
        raise MergeError(f"{source}: backend runtime module closure is not observed v1")
    if closure.get("source") != "linux-proc-pid-maps":
        raise MergeError(f"{source}: backend runtime closure source is invalid")
    pid = closure.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise MergeError(f"{source}: backend runtime closure PID is invalid")
    if closure.get("maps_path") != f"/proc/{pid}/maps":
        raise MergeError(f"{source}: backend runtime closure maps path is invalid")
    server = closure.get("server")
    backend = closure.get("backend")
    if not isinstance(server, str) or not isinstance(backend, str):
        raise MergeError(f"{source}: backend runtime closure lacks server/backend")
    if server not in {"389ds", "openldap"} or backend not in {"mdb", "bdb"}:
        raise MergeError(f"{source}: unsupported backend runtime closure target")

    executable_path = server_executable.get("executable_path")
    expected_executable_name = "ns-slapd" if server == "389ds" else "slapd"
    if (
            not isinstance(executable_path, str)
            or not PurePosixPath(executable_path).is_absolute()
            or PurePosixPath(executable_path).name != expected_executable_name
            or server_executable.get("executable_name")
            != expected_executable_name):
        raise MergeError(f"{source}: installed executable path is invalid")
    executable_sha = _require_sha256(
        server_executable.get("executable_sha256"),
        f"{source}: installed executable SHA-256",
    )
    executable_owner = server_executable.get("owning_package")
    if not isinstance(executable_owner, str) or not executable_owner:
        raise MergeError(f"{source}: installed executable RPM owner is missing")
    live_executable = closure.get("live_executable")
    if (
            not isinstance(live_executable, Mapping)
            or live_executable.get("path") != executable_path
            or live_executable.get("sha256") != executable_sha
            or live_executable.get("proc_exe_path") != f"/proc/{pid}/exe"):
        raise MergeError(
            f"{source}: live PID is not bound to the installed executable identity"
        )

    modules = closure.get("modules")
    if not isinstance(modules, list) or not modules:
        raise MergeError(f"{source}: backend runtime closure has no modules")
    identity_modules = []
    observed_roles: set[str] = set()
    paths: set[str] = set()
    modules_by_path: dict[str, Mapping[str, Any]] = {}
    allowed_roles = {"database-engine"}
    if server == "389ds":
        allowed_roles.update({"389ds-ldbm-backend", "389ds-db-adapter"})
    else:
        allowed_roles.add("openldap-db-backend")
    for index, module in enumerate(modules):
        if not isinstance(module, Mapping):
            raise MergeError(f"{source}: backend closure module {index} is malformed")
        path = module.get("path")
        canonical_path = PurePosixPath(path) if isinstance(path, str) else None
        if (
                not isinstance(path, str)
                or canonical_path is None
                or not canonical_path.is_absolute()
                or ".." in canonical_path.parts
                or str(canonical_path) != path
                or path in paths):
            raise MergeError(
                f"{source}: backend closure module {index} has invalid/duplicate path"
            )
        paths.add(path)
        digest = _require_sha256(
            module.get("sha256"), f"{source}: backend closure module {path}",
        )
        owner = module.get("rpm_owner")
        if not isinstance(owner, str) or not owner.strip():
            raise MergeError(f"{source}: backend closure module {path} lacks RPM owner")
        owner_returncode = module.get("rpm_owner_query_returncode")
        if not _zero_returncode(owner_returncode):
            raise MergeError(
                f"{source}: backend closure module {path} RPM ownership was not proved"
            )
        mapped_paths = module.get("mapped_paths")
        if (
                not isinstance(mapped_paths, list)
                or not mapped_paths
                or any(
                    not isinstance(mapped, str)
                    or not PurePosixPath(mapped).is_absolute()
                    for mapped in mapped_paths
                )):
            raise MergeError(
                f"{source}: backend closure module {path} mapped paths are invalid"
            )
        if (
                len(set(mapped_paths)) != len(mapped_paths)
                or mapped_paths != sorted(mapped_paths)):
            raise MergeError(
                f"{source}: backend closure module {path} mapped paths are invalid"
            )
        roles = module.get("roles")
        if (
                not isinstance(roles, list) or not roles
                or any(not isinstance(role, str) or not role for role in roles)):
            raise MergeError(f"{source}: backend closure module {path} lacks roles")
        normalized_roles = sorted(set(roles))
        if normalized_roles != roles or not set(normalized_roles).issubset(allowed_roles):
            raise MergeError(
                f"{source}: backend closure module {path} has noncanonical roles"
            )
        if path != executable_path:
            classified_path = backend_module_roles(
                Path(path), server=server, backend=backend,
            )
            classified_mappings = [
                backend_module_roles(
                    Path(mapped), server=server, backend=backend,
                )
                for mapped in mapped_paths
            ]
            expected_mapped_roles = sorted({
                role for mapped_roles in classified_mappings
                for role in mapped_roles
            })
            if (
                    any(not mapped_roles for mapped_roles in classified_mappings)
                    or normalized_roles != expected_mapped_roles
                    or normalized_roles != classified_path):
                raise MergeError(
                    f"{source}: backend closure module {path} role attribution "
                    "does not match its mapped path basenames"
                )
        observed_roles.update(normalized_roles)
        modules_by_path[path] = module
        identity_modules.append({
            "sha256": digest,
            "roles": normalized_roles,
        })
    required_roles = closure.get("required_roles")
    if (
            not isinstance(required_roles, list)
            or any(not isinstance(role, str) for role in required_roles)):
        raise MergeError(f"{source}: backend runtime closure lacks required roles")
    expected_roles = {"database-engine"}
    expected_roles.add(
        "389ds-ldbm-backend" if server == "389ds"
        else "openldap-db-backend"
    )
    if required_roles != sorted(expected_roles):
        raise MergeError(
            f"{source}: backend runtime closure required roles are not canonical"
        )
    missing_roles = expected_roles.difference(observed_roles)
    if missing_roles:
        raise MergeError(
            f"{source}: backend runtime closure misses required roles "
            + ", ".join(sorted(missing_roles))
        )

    static_evidence = closure.get("static_backend_evidence")
    executable_module = modules_by_path.get(executable_path)
    non_executable_roles = {
        role
        for module_path, module in modules_by_path.items()
        if module_path != executable_path
        for role in module["roles"]
    }
    if static_evidence is None:
        if executable_module is not None:
            raise MergeError(
                f"{source}: executable carries backend roles without static proof"
            )
    else:
        if server != "openldap" or backend != "mdb":
            raise MergeError(
                f"{source}: static backend evidence is invalid for this target"
            )
        if not isinstance(static_evidence, Mapping):
            raise MergeError(f"{source}: static backend evidence is malformed")
        raw_inventory = static_evidence.get("raw")
        if (
                static_evidence.get("status") != "observed"
                or static_evidence.get("source") != "slapd--VVV"
                or static_evidence.get("live_executable") != executable_path
                or static_evidence.get("selected_backend") != backend
                or not isinstance(raw_inventory, str)):
            raise MergeError(f"{source}: static backend evidence is inconsistent")
        try:
            parsed_backends = parse_openldap_static_backends(raw_inventory)
        except ValueError as error:
            raise MergeError(
                f"{source}: static backend inventory bytes are inconsistent: {error}"
            ) from error
        if (
                backend not in parsed_backends
                or static_evidence.get("included_static_backends") != parsed_backends
                or static_evidence.get("inventory_sha256")
                != sha256_bytes(raw_inventory.encode("utf-8"))):
            raise MergeError(
                f"{source}: static backend inventory bytes are inconsistent"
            )
        assigned_roles = static_evidence.get("assigned_roles")
        expected_assigned_roles = sorted(
            expected_roles.difference(non_executable_roles)
        )
        if (
                executable_module is None
                or not isinstance(assigned_roles, list)
                or not assigned_roles
                or any(
                    not isinstance(role, str) or not role
                    for role in assigned_roles
                )
                or assigned_roles != sorted(set(assigned_roles))
                or assigned_roles != expected_assigned_roles
                or executable_module.get("roles") != assigned_roles
                or executable_module.get("sha256") != executable_sha
                or executable_module.get("rpm_owner") != executable_owner
                or executable_module.get("mapped_paths") != [f"/proc/{pid}/exe"]):
            raise MergeError(
                f"{source}: static backend roles are not bound to live slapd"
            )

    identity_material = {
        "format_version": 1,
        "server": server,
        "backend": backend,
        "required_roles": sorted(expected_roles),
        "live_executable_sha256": executable_sha,
        "modules": sorted(
            identity_modules,
            key=lambda module: (module["roles"], module["sha256"]),
        ),
    }
    if canonical_json_bytes(closure.get("identity_material")) != canonical_json_bytes(
            identity_material):
        raise MergeError(
            f"{source}: backend runtime closure identity material is noncanonical"
        )
    computed = sha256_bytes(canonical_json_bytes(identity_material))
    embedded = _require_sha256(
        closure.get("identity_sha256"),
        f"{source}: backend runtime closure identity_sha256",
    )
    declared = _require_sha256(
        manifest.get("backend_runtime_closure_sha256"),
        f"{source}: backend_runtime_closure_sha256",
    )
    if embedded != computed or declared != computed:
        raise MergeError(f"{source}: backend runtime closure identity mismatch")
    return computed


def _validate_runtime_closure_material(
        manifest: Mapping[str, Any], source: str) -> tuple[str, str]:
    """Recompute the executable/direct-link closure used for performance identity."""
    executable = manifest.get("server_executable")
    if not isinstance(executable, Mapping):
        raise MergeError(f"{source}: server_executable is missing")
    executable_sha = _require_sha256(
        executable.get("executable_sha256"),
        f"{source}: server executable SHA-256",
    )
    material = executable.get("runtime_closure_identity_material")
    if not isinstance(material, Mapping) or material.get("format_version") != 1:
        raise MergeError(
            f"{source}: runtime closure identity material is missing or unsupported"
        )
    artifacts = material.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise MergeError(f"{source}: runtime closure has no artifacts")
    normalized: list[Dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    executable_members = 0
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, Mapping):
            raise MergeError(
                f"{source}: runtime closure artifact {index} is malformed"
            )
        digest = _require_sha256(
            artifact.get("sha256"),
            f"{source}: runtime closure artifact {index}",
        )
        roles = artifact.get("roles")
        if (
                not isinstance(roles, list) or not roles
                or any(not isinstance(role, str) or not role for role in roles)):
            raise MergeError(
                f"{source}: runtime closure artifact {index} has invalid roles"
            )
        normalized_roles = tuple(sorted(set(roles)))
        if normalized_roles not in {
                ("direct-linked-library",), ("server-executable",)}:
            raise MergeError(
                f"{source}: runtime closure artifact {index} has noncanonical roles"
            )
        identity = (digest, normalized_roles)
        if identity in seen:
            raise MergeError(f"{source}: duplicate runtime closure artifact")
        seen.add(identity)
        if "server-executable" in normalized_roles:
            executable_members += 1
            if digest != executable_sha:
                raise MergeError(
                    f"{source}: runtime closure executable member disagrees with "
                    "the installed executable"
                )
        normalized.append({"sha256": digest, "roles": list(normalized_roles)})
    if executable_members != 1:
        raise MergeError(
            f"{source}: runtime closure must contain exactly one server executable"
        )
    linked = executable.get("linked_libraries")
    if (
            not isinstance(linked, Mapping)
            or linked.get("status") != "observed"
            or linked.get("complete") is not True
            or not _zero_returncode(linked.get("ldd_returncode"))
            or linked.get("problems") != []):
        raise MergeError(
            f"{source}: captured direct-linked library evidence is incomplete"
        )
    linked_packages = linked.get("packages")
    if not isinstance(linked_packages, list) or not linked_packages:
        raise MergeError(f"{source}: captured direct-linked packages are missing")
    captured_direct_digests: list[str] = []
    captured_direct_paths: set[str] = set()
    for index, package in enumerate(linked_packages):
        if not isinstance(package, Mapping):
            raise MergeError(
                f"{source}: direct-linked package {index} is malformed"
            )
        path = package.get("path")
        canonical_path = PurePosixPath(path) if isinstance(path, str) else None
        if (
                not isinstance(path, str)
                or canonical_path is None
                or not canonical_path.is_absolute()
                or ".." in canonical_path.parts
                or str(canonical_path) != path
                or path in captured_direct_paths
                or not isinstance(package.get("owner"), str)
                or not package.get("owner", "").strip()
                or not _zero_returncode(package.get("owner_query_returncode"))):
            raise MergeError(
                f"{source}: direct-linked package {index} provenance is invalid"
            )
        captured_direct_paths.add(path)
        captured_direct_digests.append(_require_sha256(
            package.get("sha256"),
            f"{source}: direct-linked package {index} SHA-256",
        ))
    declared_direct_digests = [
        item["sha256"] for item in normalized
        if item["roles"] == ["direct-linked-library"]
    ]
    if sorted(captured_direct_digests) != sorted(declared_direct_digests):
        raise MergeError(
            f"{source}: direct-linked closure contradicts captured package evidence"
        )
    canonical_material = {
        "format_version": 1,
        "artifacts": sorted(
            normalized, key=lambda item: (item["roles"], item["sha256"]),
        ),
    }
    if canonical_json_bytes(material) != canonical_json_bytes(canonical_material):
        raise MergeError(f"{source}: runtime closure identity material is noncanonical")
    computed = sha256_bytes(canonical_json_bytes(canonical_material))
    nested = _require_sha256(
        executable.get("runtime_closure_sha256"),
        f"{source}: server executable runtime_closure_sha256",
    )
    declared = _require_sha256(
        manifest.get("runtime_closure_sha256"),
        f"{source}: runtime_closure_sha256",
    )
    if computed != nested or computed != declared:
        raise MergeError(f"{source}: runtime closure identity mismatch")
    return executable_sha, computed


def _behavioral_runtime_identity(
        runtime_closure_sha256: str,
        backend_runtime_closure_sha256: str) -> str:
    return sha256_bytes(canonical_json_bytes({
        "format_version": 1,
        "runtime_closure_sha256": runtime_closure_sha256,
        "backend_runtime_closure_sha256": backend_runtime_closure_sha256,
    }))


def _validate_behavioral_runtime_identity(
        manifest: Mapping[str, Any], source: str,
        backend_closure_sha256: str) -> tuple[str, str]:
    runtime_closure_sha256 = _require_sha256(
        manifest.get("runtime_closure_sha256"),
        f"{source}: runtime_closure_sha256",
    )
    declared = _require_sha256(
        manifest.get("behavioral_runtime_identity_sha256"),
        f"{source}: behavioral_runtime_identity_sha256",
    )
    computed = _behavioral_runtime_identity(
        runtime_closure_sha256, backend_closure_sha256,
    )
    if declared != computed:
        raise MergeError(f"{source}: behavioral runtime identity mismatch")
    nested_runtime = _nested(manifest, "server_executable", "runtime_closure_sha256")
    if nested_runtime is not None and _require_sha256(
            nested_runtime, f"{source}: server executable runtime closure"
            ) != runtime_closure_sha256:
        raise MergeError(
            f"{source}: server executable and manifest runtime closures disagree"
        )
    return runtime_closure_sha256, computed


def extract_artifacts(
        artifact_manifest: Mapping[str, Any], run_manifest: Mapping[str, Any],
        *, canonical_source: Optional[str],
        canonical_production: Optional[str], canonical_role: Optional[str],
        canonical_server: str,
        evidence_contract_version: Optional[int] = None,
        ) -> list[Dict[str, Any]]:
    commit_labels, _ = _revision_maps()
    candidates = _recursive_artifact_nodes(artifact_manifest, {})
    candidates.extend(_recursive_artifact_nodes(run_manifest, {}))
    deduplicated: Dict[
        tuple[str, str, Optional[str], Optional[str]], Dict[str, Any]
    ] = {}
    for candidate in candidates:
        sha = candidate["executable_sha256"]
        backend_closure_sha = _require_sha256(
            candidate.get("backend_runtime_closure_sha256"),
            "artifact backend_runtime_closure_sha256",
        )
        runtime_closure_sha = _require_sha256(
            candidate.get("runtime_closure_sha256"),
            "artifact runtime_closure_sha256",
        )
        behavioral_identity_sha = _require_sha256(
            candidate.get("behavioral_runtime_identity_sha256"),
            "artifact behavioral_runtime_identity_sha256",
        )
        expected_behavioral_identity = _behavioral_runtime_identity(
            runtime_closure_sha, backend_closure_sha,
        )
        if behavioral_identity_sha != expected_behavioral_identity:
            raise MergeError("artifact behavioral runtime identity mismatch")
        server = _artifact_server(candidate)
        if server != canonical_server:
            raise MergeError(
                "artifact candidate server contradicts the bundle root"
            )
        commit = _artifact_commit(candidate)
        if commit != canonical_source:
            raise MergeError(
                "artifact candidate source revision contradicts the bundle root"
            )
        production_commit = _artifact_production_commit(
            candidate, commit, server,
        )
        if production_commit != canonical_production:
            raise MergeError(
                "artifact candidate production revision contradicts the bundle root"
            )
        candidate_role = _artifact_revision_role(candidate, commit, server)
        if candidate_role is not None and candidate_role != canonical_role:
            raise MergeError(
                "artifact candidate revision role contradicts the bundle root"
            )
        key = (sha, behavioral_identity_sha, server, commit)
        normalized = {
            "executable_sha256": sha,
            "runtime_closure_sha256": runtime_closure_sha,
            "backend_runtime_closure_sha256": backend_closure_sha,
            "behavioral_runtime_identity_sha256": behavioral_identity_sha,
            "server": server,
            "commit": commit,
            "production_commit": production_commit,
            "revision_role": canonical_role,
            "label": _artifact_label(candidate, commit_labels),
            "rpm_proved": _rpm_proved(
                candidate,
                require_package_closure=(
                    evidence_contract_version
                    == NATIVE_EVIDENCE_CONTRACT_VERSION
                ),
            ),
            "evidence_contract_version": evidence_contract_version,
            "artifact_path": candidate.get("artifact_path"),
        }
        previous = deduplicated.get(key)
        if previous is None or (normalized["rpm_proved"] and not previous["rpm_proved"]):
            deduplicated[key] = normalized
    records = list(deduplicated.values())
    if not records:
        raise MergeError("artifact/run manifests contain no installed executable SHA-256")
    return records


@dataclass
class Bundle:
    root: Path
    workload: Dict[str, Any]
    workload_contract: Dict[str, Any]
    artifact_manifest: Dict[str, Any]
    run_manifest: Dict[str, Any]
    correctness_manifest: Dict[str, Any]
    artifacts: list[Dict[str, Any]]
    raw_rows: list[Dict[str, Any]]
    raw_perf_batches: list[Dict[str, Any]]
    raw_metadata: Dict[str, Any]
    raw_digest: str
    run_id: str
    host_signature: Optional[str]
    release_candidate: bool
    disposition_reasons: list[str]


def _parse_csv_value(value: str) -> Any:
    stripped = value.strip()
    if stripped == "":
        return None
    lowered = stripped.casefold()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none", "na", "n/a"}:
        return None
    try:
        return int(stripped)
    except ValueError:
        try:
            return float(stripped)
        except ValueError:
            return stripped


def _load_raw_rows(
        root: Path) -> tuple[
            list[Dict[str, Any]], list[Dict[str, Any]], Dict[str, Any], str, Path,
        ]:
    names = (
        "raw-results.json", "raw-results", "raw-results.jsonl",
        "raw-results.csv",
    )
    paths = [root / name for name in names if (root / name).is_file()]
    if not paths:
        raise MergeError(f"{root}: missing raw-results input")
    if len(paths) > 1:
        raise MergeError(
            f"{root}: ambiguous raw-results inputs: "
            + ", ".join(path.name for path in paths)
        )
    path = paths[0]
    raw_bytes = path.read_bytes()
    rows: Any
    perf_batches: Any = []
    metadata: Dict[str, Any] = {}
    try:
        if path.suffix == ".csv":
            text = raw_bytes.decode("utf-8")
            rows = [
                {key: _parse_csv_value(value or "") for key, value in row.items()}
                for row in csv.DictReader(text.splitlines())
            ]
        elif path.suffix == ".jsonl":
            rows = [
                json.loads(line) for line in raw_bytes.decode("utf-8").splitlines()
                if line.strip()
            ]
        else:
            payload = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(payload, list):
                rows = payload
            elif isinstance(payload, Mapping):
                metadata = dict(payload)
                for row_key in ("rows", "results", "measurements", "raw_results"):
                    metadata.pop(row_key, None)
                metadata.pop("perf_batches", None)
                rows = _first(payload, (
                    ("rows",), ("results",), ("measurements",),
                    ("raw_results",),
                ))
                perf_batches = payload.get("perf_batches", [])
            else:
                rows = None
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as error:
        raise MergeError(f"{path}: cannot parse raw results: {error}") from error
    if not isinstance(rows, list):
        raise MergeError(
            f"{path}: raw results must be a JSON list or an object containing "
            "rows/results/measurements/raw_results"
        )
    normalized: list[Dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise MergeError(f"{path}: raw row {index} is not an object")
        normalized.append(dict(row))
    if not isinstance(perf_batches, list):
        raise MergeError(f"{path}: perf_batches must be a list when present")
    normalized_batches: list[Dict[str, Any]] = []
    for index, batch in enumerate(perf_batches):
        if not isinstance(batch, Mapping):
            raise MergeError(f"{path}: perf batch {index} is not an object")
        normalized_batches.append(dict(batch))
    return (
        normalized,
        normalized_batches,
        metadata,
        hashlib.sha256(raw_bytes).hexdigest(),
        path,
    )


def _host_mapping(run_manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _first(run_manifest, (("host",), ("platform",), ("host_metadata",)))
    return value if isinstance(value, Mapping) else {}


def _host_class(run_manifest: Mapping[str, Any], host: Mapping[str, Any]) -> Optional[str]:
    value = _first(run_manifest, (("host_class",), ("host_mode",)))
    if value is None:
        value = _first(host, (("host_class",), ("host_mode",)))
    return value.casefold() if isinstance(value, str) else None


def _truthy_marker(mapping: Mapping[str, Any], paths: Iterable[Sequence[str]]) -> bool:
    for path in paths:
        value = _nested(mapping, *path)
        if value is True:
            return True
        if isinstance(value, str) and value.casefold() in {
                "yes", "true", "detected", "container", "emulated", "orbstack"}:
            return True
    return False


def _host_signature(
        run_manifest: Mapping[str, Any], host: Mapping[str, Any],
        host_class: Optional[str]) -> Optional[str]:
    compatibility = _first(host, (
        ("timing_environment_signature",), ("compatibility_key",),
        ("host_compatibility",),
    ))
    if compatibility is None:
        compatibility = _first(run_manifest, (
            ("timing_environment_signature",), ("host_compatibility",),
            ("compatibility_key",),
        ))
    architecture = _first(host, (("architecture",), ("arch",), ("machine",)))
    cpu = _first(host, (("cpu_model",), ("cpu", "model_name"), ("lscpu", "Model name")))
    signature = {
        "host_class": host_class,
        "compatibility_key": compatibility,
        "architecture": architecture,
        "cpu_model": cpu,
    }
    if compatibility is None and architecture is None and cpu is None:
        return None
    return sha256_bytes(canonical_json_bytes(signature))


def _effective_schema_contract_status(
        artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str]:
    expected_sha = sha256_bytes(canonical_json_bytes(
        EXPECTED_SCHEMA_SEMANTIC_CONTRACT
    ))
    sources = (
        ("artifact", artifact_manifest.get("effective_schema")),
        ("run", _nested(run_manifest, "server_setup", "effective_schema")),
    )
    verification_records: list[Mapping[str, Any]] = []
    for label, effective in sources:
        if not isinstance(effective, Mapping):
            return False, f"{label} effective-schema evidence is missing"
        if effective.get("evidence_status") != "observed" or not _is_sha256(
                effective.get("canonical_identity_sha256")):
            return False, f"{label} effective-schema capture is not observed/hashed"
        verification = effective.get("custom_schema_verification")
        if not isinstance(verification, Mapping):
            return False, f"{label} custom-schema verification is missing"
        if (
                verification.get("evidence_status") != "observed"
                or verification.get("passed") is not True):
            return False, f"{label} custom-schema verification did not pass"
        contract = verification.get("semantic_contract")
        contract_sha = verification.get("semantic_contract_sha256")
        if (
                not isinstance(contract, Mapping)
                or canonical_json_bytes(contract)
                != canonical_json_bytes(EXPECTED_SCHEMA_SEMANTIC_CONTRACT)
                or contract_sha != expected_sha
                or sha256_bytes(canonical_json_bytes(contract)) != contract_sha):
            return False, f"{label} custom-schema semantic contract is invalid"
        verification_records.append(verification)
    if canonical_json_bytes(verification_records[0]) != canonical_json_bytes(
            verification_records[1]):
        return False, "artifact/run custom-schema verification records disagree"
    return True, "live custom schema matches its canonical semantic contract"


def _is_lower_hex(value: Any, length: Optional[int] = None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if length is not None and len(value) != length:
        return False
    return all(char in "0123456789abcdef" for char in value)


def _canonical_relative_path(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if (
            path.is_absolute() or path.as_posix() != value
            or value == "." or ".." in path.parts):
        return None
    return value


def _matching_setup_evidence(
        field: str, artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[Optional[Mapping[str, Any]], str]:
    artifact_record = artifact_manifest.get(field)
    run_record = _nested(run_manifest, "server_setup", field)
    if not isinstance(artifact_record, Mapping):
        return None, f"artifact {field} evidence is missing"
    if not isinstance(run_record, Mapping):
        return None, f"run {field} evidence is missing"
    if canonical_json_bytes(artifact_record) != canonical_json_bytes(run_record):
        return None, f"artifact/run {field} evidence records disagree"
    return artifact_record, ""


def _harness_identity_status(
        artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str, Optional[str]]:
    artifact_identity = artifact_manifest.get("harness_identity")
    run_identity = run_manifest.get("harness_identity")
    if not isinstance(artifact_identity, Mapping):
        return False, "artifact harness_identity evidence is missing", None
    if not isinstance(run_identity, Mapping):
        return False, "run harness_identity evidence is missing", None
    if canonical_json_bytes(artifact_identity) != canonical_json_bytes(run_identity):
        return False, "artifact/run harness_identity records disagree", None
    if artifact_identity.get("format_version") != 1:
        return False, "harness_identity format is unsupported", None
    files = artifact_identity.get("files")
    if not isinstance(files, Mapping) or not files:
        return False, "harness_identity has no content-addressed files", None
    normalized_files: Dict[str, str] = {}
    for relative, digest in files.items():
        safe_relative = _canonical_relative_path(relative)
        if (
                safe_relative is None
                or "__pycache__" in PurePosixPath(safe_relative).parts
                or safe_relative.endswith(".pyc")):
            return False, "harness_identity contains an unsafe harness path", None
        if not _is_sha256(digest):
            return False, "harness_identity contains an invalid file SHA-256", None
        normalized_files[safe_relative] = str(digest)
    content_sha = artifact_identity.get("content_sha256")
    computed = sha256_bytes(json.dumps(
        {"format_version": 1, "files": normalized_files},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8"))
    if not _is_sha256(content_sha) or content_sha != computed:
        return False, "harness_identity content SHA-256 does not recompute", None
    if (
            artifact_identity.get("git_evidence_status") != "observed"
            or not _is_lower_hex(artifact_identity.get("git_head"), 40)
            or not _is_lower_hex(artifact_identity.get("git_tree"), 40)):
        return False, "harness_identity lacks observed 40-hex git identity", None
    status = artifact_identity.get("git_status_porcelain")
    scoped_path = _canonical_relative_path(
        artifact_identity.get("git_scoped_path")
    )
    if (
            artifact_identity.get("git_study_tree_clean") is not True
            or not isinstance(status, str) or status.strip()
            or scoped_path != "performance/large-filter-study"):
        return False, "harness_identity does not prove a clean scoped study tree", None
    return True, "harness content and clean git identity are observed", str(content_sha)


def _import_verification_status(
        workload: Mapping[str, Any], artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str]:
    record, reason = _matching_setup_evidence(
        "import_verification", artifact_manifest, run_manifest,
    )
    if record is None:
        return False, reason
    if (
            record.get("evidence_status") != "observed"
            or record.get("passed") is not True):
        return False, "live import verification is not observed/pass"
    oracles = record.get("oracles")
    contracts = workload.get("dataset_import_oracles")
    expected_counts = {
        "people": 100_000,
        "principal_outer_cohort": 612,
    }
    if (
            not isinstance(oracles, Mapping)
            or set(oracles) != set(expected_counts)
            or not isinstance(contracts, Mapping)
            or set(contracts) != set(expected_counts)):
        return False, "live import verification lacks the two canonical oracles"
    for oracle_id, expected_count in expected_counts.items():
        oracle = oracles.get(oracle_id)
        contract = contracts.get(oracle_id)
        if not isinstance(oracle, Mapping) or not isinstance(contract, Mapping):
            return False, f"live import oracle {oracle_id} is malformed"
        if (
                oracle.get("evidence_status") != "observed"
                or oracle.get("passed") is not True
                or oracle.get("oracle_id") != oracle_id
                or oracle.get("expected_result_code") != "LDAP_SUCCESS"
                or not _zero_returncode(
                    oracle.get("expected_ldap_result_code")
                )
                or not _zero_returncode(oracle.get("actual_ldap_result_code"))
                or oracle.get("expected_count") != expected_count
                or oracle.get("actual_count") != expected_count):
            return False, (
                f"live import oracle {oracle_id} did not pass its exact "
                f"{expected_count}-entry result contract"
            )
        expected_sha = oracle.get("expected_sha256")
        if (
                not _is_sha256(expected_sha)
                or oracle.get("actual_sha256") != expected_sha
                or contract.get("expected_result_code") != "LDAP_SUCCESS"
                or contract.get("expected_count") != expected_count
                or contract.get("expected_sha256") != expected_sha):
            return False, (
                f"live import oracle {oracle_id} does not bind the workload "
                "count/hash contract"
            )
        for field in (
                "base_dn", "scope", "filter", "requested_attributes"):
            if canonical_json_bytes(oracle.get(field)) != canonical_json_bytes(
                    contract.get(field)):
                return False, (
                    f"live import oracle {oracle_id} disagrees with the "
                    f"workload {field} contract"
                )
    return True, "live import cardinality and DN hashes passed"


def _lookup_mode_evidence_status(
        artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str]:
    record, reason = _matching_setup_evidence(
        "lookup_mode_evidence", artifact_manifest, run_manifest,
    )
    if record is None:
        return False, reason
    if (
            record.get("evidence_status") != "observed"
            or record.get("passed") is not True):
        return False, "lookup-mode readback is not observed/pass"
    requested = record.get("requested")
    actual = record.get("actual_readback")
    run_requested = run_manifest.get("lookup_mode_requested")
    run_actual = run_manifest.get("lookup_mode_actual")
    if (
            not isinstance(requested, str)
            or requested.casefold() not in {"on", "off", "auto", "unsupported"}
            or not isinstance(run_requested, str)
            or requested.casefold() != run_requested.casefold()):
        return False, "lookup-mode evidence disagrees with the requested run mode"
    if (
            not isinstance(actual, str)
            or actual.casefold() not in {"on", "off", "unsupported"}
            or not isinstance(run_actual, str)
            or actual.casefold() != run_actual.casefold()):
        return False, "lookup-mode readback disagrees with run actual"
    if requested.casefold() != "auto" and requested.casefold() != actual.casefold():
        return False, "lookup-mode readback does not match the explicit request"
    return True, "lookup mode was observed and read back"


def _background_referral_check_control_status(
        artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str]:
    """Validate the epoch-aligned quiet window used for native 389 DS timing."""
    record, reason = _matching_setup_evidence(
        "background_referral_check_control", artifact_manifest, run_manifest,
    )
    if record is None:
        return False, reason
    if (
            record.get("evidence_status") != "observed"
            or record.get("passed") is not True):
        return False, "background referral-check control is not observed/pass"
    if (
            record.get("attribute") != "nsslapd-referral-check-period"
            or record.get("requested_seconds") != 3600
            or str(record.get("pre_restart_readback")) != "3600"
            or str(record.get("post_restart_readback")) != "3600"
            or record.get("final_restart_applied") is not True):
        return False, (
            "background referral-check control lacks the final 3600-second "
            "restart/readback contract"
        )
    if (
            record.get("clock") != "CLOCK_MONOTONIC"
            or record.get("interval_anchor") != "kernel-monotonic-epoch"
            or record.get("safety_margin_seconds") != 5):
        return False, (
            "background referral-check control lacks the canonical "
            "monotonic-epoch safety contract"
        )
    access_control = record.get("access_log_internal_operation_control")
    if (
            not isinstance(access_control, Mapping)
            or access_control.get("attribute") != "nsslapd-accesslog-level"
            or access_control.get("requested") != 260
            or str(access_control.get("pre_restart_readback")) != "260"
            or str(access_control.get("post_restart_readback")) != "260"
            or access_control.get("internal_operation_bit_enabled") is not True
            or access_control.get("passed") is not True):
        return False, (
            "background referral-check control does not prove internal "
            "operation access logging"
        )
    expected_policy = {
        "clock": "CLOCK_MONOTONIC",
        "interval_anchor": "kernel-monotonic-epoch",
        "requested_seconds": 3600,
        "safety_margin_seconds": 5.0,
        "collection_policy": "fail-before-or-at-deadline",
    }
    if (
            canonical_json_bytes(record.get("policy_material"))
            != canonical_json_bytes(expected_policy)
            or record.get("policy_sha256")
            != sha256_bytes(canonical_json_bytes(expected_policy))):
        return False, "background referral-check policy identity is invalid"

    vattr_barrier = record.get("post_restart_vattr_check_barrier")
    if not isinstance(vattr_barrier, Mapping):
        return False, "post-restart virtual-attribute check barrier is missing"
    if (
            vattr_barrier.get("status") != "observed-complete"
            or vattr_barrier.get("passed") is not True):
        return False, (
            "post-restart virtual-attribute check barrier is not observed/pass"
        )
    if (
            vattr_barrier.get("source_function")
            != VATTR_CHECK_SOURCE_FUNCTION
            or not isinstance(vattr_barrier.get("delay_seconds"), int)
            or isinstance(vattr_barrier.get("delay_seconds"), bool)
            or vattr_barrier.get("delay_seconds") != VATTR_CHECK_DELAY_SECONDS
            or vattr_barrier.get("exact_filter") != VATTR_CHECK_FILTER):
        return False, (
            "post-restart virtual-attribute check barrier does not identify "
            "the canonical delayed vattr check"
        )
    paired_operations = vattr_barrier.get("paired_operation_count")
    start_lines = vattr_barrier.get("start_line_count")
    completion_lines = vattr_barrier.get("completion_line_count")
    unmatched_starts = vattr_barrier.get("unmatched_start_count")
    if (
            any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in (
                    paired_operations, start_lines, completion_lines,
                    unmatched_starts,
                )
            )
            or paired_operations < 1
            or start_lines < paired_operations
            or completion_lines < paired_operations
            or unmatched_starts != 0):
        return False, (
            "post-restart virtual-attribute check barrier has invalid "
            "paired-operation evidence"
        )
    stability_seconds = vattr_barrier.get("stability_seconds")
    if (
            not isinstance(stability_seconds, (int, float))
            or isinstance(stability_seconds, bool)
            or not math.isfinite(float(stability_seconds))
            or float(stability_seconds)
            < VATTR_CHECK_MINIMUM_STABILITY_SECONDS):
        return False, (
            "post-restart virtual-attribute check barrier lacks the required "
            "stability interval"
        )

    barrier = record.get("barrier")
    if not isinstance(barrier, Mapping):
        return False, "background referral-check paired barrier is missing"
    barrier_counts = (
        barrier.get("paired_operation_count"),
        barrier.get("start_line_count"),
        barrier.get("completion_line_count"),
    )
    unmatched_starts = barrier.get("unmatched_referral_start_count")
    if (
            barrier.get("status") != "observed-complete"
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value < 1
                for value in barrier_counts
            )
            or not isinstance(unmatched_starts, int)
            or isinstance(unmatched_starts, bool)
            or unmatched_starts != 0
            or barrier_counts[0] > min(barrier_counts[1:])):
        return False, "background referral-check paired barrier did not complete"

    quiet = record.get("quiet_window")
    if not isinstance(quiet, Mapping):
        return False, "background referral-check quiet-window evidence is missing"
    bucket = quiet.get("bucket")
    if not isinstance(bucket, int) or isinstance(bucket, bool) or bucket < 0:
        return False, "background referral-check quiet-window bucket is invalid"
    covered_bucket = record.get("barrier_covered_bucket")
    if (
            covered_bucket is not None
            and (
                not isinstance(covered_bucket, int)
                or isinstance(covered_bucket, bool)
                or covered_bucket != bucket
            )):
        return False, (
            "background referral-check barrier does not cover the quiet bucket"
        )
    numeric_fields = (
        "next_boundary_monotonic_seconds",
        "deadline_monotonic_seconds",
        "established_monotonic_seconds",
        "remaining_seconds",
    )
    values: Dict[str, float] = {}
    for field in numeric_fields:
        value = quiet.get(field)
        if (
                not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(float(value)) or float(value) < 0):
            return False, (
                f"background referral-check quiet-window {field} is invalid"
            )
        values[field] = float(value)
    boundary = values["next_boundary_monotonic_seconds"]
    deadline = values["deadline_monotonic_seconds"]
    established = values["established_monotonic_seconds"]
    remaining = values["remaining_seconds"]
    expected_boundary = float((bucket + 1) * 3600)
    if not math.isclose(boundary, expected_boundary, rel_tol=0.0, abs_tol=1e-6):
        return False, (
            "background referral-check quiet-window boundary is not aligned "
            "to the kernel monotonic epoch"
        )
    if not math.isclose(deadline, boundary - 5.0, rel_tol=0.0, abs_tol=1e-6):
        return False, (
            "background referral-check quiet-window deadline does not apply "
            "the declared safety margin"
        )
    if (
            not bucket * 3600 <= established < deadline
            or remaining <= 0
            or not math.isclose(
                remaining, deadline - established,
                rel_tol=0.0, abs_tol=1e-6,
            )
            or quiet.get("policy")
            != "fail-collection-before-or-at-deadline"):
        return False, (
            "background referral-check quiet window is expired, inconsistent, "
            "or lacks the fail-closed collection policy"
        )
    return True, "epoch-aligned background referral quiet window passed"


def _background_quiet_collection_status(
        evidence: Any, setup_record: Any, *, allow_not_applicable: bool = False,
        ) -> tuple[bool, str]:
    """Validate one row/perf/profile collection against its setup window."""
    if not isinstance(evidence, Mapping):
        return False, "background quiet-window collection evidence is missing"
    context = evidence.get("context")
    if not isinstance(context, str) or not context.strip():
        return False, "background quiet-window collection context is missing"
    if evidence.get("clock") != "CLOCK_MONOTONIC":
        return False, "background quiet-window collection clock is invalid"
    if evidence.get("status") == "not-applicable":
        if not allow_not_applicable:
            return False, (
                "background quiet-window collection is unexpectedly not-applicable"
            )
        reason = evidence.get("reason")
        if (
                evidence.get("passed") is not True
                or not isinstance(reason, str) or not reason.strip()
                or any(evidence.get(field) is not None for field in (
                    "bucket", "start_monotonic_seconds",
                    "end_monotonic_seconds",
                    "next_boundary_monotonic_seconds",
                    "deadline_monotonic_seconds", "safety_margin_seconds",
                    "duration_seconds",
                ))):
            return False, (
                "background quiet-window not-applicable evidence is noncanonical"
            )
        return True, "background quiet-window collection is canonically not-applicable"

    start = evidence.get("start_monotonic_seconds")
    end = evidence.get("end_monotonic_seconds")
    if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(float(value)) or float(value) < 0
            for value in (start, end)):
        return False, "background quiet-window collection timestamps are invalid"
    start_value = float(start)
    end_value = float(end)
    if end_value < start_value:
        return False, "background quiet-window collection ends before it starts"
    duration = evidence.get("duration_seconds")
    if duration is not None and (
            not isinstance(duration, (int, float)) or isinstance(duration, bool)
            or not math.isfinite(float(duration)) or float(duration) < 0
            or not math.isclose(
                float(duration), end_value - start_value,
                rel_tol=0.0, abs_tol=1e-6,
            )):
        return False, "background quiet-window collection duration is inconsistent"

    if evidence.get("status") != "passed" or evidence.get("passed") is not True:
        return False, "background quiet-window collection did not pass"
    if not isinstance(setup_record, Mapping):
        return False, "background quiet-window setup evidence is missing"
    setup_quiet = setup_record.get("quiet_window")
    if not isinstance(setup_quiet, Mapping):
        return False, "background quiet-window setup interval is missing"
    bucket = evidence.get("bucket")
    if not isinstance(bucket, int) or isinstance(bucket, bool) or bucket < 0:
        return False, "background quiet-window collection bucket is invalid"
    if bucket != setup_quiet.get("bucket"):
        return False, "background quiet-window collection changed setup bucket"
    boundary = evidence.get("next_boundary_monotonic_seconds")
    deadline = evidence.get("deadline_monotonic_seconds")
    margin = evidence.get("safety_margin_seconds")
    if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(float(value))
            for value in (boundary, deadline, margin)):
        return False, "background quiet-window collection boundary is invalid"
    boundary_value = float(boundary)
    deadline_value = float(deadline)
    margin_value = float(margin)
    setup_boundary = setup_quiet.get("next_boundary_monotonic_seconds")
    setup_deadline = setup_quiet.get("deadline_monotonic_seconds")
    if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(float(value))
            for value in (setup_boundary, setup_deadline)):
        return False, "background quiet-window setup boundary is invalid"
    if (
            margin_value != 5.0
            or not math.isclose(
                boundary_value, float((bucket + 1) * 3600),
                rel_tol=0.0, abs_tol=1e-6,
            )
            or not math.isclose(
                deadline_value, boundary_value - margin_value,
                rel_tol=0.0, abs_tol=1e-6,
            )
            or not math.isclose(
                boundary_value, float(setup_boundary),
                rel_tol=0.0, abs_tol=1e-6,
            )
            or not math.isclose(
                deadline_value, float(setup_deadline),
                rel_tol=0.0, abs_tol=1e-6,
            )
            or not bucket * 3600 <= start_value <= end_value < deadline_value):
        return False, (
            "background quiet-window collection crossed or disagrees with "
            "its epoch-aligned setup interval"
        )
    return True, "background quiet-window collection passed"


def _isolated_operation_quiet_status(
        operation: Any, setup_record: Mapping[str, Any],
        ) -> tuple[bool, str]:
    if not isinstance(operation, Mapping):
        return False, "isolated operation evidence is missing"
    if operation.get("operation_isolated") is not True:
        return False, "operation_isolated=true evidence is missing"
    isolation = operation.get("isolation")
    if not isinstance(isolation, Mapping):
        return False, "isolated operation metadata is missing"
    return _background_quiet_collection_status(
        isolation.get("background_quiet_window"), setup_record,
    )


def _release_correctness_quiet_status(
        correctness_manifest: Mapping[str, Any],
        artifact_manifest: Mapping[str, Any],
        ) -> list[str]:
    """Return fail-closed quiet-window problems for emitted correctness work."""
    setup_record = artifact_manifest.get("background_referral_check_control")
    if not isinstance(setup_record, Mapping):
        return ["correctness background quiet-window setup evidence is missing"]
    problems: list[str] = []
    records = correctness_manifest.get("scenarios", [])
    if isinstance(records, list):
        for record_index, record in enumerate(records):
            if not isinstance(record, Mapping):
                continue
            scenario = record.get("scenario", f"record-{record_index}")
            prefix = f"correctness scenario {scenario}"
            dynamic_fields = (
                "ordinary_candidates", "augmented_candidates",
                "final_search", "post_control_health",
            )
            if any(field in record for field in dynamic_fields):
                for field in dynamic_fields:
                    valid, reason = _isolated_operation_quiet_status(
                        record.get(field), setup_record,
                    )
                    if not valid:
                        problems.append(f"{prefix} {field}: {reason}")
                continue

            flights = record.get("diagnostic_flights")
            emitted_flights: list[tuple[str, Any]] = []
            if isinstance(flights, Mapping):
                emitted_flights.extend(
                    (str(phase), flight) for phase, flight in flights.items()
                )
            elif record.get("operation_isolated") is True:
                emitted_flights.append(("diagnostic", record))
            for phase, flight in emitted_flights:
                valid, reason = _isolated_operation_quiet_status(
                    flight, setup_record,
                )
                if not valid:
                    problems.append(f"{prefix} {phase}: {reason}")
                if not isinstance(flight, Mapping):
                    continue
                selection = flight.get("selection_probe")
                if (
                        isinstance(selection, Mapping)
                        and selection.get("evidence_status") == "observed"):
                    valid, reason = _isolated_operation_quiet_status(
                        selection, setup_record,
                    )
                    if not valid:
                        problems.append(
                            f"{prefix} {phase} selection probe: {reason}"
                        )

    approximate = artifact_manifest.get("approximate_semantics_evidence")
    if (
            isinstance(approximate, Mapping)
            and approximate.get("evidence_status") == "observed"):
        probes = approximate.get("probes")
        probe_records: list[tuple[str, Any]] = []
        if isinstance(probes, list):
            probe_records.extend((
                str(probe.get("probe_id", index))
                if isinstance(probe, Mapping) else str(index), probe,
            ) for index, probe in enumerate(probes))
        elif isinstance(probes, Mapping):
            probe_records.extend(
                (str(probe_id), probe) for probe_id, probe in probes.items()
            )
        for probe_id, probe in probe_records:
            valid, reason = _isolated_operation_quiet_status(
                probe, setup_record,
            )
            if not valid:
                problems.append(
                    f"approximate-semantics probe {probe_id}: {reason}"
                )
    return problems


def _zero_returncode(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _index_build_evidence_status(
        artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any]) -> tuple[bool, str]:
    record, reason = _matching_setup_evidence(
        "index_build_evidence", artifact_manifest, run_manifest,
    )
    if record is None:
        return False, reason
    if (
            record.get("evidence_status") != "observed"
            or record.get("passed") is not True):
        return False, "index-build evidence is not observed/pass"
    import_record = record.get("import")
    reindex_record = record.get("reindex")
    if import_record is not None or reindex_record is not None:
        if not isinstance(import_record, Mapping) or not isinstance(
                reindex_record, Mapping):
            return False, "389 DS index-build evidence is incomplete"
        if (
                not _zero_returncode(import_record.get("returncode"))
                or import_record.get("completed") is not True
                or not _zero_returncode(reindex_record.get("returncode"))
                or reindex_record.get("completed") is not True
                or reindex_record.get("waited_for_completion") is not True):
            return False, "389 DS import/reindex did not complete successfully"
    elif (
            not _zero_returncode(record.get("returncode"))
            or record.get("completed") is not True
            or not _is_sha256(record.get("data_file_sha256"))):
        return False, "OpenLDAP import/index build did not complete successfully"
    return True, "import and index build completed successfully"


def _server_executable_provenance_status(
        artifact_manifest: Mapping[str, Any], *,
        require_package_closure: bool = False) -> tuple[bool, str]:
    executable = artifact_manifest.get("server_executable")
    if not isinstance(executable, Mapping):
        return False, "server_executable evidence is missing"
    build_id = executable.get("elf_build_id")
    if (
            not isinstance(build_id, Mapping)
            or build_id.get("status") != "observed"
            or not _is_lower_hex(build_id.get("value"))):
        return False, "server executable lacks an observed ELF build ID"
    linked = executable.get("linked_libraries")
    if (
            not isinstance(linked, Mapping)
            or linked.get("status") != "observed"
            or linked.get("complete") is not True
            or not _zero_returncode(linked.get("ldd_returncode"))
            or linked.get("problems") != []):
        return False, "server linked-library capture is not observed/complete"
    packages = linked.get("packages")
    if not isinstance(packages, list) or not packages:
        return False, "server linked-library capture contains no packages"
    linked_digests: list[str] = []
    linked_paths: set[str] = set()
    for package in packages:
        if not isinstance(package, Mapping):
            return False, "server linked-library package evidence is malformed"
        path = package.get("path")
        owner = package.get("owner")
        digest = package.get("sha256")
        parsed_path = PurePosixPath(path) if isinstance(path, str) else None
        if (
                parsed_path is None or not parsed_path.is_absolute()
                or parsed_path.as_posix() != path or ".." in parsed_path.parts
                or path in linked_paths or not _is_sha256(digest)
                or not isinstance(owner, str) or not owner.strip()
                or not _zero_returncode(package.get("owner_query_returncode"))):
            return False, "server linked-library package identity is incomplete"
        linked_paths.add(path)
        linked_digests.append(str(digest))
    material = executable.get("runtime_closure_identity_material")
    artifacts = material.get("artifacts") if isinstance(material, Mapping) else None
    if not isinstance(artifacts, list):
        return False, "server runtime closure material is missing"
    closure_digests = sorted(
        str(artifact.get("sha256"))
        for artifact in artifacts
        if isinstance(artifact, Mapping)
        and artifact.get("roles") == ["direct-linked-library"]
    )
    if sorted(linked_digests) != closure_digests:
        return False, "linked libraries disagree with the bound runtime closure"
    package_valid, package_reason = _installed_package_closure_status(
        executable, required=require_package_closure,
    )
    if not package_valid:
        return False, package_reason
    return True, "ELF build ID and linked-library closure are observed"


def _host_capture_status(host: Mapping[str, Any]) -> tuple[bool, str]:
    captures = (
        ("storage", "lsblk", "blockdevices"),
        ("filesystems", "findmnt", "filesystems"),
    )
    for field, command, payload_key in captures:
        capture = host.get(field)
        if not isinstance(capture, Mapping):
            return False, f"host {field} capture is missing"
        argv = capture.get("argv")
        stdout = capture.get("stdout")
        if (
                not isinstance(argv, list) or not argv
                or not isinstance(argv[0], str)
                or PurePosixPath(argv[0]).name != command
                or not _zero_returncode(capture.get("returncode"))
                or not isinstance(stdout, str) or not stdout.strip()):
            return False, f"host {field} capture was not successful"
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return False, f"host {field} capture is not valid JSON"
        values = payload.get(payload_key) if isinstance(payload, Mapping) else None
        if not isinstance(values, list) or not values:
            return False, f"host {field} capture has no {payload_key} inventory"
    return True, "host storage and filesystem inventories were captured"


def _native_protocol_reasons(
        workload: Mapping[str, Any], run_manifest: Mapping[str, Any],
        rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """Independently verify cadence and iteration accounting for one run."""
    reasons: list[str] = []
    repeat_count = run_manifest.get("repeat_count")
    warmup_count = run_manifest.get("warmup_count")
    if (
            not isinstance(repeat_count, int)
            or isinstance(repeat_count, bool)
            or repeat_count < MINIMUM_NATIVE_REPEATS):
        reasons.append(
            f"native run requires at least {MINIMUM_NATIVE_REPEATS} measured "
            "repeats in that run"
        )
    if (
            not isinstance(warmup_count, int)
            or isinstance(warmup_count, bool)
            or warmup_count not in ALLOWED_NATIVE_WARMUPS):
        reasons.append("native run requires exactly 2 or 3 warm-ups")
    selected = run_manifest.get("selected_scenarios")
    scenarios = workload.get("scenarios")
    if (
            not isinstance(selected, list) or not selected
            or len(set(map(str, selected))) != len(selected)
            or not isinstance(scenarios, Mapping)
            or any(str(value) not in scenarios for value in selected)):
        reasons.append("native run has an invalid selected-scenario schedule")
        return reasons
    if not isinstance(repeat_count, int) or not isinstance(warmup_count, int):
        return reasons

    selected_ids = [str(value) for value in selected]
    grouped: dict[tuple[str, str, str], list[int]] = {}
    invalid_row = False
    for row in rows:
        scenario_id = row.get("scenario")
        variant = row.get("attribute_variant")
        phase = row.get("phase")
        iteration = row.get("iteration")
        if (
                not isinstance(scenario_id, str)
                or scenario_id not in selected_ids
                or not isinstance(variant, str) or not variant
                or phase not in {"warmup", "measured"}
                or not isinstance(iteration, int)
                or isinstance(iteration, bool) or iteration < 1):
            invalid_row = True
            continue
        grouped.setdefault((scenario_id, variant, str(phase)), []).append(
            iteration
        )
    if invalid_row:
        reasons.append(
            "raw rows contain an unselected scenario or malformed "
            "scenario/attribute/phase/iteration identity"
        )

    for scenario_id in selected_ids:
        scenario_rows = {
            key: iterations for key, iterations in grouped.items()
            if key[0] == scenario_id
        }
        if not scenario_rows:
            # Dynamic-list and expected historical-mechanism controls are
            # intentionally untimed.  Their absence is accounted for by the
            # correctness/control ledger later in the merge.
            continue
        expected_variants = {"attrs-1.1"}
        if scenario_id in {
                "principal-with-sdn2-equality",
                "principal-without-sdn2-equality"}:
            expected_variants.add("normal-attributes")
        observed_variants = {key[1] for key in scenario_rows}
        if observed_variants != expected_variants:
            reasons.append(
                f"{scenario_id}: observed attribute variants "
                f"{sorted(observed_variants)} do not equal "
                f"{sorted(expected_variants)}"
            )
        for variant in expected_variants:
            for phase, count in (
                    ("warmup", warmup_count),
                    ("measured", repeat_count)):
                observed = sorted(grouped.get(
                    (scenario_id, variant, phase), []
                ))
                expected = list(range(1, count + 1))
                if observed != expected:
                    reasons.append(
                        f"{scenario_id}/{variant}/{phase} iterations are "
                        f"{observed}, expected {expected}"
                    )
    return reasons


def _bundle_disposition(
        workload: Mapping[str, Any], artifact_manifest: Mapping[str, Any],
        run_manifest: Mapping[str, Any], correctness_manifest: Mapping[str, Any],
        raw_metadata: Mapping[str, Any], host: Mapping[str, Any],
        rows: Sequence[Mapping[str, Any]],
        ) -> tuple[bool, list[str], Optional[str]]:
    reasons: list[str] = []
    marker_sources = (
        workload, artifact_manifest, run_manifest, correctness_manifest,
        raw_metadata, host,
    )
    correctness_values = _bool_values(
        *marker_sources, key="correctness_only",
    )
    release_values = _bool_values(
        *marker_sources, key="release_timing_evidence",
    )
    timing_values = _bool_values(
        *marker_sources, key="timing_claims_allowed",
    )
    if len(correctness_values) > 1:
        raise MergeError("contradictory correctness_only markers in result bundle")
    if len(release_values) > 1:
        raise MergeError("contradictory release_timing_evidence markers in result bundle")
    if len(timing_values) > 1:
        raise MergeError("contradictory timing_claims_allowed markers in result bundle")
    correctness_only = next(iter(correctness_values), None)
    release_evidence = next(iter(release_values), None)
    timing_allowed = next(iter(timing_values), None)
    if correctness_only is not False:
        reasons.append("correctness-only or missing correctness_only=false marker")
    if release_evidence is not True:
        reasons.append("missing release_timing_evidence=true marker")
    if run_manifest.get("timing_claims_allowed") is not True or timing_allowed is not True:
        reasons.append("missing timing_claims_allowed=true marker")
    if workload.get("profile") != "full":
        reasons.append("release evidence requires workload profile=full")
    if workload.get("host_intent") != "native_fedora_timing":
        reasons.append("release evidence requires native_fedora_timing workload intent")
    entry_counts = workload.get("entry_counts")
    primary_contract = workload.get("primary_contract")
    if (
            not isinstance(entry_counts, Mapping)
            or entry_counts.get("people") != 100_000
            or entry_counts.get("principal_cohort") != 612):
        reasons.append("release evidence requires exactly 100000 people / 612 principal")
    if (
            not isinstance(primary_contract, Mapping)
            or primary_contract.get("people") != 100_000
            or primary_contract.get("logical_outer_cohort") != 612
            or primary_contract.get("dn_branches") != 355):
        reasons.append("release evidence lacks the full primary 100000/612/355 contract")
    if run_manifest.get("mode") != "native-timing":
        reasons.append("run manifest is not native-timing mode")
    if run_manifest.get("correctness_status") != "pass":
        reasons.append("run manifest correctness_status is not pass")
    reasons.extend(_native_protocol_reasons(workload, run_manifest, rows))
    configuration_contract = run_manifest.get("configuration_contract")
    if isinstance(configuration_contract, Mapping):
        classes = configuration_contract.get("perf_collection_classes")
        signatures = configuration_contract.get("perf_collection_signatures")
        measured_rows = [
            row for row in rows if row.get("phase") == "measured"
        ]
        if measured_rows and (
                not isinstance(classes, list) or len(classes) != 1
                or not isinstance(signatures, list) or len(signatures) != 1):
            reasons.append(
                "one native run must use exactly one actual perf collection "
                "class/signature"
            )
    schema_valid, schema_reason = _effective_schema_contract_status(
        artifact_manifest, run_manifest,
    )
    if not schema_valid:
        reasons.append(schema_reason)
    harness_valid, harness_reason, _harness_content_sha = (
        _harness_identity_status(artifact_manifest, run_manifest)
    )
    if not harness_valid:
        reasons.append(harness_reason)
    import_valid, import_reason = _import_verification_status(
        workload, artifact_manifest, run_manifest,
    )
    if not import_valid:
        reasons.append(import_reason)
    lookup_valid, lookup_reason = _lookup_mode_evidence_status(
        artifact_manifest, run_manifest,
    )
    if not lookup_valid:
        reasons.append(lookup_reason)
    if _artifact_server({"server": run_manifest.get("server")}) == "389ds":
        referral_valid, referral_reason = (
            _background_referral_check_control_status(
                artifact_manifest, run_manifest,
            )
        )
        if not referral_valid:
            reasons.append(referral_reason)
        else:
            reasons.extend(_release_correctness_quiet_status(
                correctness_manifest, artifact_manifest,
            ))
            profiles = run_manifest.get("profiles")
            if isinstance(profiles, list):
                setup_record = artifact_manifest.get(
                    "background_referral_check_control"
                )
                for index, profile in enumerate(profiles):
                    if not isinstance(profile, Mapping):
                        reasons.append(
                            f"profile {index} background quiet-window record "
                            "is malformed"
                        )
                        continue
                    profile_valid, profile_reason = (
                        _background_quiet_collection_status(
                            profile.get("background_quiet_window"),
                            setup_record,
                            allow_not_applicable=(
                                profile.get("status")
                                in {"disabled", "unavailable"}
                            ),
                        )
                    )
                    if not profile_valid:
                        reasons.append(
                            f"profile {index}: {profile_reason}"
                        )
    index_build_valid, index_build_reason = _index_build_evidence_status(
        artifact_manifest, run_manifest,
    )
    if not index_build_valid:
        reasons.append(index_build_reason)
    executable_valid, executable_reason = _server_executable_provenance_status(
        artifact_manifest,
        require_package_closure=(
            run_manifest.get("evidence_contract_version")
            == NATIVE_EVIDENCE_CONTRACT_VERSION
        ),
    )
    if not executable_valid:
        reasons.append(executable_reason)

    host_class = _host_class(run_manifest, host)
    if host_class not in NATIVE_HOST_CLASSES:
        reasons.append(f"non-native host class: {host_class or 'unrecorded'}")
    architecture = _first(host, (("architecture",), ("machine",), ("arch",)))
    if str(architecture).casefold() not in {"x86_64", "amd64"}:
        reasons.append(f"native release architecture is not x86_64: {architecture}")
    if host.get("system") != "Linux":
        reasons.append(f"native release system is not Linux: {host.get('system')}")
    fedora_release = host.get("fedora_release")
    if not isinstance(fedora_release, str) or "fedora" not in fedora_release.casefold():
        reasons.append("native release Fedora identity is missing")
    if host_class and any(token in host_class for token in ("orbstack", "emulat", "container")):
        reasons.append("host class names an emulated/container environment")
    if _truthy_marker(host, (
            ("emulated",), ("is_emulated",), ("container", "detected"),
            ("containerized",), ("container_kind",), ("orbstack",))):
        reasons.append("host metadata reports containerization or emulation")
    host_text = json.dumps(host, sort_keys=True).casefold()
    if any(marker in host_text for marker in ("orbstack", "rosetta", "virtualapple")):
        reasons.append("host metadata contains an Apple-emulation marker")
    container_kind = host.get("container_kind")
    if (
            isinstance(container_kind, str)
            and container_kind.strip().casefold() not in {"", "none"}):
        reasons.append(f"host metadata reports container kind {container_kind}")
    host_capture_valid, host_capture_reason = _host_capture_status(host)
    if not host_capture_valid:
        reasons.append(host_capture_reason)
    signature = _host_signature(run_manifest, host, host_class)
    if signature is None:
        reasons.append("missing native host compatibility signature")
    return not reasons, reasons, signature


def load_bundle(root: Path) -> Bundle:
    root = root.resolve()
    if not root.is_dir():
        raise MergeError(f"result directory does not exist: {root}")
    incomplete_marker = root / "INCOMPLETE"
    cleanup_failed_marker = root / "CLEANUP-FAILED"
    complete_marker = root / "COMPLETE"
    if incomplete_marker.exists() or incomplete_marker.is_symlink():
        raise MergeError(f"{root}: INCOMPLETE marker rejects this result bundle")
    if cleanup_failed_marker.exists() or cleanup_failed_marker.is_symlink():
        raise MergeError(f"{root}: CLEANUP-FAILED marker rejects this result bundle")
    if not complete_marker.is_file() or complete_marker.is_symlink():
        raise MergeError(f"{root}: required COMPLETE marker is absent or invalid")
    workload_path = root / "workload-manifest.json"
    artifact_path = root / "artifact-manifest.json"
    run_path = root / "run-manifest.json"
    workload = _load_json(workload_path)
    artifact_manifest = _load_json(artifact_path)
    run_manifest = _load_json(run_path)
    for value, path in (
            (workload, workload_path), (artifact_manifest, artifact_path),
            (run_manifest, run_path)):
        if not isinstance(value, Mapping):
            raise MergeError(f"{path}: manifest root must be an object")
    if run_manifest.get("status") != "complete":
        raise MergeError(
            f"{run_path}: status must be 'complete' before result aggregation"
        )
    evidence_contract_version = _manifest_evidence_contract_version(
        root, artifact_manifest, run_manifest,
    )
    _validate_profile_artifacts(
        root, run_manifest,
        modern=evidence_contract_version == NATIVE_EVIDENCE_CONTRACT_VERSION,
        workload=workload,
    )
    workload_contract = validate_workload_manifest(workload, workload_path)
    manifest_sha = workload_contract["workload_manifest_sha256"]
    for manifest_value, manifest_name in (
            (artifact_manifest, "artifact manifest"),
            (run_manifest, "run manifest")):
        declared_manifest_sha = _require_sha256(
            manifest_value.get("workload_manifest_sha256"),
            f"{root}: {manifest_name} workload_manifest_sha256",
        )
        if declared_manifest_sha != manifest_sha:
            raise MergeError(
                f"{root}: {manifest_name} does not bind the executed workload manifest"
            )
    if (
            run_manifest.get("workload_id") != workload.get("workload_id")
            or run_manifest.get("workload_sha256")
            != workload_contract["workload_sha256"]):
        raise MergeError(f"{root}: run manifest workload identity disagrees")
    artifact_server = _artifact_server(artifact_manifest)
    run_server = _artifact_server({"server": run_manifest.get("server")})
    run_backend_value = run_manifest.get("backend_actual")
    run_backend = (
        run_backend_value.casefold()
        if isinstance(run_backend_value, str) else None
    )
    if (
            artifact_server not in {"389ds", "openldap"}
            or run_server != artifact_server
            or run_backend not in {"mdb", "bdb"}):
        raise MergeError(
            f"{root}: artifact/run server or actual backend identity is invalid"
        )
    artifact_source = _artifact_commit(artifact_manifest)
    run_source = _artifact_commit(run_manifest)
    if artifact_source != run_source:
        raise MergeError(
            f"{root}: artifact and run manifests disagree on source revision"
        )
    artifact_production = _artifact_production_commit(
        artifact_manifest, artifact_source, artifact_server,
    )
    run_production = _artifact_production_commit(
        run_manifest, run_source, run_server,
    )
    if artifact_production != run_production:
        raise MergeError(
            f"{root}: artifact and run manifests disagree on production revision"
        )
    artifact_role = _artifact_revision_role(
        artifact_manifest, artifact_source, artifact_server,
    )
    run_role = _artifact_revision_role(
        run_manifest, run_source, run_server,
    )
    if (
            artifact_role is not None
            and run_role is not None
            and artifact_role != run_role):
        raise MergeError(
            f"{root}: artifact and run manifests disagree on revision role"
        )
    canonical_role = artifact_role or run_role
    _artifact_executable_sha, validated_runtime_sha = (
        _validate_runtime_closure_material(
            artifact_manifest, str(artifact_path),
        )
    )
    artifact_closure_sha = _validate_backend_runtime_closure(
        artifact_manifest, str(artifact_path),
        server_executable=artifact_manifest["server_executable"],
    )
    run_closure_sha = _validate_backend_runtime_closure(
        run_manifest, str(run_path),
        server_executable=artifact_manifest["server_executable"],
    )
    for closure, label in (
            (artifact_manifest["backend_runtime_module_closure"], "artifact"),
            (run_manifest["backend_runtime_module_closure"], "run")):
        if (
                closure.get("server") != artifact_server
                or closure.get("backend") != run_backend):
            raise MergeError(
                f"{root}: {label} backend runtime closure target disagrees "
                "with the executed server/backend"
            )
    artifact_runtime_sha, artifact_behavioral_sha = (
        _validate_behavioral_runtime_identity(
            artifact_manifest, str(artifact_path), artifact_closure_sha,
        )
    )
    run_runtime_sha, run_behavioral_sha = _validate_behavioral_runtime_identity(
        run_manifest, str(run_path), run_closure_sha,
    )
    if (
            artifact_runtime_sha != validated_runtime_sha
            or artifact_closure_sha != run_closure_sha
            or artifact_runtime_sha != run_runtime_sha
            or artifact_behavioral_sha != run_behavioral_sha
            or canonical_json_bytes(
                artifact_manifest["backend_runtime_module_closure"]
            ) != canonical_json_bytes(
                run_manifest["backend_runtime_module_closure"]
            )):
        raise MergeError(
            f"{root}: artifact and run manifests disagree on runtime identity"
        )
    if evidence_contract_version is not None:
        package_closure = _nested(
            artifact_manifest, "server_executable",
            "installed_package_closure",
        )
        package_closure_sha = sha256_bytes(canonical_json_bytes(
            package_closure
        ))
        artifact_package_sha = _require_sha256(
            artifact_manifest.get("installed_package_closure_sha256"),
            f"{root}: artifact installed package closure SHA-256",
        )
        run_package_sha = _require_sha256(
            run_manifest.get("installed_package_closure_sha256"),
            f"{root}: run installed package closure SHA-256",
        )
        if (
                package_closure_sha != artifact_package_sha
                or package_closure_sha != run_package_sha):
            raise MergeError(
                f"{root}: installed package closure identity disagrees"
            )
    rows, perf_batches, raw_metadata, raw_digest, _ = _load_raw_rows(root)
    run_id = run_manifest.get("run_id")
    if run_id is None:
        # Runner v1 predates an explicit run_id.  Its complete manifest plus
        # byte-exact raw payload provides a stable, content-addressed identity.
        run_id = "derived-" + sha256_bytes(canonical_json_bytes({
            "run_manifest": run_manifest,
            "raw_results_sha256": raw_digest,
        }))[:20]
    if not isinstance(run_id, str) or not run_id:
        raise MergeError(f"{run_path}: run_id must be a non-empty string")
    correctness_path = root / "correctness.json"
    correctness_manifest: Dict[str, Any] = {}
    if correctness_path.is_file():
        loaded_correctness = _load_json(correctness_path)
        if not isinstance(loaded_correctness, Mapping):
            raise MergeError(f"{correctness_path}: root must be an object")
        correctness_manifest = dict(loaded_correctness)
    if evidence_contract_version is not None:
        versioned_payloads = (
            (raw_metadata, "raw-results"),
            (correctness_manifest, "correctness"),
        )
        for payload, label in versioned_payloads:
            if payload.get("evidence_contract_version") != (
                    evidence_contract_version):
                raise MergeError(
                    f"{root}: {label} does not bind evidence contract v"
                    f"{evidence_contract_version}"
                )
    host = _host_mapping(run_manifest)
    release_candidate, reasons, signature = _bundle_disposition(
        workload, artifact_manifest, run_manifest, correctness_manifest,
        raw_metadata, host, rows,
    )
    return Bundle(
        root=root,
        workload=dict(workload),
        workload_contract=workload_contract,
        artifact_manifest=dict(artifact_manifest),
        run_manifest=dict(run_manifest),
        correctness_manifest=correctness_manifest,
        artifacts=extract_artifacts(
            artifact_manifest, run_manifest,
            canonical_source=artifact_source,
            canonical_production=artifact_production,
            canonical_role=canonical_role,
            canonical_server=artifact_server,
            evidence_contract_version=evidence_contract_version,
        ),
        raw_rows=rows,
        raw_perf_batches=perf_batches,
        raw_metadata=raw_metadata,
        raw_digest=raw_digest,
        run_id=run_id,
        host_signature=signature,
        release_candidate=release_candidate,
        disposition_reasons=reasons,
    )


def _bundle_identity(bundle: Bundle) -> str:
    value = {
        "workload": bundle.workload,
        "artifact": bundle.artifact_manifest,
        "run": bundle.run_manifest,
        "correctness": bundle.correctness_manifest,
        "raw_sha256": bundle.raw_digest,
    }
    return sha256_bytes(canonical_json_bytes(value))


def validate_bundles(bundles: Sequence[Bundle]) -> tuple[list[Bundle], list[Dict[str, Any]]]:
    if not bundles:
        raise MergeError("at least one result directory is required")
    reference = bundles[0].workload_contract
    unique: list[Bundle] = []
    duplicates: list[Dict[str, Any]] = []
    run_ids: Dict[str, tuple[str, Path]] = {}
    for bundle in bundles:
        difference = _workload_difference(reference, bundle.workload_contract)
        if difference:
            raise MergeError(
                f"{bundle.root}: incompatible {difference} hashes/contracts"
            )
        identity = _bundle_identity(bundle)
        previous = run_ids.get(bundle.run_id)
        if previous:
            previous_identity, previous_path = previous
            if identity != previous_identity:
                raise MergeError(
                    f"run_id {bundle.run_id!r} has conflicting content in "
                    f"{previous_path} and {bundle.root}"
                )
            duplicates.append({
                "run_id": bundle.run_id,
                "ignored_path": str(bundle.root),
                "canonical_path": str(previous_path),
            })
            continue
        run_ids[bundle.run_id] = (identity, bundle.root)
        unique.append(bundle)

    native_signatures = {
        bundle.host_signature for bundle in unique if bundle.release_candidate
    }
    if len(native_signatures) > 1:
        raise MergeError(
            "native result bundles have incompatible host-mode signatures; "
            "merge each timing environment separately"
        )
    native_harness_hashes = {
        str(bundle.artifact_manifest["harness_identity"]["content_sha256"])
        for bundle in unique if bundle.release_candidate
    }
    if len(native_harness_hashes) > 1:
        raise MergeError(
            "native result bundles have incompatible harness content hashes; "
            "merge results produced by one harness identity"
        )
    return unique, duplicates


def assess_schedules(bundles: Sequence[Bundle]) -> Dict[str, Any]:
    """Validate every declared ABBA block and retain exploratory screens."""
    required_positions = ("A1", "B1", "B2", "A2")
    blocks: dict[str, list[Bundle]] = {}
    screen_runs: list[str] = []
    unspecified_runs: list[str] = []
    malformed_runs: list[Dict[str, str]] = []

    def timestamp(value: Any, context: str) -> datetime:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{context} timestamp is missing")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{context} timestamp is invalid") from error
        if parsed.tzinfo is None:
            raise ValueError(f"{context} timestamp lacks a timezone")
        return parsed

    for bundle in bundles:
        schedule = bundle.run_manifest.get("schedule")
        if not isinstance(schedule, Mapping):
            unspecified_runs.append(bundle.run_id)
            continue
        if schedule.get("format_version") != 1:
            malformed_runs.append({
                "run_id": bundle.run_id,
                "reason": "unsupported schedule format version",
            })
            continue
        design = schedule.get("design")
        if design == "screen":
            screen_runs.append(bundle.run_id)
            continue
        if design == "unspecified":
            unspecified_runs.append(bundle.run_id)
            continue
        if design != "abba":
            malformed_runs.append({
                "run_id": bundle.run_id,
                "reason": f"unsupported schedule design {design!r}",
            })
            continue
        block_id = schedule.get("block_id")
        if not isinstance(block_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", block_id):
            malformed_runs.append({
                "run_id": bundle.run_id,
                "reason": "ABBA block id is missing or malformed",
            })
            continue
        blocks.setdefault(block_id, []).append(bundle)

    block_results: list[Dict[str, Any]] = []
    for block_id in sorted(blocks):
        members = blocks[block_id]
        failures: list[str] = []
        positions: dict[str, Bundle] = {}
        for bundle in members:
            schedule = bundle.run_manifest["schedule"]
            position = schedule.get("position")
            if position not in required_positions:
                failures.append(
                    f"{bundle.run_id}: invalid ABBA position {position!r}"
                )
                continue
            if str(position) in positions:
                failures.append(f"duplicate position {position}")
                continue
            positions[str(position)] = bundle
            expected_state = str(position)[0]
            if schedule.get("state") != expected_state:
                failures.append(
                    f"{bundle.run_id}: state does not match {position}"
                )
            if schedule.get("release_ordering_eligible") is not True:
                failures.append(
                    f"{bundle.run_id}: schedule is not release-ordering eligible"
                )
            for top_level, schedule_field in (
                    ("schedule_design", "design"),
                    ("schedule_block_id", "block_id"),
                    ("schedule_position", "position"),
                    ("schedule_state", "state"),
                    ("schedule_state_fingerprint", "state_fingerprint")):
                if bundle.run_manifest.get(top_level) != schedule.get(
                        schedule_field):
                    failures.append(
                        f"{bundle.run_id}: top-level {top_level} disagrees"
                    )
        missing = sorted(set(required_positions).difference(positions))
        if missing:
            failures.append("missing positions: " + ", ".join(missing))
        if len(members) != 4:
            failures.append(
                f"block contains {len(members)} runs rather than exactly 4"
            )

        fingerprints: dict[str, str] = {}
        materials: dict[str, Mapping[str, Any]] = {}
        for position, bundle in positions.items():
            schedule = bundle.run_manifest["schedule"]
            material = schedule.get("state_fingerprint_material")
            declared = schedule.get("state_fingerprint")
            if not isinstance(material, Mapping):
                failures.append(
                    f"{bundle.run_id}: state fingerprint material is missing"
                )
                continue
            profiles = bundle.run_manifest.get("profiles")
            profiles = profiles if isinstance(profiles, list) else []
            profile_states = sorted(({
                "scenario": profile.get("scenario"),
                "status": profile.get("status"),
                "sampling_event": profile.get("sampling_event"),
                "software_fallback": profile.get("software_fallback") is True,
            } for profile in profiles if isinstance(profile, Mapping)),
                key=lambda value: str(value["scenario"]))
            expected_material = {
                "format_version": 1,
                "evidence_contract_version": bundle.run_manifest.get(
                    "evidence_contract_version"
                ),
                "server": bundle.run_manifest.get("server"),
                "source_revision": bundle.run_manifest.get(
                    "expected_source_sha"
                ),
                "production_revision": bundle.run_manifest.get(
                    "production_equivalent_revision"
                ),
                "executable_sha256": _nested(
                    bundle.artifact_manifest, "server_executable",
                    "executable_sha256",
                ),
                "installed_package_closure_sha256": (
                    bundle.run_manifest.get(
                        "installed_package_closure_sha256"
                    )
                ),
                "runtime_closure_sha256": bundle.run_manifest.get(
                    "runtime_closure_sha256"
                ),
                "backend_runtime_closure_sha256": bundle.run_manifest.get(
                    "backend_runtime_closure_sha256"
                ),
                "behavioral_runtime_identity_sha256": bundle.run_manifest.get(
                    "behavioral_runtime_identity_sha256"
                ),
                "lookup_mode": bundle.run_manifest.get("lookup_mode_actual"),
                "backend": bundle.run_manifest.get("backend_actual"),
                "index_config": bundle.run_manifest.get("index_config"),
                "cache_policy": bundle.run_manifest.get("cache_policy"),
                "perf_mode": bundle.run_manifest.get("perf_mode"),
                "perf_collection_classes": bundle.run_manifest.get(
                    "perf_collection_classes", []
                ),
                "perf_collection_signatures": bundle.run_manifest.get(
                    "perf_collection_signatures", []
                ),
                "profile_mode": bundle.run_manifest.get("profile_mode"),
                "profile_collection_states": profile_states,
                "connection_policy": bundle.run_manifest.get(
                    "connection_policy"
                ),
                "bind_class": bundle.run_manifest.get("bind_class"),
                "repeat_count": bundle.run_manifest.get("repeat_count"),
                "warmup_count": bundle.run_manifest.get("warmup_count"),
                "cpu_affinity": bundle.run_manifest.get("cpu_affinity"),
                "scenario_order": bundle.run_manifest.get("scenario_order"),
                "order_seed": bundle.run_manifest.get("order_seed"),
                "selected_scenarios": bundle.run_manifest.get(
                    "selected_scenarios"
                ),
            }
            if canonical_json_bytes(material) != canonical_json_bytes(
                    expected_material):
                failures.append(
                    f"{bundle.run_id}: state fingerprint material disagrees "
                    "with the executed run"
                )
                continue
            computed = sha256_bytes(canonical_json_bytes(material))
            if not _is_sha256(declared) or declared != computed:
                failures.append(
                    f"{bundle.run_id}: state fingerprint is invalid"
                )
                continue
            fingerprints[position] = computed
            materials[position] = material
        if set(fingerprints) == set(required_positions):
            if fingerprints["A1"] != fingerprints["A2"]:
                failures.append("A1 and A2 state fingerprints differ")
            if fingerprints["B1"] != fingerprints["B2"]:
                failures.append("B1 and B2 state fingerprints differ")
            if fingerprints["A1"] == fingerprints["B1"]:
                failures.append("A and B states are identical")

        invariant_keys = (
            "evidence_contract_version", "backend", "index_config",
            "cache_policy",
            "perf_mode", "perf_collection_classes",
            "perf_collection_signatures", "profile_mode",
            "profile_collection_states", "connection_policy", "bind_class",
            "repeat_count", "warmup_count", "cpu_affinity",
            "scenario_order", "order_seed", "selected_scenarios",
        )
        if set(materials) == set(required_positions):
            invariant_values = {
                canonical_json_bytes({
                    key: materials[position].get(key)
                    for key in invariant_keys
                })
                for position in required_positions
            }
            if len(invariant_values) != 1:
                failures.append(
                    "ABBA runs disagree on invariant execution protocol"
                )

        if set(positions) == set(required_positions):
            harnesses = {
                _nested(bundle.run_manifest, "harness_identity", "content_sha256")
                for bundle in positions.values()
            }
            workloads = {
                bundle.run_manifest.get("workload_manifest_sha256")
                for bundle in positions.values()
            }
            hosts = {bundle.host_signature for bundle in positions.values()}
            if len(harnesses) != 1 or len(workloads) != 1 or len(hosts) != 1:
                failures.append(
                    "ABBA runs disagree on harness, workload, or host identity"
                )
            try:
                windows = [(
                    timestamp(
                        positions[position].run_manifest.get("created_at"),
                        f"{position} created_at",
                    ),
                    timestamp(
                        positions[position].run_manifest.get("completed_at"),
                        f"{position} completed_at",
                    ),
                ) for position in required_positions]
                if any(start > end for start, end in windows):
                    failures.append("an ABBA run completed before it started")
                if any(
                        windows[index][1] > windows[index + 1][0]
                        for index in range(len(windows) - 1)):
                    failures.append(
                        "execution timestamps do not prove A1/B1/B2/A2 order"
                    )
            except ValueError as error:
                failures.append(str(error))

        block_results.append({
            "block_id": block_id,
            "status": "pass" if not failures else "pending",
            "run_ids_by_position": {
                position: positions[position].run_id
                for position in required_positions if position in positions
            },
            "state_fingerprints": {
                position: fingerprints[position]
                for position in required_positions if position in fingerprints
            },
            "failures": sorted(set(failures)),
        })

    valid_blocks = [
        block["block_id"] for block in block_results
        if block["status"] == "pass"
    ]
    if malformed_runs or any(
            block["status"] != "pass" for block in block_results):
        status = "pending"
    elif block_results:
        status = "complete"
    else:
        status = "pending"
    return {
        "format_version": 1,
        "status": status,
        "required_design": "ABBA",
        "required_positions": list(required_positions),
        "declared_block_count": len(block_results),
        "valid_block_count": len(valid_blocks),
        "valid_blocks": valid_blocks,
        "blocks": block_results,
        "screen_run_ids": sorted(screen_runs),
        "unspecified_run_ids": sorted(unspecified_runs),
        "malformed_runs": malformed_runs,
    }


def _load_matrix_plan(
        path: Path, workload: Mapping[str, Any]) -> Dict[str, Any]:
    plan = _load_json(path)
    if not isinstance(plan, Mapping) or plan.get("format_version") != 1:
        raise MergeError(f"{path}: unsupported native matrix plan")
    protocol = plan.get("timing_protocol")
    pairs = plan.get("timed_pair_rules")
    controls = plan.get("correctness_control_rules")
    if (
            not isinstance(protocol, Mapping)
            or not isinstance(pairs, list) or not pairs
            or not isinstance(controls, list) or not controls):
        raise MergeError(f"{path}: native matrix plan is incomplete")
    if protocol.get("minimum_repeats_per_run") < MINIMUM_NATIVE_REPEATS:
        raise MergeError(f"{path}: matrix cadence is below the native minimum")
    if protocol.get("required_evidence_contract_version") != (
            NATIVE_EVIDENCE_CONTRACT_VERSION):
        raise MergeError(
            f"{path}: matrix evidence contract version is unsupported"
        )
    if protocol.get("allowed_warmups") != sorted(ALLOWED_NATIVE_WARMUPS):
        raise MergeError(f"{path}: matrix warm-up contract must be [2, 3]")
    scenarios = workload.get("scenarios")
    groups = workload.get("scenario_groups")
    if not isinstance(scenarios, Mapping) or not isinstance(groups, Mapping):
        raise MergeError("executed workload lacks scenarios or scenario groups")
    authoritative_workload = plan.get("authoritative_workload")
    if (
            not isinstance(authoritative_workload, Mapping)
            or authoritative_workload.get("scenario_count") != 118
            or not isinstance(authoritative_workload.get("workload_id"), str)
            or any(
                not _is_sha256(authoritative_workload.get(field))
                for field in (
                    "workload_sha256", "workload_manifest_sha256",
                    "canonical_workload_manifest_sha256",
                )
            )):
        raise MergeError(
            f"{path}: authoritative workload identity is incomplete"
        )
    seen_ids: set[str] = set()
    for section, rules in (
            ("timed pair", pairs), ("correctness control", controls)):
        for index, rule in enumerate(rules):
            if not isinstance(rule, Mapping):
                raise MergeError(f"{path}: malformed {section} rule {index}")
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id or rule_id in seen_ids:
                raise MergeError(f"{path}: duplicate/missing matrix rule id")
            seen_ids.add(rule_id)
            for group in (
                    rule.get("scenario_groups", [])
                    if isinstance(rule.get("scenario_groups", []), list)
                    else []):
                if not isinstance(group, str) or not group:
                    raise MergeError(
                        f"{path}: rule {rule_id} has malformed scenario group"
                    )
            group_ref = rule.get("scenario_groups_ref")
            if group_ref is not None:
                referenced = plan.get(str(group_ref))
                if not isinstance(referenced, list) or any(
                        not isinstance(group, str) or not group
                        for group in referenced):
                    raise MergeError(
                        f"{path}: rule {rule_id} has invalid group reference"
                    )
            for scenario_id in (
                    rule.get("scenarios", [])
                    if isinstance(rule.get("scenarios", []), list)
                    else []):
                if not isinstance(scenario_id, str) or not scenario_id:
                    raise MergeError(
                        f"{path}: rule {rule_id} has malformed scenario"
                    )
            group = rule.get("scenario_group")
            if group is not None and (
                    not isinstance(group, str) or not group):
                raise MergeError(
                    f"{path}: rule {rule_id} has malformed scenario group"
                )
    all_timed_groups = plan.get("all_timed_scenario_groups")
    if not isinstance(all_timed_groups, list) or any(
            not isinstance(group, str) or not group
            for group in all_timed_groups):
        raise MergeError(f"{path}: all-timed group list is invalid")
    if all(group in groups for group in all_timed_groups) and (
            "dynamic-list-correctness" in groups):
        timed = {
            str(scenario_id)
            for group in all_timed_groups
            for scenario_id in groups[group]
        }
        dynamic = set(groups["dynamic-list-correctness"])
        if timed != set(map(str, scenarios)).difference(dynamic):
            raise MergeError(
                f"{path}: all-timed groups do not cover exactly the "
                "non-dynamic matrix"
            )
    return dict(plan)


def _matrix_rule_scenarios(
        rule: Mapping[str, Any], plan: Mapping[str, Any],
        workload: Mapping[str, Any]) -> list[str]:
    groups = workload["scenario_groups"]
    names: list[str] = []
    reference = rule.get("scenario_groups_ref")
    if isinstance(reference, str):
        names.extend(map(str, plan[reference]))
    raw_groups = rule.get("scenario_groups")
    if isinstance(raw_groups, list):
        names.extend(map(str, raw_groups))
    selected = {
        str(scenario_id)
        for group in names
        for scenario_id in groups.get(group, [])
    }
    raw_scenarios = rule.get("scenarios")
    if isinstance(raw_scenarios, list):
        selected.update(
            str(value) for value in raw_scenarios
            if str(value) in workload["scenarios"]
        )
    group = rule.get("scenario_group")
    if isinstance(group, str):
        selected.update(map(str, groups.get(group, [])))
    return sorted(selected)


def assess_matrix_completion(
        plan: Mapping[str, Any], workload: Mapping[str, Any],
        summaries: Sequence[Mapping[str, Any]],
        correctness_controls: Sequence[Mapping[str, Any]],
        schedule_assessment: Mapping[str, Any], *,
        workload_contract: Optional[Mapping[str, Any]] = None,
        plan_authoritative: bool = True,
        plan_binding_failures: Sequence[str] = (),
        ) -> Dict[str, Any]:
    """Expand the frozen plan and prove each timed pair/control cell."""
    protocol = plan["timing_protocol"]
    workload_groups = workload.get("scenario_groups", {})
    workload_scenarios = workload.get("scenarios", {})
    required_groups = set(map(str, plan.get(
        "all_timed_scenario_groups", []
    )))
    required_groups.update(map(str, plan.get(
        "profile_required_groups", []
    )))
    required_groups.add("dynamic-list-correctness")
    explicit_scenarios: set[str] = set()
    for rule in [
            *plan.get("timed_pair_rules", []),
            *plan.get("correctness_control_rules", [])]:
        if not isinstance(rule, Mapping):
            continue
        required_groups.update(map(str, rule.get("scenario_groups", [])))
        if isinstance(rule.get("scenario_group"), str):
            required_groups.add(str(rule["scenario_group"]))
        reference = rule.get("scenario_groups_ref")
        if isinstance(reference, str):
            required_groups.update(map(str, plan.get(reference, [])))
        explicit_scenarios.update(map(str, rule.get("scenarios", [])))
    missing_groups = sorted(required_groups.difference(workload_groups))
    missing_scenarios = sorted(
        explicit_scenarios.difference(workload_scenarios)
    )
    full_contract = (
        workload.get("profile") == "full"
        and len(workload_scenarios) == 118
        and not missing_groups and not missing_scenarios
    )
    authoritative_workload = plan.get("authoritative_workload")
    workload_identity_problems: list[str] = []
    if authoritative_workload is not None:
        if not isinstance(authoritative_workload, Mapping):
            workload_identity_problems.append(
                "matrix plan authoritative_workload is malformed"
            )
        else:
            observed_contract = workload_contract or {}
            observed = {
                "workload_id": workload.get("workload_id"),
                "workload_sha256": workload.get("workload_sha256"),
                "workload_manifest_sha256": observed_contract.get(
                    "workload_manifest_sha256"
                ),
                "canonical_workload_manifest_sha256": observed_contract.get(
                    "canonical_workload_manifest_sha256",
                    sha256_bytes(canonical_json_bytes(workload)),
                ),
                "scenario_count": len(workload_scenarios),
            }
            for field in (
                    "workload_id", "workload_sha256",
                    "workload_manifest_sha256",
                    "canonical_workload_manifest_sha256", "scenario_count"):
                if observed.get(field) != authoritative_workload.get(field):
                    workload_identity_problems.append(
                        f"{field} does not match the frozen workload"
                    )
    full_contract = full_contract and not workload_identity_problems
    workload_instance = {
        "instance_id": "frozen-full-workload-contract",
        "status": "pass" if full_contract else "pending",
        "reason": (
            "executed workload exposes the complete 118-scenario plan"
            if full_contract else
            "executed workload cannot establish the complete frozen plan: "
            f"scenario_count={len(workload_scenarios)}, "
            f"missing_groups={missing_groups}, "
            f"missing_scenarios={missing_scenarios}, "
            f"identity_problems={workload_identity_problems}"
        ),
        "evidence_refs": [],
    }
    plan_instance: Optional[Dict[str, Any]] = None
    if authoritative_workload is not None:
        plan_valid = plan_authoritative and not plan_binding_failures
        plan_instance = {
            "instance_id": "frozen-native-matrix-plan",
            "status": "pass" if plan_valid else "pending",
            "reason": (
                "the authoritative plan hash is bound by every modern bundle"
                if plan_valid else
                "the selected plan is not release-authoritative or one or more "
                "modern bundles do not bind its exact file identity: "
                + "; ".join(plan_binding_failures)
            ),
            "evidence_refs": list(plan_binding_failures),
        }
    profile_ids = {
        str(scenario_id)
        for group in plan.get("profile_required_groups", [])
        for scenario_id in workload_groups.get(group, [])
    }
    valid_blocks = {
        str(block["block_id"]): block
        for block in schedule_assessment.get("blocks", [])
        if block.get("status") == "pass"
    }

    def expected_attribute_modes(scenario_id: str) -> list[str]:
        modes = ["attrs-1.1"]
        if scenario_id in {
                "principal-with-sdn2-equality",
                "principal-without-sdn2-equality"}:
            modes.append("normal-attributes")
        return modes

    def matching_summaries(
            selector: Mapping[str, Any], scenario_id: str,
            attribute_mode: str) -> list[Mapping[str, Any]]:
        scenario = workload_scenarios[scenario_id]
        return [
            summary for summary in summaries
            if summary.get("release_ready") is True
            and summary.get("scenario_ids") == [scenario_id]
            and summary.get("configuration", {}).get("server")
            == selector.get("server")
            and selector.get("revision_role") in summary.get(
                "revision_roles", []
            )
            and str(summary.get("configuration", {}).get(
                "lookup_mode"
            )).casefold() == str(selector.get("lookup_mode")).casefold()
            and summary.get("configuration", {}).get("backend")
            == protocol.get("required_backend")
            and summary.get("configuration", {}).get("cache_policy")
            == protocol.get("required_cache_policy")
            and summary.get("configuration", {}).get("index_variant")
            == scenario.get("index_variant")
            and summary.get("configuration", {}).get("attribute_mode")
            == attribute_mode
            and summary.get("configuration", {}).get(
                "perf_collection_class"
            ) == protocol.get("required_perf_collection_class")
            and summary.get("configuration", {}).get(
                "evidence_contract_version"
            ) == protocol.get("required_evidence_contract_version")
            and summary.get("instructions", {}).get("n", 0)
            >= int(protocol.get("minimum_repeats_per_run", 15))
            and (
                scenario_id not in profile_ids or _profile_proved(summary)
            )
        ]

    pair_instances: list[Dict[str, Any]] = []
    for rule in plan["timed_pair_rules"]:
        rule_id = str(rule["id"])
        for scenario_id in _matrix_rule_scenarios(rule, plan, workload):
            for attribute_mode in expected_attribute_modes(scenario_id):
                a_matches = matching_summaries(
                    rule["a"], scenario_id, attribute_mode,
                )
                b_matches = matching_summaries(
                    rule["b"], scenario_id, attribute_mode,
                )
                instance_id = f"{rule_id}:{scenario_id}:{attribute_mode}"
                if len(a_matches) != 1 or len(b_matches) != 1:
                    pair_instances.append({
                        "instance_id": instance_id,
                        "status": "pending",
                        "reason": (
                            "required unique release-ready hardware/profile "
                            f"summaries are absent or ambiguous (A={len(a_matches)}, "
                            f"B={len(b_matches)})"
                        ),
                        "evidence_refs": [
                            *[str(value["summary_id"]) for value in a_matches],
                            *[str(value["summary_id"]) for value in b_matches],
                        ],
                    })
                    continue
                a_summary, b_summary = a_matches[0], b_matches[0]
                same_revision_toggle = (
                    rule["a"].get("server") == rule["b"].get("server")
                    and rule["a"].get("revision_role")
                    == rule["b"].get("revision_role")
                )
                if same_revision_toggle and any((
                        a_summary.get("executable_sha256")
                        != b_summary.get("executable_sha256"),
                        a_summary.get("behavioral_runtime_identity_sha256")
                        != b_summary.get("behavioral_runtime_identity_sha256"),
                        a_summary.get("installed_package_closure_sha256")
                        != b_summary.get("installed_package_closure_sha256"),
                )):
                    pair_instances.append({
                        "instance_id": instance_id,
                        "status": "pending",
                        "reason": (
                            "same-revision runtime toggle does not use one "
                            "exact executable/runtime/package closure"
                        ),
                        "evidence_refs": [
                            str(a_summary["summary_id"]),
                            str(b_summary["summary_id"]),
                        ],
                    })
                    continue
                a_runs = set(map(str, a_summary.get("source_run_ids", [])))
                b_runs = set(map(str, b_summary.get("source_run_ids", [])))
                proving_blocks: list[tuple[str, set[str], set[str]]] = []
                for block_id, block in valid_blocks.items():
                    by_position = block.get("run_ids_by_position", {})
                    if (
                            not isinstance(by_position, Mapping)
                            or set(by_position) != {"A1", "B1", "B2", "A2"}
                            or any(
                                not isinstance(by_position[position], str)
                                or not by_position[position]
                                for position in ("A1", "B1", "B2", "A2")
                            )):
                        continue
                    a_arm = {
                        str(by_position["A1"]),
                        str(by_position["A2"]),
                    }
                    b_arm = {
                        str(by_position["B1"]),
                        str(by_position["B2"]),
                    }
                    if a_arm.issubset(a_runs) and b_arm.issubset(b_runs):
                        proving_blocks.append((block_id, a_arm, b_arm))
                covered_a = set().union(*(
                    a_arm for _, a_arm, _ in proving_blocks
                )) if proving_blocks else set()
                covered_b = set().union(*(
                    b_arm for _, _, b_arm in proving_blocks
                )) if proving_blocks else set()
                proving_ids = [block_id for block_id, _, _ in proving_blocks]
                if not proving_blocks:
                    pair_instances.append({
                        "instance_id": instance_id,
                        "status": "pending",
                        "reason": (
                            "one or more valid ABBA blocks must prove the "
                            "directed pair"
                        ),
                        "evidence_refs": [
                            str(a_summary["summary_id"]),
                            str(b_summary["summary_id"]),
                        ],
                    })
                elif covered_a != a_runs or covered_b != b_runs:
                    pair_instances.append({
                        "instance_id": instance_id,
                        "status": "pending",
                        "reason": (
                            "pooled summary rows include runs not covered by "
                            "the complete proving ABBA blocks"
                        ),
                        "evidence_refs": [
                            str(a_summary["summary_id"]),
                            str(b_summary["summary_id"]),
                            *proving_ids,
                        ],
                    })
                else:
                    pair_instances.append({
                        "instance_id": instance_id,
                        "status": "pass",
                        "reason": (
                            "every pooled run is covered by complete, "
                            "protocol-matched ABBA evidence"
                        ),
                        "evidence_refs": [
                            str(a_summary["summary_id"]),
                            str(b_summary["summary_id"]),
                            *proving_ids,
                        ],
                    })

    control_instances: list[Dict[str, Any]] = []
    for rule in plan["correctness_control_rules"]:
        rule_id = str(rule["id"])
        for scenario_id in _matrix_rule_scenarios(rule, plan, workload):
            matches = [
                control for control in correctness_controls
                if control.get("scenario_id") == scenario_id
                and control.get("server") == rule.get("server")
                and rule.get("revision_role") in control.get(
                    "revision_roles", []
                )
            ]
            historical = rule.get("expected_historical_failure") is True
            valid_matches = [
                control for control in matches
                if control.get("passed") is True
                and control.get("complete") is True
                and (
                    control.get("supporting_historical_failure") is True
                    if historical else
                    control.get("oracle_passed") is True
                )
            ]
            failed_matches = [
                control for control in matches
                if control.get("complete") is True and control not in valid_matches
            ]
            if failed_matches:
                status = "fail"
                reason = (
                    "one or more repeated correctness controls contradict the "
                    "required historical/fixed outcome"
                )
            elif valid_matches:
                status = "pass"
                reason = (
                    "all complete repeated controls agree with the required "
                    "historical/fixed outcome"
                )
            else:
                status = "pending"
                reason = (
                    "required correctness control is absent or incomplete "
                    f"({len(matches)} records)"
                )
            control_instances.append({
                "instance_id": f"{rule_id}:{scenario_id}",
                "status": status,
                "reason": reason,
                "evidence_refs": [
                    str(control["control_id"]) for control in matches
                ],
            })

    instances = [workload_instance] + pair_instances + control_instances
    if plan_instance is not None:
        instances.insert(0, plan_instance)
    status = (
        "fail" if any(item["status"] == "fail" for item in instances)
        else "complete" if instances and all(
            item["status"] == "pass" for item in instances
        ) else "pending"
    )
    return {
        "format_version": 1,
        "matrix_id": plan.get("matrix_id"),
        "status": status,
        "required_instance_count": len(instances),
        "pass_count": sum(item["status"] == "pass" for item in instances),
        "fail_count": sum(item["status"] == "fail" for item in instances),
        "pending_count": sum(item["status"] == "pending" for item in instances),
        "timed_pair_instances": pair_instances,
        "correctness_control_instances": control_instances,
        "workload_contract_instance": workload_instance,
        "plan_contract_instance": plan_instance,
    }


def _row_server(row: Mapping[str, Any], run_manifest: Mapping[str, Any]) -> Optional[str]:
    raw = _first(row, (
        ("server",), ("server_type",), ("implementation",),
        ("configuration", "server"), ("config", "server"),
    ))
    if raw is None:
        raw = _first(run_manifest, (
            ("server",), ("server_type",), ("implementation",),
        ))
    if not isinstance(raw, str):
        return None
    value = raw.casefold()
    if value in {"389ds", "389-ds", "ns-slapd", "dirsrv"}:
        return "389ds"
    if value in {"openldap", "slapd"}:
        return "openldap"
    return raw


def _select_artifact(bundle: Bundle, row: Mapping[str, Any]) -> Dict[str, Any]:
    direct = _first(row, (
        ("executable_sha256",), ("binary_sha256",),
        ("artifact", "executable_sha256"),
        ("configuration", "executable_sha256"),
    ))
    candidates = bundle.artifacts
    if direct is not None:
        digest = _require_sha256(direct, f"{bundle.root}: raw row executable hash")
        matches = [item for item in candidates if item["executable_sha256"] == digest]
        if not matches:
            raise MergeError(
                f"{bundle.root}: raw row executable hash is absent from artifact manifest"
            )
        candidates = matches
    closure_digest = _require_sha256(
        row.get("backend_runtime_closure_sha256"),
        f"{bundle.root}: raw row backend_runtime_closure_sha256",
    )
    closure_matches = [
        item for item in candidates
        if item["backend_runtime_closure_sha256"] == closure_digest
    ]
    if not closure_matches:
        raise MergeError(
            f"{bundle.root}: raw row backend runtime closure is absent from "
            "artifact manifest"
        )
    candidates = closure_matches
    runtime_digest = _require_sha256(
        row.get("runtime_closure_sha256"),
        f"{bundle.root}: raw row runtime_closure_sha256",
    )
    behavioral_digest = _require_sha256(
        row.get("behavioral_runtime_identity_sha256"),
        f"{bundle.root}: raw row behavioral_runtime_identity_sha256",
    )
    identity_matches = [
        item for item in candidates
        if item["runtime_closure_sha256"] == runtime_digest
        and item["behavioral_runtime_identity_sha256"] == behavioral_digest
    ]
    if not identity_matches:
        raise MergeError(
            f"{bundle.root}: raw row behavioral runtime identity is absent from "
            "artifact manifest"
        )
    candidates = identity_matches
    identity = _first(row, (
        ("artifact_id",), ("revision_label",), ("commit_label",),
        ("build_label",), ("source_commit",), ("expected_source_sha",),
        ("commit",),
    ))
    if isinstance(identity, str):
        matches = [
            item for item in candidates
            if identity in {item.get("label"), item.get("commit")}
        ]
        if matches:
            candidates = matches
    server = _row_server(row, bundle.run_manifest)
    if server:
        matches = [item for item in candidates if item.get("server") == server]
        if matches:
            candidates = matches
    hashes = {item["executable_sha256"] for item in candidates}
    if len(hashes) != 1:
        raise MergeError(
            f"{bundle.root}: raw row does not identify one executable artifact"
        )
    selected_hash = next(iter(hashes))
    same_hash = [item for item in candidates if item["executable_sha256"] == selected_hash]
    selected = dict(same_hash[0])
    selected["rpm_proved"] = any(item["rpm_proved"] for item in same_hash)
    return selected


def _number(value: Any, context: str, *, integral: bool = False) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MergeError(f"{context} must be a number or null")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise MergeError(f"{context} must be finite and non-negative")
    if integral and not result.is_integer():
        raise MergeError(f"{context} must be an integer")
    return result


def _scaled_metric(
        row: Mapping[str, Any], second_paths: Iterable[Sequence[str]],
        millisecond_paths: Iterable[Sequence[str]],
        nanosecond_paths: Iterable[Sequence[str]], context: str) -> Optional[float]:
    value = _first(row, second_paths)
    if value is not None:
        return _number(value, context)
    value = _first(row, millisecond_paths)
    if value is not None:
        measured = _number(value, context)
        return None if measured is None else measured / 1_000.0
    value = _first(row, nanosecond_paths)
    if value is not None:
        measured = _number(value, context)
        return None if measured is None else measured / 1_000_000_000.0
    return None


def _elapsed_seconds(row: Mapping[str, Any], context: str) -> Optional[float]:
    return _scaled_metric(
        row,
        (
            ("elapsed_seconds",), ("client_elapsed_seconds",),
            ("metrics", "elapsed_seconds"), ("timing", "elapsed_seconds"),
        ),
        (
            ("elapsed_ms",), ("client_elapsed_ms",),
            ("metrics", "elapsed_ms"),
        ),
        (
            ("elapsed_ns",), ("client_elapsed_ns",),
            ("metrics", "elapsed_ns"),
        ),
        f"{context} elapsed time",
    )


def _server_etime_seconds(row: Mapping[str, Any], context: str) -> Optional[float]:
    return _scaled_metric(
        row,
        (
            ("server_etime_seconds",), ("server_elapsed_seconds",),
            ("metrics", "server_etime_seconds"),
        ),
        (("server_etime_ms",), ("metrics", "server_etime_ms")),
        (("server_etime_ns",), ("metrics", "server_etime_ns")),
        f"{context} server etime",
    )


def _cpu_seconds(row: Mapping[str, Any], context: str) -> Optional[float]:
    direct = _scaled_metric(
        row,
        (
            ("server_cpu_seconds",), ("cpu_seconds",),
            ("process_cpu_seconds",), ("metrics", "server_cpu_seconds"),
            ("metrics", "cpu_seconds"),
        ),
        (("server_cpu_ms",), ("cpu_ms",), ("metrics", "cpu_ms")),
        (("server_cpu_ns",), ("cpu_ns",), ("metrics", "cpu_ns")),
        f"{context} CPU time",
    )
    if direct is not None:
        return direct
    user = _first(row, (
        ("user_cpu_seconds",), ("process_user_cpu_seconds",),
        ("metrics", "user_cpu_seconds"),
        ("server_metrics", "user_cpu_seconds"),
    ))
    system = _first(row, (
        ("system_cpu_seconds",), ("process_system_cpu_seconds",),
        ("metrics", "system_cpu_seconds"),
        ("server_metrics", "system_cpu_seconds"),
    ))
    if user is None and system is None:
        return None
    return (_number(user, f"{context} user CPU") or 0.0) + (
        _number(system, f"{context} system CPU") or 0.0
    )


def _instructions(row: Mapping[str, Any], context: str) -> Optional[int]:
    raw = _first(row, (
        ("instructions",), ("instructions_retired",),
        ("metrics", "instructions"), ("perf", "instructions"),
    ))
    value = _number(raw, f"{context} instructions", integral=True)
    return None if value is None else int(value)


def _memory_kib(row: Mapping[str, Any], name: str, context: str) -> Optional[float]:
    aliases = {
        "rss": (("rss_kib",), ("metrics", "rss_kib")),
        "high_water": (("high_water_kib",), ("metrics", "high_water_kib")),
    }[name]
    return _number(_first(row, aliases), f"{context} {name} KiB")


def _canonical_result_code(value: Any) -> Any:
    if isinstance(value, str):
        normalized = value.strip().upper().replace("-", "_")
        if normalized in {"0", "SUCCESS", "LDAP_SUCCESS"}:
            return "LDAP_SUCCESS"
        return normalized
    if value == 0:
        return "LDAP_SUCCESS"
    return value


def _correctness(
        row: Mapping[str, Any], scenario: Mapping[str, Any]
        ) -> tuple[bool, bool, list[str]]:
    problems: list[str] = []
    explicit = _first(row, (
        ("correctness_passed",), ("correctness_pass",), ("correct",),
        ("correctness", "passed"),
        ("validation", "passed"),
    ))
    if explicit is not None and not isinstance(explicit, bool):
        raise MergeError("correctness_passed must be boolean when present")
    expected_hash = scenario.get("expected_sha256")
    actual_hash = _first(row, (
        ("actual_dn_sha256",), ("returned_dn_sha256",), ("returned_sha256",),
        ("result_dn_sha256",), ("correctness", "actual_dn_sha256"),
        ("correctness", "returned_dn_sha256"),
        ("validation", "actual_dn_sha256"),
    ))
    row_expected_hash = _first(row, (
        ("expected_dn_sha256",), ("expected_sha256",),
        ("correctness", "expected_dn_sha256"),
    ))
    if row_expected_hash is not None and row_expected_hash != expected_hash:
        problems.append("row expected DN hash disagrees with workload oracle")
    if actual_hash is not None:
        if not _is_sha256(actual_hash):
            problems.append("actual DN hash is not a lowercase SHA-256")
        elif actual_hash != expected_hash:
            problems.append("returned DN hash differs from workload oracle")

    expected_count = scenario.get("expected_count")
    actual_count = _first(row, (
        ("actual_count",), ("returned_count",), ("entry_count",),
        ("correctness", "actual_count"), ("validation", "actual_count"),
    ))
    if actual_count is not None:
        measured_count = _number(actual_count, "actual result count", integral=True)
        if expected_count is not None and measured_count != float(expected_count):
            problems.append("returned count differs from workload oracle")
    row_expected_count = _first(row, (
        ("expected_count",), ("correctness", "expected_count"),
    ))
    if row_expected_count is not None:
        measured_expected = _number(
            row_expected_count, "row expected result count", integral=True,
        )
        if expected_count is not None and measured_expected != float(expected_count):
            problems.append("row expected count disagrees with workload oracle")

    expected_code = _canonical_result_code(scenario.get("expected_result_code"))
    actual_code = _first(row, (
        ("ldap_result_code",), ("actual_result_code",), ("result_code",),
        ("correctness", "ldap_result_code"),
        ("validation", "ldap_result_code"),
    ))
    if actual_code is not None and _canonical_result_code(actual_code) != expected_code:
        problems.append("LDAP result code differs from workload oracle")

    server_evidence = row.get("server_result_evidence")
    server_code = _first(row, (
        ("actual_server_result_code",), ("server_result_code",),
        ("server_result_evidence", "actual_server_result_code"),
    ))
    server_complete = isinstance(server_evidence, Mapping) and server_code is not None
    if not isinstance(server_evidence, Mapping):
        problems.append("isolated server LDAP result evidence is missing")
    else:
        evidence_expected = _first(server_evidence, (
            ("expected_ldap_result_code",), ("expected_result_code",),
        ))
        if evidence_expected is None or (
                _canonical_result_code(evidence_expected) != expected_code):
            problems.append("server evidence expected result code disagrees with oracle")
        if server_code is None or _canonical_result_code(server_code) != expected_code:
            problems.append("server LDAP result code differs from workload oracle")
        if server_evidence.get("evidence_status") != "observed":
            problems.append("server LDAP result evidence is not observed")
        if server_evidence.get("passed") is not True:
            problems.append("server LDAP result evidence is not marked pass")

    complete = (
        actual_hash is not None and actual_count is not None
        and actual_code is not None and server_complete
    )
    if explicit is False:
        problems.append("runner marked correctness as failed")
    if explicit is None and not complete:
        problems.append("no complete correctness evidence or explicit gate result")
    passed = not problems and (explicit is True or complete)
    return passed, complete, problems


def _phase(row: Mapping[str, Any]) -> str:
    raw = _first(row, (("phase",), ("measurement_phase",), ("kind",)))
    if isinstance(raw, str):
        value = raw.casefold()
        if value in {"warmup", "warm-up", "setup", "preflight"}:
            return "warmup"
        if value in {"measured", "measurement", "timed", "run"}:
            return "measured"
        return value
    warmup = _first(row, (("warmup",), ("is_warmup",)))
    return "warmup" if warmup is True else "measured"


def _config_value(
        row: Mapping[str, Any], run: Mapping[str, Any], names: Sequence[str]) -> Any:
    paths: list[Sequence[str]] = []
    for name in names:
        paths.extend(((name,), ("configuration", name), ("config", name)))
    value = _first(row, paths)
    if value is not None:
        return value
    return _first(run, [(name,) for name in names])


def _scenario_groups(workload: Mapping[str, Any], scenario_id: str) -> list[str]:
    groups = []
    raw_groups = workload.get("scenario_groups", {})
    if isinstance(raw_groups, Mapping):
        for group, members in raw_groups.items():
            if isinstance(members, list) and scenario_id in members:
                groups.append(str(group))
    return sorted(groups)


def _scale_value(row: Mapping[str, Any], scenario: Mapping[str, Any], name: str) -> Any:
    aliases = {
        "candidate_count": (
            "candidate_count", "logical_candidate_count",
            "logical_outer_cohort_count",
        ),
        "branch_count": ("branch_count", "equality_branch_count"),
        "values_per_entry": ("values_per_entry", "relevant_values_per_entry"),
        "dn_mode": ("dn_mode",),
    }[name]
    value = _config_value(row, {}, aliases)
    if value is not None:
        return value
    parameters = scenario.get("parameters")
    if isinstance(parameters, Mapping):
        for alias in aliases:
            if alias in parameters:
                return parameters[alias]
    for alias in aliases:
        if alias in scenario:
            return scenario[alias]
    return None


def _scale_curve_discriminator(
        scenario: Mapping[str, Any], dimension: str) -> Dict[str, Any]:
    parameters = scenario.get("parameters")
    params = dict(parameters) if isinstance(parameters, Mapping) else {}
    excluded = {
        "candidate_count": {"candidate_count", "cohort_source"},
        "branch_count": {"branch_count"},
        "values_per_entry": {"entry_values_m"},
        "dn_mode": {"dn_mode"},
    }[dimension]
    return {
        key: value for key, value in sorted(params.items())
        if key not in excluded
    }


def _verify_row_contract(
        bundle: Bundle, row: Mapping[str, Any], context: str,
        scenario_id: str, scenario: Mapping[str, Any]) -> None:
    contract_version = bundle.run_manifest.get(
        "evidence_contract_version"
    )
    row_contract_version = row.get("evidence_contract_version")
    if contract_version is not None and row_contract_version != contract_version:
        raise MergeError(
            f"{context}: row evidence contract version disagrees with run"
        )
    if contract_version is None and row_contract_version is not None:
        raise MergeError(
            f"{context}: row declares an evidence contract absent from the run"
        )
    expected_workload_id = bundle.workload.get("workload_id")
    row_workload_id = row.get("workload_id")
    if row_workload_id != expected_workload_id:
        raise MergeError(f"{context}: row workload_id disagrees with manifest")
    row_workload_sha = _require_sha256(
        row.get("workload_sha256"), f"{context}: workload_sha256",
    )
    if row_workload_sha != bundle.workload_contract["workload_sha256"]:
        raise MergeError(f"{context}: row workload_sha256 disagrees with manifest")
    row_manifest_sha = _require_sha256(
        row.get("workload_manifest_sha256"),
        f"{context}: workload_manifest_sha256",
    )
    if row_manifest_sha != bundle.workload_contract["workload_manifest_sha256"]:
        raise MergeError(
            f"{context}: row workload manifest hash disagrees with executed copy"
        )

    contract = bundle.workload_contract["scenario_contracts"][scenario_id]
    expected_file = str(scenario["expected_file"])
    expected_hashes = {
        "filter_sha256": contract["filter_sha256"],
        "expected_file_sha256": bundle.workload_contract["files"][expected_file],
    }
    server = _row_server(row, bundle.run_manifest)
    run_server = _artifact_server({
        "server": bundle.run_manifest.get("server")
    })
    if server != run_server:
        raise MergeError(f"{context}: row server disagrees with run manifest")
    if server not in bundle.workload_contract["schema_hashes"]:
        raise MergeError(f"{context}: row server has no workload schema")
    row_backend = _config_value(
        row, bundle.run_manifest, ("backend", "backend_actual"),
    )
    run_backend = bundle.run_manifest.get("backend_actual")
    if (
            not isinstance(row_backend, str)
            or not isinstance(run_backend, str)
            or row_backend.casefold() != run_backend.casefold()):
        raise MergeError(f"{context}: row backend disagrees with run manifest")

    row_lookup = _config_value(row, {}, (
        "lookup_mode", "lookup_mode_actual", "or_lookup_mode",
    ))
    run_lookup = bundle.run_manifest.get("lookup_mode_actual")
    if isinstance(row_lookup, bool):
        row_lookup = "on" if row_lookup else "off"
    if isinstance(run_lookup, bool):
        run_lookup = "on" if run_lookup else "off"
    if (
            not isinstance(row_lookup, str)
            or not isinstance(run_lookup, str)
            or row_lookup.casefold() != run_lookup.casefold()):
        raise MergeError(
            f"{context}: row lookup mode disagrees with run manifest"
        )

    for row_field, run_field, label in (
            ("perf_mode", "perf_mode", "requested perf mode"),
            ("profile_mode", "profile_mode", "requested profile mode"),
            ("cache_policy", "cache_policy", "cache policy"),
            ("connection_policy", "connection_policy", "connection policy"),
            ("bind_class", "bind_class", "bind class"),
            ("timing_environment_sha256", "timing_environment_sha256",
             "timing environment")):
        run_value = bundle.run_manifest.get(run_field)
        # Legacy bundles may predate a redundant top-level declaration.  New
        # bundles carry configuration_contract and therefore require every
        # field below.
        contract = bundle.run_manifest.get("configuration_contract")
        contract_present = isinstance(contract, Mapping)
        if run_value is None and contract_present:
            run_value = contract.get(run_field)
        if run_value is None and not contract_present:
            continue
        if row.get(row_field) != run_value:
            raise MergeError(
                f"{context}: row {label} disagrees with run manifest"
            )
    expected_hashes["schema_sha256"] = bundle.workload_contract[
        "schema_hashes"
    ][server]
    index_variant = _config_value(
        row, bundle.run_manifest, ("index_variant", "index_config"),
    ) or scenario.get("index_variant")
    run_index = bundle.run_manifest.get("index_config")
    if isinstance(run_index, str) and index_variant != run_index:
        raise MergeError(
            f"{context}: row index configuration disagrees with run manifest"
        )
    try:
        expected_index_sha = bundle.workload_contract[
            "index_intent_sha256s"
        ][server][index_variant]
    except KeyError as error:
        raise MergeError(
            f"{context}: unknown {server} index intent {index_variant!r}"
        ) from error
    expected_hashes["index_intent_sha256"] = expected_index_sha
    for field, expected_hash in expected_hashes.items():
        observed = _require_sha256(row.get(field), f"{context}: {field}")
        if observed != expected_hash:
            raise MergeError(
                f"{context}: row {field} disagrees with executed workload/setup"
            )

    setup_index_sha = _require_sha256(
        _nested(bundle.run_manifest, "server_setup", "canonical_index_intent_sha256"),
        f"{bundle.root}: server setup index intent",
    )
    if setup_index_sha != expected_index_sha:
        raise MergeError(
            f"{bundle.root}: effective setup intent disagrees with workload index variant"
        )

    attribute_variant = row.get("attribute_variant")
    requested_attributes = row.get("requested_attributes")
    expected_variants: dict[str, list[str]] = {
        "attrs-1.1": list(scenario.get("requested_attributes", ["1.1"])),
    }
    if scenario_id in {
            "principal-with-sdn2-equality",
            "principal-without-sdn2-equality"}:
        expected_variants["normal-attributes"] = list(
            NORMAL_PRIMARY_ATTRIBUTES
        )
    if attribute_variant not in expected_variants:
        raise MergeError(
            f"{context}: row attribute variant is not declared for the scenario"
        )
    if requested_attributes is not None and (
            requested_attributes != expected_variants[str(attribute_variant)]):
        raise MergeError(
            f"{context}: requested attributes disagree with attribute variant"
        )
    configuration_contract = bundle.run_manifest.get(
        "configuration_contract"
    )
    if isinstance(configuration_contract, Mapping):
        if configuration_contract.get("format_version") != 1:
            raise MergeError(
                f"{bundle.root}: unsupported configuration contract"
            )
        if configuration_contract.get("evidence_contract_version") != (
                bundle.run_manifest.get("evidence_contract_version")):
            raise MergeError(
                f"{bundle.root}: configuration evidence contract disagrees"
            )
        contract_variants = _nested(
            configuration_contract, "attribute_variants", scenario_id,
        )
        if (
                not isinstance(contract_variants, Mapping)
                or requested_attributes is None
                or contract_variants.get(str(attribute_variant))
                != requested_attributes):
            raise MergeError(
                f"{context}: row attributes disagree with configuration contract"
            )

        exact_contract_fields = {
            "server": server,
            "lookup_mode": str(row_lookup),
            "backend": str(row_backend),
            "index_config": index_variant,
            "cache_policy": row.get("cache_policy"),
            "perf_mode": row.get("perf_mode"),
            "profile_mode": row.get("profile_mode"),
            "connection_policy": row.get("connection_policy"),
            "bind_class": row.get("bind_class"),
            "timing_environment_sha256": row.get(
                "timing_environment_sha256"
            ),
        }
        for field, expected_value in exact_contract_fields.items():
            if configuration_contract.get(field) != expected_value:
                raise MergeError(
                    f"{context}: row {field} disagrees with configuration contract"
                )

    if row.get("phase") == "measured" and isinstance(
            configuration_contract, Mapping):
        collection_class = row.get("perf_collection_class")
        collection_signature = row.get("perf_collection_signature")
        classes = configuration_contract.get("perf_collection_classes")
        signatures = configuration_contract.get(
            "perf_collection_signatures"
        )
        if (
                not isinstance(collection_class, str)
                or not isinstance(classes, list)
                or collection_class not in classes):
            raise MergeError(
                f"{context}: row actual perf class disagrees with run contract"
            )
        collection_signature = _require_sha256(
            collection_signature, f"{context}: perf collection signature",
        )
        if (
                not isinstance(signatures, list)
                or collection_signature not in signatures):
            raise MergeError(
                f"{context}: row actual perf signature disagrees with run contract"
            )
        profile_class = row.get("profile_collection_class")
        profile_signature = _require_sha256(
            row.get("profile_collection_signature"),
            f"{context}: profile collection signature",
        )
        profile_classes = configuration_contract.get(
            "profile_collection_classes"
        )
        profile_signatures = configuration_contract.get(
            "profile_collection_signatures"
        )
        if (
                not isinstance(profile_class, str)
                or not isinstance(profile_classes, list)
                or profile_class not in profile_classes
                or not isinstance(profile_signatures, list)
                or profile_signature not in profile_signatures):
            raise MergeError(
                f"{context}: row actual profile collection disagrees with run contract"
            )

    schedule = bundle.run_manifest.get("schedule")
    if isinstance(schedule, Mapping):
        for row_field, schedule_field in (
                ("schedule_position", "position"),
                ("schedule_design", "design"),
                ("schedule_block_id", "block_id"),
                ("schedule_state", "state"),
                ("schedule_state_fingerprint", "state_fingerprint")):
            if row.get(row_field) != schedule.get(schedule_field):
                raise MergeError(
                    f"{context}: row {row_field} disagrees with schedule contract"
                )
    identity_fields = (
        "runtime_closure_sha256",
        "backend_runtime_closure_sha256",
        "behavioral_runtime_identity_sha256",
    )
    identities: dict[str, str] = {}
    for field in identity_fields:
        run_value = _require_sha256(
            bundle.run_manifest.get(field),
            f"{bundle.root}: run-manifest {field}",
        )
        row_value = _require_sha256(row.get(field), f"{context}: {field}")
        if row_value != run_value:
            raise MergeError(
                f"{context}: row {field} disagrees with run manifest"
            )
        identities[field] = row_value
    if identities["behavioral_runtime_identity_sha256"] != (
            _behavioral_runtime_identity(
                identities["runtime_closure_sha256"],
                identities["backend_runtime_closure_sha256"],
            )):
        raise MergeError(f"{context}: row behavioral runtime identity mismatch")

    host = _host_mapping(bundle.run_manifest)
    expected_host_class = _host_class(bundle.run_manifest, host)
    row_host_class = row.get("host_class")
    if (
            not isinstance(row_host_class, str)
            or row_host_class.casefold() != expected_host_class):
        raise MergeError(f"{context}: row host_class disagrees with run manifest")
    expected_compatibility = _first(host, (("compatibility_key",),))
    if expected_compatibility is None:
        expected_compatibility = _first(bundle.run_manifest, (("host_compatibility_key",),))
    row_compatibility = row.get("host_compatibility_key")
    if row_compatibility != expected_compatibility:
        raise MergeError(
            f"{context}: row host compatibility key disagrees with run manifest"
        )
    for key in ("correctness_only", "release_timing_evidence"):
        row_value = row.get(key)
        run_value = bundle.run_manifest.get(key)
        if not isinstance(row_value, bool) or row_value != run_value:
            raise MergeError(f"{context}: row {key} disagrees with run manifest")
    if "timing_claims_allowed" in row:
        row_timing = row.get("timing_claims_allowed")
        run_timing = bundle.run_manifest.get("timing_claims_allowed")
        if not isinstance(row_timing, bool) or row_timing != run_timing:
            raise MergeError(
                f"{context}: row timing_claims_allowed disagrees with run manifest"
            )


def _mechanism_record(
        bundle: Bundle, row: Mapping[str, Any], scenario_id: str,
        scenario: Mapping[str, Any]) -> Dict[str, Any]:
    record: Mapping[str, Any] = {}
    records = bundle.correctness_manifest.get("scenarios", [])
    if isinstance(records, list):
        for candidate in records:
            if isinstance(candidate, Mapping) and candidate.get("scenario") == scenario_id:
                record = candidate
                break
    explicit = _first(row, (
        ("mechanism_verified",), ("lookup_consumption_verified",),
        ("mechanism", "verified"),
    ))
    consumption_direct = _first(record, (
        ("lookup_consumption_directly_reported",),
        ("lookup_consumed",),
    )) is True
    consumption_status = record.get("lookup_consumption_status")
    consumption_verified = consumption_direct or (
        isinstance(consumption_status, str)
        and consumption_status.casefold() in {
            "verified", "observed", "consumed", "profile-attributed",
        }
    )
    cap_observed = record.get("cap_path_observed") is True
    profile: Mapping[str, Any] = {}
    raw_profiles = bundle.run_manifest.get("profiles", [])
    if isinstance(raw_profiles, list):
        for candidate in raw_profiles:
            if isinstance(candidate, Mapping) and candidate.get("scenario") == scenario_id:
                profile = candidate
                break
    approximate_evidence = record.get("approximate_semantics_evidence")
    if approximate_evidence is None:
        run_approximate = bundle.run_manifest.get("approximate_semantics_evidence")
        if isinstance(run_approximate, Mapping):
            if {
                    "status", "contract_sha256", "probes",
            }.issubset(run_approximate):
                # The runner emits one direct preflight record shared by every
                # selected approximate scenario.
                approximate_evidence = run_approximate
            else:
                approximate_evidence = run_approximate.get(scenario_id)
        elif isinstance(run_approximate, list):
            approximate_evidence = next((
                candidate for candidate in run_approximate
                if isinstance(candidate, Mapping)
                and candidate.get("scenario") == scenario_id
            ), None)
    if approximate_evidence is None:
        correctness_approximate = bundle.correctness_manifest.get(
            "approximate_semantics_evidence"
        )
        if isinstance(correctness_approximate, Mapping):
            approximate_evidence = correctness_approximate
    expected = scenario.get("expected_diagnostics", {})
    expected = expected if isinstance(expected, Mapping) else {}
    lookup = expected.get("or_lookup", {})
    lookup = lookup if isinstance(lookup, Mapping) else {}
    bounded = expected.get("bounded_read", {})
    bounded = bounded if isinstance(bounded, Mapping) else {}
    lookup_required = lookup.get("expectation") == "required-when-lookup-on"
    cap_required = bounded.get("expectation") in {
        "required", "required-on-bounded-feature-build",
    }
    lookup_mode = _config_value(row, bundle.run_manifest, (
        "lookup_mode", "lookup_mode_actual", "or_lookup_mode", "lookup_enabled",
    ))
    required_kind: Optional[str] = None
    verified = explicit is True
    if lookup_required and lookup_mode in {True, "on", "enabled"}:
        required_kind = "lookup consumption"
        verified = verified or consumption_verified
    elif cap_required:
        required_kind = "bounded-read engagement"
        verified = verified or cap_observed
    return {
        "required": required_kind is not None,
        "required_kind": required_kind,
        "verified": verified if required_kind else True,
        "lookup_constructed": record.get("lookup_constructed"),
        "lookup_summaries": record.get("lookup_summaries"),
        "lookup_consumption_directly_reported": consumption_direct,
        "lookup_consumption_status": consumption_status,
        "cap_path_observed": record.get("cap_path_observed"),
        "observed_final_candidate_count": record.get("observed_final_candidate_count"),
        "candidate_list_status": record.get("candidate_list_status"),
        "candidate_list_observed": record.get("candidate_list_status") == "observed",
        "candidate_list_values": record.get("candidate_list_values"),
        "access_notes": _nested(record, "access_result", "server_notes"),
        "access_notes_observed": isinstance(
            _nested(record, "access_result", "server_notes"), str,
        ),
        "stat_index_reads": record.get("stat_index_reads"),
        "stat_index_reads_observed": isinstance(
            record.get("stat_index_reads"), list,
        ),
        "selected_family_from_manifest": record.get(
            "selected_family_from_manifest"
        ),
        "selected_family_directly_reported": record.get(
            "selected_family_directly_reported"
        ) is True,
        "selected_attribute": _first(record, (
            ("selected_attribute",), ("selected_family",),
            ("direct_selected_family_evidence", "selected_attribute"),
        )),
        "selection_observation": (
            {
                "selected_attribute": _first(record, (
                    ("selected_attribute",), ("selected_family",),
                    ("direct_selected_family_evidence", "selected_attribute"),
                )),
                "largest_families": sorted({
                    int(item["largest_family"])
                    for item in (
                        record.get("lookup_summaries")
                        if isinstance(record.get("lookup_summaries"), list) else []
                    )
                    if isinstance(item, Mapping)
                    and isinstance(item.get("largest_family"), int)
                }),
            }
            if record.get("selected_family_directly_reported") is True
            else None
        ),
        "profile_status": profile.get("status"),
        "profile_sha256": _first(profile, (
            ("sha256",), ("profile_sha256",), ("data_sha256",),
            ("profile_artifact", "sha256"),
        )),
        "profile_annotation": _first(profile, (
            ("annotation",), ("lookup_consumption", "annotation"),
        )),
        "profile_consumption_status": _first(profile, (
            ("lookup_consumption_status",),
            ("lookup_consumption", "status"),
            ("annotation", "lookup_consumption_status"),
        )),
        "profile_attributed_waiver": record.get("profile_attributed_waiver"),
        "approximate_semantics_evidence": approximate_evidence,
    }


def normalize_rows(bundles: Sequence[Bundle]) -> list[Dict[str, Any]]:
    normalized: list[Dict[str, Any]] = []
    for bundle in bundles:
        declared_row_count = bundle.run_manifest.get("raw_result_rows")
        if (
                not isinstance(declared_row_count, int)
                or isinstance(declared_row_count, bool)
                or declared_row_count != len(bundle.raw_rows)):
            raise MergeError(
                f"{bundle.root}: raw_result_rows must exactly match raw-results rows"
            )
        scenarios = bundle.workload["scenarios"]
        row_ids: set[str] = set()
        for index, raw in enumerate(bundle.raw_rows):
            context = f"{bundle.root}: raw row {index}"
            if raw.get("format_version", 1) != 1:
                raise MergeError(f"{context}: unsupported raw row format")
            row_id_value = _first(raw, (("row_id",), ("measurement_id",)))
            row_id = str(row_id_value) if row_id_value is not None else f"{bundle.run_id}:{index}"
            if row_id in row_ids:
                raise MergeError(f"{context}: duplicate row_id {row_id!r}")
            row_ids.add(row_id)
            scenario_id = _first(raw, (("scenario_id",), ("scenario",), ("case",)))
            if not isinstance(scenario_id, str) or scenario_id not in scenarios:
                raise MergeError(f"{context}: unknown or missing scenario_id")
            scenario = scenarios[scenario_id]
            _verify_row_contract(
                bundle, raw, context, scenario_id, scenario,
            )
            artifact = _select_artifact(bundle, raw)
            declared_production = raw.get("production_equivalent_revision")
            if (
                    declared_production is not None
                    and declared_production != artifact.get("production_commit")):
                raise MergeError(
                    f"{context}: production-equivalent revision contradicts "
                    "the selected artifact"
                )
            declared_role = raw.get("revision_role")
            if (
                    declared_role is not None
                    and artifact.get("revision_role") is not None
                    and declared_role != artifact.get("revision_role")):
                raise MergeError(
                    f"{context}: revision role contradicts the selected artifact"
                )
            elapsed = _elapsed_seconds(raw, context)
            server_etime = _server_etime_seconds(raw, context)
            cpu = _cpu_seconds(raw, context)
            rss_kib = _memory_kib(raw, "rss", context)
            high_water_kib = _memory_kib(raw, "high_water", context)
            passed, complete, correctness_problems = _correctness(raw, scenario)
            mechanism = _mechanism_record(bundle, raw, scenario_id, scenario)
            phase = _phase(raw)
            reasons = list(bundle.disposition_reasons)
            if not artifact["rpm_proved"]:
                reasons.append("installed-RPM artifact identity is not proved")
            if phase != "measured":
                reasons.append(f"non-measured phase: {phase}")
            if not passed:
                reasons.extend(correctness_problems)
            if not complete:
                reasons.append("exact count/hash/result-code evidence is incomplete")
            if elapsed is None:
                reasons.append("elapsed timing is unavailable")
            quiet_valid = True
            quiet_reason = "not required for this bundle"
            if (
                    bundle.release_candidate
                    and _artifact_server({
                        "server": bundle.run_manifest.get("server")
                    }) == "389ds"):
                quiet_valid, quiet_reason = _background_quiet_collection_status(
                    raw.get("background_quiet_window"),
                    _nested(
                        bundle.run_manifest, "server_setup",
                        "background_referral_check_control",
                    ),
                )
                if not quiet_valid:
                    reasons.append(quiet_reason)
            release_eligible = bundle.release_candidate and not reasons
            server = _row_server(raw, bundle.run_manifest) or artifact.get("server") or "unknown"
            lookup = _config_value(raw, bundle.run_manifest, (
                "lookup_mode", "lookup_mode_actual", "or_lookup_mode", "lookup_enabled",
            ))
            if isinstance(lookup, bool):
                lookup = "on" if lookup else "off"
            configuration = {
                "evidence_contract_version": bundle.run_manifest.get(
                    "evidence_contract_version"
                ),
                "server": server,
                "lookup_mode": lookup,
                "perf_mode": _config_value(
                    raw, bundle.run_manifest, ("perf_mode", "perf"),
                ),
                "profile_mode": _config_value(
                    raw, bundle.run_manifest,
                    ("profile_mode", "profile_collection", "profile"),
                ),
                "perf_collection_class": _config_value(
                    raw, bundle.run_manifest,
                    ("perf_collection_class",),
                ),
                "perf_collection_signature": _config_value(
                    raw, bundle.run_manifest,
                    ("perf_collection_signature",),
                ),
                "profile_collection_class": _config_value(
                    raw, bundle.run_manifest,
                    ("profile_collection_class",),
                ),
                "profile_collection_signature": _config_value(
                    raw, bundle.run_manifest,
                    ("profile_collection_signature",),
                ),
                "backend": _config_value(
                    raw, bundle.run_manifest, ("backend", "backend_actual"),
                ),
                "index_variant": _config_value(
                    raw, bundle.run_manifest, ("index_variant", "index_config"),
                ) or scenario.get("index_variant"),
                "cache_policy": _config_value(
                    raw, bundle.run_manifest, ("cache_policy", "cache_mode"),
                ),
                "attribute_mode": _config_value(
                    raw, bundle.run_manifest,
                    ("attribute_mode", "attribute_variant", "requested_attribute_profile",
                     "attributes_mode", "requested_attributes"),
                ),
                "bind_class": _config_value(
                    raw, bundle.run_manifest, ("bind_class", "bind_mode"),
                ),
                "connection_policy": _config_value(
                    raw, bundle.run_manifest, ("connection_policy", "connection_mode"),
                ),
            }
            scenario_contract = bundle.workload_contract["scenario_contracts"][scenario_id]
            normalized.append({
                "run_id": bundle.run_id,
                "row_id": row_id,
                "perf_batch_id": raw.get("perf_batch_id"),
                "source_directory": str(bundle.root),
                "scenario_id": scenario_id,
                "scenario_groups": _scenario_groups(bundle.workload, scenario_id),
                "scenario_fingerprint": sha256_bytes(canonical_json_bytes({
                    "filter_sha256": scenario_contract["filter_sha256"],
                    "expected_sha256": scenario_contract["expected_sha256"],
                    "base_dn": scenario_contract["base_dn"],
                    "scope": scenario_contract["scope"],
                    "requested_attributes": scenario_contract["requested_attributes"],
                    "index_variant": scenario.get("index_variant"),
                })),
                "executable_sha256": artifact["executable_sha256"],
                "runtime_closure_sha256": artifact["runtime_closure_sha256"],
                "backend_runtime_closure_sha256": artifact[
                    "backend_runtime_closure_sha256"
                ],
                "behavioral_runtime_identity_sha256": artifact[
                    "behavioral_runtime_identity_sha256"
                ],
                "installed_package_closure_sha256": bundle.run_manifest.get(
                    "installed_package_closure_sha256"
                ),
                "artifact_label": artifact["label"],
                "source_commit": artifact.get("commit"),
                "production_commit": artifact.get("production_commit"),
                "revision_role": artifact.get("revision_role"),
                "installed_rpm_proved": artifact["rpm_proved"],
                "host_signature": bundle.host_signature,
                "phase": phase,
                "configuration": configuration,
                "scale": {
                    name: _scale_value(raw, scenario, name)
                    for name in ("candidate_count", "branch_count", "values_per_entry", "dn_mode")
                },
                "scale_curve": {
                    name: _scale_curve_discriminator(scenario, name)
                    for name in (
                        "candidate_count", "branch_count",
                        "values_per_entry", "dn_mode",
                    )
                },
                "cross_server_comparison": scenario.get(
                    "cross_server_comparison"
                ),
                "correctness": {
                    "passed": passed,
                    "complete": complete,
                    "problems": correctness_problems,
                },
                "mechanism": mechanism,
                "metrics": {
                    "elapsed_seconds": elapsed,
                    "server_etime_seconds": server_etime,
                    "server_cpu_seconds": cpu,
                    # perf counters are aggregate batch observations.  They are
                    # intentionally joined in summarize_rows rather than copied
                    # from a per-row compatibility field.
                    "instructions": None,
                    "rss_kib": rss_kib,
                    "high_water_kib": high_water_kib,
                    "startup_rss_kib": _number(
                        _nested(bundle.run_manifest, "startup_memory", "rss_kib"),
                        f"{bundle.root}: startup RSS KiB",
                    ),
                    "startup_high_water_kib": _number(
                        _nested(
                            bundle.run_manifest, "startup_memory", "high_water_kib",
                        ),
                        f"{bundle.root}: startup high-water KiB",
                    ),
                },
                "release_eligible": release_eligible,
                "release_exclusion_reasons": sorted(set(reasons)),
                "background_quiet_window_validation": {
                    "passed": quiet_valid,
                    "reason": quiet_reason,
                },
                "raw": raw,
            })
    return normalized


def normalize_perf_batches(
        bundles: Sequence[Bundle], rows: Sequence[Mapping[str, Any]],
        maximum_operations: int = PERF_BATCH_MAX_OPERATIONS
        ) -> list[Dict[str, Any]]:
    """Validate and normalize independent perf-stat batch observations.

    A batch is one statistical observation even though its aggregate is
    normalized by up to five searches.  Row links establish the timing stratum;
    they never turn one counter aggregate into multiple instruction samples.
    """

    def collection_identity(raw: Mapping[str, Any]) -> tuple[str, str]:
        status = str(raw.get("status", "unrecorded"))
        raw_events = raw.get("events")
        events = (
            [str(value) for value in raw_events]
            if isinstance(raw_events, list) else []
        )
        raw_unavailable = raw.get("unavailable_events")
        unavailable = (
            sorted(str(value) for value in raw_unavailable)
            if isinstance(raw_unavailable, list) else []
        )
        hardware = [
            "instructions", "cycles", "branches", "branch-misses",
            "cache-misses",
        ]
        raw_counts = raw.get("event_counts")
        count_events = (
            sorted(str(event) for event in raw_counts)
            if isinstance(raw_counts, Mapping) else []
        )
        missing_count_events = [
            event for event in hardware
            if not isinstance(raw_counts, Mapping) or event not in raw_counts
        ]
        invalid_count_events = [
            event for event in hardware
            if isinstance(raw_counts, Mapping)
            and event in raw_counts
            and (
                not isinstance(raw_counts[event], (int, float))
                or isinstance(raw_counts[event], bool)
                or (
                    isinstance(raw_counts[event], float)
                    and not math.isfinite(raw_counts[event])
                )
                or raw_counts[event] < 0
            )
        ]
        unexpected_count_events = [
            event for event in count_events if event not in hardware
        ]
        raw_warnings = raw.get("parse_warnings")
        parse_warnings = (
            [str(value) for value in raw_warnings]
            if isinstance(raw_warnings, list) else []
        )
        metadata_shape_errors: list[str] = []
        if not isinstance(raw_counts, Mapping):
            metadata_shape_errors.append("event_counts is not a mapping")
        if not isinstance(raw_unavailable, list):
            metadata_shape_errors.append("unavailable_events is not a list")
        if not isinstance(raw_warnings, list):
            metadata_shape_errors.append("parse_warnings is not a list")
        complete_hardware_observation = not any((
            unavailable,
            missing_count_events,
            invalid_count_events,
            unexpected_count_events,
            parse_warnings,
            metadata_shape_errors,
        ))
        if status == "disabled":
            collection_class = "disabled"
        elif status != "observed":
            collection_class = (
                "unavailable" if status == "unavailable" else "failed"
            )
        elif events == hardware and complete_hardware_observation:
            collection_class = "hardware-events"
        elif events == ["task-clock"]:
            collection_class = "software-task-clock"
        elif events == hardware:
            collection_class = "hardware-events-incomplete"
        else:
            collection_class = "custom-events"
        material = {
            "format_version": 2,
            "collection_class": collection_class,
            "status": status,
            "events": events,
            "software_fallback": raw.get("software_fallback") is True,
            "unavailable_events": unavailable,
            "observed_count_events": count_events,
            "missing_count_events": missing_count_events,
            "invalid_count_events": invalid_count_events,
            "unexpected_count_events": unexpected_count_events,
            "parse_warnings": parse_warnings,
            "metadata_shape_errors": metadata_shape_errors,
        }
        return collection_class, sha256_bytes(canonical_json_bytes(material))

    rows_by_run: Dict[str, Dict[str, Mapping[str, Any]]] = {}
    for row in rows:
        rows_by_run.setdefault(str(row["run_id"]), {})[str(row["row_id"])] = row

    seen_batch_ids: set[str] = set()
    rows_claimed_by_batches: set[tuple[str, str]] = set()
    normalized: list[Dict[str, Any]] = []
    for bundle in bundles:
        run_rows = rows_by_run.get(bundle.run_id, {})
        declared_for_run: Dict[str, set[str]] = {}
        for index, raw in enumerate(bundle.raw_perf_batches):
            context = f"{bundle.root}: perf batch {index}"
            batch_id = raw.get("batch_id")
            if not isinstance(batch_id, str) or not batch_id:
                raise MergeError(f"{context}: batch_id must be a non-empty string")
            if batch_id in seen_batch_ids:
                raise MergeError(f"duplicate perf batch_id {batch_id!r}")
            seen_batch_ids.add(batch_id)

            raw_row_ids = raw.get("row_ids")
            if not isinstance(raw_row_ids, list) or not raw_row_ids:
                raise MergeError(f"{context}: row_ids must be a non-empty list")
            if any(not isinstance(value, str) or not value for value in raw_row_ids):
                raise MergeError(f"{context}: every row_id must be a non-empty string")
            row_ids = [str(value) for value in raw_row_ids]
            if len(set(row_ids)) != len(row_ids):
                raise MergeError(f"{context}: row_ids must be unique")

            operation_count_value = _number(
                raw.get("operation_count"), f"{context} operation_count",
                integral=True,
            )
            if operation_count_value is None:
                raise MergeError(f"{context}: operation_count is required")
            operation_count = int(operation_count_value)
            if not 1 <= operation_count <= maximum_operations:
                raise MergeError(
                    f"{context}: operation_count must be 1..{maximum_operations}"
                )
            if operation_count != len(row_ids):
                raise MergeError(
                    f"{context}: operation_count does not equal row_ids length"
                )

            linked_rows: list[Mapping[str, Any]] = []
            for row_id in row_ids:
                row = run_rows.get(row_id)
                if row is None:
                    raise MergeError(f"{context}: unknown row_id {row_id!r}")
                if row.get("perf_batch_id") != batch_id:
                    raise MergeError(
                        f"{context}: row {row_id!r} does not bind back to batch_id"
                    )
                row_key = (bundle.run_id, row_id)
                if row_key in rows_claimed_by_batches:
                    raise MergeError(
                        f"{context}: row {row_id!r} is claimed by multiple perf batches"
                    )
                rows_claimed_by_batches.add(row_key)
                if row["phase"] != "measured":
                    raise MergeError(f"{context}: perf batch links a non-measured row")
                linked_rows.append(row)
            declared_for_run[batch_id] = set(row_ids)

            group_keys = {_summary_group_key(row) for row in linked_rows}
            if len(group_keys) != 1:
                raise MergeError(f"{context}: linked rows span multiple timing strata")
            first = linked_rows[0]
            computed_class, computed_signature = collection_identity(raw)
            declared_class = raw.get("collection_class")
            declared_signature = raw.get("collection_signature")
            row_classes = {
                row["configuration"].get("perf_collection_class")
                for row in linked_rows
            }
            row_signatures = {
                row["configuration"].get("perf_collection_signature")
                for row in linked_rows
            }
            modern_collection = (
                declared_class is not None or declared_signature is not None
                or row_classes != {None} or row_signatures != {None}
            )
            if modern_collection:
                if declared_class != computed_class:
                    raise MergeError(
                        f"{context}: declared perf collection class disagrees "
                        "with observed event set"
                    )
                declared_signature = _require_sha256(
                    declared_signature,
                    f"{context}: perf collection signature",
                )
                if declared_signature != computed_signature:
                    raise MergeError(
                        f"{context}: declared perf collection signature "
                        "disagrees with observed event set"
                    )
                if row_classes != {computed_class}:
                    raise MergeError(
                        f"{context}: linked rows disagree on actual perf class"
                    )
                if row_signatures != {computed_signature}:
                    raise MergeError(
                        f"{context}: linked rows disagree on actual perf signature"
                    )
            scenario = raw.get("scenario")
            if scenario != first["scenario_id"] or any(
                    row["scenario_id"] != scenario for row in linked_rows):
                raise MergeError(f"{context}: scenario does not match linked rows")
            attribute_variant = raw.get("attribute_variant")
            if attribute_variant != first["configuration"].get("attribute_mode") or any(
                    row["configuration"].get("attribute_mode") != attribute_variant
                    for row in linked_rows):
                raise MergeError(
                    f"{context}: attribute_variant does not match linked rows"
                )

            collection_scope = raw.get("collection_scope")
            count_semantics = raw.get("count_semantics")
            independent_semantics = (
                isinstance(collection_scope, str)
                and "independent" in collection_scope.casefold()
                and "batch" in collection_scope.casefold()
                and isinstance(count_semantics, str)
                and "aggregate" in count_semantics.casefold()
                and "operation_count" in count_semantics.casefold()
            )
            if raw.get("status") == "observed" and not independent_semantics:
                raise MergeError(
                    f"{context}: observed batch lacks independent aggregate semantics"
                )

            normalized_counts: Dict[str, float] = {}
            raw_counts = raw.get("event_counts_per_search", {})
            if not isinstance(raw_counts, Mapping):
                raise MergeError(f"{context}: event_counts_per_search must be an object")
            for event, value in raw_counts.items():
                measured = _number(value, f"{context} {event} per-search counter")
                if measured is not None:
                    normalized_counts[str(event)] = measured

            aggregate_counts = raw.get("event_counts", {})
            if not isinstance(aggregate_counts, Mapping):
                raise MergeError(f"{context}: event_counts must be an object")
            normalized_aggregates: Dict[str, float] = {}
            for event, value in aggregate_counts.items():
                aggregate = _number(value, f"{context} aggregate {event}")
                if aggregate is not None:
                    normalized_aggregates[str(event)] = aggregate
            if set(normalized_counts) != set(normalized_aggregates):
                missing_aggregate = sorted(
                    set(normalized_counts).difference(normalized_aggregates)
                )
                missing_normalized = sorted(
                    set(normalized_aggregates).difference(normalized_counts)
                )
                detail = []
                if missing_aggregate:
                    detail.append(
                        "missing aggregate(s): " + ", ".join(missing_aggregate)
                    )
                if missing_normalized:
                    detail.append(
                        "missing per-search value(s): "
                        + ", ".join(missing_normalized)
                    )
                raise MergeError(
                    f"{context}: perf aggregate/per-search event sets disagree ("
                    + "; ".join(detail) + ")"
                )
            for event, aggregate in normalized_aggregates.items():
                expected = aggregate / operation_count
                if not math.isclose(
                        normalized_counts[event], expected,
                        rel_tol=1e-9, abs_tol=1e-9):
                    raise MergeError(
                        f"{context}: {event} per-search count disagrees with aggregate"
                    )

            raw_units = raw.get("event_units", {})
            if not isinstance(raw_units, Mapping):
                raise MergeError(f"{context}: event_units must be an object")
            unknown_unit_events = set(raw_units).difference(normalized_aggregates)
            if unknown_unit_events:
                raise MergeError(
                    f"{context}: event_units names unobserved event(s): "
                    + ", ".join(sorted(map(str, unknown_unit_events)))
                )
            normalized_units: Dict[str, str] = {}
            for event in normalized_aggregates:
                unit = raw_units.get(event, "count")
                if not isinstance(unit, str) or not unit:
                    raise MergeError(f"{context}: {event} unit is invalid")
                normalized_units[event] = unit

            batch_cpu = _number(
                raw.get("server_cpu_seconds_per_search"),
                f"{context} server CPU per search",
            )
            observed = raw.get("status") == "observed" and independent_semantics
            quiet_valid = True
            quiet_reason = "not required for this bundle"
            if (
                    bundle.release_candidate
                    and _artifact_server({
                        "server": bundle.run_manifest.get("server")
                    }) == "389ds"):
                quiet_valid, quiet_reason = _background_quiet_collection_status(
                    raw.get("background_quiet_window"),
                    _nested(
                        bundle.run_manifest, "server_setup",
                        "background_referral_check_control",
                    ),
                )
            normalized.append({
                "batch_id": batch_id,
                "run_id": bundle.run_id,
                "source_directory": str(bundle.root),
                "row_ids": row_ids,
                "operation_count": operation_count,
                "collection_status": raw.get("status"),
                "collection_class": computed_class,
                "collection_signature": computed_signature,
                "collection_scope": collection_scope,
                "count_semantics": count_semantics,
                "sample_semantics": (
                    "one-independent-perf-batch-normalized-per-search"
                ),
                "usable": observed and quiet_valid,
                "background_quiet_window_validation": {
                    "passed": quiet_valid,
                    "reason": quiet_reason,
                },
                "instructions_per_search": (
                    normalized_counts.get("instructions") if observed else None
                ),
                "server_cpu_seconds_per_search": batch_cpu if observed else None,
                "event_counts_per_search": normalized_counts,
                "event_units": normalized_units,
                "scenario_id": first["scenario_id"],
                "scenario_fingerprint": first["scenario_fingerprint"],
                "executable_sha256": first["executable_sha256"],
                "behavioral_runtime_identity_sha256": first[
                    "behavioral_runtime_identity_sha256"
                ],
                "host_signature": first["host_signature"],
                "configuration": first["configuration"],
                "summary_group_key": next(iter(group_keys)),
            })

        for row_id, row in run_rows.items():
            batch_id = row.get("perf_batch_id")
            if batch_id is None:
                continue
            if not isinstance(batch_id, str) or not batch_id:
                raise MergeError(
                    f"{bundle.root}: row {row_id!r} has invalid perf_batch_id"
                )
            if row_id not in declared_for_run.get(batch_id, set()):
                raise MergeError(
                    f"{bundle.root}: row {row_id!r} references absent or mismatched "
                    f"perf batch {batch_id!r}"
                )
    return normalized


def normalize_correctness_controls(
        bundles: Sequence[Bundle]) -> list[Dict[str, Any]]:
    """Normalize untimed preflight and dynamic-list correctness records."""
    normalized: list[Dict[str, Any]] = []
    for bundle in bundles:
        raw_records = bundle.correctness_manifest.get("scenarios", [])
        if raw_records is None:
            raw_records = []
        if not isinstance(raw_records, list):
            raise MergeError(
                f"{bundle.root}: correctness scenarios must be a list"
            )
        seen: set[str] = set()
        scenarios = bundle.workload.get("scenarios", {})
        for index, raw in enumerate(raw_records):
            context = f"{bundle.root}: correctness scenario {index}"
            if not isinstance(raw, Mapping):
                raise MergeError(f"{context}: record must be an object")
            scenario_id = raw.get("scenario")
            if not isinstance(scenario_id, str) or scenario_id not in scenarios:
                raise MergeError(f"{context}: unknown or missing scenario")
            if scenario_id in seen:
                raise MergeError(
                    f"{bundle.root}: duplicate correctness record for {scenario_id}"
                )
            seen.add(scenario_id)
            scenario = scenarios[scenario_id]
            groups = _scenario_groups(bundle.workload, scenario_id)
            dynamic = "dynamic-list-correctness" in groups
            if dynamic:
                _validate_dynamic_final_candidate_evidence(
                    bundle.root,
                    raw.get("final_search"),
                    f"{context}: {scenario_id}",
                )
            expected_count = scenario.get("expected_count")
            expected_sha = scenario.get("expected_sha256")
            record_count = _first(raw, (
                ("expected_final_count",), ("expected_count",),
            ))
            record_sha = _first(raw, (
                ("expected_final_sha256",), ("expected_sha256",),
            ))
            problems: list[str] = []
            if expected_count is None or record_count is None or _number(
                    record_count, f"{context} expected count", integral=True,
                    ) != float(expected_count):
                problems.append("expected count is missing or disagrees with oracle")
            if record_sha is None or record_sha != expected_sha:
                problems.append("expected DN hash is missing or disagrees with oracle")
            marker = raw.get("correctness")
            explicit_pass = marker is True or (
                isinstance(marker, str) and marker.casefold() == "pass"
            )
            mechanism_gate = raw.get("mechanism_gate")
            mechanism_gate = (
                mechanism_gate if isinstance(mechanism_gate, Mapping) else {}
            )
            evidence_status = str(raw.get("evidence_status", "")).casefold()
            historical_baseline = (
                raw.get("historical_baseline") is True
                or raw.get("historical_expected_failure") is True
                or (
                    dynamic and (
                        "historical" in evidence_status
                        or (
                            isinstance(marker, str)
                            and "expected-historical" in marker.casefold()
                        )
                    )
                )
            )
            expected_historical_mechanism_mismatch = (
                raw.get("expected_historical_mechanism_mismatch") is True
                or _nested(
                    raw, "diagnostic_flights", "preflight",
                    "expected_historical_mechanism_mismatch",
                ) is True
            )
            admin_limit = raw.get("ldap_adminlimit_exceeded")
            if dynamic and not historical_baseline:
                if admin_limit is True:
                    problems.append("dynamic control reports LDAP_ADMINLIMIT_EXCEEDED")
                elif admin_limit is not False:
                    problems.append("dynamic control lacks an explicit no-admin-limit result")
            exact_operations: list[Dict[str, Any]] = []

            def add_exact_operation(
                    operation_kind: str, evidence: Any, operation_id: str, *,
                    require_scenario_oracle: bool = True,
                    server_result_evidence: Any = None) -> None:
                if not isinstance(evidence, Mapping):
                    exact_operations.append({
                        "operation_id": operation_id,
                        "operation_kind": operation_kind,
                        "status": "pending",
                        "reason": "exact-result evidence is absent",
                    })
                    return
                evidence_status = evidence.get("evidence_status")
                if evidence_status != "observed":
                    exact_operations.append({
                        "operation_id": operation_id,
                        "operation_kind": operation_kind,
                        "status": "pending",
                        "reason": f"exact-result evidence is {evidence_status!r}",
                    })
                    return
                expected_operation_count = evidence.get("expected_count")
                expected_operation_sha = evidence.get("expected_sha256")
                expected_operation_code = evidence.get(
                    "expected_ldap_result_code"
                )
                exact_passed = (
                    evidence.get("passed") is True
                    and evidence.get("returned_count") == expected_operation_count
                    and evidence.get("returned_sha256") == expected_operation_sha
                    and _canonical_result_code(evidence.get("ldap_result_code"))
                    == _canonical_result_code(expected_operation_code)
                    and evidence.get("exact_count_match", True) is True
                    and evidence.get("exact_sha256_match", True) is True
                    and evidence.get("exact_dns_match", True) is True
                    and (
                        not require_scenario_oracle
                        or (
                            expected_operation_count == expected_count
                            and expected_operation_sha == expected_sha
                            and _canonical_result_code(expected_operation_code)
                            == _canonical_result_code(
                                scenario.get("expected_result_code")
                            )
                        )
                    )
                )
                effective_server_evidence = (
                    server_result_evidence
                    if isinstance(server_result_evidence, Mapping)
                    else evidence.get("server_result_evidence")
                )
                exact_passed = exact_passed and (
                    isinstance(effective_server_evidence, Mapping)
                    and effective_server_evidence.get("evidence_status") == "observed"
                    and effective_server_evidence.get("passed") is True
                    and _canonical_result_code(
                        effective_server_evidence.get("expected_ldap_result_code")
                    ) == _canonical_result_code(expected_operation_code)
                    and _canonical_result_code(
                        effective_server_evidence.get("actual_server_result_code")
                    ) == _canonical_result_code(expected_operation_code)
                )
                exact_operations.append({
                    "operation_id": operation_id,
                    "operation_kind": operation_kind,
                    "status": "pass" if exact_passed else "fail",
                    "reason": (
                        "exact count/hash/result code match"
                        if exact_passed else
                        "exact count/hash/result code mismatch"
                    ),
                })

            flights = raw.get("diagnostic_flights")
            if not dynamic:
                for phase in ("preflight", "postflight"):
                    flight = (
                        flights.get(phase)
                        if isinstance(flights, Mapping) else
                        raw if phase == "preflight" else None
                    )
                    add_exact_operation(
                        f"mechanism-{phase}",
                        flight.get("exact_result")
                        if isinstance(flight, Mapping) else None,
                        f"{bundle.run_id}:{scenario_id}:{phase}",
                        server_result_evidence=(
                            flight.get("server_result_evidence")
                            if isinstance(flight, Mapping) else None
                        ),
                    )

            selection_probe = raw.get("selection_probe")
            if isinstance(selection_probe, Mapping) and (
                    selection_probe.get("evidence_status") == "observed"):
                add_exact_operation(
                    "selection-probe", selection_probe.get("exact_result"),
                    f"{bundle.run_id}:{scenario_id}:selection-probe",
                    require_scenario_oracle=False,
                    server_result_evidence=selection_probe.get(
                        "server_result_evidence"
                    ),
                )

            if dynamic:
                for field, operation_kind, require_scenario in (
                        ("ordinary_candidates", "dynamic-list-control", False),
                        ("augmented_candidates", "dynamic-list-control", False),
                        ("final_search", "dynamic-list-control", True),
                        ("post_control_health", "dynamic-list-control", False)):
                    evidence = raw.get(field)
                    add_exact_operation(
                        operation_kind, evidence,
                        f"{bundle.run_id}:{scenario_id}:{field}",
                        require_scenario_oracle=require_scenario,
                        server_result_evidence=(
                            evidence.get("server_result_evidence")
                            if isinstance(evidence, Mapping) else None
                        ),
                    )

            raw_profiles = bundle.run_manifest.get("profiles", [])
            if isinstance(raw_profiles, list):
                for profile_index, profile in enumerate(raw_profiles):
                    if not isinstance(profile, Mapping) or (
                            profile.get("scenario") != scenario_id):
                        continue
                    if profile.get("evidence_status") == "not-planned":
                        continue
                    profile_operations = profile.get("operations")
                    if isinstance(profile_operations, list) and profile_operations:
                        for operation in profile_operations:
                            operation_index = operation.get("operation_index")
                            add_exact_operation(
                                "profiled-search",
                                operation.get("exact_result"),
                                f"{bundle.run_id}:{scenario_id}:profile:"
                                f"{profile_index}:{operation_index}",
                                server_result_evidence=operation.get(
                                    "server_result_evidence"
                                ),
                            )
                    else:
                        add_exact_operation(
                            "profiled-search", profile.get("exact_result"),
                            f"{bundle.run_id}:{scenario_id}:profile:{profile_index}",
                            server_result_evidence=profile.get(
                                "server_result_evidence"
                            ),
                        )
            artifact_commits = sorted({
                str(artifact["commit"]) for artifact in bundle.artifacts
                if artifact.get("commit") is not None
            })
            production_commits = sorted({
                str(artifact["production_commit"])
                for artifact in bundle.artifacts
                if artifact.get("production_commit") is not None
            })
            dynamic_cap_status = "not-applicable"
            dynamic_cap_reason = "scenario is not a dynamic-list control"
            dynamic_cap_observed = _nested(
                raw, "final_search", "diagnostics", "cap_path_observed",
            )
            if dynamic:
                bounded = scenario.get("expected_diagnostics", {}).get(
                    "bounded_read", {}
                )
                revision_expectations = (
                    bounded.get("revision_expectations", {})
                    if isinstance(bounded, Mapping) else {}
                )
                role_by_commit = {
                    COMMIT_7C: "combined-diagnostic",
                    COMMIT_038: "dynamic-list-fix",
                    COMMIT_FINAL: "final",
                }
                roles = {
                    role_by_commit[commit] for commit in production_commits
                    if commit in role_by_commit
                }
                if len(roles) != 1:
                    dynamic_cap_status = "pending"
                    dynamic_cap_reason = (
                        "dynamic control does not identify one supported revision role"
                    )
                else:
                    role = next(iter(roles))
                    expectation = revision_expectations.get(role)
                    if expectation not in {
                            "required-pre-fix-diagnostic", "required", "forbidden"}:
                        dynamic_cap_status = "pending"
                        dynamic_cap_reason = (
                            f"dynamic cap expectation is undefined for {role}"
                        )
                    elif not isinstance(dynamic_cap_observed, bool):
                        dynamic_cap_status = "pending"
                        dynamic_cap_reason = (
                            "dynamic final-search cap observation is missing"
                        )
                    else:
                        required_cap = str(expectation).startswith("required")
                        cap_matches = (
                            dynamic_cap_observed is True
                            if required_cap else dynamic_cap_observed is False
                        )
                        dynamic_cap_status = "pass" if cap_matches else "fail"
                        dynamic_cap_reason = (
                            "dynamic cap observation matches the revision contract"
                            if cap_matches else
                            "dynamic cap observation contradicts the revision contract"
                        )

            mechanism_failures = mechanism_gate.get("failures")
            mechanism_failures = (
                mechanism_failures if isinstance(mechanism_failures, list) else []
            )
            failed_exact_operations = [
                operation for operation in exact_operations
                if operation["status"] == "fail"
            ]
            pending_exact_operations = [
                operation for operation in exact_operations
                if operation["status"] == "pending"
            ]
            historical_failure_observed = historical_baseline and (
                admin_limit is True
                or bool(mechanism_failures)
                or bool(failed_exact_operations)
            )
            if historical_baseline and not historical_failure_observed:
                problems.append(
                    "historical failure is claimed but no failing operation or "
                    "mechanism evidence was observed"
                )
            if not explicit_pass and not historical_failure_observed:
                problems.append("control is not explicitly marked pass")
            if dynamic and dynamic_cap_status == "fail":
                problems.append(dynamic_cap_reason)
            authoritative_operations_pass = (
                bool(exact_operations)
                and not failed_exact_operations
                and not pending_exact_operations
            )
            normalized.append({
                "control_id": f"{bundle.run_id}:{scenario_id}",
                "run_id": bundle.run_id,
                "source_directory": str(bundle.root),
                "scenario_id": scenario_id,
                "scenario_groups": groups,
                "dynamic": dynamic,
                "server": _artifact_server({
                    "server": bundle.run_manifest.get("server")
                }),
                "revision_roles": sorted({
                    str(artifact["revision_role"])
                    for artifact in bundle.artifacts
                    if artifact.get("revision_role") is not None
                }),
                "source_commits": artifact_commits,
                "production_commits": production_commits,
                "behavioral_runtime_identity_sha256s": sorted({
                    str(artifact["behavioral_runtime_identity_sha256"])
                    for artifact in bundle.artifacts
                }),
                "lookup_mode": _config_value(
                    {}, bundle.run_manifest,
                    ("lookup_mode", "lookup_mode_actual", "or_lookup_mode"),
                ),
                "release_candidate": bundle.release_candidate,
                "passed": not problems and (
                    historical_failure_observed or authoritative_operations_pass
                ),
                "oracle_passed": (
                    explicit_pass and authoritative_operations_pass
                    and (not dynamic or admin_limit is False)
                    and (not dynamic or dynamic_cap_status == "pass")
                ),
                "supporting_historical_failure": historical_failure_observed,
                "expected_historical_mechanism_mismatch": (
                    expected_historical_mechanism_mismatch
                ),
                "historical_baseline": historical_baseline,
                "complete": (
                    (explicit_pass or historical_failure_observed)
                    and record_count is not None and record_sha is not None
                    and (historical_failure_observed or authoritative_operations_pass)
                    and (not dynamic or historical_failure_observed
                         or (admin_limit is False
                             and dynamic_cap_status == "pass"))
                ),
                "problems": problems,
                "expected_count": record_count,
                "expected_sha256": record_sha,
                "ldap_adminlimit_exceeded": admin_limit,
                "dynamic_cap_status": dynamic_cap_status,
                "dynamic_cap_reason": dynamic_cap_reason,
                "dynamic_cap_observed": dynamic_cap_observed,
                "ordinary_candidate_count": raw.get("ordinary_candidate_count"),
                "augmented_candidate_count": raw.get("augmented_candidate_count"),
                "id_list_scan_limit": raw.get("id_list_scan_limit"),
                "lookthrough_limit": raw.get("lookthrough_limit"),
                "exact_operations": exact_operations,
                "raw": dict(raw),
            })
    return normalized


def nearest_rank(values: Sequence[float], percentile: float = 0.95) -> float:
    """Return the deterministic nearest-rank percentile used by the study."""
    if not values:
        raise MergeError("nearest-rank percentile requires at least one value")
    if not 0 < percentile <= 1:
        raise MergeError("percentile must be in (0, 1]")
    ordered = sorted(float(value) for value in values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _metric_summary(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {
            "n": 0,
            "median": None,
            "p95_nearest_rank": None,
            "mad": None,
        }
    numeric = [float(value) for value in values]
    median = float(statistics.median(numeric))
    deviations = [abs(value - median) for value in numeric]
    return {
        "n": len(numeric),
        "median": median,
        "p95_nearest_rank": nearest_rank(numeric),
        "mad": float(statistics.median(deviations)),
    }


def build_binary_groups(bundles: Sequence[Bundle]) -> list[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for bundle in bundles:
        for artifact in bundle.artifacts:
            digest = artifact["executable_sha256"]
            group = grouped.setdefault(digest, {
                "binary_id": digest[:16],
                "executable_sha256": digest,
                "commit_labels": set(),
                "source_commits": set(),
                "production_commits": set(),
                "revision_roles": set(),
                "servers": set(),
                "source_run_ids": set(),
                "installed_rpm_proved": False,
                "runtime_closure_sha256s": set(),
                "backend_runtime_closure_sha256s": set(),
                "behavioral_groups": {},
            })
            group["commit_labels"].add(artifact["label"])
            if artifact.get("commit"):
                group["source_commits"].add(artifact["commit"])
            if artifact.get("production_commit"):
                group["production_commits"].add(artifact["production_commit"])
            if artifact.get("revision_role"):
                group["revision_roles"].add(artifact["revision_role"])
            if artifact.get("server"):
                group["servers"].add(artifact["server"])
            group["source_run_ids"].add(bundle.run_id)
            group["installed_rpm_proved"] |= artifact["rpm_proved"]
            runtime_closure_sha = artifact["runtime_closure_sha256"]
            backend_closure_sha = artifact["backend_runtime_closure_sha256"]
            behavioral_sha = artifact["behavioral_runtime_identity_sha256"]
            group["runtime_closure_sha256s"].add(runtime_closure_sha)
            group["backend_runtime_closure_sha256s"].add(backend_closure_sha)
            behavioral_group = group["behavioral_groups"].setdefault(
                behavioral_sha, {
                "behavioral_runtime_identity_sha256": behavioral_sha,
                "runtime_closure_sha256": runtime_closure_sha,
                "backend_runtime_closure_sha256": backend_closure_sha,
                "runtime_identity_id": behavioral_sha[:16],
                "commit_labels": set(),
                "source_commits": set(),
                "production_commits": set(),
                "revision_roles": set(),
                "servers": set(),
                "source_run_ids": set(),
                "installed_rpm_proved": False,
            })
            if (
                    behavioral_group["runtime_closure_sha256"]
                    != runtime_closure_sha
                    or behavioral_group["backend_runtime_closure_sha256"]
                    != backend_closure_sha):
                raise MergeError("behavioral runtime identity collision")
            behavioral_group["commit_labels"].add(artifact["label"])
            if artifact.get("commit"):
                behavioral_group["source_commits"].add(artifact["commit"])
            if artifact.get("production_commit"):
                behavioral_group["production_commits"].add(
                    artifact["production_commit"]
                )
            if artifact.get("revision_role"):
                behavioral_group["revision_roles"].add(
                    artifact["revision_role"]
                )
            if artifact.get("server"):
                behavioral_group["servers"].add(artifact["server"])
            behavioral_group["source_run_ids"].add(bundle.run_id)
            behavioral_group["installed_rpm_proved"] |= artifact["rpm_proved"]
    serialized = []
    for digest in sorted(grouped):
        group = grouped[digest]
        behavioral_groups = group.pop("behavioral_groups")
        output = {
            key: sorted(value) if isinstance(value, set) else value
            for key, value in group.items()
        }
        output["behavioral_runtime_identity_sha256s"] = sorted(
            behavioral_groups
        )
        output["behavioral_runtime_identity_groups"] = [{
            key: sorted(value) if isinstance(value, set) else value
            for key, value in behavioral_groups[behavioral_sha].items()
        } for behavioral_sha in sorted(behavioral_groups)]
        output["performance_identity_count"] = len(behavioral_groups)
        serialized.append(output)
    return serialized


def _summary_group_key(row: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes({
        "executable_sha256": row["executable_sha256"],
        "installed_package_closure_sha256": row.get(
            "installed_package_closure_sha256"
        ),
        "behavioral_runtime_identity_sha256": row[
            "behavioral_runtime_identity_sha256"
        ],
        "scenario_fingerprint": row["scenario_fingerprint"],
        "configuration": row["configuration"],
        "host_signature": row["host_signature"],
    }))


def summarize_rows(
        rows: Sequence[Mapping[str, Any]], binary_groups: Sequence[Mapping[str, Any]],
        minimum_repeats: int,
        perf_batches: Sequence[Mapping[str, Any]] = ()) -> list[Dict[str, Any]]:
    aliases: Dict[tuple[str, str], Dict[str, Any]] = {}
    for group in binary_groups:
        for identity_group in group["behavioral_runtime_identity_groups"]:
            aliases[(
                group["executable_sha256"],
                identity_group["behavioral_runtime_identity_sha256"],
            )] = {
                **identity_group,
                "binary_id": group["binary_id"],
            }
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(_summary_group_key(row), []).append(row)
    perf_by_group: Dict[str, list[Mapping[str, Any]]] = {}
    for batch in perf_batches:
        perf_by_group.setdefault(str(batch["summary_group_key"]), []).append(batch)
    summaries: list[Dict[str, Any]] = []
    for key in sorted(grouped):
        members = grouped[key]
        first = members[0]
        member_row_keys = {
            (str(row["run_id"]), str(row["row_id"])) for row in members
        }
        elapsed = [
            row["metrics"]["elapsed_seconds"] for row in members
            if row["metrics"]["elapsed_seconds"] is not None
        ]
        cpu = [
            row["metrics"]["server_cpu_seconds"] for row in members
            if row["metrics"]["server_cpu_seconds"] is not None
        ]
        instruction_batches = [
            batch for batch in perf_by_group.get(key, [])
            if batch.get("usable")
            and batch.get("instructions_per_search") is not None
            and all(
                (str(batch["run_id"]), str(row_id)) in member_row_keys
                for row_id in batch["row_ids"]
            )
        ]
        instructions = [
            float(batch["instructions_per_search"])
            for batch in instruction_batches
        ]
        elapsed_summary = _metric_summary(elapsed)
        server_etime = [
            row["metrics"]["server_etime_seconds"] for row in members
            if row["metrics"]["server_etime_seconds"] is not None
        ]
        server_etime_summary = _metric_summary(server_etime)
        cpu_summary = _metric_summary(cpu)
        instruction_summary = _metric_summary(instructions)
        instruction_summary.update({
            "sample_semantics": (
                "one-independent-perf-batch-normalized-per-search"
            ),
            "independent_batch_count": len(instruction_batches),
            "covered_operation_count": sum(
                int(batch["operation_count"]) for batch in instruction_batches
            ),
        })
        rss_summary = _metric_summary([
            row["metrics"]["rss_kib"] for row in members
            if row["metrics"]["rss_kib"] is not None
        ])
        high_water_values = [
            row["metrics"]["high_water_kib"] for row in members
            if row["metrics"]["high_water_kib"] is not None
        ]
        startup_rss_by_run: Dict[str, float] = {}
        startup_hwm_by_run: Dict[str, float] = {}
        for row in members:
            run_id = str(row["run_id"])
            for field, destination in (
                    ("startup_rss_kib", startup_rss_by_run),
                    ("startup_high_water_kib", startup_hwm_by_run)):
                value = row["metrics"][field]
                if value is None:
                    continue
                measured = float(value)
                previous = destination.get(run_id)
                if previous is not None and previous != measured:
                    raise MergeError(
                        f"run {run_id!r} contains conflicting {field} baselines"
                    )
                destination[run_id] = measured
        startup_rss_summary = _metric_summary(
            list(startup_rss_by_run.values())
        )
        startup_hwm_summary = _metric_summary(
            list(startup_hwm_by_run.values())
        )
        binary = aliases[(
            first["executable_sha256"],
            first["behavioral_runtime_identity_sha256"],
        )]
        mechanism_required = any(row["mechanism"]["required"] for row in members)
        mechanism_verified = all(
            row["mechanism"]["verified"]
            for row in members if row["mechanism"]["required"]
        ) if mechanism_required else True
        mechanism_records = [row["mechanism"] for row in members]
        lookup_largest_families = sorted({
            int(lookup["largest_family"])
            for mechanism in mechanism_records
            for lookup in (
                mechanism.get("lookup_summaries")
                if isinstance(mechanism.get("lookup_summaries"), list) else []
            )
            if isinstance(lookup, Mapping)
            and isinstance(lookup.get("largest_family"), int)
        })
        stat_index_reads = sorted({
            canonical_json_bytes(read).decode("utf-8")
            for mechanism in mechanism_records
            for read in (
                mechanism.get("stat_index_reads")
                if isinstance(mechanism.get("stat_index_reads"), list) else []
            )
            if isinstance(read, Mapping)
        })
        summary = {
            "summary_id": key[:16],
            "executable_sha256": first["executable_sha256"],
            "runtime_closure_sha256": first["runtime_closure_sha256"],
            "backend_runtime_closure_sha256": first[
                "backend_runtime_closure_sha256"
            ],
            "behavioral_runtime_identity_sha256": first[
                "behavioral_runtime_identity_sha256"
            ],
            "installed_package_closure_sha256": first.get(
                "installed_package_closure_sha256"
            ),
            "binary_id": binary["binary_id"],
            "runtime_identity_id": binary["runtime_identity_id"],
            "commit_labels": binary["commit_labels"],
            "source_commits": binary["source_commits"],
            "production_commits": binary["production_commits"],
            "revision_roles": binary["revision_roles"],
            "scenario_ids": sorted({row["scenario_id"] for row in members}),
            "scenario_groups": sorted({
                group for row in members for group in row["scenario_groups"]
            }),
            "scenario_fingerprint": first["scenario_fingerprint"],
            "configuration": first["configuration"],
            "scale": first["scale"],
            "scale_curve": first["scale_curve"],
            "cross_server_comparison": first.get("cross_server_comparison"),
            "host_signature": first["host_signature"],
            "source_run_ids": sorted({row["run_id"] for row in members}),
            "n": elapsed_summary["n"],
            "elapsed": elapsed_summary,
            "server_etime": server_etime_summary,
            "server_cpu": cpu_summary,
            "instructions": instruction_summary,
            "instruction_batch_ids": sorted(
                str(batch["batch_id"]) for batch in instruction_batches
            ),
            "instructions_sample_semantics": (
                "one-independent-perf-batch-normalized-per-search"
            ),
            "rss_kib": rss_summary,
            "high_water_kib_max": max(high_water_values) if high_water_values else None,
            "startup_rss_kib": startup_rss_summary["median"],
            "startup_high_water_kib": startup_hwm_summary["median"],
            "startup_rss_kib_summary": startup_rss_summary,
            "startup_high_water_kib_summary": startup_hwm_summary,
            "startup_rss_kib_by_run": dict(sorted(startup_rss_by_run.items())),
            "startup_high_water_kib_by_run": dict(
                sorted(startup_hwm_by_run.items())
            ),
            "metric_coverage": {
                "server_cpu": f"{cpu_summary['n']}/{elapsed_summary['n']}",
                "server_etime": f"{server_etime_summary['n']}/{elapsed_summary['n']}",
                "instructions": (
                    f"{instruction_summary['n']} independent perf batches/"
                    f"{elapsed_summary['n']} elapsed rows"
                ),
                "rss": f"{rss_summary['n']}/{elapsed_summary['n']}",
                "high_water": f"{len(high_water_values)}/{elapsed_summary['n']}",
            },
            "mechanism_evidence": {
                "required": mechanism_required,
                "verified": mechanism_verified,
                "required_kinds": sorted({
                    row["mechanism"]["required_kind"] for row in members
                    if row["mechanism"]["required_kind"] is not None
                }),
                "candidate_counts": sorted({
                    row["mechanism"]["observed_final_candidate_count"]
                    for row in members
                    if row["mechanism"]["observed_final_candidate_count"] is not None
                }),
                "access_notes": sorted({
                    str(row["mechanism"]["access_notes"]) for row in members
                    if row["mechanism"]["access_notes"] is not None
                }),
                "lookup_constructed_values": sorted({
                    bool(mechanism["lookup_constructed"])
                    for mechanism in mechanism_records
                    if isinstance(mechanism.get("lookup_constructed"), bool)
                }),
                "lookup_largest_families": lookup_largest_families,
                "lookup_consumption_statuses": sorted({
                    str(value)
                    for mechanism in mechanism_records
                    for value in (
                        mechanism.get("lookup_consumption_status"),
                        mechanism.get("profile_consumption_status"),
                    )
                    if value is not None
                }),
                "cap_path_observed_values": sorted({
                    bool(mechanism["cap_path_observed"])
                    for mechanism in mechanism_records
                    if isinstance(mechanism.get("cap_path_observed"), bool)
                }),
                "candidate_list_statuses": sorted({
                    str(mechanism["candidate_list_status"])
                    for mechanism in mechanism_records
                    if mechanism.get("candidate_list_status") is not None
                }),
                "candidate_list_observed_values": sorted({
                    bool(mechanism["candidate_list_observed"])
                    for mechanism in mechanism_records
                }),
                "candidate_list_values": sorted({
                    int(value)
                    for mechanism in mechanism_records
                    for value in (
                        mechanism.get("candidate_list_values")
                        if isinstance(mechanism.get("candidate_list_values"), list)
                        else []
                    )
                    if isinstance(value, int)
                }),
                "access_notes_observed_values": sorted({
                    bool(mechanism["access_notes_observed"])
                    for mechanism in mechanism_records
                }),
                "stat_index_reads_observed_values": sorted({
                    bool(mechanism["stat_index_reads_observed"])
                    for mechanism in mechanism_records
                }),
                "stat_index_reads": [
                    json.loads(value) for value in stat_index_reads
                ],
                "selected_attributes_direct": sorted({
                    str(mechanism["selected_attribute"])
                    for mechanism in mechanism_records
                    if mechanism.get("selected_family_directly_reported") is True
                    and mechanism.get("selected_attribute") is not None
                }),
                "selection_observations": [
                    json.loads(value) for value in sorted({
                        canonical_json_bytes(
                            mechanism["selection_observation"]
                        ).decode("utf-8")
                        for mechanism in mechanism_records
                        if isinstance(
                            mechanism.get("selection_observation"), Mapping,
                        )
                    })
                ],
                "profile_sha256s": sorted({
                    str(mechanism["profile_sha256"])
                    for mechanism in mechanism_records
                    if _is_sha256(mechanism.get("profile_sha256"))
                }),
                "profile_statuses": sorted({
                    str(mechanism["profile_status"])
                    for mechanism in mechanism_records
                    if mechanism.get("profile_status") is not None
                }),
                "profile_attributed_waivers": [
                    mechanism["profile_attributed_waiver"]
                    for mechanism in mechanism_records
                    if isinstance(
                        mechanism.get("profile_attributed_waiver"), Mapping
                    )
                ],
                "approximate_semantics_evidence": [
                    json.loads(value) for value in sorted({
                        canonical_json_bytes(
                            mechanism["approximate_semantics_evidence"]
                        ).decode("utf-8")
                        for mechanism in mechanism_records
                        if isinstance(
                            mechanism.get("approximate_semantics_evidence"),
                            Mapping,
                        )
                    })
                ],
            },
            "release_ready": elapsed_summary["n"] >= minimum_repeats,
            # Flat aliases make the machine-readable output easy to consume
            # without weakening the fully described metric objects above.
            "elapsed_median_seconds": elapsed_summary["median"],
            "elapsed_p95_seconds": elapsed_summary["p95_nearest_rank"],
            "server_etime_median_seconds": server_etime_summary["median"],
            "server_cpu_median_seconds": cpu_summary["median"],
            "instructions_median": instruction_summary["median"],
        }
        summaries.append(summary)
    return summaries


def _comparison_configuration(summary: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the exact matched stratum, deliberately excluding lookup mode."""
    configuration = dict(summary["configuration"])
    configuration.pop("lookup_mode", None)
    return configuration


def _comparison_key(summary: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes({
        "scenario_fingerprint": summary["scenario_fingerprint"],
        "configuration_except_lookup_mode": _comparison_configuration(summary),
    }))


def _invariant_summary_stratum(summary: Mapping[str, Any]) -> str:
    """Identity for a multi-scenario comparison ladder.

    Scenario/filter/scale are deliberately absent.  Everything about the
    executable, live runtime, host, and run configuration remains invariant.
    """
    return sha256_bytes(canonical_json_bytes({
        "executable_sha256": summary.get("executable_sha256"),
        "behavioral_runtime_identity_sha256": summary.get(
            "behavioral_runtime_identity_sha256"
        ),
        "host_signature": summary.get("host_signature"),
        "configuration_except_lookup": _comparison_configuration(summary),
    }))


def _summary_revision_order(
        summary: Mapping[str, Any], revision_order: Mapping[str, int]
        ) -> tuple[int, int, str, str]:
    positions = [
        revision_order[commit] for commit in summary.get(
            "production_commits", summary["source_commits"]
        )
        if commit in revision_order
    ]
    lookup_mode = summary["configuration"].get("lookup_mode")
    lookup_rank = {
        "unsupported": 0,
        "off": 1,
        "disabled": 1,
        "on": 2,
        "enabled": 2,
    }.get(str(lookup_mode).casefold(), 3)
    return (
        min(positions) if positions else 1_000_000,
        lookup_rank,
        summary["binary_id"],
        summary["summary_id"],
    )


def _relative_change(candidate: Optional[float], baseline: Optional[float]) -> Optional[float]:
    if candidate is None or baseline is None or baseline == 0:
        return None
    return (candidate - baseline) / baseline


def _noise_fraction(
        baseline: Mapping[str, Any], candidate: Mapping[str, Any],
        gates: Mapping[str, Any]) -> float:
    model = gates["noise_model"]
    ratios = []
    for summary in (baseline, candidate):
        median = summary["elapsed"]["median"]
        mad = summary["elapsed"]["mad"]
        if median not in (None, 0) and mad is not None:
            ratios.append(mad / median)
    return max(
        float(model["numerical_floor_fraction"]),
        float(model["mad_multiplier"]) * max(ratios or [0.0]),
    )


def _classify_comparison(
        baseline: Mapping[str, Any], candidate: Mapping[str, Any],
        gates: Mapping[str, Any]) -> tuple[str, str, float]:
    noise = _noise_fraction(baseline, candidate, gates)
    performance = gates["performance"]
    elapsed_delta = _relative_change(
        candidate["elapsed"]["median"], baseline["elapsed"]["median"],
    )
    p95_delta = _relative_change(
        candidate["elapsed"]["p95_nearest_rank"],
        baseline["elapsed"]["p95_nearest_rank"],
    )
    if elapsed_delta is None:
        return "unverified due to missing mechanism evidence", "pending", noise
    median_regression = max(
        float(performance["maximum_median_regression_floor_fraction"]), noise,
    )
    p95_regression = max(
        float(performance["maximum_p95_regression_floor_fraction"]), 1.5 * noise,
    )
    regression = elapsed_delta >= median_regression or (
        p95_delta is not None and p95_delta >= p95_regression
    )
    groups = set(baseline["scenario_groups"]) | set(candidate["scenario_groups"])
    classification = gates["classification"]
    if (
            _summary_has_commit(baseline, COMMIT_9C)
            and _summary_has_commit(candidate, COMMIT_FINAL)):
        if regression:
            return "regression", "fail", noise
        if elapsed_delta <= -max(
                float(performance["material_change_floor_fraction"]), noise):
            return "demonstrated improvement", "pass", noise
        return "no material change", "pass", noise
    if (
            candidate["mechanism_evidence"]["required"]
            and not candidate["mechanism_evidence"]["verified"]):
        return "unverified due to missing mechanism evidence", "pending", noise
    if groups.intersection(classification["fallback_groups"]):
        if regression:
            return "regression", "fail", noise
        return "expected decline/fallback", "pass", noise
    if groups.intersection(classification["expected_improvement_groups"]):
        principal_gate_pair = (
            set(baseline["scenario_ids"]) == {"principal-with-sdn2-equality"}
            and set(candidate["scenario_ids"]) == {"principal-with-sdn2-equality"}
            and _summary_has_commit(baseline, COMMIT_FINAL)
            and _summary_has_commit(candidate, COMMIT_FINAL)
            and str(baseline["configuration"].get("lookup_mode")).casefold()
            in {"off", "disabled"}
            and str(candidate["configuration"].get("lookup_mode")).casefold()
            in {"on", "enabled"}
            and baseline["behavioral_runtime_identity_sha256"]
            == candidate["behavioral_runtime_identity_sha256"]
            and baseline["executable_sha256"] == candidate["executable_sha256"]
            and baseline.get("host_signature") == candidate.get("host_signature")
            and baseline["configuration"].get("attribute_mode") == "attrs-1.1"
            and candidate["configuration"].get("attribute_mode") == "attrs-1.1"
        )
        if principal_gate_pair:
            cpu_delta = _relative_change(
                candidate["server_cpu"]["median"], baseline["server_cpu"]["median"],
            )
            instruction_delta = _relative_change(
                candidate["instructions"]["median"], baseline["instructions"]["median"],
            )
            if cpu_delta is None or instruction_delta is None:
                return "unverified due to missing mechanism evidence", "pending", noise
            principal_spec = next(
                item for item in gates["gates"]
                if item["id"] == "principal-consumed-lookup-cost"
            )
            substantial = max(
                float(principal_spec["numerical_floor_fraction"]), noise,
            )
            if cpu_delta <= -substantial and instruction_delta <= -substantial:
                return "demonstrated improvement", "pass", noise
            if regression or cpu_delta >= median_regression or instruction_delta >= median_regression:
                return "regression", "fail", noise
            return "no material change", "fail", noise
        no_regression_control = (
            baseline.get("scale", {}).get("branch_count") == 15
            or baseline.get("scale", {}).get("candidate_count") == 0
            or "branch-scaling" in groups
            or groups.intersection({"family-discovery", "family-ranking"})
        )
        if no_regression_control:
            if regression:
                return "regression", "fail", noise
            if elapsed_delta <= -max(
                    float(performance["material_change_floor_fraction"]), noise):
                return "demonstrated improvement", "pass", noise
            return "no material change", "pass", noise
        improvement = max(
            float(performance["expected_improvement_floor_fraction"]), noise,
        )
        if elapsed_delta <= -improvement:
            return "demonstrated improvement", "pass", noise
        if regression:
            return "regression", "fail", noise
        return "no material change", "fail", noise
    if groups.intersection(classification["no_regression_groups"]):
        if regression:
            return "regression", "fail", noise
        if elapsed_delta <= -max(
                float(performance["material_change_floor_fraction"]), noise):
            return "demonstrated improvement", "pass", noise
        return "no material change", "pass", noise
    material = max(float(performance["material_change_floor_fraction"]), noise)
    if regression:
        return "regression", "fail", noise
    if elapsed_delta <= -material:
        return "demonstrated improvement", "pass", noise
    return "no material change", "pass", noise


def _applicable_gate_ids(
        baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> list[str]:
    groups = set(baseline["scenario_groups"]) | set(candidate["scenario_groups"])
    gate_ids = {"exact-result-parity", "no-new-result-or-admin-limit"}
    if "primary" in groups:
        gate_ids.add("principal-consumed-lookup-cost")
    if "branch-scaling" in groups:
        gate_ids.add("branch-count-scaling")
    if groups.intersection({
            "fallbacks", "decline-paths", "dynamic-list-correctness"}):
        gate_ids.add("decline-path-parity")
    if "sdn2-pair" in groups:
        gate_ids.add("sdn2-pair-attribution")
    if groups.intersection({"family-discovery", "family-ranking"}):
        gate_ids.add("selection-fix-retention")
    if groups.intersection({
            "presence-index", "fallbacks", "candidate-index-controls",
            "branch-order", "flat-family"}):
        gate_ids.add("adverse-and-small-shape-no-regression")
    if (
            _summary_has_commit(baseline, COMMIT_9C)
            and _summary_has_commit(candidate, COMMIT_FINAL)):
        gate_ids.add("final-success-path-no-regression")
    return sorted(gate_ids)


def build_comparisons(
        summaries: Sequence[Mapping[str, Any]], gates: Mapping[str, Any]
        ) -> list[Dict[str, Any]]:
    _, revision_order = _revision_maps()
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for summary in summaries:
        grouped.setdefault(_comparison_key(summary), []).append(summary)
    comparisons: list[Dict[str, Any]] = []
    for key in sorted(grouped):
        members = sorted(
            grouped[key], key=lambda item: _summary_revision_order(item, revision_order),
        )
        if len(members) < 2:
            continue
        pair_indexes = {(0, index) for index in range(1, len(members))}
        pair_indexes.update(
            (index - 1, index) for index in range(1, len(members))
        )
        declared_pairs = (
            (COMMIT_7C, COMMIT_09),
            (COMMIT_09, COMMIT_9C),
            (COMMIT_9C, COMMIT_FINAL),
        )
        for baseline_commit, candidate_commit in declared_pairs:
            baseline_indexes = [
                index for index, item in enumerate(members)
                if _summary_has_commit(item, baseline_commit)
            ]
            candidate_indexes = [
                index for index, item in enumerate(members)
                if _summary_has_commit(item, candidate_commit)
            ]
            if baseline_indexes and candidate_indexes:
                pair_indexes.add((baseline_indexes[0], candidate_indexes[0]))
        for baseline_index, candidate_index in sorted(pair_indexes):
            if baseline_index == candidate_index:
                continue
            baseline = members[baseline_index]
            candidate = members[candidate_index]
            baseline_known = any(
                commit in revision_order
                for commit in baseline.get(
                    "production_commits", baseline.get("source_commits", [])
                )
            )
            candidate_known = any(
                commit in revision_order
                for commit in candidate.get(
                    "production_commits", candidate.get("source_commits", [])
                )
            )
            same_artifact_toggle = (
                baseline.get("executable_sha256")
                == candidate.get("executable_sha256")
                and baseline.get("behavioral_runtime_identity_sha256")
                == candidate.get("behavioral_runtime_identity_sha256")
                and set(baseline.get("source_commits", [])).intersection(
                    candidate.get("source_commits", [])
                )
                and baseline["configuration"].get("lookup_mode")
                != candidate["configuration"].get("lookup_mode")
            )
            if not (
                    (baseline_known and candidate_known)
                    or same_artifact_toggle):
                # Unknown package revisions (for example Fedora stable) have
                # no truthful inferred direction.  They are emitted only by
                # an explicit directed screen/plan, never this generic table.
                continue
            if not baseline["release_ready"] or not candidate["release_ready"]:
                classification = "unverified due to missing mechanism evidence"
                gate_status = "pending"
                noise = _noise_fraction(baseline, candidate, gates)
            else:
                classification, gate_status, noise = _classify_comparison(
                    baseline, candidate, gates,
                )
            baseline_elapsed = baseline["elapsed"]["median"]
            candidate_elapsed = candidate["elapsed"]["median"]
            comparisons.append({
                "comparison_id": sha256_bytes(canonical_json_bytes({
                    "key": key,
                    "baseline_summary": baseline["summary_id"],
                    "candidate_summary": candidate["summary_id"],
                }))[:16],
                "scenario_ids": sorted(set(baseline["scenario_ids"]) | set(candidate["scenario_ids"])),
                "scenario_groups": sorted(set(baseline["scenario_groups"]) | set(candidate["scenario_groups"])),
                "configuration": _comparison_configuration(baseline),
                "baseline_configuration": baseline["configuration"],
                "candidate_configuration": candidate["configuration"],
                "baseline_lookup_mode": baseline["configuration"].get("lookup_mode"),
                "candidate_lookup_mode": candidate["configuration"].get("lookup_mode"),
                "baseline_binary_id": baseline["binary_id"],
                "baseline_runtime_identity_id": baseline["runtime_identity_id"],
                "baseline_runtime_closure_sha256": baseline[
                    "runtime_closure_sha256"
                ],
                "baseline_backend_runtime_closure_sha256": baseline[
                    "backend_runtime_closure_sha256"
                ],
                "baseline_behavioral_runtime_identity_sha256": baseline[
                    "behavioral_runtime_identity_sha256"
                ],
                "baseline_labels": baseline["commit_labels"],
                "candidate_binary_id": candidate["binary_id"],
                "candidate_runtime_identity_id": candidate["runtime_identity_id"],
                "candidate_runtime_closure_sha256": candidate[
                    "runtime_closure_sha256"
                ],
                "candidate_backend_runtime_closure_sha256": candidate[
                    "backend_runtime_closure_sha256"
                ],
                "candidate_behavioral_runtime_identity_sha256": candidate[
                    "behavioral_runtime_identity_sha256"
                ],
                "candidate_labels": candidate["commit_labels"],
                "baseline_n": baseline["n"],
                "candidate_n": candidate["n"],
                "elapsed_ratio_candidate_over_baseline": (
                    None if baseline_elapsed in (None, 0)
                    else candidate_elapsed / baseline_elapsed
                ),
                "elapsed_median_change_fraction": _relative_change(
                    candidate_elapsed, baseline_elapsed,
                ),
                "elapsed_p95_change_fraction": _relative_change(
                    candidate["elapsed"]["p95_nearest_rank"],
                    baseline["elapsed"]["p95_nearest_rank"],
                ),
                "server_etime_median_change_fraction": _relative_change(
                    candidate["server_etime"]["median"],
                    baseline["server_etime"]["median"],
                ),
                "server_cpu_median_change_fraction": _relative_change(
                    candidate["server_cpu"]["median"],
                    baseline["server_cpu"]["median"],
                ),
                "instructions_median_change_fraction": _relative_change(
                    candidate["instructions"]["median"],
                    baseline["instructions"]["median"],
                ),
                "noise_fraction": noise,
                "applicable_gate_ids": _applicable_gate_ids(baseline, candidate),
                "classification": classification,
                "gate_status": gate_status,
            })
    return comparisons


def _approximate_probe_passed(
        record: Mapping[str, Any], declared: Mapping[str, Any]) -> bool:
    exact = record.get("exact_result")
    server = record.get("server_result_evidence")
    expected_code = _canonical_result_code(declared.get("expected_result_code"))
    if not isinstance(exact, Mapping) or not isinstance(server, Mapping):
        return False
    return (
        record.get("evidence_status") == "observed"
        and record.get("operation_isolated") is True
        and record.get("result_line_isolated") is True
        and record.get("declared_probe") == declared
        and exact.get("evidence_status") == "observed"
        and exact.get("passed") is True
        and exact.get("expected_count") == declared.get("expected_count")
        and exact.get("returned_count") == declared.get("expected_count")
        and exact.get("expected_sha256") == declared.get("expected_sha256")
        and exact.get("returned_sha256") == declared.get("expected_sha256")
        and exact.get("exact_count_match") is True
        and exact.get("exact_sha256_match") is True
        and exact.get("exact_dns_match") is True
        and _canonical_result_code(exact.get("expected_ldap_result_code"))
        == expected_code
        and _canonical_result_code(exact.get("ldap_result_code"))
        == expected_code
        and server.get("evidence_status") == "observed"
        and server.get("passed") is True
        and _canonical_result_code(server.get("expected_ldap_result_code"))
        == expected_code
        and _canonical_result_code(server.get("actual_server_result_code"))
        == expected_code
    )


def _approximate_semantics_status(
        summary: Mapping[str, Any]) -> tuple[str, Optional[str], str]:
    contract = summary.get("cross_server_comparison")
    if not isinstance(contract, Mapping):
        return "missing", None, "cross-server semantic contract is absent"
    if contract.get("policy") != "requires-native-equivalence-preflight":
        return "missing", None, "semantic comparison policy is unsupported"
    semantic_contract = contract.get("semantic_contract")
    if not isinstance(semantic_contract, Mapping):
        return "missing", None, "semantic contract body is absent"
    contract_sha = contract.get("contract_sha256")
    if not _is_sha256(contract_sha):
        return "missing", None, "semantic contract hash is absent or invalid"
    if sha256_bytes(canonical_json_bytes(semantic_contract)) != contract_sha:
        return "missing", str(contract_sha), "semantic contract hash is invalid"
    required_probe_ids = contract.get("required_probe_ids")
    if (
            not isinstance(required_probe_ids, list) or not required_probe_ids
            or len(set(required_probe_ids)) != len(required_probe_ids)
            or any(not isinstance(value, str) or not value
                   for value in required_probe_ids)):
        return "missing", str(contract_sha), "required probe IDs are absent"
    declared_probes = contract.get("probes")
    if not isinstance(declared_probes, Mapping) or any(
            not isinstance(declared_probes.get(probe_id), Mapping)
            for probe_id in required_probe_ids):
        return "missing", str(contract_sha), "declared semantic probes are absent"
    evidence_records = summary["mechanism_evidence"].get(
        "approximate_semantics_evidence", []
    )
    if len(evidence_records) != 1:
        return (
            "missing", str(contract_sha),
            "one unambiguous native approximate-semantics record is required",
        )
    evidence = evidence_records[0]
    status = str(evidence.get("status", "")).casefold()
    if status in {"not-comparable", "incompatible", "different-semantics"}:
        return "incompatible", str(contract_sha), f"runtime status is {status}"
    if (
            status != "comparable"
            or evidence.get("evidence_status") != "observed"
            or evidence.get("policy") != contract.get("policy")
            or evidence.get("contract_sha256") != contract_sha
            or evidence.get("semantic_contract") != semantic_contract
            or evidence.get("required_probe_ids") != required_probe_ids):
        return (
            "missing", str(contract_sha),
            "runtime comparable status/contract hash is missing or mismatched",
        )
    raw_probes = _first(evidence, (
        ("probe_records",), ("probes",), ("required_probes",),
    ))
    probe_records: Dict[str, Mapping[str, Any]] = {}
    if isinstance(raw_probes, Mapping):
        for probe_id, record in raw_probes.items():
            if isinstance(record, Mapping):
                probe_records[str(probe_id)] = record
    elif isinstance(raw_probes, list):
        for record in raw_probes:
            if not isinstance(record, Mapping):
                continue
            probe_id = _first(record, (("probe_id",), ("id",), ("name",)))
            if isinstance(probe_id, str):
                probe_records[probe_id] = record
    invalid = [
        probe_id for probe_id in required_probe_ids
        if probe_id not in probe_records or not _approximate_probe_passed(
            probe_records[probe_id], declared_probes[probe_id],
        )
    ]
    if invalid or set(probe_records) != set(required_probe_ids):
        return (
            "missing", str(contract_sha),
            "required comparable-semantics probes lack exact isolated evidence: "
            + ", ".join(sorted(invalid or set(probe_records).symmetric_difference(
                required_probe_ids
            ))),
        )
    return "eligible", str(contract_sha), "native semantics probes are comparable"


def build_openldap_context(
        summaries: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    """Build contextual, explicitly non-acceptance cross-implementation rows."""
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for summary in summaries:
        configuration = dict(summary["configuration"])
        configuration.pop("server", None)
        configuration.pop("backend", None)
        configuration.pop("lookup_mode", None)
        key = sha256_bytes(canonical_json_bytes({
            "scenario_fingerprint": summary["scenario_fingerprint"],
            "configuration": configuration,
        }))
        grouped.setdefault(key, []).append(summary)
    context: list[Dict[str, Any]] = []
    for key in sorted(grouped):
        ds_rows = [
            item for item in grouped[key]
            if item["configuration"].get("server") == "389ds"
        ]
        openldap_rows = [
            item for item in grouped[key]
            if item["configuration"].get("server") == "openldap"
        ]
        for ds_summary in ds_rows:
            for openldap_summary in openldap_rows:
                approximate = (
                    isinstance(ds_summary.get("cross_server_comparison"), Mapping)
                    or isinstance(
                        openldap_summary.get("cross_server_comparison"), Mapping,
                    )
                    or "combined-approximate" in (
                        set(ds_summary["scenario_groups"])
                        | set(openldap_summary["scenario_groups"])
                    )
                )
                semantics_status = "not-required"
                semantics_reason = "not an approximate-semantics comparison"
                semantics_contract_sha: Optional[str] = None
                timing_eligible = True
                if approximate:
                    ds_semantics, ds_contract, ds_reason = (
                        _approximate_semantics_status(ds_summary)
                    )
                    ol_semantics, ol_contract, ol_reason = (
                        _approximate_semantics_status(openldap_summary)
                    )
                    semantics_contract_sha = (
                        ds_contract if ds_contract == ol_contract else None
                    )
                    if (
                            ds_semantics == "eligible"
                            and ol_semantics == "eligible"
                            and ds_contract == ol_contract):
                        semantics_status = "comparable"
                        semantics_reason = (
                            "both native bundles passed the same semantic contract"
                        )
                    elif (
                            "incompatible" in {ds_semantics, ol_semantics}
                            or (ds_contract is not None and ol_contract is not None
                                and ds_contract != ol_contract)):
                        semantics_status = "incompatible"
                        semantics_reason = f"389ds: {ds_reason}; OpenLDAP: {ol_reason}"
                        timing_eligible = False
                    else:
                        semantics_status = "pending"
                        semantics_reason = f"389ds: {ds_reason}; OpenLDAP: {ol_reason}"
                        timing_eligible = False

                if not ds_summary["release_ready"] or not openldap_summary["release_ready"]:
                    classification = "unverified due to missing mechanism evidence"
                    gate_status = "pending"
                    timing_eligible = False
                elif semantics_status == "pending":
                    classification = "unverified due to missing mechanism evidence"
                    gate_status = "pending"
                elif semantics_status == "incompatible":
                    classification = "unavoidable implementation difference"
                    gate_status = "contextual-only"
                else:
                    classification = "unavoidable implementation difference"
                    gate_status = "contextual-only"
                context.append({
                    "context_id": sha256_bytes(canonical_json_bytes({
                        "key": key,
                        "389ds": ds_summary["summary_id"],
                        "openldap": openldap_summary["summary_id"],
                    }))[:16],
                    "scenario_ids": sorted(
                        set(ds_summary["scenario_ids"])
                        | set(openldap_summary["scenario_ids"])
                    ),
                    "389ds_labels": ds_summary["commit_labels"],
                    "389ds_runtime_closure_sha256": ds_summary[
                        "runtime_closure_sha256"
                    ],
                    "389ds_backend_runtime_closure_sha256": ds_summary[
                        "backend_runtime_closure_sha256"
                    ],
                    "389ds_behavioral_runtime_identity_sha256": ds_summary[
                        "behavioral_runtime_identity_sha256"
                    ],
                    "openldap_labels": openldap_summary["commit_labels"],
                    "openldap_runtime_closure_sha256": openldap_summary[
                        "runtime_closure_sha256"
                    ],
                    "openldap_backend_runtime_closure_sha256": openldap_summary[
                        "backend_runtime_closure_sha256"
                    ],
                    "openldap_behavioral_runtime_identity_sha256": openldap_summary[
                        "behavioral_runtime_identity_sha256"
                    ],
                    "389ds_lookup_mode": ds_summary["configuration"].get("lookup_mode"),
                    "cross_server_timing_eligible": timing_eligible,
                    "approximate_semantics_status": semantics_status,
                    "approximate_semantics_reason": semantics_reason,
                    "semantic_contract_sha256": semantics_contract_sha,
                    "elapsed_ratio_389ds_over_openldap": (
                        None if not timing_eligible
                        or openldap_summary["elapsed"]["median"] in (None, 0)
                        else ds_summary["elapsed"]["median"]
                        / openldap_summary["elapsed"]["median"]
                    ),
                    "server_cpu_ratio_389ds_over_openldap": (
                        None if not timing_eligible
                        or openldap_summary["server_cpu"]["median"] in (None, 0)
                        or ds_summary["server_cpu"]["median"] is None
                        else ds_summary["server_cpu"]["median"]
                        / openldap_summary["server_cpu"]["median"]
                    ),
                    "instructions_ratio_389ds_over_openldap": (
                        None if not timing_eligible
                        or openldap_summary["instructions"]["median"] in (None, 0)
                        or ds_summary["instructions"]["median"] is None
                        else ds_summary["instructions"]["median"]
                        / openldap_summary["instructions"]["median"]
                    ),
                    "classification": classification,
                    "gate_status": gate_status,
                })
    return context


def build_scaling_tables(
        summaries: Sequence[Mapping[str, Any]], gates: Mapping[str, Any]
        ) -> list[Dict[str, Any]]:
    dimensions = gates["scaling"]["dimensions"]
    minimum_points = int(gates["scaling"]["minimum_distinct_points"])
    preferred_groups = {
        "candidate_count": "candidate-scaling",
        "branch_count": "branch-scaling",
        "values_per_entry": "multivalue-scaling",
        "dn_mode": "dn-normalization",
    }
    tables: list[Dict[str, Any]] = []
    for dimension in dimensions:
        grouped: Dict[str, list[Mapping[str, Any]]] = {}
        for summary in summaries:
            value = summary["scale"].get(dimension)
            if value is None or isinstance(value, (dict, list)):
                continue
            preferred = preferred_groups[dimension]
            family = preferred if preferred in summary["scenario_groups"] else ",".join(
                summary["scenario_groups"]
            )
            key = sha256_bytes(canonical_json_bytes({
                "dimension": dimension,
                "family": family,
                "binary": summary["executable_sha256"],
                "behavioral_runtime_identity_sha256": summary[
                    "behavioral_runtime_identity_sha256"
                ],
                "configuration": summary["configuration"],
                "curve_discriminator": summary.get("scale_curve", {}).get(
                    dimension, {}
                ),
            }))
            grouped.setdefault(key, []).append(summary)
        for key in sorted(grouped):
            members = grouped[key]
            values = {json.dumps(item["scale"][dimension], sort_keys=True) for item in members}
            if len(values) < minimum_points:
                continue
            if len(values) != len(members):
                raise MergeError(
                    f"scaling curve {key[:16]} has duplicate {dimension} points"
                )
            first = members[0]
            tables.append({
                "scaling_id": key[:16],
                "dimension": dimension,
                "binary_id": first["binary_id"],
                "runtime_identity_id": first["runtime_identity_id"],
                "runtime_closure_sha256": first[
                    "runtime_closure_sha256"
                ],
                "backend_runtime_closure_sha256": first[
                    "backend_runtime_closure_sha256"
                ],
                "behavioral_runtime_identity_sha256": first[
                    "behavioral_runtime_identity_sha256"
                ],
                "commit_labels": first["commit_labels"],
                "scenario_group": preferred_groups[dimension]
                    if preferred_groups[dimension] in first["scenario_groups"]
                    else ",".join(first["scenario_groups"]),
                "configuration": first["configuration"],
                "curve_discriminator": first.get("scale_curve", {}).get(
                    dimension, {}
                ),
                "points": sorted(({
                    "value": item["scale"][dimension],
                    "scenario_ids": item["scenario_ids"],
                    "n": item["n"],
                    "elapsed_median_seconds": item["elapsed"]["median"],
                    "elapsed_p95_seconds": item["elapsed"]["p95_nearest_rank"],
                    "server_etime_median_seconds": item["server_etime"]["median"],
                    "server_cpu_median_seconds": item["server_cpu"]["median"],
                    "instructions_median": item["instructions"]["median"],
                } for item in members), key=lambda point: (
                    0, float(point["value"])
                ) if isinstance(point["value"], (int, float)) else (
                    1, str(point["value"])
                )),
            })
    return tables


def _gate_instance(
        instance_id: str, status: str, classification: str, reason: str, *,
        evidence: Sequence[str] = (), computed: Optional[Mapping[str, Any]] = None,
        required: bool = True) -> Dict[str, Any]:
    return {
        "instance_id": instance_id,
        "required": required,
        "status": status,
        "classification": classification,
        "reason": reason,
        "evidence_refs": sorted(set(str(value) for value in evidence)),
        "computed": dict(computed or {}),
    }


def _aggregate_gate(
        gate_id: str, instances: Sequence[Mapping[str, Any]],
        pass_classification: str = "no material change") -> Dict[str, Any]:
    required = [item for item in instances if item.get("required", True)]
    if any(item["status"] == "fail" for item in required):
        status = "fail"
        classification = "regression"
    elif not required or any(item["status"] == "pending" for item in required):
        status = "pending"
        classification = "unverified due to missing mechanism evidence"
    else:
        status = "pass"
        classifications = {str(item["classification"]) for item in required}
        classification = (
            next(iter(classifications)) if len(classifications) == 1
            else pass_classification
        )
    return {
        "gate_id": gate_id,
        "status": status,
        "classification": classification,
        "required_instance_count": len(required),
        "pass_count": sum(item["status"] == "pass" for item in required),
        "fail_count": sum(item["status"] == "fail" for item in required),
        "pending_count": sum(item["status"] == "pending" for item in required),
        "authoritative": True,
        "instances": list(instances),
    }


def _summary_has_commit(summary: Mapping[str, Any], commit: str) -> bool:
    expected = production_equivalent_revision(commit)
    declared = summary.get("production_commits")
    if isinstance(declared, (list, tuple, set, frozenset)):
        return expected in {
            production_equivalent_revision(str(value)) for value in declared
        }
    return expected in {
        production_equivalent_revision(str(value))
        for value in summary.get("source_commits", [])
    }


def _summary_has_scenario(summary: Mapping[str, Any], scenario_id: str) -> bool:
    return set(summary.get("scenario_ids", [])) == {scenario_id}


def _toggle_pair(
        summaries: Sequence[Mapping[str, Any]], scenario_id: str,
        commit: str = COMMIT_FINAL) -> tuple[
            Optional[Mapping[str, Any]], Optional[Mapping[str, Any]], str]:
    candidates = [
        summary for summary in summaries
        if _summary_has_scenario(summary, scenario_id)
        and _summary_has_commit(summary, commit)
        and summary["configuration"].get("attribute_mode") == "attrs-1.1"
    ]
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for summary in candidates:
        key = sha256_bytes(canonical_json_bytes({
            "scenario": summary["scenario_fingerprint"],
            "executable_sha256": summary["executable_sha256"],
            "behavioral_identity": summary[
                "behavioral_runtime_identity_sha256"
            ],
            "installed_package_closure_sha256": summary.get(
                "installed_package_closure_sha256"
            ),
            "host_signature": summary.get("host_signature"),
            "configuration_except_lookup": _comparison_configuration(summary),
        }))
        grouped.setdefault(key, []).append(summary)
    pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for members in grouped.values():
        off = [
            item for item in members
            if str(item["configuration"].get("lookup_mode")).casefold()
            in {"off", "disabled"}
        ]
        on = [
            item for item in members
            if str(item["configuration"].get("lookup_mode")).casefold()
            in {"on", "enabled"}
        ]
        if len(off) == 1 and len(on) == 1:
            pairs.append((off[0], on[0]))
    if len(pairs) != 1:
        return None, None, (
            f"required unique final lookup-off/on pair is absent or ambiguous "
            f"({len(pairs)} resolved pairs)"
        )
    return pairs[0][0], pairs[0][1], ""


def _revision_pair(
        summaries: Sequence[Mapping[str, Any]], scenario_id: str,
        baseline_commit: str, candidate_commit: str,
        lookup_mode: Optional[str] = None) -> tuple[
            Optional[Mapping[str, Any]], Optional[Mapping[str, Any]], str]:
    candidates = [
        summary for summary in summaries
        if _summary_has_scenario(summary, scenario_id)
        and summary["configuration"].get("attribute_mode") == "attrs-1.1"
        and (lookup_mode is None or str(
            summary["configuration"].get("lookup_mode")
        ).casefold() == lookup_mode.casefold())
    ]
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for summary in candidates:
        key = sha256_bytes(canonical_json_bytes({
            "scenario": summary["scenario_fingerprint"],
            "host_signature": summary.get("host_signature"),
            "configuration": summary["configuration"],
        }))
        grouped.setdefault(key, []).append(summary)
    pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for members in grouped.values():
        baseline = [
            item for item in members if _summary_has_commit(item, baseline_commit)
        ]
        candidate = [
            item for item in members if _summary_has_commit(item, candidate_commit)
        ]
        if len(baseline) == 1 and len(candidate) == 1:
            pairs.append((baseline[0], candidate[0]))
    if len(pairs) != 1:
        return None, None, (
            f"required revision pair is absent or ambiguous ({len(pairs)} resolved pairs)"
        )
    return pairs[0][0], pairs[0][1], ""


def _metric_noise(
        baseline: Mapping[str, Any], candidate: Mapping[str, Any],
        metric: str, gates: Mapping[str, Any]) -> float:
    ratios: list[float] = []
    for summary in (baseline, candidate):
        values = summary[metric]
        median = values.get("median")
        mad = values.get("mad")
        if median not in (None, 0) and mad is not None:
            ratios.append(float(mad) / float(median))
    return max(
        float(gates["noise_model"]["numerical_floor_fraction"]),
        float(gates["noise_model"]["mad_multiplier"]) * max(ratios or [0.0]),
    )


def _no_regression_instance(
        instance_id: str, baseline: Mapping[str, Any],
        candidate: Mapping[str, Any], gates: Mapping[str, Any], *,
        pass_classification: str = "no material change",
        median_floor: Optional[float] = None,
        p95_floor: Optional[float] = None) -> Dict[str, Any]:
    evidence = [baseline["summary_id"], candidate["summary_id"]]
    if not baseline.get("release_ready") or not candidate.get("release_ready"):
        return _gate_instance(
            instance_id, "pending",
            "unverified due to missing mechanism evidence",
            "one or both timing strata have fewer than the required native repeats",
            evidence=evidence,
        )
    noise = _metric_noise(baseline, candidate, "elapsed", gates)
    median_delta = _relative_change(
        candidate["elapsed"]["median"], baseline["elapsed"]["median"],
    )
    p95_delta = _relative_change(
        candidate["elapsed"]["p95_nearest_rank"],
        baseline["elapsed"]["p95_nearest_rank"],
    )
    if median_delta is None or p95_delta is None:
        return _gate_instance(
            instance_id, "pending",
            "unverified due to missing mechanism evidence",
            "median or p95 evidence is incomplete", evidence=evidence,
        )
    if median_floor is None:
        median_floor = float(
            gates["performance"]["maximum_median_regression_floor_fraction"]
        )
    if p95_floor is None:
        p95_floor = float(
            gates["performance"]["maximum_p95_regression_floor_fraction"]
        )
    median_limit = max(float(median_floor), noise)
    p95_limit = max(float(p95_floor), 1.5 * noise)
    computed = {
        "elapsed_median_change_fraction": median_delta,
        "elapsed_p95_change_fraction": p95_delta,
        "noise_fraction": noise,
        "median_regression_limit": median_limit,
        "p95_regression_limit": p95_limit,
    }
    if median_delta >= median_limit or p95_delta >= p95_limit:
        return _gate_instance(
            instance_id, "fail", "regression",
            "median or p95 regression reaches the predeclared limit",
            evidence=evidence, computed=computed,
        )
    classification = (
        "demonstrated improvement"
        if median_delta <= -max(
            float(gates["performance"]["material_change_floor_fraction"]),
            noise,
        ) else pass_classification
    )
    return _gate_instance(
        instance_id, "pass", classification,
        "median and p95 remain within the predeclared no-regression limits",
        evidence=evidence, computed=computed,
    )


def _mechanism_expectation(
        scenario: Mapping[str, Any], summary: Mapping[str, Any]
        ) -> tuple[str, str]:
    expected = scenario.get("expected_diagnostics", {})
    expected = expected if isinstance(expected, Mapping) else {}
    evidence = summary["mechanism_evidence"]
    missing: list[str] = []
    failures: list[str] = []
    lookup = expected.get("or_lookup", {})
    lookup = lookup if isinstance(lookup, Mapping) else {}
    lookup_expectation = str(lookup.get("expectation", "not-applicable"))
    constructed = evidence.get("lookup_constructed_values", [])
    if lookup_expectation == "required-when-lookup-on" and str(
            summary["configuration"].get("lookup_mode")).casefold() in {
                "on", "enabled"}:
        if not constructed:
            missing.append("lookup construction")
        elif constructed != [True]:
            failures.append("required lookup was not consistently constructed")
        largest = lookup.get("largest_family")
        if largest is not None and largest not in evidence.get(
                "lookup_largest_families", []):
            missing.append(f"largest-family diagnostic {largest}")
    elif lookup_expectation.startswith("forbidden"):
        if not constructed:
            missing.append("forbidden-lookup non-engagement diagnostic")
        elif constructed != [False]:
            failures.append("forbidden lookup construction was observed")

    bounded = expected.get("bounded_read", {})
    bounded = bounded if isinstance(bounded, Mapping) else {}
    cap_expectation = str(bounded.get("expectation", "not-applicable"))
    cap_values = evidence.get("cap_path_observed_values", [])
    if cap_expectation in {"required", "required-on-bounded-feature-build"}:
        if not cap_values:
            missing.append("bounded-read engagement diagnostic")
        elif cap_values != [True]:
            failures.append("required bounded-read engagement was absent")
    elif cap_expectation.startswith(("forbidden", "must-not-engage", "absent")):
        if not cap_values:
            missing.append("bounded-read non-engagement diagnostic")
        elif cap_values != [False]:
            failures.append("forbidden bounded-read engagement was observed")
    if failures:
        return "fail", "; ".join(failures)
    if missing:
        return "pending", "; ".join(missing)
    return "pass", "declared mechanism expectations are evidenced"


def _profile_proved(summary: Mapping[str, Any]) -> bool:
    evidence = summary["mechanism_evidence"]
    return (
        bool(evidence.get("profile_sha256s"))
        and {
            str(value).casefold()
            for value in evidence.get("profile_statuses", [])
        } == {"observed"}
    )


def _dynamic_control_exact_ready(
        control: Mapping[str, Any], *, historical: bool = False) -> bool:
    operations = [
        operation for operation in control.get("exact_operations", [])
        if operation.get("operation_kind") == "dynamic-list-control"
    ]
    allowed_statuses = {"pass", "fail"} if historical else {"pass"}
    return (
        len(operations) == 4
        and all(operation.get("status") in allowed_statuses for operation in operations)
        and control.get("complete") is True
        and control.get("dynamic_cap_status") == "pass"
    )


def _sdn2_index_read_signature(mechanism: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Return structural STAT-index evidence without treating duration as shape."""
    ignored = {
        "duration_seconds", "elapsed_seconds", "etime_seconds",
        "duration_ns", "elapsed_ns",
    }
    return sorted((
        {
            str(key): value for key, value in read.items()
            if str(key) not in ignored
        }
        for read in mechanism.get("stat_index_reads", [])
        if isinstance(read, Mapping)
    ), key=lambda read: canonical_json_bytes(read))


def _find_single_summary(
        summaries: Sequence[Mapping[str, Any]], scenario_id: str, commit: str,
        lookup_mode: str = "on") -> tuple[Optional[Mapping[str, Any]], str]:
    matches = [
        summary for summary in summaries
        if _summary_has_scenario(summary, scenario_id)
        and _summary_has_commit(summary, commit)
        and summary["configuration"].get("attribute_mode") == "attrs-1.1"
        and str(summary["configuration"].get("lookup_mode")).casefold()
        == lookup_mode.casefold()
    ]
    if len(matches) != 1:
        return None, f"required unique summary is absent or ambiguous ({len(matches)})"
    return matches[0], ""


def _planned_operation_instances(
        bundles: Sequence[Bundle], rows: Sequence[Mapping[str, Any]],
        controls: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    """Account for every row/control implied by a completed runner schedule."""
    instances: list[Dict[str, Any]] = []
    for bundle in bundles:
        selected = bundle.run_manifest.get("selected_scenarios")
        repeat_count = bundle.run_manifest.get("repeat_count")
        warmup_count = bundle.run_manifest.get("warmup_count")
        if (
                not isinstance(selected, list) or not selected
                or len(set(map(str, selected))) != len(selected)
                or any(str(value) not in bundle.workload.get("scenarios", {})
                       for value in selected)
                or not isinstance(repeat_count, int)
                or isinstance(repeat_count, bool) or repeat_count < 1
                or not isinstance(warmup_count, int)
                or isinstance(warmup_count, bool) or warmup_count < 0):
            instances.append(_gate_instance(
                f"plan:{bundle.run_id}", "pending",
                "unverified due to missing mechanism evidence",
                "selected_scenarios/repeat_count/warmup_count schedule is incomplete",
            ))
            continue
        run_rows = [row for row in rows if row["run_id"] == bundle.run_id]
        run_controls = [
            item for item in controls if item["run_id"] == bundle.run_id
        ]
        controls_by_scenario = {
            scenario_id: [
                item for item in run_controls
                if str(item["scenario_id"]) == scenario_id
            ]
            for scenario_id in {str(item["scenario_id"]) for item in run_controls}
        }
        failures: list[str] = []
        missing: list[str] = []
        evidence: list[str] = []
        selected_ids = [str(value) for value in selected]
        unexpected_rows = [
            str(row["row_id"]) for row in run_rows
            if row["scenario_id"] not in selected_ids
        ]
        unexpected_controls = [
            str(item["control_id"]) for item in run_controls
            if item["scenario_id"] not in selected_ids
        ]
        if unexpected_rows or unexpected_controls:
            failures.append("unselected scenarios produced rows or controls")
            evidence.extend(unexpected_rows + unexpected_controls)
        for scenario_id in selected_ids:
            groups = set(_scenario_groups(bundle.workload, scenario_id))
            dynamic = "dynamic-list-correctness" in groups
            matching_controls = controls_by_scenario.get(scenario_id, [])
            control = matching_controls[0] if len(matching_controls) == 1 else None
            if not matching_controls:
                missing.append(f"{scenario_id}: correctness control")
            elif len(matching_controls) != 1:
                failures.append(
                    f"{scenario_id}: {len(matching_controls)} correctness controls"
                )
                evidence.extend(
                    str(item["control_id"]) for item in matching_controls
                )
            else:
                evidence.append(str(control["control_id"]))
            scenario_rows = [
                row for row in run_rows if row["scenario_id"] == scenario_id
            ]
            if any(
                    row["phase"] not in {"warmup", "measured"}
                    for row in scenario_rows):
                failures.append(f"{scenario_id}: unexpected row phase")
            historical = bool(
                control and control.get("supporting_historical_failure")
            )
            if dynamic or historical:
                if scenario_rows:
                    failures.append(
                        f"{scenario_id}: untimed control unexpectedly has raw rows"
                    )
                    evidence.extend(str(row["row_id"]) for row in scenario_rows)
                if dynamic and control is not None:
                    dynamic_operations = [
                        operation for operation in control.get("exact_operations", [])
                        if operation.get("operation_kind") == "dynamic-list-control"
                    ]
                    if len(dynamic_operations) != 4:
                        missing.append(
                            f"{scenario_id}: four dynamic-list operations"
                        )
                continue
            expected_variants = {"attrs-1.1"}
            if scenario_id in {
                    "principal-with-sdn2-equality",
                    "principal-without-sdn2-equality"}:
                expected_variants.add("normal-attributes")
            observed_variants = {
                str(row["configuration"].get("attribute_mode"))
                for row in scenario_rows
            }
            if observed_variants.difference(expected_variants):
                failures.append(f"{scenario_id}: unexpected attribute variant")
            for variant in sorted(expected_variants):
                variant_rows = [
                    row for row in scenario_rows
                    if row["configuration"].get("attribute_mode") == variant
                ]
                for phase, expected_count in (
                        ("warmup", warmup_count),
                        ("measured", repeat_count)):
                    actual = sum(row["phase"] == phase for row in variant_rows)
                    if actual != expected_count:
                        missing.append(
                            f"{scenario_id}/{variant}/{phase}: "
                            f"{actual}/{expected_count} rows"
                        )
            if control is not None:
                kinds = [
                    operation.get("operation_kind")
                    for operation in control.get("exact_operations", [])
                ]
                for kind in ("mechanism-preflight", "mechanism-postflight"):
                    if kinds.count(kind) != 1:
                        missing.append(f"{scenario_id}: {kind}")
        if failures:
            instances.append(_gate_instance(
                f"plan:{bundle.run_id}", "fail", "regression",
                "; ".join(failures), evidence=evidence,
            ))
        elif missing:
            instances.append(_gate_instance(
                f"plan:{bundle.run_id}", "pending",
                "unverified due to missing mechanism evidence",
                "; ".join(missing), evidence=evidence,
            ))
        else:
            instances.append(_gate_instance(
                f"plan:{bundle.run_id}", "pass", "no material change",
                "every selected row/control/phase/attribute variant is accounted for",
                evidence=evidence,
            ))
    return instances


def build_acceptance_gate_results(
        bundles: Sequence[Bundle], rows: Sequence[Mapping[str, Any]],
        perf_batches: Sequence[Mapping[str, Any]],
        correctness_controls: Sequence[Mapping[str, Any]],
        summaries: Sequence[Mapping[str, Any]], gates: Mapping[str, Any]
        ) -> list[Dict[str, Any]]:
    """Evaluate the ten predeclared gates independently of descriptive pairs."""
    minimum = int(gates["reporting"]["minimum_native_measured_repeats"])
    minimum_instruction_batches = int(gates["reporting"].get(
        "minimum_independent_instruction_batches", minimum,
    ))
    gate_specs = {
        str(item["id"]): item for item in gates.get("gates", [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    workload = bundles[0].workload
    workload_scenarios = workload.get("scenarios", {})
    results: list[Dict[str, Any]] = []

    # 1. Exact result parity, including untimed dynamic-list controls.
    exact_instances: list[Dict[str, Any]] = []
    bad_rows = [row for row in rows if not row["correctness"]["passed"]]
    incomplete_rows = [row for row in rows if not row["correctness"]["complete"]]
    authoritative_controls = [
        item for item in correctness_controls
        if not item.get("supporting_historical_failure")
    ]
    bad_controls = [
        item for item in authoritative_controls
        if not item["passed"]
        and (item.get("complete") is True or bool(item.get("problems")))
    ]
    incomplete_controls = [
        item for item in authoritative_controls if not item["complete"]
    ]
    exact_control_operations = [
        operation for item in authoritative_controls
        for operation in item.get("exact_operations", [])
    ]
    failed_control_operations = [
        operation for operation in exact_control_operations
        if operation["status"] == "fail"
    ]
    pending_control_operations = [
        operation for operation in exact_control_operations
        if operation["status"] == "pending"
    ]
    if bad_rows or bad_controls or failed_control_operations:
        exact_instances.append(_gate_instance(
            "all-planned-operations", "fail", "regression",
            "one or more result rows/controls disagree with the workload oracle",
            evidence=[
                *[row["row_id"] for row in bad_rows],
                *[item["control_id"] for item in bad_controls],
                *[item["operation_id"] for item in failed_control_operations],
            ],
        ))
    elif (
            incomplete_rows or incomplete_controls or pending_control_operations
            or (not rows and not authoritative_controls)):
        exact_instances.append(_gate_instance(
            "all-planned-operations", "pending",
            "unverified due to missing mechanism evidence",
            "planned exact-result evidence is incomplete or absent",
            evidence=[
                *[row["row_id"] for row in incomplete_rows],
                *[item["control_id"] for item in incomplete_controls],
                *[item["operation_id"] for item in pending_control_operations],
            ],
        ))
    else:
        exact_instances.append(_gate_instance(
            "all-planned-operations", "pass", "no material change",
            "all supplied/planned rows and untimed controls match their exact oracle",
            evidence=[
                *[row["row_id"] for row in rows],
                *[item["control_id"] for item in authoritative_controls],
            ],
        ))
    exact_instances.extend(_planned_operation_instances(
        bundles, rows, correctness_controls,
    ))
    results.append(_aggregate_gate("exact-result-parity", exact_instances))

    # 2. Paired result/admin-limit behavior. Exact-oracle matches on both sides
    # imply result-code parity without trusting generic timing classification.
    result_pair_instances: list[Dict[str, Any]] = []
    branch_gate_contract = gate_specs["branch-count-scaling"]
    required_toggle_scenarios = {
        str(gate_specs["principal-consumed-lookup-cost"]["pair"]["scenario"]),
        *map(str, gate_specs[
            "adverse-and-small-shape-no-regression"
        ]["required_scenarios"]),
        *(
            f"branch-count-{count}-{distribution}"
            for count in branch_gate_contract["required_branch_counts"]
            for distribution in branch_gate_contract["required_distributions"]
        ),
    }
    required_decline_groups = set(
        gate_specs["decline-path-parity"]["required_groups"]
    )
    required_toggle_scenarios.update({
        str(scenario_id)
        for group, members in workload.get("scenario_groups", {}).items()
        if group in required_decline_groups and isinstance(members, list)
        for scenario_id in members
        if "dynamic-list-correctness" not in _scenario_groups(
            workload, str(scenario_id)
        )
    })
    for scenario_id in sorted(required_toggle_scenarios):
        baseline, candidate, reason = _toggle_pair(summaries, scenario_id)
        if baseline is None or candidate is None:
            result_pair_instances.append(_gate_instance(
                f"final-toggle:{scenario_id}", "pending",
                "unverified due to missing mechanism evidence", reason,
            ))
        else:
            result_pair_instances.append(_gate_instance(
                f"final-toggle:{scenario_id}", "pass", "no material change",
                "both paired configurations exactly match the same workload oracle",
                evidence=[baseline["summary_id"], candidate["summary_id"]],
            ))

    for scenario_id in gate_specs[
            "final-success-path-no-regression"]["required_scenarios"]:
        baseline, candidate, reason = _revision_pair(
            summaries, str(scenario_id), COMMIT_9C, COMMIT_FINAL, "on",
        )
        if baseline is None or candidate is None:
            result_pair_instances.append(_gate_instance(
                f"revision-result:{scenario_id}", "pending",
                "unverified due to missing mechanism evidence", reason,
            ))
        else:
            result_pair_instances.append(_gate_instance(
                f"revision-result:{scenario_id}", "pass", "no material change",
                "both revisions exactly match the same workload oracle",
                evidence=[baseline["summary_id"], candidate["summary_id"]],
            ))
    dynamic_ids = (
        "dynamic-list-lookthrough-finite",
        "dynamic-list-lookthrough-unlimited",
    )
    for scenario_id in dynamic_ids:
        if scenario_id not in workload_scenarios:
            continue
        controls_by_commit = {
            commit: [
                item for item in correctness_controls
                if item["scenario_id"] == scenario_id
                and _summary_has_commit(item, commit)
            ]
            for commit in (COMMIT_7C, COMMIT_038, COMMIT_FINAL)
        }
        if any(len(items) != 1 for items in controls_by_commit.values()):
            result_pair_instances.append(_gate_instance(
                f"dynamic:{scenario_id}", "pending",
                "unverified due to missing mechanism evidence",
                "parent, 038b8f58, and final dynamic controls are all required",
                evidence=[
                    item["control_id"]
                    for items in controls_by_commit.values() for item in items
                ],
            ))
        else:
            parent = controls_by_commit[COMMIT_7C][0]
            fixed = controls_by_commit[COMMIT_038][0]
            final = controls_by_commit[COMMIT_FINAL][0]
            evidence = [
                parent["control_id"], fixed["control_id"], final["control_id"],
            ]
            if (
                    not fixed["passed"]
                    or not final["passed"]
                    or not fixed["oracle_passed"]
                    or not final["oracle_passed"]
                    or fixed["ldap_adminlimit_exceeded"] is not False
                    or final["ldap_adminlimit_exceeded"] is not False
                    or not _dynamic_control_exact_ready(fixed)
                    or not _dynamic_control_exact_ready(final)):
                result_pair_instances.append(_gate_instance(
                    f"dynamic:{scenario_id}", "fail", "regression",
                    "038b8f58 or final failed exact/no-admin-limit validation",
                    evidence=evidence,
                ))
            elif (
                    parent.get("supporting_historical_failure") is True
                    and parent.get("passed") is True
                    and _dynamic_control_exact_ready(parent, historical=True)):
                result_pair_instances.append(_gate_instance(
                    f"dynamic:{scenario_id}", "pass", "demonstrated improvement",
                    "the parent failure is observed and both fixed revisions pass exactly",
                    evidence=evidence,
                    computed={"historical_parent_failure_observed": True},
                ))
            else:
                result_pair_instances.append(_gate_instance(
                    f"dynamic:{scenario_id}", "pending",
                    "unverified due to missing mechanism evidence",
                    "the supplied parent does not prove the expected historical failure",
                    evidence=evidence,
                ))
    if not result_pair_instances:
        result_pair_instances.append(_gate_instance(
            "paired-correctness-controls", "pending",
            "unverified due to missing mechanism evidence",
            "no required paired correctness control is resolvable",
        ))
    results.append(_aggregate_gate(
        "no-new-result-or-admin-limit", result_pair_instances,
    ))

    # 3. Principal consumed lookup CPU/instruction cost.
    principal_instances: list[Dict[str, Any]] = []
    baseline, candidate, reason = _toggle_pair(
        summaries, "principal-with-sdn2-equality",
    )
    if baseline is None or candidate is None:
        principal_instances.append(_gate_instance(
            "principal-final-off-on", "pending",
            "unverified due to missing mechanism evidence", reason,
        ))
    else:
        evidence = [baseline["summary_id"], candidate["summary_id"]]
        principal_config_ok = all(
            summary["configuration"].get("server") == "389ds"
            and summary["configuration"].get("bind_class") == "administrative"
            and summary["configuration"].get("cache_policy") == "warm"
            and summary["configuration"].get("index_variant")
            == "baseline-no-presence"
            and summary.get("scale", {}).get("candidate_count") == 612
            for summary in (baseline, candidate)
        )
        principal_spec = gate_specs["principal-consumed-lookup-cost"]
        minimum_cpu = int(principal_spec.get(
            "minimum_independent_cpu_samples", minimum,
        ))
        minimum_instructions = int(principal_spec.get(
            "minimum_independent_instruction_batches",
            minimum_instruction_batches,
        ))
        metrics_ready = all(
            summary["server_cpu"]["n"] >= minimum_cpu
            and summary["instructions"]["n"] >= minimum_instructions
            for summary in (baseline, candidate)
        )
        mechanism = candidate["mechanism_evidence"]
        statuses = {
            str(value).casefold()
            for value in mechanism.get("lookup_consumption_statuses", [])
        }
        construction_ok = (
            baseline["mechanism_evidence"].get("lookup_constructed_values") == [False]
            and mechanism.get("lookup_constructed_values") == [True]
            and mechanism.get("lookup_largest_families") == [355]
        )
        if not principal_config_ok:
            principal_instances.append(_gate_instance(
                "principal-final-off-on", "pending",
                "unverified due to missing mechanism evidence",
                "principal pair is not the required administrative warm-cache baseline-index stratum",
                evidence=evidence,
            ))
        elif not metrics_ready:
            principal_instances.append(_gate_instance(
                "principal-final-off-on", "pending",
                "unverified due to missing mechanism evidence",
                f"CPU requires {minimum_cpu} samples and instructions require "
                f"{minimum_instructions} independent batches",
                evidence=evidence,
            ))
        elif not construction_ok or not _profile_proved(candidate):
            principal_instances.append(_gate_instance(
                "principal-final-off-on", "pending",
                "unverified due to missing mechanism evidence",
                "lookup construction/largest-family and hashed profile evidence are required",
                evidence=evidence,
            ))
        elif statuses != {"consumed"}:
            principal_instances.append(_gate_instance(
                "principal-final-off-on", "pending",
                "unverified due to missing mechanism evidence",
                "the principal gate requires an exclusively consumed lookup profile; "
                f"observed statuses are {sorted(statuses)}",
                evidence=evidence,
            ))
        else:
            cpu_noise = _metric_noise(baseline, candidate, "server_cpu", gates)
            insn_noise = _metric_noise(baseline, candidate, "instructions", gates)
            cpu_delta = _relative_change(
                candidate["server_cpu"]["median"], baseline["server_cpu"]["median"],
            )
            insn_delta = _relative_change(
                candidate["instructions"]["median"], baseline["instructions"]["median"],
            )
            numerical_floor = float(principal_spec["numerical_floor_fraction"])
            computed = {
                "cpu_reduction_fraction": None if cpu_delta is None else -cpu_delta,
                "instruction_reduction_fraction": None if insn_delta is None else -insn_delta,
                "cpu_required_reduction": max(numerical_floor, cpu_noise),
                "instruction_required_reduction": max(
                    numerical_floor, insn_noise,
                ),
            }
            passed = (
                cpu_delta is not None and insn_delta is not None
                and -cpu_delta >= max(numerical_floor, cpu_noise)
                and -insn_delta >= max(numerical_floor, insn_noise)
            )
            principal_instances.append(_gate_instance(
                "principal-final-off-on", "pass" if passed else "fail",
                "demonstrated improvement" if passed else "regression",
                "both reductions meet the consumed-lookup floor" if passed else
                "a consumed-lookup CPU or instruction reduction misses its floor",
                evidence=evidence, computed=computed,
            ))
    results.append(_aggregate_gate(
        "principal-consumed-lookup-cost", principal_instances,
        "demonstrated improvement",
    ))

    # 4. Endpoint branch-count slopes, kept separate by distribution.
    branch_instances: list[Dict[str, Any]] = []
    branch_spec = gate_specs["branch-count-scaling"]
    branch_counts = tuple(int(value) for value in branch_spec[
        "required_branch_counts"
    ])
    branch_endpoints = tuple(int(value) for value in branch_spec[
        "slope_endpoints"
    ])
    low_endpoint, high_endpoint = branch_endpoints
    branch_span = float(high_endpoint - low_endpoint)
    for distribution in branch_spec["required_distributions"]:
        pairs: Dict[int, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
        reasons: list[str] = []
        for count in branch_counts:
            scenario_id = f"branch-count-{count}-{distribution}"
            off, on, pair_reason = _toggle_pair(summaries, scenario_id)
            if off is None or on is None:
                reasons.append(f"{scenario_id}: {pair_reason}")
            else:
                pairs[count] = (off, on)
        if reasons:
            branch_instances.append(_gate_instance(
                distribution, "pending",
                "unverified due to missing mechanism evidence",
                "; ".join(reasons),
            ))
            continue
        branch_strata = {
            _invariant_summary_stratum(summary)
            for pair in pairs.values() for summary in pair
        }
        if len(branch_strata) != 1:
            branch_instances.append(_gate_instance(
                distribution, "pending",
                "unverified due to missing mechanism evidence",
                "the complete branch ladder is not one executable/runtime/host/configuration stratum",
                evidence=[
                    summary["summary_id"]
                    for pair in pairs.values() for summary in pair
                ],
            ))
            continue
        if any(
                not summary.get("release_ready")
                for pair in pairs.values() for summary in pair):
            branch_instances.append(_gate_instance(
                distribution, "pending",
                "unverified due to missing mechanism evidence",
                "every branch ladder point requires the minimum native repeats",
                evidence=[
                    summary["summary_id"]
                    for pair in pairs.values() for summary in pair
                ],
            ))
            continue
        on_endpoints = [pairs[low_endpoint][1], pairs[high_endpoint][1]]
        consumed = all(
            "consumed" in {
                str(value).casefold() for value in
                summary["mechanism_evidence"].get(
                    "lookup_consumption_statuses", []
                )
            }
            and _profile_proved(summary)
            for summary in on_endpoints
        )
        if not consumed:
            branch_instances.append(_gate_instance(
                distribution, "pending",
                "unverified due to missing mechanism evidence",
                "both endpoint lookup-on strata require hashed consumed-lookup evidence",
                evidence=[summary["summary_id"] for pair in pairs.values() for summary in pair],
            ))
            continue
        off16, on16 = pairs[low_endpoint]
        off1000, on1000 = pairs[high_endpoint]
        slope_off = (
            off1000["elapsed"]["median"] - off16["elapsed"]["median"]
        ) / branch_span
        slope_on = (
            on1000["elapsed"]["median"] - on16["elapsed"]["median"]
        ) / branch_span
        relative_mads = []
        for summary in (off16, off1000, on16, on1000):
            median = summary["elapsed"]["median"]
            mad = summary["elapsed"]["mad"]
            if median not in (None, 0) and mad is not None:
                relative_mads.append(float(mad) / float(median))
        slope_noise = max(
            float(gates["noise_model"]["numerical_floor_fraction"]),
            float(gates["noise_model"]["mad_multiplier"])
            * max(relative_mads or [0.0]),
        )
        if slope_off <= 0:
            branch_instances.append(_gate_instance(
                distribution, "pending",
                "unverified due to missing mechanism evidence",
                "reference endpoint slope is non-positive or unresolved",
            ))
            continue
        reduction = (slope_off - slope_on) / abs(slope_off)
        required_reduction = max(
            float(branch_spec["numerical_floor_fraction"]), slope_noise,
        )
        passed = reduction >= required_reduction
        branch_instances.append(_gate_instance(
            distribution, "pass" if passed else "fail",
            "demonstrated improvement" if passed else "regression",
            "endpoint slope reduction meets its floor" if passed else
            "endpoint slope reduction misses its floor",
            evidence=[summary["summary_id"] for pair in pairs.values() for summary in pair],
            computed={
                "off_slope_seconds_per_branch": slope_off,
                "on_slope_seconds_per_branch": slope_on,
                "slope_reduction_fraction": reduction,
                "required_reduction_fraction": required_reduction,
            },
        ))
    results.append(_aggregate_gate(
        "branch-count-scaling", branch_instances,
        "demonstrated improvement",
    ))

    # 5. Explicit adverse/small controls.
    adverse_ids = list(gate_specs[
        "adverse-and-small-shape-no-regression"
    ]["required_scenarios"])
    adverse_spec = gate_specs["adverse-and-small-shape-no-regression"]
    adverse_instances: list[Dict[str, Any]] = []
    for scenario_id in adverse_ids:
        off, on, pair_reason = _toggle_pair(summaries, scenario_id)
        if off is None or on is None:
            adverse_instances.append(_gate_instance(
                scenario_id, "pending",
                "unverified due to missing mechanism evidence", pair_reason,
            ))
            continue
        scenario = workload_scenarios.get(scenario_id, {})
        mechanism_status, mechanism_reason = _mechanism_expectation(scenario, on)
        if mechanism_status != "pass":
            adverse_instances.append(_gate_instance(
                scenario_id, mechanism_status,
                "regression" if mechanism_status == "fail" else
                "unverified due to missing mechanism evidence",
                mechanism_reason,
                evidence=[off["summary_id"], on["summary_id"]],
            ))
            continue
        adverse_instances.append(_no_regression_instance(
            scenario_id, off, on, gates,
            median_floor=float(adverse_spec[
                "median_numerical_floor_fraction"
            ]),
            p95_floor=float(adverse_spec["p95_numerical_floor_fraction"]),
        ))
    bounded_base, bounded_candidate, bounded_reason = _revision_pair(
        summaries, "combined-substring-adverse", COMMIT_PRE, COMMIT_BOUNDED,
        "unsupported",
    )
    if bounded_base is None or bounded_candidate is None:
        adverse_instances.append(_gate_instance(
            "bounded-feature:combined-substring-adverse", "pending",
            "unverified due to missing mechanism evidence", bounded_reason,
        ))
    else:
        mechanism_status, mechanism_reason = _mechanism_expectation(
            workload_scenarios.get("combined-substring-adverse", {}),
            bounded_candidate,
        )
        if mechanism_status != "pass":
            adverse_instances.append(_gate_instance(
                "bounded-feature:combined-substring-adverse", mechanism_status,
                "regression" if mechanism_status == "fail" else
                "unverified due to missing mechanism evidence",
                mechanism_reason,
                evidence=[
                    bounded_base["summary_id"], bounded_candidate["summary_id"],
                ],
            ))
        else:
            adverse_instances.append(_no_regression_instance(
                "bounded-feature:combined-substring-adverse",
                bounded_base, bounded_candidate, gates,
                median_floor=float(adverse_spec[
                    "median_numerical_floor_fraction"
                ]),
                p95_floor=float(adverse_spec[
                    "p95_numerical_floor_fraction"
                ]),
            ))
    results.append(_aggregate_gate(
        "adverse-and-small-shape-no-regression", adverse_instances,
    ))

    # 6. Threshold CPU plus dedicated, matched run-level high-water memory.
    overhead_instances: list[Dict[str, Any]] = []
    off16, on16, threshold_reason = _toggle_pair(
        summaries, "branch-count-16-zero-candidate",
    )
    off15, on15, below_reason = _toggle_pair(
        summaries, "branch-count-15-zero-candidate",
    )
    overhead_spec = gate_specs["table-build-and-memory-overhead"]
    minimum_overhead_cpu = int(overhead_spec.get(
        "minimum_independent_cpu_samples", minimum,
    ))
    if off16 is None or on16 is None or off15 is None or on15 is None:
        overhead_instances.append(_gate_instance(
            "threshold-table-build-cpu", "pending",
            "unverified due to missing mechanism evidence",
            "; ".join(value for value in (threshold_reason, below_reason) if value),
        ))
    elif len({
            _invariant_summary_stratum(summary)
            for summary in (off15, on15, off16, on16)
            }) != 1:
        overhead_instances.append(_gate_instance(
            "threshold-table-build-cpu", "pending",
            "unverified due to missing mechanism evidence",
            "the 15/16 threshold controls are not one exact build/host/configuration stratum",
            evidence=[
                summary["summary_id"]
                for summary in (off15, on15, off16, on16)
            ],
        ))
    elif any(
            summary["server_cpu"]["n"] < minimum_overhead_cpu
            for summary in (off16, on16, off15, on15)):
        overhead_instances.append(_gate_instance(
            "threshold-table-build-cpu", "pending",
            "unverified due to missing mechanism evidence",
            f"threshold/below-threshold CPU requires {minimum_overhead_cpu} "
            "independent samples",
        ))
    elif (
            on15["mechanism_evidence"].get("lookup_constructed_values") != [False]
            or on16["mechanism_evidence"].get("lookup_constructed_values") != [True]
            or 16 not in on16["mechanism_evidence"].get(
                "lookup_largest_families", [])):
        overhead_instances.append(_gate_instance(
            "threshold-table-build-cpu", "pending",
            "unverified due to missing mechanism evidence",
            "15/16 lookup construction diagnostics do not prove the threshold",
        ))
    else:
        cpu_noise = _metric_noise(off16, on16, "server_cpu", gates)
        cpu_change = _relative_change(
            on16["server_cpu"]["median"], off16["server_cpu"]["median"],
        )
        limit = max(
            float(overhead_spec["median_cpu_numerical_floor_fraction"]),
            cpu_noise,
        )
        passed = cpu_change is not None and cpu_change <= limit
        overhead_instances.append(_gate_instance(
            "threshold-table-build-cpu", "pass" if passed else "fail",
            "no material change" if passed else "regression",
            "threshold table-build CPU is within its overhead floor" if passed else
            "threshold table-build CPU exceeds its overhead floor",
            evidence=[off16["summary_id"], on16["summary_id"]],
            computed={"cpu_change_fraction": cpu_change, "limit_fraction": limit},
        ))

    memory_scenarios = set(overhead_spec["required_memory_scenarios"])
    memory_bundles = {
        bundle.run_id: bundle for bundle in bundles
        if bundle.release_candidate
        and any(
            artifact.get("production_commit") == COMMIT_FINAL
            and artifact.get("server") == "389ds"
            and artifact.get("rpm_proved") is True
            for artifact in bundle.artifacts
        )
        and isinstance(bundle.run_manifest.get("selected_scenarios"), list)
        and set(bundle.run_manifest["selected_scenarios"]) == memory_scenarios
        and all(
            any(
                row["run_id"] == bundle.run_id
                and row["scenario_id"] == scenario_id
                and row["phase"] == "measured"
                and row["release_eligible"]
                for row in rows
            )
            for scenario_id in memory_scenarios
        )
    }
    schedule = assess_schedules(bundles)
    memory_blocks: list[tuple[str, list[Bundle], list[Bundle]]] = []
    for block in schedule.get("blocks", []):
        if block.get("status") != "pass":
            continue
        by_position = block.get("run_ids_by_position")
        if (
                not isinstance(by_position, Mapping)
                or set(by_position) != {"A1", "B1", "B2", "A2"}
                or any(run_id not in memory_bundles for run_id in by_position.values())):
            continue
        baseline_runs = [
            memory_bundles[str(by_position[position])]
            for position in ("A1", "A2")
        ]
        candidate_runs = [
            memory_bundles[str(by_position[position])]
            for position in ("B1", "B2")
        ]
        if any(
                str(bundle.run_manifest.get("lookup_mode_actual")).casefold()
                not in {"off", "disabled"}
                for bundle in baseline_runs):
            continue
        if any(
                str(bundle.run_manifest.get("lookup_mode_actual")).casefold()
                not in {"on", "enabled"}
                for bundle in candidate_runs):
            continue
        artifacts = [
            artifact
            for bundle in [*baseline_runs, *candidate_runs]
            for artifact in bundle.artifacts
            if artifact.get("production_commit") == COMMIT_FINAL
            and artifact.get("server") == "389ds"
            and artifact.get("rpm_proved") is True
        ]
        if (
                len(artifacts) != 4
                or len({
                    artifact["executable_sha256"] for artifact in artifacts
                }) != 1
                or len({
                    artifact["behavioral_runtime_identity_sha256"]
                    for artifact in artifacts
                }) != 1
                or len({
                    bundle.run_manifest.get(
                        "installed_package_closure_sha256"
                    )
                    for bundle in [*baseline_runs, *candidate_runs]
                }) != 1):
            continue
        memory_blocks.append((
            str(block["block_id"]), baseline_runs, candidate_runs,
        ))
    if not memory_blocks:
        overhead_instances.append(_gate_instance(
            "dedicated-multivalue-high-water", "pending",
            "unverified due to missing mechanism evidence",
            "one or more complete matched dedicated multivalue lookup-off/on "
            "ABBA blocks are required",
        ))
    else:
        memory_computed: Dict[str, Any] = {"blocks": []}
        memory_missing: list[str] = []
        block_failures: list[str] = []
        evidence: list[str] = []
        absolute_floor = float(overhead_spec["rss_absolute_floor_bytes"])
        fractional_floor = float(overhead_spec["rss_fractional_floor"])
        for block_id, baseline_runs, candidate_runs in memory_blocks:
            arm_deltas: list[list[float]] = [[], []]
            for arm_index, arm_runs in enumerate((
                    baseline_runs, candidate_runs)):
                for bundle in arm_runs:
                    evidence.append(bundle.run_id)
                    run_rows = [
                        row for row in rows
                        if row["run_id"] == bundle.run_id
                        and row["phase"] == "measured"
                    ]
                    startup = _nested(
                        bundle.run_manifest, "startup_memory", "high_water_kib",
                    )
                    complete_peaks = bool(run_rows) and all(
                        row["release_eligible"]
                        and row["scenario_id"] in memory_scenarios
                        and row["metrics"]["high_water_kib"] is not None
                        for row in run_rows
                    )
                    if startup is None or not complete_peaks:
                        memory_missing.append(bundle.run_id)
                        continue
                    startup_value = float(startup)
                    peaks = [
                        float(row["metrics"]["high_water_kib"])
                        for row in run_rows
                    ]
                    if (
                            not math.isfinite(startup_value)
                            or startup_value < 0
                            or any(
                                not math.isfinite(peak)
                                or peak < startup_value for peak in peaks
                            )):
                        memory_missing.append(bundle.run_id)
                        continue
                    arm_deltas[arm_index].append(
                        (max(peaks) - startup_value) * 1024.0
                    )
            if any(len(values) != 2 for values in arm_deltas):
                continue
            baseline_delta = float(statistics.median(arm_deltas[0]))
            candidate_delta = float(statistics.median(arm_deltas[1]))
            increase = candidate_delta - baseline_delta
            fraction = increase / max(baseline_delta, 1.0)
            failed = increase > absolute_floor and fraction > fractional_floor
            if failed:
                block_failures.append(block_id)
            memory_computed["blocks"].append({
                "block_id": block_id,
                "baseline_run_deltas_bytes": arm_deltas[0],
                "candidate_run_deltas_bytes": arm_deltas[1],
                "baseline_median_high_water_delta_bytes": baseline_delta,
                "candidate_median_high_water_delta_bytes": candidate_delta,
                "increase_bytes": increase,
                "increase_fraction": fraction,
                "failed": failed,
            })
        memory_computed.update({
            "absolute_failure_floor_bytes": absolute_floor,
            "fractional_failure_floor": fractional_floor,
        })
        if block_failures:
            overhead_instances.append(_gate_instance(
                "dedicated-multivalue-high-water", "fail",
                "regression",
                "both RSS high-water floors are exceeded in block(s): "
                + ", ".join(block_failures),
                evidence=evidence,
                computed=memory_computed,
            ))
        elif memory_missing:
            overhead_instances.append(_gate_instance(
                "dedicated-multivalue-high-water", "pending",
                "unverified due to missing mechanism evidence",
                "startup or complete per-row peak VmHWM evidence is missing "
                "for: " + ", ".join(sorted(set(memory_missing))),
                evidence=evidence,
                computed=memory_computed,
            ))
        else:
            overhead_instances.append(_gate_instance(
                "dedicated-multivalue-high-water",
                "pass", "no material change",
                "no complete ABBA block exceeds both memory floors",
                evidence=evidence,
                computed=memory_computed,
            ))
    results.append(_aggregate_gate(
        "table-build-and-memory-overhead", overhead_instances,
    ))

    # 7. Explicit decline/fallback paths, including untimed dynamic controls.
    decline_groups = set(gate_specs["decline-path-parity"]["required_groups"])
    decline_ids = sorted({
        scenario_id
        for group, members in workload.get("scenario_groups", {}).items()
        if group in decline_groups and isinstance(members, list)
        for scenario_id in members
        if scenario_id not in dynamic_ids
    })
    decline_instances: list[Dict[str, Any]] = []
    for scenario_id in decline_ids:
        off, on, pair_reason = _toggle_pair(summaries, scenario_id)
        if off is None or on is None:
            decline_instances.append(_gate_instance(
                scenario_id, "pending",
                "unverified due to missing mechanism evidence", pair_reason,
            ))
            continue
        mechanism_status, mechanism_reason = _mechanism_expectation(
            workload_scenarios.get(scenario_id, {}), on,
        )
        if mechanism_status != "pass":
            decline_instances.append(_gate_instance(
                scenario_id, mechanism_status,
                "regression" if mechanism_status == "fail" else
                "unverified due to missing mechanism evidence",
                mechanism_reason,
                evidence=[off["summary_id"], on["summary_id"]],
            ))
            continue
        outcome = _no_regression_instance(
            scenario_id, off, on, gates,
            pass_classification="expected decline/fallback",
            median_floor=float(gate_specs[
                "decline-path-parity"
            ]["numerical_floor_fraction"]),
        )
        if outcome["status"] == "fail":
            waivers = on["mechanism_evidence"].get(
                "profile_attributed_waivers", []
            )
            proved_profiles = set(
                on["mechanism_evidence"].get("profile_sha256s", [])
            )
            valid_waiver = any(
                isinstance(waiver, Mapping)
                and _is_sha256(waiver.get("profile_sha256"))
                and waiver.get("profile_sha256") in proved_profiles
                and waiver.get("evidence_status") == "observed"
                and waiver.get("scenario") == scenario_id
                and isinstance(waiver.get("rationale"), str)
                and bool(waiver["rationale"].strip())
                for waiver in waivers
            ) and _profile_proved(on)
            if valid_waiver:
                outcome = _gate_instance(
                    scenario_id, "pass", "unavoidable implementation difference",
                    "a structured, profile-hashed waiver attributes the difference",
                    evidence=[off["summary_id"], on["summary_id"]],
                    computed=outcome["computed"],
                )
        decline_instances.append(outcome)
    for scenario_id in dynamic_ids:
        controls_by_commit = {
            commit: [
                item for item in correctness_controls
                if item["scenario_id"] == scenario_id
                and _summary_has_commit(item, commit)
            ]
            for commit in (COMMIT_038, COMMIT_FINAL)
        }
        controls = [
            item for items in controls_by_commit.values() for item in items
        ]
        if any(len(items) != 1 for items in controls_by_commit.values()):
            decline_instances.append(_gate_instance(
                f"dynamic:{scenario_id}", "pending",
                "unverified due to missing mechanism evidence",
                "both 038b8f58 and final dynamic controls are required",
                evidence=[item["control_id"] for item in controls],
            ))
        elif any(
                not item["passed"]
                or not item["oracle_passed"]
                or item["ldap_adminlimit_exceeded"] is not False
                or not _dynamic_control_exact_ready(item)
                for item in controls):
            decline_instances.append(_gate_instance(
                f"dynamic:{scenario_id}", "fail", "regression",
                "a dynamic control failed exact/no-admin-limit validation",
                evidence=[item["control_id"] for item in controls],
            ))
        else:
            decline_instances.append(_gate_instance(
                f"dynamic:{scenario_id}", "pass", "expected decline/fallback",
                "both post-fix revisions retain exact dynamic-list behavior",
                evidence=[item["control_id"] for item in controls],
            ))
    results.append(_aggregate_gate(
        "decline-path-parity", decline_instances,
        "expected decline/fallback",
    ))

    # 8. Final successful paths compared only to the production parent.
    success_ids = tuple(gate_specs[
        "final-success-path-no-regression"
    ]["required_scenarios"])
    success_spec = gate_specs["final-success-path-no-regression"]
    success_instances: list[Dict[str, Any]] = []
    for scenario_id in success_ids:
        parent, final, pair_reason = _revision_pair(
            summaries, scenario_id, COMMIT_9C, COMMIT_FINAL, "on",
        )
        if parent is None or final is None:
            success_instances.append(_gate_instance(
                scenario_id, "pending",
                "unverified due to missing mechanism evidence", pair_reason,
            ))
            continue
        mechanism_status, mechanism_reason = _mechanism_expectation(
            workload_scenarios.get(scenario_id, {}), final,
        )
        if mechanism_status != "pass":
            success_instances.append(_gate_instance(
                scenario_id, mechanism_status,
                "regression" if mechanism_status == "fail" else
                "unverified due to missing mechanism evidence",
                mechanism_reason,
                evidence=[parent["summary_id"], final["summary_id"]],
            ))
        else:
            success_instances.append(_no_regression_instance(
                scenario_id, parent, final, gates,
                median_floor=float(success_spec[
                    "median_numerical_floor_fraction"
                ]),
                p95_floor=float(success_spec[
                    "p95_numerical_floor_fraction"
                ]),
            ))
    results.append(_aggregate_gate(
        "final-success-path-no-regression", success_instances,
    ))

    # 9. Explicit cross-shape sDN2 pairs. Performance differences are reported,
    # but only resolved candidate/index/profile attribution can pass the gate.
    sdn2_pairs = gate_specs["sdn2-pair-attribution"]["required_pairs"]
    sdn2_instances: list[Dict[str, Any]] = []
    for pair_id, (with_id, without_id) in sdn2_pairs.items():
        with_summary, with_reason = _find_single_summary(
            summaries, with_id, COMMIT_FINAL, "on",
        )
        without_summary, without_reason = _find_single_summary(
            summaries, without_id, COMMIT_FINAL, "on",
        )
        if with_summary is None or without_summary is None:
            sdn2_instances.append(_gate_instance(
                pair_id, "pending",
                "unverified due to missing mechanism evidence",
                "; ".join(value for value in (with_reason, without_reason) if value),
            ))
            continue
        expected_with = workload_scenarios.get(with_id, {}).get("expected_sha256")
        expected_without = workload_scenarios.get(without_id, {}).get("expected_sha256")
        expected_with_count = workload_scenarios.get(with_id, {}).get(
            "expected_count"
        )
        expected_without_count = workload_scenarios.get(without_id, {}).get(
            "expected_count"
        )
        if (
                expected_with != expected_without
                or expected_with_count != expected_without_count):
            sdn2_instances.append(_gate_instance(
                pair_id, "fail", "regression",
                "paired workload oracles do not have identical DN hashes",
                evidence=[with_summary["summary_id"], without_summary["summary_id"]],
            ))
            continue
        if (
                with_summary["executable_sha256"]
                != without_summary["executable_sha256"]
                or with_summary.get("host_signature")
                != without_summary.get("host_signature")
                or with_summary["behavioral_runtime_identity_sha256"]
                != without_summary["behavioral_runtime_identity_sha256"]
                or with_summary["configuration"] != without_summary["configuration"]):
            sdn2_instances.append(_gate_instance(
                pair_id, "pending",
                "unverified due to missing mechanism evidence",
                "cross-shape summaries are not from one exact build/configuration",
            ))
            continue
        mechanisms = [
            with_summary["mechanism_evidence"],
            without_summary["mechanism_evidence"],
        ]
        mechanism_ready = all(
            mechanism.get("candidate_list_statuses") == ["observed"]
            and mechanism.get("candidate_list_observed_values") == [True]
            and len(mechanism.get("candidate_list_values", [])) == 1
            and len(mechanism.get("candidate_counts", [])) == 1
            and mechanism.get("candidate_list_values")
            == mechanism.get("candidate_counts")
            and mechanism.get("access_notes_observed_values") == [True]
            and len(mechanism.get("access_notes", [])) == 1
            and mechanism.get("stat_index_reads_observed_values") == [True]
            and _profile_proved(summary)
            for summary, mechanism in zip(
                (with_summary, without_summary), mechanisms,
            )
        )
        metric_ready = all(
            summary.get("release_ready")
            and summary["instructions"]["n"] >= minimum_instruction_batches
            and summary["server_cpu"]["n"] >= minimum
            for summary in (with_summary, without_summary)
        )
        elapsed_change = _relative_change(
                without_summary["elapsed"]["median"],
                with_summary["elapsed"]["median"],
        )
        cpu_change = _relative_change(
                without_summary["server_cpu"]["median"],
                with_summary["server_cpu"]["median"],
        )
        instruction_change = _relative_change(
                without_summary["instructions"]["median"],
                with_summary["instructions"]["median"],
        )
        index_read_signatures = [
            _sdn2_index_read_signature(mechanism) for mechanism in mechanisms
        ]
        computed = {
            "elapsed_median_change_fraction_without_vs_with": elapsed_change,
            "cpu_median_change_fraction_without_vs_with": cpu_change,
            "instructions_change_fraction_without_vs_with": instruction_change,
            "with_candidate_list": mechanisms[0].get("candidate_list_values"),
            "without_candidate_list": mechanisms[1].get("candidate_list_values"),
            "with_access_notes": mechanisms[0].get("access_notes"),
            "without_access_notes": mechanisms[1].get("access_notes"),
            "with_stat_index_reads": mechanisms[0].get("stat_index_reads"),
            "without_stat_index_reads": mechanisms[1].get("stat_index_reads"),
            "with_structural_index_reads": index_read_signatures[0],
            "without_structural_index_reads": index_read_signatures[1],
        }
        if not mechanism_ready or not metric_ready or any(
                value is None
                for value in (elapsed_change, cpu_change, instruction_change)):
            sdn2_instances.append(_gate_instance(
                pair_id, "pending",
                "unverified due to missing mechanism evidence",
                "observed candidate-list, notes-U, STAT-index-read, hashed-profile, "
                "and release metric channels are all required",
                evidence=[with_summary["summary_id"], without_summary["summary_id"]],
                computed=computed,
            ))
        else:
            mechanism_changed = any(
                mechanisms[0].get(field) != mechanisms[1].get(field)
                for field in (
                    "candidate_list_values", "candidate_counts", "access_notes",
                )
            ) or index_read_signatures[0] != index_read_signatures[1]
            metric_thresholds = {
                "elapsed": max(
                    float(gates["performance"][
                        "material_change_floor_fraction"
                    ]),
                    _metric_noise(
                        with_summary, without_summary, "elapsed", gates,
                    ),
                ),
                "cpu": max(
                    float(gates["performance"][
                        "material_change_floor_fraction"
                    ]),
                    _metric_noise(
                        with_summary, without_summary, "server_cpu", gates,
                    ),
                ),
                "instructions": max(
                    float(gates["performance"][
                        "material_change_floor_fraction"
                    ]),
                    _metric_noise(
                        with_summary, without_summary, "instructions", gates,
                    ),
                ),
            }
            metric_changed = (
                abs(float(elapsed_change)) >= metric_thresholds["elapsed"]
                or abs(float(cpu_change)) >= metric_thresholds["cpu"]
                or abs(float(instruction_change))
                >= metric_thresholds["instructions"]
            )
            attribution = (
                "candidate-generation-changed" if mechanism_changed else
                "evaluator-only-cost" if metric_changed else
                "no-material-difference"
            )
            computed.update({
                "derived_attribution": attribution,
                "metric_materiality_thresholds": metric_thresholds,
            })
            sdn2_instances.append(_gate_instance(
                pair_id, "pass", "no material change",
                "exact paired results have a deterministic attribution derived "
                "from the observed candidate/index/profile and metric channels",
                evidence=[with_summary["summary_id"], without_summary["summary_id"]],
                computed=computed,
            ))
    results.append(_aggregate_gate("sdn2-pair-attribution", sdn2_instances))

    # 10. Absolute fix/retention observations; manifest expectations alone do
    # not count as selected-family evidence.
    role_commits = {
        "all-family-fix": COMMIT_09,
        "largest-family-fix": COMMIT_9C,
        "final": COMMIT_FINAL,
    }
    selection_requirements = [
        (
            role_commits[str(observation["revision_role"])],
            str(observation["scenario"]),
            str(observation["selected_attribute"]),
            int(observation["largest_family"]),
        )
        for observation in gate_specs[
            "selection-fix-retention"
        ]["required_observations"]
    ]
    selection_instances: list[Dict[str, Any]] = []
    for commit, scenario_id, expected_attribute, expected_largest in selection_requirements:
        summary, summary_reason = _find_single_summary(
            summaries, scenario_id, commit, "on",
        )
        instance_id = f"{commit[:8]}:{scenario_id}"
        if summary is None:
            selection_instances.append(_gate_instance(
                instance_id, "pending",
                "unverified due to missing mechanism evidence", summary_reason,
            ))
            continue
        mechanism = summary["mechanism_evidence"]
        direct = mechanism.get("selected_attributes_direct", [])
        largest = mechanism.get("lookup_largest_families", [])
        observations = mechanism.get("selection_observations", [])
        if not direct or not largest or not observations:
            selection_instances.append(_gate_instance(
                instance_id, "pending",
                "unverified due to missing mechanism evidence",
                "direct selected-attribute and largest-family evidence are required",
                evidence=[summary["summary_id"]],
            ))
        elif (
                [value.casefold() for value in direct]
                != [expected_attribute.casefold()]
                or largest != [expected_largest]
                or len(observations) != 1
                or str(observations[0].get(
                    "selected_attribute", ""
                )).casefold() != expected_attribute.casefold()
                or observations[0].get("largest_families")
                != [expected_largest]):
            selection_instances.append(_gate_instance(
                instance_id, "fail", "regression",
                "observed selected attribute or largest family is incorrect",
                evidence=[summary["summary_id"]],
                computed={
                    "observed_selected_attributes": direct,
                    "observed_largest_families": largest,
                    "observed_selection_evidence": observations,
                    "expected_selected_attribute": expected_attribute,
                    "expected_largest_family": expected_largest,
                },
            ))
        else:
            selection_instances.append(_gate_instance(
                instance_id, "pass", "no material change",
                "exact result and direct selection evidence retain the fix",
                evidence=[summary["summary_id"]],
            ))
    results.append(_aggregate_gate("selection-fix-retention", selection_instances))

    declared_ids = [str(item["id"]) for item in gates.get("gates", [])]
    produced_ids = [str(item["gate_id"]) for item in results]
    if produced_ids != declared_ids:
        raise MergeError(
            "explicit gate evaluator IDs/order disagree with acceptance-gates.json"
        )
    return results


def _markdown(value: Any) -> str:
    if value is None:
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _seconds(value: Any) -> str:
    if value is None:
        return "—"
    return f"{float(value):.6g}"


def _fraction(value: Any) -> str:
    if value is None:
        return "—"
    return f"{float(value) * 100:+.2f}%"


def _labels(summary: Mapping[str, Any]) -> str:
    return ", ".join(summary["commit_labels"])


def _summary_table(summaries: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = [
        "| binary aliases | runtime identity | server | scenario aliases | n | median client elapsed (s) | nearest-rank p95 (s) | median server etime (s) | median CPU (s) | median instructions |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            "| {labels} | `{runtime}` | {server} | {scenarios} | {n} | {median} | {p95} | {etime} | {cpu} | {instructions} |".format(
                labels=_markdown(_labels(summary)),
                runtime=summary["runtime_identity_id"],
                server=_markdown(summary["configuration"].get("server")),
                scenarios=_markdown(", ".join(summary["scenario_ids"])),
                n=summary["n"],
                median=_seconds(summary["elapsed"]["median"]),
                p95=_seconds(summary["elapsed"]["p95_nearest_rank"]),
                etime=_seconds(summary["server_etime"]["median"]),
                cpu=_seconds(summary["server_cpu"]["median"]),
                instructions=_markdown(summary["instructions"]["median"]),
            )
        )
    return lines


def render_results(
        status: str, bundles: Sequence[Bundle], rows: Sequence[Mapping[str, Any]],
        perf_batches: Sequence[Mapping[str, Any]],
        correctness_controls: Sequence[Mapping[str, Any]],
        binary_groups: Sequence[Mapping[str, Any]],
        release_summaries: Sequence[Mapping[str, Any]],
        exploratory_summaries: Sequence[Mapping[str, Any]],
        unsafe_summaries: Sequence[Mapping[str, Any]],
        comparisons: Sequence[Mapping[str, Any]],
        exploratory_comparisons: Sequence[Mapping[str, Any]],
        openldap_context: Sequence[Mapping[str, Any]],
        scaling_tables: Sequence[Mapping[str, Any]],
        acceptance_gate_results: Sequence[Mapping[str, Any]],
        schedule_assessment: Mapping[str, Any],
        matrix_assessment: Mapping[str, Any],
        release_conclusion: Mapping[str, Any],
        duplicate_bundles: Sequence[Mapping[str, Any]],
        unsafe_include_nonrelease: bool,
        minimum_repeats: int) -> str:
    passed = sum(1 for row in rows if row["correctness"]["passed"])
    complete = sum(1 for row in rows if row["correctness"]["complete"])
    release_rows = sum(1 for row in rows if row["release_eligible"])
    excluded_rows = len(rows) - release_rows
    lines = [
        "# Large-filter study merged results",
        "",
        f"Status: **{status}**",
        "",
        "Release authority: **native installed-RPM timing evidence only**. "
        "Correctness-only and unsafe appendix data are explicitly nonrelease "
        "and cannot satisfy performance acceptance gates.",
        "",
        "Matrix completion: **{status}** ({passed}/{required} required cells; "
        "{failed} failed; {pending} pending).".format(
            status=matrix_assessment.get("status"),
            passed=matrix_assessment.get("pass_count", 0),
            required=matrix_assessment.get("required_instance_count", 0),
            failed=matrix_assessment.get("fail_count", 0),
            pending=matrix_assessment.get("pending_count", 0),
        ),
        "",
        "ABBA schedule validation: **{status}** ({valid}/{declared} declared "
        "blocks valid; {screens} exploratory screen run(s)).".format(
            status=schedule_assessment.get("status"),
            valid=schedule_assessment.get("valid_block_count", 0),
            declared=schedule_assessment.get("declared_block_count", 0),
            screens=len(schedule_assessment.get("screen_run_ids", [])),
        ),
        "",
        "Release conclusion: **{status}**. Recommendation: **{recommendation}**. "
        "{reason}".format(
            status=release_conclusion.get("status"),
            recommendation=release_conclusion.get("recommendation"),
            reason=release_conclusion.get("reason"),
        ),
        "",
        "## Validation",
        "",
        f"- Result bundles accepted: {len(bundles)}.",
        f"- Exact workload/schema/filter/expected-result contract: validated as `{bundles[0].workload_contract['workload_sha256']}`.",
        f"- Raw rows retained: {len(rows)}; correctness passed: {passed}; complete count/hash/result-code evidence: {complete}.",
        f"- Independent perf batches validated: {len(perf_batches)}; untimed correctness/mechanism controls retained: {len(correctness_controls)}.",
        f"- Native installed-RPM timing rows eligible for release tables: {release_rows}; excluded: {excluded_rows}.",
        f"- Identical executable hashes collapsed to {len(binary_groups)} binary identity/identities while retaining commit labels.",
        "- Timing rows pool only when the combined direct-link and live-backend "
        "behavioral runtime identity also matches.",
    ]
    if duplicate_bundles:
        lines.append(
            f"- Exact duplicate run bundles ignored once: {len(duplicate_bundles)}."
        )
    lines.extend([
        "",
        "## Exact binary identities",
        "",
        "| executable SHA-256 | linked closure(s) | live backend closure(s) | behavioral identity/identities | commit/build aliases | source commits | production commits | server | installed RPM proved |",
        "|---|---|---|---|---|---|---|---|---|",
    ])
    for group in binary_groups:
        lines.append(
            "| `{sha}` | {linked} | {backend} | {behavioral} | {labels} | {commits} | {production} | {servers} | {rpm} |".format(
                sha=group["executable_sha256"],
                linked=_markdown(", ".join(
                    group["runtime_closure_sha256s"]
                )),
                backend=_markdown(", ".join(
                    group["backend_runtime_closure_sha256s"]
                )),
                behavioral=_markdown(", ".join(
                    group["behavioral_runtime_identity_sha256s"]
                )),
                labels=_markdown(", ".join(group["commit_labels"])),
                commits=_markdown(", ".join(group["source_commits"])),
                production=_markdown(", ".join(group["production_commits"])),
                servers=_markdown(", ".join(group["servers"])),
                rpm="yes" if group["installed_rpm_proved"] else "no",
            )
        )
    lines.extend(["", "## Evidence disposition", ""])
    for bundle in bundles:
        if bundle.release_candidate:
            disposition = "native-host candidate (rows remain subject to correctness and RPM gates)"
        else:
            disposition = "validation-only: " + "; ".join(bundle.disposition_reasons)
        lines.append(f"- `{bundle.run_id}`: {_markdown(disposition)}")

    lines.extend([
        "",
        "## Authoritative acceptance gates",
        "",
        "These gate-specific results are authoritative. Generic release "
        "comparison classifications below are descriptive only.",
        "",
        "| gate | status | classification | pass | fail | pending |",
        "|---|---|---|---:|---:|---:|",
    ])
    for gate in acceptance_gate_results:
        lines.append(
            "| {gate} | {status} | {classification} | {passed} | {failed} | {pending} |".format(
                gate=_markdown(gate["gate_id"]),
                status=_markdown(gate["status"]),
                classification=_markdown(gate["classification"]),
                passed=gate["pass_count"],
                failed=gate["fail_count"],
                pending=gate["pending_count"],
            )
        )
    nonpass_instances = [
        (gate["gate_id"], instance)
        for gate in acceptance_gate_results
        for instance in gate.get("instances", [])
        if instance.get("status") != "pass"
    ]
    lines.extend([
        "",
        "### Pending and failed instance reasons",
        "",
    ])
    if nonpass_instances:
        lines.extend([
            "| gate | instance | status | reason | evidence |",
            "|---|---|---|---|---|",
        ])
        for gate_id, instance in nonpass_instances:
            lines.append(
                "| {gate} | {instance} | {status} | {reason} | {evidence} |".format(
                    gate=_markdown(gate_id),
                    instance=_markdown(instance.get("instance_id")),
                    status=_markdown(instance.get("status")),
                    reason=_markdown(instance.get("reason")),
                    evidence=_markdown(", ".join(
                        str(value) for value in instance.get(
                            "evidence_refs", []
                        )
                    )),
                )
            )
    else:
        lines.append("Every declared gate instance passed.")

    if not release_summaries:
        lines.extend([
            "",
            "No native installed-RPM timing evidence is eligible yet. The validated "
            "correctness artifacts are retained, but no release timing comparison or "
            "performance classification is emitted.",
        ])
    else:
        lines.extend([
            "",
            "## Native release timing summaries",
            "",
            f"A release classification requires at least {minimum_repeats} measured repetitions in each compared stratum.",
            "",
        ])
        lines.extend(_summary_table(release_summaries))
        lines.extend([
            "",
            "## Native candidate and mechanism validation",
            "",
            "| binary aliases | scenario aliases | index variant | candidate counts | notes | required mechanism | verified |",
            "|---|---|---|---|---|---|---|",
        ])
        for summary in release_summaries:
            evidence = summary["mechanism_evidence"]
            lines.append(
                "| {labels} | {scenarios} | {index} | {counts} | {notes} | {required} | {verified} |".format(
                    labels=_markdown(_labels(summary)),
                    scenarios=_markdown(", ".join(summary["scenario_ids"])),
                    index=_markdown(summary["configuration"].get("index_variant")),
                    counts=_markdown(", ".join(str(value) for value in evidence["candidate_counts"])),
                    notes=_markdown(", ".join(evidence["access_notes"])),
                    required=_markdown(", ".join(evidence["required_kinds"])),
                    verified="yes" if evidence["verified"] else "no",
                )
            )

    if comparisons:
        lines.extend([
            "",
            "## Native release comparisons",
            "",
            "| scenario aliases | baseline | baseline runtime | baseline lookup | candidate | candidate runtime | candidate lookup | matched configuration | client median change | server etime change | p95 change | CPU change | instructions change | noise floor | applicable gates | classification | gate |",
            "|---|---|---|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|---|---|",
        ])
        for comparison in comparisons:
            lines.append(
                "| {scenario} | {baseline} | `{baseline_runtime}` | {baseline_lookup} | {candidate} | `{candidate_runtime}` | {candidate_lookup} | {configuration} | {elapsed} | {etime} | {p95} | {cpu} | {instructions} | {noise} | {gate_ids} | {classification} | {gate} |".format(
                    scenario=_markdown(", ".join(comparison["scenario_ids"])),
                    baseline=_markdown(", ".join(comparison["baseline_labels"])),
                    baseline_runtime=comparison["baseline_runtime_identity_id"],
                    baseline_lookup=_markdown(comparison["baseline_lookup_mode"]),
                    candidate=_markdown(", ".join(comparison["candidate_labels"])),
                    candidate_runtime=comparison["candidate_runtime_identity_id"],
                    candidate_lookup=_markdown(comparison["candidate_lookup_mode"]),
                    configuration=_markdown(json.dumps(
                        comparison["configuration"], sort_keys=True,
                        separators=(",", ":"),
                    )),
                    elapsed=_fraction(comparison["elapsed_median_change_fraction"]),
                    etime=_fraction(comparison["server_etime_median_change_fraction"]),
                    p95=_fraction(comparison["elapsed_p95_change_fraction"]),
                    cpu=_fraction(comparison["server_cpu_median_change_fraction"]),
                    instructions=_fraction(comparison["instructions_median_change_fraction"]),
                    noise=_fraction(comparison["noise_fraction"]),
                    gate_ids=_markdown(", ".join(comparison["applicable_gate_ids"])),
                    classification=_markdown(comparison["classification"]),
                    gate=_markdown(comparison["gate_status"]),
                )
            )

    if exploratory_summaries:
        lines.extend([
            "",
            "## Exploratory native screen summaries (non-release)",
            "",
            "These native installed-RPM measurements are useful for a quick "
            "directional screen, but they are outside a complete validated "
            "ABBA block and cannot satisfy release gates.",
            "",
        ])
        lines.extend(_summary_table(exploratory_summaries))

    if exploratory_comparisons:
        lines.extend([
            "",
            "### Exploratory directional comparisons (non-release)",
            "",
            "| scenario aliases | baseline | baseline lookup | candidate | "
            "candidate lookup | client median change | p95 change | CPU "
            "change | classification |",
            "|---|---|---|---|---|---:|---:|---:|---|",
        ])
        for comparison in exploratory_comparisons:
            lines.append(
                "| {scenario} | {baseline} | {baseline_lookup} | "
                "{candidate} | {candidate_lookup} | {elapsed} | {p95} | "
                "{cpu} | {classification} |".format(
                    scenario=_markdown(", ".join(
                        comparison["scenario_ids"]
                    )),
                    baseline=_markdown(", ".join(
                        comparison["baseline_labels"]
                    )),
                    baseline_lookup=_markdown(
                        comparison["baseline_lookup_mode"]
                    ),
                    candidate=_markdown(", ".join(
                        comparison["candidate_labels"]
                    )),
                    candidate_lookup=_markdown(
                        comparison["candidate_lookup_mode"]
                    ),
                    elapsed=_fraction(
                        comparison["elapsed_median_change_fraction"]
                    ),
                    p95=_fraction(
                        comparison["elapsed_p95_change_fraction"]
                    ),
                    cpu=_fraction(
                        comparison["server_cpu_median_change_fraction"]
                    ),
                    classification=_markdown(
                        comparison["classification"]
                    ),
                )
            )

    if openldap_context:
        lines.extend([
            "",
            "## Native OpenLDAP contextual comparison",
            "",
            "OpenLDAP is a contextual implementation comparison, not the correctness oracle and not a 389 DS acceptance baseline.",
            "",
            "| scenario aliases | 389 DS aliases | lookup mode | OpenLDAP aliases | cross-server semantic evidence | elapsed 389 DS / OpenLDAP | CPU ratio | instructions ratio | classification |",
            "|---|---|---|---|---|---:|---:|---:|---|",
        ])
        for comparison in openldap_context:
            lines.append(
                "| {scenario} | {ds} | {lookup} | {openldap} | {semantics} | {elapsed} | {cpu} | {instructions} | {classification} |".format(
                    scenario=_markdown(", ".join(comparison["scenario_ids"])),
                    ds=_markdown(", ".join(comparison["389ds_labels"])),
                    lookup=_markdown(comparison["389ds_lookup_mode"]),
                    openldap=_markdown(", ".join(comparison["openldap_labels"])),
                    semantics=_markdown(
                        f"{comparison['approximate_semantics_status']}: "
                        f"{comparison['approximate_semantics_reason']}"
                    ),
                    elapsed=_markdown(comparison["elapsed_ratio_389ds_over_openldap"]),
                    cpu=_markdown(comparison["server_cpu_ratio_389ds_over_openldap"]),
                    instructions=_markdown(comparison["instructions_ratio_389ds_over_openldap"]),
                    classification=_markdown(comparison["classification"]),
                )
            )

    if scaling_tables:
        lines.extend(["", "## Native scaling tables", ""])
        for table in scaling_tables:
            lines.extend([
                f"### {_markdown(table['dimension'])}: {_markdown(', '.join(table['commit_labels']))}",
                "",
                "| value | scenario aliases | n | median client elapsed (s) | p95 (s) | median server etime (s) | median CPU (s) | median instructions |",
                "|---|---|---:|---:|---:|---:|---:|---:|",
            ])
            for point in table["points"]:
                lines.append(
                    "| {value} | {scenario} | {n} | {elapsed} | {p95} | {etime} | {cpu} | {instructions} |".format(
                        value=_markdown(point["value"]),
                        scenario=_markdown(", ".join(point["scenario_ids"])),
                        n=point["n"],
                        elapsed=_seconds(point["elapsed_median_seconds"]),
                        p95=_seconds(point["elapsed_p95_seconds"]),
                        etime=_seconds(point["server_etime_median_seconds"]),
                        cpu=_seconds(point["server_cpu_median_seconds"]),
                        instructions=_markdown(point["instructions_median"]),
                    )
                )
            lines.append("")

    if unsafe_include_nonrelease:
        lines.extend([
            "",
            "## NON-RELEASE / UNSAFE descriptive appendix",
            "",
            "These rows are shown only because the unsafe override was explicit. "
            "They remain non-release evidence and are not used in comparisons or classifications.",
        ])
        if unsafe_summaries:
            lines.append("")
            lines.extend(_summary_table(unsafe_summaries))
        else:
            lines.extend(["", "No otherwise-valid non-release timing rows were available."])
    return "\n".join(lines).rstrip() + "\n"


def _load_gates(path: Path) -> Dict[str, Any]:
    gates = _load_json(path)
    if not isinstance(gates, Mapping) or gates.get("format_version") != 1:
        raise MergeError(f"{path}: unsupported acceptance-gates format")
    required = {
        "classification", "correctness", "gates", "memory",
        "noise_model", "performance", "reporting", "scaling",
    }
    missing = required.difference(gates)
    if missing:
        raise MergeError(f"{path}: missing acceptance-gates sections {sorted(missing)}")
    declared = gates.get("gates")
    if not isinstance(declared, list) or len(declared) != 10 or any(
            not isinstance(item, Mapping) or not isinstance(item.get("id"), str)
            for item in declared):
        raise MergeError(f"{path}: exactly ten named gate contracts are required")
    reporting = gates.get("reporting")
    reporting = reporting if isinstance(reporting, Mapping) else {}
    maximum_batch = reporting.get("maximum_searches_per_perf_batch")
    minimum_batches = reporting.get("minimum_independent_instruction_batches")
    if (
            not isinstance(maximum_batch, int) or isinstance(maximum_batch, bool)
            or not 1 <= maximum_batch <= PERF_BATCH_MAX_OPERATIONS):
        raise MergeError(
            f"{path}: maximum_searches_per_perf_batch must be 1.."
            f"{PERF_BATCH_MAX_OPERATIONS}"
        )
    if (
            not isinstance(minimum_batches, int)
            or isinstance(minimum_batches, bool) or minimum_batches < 15):
        raise MergeError(
            f"{path}: minimum_independent_instruction_batches must be at least 15"
        )
    return dict(gates)


def _merged_artifact_manifest(
        bundles: Sequence[Bundle], binary_groups: Sequence[Mapping[str, Any]],
        workload_contract: Mapping[str, Any], duplicate_bundles: Sequence[Mapping[str, Any]],
        *, status: str, release_timing_evidence: bool,
        acceptance_gate_status: str, correctness_status: str,
        schedule_assessment: Mapping[str, Any],
        matrix_assessment: Mapping[str, Any],
        matrix_plan_sha256: str,
        matrix_plan_file_sha256: str,
        matrix_plan_authoritative: bool,
        release_conclusion: Mapping[str, Any],
        ) -> Dict[str, Any]:
    plan = _load_json(DEFAULT_REVISION_PLAN) if DEFAULT_REVISION_PLAN.is_file() else {}
    source_run_ids = [bundle.run_id for bundle in bundles]
    source_host_classes = sorted({
        _host_class(bundle.run_manifest, _host_mapping(bundle.run_manifest))
        or "unrecorded"
        for bundle in bundles
    })
    merged_host_class = (
        source_host_classes[0] if len(source_host_classes) == 1 else "mixed"
    )
    return {
        "format_version": 1,
        "manifest_kind": "large-filter-study-merged-artifacts",
        "status": status,
        "matrix_completion_status": matrix_assessment["status"],
        "matrix_plan_sha256": matrix_plan_sha256,
        "matrix_plan_file_sha256": matrix_plan_file_sha256,
        "matrix_plan_authoritative": matrix_plan_authoritative,
        "matrix_completion": dict(matrix_assessment),
        "release_conclusion": dict(release_conclusion),
        "acceptance_gate_overall_status": acceptance_gate_status,
        "correctness_status": correctness_status,
        "schedule_assessment": dict(schedule_assessment),
        "correctness_only": not release_timing_evidence,
        "release_timing_evidence": release_timing_evidence,
        "timing_claims_allowed": release_timing_evidence,
        "host_class": merged_host_class,
        "source_host_classes": source_host_classes,
        "source_run_ids": source_run_ids,
        "source_run_count": len(source_run_ids),
        "duplicate_bundle_count": len(duplicate_bundles),
        "workload_sha256": workload_contract["workload_sha256"],
        "workload_manifest_sha256": workload_contract["workload_manifest_sha256"],
        "release_timing_evidence_present": release_timing_evidence,
        "correctness_only_evidence_present": any(
            bundle.run_manifest.get("correctness_only") is True
            for bundle in bundles
        ),
        "validation_only_evidence_present": any(
            not bundle.release_candidate for bundle in bundles
        ),
        "nonrelease_evidence_can_satisfy_performance_gates": False,
        "production_equivalent_revisions": plan.get(
            "production_equivalent_revisions",
            PRODUCTION_EQUIVALENT_REVISIONS,
        ),
        "binary_deduplication": plan.get("binary_deduplication", {
            "identity_field": "installed executable SHA-256",
            "policy": "Identical executable SHA-256 values are one binary identity.",
        }),
        "binary_groups": list(binary_groups),
        "source_bundles": [{
            "run_id": bundle.run_id,
            "source_directory": str(bundle.root),
            "artifact_manifest_sha256": sha256_bytes(
                canonical_json_bytes(bundle.artifact_manifest)
            ),
            "run_manifest_sha256": sha256_bytes(canonical_json_bytes(bundle.run_manifest)),
            "correctness_manifest_sha256": (
                sha256_bytes(canonical_json_bytes(bundle.correctness_manifest))
                if bundle.correctness_manifest else None
            ),
            "raw_results_sha256": bundle.raw_digest,
            "release_candidate": bundle.release_candidate,
            "disposition_reasons": bundle.disposition_reasons,
        } for bundle in bundles],
        "duplicate_bundles_ignored": list(duplicate_bundles),
    }


def merge_result_directories(
        result_directories: Sequence[Path], output: Path, *,
        gates_path: Path = DEFAULT_GATES,
        matrix_plan_path: Path = DEFAULT_MATRIX_PLAN,
        unsafe_include_nonrelease: bool = False) -> Dict[str, Any]:
    gates_path = gates_path.resolve()
    gates = _load_gates(gates_path)
    gates_sha256 = sha256_bytes(canonical_json_bytes(gates))
    gates_file_sha256 = sha256_bytes(gates_path.read_bytes())
    gates_authoritative = gates_sha256 == AUTHORITATIVE_GATES_SHA256
    loaded = [load_bundle(Path(path)) for path in result_directories]
    bundles, duplicate_bundles = validate_bundles(loaded)
    schedule_assessment = assess_schedules(bundles)
    matrix_plan_path = matrix_plan_path.resolve()
    matrix_plan = _load_matrix_plan(
        matrix_plan_path, bundles[0].workload,
    )
    matrix_plan_sha256 = sha256_bytes(canonical_json_bytes(matrix_plan))
    matrix_plan_file_sha256 = sha256_bytes(matrix_plan_path.read_bytes())
    matrix_plan_authoritative = (
        matrix_plan_sha256 == AUTHORITATIVE_MATRIX_PLAN_SHA256
    )

    def harness_binding_failures(
            relative: str, expected_sha256: str) -> list[str]:
        failures: list[str] = []
        for bundle in bundles:
            if bundle.run_manifest.get("evidence_contract_version") != (
                    NATIVE_EVIDENCE_CONTRACT_VERSION):
                continue
            observed = _nested(
                bundle.run_manifest, "harness_identity", "files", relative,
            )
            if observed != expected_sha256:
                failures.append(
                    f"{bundle.run_id}:{relative}={observed!r}"
                )
        return failures

    matrix_plan_binding_failures = harness_binding_failures(
        "workload/native-matrix-plan.json", matrix_plan_file_sha256,
    )
    gates_binding_failures = harness_binding_failures(
        "workload/acceptance-gates.json", gates_file_sha256,
    )
    policy_contract_status = (
        "pass" if (
            matrix_plan_authoritative and gates_authoritative
            and not matrix_plan_binding_failures
            and not gates_binding_failures
        ) else "pending"
    )
    rows = normalize_rows(bundles)
    perf_batches = normalize_perf_batches(
        bundles, rows,
        int(gates["reporting"].get(
            "maximum_searches_per_perf_batch", PERF_BATCH_MAX_OPERATIONS,
        )),
    )
    correctness_controls = normalize_correctness_controls(bundles)
    binary_groups = build_binary_groups(bundles)
    minimum_repeats = int(gates["reporting"]["minimum_native_measured_repeats"])
    release_rows = [row for row in rows if row["release_eligible"]]
    release_summaries = summarize_rows(
        release_rows, binary_groups, minimum_repeats, perf_batches,
    )
    ordered_run_ids = {
        str(run_id)
        for block in schedule_assessment.get("blocks", [])
        if block.get("status") == "pass"
        for run_id in block.get("run_ids_by_position", {}).values()
    }
    causal_release_rows = [
        row for row in release_rows if row["run_id"] in ordered_run_ids
    ]
    causal_release_summaries = summarize_rows(
        causal_release_rows, binary_groups, minimum_repeats, perf_batches,
    )
    exploratory_release_rows = [
        row for row in release_rows if row["run_id"] not in ordered_run_ids
    ]
    exploratory_release_summaries = summarize_rows(
        exploratory_release_rows, binary_groups, minimum_repeats, perf_batches,
    )
    unsafe_rows = [
        row for row in rows
        if not row["release_eligible"]
        and row["phase"] == "measured"
        and row["correctness"]["passed"]
        and row["correctness"]["complete"]
        and row["metrics"]["elapsed_seconds"] is not None
    ]
    unsafe_summaries = (
        summarize_rows(unsafe_rows, binary_groups, minimum_repeats, perf_batches)
        if unsafe_include_nonrelease else []
    )
    comparisons = build_comparisons(release_summaries, gates)
    causal_comparisons = build_comparisons(
        causal_release_summaries, gates,
    )
    exploratory_comparisons = build_comparisons(
        exploratory_release_summaries, gates,
    )
    openldap_context = build_openldap_context(release_summaries)
    scaling_tables = build_scaling_tables(release_summaries, gates)
    causal_openldap_context = build_openldap_context(
        causal_release_summaries
    )
    causal_scaling_tables = build_scaling_tables(
        causal_release_summaries, gates,
    )
    acceptance_gate_results = build_acceptance_gate_results(
        bundles, rows, perf_batches, correctness_controls,
        causal_release_summaries, gates,
    )
    any_native_bundle = any(bundle.release_candidate for bundle in bundles)
    if any(summary["release_ready"] for summary in release_summaries):
        status = "native-results-available"
    elif release_rows or any_native_bundle:
        status = "native-results-incomplete"
    else:
        status = "native-results-pending"
    acceptance_gate_status = (
        "fail" if any(
            gate["status"] == "fail" for gate in acceptance_gate_results
        ) else "pending" if any(
            gate["status"] == "pending" for gate in acceptance_gate_results
        ) else "pass"
    )
    correctness_status = next(
        gate["status"] for gate in acceptance_gate_results
        if gate["gate_id"] == "exact-result-parity"
    )
    matrix_assessment = assess_matrix_completion(
        matrix_plan, bundles[0].workload, causal_release_summaries,
        correctness_controls, schedule_assessment,
        workload_contract=bundles[0].workload_contract,
        plan_authoritative=matrix_plan_authoritative,
        plan_binding_failures=matrix_plan_binding_failures,
    )
    if (
            (gates_authoritative and acceptance_gate_status == "fail")
            or (
                matrix_plan_authoritative
                and matrix_assessment["status"] == "fail"
            )):
        release_conclusion_status = "fail"
        release_recommendation = "do-not-release"
        release_reason = (
            "at least one authoritative acceptance or matrix requirement failed"
        )
    elif policy_contract_status != "pass":
        release_conclusion_status = "pending"
        release_recommendation = "withheld"
        release_reason = (
            "release authority is withheld because the selected gates/plan "
            "are non-authoritative or not bound by every modern harness"
        )
    elif (
            acceptance_gate_status == "pass"
            and matrix_assessment["status"] == "complete"
            and schedule_assessment["status"] == "complete"):
        release_conclusion_status = "pass"
        release_recommendation = "eligible-for-release"
        release_reason = (
            "the frozen matrix, ABBA schedule, and all ten gates passed"
        )
    else:
        release_conclusion_status = "pending"
        release_recommendation = "withheld"
        release_reason = (
            "release authority remains pending until the frozen matrix, "
            "ABBA schedule, and all ten gates pass"
        )
    release_conclusion = {
        "status": release_conclusion_status,
        "recommendation": release_recommendation,
        "reason": release_reason,
        "acceptance_gate_status": acceptance_gate_status,
        "matrix_completion_status": matrix_assessment["status"],
        "schedule_status": schedule_assessment["status"],
        "policy_contract_status": policy_contract_status,
        "matrix_plan_authoritative": matrix_plan_authoritative,
        "acceptance_gates_authoritative": gates_authoritative,
        "matrix_plan_binding_failures": matrix_plan_binding_failures,
        "acceptance_gates_binding_failures": gates_binding_failures,
    }
    release_timing_evidence = bool(release_rows)
    source_host_classes = sorted({
        _host_class(bundle.run_manifest, _host_mapping(bundle.run_manifest))
        or "unrecorded"
        for bundle in bundles
    })
    merged_host_class = (
        source_host_classes[0] if len(source_host_classes) == 1 else "mixed"
    )

    merged_raw = {
        "format_version": 1,
        "manifest_kind": "large-filter-study-merged-raw-results",
        "status": status,
        "correctness_status": correctness_status,
        "correctness_only": not release_timing_evidence,
        "release_timing_evidence": release_timing_evidence,
        "timing_claims_allowed": release_timing_evidence,
        "host_class": merged_host_class,
        "source_host_classes": source_host_classes,
        "matrix_completion_status": matrix_assessment["status"],
        "matrix_plan_sha256": matrix_plan_sha256,
        "matrix_plan": matrix_plan,
        "matrix_completion": matrix_assessment,
        "release_conclusion": release_conclusion,
        "unsafe_include_nonrelease": unsafe_include_nonrelease,
        "release_timing_evidence_present": release_timing_evidence,
        "correctness_only_evidence_present": any(
            bundle.run_manifest.get("correctness_only") is True
            for bundle in bundles
        ),
        "validation_only_evidence_present": any(
            not bundle.release_candidate for bundle in bundles
        ),
        "nonrelease_evidence_present": any(
            not row["release_eligible"] for row in rows
        ) or bool(correctness_controls),
        "nonrelease_evidence_can_satisfy_performance_gates": False,
        "workload_validation": bundles[0].workload_contract,
        "acceptance_gates_sha256": gates_sha256,
        "acceptance_gates_file_sha256": gates_file_sha256,
        "acceptance_gates_authoritative": gates_authoritative,
        "policy_contract_status": policy_contract_status,
        "matrix_plan_binding_failures": matrix_plan_binding_failures,
        "acceptance_gates_binding_failures": gates_binding_failures,
        "acceptance_gates": gates,
        "source_run_ids": [bundle.run_id for bundle in bundles],
        "source_run_count": len(bundles),
        "duplicate_bundle_count": len(duplicate_bundles),
        "duplicate_bundles_ignored": duplicate_bundles,
        "rows": rows,
        "perf_batches": perf_batches,
        "correctness_controls": correctness_controls,
        "release_summaries": release_summaries,
        "causal_release_summaries": causal_release_summaries,
        "exploratory_release_summaries": exploratory_release_summaries,
        "release_comparisons": comparisons,
        "causal_release_comparisons": causal_comparisons,
        "exploratory_release_comparisons": exploratory_comparisons,
        "openldap_contextual_comparisons": openldap_context,
        "release_scaling_tables": scaling_tables,
        "causal_openldap_contextual_comparisons": causal_openldap_context,
        "causal_release_scaling_tables": causal_scaling_tables,
        "acceptance_gate_results": acceptance_gate_results,
        "acceptance_gate_overall_status": acceptance_gate_status,
        "schedule_assessment": schedule_assessment,
        "unsafe_nonrelease_summaries": unsafe_summaries,
    }
    merged_artifacts = _merged_artifact_manifest(
        bundles, binary_groups, bundles[0].workload_contract, duplicate_bundles,
        status=status,
        release_timing_evidence=release_timing_evidence,
        acceptance_gate_status=acceptance_gate_status,
        correctness_status=correctness_status,
        schedule_assessment=schedule_assessment,
        matrix_assessment=matrix_assessment,
        matrix_plan_sha256=matrix_plan_sha256,
        matrix_plan_file_sha256=matrix_plan_file_sha256,
        matrix_plan_authoritative=matrix_plan_authoritative,
        release_conclusion=release_conclusion,
    )
    report = render_results(
        status, bundles, rows, perf_batches, correctness_controls,
        binary_groups, causal_release_summaries,
        exploratory_release_summaries, unsafe_summaries,
        causal_comparisons, exploratory_comparisons,
        causal_openldap_context, causal_scaling_tables,
        acceptance_gate_results, schedule_assessment, matrix_assessment,
        release_conclusion, duplicate_bundles,
        unsafe_include_nonrelease, minimum_repeats,
    )
    with atomic_output_directory(output) as temporary:
        _write_json(temporary / "merged-raw-results.json", merged_raw)
        _write_json(temporary / "artifact-manifest.json", merged_artifacts)
        _write_text(temporary / "RESULTS.md", report)
    return {
        "status": status,
        "matrix_completion_status": matrix_assessment["status"],
        "release_conclusion_status": release_conclusion_status,
        "output": str(output.resolve()),
        "release_rows": len(release_rows),
        "excluded_rows": len(rows) - len(release_rows),
        "binary_groups": len(binary_groups),
        "release_summaries": len(release_summaries),
        "release_comparisons": len(comparisons),
        "acceptance_gate_overall_status": merged_raw[
            "acceptance_gate_overall_status"
        ],
        "schedule_status": schedule_assessment["status"],
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and merge independent large-filter study result directories",
    )
    parser.add_argument(
        "result_directories", metavar="RESULT_DIR", nargs="+", type=Path,
        help="result directory containing workload/artifact/run manifests and raw results",
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="new output directory for merged artifacts",
    )
    parser.add_argument(
        "--gates", type=Path, default=DEFAULT_GATES,
        help=f"predeclared acceptance gates (default: {DEFAULT_GATES})",
    )
    parser.add_argument(
        "--matrix-plan", type=Path, default=DEFAULT_MATRIX_PLAN,
        help=f"frozen native matrix plan (default: {DEFAULT_MATRIX_PLAN})",
    )
    parser.add_argument(
        "--unsafe-include-nonrelease", action="store_true",
        help="show correctness-only/emulated timing summaries in a NON-RELEASE appendix",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        result = merge_result_directories(
            args.result_directories,
            args.output,
            gates_path=args.gates,
            matrix_plan_path=args.matrix_plan,
            unsafe_include_nonrelease=args.unsafe_include_nonrelease,
        )
    except (MergeError, FileExistsError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
