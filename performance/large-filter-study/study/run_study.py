"""Installed-package correctness and measurement driver.

The driver has two deliberately separate modes:

* ``native-timing`` is accepted only on a non-container Fedora host and
  produces release-eligible rows.
* ``correctness-only`` requires an explicit host class and can exercise the
  same setup/search/artifact path in OrbStack or another development system,
  but every row is permanently marked as non-release evidence.

Neither mode contains package installation or server build functionality.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .platform_info import (
    StudyError,
    backend_runtime_module_closure,
    combined_behavioral_runtime_identity,
    command_path,
    enforce_native_fedora,
    host_metadata,
    installed_rpm_identity,
    metric_delta,
    process_metrics,
    read_text,
    require_commands,
    run_command,
    sha256_bytes,
    sha256_file,
    write_json,
)
from .environment_capture import (
    build_environment_record,
    capture_environment_snapshot,
    write_environment_sidecar,
)
from .revisions import (
    PRODUCTION_EQUIVALENT_REVISIONS,
    REVISION_ROLES,
    analysis_revision_role,
    declared_production_equivalence,
    production_equivalent_revision,
)
from .server_runtime import (
    DS389Runtime,
    SUFFIX,
    ServerRuntime,
    create_runtime,
    internal_access_lines,
)


FORMAT_VERSION = 1
NATIVE_EVIDENCE_CONTRACT_VERSION = 2
ALLOWED_NATIVE_PREWARM_PASSES = frozenset({2, 3})
STUDY_ROOT = Path(__file__).resolve().parents[1]
LOOKUP_PATTERN = re.compile(
    r"OR filter equality lookup engaged: (\d+) node\(s\), largest (\d+) branches"
)
CAP_PATTERN = re.compile(
    r"costly AND component returned ALLIDS under read cap (\d+)"
)
CANDIDATE_PATTERN = re.compile(r"Candidate list has (\d+) ids")
STAT_PATTERN = re.compile(
    r"STAT read index: attribute=(\S+) key\(([^)]+)\)=(.*?) --> count (\d+) "
    r"\(duration ([0-9.]+)\)"
)
AVA_PATTERN = re.compile(
    r"=>\s*AVA:\s*([A-Za-z][A-Za-z0-9-]*(?:;[A-Za-z0-9-]+)*)"
    r"\s*(?:~=|>=|<=|=)",
    re.I,
)

CAPABLE_REVISIONS = {
    REVISION_ROLES[name]
    for name in (
        "bounded-feature", "combined-diagnostic", "dynamic-list-fix",
        "all-family-fix", "largest-family-fix", "lifecycle-tests",
        "asan-harness", "final",
    )
}
LOOKUP_REVISIONS = {
    REVISION_ROLES[name]
    for name in (
        "combined-diagnostic", "dynamic-list-fix", "all-family-fix",
        "largest-family-fix", "lifecycle-tests", "asan-harness", "final",
    )
}
DYNAMIC_PRE_FIX_CAP_REVISIONS = {
    REVISION_ROLES["bounded-feature"],
    REVISION_ROLES["combined-diagnostic"],
}
DYNAMIC_SAFE_REVISIONS = {
    REVISION_ROLES[name]
    for name in (
        "dynamic-list-fix", "all-family-fix", "largest-family-fix",
        "lifecycle-tests", "asan-harness", "final",
    )
}
NORMAL_PRIMARY_ATTRIBUTES = [
    "uid", "cn", "sString1", "sString2", "sString3", "sString4",
    "sDN1", "sDN2",
]
PERF_EVENTS = [
    "instructions", "cycles", "branches", "branch-misses", "cache-misses"
]
PERF_SOFTWARE_FALLBACK_EVENTS = ["task-clock"]
PROFILE_SOFTWARE_FALLBACK_EVENT = "cpu-clock"
PROFILE_OPERATION_COUNT = 20
PERF_BATCH_MAX_SEARCHES = 5
PERF_RUNNER_BATCH_SEARCHES = 1
LDAP_RESULT_CODES = {
    "LDAP_SUCCESS": 0,
    "LDAP_TIMELIMIT_EXCEEDED": 3,
    "LDAP_SIZELIMIT_EXCEEDED": 4,
    "LDAP_ADMINLIMIT_EXCEEDED": 11,
}
PROFILE_LOOKUP_SYMBOLS = (
    "vattr_test_filter_or_lookup",
    "filter_or_lookup_probe",
)
FEDORA_STABLE_PACKAGE_REVISION = "fedora-stable-package"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_revision(value: str, server: str) -> tuple[str, str | None]:
    lowered = value.lower()
    if lowered in REVISION_ROLES:
        source_revision = REVISION_ROLES[lowered]
        return source_revision, analysis_revision_role(source_revision)
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return lowered, analysis_revision_role(lowered)
    if server == "389ds" and lowered in {
            "fedora-package", FEDORA_STABLE_PACKAGE_REVISION}:
        return FEDORA_STABLE_PACKAGE_REVISION, "fedora-stable-package"
    if server == "openldap" and value in {"fedora-package", "packaged-openldap"}:
        return value, "openldap-fedora-package"
    raise StudyError(
        "--expected-source-sha must be a 40-hex revision, a documented revision "
        "role, fedora-stable-package for an exploratory 389 DS screen, or "
        "fedora-package for OpenLDAP"
    )


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StudyError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise StudyError(f"expected a JSON object in {path}")
    return value


def harness_identity() -> dict[str, Any]:
    """Content-address the executable study and record its committed revision."""
    files: dict[str, str] = {}
    roots = (STUDY_ROOT / "bin", STUDY_ROOT / "study", STUDY_ROOT / "workload")
    candidates = [STUDY_ROOT / "artifact-manifest.json"]
    for root in roots:
        candidates.extend(sorted(root.rglob("*")))
    for path in sorted(set(candidates)):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise StudyError(f"harness identity refuses symlinked input: {path}")
        relative = path.relative_to(STUDY_ROOT).as_posix()
        files[relative] = sha256_file(path)
    if not files:
        raise StudyError("harness identity found no executable study files")
    content_sha256 = sha256_bytes(json.dumps(
        {"format_version": 1, "files": files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))
    identity: dict[str, Any] = {
        "format_version": 1,
        "content_sha256": content_sha256,
        "files": files,
        "git_head": None,
        "git_tree": None,
        "git_status_porcelain": None,
        "git_study_tree_clean": False,
        "git_evidence_status": "unavailable",
    }
    git = command_path("git")
    if git:
        top = run_command(
            [git, "-C", str(STUDY_ROOT), "rev-parse", "--show-toplevel"],
            check=False,
            timeout=30,
        )
        if top.returncode == 0 and top.stdout.strip():
            repository = Path(top.stdout.strip()).resolve()
            try:
                scoped_path = STUDY_ROOT.resolve().relative_to(repository).as_posix()
            except ValueError as error:
                raise StudyError("study directory is outside its reported git root") from error
            head = run_command(
                [git, "-C", str(repository), "rev-parse", "HEAD"],
                check=False,
                timeout=30,
            )
            tree = run_command(
                [git, "-C", str(repository), "rev-parse", "HEAD^{tree}"],
                check=False,
                timeout=30,
            )
            status = run_command(
                [
                    git, "-C", str(repository), "status", "--porcelain=v1",
                    "--untracked-files=all", "--", scoped_path,
                ],
                check=False,
                timeout=60,
            )
            if head.returncode == tree.returncode == status.returncode == 0:
                identity.update({
                    "git_head": head.stdout.strip().casefold(),
                    "git_tree": tree.stdout.strip().casefold(),
                    "git_status_porcelain": status.stdout,
                    "git_study_tree_clean": not status.stdout.strip(),
                    "git_evidence_status": "observed",
                    "git_scoped_path": scoped_path,
                })
    return identity


def invocation_evidence(argv: Sequence[str]) -> dict[str, Any]:
    """Record the exact top-level command while redacting secret values."""
    redacted: list[str] = []
    redact_next = False
    for value in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(value)
        if value in {"-w", "--password", "--bind-password"}:
            redact_next = True
    return {
        "argv": redacted,
        "shell_escaped": shlex.join(redacted),
        "credentials_redacted": redacted != list(argv),
    }


def verify_workload(workload: Path) -> dict[str, Any]:
    manifest_path = workload / "workload-manifest.json"
    manifest = load_json(manifest_path)
    if manifest.get("format_version") != FORMAT_VERSION:
        raise StudyError(f"unsupported workload format: {manifest.get('format_version')!r}")
    files = manifest.get("files")
    if not isinstance(files, Mapping) or not files:
        raise StudyError("workload manifest has no non-empty files hash mapping")
    failures: list[str] = []
    for relative, expected in files.items():
        path = (workload / str(relative)).resolve()
        try:
            path.relative_to(workload.resolve())
        except ValueError:
            failures.append(f"unsafe path {relative}")
            continue
        if not path.is_file():
            failures.append(f"missing {relative}")
        else:
            actual = sha256_file(path)
            if actual != expected:
                failures.append(f"hash {relative}: {actual} != {expected}")
    if failures:
        raise StudyError("workload validation failed: " + "; ".join(failures[:20]))
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, Mapping) or not scenarios:
        raise StudyError("workload manifest contains no scenarios")
    import_oracles = manifest.get("dataset_import_oracles")
    entry_counts = manifest.get("entry_counts")
    if not isinstance(import_oracles, Mapping) or set(import_oracles) != {
            "people", "principal_outer_cohort"}:
        raise StudyError(
            "workload manifest requires people and principal_outer_cohort "
            "dataset import oracles"
        )
    expected_import_counts = {
        "people": (
            entry_counts.get("people") if isinstance(entry_counts, Mapping)
            else None
        ),
        "principal_outer_cohort": (
            entry_counts.get("principal_cohort")
            if isinstance(entry_counts, Mapping) else None
        ),
    }
    for oracle_id, expected_count in expected_import_counts.items():
        contract = import_oracles.get(oracle_id)
        if (
                not isinstance(contract, Mapping)
                or contract.get("expected_result_code") != "LDAP_SUCCESS"
                or contract.get("expected_count") != expected_count
                or not isinstance(contract.get("expected_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", contract["expected_sha256"])):
            raise StudyError(
                f"workload manifest has an invalid {oracle_id} import oracle"
            )
    return manifest


def copy_workload_payload(
    workload: Path, manifest: Mapping[str, Any], destination: Path
) -> None:
    """Make a result bundle independently auditable and re-runnable."""
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        workload / "workload-manifest.json",
        destination / "workload-manifest.json",
    )
    for relative in manifest["files"]:
        source = (workload / str(relative)).resolve()
        target = (destination / str(relative)).resolve()
        try:
            target.relative_to(destination.resolve())
        except ValueError as error:
            raise StudyError(f"unsafe workload payload path: {relative}") from error
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def enforce_native_workload_manifest(manifest: Mapping[str, Any]) -> None:
    """Require the immutable full-profile contract for release timing."""
    problems: list[str] = []
    if manifest.get("profile") != "full":
        problems.append("profile is not 'full'")
    if manifest.get("host_intent") != "native_fedora_timing":
        problems.append("host_intent is not native_fedora_timing")
    if manifest.get("correctness_only") is not False:
        problems.append("correctness_only is not false")
    if manifest.get("release_timing_evidence") is not True:
        problems.append("release_timing_evidence is not true")
    if manifest.get("entries") != 100_000:
        problems.append("entries is not exactly 100000")

    entry_counts = manifest.get("entry_counts")
    entry_counts = entry_counts if isinstance(entry_counts, Mapping) else {}
    if entry_counts.get("people") != 100_000:
        problems.append("entry_counts.people is not exactly 100000")
    if entry_counts.get("principal_cohort") != 612:
        problems.append("entry_counts.principal_cohort is not exactly 612")

    primary = manifest.get("primary_contract")
    primary = primary if isinstance(primary, Mapping) else {}
    if primary.get("people") != 100_000:
        problems.append("primary_contract.people is not exactly 100000")
    if primary.get("logical_outer_cohort") != 612:
        problems.append("primary_contract.logical_outer_cohort is not exactly 612")
    if primary.get("dn_branches") != 355:
        problems.append("primary_contract.dn_branches is not exactly 355")

    scenarios = manifest.get("scenarios")
    scenarios = scenarios if isinstance(scenarios, Mapping) else {}
    principal = scenarios.get("principal-with-sdn2-equality")
    principal = principal if isinstance(principal, Mapping) else {}
    if principal.get("logical_outer_cohort_count") != 612:
        problems.append("primary scenario outer cohort is not exactly 612")
    lookup = principal.get("expected_lookup_diagnostic")
    lookup = lookup if isinstance(lookup, Mapping) else {}
    if lookup.get("largest_family") != 355:
        problems.append("primary scenario largest DN family is not exactly 355")
    if problems:
        raise StudyError(
            "native timing requires the exact full workload contract: "
            + "; ".join(problems)
        )


def select_scenarios(
    manifest: Mapping[str, Any],
    *,
    requested: Sequence[str],
    groups: Sequence[str],
    smoke_selected: bool,
    server: str,
    index_config: str,
) -> list[str]:
    scenarios = manifest["scenarios"]
    selected: list[str] = []

    def add(identifier: str) -> None:
        if identifier not in scenarios:
            raise StudyError(f"unknown scenario: {identifier}")
        if identifier not in selected:
            selected.append(identifier)

    for identifier in requested:
        add(identifier)
    group_map = manifest.get("scenario_groups", {})
    for group in groups:
        if group not in group_map:
            raise StudyError(f"unknown scenario group: {group}")
        for identifier in group_map[group]:
            add(identifier)
    if smoke_selected:
        for identifier, scenario in scenarios.items():
            if scenario.get("smoke_selected"):
                add(identifier)
    if not selected:
        add("principal-with-sdn2-equality")
        add("principal-without-sdn2-equality")

    compatible: list[str] = []
    for identifier in selected:
        scenario = scenarios[identifier]
        if server not in scenario.get("server_support", []):
            if smoke_selected:
                continue
            raise StudyError(f"scenario {identifier} does not support {server}")
        required_index = scenario.get("index_variant", "baseline-no-presence")
        if required_index != index_config:
            if smoke_selected:
                continue
            raise StudyError(
                f"scenario {identifier} requires index configuration {required_index}, "
                f"but this run requested {index_config}"
            )
        compatible.append(identifier)
    if not compatible:
        raise StudyError("no selected scenario is compatible with this server/index configuration")
    return compatible


def expected_dns(workload: Path, scenario: Mapping[str, Any]) -> tuple[list[str], str]:
    path = workload / scenario["expected_file"]
    text = path.read_text(encoding="utf-8")
    values = sorted(line.strip().lower() for line in text.splitlines() if line.strip())
    digest = sha256_bytes("".join(f"{dn}\n" for dn in values).encode("utf-8"))
    if len(values) != scenario["expected_count"] or digest != scenario["expected_sha256"]:
        raise StudyError(
            f"independent expectation file {path} disagrees with its manifest metadata"
        )
    return values, digest


def dns_digest(values: Iterable[str]) -> str:
    normalized = sorted(value.lower() for value in values)
    return sha256_bytes("".join(f"{dn}\n" for dn in normalized).encode("utf-8"))


def ldap_result_code_value(value: Any, context: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().upper().replace("-", "_")
        if normalized.isdigit():
            return int(normalized)
        if normalized in LDAP_RESULT_CODES:
            return LDAP_RESULT_CODES[normalized]
    raise StudyError(f"{context}: invalid expected LDAP result code {value!r}")


def assert_correct(
    scenario_id: str,
    result: Any,
    expected: Sequence[str],
    expected_hash: str,
    expected_result_code: Any = "LDAP_SUCCESS",
) -> None:
    expected_code = ldap_result_code_value(expected_result_code, scenario_id)
    if result.returncode != expected_code:
        raise StudyError(
            f"{scenario_id}: LDAP result code {result.returncode}, "
            f"expected {expected_code}: {result.stderr.strip()}"
        )
    if result.dns != list(expected):
        raise StudyError(
            f"{scenario_id}: exact DN mismatch: returned {len(result.dns)} "
            f"({dns_digest(result.dns)}), expected {len(expected)} ({expected_hash})"
        )


def parse_access_result(implementation: str, text: str) -> dict[str, Any]:
    lines = text.splitlines()
    if implementation == "389ds":
        result_lines = [
            line for line in lines
            if " RESULT " in line and "tag=101" in line
            and not internal_access_lines(line)
        ]
    else:
        result_lines = [line for line in lines if "SEARCH RESULT" in line]
    line = result_lines[-1] if result_lines else ""
    etime_match = re.search(r"etime=([0-9.]+)", line)
    count_match = re.search(r"nentries=(\d+)", line)
    notes_match = re.search(r"notes=([^\s]+)", line)
    error_match = re.search(r"(?:err|errCode)=([0-9]+)", line)
    return {
        "raw": line,
        "server_etime_seconds": float(etime_match.group(1)) if etime_match else None,
        "server_nentries": int(count_match.group(1)) if count_match else None,
        "server_notes": notes_match.group(1).strip('"') if notes_match else "",
        "server_result_code": int(error_match.group(1)) if error_match else None,
        "result_line_count": len(result_lines),
    }


def parse_diagnostics(error_text: str, access_text: str) -> dict[str, Any]:
    lookups = [(int(nodes), int(largest)) for nodes, largest in LOOKUP_PATTERN.findall(error_text)]
    caps = [int(value) for value in CAP_PATTERN.findall(error_text)]
    candidates = [int(value) for value in CANDIDATE_PATTERN.findall(error_text)]
    stat_reads = [
        {
            "attribute": match.group(1),
            "index_type": match.group(2),
            "key": match.group(3),
            "posting_count": int(match.group(4)),
            "duration_seconds": float(match.group(5)),
        }
        for match in STAT_PATTERN.finditer(access_text)
    ]
    ava_attributes = [match.group(1) for match in AVA_PATTERN.finditer(error_text)]
    ava_counts: dict[str, int] = {}
    for attribute in ava_attributes:
        canonical = attribute.casefold()
        ava_counts[canonical] = ava_counts.get(canonical, 0) + 1
    candidate_status = "observed" if len(candidates) == 1 else (
        "not-observed" if not candidates else "ambiguous-multiple-traces"
    )
    return {
        "lookup_summaries": [
            {"node_count": nodes, "largest_family": largest} for nodes, largest in lookups
        ],
        "lookup_constructed": bool(lookups),
        "cap_values": caps,
        "cap_path_observed": bool(caps),
        "candidate_list_values": candidates,
        "candidate_list_status": candidate_status,
        "observed_final_candidate_count": candidates[0] if len(candidates) == 1 else None,
        "stat_index_reads": stat_reads,
        "stat_index_read_count": len(stat_reads),
        "filter_ava_attributes": ava_attributes,
        "filter_ava_attribute_counts": dict(sorted(ava_counts.items())),
    }


def mechanism_gate(
    *,
    server: str,
    revision: str,
    lookup_mode: str,
    scenario: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
) -> list[str]:
    if server != "389ds":
        return []
    revision = production_equivalent_revision(revision)
    failures: list[str] = []
    expected = scenario.get("expected_diagnostics", {})
    lookup = expected.get("or_lookup", {})
    lookup_expectation = lookup.get("expectation", "not-applicable")
    capable_lookup = revision in LOOKUP_REVISIONS
    if lookup_mode == "off" and diagnostics["lookup_constructed"]:
        failures.append("lookup-off search still logged lookup construction")
    if (
        lookup_mode == "on"
        and lookup_expectation.startswith("forbidden")
        and diagnostics["lookup_constructed"]
    ):
        failures.append(
            "equality lookup construction appeared on an intentional "
            "below-threshold/unsupported shape"
        )
    if (
        lookup_mode == "on"
        and capable_lookup
        and lookup_expectation == "required-when-lookup-on"
    ):
        if not diagnostics["lookup_constructed"]:
            failures.append("required equality lookup construction diagnostic is absent")
        largest = lookup.get("largest_family")
        if largest is not None and largest not in {
            row["largest_family"] for row in diagnostics["lookup_summaries"]
        }:
            failures.append(f"lookup diagnostic did not report largest family {largest}")
        selected = lookup.get("selected_attribute")
        evidence = diagnostics.get("direct_selected_family_evidence")
        if (
                selected is not None
                and isinstance(scenario.get("selection_probe"), Mapping)
                and isinstance(evidence, Mapping)):
            observed = evidence.get("selected_attribute")
            if not isinstance(observed, str) or observed.casefold() != str(selected).casefold():
                failures.append(
                    f"FILTER AVA probe did not directly select family {selected}"
                )

    bounded = expected.get("bounded_read", {})
    cap_expectation = bounded.get("expectation", "not-applicable")
    capable_cap = revision in CAPABLE_REVISIONS
    cap_required = (
        capable_cap
        and cap_expectation in {"required", "required-on-bounded-feature-build"}
    )
    cap_forbidden = (
        cap_expectation.startswith("forbidden")
        or cap_expectation.startswith("must-not-engage")
        or cap_expectation == "absent"
    )
    if cap_expectation == "revision-dependent-dynamic-safety":
        if revision in DYNAMIC_PRE_FIX_CAP_REVISIONS:
            cap_required = True
        elif revision in DYNAMIC_SAFE_REVISIONS:
            cap_forbidden = True
        else:
            failures.append(
                "dynamic-list cap expectation is undefined for this revision"
            )
    if cap_required:
        if not diagnostics["cap_path_observed"]:
            failures.append("required bounded-read cap diagnostic is absent")
    if cap_forbidden and diagnostics["cap_path_observed"]:
        failures.append(
            "bounded-read cap appeared after dynamic-list augmentation"
            if cap_expectation == "revision-dependent-dynamic-safety"
            else "bounded-read cap appeared on an intentional decline/adverse shape"
        )

    access = diagnostics.get("access_result", {})
    result_code = access.get("server_result_code") if isinstance(access, Mapping) else None
    expected_code = ldap_result_code_value(
        scenario.get("expected_result_code", "LDAP_SUCCESS"),
        "mechanism gate",
    )
    if result_code is None:
        failures.append("access log did not expose a server LDAP result code")
    elif result_code != expected_code:
        failures.append(
            f"access log reports LDAP result code {result_code}, expected "
            f"{expected_code}"
        )
    if diagnostics.get("candidate_list_status") == "ambiguous-multiple-traces":
        failures.append(
            "multiple candidate-list traces make the diagnostic flight "
            "ambiguous"
        )
    # Access-log notes, including U, are observations rather than predictions
    # derived from index intent.  They remain in every diagnostic and raw row.
    return failures


def _write_diagnostic_window(
        diagnostic_dir: Path, scenario_id: str, phase: str,
        operation: str, window: Mapping[str, str]) -> dict[str, Any]:
    diagnostic_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{scenario_id}.{phase}.{operation}"
    error_path = diagnostic_dir / f"{prefix}.error.log"
    access_path = diagnostic_dir / f"{prefix}.access.log"
    error_path.write_text(window["error"], encoding="utf-8")
    access_path.write_text(window["access"], encoding="utf-8")
    return {
        "error_log": error_path.relative_to(diagnostic_dir.parent).as_posix(),
        "error_log_sha256": sha256_file(error_path),
        "error_log_size_bytes": error_path.stat().st_size,
        "access_log": access_path.relative_to(diagnostic_dir.parent).as_posix(),
        "access_log_sha256": sha256_file(access_path),
        "access_log_size_bytes": access_path.stat().st_size,
    }


def _exact_result_evidence(
        result: Any, expected: Sequence[str], expected_hash: str,
        expected_result_code: Any) -> dict[str, Any]:
    returned_hash = dns_digest(result.dns)
    expected_code = ldap_result_code_value(
        expected_result_code, "exact-result evidence",
    )
    return {
        "evidence_status": "observed",
        "ldap_result_code": result.returncode,
        "actual_client_result_code": result.returncode,
        "expected_ldap_result_code": expected_code,
        "expected_result_code": expected_result_code,
        "returned_count": len(result.dns),
        "returned_sha256": returned_hash,
        "expected_count": len(expected),
        "expected_sha256": expected_hash,
        "exact_count_match": len(result.dns) == len(expected),
        "exact_sha256_match": returned_hash == expected_hash,
        "exact_dns_match": result.dns == list(expected),
        "client_result_code_match": result.returncode == expected_code,
        "passed": (
            result.returncode == expected_code
            and result.dns == list(expected)
            and returned_hash == expected_hash
        ),
    }


def _server_result_evidence(
        access: Mapping[str, Any], expected_result_code: Any,
        context: str) -> dict[str, Any]:
    expected_code = ldap_result_code_value(expected_result_code, context)
    actual = access.get("server_result_code")
    observed = isinstance(actual, int) and not isinstance(actual, bool)
    return {
        "evidence_status": "observed" if observed else "missing",
        "actual_server_result_code": actual,
        "expected_result_code": expected_result_code,
        "expected_ldap_result_code": expected_code,
        "server_result_code_match": observed and actual == expected_code,
        "passed": observed and actual == expected_code,
    }


def _require_server_result(
        access: Mapping[str, Any], expected_result_code: Any,
        context: str) -> dict[str, Any]:
    evidence = _server_result_evidence(
        access, expected_result_code, context,
    )
    if evidence["evidence_status"] != "observed":
        raise StudyError(
            f"{context}: isolated access log has no server LDAP result code"
        )
    if not evidence["passed"]:
        raise StudyError(
            f"{context}: server LDAP result code "
            f"{evidence['actual_server_result_code']}, expected "
            f"{evidence['expected_ldap_result_code']}"
        )
    return evidence


def _selected_approximate_policy(
        manifest: Mapping[str, Any], selected: Sequence[str]
) -> Mapping[str, Any] | None:
    policies = [
        manifest["scenarios"][scenario_id]["cross_server_comparison"]
        for scenario_id in selected
        if isinstance(
            manifest["scenarios"][scenario_id].get(
                "cross_server_comparison"
            ),
            Mapping,
        )
    ]
    if not policies:
        return None
    canonical = {
        json.dumps(policy, sort_keys=True, separators=(",", ":"))
        for policy in policies
    }
    if len(canonical) != 1:
        raise StudyError(
            "selected approximate scenarios do not share one semantic "
            "comparison policy"
        )
    policy = policies[0]
    if policy.get("policy") != "requires-native-equivalence-preflight":
        raise StudyError("unsupported approximate cross-server comparison policy")
    semantic_contract = policy.get("semantic_contract")
    if not isinstance(semantic_contract, Mapping):
        raise StudyError("approximate semantic contract is missing")
    calculated_hash = sha256_bytes(json.dumps(
        semantic_contract,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8"))
    if policy.get("contract_sha256") != calculated_hash:
        raise StudyError("approximate semantic contract hash is invalid")
    return policy


def run_approximate_semantics_preflight(
        *, runtime: ServerRuntime, manifest: Mapping[str, Any],
        selected: Sequence[str], diagnostic_dir: Path) -> dict[str, Any]:
    """Run the declared direct base probes for approximate comparability."""
    policy = _selected_approximate_policy(manifest, selected)
    if policy is None:
        return {
            "status": "not-applicable",
            "evidence_status": "not-planned",
            "contract_sha256": None,
            "probes": [],
        }
    required = policy.get("required_probe_ids")
    probes = policy.get("probes")
    if not isinstance(required, list) or not required:
        raise StudyError("approximate comparison policy has no required probes")
    if not isinstance(probes, Mapping):
        raise StudyError("approximate comparison policy has no probes mapping")
    records: list[dict[str, Any]] = []
    for probe_id_value in required:
        probe_id = str(probe_id_value)
        probe = probes.get(probe_id)
        if not isinstance(probe, Mapping):
            raise StudyError(f"approximate probe {probe_id} is missing")
        count = probe.get("expected_count")
        if count == 0:
            expected: list[str] = []
        elif count == 1:
            expected = [str(probe["base_dn"]).casefold()]
        else:
            raise StudyError(
                f"approximate probe {probe_id} must expect zero or one base DN"
            )
        expected_hash = str(probe.get("expected_sha256", ""))
        if dns_digest(expected) != expected_hash:
            raise StudyError(
                f"approximate probe {probe_id} oracle hash is invalid"
            )
        expected_result_code = probe.get("expected_result_code")
        if expected_result_code is None:
            raise StudyError(
                f"approximate probe {probe_id} expected_result_code is missing"
            )
        result, window, isolation = runtime.search_with_isolated_diagnostics(
            base=str(probe["base_dn"]),
            scope=str(probe.get("scope", "base")),
            filter_text=str(probe["filter"]),
            attributes=list(probe.get("requested_attributes", ["1.1"])),
        )
        access = parse_access_result(runtime.implementation, window["access"])
        exact = _exact_result_evidence(
            result, expected, expected_hash, expected_result_code,
        )
        server = _server_result_evidence(
            access, expected_result_code, f"approximate probe {probe_id}",
        )
        result_line_isolated = access["result_line_count"] == 1
        records.append({
            "probe_id": probe_id,
            "evidence_status": "observed",
            "operation_isolated": True,
            "isolation": isolation,
            "declared_probe": dict(probe),
            "exact_result": exact,
            "access_result": access,
            "server_result_evidence": server,
            "result_line_isolated": result_line_isolated,
            "passed": exact["passed"] and server["passed"]
            and result_line_isolated,
            "diagnostic_artifacts": _write_diagnostic_window(
                diagnostic_dir, "approximate-semantics", "preflight",
                probe_id, window,
            ),
        })
    passed = len(records) == len(required) and all(
        record["passed"] for record in records
    )
    return {
        "status": "comparable" if passed else "unverified",
        "evidence_status": "observed",
        "policy": policy["policy"],
        "contract_sha256": policy["contract_sha256"],
        "semantic_contract": policy["semantic_contract"],
        "required_probe_ids": list(required),
        "probes": records,
    }


def _selection_probe_requested(
        runtime: ServerRuntime, revision: str,
        scenario: Mapping[str, Any]) -> bool:
    revision = production_equivalent_revision(revision)
    groups = set(scenario.get("groups", []))
    return (
        runtime.implementation == "389ds"
        and runtime.actual_lookup_mode == "on"
        and revision in LOOKUP_REVISIONS
        and bool(groups.intersection({"family-discovery", "family-ranking"}))
        and isinstance(scenario.get("selection_probe"), Mapping)
    )


def _historical_selection_baseline(
        revision: str, scenario_id: str) -> bool:
    revision = production_equivalent_revision(revision)
    expected = {
        REVISION_ROLES["combined-diagnostic"]: {
            "flat-family-third-after-distractors",
            "flat-family-ranking-a16-b64",
        },
        REVISION_ROLES["all-family-fix"]: {
            "flat-family-ranking-a16-b64",
        },
    }
    return scenario_id in expected.get(revision, set())


def _expected_historical_selection_failures(
        scenario_id: str, failures: Sequence[str]) -> bool:
    """Limit historical timing waivers to the known family-choice mismatch."""
    allowed_prefixes = [
        "lookup diagnostic did not report largest family ",
        "FILTER AVA probe did not directly select family ",
    ]
    if scenario_id == "flat-family-third-after-distractors":
        allowed_prefixes.append(
            "required equality lookup construction diagnostic is absent"
        )
    return bool(failures) and all(
        failure.startswith(tuple(allowed_prefixes)) for failure in failures
    )


def mechanism_signature_material(
        diagnostics: Mapping[str, Any],
        selected_family: Mapping[str, Any],
        access_result: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize mechanism observations while preserving ambiguity."""
    lookup_pairs = [
        (int(item["node_count"]), int(item["largest_family"]))
        for item in diagnostics.get("lookup_summaries", [])
    ]
    return {
        "lookup_summaries": [
            {"node_count": node_count, "largest_family": largest_family}
            for node_count, largest_family in sorted(lookup_pairs)
        ],
        "cap_values": sorted([
            int(value) for value in diagnostics.get("cap_values", [])
        ]),
        "candidate_list_values": sorted([
            int(value)
            for value in diagnostics.get("candidate_list_values", [])
        ]),
        "candidate_list_status": diagnostics.get("candidate_list_status"),
        "observed_final_candidate_count": diagnostics.get(
            "observed_final_candidate_count"
        ),
        "selected_family": dict(selected_family),
        "server_notes": access_result["server_notes"],
        "server_result_code": access_result["server_result_code"],
    }


def resolve_state_prewarm(args: argparse.Namespace, *, mode: str) -> dict[str, Any]:
    if args.prewarm_passes < 1:
        raise StudyError("--prewarm-passes must be at least 1")
    if args.prewarm == "on" and args.cache_policy == "cold":
        raise StudyError(
            "--prewarm on contradicts --cache-policy cold: the cold policy "
            "drops caches before every measured search"
        )
    enabled = args.prewarm == "on" or (
        args.prewarm == "auto"
        and mode == "native-timing"
        and args.cache_policy == "warm"
    )
    if enabled:
        return {"enabled": True, "status": "pending", "passes": args.prewarm_passes}
    if args.cache_policy == "cold":
        status = "not-applicable-cold-cache"
    elif mode != "native-timing":
        status = "not-applicable-correctness-only"
    else:
        status = "disabled"
    return {"enabled": False, "status": status, "passes": 0}


def run_state_prewarm(
    *,
    runtime: ServerRuntime,
    manifest: Mapping[str, Any],
    passes: int,
) -> dict[str, Any]:
    """Prime server and host caches with full-database scans.

    Screen states run as separate sequential runner invocations, so without
    this the later states always start on a warmer host. The scans are
    deterministic and bundle-independent: every entry passes through the
    entry cache, the backend's page cache, and the host file-system cache
    before any diagnostic or timed search runs. The evidence goes to the run
    manifest only - pre-warm passes are never result rows.
    """
    minimum = manifest.get("entries")
    if not isinstance(minimum, int) or minimum < 1:
        raise StudyError(
            "workload manifest lacks a positive entry count for the state pre-warm"
        )
    records: list[dict[str, Any]] = []
    for iteration in range(1, passes + 1):
        started = time.monotonic_ns()
        result = runtime.search(
            base=SUFFIX,
            scope="sub",
            filter_text="(objectClass=*)",
            attributes=["1.1"],
        )
        elapsed = time.monotonic_ns() - started
        if result.returncode != 0:
            raise StudyError(
                f"state pre-warm pass {iteration} failed with LDAP result "
                f"{result.returncode}: {result.stderr.strip()}"
            )
        if len(result.dns) < minimum:
            raise StudyError(
                f"state pre-warm pass {iteration} returned {len(result.dns)} "
                f"entries, below the workload minimum {minimum}"
            )
        records.append({
            "iteration": iteration,
            "client_elapsed_ns": elapsed,
            "returned_count": len(result.dns),
        })
    return {
        "format_version": 1,
        "status": "completed",
        "policy": "full-database-scan",
        "base_dn": SUFFIX,
        "scope": "sub",
        "filter": "(objectClass=*)",
        "requested_attributes": ["1.1"],
        "requested_passes": passes,
        "executed_passes": len(records),
        "passes": records,
    }


def disabled_state_prewarm(status: str) -> dict[str, Any]:
    return {
        "format_version": 1,
        "status": status,
        "policy": "full-database-scan",
        "requested_passes": 0,
        "executed_passes": 0,
        "passes": [],
    }


def diagnostic_flight(
    *,
    runtime: ServerRuntime,
    scenario_id: str,
    scenario: Mapping[str, Any],
    filter_text: str,
    expected: Sequence[str],
    expected_hash: str,
    revision: str,
    diagnostic_dir: Path,
    phase: str,
) -> dict[str, Any]:
    if phase not in {"preflight", "postflight"}:
        raise StudyError(f"unsupported diagnostic flight phase: {phase}")
    expected_result_code = scenario.get("expected_result_code")
    if expected_result_code is None:
        raise StudyError(f"{scenario_id}: expected_result_code is missing")
    state = runtime.diagnostics_enable(filter_trace=False)
    try:
        result, window, isolation = runtime.search_with_isolated_diagnostics(
            base=scenario["base_dn"],
            scope=scenario.get("scope", "sub"),
            filter_text=filter_text,
            attributes=scenario.get("requested_attributes", ["1.1"]),
        )
        assert_correct(
            scenario_id, result, expected, expected_hash,
            expected_result_code,
        )
    finally:
        runtime.diagnostics_restore(state)

    parsed = parse_diagnostics(window["error"], window["access"])
    parsed["access_result"] = parse_access_result(runtime.implementation, window["access"])
    if parsed["access_result"]["result_line_count"] != 1:
        raise StudyError(
            f"{scenario_id} {phase}: isolated diagnostic window contains "
            f"{parsed['access_result']['result_line_count']} result records"
        )
    server_result_evidence = _require_server_result(
        parsed["access_result"], expected_result_code,
        f"{scenario_id} {phase}",
    )
    notes = parsed["access_result"]["server_notes"]
    parsed["partially_unindexed_note_observed"] = "U" in {
        token.strip() for token in notes.split(",") if token.strip()
    }
    expected_selected = scenario.get("expected_diagnostics", {}).get(
        "or_lookup", {}
    ).get("selected_attribute")
    parsed["selected_family_from_manifest"] = expected_selected
    parsed["selected_family_directly_reported"] = False
    parsed["direct_selected_family_evidence"] = {
        "status": "not-requested",
        "source": "operation-isolated FILTER AVA selection probe",
        "selected_attribute": None,
        "observed_ava_attributes": [],
    }
    selection_probe: dict[str, Any] = {
        "evidence_status": "not-applicable",
        "reason": "FILTER selection tracing was not planned for this operation",
    }
    if _selection_probe_requested(runtime, revision, scenario):
        probe = scenario["selection_probe"]
        probe_dn = str(probe["base_dn"]).lower()
        probe_expected = [probe_dn]
        probe_expected_hash = str(probe["expected_sha256"])
        if probe.get("scope") != "base" or probe.get("expected_count") != 1:
            raise StudyError(f"{scenario_id}: invalid selection_probe contract")
        if dns_digest(probe_expected) != probe_expected_hash:
            raise StudyError(f"{scenario_id}: selection_probe oracle hash is invalid")
        trace_state = runtime.diagnostics_enable(filter_trace=True)
        try:
            probe_result, probe_window, probe_isolation = (
                runtime.search_with_isolated_diagnostics(
                    base=str(probe["base_dn"]),
                    scope="base",
                    filter_text=filter_text,
                    attributes=scenario.get("requested_attributes", ["1.1"]),
                )
            )
            assert_correct(
                f"{scenario_id} selection probe", probe_result,
                probe_expected, probe_expected_hash, "LDAP_SUCCESS",
            )
        finally:
            runtime.diagnostics_restore(trace_state)
        probe_parsed = parse_diagnostics(
            probe_window["error"], probe_window["access"],
        )
        probe_access = parse_access_result(
            runtime.implementation, probe_window["access"],
        )
        if probe_access["result_line_count"] != 1:
            raise StudyError(
                f"{scenario_id} {phase}: isolated selection probe contains "
                f"{probe_access['result_line_count']} result records"
            )
        probe_server_result_evidence = _require_server_result(
            probe_access, "LDAP_SUCCESS",
            f"{scenario_id} {phase} selection probe",
        )
        observed_attributes = sorted({
            value.casefold()
            for value in probe_parsed["filter_ava_attributes"]
        })
        expected_folded = (
            str(expected_selected).casefold()
            if expected_selected is not None else None
        )
        direct_attribute = (
            observed_attributes[0] if len(observed_attributes) == 1 else None
        )
        evidence_status = (
            "observed-expected"
            if direct_attribute is not None
            and direct_attribute == expected_folded
            else "observed-mismatch"
            if direct_attribute is not None
            else "ambiguous"
            if observed_attributes else "not-observed"
        )
        parsed["selected_family_directly_reported"] = direct_attribute is not None
        parsed["direct_selected_family_evidence"] = {
            "status": evidence_status,
            "source": "operation-isolated FILTER AVA selection probe",
            "selected_attribute": direct_attribute,
            "observed_ava_attributes": observed_attributes,
            "expected_attribute": expected_selected,
        }
        selection_probe = {
            "evidence_status": "observed",
            "operation_isolated": True,
            "isolation": probe_isolation,
            "exact_result": _exact_result_evidence(
                probe_result, probe_expected, probe_expected_hash,
                "LDAP_SUCCESS",
            ),
            "diagnostics": probe_parsed,
            "access_result": probe_access,
            "server_result_evidence": probe_server_result_evidence,
            "artifacts": _write_diagnostic_window(
                diagnostic_dir, scenario_id, phase, "selection-probe",
                probe_window,
            ),
        }
    parsed["lookup_consumption_directly_reported"] = False
    parsed["lookup_consumption_status"] = "requires lookup-off/on A/B plus profile"
    failures = mechanism_gate(
        server=runtime.implementation,
        revision=revision,
        lookup_mode=runtime.actual_lookup_mode,
        scenario=scenario,
        diagnostics=parsed,
    )
    historical_baseline = _historical_selection_baseline(
        revision, scenario_id,
    )
    historical_mismatch = (
        historical_baseline
        and _expected_historical_selection_failures(scenario_id, failures)
    )
    if historical_baseline and not failures:
        raise StudyError(
            f"{scenario_id} mechanism {phase} unexpectedly passed the "
            "predeclared historical family-selection control"
        )
    if failures and not historical_mismatch:
        raise StudyError(
            f"{scenario_id} mechanism {phase} failed: " + "; ".join(failures)
        )
    mechanism_signature_material_value = mechanism_signature_material(
        parsed,
        parsed["direct_selected_family_evidence"],
        parsed["access_result"],
    )
    mechanism_signature_sha256 = sha256_bytes(json.dumps(
        mechanism_signature_material_value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))
    return {
        "scenario": scenario_id,
        "correctness": "pass",
        "expected_historical_mechanism_mismatch": historical_mismatch,
        "diagnostic_phase": phase,
        "operation_isolated": True,
        "isolation": isolation,
        "exact_result": _exact_result_evidence(
            result, expected, expected_hash, expected_result_code,
        ),
        "expected_result_code": expected_result_code,
        "actual_ldap_result_code": result.returncode,
        "actual_server_result_code": parsed["access_result"][
            "server_result_code"
        ],
        "server_result_evidence": server_result_evidence,
        "diagnostic_artifacts": _write_diagnostic_window(
            diagnostic_dir, scenario_id, phase, "scenario", window,
        ),
        "selection_probe": selection_probe,
        "timing_eligible": True,
        "mechanism_gate": {
            "status": (
                "expected-historical-mismatch"
                if historical_mismatch
                else "historical-baseline-unexpected-pass"
                if historical_baseline
                else "pass"
            ),
            "failures": failures,
            "historical_baseline": historical_baseline,
        },
        "mechanism_signature_sha256": mechanism_signature_sha256,
        "mechanism_signature_material": mechanism_signature_material_value,
        "expected_count": len(expected),
        "expected_sha256": expected_hash,
        **parsed,
    }


def drop_caches() -> None:
    run_command(["sync"], timeout=120)
    try:
        Path("/proc/sys/vm/drop_caches").write_text("3\n", encoding="ascii")
    except OSError as error:
        raise StudyError(f"cold cache policy could not drop Linux page caches: {error}") from error


def perf_start(pid: int, output: Path, required: bool) -> tuple[subprocess.Popen[str] | None, dict[str, Any]]:
    perf = command_path("perf")
    if not perf:
        if required:
            raise StudyError("--perf on requested but perf is missing")
        return None, {"status": "unavailable", "reason": "perf missing"}
    output.parent.mkdir(parents=True, exist_ok=True)
    failed_attempts: list[dict[str, Any]] = []
    event_sets = [PERF_EVENTS]
    if not required:
        event_sets.append(PERF_SOFTWARE_FALLBACK_EVENTS)
    for events in event_sets:
        process: subprocess.Popen[str] | None = None
        output.unlink(missing_ok=True)
        try:
            process = subprocess.Popen(
                [
                    perf, "stat", "-x", ",", "-e", ",".join(events),
                    "-p", str(pid), "-o", str(output), "--", "sleep", "86400",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.15)
        except BaseException:
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            raise
        assert process is not None
        if process.poll() is None:
            fallback = events != PERF_EVENTS
            return process, {
                "status": "running",
                "events": list(events),
                "requested_hardware_events": list(PERF_EVENTS),
                "software_fallback": fallback,
                "hardware_events_unavailable": (
                    list(PERF_EVENTS) if fallback else []
                ),
                "failed_attempts": failed_attempts,
                "path": str(output),
            }
        stdout, stderr = process.communicate()
        failure = {
            "events": list(events),
            "returncode": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "reason": (stderr or stdout).strip(),
        }
        failed_attempts.append(failure)
        if required:
            raise StudyError(f"perf stat could not attach: {stderr or stdout}")
    return None, {
        "status": "unavailable",
        "reason": "; ".join(
            attempt["reason"] for attempt in failed_attempts
            if attempt["reason"]
        ),
        "requested_hardware_events": list(PERF_EVENTS),
        "software_fallback": False,
        "hardware_events_unavailable": list(PERF_EVENTS),
        "failed_attempts": failed_attempts,
    }


def parse_perf_stat(path: Path) -> dict[str, Any]:
    """Parse perf's stable ``-x,`` output without treating it as timing data."""
    if not path.is_file():
        return {
            "event_counts": {},
            "event_units": {},
            "unavailable_events": list(PERF_EVENTS),
            "parse_warnings": ["perf stat output file is absent"],
        }
    event_counts: dict[str, int | float] = {}
    event_units: dict[str, str] = {}
    unavailable: list[str] = []
    warnings: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for line_number, fields in enumerate(csv.reader(stream), 1):
            if not fields or not any(field.strip() for field in fields):
                continue
            if fields[0].lstrip().startswith("#"):
                continue
            if len(fields) < 3:
                warnings.append(f"line {line_number}: fewer than three CSV fields")
                continue
            raw_count = fields[0].strip()
            event = fields[2].strip().split(":", 1)[0]
            if event not in PERF_EVENTS + PERF_SOFTWARE_FALLBACK_EVENTS:
                continue
            if raw_count.startswith("<"):
                unavailable.append(event)
                continue
            try:
                # perf suppresses digit grouping in CSV mode.  A decimal can
                # still appear on multiplexed/derived configurations.
                count = float(raw_count)
            except ValueError:
                warnings.append(
                    f"line {line_number}: invalid count {raw_count!r} for {event}"
                )
                continue
            if not math.isfinite(count) or count < 0:
                warnings.append(
                    f"line {line_number}: non-finite/negative count for {event}"
                )
                continue
            unit = fields[1].strip() or "count"
            event_counts[event] = (
                int(count) if unit == "count" and count.is_integer() else count
            )
            event_units[event] = unit
    return {
        "event_counts": event_counts,
        "event_units": event_units,
        "unavailable_events": sorted(set(unavailable)),
        "parse_warnings": warnings,
    }


def perf_stop(process: subprocess.Popen[str] | None, metadata: dict[str, Any]) -> dict[str, Any]:
    if process is None:
        return metadata
    process.send_signal(signal.SIGINT)
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    metadata.update({
        "status": "observed" if process.returncode in (0, -signal.SIGINT, 130) else "failed",
        "returncode": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    })
    path = metadata.get("path")
    if isinstance(path, str):
        parsed = parse_perf_stat(Path(path))
        unavailable = set(parsed.get("unavailable_events", []))
        unavailable.update(metadata.get("hardware_events_unavailable", []))
        metadata.update(parsed)
        metadata["unavailable_events"] = sorted(unavailable)
    return metadata


def profile_lookup_symbol_evidence(
        report_text: str, *, lookup_mode: str,
        report_observed: bool) -> dict[str, Any]:
    """Conservatively identify lookup consumption from sampled symbols."""
    counts = {
        symbol: len(re.findall(rf"\b{re.escape(symbol)}\b", report_text))
        for symbol in PROFILE_LOOKUP_SYMBOLS
    }
    sampled = [symbol for symbol, count in counts.items() if count]
    if lookup_mode == "off" and sampled:
        raise StudyError(
            "lookup-off profile sampled lookup-only symbol(s): "
            + ", ".join(sampled)
        )
    consumed = report_observed and bool(sampled)
    return {
        "status": "consumed" if consumed else "unresolved",
        "evidence_status": "observed" if report_observed else "not-observed",
        "source": "perf report sampled symbols",
        "sampled_symbols": sampled,
        "symbol_line_counts": counts,
        "absence_interpretation": (
            "No inference of non-consumption is permitted when symbols are absent"
        ),
    }


def perf_iteration_batches(repeat_count: int) -> list[range]:
    """Partition measured iterations into independently collected perf runs."""
    if repeat_count < 1:
        raise StudyError("perf batching requires at least one measured iteration")
    return [
        range(start, min(start + PERF_RUNNER_BATCH_SEARCHES, repeat_count + 1))
        for start in range(1, repeat_count + 1, PERF_RUNNER_BATCH_SEARCHES)
    ]


def finalize_perf_batch(
        metadata: dict[str, Any], *, operation_count: int,
        cpu_before: Mapping[str, Any], cpu_after: Mapping[str, Any],
        required: bool) -> dict[str, Any]:
    """Normalize one independent perf batch and enforce explicit collection."""
    if operation_count < 1 or operation_count > PERF_BATCH_MAX_SEARCHES:
        raise StudyError(
            f"perf batch operation count must be 1..{PERF_BATCH_MAX_SEARCHES}"
        )
    counts = metadata.get("event_counts")
    counts = counts if isinstance(counts, Mapping) else {}
    metadata["operation_count"] = operation_count
    metadata["event_counts_per_search"] = {
        event: count / operation_count
        for event, count in counts.items()
        if isinstance(count, (int, float)) and not isinstance(count, bool)
    }
    cpu = metric_delta(cpu_before, cpu_after)
    metadata["server_cpu_delta"] = cpu
    metadata["server_cpu_seconds"] = cpu["server_cpu_seconds"]
    metadata["server_cpu_seconds_per_search"] = (
        cpu["server_cpu_seconds"] / operation_count
        if cpu["server_cpu_seconds"] is not None else None
    )
    if required:
        problems: list[str] = []
        if metadata.get("status") != "observed":
            problems.append(f"status is {metadata.get('status')!r}")
        unavailable = metadata.get("unavailable_events")
        if isinstance(unavailable, list) and unavailable:
            problems.append("unavailable events: " + ", ".join(unavailable))
        missing = [event for event in PERF_EVENTS if event not in counts]
        if missing:
            problems.append("missing counters: " + ", ".join(missing))
        warnings = metadata.get("parse_warnings")
        if isinstance(warnings, list) and warnings:
            problems.append("parse warnings: " + "; ".join(map(str, warnings)))
        if problems:
            raise StudyError(
                "--perf on collection was incomplete: " + "; ".join(problems)
            )
    return metadata


def perf_collection_identity(metadata: Mapping[str, Any]) -> dict[str, str]:
    """Describe the *observed* perf attachment, not only the requested mode.

    ``--perf auto`` may attach the hardware PMU on one host and fall back to
    task-clock on another.  Those collections impose different measurement
    conditions and must therefore occupy different timing strata.
    """
    status = str(metadata.get("status", "unrecorded"))
    raw_events = metadata.get("events")
    events = [str(value) for value in raw_events] if isinstance(raw_events, list) else []
    unavailable = metadata.get("unavailable_events")
    unavailable_events = (
        sorted(str(value) for value in unavailable)
        if isinstance(unavailable, list) else []
    )
    raw_counts = metadata.get("event_counts")
    count_events = (
        sorted(str(event) for event in raw_counts)
        if isinstance(raw_counts, Mapping) else []
    )
    missing_count_events = [
        event for event in PERF_EVENTS
        if not isinstance(raw_counts, Mapping) or event not in raw_counts
    ]
    invalid_count_events = [
        event for event in PERF_EVENTS
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
        event for event in count_events if event not in PERF_EVENTS
    ]
    raw_warnings = metadata.get("parse_warnings")
    parse_warnings = (
        [str(value) for value in raw_warnings]
        if isinstance(raw_warnings, list) else []
    )
    metadata_shape_errors: list[str] = []
    if not isinstance(raw_counts, Mapping):
        metadata_shape_errors.append("event_counts is not a mapping")
    if not isinstance(unavailable, list):
        metadata_shape_errors.append("unavailable_events is not a list")
    if not isinstance(raw_warnings, list):
        metadata_shape_errors.append("parse_warnings is not a list")
    complete_hardware_observation = not any((
        unavailable_events,
        missing_count_events,
        invalid_count_events,
        unexpected_count_events,
        parse_warnings,
        metadata_shape_errors,
    ))
    if status == "disabled":
        collection_class = "disabled"
    elif status != "observed":
        collection_class = "unavailable" if status == "unavailable" else "failed"
    elif events == PERF_EVENTS and complete_hardware_observation:
        collection_class = "hardware-events"
    elif events == PERF_SOFTWARE_FALLBACK_EVENTS:
        collection_class = "software-task-clock"
    elif events == PERF_EVENTS:
        collection_class = "hardware-events-incomplete"
    else:
        collection_class = "custom-events"
    material = {
        "format_version": 2,
        "collection_class": collection_class,
        "status": status,
        "events": events,
        "software_fallback": metadata.get("software_fallback") is True,
        "unavailable_events": unavailable_events,
        "observed_count_events": count_events,
        "missing_count_events": missing_count_events,
        "invalid_count_events": invalid_count_events,
        "unexpected_count_events": unexpected_count_events,
        "parse_warnings": parse_warnings,
        "metadata_shape_errors": metadata_shape_errors,
    }
    return {
        "collection_class": collection_class,
        "collection_signature": sha256_bytes(json.dumps(
            material, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")),
    }


def profile_collection_identity(metadata: Mapping[str, Any]) -> dict[str, str]:
    """Content-address the observed perf-record sampling condition."""
    status = str(metadata.get("status", "unrecorded"))
    event = metadata.get("sampling_event")
    if status == "observed" and event == "default-hardware":
        collection_class = "hardware-sampling"
    elif status == "observed" and event == PROFILE_SOFTWARE_FALLBACK_EVENT:
        collection_class = "software-cpu-clock"
    elif status == "disabled":
        collection_class = "disabled"
    elif status == "unavailable":
        collection_class = "unavailable"
    elif status.startswith("skipped-"):
        collection_class = "skipped"
    else:
        collection_class = "failed"
    material = {
        "format_version": 1,
        "collection_class": collection_class,
        "status": status,
        "sampling_event": event,
        "software_fallback": metadata.get("software_fallback") is True,
    }
    return {
        "collection_class": collection_class,
        "collection_signature": sha256_bytes(json.dumps(
            material, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")),
    }


def link_rows_to_perf_batch(
        rows: Sequence[dict[str, Any]], batch_id: str,
        collection: Mapping[str, str]) -> None:
    """Link rows to aggregate counters without cloning counters into samples."""
    for row in rows:
        row["perf_batch_id"] = batch_id
        row["perf_collection_class"] = collection["collection_class"]
        row["perf_collection_signature"] = collection["collection_signature"]


def run_profile(
    runtime: ServerRuntime,
    scenario_id: str,
    scenario: Mapping[str, Any],
    filter_text: str,
    output: Path,
    enabled: bool,
    expected: Sequence[str],
    expected_hash: str,
    required: bool = False,
    bundle_root: Path | None = None,
) -> dict[str, Any]:
    expected_result_code = scenario.get("expected_result_code")
    if expected_result_code is None:
        raise StudyError(f"{scenario_id}: expected_result_code is missing")
    expected_numeric_code = ldap_result_code_value(
        expected_result_code, scenario_id,
    )
    unresolved_lookup = profile_lookup_symbol_evidence(
        "", lookup_mode=runtime.actual_lookup_mode, report_observed=False,
    )
    missing_server_result = {
        "evidence_status": "not-observed",
        "actual_server_result_code": None,
        "expected_result_code": expected_result_code,
        "expected_ldap_result_code": expected_numeric_code,
        "server_result_code_match": False,
        "passed": False,
    }

    def artifact_path(path: Path) -> str:
        if bundle_root is not None:
            try:
                return path.resolve().relative_to(bundle_root.resolve()).as_posix()
            except ValueError:
                pass
        return path.name

    not_produced = {
        "evidence_status": "not-produced",
        "path": artifact_path(output),
        "sha256": None,
        "size_bytes": None,
    }
    profile_guard_context = f"{scenario_id} perf profile collection"
    if not enabled:
        if required:
            raise StudyError("--profile on requested but profiling is disabled")
        return {
            "status": "disabled",
            "evidence_status": "not-planned",
            "operation_count": 0,
            "operations": [],
            "expected_result_code": expected_result_code,
            "expected_ldap_result_code": expected_numeric_code,
            "actual_client_result_code": None,
            "actual_server_result_code": None,
            "server_result_evidence": missing_server_result,
            "exact_result": {"evidence_status": "not-observed"},
            "profile_artifact": not_produced,
            "lookup_consumption": unresolved_lookup,
            "background_quiet_window": (
                runtime.background_quiet_not_applicable(
                    profile_guard_context, "profiling disabled"
                )
            ),
        }
    if runtime.pid is None:
        if required:
            raise StudyError("--profile on requested but server pid is unavailable")
        return {
            "status": "unavailable",
            "evidence_status": "missing-planned-evidence",
            "reason": "server pid unavailable",
            "operation_count": 0,
            "operations": [],
            "expected_result_code": expected_result_code,
            "expected_ldap_result_code": expected_numeric_code,
            "actual_client_result_code": None,
            "actual_server_result_code": None,
            "server_result_evidence": missing_server_result,
            "exact_result": {"evidence_status": "not-observed"},
            "profile_artifact": not_produced,
            "lookup_consumption": unresolved_lookup,
            "background_quiet_window": (
                runtime.background_quiet_not_applicable(
                    profile_guard_context, "server pid unavailable"
                )
            ),
        }
    perf = command_path("perf")
    if not perf:
        if required:
            raise StudyError("--profile on requested but perf is missing")
        return {
            "status": "unavailable",
            "evidence_status": "missing-planned-evidence",
            "reason": "perf missing",
            "operation_count": 0,
            "operations": [],
            "expected_result_code": expected_result_code,
            "expected_ldap_result_code": expected_numeric_code,
            "actual_client_result_code": None,
            "actual_server_result_code": None,
            "server_result_evidence": missing_server_result,
            "exact_result": {"evidence_status": "not-observed"},
            "profile_artifact": not_produced,
            "lookup_consumption": unresolved_lookup,
            "background_quiet_window": (
                runtime.background_quiet_not_applicable(
                    profile_guard_context, "perf unavailable"
                )
            ),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    background_guard = runtime.begin_background_quiet_collection(
        profile_guard_context
    )
    process: subprocess.Popen[str] | None = None
    sampling_event = "default-hardware"
    record_attempts: list[dict[str, Any]] = []
    profile_running = False
    commands = [
        (
            "default-hardware",
            [
                perf, "record", "-g", "-p", str(runtime.pid),
                "-o", str(output), "--", "sleep", "86400",
            ],
        ),
        (
            PROFILE_SOFTWARE_FALLBACK_EVENT,
            [
                perf, "record", "-e", PROFILE_SOFTWARE_FALLBACK_EVENT,
                "-g", "-p", str(runtime.pid), "-o", str(output),
                "--", "sleep", "86400",
            ],
        ),
    ]
    for attempt_index, (event_name, command) in enumerate(commands):
        process = None
        if attempt_index:
            output.unlink(missing_ok=True)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.15)
        except BaseException:
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            runtime.finish_background_quiet_collection(background_guard)
            raise
        assert process is not None
        if process.poll() is None:
            sampling_event = event_name
            profile_running = True
            break
        attempt_stdout, attempt_stderr = process.communicate()
        record_attempts.append({
            "sampling_event": event_name,
            "returncode": process.returncode,
            "stdout": attempt_stdout,
            "stderr": attempt_stderr,
            "reason": (attempt_stderr or attempt_stdout).strip(),
        })
    assert process is not None
    if not profile_running:
        background_guard = runtime.finish_background_quiet_collection(
            background_guard
        )
        reason = "; ".join(
            attempt["reason"] for attempt in record_attempts
            if attempt["reason"]
        )
        if required:
            raise StudyError(
                "--profile on could not start perf record: "
                + reason
            )
        return {
            "status": "unavailable",
            "evidence_status": "missing-planned-evidence",
            "reason": reason,
            "sampling_event": None,
            "record_attempts": record_attempts,
            "operation_count": 0,
            "operations": [],
            "expected_result_code": expected_result_code,
            "expected_ldap_result_code": expected_numeric_code,
            "actual_client_result_code": None,
            "actual_server_result_code": None,
            "server_result_evidence": missing_server_result,
            "exact_result": {"evidence_status": "not-observed"},
            "profile_artifact": not_produced,
            "lookup_consumption": unresolved_lookup,
            "background_quiet_window": background_guard,
        }
    operations: list[dict[str, Any]] = []
    try:
        for operation_index in range(1, PROFILE_OPERATION_COUNT + 1):
            result, search_window, search_isolation = (
                runtime.search_with_isolated_diagnostics(
                    base=scenario["base_dn"],
                    scope=scenario.get("scope", "sub"),
                    filter_text=filter_text,
                    attributes=scenario.get(
                        "requested_attributes", ["1.1"]
                    ),
                )
            )
            operation_context = (
                f"{scenario_id} profile operation {operation_index}"
            )
            assert_correct(
                operation_context, result, expected, expected_hash,
                expected_result_code,
            )
            access_result = parse_access_result(
                runtime.implementation, search_window["access"],
            )
            if access_result["result_line_count"] != 1:
                raise StudyError(
                    f"{operation_context}: isolated access-log window "
                    f"contains {access_result['result_line_count']} result "
                    "records"
                )
            server_result_evidence = _require_server_result(
                access_result, expected_result_code, operation_context,
            )
            exact_result = _exact_result_evidence(
                result, expected, expected_hash, expected_result_code,
            )
            operations.append({
                "operation_index": operation_index,
                "operation_isolated": True,
                "isolation": search_isolation,
                "access_result": access_result,
                "server_result_evidence": server_result_evidence,
                "exact_result": exact_result,
                "actual_client_result_code": result.returncode,
                "actual_server_result_code": access_result[
                    "server_result_code"
                ],
                "search_returned_count": len(result.dns),
                "search_returned_sha256": dns_digest(result.dns),
            })
    finally:
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        background_guard = runtime.finish_background_quiet_collection(
            background_guard
        )
    if len(operations) != PROFILE_OPERATION_COUNT:
        raise StudyError(
            f"{scenario_id} profile collected {len(operations)} operations, "
            f"expected {PROFILE_OPERATION_COUNT}"
        )
    final_operation = operations[-1]
    access_result = final_operation["access_result"]
    server_result_evidence = final_operation["server_result_evidence"]
    exact_result = final_operation["exact_result"]
    report_path = output.with_suffix(output.suffix + ".report.txt")
    report_status: dict[str, Any] = {
        "path": artifact_path(report_path),
        "returncode": None,
        "status": "not-run",
        "sha256": None,
        "size_bytes": None,
    }
    report_text = ""
    if output.exists() and output.stat().st_size:
        report = run_command(
            [perf, "report", "--stdio", "--no-children", "-i", str(output)],
            check=False,
            timeout=180,
        )
        report_text = report.stdout + report.stderr
        report_path.write_text(report_text, encoding="utf-8")
        report_status["returncode"] = report.returncode
        report_status["status"] = (
            "observed" if report.returncode == 0 else "failed"
        )
        report_status["sha256"] = sha256_file(report_path)
        report_status["size_bytes"] = report_path.stat().st_size
    record_ok = process.returncode in (0, -signal.SIGINT, 130)
    output_ok = output.exists() and output.stat().st_size > 0
    report_ok = report_status["status"] == "observed"
    status = "observed" if record_ok and output_ok and report_ok else "failed"
    lookup_consumption = profile_lookup_symbol_evidence(
        report_text,
        lookup_mode=runtime.actual_lookup_mode,
        report_observed=report_ok,
    )
    profile_artifact = {
        "evidence_status": "observed" if output_ok else "not-produced",
        "path": artifact_path(output),
        "sha256": sha256_file(output) if output_ok else None,
        "size_bytes": output.stat().st_size if output_ok else None,
    }
    metadata = {
        "status": status,
        "evidence_status": (
            "observed" if status == "observed" else "missing-planned-evidence"
        ),
        "operation_count": len(operations),
        "operations": operations,
        "search_returncode": final_operation["actual_client_result_code"],
        "actual_client_result_code": final_operation[
            "actual_client_result_code"
        ],
        "actual_server_result_code": access_result["server_result_code"],
        "expected_result_code": expected_result_code,
        "expected_ldap_result_code": expected_numeric_code,
        "operation_isolated": True,
        "isolation": final_operation["isolation"],
        "access_result": access_result,
        "server_result_evidence": server_result_evidence,
        "exact_result": exact_result,
        "background_quiet_window": background_guard,
        "search_returned_count": final_operation["search_returned_count"],
        "search_returned_sha256": final_operation[
            "search_returned_sha256"
        ],
        "returncode": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "sampling_event": sampling_event,
        "software_fallback": sampling_event == PROFILE_SOFTWARE_FALLBACK_EVENT,
        "record_attempts": record_attempts,
        "path": artifact_path(output),
        "profile_artifact": profile_artifact,
        "lookup_consumption": lookup_consumption,
        "report": report_status,
    }
    if required and status != "observed":
        problems = []
        if not record_ok:
            problems.append(f"perf record return code {process.returncode}")
        if not output_ok:
            problems.append("perf.data is absent or empty")
        if not report_ok:
            problems.append(
                f"perf report status {report_status['status']} "
                f"(return code {report_status['returncode']})"
            )
        raise StudyError("--profile on collection failed: " + "; ".join(problems))
    return metadata


def measure_one(
    *,
    runtime: ServerRuntime,
    scenario_id: str,
    scenario: Mapping[str, Any],
    filter_text: str,
    expected: Sequence[str],
    expected_hash: str,
    attributes: Sequence[str],
    attribute_variant: str,
    phase: str,
    iteration: int,
    cache_policy: str,
    row_base: Mapping[str, Any],
) -> dict[str, Any]:
    if cache_policy == "cold":
        drop_caches()
    if runtime.pid is None:
        raise StudyError("server pid is unavailable")
    background_guard = runtime.begin_background_quiet_collection(
        f"{scenario_id} timed search"
    )
    cursor = runtime.log_cursor()
    before = process_metrics(runtime.pid)
    started = time.monotonic_ns()
    result = runtime.search(
        base=scenario["base_dn"], scope=scenario.get("scope", "sub"),
        filter_text=filter_text, attributes=attributes,
    )
    elapsed = time.monotonic_ns() - started
    after = process_metrics(runtime.pid)
    expected_result_code = scenario.get("expected_result_code")
    if expected_result_code is None:
        raise StudyError(f"{scenario_id}: expected_result_code is missing")
    assert_correct(
        scenario_id, result, expected, expected_hash, expected_result_code,
    )
    logs, log_isolation = runtime.await_isolated_search_log(
        cursor,
        context=f"{scenario_id} timed search",
    )
    background_guard = runtime.finish_background_quiet_collection(
        background_guard
    )
    access = parse_access_result(runtime.implementation, logs["access"])
    if access["result_line_count"] != 1:
        raise StudyError(
            f"{scenario_id}: timed search access-log window contains "
            f"{access['result_line_count']} result records"
        )
    server_result_evidence = _require_server_result(
        access, expected_result_code, f"{scenario_id} timed search",
    )
    if access["server_nentries"] is not None and access["server_nentries"] != len(expected):
        raise StudyError(
            f"{scenario_id}: access log reports {access['server_nentries']} entries, expected {len(expected)}"
        )
    cpu = metric_delta(before, after)
    if (
            row_base.get("release_timing_evidence") is True
            and cpu["server_cpu_seconds"] is None):
        raise StudyError(
            f"{scenario_id}: high-resolution whole-process CPU is unavailable"
        )
    row_id = (
        f"{row_base['run_id']}:{scenario_id}:{attribute_variant}:"
        f"{phase}:{iteration}"
    )
    return {
        **row_base,
        "row_id": row_id,
        "scenario": scenario_id,
        "scenario_groups": scenario.get("groups", []),
        "index_config": scenario.get("index_variant"),
        "phase": phase,
        "iteration": iteration,
        "attribute_variant": attribute_variant,
        "requested_attributes": list(attributes),
        "cache_policy": cache_policy,
        "connection_policy": "new-connection-per-search",
        "bind_class": "administrative",
        "correctness_pass": True,
        "evidence_status": "observed",
        "background_quiet_window": background_guard,
        "log_isolation": log_isolation,
        "ldap_result_code": result.returncode,
        "actual_client_result_code": result.returncode,
        "expected_result_code": expected_result_code,
        "expected_ldap_result_code": ldap_result_code_value(
            expected_result_code, scenario_id,
        ),
        "returned_count": len(result.dns),
        "returned_sha256": dns_digest(result.dns),
        "expected_count": len(expected),
        "expected_sha256": expected_hash,
        "exact_result": _exact_result_evidence(
            result, expected, expected_hash, expected_result_code,
        ),
        "client_elapsed_ns": elapsed,
        "server_etime_seconds": access["server_etime_seconds"],
        "server_nentries": access["server_nentries"],
        "server_notes": access["server_notes"],
        "server_result_code": access["server_result_code"],
        "actual_server_result_code": access["server_result_code"],
        "server_result_evidence": server_result_evidence,
        "server_cpu_seconds": cpu["server_cpu_seconds"],
        "server_cpu_ns": cpu["server_cpu_ns"],
        "process_user_cpu_seconds": cpu["user_cpu_seconds"],
        "process_system_cpu_seconds": cpu["system_cpu_seconds"],
        "process_user_cpu_ticks": cpu["user_cpu_ticks"],
        "process_system_cpu_ticks": cpu["system_cpu_ticks"],
        "process_clock_ticks_per_second": cpu["clock_ticks_per_second"],
        "cpu_clock_source": cpu["cpu_clock_source"],
        "schedstat_before_task_count": cpu["schedstat_before_task_count"],
        "schedstat_after_task_count": cpu["schedstat_after_task_count"],
        "rss_kib": cpu["rss_kib"],
        "high_water_kib": cpu["high_water_kib"],
    }


def run_dynamic_control(
    *,
    runtime: ServerRuntime,
    scenario_id: str,
    scenario: Mapping[str, Any],
    filter_text: str,
    expected: Sequence[str],
    expected_hash: str,
    revision: str,
    diagnostic_dir: Path,
) -> dict[str, Any]:
    if not isinstance(runtime, DS389Runtime):
        raise StudyError("dynamic-list correctness control is 389 DS only")
    metadata = runtime.manifest.get("dynamic_list")
    if not isinstance(metadata, Mapping):
        raise StudyError("dynamic-list metadata is missing")
    expected_result_code = scenario.get("expected_result_code")
    if expected_result_code is None:
        raise StudyError(f"{scenario_id}: expected_result_code is missing")
    runtime.prepare_dynamic_limits()
    runtime.configure_dynamic_lists(False)
    state = runtime.diagnostics_enable(filter_trace=False)

    def operation(
            label: str, *, planned_expected: Sequence[str],
            planned_hash: str, planned_result_code: Any = "LDAP_SUCCESS",
            allow_historical_failure: bool = False,
            allow_internal_operations: bool = False,
            require_internal_operations: bool = False,
            **search: Any) -> tuple[Any, dict[str, Any]]:
        result, window, isolation = runtime.search_with_isolated_diagnostics(
            allow_internal_operations=allow_internal_operations,
            require_internal_operations=require_internal_operations,
            **search,
        )
        parsed = parse_diagnostics(window["error"], window["access"])
        access = parse_access_result(runtime.implementation, window["access"])
        evidence = _exact_result_evidence(
            result, planned_expected, planned_hash, planned_result_code,
        )
        client_exact_result_passed = evidence["passed"]
        server_result_evidence = _server_result_evidence(
            access, planned_result_code, f"{scenario_id} {label}",
        )
        evidence.update({
            "operation": label,
            "operation_isolated": True,
            "isolation": isolation,
            "diagnostics": parsed,
            "access_result": access,
            "client_exact_result_passed": client_exact_result_passed,
            "server_result_evidence": server_result_evidence,
            "actual_server_result_code": access["server_result_code"],
            "diagnostic_artifacts": _write_diagnostic_window(
                diagnostic_dir, scenario_id, "control", label, window,
            ),
        })
        if access["result_line_count"] != 1:
            raise StudyError(
                f"{scenario_id} {label}: isolated diagnostic window contains "
                f"{access['result_line_count']} result records"
            )
        evidence["passed"] = (
            client_exact_result_passed and server_result_evidence["passed"]
        )
        if not evidence["passed"] and not allow_historical_failure:
            if not client_exact_result_passed:
                assert_correct(
                    f"{scenario_id} {label}", result, planned_expected,
                    planned_hash, planned_result_code,
                )
            _require_server_result(
                access, planned_result_code, f"{scenario_id} {label}",
            )
        return result, evidence

    try:
        expected_stored = sorted(dn.lower() for dn in metadata["stored_dns"])
        ordinary, ordinary_evidence = operation(
            "ordinary-candidates",
            planned_expected=expected_stored,
            planned_hash=dns_digest(expected_stored),
            base=str(metadata["base_dn"]), scope="sub",
            filter_text=f"(member={metadata['target_dn']})",
            attributes=["1.1"],
        )
        runtime.configure_dynamic_lists(True)
        expected_augmented = sorted(
            [dn.lower() for dn in metadata["stored_dns"]]
            + [dn.lower() for dn in metadata["dynamic_url_dns"]]
        )
        augmented, augmented_evidence = operation(
            "augmented-candidates",
            planned_expected=expected_augmented,
            planned_hash=dns_digest(expected_augmented),
            allow_internal_operations=True,
            base=str(metadata["base_dn"]), scope="sub",
            filter_text=f"(member={metadata['target_dn']})",
            attributes=["1.1"],
        )
        finite = scenario_id.endswith("finite")
        bind_dn = str(
            metadata["limited_bind_dn"]
            if finite else metadata["control_bind_dn"]
        )
        password = str(metadata["bind_password"])
        historical_parent = revision == REVISION_ROLES["combined-diagnostic"]
        historical_adminlimit_control = historical_parent and finite
        result, final_evidence = operation(
            "final-search",
            planned_expected=expected,
            planned_hash=expected_hash,
            planned_result_code=expected_result_code,
            allow_historical_failure=historical_adminlimit_control,
            allow_internal_operations=True,
            base=scenario["base_dn"], scope=scenario.get("scope", "sub"),
            filter_text=filter_text, attributes=["1.1"], bind_dn=bind_dn,
            password=password,
        )
        health_expected = ["dc=example,dc=com"]
        health, health_evidence = operation(
            "post-control-health",
            planned_expected=health_expected,
            planned_hash=dns_digest(health_expected),
            planned_result_code="LDAP_SUCCESS",
            # This deliberately reuses the limited/control non-admin bind.
            # 389 DS may authenticate it through a same-connection internal
            # base read before issuing the external health search.
            allow_internal_operations=True,
            base="dc=example,dc=com", scope="base",
            filter_text="(objectClass=*)", attributes=["1.1"],
            bind_dn=bind_dn, password=password,
        )
    finally:
        runtime.diagnostics_restore(state)

    final_diagnostics = dict(final_evidence["diagnostics"])
    final_diagnostics["access_result"] = final_evidence["access_result"]
    candidate_values = final_diagnostics.get("candidate_list_values", [])
    if candidate_values:
        # Dynamic-list evaluation performs nested internal searches inside the
        # one isolated external operation.  The production error-log trace has
        # no conn/op identity, so its outer and nested candidate-list messages
        # cannot be attributed without inventing an ordering heuristic.  Keep
        # every raw value, report the final list as not directly observable,
        # and rely on the exact-result and cap-path gates for this correctness
        # control.
        candidate_observation = {
            "status": "not-directly-observable",
            "reason": (
                "the isolated dynamic-list operation contains uncorrelated "
                "outer and nested-internal build_candidate_list traces"
            ),
            "raw_trace_count": len(
                candidate_values
            ),
            "parser_status": final_diagnostics.get("candidate_list_status"),
        }
        final_diagnostics["candidate_list_status"] = (
            "not-directly-observable-unattributed-traces"
        )
        final_diagnostics["observed_final_candidate_count"] = None
        final_diagnostics["candidate_list_observation"] = candidate_observation
        final_evidence["diagnostics"]["candidate_list_status"] = (
            "not-directly-observable-unattributed-traces"
        )
        final_evidence["diagnostics"]["observed_final_candidate_count"] = None
        final_evidence["diagnostics"][
            "candidate_list_observation"
        ] = candidate_observation
    mechanism_failures = mechanism_gate(
        server=runtime.implementation,
        revision=revision,
        lookup_mode=runtime.actual_lookup_mode,
        scenario=scenario,
        diagnostics=final_diagnostics,
    )
    historical_failure = False
    if historical_adminlimit_control:
        adminlimit = LDAP_RESULT_CODES["LDAP_ADMINLIMIT_EXCEEDED"]
        historical_signature = (
            not final_evidence["passed"]
            and result.returncode == adminlimit
            and final_evidence["actual_server_result_code"] == adminlimit
            and final_evidence["diagnostics"].get("cap_path_observed") is True
        )
        if not historical_signature:
            raise StudyError(
                f"{scenario_id}: the combined-diagnostic waiver applies only "
                "to the known isolated LDAP_ADMINLIMIT_EXCEEDED result with "
                "the required bounded-read cap diagnostic"
            )
        historical_failure = True
    elif not final_evidence["passed"] or mechanism_failures:
        if not final_evidence["passed"]:
            assert_correct(
                scenario_id, result, expected, expected_hash,
                expected_result_code,
            )
        raise StudyError(
            f"{scenario_id} dynamic-list mechanism failed: "
            + "; ".join(mechanism_failures)
        )
    return {
        "scenario": scenario_id,
        "correctness": "expected-historical-failure" if historical_failure else "pass",
        "evidence_status": (
            "historical-failure-observed" if historical_failure
            else "all-planned-operations-observed"
        ),
        "timed": False,
        "timing_eligible": False,
        "expected_result_code": expected_result_code,
        "actual_ldap_result_code": result.returncode,
        "actual_server_result_code": final_evidence[
            "actual_server_result_code"
        ],
        "historical_expected_failure": historical_failure,
        "mechanism_gate": {
            "status": (
                "expected-historical-failure" if historical_failure else "pass"
            ),
            "failures": mechanism_failures,
        },
        "ordinary_candidates": ordinary_evidence,
        "augmented_candidates": augmented_evidence,
        "final_search": final_evidence,
        "post_control_health": health_evidence,
        "ordinary_candidate_count": len(ordinary.dns),
        "augmented_candidate_count": len(augmented.dns),
        "returned_final_count": len(result.dns),
        "returned_final_sha256": dns_digest(result.dns),
        "expected_final_count": len(expected),
        "expected_final_sha256": expected_hash,
        "health_returned_count": len(health.dns),
        "health_returned_sha256": dns_digest(health.dns),
        "health_ldap_result_code": health.returncode,
        "bind_dn": bind_dn,
        "id_list_scan_limit": scenario.get("parameters", {}).get("id_list_scan_limit"),
        "lookthrough_limit": metadata["lookthrough_limit"],
        "ldap_adminlimit_exceeded": (
            result.returncode == LDAP_RESULT_CODES["LDAP_ADMINLIMIT_EXCEEDED"]
            or final_evidence["actual_server_result_code"]
            == LDAP_RESULT_CODES["LDAP_ADMINLIMIT_EXCEEDED"]
        ),
    }


def client_identity() -> dict[str, Any]:
    path = Path(require_commands(["ldapsearch"])["ldapsearch"])
    identity: dict[str, Any] = {
        "path": str(path),
        "sha256": sha256_file(path),
        "version": run_command([str(path), "-VV"], check=False, timeout=30).stdout
        + run_command([str(path), "-VV"], check=False, timeout=30).stderr,
    }
    rpm = command_path("rpm")
    if rpm:
        owner = run_command([rpm, "-qf", str(path)], check=False, timeout=30)
        identity["owning_package"] = owner.stdout.strip() if owner.returncode == 0 else None
    return identity


def prepare_output(path: Path) -> None:
    if path.exists() and any(path.iterdir() if path.is_dir() else [path]):
        raise StudyError(f"output path already exists and is non-empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def declared_schedule(args: argparse.Namespace) -> dict[str, Any]:
    """Validate and normalize the externally controlled run schedule.

    A free-form ``schedule_position`` remains available for exploratory and
    legacy runs, but only a fully declared ABBA block can later satisfy the
    release matrix's cross-build ordering requirement.
    """
    design = str(getattr(args, "schedule_design", "unspecified"))
    raw_block = getattr(args, "schedule_block", None)
    block_id = str(raw_block).strip() if raw_block is not None else None
    position = str(getattr(args, "schedule_position", "unspecified")).strip()
    if not position:
        raise StudyError("--schedule-position may not be empty")
    if design == "abba":
        if not block_id:
            raise StudyError("--schedule-design abba requires --schedule-block")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", block_id):
            raise StudyError(
                "--schedule-block must be a 1..128 character stable identifier"
            )
        if position not in {"A1", "B1", "B2", "A2"}:
            raise StudyError(
                "--schedule-design abba requires --schedule-position "
                "A1, B1, B2, or A2"
            )
        state = position[0]
    elif design == "screen":
        if block_id:
            raise StudyError(
                "--schedule-block is reserved for --schedule-design abba"
            )
        if position == "unspecified":
            raise StudyError(
                "--schedule-design screen requires a descriptive "
                "--schedule-position"
            )
        state = None
    elif design == "unspecified":
        if block_id:
            raise StudyError(
                "--schedule-block requires --schedule-design abba"
            )
        state = None
    else:  # argparse normally prevents this, but direct callers remain safe.
        raise StudyError(f"unsupported schedule design {design!r}")
    return {
        "format_version": 1,
        "design": design,
        "block_id": block_id,
        "position": position,
        "state": state,
        "release_ordering_eligible": design == "abba",
        "state_fingerprint": None,
        "state_fingerprint_material": None,
    }


def run(args: argparse.Namespace, *, forced_mode: str | None = None) -> int:
    mode = forced_mode or args.mode
    correctness_only = mode == "correctness-only"
    prewarm_decision = resolve_state_prewarm(args, mode=mode)
    if mode == "native-timing":
        enforce_native_fedora()
        host_class = "fedora_native"
        if args.repeat < 15:
            raise StudyError("native timing requires at least 15 measured repeats")
        if args.warmups not in {2, 3}:
            raise StudyError("native timing requires 2 or 3 warm-ups")
        if args.cache_policy == "warm":
            if not prewarm_decision["enabled"]:
                raise StudyError(
                    "native timing with the warm cache policy requires the "
                    "state pre-warm"
                )
            if prewarm_decision["passes"] not in ALLOWED_NATIVE_PREWARM_PASSES:
                raise StudyError("native timing requires 2 or 3 pre-warm passes")
    else:
        if not args.host_class:
            raise StudyError("correctness-only mode requires --host-class")
        host_class = args.host_class
        if host_class == "fedora_native":
            raise StudyError("correctness-only mode may not claim host_class fedora_native")
        explicitly_emulated = (
            os.environ.get("LFSTUDY_EMULATED", "").casefold()
            in {"1", "yes", "true", "on"}
        )
        emulation_named = any(
            token in host_class.casefold()
            for token in ("orbstack", "rosetta", "emulat")
        )
        if (explicitly_emulated or emulation_named) and (
                host_class != "macos_orbstack_emulated"):
            raise StudyError(
                "Apple-hosted/emulated correctness runs require the exact "
                "host_class macos_orbstack_emulated"
            )

    schedule = declared_schedule(args)

    expected_revision, revision_role = resolve_revision(
        args.expected_source_sha, args.server,
    )
    if expected_revision == FEDORA_STABLE_PACKAGE_REVISION and not (
            mode == "native-timing"
            and schedule["design"] == "screen"
            and args.lookup == "unsupported"):
        raise StudyError(
            "fedora-stable-package is package-only provenance and is allowed "
            "only for a native 389 DS lookup-unsupported screen"
        )
    production_revision = (
        production_equivalent_revision(expected_revision)
        if (
            args.server == "389ds"
            and expected_revision != FEDORA_STABLE_PACKAGE_REVISION
        ) else None
    )
    production_equivalence = (
        declared_production_equivalence(expected_revision)
        if args.server == "389ds" else None
    )
    # Installed artifact identity is the first substantive native-run action.
    # Workload copying and server-instance creation happen only after this
    # immutable package/binary snapshot has succeeded.
    executable = "ns-slapd" if args.server == "389ds" else "slapd"
    identity = installed_rpm_identity(
        executable,
        expected_source_sha=expected_revision,
        fail_on_verify=not args.allow_rpm_verify_differences,
        require_complete_389_closure=(
            mode == "native-timing" and args.server == "389ds"
        ),
    )
    installed_package_closure_sha256 = sha256_bytes(json.dumps(
        identity.get("installed_package_closure"),
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8"))
    if mode == "native-timing" and not identity.get("unsanitized", False):
        raise StudyError(
            "native timing refuses a sanitizer-linked server: "
            + ", ".join(identity.get("sanitizer_libraries", []))
        )
    if mode == "native-timing":
        build_id = identity.get("elf_build_id")
        linked = identity.get("linked_libraries")
        if (
                not isinstance(build_id, Mapping)
                or build_id.get("status") != "observed"
                or not build_id.get("value")):
            raise StudyError(
                "native timing requires an observed ELF build ID; install "
                "binutils and use a normal Fedora RPM with build-id notes"
            )
        if not isinstance(linked, Mapping) or linked.get("complete") is not True:
            problems = (
                linked.get("problems", []) if isinstance(linked, Mapping) else []
            )
            raise StudyError(
                "native timing requires a complete ldd/RPM-owned linked "
                "library closure: " + "; ".join(str(value) for value in problems)
            )
    client = client_identity()
    host = host_metadata(host_class=host_class, correctness_only=correctness_only)
    harness = harness_identity()
    invocation = invocation_evidence(sys.argv)
    if mode == "native-timing" and (
            harness.get("git_evidence_status") != "observed"
            or not re.fullmatch(r"[0-9a-f]{40}", str(harness.get("git_head")))
            or harness.get("git_study_tree_clean") is not True):
        raise StudyError(
            "native timing requires the study to come from a clean committed "
            "git checkout with an observed 40-hex harness HEAD"
        )

    source_workload = args.workload.resolve()
    source_manifest = verify_workload(source_workload)
    source_manifest_sha256 = sha256_file(
        source_workload / "workload-manifest.json"
    )
    if mode == "native-timing":
        enforce_native_workload_manifest(source_manifest)
    output = args.output.resolve()
    prepare_output(output)
    started_at = utc_now()
    (output / "INCOMPLETE").write_text(
        f"started {started_at}\n", encoding="utf-8",
    )
    environment_start = capture_environment_snapshot()
    copied_workload = output / "workload"
    copy_workload_payload(source_workload, source_manifest, copied_workload)
    manifest = verify_workload(copied_workload)
    copied_manifest_sha256 = sha256_file(
        copied_workload / "workload-manifest.json"
    )
    if (
            copied_manifest_sha256 != source_manifest_sha256
            or manifest != source_manifest):
        raise StudyError(
            "copied workload manifest changed while establishing the result payload"
        )
    shutil.copy2(
        copied_workload / "workload-manifest.json",
        output / "workload-manifest.json",
    )
    workload = copied_workload
    workload_manifest_sha256 = sha256_file(output / "workload-manifest.json")
    run_id = str(uuid.uuid4())

    selected = select_scenarios(
        manifest,
        requested=args.scenario,
        groups=args.scenario_group,
        smoke_selected=args.smoke_selected,
        server=args.server,
        index_config=args.index_config,
    )
    if args.scenario_order == "randomized":
        random.Random(args.order_seed).shuffle(selected)
    declared_approximate_policy = _selected_approximate_policy(
        manifest, selected,
    )
    approximate_semantics_evidence: dict[str, Any] = (
        {
            "status": "pending",
            "evidence_status": "not-yet-observed",
            "contract_sha256": declared_approximate_policy[
                "contract_sha256"
            ],
            "probes": [],
        }
        if declared_approximate_policy is not None
        else {
            "status": "not-applicable",
            "evidence_status": "not-planned",
            "contract_sha256": None,
            "probes": [],
        }
    )
    reference_manifest_path = Path(__file__).resolve().parents[1] / "artifact-manifest.json"
    references = load_json(reference_manifest_path) if reference_manifest_path.exists() else {
        "revision_roles": REVISION_ROLES,
        "production_equivalent_revisions": PRODUCTION_EQUIVALENT_REVISIONS,
    }
    artifact = {
        "format_version": FORMAT_VERSION,
        "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
        "created_at": started_at,
        "run_id": run_id,
        "build_label": args.build_label,
        "server": args.server,
        "host_class": host_class,
        "correctness_only": correctness_only,
        "release_timing_evidence": not correctness_only,
        "timing_claims_allowed": not correctness_only,
        "expected_source_sha": expected_revision,
        "production_equivalent_revision": production_revision,
        "production_equivalence": production_equivalence,
        "revision_role": revision_role,
        "operator_assertion": args.operator_assertion,
        "invocation": invocation,
        "harness_identity": harness,
        "server_executable": identity,
        "installed_package_closure_sha256": (
            installed_package_closure_sha256
        ),
        "runtime_closure_sha256": identity["runtime_closure_sha256"],
        "client_executable": client,
        "reference_study": references,
        "binary_deduplication": {
            "status": "pending-result-merge",
            "executable_sha256": identity["executable_sha256"],
        },
        "workload_manifest_sha256": workload_manifest_sha256,
        "workload_execution_root": "workload",
        "copied_workload_verified": True,
        "approximate_semantics_evidence": approximate_semantics_evidence,
    }
    write_json(output / "artifact-manifest.json", artifact)

    runtime_dir = output / "runtime"
    runtime = create_runtime(
        args.server,
        workload=workload,
        manifest=manifest,
        runtime_dir=runtime_dir,
        lookup_mode=args.lookup,
        index_config=args.index_config,
        backend=args.backend,
        cpu=args.cpu,
    )
    raw_rows: list[dict[str, Any]] = []
    correctness: list[dict[str, Any]] = []
    perf_batches: list[dict[str, Any]] = []
    profiles: list[dict[str, Any]] = []
    cleanup_error: str | None = None
    try:
        runtime.setup()
        if runtime.pid is None:
            raise StudyError("server runtime did not expose its pid")
        backend_closure = backend_runtime_module_closure(
            runtime.pid,
            server=args.server,
            backend=runtime.actual_backend,
            expected_executable_path=Path(identity["executable_path"]),
            expected_executable_sha256=identity["executable_sha256"],
        )
        backend_closure_sha256 = backend_closure["identity_sha256"]
        behavioral_runtime_identity_sha256 = combined_behavioral_runtime_identity(
            identity["runtime_closure_sha256"], backend_closure_sha256,
        )
        artifact["backend_runtime_module_closure"] = backend_closure
        artifact["backend_runtime_closure_sha256"] = backend_closure_sha256
        artifact["behavioral_runtime_identity_sha256"] = (
            behavioral_runtime_identity_sha256
        )
        artifact["binary_deduplication"]["runtime_closure_sha256"] = (
            identity["runtime_closure_sha256"]
        )
        artifact["binary_deduplication"][
            "backend_runtime_closure_sha256"
        ] = backend_closure_sha256
        artifact["binary_deduplication"][
            "behavioral_runtime_identity_sha256"
        ] = behavioral_runtime_identity_sha256
        artifact["effective_schema"] = runtime.setup_metadata.get(
            "effective_schema"
        )
        artifact["index_contract_evidence"] = runtime.setup_metadata.get(
            "index_contract_evidence"
        )
        artifact["index_build_evidence"] = runtime.setup_metadata.get(
            "index_build_evidence"
        )
        artifact["import_verification"] = runtime.setup_metadata.get(
            "import_verification"
        )
        artifact["lookup_mode_evidence"] = runtime.setup_metadata.get(
            "lookup_mode_evidence"
        )
        artifact["server_thread_affinity"] = runtime.setup_metadata.get(
            "server_thread_affinity"
        )
        artifact["background_referral_check_control"] = (
            runtime.setup_metadata.get("background_referral_check_control")
        )
        startup_memory = process_metrics(runtime.pid)
        if prewarm_decision["enabled"]:
            state_prewarm = run_state_prewarm(
                runtime=runtime,
                manifest=manifest,
                passes=prewarm_decision["passes"],
            )
        else:
            state_prewarm = disabled_state_prewarm(prewarm_decision["status"])
        artifact["state_prewarm"] = state_prewarm
        approximate_semantics_evidence = (
            run_approximate_semantics_preflight(
                runtime=runtime,
                manifest=manifest,
                selected=selected,
                diagnostic_dir=output / "diagnostics",
            )
        )
        artifact["approximate_semantics_evidence"] = (
            approximate_semantics_evidence
        )
        write_json(output / "artifact-manifest.json", artifact)
        if (
                declared_approximate_policy is not None
                and approximate_semantics_evidence["status"] != "comparable"):
            raise StudyError(
                "selected approximate scenarios failed the mandatory native "
                "semantic-equivalence preflight"
            )
        approximate_semantics_by_scenario = {
            scenario_id: approximate_semantics_evidence
            for scenario_id in selected
            if isinstance(
                manifest["scenarios"][scenario_id].get(
                    "cross_server_comparison"
                ),
                Mapping,
            )
        }
        row_base = {
            "format_version": FORMAT_VERSION,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "run_id": run_id,
            "build_label": args.build_label,
            "expected_source_sha": expected_revision,
            "production_equivalent_revision": production_revision,
            "revision_role": revision_role,
            "executable_sha256": identity["executable_sha256"],
            "server": args.server,
            "backend": runtime.actual_backend,
            "lookup_mode": runtime.actual_lookup_mode,
            "host_class": host_class,
            "host_compatibility_key": host["compatibility_key"],
            "correctness_only": correctness_only,
            "release_timing_evidence": not correctness_only,
            "timing_claims_allowed": not correctness_only,
            "workload_id": manifest["workload_id"],
            "workload_sha256": manifest["workload_sha256"],
            "workload_manifest_sha256": workload_manifest_sha256,
            "workload_execution_root": "workload",
            "copied_workload_verified": True,
            "client_executable_sha256": client["sha256"],
            "runtime_closure_sha256": identity["runtime_closure_sha256"],
            "backend_runtime_closure_sha256": backend_closure_sha256,
            "behavioral_runtime_identity_sha256": (
                behavioral_runtime_identity_sha256
            ),
            "schedule_position": schedule["position"],
            "schedule_design": schedule["design"],
            "schedule_block_id": schedule["block_id"],
            "schedule_state": schedule["state"],
            "schedule_state_fingerprint": schedule["state_fingerprint"],
            "profile_mode": args.profile,
            "background_referral_check_policy_sha256": (
                runtime.setup_metadata.get(
                    "background_referral_check_policy_sha256"
                )
            ),
        }
        host_environment_material = {
            "host_compatibility_key": host["compatibility_key"],
            "governors": host.get("cpu_governors", []),
            "storage": host.get("storage"),
            "cpu_affinity": args.cpu,
            "client_sha256": client["sha256"],
            "connection_policy": "new-connection-per-search",
        }
        host["timing_environment_signature"] = sha256_bytes(
            json.dumps(host_environment_material, sort_keys=True).encode("utf-8")
        )
        timing_environment_material = {
            **host_environment_material,
            "cache_policy": args.cache_policy,
            "state_prewarm": {
                "policy": ("full-database-scan" if prewarm_decision["enabled"]
                           else "disabled"),
                "passes": prewarm_decision["passes"],
            },
            "backend": runtime.actual_backend,
            "perf_collection": args.perf,
            "profile_collection": args.profile,
            "index_intent_sha256": runtime.setup_metadata.get(
                "canonical_index_intent_sha256"
            ),
            "background_referral_check_policy_sha256": (
                runtime.setup_metadata.get(
                    "background_referral_check_policy_sha256"
                )
            ),
        }
        row_base["timing_environment_sha256"] = sha256_bytes(
            json.dumps(timing_environment_material, sort_keys=True).encode("utf-8")
        )
        row_base["perf_mode"] = args.perf
        for scenario_id in selected:
            scenario = manifest["scenarios"][scenario_id]
            filter_path = workload / scenario["filter_file"]
            filter_text = filter_path.read_text(encoding="utf-8").strip()
            expected, expected_hash = expected_dns(workload, scenario)
            scenario_row_base = {
                **row_base,
                "filter_sha256": manifest["files"][scenario["filter_file"]],
                "expected_file_sha256": manifest["files"][scenario["expected_file"]],
                "schema_sha256": manifest["files"][manifest["schema_files"][args.server]],
                "index_intent_sha256": runtime.setup_metadata.get(
                    "canonical_index_intent_sha256"
                ),
            }
            if scenario_id in approximate_semantics_by_scenario:
                scenario_row_base["approximate_semantics_evidence"] = (
                    approximate_semantics_by_scenario[scenario_id]
                )
            if "dynamic-list-correctness" in scenario.get("groups", []):
                record = run_dynamic_control(
                    runtime=runtime, scenario_id=scenario_id, scenario=scenario,
                    filter_text=filter_text, expected=expected, expected_hash=expected_hash,
                    revision=production_revision or expected_revision,
                    diagnostic_dir=output / "diagnostics",
                )
                correctness.append(record)
                continue

            preflight = diagnostic_flight(
                runtime=runtime, scenario_id=scenario_id, scenario=scenario,
                filter_text=filter_text, expected=expected, expected_hash=expected_hash,
                revision=production_revision or expected_revision,
                diagnostic_dir=output / "diagnostics",
                phase="preflight",
            )
            correctness_record = {
                **preflight,
                "evidence_status": "preflight-observed-postflight-pending",
                "diagnostic_flights": {"preflight": preflight},
            }
            if scenario_id in approximate_semantics_by_scenario:
                correctness_record["approximate_semantics_evidence"] = (
                    approximate_semantics_by_scenario[scenario_id]
                )
            correctness.append(correctness_record)

            runtime.setup_metadata.setdefault(
                "server_thread_affinity_pre_timing_checks", {}
            )[scenario_id] = runtime.verify_affinity()
            attribute_variants: list[tuple[str, Sequence[str]]] = [
                ("attrs-1.1", scenario.get("requested_attributes", ["1.1"]))
            ]
            if scenario_id in {
                "principal-with-sdn2-equality", "principal-without-sdn2-equality"
            }:
                attribute_variants.append(("normal-attributes", NORMAL_PRIMARY_ATTRIBUTES))

            for variant_name, attributes in attribute_variants:
                for iteration in range(1, args.warmups + 1):
                    raw_rows.append(measure_one(
                        runtime=runtime, scenario_id=scenario_id, scenario=scenario,
                        filter_text=filter_text, expected=expected, expected_hash=expected_hash,
                        attributes=attributes, attribute_variant=variant_name,
                        phase="warmup", iteration=iteration, cache_policy=args.cache_policy,
                        row_base=scenario_row_base,
                    ))

                perf_required = args.perf == "on"
                perf_enabled = args.perf == "on" or (args.perf == "auto" and not correctness_only)
                if not perf_enabled:
                    disabled_perf = perf_collection_identity({
                        "status": "disabled",
                        "events": [],
                        "software_fallback": False,
                        "unavailable_events": [],
                    })
                    for iteration in range(1, args.repeat + 1):
                        measured_row = measure_one(
                            runtime=runtime, scenario_id=scenario_id, scenario=scenario,
                            filter_text=filter_text, expected=expected, expected_hash=expected_hash,
                            attributes=attributes, attribute_variant=variant_name,
                            phase="measured", iteration=iteration, cache_policy=args.cache_policy,
                            row_base=scenario_row_base,
                        )
                        measured_row.update({
                            "perf_collection_class": disabled_perf[
                                "collection_class"
                            ],
                            "perf_collection_signature": disabled_perf[
                                "collection_signature"
                            ],
                        })
                        raw_rows.append(measured_row)
                else:
                    for batch_index, iterations in enumerate(
                            perf_iteration_batches(args.repeat), 1):
                        batch_id = (
                            f"{run_id}:{scenario_id}:{variant_name}:"
                            f"perf-stat:{batch_index}"
                        )
                        perf_background_guard = (
                            runtime.begin_background_quiet_collection(
                                f"{scenario_id} {variant_name} perf-stat "
                                f"batch {batch_index}"
                            )
                        )
                        batch_start = len(raw_rows)
                        perf_process: subprocess.Popen[str] | None = None
                        perf_meta: dict[str, Any] = {
                            "status": "not-started"
                        }
                        cpu_before: Mapping[str, Any] | None = None
                        cpu_after: Mapping[str, Any] | None = None
                        try:
                            perf_process, perf_meta = perf_start(
                                runtime.pid,
                                output / "profiles" / (
                                    f"{scenario_id}-{variant_name}-perf-stat-"
                                    f"{batch_index}.csv"
                                ),
                                perf_required,
                            )
                            cpu_before = process_metrics(runtime.pid)
                            for iteration in iterations:
                                raw_rows.append(measure_one(
                                    runtime=runtime,
                                    scenario_id=scenario_id,
                                    scenario=scenario,
                                    filter_text=filter_text,
                                    expected=expected,
                                    expected_hash=expected_hash,
                                    attributes=attributes,
                                    attribute_variant=variant_name,
                                    phase="measured",
                                    iteration=iteration,
                                    cache_policy=args.cache_policy,
                                    row_base=scenario_row_base,
                                ))
                        finally:
                            try:
                                cpu_after = process_metrics(runtime.pid)
                            finally:
                                try:
                                    perf_meta = perf_stop(
                                        perf_process, perf_meta
                                    )
                                finally:
                                    perf_background_guard = (
                                        runtime.finish_background_quiet_collection(
                                            perf_background_guard
                                        )
                                    )
                        if cpu_before is None or cpu_after is None:
                            raise StudyError(
                                f"{batch_id}: perf batch CPU evidence is missing"
                            )
                        batch_rows = raw_rows[batch_start:]
                        perf_meta.update({
                            "batch_id": batch_id,
                            "scenario": scenario_id,
                            "attribute_variant": variant_name,
                            "row_ids": [row["row_id"] for row in batch_rows],
                            "collection_scope": (
                                "server-process aggregate over an independent "
                                "measured batch"
                            ),
                            "count_semantics": (
                                "batch aggregates normalized once by operation_count; "
                                "not independent per-search counter samples"
                            ),
                            "background_quiet_window": (
                                perf_background_guard
                            ),
                        })
                        perf_meta = finalize_perf_batch(
                            perf_meta,
                            operation_count=len(batch_rows),
                            cpu_before=cpu_before,
                            cpu_after=cpu_after,
                            required=perf_required,
                        )
                        collection = perf_collection_identity(perf_meta)
                        perf_meta.update(collection)
                        perf_path_value = perf_meta.get("path")
                        if isinstance(perf_path_value, str):
                            perf_path = Path(perf_path_value)
                            perf_observed = (
                                perf_path.is_file()
                                and perf_path.stat().st_size > 0
                            )
                            portable_perf_path = perf_path.resolve().relative_to(
                                output.resolve()
                            ).as_posix()
                            perf_meta["path"] = portable_perf_path
                            perf_meta["perf_stat_artifact"] = {
                                "evidence_status": (
                                    "observed" if perf_observed
                                    else "not-produced"
                                ),
                                "path": portable_perf_path,
                                "sha256": (
                                    sha256_file(perf_path)
                                    if perf_observed else None
                                ),
                                "size_bytes": (
                                    perf_path.stat().st_size
                                    if perf_observed else None
                                ),
                            }
                        link_rows_to_perf_batch(
                            batch_rows, batch_id, collection,
                        )
                        perf_batches.append(perf_meta)

            postflight = diagnostic_flight(
                runtime=runtime, scenario_id=scenario_id, scenario=scenario,
                filter_text=filter_text, expected=expected,
                expected_hash=expected_hash,
                revision=production_revision or expected_revision,
                diagnostic_dir=output / "diagnostics", phase="postflight",
            )
            correctness_record["diagnostic_flights"]["postflight"] = postflight
            correctness_record["postflight"] = postflight
            correctness_record["postflight_verified"] = True
            correctness_record["pre_post_mechanism_match"] = (
                preflight["mechanism_signature_sha256"]
                == postflight["mechanism_signature_sha256"]
            )
            if not correctness_record["pre_post_mechanism_match"]:
                raise StudyError(
                    f"{scenario_id}: pre/post mechanism diagnostics changed"
                )
            correctness_record["evidence_status"] = "preflight-and-postflight-observed"

            should_profile = (
                args.profile == "on"
                or (args.profile == "auto" and not correctness_only and (
                    "acceptance" in scenario.get("groups", [])
                    or "combined-features" in scenario.get("groups", [])
                    or "presence-index" in scenario.get("groups", [])
                ))
            )
            profile = run_profile(
                runtime, scenario_id, scenario, filter_text,
                output / "profiles" / f"{scenario_id}.perf.data", should_profile,
                expected, expected_hash, required=args.profile == "on",
                bundle_root=output,
            )
            profile["scenario"] = scenario_id
            profiles.append(profile)
            lookup_consumption = profile["lookup_consumption"]
            correctness_record["profile_lookup_consumption"] = (
                lookup_consumption
            )
            correctness_record["lookup_consumption_status"] = (
                lookup_consumption["status"]
            )
            correctness_record["lookup_consumption_directly_reported"] = (
                lookup_consumption["status"] == "consumed"
            )
            write_json(output / "raw-results.json", {
                "format_version": FORMAT_VERSION,
                "evidence_contract_version": (
                    NATIVE_EVIDENCE_CONTRACT_VERSION
                ),
                "host_class": host_class,
                "correctness_only": correctness_only,
                "release_timing_evidence": not correctness_only,
                "timing_claims_allowed": not correctness_only,
                "approximate_semantics_evidence": (
                    approximate_semantics_evidence
                ),
                "rows": raw_rows,
                "perf_batches": perf_batches,
            })
            write_json(output / "correctness.json", {
                "format_version": FORMAT_VERSION,
                "evidence_contract_version": (
                    NATIVE_EVIDENCE_CONTRACT_VERSION
                ),
                "host_class": host_class,
                "correctness_only": correctness_only,
                "release_timing_evidence": not correctness_only,
                "timing_claims_allowed": not correctness_only,
                "approximate_semantics_evidence": (
                    approximate_semantics_evidence
                ),
                "scenarios": correctness,
            })

        profile_by_scenario: dict[str, dict[str, str]] = {}
        for profile in profiles:
            profile_identity = profile_collection_identity(profile)
            profile["collection_class"] = profile_identity[
                "collection_class"
            ]
            profile["collection_signature"] = profile_identity[
                "collection_signature"
            ]
            scenario_id = profile.get("scenario")
            if isinstance(scenario_id, str):
                profile_by_scenario[scenario_id] = profile_identity
        for row in raw_rows:
            scenario_id = row.get("scenario")
            identity_for_scenario = profile_by_scenario.get(
                str(scenario_id)
            )
            if identity_for_scenario is not None:
                row["profile_collection_class"] = identity_for_scenario[
                    "collection_class"
                ]
                row["profile_collection_signature"] = identity_for_scenario[
                    "collection_signature"
                ]

        perf_collection_classes = sorted({
            str(row["perf_collection_class"])
            for row in raw_rows
            if row.get("phase") == "measured"
            and isinstance(row.get("perf_collection_class"), str)
        })
        perf_collection_signatures = sorted({
            str(row["perf_collection_signature"])
            for row in raw_rows
            if row.get("phase") == "measured"
            and isinstance(row.get("perf_collection_signature"), str)
        })
        profile_collection_classes = sorted({
            str(profile["collection_class"])
            for profile in profiles
            if isinstance(profile.get("collection_class"), str)
        })
        profile_collection_signatures = sorted({
            str(profile["collection_signature"])
            for profile in profiles
            if isinstance(profile.get("collection_signature"), str)
        })
        profile_collection_states = sorted(({
            "scenario": profile.get("scenario"),
            "status": profile.get("status"),
            "sampling_event": profile.get("sampling_event"),
            "software_fallback": profile.get("software_fallback") is True,
        } for profile in profiles), key=lambda value: str(value["scenario"]))
        schedule_state_material = {
            "format_version": 1,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "server": args.server,
            "source_revision": expected_revision,
            "production_revision": production_revision,
            "executable_sha256": identity["executable_sha256"],
            "installed_package_closure_sha256": (
                installed_package_closure_sha256
            ),
            "runtime_closure_sha256": identity["runtime_closure_sha256"],
            "backend_runtime_closure_sha256": backend_closure_sha256,
            "behavioral_runtime_identity_sha256": (
                behavioral_runtime_identity_sha256
            ),
            "lookup_mode": runtime.actual_lookup_mode,
            "backend": runtime.actual_backend,
            "index_config": args.index_config,
            "cache_policy": args.cache_policy,
            "perf_mode": args.perf,
            "perf_collection_classes": perf_collection_classes,
            "perf_collection_signatures": perf_collection_signatures,
            "profile_mode": args.profile,
            "profile_collection_states": profile_collection_states,
            "connection_policy": "new-connection-per-search",
            "bind_class": "administrative",
            "repeat_count": args.repeat,
            "warmup_count": args.warmups,
            "cpu_affinity": args.cpu,
            "scenario_order": args.scenario_order,
            "order_seed": args.order_seed,
            "selected_scenarios": list(selected),
        }
        schedule["state_fingerprint_material"] = schedule_state_material
        schedule["state_fingerprint"] = sha256_bytes(json.dumps(
            schedule_state_material, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
        for row in raw_rows:
            row["schedule_state_fingerprint"] = schedule[
                "state_fingerprint"
            ]
        attribute_variant_contract: dict[str, dict[str, list[str]]] = {}
        for scenario_id in selected:
            scenario = manifest["scenarios"][scenario_id]
            variants = {
                "attrs-1.1": list(
                    scenario.get("requested_attributes", ["1.1"])
                ),
            }
            if scenario_id in {
                    "principal-with-sdn2-equality",
                    "principal-without-sdn2-equality"}:
                variants["normal-attributes"] = list(
                    NORMAL_PRIMARY_ATTRIBUTES
                )
            attribute_variant_contract[scenario_id] = variants
        configuration_contract = {
            "format_version": 1,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "server": args.server,
            "lookup_mode": runtime.actual_lookup_mode,
            "backend": runtime.actual_backend,
            "index_config": args.index_config,
            "cache_policy": args.cache_policy,
            "perf_mode": args.perf,
            "profile_mode": args.profile,
            "profile_collection_classes": profile_collection_classes,
            "profile_collection_signatures": profile_collection_signatures,
            "perf_collection_classes": perf_collection_classes,
            "perf_collection_signatures": perf_collection_signatures,
            "connection_policy": "new-connection-per-search",
            "bind_class": "administrative",
            "timing_environment_sha256": row_base[
                "timing_environment_sha256"
            ],
            "attribute_variants": attribute_variant_contract,
        }

        run_manifest = {
            "format_version": FORMAT_VERSION,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "run_id": run_id,
            "created_at": started_at,
            "completed_at": utc_now(),
            "status": "complete",
            "mode": mode,
            "host_class": host_class,
            "correctness_only": correctness_only,
            "release_timing_evidence": not correctness_only,
            "timing_claims_allowed": not correctness_only,
            "host": host,
            "invocation": invocation,
            "harness_identity": harness,
            "build_label": args.build_label,
            "expected_source_sha": expected_revision,
            "production_equivalent_revision": production_revision,
            "production_equivalence": production_equivalence,
            "revision_role": revision_role,
            "server": args.server,
            "lookup_mode_requested": args.lookup,
            "lookup_mode_actual": runtime.actual_lookup_mode,
            "perf_mode": args.perf,
            "backend_requested": args.backend,
            "backend_actual": runtime.actual_backend,
            "index_config": args.index_config,
            "selected_scenarios": selected,
            "repeat_count": args.repeat,
            "warmup_count": args.warmups,
            "prewarm_passes": prewarm_decision["passes"],
            "state_prewarm": state_prewarm,
            "cache_policy": args.cache_policy,
            "connection_policy": "new-connection-per-search",
            "bind_class": "administrative",
            "configuration_contract": configuration_contract,
            "scenario_order": args.scenario_order,
            "order_seed": args.order_seed,
            "schedule_position": schedule["position"],
            "schedule_design": schedule["design"],
            "schedule_block_id": schedule["block_id"],
            "schedule_state": schedule["state"],
            "schedule_state_fingerprint": schedule["state_fingerprint"],
            "schedule": schedule,
            "cpu_affinity": args.cpu,
            "startup_memory": startup_memory,
            "server_setup": runtime.setup_metadata,
            "backend_runtime_module_closure": backend_closure,
            "installed_package_closure_sha256": (
                installed_package_closure_sha256
            ),
            "runtime_closure_sha256": identity["runtime_closure_sha256"],
            "backend_runtime_closure_sha256": backend_closure_sha256,
            "behavioral_runtime_identity_sha256": (
                behavioral_runtime_identity_sha256
            ),
            "workload_id": manifest["workload_id"],
            "workload_sha256": manifest["workload_sha256"],
            "workload_manifest_sha256": workload_manifest_sha256,
            "workload_execution_root": "workload",
            "copied_workload_verified": True,
            "approximate_semantics_evidence": (
                approximate_semantics_by_scenario
            ),
            "timing_environment_sha256": row_base["timing_environment_sha256"],
            "raw_result_rows": len(raw_rows),
            "correctness_status": "pass",
            "profiles": profiles,
            "profile_mode": args.profile,
            "profile_collection_classes": profile_collection_classes,
            "profile_collection_signatures": profile_collection_signatures,
            "perf_collection_classes": perf_collection_classes,
            "perf_collection_signatures": perf_collection_signatures,
        }
        write_json(output / "run-manifest.json", run_manifest)
        write_json(output / "raw-results.json", {
            "format_version": FORMAT_VERSION,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "host_class": host_class,
            "correctness_only": correctness_only,
            "release_timing_evidence": not correctness_only,
            "timing_claims_allowed": not correctness_only,
            "approximate_semantics_evidence": (
                approximate_semantics_evidence
            ),
            "rows": raw_rows,
            "perf_batches": perf_batches,
        })
        write_json(output / "correctness.json", {
            "format_version": FORMAT_VERSION,
            "evidence_contract_version": NATIVE_EVIDENCE_CONTRACT_VERSION,
            "host_class": host_class,
            "correctness_only": correctness_only,
            "release_timing_evidence": not correctness_only,
            "timing_claims_allowed": not correctness_only,
            "approximate_semantics_evidence": (
                approximate_semantics_evidence
            ),
            "scenarios": correctness,
        })
        write_environment_sidecar(output, build_environment_record(
            environment_start,
            capture_environment_snapshot(),
            run_id=run_id,
            perf_mode=args.perf,
            profile_mode=args.profile,
        ))
    finally:
        logs_dir = output / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        if runtime.access_log and runtime.access_log.exists():
            shutil.copy2(runtime.access_log, logs_dir / "server-access.log")
        if (
            runtime.error_log
            and runtime.error_log.exists()
            and runtime.error_log != runtime.access_log
        ):
            shutil.copy2(runtime.error_log, logs_dir / "server-error.log")
        if not args.retain:
            try:
                runtime.cleanup()
            except Exception as error:  # preserve artifacts while surfacing cleanup failure
                cleanup_error = str(error)
        if cleanup_error:
            (output / "CLEANUP-FAILED").write_text(cleanup_error + "\n", encoding="utf-8")
    if cleanup_error:
        raise StudyError(f"study completed but cleanup failed: {cleanup_error}")
    (output / "INCOMPLETE").unlink(missing_ok=True)
    (output / "COMPLETE").write_text(f"completed {utc_now()}\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "server": args.server,
        "build_label": args.build_label,
        "host_class": host_class,
        "correctness_only": correctness_only,
        "release_timing_evidence": not correctness_only,
        "scenarios": len(selected),
        "raw_rows": len(raw_rows),
    }, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("native-timing", "correctness-only"), default="correctness-only")
    parser.add_argument("--server", choices=("389ds", "openldap"), required=True)
    parser.add_argument("--build-label", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--operator-assertion", default="operator supplied and installed the declared package")
    parser.add_argument("--lookup", choices=("on", "off", "unsupported", "auto"), default="auto")
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--scenario-group", action="append", default=[])
    parser.add_argument("--smoke-selected", action="store_true")
    parser.add_argument(
        "--index-config",
        choices=(
            "baseline-no-presence", "presence-sdn1", "presence-sdn2",
            "presence-both", "without-sdn1-equality", "without-sdn2-equality",
        ),
        default="baseline-no-presence",
    )
    parser.add_argument("--backend", choices=("mdb", "bdb"), default="mdb")
    parser.add_argument("--repeat", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--prewarm", choices=("auto", "on", "off"), default="auto")
    parser.add_argument("--prewarm-passes", type=int, default=3)
    parser.add_argument("--cache-policy", choices=("warm", "cold"), default="warm")
    parser.add_argument("--host-class")
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--perf", choices=("auto", "on", "off"), default="auto")
    parser.add_argument("--profile", choices=("auto", "on", "off"), default="auto")
    parser.add_argument("--scenario-order", choices=("manifest", "randomized"), default="manifest")
    parser.add_argument("--order-seed", type=int, default=38920260720)
    parser.add_argument(
        "--schedule-design",
        choices=("unspecified", "screen", "abba"),
        default="unspecified",
        help=(
            "external cross-build schedule contract; only a complete ABBA "
            "block can satisfy release ordering"
        ),
    )
    parser.add_argument(
        "--schedule-block",
        help="stable block identifier shared by the four positions of one ABBA block",
    )
    parser.add_argument("--schedule-position", default="unspecified")
    parser.add_argument("--allow-rpm-verify-differences", action="store_true")
    cleanup = parser.add_mutually_exclusive_group()
    cleanup.add_argument("--cleanup", dest="retain", action="store_false")
    cleanup.add_argument("--retain", dest="retain", action="store_true")
    parser.set_defaults(retain=False)
    return parser


def main(argv: Sequence[str] | None = None, *, forced_mode: str | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups may not be negative")
    try:
        return run(args, forced_mode=forced_mode)
    except StudyError as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
