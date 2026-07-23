"""Fresh 389 DS and OpenLDAP instance management for the study."""

from __future__ import annotations

import base64
from collections import Counter
import errno
import json
import hashlib
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .platform_info import (
    StudyError,
    command_path,
    read_text,
    require_commands,
    run_command,
    sha256_file,
)


SUFFIX = "dc=example,dc=com"
PEOPLE_BASE = f"ou=people,{SUFFIX}"
PASSWORD = os.environ.get("LFSTUDY_PASSWORD", "LargeFilterStudy-Only-42")
OR_LOOKUP_ATTR = "nsslapd-enable-or-filter-lookup"
REFERRAL_CHECK_PERIOD_SECONDS = 3600
ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS = 260
REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS = 5.0
REFERRAL_BARRIER_STABILITY_SECONDS = 0.1
REFERRAL_BARRIER_TIMEOUT_SECONDS = 60.0
REFERRAL_SETUP_FINALIZATION_RESERVE_SECONDS = 5.0
REFERRAL_RESTART_RESERVE_SECONDS = 55.0
VATTR_CHECK_DELAY_SECONDS = 3
VATTR_CHECK_STABILITY_SECONDS = 1.0
VATTR_CHECK_TIMEOUT_SECONDS = 60.0
VATTR_CHECK_FILTER = (
    "(&(objectclass=ldapsubentry)"
    "(|(objectclass=nsRoleDefinition)(objectclass=cosSuperDefinition)))"
)
INTERNAL_CONNECTION_PATTERN_TEXT = (
    r"(?:conn=Internal(?:\([^)]*\))?|conn=\d+\s+\(Internal\))"
)
INTERNAL_OPERATION_IDENTITY_PATTERN_TEXT = (
    rf"(?P<identity>{INTERNAL_CONNECTION_PATTERN_TEXT}"
    r"\s+op=\d+\(\d+\)\(\d+\))"
)
INTERNAL_ACCESS_PATTERN = re.compile(
    rf"\b{INTERNAL_CONNECTION_PATTERN_TEXT}"
)
ROOT_INTERNAL_ACCESS_PATTERN = re.compile(
    r"\bconn=Internal(?:\([^)]*\))?"
)
NESTED_INTERNAL_ACCESS_PATTERN = re.compile(
    r"\bconn=(?P<connection>\d+)\s+\(Internal\)"
)
REFERRAL_ACCESS_PATTERN = re.compile(
    rf"\b{INTERNAL_OPERATION_IDENTITY_PATTERN_TEXT}.*"
    r"attribute=objectClass\s+key\(eq\)=referral\b",
    re.I,
)
INTERNAL_STAT_COMPLETION_PATTERN = re.compile(
    rf"\b{INTERNAL_OPERATION_IDENTITY_PATTERN_TEXT}"
    r"\s*STAT read index: duration\b",
    re.I,
)
VATTR_CHECK_ACCESS_PATTERN = re.compile(
    rf'\b{INTERNAL_OPERATION_IDENTITY_PATTERN_TEXT}\s+SRCH\s+'
    rf'base="{re.escape(SUFFIX)}"\s+scope=2\s+'
    rf'filter="{re.escape(VATTR_CHECK_FILTER)}"\s+attrs=ALL\b',
    re.I,
)
INTERNAL_SUCCESS_RESULT_PATTERN = re.compile(
    rf"\b{INTERNAL_OPERATION_IDENTITY_PATTERN_TEXT}"
    r"\s+RESULT\s+err=0\s+tag=48\b",
    re.I,
)
SUBSCHEMA_ATTRIBUTES = (
    "attributeTypes", "objectClasses", "matchingRules", "ldapSyntaxes",
)
STUDY_ATTRIBUTE_SCHEMA_IDENTITIES = {
    f"1.3.6.1.4.1.2312.999.2026.100.{number}": name
    for number, name in enumerate(
        (
            "sString1", "sString2", "sString3", "sString4",
            "sDN1", "sDN2", "sSub", "sApprox",
        ),
        1,
    )
}
STUDY_OBJECTCLASS_SCHEMA_IDENTITIES = {
    "1.3.6.1.4.1.2312.999.2026.100.20": "largeFilterStudyPerson",
}
DIRECTORY_STRING_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15"
DISTINGUISHED_NAME_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.12"
STUDY_ATTRIBUTE_SCHEMA_CONTRACT = {
    oid: {
        "name": name,
        "syntax": (
            DISTINGUISHED_NAME_SYNTAX
            if name in {"sDN1", "sDN2"}
            else DIRECTORY_STRING_SYNTAX
        ),
        "equality": (
            "distinguishedNameMatch"
            if name in {"sDN1", "sDN2"}
            else "caseIgnoreMatch"
        ),
        "substring": (
            "caseIgnoreSubstringsMatch"
            if name in {"sString1", "sString2", "sString3", "sString4", "sSub"}
            else None
        ),
        "single_value": name != "sDN1",
    }
    for oid, name in STUDY_ATTRIBUTE_SCHEMA_IDENTITIES.items()
}
STUDY_OBJECTCLASS_SCHEMA_CONTRACT = {
    "1.3.6.1.4.1.2312.999.2026.100.20": {
        "name": "largeFilterStudyPerson",
        "superior": "top",
        "kind": "AUXILIARY",
        "may": sorted(STUDY_ATTRIBUTE_SCHEMA_IDENTITIES.values()),
    },
}


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def file_cursor(path: Path) -> dict[str, int | bool]:
    """Capture an append-only byte cursor with rotation/truncation identity."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"exists": False, "device": 0, "inode": 0, "offset": 0}
    return {
        "exists": True,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "offset": stat.st_size,
    }


def read_after_cursor(path: Path, cursor: Mapping[str, Any]) -> str:
    """Read exactly the bytes appended after ``cursor`` or reject log churn."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        if not cursor.get("exists"):
            return ""
        raise StudyError(f"diagnostic log disappeared after cursor capture: {path}")
    offset = int(cursor.get("offset", 0))
    if cursor.get("exists") and (
            stat.st_dev != cursor.get("device")
            or stat.st_ino != cursor.get("inode")):
        raise StudyError(f"diagnostic log rotated after cursor capture: {path}")
    if stat.st_size < offset:
        raise StudyError(f"diagnostic log was truncated after cursor capture: {path}")
    with path.open("rb") as stream:
        stream.seek(offset)
        return stream.read().decode("utf-8", errors="replace")


def internal_access_lines(access: str) -> list[str]:
    """Return server-internal operations mixed into an access-log window."""
    return [
        line for line in access.splitlines()
        if INTERNAL_ACCESS_PATTERN.search(line)
    ]


def root_internal_access_lines(access: str) -> list[str]:
    """Return maintenance operations with no owning external connection."""
    return [
        line for line in access.splitlines()
        if ROOT_INTERNAL_ACCESS_PATTERN.search(line)
    ]


def nested_internal_access_lines(access: str) -> list[str]:
    """Return internal operations nested under an external connection."""
    return [
        line for line in access.splitlines()
        if NESTED_INTERNAL_ACCESS_PATTERN.search(line)
    ]


def referral_monitor_access_lines(access: str) -> list[str]:
    """Return periodic referral-monitor index reads in an access window."""
    return [
        line for line in access.splitlines()
        if REFERRAL_ACCESS_PATTERN.search(line)
    ]


def referral_monitor_operation_evidence(access: str) -> dict[str, Any]:
    """Pair referral STAT starts with same-internal-operation completions."""
    starts: Counter[str] = Counter()
    completions: Counter[str] = Counter()
    pending: Counter[str] = Counter()
    start_lines: list[str] = []
    completion_lines: list[str] = []
    for line in access.splitlines():
        start = REFERRAL_ACCESS_PATTERN.search(line)
        if start:
            identity = start.group("identity")
            starts[identity] += 1
            pending[identity] += 1
            start_lines.append(line)
        completion = INTERNAL_STAT_COMPLETION_PATTERN.search(line)
        if completion and pending[completion.group("identity")] > 0:
            identity = completion.group("identity")
            pending[identity] -= 1
            completions[identity] += 1
            completion_lines.append(line)
    identities = sorted(set(starts) | set(completions))
    paired = {
        identity: completions[identity]
        for identity in identities if completions[identity]
    }
    unmatched_starts = {
        identity: pending[identity]
        for identity in identities
        if pending[identity] > 0
    }
    return {
        "start_line_count": len(start_lines),
        "completion_line_count": len(completion_lines),
        "paired_operation_count": sum(paired.values()),
        "paired_by_identity": paired,
        "unmatched_referral_start_count": sum(unmatched_starts.values()),
        "unmatched_referral_starts_by_identity": unmatched_starts,
        "start_lines": start_lines,
        "completion_lines": completion_lines,
    }


def vattr_check_operation_evidence(access: str) -> dict[str, Any]:
    """Pair the delayed vattr role/COS search with its later result.

    Internal operation identifiers can be reused by different startup
    threads.  Pairing is therefore deliberately ordered: a result that
    precedes the exact vattr search cannot satisfy this barrier.
    """
    starts: Counter[str] = Counter()
    completions: Counter[str] = Counter()
    pending: Counter[str] = Counter()
    start_lines: list[str] = []
    completion_lines: list[str] = []
    for line in access.splitlines():
        start = VATTR_CHECK_ACCESS_PATTERN.search(line)
        if start:
            identity = start.group("identity")
            starts[identity] += 1
            pending[identity] += 1
            start_lines.append(line)
        completion = INTERNAL_SUCCESS_RESULT_PATTERN.search(line)
        if completion and pending[completion.group("identity")] > 0:
            identity = completion.group("identity")
            pending[identity] -= 1
            completions[identity] += 1
            completion_lines.append(line)
    identities = sorted(set(starts) | set(completions))
    paired = {
        identity: completions[identity]
        for identity in identities if completions[identity]
    }
    unmatched = {
        identity: pending[identity]
        for identity in identities if pending[identity] > 0
    }
    return {
        "start_line_count": len(start_lines),
        "completion_line_count": len(completion_lines),
        "paired_operation_count": sum(paired.values()),
        "paired_by_identity": paired,
        "unmatched_start_count": sum(unmatched.values()),
        "unmatched_starts_by_identity": unmatched,
        "start_lines": start_lines,
        "completion_lines": completion_lines,
    }


def referral_quiet_window(
        monotonic_seconds: float,
        *, interval_seconds: int = REFERRAL_CHECK_PERIOD_SECONDS,
        safety_margin_seconds: float = (
            REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS
        )) -> dict[str, int | float]:
    """Describe the epoch-aligned interval before the next referral tick."""
    if not math.isfinite(monotonic_seconds) or monotonic_seconds < 0:
        raise StudyError(
            f"invalid CLOCK_MONOTONIC sample: {monotonic_seconds!r}"
        )
    if interval_seconds <= 0:
        raise StudyError(f"invalid referral interval: {interval_seconds!r}")
    if (
            not math.isfinite(safety_margin_seconds)
            or safety_margin_seconds <= 0
            or safety_margin_seconds >= interval_seconds):
        raise StudyError(
            f"invalid referral safety margin: {safety_margin_seconds!r}"
        )
    bucket = math.floor(monotonic_seconds / interval_seconds)
    boundary = float((bucket + 1) * interval_seconds)
    deadline = boundary - safety_margin_seconds
    return {
        "bucket": bucket,
        "next_boundary_monotonic_seconds": boundary,
        "deadline_monotonic_seconds": deadline,
        "remaining_to_boundary_seconds": boundary - monotonic_seconds,
        "remaining_to_deadline_seconds": deadline - monotonic_seconds,
    }


def decode_ldif_dn(line: str) -> str | None:
    if line.startswith("dn: "):
        return line[4:].strip()
    if line.startswith("dn:: "):
        try:
            return base64.b64decode(line[5:].strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return None


def parse_search_dns(stdout: str) -> list[str]:
    dns: list[str] = []
    for line in stdout.splitlines():
        value = decode_ldif_dn(line)
        if value is not None:
            dns.append(value.lower())
    return sorted(dns)


def parse_live_subschema(text: str) -> dict[str, list[str]]:
    """Unfold and canonicalize the four required subschema value classes."""
    unfolded: list[str] = []
    for line in text.splitlines():
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    by_casefold = {attribute.casefold(): attribute for attribute in SUBSCHEMA_ATTRIBUTES}
    values: dict[str, list[str]] = {
        attribute: [] for attribute in SUBSCHEMA_ATTRIBUTES
    }
    for line in unfolded:
        match = re.match(r"^([^:]+)(::?)\s?(.*)$", line)
        if not match:
            continue
        canonical_attribute = by_casefold.get(match.group(1).casefold())
        if canonical_attribute is None:
            continue
        raw_value = match.group(3)
        if match.group(2) == "::":
            try:
                raw_value = base64.b64decode(raw_value).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise StudyError(
                    f"could not decode live {canonical_attribute} schema value"
                ) from error
        values[canonical_attribute].append(
            re.sub(r"\s+", " ", raw_value).strip()
        )
    return {
        attribute: sorted(set(category_values))
        for attribute, category_values in values.items()
    }


def _schema_keyword_value(definition: str, keyword: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(keyword)}\s+([^\s()]+)", definition, re.I,
    )
    return match.group(1) if match else None


def _schema_token_equivalent(observed: str | None, expected: str) -> bool:
    aliases = {
        "caseignorematch": {"caseignorematch", "2.5.13.2"},
        "caseignoresubstringsmatch": {
            "caseignoresubstringsmatch", "2.5.13.4",
        },
        "distinguishednamematch": {"distinguishednamematch", "2.5.13.1"},
        "top": {"top", "2.5.6.0"},
    }
    if observed is None:
        return False
    expected_folded = expected.casefold()
    return observed.casefold() in aliases.get(expected_folded, {expected_folded})


def _schema_definition(
        definitions: Sequence[str], oid: str, name: str,
        category: str) -> str:
    matches = [
        value for value in definitions
        if re.search(rf"\(\s*{re.escape(oid)}(?:\s|$)", value)
        and re.search(
            rf"\bNAME\s+(?:\(\s*)?['\"]{re.escape(name)}['\"]",
            value,
            re.I,
        )
    ]
    if len(matches) != 1:
        raise StudyError(
            f"live effective schema requires exactly one {category} "
            f"definition for {oid}:{name}; observed {len(matches)}"
        )
    return matches[0]


def _objectclass_may_values(definition: str) -> list[str] | None:
    match = re.search(r"\bMAY\s+\(\s*([^)]*?)\s*\)", definition, re.I)
    if not match:
        return None
    return sorted({
        token.casefold()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9-]*", match.group(1))
    })


def verify_study_schema_identities(
        canonical: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    """Prove the live custom schema has the exact study semantics.

    OID/name presence alone is not sufficient for a cross-server experiment:
    a stale definition with the wrong matching rule, syntax, cardinality, or
    object-class membership would silently change the measured workload.  The
    normalized semantic material returned here is also hashed into the run
    evidence so the merger can bind its release disposition to this check.
    """
    checks: dict[str, Any] = {}
    normalized_attributes: dict[str, Any] = {}
    normalized_objectclasses: dict[str, Any] = {}
    failures: list[str] = []
    attribute_definitions = list(canonical.get("attributeTypes", ()))
    objectclass_definitions = list(canonical.get("objectClasses", ()))

    for oid, expected in STUDY_ATTRIBUTE_SCHEMA_CONTRACT.items():
        name = str(expected["name"])
        key = f"{oid}:{name}"
        try:
            definition = _schema_definition(
                attribute_definitions, oid, name, "attributeTypes",
            )
        except StudyError as error:
            failures.append(str(error))
            checks[key] = {
                "category": "attributeTypes", "oid": oid, "name": name,
                "observed": False, "passed": False,
            }
            continue
        observed_syntax = _schema_keyword_value(definition, "SYNTAX")
        if observed_syntax:
            observed_syntax = observed_syntax.split("{", 1)[0]
        observed = {
            "name": name,
            "syntax": observed_syntax,
            "equality": _schema_keyword_value(definition, "EQUALITY"),
            "substring": _schema_keyword_value(definition, "SUBSTR"),
            "single_value": bool(re.search(r"\bSINGLE-VALUE\b", definition, re.I)),
        }
        field_failures: list[str] = []
        if observed["syntax"] != expected["syntax"]:
            field_failures.append(
                f"syntax expected {expected['syntax']}, observed {observed['syntax']}"
            )
        if not _schema_token_equivalent(
                observed["equality"], str(expected["equality"])):
            field_failures.append(
                f"equality expected {expected['equality']}, "
                f"observed {observed['equality']}"
            )
        expected_substring = expected["substring"]
        if expected_substring is None:
            if observed["substring"] is not None:
                field_failures.append(
                    f"unexpected substring rule {observed['substring']}"
                )
        elif not _schema_token_equivalent(
                observed["substring"], str(expected_substring)):
            field_failures.append(
                f"substring expected {expected_substring}, "
                f"observed {observed['substring']}"
            )
        if observed["single_value"] is not expected["single_value"]:
            field_failures.append(
                f"single_value expected {expected['single_value']}, "
                f"observed {observed['single_value']}"
            )
        passed = not field_failures
        checks[key] = {
            "category": "attributeTypes", "oid": oid, "name": name,
            "observed": True, "passed": passed,
            "expected": dict(expected), "observed_semantics": observed,
            "definition_sha256": hashlib.sha256(
                definition.encode("utf-8")
            ).hexdigest(),
            "failures": field_failures,
        }
        normalized_attributes[oid] = observed
        failures.extend(f"{key}: {failure}" for failure in field_failures)

    for oid, expected in STUDY_OBJECTCLASS_SCHEMA_CONTRACT.items():
        name = str(expected["name"])
        key = f"{oid}:{name}"
        try:
            definition = _schema_definition(
                objectclass_definitions, oid, name, "objectClasses",
            )
        except StudyError as error:
            failures.append(str(error))
            checks[key] = {
                "category": "objectClasses", "oid": oid, "name": name,
                "observed": False, "passed": False,
            }
            continue
        observed = {
            "name": name,
            "superior": _schema_keyword_value(definition, "SUP"),
            "kind": "AUXILIARY" if re.search(
                r"\bAUXILIARY\b", definition, re.I,
            ) else None,
            "may": _objectclass_may_values(definition),
        }
        expected_may = sorted(str(value).casefold() for value in expected["may"])
        field_failures = []
        if not _schema_token_equivalent(
                observed["superior"], str(expected["superior"])):
            field_failures.append(
                f"superior expected {expected['superior']}, "
                f"observed {observed['superior']}"
            )
        if observed["kind"] != expected["kind"]:
            field_failures.append(
                f"kind expected {expected['kind']}, observed {observed['kind']}"
            )
        if observed["may"] != expected_may:
            field_failures.append(
                f"MAY expected {expected_may}, observed {observed['may']}"
            )
        passed = not field_failures
        checks[key] = {
            "category": "objectClasses", "oid": oid, "name": name,
            "observed": True, "passed": passed,
            "expected": dict(expected), "observed_semantics": observed,
            "definition_sha256": hashlib.sha256(
                definition.encode("utf-8")
            ).hexdigest(),
            "failures": field_failures,
        }
        normalized_objectclasses[oid] = observed
        failures.extend(f"{key}: {failure}" for failure in field_failures)

    if failures:
        raise StudyError(
            "live effective study schema semantics differ: " + "; ".join(failures)
        )
    # Hash the canonical expected semantics after every observed field has
    # proved equivalent.  Raw servers may spell standard matching rules or
    # ``top`` by name or OID, so hashing their presentation would create a
    # false cross-server mismatch.
    semantic_contract = {
        "format_version": 1,
        "attribute_types": STUDY_ATTRIBUTE_SCHEMA_CONTRACT,
        "object_classes": STUDY_OBJECTCLASS_SCHEMA_CONTRACT,
    }
    semantic_contract_sha256 = hashlib.sha256(json.dumps(
        semantic_contract,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    return {
        "evidence_status": "observed",
        "passed": True,
        "semantic_contract": semantic_contract,
        "semantic_contract_sha256": semantic_contract_sha256,
        "observed_semantics": {
            "attribute_types": normalized_attributes,
            "object_classes": normalized_objectclasses,
        },
        "definitions": checks,
    }


def configured_indexes(
    workload: Path,
    manifest: Mapping[str, Any],
    server: str,
    variant: str,
) -> dict[str, tuple[str, ...]]:
    """Resolve the hashed workload index intent instead of duplicating it."""
    contract = configured_index_contract(
        workload, manifest, server, variant,
    )
    return {
        attribute: types
        for attribute, types in contract.items()
        if types
    }


def configured_index_contract(
    workload: Path,
    manifest: Mapping[str, Any],
    server: str,
    variant: str,
) -> dict[str, tuple[str, ...]]:
    """Return desired types for every workload-controlled attribute.

    Empty tuples are significant: a variant that removes the final desired
    type requires the server-side index entry to be absent.
    """
    relative = manifest.get("index_config_file")
    if not relative:
        raise StudyError("workload manifest has no index_config_file")
    path = (workload / str(relative)).resolve()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        base = document["servers"][server]["baseline"]
        changes = document["variants"][variant]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise StudyError(f"invalid index configuration {path}: {error}") from error
    indexes: dict[str, tuple[str, ...]] = {
        str(attribute): tuple(str(kind) for kind in kinds)
        for attribute, kinds in base.items()
    }
    for attribute, kinds in changes.get("remove", {}).items():
        remaining = tuple(kind for kind in indexes.get(attribute, ()) if kind not in kinds)
        indexes[str(attribute)] = remaining
    for attribute, kinds in changes.get("add", {}).items():
        indexes[str(attribute)] = tuple(
            dict.fromkeys(indexes.get(attribute, ()) + tuple(str(kind) for kind in kinds))
        )
    return {
        attribute: tuple(kind.casefold() for kind in kinds)
        for attribute, kinds in indexes.items()
    }


@dataclass
class SearchResult:
    returncode: int
    stdout: str
    stderr: str
    dns: list[str]


def _dns_sha256(dns: Sequence[str]) -> str:
    return hashlib.sha256(
        "".join(f"{dn}\n" for dn in sorted(dns)).encode("utf-8")
    ).hexdigest()


class ServerRuntime:
    implementation = "unknown"
    root_dn = ""

    def __init__(
        self,
        *,
        workload: Path,
        manifest: Mapping[str, Any],
        runtime_dir: Path,
        lookup_mode: str,
        index_config: str,
        backend: str,
        cpu: int | None,
    ) -> None:
        self.workload = workload
        self.manifest = manifest
        self.runtime_dir = runtime_dir
        self.lookup_mode = lookup_mode
        self.index_config = index_config
        self.backend = backend
        self.cpu = cpu
        self.port = choose_port()
        self.secure_port = choose_port()
        while self.secure_port == self.port:
            self.secure_port = choose_port()
        self.pid: int | None = None
        self.actual_lookup_mode = "unsupported"
        self.actual_backend = "unknown"
        self.access_log: Path | None = None
        self.error_log: Path | None = None
        self.setup_metadata: dict[str, Any] = {}
        self.background_quiet_window_state: dict[str, Any] | None = None
        self.affinity_metadata: dict[str, Any] = {
            "status": "not-requested" if cpu is None else "pending",
            "requested_cpu": cpu,
        }

    @property
    def uri(self) -> str:
        return f"ldap://127.0.0.1:{self.port}"

    def setup(self) -> None:
        raise NotImplementedError

    def cleanup(self) -> None:
        raise NotImplementedError

    def begin_background_quiet_collection(
            self, context: str) -> dict[str, Any]:
        """Start a collection that must not overlap a referral-monitor tick."""
        now = time.clock_gettime(time.CLOCK_MONOTONIC)
        if self.implementation != "389ds":
            return {
                "status": "not-applicable",
                "context": context,
                "clock": "CLOCK_MONOTONIC",
                "bucket": None,
                "start_monotonic_seconds": now,
                "end_monotonic_seconds": None,
                "next_boundary_monotonic_seconds": None,
                "deadline_monotonic_seconds": None,
                "safety_margin_seconds": None,
                "passed": True,
            }
        state = self.background_quiet_window_state
        if not isinstance(state, Mapping):
            raise StudyError(
                f"{context}: background referral quiet window is not established"
            )
        window = referral_quiet_window(now)
        bucket = int(state["bucket"])
        deadline = float(state["deadline_monotonic_seconds"])
        if int(window["bucket"]) != bucket or now >= deadline:
            raise StudyError(
                f"{context}: controlled background-quiet window expired; "
                "discard this bundle and split or rerun it after the next "
                "referral-monitor boundary"
            )
        return {
            "status": "started",
            "context": context,
            "clock": "CLOCK_MONOTONIC",
            "bucket": bucket,
            "start_monotonic_seconds": now,
            "end_monotonic_seconds": None,
            "next_boundary_monotonic_seconds": float(
                state["next_boundary_monotonic_seconds"]
            ),
            "deadline_monotonic_seconds": deadline,
            "safety_margin_seconds": (
                REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS
            ),
            "passed": False,
        }

    def background_quiet_not_applicable(
            self, context: str, reason: str) -> dict[str, Any]:
        """Record that no server-attached collection was attempted."""
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
            "passed": True,
        }

    def finish_background_quiet_collection(
            self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        """Seal a collection and reject evidence that crossed its deadline."""
        now = time.clock_gettime(time.CLOCK_MONOTONIC)
        result = dict(evidence)
        result["end_monotonic_seconds"] = now
        start = float(evidence["start_monotonic_seconds"])
        result["duration_seconds"] = now - start
        if evidence.get("status") == "not-applicable":
            result["passed"] = True
            return result
        state = self.background_quiet_window_state
        if not isinstance(state, Mapping):
            raise StudyError(
                f"{evidence.get('context')}: background referral quiet "
                "window disappeared during collection"
            )
        current = referral_quiet_window(now)
        bucket = int(evidence["bucket"])
        deadline = float(evidence["deadline_monotonic_seconds"])
        passed = (
            evidence.get("status") == "started"
            and int(current["bucket"]) == bucket
            and int(state["bucket"]) == bucket
            and now < deadline
            and start < deadline
        )
        result["status"] = "passed" if passed else "failed-crossed-boundary"
        result["passed"] = passed
        if not passed:
            raise StudyError(
                f"{evidence.get('context')}: collection crossed the "
                "controlled background-quiet deadline; discard this bundle "
                "and split or rerun it after the next referral-monitor boundary"
            )
        return result

    def search(
        self,
        *,
        base: str,
        scope: str,
        filter_text: str,
        attributes: Sequence[str],
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> SearchResult:
        paths = require_commands(["ldapsearch"])
        argv = [
            paths["ldapsearch"], "-LLL", "-x", "-H", self.uri,
            "-D", bind_dn or self.root_dn, "-w", password or PASSWORD,
            "-b", base, "-s", scope, "-o", "ldif-wrap=no",
            filter_text,
        ]
        argv.extend(attributes)
        if self.cpu is not None and command_path("taskset"):
            argv = [command_path("taskset") or "taskset", "-c", str(self.cpu), *argv]
        proc = run_command(argv, check=False, timeout=600)
        return SearchResult(proc.returncode, proc.stdout, proc.stderr, parse_search_dns(proc.stdout))

    def verify_imported_dataset(self) -> dict[str, Any]:
        """Verify live import cardinality and DN identity before any timing."""
        contracts = self.manifest.get("dataset_import_oracles")
        if not isinstance(contracts, Mapping) or set(contracts) != {
                "people", "principal_outer_cohort"}:
            raise StudyError(
                "workload manifest requires people and principal_outer_cohort "
                "dataset import oracles"
            )
        evidence: dict[str, Any] = {}
        for oracle_id in ("people", "principal_outer_cohort"):
            contract = contracts[oracle_id]
            if not isinstance(contract, Mapping):
                raise StudyError(f"dataset import oracle {oracle_id} is invalid")
            expected_count = contract.get("expected_count")
            expected_sha256 = contract.get("expected_sha256")
            if (
                    contract.get("expected_result_code") != "LDAP_SUCCESS"
                    or not isinstance(expected_count, int)
                    or isinstance(expected_count, bool)
                    or expected_count < 1
                    or not isinstance(expected_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
                raise StudyError(
                    f"dataset import oracle {oracle_id} has an invalid result contract"
                )
            attributes = contract.get("requested_attributes")
            if not isinstance(attributes, list) or not attributes or any(
                    not isinstance(value, str) for value in attributes):
                raise StudyError(
                    f"dataset import oracle {oracle_id} has invalid attributes"
                )
            result = self.search(
                base=str(contract.get("base_dn")),
                scope=str(contract.get("scope")),
                filter_text=str(contract.get("filter")),
                attributes=attributes,
            )
            actual_sha256 = _dns_sha256(result.dns)
            passed = (
                result.returncode == 0
                and len(result.dns) == expected_count
                and actual_sha256 == expected_sha256
            )
            record = {
                "evidence_status": "observed",
                "oracle_id": oracle_id,
                "base_dn": contract.get("base_dn"),
                "scope": contract.get("scope"),
                "filter": contract.get("filter"),
                "requested_attributes": list(attributes),
                "expected_result_code": "LDAP_SUCCESS",
                "expected_ldap_result_code": 0,
                "actual_ldap_result_code": result.returncode,
                "expected_count": expected_count,
                "actual_count": len(result.dns),
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
                "passed": passed,
            }
            evidence[oracle_id] = record
            if not passed:
                raise StudyError(
                    f"live dataset import oracle {oracle_id} failed: "
                    f"LDAP {result.returncode}, count {len(result.dns)} "
                    f"(expected {expected_count}), SHA-256 {actual_sha256} "
                    f"(expected {expected_sha256})"
                )
        return {
            "evidence_status": "observed",
            "passed": True,
            "oracles": evidence,
        }

    def wait_ready(self, seconds: int = 90) -> None:
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            result = run_command(
                ["ldapsearch", "-LLL", "-x", "-H", self.uri, "-b", "", "-s", "base", "namingContexts"],
                check=False,
                timeout=10,
            )
            if result.returncode == 0:
                return
            last = result.stderr.strip()
            time.sleep(0.5)
        raise StudyError(f"{self.implementation} did not answer on {self.uri}: {last}")

    def configure_affinity(self) -> None:
        if self.cpu is None:
            self.affinity_metadata = {
                "status": "not-requested",
                "requested_cpu": None,
            }
            return
        if self.pid is None:
            raise StudyError("cannot pin server threads before pid discovery")
        task_dir = Path(f"/proc/{self.pid}/task")
        if not hasattr(os, "sched_setaffinity") or not task_dir.is_dir():
            raise StudyError(
                "whole-process CPU affinity requires Linux /proc task data"
            )
        # Threads can exit or appear while the task directory is scanned.
        # Repeat until a stable scan has had the requested mask applied.
        for _attempt in range(5):
            before = {
                int(path.name) for path in task_dir.iterdir()
                if path.name.isdigit()
            }
            for tid in sorted(before):
                try:
                    os.sched_setaffinity(tid, {self.cpu})
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise StudyError(
                            f"could not pin server tid {tid} to CPU "
                            f"{self.cpu}: {error}"
                        ) from error
            after = {
                int(path.name) for path in task_dir.iterdir()
                if path.name.isdigit()
            }
            if after.issubset(before):
                self.verify_affinity()
                return
        raise StudyError(
            f"server pid {self.pid} kept creating threads while affinity "
            "was being established"
        )

    def verify_affinity(self) -> dict[str, Any]:
        """Require every live server thread to have the intended CPU mask."""
        if self.cpu is None:
            self.affinity_metadata = {
                "status": "not-requested",
                "requested_cpu": None,
            }
            return self.affinity_metadata
        if self.pid is None or not hasattr(os, "sched_getaffinity"):
            raise StudyError("cannot verify whole-process CPU affinity")
        task_dir = Path(f"/proc/{self.pid}/task")
        if not task_dir.is_dir():
            raise StudyError(
                f"cannot enumerate threads for server pid {self.pid}"
            )
        effective: dict[str, list[int]] = {}
        for path in sorted(task_dir.iterdir(), key=lambda item: item.name):
            if not path.name.isdigit():
                continue
            tid = int(path.name)
            try:
                mask = sorted(os.sched_getaffinity(tid))
            except OSError as error:
                if error.errno == errno.ESRCH:
                    continue
                raise StudyError(
                    f"could not read affinity for server tid {tid}: {error}"
                ) from error
            effective[path.name] = mask
        if not effective:
            raise StudyError(
                f"server pid {self.pid} exposed no live threads for affinity audit"
            )
        mismatches = {
            tid: mask for tid, mask in effective.items()
            if mask != [self.cpu]
        }
        if mismatches:
            raise StudyError(
                "server thread affinity does not match requested CPU "
                f"{self.cpu}: {mismatches}"
            )
        self.affinity_metadata = {
            "status": "verified",
            "requested_cpu": self.cpu,
            "server_pid": self.pid,
            "task_count": len(effective),
            "effective_masks": effective,
        }
        return self.affinity_metadata

    def capture_effective_schema(self) -> dict[str, Any]:
        """Capture the complete live subschema entry as a portable artifact."""
        discovery = run_command(
            [
                "ldapsearch", "-LLL", "-x", "-H", self.uri,
                "-D", self.root_dn, "-w", PASSWORD,
                "-b", "", "-s", "base", "-o", "ldif-wrap=no",
                "subschemaSubentry",
            ],
            check=False,
            timeout=60,
        )
        if discovery.returncode != 0:
            raise StudyError(
                "could not discover the live subschema entry: "
                + (discovery.stderr or discovery.stdout).strip()
            )
        match = re.search(
            r"^subschemaSubentry:\s*(\S.*?)\s*$",
            discovery.stdout,
            re.I | re.M,
        )
        if not match:
            raise StudyError("root DSE did not expose subschemaSubentry")
        subschema_dn = match.group(1).strip()
        attributes = SUBSCHEMA_ATTRIBUTES
        result = run_command(
            [
                "ldapsearch", "-LLL", "-x", "-H", self.uri,
                "-D", self.root_dn, "-w", PASSWORD,
                "-b", subschema_dn, "-s", "base", "-o", "ldif-wrap=no",
                *attributes,
            ],
            check=False,
            timeout=180,
        )
        if result.returncode != 0:
            raise StudyError(
                f"could not read live subschema {subschema_dn}: "
                + (result.stderr or result.stdout).strip()
            )
        canonical = parse_live_subschema(result.stdout)
        counts = {
            attribute: len(canonical[attribute]) for attribute in attributes
        }
        for attribute in attributes:
            if not canonical[attribute]:
                raise StudyError(
                    f"live subschema omitted required {attribute} values"
                )
        custom_verification = verify_study_schema_identities(canonical)
        canonical_bytes = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        canonical_identity = hashlib.sha256(canonical_bytes).hexdigest()
        artifact = (
            self.runtime_dir.parent / "schema"
            / f"{self.implementation}-effective-subschema.ldif"
        )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(result.stdout, encoding="utf-8")
        canonical_artifact = artifact.with_suffix(".canonical.json")
        canonical_artifact.write_text(
            json.dumps(canonical, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            "evidence_status": "observed",
            "subschema_dn": subschema_dn,
            "requested_attributes": list(attributes),
            "value_counts": counts,
            "canonical_identity_sha256": canonical_identity,
            "custom_schema_verification": custom_verification,
            "raw_artifact": {
                "path": artifact.relative_to(
                    self.runtime_dir.parent
                ).as_posix(),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "size_bytes": artifact.stat().st_size,
            },
            "canonical_artifact": {
                "path": canonical_artifact.relative_to(
                    self.runtime_dir.parent
                ).as_posix(),
                "sha256": hashlib.sha256(
                    canonical_artifact.read_bytes()
                ).hexdigest(),
                "size_bytes": canonical_artifact.stat().st_size,
            },
        }

    def log_cursor(self) -> dict[str, dict[str, int | bool]]:
        return {
            "access": file_cursor(self.access_log) if self.access_log else {
                "exists": False, "device": 0, "inode": 0, "offset": 0,
            },
            "error": file_cursor(self.error_log) if self.error_log else {
                "exists": False, "device": 0, "inode": 0, "offset": 0,
            },
        }

    def log_window(self, cursor: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
        return {
            "access": read_after_cursor(self.access_log, cursor.get("access", {})) if self.access_log else "",
            "error": read_after_cursor(self.error_log, cursor.get("error", {})) if self.error_log else "",
        }

    def _diagnostic_log_state(self, access: str) -> dict[str, Any]:
        search_pattern = re.compile(r"\bconn=(\d+)\s+op=(\d+)\s+SRCH\b")
        if self.implementation == "389ds":
            result_pattern = re.compile(
                r"\bconn=(\d+)\s+op=(\d+)\s+RESULT\b.*\btag=101\b"
            )
        else:
            result_pattern = re.compile(
                r"\bconn=(\d+)\s+op=(\d+)\s+SEARCH RESULT\b"
            )
        search_pairs = search_pattern.findall(access)
        result_pairs = result_pattern.findall(access)
        internal_lines = internal_access_lines(access)
        distinct_searches = list(dict.fromkeys(search_pairs))
        target = distinct_searches[0] if len(distinct_searches) == 1 else None
        return {
            "search_pairs": search_pairs,
            "distinct_search_pairs": distinct_searches,
            "result_pairs": result_pairs,
            "result_line_count": len(result_pairs),
            "target": target,
            "target_result_count": result_pairs.count(target) if target else 0,
            "internal_lines": internal_lines,
        }

    def await_isolated_search_log(
            self, cursor: Mapping[str, Mapping[str, Any]], *,
            allow_internal_operations: bool = False,
            require_internal_operations: bool = False,
            context: str = "isolated diagnostic search",
            timeout_seconds: float = 15.0,
            stability_seconds: float = 0.025,
            ) -> tuple[dict[str, str], dict[str, Any]]:
        """Wait for and seal one already-issued external search log window."""
        if require_internal_operations and not allow_internal_operations:
            raise StudyError(
                f"{context}: required internal operations must be explicitly "
                "allowed"
            )
        # The LDAP response can reach the client before an asynchronous server
        # access-log writer appends the matching final result record.  Do not
        # start another harness operation until that record seals this window.
        started = time.monotonic()
        polls = 0
        window = self.log_window(cursor)
        state = self._diagnostic_log_state(window["access"])

        def reject_internal_contamination() -> None:
            referral_lines = referral_monitor_access_lines(window["access"])
            if referral_lines:
                raise StudyError(
                    f"{context}: log window is contaminated by the "
                    f"periodic referral monitor: {referral_lines}"
                )
            if state["internal_lines"] and not allow_internal_operations:
                raise StudyError(
                    f"{context}: log window is contaminated by unplanned "
                    f"internal server operations: {state['internal_lines']}"
                )
            if allow_internal_operations:
                root_lines = root_internal_access_lines(window["access"])
                if root_lines:
                    raise StudyError(
                        f"{context}: planned nested-internal allowance cannot "
                        f"admit root maintenance operations: {root_lines}"
                    )
                if state["target"] is not None:
                    target_connection = str(state["target"][0])
                    mismatched = [
                        line
                        for line in nested_internal_access_lines(
                            window["access"]
                        )
                        if (
                            NESTED_INTERNAL_ACCESS_PATTERN.search(line)
                            is not None
                            and NESTED_INTERNAL_ACCESS_PATTERN.search(
                                line
                            ).group("connection") != target_connection
                        )
                    ]
                    if mismatched:
                        raise StudyError(
                            f"{context}: nested internal operations belong "
                            f"to another connection: {mismatched}"
                        )

        while True:
            reject_internal_contamination()
            if len(state["distinct_search_pairs"]) > 1:
                raise StudyError(
                    f"{context}: log window is contaminated by multiple "
                    f"search operations: {state['distinct_search_pairs']}"
                )
            if state["target_result_count"] == 1:
                # Re-read after a stability interval so a partially appended
                # record or already queued unrelated result cannot seal the
                # evidence window prematurely.
                time.sleep(stability_seconds)
                polls += 1
                window = self.log_window(cursor)
                state = self._diagnostic_log_state(window["access"])
                reject_internal_contamination()
                if (
                    len(state["distinct_search_pairs"]) == 1
                    and state["target_result_count"] == 1
                    and state["result_line_count"] == 1
                ):
                    break
                raise StudyError(
                    f"{context}: log window is contaminated after target "
                    f"completion: searches={state['distinct_search_pairs']}, "
                    f"results={state['result_pairs']}"
                )
            if state["target_result_count"] > 1:
                raise StudyError(
                    f"{context}: log window contains duplicate target "
                    f"results: {state['result_pairs']}"
                )
            if time.monotonic() - started >= timeout_seconds:
                raise StudyError(
                    f"{context}: timed out waiting for the target "
                    f"result: searches={state['distinct_search_pairs']}, "
                    f"results={state['result_pairs']}"
                )
            polls += 1
            time.sleep(0.025)
            window = self.log_window(cursor)
            state = self._diagnostic_log_state(window["access"])
        target_connection, target_operation = state["target"]
        nested_lines = nested_internal_access_lines(window["access"])
        if require_internal_operations and not nested_lines:
            raise StudyError(
                f"{context}: required planned nested internal operation was "
                "not observed"
            )
        return window, {
            "operation_count": 1,
            "cursor": cursor,
            "internal_server_operations": {
                "status": (
                    "observed-planned"
                    if state["internal_lines"] else "not-observed"
                ),
                "allowed": allow_internal_operations,
                "required": require_internal_operations,
                "line_count": len(state["internal_lines"]),
                "nested_line_count": len(nested_lines),
                "referral_monitor_line_count": 0,
            },
            "log_completion": {
                "status": "observed-target",
                "target_connection": int(target_connection),
                "target_operation": int(target_operation),
                "result_line_count": state["result_line_count"],
                "poll_count": polls,
                "wait_seconds": time.monotonic() - started,
            },
        }

    def search_with_isolated_diagnostics(
            self, *, allow_internal_operations: bool = False,
            require_internal_operations: bool = False,
            **search: Any) -> tuple[SearchResult, dict[str, str], dict[str, Any]]:
        """Run exactly one harness operation inside a fresh diagnostic window."""
        background_guard = self.begin_background_quiet_collection(
            "isolated diagnostic search"
        )
        cursor = self.log_cursor()
        result = self.search(**search)
        window, isolation = self.await_isolated_search_log(
            cursor,
            allow_internal_operations=allow_internal_operations,
            require_internal_operations=require_internal_operations,
        )
        isolation["background_quiet_window"] = (
            self.finish_background_quiet_collection(background_guard)
        )
        return result, window, isolation

    def diagnostics_enable(self, *, filter_trace: bool = False) -> Any:
        del filter_trace
        return None

    def diagnostics_restore(self, state: Any) -> None:
        del state


class DS389Runtime(ServerRuntime):
    implementation = "389ds"
    root_dn = "cn=Directory Manager"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.instance = f"lfstudy{os.getpid() % 100000:05d}"
        self.instance_created = False

    def _dsconf(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run_command(
            ["dsconf", "-D", self.root_dn, "-w", PASSWORD, self.uri, *args],
            check=check,
            timeout=1800,
        )

    def _config_value(self, attribute: str, dn: str = "cn=config") -> str | None:
        result = run_command(
            [
                "ldapsearch", "-LLL", "-x", "-H", self.uri,
                "-D", self.root_dn, "-w", PASSWORD,
                "-b", dn, "-s", "base", attribute,
            ],
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        match = re.search(rf"^{re.escape(attribute)}:\s*(.*)$", result.stdout, re.I | re.M)
        return match.group(1).strip() if match else None

    def _replace_config(self, attribute: str, value: str, dn: str = "cn=config") -> None:
        ldif = f"dn: {dn}\nchangetype: modify\nreplace: {attribute}\n{attribute}: {value}\n\n"
        run_command(
            ["ldapmodify", "-x", "-H", self.uri, "-D", self.root_dn, "-w", PASSWORD],
            input_text=ldif,
            timeout=60,
        )

    def _index_details(self, attribute: str) -> dict[str, Any]:
        result = self._dsconf(
            "backend", "index", "get", "--attr", attribute,
            "userRoot", check=False,
        )
        if result.returncode != 0:
            raise StudyError(
                f"could not read 389 DS index {attribute}: "
                + (result.stderr or result.stdout).strip()
            )
        raw = result.stdout + result.stderr
        return {
            "attribute": attribute,
            "index_types": sorted({
                match.casefold() for match in re.findall(
                    r"^nsIndexType:\s*(\S+)", raw, re.I | re.M,
                )
            }),
            "matching_rules": sorted({
                match.casefold() for match in re.findall(
                    r"^nsMatchingRule:\s*(\S+)", raw, re.I | re.M,
                )
            }),
            "raw": raw,
        }

    def _live_index_inventory(self) -> dict[str, Any]:
        listed = self._dsconf(
            "backend", "index", "list", "--just-names", "userRoot"
        )
        names = sorted({
            line.strip().casefold()
            for line in listed.stdout.splitlines()
            if line.strip()
        })
        entries = {
            name: self._index_details(name) for name in names
        }
        material = {
            name: {
                "index_types": entries[name]["index_types"],
                "matching_rules": entries[name]["matching_rules"],
            }
            for name in names
        }
        return {
            "evidence_status": "observed",
            "source": "live dsconf backend index list/get",
            "attributes": entries,
            "identity_sha256": hashlib.sha256(json.dumps(
                material, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest(),
        }

    def _reconcile_workload_indexes(
            self, contract: Mapping[str, Sequence[str]]) -> dict[str, Any]:
        initial = self._live_index_inventory()
        existing = set(initial["attributes"])
        for attribute, desired_values in contract.items():
            key = attribute.casefold()
            desired = {value.casefold() for value in desired_values}
            if not desired:
                if key in existing:
                    self._dsconf(
                        "backend", "index", "delete", "--attr", attribute,
                        "userRoot",
                    )
                    existing.remove(key)
                continue
            if key not in existing:
                argv = ["backend", "index", "add", "--attr", attribute]
                for index_type in sorted(desired):
                    argv.extend(["--index-type", index_type])
                argv.append("userRoot")
                self._dsconf(*argv)
                existing.add(key)
                continue
            actual = set(
                initial["attributes"][key]["index_types"]
            )
            for index_type in sorted(actual - desired):
                self._dsconf(
                    "backend", "index", "set", "--attr", attribute,
                    "--del-type", index_type, "userRoot",
                )
            for index_type in sorted(desired - actual):
                self._dsconf(
                    "backend", "index", "set", "--attr", attribute,
                    "--add-type", index_type, "userRoot",
                )

        effective = self._live_index_inventory()
        verification: dict[str, Any] = {}
        failures: list[str] = []
        for attribute, desired_values in contract.items():
            key = attribute.casefold()
            desired = sorted({value.casefold() for value in desired_values})
            actual = (
                effective["attributes"].get(key, {}).get("index_types", [])
            )
            passed = actual == desired
            verification[attribute] = {
                "desired_index_types": desired,
                "actual_index_types": actual,
                "passed": passed,
            }
            if not passed:
                failures.append(
                    f"{attribute}: desired {desired}, observed {actual}"
                )
        if failures:
            raise StudyError(
                "workload-controlled 389 DS index reconciliation failed: "
                + "; ".join(failures)
            )
        return {
            "initial_live_inventory": initial,
            "complete_live_inventory": effective,
            "workload_controlled_verification": verification,
            "all_workload_controlled_indexes_exact": True,
        }

    def _wait_for_referral_monitor_barrier(
            self, cursor: Mapping[str, Mapping[str, Any]], *,
            minimum_paired_operation_count: int = 1,
            timeout_seconds: float = REFERRAL_BARRIER_TIMEOUT_SECONDS,
            context: str = "post-restart referral monitor") -> dict[str, Any]:
        """Observe a referral STAT start and its same-operation completion."""
        started = time.clock_gettime(time.CLOCK_MONOTONIC)
        polls = 0
        while True:
            window = self.log_window(cursor)
            evidence = referral_monitor_operation_evidence(window["access"])
            if (
                    evidence["paired_operation_count"]
                    >= minimum_paired_operation_count
                    and evidence["unmatched_referral_start_count"] == 0):
                time.sleep(REFERRAL_BARRIER_STABILITY_SECONDS)
                polls += 1
                stable_window = self.log_window(cursor)
                stable = referral_monitor_operation_evidence(
                    stable_window["access"]
                )
                if (
                        stable["paired_operation_count"]
                        >= minimum_paired_operation_count
                        and stable["unmatched_referral_start_count"] == 0):
                    completed_at = time.clock_gettime(time.CLOCK_MONOTONIC)
                    return {
                        **stable,
                        "status": "observed-complete",
                        "context": context,
                        "minimum_paired_operation_count": (
                            minimum_paired_operation_count
                        ),
                        "poll_count": polls,
                        "wait_seconds": (
                            completed_at - started
                        ),
                        "completion_observed_monotonic_seconds": completed_at,
                        "stability_seconds": (
                            REFERRAL_BARRIER_STABILITY_SECONDS
                        ),
                    }
            now = time.clock_gettime(time.CLOCK_MONOTONIC)
            if now - started >= timeout_seconds:
                raise StudyError(
                    f"{context}: no paired referral-monitor STAT completion "
                    f"within {timeout_seconds:g}s: {evidence}"
                )
            polls += 1
            time.sleep(0.025)

    def _wait_for_vattr_check_barrier(
            self, cursor: Mapping[str, Mapping[str, Any]], *,
            timeout_seconds: float = VATTR_CHECK_TIMEOUT_SECONDS,
            ) -> dict[str, Any]:
        """Wait for the three-second startup vattr check to become quiet."""
        started = time.clock_gettime(time.CLOCK_MONOTONIC)
        polls = 0
        while True:
            window = self.log_window(cursor)
            evidence = vattr_check_operation_evidence(window["access"])
            if (
                    evidence["paired_operation_count"] >= 1
                    and evidence["unmatched_start_count"] == 0):
                root_line_count = len(root_internal_access_lines(
                    window["access"]
                ))
                time.sleep(VATTR_CHECK_STABILITY_SECONDS)
                polls += 1
                stable_window = self.log_window(cursor)
                stable = vattr_check_operation_evidence(
                    stable_window["access"]
                )
                stable_root_line_count = len(root_internal_access_lines(
                    stable_window["access"]
                ))
                if (
                        stable["paired_operation_count"] >= 1
                        and stable["unmatched_start_count"] == 0
                        and stable_root_line_count == root_line_count):
                    completed_at = time.clock_gettime(
                        time.CLOCK_MONOTONIC
                    )
                    return {
                        **stable,
                        "status": "observed-complete",
                        "source_function": (
                            "vattr_check/vattr_check_thread"
                        ),
                        "delay_seconds": VATTR_CHECK_DELAY_SECONDS,
                        "exact_filter": VATTR_CHECK_FILTER,
                        "poll_count": polls,
                        "wait_seconds": completed_at - started,
                        "completion_observed_monotonic_seconds": (
                            completed_at
                        ),
                        "stability_seconds": (
                            VATTR_CHECK_STABILITY_SECONDS
                        ),
                        "root_internal_line_count_at_completion": (
                            root_line_count
                        ),
                        "root_internal_line_count_after_stability": (
                            stable_root_line_count
                        ),
                        "stability_no_new_root_internal_lines": True,
                        "passed": True,
                    }
            now = time.clock_gettime(time.CLOCK_MONOTONIC)
            if now - started >= timeout_seconds:
                raise StudyError(
                    "post-restart vattr check: no ordered role/COS search "
                    f"and successful result within {timeout_seconds:g}s: "
                    f"{evidence}"
                )
            polls += 1
            time.sleep(0.025)

    def setup(self) -> None:
        require_commands(["ns-slapd", "dscreate", "dsctl", "dsconf", "ldapsearch", "ldapmodify"])
        instance_dir = Path(f"/etc/dirsrv/slapd-{self.instance}")
        if instance_dir.exists():
            raise StudyError(
                f"refusing to reuse pre-existing 389 DS instance {self.instance}"
            )
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        inf = self.runtime_dir / "instance.inf"
        inf.write_text(
            "[general]\n"
            "config_version = 2\n"
            "full_machine_name = localhost.localdomain\n"
            "start = True\n\n"
            "[slapd]\n"
            f"instance_name = {self.instance}\n"
            f"root_dn = {self.root_dn}\n"
            f"root_password = {PASSWORD}\n"
            f"port = {self.port}\n"
            f"secure_port = {self.secure_port}\n"
            "self_sign_cert = False\n"
            f"db_lib = {self.backend}\n\n"
            "[backend-userroot]\n"
            f"suffix = {SUFFIX}\n"
            "create_suffix_entry = True\n",
            encoding="utf-8",
        )
        # The unique instance name is owned by this run as soon as creation is
        # attempted.  This makes cleanup cover a partially-created instance if
        # dscreate returns an error after writing its configuration.
        self.instance_created = True
        run_command(["dscreate", "from-file", str(inf)], timeout=600)

        schema_rel = self.manifest.get("schema_files", {}).get("389ds")
        if not schema_rel:
            raise StudyError("workload manifest has no schema_files.389ds")
        schema_source = (self.workload / schema_rel).resolve()
        schema_target = Path(f"/etc/dirsrv/slapd-{self.instance}/schema/99large-filter-study.ldif")
        shutil.copy2(schema_source, schema_target)
        schema_target.chmod(0o644)
        run_command(["dsctl", self.instance, "restart"], timeout=180)
        self.wait_ready()

        self.access_log = Path(f"/var/log/dirsrv/slapd-{self.instance}/access")
        self.error_log = Path(f"/var/log/dirsrv/slapd-{self.instance}/errors")
        self._dsconf("config", "replace", "nsslapd-accesslog-logbuffering=off")
        self._dsconf("config", "replace", "nsslapd-accesslog-logrotationtime=-1")
        self._dsconf("config", "replace", "nsslapd-errorlog-logbuffering=off")
        self._dsconf("config", "replace", "nsslapd-errorlog-logrotationtime=-1")

        initial_access_log_level = self._config_value(
            "nsslapd-accesslog-level"
        )
        self._replace_config(
            "nsslapd-accesslog-level",
            str(ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS),
        )
        access_log_level_readback = self._config_value(
            "nsslapd-accesslog-level"
        )
        if access_log_level_readback != str(
                ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS):
            raise StudyError(
                "access-log level read-back is "
                f"{access_log_level_readback!r}, expected "
                f"{ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS!r}"
            )

        initial_referral_period = self._config_value(
            "nsslapd-referral-check-period"
        )
        self._replace_config(
            "nsslapd-referral-check-period",
            str(REFERRAL_CHECK_PERIOD_SECONDS),
        )
        referral_period_pre_restart_readback = self._config_value(
            "nsslapd-referral-check-period"
        )
        if referral_period_pre_restart_readback != str(
                REFERRAL_CHECK_PERIOD_SECONDS):
            raise StudyError(
                "referral-check period read-back is "
                f"{referral_period_pre_restart_readback!r}, expected "
                f"{REFERRAL_CHECK_PERIOD_SECONDS!r}"
            )

        available_lookup = self._config_value(OR_LOOKUP_ATTR)
        lookup_evidence: dict[str, Any] = {
            "attribute": OR_LOOKUP_ATTR,
            "requested": self.lookup_mode,
            "initial": available_lookup.lower() if available_lookup else None,
        }
        if self.lookup_mode in {"on", "off"}:
            if available_lookup is None:
                raise StudyError(f"lookup mode {self.lookup_mode} requested but {OR_LOOKUP_ATTR} is unsupported")
            self._replace_config(OR_LOOKUP_ATTR, self.lookup_mode)
            readback = self._config_value(OR_LOOKUP_ATTR)
            if not isinstance(readback, str) or readback.casefold() != self.lookup_mode:
                raise StudyError(
                    f"lookup mode read-back is {readback!r}, requested "
                    f"{self.lookup_mode!r}"
                )
            self.actual_lookup_mode = readback.casefold()
        elif self.lookup_mode == "unsupported":
            if available_lookup is not None:
                raise StudyError("lookup mode unsupported was requested but the installed server exposes the switch")
            self.actual_lookup_mode = "unsupported"
        else:
            self.actual_lookup_mode = available_lookup.lower() if available_lookup else "unsupported"
        lookup_evidence.update({
            "actual_readback": self.actual_lookup_mode,
            "passed": self.actual_lookup_mode == (
                self.lookup_mode if self.lookup_mode != "auto"
                else self.actual_lookup_mode
            ),
            "evidence_status": "observed",
        })

        index_contract = configured_index_contract(
            self.workload, self.manifest, "389ds", self.index_config
        )
        index_evidence = self._reconcile_workload_indexes(index_contract)

        data_rel = self.manifest.get("server_data_files", {}).get(
            "389ds", self.manifest.get("data_file", "data.ldif")
        )
        data_source = (self.workload / data_rel).resolve()
        ldif_dir = Path(f"/var/lib/dirsrv/slapd-{self.instance}/ldif")
        ldif_dir.mkdir(parents=True, exist_ok=True)
        data_target = ldif_dir / "large-filter-study.ldif"
        shutil.copy2(data_source, data_target)
        try:
            shutil.chown(data_target, user="dirsrv", group="dirsrv")
        except LookupError:
            pass
        import_result = self._dsconf(
            "backend", "import", "userRoot", str(data_target)
        )
        reindex_result = self._dsconf(
            "backend", "index", "reindex", "--wait", "userRoot"
        )
        index_build_evidence = {
            "evidence_status": "observed",
            "import": {
                "operation": "dsconf backend import userRoot <copied-data-ldif>",
                "returncode": import_result.returncode,
                "stdout": import_result.stdout,
                "stderr": import_result.stderr,
                "completed": import_result.returncode == 0,
            },
            "reindex": {
                "operation": "dsconf backend index reindex --wait userRoot",
                "returncode": reindex_result.returncode,
                "stdout": reindex_result.stdout,
                "stderr": reindex_result.stderr,
                "completed": reindex_result.returncode == 0,
                "waited_for_completion": True,
            },
            "passed": (
                import_result.returncode == 0 and reindex_result.returncode == 0
            ),
        }

        backend_dn = "cn=config,cn=ldbm database,cn=plugins,cn=config"
        self.actual_backend = self._config_value("nsslapd-backend-implement", backend_dn) or "unknown"
        if self.actual_backend.lower() != self.backend.lower():
            raise StudyError(f"created backend is {self.actual_backend}, requested {self.backend}")
        effective_schema = self.capture_effective_schema()
        import_verification = self.verify_imported_dataset()

        # Install the persisted monitor interval only after schema, index, and
        # import setup.  STAT logging is on across the restart so the immediate
        # when=0 referral pass and its same-operation completion form a direct
        # barrier.  Subsequent ticks are aligned to CLOCK_MONOTONIC epoch
        # multiples by eventq.c, not relative to this restart.
        initial_stat_log_level = self._config_value("nsslapd-statlog-level")
        self._replace_config("nsslapd-statlog-level", "1")
        run_command(["dsctl", self.instance, "stop"], timeout=180)
        # Capture only after the old process is gone.  A cursor taken before
        # stop could admit an old-period callback and mistake it for the new
        # process's immediate when=0 barrier.
        pre_start_wait_seconds = 0.0
        stopped_window = referral_quiet_window(
            time.clock_gettime(time.CLOCK_MONOTONIC)
        )
        if float(stopped_window[
                "remaining_to_boundary_seconds"]) <= (
                REFERRAL_RESTART_RESERVE_SECONDS):
            pre_start_wait_seconds = (
                float(stopped_window["remaining_to_boundary_seconds"]) + 1.0
            )
            time.sleep(pre_start_wait_seconds)
        referral_barrier_cursor = self.log_cursor()
        restart_initiated_at = time.clock_gettime(time.CLOCK_MONOTONIC)
        restart_bucket = int(referral_quiet_window(
            restart_initiated_at
        )["bucket"])
        run_command(["dsctl", self.instance, "start"], timeout=180)
        self.wait_ready()
        referral_period_post_restart_readback = self._config_value(
            "nsslapd-referral-check-period"
        )
        if referral_period_post_restart_readback != str(
                REFERRAL_CHECK_PERIOD_SECONDS):
            raise StudyError(
                "post-restart referral-check period read-back is "
                f"{referral_period_post_restart_readback!r}, expected "
                f"{REFERRAL_CHECK_PERIOD_SECONDS!r}"
            )
        access_log_level_post_restart_readback = self._config_value(
            "nsslapd-accesslog-level"
        )
        if access_log_level_post_restart_readback != str(
                ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS):
            raise StudyError(
                "post-restart access-log level read-back is "
                f"{access_log_level_post_restart_readback!r}, expected "
                f"{ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS!r}"
            )

        pid_file = Path(f"/run/dirsrv/slapd-{self.instance}.pid")
        try:
            self.pid = int(pid_file.read_text().strip())
        except (OSError, ValueError) as error:
            raise StudyError(
                f"cannot determine ns-slapd pid from {pid_file}: {error}"
            ) from error
        self.configure_affinity()
        self.actual_backend = (
            self._config_value("nsslapd-backend-implement", backend_dn)
            or "unknown"
        )
        if self.actual_backend.lower() != self.backend.lower():
            raise StudyError(
                f"restarted backend is {self.actual_backend}, requested "
                f"{self.backend}"
            )

        referral_barrier = self._wait_for_referral_monitor_barrier(
            referral_barrier_cursor
        )
        # vattr_check() schedules vattr_check_thread exactly three seconds
        # after every process start.  Its root internal role/COS search would
        # otherwise land in the first measured query's diagnostic window.
        # Observe its exact search and later successful RESULT, then require a
        # full second with no further root-internal access-log activity.
        vattr_check_barrier = self._wait_for_vattr_check_barrier(
            referral_barrier_cursor
        )
        now = time.clock_gettime(time.CLOCK_MONOTONIC)
        current_window = referral_quiet_window(now)
        if int(current_window["bucket"]) != restart_bucket:
            raise StudyError(
                "final server start crossed a referral-monitor boundary "
                "despite the startup reserve; discard and rerun the bundle"
            )

        setup_reserve = (
            REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS
            + REFERRAL_SETUP_FINALIZATION_RESERVE_SECONDS
        )
        if float(current_window[
                "remaining_to_boundary_seconds"]) <= setup_reserve:
            required_pairs = int(
                referral_barrier["paired_operation_count"]
            ) + 1
            referral_barrier = self._wait_for_referral_monitor_barrier(
                referral_barrier_cursor,
                minimum_paired_operation_count=required_pairs,
                timeout_seconds=(
                    float(current_window["remaining_to_boundary_seconds"])
                    + REFERRAL_BARRIER_TIMEOUT_SECONDS
                ),
                context="referral monitor at setup quiet-window boundary",
            )
            current_window = referral_quiet_window(
                time.clock_gettime(time.CLOCK_MONOTONIC)
            )

        covered_bucket = int(current_window["bucket"])
        self._replace_config(
            "nsslapd-statlog-level", initial_stat_log_level or "0"
        )
        stat_log_level_final_readback = self._config_value(
            "nsslapd-statlog-level"
        )
        if stat_log_level_final_readback != (initial_stat_log_level or "0"):
            raise StudyError(
                "final STAT-log level read-back is "
                f"{stat_log_level_final_readback!r}, expected "
                f"{(initial_stat_log_level or '0')!r}"
            )
        established_at = time.clock_gettime(time.CLOCK_MONOTONIC)
        quiet_window = referral_quiet_window(established_at)
        if (
                int(quiet_window["bucket"]) != covered_bucket
                or established_at >= float(
                    quiet_window["deadline_monotonic_seconds"]
                )):
            raise StudyError(
                "referral quiet-window setup crossed a monitor boundary while "
                "restoring diagnostics; discard and rerun the bundle"
            )
        self.background_quiet_window_state = {
            "bucket": int(quiet_window["bucket"]),
            "next_boundary_monotonic_seconds": float(
                quiet_window["next_boundary_monotonic_seconds"]
            ),
            "deadline_monotonic_seconds": float(
                quiet_window["deadline_monotonic_seconds"]
            ),
        }
        referral_policy_material = {
            "clock": "CLOCK_MONOTONIC",
            "interval_anchor": "kernel-monotonic-epoch",
            "requested_seconds": REFERRAL_CHECK_PERIOD_SECONDS,
            "safety_margin_seconds": (
                REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS
            ),
            "collection_policy": "fail-before-or-at-deadline",
        }
        referral_policy_sha256 = hashlib.sha256(json.dumps(
            referral_policy_material,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        referral_monitor_evidence = {
            "attribute": "nsslapd-referral-check-period",
            "initial": initial_referral_period,
            "requested_seconds": REFERRAL_CHECK_PERIOD_SECONDS,
            "pre_restart_readback": (
                referral_period_pre_restart_readback
            ),
            "post_restart_readback": (
                referral_period_post_restart_readback
            ),
            "final_restart_applied": True,
            "final_restart_method": "controlled-stop-cursor-start",
            "clock": "CLOCK_MONOTONIC",
            "interval_anchor": "kernel-monotonic-epoch",
            "safety_margin_seconds": (
                REFERRAL_QUIET_WINDOW_SAFETY_MARGIN_SECONDS
            ),
            "barrier": referral_barrier,
            "post_restart_vattr_check_barrier": vattr_check_barrier,
            "restart_initiated_monotonic_seconds": restart_initiated_at,
            "restart_initiated_bucket": restart_bucket,
            "pre_start_wait_seconds": pre_start_wait_seconds,
            "startup_reserve_seconds": REFERRAL_RESTART_RESERVE_SECONDS,
            "barrier_covered_bucket": covered_bucket,
            "stat_log_control": {
                "initial": initial_stat_log_level,
                "barrier_value": "1",
                "final_readback": stat_log_level_final_readback,
                "restored": True,
            },
            "quiet_window": {
                "bucket": int(quiet_window["bucket"]),
                "next_boundary_monotonic_seconds": float(
                    quiet_window["next_boundary_monotonic_seconds"]
                ),
                "deadline_monotonic_seconds": float(
                    quiet_window["deadline_monotonic_seconds"]
                ),
                "established_monotonic_seconds": established_at,
                "remaining_seconds": float(
                    quiet_window["remaining_to_deadline_seconds"]
                ),
                "policy": "fail-collection-before-or-at-deadline",
            },
            "access_log_internal_operation_control": {
                "attribute": "nsslapd-accesslog-level",
                "initial": initial_access_log_level,
                "requested": ACCESS_LOG_LEVEL_WITH_INTERNAL_OPERATIONS,
                "pre_restart_readback": access_log_level_readback,
                "post_restart_readback": (
                    access_log_level_post_restart_readback
                ),
                "internal_operation_bit_enabled": True,
                "passed": True,
            },
            "policy_material": referral_policy_material,
            "policy_sha256": referral_policy_sha256,
            "evidence_status": "observed",
            "passed": True,
        }
        self.setup_metadata = {
            "instance": self.instance,
            "uri": self.uri,
            "backend": self.actual_backend,
            "lookup_mode": self.actual_lookup_mode,
            "lookup_mode_evidence": lookup_evidence,
            "background_referral_check_control": referral_monitor_evidence,
            "background_referral_check_policy_sha256": (
                referral_policy_sha256
            ),
            "index_configuration": self.index_config,
            "index_contract_evidence": index_evidence,
            "index_build_evidence": index_build_evidence,
            "effective_indexes": index_evidence["complete_live_inventory"],
            "effective_schema": effective_schema,
            "import_verification": import_verification,
            "server_thread_affinity": self.affinity_metadata,
            "canonical_index_intent": {
                attribute: list(index_contract[attribute])
                for attribute in sorted(index_contract)
            },
            "canonical_index_intent_sha256": hashlib.sha256(
                json.dumps(
                    {
                        attribute: list(index_contract[attribute])
                        for attribute in sorted(index_contract)
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }

    def diagnostics_enable(self, *, filter_trace: bool = False) -> dict[str, str | None]:
        old = {
            "nsslapd-errorlog-level": self._config_value("nsslapd-errorlog-level"),
            "nsslapd-statlog-level": self._config_value("nsslapd-statlog-level"),
        }
        # Backend (524288) + trace (1); add FILTER (32) only for the small
        # family-selection controls because it can be extremely verbose on
        # the 612 x 355 principal shape.  STAT index logging has its own switch.
        level = 524288 + 1 + (32 if filter_trace else 0)
        self._replace_config("nsslapd-errorlog-level", str(level))
        self._replace_config("nsslapd-statlog-level", "1")
        return old

    def diagnostics_restore(self, state: Mapping[str, str | None]) -> None:
        for attribute, value in state.items():
            self._replace_config(attribute, value or "0")

    def configure_dynamic_lists(self, enabled: bool) -> None:
        dn = "cn=config,cn=ldbm database,cn=plugins,cn=config"
        self._replace_config("nsslapd-dynamic-lists-attr", "member", dn)
        self._replace_config("nsslapd-dynamic-lists-oc", "groupOfUrls", dn)
        self._replace_config("nsslapd-dynamic-lists-url-attr", "memberURL", dn)
        self._replace_config("nsslapd-dynamic-lists-enabled", "on" if enabled else "off", dn)

    def prepare_dynamic_limits(self) -> None:
        metadata = self.manifest.get("dynamic_list")
        if not isinstance(metadata, Mapping):
            raise StudyError("workload manifest has no dynamic_list metadata")
        values = (
            (str(metadata["control_bind_dn"]), str(metadata["unlimited_scan_limit"])),
            (str(metadata["limited_bind_dn"]), str(metadata["finite_scan_limit"])),
        )
        for bind_dn, scan_limit in values:
            ldif = (
                f"dn: {bind_dn}\n"
                "changetype: modify\n"
                "replace: nsLookThroughLimit\n"
                f"nsLookThroughLimit: {metadata['lookthrough_limit']}\n"
                "-\n"
                "replace: nsIDListScanLimit\n"
                f"nsIDListScanLimit: {scan_limit}\n\n"
            )
            run_command(
                ["ldapmodify", "-x", "-H", self.uri, "-D", self.root_dn, "-w", PASSWORD],
                input_text=ldif,
                timeout=60,
            )

    def cleanup(self) -> None:
        if not self.instance_created:
            if self.runtime_dir.exists():
                shutil.rmtree(self.runtime_dir)
            return
        instance_dir = Path(f"/etc/dirsrv/slapd-{self.instance}")
        if not instance_dir.exists():
            self.instance_created = False
            if self.runtime_dir.exists():
                shutil.rmtree(self.runtime_dir)
            return
        result = run_command(["dsctl", self.instance, "remove", "--do-it"], check=False, timeout=300)
        if result.returncode != 0:
            raise StudyError(f"failed to remove instance {self.instance}: {result.stderr or result.stdout}")
        self.instance_created = False
        if self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir)


class OpenLDAPRuntime(ServerRuntime):
    implementation = "openldap"
    root_dn = f"cn=Manager,{SUFFIX}"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.process: subprocess.Popen[str] | None = None
        self._log_stream: Any = None

    def setup(self) -> None:
        require_commands(["slapd", "slapadd", "ldapsearch"])
        if self.lookup_mode not in {"unsupported", "auto"}:
            raise StudyError("OpenLDAP does not support the 389 DS lookup configuration switch")
        if self.backend != "mdb":
            raise StudyError("the OpenLDAP comparison uses its packaged MDB backend")
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        database = self.runtime_dir / "openldap-db"
        database.mkdir(mode=0o700)
        schema_rel = self.manifest.get("schema_files", {}).get("openldap")
        if not schema_rel:
            raise StudyError("workload manifest has no schema_files.openldap")
        schema = (self.workload / schema_rel).resolve()
        config = self.runtime_dir / "slapd.conf"
        modules = ""
        module_candidates = list(Path("/usr/lib64/openldap").glob("back_mdb*"))
        if module_candidates:
            modules = "modulepath /usr/lib64/openldap\nmoduleload back_mdb\n"
        index_lines = []
        index_contract = configured_index_contract(
            self.workload, self.manifest, "openldap", self.index_config
        )
        index_intent = {
            attribute: types
            for attribute, types in index_contract.items()
            if types
        }
        for attribute, types in index_intent.items():
            index_lines.append(f"index {attribute} {','.join(types)}")
        config.write_text(
            "include /etc/openldap/schema/core.schema\n"
            "include /etc/openldap/schema/cosine.schema\n"
            "include /etc/openldap/schema/inetorgperson.schema\n"
            f"include {schema}\n\n"
            f"pidfile {self.runtime_dir / 'slapd.pid'}\n"
            f"argsfile {self.runtime_dir / 'slapd.args'}\n"
            "loglevel stats\n"
            f"{modules}\n"
            "database mdb\n"
            f"suffix \"{SUFFIX}\"\n"
            f"rootdn \"{self.root_dn}\"\n"
            f"rootpw {PASSWORD}\n"
            f"directory {database}\n"
            "maxsize 8589934592\n"
            "sizelimit unlimited\n"
            "timelimit unlimited\n"
            + "\n".join(index_lines)
            + "\n",
            encoding="utf-8",
        )
        data_rel = self.manifest.get("server_data_files", {}).get(
            "openldap", self.manifest.get("data_file", "data.ldif")
        )
        data_source = (self.workload / data_rel).resolve()
        slapadd = run_command(["slapadd", "-q", "-f", str(config), "-l", str(data_source)], check=False, timeout=3600)
        if slapadd.returncode != 0:
            raise StudyError(f"slapadd failed: {slapadd.stderr or slapadd.stdout}")

        self.access_log = self.runtime_dir / "slapd.log"
        self.error_log = self.access_log
        self._log_stream = self.access_log.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            ["slapd", "-f", str(config), "-h", f"{self.uri}/", "-d", "256"],
            stdout=self._log_stream,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.pid = self.process.pid
        self.wait_ready()
        self.configure_affinity()
        self.actual_lookup_mode = "unsupported"
        self.actual_backend = "mdb"
        complete_index_listing = {
            attribute.casefold(): {
                "attribute": attribute,
                "index_types": sorted({kind.casefold() for kind in types}),
                "source": "live slapd.conf index directive",
            }
            for attribute, types in index_intent.items()
        }
        index_verification: dict[str, Any] = {}
        failures: list[str] = []
        for attribute, desired_values in index_contract.items():
            desired = sorted({value.casefold() for value in desired_values})
            actual = complete_index_listing.get(
                attribute.casefold(), {}
            ).get("index_types", [])
            passed = actual == desired
            index_verification[attribute] = {
                "desired_index_types": desired,
                "actual_index_types": actual,
                "passed": passed,
            }
            if not passed:
                failures.append(
                    f"{attribute}: desired {desired}, observed {actual}"
                )
        if failures:
            raise StudyError(
                "workload-controlled OpenLDAP index reconciliation failed: "
                + "; ".join(failures)
            )
        index_inventory_material = {
            key: value["index_types"]
            for key, value in complete_index_listing.items()
        }
        effective_schema = self.capture_effective_schema()
        import_verification = self.verify_imported_dataset()
        self.setup_metadata = {
            "uri": self.uri,
            "backend": "mdb",
            "lookup_mode": "unsupported",
            "lookup_mode_evidence": {
                "evidence_status": "observed",
                "requested": self.lookup_mode,
                "actual_readback": "unsupported",
                "reason": "packaged OpenLDAP exposes no 389 DS OR lookup switch",
                "passed": self.lookup_mode in {"unsupported", "auto"},
            },
            "index_configuration": self.index_config,
            "effective_config": config.read_text(encoding="utf-8"),
            "index_build_evidence": {
                "evidence_status": "observed",
                "operation": "slapadd -q -f <generated-config> -l <copied-data-ldif>",
                "returncode": slapadd.returncode,
                "stdout": slapadd.stdout,
                "stderr": slapadd.stderr,
                "completed": slapadd.returncode == 0,
                "data_file_sha256": sha256_file(data_source),
                "passed": slapadd.returncode == 0,
            },
            "index_contract_evidence": {
                "source": "slapd.conf loaded by the live slapd process",
                "complete_live_inventory": {
                    "evidence_status": "observed",
                    "attributes": complete_index_listing,
                    "implicit_internal_indexes": (
                        "OpenLDAP internal entry/DN bookkeeping is not "
                        "configured as olcDbIndex attributes"
                    ),
                    "identity_sha256": hashlib.sha256(json.dumps(
                        index_inventory_material,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")).hexdigest(),
                },
                "workload_controlled_verification": index_verification,
                "all_workload_controlled_indexes_exact": True,
            },
            "effective_indexes": complete_index_listing,
            "effective_schema": effective_schema,
            "import_verification": import_verification,
            "server_thread_affinity": self.affinity_metadata,
            "canonical_index_intent": {
                attribute: list(index_contract[attribute])
                for attribute in sorted(index_contract)
            },
            "canonical_index_intent_sha256": hashlib.sha256(
                json.dumps(
                    {
                        attribute: list(index_contract[attribute])
                        for attribute in sorted(index_contract)
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }

    def cleanup(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self._log_stream is not None:
            self._log_stream.close()
        self.process = None
        if self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir)


def create_runtime(implementation: str, **kwargs: Any) -> ServerRuntime:
    if implementation == "389ds":
        return DS389Runtime(**kwargs)
    if implementation == "openldap":
        return OpenLDAPRuntime(**kwargs)
    raise StudyError(f"unsupported server implementation: {implementation}")
