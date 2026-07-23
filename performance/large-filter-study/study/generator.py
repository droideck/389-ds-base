"""Manifest-driven generator for the complete large-filter study workload."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from .common import (
    AND,
    APPROX,
    EQ,
    NOT,
    OR,
    PRESENT,
    SUBSTRING,
    DataSet,
    Filter,
    atomic_output_directory,
    canonical_json_bytes,
    normalize_dn,
    normalize_equality,
    search_request_ber,
    sha256_bytes,
    sha256_file,
    write_json,
    write_text,
)


STUDY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = STUDY_ROOT / "workload" / "study-spec.json"
SCENARIO_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
PEOPLE_RDN = "ou=people"
DYNAMIC_RDN = "ou=dynamic"
REQUESTED_ATTRIBUTES = ["1.1"]
ACCOUNT_DN = "cn=account1,ou=accounts,o=data,dc=example,dc=com"
POSITIVE_DN = "cn=lookup-positive-target,ou=References,dc=example,dc=com"
SHORT_DN = "cn=target,ou=References,dc=example,dc=com"
ESCAPED_DN = r"cn=Smith\, Alice,ou=References,dc=example,dc=com"
BIND_PASSWORD = "LargeFilterStudy-Only-42"
AUTHENTICATED_READ_ACI = (
    '(targetattr="*")(version 3.0; acl "large-filter authenticated search"; '
    'allow (read,search,compare) userdn="ldap:///all";)'
)


class SpecificationError(ValueError):
    """Raised before output creation when a source manifest is inconsistent."""


def load_spec(path: Path) -> Dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise SpecificationError(f"cannot read study spec {path}: {error}") from error
    if not isinstance(value, dict):
        raise SpecificationError("study spec must be a JSON object")
    return value


def _require_int(mapping: Mapping[str, Any], key: str, minimum: int = 0) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise SpecificationError(f"{key} must be an integer >= {minimum}")
    return value


def _require_int_list(
        mapping: Mapping[str, Any], key: str, minimum: int = 0) -> list[int]:
    value = mapping.get(key)
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, int) or isinstance(item, bool)
                   or item < minimum for item in value)):
        raise SpecificationError(f"{key} must be a non-empty integer list")
    if len(set(value)) != len(value):
        raise SpecificationError(f"{key} contains duplicates")
    return value


def _required_people(profile: Mapping[str, Any], spec: Mapping[str, Any]) -> int:
    scenario = int(profile["scenario_cohort"])
    dn_cohort = int(profile["dn_mode_cohort"])
    principal = int(profile["principal_cohort"])
    # The 612-candidate scale point intentionally reuses the exact principal
    # cohort when the sizes agree.  Every other scale point remains disjoint.
    candidates = sum(
        int(value) for value in profile["candidate_counts"]
        if int(value) != principal
    )
    # principal, branch, positive, two fallbacks, four multivalue cohorts,
    # m>k guard, five DN-mode cohorts, adverse, candidates, flat controls,
    # and two dynamic-list bind identities.
    return (
        principal
        + scenario * 2
        + min(32, scenario) * 2
        + scenario * len(spec["matrices"]["multivalue_counts"])
        + scenario
        + dn_cohort * len(spec["matrices"]["dn_modes"])
        + min(8, scenario)
        + candidates
        + 8
        + 2
    )


def validate_spec(spec: Mapping[str, Any], profile_name: str, spec_path: Path) -> Dict[str, Any]:
    if spec.get("format_version") != 1:
        raise SpecificationError("unsupported study spec format_version")
    _require_int(spec, "seed", 0)
    for key in ("base_dn", "suffix_dn", "study"):
        if not isinstance(spec.get(key), str) or not spec[key].strip():
            raise SpecificationError(f"{key} must be a non-empty string")
        if key.endswith("dn") and normalize_dn(spec[key]) is None:
            raise SpecificationError(f"{key} is not a valid DN")

    primary = spec.get("primary")
    if not isinstance(primary, dict):
        raise SpecificationError("primary must be an object")
    if _require_int(primary, "dn_branches", 1) != 355:
        raise SpecificationError("the primary workload requires exactly 355 DN branches")
    long_dn_length = _require_int(primary, "long_dn_length", 1)
    if not 100 <= long_dn_length <= 110:
        raise SpecificationError("primary long DN length must be within 100..110")
    if _require_int(primary, "expected_node_count", 1) != 368:
        raise SpecificationError("the primary workload requires exactly 368 nodes")
    low = _require_int(primary, "filter_bytes_min", 1)
    high = _require_int(primary, "filter_bytes_max", low)
    if high > 50000 or low < 38000:
        raise SpecificationError("primary byte bounds are not a ~42KB range")
    if primary.get("simple_sdn2_assertion") != ACCOUNT_DN:
        raise SpecificationError("primary simple sDN2 assertion changed unexpectedly")
    outer_values = primary.get("outer_values")
    if outer_values != ["asd", "ff", "vv"]:
        raise SpecificationError("primary outer values must remain asd/ff/vv")

    matrices = spec.get("matrices")
    if not isinstance(matrices, dict):
        raise SpecificationError("matrices must be an object")
    required_branches = [15, 16, 32, 64, 128, 355, 500, 1000]
    if _require_int_list(matrices, "branch_counts", 1) != required_branches:
        raise SpecificationError("branch_counts must contain the predeclared ladder")
    if matrices.get("branch_distributions") != [
            "all-absent", "mostly-live", "mixed", "duplicates"]:
        raise SpecificationError("branch_distributions changed unexpectedly")
    if _require_int_list(matrices, "multivalue_counts", 1) != [1, 4, 16, 64]:
        raise SpecificationError("multivalue_counts must be 1/4/16/64")
    required_dn_modes = {
        "short-canonical", "long-canonical", "case-equivalent",
        "escaped-comma", "invalid-remainder",
    }
    if set(matrices.get("dn_modes", ())) != required_dn_modes:
        raise SpecificationError("dn_modes is incomplete")
    if matrices.get("sub_threshold_branch_counts") is not None:
        sub_threshold = _require_int_list(
            matrices, "sub_threshold_branch_counts", 1
        )
        if any(count >= 16 for count in sub_threshold):
            raise SpecificationError(
                "sub_threshold_branch_counts must stay below the 16-branch "
                "lookup threshold"
            )
        if set(sub_threshold) & set(matrices["branch_counts"]):
            raise SpecificationError(
                "sub_threshold_branch_counts duplicates the predeclared ladder"
            )
    canary = spec.get("drift_canary")
    if canary is not None:
        if not isinstance(canary, dict):
            raise SpecificationError("drift_canary must be an object")
        if _require_int(canary, "branch_count", 1) >= 16:
            raise SpecificationError(
                "drift_canary branch_count must stay below the 16-branch "
                "lookup threshold"
            )

    dynamic = spec.get("dynamic_list")
    if not isinstance(dynamic, dict):
        raise SpecificationError("dynamic_list must be an object")
    stored = _require_int(dynamic, "stored_candidates", 1)
    matches = _require_int(dynamic, "stored_matches", 1)
    dynamic_count = _require_int(dynamic, "dynamic_entries", 1)
    lookthrough = _require_int(dynamic, "lookthrough_limit", 1)
    if not (matches + dynamic_count < lookthrough <= stored + dynamic_count
            and stored < lookthrough):
        raise SpecificationError("dynamic-list lookthrough invariant is not satisfied")

    profiles = spec.get("profiles")
    if not isinstance(profiles, dict) or profile_name not in profiles:
        raise SpecificationError(
            f"unknown profile {profile_name!r}; choose from {sorted(profiles or {})}"
        )
    profile = profiles[profile_name]
    if not isinstance(profile, dict):
        raise SpecificationError(f"profile {profile_name} must be an object")
    people = _require_int(profile, "people", 1)
    principal = _require_int(profile, "principal_cohort", 1)
    _require_int(profile, "scenario_cohort", 1)
    _require_int(profile, "dn_mode_cohort", 1)
    candidates = _require_int_list(profile, "candidate_counts", 0)
    if max(candidates) > people:
        raise SpecificationError("candidate count exceeds the profile population")
    if profile_name == "full" and (people != 100000 or principal != 612):
        raise SpecificationError("full profile must be exactly 100,000 people / 612 principal")
    if profile_name == "full" and candidates != [0, 1, 10, 100, 612, 1000, 10000]:
        raise SpecificationError("full candidate ladder changed unexpectedly")
    if profile_name == "smoke" and (
            people != 12000 or principal != 612
            or candidates != [0, 1, 10, 100, 612, 1000, 10000]):
        raise SpecificationError(
            "smoke profile must retain 12,000 people, 612 principal entries, "
            "and the complete candidate ladder"
        )
    required_people = _required_people(profile, spec)
    if required_people > people:
        raise SpecificationError(
            f"profile {profile_name} needs {required_people} disjoint people, has {people}"
        )
    if profile.get("host_intent") not in {"native_fedora_timing", "correctness_only"}:
        raise SpecificationError("profile host_intent is invalid")

    static = spec.get("static_files")
    if not isinstance(static, dict):
        raise SpecificationError("static_files must be an object")
    workload_root = spec_path.resolve().parent
    for key in ("schema_389ds", "schema_openldap", "index_config"):
        relative = static.get(key)
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise SpecificationError(f"static_files.{key} must be relative")
        source = (workload_root / relative).resolve()
        if workload_root not in source.parents or not source.is_file():
            raise SpecificationError(f"static file is missing or escapes workload/: {relative}")
    return dict(profile)


class Allocator:
    def __init__(self, total: int) -> None:
        self.total = total
        self.next_id = 0
        self.cohorts: Dict[str, list[int]] = {}

    def allocate(self, name: str, count: int) -> list[int]:
        if name in self.cohorts:
            raise SpecificationError(f"duplicate cohort {name}")
        if count < 0 or self.next_id + count > self.total:
            raise SpecificationError(f"cohort {name} does not fit the profile")
        ids = list(range(self.next_id, self.next_id + count))
        self.next_id += count
        self.cohorts[name] = ids
        return ids


def _people_dn(index: int, base_dn: str) -> str:
    return f"uid=lfs{index:06d},{base_dn}"


def _long_dn(index: int, target_length: int, label: str = "missing") -> str:
    prefix = f"cn={label}-{index:04d}-"
    suffix = ",ou=Filter Assertions,ou=References,dc=example,dc=com"
    padding = target_length - len(prefix) - len(suffix)
    if padding < 1:
        raise SpecificationError("long DN target is too short for its stable namespace")
    value = prefix + ("x" * padding) + suffix
    if len(value.encode("utf-8")) != target_length or normalize_dn(value) is None:
        raise SpecificationError("failed to construct a valid fixed-length DN")
    return value


def _stored_dn(namespace: str, entry: int, value: int = 0) -> str:
    return (
        f"cn={namespace}-{entry:06d}-{value:03d},"
        "ou=Stored Values,ou=References,dc=example,dc=com"
    )


def _outer_values(name: str) -> Dict[str, list[str]]:
    return {
        "sString1": [f"{name}-a"],
        "sString2": [f"{name}-b"],
        "sString3": [f"{name}-c"],
        "sString4": ["QWEQWEQWE"],
    }


def _set_overrides(
        overrides: Dict[int, Dict[str, list[str]]], ids: Iterable[int],
        attrs: Mapping[str, Sequence[str]]) -> None:
    for entry_id in ids:
        target = overrides.setdefault(entry_id, {})
        for attr, values in attrs.items():
            target[attr] = list(values)


@dataclass
class WorkloadData:
    data: DataSet
    cohorts: Dict[str, list[int]]
    people_ids: set[int]
    dynamic_ids: set[int]
    overrides: Dict[int, Dict[str, list[str]]]
    flat_ids: list[int]
    dynamic_metadata: Dict[str, Any]


def _write_ldif_entry(stream: Any, dn: str, attrs: Mapping[str, Sequence[str]]) -> None:
    stream.write(f"dn: {dn}\n")
    for attr, values in attrs.items():
        for value in values:
            if "\n" in value or "\r" in value:
                raise SpecificationError(f"LDIF value for {attr} contains a newline")
            stream.write(f"{attr}: {value}\n")
    stream.write("\n")


def build_data(
        spec: Mapping[str, Any], profile: Mapping[str, Any], output: Path) -> WorkloadData:
    people = int(profile["people"])
    principal_count = int(profile["principal_cohort"])
    scenario_count = int(profile["scenario_cohort"])
    dn_mode_count = int(profile["dn_mode_cohort"])
    base_dn = str(spec["base_dn"])
    suffix_dn = str(spec["suffix_dn"])
    matrices = spec["matrices"]
    dynamic = spec["dynamic_list"]
    allocator = Allocator(people)

    principal = allocator.allocate("principal", principal_count)
    branch = allocator.allocate("branch-scaling", scenario_count)
    positive = allocator.allocate("positive-hit", scenario_count)
    fallback_count = min(32, scenario_count)
    fallback_simple = allocator.allocate("fallback-simple", fallback_count)
    fallback_complex = allocator.allocate("fallback-complex", fallback_count)
    for count in matrices["multivalue_counts"]:
        allocator.allocate(f"multivalue-{count}", scenario_count)
    allocator.allocate("multivalue-m-gt-k", scenario_count)
    for mode in matrices["dn_modes"]:
        allocator.allocate(f"dn-mode-{mode}", dn_mode_count)
    adverse = allocator.allocate("substring-adverse", min(8, scenario_count))
    for count in profile["candidate_counts"]:
        cohort_name = f"candidate-{count}"
        if int(count) == principal_count:
            allocator.cohorts[cohort_name] = list(principal)
        else:
            allocator.allocate(cohort_name, int(count))
    flat_ids = allocator.allocate("flat-family-controls", 8)
    bind_ids = allocator.allocate("dynamic-bind-users", 2)

    overrides: Dict[int, Dict[str, list[str]]] = {}
    _set_overrides(overrides, principal, {
        "sString1": ["asd"], "sString2": ["ff"], "sString3": ["vv"],
        "sString4": ["QWEQWEQWE"],
    })
    for entry_id in principal:
        _set_overrides(overrides, [entry_id], {
            "sDN1": [_stored_dn("principal", entry_id)],
            "sDN2": [_stored_dn("principal-account", entry_id)],
        })

    _set_overrides(overrides, branch, _outer_values("branch"))
    branch_live = [
        _long_dn(index, int(spec["primary"]["long_dn_length"]), "live")
        for index in range(scenario_count)
    ]
    for offset, entry_id in enumerate(branch):
        _set_overrides(overrides, [entry_id], {
            "sDN1": [branch_live[offset % len(branch_live)]],
            "sDN2": [_stored_dn("branch-account", entry_id)],
        })

    _set_overrides(overrides, positive, _outer_values("positive"))
    for entry_id in positive:
        _set_overrides(overrides, [entry_id], {
            "sDN1": [POSITIVE_DN],
            "sDN2": [_stored_dn("positive-account", entry_id)],
        })

    _set_overrides(overrides, fallback_simple, _outer_values("fallback-simple"))
    for entry_id in fallback_simple:
        _set_overrides(overrides, [entry_id], {
            "sDN1": [_stored_dn("fallback-simple", entry_id)],
            "sDN2": [ACCOUNT_DN],
        })
    # The complex cohort intentionally has neither DN attribute.
    _set_overrides(overrides, fallback_complex, _outer_values("fallback-complex"))

    for value_count in matrices["multivalue_counts"]:
        ids = allocator.cohorts[f"multivalue-{value_count}"]
        _set_overrides(overrides, ids, _outer_values(f"multivalue-{value_count}"))
        for entry_id in ids:
            _set_overrides(overrides, [entry_id], {
                "sDN1": [
                    _stored_dn(f"mv{value_count}", entry_id, value)
                    for value in range(value_count)
                ],
                "sDN2": [_stored_dn("mv-account", entry_id)],
            })
    guard_ids = allocator.cohorts["multivalue-m-gt-k"]
    _set_overrides(overrides, guard_ids, _outer_values("multivalue-guard"))
    for entry_id in guard_ids:
        _set_overrides(overrides, [entry_id], {
            "sDN1": [_stored_dn("guard17", entry_id, value) for value in range(17)],
            "sDN2": [_stored_dn("guard-account", entry_id)],
        })

    long_live = _long_dn(9999, int(spec["primary"]["long_dn_length"]), "target")
    dn_stored = {
        "short-canonical": SHORT_DN,
        "long-canonical": long_live,
        "case-equivalent": SHORT_DN,
        "escaped-comma": ESCAPED_DN,
        "invalid-remainder": SHORT_DN,
    }
    for mode, value in dn_stored.items():
        ids = allocator.cohorts[f"dn-mode-{mode}"]
        _set_overrides(overrides, ids, _outer_values(f"dn-{mode}"))
        for entry_id in ids:
            _set_overrides(overrides, [entry_id], {
                "sDN1": [value],
                "sDN2": [_stored_dn("dn-mode-account", entry_id)],
            })

    _set_overrides(overrides, adverse, _outer_values("substring-adverse"))
    for entry_id in adverse:
        _set_overrides(overrides, [entry_id], {
            "sDN1": [POSITIVE_DN],
            "sDN2": [_stored_dn("adverse-account", entry_id)],
            "sSub": ["rare-adverse-fragment"],
        })

    for count in profile["candidate_counts"]:
        ids = allocator.cohorts[f"candidate-{count}"]
        if int(count) == principal_count:
            continue
        _set_overrides(overrides, ids, _outer_values(f"candidate-{count}"))
        for entry_id in ids:
            _set_overrides(overrides, [entry_id], {
                "sDN1": [_stored_dn(f"candidate{count}", entry_id)],
                "sDN2": [_stored_dn("candidate-account", entry_id)],
            })

    flat_values = [
        {"sString1": ["flat-a-hit"]},
        {"sString2": ["flat-b-hit"]},
        {"sString1": ["flat-a-hit"], "sString2": ["flat-b-hit"]},
        {"sString3": ["flat-c-hit"]},
        {"sString1": ["flat-supported-hit"]},
        {"sString1": ["flat-tie-a"], "sString2": ["flat-tie-b"]},
        {"sString1": ["flat-unused-six"]},
        {"sString2": ["flat-unused-seven"]},
    ]
    for entry_id, values in zip(flat_ids, flat_values):
        _set_overrides(overrides, [entry_id], values)
    _set_overrides(overrides, [bind_ids[0]], {"userPassword": [BIND_PASSWORD]})
    _set_overrides(overrides, [bind_ids[1]], {"userPassword": [BIND_PASSWORD]})

    data = DataSet()
    data_path = output / "data.ldif"
    openldap_data_path = output / "data-openldap.ldif"
    data_path.parent.mkdir(parents=True, exist_ok=True)
    with (
            data_path.open("w", encoding="utf-8", newline="\n") as stream,
            openldap_data_path.open(
                "w", encoding="utf-8", newline="\n"
            ) as openldap_stream):
        _write_ldif_entry(stream, suffix_dn, {
            "objectClass": ["top", "domain"],
            "dc": ["example"],
            "aci": [AUTHENTICATED_READ_ACI],
        })
        _write_ldif_entry(openldap_stream, suffix_dn, {
            "objectClass": ["top", "domain"],
            "dc": ["example"],
        })
        people_base_attrs = {
            "objectClass": ["top", "organizationalUnit"], "ou": ["people"],
        }
        _write_ldif_entry(stream, base_dn, people_base_attrs)
        _write_ldif_entry(openldap_stream, base_dn, people_base_attrs)
        dynamic_base = f"{DYNAMIC_RDN},{suffix_dn}"
        dynamic_base_attrs = {
            "objectClass": ["top", "organizationalUnit"], "ou": ["dynamic"],
        }
        _write_ldif_entry(stream, dynamic_base, dynamic_base_attrs)
        _write_ldif_entry(openldap_stream, dynamic_base, dynamic_base_attrs)

        seed = int(spec["seed"])
        for entry_id in range(people):
            attrs: Dict[str, list[str]] = {
                "objectClass": [
                    "top", "person", "organizationalPerson", "inetOrgPerson",
                    "largeFilterStudyPerson",
                ],
                "uid": [f"lfs{entry_id:06d}"],
                "cn": [f"Large Filter Study Person {entry_id:06d}"],
                "sn": [f"Study{entry_id:06d}"],
                "sString1": [f"filler-a-{(entry_id + seed) % 997:03d}"],
                "sString2": [f"filler-b-{(entry_id + seed) % 991:03d}"],
                "sString3": [f"filler-c-{(entry_id + seed) % 983:03d}"],
                "sString4": ["filler-guard"],
                "sSub": ["broad common-fragment indexed value"],
                "sApprox": ["Xanadu Approximate Common"],
            }
            attrs.update(overrides.get(entry_id, {}))
            dn = _people_dn(entry_id, base_dn)
            _write_ldif_entry(stream, dn, attrs)
            _write_ldif_entry(openldap_stream, dn, attrs)
            data.add(dn, attrs)

        target_dn = _people_dn(0, base_dn)
        static_dns = []
        expected_dynamic_dns = []
        for index in range(int(dynamic["stored_candidates"])):
            dn = f"cn=dynamic-budget-static-{index:02d},{dynamic_base}"
            cn_values = [f"dynamic-budget-static-{index:02d}"]
            if index < int(dynamic["stored_matches"]):
                cn_values.append(f"Common Xanadu Dynamic Budget Static {index:02d}")
                expected_dynamic_dns.append(dn)
            attrs = {
                "objectClass": ["top", "groupOfNames", "extensibleObject"],
                "cn": cn_values,
                "sn": ["DynamicBudgetSn"],
                "member": [target_dn],
            }
            _write_ldif_entry(stream, dn, attrs)
            _write_ldif_entry(openldap_stream, dn, attrs)
            data.add(dn, attrs)
            static_dns.append(dn)

        url_dns = []
        for index in range(int(dynamic["dynamic_entries"])):
            dn = f"cn=dynamic-budget-url-{index:02d},{dynamic_base}"
            attrs = {
                "objectClass": ["top", "groupOfURLs", "extensibleObject"],
                "cn": [f"Dynamic Budget Plain URL {index:02d}"],
                "sn": ["DynamicBudgetSn"],
                "memberURL": [f"ldap:///{target_dn}??base?(objectClass=*)"],
            }
            _write_ldif_entry(stream, dn, attrs)
            data.add(dn, attrs)
            url_dns.append(dn)
        stream.flush()
        os.fsync(stream.fileno())
        openldap_stream.flush()
        os.fsync(openldap_stream.fileno())

    dynamic_ids = set(range(people, len(data.dns)))
    dynamic_metadata = {
        "base_dn": f"{DYNAMIC_RDN},{suffix_dn}",
        "target_dn": target_dn,
        "stored_dns": sorted(static_dns),
        "expected_dns": sorted(expected_dynamic_dns),
        "dynamic_url_dns": sorted(url_dns),
        "control_bind_dn": _people_dn(bind_ids[0], base_dn),
        "limited_bind_dn": _people_dn(bind_ids[1], base_dn),
        "bind_password": BIND_PASSWORD,
        "stored_candidates": int(dynamic["stored_candidates"]),
        "stored_matches": int(dynamic["stored_matches"]),
        "dynamic_entries": int(dynamic["dynamic_entries"]),
        "lookthrough_limit": int(dynamic["lookthrough_limit"]),
        "finite_scan_limit": int(dynamic["finite_scan_limit"]),
        "unlimited_scan_limit": int(dynamic["unlimited_scan_limit"]),
    }
    return WorkloadData(
        data=data,
        cohorts=allocator.cohorts,
        people_ids=set(range(people)),
        dynamic_ids=dynamic_ids,
        overrides=overrides,
        flat_ids=flat_ids,
        dynamic_metadata=dynamic_metadata,
    )


def _hash_dns(dns: Sequence[str]) -> str:
    return sha256_bytes("".join(f"{dn}\n" for dn in dns).encode("utf-8"))


def _diagnostic(
        expectation: str, applicable: bool, *, largest: Optional[int] = None,
        selected_attribute: Optional[str] = None, evidence: str = "") -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "applicable": applicable,
        "expectation": expectation,
        "evidence": evidence,
    }
    if largest is not None:
        value["largest_family"] = largest
    if selected_attribute is not None:
        value["selected_attribute"] = selected_attribute
    return value


def lookup_diagnostic(
        largest: Optional[int], selected_attribute: Optional[str] = None,
        expectation: Optional[str] = None) -> Dict[str, Any]:
    if expectation is None:
        expectation = "required-when-lookup-on" if largest is not None else "forbidden"
    return _diagnostic(
        expectation, True, largest=largest, selected_attribute=selected_attribute,
        evidence="OR filter equality lookup engaged: N node(s), largest K branches",
    )


def cap_diagnostic(expectation: str = "not-applicable") -> Dict[str, Any]:
    return _diagnostic(
        expectation,
        expectation != "not-applicable",
        evidence="costly AND component returned ALLIDS under read cap N",
    )


def assertion_stats(
        attr: str, values: Sequence[str], *, live: int = 0,
        absent: Optional[int] = None) -> Dict[str, int]:
    keys = [normalize_equality(attr, value) for value in values]
    valid = [key for key in keys if key is not None]
    invalid = len(keys) - len(valid)
    unique = len(set(valid))
    duplicates = len(valid) - unique
    if absent is None:
        absent = max(0, len(values) - live)
    return {
        "total": len(values),
        "live": live,
        "absent": absent,
        "duplicates": duplicates,
        "invalid": invalid,
        "normalized_unique": unique,
    }


class ScenarioWriter:
    def __init__(
            self, output: Path, workload: WorkloadData, profile_name: str,
            profile: Mapping[str, Any], base_dn: str) -> None:
        self.output = output
        self.workload = workload
        self.profile_name = profile_name
        self.profile = profile
        self.base_dn = base_dn
        self.scenarios: Dict[str, Dict[str, Any]] = {}
        self.scenario_groups: Dict[str, list[str]] = {}

    def add(
            self, scenario_id: str, filter_node: Filter, *,
            groups: Sequence[str], cohort_ids: Sequence[int],
            base_ids: Optional[set[int]] = None,
            base_dn: Optional[str] = None, scope: str = "sub",
            server_support: Sequence[str] = ("389ds", "openldap"),
            smoke_selected: bool = True,
            assertions: Optional[Mapping[str, int]] = None,
            relevant_values_per_entry: Any = 0,
            dn_mode: str = "not-applicable",
            simple_sdn2_branch: bool = False,
            lookup: Optional[Mapping[str, Any]] = None,
            cap: Optional[Mapping[str, Any]] = None,
            index_variant: str = "baseline-no-presence",
            description: str = "",
            parameters: Optional[Mapping[str, Any]] = None,
            server_notes: Optional[Mapping[str, str]] = None,
            selection_probe_id: Optional[int] = None,
            logical_outer_filter: Optional[Filter] = None,
            cross_server_comparison: Optional[Mapping[str, Any]] = None) -> None:
        if not SCENARIO_ID_RE.fullmatch(scenario_id):
            raise SpecificationError(f"invalid scenario id: {scenario_id}")
        if scenario_id in self.scenarios:
            raise SpecificationError(f"duplicate scenario id: {scenario_id}")
        if not groups or len(set(groups)) != len(groups):
            raise SpecificationError(f"scenario {scenario_id} needs unique groups")
        if scope not in {"base", "one", "sub"}:
            raise SpecificationError(f"invalid scope for {scenario_id}: {scope}")
        if any(server not in {"389ds", "openldap"} for server in server_support):
            raise SpecificationError(f"invalid server support for {scenario_id}")
        base_ids = self.workload.people_ids if base_ids is None else base_ids
        base_dn = base_dn or self.base_dn
        matched = filter_node.evaluate(self.workload.data).intersection(base_ids)
        expected_dns = self.workload.data.sorted_dns(matched)
        declared_cohort = set(cohort_ids)
        if len(declared_cohort) != len(cohort_ids):
            raise SpecificationError(f"scenario {scenario_id} has duplicate cohort IDs")
        cohort_basis = "declared-controlled-cohort"
        if logical_outer_filter is not None:
            required_components = (
                list(logical_outer_filter.children)
                if logical_outer_filter.kind == "and"
                else [logical_outer_filter]
            )
            available_components = (
                list(filter_node.children)
                if filter_node.kind == "and"
                else [filter_node]
            )
            for component in required_components:
                try:
                    available_components.remove(component)
                except ValueError as error:
                    raise SpecificationError(
                        f"scenario {scenario_id} logical outer AST is not a "
                        "component of its executed filter AST"
                    ) from error
            derived_cohort = logical_outer_filter.evaluate(
                self.workload.data).intersection(base_ids)
            if derived_cohort != declared_cohort:
                missing = len(declared_cohort - derived_cohort)
                unexpected = len(derived_cohort - declared_cohort)
                raise SpecificationError(
                    f"scenario {scenario_id} outer AST/cohort mismatch: "
                    f"{missing} declared IDs missing, {unexpected} unexpected IDs"
                )
            declared_cohort = derived_cohort
            cohort_basis = "derived-and-verified-from-outer-filter-ast"
        cohort_dns = self.workload.data.sorted_dns(declared_cohort)
        rendered = filter_node.render()
        filter_path = Path("filters") / f"{scenario_id}.filter"
        expected_path = Path("expected") / f"{scenario_id}.dns"
        expected_text = "".join(f"{dn}\n" for dn in expected_dns)
        write_text(self.output / filter_path, rendered + "\n")
        write_text(self.output / expected_path, expected_text)
        ber_filter = filter_node.ber()
        ber_request = search_request_ber(filter_node, base_dn, REQUESTED_ATTRIBUTES)
        assertion_value = dict(assertions or {
            "total": 0, "live": 0, "absent": 0, "duplicates": 0,
            "invalid": 0, "normalized_unique": 0,
        })
        required_assertion_keys = {
            "total", "live", "absent", "duplicates", "invalid",
            "normalized_unique",
        }
        if set(assertion_value) != required_assertion_keys:
            raise SpecificationError(f"scenario {scenario_id} has incomplete assertion stats")
        lookup_value = dict(lookup or lookup_diagnostic(None, expectation="not-applicable"))
        cap_value = dict(cap or cap_diagnostic())
        candidate = {
            "applicable": "389ds" in server_support,
            "status": "pending-observation",
            "observed_backend_candidate_count": None,
            "logical_outer_cohort_count": len(cohort_dns),
            "oracle": "operation-isolated build_candidate_list trace when available",
        }
        scenario: Dict[str, Any] = {
            "filter_file": filter_path.as_posix(),
            "expected_file": expected_path.as_posix(),
            "expected_count": len(expected_dns),
            "expected_sha256": sha256_bytes(expected_text.encode("utf-8")),
            "expected_result_code": "LDAP_SUCCESS",
            "base_dn": base_dn,
            "scope": scope,
            "requested_attributes": list(REQUESTED_ATTRIBUTES),
            "server_support": list(server_support),
            "server_notes": dict(server_notes or {}),
            "groups": list(groups),
            "smoke_selected": bool(smoke_selected),
            "description": description,
            "rendered_bytes": len(rendered.encode("utf-8")),
            "ber_filter_bytes": len(ber_filter),
            "ber_search_request_bytes": len(ber_request),
            "node_count": filter_node.node_count(),
            "branch_count": filter_node.leaf_count(),
            "equality_branch_count": filter_node.equality_count(),
            "logical_outer_cohort_count": len(cohort_dns),
            "logical_outer_cohort_sha256": _hash_dns(cohort_dns),
            "logical_outer_cohort_basis": cohort_basis,
            "live_assertions": assertion_value["live"],
            "absent_assertions": assertion_value["absent"],
            "duplicate_assertions": assertion_value["duplicates"],
            "invalid_assertions": assertion_value["invalid"],
            "normalized_unique_assertions": assertion_value["normalized_unique"],
            "assertion_counts": assertion_value,
            "relevant_values_per_entry": relevant_values_per_entry,
            "dn_mode": dn_mode,
            "simple_sdn2_branch": bool(simple_sdn2_branch),
            "index_variant": index_variant,
            "candidate_observation": candidate,
            "expected_lookup_diagnostic": lookup_value,
            "expected_cap_diagnostic": cap_value,
            "expected_candidate_count_diagnostic": candidate,
            "expected_diagnostics": {
                "or_lookup": lookup_value,
                "bounded_read": cap_value,
                "candidate_list": candidate,
            },
            "parameters": dict(parameters or {}),
        }
        if cross_server_comparison is not None:
            scenario["cross_server_comparison"] = dict(cross_server_comparison)
        if selection_probe_id is not None:
            if selection_probe_id not in base_ids:
                raise SpecificationError(
                    f"selection probe for {scenario_id} is outside its search base"
                )
            if selection_probe_id not in matched:
                raise SpecificationError(
                    f"selection probe for {scenario_id} does not match its filter"
                )
            probe_dn = self.workload.data.dns[selection_probe_id]
            scenario["selection_probe"] = {
                "base_dn": probe_dn,
                "scope": "base",
                "expected_count": 1,
                "expected_sha256": _hash_dns([probe_dn]),
                "oracle": "generated data/AST plus operation-isolated FILTER AVA trace",
            }
        self.scenarios[scenario_id] = scenario
        for group in groups:
            self.scenario_groups.setdefault(group, []).append(scenario_id)


def _outer_terms(name: str) -> list[Filter]:
    return [
        EQ("sString1", f"{name}-a"),
        EQ("sString2", f"{name}-b"),
        EQ("sString3", f"{name}-c"),
    ]


def _principal_outer_terms() -> list[Filter]:
    return [EQ("sString1", "asd"), EQ("sString2", "ff"), EQ("sString3", "vv")]


def _dn_family(values: Sequence[str]) -> Filter:
    return OR(*(EQ("sDN1", value) for value in values))


def _complex_fallback() -> Filter:
    return AND(
        EQ("sString4", "QWEQWEQWE"),
        NOT(PRESENT("sDN1")),
        NOT(PRESENT("sDN2")),
    )


def _primary_or(
        assertions: Sequence[str], *, include_sdn2: bool = True,
        order: Sequence[str] = ("dn", "sdn2", "fallback")) -> Filter:
    components = {
        "dn": _dn_family(assertions),
        "sdn2": EQ("sDN2", ACCOUNT_DN),
        "fallback": _complex_fallback(),
    }
    selected = [name for name in order if name != "sdn2" or include_sdn2]
    if set(selected) != ({"dn", "fallback", "sdn2"} if include_sdn2
                         else {"dn", "fallback"}):
        raise SpecificationError("primary OR order is inconsistent")
    return OR(*(components[name] for name in selected))


def _full_filter(
        outer: Sequence[Filter], assertions: Sequence[str], *,
        include_sdn2: bool = True,
        or_order: Sequence[str] = ("dn", "sdn2", "fallback"),
        extra: Sequence[Filter] = (), component_order: Optional[Sequence[str]] = None) -> Filter:
    large_or = _primary_or(assertions, include_sdn2=include_sdn2, order=or_order)
    if component_order is None:
        return AND(*outer, large_or, *extra)
    named: Dict[str, Filter] = {f"outer-{index}": node for index, node in enumerate(outer)}
    named["large-or"] = large_or
    for index, node in enumerate(extra):
        named[f"extra-{index}"] = node
    if set(component_order) != set(named):
        raise SpecificationError("AND component order is inconsistent")
    return AND(*(named[name] for name in component_order))


def _ghosts(spec: Mapping[str, Any], count: int, offset: int = 0) -> list[str]:
    length = int(spec["primary"]["long_dn_length"])
    return [_long_dn(offset + index, length, "missing") for index in range(count)]


def _dn_mode_assertions(
        spec: Mapping[str, Any], mode: str, positive: bool) -> list[str]:
    branch_count = int(spec["primary"]["dn_branches"])
    if mode == "invalid-remainder":
        valid_count = 14
        values = _ghosts(spec, valid_count, offset=7000)
        if positive:
            values[0] = SHORT_DN
        values.extend([
            "not a dn at all",
            # Keep malformed components in the middle of the DN.  A bare
            # terminal component or trailing comma reaches a permissive
            # terminal parser state in 389 DS and can become a lookup key;
            # these forms instead take an explicit invalid-DN path and must
            # remain in the classic evaluator remainder.
            "cn=missing,ou=References,dc=example,dc=com,bare,ou=tail",
            "cn=bad\\",
            "=missing,dc=example,dc=com",
            "cn=missing+bad,dc=example,dc=com",
            "cn=missing,dc=example,dc,ou=tail",
        ])
        return values
    values = _ghosts(spec, branch_count, offset=8000)
    if not positive:
        return values
    if mode == "short-canonical":
        assertion = SHORT_DN
    elif mode == "long-canonical":
        assertion = _long_dn(9999, int(spec["primary"]["long_dn_length"]), "target")
    elif mode == "case-equivalent":
        assertion = "CN=TARGET, OU=REFERENCES, DC=EXAMPLE, DC=COM"
    elif mode == "escaped-comma":
        assertion = r"CN=SMITH\, ALICE, OU=REFERENCES, DC=EXAMPLE, DC=COM"
    else:
        raise SpecificationError(f"unknown DN mode {mode}")
    values[0] = assertion
    return values


def emit_primary_and_index_scenarios(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    ghosts = _ghosts(spec, 355)
    outer = _principal_outer_terms()
    logical_outer = AND(*outer)
    cohort = workload.cohorts["principal"]
    full_stats = {
        "total": 356, "live": 0, "absent": 356, "duplicates": 0,
        "invalid": 0, "normalized_unique": 356,
    }
    without_stats = assertion_stats("sDN1", ghosts, live=0, absent=355)
    primary = _full_filter(outer, ghosts)
    without = _full_filter(outer, ghosts, include_sdn2=False)
    writer.add(
        "principal-with-sdn2-equality", primary,
        groups=["primary", "acceptance", "sdn2-pair"], cohort_ids=cohort,
        logical_outer_filter=logical_outer,
        assertions=full_stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
        lookup=lookup_diagnostic(355, "sDN1"),
        description="Exact 355-DN, 42KB, unproxied-root all-miss primary shape",
        parameters={"intentional_all_miss": True, "dn_assertion_length": 110},
    )
    writer.add(
        "principal-without-sdn2-equality", without,
        groups=["primary", "acceptance", "sdn2-pair"], cohort_ids=cohort,
        logical_outer_filter=logical_outer,
        assertions=without_stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-all-miss", simple_sdn2_branch=False,
        lookup=lookup_diagnostic(355, "sDN1"),
        description="Paired primary shape removing only the simple sDN2 equality",
        parameters={"intentional_all_miss": True, "paired_with": "principal-with-sdn2-equality"},
    )

    presence_variants = [
        ("none", "baseline-no-presence"),
        ("sdn1", "presence-sdn1"),
        ("sdn2", "presence-sdn2"),
        ("both", "presence-both"),
    ]
    for label, variant in presence_variants:
        writer.add(
            f"presence-primary-{label}", primary,
            groups=["presence-index", "primary"], cohort_ids=cohort,
            logical_outer_filter=logical_outer,
            assertions=full_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"), index_variant=variant,
            description=f"Primary shape with index variant {variant}",
            parameters={"presence_variant": variant},
        )
    for label, variant in (
            ("none", "baseline-no-presence"), ("both", "presence-both")):
        writer.add(
            f"presence-no-sdn2-{label}", without,
            groups=["presence-index", "sdn2-pair"], cohort_ids=cohort,
            logical_outer_filter=logical_outer,
            assertions=without_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=False,
            lookup=lookup_diagnostic(355, "sDN1"), index_variant=variant,
            description="Boundary presence-index control without simple sDN2 equality",
            parameters={"presence_variant": variant},
        )

    for label, variant in (
            ("all-equality", "baseline-no-presence"),
            ("without-sdn1", "without-sdn1-equality"),
            ("without-sdn2", "without-sdn2-equality")):
        writer.add(
            f"candidate-index-{label}", primary,
            groups=["candidate-index-controls", "primary"], cohort_ids=cohort,
            logical_outer_filter=logical_outer,
            assertions=full_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"), index_variant=variant,
            description="Candidate-generation index attribution control",
            parameters={"index_variant": variant},
        )

    primary_manifest = writer.scenarios["principal-with-sdn2-equality"]
    if primary_manifest["node_count"] != int(spec["primary"]["expected_node_count"]):
        raise SpecificationError(
            f"primary node count is {primary_manifest['node_count']}, expected 368"
        )
    if not (int(spec["primary"]["filter_bytes_min"])
            <= primary_manifest["rendered_bytes"]
            <= int(spec["primary"]["filter_bytes_max"])):
        raise SpecificationError(
            f"primary filter is {primary_manifest['rendered_bytes']} bytes, outside ~42KB bounds"
        )
    if writer.scenarios["principal-without-sdn2-equality"]["node_count"] != 367:
        raise SpecificationError("no-sDN2 pair must have exactly one fewer filter node")


def emit_candidate_and_branch_scaling(
        spec: Mapping[str, Any], profile: Mapping[str, Any],
        workload: WorkloadData, writer: ScenarioWriter) -> None:
    ghosts355 = _ghosts(spec, 355)
    full_stats = {
        "total": 356, "live": 0, "absent": 356, "duplicates": 0,
        "invalid": 0, "normalized_unique": 356,
    }
    for count in profile["candidate_counts"]:
        marker = f"candidate-{count}"
        if int(count) == int(profile["principal_cohort"]):
            outer = _principal_outer_terms()
            cohort_source = "principal"
        else:
            outer = _outer_terms(marker)
            cohort_source = marker
        writer.add(
            f"candidate-count-{count}",
            _full_filter(outer, ghosts355),
            groups=["candidate-scaling"], cohort_ids=workload.cohorts[marker],
            logical_outer_filter=AND(*outer),
            assertions=full_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Constant 355-branch filter with a controlled outer cohort",
            parameters={
                "candidate_count": count,
                "cohort_source": cohort_source,
                "intentional_all_miss": True,
            },
        )
        scenario = writer.scenarios[f"candidate-count-{count}"]
        if scenario["node_count"] != int(spec["primary"]["expected_node_count"]):
            raise SpecificationError(
                f"candidate-count-{count} changed the primary filter node count"
            )
        if not (
                int(spec["primary"]["filter_bytes_min"])
                <= scenario["rendered_bytes"]
                <= int(spec["primary"]["filter_bytes_max"])):
            raise SpecificationError(
                f"candidate-count-{count} is outside the primary byte bounds"
            )

    long_length = int(spec["primary"]["long_dn_length"])
    live_pool = [
        _long_dn(index, long_length, "live")
        for index in range(int(profile["scenario_cohort"]))
    ]
    for count in spec["matrices"]["branch_counts"]:
        _emit_branch_count_rung(spec, workload, writer, live_pool, count)


def _emit_branch_count_rung(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter, live_pool: Sequence[str], count: int) -> None:
    branch_cohort = workload.cohorts["branch-scaling"]
    branch_outer = _outer_terms("branch")
    zero_candidate_values = _ghosts(spec, count, offset=11000 + count)
    zero_outer = _outer_terms(f"branch-zero-{count}")
    writer.add(
        f"branch-count-{count}-zero-candidate",
        AND(*zero_outer, _dn_family(zero_candidate_values)),
        groups=["branch-scaling", "branch-zero-candidate"],
        cohort_ids=[],
        logical_outer_filter=AND(*zero_outer),
        assertions=assertion_stats("sDN1", zero_candidate_values, live=0),
        relevant_values_per_entry=0,
        dn_mode="long-canonical-all-miss",
        lookup=lookup_diagnostic(
            count if count >= 16 else None,
            "sDN1" if count >= 16 else None,
        ),
        description="Branch-count table-build control with no outer candidates",
        parameters={
            "branch_count": count,
            "distribution": "all-absent",
            "candidate_count": 0,
        },
    )
    for distribution in spec["matrices"]["branch_distributions"]:
        if distribution == "all-absent":
            values = zero_candidate_values
            live = 0
        elif distribution == "mostly-live":
            values = live_pool[:min(len(live_pool), count)]
            values += _ghosts(spec, count - len(values), offset=13000 + count)
            live = min(len(live_pool), count)
        elif distribution == "mixed":
            live = min(3, count)
            values = live_pool[:live] + _ghosts(
                spec, count - live, offset=15000 + count)
        elif distribution == "duplicates":
            live = max(2, count // 4)
            values = [live_pool[0]] * live
            values += _ghosts(spec, count - live, offset=17000 + count)
        else:
            raise SpecificationError(f"unknown branch distribution {distribution}")
        stats = assertion_stats("sDN1", values, live=live)
        writer.add(
            f"branch-count-{count}-{distribution}",
            AND(*branch_outer, _dn_family(values)),
            groups=["branch-scaling", f"branch-{distribution}"],
            cohort_ids=branch_cohort, assertions=stats,
            logical_outer_filter=AND(*branch_outer),
            relevant_values_per_entry=1, dn_mode="long-canonical",
            lookup=lookup_diagnostic(
                count if count >= 16 else None, "sDN1" if count >= 16 else None),
            description="Fixed-cohort DN equality branch-count scaling",
            parameters={"branch_count": count, "distribution": distribution},
        )


def emit_sub_threshold_branch_rungs(
        spec: Mapping[str, Any], profile: Mapping[str, Any],
        workload: WorkloadData, writer: ScenarioWriter) -> None:
    counts = spec["matrices"].get("sub_threshold_branch_counts")
    if not counts:
        return
    long_length = int(spec["primary"]["long_dn_length"])
    live_pool = [
        _long_dn(index, long_length, "live")
        for index in range(int(profile["scenario_cohort"]))
    ]
    for count in counts:
        _emit_branch_count_rung(spec, workload, writer, live_pool, count)


CANARY_SCENARIO_PREFIX = "drift-canary"
CANARY_INDEX_VARIANTS = (
    "baseline-no-presence",
    "presence-sdn1",
    "presence-sdn2",
    "presence-both",
    "without-sdn1-equality",
    "without-sdn2-equality",
)


def emit_drift_canary(spec: Mapping[str, Any], writer: ScenarioWriter) -> None:
    canary = spec.get("drift_canary")
    if not isinstance(canary, dict):
        return
    branch_count = int(canary["branch_count"])
    values = _ghosts(spec, branch_count, offset=31000)
    outer = _outer_terms("drift-canary")
    for variant in CANARY_INDEX_VARIANTS:
        writer.add(
            f"{CANARY_SCENARIO_PREFIX}-{variant}",
            AND(*outer, _dn_family(values)),
            groups=["drift-canary"],
            cohort_ids=[],
            logical_outer_filter=AND(*outer),
            assertions=assertion_stats("sDN1", values, live=0),
            relevant_values_per_entry=0,
            dn_mode="long-canonical-all-miss",
            lookup=lookup_diagnostic(None),
            index_variant=variant,
            description=(
                "Always-present cheap drift anchor; identical sub-threshold "
                "filter repeated in every bundle of every state"
            ),
            parameters={
                "branch_count": branch_count,
                "distribution": "all-absent",
                "candidate_count": 0,
                "drift_canary": True,
            },
        )


def emit_hits_fallbacks_and_multivalue(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    ghosts = _ghosts(spec, 355, offset=21000)
    positions = {"early": 0, "middle": 177, "late": 354}
    positive_cohort = workload.cohorts["positive-hit"]
    positive_outer = _outer_terms("positive")
    for label, position in positions.items():
        values = list(ghosts)
        values[position] = POSITIVE_DN
        writer.add(
            f"hit-position-{label}",
            AND(*positive_outer, _dn_family(values)),
            groups=["hit-position"], cohort_ids=positive_cohort,
            logical_outer_filter=AND(*positive_outer),
            assertions=assertion_stats("sDN1", values, live=1),
            relevant_values_per_entry=1, dn_mode="long-canonical-positive",
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Sole live DN assertion at a controlled source position",
            parameters={"hit_position": position, "reversed": False},
        )
    for label, values, cohort, outer, live in (
            ("all-miss-forward", list(ghosts), workload.cohorts["principal"],
             _principal_outer_terms(), 0),
            ("all-miss-reversed", list(reversed(ghosts)), workload.cohorts["principal"],
             _principal_outer_terms(), 0),
            ("positive-forward", [POSITIVE_DN] + ghosts[1:], positive_cohort,
             _outer_terms("positive"), 1),
            ("positive-reversed", list(reversed([POSITIVE_DN] + ghosts[1:])),
             positive_cohort, _outer_terms("positive"), 1)):
        writer.add(
            f"assertion-order-{label}", AND(*outer, _dn_family(values)),
            groups=["hit-position", "assertion-order"], cohort_ids=cohort,
            logical_outer_filter=AND(*outer),
            assertions=assertion_stats("sDN1", values, live=live),
            relevant_values_per_entry=1, dn_mode="long-canonical",
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Forward/reversed 355-assertion control",
            parameters={"order": "reversed" if label.endswith("reversed") else "forward"},
        )

    simple_outer = _outer_terms("fallback-simple")
    simple_filter = _full_filter(simple_outer, ghosts)
    writer.add(
        "fallback-simple-hit", simple_filter,
        groups=["fallbacks"], cohort_ids=workload.cohorts["fallback-simple"],
        logical_outer_filter=AND(*simple_outer),
        assertions={
            "total": 356, "live": 1, "absent": 355, "duplicates": 0,
            "invalid": 0, "normalized_unique": 356,
        }, relevant_values_per_entry=1, dn_mode="long-canonical-all-miss",
        simple_sdn2_branch=True, lookup=lookup_diagnostic(355, "sDN1"),
        description="Large DN family misses before the simple sDN2 fallback hits",
        parameters={"fallback": "simple"},
    )
    complex_outer = _outer_terms("fallback-complex")
    complex_filter = _full_filter(complex_outer, ghosts)
    writer.add(
        "fallback-complex-hit", complex_filter,
        groups=["fallbacks"], cohort_ids=workload.cohorts["fallback-complex"],
        logical_outer_filter=AND(*complex_outer),
        assertions={
            "total": 356, "live": 0, "absent": 356, "duplicates": 0,
            "invalid": 0, "normalized_unique": 356,
        }, relevant_values_per_entry=0, dn_mode="long-canonical-all-miss",
        simple_sdn2_branch=True, lookup=lookup_diagnostic(355, "sDN1"),
        description="Dedicated DN-absent cohort makes the complex fallback true",
        parameters={"fallback": "complex", "dn_attributes_genuinely_absent": True},
    )

    for count in spec["matrices"]["multivalue_counts"]:
        cohort = workload.cohorts[f"multivalue-{count}"]
        outer = _outer_terms(f"multivalue-{count}")
        writer.add(
            f"multivalue-sdn1-{count}",
            AND(*outer, _dn_family(ghosts)),
            groups=["multivalue-scaling"], cohort_ids=cohort,
            logical_outer_filter=AND(*outer),
            assertions=assertion_stats("sDN1", ghosts, live=0),
            relevant_values_per_entry=count, dn_mode="long-canonical-all-miss",
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Controlled multi-valued sDN1 all-miss scaling",
            parameters={"entry_values_m": count, "raw_k": 355, "unique_k": 355},
        )
    guard_values = _ghosts(spec, 16, offset=23000)
    guard_outer = _outer_terms("multivalue-guard")
    writer.add(
        "multivalue-m-gt-k-17-vs-16",
        AND(*guard_outer, _dn_family(guard_values)),
        groups=["multivalue-scaling", "decline-paths"],
        cohort_ids=workload.cohorts["multivalue-m-gt-k"],
        logical_outer_filter=AND(*guard_outer),
        assertions=assertion_stats("sDN1", guard_values, live=0),
        relevant_values_per_entry=17, dn_mode="long-canonical-all-miss",
        lookup=lookup_diagnostic(16, "sDN1"),
        description="Focused high-cardinality decline with m=17 and unique k=16",
        parameters={"entry_values_m": 17, "raw_k": 16, "unique_k": 16,
                    "expected_evaluator_path": "m-greater-than-k-decline"},
    )


def emit_dn_normalization(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    for mode in spec["matrices"]["dn_modes"]:
        cohort = workload.cohorts[f"dn-mode-{mode}"]
        positive_values = _dn_mode_assertions(spec, mode, True)
        miss_values = _dn_mode_assertions(spec, mode, False)
        lookup_size = (None if mode == "invalid-remainder"
                       else int(spec["primary"]["dn_branches"]))
        for result_mode, outer_name, cohort_ids, values, live in (
                ("zero-candidate", f"dn-{mode}-zero", [], positive_values, 1),
                ("positive", f"dn-{mode}", cohort, positive_values, 1),
                ("all-miss", f"dn-{mode}", cohort, miss_values, 0)):
            outer = _outer_terms(outer_name)
            writer.add(
                f"dn-{mode}-{result_mode}",
                AND(*outer, _dn_family(values)),
                groups=["dn-normalization", f"dn-{mode}"],
                cohort_ids=cohort_ids,
                logical_outer_filter=AND(*outer),
                assertions=assertion_stats("sDN1", values, live=live),
                relevant_values_per_entry=(0 if result_mode == "zero-candidate" else 1),
                dn_mode=mode,
                lookup=lookup_diagnostic(
                    lookup_size, "sDN1" if lookup_size is not None else None,
                    expectation=("forbidden-valid-family-below-threshold"
                                 if mode == "invalid-remainder" else None)),
                description="Syntax-aware DN normalization/build/probe control",
                parameters={
                    "result_distribution": result_mode,
                    "invalid_remainder": mode == "invalid-remainder",
                    "valid_family_size": 14 if mode == "invalid-remainder" else 355,
                },
            )


def emit_decomposition(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    ghosts = _ghosts(spec, 355, offset=25000)
    outer = _principal_outer_terms()
    logical_outer = AND(*outer)
    cohort = workload.cohorts["principal"]
    cases = {
        "a-outer-only": (AND(*outer), assertion_stats("sDN1", [], live=0), False, None),
        "b-one-absent-equality": (
            AND(*outer, OR(EQ("sDN1", ghosts[0]))),
            assertion_stats("sDN1", ghosts[:1], live=0), False, None),
        "c-large-sdn1-only": (
            AND(*outer, _dn_family(ghosts)),
            assertion_stats("sDN1", ghosts, live=0), False, 355),
        "d-sdn2-and-complex-only": (
            AND(*outer, OR(EQ("sDN2", ACCOUNT_DN), _complex_fallback())),
            {"total": 1, "live": 0, "absent": 1, "duplicates": 0,
             "invalid": 0, "normalized_unique": 1}, True, None),
        "e-full-primary": (
            _full_filter(outer, ghosts),
            {"total": 356, "live": 0, "absent": 356, "duplicates": 0,
             "invalid": 0, "normalized_unique": 356}, True, 355),
        "f-full-no-sdn2": (
            _full_filter(outer, ghosts, include_sdn2=False),
            assertion_stats("sDN1", ghosts, live=0), False, 355),
        "g-complex-only": (
            AND(*outer, _complex_fallback()), assertion_stats("sDN1", [], live=0),
            False, None),
    }
    for case, (filter_node, stats, has_sdn2, largest) in cases.items():
        writer.add(
            f"decomposition-{case}", filter_node,
            groups=["decomposition"], cohort_ids=cohort,
            logical_outer_filter=logical_outer,
            assertions=stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=has_sdn2,
            lookup=lookup_diagnostic(largest, "sDN1" if largest else None),
            description="Primary filter decomposition control",
            parameters={"decomposition_case": case.split("-", 1)[0].upper()},
        )


def _approximate_cross_server_policy(workload: WorkloadData) -> Dict[str, Any]:
    semantic_contract = {
        "version": 1,
        "attribute": "sApprox",
        "oracle": "casefolded-alphanumeric-identical-token",
        "positive_assertion": "xanadu approximate common",
        "negative_assertion": "definitely dissimilar token 98f221",
        "scope": "base",
    }
    contract_sha256 = sha256_bytes(canonical_json_bytes(semantic_contract))
    target_id = min(workload.people_ids)
    target_dn = workload.data.dns[target_id]
    positive = APPROX("sApprox", semantic_contract["positive_assertion"])
    negative = APPROX("sApprox", semantic_contract["negative_assertion"])
    return {
        "policy": "requires-native-equivalence-preflight",
        "default_eligibility": "excluded",
        "semantic_contract": semantic_contract,
        "contract_sha256": contract_sha256,
        "required_probe_ids": ["positive-identical-token", "negative-dissimilar-token"],
        "probes": {
            "positive-identical-token": {
                "base_dn": target_dn,
                "scope": "base",
                "filter": positive.render(),
                "requested_attributes": list(REQUESTED_ATTRIBUTES),
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 1,
                "expected_sha256": _hash_dns([target_dn]),
            },
            "negative-dissimilar-token": {
                "base_dn": target_dn,
                "scope": "base",
                "filter": negative.render(),
                "requested_attributes": list(REQUESTED_ATTRIBUTES),
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 0,
                "expected_sha256": _hash_dns([]),
            },
        },
    }


def emit_combined_and_order_controls(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    ghosts = _ghosts(spec, 355, offset=27000)
    positive_values = list(ghosts)
    positive_values[177] = POSITIVE_DN
    stats = {
        "total": 356, "live": 1, "absent": 355, "duplicates": 0,
        "invalid": 0, "normalized_unique": 356,
    }
    positive = workload.cohorts["positive-hit"]
    positive_outer = _outer_terms("positive")
    approximate_comparison = _approximate_cross_server_policy(workload)
    gain = _full_filter(
        positive_outer, positive_values,
        extra=(SUBSTRING("sSub", "*common-fragment*"),))
    writer.add(
        "combined-substring-gain", gain,
        groups=["combined-substring", "combined-features"], cohort_ids=positive,
        logical_outer_filter=AND(*positive_outer),
        assertions=stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-positive", simple_sdn2_branch=True,
        lookup=lookup_diagnostic(355, "sDN1"), cap=cap_diagnostic("required"),
        description="Broad substring posting exceeds the established outer bound",
        parameters={"substring_posting_intent": "much-larger-than-bound", "gain_expected": True},
    )
    adverse_cohort = workload.cohorts["substring-adverse"]
    adverse_outer = _outer_terms("substring-adverse")
    adverse = _full_filter(
        adverse_outer, positive_values,
        extra=(SUBSTRING("sSub", "*rare-adverse-fragment*"),))
    writer.add(
        "combined-substring-adverse", adverse,
        groups=["combined-substring", "decline-paths"], cohort_ids=adverse_cohort,
        logical_outer_filter=AND(*adverse_outer),
        assertions=stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-positive", simple_sdn2_branch=True,
        lookup=lookup_diagnostic(355, "sDN1"),
        cap=cap_diagnostic("forbidden-selective-posting"),
        description="Selective substring posting where a bounded fallback should not help",
        parameters={"substring_posting_intent": "already-selective", "gain_expected": False},
    )
    approximate = _full_filter(
        positive_outer, positive_values,
        extra=(APPROX("sApprox", "xanadu approximate common"),))
    writer.add(
        "combined-approximate-gain", approximate,
        groups=["combined-approximate", "combined-features"], cohort_ids=positive,
        logical_outer_filter=AND(*positive_outer),
        assertions=stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-positive", simple_sdn2_branch=True,
        lookup=lookup_diagnostic(355, "sDN1"), cap=cap_diagnostic("required"),
        description="Indexed approximate component with conservative identical-token oracle",
        parameters={"approximate_oracle": "casefolded-alphanumeric-identical-token"},
        cross_server_comparison=approximate_comparison,
        server_notes={
            "openldap": "Cross-server timing requires native preflight confirming comparable approx semantics",
            "389ds": "Expected to use the configured approximate index",
        },
    )

    principal_cohort = workload.cohorts["principal"]
    outer_orders = [
        ("abc", [0, 1, 2]),
        ("cba", [2, 1, 0]),
        ("bca", [1, 2, 0]),
    ]
    principal_outer = _principal_outer_terms()
    all_miss_stats = {
        "total": 356, "live": 0, "absent": 356, "duplicates": 0,
        "invalid": 0, "normalized_unique": 356,
    }
    for label, order in outer_orders:
        ordered = [principal_outer[index] for index in order]
        writer.add(
            f"order-principal-outer-{label}", _full_filter(ordered, ghosts),
            groups=["branch-order"], cohort_ids=principal_cohort,
            logical_outer_filter=AND(*ordered),
            assertions=all_miss_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Permutation of the three selective outer equalities",
            parameters={"outer_order": label},
        )
    for label, order in (
            ("dn-sdn2-fallback", ("dn", "sdn2", "fallback")),
            ("fallback-sdn2-dn", ("fallback", "sdn2", "dn")),
            ("sdn2-dn-fallback", ("sdn2", "dn", "fallback"))):
        writer.add(
            f"order-principal-or-{label}",
            _full_filter(principal_outer, ghosts, or_order=order),
            groups=["branch-order"], cohort_ids=principal_cohort,
            logical_outer_filter=AND(*principal_outer),
            assertions=all_miss_stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"),
            description="Permutation of the large family and fallback branches",
            parameters={"outer_or_order": list(order)},
        )
    writer.add(
        "order-principal-assertions-reversed",
        _full_filter(principal_outer, list(reversed(ghosts))),
        groups=["branch-order", "assertion-order"], cohort_ids=principal_cohort,
        logical_outer_filter=AND(*principal_outer),
        assertions=all_miss_stats, relevant_values_per_entry=1,
        dn_mode="long-canonical-all-miss", simple_sdn2_branch=True,
        lookup=lookup_diagnostic(355, "sDN1"),
        description="Full primary with all 355 DN assertions reversed",
        parameters={"assertion_order": "reversed"},
    )

    outer = _outer_terms("positive")
    extra = (SUBSTRING("sSub", "*common-fragment*"),)
    for label, order in (
            ("outer-first", ("outer-0", "outer-1", "outer-2", "large-or", "extra-0")),
            ("costly-first", ("extra-0", "large-or", "outer-2", "outer-1", "outer-0")),
            ("large-or-first", ("large-or", "extra-0", "outer-0", "outer-1", "outer-2"))):
        writer.add(
            f"order-combined-{label}",
            _full_filter(outer, positive_values, extra=extra, component_order=order),
            groups=["branch-order", "combined-substring"], cohort_ids=positive,
            logical_outer_filter=AND(*outer),
            assertions=stats, relevant_values_per_entry=1,
            dn_mode="long-canonical-positive", simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"), cap=cap_diagnostic("required"),
            description="Combined-feature source-order permutation",
            parameters={"and_order": list(order), "combined_feature": "substring"},
        )

    approximate_extra = (APPROX("sApprox", "xanadu approximate common"),)
    for label, order in (
            ("outer-first", ("outer-0", "outer-1", "outer-2", "large-or", "extra-0")),
            ("costly-first", ("extra-0", "large-or", "outer-2", "outer-1", "outer-0")),
            ("large-or-first", ("large-or", "extra-0", "outer-0", "outer-1", "outer-2"))):
        writer.add(
            f"order-combined-approx-{label}",
            _full_filter(
                outer,
                positive_values,
                extra=approximate_extra,
                component_order=order,
            ),
            groups=["branch-order", "combined-approximate"],
            cohort_ids=positive,
            logical_outer_filter=AND(*outer),
            assertions=stats,
            relevant_values_per_entry=1,
            dn_mode="long-canonical-positive",
            simple_sdn2_branch=True,
            lookup=lookup_diagnostic(355, "sDN1"),
            cap=cap_diagnostic("required"),
            description="Approximate combined-feature source-order permutation",
            parameters={"and_order": list(order), "combined_feature": "approximate"},
            cross_server_comparison=approximate_comparison,
            server_notes={
                "openldap": (
                    "Cross-server timing requires native preflight confirming "
                    "comparable approx semantics"
                ),
                "389ds": "Expected to use the configured approximate index",
            },
        )


def _flat_equalities(attr: str, values: Sequence[str]) -> list[Filter]:
    return [EQ(attr, value) for value in values]


def emit_flat_family_controls(
        spec: Mapping[str, Any], workload: WorkloadData,
        writer: ScenarioWriter) -> None:
    flat = workload.flat_ids
    flat_cohort = flat
    a16 = ["flat-a-hit"] + [f"flat-a-miss-{index:02d}" for index in range(15)]
    b64 = ["flat-b-hit"] + [f"flat-b-miss-{index:02d}" for index in range(63)]
    for label, components in (
            ("a16-b64", _flat_equalities("sString1", a16)
             + _flat_equalities("sString2", b64)),
            ("b64-a16", _flat_equalities("sString2", b64)
             + _flat_equalities("sString1", a16))):
        values = a16 + b64
        writer.add(
            f"flat-family-ranking-{label}", OR(*components),
            groups=["flat-family", "family-ranking"], cohort_ids=flat_cohort,
            assertions={
                "total": 80, "live": 2, "absent": 78, "duplicates": 0,
                "invalid": 0, "normalized_unique": len(set(values)),
            }, relevant_values_per_entry={"min": 0, "max": 2},
            dn_mode="not-applicable", lookup=lookup_diagnostic(64, "sString2"),
            description="16-branch A and 64-branch B in both source orders",
            parameters={"family_sizes": {"sString1": 16, "sString2": 64}},
            selection_probe_id=flat[2],
        )

    c64 = ["flat-c-hit"] + [f"flat-c-miss-{index:02d}" for index in range(63)]
    third = OR(
        EQ("sString1", "flat-a-distractor"),
        EQ("sString2", "flat-b-distractor"),
        *_flat_equalities("sString3", c64),
    )
    writer.add(
        "flat-family-third-after-distractors", third,
        groups=["flat-family", "family-discovery"], cohort_ids=flat_cohort,
        assertions={
            "total": 66, "live": 1, "absent": 65, "duplicates": 0,
            "invalid": 0, "normalized_unique": 66,
        }, relevant_values_per_entry={"min": 0, "max": 1},
        lookup=lookup_diagnostic(64, "sString3"),
        description="Large third family follows one-branch A/B distractors",
        parameters={"expected_fix": "all-family-discovery"},
        selection_probe_id=flat[3],
    )

    unsupported = [f"not a valid dn {index}" for index in range(64)]
    supported = ["flat-supported-hit"] + [f"flat-supported-miss-{index:02d}"
                                           for index in range(15)]
    fallback = OR(
        *_flat_equalities("sDN1", unsupported),
        *_flat_equalities("sString1", supported),
    )
    writer.add(
        "flat-family-unsupported-fallback", fallback,
        groups=["flat-family", "family-ranking", "decline-paths"],
        cohort_ids=flat_cohort,
        assertions={
            "total": 80, "live": 1, "absent": 79, "duplicates": 0,
            "invalid": 64, "normalized_unique": 16,
        }, relevant_values_per_entry={"min": 0, "max": 1},
        dn_mode="invalid-remainder", lookup=lookup_diagnostic(16, "sString1"),
        description="Larger unnormalizable DN family falls back to supported family",
        parameters={"unsupported_family_raw": 64, "supported_family": 16},
        selection_probe_id=flat[4],
    )

    tie_a = ["flat-tie-a"] + [f"flat-tie-a-miss-{index:02d}" for index in range(15)]
    tie_b = ["flat-tie-b"] + [f"flat-tie-b-miss-{index:02d}" for index in range(15)]
    for label, first, second, selected in (
            ("a-first", ("sString1", tie_a), ("sString2", tie_b), "sString1"),
            ("b-first", ("sString2", tie_b), ("sString1", tie_a), "sString2")):
        filter_node = OR(
            *_flat_equalities(first[0], first[1]),
            *_flat_equalities(second[0], second[1]),
        )
        writer.add(
            f"flat-family-tie-{label}", filter_node,
            groups=["flat-family", "family-ranking"], cohort_ids=flat_cohort,
            assertions={
                "total": 32, "live": 2, "absent": 30, "duplicates": 0,
                "invalid": 0, "normalized_unique": 32,
            }, relevant_values_per_entry={"min": 0, "max": 2},
            lookup=lookup_diagnostic(16, selected),
            description="Equal-size families use deterministic first-occurrence tie-break",
            parameters={"first_family": selected, "tie_size": 16},
            selection_probe_id=flat[5],
        )


def emit_dynamic_list_controls(
        workload: WorkloadData, writer: ScenarioWriter) -> None:
    metadata = workload.dynamic_metadata
    filter_node = AND(
        EQ("sn", "DynamicBudgetSn"),
        EQ("member", metadata["target_dn"]),
        SUBSTRING("cn", "*xanadu*"),
    )
    stats = {
        "total": 1, "live": 1, "absent": 0, "duplicates": 0,
        "invalid": 0, "normalized_unique": 1,
    }
    dynamic_cap = cap_diagnostic("revision-dependent-dynamic-safety")
    dynamic_cap["revision_expectations"] = {
        "combined-diagnostic": "required-pre-fix-diagnostic",
        "dynamic-list-fix": "forbidden",
        "final": "forbidden",
    }
    for label, scan_limit in (
            ("unlimited", metadata["unlimited_scan_limit"]),
            ("finite", metadata["finite_scan_limit"])):
        writer.add(
            f"dynamic-list-lookthrough-{label}", filter_node,
            groups=["dynamic-list-correctness"],
            cohort_ids=[
                writer.workload.data.dns.index(dn) for dn in metadata["stored_dns"]
            ],
            base_ids=workload.dynamic_ids, base_dn=metadata["base_dn"],
            server_support=["389ds"], assertions=stats,
            relevant_values_per_entry=1, dn_mode="canonical",
            lookup=lookup_diagnostic(None, expectation="not-applicable"),
            cap=dynamic_cap,
            description="20 stored + 20 dynamic candidates, two exact matches, L=30",
            parameters={
                **metadata,
                "id_list_scan_limit": scan_limit,
                "dynamic_lists_enabled": True,
                "expected_final_dns": metadata["expected_dns"],
            },
            server_notes={"389ds": "Correctness-only control; never include in timing ratios"},
        )


def emit_all_scenarios(
        spec: Mapping[str, Any], profile: Mapping[str, Any],
        workload: WorkloadData, writer: ScenarioWriter) -> None:
    emit_primary_and_index_scenarios(spec, workload, writer)
    emit_candidate_and_branch_scaling(spec, profile, workload, writer)
    emit_hits_fallbacks_and_multivalue(spec, workload, writer)
    emit_dn_normalization(spec, workload, writer)
    emit_decomposition(spec, workload, writer)
    emit_combined_and_order_controls(spec, workload, writer)
    emit_flat_family_controls(spec, workload, writer)
    emit_dynamic_list_controls(workload, writer)
    emit_sub_threshold_branch_rungs(spec, profile, workload, writer)
    emit_drift_canary(spec, writer)


def _copy_static_files(
        spec: Mapping[str, Any], spec_path: Path, output: Path) -> Dict[str, str]:
    workload_root = spec_path.resolve().parent
    static = spec["static_files"]
    destinations = {
        "schema_389ds": Path("schema") / "99large-filter-study.ldif",
        "schema_openldap": Path("schema") / "large-filter-study.schema",
        "index_config": Path("indexes") / "index-configurations.json",
    }
    for key, destination in destinations.items():
        source = workload_root / static[key]
        write_text(output / destination, source.read_text(encoding="utf-8"))
    return {key: value.as_posix() for key, value in destinations.items()}


def _file_hashes(output: Path) -> Dict[str, str]:
    files = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "workload-manifest.json":
            files[path.relative_to(output).as_posix()] = sha256_file(path)
    return files


def generate_workload(spec_path: Path, profile_name: str, output_path: Path) -> Dict[str, Any]:
    spec_path = spec_path.resolve()
    spec = load_spec(spec_path)
    profile = validate_spec(spec, profile_name, spec_path)
    with atomic_output_directory(output_path) as temporary:
        static_paths = _copy_static_files(spec, spec_path, temporary)
        write_json(temporary / "study-spec.json", spec)
        workload = build_data(spec, profile, temporary)
        writer = ScenarioWriter(
            temporary, workload, profile_name, profile, str(spec["base_dn"])
        )
        emit_all_scenarios(spec, profile, workload, writer)

        required_groups = {
            "primary", "sdn2-pair", "presence-index", "candidate-scaling",
            "branch-scaling", "hit-position", "fallbacks",
            "multivalue-scaling", "dn-normalization", "decomposition",
            "candidate-index-controls", "combined-substring",
            "combined-approximate", "branch-order", "flat-family",
            "family-discovery", "family-ranking", "dynamic-list-correctness",
            "decline-paths",
        }
        missing_groups = required_groups.difference(writer.scenario_groups)
        if missing_groups:
            raise SpecificationError(
                f"generator omitted required scenario groups: {sorted(missing_groups)}"
            )
        for group, scenario_ids in writer.scenario_groups.items():
            if not scenario_ids:
                raise SpecificationError(f"empty scenario group {group}")

        files = _file_hashes(temporary)
        workload_digest_input = {
            "format_version": 1,
            "profile": profile_name,
            "seed": spec["seed"],
            "host_intent": profile["host_intent"],
            "files": files,
        }
        workload_sha256 = sha256_bytes(canonical_json_bytes(workload_digest_input))
        workload_id = f"{profile_name}-{workload_sha256[:16]}"
        scenario_groups = {
            group: sorted(ids) for group, ids in sorted(writer.scenario_groups.items())
        }
        scenarios = {
            scenario_id: writer.scenarios[scenario_id]
            for scenario_id in sorted(writer.scenarios)
        }
        people_dns = workload.data.sorted_dns(workload.people_ids)
        principal_dns = workload.data.sorted_dns(workload.cohorts["principal"])
        manifest: Dict[str, Any] = {
            "format_version": 1,
            "profile": profile_name,
            "host_intent": profile["host_intent"],
            "correctness_only": profile["host_intent"] == "correctness_only",
            "release_timing_evidence": profile["host_intent"] == "native_fedora_timing",
            "workload_id": workload_id,
            "workload_sha256": workload_sha256,
            "entries": int(profile["people"]),
            "entry_counts": {
                "people": int(profile["people"]),
                "principal_cohort": int(profile["principal_cohort"]),
                "dynamic_stored": int(spec["dynamic_list"]["stored_candidates"]),
                "dynamic_urls": int(spec["dynamic_list"]["dynamic_entries"]),
                "ldif_records_total": (
                    int(profile["people"])
                    + int(spec["dynamic_list"]["stored_candidates"])
                    + int(spec["dynamic_list"]["dynamic_entries"])
                    + 3
                ),
                "openldap_ldif_records_total": (
                    int(profile["people"])
                    + int(spec["dynamic_list"]["stored_candidates"])
                    + 3
                ),
            },
            "dataset_import_oracles": {
                "people": {
                    "base_dn": str(spec["base_dn"]),
                    "scope": "sub",
                    "filter": "(objectClass=largeFilterStudyPerson)",
                    "requested_attributes": ["1.1"],
                    "expected_result_code": "LDAP_SUCCESS",
                    "expected_count": len(people_dns),
                    "expected_sha256": _hash_dns(people_dns),
                },
                "principal_outer_cohort": {
                    "base_dn": str(spec["base_dn"]),
                    "scope": "sub",
                    "filter": (
                        "(&(sString1=asd)(sString2=ff)(sString3=vv))"
                    ),
                    "requested_attributes": ["1.1"],
                    "expected_result_code": "LDAP_SUCCESS",
                    "expected_count": len(principal_dns),
                    "expected_sha256": _hash_dns(principal_dns),
                },
            },
            "seed": int(spec["seed"]),
            "data_file": "data.ldif",
            "server_data_files": {
                "389ds": "data.ldif",
                "openldap": "data-openldap.ldif",
            },
            "files": files,
            "scenario_groups": scenario_groups,
            "scenarios": scenarios,
            "index_config_file": static_paths["index_config"],
            "schema_files": {
                "389ds": static_paths["schema_389ds"],
                "openldap": static_paths["schema_openldap"],
            },
            "source_spec_file": "study-spec.json",
            "oracle": {
                "source": "generated data plus syntax-aware filter AST",
                "expected_order": "ascending UTF-8 DN text",
                "expected_hash": "SHA-256 of bare sorted DNs, each followed by LF",
                "directory_string": "Unicode NFKC, casefold, insignificant-space collapse",
                "distinguished_name": "RFC4514 generated subset with escaped/hex values and AVA normalization",
                "substring": "case-ignore initial/any/final semantics",
                "approximate": "conservative identical alphanumeric token semantics; native equivalence preflight required",
                "server_agreement_used": False,
            },
            "primary_contract": {
                "people": int(profile["people"]),
                "logical_outer_cohort": int(profile["principal_cohort"]),
                "dn_branches": 355,
                "node_count": writer.scenarios["principal-with-sdn2-equality"]["node_count"],
                "rendered_bytes": writer.scenarios["principal-with-sdn2-equality"]["rendered_bytes"],
                "expected_count": 0,
                "intentional_all_miss": True,
                "outer_values": {
                    "sString1": "asd",
                    "sString2": "ff",
                    "sString3": "vv",
                    "sString4": "QWEQWEQWE",
                },
                "principal_attribute_presence": {
                    "sDN1": int(profile["principal_cohort"]),
                    "sDN2": int(profile["principal_cohort"]),
                },
                "simple_sdn2_assertion": ACCOUNT_DN,
                "simple_sdn2_expected_matches": 0,
                "complex_fallback_expected_matches": 0,
                "requested_attributes": list(REQUESTED_ATTRIBUTES),
                "paired_scenarios": [
                    "principal-with-sdn2-equality",
                    "principal-without-sdn2-equality",
                ],
            },
            "dynamic_list": workload.dynamic_metadata,
        }
        write_json(temporary / "workload-manifest.json", manifest)
    return manifest


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate one deterministic large-filter study workload"
    )
    parser.add_argument(
        "--spec", type=Path, default=DEFAULT_SPEC,
        help=f"source study spec (default: {DEFAULT_SPEC})",
    )
    parser.add_argument(
        "--profile", choices=("full", "smoke", "tiny"), required=True,
        help="full native workload or reduced correctness workload",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="new output directory; existing paths are rejected",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        manifest = generate_workload(args.spec, args.profile, args.output)
    except (SpecificationError, FileExistsError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({
        "output": str(args.output.resolve()),
        "profile": manifest["profile"],
        "workload_id": manifest["workload_id"],
        "entries": manifest["entries"],
        "scenarios": len(manifest["scenarios"]),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
