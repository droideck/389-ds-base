"""Unit tests for the OrbStack correctness-only smoke orchestrator."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


STUDY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = STUDY_ROOT / "bin" / "run-orbstack-smoke"
LOADER = importlib.machinery.SourceFileLoader("run_orbstack_smoke", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[LOADER.name] = smoke
LOADER.exec_module(smoke)


EXPECTED_SHA = "e0161d0e61d0cdef22175418f0d4a1e126216a86"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class RPMValidationTests(unittest.TestCase):
    def make_rpms(self, root: Path, token: str = "e0161d0e") -> None:
        names = (
            f"389-ds-base-3.3.0.20260720git{token}-1.fc42.x86_64.rpm",
            f"389-ds-base-libs-3.3.0.20260720git{token}-1.fc42.x86_64.rpm",
            f"python3-lib389-3.3.0.20260720git{token}-1.fc42.noarch.rpm",
            f"389-ds-base-debuginfo-3.3.0.20260720git{token}-1.fc42.x86_64.rpm",
        )
        for name in names:
            (root / name).write_bytes(name.encode("ascii"))

    def test_accepts_exact_source_prefix_and_selects_runtime_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_rpms(root)
            result = smoke.validate_rpms(root, EXPECTED_SHA)
        self.assertEqual(
            result["install_filenames"],
            [
                "389-ds-base-libs-3.3.0.20260720gite0161d0e-1.fc42.x86_64.rpm",
                "python3-lib389-3.3.0.20260720gite0161d0e-1.fc42.noarch.rpm",
                "389-ds-base-3.3.0.20260720gite0161d0e-1.fc42.x86_64.rpm",
            ],
        )

    def test_rejects_stale_rpm_filename_before_container_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_rpms(root, token="fb50cf8e7")
            with self.assertRaisesRegex(smoke.SmokeError, "refusing stale RPM filenames"):
                smoke.validate_rpms(root, EXPECTED_SHA)

    def test_rejects_rpm_without_source_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "389-ds-base-3.3.0-1.fc42.x86_64.rpm",
                "389-ds-base-libs-3.3.0-1.fc42.x86_64.rpm",
                "python3-lib389-3.3.0-1.fc42.noarch.rpm",
            ):
                (root / name).write_bytes(b"rpm")
            with self.assertRaisesRegex(smoke.SmokeError, "does not expose a git<sha>"):
                smoke.validate_rpms(root, EXPECTED_SHA)


class InstalledIdentityTests(unittest.TestCase):
    @staticmethod
    def manifests() -> tuple[smoke.RunSpec, dict[str, object], dict[str, object]]:
        spec = smoke.RUN_SPECS[0]
        hashes = {
            "runtime_closure_sha256": "a" * 64,
            "backend_runtime_closure_sha256": "b" * 64,
            "behavioral_runtime_identity_sha256": "c" * 64,
        }
        harness = {"content_sha256": "d" * 64}
        run_manifest = {**hashes, "harness_identity": harness}
        artifact_manifest = {
            **hashes,
            "harness_identity": harness,
            "server_executable": {
                "executable_name": "ns-slapd",
                "executable_path": "/usr/bin/ns-slapd",
                "executable_sha256": "e" * 64,
                "elf_build_id": {
                    "status": "observed",
                    "value": "f" * 40,
                },
                "owning_package": "389-ds-base-3.3.0-1.fc42.x86_64",
                "package_nevra": "389-ds-base-3.3.0-1.fc42.x86_64",
                "runtime_closure_sha256": hashes["runtime_closure_sha256"],
                "rpm_verify": {
                    "accepted": True,
                    "returncode": 0,
                    "stdout": "",
                    "stderr": "",
                },
            },
        }
        return spec, run_manifest, artifact_manifest

    def test_installed_artifact_identity_rejects_dirty_or_bool_rpm_verify(
            self) -> None:
        cases = {
            "not accepted": ("accepted", False),
            "boolean return code": ("returncode", True),
            "nonzero return code": ("returncode", 1),
            "dirty stdout": ("stdout", ".....UG..  g /var/lock/dirsrv\n"),
            "dirty stderr": ("stderr", "rpm verification warning\n"),
        }
        for name, (field, value) in cases.items():
            with self.subTest(name=name):
                spec, run_manifest, artifact_manifest = self.manifests()
                artifact_manifest["server_executable"]["rpm_verify"][field] = value
                with self.assertRaisesRegex(
                        smoke.SmokeError, "strict rpm -V evidence is not clean"):
                    smoke.verified_installed_artifact_identity(
                        run_manifest, artifact_manifest, spec
                    )

    def test_cross_container_identity_accepts_three_distinct_identical_records(
            self) -> None:
        run_records, container_records = self.cross_container_records()
        verified = smoke.verify_389ds_cross_container_identity(
            run_records, container_records
        )
        self.assertEqual(verified["status"], "pass")
        self.assertEqual(verified["bundle_count"], 3)
        self.assertEqual(verified["distinct_container_count"], 3)
        self.assertTrue(verified["strict_rpm_verify_all_clean"])

    def test_cross_container_identity_rejects_each_identity_divergence(
            self) -> None:
        for divergence, expected_error in (
                ("runtime", "installed artifact identity differs"),
                ("image", "container image identity differs"),
                ("nevra", "installed NEVRA identity differs"),
                ("container-id", "did not use three distinct containers")):
            with self.subTest(divergence=divergence):
                run_records, container_records = self.cross_container_records()
                if divergence == "runtime":
                    run_records[1]["installed_artifact_identity"][
                        "runtime_closure_sha256"
                    ] = "9" * 64
                elif divergence == "image":
                    container_records[1]["image_identity"][
                        "container_image_id"
                    ] = "sha256:" + "9" * 64
                elif divergence == "nevra":
                    container_records[1]["environment"]["installed_nevras"] = [
                        "389-ds-base-3.3.1-1.fc42.x86_64"
                    ]
                else:
                    container_records[1]["id"] = container_records[0]["id"]
                with self.assertRaisesRegex(smoke.SmokeError, expected_error):
                    smoke.verify_389ds_cross_container_identity(
                        run_records, container_records
                    )

    @classmethod
    def cross_container_records(
            cls) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        spec, run_manifest, artifact_manifest = cls.manifests()
        identity, rpm_verify = smoke.verified_installed_artifact_identity(
            run_manifest, artifact_manifest, spec
        )
        run_records: list[dict[str, object]] = []
        container_records: list[dict[str, object]] = []
        for index, run_spec in enumerate(
                item for item in smoke.RUN_SPECS if item.server == "389ds"):
            run_records.append({
                "name": run_spec.name,
                "server": "389ds",
                "installed_artifact_identity": dict(identity),
                "rpm_verify": dict(rpm_verify),
            })
            container_records.append({
                "bundle": run_spec.name,
                "id": f"container-id-{index}",
                "name": f"container-name-{index}",
                "image_identity": {
                    "container_image_id": "sha256:" + "1" * 64,
                    "configured_image": "fedora:42",
                },
                "environment": {
                    "installed_nevras": [
                        "389-ds-base-3.3.0-1.fc42.x86_64"
                    ],
                },
            })
        return run_records, container_records


class OwnedContainerCleanupTests(unittest.TestCase):
    @staticmethod
    def completed(
            returncode: int = 0, stdout: str = "", stderr: str = ""):
        return smoke.subprocess.CompletedProcess(
            args=["docker"], returncode=returncode,
            stdout=stdout, stderr=stderr,
        )

    @staticmethod
    def owned(*, retain: bool) -> smoke.OwnedContainers:
        owned = smoke.OwnedContainers("docker", "run-123", retain)
        owned.names = ["owned-container"]
        owned.records = [{
            "name": "owned-container",
            "id": "container-id-1",
            "status": "running",
        }]
        return owned

    def test_cleanup_proves_post_removal_absence_and_empty_label_query(
            self) -> None:
        owned = self.owned(retain=False)
        with mock.patch.object(
                smoke, "run_process", side_effect=(
                    self.completed(stdout=json.dumps(owned.labels)),
                    self.completed(stdout="owned-container\n"),
                    self.completed(returncode=1),
                    self.completed(stdout=""),
                )) as run_process:
            errors = owned.cleanup()
        self.assertEqual(errors, [])
        self.assertEqual(owned.records[0]["status"], "removed")
        self.assertTrue(owned.records[0]["removal_verified_absent"])
        self.assertEqual(owned.cleanup_evidence["status"], "pass")
        self.assertTrue(owned.cleanup_evidence["zero_owned_containers_remaining"])
        label_query = run_process.call_args_list[-1].args[0]
        self.assertIn("ps", label_query)
        for key, value in owned.labels.items():
            self.assertIn(f"label={key}={value}", label_query)

    def test_retain_cleanup_verifies_id_and_ownership_labels(self) -> None:
        owned = self.owned(retain=True)
        observed = {
            "Id": "container-id-1",
            "Config": {"Labels": owned.labels},
            "State": {"Status": "running"},
        }
        with mock.patch.object(
                smoke, "run_process",
                return_value=self.completed(stdout=json.dumps(observed))):
            errors = owned.cleanup()
        self.assertEqual(errors, [])
        self.assertEqual(owned.records[0]["status"], "retained")
        self.assertTrue(owned.records[0]["retention_verified"])
        self.assertEqual(owned.cleanup_evidence["status"], "pass")
        self.assertEqual(owned.cleanup_evidence["verified_retained_count"], 1)


class MatrixAndArtifactTests(unittest.TestCase):
    def test_emulated_dirsrv_stop_policy_is_explicit_and_non_native(self) -> None:
        self.assertEqual(
            smoke.ORBSTACK_DIRSRV_SERVICE_OVERRIDES,
            {"MemoryDenyWriteExecute": "no", "KillSignal": "SIGKILL"},
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("'KillSignal=SIGKILL'", source)
        self.assertNotIn("ORBSTACK_DIRSRV_SERVICE_OVERRIDES", (STUDY_ROOT / "bin" / "run-fedora-study").read_text(encoding="utf-8"))

    def workload_manifest(self) -> dict[str, object]:
        scenarios: dict[str, object] = {}
        for run in smoke.RUN_SPECS:
            for scenario_id in run.scenarios:
                existing = scenarios.setdefault(
                    scenario_id,
                    {
                        "server_support": [],
                        "index_variant": run.index_config,
                    },
                )
                self.assertEqual(existing["index_variant"], run.index_config)
                if run.server not in existing["server_support"]:
                    existing["server_support"].append(run.server)
        return {
            "format_version": 1,
            "profile": "smoke",
            "correctness_only": True,
            "release_timing_evidence": False,
            "entry_counts": {"people": 12_000, "principal_cohort": 612},
            "dataset_import_oracles": {
                "people": {
                    "expected_count": 12_000,
                    "expected_result_code": "LDAP_SUCCESS",
                    "expected_sha256": "a" * 64,
                },
                "principal_outer_cohort": {
                    "expected_count": 612,
                    "expected_result_code": "LDAP_SUCCESS",
                    "expected_sha256": "b" * 64,
                },
            },
            "scenarios": scenarios,
        }

    def test_matrix_matches_a_correctness_workload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_json(root / "workload-manifest.json", self.workload_manifest())
            loaded = smoke.validate_workload(root)
        self.assertEqual(loaded["profile"], "smoke")

    def test_runner_command_hard_codes_nonrelease_execution(self) -> None:
        run = smoke.RUN_SPECS[0]
        command = smoke.runner_command(run, expected_sha=EXPECTED_SHA, retain=False)
        pairs = dict(zip(command, command[1:]))
        self.assertEqual(pairs["--mode"], "correctness-only")
        self.assertEqual(pairs["--host-class"], "macos_orbstack_emulated")
        self.assertEqual(pairs["--repeat"], "1")
        self.assertEqual(pairs["--warmups"], "0")
        self.assertEqual(pairs["--perf"], "off")
        self.assertEqual(pairs["--profile"], "off")
        self.assertNotIn("native-timing", command)
        self.assertIn("--cleanup", command)
        self.assertNotIn("--allow-rpm-verify-differences", command)

    def test_dry_run_assigns_each_389ds_bundle_a_fresh_container(self) -> None:
        plan = smoke.dry_run_plan(
            args=smoke.argparse.Namespace(workload=None, retain=False),
            expected_sha=EXPECTED_SHA,
            host={"docker": "/usr/local/bin/docker"},
            rpm_metadata={},
            output=Path("/tmp/results"),
            workload=Path("/tmp/workload"),
        )
        ds_containers = [
            command["container"]
            for command in plan["commands"]
            if command["run"].startswith("389ds-")
        ]
        self.assertEqual(len(ds_containers), 3)
        self.assertEqual(len(set(ds_containers)), 3)
        self.assertEqual(
            plan["container_isolation"],
            "fresh-container-per-389ds-bundle",
        )
        for command in plan["commands"]:
            self.assertNotIn(
                "--allow-rpm-verify-differences", command["argv"]
            )

    @staticmethod
    def background_referral_control() -> dict[str, object]:
        policy = {
            "clock": "CLOCK_MONOTONIC",
            "interval_anchor": "kernel-monotonic-epoch",
            "requested_seconds": 3600,
            "safety_margin_seconds": 5.0,
            "collection_policy": "fail-before-or-at-deadline",
        }
        return {
            "attribute": "nsslapd-referral-check-period",
            "initial": "60",
            "requested_seconds": 3600,
            "pre_restart_readback": "3600",
            "post_restart_readback": "3600",
            "final_restart_applied": True,
            "clock": "CLOCK_MONOTONIC",
            "interval_anchor": "kernel-monotonic-epoch",
            "safety_margin_seconds": 5.0,
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
                "context": "synthetic post-restart referral monitor",
                "paired_operation_count": 1,
                "start_line_count": 1,
                "completion_line_count": 1,
                "unmatched_referral_start_count": 0,
                "minimum_paired_operation_count": 1,
                "poll_count": 1,
                "wait_seconds": 0.1,
                "completion_observed_monotonic_seconds": 43_204.0,
                "stability_seconds": 0.05,
            },
            "restart_initiated_monotonic_seconds": 43_200.0,
            "restart_initiated_bucket": 12,
            "barrier_covered_bucket": 12,
            "stat_log_control": {
                "initial": "0",
                "barrier_value": "1",
                "final_readback": "0",
                "restored": True,
            },
            "quiet_window": {
                "bucket": 12,
                "next_boundary_monotonic_seconds": 46_800.0,
                "deadline_monotonic_seconds": 46_795.0,
                "established_monotonic_seconds": 43_205.0,
                "remaining_seconds": 3_590.0,
                "policy": "fail-collection-before-or-at-deadline",
            },
            "access_log_internal_operation_control": {
                "attribute": "nsslapd-accesslog-level",
                "initial": "0",
                "requested": 260,
                "pre_restart_readback": "260",
                "post_restart_readback": "260",
                "internal_operation_bit_enabled": True,
                "passed": True,
            },
            "policy_material": policy,
            "policy_sha256": hashlib.sha256(json.dumps(
                policy, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest(),
            "evidence_status": "observed",
            "passed": True,
        }

    @staticmethod
    def background_quiet_guard(
            server: str, context: str) -> dict[str, object]:
        if server == "openldap":
            return {
                "status": "not-applicable",
                "context": context,
                "clock": "CLOCK_MONOTONIC",
                "bucket": None,
                "start_monotonic_seconds": 43_210.0,
                "end_monotonic_seconds": 43_211.0,
                "duration_seconds": 1.0,
                "next_boundary_monotonic_seconds": None,
                "deadline_monotonic_seconds": None,
                "safety_margin_seconds": None,
                "passed": True,
            }
        return {
            "status": "passed",
            "context": context,
            "clock": "CLOCK_MONOTONIC",
            "bucket": 12,
            "start_monotonic_seconds": 43_210.0,
            "end_monotonic_seconds": 43_211.0,
            "duration_seconds": 1.0,
            "next_boundary_monotonic_seconds": 46_800.0,
            "deadline_monotonic_seconds": 46_795.0,
            "safety_margin_seconds": 5.0,
            "passed": True,
        }

    def write_result_bundle(
            self, root: Path, run: smoke.RunSpec, *, row_release: bool = False) -> None:
        payload = b"deterministic payload\n"
        payload_sha = hashlib.sha256(payload).hexdigest()
        empty_sha = hashlib.sha256(b"").hexdigest()
        scenarios = {
            scenario_id: {
                "expected_count": 0,
                "expected_sha256": empty_sha,
                "expected_result_code": "LDAP_SUCCESS",
                "groups": ["presence-index"],
                "requested_attributes": ["1.1"],
            }
            for scenario_id in run.scenarios
        }
        workload = {
            "correctness_only": True,
            "release_timing_evidence": False,
            "files": {"payload.txt": payload_sha},
            "scenarios": scenarios,
        }
        runtime_closure_sha = "c" * 64
        backend_closure_sha = "d" * 64
        behavioral_identity_sha = "e" * 64
        harness_identity = {"content_sha256": "f" * 64}
        run_manifest = {
            "run_id": f"synthetic-{run.name}",
            "status": "complete",
            "mode": "correctness-only",
            "host_class": smoke.HOST_CLASS,
            "correctness_only": True,
            "release_timing_evidence": False,
            "repeat_count": 1,
            "warmup_count": 0,
            "index_config": run.index_config,
            "server": run.server,
            "lookup_mode_requested": run.lookup,
            "lookup_mode_actual": run.lookup,
            "backend_requested": "mdb",
            "backend_actual": "mdb",
            "selected_scenarios": list(run.scenarios),
            "correctness_status": "pass",
            "runtime_closure_sha256": runtime_closure_sha,
            "backend_runtime_closure_sha256": backend_closure_sha,
            "behavioral_runtime_identity_sha256": behavioral_identity_sha,
            "harness_identity": harness_identity,
        }
        referral_control = None
        if run.server == "389ds":
            referral_control = self.background_referral_control()
            run_manifest["server_setup"] = {
                "background_referral_check_control": referral_control,
            }
        write_json(root / "run-manifest.json", run_manifest)
        write_json(root / "workload-manifest.json", workload)
        write_json(root / "workload" / "workload-manifest.json", workload)
        (root / "workload" / "payload.txt").write_bytes(payload)
        markers = {
            "host_class": smoke.HOST_CLASS,
            "correctness_only": True,
            "release_timing_evidence": False,
        }

        def exact_result() -> dict[str, object]:
            return {
                "evidence_status": "observed",
                "ldap_result_code": 0,
                "actual_client_result_code": 0,
                "expected_ldap_result_code": 0,
                "expected_result_code": "LDAP_SUCCESS",
                "returned_count": 0,
                "returned_sha256": empty_sha,
                "expected_count": 0,
                "expected_sha256": empty_sha,
                "exact_count_match": True,
                "exact_sha256_match": True,
                "exact_dns_match": True,
                "client_result_code_match": True,
                "passed": True,
            }

        server_result = {
            "evidence_status": "observed",
            "actual_server_result_code": 0,
            "expected_result_code": "LDAP_SUCCESS",
            "expected_ldap_result_code": 0,
            "server_result_code_match": True,
            "passed": True,
        }
        executable_name = "ns-slapd" if run.server == "389ds" else "slapd"
        executable_path = (
            "/usr/bin/ns-slapd" if run.server == "389ds" else "/usr/sbin/slapd"
        )
        package_name = "389-ds-base" if run.server == "389ds" else "openldap-servers"
        artifact_manifest = {
            **markers,
            "server": run.server,
            "runtime_closure_sha256": runtime_closure_sha,
            "backend_runtime_closure_sha256": backend_closure_sha,
            "behavioral_runtime_identity_sha256": behavioral_identity_sha,
            "harness_identity": harness_identity,
            "server_executable": {
                "executable_name": executable_name,
                "executable_path": executable_path,
                "executable_sha256": "a" * 64,
                "elf_build_id": {
                    "status": "observed",
                    "value": "1" * 40,
                },
                "owning_package": f"{package_name}-1.fc42.x86_64",
                "package_nevra": f"{package_name}-1.fc42.x86_64",
                "runtime_closure_sha256": runtime_closure_sha,
                "rpm_verify": {
                    "accepted": True,
                    "returncode": 0,
                    "stdout": "",
                    "stderr": "",
                },
            },
        }
        if referral_control is not None:
            artifact_manifest["background_referral_check_control"] = (
                referral_control
            )
        write_json(root / "artifact-manifest.json", artifact_manifest)
        write_json(
            root / "correctness.json",
            {
                **markers,
                "scenarios": [
                    {
                        "scenario": scenario_id,
                        "correctness": "pass",
                        "postflight_verified": True,
                        "pre_post_mechanism_match": True,
                        "diagnostic_flights": {
                            phase: {
                                "operation_isolated": True,
                                "isolation": {
                                    "background_quiet_window": (
                                        self.background_quiet_guard(
                                            run.server,
                                            f"{scenario_id} {phase}",
                                        )
                                    ),
                                },
                                "exact_result": exact_result(),
                                "server_result_evidence": server_result,
                            }
                            for phase in ("preflight", "postflight")
                        },
                    }
                    for scenario_id in run.scenarios
                ],
            },
        )
        write_json(
            root / "raw-results.json",
            {
                **markers,
                "rows": [
                    {
                        **markers,
                        "release_timing_evidence": row_release,
                        "scenario": scenario_id,
                        "server": run.server,
                        "backend": "mdb",
                        "lookup_mode": run.lookup,
                        "index_config": run.index_config,
                        "phase": "measured",
                        "attribute_variant": "attrs-1.1",
                        "requested_attributes": ["1.1"],
                        "background_quiet_window": (
                            self.background_quiet_guard(
                                run.server, f"measured {scenario_id}",
                            )
                        ),
                        "exact_result": exact_result(),
                        "server_result_evidence": server_result,
                    }
                    for scenario_id in run.scenarios
                ],
            },
        )
        (root / "COMPLETE").write_text("complete\n", encoding="utf-8")

    def attach_approximate_evidence(self, root: Path, scenario_id: str) -> None:
        run_manifest = json.loads((root / "run-manifest.json").read_text())
        server = str(run_manifest["server"])
        target_dn = "uid=lfs000000,ou=people,dc=example,dc=com"
        semantic_contract = {
            "version": 1,
            "attribute": "sApprox",
            "oracle": "casefolded-alphanumeric-identical-token",
        }
        contract_sha = hashlib.sha256(json.dumps(
            semantic_contract,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()).hexdigest()
        probes = {
            "positive-identical-token": {
                "base_dn": target_dn,
                "scope": "base",
                "filter": "(sApprox~=xanadu approximate common)",
                "requested_attributes": ["1.1"],
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 1,
                "expected_sha256": smoke.dns_digest([target_dn]),
            },
            "negative-dissimilar-token": {
                "base_dn": target_dn,
                "scope": "base",
                "filter": "(sApprox~=definitely dissimilar token 98f221)",
                "requested_attributes": ["1.1"],
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 0,
                "expected_sha256": smoke.dns_digest([]),
            },
        }
        required = list(probes)
        policy = {
            "policy": "requires-native-equivalence-preflight",
            "default_eligibility": "excluded",
            "semantic_contract": semantic_contract,
            "contract_sha256": contract_sha,
            "required_probe_ids": required,
            "probes": probes,
        }
        workload = json.loads((root / "workload-manifest.json").read_text())
        workload["scenarios"][scenario_id]["groups"] = ["combined-approximate"]
        workload["scenarios"][scenario_id]["cross_server_comparison"] = policy
        write_json(root / "workload-manifest.json", workload)
        write_json(root / "workload" / "workload-manifest.json", workload)

        def exact(probe: dict[str, object]) -> dict[str, object]:
            return {
                "evidence_status": "observed",
                "ldap_result_code": 0,
                "actual_client_result_code": 0,
                "expected_ldap_result_code": 0,
                "expected_result_code": "LDAP_SUCCESS",
                "returned_count": probe["expected_count"],
                "returned_sha256": probe["expected_sha256"],
                "expected_count": probe["expected_count"],
                "expected_sha256": probe["expected_sha256"],
                "exact_count_match": True,
                "exact_sha256_match": True,
                "exact_dns_match": True,
                "client_result_code_match": True,
                "passed": True,
            }

        server_result = {
            "evidence_status": "observed",
            "actual_server_result_code": 0,
            "expected_result_code": "LDAP_SUCCESS",
            "expected_ldap_result_code": 0,
            "server_result_code_match": True,
            "passed": True,
        }
        artifact = json.loads((root / "artifact-manifest.json").read_text())
        artifact["approximate_semantics_evidence"] = {
            "status": "comparable",
            "evidence_status": "observed",
            "policy": policy["policy"],
            "contract_sha256": contract_sha,
            "semantic_contract": semantic_contract,
            "required_probe_ids": required,
            "probes": [
                {
                    "probe_id": probe_id,
                    "evidence_status": "observed",
                    "operation_isolated": True,
                    "isolation": {
                        "background_quiet_window": self.background_quiet_guard(
                            server, f"approximate probe {probe_id}",
                        ),
                    },
                    "declared_probe": probe,
                    "exact_result": exact(probe),
                    "server_result_evidence": server_result,
                    "result_line_isolated": True,
                    "passed": True,
                }
                for probe_id, probe in probes.items()
            ],
        }
        write_json(root / "artifact-manifest.json", artifact)

    def attach_dynamic_evidence(self, root: Path, scenario_id: str) -> None:
        run_manifest = json.loads((root / "run-manifest.json").read_text())
        server = str(run_manifest["server"])
        stored = [
            "cn=stored-00,ou=dynamic,dc=example,dc=com",
            "cn=stored-01,ou=dynamic,dc=example,dc=com",
        ]
        dynamic = ["cn=url-00,ou=dynamic,dc=example,dc=com"]
        workload = json.loads((root / "workload-manifest.json").read_text())
        workload["scenarios"][scenario_id]["groups"] = [
            "dynamic-list-correctness"
        ]
        workload["dynamic_list"] = {
            "stored_dns": stored,
            "dynamic_url_dns": dynamic,
        }
        write_json(root / "workload-manifest.json", workload)
        write_json(root / "workload" / "workload-manifest.json", workload)

        def operation(
                label: str, dns: list[str], *,
                allow_nested: bool,
                observed_nested: bool = False) -> dict[str, object]:
            expected = sorted(value.casefold() for value in dns)
            evidence: dict[str, object] = {
                "operation": label,
                "operation_isolated": True,
                "isolation": {
                    "background_quiet_window": self.background_quiet_guard(
                        server, label,
                    ),
                    "internal_server_operations": {
                        "status": (
                            "observed-planned"
                            if observed_nested else "not-observed"
                        ),
                        "allowed": allow_nested,
                        "required": False,
                        "line_count": 1 if observed_nested else 0,
                        "nested_line_count": 1 if observed_nested else 0,
                        "referral_monitor_line_count": 0,
                    },
                },
                "evidence_status": "observed",
                "ldap_result_code": 0,
                "actual_client_result_code": 0,
                "expected_ldap_result_code": 0,
                "expected_result_code": "LDAP_SUCCESS",
                "returned_count": len(expected),
                "returned_sha256": smoke.dns_digest(expected),
                "expected_count": len(expected),
                "expected_sha256": smoke.dns_digest(expected),
                "exact_count_match": True,
                "exact_sha256_match": True,
                "exact_dns_match": True,
                "client_result_code_match": True,
                "server_result_evidence": {
                    "evidence_status": "observed",
                    "actual_server_result_code": 0,
                    "expected_result_code": "LDAP_SUCCESS",
                    "expected_ldap_result_code": 0,
                    "server_result_code_match": True,
                    "passed": True,
                },
                "passed": True,
            }
            if label == "final-search":
                values = [20, 22, 1]
                error_path = (
                    root / "diagnostics" /
                    f"{scenario_id}.control.final-search.error.log"
                )
                error_path.parent.mkdir(parents=True, exist_ok=True)
                error_path.write_text("".join(
                    f"Candidate list has {value} ids\n" for value in values
                ))
                evidence["diagnostics"] = {
                    "candidate_list_values": values,
                    "candidate_list_status": (
                        "not-directly-observable-unattributed-traces"
                    ),
                    "observed_final_candidate_count": None,
                    "candidate_list_observation": {
                        "status": "not-directly-observable",
                        "reason": (
                            "outer and nested-internal traces are not "
                            "conn/op-correlated"
                        ),
                        "raw_trace_count": len(values),
                        "parser_status": "ambiguous-multiple-traces",
                    },
                }
                evidence["diagnostic_artifacts"] = {
                    "error_log": error_path.relative_to(root).as_posix(),
                    "error_log_sha256": hashlib.sha256(
                        error_path.read_bytes()
                    ).hexdigest(),
                    "error_log_size_bytes": error_path.stat().st_size,
                }
            return evidence

        correctness = json.loads((root / "correctness.json").read_text())
        correctness["scenarios"] = [{
            "scenario": scenario_id,
            "correctness": "pass",
            "historical_expected_failure": False,
            "ldap_adminlimit_exceeded": False,
            "mechanism_gate": {"status": "pass", "failures": []},
            "ordinary_candidates": operation(
                "ordinary-candidates", stored, allow_nested=False,
            ),
            "augmented_candidates": operation(
                "augmented-candidates", stored + dynamic, allow_nested=True,
            ),
            "final_search": operation(
                "final-search", [], allow_nested=True, observed_nested=True,
            ),
            "post_control_health": operation(
                "post-control-health", ["dc=example,dc=com"],
                allow_nested=True,
            ),
        }]
        write_json(root / "correctness.json", correctness)
        raw = json.loads((root / "raw-results.json").read_text())
        raw["rows"] = []
        write_json(root / "raw-results.json", raw)

    def test_result_verifier_accepts_complete_nonrelease_bundle(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            verified = smoke.verify_result_bundle(root, run)
        self.assertEqual(verified["status"], "pass")
        self.assertFalse(verified["release_timing_evidence"])

    def test_result_verifier_rejects_tampered_background_evidence(self) -> None:
        run = smoke.RUN_SPECS[2]
        for target, expected in (
                ("setup", "post_restart_readback is invalid"),
                ("row", "background-quiet guard did not pass")):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_result_bundle(root, run)
                if target == "setup":
                    for name, path in (
                            ("run", root / "run-manifest.json"),
                            ("artifact", root / "artifact-manifest.json")):
                        manifest = json.loads(path.read_text())
                        control = (
                            manifest["server_setup"][
                                "background_referral_check_control"
                            ]
                            if name == "run"
                            else manifest["background_referral_check_control"]
                        )
                        control["post_restart_readback"] = "60"
                        write_json(path, manifest)
                else:
                    raw_path = root / "raw-results.json"
                    raw = json.loads(raw_path.read_text())
                    raw["rows"][0]["background_quiet_window"]["status"] = (
                        "failed-crossed-boundary"
                    )
                    write_json(raw_path, raw)
                with self.assertRaisesRegex(smoke.SmokeError, expected):
                    smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_tampered_vattr_barrier(self) -> None:
        run = smoke.RUN_SPECS[2]
        cases = {
            "status": ("status", "not-observed", "barrier did not pass"),
            "source": (
                "source_function", "vattr_check_thread",
                "source_function is invalid",
            ),
            "delay": ("delay_seconds", True, "delay_seconds is invalid"),
            "filter": ("exact_filter", "(objectclass=*)", "exact_filter is invalid"),
            "pairing": (
                "completion_line_count", 0,
                "paired-operation evidence is invalid",
            ),
            "unmatched": (
                "unmatched_start_count", 1,
                "paired-operation evidence is invalid",
            ),
            "stability": (
                "stability_seconds", 0.999,
                "stability interval is invalid",
            ),
            "passed": ("passed", False, "barrier did not pass"),
        }
        for name, (field, value, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_result_bundle(root, run)
                for manifest_name, path in (
                        ("run", root / "run-manifest.json"),
                        ("artifact", root / "artifact-manifest.json")):
                    manifest = json.loads(path.read_text())
                    control = (
                        manifest["server_setup"][
                            "background_referral_check_control"
                        ]
                        if manifest_name == "run"
                        else manifest["background_referral_check_control"]
                    )
                    control["post_restart_vattr_check_barrier"][field] = value
                    write_json(path, manifest)
                with self.assertRaisesRegex(smoke.SmokeError, expected):
                    smoke.verify_result_bundle(root, run)

    def test_openldap_background_guards_remain_not_applicable(self) -> None:
        run = smoke.RunSpec(
            "openldap-background-na", "openldap", "unsupported",
            "presence-both", ("presence-primary-both",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            self.assertEqual(smoke.verify_result_bundle(root, run)["status"], "pass")
            artifact = json.loads((root / "artifact-manifest.json").read_text())
            run_manifest = json.loads((root / "run-manifest.json").read_text())
            correctness = json.loads((root / "correctness.json").read_text())
            raw = json.loads((root / "raw-results.json").read_text())
        self.assertNotIn("background_referral_check_control", artifact)
        self.assertNotIn("server_setup", run_manifest)
        self.assertTrue(all(
            flight["isolation"]["background_quiet_window"]["status"]
            == "not-applicable"
            for record in correctness["scenarios"]
            for flight in record["diagnostic_flights"].values()
        ))
        self.assertTrue(all(
            row["background_quiet_window"]["status"] == "not-applicable"
            for row in raw["rows"]
        ))

    def test_result_verifier_rejects_release_marker(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run, row_release=True)
            with self.assertRaisesRegex(smoke.SmokeError, "release_timing_evidence"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_duplicate_correctness_record(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            correctness = json.loads((root / "correctness.json").read_text())
            correctness["scenarios"].append(correctness["scenarios"][0])
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(smoke.SmokeError, "exactly one is required"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_missing_measured_rows(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            raw = json.loads((root / "raw-results.json").read_text())
            raw["rows"] = []
            write_json(root / "raw-results.json", raw)
            with self.assertRaisesRegex(smoke.SmokeError, "measured rows"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_forged_exact_hash(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            correctness = json.loads((root / "correctness.json").read_text())
            correctness["scenarios"][0]["diagnostic_flights"]["preflight"][
                "exact_result"
            ]["returned_sha256"] = "0" * 64
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(smoke.SmokeError, "returned hash"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_forged_numeric_result_codes(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            correctness = json.loads((root / "correctness.json").read_text())
            preflight = correctness["scenarios"][0]["diagnostic_flights"][
                "preflight"
            ]
            preflight["exact_result"]["ldap_result_code"] = 50
            preflight["exact_result"]["actual_client_result_code"] = 50
            preflight["server_result_evidence"]["actual_server_result_code"] = 50
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(smoke.SmokeError, "LDAP result is not success"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_external_workload_symlink(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "bundle"
            root.mkdir()
            self.write_result_bundle(root, run)
            external = parent / "external-workload"
            (root / "workload").rename(external)
            os.symlink(external, root / "workload")
            with self.assertRaisesRegex(smoke.SmokeError, "workload root"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_rejects_lookup_or_attribute_mislabel(self) -> None:
        run = smoke.RUN_SPECS[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            manifest = json.loads((root / "run-manifest.json").read_text())
            manifest["lookup_mode_actual"] = "off"
            write_json(root / "run-manifest.json", manifest)
            raw = json.loads((root / "raw-results.json").read_text())
            raw["rows"][0]["requested_attributes"] = ["uid"]
            write_json(root / "raw-results.json", raw)
            with self.assertRaisesRegex(
                    smoke.SmokeError, "actual lookup mode differs.*requested attributes differ"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_checks_declared_approximate_probe_oracles(self) -> None:
        run = smoke.RunSpec(
            "approximate", "openldap", "unsupported",
            "baseline-no-presence", ("combined-approximate-gain",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            self.attach_approximate_evidence(root, run.scenarios[0])
            self.assertEqual(smoke.verify_result_bundle(root, run)["status"], "pass")
            artifact = json.loads((root / "artifact-manifest.json").read_text())
            forged = artifact["approximate_semantics_evidence"]["probes"][0]
            forged["exact_result"]["returned_count"] = 999
            forged["server_result_evidence"]["actual_server_result_code"] = 50
            write_json(root / "artifact-manifest.json", artifact)
            with self.assertRaisesRegex(
                    smoke.SmokeError, "returned count.*server LDAP result is not success"):
                smoke.verify_result_bundle(root, run)

    def test_result_verifier_checks_all_dynamic_operation_oracles(self) -> None:
        run = smoke.RunSpec(
            "dynamic", "389ds", "on", "baseline-no-presence",
            ("dynamic-list-lookthrough-finite",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            self.attach_dynamic_evidence(root, run.scenarios[0])
            self.assertEqual(smoke.verify_result_bundle(root, run)["status"], "pass")
            correctness = json.loads((root / "correctness.json").read_text())
            correctness["scenarios"][0]["ordinary_candidates"][
                "returned_count"
            ] = 999
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(smoke.SmokeError, "returned count"):
                smoke.verify_result_bundle(root, run)
            ordinary = correctness["scenarios"][0]["ordinary_candidates"]
            ordinary["returned_count"] = 2
            ordinary["isolation"]["internal_server_operations"][
                "allowed"
            ] = True
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(
                    smoke.SmokeError, "unexpectedly allowed internal work"):
                smoke.verify_result_bundle(root, run)

    def test_dynamic_optional_internal_policy_rejects_tampering(self) -> None:
        run = smoke.RunSpec(
            "dynamic", "389ds", "on", "baseline-no-presence",
            ("dynamic-list-lookthrough-finite",),
        )
        cases = (
            (
                "required nested work",
                "augmented_candidates", "required", True,
                "optional nested internal-work policy is invalid",
            ),
            (
                "disallowed nested work",
                "augmented_candidates", "allowed", False,
                "optional nested internal-work policy is invalid",
            ),
            (
                "disallowed health-bind work",
                "post_control_health", "allowed", False,
                "optional nested internal-work policy is invalid",
            ),
            (
                "unreported observed count",
                "augmented_candidates", "line_count", 1,
                "inconsistent not-observed internal counts",
            ),
            (
                "observed status without nested lines",
                "augmented_candidates", "status", "observed-planned",
                "inconsistent observed-planned internal counts",
            ),
            (
                "not-observed status with nested lines",
                "final_search", "status", "not-observed",
                "inconsistent not-observed internal counts",
            ),
            (
                "observed line-count mismatch",
                "final_search", "nested_line_count", 2,
                "inconsistent observed-planned internal counts",
            ),
        )
        for name, operation, field, value, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_result_bundle(root, run)
                self.attach_dynamic_evidence(root, run.scenarios[0])
                correctness = json.loads(
                    (root / "correctness.json").read_text()
                )
                internal = correctness["scenarios"][0][operation][
                    "isolation"
                ]["internal_server_operations"]
                internal[field] = value
                write_json(root / "correctness.json", correctness)
                with self.assertRaisesRegex(smoke.SmokeError, expected_error):
                    smoke.verify_result_bundle(root, run)

    def test_dynamic_candidate_observation_rejects_tampering(self) -> None:
        run = smoke.RunSpec(
            "dynamic", "389ds", "on", "baseline-no-presence",
            ("dynamic-list-lookthrough-finite",),
        )
        cases = (
            (
                "invented final count", "observed_final_candidate_count", 22,
                "unattributed candidate-list evidence is inconsistent",
            ),
            (
                "wrong raw count", "candidate_list_observation", {
                    "status": "not-directly-observable",
                    "reason": "nested traces",
                    "raw_trace_count": 2,
                }, "candidate-list unobservability is not documented",
            ),
            (
                "forged status", "candidate_list_status", "observed",
                "unattributed candidate-list evidence is inconsistent",
            ),
        )
        for name, field, value, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_result_bundle(root, run)
                self.attach_dynamic_evidence(root, run.scenarios[0])
                correctness = json.loads(
                    (root / "correctness.json").read_text()
                )
                diagnostics = correctness["scenarios"][0]["final_search"][
                    "diagnostics"
                ]
                diagnostics[field] = value
                write_json(root / "correctness.json", correctness)
                with self.assertRaisesRegex(smoke.SmokeError, expected_error):
                    smoke.verify_result_bundle(root, run)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_result_bundle(root, run)
            self.attach_dynamic_evidence(root, run.scenarios[0])
            correctness = json.loads((root / "correctness.json").read_text())
            diagnostics = correctness["scenarios"][0]["final_search"][
                "diagnostics"
            ]
            diagnostics["candidate_list_values"] = [777, 888]
            diagnostics["candidate_list_observation"]["raw_trace_count"] = 2
            write_json(root / "correctness.json", correctness)
            with self.assertRaisesRegex(
                    smoke.SmokeError,
                    "candidate-list traces differ from the error log"):
                smoke.verify_result_bundle(root, run)

    def test_exact_ownership_labels_are_required(self) -> None:
        expected = smoke.ownership_labels("run-123")
        self.assertTrue(smoke.labels_match(dict(expected), expected))
        changed = dict(expected)
        changed[smoke.LABEL_RUN_ID] = "some-other-run"
        self.assertFalse(smoke.labels_match(changed, expected))

    def write_merged_fixture(
            self, root: Path) -> tuple[Path, list[Path]]:
        workload = {
            "workload_id": "smoke-synthetic",
            "workload_sha256": "a" * 64,
        }
        sources: list[Path] = []
        normalized_rows = []
        source_bundles = []
        for index, spec in enumerate(smoke.RUN_SPECS):
            source = root / "runs" / spec.name
            source.mkdir(parents=True)
            run_id = f"source-{index}"
            run = {"run_id": run_id}
            artifact = {"source": run_id}
            correctness = {"source": run_id, "passed": True}
            raw_row = {
                "host_class": smoke.HOST_CLASS,
                "correctness_only": True,
                "release_timing_evidence": False,
            }
            raw = {"rows": [raw_row], "perf_batches": []}
            for name, value in (
                ("run-manifest.json", run),
                ("artifact-manifest.json", artifact),
                ("correctness.json", correctness),
                ("raw-results.json", raw),
                ("workload-manifest.json", workload),
            ):
                write_json(source / name, value)
            sources.append(source)
            normalized_rows.append({
                "run_id": run_id,
                "release_eligible": False,
                "raw": raw_row,
            })
            source_bundles.append({
                "run_id": run_id,
                "artifact_manifest_sha256": smoke.canonical_json_sha256(artifact),
                "run_manifest_sha256": smoke.canonical_json_sha256(run),
                "correctness_manifest_sha256": smoke.canonical_json_sha256(
                    correctness
                ),
                "raw_results_sha256": smoke.sha256_file(
                    source / "raw-results.json"
                ),
                "release_candidate": False,
                "disposition_reasons": ["correctness-only evidence"],
            })
        merged = root / "merged"
        merged.mkdir()
        source_ids = [record["run_id"] for record in source_bundles]
        manifest_sha = smoke.sha256_file(
            sources[0] / "workload-manifest.json"
        )
        common = {
            "status": "native-results-pending",
            "correctness_status": "pass",
            "correctness_only": True,
            "release_timing_evidence": False,
            "timing_claims_allowed": False,
            "host_class": smoke.HOST_CLASS,
            "source_host_classes": [smoke.HOST_CLASS],
            "source_run_ids": source_ids,
            "source_run_count": len(source_ids),
            "duplicate_bundle_count": 0,
            "correctness_only_evidence_present": True,
            "validation_only_evidence_present": True,
            "nonrelease_evidence_can_satisfy_performance_gates": False,
            "matrix_completion_status": "not-established-by-merger",
        }
        gates = [{
            "gate_id": gate_id,
            "status": "pass" if gate_id == "exact-result-parity" else "pending",
        } for gate_id in sorted(smoke.EXPECTED_ACCEPTANCE_GATES)]
        write_json(merged / "merged-raw-results.json", {
            **common,
            "unsafe_include_nonrelease": False,
            "rows": normalized_rows,
            "perf_batches": [],
            "release_summaries": [],
            "release_comparisons": [],
            "openldap_contextual_comparisons": [],
            "release_scaling_tables": [],
            "unsafe_nonrelease_summaries": [],
            "acceptance_gate_results": gates,
            "acceptance_gate_overall_status": "pending",
        })
        write_json(merged / "artifact-manifest.json", {
            **common,
            "acceptance_gate_overall_status": "pending",
            "workload_sha256": workload["workload_sha256"],
            "workload_manifest_sha256": manifest_sha,
            "source_bundles": source_bundles,
        })
        (merged / "RESULTS.md").write_text(
            "# Results\n\nStatus: **native-results-pending**\n\n"
            "Release authority: **native installed-RPM timing evidence only**.\n",
            encoding="utf-8",
        )
        return merged, sources

    def test_merged_verifier_proves_nonrelease_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            merged, sources = self.write_merged_fixture(Path(temporary))
            verified = smoke.verify_merged_result_bundle(merged, sources)
        self.assertEqual(verified["native_status"], "native-results-pending")
        self.assertEqual(verified["source_run_count"], 4)
        self.assertEqual(
            verified["release_array_counts"],
            {
                "release_summaries": 0,
                "release_comparisons": 0,
                "openldap_contextual_comparisons": 0,
                "release_scaling_tables": 0,
                "unsafe_nonrelease_summaries": 0,
            },
        )
        self.assertEqual(verified["release_eligible_row_count"], 0)

    def test_merged_verifier_rejects_a_release_evidence_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            merged, sources = self.write_merged_fixture(Path(temporary))
            raw_path = merged / "merged-raw-results.json"
            raw = json.loads(raw_path.read_text())
            raw["release_timing_evidence"] = True
            raw["release_summaries"] = [{"median": 1.0}]
            write_json(raw_path, raw)
            with self.assertRaisesRegex(
                    smoke.SmokeError, "release_timing_evidence.*release_summaries"):
                smoke.verify_merged_result_bundle(merged, sources)


if __name__ == "__main__":
    unittest.main()
