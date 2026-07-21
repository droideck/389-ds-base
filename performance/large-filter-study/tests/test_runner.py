"""Focused contracts for the installed-package study runner."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
import json
import hashlib

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


STUDY_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(STUDY_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDY_ROOT))

from study.platform_info import (  # noqa: E402
    StudyError,
    backend_module_roles,
    backend_runtime_module_closure,
    combined_behavioral_runtime_identity,
    metric_delta,
    native_fedora_rejection_reasons,
    process_metrics,
    rpm_source_identity_evidence,
    rpm_verify_evidence,
)
from study.run_study import (  # noqa: E402
    PERF_EVENTS,
    PROFILE_OPERATION_COUNT,
    REVISION_ROLES,
    copy_workload_payload,
    declared_schedule,
    diagnostic_flight,
    dns_digest,
    enforce_native_workload_manifest,
    finalize_perf_batch,
    link_rows_to_perf_batch,
    invocation_evidence,
    mechanism_signature_material,
    mechanism_gate,
    parse_access_result,
    parse_diagnostics,
    parse_perf_stat,
    perf_collection_identity,
    perf_start,
    perf_iteration_batches,
    profile_lookup_symbol_evidence,
    resolve_revision,
    run_approximate_semantics_preflight,
    run_dynamic_control,
    run_profile,
    verify_workload,
)
from study.revisions import (  # noqa: E402
    FINAL_PRODUCTION_REVISION,
    FINAL_STUDY_TIP_REVISION,
    PRODUCTION_EQUIVALENT_REVISIONS,
    production_equivalent_revision,
)
from study.server_runtime import (  # noqa: E402
    DS389Runtime,
    REFERRAL_CHECK_PERIOD_SECONDS,
    SearchResult,
    ServerRuntime,
    VATTR_CHECK_FILTER,
    configured_index_contract,
    file_cursor,
    internal_access_lines,
    parse_live_subschema,
    read_after_cursor,
    referral_monitor_operation_evidence,
    referral_quiet_window,
    vattr_check_operation_evidence,
    verify_study_schema_identities,
)


class WorkloadBoundaryTests(unittest.TestCase):
    @staticmethod
    def _native_manifest() -> dict[str, object]:
        return {
            "profile": "full",
            "host_intent": "native_fedora_timing",
            "correctness_only": False,
            "release_timing_evidence": True,
            "entries": 100_000,
            "entry_counts": {
                "people": 100_000,
                "principal_cohort": 612,
            },
            "primary_contract": {
                "people": 100_000,
                "logical_outer_cohort": 612,
                "dn_branches": 355,
            },
            "scenarios": {
                "principal-with-sdn2-equality": {
                    "logical_outer_cohort_count": 612,
                    "expected_lookup_diagnostic": {
                        "largest_family": 355,
                    },
                },
            },
        }

    def test_native_manifest_requires_the_exact_full_contract(self) -> None:
        manifest = self._native_manifest()
        enforce_native_workload_manifest(manifest)
        manifest["entries"] = 99_999
        with self.assertRaisesRegex(StudyError, "exact full workload"):
            enforce_native_workload_manifest(manifest)

    def test_runner_executes_a_verified_copied_workload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            copied = root / "result" / "workload"
            (source / "filters").mkdir(parents=True)
            payload = source / "filters" / "case.filter"
            payload.write_text("(uid=case)\n", encoding="utf-8")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            manifest = {
                "format_version": 1,
                "files": {"filters/case.filter": digest},
                "entry_counts": {"people": 1, "principal_cohort": 1},
                "dataset_import_oracles": {
                    key: {
                        "expected_result_code": "LDAP_SUCCESS",
                        "expected_count": 1,
                        "expected_sha256": "0" * 64,
                    }
                    for key in ("people", "principal_outer_cohort")
                },
                "scenarios": {"case": {}},
            }
            (source / "workload-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            verified = verify_workload(source)
            copy_workload_payload(source, verified, copied)
            self.assertEqual(verify_workload(copied), verified)
            self.assertTrue((copied / "workload-manifest.json").is_file())

            payload.write_text("(uid=changed)\n", encoding="utf-8")
            self.assertEqual(
                (copied / "filters" / "case.filter").read_text(
                    encoding="utf-8"
                ),
                "(uid=case)\n",
            )


class ApproximateSemanticsTests(unittest.TestCase):
    class _Runtime:
        implementation = "389ds"

        def __init__(self, results: list[SearchResult]) -> None:
            self.results = results

        def search_with_isolated_diagnostics(
                self, **_search: object
        ) -> tuple[SearchResult, dict[str, str], dict[str, object]]:
            result = self.results.pop(0)
            access = (
                "conn=1 op=1 RESULT err="
                f"{result.returncode} tag=101 nentries={len(result.dns)} "
                "etime=0.001\n"
            )
            return result, {"access": access, "error": ""}, {
                "operation_count": 1,
                "cursor": {},
            }

    @staticmethod
    def _manifest() -> tuple[dict[str, object], str]:
        base_dn = "uid=probe,ou=people,dc=example,dc=com"
        contract = {
            "version": 1,
            "attribute": "sApprox",
            "oracle": "casefolded-alphanumeric-identical-token",
            "positive_assertion": "xanadu approximate common",
            "negative_assertion": "definitely dissimilar token 98f221",
            "scope": "base",
        }
        contract_hash = hashlib.sha256(json.dumps(
            contract, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        probes = {
            "positive-identical-token": {
                "base_dn": base_dn,
                "scope": "base",
                "filter": "(sApprox~=xanadu approximate common)",
                "requested_attributes": ["1.1"],
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 1,
                "expected_sha256": dns_digest([base_dn]),
            },
            "negative-dissimilar-token": {
                "base_dn": base_dn,
                "scope": "base",
                "filter": "(sApprox~=definitely dissimilar token 98f221)",
                "requested_attributes": ["1.1"],
                "expected_result_code": "LDAP_SUCCESS",
                "expected_count": 0,
                "expected_sha256": dns_digest([]),
            },
        }
        policy = {
            "policy": "requires-native-equivalence-preflight",
            "default_eligibility": "excluded",
            "semantic_contract": contract,
            "contract_sha256": contract_hash,
            "required_probe_ids": list(probes),
            "probes": probes,
        }
        return {
            "scenarios": {
                "approximate": {"cross_server_comparison": policy},
            },
        }, base_dn

    def test_direct_approximate_probes_establish_comparable_evidence(self) -> None:
        manifest, base_dn = self._manifest()
        runtime = self._Runtime([
            SearchResult(0, "", "", [base_dn]),
            SearchResult(0, "", "", []),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            evidence = run_approximate_semantics_preflight(
                runtime=runtime,
                manifest=manifest,
                selected=["approximate"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        self.assertEqual(evidence["status"], "comparable")
        self.assertEqual(len(evidence["probes"]), 2)
        self.assertTrue(all(probe["passed"] for probe in evidence["probes"]))
        self.assertTrue(all(
            probe["exact_result"]["evidence_status"] == "observed"
            for probe in evidence["probes"]
        ))

    def test_failed_negative_probe_is_unverified_not_comparable(self) -> None:
        manifest, base_dn = self._manifest()
        runtime = self._Runtime([
            SearchResult(0, "", "", [base_dn]),
            SearchResult(0, "", "", [base_dn]),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            evidence = run_approximate_semantics_preflight(
                runtime=runtime,
                manifest=manifest,
                selected=["approximate"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        self.assertEqual(evidence["status"], "unverified")
        self.assertFalse(evidence["probes"][1]["passed"])


class DiagnosticTests(unittest.TestCase):
    def test_mechanism_signature_preserves_duplicate_log_observations(self) -> None:
        selected = {
            "status": "not-requested",
            "selected_attribute": None,
        }
        access = {"server_notes": "", "server_result_code": 0}
        first = mechanism_signature_material(
            {
                "lookup_summaries": [
                    {"node_count": 2, "largest_family": 355},
                    {"node_count": 2, "largest_family": 355},
                ],
                "cap_values": [612, 612],
                "candidate_list_values": [0, 0],
            },
            selected,
            access,
        )
        second = mechanism_signature_material(
            {
                "lookup_summaries": [
                    {"node_count": 2, "largest_family": 355},
                ],
                "cap_values": [612],
                "candidate_list_values": [0],
            },
            selected,
            access,
        )
        self.assertNotEqual(first, second)
        self.assertEqual(len(first["lookup_summaries"]), 2)
        self.assertEqual(first["cap_values"], [612, 612])
        self.assertEqual(first["candidate_list_values"], [0, 0])
        distinct = mechanism_signature_material(
            {
                "lookup_summaries": [
                    {"node_count": 2, "largest_family": 355},
                ],
                "cap_values": [612],
                "candidate_list_values": [0, 20],
            },
            selected,
            access,
        )
        self.assertNotEqual(first, distinct)

    def test_existing_production_diagnostics_are_parsed_without_substitution(self) -> None:
        error = """
OR filter equality lookup engaged: 368 node(s), largest 355 branches
Candidate list has 612 ids
costly AND component returned ALLIDS under read cap 612 - relying on the other components and the filter test
"""
        access = (
            "STAT read index: attribute=sSub key(sub)=xanadu --> count 10000 "
            "(duration 0.001234)\n"
        )
        parsed = parse_diagnostics(error, access)
        self.assertEqual(parsed["observed_final_candidate_count"], 612)
        self.assertEqual(parsed["lookup_summaries"][0]["largest_family"], 355)
        self.assertTrue(parsed["cap_path_observed"])
        self.assertEqual(parsed["stat_index_reads"][0]["attribute"], "sSub")

    def test_multiple_candidate_traces_remain_ambiguous_and_unsubstituted(self) -> None:
        parsed = parse_diagnostics(
            "Candidate list has 20 ids\n"
            "Candidate list has 22 ids\n"
            "Candidate list has 1 ids\n",
            "",
        )
        self.assertEqual(parsed["candidate_list_values"], [20, 22, 1])
        self.assertEqual(
            parsed["candidate_list_status"], "ambiguous-multiple-traces"
        )
        self.assertIsNone(parsed["observed_final_candidate_count"])

    def test_mechanism_gate_rejects_multiple_candidate_traces_by_default(self) -> None:
        scenario = {
            "groups": [],
            "expected_result_code": "LDAP_SUCCESS",
            "expected_diagnostics": {
                "or_lookup": {"expectation": "not-applicable"},
                "bounded_read": {"expectation": "not-applicable"},
            },
        }
        diagnostics = {
            "lookup_constructed": False,
            "lookup_summaries": [],
            "cap_path_observed": False,
            "candidate_list_status": "ambiguous-multiple-traces",
            "access_result": {"server_notes": "", "server_result_code": 0},
        }
        failures = mechanism_gate(
            server="389ds",
            revision=REVISION_ROLES["final"],
            lookup_mode="on",
            scenario=scenario,
            diagnostics=diagnostics,
        )
        self.assertIn(
            "multiple candidate-list traces make the diagnostic flight ambiguous",
            failures,
        )

    def test_mechanism_gate_does_not_predict_presence_notes(self) -> None:
        for variant, simple_sdn2 in (
                ("baseline-no-presence", True),
                ("baseline-no-presence", False),
                ("presence-sdn1", True),
                ("presence-sdn2", True),
                ("presence-both", True),
                ("presence-both", False)):
            scenario = {
                "groups": ["presence-index"],
                "index_variant": variant,
                "simple_sdn2_branch": simple_sdn2,
                "expected_diagnostics": {
                    "or_lookup": {
                        "expectation": "required-when-lookup-on",
                        "largest_family": 355,
                    },
                    "bounded_read": {"expectation": "required"},
                },
            }
            for notes in ("", "U"):
                diagnostics = {
                    "lookup_constructed": True,
                    "lookup_summaries": [
                        {"node_count": 368, "largest_family": 355}
                    ],
                    "cap_path_observed": True,
                    "access_result": {
                        "server_notes": notes,
                        "server_result_code": 0,
                    },
                }
                with self.subTest(
                        variant=variant, simple_sdn2=simple_sdn2, notes=notes):
                    self.assertEqual(
                        mechanism_gate(
                            server="389ds",
                            revision=(
                                "e0161d0e61d0cdef22175418f0d4a1e126216a86"
                            ),
                            lookup_mode="on",
                            scenario=scenario,
                            diagnostics=diagnostics,
                        ),
                        [],
                    )

    def test_mechanism_gate_rejects_intentional_decline_diagnostics(self) -> None:
        scenario = {
            "groups": ["decline-paths"],
            "index_variant": "baseline-no-presence",
            "expected_diagnostics": {
                "or_lookup": {
                    "expectation": "forbidden-valid-family-below-threshold",
                },
                "bounded_read": {
                    "expectation": "forbidden-selective-posting",
                },
            },
        }
        failures = mechanism_gate(
            server="389ds",
            revision="e0161d0e61d0cdef22175418f0d4a1e126216a86",
            lookup_mode="on",
            scenario=scenario,
            diagnostics={
                "lookup_constructed": True,
                "lookup_summaries": [{"node_count": 2, "largest_family": 16}],
                "cap_path_observed": True,
                "access_result": {"server_notes": "", "server_result_code": 0},
            },
        )
        self.assertTrue(any("below-threshold" in failure for failure in failures))
        self.assertTrue(any("bounded-read cap" in failure for failure in failures))


class DiagnosticFlightTests(unittest.TestCase):
    class _Runtime:
        implementation = "389ds"
        actual_lookup_mode = "on"

        def __init__(
                self,
                operations: list[tuple[SearchResult, dict[str, str]]]) -> None:
            self.operations = operations
            self.filter_trace_requests: list[bool] = []

        def diagnostics_enable(self, *, filter_trace: bool = False) -> object:
            self.filter_trace_requests.append(filter_trace)
            return object()

        def diagnostics_restore(self, _state: object) -> None:
            return None

        def search_with_isolated_diagnostics(
                self, **_search: object
        ) -> tuple[SearchResult, dict[str, str], dict[str, object]]:
            result, window = self.operations.pop(0)
            return result, window, {"operation_count": 1, "cursor": {}}

    @staticmethod
    def _access(count: int, code: int = 0) -> str:
        return (
            "[20/Jul/2026:12:00:00] conn=1 op=1 RESULT err="
            f"{code} tag=101 nentries={count} etime=0.001\n"
        )

    @staticmethod
    def _scenario(probe_dn: str, selected: str = "sString2") -> dict[str, object]:
        return {
            "base_dn": "ou=people,dc=example,dc=com",
            "scope": "sub",
            "groups": ["family-ranking"],
            "expected_result_code": "LDAP_SUCCESS",
            "requested_attributes": ["1.1"],
            "selection_probe": {
                "base_dn": probe_dn,
                "scope": "base",
                "expected_count": 1,
                "expected_sha256": dns_digest([probe_dn]),
            },
            "expected_diagnostics": {
                "or_lookup": {
                    "expectation": "required-when-lookup-on",
                    "largest_family": 64,
                    "selected_attribute": selected,
                },
                "bounded_read": {"expectation": "not-applicable"},
            },
        }

    def _run(self, *, revision: str, probe_attribute: str) -> dict[str, object]:
        expected = ["uid=match,ou=people,dc=example,dc=com"]
        probe_dn = "uid=probe,ou=people,dc=example,dc=com"
        runtime = self._Runtime([
            (
                SearchResult(0, "", "", expected),
                {
                    "error": (
                        "OR filter equality lookup engaged: 80 node(s), "
                        "largest 64 branches\n"
                    ),
                    "access": self._access(1),
                },
            ),
            (
                SearchResult(0, "", "", [probe_dn]),
                {
                    "error": f"=> AVA: {probe_attribute}=probe-value\n",
                    "access": self._access(1),
                },
            ),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            result = diagnostic_flight(
                runtime=runtime,
                scenario_id="flat-family-ranking-a16-b64",
                scenario=self._scenario(probe_dn),
                filter_text="(|(sString1=a)(sString2=b))",
                expected=expected,
                expected_hash=dns_digest(expected),
                revision=revision,
                diagnostic_dir=Path(temporary) / "diagnostics",
                phase="preflight",
            )
            self.assertTrue(all(
                not Path(value).is_absolute()
                for key, value in result["diagnostic_artifacts"].items()
                if key.endswith("_log")
            ))
        self.assertEqual(runtime.filter_trace_requests, [False, True])
        return result

    def test_selection_is_derived_only_from_isolated_filter_ava_probe(self) -> None:
        result = self._run(
            revision=REVISION_ROLES["final"],
            probe_attribute="sString2",
        )
        self.assertTrue(result["timing_eligible"])
        self.assertEqual(
            result["direct_selected_family_evidence"]["selected_attribute"],
            "sstring2",
        )
        self.assertEqual(
            result["selection_probe"]["server_result_evidence"]["evidence_status"],
            "observed",
        )

    def test_historical_ranking_mismatch_is_preserved_and_timed(self) -> None:
        result = self._run(
            revision=REVISION_ROLES["combined-diagnostic"],
            probe_attribute="sString1",
        )
        self.assertTrue(result["timing_eligible"])
        self.assertEqual(
            result["mechanism_gate"]["status"],
            "expected-historical-mismatch",
        )
        self.assertTrue(result["mechanism_gate"]["failures"])

    def test_historical_ranking_unexpected_pass_is_rejected(self) -> None:
        with self.assertRaisesRegex(
                StudyError, "unexpectedly passed.*historical"):
            self._run(
                revision=REVISION_ROLES["combined-diagnostic"],
                probe_attribute="sString2",
            )

    def test_final_ranking_mismatch_is_a_hard_failure(self) -> None:
        with self.assertRaisesRegex(StudyError, "FILTER AVA probe"):
            self._run(
                revision=REVISION_ROLES["final"],
                probe_attribute="sString1",
            )


class PerfTests(unittest.TestCase):
    class _Process:
        def __init__(self, poll_result: int | None, stderr: str = "") -> None:
            self.poll_result = poll_result
            self.returncode = 1 if poll_result is not None else None
            self.stderr = stderr

        def poll(self) -> int | None:
            return self.poll_result

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            return "", self.stderr

        def send_signal(self, _signal: int) -> None:
            return None

        def kill(self) -> None:
            return None

    def test_perf_auto_falls_back_to_software_task_clock(self) -> None:
        failed = self._Process(1, "instructions event is not supported")
        running = self._Process(None)
        commands: list[list[str]] = []

        def start(command: list[str], **_kwargs: object) -> object:
            commands.append(command)
            return failed if len(commands) == 1 else running

        with (
                tempfile.TemporaryDirectory() as temporary,
                patch("study.run_study.command_path", return_value="/usr/bin/perf"),
                patch("study.run_study.subprocess.Popen", side_effect=start),
                patch("study.run_study.time.sleep")):
            process, metadata = perf_start(
                123, Path(temporary) / "perf.csv", required=False,
            )
        self.assertIs(process, running)
        self.assertEqual(metadata["events"], ["task-clock"])
        self.assertTrue(metadata["software_fallback"])
        self.assertEqual(metadata["hardware_events_unavailable"], PERF_EVENTS)
        self.assertIn("instructions", commands[0][commands[0].index("-e") + 1])
        self.assertEqual(
            commands[1][commands[1].index("-e") + 1], "task-clock",
        )

    def test_perf_csv_counts_and_unavailable_events_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "perf.csv"
            path.write_text(
                "120000,,instructions,100.00,100.00,,\n"
                "60000,,cycles:u,100.00,100.00,,\n"
                "1.61,msec,task-clock,100.00,100.00,,\n"
                "<not supported>,,cache-misses,0.00,0.00,,\n",
                encoding="utf-8",
            )
            parsed = parse_perf_stat(path)
        self.assertEqual(parsed["event_counts"]["instructions"], 120000)
        self.assertEqual(parsed["event_counts"]["cycles"], 60000)
        self.assertEqual(parsed["event_counts"]["task-clock"], 1.61)
        self.assertEqual(parsed["event_units"]["task-clock"], "msec")
        self.assertEqual(parsed["unavailable_events"], ["cache-misses"])
        self.assertTrue(set(parsed["event_counts"]).issubset(
            PERF_EVENTS + ["task-clock"],
        ))

    def test_runner_perf_batches_contain_exactly_one_measured_search(self) -> None:
        batches = perf_iteration_batches(12)
        self.assertEqual(
            [list(batch) for batch in batches],
            [[iteration] for iteration in range(1, 13)],
        )

    def test_perf_batch_normalizes_once_and_rows_only_reference_batch(self) -> None:
        before = {
            "schedstat_runtime_ns": 1_000_000_000,
            "schedstat_task_count": 4,
            "schedstat_complete": True,
            "clock_ticks_per_second": 100,
            "user_cpu_seconds": 1.0,
            "system_cpu_seconds": 0.5,
            "user_cpu_ticks": 100,
            "system_cpu_ticks": 50,
        }
        after = {
            "schedstat_runtime_ns": 2_000_000_000,
            "schedstat_task_count": 4,
            "schedstat_complete": True,
            "clock_ticks_per_second": 100,
            "user_cpu_seconds": 1.7,
            "system_cpu_seconds": 0.8,
            "user_cpu_ticks": 170,
            "system_cpu_ticks": 80,
            "rss_kib": 123,
            "high_water_kib": 456,
        }
        metadata = finalize_perf_batch(
            {
                "status": "observed",
                "event_counts": {event: 500 for event in PERF_EVENTS},
                "unavailable_events": [],
                "parse_warnings": [],
            },
            operation_count=5,
            cpu_before=before,
            cpu_after=after,
            required=True,
        )
        self.assertEqual(metadata["event_counts_per_search"]["instructions"], 100)
        self.assertEqual(metadata["server_cpu_seconds"], 1.0)
        self.assertEqual(metadata["server_cpu_seconds_per_search"], 0.2)
        rows = [{"row_id": "one"}, {"row_id": "two"}]
        link_rows_to_perf_batch(rows, "batch-1", {
            "collection_class": "hardware-events",
            "collection_signature": "a" * 64,
        })
        self.assertEqual([row["perf_batch_id"] for row in rows], ["batch-1"] * 2)
        self.assertTrue(all(
            row["perf_collection_class"] == "hardware-events"
            and row["perf_collection_signature"] == "a" * 64
            for row in rows
        ))
        self.assertTrue(all("instructions" not in row for row in rows))
        self.assertTrue(all("event_counts_per_search" not in row for row in rows))

    def test_required_perf_rejects_incomplete_counters_after_collection(self) -> None:
        snapshot = {
            "schedstat_runtime_ns": 1,
            "schedstat_task_count": 1,
            "schedstat_complete": True,
            "clock_ticks_per_second": 100,
            "user_cpu_seconds": 0.0,
            "system_cpu_seconds": 0.0,
            "user_cpu_ticks": 0,
            "system_cpu_ticks": 0,
        }
        with self.assertRaisesRegex(StudyError, "missing counters"):
            finalize_perf_batch(
                {
                    "status": "observed",
                    "event_counts": {"instructions": 10},
                    "unavailable_events": [],
                    "parse_warnings": [],
                },
                operation_count=1,
                cpu_before=snapshot,
                cpu_after=snapshot,
                required=True,
            )

    def test_hardware_perf_identity_requires_complete_clean_counts(self) -> None:
        complete = {
            "status": "observed",
            "events": list(PERF_EVENTS),
            "software_fallback": False,
            "event_counts": {
                event: index + 1 for index, event in enumerate(PERF_EVENTS)
            },
            "unavailable_events": [],
            "parse_warnings": [],
        }
        identity = perf_collection_identity(complete)
        self.assertEqual(identity["collection_class"], "hardware-events")

        incomplete_cases = {
            "missing count": {
                **complete,
                "event_counts": {
                    event: 1 for event in PERF_EVENTS if event != "instructions"
                },
            },
            "missing count proof": {
                key: value for key, value in complete.items()
                if key != "event_counts"
            },
            "invalid count": {
                **complete,
                "event_counts": {
                    **complete["event_counts"], "cycles": float("nan")
                },
            },
            "unexpected count": {
                **complete,
                "event_counts": {**complete["event_counts"], "task-clock": 1.0},
            },
            "unavailable event": {
                **complete,
                "unavailable_events": ["branch-misses"],
            },
            "missing availability proof": {
                key: value for key, value in complete.items()
                if key != "unavailable_events"
            },
            "parse warning": {
                **complete,
                "parse_warnings": ["line 2: invalid count"],
            },
            "missing parser proof": {
                key: value for key, value in complete.items()
                if key != "parse_warnings"
            },
        }
        for label, metadata in incomplete_cases.items():
            with self.subTest(label=label):
                self.assertEqual(
                    perf_collection_identity(metadata)["collection_class"],
                    "hardware-events-incomplete",
                )

    def test_hardware_perf_identity_signature_ignores_counter_magnitude(self) -> None:
        def identity(multiplier: int) -> dict[str, str]:
            return perf_collection_identity({
                "status": "observed",
                "events": list(PERF_EVENTS),
                "software_fallback": False,
                "event_counts": {
                    event: multiplier * (index + 1)
                    for index, event in enumerate(PERF_EVENTS)
                },
                "unavailable_events": [],
                "parse_warnings": [],
            })

        self.assertEqual(identity(1), identity(10_000))


class ProcessCpuTests(unittest.TestCase):
    def test_schedstat_sums_all_threads_and_ticks_remain_audit_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc_root = Path(temporary)
            process = proc_root / "42"
            (process / "task" / "42").mkdir(parents=True)
            (process / "task" / "77").mkdir()
            stat_fields = ["S"] + ["0"] * 10 + ["12", "7"]
            (process / "stat").write_text(
                "42 (ns-slapd worker) " + " ".join(stat_fields) + "\n",
                encoding="ascii",
            )
            (process / "status").write_text(
                "VmRSS: 123 kB\nVmHWM: 456 kB\n", encoding="ascii",
            )
            (process / "task" / "42" / "schedstat").write_text(
                "100 0 1\n", encoding="ascii",
            )
            (process / "task" / "77" / "schedstat").write_text(
                "250 0 2\n", encoding="ascii",
            )
            metrics = process_metrics(42, proc_root=proc_root)
        self.assertEqual(metrics["schedstat_runtime_ns"], 350)
        self.assertEqual(metrics["schedstat_task_count"], 2)
        self.assertTrue(metrics["schedstat_complete"])
        self.assertEqual(metrics["user_cpu_ticks"], 12)
        self.assertEqual(metrics["system_cpu_ticks"], 7)
        self.assertEqual(metrics["rss_kib"], 123)

    def test_metric_delta_prefers_nanosecond_whole_process_clock(self) -> None:
        before = {
            "schedstat_runtime_ns": 2_000_000_000,
            "schedstat_task_count": 2,
            "schedstat_complete": True,
            "clock_ticks_per_second": 100,
            "user_cpu_seconds": 2.0,
            "system_cpu_seconds": 1.0,
            "user_cpu_ticks": 200,
            "system_cpu_ticks": 100,
        }
        after = {
            **before,
            "schedstat_runtime_ns": 2_123_456_789,
            "user_cpu_seconds": 2.1,
            "user_cpu_ticks": 210,
            "rss_kib": 1,
            "high_water_kib": 2,
        }
        delta = metric_delta(before, after)
        self.assertEqual(delta["server_cpu_ns"], 123_456_789)
        self.assertAlmostEqual(delta["server_cpu_seconds"], 0.123456789)
        self.assertEqual(delta["user_cpu_ticks"], 10)
        self.assertEqual(delta["system_cpu_ticks"], 0)


class ProfileTests(unittest.TestCase):
    class _Process:
        def __init__(
                self, events: list[str] | None = None,
                *, poll_result: int | None = None) -> None:
            self.events = events
            self.poll_result = poll_result
            self.returncode = 0 if poll_result is None else poll_result

        def poll(self) -> int | None:
            if self.events is not None:
                self.events.append("perf-poll")
            return self.poll_result

        def send_signal(self, _signal: int) -> None:
            if self.events is not None:
                self.events.append("perf-stop")
            return None

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            if self.events is not None:
                self.events.append("perf-communicate")
            return "", ""

        def kill(self) -> None:
            if self.events is not None:
                self.events.append("perf-kill")
            return None

    class _Runtime:
        pid = 123
        implementation = "389ds"
        actual_lookup_mode = "on"

        def __init__(
                self, dns: list[str], events: list[str] | None = None,
                *, finish_error: str | None = None) -> None:
            self.dns = dns
            self.events = events
            self.finish_error = finish_error

        def begin_background_quiet_collection(
                self, context: str) -> dict[str, object]:
            if self.events is not None:
                self.events.append("guard-begin")
            return {
                "status": "started",
                "context": context,
                "passed": False,
            }

        def finish_background_quiet_collection(
                self, evidence: dict[str, object]) -> dict[str, object]:
            if self.events is not None:
                self.events.append("guard-finish")
            if self.finish_error is not None:
                raise StudyError(self.finish_error)
            return {**evidence, "status": "passed", "passed": True}

        def background_quiet_not_applicable(
                self, context: str, reason: str) -> dict[str, object]:
            return {
                "status": "not-applicable",
                "context": context,
                "reason": reason,
                "passed": True,
            }

        def search_with_isolated_diagnostics(
                self, **_kwargs: object
        ) -> tuple[SimpleNamespace, dict[str, str], dict[str, object]]:
            if self.events is not None:
                self.events.append("search")
            result = SimpleNamespace(returncode=0, dns=self.dns, stderr="")
            access = (
                "conn=1 op=1 RESULT err=0 tag=101 "
                f"nentries={len(self.dns)} etime=0.001\n"
            )
            return result, {"access": access, "error": ""}, {
                "operation_count": 1,
                "cursor": {},
            }

    def test_disabled_and_unavailable_profiles_record_zero_operations(
            self) -> None:
        scenario = {
            "base_dn": "dc=example,dc=com",
            "expected_result_code": "LDAP_SUCCESS",
        }
        runtime = self._Runtime([])
        disabled = run_profile(
            runtime, "case", scenario, "(uid=*)", Path("unused"), False,
            [], dns_digest([]),
        )
        self.assertEqual(disabled["status"], "disabled")
        self.assertEqual(disabled["operation_count"], 0)
        self.assertEqual(disabled["operations"], [])

        runtime.pid = None
        no_pid = run_profile(
            runtime, "case", scenario, "(uid=*)", Path("unused"), True,
            [], dns_digest([]),
        )
        self.assertEqual(no_pid["status"], "unavailable")
        self.assertEqual(no_pid["operation_count"], 0)
        self.assertEqual(no_pid["operations"], [])

        runtime.pid = 123
        with patch("study.run_study.command_path", return_value=None):
            no_perf = run_profile(
                runtime, "case", scenario, "(uid=*)", Path("unused"), True,
                [], dns_digest([]),
            )
        self.assertEqual(no_perf["status"], "unavailable")
        self.assertEqual(no_perf["operation_count"], 0)
        self.assertEqual(no_perf["operations"], [])

    def test_each_profile_operation_must_pass_exact_oracle(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]

        class ChangingRuntime(self._Runtime):
            def __init__(self) -> None:
                super().__init__(expected)
                self.search_count = 0

            def search_with_isolated_diagnostics(
                    self, **kwargs: object
            ) -> tuple[SimpleNamespace, dict[str, str], dict[str, object]]:
                self.search_count += 1
                if self.search_count == 7:
                    self.dns = ["uid=wrong,dc=example,dc=com"]
                return super().search_with_isolated_diagnostics(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            output.write_bytes(b"perf data")
            with (
                    patch(
                        "study.run_study.command_path",
                        return_value="/usr/bin/perf",
                    ),
                    patch(
                        "study.run_study.subprocess.Popen",
                        return_value=self._Process(),
                    ),
                    patch("study.run_study.time.sleep")):
                with self.assertRaisesRegex(
                        StudyError, "profile operation 7: exact DN mismatch"):
                    run_profile(
                        ChangingRuntime(), "case", {
                            "base_dn": "dc=example,dc=com",
                            "expected_result_code": "LDAP_SUCCESS",
                        },
                        "(uid=*)", output, True,
                        expected, dns_digest(expected),
                    )

    def test_each_profile_operation_requires_one_server_result(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]

        class DuplicateResultRuntime(self._Runtime):
            def __init__(self) -> None:
                super().__init__(expected)
                self.search_count = 0

            def search_with_isolated_diagnostics(
                    self, **kwargs: object
            ) -> tuple[SimpleNamespace, dict[str, str], dict[str, object]]:
                self.search_count += 1
                result, window, isolation = (
                    super().search_with_isolated_diagnostics(**kwargs)
                )
                if self.search_count == 7:
                    window["access"] += window["access"]
                return result, window, isolation

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            output.write_bytes(b"perf data")
            with (
                    patch(
                        "study.run_study.command_path",
                        return_value="/usr/bin/perf",
                    ),
                    patch(
                        "study.run_study.subprocess.Popen",
                        return_value=self._Process(),
                    ),
                    patch("study.run_study.time.sleep")):
                with self.assertRaisesRegex(
                        StudyError,
                        "profile operation 7: isolated access-log window "
                        "contains 2 result records"):
                    run_profile(
                        DuplicateResultRuntime(), "case", {
                            "base_dn": "dc=example,dc=com",
                            "expected_result_code": "LDAP_SUCCESS",
                        },
                        "(uid=*)", output, True,
                        expected, dns_digest(expected),
                    )

    def test_profiled_search_must_pass_exact_oracle(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            output.write_bytes(b"perf data")
            with (
                    patch("study.run_study.command_path", return_value="/usr/bin/perf"),
                    patch("study.run_study.subprocess.Popen", return_value=self._Process()),
                    patch("study.run_study.time.sleep"),
                    patch(
                        "study.run_study.run_command",
                        return_value=SimpleNamespace(
                            returncode=0, stdout="report", stderr="",
                        ),
                    )):
                with self.assertRaisesRegex(StudyError, "exact DN mismatch"):
                    run_profile(
                        self._Runtime(["uid=wrong,dc=example,dc=com"]),
                        "case", {
                            "base_dn": "dc=example,dc=com",
                            "expected_result_code": "LDAP_SUCCESS",
                        },
                        "(uid=*)", output, True,
                        expected, dns_digest(expected),
                    )

    def test_required_profile_rejects_report_failure(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            output.write_bytes(b"perf data")
            with (
                    patch("study.run_study.command_path", return_value="/usr/bin/perf"),
                    patch("study.run_study.subprocess.Popen", return_value=self._Process()),
                    patch("study.run_study.time.sleep"),
                    patch(
                        "study.run_study.run_command",
                        return_value=SimpleNamespace(
                            returncode=1, stdout="", stderr="report failed",
                        ),
                    )):
                with self.assertRaisesRegex(StudyError, "perf report status failed"):
                    run_profile(
                        self._Runtime(expected),
                        "case", {
                            "base_dn": "dc=example,dc=com",
                            "expected_result_code": "LDAP_SUCCESS",
                        },
                        "(uid=*)", output, True,
                        expected, dns_digest(expected), required=True,
                    )

    def test_required_profile_rejects_unavailable_perf(self) -> None:
        with patch("study.run_study.command_path", return_value=None):
            with self.assertRaisesRegex(StudyError, "perf is missing"):
                run_profile(
                    self._Runtime([]), "case", {
                        "base_dn": "dc=example,dc=com",
                        "expected_result_code": "LDAP_SUCCESS",
                    },
                    "(uid=*)", Path("unused"), True, [], dns_digest([]),
                    required=True,
                )

    def test_profile_artifacts_are_portable_hashed_and_symbol_annotated(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            output = bundle / "profiles" / "case.perf.data"
            output.parent.mkdir()
            output.write_bytes(b"perf data")
            with (
                    patch("study.run_study.command_path", return_value="/usr/bin/perf"),
                    patch("study.run_study.subprocess.Popen", return_value=self._Process()),
                    patch("study.run_study.time.sleep"),
                    patch(
                        "study.run_study.run_command",
                        return_value=SimpleNamespace(
                            returncode=0,
                            stdout=(
                                "10.00% ns-slapd "
                                "vattr_test_filter_or_lookup\n"
                            ),
                            stderr="",
                        ),
                    )):
                profile = run_profile(
                    self._Runtime(expected),
                    "case", {
                        "base_dn": "dc=example,dc=com",
                        "expected_result_code": "LDAP_SUCCESS",
                    },
                    "(uid=*)", output, True,
                    expected, dns_digest(expected), required=True,
                    bundle_root=bundle,
                )
        self.assertEqual(profile["status"], "observed")
        self.assertEqual(profile["path"], "profiles/case.perf.data")
        self.assertEqual(len(profile["profile_artifact"]["sha256"]), 64)
        self.assertEqual(
            profile["report"]["path"],
            "profiles/case.perf.data.report.txt",
        )
        self.assertEqual(len(profile["report"]["sha256"]), 64)
        self.assertEqual(profile["lookup_consumption"]["status"], "consumed")
        self.assertEqual(profile["operation_count"], PROFILE_OPERATION_COUNT)
        self.assertEqual(len(profile["operations"]), PROFILE_OPERATION_COUNT)
        self.assertEqual(
            [operation["operation_index"] for operation in profile["operations"]],
            list(range(1, PROFILE_OPERATION_COUNT + 1)),
        )
        self.assertTrue(all(
            operation["exact_result"]["passed"]
            and operation["server_result_evidence"]["passed"]
            and operation["access_result"]["result_line_count"] == 1
            for operation in profile["operations"]
        ))
        self.assertEqual(profile["actual_client_result_code"], 0)
        self.assertEqual(profile["actual_server_result_code"], 0)
        self.assertTrue(profile["background_quiet_window"]["passed"])

    def test_profile_guard_covers_perf_startup_failure(self) -> None:
        events: list[str] = []
        runtime = self._Runtime([], events)
        process = self._Process(events, poll_result=1)
        with tempfile.TemporaryDirectory() as temporary:
            with (
                    patch(
                        "study.run_study.command_path",
                        return_value="/usr/bin/perf",
                    ),
                    patch(
                        "study.run_study.subprocess.Popen",
                        side_effect=lambda *_args, **_kwargs: (
                            events.append("perf-start") or process
                        ),
                    ),
                    patch("study.run_study.time.sleep")):
                profile = run_profile(
                    runtime,
                    "case",
                    {
                        "base_dn": "dc=example,dc=com",
                        "expected_result_code": "LDAP_SUCCESS",
                    },
                    "(uid=*)",
                    Path(temporary) / "profile.data",
                    True,
                    [],
                    dns_digest([]),
                )
        self.assertEqual(profile["status"], "unavailable")
        self.assertEqual(profile["operation_count"], 0)
        self.assertEqual(profile["operations"], [])
        self.assertEqual(
            events,
            [
                "guard-begin",
                "perf-start",
                "perf-poll",
                "perf-communicate",
                "perf-start",
                "perf-poll",
                "perf-communicate",
                "guard-finish",
            ],
        )

    def test_profile_falls_back_to_software_cpu_clock(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]
        failed = self._Process(poll_result=1)
        running = self._Process()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            starts = 0

            def start(*_args: object, **_kwargs: object) -> object:
                nonlocal starts
                starts += 1
                if starts == 1:
                    return failed
                output.write_bytes(b"software perf data")
                return running

            with (
                    patch("study.run_study.command_path", return_value="/usr/bin/perf"),
                    patch("study.run_study.subprocess.Popen", side_effect=start),
                    patch("study.run_study.time.sleep"),
                    patch(
                        "study.run_study.run_command",
                        return_value=SimpleNamespace(
                            returncode=0,
                            stdout="vattr_test_filter_or_lookup\n",
                            stderr="",
                        ),
                    )):
                profile = run_profile(
                    self._Runtime(expected),
                    "case",
                    {
                        "base_dn": "dc=example,dc=com",
                        "expected_result_code": "LDAP_SUCCESS",
                    },
                    "(uid=*)", output, True,
                    expected, dns_digest(expected), required=True,
                )
        self.assertEqual(profile["status"], "observed")
        self.assertEqual(profile["sampling_event"], "cpu-clock")
        self.assertTrue(profile["software_fallback"])
        self.assertEqual(len(profile["record_attempts"]), 1)

    def test_profile_guard_is_sealed_after_perf_stop(self) -> None:
        expected = ["uid=expected,dc=example,dc=com"]
        events: list[str] = []
        runtime = self._Runtime(
            expected,
            events,
            finish_error="profile crossed quiet-window boundary",
        )
        process = self._Process(events)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.data"
            output.write_bytes(b"perf data")
            with (
                    patch(
                        "study.run_study.command_path",
                        return_value="/usr/bin/perf",
                    ),
                    patch(
                        "study.run_study.subprocess.Popen",
                        side_effect=lambda *_args, **_kwargs: (
                            events.append("perf-start") or process
                        ),
                    ),
                    patch("study.run_study.time.sleep"),
                    patch("study.run_study.run_command") as report):
                with self.assertRaisesRegex(
                        StudyError, "crossed quiet-window boundary"):
                    run_profile(
                        runtime,
                        "case",
                        {
                            "base_dn": "dc=example,dc=com",
                            "expected_result_code": "LDAP_SUCCESS",
                        },
                        "(uid=*)",
                        output,
                        True,
                        expected,
                        dns_digest(expected),
                    )
        report.assert_not_called()
        self.assertEqual(
            events,
            [
                "guard-begin",
                "perf-start",
                "perf-poll",
                *(["search"] * PROFILE_OPERATION_COUNT),
                "perf-stop",
                "perf-communicate",
                "guard-finish",
            ],
        )

    def test_profile_symbol_absence_is_unresolved_not_nonconsumption(self) -> None:
        evidence = profile_lookup_symbol_evidence(
            "unrelated symbols", lookup_mode="on", report_observed=True,
        )
        self.assertEqual(evidence["status"], "unresolved")
        self.assertIn("No inference", evidence["absence_interpretation"])

    def test_lookup_off_profile_rejects_lookup_only_symbol(self) -> None:
        with self.assertRaisesRegex(StudyError, "lookup-off profile"):
            profile_lookup_symbol_evidence(
                "filter_or_lookup_probe", lookup_mode="off",
                report_observed=True,
            )


class DynamicControlTests(unittest.TestCase):
    class _Runtime(DS389Runtime):
        actual_lookup_mode = "on"

        def __init__(
                self, manifest: dict[str, object],
                operations: list[tuple[SearchResult, dict[str, str]]]) -> None:
            self.manifest = manifest
            self.operations = operations
            self.dynamic_states: list[bool] = []
            self.internal_operation_policies: list[tuple[bool, bool]] = []

        def prepare_dynamic_limits(self) -> None:
            return None

        def configure_dynamic_lists(self, enabled: bool) -> None:
            self.dynamic_states.append(enabled)

        def diagnostics_enable(self, *, filter_trace: bool = False) -> object:
            self.assert_no_filter_trace = not filter_trace
            return object()

        def diagnostics_restore(self, _state: object) -> None:
            return None

        def search_with_isolated_diagnostics(
                self, **_search: object
        ) -> tuple[SearchResult, dict[str, str], dict[str, object]]:
            self.internal_operation_policies.append((
                bool(_search.get("allow_internal_operations", False)),
                bool(_search.get("require_internal_operations", False)),
            ))
            result, window = self.operations.pop(0)
            return result, window, {"operation_count": 1, "cursor": {}}

    @staticmethod
    def _access(count: int, code: int = 0) -> str:
        return (
            "conn=1 op=1 RESULT err="
            f"{code} tag=101 nentries={count} etime=0.001\n"
        )

    @staticmethod
    def _contract() -> tuple[dict[str, object], dict[str, object], list[str]]:
        stored = sorted(
            f"cn=stored-{index},ou=groups,dc=example,dc=com"
            for index in range(20)
        )
        dynamic = sorted(
            f"cn=dynamic-{index},ou=groups,dc=example,dc=com"
            for index in range(20)
        )
        expected = stored[:2]
        manifest = {
            "dynamic_list": {
                "stored_dns": stored,
                "dynamic_url_dns": dynamic,
                "base_dn": "ou=groups,dc=example,dc=com",
                "target_dn": "uid=target,dc=example,dc=com",
                "limited_bind_dn": "cn=limited,dc=example,dc=com",
                "control_bind_dn": "cn=control,dc=example,dc=com",
                "bind_password": "password",
                "lookthrough_limit": 30,
            },
        }
        scenario = {
            "base_dn": "ou=groups,dc=example,dc=com",
            "scope": "sub",
            "groups": ["dynamic-list-correctness"],
            "expected_result_code": "LDAP_SUCCESS",
            "parameters": {"id_list_scan_limit": 30},
            "expected_diagnostics": {
                "or_lookup": {"expectation": "not-applicable"},
                "bounded_read": {
                    "expectation": "revision-dependent-dynamic-safety",
                    "revision_expectations": {
                        "combined-diagnostic": "required-pre-fix-diagnostic",
                        "dynamic-list-fix": "forbidden",
                        "final": "forbidden",
                    },
                },
            },
        }
        return manifest, scenario, expected

    def _runtime(
            self, *, final_code: int, final_dns: list[str],
            final_cap: bool) -> tuple[_Runtime, dict[str, object], list[str]]:
        manifest, scenario, expected = self._contract()
        stored = list(manifest["dynamic_list"]["stored_dns"])
        augmented = sorted(
            stored + list(manifest["dynamic_list"]["dynamic_url_dns"])
        )
        cap = (
            "costly AND component returned ALLIDS under read cap 30\n"
            if final_cap else ""
        )
        operations = [
            (
                SearchResult(0, "", "", stored),
                {"error": "", "access": self._access(20)},
            ),
            (
                SearchResult(0, "", "", augmented),
                {"error": "", "access": self._access(40)},
            ),
            (
                SearchResult(final_code, "", "admin limit", final_dns),
                {
                    "error": cap,
                    "access": self._access(len(final_dns), final_code),
                },
            ),
            (
                SearchResult(0, "", "", ["dc=example,dc=com"]),
                {"error": "", "access": self._access(1)},
            ),
        ]
        return self._Runtime(manifest, operations), scenario, expected

    def test_7c_admin_limit_is_preserved_with_health_and_diagnostics(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=11, final_dns=[], final_cap=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            record = run_dynamic_control(
                runtime=runtime,
                scenario_id="dynamic-finite",
                scenario=scenario,
                filter_text="(&(objectClass=groupOfNames)(member=target))",
                expected=expected,
                expected_hash=dns_digest(expected),
                revision=REVISION_ROLES["combined-diagnostic"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        self.assertEqual(record["correctness"], "expected-historical-failure")
        self.assertTrue(record["ldap_adminlimit_exceeded"])
        self.assertTrue(record["post_control_health"]["passed"])
        self.assertEqual(record["final_search"]["actual_client_result_code"], 11)
        self.assertEqual(record["final_search"]["actual_server_result_code"], 11)
        self.assertTrue(
            record["final_search"]["diagnostics"]["cap_path_observed"]
        )
        self.assertEqual(runtime.dynamic_states, [False, True])

    def test_7c_waiver_rejects_an_unrelated_failure(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=50, final_dns=[], final_cap=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                    StudyError, "waiver applies only.*LDAP_ADMINLIMIT_EXCEEDED"):
                run_dynamic_control(
                    runtime=runtime,
                    scenario_id="dynamic-finite",
                    scenario=scenario,
                    filter_text="(member=target)",
                    expected=expected,
                    expected_hash=dns_digest(expected),
                    revision=REVISION_ROLES["combined-diagnostic"],
                    diagnostic_dir=Path(temporary) / "diagnostics",
                )

    def test_final_dynamic_control_requires_success_and_forbids_cap(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=0,
            final_dns=self._contract()[2],
            final_cap=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            record = run_dynamic_control(
                runtime=runtime,
                scenario_id="dynamic-finite",
                scenario=scenario,
                filter_text="(&(objectClass=groupOfNames)(member=target))",
                expected=expected,
                expected_hash=dns_digest(expected),
                revision=REVISION_ROLES["final"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        self.assertEqual(record["correctness"], "pass")
        self.assertFalse(record["historical_expected_failure"])
        self.assertEqual(record["mechanism_gate"]["status"], "pass")
        self.assertEqual(
            runtime.internal_operation_policies,
            [
                (False, False),
                (True, False),
                (True, False),
                (True, False),
            ],
        )

    def test_dynamic_nested_candidate_traces_are_retained_but_not_attributed(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=0,
            final_dns=self._contract()[2],
            final_cap=False,
        )
        candidate_values = [1, 20, 22, *([1] * 20)]
        runtime.operations[2][1]["error"] = "".join(
            f"Candidate list has {value} ids\n" for value in candidate_values
        )
        with tempfile.TemporaryDirectory() as temporary:
            record = run_dynamic_control(
                runtime=runtime,
                scenario_id="dynamic-finite",
                scenario=scenario,
                filter_text="(&(objectClass=groupOfNames)(member=target))",
                expected=expected,
                expected_hash=dns_digest(expected),
                revision=REVISION_ROLES["final"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        diagnostics = record["final_search"]["diagnostics"]
        self.assertEqual(diagnostics["candidate_list_values"], candidate_values)
        self.assertEqual(
            diagnostics["candidate_list_status"],
            "not-directly-observable-unattributed-traces",
        )
        self.assertIsNone(diagnostics["observed_final_candidate_count"])
        self.assertEqual(
            diagnostics["candidate_list_observation"]["status"],
            "not-directly-observable",
        )
        self.assertEqual(record["mechanism_gate"]["status"], "pass")

    def test_dynamic_single_candidate_trace_is_not_falsely_attributed(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=0,
            final_dns=self._contract()[2],
            final_cap=False,
        )
        runtime.operations[2][1]["error"] = "Candidate list has 1 ids\n"
        with tempfile.TemporaryDirectory() as temporary:
            record = run_dynamic_control(
                runtime=runtime,
                scenario_id="dynamic-finite",
                scenario=scenario,
                filter_text="(&(objectClass=groupOfNames)(member=target))",
                expected=expected,
                expected_hash=dns_digest(expected),
                revision=REVISION_ROLES["final"],
                diagnostic_dir=Path(temporary) / "diagnostics",
            )
        diagnostics = record["final_search"]["diagnostics"]
        self.assertEqual(diagnostics["candidate_list_values"], [1])
        self.assertEqual(
            diagnostics["candidate_list_status"],
            "not-directly-observable-unattributed-traces",
        )
        self.assertIsNone(diagnostics["observed_final_candidate_count"])
        self.assertEqual(
            diagnostics["candidate_list_observation"]["parser_status"],
            "observed",
        )

    def test_dynamic_candidate_trace_allowance_does_not_waive_cap_gate(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=0,
            final_dns=self._contract()[2],
            final_cap=True,
        )
        runtime.operations[2][1]["error"] += (
            "Candidate list has 20 ids\nCandidate list has 22 ids\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                    StudyError, "bounded-read cap appeared"):
                run_dynamic_control(
                    runtime=runtime,
                    scenario_id="dynamic-finite",
                    scenario=scenario,
                    filter_text="(&(objectClass=groupOfNames)(member=target))",
                    expected=expected,
                    expected_hash=dns_digest(expected),
                    revision=REVISION_ROLES["final"],
                    diagnostic_dir=Path(temporary) / "diagnostics",
                )

    def test_final_dynamic_admin_limit_is_a_hard_failure(self) -> None:
        runtime, scenario, expected = self._runtime(
            final_code=11, final_dns=[], final_cap=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(StudyError, "LDAP result code 11"):
                run_dynamic_control(
                    runtime=runtime,
                    scenario_id="dynamic-finite",
                    scenario=scenario,
                    filter_text="(member=target)",
                    expected=expected,
                    expected_hash=dns_digest(expected),
                    revision=REVISION_ROLES["final"],
                    diagnostic_dir=Path(temporary) / "diagnostics",
                )


class LogCursorTests(unittest.TestCase):
    class _DelayedRuntime(ServerRuntime):
        implementation = "389ds"

        def search(self, **_search: object) -> SearchResult:
            assert self.access_log is not None
            path = self.access_log
            with path.open("a", encoding="utf-8") as stream:
                stream.write("conn=7 op=1 SRCH base=\"dc=example,dc=com\"\n")

            def append_result() -> None:
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        "conn=7 op=1 RESULT err=0 tag=101 nentries=0 "
                        "etime=0.001\n"
                    )

            threading.Timer(0.1, append_result).start()
            return SearchResult(0, "", "", [])

    class _StaleResultRuntime(_DelayedRuntime):
        def search(self, **_search: object) -> SearchResult:
            assert self.access_log is not None
            path = self.access_log
            with path.open("a", encoding="utf-8") as stream:
                stream.write("conn=7 op=1 SRCH base=\"dc=example,dc=com\"\n")

            def append_stale_result() -> None:
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        "conn=6 op=1 RESULT err=0 tag=101 nentries=0 "
                        "etime=0.001\n"
                    )

            def append_target_result() -> None:
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        "conn=7 op=1 RESULT err=0 tag=101 nentries=0 "
                        "etime=0.001\n"
                    )

            threading.Timer(0.05, append_stale_result).start()
            threading.Timer(0.15, append_target_result).start()
            return SearchResult(0, "", "", [])

    class _InternalContaminationRuntime(_DelayedRuntime):
        def search(self, **_search: object) -> SearchResult:
            assert self.access_log is not None
            with self.access_log.open("a", encoding="utf-8") as stream:
                stream.write("conn=7 op=1 SRCH base=\"dc=example,dc=com\"\n")
                stream.write(
                    "conn=Internal(0) op=0(2)(1)STAT read index: "
                    "attribute=objectClass key(eq)=referral --> count 0\n"
                )
                stream.write(
                    "conn=7 op=1 RESULT err=0 tag=101 nentries=0 "
                    "etime=0.001\n"
                )
            return SearchResult(0, "", "", [])

    @staticmethod
    def _set_quiet_state(
            runtime: ServerRuntime, monotonic_seconds: float = 1000.0) -> None:
        window = referral_quiet_window(monotonic_seconds)
        runtime.background_quiet_window_state = {
            "bucket": window["bucket"],
            "next_boundary_monotonic_seconds": (
                window["next_boundary_monotonic_seconds"]
            ),
            "deadline_monotonic_seconds": window["deadline_monotonic_seconds"],
        }

    @staticmethod
    def _append_complete_search(
            access: Path, internal_lines: list[str] | None = None) -> None:
        with access.open("a", encoding="utf-8") as stream:
            stream.write("conn=7 op=1 SRCH base=\"dc=example,dc=com\"\n")
            for line in internal_lines or []:
                stream.write(line.rstrip("\n") + "\n")
            stream.write(
                "conn=7 op=1 RESULT err=0 tag=101 nentries=0 "
                "etime=0.001\n"
            )

    def test_referral_quiet_window_is_epoch_aligned_and_deadline_exclusive(
            self) -> None:
        before_deadline = referral_quiet_window(3594.999)
        self.assertEqual(before_deadline["bucket"], 0)
        self.assertEqual(before_deadline["next_boundary_monotonic_seconds"], 3600.0)
        self.assertEqual(before_deadline["deadline_monotonic_seconds"], 3595.0)
        self.assertAlmostEqual(
            before_deadline["remaining_to_deadline_seconds"], 0.001,
        )

        at_boundary = referral_quiet_window(3600.0)
        self.assertEqual(at_boundary["bucket"], 1)
        self.assertEqual(at_boundary["next_boundary_monotonic_seconds"], 7200.0)
        self.assertEqual(at_boundary["deadline_monotonic_seconds"], 7195.0)

    def test_internal_startup_barriers_pair_only_later_same_operation_results(
            self) -> None:
        identity = "conn=Internal(0) op=0(1)(1)"
        prior_result = f"{identity} RESULT err=0 tag=48 nentries=1"
        referral_start = (
            f"{identity}STAT read index: attribute=objectClass "
            "key(eq)=referral --> count 0"
        )
        referral_completion = (
            f"{identity}STAT read index: duration 0.000001"
        )
        incomplete_referral = referral_monitor_operation_evidence(
            f"{prior_result}\n{referral_start}\n"
        )
        self.assertEqual(incomplete_referral["paired_operation_count"], 0)
        self.assertEqual(
            incomplete_referral["unmatched_referral_start_count"], 1,
        )
        complete_referral = referral_monitor_operation_evidence(
            f"{prior_result}\n{referral_start}\n{referral_completion}\n"
        )
        self.assertEqual(complete_referral["paired_operation_count"], 1)
        self.assertEqual(complete_referral["completion_line_count"], 1)

        vattr_start = (
            f'{identity} SRCH base="dc=example,dc=com" scope=2 '
            f'filter="{VATTR_CHECK_FILTER}" attrs=ALL'
        )
        incomplete_vattr = vattr_check_operation_evidence(
            f"{prior_result}\n{vattr_start}\n"
        )
        self.assertEqual(incomplete_vattr["paired_operation_count"], 0)
        self.assertEqual(incomplete_vattr["unmatched_start_count"], 1)
        complete_vattr = vattr_check_operation_evidence(
            f"{prior_result}\n{vattr_start}\n"
            f"{identity} RESULT err=0 tag=48 nentries=0\n"
        )
        self.assertEqual(complete_vattr["paired_operation_count"], 1)
        self.assertEqual(complete_vattr["completion_line_count"], 1)

    def test_background_quiet_guard_rejects_start_or_finish_at_deadline(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = self._DelayedRuntime(
                workload=root,
                manifest={},
                runtime_dir=root / "runtime",
                lookup_mode="on",
                index_config="baseline-no-presence",
                backend="mdb",
                cpu=None,
            )
            self._set_quiet_state(runtime, 3594.0)
            with patch(
                    "study.server_runtime.time.clock_gettime",
                    side_effect=[3594.0, 3595.0]):
                evidence = runtime.begin_background_quiet_collection("test")
                with self.assertRaisesRegex(StudyError, "crossed.*deadline"):
                    runtime.finish_background_quiet_collection(evidence)
            with patch(
                    "study.server_runtime.time.clock_gettime",
                    return_value=3595.0):
                with self.assertRaisesRegex(StudyError, "window expired"):
                    runtime.begin_background_quiet_collection("test")

    def test_isolated_search_waits_for_async_result_log_flush(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            access = root / "access"
            access.write_text("old\n", encoding="utf-8")
            runtime = self._DelayedRuntime(
                workload=root,
                manifest={},
                runtime_dir=root / "runtime",
                lookup_mode="on",
                index_config="baseline-no-presence",
                backend="mdb",
                cpu=None,
            )
            runtime.access_log = access
            self._set_quiet_state(runtime)
            with patch(
                    "study.server_runtime.time.clock_gettime",
                    return_value=1000.0):
                result, window, isolation = (
                    runtime.search_with_isolated_diagnostics(
                        base="dc=example,dc=com",
                        scope="sub",
                        filter_text="(objectClass=*)",
                        attributes=["1.1"],
                    )
                )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("old", window["access"])
        self.assertIn("tag=101", window["access"])
        self.assertEqual(
            isolation["log_completion"]["status"], "observed-target"
        )
        self.assertEqual(isolation["log_completion"]["target_connection"], 7)
        self.assertEqual(isolation["log_completion"]["target_operation"], 1)
        self.assertEqual(isolation["log_completion"]["result_line_count"], 1)
        self.assertGreater(isolation["log_completion"]["poll_count"], 0)

    def test_isolated_search_rejects_stale_result_before_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            access = root / "access"
            access.write_text("old\n", encoding="utf-8")
            runtime = self._StaleResultRuntime(
                workload=root,
                manifest={},
                runtime_dir=root / "runtime",
                lookup_mode="on",
                index_config="baseline-no-presence",
                backend="mdb",
                cpu=None,
            )
            runtime.access_log = access
            self._set_quiet_state(runtime)
            with patch(
                    "study.server_runtime.time.clock_gettime",
                    return_value=1000.0):
                with self.assertRaisesRegex(
                        StudyError, "contaminated after target"):
                    runtime.search_with_isolated_diagnostics(
                        base="dc=example,dc=com",
                        scope="sub",
                        filter_text="(objectClass=*)",
                        attributes=["1.1"],
                    )

    def test_isolated_search_rejects_referral_monitor_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            access = root / "access"
            access.write_text("old\n", encoding="utf-8")
            runtime = self._InternalContaminationRuntime(
                workload=root,
                manifest={},
                runtime_dir=root / "runtime",
                lookup_mode="on",
                index_config="baseline-no-presence",
                backend="mdb",
                cpu=None,
            )
            runtime.access_log = access
            self._set_quiet_state(runtime)
            with patch(
                    "study.server_runtime.time.clock_gettime",
                    return_value=1000.0):
                with self.assertRaisesRegex(
                        StudyError, "periodic referral monitor"):
                    runtime.search_with_isolated_diagnostics(
                        base="dc=example,dc=com",
                        scope="sub",
                        filter_text="(objectClass=*)",
                        attributes=["1.1"],
                    )

    def test_stability_reread_rejects_late_internal_or_referral_lines(
            self) -> None:
        cases = (
            (
                "generic-internal",
                "conn=Internal(0) op=0(2)(1) SRCH "
                "base=\"cn=config\" scope=0 filter=\"(objectClass=*)\"",
                "internal server operations",
                False,
            ),
            (
                "referral-monitor",
                "conn=Internal(0) op=0(2)(1) STAT read index: "
                "attribute=objectClass key(eq)=referral --> count 0",
                "periodic referral monitor",
                True,
            ),
        )
        for label, late_line, message, allow_internal in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                access = root / "access"
                access.write_text("old\n", encoding="utf-8")
                runtime = self._DelayedRuntime(
                    workload=root,
                    manifest={},
                    runtime_dir=root / "runtime",
                    lookup_mode="on",
                    index_config="baseline-no-presence",
                    backend="mdb",
                    cpu=None,
                )
                runtime.access_log = access
                cursor = runtime.log_cursor()
                self._append_complete_search(access)
                appended = False

                def append_during_stability(_seconds: float) -> None:
                    nonlocal appended
                    if not appended:
                        with access.open("a", encoding="utf-8") as stream:
                            stream.write(late_line + "\n")
                        appended = True

                with patch(
                        "study.server_runtime.time.sleep",
                        side_effect=append_during_stability):
                    with self.assertRaisesRegex(StudyError, message):
                        runtime.await_isolated_search_log(
                            cursor,
                            allow_internal_operations=allow_internal,
                        )

    def test_planned_nested_internal_operations_are_scoped_to_target_connection(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            access = root / "access"
            access.write_text("old\n", encoding="utf-8")
            runtime = self._DelayedRuntime(
                workload=root,
                manifest={},
                runtime_dir=root / "runtime",
                lookup_mode="on",
                index_config="baseline-no-presence",
                backend="mdb",
                cpu=None,
            )
            runtime.access_log = access
            cursor = runtime.log_cursor()
            self._append_complete_search(access, [
                "conn=7 (Internal) op=1(2)(1) SRCH "
                "base=\"ou=people,dc=example,dc=com\"",
                "conn=7 (Internal) op=1(2)(1) RESULT err=0 "
                "tag=48 nentries=1 etime=0.001",
            ])
            with patch("study.server_runtime.time.sleep"):
                _window, isolation = runtime.await_isolated_search_log(
                    cursor,
                    allow_internal_operations=True,
                    require_internal_operations=True,
                )
        planned = isolation["internal_server_operations"]
        self.assertEqual(planned["status"], "observed-planned")
        self.assertTrue(planned["allowed"])
        self.assertTrue(planned["required"])
        self.assertEqual(planned["nested_line_count"], 2)

    def test_planned_internal_allowance_rejects_root_or_other_connection(
            self) -> None:
        cases = (
            (
                "root",
                "conn=Internal(0) op=0(2)(1) SRCH base=\"cn=config\"",
                "cannot admit root maintenance operations",
            ),
            (
                "other-connection",
                "conn=8 (Internal) op=1(2)(1) SRCH "
                "base=\"ou=people,dc=example,dc=com\"",
                "belong to another connection",
            ),
        )
        for label, internal_line, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                access = root / "access"
                access.write_text("old\n", encoding="utf-8")
                runtime = self._DelayedRuntime(
                    workload=root,
                    manifest={},
                    runtime_dir=root / "runtime",
                    lookup_mode="on",
                    index_config="baseline-no-presence",
                    backend="mdb",
                    cpu=None,
                )
                runtime.access_log = access
                cursor = runtime.log_cursor()
                self._append_complete_search(access, [internal_line])
                with self.assertRaisesRegex(StudyError, message):
                    runtime.await_isolated_search_log(
                        cursor,
                        allow_internal_operations=True,
                    )

    def test_internal_result_forms_are_not_external_search_results(self) -> None:
        access = (
            "conn=7 op=1 RESULT err=0 tag=101 nentries=3 etime=0.001\n"
            "conn=Internal(0) op=0(2)(1) RESULT err=0 tag=101 "
            "nentries=99 etime=0.001\n"
            "conn=7 (Internal) op=1(2)(1) RESULT err=0 tag=101 "
            "nentries=88 etime=0.001\n"
        )
        self.assertEqual(len(internal_access_lines(access)), 2)
        parsed = parse_access_result("389ds", access)
        self.assertEqual(parsed["result_line_count"], 1)
        self.assertEqual(parsed["server_nentries"], 3)
        self.assertEqual(parsed["server_result_code"], 0)

    def test_referral_monitor_uses_supported_maximum_period(self) -> None:
        self.assertEqual(REFERRAL_CHECK_PERIOD_SECONDS, 3600)

    def test_byte_cursor_reads_only_appended_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "errors"
            path.write_text("old\n", encoding="utf-8")
            cursor = file_cursor(path)
            with path.open("a", encoding="utf-8") as stream:
                stream.write("new\n")
            self.assertEqual(read_after_cursor(path, cursor), "new\n")

    def test_cursor_rejects_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "errors"
            path.write_text("long original record\n", encoding="utf-8")
            cursor = file_cursor(path)
            path.write_text("x\n", encoding="utf-8")
            with self.assertRaisesRegex(StudyError, "truncated"):
                read_after_cursor(path, cursor)


class BackendRuntimeIdentityTests(unittest.TestCase):
    @staticmethod
    def _write_maps(path: Path, modules: list[Path], address: int) -> None:
        lines = []
        for index, module in enumerate(modules):
            start = address + index * 0x2000
            lines.append(
                f"{start:x}-{start + 0x1000:x} r-xp 00000000 00:00 1 {module}\n"
            )
        path.write_text("".join(lines), encoding="utf-8")

    @staticmethod
    def _fake_rpm(path: Path, owner: str) -> None:
        path.write_text(
            "#!/bin/sh\nprintf '%s\\n' '" + owner + "'\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    @staticmethod
    def _fake_slapd(path: Path, backends: list[str]) -> None:
        backend_lines = " ".join(f"'    {backend}'" for backend in backends)
        path.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'synthetic slapd' "
            f"'Included static backends:' {backend_lines}\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_live_backend_identity_uses_content_and_roles_not_location_or_owner(
            self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closures = []
            for name, owner, address, reverse in (
                    ("first", "package-a-1.x86_64", 0x1000, False),
                    ("second", "package-b-9.x86_64", 0x9000, True)):
                directory = root / name
                directory.mkdir()
                plugin = directory / "libback-ldbm.so"
                engine = directory / "liblmdb.so.0"
                server_executable = directory / "ns-slapd"
                plugin.write_bytes(b"identical ldbm plugin")
                engine.write_bytes(b"identical lmdb engine")
                server_executable.write_bytes(b"identical server executable")
                maps = directory / "maps"
                modules = [plugin, engine]
                if reverse:
                    modules.reverse()
                self._write_maps(maps, modules, address)
                rpm = directory / "rpm"
                self._fake_rpm(rpm, owner)
                closures.append(backend_runtime_module_closure(
                    1234,
                    server="389ds",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=server_executable,
                ))

            first, second = closures
            self.assertEqual(first["identity_sha256"], second["identity_sha256"])
            self.assertNotEqual(first["modules"][0]["path"], second["modules"][0]["path"])
            self.assertNotEqual(
                {module["rpm_owner"] for module in first["modules"]},
                {module["rpm_owner"] for module in second["modules"]},
            )
            self.assertEqual(
                {role for module in first["modules"] for role in module["roles"]},
                {"389ds-ldbm-backend", "database-engine"},
            )
            for module in first["modules"]:
                self.assertTrue(module["path"].startswith("/"))
                self.assertEqual(len(module["sha256"]), 64)
                self.assertTrue(module["rpm_owner"])

            second_engine = root / "second" / "liblmdb.so.0"
            second_engine.write_bytes(b"changed lmdb engine")
            changed = backend_runtime_module_closure(
                1234,
                server="389ds",
                backend="mdb",
                maps_path=root / "second" / "maps",
                rpm_command=str(root / "second" / "rpm"),
                live_executable_path=root / "second" / "ns-slapd",
            )
            self.assertNotEqual(first["identity_sha256"], changed["identity_sha256"])

    def test_live_backend_identity_requires_plugin_and_engine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "libback-ldbm.so"
            server_executable = root / "ns-slapd"
            plugin.write_bytes(b"plugin")
            server_executable.write_bytes(b"server")
            maps = root / "maps"
            self._write_maps(maps, [plugin], 0x1000)
            rpm = root / "rpm"
            self._fake_rpm(rpm, "389-ds-base-libs-1.x86_64")
            with self.assertRaisesRegex(StudyError, "database-engine"):
                backend_runtime_module_closure(
                    1234,
                    server="389ds",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=server_executable,
                )

    def test_openldap_static_mdb_backend_binds_both_roles_to_live_slapd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            maps = root / "maps"
            maps.write_text("", encoding="utf-8")
            slapd = root / "slapd"
            self._fake_slapd(slapd, ["config", "mdb", "monitor"])
            rpm = root / "rpm"
            self._fake_rpm(rpm, "openldap-servers-2.6.13.x86_64")
            closure = backend_runtime_module_closure(
                4321,
                server="openldap",
                backend="mdb",
                maps_path=maps,
                rpm_command=str(rpm),
                live_executable_path=slapd,
            )
            self.assertEqual(len(closure["modules"]), 1)
            self.assertEqual(
                closure["modules"][0]["roles"],
                ["database-engine", "openldap-db-backend"],
            )
            self.assertEqual(
                closure["static_backend_evidence"][
                    "included_static_backends"
                ],
                ["config", "mdb", "monitor"],
            )
            self.assertEqual(
                closure["static_backend_evidence"]["selected_backend"],
                "mdb",
            )

    def test_openldap_static_inventory_must_name_selected_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            maps = root / "maps"
            maps.write_text("", encoding="utf-8")
            slapd = root / "slapd"
            self._fake_slapd(slapd, ["config", "monitor"])
            rpm = root / "rpm"
            self._fake_rpm(rpm, "openldap-servers-2.6.13.x86_64")
            with self.assertRaisesRegex(
                    StudyError, "does not report mdb as an included static backend"):
                backend_runtime_module_closure(
                    4321,
                    server="openldap",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=slapd,
                )

    def test_openldap_static_inventory_ignores_unrelated_footer_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            maps = root / "maps"
            maps.write_text("", encoding="utf-8")
            slapd = root / "slapd"
            slapd.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Included static backends:' "
                "'    config' '    monitor' 'Unrelated diagnostics:' 'mdb'\n",
                encoding="utf-8",
            )
            slapd.chmod(0o755)
            rpm = root / "rpm"
            self._fake_rpm(rpm, "openldap-servers-2.6.13.x86_64")
            with self.assertRaisesRegex(
                    StudyError, "does not report mdb as an included static backend"):
                backend_runtime_module_closure(
                    4321,
                    server="openldap",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=slapd,
                )

    def test_openldap_static_backend_assigns_only_roles_missing_from_maps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            engine = root / "liblmdb.so.0"
            engine.write_bytes(b"mapped lmdb engine")
            maps = root / "maps"
            self._write_maps(maps, [engine], 0x1000)
            slapd = root / "slapd"
            self._fake_slapd(slapd, ["config", "mdb"])
            rpm = root / "rpm"
            self._fake_rpm(rpm, "openldap-servers-2.6.13.x86_64")
            closure = backend_runtime_module_closure(
                4321,
                server="openldap",
                backend="mdb",
                maps_path=maps,
                rpm_command=str(rpm),
                live_executable_path=slapd,
            )
            roles_by_path = {
                Path(module["path"]).name: module["roles"]
                for module in closure["modules"]
            }
            self.assertEqual(roles_by_path["liblmdb.so.0"], ["database-engine"])
            self.assertEqual(roles_by_path["slapd"], ["openldap-db-backend"])
            self.assertEqual(
                closure["static_backend_evidence"]["assigned_roles"],
                ["openldap-db-backend"],
            )

    def test_backend_roles_require_executable_canonical_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "prefix-libback-ldbm-copy.so"
            engine = root / "liblmdb.so.0"
            server_executable = root / "ns-slapd"
            for path in (plugin, engine, server_executable):
                path.write_bytes(path.name.encode("ascii"))
            maps = root / "maps"
            maps.write_text(
                f"1000-2000 r-xp 00000000 00:00 1 {plugin}\n"
                f"3000-4000 r--p 00000000 00:00 2 {engine}\n",
                encoding="utf-8",
            )
            rpm = root / "rpm"
            self._fake_rpm(rpm, "synthetic-package")
            with self.assertRaisesRegex(
                    StudyError, "389ds-ldbm-backend, database-engine"):
                backend_runtime_module_closure(
                    1234,
                    server="389ds",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=server_executable,
                )

    def test_backend_role_classifier_rejects_wrong_server_and_decoy_names(self) -> None:
        self.assertEqual(
            backend_module_roles(
                Path("libdb-mdb.so"), server="openldap", backend="mdb",
            ),
            [],
        )
        self.assertEqual(
            backend_module_roles(
                Path("back_mdb-2.6.so"), server="389ds", backend="mdb",
            ),
            [],
        )
        self.assertEqual(
            backend_module_roles(
                Path("libmdb.so.0"), server="389ds", backend="mdb",
            ),
            [],
        )
        self.assertEqual(
            backend_module_roles(
                Path("back_mdb-2.6.so"), server="openldap", backend="mdb",
            ),
            ["openldap-db-backend"],
        )

    def test_live_pid_executable_must_match_installed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin = root / "libback-ldbm.so"
            engine = root / "liblmdb.so.0"
            live_executable = root / "ns-slapd"
            expected_executable = root / "expected-ns-slapd"
            for path in (plugin, engine, live_executable, expected_executable):
                path.write_bytes(path.name.encode("ascii"))
            maps = root / "maps"
            self._write_maps(maps, [plugin, engine], 0x1000)
            rpm = root / "rpm"
            self._fake_rpm(rpm, "synthetic-package")
            with self.assertRaisesRegex(
                    StudyError, "belongs to a different executable"):
                backend_runtime_module_closure(
                    1234,
                    server="389ds",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=live_executable,
                    expected_executable_path=expected_executable,
                )

            expected_sha = hashlib.sha256(live_executable.read_bytes()).hexdigest()
            with self.assertRaisesRegex(
                    StudyError, "hash differs from installed-artifact identity"):
                backend_runtime_module_closure(
                    1234,
                    server="389ds",
                    backend="mdb",
                    maps_path=maps,
                    rpm_command=str(rpm),
                    live_executable_path=live_executable,
                    expected_executable_path=live_executable,
                    expected_executable_sha256=(
                        "0" * 64 if expected_sha != "0" * 64 else "1" * 64
                    ),
                )

            first = backend_runtime_module_closure(
                1234,
                server="389ds",
                backend="mdb",
                maps_path=maps,
                rpm_command=str(rpm),
                live_executable_path=live_executable,
                expected_executable_path=live_executable,
                expected_executable_sha256=expected_sha,
            )
            live_executable.write_bytes(b"changed live executable bytes")
            second = backend_runtime_module_closure(
                1234,
                server="389ds",
                backend="mdb",
                maps_path=maps,
                rpm_command=str(rpm),
                live_executable_path=live_executable,
                expected_executable_path=live_executable,
            )
            self.assertNotEqual(first["identity_sha256"], second["identity_sha256"])

    def test_backend_runtime_pid_rejects_boolean(self) -> None:
        with self.assertRaisesRegex(StudyError, "positive server pid"):
            backend_runtime_module_closure(
                True,
                server="389ds",
                backend="mdb",
            )

    def test_behavioral_identity_combines_linked_and_loaded_closures(self) -> None:
        linked = "a" * 64
        loaded = "b" * 64
        identity = combined_behavioral_runtime_identity(linked, loaded)
        self.assertEqual(len(identity), 64)
        self.assertNotEqual(
            identity,
            combined_behavioral_runtime_identity("c" * 64, loaded),
        )
        self.assertNotEqual(
            identity,
            combined_behavioral_runtime_identity(linked, "d" * 64),
        )


class NativeSafetyTests(unittest.TestCase):
    def test_abba_schedule_contract_is_structured_and_fail_closed(self) -> None:
        schedule = declared_schedule(SimpleNamespace(
            schedule_design="abba",
            schedule_block="principal-pre-vs-final-on",
            schedule_position="B2",
        ))
        self.assertEqual(schedule["design"], "abba")
        self.assertEqual(schedule["block_id"], "principal-pre-vs-final-on")
        self.assertEqual(schedule["state"], "B")
        self.assertTrue(schedule["release_ordering_eligible"])

        for values, message in (
            ({
                "schedule_design": "abba",
                "schedule_block": None,
                "schedule_position": "A1",
            }, "requires --schedule-block"),
            ({
                "schedule_design": "abba",
                "schedule_block": "block",
                "schedule_position": "SCREEN-1",
            }, "requires --schedule-position"),
            ({
                "schedule_design": "screen",
                "schedule_block": "block",
                "schedule_position": "SCREEN-1",
            }, "reserved"),
            ({
                "schedule_design": "unspecified",
                "schedule_block": "block",
                "schedule_position": "unspecified",
            }, "requires --schedule-design abba"),
        ):
            with self.subTest(values=values):
                with self.assertRaisesRegex(StudyError, message):
                    declared_schedule(SimpleNamespace(**values))

    def test_screen_schedule_is_never_release_ordering_evidence(self) -> None:
        schedule = declared_schedule(SimpleNamespace(
            schedule_design="screen",
            schedule_block=None,
            schedule_position="SCREEN-HEAD-OFF-2",
        ))
        self.assertEqual(schedule["design"], "screen")
        self.assertIsNone(schedule["state"])
        self.assertFalse(schedule["release_ordering_eligible"])

    def test_invocation_evidence_redacts_password_values(self) -> None:
        evidence = invocation_evidence([
            "run-study", "--server", "389ds", "--password", "secret",
        ])
        self.assertNotIn("secret", evidence["argv"])
        self.assertIn("<redacted>", evidence["shell_escaped"])

    def test_live_import_verification_checks_people_and_principal_hashes(self) -> None:
        people = [
            "uid=lfs000000,ou=people,dc=example,dc=com",
            "uid=lfs000001,ou=people,dc=example,dc=com",
        ]
        principal = people[:1]

        class Runtime(ServerRuntime):
            def __init__(self) -> None:
                self.manifest = {
                    "dataset_import_oracles": {
                        "people": {
                            "base_dn": "ou=people,dc=example,dc=com",
                            "scope": "sub",
                            "filter": "(objectClass=largeFilterStudyPerson)",
                            "requested_attributes": ["1.1"],
                            "expected_result_code": "LDAP_SUCCESS",
                            "expected_count": len(people),
                            "expected_sha256": dns_digest(people),
                        },
                        "principal_outer_cohort": {
                            "base_dn": "ou=people,dc=example,dc=com",
                            "scope": "sub",
                            "filter": "(&(sString1=asd)(sString2=ff)(sString3=vv))",
                            "requested_attributes": ["1.1"],
                            "expected_result_code": "LDAP_SUCCESS",
                            "expected_count": len(principal),
                            "expected_sha256": dns_digest(principal),
                        },
                    },
                }
                self.results = [
                    SearchResult(0, "", "", people),
                    SearchResult(0, "", "", principal),
                ]

            def search(self, **_kwargs: object) -> SearchResult:
                return self.results.pop(0)

        evidence = Runtime().verify_imported_dataset()
        self.assertTrue(evidence["passed"])
        self.assertEqual(
            evidence["oracles"]["people"]["actual_sha256"],
            dns_digest(people),
        )

    def test_native_boundary_accepts_generic_fedora_vm_but_rejects_emulation(self) -> None:
        self.assertEqual(native_fedora_rejection_reasons(
            system="Linux",
            machine="x86_64",
            fedora_release="Fedora Linux 42",
            container_kind=None,
            apple_markers=[],
            explicitly_emulated=False,
        ), [])
        reasons = native_fedora_rejection_reasons(
            system="Linux",
            machine="aarch64",
            fedora_release="Fedora Linux 42",
            container_kind=None,
            apple_markers=["dmi-product-name"],
            explicitly_emulated=True,
        )
        self.assertTrue(any("architecture" in reason for reason in reasons))
        self.assertTrue(any("Apple/Rosetta/OrbStack" in reason for reason in reasons))
        self.assertTrue(any("LFSTUDY_EMULATED" in reason for reason in reasons))

    def test_final_study_tip_preserves_source_and_resolves_final_role(self) -> None:
        self.assertEqual(
            resolve_revision(FINAL_STUDY_TIP_REVISION, "389ds"),
            (FINAL_STUDY_TIP_REVISION, "final"),
        )
        self.assertEqual(
            resolve_revision("final-study-tip", "389ds"),
            (FINAL_STUDY_TIP_REVISION, "final"),
        )
        self.assertEqual(
            resolve_revision("final", "389ds"),
            (FINAL_PRODUCTION_REVISION, "final"),
        )
        self.assertEqual(
            resolve_revision("fedora-stable-package", "389ds"),
            ("fedora-stable-package", "fedora-stable-package"),
        )
        self.assertEqual(
            production_equivalent_revision(FINAL_STUDY_TIP_REVISION),
            FINAL_PRODUCTION_REVISION,
        )

    def test_final_study_tip_requires_final_mechanism_diagnostics(self) -> None:
        scenario = {
            "groups": ["combined-features"],
            "expected_result_code": "LDAP_SUCCESS",
            "expected_diagnostics": {
                "or_lookup": {
                    "expectation": "required-when-lookup-on",
                    "largest_family": 355,
                },
                "bounded_read": {"expectation": "required"},
            },
        }
        failures = mechanism_gate(
            server="389ds",
            revision=FINAL_STUDY_TIP_REVISION,
            lookup_mode="on",
            scenario=scenario,
            diagnostics={
                "lookup_constructed": False,
                "lookup_summaries": [],
                "cap_path_observed": False,
                "candidate_list_status": "not-observed",
                "access_result": {"server_notes": "", "server_result_code": 0},
            },
        )
        self.assertIn(
            "required equality lookup construction diagnostic is absent",
            failures,
        )
        self.assertIn("required bounded-read cap diagnostic is absent", failures)

    def test_committed_revision_plan_matches_source_production_alias(self) -> None:
        plan = json.loads(
            (STUDY_ROOT / "artifact-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            plan["revision_roles"]["final"], FINAL_PRODUCTION_REVISION,
        )
        self.assertEqual(
            plan["revision_roles"]["final-study-tip"],
            FINAL_STUDY_TIP_REVISION,
        )
        self.assertEqual(
            plan["production_equivalent_revisions"],
            PRODUCTION_EQUIVALENT_REVISIONS,
        )

    def test_short_rpm_git_token_is_prefix_only_not_independent_proof(self) -> None:
        expected = REVISION_ROLES["final"]
        short = rpm_source_identity_evidence(expected, [expected[:8]])
        self.assertTrue(short["source_identity_prefix_verified"])
        self.assertFalse(short["source_identity_independently_proved"])
        self.assertEqual(
            short["source_identity_basis"],
            "package-metadata-prefix-plus-operator-assertion",
        )
        exact = rpm_source_identity_evidence(expected, [expected])
        self.assertTrue(exact["source_identity_independently_proved"])
        self.assertEqual(exact["source_metadata_exact_git_tokens"], [expected])
        with self.assertRaisesRegex(StudyError, "not operator-expected"):
            rpm_source_identity_evidence(expected, ["deadbee"])
        packaged = rpm_source_identity_evidence(
            "fedora-package", [expected[:8]],
        )
        self.assertEqual(packaged["source_identity_basis"], "operator-assertion")
        self.assertFalse(packaged["source_identity_prefix_verified"])

    def test_normal_runtime_lock_ghost_ownership_is_the_only_allowed_rpm_delta(
            self) -> None:
        runtime_lock = {
            "status": "observed",
            "path": "/var/lock/dirsrv",
            "is_directory": True,
            "is_symlink": False,
            "mode": "0770",
            "owner": "dirsrv",
            "group": "dirsrv",
        }
        accepted = rpm_verify_evidence(
            "ns-slapd", returncode=1,
            stdout=".....UG..  g /var/lock/dirsrv\n", stderr="",
            runtime_lock_metadata=runtime_lock,
        )
        self.assertTrue(accepted["accepted"])
        self.assertTrue(accepted["accepted_via_runtime_ghost_allowlist"])
        self.assertEqual(accepted["unexpected_differences"], [])

        for name, changes in {
            "content-difference": {
                "stdout": "S.5....T.  c /etc/dirsrv/config/template-dse.ldif\n",
            },
            "additional-path": {
                "stdout": (
                    ".....UG..  g /var/lock/dirsrv\n"
                    ".......T.    /usr/share/dirsrv/schema/30ns-common.ldif\n"
                ),
            },
            "wrong-owner": {
                "runtime_lock_metadata": {**runtime_lock, "owner": "root"},
            },
            "wrong-mode": {
                "runtime_lock_metadata": {**runtime_lock, "mode": "0777"},
            },
            "other-server": {"executable_name": "slapd"},
        }.items():
            with self.subTest(name=name):
                evidence = rpm_verify_evidence(
                    changes.get("executable_name", "ns-slapd"),
                    returncode=1,
                    stdout=changes.get(
                        "stdout", ".....UG..  g /var/lock/dirsrv\n",
                    ),
                    stderr="",
                    runtime_lock_metadata=changes.get(
                        "runtime_lock_metadata", runtime_lock,
                    ),
                )
                self.assertFalse(evidence["accepted"])

    def test_index_contract_retains_attributes_whose_last_type_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = "indexes.json"
            (root / relative).write_text(json.dumps({
                "servers": {"389ds": {"baseline": {"sDN2": ["eq"]}}},
                "variants": {
                    "without": {
                        "add": {},
                        "remove": {"sDN2": ["eq"]},
                    },
                },
            }), encoding="utf-8")
            contract = configured_index_contract(
                root, {"index_config_file": relative},
                "389ds", "without",
            )
        self.assertIn("sDN2", contract)
        self.assertEqual(contract["sDN2"], ())

    def test_live_subschema_is_unfolded_canonicalized_and_custom_verified(self) -> None:
        lines = [
            "matchingRules: ( 2.5.13.2 NAME 'caseIgnoreMatch' )",
            "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]
        schema_lines = (STUDY_ROOT / "workload" / "schema" /
                        "99large-filter-study.ldif").read_text(
                            encoding="utf-8"
                        ).splitlines()
        lines.extend(schema_lines[5:])
        canonical = parse_live_subschema("\n".join(lines) + "\n")
        self.assertEqual(len(canonical["attributeTypes"]), 8)
        self.assertIn("EQUALITY caseIgnoreMatch", canonical["attributeTypes"][0])
        verification = verify_study_schema_identities(canonical)
        self.assertTrue(verification["passed"])
        self.assertEqual(
            verification["semantic_contract"]["format_version"], 1,
        )
        self.assertEqual(len(verification["semantic_contract_sha256"]), 64)

    def test_live_subschema_rejects_semantically_wrong_custom_definition(self) -> None:
        schema = (STUDY_ROOT / "workload" / "schema" /
                  "99large-filter-study.ldif").read_text(encoding="utf-8")
        wrong = schema.replace(
            "EQUALITY distinguishedNameMatch SYNTAX "
            "1.3.6.1.4.1.1466.115.121.1.12 X-ORIGIN",
            "EQUALITY caseIgnoreMatch SYNTAX "
            "1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN",
            1,
        )
        canonical = parse_live_subschema(wrong)
        with self.assertRaisesRegex(
                StudyError, "equality expected distinguishedNameMatch"):
            verify_study_schema_identities(canonical)

    def test_native_runner_has_no_build_or_package_install_primitive(self) -> None:
        runner_sources = "\n".join(
            (STUDY_ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "bin/run-fedora-study",
                "study/run_study.py",
                "study/server_runtime.py",
                "study/platform_info.py",
            )
        )
        forbidden = (
            "mock --rebuild",
            "rpmbuild ",
            "dnf install",
            "yum install",
            "389ds-container build",
            "git worktree",
        )
        for token in forbidden:
            self.assertNotIn(token, runner_sources)


if __name__ == "__main__":
    unittest.main()
