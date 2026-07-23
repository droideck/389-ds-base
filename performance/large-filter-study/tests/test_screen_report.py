"""Contracts for the extracted full-screen report renderer."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest

from pathlib import Path


STUDY_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(STUDY_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDY_ROOT))

from study.screen_report import (  # noqa: E402
    collect_attempt_hygiene,
    compute_noise_yardstick,
    delta_coherence,
    least_squares_slope,
    main,
    mann_whitney_u,
    noise_flags,
    regenerate_main,
    relative_spread,
    summarize_environment_captures,
)

BUNDLE_INDEX_CONFIGS = {
    "baseline-core": "baseline-no-presence",
    "baseline-branch-scaling": "baseline-no-presence",
    "baseline-dn-and-decomposition": "baseline-no-presence",
    "baseline-combined-and-family": "baseline-no-presence",
    "baseline-index-controls": "baseline-no-presence",
    "presence-sdn1": "presence-sdn1",
    "presence-sdn2": "presence-sdn2",
    "presence-both": "presence-both",
    "without-sdn1-equality": "without-sdn1-equality",
    "without-sdn2-equality": "without-sdn2-equality",
}
CANARY_VARIANTS = tuple(sorted(set(BUNDLE_INDEX_CONFIGS.values())))
BINARIES = {
    "openldap": "0" * 64,
    "custom-off": "1" * 64,
    "custom-on": "1" * 64,
    "custom-unsupported": "1" * 64,
    "fedora-stable": "2" * 64,
}
RUNG_DISTRIBUTIONS = (
    "all-absent", "mostly-live", "mixed", "duplicates", "zero-candidate",
)


def scenario_names(extended=False):
    names = ["branch-count-15-zero-candidate"]
    names += [f"scn-{index:03d}" for index in range(115)]
    if extended:
        names += [f"drift-canary-{variant}" for variant in CANARY_VARIANTS]
        names += [
            f"branch-count-{count}-{distribution}"
            for count in (4, 8) for distribution in RUNG_DISTRIBUTIONS
        ]
    return names


def _scenario_entry(name, *, forbidden, groups, branch_count,
                    index_variant="baseline-no-presence"):
    return {
        "description": f"synthetic {name}",
        "node_count": 4,
        "branch_count": branch_count,
        "expected_count": 0,
        "groups": list(groups),
        "dn_mode": "long-canonical-all-miss",
        "logical_outer_cohort_count": 0,
        "relevant_values_per_entry": 0,
        "rendered_bytes": 100,
        "simple_sdn2_branch": False,
        "assertion_counts": {
            "total": branch_count, "live": 0, "absent": branch_count,
            "duplicates": 0, "invalid": 0,
        },
        "index_variant": index_variant,
        "expected_lookup_diagnostic": {
            "applicable": True,
            "expectation": (
                "forbidden" if forbidden else "required-when-lookup-on"
            ),
        },
        "parameters": {"branch_count": branch_count},
    }


def make_workload_manifest(*, extended=False, forbidden_control=True):
    scenarios = {}
    groups = {}

    def add(name, entry):
        scenarios[name] = entry
        for group in entry["groups"]:
            groups.setdefault(group, []).append(name)

    add("branch-count-15-zero-candidate", _scenario_entry(
        "branch-count-15-zero-candidate",
        forbidden=forbidden_control,
        groups=["branch-scaling", "branch-zero-candidate"],
        branch_count=15,
    ))
    for index in range(115):
        add(f"scn-{index:03d}", _scenario_entry(
            f"scn-{index:03d}", forbidden=False, groups=["primary"],
            branch_count=355,
        ))
    if extended:
        for variant in CANARY_VARIANTS:
            add(f"drift-canary-{variant}", _scenario_entry(
                f"drift-canary-{variant}", forbidden=True,
                groups=["drift-canary"], branch_count=8,
                index_variant=variant,
            ))
        for count in (4, 8):
            for distribution in RUNG_DISTRIBUTIONS:
                rung_groups = ["branch-scaling"]
                if distribution == "zero-candidate":
                    rung_groups.append("branch-zero-candidate")
                else:
                    rung_groups.append(f"branch-{distribution}")
                add(f"branch-count-{count}-{distribution}", _scenario_entry(
                    f"branch-count-{count}-{distribution}", forbidden=True,
                    groups=rung_groups, branch_count=count,
                ))
    return {
        "workload_sha256": "w" * 64,
        "scenarios": scenarios,
        "scenario_groups": groups,
    }


def _run_values(spec, repeat):
    if isinstance(spec, (int, float)):
        return [float(spec)] * repeat
    return [float(value) for value in spec]


def _rows(scenario, index_config, elapsed_values, cpu_values, label):
    rows = []
    for iteration, (elapsed, cpu) in enumerate(
            zip(elapsed_values, cpu_values), 1):
        rows.append({
            "phase": "measured",
            "iteration": iteration,
            "scenario": scenario,
            "attribute_variant": "attrs-1.1",
            "index_config": index_config,
            "build_label": label,
            "client_elapsed_ns": int(round(elapsed * 1e9)),
            "server_cpu_seconds": cpu,
            "server_etime_seconds": elapsed * 0.9,
            "rss_kib": 1000,
            "high_water_kib": 1100,
        })
    return rows


def make_screen_tree(
        root, *, repeat=3, openldap=True, layout="toggle", extended=False,
        forbidden_control=True, values=None, created_at=None,
        environments=None, drop_scenarios=(), drop_bundles=()):
    """Build a synthetic screen results tree that satisfies main()'s checks.

    ``values`` maps ``(state, scenario)`` to ``(elapsed, cpu)`` where each
    item is a constant or a per-run list.  ``created_at`` maps
    ``(state, bundle)`` to an ISO timestamp.  ``environments`` maps
    ``(state, bundle)`` to an environment.json payload.
    """
    values = values or {}
    created_at = created_at or {}
    environments = environments or {}
    names = [
        name for name in scenario_names(extended)
        if name not in drop_scenarios
    ]
    manifest = make_workload_manifest(
        extended=extended, forbidden_control=forbidden_control,
    )
    for name in drop_scenarios:
        manifest["scenarios"].pop(name, None)
    defaults = {
        name: (0.1 + index * 1e-4, 0.08)
        for index, name in enumerate(names)
    }
    results = root / "results"
    state_dirs = {}
    if openldap:
        state_dirs["openldap"] = results / "openldap"
    if layout == "toggle":
        state_dirs["custom-off"] = results / "custom-off"
        state_dirs["custom-on"] = results / "custom-on"
    else:
        state_dirs["custom-unsupported"] = results / "custom-unsupported"
    state_dirs["stable"] = results / "fedora-stable"
    harness = {
        "files": {
            "bin/run-full-fedora-screen": "wrapper-hash",
            "study/run_study.py": "core-hash",
        },
        "content_sha256": "harness-hash",
    }
    for state, state_dir in state_dirs.items():
        binary = BINARIES[state_dir.name]
        label = f"{state}-label"
        for bundle_name, index_config in BUNDLE_INDEX_CONFIGS.items():
            if bundle_name in drop_bundles:
                continue
            bundle = state_dir / bundle_name
            bundle.mkdir(parents=True)
            (bundle / "COMPLETE").write_text("completed synthetic\n")
            (bundle / "workload-manifest.json").write_text(
                json.dumps(manifest)
            )
            (bundle / "artifact-manifest.json").write_text(json.dumps({
                "harness_identity": harness,
                "server_executable": {"executable_sha256": binary},
            }))
            stamp = created_at.get((state, bundle_name))
            if stamp is not None:
                (bundle / "run-manifest.json").write_text(json.dumps({
                    "created_at": stamp,
                }))
            environment = environments.get((state, bundle_name))
            if environment is not None:
                (bundle / "environment.json").write_text(
                    json.dumps(environment)
                )
            rows = []

            def emit(scenario, row_index_config):
                spec = values.get((state, scenario), defaults[scenario])
                rows.extend(_rows(
                    scenario, row_index_config,
                    _run_values(spec[0], repeat),
                    _run_values(spec[1], repeat),
                    label,
                ))

            if bundle_name == "baseline-core":
                for scenario in names:
                    if scenario.startswith("drift-canary-"):
                        continue
                    emit(scenario, "baseline-no-presence")
            if extended:
                canary = f"drift-canary-{index_config}"
                if canary in manifest["scenarios"]:
                    emit(canary, index_config)
            (bundle / "raw-results.json").write_text(json.dumps({
                "rows": rows,
            }))
    return results


def render(results, *, repeat=3, layout="toggle", openldap=True):
    return main([
        str(results), str(repeat), "c" * 40, "3.3.0-synthetic",
        "3.2.2-synthetic", layout, "on" if openldap else "off",
        "2.6.13-synthetic" if openldap else "",
    ])


class MathHelperTests(unittest.TestCase):
    def test_mann_whitney_matches_reference_values(self):
        result = mann_whitney_u([1.0, 2.0], [3.0, 4.0])
        self.assertEqual(result["u"], 0.0)
        self.assertAlmostEqual(result["z"], -1.161895, places=5)
        self.assertAlmostEqual(result["p_two_sided"], 0.245278, places=5)
        mirrored = mann_whitney_u([3.0, 4.0], [1.0, 2.0])
        self.assertAlmostEqual(mirrored["z"], 1.161895, places=5)

    def test_mann_whitney_all_tied_degenerates(self):
        result = mann_whitney_u([5.0, 5.0], [5.0, 5.0])
        self.assertEqual(result["z"], 0.0)
        self.assertEqual(result["p_two_sided"], 1.0)
        self.assertEqual(result["u"], 2.0)

    def test_mann_whitney_empty_side_is_unavailable(self):
        result = mann_whitney_u([], [1.0])
        self.assertIsNone(result["u"])
        self.assertIsNone(result["p_two_sided"])

    def test_least_squares_exact_fit(self):
        fit = least_squares_slope([1, 2, 3], [2.0, 4.0, 6.0])
        self.assertAlmostEqual(fit["slope"], 2.0)
        self.assertAlmostEqual(fit["intercept"], 0.0)
        self.assertAlmostEqual(fit["r2"], 1.0)
        self.assertIsNone(least_squares_slope([1], [2.0]))
        self.assertIsNone(least_squares_slope([1, 1], [2.0, 3.0]))

    def test_noise_yardstick_band_is_max_abs_delta(self):
        yardstick = compute_noise_yardstick(
            [1.0, -5.0, 2.0], [0.5, None, -1.0],
            strata_count=3, scenarios=["a", "b", "c"],
        )
        self.assertEqual(yardstick["status"], "available")
        self.assertEqual(yardstick["elapsed_band_percent"], 5.0)
        self.assertEqual(yardstick["cpu_band_percent"], 1.0)
        self.assertEqual(yardstick["median_abs_elapsed_delta_percent"], 2.0)
        self.assertEqual(yardstick["median_abs_cpu_delta_percent"], 0.75)

    def test_noise_yardstick_unavailable_without_deltas(self):
        yardstick = compute_noise_yardstick(
            [], [], strata_count=0, scenarios=[],
        )
        self.assertEqual(yardstick["status"], "unavailable")
        self.assertIsNone(yardstick["elapsed_band_percent"])

    def test_noise_flags_and_coherence(self):
        self.assertEqual(noise_flags(6.0, 5.0), ("†", "exceeds-noise"))
        self.assertEqual(noise_flags(5.0, 5.0), ("~", "within-noise"))
        self.assertEqual(noise_flags(None, 5.0), ("", "n/a"))
        self.assertEqual(noise_flags(3.0, None), ("", "n/a"))
        self.assertEqual(
            delta_coherence("exceeds-noise", "exceeds-noise"), "coherent"
        )
        self.assertEqual(
            delta_coherence("exceeds-noise", "within-noise"), "elapsed-only"
        )
        self.assertEqual(
            delta_coherence("within-noise", "exceeds-noise"), "cpu-only"
        )
        self.assertEqual(
            delta_coherence("within-noise", "within-noise"), "within-noise"
        )
        self.assertEqual(delta_coherence("n/a", "exceeds-noise"), "n/a")

    def test_relative_spread(self):
        self.assertAlmostEqual(relative_spread(0.12, 0.1), 0.2)
        self.assertIsNone(relative_spread(None, 0.1))
        self.assertIsNone(relative_spread(0.12, 0))


class EnvironmentSummaryTests(unittest.TestCase):
    def test_aggregation_and_degradation(self):
        record = {
            "start": {
                "kernel": "6.15.0", "loadavg": [0.4, 0.3, 0.2],
                "cpufreq_governors": {"cpu0": "performance"},
            },
            "end": {
                "kernel": "6.15.0", "loadavg": [1.5, 0.9, 0.5],
                "cpufreq_governors": {"cpu0": "performance"},
            },
            "deltas": {
                "cpu_steal_ticks": 4,
                "thermal_throttle": {"cpu0": {"core_throttle_count": 2}},
            },
        }
        summary = summarize_environment_captures({
            ("custom-off", "baseline-core"): record,
            ("custom-off", "presence-sdn1"): None,
            ("stable", "baseline-core"): None,
        })
        off = summary["custom-off"]
        self.assertEqual(off["bundles_total"], 2)
        self.assertEqual(off["bundles_with_capture"], 1)
        self.assertEqual(off["kernels"], ["6.15.0"])
        self.assertEqual(off["governors"], ["performance"])
        self.assertEqual(off["cpu_steal_ticks_delta_total"], 4)
        self.assertEqual(off["thermal_throttle_events"], 2)
        self.assertEqual(off["max_loadavg_1m"], 1.5)
        stable = summary["stable"]
        self.assertEqual(stable["bundles_with_capture"], 0)
        self.assertEqual(stable["kernels"], "unavailable")
        self.assertEqual(
            stable["cpu_steal_ticks_delta_total"], "unavailable"
        )


class AttemptHygieneTests(unittest.TestCase):
    def test_parses_hyphenated_states_and_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            incomplete = Path(tmp) / "incomplete"
            logs.mkdir()
            incomplete.mkdir()
            for name in (
                    "custom-off-baseline-core-attempt1.log",
                    "custom-off-baseline-core-attempt2.log",
                    "fedora-stable-presence-sdn2-attempt1.log",
                    "junk-attempt1.log",
                    "provenance-preflight.log"):
                (logs / name).write_text("log\n")
            for name in (
                    "custom-off-baseline-core-attempt1-"
                    "20260722T000000Z-1-2",
                    "fedora-stable-presence-sdn2-preexisting-"
                    "20260722T000001Z-3-4",
                    "garbage-directory"):
                (incomplete / name).mkdir()
            completed = {
                ("custom-off", "baseline-core"),
                ("fedora-stable", "presence-sdn2"),
            }
            hygiene = collect_attempt_hygiene(logs, incomplete, completed)
        self.assertEqual(hygiene["status"], "available")
        core = hygiene["states"]["custom-off"]["baseline-core"]
        self.assertEqual(core["attempts_observed"], [1, 2])
        self.assertEqual(core["attempt_used"], 2)
        self.assertEqual(core["archived"][0]["reason"], "attempt1")
        sdn2 = hygiene["states"]["fedora-stable"]["presence-sdn2"]
        self.assertEqual(sdn2["attempt_used"], 1)
        self.assertEqual(sdn2["archived"][0]["reason"], "preexisting")
        self.assertEqual(
            hygiene["unrecognized_log_files"], ["junk-attempt1.log"]
        )
        self.assertEqual(
            hygiene["unrecognized_archives"], ["garbage-directory"]
        )

    def test_unavailable_without_directories(self):
        hygiene = collect_attempt_hygiene(
            Path("/nonexistent-a"), Path("/nonexistent-b"),
            {("custom-off", "baseline-core")},
        )
        self.assertEqual(hygiene["status"], "unavailable")


class ScreenTreeRenderTests(unittest.TestCase):
    def test_end_to_end_writes_all_output_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root)
            self.assertEqual(render(results), 0)
            for name in (
                    "REPORT.md", "summary.csv", "comparisons.csv",
                    "openldap-context.csv", "screen-summary.json",
                    "statistical-appendix.md"):
                self.assertTrue((root / name).is_file(), name)
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertEqual(summary["scenario_count"], 116)
        self.assertEqual(summary["attribute_strata_count"], 116)
        for key in (
                "provenance", "noise_yardstick", "environment_capture",
                "attempt_hygiene", "statistical_appendix"):
            self.assertIn(key, summary)

    def test_csv_headers_keep_legacy_prefix_with_appended_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root)
            render(results)
            with (root / "summary.csv").open() as stream:
                summary_header = next(csv.reader(stream))
            with (root / "comparisons.csv").open() as stream:
                reader = csv.reader(stream)
                comparison_header = next(reader)
                comparison_rows = list(reader)
        self.assertEqual(summary_header[:12], [
            "state", "index_config", "scenario", "attribute_variant",
            "filter_structure", "measured_runs", "median_elapsed_seconds",
            "p95_elapsed_seconds", "median_server_cpu_seconds",
            "median_server_etime_seconds", "median_rss_kib",
            "median_high_water_kib",
        ])
        self.assertEqual(summary_header[12:], [
            "elapsed_relative_spread", "cpu_relative_spread",
        ])
        self.assertEqual(comparison_header[13:], [
            "elapsed_noise_flag", "cpu_noise_flag", "delta_coherence",
        ])
        for row in comparison_rows:
            if row[0] != "custom-off-to-custom-on":
                self.assertEqual(row[13:], ["n/a", "n/a", "n/a"], row[0])

    def test_invariant_wrong_bundle_set_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = make_screen_tree(
                Path(tmp), drop_bundles=("presence-both",),
            )
            with self.assertRaisesRegex(RuntimeError, "expected bundles"):
                render(results)

    def test_invariant_row_count_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = make_screen_tree(Path(tmp), repeat=3)
            with self.assertRaisesRegex(RuntimeError, "measured rows"):
                render(results, repeat=4)

    def test_invariant_scenario_count_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = make_screen_tree(
                Path(tmp), drop_scenarios=("scn-114",),
            )
            with self.assertRaisesRegex(
                    RuntimeError, "expected 116 or 132"):
                render(results)

    def test_noise_markers_and_coherence_in_report(self):
        values = {
            ("custom-on", "branch-count-15-zero-candidate"): (0.105, 0.084),
            ("custom-on", "scn-000"): (0.02, 0.016),
            ("custom-on", "scn-002"): (0.05, None),
        }
        # scn-002 keeps the default CPU so only elapsed exceeds the band.
        values[("custom-on", "scn-002")] = (0.05, 0.08)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root, values=values)
            render(results)
            report = (root / "REPORT.md").read_text()
            comparisons = list(csv.DictReader(
                (root / "comparisons.csv").open()
            ))
        self.assertIn("Noise band (off -> on, over 1 no-effect strata)", report)
        self.assertIn("elapsed ±5.00%", report)
        self.assertIn("CPU ±5.00%", report)
        big_win = next(
            line for line in report.splitlines() if "| scn-000 |" in line
        )
        self.assertIn("80.0%† / 80.0%†", big_win)
        self.assertNotIn("‡", big_win)
        # stable -> off benefit cell in the same row stays unmarked.
        self.assertIn("| 0.0% / 0.0% |", big_win)
        quiet = next(
            line for line in report.splitlines() if "| scn-001 |" in line
        )
        self.assertIn("0.0%~ / 0.0%~", quiet)
        incoherent = next(
            line for line in report.splitlines() if "| scn-002 |" in line
        )
        self.assertIn("†", incoherent)
        self.assertIn("‡", incoherent)
        self.assertIn("Off -> on benefit markers", report)
        flagged = next(
            row for row in comparisons
            if row["comparison"] == "custom-off-to-custom-on"
            and row["scenario"] == "scn-002"
        )
        self.assertEqual(flagged["elapsed_noise_flag"], "exceeds-noise")
        self.assertEqual(flagged["cpu_noise_flag"], "within-noise")
        self.assertEqual(flagged["delta_coherence"], "elapsed-only")

    def test_noise_unavailable_without_forbidden_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root, forbidden_control=False)
            render(results)
            report = (root / "REPORT.md").read_text()
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertIn("- Noise band: unavailable", report)
        self.assertNotIn("†", report)
        self.assertNotIn("‡", report)
        self.assertEqual(summary["noise_yardstick"]["status"], "unavailable")

    def test_unsupported_layout_has_no_markers_and_degrades_appendix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(
                root, layout="unsupported", openldap=False,
            )
            self.assertEqual(
                render(results, layout="unsupported", openldap=False), 0
            )
            report = (root / "REPORT.md").read_text()
            appendix = (root / "statistical-appendix.md").read_text()
        self.assertNotIn("†", report)
        self.assertIn("- Noise band: unavailable", report)
        self.assertIn(
            "Unavailable: this run's custom build has no off/on lookup",
            appendix,
        )

    def test_provenance_rendering_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root)
            render(results)
            report = (root / "REPORT.md").read_text()
            self.assertIn("- Provenance: unavailable", report)

            (root / "provenance.json").write_text(json.dumps({
                "match": True,
                "expected_source": {"resolved_sha": "c" * 40},
                "observed_source": {"resolved_sha": "c" * 40},
                "ancestor_check": {"observed_is_ancestor_of_head": True},
                "repo_describe": "v1-synthetic",
            }))
            render(results)
            report = (root / "REPORT.md").read_text()
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertIn(
            "- Provenance: asserted source matches the installed RPM", report
        )
        self.assertIn("ancestor of harness HEAD: yes", report)
        self.assertEqual(summary["provenance"]["status"], "asserted-match")
        self.assertEqual(
            summary["provenance"]["repo_describe"], "v1-synthetic"
        )

    def test_provenance_observed_only_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root)
            (root / "provenance.json").write_text(json.dumps({
                "match": None,
                "expected_source": {"resolved_sha": None},
                "observed_source": {"resolved_sha": "d" * 40},
                "ancestor_check": {"observed_is_ancestor_of_head": None},
            }))
            render(results)
            report = (root / "REPORT.md").read_text()
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertIn(
            "- Provenance warning: LF_EXPECTED_SOURCE was not set", report
        )
        self.assertEqual(summary["provenance"]["status"], "observed-only")

    def test_environment_capture_aggregated_and_degraded(self):
        environment = {
            "start": {
                "kernel": "6.15.0-synthetic",
                "loadavg": [0.5, 0.4, 0.3],
                "cpufreq_governors": {"cpu2": "performance"},
            },
            "end": {
                "kernel": "6.15.0-synthetic",
                "loadavg": [0.9, 0.6, 0.4],
                "cpufreq_governors": {"cpu2": "performance"},
            },
            "deltas": {
                "cpu_steal_ticks": 3,
                "thermal_throttle": {"cpu2": {"core_throttle_count": 1}},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root, environments={
                ("custom-off", "baseline-core"): environment,
            })
            render(results)
            report = (root / "REPORT.md").read_text()
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertIn("## Environment capture", report)
        self.assertIn("custom-off: 1/10 bundles captured", report)
        self.assertIn("- custom-on: unavailable (no capture)", report)
        capture = summary["environment_capture"]
        self.assertEqual(capture["bundles_with_capture"], 1)
        self.assertEqual(
            capture["states"]["custom-off"]["cpu_steal_ticks_delta_total"], 3
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root)
            render(results)
            report = (root / "REPORT.md").read_text()
            summary = json.loads((root / "screen-summary.json").read_text())
        self.assertIn("Environment capture: unavailable", report)
        self.assertEqual(summary["environment_capture"], "unavailable")

    def test_appendix_sections_and_cross_state_anchor(self):
        created = {
            (state, "baseline-branch-scaling"):
                f"2026-07-22T0{index}:00:00Z"
            for index, state in enumerate(
                ("openldap", "custom-off", "custom-on", "stable"))
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root, created_at=created)
            render(results)
            appendix = (root / "statistical-appendix.md").read_text()
            report = (root / "REPORT.md").read_text()
        self.assertIn("## Off -> on per-stratum tests", appendix)
        self.assertIn("### elapsed", appendix)
        self.assertIn("### server CPU", appendix)
        self.assertIn("## Zero-candidate CPU vs branch count", appendix)
        self.assertIn("## Within-bundle drift", appendix)
        self.assertIn("## Cross-bundle wall-clock drift", appendix)
        self.assertIn("branch-count-15-zero-candidate", appendix)
        self.assertIn("2026-07-22T01:00:00Z", appendix)
        self.assertIn(
            "- Statistical appendix: `statistical-appendix.md`", report
        )

    def test_appendix_effect_and_test_columns(self):
        values = {
            ("custom-on", "scn-000"): (0.02, 0.016),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(root, values=values)
            render(results)
            appendix = (root / "statistical-appendix.md").read_text()
        line = next(
            text for text in appendix.splitlines()
            if text.startswith("| baseline-no-presence | scn-000 |")
        )
        self.assertIn("+80.100", line)
        self.assertIn("on-faster", line)

    def test_extended_workload_canary_and_drift_track(self):
        created = {}
        for state in ("openldap", "custom-off", "custom-on", "stable"):
            for index, bundle in enumerate(BUNDLE_INDEX_CONFIGS):
                created[(state, bundle)] = (
                    f"2026-07-22T10:{index:02d}:00Z"
                )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = make_screen_tree(
                root, extended=True, created_at=created,
            )
            self.assertEqual(render(results), 0)
            summary = json.loads((root / "screen-summary.json").read_text())
            appendix = (root / "statistical-appendix.md").read_text()
            with (root / "summary.csv").open() as stream:
                rows = list(csv.DictReader(stream))
        self.assertEqual(summary["scenario_count"], 132)
        canary_row = next(
            row for row in rows
            if row["state"] == "custom-off"
            and row["scenario"] == "drift-canary-baseline-no-presence"
        )
        # Five baseline bundles each contribute one repeat block.
        self.assertEqual(canary_row["measured_runs"], "15")
        self.assertIn("Per-bundle medians of the drift-canary scenario", appendix)
        self.assertIn("### custom-off", appendix)
        self.assertIn("Elapsed trend:", appendix)
        self.assertIn("below threshold", appendix)


class RegenerateCliTests(unittest.TestCase):
    def _hashes(self, root):
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.iterdir() if path.is_file()
        }

    def test_recovers_inputs_and_leaves_source_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            results = make_screen_tree(root)
            render(results)
            before = self._hashes(root)
            output = Path(tmp) / "regen"
            self.assertEqual(
                regenerate_main([str(root), "--output", str(output)]), 0
            )
            self.assertEqual(self._hashes(root), before)
            for name in ("REPORT.md", "summary.csv", "screen-summary.json"):
                self.assertTrue((output / name).is_file(), name)
            self.assertEqual(
                (output / "REPORT.md").read_text(),
                (root / "REPORT.md").read_text(),
            )

    def test_refuses_nonempty_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            results = make_screen_tree(root)
            render(results)
            output = Path(tmp) / "occupied"
            output.mkdir()
            (output / "marker").write_text("x")
            with self.assertRaises(SystemExit) as raised:
                regenerate_main([str(root), "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)

    def test_requires_repeat_when_summary_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            results = make_screen_tree(root)
            output = Path(tmp) / "regen"
            with self.assertRaises(SystemExit) as raised:
                regenerate_main([str(root), "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(
                regenerate_main([
                    str(root), "--output", str(output), "--repeat", "3",
                ]),
                0,
            )
            del results

    def test_in_place_writes_into_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            make_screen_tree(root)
            self.assertEqual(
                regenerate_main([str(root), "--in-place", "--repeat", "3"]),
                0,
            )
            self.assertTrue((root / "REPORT.md").is_file())


if __name__ == "__main__":
    unittest.main()
