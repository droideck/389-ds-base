"""Contracts for the per-bundle environment sidecar capture."""

from __future__ import annotations

import json
import tempfile
import unittest

from pathlib import Path


STUDY_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(STUDY_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDY_ROOT))

from study.environment_capture import (  # noqa: E402
    build_environment_record,
    capture_environment_snapshot,
    write_environment_sidecar,
)


def make_fake_host(root: Path, *, cpus: int = 2, steal: int = 7,
                   throttle: int = 3) -> tuple[Path, Path]:
    proc = root / "proc"
    sysfs = root / "sys"
    proc.mkdir()
    (proc / "version").write_text(
        "Linux version 6.15.0-synthetic (build@host)\n"
    )
    (proc / "loadavg").write_text("0.42 0.36 0.30 1/234 5678\n")
    (proc / "stat").write_text(
        f"cpu  100 0 50 1000 5 0 2 {steal} 0 0\n"
        "cpu0 50 0 25 500 2 0 1 3 0 0\n"
    )
    for index in range(cpus):
        cpu_dir = sysfs / "devices/system/cpu" / f"cpu{index}"
        (cpu_dir / "cpufreq").mkdir(parents=True)
        (cpu_dir / "cpufreq" / "scaling_governor").write_text("performance\n")
        (cpu_dir / "thermal_throttle").mkdir()
        (cpu_dir / "thermal_throttle" / "core_throttle_count").write_text(
            f"{throttle}\n"
        )
    return proc, sysfs


class SnapshotTests(unittest.TestCase):
    def test_snapshot_reads_fake_host_fully(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, sysfs = make_fake_host(Path(tmp))
            snapshot = capture_environment_snapshot(
                proc_root=proc, sys_root=sysfs,
            )
        self.assertIn("6.15.0-synthetic", snapshot["kernel"])
        self.assertEqual(
            snapshot["cpufreq_governors"],
            {"cpu0": "performance", "cpu1": "performance"},
        )
        self.assertEqual(snapshot["loadavg"], [0.42, 0.36, 0.3])
        self.assertEqual(snapshot["cpu_ticks"]["steal_ticks"], 7)
        self.assertEqual(snapshot["cpu_ticks"]["total_ticks"], 1164)
        self.assertEqual(
            snapshot["thermal_throttle"]["cpu0"]["core_throttle_count"], 3
        )

    def test_each_source_degrades_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, sysfs = make_fake_host(Path(tmp))
            (proc / "loadavg").unlink()
            (proc / "stat").write_text("garbage\n")
            for cpu in (sysfs / "devices/system/cpu").iterdir():
                governor = cpu / "cpufreq" / "scaling_governor"
                governor.unlink()
            snapshot = capture_environment_snapshot(
                proc_root=proc, sys_root=sysfs,
            )
        self.assertEqual(snapshot["loadavg"], "unavailable")
        self.assertEqual(snapshot["cpu_ticks"], "unavailable")
        self.assertEqual(snapshot["cpufreq_governors"], "unavailable")
        self.assertIn("6.15.0-synthetic", snapshot["kernel"])
        self.assertNotEqual(snapshot["thermal_throttle"], "unavailable")

    def test_missing_roots_never_raise(self):
        missing = Path("/nonexistent-environment-capture-root")
        snapshot = capture_environment_snapshot(
            proc_root=missing, sys_root=missing,
        )
        self.assertEqual(snapshot["loadavg"], "unavailable")
        self.assertEqual(snapshot["cpu_ticks"], "unavailable")
        self.assertEqual(snapshot["cpufreq_governors"], "unavailable")
        self.assertEqual(snapshot["thermal_throttle"], "unavailable")


class RecordTests(unittest.TestCase):
    def test_deltas_computed_from_paired_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, sysfs = make_fake_host(Path(tmp), steal=7, throttle=3)
            start = capture_environment_snapshot(
                proc_root=proc, sys_root=sysfs,
            )
            (proc / "stat").write_text(
                "cpu  200 0 90 2000 8 0 4 19 0 0\n"
            )
            for cpu in (sysfs / "devices/system/cpu").iterdir():
                counter = cpu / "thermal_throttle" / "core_throttle_count"
                counter.write_text("5\n")
            end = capture_environment_snapshot(
                proc_root=proc, sys_root=sysfs,
            )
        record = build_environment_record(
            start, end, run_id="run-1", perf_mode="off", profile_mode="off",
        )
        self.assertEqual(record["format_version"], 1)
        self.assertEqual(record["run_id"], "run-1")
        self.assertEqual(record["deltas"]["cpu_steal_ticks"], 12)
        self.assertEqual(
            record["deltas"]["thermal_throttle"]["cpu0"][
                "core_throttle_count"
            ],
            2,
        )

    def test_unavailable_inputs_propagate_to_deltas(self):
        start = {
            "cpu_ticks": "unavailable", "thermal_throttle": "unavailable",
        }
        end = dict(start)
        record = build_environment_record(
            start, end, run_id="run-2", perf_mode="auto", profile_mode="off",
        )
        self.assertEqual(record["deltas"]["cpu_steal_ticks"], "unavailable")
        self.assertEqual(
            record["deltas"]["thermal_throttle"], "unavailable"
        )

    def test_sidecar_written_as_environment_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = build_environment_record(
                {}, {}, run_id="run-3", perf_mode="off", profile_mode="off",
            )
            write_environment_sidecar(Path(tmp), record)
            loaded = json.loads(
                (Path(tmp) / "environment.json").read_text()
            )
        self.assertEqual(loaded["run_id"], "run-3")


if __name__ == "__main__":
    unittest.main()
