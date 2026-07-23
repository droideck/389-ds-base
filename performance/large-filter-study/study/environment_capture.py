"""Best-effort host environment capture for one result bundle.

The runner snapshots the environment right after the bundle is opened and
again after the last artifact write, then stores both plus deltas in an
``environment.json`` sidecar inside the bundle.  Every source degrades to
``"unavailable"`` independently; capture never raises and never touches any
timed section.
"""

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

FORMAT_VERSION = 1
UNAVAILABLE = "unavailable"


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_kernel(proc_root):
    try:
        version = (proc_root / "version").read_text().strip()
    except OSError:
        version = ""
    if version:
        return version
    try:
        release = platform.release()
    except Exception:
        release = ""
    return release or UNAVAILABLE


def _read_governors(sys_root):
    governors = {}
    try:
        cpus = sorted((sys_root / "devices/system/cpu").glob("cpu[0-9]*"))
    except OSError:
        cpus = []
    for cpu in cpus:
        try:
            value = (cpu / "cpufreq/scaling_governor").read_text().strip()
        except OSError:
            continue
        if value:
            governors[cpu.name] = value
    return governors or UNAVAILABLE


def _read_loadavg(proc_root):
    try:
        fields = (proc_root / "loadavg").read_text().split()
        return [float(field) for field in fields[:3]]
    except (OSError, ValueError, IndexError):
        return UNAVAILABLE


def _read_cpu_ticks(proc_root):
    try:
        for line in (proc_root / "stat").read_text().splitlines():
            if line.startswith("cpu "):
                fields = [int(field) for field in line.split()[1:]]
                if len(fields) < 8:
                    return UNAVAILABLE
                return {
                    "steal_ticks": fields[7],
                    "total_ticks": sum(fields),
                }
    except (OSError, ValueError):
        pass
    return UNAVAILABLE


def _read_thermal_throttle(sys_root):
    counters = {}
    try:
        cpus = sorted((sys_root / "devices/system/cpu").glob("cpu[0-9]*"))
    except OSError:
        cpus = []
    for cpu in cpus:
        throttle_dir = cpu / "thermal_throttle"
        if not throttle_dir.is_dir():
            continue
        per_cpu = {}
        try:
            entries = sorted(throttle_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith("_count"):
                continue
            try:
                per_cpu[entry.name] = int(entry.read_text().strip())
            except (OSError, ValueError):
                continue
        if per_cpu:
            counters[cpu.name] = per_cpu
    return counters or UNAVAILABLE


def capture_environment_snapshot(*, proc_root=Path("/proc"), sys_root=Path("/sys")):
    return {
        "captured_at": _utc_now(),
        "kernel": _read_kernel(proc_root),
        "cpufreq_governors": _read_governors(sys_root),
        "loadavg": _read_loadavg(proc_root),
        "cpu_ticks": _read_cpu_ticks(proc_root),
        "thermal_throttle": _read_thermal_throttle(sys_root),
    }


def _tick_delta(start, end, key):
    if not isinstance(start, dict) or not isinstance(end, dict):
        return UNAVAILABLE
    if key not in start or key not in end:
        return UNAVAILABLE
    return end[key] - start[key]


def _throttle_delta(start, end):
    if not isinstance(start, dict) or not isinstance(end, dict):
        return UNAVAILABLE
    deltas = {}
    for cpu, end_counters in end.items():
        start_counters = start.get(cpu)
        if not isinstance(start_counters, dict):
            continue
        per_cpu = {
            name: value - start_counters[name]
            for name, value in end_counters.items()
            if name in start_counters
        }
        if per_cpu:
            deltas[cpu] = per_cpu
    return deltas or UNAVAILABLE


def build_environment_record(start, end, *, run_id, perf_mode, profile_mode):
    return {
        "format_version": FORMAT_VERSION,
        "run_id": run_id,
        "perf_mode": perf_mode,
        "profile_mode": profile_mode,
        "start": start,
        "end": end,
        "deltas": {
            "cpu_steal_ticks": _tick_delta(
                start.get("cpu_ticks"), end.get("cpu_ticks"), "steal_ticks"
            ),
            "cpu_total_ticks": _tick_delta(
                start.get("cpu_ticks"), end.get("cpu_ticks"), "total_ticks"
            ),
            "thermal_throttle": _throttle_delta(
                start.get("thermal_throttle"), end.get("thermal_throttle")
            ),
        },
    }


def write_environment_sidecar(output_dir, record):
    (Path(output_dir) / "environment.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
