"""Render the full-screen summary artifacts from completed result bundles.

Extracted verbatim from the summarizer stage of bin/run-full-fedora-screen so
the same rendering can be unit tested and re-run against an existing screen
output directory (see bin/regenerate-screen-report).  Argument order matches
the wrapper invocation: results root, repeat, custom sha, custom
version-release, stable version-release, custom lookup layout, openldap
on/off, openldap version-release.
"""

import argparse
import csv
import json
import math
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

UNAVAILABLE = "unavailable"
NOISE_STATISTIC = "max-abs-off-on-benefit-percent-across-no-effect-strata"


def compute_noise_yardstick(elapsed_deltas, cpu_deltas, *, strata_count, scenarios):
    """Summarize off->on deltas over strata where the lookup cannot engage.

    The band per metric is the maximum absolute benefit percentage across the
    no-effect strata: any of those strata's observed delta is pure noise, so
    the largest one bounds what a zero-effect stratum can show.  At the
    current stratum counts the harness's nearest-rank p95 equals this
    maximum, making max the conservative choice.
    """
    elapsed = [abs(value) for value in elapsed_deltas if value is not None]
    cpu = [abs(value) for value in cpu_deltas if value is not None]
    status = "available" if (elapsed or cpu) else "unavailable"
    return {
        "status": status,
        "no_effect_strata_count": strata_count,
        "no_effect_scenarios": list(scenarios),
        "elapsed_band_percent": max(elapsed) if elapsed else None,
        "cpu_band_percent": max(cpu) if cpu else None,
        "median_abs_elapsed_delta_percent": (
            statistics.median(elapsed) if elapsed else None
        ),
        "median_abs_cpu_delta_percent": (
            statistics.median(cpu) if cpu else None
        ),
        "statistic": NOISE_STATISTIC,
    }


def noise_flags(benefit_value, band):
    """Return the in-cell marker and CSV flag for one benefit percentage."""
    if benefit_value is None or band is None:
        return "", "n/a"
    if abs(benefit_value) > band:
        return "†", "exceeds-noise"
    return "~", "within-noise"


def delta_coherence(elapsed_flag, cpu_flag):
    if "n/a" in (elapsed_flag, cpu_flag):
        return "n/a"
    if elapsed_flag == "exceeds-noise" and cpu_flag == "exceeds-noise":
        return "coherent"
    if elapsed_flag == "exceeds-noise":
        return "elapsed-only"
    if cpu_flag == "exceeds-noise":
        return "cpu-only"
    return "within-noise"


def relative_spread(p95, median):
    if p95 is None or median in (None, 0):
        return None
    return (p95 - median) / median


def mann_whitney_u(a, b):
    """Two-sided Mann-Whitney U via the tie-corrected normal approximation.

    Returns {u, z, p_two_sided, method}.  With n=15 per side the normal
    approximation with midranks, tie-corrected variance, and a 0.5 continuity
    correction is accurate to well past the resolution this report needs; no
    exact permutation p-value is computed.  All-tied inputs degenerate to
    z=0, p=1.
    """
    n1 = len(a)
    n2 = len(b)
    if n1 == 0 or n2 == 0:
        return {
            "u": None, "z": None, "p_two_sided": None,
            "method": "normal-approximation-tie-corrected",
        }
    combined = sorted(
        ((value, 0) for value in a), key=lambda item: item[0]
    ) + sorted(((value, 1) for value in b), key=lambda item: item[0])
    combined.sort(key=lambda item: item[0])
    total = n1 + n2
    ranks = [0.0] * total
    tie_correction = 0.0
    position = 0
    while position < total:
        end = position
        while (
            end + 1 < total
            and combined[end + 1][0] == combined[position][0]
        ):
            end += 1
        midrank = (position + end) / 2 + 1
        for index in range(position, end + 1):
            ranks[index] = midrank
        tie_size = end - position + 1
        tie_correction += tie_size ** 3 - tie_size
        position = end + 1
    rank_sum_a = sum(
        rank for rank, (_, side) in zip(ranks, combined) if side == 0
    )
    u_a = rank_sum_a - n1 * (n1 + 1) / 2
    mean_u = n1 * n2 / 2
    variance = (
        n1 * n2 / 12
        * ((total + 1) - tie_correction / (total * (total - 1)))
    )
    if variance <= 0:
        return {
            "u": u_a, "z": 0.0, "p_two_sided": 1.0,
            "method": "normal-approximation-tie-corrected",
        }
    correction = 0.5 if u_a != mean_u else 0.0
    z = (u_a - mean_u - correction * (1 if u_a > mean_u else -1)) / math.sqrt(
        variance
    )
    p_two_sided = math.erfc(abs(z) / math.sqrt(2))
    return {
        "u": u_a, "z": z, "p_two_sided": p_two_sided,
        "method": "normal-approximation-tie-corrected",
    }


def least_squares_slope(xs, ys):
    """Ordinary least squares fit; returns {slope, intercept, r2} or None."""
    points = [
        (float(x), float(y)) for x, y in zip(xs, ys)
        if x is not None and y is not None
    ]
    if len(points) < 2:
        return None
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    sxx = sum((x - mean_x) ** 2 for x, _ in points)
    if sxx == 0:
        return None
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in points)
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    syy = sum((y - mean_y) ** 2 for _, y in points)
    if syy == 0:
        r2 = 1.0
    else:
        r2 = (sxy * sxy) / (sxx * syy)
    return {"slope": slope, "intercept": intercept, "r2": r2}


def _plain_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_created_at(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


KNOWN_STATES = (
    "custom-off", "custom-on", "custom-unsupported", "fedora-stable",
    "openldap",
)
KNOWN_BUNDLES = (
    "baseline-core", "baseline-branch-scaling",
    "baseline-dn-and-decomposition", "baseline-combined-and-family",
    "baseline-index-controls", "presence-sdn1", "presence-sdn2",
    "presence-both", "without-sdn1-equality", "without-sdn2-equality",
)
_ATTEMPT_LOG_RE = re.compile(r"\A(?P<sb>.+)-attempt(?P<n>\d+)\.log\Z")
_ARCHIVE_RE = re.compile(
    r"\A(?P<sb>.+)-(?P<reason>preexisting|attempt\d+)-"
    r"(?P<stamp>\d{8}T\d{6}Z)-(?P<pid>\d+)-(?P<rand>\d+)\Z"
)


def _split_state_bundle(text):
    """Split a hyphenated <state>-<bundle> token against the known names."""
    for state in KNOWN_STATES:
        prefix = state + "-"
        if text.startswith(prefix) and text[len(prefix):] in KNOWN_BUNDLES:
            return state, text[len(prefix):]
    return None


def collect_attempt_hygiene(logs_dir, incomplete_dir, completed_bundles):
    """Reconstruct per-bundle attempt bookkeeping from the run directory.

    ``completed_bundles`` holds ``(state_dir_name, bundle_name)`` for every
    COMPLETE bundle in the results tree.  Degrades to ``unavailable`` when
    neither ``logs/`` nor ``incomplete/`` sits alongside the results (e.g.
    an old run regenerated without them).
    """
    logs_present = logs_dir is not None and logs_dir.is_dir()
    incomplete_present = incomplete_dir is not None and incomplete_dir.is_dir()
    if not logs_present and not incomplete_present:
        return {
            "status": "unavailable",
            "states": {},
            "unrecognized_log_files": [],
            "unrecognized_archives": [],
        }
    attempts = {}
    unrecognized_logs = []
    if logs_present:
        for entry in sorted(logs_dir.iterdir()):
            match = _ATTEMPT_LOG_RE.match(entry.name)
            if not match:
                continue
            split = _split_state_bundle(match.group("sb"))
            if split is None:
                unrecognized_logs.append(entry.name)
                continue
            attempts.setdefault(split, set()).add(int(match.group("n")))
    archives = {}
    unrecognized_archives = []
    if incomplete_present:
        for entry in sorted(incomplete_dir.iterdir()):
            match = _ARCHIVE_RE.match(entry.name)
            split = (
                _split_state_bundle(match.group("sb")) if match else None
            )
            if split is None:
                unrecognized_archives.append(entry.name)
                continue
            archives.setdefault(split, []).append({
                "reason": match.group("reason"),
                "stamp": match.group("stamp"),
            })
    states = {}
    for state, bundle in sorted(
            set(attempts) | set(archives) | set(completed_bundles)):
        observed = sorted(attempts.get((state, bundle), ()))
        used = None
        if (state, bundle) in completed_bundles and observed:
            used = max(observed)
        states.setdefault(state, {})[bundle] = {
            "attempts_observed": observed,
            "attempt_used": used,
            "archived": archives.get((state, bundle), []),
        }
    return {
        "status": "available",
        "states": states,
        "unrecognized_log_files": unrecognized_logs,
        "unrecognized_archives": unrecognized_archives,
    }


def _write_statistical_appendix(
        path, *, states, layout, repeat, metrics, strata, rows_by_key,
        manifest_scenarios, scenario_groups, canary_rows_by_bundle,
        bundle_created_at):
    canary_ids = set(scenario_groups.get("drift-canary", []))

    def rows_for(state, stratum):
        return rows_by_key.get((state,) + stratum, [])

    def elapsed_values(state, stratum):
        return [
            row["client_elapsed_ns"] / 1e9 for row in rows_for(state, stratum)
        ]

    def cpu_values(state, stratum):
        return [
            row["server_cpu_seconds"] for row in rows_for(state, stratum)
            if row.get("server_cpu_seconds") is not None
        ]

    def fmt(value, digits=6):
        return "n/a" if value is None else f"{value:.{digits}f}"

    lines = []
    lines.append("# Statistical appendix")
    lines.append("")
    lines.append(
        "Generated alongside REPORT.md from the same raw measurement rows. "
        "Mann-Whitney U uses midranks, a tie-corrected variance, a 0.5 "
        "continuity correction, and the two-sided normal approximation "
        f"(n={repeat} per side for single-bundle strata); no exact "
        "permutation p-value and no multiple-comparison correction are "
        "applied - this is a directional screen. Raw measurement rows carry "
        "only monotonic durations, so every temporal ordering below uses "
        "bundle-level run-manifest `created_at` wall-clock timestamps."
    )
    lines.append("")
    lines.append("## Off -> on per-stratum tests")
    lines.append("")
    if layout != "toggle":
        lines.append(
            "Unavailable: this run's custom build has no off/on lookup "
            "toggle."
        )
        lines.append("")
    else:
        for metric_label, values_fn, metric_key in (
                ("elapsed", elapsed_values, "elapsed"),
                ("server CPU", cpu_values, "cpu")):
            lines.append(f"### {metric_label}")
            lines.append("")
            lines.append(
                "| Index | Scenario | Attributes | off median (s) | "
                "on median (s) | effect (ms) | sign | U | z | p |"
            )
            lines.append("|---|---|---|---:|---:|---:|---|---:|---:|---:|")
            for stratum in strata:
                index, scenario, attrs = stratum
                test = mann_whitney_u(
                    values_fn("custom-off", stratum),
                    values_fn("custom-on", stratum),
                )
                off_median = metrics[("custom-off",) + stratum][metric_key]
                on_median = metrics[("custom-on",) + stratum][metric_key]
                if off_median is None or on_median is None:
                    effect_text = "n/a"
                    sign = "n/a"
                else:
                    effect_ms = (off_median - on_median) * 1000.0
                    effect_text = f"{effect_ms:+.3f}"
                    if effect_ms > 0:
                        sign = "on-faster"
                    elif effect_ms < 0:
                        sign = "on-slower"
                    else:
                        sign = "tie"
                lines.append(
                    f"| {index} | {scenario} | {attrs} | {fmt(off_median)} | "
                    f"{fmt(on_median)} | {effect_text} | {sign} | "
                    f"{fmt(test['u'], 1)} | {fmt(test['z'], 3)} | "
                    f"{fmt(test['p_two_sided'], 6)} |"
                )
            lines.append("")
    lines.append("## Zero-candidate CPU vs branch count")
    lines.append("")
    zero_rungs = []
    for stratum in strata:
        value = manifest_scenarios.get(stratum[1], {})
        if "branch-zero-candidate" not in value.get("groups", []):
            continue
        branch = (value.get("parameters") or {}).get("branch_count")
        if branch is None:
            continue
        zero_rungs.append((int(branch), stratum))
    zero_rungs.sort()
    toggle = layout == "toggle"
    if not zero_rungs:
        lines.append("Unavailable: no zero-candidate branch ladder strata.")
        lines.append("")
    else:
        header = "| Branch count |"
        rule = "|---:|"
        for state in states:
            header += f" {state} CPU median (s) |"
            rule += "---:|"
        if toggle:
            header += " off -> on CPU delta (µs) |"
            rule += "---:|"
        lines.append(header)
        lines.append(rule)
        per_state_points = {state: [] for state in states}
        delta_points = []
        for branch, stratum in zero_rungs:
            row_text = f"| {branch} |"
            for state in states:
                cpu_median = metrics[(state,) + stratum]["cpu"]
                per_state_points[state].append((branch, cpu_median))
                row_text += f" {fmt(cpu_median)} |"
            if toggle:
                off_cpu = metrics[("custom-off",) + stratum]["cpu"]
                on_cpu = metrics[("custom-on",) + stratum]["cpu"]
                if off_cpu is None or on_cpu is None:
                    delta_points.append((branch, None))
                    row_text += " n/a |"
                else:
                    delta_seconds = on_cpu - off_cpu
                    delta_points.append((branch, delta_seconds))
                    row_text += f" {delta_seconds * 1e6:+.1f} |"
            lines.append(row_text)
        lines.append("")
        threshold = 16

        def describe_fit(points):
            usable = [
                (branch, value) for branch, value in points
                if value is not None
            ]
            fit = least_squares_slope(
                [branch for branch, _ in usable],
                [value for _, value in usable],
            )
            if fit is None:
                return "n/a"
            return (
                f"{fit['slope'] * 1e6:+.2f} µs/branch (intercept "
                f"{fit['intercept'] * 1e6:+.1f} µs, r² {fit['r2']:.3f}, "
                f"n={len(usable)})"
            )

        for state in states:
            points = per_state_points[state]
            above = [(b, v) for b, v in points if b >= threshold]
            below = [(b, v) for b, v in points if b < threshold]
            text = f"- {state}: CPU slope at/above threshold {describe_fit(above)}"
            if len(below) >= 2:
                text += f"; below threshold {describe_fit(below)}"
            lines.append(text)
        if toggle:
            above = [(b, v) for b, v in delta_points if b >= threshold]
            below = [(b, v) for b, v in delta_points if b < threshold]
            text = (
                "- off -> on CPU delta slope at/above threshold "
                f"{describe_fit(above)}"
            )
            if len(below) >= 2:
                text += f"; below threshold {describe_fit(below)}"
            lines.append(text)
        lines.append(
            f"- The lookup engages at {threshold} same-type equality "
            "branches (FILTER_OR_LOOKUP_THRESHOLD); rungs below that keep "
            "the classic walk in every state."
        )
        lines.append("")
    lines.append("## Within-bundle drift (measured run index vs elapsed)")
    lines.append("")
    trend_rows = []
    for state in states:
        rel_slopes = []
        for stratum in strata:
            if stratum[1] in canary_ids:
                continue
            rows = rows_for(state, stratum)
            fit = least_squares_slope(
                [row.get("iteration") for row in rows],
                [row["client_elapsed_ns"] / 1e9 for row in rows],
            )
            if fit is None:
                continue
            median = metrics[(state,) + stratum]["elapsed"]
            if median in (None, 0):
                continue
            relative = fit["slope"] * (repeat - 1) / median
            rel_slopes.append(relative)
            trend_rows.append((abs(relative), relative, state, stratum))
        if rel_slopes:
            magnitudes = sorted(abs(value) for value in rel_slopes)
            lines.append(
                f"- {state}: median |relative slope| "
                f"{statistics.median(magnitudes) * 100:.2f}%, max "
                f"{magnitudes[-1] * 100:.2f}%, strata over 5%: "
                f"{sum(1 for value in magnitudes if value > 0.05)} of "
                f"{len(magnitudes)}"
            )
        else:
            lines.append(f"- {state}: unavailable")
    trend_rows.sort(key=lambda item: item[0], reverse=True)
    if trend_rows:
        lines.append("")
        lines.append(
            "Top strata by |relative slope| (the fitted elapsed change "
            "across the measured window as a fraction of the stratum "
            "median; descriptive only, not a gate):"
        )
        lines.append("")
        lines.append(
            "| State | Index | Scenario | Attributes | relative slope |"
        )
        lines.append("|---|---|---|---|---:|")
        for _, relative, state, stratum in trend_rows[:10]:
            lines.append(
                f"| {state} | {stratum[0]} | {stratum[1]} | {stratum[2]} | "
                f"{relative * 100:+.2f}% |"
            )
    lines.append("")
    lines.append("## Cross-bundle wall-clock drift")
    lines.append("")
    if canary_rows_by_bundle:
        lines.append(
            "Per-bundle medians of the drift-canary scenario, ordered by "
            "each bundle's run-manifest `created_at`:"
        )
        for state in states:
            entries = []
            for (row_state, bundle_name), rows in sorted(
                    canary_rows_by_bundle.items()):
                if row_state != state or not rows:
                    continue
                elapsed_list = [
                    row["client_elapsed_ns"] / 1e9 for row in rows
                ]
                cpu_list = [
                    row["server_cpu_seconds"] for row in rows
                    if row.get("server_cpu_seconds") is not None
                ]
                created = bundle_created_at.get((state, bundle_name))
                entries.append((
                    _parse_created_at(created), created, bundle_name,
                    rows[0].get("index_config"),
                    statistics.median(elapsed_list) if elapsed_list else None,
                    statistics.median(cpu_list) if cpu_list else None,
                ))
            lines.append("")
            lines.append(f"### {state}")
            lines.append("")
            if not entries:
                lines.append("Unavailable: no canary rows for this state.")
                continue
            entries.sort(key=lambda entry: (
                (0, entry[0].isoformat()) if entry[0] is not None
                else (1, entry[2])
            ))
            lines.append(
                "| Bundle | Index config | created_at | "
                "median elapsed (s) | median CPU (s) |"
            )
            lines.append("|---|---|---|---:|---:|")
            for parsed, created, bundle_name, index_config, med_e, med_c in entries:
                lines.append(
                    f"| {bundle_name} | {index_config} | "
                    f"{created or 'unavailable'} | {fmt(med_e)} | "
                    f"{fmt(med_c)} |"
                )
            timed = [
                (parsed, med_e)
                for parsed, _, _, _, med_e, _ in entries
                if parsed is not None and med_e is not None
            ]
            if len(timed) >= 2:
                start = timed[0][0]
                fit = least_squares_slope(
                    [
                        (parsed - start).total_seconds() / 3600.0
                        for parsed, _ in timed
                    ],
                    [value for _, value in timed],
                )
                state_median = statistics.median(
                    [value for _, value in timed]
                )
                if fit is not None and state_median:
                    lines.append("")
                    lines.append(
                        "Elapsed trend: "
                        f"{fit['slope'] / state_median * 100:+.2f}% per hour "
                        "relative to the state's canary median "
                        f"(r² {fit['r2']:.3f})."
                    )
    else:
        anchor = (
            "baseline-no-presence", "branch-count-15-zero-candidate",
            "attrs-1.1",
        )
        lines.append(
            "No drift-canary scenarios in this workload; falling back to "
            "the cross-state anchor `branch-count-15-zero-candidate` "
            "(cheap, feature-inert, present in every state). Its bundle "
            "(`baseline-branch-scaling`) start time orders the states:"
        )
        lines.append("")
        lines.append(
            "| State | bundle created_at | median elapsed (s) | "
            "median CPU (s) |"
        )
        lines.append("|---|---|---:|---:|")
        for state in states:
            value = metrics.get((state,) + anchor)
            created = bundle_created_at.get(
                (state, "baseline-branch-scaling")
            )
            if value is None:
                lines.append(
                    f"| {state} | {created or 'unavailable'} | n/a | n/a |"
                )
            else:
                lines.append(
                    f"| {state} | {created or 'unavailable'} | "
                    f"{fmt(value['elapsed'])} | {fmt(value['cpu'])} |"
                )
    lines.append("")
    path.write_text("\n".join(lines))


def summarize_environment_captures(environment_captures):
    """Aggregate per-bundle environment.json records into per-state summaries.

    ``environment_captures`` maps ``(state, bundle_name)`` to the parsed
    record or ``None`` when the bundle has no capture.  Every aggregate
    degrades to ``"unavailable"`` when its sources are missing.
    """
    states = {}
    for (state, _bundle), record in sorted(environment_captures.items()):
        summary = states.setdefault(state, {
            "bundles_total": 0,
            "bundles_with_capture": 0,
            "kernels": set(),
            "governors": set(),
            "steal_total": 0,
            "steal_available": False,
            "throttle_total": 0,
            "throttle_available": False,
            "max_loadavg_1m": None,
        })
        summary["bundles_total"] += 1
        if not isinstance(record, dict):
            continue
        summary["bundles_with_capture"] += 1
        for snapshot_key in ("start", "end"):
            snapshot = record.get(snapshot_key)
            if not isinstance(snapshot, dict):
                continue
            kernel = snapshot.get("kernel")
            if isinstance(kernel, str) and kernel != UNAVAILABLE:
                summary["kernels"].add(kernel)
            governors = snapshot.get("cpufreq_governors")
            if isinstance(governors, dict):
                summary["governors"].update(
                    value for value in governors.values()
                    if isinstance(value, str)
                )
            loadavg = snapshot.get("loadavg")
            if isinstance(loadavg, list) and loadavg:
                try:
                    first = float(loadavg[0])
                except (TypeError, ValueError):
                    first = None
                if first is not None and (
                    summary["max_loadavg_1m"] is None
                    or first > summary["max_loadavg_1m"]
                ):
                    summary["max_loadavg_1m"] = first
        deltas = record.get("deltas")
        if isinstance(deltas, dict):
            steal = deltas.get("cpu_steal_ticks")
            if _plain_int(steal):
                summary["steal_total"] += steal
                summary["steal_available"] = True
            throttle = deltas.get("thermal_throttle")
            if isinstance(throttle, dict):
                summary["throttle_available"] = True
                for per_cpu in throttle.values():
                    if isinstance(per_cpu, dict):
                        summary["throttle_total"] += sum(
                            value for value in per_cpu.values()
                            if _plain_int(value)
                        )
    result = {}
    for state, summary in states.items():
        result[state] = {
            "bundles_total": summary["bundles_total"],
            "bundles_with_capture": summary["bundles_with_capture"],
            "kernels": sorted(summary["kernels"]) or UNAVAILABLE,
            "governors": sorted(summary["governors"]) or UNAVAILABLE,
            "cpu_steal_ticks_delta_total": (
                summary["steal_total"]
                if summary["steal_available"] else UNAVAILABLE
            ),
            "thermal_throttle_events": (
                summary["throttle_total"]
                if summary["throttle_available"] else UNAVAILABLE
            ),
            "max_loadavg_1m": (
                summary["max_loadavg_1m"]
                if summary["max_loadavg_1m"] is not None else UNAVAILABLE
            ),
        }
    return result


def main(argv=None):
    args = list(argv) if argv is not None else sys.argv[1:]
    root = Path(args[0])
    repeat = int(args[1])
    custom_sha = args[2]
    custom_vr = args[3]
    stable_vr = args[4]
    custom_lookup_layout = args[5]
    openldap_included = args[6] == "on"
    openldap_vr = args[7]
    provenance = None
    provenance_path = root.parent / "provenance.json"
    if provenance_path.is_file():
        try:
            loaded_provenance = json.loads(provenance_path.read_text())
        except (OSError, ValueError):
            loaded_provenance = None
        if isinstance(loaded_provenance, dict):
            provenance = loaded_provenance
    state_paths = {}
    if openldap_included:
        state_paths["openldap"] = root / "openldap"
    if custom_lookup_layout == "toggle":
        state_paths.update({
            "custom-off": root / "custom-off",
            "custom-on": root / "custom-on",
        })
        custom_reference_state = "custom-on"
    elif custom_lookup_layout == "unsupported":
        state_paths["custom-unsupported"] = root / "custom-unsupported"
        custom_reference_state = "custom-unsupported"
    else:
        raise RuntimeError(f"unknown custom lookup layout: {custom_lookup_layout}")
    state_paths["stable"] = root / "fedora-stable"
    expected_bundles = {
        "baseline-core",
        "baseline-branch-scaling",
        "baseline-dn-and-decomposition",
        "baseline-combined-and-family",
        "baseline-index-controls",
        "presence-sdn1",
        "presence-sdn2",
        "presence-both",
        "without-sdn1-equality",
        "without-sdn2-equality",
    }

    def nearest_rank_p95(values):
        ordered = sorted(values)
        return ordered[math.ceil(0.95 * len(ordered)) - 1]

    def median_optional(values):
        present = [value for value in values if value is not None]
        return statistics.median(present) if present else None

    def benefit(baseline, candidate):
        if baseline in (None, 0) or candidate is None:
            return None
        return 100.0 * (baseline - candidate) / baseline

    manifest = None
    rows_by_key = defaultdict(list)
    binary_hashes = defaultdict(set)
    build_labels = defaultdict(set)
    harness_content_hashes = set()
    measurement_harness_files = None
    environment_captures = {}
    bundle_created_at = {}
    canary_rows_by_bundle = {}
    completed_bundles = set()

    for state, state_path in state_paths.items():
        bundles = {path.name for path in state_path.iterdir() if path.is_dir()}
        if bundles != expected_bundles:
            raise RuntimeError(
                f"{state}: expected bundles {sorted(expected_bundles)}, "
                f"found {sorted(bundles)}"
            )
        for bundle in sorted(state_path.iterdir()):
            if not (bundle / "COMPLETE").is_file():
                raise RuntimeError(f"incomplete bundle: {bundle}")
            completed_bundles.add((state_path.name, bundle.name))
            current_manifest = json.loads(
                (bundle / "workload-manifest.json").read_text()
            )
            if manifest is None:
                manifest = current_manifest
            elif current_manifest["workload_sha256"] != manifest["workload_sha256"]:
                raise RuntimeError(f"workload mismatch in {bundle}")
            artifact = json.loads((bundle / "artifact-manifest.json").read_text())
            harness = artifact.get("harness_identity", {})
            harness_files = dict(harness.get("files", {}))
            if harness_files.pop("bin/run-full-fedora-screen", None) is None:
                raise RuntimeError(f"{bundle}: full-screen wrapper identity is missing")
            if measurement_harness_files is None:
                measurement_harness_files = harness_files
            elif harness_files != measurement_harness_files:
                raise RuntimeError(
                    f"{bundle}: measurement harness differs beyond the outer "
                    "full-screen wrapper"
                )
            harness_content_hashes.add(harness.get("content_sha256"))
            binary_hashes[state].add(
                artifact["server_executable"]["executable_sha256"]
            )
            environment_record = None
            environment_file = bundle / "environment.json"
            if environment_file.is_file():
                try:
                    loaded_environment = json.loads(environment_file.read_text())
                except (OSError, ValueError):
                    loaded_environment = None
                if isinstance(loaded_environment, dict):
                    environment_record = loaded_environment
            environment_captures[(state, bundle.name)] = environment_record
            bundle_created = None
            run_manifest_file = bundle / "run-manifest.json"
            if run_manifest_file.is_file():
                try:
                    loaded_run_manifest = json.loads(
                        run_manifest_file.read_text()
                    )
                except (OSError, ValueError):
                    loaded_run_manifest = None
                if isinstance(loaded_run_manifest, dict):
                    created_value = loaded_run_manifest.get("created_at")
                    if isinstance(created_value, str):
                        bundle_created = created_value
            bundle_created_at[(state, bundle.name)] = bundle_created
            bundle_canary_ids = set(
                current_manifest.get("scenario_groups", {}).get(
                    "drift-canary", []
                )
            )
            payload = json.loads((bundle / "raw-results.json").read_text())
            for row in payload["rows"]:
                if row["phase"] != "measured":
                    continue
                key = (
                    state,
                    row["index_config"],
                    row["scenario"],
                    row["attribute_variant"],
                )
                rows_by_key[key].append(row)
                build_labels[state].add(row["build_label"])
                if row["scenario"] in bundle_canary_ids:
                    canary_rows_by_bundle.setdefault(
                        (state, bundle.name), []
                    ).append(row)

    for state, hashes in binary_hashes.items():
        if len(hashes) != 1:
            raise RuntimeError(f"{state}: bundles used different server binaries")
    if (
        custom_lookup_layout == "toggle"
        and binary_hashes["custom-off"] != binary_hashes["custom-on"]
    ):
        raise RuntimeError("custom off/on executable hashes differ")

    assert manifest is not None
    descriptions = {}
    for scenario, value in manifest["scenarios"].items():
        description = value.get("description") or "generated filter"
        descriptions[scenario] = (
            f"{description}; {value['node_count']} nodes, "
            f"{value['branch_count']} leaves, {value['expected_count']} result(s)"
        )
    canary_scenarios = set(
        manifest.get("scenario_groups", {}).get("drift-canary", [])
    )
    metrics = {}
    for key, rows in rows_by_key.items():
        if key[2] in canary_scenarios:
            # The drift canary runs once per bundle, so a stratum holds one
            # repeat block per bundle sharing its index configuration.
            if len(rows) < repeat or len(rows) % repeat:
                raise RuntimeError(
                    f"{key}: expected a positive multiple of {repeat} "
                    f"canary rows, got {len(rows)}"
                )
        elif len(rows) != repeat:
            raise RuntimeError(f"{key}: expected {repeat} measured rows, got {len(rows)}")
        elapsed = [row["client_elapsed_ns"] / 1_000_000_000 for row in rows]
        cpu = [row["server_cpu_seconds"] for row in rows]
        etime = [row["server_etime_seconds"] for row in rows]
        cpu_present = [value for value in cpu if value is not None]
        metrics[key] = {
            "n": len(rows),
            "elapsed": statistics.median(elapsed),
            "p95": nearest_rank_p95(elapsed),
            "cpu": median_optional(cpu),
            "etime": median_optional(etime),
            "rss": median_optional([row["rss_kib"] for row in rows]),
            "high_water": median_optional([row["high_water_kib"] for row in rows]),
            "cpu_p95": nearest_rank_p95(cpu_present) if cpu_present else None,
        }

    state_keys = {
        state: {(index, scenario, attrs) for row_state, index, scenario, attrs in metrics
                if row_state == state}
        for state in state_paths
    }
    if len({frozenset(keys) for keys in state_keys.values()}) != 1:
        raise RuntimeError("screen states do not contain identical scenario strata")
    strata = sorted(state_keys["stable"])
    scenario_count = len({scenario for _, scenario, _ in strata})
    # 116 is the frozen legacy matrix; 132 adds the 6 drift-canary variants
    # and the 10 sub-threshold branch rungs.
    if scenario_count not in (116, 132):
        raise RuntimeError(
            f"expected 116 or 132 timed scenarios, got {scenario_count}"
        )

    manifest_scenarios = manifest["scenarios"]

    def _lookup_forbidden(name):
        diagnostic = (
            manifest_scenarios.get(name, {}).get("expected_lookup_diagnostic")
            or {}
        )
        return str(diagnostic.get("expectation", "")).startswith("forbidden")

    no_effect_strata = [key for key in strata if _lookup_forbidden(key[1])]
    no_effect_scenarios = sorted({scenario for _, scenario, _ in no_effect_strata})
    noise_elapsed_deltas = []
    noise_cpu_deltas = []
    if custom_lookup_layout == "toggle":
        for index, scenario, attrs in no_effect_strata:
            off = metrics["custom-off", index, scenario, attrs]
            on = metrics["custom-on", index, scenario, attrs]
            noise_elapsed_deltas.append(benefit(off["elapsed"], on["elapsed"]))
            noise_cpu_deltas.append(benefit(off["cpu"], on["cpu"]))
    noise_yardstick = compute_noise_yardstick(
        noise_elapsed_deltas, noise_cpu_deltas,
        strata_count=len(no_effect_strata),
        scenarios=no_effect_scenarios,
    )
    elapsed_band = noise_yardstick["elapsed_band_percent"]
    cpu_band = noise_yardstick["cpu_band_percent"]
    attempt_hygiene = collect_attempt_hygiene(
        root.parent / "logs", root.parent / "incomplete", completed_bundles,
    )

    summary_path = root.parent / "summary.csv"
    with summary_path.open("w", newline="") as stream:
        fieldnames = [
            "state", "index_config", "scenario", "attribute_variant",
            "filter_structure", "measured_runs", "median_elapsed_seconds",
            "p95_elapsed_seconds", "median_server_cpu_seconds",
            "median_server_etime_seconds", "median_rss_kib",
            "median_high_water_kib",
            "elapsed_relative_spread", "cpu_relative_spread",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for state in state_paths:
            for index, scenario, attrs in strata:
                value = metrics[state, index, scenario, attrs]
                writer.writerow({
                    "state": state,
                    "index_config": index,
                    "scenario": scenario,
                    "attribute_variant": attrs,
                    "filter_structure": descriptions[scenario],
                    "measured_runs": value["n"],
                    "median_elapsed_seconds": value["elapsed"],
                    "p95_elapsed_seconds": value["p95"],
                    "median_server_cpu_seconds": value["cpu"],
                    "median_server_etime_seconds": value["etime"],
                    "median_rss_kib": value["rss"],
                    "median_high_water_kib": value["high_water"],
                    "elapsed_relative_spread": relative_spread(
                        value["p95"], value["elapsed"]
                    ),
                    "cpu_relative_spread": relative_spread(
                        value["cpu_p95"], value["cpu"]
                    ),
                })

    if custom_lookup_layout == "toggle":
        comparison_specs = (
            ("stable-to-custom-off", "stable", "custom-off"),
            ("stable-to-custom-on", "stable", "custom-on"),
            ("custom-off-to-custom-on", "custom-off", "custom-on"),
        )
    else:
        comparison_specs = ((
            "stable-to-custom-unsupported", "stable", "custom-unsupported",
        ),)
    comparison_path = root.parent / "comparisons.csv"
    with comparison_path.open("w", newline="") as stream:
        fieldnames = [
            "comparison", "baseline_state", "candidate_state", "index_config",
            "scenario", "attribute_variant", "filter_structure",
            "baseline_median_elapsed_seconds", "candidate_median_elapsed_seconds",
            "elapsed_benefit_percent", "baseline_median_server_cpu_seconds",
            "candidate_median_server_cpu_seconds", "cpu_benefit_percent",
            "elapsed_noise_flag", "cpu_noise_flag", "delta_coherence",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for comparison, baseline_state, candidate_state in comparison_specs:
            for index, scenario, attrs in strata:
                baseline = metrics[baseline_state, index, scenario, attrs]
                candidate = metrics[candidate_state, index, scenario, attrs]
                elapsed_benefit = benefit(
                    baseline["elapsed"], candidate["elapsed"]
                )
                cpu_benefit = benefit(baseline["cpu"], candidate["cpu"])
                if comparison == "custom-off-to-custom-on":
                    elapsed_flag = noise_flags(elapsed_benefit, elapsed_band)[1]
                    cpu_flag = noise_flags(cpu_benefit, cpu_band)[1]
                    coherence = delta_coherence(elapsed_flag, cpu_flag)
                else:
                    elapsed_flag = cpu_flag = coherence = "n/a"
                writer.writerow({
                    "comparison": comparison,
                    "baseline_state": baseline_state,
                    "candidate_state": candidate_state,
                    "index_config": index,
                    "scenario": scenario,
                    "attribute_variant": attrs,
                    "filter_structure": descriptions[scenario],
                    "baseline_median_elapsed_seconds": baseline["elapsed"],
                    "candidate_median_elapsed_seconds": candidate["elapsed"],
                    "elapsed_benefit_percent": elapsed_benefit,
                    "baseline_median_server_cpu_seconds": baseline["cpu"],
                    "candidate_median_server_cpu_seconds": candidate["cpu"],
                    "cpu_benefit_percent": cpu_benefit,
                    "elapsed_noise_flag": elapsed_flag,
                    "cpu_noise_flag": cpu_flag,
                    "delta_coherence": coherence,
                })

    def ratio(numerator, denominator):
        if numerator is None or denominator in (None, 0):
            return None
        return numerator / denominator

    openldap_context_path = None
    if openldap_included:
        openldap_context_path = root.parent / "openldap-context.csv"
        with openldap_context_path.open("w", newline="") as stream:
            fieldnames = [
                "index_config", "scenario", "attribute_variant",
                "filter_structure", "custom_reference_state",
                "openldap_median_elapsed_seconds",
                "openldap_median_server_cpu_seconds",
                "custom_reference_median_elapsed_seconds",
                "custom_reference_median_server_cpu_seconds",
                "custom_over_openldap_elapsed_ratio",
                "custom_over_openldap_cpu_ratio",
            ]
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            for index, scenario, attrs in strata:
                ol = metrics["openldap", index, scenario, attrs]
                ref = metrics[custom_reference_state, index, scenario, attrs]
                writer.writerow({
                    "index_config": index,
                    "scenario": scenario,
                    "attribute_variant": attrs,
                    "filter_structure": descriptions[scenario],
                    "custom_reference_state": custom_reference_state,
                    "openldap_median_elapsed_seconds": ol["elapsed"],
                    "openldap_median_server_cpu_seconds": ol["cpu"],
                    "custom_reference_median_elapsed_seconds": ref["elapsed"],
                    "custom_reference_median_server_cpu_seconds": ref["cpu"],
                    "custom_over_openldap_elapsed_ratio": ratio(
                        ref["elapsed"], ol["elapsed"]
                    ),
                    "custom_over_openldap_cpu_ratio": ratio(ref["cpu"], ol["cpu"]),
                })

    def number(value, digits=6):
        return "n/a" if value is None else f"{value:.{digits}f}"

    def percent(value):
        return "n/a" if value is None else f"{value:.1f}%"

    def times(value):
        return "n/a" if value is None else f"{value:.2f}x"

    def markdown(value):
        return str(value).replace("|", "\\|").replace("\n", " ")

    report_path = root.parent / "REPORT.md"
    with report_path.open("w") as stream:
        stream.write("# Full native Fedora directional screen\n\n")
        stream.write(f"- Custom source: `{custom_sha}`\n")
        stream.write(f"- Custom package: `{custom_vr}`\n")
        stream.write(f"- Fedora stable package: `{stable_vr}`\n")
        if openldap_included:
            stream.write(f"- OpenLDAP package: `{openldap_vr}` (contextual state)\n")
        stream.write(f"- Timed scenarios: {scenario_count} ({len(strata)} attribute strata)\n")
        stream.write(f"- Measured searches per stratum: {repeat}\n")
        openldap_scope = "packaged OpenLDAP first, then " if openldap_included else ""
        if custom_lookup_layout == "toggle":
            stream.write(
                f"- Scope: {openldap_scope}custom/off, identical custom/on, then "
                "Fedora stable; directional screen, not an ABBA release decision\n"
            )
        else:
            stream.write(
                f"- Scope: {openldap_scope}custom/unsupported (OR switch absent), "
                "then Fedora stable; directional screen, not an ABBA release "
                "decision\n"
            )
        stream.write(
            "- Benefit sign: positive means the candidate state used less time/CPU\n\n"
        )
        if len(harness_content_hashes) > 1:
            stream.write(
                "- Resume note: bundles span an outer-wrapper-only update; all "
                "measurement runner, study, and workload files are identical\n\n"
            )
        if provenance is None:
            stream.write(
                "- Provenance: unavailable (run predates the provenance "
                "preflight; installed source not asserted)\n\n"
            )
        else:
            provenance_expected = provenance.get("expected_source") or {}
            provenance_observed = provenance.get("observed_source") or {}
            provenance_ancestor = provenance.get("ancestor_check") or {}
            ancestor_state = {True: "yes", False: "no"}.get(
                provenance_ancestor.get("observed_is_ancestor_of_head"),
                "unavailable",
            )
            provenance_observed_sha = (
                provenance_observed.get("resolved_sha") or "unavailable"
            )
            if provenance.get("match") is True:
                stream.write(
                    "- Provenance: asserted source matches the installed RPM "
                    f"(`{provenance_observed_sha}`; ancestor of harness HEAD: "
                    f"{ancestor_state})\n\n"
                )
            elif provenance.get("match") is False:
                stream.write(
                    "- Provenance warning: asserted source "
                    f"`{provenance_expected.get('resolved_sha') or 'unavailable'}` "
                    "does not match the installed RPM "
                    f"(`{provenance_observed_sha}`)\n\n"
                )
            else:
                stream.write(
                    "- Provenance warning: LF_EXPECTED_SOURCE was not set; "
                    f"installed source `{provenance_observed_sha}` observed but "
                    "not asserted (ancestor of harness HEAD: "
                    f"{ancestor_state})\n\n"
                )

        def band_text(value):
            return "unavailable" if value is None else f"±{value:.2f}%"

        if noise_yardstick["status"] == "available":
            stream.write(
                "- Noise band (off -> on, over "
                f"{noise_yardstick['no_effect_strata_count']} no-effect "
                f"strata): elapsed {band_text(elapsed_band)}, CPU "
                f"{band_text(cpu_band)}; the band is the maximum |benefit| "
                "across strata where the lookup cannot engage\n\n"
            )
        else:
            stream.write(
                "- Noise band: unavailable (requires the off/on toggle "
                "layout and no-effect strata)\n\n"
            )
        stream.write("- Statistical appendix: `statistical-appendix.md`\n\n")
        stream.write("## Binary identity\n\n")
        for state in state_paths:
            stream.write(
                f"- {state}: `{next(iter(binary_hashes[state]))}` "
                f"({len(build_labels[state])} bundle labels)\n"
            )
        if openldap_included:
            stream.write(
                "- OpenLDAP columns are contextual (packaged server, unavoidable "
                "implementation differences, never release evidence): x-ratios "
                "divide the 389 DS state's elapsed median by OpenLDAP's; above "
                "1.00x means 389 DS was slower\n"
            )
        stream.write("\n## Per-filter results\n\n")
        if custom_lookup_layout == "toggle":
            header = "| Index | Scenario | Attributes | Short filter structure | "
            rule = "|---|---|---|---|"
            if openldap_included:
                header += "openldap elapsed/CPU | "
                rule += "---:|"
            header += (
                "stable elapsed/CPU | custom-off elapsed/CPU | "
                "custom-on elapsed/CPU | stable -> off benefit | "
                "off -> on benefit |"
            )
            rule += "---:|---:|---:|---:|---:|"
            if openldap_included:
                header += " off/OL | on/OL |"
                rule += "---:|---:|"
            stream.write(header + "\n" + rule + "\n")
            for index, scenario, attrs in strata:
                stable = metrics["stable", index, scenario, attrs]
                off = metrics["custom-off", index, scenario, attrs]
                on = metrics["custom-on", index, scenario, attrs]
                stable_off = (
                    f"{percent(benefit(stable['elapsed'], off['elapsed']))} / "
                    f"{percent(benefit(stable['cpu'], off['cpu']))}"
                )
                off_on_elapsed = benefit(off['elapsed'], on['elapsed'])
                off_on_cpu = benefit(off['cpu'], on['cpu'])
                elapsed_mark, elapsed_flag = noise_flags(
                    off_on_elapsed, elapsed_band
                )
                cpu_mark, cpu_flag = noise_flags(off_on_cpu, cpu_band)
                incoherent = (
                    " ‡"
                    if delta_coherence(elapsed_flag, cpu_flag)
                    in ("elapsed-only", "cpu-only")
                    else ""
                )
                off_on = (
                    f"{percent(off_on_elapsed)}{elapsed_mark} / "
                    f"{percent(off_on_cpu)}{cpu_mark}{incoherent}"
                )
                row = (
                    f"| {markdown(index)} | {markdown(scenario)} | {markdown(attrs)} | "
                    f"{markdown(descriptions[scenario])} | "
                )
                if openldap_included:
                    ol = metrics["openldap", index, scenario, attrs]
                    row += f"{number(ol['elapsed'])} / {number(ol['cpu'])} | "
                row += (
                    f"{number(stable['elapsed'])} / {number(stable['cpu'])} | "
                    f"{number(off['elapsed'])} / {number(off['cpu'])} | "
                    f"{number(on['elapsed'])} / {number(on['cpu'])} | "
                    f"{stable_off} | {off_on} |"
                )
                if openldap_included:
                    row += (
                        f" {times(ratio(off['elapsed'], ol['elapsed']))} |"
                        f" {times(ratio(on['elapsed'], ol['elapsed']))} |"
                    )
                stream.write(row + "\n")
        else:
            header = (
                "| Index | Scenario | Attributes | Short filter structure | "
            )
            rule = "|---|---|---|---|"
            if openldap_included:
                header += "openldap elapsed/CPU | "
                rule += "---:|"
            header += "stable elapsed/CPU | custom elapsed/CPU | benefit |"
            rule += "---:|---:|---:|"
            if openldap_included:
                header += " custom/OL |"
                rule += "---:|"
            stream.write(header + "\n" + rule + "\n")
            for index, scenario, attrs in strata:
                stable = metrics["stable", index, scenario, attrs]
                custom = metrics["custom-unsupported", index, scenario, attrs]
                change = (
                    f"{percent(benefit(stable['elapsed'], custom['elapsed']))} / "
                    f"{percent(benefit(stable['cpu'], custom['cpu']))}"
                )
                row = (
                    f"| {markdown(index)} | {markdown(scenario)} | {markdown(attrs)} | "
                    f"{markdown(descriptions[scenario])} | "
                )
                if openldap_included:
                    ol = metrics["openldap", index, scenario, attrs]
                    row += f"{number(ol['elapsed'])} / {number(ol['cpu'])} | "
                row += (
                    f"{number(stable['elapsed'])} / {number(stable['cpu'])} | "
                    f"{number(custom['elapsed'])} / {number(custom['cpu'])} | "
                    f"{change} |"
                )
                if openldap_included:
                    row += f" {times(ratio(custom['elapsed'], ol['elapsed']))} |"
                stream.write(row + "\n")
        stream.write(
            "\nEach elapsed/CPU cell is the median in seconds. Nearest-rank p95, "
            "server etime, RSS, and high-water values are retained in `summary.csv`."
        )
        if openldap_included:
            stream.write(
                " Per-scenario OpenLDAP CPU ratios are retained in "
                "`openldap-context.csv`."
            )
        if noise_yardstick["status"] == "available":
            stream.write(
                "\n\nOff -> on benefit markers: `†` exceeds the no-effect "
                "noise band, `~` is within it, and a trailing `‡` flags an "
                "incoherent delta where only one of elapsed/CPU exceeds its "
                "band (an elapsed-only move is likely a scheduler artifact). "
                "The raw benefit numbers are never altered. Stable -> off "
                "cells and the contextual OpenLDAP medians/ratios carry no "
                "markers."
            )
        stream.write("\n\n## Scenario reference\n\n")
        stream.write(
            "All states share one generated dataset: 100,000 person entries under "
            "a single suffix plus small structural containers. Each scenario "
            "selects a disjoint entry cohort whose attribute values make exactly "
            "the intended filter branches live. Attribute roles and baseline "
            "index intent: `sString1/2/3` select the outer cohort by equality "
            "(eq); `sString4` guards the complex fallback (eq); `sDN1` carries "
            "the large DN-syntax OR family and `sDN2` the simple DN fallback "
            "(both eq; presence added only in the `presence-*` index variants, "
            "equality removed in the `without-*-equality` variants); `sSub` is "
            "the substring component (eq,sub); `sApprox` the approximate "
            "component (eq,approx). The primary shape is\n"
            "`(&(three outer equalities)(|(N x (sDN1=DN))(sDN2=DN)"
            "(&(sString4=guard)(!(sDN1=*))(!(sDN2=*)))))`\n"
            "- about 42 KB at N=355; the other scenarios permute, decompose, or "
            "rescale this shape (each row's structure column above says how). "
            "The assertion columns below count the DN-family branches: total, "
            "live (a matching entry exists), absent (no match in the data), "
            "duplicates; `+I` marks invalid DN assertions kept in the classic "
            "evaluator remainder. Outer cohort is the entry count selected by "
            "the outer equalities (the candidate load the filter test must "
            "process); values/entry is how many relevant attribute values each "
            "cohort entry carries.\n\n"
        )
        stream.write(
            "| Scenario | Groups | Filter bytes | Nodes/leaves | "
            "sDN1 assertions | DN mode | Outer cohort | Values/entry | "
            "sDN2 branch | Expected |\n"
        )
        stream.write("|---|---|---:|---|---|---|---:|---:|---|---:|\n")
        for scenario in sorted({name for _, name, _ in strata}):
            value = manifest["scenarios"][scenario]
            counts = value.get("assertion_counts") or {}
            assertions = "-"
            if counts.get("total"):
                assertions = (
                    f"{counts['total']} (L{counts.get('live', 0)}/"
                    f"A{counts.get('absent', 0)}/D{counts.get('duplicates', 0)}"
                )
                assertions += (
                    f"/I{counts['invalid']})" if counts.get("invalid") else ")"
                )
            dn_mode = value.get("dn_mode") or "-"
            if dn_mode == "not-applicable":
                dn_mode = "-"
            cohort = value.get("logical_outer_cohort_count")
            per_entry = value.get("relevant_values_per_entry") or 0
            stream.write(
                f"| {markdown(scenario)} | "
                f"{markdown(', '.join(value.get('groups', [])))} | "
                f"{value.get('rendered_bytes', 0)} | "
                f"{value['node_count']}/{value['branch_count']} | "
                f"{assertions} | {markdown(dn_mode)} | "
                f"{cohort if cohort is not None else '-'} | "
                f"{per_entry if per_entry else '-'} | "
                f"{'yes' if value.get('simple_sdn2_branch') else '-'} | "
                f"{value['expected_count']} |\n"
            )
        environment_states = summarize_environment_captures(environment_captures)
        environment_captured = sum(
            value["bundles_with_capture"] for value in environment_states.values()
        )
        stream.write("\n## Environment capture\n\n")
        if environment_captured == 0:
            stream.write(
                "Environment capture: unavailable (no bundle carries an "
                "`environment.json` sidecar; runs recorded before the capture "
                "was added report this way).\n"
            )
        else:
            for state in state_paths:
                value = environment_states.get(state)
                if value is None:
                    continue
                if value["bundles_with_capture"] == 0:
                    stream.write(f"- {state}: unavailable (no capture)\n")
                    continue
                kernels = value["kernels"]
                governors = value["governors"]
                stream.write(
                    f"- {state}: {value['bundles_with_capture']}/"
                    f"{value['bundles_total']} bundles captured; kernels: "
                    f"{', '.join(kernels) if kernels != UNAVAILABLE else UNAVAILABLE}; "
                    f"governors: "
                    f"{', '.join(governors) if governors != UNAVAILABLE else UNAVAILABLE}; "
                    f"steal delta: {value['cpu_steal_ticks_delta_total']} ticks; "
                    f"throttle events: {value['thermal_throttle_events']}; "
                    f"max loadavg(1m): {value['max_loadavg_1m']}\n"
                )
        stream.write("\n## Attempt hygiene\n\n")
        if attempt_hygiene["status"] == "unavailable":
            stream.write(
                "Attempt hygiene: unavailable (no runner `logs/` or "
                "`incomplete/` directories alongside the results).\n"
            )
        else:
            for state in sorted(attempt_hygiene["states"]):
                bundles_map = attempt_hygiene["states"][state]
                noisy = {
                    bundle: value for bundle, value in bundles_map.items()
                    if value["archived"] or value["attempts_observed"] not in ([], [1])
                }
                clean_count = len(bundles_map) - len(noisy)
                stream.write(
                    f"- {state}: {clean_count}/{len(bundles_map)} bundles "
                    "first-attempt clean\n"
                )
                for bundle, value in sorted(noisy.items()):
                    archived_text = ", ".join(
                        f"{item['reason']} @ {item['stamp']}"
                        for item in value["archived"]
                    ) or "none"
                    used = value["attempt_used"]
                    observed = value["attempts_observed"]
                    stream.write(
                        f"  - {bundle}: used attempt "
                        f"{used if used is not None else 'unknown'} "
                        f"(attempts observed: {observed or 'none'}; "
                        f"archived: {archived_text})\n"
                    )
            if (
                attempt_hygiene["unrecognized_log_files"]
                or attempt_hygiene["unrecognized_archives"]
            ):
                stream.write(
                    "- Unrecognized entries: "
                    f"{attempt_hygiene['unrecognized_log_files']} logs, "
                    f"{attempt_hygiene['unrecognized_archives']} archives\n"
                )

    screen_summary = {
        "format_version": 1,
        "custom_source_sha": custom_sha,
        "custom_package_version_release": custom_vr,
        "custom_lookup_layout": custom_lookup_layout,
        "stable_package_version_release": stable_vr,
        "openldap_included": openldap_included,
        "openldap_package_version_release": (
            openldap_vr if openldap_included else None
        ),
        "openldap_context_csv": (
            openldap_context_path.name if openldap_context_path else None
        ),
        "scenario_count": scenario_count,
        "attribute_strata_count": len(strata),
        "measured_searches_per_stratum": repeat,
        "outer_wrapper_only_resume_update": len(harness_content_hashes) > 1,
        "states": {
            state: {
                "server_executable_sha256": next(iter(binary_hashes[state])),
                "bundle_count": len(expected_bundles),
            }
            for state in state_paths
        },
        "summary_csv": summary_path.name,
        "comparisons_csv": comparison_path.name,
        "report": report_path.name,
    }
    appendix_path = root.parent / "statistical-appendix.md"
    _write_statistical_appendix(
        appendix_path,
        states=list(state_paths),
        layout=custom_lookup_layout,
        repeat=repeat,
        metrics=metrics,
        strata=strata,
        rows_by_key=rows_by_key,
        manifest_scenarios=manifest_scenarios,
        scenario_groups=manifest.get("scenario_groups", {}),
        canary_rows_by_bundle=canary_rows_by_bundle,
        bundle_created_at=bundle_created_at,
    )
    screen_summary["statistical_appendix"] = appendix_path.name
    screen_summary["noise_yardstick"] = noise_yardstick
    screen_summary["attempt_hygiene"] = attempt_hygiene
    if environment_captured == 0:
        screen_summary["environment_capture"] = UNAVAILABLE
    else:
        screen_summary["environment_capture"] = {
            "bundles_total": sum(
                value["bundles_total"]
                for value in environment_states.values()
            ),
            "bundles_with_capture": environment_captured,
            "states": environment_states,
        }
    if provenance is None:
        screen_summary["provenance"] = {
            "status": "unavailable",
            "expected_source_sha": None,
            "observed_source_sha": None,
            "ancestor_of_head": None,
            "repo_describe": None,
            "provenance_json": None,
        }
    else:
        provenance_match = provenance.get("match")
        if provenance_match is True:
            provenance_status = "asserted-match"
        elif provenance_match is False:
            provenance_status = "asserted-mismatch"
        else:
            provenance_status = "observed-only"
        screen_summary["provenance"] = {
            "status": provenance_status,
            "expected_source_sha": (
                (provenance.get("expected_source") or {}).get("resolved_sha")
            ),
            "observed_source_sha": (
                (provenance.get("observed_source") or {}).get("resolved_sha")
            ),
            "ancestor_of_head": (
                (provenance.get("ancestor_check") or {}).get(
                    "observed_is_ancestor_of_head"
                )
            ),
            "repo_describe": provenance.get("repo_describe"),
            "provenance_json": provenance_path.name,
        }
    (root.parent / "screen-summary.json").write_text(
        json.dumps(screen_summary, indent=2, sort_keys=True) + "\n"
    )

    print()
    print(
        f"Completed: {scenario_count} timed scenarios, {len(strata)} strata, "
        f"{repeat} measured searches per state/stratum"
    )
    print(f"Report:      {report_path}")
    print(f"Summary CSV: {summary_path}")
    print(f"Comparisons: {comparison_path}")
    print(f"Appendix:    {appendix_path}")
    if openldap_context_path is not None:
        print(f"OpenLDAP context: {openldap_context_path}")
    print(f"Raw bundles: {root}")
    return 0


def regenerate_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="regenerate-screen-report",
        description=(
            "Re-run the full-screen report rendering against an existing "
            "screen output directory. The default --output mode never "
            "modifies the source run directory."
        ),
    )
    parser.add_argument("run_dir", type=Path)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output", type=Path)
    target.add_argument(
        "--in-place", action="store_true",
        help="overwrite the run directory's own report files",
    )
    parser.add_argument("--repeat", type=int)
    parser.add_argument("--custom-sha")
    parser.add_argument("--custom-vr")
    parser.add_argument("--stable-vr")
    parser.add_argument("--layout", choices=("toggle", "unsupported"))
    parser.add_argument("--openldap", choices=("on", "off"))
    parser.add_argument("--openldap-vr")
    args = parser.parse_args(argv)

    run_dir = args.run_dir.resolve()
    results = run_dir / "results"
    if not results.is_dir():
        parser.error(f"{run_dir} does not contain a results/ directory")
    summary = {}
    summary_path = run_dir / "screen-summary.json"
    if summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text())
        except (OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            summary = loaded

    def recovered(flag_value, key, fallback="unavailable"):
        if flag_value is not None:
            return flag_value
        value = summary.get(key)
        if value is None:
            return fallback
        return str(value)

    repeat = args.repeat
    if repeat is None:
        recorded = summary.get("measured_searches_per_stratum")
        if isinstance(recorded, int):
            repeat = recorded
    if repeat is None:
        parser.error(
            "measured_searches_per_stratum is absent from screen-summary.json; "
            "pass --repeat"
        )
    layout = args.layout or summary.get("custom_lookup_layout")
    if layout is None:
        if (results / "custom-off").is_dir():
            layout = "toggle"
        elif (results / "custom-unsupported").is_dir():
            layout = "unsupported"
        else:
            parser.error("cannot infer the custom lookup layout; pass --layout")
    openldap = args.openldap
    if openldap is None:
        included = summary.get("openldap_included")
        if isinstance(included, bool):
            openldap = "on" if included else "off"
        else:
            openldap = "on" if (results / "openldap").is_dir() else "off"
    custom_sha = recovered(args.custom_sha, "custom_source_sha")
    custom_vr = recovered(args.custom_vr, "custom_package_version_release")
    stable_vr = recovered(args.stable_vr, "stable_package_version_release")
    openldap_vr = recovered(args.openldap_vr, "openldap_package_version_release", "")

    if args.in_place:
        render_root = results
    else:
        output = args.output.resolve()
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            parser.error(f"refusing to write into existing non-empty {output}")
        output.mkdir(parents=True, exist_ok=True)
        (output / "results").symlink_to(results)
        for name in ("logs", "incomplete", "provenance.json"):
            source = run_dir / name
            if source.exists():
                (output / name).symlink_to(source)
        render_root = output / "results"

    return main([
        str(render_root), str(repeat), custom_sha, custom_vr, stable_vr,
        layout, openldap, openldap_vr,
    ])


if __name__ == "__main__":
    raise SystemExit(main())
