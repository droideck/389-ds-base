"""Record and optionally assert the provenance of the installed custom RPM.

The full-screen wrapper already extracts the git hash embedded in the
installed 389-ds-base release string.  This module writes that observation to
``provenance.json`` at the screen output root and, when the operator sets
``LF_EXPECTED_SOURCE``, asserts that the observed hash is the commit under
review.  The record is written in every case so a mismatch is preserved on
disk; ``--assert-match`` then exits with status 3.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

FORMAT_VERSION = 1
ASSERT_MISMATCH_EXIT = 3


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_provenance(
    *,
    expected_raw=None,
    expected_sha=None,
    observed_token=None,
    observed_sha=None,
    rpm_version_release=None,
    ancestor=None,
    head_sha=None,
    describe=None,
    workload_id=None,
    workload_sha256=None,
    captured_at=None,
):
    asserted = expected_sha is not None
    if asserted:
        match = observed_sha is not None and expected_sha == observed_sha
    else:
        match = None
    if ancestor in ("yes", "no"):
        ancestor_check = {
            "status": "observed",
            "observed_is_ancestor_of_head": ancestor == "yes",
            "head_sha": head_sha or "unavailable",
        }
    else:
        ancestor_check = {
            "status": "unavailable",
            "observed_is_ancestor_of_head": None,
            "head_sha": head_sha or "unavailable",
        }
    if workload_id or workload_sha256:
        workload = {
            "workload_id": workload_id or "unavailable",
            "workload_sha256": workload_sha256 or "unavailable",
        }
    else:
        workload = "unavailable"
    return {
        "format_version": FORMAT_VERSION,
        "captured_at": captured_at or _utc_now(),
        "expected_source": {
            "raw": expected_raw,
            "resolved_sha": expected_sha,
            "asserted": asserted,
        },
        "observed_source": {
            "rpm_version_release": rpm_version_release or "unavailable",
            "rpm_git_token": observed_token or "unavailable",
            "resolved_sha": observed_sha or "unavailable",
        },
        "match": match,
        "ancestor_check": ancestor_check,
        "repo_describe": describe or "unavailable",
        "workload": workload,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="provenance",
        description=__doc__.splitlines()[0],
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-raw")
    parser.add_argument("--expected-sha")
    parser.add_argument("--observed-token")
    parser.add_argument("--observed-sha")
    parser.add_argument("--rpm-vr")
    parser.add_argument("--ancestor", choices=("yes", "no", "unavailable"))
    parser.add_argument("--head-sha")
    parser.add_argument("--describe")
    parser.add_argument("--workload-manifest", type=Path)
    parser.add_argument("--assert-match", action="store_true")
    args = parser.parse_args(argv)
    if args.assert_match and not args.expected_sha:
        parser.error("--assert-match requires --expected-sha")

    workload_id = None
    workload_sha256 = None
    if args.workload_manifest and args.workload_manifest.is_file():
        try:
            manifest = json.loads(args.workload_manifest.read_text())
        except (OSError, ValueError):
            manifest = None
        if isinstance(manifest, dict):
            workload_id = manifest.get("workload_id")
            workload_sha256 = manifest.get("workload_sha256")

    record = build_provenance(
        expected_raw=args.expected_raw,
        expected_sha=args.expected_sha,
        observed_token=args.observed_token,
        observed_sha=args.observed_sha,
        rpm_version_release=args.rpm_vr,
        ancestor=args.ancestor,
        head_sha=args.head_sha,
        describe=args.describe,
        workload_id=workload_id,
        workload_sha256=workload_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    if args.assert_match and record["match"] is False:
        print(
            f"provenance mismatch: expected {args.expected_sha}, installed RPM "
            f"carries {record['observed_source']['resolved_sha']}",
            file=sys.stderr,
        )
        return ASSERT_MISMATCH_EXIT
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
