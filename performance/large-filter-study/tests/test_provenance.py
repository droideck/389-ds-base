"""Contracts for the installed-RPM provenance record and assertion."""

from __future__ import annotations

import json
import tempfile
import unittest

from pathlib import Path


STUDY_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(STUDY_ROOT) not in sys.path:
    sys.path.insert(0, str(STUDY_ROOT))

from study.provenance import (  # noqa: E402
    ASSERT_MISMATCH_EXIT,
    build_provenance,
    main,
)

SHA_A = "a" * 40
SHA_B = "b" * 40


class BuildProvenanceTests(unittest.TestCase):
    def test_asserted_match(self):
        record = build_provenance(
            expected_raw="feature-branch",
            expected_sha=SHA_A,
            observed_token=SHA_A[:9],
            observed_sha=SHA_A,
            rpm_version_release="3.3.0.git" + SHA_A[:9] + "-1.fc44",
            ancestor="yes",
            head_sha=SHA_B,
            describe="v3.3.0-12-g" + SHA_A[:9],
        )
        self.assertTrue(record["expected_source"]["asserted"])
        self.assertIs(record["match"], True)
        self.assertEqual(record["ancestor_check"]["status"], "observed")
        self.assertIs(
            record["ancestor_check"]["observed_is_ancestor_of_head"], True
        )
        self.assertEqual(record["observed_source"]["resolved_sha"], SHA_A)

    def test_asserted_mismatch_sets_match_false(self):
        record = build_provenance(
            expected_sha=SHA_A, observed_sha=SHA_B,
        )
        self.assertIs(record["match"], False)

    def test_unasserted_has_null_match(self):
        record = build_provenance(observed_sha=SHA_A)
        self.assertFalse(record["expected_source"]["asserted"])
        self.assertIsNone(record["match"])

    def test_missing_fields_encode_unavailable(self):
        record = build_provenance()
        self.assertEqual(
            record["observed_source"]["resolved_sha"], "unavailable"
        )
        self.assertEqual(record["repo_describe"], "unavailable")
        self.assertEqual(record["workload"], "unavailable")
        self.assertEqual(record["ancestor_check"]["status"], "unavailable")
        self.assertIsNone(
            record["ancestor_check"]["observed_is_ancestor_of_head"]
        )


class ProvenanceCliTests(unittest.TestCase):
    def test_assert_match_exit_codes_and_file_always_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "provenance.json"
            status = main([
                "--output", str(output),
                "--expected-sha", SHA_A,
                "--observed-sha", SHA_A,
                "--assert-match",
            ])
            self.assertEqual(status, 0)
            self.assertIs(json.loads(output.read_text())["match"], True)

            status = main([
                "--output", str(output),
                "--expected-sha", SHA_A,
                "--observed-sha", SHA_B,
                "--assert-match",
            ])
            self.assertEqual(status, ASSERT_MISMATCH_EXIT)
            self.assertIs(json.loads(output.read_text())["match"], False)

            status = main([
                "--output", str(output),
                "--observed-sha", SHA_B,
            ])
            self.assertEqual(status, 0)
            self.assertIsNone(json.loads(output.read_text())["match"])

    def test_assert_match_requires_expected_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "provenance.json"
            with self.assertRaises(SystemExit) as raised:
                main(["--output", str(output), "--assert-match"])
            self.assertEqual(raised.exception.code, 2)

    def test_workload_manifest_fields_recovered_and_degraded(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "workload-manifest.json"
            manifest.write_text(json.dumps({
                "workload_id": "full-abc", "workload_sha256": "c" * 64,
            }))
            output = Path(tmp) / "provenance.json"
            main([
                "--output", str(output),
                "--workload-manifest", str(manifest),
            ])
            record = json.loads(output.read_text())
            self.assertEqual(record["workload"]["workload_id"], "full-abc")

            main([
                "--output", str(output),
                "--workload-manifest", str(Path(tmp) / "missing.json"),
            ])
            record = json.loads(output.read_text())
            self.assertEqual(record["workload"], "unavailable")


if __name__ == "__main__":
    unittest.main()
