"""Fast contract tests for the deterministic large-filter workload generator."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

from pathlib import Path


STUDY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STUDY_ROOT))

from study.common import (  # noqa: E402
    AND,
    APPROX,
    EQ,
    NOT,
    OR,
    PRESENT,
    SUBSTRING,
    DataSet,
    atomic_output_directory,
    normalize_dn,
    sha256_file,
)
from study.generator import (  # noqa: E402
    DEFAULT_SPEC,
    ScenarioWriter,
    SpecificationError,
    WorkloadData,
    generate_workload,
    load_spec,
    validate_spec,
)


REQUIRED_GROUPS = {
    "primary",
    "sdn2-pair",
    "presence-index",
    "candidate-scaling",
    "branch-scaling",
    "hit-position",
    "fallbacks",
    "multivalue-scaling",
    "dn-normalization",
    "decomposition",
    "candidate-index-controls",
    "combined-substring",
    "combined-approximate",
    "branch-order",
    "flat-family",
    "family-discovery",
    "family-ranking",
    "dynamic-list-correctness",
    "decline-paths",
}


class OracleTests(unittest.TestCase):
    def test_dn_normalization_equivalence_and_rejection(self) -> None:
        canonical = "cn=target,ou=References,dc=example,dc=com"
        equivalent = " CN=TARGET , OU=REFERENCES , DC=EXAMPLE , DC=COM "
        self.assertEqual(normalize_dn(canonical), normalize_dn(equivalent))

        escaped = r"cn=Smith\, Alice,ou=References,dc=example,dc=com"
        hex_escaped = r"CN=SMITH\2c ALICE,OU=REFERENCES,DC=EXAMPLE,DC=COM"
        self.assertEqual(normalize_dn(escaped), normalize_dn(hex_escaped))

        multivalued_a = "cn=Alice+uid=7,dc=example,dc=com"
        multivalued_b = "UID=7+CN=ALICE,DC=EXAMPLE,DC=COM"
        self.assertEqual(normalize_dn(multivalued_a), normalize_dn(multivalued_b))

        for malformed in (
            "not a dn at all",
            "cn=missing,ou=References,dc=example,dc=com,bare,ou=tail",
            "cn=bad\\",
            "=missing,dc=example,dc=com",
            "cn=missing+bad,dc=example,dc=com",
            "cn=missing,dc=example,dc,ou=tail",
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(normalize_dn(malformed))

    def test_filter_oracle_covers_dn_substring_approx_not_and_presence(self) -> None:
        data = DataSet()
        first = data.add(
            "uid=one,ou=people,dc=example,dc=com",
            {
                "sDN1": ["cn=target,ou=References,dc=example,dc=com"],
                "cn": ["Alpha Common Suffix"],
                "sApprox": ["Xanadu Approximate"],
            },
        )
        second = data.add(
            "uid=two,ou=people,dc=example,dc=com",
            {
                "sDN1": [r"cn=Smith\, Alice,ou=References,dc=example,dc=com"],
                "sDN2": ["cn=account,dc=example,dc=com"],
                "cn": ["unrelated"],
            },
        )

        compound = AND(
            EQ("sDN1", "CN=TARGET, OU=REFERENCES, DC=EXAMPLE, DC=COM"),
            SUBSTRING("cn", "*common*suffix"),
            NOT(PRESENT("sDN2")),
        )
        self.assertEqual(compound.evaluate(data), {first})
        self.assertEqual(
            EQ(
                "sDN1",
                r"CN=SMITH\, ALICE,OU=REFERENCES,DC=EXAMPLE,DC=COM",
            ).evaluate(data),
            {second},
        )
        self.assertEqual(
            APPROX("sApprox", "xanadu approximate").evaluate(data), {first}
        )
        self.assertEqual(
            OR(
                EQ("sDN1", "not a valid dn"),
                EQ("sDN1", "cn=target,ou=References,dc=example,dc=com"),
            ).evaluate(data),
            {first},
        )


class SpecificationTests(unittest.TestCase):
    def test_full_profile_contract_and_consistency_rejection(self) -> None:
        spec = load_spec(DEFAULT_SPEC)
        profile = validate_spec(spec, "full", DEFAULT_SPEC)
        self.assertEqual(profile["people"], 100_000)
        self.assertEqual(profile["principal_cohort"], 612)
        self.assertEqual(
            profile["candidate_counts"], [0, 1, 10, 100, 612, 1000, 10000]
        )

        bad_primary = copy.deepcopy(spec)
        bad_primary["primary"]["dn_branches"] = 354
        with self.assertRaisesRegex(SpecificationError, "exactly 355"):
            validate_spec(bad_primary, "tiny", DEFAULT_SPEC)

        bad_dynamic = copy.deepcopy(spec)
        bad_dynamic["dynamic_list"]["lookthrough_limit"] = 10_001
        with self.assertRaisesRegex(SpecificationError, "lookthrough invariant"):
            validate_spec(bad_dynamic, "tiny", DEFAULT_SPEC)

        index_config = json.loads(
            (STUDY_ROOT / "workload/indexes/index-configurations.json").read_text()
        )
        for server in ("389ds", "openldap"):
            baseline = index_config["servers"][server]["baseline"]
            self.assertEqual(baseline["member"], ["eq"])
            self.assertIn("sub", baseline["cn"])


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="large-filter-generator-test-")
        cls.root = Path(cls.temporary.name)
        cls.tiny_a = cls.root / "tiny-a"
        cls.tiny_b = cls.root / "tiny-b"
        cls.smoke = cls.root / "smoke"
        cls.tiny_manifest = generate_workload(DEFAULT_SPEC, "tiny", cls.tiny_a)
        cls.tiny_manifest_b = generate_workload(DEFAULT_SPEC, "tiny", cls.tiny_b)
        cls.smoke_manifest = generate_workload(DEFAULT_SPEC, "smoke", cls.smoke)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_tiny_manifest_files_and_primary_contract(self) -> None:
        manifest = self.tiny_manifest
        required_top_level = {
            "format_version",
            "profile",
            "host_intent",
            "workload_id",
            "workload_sha256",
            "entries",
            "files",
            "scenario_groups",
            "scenarios",
            "index_config_file",
            "schema_files",
            "server_data_files",
        }
        self.assertTrue(required_top_level.issubset(manifest))
        self.assertEqual(manifest["profile"], "tiny")
        self.assertEqual(manifest["entries"], 512)
        self.assertTrue(manifest["correctness_only"])
        self.assertFalse(manifest["release_timing_evidence"])
        self.assertTrue(REQUIRED_GROUPS.issubset(manifest["scenario_groups"]))

        actual_files = {
            path.relative_to(self.tiny_a).as_posix()
            for path in self.tiny_a.rglob("*")
            if path.is_file() and path.name != "workload-manifest.json"
        }
        self.assertEqual(set(manifest["files"]), actual_files)
        for relative, expected_sha in manifest["files"].items():
            with self.subTest(relative=relative):
                self.assertEqual(sha256_file(self.tiny_a / relative), expected_sha)

        self.assertEqual(
            manifest["schema_files"],
            {
                "389ds": "schema/99large-filter-study.ldif",
                "openldap": "schema/large-filter-study.schema",
            },
        )
        self.assertEqual(
            manifest["index_config_file"], "indexes/index-configurations.json"
        )
        self.assertEqual(
            manifest["server_data_files"],
            {"389ds": "data.ldif", "openldap": "data-openldap.ldif"},
        )

        scenarios = manifest["scenarios"]
        primary = scenarios["principal-with-sdn2-equality"]
        pair = scenarios["principal-without-sdn2-equality"]
        self.assertEqual(primary["node_count"], 368)
        self.assertEqual(pair["node_count"], 367)
        self.assertEqual(primary["equality_branch_count"], 360)
        self.assertEqual(pair["equality_branch_count"], 359)
        self.assertEqual(primary["logical_outer_cohort_count"], 32)
        self.assertEqual(
            primary["logical_outer_cohort_basis"],
            "derived-and-verified-from-outer-filter-ast",
        )
        self.assertEqual(
            primary["logical_outer_cohort_sha256"],
            scenarios["decomposition-a-outer-only"]["expected_sha256"],
        )
        self.assertEqual(primary["expected_count"], 0)
        self.assertEqual(pair["expected_count"], 0)
        self.assertTrue(41_000 <= primary["rendered_bytes"] <= 44_000)
        self.assertTrue(primary["simple_sdn2_branch"])
        self.assertFalse(pair["simple_sdn2_branch"])
        self.assertEqual(primary["assertion_counts"]["total"], 356)
        self.assertEqual(primary["expected_lookup_diagnostic"]["largest_family"], 355)

        primary_text = (self.tiny_a / primary["filter_file"]).read_text().rstrip("\n")
        pair_text = (self.tiny_a / pair["filter_file"]).read_text().rstrip("\n")
        self.assertEqual(len(primary_text.encode()), primary["rendered_bytes"])
        removed_component = (
            "(sDN2=cn=account1,ou=accounts,o=data,dc=example,dc=com)"
        )
        self.assertIn(removed_component, primary_text)
        self.assertNotIn(removed_component, pair_text)
        self.assertEqual(primary_text.replace(removed_component, "", 1), pair_text)

    def test_expected_sets_are_bare_sorted_dns_with_verified_hashes(self) -> None:
        for scenario_id, scenario in self.tiny_manifest["scenarios"].items():
            expected_bytes = (self.tiny_a / scenario["expected_file"]).read_bytes()
            lines = expected_bytes.decode("utf-8").splitlines()
            with self.subTest(scenario_id=scenario_id):
                self.assertEqual(lines, sorted(lines))
                self.assertTrue(all(line.startswith(("uid=", "cn=")) for line in lines))
                self.assertEqual(len(lines), scenario["expected_count"])
                self.assertEqual(
                    hashlib.sha256(expected_bytes).hexdigest(),
                    scenario["expected_sha256"],
                )

    def test_syntax_sensitive_and_feature_family_expectations(self) -> None:
        scenarios = self.tiny_manifest["scenarios"]
        self.assertEqual(scenarios["dn-case-equivalent-positive"]["expected_count"], 4)
        escaped = scenarios["dn-escaped-comma-positive"]
        self.assertEqual(escaped["expected_count"], 4)
        escaped_filter = (self.tiny_a / escaped["filter_file"]).read_text()
        self.assertIn(r"CN=SMITH\5c, ALICE", escaped_filter)

        invalid = scenarios["dn-invalid-remainder-positive"]
        self.assertEqual(invalid["expected_count"], 4)
        self.assertEqual(invalid["assertion_counts"]["total"], 20)
        self.assertEqual(invalid["invalid_assertions"], 6)
        self.assertEqual(invalid["normalized_unique_assertions"], 14)
        self.assertEqual(
            invalid["expected_lookup_diagnostic"]["expectation"],
            "forbidden-valid-family-below-threshold",
        )
        invalid_filter = (self.tiny_a / invalid["filter_file"]).read_text()
        self.assertIn(
            "cn=missing,ou=References,dc=example,dc=com,bare,ou=tail",
            invalid_filter,
        )
        self.assertIn("cn=missing,dc=example,dc,ou=tail", invalid_filter)
        self.assertNotIn(
            "(sDN1=cn=missing,ou=References,dc=example,dc=com,)",
            invalid_filter,
        )
        self.assertNotIn("(sDN1=cn=missing,dc=example,dc)", invalid_filter)
        self.assertEqual(
            scenarios["dn-invalid-remainder-all-miss"]["expected_count"], 0
        )

        self.assertEqual(scenarios["fallback-simple-hit"]["expected_count"], 16)
        self.assertEqual(scenarios["fallback-complex-hit"]["expected_count"], 16)
        self.assertEqual(scenarios["combined-substring-gain"]["expected_count"], 16)
        self.assertEqual(scenarios["combined-substring-adverse"]["expected_count"], 8)
        self.assertEqual(scenarios["combined-approximate-gain"]["expected_count"], 16)
        for label in ("outer-first", "costly-first", "large-or-first"):
            self.assertEqual(
                scenarios[f"order-combined-approx-{label}"]["expected_count"], 16
            )
        self.assertEqual(
            scenarios["dynamic-list-lookthrough-finite"]["expected_count"], 2
        )
        self.assertEqual(
            scenarios["dynamic-list-lookthrough-unlimited"]["expected_count"], 2
        )
        for scenario_id in (
            "dynamic-list-lookthrough-finite",
            "dynamic-list-lookthrough-unlimited",
        ):
            bounded = scenarios[scenario_id]["expected_cap_diagnostic"]
            self.assertEqual(
                bounded["expectation"], "revision-dependent-dynamic-safety"
            )
            self.assertEqual(
                bounded["revision_expectations"],
                {
                    "combined-diagnostic": "required-pre-fix-diagnostic",
                    "dynamic-list-fix": "forbidden",
                    "final": "forbidden",
                },
            )

    def test_family_selection_controls_have_exact_base_object_probes(self) -> None:
        scenarios = self.tiny_manifest["scenarios"]
        expected_attributes = {
            "flat-family-ranking-a16-b64": "sString2",
            "flat-family-ranking-b64-a16": "sString2",
            "flat-family-third-after-distractors": "sString3",
            "flat-family-unsupported-fallback": "sString1",
            "flat-family-tie-a-first": "sString1",
            "flat-family-tie-b-first": "sString2",
        }
        for scenario_id, selected_attribute in expected_attributes.items():
            scenario = scenarios[scenario_id]
            probe = scenario["selection_probe"]
            expected_payload = f"{probe['base_dn']}\n".encode("utf-8")
            with self.subTest(scenario_id=scenario_id):
                self.assertEqual(probe["scope"], "base")
                self.assertEqual(probe["expected_count"], 1)
                self.assertEqual(
                    probe["expected_sha256"],
                    hashlib.sha256(expected_payload).hexdigest(),
                )
                self.assertEqual(
                    scenario["expected_lookup_diagnostic"]["selected_attribute"],
                    selected_attribute,
                )
                result_dns = (
                    self.tiny_a / scenario["expected_file"]
                ).read_text(encoding="utf-8").splitlines()
                self.assertIn(probe["base_dn"], result_dns)

    def test_outer_cohort_mismatch_is_rejected(self) -> None:
        data = DataSet()
        first = data.add("uid=one,ou=people,dc=example,dc=com", {"x": ["one"]})
        second = data.add("uid=two,ou=people,dc=example,dc=com", {"x": ["two"]})
        workload = WorkloadData(
            data=data,
            cohorts={},
            people_ids={first, second},
            dynamic_ids=set(),
            overrides={},
            flat_ids=[],
            dynamic_metadata={},
        )
        with tempfile.TemporaryDirectory(prefix="large-filter-cohort-test-") as root:
            writer = ScenarioWriter(
                Path(root), workload, "test", {}, "ou=people,dc=example,dc=com"
            )
            with self.assertRaisesRegex(SpecificationError, "outer AST/cohort mismatch"):
                writer.add(
                    "mismatched-cohort",
                    EQ("x", "one"),
                    groups=["test"],
                    cohort_ids=[second],
                    logical_outer_filter=EQ("x", "one"),
                )
            with self.assertRaisesRegex(
                    SpecificationError, "not a component of its executed filter AST"):
                writer.add(
                    "mismatched-outer-filter",
                    EQ("x", "two"),
                    groups=["test"],
                    cohort_ids=[first],
                    logical_outer_filter=EQ("x", "one"),
                )

    def test_approximate_cross_server_policy_has_exact_native_probes(self) -> None:
        scenario = self.tiny_manifest["scenarios"]["combined-approximate-gain"]
        policy = scenario["cross_server_comparison"]
        self.assertEqual(policy["policy"], "requires-native-equivalence-preflight")
        self.assertEqual(policy["default_eligibility"], "excluded")
        self.assertRegex(policy["contract_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            policy["required_probe_ids"],
            ["positive-identical-token", "negative-dissimilar-token"],
        )
        positive = policy["probes"]["positive-identical-token"]
        negative = policy["probes"]["negative-dissimilar-token"]
        self.assertEqual((positive["scope"], positive["expected_count"]), ("base", 1))
        self.assertEqual((negative["scope"], negative["expected_count"]), ("base", 0))
        self.assertEqual(
            hashlib.sha256(f"{positive['base_dn']}\n".encode()).hexdigest(),
            positive["expected_sha256"],
        )
        self.assertEqual(hashlib.sha256(b"").hexdigest(), negative["expected_sha256"])

    def test_candidate_ladder_and_pending_observation_metadata(self) -> None:
        scenarios = self.tiny_manifest["scenarios"]
        for count in (0, 1, 4, 16, 64):
            scenario = scenarios[f"candidate-count-{count}"]
            with self.subTest(count=count):
                self.assertEqual(scenario["logical_outer_cohort_count"], count)
                self.assertEqual(scenario["expected_count"], 0)
                self.assertEqual(
                    scenario["candidate_observation"]["status"],
                    "pending-observation",
                )
                self.assertIsNone(
                    scenario["candidate_observation"][
                        "observed_backend_candidate_count"
                    ]
                )
                self.assertEqual(scenario["requested_attributes"], ["1.1"])
                self.assertEqual(scenario["server_support"], ["389ds", "openldap"])

        for count in (15, 16, 32, 64, 128, 355, 500, 1000):
            scenario = scenarios[f"branch-count-{count}-zero-candidate"]
            with self.subTest(branch_count=count):
                self.assertEqual(scenario["logical_outer_cohort_count"], 0)
                self.assertEqual(scenario["expected_count"], 0)
                self.assertEqual(scenario["relevant_values_per_entry"], 0)
                self.assertEqual(scenario["assertion_counts"]["total"], count)
                self.assertEqual(
                    scenario["expected_lookup_diagnostic"]["expectation"],
                    "required-when-lookup-on" if count >= 16 else "forbidden",
                )

    def test_generation_is_byte_deterministic(self) -> None:
        self.assertEqual(self.tiny_manifest, self.tiny_manifest_b)
        self.assertEqual(
            (self.tiny_a / "workload-manifest.json").read_bytes(),
            (self.tiny_b / "workload-manifest.json").read_bytes(),
        )
        self.assertEqual(self.tiny_manifest["files"], self.tiny_manifest_b["files"])

    def test_server_specific_ldifs_separate_aci_and_dynamic_urls(self) -> None:
        canonical = (self.tiny_a / "data.ldif").read_text()
        openldap = (self.tiny_a / "data-openldap.ldif").read_text()
        self.assertIn('userdn="ldap:///all"', canonical)
        self.assertNotIn("\naci: ", openldap)
        self.assertIn("objectClass: groupOfURLs", canonical)
        self.assertIn("memberURL: ", canonical)
        self.assertNotIn("objectClass: groupOfURLs", openldap)
        self.assertNotIn("memberURL: ", openldap)
        self.assertIn("objectClass: groupOfNames", openldap)
        self.assertEqual(
            canonical.count("\ndn: ") + int(canonical.startswith("dn: ")),
            self.tiny_manifest["entry_counts"]["ldif_records_total"],
        )
        self.assertEqual(
            openldap.count("\ndn: ") + int(openldap.startswith("dn: ")),
            self.tiny_manifest["entry_counts"]["openldap_ldif_records_total"],
        )
        self.assertEqual(
            self.tiny_manifest["dynamic_list"]["bind_password"],
            "LargeFilterStudy-Only-42",
        )

    def test_smoke_profile_retains_all_families_and_612_primary_entries(self) -> None:
        manifest = self.smoke_manifest
        self.assertEqual(manifest["entries"], 12000)
        self.assertEqual(manifest["entry_counts"]["principal_cohort"], 612)
        self.assertEqual(
            manifest["scenarios"]["principal-with-sdn2-equality"][
                "logical_outer_cohort_count"
            ],
            612,
        )
        candidate = manifest["scenarios"]["candidate-count-612"]
        self.assertEqual(candidate["logical_outer_cohort_count"], 612)
        self.assertEqual(candidate["parameters"]["cohort_source"], "principal")
        self.assertEqual(
            candidate["logical_outer_cohort_sha256"],
            manifest["scenarios"]["principal-with-sdn2-equality"][
                "logical_outer_cohort_sha256"
            ],
        )
        self.assertEqual(
            manifest["scenarios"]["candidate-count-10000"][
                "logical_outer_cohort_count"
            ],
            10000,
        )
        self.assertEqual(
            manifest["scenarios"]["branch-count-15-mostly-live"][
                "expected_count"
            ],
            15,
        )
        self.assertEqual(
            manifest["scenarios"]["branch-count-1000-mostly-live"][
                "expected_count"
            ],
            20,
        )
        self.assertTrue(REQUIRED_GROUPS.issubset(manifest["scenario_groups"]))
        self.assertTrue(all(
            scenario["smoke_selected"] for scenario in manifest["scenarios"].values()
        ))

    def test_existing_output_is_rejected_without_mutation(self) -> None:
        existing = self.root / "existing-output"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("preserve me\n")
        with self.assertRaises(FileExistsError):
            generate_workload(DEFAULT_SPEC, "tiny", existing)
        self.assertEqual(sentinel.read_text(), "preserve me\n")
        self.assertEqual({path.name for path in existing.iterdir()}, {"sentinel"})

    def test_failed_atomic_publish_cleans_temporary_sibling(self) -> None:
        target = self.root / "never-published"
        before = set(self.root.iterdir())
        with self.assertRaisesRegex(RuntimeError, "injected failure"):
            with atomic_output_directory(target) as temporary:
                (temporary / "partial").write_text("partial\n")
                raise RuntimeError("injected failure")
        self.assertFalse(target.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_broken_output_symlink_is_not_followed_or_replaced(self) -> None:
        target = self.root / "broken-output-link"
        missing = self.root / "missing-link-destination"
        os.symlink(missing, target)
        with self.assertRaises(FileExistsError):
            generate_workload(DEFAULT_SPEC, "tiny", target)
        self.assertTrue(target.is_symlink())
        self.assertEqual(Path(os.readlink(target)), missing)
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
