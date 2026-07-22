import copy
import importlib.util
import json
import re
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "pohw-experiment-2-consensus-identity.py"
POLICY = ROOT / "compatibility" / "experiment-2-consensus-identity-policy.fixture.json"
AUTHORIZATION = (
    ROOT
    / "compatibility"
    / "experiment-2-consensus-identity-authorization.fixture.json"
)
MANIFEST = ROOT / "compatibility" / "experiment-2-consensus-identity-candidate.json"
LOCK = ROOT / "compatibility" / "experiment-2-bitcoin-core-patch-lock.json"
BUILD_EVIDENCE = ROOT / "scripts" / "pohw-bitcoin-core-build-evidence.py"
BUILDER = ROOT / "scripts" / "pohw-build-bitcoin-core-fork.sh"
SOURCE_VERIFIER = ROOT / "scripts" / "pohw-verify-bitcoin-core-source.sh"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def load_validator():
    spec = importlib.util.spec_from_file_location("pohw_experiment_2", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Experiment2ConsensusIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()
        cls.policy = json.loads(POLICY.read_text(encoding="utf-8"))
        cls.authorization = json.loads(AUTHORIZATION.read_text(encoding="utf-8"))
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.lock = json.loads(LOCK.read_text(encoding="utf-8"))

    def test_tracked_candidate_and_patch_series_verify(self):
        result = subprocess.run(
            ["python3", str(VALIDATOR), "--repo-root", str(ROOT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("inactive Experiment 2", result.stdout)

    def test_cross_language_fixed_vectors_match(self):
        self.assertEqual(
            self.validator.policy_hash(self.policy),
            self.validator.EXPECTED_POLICY_HASH,
        )
        self.assertEqual(
            self.validator.activation_id(self.manifest),
            self.validator.EXPECTED_ACTIVATION_ID,
        )
        self.validator.verify_authorization(self.policy, self.authorization)

    def test_merkle_proof_and_identity_state_fail_closed(self):
        bad_proof = copy.deepcopy(self.authorization)
        bad_proof["proof"]["siblings"][0] = "00" * 32
        with self.assertRaisesRegex(self.validator.VerificationError, "Merkle proof"):
            self.validator.verify_authorization(self.policy, bad_proof)

        short_proof = copy.deepcopy(self.authorization)
        short_proof["proof"]["siblings"].pop()
        with self.assertRaisesRegex(self.validator.VerificationError, "proof depth"):
            self.validator.verify_authorization(self.policy, short_proof)

        long_proof = copy.deepcopy(self.authorization)
        long_proof["proof"]["siblings"].append("00" * 32)
        with self.assertRaisesRegex(self.validator.VerificationError, "proof depth"):
            self.validator.verify_authorization(self.policy, long_proof)

        ineligible = copy.deepcopy(self.authorization)
        ineligible["leaf"]["identity_state"] = "Candidate"
        with self.assertRaisesRegex(self.validator.VerificationError, "ineligible"):
            self.validator.verify_authorization(self.policy, ineligible)

    def test_activation_cannot_be_enabled_without_a_new_id(self):
        active = copy.deepcopy(self.manifest)
        active["status"] = "experimental-active"
        active["launch_enabled"] = True
        self.assertNotEqual(
            self.validator.activation_id(active),
            self.manifest["activation_id"],
        )

    def test_policy_capacity_and_time_windows_fail_closed(self):
        shallow = copy.deepcopy(self.policy)
        shallow["max_proof_depth"] = 1
        with self.assertRaisesRegex(
            self.validator.VerificationError, "too small"
        ):
            self.validator.policy_hash(shallow)

        over_capacity = copy.deepcopy(self.policy)
        over_capacity["authorized_identity_count"] = (1 << 16) + 1
        with self.assertRaisesRegex(
            self.validator.VerificationError, "tree capacity"
        ):
            self.validator.policy_hash(over_capacity)

        stale = copy.deepcopy(self.policy)
        stale["bitcoin_expiry_mtp"] = stale["idena_next_validation_timestamp"] + 1
        with self.assertRaisesRegex(
            self.validator.VerificationError, "MTP expiry"
        ):
            self.validator.policy_hash(stale)

        oversized_window = copy.deepcopy(self.policy)
        oversized_window["idena_next_validation_timestamp"] = (
            oversized_window["idena_finalized_timestamp"]
            + self.validator.MAX_SNAPSHOT_SECONDS
            + 1
        )
        with self.assertRaisesRegex(
            self.validator.VerificationError, "snapshot time window"
        ):
            self.validator.policy_hash(oversized_window)

    def test_patch_digest_substitution_is_rejected(self):
        tampered = copy.deepcopy(self.lock)
        tampered["patch_series"][1]["sha256"] = "00" * 32
        with self.assertRaisesRegex(self.validator.VerificationError, "patch SHA-256"):
            self.validator.verify_lock(ROOT, tampered, self.policy, self.manifest)

    def test_activation_source_and_parent_substitution_is_rejected(self):
        wrong_series = copy.deepcopy(self.manifest)
        wrong_series["bitcoin_core_patch_series_sha256"] = "ff" * 32
        with self.assertRaisesRegex(
            self.validator.VerificationError, "locked patch series"
        ):
            self.validator.verify_lock(ROOT, self.lock, self.policy, wrong_series)

        wrong_source = copy.deepcopy(self.manifest)
        wrong_source["bitcoin_core_upstream_commit"] = "ff" * 20
        with self.assertRaisesRegex(
            self.validator.VerificationError, "upstream commit"
        ):
            self.validator.verify_lock(ROOT, self.lock, self.policy, wrong_source)

        wrong_parent = copy.deepcopy(self.manifest)
        wrong_parent["authorization_parent_hash"] = "ff" * 32
        with self.assertRaisesRegex(
            self.validator.VerificationError, "parent hash"
        ):
            self.validator.verify_lock(ROOT, self.lock, self.policy, wrong_parent)

    def test_duplicate_json_keys_are_rejected(self):
        raw = POLICY.read_text(encoding="utf-8")
        duplicate = raw.replace(
            '"schema_version": 1,',
            '"schema_version": 2,\n  "schema_version": 1,',
            1,
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "duplicate.json"
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(
                self.validator.VerificationError, "duplicate JSON key"
            ):
                self.validator.read_json(path)

    def test_clean_room_build_profile_requires_experiment_2_consensus_tests(self):
        evidence = runpy.run_path(str(BUILD_EVIDENCE))
        profile = evidence["manifest_profile"](self.lock)
        activation_flag = (
            "-DPOHW2_ACTIVATION_ID="
            + self.lock["network"]["candidate_activation_id"]
        )
        self.assertEqual(profile["id"], "experiment-2")
        self.assertIn(activation_flag, profile["cmake_flags"])
        self.assertEqual(
            profile["test_filters"]["consensus_identity"],
            "pohw_identity_auth_tests",
        )
        self.assertIn("consensus_identity", profile["required_steps"])
        self.assertIn("consensus_identity_functional", profile["required_steps"])
        self.assertEqual(
            profile["functional_tests"][-1],
            ("consensus_identity_functional", "feature_pohw_identity_auth.py"),
        )

    def test_clean_room_scripts_apply_the_series_and_record_profile_only_steps(self):
        verifier = SOURCE_VERIFIER.read_text(encoding="utf-8")
        builder = BUILDER.read_text(encoding="utf-8")
        self.assertIn('for PATCH in "${PATCHES[@]}"', verifier)
        self.assertIn("pohw-experiment-2-consensus-identity.py", verifier)
        self.assertIn("-DPOHW2_ACTIVATION_ID=$POHW2_ACTIVATION_ID", builder)
        self.assertIn("run_profile_step consensus_identity", builder)
        self.assertIn("feature_pohw_identity_auth.py", builder)

    def test_ci_builds_and_tests_the_locked_bitcoin_core_consensus_patch(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        marker = "  bitcoin-core-consensus:\n"
        self.assertEqual(workflow.count(marker), 1)
        job_start = workflow.index(marker)
        next_job = re.search(
            r"^  [a-z0-9-]+:\n",
            workflow[job_start + len(marker) :],
            re.MULTILINE,
        )
        job_end = (
            len(workflow)
            if next_job is None
            else job_start + len(marker) + next_job.start()
        )
        job = workflow[job_start:job_end]
        required_commands = (
            "pohw-experiment-2-consensus-identity.py",
            "pohw-verify-bitcoin-core-source.sh",
            "experiment-2-bitcoin-core-patch-lock.json",
            "-DPOHW2_ACTIVATION_ID=$POHW2_ACTIVATION_ID",
            "cmake --build",
            "--run_test=pohw_identity_auth_tests",
            "feature_pohw_replay.py",
            "feature_pohw_identity_auth.py",
            "ctest --test-dir",
        )
        for command in required_commands:
            with self.subTest(command=command):
                self.assertIn(command, job)

    def test_snapshot_and_build_assurance_cannot_be_downgraded(self):
        weak_snapshot = copy.deepcopy(self.lock)
        weak_snapshot["snapshot_assurance"]["minimum_matching_captures"] = 1
        with self.assertRaisesRegex(
            self.validator.VerificationError, "snapshot assurance policy differs"
        ):
            self.validator.verify_lock(
                ROOT, weak_snapshot, self.policy, self.manifest
            )

        false_row_proof = copy.deepcopy(self.lock)
        false_row_proof["snapshot_assurance"][
            "identity_rows_cryptographically_bound_to_root"
        ] = True
        with self.assertRaisesRegex(
            self.validator.VerificationError, "snapshot assurance policy differs"
        ):
            self.validator.verify_lock(
                ROOT, false_row_proof, self.policy, self.manifest
            )

        weak_build = copy.deepcopy(self.lock)
        weak_build["independent_builds"]["comparison_release_authorized"] = True
        with self.assertRaisesRegex(
            self.validator.VerificationError, "independent build policy differs"
        ):
            self.validator.verify_lock(ROOT, weak_build, self.policy, self.manifest)


if __name__ == "__main__":
    unittest.main()
