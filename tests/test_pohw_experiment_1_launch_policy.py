import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "compatibility" / "experiment-1-launch-policy.json"
SCRIPT = ROOT / "scripts" / "pohw-experiment-1-launch-policy.py"
SPEC = importlib.util.spec_from_file_location("pohw_launch_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Experiment1LaunchPolicyTests(unittest.TestCase):
    DAG_CBOR_CID = "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq"

    def complete_readiness(self, policy):
        policy["public_join_readiness"].update(
            {key: True for key in MODULE.READINESS_BOOLEAN_FIELDS}
        )
        policy["public_join_readiness"].update(
            {
                "verified_independent_registry_build_operators": 2,
                "deployment_readiness_report_cid": self.DAG_CBOR_CID,
                "deployment_readiness_report_car_sha256": "11" * 32,
                "deployment_readiness_candidate_ecosystem_cid": self.DAG_CBOR_CID,
            }
        )

    def test_checked_in_policy_is_valid_and_blocked(self):
        result = subprocess.run(
            ["python3", str(SCRIPT), str(POLICY), "--repo-root", str(ROOT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("blocked-release-readiness", result.stdout)

    def test_ready_status_cannot_bypass_incomplete_gates(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        policy["status"] = MODULE.READY_STATUS
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "must remain blocked"):
            MODULE.validate(policy, POLICY, ROOT)

    def test_completed_flags_still_require_deployment_and_independent_builders(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.complete_readiness(policy)
        policy["status"] = MODULE.READY_STATUS
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "must remain blocked"):
            MODULE.validate(policy, POLICY, ROOT)

        policy = copy.deepcopy(policy)
        policy["registry_deployment"] = {"finalized": True}
        MODULE.validate(policy, POLICY, ROOT)

    def test_empty_deployment_record_cannot_open_joining(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.complete_readiness(policy)
        policy["registry_deployment"] = {}
        policy["status"] = MODULE.READY_STATUS
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "must remain blocked"):
            MODULE.validate(policy, POLICY, ROOT)

    def test_missing_or_noncanonical_readiness_report_cannot_open_joining(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        policy["public_join_readiness"].update(
            {key: True for key in MODULE.READINESS_BOOLEAN_FIELDS}
        )
        policy["public_join_readiness"][
            "verified_independent_registry_build_operators"
        ] = 2
        policy["registry_deployment"] = {"finalized": True}
        policy["status"] = MODULE.READY_STATUS
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "must remain blocked"):
            MODULE.validate(policy, POLICY, ROOT)

        policy["public_join_readiness"].update(
            {
                "deployment_readiness_report_cid": (
                    "bafkreigxrilyixjonuw6ebyg4eksguukqcpq7gb35gmeszwqonsaqq53ae"
                ),
                "deployment_readiness_report_car_sha256": "11" * 32,
                "deployment_readiness_candidate_ecosystem_cid": self.DAG_CBOR_CID,
            }
        )
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "DAG-CBOR"):
            MODULE.validate(policy, POLICY, ROOT)

    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text('{"status":"first","status":"second"}\n', encoding="ascii")
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "duplicate JSON key"):
                MODULE.read_json(path, "launch policy")


if __name__ == "__main__":
    unittest.main()
