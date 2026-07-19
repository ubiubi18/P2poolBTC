import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-compare-bitcoin-core-builds.py"
LOCK_PATH = ROOT / "compatibility" / "experiment-2-bitcoin-core-patch-lock.json"


def load_module():
    spec = importlib.util.spec_from_file_location("pohw_compare_core_builds", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CompareBitcoinCoreBuildsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        cls.lock_sha256 = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        cls.profile = cls.module.load_evidence_module(ROOT).manifest_profile(cls.lock)

    def evidence(self, marker: int) -> dict:
        artifacts = {
            "bitcoin-cli": {"path": "pohw-release/bin/bitcoin-cli", "sha256": "11" * 32, "size_bytes": 101},
            "bitcoind": {"path": "pohw-release/bin/bitcoind", "sha256": "22" * 32, "size_bytes": 202},
            "test_bitcoin": {"path": "pohw-release/libexec/test_bitcoin", "sha256": "33" * 32, "size_bytes": 303},
        }
        return {
            "schema_version": self.module.EVIDENCE_SCHEMA,
            "activation_id": self.profile["activation_id"],
            "manifest_sha256": self.lock_sha256,
            "upstream_commit": self.profile["upstream_commit"],
            "patch_sha256": self.profile["patch_sha256"],
            "source_snapshot": {"snapshot": {"sha256": "44" * 32}},
            "build": {
                "generator": "Ninja",
                "cmake_flags": list(self.profile["cmake_flags"]),
                "cmake_cache": {"CMAKE_GENERATOR": "Ninja"},
                "cmake_cxx_configuration_sha256": "55" * 32,
                "depends": {"host": "fixture-host"},
                "environment": {"builder_marker": str(marker)},
                "commands": [
                    {
                        "label": label,
                        "argv": ["/fixture/tool", label],
                        "env": {},
                        "exit_code": 0,
                        "log_path": f"pohw-build-logs/{label}.log",
                        "output_sha256": f"{marker:02x}" * 32,
                    }
                    for label in self.profile["required_steps"]
                ],
                "run_record_sha256": "66" * 32,
                "snapshot_metadata_sha256": "77" * 32,
            },
            "tests": {"status": "passed", "required_steps": list(self.profile["test_steps"])},
            "toolchain": {"builder_marker": marker},
            "artifacts": artifacts,
        }

    def write_evidence(self, directory: Path, marker: int, value=None) -> Path:
        path = directory / f"builder-{marker}.json"
        path.write_text(json.dumps(value or self.evidence(marker), sort_keys=True) + "\n", encoding="ascii")
        return path

    def test_three_matching_builds_produce_an_unattributed_nonrelease_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = [self.write_evidence(root, marker) for marker in (1, 2, 3)]
            report = self.module.compare(ROOT, LOCK_PATH, paths, 3)
        self.assertEqual(report["matching_build_count"], 3)
        self.assertFalse(report["operator_independence_verified"])
        self.assertFalse(report["release_authorized"])
        self.assertIn("BuildAttestationV1", report["next_gate"])

    def test_mismatching_artifact_and_missing_identity_test_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            values = [self.evidence(marker) for marker in (1, 2, 3)]
            values[2]["artifacts"]["bitcoind"]["sha256"] = "ff" * 32
            paths = [self.write_evidence(root, marker, value) for marker, value in enumerate(values, 1)]
            with self.assertRaisesRegex(self.module.ComparisonError, "artifact sets"):
                self.module.compare(ROOT, LOCK_PATH, paths, 3)

            missing = self.evidence(4)
            missing["tests"]["required_steps"].remove("consensus_identity")
            with self.assertRaisesRegex(self.module.ComparisonError, "required tests"):
                self.module.validate_evidence(
                    missing, self.lock, self.lock_sha256, self.profile
                )

            subset = self.evidence(5)
            subset["artifacts"].pop("test_bitcoin")
            with self.assertRaisesRegex(self.module.ComparisonError, "exact required artifact"):
                self.module.validate_evidence(
                    subset, self.lock, self.lock_sha256, self.profile
                )

    def test_duplicate_payload_and_two_build_threshold_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            duplicate = self.evidence(1)
            first = self.write_evidence(root, 1, duplicate)
            second = self.write_evidence(root, 2, duplicate)
            third = self.write_evidence(root, 3)
            with self.assertRaisesRegex(self.module.ComparisonError, "duplicate"):
                self.module.compare(ROOT, LOCK_PATH, [first, second, third], 3)
            with self.assertRaisesRegex(self.module.ComparisonError, "at least three"):
                self.module.compare(ROOT, LOCK_PATH, [first, third], 2)


if __name__ == "__main__":
    unittest.main()
