import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-compare-idena-snapshots.py"


def load_module():
    spec = importlib.util.spec_from_file_location("pohw_compare_idena_snapshots", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CompareIdenaSnapshotsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def report(self) -> dict:
        return {
            "schema_version": self.module.VERIFICATION_SCHEMA,
            "status": "verified-inactive-input",
            "experiment_id": "p2poolbtc-experiment-2",
            "registry_contract_address": "0x" + "11" * 20,
            "source_input_hash": "22" * 32,
            "idena_finalized_height": 100,
            "idena_finalized_timestamp": 1_800_000_000,
            "idena_finalized_block_hash": "0x" + "33" * 32,
            "idena_identity_root": "0x" + "44" * 32,
            "idena_finality_height": 106,
            "idena_finality_block_hash": "0x" + "55" * 32,
            "finality_confirmations": 6,
            "idena_next_validation_timestamp": 1_800_086_400,
            "authorization_root": "66" * 32,
            "authorized_identity_count": 7,
        }

    def fixture(self, directory: Path, reports: list[dict]):
        verifier = directory / "fake-indexer"
        verifier.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "path = pathlib.Path(sys.argv[sys.argv.index('--input-file') + 1])\n"
            "sys.stdout.write(path.read_text(encoding='ascii'))\n",
            encoding="ascii",
        )
        verifier.chmod(0o700)
        inputs = []
        bundles = []
        for index, report in enumerate(reports):
            input_path = directory / f"input-{index}.json"
            bundle_path = directory / f"bundle-{index}.json"
            input_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="ascii")
            bundle_path.write_text("{}\n", encoding="ascii")
            inputs.append(input_path)
            bundles.append(bundle_path)
        return verifier, inputs, bundles

    def test_three_matching_verified_pairs_remain_unattributed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            verifier, inputs, bundles = self.fixture(
                directory, [self.report(), self.report(), self.report()]
            )
            result = self.module.compare(verifier, inputs, bundles, 3)
        self.assertEqual(result["matching_capture_count"], 3)
        self.assertTrue(result["distinct_capture_files_verified"])
        self.assertEqual(result["identity_rows_assurance"], "compatible-rpc-unproven")
        self.assertFalse(result["identity_rows_cryptographically_bound_to_root"])
        self.assertFalse(result["operator_independence_verified"])
        self.assertFalse(result["release_authorized"])
        self.assertIn("distinct eligible Idena owner", result["next_gate"])

    def test_boundary_mismatch_and_low_threshold_fail_closed(self):
        different = copy.deepcopy(self.report())
        different["authorization_root"] = "ff" * 32
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            verifier, inputs, bundles = self.fixture(
                directory, [self.report(), self.report(), different]
            )
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "authorization_root"
            ):
                self.module.compare(verifier, inputs, bundles, 3)
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "at least three"
            ):
                self.module.compare(verifier, inputs[:2], bundles[:2], 2)

    def test_unknown_verification_field_is_rejected(self):
        report = self.report()
        report["age"] = 99
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            verifier, inputs, bundles = self.fixture(
                directory, [report, report, report]
            )
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "fields differ"
            ):
                self.module.compare(verifier, inputs, bundles, 3)

    def test_verifier_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            verifier, inputs, bundles = self.fixture(
                directory, [self.report(), self.report(), self.report()]
            )
            link = directory / "linked-indexer"
            link.symlink_to(verifier)
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "must not be a symlink"
            ):
                self.module.compare(link, inputs, bundles, 3)

    def test_repeated_paths_and_hardlinks_do_not_count_as_independent_captures(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            verifier, inputs, bundles = self.fixture(
                directory, [self.report(), self.report(), self.report()]
            )
            repeated_inputs = [inputs[0], inputs[0], inputs[2]]
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "repeats a capture path"
            ):
                self.module.compare(verifier, repeated_inputs, bundles, 3)

            hardlink = directory / "input-hardlink.json"
            os.link(inputs[0], hardlink)
            hardlinked_inputs = [inputs[0], hardlink, inputs[2]]
            with self.assertRaisesRegex(
                self.module.SnapshotComparisonError, "repeats a capture file"
            ):
                self.module.compare(verifier, hardlinked_inputs, bundles, 3)


if __name__ == "__main__":
    unittest.main()
