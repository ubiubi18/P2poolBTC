import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-experiment-1-replay-probe.py"
SPEC = importlib.util.spec_from_file_location("pohw_replay_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Experiment1ReplayProbeTests(unittest.TestCase):
    def test_unprotected_spend_must_reach_the_replay_gate(self):
        outcome = MODULE.validate_probe_results(
            {"allowed": False, "reject-reason": MODULE.REPLAY_REJECT_REASON},
            {
                "allowed": False,
                "reject-reason": "bad-txns-premature-spend-of-coinbase",
            },
        )
        self.assertEqual(outcome, "passed-replay-gate-then-rejected-by-later-rule")

        with self.assertRaisesRegex(MODULE.ProbeError, "did not reach"):
            MODULE.validate_probe_results(
                {"allowed": False, "reject-reason": "tx-size-small"},
                {
                    "allowed": False,
                    "reject-reason": "bad-txns-premature-spend-of-coinbase",
                },
            )

    def test_unknown_later_rejection_does_not_create_false_assurance(self):
        with self.assertRaisesRegex(MODULE.ProbeError, "recognized later"):
            MODULE.validate_probe_results(
                {"allowed": False, "reject-reason": MODULE.REPLAY_REJECT_REASON},
                {"allowed": False, "reject-reason": "missing-inputs"},
            )

    def test_marker_protected_result_cannot_still_be_a_replay_rejection(self):
        with self.assertRaisesRegex(MODULE.ProbeError, "still rejected"):
            MODULE.validate_probe_results(
                {"allowed": False, "reject-reason": MODULE.REPLAY_REJECT_REASON},
                {"allowed": False, "reject-reason": MODULE.REPLAY_REJECT_REASON},
            )
        self.assertEqual(
            MODULE.validate_probe_results(
                {"allowed": False, "reject-reason": MODULE.REPLAY_REJECT_REASON},
                {"allowed": True},
            ),
            "accepted-by-mempool-simulation",
        )

    def test_manifest_parser_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text('{"status":"first","status":"second"}\n', encoding="ascii")
            with self.assertRaisesRegex(MODULE.ProbeError, "duplicate JSON key"):
                MODULE.read_manifest(manifest)

    def test_probe_output_and_source_never_publish_transactions(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("testmempoolaccept", source)
        self.assertNotIn('"sendrawtransaction"', source)
        self.assertNotIn('print(txid', source)
        self.assertNotIn('print(raw_transaction', source)

    def test_installed_manifest_is_preferred_over_repository_layout(self):
        source = SCRIPT.read_text(encoding="utf-8")
        installed = source.index('distribution_root / "experiment-manifest.json"')
        repository = source.index(
            'distribution_root / "compatibility/experiment-1-full-consensus.json"'
        )
        selection = source.index(
            "installed_manifest if installed_manifest.is_file() else repository_manifest"
        )
        self.assertLess(installed, selection)
        self.assertLess(repository, selection)

    def test_input_encoding_is_canonical(self):
        encoded = json.dumps(
            [{"txid": "00" * 32, "vout": 1}],
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(encoded, '[{"txid":"' + "00" * 32 + '","vout":1}]')


if __name__ == "__main__":
    unittest.main()
