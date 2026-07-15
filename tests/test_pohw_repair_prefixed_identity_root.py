from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-repair-prefixed-identity-root.py"
SPEC = importlib.util.spec_from_file_location("repair_prefixed_root", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def commitment(prefixed: bool = True) -> dict[str, object]:
    root = "0x" + "22" * 32 if prefixed else "22" * 32
    return {
        "type": "PohwCommitment",
        "payload": {
            "version": "POHW1",
            "idena_snapshot_id": "fixture",
            "idena_score_root": "11" * 32,
            "miner_idena_address": "0x" + "33" * 20,
            "identity_proof_root": root,
            "sharechain_tip": "44" * 32,
            "sharechain_state_root": "55" * 32,
            "payout_schedule_root": "66" * 32,
            "vault_epoch_id": 1,
            "frost_vault_key_xonly": "77" * 32,
        },
    }


class PrefixedIdentityRootRepairTests(unittest.TestCase):
    def test_repair_quarantines_only_the_invalid_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            datadir = Path(temporary)
            registration = {"type": "FixtureRegistration", "payload": {"ok": True}}
            bad = commitment()
            sharechain = datadir / "sharechain.ndjson"
            gossip = datadir / "gossip-envelopes.ndjson"
            sharechain.write_text(
                json.dumps(registration) + "\n" + json.dumps(bad) + "\n",
                encoding="utf-8",
            )
            gossip.write_text(
                json.dumps({"envelope": {"message": registration}})
                + "\n"
                + json.dumps({"envelope": {"message": bad}, "signature": "fixture"})
                + "\n",
                encoding="utf-8",
            )
            (datadir / "confirmed-payouts.ndjson").write_text("", encoding="utf-8")
            (datadir / "sharechain-index.json").write_text("{}\n", encoding="utf-8")

            self.assertEqual(MODULE.repair(datadir, False), (1, 2))
            self.assertEqual(MODULE.repair(datadir, True), (1, 2))

            self.assertEqual(
                [json.loads(line) for line in sharechain.read_text().splitlines()],
                [registration],
            )
            self.assertEqual(
                [json.loads(line) for line in gossip.read_text().splitlines()],
                [{"envelope": {"message": registration}}],
            )
            self.assertFalse((datadir / "sharechain-index.json").exists())
            quarantine = datadir / "quarantine-prefixed-identity-root.json"
            self.assertEqual(stat.S_IMODE(quarantine.stat().st_mode), 0o600)
            self.assertEqual(len(json.loads(quarantine.read_text())["records"]), 2)
            self.assertTrue(
                (datadir / "sharechain.ndjson.pre-prefixed-identity-root-repair").is_file()
            )
            self.assertTrue(
                (datadir / "gossip-envelopes.ndjson.pre-prefixed-identity-root-repair").is_file()
            )

    def test_repair_refuses_confirmed_payout_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            datadir = Path(temporary)
            bad = commitment()
            (datadir / "sharechain.ndjson").write_text(json.dumps(bad) + "\n")
            (datadir / "gossip-envelopes.ndjson").write_text(
                json.dumps({"envelope": {"message": bad}}) + "\n"
            )
            (datadir / "confirmed-payouts.ndjson").write_text("{}\n")

            with self.assertRaisesRegex(MODULE.RepairError, "confirmed payout"):
                MODULE.repair(datadir, True)

    def test_noncanonical_defects_outside_identity_root_are_not_repaired(self) -> None:
        value = commitment()
        value["payload"]["sharechain_tip"] = "bad"  # type: ignore[index]
        self.assertFalse(MODULE.malformed_prefixed_commitment(value))


if __name__ == "__main__":
    unittest.main()
