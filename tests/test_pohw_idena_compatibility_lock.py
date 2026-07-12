from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-idena-compatibility-lock.py"
LOCK = ROOT / "compatibility" / "stack-lock.json"
SPEC = importlib.util.spec_from_file_location("pohw_idena_compatibility_lock", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IdenaCompatibilityLockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.canonical = json.loads(LOCK.read_text(encoding="utf-8"))

    def test_accepts_reviewed_candidate(self) -> None:
        MODULE.verify_lock(copy.deepcopy(self.canonical))

    def test_rejects_consensus_or_network_changes(self) -> None:
        for field, value in (("mainnetNetworkId", 2), ("consensusChangesAllowed", True)):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.canonical)
                payload["chainInvariants"][field] = value
                with self.assertRaises(MODULE.CompatibilityError):
                    MODULE.verify_lock(payload)

    def test_rejects_changed_pohw_pin(self) -> None:
        payload = copy.deepcopy(self.canonical)
        payload["consumerPins"]["P2poolBTC"]["idena-go"] = "0" * 40
        with self.assertRaisesRegex(MODULE.CompatibilityError, "PoHW node pin changed"):
            MODULE.verify_lock(payload)

    def test_provenance_must_match_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "source-commit"
            path.write_text(f'{MODULE.EXPECTED["node_commit"]}\n', encoding="ascii")
            MODULE.verify_provenance(path, MODULE.EXPECTED["node_commit"])
            path.write_text(f'{MODULE.EXPECTED["legacy_commit"]}\n', encoding="ascii")
            with self.assertRaisesRegex(MODULE.CompatibilityError, "does not match"):
                MODULE.verify_provenance(path, MODULE.EXPECTED["node_commit"])

    def test_provenance_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "target"
            target.write_text(f'{MODULE.EXPECTED["node_commit"]}\n', encoding="ascii")
            link = Path(temp_dir) / "source-commit"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.CompatibilityError, "regular file"):
                MODULE.verify_provenance(link, MODULE.EXPECTED["node_commit"])


if __name__ == "__main__":
    unittest.main()
