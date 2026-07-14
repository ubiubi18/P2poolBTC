from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLYSCRIPT_VERSION = "0.27.37"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ContractToolchainLockTest(unittest.TestCase):
    def test_contracts_and_build_manifests_use_reviewed_assemblyscript(self) -> None:
        package_paths = (
            ROOT / "contracts/idena-snapshot-registry/package.json",
            ROOT / "contracts/idena-code-governance/package.json",
        )
        manifest_paths = (
            ROOT / "compatibility/governance-build-plan-v1.json",
            ROOT / "compatibility/governance-fork-lock.json",
        )

        for path in package_paths:
            with self.subTest(path=path.relative_to(ROOT)):
                package = load_json(path)
                self.assertEqual(
                    package["devDependencies"]["assemblyscript"],
                    ASSEMBLYSCRIPT_VERSION,
                )

        for path in manifest_paths:
            with self.subTest(path=path.relative_to(ROOT)):
                manifest = load_json(path)
                self.assertEqual(
                    manifest["toolchains"]["assemblyscript"],
                    ASSEMBLYSCRIPT_VERSION,
                )


if __name__ == "__main__":
    unittest.main()
