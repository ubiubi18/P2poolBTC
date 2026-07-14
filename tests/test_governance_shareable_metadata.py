import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GovernanceShareableMetadataTests(unittest.TestCase):
    def test_governance_metadata_has_no_machine_specific_home_path(self):
        roots = [
            ROOT / "docs" / "governance",
            ROOT / "schemas" / "governance",
            ROOT / "compatibility" / "governance-build-plan-v1.json",
            ROOT / "compatibility" / "governance-fork-lock.json",
            ROOT / "compatibility" / "governance-testnet-parameters-v1.json",
        ]
        home_patterns = [
            re.compile(r"/Users/[A-Za-z0-9._-]+/"),
            re.compile(r"/home/[A-Za-z0-9._-]+/"),
            re.compile(r"[A-Za-z]:\\Users\\[^\\]+\\"),
        ]
        findings = []
        for root in roots:
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in paths:
                if not path.is_file() or path.suffix.lower() not in {".json", ".md"}:
                    continue
                text = path.read_text(encoding="utf-8")
                if any(pattern.search(text) for pattern in home_patterns):
                    findings.append(path.relative_to(ROOT).as_posix())
        self.assertEqual([], findings)

    def test_inventory_contains_no_private_key_material(self):
        inventory = (ROOT / "docs" / "governance" / "REPOSITORY-INVENTORY.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("BEGIN PRIVATE KEY", inventory.upper())
        self.assertNotRegex(inventory, r"(?i)(?:password|api[_-]?key)\s*[:=]\s*\S+")


if __name__ == "__main__":
    unittest.main()
