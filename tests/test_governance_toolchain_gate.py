import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "governance_toolchain_gate",
    ROOT / "scripts" / "pohw-governance-toolchain-gate.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GovernanceToolchainGateTests(unittest.TestCase):
    def test_parses_exact_locked_versions(self):
        versions = MODULE.parse_versions({
            "rust": "rustc 1.97.0 (deadbeef 2026-07-07)",
            "go": "go version go1.26.5 darwin/arm64",
            "node": "v24.18.0",
            "npm": "11.16.0",
            "pnpm": "11.11.0",
            "assemblyscript": "Version 0.27.37",
        })
        self.assertEqual(versions["rust"], "1.97.0")
        self.assertEqual(versions["go"], "1.26.5")

    def test_rejects_unparseable_output(self):
        with self.assertRaises(MODULE.ToolchainGateError):
            MODULE.parse_versions({
                "rust": "rustc latest",
                "go": "go version go1.26.5 darwin/arm64",
                "node": "v24.18.0",
                "npm": "11.16.0",
                "pnpm": "11.11.0",
                "assemblyscript": "Version 0.27.37",
            })


if __name__ == "__main__":
    unittest.main()
