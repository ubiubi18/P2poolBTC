import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.sh"
POWERSHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.ps1"
SCHEMA = ROOT / "schemas" / "pohw-source-join-v1.schema.json"
PACKAGE_SCRIPT = ROOT / "scripts" / "pohw-experiment-package.sh"


class CommunityJoinTests(unittest.TestCase):
    def test_shell_script_is_valid_and_documents_source_only_trust(self):
        subprocess.run(["bash", "-n", str(SHELL_SCRIPT)], check=True)
        result = subprocess.run(
            ["bash", str(SHELL_SCRIPT), "--help"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("trusts no prebuilt executable", result.stdout)
        self.assertIn("no lead-developer signature", result.stdout)

    def test_shell_script_has_no_binary_download_or_signature_bypass(self):
        source = SHELL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("cargo build", source)
        self.assertIn("--locked", source)
        self.assertIn("join-source", source)
        self.assertIn("mktemp -d", source)
        self.assertIn("ls-files --others --ignored --exclude-standard --directory", source)
        self.assertIn('export CARGO_TARGET_DIR="$BUILD_ROOT"', source)
        self.assertIn('cd -- "$ROOT_DIR"', source)
        self.assertIn('--build-root "$BUILD_ROOT"', source)
        self.assertIn('--snapshot-dir "$SNAPSHOT_DIR"', source)
        self.assertIn('--snapshot-min-voters "$SNAPSHOT_MIN_VOTERS"', source)
        for forbidden in (
            "curl ",
            "wget ",
            "eval ",
            "trusted-signer",
            "bootstrap-sign",
            "skip-build",
            "agent-bin",
            "--snapshot-id",
            "--snapshot-proof-root",
            "--snapshot-source-height",
            "--snapshot-distinct-voter-count",
        ):
            self.assertNotIn(forbidden, source)

    def test_missing_peer_hints_fail_before_build(self):
        result = subprocess.run(
            ["bash", str(SHELL_SCRIPT)],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--gossip-peer", result.stderr)

    def test_windows_launcher_uses_the_same_source_only_command(self):
        source = POWERSHELL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("cargo build", source)
        self.assertIn("--locked", source)
        self.assertIn('"join-source"', source)
        self.assertIn("[Guid]::NewGuid()", source)
        self.assertIn("ls-files --others --ignored --exclude-standard --directory", source)
        self.assertIn("$env:CARGO_TARGET_DIR = $BuildRoot", source)
        self.assertIn("Push-Location -LiteralPath $RootDir", source)
        self.assertIn("if ($locationPushed) { Pop-Location }", source)
        self.assertIn('"--build-root", $BuildRoot', source)
        self.assertIn('"--snapshot-dir", $SnapshotDir', source)
        self.assertIn('"--snapshot-min-voters", "$SnapshotMinVoters"', source)
        self.assertNotIn("Invoke-WebRequest", source)
        self.assertNotIn("trusted-signer", source)

    def test_schema_is_strict_and_has_no_single_signer_authority(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["trust_model"]["const"],
            "local-source-build",
        )
        serialized = json.dumps(schema)
        self.assertNotIn("authorization", serialized)
        self.assertNotIn("signer", serialized)
        self.assertIn(
            "cyclonedx_sbom_sha256",
            schema["properties"]["source"]["required"],
        )
        self.assertEqual(
            schema["properties"]["launch"]["properties"]["mainnet_handoff_armed"]["const"],
            False,
        )

    def test_source_bundle_includes_agent_assets_windows_launcher_and_schema(self):
        source = PACKAGE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("*/assets/*.html", source)
        self.assertIn("*.ps1", source)
        self.assertIn("add_find schemas", source)


if __name__ == "__main__":
    unittest.main()
