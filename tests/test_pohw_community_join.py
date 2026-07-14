import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.sh"
POWERSHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.ps1"
SCHEMA = ROOT / "schemas" / "pohw-source-join-v1.schema.json"
PACKAGE_SCRIPT = ROOT / "scripts" / "pohw-experiment-package.sh"
STATUS_SCRIPT = ROOT / "scripts" / "pohw-community-status.py"
COMMUNITY_GUIDE = ROOT / "COMMUNITY-README.md"
EXPERIMENT_RUNBOOK = ROOT / "EXPERIMENT-0.md"
ACTIVATION_ID = "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"


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

    def test_guides_explain_observable_success_without_claiming_a_core_balance(self):
        community = COMMUNITY_GUIDE.read_text(encoding="utf-8")
        experiment = EXPERIMENT_RUNBOOK.read_text(encoding="utf-8")
        for source in (community, experiment):
            self.assertIn("pohw-community-status.py", source)
            self.assertIn("Bitcoin Core", source)
            self.assertIn("p2pool-node", source)
        self.assertIn("Bitcoin Core Qt will not show", community)
        self.assertIn("bitcoin-cli getbalance", community)
        self.assertIn("Sharechain", community)
        self.assertIn("Fork blocks", community)

    @unittest.skipIf(os.name == "nt", "fixture executable uses a POSIX shebang")
    def test_status_command_rechecks_receipts_and_redacts_private_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = pathlib.Path(temporary)
            datadir = temporary_root / "agent"
            receipt_dir = datadir / "build-receipt"
            registration_dir = datadir / "node" / "agent-registration"
            receipt_dir.mkdir(parents=True, mode=0o700)
            registration_dir.mkdir(parents=True, mode=0o700)

            fake_node = temporary_root / "p2pool-node"
            fake_node.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import sys

                    command = sys.argv[1]
                    if command == "verify-miner-registration-envelope":
                        value = {
                            "valid": True,
                            "message_hash": "22" * 32,
                            "envelope_hash": "33" * 32,
                            "registration_binding_hash": "44" * 32,
                            "miner_registration": {
                                "miner_id": "fixture-miner",
                                "idena_address": "0x" + "11" * 20,
                                "btc_payout_script_hex": "5120" + "55" * 32,
                                "claim_owner_pubkey_hex": "66" * 32,
                                "mining_pubkey_hex": "77" * 32,
                            },
                        }
                    elif command == "status":
                        value = {
                            "replay": {
                                "applied_message_count": 12,
                                "registered_miner_count": 2,
                                "active_share_count": 3,
                                "inactive_share_count": 1,
                                "share_miner_count": 2,
                                "snapshot_vote_root_count": 1,
                            }
                        }
                    elif command == "fork-chain-status":
                        value = {
                            "activation_id": "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e",
                            "tip_height": 957784,
                            "active_fork_block_count": 3,
                            "stored_block_count": 3,
                            "difficulty_phase": "bootstrap",
                        }
                    else:
                        raise SystemExit(2)
                    print(json.dumps(value))
                    """
                ),
                encoding="utf-8",
            )
            fake_node.chmod(0o700)
            binary_sha = hashlib.sha256(fake_node.read_bytes()).hexdigest()

            activation_path = receipt_dir / "fork-activation.json"
            activation_bytes = (
                json.dumps({"activation_id": ACTIVATION_ID}, separators=(",", ":"))
                + "\n"
            ).encode()
            activation_path.write_bytes(activation_bytes)
            activation_path.chmod(0o600)
            activation_sha = hashlib.sha256(activation_bytes).hexdigest()

            source_cid = "bafkreifixturecidforstatuscommandonly000000000000000000000"
            git_commit = "88" * 20
            join_manifest = {
                "schema_version": "pohw-source-join/v1",
                "experiment_id": "pohw-experiment-0",
                "network_mode": "join-existing",
                "trust_model": "local-source-build",
                "source": {
                    "git_commit": git_commit,
                    "source_tree_cid": source_cid,
                    "local_artifact": {"sha256": binary_sha},
                },
                "activation": {
                    "activation_id": ACTIVATION_ID,
                    "manifest_sha256": activation_sha,
                },
                "launch": {
                    "phase": "mining",
                    "no_value": True,
                    "mainnet_handoff_armed": False,
                },
            }
            manifest_bytes = (json.dumps(join_manifest, sort_keys=True) + "\n").encode()
            (receipt_dir / "source-join-manifest.json").write_bytes(manifest_bytes)
            (receipt_dir / "source-join-manifest.json").chmod(0o600)

            config = {
                "schema_version": "pohw-agent-config/v2",
                "datadir": str(datadir),
                "join_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "p2pool_node_path": str(fake_node),
                "p2pool_node_sha256": binary_sha,
                "activation_manifest_path": str(activation_path),
                "source_tree_cid": source_cid,
                "git_commit": git_commit,
            }
            (datadir / "agent-config.json").write_text(
                json.dumps(config), encoding="utf-8"
            )
            (datadir / "agent-config.json").chmod(0o600)

            registration = {
                "status": "registration_ready",
                "miner_id": "fixture-miner",
                "idena_address": "0x" + "11" * 20,
                "message_hash": "22" * 32,
                "envelope_hash": "33" * 32,
                "registration_binding_hash": "44" * 32,
                "btc_payout_script_hex": "5120" + "55" * 32,
                "claim_owner_pubkey_hex": "66" * 32,
                "mining_pubkey_hex": "77" * 32,
                "gossip_delivery": [
                    {
                        "endpoint": "private-peer.example:40406",
                        "delivered": True,
                    }
                ],
            }
            for path, value in (
                (registration_dir / "registration-public.json", registration),
                (registration_dir / "miner-registration-message.json", {"fixture": True}),
                (registration_dir / "miner-registration-envelope.json", {"fixture": True}),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)

            result = subprocess.run(
                [
                    "python3",
                    str(STATUS_SCRIPT),
                    "--datadir",
                    str(datadir),
                    "--json",
                ],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            status = json.loads(result.stdout)
            self.assertTrue(status["phase_ready"])
            self.assertTrue(status["registration"]["verified"])
            self.assertEqual(status["fork"]["tip_height"], 957784)
            self.assertEqual(status["sharechain"]["active_shares"], 3)
            self.assertFalse(status["bitcoin_core"]["contains_experiment_fork"])
            self.assertNotIn(str(temporary_root), result.stdout)
            self.assertNotIn("private-peer.example", result.stdout)
            self.assertNotIn("0x" + "11" * 20, result.stdout)
            self.assertNotIn("fixture-miner", result.stdout)


if __name__ == "__main__":
    unittest.main()
