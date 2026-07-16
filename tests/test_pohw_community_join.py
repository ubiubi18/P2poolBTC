import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.sh"
POWERSHELL_SCRIPT = ROOT / "scripts" / "pohw-community-join.ps1"
SCHEMA = ROOT / "schemas" / "pohw-source-join-v1.schema.json"
PACKAGE_SCRIPT = ROOT / "scripts" / "pohw-experiment-package.sh"
STATUS_SCRIPT = ROOT / "scripts" / "pohw-community-status.py"
COMMUNITY_GUIDE = ROOT / "COMMUNITY-README.md"
EXPERIMENT_RUNBOOK = ROOT / "EXPERIMENT-0.md"
EXPERIMENT_1_COMMUNITY_GUIDE = ROOT / "COMMUNITY-EXPERIMENT-1.md"
EXPERIMENT_1_QUICKSTART = ROOT / "COMMUNITY-QUICKSTART.md"
EXPERIMENT_1_VERIFICATION_FORM = (
    ROOT / ".github" / "ISSUE_TEMPLATE" / "experiment-1-independent-verification.yml"
)
ACTIVATION_ID = "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"


class CommunityJoinTests(unittest.TestCase):
    def test_experiment_1_docs_separate_review_from_live_join(self):
        readme = README.read_text(encoding="utf-8")
        guide = EXPERIMENT_1_COMMUNITY_GUIDE.read_text(encoding="utf-8")

        for source in (readme, guide):
            self.assertIn("Review And Rehearse Now", source)
            self.assertIn("blocked-release-readiness", source)
            self.assertIn("vibe/experiment-1-release-readiness", source)
            self.assertIn("source CID", source)
            self.assertIn("CAR digest", source)
            self.assertIn("loopback-only", source)
            self.assertIn("sharechain", source)

        self.assertIn("Five-Step Live Journey", readme)
        self.assertIn("Join Live Only After The Interlock Opens", guide)
        self.assertIn("uses no Idena identity signature", guide)
        self.assertIn("must not create a registration", guide)
        self.assertIn("revision-3 checkpoint height `958175`", guide)
        self.assertIn("getblockhash 958175", guide)
        self.assertIn(
            "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6",
            guide,
        )

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


class Experiment1CommunityGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guide = EXPERIMENT_1_COMMUNITY_GUIDE.read_text(encoding="utf-8")
        cls.step_five = cls.guide.split(
            "## 5. Start P2Pool And Mine", maxsplit=1
        )[1].split("## How To Know You Joined Successfully", maxsplit=1)[0]
        cls.guide_prose = " ".join(cls.guide.split())
        cls.step_five_prose = " ".join(cls.step_five.split())

    def test_public_join_interlock_remains_strict_and_blocked(self) -> None:
        blocked_verifier = textwrap.dedent(
            """\
            STATUS=$(python3 scripts/pohw-experiment-1-launch-policy.py \\
              compatibility/experiment-1-launch-policy.json | \\
              sed -n 's/^launch policy verified: //p')
            test "$STATUS" = blocked-release-readiness
            """
        )
        self.assertIn("blocked-release-readiness", self.guide)
        self.assertIn(blocked_verifier, self.guide)
        self.assertGreaterEqual(self.guide.count("--readiness-car"), 2)
        self.assertGreaterEqual(self.guide.count("--readiness-evidence-car"), 2)
        self.assertGreaterEqual(self.guide.count("--governance-cli"), 2)
        self.assertGreaterEqual(self.guide.count("--idena-anchor-policy"), 2)
        self.assertGreaterEqual(self.guide.count("--require-ready"), 2)
        self.assertIn(
            "Do not invite people to connect miners to the live experiment yet.",
            self.guide_prose,
        )

    def test_review_day_tracks_are_explicit_and_fail_closed(self) -> None:
        quickstart = EXPERIMENT_1_QUICKSTART.read_text(encoding="utf-8")
        verification_form = EXPERIMENT_1_VERIFICATION_FORM.read_text(
            encoding="utf-8"
        )
        for role in (
            "Observer or source reviewer",
            "Independent miner-registry builder",
            "Second-node host operator",
        ):
            self.assertIn(role, quickstart)
            self.assertIn(role, verification_form)
        self.assertIn("--role observer", quickstart)
        self.assertIn("onboarding receipts\nmust not turn hostile source", quickstart)
        self.assertNotIn("--role observer --run-tests", quickstart)
        self.assertIn("--role pruned-miner", quickstart)
        self.assertIn("blocked-public-join", quickstart)
        self.assertIn("does not authorize identity registration", verification_form)
        self.assertIn("I did not register an identity", verification_form)
        self.assertIn("private vulnerability", quickstart)
        self.assertIn("id: source_cid", verification_form)
        self.assertIn("id: source_car_sha256", verification_form)
        self.assertIn("never replaces the source CID", verification_form)

    def test_evidence_install_and_preflight_precede_every_p2pool_start(self) -> None:
        step = self.step_five
        install = step.index(
            "INSTALL_RESULT=$(sudo scripts/pohw-install-experiment-1-adapter.sh"
        )
        placeholder = step.index("RefuseManualStart=yes")
        preflight = step.index("build-dynamic-pohw-stratum-job-rpc")
        cleanup = step.index("start_failed()")
        marker = step.index(
            "sudo install -o root -g root -m 0600 /dev/null"
        )
        gossip_start = step.index(
            "sudo systemctl start pohw-gossip-mesh.service"
        )
        adapter_start = step.index(
            "sudo systemctl start pohw-mining-adapter.service"
        )

        self.assertLess(placeholder, install)
        self.assertLess(install, preflight)
        self.assertLess(preflight, cleanup)
        self.assertLess(cleanup, marker)
        self.assertLess(preflight, marker)
        self.assertLess(marker, gossip_start)
        self.assertLess(gossip_start, adapter_start)
        self.assertNotIn("systemctl enable --now", step)
        self.assertIn("services remain stopped", step)
        self.assertIn("test \"$unit_status\" -eq 3", step)
        self.assertIn(
            "/etc/pohw/enable-experiment-1-mining || start_failed", step
        )
        self.assertIn(
            '"$INSTALLED_NODE" status --datadir "$POHW_DATADIR" || start_failed',
            step,
        )
        for argument in (
            '--source-root "$REPO"',
            '--build-plan "$BUILD_PLAN"',
            '--build-evidence "$EVIDENCE_DIR/build-evidence.json"',
            '--expected-evidence-sha256 "$EXPECTED_EVIDENCE_SHA256"',
            '--expected-source-cid "$EXPECTED_SOURCE_CID"',
            '--binary "$REPO/target/release/p2pool-node"',
        ):
            self.assertIn(argument, step)

    def test_systemd_uses_only_fixed_evidence_installed_runtime_paths(self) -> None:
        step = self.step_five
        runtime = "/usr/local/libexec/p2pool-experiment-1"
        for path in (
            f"{runtime}/p2pool-node",
            f"{runtime}/pohw-run-gossip-mesh.sh",
            f"{runtime}/pohw-run-mining-adapter.sh",
            f"{runtime}/pohw-health-status.py",
            "/etc/systemd/system/pohw-gossip-mesh.service",
            "/etc/systemd/system/pohw-mining-adapter.service",
            "/etc/systemd/system/pohw-gossip-mesh.service.d/server.conf",
            "/etc/systemd/system/pohw-mining-adapter.service.d/server.conf",
        ):
            self.assertIn(path, step)
        self.assertIn(f"POHW_WORKDIR={runtime}", step)
        self.assertIn(f"POHW_P2POOL_NODE_BIN={runtime}/p2pool-node", step)
        self.assertNotIn("ExecStart=/mnt/ssd/p2pool/scripts/", step)
        self.assertNotIn("ExecStart=/opt/p2pool/scripts/", step)
        self.assertNotIn("deploy/systemd/pohw-bootstrap-miner.service", step)
        self.assertIn(
            "systemd does not execute a wrapper or helper from the checkout",
            self.step_five_prose,
        )
        self.assertIn(
            'test "$(sudo systemctl show -p User --value "$unit")" = pohw',
            step,
        )
        self.assertIn("grep -Fqw /srv/sharechain", step)
        self.assertIn(
            'test "$(sudo systemctl show -p RefuseManualStart --value "$unit")" = no',
            step,
        )
        self.assertIn('systemctl is-enabled --quiet "$unit"', step)
        self.assertNotIn("sudo -u ubuntu", step)

    def test_runtime_configuration_is_manifest_policy_and_local_rpc_bound(self) -> None:
        step = self.step_five
        for required in (
            'DATA_SUBDIRECTORY=$(python3 -c',
            'POHW_DATADIR="/srv/sharechain/${DATA_SUBDIRECTORY}-${ACTIVATION_ID:0:8}"',
            "POHW_GOSSIP_NETWORK_ID=$ACTIVATION_ID",
            "inspect-idena-anchor-policy",
            "EXPECTED_POLICY_SHA256='<published-v2-policy-sha256>'",
            "EXPECTED_POLICY_COMMITMENT='<published-v2-policy-commitment>'",
            "V2 Idena policy evidence verified",
            "--idena-rpc-url http://127.0.0.1:9009",
            "IDENA_API_KEY_FILE=/etc/pohw/secrets/idena-api.key",
            "POHW_BITCOIN_RPC_URL=http://127.0.0.1:40414",
            "POHW_BITCOIN_EXPECTED_CHAIN=pohw",
            "POHW_BITCOIN_RPC_COOKIE_FILE=/run/bitcoin-pohw-rpc/.cookie",
            "test \"$(sudo stat -c %a \"$RPC_COOKIE\")\" = 640",
            "sync-gossip",
            "multinode-preflight",
            "reachable < 1",
            "mining-snapshot-evidence",
            "run_pohw_rpc_to",
            "sudo cmp -s \"$MANIFEST\" /etc/pohw/experiment-1-full-consensus.json",
            "sha256sum /etc/pohw/idena-anchor-policy-v2.json",
        ):
            self.assertIn(required, step)

    def test_secret_files_are_paths_with_restrictive_modes_and_pi_is_observer_only(
        self,
    ) -> None:
        step = self.step_five
        self.assertIn(
            'sudo install -o root -g pohw -m 0640 "$IDENA_API_KEY_SOURCE"',
            step,
        )
        self.assertIn('test "$(stat -c %a "$KEY_DIR/$secret")" = 600', step)
        self.assertIn(
            'sudo find "$POHW_DATADIR" -xdev -type l -print -quit', step
        )
        self.assertIn('sudo chown -hR pohw:pohw "$POHW_DATADIR"', step)
        self.assertIn(
            'test "$(sudo stat -c %U:%G /etc/pohw/secrets/idena-api.key)" = root:pohw',
            step,
        )
        self.assertIn("require_safe_regular_destination /etc/pohw/p2pool.env", step)
        self.assertIn(
            "require_safe_regular_destination /etc/pohw/miner-registry-anchor.json",
            step,
        )
        self.assertIn("400|440|600|640", step)
        self.assertIn(
            'sudo install -o root -g root -m 0600 "$ENV_TMP"', step
        )
        self.assertIn("unset IDENA_API_KEY_SOURCE", step)
        self.assertNotIn("IDENA_API_KEY=", step)
        self.assertIn("Pi is observer-only", self.guide)
        self.assertIn(
            'test "$(getent passwd pohw | cut -d: -f7)" = /usr/sbin/nologin',
            self.guide,
        )
        self.assertIn("never a Pi or systemd workload", self.step_five_prose)

    def test_step_five_embeds_only_loopback_endpoints_and_placeholders(self) -> None:
        ipv4_literals = set(
            re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", self.step_five)
        )
        self.assertEqual(ipv4_literals, {"127.0.0.1"})
        public_checkpoint = (
            "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6"
        )
        self.assertEqual(self.step_five.count(public_checkpoint), 1)
        self.assertIsNone(
            re.search(r"\b[0-9a-fA-F]{40,}\b", self.step_five.replace(public_checkpoint, ""))
        )
        for placeholder in (
            "<published-build-evidence-sha256>",
            "<published-canonical-source-cid>",
            "<published-v2-policy-sha256>",
            "<published-v2-policy-commitment>",
            "<verified-gossip-peer-ip:40406>",
        ):
            self.assertIn(placeholder, self.step_five)


if __name__ == "__main__":
    unittest.main()
