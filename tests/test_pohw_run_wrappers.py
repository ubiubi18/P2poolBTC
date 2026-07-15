import os
import subprocess
import tempfile
import unittest
import json
import datetime as dt
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MINING_ADAPTER_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-mining-adapter.sh"
FORK_CHAIN_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-fork-chain-node.sh"
GOSSIP_MESH_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-gossip-mesh.sh"
DASHBOARD_UI_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-dashboard-ui.sh"
DASHBOARD_API_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-dashboard-api.sh"
DASHBOARD_MAIN = REPO_ROOT / "ui" / "pohw-dashboard" / "src" / "main.tsx"
LOCAL_GOSSIP_PEER_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-local-gossip-peer.sh"


class RunWrapperValidationTest(unittest.TestCase):
    def test_dashboard_source_rejects_build_time_api_tokens(self) -> None:
        source = DASHBOARD_MAIN.read_text(encoding="utf-8")

        self.assertNotIn("VITE_POHW_DASHBOARD_API_TOKEN", source)
        self.assertIn("runtimeDashboardConfig.apiToken", source)

    def base_env(self, root: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_DATADIR": str(root / "datadir"),
                "POHW_MINER_ID": "alice",
                "POHW_IDENA_SNAPSHOT_ID": "2026-07-05",
                "POHW_IDENA_SNAPSHOT_PROOF_ROOT": "11" * 32,
                "POHW_STRATUM_JOB_FILE": str(root / "job.json"),
                "POHW_BITCOIN_EXPECTED_CHAIN": "pohw",
                "POHW_GOSSIP_NETWORK_ID": "ab" * 32,
            }
        )
        return env

    def write_fake_node(self, root: Path) -> Path:
        fake = root / "p2pool-node"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'CALL\\n' >> \"$POHW_FAKE_NODE_ARGS_OUT\"\n"
            "printf '%s\\n' \"$@\" >> \"$POHW_FAKE_NODE_ARGS_OUT\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def write_fake_http_server(self, root: Path) -> Path:
        fake = root / "fake-http-server"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'cwd=%s\\n' \"$PWD\" > \"$POHW_FAKE_HTTP_OUT\"\n"
            "printf 'args=%s\\n' \"$*\" >> \"$POHW_FAKE_HTTP_OUT\"\n"
            "printf 'config=' >> \"$POHW_FAKE_HTTP_OUT\"\n"
            "tr -d '\\n' < pohw-dashboard-config.js >> \"$POHW_FAKE_HTTP_OUT\"\n"
            "printf '\\n' >> \"$POHW_FAKE_HTTP_OUT\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def test_mining_adapter_refuses_packaged_example_job_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-example-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            Path(env["POHW_STRATUM_JOB_FILE"]).write_text(
                '{ "job_id": "experiment-0-example" }\n',
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to start Stratum with the packaged example mining job", result.stderr)

    def test_mining_adapter_allows_example_job_only_for_explicit_dry_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-dry-run-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = self.base_env(root)
            env.update(
                {
                    "POHW_ALLOW_EXAMPLE_MINING_JOB": "true",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )
            Path(env["POHW_STRATUM_JOB_FILE"]).write_text(
                '{ "job_id": "experiment-0-example" }\n',
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-mining-adapter", args)
        self.assertIn("initialize-gossip-network", args)
        self.assertIn("--network-id\n" + "ab" * 32, args)
        self.assertIn("--allow-example-mining-job", args)
        self.assertIn(str(root / "job.json"), args)
        self.assertIn("--block-candidate-dir", args)
        self.assertIn(str(root / "datadir" / "block-candidates"), args)

    def test_mining_adapter_forwards_idena_anchor_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-idena-anchor-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            policy = root / "idena-anchor-policy.json"
            api_key = root / "idena-api.key"
            policy.write_text("{}\n", encoding="utf-8")
            api_key.write_text("local-test-key\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_IDENA_ANCHOR_POLICY": str(policy),
                    "IDENA_RPC_URL": "http://127.0.0.1:9009",
                    "IDENA_API_KEY_FILE": str(api_key),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )
            Path(env["POHW_STRATUM_JOB_FILE"]).write_text(
                '{ "job_id": "live-job" }\n', encoding="utf-8"
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--idena-anchor-policy\n" + str(policy), args)
        self.assertIn("--idena-rpc-url\nhttp://127.0.0.1:9009", args)
        self.assertIn("--idena-api-key-file\n" + str(api_key), args)
        self.assertNotIn("--allow-remote-idena-rpc", args)

    def test_mining_adapter_mandatory_anchor_policy_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-required-anchor-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            env["POHW_REQUIRE_IDENA_ANCHOR_POLICY"] = "true"
            env.pop("POHW_IDENA_ANCHOR_POLICY", None)

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required by this launch profile", result.stderr)

    def test_pohw_rpc_mining_requires_a_gossip_network_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-network-id-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = self.base_env(root)
            env.pop("POHW_GOSSIP_NETWORK_ID")
            env.update(
                {
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("POHW_GOSSIP_NETWORK_ID is required", result.stderr)
        self.assertFalse(args_out.exists())

    def test_mining_adapter_can_refresh_job_from_local_rpc_before_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-rpc-job-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            cookie = root / "bitcoin.cookie"
            cookie.write_text("__cookie__:secret\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_BUILD_JOB_FROM_RPC": "true",
                    "POHW_BITCOIN_RPC_URL": "http://127.0.0.1:8332",
                    "POHW_BITCOIN_RPC_COOKIE_FILE": str(cookie),
                    "POHW_BITCOIN_RPC_USER": "rpcuser",
                    "POHW_BITCOIN_RPC_PASSWORD": "super-secret-rpc-password",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build-stratum-job-rpc", args)
        self.assertIn("--replace", args)
        self.assertIn("--rpc-cookie-file", args)
        self.assertIn(str(cookie), args)
        self.assertNotIn("--rpc-password", args)
        self.assertNotIn("super-secret-rpc-password", args)
        self.assertIn("run-mining-adapter", args)
        self.assertIn("--refresh-job-from-rpc", args)

    def test_mainnet_handoff_uses_dynamic_payouts_without_static_job_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-dynamic-mainnet-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            commitment = root / "pohw-commitment.json"
            commitment.write_text("{}\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_MAINNET_HANDOFF_ACTIVE": "true",
                    "POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE": "true",
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_STRATUM_ALLOW_MAINNET_SUBMIT": "true",
                    "POHW_BITCOIN_EXPECTED_CHAIN": "main",
                    "POHW_STRATUM_POHW_COMMITMENT_FILE": str(commitment),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_PAYOUT_CANDIDATE_DIR": str(root / "payout-candidates"),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-mining-adapter", args)
        self.assertIn("--derive-pohw-payouts-from-state", args)
        self.assertIn("--derive-pohw-min-snapshot-voters\n3", args)
        self.assertIn("--snapshot-dir", args)
        self.assertIn("--payout-candidate-dir", args)
        self.assertIn("--pohw-commitment-file", args)
        self.assertIn("--refresh-job-from-rpc", args)
        self.assertIn("--auto-submit-blocks", args)
        self.assertIn("--allow-mainnet-submit", args)
        self.assertIn("--rpc-url\nhttp://127.0.0.1:8332", args)
        self.assertIn("--expected-rpc-chain\nmain", args)
        self.assertNotIn("--payout-schedule-file", args)
        self.assertNotIn("--job-file", args)
        self.assertNotIn("build-pohw-stratum-job-rpc", args)
        self.assertIn("--job-refresh-interval-seconds", args)

    def test_mining_adapter_health_gate_blocks_rpc_job_refresh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-health-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            health_file = root / "health.json"
            health_file.write_text(
                json.dumps(
                    {
                        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "readiness": {
                            "miningReady": False,
                            "blockers": ["bitcoin_rpc_timeout"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_BUILD_JOB_FROM_RPC": "true",
                    "POHW_HEALTH_STATUS_FILE": str(health_file),
                    "POHW_HEALTH_SCRIPT": str(REPO_ROOT / "scripts" / "pohw-health-status.py"),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PoHW health is not mining-ready", result.stderr)
        self.assertFalse(args_out.exists())

    def test_mining_adapter_can_refresh_pohw_job_from_local_rpc_before_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-pohw-rpc-job-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            payout_schedule = root / "payout-schedule.json"
            pohw_commitment = root / "pohw-commitment.json"
            payout_schedule.write_text("{}\n", encoding="utf-8")
            pohw_commitment.write_text("{}\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC": "true",
                    "POHW_STRATUM_PAYOUT_SCHEDULE_FILE": str(payout_schedule),
                    "POHW_STRATUM_POHW_COMMITMENT_FILE": str(pohw_commitment),
                    "POHW_BITCOIN_RPC_URL": "http://127.0.0.1:8332",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build-pohw-stratum-job-rpc", args)
        self.assertIn("--payout-schedule-file", args)
        self.assertIn(str(payout_schedule), args)
        self.assertIn("--pohw-commitment-file", args)
        self.assertIn(str(pohw_commitment), args)
        self.assertIn("run-mining-adapter", args)
        self.assertIn("--refresh-job-from-rpc", args)

    def test_mining_adapter_auto_submit_is_explicit_and_uses_rpc_without_rebuilding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-auto-submit-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            cookie = root / "bitcoin.cookie"
            cookie.write_text("__cookie__:secret\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_BITCOIN_RPC_COOKIE_FILE": str(cookie),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )
            Path(env["POHW_STRATUM_JOB_FILE"]).write_text(
                '{ "job_id": "live-job" }\n', encoding="utf-8"
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-mining-adapter", args)
        self.assertIn("--auto-submit-blocks", args)
        self.assertNotIn("--allow-mainnet-submit", args)
        self.assertIn("--rpc-cookie-file", args)
        self.assertNotIn("build-stratum-job-rpc", args)
        self.assertNotIn("build-pohw-stratum-job-rpc", args)

    def test_mining_adapter_mainnet_submission_requires_separate_opt_in(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-mainnet-submit-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_STRATUM_ALLOW_MAINNET_SUBMIT": "true",
                    "POHW_BITCOIN_EXPECTED_CHAIN": "main",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )
            Path(env["POHW_STRATUM_JOB_FILE"]).write_text(
                '{ "job_id": "live-job" }\n', encoding="utf-8"
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--auto-submit-blocks", args)
        self.assertIn("--allow-mainnet-submit", args)
        self.assertIn("--expected-rpc-chain\nmain", args)

    def test_mining_adapter_refuses_rpc_without_expected_chain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-chain-binding-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            env.pop("POHW_BITCOIN_EXPECTED_CHAIN")
            env.update(
                {
                    "POHW_STRATUM_BUILD_JOB_FROM_RPC": "true",
                    "POHW_FAKE_NODE_ARGS_OUT": str(root / "args.txt"),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("POHW_BITCOIN_EXPECTED_CHAIN must be pohw or main", result.stderr)

    def test_mining_adapter_rejects_conflicting_job_refresh_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-conflicting-jobs-") as temp:
            root = Path(temp)
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_BUILD_JOB_FROM_RPC": "true",
                    "POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC": "true",
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Enable only one Bitcoin RPC job mode", result.stderr)

    def test_mining_adapter_uses_live_fork_templates_without_bitcoin_rpc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-fork-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR": "127.0.0.1:40408",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_BITCOIN_RPC_USER": "must-not-be-forwarded",
                    "POHW_BITCOIN_RPC_PASSWORD": "must-not-be-forwarded",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = args_out.read_text(encoding="utf-8")

        self.assertIn("--fork-chain-rpc-addr", args)
        self.assertIn("--fork-chain-activation-manifest", args)
        self.assertIn("--auto-submit-blocks", args)
        self.assertIn(
            "--share-target\n7fffff0000000000000000000000000000000000000000000000000000000000",
            args,
        )
        self.assertIn("--stratum-difficulty\n4.6565423739069247e-10", args)
        self.assertNotIn("--allow-mainnet-submit", args)
        self.assertNotIn("--job-file", args)
        self.assertNotIn("--rpc-url", args)
        self.assertNotIn("must-not-be-forwarded", args)

    def test_mining_adapter_derives_dynamic_payouts_from_fork_templates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-fork-payout-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            commitment = root / "pohw-commitment.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            commitment.write_text("{}\n", encoding="utf-8")
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR": "127.0.0.1:40408",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE": "true",
                    "POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS": "1",
                    "POHW_STRATUM_POHW_COMMITMENT_FILE": str(commitment),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_PAYOUT_CANDIDATE_DIR": str(root / "payout-candidates"),
                    "POHW_STRATUM_AUTO_SUBMIT_BLOCKS": "true",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = args_out.read_text(encoding="utf-8")

        self.assertIn("--fork-chain-rpc-addr", args)
        self.assertIn("--derive-pohw-payouts-from-state", args)
        self.assertIn("--derive-pohw-min-snapshot-voters\n1", args)
        self.assertIn("--snapshot-dir", args)
        self.assertIn("--payout-candidate-dir", args)
        self.assertIn("--pohw-commitment-file", args)
        self.assertIn("--auto-submit-blocks", args)
        self.assertNotIn("--refresh-job-from-rpc", args)
        self.assertNotIn("--allow-mainnet-submit", args)
        self.assertNotIn("--rpc-url", args)
        self.assertNotIn("--payout-schedule-file", args)

    def test_mining_adapter_rejects_invalid_fork_pow_limit_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-mining-wrapper-fork-policy-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_text(
                '{"config":{"post_fork_pow_limit_bits":0}}\n', encoding="utf-8"
            )
            env = self.base_env(root)
            env.update(
                {
                    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR": "127.0.0.1:40408",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(MINING_ADAPTER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("negative or zero PoW limit", result.stderr)
        self.assertFalse(args_out.exists())

    def test_fork_chain_runner_enforces_no_value_ack_and_peer_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-fork-wrapper-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            env = dict(os.environ)
            env.update(
                {
                    "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
                    "POHW_EXPERIMENT_NETWORK_MODE": "join-existing",
                    "POHW_FORK_CHAIN_DATADIR": str(root / "fork-chain"),
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FORK_P2P_BIND_ADDR": "127.0.0.1:40409",
                    "POHW_FORK_PEER_ADDRS": "127.0.0.1:41409,127.0.0.1:42409",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(FORK_CHAIN_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-fork-chain-node", args)
        self.assertIn("--activation-manifest", args)
        self.assertIn("127.0.0.1:41409", args)
        self.assertIn("127.0.0.1:42409", args)

    def test_fork_chain_runner_rejects_peerless_ordinary_joiner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-fork-peerless-joiner-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            env = dict(os.environ)
            env.pop("POHW_FORK_PEER_ADDRS", None)
            env.pop("POHW_FORK_BOOTSTRAP_FIRST_SEED", None)
            env.update(
                {
                    "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
                    "POHW_EXPERIMENT_NETWORK_MODE": "join-existing",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(FORK_CHAIN_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires at least one POHW_FORK_PEER_ADDRS entry", result.stderr)
        self.assertFalse(args_out.exists())

    def test_fork_chain_runner_allows_explicit_canonical_first_seed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-fork-first-seed-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            env = dict(os.environ)
            env.pop("POHW_FORK_PEER_ADDRS", None)
            env.update(
                {
                    "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
                    "POHW_EXPERIMENT_NETWORK_MODE": "join-existing",
                    "POHW_FORK_BOOTSTRAP_FIRST_SEED": "true",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(FORK_CHAIN_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-fork-chain-node", args)
        self.assertNotIn("--peer-addr", args)

    def test_fork_chain_runner_rejects_stale_first_seed_exception(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-fork-stale-first-seed-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_bytes(
                (REPO_ROOT / "compatibility" / "experiment-0-activation.json").read_bytes()
            )
            env = dict(os.environ)
            env.update(
                {
                    "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
                    "POHW_EXPERIMENT_NETWORK_MODE": "join-existing",
                    "POHW_FORK_BOOTSTRAP_FIRST_SEED": "true",
                    "POHW_FORK_PEER_ADDRS": "127.0.0.1:41409",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(FORK_CHAIN_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exception must be removed once fork peers are configured", result.stderr)
        self.assertFalse(args_out.exists())

    def test_fork_chain_runner_rejects_other_activation_in_join_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-fork-join-guard-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_text('{"activation_id":"different-network"}\n', encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
                    "POHW_EXPERIMENT_NETWORK_MODE": "join-existing",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(FORK_CHAIN_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing noncanonical activation manifest", result.stderr)
        self.assertFalse(args_out.exists())

    def test_gossip_mesh_admits_templates_against_local_fork_node(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-gossip-fork-admission-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "fork-activation.json"
            manifest.write_text("{}\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_ADMIT_PEER_WORK_TEMPLATES": "true",
                    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR": "127.0.0.1:40408",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_BITCOIN_RPC_PASSWORD": "must-not-be-forwarded",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--admit-peer-work-templates", args)
        self.assertIn("--fork-chain-rpc-addr", args)
        self.assertIn("--fork-chain-activation-manifest", args)
        self.assertNotIn("--rpc-url", args)
        self.assertNotIn("must-not-be-forwarded", args)

    def test_gossip_mesh_anchor_policy_requires_admission_and_api_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-gossip-idena-anchor-") as temp:
            root = Path(temp)
            policy = root / "idena-anchor-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_IDENA_ANCHOR_POLICY": str(policy),
                    "POHW_FAKE_NODE_ARGS_OUT": str(root / "args.txt"),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )
            env.pop("IDENA_API_KEY_FILE", None)

            no_admission = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            env["POHW_ADMIT_PEER_WORK_TEMPLATES"] = "true"
            no_key = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(no_admission.returncode, 0)
        self.assertIn("requires POHW_ADMIT_PEER_WORK_TEMPLATES=true", no_admission.stderr)
        self.assertNotEqual(no_key.returncode, 0)
        self.assertIn("IDENA_API_KEY_FILE is required", no_key.stderr)

    def test_gossip_mesh_forwards_idena_anchor_policy_to_local_rpc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-gossip-idena-anchor-ok-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            policy = root / "idena-anchor-policy.json"
            api_key = root / "idena-api.key"
            manifest = root / "fork-activation.json"
            policy.write_text("{}\n", encoding="utf-8")
            api_key.write_text("local-test-key\n", encoding="utf-8")
            manifest.write_text("{}\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_ADMIT_PEER_WORK_TEMPLATES": "true",
                    "POHW_STRATUM_FORK_CHAIN_RPC_ADDR": "127.0.0.1:40408",
                    "POHW_FORK_ACTIVATION_MANIFEST": str(manifest),
                    "POHW_IDENA_ANCHOR_POLICY": str(policy),
                    "IDENA_RPC_URL": "http://127.0.0.1:9009",
                    "IDENA_API_KEY_FILE": str(api_key),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--idena-anchor-policy\n" + str(policy), args)
        self.assertIn("--idena-rpc-url\nhttp://127.0.0.1:9009", args)
        self.assertIn("--idena-api-key-file\n" + str(api_key), args)
        self.assertNotIn("--allow-remote-idena-rpc", args)

    def test_gossip_mesh_mandatory_anchor_policy_requires_admission(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-gossip-required-anchor-") as temp:
            root = Path(temp)
            policy = root / "policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_REQUIRE_IDENA_ANCHOR_POLICY": "true",
                    "POHW_IDENA_ANCHOR_POLICY": str(policy),
                    "POHW_ADMIT_PEER_WORK_TEMPLATES": "false",
                }
            )

            result = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mandatory Idena anchor policy", result.stderr)

    def test_gossip_mesh_initializes_the_configured_network_before_serving(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-gossip-network-init-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_GOSSIP_NETWORK_ID": "cd" * 32,
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(GOSSIP_MESH_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("initialize-gossip-network", args)
        self.assertIn("--network-id\n" + "cd" * 32, args)
        self.assertIn("run-gossip-mesh", args)

    def test_dashboard_ui_runner_uses_loopback_and_token_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-ui-wrapper-") as temp:
            root = Path(temp)
            ui_dir = root / "ui"
            dist_dir = ui_dir / "dist"
            dist_dir.mkdir(parents=True)
            (dist_dir / "index.html").write_text(
                '<!doctype html>\n<div id="root"></div>\n<script type="module" src="/assets/index.js"></script>\n',
                encoding="utf-8",
            )
            token_file = root / "dashboard.token"
            token_file.write_text("secret-dashboard-token\n", encoding="utf-8")
            out = root / "http.txt"
            fake_http_server = self.write_fake_http_server(root)
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DASHBOARD_UI_DIR": str(ui_dir),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_DASHBOARD_API_TOKEN_FILE": str(token_file),
                    "POHW_DASHBOARD_UI_HTTP_SERVER_BIN": str(fake_http_server),
                    "POHW_FAKE_HTTP_OUT": str(out),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_UI_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            rendered = out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"cwd={root / 'datadir' / 'dashboard-ui-cache' / 'www'}", rendered)
        self.assertIn("args=-m http.server 5176 --bind 127.0.0.1", rendered)
        self.assertIn('apiUrl: "http://127.0.0.1:40407/dashboard.json"', rendered)
        self.assertIn('apiToken: "secret-dashboard-token"', rendered)

    def test_dashboard_api_prefers_systemd_credential_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-api-credential-") as temp:
            root = Path(temp)
            credential_dir = root / "credentials"
            credential_dir.mkdir()
            credential_token = credential_dir / "dashboard-api.token"
            credential_token.write_text("credential-token\n", encoding="utf-8")
            args_out = root / "args.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_WORKDIR": str(root),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_DASHBOARD_API_TOKEN_FILE": "/private/source/token",
                    "CREDENTIALS_DIRECTORY": str(credential_dir),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_API_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(credential_token), args)
        self.assertNotIn("/private/source/token", args)

    def test_dashboard_api_forwards_only_the_loopback_index_url(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-api-index-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_WORKDIR": str(root),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_EXPLORER_BITCOIN_INDEX_URL": "http://127.0.0.1:3002",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_API_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--explorer-bitcoin-index-url", args)
        self.assertIn("http://127.0.0.1:3002", args)
        self.assertNotIn("cookie", args.lower())

    def test_dashboard_api_forwards_experiment_1_core_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-api-core-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            manifest = root / "experiment-1.json"
            cookie = root / "bitcoin.cookie"
            manifest.write_text("{}\n", encoding="utf-8")
            cookie.write_text("__cookie__:secret\n", encoding="utf-8")
            env = dict(os.environ)
            env.update(
                {
                    "POHW_WORKDIR": str(root),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_EXPLORER_POHW_CORE_MANIFEST": str(manifest),
                    "POHW_ENABLE_BITCOIN_RPC": "true",
                    "BITCOIN_RPC_URL": "http://127.0.0.1:40414",
                    "BITCOIN_RPC_COOKIE_FILE": str(cookie),
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_API_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--explorer-pohw-core-manifest", args)
        self.assertIn(str(manifest), args)
        self.assertIn("--enable-bitcoin-rpc", args)
        self.assertIn("--bitcoin-rpc-url", args)
        self.assertIn("http://127.0.0.1:40414", args)
        self.assertIn("--bitcoin-rpc-cookie-file", args)
        self.assertNotIn("__cookie__", args)
        self.assertNotIn("secret", args)

    def test_dashboard_api_forwards_explicit_remote_index_opt_in(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-api-remote-index-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_WORKDIR": str(root),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_SNAPSHOT_DIR": str(root / "snapshots"),
                    "POHW_EXPLORER_BITCOIN_INDEX_URL": "https://blockstream.info/api",
                    "POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX": "true",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_API_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--explorer-allow-remote-bitcoin-index", args)
        self.assertIn("https://blockstream.info/api", args)

    def test_dashboard_ui_runner_refuses_non_loopback_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-ui-non-loopback-") as temp:
            root = Path(temp)
            ui_dir = root / "ui"
            ui_dir.mkdir()
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DASHBOARD_UI_DIR": str(ui_dir),
                    "POHW_DASHBOARD_UI_BIND_HOST": "0.0.0.0",
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_UI_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to bind dashboard UI to non-loopback host", result.stderr)

    def test_dashboard_ui_never_exposes_participant_token_on_non_loopback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-ui-token-exposure-") as temp:
            root = Path(temp)
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DASHBOARD_UI_DIR": str(root / "ui"),
                    "POHW_DASHBOARD_UI_BIND_HOST": "0.0.0.0",
                    "POHW_DASHBOARD_UI_ALLOW_NON_LOOPBACK": "true",
                    "POHW_DASHBOARD_UI_PARTICIPANT_ENABLED": "true",
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_UI_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("browser config contains the dashboard token", result.stderr)

    def test_public_explorer_ui_never_embeds_dashboard_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-explorer-ui-wrapper-") as temp:
            root = Path(temp)
            ui_dir = root / "ui"
            dist_dir = ui_dir / "dist"
            dist_dir.mkdir(parents=True)
            (dist_dir / "index.html").write_text(
                '<!doctype html>\n<div id="root"></div>\n<script type="module" src="/assets/index.js"></script>\n',
                encoding="utf-8",
            )
            token_file = root / "dashboard.token"
            token_file.write_text("must-not-be-public\n", encoding="utf-8")
            out = root / "http.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_DASHBOARD_UI_DIR": str(ui_dir),
                    "POHW_DATADIR": str(root / "datadir"),
                    "POHW_DASHBOARD_API_TOKEN_FILE": str(token_file),
                    "POHW_DASHBOARD_UI_DEFAULT_VIEW": "explorer",
                    "POHW_DASHBOARD_UI_PARTICIPANT_ENABLED": "false",
                    "POHW_EXPLORER_UI_API_BASE": "/api/v1",
                    "POHW_DASHBOARD_UI_HTTP_SERVER_BIN": str(
                        self.write_fake_http_server(root)
                    ),
                    "POHW_FAKE_HTTP_OUT": str(out),
                }
            )

            result = subprocess.run(
                ["bash", str(DASHBOARD_UI_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            rendered = out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('explorerApiBase: "/api/v1"', rendered)
        self.assertIn('defaultView: "explorer"', rendered)
        self.assertIn("participantDashboard: false", rendered)
        self.assertIn('apiToken: ""', rendered)
        self.assertNotIn("must-not-be-public", rendered)

    def test_dashboard_ui_runner_requires_built_static_assets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-dashboard-ui-missing-deps-") as temp:
            root = Path(temp)
            ui_dir = root / "ui"
            ui_dir.mkdir()
            env = dict(os.environ)
            env["POHW_DASHBOARD_UI_DIR"] = str(ui_dir)

            result = subprocess.run(
                ["bash", str(DASHBOARD_UI_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Dashboard UI build is missing", result.stderr)

    def test_local_gossip_peer_runner_uses_explicit_peer_settings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-local-gossip-peer-wrapper-") as temp:
            root = Path(temp)
            args_out = root / "args.txt"
            env = dict(os.environ)
            env.update(
                {
                    "POHW_LOCAL_GOSSIP_DATADIR": str(root / "local-peer"),
                    "POHW_LOCAL_GOSSIP_BIND_ADDR": "192.0.2.10:40416",
                    "POHW_LOCAL_GOSSIP_ADVERTISE_ADDR": "192.0.2.10:40416",
                    "POHW_LOCAL_GOSSIP_PEER_ADDRS": "192.0.2.10:40406,192.0.2.11:40406",
                    "POHW_PEER_ADDRS": "192.0.2.99:40406",
                    "POHW_FAKE_NODE_ARGS_OUT": str(args_out),
                    "POHW_P2POOL_NODE_BIN": str(self.write_fake_node(root)),
                }
            )

            result = subprocess.run(
                ["bash", str(LOCAL_GOSSIP_PEER_WRAPPER)],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            args = args_out.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-gossip-mesh", args)
        self.assertIn(str(root / "local-peer"), args)
        self.assertIn("192.0.2.10:40416", args)
        self.assertIn("192.0.2.10:40406", args)
        self.assertIn("192.0.2.11:40406", args)
        self.assertNotIn("192.0.2.99:40406", args)


if __name__ == "__main__":
    unittest.main()
