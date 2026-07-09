import os
import subprocess
import tempfile
import unittest
import json
import datetime as dt
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MINING_ADAPTER_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-mining-adapter.sh"
DASHBOARD_UI_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-dashboard-ui.sh"
LOCAL_GOSSIP_PEER_WRAPPER = REPO_ROOT / "scripts" / "pohw-run-local-gossip-peer.sh"


class RunWrapperValidationTest(unittest.TestCase):
    def base_env(self, root: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_DATADIR": str(root / "datadir"),
                "POHW_MINER_ID": "alice",
                "POHW_IDENA_SNAPSHOT_ID": "2026-07-05",
                "POHW_IDENA_SNAPSHOT_PROOF_ROOT": "11" * 32,
                "POHW_STRATUM_JOB_FILE": str(root / "job.json"),
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
        self.assertIn("--allow-example-mining-job", args)
        self.assertIn(str(root / "job.json"), args)
        self.assertIn("--block-candidate-dir", args)
        self.assertIn(str(root / "datadir" / "block-candidates"), args)

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
        self.assertIn("--rpc-cookie-file", args)
        self.assertNotIn("build-stratum-job-rpc", args)
        self.assertNotIn("build-pohw-stratum-job-rpc", args)

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
        self.assertIn("Use either POHW_STRATUM_BUILD_JOB_FROM_RPC", result.stderr)

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
