import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HANDOFF = REPO_ROOT / "scripts" / "pohw-mainnet-handoff.py"


class MainnetHandoffTest(unittest.TestCase):
    def write_executable(self, path: Path, content: str) -> Path:
        path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
        path.chmod(0o700)
        return path

    def setup_runtime(self, root: Path, *, active: int = 20) -> dict[str, str]:
        node = self.write_executable(
            root / "p2pool-node",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import pathlib
            import sys

            command = sys.argv[1]
            if command == "mainnet-handoff-evidence":
                counter_path = pathlib.Path(os.environ["FAKE_EVIDENCE_COUNTER"])
                counter = int(counter_path.read_text()) + 1 if counter_path.exists() else 1
                counter_path.write_text(str(counter), encoding="utf-8")
                active = int(os.environ.get("FAKE_ACTIVE_IDENTITIES", "20"))
                eligible = int(os.environ.get("FAKE_ELIGIBLE_ACTIVE_IDENTITIES", str(active)))
                unique = int(os.environ.get("FAKE_UNIQUE_IDENTITIES", str(active)))
                registered = int(os.environ.get("FAKE_REGISTERED_MINERS", str(unique)))
                print(json.dumps({
                    "registered_miner_count": registered,
                    "unique_registered_idena_count": unique,
                    "active_idena_participant_count": active,
                    "eligible_active_idena_participant_count": eligible,
                    "snapshot_voter_idena_count": 3,
                    "snapshot_day": "2026-07-13",
                    "last_message_hash": (
                        "ab" * 32
                        if os.environ.get("FAKE_STATIC_EVIDENCE_HASH") == "true"
                        else f"{counter:064x}"
                    ),
                }))
            elif command == "bitcoin-mining-readiness":
                if os.environ.get("FAKE_MAINNET_READY", "true") != "true":
                    raise SystemExit(1)
                print(json.dumps({
                    "ready": True,
                    "chain": "main",
                    "blocks": 900000,
                    "headers": 900000,
                    "initialBlockDownload": False,
                    "templateHeight": 900001,
                }))
            elif command == "build-dynamic-pohw-stratum-job-rpc":
                for option in (
                    "--datadir",
                    "--snapshot-dir",
                    "--miner-id",
                    "--pohw-commitment-file",
                    "--job-out",
                ):
                    if option not in sys.argv:
                        raise SystemExit(3)
                output = pathlib.Path(sys.argv[sys.argv.index("--job-out") + 1])
                output.write_text("{}\n", encoding="utf-8")
                print("{}")
            else:
                raise SystemExit(2)
            """,
        )
        systemctl = self.write_executable(
            root / "systemctl",
            r"""
            #!/usr/bin/env python3
            import json
            import os
            import pathlib
            import sys

            log = pathlib.Path(os.environ["FAKE_SYSTEMCTL_LOG"])
            with log.open("a", encoding="utf-8") as handle:
                handle.write(" ".join(sys.argv[1:]) + "\n")
            if os.environ.get("FAKE_SYSTEMCTL_FAIL_ON") == " ".join(sys.argv[1:]):
                raise SystemExit(1)
            state_path = pathlib.Path(os.environ["FAKE_SYSTEMCTL_STATE"])
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            command = sys.argv[1]
            service = sys.argv[-1]
            if command == "stop":
                state[service] = False
                state_path.write_text(json.dumps(state), encoding="utf-8")
            elif command == "start":
                state[service] = True
                state_path.write_text(json.dumps(state), encoding="utf-8")
            elif command == "is-active" and not state.get(service, True):
                raise SystemExit(3)
            if sys.argv[1] == "show":
                print("123")
            """,
        )

        fork_dir = root / "fork-chain"
        fork_dir.mkdir()
        (fork_dir / "fork-chain.lock").write_text("", encoding="utf-8")
        (fork_dir / "fork-blocks.ndjson").write_text("{}\n", encoding="utf-8")
        marker = root / "enable-experiment-0-fork"
        marker.write_text("approved\n", encoding="utf-8")
        marker.chmod(0o600)
        commitment = root / "pohw-commitment.json"
        commitment.write_text("{}\n", encoding="utf-8")
        snapshot_dir = root / "snapshots"
        snapshot_dir.mkdir()
        payout_candidate_dir = root / "payout-candidates"
        cmdline = root / "mining.cmdline"
        cmdline.write_bytes(
            "\0".join(
                (
                    "p2pool-node",
                    "run-mining-adapter",
                    "--datadir",
                    str(root / "sharechain"),
                    "--miner-id",
                    "test-miner",
                    "--refresh-job-from-rpc",
                    "--derive-pohw-payouts-from-state",
                    "--auto-submit-blocks",
                    "--allow-mainnet-submit",
                    "--expected-rpc-chain",
                    "main",
                    "--snapshot-dir",
                    str(snapshot_dir),
                    "--payout-candidate-dir",
                    str(payout_candidate_dir),
                    "--pohw-commitment-file",
                    str(commitment),
                    "--rpc-url",
                    "http://127.0.0.1:8332",
                    "",
                )
            ).encode("utf-8")
        )

        env = dict(os.environ)
        env.update(
            {
                "POHW_WORKDIR": str(root),
                "POHW_P2POOL_NODE_BIN": str(node),
                "POHW_DATADIR": str(root / "sharechain"),
                "POHW_MINER_ID": "test-miner",
                "POHW_SNAPSHOT_DIR": str(snapshot_dir),
                "POHW_PAYOUT_CANDIDATE_DIR": str(payout_candidate_dir),
                "POHW_MAINNET_HANDOFF_STATE_DIR": str(root / "handoff"),
                "POHW_FORK_CHAIN_DATADIR": str(fork_dir),
                "POHW_MAINNET_HANDOFF_FORK_MARKER": str(marker),
                "POHW_STRATUM_POHW_COMMITMENT_FILE": str(commitment),
                "POHW_SYSTEMCTL_BIN": str(systemctl),
                "POHW_MAINNET_HANDOFF_PROCESS_CMDLINE_FILE": str(cmdline),
                "POHW_MAINNET_HANDOFF_ENABLED": "true",
                "POHW_MAINNET_HANDOFF_ACK": "I_UNDERSTAND_REAL_BITCOIN",
                "POHW_MAINNET_HANDOFF_CONFIRMATIONS": "1",
                "POHW_MAINNET_HANDOFF_SETTLE_SECONDS": "0",
                "POHW_MAINNET_HANDOFF_COMMAND_TIMEOUT_SECONDS": "10",
                "POHW_MAINNET_HANDOFF_MIN_CONFIRMATION_INTERVAL_SECONDS": "0",
                "POHW_BITCOIN_RPC_URL": "http://127.0.0.1:8332",
                "FAKE_ACTIVE_IDENTITIES": str(active),
                "FAKE_SYSTEMCTL_LOG": str(root / "systemctl.log"),
                "FAKE_SYSTEMCTL_STATE": str(root / "systemctl-state.json"),
                "FAKE_EVIDENCE_COUNTER": str(root / "evidence-counter"),
            }
        )
        return env

    def run_handoff(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        command = ["python3", str(HANDOFF)]
        cmdline_file = env.get("POHW_MAINNET_HANDOFF_PROCESS_CMDLINE_FILE")
        if cmdline_file:
            command.extend(["--process-cmdline-file", cmdline_file])
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_waits_for_twenty_snapshot_eligible_active_identities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-wait-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root, active=20)
            env["FAKE_ELIGIBLE_ACTIVE_IDENTITIES"] = "19"
            env["FAKE_REGISTERED_MINERS"] = "40"
            env["FAKE_UNIQUE_IDENTITIES"] = "20"

            result = self.run_handoff(env)
            status = json.loads((root / "handoff/status.json").read_text(encoding="utf-8"))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(status["phase"], "monitoring")
            self.assertEqual(status["activeIdenaParticipants"], 19)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertFalse((root / "systemctl.log").exists())

    def test_requires_consecutive_threshold_observations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-confirm-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["POHW_MAINNET_HANDOFF_CONFIRMATIONS"] = "2"

            first = self.run_handoff(env)
            first_status = json.loads(
                (root / "handoff/status.json").read_text(encoding="utf-8")
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first_status["phase"], "confirming")
            self.assertTrue((root / "fork-chain").is_dir())

            second = self.run_handoff(env)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertFalse((root / "fork-chain").exists())

    def test_unchanged_replay_evidence_cannot_advance_confirmations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-static-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["POHW_MAINNET_HANDOFF_CONFIRMATIONS"] = "2"
            env["FAKE_STATIC_EVIDENCE_HASH"] = "true"

            first = self.run_handoff(env)
            second = self.run_handoff(env)
            status = json.loads(
                (root / "handoff/status.json").read_text(encoding="utf-8")
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(status["phase"], "confirming")
            self.assertEqual(status["confirmationCount"], 1)
            self.assertTrue((root / "fork-chain").exists())

    def test_confirmation_interval_uses_last_accepted_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-interval-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["POHW_MAINNET_HANDOFF_CONFIRMATIONS"] = "3"
            env["POHW_MAINNET_HANDOFF_MIN_CONFIRMATION_INTERVAL_SECONDS"] = "600"

            first = self.run_handoff(env)
            state_path = root / "handoff/controller-state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["updatedAt"] = "2999-01-01T00:00:00Z"
            state["lastConfirmationAt"] = "2000-01-01T00:00:00Z"
            state_path.write_text(json.dumps(state), encoding="utf-8")

            second = self.run_handoff(env)
            updated = json.loads(state_path.read_text(encoding="utf-8"))

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(updated["confirmationCount"], 2)
            self.assertNotEqual(
                updated["lastConfirmedMessageHash"],
                state["lastConfirmedMessageHash"],
            )

    def test_switches_to_verified_mainnet_before_deleting_fork(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-switch-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env.pop("POHW_BITCOIN_RPC_URL")

            result = self.run_handoff(env)
            receipt = json.loads(
                (root / "handoff/handoff-receipt.json").read_text(encoding="utf-8")
            )
            mode = (root / "handoff/mining-mode.env").read_text(encoding="utf-8")
            calls = (root / "systemctl.log").read_text(encoding="utf-8").splitlines()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "fork-chain").exists())
            self.assertFalse((root / "enable-experiment-0-fork").exists())
            self.assertEqual(receipt["miningMode"], "bitcoin-mainnet")
            self.assertTrue(receipt["forkDataDeleted"])
            self.assertIn("POHW_STRATUM_ALLOW_MAINNET_SUBMIT=true", mode)
            self.assertIn("POHW_BITCOIN_EXPECTED_CHAIN=main", mode)
            self.assertIn("POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE=true", mode)
            self.assertIn("POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=false", mode)
            self.assertIn("POHW_STRATUM_FORK_CHAIN_RPC_ADDR=\n", mode)
            self.assertLess(
                calls.index("stop pohw-mining-adapter.service"),
                calls.index("start pohw-mining-adapter.service"),
            )

    def test_mainnet_preflight_failure_preserves_fork_without_stopping_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-preflight-fail-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["FAKE_MAINNET_READY"] = "false"

            result = self.run_handoff(env)

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertTrue((root / "enable-experiment-0-fork").is_file())
            self.assertFalse((root / "handoff/mining-mode.env").exists())
            self.assertFalse((root / "systemctl.log").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_permissive_fork_marker_is_rejected_before_service_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-marker-mode-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            marker = Path(env["POHW_MAINNET_HANDOFF_FORK_MARKER"])
            marker.chmod(0o666)

            result = self.run_handoff(env)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not be accessible by group or others", result.stderr)
            self.assertFalse((root / "systemctl.log").exists())

    def test_service_stop_failure_rolls_back_before_activation_commit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-stop-fail-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["FAKE_SYSTEMCTL_FAIL_ON"] = "stop pohw-fork-chain-node.service"

            result = self.run_handoff(env)
            calls = (root / "systemctl.log").read_text(encoding="utf-8")

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertTrue((root / "enable-experiment-0-fork").is_file())
            self.assertFalse((root / "handoff/mainnet-activated.json").exists())
            self.assertFalse((root / "handoff/mining-mode.env").exists())
            self.assertIn("start pohw-fork-chain-node.service", calls)
            self.assertIn("start pohw-mining-adapter.service", calls)

    def test_unverified_process_after_activation_preserves_fork_data_without_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-process-fail-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            Path(env["POHW_MAINNET_HANDOFF_PROCESS_CMDLINE_FILE"]).write_bytes(
                b"p2pool-node\0run-mining-adapter\0--fork-chain-rpc-addr\0"
            )

            result = self.run_handoff(env)
            calls = (root / "systemctl.log").read_text(encoding="utf-8")

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertFalse((root / "enable-experiment-0-fork").exists())
            self.assertTrue((root / "handoff/mining-mode.env").is_file())
            self.assertTrue((root / "handoff/mainnet-activated.json").is_file())
            self.assertNotIn("start pohw-fork-chain-node.service", calls)

    def test_invalid_activation_marker_changes_no_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-invalid-marker-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            state_dir = root / "handoff"
            state_dir.mkdir(mode=0o700)
            (state_dir / "mainnet-activated.json").write_text("{}\n", encoding="utf-8")

            result = self.run_handoff(env)

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertTrue((root / "enable-experiment-0-fork").is_file())
            self.assertFalse((root / "systemctl.log").exists())

    def test_wrong_mainnet_payout_candidate_path_preserves_fork_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-wrong-payout-dir-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            Path(env["POHW_MAINNET_HANDOFF_PROCESS_CMDLINE_FILE"]).write_bytes(
                "\0".join(
                    (
                        "p2pool-node",
                        "run-mining-adapter",
                        "--datadir",
                        str(root / "sharechain"),
                        "--miner-id",
                        "test-miner",
                        "--refresh-job-from-rpc",
                        "--derive-pohw-payouts-from-state",
                        "--auto-submit-blocks",
                        "--allow-mainnet-submit",
                        "--snapshot-dir",
                        str(root / "snapshots"),
                        "--payout-candidate-dir",
                        str(root / "wrong-payout-candidates"),
                        "--pohw-commitment-file",
                        str(root / "pohw-commitment.json"),
                        "--rpc-url",
                        "http://127.0.0.1:8332",
                        "",
                    )
                ).encode("utf-8")
            )

            result = self.run_handoff(env)

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertTrue((root / "handoff/mainnet-activated.json").is_file())

    def test_unrecognized_fork_datadir_is_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-delete-guard-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            (root / "fork-chain/fork-chain.lock").unlink()

            result = self.run_handoff(env)
            status = json.loads((root / "handoff/status.json").read_text(encoding="utf-8"))

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertEqual(status["phase"], "mainnet_active_cleanup_pending")

    def test_disabled_controller_never_changes_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-disabled-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["POHW_MAINNET_HANDOFF_ENABLED"] = "false"
            env["POHW_P2POOL_NODE_BIN"] = str(root / "missing-p2pool-node")

            result = self.run_handoff(env)
            status = json.loads((root / "handoff/status.json").read_text(encoding="utf-8"))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(status["phase"], "disabled")
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertFalse((root / "systemctl.log").exists())

    def test_unacknowledged_controller_does_not_read_participant_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-handoff-disarmed-") as temp:
            root = Path(temp).resolve()
            env = self.setup_runtime(root)
            env["POHW_MAINNET_HANDOFF_ACK"] = ""
            env["POHW_P2POOL_NODE_BIN"] = str(root / "missing-p2pool-node")

            result = self.run_handoff(env)
            status = json.loads((root / "handoff/status.json").read_text(encoding="utf-8"))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(status["phase"], "disarmed")
            self.assertTrue((root / "fork-chain").is_dir())
            self.assertFalse((root / "systemctl.log").exists())


if __name__ == "__main__":
    unittest.main()
