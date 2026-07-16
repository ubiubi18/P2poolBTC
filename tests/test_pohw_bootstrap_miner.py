import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "pohw-run-bootstrap-miner.sh"


class BootstrapMinerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.cookie = self.root / "cookie"
        self.cookie.write_text("test:test\n", encoding="utf-8")
        self.cookie.chmod(0o600)
        self.marker = self.root / "smoke-args.json"
        self.cli_marker = self.root / "bitcoin-cli-args.txt"
        self.info = {
            "chain": "pohw",
            "blocks": 958175,
            "headers": 958175,
            "initialblockdownload": False,
            "pohw_experiment": {
                "handoff_active": False,
                "fork_height": 958016,
                "fork_hash": "00000000000000000001d0f198da4adf33b597782a36c766685b2f217110cfc8",
                "first_fork_hash": "64d2122b44c111f2f593869ce404117d34c6c830f4390eb70245c11dcc503d01",
                "inherited_utxo_spending": True,
                "replay_protection": "inherited-input-requires-fork-marker-and-signature-domain-v3",
                "replay_marker_activation_height": 958018,
                "replay_sighash_activation_height": 958176,
                "replay_sighash_parent_hash": "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6",
                "replay_sighash_version_bit": 1073741824,
                "replay_sighash_domain": "pohw-experiment-1-full-consensus/replay-sighash-v3",
                "bootstrap_handoff_hashrate_hps": 1000000000000000,
            },
        }
        self.cli = self._write_executable(
            "bitcoin-cli",
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"$POHW_TEST_CLI_MARKER\"\n"
            "last=\n"
            "for arg do last=$arg; done\n"
            "case \"$last\" in\n"
            "  getblockchaininfo) printf '%s\\n' \"$POHW_TEST_BLOCKCHAIN_INFO\" ;;\n"
            "  958175) printf '%s\\n' \"$POHW_TEST_CHECKPOINT_HASH\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
        )
        self.smoke = self._write_executable(
            "smoke.py",
            "import json, os, sys\n"
            "open(os.environ['POHW_TEST_MARKER'], 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_executable(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _run(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "POHW_EXPERIMENT_NO_VALUE_ACK": "I_UNDERSTAND_NO_VALUE",
            "POHW_BOOTSTRAP_MINER_ALLOW_HOST": "I_UNDERSTAND_HETZNER_ONLY",
            "POHW_BOOTSTRAP_MINER_PYTHON": sys.executable,
            "POHW_BOOTSTRAP_MINER_BITCOIN_CLI": str(self.cli),
            "POHW_BOOTSTRAP_MINER_BITCOIN_COOKIE_FILE": str(self.cookie),
            "POHW_BOOTSTRAP_MINER_BITCOIN_RPC_PORT": "40414",
            "POHW_BOOTSTRAP_MINER_SCRIPT": str(self.smoke),
            "POHW_BOOTSTRAP_MINER_STRATUM_HOST": "127.0.0.1",
            "POHW_BOOTSTRAP_MINER_STRATUM_PORT": "3333",
            "POHW_BOOTSTRAP_MINER_MAX_HASHES": "1000",
            "POHW_BOOTSTRAP_MINER_TIMEOUT_SECONDS": "2",
            "POHW_TEST_BLOCKCHAIN_INFO": json.dumps(self.info),
            "POHW_TEST_CHECKPOINT_HASH": "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6",
            "POHW_TEST_CLI_MARKER": str(self.cli_marker),
            "POHW_TEST_MARKER": str(self.marker),
        }
        env.update(overrides)
        return subprocess.run(
            ["bash", str(RUNNER)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_runs_one_bounded_loopback_attempt_during_bootstrap(self) -> None:
        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.marker.read_text(encoding="utf-8"))
        cli_args = self.cli_marker.read_text(encoding="utf-8").splitlines()
        self.assertIn("-noconf", cli_args)
        self.assertIn("-rpcconnect=127.0.0.1", cli_args)
        self.assertIn("958175", cli_args)
        self.assertFalse(any(arg.startswith("-datadir=") for arg in cli_args))
        self.assertIn("--allow-no-solution", args)
        self.assertEqual(args[args.index("--max-hashes") + 1], "1000")
        self.assertEqual(args[args.index("--timeout-seconds") + 1], "2")

    def test_skips_after_consensus_handoff(self) -> None:
        self.info["pohw_experiment"]["handoff_active"] = True
        result = self._run(POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bounded miner is disabled", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_skips_before_pinned_revision_three_checkpoint(self) -> None:
        self.info["blocks"] = 958174
        self.info["headers"] = 958174
        result = self._run(POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pinned revision-3 checkpoint", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_rejects_wrong_pinned_revision_three_checkpoint_hash(self) -> None:
        result = self._run(POHW_TEST_CHECKPOINT_HASH="00" * 32)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong revision-3 checkpoint hash", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_rejects_revision_two_or_incomplete_revision_three_metadata(self) -> None:
        profile = self.info["pohw_experiment"]
        profile["replay_protection"] = "inherited-input-requires-fork-only-marker-v2"
        revision_two = self._run(POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info))
        self.assertNotEqual(revision_two.returncode, 0)
        self.assertIn("replay_protection", revision_two.stderr)

        profile["replay_protection"] = (
            "inherited-input-requires-fork-marker-and-signature-domain-v3"
        )
        del profile["replay_sighash_parent_hash"]
        incomplete = self._run(POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info))
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("replay_sighash_parent_hash", incomplete.stderr)
        self.assertFalse(self.marker.exists())

    def test_rejects_wrong_chain_and_remote_stratum(self) -> None:
        self.info["chain"] = "main"
        wrong_chain = self._run(POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info))
        self.assertNotEqual(wrong_chain.returncode, 0)
        self.assertFalse(self.marker.exists())

        self.info["chain"] = "pohw"
        remote = self._run(
            POHW_TEST_BLOCKCHAIN_INFO=json.dumps(self.info),
            POHW_BOOTSTRAP_MINER_STRATUM_HOST="192.0.2.1",
        )
        self.assertNotEqual(remote.returncode, 0)
        self.assertIn("loopback", remote.stderr)

    def test_enforces_small_hash_and_time_budgets(self) -> None:
        too_many = self._run(POHW_BOOTSTRAP_MINER_MAX_HASHES="1000001")
        too_long = self._run(POHW_BOOTSTRAP_MINER_TIMEOUT_SECONDS="31")

        self.assertNotEqual(too_many.returncode, 0)
        self.assertNotEqual(too_long.returncode, 0)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
