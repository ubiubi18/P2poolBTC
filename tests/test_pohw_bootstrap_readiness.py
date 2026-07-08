import json
import subprocess
import tempfile
import unittest
import datetime as dt
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_SCRIPT = REPO_ROOT / "scripts" / "pohw-bootstrap-readiness.sh"


class BootstrapReadinessScriptTest(unittest.TestCase):
    def make_fixture(self, root: Path, fake_p2pool: str) -> Path:
        datadir = root / "datadir"
        snapshot_dir = root / "snapshots"
        output_root = root / "output"
        key_dir = datadir / "keys" / "alice"
        key_dir.mkdir(parents=True)
        snapshot_dir.mkdir()
        output_root.mkdir()
        (key_dir / "mining.key").write_text("fake-mining-key", encoding="utf-8")
        (key_dir / "gossip-node.key").write_text("fake-node-key", encoding="utf-8")
        for key in key_dir.iterdir():
            key.chmod(0o600)
        (snapshot_dir / "idena-snapshot-test.json").write_text(
            json.dumps(
                {
                    "snapshot_day": "2026-07-08",
                    "idena_height": 123,
                    "score_root": "ab" * 32,
                    "identity_root": "cd" * 32,
                    "idena_block_hash": "0x" + "ef" * 32,
                    "formula_version": 2,
                    "leaves": [],
                }
            ),
            encoding="utf-8",
        )
        fake_bin = root / "p2pool-node"
        fake_bin.write_text(fake_p2pool, encoding="utf-8")
        fake_bin.chmod(0o700)
        env_file = root / ".pohw-experiment.env"
        env_file.write_text(
            "\n".join(
                [
                    f"POHW_WORKDIR={root}",
                    f"POHW_DATADIR={datadir}",
                    f"POHW_SNAPSHOT_DIR={snapshot_dir}",
                    f"POHW_EXPERIMENT_OUTPUT_ROOT={output_root}",
                    "POHW_MINER_ID=alice",
                    f"POHW_P2POOL_NODE_BIN={fake_bin}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        return env_file

    def test_dev_append_requires_explicit_ack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-dev-ack-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, "#!/usr/bin/env bash\nexit 99\n")

            result = subprocess.run(
                [str(BOOTSTRAP_SCRIPT), str(env_file), "--mode", "dev", "--append"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Dev append requires", result.stderr)

    def test_real_mode_exits_cleanly_when_bitcoin_template_is_unavailable(self) -> None:
        fake = """#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
case "$cmd" in
  build-stratum-job-rpc)
    echo "Bitcoin Core is in initial sync and waiting for blocks" >&2
    exit 2
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 3
    ;;
esac
"""
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-real-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, fake)

            result = subprocess.run(
                [str(BOOTSTRAP_SCRIPT), str(env_file), "--mode", "real"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Bitcoin RPC is not template-ready", result.stderr)
            status_files = list((root / "output").glob("work-bootstrap-*/status.json"))
            self.assertEqual(len(status_files), 1)
            status = json.loads(status_files[0].read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "bitcoin_not_ready")

    def test_real_mode_uses_health_status_before_bitcoin_rpc(self) -> None:
        fake = """#!/usr/bin/env bash
printf 'unexpected call\\n' >> "$(dirname "$0")/calls.txt"
exit 99
"""
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-health-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, fake)
            health_file = root / "health.json"
            health_file.write_text(
                json.dumps(
                    {
                        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                        "readiness": {
                            "miningReady": False,
                            "blockers": ["bitcoin_node_network_limited"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            with env_file.open("a", encoding="utf-8") as handle:
                handle.write(f"POHW_HEALTH_STATUS_FILE={health_file}\n")
                handle.write(f"POHW_HEALTH_SCRIPT={REPO_ROOT / 'scripts' / 'pohw-health-status.py'}\n")

            result = subprocess.run(
                [str(BOOTSTRAP_SCRIPT), str(env_file), "--mode", "real"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            calls_file = root / "calls.txt"
            status_files = list((root / "output").glob("work-bootstrap-*/status.json"))
            status = json.loads(status_files[0].read_text(encoding="utf-8")) if status_files else {}

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PoHW health is not mining-ready", result.stderr)
        self.assertFalse(calls_file.exists())
        self.assertEqual(len(status_files), 1)
        self.assertEqual(status["status"], "bitcoin_not_ready")
        self.assertEqual(status["healthBlockers"], ["bitcoin_node_network_limited"])

    def test_real_mode_fails_on_non_ibd_bitcoin_rpc_error(self) -> None:
        fake = """#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
case "$cmd" in
  build-stratum-job-rpc)
    echo "Bitcoin RPC cookie file directory must not be a symlink" >&2
    exit 2
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 3
    ;;
esac
"""
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-rpc-error-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, fake)

            result = subprocess.run(
                [str(BOOTSTRAP_SCRIPT), str(env_file), "--mode", "real"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("must not be a symlink", result.stderr)
            status_files = list((root / "output").glob("work-bootstrap-*/status.json"))
            self.assertEqual(len(status_files), 1)
            status = json.loads(status_files[0].read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "bitcoin_rpc_error")

    def test_real_mode_publishes_rpc_validated_template_and_share(self) -> None:
        merkle = "22" * 32
        zero_hash = "00" * 32
        target = "7fffff0000000000000000000000000000000000000000000000000000000000"
        header = "01000000" + ("00" * 32) + ("22" * 32) + "00000000ffff7f2000000000"
        fake = f"""#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
printf '%s' "$cmd" >> "$(dirname "$0")/calls.txt"
for arg in "$@"; do printf ' %s' "$arg" >> "$(dirname "$0")/calls.txt"; done
printf '\\n' >> "$(dirname "$0")/calls.txt"
case "$cmd" in
  build-stratum-job-rpc)
    job_out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --job-out) job_out="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '{{"ntime":"00000000"}}\\n' > "$job_out"
    printf '{{"status":"built"}}\\n'
    ;;
  build-stratum-block-candidate)
    candidate_out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --candidate-out) candidate_out="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    cat > "$candidate_out" <<'JSON'
{{"bitcoin_header_hex":"{header}","header_merkle_root_hex":"{merkle}","block_hash":"{zero_hash}","target":"{target}"}}
JSON
    printf '{{"status":"candidate"}}\\n'
    ;;
  publish-bitcoin-work-template|publish-share)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --message-out|--envelope-out) printf '{{}}\\n' > "$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '{{"status":"published","command":"%s"}}\\n' "$cmd"
    ;;
  multinode-preflight)
    printf '{{"readiness":{{"has_registered_miner":true,"has_snapshot":true,"has_published_bitcoin_work_template":true,"has_accepted_bitcoin_work_template":true,"has_share_tip":true,"has_gossip_peers":false}}}}\\n'
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 3
    ;;
esac
"""
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-real-happy-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, fake)

            result = subprocess.run(
                [str(BOOTSTRAP_SCRIPT), str(env_file), "--mode", "real"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            calls = (root / "calls.txt").read_text(encoding="utf-8")
            self.assertIn("--expected-header-merkle-root-hex " + ("22" * 32), calls)
            self.assertNotIn("--allow-unverified-merkle-root", calls)
            self.assertIn("publish-share", calls)
            status_files = list((root / "output").glob("work-bootstrap-*/status.json"))
            self.assertEqual(len(status_files), 1)
            status = json.loads(status_files[0].read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "completed")
            self.assertTrue(status["readiness"]["has_share_tip"])

    def test_dev_mode_can_publish_template_and_share_with_ack(self) -> None:
        fake = """#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
case "$cmd" in
  publish-snapshot-vote|publish-bitcoin-work-template|publish-share)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --message-out|--envelope-out) printf '{}\\n' > "$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '{"status":"published","command":"%s"}\\n' "$cmd"
    ;;
  multinode-preflight)
    printf '{"readiness":{"has_registered_miner":true,"has_snapshot":true,"has_published_bitcoin_work_template":true,"has_accepted_bitcoin_work_template":true,"has_share_tip":true,"has_gossip_peers":false}}\\n'
    ;;
  *)
    echo "unexpected command: $cmd" >&2
    exit 3
    ;;
esac
"""
        with tempfile.TemporaryDirectory(prefix="pohw-bootstrap-dev-") as temp:
            root = Path(temp)
            env_file = self.make_fixture(root, fake)

            result = subprocess.run(
                [
                    str(BOOTSTRAP_SCRIPT),
                    str(env_file),
                    "--mode",
                    "dev",
                    "--dev-ack",
                    "I_UNDERSTAND_DEV_ONLY",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            status_files = list((root / "output").glob("work-bootstrap-*/status.json"))
            self.assertEqual(len(status_files), 1)
            status = json.loads(status_files[0].read_text(encoding="utf-8"))
            self.assertEqual(status["mode"], "dev")
            self.assertTrue(status["readiness"]["has_share_tip"])


if __name__ == "__main__":
    unittest.main()
