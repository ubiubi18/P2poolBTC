import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
P2POOL_NODE = REPO_ROOT / "target" / "debug" / "p2pool-node"
_P2POOL_NODE_BUILT = False

COINBASE1 = "0200000001" + ("00" * 32) + "ffffffff08"
COINBASE2 = "ffffffff010000000000000000016a00000000"


def ensure_p2pool_node_binary() -> Path:
    global _P2POOL_NODE_BUILT
    if not _P2POOL_NODE_BUILT:
        subprocess.run(
            ["cargo", "build", "-p", "p2pool-node"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        _P2POOL_NODE_BUILT = True
    return P2POOL_NODE


class StratumBlockCandidateCliTest(unittest.TestCase):
    def test_builds_candidate_artifact_from_stratum_submit_tuple(self) -> None:
        binary = ensure_p2pool_node_binary()
        with tempfile.TemporaryDirectory(prefix="pohw-stratum-candidate-cli-") as temp:
            root = Path(temp)
            job_file = root / "job.json"
            candidate_out = root / "candidate.json"
            job_file.write_text(
                json.dumps(
                    {
                        "job_id": "job-1",
                        "version": "00000020",
                        "prevhash": "00" * 32,
                        "coinbase1": COINBASE1,
                        "coinbase2": COINBASE2,
                        "merkle_branches": [],
                        "nbits": "ffff7f20",
                        "ntime": "04030201",
                        "clean_jobs": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    str(binary),
                    "build-stratum-block-candidate",
                    "--job-file",
                    str(job_file),
                    "--candidate-out",
                    str(candidate_out),
                    "--replace",
                    "--extranonce1",
                    "aabbccdd",
                    "--extranonce2",
                    "01020304",
                    "--ntime",
                    "04030201",
                    "--nonce",
                    "05060708",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

            stdout = json.loads(result.stdout)
            candidate = json.loads(candidate_out.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stdout["candidate_out"], str(candidate_out))
        self.assertEqual(stdout["job_id"], "job-1")
        self.assertEqual(stdout["block_hex_status"], "complete_coinbase_only")
        self.assertEqual(stdout["coinbase_txid"], candidate["coinbase_txid"])
        self.assertEqual(stdout["block_hash"], candidate["block_hash"])
        self.assertEqual(candidate["extranonce1"], "aabbccdd")
        self.assertEqual(candidate["extranonce2"], "01020304")
        self.assertEqual(candidate["ntime"], "04030201")
        self.assertEqual(candidate["nonce"], "05060708")
        self.assertEqual(
            candidate["block_hex"],
            candidate["bitcoin_header_hex"] + "01" + candidate["coinbase_tx_hex"],
        )

    def test_require_block_target_rejects_non_block_hash(self) -> None:
        binary = ensure_p2pool_node_binary()
        with tempfile.TemporaryDirectory(prefix="pohw-stratum-candidate-target-") as temp:
            root = Path(temp)
            job_file = root / "job.json"
            job_file.write_text(
                json.dumps(
                    {
                        "job_id": "job-1",
                        "version": "00000020",
                        "prevhash": "00" * 32,
                        "coinbase1": COINBASE1,
                        "coinbase2": COINBASE2,
                        "merkle_branches": [],
                        "nbits": "00000101",
                        "ntime": "04030201",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    str(binary),
                    "build-stratum-block-candidate",
                    "--job-file",
                    str(job_file),
                    "--extranonce1",
                    "aabbccdd",
                    "--extranonce2",
                    "01020304",
                    "--ntime",
                    "04030201",
                    "--nonce",
                    "05060708",
                    "--require-block-target",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not meet block target", result.stderr)

    def test_submit_candidate_refuses_non_target_artifact_before_rpc(self) -> None:
        binary = ensure_p2pool_node_binary()
        with tempfile.TemporaryDirectory(prefix="pohw-stratum-candidate-submit-") as temp:
            root = Path(temp)
            job_file = root / "job.json"
            candidate_file = root / "candidate.json"
            job_file.write_text(
                json.dumps(
                    {
                        "job_id": "job-1",
                        "version": "00000020",
                        "prevhash": "00" * 32,
                        "coinbase1": COINBASE1,
                        "coinbase2": COINBASE2,
                        "merkle_branches": [],
                        "nbits": "00000101",
                        "ntime": "04030201",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            build = subprocess.run(
                [
                    str(binary),
                    "build-stratum-block-candidate",
                    "--job-file",
                    str(job_file),
                    "--candidate-out",
                    str(candidate_file),
                    "--replace",
                    "--extranonce1",
                    "aabbccdd",
                    "--extranonce2",
                    "01020304",
                    "--ntime",
                    "04030201",
                    "--nonce",
                    "05060708",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)

            result = subprocess.run(
                [
                    str(binary),
                    "submit-stratum-block-candidate",
                    "--candidate-file",
                    str(candidate_file),
                    "--rpc-url",
                    "http://127.0.0.1:1",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not meet the advertised block target", result.stderr)
        self.assertNotIn("Bitcoin RPC request", result.stderr)


if __name__ == "__main__":
    unittest.main()
