import json
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    def build_target_candidate(self, binary: Path, root: Path) -> Path:
        job_file = root / "target-job.json"
        candidate_file = root / "target-candidate.json"
        job_file.write_text(
            json.dumps(
                {
                    "job_id": "target-job",
                    "version": "00000020",
                    "prevhash": "00" * 32,
                    "coinbase1": COINBASE1,
                    "coinbase2": COINBASE2,
                    "merkle_branches": [],
                    "nbits": "ffff7f20",
                    "ntime": "04030201",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        for nonce in range(256):
            result = subprocess.run(
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
                    nonce.to_bytes(4, "little").hex(),
                    "--require-block-target",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return candidate_file
        self.fail("failed to build a target-meeting fixture candidate")

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

    def test_pohw_candidate_submission_requires_idena_policy_before_submitblock(self) -> None:
        binary = ensure_p2pool_node_binary()
        methods: list[str] = []

        class RpcHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length))
                methods.append(request["method"])
                response = {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "chain": "pohw",
                        "blocks": 958200,
                        "headers": 958200,
                        "initialblockdownload": False,
                        "verificationprogress": 1.0,
                    },
                    "error": None,
                }
                payload = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), RpcHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="pohw-idena-submit-gate-") as temp:
                root = Path(temp)
                candidate_file = self.build_target_candidate(binary, root)
                result = subprocess.run(
                    [
                        str(binary),
                        "submit-stratum-block-candidate",
                        "--candidate-file",
                        str(candidate_file),
                        "--rpc-url",
                        f"http://127.0.0.1:{server.server_port}",
                    ],
                    cwd=REPO_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --idena-anchor-policy", result.stderr)
        self.assertEqual(methods, ["getblockchaininfo"])


if __name__ == "__main__":
    unittest.main()
