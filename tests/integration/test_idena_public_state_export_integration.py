from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPORTER = REPO_ROOT / "scripts" / "idena-public-state-export-push.sh"
MANIFEST = REPO_ROOT / "scripts" / "idena-public-state-manifest.py"
LOCK_HELPER = REPO_ROOT / "scripts" / "idena-private-lock-exec.py"
REQUIRED_COMMANDS = ("bash", "cp", "df", "du", "find", "flock", "mountpoint")


class ExportRpcHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        if request.get("method") == "bcn_syncing":
            result: object = {
                "currentBlock": 100,
                "highestBlock": 100,
                "syncing": False,
                "wrongTime": False,
            }
        elif request.get("method") == "net_peers":
            result = [{"id": "test-peer"}]
        else:
            result = None
        body = json.dumps({"id": request.get("id"), "result": result}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def integration_supported() -> tuple[bool, str]:
    if not sys.platform.startswith("linux"):
        return False, "requires Linux"
    if os.geteuid() != 0:
        return False, "requires root"
    if any(shutil.which(command) is None for command in REQUIRED_COMMANDS):
        return False, "required Linux commands are missing"
    return True, ""


SUPPORTED, SKIP_REASON = integration_supported()


@unittest.skipUnless(SUPPORTED, SKIP_REASON)
class IdenaPublicStateExportIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="idena-export-integration-", dir="/var/tmp")
        self.root = Path(self.temp.name)
        self.datadir = self.root / "idena"
        self.export = self.root / "export"
        self.state = self.root / "state"
        self.destination = self.root / "destination"
        for directory in (
            self.datadir / "idenachain.db",
            self.datadir / "ipfs" / "badgerds",
            self.datadir / "keystore",
            self.datadir / "snapshots",
            self.export,
            self.state,
            self.destination,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self.write_file(self.datadir / "idenachain.db" / "state", b"chain-state")
        self.write_file(self.datadir / "ipfs" / "badgerds" / "state", b"ipfs-state")
        self.write_file(self.datadir / "snapshots" / "state", b"snapshot-state")
        self.write_file(self.datadir / "keystore" / "nodekey", b"temporary-source-node-key")
        self.write_file(self.datadir / "api.key", b"temporary-source-api-key")
        self.write_file(self.datadir / "ipfs" / "config", b"temporary-source-ipfs-config")
        self.write_file(self.datadir / "ipfs" / "swarm.key", b"temporary-source-swarm-key")

        self.service_state = self.root / "service.state"
        self.service_state.write_text("active\n", encoding="ascii")
        self.fake_systemctl = self.root / "systemctl"
        self.fake_systemctl.write_text(
            """#!/bin/sh
set -eu
case "$1" in
  is-active) grep -qx active "$FAKE_SERVICE_STATE" ;;
  start) printf '%s\\n' active >"$FAKE_SERVICE_STATE" ;;
  stop) printf '%s\\n' inactive >"$FAKE_SERVICE_STATE" ;;
  *) exit 1 ;;
esac
""",
            encoding="ascii",
        )
        self.fake_systemctl.chmod(0o755)

        self.fake_ssh = self.root / "ssh"
        self.fake_ssh.write_text("#!/bin/sh\nprintf '%s\\n' 999999999999\n", encoding="ascii")
        self.fake_ssh.chmod(0o755)
        self.rsync_log = self.root / "rsync.log"
        self.fake_rsync = self.root / "rsync"
        self.fake_rsync.write_text(
            """#!/bin/sh
set -eu
previous=''
last=''
for argument in "$@"; do
  previous="$last"
  last="$argument"
done
case "$last" in
  *:current/)
    find "$FAKE_DESTINATION" -mindepth 1 -depth -delete
    cp -a "$previous"/. "$FAKE_DESTINATION"/
    printf '%s\\n' data >>"$FAKE_RSYNC_LOG"
    ;;
  *:current/READY)
    phase="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["phase"])' \
      "$IDENA_EXPORT_STATE_DIR/pushed.json")"
    printf 'ready:%s\\n' "$phase" >>"$FAKE_RSYNC_LOG"
    [ "${FAKE_FAIL_READY:-0}" = 0 ] || exit 23
    cp -a "$previous" "$FAKE_DESTINATION/READY"
    ;;
  *) exit 2 ;;
esac
""",
            encoding="ascii",
        )
        self.fake_rsync.chmod(0o755)

        self.ssh_key = self.root / "id_ed25519"
        self.ssh_key.write_text("integration-placeholder\n", encoding="ascii")
        self.ssh_key.chmod(0o600)
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text("integration-placeholder\n", encoding="ascii")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ExportRpcHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        unique = f"{os.getpid()}-{id(self)}"
        self.lock = Path(f"/run/lock/idena-export-integration-{unique}.lock")
        self.recovery = Path(f"/run/lock/idena-export-integration-{unique}.source-active")
        (self.state / "sync-ready.since").write_text(
            f"{int(time.time()) - 120}\n", encoding="ascii"
        )
        self.env = dict(os.environ)
        self.env.update(
            {
                "FAKE_DESTINATION": str(self.destination),
                "FAKE_RSYNC_LOG": str(self.rsync_log),
                "FAKE_SERVICE_STATE": str(self.service_state),
                "IDENA_EXPORT_SERVICE": "idena-export-integration.service",
                "IDENA_EXPORT_DATADIR": str(self.datadir),
                "IDENA_EXPORT_DIR": str(self.export),
                "IDENA_EXPORT_STATE_DIR": str(self.state),
                "IDENA_EXPORT_LOCK_FILE": str(self.lock),
                "IDENA_EXPORT_SOURCE_RECOVERY_FILE": str(self.recovery),
                "IDENA_EXPORT_RPC_URL": f"http://127.0.0.1:{self.server.server_port}",
                "IDENA_EXPORT_MIN_HEIGHT": "100",
                "IDENA_EXPORT_MIN_PEERS": "1",
                "IDENA_EXPORT_STABLE_SECONDS": "60",
                "IDENA_EXPORT_MIN_FREE_BYTES": str(1024**3),
                "IDENA_RETURN_MIN_FREE_BYTES": str(1024**3),
                "IDENA_RETURN_TARGET": "idena-return@test-host",
                "IDENA_RETURN_DIR": "current",
                "IDENA_RETURN_SSH_PORT": "2222",
                "IDENA_RETURN_SSH_KEY_FILE": str(self.ssh_key),
                "IDENA_RETURN_KNOWN_HOSTS_FILE": str(self.known_hosts),
                "IDENA_TRANSFER_MANIFEST_TOOL": str(MANIFEST),
                "IDENA_TRANSFER_SYSTEMCTL_BIN": str(self.fake_systemctl),
                "IDENA_TRANSFER_RSYNC_BIN": str(self.fake_rsync),
                "IDENA_TRANSFER_SSH_BIN": str(self.fake_ssh),
                "IDENA_PRIVATE_LOCK_HELPER": str(LOCK_HELPER),
            }
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.lock.unlink(missing_ok=True)
        self.recovery.unlink(missing_ok=True)
        self.temp.cleanup()

    @staticmethod
    def write_file(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def run_export(
        self, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(EXPORTER), *arguments],
            env=self.env if env is None else env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_successful_export_commits_after_ready(self) -> None:
        result = self.run_export()

        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads((self.state / "pushed.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phase"], "ready-sent")
        self.assertEqual(self.rsync_log.read_text(encoding="ascii").splitlines(), ["data", "ready:ready-intent"])
        validated = subprocess.run(
            [
                sys.executable,
                str(MANIFEST),
                "validate",
                "--root",
                str(self.destination),
                "--manifest",
                str(self.destination / "manifest.json"),
                "--print-summary",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "active")
        self.assertFalse(self.recovery.exists())
        for forbidden in ("api.key", "keystore", "config", "swarm.key", "nodekey"):
            self.assertFalse((self.destination / forbidden).exists())

    def test_failed_ready_send_is_fail_closed(self) -> None:
        env = dict(self.env)
        env["FAKE_FAIL_READY"] = "1"
        first = self.run_export(env=env)

        self.assertNotEqual(first.returncode, 0)
        state = json.loads((self.state / "pushed.json").read_text(encoding="utf-8"))
        self.assertEqual(state["phase"], "ready-intent")
        calls_before = self.rsync_log.read_text(encoding="ascii")
        second = self.run_export(env=env)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.rsync_log.read_text(encoding="ascii"), calls_before)
        self.assertIn("inspect it before any intentional retry", second.stdout)

    def test_sigkill_recovery_marker_restarts_source(self) -> None:
        killer = self.root / "manifest-killer"
        killer.write_text("#!/bin/sh\nkill -KILL \"$PPID\"\nsleep 1\nexit 99\n", encoding="ascii")
        killer.chmod(0o755)
        env = dict(self.env)
        env["IDENA_TRANSFER_MANIFEST_TOOL"] = str(killer)
        killed = self.run_export(env=env)

        self.assertNotEqual(killed.returncode, 0)
        self.assertTrue(self.recovery.exists())
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "inactive")
        recovered = self.run_export("--recover-source", env=env)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "active")
        self.assertFalse(self.recovery.exists())

    def test_source_hard_link_is_rejected_before_copy(self) -> None:
        chain_file = self.datadir / "idenachain.db" / "state"
        chain_file.unlink()
        os.link(self.datadir / "api.key", chain_file)

        result = self.run_export()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe file", result.stderr)
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "active")
        self.assertFalse(self.recovery.exists())
        self.assertFalse(any(self.destination.iterdir()))


if __name__ == "__main__":
    unittest.main()
