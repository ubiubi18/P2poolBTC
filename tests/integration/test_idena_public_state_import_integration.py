from __future__ import annotations

import fcntl
import grp
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
IMPORTER = REPO_ROOT / "scripts" / "idena-public-state-import.sh"
MANIFEST = REPO_ROOT / "scripts" / "idena-public-state-manifest.py"
LOCK_HELPER = REPO_ROOT / "scripts" / "idena-private-lock-exec.py"
TRANSFER_ID = "0123456789abcdef0123456789abcdef"
REQUIRED_COMMANDS = ("bash", "df", "find", "flock", "getent", "mountpoint", "sha256sum")


class SyncHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        result = {
            "currentBlock": 100,
            "highestBlock": 100,
            "syncing": False,
            "wrongTime": self.server.wrong_time,
        }
        body = json.dumps({"id": 1, "result": result}).encode("utf-8")
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
    try:
        grp.getgrnam("idena-return")
    except KeyError:
        return False, "idena-return group is missing"
    return True, ""


SUPPORTED, SKIP_REASON = integration_supported()


@unittest.skipUnless(SUPPORTED, SKIP_REASON)
class IdenaPublicStateImportIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="idena-import-integration-", dir="/var/tmp")
        self.root = Path(self.temp.name)
        self.datadir = self.root / "idena"
        self.inbox_root = self.root / "inbox"
        self.inbox = self.inbox_root / "current"
        self.backup_root = self.root / "backup"
        self.backup = self.backup_root / "current"
        self.failed = self.root / "failed"
        self.state = self.root / "state"
        for directory in (
            self.datadir,
            self.inbox,
            self.backup,
            self.failed,
            self.state,
            self.datadir / "keystore",
            self.datadir / "ipfs" / "badgerds",
            self.datadir / "idenachain.db",
            self.datadir / "snapshots",
        ):
            directory.mkdir(parents=True, exist_ok=True)

        self.write_file(self.datadir / "keystore" / "nodekey", b"pi-node-key")
        self.write_file(self.datadir / "api.key", b"pi-api-key")
        self.write_file(self.datadir / "ipfs" / "config", b"pi-ipfs-config")
        self.write_file(self.datadir / "ipfs" / "swarm.key", b"pi-swarm-key")
        self.write_file(self.datadir / "idenachain.db" / "state", b"old-chain")
        self.write_file(self.datadir / "ipfs" / "badgerds" / "state", b"old-ipfs")
        self.write_file(self.datadir / "snapshots" / "state", b"old-snapshot")

        self.service_state = self.root / "service.state"
        self.service_state.write_text("active\n", encoding="ascii")
        self.fake_systemctl = self.root / "systemctl"
        self.fake_systemctl.write_text(
            """#!/bin/sh
set -eu
case "$1" in
  show)
    case "$*" in
      *"-p User"*) printf '%s\\n' root ;;
      *"-p Group"*) printf '%s\\n' root ;;
      *) exit 1 ;;
    esac
    ;;
  is-active)
    grep -qx active "$FAKE_SERVICE_STATE"
    ;;
  start)
    printf '%s\\n' active >"$FAKE_SERVICE_STATE"
    ;;
  stop)
    printf '%s\\n' inactive >"$FAKE_SERVICE_STATE"
    ;;
  *) exit 1 ;;
esac
""",
            encoding="ascii",
        )
        self.fake_systemctl.chmod(0o755)

        self.lock = Path(f"/run/lock/idena-return-integration-{os.getpid()}-{id(self)}.lock")
        descriptor = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o660)
        os.close(descriptor)
        group = grp.getgrnam("idena-return")
        os.chown(self.lock, 0, group.gr_gid)
        os.chmod(self.lock, 0o660)
        self.import_lock = Path(f"/run/lock/idena-import-integration-{os.getpid()}-{id(self)}.lock")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), SyncHandler)
        self.server.wrong_time = False
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        self.env = dict(os.environ)
        self.env.update(
            {
                "FAKE_SERVICE_STATE": str(self.service_state),
                "IDENA_IMPORT_SERVICE": "idena-integration.service",
                "IDENA_IMPORT_DATADIR": str(self.datadir),
                "IDENA_IMPORT_INBOX_ROOT": str(self.inbox_root),
                "IDENA_IMPORT_INBOX": str(self.inbox),
                "IDENA_IMPORT_BACKUP_ROOT": str(self.backup_root),
                "IDENA_IMPORT_BACKUP": str(self.backup),
                "IDENA_IMPORT_FAILED_ROOT": str(self.failed),
                "IDENA_IMPORT_STATE_DIR": str(self.state),
                "IDENA_IMPORT_LOCK_FILE": str(self.import_lock),
                "IDENA_TRANSFER_LOCK_FILE": str(self.lock),
                "IDENA_IMPORT_RPC_URL": f"http://127.0.0.1:{self.server.server_port}",
                "IDENA_IMPORT_RPC_TIMEOUT_SECONDS": "30",
                "IDENA_IMPORT_LOCK_TIMEOUT_SECONDS": "60",
                "IDENA_IMPORT_MIN_FREE_BYTES": str(1024**3),
                "IDENA_TRANSFER_MANIFEST_TOOL": str(MANIFEST),
                "IDENA_TRANSFER_SYSTEMCTL_BIN": str(self.fake_systemctl),
                "IDENA_PRIVATE_LOCK_HELPER": str(LOCK_HELPER),
            }
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.lock.unlink(missing_ok=True)
        self.import_lock.unlink(missing_ok=True)
        self.temp.cleanup()

    @staticmethod
    def write_file(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def prepare_transfer(self) -> None:
        for component in ("idenachain.db", "ipfs-badgerds", "snapshots"):
            (self.inbox / component).mkdir(parents=True, exist_ok=True)
        self.write_file(self.inbox / "idenachain.db" / "state", b"new-chain")
        self.write_file(self.inbox / "ipfs-badgerds" / "state", b"new-ipfs")
        self.write_file(self.inbox / "snapshots" / "state", b"new-snapshot")
        created = subprocess.run(
            [
                sys.executable,
                str(MANIFEST),
                "create",
                "--root",
                str(self.inbox),
                "--transfer-id",
                TRANSFER_ID,
                "--source-height",
                "100",
                "--source-highest",
                "100",
                "--output",
                str(self.inbox / "manifest.json"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        (self.inbox / "READY").write_text(
            json.dumps(
                {"schema": 2, "sourceHeight": 100, "transferId": TRANSFER_ID},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

    def run_import(self, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(IMPORTER)],
            env=self.env if env is None else env,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )

    def assert_keys_preserved(self) -> None:
        self.assertEqual((self.datadir / "keystore" / "nodekey").read_bytes(), b"pi-node-key")
        self.assertEqual((self.datadir / "api.key").read_bytes(), b"pi-api-key")
        self.assertEqual((self.datadir / "ipfs" / "config").read_bytes(), b"pi-ipfs-config")
        self.assertEqual((self.datadir / "ipfs" / "swarm.key").read_bytes(), b"pi-swarm-key")

    def swap_without_running_importer(self, phase: str, validated_height: int | None) -> None:
        (self.datadir / "idenachain.db").rename(self.backup / "idenachain.db")
        (self.datadir / "ipfs" / "badgerds").rename(self.backup / "ipfs-badgerds")
        (self.datadir / "snapshots").rename(self.backup / "snapshots")
        (self.inbox / "idenachain.db").rename(self.datadir / "idenachain.db")
        (self.inbox / "ipfs-badgerds").rename(self.datadir / "ipfs" / "badgerds")
        (self.inbox / "snapshots").rename(self.datadir / "snapshots")
        payload = {
            "schema": 1,
            "phase": phase,
            "transferId": TRANSFER_ID,
            "sourceHeight": 100,
            "transferBytes": 30,
            "serviceWasActive": True,
            "snapshotsWerePresent": True,
            "validatedHeight": validated_height,
            "updatedAt": "2026-01-01T00:00:00Z",
        }
        (self.state / "in-progress.json").write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def test_successful_import(self) -> None:
        self.prepare_transfer()
        result = self.run_import()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.datadir / "idenachain.db" / "state").read_bytes(), b"new-chain")
        self.assertEqual((self.datadir / "ipfs" / "badgerds" / "state").read_bytes(), b"new-ipfs")
        self.assertEqual((self.datadir / "snapshots" / "state").read_bytes(), b"new-snapshot")
        self.assertFalse(any(self.inbox.iterdir()))
        self.assertFalse(any(self.backup.iterdir()))
        self.assertFalse((self.state / "in-progress.json").exists())
        completed = json.loads((self.state / "completed.json").read_text(encoding="utf-8"))
        self.assertEqual(completed["transferId"], TRANSFER_ID)
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "active")
        self.assert_keys_preserved()

    def test_private_process_lock_rejects_symlink_without_touching_target(self) -> None:
        victim = self.root / "lock-victim"
        victim.write_text("must-survive\n", encoding="ascii")
        self.import_lock.symlink_to(victim)

        result = self.run_import()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(victim.read_text(encoding="ascii"), "must-survive\n")
        self.assertIn("cannot safely open lock", result.stderr)

    def test_rpc_failure_rolls_back(self) -> None:
        self.prepare_transfer()
        self.server.wrong_time = True
        result = self.run_import()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.datadir / "idenachain.db" / "state").read_bytes(), b"old-chain")
        self.assertEqual((self.datadir / "ipfs" / "badgerds" / "state").read_bytes(), b"old-ipfs")
        self.assertEqual((self.datadir / "snapshots" / "state").read_bytes(), b"old-snapshot")
        self.assertFalse(any(self.inbox.iterdir()))
        self.assertFalse((self.state / "in-progress.json").exists())
        self.assertTrue((self.failed / f"transfer-{TRANSFER_ID}" / "imported-state").is_dir())
        self.assertEqual(self.service_state.read_text(encoding="ascii").strip(), "active")
        self.assert_keys_preserved()

    def test_writer_cannot_mutate_after_validation_starts(self) -> None:
        self.prepare_transfer()
        wrapper = self.root / "manifest-wrapper"
        wrapper.write_text(
            f"#!/bin/sh\n{MANIFEST} \"$@\"\nstatus=$?\nsleep 2\nexit $status\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        env = dict(self.env)
        env["IDENA_TRANSFER_MANIFEST_TOOL"] = str(wrapper)
        importer = subprocess.Popen(
            ["bash", str(IMPORTER)],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            descriptor = os.open(self.lock, os.O_RDWR)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except BlockingIOError:
                    break
            finally:
                os.close(descriptor)
            time.sleep(0.01)
        else:
            importer.kill()
            self.fail("importer never acquired the shared transfer lock")

        mutation_target = self.inbox / "idenachain.db" / "state"
        writer_code = """
import fcntl, os, pathlib, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    pathlib.Path(sys.argv[2]).write_bytes(b'mutated-after-validation')
finally:
    os.close(fd)
"""
        writer = subprocess.Popen(
            [sys.executable, "-c", writer_code, str(self.lock), str(mutation_target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stdout, stderr = importer.communicate(timeout=20)
        writer_result = writer.wait(timeout=10)

        self.assertEqual(importer.returncode, 0, stderr)
        self.assertNotEqual(writer_result, 0)
        self.assertEqual((self.datadir / "idenachain.db" / "state").read_bytes(), b"new-chain")

    def test_running_journal_recovers_by_rollback(self) -> None:
        self.prepare_transfer()
        self.swap_without_running_importer("running", None)
        result = self.run_import()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.datadir / "idenachain.db" / "state").read_bytes(), b"old-chain")
        self.assertFalse((self.state / "in-progress.json").exists())
        self.assertFalse(any(self.inbox.iterdir()))
        self.assert_keys_preserved()

    def test_committed_journal_recovers_by_finalizing(self) -> None:
        self.prepare_transfer()
        self.swap_without_running_importer("committed", 100)
        result = self.run_import()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.datadir / "idenachain.db" / "state").read_bytes(), b"new-chain")
        self.assertFalse((self.state / "in-progress.json").exists())
        self.assertFalse(any(self.inbox.iterdir()))
        self.assertFalse(any(self.backup.iterdir()))
        self.assert_keys_preserved()


if __name__ == "__main__":
    unittest.main()
