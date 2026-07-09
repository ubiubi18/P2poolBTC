import datetime as dt
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTO_BOOTSTRAP = REPO_ROOT / "scripts" / "pohw-auto-bootstrap-if-ready.sh"
HEALTH_SCRIPT = REPO_ROOT / "scripts" / "pohw-health-status.py"


class AutoBootstrapTest(unittest.TestCase):
    def write_health(self, path: Path, *, ready: bool, blockers=None) -> None:
        path.write_text(
            json.dumps(
                {
                    "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                    "readiness": {
                        "miningReady": ready,
                        "blockers": blockers or [],
                    },
                }
            ),
            encoding="utf-8",
        )

    def write_fake_bootstrap(self, root: Path, *, status: str = "completed") -> Path:
        fake = root / "fake-bootstrap.sh"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$POHW_FAKE_BOOTSTRAP_CALLS"
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -z "$out" ]]; then
  echo "missing output dir" >&2
  exit 2
fi
mkdir -p "$out"
cat > "$out/status.json" <<JSON
{"status":"STATUS_PLACEHOLDER","mode":"real","appended":true}
JSON
""".replace("STATUS_PLACEHOLDER", status),
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def base_env(self, root: Path, health_file: Path, fake_bootstrap: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_WORKDIR": str(REPO_ROOT),
                "POHW_DATADIR": str(root / "datadir"),
                "POHW_HEALTH_STATUS_FILE": str(health_file),
                "POHW_HEALTH_SCRIPT": str(HEALTH_SCRIPT),
                "POHW_BOOTSTRAP_SCRIPT": str(fake_bootstrap),
                "POHW_AUTO_BOOTSTRAP_DIR": str(root / "auto-bootstrap"),
                "POHW_AUTO_BOOTSTRAP_OUTPUT_ROOT": str(root / "output"),
                "POHW_FAKE_BOOTSTRAP_CALLS": str(root / "calls.txt"),
            }
        )
        return env

    def test_skips_when_health_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-auto-bootstrap-wait-") as temp:
            root = Path(temp)
            health_file = root / "health.json"
            self.write_health(health_file, ready=False, blockers=["bitcoin_node_network_limited"])
            fake_bootstrap = self.write_fake_bootstrap(root)

            result = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=self.base_env(root, health_file, fake_bootstrap),
                text=True,
                capture_output=True,
                check=False,
            )

            calls_file = root / "calls.txt"
            marker = root / "auto-bootstrap" / "bootstrap.done.json"

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not mining-ready", result.stderr)
        self.assertFalse(calls_file.exists())
        self.assertFalse(marker.exists())

    def test_runs_bootstrap_and_writes_marker_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-auto-bootstrap-ready-") as temp:
            root = Path(temp)
            health_file = root / "health.json"
            self.write_health(health_file, ready=True)
            fake_bootstrap = self.write_fake_bootstrap(root)
            env = self.base_env(root, health_file, fake_bootstrap)

            first = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            second = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            calls = (root / "calls.txt").read_text(encoding="utf-8").splitlines()
            marker = json.loads((root / "auto-bootstrap" / "bootstrap.done.json").read_text(encoding="utf-8"))

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(calls), 1)
        self.assertIn("--mode real", calls[0])
        self.assertIn("--append", calls[0])
        self.assertEqual(marker["status"], "completed")
        self.assertTrue(marker["appended"])

    def test_does_not_mark_incomplete_bootstrap_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-auto-bootstrap-incomplete-") as temp:
            root = Path(temp)
            health_file = root / "health.json"
            self.write_health(health_file, ready=True)
            fake_bootstrap = self.write_fake_bootstrap(root, status="bitcoin_not_ready")

            result = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=self.base_env(root, health_file, fake_bootstrap),
                text=True,
                capture_output=True,
                check=False,
            )

            marker = root / "auto-bootstrap" / "bootstrap.done.json"

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_recovers_stale_empty_lock_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-auto-bootstrap-stale-lock-") as temp:
            root = Path(temp)
            health_file = root / "health.json"
            self.write_health(health_file, ready=True)
            fake_bootstrap = self.write_fake_bootstrap(root)
            env = self.base_env(root, health_file, fake_bootstrap)
            env["POHW_AUTO_BOOTSTRAP_LOCK_STALE_SECONDS"] = "0"
            lock = root / "auto-bootstrap" / "bootstrap.lock"
            lock.mkdir(parents=True)

            result = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            calls = (root / "calls.txt").read_text(encoding="utf-8").splitlines()
            marker = root / "auto-bootstrap" / "bootstrap.done.json"
            self.assertTrue(marker.exists())
            self.assertFalse(lock.exists())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Removing stale PoHW auto-bootstrap lock without pid", result.stdout)
        self.assertEqual(len(calls), 1)

    def test_active_lock_pid_skips_without_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-auto-bootstrap-active-lock-") as temp:
            root = Path(temp)
            health_file = root / "health.json"
            self.write_health(health_file, ready=True)
            fake_bootstrap = self.write_fake_bootstrap(root)
            env = self.base_env(root, health_file, fake_bootstrap)
            lock = root / "auto-bootstrap" / "bootstrap.lock"
            lock.mkdir(parents=True)
            (lock / "pid").write_text(f"{os.getpid()}\n", encoding="utf-8")

            result = subprocess.run(
                ["bash", str(AUTO_BOOTSTRAP)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            calls_file = root / "calls.txt"
            self.assertFalse(calls_file.exists())
            self.assertTrue(lock.exists())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already running", result.stdout)


if __name__ == "__main__":
    unittest.main()
