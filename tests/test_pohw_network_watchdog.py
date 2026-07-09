from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = REPO_ROOT / "scripts" / "pohw-network-watchdog.sh"


class NetworkWatchdogTest(unittest.TestCase):
    def write_fake_ping(self, root: Path) -> Path:
        fake = root / "fake-ping.sh"
        fake.write_text(
            """#!/usr/bin/env bash
if [[ "${POHW_FAKE_PING_OK:-false}" == "true" ]]; then
  exit 0
fi
exit 1
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def write_fake_systemctl(self, root: Path) -> Path:
        fake = root / "fake-systemctl.sh"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$POHW_FAKE_SYSTEMCTL_LOG"
last=""
for arg in "$@"; do
  last="$arg"
done
if [[ "${1:-}" == "is-active" ]]; then
  if [[ "$last" == "NetworkManager.service" ]]; then
    exit 0
  fi
  exit 3
fi
exit 0
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def run_watchdog(
        self,
        root: Path,
        *,
        ping_ok: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_NETWORK_WATCHDOG_STATE_DIR": str(root / "state"),
                "POHW_NETWORK_WATCHDOG_TARGETS": "192.0.2.1,192.0.2.2",
                "POHW_NETWORK_WATCHDOG_PING_TIMEOUT_SECONDS": "1",
                "POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD": "2",
                "POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD": "4",
                "POHW_NETWORK_WATCHDOG_DRY_RUN": "false",
                "POHW_NETWORK_WATCHDOG_PING_BIN": str(root / "fake-ping.sh"),
                "POHW_NETWORK_WATCHDOG_SYSTEMCTL_BIN": str(root / "fake-systemctl.sh"),
                "POHW_FAKE_SYSTEMCTL_LOG": str(root / "systemctl.log"),
                "POHW_FAKE_PING_OK": "true" if ping_ok else "false",
            }
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(WATCHDOG)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def read_status(self, root: Path) -> dict:
        return json.loads((root / "state" / "status.json").read_text(encoding="utf-8"))

    def test_successful_ping_resets_failure_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-network-watchdog-ok-") as temp:
            root = Path(temp)
            self.write_fake_ping(root)
            self.write_fake_systemctl(root)
            state = root / "state"
            state.mkdir()
            (state / "failure-count").write_text("3\n", encoding="utf-8")
            (state / "network-restart-attempted").write_text("old\n", encoding="utf-8")

            result = self.run_watchdog(root, ping_ok=True)
            status = self.read_status(root)
            failure_count = (state / "failure-count").read_text(encoding="utf-8").strip()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["failureCount"], 0)
        self.assertEqual(failure_count, "0")
        self.assertFalse((state / "network-restart-attempted").exists())

    def test_failure_streak_restarts_network_once_then_reboots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-network-watchdog-fail-") as temp:
            root = Path(temp)
            self.write_fake_ping(root)
            self.write_fake_systemctl(root)

            first = self.run_watchdog(root)
            second = self.run_watchdog(root)
            third = self.run_watchdog(root)
            fourth = self.run_watchdog(root)

            status = self.read_status(root)
            log = (root / "systemctl.log").read_text(encoding="utf-8").splitlines()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertEqual(fourth.returncode, 0, fourth.stderr)
        self.assertIn("Network watchdog failed 1/4 checks.", first.stdout)
        self.assertIn("Restarting active network service: NetworkManager.service", second.stdout)
        self.assertIn("Network watchdog still failing after restart attempt: 3/4.", third.stdout)
        self.assertEqual(status["status"], "reboot_requested")
        self.assertEqual(status["failureCount"], 4)
        self.assertIn("try-restart NetworkManager.service", log)
        self.assertEqual(log[-1], "reboot")

    def test_invalid_thresholds_fail_before_actions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-network-watchdog-invalid-") as temp:
            root = Path(temp)
            self.write_fake_ping(root)
            self.write_fake_systemctl(root)
            env = dict(os.environ)
            env.update(
                {
                    "POHW_NETWORK_WATCHDOG_STATE_DIR": str(root / "state"),
                    "POHW_NETWORK_WATCHDOG_TARGETS": "192.0.2.1",
                    "POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD": "5",
                    "POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD": "4",
                    "POHW_NETWORK_WATCHDOG_PING_BIN": str(root / "fake-ping.sh"),
                    "POHW_NETWORK_WATCHDOG_SYSTEMCTL_BIN": str(root / "fake-systemctl.sh"),
                    "POHW_FAKE_SYSTEMCTL_LOG": str(root / "systemctl.log"),
                }
            )

            result = subprocess.run(
                ["bash", str(WATCHDOG)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid watchdog thresholds", result.stderr)
        self.assertFalse((root / "systemctl.log").exists())

    def test_recovers_stale_empty_lock_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-network-watchdog-stale-lock-") as temp:
            root = Path(temp)
            self.write_fake_ping(root)
            self.write_fake_systemctl(root)
            lock = root / "state" / "lock"
            lock.mkdir(parents=True)

            result = self.run_watchdog(
                root,
                ping_ok=True,
                extra_env={"POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS": "0"},
            )
            status = self.read_status(root)
            self.assertFalse(lock.exists())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Removing stale PoHW network watchdog lock without pid", result.stdout)
        self.assertEqual(status["status"], "ok")

    def test_active_lock_pid_skips_without_probe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-network-watchdog-active-lock-") as temp:
            root = Path(temp)
            self.write_fake_ping(root)
            self.write_fake_systemctl(root)
            lock = root / "state" / "lock"
            lock.mkdir(parents=True)
            (lock / "pid").write_text(f"{os.getpid()}\n", encoding="utf-8")

            result = self.run_watchdog(root, ping_ok=True)
            self.assertFalse((root / "state" / "status.json").exists())
            self.assertFalse((root / "systemctl.log").exists())
            self.assertTrue(lock.exists())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already running", result.stdout)


if __name__ == "__main__":
    unittest.main()
