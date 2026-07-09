from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = REPO_ROOT / "scripts" / "pohw-idena-priority-guard.py"
spec = importlib.util.spec_from_file_location("pohw_idena_priority_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


class FakeClient:
    def __init__(self, epoch: dict[str, Any] | None = None, *, error: Exception | None = None) -> None:
        self.epoch = epoch or {"epoch": 1, "currentPeriod": "None", "nextValidation": "2099-01-01T00:00:00Z"}
        self.error = error

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        if self.error:
            raise self.error
        if method != "dna_epoch":
            raise AssertionError(method)
        return self.epoch


class FakeService:
    def __init__(self, *, active: bool) -> None:
        self.active = active
        self.calls: list[str] = []

    def is_active(self, service: str) -> bool:
        self.calls.append(f"is-active {service}")
        return self.active

    def stop(self, service: str) -> None:
        self.calls.append(f"stop {service}")
        self.active = False

    def start(self, service: str) -> None:
        self.calls.append(f"start {service}")
        self.active = True


class IdenaPriorityGuardTest(unittest.TestCase):
    def test_default_state_is_outside_the_operator_writable_datadir(self) -> None:
        cfg = guard.load_config({})

        self.assertEqual(cfg.state_dir, Path("/var/lib/pohw/idena-priority"))

    def config(self, root: Path, *, lead: int = 3600, cooldown: int = 1800) -> guard.GuardConfig:
        state = root / "idena-priority"
        return guard.GuardConfig(
            state_dir=state,
            status_file=state / "status.json",
            marker_file=state / "bitcoin-paused.json",
            bitcoin_service="bitcoind-mainnet.service",
            lead_seconds=lead,
            cooldown_seconds=cooldown,
            period_keywords=("flip", "short", "long", "validation"),
            restore_bitcoin=True,
            force=False,
            dry_run=False,
        )

    def test_protection_reasons_match_active_validation_period(self) -> None:
        now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
        cfg = self.config(Path(tempfile.gettempdir()))

        reasons = guard.protection_reasons(
            cfg,
            {"currentPeriod": "ShortSession", "nextValidation": "2099-01-01T00:00:00Z"},
            now,
        )

        self.assertIn("current_period:ShortSession", reasons)

    def test_protection_reasons_match_upcoming_validation_window(self) -> None:
        now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
        cfg = self.config(Path(tempfile.gettempdir()), lead=3600)
        next_validation = now + timedelta(minutes=20)

        reasons = guard.protection_reasons(
            cfg,
            {"currentPeriod": "None", "nextValidation": guard.iso_utc(next_validation)},
            now,
        )

        self.assertEqual(reasons, ["validation_window:1200s"])

    def test_stops_active_bitcoin_when_idena_period_is_protected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-priority-stop-") as temp:
            root = Path(temp)
            cfg = self.config(root)
            service = FakeService(active=True)

            status = guard.run_once(
                cfg,
                FakeClient({"epoch": 9, "currentPeriod": "LongSession", "nextValidation": "2099-01-01T00:00:00Z"}),
                service,
                now=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(status["status"], "stopped_bitcoin")
        self.assertIn("stop bitcoind-mainnet.service", service.calls)
        self.assertFalse(service.active)

    def test_restarts_only_after_guard_managed_stop_and_cooldown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-priority-start-") as temp:
            root = Path(temp)
            cfg = self.config(root, cooldown=60)
            cfg.state_dir.mkdir()
            guard.write_json_file(
                cfg.marker_file,
                {
                    "managedStop": True,
                    "lastProtectedAt": "2026-07-09T09:58:00Z",
                    "reasons": ["current_period:ShortSession"],
                },
            )
            service = FakeService(active=False)

            status = guard.run_once(
                cfg,
                FakeClient({"epoch": 9, "currentPeriod": "None", "nextValidation": "2099-01-01T00:00:00Z"}),
                service,
                now=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(status["status"], "started_bitcoin")
        self.assertIn("start bitcoind-mainnet.service", service.calls)
        self.assertTrue(service.active)
        self.assertFalse(cfg.marker_file.exists())

    def test_does_not_start_bitcoin_when_it_was_already_stopped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-idena-priority-unmanaged-") as temp:
            root = Path(temp)
            cfg = self.config(root, cooldown=60)
            cfg.state_dir.mkdir()
            guard.write_json_file(
                cfg.marker_file,
                {
                    "managedStop": False,
                    "lastProtectedAt": "2026-07-09T09:58:00Z",
                    "reasons": ["current_period:ShortSession"],
                },
            )
            service = FakeService(active=False)

            status = guard.run_once(
                cfg,
                FakeClient({"epoch": 9, "currentPeriod": "None", "nextValidation": "2099-01-01T00:00:00Z"}),
                service,
                now=datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(status["status"], "cleared_marker")
        self.assertNotIn("start bitcoind-mainnet.service", service.calls)
        self.assertFalse(service.active)

    def test_systemd_stop_uses_no_block(self) -> None:
        calls: list[tuple[list[str], bool]] = []

        def fake_run(args: list[str], *, check: bool = False) -> object:
            calls.append((args, check))
            return object()

        manager = guard.SystemdServiceManager("systemctl")
        with mock.patch.object(guard.subprocess, "run", fake_run):
            manager.stop("bitcoind-mainnet.service")

        self.assertEqual(calls, [(["systemctl", "--no-block", "stop", "bitcoind-mainnet.service"], True)])


if __name__ == "__main__":
    unittest.main()
