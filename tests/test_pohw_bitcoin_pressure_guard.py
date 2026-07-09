from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = REPO_ROOT / "scripts" / "pohw-bitcoin-pressure-guard.py"
spec = importlib.util.spec_from_file_location("pohw_bitcoin_pressure_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


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


class BitcoinPressureGuardTest(unittest.TestCase):
    def test_default_state_is_outside_the_operator_writable_datadir(self) -> None:
        cfg = guard.load_config({})

        self.assertEqual(cfg.state_dir, Path("/var/lib/pohw/bitcoin-pressure"))

    def config(
        self,
        root: Path,
        *,
        high_streak: int = 2,
        low_streak: int = 3,
        cooldown: int = 1800,
        stop_when_mining_ready: bool = False,
        force: bool = False,
    ) -> guard.GuardConfig:
        state = root / "bitcoin-pressure"
        return guard.GuardConfig(
            state_dir=state,
            status_file=state / "status.json",
            state_file=state / "state.json",
            marker_file=state / "bitcoin-paused.json",
            health_status_file=root / "health.json",
            health_max_age_seconds=180,
            bitcoin_service="bitcoind-mainnet.service",
            high_iowait_percent=40.0,
            high_util_percent=85.0,
            critical_util_percent=98.0,
            critical_await_ms=250.0,
            low_iowait_percent=20.0,
            low_util_percent=60.0,
            low_await_ms=50.0,
            high_streak_threshold=high_streak,
            low_streak_threshold=low_streak,
            cooldown_seconds=cooldown,
            restore_bitcoin=True,
            stop_when_mining_ready=stop_when_mining_ready,
            force=force,
            dry_run=False,
        )

    def write_health(
        self,
        root: Path,
        *,
        now: datetime,
        iowait: float,
        util: float,
        read_await_ms: float = 10.0,
        write_await_ms: float = 5.0,
        mining_ready: bool = False,
    ) -> None:
        payload = {
            "generatedAt": guard.iso_utc(now),
            "io": {
                "cpuIowaitPercent": iowait,
                "utilPercent": util,
                "readAwaitMs": read_await_ms,
                "writeAwaitMs": write_await_ms,
            },
            "readiness": {"miningReady": mining_ready},
        }
        (root / "health.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_observes_high_pressure_before_stopping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-observe-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=55.0, util=90.0)
            cfg = self.config(root, high_streak=2)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "observing_high_pressure")
        self.assertNotIn("stop bitcoind-mainnet.service", service.calls)
        self.assertTrue(service.active)

    def test_stops_bitcoin_after_high_pressure_streak(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-stop-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=55.0, util=90.0)
            cfg = self.config(root, high_streak=2)
            service = FakeService(active=True)

            first = guard.run_once(cfg, service, now=now)
            second = guard.run_once(cfg, service, now=now + timedelta(minutes=1))
            marker_exists = cfg.marker_file.exists()

        self.assertEqual(first["status"], "observing_high_pressure")
        self.assertEqual(second["status"], "stopped_bitcoin")
        self.assertIn("stop bitcoind-mainnet.service", service.calls)
        self.assertFalse(service.active)
        self.assertTrue(marker_exists)

    def test_high_utilization_alone_does_not_pause_normal_ibd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-normal-ibd-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=5.0, util=99.0)
            cfg = self.config(root, high_streak=1)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "idle_intermediate_pressure")
        self.assertFalse(status["rawPressureHigh"])
        self.assertNotIn("stop bitcoind-mainnet.service", service.calls)

    def test_critical_latency_and_utilization_can_pause_without_high_iowait(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-critical-await-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(
                root,
                now=now,
                iowait=5.0,
                util=99.0,
                read_await_ms=300.0,
            )
            cfg = self.config(root, high_streak=1)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "stopped_bitcoin")
        self.assertIn("stop bitcoind-mainnet.service", service.calls)
        self.assertTrue(
            any(reason.startswith("io_critical_latency:") for reason in status["reasons"])
        )

    def test_ignores_pressure_when_mining_ready_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-mining-ready-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=80.0, util=99.0, mining_ready=True)
            cfg = self.config(root, high_streak=1)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "mining_ready_pressure_ignored")
        self.assertTrue(status["rawPressureHigh"])
        self.assertFalse(status["pressureHigh"])
        self.assertNotIn("stop bitcoind-mainnet.service", service.calls)

    def test_restarts_after_cooldown_and_low_pressure_streak(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-start-") as temp:
            root = Path(temp)
            cfg = self.config(root, low_streak=2, cooldown=60)
            cfg.state_dir.mkdir()
            guard.write_json_file(
                cfg.marker_file,
                {
                    "managedStop": True,
                    "lastPressureAt": "2026-07-09T09:58:00Z",
                    "reasons": ["io_iowait:55.00>=40.00"],
                },
            )
            service = FakeService(active=False)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=10.0, util=40.0)

            first = guard.run_once(cfg, service, now=now)
            second = guard.run_once(cfg, service, now=now + timedelta(minutes=1))

            marker_exists = cfg.marker_file.exists()

        self.assertEqual(first["status"], "observing_low_pressure")
        self.assertEqual(second["status"], "started_bitcoin")
        self.assertIn("start bitcoind-mainnet.service", service.calls)
        self.assertTrue(service.active)
        self.assertFalse(marker_exists)

    def test_force_overrides_mining_ready_exemption(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-force-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=5.0, util=10.0, mining_ready=True)
            cfg = self.config(root, high_streak=1, force=True)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "stopped_bitcoin")
        self.assertIn("forced", status["reasons"])
        self.assertIn("stop bitcoind-mainnet.service", service.calls)

    def test_systemd_stop_uses_no_block(self) -> None:
        calls: list[tuple[list[str], bool]] = []

        def fake_run(args: list[str], *, check: bool = False) -> object:
            calls.append((args, check))
            return object()

        manager = guard.SystemdServiceManager("systemctl")
        with mock.patch.object(guard.subprocess, "run", fake_run):
            manager.stop("bitcoind-mainnet.service")

        self.assertEqual(calls, [(["systemctl", "--no-block", "stop", "bitcoind-mainnet.service"], True)])

    def test_does_not_start_bitcoin_after_unmanaged_stop(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-unmanaged-") as temp:
            root = Path(temp)
            cfg = self.config(root, low_streak=1, cooldown=0)
            cfg.state_dir.mkdir()
            guard.write_json_file(
                cfg.marker_file,
                {
                    "managedStop": False,
                    "lastPressureAt": "2026-07-09T09:58:00Z",
                    "reasons": ["io_util:90.00>=85.00"],
                },
            )
            service = FakeService(active=False)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now, iowait=10.0, util=40.0)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "cleared_marker")
        self.assertNotIn("start bitcoind-mainnet.service", service.calls)
        self.assertFalse(service.active)

    def test_stale_health_does_not_stop_bitcoin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-bitcoin-pressure-stale-") as temp:
            root = Path(temp)
            now = datetime(2026, 7, 9, 10, 0, tzinfo=timezone.utc)
            self.write_health(root, now=now - timedelta(minutes=10), iowait=90.0, util=99.0)
            cfg = self.config(root, high_streak=1)
            service = FakeService(active=True)

            status = guard.run_once(cfg, service, now=now)

        self.assertEqual(status["status"], "health_stale")
        self.assertNotIn("stop bitcoind-mainnet.service", service.calls)
        self.assertTrue(service.active)


if __name__ == "__main__":
    unittest.main()
