#!/usr/bin/env python3
"""Pause Bitcoin Core when host I/O pressure threatens Pi responsiveness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class GuardConfig:
    state_dir: Path
    status_file: Path
    state_file: Path
    marker_file: Path
    health_status_file: Path
    health_max_age_seconds: int
    bitcoin_service: str
    high_iowait_percent: float
    high_util_percent: float
    critical_util_percent: float
    critical_await_ms: float
    low_iowait_percent: float
    low_util_percent: float
    low_await_ms: float
    high_streak_threshold: int
    low_streak_threshold: int
    cooldown_seconds: int
    restore_bitcoin: bool
    stop_when_mining_ready: bool
    force: bool
    dry_run: bool


class ServiceManager(Protocol):
    def is_active(self, service: str) -> bool:
        ...

    def stop(self, service: str) -> None:
        ...

    def start(self, service: str) -> None:
        ...


class SystemdServiceManager:
    def __init__(self, systemctl_bin: str = "systemctl", *, dry_run: bool = False) -> None:
        self.systemctl_bin = systemctl_bin
        self.dry_run = dry_run

    def is_active(self, service: str) -> bool:
        result = subprocess.run(
            [self.systemctl_bin, "is-active", "--quiet", service],
            check=False,
        )
        return result.returncode == 0

    def stop(self, service: str) -> None:
        if self.dry_run:
            print(f"Dry-run: would stop {service}")
            return
        subprocess.run([self.systemctl_bin, "--no-block", "stop", service], check=True)

    def start(self, service: str) -> None:
        if self.dry_run:
            print(f"Dry-run: would start {service}")
            return
        subprocess.run([self.systemctl_bin, "start", service], check=True)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value in {"1", "true", "TRUE", "yes", "YES", "on", "ON"}


def parse_nonnegative_int(value: str | None, name: str, *, default: int) -> int:
    raw = str(default) if value is None or value == "" else value
    try:
        parsed = int(raw, 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be >= 0")
    return parsed


def parse_positive_int(value: str | None, name: str, *, default: int) -> int:
    parsed = parse_nonnegative_int(value, name, default=default)
    if parsed < 1:
        raise ValueError(f"{name} must be >= 1")
    return parsed


def parse_percent(value: str | None, name: str, *, default: float) -> float:
    raw = str(default) if value is None or value == "" else value
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if parsed < 0 or parsed > 100:
        raise ValueError(f"{name} must be between 0 and 100")
    return parsed


def parse_nonnegative_float(value: str | None, name: str, *, default: float) -> float:
    raw = str(default) if value is None or value == "" else value
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be >= 0")
    return parsed


def load_config(env: dict[str, str] | None = None) -> GuardConfig:
    env = env or os.environ
    datadir = Path(env.get("POHW_DATADIR", "/mnt/ssd/pohw-p2pool"))
    state_dir = Path(env.get("POHW_BITCOIN_PRESSURE_STATE_DIR", "/var/lib/pohw/bitcoin-pressure"))
    return GuardConfig(
        state_dir=state_dir,
        status_file=Path(env.get("POHW_BITCOIN_PRESSURE_STATUS_FILE", str(state_dir / "status.json"))),
        state_file=Path(env.get("POHW_BITCOIN_PRESSURE_STATE_FILE", str(state_dir / "state.json"))),
        marker_file=Path(env.get("POHW_BITCOIN_PRESSURE_MARKER_FILE", str(state_dir / "bitcoin-paused.json"))),
        health_status_file=Path(env.get("POHW_HEALTH_STATUS_FILE", str(datadir / "health" / "status.json"))),
        health_max_age_seconds=parse_positive_int(
            env.get("POHW_BITCOIN_PRESSURE_HEALTH_MAX_AGE_SECONDS"),
            "POHW_BITCOIN_PRESSURE_HEALTH_MAX_AGE_SECONDS",
            default=180,
        ),
        bitcoin_service=env.get("POHW_BITCOIN_PRESSURE_BITCOIN_SERVICE", "bitcoind-mainnet.service"),
        high_iowait_percent=parse_percent(
            env.get("POHW_BITCOIN_PRESSURE_HIGH_IOWAIT_PERCENT"),
            "POHW_BITCOIN_PRESSURE_HIGH_IOWAIT_PERCENT",
            default=40.0,
        ),
        high_util_percent=parse_percent(
            env.get("POHW_BITCOIN_PRESSURE_HIGH_UTIL_PERCENT"),
            "POHW_BITCOIN_PRESSURE_HIGH_UTIL_PERCENT",
            default=85.0,
        ),
        critical_util_percent=parse_percent(
            env.get("POHW_BITCOIN_PRESSURE_CRITICAL_UTIL_PERCENT"),
            "POHW_BITCOIN_PRESSURE_CRITICAL_UTIL_PERCENT",
            default=98.0,
        ),
        critical_await_ms=parse_nonnegative_float(
            env.get("POHW_BITCOIN_PRESSURE_CRITICAL_AWAIT_MS"),
            "POHW_BITCOIN_PRESSURE_CRITICAL_AWAIT_MS",
            default=250.0,
        ),
        low_iowait_percent=parse_percent(
            env.get("POHW_BITCOIN_PRESSURE_LOW_IOWAIT_PERCENT"),
            "POHW_BITCOIN_PRESSURE_LOW_IOWAIT_PERCENT",
            default=20.0,
        ),
        low_util_percent=parse_percent(
            env.get("POHW_BITCOIN_PRESSURE_LOW_UTIL_PERCENT"),
            "POHW_BITCOIN_PRESSURE_LOW_UTIL_PERCENT",
            default=60.0,
        ),
        low_await_ms=parse_nonnegative_float(
            env.get("POHW_BITCOIN_PRESSURE_LOW_AWAIT_MS"),
            "POHW_BITCOIN_PRESSURE_LOW_AWAIT_MS",
            default=50.0,
        ),
        high_streak_threshold=parse_positive_int(
            env.get("POHW_BITCOIN_PRESSURE_HIGH_STREAK"),
            "POHW_BITCOIN_PRESSURE_HIGH_STREAK",
            default=2,
        ),
        low_streak_threshold=parse_positive_int(
            env.get("POHW_BITCOIN_PRESSURE_LOW_STREAK"),
            "POHW_BITCOIN_PRESSURE_LOW_STREAK",
            default=3,
        ),
        cooldown_seconds=parse_nonnegative_int(
            env.get("POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS"),
            "POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS",
            default=1800,
        ),
        restore_bitcoin=parse_bool(env.get("POHW_BITCOIN_PRESSURE_RESTORE_BITCOIN"), default=True),
        stop_when_mining_ready=parse_bool(env.get("POHW_BITCOIN_PRESSURE_STOP_WHEN_MINING_READY"), default=False),
        force=parse_bool(env.get("POHW_BITCOIN_PRESSURE_FORCE"), default=False),
        dry_run=parse_bool(env.get("POHW_BITCOIN_PRESSURE_DRY_RUN"), default=False),
    )


def ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlinked state directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    if not isinstance(data, dict):
        raise RuntimeError(f"JSON file is not an object: {path}")
    return data


def write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def health_age_seconds(health: dict[str, Any], now: datetime) -> int | None:
    generated_at = parse_datetime(health.get("generatedAt"))
    if generated_at is None:
        return None
    return max(int((now - generated_at).total_seconds()), 0)


def health_available(config: GuardConfig, health: dict[str, Any] | None, now: datetime) -> tuple[bool, str, int | None]:
    if health is None:
        return False, "health_missing", None
    age = health_age_seconds(health, now)
    if age is None:
        return False, "health_timestamp_missing", None
    if age > config.health_max_age_seconds:
        return False, "health_stale", age
    return True, "", age


def io_metrics(health: dict[str, Any] | None) -> dict[str, float | None]:
    io = health.get("io") if isinstance(health, dict) else None
    if not isinstance(io, dict):
        io = {}
    return {
        "iowaitPercent": number(io.get("cpuIowaitPercent")),
        "utilPercent": number(io.get("utilPercent")),
        "readAwaitMs": number(io.get("readAwaitMs")),
        "writeAwaitMs": number(io.get("writeAwaitMs")),
    }


def mining_ready(health: dict[str, Any] | None) -> bool:
    readiness = health.get("readiness") if isinstance(health, dict) else None
    return bool(readiness.get("miningReady")) if isinstance(readiness, dict) else False


def pressure_reasons(config: GuardConfig, metrics: dict[str, float | None]) -> list[str]:
    reasons: list[str] = []
    iowait = metrics.get("iowaitPercent")
    util = metrics.get("utilPercent")
    await_values = [
        value
        for value in (metrics.get("readAwaitMs"), metrics.get("writeAwaitMs"))
        if value is not None
    ]
    max_await = max(await_values) if await_values else None
    if (
        iowait is not None
        and util is not None
        and iowait >= config.high_iowait_percent
        and util >= config.high_util_percent
    ):
        reasons.append(
            "io_saturation:"
            f"iowait={iowait:.2f}>={config.high_iowait_percent:.2f},"
            f"util={util:.2f}>={config.high_util_percent:.2f}"
        )
    if (
        util is not None
        and max_await is not None
        and util >= config.critical_util_percent
        and max_await >= config.critical_await_ms
    ):
        reasons.append(
            "io_critical_latency:"
            f"util={util:.2f}>={config.critical_util_percent:.2f},"
            f"await_ms={max_await:.2f}>={config.critical_await_ms:.2f}"
        )
    return reasons


def pressure_is_low(config: GuardConfig, metrics: dict[str, float | None]) -> bool:
    iowait = metrics.get("iowaitPercent")
    util = metrics.get("utilPercent")
    await_values = [
        value
        for value in (metrics.get("readAwaitMs"), metrics.get("writeAwaitMs"))
        if value is not None
    ]
    max_await = max(await_values) if await_values else None
    if iowait is None or util is None:
        return False
    await_is_low = max_await is None or max_await <= config.low_await_ms
    return (
        iowait <= config.low_iowait_percent
        and util <= config.low_util_percent
        and await_is_low
    )


def stopped_marker(now: datetime, *, managed_stop: bool, reasons: list[str], health: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "managedStop": managed_stop,
        "reasons": reasons,
        "stoppedAt": iso_utc(now),
        "lastPressureAt": iso_utc(now),
        "healthGeneratedAt": health.get("generatedAt") if isinstance(health, dict) else None,
    }


def update_marker(marker: dict[str, Any], now: datetime, reasons: list[str], health: dict[str, Any] | None) -> dict[str, Any]:
    updated = dict(marker)
    updated["lastPressureAt"] = iso_utc(now)
    updated["reasons"] = reasons
    updated["healthGeneratedAt"] = health.get("generatedAt") if isinstance(health, dict) else None
    return updated


def run_once(
    config: GuardConfig,
    service: ServiceManager,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    ensure_private_dir(config.state_dir)

    health = read_json_file(config.health_status_file)
    health_ok, health_status, health_age = health_available(config, health, now)
    metrics = io_metrics(health)
    ready = mining_ready(health)
    raw_reasons = pressure_reasons(config, metrics)
    raw_high = bool(raw_reasons)
    effective_reasons = list(raw_reasons)
    if config.force:
        effective_reasons.append("forced")
    if ready and not config.stop_when_mining_ready and not config.force:
        effective_reasons = []
    pressure_high = bool(effective_reasons) and (health_ok or config.force)
    low_pressure = health_ok and (pressure_is_low(config, metrics) or (ready and not config.stop_when_mining_ready))

    previous_state = read_json_file(config.state_file) or {}
    high_streak = int(previous_state.get("highStreak") or 0)
    low_streak = int(previous_state.get("lowStreak") or 0)
    if pressure_high:
        high_streak += 1
        low_streak = 0
    elif low_pressure:
        high_streak = 0
        low_streak += 1
    else:
        high_streak = 0
        low_streak = 0

    bitcoin_active = service.is_active(config.bitcoin_service)
    marker = read_json_file(config.marker_file)
    action = "idle"
    detail = "Bitcoin pressure guard is idle."

    if not health_ok and not config.force:
        if marker is not None:
            action = "holding_on_health_error"
            detail = f"Health status is unavailable ({health_status}); keeping current Bitcoin state."
        else:
            action = health_status
            detail = "Health status is unavailable; not changing Bitcoin state."
    elif pressure_high:
        if high_streak < config.high_streak_threshold:
            action = "observing_high_pressure"
            detail = f"High I/O pressure observed ({high_streak}/{config.high_streak_threshold})."
        elif bitcoin_active:
            service.stop(config.bitcoin_service)
            marker = stopped_marker(now, managed_stop=True, reasons=effective_reasons, health=health)
            write_json_file(config.marker_file, marker)
            action = "stopped_bitcoin"
            detail = "Bitcoin Core stopped to reduce Pi I/O pressure."
        elif marker is None:
            marker = stopped_marker(now, managed_stop=False, reasons=effective_reasons, health=health)
            write_json_file(config.marker_file, marker)
            action = "holding_existing_stop"
            detail = "Bitcoin Core was already inactive; guard will not restart it later."
        else:
            marker = update_marker(marker, now, effective_reasons, health)
            write_json_file(config.marker_file, marker)
            action = "holding_bitcoin"
            detail = "I/O pressure remains high; keeping Bitcoin Core stopped."
    elif marker is not None:
        last_pressure = parse_datetime(marker.get("lastPressureAt")) or parse_datetime(marker.get("stoppedAt")) or now
        elapsed = int((now - last_pressure).total_seconds())
        cooldown_remaining = max(config.cooldown_seconds - elapsed, 0)
        managed_stop = bool(marker.get("managedStop"))
        if cooldown_remaining > 0:
            action = "cooldown"
            detail = f"Waiting {cooldown_remaining}s before restoring Bitcoin Core."
        elif not low_pressure:
            action = "waiting_for_low_pressure"
            detail = "Waiting for I/O pressure to fall below resume thresholds."
        elif low_streak < config.low_streak_threshold:
            action = "observing_low_pressure"
            detail = f"Low I/O pressure observed ({low_streak}/{config.low_streak_threshold})."
        elif managed_stop and config.restore_bitcoin:
            if not bitcoin_active:
                service.start(config.bitcoin_service)
            config.marker_file.unlink(missing_ok=True)
            marker = None
            action = "started_bitcoin"
            detail = "Bitcoin Core restarted after pressure cooldown."
        else:
            config.marker_file.unlink(missing_ok=True)
            marker = None
            action = "cleared_marker"
            detail = "Guard marker cleared; Bitcoin was not stopped by this guard."
    elif raw_high and ready and not config.stop_when_mining_ready:
        action = "mining_ready_pressure_ignored"
        detail = "Bitcoin appears mining-ready; pressure guard will not pause it by default."
    elif low_pressure:
        action = "idle_low_pressure"
        detail = "I/O pressure is below resume thresholds."
    else:
        action = "idle_intermediate_pressure"
        detail = "I/O pressure is below stop thresholds but not yet below resume thresholds."

    state = {
        "highStreak": high_streak,
        "lowStreak": low_streak,
        "updatedAt": iso_utc(now),
    }
    write_json_file(config.state_file, state)

    status = {
        "generatedAt": iso_utc(now),
        "status": action,
        "detail": detail,
        "bitcoinService": config.bitcoin_service,
        "bitcoinWasActive": bitcoin_active,
        "protecting": marker is not None,
        "healthStatus": "ok" if health_ok else health_status,
        "healthAgeSeconds": health_age,
        "miningReady": ready,
        "rawPressureHigh": raw_high,
        "pressureHigh": pressure_high,
        "lowPressure": low_pressure,
        "reasons": effective_reasons,
        "rawReasons": raw_reasons,
        "metrics": metrics,
        "highStreak": high_streak,
        "lowStreak": low_streak,
        "thresholds": {
            "highIowaitPercent": config.high_iowait_percent,
            "highUtilPercent": config.high_util_percent,
            "criticalUtilPercent": config.critical_util_percent,
            "criticalAwaitMs": config.critical_await_ms,
            "lowIowaitPercent": config.low_iowait_percent,
            "lowUtilPercent": config.low_util_percent,
            "lowAwaitMs": config.low_await_ms,
            "highStreak": config.high_streak_threshold,
            "lowStreak": config.low_streak_threshold,
            "cooldownSeconds": config.cooldown_seconds,
        },
        "restoreBitcoin": config.restore_bitcoin,
        "stopWhenMiningReady": config.stop_when_mining_ready,
        "dryRun": config.dry_run,
    }
    write_json_file(config.status_file, status)
    print(f"PoHW Bitcoin pressure guard: {action} - {detail}")
    return status


def main() -> int:
    try:
        config = load_config()
        service = SystemdServiceManager(
            os.getenv("POHW_BITCOIN_PRESSURE_SYSTEMCTL_BIN", "systemctl"),
            dry_run=config.dry_run,
        )
        run_once(config, service)
    except Exception as exc:
        print(f"PoHW Bitcoin pressure guard failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
