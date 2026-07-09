#!/usr/bin/env python3
"""Temporarily pause Bitcoin Core when Idena validation needs Pi resources."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

SCRIPT_DIR = Path(__file__).resolve().parent
RUNTIME_ROOT = SCRIPT_DIR if (SCRIPT_DIR / "pohw_idena_rpc").is_dir() else SCRIPT_DIR.parent
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from pohw_idena_rpc.idena_rpc_client_minimal import (  # noqa: E402
    IdenaRPCClientMinimal,
    IdenaRPCError,
)

DEFAULT_PERIOD_KEYWORDS = (
    "flip",
    "short",
    "long",
    "validation",
)


@dataclass(frozen=True)
class GuardConfig:
    state_dir: Path
    status_file: Path
    marker_file: Path
    bitcoin_service: str
    lead_seconds: int
    cooldown_seconds: int
    period_keywords: tuple[str, ...]
    restore_bitcoin: bool
    force: bool
    dry_run: bool


class IdenaClient(Protocol):
    def call(self, method: str, params: list[Any] | None = None) -> Any:
        ...


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


def parse_keywords(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_PERIOD_KEYWORDS
    return tuple(part.strip().lower() for part in raw.replace(",", " ").split() if part.strip())


def load_config(env: dict[str, str] | None = None) -> GuardConfig:
    env = env or os.environ
    state_dir = Path(env.get("POHW_IDENA_PRIORITY_STATE_DIR", "/var/lib/pohw/idena-priority"))
    return GuardConfig(
        state_dir=state_dir,
        status_file=Path(env.get("POHW_IDENA_PRIORITY_STATUS_FILE", str(state_dir / "status.json"))),
        marker_file=Path(env.get("POHW_IDENA_PRIORITY_MARKER_FILE", str(state_dir / "bitcoin-paused.json"))),
        bitcoin_service=env.get("POHW_IDENA_PRIORITY_BITCOIN_SERVICE", "bitcoind-mainnet.service"),
        lead_seconds=parse_nonnegative_int(
            env.get("POHW_IDENA_PRIORITY_LEAD_SECONDS"),
            "POHW_IDENA_PRIORITY_LEAD_SECONDS",
            default=3600,
        ),
        cooldown_seconds=parse_nonnegative_int(
            env.get("POHW_IDENA_PRIORITY_COOLDOWN_SECONDS"),
            "POHW_IDENA_PRIORITY_COOLDOWN_SECONDS",
            default=1800,
        ),
        period_keywords=parse_keywords(env.get("POHW_IDENA_PRIORITY_PERIOD_KEYWORDS")),
        restore_bitcoin=parse_bool(env.get("POHW_IDENA_PRIORITY_RESTORE_BITCOIN"), default=True),
        force=parse_bool(env.get("POHW_IDENA_PRIORITY_FORCE"), default=False),
        dry_run=parse_bool(env.get("POHW_IDENA_PRIORITY_DRY_RUN"), default=False),
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


def protection_reasons(config: GuardConfig, epoch: dict[str, Any], now: datetime) -> list[str]:
    reasons: list[str] = []
    if config.force:
        reasons.append("forced")

    period = str(epoch.get("currentPeriod") or "").strip()
    period_lower = period.lower()
    if period_lower and any(keyword in period_lower for keyword in config.period_keywords):
        reasons.append(f"current_period:{period}")

    next_validation = parse_datetime(epoch.get("nextValidation"))
    if next_validation is not None:
        seconds_until = int((next_validation - now).total_seconds())
        if -config.cooldown_seconds <= seconds_until <= config.lead_seconds:
            reasons.append(f"validation_window:{seconds_until}s")

    return reasons


def fetch_epoch(client: IdenaClient) -> dict[str, Any]:
    result = client.call("dna_epoch", [])
    if not isinstance(result, dict):
        raise IdenaRPCError(f"unexpected dna_epoch result: {type(result)}")
    return result


def stopped_marker(now: datetime, *, managed_stop: bool, reasons: list[str], epoch: dict[str, Any]) -> dict[str, Any]:
    return {
        "managedStop": managed_stop,
        "reasons": reasons,
        "stoppedAt": iso_utc(now),
        "lastProtectedAt": iso_utc(now),
        "epoch": {
            "epoch": epoch.get("epoch"),
            "currentPeriod": epoch.get("currentPeriod"),
            "nextValidation": epoch.get("nextValidation"),
        },
    }


def update_marker(marker: dict[str, Any], now: datetime, reasons: list[str], epoch: dict[str, Any]) -> dict[str, Any]:
    updated = dict(marker)
    updated["lastProtectedAt"] = iso_utc(now)
    updated["reasons"] = reasons
    updated["epoch"] = {
        "epoch": epoch.get("epoch"),
        "currentPeriod": epoch.get("currentPeriod"),
        "nextValidation": epoch.get("nextValidation"),
    }
    return updated


def run_once(
    config: GuardConfig,
    client: IdenaClient,
    service: ServiceManager,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    ensure_private_dir(config.state_dir)
    marker = read_json_file(config.marker_file)

    try:
        epoch = fetch_epoch(client)
        rpc_error = ""
    except Exception as exc:
        epoch = {}
        rpc_error = str(exc)

    bitcoin_active = service.is_active(config.bitcoin_service)
    reasons = protection_reasons(config, epoch, now) if not rpc_error else []
    should_protect = bool(reasons)
    action = "none"
    detail = ""

    if should_protect:
        if bitcoin_active:
            service.stop(config.bitcoin_service)
            marker = stopped_marker(now, managed_stop=True, reasons=reasons, epoch=epoch)
            write_json_file(config.marker_file, marker)
            action = "stopped_bitcoin"
            detail = "Bitcoin Core stopped to give Idena validation priority."
        elif marker is None:
            marker = stopped_marker(now, managed_stop=False, reasons=reasons, epoch=epoch)
            write_json_file(config.marker_file, marker)
            action = "holding_existing_stop"
            detail = "Bitcoin Core was already inactive; guard will not restart it later."
        else:
            marker = update_marker(marker, now, reasons, epoch)
            write_json_file(config.marker_file, marker)
            action = "holding_bitcoin"
            detail = "Idena validation priority window remains active."
    elif marker is not None:
        last_protected = parse_datetime(marker.get("lastProtectedAt")) or now
        elapsed = int((now - last_protected).total_seconds())
        cooldown_remaining = max(config.cooldown_seconds - elapsed, 0)
        managed_stop = bool(marker.get("managedStop"))
        if rpc_error:
            action = "holding_on_rpc_error"
            detail = "Idena RPC unavailable while a guard marker exists; keeping current Bitcoin state."
        elif cooldown_remaining > 0:
            action = "cooldown"
            detail = f"Waiting {cooldown_remaining}s before restoring Bitcoin Core."
        elif managed_stop and config.restore_bitcoin:
            if not bitcoin_active:
                service.start(config.bitcoin_service)
            config.marker_file.unlink(missing_ok=True)
            marker = None
            action = "started_bitcoin"
            detail = "Bitcoin Core restarted after Idena priority cooldown."
        else:
            config.marker_file.unlink(missing_ok=True)
            marker = None
            action = "cleared_marker"
            detail = "Guard marker cleared; Bitcoin was not stopped by this guard."
    elif rpc_error:
        action = "idena_rpc_error"
        detail = "Idena RPC unavailable; no existing guard marker, so Bitcoin state was not changed."
    else:
        action = "idle"
        detail = "No Idena validation priority window detected."

    status = {
        "generatedAt": iso_utc(now),
        "status": action,
        "detail": detail,
        "bitcoinService": config.bitcoin_service,
        "bitcoinWasActive": bitcoin_active,
        "protecting": should_protect or marker is not None,
        "reasons": reasons,
        "idenaRpcError": rpc_error,
        "epoch": {
            "epoch": epoch.get("epoch"),
            "currentPeriod": epoch.get("currentPeriod"),
            "nextValidation": epoch.get("nextValidation"),
        },
        "leadSeconds": config.lead_seconds,
        "cooldownSeconds": config.cooldown_seconds,
        "dryRun": config.dry_run,
    }
    write_json_file(config.status_file, status)
    print(f"PoHW Idena priority guard: {action} - {detail}")
    return status


def main() -> int:
    try:
        config = load_config()
        timeout = parse_nonnegative_int(
            os.getenv("POHW_IDENA_PRIORITY_RPC_TIMEOUT_SECONDS"),
            "POHW_IDENA_PRIORITY_RPC_TIMEOUT_SECONDS",
            default=8,
        )
        client = IdenaRPCClientMinimal(
            url=os.getenv("IDENA_RPC_URL", "http://127.0.0.1:9009"),
            api_key_file=os.getenv("IDENA_API_KEY_FILE", "/mnt/ssd/idena/idena-data/api.key"),
            timeout=max(timeout, 1),
        )
        service = SystemdServiceManager(
            os.getenv("POHW_IDENA_PRIORITY_SYSTEMCTL_BIN", "systemctl"),
            dry_run=config.dry_run,
        )
        run_once(config, client, service)
    except Exception as exc:
        print(f"PoHW Idena priority guard failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
