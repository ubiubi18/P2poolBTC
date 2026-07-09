#!/usr/bin/env python3
"""Secret-safe PoHW host health and mining-readiness status.

The monitor intentionally treats Bitcoin RPC as optional. It always tries to
derive the latest Bitcoin height/progress/mode from debug.log first, then adds
bounded RPC probes when they respond quickly enough.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "pohw_idena_rpc"))

try:
    from idena_rpc_client_minimal import IdenaRPCClientMinimal, IdenaRPCError
except Exception:  # pragma: no cover - handled as unavailable at runtime
    IdenaRPCClientMinimal = None  # type: ignore[assignment]

    class IdenaRPCError(Exception):
        pass


DEFAULT_BITCOIN_DATADIR = Path("/mnt/ssd/bitcoin/bitcoin-core-mainnet")
DEFAULT_IDENA_DATADIR = Path("/mnt/ssd/idena/idena-data")
DEFAULT_IDENA_API_KEY_FILE = Path("/mnt/ssd/idena/idena-data/api.key")
DEFAULT_HEALTH_OUTPUT = Path("/mnt/ssd/pohw-p2pool/health/status.json")
DEFAULT_MOUNT = Path("/mnt/ssd")
DEFAULT_SERVICES = (
    "bitcoind-mainnet.service",
    "idena.service",
    "idena-reward-indexer.service",
    "idena-session-recorder.service",
    "pohw-gossip-mesh.service",
    "pohw-dashboard-api.service",
)
MAX_ERROR_CHARS = 320

UPDATE_TIP_RE = re.compile(
    r"^(?P<timestamp>\S+) UpdateTip: .* height=(?P<height>\d+) .* "
    r"date='(?P<block_time>[^']+)' progress=(?P<progress>[0-9.]+) "
    r"cache=(?P<cache_mib>[0-9.]+)MiB\((?P<cache_txo>\d+)txo\)"
)
BEST_CHAIN_RE = re.compile(
    r"Loaded best chain: .* height=(?P<height>\d+) .* progress=(?P<progress>[0-9.]+)"
)
UTXO_CACHE_RE = re.compile(r"\* Using (?P<cache_mib>[0-9.]+) MiB for in-memory UTXO set")
COINSTIP_CACHE_RE = re.compile(
    r"\[Chainstate \[(?P<chainstate>[^\]]+)\].* resized coinstip cache to "
    r"(?P<cache_mib>[0-9.]+) MiB"
)
IDENA_IPFS_PORT_RE = re.compile(r"Finish changing IPFS port\s+new=(?P<port>\d+)")
IDENA_LOOP_RE = re.compile(
    r"Start loop\s+round=(?P<round>\d+).*?"
    r"total-peers=(?P<total_peers>\d+)\s+"
    r"own-shard-peers=(?P<own_shard_peers>\d+).*?"
    r"online-nodes=(?P<online_nodes>\d+)\s+"
    r"network=(?P<network_size>\d+)"
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def scrub_text(value: str, limit: int = MAX_ERROR_CHARS) -> str:
    value = value.replace("\x00", "")
    value = re.sub(r"/Users/[^/\s]+", "<home>", value)
    value = re.sub(r"/home/[^/\s]+", "<home>", value)
    value = re.sub(r"([A-Za-z0-9+/]{32,}={0,2})", "<redacted>", value)
    value = re.sub(r"0x[a-fA-F0-9]{40}", "0x<redacted-address>", value)
    value = " ".join(value.split())
    if len(value) > limit:
        return value[: limit - 3] + "..."
    return value


def run_command(cmd: list[str], timeout: float) -> dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"status": "missing_command", "ok": False, "error": cmd[0]}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "ok": False, "error": f"timed out after {timeout:g}s"}
    if result.returncode == 0:
        return {"status": "ok", "ok": True, "stdout": result.stdout}
    return {
        "status": "error",
        "ok": False,
        "returnCode": result.returncode,
        "error": scrub_text(result.stderr or result.stdout),
    }


def reject_symlink_ancestors(path: Path) -> None:
    current = path.expanduser().absolute()
    for parent in [current, *current.parents]:
        if parent == parent.parent:
            break
        if parent.exists() and parent.is_symlink():
            raise RuntimeError(f"refusing symlinked path component: {parent}")


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path = path.expanduser()
    parent = path.parent
    reject_symlink_ancestors(parent)
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing to overwrite symlinked output file: {path}")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def parse_bitcoin_debug_log(path: Path, max_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    status: dict[str, Any] = {"available": False, "path": "debug.log"}
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                handle.readline()
            raw = handle.read(max_bytes)
    except OSError as exc:
        status.update({"status": "unavailable", "error": scrub_text(str(exc))})
        return status

    lines = raw.decode("utf-8", errors="replace").splitlines()
    status.update({"available": True, "status": "ok"})
    limited_index: int | None = None
    complete_index: int | None = None
    latest_tip: dict[str, Any] | None = None
    snapshot_height: int | None = None
    background_height: int | None = None
    coinstip_caches: dict[str, float] = {}

    for index, line in enumerate(lines):
        if "Running node in NODE_NETWORK_LIMITED mode" in line:
            limited_index = index
        if re.search(r"snapshot background .*completed|background sync .*completed", line, re.I):
            complete_index = index
        match = UPDATE_TIP_RE.search(line)
        if match:
            latest_tip = {
                "timestamp": match.group("timestamp"),
                "height": int(match.group("height")),
                "blockTime": match.group("block_time"),
                "verificationProgress": float(match.group("progress")),
                "cacheMiB": float(match.group("cache_mib")),
                "cacheTxo": int(match.group("cache_txo")),
            }
            continue
        match = BEST_CHAIN_RE.search(line)
        if match and "Chainstate [snapshot]" in line:
            snapshot_height = int(match.group("height"))
        elif match and "Chainstate [ibd]" in line:
            background_height = int(match.group("height"))
        match = UTXO_CACHE_RE.search(line)
        if match:
            status["inMemoryUtxoCacheMiB"] = float(match.group("cache_mib"))
            continue
        match = COINSTIP_CACHE_RE.search(line)
        if match:
            coinstip_caches[match.group("chainstate")] = float(match.group("cache_mib"))

    if latest_tip:
        status["latestTip"] = latest_tip
    if snapshot_height is not None:
        status["snapshotHeight"] = snapshot_height
    if background_height is not None:
        status["backgroundValidationHeight"] = background_height
    if coinstip_caches:
        status["coinstipCacheMiB"] = coinstip_caches
    status["nodeNetworkLimited"] = limited_index is not None and (
        complete_index is None or limited_index > complete_index
    )
    return status


def probe_services(services: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for service in services:
        probe = run_command(["systemctl", "is-active", service], timeout=5)
        stdout = str(probe.get("stdout", "")).strip()
        result[service] = {
            "active": probe.get("ok") is True and stdout == "active",
            "state": stdout or probe.get("status", "unknown"),
        }
    return result


def probe_bitcoin_rpc(datadir: Path, bitcoin_cli: str, timeout_seconds: int) -> dict[str, Any]:
    probe = run_command(
        [
            bitcoin_cli,
            f"-datadir={datadir}",
            f"-rpcclienttimeout={timeout_seconds}",
            "getblockchaininfo",
        ],
        timeout=timeout_seconds + 2,
    )
    if not probe.get("ok"):
        return {"status": probe["status"], "ok": False, "error": probe.get("error", "")}
    try:
        payload = json.loads(str(probe.get("stdout", "")))
    except json.JSONDecodeError as exc:
        return {"status": "invalid_json", "ok": False, "error": scrub_text(str(exc))}
    return {
        "status": "ok",
        "ok": True,
        "blocks": int(payload.get("blocks") or 0),
        "headers": int(payload.get("headers") or 0),
        "initialBlockDownload": bool(payload.get("initialblockdownload")),
        "verificationProgress": float(payload.get("verificationprogress") or 0.0),
        "chain": payload.get("chain"),
    }


def probe_getblocktemplate(
    datadir: Path,
    bitcoin_cli: str,
    timeout_seconds: int,
    *,
    enabled: bool,
    bitcoin_rpc: dict[str, Any],
    node_network_limited: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"status": "disabled", "ok": False}
    if not bitcoin_rpc.get("ok"):
        return {"status": "skipped", "ok": False, "reason": "bitcoin_rpc_unavailable"}
    if bitcoin_rpc.get("initialBlockDownload"):
        return {"status": "skipped", "ok": False, "reason": "bitcoin_initial_block_download"}
    if node_network_limited:
        return {"status": "skipped", "ok": False, "reason": "bitcoin_node_network_limited"}
    probe = run_command(
        [
            bitcoin_cli,
            f"-datadir={datadir}",
            f"-rpcclienttimeout={timeout_seconds}",
            "getblocktemplate",
            '{"rules":["segwit"]}',
        ],
        timeout=timeout_seconds + 2,
    )
    if probe.get("ok"):
        return {"status": "ok", "ok": True}
    return {"status": probe["status"], "ok": False, "error": probe.get("error", "")}


def validate_loopback_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Idena RPC URL must be http(s) with a host")
    host = parsed.hostname.lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Idena RPC URL must be loopback")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Idena RPC URL must not include userinfo, query, or fragment data")
    return url


def probe_idena_rpc(url: str, api_key_file: Path, timeout_seconds: int) -> dict[str, Any]:
    if IdenaRPCClientMinimal is None:
        return {"status": "missing_client", "ok": False}
    try:
        client = IdenaRPCClientMinimal(
            url=validate_loopback_url(url),
            api_key_file=str(api_key_file),
            timeout=timeout_seconds,
        )
        sync = client.call("bcn_syncing")
    except (IdenaRPCError, RuntimeError, OSError, ValueError) as exc:
        return {"status": "error", "ok": False, "error": scrub_text(str(exc))}
    if not isinstance(sync, dict):
        return {"status": "invalid_response", "ok": False}
    current = int(sync.get("currentBlock") or 0)
    highest = int(sync.get("highestBlock") or 0)
    syncing = bool(sync.get("syncing")) and not (highest > 0 and current >= highest)
    wrong_time = bool(sync.get("wrongTime"))
    return {
        "status": "ok",
        "ok": True,
        "syncing": syncing,
        "wrongTime": wrong_time,
        "currentBlock": current,
        "highestBlock": highest,
        "ready": not syncing and not wrong_time,
    }


def read_file_tail(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(size - max_bytes)
            handle.readline()
        return handle.read(max_bytes).decode("utf-8", errors="replace")


def probe_idena_p2p(datadir: Path, min_peers: int, max_log_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    status: dict[str, Any] = {"status": "ok", "ok": True, "warnings": []}
    config_path = datadir / "config.json"
    log_path = datadir / "logs" / "output.log"
    configured_port: int | None = None
    active_port: int | None = None
    latest_loop: dict[str, int] | None = None

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        configured_raw = (config.get("IpfsConf") or {}).get("IpfsPort")
        if configured_raw is not None:
            configured_port = int(configured_raw)
            active_port = configured_port
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        status["configStatus"] = "error"
        status["configError"] = scrub_text(str(exc))

    try:
        for line in read_file_tail(log_path, max_log_bytes).splitlines():
            port_match = IDENA_IPFS_PORT_RE.search(line)
            if port_match:
                active_port = int(port_match.group("port"))
            loop_match = IDENA_LOOP_RE.search(line)
            if loop_match:
                latest_loop = {key: int(value) for key, value in loop_match.groupdict().items()}
    except OSError as exc:
        status["logStatus"] = "unavailable"
        status["logError"] = scrub_text(str(exc))

    if configured_port is not None:
        status["configuredIpfsPort"] = configured_port
    if active_port is not None:
        status["activeIpfsPort"] = active_port
    if latest_loop:
        status["latestLoop"] = latest_loop

    warnings: list[str] = []
    if configured_port is not None and active_port is not None and active_port != configured_port:
        warnings.append("idena_ipfs_port_drift")
    if min_peers > 0 and latest_loop and latest_loop["total_peers"] < min_peers:
        warnings.append("idena_low_peer_count")

    status["warnings"] = warnings
    status["ok"] = not warnings
    if warnings:
        status["status"] = "warning"
    return status


def probe_disk(mount_path: Path) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(mount_path)
    except OSError as exc:
        return {"status": "error", "error": scrub_text(str(exc))}
    return {
        "status": "ok",
        "mount": str(mount_path),
        "totalBytes": usage.total,
        "usedBytes": usage.used,
        "freeBytes": usage.free,
        "usedPercent": round((usage.used / usage.total) * 100, 2) if usage.total else 0,
    }


def base_device_name(device: str) -> str:
    name = Path(device).name
    if name.startswith("nvme") or name.startswith("mmcblk"):
        return re.sub(r"p\d+$", "", name)
    return re.sub(r"\d+$", "", name)


def mount_source(mount_path: Path) -> str:
    probe = run_command(["findmnt", "-no", "SOURCE", str(mount_path)], timeout=2)
    if probe.get("ok"):
        return str(probe.get("stdout", "")).strip()
    return ""


def parse_iostat(output: str, device: str) -> dict[str, Any]:
    cpu_iowait: float | None = None
    target = base_device_name(device)
    device_status: dict[str, Any] | None = None
    lines = [line for line in output.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        if line.startswith("avg-cpu:") and index + 1 < len(lines):
            values = lines[index + 1].split()
            if len(values) >= 4:
                try:
                    cpu_iowait = float(values[3])
                except ValueError:
                    pass
        if target and line.split()[0:1] == [target]:
            parts = line.split()
            if len(parts) >= 23:
                try:
                    device_status = {
                        "device": target,
                        "readKiBPerSecond": float(parts[2]),
                        "writeKiBPerSecond": float(parts[8]),
                        "readAwaitMs": float(parts[5]),
                        "writeAwaitMs": float(parts[11]),
                        "utilPercent": float(parts[22]),
                    }
                except ValueError:
                    device_status = {"device": target, "status": "parse_error"}
    status: dict[str, Any] = {"status": "ok"}
    if cpu_iowait is not None:
        status["cpuIowaitPercent"] = cpu_iowait
    if device_status:
        status.update(device_status)
    elif target:
        status.update({"device": target, "status": "device_not_found"})
    return status


def probe_iostat(mount_path: Path, timeout_seconds: int, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"status": "disabled"}
    source = mount_source(mount_path)
    if not source:
        return {"status": "mount_source_unavailable"}
    probe = run_command(["iostat", "-xz", "1", "2"], timeout=timeout_seconds)
    if not probe.get("ok"):
        return {"status": probe["status"], "error": probe.get("error", "")}
    status = parse_iostat(str(probe.get("stdout", "")), source)
    status["source"] = source
    return status


def compute_readiness(
    services: dict[str, Any],
    bitcoin_log: dict[str, Any],
    bitcoin_rpc: dict[str, Any],
    template: dict[str, Any],
    idena_rpc: dict[str, Any],
    idena_p2p: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    for service in ("bitcoind-mainnet.service", "idena.service", "idena-reward-indexer.service"):
        if service in services and not services[service].get("active"):
            blockers.append(f"{service}:{services[service].get('state', 'inactive')}")
    if not idena_rpc.get("ready"):
        blockers.append("idena_not_ready")
    if bitcoin_log.get("nodeNetworkLimited"):
        blockers.append("bitcoin_node_network_limited")
    if not bitcoin_rpc.get("ok"):
        blockers.append(f"bitcoin_rpc_{bitcoin_rpc.get('status', 'unavailable')}")
    elif bitcoin_rpc.get("initialBlockDownload"):
        blockers.append("bitcoin_initial_block_download")
    if not template.get("ok"):
        blockers.append(f"getblocktemplate_{template.get('status', 'unavailable')}")
    p2p_warnings = idena_p2p.get("warnings")
    if isinstance(p2p_warnings, list):
        warnings.extend(str(item) for item in p2p_warnings)
    return {"miningReady": not blockers, "blockers": blockers, "warnings": warnings}


def build_status(args: argparse.Namespace) -> dict[str, Any]:
    bitcoin_datadir = Path(args.bitcoin_datadir)
    mount_path = Path(args.mount_path)
    services = probe_services(tuple(args.service))
    bitcoin_log = parse_bitcoin_debug_log(bitcoin_datadir / "debug.log")
    bitcoin_rpc = probe_bitcoin_rpc(bitcoin_datadir, args.bitcoin_cli, args.bitcoin_rpc_timeout)
    template = probe_getblocktemplate(
        bitcoin_datadir,
        args.bitcoin_cli,
        args.bitcoin_rpc_timeout,
        enabled=not args.skip_getblocktemplate,
        bitcoin_rpc=bitcoin_rpc,
        node_network_limited=bool(bitcoin_log.get("nodeNetworkLimited")),
    )
    idena_rpc = probe_idena_rpc(args.idena_rpc_url, Path(args.idena_api_key_file), args.idena_rpc_timeout)
    idena_p2p = probe_idena_p2p(Path(args.idena_datadir), args.idena_min_peers)
    disk = probe_disk(mount_path)
    io_status = probe_iostat(mount_path, args.iostat_timeout, enabled=not args.skip_iostat)
    readiness = compute_readiness(services, bitcoin_log, bitcoin_rpc, template, idena_rpc, idena_p2p)
    return {
        "generatedAt": utc_now(),
        "status": "ready_for_mining" if readiness["miningReady"] else "waiting",
        "readiness": readiness,
        "services": services,
        "bitcoin": {
            "debugLog": bitcoin_log,
            "rpc": bitcoin_rpc,
            "getblocktemplate": template,
        },
        "idena": {"rpc": idena_rpc, "p2p": idena_p2p},
        "disk": disk,
        "io": io_status,
    }


def human_bytes(value: int | float | None) -> str:
    if value is None:
        return "unknown"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TiB"


def summary_lines(status: dict[str, Any]) -> list[str]:
    readiness = status.get("readiness", {})
    bitcoin = status.get("bitcoin", {})
    blog = bitcoin.get("debugLog", {})
    brpc = bitcoin.get("rpc", {})
    template = bitcoin.get("getblocktemplate", {})
    idena_status = status.get("idena", {})
    idena = idena_status.get("rpc", {})
    idena_p2p = idena_status.get("p2p", {})
    disk = status.get("disk", {})
    io_status = status.get("io", {})
    tip = blog.get("latestTip", {})
    blockers = readiness.get("blockers") or []
    warnings = readiness.get("warnings") or []
    lines = [f"PoHW health: {status.get('status', 'unknown')}"]
    lines.append(
        "Bitcoin: "
        f"height={tip.get('height', blog.get('snapshotHeight', 'unknown'))} "
        f"progress={float(tip.get('verificationProgress', brpc.get('verificationProgress', 0.0))) * 100:.4f}% "
        f"mode={'NODE_NETWORK_LIMITED' if blog.get('nodeNetworkLimited') else 'normal'} "
        f"rpc={brpc.get('status', 'unknown')} "
        f"getblocktemplate={template.get('status', 'unknown')}"
    )
    idena_line = (
        "Idena: "
        f"status={idena.get('status', 'unknown')} "
        f"ready={idena.get('ready', False)} "
        f"height={idena.get('currentBlock', 'unknown')}"
    )
    if idena_p2p:
        latest_loop = idena_p2p.get("latestLoop") or {}
        idena_line += (
            f" p2p={idena_p2p.get('status', 'unknown')} "
            f"port={idena_p2p.get('activeIpfsPort', 'unknown')}"
            f"(config={idena_p2p.get('configuredIpfsPort', 'unknown')}) "
            f"peers={latest_loop.get('total_peers', 'unknown')}"
        )
    lines.append(idena_line)
    if disk.get("status") == "ok":
        lines.append(
            f"Disk {disk.get('mount')}: free={human_bytes(disk.get('freeBytes'))} "
            f"used={disk.get('usedPercent')}%"
        )
    if io_status.get("status") == "ok":
        lines.append(
            "I/O: "
            f"device={io_status.get('device', 'unknown')} "
            f"iowait={io_status.get('cpuIowaitPercent', 'unknown')}% "
            f"util={io_status.get('utilPercent', 'unknown')}%"
        )
    if blockers:
        lines.append("Readiness blockers: " + ", ".join(str(item) for item in blockers))
    if warnings:
        lines.append("Warnings: " + ", ".join(str(item) for item in warnings))
    return lines


def read_status_file(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"refusing symlinked health status file: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError(f"health status file is too large: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("health status must be a JSON object")
    return data


def check_mining_ready(path: Path, max_age_seconds: int) -> int:
    try:
        data = read_status_file(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"PoHW health status is unavailable: {scrub_text(str(exc))}", file=sys.stderr)
        return 1
    generated = parse_utc(str(data.get("generatedAt", "")))
    if generated is None:
        print("PoHW health status has no valid generatedAt timestamp", file=sys.stderr)
        return 1
    age = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds()
    if age > max_age_seconds:
        print(
            f"PoHW health status is stale: age={int(age)}s max={max_age_seconds}s",
            file=sys.stderr,
        )
        return 1
    readiness = data.get("readiness")
    if isinstance(readiness, dict) and readiness.get("miningReady") is True:
        print("PoHW health is mining-ready.")
        return 0
    blockers = readiness.get("blockers") if isinstance(readiness, dict) else []
    if not isinstance(blockers, list):
        blockers = []
    print(
        "PoHW health is not mining-ready: "
        + (", ".join(str(item) for item in blockers) if blockers else "unknown blocker"),
        file=sys.stderr,
    )
    return 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "summary"), default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bitcoin-datadir", default=os.getenv("POHW_BITCOIN_DATADIR", str(DEFAULT_BITCOIN_DATADIR)))
    parser.add_argument("--bitcoin-cli", default=os.getenv("POHW_BITCOIN_CLI", "bitcoin-cli"))
    parser.add_argument("--bitcoin-rpc-timeout", type=int, default=int(os.getenv("POHW_HEALTH_BITCOIN_RPC_TIMEOUT", "5")))
    parser.add_argument("--skip-getblocktemplate", action="store_true")
    parser.add_argument("--idena-datadir", default=os.getenv("POHW_IDENA_DATADIR", str(DEFAULT_IDENA_DATADIR)))
    parser.add_argument("--idena-rpc-url", default=os.getenv("IDENA_RPC_URL", "http://127.0.0.1:9009"))
    parser.add_argument("--idena-api-key-file", default=os.getenv("IDENA_API_KEY_FILE", str(DEFAULT_IDENA_API_KEY_FILE)))
    parser.add_argument("--idena-rpc-timeout", type=int, default=int(os.getenv("POHW_HEALTH_IDENA_RPC_TIMEOUT", "5")))
    parser.add_argument("--idena-min-peers", type=int, default=int(os.getenv("POHW_HEALTH_IDENA_MIN_PEERS", "3")))
    parser.add_argument("--mount-path", default=os.getenv("POHW_HEALTH_MOUNT_PATH", str(DEFAULT_MOUNT)))
    parser.add_argument("--skip-iostat", action="store_true")
    parser.add_argument("--iostat-timeout", type=int, default=int(os.getenv("POHW_HEALTH_IOSTAT_TIMEOUT", "5")))
    parser.add_argument("--service", action="append", default=list(DEFAULT_SERVICES))
    parser.add_argument("--check-mining-ready", action="store_true")
    parser.add_argument("--status-file", type=Path, default=DEFAULT_HEALTH_OUTPUT)
    parser.add_argument("--max-age-seconds", type=int, default=int(os.getenv("POHW_HEALTH_MAX_AGE_SECONDS", "180")))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.check_mining_ready:
        return check_mining_ready(args.status_file, args.max_age_seconds)
    status = build_status(args)
    if args.output:
        write_json_atomic(args.output, status)
    if args.format == "json":
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print("\n".join(summary_lines(status)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
