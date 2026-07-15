#!/usr/bin/env python3
"""Audit or atomically apply the dedicated PoHW Debian nftables policy."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


TABLE_FAMILY = "inet"
TABLE_NAME = "pohw_host_firewall"
APPLY_ACKNOWLEDGEMENT = "I_UNDERSTAND_THIS_REPLACES_THE_POHW_FIREWALL_TABLE"
COMMAND_TIMEOUT_SECONDS = 10
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
TRUSTED_ROOT_NFT_BIN = Path("/usr/sbin/nft")
TRUSTED_ROOT_SS_BIN = Path("/usr/bin/ss")
TRUSTED_ROOT_CONFIG = Path("/etc/pohw/host-firewall.json")
CONFIG_SCHEMA = "pohw-host-firewall-config/v1"
DEFAULT_SENSITIVE_PORTS = {
    3002: "explorer-api",
    3030: "idena-web-ui",
    3333: "stratum",
    50001: "electrum-api",
    5176: "dashboard-ui",
    8332: "bitcoin-mainnet-rpc",
    9009: "idena-rpc",
    19009: "idena-rpc-proxy",
    40407: "dashboard-api",
    40408: "fork-control-rpc",
    40414: "bitcoin-fork-rpc",
}


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    detail: str
    port: int | None = None
    service: str | None = None


@dataclass(frozen=True)
class Listener:
    port: int
    scope: str


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(binary: str, arguments: list[str], label: str) -> CommandResult:
    try:
        completed = subprocess.run(
            [binary, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise FirewallError(
            f"{label} is unavailable; install it explicitly before using this tool"
        ) from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FirewallError(f"{label} could not be executed safely") from error

    if (
        len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES
        or len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise FirewallError(f"{label} output exceeds the safety limit")
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout.decode("utf-8", errors="replace"),
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )


def parse_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be a decimal integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def normalized_ports(values: Iterable[int]) -> tuple[int, ...]:
    return tuple(sorted(set(values)))


def validate_privileged_binary(
    configured: str, *, expected: Path, label: str, euid: int
) -> None:
    """Prevent sudo callers from selecting an attacker-controlled executable."""
    if euid != 0:
        return
    configured_path = Path(configured)
    if configured_path != expected:
        raise FirewallError(
            f"root execution requires the trusted {label} path {expected}"
        )
    try:
        resolved = expected.resolve(strict=True)
        executable_stat = resolved.stat()
    except OSError as error:
        raise FirewallError(f"trusted {label} executable is unavailable") from error
    if not stat.S_ISREG(executable_stat.st_mode):
        raise FirewallError(f"trusted {label} path is not a regular file")
    if executable_stat.st_uid != 0 or executable_stat.st_mode & 0o022:
        raise FirewallError(
            f"trusted {label} executable must be root-owned and not group/other writable"
        )
    for parent in (resolved.parent, *resolved.parents):
        try:
            parent_stat = parent.stat()
        except OSError as error:
            raise FirewallError(f"trusted {label} path cannot be verified") from error
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise FirewallError(
                f"trusted {label} executable has an unsafe parent directory"
            )
        if parent == parent.parent:
            break


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FirewallError(f"duplicate firewall configuration key: {key}")
        result[key] = value
    return result


def _config_ports(value: Any, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise FirewallError(f"{label} must be an array of TCP ports")
    ports: list[int] = []
    for port in value:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            raise FirewallError(f"{label} contains an invalid TCP port")
        ports.append(port)
    if len(ports) != len(set(ports)):
        raise FirewallError(f"{label} contains a duplicate TCP port")
    return normalized_ports(ports)


def load_config(path: Path, *, euid: int) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    if euid == 0 and path != TRUSTED_ROOT_CONFIG:
        raise FirewallError(
            f"root execution requires the trusted configuration path {TRUSTED_ROOT_CONFIG}"
        )
    try:
        before = path.lstat()
    except OSError as error:
        raise FirewallError("firewall configuration is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FirewallError("firewall configuration must be a regular non-symlink file")
    if before.st_size > MAX_CONFIG_BYTES:
        raise FirewallError("firewall configuration exceeds the size limit")
    if euid == 0:
        if before.st_uid != 0 or before.st_mode & 0o022:
            raise FirewallError(
                "firewall configuration must be root-owned and not group/other writable"
            )
        resolved_parent = path.parent.resolve(strict=True)
        for parent in (resolved_parent, *resolved_parent.parents):
            parent_stat = parent.stat()
            if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
                raise FirewallError("firewall configuration has an unsafe parent directory")
            if parent == parent.parent:
                break
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            remaining = MAX_CONFIG_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise FirewallError("firewall configuration could not be read safely") from error
    identity = lambda metadata: (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    raw = b"".join(chunks)
    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise FirewallError("firewall configuration changed while being read")
    if len(raw) != opened.st_size or len(raw) > MAX_CONFIG_BYTES:
        raise FirewallError("firewall configuration size changed while being read")
    try:
        config = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FirewallError("firewall configuration is not valid JSON") from error
    expected_keys = {
        "schema",
        "publicSshTcpPorts",
        "publicP2pTcpPorts",
        "sensitiveTcpPorts",
    }
    if not isinstance(config, dict) or set(config) != expected_keys:
        raise FirewallError("firewall configuration fields do not match the schema")
    if config.get("schema") != CONFIG_SCHEMA:
        raise FirewallError("unsupported firewall configuration schema")
    return (
        _config_ports(config["publicSshTcpPorts"], "publicSshTcpPorts"),
        _config_ports(config["publicP2pTcpPorts"], "publicP2pTcpPorts"),
        _config_ports(config["sensitiveTcpPorts"], "sensitiveTcpPorts"),
    )


def nft_set(values: tuple[int, ...]) -> str:
    if not values:
        raise FirewallError("an empty nftables port set cannot be rendered")
    return "{ " + ", ".join(str(value) for value in values) + " }"


def expected_rule_tokens(
    ssh_ports: tuple[int, ...], public_p2p_ports: tuple[int, ...]
) -> dict[str, set[str]]:
    expected = {
        "pohw:accept-loopback": {"iifname", "lo", "accept"},
        "pohw:accept-tailscale": {"iifname", "tailscale0", "accept"},
        "pohw:drop-invalid": {"state", "invalid", "drop"},
        "pohw:accept-established-related": {
            "state",
            "established",
            "related",
            "accept",
        },
        "pohw:accept-icmp": {"icmp", "accept"},
        "pohw:accept-icmpv6": {"ipv6-icmp", "accept"},
        "pohw:drop-all-other-input": {"drop"},
    }
    if ssh_ports:
        expected["pohw:accept-ssh"] = {
            "tcp",
            "dport",
            "accept",
            *map(str, ssh_ports),
        }
    if public_p2p_ports:
        expected["pohw:accept-public-p2p"] = {
            "tcp",
            "dport",
            "accept",
            *map(str, public_p2p_ports),
        }
    return expected


def render_ruleset(
    *,
    table_exists: bool,
    ssh_ports: tuple[int, ...],
    public_p2p_ports: tuple[int, ...],
) -> str:
    lines = [
        "# Generated by pohw-host-firewall.py; do not add addresses or secrets.",
    ]
    if table_exists:
        lines.append(f"delete table {TABLE_FAMILY} {TABLE_NAME}")
    lines.extend(
        [
            f"table {TABLE_FAMILY} {TABLE_NAME} {{",
            '  comment "Managed by pohw-host-firewall.py schema v1"',
            "  chain input {",
            "    type filter hook input priority -10; policy drop;",
            '    iifname "lo" counter accept comment "pohw:accept-loopback"',
            '    ct state invalid counter drop comment "pohw:drop-invalid"',
            "    ct state { established, related } counter accept "
            'comment "pohw:accept-established-related"',
            '    iifname "tailscale0" counter accept comment "pohw:accept-tailscale"',
            '    meta l4proto icmp counter accept comment "pohw:accept-icmp"',
            "    meta l4proto ipv6-icmp counter accept "
            'comment "pohw:accept-icmpv6"',
        ]
    )
    if ssh_ports:
        lines.append(
            f"    tcp dport {nft_set(ssh_ports)} ct state new counter accept "
            'comment "pohw:accept-ssh"'
        )
    if public_p2p_ports:
        lines.append(
            f"    tcp dport {nft_set(public_p2p_ports)} ct state new counter accept "
            'comment "pohw:accept-public-p2p"'
        )
    lines.extend(
        [
            '    counter drop comment "pohw:drop-all-other-input"',
            "  }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def parse_json_output(output: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise FirewallError(f"{label} did not return valid JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("nftables"), list):
        raise FirewallError(f"{label} returned an unexpected JSON structure")
    return value


def table_exists(nft_bin: str) -> bool:
    result = run_command(
        nft_bin, ["--json", "--numeric", "list", "tables"], "nftables"
    )
    if result.returncode != 0:
        raise FirewallError("nftables table inventory failed; refusing to assume state")
    payload = parse_json_output(result.stdout, "nftables table inventory")
    for entry in payload["nftables"]:
        if not isinstance(entry, dict):
            continue
        table = entry.get("table")
        if not isinstance(table, dict):
            continue
        if table.get("family") == TABLE_FAMILY and table.get("name") == TABLE_NAME:
            return True
    return False


def flatten_json_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            tokens.add(str(key))
            tokens.update(flatten_json_tokens(item))
    elif isinstance(value, list):
        for item in value:
            tokens.update(flatten_json_tokens(item))
    elif value is not None:
        tokens.add(str(value))
    return tokens


def extract_tcp_dports(rule: dict[str, Any]) -> set[int] | None:
    expressions = rule.get("expr")
    if not isinstance(expressions, list):
        return None
    matches: list[set[int]] = []
    for expression in expressions:
        if not isinstance(expression, dict):
            continue
        match = expression.get("match")
        if not isinstance(match, dict):
            continue
        left = match.get("left")
        if not isinstance(left, dict):
            continue
        payload = left.get("payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("protocol") != "tcp" or payload.get("field") != "dport":
            continue
        right = match.get("right")
        if isinstance(right, int) and not isinstance(right, bool):
            matches.append({right})
            continue
        if isinstance(right, dict) and isinstance(right.get("set"), list):
            values = right["set"]
            if all(isinstance(value, int) and not isinstance(value, bool) for value in values):
                matches.append(set(values))
                continue
        return None
    if len(matches) != 1:
        return None
    return matches[0]


def audit_managed_table(
    nft_bin: str,
    *,
    present: bool,
    ssh_ports: tuple[int, ...],
    public_p2p_ports: tuple[int, ...],
) -> list[Finding]:
    if not present:
        return [
            Finding(
                code="managed_table_missing",
                severity="critical",
                detail="the dedicated input firewall table is not loaded",
            )
        ]

    result = run_command(
        nft_bin,
        ["--json", "--numeric", "list", "table", TABLE_FAMILY, TABLE_NAME],
        "managed nftables table",
    )
    if result.returncode != 0:
        raise FirewallError("the managed nftables table could not be inspected")
    payload = parse_json_output(result.stdout, "managed nftables table")
    entries = payload["nftables"]

    chain = None
    rules: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        candidate_chain = entry.get("chain")
        if (
            isinstance(candidate_chain, dict)
            and candidate_chain.get("family") == TABLE_FAMILY
            and candidate_chain.get("table") == TABLE_NAME
            and candidate_chain.get("name") == "input"
        ):
            chain = candidate_chain
        rule = entry.get("rule")
        if (
            isinstance(rule, dict)
            and rule.get("family") == TABLE_FAMILY
            and rule.get("table") == TABLE_NAME
            and rule.get("chain") == "input"
        ):
            rules.append(rule)

    findings: list[Finding] = []
    if not isinstance(chain, dict) or any(
        chain.get(field) != expected
        for field, expected in (
            ("type", "filter"),
            ("hook", "input"),
            ("prio", -10),
            ("policy", "drop"),
        )
    ):
        findings.append(
            Finding(
                code="managed_chain_not_fail_closed",
                severity="critical",
                detail="the managed input chain is absent or does not have policy drop",
            )
        )

    expected = expected_rule_tokens(ssh_ports, public_p2p_ports)
    actual: dict[str, dict[str, Any]] = {}
    duplicate_or_unnamed = False
    for rule in rules:
        comment = rule.get("comment")
        if not isinstance(comment, str) or comment in actual:
            duplicate_or_unnamed = True
            continue
        actual[comment] = rule

    if duplicate_or_unnamed or set(actual) != set(expected):
        findings.append(
            Finding(
                code="managed_rule_set_drift",
                severity="critical",
                detail="the managed input chain does not contain exactly the expected rules",
            )
        )
        return findings

    for comment, required in expected.items():
        tokens = flatten_json_tokens(actual[comment])
        if not required.issubset(tokens):
            findings.append(
                Finding(
                    code="managed_rule_semantics_drift",
                    severity="critical",
                    detail=f"managed rule {comment} no longer matches its declared purpose",
                )
            )
    for comment, ports in (
        ("pohw:accept-ssh", ssh_ports),
        ("pohw:accept-public-p2p", public_p2p_ports),
    ):
        if not ports:
            continue
        if extract_tcp_dports(actual[comment]) != set(ports):
            findings.append(
                Finding(
                    code="managed_port_set_drift",
                    severity="critical",
                    detail=f"managed rule {comment} does not have the exact intended ports",
                )
            )
    return findings


def parse_listener_endpoint(endpoint: str) -> Listener | None:
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port_text = endpoint[1:].rsplit("]:", 1)
    elif ":" in endpoint:
        host, port_text = endpoint.rsplit(":", 1)
    else:
        return None
    if port_text == "*":
        return None
    try:
        port = int(port_text, 10)
    except ValueError:
        return None
    normalized_host = host.strip("[]")
    if normalized_host in {"*", "0.0.0.0", "::", ""}:
        scope = "wildcard"
    elif normalized_host in {"127.0.0.1", "::1", "localhost"}:
        scope = "loopback"
    else:
        scope = "specific"
    return Listener(port=port, scope=scope)


def inspect_listeners(ss_bin: str) -> list[Listener]:
    result = run_command(
        ss_bin,
        ["--no-header", "--tcp", "--listening", "--numeric", "--oneline"],
        "ss listener inventory",
    )
    if result.returncode != 0:
        raise FirewallError("TCP listener inventory failed; refusing an incomplete audit")
    listeners: set[Listener] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        listener = parse_listener_endpoint(fields[3])
        if listener is not None:
            listeners.add(listener)
    return sorted(listeners, key=lambda item: (item.port, item.scope))


def audit_listeners(
    listeners: list[Listener],
    *,
    ssh_ports: tuple[int, ...],
    public_p2p_ports: tuple[int, ...],
    sensitive_ports: dict[int, str],
) -> list[Finding]:
    allowed_non_loopback = set(ssh_ports) | set(public_p2p_ports)
    findings: list[Finding] = []
    for listener in listeners:
        if listener.scope == "loopback":
            continue
        if listener.port in sensitive_ports:
            wildcard = listener.scope == "wildcard"
            findings.append(
                Finding(
                    code=(
                        "sensitive_wildcard_listener"
                        if wildcard
                        else "sensitive_non_loopback_listener"
                    ),
                    severity="critical",
                    detail=(
                        "a sensitive service is bound to every host interface"
                        if wildcard
                        else "a sensitive service is bound to a non-loopback address"
                    ),
                    port=listener.port,
                    service=sensitive_ports[listener.port],
                )
            )
        elif listener.port not in allowed_non_loopback:
            wildcard = listener.scope == "wildcard"
            findings.append(
                Finding(
                    code=(
                        "unexpected_wildcard_listener"
                        if wildcard
                        else "unexpected_non_loopback_listener"
                    ),
                    severity="warning",
                    detail=(
                        "a TCP listener is public-facing but not in the explicit allowlist"
                        if wildcard
                        else "a TCP listener uses a non-loopback address but is not allowlisted"
                    ),
                    port=listener.port,
                    service="unclassified",
                )
            )
    return findings


def validate_port_policy(
    ssh_ports: tuple[int, ...],
    public_p2p_ports: tuple[int, ...],
    sensitive_ports: dict[int, str],
) -> None:
    sensitive_ssh = set(ssh_ports) & set(sensitive_ports)
    if sensitive_ssh:
        raise FirewallError(
            "sensitive service ports cannot be declared as SSH ports: "
            + ", ".join(map(str, sorted(sensitive_ssh)))
        )
    overlap = set(ssh_ports) & set(public_p2p_ports)
    if overlap:
        raise FirewallError(
            "SSH ports and public P2P ports must be distinct: "
            + ", ".join(map(str, sorted(overlap)))
        )
    forbidden = set(public_p2p_ports) & set(sensitive_ports)
    if forbidden:
        raise FirewallError(
            "sensitive service ports cannot be public P2P ports: "
            + ", ".join(map(str, sorted(forbidden)))
        )


def write_ruleset_temporarily(ruleset: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix="pohw-firewall-", suffix=".nft")
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(ruleset)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def apply_ruleset(nft_bin: str, ruleset: str) -> None:
    path = write_ruleset_temporarily(ruleset)
    try:
        checked = run_command(
            nft_bin, ["--check", "--file", str(path)], "nftables validation"
        )
        if checked.returncode != 0:
            raise FirewallError("nft --check rejected the generated policy; no rules loaded")
        loaded = run_command(nft_bin, ["--file", str(path)], "nftables atomic load")
        if loaded.returncode != 0:
            raise FirewallError("the atomic nftables load failed")
    finally:
        path.unlink(missing_ok=True)


def build_report(
    *,
    nft_bin: str,
    ss_bin: str,
    ssh_ports: tuple[int, ...],
    public_p2p_ports: tuple[int, ...],
    sensitive_ports: dict[int, str],
) -> dict[str, Any]:
    present = table_exists(nft_bin)
    listeners = inspect_listeners(ss_bin)
    findings = audit_managed_table(
        nft_bin,
        present=present,
        ssh_ports=ssh_ports,
        public_p2p_ports=public_p2p_ports,
    )
    findings.extend(
        audit_listeners(
            listeners,
            ssh_ports=ssh_ports,
            public_p2p_ports=public_p2p_ports,
            sensitive_ports=sensitive_ports,
        )
    )
    return {
        "schema": "pohw-host-firewall-status/v2",
        "ok": not findings,
        "managedTable": present,
        "sshTcpPorts": list(ssh_ports),
        "publicP2pTcpPorts": list(public_p2p_ports),
        "persistenceManaged": False,
        "listenerSummary": {
            "wildcard": sum(item.scope == "wildcard" for item in listeners),
            "loopback": sum(item.scope == "loopback" for item in listeners),
            "specific": sum(item.scope == "specific" for item in listeners),
        },
        "findings": [asdict(item) for item in findings],
    }


def print_human_report(report: dict[str, Any], *, applied: bool) -> None:
    action = "applied and audited" if applied else "audit"
    result = "PASS" if report["ok"] else "ATTENTION"
    print(f"PoHW host firewall {action}: {result}")
    print(f"managed table loaded: {'yes' if report['managedTable'] else 'no'}")
    print(
        "SSH TCP ports: "
        + (", ".join(map(str, report["sshTcpPorts"])) or "none (Tailscale only)")
        + "; public P2P TCP ports: "
        + (", ".join(map(str, report["publicP2pTcpPorts"])) or "none")
    )
    print("reboot persistence: not managed; install an audited boot policy separately")
    for finding in report["findings"]:
        suffix = ""
        if finding.get("port") is not None:
            suffix = f" ({finding.get('service')} tcp/{finding['port']})"
        print(
            f"{finding['severity'].upper()}: {finding['code']}: "
            f"{finding['detail']}{suffix}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit or apply the dedicated fail-closed PoHW nftables input policy. "
            "The default operation is read-only."
        )
    )
    parser.add_argument(
        "--apply",
        metavar="ACKNOWLEDGEMENT",
        help=(
            "atomically load the policy only when set to "
            f"{APPLY_ACKNOWLEDGEMENT}"
        ),
    )
    parser.add_argument(
        "--status", action="store_true", help="explicitly select read-only audit mode"
    )
    parser.add_argument("--json", action="store_true", help="emit the status as JSON")
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "strict JSON policy file; root execution accepts only "
            "/etc/pohw/host-firewall.json"
        ),
    )
    parser.add_argument(
        "--ssh-port",
        action="append",
        type=parse_port,
        default=None,
        help=(
            "public-interface SSH TCP port to preserve; repeat as needed; "
            "none is inferred (Tailscale remains allowed)"
        ),
    )
    parser.add_argument(
        "--public-p2p-port",
        action="append",
        type=parse_port,
        default=None,
        help="public P2P TCP port to allow; no public P2P port is inferred",
    )
    parser.add_argument(
        "--sensitive-port",
        action="append",
        type=parse_port,
        default=None,
        help="additional TCP port that must never be selected as SSH or public P2P",
    )
    parser.add_argument(
        "--nft-bin",
        default=str(TRUSTED_ROOT_NFT_BIN),
        help="nft executable; root execution requires /usr/sbin/nft",
    )
    parser.add_argument(
        "--ss-bin",
        default=str(TRUSTED_ROOT_SS_BIN),
        help="ss executable; root execution requires /usr/bin/ss",
    )
    args = parser.parse_args()
    if args.status and args.apply is not None:
        parser.error("--status and --apply are mutually exclusive")
    if args.config is not None and any(
        value is not None
        for value in (args.ssh_port, args.public_p2p_port, args.sensitive_port)
    ):
        parser.error("--config cannot be combined with command-line port options")
    return args


def main() -> int:
    args = parse_args()
    if args.config is not None:
        try:
            ssh_ports, public_p2p_ports, extra_sensitive_ports = load_config(
                args.config, euid=os.geteuid()
            )
        except FirewallError as error:
            if args.json:
                print(
                    json.dumps(
                        {
                            "schema": "pohw-host-firewall-status/v2",
                            "ok": False,
                            "error": str(error),
                        },
                        sort_keys=True,
                    )
                )
            else:
                print(f"ERROR: {error}", file=sys.stderr)
            return 2
    else:
        ssh_ports = normalized_ports(args.ssh_port or [])
        public_p2p_ports = normalized_ports(args.public_p2p_port or [])
        extra_sensitive_ports = normalized_ports(args.sensitive_port or [])
    sensitive_ports = dict(DEFAULT_SENSITIVE_PORTS)
    for port in extra_sensitive_ports:
        sensitive_ports.setdefault(port, "operator-defined-sensitive-service")

    try:
        validate_privileged_binary(
            args.nft_bin,
            expected=TRUSTED_ROOT_NFT_BIN,
            label="nft",
            euid=os.geteuid(),
        )
        validate_privileged_binary(
            args.ss_bin,
            expected=TRUSTED_ROOT_SS_BIN,
            label="ss",
            euid=os.geteuid(),
        )
        validate_port_policy(ssh_ports, public_p2p_ports, sensitive_ports)
        applied = args.apply is not None
        if applied:
            if args.apply != APPLY_ACKNOWLEDGEMENT:
                raise FirewallError(
                    "--apply acknowledgement does not match; no rules were loaded"
                )
            inspect_listeners(args.ss_bin)
            present = table_exists(args.nft_bin)
            ruleset = render_ruleset(
                table_exists=present,
                ssh_ports=ssh_ports,
                public_p2p_ports=public_p2p_ports,
            )
            apply_ruleset(args.nft_bin, ruleset)

        report = build_report(
            nft_bin=args.nft_bin,
            ss_bin=args.ss_bin,
            ssh_ports=ssh_ports,
            public_p2p_ports=public_p2p_ports,
            sensitive_ports=sensitive_ports,
        )
    except FirewallError as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema": "pohw-host-firewall-status/v2",
                        "ok": False,
                        "error": str(error),
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print_human_report(report, applied=applied)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
