#!/usr/bin/env python3
"""Probe Experiment 1 replay isolation without broadcasting a transaction."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RPC_BYTES = 16 * 1024 * 1024
RPC_TIMEOUT_SECONDS = 30
REPLAY_MARKER_HEX = "5150"
REPLAY_REJECT_REASON = "bad-pohw-replay-unprotected"
EXPECTED_LATER_REJECTIONS = {
    "bad-txns-premature-spend-of-coinbase",
    "mandatory-script-verify-flag-failed",
    "mempool-script-verify-flag-failed",
    "non-mandatory-script-verify-flag",
}


class ProbeError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProbeError("manifest must be a regular non-symlink file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise ProbeError("manifest exceeds 1 MiB")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ProbeError("manifest root must be an object")
    return value


def require_regular_executable(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProbeError(f"cannot inspect bitcoin-cli: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProbeError("bitcoin-cli must be a regular non-symlink file")
    if not os.access(path, os.X_OK):
        raise ProbeError("bitcoin-cli is not executable")
    return path.resolve(strict=True)


class RpcClient:
    def __init__(self, bitcoin_cli: Path, datadir: Path):
        self.bitcoin_cli = require_regular_executable(bitcoin_cli)
        if not datadir.is_absolute():
            raise ProbeError("datadir must be absolute")
        self.datadir = datadir

    def call(self, method: str, *args: str) -> str:
        command = [
            str(self.bitcoin_cli),
            f"-datadir={self.datadir}",
            "-chain=pohw",
            "-rpcconnect=127.0.0.1",
            method,
            *args,
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=RPC_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeError(f"RPC operation {method} failed") from exc
        if len(result.stdout) > MAX_RPC_BYTES or len(result.stderr) > MAX_RPC_BYTES:
            raise ProbeError(f"RPC operation {method} exceeded the output limit")
        if result.returncode != 0:
            raise ProbeError(f"RPC operation {method} was rejected")
        try:
            return result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise ProbeError(f"RPC operation {method} returned invalid UTF-8") from exc

    def json(self, method: str, *args: str) -> Any:
        try:
            return json.loads(self.call(method, *args), object_pairs_hook=reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise ProbeError(f"RPC operation {method} returned invalid JSON") from exc


def require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProbeError(f"{name} must be an integer")
    return value


def coinbase_transaction(rpc: RpcClient, height: int) -> dict[str, Any]:
    block_hash = rpc.call("getblockhash", str(height))
    block = rpc.json("getblock", block_hash, "1")
    txids = block.get("tx") if isinstance(block, dict) else None
    if not isinstance(txids, list) or not txids or not isinstance(txids[0], str):
        raise ProbeError("block does not expose a canonical coinbase transaction")
    tx = rpc.json("getrawtransaction", txids[0], "true", block_hash)
    if not isinstance(tx, dict) or tx.get("txid") != txids[0]:
        raise ProbeError("coinbase transaction response is inconsistent")
    return tx


def find_unspent_output(
    rpc: RpcClient,
    transaction: dict[str, Any],
    required_script_hex: str | None = None,
) -> tuple[str, int]:
    txid = transaction.get("txid")
    outputs = transaction.get("vout")
    if not isinstance(txid, str) or not isinstance(outputs, list):
        raise ProbeError("transaction output structure is invalid")
    for output in outputs:
        if not isinstance(output, dict):
            continue
        index = output.get("n")
        script = output.get("scriptPubKey")
        script_hex = script.get("hex", "").lower() if isinstance(script, dict) else ""
        if required_script_hex is not None and script_hex != required_script_hex:
            continue
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            continue
        if rpc.json("gettxout", txid, str(index), "true") is not None:
            return txid, index
    raise ProbeError("no matching unspent output is available for the probe")


def build_probe_transaction(
    rpc: RpcClient,
    inputs: list[tuple[str, int]],
) -> str:
    encoded_inputs = json.dumps(
        [{"txid": txid, "vout": index} for txid, index in inputs],
        sort_keys=True,
        separators=(",", ":"),
    )
    encoded_outputs = json.dumps(
        {"data": "00" * 40},
        sort_keys=True,
        separators=(",", ":"),
    )
    return rpc.call("createrawtransaction", encoded_inputs, encoded_outputs)


def require_still_unspent(rpc: RpcClient, outpoint: tuple[str, int], name: str) -> None:
    if rpc.json("gettxout", outpoint[0], str(outpoint[1]), "true") is None:
        raise ProbeError(f"{name} changed while the replay probe was running")


def mempool_result(rpc: RpcClient, raw_transaction: str) -> dict[str, Any]:
    result = rpc.json(
        "testmempoolaccept",
        json.dumps([raw_transaction], separators=(",", ":")),
        "0",
    )
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ProbeError("testmempoolaccept returned an unexpected result")
    return result[0]


def validate_probe_results(
    unprotected: dict[str, Any],
    marker_protected: dict[str, Any],
) -> str:
    if unprotected.get("allowed") is not False:
        raise ProbeError("unprotected inherited spend was not rejected")
    if unprotected.get("reject-reason") != REPLAY_REJECT_REASON:
        raise ProbeError("unprotected inherited spend did not reach the replay gate")
    if marker_protected.get("reject-reason") == REPLAY_REJECT_REASON:
        raise ProbeError("marker-protected spend was still rejected by the replay gate")
    if marker_protected.get("allowed") is True:
        return "accepted-by-mempool-simulation"
    if marker_protected.get("allowed") is not False:
        raise ProbeError("marker-protected probe has no deterministic acceptance result")
    reject_reason = marker_protected.get("reject-reason")
    if not isinstance(reject_reason, str):
        raise ProbeError("marker-protected rejection is missing its reason")
    if not any(
        reject_reason == expected or reject_reason.startswith(expected + " ")
        for expected in EXPECTED_LATER_REJECTIONS
    ):
        raise ProbeError("marker-protected probe did not reach a recognized later validation rule")
    return "passed-replay-gate-then-rejected-by-later-rule"


def main() -> int:
    distribution_root = Path(__file__).resolve().parents[1]
    installed_manifest = distribution_root / "experiment-manifest.json"
    repository_manifest = (
        distribution_root / "compatibility/experiment-1-full-consensus.json"
    )
    default_manifest = (
        installed_manifest if installed_manifest.is_file() else repository_manifest
    )
    parser = argparse.ArgumentParser(
        description="Read-only Experiment 1 inherited-spend replay probe. Nothing is broadcast."
    )
    parser.add_argument(
        "--bitcoin-cli",
        type=Path,
        default=Path("/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli"),
    )
    parser.add_argument("--datadir", type=Path, default=Path("/srv/bitcoin/pohw"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
    )
    args = parser.parse_args()

    try:
        manifest = read_manifest(args.manifest)
        if manifest.get("status") != "experimental-no-value":
            raise ProbeError("manifest is not the no-value Experiment 1 profile")
        fork_height = require_int(
            manifest.get("fork_point", {}).get("inherited_tip_height"),
            "inherited tip height",
        )
        marker_height = require_int(
            manifest.get("consensus", {})
            .get("replay_protection", {})
            .get("marker_activation_height"),
            "marker activation height",
        )
        first_fork_height = require_int(
            manifest.get("fork_point", {}).get("first_fork_height"),
            "first fork height",
        )
        first_fork_hash = manifest.get("fork_point", {}).get("first_fork_hash")
        if not isinstance(first_fork_hash, str) or len(first_fork_hash) != 64:
            raise ProbeError("manifest has no exact first fork checkpoint")
        rpc = RpcClient(args.bitcoin_cli, args.datadir)
        info = rpc.json("getblockchaininfo")
        if not isinstance(info, dict) or info.get("chain") != "pohw":
            raise ProbeError("RPC is not bound to the pohw chain")
        if require_int(info.get("blocks"), "RPC block height") < marker_height:
            raise ProbeError("chain has not reached replay-marker activation")
        if rpc.call("getblockhash", str(first_fork_height)) != first_fork_hash:
            raise ProbeError("active chain does not match the first fork checkpoint")

        inherited = find_unspent_output(rpc, coinbase_transaction(rpc, fork_height))
        marker = find_unspent_output(
            rpc,
            coinbase_transaction(rpc, marker_height),
            REPLAY_MARKER_HEX,
        )
        unprotected = mempool_result(rpc, build_probe_transaction(rpc, [inherited]))
        protected = mempool_result(
            rpc,
            build_probe_transaction(rpc, [inherited, marker]),
        )
        protected_outcome = validate_probe_results(unprotected, protected)
        require_still_unspent(rpc, inherited, "inherited probe input")
        require_still_unspent(rpc, marker, "replay-marker probe input")
        print("Experiment 1 replay probe passed; no transaction was broadcast")
        print("unprotected_inherited_spend=replay-gate-rejected")
        print(f"marker_protected_spend={protected_outcome}")
        return 0
    except ProbeError as exc:
        print(f"replay probe failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
