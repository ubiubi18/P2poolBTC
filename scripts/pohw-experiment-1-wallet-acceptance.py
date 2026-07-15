#!/usr/bin/env python3
"""Exercise an inherited Experiment 1 wallet/PSBT spend without broadcasting."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Optional


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RPC_BYTES = 16 * 1024 * 1024
MAX_PSBT_BYTES = 16 * 1024 * 1024
RPC_TIMEOUT_SECONDS = 30
SATOSHIS_PER_BTC = 100_000_000
MAX_MONEY_SATOSHIS = 21_000_000 * SATOSHIS_PER_BTC
COINBASE_MATURITY = 100
REPLAY_MARKER_HEX = "5150"
REPLAY_REJECT_REASON = "bad-pohw-replay-unprotected"
HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")


class AcceptanceError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AcceptanceError("manifest must be a regular non-symlink file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise AcceptanceError("manifest exceeds 1 MiB")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_float=Decimal,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise AcceptanceError("manifest root must be an object")
    return value


def require_regular_executable(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AcceptanceError(f"cannot inspect bitcoin-cli: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceError("bitcoin-cli must be a regular non-symlink file")
    if not os.access(path, os.X_OK):
        raise AcceptanceError("bitcoin-cli is not executable")
    return path.resolve(strict=True)


def validate_wallet_name(wallet: str) -> str:
    if not wallet or len(wallet.encode("utf-8")) > 128:
        raise AcceptanceError("wallet name must contain 1 to 128 UTF-8 bytes")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in wallet):
        raise AcceptanceError("wallet name contains a control character")
    return wallet


class RpcClient:
    def __init__(self, bitcoin_cli: Path, datadir: Path, wallet: str):
        self.bitcoin_cli = require_regular_executable(bitcoin_cli)
        if not datadir.is_absolute():
            raise AcceptanceError("datadir must be absolute")
        self.datadir = datadir
        self.wallet = validate_wallet_name(wallet)

    def call(self, method: str, *args: str, sensitive: bool = False) -> str:
        if not method or not method.replace("_", "").isalnum():
            raise AcceptanceError("RPC method is invalid")
        if any("\n" in argument or "\r" in argument for argument in args):
            raise AcceptanceError(f"RPC operation {method} contains a line break")
        command = [
            str(self.bitcoin_cli),
            f"-datadir={self.datadir}",
            "-chain=pohw",
            "-rpcconnect=127.0.0.1",
            f"-rpcwallet={self.wallet}",
        ]
        input_bytes = None
        if sensitive and args:
            command.extend(("-stdin", method))
            input_bytes = ("\n".join(args) + "\n").encode("utf-8")
        else:
            command.extend((method, *args))
        try:
            result = subprocess.run(
                command,
                input=input_bytes,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=RPC_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AcceptanceError(f"RPC operation {method} failed") from exc
        if len(result.stdout) > MAX_RPC_BYTES or len(result.stderr) > MAX_RPC_BYTES:
            raise AcceptanceError(f"RPC operation {method} exceeded the output limit")
        if result.returncode != 0:
            raise AcceptanceError(f"RPC operation {method} was rejected")
        try:
            return result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise AcceptanceError(f"RPC operation {method} returned invalid UTF-8") from exc

    def json(self, method: str, *args: str, sensitive: bool = False) -> Any:
        try:
            return json.loads(
                self.call(method, *args, sensitive=sensitive),
                object_pairs_hook=reject_duplicate_keys,
                parse_float=Decimal,
            )
        except json.JSONDecodeError as exc:
            raise AcceptanceError(
                f"RPC operation {method} returned invalid JSON"
            ) from exc


def require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AcceptanceError(f"{name} must be an integer")
    return value


def parse_outpoint(value: str) -> tuple[str, int]:
    txid, separator, raw_index = value.partition(":")
    if separator != ":" or not HEX_32_RE.fullmatch(txid):
        raise AcceptanceError("inherited outpoint must be lowercase TXID:VOUT")
    if not raw_index.isascii() or not raw_index.isdecimal():
        raise AcceptanceError("inherited vout must be a decimal integer")
    index = int(raw_index)
    if index > 0xFFFFFFFF:
        raise AcceptanceError("inherited vout exceeds uint32")
    return txid, index


def outpoint_bytes(outpoint: tuple[str, int]) -> bytes:
    txid, index = outpoint
    return bytes.fromhex(txid)[::-1] + index.to_bytes(4, "little")


def btc_to_satoshis(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise AcceptanceError(f"{name} must be an exact JSON number")
    try:
        atomic = Decimal(value) * SATOSHIS_PER_BTC
    except (InvalidOperation, ValueError) as exc:
        raise AcceptanceError(f"{name} is invalid") from exc
    if atomic != atomic.to_integral_value():
        raise AcceptanceError(f"{name} has more than eight decimal places")
    result = int(atomic)
    if result < 0 or result > MAX_MONEY_SATOSHIS:
        raise AcceptanceError(f"{name} is outside Bitcoin's money range")
    return result


def satoshis_to_btc(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AcceptanceError("satoshi amount must be an integer")
    if value < 0 or value > MAX_MONEY_SATOSHIS:
        raise AcceptanceError("satoshi amount is outside Bitcoin's money range")
    whole, fraction = divmod(value, SATOSHIS_PER_BTC)
    return f"{whole}.{fraction:08d}"


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise AcceptanceError("truncated compact-size integer")
    prefix = data[offset]
    offset += 1
    if prefix < 253:
        return prefix, offset
    widths = {253: 2, 254: 4, 255: 8}
    width = widths[prefix]
    end = offset + width
    if end > len(data):
        raise AcceptanceError("truncated compact-size integer")
    value = int.from_bytes(data[offset:end], "little")
    minimum = {253: 253, 254: 0x10000, 255: 0x100000000}[prefix]
    if value < minimum:
        raise AcceptanceError("non-canonical compact-size integer")
    return value, end


def write_compact_size(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise AcceptanceError("compact-size integer is outside uint64")
    if value < 253:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def read_varbytes(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = read_compact_size(data, offset)
    end = offset + length
    if end > len(data):
        raise AcceptanceError("truncated byte string")
    return data[offset:end], end


def read_psbt_map(data: bytes, offset: int) -> tuple[dict[bytes, bytes], int]:
    result: dict[bytes, bytes] = {}
    while True:
        key, offset = read_varbytes(data, offset)
        if not key:
            return result, offset
        if key in result:
            raise AcceptanceError("duplicate PSBT map key")
        value, offset = read_varbytes(data, offset)
        result[key] = value


@dataclass(frozen=True)
class TxInput:
    outpoint: bytes
    sequence: bytes


@dataclass(frozen=True)
class TxOutput:
    value: bytes
    script: bytes


@dataclass(frozen=True)
class UnsignedTransaction:
    version: bytes
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    locktime: bytes


def require_bytes(data: bytes, offset: int, length: int, name: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise AcceptanceError(f"truncated {name}")
    return data[offset:end], end


def parse_unsigned_transaction(data: bytes) -> UnsignedTransaction:
    offset = 0
    version, offset = require_bytes(data, offset, 4, "transaction version")
    input_count, offset = read_compact_size(data, offset)
    if input_count == 0:
        raise AcceptanceError("PSBT unsigned transaction uses witness serialization")
    if input_count > 100_000:
        raise AcceptanceError("PSBT unsigned transaction has too many inputs")
    inputs: list[TxInput] = []
    for _ in range(input_count):
        outpoint, offset = require_bytes(data, offset, 36, "transaction outpoint")
        script_sig, offset = read_varbytes(data, offset)
        if script_sig:
            raise AcceptanceError("PSBT unsigned transaction has a nonempty scriptSig")
        sequence, offset = require_bytes(data, offset, 4, "transaction sequence")
        inputs.append(TxInput(outpoint=outpoint, sequence=sequence))
    output_count, offset = read_compact_size(data, offset)
    if output_count > 100_000:
        raise AcceptanceError("PSBT unsigned transaction has too many outputs")
    outputs: list[TxOutput] = []
    for _ in range(output_count):
        value, offset = require_bytes(data, offset, 8, "transaction output value")
        script, offset = read_varbytes(data, offset)
        outputs.append(TxOutput(value=value, script=script))
    locktime, offset = require_bytes(data, offset, 4, "transaction locktime")
    if offset != len(data):
        raise AcceptanceError("PSBT unsigned transaction has trailing bytes")
    return UnsignedTransaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
    )


def parse_final_witness(data: bytes) -> tuple[bytes, ...]:
    count, offset = read_compact_size(data, 0)
    if count > 100_000:
        raise AcceptanceError("final witness has too many elements")
    stack: list[bytes] = []
    for _ in range(count):
        item, offset = read_varbytes(data, offset)
        stack.append(item)
    if offset != len(data):
        raise AcceptanceError("final witness has trailing bytes")
    return tuple(stack)


def serialize_witness(stack: tuple[bytes, ...]) -> bytes:
    return write_compact_size(len(stack)) + b"".join(
        write_compact_size(len(item)) + item for item in stack
    )


def decode_psbt(value: str) -> tuple[UnsignedTransaction, list[dict[bytes, bytes]]]:
    if len(value) > MAX_PSBT_BYTES * 2:
        raise AcceptanceError("encoded PSBT exceeds the input bound")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AcceptanceError("PSBT is not canonical base64") from exc
    if len(data) > MAX_PSBT_BYTES:
        raise AcceptanceError("PSBT exceeds 16 MiB")
    if not data.startswith(b"psbt\xff"):
        raise AcceptanceError("PSBT magic is invalid")
    global_map, offset = read_psbt_map(data, 5)
    if b"\x00" not in global_map:
        raise AcceptanceError("PSBTv0 unsigned transaction is missing")
    if any(key[0] == 0x00 and key != b"\x00" for key in global_map):
        raise AcceptanceError("PSBT unsigned transaction key has key data")
    version = global_map.get(b"\xfb")
    if version is not None and version != b"\x00\x00\x00\x00":
        raise AcceptanceError("only PSBTv0 is supported")
    transaction = parse_unsigned_transaction(global_map[b"\x00"])
    input_maps: list[dict[bytes, bytes]] = []
    for _ in transaction.inputs:
        input_map, offset = read_psbt_map(data, offset)
        input_maps.append(input_map)
    for _ in transaction.outputs:
        _, offset = read_psbt_map(data, offset)
    if offset != len(data):
        raise AcceptanceError("PSBT has trailing maps or bytes")
    return transaction, input_maps


def extract_marker_finalized_transaction(
    psbt: str,
    expected_inputs: list[tuple[str, int]],
    marker_input_index: int,
    expected_transaction: Optional[UnsignedTransaction] = None,
) -> str:
    transaction, input_maps = decode_psbt(psbt)
    if expected_transaction is not None and transaction != expected_transaction:
        raise AcceptanceError("signed PSBT changed the unsigned transaction")
    if len(transaction.inputs) != len(expected_inputs):
        raise AcceptanceError("signed PSBT input count changed")
    if marker_input_index < 0 or marker_input_index >= len(transaction.inputs):
        raise AcceptanceError("marker input index is outside the transaction")
    for index, expected in enumerate(expected_inputs):
        if transaction.inputs[index].outpoint != outpoint_bytes(expected):
            raise AcceptanceError("signed PSBT input order or outpoint changed")

    script_sigs: list[bytes] = []
    witnesses: list[Optional[tuple[bytes, ...]]] = []
    for index, input_map in enumerate(input_maps):
        final_script_sig = input_map.get(b"\x07")
        final_witness_raw = input_map.get(b"\x08")
        if index == marker_input_index:
            if final_script_sig not in (None, b"") or final_witness_raw is not None:
                raise AcceptanceError("replay-marker input has unexpected final data")
            script_sigs.append(b"")
            witnesses.append(None)
            continue
        if final_script_sig is None and final_witness_raw is None:
            raise AcceptanceError("a non-marker PSBT input is not finalized")
        final_witness = (
            parse_final_witness(final_witness_raw)
            if final_witness_raw is not None
            else None
        )
        if final_script_sig in (None, b"") and final_witness in (None, ()):
            raise AcceptanceError("a non-marker PSBT input has empty final data")
        script_sigs.append(final_script_sig or b"")
        witnesses.append(final_witness)

    has_witness = any(witness is not None for witness in witnesses)
    result = bytearray(transaction.version)
    if has_witness:
        result.extend(b"\x00\x01")
    result.extend(write_compact_size(len(transaction.inputs)))
    for tx_input, script_sig in zip(transaction.inputs, script_sigs):
        result.extend(tx_input.outpoint)
        result.extend(write_compact_size(len(script_sig)))
        result.extend(script_sig)
        result.extend(tx_input.sequence)
    result.extend(write_compact_size(len(transaction.outputs)))
    for output in transaction.outputs:
        result.extend(output.value)
        result.extend(write_compact_size(len(output.script)))
        result.extend(output.script)
    if has_witness:
        for witness in witnesses:
            result.extend(serialize_witness(witness or ()))
    result.extend(transaction.locktime)
    return bytes(result).hex()


def find_mature_replay_marker(
    rpc: RpcClient,
    chain_height: int,
    activation_height: int,
    search_depth: int,
) -> tuple[str, int]:
    latest_mature = chain_height + 1 - COINBASE_MATURITY
    if latest_mature < activation_height:
        raise AcceptanceError("the fork does not yet have a mature replay marker")
    lowest = max(activation_height, latest_mature - search_depth + 1)
    for height in range(latest_mature, lowest - 1, -1):
        block_hash = rpc.call("getblockhash", str(height))
        block = rpc.json("getblock", block_hash, "2")
        transactions = block.get("tx") if isinstance(block, dict) else None
        if not isinstance(transactions, list) or not transactions:
            raise AcceptanceError("fork block has no decoded coinbase transaction")
        coinbase = transactions[0]
        if not isinstance(coinbase, dict) or not isinstance(coinbase.get("txid"), str):
            raise AcceptanceError("fork coinbase transaction is malformed")
        for output in coinbase.get("vout", []):
            if not isinstance(output, dict):
                continue
            script = output.get("scriptPubKey")
            if not isinstance(script, dict) or script.get("hex", "").lower() != REPLAY_MARKER_HEX:
                continue
            index = output.get("n")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                continue
            txout = rpc.json("gettxout", coinbase["txid"], str(index), "false")
            if not isinstance(txout, dict):
                continue
            if txout.get("coinbase") is not True or btc_to_satoshis(
                txout.get("value"), "replay-marker value"
            ) != 0:
                raise AcceptanceError("candidate replay marker is not a zero-value coinbase")
            return coinbase["txid"], index
    raise AcceptanceError("no unspent mature replay marker was found within the search bound")


def mempool_result(rpc: RpcClient, raw_transaction: str) -> dict[str, Any]:
    result = rpc.json(
        "testmempoolaccept",
        json.dumps([raw_transaction], separators=(",", ":")),
        sensitive=True,
    )
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise AcceptanceError("testmempoolaccept returned an unexpected result")
    return result[0]


def require_unspent(rpc: RpcClient, outpoint: tuple[str, int], name: str) -> dict[str, Any]:
    value = rpc.json("gettxout", outpoint[0], str(outpoint[1]), "false")
    if not isinstance(value, dict):
        raise AcceptanceError(f"{name} is not an unspent confirmed output")
    return value


def create_psbt(
    rpc: RpcClient,
    inputs: list[tuple[str, int]],
    destination: str,
    output_satoshis: int,
) -> str:
    input_json = json.dumps(
        [{"txid": txid, "vout": index} for txid, index in inputs],
        sort_keys=True,
        separators=(",", ":"),
    )
    output_json = (
        "[{"
        + json.dumps(destination, ensure_ascii=True)
        + ":"
        + satoshis_to_btc(output_satoshis)
        + "}]"
    )
    return rpc.call("createpsbt", input_json, output_json, sensitive=True)


def process_psbt(rpc: RpcClient, psbt: str) -> dict[str, Any]:
    expected_transaction, _ = decode_psbt(psbt)
    updated = rpc.call("utxoupdatepsbt", psbt, sensitive=True)
    updated_transaction, _ = decode_psbt(updated)
    if updated_transaction != expected_transaction:
        raise AcceptanceError("utxoupdatepsbt changed the unsigned transaction")
    result = rpc.json("walletprocesspsbt", updated, sensitive=True)
    if not isinstance(result, dict) or not isinstance(result.get("psbt"), str):
        raise AcceptanceError("walletprocesspsbt returned an unexpected result")
    processed_transaction, _ = decode_psbt(result["psbt"])
    if processed_transaction != expected_transaction:
        raise AcceptanceError("walletprocesspsbt changed the unsigned transaction")
    return result


def run_acceptance(args: argparse.Namespace) -> None:
    manifest = read_manifest(args.manifest)
    if manifest.get("status") != "experimental-no-value":
        raise AcceptanceError("manifest is not the no-value Experiment 1 profile")
    fork = manifest.get("fork_point", {})
    consensus = manifest.get("consensus", {})
    replay = consensus.get("replay_protection", {})
    fork_height = require_int(fork.get("inherited_tip_height"), "inherited tip height")
    first_fork_height = require_int(fork.get("first_fork_height"), "first fork height")
    first_fork_hash = fork.get("first_fork_hash")
    marker_height = require_int(replay.get("marker_activation_height"), "marker activation height")
    if not isinstance(first_fork_hash, str) or not HEX_32_RE.fullmatch(first_fork_hash):
        raise AcceptanceError("manifest has no exact first fork checkpoint")
    if consensus.get("inherited_utxo_spending_enabled") is not True:
        raise AcceptanceError("manifest does not enable inherited UTXO spending")

    rpc = RpcClient(args.bitcoin_cli, args.datadir, args.wallet)
    info = rpc.json("getblockchaininfo")
    if not isinstance(info, dict) or info.get("chain") != "pohw":
        raise AcceptanceError("RPC is not bound to the pohw chain")
    if info.get("initialblockdownload") is not False:
        raise AcceptanceError("PoHW node is still in initial block download")
    chain_height = require_int(info.get("blocks"), "RPC block height")
    if rpc.call("getblockhash", str(first_fork_height)) != first_fork_hash:
        raise AcceptanceError("active chain does not match the first fork checkpoint")

    loaded_wallets = rpc.json("listwallets")
    if not isinstance(loaded_wallets, list) or args.wallet not in loaded_wallets:
        raise AcceptanceError("the requested wallet is not loaded")
    address_info = rpc.json("getaddressinfo", args.destination)
    if not isinstance(address_info, dict) or address_info.get("ismine") is not True:
        raise AcceptanceError("destination must belong to the selected fork-only wallet")

    inherited = parse_outpoint(args.inherited_outpoint)
    inherited_txout = require_unspent(rpc, inherited, "inherited input")
    confirmations = require_int(inherited_txout.get("confirmations"), "inherited confirmations")
    if confirmations <= 0:
        raise AcceptanceError("inherited input must be confirmed")
    creation_height = chain_height - confirmations + 1
    if creation_height < 0 or creation_height > fork_height:
        raise AcceptanceError("supplied input was not inherited at the pinned fork point")
    script = inherited_txout.get("scriptPubKey")
    if isinstance(script, dict) and script.get("hex", "").lower() == REPLAY_MARKER_HEX:
        raise AcceptanceError("inherited input cannot be a replay marker")
    input_satoshis = btc_to_satoshis(inherited_txout.get("value"), "inherited input value")
    if args.fee_satoshis <= 0 or args.fee_satoshis > args.max_fee_satoshis:
        raise AcceptanceError("fee is outside the explicit acceptance bound")
    if input_satoshis <= args.fee_satoshis:
        raise AcceptanceError("inherited input does not cover the bounded fee")
    output_satoshis = input_satoshis - args.fee_satoshis

    marker = find_mature_replay_marker(
        rpc,
        chain_height,
        marker_height,
        args.marker_search_depth,
    )
    unprotected_psbt = create_psbt(rpc, [inherited], args.destination, output_satoshis)
    unprotected_processed = process_psbt(rpc, unprotected_psbt)
    if unprotected_processed.get("complete") is not True or not isinstance(
        unprotected_processed.get("hex"), str
    ):
        raise AcceptanceError("wallet could not finalize the inherited input")
    unprotected_result = mempool_result(rpc, unprotected_processed["hex"])
    if unprotected_result.get("allowed") is not False or unprotected_result.get(
        "reject-reason"
    ) != REPLAY_REJECT_REASON:
        raise AcceptanceError("unprotected wallet PSBT did not reach the replay gate")

    protected_inputs = [inherited, marker]
    protected_psbt = create_psbt(rpc, protected_inputs, args.destination, output_satoshis)
    protected_transaction, _ = decode_psbt(protected_psbt)
    protected_processed = process_psbt(rpc, protected_psbt)
    protected_raw = extract_marker_finalized_transaction(
        protected_processed["psbt"],
        protected_inputs,
        marker_input_index=1,
        expected_transaction=protected_transaction,
    )
    protected_result = mempool_result(rpc, protected_raw)
    if protected_result.get("allowed") is not True:
        raise AcceptanceError("marker-protected wallet PSBT was not accepted by mempool simulation")

    require_unspent(rpc, inherited, "inherited input")
    require_unspent(rpc, marker, "replay-marker input")
    print("Experiment 1 wallet/PSBT acceptance passed")
    print("unprotected_inherited_psbt=replay-gate-rejected")
    print("marker_protected_inherited_psbt=accepted-by-mempool-simulation")
    print("broadcast=false")


def main() -> int:
    distribution_root = Path(__file__).resolve().parents[1]
    installed_manifest = distribution_root / "experiment-manifest.json"
    repository_manifest = distribution_root / "compatibility/experiment-1-full-consensus.json"
    default_manifest = installed_manifest if installed_manifest.is_file() else repository_manifest
    parser = argparse.ArgumentParser(
        description=(
            "No-broadcast wallet/PSBT acceptance test for one explicitly supplied "
            "Experiment 1 inherited UTXO"
        )
    )
    parser.add_argument(
        "--bitcoin-cli",
        type=Path,
        default=Path("/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli"),
    )
    parser.add_argument("--datadir", type=Path, default=Path("/srv/bitcoin/pohw"))
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--inherited-outpoint", required=True, metavar="TXID:VOUT")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--fee-satoshis", type=int, default=1_000)
    parser.add_argument("--max-fee-satoshis", type=int, default=100_000)
    parser.add_argument("--marker-search-depth", type=int, default=4_096)
    args = parser.parse_args()
    if not 1 <= args.marker_search_depth <= 100_000:
        parser.error("--marker-search-depth must be between 1 and 100000")
    if not 1 <= args.max_fee_satoshis <= 10_000_000:
        parser.error("--max-fee-satoshis must be between 1 and 10000000")
    try:
        run_acceptance(args)
        return 0
    except AcceptanceError as exc:
        print(f"wallet/PSBT acceptance failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
