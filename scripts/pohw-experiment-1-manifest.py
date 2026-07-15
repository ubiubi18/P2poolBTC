#!/usr/bin/env python3
"""Validate the immutable Experiment 1 Bitcoin Core fork manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "pohw-bitcoin-core-fork-manifest/v1"
TAG = b"POHW_EXPERIMENT_1_ACTIVATION_V1\0"
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HEX_20 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_UPSTREAM_COMMIT = "9be056a8a72b624dae9623b2f7bded92c2a21c91"
PREVIOUS_ACTIVATION_ID = "3aed5c759ab096064957555c1f374c0fba6e35c88a3e0ca069ac392df4fec63a"
EXPECTED_FIRST_FORK_HASH = "64d2122b44c111f2f593869ce404117d34c6c830f4390eb70245c11dcc503d01"


class ManifestError(ValueError):
    pass


def canonical_payload(manifest: dict[str, Any]) -> bytes:
    payload = dict(manifest)
    payload.pop("activation_id", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def activation_id(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(TAG + canonical_payload(manifest)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    _require(isinstance(value, dict), "manifest root must be an object")
    return value


def validate(manifest: dict[str, Any], repo_root: Path, verify_patch: bool = True) -> None:
    _require(manifest.get("schema_version") == SCHEMA, f"schema_version must be {SCHEMA}")
    _require(manifest.get("experiment_id") == "pohw-experiment-1-full-consensus", "unexpected experiment_id")
    _require(manifest.get("profile_revision") == 2, "Experiment 1 profile revision must be 2")
    _require(manifest.get("status") == "experimental-no-value", "status must remain experimental-no-value")
    _require(
        manifest.get("supersedes_activation_id") == PREVIOUS_ACTIVATION_ID,
        "profile revision must supersede the pinned revision-1 activation ID",
    )
    _require(
        manifest.get("supersedes_activation_id") != manifest.get("activation_id"),
        "profile revision must not reuse its predecessor activation ID",
    )

    predecessor = manifest.get("predecessor", {})
    _require(predecessor.get("history_reinterpreted") is False, "Experiment 0 history must not be reinterpreted")

    upstream = manifest.get("upstream", {})
    _require(upstream.get("repository") == "https://github.com/bitcoin/bitcoin.git", "unexpected Bitcoin Core upstream")
    _require(upstream.get("tag") == "v31.1", "Bitcoin Core tag must be v31.1")
    _require(bool(HEX_20.fullmatch(str(upstream.get("commit", "")))), "upstream commit must be an exact 40-character revision")
    _require(upstream.get("commit") == EXPECTED_UPSTREAM_COMMIT, "Bitcoin Core commit does not match the pinned v31.1 revision")

    fork = manifest.get("fork_point", {})
    height = fork.get("inherited_tip_height")
    fork_hash = str(fork.get("inherited_tip_hash", ""))
    first_fork_hash = str(fork.get("first_fork_hash", ""))
    _require(isinstance(height, int) and height > 0, "inherited tip height must be positive")
    _require(bool(HEX_32.fullmatch(fork_hash)), "inherited tip hash must be lowercase 32-byte hex")
    _require(fork.get("first_fork_height") == height + 1, "first fork height must immediately follow inherited tip")
    _require(bool(HEX_32.fullmatch(first_fork_hash)), "first fork hash must be lowercase 32-byte hex")
    _require(first_fork_hash != fork_hash, "first fork hash must differ from inherited tip")
    _require(first_fork_hash == EXPECTED_FIRST_FORK_HASH, "first fork checkpoint does not match live history")

    network = manifest.get("network", {})
    expected_magic = hashlib.sha256(
        f"{manifest['experiment_id']}|{height}|{fork_hash}".encode("ascii")
    ).hexdigest()[:8]
    _require(network.get("message_start_hex") == expected_magic, "message start does not match the deterministic network identity")
    _require(network.get("chain_argument") == "pohw", "chain argument must be pohw")
    _require(network.get("data_subdirectory") == "pohw-experiment-1", "unexpected data subdirectory")
    _require(network.get("dns_seeds") == [] and network.get("fixed_seeds") == [], "Experiment 1 must not inherit Bitcoin mainnet seeds")
    _require(network.get("address_encoding") == "bitcoin-mainnet-compatible", "inherited scripts require explicit mainnet-compatible address encoding")
    _require(network.get("p2p_port") == 40412, "unexpected Experiment 1 P2P port")
    _require(network.get("rpc_port") == 40414, "unexpected Experiment 1 RPC port")
    _require(network.get("p2p_port") != network.get("rpc_port"), "P2P and RPC ports must differ")

    consensus = manifest.get("consensus", {})
    _require(consensus.get("engine") == "bitcoin-core-v31.1-full", "full Bitcoin Core consensus engine is required")
    _require(consensus.get("all_upstream_transaction_and_script_rules_enabled") is True, "all upstream script paths must remain enabled")
    required_script_classes = {
        "legacy-p2pk",
        "legacy-p2pkh",
        "legacy-bare-multisig",
        "p2sh-and-arbitrary-redeem-scripts",
        "segwit-v0-p2wpkh",
        "segwit-v0-p2wsh",
        "nested-segwit",
        "taproot-key-path",
        "taproot-script-path-and-tapscript",
        "cltv-and-csv-timelocks",
        "all-other-bitcoin-core-v31.1-consensus-valid-scripts",
    }
    script_classes = consensus.get("supported_transaction_and_script_classes", [])
    _require(isinstance(script_classes, list), "supported transaction and script classes must be a list")
    _require(required_script_classes.issubset(set(script_classes)), "full upstream transaction and script surface is not declared")
    _require(
        consensus.get("policy_and_wallet_behavior")
        == "unchanged-from-bitcoin-core-v31.1-except-for-fork-replay-protection",
        "upstream wallet and relay policy must remain explicit",
    )
    _require(consensus.get("inherited_utxo_spending_enabled") is True, "inherited UTXO spending must be explicit")
    replay = consensus.get("replay_protection", {})
    _require(replay.get("required") is True, "replay protection cannot be disabled")
    _require(replay.get("rule") == "inherited-input-requires-fork-only-marker-v2", "unexpected replay-protection rule")
    _require(replay.get("marker_activation_height") == height + 2, "unexpected replay-marker activation height")
    _require(replay.get("marker_script_hex") == "5150", "unexpected replay-marker script")
    _require("100-block" in str(replay.get("bootstrap_constraint", "")), "inherited-spend bootstrap constraint must be explicit")

    proof = consensus.get("proof_of_work", {})
    _require(proof.get("algorithm") == "bootstrap-then-bitcoin-2016-v1", "unexpected PoW algorithm")
    _require(proof.get("bootstrap_pow_limit_bits") == "207fffff", "unexpected bootstrap target")
    _require(proof.get("bootstrap_handoff_hashrate_hps") == 1_000_000_000_000_000, "unexpected handoff hashrate")
    _require(proof.get("target_spacing_seconds") == 600, "target spacing must be 600 seconds")
    _require(proof.get("post_handoff_retarget_interval") == 2016, "post-handoff retarget interval must be 2016")

    bootstrap = manifest.get("bootstrap", {})
    _require(bootstrap.get("copy_wallets") is False, "bootstrap must not copy wallets")
    _require(bootstrap.get("copy_rpc_credentials") is False, "bootstrap must not copy RPC credentials")
    _require(bootstrap.get("copy_peer_state") is False, "bootstrap must not copy peer state")

    build = manifest.get("build", {})
    _require(
        build.get("cmake_flags")
        == [
            "-DBUILD_GUI=OFF",
            "-DBUILD_TESTS=ON",
            "-DBUILD_BENCH=OFF",
            "-DBUILD_FUZZ_BINARY=OFF",
            "-DENABLE_IPC=OFF",
        ],
        "canonical CMake flags must remain exact and ordered",
    )
    patch_rel = str(build.get("patch_path", ""))
    patch_hash = str(build.get("patch_sha256", ""))
    _require(bool(HEX_32.fullmatch(patch_hash)), "patch_sha256 must be lowercase 32-byte hex")
    _require(patch_rel.startswith("vendor/bitcoin-core/patches/"), "patch must remain under vendor/bitcoin-core/patches")
    patch_path = (repo_root / patch_rel).resolve()
    _require(repo_root.resolve() in patch_path.parents, "patch path escapes repository")
    if verify_patch:
        try:
            patch_bytes = patch_path.read_bytes()
        except OSError as exc:
            raise ManifestError(f"cannot read pinned patch {patch_path}: {exc}") from exc
        _require(hashlib.sha256(patch_bytes).hexdigest() == patch_hash, "Bitcoin Core patch SHA-256 mismatch")
        patch_text = patch_bytes.decode("utf-8", errors="strict")
        for required in (
            f"FORK_HEIGHT{{{height}}}",
            f"REPLAY_MARKER_ACTIVATION_HEIGHT{{{height + 2}}}",
            fork_hash,
            first_fork_hash,
            "pohw_first_fork_hash",
            "wrong_first_fork_block",
            "coin->IsCoinBase() && coin->out.nValue == 0",
            "{0xd9, 0x70, 0x38, 0xba}",
            "P2P_PORT{40412}",
            "RPC_PORT{40414}",
            "BOOTSTRAP_HANDOFF_HASHRATE_HPS{1'000'000'000'000'000ULL}",
            "HANDOFF_VERSION_BIT{1 << 27}",
            'NETWORK_ID[] = "pohw-experiment-1-full-consensus"',
            "CheckPoHWForkReplayProtection",
            "SCRIPT_VERIFY_POHW_REPLAY_MARKER",
            "CScript{} << OP_1 << OP_RESERVED",
            "IsBlockFileMessageStart",
            "FindAnyByte",
            "CChainParams::PoHW",
            "ChainType::POHW",
        ):
            _require(required in patch_text, f"pinned patch is missing consensus marker: {required}")

    actual_activation = str(manifest.get("activation_id", ""))
    _require(bool(HEX_32.fullmatch(actual_activation)), "activation_id must be lowercase 32-byte hex")
    _require(actual_activation == activation_id(manifest), "activation_id does not match canonical manifest payload")

    risks = manifest.get("risk_acknowledgements", [])
    _require(isinstance(risks, list) and len(risks) >= 5, "risk acknowledgements are incomplete")
    risk_text = " ".join(str(item).lower() for item in risks)
    for term in ("no promised monetary value", "same private keys", "idena", "replay", "real mainnet btc"):
        _require(term in risk_text, f"risk acknowledgements must mention {term!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("compute", "verify"))
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-patch", action="store_true", help="only for generating a manifest before its patch artifact exists")
    args = parser.parse_args()

    try:
        manifest = _read_json(args.manifest)
        if args.command == "compute":
            print(activation_id(manifest))
        else:
            validate(manifest, args.repo_root, verify_patch=not args.skip_patch)
            print("Experiment 1 manifest verified")
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
