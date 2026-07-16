import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-community-onboarding.py"
SHELL = ROOT / "scripts" / "pohw-community-onboard.sh"
POWERSHELL = ROOT / "scripts" / "pohw-community-onboard.ps1"
PROFILE = ROOT / "compatibility" / "experiment-1-onboarding-profile.json"
PROFILE_SCHEMA = ROOT / "schemas" / "pohw-community-onboarding-profile-v1.schema.json"
RECEIPT_SCHEMA = ROOT / "schemas" / "pohw-community-onboarding-receipt-v1.schema.json"
ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "experiment-1-bug.yml"
QUICKSTART = ROOT / "COMMUNITY-QUICKSTART.md"
COMMUNITY_GUIDE = ROOT / "COMMUNITY-EXPERIMENT-1.md"
ECOSYSTEM_CID = "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq"

SPEC = importlib.util.spec_from_file_location("pohw_community_onboarding", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ONBOARDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ONBOARDING)


def good_host():
    return {
        "eligible_for_role": True,
        "platform_class": "linux",
        "cpu_cores": 8,
        "memory_gib": 32,
        "free_storage_gib": 1000,
        "storage_path_verified": True,
        "ssd_confirmed": True,
        "systemd_available": True,
        "missing_command_groups": [],
        "failed_checks": [],
    }


def verified_release(*, ready=False, registry_chain_verified=None):
    artifacts = {}
    if ready:
        for index, name in enumerate(ONBOARDING.REQUIRED_RUNTIME_ARTIFACTS, start=1):
            digest = f"{index:02x}" * 32
            artifacts[name] = {
                "cid": ONBOARDING._cid_text(
                    ONBOARDING.RAW_CID_PREFIX + bytes.fromhex(digest),
                    codec_prefix=ONBOARDING.RAW_CID_PREFIX,
                    label=name,
                ),
                "sha256": digest,
                "size": index,
            }
    if registry_chain_verified is None:
        registry_chain_verified = ready
    return {
        "policy_status": "ready-for-public-join" if ready else "blocked-release-readiness",
        "activation_id": "86dfc3ff2736717781cdf007727bfc6bc3ec56a87f27a1d09703885adca434d8",
        "manifest_verified": True,
        "launch_policy_verified": True,
        "source_commit": "1" * 40,
        "source_tree_clean": True,
        "candidate_ecosystem_cid": ECOSYSTEM_CID if ready else None,
        "candidate_ecosystem_verified": ready,
        "canonical_source_cid": ECOSYSTEM_CID if ready else None,
        "source_car_sha256": "3" * 64 if ready else None,
        "canonical_source_verified": ready,
        "source_commit_matches": True if ready else None,
        "governance_cli_verified": ready,
        "registry_chain_verified": registry_chain_verified,
        "attested_artifacts": artifacts,
        "focused_tests_passed": None,
        "canonical_source_published": ready,
        "public_join_ready": ready,
        "missing_release_gates": [] if ready else ["external-security-review-passed"],
    }


def args_for(role, output_dir, *, probe_live=False):
    return argparse.Namespace(
        role=role,
        repo_root=ROOT,
        profile=PROFILE,
        storage_path=ROOT,
        output_dir=output_dir,
        run_tests=False,
        json=False,
        open_report=False,
        readiness_car=None,
        readiness_evidence_car=None,
        expected_ecosystem_cid=None,
        candidate_ecosystem_car=None,
        source_car=None,
        governance_cli=None,
        idena_anchor_policy=None,
        idena_rpc_url="http://127.0.0.1:9009",
        idena_api_key_file=None,
        probe_live=probe_live,
        p2pool_node=None,
        p2pool_datadir=None,
        snapshot_dir=None,
        miner_id=None,
        bitcoin_cli=None,
        bitcoin_datadir=None,
        bitcoin_cookie_file=None,
    )


def good_live(profile):
    return {
        "core_ready": True,
        "core_profile_verified": True,
        "core_local_service_verified": True,
        "checkpoint_verified": True,
        "core_height": 958200,
        "core_tip_age_seconds": 60,
        "bitcoin_peers": profile["live_success"]["minimum_bitcoin_peers"],
        "registered_miner": True,
        "verified_snapshot": True,
        "snapshot_voters": profile["live_success"]["minimum_snapshot_voters"],
        "reachable_gossip_peers": 2,
        "accepted_bitcoin_template": True,
        "active_shares": 3,
        "miner_active_shares": 1,
        "miner_share_age_seconds": 60,
        "share_tip_present": True,
    }


class CidTag:
    def __init__(self, raw):
        self.raw = raw


def encode_head(major, value):
    if value < 24:
        return bytes(((major << 5) | value,))
    for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (width * 8):
            return bytes(((major << 5) | marker,)) + value.to_bytes(width, "big")
    raise ValueError("CBOR integer is too large")


def encode_cbor(value):
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, CidTag):
        return encode_head(6, 42) + encode_cbor(b"\0" + value.raw)
    if isinstance(value, int):
        return encode_head(0, value)
    if isinstance(value, bytes):
        return encode_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return encode_head(3, len(raw)) + raw
    if isinstance(value, list):
        return encode_head(4, len(value)) + b"".join(encode_cbor(item) for item in value)
    if isinstance(value, dict):
        entries = [encode_cbor(key) + encode_cbor(item) for key, item in value.items()]
        return encode_head(5, len(entries)) + b"".join(sorted(entries))
    raise TypeError(type(value))


def encode_uvarint(value):
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def package_car(value):
    block = encode_cbor(value)
    root = ONBOARDING.DAG_CBOR_CID_PREFIX + hashlib.sha256(block).digest()
    header = encode_cbor({"roots": [CidTag(root)], "version": 1})
    car = (
        encode_uvarint(len(header))
        + header
        + encode_uvarint(len(root) + len(block))
        + root
        + block
    )
    return car, "b" + base64.b32encode(root).decode("ascii").lower().rstrip("=")


class CommunityOnboardingTests(unittest.TestCase):
    def test_guides_require_canonical_and_participant_specific_live_proof(self):
        for guide_path in (QUICKSTART, COMMUNITY_GUIDE):
            guide = guide_path.read_text(encoding="utf-8")
            self.assertIn("--expected-ecosystem-cid", guide)
            self.assertIn("--candidate-ecosystem-car", guide)
            self.assertIn("--source-car", guide)
            self.assertIn("--probe-live", guide)
            self.assertIn("three", guide.lower())
            self.assertIn("fresh", guide.lower())
        quickstart = QUICKSTART.read_text(encoding="utf-8")
        self.assertIn("another miner's historical share", quickstart.lower())
        self.assertIn("before executing it", quickstart)
        community = COMMUNITY_GUIDE.read_text(encoding="utf-8")
        self.assertIn("another miner's historical share does not count", community)
        self.assertIn("pohw-governance.sha256", community)
        self.assertIn("--idena-api-key-file", community)
        self.assertLess(
            community.index("verify-idena-registry-deployment"),
            community.index("registerMiner("),
        )

    def test_profile_is_strict_and_bound_to_manifest_and_policy(self):
        profile = ONBOARDING._read_json(PROFILE, "profile")
        validated = ONBOARDING.validate_profile(profile, ROOT)
        self.assertEqual(validated["manifest"]["activation_id"], validated["policy"]["activation_id"])
        self.assertEqual(
            profile["live_success"]["checkpoint_height"],
            validated["manifest"]["consensus"]["replay_protection"]["signature_domain"][
                "activation_parent_height"
            ],
        )
        self.assertEqual(
            profile["live_success"]["checkpoint_hash"],
            validated["manifest"]["consensus"]["replay_protection"]["signature_domain"][
                "activation_parent_hash"
            ],
        )
        for schema_path in (PROFILE_SCHEMA, RECEIPT_SCHEMA):
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_unknown_profile_fields_fail_closed(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        profile["download_url"] = "https://example.invalid/binary"
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "unknown download_url"):
            ONBOARDING.validate_profile(profile, ROOT)

    def test_role_requirement_downgrade_fails_closed(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        profile["roles"]["pruned-miner"]["minimum_memory_gib"] = 1
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "reviewed profile"):
            ONBOARDING.validate_profile(profile, ROOT)

    def test_candidate_ecosystem_car_binds_source_and_all_runtime_artifacts(self):
        source_digest = hashlib.sha256(b"source tree").digest()
        artifacts = []
        for name in sorted(ONBOARDING.REQUIRED_RUNTIME_ARTIFACTS):
            payload = name.encode("ascii")
            digest = hashlib.sha256(payload).digest()
            artifacts.append(
                {
                    "name": name,
                    "cid": CidTag(ONBOARDING.RAW_CID_PREFIX + digest),
                    "sha256": digest.hex(),
                    "size": len(payload),
                }
            )
        manifest = {
            "schemaVersion": 1,
            "ecosystemId": "ubiubi18.pohw-testnet",
            "parentEcosystemCid": None,
            "repositories": [
                {
                    "schemaVersion": 1,
                    "name": "P2poolBTC",
                    "sourceTreeCid": CidTag(
                        ONBOARDING.DAG_CBOR_CID_PREFIX + source_digest
                    ),
                    "sourceTreeSha256": source_digest.hex(),
                    "gitBundleCid": None,
                    "gitCommitMetadata": "1" * 40,
                    "dependencyLocks": [],
                    "toolchainLocks": {},
                    "buildInstructions": ["cargo build --locked"],
                    "artifacts": artifacts,
                }
            ],
            "compatibilityPins": {},
            "toolchainLocks": {},
            "governanceContractVersion": "0.1.0",
            "governanceParameterSetCid": CidTag(
                ONBOARDING.DAG_CBOR_CID_PREFIX + hashlib.sha256(b"parameters").digest()
            ),
        }
        car, cid = package_car(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "ecosystem.car"
            path.write_bytes(car)
            bindings = ONBOARDING._extract_ecosystem_bindings(path, cid)
            self.assertEqual(bindings["ecosystem_cid"], cid)
            self.assertEqual(bindings["source_sha256"], source_digest.hex())
            self.assertEqual(
                set(bindings["artifacts"]), set(ONBOARDING.REQUIRED_RUNTIME_ARTIFACTS)
            )
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "launch-policy CID"):
                ONBOARDING._extract_ecosystem_bindings(path, ECOSYSTEM_CID)

    def test_partial_canonical_source_inputs_fail_closed(self):
        profile = ONBOARDING._read_json(PROFILE, "profile")
        validated = ONBOARDING.validate_profile(profile, ROOT)
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "supplied together"):
            ONBOARDING.verify_release(
                ROOT,
                validated,
                expected_ecosystem_cid=ECOSYSTEM_CID,
                readiness_car=None,
                readiness_evidence_car=None,
                candidate_ecosystem_car=pathlib.Path("candidate.car"),
                source_car=None,
                governance_cli=None,
                idena_anchor_policy=None,
                p2pool_node=None,
                idena_rpc_url="http://127.0.0.1:9009",
                idena_api_key_file=None,
                run_tests=False,
            )

    def test_canonical_source_verification_rejects_a_changed_source_car(self):
        source_car = pathlib.Path("source.car")
        ecosystem_car = pathlib.Path("ecosystem.car")
        source_digest = "4" * 64
        ecosystem_digest = "5" * 64
        artifacts = {
            name: {"cid": ECOSYSTEM_CID, "sha256": "6" * 64, "size": 1}
            for name in ONBOARDING.REQUIRED_RUNTIME_ARTIFACTS
        }
        bindings = {
            "ecosystem_cid": ECOSYSTEM_CID,
            "ecosystem_sha256": ecosystem_digest,
            "source_cid": ECOSYSTEM_CID,
            "source_sha256": source_digest,
            "source_commit": "1" * 40,
            "artifacts": artifacts,
        }
        repository = {
            "name": ONBOARDING.SOURCE_REPOSITORY,
            "sourceTreeCid": ECOSYSTEM_CID,
            "sourceTreeSha256": source_digest,
            "gitCommitMetadata": "1" * 40,
            "artifacts": [
                {"name": name, **artifact} for name, artifact in artifacts.items()
            ],
        }
        command_results = (
            {
                "schemaVersion": 1,
                "ecosystemCid": ECOSYSTEM_CID,
                "ecosystemSha256": ecosystem_digest,
                "carSha256": "7" * 64,
                "manifest": {"repositories": [repository]},
            },
            {
                "verified": True,
                "sourceTreeCid": ECOSYSTEM_CID,
                "sourceTreeSha256": source_digest,
                "repository": ONBOARDING.SOURCE_REPOSITORY,
                "files": 1,
                "localTreeMatch": True,
            },
        )
        source_hashes = iter((("8" * 64, 10), ("9" * 64, 10)))

        def hash_file(path, _label, _maximum):
            return next(source_hashes) if path == source_car else ("7" * 64, 20)

        policy = {
            "public_join_readiness": {
                "deployment_readiness_candidate_ecosystem_cid": ECOSYSTEM_CID
            }
        }
        with mock.patch.object(
            ONBOARDING, "_extract_ecosystem_bindings", return_value=bindings
        ), mock.patch.object(
            ONBOARDING, "_attested_command_json", side_effect=command_results
        ), mock.patch.object(
            ONBOARDING, "_hash_regular_file", side_effect=hash_file
        ), self.assertRaisesRegex(ONBOARDING.OnboardingError, "changed during"):
            ONBOARDING._verify_canonical_source(
                ROOT,
                policy,
                expected_ecosystem_cid=ECOSYSTEM_CID,
                candidate_ecosystem_car=ecosystem_car,
                source_car=source_car,
                governance_cli=pathlib.Path("pohw-governance"),
            )

    def test_onboarding_refuses_to_execute_repository_tests(self):
        profile = ONBOARDING._read_json(PROFILE, "profile")
        validated = ONBOARDING.validate_profile(profile, ROOT)
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "never executes"):
            ONBOARDING.verify_release(
                ROOT,
                validated,
                expected_ecosystem_cid=None,
                readiness_car=None,
                readiness_evidence_car=None,
                candidate_ecosystem_car=None,
                source_car=None,
                governance_cli=None,
                idena_anchor_policy=None,
                p2pool_node=None,
                idena_rpc_url="http://127.0.0.1:9009",
                idena_api_key_file=None,
                run_tests=True,
            )

    def test_ready_release_requires_exact_chain_backed_registry_verification(self):
        validated = ONBOARDING.validate_profile(
            ONBOARDING._read_json(PROFILE, "profile"), ROOT
        )
        validated = dict(validated)
        policy = json.loads(json.dumps(validated["policy"]))
        validated["policy"] = policy
        policy["status"] = ONBOARDING.READY_POLICY_STATUS
        readiness = policy["public_join_readiness"]
        for field in ONBOARDING.READINESS_BOOLEAN_FIELDS:
            readiness[field] = True
        readiness["verified_independent_registry_build_operators"] = readiness[
            "required_independent_registry_build_operators"
        ]
        policy["registry_source_candidate"]["deployment_authorized"] = True
        p2pool_node = pathlib.Path("/attested/p2pool-node")
        anchor = pathlib.Path("/verified/idena-anchor-policy.json")
        api_key = pathlib.Path("/private/idena-api.key")
        source_binding = {
            "ecosystem_cid": ECOSYSTEM_CID,
            "source_cid": ECOSYSTEM_CID,
            "source_car_sha256": "3" * 64,
            "source_commit_matches": True,
            "governance_cli_verified": True,
            "artifacts": {
                "pohw-governance": {"sha256": "1" * 64, "size": 1, "cid": ECOSYSTEM_CID},
                "p2pool-node": {"sha256": "2" * 64, "size": 1, "cid": ECOSYSTEM_CID}
            },
        }
        exact = b"Idena registry deployment verified against synchronized local RPC\n"
        for stdout, expected_ready in ((exact, True), (exact + b"extra\n", False)):
            with self.subTest(stdout=stdout), mock.patch.object(
                ONBOARDING, "_static_policy_bindings_verified", return_value=True
            ), mock.patch.object(
                ONBOARDING, "_git_source_state", return_value=("1" * 40, True)
            ), mock.patch.object(
                ONBOARDING, "_verify_canonical_source", return_value=source_binding
            ), mock.patch.object(
                ONBOARDING, "_command_succeeded", return_value=True
            ), mock.patch.object(
                ONBOARDING,
                "_run_attested_command",
                return_value=subprocess.CompletedProcess([], 0, stdout, b""),
            ) as run_attested:
                release = ONBOARDING.verify_release(
                    ROOT,
                    validated,
                    expected_ecosystem_cid=ECOSYSTEM_CID,
                    readiness_car=pathlib.Path("readiness.car"),
                    readiness_evidence_car=pathlib.Path("readiness-evidence.car"),
                    candidate_ecosystem_car=pathlib.Path("ecosystem.car"),
                    source_car=pathlib.Path("source.car"),
                    governance_cli=pathlib.Path("pohw-governance"),
                    idena_anchor_policy=anchor,
                    p2pool_node=p2pool_node,
                    idena_rpc_url="http://127.0.0.1:9009",
                    idena_api_key_file=api_key,
                    run_tests=False,
                )
            self.assertEqual(release["registry_chain_verified"], expected_ready)
            self.assertEqual(release["public_join_ready"], expected_ready)
            run_attested.assert_called_once_with(
                p2pool_node,
                "p2pool-node",
                source_binding["artifacts"]["p2pool-node"],
                (
                    "verify-idena-registry-deployment",
                    "--idena-anchor-policy",
                    str(anchor),
                    "--idena-rpc-url",
                    "http://127.0.0.1:9009",
                    "--idena-api-key-file",
                    str(api_key),
                ),
                ROOT,
                timeout=60,
            )

    def test_execute_rejects_substituted_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            substitute = root / "weaker-profile.json"
            substitute.write_bytes(PROFILE.read_bytes())
            arguments = args_for("observer", root / "receipt")
            arguments.profile = substitute
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "canonical"):
                ONBOARDING.execute(
                    arguments,
                    host_inspector=lambda *_: good_host(),
                    release_verifier=lambda *_args, **_kwargs: verified_release(ready=False),
                )

    def test_execute_rejects_output_inside_source_checkout(self):
        arguments = args_for("observer", ROOT / "onboarding-output-must-not-exist")
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "outside"):
            ONBOARDING.execute(
                arguments,
                host_inspector=lambda *_: good_host(),
                release_verifier=lambda *_args, **_kwargs: verified_release(ready=False),
            )

    def test_git_source_state_rejects_assume_unchanged_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            tracked = repository / "tracked.txt"
            tracked.write_text("original\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "update-index", "--assume-unchanged", "tracked.txt"],
                check=True,
            )
            tracked.write_text("hidden edit\n", encoding="utf-8")
            _commit, clean = ONBOARDING._git_source_state(repository)
            self.assertFalse(clean)

    def test_observer_can_rehearse_while_public_join_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt, paths, exit_code = ONBOARDING.execute(
                args_for("observer", pathlib.Path(temporary) / "receipt"),
                host_inspector=lambda *_: good_host(),
                release_verifier=lambda *_args, **_kwargs: verified_release(ready=False),
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(receipt["journey_status"], "review-ready")
        self.assertEqual(
            [stage["status"] for stage in receipt["stages"]],
            ["passed", "not-required", "not-required", "not-required", "passed"],
        )
        self.assertEqual(set(paths), {"receipt", "report", "issue"})

    def test_miner_stops_before_identity_while_public_join_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            live_prober = mock.Mock(side_effect=AssertionError("live probe must not run"))
            receipt, _paths, exit_code = ONBOARDING.execute(
                args_for("pruned-miner", pathlib.Path(temporary) / "receipt"),
                host_inspector=lambda *_: good_host(),
                release_verifier=lambda *_args, **_kwargs: verified_release(ready=False),
                live_prober=live_prober,
            )
        self.assertEqual(exit_code, 2)
        self.assertEqual(receipt["journey_status"], "blocked-public-join")
        self.assertEqual(receipt["stages"][2]["status"], "blocked")
        self.assertIn("external-security-review-passed", receipt["next_action_codes"])
        live_prober.assert_not_called()

    def test_explicit_live_probe_is_refused_before_ready_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            live_prober = mock.Mock(side_effect=AssertionError("live probe must not run"))
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "not ready"):
                ONBOARDING.execute(
                    args_for(
                        "pruned-miner",
                        pathlib.Path(temporary) / "receipt",
                        probe_live=True,
                    ),
                    host_inspector=lambda *_: good_host(),
                    release_verifier=lambda *_args, **_kwargs: verified_release(ready=False),
                    live_prober=live_prober,
                )
            live_prober.assert_not_called()

    def test_ready_policy_without_authenticated_registry_chain_proof_stays_blocked(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        release = verified_release(ready=True, registry_chain_verified=False)
        release["public_join_ready"] = False
        release["missing_release_gates"] = ["registry-chain-verification"]
        receipt = ONBOARDING.build_receipt(
            role_name="pruned-miner",
            role=profile["roles"]["pruned-miner"],
            release=release,
            host=good_host(),
            live=None,
            live_policy=profile["live_success"],
        )
        ONBOARDING.validate_receipt(receipt)
        self.assertEqual(receipt["journey_status"], "blocked-public-join")
        self.assertEqual(receipt["stages"][1]["status"], "blocked")
        self.assertIn("registry-chain-verification", receipt["next_action_codes"])

    def test_explicit_live_probe_is_refused_on_ineligible_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            live_prober = mock.Mock(side_effect=AssertionError("live probe must not run"))
            failed_host = good_host()
            failed_host["eligible_for_role"] = False
            failed_host["failed_checks"] = ["insufficient-storage"]
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "host"):
                ONBOARDING.execute(
                    args_for(
                        "pruned-miner",
                        pathlib.Path(temporary) / "receipt",
                        probe_live=True,
                    ),
                    host_inspector=lambda *_: failed_host,
                    release_verifier=lambda *_args, **_kwargs: verified_release(ready=True),
                    live_prober=live_prober,
                )
            live_prober.assert_not_called()

    def test_receipt_contains_no_private_context(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        live = good_live(profile)
        receipt = ONBOARDING.build_receipt(
            role_name="pruned-miner",
            role=profile["roles"]["pruned-miner"],
            release=verified_release(ready=True),
            host=good_host(),
            live=live,
            live_policy=profile["live_success"],
        )
        ONBOARDING.validate_receipt(receipt)
        encoded = json.dumps(receipt)
        for forbidden in (
            "0xcbd39",
            "genesis-01",
            "127.0.0.1",
            "/srv/",
            '"cookie":',
            '"wallet":',
            '"private_key":',
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(receipt["journey_status"], "live-join-verified")
        self.assertTrue(all(value is False for value in receipt["privacy"].values()))

    def test_verified_receipt_requires_source_car_digest(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        release = verified_release(ready=True)
        release["source_car_sha256"] = None
        receipt = ONBOARDING.build_receipt(
            role_name="observer",
            role=profile["roles"]["observer"],
            release=release,
            host=good_host(),
            live=None,
            live_policy=profile["live_success"],
        )
        with self.assertRaisesRegex(ONBOARDING.OnboardingError, "proof is incomplete"):
            ONBOARDING.validate_receipt(receipt)

    def test_global_history_cannot_substitute_for_this_miners_fresh_share(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        live = good_live(profile)
        live["active_shares"] = 1000
        live["miner_active_shares"] = 0
        live["miner_share_age_seconds"] = None
        self.assertFalse(ONBOARDING._live_succeeded(live, profile["live_success"]))
        live = good_live(profile)
        live["miner_share_age_seconds"] = (
            profile["live_success"]["maximum_miner_share_age_seconds"] + 1
        )
        self.assertFalse(ONBOARDING._live_succeeded(live, profile["live_success"]))

    def test_core_peer_snapshot_and_tip_thresholds_are_independent(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        for field, value in (
            ("bitcoin_peers", 0),
            ("snapshot_voters", 0),
            (
                "core_tip_age_seconds",
                profile["live_success"]["maximum_core_tip_age_seconds"] + 1,
            ),
        ):
            with self.subTest(field=field):
                live = good_live(profile)
                live[field] = value
                self.assertFalse(
                    ONBOARDING._live_succeeded(live, profile["live_success"])
                )

    def test_core_profile_mismatch_is_rejected(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        validated = ONBOARDING.validate_profile(profile, ROOT)
        expected = validated["core_expectations"]
        self.assertTrue(ONBOARDING._core_profile_matches(dict(expected), expected))
        changed = dict(expected)
        changed["fork_height"] = expected["fork_height"] + 1
        self.assertFalse(ONBOARDING._core_profile_matches(changed, expected))

    def test_live_probe_reduces_sensitive_node_output_to_aggregates(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        validated = ONBOARDING.validate_profile(profile, ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            storage = pathlib.Path(temporary)
            p2pool = storage / "p2pool"
            snapshots = storage / "snapshots"
            bitcoin = storage / "bitcoin"
            for directory in (p2pool, snapshots, bitcoin):
                directory.mkdir()
            cookie = bitcoin / ".cookie"
            cookie.write_text("private-cookie", encoding="ascii")
            namespace = args_for("pruned-miner", pathlib.Path("unused"), probe_live=True)
            namespace.storage_path = storage
            namespace.p2pool_node = storage / "p2pool-node"
            namespace.p2pool_datadir = p2pool
            namespace.snapshot_dir = snapshots
            namespace.miner_id = "private-miner"
            namespace.bitcoin_cli = storage / "bitcoin-cli"
            namespace.bitcoin_datadir = bitcoin
            namespace.bitcoin_cookie_file = cookie

            preflight = {
                "readiness": {
                    "has_registered_miner": True,
                    "has_snapshot": True,
                    "has_accepted_bitcoin_work_template": True,
                    "has_share_tip": True,
                },
                "local": {"replay": {"active_share_count": 4}},
                "miner_registration": {
                    "miner_id": "private-miner",
                    "idena_address": "0x" + "11" * 20,
                },
                "miner_activity": {
                    "active_share_count": 1,
                    "latest_active_share_height": 4,
                    "latest_template_created_at_unix": int(time.time()) - 30,
                },
                "peer_inventory_probe": [
                    {"peer_addr": "203.0.113.1:40406", "reachable": True},
                    {"peer_addr": "203.0.113.2:40406", "reachable": False},
                ],
            }
            snapshot = {
                "schema_version": "pohw-mining-snapshot-evidence/v1",
                "miner_eligible": True,
                "distinct_voter_count": profile["live_success"]["minimum_snapshot_voters"],
            }
            best_hash = "ab" * 32
            chain = {
                "chain": "pohw",
                "blocks": 958200,
                "headers": 958200,
                "bestblockhash": best_hash,
                "initialblockdownload": False,
                "verificationprogress": 1.0,
                "pohw_experiment": validated["core_expectations"],
            }

            def command_result(command, **_kwargs):
                if "multinode-preflight" in command:
                    payload = preflight
                elif "mining-snapshot-evidence" in command:
                    payload = snapshot
                elif "getblockchaininfo" in command:
                    payload = chain
                elif "getnetworkinfo" in command:
                    payload = {"connections": 2}
                elif "getblockheader" in command:
                    payload = {"height": 958200, "time": int(time.time()) - 60}
                elif "getblockhash" in command:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        (profile["live_success"]["checkpoint_hash"] + "\n").encode(),
                        b"",
                    )
                else:
                    raise AssertionError(command)
                return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode(), b"")

            bitcoind_arguments = (
                str(storage / "bitcoind"),
                f"-datadir={bitcoin.resolve()}",
                "-chain=pohw",
                "-daemon=0",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
            )
            bitcoind_process = (
                storage / "bitcoind",
                bitcoind_arguments,
                1234,
                5678,
            )
            @contextlib.contextmanager
            def staged(path, *_args):
                yield ONBOARDING.StagedExecutable(str(path))

            with mock.patch.object(
                ONBOARDING, "_stage_attested_executable", side_effect=staged
            ), mock.patch.object(
                ONBOARDING,
                "_running_systemd_process",
                return_value=bitcoind_process,
            ) as running_process, mock.patch.object(
                ONBOARDING, "_verify_running_executable"
            ) as running_verifier, mock.patch.object(
                ONBOARDING, "_verify_local_rpc_listener"
            ) as listener_verifier, mock.patch.object(
                ONBOARDING, "run_command", side_effect=command_result
            ):
                live = ONBOARDING.probe_live(
                    namespace,
                    ROOT,
                    profile["live_success"],
                    validated["core_expectations"],
                    verified_release(ready=True),
                )
            self.assertEqual(running_process.call_count, 2)
            self.assertEqual(running_verifier.call_count, 2)
            self.assertEqual(listener_verifier.call_count, 2)
            changed_process = (*bitcoind_process[:2], 1235, 5679)
            with mock.patch.object(
                ONBOARDING, "_stage_attested_executable", side_effect=staged
            ), mock.patch.object(
                ONBOARDING,
                "_running_systemd_process",
                side_effect=(bitcoind_process, changed_process),
            ), mock.patch.object(
                ONBOARDING, "_verify_running_executable"
            ), mock.patch.object(
                ONBOARDING, "_verify_local_rpc_listener"
            ), mock.patch.object(
                ONBOARDING, "run_command", side_effect=command_result
            ), self.assertRaisesRegex(ONBOARDING.OnboardingError, "changed during"):
                ONBOARDING.probe_live(
                    namespace,
                    ROOT,
                    profile["live_success"],
                    validated["core_expectations"],
                    verified_release(ready=True),
                )
        self.assertEqual(live["reachable_gossip_peers"], 1)
        self.assertEqual(live["active_shares"], 4)
        self.assertEqual(live["miner_active_shares"], 1)
        self.assertTrue(live["core_profile_verified"])
        encoded = json.dumps(live)
        for forbidden in ("private-miner", "203.0.113", "/secret", "0x1111"):
            self.assertNotIn(forbidden, encoded)

    def test_bitcoin_core_profile_rejects_conflicting_or_extra_arguments(self):
        datadir = pathlib.Path("/srv/bitcoin/pohw")
        reviewed = (
            "/usr/local/bin/bitcoind",
            f"-datadir={datadir}",
            "-chain=pohw",
            "-daemon=0",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
        )
        ONBOARDING._validate_bitcoind_arguments(reviewed, datadir)
        for extra in (
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            "-datadir=/tmp/substituted",
            "-conf=/tmp/substituted.conf",
        ):
            with self.subTest(extra=extra), self.assertRaisesRegex(
                ONBOARDING.OnboardingError, "exact reviewed profile"
            ):
                ONBOARDING._validate_bitcoind_arguments((*reviewed, extra), datadir)

    def test_bitcoin_rpc_listener_proof_requires_loopback_on_the_configured_port(self):
        descriptor = pathlib.Path("/proc/123/fd/7")

        def verify_with(entries):
            with mock.patch.object(
                pathlib.Path, "iterdir", return_value=iter((descriptor,))
            ), mock.patch.object(
                ONBOARDING.os, "readlink", return_value="socket:[42]"
            ), mock.patch.object(
                ONBOARDING,
                "_read_proc_network_table",
                side_effect=(entries, []),
            ):
                ONBOARDING._verify_local_rpc_listener(123, 18443)

        verify_with([("0100007F", 18443, "42")])
        verify_with([("00000000000000000000000001000000", 18443, "42")])
        self.assertTrue(
            ONBOARDING._proc_address(
                "00000000000000000000000001000000"
            ).is_loopback
        )
        for entries in (
            [("00000000", 18443, "42")],
            [("0100007F", 18444, "42")],
            [("0100007F", 18443, "99")],
        ):
            with self.subTest(entries=entries), self.assertRaisesRegex(
                ONBOARDING.OnboardingError, "exclusively to loopback"
            ):
                verify_with(entries)

    @unittest.skipUnless(sys.platform.startswith("linux"), "sealed executable snapshots require Linux")
    def test_attested_execution_uses_a_snapshot_when_source_path_is_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "reviewed-tool"
            original = b"#!/bin/sh\nprintf 'reviewed\\n'\n"
            source.write_bytes(original)
            source.chmod(0o700)
            expected = {
                "sha256": hashlib.sha256(original).hexdigest(),
                "size": len(original),
            }
            with ONBOARDING._stage_attested_executable(
                source, "reviewed tool", expected
            ) as staged:
                source.write_text("#!/bin/sh\nprintf 'substituted\\n'\n", encoding="ascii")
                source.chmod(0o700)
                result = ONBOARDING.run_command(
                    (staged.command_path,), cwd=ROOT, pass_fds=staged.pass_fds
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"reviewed\n")

    def test_attested_execution_fails_closed_without_linux_sealing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "reviewed-tool"
            payload = b"#!/bin/sh\nexit 0\n"
            source.write_bytes(payload)
            source.chmod(0o700)
            expected = {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            with mock.patch.object(ONBOARDING.platform, "system", return_value="Darwin"):
                with self.assertRaisesRegex(
                    ONBOARDING.OnboardingError, "supported only on Linux"
                ):
                    with ONBOARDING._stage_attested_executable(
                        source, "reviewed tool", expected
                    ):
                        self.fail("non-Linux staging must not yield an executable")

    def test_html_escapes_report_content(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        receipt = ONBOARDING.build_receipt(
            role_name="observer",
            role=profile["roles"]["observer"],
            release=verified_release(ready=False),
            host=good_host(),
            live=None,
            live_policy=profile["live_success"],
        )
        receipt["next_action_codes"] = ["<script>alert(1)</script>"]
        rendered = ONBOARDING.render_html(receipt)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn("default-src 'none'", rendered)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)

    def test_issue_report_binds_canonical_source_and_car_without_local_paths(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        receipt = ONBOARDING.build_receipt(
            role_name="observer",
            role=profile["roles"]["observer"],
            release=verified_release(ready=True),
            host=good_host(),
            live=None,
            live_policy=profile["live_success"],
        )
        rendered = ONBOARDING.render_issue_report(receipt)
        self.assertIn(f"Canonical source CID: `{ECOSYSTEM_CID}`", rendered)
        self.assertIn(f"Source CAR SHA-256: `{'3' * 64}`", rendered)
        self.assertIn("Git commit metadata: `", rendered)
        self.assertNotIn(str(ROOT), rendered)
        self.assertNotIn("Exact source commit", rendered)

    def test_html_report_exposes_authoritative_source_binding(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        receipt = ONBOARDING.build_receipt(
            role_name="observer",
            role=profile["roles"]["observer"],
            release=verified_release(ready=True),
            host=good_host(),
            live=None,
            live_policy=profile["live_success"],
        )
        rendered = ONBOARDING.render_html(receipt)
        self.assertIn("Verified release binding", rendered)
        self.assertIn(ECOSYSTEM_CID, rendered)
        self.assertIn("3" * 64, rendered)
        self.assertIn("The source CID and CAR digest are authoritative", rendered)
        self.assertIn("Registry chain verification", rendered)
        self.assertNotIn(str(ROOT), rendered)

    def test_output_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "symlink"):
                ONBOARDING._prepare_output_dir(link)

    def test_host_check_fails_when_declared_storage_path_does_not_exist(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            missing = pathlib.Path(temporary) / "missing"
            host = ONBOARDING.inspect_host(profile["roles"]["observer"], missing, ROOT)
        self.assertFalse(host["storage_path_verified"])
        self.assertFalse(host["eligible_for_role"])
        self.assertIn("storage-path-unavailable", host["failed_checks"])

    def test_storage_root_need_not_be_writable_by_the_operator_account(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            ONBOARDING.os, "access", return_value=True
        ) as access:
            root = pathlib.Path(temporary).resolve()
            self.assertEqual(ONBOARDING._verified_storage_path(root), root)
        access.assert_called_once_with(root, ONBOARDING.os.R_OK | ONBOARDING.os.X_OK)

    def test_command_output_is_killed_at_the_memory_bound(self):
        with mock.patch.object(ONBOARDING, "MAX_COMMAND_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(ONBOARDING.OnboardingError, "excessive output"):
                ONBOARDING.run_command(
                    (
                        sys.executable,
                        "-c",
                        "import os; os.write(1, b'x' * 65536)",
                    ),
                    cwd=ROOT,
                    timeout=10,
                )

    def test_wrapper_is_source_only_and_has_no_side_effect_commands(self):
        subprocess.run(["bash", "-n", str(SHELL)], check=True)
        source = SHELL.read_text(encoding="utf-8")
        self.assertIn("pohw-community-onboarding.py", source)
        self.assertIn('"$@" --repo-root "${REPO_ROOT}"', source)
        for forbidden in (
            "curl ",
            "wget ",
            "eval ",
            "systemctl start",
            "systemctl enable",
            "docker run",
            "tailscale",
        ):
            self.assertNotIn(forbidden, source)

    def test_powershell_wrapper_uses_the_same_source_only_state_machine(self):
        source = POWERSHELL.read_text(encoding="utf-8")
        self.assertIn("pohw-community-onboarding.py", source)
        self.assertIn("--repo-root", source)
        self.assertIn("@args", source)
        self.assertLess(source.index("@args"), source.index("--repo-root"))
        for forbidden in (
            "Invoke-WebRequest",
            "Start-Service",
            "Set-Service",
            "Start-Process",
            "DownloadFile",
        ):
            self.assertNotIn(forbidden, source)

    def test_public_issue_form_accepts_redacted_onboarding_status(self):
        source = ISSUE_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("Onboarding or host readiness", source)
        self.assertIn("id: onboarding_status", source)
        self.assertIn("blocked-public-join", source)
        self.assertIn("id: onboarding_actions", source)
        self.assertIn("never paste a path, address, endpoint, or raw log", source)

    def test_cli_help_explains_read_only_guard(self):
        result = subprocess.run(
            [str(SHELL), "--help"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn("intentionally read-only", result.stdout)
        self.assertIn("policy must already be ready", result.stdout)

    def test_default_python_path_has_no_network_fetcher(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('("cargo", "test"', source)
        self.assertIn("onboarding never executes repository tests", source)
        for forbidden in (
            "import requests",
            "import socket",
            "import urllib",
            "urlopen(",
            "curl ",
            "wget ",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
