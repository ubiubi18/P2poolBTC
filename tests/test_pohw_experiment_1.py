import copy
import hashlib
import importlib.util
import json
import stat
import subprocess
import unittest
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "compatibility" / "experiment-1-full-consensus.json"
LAUNCH_POLICY_PATH = ROOT / "compatibility" / "experiment-1-launch-policy.json"
IDENA_POLICY_SCHEMA_PATH = ROOT / "schemas" / "pohw" / "IdenaAnchorPolicyV2.schema.json"
VALIDATOR_PATH = ROOT / "scripts" / "pohw-experiment-1-manifest.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("pohw_experiment_1_manifest", VALIDATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Experiment1ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_tracked_manifest_and_patch_verify(self):
        result = subprocess.run(
            [
                "python3",
                str(VALIDATOR_PATH),
                "verify",
                str(MANIFEST_PATH),
                "--repo-root",
                str(ROOT),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("manifest verified", result.stdout)

    def test_launch_policy_blocks_unverified_registry_deployment(self):
        policy = json.loads(LAUNCH_POLICY_PATH.read_text(encoding="utf-8"))
        manifest_bytes = MANIFEST_PATH.read_bytes()

        self.assertEqual(policy["activation_id"], self.manifest["activation_id"])
        self.assertEqual(policy["fork_manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        self.assertEqual(policy["status"], "blocked-pending-idena-registry-deployment")
        self.assertIsNone(policy["registry_deployment"])
        self.assertEqual(policy["idena_anchor_policy_schema"], 2)
        self.assertEqual(
            policy["required_handoff_version_bit"],
            self.manifest["consensus"]["proof_of_work"]["handoff_version_bit"],
        )
        gates = policy["required_runtime_gates"]
        self.assertTrue(gates["idena_anchor_policy_required"])
        self.assertTrue(gates["peer_work_template_admission_required"])
        self.assertTrue(gates["registry_deployment_verification_required"])
        self.assertTrue(gates["registry_registration_identity_callback_required"])
        self.assertTrue(gates["checkpoint_vote_identity_callback_required"])
        self.assertTrue(gates["production_idena_wasm_runtime_gate_required"])
        self.assertFalse(gates["bound_policy_replacement_allowed"])

        candidate_binding = policy["registry_source_candidate"]
        candidate_path = ROOT / candidate_binding["path"]
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        artifact = candidate["artifact"]
        artifact_path = ROOT / artifact["path"]
        self.assertEqual(
            candidate_binding["sha256"],
            hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(candidate_binding["contract_schema_version"], 3)
        self.assertEqual(candidate_binding["contract_version"], "0.3.0")
        self.assertEqual(candidate_binding["wasm_sha256"], artifact["sha256"])
        self.assertEqual(candidate_binding["wasm_cid"], artifact["cid"])
        self.assertFalse(candidate_binding["deployment_authorized"])
        if artifact_path.exists():
            self.assertEqual(hashlib.sha256(artifact_path.read_bytes()).hexdigest(), artifact["sha256"])
            self.assertEqual(artifact_path.stat().st_size, artifact["size"])

    def test_v2_idena_policy_schema_has_no_target_selected_throttle(self):
        schema = json.loads(IDENA_POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
        required = set(schema["required"])

        self.assertEqual(schema["properties"]["schema_version"]["const"], 2)
        self.assertIn("handoff_version_bit", required)
        self.assertIn("registry_deployment_payload_sha256", required)
        self.assertNotIn("bootstrap_share_target_floor", required)

    def test_manifest_parser_rejects_duplicate_keys(self):
        raw = MANIFEST_PATH.read_text(encoding="utf-8")
        duplicate = raw.replace(
            '"schema_version": "pohw-bitcoin-core-fork-manifest/v1",',
            '"schema_version": "wrong",\n  "schema_version": "pohw-bitcoin-core-fork-manifest/v1",',
            1,
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "duplicate.json"
            path.write_text(duplicate, encoding="utf-8")
            result = subprocess.run(
                ["python3", str(VALIDATOR_PATH), "verify", str(path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON key", result.stderr)

    def test_manifest_requires_exact_build_flags(self):
        tampered = copy.deepcopy(self.manifest)
        tampered["build"]["cmake_flags"][0] = "-DBUILD_GUI=ON"
        with self.assertRaisesRegex(self.validator.ManifestError, "CMake flags"):
            self.validator.validate(tampered, ROOT, verify_patch=False)

    def test_full_script_surface_and_inherited_spends_are_mandatory(self):
        consensus = self.manifest["consensus"]
        self.assertTrue(consensus["all_upstream_transaction_and_script_rules_enabled"])
        self.assertTrue(consensus["inherited_utxo_spending_enabled"])
        self.assertIn("taproot-script-path-and-tapscript", consensus["supported_transaction_and_script_classes"])
        self.assertIn("p2sh-and-arbitrary-redeem-scripts", consensus["supported_transaction_and_script_classes"])

        tampered = copy.deepcopy(self.manifest)
        tampered["consensus"]["inherited_utxo_spending_enabled"] = False
        with self.assertRaisesRegex(self.validator.ManifestError, "inherited UTXO"):
            self.validator.validate(tampered, ROOT, verify_patch=False)

    def test_experiment_zero_is_not_reinterpreted(self):
        self.assertFalse(self.manifest["predecessor"]["history_reinterpreted"])
        self.assertNotEqual(
            self.manifest["activation_id"],
            self.manifest["predecessor"]["activation_id"],
        )

    def test_revision_pins_the_existing_first_fork_block(self):
        self.assertEqual(self.manifest["profile_revision"], 2)
        self.assertNotEqual(
            self.manifest["activation_id"],
            self.manifest["supersedes_activation_id"],
        )
        fork = self.manifest["fork_point"]
        self.assertEqual(fork["first_fork_height"], fork["inherited_tip_height"] + 1)
        self.assertRegex(fork["first_fork_hash"], r"^[0-9a-f]{64}$")

        tampered = copy.deepcopy(self.manifest)
        tampered["fork_point"]["first_fork_hash"] = "00" * 32
        with self.assertRaisesRegex(self.validator.ManifestError, "live history"):
            self.validator.validate(tampered, ROOT, verify_patch=False)

    def test_patch_contains_consensus_enforcement_not_only_metadata(self):
        patch_path = ROOT / self.manifest["build"]["patch_path"]
        patch = patch_path.read_text(encoding="utf-8")
        for marker in (
            "CheckPoHWForkReplayProtection",
            "IsBlockFileMessageStart",
            "FindAnyByte",
            "bad-pohw-replay-unprotected",
            "bad-pohw-fork-point",
            "wrong_first_fork_block",
            "pohw_first_fork_hash",
            "coin->IsCoinBase() && coin->out.nValue == 0",
            "replay_rule_changes_for_next_block",
            "m_mempool->removeForReorg(m_chain, replay_invalid)",
            "A reorg can cross the PoHW replay-marker activation boundary",
            "bad-pohw-handoff-version",
            "ComputePoHWBlockVersion",
            "consensusParams.fPowAllowMinDifficultyBlocks || consensusParams.pohw_experiment",
            "POHW_update_time_refreshes_template_difficulty",
        ):
            self.assertIn(marker, patch)

    def test_service_cannot_accidentally_start_mainnet(self):
        unit = (ROOT / "deploy/systemd/bitcoind-pohw-experiment-1.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("-chain=pohw", unit)
        self.assertIn("-rpcbind=127.0.0.1", unit)
        self.assertIn("ConditionPathExists=/srv/bitcoin/pohw/bitcoin.conf", unit)
        self.assertNotIn("chainstate/CURRENT", unit)
        self.assertNotIn("-chain=main", unit)
        self.assertNotIn("8332", unit)

        adapter_dropin = (
            ROOT / "deploy/systemd/pohw-mining-experiment-1.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("Requires=bitcoind-pohw-experiment-1.service", adapter_dropin)
        self.assertIn("SupplementaryGroups=bitcoin-pohw-rpc", adapter_dropin)
        self.assertIn("enable-experiment-1-mining", adapter_dropin)
        self.assertNotIn("enable-experiment-0-mining", adapter_dropin)

        gossip_dropin = (
            ROOT / "deploy/systemd/pohw-gossip-experiment-1.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("Requires=bitcoind-pohw-experiment-1.service", gossip_dropin)
        self.assertIn("SupplementaryGroups=bitcoin-pohw-rpc", gossip_dropin)
        self.assertIn("enable-experiment-1-mining", gossip_dropin)
        self.assertNotIn("enable-experiment-0-mining", gossip_dropin)

    def test_public_templates_do_not_contain_credentials(self):
        for relative in (
            "deploy/bitcoin/bitcoin-pohw-experiment-1.conf.example",
            "deploy/pohw-experiment-1.env.example",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8").lower()
            self.assertNotIn("rpcpassword=", text)
            self.assertNotIn("private_key", text)
            self.assertNotRegex(text, r"(?m)^[a-z0-9_]*api_key\s*=\s*[^#\s]")

    def test_public_runbooks_disclose_both_live_value_boundaries(self):
        for relative in (
            "README.md",
            "EXPERIMENT-1.md",
            "SECURITY.md",
            "BETA-TESTING.md",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8").lower()
            self.assertIn("inherited", text, relative)
            self.assertIn("mainnet", text, relative)
            self.assertIn("idena", text, relative)
            self.assertIn("live", text, relative)
            self.assertIn("private key", text, relative)

    def test_stratum_acceptance_tool_is_bounded_and_documented(self):
        script = ROOT / "scripts" / "pohw-stratum-smoke-mine.py"
        self.assertTrue(stat.S_IMODE(script.stat().st_mode) & stat.S_IXUSR)
        source = script.read_text(encoding="utf-8")
        self.assertIn("MAX_HASHES_LIMIT", source)
        self.assertIn("is_loopback", source)
        self.assertIn("MAX_JSON_LINE_BYTES", source)
        runbook = (ROOT / "EXPERIMENT-1.md").read_text(encoding="utf-8")
        self.assertIn("pohw-stratum-smoke-mine.py", runbook)

    def test_installer_rebuilds_or_revalidates_before_atomic_install(self):
        source = (ROOT / "scripts" / "pohw-install-bitcoin-core-fork.sh").read_text(
            encoding="utf-8"
        )
        build_call = source.index('"$SCRIPT_DIR/pohw-build-bitcoin-core-fork.sh"')
        evidence_call = source.index("pohw-bitcoin-core-build-evidence.py\" verify")
        install_call = source.index("Copy each provenance-bound file")
        self.assertLess(build_call, evidence_call)
        self.assertLess(evidence_call, install_call)
        self.assertIn("install path contains a symlink", source)
        self.assertIn("--use-verified-build is intentionally disabled", source)
        self.assertIn("pohw-bitcoin-core-build-evidence/v4", source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn('run_as_build_user "$SCRIPT_DIR/pohw-build-bitcoin-core-fork.sh"', source)
        self.assertIn("verify_exact_patched_source", source)
        self.assertIn("pohw-verify-bitcoin-core-source.sh", source)
        self.assertIn('systemctl is-active --quiet -- "$SERVICE_NAME"', source)
        self.assertIn('mktemp -d "$INSTALL_PARENT/', source)
        self.assertIn('chmod 0755 "$STAGING"', source)
        self.assertIn('mv -- "$STAGING" "$INSTALL_ROOT"', source)
        self.assertIn("restored the previous service state", source)
        self.assertIn("pohw-experiment-1-replay-probe", source)
        self.assertIn("pohw-experiment-1-wallet-acceptance", source)

    def test_wallet_psbt_acceptance_is_no_broadcast_and_documented(self):
        script = ROOT / "scripts" / "pohw-experiment-1-wallet-acceptance.py"
        self.assertTrue(stat.S_IMODE(script.stat().st_mode) & stat.S_IXUSR)
        source = script.read_text(encoding="utf-8")
        self.assertIn("testmempoolaccept", source)
        self.assertIn("extract_marker_finalized_transaction", source)
        self.assertIn('print("broadcast=false")', source)
        self.assertNotIn("sendrawtransaction", source)
        runbook = (ROOT / "EXPERIMENT-1.md").read_text(encoding="utf-8")
        self.assertIn("pohw-experiment-1-wallet-acceptance", runbook)
        self.assertIn("not a general-purpose", runbook)

    def test_build_runs_template_difficulty_regression_explicitly(self):
        source = (ROOT / "scripts" / "pohw-build-bitcoin-core-fork.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "pow_tests/POHW_update_time_refreshes_template_difficulty",
            source,
        )
        self.assertIn("run_step depends_fetch", source)
        self.assertIn("download-one", source)
        self.assertIn("run_step depends_build", source)
        self.assertIn("depends-prepare", source)
        self.assertIn("depends-metadata", source)
        self.assertIn('--toolchain "$DEPENDS_PREFIX/toolchain.cmake"', source)
        self.assertIn("-ffile-prefix-map=$SNAPSHOT_DIR=/pohw/source", source)
        self.assertIn("-ffile-prefix-map=$BUILD_DIR=/pohw/build", source)
        self.assertIn('--env "CFLAGS=$PREFIX_MAP_FLAGS"', source)
        self.assertIn('--env "CXXFLAGS=$PREFIX_MAP_FLAGS"', source)
        self.assertIn("LDFLAGS=-Wl,-no_uuid", source)
        self.assertIn("run_step install", source)
        self.assertIn('"$CMAKE" --install "$BUILD_DIR"', source)
        self.assertIn("--strip", source)
        self.assertIn('TEST_TMPDIR=$(mktemp -d "$BUILD_DIR/', source)
        self.assertIn('run_step ctest --env "TMPDIR=$TEST_TMPDIR"', source)

    def test_source_verifier_uses_an_isolated_git_index(self):
        source = (ROOT / "scripts" / "pohw-verify-bitcoin-core-source.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('TEMP_GIT="$TMP_ROOT/object-db.git"', source)
        self.assertIn('TEMP_INDEX=$(mktemp "$TMP_ROOT/index.', source)
        self.assertIn('GIT_INDEX_FILE="$TEMP_INDEX"', source)
        self.assertIn('git init -q --bare --template="$TMP_ROOT/empty-template"', source)
        self.assertIn('"${GIT[@]}" read-tree "$UPSTREAM_COMMIT"', source)
        self.assertNotIn('git -C "$SOURCE_DIR" add --intent-to-add', source)

    def test_bootstrap_checks_offline_tip_while_holding_copy_lock(self):
        source = (ROOT / "scripts" / "pohw-bootstrap-bitcoin-core-fork.sh").read_text(
            encoding="utf-8"
        )
        active_branch = source.index('if systemctl is-active --quiet -- "$SOURCE_SERVICE"; then')
        stop_call = source.index('systemctl stop -- "$SOURCE_SERVICE"', active_branch)
        offline_start = source.index('-networkactive=0 -listen=0', stop_call)
        height_check = source.index("getblockcount", offline_start)
        lock_call = source.index("fcntl.lockf(fd, fcntl.LOCK_EX)", height_check)
        copy_call = source.index('cp -a --reflink=auto -- "$SOURCE_DATADIR/chainstate"')
        self.assertLess(stop_call, offline_start)
        self.assertLess(offline_start, height_check)
        self.assertLess(height_check, lock_call)
        self.assertLess(lock_call, copy_call)
        self.assertIn("source blocks or chainstate contains a symlink", source)


if __name__ == "__main__":
    unittest.main()
