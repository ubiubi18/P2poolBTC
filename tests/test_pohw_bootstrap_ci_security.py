import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BootstrapSecurityTests(unittest.TestCase):
    def test_bootstrap_uses_root_owned_staging_and_independent_files(self):
        source = (
            ROOT / "scripts" / "pohw-bootstrap-bitcoin-core-fork.sh"
        ).read_text(encoding="utf-8")
        staging = source.index('STAGING=$(mktemp -d "$TARGET_BASE/')
        root_owner = source.index('chown root:root "$STAGING"', staging)
        historical_copy = source.index('cp -a --reflink=auto -- "$source" "$target"')
        tail_copy = source.index('cp -a --reflink=never -- "$source" "$target"')
        publish = source.index('mv -- "$STAGING" "$TARGET_NETWORK"')
        child_owner = source.index(
            'chown -R "$FORK_USER:$FORK_USER"', tail_copy
        )
        base_owner = source.index('chown root:"$FORK_USER" "$TARGET_BASE"')
        lock_ready = source.index('LOCK_READY="$TARGET_BASE/')
        top_owner = source.index(
            'chown "$FORK_USER:$FORK_USER" "$TARGET_NETWORK"', publish
        )
        self.assertLess(staging, root_owner)
        self.assertLess(root_owner, historical_copy)
        self.assertLess(root_owner, tail_copy)
        self.assertLess(historical_copy, publish)
        self.assertLess(tail_copy, publish)
        self.assertLess(child_owner, publish)
        self.assertLess(publish, top_owner)
        self.assertLess(base_owner, lock_ready)
        self.assertNotIn('ln -- "$source" "$target"', source)
        self.assertNotIn('chgrp "$SHARED_GROUP" "$source"', source)
        self.assertIn("copied block file aliases its source inode", source)
        self.assertIn('chown root:"$FORK_USER" "$TARGET_BASE"', source)
        self.assertIn('chmod 0710 "$TARGET_BASE"', source)
        self.assertIn('groupadd --system "$FORK_USER"', source)
        self.assertIn('useradd --system --gid "$FORK_USER"', source)
        config_write = source.index('cat >"$CONFIG_STAGING"')
        config_owner = source.index(
            'chown "$FORK_USER:$FORK_USER" "$CONFIG_STAGING"', config_write
        )
        self.assertLess(config_write, config_owner)
        self.assertNotIn('cat >"$TARGET_BASE/bitcoin.conf"', source)

    def test_bootstrap_requires_and_verifies_one_pinned_first_fork_source(self):
        source = (
            ROOT / "scripts" / "pohw-bootstrap-bitcoin-core-fork.sh"
        ).read_text(encoding="utf-8")

        source_choice = source.index(
            "one of --first-fork-block or --trusted-fork-peer is required"
        )
        source_stop = source.index('systemctl stop -- "$SOURCE_SERVICE"')
        header_check = source.index(
            "first-fork raw block header does not match the manifest checkpoint"
        )
        submit = source.index("-rpcclienttimeout=30 -stdin submitblock")
        height_check = source.index('verified_height=$(fork_cli getblockcount)')
        hash_check = source.index(
            'verified_hash=$(fork_cli getblockhash "$FIRST_FORK_HEIGHT")'
        )
        checkpoint_call = source.rindex("verify_first_fork_checkpoint")
        shutdown_lock = source.index('python3 -I - "$TARGET_NETWORK/.lock"')
        success = source.index(
            "chainstate clone and pinned first-fork verification complete"
        )

        self.assertLess(source_choice, source_stop)
        self.assertLess(header_check, submit)
        self.assertLess(height_check, hash_check)
        self.assertLess(hash_check, submit)
        self.assertLess(submit, checkpoint_call)
        self.assertLess(checkpoint_call, shutdown_lock)
        self.assertLess(shutdown_lock, success)
        self.assertIn("numeric IPv4:port or [IPv6]:port", source)
        self.assertIn("trusted peer port must equal manifest P2P port", source)
        self.assertIn('-connect="$TRUSTED_FORK_PEER"', source)
        self.assertIn("dnsseed=0", source)
        self.assertIn("fixedseeds=0", source)
        self.assertIn("discover=0", source)
        self.assertNotIn("addnode=", source)
        self.assertIn(
            "refusing unverifiable discovery settings",
            source,
        )
        self.assertIn("os.O_RDONLY | os.O_NOFOLLOW", source)
        self.assertIn("FIRST_FORK_STAGED=$(mktemp", source)

    def test_checkpoint_verifier_fails_closed_with_fake_core(self):
        source = (
            ROOT / "scripts" / "pohw-bootstrap-bitcoin-core-fork.sh"
        ).read_text(encoding="utf-8")
        start = source.index("verify_first_fork_checkpoint() {")
        end = source.index("\n}\n", start) + len("\n}\n")
        function = source[start:end]
        fork = json.loads(
            (ROOT / "compatibility" / "experiment-1-full-consensus.json").read_text(
                encoding="utf-8"
            )
        )["fork_point"]

        with tempfile.TemporaryDirectory() as temp_dir:
            harness = Path(temp_dir) / "verify-checkpoint.sh"
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "FIRST_FORK_HEIGHT=$1\n"
                "FIRST_FORK_HASH=$2\n"
                "FAKE_HEIGHT=$3\n"
                "FAKE_HASH=$4\n"
                "fork_cli() {\n"
                "  case $1 in\n"
                "    getblockcount) printf '%s\\n' \"$FAKE_HEIGHT\" ;;\n"
                "    getblockhash) printf '%s\\n' \"$FAKE_HASH\" ;;\n"
                "    *) return 64 ;;\n"
                "  esac\n"
                "}\n"
                f"{function}\n"
                "verify_first_fork_checkpoint\n",
                encoding="utf-8",
            )

            def run(height: int, block_hash: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "bash",
                        str(harness),
                        str(fork["first_fork_height"]),
                        fork["first_fork_hash"],
                        str(height),
                        block_hash,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            accepted = run(fork["first_fork_height"], fork["first_fork_hash"])
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            too_low = run(fork["inherited_tip_height"], fork["first_fork_hash"])
            self.assertNotEqual(too_low.returncode, 0)
            self.assertIn("did not reach pinned first-fork height", too_low.stderr)

            wrong_hash = run(fork["first_fork_height"], "00" * 32)
            self.assertNotEqual(wrong_hash.returncode, 0)
            self.assertIn("first-fork checkpoint mismatch", wrong_hash.stderr)

    def test_root_adapter_install_uses_system_tools_only(self):
        source = (
            ROOT / "scripts" / "pohw-install-experiment-1-adapter.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", source)
        self.assertIn("SYSTEMCTL_BIN=/usr/bin/systemctl", source)
        self.assertIn("POHW_SYSTEMCTL_BIN cannot override", source)
        self.assertIn('DESTINATION="$DEFAULT_DESTINATION"', source)
        self.assertIn("EXPECTED_SHA256=$(python3 -I -", source)
        self.assertIn('  "$SOURCE" "$BUILD_EVIDENCE"', source)
        self.assertIn("--expected-evidence-sha256", source)
        self.assertIn("--expected-source-cid", source)
        self.assertIn("independently selected source CID", source)


class CiProvenanceTests(unittest.TestCase):
    def test_governance_plan_local_locks_match_the_worktree(self):
        plan = json.loads(
            (ROOT / "compatibility" / "governance-build-plan-v1.json").read_text(
                encoding="utf-8"
            )
        )
        checked = 0
        for target in plan["targets"]:
            for lock in target["dependencyLocks"]:
                if lock["repository"] != "P2poolBTC":
                    continue
                path = Path(lock["path"])
                self.assertFalse(path.is_absolute())
                self.assertNotIn("..", path.parts)
                raw = (ROOT / path).read_bytes()
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(),
                    lock["sha256"],
                    f"{target['id']}:{path}",
                )
                checked += 1
        self.assertGreater(checked, 0)

    def test_ci_has_experiment_provenance_and_production_runtime_gates(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Verify Experiment 1 manifest and provenance files", workflow)
        self.assertIn("git ls-files --error-unmatch", workflow)
        self.assertIn("Validate governance build plan and local lock digests", workflow)
        self.assertIn("governance-production-runtime:", workflow)
        runtime = workflow.split("governance-production-runtime:", 1)[1].split(
            "\n  secrets:", 1
        )[0]
        self.assertIn("governance-fork-lock.json", runtime)
        self.assertIn("governance-day-fork-candidate-lock.json", runtime)
        self.assertIn("Apply exact inactive Governance Day runtime candidate", runtime)
        self.assertIn("Verify deterministic fork-candidate source CIDs", runtime)
        self.assertIn("--verify-candidate-sources-only", runtime)
        self.assertIn("--governance-cli", runtime)
        self.assertIn('cargo +"${{ steps.governance_lock.outputs.rust_version }}" build', runtime)
        self.assertIn("libidena_wasm_linux_amd64.a", runtime)
        self.assertIn("Run production Idena WASM fork-candidate compatibility gate", runtime)
        self.assertIn("--fork-candidate-lock", runtime)
        self.assertIn("--component-repo idena-wasm-binding=", runtime)
        self.assertIn("--component-repo idena-wasm=", runtime)
        self.assertIn("Confirm governance release eligibility or inactive interlock", runtime)
        self.assertIn("noncanonical governance source lacks the inactive safety interlock", runtime)
        self.assertIn("steps.governance_release.outputs.eligible == 'true'", runtime)
        self.assertIn("Run release-grade locked-source gate", runtime)
        self.assertIn("--require-locked-sources", runtime)
        self.assertIn("canonical-locked-source", runtime)
        self.assertIn('git -C "$destination" checkout -q --detach "$revision"', runtime)
        self.assertNotIn("--verify-artifact-only", runtime)
        setup_go = re.search(r"actions/setup-go@([0-9a-f]{40})", runtime)
        self.assertIsNotNone(setup_go)
        action_pins = re.findall(r"uses:\s*[^@\s]+@([^\s]+)", workflow)
        self.assertGreater(len(action_pins), 0)
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in action_pins),
            action_pins,
        )


if __name__ == "__main__":
    unittest.main()
