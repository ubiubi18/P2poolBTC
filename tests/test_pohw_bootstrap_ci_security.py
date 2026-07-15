import hashlib
import json
import re
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
        self.assertIn("Run production Idena WASM runtime compatibility gate", runtime)
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
