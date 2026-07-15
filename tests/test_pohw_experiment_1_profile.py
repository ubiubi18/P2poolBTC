import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pohw-activate-experiment-1-profile.py"
SPEC = importlib.util.spec_from_file_location("pohw_experiment_1_profile", SCRIPT)
PROFILE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(PROFILE)
CURRENT_ACTIVATION_ID, CURRENT_DATADIR, _ = PROFILE.load_experiment_profile(
    PROFILE.DEFAULT_MANIFEST
)


BASE = """# private operator settings
POHW_MINER_ID=miner
POHW_IDENA_SNAPSHOT_ID=snapshot
POHW_IDENA_SNAPSHOT_PROOF_ROOT=root
POHW_STRATUM_POHW_COMMITMENT_FILE=/private/commitment.json
POHW_MINING_SECRET_KEY_FILE=/private/mining.key
POHW_NODE_SECRET_KEY_FILE=/private/gossip-node.key
POHW_SNAPSHOT_DIR=/private/snapshots
POHW_IDENA_ANCHOR_POLICY=/private/idena-anchor-policy-v2.json
IDENA_API_KEY_FILE=/private/idena-api.key
POHW_MINER_REGISTRY_EXPERIMENT_ID=p2poolbtc-experiment-1
POHW_MINER_REGISTRY_ANCHOR_FILE=/private/miner-registry-anchor.json
POHW_LOCAL_SECRET=preserve-me
POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408
POHW_FORK_ACTIVATION_MANIFEST=/private/experiment-0.json
POHW_STRATUM_DIFFICULTY=0.00000000046565423739069247
POHW_STRATUM_SHARE_TARGET=7fffff0000000000000000000000000000000000000000000000000000000000
POHW_STRATUM_AUTO_SUBMIT_BLOCKS=false
"""


class Experiment1ProfileTests(unittest.TestCase):
    def test_switch_preserves_private_settings_and_is_idempotent(self):
        rendered, changed = PROFILE.render_profile(BASE.splitlines())
        self.assertIn("POHW_LOCAL_SECRET=preserve-me", rendered)
        self.assertNotIn("POHW_STRATUM_FORK_CHAIN_RPC_ADDR=", rendered)
        self.assertNotIn("POHW_FORK_ACTIVATION_MANIFEST=", rendered)
        self.assertNotIn("POHW_STRATUM_DIFFICULTY=", rendered)
        self.assertNotIn("POHW_STRATUM_SHARE_TARGET=", rendered)
        self.assertIn("POHW_BITCOIN_EXPECTED_CHAIN=pohw", rendered)
        self.assertIn("POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true", rendered)
        self.assertIn("POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS=1", rendered)
        self.assertIn("POHW_REQUIRE_IDENA_ANCHOR_POLICY=true", rendered)
        self.assertIn("POHW_ADMIT_PEER_WORK_TEMPLATES=true", rendered)
        self.assertIn(f"POHW_DATADIR={CURRENT_DATADIR}", rendered)
        self.assertIn(
            f"POHW_GOSSIP_NETWORK_ID={CURRENT_ACTIVATION_ID}", rendered
        )
        self.assertIn(
            f"POHW_STRATUM_BLOCK_CANDIDATE_DIR={CURRENT_DATADIR}/block-candidates",
            rendered,
        )
        self.assertIn("POHW_STRATUM_ALLOW_MAINNET_SUBMIT=false", rendered)
        self.assertIn("POHW_STRATUM_FORK_CHAIN_RPC_ADDR", changed)

        rerendered, second_changed = PROFILE.render_profile(rendered.splitlines())
        self.assertEqual(rerendered, rendered)
        self.assertEqual(second_changed, [])

    def test_network_id_matches_the_exact_experiment_manifest(self):
        manifest = json.loads(
            (ROOT / "compatibility" / "experiment-1-full-consensus.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(CURRENT_ACTIVATION_ID, manifest["activation_id"])
        self.assertEqual(
            CURRENT_DATADIR,
            "/srv/sharechain/"
            + manifest["network"]["data_subdirectory"]
            + "-"
            + manifest["activation_id"][:8],
        )

    def test_profile_values_are_derived_from_selected_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = json.loads(PROFILE.DEFAULT_MANIFEST.read_text(encoding="utf-8"))
            manifest["activation_id"] = "a" * 64
            manifest["profile_revision"] += 1
            manifest["supersedes_activation_id"] = CURRENT_ACTIVATION_ID
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            activation_id, datadir, values = PROFILE.load_experiment_profile(path)
            self.assertEqual(activation_id, "a" * 64)
            self.assertEqual(datadir, "/srv/sharechain/pohw-experiment-1-aaaaaaaa")
            self.assertEqual(values["POHW_GOSSIP_NETWORK_ID"], "a" * 64)
            self.assertEqual(values["POHW_DATADIR"], datadir)

    def test_duplicate_or_missing_required_settings_fail(self):
        with self.assertRaisesRegex(PROFILE.ProfileError, "duplicate"):
            PROFILE.render_profile((BASE + "POHW_MINER_ID=other\n").splitlines())
        with self.assertRaisesRegex(PROFILE.ProfileError, "required existing"):
            PROFILE.render_profile("POHW_MINER_ID=miner\n".splitlines())

    def test_atomic_write_preserves_mode_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p2pool.env"
            path.write_text(BASE, encoding="utf-8")
            path.chmod(0o640)
            lines, metadata = PROFILE._read_environment(path)
            rendered, _ = PROFILE.render_profile(lines)
            PROFILE.write_profile(path, rendered, metadata)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

            link = Path(directory) / "link.env"
            os.symlink(path, link)
            with self.assertRaisesRegex(PROFILE.ProfileError, "non-symlink"):
                PROFILE._read_environment(link)

    def test_activation_keeps_exact_backup_and_rollback_is_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p2pool.env"
            backup = Path(directory) / "p2pool.env.experiment-1.previous"
            path.write_text(BASE, encoding="utf-8")
            path.chmod(0o640)
            original = path.read_bytes()
            lines, metadata = PROFILE._read_environment(path)
            rendered, _ = PROFILE.render_profile(lines)

            self.assertTrue(
                PROFILE.activate_profile(path, backup, rendered, metadata)
            )
            self.assertEqual(backup.read_bytes(), original)
            self.assertEqual(path.read_text(encoding="utf-8"), rendered)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o640)

            active_backup = backup.read_bytes()
            active_lines, active_metadata = PROFILE._read_environment(path)
            active_rendered, _ = PROFILE.render_profile(active_lines)
            self.assertFalse(
                PROFILE.activate_profile(
                    path, backup, active_rendered, active_metadata
                )
            )
            self.assertEqual(backup.read_bytes(), active_backup)

            PROFILE.rollback_profile(path, backup)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_activation_rejects_unsafe_backup_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "p2pool.env"
            target = root / "other"
            backup = root / "p2pool.env.experiment-1.previous"
            path.write_text(BASE, encoding="utf-8")
            target.write_text("do not replace\n", encoding="utf-8")
            backup.symlink_to(target)
            lines, metadata = PROFILE._read_environment(path)
            rendered, _ = PROFILE.render_profile(lines)
            with self.assertRaisesRegex(PROFILE.ProfileError, "backup"):
                PROFILE.activate_profile(path, backup, rendered, metadata)
            self.assertEqual(target.read_text(encoding="utf-8"), "do not replace\n")


if __name__ == "__main__":
    unittest.main()
