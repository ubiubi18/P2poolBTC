import importlib.util
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pohw_governance_runtime_gate",
    ROOT / "scripts" / "pohw-governance-runtime-gate.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GovernanceRuntimeGateTests(unittest.TestCase):
    def test_raw_cid_matches_locked_contract_artifact(self):
        digest = "8d05fd842aefd3d4a078038c8fbf8744af8a22d88b1fc7a56be27f7fe835da49"
        self.assertEqual(
            MODULE.raw_cid(digest),
            "bafkreienax6yikxp2pkka6adrsh37b2ev6fcfweld7d2k27cp576qno2je",
        )

    def test_duplicate_lock_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock.json"
            lock.write_text('{"schema":1,"schema":2}\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.GateError, "duplicate object key"):
                MODULE.load_json(lock)

    def test_noncanonical_prototype_cannot_pass_locked_source_gate(self):
        lock = {
            "governancePrototype": {
                "sourceStatus": "committed-experimental-prototype",
                "baseCommit": "0" * 40,
            },
            "components": [],
        }
        with self.assertRaisesRegex(MODULE.GateError, "not a canonical locked source"):
            MODULE.verify_locked_sources(ROOT, lock, ROOT, {})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlinked_contract_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "contract.wasm"
            target.write_bytes(b"fixture")
            link = root / "linked.wasm"
            os.symlink(target, link)
            with self.assertRaisesRegex(MODULE.GateError, "non-symlink"):
                MODULE.hash_regular_file(link)

    def test_repository_lock_is_valid_json(self):
        lock = MODULE.load_json(ROOT / "compatibility" / "governance-fork-lock.json")
        prototype = lock["governancePrototype"]
        self.assertEqual(prototype["sourceStatus"], "committed-experimental-prototype")
        subprocess.run(
            ["git", "cat-file", "-e", prototype["baseCommit"] + "^{commit}"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        artifact = prototype["contractArtifact"]
        self.assertEqual(set(artifact), {"name", "size", "cid", "sha256"})
        self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(artifact["size"], 0)
        self.assertEqual(MODULE.raw_cid(artifact["sha256"]), artifact["cid"])
        overlay = prototype["runtimeIntegrationTestOverlay"]
        self.assertEqual(
            set(overlay),
            {"path", "targetPath", "testName", "size", "cid", "sha256"},
        )
        source, payload, target, test_name = MODULE.verify_runtime_test_overlay(ROOT, lock)
        self.assertEqual(source.stat().st_size, overlay["size"])
        self.assertEqual(len(payload), overlay["size"])
        self.assertEqual(target, MODULE.RUNTIME_TEST_TARGET)
        self.assertEqual(test_name, MODULE.RUNTIME_TEST_NAME)

    def test_runtime_overlay_content_is_digest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "runtime_test.go"
            source.write_bytes(b"package wasm\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            lock = {
                "governancePrototype": {
                    "runtimeIntegrationTestOverlay": {
                        "path": source.name,
                        "targetPath": MODULE.RUNTIME_TEST_TARGET,
                        "testName": MODULE.RUNTIME_TEST_NAME,
                        "size": source.stat().st_size,
                        "cid": MODULE.raw_cid(digest),
                        "sha256": digest,
                    }
                }
            }
            MODULE.verify_runtime_test_overlay(root, lock)
            source.write_bytes(b"package substituted\n")
            with self.assertRaisesRegex(MODULE.GateError, "size does not match"):
                MODULE.verify_runtime_test_overlay(root, lock)

    def test_runtime_overlay_path_escape_is_rejected(self):
        lock = {
            "governancePrototype": {
                "runtimeIntegrationTestOverlay": {
                    "path": "../outside.go",
                    "targetPath": MODULE.RUNTIME_TEST_TARGET,
                    "testName": MODULE.RUNTIME_TEST_NAME,
                    "size": 1,
                    "cid": MODULE.raw_cid("0" * 64),
                    "sha256": "0" * 64,
                }
            }
        }
        with self.assertRaisesRegex(MODULE.GateError, "path is unsafe"):
            MODULE.verify_runtime_test_overlay(ROOT, lock)

    def test_runtime_environment_drops_secrets_and_pins_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": "/usr/bin",
                    "OPENAI_API_KEY": "must-not-cross-runtime-boundary",
                },
                clear=True,
            ):
                environment = MODULE.runtime_test_environment(
                    Path(temporary), "/verified/module-cache", "go1.26.5"
                )
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["GOTOOLCHAIN"], "go1.26.5")
        self.assertEqual(environment["GOMODCACHE"], "/verified/module-cache")

    def test_build_plan_contract_artifact_matches_fork_lock(self):
        lock = MODULE.load_json(ROOT / "compatibility" / "governance-fork-lock.json")
        plan = MODULE.load_json(ROOT / "compatibility" / "governance-build-plan-v1.json")
        target = next(item for item in plan["targets"] if item["id"] == "governance-contract")
        artifact = next(item for item in target["artifacts"] if item["name"] == "idena-code-governance.wasm")
        locked = lock["governancePrototype"]["contractArtifact"]
        self.assertEqual(artifact["expectedCid"], locked["cid"])
        self.assertEqual(artifact["expectedSha256"], locked["sha256"])
        self.assertEqual(artifact["expectedSize"], locked["size"])

    def test_built_contract_matches_local_governance_day_candidate_only(self):
        lock = MODULE.load_json(
            ROOT / "compatibility" / "governance-day-local-candidate-lock.json"
        )
        self.assertFalse(lock["authorizedForDeployment"])
        self.assertFalse(lock["authorizedForRelease"])
        self.assertFalse(lock["canonicalReferenceChangePermitted"])
        artifact = lock["contractArtifact"]
        contract = ROOT / artifact["path"]
        if not contract.exists():
            self.skipTest("governance contract artifact is generated by the JavaScript build job")
        digest, size, cid = MODULE.verify_artifact_descriptor(
            contract,
            artifact,
            "local Governance Day candidate lock",
        )
        self.assertEqual(digest, artifact["sha256"])
        self.assertEqual(size, artifact["size"])
        self.assertEqual(cid, artifact["cid"])


if __name__ == "__main__":
    unittest.main()
