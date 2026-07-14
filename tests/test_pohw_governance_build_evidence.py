import argparse
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pohw_governance_build_evidence",
    ROOT / "scripts" / "pohw-governance-build-evidence.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GovernanceBuildEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_verifier = ROOT / "target" / "debug" / "pohw-governance"
        if not cls.source_verifier.exists():
            subprocess.run(
                ["cargo", "build", "--locked", "-p", "governance-cli"],
                cwd=ROOT,
                check=True,
            )
        cls.source_verifier_sha256 = hashlib.sha256(
            cls.source_verifier.read_bytes()
        ).hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        package_lock = {
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {"name": "fixture", "version": "1.0.0"},
                "node_modules/example": {
                    "version": "2.0.0",
                    "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                },
            },
        }
        self.lock_path = self.repository / "package-lock.json"
        self.lock_path.write_text(json.dumps(package_lock, sort_keys=True) + "\n", encoding="utf-8")
        lock_digest = hashlib.sha256(self.lock_path.read_bytes()).hexdigest()

        self.artifact = self.repository / "dist"
        (self.artifact / "assets").mkdir(parents=True)
        (self.artifact / "Z.js").write_text("z\n", encoding="utf-8")
        executable = self.artifact / "assets" / "a.js"
        executable.write_text("a\n", encoding="utf-8")
        executable.chmod(0o755)

        self.plan = {
            "schemaVersion": 1,
            "planId": "fixture-build-v1",
            "status": "experimental-local-only",
            "forkReleaseId": "fixture-fork-v1",
            "sourceDateEpoch": 1,
            "toolchains": {"node": "24.18.0"},
            "targets": [
                {
                    "id": "fixture",
                    "sourceRepositories": ["fixture"],
                    "requiredToolchains": ["node"],
                    "dependencyLocks": [
                        {
                            "repository": "fixture",
                            "path": "package-lock.json",
                            "sha256": lock_digest,
                            "format": "npm-package-lock",
                        }
                    ],
                    "commands": ["npm ci --ignore-scripts", "npm test"],
                    "dependencyFetchCommandCount": 1,
                    "artifacts": [
                        {
                            "name": "renderer",
                            "repository": "fixture",
                            "kind": "directory-tar",
                            "pathHint": "dist",
                            "platform": "web",
                            "architecture": "any",
                            "deterministic": True,
                            "expectedCid": None,
                            "expectedSha256": None,
                            "expectedSize": None,
                        }
                    ],
                    "reproducibility": "deterministic-core",
                    "limitations": [],
                }
            ],
        }
        self.plan_path = self.root / "plan.json"
        self.write_json(self.plan_path, self.plan)

        self.result = {
            "schemaVersion": 1,
            "target": "fixture",
            "sourceCids": {},
            "cleanRoom": True,
            "readOnlySources": True,
            "networkDisabledAfterFetch": True,
            "dependencyFetchSeparated": True,
            "isolationKind": "equivalent-clean-room",
            "containerImageDigest": None,
            "resourceLimits": {"cpuCount": 2, "memoryBytes": 1024, "processes": 32},
            "redactionPolicy": "pohw-build-log-redaction-v1",
            "toolchains": {"node": "24.18.0"},
            "platform": "fixture-os",
            "architecture": "fixture-arch",
            "osFamily": "fixture",
            "commands": [
                {"command": "npm ci --ignore-scripts", "exitCode": 0},
                {"command": "npm test", "exitCode": 0},
            ],
        }
        self.result_path = self.root / "result.json"
        self.source_package_counter = 0
        self.refresh_source_binding()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        (self.logs / "000.stdout.log").write_text("tests passed\n", encoding="utf-8")
        (self.logs / "000.stderr.log").write_bytes(b"")
        (self.logs / "001.stdout.log").write_text("tests passed\n", encoding="utf-8")
        (self.logs / "001.stderr.log").write_bytes(b"")

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_json(path, payload):
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def refresh_source_binding(self):
        self.source_package_counter += 1
        output = self.root / f"source-package-{self.source_package_counter}"
        completed = subprocess.run(
            [
                str(self.source_verifier),
                "package",
                "--root",
                str(self.repository),
                "--repository",
                "fixture",
                "--output-dir",
                str(output),
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        package = json.loads(completed.stdout)
        cars = list(output.glob("*.car"))
        self.assertEqual(len(cars), 1)
        self.source_car = cars[0]
        self.source_cid = package["sourceTreeCid"]
        self.result["sourceCids"] = {"fixture": self.source_cid}
        self.write_json(self.result_path, self.result)

    def args(self, output):
        return argparse.Namespace(
            plan=str(self.plan_path),
            target="fixture",
            repository_root=[f"fixture={self.repository}"],
            source_cid=[f"fixture={self.source_cid}"],
            source_car=[f"fixture={self.source_car}"],
            source_verifier=str(self.source_verifier),
            source_verifier_sha256=self.source_verifier_sha256,
            artifact_exclusions=[],
            artifact=[f"renderer={self.artifact}"],
            result_record=str(self.result_path),
            logs_dir=str(self.logs),
            output_dir=str(output),
        )

    def test_generation_is_byte_reproducible_and_content_addressed(self):
        first = self.root / "output-1"
        second = self.root / "output-2"
        first_summary = MODULE.generate_evidence(self.args(first))
        second_summary = MODULE.generate_evidence(self.args(second))
        self.assertEqual(first_summary["coreArtifactDigest"], second_summary["coreArtifactDigest"])
        self.assertEqual(first_summary["buildEvidence"], second_summary["buildEvidence"])
        first_files = {path.name: path.read_bytes() for path in first.iterdir()}
        second_files = {path.name: path.read_bytes() for path in second.iterdir()}
        self.assertEqual(first_files, second_files)
        evidence = json.loads((first / "build-evidence.json").read_text())
        test_results = json.loads((first / "test-results.json").read_text())
        self.assertIs(test_results["passed"], True)
        artifact = evidence["artifacts"][0]
        self.assertEqual(MODULE.validate_cid(artifact["cid"], MODULE.RAW_CODEC, "artifact"), artifact["sha256"])
        self.assertEqual(evidence["sbom"]["sha256"], MODULE.validate_cid(evidence["sbom"]["cid"], MODULE.RAW_CODEC, "sbom"))
        toolchain_bytes = (first / "toolchain-locks.dag-cbor").read_bytes()
        self.assertEqual(toolchain_bytes.hex(), "a1646e6f64656732342e31382e30")
        self.assertEqual(
            evidence["toolchainLocks"]["sha256"],
            MODULE.validate_cid(
                evidence["toolchainLocks"]["cid"],
                MODULE.DAG_CBOR_CODEC,
                "toolchain locks",
            ),
        )
        self.assertEqual(first_summary["toolchain"], evidence["toolchainLocks"])
        sbom = json.loads((first / "sbom.cdx.json").read_text())
        self.assertEqual([item["name"] for item in sbom["components"]], ["example", "fixture"])

    def test_core_artifact_set_digest_matches_shared_vector(self):
        artifacts = [
            {
                "name": "core",
                "cid": "bafkreieqc6pihqlmlesywkcjo3pb6vdqgfdlfq7o6pgfcwo4t6o4pciziy",
                "sha256": "90179e83c16c59258b284976de1f54703146b2c3eef3cc5159dc9f9dc7891946",
                "size": 22,
                "deterministic": True,
            }
        ]
        self.assertEqual(
            MODULE.core_artifact_set_digest(artifacts),
            "2cc1819daf00a581b5ee8b9380d9d4c01a13e54dc481c8e5a5ae61c349c30da8",
        )

    def test_toolchain_dag_cbor_matches_shared_vector(self):
        value = {
            "go": "1.26.5",
            "rust": "1.97.0",
            "node": "24.18.0",
            "npm": "11.16.0",
            "pnpm": "10.30.3",
            "assemblyscript": "0.28.10",
        }
        self.assertEqual(
            MODULE.canonical_dag_cbor_string_map(value).hex(),
            "a662676f66312e32362e35636e706d6731312e31362e30646e6f64656732342e31382e3064706e706d6731302e33302e33647275737466312e39372e306e617373656d626c7973637269707467302e32382e3130",
        )

    def test_plan_without_a_deterministic_core_is_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["targets"][0]["artifacts"][0]["deterministic"] = False
        self.write_json(self.plan_path, plan)
        with self.assertRaisesRegex(MODULE.EvidenceError, "deterministic core artifact"):
            MODULE.validate_plan(MODULE.load_json(self.plan_path, "build plan"))

    def test_dependency_lock_tampering_fails_closed(self):
        self.lock_path.write_text("{}\n", encoding="utf-8")
        self.refresh_source_binding()
        with self.assertRaisesRegex(MODULE.EvidenceError, "dependency lock digest mismatch"):
            MODULE.generate_evidence(self.args(self.root / "tampered"))

    def test_toolchain_and_allowlisted_command_mismatches_fail(self):
        result = copy.deepcopy(self.result)
        result["toolchains"]["node"] = "24.18.1"
        self.write_json(self.result_path, result)
        with self.assertRaisesRegex(MODULE.EvidenceError, "toolchain versions"):
            MODULE.generate_evidence(self.args(self.root / "wrong-tool"))

        result = copy.deepcopy(self.result)
        result["commands"][1]["command"] = "curl https://example.invalid"
        self.write_json(self.result_path, result)
        with self.assertRaisesRegex(MODULE.EvidenceError, "allowlisted plan"):
            MODULE.generate_evidence(self.args(self.root / "wrong-command"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_directory_artifact_symlink_is_rejected(self):
        os.symlink(self.artifact / "Z.js", self.artifact / "link.js")
        with self.assertRaisesRegex(MODULE.EvidenceError, "contains a symlink"):
            MODULE.generate_evidence(self.args(self.root / "symlink"))

    def test_failed_command_and_invalid_source_cid_fail(self):
        result = copy.deepcopy(self.result)
        result["commands"][1]["exitCode"] = 1
        self.write_json(self.result_path, result)
        with self.assertRaisesRegex(MODULE.EvidenceError, "failed with exit code 1"):
            MODULE.generate_evidence(self.args(self.root / "failed"))

        self.write_json(self.result_path, self.result)
        args = self.args(self.root / "bad-cid")
        args.source_cid = ["fixture=bafkbad"]
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.generate_evidence(args)

    def test_source_tree_mutation_and_verifier_digest_mismatch_fail(self):
        (self.repository / "uncommitted.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "source tree does not match"):
            MODULE.generate_evidence(self.args(self.root / "source-mutated"))

        (self.repository / "uncommitted.txt").unlink()
        args = self.args(self.root / "wrong-verifier")
        args.source_verifier_sha256 = "0" * 64
        with self.assertRaisesRegex(MODULE.EvidenceError, "source verifier SHA-256"):
            MODULE.generate_evidence(args)

    def test_duplicate_json_keys_and_unredacted_logs_fail(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schemaVersion":1,"schemaVersion":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate object key"):
            MODULE.load_json(duplicate, "duplicate fixture")

        (self.logs / "001.stderr.log").write_text(
            "password=not-a-real-credential\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.EvidenceError, "unredacted credential-like"):
            MODULE.generate_evidence(self.args(self.root / "secret-log"))

    def test_pnpm_parser_ignores_nested_mapping_keys(self):
        raw = b"""lockfileVersion: '9.0'

packages:

  example@1.2.3:
    resolution: {integrity: sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=}
    peerDependencies:
      other: ^1.0.0

snapshots:
  example@1.2.3: {}
"""
        components = MODULE.parse_pnpm_lock(raw, "fixture", "pnpm-lock.yaml")
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "example")


if __name__ == "__main__":
    unittest.main()
