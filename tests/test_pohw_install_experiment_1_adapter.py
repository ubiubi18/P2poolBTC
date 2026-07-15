from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "pohw-install-experiment-1-adapter.sh"


class Experiment1AdapterInstallerTests(unittest.TestCase):
    SOURCE_CID = "bafyreih3yhu25jmihmtwtwimyav4f4nyxk6haqs3va4jlxqvwdaylqmfeq"

    def write_binary(self, path: Path, marker: str, execution_marker: Path | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        execution = f"touch {execution_marker!s}\n" if execution_marker else ""
        path.write_text(
            "#!/usr/bin/env bash\n"
            f"# {marker}\n"
            + execution
            + "exit 0\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    @staticmethod
    def canonical_json(value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()

    @staticmethod
    def encode_varint(value: int) -> bytes:
        result = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            result.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(result)

    @classmethod
    def reference(cls, raw: bytes) -> dict[str, object]:
        digest = hashlib.sha256(raw).hexdigest()
        cid_raw = (
            cls.encode_varint(1)
            + cls.encode_varint(0x55)
            + cls.encode_varint(0x12)
            + cls.encode_varint(32)
            + bytes.fromhex(digest)
        )
        cid = "b" + base64.b32encode(cid_raw).decode().lower().rstrip("=")
        return {"cid": cid, "sha256": digest, "size": len(raw)}

    def write_build_evidence(self, source_root: Path, source: Path) -> Path:
        plan = json.loads(
            (ROOT / "compatibility" / "governance-build-plan-v1.json").read_text(
                encoding="utf-8"
            )
        )
        target = next(item for item in plan["targets"] if item["id"] == "rust-workspace")
        (source_root / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
        source_cid = self.SOURCE_CID
        source_verification = {
            "schemaVersion": 1,
            "sourceVerifier": self.reference(b"fixture-verifier"),
            "sources": [
                {
                    "artifactExclusions": None,
                    "files": 1,
                    "repository": "P2poolBTC",
                    "sourceCar": self.reference(b"fixture-car"),
                    "sourceCid": source_cid,
                    "sourceTreeSha256": "0" * 64,
                }
            ],
        }
        source_verification_raw = self.canonical_json(source_verification)
        test_results = {
            "schemaVersion": 1,
            "passed": True,
            "redactionPolicy": "pohw-build-log-redaction-v1",
            "sourceCids": {"P2poolBTC": source_cid},
            "target": "rust-workspace",
            "commands": [
                {"command": command, "exitCode": 0, "phase": "build"}
                for command in target["commands"]
            ],
        }
        test_results_raw = self.canonical_json(test_results)
        plan_raw = self.canonical_json(plan)
        environment = {
            "schemaVersion": 1,
            "architecture": "fixture",
            "cleanRoom": True,
            "containerImageDigest": None,
            "dependencyFetchSeparated": True,
            "dependencyFetchCommandCount": target["dependencyFetchCommandCount"],
            "isolationKind": "equivalent-clean-room",
            "networkDisabledAfterFetch": True,
            "osFamily": "fixture",
            "plan": self.reference(plan_raw),
            "platform": "fixture",
            "readOnlySources": True,
            "resourceLimits": {"cpuCount": 1, "memoryBytes": 1, "processes": 1},
            "sourceVerification": self.reference(source_verification_raw),
            "sourceDateEpoch": plan["sourceDateEpoch"],
            "toolchains": plan["toolchains"],
        }
        environment_raw = self.canonical_json(environment)
        artifact_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        artifacts = []
        for declaration in target["artifacts"]:
            is_node = declaration["name"] == "p2pool-node"
            artifacts.append(
                {
                    "architecture": "fixture",
                    "cid": self.reference(
                        source.read_bytes()
                        if is_node
                        else declaration["name"].encode()
                    )["cid"],
                    "deterministic": declaration["deterministic"],
                    "kind": declaration["kind"],
                    "name": declaration["name"],
                    "packagedName": declaration["name"],
                    "platform": "fixture",
                    "repository": declaration["repository"],
                    "sha256": artifact_sha
                    if is_node
                    else hashlib.sha256(declaration["name"].encode()).hexdigest(),
                    "size": source.stat().st_size
                    if is_node
                    else len(declaration["name"].encode()),
                }
            )
        lock_raw = (source_root / "Cargo.lock").read_bytes()
        lock_sha = hashlib.sha256(lock_raw).hexdigest()
        evidence = {
            "schemaVersion": 1,
            "artifacts": artifacts,
            "buildEnvironment": self.reference(environment_raw),
            "buildPlan": self.reference(plan_raw),
            "coreArtifactDigest": "0" * 64,
            "dependencyLocks": [
                {
                    "cid": self.reference(lock_raw)["cid"],
                    "format": "cargo-lock",
                    "path": "Cargo.lock",
                    "repository": "P2poolBTC",
                    "sha256": lock_sha,
                    "size": len(lock_raw),
                }
            ],
            "forkReleaseId": plan["forkReleaseId"],
            "limitations": target["limitations"],
            "planId": plan["planId"],
            "reproducibility": target["reproducibility"],
            "sbom": self.reference(b"fixture-sbom"),
            "sourceVerification": self.reference(source_verification_raw),
            "sourceCids": [{"repository": "P2poolBTC", "sourceCid": source_cid}],
            "status": "verified-local-build-evidence",
            "target": "rust-workspace",
            "testResults": self.reference(test_results_raw),
            "toolchainLocks": self.reference(b"fixture-toolchain-locks"),
        }
        evidence_dir = source_root / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "source-verification.json").write_bytes(source_verification_raw)
        (evidence_dir / "test-results.json").write_bytes(test_results_raw)
        (evidence_dir / "build-environment.json").write_bytes(environment_raw)
        evidence_path = evidence_dir / "build-evidence.json"
        evidence_path.write_bytes(self.canonical_json(evidence))
        return evidence_path

    def write_systemctl(
        self, path: Path, active: bool, *, exit_code: int | None = None
    ) -> None:
        status = exit_code if exit_code is not None else (0 if active else 3)
        path.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"$POHW_SYSTEMCTL_LOG\"\n"
            f"exit {status}\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def run_installer(
        self,
        source: Path,
        destination: Path,
        systemctl: Path,
        log: Path,
        source_root: Path,
        evidence: Path | None,
        *,
        expected_evidence_sha256: str | None = None,
        expected_source_cid: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            {
                "POHW_SYSTEMCTL_BIN": str(systemctl),
                "POHW_SYSTEMCTL_LOG": str(log),
            }
        )
        evidence_arguments: list[str] = []
        if evidence:
            evidence_arguments = [
                "--build-evidence",
                str(evidence),
                "--expected-evidence-sha256",
                expected_evidence_sha256
                or hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "--expected-source-cid",
                expected_source_cid or self.SOURCE_CID,
            ]
        return subprocess.run(
            [
                "bash",
                str(INSTALLER),
                "--binary",
                str(source),
                "--source-root",
                str(source_root),
                "--build-plan",
                str(ROOT / "compatibility" / "governance-build-plan-v1.json"),
                *evidence_arguments,
                "--destination",
                str(destination),
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_installs_atomically_and_keeps_one_rollback_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-install-") as temp:
            root = Path(temp)
            source = root / "source" / "target" / "release" / "p2pool-node"
            source_root = root / "source"
            destination = root / "libexec" / "p2pool-node"
            destination.parent.mkdir()
            execution_marker = root / "candidate-was-executed"
            self.write_binary(source, "new", execution_marker)
            self.write_binary(destination, "old")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            result = self.run_installer(
                source, destination, systemctl, log, source_root, evidence
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertIn("# old", Path(f"{destination}.previous").read_text())
            service_checks = log.read_text(encoding="utf-8")
            self.assertIn("pohw-mining-adapter.service", service_checks)
            self.assertIn("pohw-gossip-mesh.service", service_checks)
            self.assertFalse(execution_marker.exists())

    def test_refuses_active_service_without_touching_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-active-") as temp:
            root = Path(temp)
            source = root / "source" / "target" / "release" / "p2pool-node"
            source_root = root / "source"
            destination = root / "p2pool-node"
            self.write_binary(source, "new")
            self.write_binary(destination, "old")
            evidence = self.write_build_evidence(source_root, source)
            before = destination.read_bytes()
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=True)

            result = self.run_installer(
                source, destination, systemctl, log, source_root, evidence
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is active", result.stderr)
            self.assertEqual(destination.read_bytes(), before)

    def test_fails_closed_when_service_state_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-service-unknown-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            destination = root / "p2pool-node"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False, exit_code=4)

            result = self.run_installer(
                source, destination, systemctl, log, source_root, evidence
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Cannot prove", result.stderr)
            self.assertFalse(destination.exists())

    def test_refuses_symlinked_or_evidence_mismatched_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-invalid-") as temp:
            root = Path(temp)
            source_root = root / "source"
            real_source = source_root / "target" / "release" / "p2pool-node"
            self.write_binary(real_source, "real")
            evidence = self.write_build_evidence(source_root, real_source)
            source_link = real_source.with_name("node-link")
            source_link.symlink_to(real_source)
            destination = root / "p2pool-node"
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            linked = self.run_installer(
                source_link, destination, systemctl, log, source_root, evidence
            )
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("non-symlink", linked.stderr)

            real_source.write_text("tampered after evidence\n", encoding="utf-8")
            real_source.chmod(0o755)
            invalid = self.run_installer(
                real_source, destination, systemctl, log, source_root, evidence
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("does not match build evidence", invalid.stderr)
            self.assertFalse(destination.exists())

    def test_requires_build_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-no-evidence-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            self.write_binary(source, "new")
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)
            result = self.run_installer(
                source, root / "destination", systemctl, log, source_root, None
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--build-evidence is required", result.stderr)

    def test_requires_independently_selected_evidence_and_source_references(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-trust-root-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            destination = root / "destination"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            wrong_evidence = self.run_installer(
                source,
                destination,
                systemctl,
                log,
                source_root,
                evidence,
                expected_evidence_sha256="0" * 64,
            )
            self.assertNotEqual(wrong_evidence.returncode, 0)
            self.assertIn("independently selected SHA-256", wrong_evidence.stderr)

            wrong_source = self.run_installer(
                source,
                destination,
                systemctl,
                log,
                source_root,
                evidence,
                expected_source_cid=(
                    "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            )
            self.assertNotEqual(wrong_source.returncode, 0)
            self.assertIn("independently selected source CID", wrong_source.stderr)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
