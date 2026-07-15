from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "pohw-install-experiment-1-adapter.sh"


class Experiment1AdapterInstallerTests(unittest.TestCase):
    SOURCE_CID = "bafyreih3yhu25jmihmtwtwimyav4f4nyxk6haqs3va4jlxqvwdaylqmfeq"
    RUNTIME_DIR = Path("usr/local/libexec/p2pool-experiment-1")
    SYSTEMD_DIR = Path("etc/systemd/system")
    FIXED_ARTIFACTS = {
        "pohw-run-mining-adapter.sh": Path("scripts/pohw-run-mining-adapter.sh"),
        "pohw-run-gossip-mesh.sh": Path("scripts/pohw-run-gossip-mesh.sh"),
        "pohw-health-status.py": Path("scripts/pohw-health-status.py"),
        "pohw-mining-adapter.service": Path(
            "deploy/systemd/pohw-mining-adapter.service"
        ),
        "pohw-gossip-mesh.service": Path("deploy/systemd/pohw-gossip-mesh.service"),
        "pohw-mining-adapter-server.conf": Path(
            "deploy/systemd/pohw-mining-adapter-server.conf"
        ),
        "pohw-gossip-mesh-server.conf": Path(
            "deploy/systemd/pohw-gossip-mesh-server.conf"
        ),
    }

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
        for relative_path in self.FIXED_ARTIFACTS.values():
            fixture_path = source_root / relative_path
            fixture_path.parent.mkdir(parents=True, exist_ok=True)
            fixture_path.write_bytes((ROOT / relative_path).read_bytes())
            fixture_path.chmod(stat.S_IMODE((ROOT / relative_path).stat().st_mode))
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
        artifacts = []
        for declaration in target["artifacts"]:
            name = declaration["name"]
            if name == "p2pool-node":
                artifact_raw = source.read_bytes()
            elif name in self.FIXED_ARTIFACTS:
                artifact_raw = (source_root / self.FIXED_ARTIFACTS[name]).read_bytes()
            else:
                artifact_raw = name.encode()
            artifacts.append(
                {
                    "architecture": "fixture"
                    if declaration["architecture"] == "builder-platform"
                    else declaration["architecture"],
                    "cid": self.reference(artifact_raw)["cid"],
                    "deterministic": declaration["deterministic"],
                    "kind": declaration["kind"],
                    "name": name,
                    "packagedName": Path(declaration["pathHint"]).name,
                    "platform": "fixture"
                    if declaration["platform"] == "builder-platform"
                    else declaration["platform"],
                    "repository": declaration["repository"],
                    "sha256": hashlib.sha256(artifact_raw).hexdigest(),
                    "size": len(artifact_raw),
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
        self,
        path: Path,
        active: bool,
        *,
        exit_code: int | None = None,
        daemon_reload_exit_code: int = 0,
    ) -> None:
        status = exit_code if exit_code is not None else (0 if active else 3)
        path.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"$POHW_SYSTEMCTL_LOG\"\n"
            f"[[ ${{1:-}} == daemon-reload ]] && exit {daemon_reload_exit_code}\n"
            f"exit {status}\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def run_installer(
        self,
        source: Path,
        install_root: Path,
        systemctl: Path,
        log: Path,
        source_root: Path,
        evidence: Path | None,
        *,
        expected_evidence_sha256: str | None = None,
        expected_source_cid: str | None = None,
        destination_override: Path | None = None,
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
        destination_arguments = (
            ["--destination", str(destination_override)]
            if destination_override is not None
            else []
        )
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
                *destination_arguments,
                "--install-root",
                str(install_root),
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_installs_fixed_layout_modes_and_keeps_one_rollback_binary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-install-") as temp:
            root = Path(temp)
            source = root / "source" / "target" / "release" / "p2pool-node"
            source_root = root / "source"
            install_root = root / "install-root"
            destination = install_root / self.RUNTIME_DIR / "p2pool-node"
            destination.parent.mkdir(parents=True)
            execution_marker = root / "candidate-was-executed"
            self.write_binary(source, "new", execution_marker)
            self.write_binary(destination, "old")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            result = self.run_installer(
                source, install_root, systemctl, log, source_root, evidence
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            expected_files = {
                destination: (source, 0o755),
                install_root / self.RUNTIME_DIR / "pohw-run-mining-adapter.sh": (
                    source_root / self.FIXED_ARTIFACTS["pohw-run-mining-adapter.sh"],
                    0o755,
                ),
                install_root / self.RUNTIME_DIR / "pohw-run-gossip-mesh.sh": (
                    source_root / self.FIXED_ARTIFACTS["pohw-run-gossip-mesh.sh"],
                    0o755,
                ),
                install_root / self.RUNTIME_DIR / "pohw-health-status.py": (
                    source_root / self.FIXED_ARTIFACTS["pohw-health-status.py"],
                    0o755,
                ),
                install_root / self.SYSTEMD_DIR / "pohw-mining-adapter.service": (
                    source_root / self.FIXED_ARTIFACTS["pohw-mining-adapter.service"],
                    0o644,
                ),
                install_root / self.SYSTEMD_DIR / "pohw-gossip-mesh.service": (
                    source_root / self.FIXED_ARTIFACTS["pohw-gossip-mesh.service"],
                    0o644,
                ),
                install_root
                / self.SYSTEMD_DIR
                / "pohw-mining-adapter.service.d"
                / "server.conf": (
                    source_root
                    / self.FIXED_ARTIFACTS["pohw-mining-adapter-server.conf"],
                    0o644,
                ),
                install_root
                / self.SYSTEMD_DIR
                / "pohw-gossip-mesh.service.d"
                / "server.conf": (
                    source_root
                    / self.FIXED_ARTIFACTS["pohw-gossip-mesh-server.conf"],
                    0o644,
                ),
            }
            for installed, (fixture, expected_mode) in expected_files.items():
                with self.subTest(installed=installed):
                    self.assertEqual(installed.read_bytes(), fixture.read_bytes())
                    self.assertEqual(
                        stat.S_IMODE(installed.stat().st_mode), expected_mode
                    )
            self.assertIn("# old", Path(f"{destination}.previous").read_text())
            service_checks = log.read_text(encoding="utf-8")
            self.assertIn("pohw-mining-adapter.service", service_checks)
            self.assertIn("pohw-gossip-mesh.service", service_checks)
            self.assertIn("daemon-reload", service_checks)
            self.assertFalse(execution_marker.exists())

    def test_daemon_reload_failure_restores_the_entire_runtime_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-rollback-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            install_root = root / "install-root"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            installed = {
                install_root / self.RUNTIME_DIR / "p2pool-node": 0o700,
                install_root
                / self.RUNTIME_DIR
                / "pohw-run-mining-adapter.sh": 0o700,
                install_root / self.RUNTIME_DIR / "pohw-run-gossip-mesh.sh": 0o700,
                install_root / self.RUNTIME_DIR / "pohw-health-status.py": 0o700,
                install_root
                / self.SYSTEMD_DIR
                / "pohw-mining-adapter.service": 0o600,
                install_root / self.SYSTEMD_DIR / "pohw-gossip-mesh.service": 0o600,
                install_root
                / self.SYSTEMD_DIR
                / "pohw-mining-adapter.service.d"
                / "server.conf": 0o600,
                install_root
                / self.SYSTEMD_DIR
                / "pohw-gossip-mesh.service.d"
                / "server.conf": 0o600,
            }
            before = {}
            for index, (path, mode) in enumerate(installed.items()):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"old runtime artifact {index}\n", encoding="utf-8")
                path.chmod(mode)
                before[path] = (path.read_bytes(), mode)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(
                systemctl, active=False, daemon_reload_exit_code=1
            )

            result = self.run_installer(
                source, install_root, systemctl, log, source_root, evidence
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("daemon-reload failed", result.stderr)
            for path, (expected_bytes, expected_mode) in before.items():
                with self.subTest(path=path):
                    self.assertEqual(path.read_bytes(), expected_bytes)
                    self.assertEqual(
                        stat.S_IMODE(path.stat().st_mode), expected_mode
                    )

    def test_refuses_active_service_without_touching_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-active-") as temp:
            root = Path(temp)
            source = root / "source" / "target" / "release" / "p2pool-node"
            source_root = root / "source"
            install_root = root / "install-root"
            destination = install_root / self.RUNTIME_DIR / "p2pool-node"
            self.write_binary(source, "new")
            self.write_binary(destination, "old")
            evidence = self.write_build_evidence(source_root, source)
            before = destination.read_bytes()
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=True)

            result = self.run_installer(
                source, install_root, systemctl, log, source_root, evidence
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is active", result.stderr)
            self.assertEqual(destination.read_bytes(), before)

    def test_fails_closed_when_service_state_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-service-unknown-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            install_root = root / "install-root"
            destination = install_root / self.RUNTIME_DIR / "p2pool-node"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False, exit_code=4)

            result = self.run_installer(
                source, install_root, systemctl, log, source_root, evidence
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
            install_root = root / "install-root"
            destination = install_root / self.RUNTIME_DIR / "p2pool-node"
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            linked = self.run_installer(
                source_link, install_root, systemctl, log, source_root, evidence
            )
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("non-symlink", linked.stderr)

            real_source.write_text("tampered after evidence\n", encoding="utf-8")
            real_source.chmod(0o755)
            invalid = self.run_installer(
                real_source, install_root, systemctl, log, source_root, evidence
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("does not match build evidence", invalid.stderr)
            self.assertFalse(destination.exists())

    def test_refuses_altered_evidence_bound_runtime_artifacts(self) -> None:
        for name, relative_path in self.FIXED_ARTIFACTS.items():
            with self.subTest(artifact=name), tempfile.TemporaryDirectory(
                prefix="pohw-adapter-runtime-tamper-"
            ) as temp:
                root = Path(temp)
                source_root = root / "source"
                source = source_root / "target" / "release" / "p2pool-node"
                install_root = root / "install-root"
                self.write_binary(source, "new")
                evidence = self.write_build_evidence(source_root, source)
                altered = source_root / relative_path
                altered.write_bytes(altered.read_bytes() + b"# altered after evidence\n")
                systemctl = root / "systemctl"
                log = root / "systemctl.log"
                self.write_systemctl(systemctl, active=False)

                result = self.run_installer(
                    source, install_root, systemctl, log, source_root, evidence
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not match build evidence", result.stderr)
                self.assertFalse(
                    (install_root / self.RUNTIME_DIR / "p2pool-node").exists()
                )

    def test_refuses_non_fixed_binary_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-destination-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            install_root = root / "install-root"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            result = self.run_installer(
                source,
                install_root,
                systemctl,
                log,
                source_root,
                evidence,
                destination_override=root / "redirected-p2pool-node",
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fixed binary destination", result.stderr)
            self.assertFalse(install_root.exists())

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
                source, root / "install-root", systemctl, log, source_root, None
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--build-evidence is required", result.stderr)

    def test_requires_independently_selected_evidence_and_source_references(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pohw-adapter-trust-root-") as temp:
            root = Path(temp)
            source_root = root / "source"
            source = source_root / "target" / "release" / "p2pool-node"
            install_root = root / "install-root"
            destination = install_root / self.RUNTIME_DIR / "p2pool-node"
            self.write_binary(source, "new")
            evidence = self.write_build_evidence(source_root, source)
            systemctl = root / "systemctl"
            log = root / "systemctl.log"
            self.write_systemctl(systemctl, active=False)

            wrong_evidence = self.run_installer(
                source,
                install_root,
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
                install_root,
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
