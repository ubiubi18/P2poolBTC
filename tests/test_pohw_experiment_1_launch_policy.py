import base64
import contextlib
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "compatibility" / "experiment-1-launch-policy.json"
CANDIDATE = ROOT / "compatibility" / "experiment-1-miner-registry-candidate.json"
SCRIPT = ROOT / "scripts" / "pohw-experiment-1-launch-policy.py"
SPEC = importlib.util.spec_from_file_location("pohw_launch_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


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
        if value < 0:
            return encode_head(1, -1 - value)
        return encode_head(0, value)
    if isinstance(value, bytes):
        return encode_head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return encode_head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return encode_head(4, len(value)) + b"".join(encode_cbor(item) for item in value)
    if isinstance(value, dict):
        entries = [encode_cbor(key) + encode_cbor(item) for key, item in value.items()]
        return encode_head(5, len(entries)) + b"".join(sorted(entries))
    raise TypeError(f"unsupported CBOR fixture value: {type(value)!r}")


def encode_uvarint(value):
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def cid_text(raw):
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def package_report(report):
    block = encode_cbor(report)
    root = MODULE.CID_BYTES_PREFIX + hashlib.sha256(block).digest()
    header = encode_cbor({"roots": [CidTag(root)], "version": 1})
    car = (
        encode_uvarint(len(header))
        + header
        + encode_uvarint(len(root) + len(block))
        + root
        + block
    )
    return car, cid_text(root)


class Experiment1LaunchPolicyTests(unittest.TestCase):
    DAG_CBOR_CID = "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq"

    def readiness_report(self, evidence_bundle_cid=None):
        return {
            "schemaVersion": 1,
            "evidenceBundleCid": evidence_bundle_cid or self.DAG_CBOR_CID,
            "candidateEcosystemCid": self.DAG_CBOR_CID,
            "scopeEvidenceCid": self.DAG_CBOR_CID,
            "riskClass": "normal",
            "ready": True,
            "sourceCommitReceiptThreshold": 1,
            "verifiedSourceCommitReceiptCount": 1,
            "builderThreshold": 2,
            "matchingBuilderCount": 2,
            "builderPlatformThreshold": 1,
            "matchingBuilderPlatformCount": 1,
            "selectedCoreArtifactDigest": "ab" * 32,
            "availabilityThreshold": 2,
            "completeAvailabilityCount": 2,
            "externalAuditThreshold": 1,
            "passingExternalAuditCount": 1,
            "migrationRehearsalThreshold": 0,
            "matchingMigrationRehearsalCount": 0,
            "migrationRehearsalPlatformThreshold": 0,
            "matchingMigrationRehearsalPlatformCount": 0,
            "selectedMigrationRehearsalDigest": None,
            "requiredContentCidCount": 12,
            "failureCodes": [],
        }

    def build_ready_policy(self, directory, report=None):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        candidate = json.loads(CANDIDATE.read_text(encoding="utf-8"))
        evidence_car, evidence_cid = package_report(
            {"schemaVersion": 1, "fixture": "authenticated-readiness-evidence"}
        )
        evidence_path = directory / "deployment-readiness-evidence.car"
        evidence_path.write_bytes(evidence_car)
        report = self.readiness_report() if report is None else report
        report["evidenceBundleCid"] = evidence_cid
        car, report_cid = package_report(report)
        car_path = directory / "deployment-readiness.car"
        car_path.write_bytes(car)

        readiness = policy["public_join_readiness"]
        readiness.update({key: True for key in MODULE.READINESS_BOOLEAN_FIELDS})
        readiness.update(
            {
                "verified_independent_registry_build_operators": 2,
                "deployment_readiness_report_cid": report_cid,
                "deployment_readiness_report_car_sha256": hashlib.sha256(car).hexdigest(),
                "deployment_readiness_candidate_ecosystem_cid": self.DAG_CBOR_CID,
                "deployment_readiness_evidence_cid": evidence_cid,
                "deployment_readiness_evidence_car_sha256": hashlib.sha256(
                    evidence_car
                ).hexdigest(),
            }
        )
        policy["registry_source_candidate"]["deployment_authorized"] = True
        policy["status"] = MODULE.READY_STATUS

        anchor = {
            "schema_version": 2,
            "experiment_id": candidate["experiment_id"],
            "registry_contract_address": "0x" + "11" * 20,
            "registry_deployment_tx_hash": "0x" + "22" * 32,
            "registry_deployment_payload_sha256": "33" * 32,
            "registry_contract_code_hash": "44" * 32,
            "registry_contract_wasm_sha256": candidate["artifact"]["sha256"],
            "registry_ecosystem_cid": self.DAG_CBOR_CID,
            "minimum_registration_burn_atoms": "1000",
            "activation_idena_height": 100,
            "finality_confirmations": 6,
            "max_anchor_age_blocks": 12,
            "handoff_version_bit": 27,
        }
        anchor_path = directory / "idena-anchor-policy-v2.json"
        anchor_bytes = (json.dumps(anchor, indent=2, sort_keys=True) + "\n").encode("ascii")
        anchor_path.write_bytes(anchor_bytes)
        policy["registry_deployment"] = {
            "schema_version": MODULE.REGISTRY_DEPLOYMENT_SCHEMA,
            "idena_anchor_policy_sha256": hashlib.sha256(anchor_bytes).hexdigest(),
            "registry_contract_address": anchor["registry_contract_address"],
            "registry_deployment_tx_hash": anchor["registry_deployment_tx_hash"],
            "deployment_block_hash": "0x" + "55" * 32,
            "deployment_block_height": 80,
            "finalized_block_hash": "0x" + "66" * 32,
            "finalized_block_height": 86,
            "observed_registry_experiment_id": anchor["experiment_id"],
            "observed_registry_ecosystem_cid": anchor["registry_ecosystem_cid"],
            "observed_minimum_registration_burn_atoms": anchor[
                "minimum_registration_burn_atoms"
            ],
        }
        verification = {
            "schemaVersion": 1,
            "evidenceBundleCid": evidence_cid,
            "reportCid": report_cid,
            "reportSha256": hashlib.sha256(encode_cbor(report)).hexdigest(),
            "report": report,
        }
        verifier_path = directory / "pohw-governance"
        verifier_path.write_text(
            "#!/usr/bin/env python3\nprint(" + repr(json.dumps(verification)) + ")\n",
            encoding="ascii",
        )
        verifier_path.chmod(0o700)
        return policy, car_path, evidence_path, verifier_path, anchor_path

    def validate_ready(
        self, policy, car_path, evidence_path, verifier_path, anchor_path
    ):
        @contextlib.contextmanager
        def staged(path, *_args):
            yield MODULE.StagedExecutable(str(path))

        with mock.patch.object(
            MODULE, "stage_attested_executable", side_effect=staged
        ):
            MODULE.validate(
                policy,
                POLICY,
                ROOT,
                readiness_car_path=car_path,
                readiness_evidence_car_path=evidence_path,
                governance_cli_path=verifier_path,
                governance_cli_sha256=hashlib.sha256(verifier_path.read_bytes()).hexdigest(),
                idena_anchor_policy_path=anchor_path,
            )

    def test_checked_in_policy_is_valid_and_blocked(self):
        result = subprocess.run(
            ["python3", str(SCRIPT), str(POLICY), "--repo-root", str(ROOT)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("blocked-release-readiness", result.stdout)

    def test_service_mode_rejects_checked_in_blocked_policy(self):
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                str(POLICY),
                "--repo-root",
                str(ROOT),
                "--require-ready",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("launch requires ready-for-public-join", result.stderr)

    def test_ready_status_cannot_bypass_incomplete_gates(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        policy["status"] = MODULE.READY_STATUS
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "must remain blocked"):
            MODULE.validate(policy, POLICY, ROOT)

    def test_migration_readiness_requires_a_bound_rehearsal_digest(self):
        report = self.readiness_report()
        report.update(
            {
                "riskClass": "migration",
                "migrationRehearsalThreshold": 2,
                "matchingMigrationRehearsalCount": 2,
                "migrationRehearsalPlatformThreshold": 2,
                "matchingMigrationRehearsalPlatformCount": 2,
            }
        )
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "rehearsal digest"):
            MODULE.validate_readiness_report(report, self.DAG_CBOR_CID)

        report["selectedMigrationRehearsalDigest"] = "cd" * 32
        MODULE.validate_readiness_report(report, self.DAG_CBOR_CID)

        report["riskClass"] = "normal"
        report["migrationRehearsalThreshold"] = 0
        report["matchingMigrationRehearsalCount"] = 0
        report["migrationRehearsalPlatformThreshold"] = 0
        report["matchingMigrationRehearsalPlatformCount"] = 0
        with self.assertRaisesRegex(MODULE.LaunchPolicyError, "unexpected.*digest"):
            MODULE.validate_readiness_report(report, self.DAG_CBOR_CID)

    def test_complete_strict_evidence_can_satisfy_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            self.validate_ready(
                policy, car_path, evidence_path, verifier_path, anchor_path
            )

            compatibility = directory / "compatibility"
            compatibility.mkdir()
            for source in (
                ROOT / "compatibility" / "experiment-1-full-consensus.json",
                CANDIDATE,
            ):
                (compatibility / source.name).write_bytes(source.read_bytes())
            policy_path = compatibility / POLICY.name
            policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="ascii")
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    str(policy_path),
                    "--repo-root",
                    str(directory),
                    "--readiness-car",
                    str(car_path),
                    "--readiness-evidence-car",
                    str(evidence_path),
                    "--governance-cli",
                    str(verifier_path),
                    "--governance-cli-sha256",
                    hashlib.sha256(verifier_path.read_bytes()).hexdigest(),
                    "--idena-anchor-policy",
                    str(anchor_path),
                    "--require-ready",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if platform.system() == "Linux":
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(MODULE.READY_STATUS, result.stdout)
            else:
                self.assertEqual(result.returncode, 1)
                self.assertIn("supported only on Linux", result.stderr)

    def test_finalized_boolean_is_not_deployment_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(Path(temp_dir))
            )
            policy["registry_deployment"] = {"finalized": True}
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "registry deployment evidence fields are invalid"
            ):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

    def test_readiness_car_digest_and_root_are_recomputed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            policy["public_join_readiness"][
                "deployment_readiness_report_car_sha256"
            ] = "00" * 32
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "CAR SHA-256 does not match"):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

    def test_readiness_evidence_and_recomputed_report_are_transitively_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            policy["public_join_readiness"][
                "deployment_readiness_evidence_car_sha256"
            ] = "00" * 32
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "evidence CAR SHA-256 does not match"
            ):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            verifier_path.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="ascii")
            verifier_path.chmod(0o700)
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "readiness output fields are invalid"
            ):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            report = self.readiness_report(
                policy["public_join_readiness"]["deployment_readiness_evidence_cid"]
            )
            forged = {
                "schemaVersion": 1,
                "evidenceBundleCid": report["evidenceBundleCid"],
                "reportCid": policy["public_join_readiness"][
                    "deployment_readiness_report_cid"
                ],
                "reportSha256": "00" * 32,
                "report": report,
            }
            verifier_path.write_text(
                "#!/usr/bin/env python3\nprint("
                + repr(json.dumps(forged))
                + ")\n",
                encoding="ascii",
            )
            verifier_path.chmod(0o700)
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "recomputed readiness does not match"
            ):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            modified_car = bytearray(car_path.read_bytes())
            modified_car[-1] ^= 1
            car_path.write_bytes(modified_car)
            policy["public_join_readiness"][
                "deployment_readiness_report_car_sha256"
            ] = hashlib.sha256(modified_car).hexdigest()
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "root CID does not match its block"
            ):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            policy["public_join_readiness"][
                "deployment_readiness_report_cid"
            ] = self.DAG_CBOR_CID
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "root CID does not match"):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

    def test_readiness_report_is_strict_candidate_bound_and_ready(self):
        cases = (
            ("unknownField", True, "fields are invalid"),
            (
                "candidateEcosystemCid",
                cid_text(MODULE.CID_BYTES_PREFIX + b"\x99" * 32),
                "different candidate",
            ),
            ("ready", False, "report is not ready"),
        )
        for field, value, message in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                report = self.readiness_report()
                report[field] = value
                policy, car_path, evidence_path, verifier_path, anchor_path = (
                    self.build_ready_policy(Path(temp_dir), report)
                )
                with self.assertRaisesRegex(MODULE.LaunchPolicyError, message):
                    self.validate_ready(
                        policy, car_path, evidence_path, verifier_path, anchor_path
                    )

    def test_registry_evidence_requires_anchor_binding_and_finality_depth(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            policy["registry_deployment"]["finalized_block_height"] = 85
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "not finalized"):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            anchor = json.loads(anchor_path.read_text(encoding="ascii"))
            anchor["registry_contract_wasm_sha256"] = "77" * 32
            anchor_bytes = (json.dumps(anchor, indent=2, sort_keys=True) + "\n").encode(
                "ascii"
            )
            anchor_path.write_bytes(anchor_bytes)
            policy["registry_deployment"][
                "idena_anchor_policy_sha256"
            ] = hashlib.sha256(anchor_bytes).hexdigest()
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "reviewed registry WASM"):
                self.validate_ready(
                    policy, car_path, evidence_path, verifier_path, anchor_path
                )

    def test_missing_readiness_car_cannot_open_joining(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy, _, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(Path(temp_dir))
            )
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "CAR path is required"):
                MODULE.validate(
                    policy,
                    POLICY,
                    ROOT,
                    readiness_car_path=None,
                    readiness_evidence_car_path=evidence_path,
                    governance_cli_path=verifier_path,
                    governance_cli_sha256=hashlib.sha256(
                        verifier_path.read_bytes()
                    ).hexdigest(),
                    idena_anchor_policy_path=anchor_path,
                )

    @unittest.skipUnless(platform.system() == "Linux", "sealed executable snapshots require Linux")
    def test_readiness_verifier_binary_is_digest_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            policy, car_path, evidence_path, verifier_path, anchor_path = (
                self.build_ready_policy(directory)
            )
            with self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "independently selected SHA-256"
            ):
                MODULE.validate(
                    policy,
                    POLICY,
                    ROOT,
                    readiness_car_path=car_path,
                    readiness_evidence_car_path=evidence_path,
                    governance_cli_path=verifier_path,
                    governance_cli_sha256="00" * 32,
                    idena_anchor_policy_path=anchor_path,
                )

            digest = hashlib.sha256(verifier_path.read_bytes()).hexdigest()
            verifier_path.with_name(verifier_path.name + ".sha256").write_text(
                digest + "\n", encoding="ascii"
            )
            MODULE.validate(
                policy,
                POLICY,
                ROOT,
                readiness_car_path=car_path,
                readiness_evidence_car_path=evidence_path,
                governance_cli_path=verifier_path,
                idena_anchor_policy_path=anchor_path,
            )

    @unittest.skipUnless(platform.system() == "Linux", "sealed executable snapshots require Linux")
    def test_readiness_verifier_executes_the_attested_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            verifier = Path(temp_dir) / "pohw-governance"
            original = b"#!/bin/sh\nprintf 'reviewed\\n'\n"
            verifier.write_bytes(original)
            verifier.chmod(0o700)
            with MODULE.stage_attested_executable(
                verifier,
                "pohw-governance verifier",
                hashlib.sha256(original).hexdigest(),
            ) as staged:
                verifier.write_text("#!/bin/sh\nprintf 'substituted\\n'\n", encoding="ascii")
                verifier.chmod(0o700)
                result = MODULE.run_bounded(
                    [staged.command_path], pass_fds=staged.pass_fds
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"reviewed\n")

    def test_readiness_verifier_fails_closed_without_linux_sealing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            verifier = Path(temp_dir) / "pohw-governance"
            payload = b"#!/bin/sh\nexit 0\n"
            verifier.write_bytes(payload)
            verifier.chmod(0o700)
            with mock.patch.object(MODULE.platform, "system", return_value="Darwin"):
                with self.assertRaisesRegex(
                    MODULE.LaunchPolicyError, "supported only on Linux"
                ):
                    with MODULE.stage_attested_executable(
                        verifier,
                        "pohw-governance verifier",
                        hashlib.sha256(payload).hexdigest(),
                    ):
                        self.fail("non-Linux staging must not yield an executable")

    def test_readiness_verifier_output_is_bounded_before_capture(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(
                MODULE.LaunchPolicyError, "exceeds its size limit"
            ):
                MODULE.run_bounded(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import sys; sys."
                            + stream
                            + ".buffer.write(b'x' * "
                            + str(MODULE.MAX_JSON_BYTES + 1)
                            + ")"
                        ),
                    ]
                )

    def test_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.json"
            path.write_text('{"status":"first","status":"second"}\n', encoding="ascii")
            with self.assertRaisesRegex(MODULE.LaunchPolicyError, "duplicate JSON key"):
                MODULE.read_json(path, "launch policy")


if __name__ == "__main__":
    unittest.main()
