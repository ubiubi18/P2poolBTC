import hashlib
import json
import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "governance" / "governance-day-e2e.sh"
ASSEMBLER = (
    ROOT / "tests" / "governance" / "assemble-governance-day-e2e-report.mjs"
)
INTEGRATION = ROOT / "compatibility" / "governance-day-idena-ai-integration.json"
PARAMETERS = ROOT / "compatibility" / "governance-day-parameters.json"
PARAMETER_LOCK = ROOT / "compatibility" / "governance-day-parameters.lock.json"
LOCAL_CANDIDATE_LOCK = (
    ROOT / "compatibility" / "governance-day-local-candidate-lock.json"
)
FORK_CANDIDATE_LOCK = (
    ROOT / "compatibility" / "governance-day-fork-candidate-lock.json"
)


class GovernanceDayE2ETests(unittest.TestCase):
    def test_governance_day_parameter_lock_binds_every_consumer(self):
        lock = json.loads(PARAMETER_LOCK.read_text(encoding="utf-8"))
        parameter_bytes = PARAMETERS.read_bytes()
        self.assertEqual(lock["status"], "experimental-local-only")
        self.assertFalse(lock["authorizedForDeployment"])
        self.assertEqual(lock["sourceSha256"], hashlib.sha256(parameter_bytes).hexdigest())
        cid = lock["parameterSetCid"]
        generated = (
            ROOT
            / "contracts"
            / "idena-code-governance"
            / "assembly"
            / "generated_parameters.ts"
        ).read_text(encoding="utf-8")
        self.assertIn(f'GOVERNANCE_PARAMETER_SET_CID: string = "{cid}"', generated)
        contract = (
            ROOT / "contracts" / "idena-code-governance" / "assembly" / "index.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("EXPECTED_PARAMETER_CID = GOVERNANCE_PARAMETER_SET_CID", contract)
        emulator = (
            ROOT
            / "contracts"
            / "idena-code-governance"
            / "scripts"
            / "emulator-test.mjs"
        ).read_text(encoding="utf-8")
        self.assertIn("assert.deepEqual(deployedParameters.parameterProfile, lockedParameters)", emulator)
        node_api = (
            ROOT / "crates" / "p2pool-node" / "src" / "governance_api.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(cid, node_api)

        local_lock = json.loads(LOCAL_CANDIDATE_LOCK.read_text(encoding="utf-8"))
        fork_lock = json.loads(FORK_CANDIDATE_LOCK.read_text(encoding="utf-8"))
        lock_sha256 = hashlib.sha256(PARAMETER_LOCK.read_bytes()).hexdigest()
        self.assertEqual(local_lock["parameterSet"]["cid"], cid)
        self.assertEqual(local_lock["parameterSet"]["sha256"], lock["parameterSetSha256"])
        self.assertEqual(fork_lock["parameterSet"]["cid"], cid)
        self.assertEqual(fork_lock["parameterSet"]["sha256"], lock["parameterSetSha256"])
        self.assertEqual(fork_lock["parameterSet"]["lockSha256"], lock_sha256)

    def test_idena_ai_integration_record_is_exact_and_inactive(self):
        record = json.loads(INTEGRATION.read_text(encoding="utf-8"))
        patch = ROOT / record["integrationPatch"]["path"]
        patch_bytes = patch.read_bytes()
        self.assertEqual(record["status"], "experimental-local-only")
        self.assertEqual(record["canonicalAuthorization"], "none")
        self.assertFalse(record["deploymentPermitted"])
        self.assertFalse(record["releasePublicationPermitted"])
        self.assertFalse(record["automaticInstall"])
        self.assertFalse(record["automaticRollback"])
        self.assertEqual(record["integrationPatch"]["size"], len(patch_bytes))
        self.assertNotIn(b".env.e2e", patch_bytes)
        self.assertEqual(
            record["integrationPatch"]["sha256"],
            hashlib.sha256(patch_bytes).hexdigest(),
        )
        self.assertRegex(record["sourcePackage"]["canonicalSourceCid"], r"^bafy")
        self.assertEqual(record["sourcePackage"]["status"], "packaged-local-candidate")
        self.assertFalse(record["sourcePackage"]["policyRelaxed"])
        self.assertEqual(record["sourcePackage"]["removedForbiddenPath"], ".env.e2e")
        self.assertEqual(
            record["sourcePackage"]["redactionMechanism"],
            "harness-policy-removal-before-packaging",
        )

    def test_local_candidate_lock_cannot_authorize_deployment(self):
        lock = json.loads(LOCAL_CANDIDATE_LOCK.read_text(encoding="utf-8"))
        self.assertEqual(lock["status"], "experimental-local-only")
        self.assertFalse(lock["authorizedForDeployment"])
        self.assertFalse(lock["authorizedForRelease"])
        self.assertFalse(lock["canonicalReferenceChangePermitted"])
        self.assertIsNone(lock["source"]["candidateSourceCid"])
        profile = lock["governanceProfile"]
        self.assertTrue(profile["normalRiskEnabled"])
        self.assertEqual(
            profile["normalRiskClassifier"],
            "pohw-objective-risk-classifier-v2",
        )
        self.assertTrue(profile["scopeCountersDerivedFromVerifiedSourceTransitions"])
        self.assertTrue(profile["epochAnchorAuthenticated"])
        self.assertEqual(
            profile["epochAnchorRequiresSeparateForkProfile"],
            "compatibility/governance-day-fork-candidate-lock.json",
        )
        fork = json.loads(FORK_CANDIDATE_LOCK.read_text(encoding="utf-8"))
        self.assertFalse(fork["activation"]["enabled"])
        self.assertTrue(fork["forkProfile"]["consensusChangesAllowed"])
        self.assertTrue(
            all(
                component.get("candidateCommit") is None
                and component.get("candidateSourceStatus")
                == "deterministic-patched-source-uncommitted"
                and isinstance(component.get("candidateSourceCid"), str)
                and component["candidateSourceCid"].startswith("bafy")
                for component in fork["components"]
                if "patch" in component
            )
        )
        self.assertIsNone(lock["idenaAiIntegration"]["sourcePackagingBlocker"])
        self.assertRegex(lock["idenaAiIntegration"]["canonicalSourceCid"], r"^bafy")
        self.assertFalse(lock["executionPolicy"]["automaticInstall"])
        self.assertFalse(lock["executionPolicy"]["automaticRollback"])
        self.assertEqual(lock["executionPolicy"]["canonicalHistoryPageLimit"], 64)
        self.assertEqual(
            lock["parameterSet"]["cid"],
            json.loads(PARAMETER_LOCK.read_text(encoding="utf-8"))["parameterSetCid"],
        )

    def test_harness_is_explicit_disposable_and_non_deploying(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('POHW_CONFIRM_LOCAL_TEST_PATCH" != "YES"', source)
        self.assertIn("mktemp -d", source)
        self.assertIn("git -C \"$IDENA_AI_ROOT\" archive", source)
        self.assertIn("git -C \"$idena_ai_test_root\" apply --check", source)
        self.assertIn("demo-epoch-governance", source)
        self.assertIn("governance_vertical_slice", source)
        self.assertIn("proposal-verify", source)
        self.assertNotIn("git push", source)
        self.assertNotIn("docker push", source)
        self.assertNotIn("npm publish", source)

    def test_report_assembler_requires_every_numbered_step(self):
        source = ASSEMBLER.read_text(encoding="utf-8")
        self.assertIn("step <= 33", source)
        self.assertIn("missing concrete evidence", source)
        self.assertIn("automaticCodeInstall: false", source)
        self.assertIn("onChainRevertWhileChainStuck: false", source)

    @unittest.skipUnless(
        os.environ.get("POHW_RUN_GOVERNANCE_DAY_E2E") == "1",
        "set POHW_RUN_GOVERNANCE_DAY_E2E=1 with IDENA_AI_ROOT to run both repositories",
    )
    def test_cross_repository_governance_day(self):
        environment = os.environ.copy()
        environment["POHW_CONFIRM_LOCAL_TEST_PATCH"] = "YES"
        subprocess.run(
            [str(SCRIPT)],
            cwd=ROOT,
            check=True,
            timeout=1200,
            env=environment,
        )


if __name__ == "__main__":
    unittest.main()
