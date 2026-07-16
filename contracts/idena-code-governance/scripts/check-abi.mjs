import { readFile } from "node:fs/promises";

const wasm = await readFile(new URL("../build/idena-code-governance.wasm", import.meta.url));
const module = new WebAssembly.Module(wasm);
const asconfig = JSON.parse(
  await readFile(new URL("../asconfig.json", import.meta.url), "utf8"),
);
const disabledFeatures = asconfig?.targets?.release?.disable;
if (!Array.isArray(disabledFeatures) || !disabledFeatures.includes("bulk-memory")) {
  throw new Error("release target must disable bulk-memory for the pinned Idena runtime");
}

const allowedImports = new Set([
  "env.abort",
  "env.get_storage",
  "env.pay_amount",
  "env.set_storage",
  "env.emit_event",
  "env.caller",
  "env.own_addr",
  "env.epoch",
  "env.block_number",
  "env.epoch_block",
  "env.remove_storage",
  "env.create_transfer_promise",
  "env.burn",
]);
for (const item of WebAssembly.Module.imports(module)) {
  const key = `${item.module}.${item.name}`;
  if (item.kind !== "function" || !allowedImports.has(key)) {
    throw new Error(`unexpected WASM import: ${key} (${item.kind})`);
  }
}

const requiredExports = new Set([
  "memory",
  "allocate",
  "deploy",
  "registerGovernanceStake",
  "activateGovernanceStake",
  "activateCommunityGovernance",
  "scheduleWithdrawal",
  "beginUnbonding",
  "finalizeUnbonding",
  "registerIdentityMetricsProof",
  "submitIdentityMetricsAttestation",
  "identityMetricsCertification",
  "openReviewRound",
  "freezeReviewRound",
  "registerCriticalFindingWaiver",
  "expireReviewRound",
  "withdrawExpiredReviewBond",
  "withdrawExpiredReviewAttestationBond",
  "reviewRoundState",
  "createProposal",
  "submitProposalMetadataRoot",
  "submitAgentAttestation",
  "submitBuildAttestation",
  "submitDataAvailabilityAttestation",
  "openVoting",
  "castVote",
  "finalizeVoting",
  "submitObjectiveChallenge",
  "resolveObjectiveChallenge",
  "advanceChallengePeriod",
  "executeProposal",
  "executeRevert",
  "expireProposal",
  "withdrawRefundableBond",
  "claimAcceptedProposalBond",
  "claimNoQuorumRefund",
  "withdrawAttestationBond",
  "canonicalEcosystemCid",
  "governanceParameterSetCid",
  "proposalState",
  "voterReceipt",
  "governanceStakeState",
  "governanceParameters",
  "communityGovernanceStatus",
  "attestationDiversityCapability",
  "anchorGovernanceEpoch",
  "attachAiReviewRoot",
  "attachBuildRoot",
  "attachRecoveryManifest",
  "cancelProposalBeforeCutoff",
  "commitEpochBallot",
  "createRevertProposal",
  "enterExecutionReadyState",
  "finalizeEpochVoting",
  "finalizeEpochVotingForEpoch",
  "freezeEpochProposalSet",
  "getCanonicalHistory",
  "getCanonicalHistoryPage",
  "getEpochBallotReceipt",
  "getEpochDecisionRecord",
  "getEpochProposalSet",
  "getGovernanceEpoch",
  "getGovernanceSchedule",
  "getProposalSlot",
  "getTreasuryState",
  "previewVotingPower",
  "revealEpochBallot",
]);
const exports = new Set(WebAssembly.Module.exports(module).map((item) => item.name));
for (const name of requiredExports) {
  if (!exports.has(name)) throw new Error(`required WASM export is missing: ${name}`);
}
for (const name of exports) {
  if (!requiredExports.has(name)) throw new Error(`unexpected WASM export: ${name}`);
}

console.log(`ABI check passed: ${allowedImports.size} allowlisted imports, ${exports.size} exports`);
