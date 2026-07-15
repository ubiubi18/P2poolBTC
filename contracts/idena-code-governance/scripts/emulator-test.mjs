import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { TextDecoder, TextEncoder } from "node:util";
import * as dagCbor from "@ipld/dag-cbor";
import { CID } from "multiformats/cid";

const wasm = await readFile(new URL("../build/idena-code-governance.wasm", import.meta.url));
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const storage = new Map();
const events = [];
const transfers = [];
const burns = [];
let caller = Buffer.alloc(20);
let payment = 0n;
let epoch = 10;
let block = 1n;
let epochBlock = 1n;
let exports;
const contractAddress = Buffer.from("99".repeat(20), "hex");

const imports = {
  env: {
    abort(messagePtr, filePtr, line, column) {
      throw new Error(`WASM assertion failed: ${readAssemblyScriptString(messagePtr)} at ${readAssemblyScriptString(filePtr)}:${line}:${column}`);
    },
    get_storage(keyPtr) {
      const value = storage.get(readString(keyPtr));
      return value === undefined ? 0 : writeBytes(value);
    },
    set_storage(keyPtr, valuePtr) {
      storage.set(readString(keyPtr), Buffer.from(readBytes(valuePtr)));
    },
    remove_storage(keyPtr) { storage.delete(readString(keyPtr)); },
    caller() { return writeBytes(caller); },
    own_addr() { return writeBytes(contractAddress); },
    pay_amount() { return payment === 0n ? 0 : writeBytes(bigEndian(payment)); },
    create_transfer_promise(addressPtr, amountPtr) {
      transfers.push({ address: Buffer.from(readBytes(addressPtr)).toString("hex"), amount: fromBigEndian(readBytes(amountPtr)) });
    },
    emit_event(namePtr, argsPtr) {
      events.push({ name: readString(namePtr), args: Buffer.from(readBytes(argsPtr)) });
    },
    epoch() { return epoch; },
    block_number() { return block; },
    epoch_block() { return epochBlock; },
    remove_storage() {},
    burn(amountPtr) { burns.push(fromBigEndian(readBytes(amountPtr))); },
  },
};
delete imports.env.remove_storage;
imports.env.remove_storage = (keyPtr) => storage.delete(readString(keyPtr));

const instance = await WebAssembly.instantiate(wasm, imports);
exports = instance.instance.exports;

const addresses = Array.from({ length: 13 }, (_, index) => {
  const value = Buffer.alloc(20);
  value.writeUInt32BE(index + 1, 16);
  return value;
});
const states = [
  "Human", "Verified", "Human", "Verified", "Human", "Verified",
  "Newbie", "Newbie", "Newbie", "Newbie", "Newbie", "Newbie", "Newbie",
];
const sourceHash = digest("metrics-source").toString("hex");
const metricLeaves = addresses.map((address, index) => ({
  address,
  state: states[index],
  finalized: BigInt(index),
  reported: 0n,
  trust: flipTrust(BigInt(index), 0n),
  sourceEpoch: 10,
  sourceHeight: 1000n,
  sourceHash,
}));
const metricTree = metricsTree(metricLeaves);

const parameterCid = "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq";
const ecosystemManifests = new Map();
const initialSource = sourceManifestFixture("P2poolBTC", [
  sourceFileFixture("fixture.txt", "initial-source-content"),
]);
const initialManifest = ecosystemManifestFixture("initial", null, initialSource, []);
const initialCid = initialManifest.cid;
expectFailure(() => call("deploy", [initialCid, cid("wrong-parameters"), metricTree.root, "10"], {
  caller: addresses[0], block: 1n, epoch: 10,
}));
call("deploy", [initialCid, parameterCid, metricTree.root, "10"], { caller: addresses[0], block: 1n, epoch: 10 });
assert.equal(storage.get("epoch-governance:enabled").toString(), "1");
// Legacy regression cases below deliberately bypass the production deployment
// invariant through direct emulator storage access. No contract method can do this.
storage.delete("epoch-governance:enabled");

for (let index = 0; index < addresses.length; index++) {
  const leaf = metricLeaves[index];
  call("registerIdentityMetricsProof", [
    leaf.state,
    leaf.finalized.toString(),
    leaf.reported.toString(),
    leaf.trust.toString(),
    leaf.sourceEpoch.toString(),
    leaf.sourceHeight.toString(),
    leaf.sourceHash,
    index.toString(),
    metricLeaves.length.toString(),
    metricTree.proofs[index].join(","),
  ], { caller: addresses[index], block: 2n, epoch: 10 });
  call("registerGovernanceStake", [], {
    caller: addresses[index], block: 2n, epoch: 10, payment: 100n * 10n ** 18n,
  });
}
for (const address of addresses) {
  call("activateGovernanceStake", [], { caller: address, block: 3n, epoch: 11 });
}

const metricsAttestations = addresses.slice(0, 3).map((address) => metricsAttestation(address));
call("submitIdentityMetricsAttestation", [metricsAttestations[0].cid, metricsAttestations[0].hex], {
  caller: addresses[0], block: 3n, epoch: 11,
});
expectFailure(() => call(
  "submitIdentityMetricsAttestation",
  [metricsAttestations[0].cid, metricsAttestations[0].hex],
  { caller: addresses[0], block: 3n, epoch: 11 },
));
const disagreeingMetricsAttestation = metricsAttestation(addresses[3], {
  replayCommitment: digest("different-replay").toString("hex"),
});
call(
  "submitIdentityMetricsAttestation",
  [disagreeingMetricsAttestation.cid, disagreeingMetricsAttestation.hex],
  { caller: addresses[3], block: 3n, epoch: 11 },
);
for (let index = 1; index < metricsAttestations.length; index++) {
  call("submitIdentityMetricsAttestation", [metricsAttestations[index].cid, metricsAttestations[index].hex], {
    caller: addresses[index], block: 3n, epoch: 11,
  });
}
const metricsCertification = JSON.parse(call("identityMetricsCertification", [metricTree.root, "10"], {
  caller: addresses[7], block: 3n, epoch: 11,
}));
assert.equal(metricsCertification.attestations, 3);
assert.equal(metricsCertification.certified, true);
expectFailure(() => call(
  "submitIdentityMetricsAttestation",
  [disagreeingMetricsAttestation.cid, disagreeingMetricsAttestation.hex],
  { caller: addresses[4], block: 3n, epoch: 11 },
));
const certificationAfterRejectedConflict = JSON.parse(call(
  "identityMetricsCertification",
  [metricTree.root, "10"],
  { caller: addresses[7], block: 3n, epoch: 11 },
));
assert.equal(certificationAfterRejectedConflict.certified, true);
assert.equal(certificationAfterRejectedConflict.conflict, false);
assert.equal(certificationAfterRejectedConflict.attestations, 3);

const unstableSnapshot = proposalFixtures(
  "same-block-snapshot", addresses, initialCid, cid("same-block-candidate"), false, 44, 12,
);
call("registerGovernanceStake", [], {
  caller: addresses[0], block: 4n, epoch: 11, payment: 100n * 10n ** 18n,
});
const unstableRound = openAndFreezeReview(unstableSnapshot, 4n, 44n, 11, 12);
bindProposalToReview(unstableSnapshot, unstableRound.reviewRoundId);
const autoSettledCreate = JSON.parse(call("createProposal", unstableSnapshot.createArgs, {
  caller: addresses[0], block: 44n, epoch: 12,
}));
const autoSettledState = JSON.parse(call("proposalState", [autoSettledCreate.proposalId], {
  caller: addresses[7], block: 44n, epoch: 12,
}));
const expectedAutoSettledWeight = metricLeaves.reduce((total, leaf, index) => (
  total + governanceWeight((index === 0 ? 200n : 100n) * 10n ** 18n, leaf.state, leaf.trust)
), 0n);
assert.equal(autoSettledState.pos.snapshot, expectedAutoSettledWeight.toString());
const lazilyActivatedStake = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 44n, epoch: 12,
}));
assert.equal(lazilyActivatedStake.active, (100n * 10n ** 18n).toString());
assert.match(lazilyActivatedStake.pending, /^100000000000000000000~12~/);

const first = proposalFixtures("first", addresses, initialCid, cid("candidate-one"), false, 50, 12);
const unlistedSourceCid = cid("unlisted-candidate-source");
const unlistedCandidate = dagObject({
  ...first.candidateManifest.value,
  repositories: [
    ...first.candidateManifest.value.repositories,
    {
      schemaVersion: 1,
      name: "Unreviewed",
      sourceTreeCid: link(unlistedSourceCid),
      sourceTreeSha256: cidSha256(unlistedSourceCid),
      gitBundleCid: null,
      gitCommitMetadata: null,
      dependencyLocks: [],
      toolchainLocks: { cargo: "1.97.0" },
      buildInstructions: ["cargo build --locked"],
      artifacts: [],
    },
  ],
});
const incompleteAggregatePatch = dagObject({
  ...first.patch.value,
  candidateEcosystemCid: link(unlistedCandidate.cid),
});
expectFailure(() => call("openReviewRound", [
  first.parentCid, first.parentManifest.hex,
  unlistedCandidate.cid, unlistedCandidate.hex,
  incompleteAggregatePatch.cid, incompleteAggregatePatch.hex,
  first.pinset.cid, first.pinset.hex,
  first.scope.cid, first.scope.hex,
], { caller: addresses[0], block: 10n, epoch: 11, payment: 25n * 10n ** 18n }));
expectFailure(() => call("openReviewRound", [
  ...first.openArgs.slice(0, 3), `${first.candidateManifest.hex.slice(0, -2)}00`, ...first.openArgs.slice(4),
], { caller: addresses[0], block: 10n, epoch: 11, payment: 25n * 10n ** 18n }));
const fabricatedScope = dagObject({
  ...first.scope.value,
  repositories: [{
    ...first.scope.value.repositories[0],
    changes: [{
      path: "docs/fabricated.md",
      changeKind: "upsert",
      size: first.scope.value.repositories[0].changes[0].size,
    }],
  }],
  derivedRiskClass: "normal",
});
expectFailure(() => call("openReviewRound", [
  ...first.openArgs.slice(0, 8), fabricatedScope.cid, fabricatedScope.hex,
], { caller: addresses[0], block: 10n, epoch: 11, payment: 25n * 10n ** 18n }));
const firstRound = JSON.parse(call("openReviewRound", first.openArgs, {
  caller: addresses[0], block: 10n, epoch: 11, payment: 25n * 10n ** 18n,
}));
const omittedArtifact = proposalFixtures(
  "omitted-build-artifact",
  addresses,
  initialCid,
  cid("omitted-build-artifact-candidate"),
  false,
  50,
  12,
  false,
  null,
  "crates/p2pool-node/src/lib.rs",
  "critical",
  true,
);
const omittedArtifactRound = JSON.parse(call("openReviewRound", omittedArtifact.openArgs, {
  caller: addresses[0], block: 10n, epoch: 11, payment: 25n * 10n ** 18n,
}));
expectFailure(() => call("submitBuildAttestation", [
  omittedArtifactRound.reviewRoundId,
  omittedArtifact.builds[0].cid,
  omittedArtifact.builds[0].hex,
  omittedArtifact.toolchain.hex,
], { caller: omittedArtifact.builds[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const unrelatedAgentSource = dagObject({
  ...first.agents[0].value,
  affectedRepositories: [{ repository: "P2poolBTC", cid: cid("unrelated-agent-source") }],
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, unrelatedAgentSource.cid, unrelatedAgentSource.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const unrelatedBuildSource = dagObject({
  ...first.builds[0].value,
  sourceCids: [{ repository: "P2poolBTC", cid: cid("unrelated-build-source") }],
});
expectFailure(() => call("submitBuildAttestation", [
  firstRound.reviewRoundId, unrelatedBuildSource.cid, unrelatedBuildSource.hex, first.toolchain.hex,
], { caller: first.builds[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const unrelatedToolchain = dagObject({
  schemaVersion: 1,
  ecosystemLocks: { node: "24.18.0", rust: "different" },
  repositoryLocks: [{ repository: "P2poolBTC", toolchainLocks: { cargo: "1.97.0" } }],
});
const unrelatedToolchainBuild = dagObject({
  ...first.builds[0].value,
  toolchainCid: unrelatedToolchain.cid,
});
expectFailure(() => call("submitBuildAttestation", [
  firstRound.reviewRoundId, unrelatedToolchainBuild.cid, unrelatedToolchainBuild.hex, unrelatedToolchain.hex,
], { caller: first.builds[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const rogueArtifact = {
  name: "rogue",
  cid: rawCid("rogue-artifact"),
  sha256: digest("rogue-artifact").toString("hex"),
  size: 1,
  core: true,
};
const rogueArtifactBuild = dagObject({
  ...first.builds[0].value,
  artifacts: [rogueArtifact],
  coreArtifactDigest: coreArtifactSetDigest([rogueArtifact]),
});
expectFailure(() => call("submitBuildAttestation", [
  firstRound.reviewRoundId, rogueArtifactBuild.cid, rogueArtifactBuild.hex, first.toolchain.hex,
], { caller: first.builds[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const incompleteAvailability = dagObject({
  ...first.availability[0].value,
  verifiedCids: [first.candidateCid],
});
expectFailure(() => call("submitDataAvailabilityAttestation", [
  firstRound.reviewRoundId, incompleteAvailability.cid, incompleteAvailability.hex,
], { caller: first.availability[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const lateFinalizationGapAvailability = dagObject({
  ...first.availability[0].value,
  // The round opened at block 10 and can be claimed at block 90. An expiry at
  // 1029 covers the original schedule but not a finalization delayed to the
  // original challenge deadline followed by a fresh challenge period.
  expiresAtBlock: 1029,
});
expectFailure(() => call("submitDataAvailabilityAttestation", [
  firstRound.reviewRoundId,
  lateFinalizationGapAvailability.cid,
  lateFinalizationGapAvailability.hex,
], { caller: first.availability[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, first.agents[0].cid, `${first.agents[0].hex.slice(0, -2)}00`,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const wrongResultCodec = dagObject({
  ...first.agents[0].value,
  testResultsCid: cid("dag-cbor-result-is-forbidden"),
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, wrongResultCodec.cid, wrongResultCodec.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const outOfRangeExitCode = dagObject({
  ...first.agents[0].value,
  commandsExecuted: first.agents[0].value.commandsExecuted.map((entry) => ({
    ...entry,
    exitCode: 2147483648,
  })),
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, outOfRangeExitCode.cid, outOfRangeExitCode.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const contradictoryAgentResult = dagObject({
  ...first.agents[0].value,
  commandsExecuted: first.agents[0].value.commandsExecuted.map((entry) => ({
    ...entry,
    exitCode: 1,
  })),
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, contradictoryAgentResult.cid, contradictoryAgentResult.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const contradictoryBuildResult = dagObject({
  ...first.builds[0].value,
  commands: first.builds[0].value.commands.map((entry) => ({
    ...entry,
    exitCode: 1,
  })),
});
expectFailure(() => call("submitBuildAttestation", [
  firstRound.reviewRoundId, contradictoryBuildResult.cid, contradictoryBuildResult.hex, first.toolchain.hex,
], { caller: first.builds[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const partiallyRedactedSecret = dagObject({
  ...first.agents[0].value,
  commandsExecuted: first.agents[0].value.commandsExecuted.map((entry) => ({
    ...entry,
    command: "tool --token=[REDACTED] --password=still-visible",
  })),
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, partiallyRedactedSecret.cid, partiallyRedactedSecret.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
submitEvidenceAttestations(firstRound.reviewRoundId, first, 11n, 11);
const ownerCappedAgent = dagObject({
  ...first.agents[0].value,
  modelIdentifier: "owner-cap-model",
  providerOrRuntimeIdentifier: "owner-cap-runtime",
  modelFamily: "owner-cap-family",
  testResultsCid: rawCid("owner-cap-agent-result"),
  staticAnalysisResultsCid: cid("owner-cap-static"),
  dependencyFindingsCid: cid("owner-cap-dependencies"),
});
expectFailure(() => call("submitAgentAttestation", [
  firstRound.reviewRoundId, ownerCappedAgent.cid, ownerCappedAgent.hex,
], { caller: first.agents[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const duplicateUnavailableProvider = dagObject({
  ...first.availability[0].value,
  available: false,
});
expectFailure(() => call("submitDataAvailabilityAttestation", [
  firstRound.reviewRoundId, duplicateUnavailableProvider.cid, duplicateUnavailableProvider.hex,
], { caller: first.availability[0].owner, block: 11n, epoch: 11, payment: 10n ** 18n }));
const firstEvidenceFrozen = JSON.parse(call("freezeReviewRound", [firstRound.reviewRoundId], {
  caller: addresses[7], block: 50n, epoch: 12,
  }));
assert.equal(firstEvidenceFrozen.state, "AvailabilityOpen");
assert.equal(firstEvidenceFrozen.dataAvailabilityRoot, null);
call("submitDataAvailabilityAttestation", [
  firstRound.reviewRoundId, first.availability[0].cid, first.availability[0].hex,
], { caller: first.availability[0].owner, block: 50n, epoch: 12, payment: 10n ** 18n });
expectFailure(() => call("freezeReviewRound", [firstRound.reviewRoundId], {
  caller: addresses[7], block: 50n, epoch: 12,
}));
assert.equal(JSON.parse(call("reviewRoundState", [firstRound.reviewRoundId], {
  caller: addresses[7], block: 50n, epoch: 12,
})).state, "AvailabilityOpen");
first.availability.slice(1).forEach((item) => call("submitDataAvailabilityAttestation", [
  firstRound.reviewRoundId, item.cid, item.hex,
], { caller: item.owner, block: 50n, epoch: 12, payment: 10n ** 18n }));
const firstFrozen = JSON.parse(call("freezeReviewRound", [firstRound.reviewRoundId], {
  caller: addresses[7], block: 50n, epoch: 12,
}));
assert.equal(firstFrozen.agentReviewRoot, first.agentTree.root);
assert.equal(firstFrozen.buildAttestationRoot, first.buildTree.root);
assert.equal(firstFrozen.dataAvailabilityRoot, first.availabilityTree.root);
bindProposalToReview(first, firstRound.reviewRoundId);
expectFailure(() => call("createProposal", [first.createArgs[0], `${first.createArgs[1].slice(0, -2)}00`], {
  caller: addresses[0], block: 50n, epoch: 12,
}));
const forbiddenMetricsTransition = dagObject({
  ...first.proposal.value,
  candidateIdentityMetricsRoot: digest("forbidden-metrics").toString("hex"),
  candidateIdentityMetricsEpoch: 11,
});
expectFailure(() => call("createProposal", [forbiddenMetricsTransition.cid, forbiddenMetricsTransition.hex], {
  caller: addresses[0], block: 50n, epoch: 12,
}));
const substitutedBaseSource = dagObject({
  ...first.proposal.value,
  baseSourceCids: { P2poolBTC: cid("substituted-base-source") },
});
expectFailure(() => call("createProposal", [substitutedBaseSource.cid, substitutedBaseSource.hex], {
  caller: addresses[0], block: 50n, epoch: 12,
}));
const create = JSON.parse(call("createProposal", first.createArgs, {
  caller: addresses[0], block: 50n, epoch: 12,
}));
assert.match(create.proposalId, /^[0-9a-f]{64}$/);
const storedProposalKey = `proposal:${create.proposalId}`;
const validStoredProposal = Buffer.from(storage.get(storedProposalKey));
for (const [field, invalid] of [[8, "256"], [34, "4294967296"], [52, "2"]]) {
  const corrupt = decoder.decode(validStoredProposal).split("~");
  corrupt[field] = invalid;
  storage.set(storedProposalKey, Buffer.from(corrupt.join("~")));
  expectFailure(() => call("proposalState", [create.proposalId], {
    caller: addresses[7], block: 50n, epoch: 12,
  }));
}
storage.set(storedProposalKey, validStoredProposal);
call("submitProposalMetadataRoot", [create.proposalId, create.metadataRoot], { caller: addresses[7], block: 50n, epoch: 12 });
expectFailure(() => call("openVoting", [create.proposalId], { caller: addresses[7], block: 89n, epoch: 12 }));
call("openVoting", [create.proposalId], { caller: addresses[7], block: 90n, epoch: 12 });

call("castVote", [create.proposalId, "no"], { caller: addresses[0], block: 91n, epoch: 12 });
call("castVote", [create.proposalId, "yes"], { caller: addresses[0], block: 91n, epoch: 12 });
for (let index = 1; index < addresses.length; index++) {
  call("castVote", [create.proposalId, "yes"], { caller: addresses[index], block: 91n, epoch: 12 });
}
expectFailure(() => call("castVote", [create.proposalId, "yes"], { caller: addresses[7], block: 210n, epoch: 12 }));
let state = JSON.parse(call("finalizeVoting", [create.proposalId], { caller: addresses[7], block: 210n, epoch: 12 }));
assert.equal(state.state, "AcceptedPendingChallenge");
assert.equal(state.pohw.yesIdentities, 13);
state = JSON.parse(call("advanceChallengePeriod", [create.proposalId], { caller: addresses[7], block: 270n, epoch: 12 }));
assert.equal(state.state, "AcceptedPendingExecution");
expectFailure(() => call("executeProposal", [create.proposalId], { caller: addresses[6], block: 329n, epoch: 12 }));
state = JSON.parse(call("executeProposal", [create.proposalId], { caller: addresses[6], block: 330n, epoch: 12 }));
assert.equal(state.state, "Executed");
assert.equal(state.buildAttestationRoot, first.buildTree.root);
assert.equal(JSON.parse(call("canonicalEcosystemCid", [], { caller: addresses[3], block: 330n, epoch: 12 })).canonicalEcosystemCid, first.candidateCid);
expectFailure(() => call("executeProposal", [create.proposalId], { caller: addresses[0], block: 331n, epoch: 12 }));
call("expireReviewRound", [omittedArtifactRound.reviewRoundId], {
  caller: addresses[7], block: 331n, epoch: 12,
});
call("withdrawExpiredReviewBond", [omittedArtifactRound.reviewRoundId], {
  caller: addresses[0], block: 331n, epoch: 12,
});

call("withdrawRefundableBond", [create.proposalId], { caller: addresses[0], block: 331n, epoch: 12 });
call("withdrawAttestationBond", [create.proposalId, "agent", first.agents[0].cid], { caller: addresses[0], block: 331n, epoch: 12 });
assert.equal(transfers.at(-2).amount, 25n * 10n ** 18n);
assert.equal(transfers.at(-1).amount, 10n ** 18n);
for (let index = 1; index < first.agents.length; index++) {
  call("withdrawAttestationBond", [create.proposalId, "agent", first.agents[index].cid], {
    caller: first.agents[index].owner, block: 331n, epoch: 12,
  });
}
for (const [kind, entries] of [["build", first.builds], ["availability", first.availability]]) {
  for (const item of entries) {
    call("withdrawAttestationBond", [create.proposalId, kind, item.cid], {
      caller: item.owner, block: 331n, epoch: 12,
    });
  }
}
call("expireProposal", [autoSettledCreate.proposalId], { caller: addresses[7], block: 331n, epoch: 12 });
call("withdrawRefundableBond", [autoSettledCreate.proposalId], {
  caller: addresses[0], block: 332n, epoch: 12,
});
withdrawProposalAttestationBonds(autoSettledCreate.proposalId, unstableSnapshot, 332n, 12);

const conflicted = proposalFixtures("conflicted", addresses, first.candidateCid, cid("candidate-two"), true, 380, 12);
const conflictedRound = openAndFreezeReview(conflicted, 340n, 380n, 12, 12);
bindProposalToReview(conflicted, conflictedRound.reviewRoundId);
const conflictedCreate = JSON.parse(call("createProposal", conflicted.createArgs, {
  caller: addresses[0], block: 380n, epoch: 12,
}));
call("submitProposalMetadataRoot", [conflictedCreate.proposalId, conflictedCreate.metadataRoot], {
  caller: addresses[7], block: 380n, epoch: 12,
});
state = JSON.parse(call("reviewRoundState", [conflictedRound.reviewRoundId], {
  caller: addresses[7], block: 380n, epoch: 12,
}));
assert.equal(state.state, "Claimed");
assert.equal(state.buildAttestations, 4);
assert.equal(state.builderConflicts, 1);
state = JSON.parse(call("expireProposal", [conflictedCreate.proposalId], {
  caller: addresses[7], block: 540n, epoch: 12,
}));
assert.equal(state.state, "Expired");
assert.equal(JSON.parse(call("canonicalEcosystemCid", [], { caller: addresses[3], block: 541n, epoch: 12 })).canonicalEcosystemCid, first.candidateCid);
call("withdrawRefundableBond", [conflictedCreate.proposalId], {
  caller: addresses[0], block: 541n, epoch: 12,
});
withdrawProposalAttestationBonds(conflictedCreate.proposalId, conflicted, 541n, 12);

const pendingUnbondRebaseBranch = snapshotHarnessState();
const pendingUnbondAddress = addresses[12];
const pendingUnbondActive = 100n * 10n ** 18n;
const pendingUnbondDeposit = 1n * 10n ** 18n;
call("scheduleWithdrawal", [pendingUnbondActive.toString()], {
  caller: pendingUnbondAddress, block: 542n, epoch: 16,
});
call("registerGovernanceStake", [], {
  caller: pendingUnbondAddress, block: 543n, epoch: 21, payment: pendingUnbondDeposit,
});
const pendingUnbondBefore = JSON.parse(call("governanceStakeState", [], {
  caller: pendingUnbondAddress, block: 543n, epoch: 21,
})).pending.split("~");
assert.equal(
  pendingUnbondBefore[3],
  (
    governanceWeight(pendingUnbondActive + pendingUnbondDeposit, metricLeaves[12].state, metricLeaves[12].trust)
    - governanceWeight(pendingUnbondActive, metricLeaves[12].state, metricLeaves[12].trust)
  ).toString(),
);
call("finalizeUnbonding", [], { caller: pendingUnbondAddress, block: 544n, epoch: 21 });
const pendingUnbondAfter = JSON.parse(call("governanceStakeState", [], {
  caller: pendingUnbondAddress, block: 544n, epoch: 21,
}));
assert.equal(pendingUnbondAfter.active, "0");
assert.equal(pendingUnbondAfter.pending.split("~")[3], governanceWeight(
  pendingUnbondDeposit, metricLeaves[12].state, metricLeaves[12].trust,
).toString());
assert.equal(
  decoder.decode(storage.get("governance:scheduled-weight-delta")),
  governanceWeight(pendingUnbondDeposit, metricLeaves[12].state, metricLeaves[12].trust).toString(),
);
call("activateGovernanceStake", [], { caller: pendingUnbondAddress, block: 545n, epoch: 22 });
assert.equal(JSON.parse(call("governanceStakeState", [], {
  caller: pendingUnbondAddress, block: 545n, epoch: 22,
})).active, pendingUnbondDeposit.toString());
restoreHarnessState(pendingUnbondRebaseBranch);

call("scheduleWithdrawal", [(100n * 10n ** 18n).toString()], { caller: addresses[0], block: 550n, epoch: 11 });
call("finalizeUnbonding", [], { caller: addresses[0], block: 580n, epoch: 16 });
assert.equal(transfers.at(-1).amount, 100n * 10n ** 18n);
const baseRegisteredWeight = metricLeaves.reduce((total, leaf) => (
  total + governanceWeight(100n * 10n ** 18n, leaf.state, leaf.trust)
), 0n);
assert.equal(decoder.decode(storage.get("governance:total-weight")), baseRegisteredWeight.toString());

const expired = proposalFixtures("expired", addresses, first.candidateCid, cid("candidate-expired"), false, 600, 16);
const expiredCreate = prepareProposal(expired, 560n, 600n, 16);
call("openVoting", [expiredCreate.proposalId], { caller: addresses[7], block: 640n, epoch: 16 });
call("scheduleWithdrawal", [(100n * 10n ** 18n).toString()], { caller: addresses[1], block: 640n, epoch: 16 });
expectFailure(() => call("finalizeUnbonding", [], { caller: addresses[1], block: 641n, epoch: 21 }));
assert.equal(
  decoder.decode(storage.get("governance:total-weight")),
  baseRegisteredWeight.toString(),
);
for (let index = 1; index < addresses.length; index++) {
  call("castVote", [expiredCreate.proposalId, "yes"], { caller: addresses[index], block: 642n, epoch: 21 });
}
state = JSON.parse(call("finalizeVoting", [expiredCreate.proposalId], {
  caller: addresses[7], block: 760n, epoch: 16,
}));
assert.equal(state.state, "AcceptedPendingChallenge");
state = JSON.parse(call("advanceChallengePeriod", [expiredCreate.proposalId], {
  caller: addresses[7], block: 821n, epoch: 16,
}));
assert.equal(state.state, "AcceptedPendingExecution");
expectFailure(() => call("expireProposal", [expiredCreate.proposalId], {
  caller: addresses[6], block: 1480n, epoch: 16,
}));
expectFailure(() => call("executeProposal", [expiredCreate.proposalId], {
  caller: addresses[6], block: 1481n, epoch: 16,
}));
state = JSON.parse(call("expireProposal", [expiredCreate.proposalId], {
  caller: addresses[6], block: 1481n, epoch: 16,
}));
assert.equal(state.state, "Expired");
assert.equal(burns.at(-1), 625n * 10n ** 16n);
assert.equal(JSON.parse(call("canonicalEcosystemCid", [], {
  caller: addresses[3], block: 1481n, epoch: 16,
})).canonicalEcosystemCid, first.candidateCid);
call("withdrawRefundableBond", [expiredCreate.proposalId], {
  caller: addresses[0], block: 1482n, epoch: 16,
});
assert.equal(transfers.at(-1).amount, 1875n * 10n ** 16n);

call("registerGovernanceStake", [], {
  caller: addresses[0], block: 1490n, epoch: 20, payment: 100n * 10n ** 18n,
});
call("registerGovernanceStake", [], {
  caller: addresses[1], block: 1490n, epoch: 20, payment: 100n * 10n ** 18n,
});
call("activateGovernanceStake", [], { caller: addresses[0], block: 1491n, epoch: 21 });
call("activateGovernanceStake", [], { caller: addresses[1], block: 1491n, epoch: 21 });
const expectedAfterBlockedUnbonding = expectedAutoSettledWeight
  + governanceWeight(200n * 10n ** 18n, metricLeaves[1].state, metricLeaves[1].trust)
  - governanceWeight(100n * 10n ** 18n, metricLeaves[1].state, metricLeaves[1].trust);
assert.equal(decoder.decode(storage.get("governance:total-weight")), expectedAfterBlockedUnbonding.toString());

exerciseFalseClaimChallenge("agent-false-claim", "agent_test_result", 1600);
exerciseFalseClaimChallenge("builder-false-claim", "builder_test_result", 1800);
exerciseFalseClaimChallenge("availability-false-claim", "availability_probe", 2000);

const duplicateAgents = proposalFixtures(
  "duplicate-agents",
  addresses,
  first.candidateCid,
  cid("candidate-duplicate-agents"),
  false,
  2200,
  21,
  true,
);
const duplicateRound = openAndFreezeReview(duplicateAgents, 2160n, 2200n, 21, 21);
bindProposalToReview(duplicateAgents, duplicateRound.reviewRoundId);
expectFailure(() => call("createProposal", duplicateAgents.createArgs, {
  caller: addresses[0], block: 2200n, epoch: 21,
}));
call("expireReviewRound", [duplicateRound.reviewRoundId], { caller: addresses[7], block: 2241n, epoch: 21 });
withdrawExpiredRoundBonds(duplicateRound.reviewRoundId, duplicateAgents, 2242n, 21);

const selfClassifiedNormal = proposalFixtures(
  "self-classified-normal",
  addresses,
  first.candidateCid,
  cid("candidate-self-classified-normal"),
  false,
  2300,
  21,
);
const normalRound = openAndFreezeReview(selfClassifiedNormal, 2260n, 2300n, 21, 21);
selfClassifiedNormal.proposalValue.riskClass = "normal";
bindProposalToReview(selfClassifiedNormal, normalRound.reviewRoundId);
expectFailure(() => call("createProposal", selfClassifiedNormal.createArgs, {
  caller: addresses[0], block: 2300n, epoch: 21,
}));
call("expireReviewRound", [normalRound.reviewRoundId], { caller: addresses[7], block: 2341n, epoch: 21 });
withdrawExpiredRoundBonds(normalRound.reviewRoundId, selfClassifiedNormal, 2342n, 21);

const delayed = proposalFixtures(
  "delayed-finalization",
  addresses,
  first.candidateCid,
  cid("candidate-delayed-finalization"),
  false,
  2400,
  21,
);
const delayedCreate = prepareProposal(delayed, 2360n, 2400n, 21);
call("openVoting", [delayedCreate.proposalId], {
  caller: addresses[7], block: 2440n, epoch: 21,
});
for (const address of addresses) {
  call("castVote", [delayedCreate.proposalId, "yes"], {
    caller: address, block: 2441n, epoch: 21,
  });
}
state = JSON.parse(call("finalizeVoting", [delayedCreate.proposalId], {
  caller: addresses[7], block: 2580n, epoch: 21,
}));
assert.equal(state.state, "AcceptedPendingChallenge");
assert.equal(state.challengeEnd, 2640);
assert.equal(state.executeAfter, 2700);
expectFailure(() => call("advanceChallengePeriod", [delayedCreate.proposalId], {
  caller: addresses[7], block: 2620n, epoch: 21,
}));
state = JSON.parse(call("advanceChallengePeriod", [delayedCreate.proposalId], {
  caller: addresses[7], block: 2640n, epoch: 21,
}));
assert.equal(state.state, "AcceptedPendingExecution");
expectFailure(() => call("executeProposal", [delayedCreate.proposalId], {
  caller: addresses[6], block: 2699n, epoch: 21,
}));
state = JSON.parse(call("executeProposal", [delayedCreate.proposalId], {
  caller: addresses[6], block: 2700n, epoch: 21,
}));
assert.equal(state.state, "Executed");

const objectivelyNormal = proposalFixtures(
  "objective-normal", addresses, delayed.candidateCid, cid("objective-normal-candidate"),
  false, 2760, 21, false, null, "docs/operator-guide.md", "normal",
);
const objectivelyNormalCreate = prepareProposal(objectivelyNormal, 2720n, 2760n, 21);
const objectivelyNormalState = JSON.parse(call("proposalState", [objectivelyNormalCreate.proposalId], {
  caller: addresses[7], block: 2760n, epoch: 21,
}));
assert.equal(objectivelyNormalState.riskClass, "normal");
assert.equal(objectivelyNormalState.scopeEvidenceCid, objectivelyNormal.scope.cid);

const consensusScopeBranch = snapshotHarnessState();
for (const [prefix, path] of [
  ["governance-day-lock-scope", "compatibility/governance-day-fork-candidate-lock.json"],
  ["epoch-anchor-scope", "integrations/governance-epoch-anchor/idena-go.patch"],
]) {
  const fixture = proposalFixtures(
    prefix, addresses, delayed.candidateCid, cid(`${prefix}-candidate`),
    false, 2800, 21, false, null, path, "consensus",
  );
  const opened = JSON.parse(call("openReviewRound", fixture.openArgs, {
    caller: addresses[0], block: 2770n, epoch: 21, payment: 25n * 10n ** 18n,
  }));
  assert.equal(decoder.decode(storage.get(`review-scope-risk:${opened.reviewRoundId}`)), "consensus");
}
const underclassifiedForkScope = proposalFixtures(
  "underclassified-governance-day-lock", addresses, delayed.candidateCid,
  cid("underclassified-governance-day-lock-candidate"), false, 2800, 21,
  false, null, "compatibility/governance-day-fork-candidate-lock.json", "critical",
);
expectFailure(() => call("openReviewRound", underclassifiedForkScope.openArgs, {
  caller: addresses[0], block: 2771n, epoch: 21, payment: 25n * 10n ** 18n,
}));
restoreHarnessState(consensusScopeBranch);

const metricsMigrationBranch = snapshotHarnessState();
const migratedSourceHash = digest("migrated-metrics-source").toString("hex");
const migratedMetricLeaves = metricLeaves.map((leaf, index) => ({
  ...leaf,
  state: index === 0 ? "Newbie" : leaf.state,
  finalized: index === 0 ? 20n : leaf.finalized,
  reported: index === 0 ? 20n : leaf.reported,
  trust: index === 0 ? flipTrust(20n, 20n) : leaf.trust,
  sourceEpoch: 11,
  sourceHeight: 2000n,
  sourceHash: migratedSourceHash,
}));
const migratedMetricTree = metricsTree(migratedMetricLeaves);
const migratedSnapshotSeed = "migrated-metrics-snapshot";
const migratedMetricsDescriptor = {
  metricsRoot: migratedMetricTree.root,
  snapshotCid: cid(migratedSnapshotSeed),
  snapshotSha256: digest(migratedSnapshotSeed).toString("hex"),
  sourceEpoch: 11,
  sourceBlockHeight: 2000,
  sourceBlockHash: migratedSourceHash,
  replayStartHeight: 1,
  replayCommitment: digest("migrated-metrics-replay").toString("hex"),
  indexerImplementationCid: cid("migrated-metrics-indexer"),
  observedAtBlockOrTimestamp: 2772,
};
for (let index = 0; index < 3; index++) {
  const attestation = metricsAttestation(addresses[index], migratedMetricsDescriptor);
  call("submitIdentityMetricsAttestation", [attestation.cid, attestation.hex], {
    caller: addresses[index], block: 2772n, epoch: 23,
  });
}
const stakeBeforeMigration = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 2773n, epoch: 23,
}));
const activeBeforeMigration = BigInt(stakeBeforeMigration.active);
const pendingDeposit = 100n * 10n ** 18n;
call("registerGovernanceStake", [], {
  caller: addresses[0], block: 2773n, epoch: 23, payment: pendingDeposit,
});
const pendingBeforeMigration = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 2773n, epoch: 23,
})).pending.split("~");
assert.equal(pendingBeforeMigration.length, 4);
const scheduledBeforeMigration = decoder.decode(storage.get("governance:scheduled-weight-delta"));
assert.equal(pendingBeforeMigration[3], scheduledBeforeMigration);
const globalBeforeMigration = BigInt(decoder.decode(storage.get("governance:total-weight")));

const metricsMigration = proposalFixtures(
  "identity-metrics-migration", addresses, delayed.candidateCid,
  cid("identity-metrics-migration-candidate"), false, 2820, 23,
  false, null, "migrations/identity-metrics-v11.json", "migration",
);
metricsMigration.proposalValue.candidateIdentityMetricsRoot = migratedMetricTree.root;
metricsMigration.proposalValue.candidateIdentityMetricsEpoch = 11;
const metricsMigrationCreate = prepareProposal(metricsMigration, 2780n, 2820n, 23);
call("openVoting", [metricsMigrationCreate.proposalId], {
  caller: addresses[7], block: 2860n, epoch: 23,
});
for (const address of addresses) {
  call("castVote", [metricsMigrationCreate.proposalId, "yes"], {
    caller: address, block: 2861n, epoch: 23,
  });
}
state = JSON.parse(call("finalizeVoting", [metricsMigrationCreate.proposalId], {
  caller: addresses[7], block: 2980n, epoch: 23,
}));
assert.equal(state.state, "AcceptedPendingChallenge");
call("advanceChallengePeriod", [metricsMigrationCreate.proposalId], {
  caller: addresses[7], block: 3040n, epoch: 23,
});
state = JSON.parse(call("executeProposal", [metricsMigrationCreate.proposalId], {
  caller: addresses[7], block: 3100n, epoch: 23,
}));
assert.equal(state.state, "Executed");
assert.equal(decoder.decode(storage.get("governance:scheduled-weight-delta")), scheduledBeforeMigration);
assert.equal(BigInt(decoder.decode(storage.get("governance:total-weight"))), globalBeforeMigration);

const migratedLeaf = migratedMetricLeaves[0];
call("registerIdentityMetricsProof", [
  migratedLeaf.state,
  migratedLeaf.finalized.toString(),
  migratedLeaf.reported.toString(),
  migratedLeaf.trust.toString(),
  migratedLeaf.sourceEpoch.toString(),
  migratedLeaf.sourceHeight.toString(),
  migratedLeaf.sourceHash,
  "0",
  migratedMetricLeaves.length.toString(),
  migratedMetricTree.proofs[0].join(","),
], { caller: addresses[0], block: 3101n, epoch: 23 });
const oldActiveWeight = governanceWeight(
  activeBeforeMigration, metricLeaves[0].state, metricLeaves[0].trust,
);
const newActiveWeight = governanceWeight(
  activeBeforeMigration, migratedLeaf.state, migratedLeaf.trust,
);
const expectedRebasedDelta = governanceWeight(
  activeBeforeMigration + pendingDeposit, migratedLeaf.state, migratedLeaf.trust,
) - newActiveWeight;
assert.equal(
  BigInt(decoder.decode(storage.get("governance:total-weight"))),
  globalBeforeMigration - oldActiveWeight + newActiveWeight,
);
assert.equal(BigInt(decoder.decode(storage.get("governance:scheduled-weight-delta"))), expectedRebasedDelta);
const pendingAfterRefresh = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3101n, epoch: 23,
})).pending.split("~");
assert.equal(pendingAfterRefresh[2], migratedMetricTree.root);
assert.equal(BigInt(pendingAfterRefresh[3]), expectedRebasedDelta);

storage.set("epoch-governance:enabled", Buffer.from("1"));
call("anchorGovernanceEpoch", [], {
  caller: addresses[8], block: 3200n, epoch: 24, epochBlock: 3200n,
});
const migratedEpochWeight = BigInt(decoder.decode(storage.get("epoch-governance:weight:24")));
assert.equal(
  migratedEpochWeight,
  globalBeforeMigration - oldActiveWeight + newActiveWeight + expectedRebasedDelta,
);
const migratedVoter = JSON.parse(call("previewVotingPower", ["24"], {
  caller: addresses[0], block: 3200n, epoch: 24,
}));
assert.equal(
  BigInt(migratedVoter.effectiveVoteWeight),
  governanceWeight(activeBeforeMigration + pendingDeposit, migratedLeaf.state, migratedLeaf.trust),
);
assert.ok(BigInt(migratedVoter.effectiveVoteWeight) <= migratedEpochWeight);
call("activateGovernanceStake", [], { caller: addresses[0], block: 3200n, epoch: 24 });
assert.equal(JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3200n, epoch: 24,
})).pending, "");
restoreHarnessState(metricsMigrationBranch);

// Epoch-governance profile: one authenticated proposal slot, one frozen set,
// one batch commit/reveal ballot, grace, and append-only execution history.
const epochParent = JSON.parse(call("canonicalEcosystemCid", [], {
  caller: addresses[6], block: 2800n, epoch: 21,
})).canonicalEcosystemCid;

const expiredDraftFreezeBranch = snapshotHarnessState();
const expiredEpochDraft = proposalFixtures(
  "expired-epoch-draft", addresses, epochParent, cid("expired-epoch-draft-candidate"),
  false, 2901, 22,
);
const expiredEpochDraftOpened = JSON.parse(call("openReviewRound", expiredEpochDraft.openArgs, {
  caller: addresses[0], block: 2861n, epoch: 21, payment: 25n * 10n ** 18n,
}));
submitEvidenceAttestations(expiredEpochDraftOpened.reviewRoundId, expiredEpochDraft, 2862n, 21);
storage.set("epoch-governance:enabled", Buffer.from("1"));
call("anchorGovernanceEpoch", [], {
  caller: addresses[9], block: 2900n, epoch: 22, epochBlock: 2900n,
});
call("freezeReviewRound", [expiredEpochDraftOpened.reviewRoundId], {
  caller: addresses[8], block: 2901n, epoch: 22,
});
submitAvailabilityAttestations(expiredEpochDraftOpened.reviewRoundId, expiredEpochDraft, 2901n, 22);
const expiredEpochDraftRound = JSON.parse(call("freezeReviewRound", [expiredEpochDraftOpened.reviewRoundId], {
  caller: addresses[8], block: 2901n, epoch: 22,
}));
bindProposalToReview(expiredEpochDraft, expiredEpochDraftRound.reviewRoundId);
const expiredEpochDraftCreate = JSON.parse(call("createProposal", expiredEpochDraft.createArgs, {
  caller: addresses[0], block: 2901n, epoch: 22,
}));
state = JSON.parse(call("expireProposal", [expiredEpochDraftCreate.proposalId], {
  caller: addresses[7], block: 2942n, epoch: 22,
}));
assert.equal(state.state, "Expired");
const emptyFrozenSet = JSON.parse(call("freezeEpochProposalSet", [], {
  caller: addresses[8], block: 2942n, epoch: 22,
}));
assert.equal(emptyFrozenSet.proposals.length, 0);
assert.equal(JSON.parse(call("finalizeEpochVotingForEpoch", ["22"], {
  caller: addresses[8], block: 3021n, epoch: 23,
})).proposals.length, 0);
const reservationsBeforeExpiredDraftRefund = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3021n, epoch: 23,
})).slashReservations;
call("withdrawRefundableBond", [expiredEpochDraftCreate.proposalId], {
  caller: addresses[0], block: 3021n, epoch: 23,
});
assert.equal(JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3021n, epoch: 23,
})).slashReservations, reservationsBeforeExpiredDraftRefund - 1);
withdrawProposalAttestationBonds(expiredEpochDraftCreate.proposalId, expiredEpochDraft, 3021n, 23);
restoreHarnessState(expiredDraftFreezeBranch);

const epochFirst = proposalFixtures(
  "epoch-first", addresses, epochParent, cid("epoch-first-candidate"), false, 2939, 22,
);
const epochSecond = proposalFixtures(
  "epoch-second", addresses, epochParent, cid("epoch-second-candidate"), false, 2939, 22,
);
const epochFirstOpened = JSON.parse(call("openReviewRound", epochFirst.openArgs, {
  caller: addresses[0], block: 2899n, epoch: 21, payment: 25n * 10n ** 18n,
}));
const epochSecondOpened = JSON.parse(call("openReviewRound", epochSecond.openArgs, {
  caller: addresses[0], block: 2899n, epoch: 21, payment: 25n * 10n ** 18n,
}));

storage.set("epoch-governance:enabled", Buffer.from("1"));
const schedule = JSON.parse(call("anchorGovernanceEpoch", [], {
  caller: addresses[9], block: 2900n, epoch: 22, epochBlock: 2900n,
}));
assert.equal(schedule.proposalCutoffBlock, 2940);
expectFailure(() => call("anchorGovernanceEpoch", [], {
  caller: addresses[8], block: 2901n, epoch: 22, epochBlock: 2899n,
}));
const liveMetricsRoot = storage.get("governance:metrics-root");
const liveMetricsEpoch = storage.get("governance:metrics-epoch");
storage.set("governance:metrics-root", Buffer.from("aa".repeat(32)));
storage.set("governance:metrics-epoch", Buffer.from("99"));
assert.doesNotThrow(() => call("previewVotingPower", ["22"], {
  caller: addresses[0], block: 2900n, epoch: 22,
}));
storage.set("governance:metrics-root", liveMetricsRoot);
storage.set("governance:metrics-epoch", liveMetricsEpoch);
const anchoredPendingUnbondBranch = snapshotHarnessState();
const anchoredPendingUnbondAddress = addresses[12];
const anchoredPendingUnbondState = JSON.parse(call("governanceStakeState", [], {
  caller: anchoredPendingUnbondAddress, block: 2900n, epoch: 22, epochBlock: 2900n,
}));
assert.equal(anchoredPendingUnbondState.slashReservations, 0);
call("scheduleWithdrawal", [anchoredPendingUnbondState.active], {
  caller: anchoredPendingUnbondAddress, block: 2901n, epoch: 22, epochBlock: 2900n,
});
const anchoredPendingDeposit = 1n * 10n ** 18n;
call("registerGovernanceStake", [], {
  caller: anchoredPendingUnbondAddress,
  block: 4000n,
  epoch: 27,
  epochBlock: 4000n,
  payment: anchoredPendingDeposit,
});
call("finalizeUnbonding", [], {
  caller: anchoredPendingUnbondAddress, block: 4001n, epoch: 27, epochBlock: 4000n,
});
const anchoredPendingUnbondAfter = JSON.parse(call("governanceStakeState", [], {
  caller: anchoredPendingUnbondAddress, block: 4001n, epoch: 27, epochBlock: 4000n,
}));
assert.equal(anchoredPendingUnbondAfter.active, "0");
assert.equal(
  anchoredPendingUnbondAfter.pending.split("~")[3],
  governanceWeight(
    anchoredPendingDeposit, metricLeaves[12].state, metricLeaves[12].trust,
  ).toString(),
);
restoreHarnessState(anchoredPendingUnbondBranch);
const expectedEpochWeight = addresses.reduce((total, address) => {
  const snapshot = JSON.parse(call("previewVotingPower", ["22"], {
    caller: address, block: 2900n, epoch: 22,
  }));
  return total + BigInt(snapshot.effectiveVoteWeight);
}, 0n);
submitEvidenceAttestations(epochFirstOpened.reviewRoundId, epochFirst, 2900n, 22);
submitEvidenceAttestations(epochSecondOpened.reviewRoundId, epochSecond, 2900n, 22);
call("freezeReviewRound", [epochFirstOpened.reviewRoundId], {
  caller: addresses[9], block: 2939n, epoch: 22,
});
call("freezeReviewRound", [epochSecondOpened.reviewRoundId], {
  caller: addresses[9], block: 2939n, epoch: 22,
});
submitAvailabilityAttestations(epochFirstOpened.reviewRoundId, epochFirst, 2939n, 22);
submitAvailabilityAttestations(epochSecondOpened.reviewRoundId, epochSecond, 2939n, 22);
const epochFirstRound = JSON.parse(call("freezeReviewRound", [epochFirstOpened.reviewRoundId], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
const epochSecondRound = JSON.parse(call("freezeReviewRound", [epochSecondOpened.reviewRoundId], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
bindProposalToReview(epochFirst, epochFirstRound.reviewRoundId);
bindProposalToReview(epochSecond, epochSecondRound.reviewRoundId);

const priorEpochRecoveryBranch = snapshotHarnessState();
const priorEpochRecoveryCreate = JSON.parse(call("createProposal", epochFirst.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
call("submitProposalMetadataRoot", [priorEpochRecoveryCreate.proposalId, priorEpochRecoveryCreate.metadataRoot], {
  caller: addresses[7], block: 2939n, epoch: 22,
});
const recoveredEpoch = JSON.parse(call("finalizeEpochVotingForEpoch", ["22"], {
  caller: addresses[8], block: 3100n, epoch: 23,
}));
assert.equal(recoveredEpoch.proposals.length, 0);
assert.equal(JSON.parse(call("proposalState", [priorEpochRecoveryCreate.proposalId], {
  caller: addresses[8], block: 3100n, epoch: 23,
})).state, "Expired");
const reservationsBeforeRecoveryRefund = JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3100n, epoch: 23,
})).slashReservations;
call("withdrawRefundableBond", [priorEpochRecoveryCreate.proposalId], {
  caller: addresses[0], block: 3100n, epoch: 23,
});
assert.equal(JSON.parse(call("governanceStakeState", [], {
  caller: addresses[0], block: 3100n, epoch: 23,
})).slashReservations, reservationsBeforeRecoveryRefund - 1);
withdrawProposalAttestationBonds(priorEpochRecoveryCreate.proposalId, epochFirst, 3100n, 23);
restoreHarnessState(priorEpochRecoveryBranch);

const priorEpochFinalizationBranch = snapshotHarnessState();
const priorEpochFinalizationCreate = JSON.parse(call("createProposal", epochFirst.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
call("submitProposalMetadataRoot", [priorEpochFinalizationCreate.proposalId, priorEpochFinalizationCreate.metadataRoot], {
  caller: addresses[7], block: 2939n, epoch: 22,
});
call("freezeEpochProposalSet", [], {
  caller: addresses[8], block: 2940n, epoch: 22,
});
const priorEpochFinalized = JSON.parse(call("finalizeEpochVotingForEpoch", ["22"], {
  caller: addresses[8], block: 3100n, epoch: 23,
}));
assert.equal(priorEpochFinalized.proposals[0].state, "NoQuorum");
call("claimNoQuorumRefund", [priorEpochFinalizationCreate.proposalId], {
  caller: addresses[0], block: 3100n, epoch: 23,
});
withdrawProposalAttestationBonds(priorEpochFinalizationCreate.proposalId, epochFirst, 3100n, 23);
restoreHarnessState(priorEpochFinalizationBranch);

const wrongParameterProposal = dagObject({
  ...epochFirst.proposalValue,
  governanceParameterSetCid: cid("wrong-governance-parameters"),
  reviewRoundId: epochFirstRound.reviewRoundId,
});
expectFailure(() => call("createProposal", [wrongParameterProposal.cid, wrongParameterProposal.hex], {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
const slotAfterWrongParameters = JSON.parse(call("getProposalSlot", ["22", `0x${addresses[0].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(slotAfterWrongParameters.used, false);
const oversizedProposal = dagObject({
  ...epochFirst.proposalValue,
  changedFileCount: 1025,
  reviewRoundId: epochFirstRound.reviewRoundId,
});
expectFailure(() => call("createProposal", [oversizedProposal.cid, oversizedProposal.hex], {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
const slotAfterOversizedProposal = JSON.parse(call("getProposalSlot", ["22", `0x${addresses[0].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(slotAfterOversizedProposal.used, false);
const cancellationBranch = snapshotHarnessState();
const cancelledEpochProposal = JSON.parse(call("createProposal", epochFirst.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
const cancelledState = JSON.parse(call("cancelProposalBeforeCutoff", [cancelledEpochProposal.proposalId], {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
assert.equal(cancelledState.state, "CancelledBeforeCutoff");
const cancelledSlot = JSON.parse(call("getProposalSlot", ["22", `0x${addresses[0].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(cancelledSlot.used, true);
assert.equal(cancelledSlot.proposalId, cancelledEpochProposal.proposalId);
const reopenedCancelledCandidate = JSON.parse(call("openReviewRound", epochFirst.openArgs, {
  caller: addresses[1], block: 2939n, epoch: 22, payment: 25n * 10n ** 18n,
}));
assert.notEqual(reopenedCancelledCandidate.reviewRoundId, epochFirstOpened.reviewRoundId);
expectFailure(() => call("createProposal", epochSecond.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
restoreHarnessState(cancellationBranch);
const epochCreated = JSON.parse(call("createProposal", epochFirst.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
const epochCreatedState = JSON.parse(call("proposalState", [epochCreated.proposalId], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(epochCreatedState.pos.snapshot, expectedEpochWeight.toString());
call("submitProposalMetadataRoot", [epochCreated.proposalId, epochCreated.metadataRoot], {
  caller: addresses[7], block: 2939n, epoch: 22,
});
call("attachRecoveryManifest", [
  epochCreated.proposalId,
  epochFirst.proposalValue.rollbackManifestCid,
  epochFirst.proposalValue.rollbackInstructionsCid,
], { caller: addresses[0], block: 2939n, epoch: 22 });
expectFailure(() => call("createProposal", epochSecond.createArgs, {
  caller: addresses[0], block: 2939n, epoch: 22,
}));
const slot = JSON.parse(call("getProposalSlot", ["22", `0x${addresses[0].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(slot.proposalId, epochCreated.proposalId);
const independentSlot = JSON.parse(call("getProposalSlot", ["22", `0x${addresses[1].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(independentSlot.used, false);
const nextEpochSlot = JSON.parse(call("getProposalSlot", ["23", `0x${addresses[0].toString("hex")}`], {
  caller: addresses[9], block: 2939n, epoch: 22,
}));
assert.equal(nextEpochSlot.used, false);

const epochSet = JSON.parse(call("freezeEpochProposalSet", [], {
  caller: addresses[9], block: 2940n, epoch: 22,
}));
assert.equal(epochSet.proposals.length, 1);
assert.equal(epochSet.proposals[0].proposalId, epochCreated.proposalId);
expectFailure(() => call("openVoting", [epochCreated.proposalId], {
  caller: addresses[9], block: 2941n, epoch: 22,
}));

const epochChoices = `${epochCreated.proposalId}:yes`;
const epochVoters = addresses.slice(0, 12);
const epochSecrets = epochVoters.map((voter, index) => ({
  nonce: BigInt(index + 1),
  salt: digest(`epoch-salt-${index}`).toString("hex"),
  commitment: epochBallotCommitment({
    epoch: 22,
    voter,
    frozenRoot: epochSet.frozenRoot,
    choices: ["yes"],
    nonce: BigInt(index + 1),
    salt: digest(`epoch-salt-${index}`),
  }),
}));
epochVoters.forEach((voter, index) => call("commitEpochBallot", [epochSecrets[index].commitment], {
  caller: voter, block: 2980n, epoch: 22,
}));
expectFailure(() => call("revealEpochBallot", [epochChoices, epochSecrets[0].nonce, digest("wrong-salt").toString("hex")], {
  caller: epochVoters[0], block: 3000n, epoch: 22,
}));
epochVoters.forEach((voter, index) => call("revealEpochBallot", [
  epochChoices, epochSecrets[index].nonce, epochSecrets[index].salt,
], { caller: voter, block: 3000n, epoch: 22 }));
const staleAvailabilityBranch = snapshotHarnessState();
const staleAvailabilityResult = JSON.parse(call("finalizeEpochVoting", [], {
  caller: addresses[9], block: 3160n, epoch: 22,
}));
assert.equal(staleAvailabilityResult.proposals[0].state, "Expired");
restoreHarnessState(staleAvailabilityBranch);
const epochFinalized = JSON.parse(call("finalizeEpochVoting", [], {
  caller: addresses[9], block: 3020n, epoch: 22,
}));
assert.equal(epochFinalized.proposals[0].state, "AcceptedPendingGrace");
const epochDecision = JSON.parse(call("getEpochDecisionRecord", [epochCreated.proposalId], {
  caller: addresses[9], block: 3020n, epoch: 22,
}));
assert.equal(epochDecision.record.state, "AcceptedPendingGrace");
assert.equal(epochDecision.record.proposalSetRoot, epochSet.frozenRoot);
assert.equal(epochDecision.decisionRecordCid, rawObject(JSON.stringify(epochDecision.record)).cid);

const preservedExecutionDeadlineBranch = snapshotHarnessState();
call("enterExecutionReadyState", [epochCreated.proposalId], {
  caller: addresses[8], block: 3300n, epoch: 22,
});
assert.equal(JSON.parse(call("proposalState", [epochCreated.proposalId], {
  caller: addresses[8], block: 3300n, epoch: 22,
})).executeAfter, 3200);
expectFailure(() => call("executeProposal", [epochCreated.proposalId], {
  caller: addresses[8], block: 3801n, epoch: 22,
}));
assert.equal(JSON.parse(call("expireProposal", [epochCreated.proposalId], {
  caller: addresses[8], block: 3801n, epoch: 22,
})).state, "Expired");
restoreHarnessState(preservedExecutionDeadlineBranch);

const expiredGraceBranch = snapshotHarnessState();
expectFailure(() => call("enterExecutionReadyState", [epochCreated.proposalId], {
  caller: addresses[8], block: 3801n, epoch: 22,
}));
assert.equal(JSON.parse(call("expireProposal", [epochCreated.proposalId], {
  caller: addresses[8], block: 3801n, epoch: 22,
})).state, "Expired");
restoreHarnessState(expiredGraceBranch);

expectFailure(() => call("enterExecutionReadyState", [epochCreated.proposalId], {
  caller: addresses[9], block: 3199n, epoch: 22,
}));
call("enterExecutionReadyState", [epochCreated.proposalId], {
  caller: addresses[9], block: 3200n, epoch: 22,
});
expectFailure(() => call("executeRevert", [epochCreated.proposalId], {
  caller: addresses[9], block: 3200n, epoch: 22,
}));
state = JSON.parse(call("executeProposal", [epochCreated.proposalId], {
  caller: addresses[9], block: 3200n, epoch: 22,
}));
assert.equal(state.state, "Executed");
const history = JSON.parse(call("getCanonicalHistory", [], {
  caller: addresses[9], block: 3200n, epoch: 22,
}));
assert.equal(history.totalCount, 1);
assert.equal(history.start, 0);
assert.equal(history.nextStart, null);
assert.equal(history.entries.length, 1);
assert.equal(history.entries[0].previousCid, epochParent);
assert.equal(history.entries[0].newCid, epochFirst.candidateCid);
assert.equal(history.entries[0].decisionRecordCid, epochDecision.decisionRecordCid);
const historyPage = JSON.parse(call("getCanonicalHistoryPage", ["0", "1"], {
  caller: addresses[9], block: 3200n, epoch: 22,
}));
assert.deepEqual(historyPage, history);
expectFailure(() => call("getCanonicalHistoryPage", ["0", "65"], {
  caller: addresses[9], block: 3200n, epoch: 22,
}));
expectFailure(() => call("claimNoQuorumRefund", [epochCreated.proposalId], {
  caller: addresses[0], block: 3200n, epoch: 22,
}));
const transferCountBeforeAcceptedClaim = transfers.length;
const acceptedClaim = JSON.parse(call("claimAcceptedProposalBond", [epochCreated.proposalId], {
  caller: addresses[0], block: 3200n, epoch: 22,
}));
assert.equal(acceptedClaim.amount, (25n * 10n ** 18n).toString());
assert.equal(transfers.length, transferCountBeforeAcceptedClaim + 1);
expectFailure(() => call("claimAcceptedProposalBond", [epochCreated.proposalId], {
  caller: addresses[0], block: 3200n, epoch: 22,
}));
const unbonding = JSON.parse(call("beginUnbonding", [(10n ** 18n).toString()], {
  caller: addresses[12], block: 3201n, epoch: 22,
}));
assert.equal(unbonding.readyEpoch, "27");

assert(events.some((event) => event.name === "CanonicalEcosystemUpdatedV1"));
console.log(`Contract emulator passed: ${events.length} events, ${transfers.length} transfers, ${burns.length} burns`);

function proposalFixtures(
  prefix,
  owners,
  parentCid,
  _candidateSeedCid,
  includeHiddenConflict,
  creationBlock,
  creationEpoch,
  duplicateAgentInstance = false,
  falseClaimKind = null,
  scopePath = "crates/p2pool-node/src/lib.rs",
  scopeRisk = "critical",
  includeSecondaryCandidateArtifact = false,
) {
  const parentManifest = ecosystemManifests.get(parentCid);
  assert.ok(parentManifest, `missing parent manifest fixture for ${parentCid}`);
  const changedSourceFile = sourceFileFixture(scopePath, `${prefix}-source-content`);
  const candidateSource = sourceManifestFixture("P2poolBTC", [
    ...parentManifest.source.entries.filter((entry) => entry.path !== scopePath),
    changedSourceFile,
  ]);
  const sourceCid = candidateSource.cid;
  const expectedArtifactDigest = digest(`${prefix}-artifact`).toString("hex");
  const candidateArtifacts = [{
    name: "core",
    cid: rawCid(`${prefix}-artifact`),
    sha256: expectedArtifactDigest,
    size: 1,
  }];
  if (includeHiddenConflict) {
    candidateArtifacts.push({
      name: "core-conflict",
      cid: rawCid(`${prefix}-conflict`),
      sha256: digest(`${prefix}-conflict`).toString("hex"),
      size: 1,
    });
  }
  if (includeSecondaryCandidateArtifact) {
    candidateArtifacts.push({
      name: "secondary",
      cid: rawCid(`${prefix}-secondary-artifact`),
      sha256: digest(`${prefix}-secondary-artifact`).toString("hex"),
      size: 1,
    });
  }
  const candidateManifest = ecosystemManifestFixture(prefix, parentCid, candidateSource, candidateArtifacts);
  const candidateCid = candidateManifest.cid;
  const repositoryPatch = dagObject({
    schemaVersion: 1,
    kind: "pohw-source-patch-v1",
    repository: "P2poolBTC",
    baseSourceCid: link(parentManifest.sourceCid),
    candidateSourceCid: link(sourceCid),
    removedPaths: [],
    upsertedFiles: [{ ...changedSourceFile, cid: link(changedSourceFile.cid) }],
  });
  const patch = dagObject({
    schemaVersion: 1,
    kind: "pohw-ecosystem-patch-v1",
    parentEcosystemCid: link(parentCid),
    candidateEcosystemCid: link(candidateCid),
    repositoryPatches: [{
      repository: "P2poolBTC",
      baseSourceCid: link(parentManifest.sourceCid),
      candidateSourceCid: link(sourceCid),
      patchCid: link(repositoryPatch.cid),
      patchSha256: digest(Buffer.from(repositoryPatch.hex, "hex")).toString("hex"),
    }],
  });
  const patchCid = patch.cid;
  const toolchain = dagObject({
    schemaVersion: 1,
    ecosystemLocks: { "/node": "24.18.0", "rust:compiler": "1.97.0" },
    repositoryLocks: [{
      repository: "P2poolBTC",
      toolchainLocks: { cargo: "1.97.0" },
    }],
  });
  const rationaleCid = cid(`${prefix}-rationale`);
  const migrationNotesCid = cid(`${prefix}-migration-notes`);
  const testPlanCid = cid(`${prefix}-test-plan`);
  const rollbackManifestCid = cid(`${prefix}-rollback-manifest`);
  const rollbackInstructionsCid = cid(`${prefix}-rollback-instructions`);
  const scope = dagObject({
    schemaVersion: 1,
    classifierVersion: "pohw-objective-risk-classifier-v2",
    parentEcosystemCid: parentCid,
    candidateEcosystemCid: candidateCid,
    patchCid,
    repositories: [{
      repository: "P2poolBTC",
      baseSourceCid: parentManifest.sourceCid,
      candidateSourceCid: sourceCid,
      patchCid: repositoryPatch.cid,
      patchSha256: digest(Buffer.from(repositoryPatch.hex, "hex")).toString("hex"),
      baseManifestDagCborHex: parentManifest.source.hex,
      candidateManifestDagCborHex: candidateSource.hex,
      patchDagCborHex: repositoryPatch.hex,
      patchContentBytes: changedSourceFile.size,
      candidateContentBytes: candidateSource.entries.reduce((total, entry) => total + entry.size, 0),
      changes: [{ path: scopePath, changeKind: "upsert", size: changedSourceFile.size }],
    }],
    rationaleBytes: 128,
    migrationNotesBytes: 128,
    testPlanBytes: 256,
    changedFileCount: 1,
    patchBytes: changedSourceFile.size,
    sourcePackageBytes: candidateSource.entries.reduce((total, entry) => total + entry.size, 0),
    descriptionBytes: 512,
    migrationOperationCount: scopePath.startsWith("migrations/") || scopePath.includes("/migrations/")
      || scopePath.startsWith("migration/") || scopePath.includes("/migration/") ? 1 : 0,
    derivedRiskClass: scopeRisk,
  });
  const pinsetCids = [
    candidateCid,
    patchCid,
    repositoryPatch.cid,
    sourceCid,
    parameterCid,
    rationaleCid,
    migrationNotesCid,
    testPlanCid,
    rollbackManifestCid,
    rollbackInstructionsCid,
    scope.cid,
    ...candidateArtifacts.map((artifact) => artifact.cid),
  ].sort();
  const pinset = dagObject({
    schemaVersion: 1,
    ecosystemCid: link(candidateCid),
    cids: pinsetCids.map(link),
  });
  const attestationBlock = creationBlock - 39;
  const agents = Array.from({ length: 5 }, (_, index) => ({
    model: `model-family-${index}`,
    owner: owners[index % 3],
    unresolved: 0,
  }));
  if (duplicateAgentInstance) {
    agents[3].model = agents[0].model;
    agents[3].owner = agents[0].owner;
  }
  for (let index = 0; index < agents.length; index++) {
    agents[index].testResult = index === 0 && falseClaimKind === "agent_test_result"
      ? rawObject('{"passed":false}')
      : { cid: rawCid(`${prefix}-agent-tests-${index}`), hex: "" };
    Object.assign(agents[index], dagObject({
      schemaVersion: 1,
      parentEcosystemCid: parentCid,
      candidateEcosystemCid: candidateCid,
      patchCid,
      affectedRepositories: [{ repository: "P2poolBTC", cid: sourceCid }],
      modelIdentifier: `${prefix}-review-${index}`,
      modelRevision: null,
      providerOrRuntimeIdentifier: `${prefix}-runtime-${index}`,
      modelFamily: agents[index].model,
      agentPolicyCid: cid(`${prefix}-agent-policy`),
      systemPromptPolicyCid: cid(`${prefix}-prompt-policy`),
      toolVersions: { cargo: "1.97.0" },
      commandsExecuted: [{ command: "cargo test --workspace", exitCode: 0, stdoutSha256: digest("stdout").toString("hex"), stderrSha256: digest("stderr").toString("hex") }],
      testResultsCid: agents[index].testResult.cid,
      testsPassed: true,
      staticAnalysisResultsCid: cid(`${prefix}-static-${index}`),
      dependencyFindingsCid: cid(`${prefix}-dependencies-${index}`),
      securityFindings: [],
      unresolvedCriticalFindings: agents[index].unresolved,
      verdict: "approve",
      ownerIdenaAddress: `0x${agents[index].owner.toString("hex")}`,
      reviewerBondAtoms: (10n ** 18n).toString(),
      creationBlockOrTimestamp: attestationBlock,
      authentication: "on-chain-submitter",
    }));
  }
  const builds = [
    { artifactDigest: expectedArtifactDigest, artifactCid: rawCid(`${prefix}-artifact`), runtime: "linux", architecture: "x86_64", platform: "linux-x86_64", owner: owners[0] },
    { artifactDigest: expectedArtifactDigest, artifactCid: rawCid(`${prefix}-artifact`), runtime: "macos", architecture: "arm64", platform: "macos-arm64", owner: owners[1] },
    { artifactDigest: expectedArtifactDigest, artifactCid: rawCid(`${prefix}-artifact`), runtime: "linux", architecture: "x86_64", platform: "linux-x86_64", owner: owners[2] },
  ];
  if (includeHiddenConflict) {
    builds.push({ artifactDigest: digest(`${prefix}-conflict`).toString("hex"), artifactCid: rawCid(`${prefix}-conflict`), artifactName: "core-conflict", runtime: "linux", architecture: "arm64", platform: "linux-arm64", owner: owners[3] });
  }
  for (let index = 0; index < builds.length; index++) {
    builds[index].testResult = index === 0 && falseClaimKind === "builder_test_result"
      ? rawObject('{"passed":false}')
      : { cid: rawCid(`${prefix}-build-tests-${index}`), hex: "" };
    const selectedCoreArtifact = builds[index].artifactName ?? "core";
    const buildArtifacts = candidateArtifacts
      .filter((artifact) => !includeSecondaryCandidateArtifact || artifact.name !== "secondary")
      .map((artifact) => ({
        ...artifact,
        core: artifact.name === selectedCoreArtifact,
      }));
    builds[index].digest = coreArtifactSetDigest(buildArtifacts);
    Object.assign(builds[index], dagObject({
      schemaVersion: 1,
      candidateEcosystemCid: candidateCid,
      sourceCids: [{ repository: "P2poolBTC", cid: sourceCid }],
      toolchainCid: toolchain.cid,
      scopeEvidenceCid: scope.cid,
      builderIdentity: `0x${builds[index].owner.toString("hex")}`,
      runtimeFamily: builds[index].runtime,
      architecture: builds[index].architecture,
      commands: [{ command: "cargo build --workspace --locked", exitCode: 0, stdoutSha256: digest("stdout").toString("hex"), stderrSha256: digest("stderr").toString("hex") }],
      testResultsCid: builds[index].testResult.cid,
      testsPassed: true,
      sbomCid: rawCid(`${prefix}-sbom-${index}`),
      artifacts: buildArtifacts,
      coreArtifactDigest: builds[index].digest,
      builderBondAtoms: (10n ** 18n).toString(),
      creationBlockOrTimestamp: attestationBlock,
      authentication: "on-chain-submitter",
    }));
  }
  const requiredAvailabilityCids = new Set(pinsetCids);
  for (const agent of agents) {
    for (const requiredCid of [
      agent.cid,
      agent.value.agentPolicyCid,
      agent.value.systemPromptPolicyCid,
      agent.value.testResultsCid,
      agent.value.staticAnalysisResultsCid,
      agent.value.dependencyFindingsCid,
      ...agent.value.securityFindings.flatMap((finding) => finding.evidenceCid ? [finding.evidenceCid] : []),
    ]) requiredAvailabilityCids.add(requiredCid);
  }
  for (const build of builds) {
    for (const requiredCid of [
      build.cid,
      build.value.toolchainCid,
      build.value.testResultsCid,
      build.value.sbomCid,
      ...build.value.artifacts.map((artifact) => artifact.cid),
    ]) requiredAvailabilityCids.add(requiredCid);
  }
  const availability = [
    { owner: owners[1] },
    { owner: owners[2] },
    { owner: owners[3] },
  ];
  for (let index = 0; index < availability.length; index++) {
    availability[index].testResult = index === 0 && falseClaimKind === "availability_probe"
      ? rawObject('{"available":false}')
      : { cid: rawCid(`${prefix}-probe-${index}`), hex: "" };
    const verifiedCids = [...requiredAvailabilityCids, availability[index].testResult.cid].sort();
    Object.assign(availability[index], dagObject({
      schemaVersion: 1,
      candidateEcosystemCid: candidateCid,
      pinsetCid: pinset.cid,
      providerId: `${prefix}-provider-${index}`,
      operatorIdentity: `0x${availability[index].owner.toString("hex")}`,
      verifiedCids,
      probeResultCid: availability[index].testResult.cid,
      available: true,
      observedAtBlockOrTimestamp: attestationBlock,
      expiresAtBlock: creationBlock + 1000,
      bondAtoms: (10n ** 18n).toString(),
      authentication: "on-chain-submitter",
    }));
  }
  const agentFields = agents.map((item) => `${item.cid}|${item.model}|${item.owner.toString("hex")}|${item.unresolved}`);
  const buildFields = builds.map((item) => `${item.cid}|${item.digest}|${item.platform}|${item.owner.toString("hex")}`);
  const availabilityFields = availability.map((item, index) => (
    `${item.cid}|${candidateCid}|${pinset.cid}|${prefix}-provider-${index}|${item.owner.toString("hex")}`
  ));
  const agentTree = attestationTree("agent_review_v1", agentFields);
  const buildTree = attestationTree("build_attestation_v1", buildFields);
  const availabilityTree = attestationTree("data_availability_v1", availabilityFields);
  const proposalValue = {
    schemaVersion: 2,
    scopeEvidenceCid: scope.cid,
    governanceParameterSetCid: parameterCid,
    parentCanonicalEcosystemCid: parentCid,
    candidateEcosystemCid: candidateCid,
    affectedRepositories: ["P2poolBTC"],
    changedFileCount: scope.value.changedFileCount,
    patchBytes: scope.value.patchBytes,
    sourcePackageBytes: scope.value.sourcePackageBytes,
    descriptionBytes: scope.value.descriptionBytes,
    migrationOperationCount: scope.value.migrationOperationCount,
    baseSourceCids: { P2poolBTC: parentManifest.sourceCid },
    candidateSourceCids: { P2poolBTC: sourceCid },
    patchCid,
    proposerAddress: `0x${owners[0].toString("hex")}`,
    proposalBondAtoms: (25n * 10n ** 18n).toString(),
    riskClass: scopeRisk,
    rationaleCid,
    migrationNotesCid,
    testPlanCid,
    rollbackManifestCid,
    rollbackInstructionsCid,
    releaseManifestCid: null,
    criticalFindingWaiverCid: null,
    agentReviewRoot: agentTree.root,
    buildAttestationRoot: buildTree.root,
    dataAvailabilityRoot: availabilityTree.root,
    creationBlock,
    creationEpoch,
    stakingEpoch: creationEpoch,
    identityMetricsEpoch: 10,
    candidateIdentityMetricsRoot: null,
    candidateIdentityMetricsEpoch: null,
    votingStart: creationBlock + 40,
    votingEnd: creationBlock + 160,
    challengeEnd: creationBlock + 220,
  };
  return {
    parentCid,
    candidateCid,
    patchCid,
    parentManifest,
    candidateManifest,
    patch,
    scope,
    pinset,
    pinsetCids,
    toolchain,
    openArgs: [
      parentCid, parentManifest.hex,
      candidateCid, candidateManifest.hex,
      patchCid, patch.hex,
      pinset.cid, pinset.hex,
      scope.cid, scope.hex,
    ],
    proposalValue,
    agents,
    builds,
    availability,
    agentTree,
    buildTree,
    availabilityTree,
    proposal: null,
    createArgs: null,
  };
}

function openAndFreezeReview(fixtures, openBlock, freezeBlock, openEpoch, freezeEpoch) {
  const opened = JSON.parse(call("openReviewRound", fixtures.openArgs, {
    caller: addresses[0], block: openBlock, epoch: openEpoch, payment: 25n * 10n ** 18n,
  }));
  submitEvidenceAttestations(opened.reviewRoundId, fixtures, openBlock + 1n, openEpoch);
  const evidenceFrozen = JSON.parse(call("freezeReviewRound", [opened.reviewRoundId], {
    caller: addresses[7], block: freezeBlock, epoch: freezeEpoch,
  }));
  assert.equal(evidenceFrozen.state, "AvailabilityOpen");
  submitAvailabilityAttestations(opened.reviewRoundId, fixtures, freezeBlock, freezeEpoch);
  const frozen = JSON.parse(call("freezeReviewRound", [opened.reviewRoundId], {
    caller: addresses[7], block: freezeBlock, epoch: freezeEpoch,
  }));
  assert.equal(frozen.schemaVersion, 1);
  assert.equal(frozen.agentReviewRoot, fixtures.agentTree.root);
  assert.equal(frozen.buildAttestationRoot, fixtures.buildTree.root);
  assert.equal(frozen.dataAvailabilityRoot, fixtures.availabilityTree.root);
  return frozen;
}

function bindProposalToReview(fixtures, reviewRoundId) {
  fixtures.proposal = dagObject({ ...fixtures.proposalValue, reviewRoundId });
  fixtures.createArgs = [fixtures.proposal.cid, fixtures.proposal.hex];
}

function prepareProposal(fixtures, openBlock, creationBlock, creationEpoch) {
  const frozen = openAndFreezeReview(fixtures, openBlock, creationBlock, creationEpoch, creationEpoch);
  bindProposalToReview(fixtures, frozen.reviewRoundId);
  const created = JSON.parse(call("createProposal", fixtures.createArgs, {
    caller: addresses[0], block: creationBlock, epoch: creationEpoch,
  }));
  call("submitProposalMetadataRoot", [created.proposalId, created.metadataRoot], {
    caller: addresses[7], block: creationBlock, epoch: creationEpoch,
  });
  return created;
}

function withdrawExpiredRoundBonds(reviewRoundId, fixtures, atBlock, atEpoch) {
  call("withdrawExpiredReviewBond", [reviewRoundId], {
    caller: addresses[0], block: atBlock, epoch: atEpoch,
  });
  for (const [kind, entries] of [
    ["agent", fixtures.agents],
    ["build", fixtures.builds],
    ["availability", fixtures.availability],
  ]) {
    for (const item of entries) {
      call("withdrawExpiredReviewAttestationBond", [reviewRoundId, kind, item.cid], {
        caller: item.owner, block: atBlock, epoch: atEpoch,
      });
    }
  }
}

function withdrawProposalAttestationBonds(proposalId, fixtures, atBlock, atEpoch) {
  for (const [kind, entries] of [
    ["agent", fixtures.agents],
    ["build", fixtures.builds],
    ["availability", fixtures.availability],
  ]) {
    for (const item of entries) {
      call("withdrawAttestationBond", [proposalId, kind, item.cid], {
        caller: item.owner, block: atBlock, epoch: atEpoch,
      });
    }
  }
}

function exerciseFalseClaimChallenge(prefix, kind, creationBlock) {
  const fixtures = proposalFixtures(
    prefix,
    addresses,
    first.candidateCid,
    cid(`${prefix}-candidate`),
    false,
    creationBlock,
    21,
    false,
    kind,
  );
  const created = prepareProposal(fixtures, BigInt(creationBlock - 40), BigInt(creationBlock), 21);
  call("openVoting", [created.proposalId], {
    caller: addresses[7], block: BigInt(creationBlock + 40), epoch: 21,
  });
  for (let index = 0; index < addresses.length; index++) {
    call("castVote", [created.proposalId, "yes"], {
      caller: addresses[index], block: BigInt(creationBlock + 41), epoch: 21,
    });
  }
  let challengedState = JSON.parse(call("finalizeVoting", [created.proposalId], {
    caller: addresses[7], block: BigInt(creationBlock + 160), epoch: 21,
  }));
  assert.equal(challengedState.state, "AcceptedPendingChallenge");

  const target = kind === "agent_test_result"
    ? fixtures.agents[0]
    : kind === "builder_test_result"
      ? fixtures.builds[0]
      : fixtures.availability[0];
  const tree = kind === "agent_test_result"
    ? fixtures.agentTree
    : kind === "builder_test_result"
      ? fixtures.buildTree
      : fixtures.availabilityTree;
  const leafCount = kind === "agent_test_result"
    ? fixtures.agents.length
    : kind === "builder_test_result"
      ? fixtures.builds.length
      : fixtures.availability.length;
  if (kind === "agent_test_result") {
    const active = JSON.parse(call("governanceStakeState", [], {
      caller: addresses[0], block: BigInt(creationBlock + 160), epoch: 21,
    })).active;
    call("scheduleWithdrawal", [active], {
      caller: addresses[0], block: BigInt(creationBlock + 160), epoch: 21,
    });
  }
  if (kind === "availability_probe") {
    call("registerGovernanceStake", [], {
      caller: target.owner,
      block: BigInt(creationBlock + 160),
      epoch: 22,
      payment: 100n * 10n ** 18n,
    });
  }
  const challengeEpoch = kind === "availability_probe" ? 22 : 21;
  const proposerStakeBefore = JSON.parse(call("governanceStakeState", [], {
    caller: addresses[0], block: BigInt(creationBlock + 161), epoch: challengeEpoch,
  }));
  const offenderStakeBefore = JSON.parse(call("governanceStakeState", [], {
    caller: target.owner, block: BigInt(creationBlock + 161), epoch: challengeEpoch,
  }));
  const targetFields = kind === "agent_test_result"
    ? `${target.cid}|${target.model}|${target.owner.toString("hex")}|${target.unresolved}`
    : kind === "builder_test_result"
      ? `${target.cid}|${target.digest}|${target.platform}|${target.owner.toString("hex")}`
      : `${target.cid}|${fixtures.candidateCid}|${fixtures.pinset.cid}|${target.value.providerId}|${target.owner.toString("hex")}`;
  const targetIndex = tree.indexByField.get(targetFields);
  assert.notEqual(targetIndex, undefined);
  expectFailure(() => call("submitObjectiveChallenge", [
    created.proposalId, kind, target.cid, target.hex, target.testResult.cid,
    `${target.testResult.hex.slice(0, -2)}00`, targetIndex.toString(), leafCount.toString(), tree.proofs[targetIndex].join(","),
  ], { caller: addresses[7], block: BigInt(creationBlock + 161), epoch: challengeEpoch }));
  challengedState = JSON.parse(call("submitObjectiveChallenge", [
    created.proposalId, kind, target.cid, target.hex, target.testResult.cid,
    target.testResult.hex, targetIndex.toString(), leafCount.toString(), tree.proofs[targetIndex].join(","),
  ], { caller: addresses[7], block: BigInt(creationBlock + 161), epoch: challengeEpoch }));
  assert.equal(challengedState.state, "Challenged");
  assert.equal(challengedState.challengeEvidenceCid, target.testResult.cid);
  challengedState = JSON.parse(call("resolveObjectiveChallenge", [created.proposalId], {
    caller: addresses[6], block: BigInt(creationBlock + 161), epoch: challengeEpoch,
  }));
  const proposerIsOffender = target.owner.equals(addresses[0]);
  assert.equal(challengedState.state, proposerIsOffender ? "Rejected" : "Expired");
  const proposerStakeAfter = JSON.parse(call("governanceStakeState", [], {
    caller: addresses[0], block: BigInt(creationBlock + 161), epoch: challengeEpoch,
  }));
  const expectedProposerSlash = proposerIsOffender ? BigInt(proposerStakeBefore.active) * 5n / 100n : 0n;
  assert.equal(BigInt(proposerStakeAfter.active), BigInt(proposerStakeBefore.active) - expectedProposerSlash);
  assert.equal(proposerStakeAfter.withdrawal.split("~")[0], proposerStakeAfter.active);
  assert.equal(
    proposerStakeAfter.slashReservations,
    proposerStakeBefore.slashReservations - (proposerIsOffender ? 2 : 1),
  );
  if (!proposerIsOffender) {
    const offenderStakeAfter = JSON.parse(call("governanceStakeState", [], {
      caller: target.owner, block: BigInt(creationBlock + 161), epoch: challengeEpoch,
    }));
    const pendingBeforeFields = offenderStakeBefore.pending
      ? offenderStakeBefore.pending.split("~")
      : [];
    const slashableStake = BigInt(offenderStakeBefore.active);
    const expectedOffenderSlash = slashableStake * 5n / 100n;
    assert.equal(BigInt(offenderStakeAfter.active), slashableStake - expectedOffenderSlash);
    if (kind === "availability_probe") {
      const pendingAfterFields = offenderStakeAfter.pending.split("~");
      assert.equal(pendingAfterFields[0], pendingBeforeFields[0]);
      assert.equal(pendingAfterFields[1], pendingBeforeFields[1]);
      assert.equal(pendingAfterFields[2], pendingBeforeFields[2]);
      assert.equal(
        pendingAfterFields[3],
        (
          governanceWeight(
            BigInt(offenderStakeAfter.active) + BigInt(pendingAfterFields[0]),
            metricLeaves[addresses.findIndex((address) => address.equals(target.owner))].state,
            metricLeaves[addresses.findIndex((address) => address.equals(target.owner))].trust,
          )
          - governanceWeight(
            BigInt(offenderStakeAfter.active),
            metricLeaves[addresses.findIndex((address) => address.equals(target.owner))].state,
            metricLeaves[addresses.findIndex((address) => address.equals(target.owner))].trust,
          )
        ).toString(),
      );
    } else {
      assert.equal(offenderStakeAfter.pending, "");
    }
    assert.equal(offenderStakeAfter.slashReservations, offenderStakeBefore.slashReservations - 1);
  }
  call("withdrawRefundableBond", [created.proposalId], {
    caller: addresses[0], block: BigInt(creationBlock + 162), epoch: 21,
  });
  assert.equal(
    transfers.at(-1).amount,
    (proposerIsOffender ? 125n : 250n) * 10n ** 17n,
  );
  if (kind === "availability_probe") {
    call("withdrawAttestationBond", [created.proposalId, "availability", target.cid], {
      caller: target.owner, block: BigInt(creationBlock + 162), epoch: 21,
    });
    assert.equal(transfers.at(-1).amount, 5n * 10n ** 17n);
  } else {
    expectFailure(() => call("withdrawAttestationBond", [
      created.proposalId, kind === "agent_test_result" ? "agent" : "build", target.cid,
    ], { caller: target.owner, block: BigInt(creationBlock + 162), epoch: 21 }));
  }
}

function submitEvidenceAttestations(reviewRoundId, fixtures, atBlock, atEpoch = 11) {
  fixtures.agents.forEach((item) => call("submitAgentAttestation", [
    reviewRoundId, item.cid, item.hex,
  ], { caller: item.owner, block: atBlock, epoch: atEpoch, payment: 10n ** 18n }));
  fixtures.builds.forEach((item) => call("submitBuildAttestation", [
    reviewRoundId, item.cid, item.hex, fixtures.toolchain.hex,
  ], { caller: item.owner, block: atBlock, epoch: atEpoch, payment: 10n ** 18n }));
}

function submitAvailabilityAttestations(reviewRoundId, fixtures, atBlock, atEpoch = 11) {
  fixtures.availability.forEach((item) => call("submitDataAvailabilityAttestation", [
    reviewRoundId, item.cid, item.hex,
  ], { caller: item.owner, block: atBlock, epoch: atEpoch, payment: 10n ** 18n }));
}

function call(method, args, context = {}) {
  const snapshot = snapshotHarnessState();
  caller = Buffer.from(context.caller ?? caller);
  payment = context.payment ?? 0n;
  epoch = context.epoch ?? epoch;
  block = context.block ?? block;
  epochBlock = context.epochBlock ?? epochBlock;
  try {
    const pointers = args.map((value) => writeBytes(encoder.encode(String(value))));
    for (let index = 0; index < pointers.length; index++) {
      assert.equal(readString(pointers[index]), String(args[index]), `argument region ${index} changed before ${method}`);
    }
    const result = exports[method](...pointers);
    payment = 0n;
    if (result === undefined || result === 0) return null;
    return readString(result);
  } catch (error) {
    restoreHarnessState(snapshot);
    throw error;
  }
}

function snapshotHarnessState() {
  return {
    storage: new Map([...storage].map(([key, value]) => [key, Buffer.from(value)])),
    eventLength: events.length,
    transferLength: transfers.length,
    burnLength: burns.length,
    caller: Buffer.from(caller),
    payment,
    epoch,
    block,
    epochBlock,
  };
}

function restoreHarnessState(snapshot) {
  storage.clear();
  for (const [key, value] of snapshot.storage) storage.set(key, Buffer.from(value));
  events.length = snapshot.eventLength;
  transfers.length = snapshot.transferLength;
  burns.length = snapshot.burnLength;
  caller = Buffer.from(snapshot.caller);
  payment = snapshot.payment;
  epoch = snapshot.epoch;
  block = snapshot.block;
  epochBlock = snapshot.epochBlock;
}

function expectFailure(fn) {
  assert.throws(fn, /WASM assertion failed/);
}

function readRegion(ptr) {
  const view = new DataView(exports.memory.buffer);
  return { offset: view.getUint32(ptr, true), len: view.getUint32(ptr + 4, true) };
}

function readBytes(ptr) {
  if (ptr === 0) return new Uint8Array();
  const { offset, len } = readRegion(ptr);
  return new Uint8Array(exports.memory.buffer.slice(offset, offset + len));
}

function readString(ptr) { return decoder.decode(readBytes(ptr)); }

function readAssemblyScriptString(ptr) {
  if (!ptr || !exports) return "unknown";
  const view = new DataView(exports.memory.buffer);
  const byteLength = view.getUint32(ptr - 4, true);
  const units = new Uint16Array(exports.memory.buffer, ptr, byteLength / 2);
  return String.fromCharCode(...units);
}

function writeBytes(value) {
  const bytes = Buffer.from(value);
  const ptr = exports.allocate(bytes.length);
  const { offset, len } = readRegion(ptr);
  assert.equal(len, bytes.length);
  new Uint8Array(exports.memory.buffer, offset, len).set(bytes);
  return ptr;
}

function digest(value) { return createHash("sha256").update(value).digest(); }

function coreArtifactSetDigest(artifacts) {
  const core = artifacts
    .filter((artifact) => artifact.core)
    .sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
  assert.ok(core.length > 0);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(core.length);
  const parts = [Buffer.from("IDENA_GOV_CORE_ARTIFACT_SET_V1\0"), count];
  for (const artifact of core) {
    for (const value of [artifact.name, artifact.cid]) {
      const bytes = Buffer.from(value, "utf8");
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      parts.push(length, bytes);
    }
    parts.push(Buffer.from(artifact.sha256, "hex"), u64be(artifact.size));
  }
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

function cid(seed) {
  return `b${base32(Buffer.concat([Buffer.from([1, 0x71, 0x12, 0x20]), digest(seed)]))}`;
}

function link(value) { return CID.parse(value); }

function cidSha256(value) {
  return Buffer.from(link(value).multihash.digest).toString("hex");
}

function sourceFileFixture(path, content) {
  const bytes = Buffer.from(content);
  const raw = rawObject(bytes);
  return {
    path,
    mode: 0o644,
    size: bytes.length,
    cid: raw.cid,
    sha256: digest(bytes).toString("hex"),
  };
}

function sourceManifestFixture(repository, entries) {
  const sortedEntries = entries.map((entry) => ({ ...entry })).sort((left, right) => (
    Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))
  ));
  const packaged = dagObject({
    schemaVersion: 1,
    kind: "pohw-source-tree-v1",
    repository,
    files: sortedEntries.map((entry) => ({ ...entry, cid: link(entry.cid) })),
  });
  return { ...packaged, entries: sortedEntries };
}

function ecosystemManifestFixture(prefix, parentCid, source, artifacts) {
  const sourceCid = source.cid;
  const value = {
    schemaVersion: 1,
    ecosystemId: `pohw-${prefix}`,
    parentEcosystemCid: parentCid === null ? null : link(parentCid),
    repositories: [{
      schemaVersion: 1,
      name: "P2poolBTC",
      sourceTreeCid: link(sourceCid),
      sourceTreeSha256: cidSha256(sourceCid),
      gitBundleCid: null,
      gitCommitMetadata: null,
      dependencyLocks: [],
      toolchainLocks: { cargo: "1.97.0" },
      buildInstructions: ["cargo build --workspace --locked"],
      artifacts: artifacts.map((artifact) => ({
        ...artifact,
        cid: link(artifact.cid),
      })),
    }],
    compatibilityPins: {},
    toolchainLocks: { "/node": "24.18.0", "rust:compiler": "1.97.0" },
    governanceContractVersion: "0.1.0",
    governanceParameterSetCid: link(parameterCid),
  };
  const packaged = dagObject(value);
  const fixture = { ...packaged, sourceCid, source, artifacts };
  ecosystemManifests.set(fixture.cid, fixture);
  return fixture;
}

function dagObject(value) {
  const bytes = Buffer.from(dagCbor.encode(value));
  return {
    value,
    cid: `b${base32(Buffer.concat([Buffer.from([1, 0x71, 0x12, 0x20]), digest(bytes)]))}`,
    hex: bytes.toString("hex"),
  };
}

function metricsAttestation(operator, overrides = {}) {
  return dagObject({
    schemaVersion: 1,
    metricsRoot: metricTree.root,
    snapshotCid: cid("metrics-snapshot"),
    snapshotSha256: digest("metrics-snapshot").toString("hex"),
    sourceEpoch: 10,
    sourceBlockHeight: 1000,
    sourceBlockHash: sourceHash,
    replayStartHeight: 1,
    replayCommitment: digest("metrics-replay").toString("hex"),
    indexerImplementationCid: cid("metrics-indexer-implementation"),
    operatorIdenaAddress: `0x${operator.toString("hex")}`,
    observedAtBlockOrTimestamp: 3,
    authentication: "on-chain-submitter",
    ...overrides,
  });
}

function rawObject(value) {
  const bytes = Buffer.from(value);
  return {
    cid: `b${base32(Buffer.concat([Buffer.from([1, 0x55, 0x12, 0x20]), digest(bytes)]))}`,
    hex: bytes.toString("hex"),
  };
}

function rawCid(seed) { return rawObject(seed).cid; }

function base32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function bigEndian(value) {
  if (value === 0n) return Buffer.alloc(0);
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, "hex");
}

function fromBigEndian(value) {
  const hex = Buffer.from(value).toString("hex");
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function u64be(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function u16be(value) {
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return output;
}

function u32be(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function epochBallotCommitment({ epoch, voter, frozenRoot, choices, nonce, salt }) {
  const chainId = Buffer.from("idena-code-governance-day-local-testnet-v2:10002");
  return digest(Buffer.concat([
    Buffer.from("IDENA_CODE_DAO_EPOCH_BALLOT_V1"),
    u32be(chainId.length),
    chainId,
    contractAddress,
    u64be(epoch),
    voter,
    Buffer.from(frozenRoot, "hex"),
    u32be(choices.length),
    Buffer.from(choices.map((choice) => choice === "yes" ? 1 : choice === "no" ? 2 : 3)),
    u64be(nonce),
    salt,
  ])).toString("hex");
}

function flipTrust(finalized, reported) {
  assert(reported <= finalized);
  const rate = ((reported + 1n) * 10000n) / (finalized + 20n);
  const trust = 10000n - (15000n * rate) / 10000n;
  return Number(trust < 4000n ? 4000n : trust > 10000n ? 10000n : trust);
}

function governanceWeight(stakeAtoms, state, trustBps) {
  const statusBps = state === "Human" ? 10000n : state === "Verified" ? 8500n : 7000n;
  const quanta = stakeAtoms / 10n ** 12n;
  return integerSqrt(quanta) * statusBps * BigInt(trustBps) / 100000000n;
}

function integerSqrt(value) {
  if (value < 2n) return value;
  let left = 1n;
  let right = value / 2n + 1n;
  while (left <= right) {
    const middle = (left + right) / 2n;
    const quotient = value / middle;
    if (middle === quotient || (middle < quotient && middle + 1n > value / (middle + 1n))) return middle;
    if (middle > quotient) right = middle - 1n;
    else left = middle + 1n;
  }
  return right;
}

function metricsLeaf(item) {
  const stateCode = { Newbie: 1, Verified: 2, Human: 3 }[item.state];
  return digest(Buffer.concat([
    Buffer.from("IDENA_GOV_METRICS_V1\0"), item.address, Buffer.from([stateCode]),
    u64be(item.finalized), u64be(item.reported), u16be(item.trust), u16be(item.sourceEpoch),
    u64be(item.sourceHeight), Buffer.from(item.sourceHash, "hex"),
  ]));
}

function metricsTree(items) {
  const leaves = items.map(metricsLeaf);
  const { root: treeRoot, proofs } = treeWithProofs(leaves, (left, right) => digest(Buffer.concat([
    Buffer.from("IDENA_GOV_MERKLE_V1\0"), left, right,
  ])));
  return {
    root: digest(Buffer.concat([Buffer.from("IDENA_GOV_METRICS_ROOT_V1\0"), u64be(leaves.length), treeRoot])).toString("hex"),
    proofs,
  };
}

function attestationTree(domain, fields) {
  const sortedFields = [...fields].sort();
  const leaves = sortedFields.map((value) => digest(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(value)])));
  const { root: treeRoot, proofs } = treeWithProofs(leaves, (left, right) => digest(Buffer.concat([
    Buffer.from("IDENA_GOV_ATTESTATION_MERKLE_V1\0"), left, right,
  ])));
  return {
    root: digest(Buffer.concat([
      Buffer.from("IDENA_GOV_ATTESTATION_ROOT_V1\0"), Buffer.from(domain), Buffer.from([0]), u64be(leaves.length), treeRoot,
    ])).toString("hex"),
    proofs,
    indexByField: new Map(sortedFields.map((value, index) => [value, index])),
  };
}

function treeWithProofs(leaves, hashNode) {
  assert(leaves.length > 0);
  const proofs = leaves.map(() => []);
  let level = leaves.map((hash, index) => ({ hash, members: [index] }));
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      for (const member of left.members) proofs[member].push(right.hash.toString("hex"));
      if (right !== left) for (const member of right.members) proofs[member].push(left.hash.toString("hex"));
      next.push({ hash: hashNode(left.hash, right.hash), members: right === left ? [...left.members] : [...left.members, ...right.members] });
    }
    level = next;
  }
  return { root: level[0].hash, proofs };
}
