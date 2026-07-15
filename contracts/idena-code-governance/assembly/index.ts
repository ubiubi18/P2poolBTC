import { u128Safe as u128 } from "as-bignum/assembly";
import {
  allocate,
  argumentString,
  attachedAmount,
  burn,
  bytesToHex,
  callerBytes,
  callerHex,
  currentBlock,
  currentEpoch,
  emitVersionedEvent,
  getString,
  hasKey,
  hexToBytes,
  optionalArgumentString,
  removeKey,
  requireNoPayment,
  returnString,
  setString,
  stringToBytes,
  transfer,
} from "./host";
import {
  epochAttestationGatesPass,
  ensureCurrentGovernanceEpochAnchored,
  initializeEpochGovernanceProfile,
  isEpochGovernanceEnabled,
  isBoundRevertProposal,
  recordEpochExecution,
  registerEpochProposal,
} from "./epoch_governance";
import {
  effectiveVoteWeight,
  flipTrustBps,
  parseAmount,
  parseU16,
  parseU32,
  parseU64,
  ratioAtLeast,
  statusBps,
} from "./math";
import { sha256 } from "./sha256";
import {
  TOTAL_WEIGHT_KEY,
  WEIGHT_EPOCH_KEY,
  WEIGHT_LAST_CHANGED_BLOCK_KEY,
  replaceGlobalWeight,
  replaceScheduledWeightDelta,
  syncGlobalWeightEpoch,
} from "./stake_weight";
import {
  CanonicalDagCborMap,
  verifiedCanonicalDagCborMap,
  verifiedCanonicalScopeDagCborMap,
  verifiedCanonicalSourceProofDagCborMap,
  verifiedFalseResult,
} from "./dag_cbor";
import {
  BondRecord,
  MetricsRecord,
  Proposal,
  ReviewRound,
  REVIEW_ROUND_AVAILABILITY_OPEN,
  REVIEW_ROUND_CLAIMED,
  REVIEW_ROUND_EXPIRED,
  REVIEW_ROUND_FROZEN,
  REVIEW_ROUND_OPEN,
  STATE_ACCEPTED_PENDING_CHALLENGE,
  STATE_ACCEPTED_PENDING_EXECUTION,
  STATE_CHALLENGED,
  STATE_DRAFT,
  STATE_EXECUTED,
  STATE_EXPIRED,
  STATE_ACCEPTED_PENDING_GRACE,
  STATE_CANCELLED_BEFORE_CUTOFF,
  STATE_NO_QUORUM,
  STATE_PROPOSAL_SET_FROZEN,
  STATE_REJECTED,
  STATE_REVERT_PROPOSED,
  STATE_REVERTED,
  STATE_REVIEW_OPEN,
  STATE_STALE,
  STATE_VOTING_COMMIT,
  STATE_VOTING_REVEAL,
  STATE_VOTING_OPEN,
  loadProposal,
  loadReviewRound,
  proposalKey,
  saveProposal,
  saveReviewRound,
} from "./state";
import {
  buildAttestationCommitmentRoot,
  canonicalContentCidSha256,
  canonicalManifestCidSha256,
  isCanonicalHash,
  isCanonicalManifestCid,
  isCanonicalRawCid,
  isSafeLabel,
  verifyAttestationCommitment,
  verifyIdentityMetricsProof,
} from "./validation";

export {
  anchorGovernanceEpoch,
  attachAiReviewRoot,
  attachBuildRoot,
  attachRecoveryManifest,
  cancelProposalBeforeCutoff,
  commitEpochBallot,
  createRevertProposal,
  enterExecutionReadyState,
  freezeEpochProposalSet,
  getCanonicalHistory,
  getCanonicalHistoryPage,
  getEpochBallotReceipt,
  getEpochDecisionRecord,
  getEpochProposalSet,
  getGovernanceEpoch,
  getGovernanceSchedule,
  getProposalSlot,
  getTreasuryState,
  previewVotingPower,
  revealEpochBallot,
  finalizeEpochVoting,
  finalizeEpochVotingForEpoch,
} from "./epoch_governance";

export { allocate };

const SCHEMA_VERSION = "1";
const CONTRACT_VERSION = "0.1.0";
const INITIALIZED_KEY = "governance:initialized";
const CANONICAL_CID_KEY = "governance:canonical-cid";
const PARAMETER_CID_KEY = "governance:parameter-cid";
const METRICS_ROOT_KEY = "governance:metrics-root";
const METRICS_EPOCH_KEY = "governance:metrics-epoch";

const EXPECTED_PARAMETER_CID = "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq";
const REVIEW_BLOCKS: u64 = 40;
const VOTING_BLOCKS: u64 = 120;
const CHALLENGE_BLOCKS: u64 = 60;
const TIMELOCK_BLOCKS: u64 = 60;
const EXECUTION_WINDOW_BLOCKS: u64 = 600;
const UNBONDING_EPOCHS: u16 = 4;
const MAX_STAKE_HISTORY = 256;
const CORE_ARTIFACT_SET_DOMAIN = "IDENA_GOV_CORE_ARTIFACT_SET_V1\0";
const MAX_PORTABLE_ARTIFACT_SIZE: u64 = 9007199254740991;
const MAX_COMMITTED_ATTESTATIONS: u32 = 256;
const MAX_ATTESTATIONS_PER_OWNER_PER_CLASS: u32 = 2;
const MAX_REQUIRED_AVAILABILITY_CIDS: u32 = 4096;
const MIN_IDENTITY_METRICS_ATTESTATIONS: u32 = 3;

const MIN_ACTIVE_STAKE_ATOMS = "1000000000000000000";
const MIN_PROPOSAL_BOND_ATOMS = "10000000000000000000";
const CRITICAL_PROPOSAL_BOND_ATOMS = "25000000000000000000";
const MIN_REVIEWER_BOND_ATOMS = "1000000000000000000";
const MIN_BUILDER_BOND_ATOMS = "1000000000000000000";
const MIN_AVAILABILITY_BOND_ATOMS = "1000000000000000000";
const STALE_PROCESSING_FEE_ATOMS = "100000000000000000";
const FRAUDULENT_ACTOR_STAKE_SLASH_PERCENT: u8 = 5;
const UNAVAILABLE_BOND_SLASH_PERCENT: u8 = 50;

const NORMAL_QUORUM_BPS: u16 = 2000;
const NORMAL_YES_BPS: u16 = 6667;
const CRITICAL_QUORUM_BPS: u16 = 3000;
const CRITICAL_YES_BPS: u16 = 7500;

export function deploy(
  initialCanonicalCidPtr: usize,
  parameterCidPtr: usize,
  metricsRootPtr: usize,
  metricsEpochPtr: usize,
): void {
  assert(!hasKey(INITIALIZED_KEY), "contract is already initialized");
  requireNoPayment();
  const canonicalCid = argumentString(initialCanonicalCidPtr, 128);
  const parameterCid = argumentString(parameterCidPtr, 128);
  const metricsRoot = argumentString(metricsRootPtr, 64);
  const metricsEpoch = parseU16(argumentString(metricsEpochPtr, 5));
  assert(isCanonicalManifestCid(canonicalCid), "initial ecosystem CID is not canonical DAG-CBOR CIDv1");
  assert(isCanonicalManifestCid(parameterCid), "parameter CID is not canonical DAG-CBOR CIDv1");
  assert(parameterCid == EXPECTED_PARAMETER_CID, "parameter CID does not match this contract build");
  assert(isCanonicalHash(metricsRoot), "identity metrics root must be lowercase SHA-256");
  setString(INITIALIZED_KEY, "1");
  setString(CANONICAL_CID_KEY, canonicalCid);
  setString(PARAMETER_CID_KEY, parameterCid);
  setString(METRICS_ROOT_KEY, metricsRoot);
  setString(METRICS_EPOCH_KEY, metricsEpoch.toString());
  setString(TOTAL_WEIGHT_KEY, "0");
  setString(WEIGHT_LAST_CHANGED_BLOCK_KEY, currentBlock().toString());
  setString(WEIGHT_EPOCH_KEY, currentEpoch().toString());
  initializeEpochGovernanceProfile();
  emitVersionedEvent("GovernanceInitializedV1", [canonicalCid, parameterCid, metricsRoot, metricsEpoch.toString()]);
}

export function registerGovernanceStake(): usize {
  ensureInitialized();
  const payment = attachedAmount();
  assert(!payment.isZero(), "stake deposit must be nonzero");
  const address = callerHex();
  activateStakeFor(address);
  requireCurrentEligibleMetrics(address);
  const activationEpoch = checkedEpochAdd(currentEpoch(), 1);
  const key = pendingStakeKey(address);
  let previousPending = u128.Zero;
  let previousDelta = u128.Zero;
  if (hasKey(key)) {
    const pending = getString(key).split("~");
    assert(pending.length == 4, "corrupt pending stake record");
    assert(parseU16(pending[1]) == activationEpoch, "older stake deposit must be activated first");
    assert(pending[2] == getString(METRICS_ROOT_KEY), "pending stake belongs to an older metrics generation");
    previousPending = parseAmount(pending[0]);
    previousDelta = parseAmount(pending[3]);
  }
  const amount = previousPending + payment;
  const active = activeStake(address);
  const currentWeight = registeredWeight(address, active);
  const projectedWeight = registeredWeight(address, active + amount);
  assert(projectedWeight >= currentWeight, "stake activation would reduce registered weight");
  const scheduledDelta = projectedWeight - currentWeight;
  replaceScheduledWeightDelta(activationEpoch, previousDelta, scheduledDelta);
  appendStakeLot(address, payment, activationEpoch);
  setString(
    key,
    amount.toString() + "~" + activationEpoch.toString() + "~"
      + getString(METRICS_ROOT_KEY) + "~" + scheduledDelta.toString(),
  );
  emitVersionedEvent("GovernanceStakeScheduledV1", [address, amount.toString(), activationEpoch.toString()]);
  return okJson("activationEpoch", activationEpoch.toString());
}

export function activateGovernanceStake(): usize {
  ensureInitialized();
  requireNoPayment();
  const activated = activateStakeFor(callerHex());
  return returnString("{\"ok\":true,\"activated\":" + (activated ? "true" : "false") + "}");
}

export function scheduleWithdrawal(amountPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  activateStakeFor(address);
  const amount = parseAmount(argumentString(amountPtr, 39));
  assert(!amount.isZero(), "withdrawal amount must be nonzero");
  assert(!hasKey(withdrawalKey(address)), "an unbonding withdrawal already exists");
  assert(activeStake(address) >= amount, "withdrawal exceeds active governance stake");
  const startEpoch = checkedEpochAdd(currentEpoch(), 1);
  const readyEpoch = checkedEpochAdd(startEpoch, UNBONDING_EPOCHS);
  setString(withdrawalKey(address), amount.toString() + "~" + startEpoch.toString() + "~" + readyEpoch.toString());
  emitVersionedEvent("GovernanceWithdrawalScheduledV1", [address, amount.toString(), startEpoch.toString(), readyEpoch.toString()]);
  return okJson("readyEpoch", readyEpoch.toString());
}

export function beginUnbonding(amountPtr: usize): usize {
  return scheduleWithdrawal(amountPtr);
}

export function finalizeUnbonding(): usize {
  ensureInitialized();
  requireNoPayment();
  ensureCurrentGovernanceEpochAnchored();
  const address = callerHex();
  assert(
    stakeSlashReservationCount(address) == 0,
    "unbonding cannot finalize while slashable governance bonds remain unsettled",
  );
  // A matured pending lot is already reflected in the settled global weight.
  // Materialize it before replacing this voter's nonlinear aggregate weight.
  activateStakeFor(address);
  const key = withdrawalKey(address);
  const fields = getString(key).split("~");
  assert(fields.length == 3, "no scheduled withdrawal exists");
  const amount = parseAmount(fields[0]);
  assert(currentEpoch() >= parseU16(fields[2]), "unbonding delay has not elapsed");
  const oldStake = activeStake(address);
  assert(oldStake >= amount, "slash or state change reduced the withdrawable stake");
  const oldWeight = recordedWeight(address, oldStake);
  appendWithdrawalCheckpoint(address, amount, false);
  const newStake = oldStake - amount;
  setString(activeStakeKey(address), newStake.toString());
  const newWeight = recordedWeight(address, newStake);
  replaceGlobalWeight(oldWeight, newWeight);
  refreshPendingStakeWeight(address, loadMetrics(address), newStake, newWeight);
  removeKey(key);
  emitVersionedEvent("GovernanceWithdrawalFinalizedV1", [address, amount.toString()]);
  transfer(hexToBytes(address), amount);
  return okJson("amount", amount.toString());
}

export function registerIdentityMetricsProof(
  statePtr: usize,
  finalizedPtr: usize,
  reportedPtr: usize,
  trustPtr: usize,
  sourceEpochPtr: usize,
  sourceHeightPtr: usize,
  sourceHashPtr: usize,
  indexPtr: usize,
  leafCountPtr: usize,
  siblingsPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  ensureCurrentGovernanceEpochAnchored();
  const state = argumentString(statePtr, 16);
  const finalized = parseU64(argumentString(finalizedPtr, 20));
  const reported = parseU64(argumentString(reportedPtr, 20));
  const trust = parseU16(argumentString(trustPtr, 5));
  const sourceEpoch = parseU16(argumentString(sourceEpochPtr, 5));
  const sourceHeight = parseU64(argumentString(sourceHeightPtr, 20));
  const sourceHash = argumentString(sourceHashPtr, 64);
  const index = parseU64(argumentString(indexPtr, 20));
  const leafCount = parseU64(argumentString(leafCountPtr, 20));
  const siblings = optionalArgumentString(siblingsPtr, 8192);
  const root = getString(METRICS_ROOT_KEY);
  assert(sourceEpoch == parseStoredU16(METRICS_EPOCH_KEY), "identity proof uses the wrong snapshot epoch");
  const addressBytes = callerBytes();
  assert(
    verifyIdentityMetricsProof(
      addressBytes, state, finalized, reported, trust, sourceEpoch, sourceHeight,
      sourceHash, index, leafCount, siblings, root,
    ),
    "invalid identity metrics proof",
  );
  const address = bytesToHex(addressBytes);
  activateStakeFor(address);
  const oldStake = activeStake(address);
  const oldWeight = recordedWeight(address, oldStake);
  const record = new MetricsRecord(
    state, finalized, reported, trust, sourceEpoch, sourceHeight, sourceHash, root, currentBlock(),
  );
  setString(metricsKey(address), record.encode());
  const newWeight = weightForMetrics(oldStake, state, trust);
  replaceGlobalWeight(oldWeight, newWeight);
  refreshPendingStakeWeight(address, record, oldStake, newWeight);
  emitVersionedEvent("IdentityMetricsRegisteredV1", [address, root, sourceEpoch.toString()]);
  return okJson("root", root);
}

export function submitIdentityMetricsAttestation(
  attestationCidPtr: usize,
  attestationDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const owner = callerHex();
  requireCurrentEligibleMetrics(owner);
  const cid = argumentString(attestationCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(cid, argumentString(attestationDagCborHexPtr, 131072));
  payload.requireExactKeys(identityMetricsAttestationPayloadKeys());
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "identity metrics attestation schema version is unsupported");
  const root = payload.string("metricsRoot");
  const snapshotCid = payload.string("snapshotCid");
  const snapshotSha256 = payload.string("snapshotSha256");
  const sourceEpoch = parseU16(payload.unsigned("sourceEpoch"));
  const sourceHeight = parseU64(payload.unsigned("sourceBlockHeight"));
  const sourceHash = payload.string("sourceBlockHash");
  const replayStartHeight = parseU64(payload.unsigned("replayStartHeight"));
  const replayCommitment = payload.string("replayCommitment");
  const implementationCid = payload.string("indexerImplementationCid");
  const payloadOwner = canonicalPayloadAddress(payload.string("operatorIdenaAddress"));
  assert(isCanonicalHash(root), "identity metrics root must be lowercase SHA-256");
  assert(isCanonicalManifestCid(snapshotCid), "identity metrics snapshot must use canonical DAG-CBOR CIDv1");
  assert(isCanonicalHash(snapshotSha256), "identity metrics snapshot digest must be lowercase SHA-256");
  assert(canonicalManifestCidSha256(snapshotCid) == snapshotSha256, "identity metrics snapshot CID and digest disagree");
  assert(isCanonicalHash(sourceHash), "identity metrics source block hash must be lowercase SHA-256");
  assert(isCanonicalHash(replayCommitment), "identity metrics replay commitment must be lowercase SHA-256");
  assert(isCanonicalManifestCid(implementationCid), "identity metrics implementation must use canonical source CIDv1");
  assert(replayStartHeight <= sourceHeight, "identity metrics replay boundary exceeds its source height");
  assert(payloadOwner == owner, "identity metrics attestation owner does not match the caller");
  assert(payload.string("authentication") == "on-chain-submitter", "unsupported identity metrics attestation authentication");
  assert(parseU64(payload.unsigned("observedAtBlockOrTimestamp")) <= currentBlock(), "identity metrics attestation is from the future");
  const descriptor = snapshotCid + "|" + snapshotSha256 + "|" + sourceHeight.toString()
    + "|" + sourceHash + "|" + replayStartHeight.toString() + "|" + replayCommitment
    + "|" + implementationCid;
  const descriptorHash = hashString("IDENA_GOV_METRICS_CERTIFICATION_V1\x00" + descriptor);
  const certifiedKey = metricsCertificationFinalizedDescriptorKey(root, sourceEpoch);
  const certifiedDescriptor = getString(certifiedKey);
  assert(
    certifiedDescriptor.length == 0 || certifiedDescriptor == descriptorHash,
    "identity metrics descriptor differs from the immutable certified descriptor",
  );
  const marker = metricsCertificationOwnerKey(root, sourceEpoch, owner);
  assert(!hasKey(marker), "identity may certify a metrics root only once");
  setString(marker, cid + "|" + descriptorHash);
  const descriptorKey = metricsCertificationDescriptorKey(root, sourceEpoch, descriptorHash);
  if (!hasKey(descriptorKey)) setString(descriptorKey, descriptor);
  const countKey = metricsCertificationCandidateCountKey(root, sourceEpoch, descriptorHash);
  const oldCount = getString(countKey);
  const count = checkedU32Add(oldCount.length == 0 ? 0 : parseU32(oldCount), 1);
  setString(countKey, count.toString());
  if (count >= MIN_IDENTITY_METRICS_ATTESTATIONS && !hasKey(certifiedKey)) {
    setString(certifiedKey, descriptorHash);
  }
  emitVersionedEvent("MetricsAttestationSubmittedV1", [root, sourceEpoch.toString(), descriptorHash, cid, owner, count.toString()]);
  return metricsCertificationJson(root, sourceEpoch);
}

export function identityMetricsCertification(rootPtr: usize, epochPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const root = argumentString(rootPtr, 64);
  const epoch = parseU16(argumentString(epochPtr, 5));
  assert(isCanonicalHash(root), "identity metrics root must be lowercase SHA-256");
  return metricsCertificationJson(root, epoch);
}

export function openReviewRound(
  parentCidPtr: usize,
  parentDagCborHexPtr: usize,
  candidateCidPtr: usize,
  candidateDagCborHexPtr: usize,
  patchCidPtr: usize,
  patchDagCborHexPtr: usize,
  pinsetCidPtr: usize,
  pinsetDagCborHexPtr: usize,
  scopeCidPtr: usize,
  scopeDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  const opener = callerHex();
  requireCurrentEligibleMetrics(opener);
  const parent = argumentString(parentCidPtr, 128);
  const candidate = argumentString(candidateCidPtr, 128);
  const patch = argumentString(patchCidPtr, 128);
  const pinsetCid = argumentString(pinsetCidPtr, 128);
  const scopeCid = argumentString(scopeCidPtr, 128);
  assert(parent == getString(CANONICAL_CID_KEY), "review round parent is stale");
  assert(isCanonicalManifestCid(candidate), "candidate ecosystem CID must be canonical DAG-CBOR CIDv1");
  assert(isCanonicalManifestCid(patch), "patch CID must be canonical DAG-CBOR CIDv1");
  assert(isCanonicalManifestCid(pinsetCid), "pinset CID must be canonical DAG-CBOR CIDv1");
  assert(isCanonicalManifestCid(scopeCid), "scope evidence CID must be canonical DAG-CBOR CIDv1");
  const parentBinding = validateEcosystemManifest(
    verifiedCanonicalDagCborMap(parent, argumentString(parentDagCborHexPtr, 131072)),
    "",
  );
  const candidateBinding = validateEcosystemManifest(
    verifiedCanonicalDagCborMap(candidate, argumentString(candidateDagCborHexPtr, 131072)),
    parent,
  );
  const patchBinding = validateEcosystemPatch(
    verifiedCanonicalDagCborMap(patch, argumentString(patchDagCborHexPtr, 131072)),
    parent,
    candidate,
    parentBinding.sources,
    candidateBinding.sources,
  );
  const scopeBinding = validateProposalScopeEvidence(
    verifiedCanonicalScopeDagCborMap(scopeCid, argumentString(scopeDagCborHexPtr, 2800000)),
    parent,
    candidate,
    patch,
    patchBinding,
  );
  for (let i = 0; i < patchBinding.requiredCids.length; i++) {
    candidateBinding.requiredCids.push(patchBinding.requiredCids[i]);
  }
  candidateBinding.requiredCids.push(scopeCid);
  const pinset = validatePinsetManifest(
    verifiedCanonicalDagCborMap(pinsetCid, argumentString(pinsetDagCborHexPtr, 131072)),
    candidate,
    patch,
    candidateBinding.requiredCids,
  );
  const candidateKey = reviewCandidateKey(parent, candidate, patch);
  assert(!hasKey(candidateKey), "this exact candidate already has an active review round or proposal");
  const bond = attachedAmount();
  assert(bond >= parseAmount(MIN_PROPOSAL_BOND_ATOMS), "review opening bond is below the proposal minimum");
  reserveStakeSlashSlot(opener);
  const opened = currentBlock();
  const end = checkedBlockAdd(opened, REVIEW_BLOCKS);
  const claimDeadline = checkedBlockAdd(end, REVIEW_BLOCKS);
  const id = hashString(
    "IDENA_GOV_REVIEW_ROUND_V2\x00" + parent + "|" + candidate + "|" + patch + "|" + scopeCid + "|" + opener + "|" + opened.toString(),
  );
  const round = new ReviewRound(
    id, parent, candidate, patch, candidateBinding.sourceBinding, patchBinding.affectedSourceBinding,
    candidateBinding.toolchainBinding, pinsetCid, <u32>pinset.length,
    opener, REVIEW_ROUND_OPEN, opened, end,
    claimDeadline, "", "", "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "",
    bond.toString(), "0", false,
  );
  saveReviewRound(round);
  setString(reviewCandidateArtifactCountKey(id), candidateBinding.artifactKeys.length.toString());
  for (let i = 0; i < candidateBinding.artifactKeys.length; i++) {
    setString(candidateArtifactKey(id, candidateBinding.artifactKeys[i]), "1");
  }
  setString(reviewSourceTransitionKey(id), patchBinding.sourceTransitionBinding);
  setString(reviewScopeEvidenceKey(id), scopeCid);
  setString(reviewScopeRiskKey(id), scopeBinding.risk);
  setString(reviewScopeCountersKey(id), scopeBinding.counters());
  for (let i = 0; i < pinset.length; i++) {
    setString(reviewPinsetMemberKey(id, pinset[i]), "1");
    addAvailabilityRequirement(id, pinset[i]);
  }
  setString(candidateKey, id);
  emitVersionedEvent(
    "ReviewRoundOpenedV2",
    [id, parent, candidate, patch, scopeCid, pinsetCid, opener, end.toString(), claimDeadline.toString()],
  );
  return reviewRoundStateJson(round);
}

export function freezeReviewRound(reviewRoundIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const round = loadReviewRound(validReviewRoundId(argumentString(reviewRoundIdPtr, 64)));
  assert(currentBlock() <= round.claimDeadline, "review round claim deadline has elapsed");
  assert(round.parentCid == getString(CANONICAL_CID_KEY), "review round parent is stale");
  if (round.state == REVIEW_ROUND_OPEN) {
    assert(currentBlock() >= round.endBlock, "review evidence submission deadline has not elapsed");
    assert(round.agentLeafCount > 0 && round.buildLeafCount > 0, "review evidence set is incomplete");
    round.agentRoot = buildAttestationCommitmentRoot(
      "agent_review_v1", loadReviewEntries("agent", round.id, round.agentLeafCount),
    );
    round.buildRoot = buildAttestationCommitmentRoot(
      "build_attestation_v1", loadReviewEntries("build", round.id, round.buildLeafCount),
    );
    recomputeAgentAggregates(round);
    selectBuildDigest(round);
    round.state = REVIEW_ROUND_AVAILABILITY_OPEN;
    saveReviewRound(round);
    emitVersionedEvent("ReviewEvidenceFrozenV1", [round.id, round.agentRoot, round.buildRoot]);
    return reviewRoundStateJson(round);
  }
  assert(round.state == REVIEW_ROUND_AVAILABILITY_OPEN, "review round is not awaiting availability evidence");
  assert(round.availabilityLeafCount > 0, "review round availability set is incomplete");
  round.availabilityRoot = buildAttestationCommitmentRoot(
    "data_availability_v1", loadReviewEntries("availability", round.id, round.availabilityLeafCount),
  );
  finalizeAvailabilityCoverage(round);
  const availabilityMinimum: u32 = getString(reviewScopeRiskKey(round.id)) == "normal" ? 2 : 3;
  assert(
    round.availabilityOwnerCount >= availabilityMinimum,
    "review round lacks complete independent data-availability coverage",
  );
  round.state = REVIEW_ROUND_FROZEN;
  saveReviewRound(round);
  emitVersionedEvent("ReviewRoundFrozenV2", [round.id, round.agentRoot, round.buildRoot, round.availabilityRoot]);
  return reviewRoundStateJson(round);
}

export function expireReviewRound(reviewRoundIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const round = loadReviewRound(validReviewRoundId(argumentString(reviewRoundIdPtr, 64)));
  assert(
    round.state == REVIEW_ROUND_OPEN
      || round.state == REVIEW_ROUND_AVAILABILITY_OPEN
      || round.state == REVIEW_ROUND_FROZEN,
    "review round cannot expire",
  );
  const stale = round.parentCid != getString(CANONICAL_CID_KEY);
  assert(stale || currentBlock() > round.claimDeadline, "review round claim deadline has not elapsed");
  let refund = percentage(round.bondAmount(), 75);
  if (stale) {
    const feeLimit = parseAmount(STALE_PROCESSING_FEE_ATOMS);
    const fee = round.bondAmount() < feeLimit ? round.bondAmount() : feeLimit;
    refund = round.bondAmount() - fee;
  }
  const slash = round.bondAmount() - refund;
  round.state = REVIEW_ROUND_EXPIRED;
  round.refundableBond = refund.toString();
  releaseReviewCandidate(round);
  saveReviewRound(round);
  if (!slash.isZero()) burn(slash);
  emitVersionedEvent("ReviewRoundExpiredV1", [round.id, refund.toString(), slash.toString()]);
  return reviewRoundStateJson(round);
}

export function withdrawExpiredReviewBond(reviewRoundIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const round = loadReviewRound(validReviewRoundId(argumentString(reviewRoundIdPtr, 64)));
  const address = callerHex();
  assert(round.state == REVIEW_ROUND_EXPIRED, "review round bond remains locked");
  assert(round.opener == address, "only the review-round opener may withdraw");
  assert(!round.bondClaimed, "review round bond was already withdrawn");
  const amount = round.refundableBondAmount();
  assert(!amount.isZero(), "review round has no refundable bond");
  round.bondClaimed = true;
  saveReviewRound(round);
  releaseStakeSlashSlot(address);
  emitVersionedEvent("ReviewRoundBondWithdrawnV1", [round.id, address, amount.toString()]);
  transfer(hexToBytes(address), amount);
  return okJson("amount", amount.toString());
}

export function withdrawExpiredReviewAttestationBond(
  reviewRoundIdPtr: usize,
  kindPtr: usize,
  attestationCidPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const round = loadReviewRound(validReviewRoundId(argumentString(reviewRoundIdPtr, 64)));
  assert(round.state == REVIEW_ROUND_EXPIRED, "review attestation bond remains locked");
  const kind = argumentString(kindPtr, 16);
  assert(kind == "agent" || kind == "build" || kind == "availability", "unknown attestation bond kind");
  const cid = argumentString(attestationCidPtr, 128);
  const key = attestationBondKey(kind, round.id, cid);
  const record = BondRecord.decode(getString(key));
  const address = callerHex();
  assert(record.owner == address, "only the bonded attestor may withdraw");
  assert(!record.slashed && !record.claimed, "attestation bond is slashed or already withdrawn");
  record.claimed = true;
  setString(key, record.encode());
  releaseStakeSlashSlot(address);
  const amount = record.amountValue();
  emitVersionedEvent("ExpiredAttestBondWithdrawnV1", [round.id, kind, cid, address, amount.toString()]);
  transfer(hexToBytes(address), amount);
  return okJson("amount", amount.toString());
}

export function reviewRoundState(reviewRoundIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  return reviewRoundStateJson(loadReviewRound(validReviewRoundId(argumentString(reviewRoundIdPtr, 64))));
}

export function createProposal(
  proposalCidPtr: usize,
  proposalDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const weightLastChangedBeforeSettlement = parseU64(getString(WEIGHT_LAST_CHANGED_BLOCK_KEY));
  syncGlobalWeightEpoch();
  const proposer = callerHex();
  requireCurrentEligibleMetrics(proposer);
  const proposalCid = argumentString(proposalCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(
    proposalCid,
    argumentString(proposalDagCborHexPtr, 131072),
  );
  payload.requireExactKeys(proposalPayloadKeys());
  assert(parseU16(payload.unsigned("schemaVersion")) == 2, "proposal schema version is unsupported");
  const scopeCid = payload.string("scopeEvidenceCid");
  const proposalParameterCid = payload.string("governanceParameterSetCid");
  const parent = payload.string("parentCanonicalEcosystemCid");
  const candidateCid = payload.string("candidateEcosystemCid");
  const patchCid = payload.string("patchCid");
  const reviewRoundId = validReviewRoundId(payload.string("reviewRoundId"));
  const round = loadReviewRound(reviewRoundId);
  const risk = payload.string("riskClass");
  const agentRoot = payload.string("agentReviewRoot");
  const buildRoot = payload.string("buildAttestationRoot");
  const availabilityRoot = payload.string("dataAvailabilityRoot");
  const candidateMetricsRoot = payload.nullableString("candidateIdentityMetricsRoot");
  const candidateMetricsEpochString = payload.nullableUnsigned("candidateIdentityMetricsEpoch");
  const waiverCid = payload.nullableString("criticalFindingWaiverCid");
  const releaseManifestCid = payload.nullableString("releaseManifestCid");
  const rollbackManifestCid = payload.string("rollbackManifestCid");
  const rollbackInstructionsCid = payload.string("rollbackInstructionsCid");
  const contentProposer = canonicalPayloadAddress(payload.string("proposerAddress"));
  const contentBond = parseAmount(payload.string("proposalBondAtoms"));
  const creation = parseU64(payload.unsigned("creationBlock"));
  const creationEpoch = parseU16(payload.unsigned("creationEpoch"));
  const stakingEpoch = parseU16(payload.unsigned("stakingEpoch"));
  const metricsEpoch = parseU16(payload.unsigned("identityMetricsEpoch"));
  const votingStart = parseU64(payload.unsigned("votingStart"));
  const votingEnd = parseU64(payload.unsigned("votingEnd"));
  const challengeEnd = parseU64(payload.unsigned("challengeEnd"));
  const proposalAffectedBinding = validateProposalNestedPayload(payload);
  assert(
    proposalParameterCid == getString(PARAMETER_CID_KEY),
    "proposal governance parameter set does not match this contract",
  );
  assert(isCanonicalManifestCid(candidateCid), "candidate ecosystem CID must be canonical DAG-CBOR CIDv1");
  assert(isCanonicalManifestCid(patchCid), "patch CID must be canonical DAG-CBOR CIDv1");
  assert(isRiskClass(risk), "unknown proposal risk class");
  assert(scopeCid == getString(reviewScopeEvidenceKey(round.id)), "proposal scope evidence does not match its review round");
  assert(risk == getString(reviewScopeRiskKey(round.id)), "proposal risk differs from the objective scope classifier");
  assert(proposalDeclaredCounters(payload) == getString(reviewScopeCountersKey(round.id)), "proposal counters differ from verified scope evidence");
  validateProposalDeclaredLimits(payload, risk);
  assert(isCanonicalHash(agentRoot) && isCanonicalHash(buildRoot) && isCanonicalHash(availabilityRoot), "attestation roots must be lowercase SHA-256");
  assert(waiverCid.length == 0 || (risk != "normal" && isCanonicalManifestCid(waiverCid)), "critical waiver must be an immutable CID on a critical proposal");
  assert(releaseManifestCid.length == 0 || isCanonicalManifestCid(releaseManifestCid), "release manifest must use canonical DAG-CBOR CIDv1");
  assert(
    isCanonicalContentCid(rollbackManifestCid) && isCanonicalContentCid(rollbackInstructionsCid),
    "rollback metadata must use canonical CIDv1/SHA2-256",
  );
  assert(contentProposer == proposer, "proposal proposer does not match the caller");
  assert(round.state == REVIEW_ROUND_FROZEN, "proposal review round is not frozen");
  assert(round.opener == proposer, "only the bonded review-round opener may create its proposal");
  assert(currentBlock() <= round.claimDeadline, "review round claim deadline has elapsed");
  assert(round.parentCid == parent && round.candidateCid == candidateCid && round.patchCid == patchCid, "proposal does not match its frozen review round");
  assert(
    hasKey(reviewPinsetMemberKey(round.id, payload.string("rationaleCid")))
      && hasKey(reviewPinsetMemberKey(round.id, payload.string("migrationNotesCid")))
      && hasKey(reviewPinsetMemberKey(round.id, payload.string("testPlanCid"))),
    "proposal rationale, migration notes, and test plan must be committed by the opening pinset",
  );
  assert(
    releaseManifestCid.length == 0 || hasKey(reviewPinsetMemberKey(round.id, releaseManifestCid)),
    "release manifest is not committed by the opening pinset",
  );
  assert(
    hasKey(reviewPinsetMemberKey(round.id, rollbackManifestCid))
      && hasKey(reviewPinsetMemberKey(round.id, rollbackInstructionsCid)),
    "proposal rollback metadata must be committed by the opening pinset",
  );
  assert(
    waiverCid.length == 0 || hasKey(reviewPinsetMemberKey(round.id, waiverCid)),
    "critical finding waiver is not committed by the opening pinset",
  );
  assert(
    proposalAffectedBinding == getString(reviewSourceTransitionKey(round.id)),
    "proposal source transition does not match the verified ecosystem patch",
  );
  assert(round.agentRoot == agentRoot && round.buildRoot == buildRoot && round.availabilityRoot == availabilityRoot, "proposal attestation roots do not match the complete frozen review set");
  assert(parent == getString(CANONICAL_CID_KEY), "proposal parent is stale");
  assert(creation == currentBlock() && creationEpoch == currentEpoch(), "proposal creation boundary does not match the chain");
  assert(stakingEpoch == creationEpoch, "proposal staking epoch must equal its creation epoch");
  assert(metricsEpoch == parseStoredU16(METRICS_EPOCH_KEY), "proposal uses the wrong identity metrics epoch");
  assert(
    metricsCertificationCount(getString(METRICS_ROOT_KEY), metricsEpoch) >= MIN_IDENTITY_METRICS_ATTESTATIONS,
    "current identity metrics root lacks independent operator attestations",
  );
  assert(
    weightLastChangedBeforeSettlement < creation,
    "proposal weight snapshot requires a block without prior weight changes",
  );
  assert(votingStart == checkedBlockAdd(creation, REVIEW_BLOCKS), "proposal voting start is invalid");
  assert(votingEnd == checkedBlockAdd(votingStart, VOTING_BLOCKS), "proposal voting end is invalid");
  assert(challengeEnd == checkedBlockAdd(votingEnd, CHALLENGE_BLOCKS), "proposal challenge end is invalid");
  assert(
    (candidateMetricsRoot.length == 0) == (candidateMetricsEpochString.length == 0),
    "candidate identity metrics root and epoch must be supplied together",
  );
  let candidateMetricsEpoch = metricsEpoch;
  if (candidateMetricsRoot.length > 0) {
    assert(risk == "migration", "identity metrics transitions require a migration proposal");
    assert(isCanonicalHash(candidateMetricsRoot), "candidate metrics root must be lowercase SHA-256");
    candidateMetricsEpoch = parseU16(candidateMetricsEpochString);
    assert(candidateMetricsEpoch > metricsEpoch, "candidate metrics epoch must advance");
    assert(
      metricsCertificationCount(candidateMetricsRoot, candidateMetricsEpoch) >= MIN_IDENTITY_METRICS_ATTESTATIONS,
      "candidate identity metrics root lacks independent operator attestations",
    );
  }
  const bond = round.bondAmount();
  assert(bond == contentBond, "proposal bond does not match the bonded review round");
  const requiredBond = risk == "normal"
    ? parseAmount(MIN_PROPOSAL_BOND_ATOMS)
    : parseAmount(CRITICAL_PROPOSAL_BOND_ATOMS);
  assert(bond >= requiredBond, "proposal bond is below its risk-class minimum");
  const draftExpiry = checkedBlockAdd(creation, REVIEW_BLOCKS);
  const executeAfter = checkedBlockAdd(challengeEnd, TIMELOCK_BLOCKS);
  const metadataRoot = hashString("IDENA_GOV_PROPOSAL_METADATA_V2\x00" + proposalCid);
  const proposalId = hashString("IDENA_GOV_PROPOSAL_ID_V2\x00" + reviewRoundId);
  assert(!hasKey(proposalKey(proposalId)), "proposal ID collision");
  const proposal = new Proposal(
    proposalId, proposalCid, parent, candidateCid, patchCid, reviewRoundId, proposer, risk, STATE_DRAFT,
    agentRoot, buildRoot, availabilityRoot,
    round.agentLeafCount, round.agentLeafCount,
    round.buildLeafCount, round.buildLeafCount,
    round.availabilityLeafCount, round.availabilityLeafCount,
    metadataRoot, getString(METRICS_ROOT_KEY),
    metricsEpoch, stakingEpoch, candidateMetricsRoot, candidateMetricsEpoch,
    creation, draftExpiry, votingStart, votingEnd, challengeEnd, executeAfter,
    getString(TOTAL_WEIGHT_KEY), "0", "0", "0", 0, 0,
    round.agentCount, round.agentModelCount, round.agentOwnerCount,
    round.unresolvedCriticalCount, round.builderOwnerCount, round.builderPlatformCount,
    round.builderConflictCount, round.availabilityOwnerCount, round.artifactDigest,
    waiverCid, releaseManifestCid, "", "", "", bond.toString(), "0", false,
  );
  assert(
    isEpochGovernanceEnabled()
      ? epochAttestationGatesPass(proposal)
      : attestationGatesPass(proposal),
    "frozen review round does not satisfy the proposal risk-class gates",
  );
  round.state = REVIEW_ROUND_CLAIMED;
  round.proposalId = proposalId;
  registerEpochProposal(proposal, rollbackManifestCid, rollbackInstructionsCid);
  saveReviewRound(round);
  saveProposal(proposal);
  emitVersionedEvent("ProposalCreatedV1", [proposalId, reviewRoundId, parent, candidateCid, proposalCid, metadataRoot]);
  return returnString("{\"ok\":true,\"proposalId\":\"" + proposalId + "\",\"metadataRoot\":\"" + metadataRoot + "\"}");
}

export function submitProposalMetadataRoot(proposalIdPtr: usize, metadataRootPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_DRAFT, "proposal is not awaiting metadata confirmation");
  assert(currentBlock() <= proposal.draftExpiry, "proposal metadata confirmation deadline elapsed");
  assert(argumentString(metadataRootPtr, 64) == proposal.metadataRoot, "proposal metadata is immutable");
  proposal.state = STATE_REVIEW_OPEN;
  saveProposal(proposal);
  emitVersionedEvent("ProposalReviewOpenedV1", [proposal.id, proposal.metadataRoot, proposal.votingStart.toString()]);
  return proposalStateJson(proposal);
}

export function submitAgentAttestation(
  reviewRoundIdPtr: usize,
  attestationCidPtr: usize,
  attestationDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  const round = loadOpenReviewRound(argumentString(reviewRoundIdPtr, 64));
  const owner = callerHex();
  requireCurrentEligibleMetrics(owner);
  assert(activeStake(owner) >= parseAmount(MIN_ACTIVE_STAKE_ATOMS), "reviewer must maintain minimum active governance stake");
  const cid = argumentString(attestationCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(cid, argumentString(attestationDagCborHexPtr, 131072));
  payload.requireExactKeys(agentAttestationPayloadKeys());
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "agent attestation schema version is unsupported");
  const modelFamily = payload.string("modelFamily");
  const unresolved = parseU32(payload.unsigned("unresolvedCriticalFindings"));
  const payloadOwner = canonicalPayloadAddress(payload.string("ownerIdenaAddress"));
  const testsPassed = payload.boolean("testsPassed");
  const verdict = payload.string("verdict");
  const payloadBond = parseAmount(payload.string("reviewerBondAtoms"));
  const affectedSourceBinding = validateAgentNestedPayload(payload, unresolved, testsPassed);
  assert(isSafeLabel(modelFamily, 64), "invalid model-family label");
  assert(isCanonicalRawCid(payload.string("testResultsCid")), "agent test result must use raw CIDv1/SHA2-256");
  assert(payloadOwner == owner, "agent attestation owner does not match the caller");
  assert(payload.string("parentEcosystemCid") == round.parentCid, "agent attestation parent mismatch");
  assert(payload.string("candidateEcosystemCid") == round.candidateCid, "agent attestation candidate mismatch");
  assert(payload.string("patchCid") == round.patchCid, "agent attestation patch mismatch");
  assert(affectedSourceBinding == round.affectedSourceBinding, "agent attestation source set does not match the verified ecosystem patch");
  assert(payload.string("authentication") == "on-chain-submitter", "unsupported agent attestation authentication");
  assert(parseU64(payload.unsigned("creationBlockOrTimestamp")) <= currentBlock(), "agent attestation is from the future");
  const fields = cid + "|" + modelFamily + "|" + owner + "|" + unresolved.toString();
  const marker = attestationMarker("agent", round.id, cid);
  assert(!hasKey(marker), "duplicate agent attestation");
  const bond = attachedAmount();
  assert(
    bond == payloadBond && bond >= parseAmount(MIN_REVIEWER_BOND_ATOMS),
    "reviewer bond does not match the canonical attestation payload",
  );
  reserveReviewOwnerEntry("agent", round.id, owner);
  addAgentAvailabilityRequirements(round.id, cid, payload);
  reserveStakeSlashSlot(owner);
  appendReviewEntry(round, "agent", fields);
  setString(marker, fields);
  setString(attestationBondKey("agent", round.id, cid), new BondRecord(owner, bond.toString(), false, false).encode());
  if (verdict == "approve" && testsPassed) {
    setString(agentQualifyingKey(round.id, cid), "1");
    if (markUnique("agent-instance", round.id, hashString(owner + "~" + modelFamily))) {
      round.agentCount = checkedU32Add(round.agentCount, 1);
    }
    if (markUnique("agent-model", round.id, hashString(modelFamily))) {
      round.agentModelCount = checkedU32Add(round.agentModelCount, 1);
    }
    if (markUnique("agent-owner", round.id, owner)) {
      round.agentOwnerCount = checkedU32Add(round.agentOwnerCount, 1);
    }
  } else {
    assert(verdict == "approve" || verdict == "reject" || verdict == "abstain", "invalid agent verdict");
  }
  if (unresolved > 0 && markUnique("agent-critical-owner", round.id, owner)) {
    round.unresolvedCriticalCount = checkedU32Add(round.unresolvedCriticalCount, 1);
  }
  saveReviewRound(round);
  emitVersionedEvent("AgentAttestationSubmittedV1", [round.id, cid, owner, modelFamily]);
  return reviewRoundStateJson(round);
}

export function submitBuildAttestation(
  reviewRoundIdPtr: usize,
  attestationCidPtr: usize,
  attestationDagCborHexPtr: usize,
  toolchainDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  const round = loadOpenReviewRound(argumentString(reviewRoundIdPtr, 64));
  const owner = callerHex();
  requireCurrentEligibleMetrics(owner);
  assert(activeStake(owner) >= parseAmount(MIN_ACTIVE_STAKE_ATOMS), "builder must maintain minimum active governance stake");
  const cid = argumentString(attestationCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(cid, argumentString(attestationDagCborHexPtr, 131072));
  payload.requireExactKeys(buildAttestationPayloadKeys());
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "build attestation schema version is unsupported");
  const digest = payload.string("coreArtifactDigest");
  const runtime = payload.string("runtimeFamily");
  const architecture = payload.string("architecture");
  const platform = runtime + "-" + architecture;
  const payloadOwner = canonicalPayloadAddress(payload.string("builderIdentity"));
  const payloadBond = parseAmount(payload.string("builderBondAtoms"));
  const testsPassed = payload.boolean("testsPassed");
  const sourceBinding = validateBuildNestedPayload(payload, digest, testsPassed, round.id);
  const toolchainBinding = validateToolchainManifest(
    verifiedCanonicalDagCborMap(
      payload.string("toolchainCid"),
      argumentString(toolchainDagCborHexPtr, 131072),
    ),
  );
  assert(isCanonicalHash(digest), "artifact digest must be lowercase SHA-256");
  assert(isCanonicalRawCid(payload.string("testResultsCid")), "builder test result must use raw CIDv1/SHA2-256");
  assert(isSafeLabel(runtime, 31) && isSafeLabel(architecture, 31) && isSafeLabel(platform, 64), "invalid platform-family label");
  assert(payloadOwner == owner, "build attestation owner does not match the caller");
  assert(payload.string("candidateEcosystemCid") == round.candidateCid, "build attestation candidate mismatch");
  assert(payload.string("scopeEvidenceCid") == getString(reviewScopeEvidenceKey(round.id)), "build attestation scope evidence mismatch");
  assert(sourceBinding == round.sourceBinding, "build attestation source set does not match the candidate ecosystem");
  assert(toolchainBinding == round.toolchainBinding, "build attestation toolchain does not match the candidate ecosystem");
  assert(payload.string("authentication") == "on-chain-submitter", "unsupported build attestation authentication");
  assert(parseU64(payload.unsigned("creationBlockOrTimestamp")) <= currentBlock(), "build attestation is from the future");
  const fields = cid + "|" + digest + "|" + platform + "|" + owner;
  const marker = attestationMarker("build", round.id, cid);
  assert(!hasKey(marker), "duplicate build attestation");
  const bond = attachedAmount();
  assert(
    bond == payloadBond && bond >= parseAmount(MIN_BUILDER_BOND_ATOMS),
    "builder bond does not match the canonical attestation payload",
  );
  reserveReviewOwnerEntry("build", round.id, owner);
  addBuildAvailabilityRequirements(round.id, cid, payload);
  reserveStakeSlashSlot(owner);
  appendReviewEntry(round, "build", fields);
  setString(marker, fields);
  setString(attestationBondKey("build", round.id, cid), new BondRecord(owner, bond.toString(), false, false).encode());
  if (testsPassed) {
    setString(buildPassingKey(round.id, cid), "1");
    if (markUnique("build-digest", round.id, digest)) {
      const count = storedU32(buildDigestCountKey(round.id));
      assert(count < MAX_COMMITTED_ATTESTATIONS, "build digest group limit reached");
      setString(buildDigestKey(round.id, count), digest);
      setString(buildDigestCountKey(round.id), checkedU32Add(count, 1).toString());
    }
    if (markUnique("build-digest-owner", round.id, hashString(digest + "~" + owner))) {
      incrementStoredU32(buildDigestOwnerCountKey(round.id, digest));
    }
    if (markUnique("build-digest-platform", round.id, hashString(digest + "~" + platform))) {
      incrementStoredU32(buildDigestPlatformCountKey(round.id, digest));
    }
  }
  saveReviewRound(round);
  emitVersionedEvent("BuildAttestationSubmittedV1", [round.id, cid, owner, digest]);
  return reviewRoundStateJson(round);
}

export function submitDataAvailabilityAttestation(
  reviewRoundIdPtr: usize,
  attestationCidPtr: usize,
  attestationDagCborHexPtr: usize,
): usize {
  ensureInitialized();
  const round = loadAvailabilityReviewRound(argumentString(reviewRoundIdPtr, 64));
  const owner = callerHex();
  requireCurrentEligibleMetrics(owner);
  assert(activeStake(owner) >= parseAmount(MIN_ACTIVE_STAKE_ATOMS), "availability operator must maintain minimum active governance stake");
  const cid = argumentString(attestationCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(cid, argumentString(attestationDagCborHexPtr, 131072));
  payload.requireExactKeys(dataAvailabilityPayloadKeys());
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "availability attestation schema version is unsupported");
  const payloadOwner = canonicalPayloadAddress(payload.string("operatorIdentity"));
  const payloadBond = parseAmount(payload.string("bondAtoms"));
  const available = payload.boolean("available");
  const expiresAtBlock = parseU64(payload.unsigned("expiresAtBlock"));
  const verifiedCids = validateAvailabilityNestedPayload(payload, round);
  assert(isCanonicalRawCid(payload.string("probeResultCid")), "availability probe must use raw CIDv1/SHA2-256");
  assert(payloadOwner == owner, "availability attestation owner does not match the caller");
  assert(payload.string("candidateEcosystemCid") == round.candidateCid, "availability attestation candidate mismatch");
  assert(payload.string("authentication") == "on-chain-submitter", "unsupported availability attestation authentication");
  assert(parseU64(payload.unsigned("observedAtBlockOrTimestamp")) <= currentBlock(), "availability attestation is from the future");
  assert(
    expiresAtBlock >= maxReviewExecutionExpiry(round),
    "availability expires before the latest possible execution deadline",
  );
  const pinsetCid = payload.string("pinsetCid");
  const providerId = payload.string("providerId");
  const fields = cid + "|" + round.candidateCid + "|" + pinsetCid + "|" + providerId + "|" + owner;
  const marker = attestationMarker("availability", round.id, cid);
  assert(!hasKey(marker), "duplicate availability attestation");
  const bond = attachedAmount();
  assert(
    bond == payloadBond && bond >= parseAmount(MIN_AVAILABILITY_BOND_ATOMS),
    "availability bond does not match the canonical attestation payload",
  );
  assert(markUnique("availability-provider", round.id, providerId), "availability provider is already represented");
  assert(markUnique("availability-owner", round.id, owner), "availability owner is already represented");
  for (let i = 0; i < verifiedCids.length; i++) {
    setString(availabilityVerifiedCidKey(round.id, cid, verifiedCids[i]), "1");
  }
  setString(availabilityAvailableKey(round.id, cid), available ? "1" : "0");
  setString(availabilityExpiryKey(round.id, cid), expiresAtBlock.toString());
  reserveStakeSlashSlot(owner);
  appendReviewEntry(round, "availability", fields);
  setString(marker, fields);
  setString(attestationBondKey("availability", round.id, cid), new BondRecord(owner, bond.toString(), false, false).encode());
  saveReviewRound(round);
  emitVersionedEvent("DataAvailabilitySubmittedV1", [round.id, cid, owner]);
  return reviewRoundStateJson(round);
}

export function openVoting(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  assert(!isEpochGovernanceEnabled(), "per-proposal voting is disabled by the epoch governance profile");
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_REVIEW_OPEN, "proposal review is not open");
  assert(currentBlock() >= proposal.votingStart && currentBlock() < proposal.votingEnd, "voting window is not open");
  if (proposal.parentCid != getString(CANONICAL_CID_KEY)) {
    settleStale(proposal);
    return proposalStateJson(proposal);
  }
  assert(attestationGatesPass(proposal), "review, build, or data-availability gate is incomplete");
  proposal.state = STATE_VOTING_OPEN;
  saveProposal(proposal);
  emitVersionedEvent("ProposalVotingOpenedV1", [proposal.id, proposal.metricsRoot, proposal.snapshotWeight]);
  return proposalStateJson(proposal);
}

export function castVote(proposalIdPtr: usize, choicePtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  assert(!isEpochGovernanceEnabled(), "per-proposal voting is disabled by the epoch governance profile");
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_VOTING_OPEN, "proposal voting is not open");
  assert(currentBlock() >= proposal.votingStart && currentBlock() < proposal.votingEnd, "voting deadline has elapsed");
  assert(proposal.parentCid == getString(CANONICAL_CID_KEY), "proposal parent is stale");
  const choice = argumentString(choicePtr, 7);
  assert(choice == "yes" || choice == "no" || choice == "abstain", "vote must be yes, no, or abstain");
  const address = callerHex();
  const metrics = loadMetrics(address);
  assert(metrics.root == proposal.metricsRoot && metrics.sourceEpoch == proposal.metricsEpoch, "voter identity proof uses the wrong snapshot");
  assert(metrics.registeredBlock < proposal.creationBlock, "identity proof was registered after the proposal snapshot");
  const stake = stakeAt(address, proposal.stakeEpoch, proposal.creationBlock);
  assert(stake >= parseAmount(MIN_ACTIVE_STAKE_ATOMS), "voter active stake is below the minimum");
  const weight = effectiveVoteWeight(stake, statusBps(metrics.state), metrics.trustBps);
  assert(!weight.isZero(), "voter has zero effective governance weight");
  const receiptKey = voteKey(proposal.id, address);
  if (hasKey(receiptKey)) removeVoteFromTotals(proposal, getString(receiptKey));
  addVoteToTotals(proposal, choice, weight, metrics.state);
  setString(receiptKey, choice + "~" + weight.toString() + "~" + (isStrongState(metrics.state) ? "1" : "0"));
  saveProposal(proposal);
  emitVersionedEvent("VoteCastV1", [proposal.id, address, choice, weight.toString()]);
  return returnString("{\"ok\":true,\"choice\":\"" + choice + "\",\"weight\":\"" + weight.toString() + "\"}");
}

export function finalizeVoting(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  assert(!isEpochGovernanceEnabled(), "per-proposal voting is disabled by the epoch governance profile");
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_VOTING_OPEN, "proposal voting is not open");
  assert(currentBlock() >= proposal.votingEnd, "voting deadline has not elapsed");
  assert(currentBlock() <= proposal.challengeEnd, "voting finalization deadline has elapsed");
  if (proposal.parentCid != getString(CANONICAL_CID_KEY)) {
    settleStale(proposal);
    return proposalStateJson(proposal);
  }
  if (allGatesPass(proposal)) {
    proposal.challengeEnd = checkedBlockAdd(currentBlock(), CHALLENGE_BLOCKS);
    proposal.executeAfter = checkedBlockAdd(proposal.challengeEnd, TIMELOCK_BLOCKS);
    proposal.state = STATE_ACCEPTED_PENDING_CHALLENGE;
    saveProposal(proposal);
    emitVersionedEvent("ProposalChallengePendingV1", [proposal.id, proposal.challengeEnd.toString()]);
  } else {
    settleRejected(proposal, 90);
  }
  return proposalStateJson(proposal);
}

export function submitObjectiveChallenge(
  proposalIdPtr: usize,
  kindPtr: usize,
  attestationCidPtr: usize,
  attestationDagCborHexPtr: usize,
  evidenceCidPtr: usize,
  evidenceHexPtr: usize,
  indexPtr: usize,
  leafCountPtr: usize,
  siblingsPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(
    proposal.state == STATE_ACCEPTED_PENDING_CHALLENGE
      || proposal.state == STATE_ACCEPTED_PENDING_GRACE,
    "proposal is not challengeable",
  );
  assert(currentBlock() < proposal.challengeEnd, "challenge deadline has elapsed");
  const kind = argumentString(kindPtr, 32);
  const cid = argumentString(attestationCidPtr, 128);
  const payload = verifiedCanonicalDagCborMap(cid, argumentString(attestationDagCborHexPtr, 131072));
  const evidenceCid = argumentString(evidenceCidPtr, 128);
  const evidenceHex = argumentString(evidenceHexPtr, 128);
  let valid = false;
  if (kind == "agent_test_result") {
    payload.requireExactKeys(agentAttestationPayloadKeys());
    const modelFamily = payload.string("modelFamily");
    const owner = canonicalPayloadAddress(payload.string("ownerIdenaAddress"));
    const unresolved = parseU32(payload.unsigned("unresolvedCriticalFindings"));
    assert(payload.boolean("testsPassed"), "agent attestation did not claim that tests passed");
    assert(payload.string("testResultsCid") == evidenceCid, "agent result CID does not match challenge evidence");
    assert(payload.string("parentEcosystemCid") == proposal.parentCid, "challenged review parent mismatch");
    assert(payload.string("candidateEcosystemCid") == proposal.candidateCid, "challenged review candidate mismatch");
    assert(payload.string("patchCid") == proposal.patchCid, "challenged review patch mismatch");
    const fields = cid + "|" + modelFamily + "|" + owner + "|" + unresolved.toString();
    assertAttestationProof(proposal.agentRoot, "agent_review_v1", fields, indexPtr, leafCountPtr, siblingsPtr);
    verifiedFalseResult(evidenceCid, evidenceHex, "passed");
    valid = true;
  } else if (kind == "builder_test_result") {
    payload.requireExactKeys(buildAttestationPayloadKeys());
    const digest = payload.string("coreArtifactDigest");
    const runtime = payload.string("runtimeFamily");
    const architecture = payload.string("architecture");
    const platform = runtime + "-" + architecture;
    const owner = canonicalPayloadAddress(payload.string("builderIdentity"));
    assert(payload.boolean("testsPassed"), "builder attestation did not claim that tests passed");
    assert(payload.string("testResultsCid") == evidenceCid, "builder result CID does not match challenge evidence");
    assert(isCanonicalHash(digest) && isSafeLabel(runtime, 31) && isSafeLabel(architecture, 31), "invalid builder challenge evidence");
    assert(payload.string("candidateEcosystemCid") == proposal.candidateCid, "challenged build candidate mismatch");
    assert(payload.string("scopeEvidenceCid") == getString(reviewScopeEvidenceKey(proposal.reviewRoundId)), "challenged build scope evidence mismatch");
    const fields = cid + "|" + digest + "|" + platform + "|" + owner;
    assertAttestationProof(proposal.buildRoot, "build_attestation_v1", fields, indexPtr, leafCountPtr, siblingsPtr);
    verifiedFalseResult(evidenceCid, evidenceHex, "passed");
    valid = true;
  } else if (kind == "availability_probe") {
    payload.requireExactKeys(dataAvailabilityPayloadKeys());
    const owner = canonicalPayloadAddress(payload.string("operatorIdentity"));
    const round = loadReviewRound(proposal.reviewRoundId);
    validateAvailabilityNestedPayload(payload, round);
    assert(payload.boolean("available"), "availability attestation did not claim that content was available");
    assert(payload.string("probeResultCid") == evidenceCid, "availability result CID does not match challenge evidence");
    assert(payload.string("candidateEcosystemCid") == proposal.candidateCid, "challenged availability candidate mismatch");
    const fields = cid + "|" + proposal.candidateCid + "|" + payload.string("pinsetCid")
      + "|" + payload.string("providerId") + "|" + owner;
    assertAttestationProof(proposal.availabilityRoot, "data_availability_v1", fields, indexPtr, leafCountPtr, siblingsPtr);
    verifiedFalseResult(evidenceCid, evidenceHex, "available");
    valid = true;
  } else {
    assert(false, "unsupported objective challenge type");
  }
  assert(valid, "challenge payload does not prove an objective violation");
  const bondKind = kind == "agent_test_result" ? "agent"
    : kind == "availability_probe" ? "availability" : "build";
  assert(
    !hasKey(attestationInvalidKey(bondKind, proposal.reviewRoundId, cid)),
    "challenged attestation is already invalidated",
  );
  setString(challengePreviousStateKey(proposal.id), proposal.state.toString());
  proposal.state = STATE_CHALLENGED;
  proposal.challengeKind = kind;
  proposal.challengeTarget = cid;
  proposal.challengeEvidenceCid = evidenceCid;
  saveProposal(proposal);
  emitVersionedEvent("ObjectiveChallengeAcceptedV1", [proposal.id, kind, cid, evidenceCid]);
  return proposalStateJson(proposal);
}

export function resolveObjectiveChallenge(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_CHALLENGED, "proposal has no accepted objective challenge");
  let bondKind = "build";
  if (proposal.challengeKind == "agent_test_result") bondKind = "agent";
  else if (proposal.challengeKind == "availability_probe") bondKind = "availability";
  const targetKey = attestationBondKey(bondKind, proposal.reviewRoundId, proposal.challengeTarget);
  assert(hasKey(targetKey), "challenged attestation bond is missing");
  const record = BondRecord.decode(getString(targetKey));
  assert(!record.slashed && !record.claimed, "challenged attestation bond is already settled");
  const proposerIsOffender = record.owner == proposal.proposer;
  const targetBond = record.amountValue();
  let targetSlash = targetBond;
  let targetRefund = u128.Zero;
  if (bondKind == "availability") {
    targetSlash = percentage(targetBond, UNAVAILABLE_BOND_SLASH_PERCENT);
    targetRefund = targetBond - targetSlash;
    record.amount = targetRefund.toString();
  } else {
    record.slashed = true;
  }
  setString(targetKey, record.encode());
  setString(attestationInvalidKey(bondKind, proposal.reviewRoundId, proposal.challengeTarget), "1");

  const round = loadReviewRound(proposal.reviewRoundId);
  recomputeAgentAggregates(round);
  selectBuildDigest(round);
  finalizeAvailabilityCoverage(round);
  saveReviewRound(round);
  proposal.agentCount = round.agentCount;
  proposal.agentModelCount = round.agentModelCount;
  proposal.agentOwnerCount = round.agentOwnerCount;
  proposal.unresolvedCriticalCount = round.unresolvedCriticalCount;
  proposal.builderOwnerCount = round.builderOwnerCount;
  proposal.builderPlatformCount = round.builderPlatformCount;
  proposal.builderConflictCount = round.builderConflictCount;
  proposal.availabilityOwnerCount = round.availabilityOwnerCount;
  proposal.artifactDigest = round.artifactDigest;

  const previousStateValue = getString(challengePreviousStateKey(proposal.id));
  assert(previousStateValue.length > 0, "challenged proposal is missing its previous state");
  const previousState = <u8>parseU16(previousStateValue);
  assert(
    previousState == STATE_ACCEPTED_PENDING_CHALLENGE || previousState == STATE_ACCEPTED_PENDING_GRACE,
    "challenged proposal previous state is invalid",
  );
  proposal.state = previousState;
  const remainingGatesPass = isEpochGovernanceEnabled()
    ? epochAttestationGatesPass(proposal)
    : attestationGatesPass(proposal);

  let proposerRefund = u128.Zero;
  let proposerSlash = u128.Zero;
  let proposerStakeSlash = u128.Zero;
  let offenderStakeSlash = u128.Zero;
  if (proposerIsOffender) {
    proposerRefund = percentage(proposal.bondAmount(), 50);
    proposerSlash = proposal.bondAmount() - proposerRefund;
    proposal.refundableBond = proposerRefund.toString();
    proposal.state = STATE_REJECTED;
    proposerStakeSlash = slashGovernanceStake(proposal.proposer);
    setString(proposalSlashReservationConsumedKey(proposal.id), "1");
    releaseStakeSlashSlot(record.owner);
    releaseReviewCandidateForProposal(proposal);
  } else {
    offenderStakeSlash = slashGovernanceStake(record.owner);
    if (remainingGatesPass) {
      proposal.state = previousState;
    } else {
      proposerRefund = proposal.bondAmount();
      proposal.refundableBond = proposerRefund.toString();
      proposal.state = STATE_EXPIRED;
      releaseStakeSlashSlot(proposal.proposer);
      setString(proposalSlashReservationConsumedKey(proposal.id), "1");
      releaseReviewCandidateForProposal(proposal);
    }
  }
  setString(attestationSlashReservationConsumedKey(bondKind, proposal.reviewRoundId, proposal.challengeTarget), "1");
  removeKey(challengePreviousStateKey(proposal.id));
  saveProposal(proposal);
  if (!proposerSlash.isZero()) burn(proposerSlash);
  if (!targetSlash.isZero()) burn(targetSlash);
  if (!proposerStakeSlash.isZero()) burn(proposerStakeSlash);
  if (!offenderStakeSlash.isZero()) burn(offenderStakeSlash);
  emitVersionedEvent(
    "ObjectiveChallengeResolvedV2",
    [
      proposal.id, proposal.challengeKind, proposerSlash.toString(), targetSlash.toString(),
      targetRefund.toString(), proposerStakeSlash.toString(), offenderStakeSlash.toString(),
      remainingGatesPass ? "continued" : "terminal",
    ],
  );
  return proposalStateJson(proposal);
}

export function advanceChallengePeriod(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  assert(!isEpochGovernanceEnabled(), "use enterExecutionReadyState for epoch governance");
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_ACCEPTED_PENDING_CHALLENGE, "proposal is not awaiting challenge completion");
  assert(currentBlock() >= proposal.challengeEnd, "challenge deadline has not elapsed");
  proposal.state = STATE_ACCEPTED_PENDING_EXECUTION;
  saveProposal(proposal);
  emitVersionedEvent("ProposalExecutionTimelockV1", [proposal.id, proposal.executeAfter.toString()]);
  return proposalStateJson(proposal);
}

export function executeProposal(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  ensureCurrentGovernanceEpochAnchored();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_ACCEPTED_PENDING_EXECUTION, "proposal is not executable");
  assert(currentBlock() >= proposal.executeAfter, "execution timelock has not elapsed");
  assert(
    currentBlock() <= checkedBlockAdd(proposal.executeAfter, EXECUTION_WINDOW_BLOCKS),
    "proposal execution window has elapsed",
  );
  const availabilityExpiry = getString(reviewAvailabilityMinimumExpiryKey(proposal.reviewRoundId));
  assert(availabilityExpiry.length > 0, "proposal has no live data-availability coverage");
  assert(
    parseU64(availabilityExpiry) >= currentBlock(),
    "proposal data-availability coverage has elapsed",
  );
  const requiredAvailabilityProviders: u32 = proposal.isCritical() ? 3 : 2;
  assert(
    proposal.availabilityOwnerCount >= requiredAvailabilityProviders,
    "proposal lacks independent data-availability providers",
  );
  if (proposal.parentCid != getString(CANONICAL_CID_KEY)) {
    settleStale(proposal);
    return proposalStateJson(proposal);
  }
  const oldCid = proposal.parentCid;
  setString(CANONICAL_CID_KEY, proposal.candidateCid);
  if (proposal.candidateMetricsRoot.length > 0) {
    setString(METRICS_ROOT_KEY, proposal.candidateMetricsRoot);
    setString(METRICS_EPOCH_KEY, proposal.candidateMetricsEpoch.toString());
    // Preserve both active and scheduled registered weight. Until an identity
    // refreshes its proof, its prior contribution remains in the denominator
    // but cannot vote against the new metrics root. Refreshing replaces the
    // active contribution and rebases any pending activation delta atomically.
  }
  proposal.state = STATE_EXECUTED;
  proposal.refundableBond = proposal.bond;
  recordEpochExecution(proposal, oldCid);
  releaseReviewCandidateForProposal(proposal);
  saveProposal(proposal);
  emitVersionedEvent(
    "CanonicalEcosystemUpdatedV1",
    [oldCid, proposal.candidateCid, proposal.id, proposal.agentRoot, proposal.buildRoot, proposal.availabilityRoot],
  );
  return proposalStateJson(proposal);
}

export function executeRevert(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposalId = validProposalId(argumentString(proposalIdPtr, 64));
  assert(isBoundRevertProposal(proposalId), "proposal is not bound to a historical execution");
  return executeProposal(proposalIdPtr);
}

export function expireProposal(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  const expiredDraft = proposal.state == STATE_DRAFT && currentBlock() > proposal.draftExpiry;
  const expiredReview = proposal.state == STATE_REVIEW_OPEN && currentBlock() >= proposal.votingEnd;
  const expiredExecution = proposal.state == STATE_ACCEPTED_PENDING_EXECUTION
    && currentBlock() > checkedBlockAdd(proposal.executeAfter, EXECUTION_WINDOW_BLOCKS);
  const expiredGrace = proposal.state == STATE_ACCEPTED_PENDING_GRACE
    && currentBlock() > checkedBlockAdd(proposal.executeAfter, EXECUTION_WINDOW_BLOCKS);
  assert(expiredDraft || expiredReview || expiredExecution || expiredGrace, "proposal is not expired");
  const refund = percentage(proposal.bondAmount(), 75);
  const slash = proposal.bondAmount() - refund;
  proposal.state = STATE_EXPIRED;
  proposal.refundableBond = refund.toString();
  releaseReviewCandidateForProposal(proposal);
  saveProposal(proposal);
  if (!slash.isZero()) burn(slash);
  emitVersionedEvent("ProposalExpiredV1", [proposal.id, refund.toString(), slash.toString()]);
  return proposalStateJson(proposal);
}

export function withdrawRefundableBond(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  const address = callerHex();
  assert(proposal.proposer == address, "only the proposer may withdraw its refundable proposal bond");
  assert(isTerminalState(proposal.state), "proposal bond remains locked");
  assert(!proposal.bondClaimed, "proposal bond was already withdrawn");
  const amount = proposal.refundableBondAmount();
  assert(!amount.isZero(), "proposal has no refundable bond");
  proposal.bondClaimed = true;
  saveProposal(proposal);
  if (!hasKey(proposalSlashReservationConsumedKey(proposal.id))) {
    releaseStakeSlashSlot(address);
  }
  emitVersionedEvent("ProposalBondWithdrawnV1", [proposal.id, address, amount.toString()]);
  transfer(hexToBytes(address), amount);
  return okJson("amount", amount.toString());
}

export function claimAcceptedProposalBond(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(
    proposal.state == STATE_EXECUTED || proposal.state == STATE_REVERTED,
    "accepted proposal has not executed",
  );
  return withdrawRefundableBond(proposalIdPtr);
}

export function claimNoQuorumRefund(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_NO_QUORUM, "proposal did not end without quorum");
  return withdrawRefundableBond(proposalIdPtr);
}

export function withdrawAttestationBond(
  proposalIdPtr: usize,
  kindPtr: usize,
  attestationCidPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const proposal = loadProposal(validProposalId(argumentString(proposalIdPtr, 64)));
  assert(isTerminalState(proposal.state), "attestation bond remains locked");
  const kind = argumentString(kindPtr, 16);
  assert(kind == "agent" || kind == "build" || kind == "availability", "unknown attestation bond kind");
  const cid = argumentString(attestationCidPtr, 128);
  const key = attestationBondKey(kind, proposal.reviewRoundId, cid);
  const record = BondRecord.decode(getString(key));
  const address = callerHex();
  assert(record.owner == address, "only the bonded attestor may withdraw");
  assert(!record.slashed && !record.claimed, "attestation bond is slashed or already withdrawn");
  record.claimed = true;
  setString(key, record.encode());
  if (!hasKey(attestationSlashReservationConsumedKey(kind, proposal.reviewRoundId, cid))) {
    releaseStakeSlashSlot(address);
  }
  const amount = record.amountValue();
  emitVersionedEvent("AttestationBondWithdrawnV1", [proposal.id, kind, cid, address, amount.toString()]);
  transfer(hexToBytes(address), amount);
  return okJson("amount", amount.toString());
}

export function canonicalEcosystemCid(): usize {
  ensureInitialized();
  requireNoPayment();
  return okJson("canonicalEcosystemCid", getString(CANONICAL_CID_KEY));
}

export function governanceParameterSetCid(): usize {
  ensureInitialized();
  requireNoPayment();
  return okJson("governanceParameterSetCid", getString(PARAMETER_CID_KEY));
}

export function proposalState(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  return proposalStateJson(loadProposal(validProposalId(argumentString(proposalIdPtr, 64))));
}

export function voterReceipt(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const id = validProposalId(argumentString(proposalIdPtr, 64));
  const value = getString(voteKey(id, callerHex()));
  if (value.length == 0) return returnString("{\"found\":false}");
  const f = value.split("~");
  assert(f.length == 3, "corrupt voter receipt");
  return returnString("{\"found\":true,\"choice\":\"" + f[0] + "\",\"weight\":\"" + f[1] + "\"}");
}

export function governanceStakeState(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  return returnString(
    "{\"active\":\"" + activeStake(address).toString()
      + "\",\"pending\":\"" + getString(pendingStakeKey(address))
      + "\",\"withdrawal\":\"" + getString(withdrawalKey(address))
      + "\",\"slashReservations\":" + stakeSlashReservationCount(address).toString() + "}",
  );
}

export function governanceParameters(): usize {
  ensureInitialized();
  requireNoPayment();
  return returnString(
    "{\"schemaVersion\":1,\"contractVersion\":\"" + CONTRACT_VERSION
      + "\",\"parameterSetCid\":\"" + EXPECTED_PARAMETER_CID
      + "\",\"stakeQuantumAtoms\":\"1000000000000\",\"minimumActiveStakeAtoms\":\""
      + MIN_ACTIVE_STAKE_ATOMS + "\",\"statusBps\":{\"Human\":10000,\"Verified\":8500,\"Newbie\":7000}"
      + ",\"normal\":{\"quorumBps\":2000,\"yesBps\":6667,\"yesIdentities\":7,\"strongIdentities\":3}"
      + ",\"critical\":{\"quorumBps\":3000,\"yesBps\":7500,\"yesIdentities\":12,\"strongIdentities\":5}"
      + ",\"periodBlocks\":{\"review\":40,\"voting\":120,\"challenge\":60,\"timelock\":60,\"execution\":600}"
      + ",\"minimumIdentityMetricsAttestations\":3"
      + ",\"objectiveSlashBps\":{\"proposal\":5000,\"reviewer\":10000,\"builder\":10000,\"availability\":5000,\"actorStake\":500}"
      + ",\"unbondingEpochs\":4}",
  );
}

function ensureInitialized(): void {
  assert(hasKey(INITIALIZED_KEY), "contract is not initialized");
}

function activateStakeFor(address: string): bool {
  ensureCurrentGovernanceEpochAnchored();
  syncGlobalWeightEpoch();
  const key = pendingStakeKey(address);
  if (!hasKey(key)) return false;
  const pending = getString(key).split("~");
  assert(pending.length == 4, "corrupt pending stake record");
  const activationEpoch = parseU16(pending[1]);
  if (currentEpoch() < activationEpoch) return false;
  const amount = parseAmount(pending[0]);
  const oldStake = activeStake(address);
  const newStake = oldStake + amount;
  setString(activeStakeKey(address), newStake.toString());
  removeKey(key);
  emitVersionedEvent("GovernanceStakeActivatedV1", [address, amount.toString(), activationEpoch.toString()]);
  return true;
}

function appendStakeLot(address: string, amount: u128, activationEpoch: u16): void {
  const count = storedHistoryCount(stakeLotCountKey(address));
  assert(count < MAX_STAKE_HISTORY, "stake lot history limit reached");
  setString(
    stakeLotKey(address, count),
    amount.toString() + "~" + activationEpoch.toString() + "~" + currentBlock().toString(),
  );
  setString(stakeLotCountKey(address), (count + 1).toString());
}

function appendWithdrawalCheckpoint(address: string, amount: u128, consumeReservedSlot: bool): void {
  const count = storedHistoryCount(withdrawalCheckpointCountKey(address));
  const reserved = stakeSlashReservationCount(address);
  if (consumeReservedSlot) {
    assert(reserved > 0 && count < MAX_STAKE_HISTORY, "stake-slash checkpoint reservation is missing");
  } else {
    assert(count + reserved < MAX_STAKE_HISTORY, "withdrawal history capacity is reserved for slashable bonds");
  }
  setString(
    withdrawalCheckpointKey(address, count),
    amount.toString() + "~" + currentBlock().toString(),
  );
  setString(withdrawalCheckpointCountKey(address), (count + 1).toString());
  if (consumeReservedSlot) setStakeSlashReservationCount(address, reserved - 1);
}

function reserveStakeSlashSlot(address: string): void {
  const count = storedHistoryCount(withdrawalCheckpointCountKey(address));
  const reserved = stakeSlashReservationCount(address);
  assert(count + reserved < MAX_STAKE_HISTORY, "stake history has no capacity for a slashable bond");
  setStakeSlashReservationCount(address, reserved + 1);
}

function releaseStakeSlashSlot(address: string): void {
  const reserved = stakeSlashReservationCount(address);
  assert(reserved > 0, "stake-slash reservation underflow");
  setStakeSlashReservationCount(address, reserved - 1);
}

function slashGovernanceStake(address: string): u128 {
  ensureCurrentGovernanceEpochAnchored();
  activateStakeFor(address);
  const oldStake = activeStake(address);
  const slash = percentage(oldStake, FRAUDULENT_ACTOR_STAKE_SLASH_PERCENT);
  if (slash.isZero()) {
    releaseStakeSlashSlot(address);
    return u128.Zero;
  }
  const oldWeight = recordedWeight(address, oldStake);
  appendWithdrawalCheckpoint(address, slash, true);
  const newStake = oldStake - slash;
  setString(activeStakeKey(address), newStake.toString());
  const newWeight = recordedWeight(address, newStake);
  replaceGlobalWeight(oldWeight, newWeight);
  refreshPendingStakeWeight(address, loadMetrics(address), newStake, newWeight);
  const withdrawal = withdrawalKey(address);
  if (hasKey(withdrawal)) {
    const fields = getString(withdrawal).split("~");
    assert(fields.length == 3, "corrupt scheduled withdrawal record");
    const scheduled = parseAmount(fields[0]);
    if (scheduled > newStake) {
      if (newStake.isZero()) removeKey(withdrawal);
      else setString(withdrawal, newStake.toString() + "~" + fields[1] + "~" + fields[2]);
    }
  }
  emitVersionedEvent("GovernanceStakeSlashedV1", [address, slash.toString(), newStake.toString()]);
  return slash;
}

function stakeAt(address: string, snapshotEpoch: u16, snapshotBlock: u64): u128 {
  let total = u128.Zero;
  const lotCount = storedHistoryCount(stakeLotCountKey(address));
  for (let i = 0; i < lotCount; i++) {
    const lot = getString(stakeLotKey(address, i)).split("~");
    assert(lot.length == 3, "corrupt immutable stake lot");
    const epoch = parseU16(lot[1]);
    if (epoch > snapshotEpoch) continue;
    if (parseU64(lot[2]) < snapshotBlock) total += parseAmount(lot[0]);
  }
  let withdrawn = u128.Zero;
  const withdrawalCount = storedHistoryCount(withdrawalCheckpointCountKey(address));
  for (let i = 0; i < withdrawalCount; i++) {
    const checkpoint = getString(withdrawalCheckpointKey(address, i)).split("~");
    assert(checkpoint.length == 2, "corrupt immutable withdrawal checkpoint");
    if (parseU64(checkpoint[1]) < snapshotBlock) withdrawn += parseAmount(checkpoint[0]);
  }
  assert(total >= withdrawn, "withdrawal history exceeds deposited stake history");
  return total - withdrawn;
}

function registeredWeight(address: string, stake: u128): u128 {
  const key = metricsKey(address);
  if (!hasKey(key)) return u128.Zero;
  const metrics = MetricsRecord.decode(getString(key));
  if (metrics.root != getString(METRICS_ROOT_KEY) || metrics.sourceEpoch != parseStoredU16(METRICS_EPOCH_KEY)) return u128.Zero;
  return weightForMetrics(stake, metrics.state, metrics.trustBps);
}

function recordedWeight(address: string, stake: u128): u128 {
  const key = metricsKey(address);
  if (!hasKey(key)) return u128.Zero;
  const metrics = MetricsRecord.decode(getString(key));
  return weightForMetrics(stake, metrics.state, metrics.trustBps);
}

function weightForMetrics(stake: u128, state: string, trust: u16): u128 {
  if (stake < parseAmount(MIN_ACTIVE_STAKE_ATOMS)) return u128.Zero;
  return effectiveVoteWeight(stake, statusBps(state), trust);
}

function refreshPendingStakeWeight(
  address: string,
  metrics: MetricsRecord,
  active: u128,
  activeWeight: u128,
): void {
  const key = pendingStakeKey(address);
  if (!hasKey(key)) return;
  const pending = getString(key).split("~");
  assert(pending.length == 4, "corrupt pending stake record");
  const amount = parseAmount(pending[0]);
  const activationEpoch = parseU16(pending[1]);
  assert(activationEpoch > currentEpoch(), "matured pending stake was not activated before metrics refresh");
  const oldDelta = parseAmount(pending[3]);
  const projectedStake = active + amount;
  assert(projectedStake >= active, "pending stake projection overflow");
  const projectedWeight = weightForMetrics(projectedStake, metrics.state, metrics.trustBps);
  assert(projectedWeight >= activeWeight, "metrics refresh would create a negative pending weight delta");
  const newDelta = projectedWeight - activeWeight;
  replaceScheduledWeightDelta(activationEpoch, oldDelta, newDelta);
  setString(
    key,
    amount.toString() + "~" + activationEpoch.toString() + "~" + metrics.root + "~" + newDelta.toString(),
  );
}

function requireCurrentEligibleMetrics(address: string): MetricsRecord {
  const metrics = loadMetrics(address);
  assert(metrics.root == getString(METRICS_ROOT_KEY), "identity metrics proof is stale");
  assert(metrics.sourceEpoch == parseStoredU16(METRICS_EPOCH_KEY), "identity metrics epoch is stale");
  assert(statusBps(metrics.state) > 0, "identity state is not governance-eligible");
  return metrics;
}

function loadMetrics(address: string): MetricsRecord {
  const value = getString(metricsKey(address));
  assert(value.length > 0, "identity metrics proof is not registered");
  return MetricsRecord.decode(value);
}

function loadOpenReviewRound(idValue: string): ReviewRound {
  const round = loadReviewRound(validReviewRoundId(idValue));
  assert(round.state == REVIEW_ROUND_OPEN, "review round is not open");
  assert(currentBlock() < round.endBlock, "review round submission deadline has elapsed");
  assert(round.parentCid == getString(CANONICAL_CID_KEY), "review round parent is stale");
  return round;
}

function loadAvailabilityReviewRound(idValue: string): ReviewRound {
  const round = loadReviewRound(validReviewRoundId(idValue));
  assert(round.state == REVIEW_ROUND_AVAILABILITY_OPEN, "review evidence must be frozen before availability attestation");
  assert(currentBlock() <= round.claimDeadline, "review round claim deadline has elapsed");
  assert(round.parentCid == getString(CANONICAL_CID_KEY), "review round parent is stale");
  return round;
}

function assertAttestationProof(
  root: string,
  domain: string,
  fields: string,
  indexPtr: usize,
  leafCountPtr: usize,
  siblingsPtr: usize,
): u32 {
  const index = parseU64(argumentString(indexPtr, 20));
  const count = parseU64(argumentString(leafCountPtr, 20));
  assert(count <= <u64>MAX_COMMITTED_ATTESTATIONS, "attestation commitment exceeds the bounded leaf limit");
  const siblings = optionalArgumentString(siblingsPtr, 8192);
  assert(verifyAttestationCommitment(domain, fields, index, count, siblings, root), "attestation is not committed by the proposal root");
  return <u32>count;
}

function appendReviewEntry(round: ReviewRound, kind: string, fields: string): void {
  assert(fields.length > 0 && fields.length <= 2048, "invalid canonical attestation fields");
  let index: u32 = 0;
  if (kind == "agent") {
    index = round.agentLeafCount;
    round.agentLeafCount = checkedU32Add(round.agentLeafCount, 1);
  } else if (kind == "build") {
    index = round.buildLeafCount;
    round.buildLeafCount = checkedU32Add(round.buildLeafCount, 1);
  } else {
    assert(kind == "availability", "unknown attestation kind");
    index = round.availabilityLeafCount;
    round.availabilityLeafCount = checkedU32Add(round.availabilityLeafCount, 1);
  }
  assert(index < MAX_COMMITTED_ATTESTATIONS, "review round attestation limit reached");
  setString(reviewEntryKey(kind, round.id, index), fields);
}

function reserveReviewOwnerEntry(kind: string, reviewRoundId: string, owner: string): void {
  assert(kind == "agent" || kind == "build", "unsupported owner-cap evidence class");
  const key = reviewOwnerEntryCountKey(kind, reviewRoundId, owner);
  const count = storedU32(key);
  assert(count < MAX_ATTESTATIONS_PER_OWNER_PER_CLASS, "review owner attestation limit reached");
  setString(key, checkedU32Add(count, 1).toString());
}

function addAvailabilityRequirement(reviewRoundId: string, cid: string): void {
  assert(isCanonicalContentCid(cid), "availability requirement must use canonical CIDv1/SHA2-256");
  const marker = availabilityRequirementMemberKey(reviewRoundId, cid);
  if (hasKey(marker)) return;
  const count = storedU32(availabilityRequirementCountKey(reviewRoundId));
  assert(count < MAX_REQUIRED_AVAILABILITY_CIDS, "availability requirement limit reached");
  setString(availabilityRequirementKey(reviewRoundId, count), cid);
  setString(availabilityRequirementCountKey(reviewRoundId), checkedU32Add(count, 1).toString());
  setString(marker, "1");
}

function addAgentAvailabilityRequirements(
  reviewRoundId: string,
  attestationCid: string,
  payload: CanonicalDagCborMap,
): void {
  addAvailabilityRequirement(reviewRoundId, attestationCid);
  addAvailabilityRequirement(reviewRoundId, payload.string("agentPolicyCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("systemPromptPolicyCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("testResultsCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("staticAnalysisResultsCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("dependencyFindingsCid"));
  const findings = payload.objectArray("securityFindings");
  for (let i = 0; i < findings.length; i++) {
    if (!findings[i].isNull("evidenceCid")) {
      addAvailabilityRequirement(reviewRoundId, findings[i].string("evidenceCid"));
    }
  }
}

function addBuildAvailabilityRequirements(
  reviewRoundId: string,
  attestationCid: string,
  payload: CanonicalDagCborMap,
): void {
  addAvailabilityRequirement(reviewRoundId, attestationCid);
  addAvailabilityRequirement(reviewRoundId, payload.string("toolchainCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("testResultsCid"));
  addAvailabilityRequirement(reviewRoundId, payload.string("sbomCid"));
  const artifacts = payload.objectArray("artifacts");
  for (let i = 0; i < artifacts.length; i++) {
    addAvailabilityRequirement(reviewRoundId, artifacts[i].string("cid"));
  }
}

function finalizeAvailabilityCoverage(round: ReviewRound): void {
  const requiredCount = storedU32(availabilityRequirementCountKey(round.id));
  assert(
    requiredCount >= round.pinsetCount && requiredCount <= MAX_REQUIRED_AVAILABILITY_CIDS,
    "availability requirement set is invalid",
  );
  let owners: u32 = 0;
  let minimumExpiry: u64 = u64.MAX_VALUE;
  for (let i: u32 = 0; i < round.availabilityLeafCount; i++) {
    const fields = getString(reviewEntryKey("availability", round.id, i)).split("|");
    assert(fields.length == 5, "corrupt availability attestation fields");
    const attestationCid = fields[0];
    if (hasKey(attestationInvalidKey("availability", round.id, attestationCid))) continue;
    if (getString(availabilityAvailableKey(round.id, attestationCid)) != "1") continue;
    let complete = true;
    for (let requiredIndex: u32 = 0; requiredIndex < requiredCount; requiredIndex++) {
      const requiredCid = getString(availabilityRequirementKey(round.id, requiredIndex));
      assert(requiredCid.length > 0, "availability requirement entry is missing");
      if (!hasKey(availabilityVerifiedCidKey(round.id, attestationCid, requiredCid))) {
        complete = false;
        break;
      }
    }
    if (complete) {
      owners = checkedU32Add(owners, 1);
      const expiry = parseU64(getString(availabilityExpiryKey(round.id, attestationCid)));
      if (expiry < minimumExpiry) minimumExpiry = expiry;
    }
  }
  round.availabilityOwnerCount = owners;
  const expiryKey = reviewAvailabilityMinimumExpiryKey(round.id);
  if (minimumExpiry == u64.MAX_VALUE) removeKey(expiryKey);
  else setString(expiryKey, minimumExpiry.toString());
}

function loadReviewEntries(kind: string, reviewRoundId: string, count: u32): string[] {
  assert(count > 0 && count <= MAX_COMMITTED_ATTESTATIONS, "invalid review entry count");
  const entries = new Array<string>();
  for (let i: u32 = 0; i < count; i++) {
    const fields = getString(reviewEntryKey(kind, reviewRoundId, i));
    assert(fields.length > 0, "review round evidence entry is missing");
    entries.push(fields);
  }
  return entries;
}

function recomputeAgentAggregates(round: ReviewRound): void {
  const instances = new Array<string>();
  const models = new Array<string>();
  const owners = new Array<string>();
  const criticalOwners = new Array<string>();
  for (let i: u32 = 0; i < round.agentLeafCount; i++) {
    const fields = getString(reviewEntryKey("agent", round.id, i)).split("|");
    assert(fields.length == 4, "corrupt agent attestation fields");
    const cid = fields[0];
    if (hasKey(attestationInvalidKey("agent", round.id, cid))) continue;
    const model = fields[1];
    const owner = fields[2];
    const unresolved = parseU32(fields[3]);
    if (hasKey(agentQualifyingKey(round.id, cid))) {
      pushUnique(instances, owner + "~" + model);
      pushUnique(models, model);
      pushUnique(owners, owner);
    }
    if (unresolved > 0) pushUnique(criticalOwners, owner);
  }
  round.agentCount = <u32>instances.length;
  round.agentModelCount = <u32>models.length;
  round.agentOwnerCount = <u32>owners.length;
  round.unresolvedCriticalCount = <u32>criticalOwners.length;
}

function selectBuildDigest(round: ReviewRound): void {
  const digests = new Array<string>();
  const ownerPairs = new Array<string>();
  const platformPairs = new Array<string>();
  for (let i: u32 = 0; i < round.buildLeafCount; i++) {
    const fields = getString(reviewEntryKey("build", round.id, i)).split("|");
    assert(fields.length == 4, "corrupt build attestation fields");
    const cid = fields[0];
    if (hasKey(attestationInvalidKey("build", round.id, cid)) || !hasKey(buildPassingKey(round.id, cid))) continue;
    const digest = fields[1];
    pushUnique(digests, digest);
    pushUnique(ownerPairs, digest + "~" + fields[3]);
    pushUnique(platformPairs, digest + "~" + fields[2]);
  }
  assert(digests.length > 0, "review round has no passing build digest group");
  let bestDigest = "";
  let bestOwners: u32 = 0;
  let bestPlatforms: u32 = 0;
  for (let i = 0; i < digests.length; i++) {
    const digest = digests[i];
    assert(isCanonicalHash(digest), "corrupt build digest group");
    const owners = countPrefixed(ownerPairs, digest + "~");
    const platforms = countPrefixed(platformPairs, digest + "~");
    if (
      bestDigest.length == 0
      || owners > bestOwners
      || (owners == bestOwners && platforms > bestPlatforms)
      || (owners == bestOwners && platforms == bestPlatforms && digest < bestDigest)
    ) {
      bestDigest = digest;
      bestOwners = owners;
      bestPlatforms = platforms;
    }
  }
  round.artifactDigest = bestDigest;
  round.builderOwnerCount = bestOwners;
  round.builderPlatformCount = bestPlatforms;
  round.builderConflictCount = <u32>(digests.length - 1);
}

function pushUnique(values: string[], value: string): void {
  for (let i = 0; i < values.length; i++) {
    if (values[i] == value) return;
  }
  values.push(value);
}

function countPrefixed(values: string[], prefix: string): u32 {
  let count: u32 = 0;
  for (let i = 0; i < values.length; i++) {
    if (values[i].startsWith(prefix)) count = checkedU32Add(count, 1);
  }
  return count;
}

function attestationGatesPass(proposal: Proposal): bool {
  const agentMin: u32 = proposal.isCritical() ? 5 : 3;
  const modelMin: u32 = proposal.isCritical() ? 3 : 2;
  const ownerMin: u32 = proposal.isCritical() ? 3 : 2;
  const builderMin: u32 = proposal.isCritical() ? 3 : 2;
  const platformMin: u32 = proposal.isCritical() ? 2 : 1;
  const availabilityMin: u32 = proposal.isCritical() ? 3 : 2;
  const criticalFindingOwnerThreshold: u32 = proposal.isCritical() ? 3 : 2;
  const criticalResolved = proposal.unresolvedCriticalCount < criticalFindingOwnerThreshold
    || proposal.waiverCid.length > 0;
  const minimumExpiryValue = getString(reviewAvailabilityMinimumExpiryKey(proposal.reviewRoundId));
  const requiredAvailabilityUntil = checkedBlockAdd(proposal.executeAfter, EXECUTION_WINDOW_BLOCKS);
  return proposal.agentLeafCount > 0
    && proposal.agentSubmittedCount == proposal.agentLeafCount
    && proposal.buildLeafCount > 0
    && proposal.buildSubmittedCount == proposal.buildLeafCount
    && proposal.availabilityLeafCount > 0
    && proposal.availabilitySubmittedCount == proposal.availabilityLeafCount
    && proposal.agentCount >= agentMin
    && proposal.agentModelCount >= modelMin
    && proposal.agentOwnerCount >= ownerMin
    && criticalResolved
    && proposal.builderOwnerCount >= builderMin
    && proposal.builderPlatformCount >= platformMin
    && proposal.artifactDigest.length == 64
    && proposal.availabilityOwnerCount >= availabilityMin
    && minimumExpiryValue.length > 0
    && parseU64(minimumExpiryValue) >= requiredAvailabilityUntil;
}

function allGatesPass(proposal: Proposal): bool {
  if (!attestationGatesPass(proposal)) return false;
  const yes = proposal.yesWeightAmount();
  const no = proposal.noWeightAmount();
  const abstain = proposal.abstainWeightAmount();
  const turnout = yes + no + abstain;
  const decisive = yes + no;
  const quorum = proposal.isCritical() ? CRITICAL_QUORUM_BPS : NORMAL_QUORUM_BPS;
  const yesThreshold = proposal.isCritical() ? CRITICAL_YES_BPS : NORMAL_YES_BPS;
  if (!ratioAtLeast(turnout, proposal.snapshotWeightAmount(), quorum)) return false;
  if (!ratioAtLeast(yes, decisive, yesThreshold)) return false;
  const breadth: u32 = proposal.isCritical() ? 12 : 7;
  const strongBreadth: u32 = proposal.isCritical() ? 5 : 3;
  return proposal.yesIdentities >= breadth && proposal.yesStrongIdentities >= strongBreadth;
}

function addVoteToTotals(proposal: Proposal, choice: string, weight: u128, state: string): void {
  if (choice == "yes") {
    proposal.yesWeight = (proposal.yesWeightAmount() + weight).toString();
    proposal.yesIdentities = checkedU32Add(proposal.yesIdentities, 1);
    if (isStrongState(state)) {
      proposal.yesStrongIdentities = checkedU32Add(proposal.yesStrongIdentities, 1);
    }
  } else if (choice == "no") {
    proposal.noWeight = (proposal.noWeightAmount() + weight).toString();
  } else {
    proposal.abstainWeight = (proposal.abstainWeightAmount() + weight).toString();
  }
}

function removeVoteFromTotals(proposal: Proposal, receipt: string): void {
  const fields = receipt.split("~");
  assert(fields.length == 3, "corrupt voter receipt");
  assert(fields[0] == "yes" || fields[0] == "no" || fields[0] == "abstain", "corrupt vote choice");
  assert(fields[2] == "0" || fields[2] == "1", "corrupt vote strength flag");
  const weight = parseAmount(fields[1]);
  if (fields[0] == "yes") {
    proposal.yesWeight = (proposal.yesWeightAmount() - weight).toString();
    assert(proposal.yesIdentities > 0, "yes breadth underflow");
    proposal.yesIdentities--;
    if (fields[2] == "1") {
      assert(proposal.yesStrongIdentities > 0, "strong yes breadth underflow");
      proposal.yesStrongIdentities--;
    }
  } else if (fields[0] == "no") {
    proposal.noWeight = (proposal.noWeightAmount() - weight).toString();
  } else {
    proposal.abstainWeight = (proposal.abstainWeightAmount() - weight).toString();
  }
}

function settleRejected(proposal: Proposal, refundPercent: u8): void {
  const refund = percentage(proposal.bondAmount(), refundPercent);
  const fee = proposal.bondAmount() - refund;
  proposal.state = STATE_REJECTED;
  proposal.refundableBond = refund.toString();
  releaseReviewCandidateForProposal(proposal);
  saveProposal(proposal);
  if (!fee.isZero()) burn(fee);
  emitVersionedEvent("ProposalRejectedV1", [proposal.id, refund.toString(), fee.toString()]);
}

function settleStale(proposal: Proposal): void {
  const feeLimit = parseAmount(STALE_PROCESSING_FEE_ATOMS);
  const fee = proposal.bondAmount() < feeLimit ? proposal.bondAmount() : feeLimit;
  proposal.state = STATE_STALE;
  proposal.refundableBond = (proposal.bondAmount() - fee).toString();
  releaseReviewCandidateForProposal(proposal);
  saveProposal(proposal);
  if (!fee.isZero()) burn(fee);
  emitVersionedEvent("ProposalStaleV1", [proposal.id, proposal.parentCid, getString(CANONICAL_CID_KEY), fee.toString()]);
}

function percentage(value: u128, percent: u8): u128 {
  assert(percent <= 100, "invalid percentage");
  const hundred = u128.fromU64(100);
  const quotient = value / hundred;
  const remainder = value % hundred;
  return quotient * u128.fromU64(percent) + (remainder * u128.fromU64(percent)) / hundred;
}

function metricsCertificationJson(root: string, epoch: u16): usize {
  const finalizedKey = metricsCertificationFinalizedDescriptorKey(root, epoch);
  const descriptorHash = getString(finalizedKey);
  const descriptorKey = descriptorHash.length == 0
    ? ""
    : metricsCertificationDescriptorKey(root, epoch, descriptorHash);
  const count = metricsCertificationCount(root, epoch);
  return returnString(
    "{\"metricsRoot\":\"" + root + "\",\"sourceEpoch\":" + epoch.toString()
      + ",\"attestations\":" + count.toString()
      + ",\"minimumRequired\":" + MIN_IDENTITY_METRICS_ATTESTATIONS.toString()
      + ",\"certified\":" + (count >= MIN_IDENTITY_METRICS_ATTESTATIONS ? "true" : "false")
      + ",\"conflict\":false"
      + ",\"descriptorHash\":" + (descriptorHash.length > 0 ? "\"" + descriptorHash + "\"" : "null")
      + ",\"descriptor\":" + (descriptorKey.length > 0 ? "\"" + getString(descriptorKey) + "\"" : "null") + "}",
  );
}

function reviewRoundStateJson(round: ReviewRound): usize {
  return returnString(
    "{\"schemaVersion\":1,\"reviewRoundId\":\"" + round.id + "\",\"state\":\"" + reviewRoundStateName(round.state)
      + "\",\"parentCid\":\"" + round.parentCid + "\",\"candidateCid\":\"" + round.candidateCid
      + "\",\"patchCid\":\"" + round.patchCid + "\",\"opener\":\"0x" + round.opener
      + "\",\"scopeEvidenceCid\":\"" + getString(reviewScopeEvidenceKey(round.id))
      + "\",\"pinsetCid\":\"" + round.pinsetCid + "\",\"pinsetCount\":" + round.pinsetCount.toString()
      + ",\"openedBlock\":" + round.openedBlock.toString() + ",\"endBlock\":" + round.endBlock.toString()
      + ",\"claimDeadline\":" + round.claimDeadline.toString() + ",\"proposalId\":"
      + (round.proposalId.length > 0 ? "\"" + round.proposalId + "\"" : "null")
      + ",\"agentReviewRoot\":" + (round.agentRoot.length > 0 ? "\"" + round.agentRoot + "\"" : "null")
      + ",\"buildAttestationRoot\":" + (round.buildRoot.length > 0 ? "\"" + round.buildRoot + "\"" : "null")
      + ",\"dataAvailabilityRoot\":" + (round.availabilityRoot.length > 0 ? "\"" + round.availabilityRoot + "\"" : "null")
      + ",\"reviewAttestations\":" + round.agentLeafCount.toString()
      + ",\"buildAttestations\":" + round.buildLeafCount.toString()
      + ",\"availabilityAttestations\":" + round.availabilityLeafCount.toString()
      + ",\"validReviews\":" + round.agentCount.toString()
      + ",\"reviewModelFamilies\":" + round.agentModelCount.toString()
      + ",\"reviewOwners\":" + round.agentOwnerCount.toString()
      + ",\"unresolvedCriticalFindings\":" + round.unresolvedCriticalCount.toString()
      + ",\"builders\":" + round.builderOwnerCount.toString()
      + ",\"builderPlatforms\":" + round.builderPlatformCount.toString()
      + ",\"builderConflicts\":" + round.builderConflictCount.toString()
      + ",\"availabilityOwners\":" + round.availabilityOwnerCount.toString()
      + ",\"artifactDigest\":" + (round.artifactDigest.length > 0 ? "\"" + round.artifactDigest + "\"" : "null")
      + ",\"bond\":\"" + round.bond + "\",\"refundableBond\":\"" + round.refundableBond + "\"}",
  );
}

function reviewRoundStateName(state: u8): string {
  if (state == REVIEW_ROUND_OPEN) return "Open";
  if (state == REVIEW_ROUND_AVAILABILITY_OPEN) return "AvailabilityOpen";
  if (state == REVIEW_ROUND_FROZEN) return "Frozen";
  if (state == REVIEW_ROUND_CLAIMED) return "Claimed";
  if (state == REVIEW_ROUND_EXPIRED) return "Expired";
  return "Unknown";
}

function proposalStateJson(proposal: Proposal): usize {
  return returnString(
    "{\"proposalId\":\"" + proposal.id + "\",\"state\":\"" + stateName(proposal.state)
      + "\",\"proposalCid\":\"" + proposal.proposalCid + "\",\"reviewRoundId\":\"" + proposal.reviewRoundId
      + "\",\"parentCid\":\"" + proposal.parentCid
      + "\",\"scopeEvidenceCid\":\"" + getString(reviewScopeEvidenceKey(proposal.reviewRoundId))
      + "\",\"candidateCid\":\"" + proposal.candidateCid + "\",\"agentReviewRoot\":\"" + proposal.agentRoot
      + "\",\"buildAttestationRoot\":\"" + proposal.buildRoot + "\",\"dataAvailabilityRoot\":\"" + proposal.availabilityRoot
      + "\",\"identityMetricsRoot\":\"" + proposal.metricsRoot + "\",\"identityMetricsEpoch\":" + proposal.metricsEpoch.toString()
      + ",\"candidateIdentityMetricsRoot\":" + (proposal.candidateMetricsRoot.length > 0 ? "\"" + proposal.candidateMetricsRoot + "\"" : "null")
      + ",\"candidateIdentityMetricsEpoch\":" + (proposal.candidateMetricsRoot.length > 0 ? proposal.candidateMetricsEpoch.toString() : "null")
      + ",\"riskClass\":\"" + proposal.risk + "\",\"bond\":\"" + proposal.bond
      + "\",\"challengeEnd\":" + proposal.challengeEnd.toString() + ",\"executeAfter\":" + proposal.executeAfter.toString()
      + ",\"pos\":{\"yes\":\"" + proposal.yesWeight + "\",\"no\":\"" + proposal.noWeight
      + "\",\"abstain\":\"" + proposal.abstainWeight + "\",\"snapshot\":\"" + proposal.snapshotWeight
      + "\"},\"pohw\":{\"yesIdentities\":" + proposal.yesIdentities.toString()
      + ",\"strongYesIdentities\":" + proposal.yesStrongIdentities.toString()
      + "},\"reviews\":" + proposal.agentCount.toString() + ",\"reviewModelFamilies\":" + proposal.agentModelCount.toString()
      + ",\"reviewOwners\":" + proposal.agentOwnerCount.toString() + ",\"unresolvedCriticalFindings\":" + proposal.unresolvedCriticalCount.toString()
      + ",\"reviewAttestationsSubmitted\":" + proposal.agentSubmittedCount.toString() + ",\"reviewAttestationsCommitted\":" + proposal.agentLeafCount.toString()
      + ",\"hasCriticalWaiver\":" + (proposal.waiverCid.length > 0 ? "true" : "false")
      + ",\"builders\":" + proposal.builderOwnerCount.toString() + ",\"builderPlatforms\":" + proposal.builderPlatformCount.toString()
      + ",\"builderConflicts\":" + proposal.builderConflictCount.toString() + ",\"artifactDigest\":\"" + proposal.artifactDigest
      + "\",\"releaseManifestCid\":" + (proposal.releaseManifestCid.length > 0 ? "\"" + proposal.releaseManifestCid + "\"" : "null")
      + ",\"buildAttestationsSubmitted\":" + proposal.buildSubmittedCount.toString() + ",\"buildAttestationsCommitted\":" + proposal.buildLeafCount.toString()
      + ",\"availability\":" + proposal.availabilityOwnerCount.toString()
      + ",\"availabilityAttestationsSubmitted\":" + proposal.availabilitySubmittedCount.toString() + ",\"availabilityAttestationsCommitted\":" + proposal.availabilityLeafCount.toString()
      + ",\"challengeKind\":" + (proposal.challengeKind.length > 0 ? "\"" + proposal.challengeKind + "\"" : "null")
      + ",\"challengeTargetCid\":" + (proposal.challengeTarget.length > 0 ? "\"" + proposal.challengeTarget + "\"" : "null")
      + ",\"challengeEvidenceCid\":" + (proposal.challengeEvidenceCid.length > 0 ? "\"" + proposal.challengeEvidenceCid + "\"" : "null") + "}",
  );
}

function stateName(state: u8): string {
  if (state == STATE_DRAFT) return "Draft";
  if (state == STATE_REVIEW_OPEN) return "ReviewOpen";
  if (state == STATE_VOTING_OPEN) return "VotingOpen";
  if (state == STATE_ACCEPTED_PENDING_CHALLENGE) return "AcceptedPendingChallenge";
  if (state == STATE_REJECTED) return "Rejected";
  if (state == STATE_CHALLENGED) return "Challenged";
  if (state == STATE_ACCEPTED_PENDING_EXECUTION) return "AcceptedPendingExecution";
  if (state == STATE_EXECUTED) return "Executed";
  if (state == STATE_STALE) return "Stale";
  if (state == STATE_EXPIRED) return "Expired";
  if (state == STATE_NO_QUORUM) return "NoQuorum";
  if (state == STATE_ACCEPTED_PENDING_GRACE) return "AcceptedPendingGrace";
  if (state == STATE_PROPOSAL_SET_FROZEN) return "ProposalSetFrozen";
  if (state == STATE_VOTING_COMMIT) return "VotingCommit";
  if (state == STATE_VOTING_REVEAL) return "VotingReveal";
  if (state == STATE_CANCELLED_BEFORE_CUTOFF) return "CancelledBeforeCutoff";
  if (state == STATE_REVERT_PROPOSED) return "RevertProposed";
  if (state == STATE_REVERTED) return "Reverted";
  return "Unknown";
}

function isTerminalState(state: u8): bool {
  return state == STATE_REJECTED
    || state == STATE_NO_QUORUM
    || state == STATE_EXECUTED
    || state == STATE_REVERTED
    || state == STATE_STALE
    || state == STATE_EXPIRED
    || state == STATE_CANCELLED_BEFORE_CUTOFF;
}

function isRiskClass(value: string): bool {
  return value == "normal" || value == "critical" || value == "consensus" || value == "migration";
}

function isStrongState(value: string): bool { return value == "Human" || value == "Verified"; }

class EcosystemContentBinding {
  constructor(
    public sources: Map<string, string>,
    public sourceBinding: string,
    public toolchainBinding: string,
    public artifactKeys: string[],
    public requiredCids: string[],
  ) {}
}

class EcosystemPatchBinding {
  constructor(
    public affectedSourceBinding: string,
    public sourceTransitionBinding: string,
    public requiredCids: string[],
    public repositories: string[],
    public baseSourceCids: string[],
    public candidateSourceCids: string[],
    public patchCids: string[],
    public patchDigests: string[],
  ) {}
}

class ProposalScopeBinding {
  constructor(
    public risk: string,
    public changedFiles: u32,
    public patchBytes: u64,
    public sourcePackageBytes: u64,
    public descriptionBytes: u32,
    public migrationOperations: u32,
  ) {}

  counters(): string {
    return this.changedFiles.toString() + "~" + this.patchBytes.toString() + "~"
      + this.sourcePackageBytes.toString() + "~" + this.descriptionBytes.toString() + "~"
      + this.migrationOperations.toString();
  }
}

const MAX_SCOPE_PROOF_BYTES: u64 = 600000;
const MAX_SCOPE_FILES_PER_REPOSITORY = 2048;
const MAX_SCOPE_SOURCE_FILE_BYTES: u64 = 268435456;
const MAX_SCOPE_SOURCE_TREE_BYTES: u64 = 2147483648;

class SourceFileBinding {
  constructor(
    public path: string,
    public mode: u32,
    public size: u64,
    public cid: string,
    public sha256: string,
  ) {}
}

class SourceManifestBinding {
  constructor(
    public files: SourceFileBinding[],
    public contentBytes: u64,
  ) {}
}

class ScopeChangeBinding {
  constructor(
    public path: string,
    public changeKind: string,
    public size: u64,
  ) {}
}

class RepositoryScopeProofBinding {
  constructor(
    public changes: ScopeChangeBinding[],
    public patchContentBytes: u64,
    public candidateContentBytes: u64,
  ) {}
}

function validateEcosystemManifest(
  payload: CanonicalDagCborMap,
  expectedParentCid: string,
): EcosystemContentBinding {
  payload.requireExactKeys([
    "schemaVersion", "ecosystemId", "parentEcosystemCid", "repositories",
    "compatibilityPins", "toolchainLocks", "governanceContractVersion",
    "governanceParameterSetCid",
  ]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "ecosystem schema version is unsupported");
  assert(isSafeAsciiLabel(payload.string("ecosystemId"), 80), "invalid ecosystem identifier");
  const declaredParent = payload.nullableLink("parentEcosystemCid");
  assert(
    expectedParentCid.length == 0 || declaredParent == expectedParentCid,
    "candidate ecosystem parent does not match the canonical ecosystem",
  );
  assert(
    payload.string("governanceContractVersion") == CONTRACT_VERSION,
    "ecosystem governance contract version does not match this contract",
  );
  const parameterCid = payload.link("governanceParameterSetCid");
  assert(parameterCid == EXPECTED_PARAMETER_CID, "ecosystem governance parameter set does not match this contract");
  const repositories = payload.objectArray("repositories");
  assert(repositories.length > 0 && repositories.length <= 64, "ecosystem repository count is invalid");
  const sources = new Map<string, string>();
  const names = new Array<string>();
  const sourceCids = new Array<string>();
  const artifactKeys = new Array<string>();
  const artifactNames = new Map<string, bool>();
  const requiredCids = new Array<string>();
  let previousRepository = "";
  let toolchainMaterial = "ecosystem:" + stringMapBinding(payload.object("toolchainLocks"), "toolchainLocks");
  for (let i = 0; i < repositories.length; i++) {
    const repository = repositories[i];
    repository.requireExactKeys([
      "schemaVersion", "name", "sourceTreeCid", "sourceTreeSha256", "gitBundleCid",
      "gitCommitMetadata", "dependencyLocks", "toolchainLocks", "buildInstructions", "artifacts",
    ]);
    assert(parseU16(repository.unsigned("schemaVersion")) == 1, "repository schema version is unsupported");
    const name = repository.string("name");
    assert(isSafeAsciiLabel(name, 80), "invalid repository name");
    assert(i == 0 || previousRepository < name, "ecosystem repositories must be uniquely sorted");
    const sourceCid = repository.link("sourceTreeCid");
    assert(isCanonicalManifestCid(sourceCid), "repository source must use canonical DAG-CBOR CIDv1");
    const sourceSha = repository.string("sourceTreeSha256");
    assert(isCanonicalHash(sourceSha), "repository source digest must be lowercase SHA-256");
    assert(canonicalManifestCidSha256(sourceCid) == sourceSha, "repository source CID and SHA-256 disagree");
    const gitBundleCid = repository.nullableLink("gitBundleCid");
    assert(gitBundleCid.length == 0 || isCanonicalRawCid(gitBundleCid), "Git bundle must use canonical raw CIDv1");
    const gitCommit = repository.nullableString("gitCommitMetadata");
    assert(gitCommit.length == 0 || isCanonicalCommitHash(gitCommit), "Git commit metadata must be lowercase hex");
    validateDependencyLocks(repository.objectArray("dependencyLocks"));
    const repositoryToolchains = repository.object("toolchainLocks");
    toolchainMaterial += "|repository:" + lengthPrefixedText(name)
      + stringMapBinding(repositoryToolchains, "repository toolchainLocks");
    const buildInstructions = repository.stringArray("buildInstructions");
    assert(buildInstructions.length > 0 && buildInstructions.length <= 256, "build instruction list is invalid");
    for (let j = 0; j < buildInstructions.length; j++) {
      assert(isBoundedText(buildInstructions[j], 1, 4096), "invalid build instruction");
    }
    const artifacts = repository.objectArray("artifacts");
    assert(artifacts.length <= 4096, "repository artifact list is too large");
    let previousArtifact = "";
    for (let j = 0; j < artifacts.length; j++) {
      const artifact = artifacts[j];
      artifact.requireExactKeys(["name", "cid", "sha256", "size"]);
      const artifactName = artifact.string("name");
      const artifactCid = artifact.link("cid");
      const artifactSha = artifact.string("sha256");
      const artifactSize = parseU64(artifact.unsigned("size"));
      assert(isPortableArtifactName(artifactName), "invalid candidate artifact name");
      assert(j == 0 || previousArtifact < artifactName, "candidate artifacts must be uniquely sorted");
      assert(!artifactNames.has(artifactName), "candidate artifact names must be unique across the ecosystem");
      assert(isCanonicalRawCid(artifactCid), "candidate artifact must use canonical raw CIDv1");
      assert(isCanonicalHash(artifactSha), "candidate artifact digest must be lowercase SHA-256");
      assert(canonicalContentCidSha256(artifactCid) == artifactSha, "candidate artifact CID and SHA-256 disagree");
      assert(artifactSize <= MAX_PORTABLE_ARTIFACT_SIZE, "candidate artifact exceeds the portable size limit");
      artifactKeys.push(artifactBindingKey(artifactName, artifactCid, artifactSha, artifactSize));
      artifactNames.set(artifactName, true);
      requiredCids.push(artifactCid);
      previousArtifact = artifactName;
    }
    sources.set(name, sourceCid);
    names.push(name);
    sourceCids.push(sourceCid);
    requiredCids.push(sourceCid);
    previousRepository = name;
  }
  const compatibilityPins = payload.object("compatibilityPins");
  const consumers = compatibilityPins.keys();
  assert(consumers.length <= 256, "compatibility pin map is too large");
  for (let i = 0; i < consumers.length; i++) {
    assert(isSafeMapKey(consumers[i], 120), "invalid compatibility-pin consumer");
    stringMapBinding(compatibilityPins.object(consumers[i]), "compatibilityPins");
  }
  requiredCids.push(parameterCid);
  return new EcosystemContentBinding(
    sources,
    sourceSetBinding(names, sourceCids),
    hashString("IDENA_GOV_TOOLCHAIN_BINDING_V1\x00" + toolchainMaterial),
    artifactKeys,
    requiredCids,
  );
}

function validateEcosystemPatch(
  payload: CanonicalDagCborMap,
  parentCid: string,
  candidateCid: string,
  parentSources: Map<string, string>,
  candidateSources: Map<string, string>,
): EcosystemPatchBinding {
  payload.requireExactKeys([
    "schemaVersion", "kind", "parentEcosystemCid", "candidateEcosystemCid", "repositoryPatches",
  ]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "ecosystem patch schema version is unsupported");
  assert(payload.string("kind") == "pohw-ecosystem-patch-v1", "ecosystem patch kind is unsupported");
  assert(payload.link("parentEcosystemCid") == parentCid, "ecosystem patch parent mismatch");
  assert(payload.link("candidateEcosystemCid") == candidateCid, "ecosystem patch candidate mismatch");
  const patches = payload.objectArray("repositoryPatches");
  assert(patches.length > 0 && patches.length <= 64, "ecosystem patch repository set is invalid");
  const names = new Array<string>();
  const baseCids = new Array<string>();
  const candidateCids = new Array<string>();
  const requiredCids = new Array<string>();
  const patchCids = new Array<string>();
  const patchDigests = new Array<string>();
  let previous = "";
  for (let i = 0; i < patches.length; i++) {
    const patch = patches[i];
    patch.requireExactKeys(["repository", "baseSourceCid", "candidateSourceCid", "patchCid", "patchSha256"]);
    const name = patch.string("repository");
    const baseSourceCid = patch.link("baseSourceCid");
    const candidateSourceCid = patch.link("candidateSourceCid");
    const repositoryPatchCid = patch.link("patchCid");
    const repositoryPatchSha = patch.string("patchSha256");
    assert(isSafeAsciiLabel(name, 80), "invalid patched repository name");
    assert(i == 0 || previous < name, "repository patches must be uniquely sorted");
    assert(parentSources.has(name) && parentSources.get(name) == baseSourceCid, "patch base source is not in the parent ecosystem");
    assert(candidateSources.has(name) && candidateSources.get(name) == candidateSourceCid, "patch candidate source is not in the candidate ecosystem");
    assert(baseSourceCid != candidateSourceCid, "repository patch must change the source CID");
    assert(isCanonicalManifestCid(repositoryPatchCid), "repository patch must use canonical DAG-CBOR CIDv1");
    assert(isCanonicalHash(repositoryPatchSha), "repository patch digest must be lowercase SHA-256");
    assert(canonicalManifestCidSha256(repositoryPatchCid) == repositoryPatchSha, "repository patch CID and SHA-256 disagree");
    names.push(name);
    baseCids.push(baseSourceCid);
    candidateCids.push(candidateSourceCid);
    requiredCids.push(repositoryPatchCid);
    patchCids.push(repositoryPatchCid);
    patchDigests.push(repositoryPatchSha);
    previous = name;
  }
  const parentNames = parentSources.keys();
  const candidateNames = candidateSources.keys();
  assert(parentNames.length == candidateNames.length, "candidate repository source set differs from its parent");
  let changed: u32 = 0;
  for (let i = 0; i < parentNames.length; i++) {
    const name = parentNames[i];
    assert(candidateSources.has(name), "candidate repository source set differs from its parent");
    if (parentSources.get(name) != candidateSources.get(name)) {
      changed = checkedU32Add(changed, 1);
      assert(containsString(names, name), "candidate source change is missing from the ecosystem patch");
    } else {
      assert(!containsString(names, name), "ecosystem patch includes an unchanged repository source");
    }
  }
  for (let i = 0; i < candidateNames.length; i++) {
    assert(parentSources.has(candidateNames[i]), "candidate repository source set differs from its parent");
  }
  assert(changed == <u32>patches.length, "ecosystem patch does not exactly cover candidate source changes");
  return new EcosystemPatchBinding(
    sourceSetBinding(names, candidateCids),
    sourceTransitionBinding(names, baseCids, candidateCids),
    requiredCids,
    names,
    baseCids,
    candidateCids,
    patchCids,
    patchDigests,
  );
}

function validateProposalScopeEvidence(
  payload: CanonicalDagCborMap,
  parentCid: string,
  candidateCid: string,
  aggregatePatchCid: string,
  patchBinding: EcosystemPatchBinding,
): ProposalScopeBinding {
  payload.requireExactKeys([
    "schemaVersion", "classifierVersion", "parentEcosystemCid", "candidateEcosystemCid",
    "patchCid", "repositories", "rationaleBytes", "migrationNotesBytes", "testPlanBytes",
    "changedFileCount", "patchBytes", "sourcePackageBytes", "descriptionBytes",
    "migrationOperationCount", "derivedRiskClass",
  ]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "scope evidence schema version is unsupported");
  assert(payload.string("classifierVersion") == "pohw-objective-risk-classifier-v2", "scope classifier version is unsupported");
  assert(payload.string("parentEcosystemCid") == parentCid, "scope parent ecosystem mismatch");
  assert(payload.string("candidateEcosystemCid") == candidateCid, "scope candidate ecosystem mismatch");
  assert(payload.string("patchCid") == aggregatePatchCid, "scope aggregate patch mismatch");
  const repositories = payload.objectArray("repositories");
  assert(repositories.length == patchBinding.repositories.length, "scope repository set does not match the ecosystem patch");
  let changedFiles: u32 = 0;
  let patchBytes: u64 = 0;
  let sourcePackageBytes: u64 = 0;
  let migrationOperations: u32 = 0;
  let risk = "normal";
  let previousRepository = "";
  let proofBytes: u64 = 0;
  for (let i = 0; i < repositories.length; i++) {
    const repository = repositories[i];
    repository.requireExactKeys([
      "repository", "baseSourceCid", "candidateSourceCid", "patchCid", "patchSha256",
      "baseManifestDagCborHex", "candidateManifestDagCborHex", "patchDagCborHex",
      "patchContentBytes", "candidateContentBytes", "changes",
    ]);
    const name = repository.string("repository");
    assert(isSafeAsciiLabel(name, 80), "scope repository name is invalid");
    assert(i == 0 || previousRepository < name, "scope repositories must be uniquely sorted");
    assert(name == patchBinding.repositories[i], "scope repository order differs from the ecosystem patch");
    assert(repository.string("baseSourceCid") == patchBinding.baseSourceCids[i], "scope base source mismatch");
    assert(repository.string("candidateSourceCid") == patchBinding.candidateSourceCids[i], "scope candidate source mismatch");
    assert(repository.string("patchCid") == patchBinding.patchCids[i], "scope repository patch mismatch");
    assert(repository.string("patchSha256") == patchBinding.patchDigests[i], "scope repository patch digest mismatch");

    const baseHex = repository.string("baseManifestDagCborHex");
    const candidateHex = repository.string("candidateManifestDagCborHex");
    const patchHex = repository.string("patchDagCborHex");
    proofBytes = checkedU64Add(proofBytes, sourceProofHexBytes(baseHex));
    proofBytes = checkedU64Add(proofBytes, sourceProofHexBytes(candidateHex));
    proofBytes = checkedU64Add(proofBytes, sourceProofHexBytes(patchHex));
    assert(proofBytes <= MAX_SCOPE_PROOF_BYTES, "source-manifest proof bytes exceed the contract limit");
    const verified = validateRepositoryScopeProof(
      name,
      patchBinding.baseSourceCids[i],
      patchBinding.candidateSourceCids[i],
      patchBinding.patchCids[i],
      baseHex,
      candidateHex,
      patchHex,
    );
    assert(
      parseU64(repository.unsigned("patchContentBytes")) == verified.patchContentBytes,
      "scope patch-content counter is not derived",
    );
    assert(
      parseU64(repository.unsigned("candidateContentBytes")) == verified.candidateContentBytes,
      "scope candidate-content counter is not derived",
    );
    patchBytes = checkedU64Add(patchBytes, verified.patchContentBytes);
    sourcePackageBytes = checkedU64Add(sourcePackageBytes, verified.candidateContentBytes);
    const changes = repository.objectArray("changes");
    assert(changes.length == verified.changes.length, "scope changed paths differ from the verified source transition");
    for (let j = 0; j < changes.length; j++) {
      const change = changes[j];
      change.requireExactKeys(["path", "changeKind", "size"]);
      const path = change.string("path");
      const kind = change.string("changeKind");
      const size = parseU64(change.unsigned("size"));
      const expected = verified.changes[j];
      assert(
        path == expected.path && kind == expected.changeKind && size == expected.size,
        "scope changed paths differ from the verified source transition",
      );
      changedFiles = checkedU32Add(changedFiles, 1);
      if (isMigrationScopePath(path)) migrationOperations = checkedU32Add(migrationOperations, 1);
      risk = maxScopeRisk(risk, classifyScopePath(name, path));
    }
    previousRepository = name;
  }
  const rationaleBytes = parseU32(payload.unsigned("rationaleBytes"));
  const migrationNotesBytes = parseU32(payload.unsigned("migrationNotesBytes"));
  const testPlanBytes = parseU32(payload.unsigned("testPlanBytes"));
  assert(rationaleBytes > 0 && testPlanBytes > 0, "scope rationale and test plan must be nonempty");
  const descriptionBytes = checkedU32Add(checkedU32Add(rationaleBytes, migrationNotesBytes), testPlanBytes);
  assert(parseU32(payload.unsigned("changedFileCount")) == changedFiles, "scope changed-file counter is not derived");
  assert(parseU64(payload.unsigned("patchBytes")) == patchBytes, "scope patch-byte counter is not derived");
  assert(parseU64(payload.unsigned("sourcePackageBytes")) == sourcePackageBytes, "scope source-byte counter is not derived");
  assert(parseU32(payload.unsigned("descriptionBytes")) == descriptionBytes, "scope description-byte counter is not derived");
  assert(parseU32(payload.unsigned("migrationOperationCount")) == migrationOperations, "scope migration counter is not derived");
  assert(payload.string("derivedRiskClass") == risk, "scope risk class is not derived");
  return new ProposalScopeBinding(
    risk,
    changedFiles,
    patchBytes,
    sourcePackageBytes,
    descriptionBytes,
    migrationOperations,
  );
}

function sourceProofHexBytes(value: string): u64 {
  assert(value.length > 0 && value.length % 2 == 0, "source-manifest proof hex is empty or malformed");
  return <u64>(value.length / 2);
}

function validateRepositoryScopeProof(
  repository: string,
  baseSourceCid: string,
  candidateSourceCid: string,
  patchCid: string,
  baseHex: string,
  candidateHex: string,
  patchHex: string,
): RepositoryScopeProofBinding {
  const base = validateSourceManifest(
    verifiedCanonicalSourceProofDagCborMap(baseSourceCid, baseHex),
    repository,
  );
  const candidate = validateSourceManifest(
    verifiedCanonicalSourceProofDagCborMap(candidateSourceCid, candidateHex),
    repository,
  );
  const patch = verifiedCanonicalSourceProofDagCborMap(patchCid, patchHex);
  patch.requireExactKeys([
    "schemaVersion", "kind", "repository", "baseSourceCid", "candidateSourceCid",
    "removedPaths", "upsertedFiles",
  ]);
  assert(parseU16(patch.unsigned("schemaVersion")) == 1, "source patch schema version is unsupported");
  assert(patch.string("kind") == "pohw-source-patch-v1", "source patch kind is unsupported");
  assert(patch.string("repository") == repository, "source patch repository mismatch");
  assert(patch.link("baseSourceCid") == baseSourceCid, "source patch base CID mismatch");
  assert(patch.link("candidateSourceCid") == candidateSourceCid, "source patch candidate CID mismatch");

  const removedPaths = patch.stringArray("removedPaths");
  const upsertedMaps = patch.objectArray("upsertedFiles");
  const patchUpserted = new Array<SourceFileBinding>();
  for (let i = 0; i < upsertedMaps.length; i++) {
    patchUpserted.push(validateSourceFileEntry(upsertedMaps[i]));
  }

  const derivedRemoved = new Array<string>();
  const derivedUpserted = new Array<SourceFileBinding>();
  let baseIndex = 0;
  let candidateIndex = 0;
  while (baseIndex < base.files.length || candidateIndex < candidate.files.length) {
    if (
      candidateIndex >= candidate.files.length
        || (baseIndex < base.files.length && base.files[baseIndex].path < candidate.files[candidateIndex].path)
    ) {
      derivedRemoved.push(base.files[baseIndex].path);
      baseIndex++;
    } else if (
      baseIndex >= base.files.length
        || candidate.files[candidateIndex].path < base.files[baseIndex].path
    ) {
      derivedUpserted.push(candidate.files[candidateIndex]);
      candidateIndex++;
    } else {
      if (!sourceFileEquals(base.files[baseIndex], candidate.files[candidateIndex])) {
        derivedUpserted.push(candidate.files[candidateIndex]);
      }
      baseIndex++;
      candidateIndex++;
    }
  }
  assert(
    derivedRemoved.length + derivedUpserted.length > 0,
    "source patch must contain at least one verified change",
  );
  assert(derivedRemoved.length == removedPaths.length, "source patch removals do not reconstruct the candidate");
  for (let i = 0; i < derivedRemoved.length; i++) {
    assert(derivedRemoved[i] == removedPaths[i], "source patch removals do not reconstruct the candidate");
  }
  assert(derivedUpserted.length == patchUpserted.length, "source patch upserts do not reconstruct the candidate");
  for (let i = 0; i < derivedUpserted.length; i++) {
    assert(sourceFileEquals(derivedUpserted[i], patchUpserted[i]), "source patch upserts do not reconstruct the candidate");
  }

  let patchContentBytes: u64 = 0;
  for (let i = 0; i < derivedUpserted.length; i++) {
    patchContentBytes = checkedU64Add(patchContentBytes, derivedUpserted[i].size);
  }
  const changes = new Array<ScopeChangeBinding>();
  let removedIndex = 0;
  let upsertedIndex = 0;
  while (removedIndex < derivedRemoved.length || upsertedIndex < derivedUpserted.length) {
    if (
      upsertedIndex >= derivedUpserted.length
        || (removedIndex < derivedRemoved.length && derivedRemoved[removedIndex] < derivedUpserted[upsertedIndex].path)
    ) {
      changes.push(new ScopeChangeBinding(derivedRemoved[removedIndex], "remove", 0));
      removedIndex++;
    } else {
      const entry = derivedUpserted[upsertedIndex];
      changes.push(new ScopeChangeBinding(entry.path, "upsert", entry.size));
      upsertedIndex++;
    }
  }
  assert(changes.length <= 1024, "scope changed path set exceeds the contract limit");
  return new RepositoryScopeProofBinding(changes, patchContentBytes, candidate.contentBytes);
}

function validateSourceManifest(
  payload: CanonicalDagCborMap,
  repository: string,
): SourceManifestBinding {
  payload.requireExactKeys(["schemaVersion", "kind", "repository", "files"]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "source manifest schema version is unsupported");
  assert(payload.string("kind") == "pohw-source-tree-v1", "source manifest kind is unsupported");
  assert(payload.string("repository") == repository, "source manifest repository mismatch");
  const fileMaps = payload.objectArray("files");
  assert(fileMaps.length <= MAX_SCOPE_FILES_PER_REPOSITORY, "source manifest exceeds the scope-proof file limit");
  const files = new Array<SourceFileBinding>();
  const portablePaths = new Map<string, bool>();
  let previousPath = "";
  let contentBytes: u64 = 0;
  for (let i = 0; i < fileMaps.length; i++) {
    const entry = validateSourceFileEntry(fileMaps[i]);
    assert(i == 0 || previousPath < entry.path, "source manifest paths must be strictly sorted");
    const portablePath = entry.path.toLowerCase();
    assert(!portablePaths.has(portablePath), "source manifest paths collide on a case-insensitive filesystem");
    portablePaths.set(portablePath, true);
    contentBytes = checkedU64Add(contentBytes, entry.size);
    assert(contentBytes <= MAX_SCOPE_SOURCE_TREE_BYTES, "source manifest content exceeds the deterministic limit");
    files.push(entry);
    previousPath = entry.path;
  }
  return new SourceManifestBinding(files, contentBytes);
}

function validateSourceFileEntry(payload: CanonicalDagCborMap): SourceFileBinding {
  payload.requireExactKeys(["path", "mode", "size", "cid", "sha256"]);
  const path = payload.string("path");
  const mode = parseU32(payload.unsigned("mode"));
  const size = parseU64(payload.unsigned("size"));
  const cid = payload.link("cid");
  const sha = payload.string("sha256");
  assert(isSafeRelativePath(path), "source manifest path is invalid");
  assert(mode == 420 || mode == 493, "source manifest mode is not normalized");
  assert(size <= MAX_SCOPE_SOURCE_FILE_BYTES, "source manifest file exceeds the deterministic limit");
  assert(isCanonicalRawCid(cid), "source manifest file CID must be canonical raw CIDv1");
  assert(isCanonicalHash(sha), "source manifest file digest must be lowercase SHA-256");
  assert(canonicalContentCidSha256(cid) == sha, "source manifest file CID and digest disagree");
  return new SourceFileBinding(path, mode, size, cid, sha);
}

function sourceFileEquals(left: SourceFileBinding, right: SourceFileBinding): bool {
  return left.path == right.path && left.mode == right.mode && left.size == right.size
    && left.cid == right.cid && left.sha256 == right.sha256;
}

function classifyScopePath(repository: string, path: string): string {
  if (repository == "idena-wasm" || repository == "idena-wasm-binding" || repository == "wasmer") {
    return "consensus";
  }
  if (repository == "idena-go" && (
    path.startsWith("blockchain/") || path.startsWith("core/") || path.startsWith("vm/")
      || path.startsWith("consensus/") || path.startsWith("config/")
  )) return "consensus";
  if (repository == "P2poolBTC" && (
    path.startsWith("contracts/idena-code-governance/")
      || path.startsWith("compatibility/governance-fork")
      || path == "compatibility/governance-day-fork-candidate-lock.json"
      || path.startsWith("integrations/governance-epoch-anchor/")
      || path.indexOf("fork_chain") >= 0 || path.indexOf("sharechain") >= 0
      || path.indexOf("consensus") >= 0
  )) return "consensus";
  if (isMigrationScopePath(path)) return "migration";
  if (isDocumentationScopePath(path)) return "normal";
  return "critical";
}

function isDocumentationScopePath(path: string): bool {
  const extensionAllowed = path.endsWith(".md") || path.endsWith(".txt");
  if (!extensionAllowed) return false;
  if (path.startsWith("docs/")) return true;
  if (path.indexOf("/") >= 0) return false;
  return path == "README.md" || path == "CONTRIBUTING.md" || path == "SECURITY.md"
    || path == "CODE_OF_CONDUCT.md";
}

function isMigrationScopePath(path: string): bool {
  return path.startsWith("migrations/") || path.indexOf("/migrations/") >= 0
    || path.startsWith("migration/") || path.indexOf("/migration/") >= 0;
}

function maxScopeRisk(left: string, right: string): string {
  return scopeRiskRank(right) > scopeRiskRank(left) ? right : left;
}

function scopeRiskRank(risk: string): i32 {
  if (risk == "normal") return 0;
  if (risk == "critical") return 1;
  if (risk == "migration") return 2;
  if (risk == "consensus") return 3;
  assert(false, "unknown objective scope risk class");
  return -1;
}

function validatePinsetManifest(
  payload: CanonicalDagCborMap,
  candidateCid: string,
  patchCid: string,
  candidateRequiredCids: string[],
): string[] {
  payload.requireExactKeys(["schemaVersion", "ecosystemCid", "cids"]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "pinset schema version is unsupported");
  assert(payload.link("ecosystemCid") == candidateCid, "pinset ecosystem CID mismatch");
  const cids = payload.linkArray("cids");
  assert(cids.length > 0 && cids.length <= 4096, "pinset CID set is invalid");
  assert(strictSortedUnique(cids), "pinset CIDs must be uniquely sorted");
  assert(containsString(cids, candidateCid), "pinset must include the candidate ecosystem CID");
  assert(containsString(cids, patchCid), "pinset must include the ecosystem patch CID");
  for (let i = 0; i < candidateRequiredCids.length; i++) {
    assert(containsString(cids, candidateRequiredCids[i]), "pinset omits candidate source, artifact, or parameter content");
  }
  for (let i = 0; i < cids.length; i++) {
    assert(isCanonicalContentCid(cids[i]), "pinset member must use canonical CIDv1/SHA2-256");
  }
  return cids;
}

function validateToolchainManifest(payload: CanonicalDagCborMap): string {
  payload.requireExactKeys(["schemaVersion", "ecosystemLocks", "repositoryLocks"]);
  assert(parseU16(payload.unsigned("schemaVersion")) == 1, "toolchain manifest schema version is unsupported");
  let material = "ecosystem:" + stringMapBinding(payload.object("ecosystemLocks"), "toolchain ecosystemLocks");
  const repositories = payload.objectArray("repositoryLocks");
  assert(repositories.length > 0 && repositories.length <= 64, "toolchain repository lock set is invalid");
  let previous = "";
  for (let i = 0; i < repositories.length; i++) {
    const repository = repositories[i];
    repository.requireExactKeys(["repository", "toolchainLocks"]);
    const name = repository.string("repository");
    assert(isSafeAsciiLabel(name, 80), "invalid toolchain repository name");
    assert(i == 0 || previous < name, "toolchain repositories must be uniquely sorted");
    material += "|repository:" + lengthPrefixedText(name)
      + stringMapBinding(repository.object("toolchainLocks"), "toolchain repository locks");
    previous = name;
  }
  return hashString("IDENA_GOV_TOOLCHAIN_BINDING_V1\x00" + material);
}

function validateProposalNestedPayload(payload: CanonicalDagCborMap): string {
  const affected = payload.stringArray("affectedRepositories");
  assert(affected.length > 0 && affected.length <= 64, "affected repository list is empty or too large");
  assert(strictSortedUnique(affected), "affected repositories must be uniquely sorted");
  const base = payload.object("baseSourceCids");
  const candidate = payload.object("candidateSourceCids");
  assert(base.size() == affected.length && candidate.size() == affected.length, "source CID maps must exactly match affected repositories");
  for (let i = 0; i < affected.length; i++) {
    const name = affected[i];
    assert(isSafeAsciiLabel(name, 80), "invalid affected repository name");
    assert(base.has(name) && candidate.has(name), "source CID maps must exactly match affected repositories");
    assert(isCanonicalManifestCid(base.string(name)), "base source CID must be canonical DAG-CBOR CIDv1");
    assert(isCanonicalManifestCid(candidate.string(name)), "candidate source CID must be canonical DAG-CBOR CIDv1");
  }
  for (let i = 0; i < base.keys().length; i++) {
    assert(containsString(affected, base.keys()[i]), "base source CID map contains an unrelated repository");
  }
  for (let i = 0; i < candidate.keys().length; i++) {
    assert(containsString(affected, candidate.keys()[i]), "candidate source CID map contains an unrelated repository");
  }
  assert(isCanonicalContentCid(payload.string("rationaleCid")), "rationale must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("migrationNotesCid")), "migration notes must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("testPlanCid")), "test plan must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("rollbackManifestCid")), "rollback manifest must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("rollbackInstructionsCid")), "rollback instructions must be an immutable CID");
  const baseCids = new Array<string>();
  const candidateCids = new Array<string>();
  for (let i = 0; i < affected.length; i++) {
    baseCids.push(base.string(affected[i]));
    candidateCids.push(candidate.string(affected[i]));
  }
  return sourceTransitionBinding(affected, baseCids, candidateCids);
}

function validateProposalDeclaredLimits(payload: CanonicalDagCborMap, risk: string): void {
  const critical = risk != "normal";
  const maxRepositories: u32 = critical ? 16 : 4;
  const maxChangedFiles: u32 = critical ? 1024 : 128;
  const maxPatchBytes: u64 = critical ? 16 * 1024 * 1024 : 2 * 1024 * 1024;
  const maxSourcePackageBytes: u64 = critical ? 1024 * 1024 * 1024 : 256 * 1024 * 1024;
  const maxDescriptionBytes: u32 = critical ? 64 * 1024 : 16 * 1024;
  const maxMigrationOperations: u32 = critical ? 64 : 8;
  const changedFiles = parseU32(payload.unsigned("changedFileCount"));
  const patchBytes = parseU64(payload.unsigned("patchBytes"));
  const sourcePackageBytes = parseU64(payload.unsigned("sourcePackageBytes"));
  const descriptionBytes = parseU32(payload.unsigned("descriptionBytes"));
  const migrationOperations = parseU32(payload.unsigned("migrationOperationCount"));
  assert(<u32>payload.stringArray("affectedRepositories").length <= maxRepositories, "affected repository limit exceeded");
  assert(changedFiles > 0 && changedFiles <= maxChangedFiles, "changed-file limit exceeded");
  assert(patchBytes <= maxPatchBytes, "patch-size limit exceeded");
  assert(sourcePackageBytes <= maxSourcePackageBytes, "source-package limit exceeded");
  assert(descriptionBytes > 0 && descriptionBytes <= maxDescriptionBytes, "description-size limit exceeded");
  assert(migrationOperations <= maxMigrationOperations, "migration-operation limit exceeded");
}

function proposalDeclaredCounters(payload: CanonicalDagCborMap): string {
  return parseU32(payload.unsigned("changedFileCount")).toString() + "~"
    + parseU64(payload.unsigned("patchBytes")).toString() + "~"
    + parseU64(payload.unsigned("sourcePackageBytes")).toString() + "~"
    + parseU32(payload.unsigned("descriptionBytes")).toString() + "~"
    + parseU32(payload.unsigned("migrationOperationCount")).toString();
}

function validateAgentNestedPayload(
  payload: CanonicalDagCborMap,
  declaredUnresolved: u32,
  testsPassed: bool,
): string {
  const sourceBinding = validateRepositoryCidList(payload.objectArray("affectedRepositories"), "affectedRepositories");
  assert(isBoundedText(payload.string("modelIdentifier"), 1, 160), "invalid model identifier");
  if (!payload.isNull("modelRevision")) {
    assert(isBoundedText(payload.string("modelRevision"), 1, 160), "invalid model revision");
  }
  assert(isBoundedText(payload.string("providerOrRuntimeIdentifier"), 1, 160), "invalid provider or runtime identifier");
  assert(isCanonicalContentCid(payload.string("agentPolicyCid")), "agent policy must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("systemPromptPolicyCid")), "system prompt policy must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("staticAnalysisResultsCid")), "static analysis result must be an immutable CID");
  assert(isCanonicalContentCid(payload.string("dependencyFindingsCid")), "dependency findings must be an immutable CID");
  validateToolVersions(payload.object("toolVersions"));
  validateCommandExecutions(payload.objectArray("commandsExecuted"), testsPassed);
  const findings = payload.objectArray("securityFindings");
  assert(findings.length <= 10000, "security finding list exceeds deterministic limit");
  let unresolved: u32 = 0;
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    finding.requireExactKeys(["severity", "summary", "evidenceCid", "resolved"]);
    const severity = finding.string("severity");
    assert(
      severity == "info" || severity == "low" || severity == "medium"
        || severity == "high" || severity == "critical",
      "unknown security finding severity",
    );
    assert(isBoundedText(finding.string("summary"), 1, 4096), "invalid security finding summary");
    if (!finding.isNull("evidenceCid")) {
      assert(isCanonicalContentCid(finding.string("evidenceCid")), "security finding evidence must be an immutable CID");
    }
    if (severity == "critical" && !finding.boolean("resolved")) unresolved = checkedU32Add(unresolved, 1);
  }
  assert(unresolved == declaredUnresolved, "unresolved critical finding count does not match the finding list");
  return sourceBinding;
}

function validateBuildNestedPayload(
  payload: CanonicalDagCborMap,
  coreDigest: string,
  testsPassed: bool,
  reviewRoundId: string,
): string {
  const sourceBinding = validateRepositoryCidList(payload.objectArray("sourceCids"), "sourceCids");
  assert(isCanonicalManifestCid(payload.string("toolchainCid")), "toolchain manifest must use canonical DAG-CBOR CIDv1");
  assert(isCanonicalRawCid(payload.string("sbomCid")), "SBOM must use a canonical raw CID");
  validateCommandExecutions(payload.objectArray("commands"), testsPassed);
  const artifacts = payload.objectArray("artifacts");
  assert(artifacts.length > 0 && artifacts.length <= 4096, "artifact list is empty or too large");
  assert(
    <u32>artifacts.length == storedU32(reviewCandidateArtifactCountKey(reviewRoundId)),
    "build attestation must cover the complete candidate artifact set",
  );
  let previous = "";
  let coreCount: u32 = 0;
  const coreParts = new Array<Uint8Array>();
  for (let i = 0; i < artifacts.length; i++) {
    const artifact = artifacts[i];
    artifact.requireExactKeys(["name", "cid", "sha256", "size", "core"]);
    const name = artifact.string("name");
    const cid = artifact.string("cid");
    const digest = artifact.string("sha256");
    const size = parseU64(artifact.unsigned("size"));
    const core = artifact.boolean("core");
    assert(isPortableArtifactName(name), "invalid portable artifact name");
    assert(i == 0 || previous < name, "artifacts must be uniquely sorted by name");
    assert(isCanonicalRawCid(cid), "artifact must use a canonical raw CIDv1/SHA2-256");
    assert(isCanonicalHash(digest), "artifact digest must be lowercase SHA-256");
    assert(canonicalContentCidSha256(cid) == digest, "artifact CID and SHA-256 disagree");
    assert(size <= MAX_PORTABLE_ARTIFACT_SIZE, "artifact size exceeds the portable integer limit");
    assert(
      hasKey(candidateArtifactKey(reviewRoundId, artifactBindingKey(name, cid, digest, size))),
      "build artifact is not authorized by the candidate ecosystem manifest",
    );
    if (core) {
      coreCount = checkedU32Add(coreCount, 1);
      appendLengthPrefixed(coreParts, stringToBytes(name));
      appendLengthPrefixed(coreParts, stringToBytes(cid));
      coreParts.push(hexToBytes(digest));
      coreParts.push(u64BigEndianBytes(size));
    }
    previous = name;
  }
  assert(coreCount > 0, "at least one core artifact is required");
  const digestParts = new Array<Uint8Array>();
  digestParts.push(stringToBytes(CORE_ARTIFACT_SET_DOMAIN));
  digestParts.push(u32BigEndianBytes(coreCount));
  for (let i = 0; i < coreParts.length; i++) digestParts.push(coreParts[i]);
  assert(
    bytesToHex(sha256(concatByteArrays(digestParts))) == coreDigest,
    "core artifact digest does not match the declared core artifact set",
  );
  return sourceBinding;
}

function appendLengthPrefixed(parts: Array<Uint8Array>, value: Uint8Array): void {
  assert(value.length >= 0, "invalid artifact field length");
  parts.push(u32BigEndianBytes(<u32>value.length));
  parts.push(value);
}

function u32BigEndianBytes(value: u32): Uint8Array {
  const result = new Uint8Array(4);
  result[0] = <u8>(value >> 24);
  result[1] = <u8>(value >> 16);
  result[2] = <u8>(value >> 8);
  result[3] = <u8>value;
  return result;
}

function u64BigEndianBytes(value: u64): Uint8Array {
  const result = new Uint8Array(8);
  for (let i = 0; i < 8; i++) result[i] = <u8>(value >> (<u64>(7 - i) * 8));
  return result;
}

function concatByteArrays(parts: Array<Uint8Array>): Uint8Array {
  let total: i32 = 0;
  for (let i = 0; i < parts.length; i++) {
    assert(parts[i].length <= i32.MAX_VALUE - total, "core artifact set is too large");
    total += parts[i].length;
  }
  const result = new Uint8Array(total);
  let offset: i32 = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part.length > 0) memory.copy(result.dataStart + offset, part.dataStart, part.length);
    offset += part.length;
  }
  return result;
}

function validateAvailabilityNestedPayload(payload: CanonicalDagCborMap, round: ReviewRound): string[] {
  assert(payload.string("pinsetCid") == round.pinsetCid, "availability attestation pinset mismatch");
  assert(isSafeAsciiLabel(payload.string("providerId"), 80), "invalid availability provider identifier");
  const verified = payload.stringArray("verifiedCids");
  assert(
    verified.length >= <i32>round.pinsetCount && verified.length <= <i32>MAX_REQUIRED_AVAILABILITY_CIDS,
    "verified CID set is outside the deterministic limits",
  );
  assert(strictSortedUnique(verified), "verified CIDs must be uniquely sorted");
  let pinsetCovered: u32 = 0;
  for (let i = 0; i < verified.length; i++) {
    assert(isCanonicalContentCid(verified[i]), "verified content CID must be canonical CIDv1/SHA2-256");
    if (hasKey(reviewPinsetMemberKey(round.id, verified[i]))) pinsetCovered = checkedU32Add(pinsetCovered, 1);
  }
  assert(pinsetCovered == round.pinsetCount, "verified CID set omits opening pinset content");
  assert(containsString(verified, payload.string("probeResultCid")), "availability attestation must verify its probe result");
  assert(
    parseU64(payload.unsigned("expiresAtBlock")) > parseU64(payload.unsigned("observedAtBlockOrTimestamp")),
    "availability expiry must follow its observation boundary",
  );
  return verified;
}

function validateRepositoryCidList(values: CanonicalDagCborMap[], field: string): string {
  assert(values.length > 0 && values.length <= 64, field + " is empty or too large");
  let previous = "";
  const names = new Array<string>();
  const cids = new Array<string>();
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    value.requireExactKeys(["repository", "cid"]);
    const repository = value.string("repository");
    assert(isSafeAsciiLabel(repository, 80), "invalid repository name");
    assert(i == 0 || previous < repository, "repository CID list must be uniquely sorted");
    assert(isCanonicalManifestCid(value.string("cid")), "repository source must use canonical DAG-CBOR CIDv1");
    names.push(repository);
    cids.push(value.string("cid"));
    previous = repository;
  }
  return sourceSetBinding(names, cids);
}

function validateDependencyLocks(values: CanonicalDagCborMap[]): void {
  assert(values.length <= 4096, "dependency lock list exceeds the deterministic limit");
  let previous = "";
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    value.requireExactKeys(["path", "sha256"]);
    const path = value.string("path");
    assert(isSafeRelativePath(path), "invalid dependency lock path");
    assert(i == 0 || previous < path, "dependency locks must be uniquely sorted by path");
    assert(isCanonicalHash(value.string("sha256")), "dependency lock digest must be lowercase SHA-256");
    previous = path;
  }
}

function stringMapBinding(values: CanonicalDagCborMap, field: string): string {
  const keys = values.keys();
  assert(keys.length <= 256, field + " has too many entries");
  let result = keys.length.toString() + ":";
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    assert(isSafeMapKey(key, 120), "invalid " + field + " key");
    const value = values.string(key);
    assert(isBoundedText(value, 1, 4096), "invalid " + field + " value");
    result += lengthPrefixedText(key) + lengthPrefixedText(value);
  }
  return result;
}

function lengthPrefixedText(value: string): string {
  return value.length.toString() + ":" + value;
}

function sourceSetBinding(names: string[], cids: string[]): string {
  assert(names.length == cids.length && names.length > 0, "source binding set is invalid");
  let material = names.length.toString() + ":";
  for (let i = 0; i < names.length; i++) {
    assert(i == 0 || names[i - 1] < names[i], "source binding repositories must be uniquely sorted");
    material += lengthPrefixedText(names[i]) + lengthPrefixedText(cids[i]);
  }
  return hashString("IDENA_GOV_SOURCE_BINDING_V1\x00" + material);
}

function sourceTransitionBinding(names: string[], baseCids: string[], candidateCids: string[]): string {
  assert(
    names.length == baseCids.length && names.length == candidateCids.length && names.length > 0,
    "source transition binding set is invalid",
  );
  let material = names.length.toString() + ":";
  for (let i = 0; i < names.length; i++) {
    assert(i == 0 || names[i - 1] < names[i], "source transition repositories must be uniquely sorted");
    material += lengthPrefixedText(names[i])
      + lengthPrefixedText(baseCids[i]) + lengthPrefixedText(candidateCids[i]);
  }
  return hashString("IDENA_GOV_SOURCE_TRANSITION_V1\x00" + material);
}

function artifactBindingKey(name: string, cid: string, digest: string, size: u64): string {
  return hashString(
    "IDENA_GOV_CANDIDATE_ARTIFACT_V1\x00"
      + lengthPrefixedText(name) + lengthPrefixedText(cid) + digest + size.toString(),
  );
}

function validateToolVersions(values: CanonicalDagCborMap): void {
  const keys = values.keys();
  assert(keys.length > 0 && keys.length <= 256, "tool version map is empty or too large");
  for (let i = 0; i < keys.length; i++) {
    assert(isSafeAsciiLabel(keys[i], 80), "invalid tool version key");
    assert(isBoundedText(values.string(keys[i]), 1, 160), "invalid tool version value");
  }
}

function validateCommandExecutions(values: CanonicalDagCborMap[], requireSuccess: bool): void {
  assert(values.length > 0 && values.length <= 2000, "command log is empty or too large");
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    value.requireExactKeys(["command", "exitCode", "stdoutSha256", "stderrSha256"]);
    const command = value.string("command");
    assert(isBoundedText(command, 1, 8192), "invalid command log entry");
    const exitCode = value.integer("exitCode");
    assert(isCanonicalI32(exitCode), "command exit code exceeds i32");
    assert(!requireSuccess || exitCode == "0", "testsPassed contradicts a nonzero command exit code");
    assert(isCanonicalHash(value.string("stdoutSha256")), "command stdout digest must be lowercase SHA-256");
    assert(isCanonicalHash(value.string("stderrSha256")), "command stderr digest must be lowercase SHA-256");
    assert(!containsUnredactedSecret(command), "command log appears to contain an unredacted secret");
  }
}

function isCanonicalContentCid(value: string): bool {
  return isCanonicalManifestCid(value) || isCanonicalRawCid(value);
}

function strictSortedUnique(values: string[]): bool {
  for (let i = 1; i < values.length; i++) if (values[i - 1] >= values[i]) return false;
  return true;
}

function containsString(values: string[], expected: string): bool {
  for (let i = 0; i < values.length; i++) if (values[i] == expected) return true;
  return false;
}

function isSafeAsciiLabel(value: string, maxLength: i32): bool {
  if (value.length == 0 || value.length > maxLength) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!(
      (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
        || (code >= 48 && code <= 57) || code == 45 || code == 46 || code == 95
    )) return false;
  }
  return true;
}

function isSafeMapKey(value: string, maxLength: i32): bool {
  if (value.length == 0 || value.length > maxLength) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!(
      (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
        || (code >= 48 && code <= 57) || code == 45 || code == 46 || code == 95
        || code == 47 || code == 58
    )) return false;
  }
  return true;
}

function isBoundedText(value: string, minimum: i32, maximum: i32): bool {
  const bytes = stringToBytes(value);
  if (bytes.length < minimum || bytes.length > maximum) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if ((code < 32 && code != 9 && code != 10) || (code >= 127 && code <= 159)) return false;
  }
  return true;
}

function isCanonicalCommitHash(value: string): bool {
  if (value.length != 40 && value.length != 64) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!((code >= 48 && code <= 57) || (code >= 97 && code <= 102))) return false;
  }
  return true;
}

function isSafeRelativePath(value: string): bool {
  if (!isBoundedText(value, 1, 1024) || value.startsWith("/") || value.endsWith("/")) return false;
  const parts = value.split("/");
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].length == 0 || parts[i] == "." || parts[i] == "..") return false;
    if (parts[i].indexOf("\\") >= 0 || parts[i].indexOf(":") >= 0) return false;
  }
  return true;
}

function isPortableArtifactName(value: string): bool {
  if (value.length == 0 || value.length > 128) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const alphanumeric =
      (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57);
    if (!alphanumeric && code != 45 && code != 46 && code != 95) return false;
    if (i == 0 && !alphanumeric) return false;
  }
  return true;
}

function containsUnredactedSecret(value: string): bool {
  const lower = value.toLowerCase();
  const assignments = [
    "private_key=", "private-key=", "api_key=", "apikey=", "auth_token=",
    "access_token=", "secret_key=", "--password=", "--token=",
  ];
  for (let i = 0; i < assignments.length; i++) {
    let offset = 0;
    while (offset < lower.length) {
      const relative = lower.substring(offset).indexOf(assignments[i]);
      if (relative < 0) break;
      const valueOffset = offset + relative + assignments[i].length;
      if (!hasScopedRedaction(value, valueOffset)) return true;
      offset = valueOffset;
    }
  }
  const tokenPrefixes = ["tskey-", "ghp_", "github_pat_"];
  for (let i = 0; i < tokenPrefixes.length; i++) {
    if (lower.indexOf(tokenPrefixes[i]) >= 0) return true;
  }
  return false;
}

function hasScopedRedaction(value: string, offset: i32): bool {
  const marker = "[REDACTED]";
  if (value.substring(offset, offset + marker.length) != marker) return false;
  const end = offset + marker.length;
  if (end == value.length) return true;
  const code = value.charCodeAt(end);
  return code == 9 || code == 10 || code == 13 || code == 32 || code == 34 || code == 39
    || code == 38 || code == 41 || code == 44 || code == 59 || code == 93 || code == 124 || code == 125;
}

function isCanonicalI32(value: string): bool {
  if (value.startsWith("-")) {
    if (value.length <= 1) return false;
    return parseU64(value.substring(1)) <= 2_147_483_648;
  }
  return parseU64(value) <= 2_147_483_647;
}

function proposalPayloadKeys(): string[] {
  return [
    "schemaVersion", "scopeEvidenceCid", "governanceParameterSetCid", "parentCanonicalEcosystemCid", "candidateEcosystemCid",
    "affectedRepositories", "changedFileCount", "patchBytes", "sourcePackageBytes", "descriptionBytes",
    "migrationOperationCount", "baseSourceCids", "candidateSourceCids", "patchCid", "reviewRoundId",
    "proposerAddress", "proposalBondAtoms", "riskClass", "rationaleCid",
    "migrationNotesCid", "testPlanCid", "rollbackManifestCid", "rollbackInstructionsCid",
    "releaseManifestCid", "criticalFindingWaiverCid",
    "agentReviewRoot", "buildAttestationRoot", "dataAvailabilityRoot",
    "creationBlock", "creationEpoch", "stakingEpoch", "identityMetricsEpoch",
    "candidateIdentityMetricsRoot", "candidateIdentityMetricsEpoch",
    "votingStart", "votingEnd", "challengeEnd",
  ];
}

function agentAttestationPayloadKeys(): string[] {
  return [
    "schemaVersion", "parentEcosystemCid", "candidateEcosystemCid", "patchCid",
    "affectedRepositories", "modelIdentifier", "modelRevision",
    "providerOrRuntimeIdentifier", "modelFamily", "agentPolicyCid",
    "systemPromptPolicyCid", "toolVersions", "commandsExecuted", "testResultsCid",
    "testsPassed", "staticAnalysisResultsCid", "dependencyFindingsCid",
    "securityFindings", "unresolvedCriticalFindings", "verdict", "ownerIdenaAddress",
    "reviewerBondAtoms", "creationBlockOrTimestamp", "authentication",
  ];
}

function identityMetricsAttestationPayloadKeys(): string[] {
  return [
    "schemaVersion", "metricsRoot", "snapshotCid", "snapshotSha256",
    "sourceEpoch", "sourceBlockHeight", "sourceBlockHash", "replayStartHeight",
    "replayCommitment", "indexerImplementationCid", "operatorIdenaAddress",
    "observedAtBlockOrTimestamp", "authentication",
  ];
}

function buildAttestationPayloadKeys(): string[] {
  return [
    "schemaVersion", "candidateEcosystemCid", "sourceCids", "toolchainCid", "scopeEvidenceCid",
    "builderIdentity", "runtimeFamily", "architecture", "commands", "testResultsCid",
    "testsPassed", "sbomCid", "artifacts", "coreArtifactDigest", "builderBondAtoms",
    "creationBlockOrTimestamp", "authentication",
  ];
}

function dataAvailabilityPayloadKeys(): string[] {
  return [
    "schemaVersion", "candidateEcosystemCid", "pinsetCid", "providerId",
    "operatorIdentity", "verifiedCids", "probeResultCid", "available",
    "observedAtBlockOrTimestamp", "expiresAtBlock", "bondAtoms", "authentication",
  ];
}

function canonicalPayloadAddress(value: string): string {
  assert(value.length == 42 && value.startsWith("0x"), "payload address must be canonical lowercase hex");
  const address = value.substring(2);
  assert(isAddressHex(address), "payload address must be canonical lowercase hex");
  return address;
}

function checkedU32Add(left: u32, right: u32): u32 {
  assert(left <= u32.MAX_VALUE - right, "counter arithmetic overflow");
  return left + right;
}

function checkedU64Add(left: u64, right: u64): u64 {
  assert(left <= u64.MAX_VALUE - right, "counter arithmetic overflow");
  return left + right;
}

function validProposalId(value: string): string {
  assert(isCanonicalHash(value), "proposal ID must be lowercase SHA-256");
  return value;
}

function validReviewRoundId(value: string): string {
  assert(isCanonicalHash(value), "review round ID must be lowercase SHA-256");
  return value;
}

function isAddressHex(value: string): bool {
  if (value.length != 40) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!((code >= 48 && code <= 57) || (code >= 97 && code <= 102))) return false;
  }
  return true;
}

function hashString(value: string): string { return bytesToHex(sha256(stringToBytes(value))); }

function okJson(key: string, value: string): usize {
  return returnString("{\"ok\":true,\"" + key + "\":\"" + value + "\"}");
}

function checkedEpochAdd(value: u16, delta: u16): u16 {
  assert(value <= u16.MAX_VALUE - delta, "epoch arithmetic overflow");
  return value + delta;
}

function checkedBlockAdd(value: u64, delta: u64): u64 {
  assert(value <= u64.MAX_VALUE - delta, "block arithmetic overflow");
  return value + delta;
}

function maxReviewChallengeEnd(round: ReviewRound): u64 {
  return checkedBlockAdd(
    checkedBlockAdd(checkedBlockAdd(round.claimDeadline, REVIEW_BLOCKS), VOTING_BLOCKS),
    CHALLENGE_BLOCKS,
  );
}

function maxReviewExecutionExpiry(round: ReviewRound): u64 {
  // Voting may be finalized at its original challenge deadline. Finalization
  // then opens a fresh challenge period before the timelock starts.
  return checkedBlockAdd(
    checkedBlockAdd(
      checkedBlockAdd(maxReviewChallengeEnd(round), CHALLENGE_BLOCKS),
      TIMELOCK_BLOCKS,
    ),
    EXECUTION_WINDOW_BLOCKS,
  );
}

function parseStoredU16(key: string): u16 { return parseU16(getString(key)); }
function activeStake(address: string): u128 {
  const value = getString(activeStakeKey(address));
  return value.length == 0 ? u128.Zero : parseAmount(value);
}

function storedHistoryCount(key: string): i32 {
  if (!hasKey(key)) return 0;
  const count = <i32>parseU16(getString(key));
  assert(count <= MAX_STAKE_HISTORY, "stake history count is corrupt");
  return count;
}

function storedU32(key: string): u32 {
  const value = getString(key);
  return value.length == 0 ? 0 : parseU32(value);
}

function incrementStoredU32(key: string): void {
  setString(key, checkedU32Add(storedU32(key), 1).toString());
}

function markUnique(kind: string, proposalId: string, value: string): bool {
  const key = "unique:" + kind + ":" + proposalId + ":" + value;
  if (hasKey(key)) return false;
  setString(key, "1");
  return true;
}

function metricsKey(address: string): string { return "metrics:" + address; }
function metricsCertificationDescriptorKey(root: string, epoch: u16, descriptorHash: string): string {
  return "metrics-certification:descriptor:" + root + ":" + epoch.toString() + ":" + descriptorHash;
}
function metricsCertificationOwnerKey(root: string, epoch: u16, owner: string): string {
  return "metrics-certification:owner:" + root + ":" + epoch.toString() + ":" + owner;
}
function metricsCertificationCandidateCountKey(root: string, epoch: u16, descriptorHash: string): string {
  return "metrics-certification:candidate-count:" + root + ":" + epoch.toString() + ":" + descriptorHash;
}
function metricsCertificationFinalizedDescriptorKey(root: string, epoch: u16): string {
  return "metrics-certification:finalized:" + root + ":" + epoch.toString();
}
function metricsCertificationConflictKey(root: string, epoch: u16): string {
  return "metrics-certification:conflict:" + root + ":" + epoch.toString();
}
function metricsCertificationCount(root: string, epoch: u16): u32 {
  const descriptorHash = getString(metricsCertificationFinalizedDescriptorKey(root, epoch));
  if (descriptorHash.length == 0) return 0;
  const value = getString(metricsCertificationCandidateCountKey(root, epoch, descriptorHash));
  return value.length == 0 ? 0 : parseU32(value);
}
function activeStakeKey(address: string): string { return "stake:active:" + address; }
function pendingStakeKey(address: string): string { return "stake:pending:" + address; }
function withdrawalKey(address: string): string { return "stake:withdrawal:" + address; }
function stakeSlashReservationKey(address: string): string { return "stake:slash-reservations:" + address; }
function stakeSlashReservationCount(address: string): i32 {
  return storedHistoryCount(stakeSlashReservationKey(address));
}
function setStakeSlashReservationCount(address: string, count: i32): void {
  assert(count >= 0 && count <= MAX_STAKE_HISTORY, "stake-slash reservation count is invalid");
  if (count == 0) removeKey(stakeSlashReservationKey(address));
  else setString(stakeSlashReservationKey(address), count.toString());
}
function stakeLotCountKey(address: string): string { return "stake:lot-count:" + address; }
function stakeLotKey(address: string, index: i32): string { return "stake:lot:" + address + ":" + index.toString(); }
function withdrawalCheckpointCountKey(address: string): string { return "stake:withdrawal-count:" + address; }
function withdrawalCheckpointKey(address: string, index: i32): string {
  return "stake:withdrawal-checkpoint:" + address + ":" + index.toString();
}
function voteKey(proposalId: string, address: string): string { return "vote:" + proposalId + ":" + address; }
function reviewCandidateKey(parent: string, candidate: string, patch: string): string {
  return "review-candidate:" + hashString("IDENA_GOV_REVIEW_CANDIDATE_V1\x00" + parent + "|" + candidate + "|" + patch);
}
function reviewEntryKey(kind: string, reviewRoundId: string, index: u32): string {
  return "review-entry:" + kind + ":" + reviewRoundId + ":" + index.toString();
}
function reviewOwnerEntryCountKey(kind: string, reviewRoundId: string, owner: string): string {
  return "review-owner-count:" + kind + ":" + reviewRoundId + ":" + owner;
}
function candidateArtifactKey(reviewRoundId: string, artifactKey: string): string {
  return "candidate-artifact:" + reviewRoundId + ":" + artifactKey;
}
function reviewCandidateArtifactCountKey(reviewRoundId: string): string {
  return "candidate-artifact-count:" + reviewRoundId;
}
function reviewSourceTransitionKey(reviewRoundId: string): string {
  return "review-source-transition:" + reviewRoundId;
}
function reviewScopeEvidenceKey(reviewRoundId: string): string { return "review-scope-cid:" + reviewRoundId; }
function reviewScopeRiskKey(reviewRoundId: string): string { return "review-scope-risk:" + reviewRoundId; }
function reviewScopeCountersKey(reviewRoundId: string): string { return "review-scope-counters:" + reviewRoundId; }
function reviewPinsetMemberKey(reviewRoundId: string, cid: string): string {
  return "review-pinset:" + reviewRoundId + ":" + cid;
}
function availabilityRequirementCountKey(reviewRoundId: string): string {
  return "availability-requirement-count:" + reviewRoundId;
}
function availabilityRequirementKey(reviewRoundId: string, index: u32): string {
  return "availability-requirement:" + reviewRoundId + ":" + index.toString();
}
function availabilityRequirementMemberKey(reviewRoundId: string, cid: string): string {
  return "availability-requirement-member:" + reviewRoundId + ":" + cid;
}
function availabilityVerifiedCidKey(reviewRoundId: string, attestationCid: string, cid: string): string {
  return "availability-verified:" + reviewRoundId + ":" + attestationCid + ":" + cid;
}
function availabilityAvailableKey(reviewRoundId: string, attestationCid: string): string {
  return "availability-available:" + reviewRoundId + ":" + attestationCid;
}
function availabilityExpiryKey(reviewRoundId: string, attestationCid: string): string {
  return "availability-expiry:" + reviewRoundId + ":" + attestationCid;
}
function agentQualifyingKey(reviewRoundId: string, attestationCid: string): string {
  return "agent-qualifying:" + reviewRoundId + ":" + attestationCid;
}
function buildPassingKey(reviewRoundId: string, attestationCid: string): string {
  return "build-passing:" + reviewRoundId + ":" + attestationCid;
}
function attestationInvalidKey(kind: string, reviewRoundId: string, attestationCid: string): string {
  return "attestation-invalid:" + kind + ":" + reviewRoundId + ":" + attestationCid;
}
function challengePreviousStateKey(proposalId: string): string {
  return "challenge-previous-state:" + proposalId;
}
function reviewAvailabilityMinimumExpiryKey(reviewRoundId: string): string {
  return "review-availability-min-expiry:" + reviewRoundId;
}
function buildDigestCountKey(reviewRoundId: string): string {
  return "build-digest-count:" + reviewRoundId;
}
function buildDigestKey(reviewRoundId: string, index: u32): string {
  return "build-digest:" + reviewRoundId + ":" + index.toString();
}
function buildDigestOwnerCountKey(reviewRoundId: string, digest: string): string {
  return "build-digest-owner-count:" + reviewRoundId + ":" + digest;
}
function buildDigestPlatformCountKey(reviewRoundId: string, digest: string): string {
  return "build-digest-platform-count:" + reviewRoundId + ":" + digest;
}
function releaseReviewCandidate(round: ReviewRound): void {
  const key = reviewCandidateKey(round.parentCid, round.candidateCid, round.patchCid);
  if (getString(key) == round.id) removeKey(key);
}
function releaseReviewCandidateForProposal(proposal: Proposal): void {
  releaseReviewCandidate(loadReviewRound(proposal.reviewRoundId));
}
function attestationMarker(kind: string, proposalId: string, cid: string): string {
  return "attestation:" + kind + ":" + proposalId + ":" + cid;
}
function attestationBondKey(kind: string, proposalId: string, cid: string): string {
  return "bond:" + kind + ":" + proposalId + ":" + cid;
}
function proposalSlashReservationConsumedKey(proposalId: string): string {
  return "slash-reservation-consumed:proposal:" + proposalId;
}
function attestationSlashReservationConsumedKey(kind: string, proposalId: string, cid: string): string {
  return "slash-reservation-consumed:" + kind + ":" + proposalId + ":" + cid;
}
