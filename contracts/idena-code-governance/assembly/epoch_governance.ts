import { u128Safe as u128 } from "as-bignum/assembly";
import {
  argumentString,
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
  ownAddressBytes,
  removeKey,
  requireNoPayment,
  returnString,
  setString,
  stringToBytes,
} from "./host";
import { effectiveVoteWeight, parseAmount, parseU16, parseU32, parseU64, ratioAtLeast, statusBps } from "./math";
import { sha256 } from "./sha256";
import { settledGlobalWeightForEpoch } from "./stake_weight";
import {
  MetricsRecord,
  Proposal,
  STATE_ACCEPTED_PENDING_EXECUTION,
  STATE_ACCEPTED_PENDING_GRACE,
  STATE_CANCELLED_BEFORE_CUTOFF,
  STATE_DRAFT,
  STATE_EXPIRED,
  STATE_NO_QUORUM,
  STATE_PROPOSAL_SET_FROZEN,
  STATE_REJECTED,
  STATE_REVERT_PROPOSED,
  STATE_REVERTED,
  STATE_REVIEW_OPEN,
  STATE_STALE,
  STATE_VOTING_COMMIT,
  STATE_VOTING_REVEAL,
  loadProposal,
  saveProposal,
} from "./state";
import { isCanonicalHash, isCanonicalManifestCid } from "./validation";

const PROFILE_KEY = "epoch-governance:enabled";
const CANONICAL_CID_KEY = "governance:canonical-cid";
const METRICS_ROOT_KEY = "governance:metrics-root";
const METRICS_EPOCH_KEY = "governance:metrics-epoch";
const CHAIN_ID = "idena-mainnet";
const MAX_EPOCH_PROPOSALS: u32 = 64;
const PROPOSAL_CUTOFF_OFFSET: u64 = 40;
const COMMIT_START_OFFSET: u64 = 80;
const COMMIT_END_OFFSET: u64 = 100;
const REVEAL_END_OFFSET: u64 = 120;
const NORMAL_GRACE_BLOCKS: u64 = 60;
const CRITICAL_GRACE_BLOCKS: u64 = 180;
const EXECUTION_WINDOW_BLOCKS: u64 = 600;
const MIN_ACTIVE_STAKE_ATOMS = "1000000000000000000";
const PROCESSING_FEE_ATOMS = "100000000000000000";
const BALLOT_DOMAIN = "IDENA_CODE_DAO_EPOCH_BALLOT_V1";
const PROPOSAL_SET_DOMAIN = "IDENA_CODE_DAO_PROPOSAL_SET_V1";
const MAX_CANONICAL_HISTORY_PAGE: u32 = 64;

export function isEpochGovernanceEnabled(): bool {
  return hasKey(PROFILE_KEY);
}

export function initializeEpochGovernanceProfile(): void {
  assert(!hasKey(PROFILE_KEY), "epoch governance profile is already initialized");
  setString(PROFILE_KEY, "1");
}

export function anchorGovernanceEpoch(): usize {
  ensureInitialized();
  requireNoPayment();
  const epoch = currentEpoch();
  const key = epochAnchorKey(epoch);
  if (!hasKey(key)) {
    const anchor = currentBlock();
    const settledWeight = settledGlobalWeightForEpoch(epoch);
    setString(key, anchor.toString());
    setString(epochTotalWeightKey(epoch), settledWeight);
    setString(epochMetricsRootKey(epoch), getString(METRICS_ROOT_KEY));
    setString(epochMetricsEpochKey(epoch), getString(METRICS_EPOCH_KEY));
    emitVersionedEvent("GovernanceEpochAnchoredV1", [epoch.toString(), anchor.toString()]);
  }
  return governanceScheduleJson(epoch);
}

export function registerEpochProposal(
  proposal: Proposal,
  rollbackManifestCid: string,
  rollbackInstructionsCid: string,
): void {
  if (!isEpochGovernanceEnabled()) return;
  const epoch = currentEpoch();
  const anchor = epochAnchor(epoch);
  assert(currentBlock() >= anchor && currentBlock() < cutoffBlock(epoch), "proposal cutoff has elapsed");
  assert(proposal.stakeEpoch == epoch, "proposal uses another governance epoch");
  const slot = proposalSlotKey(epoch, proposal.proposer);
  assert(!hasKey(slot), "authenticated identity already used its proposal slot this epoch");
  const count = storedU32(epochProposalCountKey(epoch));
  assert(count < MAX_EPOCH_PROPOSALS, "epoch proposal set reached its bounded limit");
  // All validation in createProposal has completed before this atomic write set.
  setString(slot, proposal.id);
  setString(epochProposalKey(epoch, count), proposal.id);
  setString(epochProposalCountKey(epoch), (count + 1).toString());
  setString(proposalRecoveryKey(proposal.id), rollbackManifestCid + "~" + rollbackInstructionsCid);
  emitVersionedEvent("EpochProposalSlotConsumedV1", [epoch.toString(), proposal.proposer, proposal.id]);
}

export function cancelProposalBeforeCutoff(proposalIdPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const epoch = currentEpoch();
  assert(currentBlock() < cutoffBlock(epoch), "proposal cutoff has elapsed");
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  assert(proposal.proposer == callerHex(), "only the authenticated proposer may cancel");
  assert(proposal.stakeEpoch == epoch, "proposal belongs to another governance epoch");
  assert(proposal.state == STATE_DRAFT || proposal.state == STATE_REVIEW_OPEN || proposal.state == STATE_REVERT_PROPOSED, "proposal can no longer be cancelled");
  const fee = minAmount(proposal.bondAmount(), parseAmount(PROCESSING_FEE_ATOMS));
  proposal.refundableBond = (proposal.bondAmount() - fee).toString();
  proposal.state = STATE_CANCELLED_BEFORE_CUTOFF;
  saveProposal(proposal);
  addTreasury(fee);
  emitVersionedEvent("EpochProposalCancelledV1", [epoch.toString(), proposal.id, fee.toString()]);
  return epochProposalStateJson(proposal);
}

export function getProposalSlot(epochPtr: usize, addressPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const epoch = parseU16(argumentString(epochPtr, 5));
  const address = canonicalAddress(argumentString(addressPtr, 42));
  const proposalId = getString(proposalSlotKey(epoch, address));
  return returnString(
    "{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString()
      + ",\"address\":\"0x" + address + "\",\"used\":" + (proposalId.length > 0 ? "true" : "false")
      + ",\"proposalId\":" + (proposalId.length > 0 ? "\"" + proposalId + "\"" : "null") + "}",
  );
}

export function freezeEpochProposalSet(): usize {
  ensureEpochMode();
  requireNoPayment();
  const epoch = currentEpoch();
  assert(currentBlock() >= cutoffBlock(epoch) && currentBlock() < commitStartBlock(epoch), "epoch proposal set cannot be frozen now");
  assert(!hasKey(epochFrozenRootKey(epoch)), "epoch proposal set is already frozen");
  const submittedCount = storedU32(epochProposalCountKey(epoch));
  const ids = new Array<string>();
  for (let i: u32 = 0; i < submittedCount; i++) {
    const id = getString(epochProposalKey(epoch, i));
    const proposal = loadProposal(id);
    if (proposal.state == STATE_CANCELLED_BEFORE_CUTOFF) continue;
    if (proposal.state == STATE_DRAFT) {
      settleIncompleteProposal(proposal);
      continue;
    }
    assert(proposal.state == STATE_REVIEW_OPEN || proposal.state == STATE_REVERT_PROPOSED, "proposal is not freeze-ready");
    ids.push(id);
  }
  ids.sort();
  const root = proposalSetRoot(epoch, ids);
  setString(epochFrozenRootKey(epoch), root);
  setString(epochFrozenCountKey(epoch), ids.length.toString());
  setString(epochFrozenAtKey(epoch), currentBlock().toString());
  for (let i = 0; i < ids.length; i++) {
    setString(epochFrozenProposalKey(epoch, <u32>i), ids[i]);
    const proposal = loadProposal(ids[i]);
    proposal.state = STATE_PROPOSAL_SET_FROZEN;
    proposal.snapshotWeight = getString(epochTotalWeightKey(epoch));
    saveProposal(proposal);
  }
  emitVersionedEvent("EpochProposalSetFrozenV1", [epoch.toString(), root, ids.length.toString()]);
  return epochProposalSetJson(epoch);
}

export function getEpochProposalSet(epochPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  return epochProposalSetJson(parseU16(argumentString(epochPtr, 5)));
}

export function attachAiReviewRoot(proposalIdPtr: usize, rootPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  const root = validHash(argumentString(rootPtr, 64));
  assert(currentBlock() < commitStartBlock(proposal.stakeEpoch), "review window has closed");
  assert(root == proposal.agentRoot, "AI review root does not match immutable proposal content");
  return epochProposalStateJson(proposal);
}

export function attachBuildRoot(proposalIdPtr: usize, rootPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  const root = validHash(argumentString(rootPtr, 64));
  assert(currentBlock() < commitStartBlock(proposal.stakeEpoch), "review window has closed");
  assert(root == proposal.buildRoot, "build root does not match immutable proposal content");
  return epochProposalStateJson(proposal);
}

export function attachRecoveryManifest(
  proposalIdPtr: usize,
  rollbackManifestCidPtr: usize,
  rollbackInstructionsCidPtr: usize,
): usize {
  ensureEpochMode();
  requireNoPayment();
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  const rollback = argumentString(rollbackManifestCidPtr, 128);
  const instructions = argumentString(rollbackInstructionsCidPtr, 128);
  assert(isCanonicalManifestCid(rollback) && isCanonicalManifestCid(instructions), "recovery metadata must use canonical DAG-CBOR CIDs");
  const key = proposalRecoveryKey(proposal.id);
  assert(getString(key) == rollback + "~" + instructions, "recovery metadata differs from the immutable proposal payload");
  return returnString("{\"ok\":true,\"proposalId\":\"" + proposal.id + "\"}");
}

export function commitEpochBallot(commitmentPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const epoch = currentEpoch();
  assert(hasKey(epochFrozenRootKey(epoch)), "epoch proposal set is not frozen");
  assert(currentBlock() >= commitStartBlock(epoch) && currentBlock() < commitEndBlock(epoch), "ballot commit window is closed");
  const commitment = validHash(argumentString(commitmentPtr, 64));
  const voter = callerHex();
  const key = ballotReceiptKey(epoch, voter);
  assert(!hasKey(key), "identity already committed an epoch ballot");
  const snapshot = epochVotingPower(epoch, voter);
  assert(!snapshot.weight.isZero(), "voter has zero snapshotted governance weight");
  setString(key, commitment + "~" + snapshot.weight.toString() + "~" + snapshot.state + "~0~");
  const count = storedU32(epochFrozenCountKey(epoch));
  for (let i: u32 = 0; i < count; i++) {
    const proposal = loadProposal(getString(epochFrozenProposalKey(epoch, i)));
    if (proposal.state == STATE_PROPOSAL_SET_FROZEN) {
      proposal.state = STATE_VOTING_COMMIT;
      saveProposal(proposal);
    }
  }
  emitVersionedEvent("EpochBallotCommittedV1", [epoch.toString(), voter, commitment, snapshot.weight.toString()]);
  return epochBallotReceiptJson(epoch, voter);
}

export function revealEpochBallot(choicesPtr: usize, noncePtr: usize, saltPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const epoch = currentEpoch();
  assert(currentBlock() >= commitEndBlock(epoch) && currentBlock() < revealEndBlock(epoch), "ballot reveal window is closed");
  const voter = callerHex();
  const receiptKey = ballotReceiptKey(epoch, voter);
  const receipt = getString(receiptKey).split("~");
  assert(receipt.length == 5 && receipt[3] == "0", "ballot commitment is missing or already revealed");
  const choicesEncoding = argumentString(choicesPtr, 8192);
  const choices = parseAndValidateChoices(epoch, choicesEncoding);
  const nonce = parseU64(argumentString(noncePtr, 20));
  const salt = validHash(argumentString(saltPtr, 64));
  const computed = epochBallotCommitment(epoch, voter, choices, nonce, salt);
  assert(computed == receipt[0], "ballot reveal does not match the commitment");
  const weight = parseAmount(receipt[1]);
  const state = receipt[2];
  for (let i = 0; i < choices.length; i++) {
    const fields = choices[i].split(":");
    const proposal = loadProposal(fields[0]);
    assert(proposal.state == STATE_VOTING_COMMIT || proposal.state == STATE_VOTING_REVEAL, "proposal is not in epoch voting");
    addEpochVote(proposal, fields[1], weight, state);
    proposal.state = STATE_VOTING_REVEAL;
    saveProposal(proposal);
  }
  setString(receiptKey, receipt[0] + "~" + receipt[1] + "~" + state + "~1~" + choicesEncoding);
  emitVersionedEvent("EpochBallotRevealedV1", [epoch.toString(), voter, getString(epochFrozenRootKey(epoch))]);
  return epochBallotReceiptJson(epoch, voter);
}

export function finalizeEpochVoting(): usize {
  ensureEpochMode();
  requireNoPayment();
  const epoch = currentEpoch();
  assert(currentBlock() >= revealEndBlock(epoch), "reveal window has not ended");
  assert(!hasKey(epochFinalizedKey(epoch)), "epoch voting is already finalized");
  const count = storedU32(epochFrozenCountKey(epoch));
  for (let i: u32 = 0; i < count; i++) {
    const proposal = loadProposal(getString(epochFrozenProposalKey(epoch, i)));
    assert(proposal.state == STATE_VOTING_COMMIT || proposal.state == STATE_VOTING_REVEAL || proposal.state == STATE_PROPOSAL_SET_FROZEN, "proposal cannot be finalized");
    if (proposal.parentCid != getString(CANONICAL_CID_KEY)) {
      settleEpochStale(proposal);
      storeEpochDecisionRecord(proposal, epoch, currentBlock());
      continue;
    }
    const critical = proposal.isCritical();
    const quorumBps: u16 = critical ? 3000 : 2000;
    const yesBps: u16 = critical ? 7500 : 6667;
    const participantMinimum: u32 = critical ? 12 : 7;
    const yesMinimum: u32 = critical ? 12 : 7;
    const strongMinimum: u32 = critical ? 5 : 3;
    const decisive = checkedAmountAdd(proposal.yesWeightAmount(), proposal.noWeightAmount());
    const turnout = checkedAmountAdd(decisive, proposal.abstainWeightAmount());
    const participants = storedU32(epochParticipantCountKey(proposal.id));
    const quorum = ratioAtLeast(turnout, proposal.snapshotWeightAmount(), quorumBps) && participants >= participantMinimum;
    if (!epochAttestationGatesPass(proposal)) {
      settleIncompleteProposal(proposal);
      storeEpochDecisionRecord(proposal, epoch, currentBlock());
      continue;
    }
    if (!quorum) {
      settleNoQuorum(proposal);
      storeEpochDecisionRecord(proposal, epoch, currentBlock());
      continue;
    }
    const approved = ratioAtLeast(proposal.yesWeightAmount(), decisive, yesBps)
      && proposal.yesIdentities >= yesMinimum
      && proposal.yesStrongIdentities >= strongMinimum;
    if (!approved) {
      settleEpochRejected(proposal);
      storeEpochDecisionRecord(proposal, epoch, currentBlock());
      continue;
    }
    const grace = critical ? CRITICAL_GRACE_BLOCKS : NORMAL_GRACE_BLOCKS;
    proposal.challengeEnd = checkedBlockAdd(currentBlock(), grace);
    proposal.executeAfter = proposal.challengeEnd;
    proposal.state = STATE_ACCEPTED_PENDING_GRACE;
    saveProposal(proposal);
    storeEpochDecisionRecord(proposal, epoch, currentBlock());
    emitVersionedEvent("ProposalGracePeriodV1", [proposal.id, proposal.challengeEnd.toString()]);
  }
  setString(epochFinalizedKey(epoch), currentBlock().toString());
  return epochProposalSetJson(epoch);
}

export function enterExecutionReadyState(proposalIdPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  assert(proposal.state == STATE_ACCEPTED_PENDING_GRACE, "proposal is not in grace");
  assert(currentBlock() >= proposal.challengeEnd, "grace period has not elapsed");
  proposal.state = STATE_ACCEPTED_PENDING_EXECUTION;
  proposal.executeAfter = currentBlock();
  saveProposal(proposal);
  emitVersionedEvent("ProposalExecutionReadyV1", [proposal.id, proposal.executeAfter.toString()]);
  return epochProposalStateJson(proposal);
}

export function createRevertProposal(proposalIdPtr: usize, executionIndexPtr: usize): usize {
  ensureEpochMode();
  requireNoPayment();
  const proposal = loadProposal(validHash(argumentString(proposalIdPtr, 64)));
  assert(proposal.proposer == callerHex(), "only the authenticated proposer may bind a revert");
  assert(proposal.state == STATE_REVIEW_OPEN, "revert binding requires a review-open proposal");
  const index = parseU32(argumentString(executionIndexPtr, 10));
  const history = getString(canonicalHistoryEntryKey(index)).split("~");
  assert(history.length == 11, "referenced canonical execution does not exist");
  assert(history[2] == getString(CANONICAL_CID_KEY), "revert target is not currently canonical");
  assert(proposal.parentCid == history[2] && proposal.candidateCid == history[1], "revert proposal does not restore the referenced parent");
  setString(revertExecutionKey(proposal.id), history[0]);
  proposal.state = STATE_REVERT_PROPOSED;
  saveProposal(proposal);
  emitVersionedEvent("RevertProposalBoundV1", [proposal.id, history[0], history[2], history[1]]);
  return epochProposalStateJson(proposal);
}

export function isBoundRevertProposal(proposalId: string): bool {
  return hasKey(revertExecutionKey(proposalId));
}

export function recordEpochExecution(proposal: Proposal, oldCid: string): void {
  if (!isEpochGovernanceEnabled()) return;
  const index = storedU32(canonicalHistoryCountKey());
  assert(index < u32.MAX_VALUE, "canonical history counter overflow");
  const executionId = hashText("IDENA_CODE_DAO_EXECUTION_V1" + index.toString() + proposal.id + oldCid + proposal.candidateCid);
  const recovery = getString(proposalRecoveryKey(proposal.id)).split("~");
  assert(recovery.length == 2, "execution requires immutable recovery metadata");
  const decisionRecordCid = getString(epochDecisionRecordCidKey(proposal.id));
  assert(decisionRecordCid.length > 0, "execution requires a deterministic decision record CID");
  const revertOf = getString(revertExecutionKey(proposal.id));
  const observationEnd = checkedBlockAdd(currentBlock(), EXECUTION_WINDOW_BLOCKS);
  setString(
    canonicalHistoryEntryKey(index),
    executionId + "~" + oldCid + "~" + proposal.candidateCid + "~" + proposal.id + "~"
      + proposal.stakeEpoch.toString() + "~" + decisionRecordCid + "~" + currentBlock().toString() + "~"
      + recovery[0] + "~" + recovery[1] + "~" + observationEnd.toString() + "~" + revertOf,
  );
  setString(canonicalHistoryCountKey(), (index + 1).toString());
  if (revertOf.length > 0) proposal.state = STATE_REVERTED;
  emitVersionedEvent("CanonicalHistoryAppendedV1", [executionId, oldCid, proposal.candidateCid, proposal.id, revertOf]);
}

export function getCanonicalHistory(): usize {
  ensureInitialized();
  requireNoPayment();
  return canonicalHistoryPageJson(0, MAX_CANONICAL_HISTORY_PAGE);
}

export function getCanonicalHistoryPage(startPtr: usize, limitPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const start = parseU32(argumentString(startPtr, 10));
  const limit = parseU32(argumentString(limitPtr, 3));
  assert(limit > 0 && limit <= MAX_CANONICAL_HISTORY_PAGE, "canonical history page limit is invalid");
  return canonicalHistoryPageJson(start, limit);
}

function canonicalHistoryPageJson(start: u32, limit: u32): usize {
  const count = storedU32(canonicalHistoryCountKey());
  assert(start <= count, "canonical history page start exceeds the history length");
  const remaining = count - start;
  const length = remaining < limit ? remaining : limit;
  const end = start + length;
  let entries = "[";
  for (let i: u32 = start; i < end; i++) {
    if (i > start) entries += ",";
    const f = getString(canonicalHistoryEntryKey(i)).split("~");
    assert(f.length == 11, "corrupt canonical history");
    entries += "{\"executionId\":\"" + f[0] + "\",\"previousCid\":\"" + f[1]
      + "\",\"newCid\":\"" + f[2] + "\",\"proposalId\":\"" + f[3]
      + "\",\"governanceEpoch\":" + f[4] + ",\"decisionRecordCid\":\"" + f[5]
      + "\",\"executionBlock\":" + f[6] + ",\"rollbackManifestCid\":\"" + f[7]
      + "\",\"rollbackInstructionsCid\":\"" + f[8] + "\",\"observationWindowEnd\":" + f[9]
      + ",\"revertsExecutionId\":" + (f[10].length > 0 ? "\"" + f[10] + "\"" : "null") + "}";
  }
  return returnString(
    "{\"schemaVersion\":1,\"totalCount\":" + count.toString()
      + ",\"start\":" + start.toString() + ",\"entries\":" + entries
      + "],\"nextStart\":" + (end < count ? end.toString() : "null") + "}",
  );
}

export function getGovernanceSchedule(epochPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  return governanceScheduleJson(parseU16(argumentString(epochPtr, 5)));
}

export function getGovernanceEpoch(): usize {
  ensureInitialized();
  requireNoPayment();
  return returnString("{\"schemaVersion\":1,\"governanceEpoch\":" + currentEpoch().toString() + "}");
}

export function previewVotingPower(epochPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const epoch = parseU16(argumentString(epochPtr, 5));
  const snapshot = epochVotingPower(epoch, callerHex());
  return returnString(
    "{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString() + ",\"activeStakeAtoms\":\""
      + snapshot.stake.toString() + "\",\"identityState\":\"" + snapshot.state
      + "\",\"flipTrustBps\":" + snapshot.trust.toString() + ",\"effectiveVoteWeight\":\""
      + snapshot.weight.toString() + "\"}",
  );
}

export function getEpochBallotReceipt(epochPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  return epochBallotReceiptJson(parseU16(argumentString(epochPtr, 5)), callerHex());
}

export function getEpochDecisionRecord(proposalIdPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const proposalId = validHash(argumentString(proposalIdPtr, 64));
  const cid = getString(epochDecisionRecordCidKey(proposalId));
  const record = getString(epochDecisionRecordKey(proposalId));
  assert(cid.length > 0 && record.length > 0, "epoch decision record is not available");
  return returnString(
    "{\"schemaVersion\":1,\"decisionRecordCid\":\"" + cid + "\",\"record\":" + record + "}",
  );
}

export function getTreasuryState(): usize {
  ensureInitialized();
  requireNoPayment();
  const value = getString(treasuryKey());
  return returnString("{\"schemaVersion\":1,\"communityExecutionTreasuryAtoms\":\"" + (value.length == 0 ? "0" : value) + "\",\"ownerWithdrawalAvailable\":false}");
}

export function epochBallotCommitment(
  epoch: u16,
  voter: string,
  choices: string[],
  nonce: u64,
  salt: string,
): string {
  const chain = stringToBytes(CHAIN_ID);
  const contract = ownAddressBytes();
  const voterBytes = hexToBytes(voter);
  const root = hexToBytes(getString(epochFrozenRootKey(epoch)));
  const saltBytes = hexToBytes(validHash(salt));
  let length = BALLOT_DOMAIN.length + 4 + chain.length + 20 + 8 + 20 + 32 + 4 + choices.length + 8 + 32;
  const bytes = new Uint8Array(length);
  let offset = 0;
  offset = writeBytes(bytes, offset, stringToBytes(BALLOT_DOMAIN));
  offset = writeU32(bytes, offset, <u32>chain.length);
  offset = writeBytes(bytes, offset, chain);
  offset = writeBytes(bytes, offset, contract);
  offset = writeU64(bytes, offset, <u64>epoch);
  offset = writeBytes(bytes, offset, voterBytes);
  offset = writeBytes(bytes, offset, root);
  offset = writeU32(bytes, offset, <u32>choices.length);
  for (let i = 0; i < choices.length; i++) {
    const fields = choices[i].split(":");
    bytes[offset++] = fields[1] == "yes" ? 1 : fields[1] == "no" ? 2 : 3;
  }
  offset = writeU64(bytes, offset, nonce);
  offset = writeBytes(bytes, offset, saltBytes);
  assert(offset == bytes.length, "ballot commitment encoding length mismatch");
  return bytesToHex(sha256(bytes));
}

class EpochVotingPower {
  constructor(public stake: u128, public state: string, public trust: u16, public weight: u128) {}
}

function epochVotingPower(epoch: u16, address: string): EpochVotingPower {
  const anchor = epochAnchor(epoch);
  const metrics = MetricsRecord.decode(getString(metricsKey(address)));
  assert(
    metrics.root == getString(epochMetricsRootKey(epoch))
      && metrics.sourceEpoch == parseU16(getString(epochMetricsEpochKey(epoch))),
    "identity metrics proof does not match the epoch snapshot",
  );
  assert(metrics.registeredBlock < anchor, "identity proof was registered after the epoch snapshot");
  const stake = stakeAt(address, epoch, anchor);
  assert(stake >= parseAmount(MIN_ACTIVE_STAKE_ATOMS), "active stake is below the governance minimum");
  return new EpochVotingPower(stake, metrics.state, metrics.trustBps, effectiveVoteWeight(stake, statusBps(metrics.state), metrics.trustBps));
}

function stakeAt(address: string, snapshotEpoch: u16, snapshotBlock: u64): u128 {
  let total = u128.Zero;
  const lotCount = storedU16(stakeLotCountKey(address));
  for (let i: u16 = 0; i < lotCount; i++) {
    const lot = getString(stakeLotKey(address, i)).split("~");
    assert(lot.length == 3, "corrupt immutable stake lot");
    if (parseU16(lot[1]) <= snapshotEpoch && parseU64(lot[2]) < snapshotBlock) {
      total = checkedAmountAdd(total, parseAmount(lot[0]));
    }
  }
  let withdrawn = u128.Zero;
  const withdrawalCount = storedU16(withdrawalCheckpointCountKey(address));
  for (let i: u16 = 0; i < withdrawalCount; i++) {
    const checkpoint = getString(withdrawalCheckpointKey(address, i)).split("~");
    assert(checkpoint.length == 2, "corrupt immutable withdrawal checkpoint");
    if (parseU64(checkpoint[1]) < snapshotBlock) {
      withdrawn = checkedAmountAdd(withdrawn, parseAmount(checkpoint[0]));
    }
  }
  assert(total >= withdrawn, "withdrawal history exceeds deposited stake");
  return total - withdrawn;
}

function addEpochVote(proposal: Proposal, choice: string, weight: u128, state: string): void {
  incrementU32(epochParticipantCountKey(proposal.id));
  if (choice == "yes") {
    proposal.yesWeight = checkedAmountAdd(proposal.yesWeightAmount(), weight).toString();
    assert(proposal.yesIdentities < u32.MAX_VALUE, "yes-identity counter overflow");
    proposal.yesIdentities++;
    if (state == "Human" || state == "Verified") {
      assert(proposal.yesStrongIdentities < u32.MAX_VALUE, "strong-identity counter overflow");
      proposal.yesStrongIdentities++;
    }
  } else if (choice == "no") {
    proposal.noWeight = checkedAmountAdd(proposal.noWeightAmount(), weight).toString();
  } else {
    proposal.abstainWeight = checkedAmountAdd(proposal.abstainWeightAmount(), weight).toString();
  }
}

export function epochAttestationGatesPass(proposal: Proposal): bool {
  const minimumAgents: u32 = proposal.isCritical() ? 3 : 2;
  const minimumFamilies: u32 = proposal.isCritical() ? 2 : 1;
  const minimumBuilders: u32 = proposal.isCritical() ? 3 : 2;
  const minimumBuilderPlatforms: u32 = proposal.isCritical() ? 2 : 1;
  const minimumAvailabilityProviders: u32 = proposal.isCritical() ? 3 : 2;
  const minimumExpiryValue = getString(reviewAvailabilityMinimumExpiryKey(proposal.reviewRoundId));
  const grace = proposal.isCritical() ? CRITICAL_GRACE_BLOCKS : NORMAL_GRACE_BLOCKS;
  const requiredAvailabilityUntil = checkedBlockAdd(
    checkedBlockAdd(currentBlock(), grace),
    EXECUTION_WINDOW_BLOCKS,
  );
  return proposal.agentSubmittedCount == proposal.agentLeafCount
    && proposal.buildSubmittedCount == proposal.buildLeafCount
    && proposal.availabilitySubmittedCount == proposal.availabilityLeafCount
    && proposal.agentCount >= minimumAgents
    && proposal.agentModelCount >= minimumFamilies
    && proposal.agentOwnerCount >= (proposal.isCritical() ? 3 : 2)
    && (proposal.unresolvedCriticalCount == 0 || proposal.waiverCid.length > 0)
    && proposal.builderOwnerCount >= minimumBuilders
    && proposal.builderPlatformCount >= minimumBuilderPlatforms
    && proposal.builderConflictCount == 0
    && proposal.artifactDigest.length == 64
    && proposal.availabilityOwnerCount >= minimumAvailabilityProviders
    && minimumExpiryValue.length > 0
    && parseU64(minimumExpiryValue) >= requiredAvailabilityUntil;
}

function settleNoQuorum(proposal: Proposal): void {
  const fee = minAmount(proposal.bondAmount(), parseAmount(PROCESSING_FEE_ATOMS));
  proposal.refundableBond = (proposal.bondAmount() - fee).toString();
  proposal.state = STATE_NO_QUORUM;
  saveProposal(proposal);
  addTreasury(fee);
  emitVersionedEvent("ProposalNoQuorumV1", [proposal.id, proposal.refundableBond, fee.toString()]);
}

function settleIncompleteProposal(proposal: Proposal): void {
  const fee = minAmount(proposal.bondAmount(), parseAmount(PROCESSING_FEE_ATOMS));
  proposal.refundableBond = (proposal.bondAmount() - fee).toString();
  proposal.state = STATE_EXPIRED;
  saveProposal(proposal);
  addTreasury(fee);
}

function settleEpochRejected(proposal: Proposal): void {
  const half = proposal.bondAmount() / u128.fromU64(2);
  const treasury = proposal.bondAmount() - half;
  proposal.refundableBond = "0";
  proposal.state = STATE_REJECTED;
  saveProposal(proposal);
  if (!half.isZero()) burn(half);
  addTreasury(treasury);
  emitVersionedEvent("ProposalRejectedByEpochV1", [proposal.id, half.toString(), treasury.toString()]);
}

function settleEpochStale(proposal: Proposal): void {
  const fee = minAmount(proposal.bondAmount(), parseAmount(PROCESSING_FEE_ATOMS));
  proposal.refundableBond = (proposal.bondAmount() - fee).toString();
  proposal.state = STATE_STALE;
  saveProposal(proposal);
  addTreasury(fee);
}

function parseAndValidateChoices(epoch: u16, encoding: string): string[] {
  const count = storedU32(epochFrozenCountKey(epoch));
  const choices = encoding.length == 0 ? new Array<string>() : encoding.split(",");
  assert(choices.length == count, "ballot must cover every frozen proposal exactly once");
  for (let i: u32 = 0; i < count; i++) {
    const fields = choices[i].split(":");
    assert(fields.length == 2, "invalid ballot choice encoding");
    assert(fields[0] == getString(epochFrozenProposalKey(epoch, i)), "ballot proposal ordering differs from the frozen set");
    assert(fields[1] == "yes" || fields[1] == "no" || fields[1] == "abstain", "invalid ballot choice");
  }
  return choices;
}

function proposalSetRoot(epoch: u16, ids: string[]): string {
  let length = PROPOSAL_SET_DOMAIN.length + 8 + 4;
  for (let i = 0; i < ids.length; i++) length += 4 + ids[i].length;
  const bytes = new Uint8Array(length);
  let offset = writeBytes(bytes, 0, stringToBytes(PROPOSAL_SET_DOMAIN));
  offset = writeU64(bytes, offset, <u64>epoch);
  offset = writeU32(bytes, offset, <u32>ids.length);
  for (let i = 0; i < ids.length; i++) {
    const value = stringToBytes(ids[i]);
    offset = writeU32(bytes, offset, <u32>value.length);
    offset = writeBytes(bytes, offset, value);
  }
  assert(offset == bytes.length, "proposal-set root encoding length mismatch");
  return bytesToHex(sha256(bytes));
}

function storeEpochDecisionRecord(proposal: Proposal, epoch: u16, finalizedBlock: u64): void {
  assert(!hasKey(epochDecisionRecordKey(proposal.id)), "epoch decision record is immutable");
  const participants = storedU32(epochParticipantCountKey(proposal.id));
  const record = "{\"schemaVersion\":1,\"proposalId\":\"" + proposal.id
    + "\",\"parameterSetCid\":\"" + getString("governance:parameter-cid")
    + "\",\"governanceEpoch\":" + epoch.toString()
    + ",\"proposalSetRoot\":\"" + getString(epochFrozenRootKey(epoch))
    + "\",\"yesWeight\":\"" + proposal.yesWeight
    + "\",\"noWeight\":\"" + proposal.noWeight
    + "\",\"abstainWeight\":\"" + proposal.abstainWeight
    + "\",\"totalRegisteredWeight\":\"" + proposal.snapshotWeight
    + "\",\"distinctParticipants\":" + participants.toString()
    + ",\"distinctYesIdentities\":" + proposal.yesIdentities.toString()
    + ",\"verifiedOrHumanYesIdentities\":" + proposal.yesStrongIdentities.toString()
    + ",\"state\":\"" + epochStateName(proposal.state)
    + "\",\"finalizedAtBlock\":" + finalizedBlock.toString()
    + ",\"graceEndBlock\":" + (proposal.state == STATE_ACCEPTED_PENDING_GRACE ? proposal.challengeEnd.toString() : "null")
    + "}";
  setString(epochDecisionRecordKey(proposal.id), record);
  setString(epochDecisionRecordCidKey(proposal.id), rawCidV1(stringToBytes(record)));
}

function rawCidV1(value: Uint8Array): string {
  const digest = sha256(value);
  const bytes = new Uint8Array(36);
  bytes[0] = 1;
  bytes[1] = 0x55;
  bytes[2] = 0x12;
  bytes[3] = 0x20;
  memory.copy(bytes.dataStart + 4, digest.dataStart, digest.length);
  return base32Lower(bytes);
}

function base32Lower(value: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let result = "b";
  let buffer: u32 = 0;
  let bits: u8 = 0;
  for (let i = 0; i < value.length; i++) {
    buffer = (buffer << 8) | value[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet.charAt(<i32>((buffer >> bits) & 31));
    }
    if (bits == 0) buffer = 0;
    else buffer &= (1 << bits) - 1;
  }
  if (bits > 0) result += alphabet.charAt(<i32>((buffer << (5 - bits)) & 31));
  return result;
}

function governanceScheduleJson(epoch: u16): usize {
  const anchor = epochAnchor(epoch);
  return returnString(
    "{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString() + ",\"epochAnchorBlock\":" + anchor.toString()
      + ",\"proposalCutoffBlock\":" + cutoffBlock(epoch).toString() + ",\"commitStartBlock\":" + commitStartBlock(epoch).toString()
      + ",\"commitEndBlock\":" + commitEndBlock(epoch).toString() + ",\"revealEndBlock\":" + revealEndBlock(epoch).toString() + "}",
  );
}

function epochProposalSetJson(epoch: u16): usize {
  const root = getString(epochFrozenRootKey(epoch));
  const count = storedU32(epochFrozenCountKey(epoch));
  let proposals = "[";
  for (let i: u32 = 0; i < count; i++) {
    if (i > 0) proposals += ",";
    const proposal = loadProposal(getString(epochFrozenProposalKey(epoch, i)));
    proposals += "{\"proposalId\":\"" + proposal.id + "\",\"state\":\"" + epochStateName(proposal.state) + "\"}";
  }
  return returnString(
    "{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString() + ",\"frozen\":" + (root.length > 0 ? "true" : "false")
      + ",\"frozenRoot\":" + (root.length > 0 ? "\"" + root + "\"" : "null") + ",\"proposals\":" + proposals + "]}",
  );
}

function epochBallotReceiptJson(epoch: u16, voter: string): usize {
  const value = getString(ballotReceiptKey(epoch, voter));
  if (value.length == 0) return returnString("{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString() + ",\"committed\":false,\"revealed\":false}");
  const f = value.split("~");
  assert(f.length == 5, "corrupt epoch ballot receipt");
  return returnString(
    "{\"schemaVersion\":1,\"governanceEpoch\":" + epoch.toString() + ",\"committed\":true,\"revealed\":" + (f[3] == "1" ? "true" : "false")
      + ",\"commitment\":\"" + f[0] + "\",\"effectiveVoteWeight\":\"" + f[1] + "\"}",
  );
}

function epochProposalStateJson(proposal: Proposal): usize {
  return returnString("{\"proposalId\":\"" + proposal.id + "\",\"state\":\"" + epochStateName(proposal.state) + "\"}");
}

function epochStateName(state: u8): string {
  if (state == STATE_DRAFT) return "Submitted";
  if (state == STATE_REVIEW_OPEN) return "ReviewOpen";
  if (state == STATE_PROPOSAL_SET_FROZEN) return "ProposalSetFrozen";
  if (state == STATE_VOTING_COMMIT) return "VotingCommit";
  if (state == STATE_VOTING_REVEAL) return "VotingReveal";
  if (state == STATE_REJECTED) return "Rejected";
  if (state == STATE_NO_QUORUM) return "NoQuorum";
  if (state == STATE_ACCEPTED_PENDING_GRACE) return "AcceptedPendingGrace";
  if (state == STATE_ACCEPTED_PENDING_EXECUTION) return "AcceptedPendingExecution";
  if (state == STATE_CANCELLED_BEFORE_CUTOFF) return "CancelledBeforeCutoff";
  if (state == STATE_REVERT_PROPOSED) return "RevertProposed";
  if (state == STATE_REVERTED) return "Reverted";
  if (state == STATE_STALE) return "Stale";
  if (state == STATE_EXPIRED) return "Expired";
  return "Unknown";
}

function epochAnchor(epoch: u16): u64 {
  const value = getString(epochAnchorKey(epoch));
  assert(value.length > 0, "governance epoch has not been anchored");
  return parseU64(value);
}

function cutoffBlock(epoch: u16): u64 { return checkedBlockAdd(epochAnchor(epoch), PROPOSAL_CUTOFF_OFFSET); }
function commitStartBlock(epoch: u16): u64 { return checkedBlockAdd(epochAnchor(epoch), COMMIT_START_OFFSET); }
function commitEndBlock(epoch: u16): u64 { return checkedBlockAdd(epochAnchor(epoch), COMMIT_END_OFFSET); }
function revealEndBlock(epoch: u16): u64 { return checkedBlockAdd(epochAnchor(epoch), REVEAL_END_OFFSET); }

function checkedBlockAdd(value: u64, delta: u64): u64 {
  assert(value <= u64.MAX_VALUE - delta, "block arithmetic overflow");
  return value + delta;
}

function writeBytes(target: Uint8Array, offset: i32, value: Uint8Array): i32 {
  memory.copy(target.dataStart + offset, value.dataStart, value.length);
  return offset + value.length;
}

function writeU32(target: Uint8Array, offset: i32, value: u32): i32 {
  target[offset] = <u8>(value >> 24);
  target[offset + 1] = <u8>(value >> 16);
  target[offset + 2] = <u8>(value >> 8);
  target[offset + 3] = <u8>value;
  return offset + 4;
}

function writeU64(target: Uint8Array, offset: i32, value: u64): i32 {
  for (let i = 7; i >= 0; i--) {
    target[offset + i] = <u8>value;
    value >>= 8;
  }
  return offset + 8;
}

function hashText(value: string): string { return bytesToHex(sha256(stringToBytes(value))); }
function validHash(value: string): string { assert(isCanonicalHash(value), "value must be lowercase SHA-256"); return value; }
function minAmount(left: u128, right: u128): u128 { return left < right ? left : right; }
function canonicalAddress(value: string): string {
  assert(value.length == 42 && value.startsWith("0x"), "address must be canonical 0x hex");
  const hex = value.substring(2);
  assert(hexToBytes(hex).length == 20 && hex == hex.toLowerCase(), "address must be canonical lowercase hex");
  return hex;
}

function ensureInitialized(): void { assert(hasKey(CANONICAL_CID_KEY), "contract is not initialized"); }
function ensureEpochMode(): void { ensureInitialized(); assert(isEpochGovernanceEnabled(), "epoch governance profile is not enabled"); }
function storedU32(key: string): u32 { const value = getString(key); return value.length == 0 ? 0 : parseU32(value); }
function storedU16(key: string): u16 { const value = getString(key); return value.length == 0 ? 0 : parseU16(value); }
function incrementU32(key: string): void { const value = storedU32(key); assert(value < u32.MAX_VALUE, "counter overflow"); setString(key, (value + 1).toString()); }
function addTreasury(value: u128): void {
  if (value.isZero()) return;
  const current = getString(treasuryKey());
  const amount = current.length == 0 ? u128.Zero : parseAmount(current);
  setString(treasuryKey(), checkedAmountAdd(amount, value).toString());
}
function checkedAmountAdd(left: u128, right: u128): u128 {
  const result = left + right;
  assert(result >= left, "governance amount overflow");
  return result;
}

function epochAnchorKey(epoch: u16): string { return "epoch-governance:anchor:" + epoch.toString(); }
function epochMetricsRootKey(epoch: u16): string { return "epoch-governance:metrics-root:" + epoch.toString(); }
function epochMetricsEpochKey(epoch: u16): string { return "epoch-governance:metrics-epoch:" + epoch.toString(); }
function epochTotalWeightKey(epoch: u16): string { return "epoch-governance:weight:" + epoch.toString(); }
function epochProposalCountKey(epoch: u16): string { return "epoch-governance:proposal-count:" + epoch.toString(); }
function epochProposalKey(epoch: u16, index: u32): string { return "epoch-governance:proposal:" + epoch.toString() + ":" + index.toString(); }
function proposalSlotKey(epoch: u16, address: string): string { return "epoch-governance:slot:" + epoch.toString() + ":" + address; }
function epochFrozenRootKey(epoch: u16): string { return "epoch-governance:frozen-root:" + epoch.toString(); }
function epochFrozenCountKey(epoch: u16): string { return "epoch-governance:frozen-count:" + epoch.toString(); }
function epochFrozenAtKey(epoch: u16): string { return "epoch-governance:frozen-at:" + epoch.toString(); }
function epochFrozenProposalKey(epoch: u16, index: u32): string { return "epoch-governance:frozen:" + epoch.toString() + ":" + index.toString(); }
function epochFinalizedKey(epoch: u16): string { return "epoch-governance:finalized:" + epoch.toString(); }
function ballotReceiptKey(epoch: u16, address: string): string { return "epoch-governance:ballot:" + epoch.toString() + ":" + address; }
function epochParticipantCountKey(proposalId: string): string { return "epoch-governance:participants:" + proposalId; }
function proposalRecoveryKey(proposalId: string): string { return "epoch-governance:recovery:" + proposalId; }
function reviewAvailabilityMinimumExpiryKey(reviewRoundId: string): string {
  return "review-availability-min-expiry:" + reviewRoundId;
}
function epochDecisionRecordKey(proposalId: string): string { return "epoch-governance:decision:" + proposalId; }
function epochDecisionRecordCidKey(proposalId: string): string { return "epoch-governance:decision-cid:" + proposalId; }
function revertExecutionKey(proposalId: string): string { return "epoch-governance:revert:" + proposalId; }
function treasuryKey(): string { return "epoch-governance:treasury"; }
function canonicalHistoryCountKey(): string { return "epoch-governance:history-count"; }
function canonicalHistoryEntryKey(index: u32): string { return "epoch-governance:history:" + index.toString(); }
function metricsKey(address: string): string { return "metrics:" + address; }
function stakeLotCountKey(address: string): string { return "stake:lot-count:" + address; }
function stakeLotKey(address: string, index: u16): string { return "stake:lot:" + address + ":" + index.toString(); }
function withdrawalCheckpointCountKey(address: string): string { return "stake:withdrawal-count:" + address; }
function withdrawalCheckpointKey(address: string, index: u16): string { return "stake:withdrawal-checkpoint:" + address + ":" + index.toString(); }
