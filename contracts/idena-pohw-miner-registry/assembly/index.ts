import { u128Safe as u128 } from "as-bignum/assembly";
import {
  allocate,
  argumentString,
  attachedAmount,
  burn,
  callerHex,
  currentBlock,
  currentEpoch,
  currentTimestamp,
  emitVersionedEvent,
  getString,
  hasKey,
  originalCallerBytes,
  originalCallerHex,
  readPromiseResult,
  removeKey,
  requireNoPayment,
  returnString,
  scheduleIdentityCallback,
  setString,
  transfer,
} from "./host";
import { parseAmount, parseU32, parseU64 } from "./math";

export { allocate };

const CONTRACT_SCHEMA_VERSION: u16 = 3;
const REGISTRATION_SCHEMA_VERSION: u16 = 1;
const CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const CONTRACT_VERSION = "0.3.0";
const CHECKPOINT_QUORUM_NUMERATOR: u32 = 2;
const CHECKPOINT_QUORUM_DENOMINATOR: u32 = 3;
const CHECKPOINT_MIN_INTERVAL_BLOCKS: u64 = 6;
const MAX_CHECKPOINT_MINERS: u32 = 48;
const IDENTITY_READ_GAS_LIMIT: u32 = 10_000_000;
const REGISTRATION_CALLBACK_GAS_LIMIT: u32 = 50_000_000;
const CHECKPOINT_CALLBACK_GAS_LIMIT: u32 = 50_000_000;
const IDENTITY_STATE_VERIFIED: u32 = 3;
const IDENTITY_STATE_NEWBIE: u32 = 7;
const IDENTITY_STATE_HUMAN: u32 = 8;
const ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
const EMPTY_LIST = "~";
const INITIALIZED_KEY = "registry:initialized";
const EXPERIMENT_ID_KEY = "registry:experiment-id";
const ECOSYSTEM_CID_KEY = "registry:ecosystem-cid";
const MIN_BURN_KEY = "registry:min-burn";
const DEPLOYMENT_BLOCK_KEY = "registry:deployment-block";
const REGISTERED_COUNT_KEY = "registry:registered-count";
const REGISTERED_MINERS_KEY = "registry:registered-miners";
const LATEST_CHECKPOINT_ROUND_KEY = "checkpoint:latest-round";
const REGISTRATION_CALLBACK = "_completeRegistration";
const CHECKPOINT_VOTE_CALLBACK = "_completeCheckpointVote";

export function deploy(
  experimentIdPtr: usize,
  ecosystemCidPtr: usize,
  minimumRegistrationBurnAtomsPtr: usize,
): void {
  assert(!hasKey(INITIALIZED_KEY), "contract is already initialized");
  requireNoPayment();
  const experimentId = normalizeExperimentId(argumentString(experimentIdPtr, 64));
  const ecosystemCid = argumentString(ecosystemCidPtr, 128);
  const minimumBurn = parseAmount(argumentString(minimumRegistrationBurnAtomsPtr, 39));
  assert(isCanonicalCidV1(ecosystemCid), "ecosystem CID must be lowercase CIDv1 base32");
  assert(!minimumBurn.isZero(), "minimum registration burn must be nonzero");
  setString(INITIALIZED_KEY, "1");
  setString(EXPERIMENT_ID_KEY, experimentId);
  setString(ECOSYSTEM_CID_KEY, ecosystemCid);
  setString(MIN_BURN_KEY, minimumBurn.toString());
  setString(DEPLOYMENT_BLOCK_KEY, currentBlock().toString());
  setString(REGISTERED_COUNT_KEY, "0");
  setString(REGISTERED_MINERS_KEY, EMPTY_LIST);
  setString(LATEST_CHECKPOINT_ROUND_KEY, "0");
  emitVersionedEvent("PohwMinerRegistryDeployedV1", [
    experimentId,
    ecosystemCid,
    minimumBurn.toString(),
  ]);
}

export function registerMiner(minerIdPtr: usize, commitmentPtr: usize): usize {
  ensureInitialized();
  const address = callerHex();
  const minerId = normalizeMinerId(argumentString(minerIdPtr, 64));
  const commitment = normalizeHash(argumentString(commitmentPtr, 64));
  assert(!hasKey(identityMinerKey(address)), "caller already registered a miner id");
  assert(!hasKey(pendingRegistrationKey(address)), "caller already has a pending registration");
  assert(!hasKey(minerOwnerKey(minerId)), "miner id is already registered");
  assert(!hasKey(pendingMinerKey(minerId)), "miner id already has a pending registration");
  const registeredCount = parseU32(getString(REGISTERED_COUNT_KEY));
  assert(registeredCount < MAX_CHECKPOINT_MINERS, "experimental checkpoint miner limit reached");
  const payment = requireRegistrationPayment();
  const pending = minerId + "|" + commitment + "|" + payment.toString();
  setString(pendingRegistrationKey(address), pending);
  setString(pendingMinerKey(minerId), address);
  emitVersionedEvent("PohwMinerRegPendingV1", [
    "0x" + address,
    minerId,
    commitment,
    payment.toString(),
  ]);
  scheduleIdentityCallback(
    hexAddressBytes(address),
    REGISTRATION_CALLBACK,
    IDENTITY_READ_GAS_LIMIT,
    REGISTRATION_CALLBACK_GAS_LIMIT,
  );
  return pendingRegistrationJson(address, minerId);
}

// The pinned Idena runtime rejects direct calls to underscore-prefixed methods.
// This export is reachable only as the callback of registerMiner's identity read.
export function _completeRegistration(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = originalCallerHex();
  const pending = getString(pendingRegistrationKey(address));
  if (pending.length == 0) return callbackResult("missing", address, "");
  const fields = pending.split("|");
  if (fields.length != 3) return refundPendingRegistration(address, "malformed-pending");
  const minerId = fields[0];
  const commitment = fields[1];
  const payment = parseAmount(fields[2]);
  const status = new Uint8Array(1);
  const identity = readPromiseResult(status);
  if (status[0] != 2) return refundPendingRegistration(address, "identity-unavailable");
  const identityState = parseIdentityState(identity);
  if (!isEligibleIdentityState(identityState)) {
    return refundPendingRegistration(address, "identity-ineligible");
  }
  if (
    hasKey(identityMinerKey(address))
      || getString(pendingMinerKey(minerId)) != address
      || hasKey(minerOwnerKey(minerId))
  ) return refundPendingRegistration(address, "registration-conflict");
  const registeredCount = parseU32(getString(REGISTERED_COUNT_KEY));
  if (registeredCount >= MAX_CHECKPOINT_MINERS) {
    return refundPendingRegistration(address, "miner-limit-reached");
  }

  const sequence: u32 = 1;
  const record = canonicalRecordLine(
    minerId,
    commitment,
    sequence,
    currentBlock(),
    currentEpoch(),
    currentTimestamp(),
  );
  setString(identityMinerKey(address), minerId);
  setString(identityCurrentSequenceKey(address), sequence.toString());
  setString(minerOwnerKey(minerId), address);
  setString(registrationKey(address, sequence), record);
  setString(REGISTERED_COUNT_KEY, (registeredCount + 1).toString());
  setString(
    REGISTERED_MINERS_KEY,
    encodeList(insertSortedUnique(decodeList(getString(REGISTERED_MINERS_KEY)), minerId)),
  );
  clearPendingRegistration(address, minerId);
  burn(payment);
  emitVersionedEvent("PohwMinerRegisteredV1", [
    "0x" + address,
    minerId,
    commitment,
    sequence.toString(),
    currentBlock().toString(),
    currentEpoch().toString(),
    currentTimestamp().toString(),
    payment.toString(),
    identityState.toString(),
  ]);
  return registrationJson(address, record);
}

export function pendingRegistration(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  const pending = getString(pendingRegistrationKey(address));
  if (pending.length == 0) return returnString("{\"ok\":true,\"pending\":null}");
  const fields = pending.split("|");
  assert(fields.length == 3, "pending registration is malformed");
  return pendingRegistrationJson(address, fields[0]);
}

export function cancelPendingRegistration(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  const pending = getString(pendingRegistrationKey(address));
  assert(pending.length > 0, "caller has no pending registration");
  return refundPendingRegistration(address, "caller-cancelled");
}

export function rotateMinerCommitment(commitmentPtr: usize): usize {
  ensureInitialized();
  const address = callerHex();
  const minerId = getString(identityMinerKey(address));
  assert(minerId.length > 0, "caller has no miner registration");
  const currentSequence = parseU32(getString(identityCurrentSequenceKey(address)));
  assert(currentSequence < u32.MAX_VALUE, "registration sequence exhausted");
  const sequence = currentSequence + 1;
  const commitment = normalizeHash(argumentString(commitmentPtr, 64));
  const currentRecord = getString(registrationKey(address, currentSequence));
  assert(!recordHasCommitment(currentRecord, commitment), "commitment is unchanged");
  const payment = requireAndBurnRegistrationPayment();
  const record = canonicalRecordLine(
    minerId,
    commitment,
    sequence,
    currentBlock(),
    currentEpoch(),
    currentTimestamp(),
  );
  setString(identityCurrentSequenceKey(address), sequence.toString());
  setString(registrationKey(address, sequence), record);
  emitVersionedEvent("PohwMinerCommitmentRotatedV1", [
    "0x" + address,
    minerId,
    commitment,
    sequence.toString(),
    currentBlock().toString(),
    currentEpoch().toString(),
    currentTimestamp().toString(),
    payment.toString(),
  ]);
  return registrationJson(address, record);
}

export function currentRegistration(addressPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const address = normalizeAddress(argumentString(addressPtr, 42));
  const sequenceValue = getString(identityCurrentSequenceKey(address));
  if (sequenceValue.length == 0) return returnString("{\"ok\":true,\"registration\":null}");
  const sequence = parseU32(sequenceValue);
  return registrationJson(address, getString(registrationKey(address, sequence)));
}

export function registration(addressPtr: usize, sequencePtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const address = normalizeAddress(argumentString(addressPtr, 42));
  const sequence = parseU32(argumentString(sequencePtr, 10));
  assert(sequence > 0, "registration sequence must be nonzero");
  const record = getString(registrationKey(address, sequence));
  if (record.length == 0) return returnString("{\"ok\":true,\"registration\":null}");
  return registrationJson(address, record);
}

export function voteCheckpoint(
  roundPtr: usize,
  shareTipHashPtr: usize,
  shareHeightPtr: usize,
  cumulativeScorePtr: usize,
  parentCheckpointTipPtr: usize,
): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  const minerId = getString(identityMinerKey(address));
  assert(minerId.length > 0, "caller has no miner registration");
  assert(!hasKey(pendingCheckpointVoteKey(address)), "caller already has a pending checkpoint vote");
  const round = parseU32(argumentString(roundPtr, 10));
  const shareTipHash = normalizeHash(argumentString(shareTipHashPtr, 64));
  assert(shareTipHash != ZERO_HASH, "checkpoint share tip must not be zero");
  const shareHeight = parseU64(argumentString(shareHeightPtr, 20));
  assert(shareHeight > 0, "checkpoint share height must be nonzero");
  const cumulativeScore = parseAmount(argumentString(cumulativeScorePtr, 39));
  assert(!cumulativeScore.isZero(), "checkpoint cumulative score must be nonzero");
  const parentCheckpointTip = normalizeHash(argumentString(parentCheckpointTipPtr, 64));

  const latestRound = parseU32(getString(LATEST_CHECKPOINT_ROUND_KEY));
  if (round <= latestRound) {
    const finalized = getString(checkpointKey(round));
    assert(finalized.length > 0, "checkpoint round is finalized without a record");
    assert(checkpointTip(finalized) == shareTipHash, "checkpoint round already finalized for another tip");
    return checkpointVoteJson(round, shareTipHash, checkpointSupporters(finalized));
  }
  validateOpenCheckpointVote(round, shareTipHash, shareHeight, cumulativeScore.toString(), parentCheckpointTip);
  const pending = round.toString() + "|" + shareTipHash + "|" + shareHeight.toString()
    + "|" + cumulativeScore.toString() + "|" + parentCheckpointTip;
  setString(pendingCheckpointVoteKey(address), pending);
  emitVersionedEvent("PohwCheckpointVotePendingV1", [
    "0x" + address,
    minerId,
    round.toString(),
    shareTipHash,
  ]);
  scheduleIdentityCallback(
    hexAddressBytes(address),
    CHECKPOINT_VOTE_CALLBACK,
    IDENTITY_READ_GAS_LIMIT,
    CHECKPOINT_CALLBACK_GAS_LIMIT,
  );
  return checkpointVotePendingJson(round, shareTipHash);
}

// Like _completeRegistration, this export is callback-only in the pinned runtime.
export function _completeCheckpointVote(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = originalCallerHex();
  const pending = getString(pendingCheckpointVoteKey(address));
  if (pending.length == 0) return checkpointVoteCallbackJson("missing", 0, ZERO_HASH);
  const fields = pending.split("|");
  if (fields.length != 5) return checkpointVoteCallbackJson("malformed", 0, ZERO_HASH);
  const round = parseU32(fields[0]);
  const shareTipHash = normalizeHash(fields[1]);
  const shareHeight = parseU64(fields[2]);
  const cumulativeScore = parseAmount(fields[3]);
  const parentCheckpointTip = normalizeHash(fields[4]);
  const status = new Uint8Array(1);
  const identity = readPromiseResult(status);
  if (status[0] != 2) {
    return rejectPendingCheckpointVote(address, round, shareTipHash, "identity-unavailable");
  }
  const identityState = parseIdentityState(identity);
  if (!isEligibleIdentityState(identityState)) {
    return rejectPendingCheckpointVote(address, round, shareTipHash, "identity-ineligible");
  }
  removeKey(pendingCheckpointVoteKey(address));
  return applyCheckpointVote(
    address,
    round,
    shareTipHash,
    shareHeight,
    cumulativeScore.toString(),
    parentCheckpointTip,
  );
}

export function cancelPendingCheckpointVote(): usize {
  ensureInitialized();
  requireNoPayment();
  const address = callerHex();
  const pending = getString(pendingCheckpointVoteKey(address));
  assert(pending.length > 0, "caller has no pending checkpoint vote");
  const fields = pending.split("|");
  assert(fields.length == 5, "pending checkpoint vote is malformed");
  return rejectPendingCheckpointVote(
    address,
    parseU32(fields[0]),
    normalizeHash(fields[1]),
    "caller-cancelled",
  );
}

function applyCheckpointVote(
  address: string,
  round: u32,
  shareTipHash: string,
  shareHeight: u64,
  cumulativeScore: string,
  parentCheckpointTip: string,
): usize {
  const minerId = getString(identityMinerKey(address));
  assert(minerId.length > 0, "caller has no miner registration");
  validateOpenCheckpointVote(round, shareTipHash, shareHeight, cumulativeScore, parentCheckpointTip);

  const candidate = shareTipHash + "|" + shareHeight.toString() + "|"
    + cumulativeScore + "|" + parentCheckpointTip;
  const candidateKeyValue = checkpointCandidateKey(round, shareTipHash);
  const voterKey = checkpointVoterKey(round, minerId);
  const oldTip = getString(voterKey);
  if (oldTip == shareTipHash) {
    return checkpointVoteJson(round, shareTipHash, decodeList(getString(checkpointSupportersKey(round, shareTipHash))));
  }
  if (oldTip.length > 0) {
    const oldSupportersKey = checkpointSupportersKey(round, oldTip);
    const oldSupporters = removeSorted(decodeList(getString(oldSupportersKey)), minerId);
    setString(oldSupportersKey, encodeList(oldSupporters));
  }

  setString(candidateKeyValue, candidate);
  const supportersKey = checkpointSupportersKey(round, shareTipHash);
  const supporters = insertSortedUnique(decodeList(getString(supportersKey)), minerId);
  setString(supportersKey, encodeList(supporters));
  setString(voterKey, shareTipHash);

  const registeredCount = parseU32(getString(REGISTERED_COUNT_KEY));
  const threshold = checkpointThreshold(registeredCount);
  if (<u32>supporters.length >= threshold) {
    const registeredMiners = decodeList(getString(REGISTERED_MINERS_KEY));
    assert(<u32>registeredMiners.length == registeredCount, "registered miner index is inconsistent");
    const record = checkpointRecord(
      round,
      shareTipHash,
      shareHeight,
      cumulativeScore,
      parentCheckpointTip,
      <u32>supporters.length,
      registeredCount,
      registeredMiners,
      supporters,
    );
    setString(checkpointKey(round), record);
    setString(LATEST_CHECKPOINT_ROUND_KEY, round.toString());
    emitVersionedEvent("PohwCheckpointFinalizedV1", [
      round.toString(),
      shareTipHash,
      shareHeight.toString(),
      cumulativeScore,
      parentCheckpointTip,
      supporters.length.toString(),
      registeredCount.toString(),
      currentBlock().toString(),
    ]);
  }
  return checkpointVoteJson(round, shareTipHash, supporters);
}

function validateOpenCheckpointVote(
  round: u32,
  shareTipHash: string,
  shareHeight: u64,
  cumulativeScore: string,
  parentCheckpointTip: string,
): void {
  assert(round > 0, "checkpoint round must be nonzero");
  assert(shareTipHash != ZERO_HASH, "checkpoint share tip must not be zero");
  assert(shareHeight > 0, "checkpoint share height must be nonzero");
  assert(!parseAmount(cumulativeScore).isZero(), "checkpoint cumulative score must be nonzero");
  normalizeHash(parentCheckpointTip);
  const latestRound = parseU32(getString(LATEST_CHECKPOINT_ROUND_KEY));
  assert(latestRound < u32.MAX_VALUE, "checkpoint round exhausted");
  assert(round == latestRound + 1, "checkpoint vote must target the next round");
  const expectedParent = latestRound == 0
    ? ZERO_HASH
    : checkpointTip(getString(checkpointKey(latestRound)));
  assert(parentCheckpointTip == expectedParent, "checkpoint parent does not match latest final checkpoint");
  const earliestBlock = latestRound == 0
    ? parseU64(getString(DEPLOYMENT_BLOCK_KEY)) + 1
    : checkpointFinalizationBlock(getString(checkpointKey(latestRound)))
      + CHECKPOINT_MIN_INTERVAL_BLOCKS;
  assert(currentBlock() >= earliestBlock, "checkpoint minimum block interval has not elapsed");

  const candidate = shareTipHash + "|" + shareHeight.toString() + "|"
    + cumulativeScore.toString() + "|" + parentCheckpointTip;
  const candidateKeyValue = checkpointCandidateKey(round, shareTipHash);
  const existingCandidate = getString(candidateKeyValue);
  assert(existingCandidate.length == 0 || existingCandidate == candidate, "checkpoint tip has conflicting metadata");
}

export function checkpoint(roundPtr: usize): usize {
  ensureInitialized();
  requireNoPayment();
  const round = parseU32(argumentString(roundPtr, 10));
  assert(round > 0, "checkpoint round must be nonzero");
  const record = getString(checkpointKey(round));
  if (record.length == 0) return returnString("{\"ok\":true,\"checkpoint\":null}");
  return checkpointJson(record);
}

export function latestCheckpoint(): usize {
  ensureInitialized();
  requireNoPayment();
  const round = parseU32(getString(LATEST_CHECKPOINT_ROUND_KEY));
  if (round == 0) return returnString("{\"ok\":true,\"checkpoint\":null}");
  return checkpointJson(getString(checkpointKey(round)));
}

export function contractParameters(): usize {
  ensureInitialized();
  requireNoPayment();
  return returnString(
    "{\"ok\":true,\"schemaVersion\":" + CONTRACT_SCHEMA_VERSION.toString()
      + ",\"contractVersion\":\"" + CONTRACT_VERSION
      + "\",\"experimentId\":\"" + getString(EXPERIMENT_ID_KEY)
      + "\",\"ecosystemCid\":\"" + getString(ECOSYSTEM_CID_KEY)
      + "\",\"minimumRegistrationBurnAtoms\":\"" + getString(MIN_BURN_KEY)
      + "\",\"checkpointQuorumNumerator\":" + CHECKPOINT_QUORUM_NUMERATOR.toString()
      + ",\"checkpointQuorumDenominator\":" + CHECKPOINT_QUORUM_DENOMINATOR.toString()
      + ",\"checkpointMinIntervalBlocks\":\"" + CHECKPOINT_MIN_INTERVAL_BLOCKS.toString()
      + "\",\"maxCheckpointMiners\":" + MAX_CHECKPOINT_MINERS.toString()
      + ",\"eligibleIdentityStates\":[\"Newbie\",\"Verified\",\"Human\"]"
      + ",\"identityReadGasLimit\":" + IDENTITY_READ_GAS_LIMIT.toString()
      + ",\"registrationCallbackGasLimit\":" + REGISTRATION_CALLBACK_GAS_LIMIT.toString()
      + ",\"checkpointCallbackGasLimit\":" + CHECKPOINT_CALLBACK_GAS_LIMIT.toString()
      + "}",
  );
}

function ensureInitialized(): void {
  assert(hasKey(INITIALIZED_KEY), "contract is not initialized");
}

function requireRegistrationPayment(): u128 {
  const payment = attachedAmount();
  const minimum = parseAmount(getString(MIN_BURN_KEY));
  assert(payment >= minimum, "registration payment is below the immutable minimum burn");
  return payment;
}

function requireAndBurnRegistrationPayment(): u128 {
  const payment = requireRegistrationPayment();
  burn(payment);
  return payment;
}

function identityMinerKey(address: string): string {
  return "identity:" + address + ":miner";
}

function identityCurrentSequenceKey(address: string): string {
  return "identity:" + address + ":current";
}

function minerOwnerKey(minerId: string): string {
  return "miner-owner:" + minerId;
}

function pendingRegistrationKey(address: string): string {
  return "pending:identity:" + address;
}

function pendingMinerKey(minerId: string): string {
  return "pending:miner:" + minerId;
}

function pendingCheckpointVoteKey(address: string): string {
  return "pending:checkpoint:" + address;
}

function registrationKey(address: string, sequence: u32): string {
  return "miner:" + address + ":" + sequence.toString();
}

function canonicalRecordLine(
  minerId: string,
  commitment: string,
  sequence: u32,
  block: u64,
  epoch: u16,
  timestamp: i64,
): string {
  return REGISTRATION_SCHEMA_VERSION.toString() + "|" + minerId + "|" + commitment + "|"
    + sequence.toString() + "|" + block.toString() + "|" + epoch.toString() + "|"
    + timestamp.toString();
}

function checkpointKey(round: u32): string {
  return "checkpoint:final:" + round.toString();
}

function checkpointCandidateKey(round: u32, shareTipHash: string): string {
  return "checkpoint:candidate:" + round.toString() + ":" + shareTipHash;
}

function checkpointSupportersKey(round: u32, shareTipHash: string): string {
  return "checkpoint:supporters:" + round.toString() + ":" + shareTipHash;
}

function checkpointVoterKey(round: u32, minerId: string): string {
  return "checkpoint:voter:" + round.toString() + ":" + minerId;
}

function checkpointThreshold(registeredCount: u32): u32 {
  assert(registeredCount > 0 && registeredCount <= MAX_CHECKPOINT_MINERS, "invalid registered miner count");
  return (registeredCount * CHECKPOINT_QUORUM_NUMERATOR + CHECKPOINT_QUORUM_DENOMINATOR - 1)
    / CHECKPOINT_QUORUM_DENOMINATOR;
}

function checkpointRecord(
  round: u32,
  shareTipHash: string,
  shareHeight: u64,
  cumulativeScore: string,
  parentCheckpointTip: string,
  supportCount: u32,
  registeredCount: u32,
  registeredMiners: string[],
  supporters: string[],
): string {
  return CHECKPOINT_SCHEMA_VERSION.toString() + "|" + round.toString() + "|" + shareTipHash
    + "|" + shareHeight.toString() + "|" + cumulativeScore + "|" + parentCheckpointTip
    + "|" + currentBlock().toString() + "|" + currentEpoch().toString() + "|"
    + currentTimestamp().toString() + "|" + supportCount.toString() + "|"
    + registeredCount.toString() + "|" + registeredMiners.join(",") + "|" + supporters.join(",");
}

function checkpointTip(record: string): string {
  const fields = record.split("|");
  assert(fields.length == 13 && fields[0] == CHECKPOINT_SCHEMA_VERSION.toString(), "invalid finalized checkpoint record");
  return normalizeHash(fields[2]);
}

function checkpointFinalizationBlock(record: string): u64 {
  const fields = record.split("|");
  assert(fields.length == 13 && fields[0] == CHECKPOINT_SCHEMA_VERSION.toString(), "invalid finalized checkpoint record");
  return parseU64(fields[6]);
}

function checkpointSupporters(record: string): string[] {
  const fields = record.split("|");
  assert(fields.length == 13 && fields[0] == CHECKPOINT_SCHEMA_VERSION.toString(), "invalid finalized checkpoint record");
  return decodeList(fields[12]);
}

function checkpointVoteJson(round: u32, shareTipHash: string, supporters: string[]): usize {
  return returnString(
    "{\"ok\":true,\"round\":" + round.toString() + ",\"shareTipHash\":\""
      + shareTipHash + "\",\"supportCount\":" + supporters.length.toString()
      + ",\"finalized\":" + (getString(checkpointKey(round)).length > 0 ? "true" : "false") + "}",
  );
}

function checkpointVotePendingJson(round: u32, shareTipHash: string): usize {
  return returnString(
    "{\"ok\":true,\"round\":" + round.toString() + ",\"shareTipHash\":\""
      + shareTipHash + "\",\"pending\":true}",
  );
}

function checkpointVoteCallbackJson(status: string, round: u32, shareTipHash: string): usize {
  return returnString(
    "{\"ok\":true,\"status\":\"" + status + "\",\"round\":" + round.toString()
      + ",\"shareTipHash\":\"" + shareTipHash + "\"}",
  );
}

function rejectPendingCheckpointVote(
  address: string,
  round: u32,
  shareTipHash: string,
  reason: string,
): usize {
  removeKey(pendingCheckpointVoteKey(address));
  emitVersionedEvent("PohwCheckpointVoteRejectedV1", [
    "0x" + address,
    round.toString(),
    shareTipHash,
    reason,
  ]);
  return checkpointVoteCallbackJson("rejected", round, shareTipHash);
}

function checkpointJson(record: string): usize {
  assert(record.length > 0, "checkpoint record is missing");
  return returnString("{\"ok\":true,\"record\":\"" + record + "\"}");
}

function decodeList(value: string): string[] {
  if (value.length == 0 || value == EMPTY_LIST) return new Array<string>();
  const values = value.split(",");
  for (let i = 0; i < values.length; i++) {
    assert(values[i].length > 0, "list contains an empty item");
    if (i > 0) assert(values[i - 1] < values[i], "list is not strictly sorted");
  }
  return values;
}

function encodeList(values: string[]): string {
  return values.length == 0 ? EMPTY_LIST : values.join(",");
}

function insertSortedUnique(values: string[], value: string): string[] {
  const result = new Array<string>();
  let inserted = false;
  for (let i = 0; i < values.length; i++) {
    if (!inserted && value < values[i]) {
      result.push(value);
      inserted = true;
    }
    if (values[i] == value) inserted = true;
    result.push(values[i]);
  }
  if (!inserted) result.push(value);
  return result;
}

function removeSorted(values: string[], value: string): string[] {
  const result = new Array<string>();
  for (let i = 0; i < values.length; i++) {
    if (values[i] != value) result.push(values[i]);
  }
  return result;
}

function registrationJson(address: string, record: string): usize {
  assert(record.length > 0, "registration record is missing");
  return returnString(
    "{\"ok\":true,\"address\":\"0x" + address + "\",\"record\":\"" + record + "\"}",
  );
}

function pendingRegistrationJson(address: string, minerId: string): usize {
  return returnString(
    "{\"ok\":true,\"address\":\"0x" + address + "\",\"minerId\":\"" + minerId
      + "\",\"pending\":true}",
  );
}

function callbackResult(status: string, address: string, minerId: string): usize {
  return returnString(
    "{\"ok\":true,\"status\":\"" + status + "\",\"address\":\"0x" + address
      + "\",\"minerId\":\"" + minerId + "\"}",
  );
}

function refundPendingRegistration(address: string, reason: string): usize {
  const pending = getString(pendingRegistrationKey(address));
  if (pending.length == 0) return callbackResult("missing", address, "");
  const fields = pending.split("|");
  if (fields.length != 3) return callbackResult("malformed", address, "");
  const minerId = fields[0];
  const payment = parseAmount(fields[2]);
  clearPendingRegistration(address, minerId);
  transfer(hexAddressBytes(address), payment);
  emitVersionedEvent("PohwMinerRegRefundedV1", [
    "0x" + address,
    minerId,
    payment.toString(),
    reason,
  ]);
  return callbackResult("refunded", address, minerId);
}

function clearPendingRegistration(address: string, minerId: string): void {
  removeKey(pendingRegistrationKey(address));
  if (getString(pendingMinerKey(minerId)) == address) removeKey(pendingMinerKey(minerId));
}

function isEligibleIdentityState(value: u32): bool {
  return value == IDENTITY_STATE_NEWBIE
    || value == IDENTITY_STATE_VERIFIED
    || value == IDENTITY_STATE_HUMAN;
}

function parseIdentityState(data: Uint8Array): u32 {
  let offset = 0;
  let found = false;
  let state: u32 = 0;
  while (offset < data.length) {
    const key = readProtoVarint(data, offset);
    if (!key.ok || key.value == 0) return u32.MAX_VALUE;
    offset = key.next;
    const field = key.value >> 3;
    const wire = key.value & 7;
    if (field == 4) {
      if (wire != 0 || found) return u32.MAX_VALUE;
      const value = readProtoVarint(data, offset);
      if (!value.ok || value.value > 255) return u32.MAX_VALUE;
      state = value.value;
      found = true;
      offset = value.next;
      continue;
    }
    if (wire == 0) {
      const value = readProtoVarint(data, offset);
      if (!value.ok) return u32.MAX_VALUE;
      offset = value.next;
    } else if (wire == 1) {
      if (offset + 8 > data.length) return u32.MAX_VALUE;
      offset += 8;
    } else if (wire == 2) {
      const length = readProtoVarint(data, offset);
      if (!length.ok || length.value > <u32>(data.length - length.next)) return u32.MAX_VALUE;
      offset = length.next + <i32>length.value;
    } else if (wire == 5) {
      if (offset + 4 > data.length) return u32.MAX_VALUE;
      offset += 4;
    } else {
      return u32.MAX_VALUE;
    }
  }
  return found ? state : u32.MAX_VALUE;
}

class ProtoVarint {
  constructor(
    public ok: bool,
    public value: u32,
    public next: i32,
  ) {}
}

function readProtoVarint(data: Uint8Array, offset: i32): ProtoVarint {
  let value: u32 = 0;
  for (let shift: u32 = 0; shift <= 28; shift += 7) {
    if (offset >= data.length) return new ProtoVarint(false, 0, offset);
    const byte = data[offset++];
    if (shift == 28 && (byte & 0xf0) != 0) return new ProtoVarint(false, 0, offset);
    value |= <u32>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0) return new ProtoVarint(true, value, offset);
  }
  return new ProtoVarint(false, 0, offset);
}

function hexAddressBytes(address: string): Uint8Array {
  assert(address.length == 40, "address must contain 20-byte lowercase hex");
  const result = new Uint8Array(20);
  for (let i = 0; i < result.length; i++) {
    result[i] = <u8>((hexNibble(address.charCodeAt(i * 2)) << 4)
      | hexNibble(address.charCodeAt(i * 2 + 1)));
  }
  return result;
}

function hexNibble(code: i32): i32 {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  assert(false, "address contains non-hex character");
  return 0;
}

function recordHasCommitment(record: string, commitment: string): bool {
  const fields = record.split("|");
  return fields.length == 7 && fields[2] == commitment;
}

function normalizeExperimentId(value: string): string {
  const normalized = value.toLowerCase();
  assert(value == normalized, "experiment id must be lowercase");
  assert(normalized.length > 0 && normalized.length <= 64, "invalid experiment id length");
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    assert(
      isLowerAlpha(code) || isDigit(code) || code == 46 || code == 95 || code == 58
        || code == 47 || code == 45,
      "invalid experiment id character",
    );
  }
  return normalized;
}

function normalizeMinerId(value: string): string {
  const normalized = value.toLowerCase();
  assert(normalized.length > 0 && normalized.length <= 64, "invalid miner id length");
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    assert(
      isLowerAlpha(code) || isDigit(code) || code == 45 || code == 95 || code == 46,
      "invalid miner id character",
    );
  }
  return normalized;
}

function normalizeHash(value: string): string {
  const normalized = value.toLowerCase();
  assert(value == normalized && normalized.length == 64, "commitment must be lowercase SHA-256 hex");
  for (let i = 0; i < normalized.length; i++) {
    assert(isHex(normalized.charCodeAt(i)), "commitment contains non-hex character");
  }
  return normalized;
}

function normalizeAddress(value: string): string {
  assert(value.length == 42 && value.startsWith("0x"), "address must be 0x-prefixed");
  const normalized = value.toLowerCase();
  assert(value == normalized, "address must be lowercase");
  for (let i = 2; i < normalized.length; i++) {
    assert(isHex(normalized.charCodeAt(i)), "address contains non-hex character");
  }
  return normalized.substring(2);
}

function isCanonicalCidV1(value: string): bool {
  if (value.length < 10 || value.length > 128 || value.charCodeAt(0) != 98) return false;
  for (let i = 1; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!isLowerAlpha(code) && !(code >= 50 && code <= 55)) return false;
  }
  return true;
}

function isLowerAlpha(code: i32): bool {
  return code >= 97 && code <= 122;
}

function isDigit(code: i32): bool {
  return code >= 48 && code <= 57;
}

function isHex(code: i32): bool {
  return isDigit(code) || (code >= 97 && code <= 102);
}
