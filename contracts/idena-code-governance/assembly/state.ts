import { u128Safe as u128 } from "as-bignum/assembly";
import { getString, setString } from "./host";
import { parseAmount, parseU16, parseU32, parseU64, parseU8 } from "./math";

export const STATE_DRAFT: u8 = 0;
export const STATE_REVIEW_OPEN: u8 = 1;
export const STATE_VOTING_OPEN: u8 = 2;
export const STATE_ACCEPTED_PENDING_CHALLENGE: u8 = 3;
export const STATE_REJECTED: u8 = 4;
export const STATE_CHALLENGED: u8 = 5;
export const STATE_ACCEPTED_PENDING_EXECUTION: u8 = 6;
export const STATE_EXECUTED: u8 = 7;
export const STATE_STALE: u8 = 8;
export const STATE_EXPIRED: u8 = 9;

export const REVIEW_ROUND_OPEN: u8 = 0;
export const REVIEW_ROUND_FROZEN: u8 = 1;
export const REVIEW_ROUND_CLAIMED: u8 = 2;
export const REVIEW_ROUND_EXPIRED: u8 = 3;

export class MetricsRecord {
  constructor(
    public state: string,
    public finalized: u64,
    public reported: u64,
    public trustBps: u16,
    public sourceEpoch: u16,
    public sourceHeight: u64,
    public sourceHash: string,
    public root: string,
    public registeredBlock: u64,
  ) {}

  encode(): string {
    return this.state
      + "~" + this.finalized.toString()
      + "~" + this.reported.toString()
      + "~" + this.trustBps.toString()
      + "~" + this.sourceEpoch.toString()
      + "~" + this.sourceHeight.toString()
      + "~" + this.sourceHash
      + "~" + this.root
      + "~" + this.registeredBlock.toString();
  }

  static decode(value: string): MetricsRecord {
    const fields = value.split("~");
    assert(fields.length == 9, "corrupt identity metrics record");
    return new MetricsRecord(
      fields[0], parseU64(fields[1]), parseU64(fields[2]), parseU16(fields[3]),
      parseU16(fields[4]), parseU64(fields[5]), fields[6], fields[7], parseU64(fields[8]),
    );
  }
}

export class ReviewRound {
  constructor(
    public id: string,
    public parentCid: string,
    public candidateCid: string,
    public patchCid: string,
    public sourceBinding: string,
    public affectedSourceBinding: string,
    public toolchainBinding: string,
    public pinsetCid: string,
    public pinsetCount: u32,
    public opener: string,
    public state: u8,
    public openedBlock: u64,
    public endBlock: u64,
    public claimDeadline: u64,
    public proposalId: string,
    public agentRoot: string,
    public buildRoot: string,
    public availabilityRoot: string,
    public agentLeafCount: u32,
    public buildLeafCount: u32,
    public availabilityLeafCount: u32,
    public agentCount: u32,
    public agentModelCount: u32,
    public agentOwnerCount: u32,
    public unresolvedCriticalCount: u32,
    public builderOwnerCount: u32,
    public builderPlatformCount: u32,
    public builderConflictCount: u32,
    public availabilityOwnerCount: u32,
    public artifactDigest: string,
    public bond: string,
    public refundableBond: string,
    public bondClaimed: bool,
  ) {}

  encode(): string {
    return [
      this.id, this.parentCid, this.candidateCid, this.patchCid,
      this.sourceBinding, this.affectedSourceBinding, this.toolchainBinding,
      this.pinsetCid, this.pinsetCount.toString(), this.opener,
      this.state.toString(), this.openedBlock.toString(), this.endBlock.toString(),
      this.claimDeadline.toString(), this.proposalId, this.agentRoot, this.buildRoot,
      this.availabilityRoot, this.agentLeafCount.toString(), this.buildLeafCount.toString(),
      this.availabilityLeafCount.toString(), this.agentCount.toString(),
      this.agentModelCount.toString(), this.agentOwnerCount.toString(),
      this.unresolvedCriticalCount.toString(), this.builderOwnerCount.toString(),
      this.builderPlatformCount.toString(), this.builderConflictCount.toString(),
      this.availabilityOwnerCount.toString(), this.artifactDigest, this.bond,
      this.refundableBond, this.bondClaimed ? "1" : "0",
    ].join("~");
  }

  static decode(value: string): ReviewRound {
    const f = value.split("~");
    assert(f.length == 33, "corrupt review round record");
    return new ReviewRound(
      f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], parseU32(f[8]),
      f[9], parseReviewRoundState(f[10]), parseU64(f[11]), parseU64(f[12]),
      parseU64(f[13]), f[14], f[15], f[16], f[17],
      parseU32(f[18]), parseU32(f[19]), parseU32(f[20]),
      parseU32(f[21]), parseU32(f[22]), parseU32(f[23]),
      parseU32(f[24]), parseU32(f[25]), parseU32(f[26]),
      parseU32(f[27]), parseU32(f[28]), f[29],
      parseAmount(f[30]).toString(), parseAmount(f[31]).toString(), parseBoolean(f[32]),
    );
  }

  bondAmount(): u128 { return parseAmount(this.bond); }
  refundableBondAmount(): u128 { return parseAmount(this.refundableBond); }
}

export class Proposal {
  constructor(
    public id: string,
    public proposalCid: string,
    public parentCid: string,
    public candidateCid: string,
    public patchCid: string,
    public reviewRoundId: string,
    public proposer: string,
    public risk: string,
    public state: u8,
    public agentRoot: string,
    public buildRoot: string,
    public availabilityRoot: string,
    public agentLeafCount: u32,
    public agentSubmittedCount: u32,
    public buildLeafCount: u32,
    public buildSubmittedCount: u32,
    public availabilityLeafCount: u32,
    public availabilitySubmittedCount: u32,
    public metadataRoot: string,
    public metricsRoot: string,
    public metricsEpoch: u16,
    public stakeEpoch: u16,
    public candidateMetricsRoot: string,
    public candidateMetricsEpoch: u16,
    public creationBlock: u64,
    public draftExpiry: u64,
    public votingStart: u64,
    public votingEnd: u64,
    public challengeEnd: u64,
    public executeAfter: u64,
    public snapshotWeight: string,
    public yesWeight: string,
    public noWeight: string,
    public abstainWeight: string,
    public yesIdentities: u32,
    public yesStrongIdentities: u32,
    public agentCount: u32,
    public agentModelCount: u32,
    public agentOwnerCount: u32,
    public unresolvedCriticalCount: u32,
    public builderOwnerCount: u32,
    public builderPlatformCount: u32,
    public builderConflictCount: u32,
    public availabilityOwnerCount: u32,
    public artifactDigest: string,
    public waiverCid: string,
    public releaseManifestCid: string,
    public challengeKind: string,
    public challengeTarget: string,
    public challengeEvidenceCid: string,
    public bond: string,
    public refundableBond: string,
    public bondClaimed: bool,
  ) {}

  encode(): string {
    const values = new Array<string>();
    values.push(this.id);
    values.push(this.proposalCid);
    values.push(this.parentCid);
    values.push(this.candidateCid);
    values.push(this.patchCid);
    values.push(this.reviewRoundId);
    values.push(this.proposer);
    values.push(this.risk);
    values.push(this.state.toString());
    values.push(this.agentRoot);
    values.push(this.buildRoot);
    values.push(this.availabilityRoot);
    values.push(this.agentLeafCount.toString());
    values.push(this.agentSubmittedCount.toString());
    values.push(this.buildLeafCount.toString());
    values.push(this.buildSubmittedCount.toString());
    values.push(this.availabilityLeafCount.toString());
    values.push(this.availabilitySubmittedCount.toString());
    values.push(this.metadataRoot);
    values.push(this.metricsRoot);
    values.push(this.metricsEpoch.toString());
    values.push(this.stakeEpoch.toString());
    values.push(this.candidateMetricsRoot);
    values.push(this.candidateMetricsEpoch.toString());
    values.push(this.creationBlock.toString());
    values.push(this.draftExpiry.toString());
    values.push(this.votingStart.toString());
    values.push(this.votingEnd.toString());
    values.push(this.challengeEnd.toString());
    values.push(this.executeAfter.toString());
    values.push(this.snapshotWeight);
    values.push(this.yesWeight);
    values.push(this.noWeight);
    values.push(this.abstainWeight);
    values.push(this.yesIdentities.toString());
    values.push(this.yesStrongIdentities.toString());
    values.push(this.agentCount.toString());
    values.push(this.agentModelCount.toString());
    values.push(this.agentOwnerCount.toString());
    values.push(this.unresolvedCriticalCount.toString());
    values.push(this.builderOwnerCount.toString());
    values.push(this.builderPlatformCount.toString());
    values.push(this.builderConflictCount.toString());
    values.push(this.availabilityOwnerCount.toString());
    values.push(this.artifactDigest);
    values.push(this.waiverCid);
    values.push(this.releaseManifestCid);
    values.push(this.challengeKind);
    values.push(this.challengeTarget);
    values.push(this.challengeEvidenceCid);
    values.push(this.bond);
    values.push(this.refundableBond);
    values.push(this.bondClaimed ? "1" : "0");
    return values.join("~");
  }

  static decode(value: string): Proposal {
    const f = value.split("~");
    assert(f.length == 53, "corrupt proposal record");
    return new Proposal(
      f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], parseProposalState(f[8]),
      f[9], f[10], f[11],
      parseU32(f[12]), parseU32(f[13]), parseU32(f[14]),
      parseU32(f[15]), parseU32(f[16]), parseU32(f[17]),
      f[18], f[19], parseU16(f[20]), parseU16(f[21]), f[22], parseU16(f[23]),
      parseU64(f[24]), parseU64(f[25]), parseU64(f[26]), parseU64(f[27]),
      parseU64(f[28]), parseU64(f[29]), f[30], f[31], f[32], f[33],
      parseU32(f[34]), parseU32(f[35]), parseU32(f[36]),
      parseU32(f[37]), parseU32(f[38]), parseU32(f[39]),
      parseU32(f[40]), parseU32(f[41]), parseU32(f[42]),
      parseU32(f[43]), f[44], f[45], f[46], f[47], f[48], f[49], f[50], f[51], parseBoolean(f[52]),
    );
  }

  isCritical(): bool {
    return this.risk != "normal";
  }

  snapshotWeightAmount(): u128 { return parseAmount(this.snapshotWeight); }
  yesWeightAmount(): u128 { return parseAmount(this.yesWeight); }
  noWeightAmount(): u128 { return parseAmount(this.noWeight); }
  abstainWeightAmount(): u128 { return parseAmount(this.abstainWeight); }
  bondAmount(): u128 { return parseAmount(this.bond); }
  refundableBondAmount(): u128 { return parseAmount(this.refundableBond); }
}

export class BondRecord {
  constructor(
    public owner: string,
    public amount: string,
    public slashed: bool,
    public claimed: bool,
  ) {}

  encode(): string {
    return this.owner + "~" + this.amount + "~" + (this.slashed ? "1" : "0") + "~" + (this.claimed ? "1" : "0");
  }

  static decode(value: string): BondRecord {
    const f = value.split("~");
    assert(f.length == 4, "corrupt bond record");
    return new BondRecord(
      f[0], parseAmount(f[1]).toString(), parseBoolean(f[2]), parseBoolean(f[3]),
    );
  }

  amountValue(): u128 { return parseAmount(this.amount); }
}

export function proposalKey(id: string): string { return "proposal:" + id; }
export function reviewRoundKey(id: string): string { return "review-round:" + id; }

export function loadReviewRound(id: string): ReviewRound {
  const value = getString(reviewRoundKey(id));
  assert(value.length > 0, "review round does not exist");
  return ReviewRound.decode(value);
}

export function saveReviewRound(round: ReviewRound): void {
  setString(reviewRoundKey(round.id), round.encode());
}

export function loadProposal(id: string): Proposal {
  const value = getString(proposalKey(id));
  assert(value.length > 0, "proposal does not exist");
  return Proposal.decode(value);
}

export function saveProposal(proposal: Proposal): void {
  setString(proposalKey(proposal.id), proposal.encode());
}

function parseReviewRoundState(value: string): u8 {
  const state = parseU8(value);
  assert(state <= REVIEW_ROUND_EXPIRED, "corrupt review round state");
  return state;
}

function parseProposalState(value: string): u8 {
  const state = parseU8(value);
  assert(state <= STATE_EXPIRED, "corrupt proposal state");
  return state;
}

function parseBoolean(value: string): bool {
  assert(value == "0" || value == "1", "corrupt boolean encoding");
  return value == "1";
}
