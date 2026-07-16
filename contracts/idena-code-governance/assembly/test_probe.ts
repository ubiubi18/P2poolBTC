import { allocate, argumentString, bytesToHex, hexToBytes, returnString, stringToBytes } from "./host";
import { u128Safe as u128 } from "as-bignum/assembly";
import {
  STAKE_QUANTUM_ATOMS,
  effectiveVoteWeight,
  flipTrustBps,
  integerSqrt,
  parseAmount,
  parseU16,
  parseU32,
  parseU64,
  statusBps,
} from "./math";
import { sha256 } from "./sha256";
import { bootstrapMigrationAttestationsPass } from "./attestation_gates";
import { Proposal } from "./state";
import { identityLeafHash, identityLeafPayload, merkleLevelCount } from "./validation";

export { allocate };

export function hashUtf8(valuePtr: usize): usize {
  return returnString(bytesToHex(sha256(stringToBytes(argumentString(valuePtr)))));
}

export function parseAmountVector(valuePtr: usize): usize {
  return returnString(parseAmount(argumentString(valuePtr)).toString());
}

export function parseU64Vector(valuePtr: usize): usize {
  return returnString(parseU64(argumentString(valuePtr)).toString());
}

export function merkleLevelsVector(valuePtr: usize): usize {
  return returnString(merkleLevelCount(parseU64(argumentString(valuePtr))).toString());
}

export function flipTrustVector(finalizedPtr: usize, reportedPtr: usize): usize {
  return returnString(flipTrustBps(
    parseU64(argumentString(finalizedPtr)),
    parseU64(argumentString(reportedPtr)),
  ).toString());
}

export function weightVector(
  stakePtr: usize,
  statePtr: usize,
  finalizedPtr: usize,
  reportedPtr: usize,
): usize {
  const stake = parseAmount(argumentString(stakePtr));
  const state = argumentString(statePtr);
  const trust = flipTrustBps(
    parseU64(argumentString(finalizedPtr)),
    parseU64(argumentString(reportedPtr)),
  );
  const score = integerSqrt(stake / u128.fromU64(STAKE_QUANTUM_ATOMS));
  const weight = effectiveVoteWeight(stake, statusBps(state), trust);
  return returnString(score.toString() + "|" + trust.toString() + "|" + weight.toString());
}

export function identityLeafPayloadHex(
  addressPtr: usize,
  statePtr: usize,
  finalizedPtr: usize,
  reportedPtr: usize,
  trustPtr: usize,
  epochPtr: usize,
  heightPtr: usize,
  sourceHashPtr: usize,
): usize {
  return returnString(bytesToHex(identityLeafPayload(
    hexToBytes(argumentString(addressPtr)),
    argumentString(statePtr),
    parseU64(argumentString(finalizedPtr)),
    parseU64(argumentString(reportedPtr)),
    parseU16(argumentString(trustPtr)),
    parseU16(argumentString(epochPtr)),
    parseU64(argumentString(heightPtr)),
    argumentString(sourceHashPtr),
  )));
}

export function hashIdentityLeaf(
  addressPtr: usize,
  statePtr: usize,
  finalizedPtr: usize,
  reportedPtr: usize,
  trustPtr: usize,
  epochPtr: usize,
  heightPtr: usize,
  sourceHashPtr: usize,
): usize {
  return returnString(bytesToHex(identityLeafHash(
    hexToBytes(argumentString(addressPtr)),
    argumentString(statePtr),
    parseU64(argumentString(finalizedPtr)),
    parseU64(argumentString(reportedPtr)),
    parseU16(argumentString(trustPtr)),
    parseU16(argumentString(epochPtr)),
    parseU64(argumentString(heightPtr)),
    argumentString(sourceHashPtr),
  )));
}

export function bootstrapMigrationGateVector(
  riskPtr: usize,
  agentCountPtr: usize,
  agentOwnerCountPtr: usize,
  unresolvedCriticalCountPtr: usize,
  builderOwnerCountPtr: usize,
  builderConflictCountPtr: usize,
  availabilityOwnerCountPtr: usize,
  completeLeavesPtr: usize,
  waiverCidPtr: usize,
): usize {
  const completeLeaves = argumentString(completeLeavesPtr) == "1";
  const proposal = new Proposal(
    "proposal", "proposal-cid", "parent-cid", "candidate-cid", "patch-cid",
    "review-round", "owner", argumentString(riskPtr), 0,
    "agent-root", "build-root", "availability-root",
    5, completeLeaves ? 5 : 4,
    3, completeLeaves ? 3 : 2,
    3, completeLeaves ? 3 : 2,
    "metadata-root", "metrics-root", 1, 1, "candidate-metrics-root", 1,
    1, 2, 3, 4, 5, 6,
    "0", "0", "0", "0", 0, 0,
    parseU32(argumentString(agentCountPtr)), 0, 0,
    parseU32(argumentString(agentOwnerCountPtr)),
    parseU32(argumentString(unresolvedCriticalCountPtr)),
    parseU32(argumentString(builderOwnerCountPtr)), 0,
    parseU32(argumentString(builderConflictCountPtr)),
    parseU32(argumentString(availabilityOwnerCountPtr)),
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    argumentString(waiverCidPtr), "release-cid", "", "", "", "0", "0", false,
  );
  return returnString(bootstrapMigrationAttestationsPass(proposal) ? "1" : "0");
}
