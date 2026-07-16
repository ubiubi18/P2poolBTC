import { u128Safe as u128, u256Safe as u256 } from "as-bignum/assembly";
import {
  GOV_FLIP_PENALTY_SCALE,
  GOV_FLIP_PRIOR_REPORTED,
  GOV_FLIP_PRIOR_TOTAL,
  GOV_FLIP_TRUST_CEILING_BPS,
  GOV_FLIP_TRUST_FLOOR_BPS,
  GOV_STAKE_QUANTUM_ATOMS,
  GOV_STATUS_HUMAN_BPS,
  GOV_STATUS_NEWBIE_BPS,
  GOV_STATUS_VERIFIED_BPS,
} from "./generated_parameters";

export const STATUS_HUMAN_BPS: u16 = GOV_STATUS_HUMAN_BPS;
export const STATUS_VERIFIED_BPS: u16 = GOV_STATUS_VERIFIED_BPS;
export const STATUS_NEWBIE_BPS: u16 = GOV_STATUS_NEWBIE_BPS;
export const PRIOR_REPORTED: u64 = GOV_FLIP_PRIOR_REPORTED;
export const PRIOR_TOTAL: u64 = GOV_FLIP_PRIOR_TOTAL;
export const STAKE_QUANTUM_ATOMS: u64 = GOV_STAKE_QUANTUM_ATOMS;

export function statusBps(state: string): u16 {
  if (state == "Human") return STATUS_HUMAN_BPS;
  if (state == "Verified") return STATUS_VERIFIED_BPS;
  if (state == "Newbie") return STATUS_NEWBIE_BPS;
  return 0;
}

export function flipTrustBps(total: u64, reported: u64): u16 {
  assert(reported <= total, "reported authored flips exceed finalized authored flips");
  const numerator = (u128.fromU64(reported) + u128.fromU64(PRIOR_REPORTED)) * u128.fromU64(10000);
  const rate = numerator / (u128.fromU64(total) + u128.fromU64(PRIOR_TOTAL));
  const penalty = (rate * u128.fromU64(GOV_FLIP_PENALTY_SCALE)) / u128.fromU64(10000);
  let trust: u64 = GOV_FLIP_TRUST_FLOOR_BPS;
  const trustRange = <u64>(GOV_FLIP_TRUST_CEILING_BPS - GOV_FLIP_TRUST_FLOOR_BPS);
  if (penalty < u128.fromU64(trustRange)) trust = <u64>GOV_FLIP_TRUST_CEILING_BPS - penalty.lo;
  return <u16>trust;
}

export function integerSqrt(value: u128): u128 {
  if (value.isZero()) return u128.Zero;
  let x = value;
  let y = (value >> 1) + u128.One;
  while (y < x) {
    x = y;
    y = (x + value / x) >> 1;
  }
  return x;
}

export function effectiveVoteWeight(stakeAtoms: u128, identityStatusBps: u16, trustBps: u16): u128 {
  if (
    identityStatusBps == 0
      || trustBps < GOV_FLIP_TRUST_FLOOR_BPS
      || trustBps > GOV_FLIP_TRUST_CEILING_BPS
  ) return u128.Zero;
  const quanta = stakeAtoms / u128.fromU64(STAKE_QUANTUM_ATOMS);
  const score = integerSqrt(quanta);
  return (score * u128.fromU64(identityStatusBps) * u128.fromU64(trustBps))
    / u128.fromU64(100_000_000);
}

export function ratioAtLeast(numerator: u128, denominator: u128, requiredBps: u16): bool {
  if (denominator.isZero()) return false;
  const left = u256.fromU128(numerator) * u256.fromU64(10000);
  const right = u256.fromU128(denominator) * u256.fromU64(requiredBps);
  return left >= right;
}

export function parseAmount(value: string): u128 {
  assert(value.length > 0 && value.length <= 39, "amount must be a bounded decimal string");
  assert(value == "0" || value.charCodeAt(0) != 48, "amount must use canonical decimal encoding");
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    assert(code >= 48 && code <= 57, "amount must contain decimal digits only");
  }
  const parsed = u128.fromString(value, 10);
  assert(parsed.toString() == value, "amount exceeds u128");
  return parsed;
}

export function parseU64(value: string): u64 {
  assert(value.length > 0 && value.length <= 20, "u64 must be a bounded decimal string");
  assert(value == "0" || value.charCodeAt(0) != 48, "u64 must use canonical decimal encoding");
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    assert(code >= 48 && code <= 57, "u64 must contain decimal digits only: " + value);
  }
  const parsed = U64.parseInt(value);
  assert(parsed.toString() == value, "u64 value is out of range");
  return parsed;
}

export function parseU16(value: string): u16 {
  const parsed = parseU64(value);
  assert(parsed <= u16.MAX_VALUE, "value exceeds u16");
  return <u16>parsed;
}

export function parseU32(value: string): u32 {
  const parsed = parseU64(value);
  assert(parsed <= u32.MAX_VALUE, "value exceeds u32");
  return <u32>parsed;
}

export function parseU8(value: string): u8 {
  const parsed = parseU64(value);
  assert(parsed <= u8.MAX_VALUE, "value exceeds u8");
  return <u8>parsed;
}
