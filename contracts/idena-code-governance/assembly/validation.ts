import { flipTrustBps, statusBps } from "./math";
import { bytesToHex, hexToBytes, stringToBytes } from "./host";
import { sha256 } from "./sha256";

const METRICS_LEAF_DOMAIN = "IDENA_GOV_METRICS_V1\x00";
const METRICS_NODE_DOMAIN = "IDENA_GOV_MERKLE_V1\x00";
const METRICS_ROOT_DOMAIN = "IDENA_GOV_METRICS_ROOT_V1\x00";
const ATTESTATION_NODE_DOMAIN = "IDENA_GOV_ATTESTATION_MERKLE_V1\x00";
const ATTESTATION_ROOT_DOMAIN = "IDENA_GOV_ATTESTATION_ROOT_V1\x00";

export function isCanonicalManifestCid(value: string): bool {
  return decodeCanonicalCid(value, 0x71).length == 36;
}

export function isCanonicalRawCid(value: string): bool {
  return decodeCanonicalCid(value, 0x55).length == 36;
}

export function canonicalManifestCidSha256(value: string): string {
  const decoded = decodeCanonicalCid(value, 0x71);
  assert(decoded.length == 36, "CID must be canonical DAG-CBOR CIDv1/SHA2-256");
  const digest = new Uint8Array(32);
  memory.copy(digest.dataStart, decoded.dataStart + 4, digest.length);
  return bytesToHex(digest);
}

export function canonicalContentCidSha256(value: string): string {
  let decoded = decodeCanonicalCid(value, 0x71);
  if (decoded.length == 0) decoded = decodeCanonicalCid(value, 0x55);
  assert(decoded.length == 36, "CID must be canonical CIDv1/SHA2-256");
  const digest = new Uint8Array(32);
  memory.copy(digest.dataStart, decoded.dataStart + 4, digest.length);
  return bytesToHex(digest);
}

export function isCanonicalHash(value: string): bool {
  if (value.length != 64) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (!((code >= 48 && code <= 57) || (code >= 97 && code <= 102))) return false;
  }
  return true;
}

export function isSafeLabel(value: string, maxLength: i32 = 64): bool {
  if (value.length == 0 || value.length > maxLength) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const valid =
      (code >= 97 && code <= 122)
      || (code >= 48 && code <= 57)
      || code == 45
      || code == 46
      || code == 95;
    if (!valid) return false;
  }
  return true;
}

export function verifyIdentityMetricsProof(
  address: Uint8Array,
  state: string,
  totalFinalized: u64,
  totalReported: u64,
  trustBps: u16,
  sourceEpoch: u16,
  sourceHeight: u64,
  sourceBlockHash: string,
  index: u64,
  leafCount: u64,
  siblingsCsv: string,
  expectedRoot: string,
): bool {
  if (address.length != 20 || statusBps(state) == 0) return false;
  if (!isCanonicalHash(sourceBlockHash) || !isCanonicalHash(expectedRoot)) return false;
  if (totalReported > totalFinalized || flipTrustBps(totalFinalized, totalReported) != trustBps) return false;
  if (leafCount == 0 || index >= leafCount) return false;
  const siblings = siblingsCsv.length == 0 ? new Array<string>() : siblingsCsv.split(",");
  const levels = merkleLevelCount(leafCount);
  if (siblings.length != levels) return false;

  let current = identityLeafHash(
    address,
    state,
    totalFinalized,
    totalReported,
    trustBps,
    sourceEpoch,
    sourceHeight,
    sourceBlockHash,
  );
  let position = index;
  let count = leafCount;
  for (let i = 0; i < siblings.length; i++) {
    if (!isCanonicalHash(siblings[i])) return false;
    const sibling = hexToBytes(siblings[i]);
    let left = current;
    let right = sibling;
    if (position % 2 == 1) {
      left = sibling;
      right = current;
    } else if (position + 1 >= count && !bytesEqual(sibling, current)) {
      return false;
    }
    current = sha256(concat3(stringToBytes(METRICS_NODE_DOMAIN), left, right));
    position /= 2;
    count = ceilHalfU64(count);
  }
  const rootPayload = concat3(stringToBytes(METRICS_ROOT_DOMAIN), u64BigEndian(leafCount), current);
  return bytesToHex(sha256(rootPayload)) == expectedRoot;
}

export function verifyAttestationCommitment(
  domain: string,
  canonicalFields: string,
  index: u64,
  leafCount: u64,
  siblingsCsv: string,
  expectedRoot: string,
): bool {
  if (!isSafeLabel(domain, 40) || !isCanonicalHash(expectedRoot)) return false;
  if (leafCount == 0 || index >= leafCount || canonicalFields.length > 2048) return false;
  const siblings = siblingsCsv.length == 0 ? new Array<string>() : siblingsCsv.split(",");
  const levels = merkleLevelCount(leafCount);
  if (siblings.length != levels) return false;
  let current = sha256(concat3(stringToBytes(domain), new Uint8Array(1), stringToBytes(canonicalFields)));
  let position = index;
  let count = leafCount;
  for (let i = 0; i < siblings.length; i++) {
    if (!isCanonicalHash(siblings[i])) return false;
    const sibling = hexToBytes(siblings[i]);
    let left = current;
    let right = sibling;
    if (position % 2 == 1) {
      left = sibling;
      right = current;
    } else if (position + 1 >= count && !bytesEqual(sibling, current)) {
      return false;
    }
    current = sha256(concat3(stringToBytes(ATTESTATION_NODE_DOMAIN), left, right));
    position /= 2;
    count = ceilHalfU64(count);
  }
  const prefix = concat3(stringToBytes(ATTESTATION_ROOT_DOMAIN), stringToBytes(domain), new Uint8Array(1));
  const rootPayload = concat3(prefix, u64BigEndian(leafCount), current);
  return bytesToHex(sha256(rootPayload)) == expectedRoot;
}

export function buildAttestationCommitmentRoot(domain: string, canonicalFields: string[]): string {
  assert(isSafeLabel(domain, 40), "invalid attestation commitment domain");
  assert(canonicalFields.length > 0 && canonicalFields.length <= 256, "invalid attestation commitment size");
  const sorted = canonicalFields.slice(0);
  for (let i = 1; i < sorted.length; i++) {
    const value = sorted[i];
    let position = i;
    while (position > 0 && sorted[position - 1] > value) {
      sorted[position] = sorted[position - 1];
      position--;
    }
    sorted[position] = value;
  }
  const level = new Array<Uint8Array>();
  for (let i = 0; i < sorted.length; i++) {
    assert(sorted[i].length > 0 && sorted[i].length <= 2048, "invalid canonical attestation fields");
    if (i > 0) {
      const leftCid = sorted[i - 1].split("|")[0];
      const rightCid = sorted[i].split("|")[0];
      assert(leftCid != rightCid, "duplicate attestation CID in review round");
    }
    level.push(sha256(concat3(stringToBytes(domain), new Uint8Array(1), stringToBytes(sorted[i]))));
  }
  let current = level;
  while (current.length > 1) {
    const next = new Array<Uint8Array>();
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : left;
      next.push(sha256(concat3(stringToBytes(ATTESTATION_NODE_DOMAIN), left, right)));
    }
    current = next;
  }
  const prefix = concat3(stringToBytes(ATTESTATION_ROOT_DOMAIN), stringToBytes(domain), new Uint8Array(1));
  return bytesToHex(sha256(concat3(prefix, u64BigEndian(<u64>sorted.length), current[0])));
}

export function merkleLevelCount(leafCount: u64): i32 {
  let levels = 0;
  for (let count = leafCount; count > 1; count = ceilHalfU64(count)) levels++;
  return levels;
}

function ceilHalfU64(value: u64): u64 {
  return (value >> 1) + (value & 1);
}

export function identityLeafHash(
  address: Uint8Array,
  state: string,
  totalFinalized: u64,
  totalReported: u64,
  trustBps: u16,
  sourceEpoch: u16,
  sourceHeight: u64,
  sourceBlockHash: string,
): Uint8Array {
  return sha256(identityLeafPayload(
    address, state, totalFinalized, totalReported, trustBps,
    sourceEpoch, sourceHeight, sourceBlockHash,
  ));
}

export function identityLeafPayload(
  address: Uint8Array,
  state: string,
  totalFinalized: u64,
  totalReported: u64,
  trustBps: u16,
  sourceEpoch: u16,
  sourceHeight: u64,
  sourceBlockHash: string,
): Uint8Array {
  const payload = new Uint8Array(
    stringToBytes(METRICS_LEAF_DOMAIN).length + 20 + 1 + 8 + 8 + 2 + 2 + 8 + 32,
  );
  let offset = 0;
  const domain = stringToBytes(METRICS_LEAF_DOMAIN);
  memory.copy(payload.dataStart + offset, domain.dataStart, domain.length);
  offset += domain.length;
  memory.copy(payload.dataStart + offset, address.dataStart, address.length);
  offset += address.length;
  payload[offset++] = identityStateCode(state);
  writeU64BE(payload, offset, totalFinalized);
  offset += 8;
  writeU64BE(payload, offset, totalReported);
  offset += 8;
  writeU16BE(payload, offset, trustBps);
  offset += 2;
  writeU16BE(payload, offset, sourceEpoch);
  offset += 2;
  writeU64BE(payload, offset, sourceHeight);
  offset += 8;
  const sourceHash = hexToBytes(sourceBlockHash);
  memory.copy(payload.dataStart + offset, sourceHash.dataStart, sourceHash.length);
  return payload;
}

function identityStateCode(state: string): u8 {
  if (state == "Human") return 3;
  if (state == "Verified") return 2;
  if (state == "Newbie") return 1;
  return 0;
}

function base32Index(code: i32): i32 {
  if (code >= 97 && code <= 122) return code - 97;
  if (code >= 50 && code <= 55) return code - 24;
  return -1;
}

function decodeCanonicalCid(value: string, expectedCodec: u8): Uint8Array {
  if (value.length != 59 || value.charCodeAt(0) != 98) return new Uint8Array(0);
  const decoded = new Uint8Array(36);
  let decodedLength = 0;
  let accumulator: u32 = 0;
  let bits: i32 = 0;
  for (let i = 1; i < value.length; i++) {
    const symbol = base32Index(value.charCodeAt(i));
    if (symbol < 0) return new Uint8Array(0);
    accumulator = (accumulator << 5) | <u32>symbol;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (decodedLength >= decoded.length) return new Uint8Array(0);
      decoded[decodedLength++] = <u8>(accumulator >> bits);
      accumulator &= bits == 0 ? 0 : (<u32>1 << bits) - 1;
    }
  }
  // A 36-byte CID consumes 288 of the 290 encoded bits. Canonical no-padding
  // base32 requires the remaining two bits to be zero.
  if (decodedLength != 36 || bits != 2 || accumulator != 0) return new Uint8Array(0);
  if (
    decoded[0] != 0x01
    || decoded[1] != expectedCodec
    || decoded[2] != 0x12
    || decoded[3] != 0x20
  ) return new Uint8Array(0);
  return decoded;
}

function concat3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length + c.length);
  memory.copy(result.dataStart, a.dataStart, a.length);
  memory.copy(result.dataStart + a.length, b.dataStart, b.length);
  memory.copy(result.dataStart + a.length + b.length, c.dataStart, c.length);
  return result;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): bool {
  if (a.length != b.length) return false;
  let difference: u8 = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference == 0;
}

function u64BigEndian(value: u64): Uint8Array {
  const result = new Uint8Array(8);
  writeU64BE(result, 0, value);
  return result;
}

function writeU64BE(output: Uint8Array, offset: i32, value: u64): void {
  for (let i = 0; i < 8; i++) output[offset + i] = <u8>(value >> (<u64>(7 - i) * 8));
}

function writeU16BE(output: Uint8Array, offset: i32, value: u16): void {
  output[offset] = <u8>(value >> 8);
  output[offset + 1] = <u8>value;
}
