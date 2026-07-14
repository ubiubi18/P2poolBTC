import { bytesToString, hexToBytes, stringToBytes } from "./host";
import { sha256 } from "./sha256";
import { isCanonicalManifestCid } from "./validation";

const MAX_DAG_CBOR_BYTES = 65536;
const MAX_OBJECTIVE_RESULT_BYTES = 64;
const MAX_DEPTH = 24;
const MAX_ITEMS = 20000;
const MAX_TOP_LEVEL_FIELDS = 64;

class CborHead {
  constructor(public major: u8, public argument: u64) {}
}

const KIND_UNSIGNED: u8 = 0;
const KIND_TEXT: u8 = 1;
const KIND_ARRAY: u8 = 2;
const KIND_MAP: u8 = 3;
const KIND_BOOL: u8 = 4;
const KIND_NULL: u8 = 5;
const KIND_INTEGER: u8 = 6;
const KIND_LINK: u8 = 7;

class CanonicalDagCborValue {
  public arrayValues: Array<CanonicalDagCborValue> = new Array<CanonicalDagCborValue>();
  public mapValues: Map<string, CanonicalDagCborValue> = new Map<string, CanonicalDagCborValue>();

  constructor(
    public kind: u8,
    public scalar: string = "",
    public boolValue: bool = false,
  ) {}
}

export class CanonicalDagCborMap {
  public values: Map<string, CanonicalDagCborValue> = new Map<string, CanonicalDagCborValue>();

  set(key: string, value: CanonicalDagCborValue): void {
    assert(!this.values.has(key), "duplicate DAG-CBOR map key");
    this.values.set(key, value);
  }

  has(key: string): bool { return this.values.has(key); }
  size(): i32 { return this.values.size; }
  keys(): string[] { return this.values.keys(); }

  requireExactKeys(keys: string[]): void {
    assert(this.values.size == keys.length, "DAG-CBOR object has unknown or missing fields");
    for (let i = 0; i < keys.length; i++) {
      assert(this.values.has(keys[i]), "DAG-CBOR object is missing a required field");
    }
  }

  string(key: string): string {
    const value = this.value(key);
    assert(value.kind == KIND_TEXT, "DAG-CBOR field must be text");
    return value.scalar;
  }

  nullableString(key: string): string {
    const value = this.value(key);
    if (value.kind == KIND_NULL) return "";
    assert(value.kind == KIND_TEXT, "DAG-CBOR field must be text or null");
    return value.scalar;
  }

  link(key: string): string {
    const value = this.value(key);
    assert(value.kind == KIND_LINK, "DAG-CBOR field must be a CID link");
    return value.scalar;
  }

  nullableLink(key: string): string {
    const value = this.value(key);
    if (value.kind == KIND_NULL) return "";
    assert(value.kind == KIND_LINK, "DAG-CBOR field must be a CID link or null");
    return value.scalar;
  }

  unsigned(key: string): string {
    const value = this.value(key);
    assert(value.kind == KIND_UNSIGNED, "DAG-CBOR field must be an unsigned integer");
    return value.scalar;
  }

  integer(key: string): string {
    const value = this.value(key);
    assert(value.kind == KIND_UNSIGNED || value.kind == KIND_INTEGER, "DAG-CBOR field must be an integer");
    return value.scalar;
  }

  nullableUnsigned(key: string): string {
    const value = this.value(key);
    if (value.kind == KIND_NULL) return "";
    assert(value.kind == KIND_UNSIGNED, "DAG-CBOR field must be an unsigned integer or null");
    return value.scalar;
  }

  boolean(key: string): bool {
    const value = this.value(key);
    assert(value.kind == KIND_BOOL, "DAG-CBOR field must be boolean");
    return value.boolValue;
  }

  isNull(key: string): bool { return this.value(key).kind == KIND_NULL; }

  stringArray(key: string): string[] {
    const value = this.value(key);
    assert(value.kind == KIND_ARRAY, "DAG-CBOR field must be an array");
    const result = new Array<string>();
    for (let i = 0; i < value.arrayValues.length; i++) {
      const item = value.arrayValues[i];
      assert(item.kind == KIND_TEXT, "DAG-CBOR array entries must be text");
      result.push(item.scalar);
    }
    return result;
  }

  linkArray(key: string): string[] {
    const value = this.value(key);
    assert(value.kind == KIND_ARRAY, "DAG-CBOR field must be an array");
    const result = new Array<string>();
    for (let i = 0; i < value.arrayValues.length; i++) {
      const item = value.arrayValues[i];
      assert(item.kind == KIND_LINK, "DAG-CBOR array entries must be CID links");
      result.push(item.scalar);
    }
    return result;
  }

  objectArray(key: string): CanonicalDagCborMap[] {
    const value = this.value(key);
    assert(value.kind == KIND_ARRAY, "DAG-CBOR field must be an array");
    const result = new Array<CanonicalDagCborMap>();
    for (let i = 0; i < value.arrayValues.length; i++) {
      const item = value.arrayValues[i];
      assert(item.kind == KIND_MAP, "DAG-CBOR array entries must be objects");
      result.push(new CanonicalDagCborMap(item.mapValues));
    }
    return result;
  }

  object(key: string): CanonicalDagCborMap {
    const value = this.value(key);
    assert(value.kind == KIND_MAP, "DAG-CBOR field must be an object");
    return new CanonicalDagCborMap(value.mapValues);
  }

  private value(key: string): CanonicalDagCborValue {
    assert(this.values.has(key), "DAG-CBOR object is missing a required field");
    return this.values.get(key);
  }

  constructor(values: Map<string, CanonicalDagCborValue> = new Map<string, CanonicalDagCborValue>()) {
    this.values = values;
  }
}

class CanonicalCborReader {
  private offset: i32 = 0;
  private items: i32 = 0;

  constructor(private bytes: Uint8Array) {}

  readTopLevelMap(): CanonicalDagCborMap {
    const head = this.readHead();
    assert(head.major == 5, "canonical governance payload must be a DAG-CBOR map");
    assert(head.argument <= <u64>MAX_TOP_LEVEL_FIELDS, "DAG-CBOR object has too many fields");
    const result = this.readMapBody(head.argument, 1);
    assert(this.offset == this.bytes.length, "trailing bytes after canonical DAG-CBOR object");
    return result;
  }

  private readMapBody(length: u64, depth: i32): CanonicalDagCborMap {
    assert(length <= <u64>MAX_ITEMS, "DAG-CBOR map exceeds deterministic limit");
    const result = new CanonicalDagCborMap();
    let previousKey = new Uint8Array(0);
    for (let i: u64 = 0; i < length; i++) {
      const keyStart = this.offset;
      const key = this.readText();
      const encodedKey = this.copyRange(keyStart, this.offset);
      if (previousKey.length > 0) {
        assert(compareCanonicalKeys(previousKey, encodedKey) < 0, "DAG-CBOR map keys are not canonical");
      }
      previousKey = encodedKey;
      result.set(key, this.readValue(depth + 1));
    }
    return result;
  }

  private readValue(depth: i32): CanonicalDagCborValue {
    assert(depth <= MAX_DEPTH, "DAG-CBOR nesting exceeds deterministic limit");
    this.items++;
    assert(this.items <= MAX_ITEMS, "DAG-CBOR item count exceeds deterministic limit");
    const head = this.readHead();
    if (head.major == 0) return new CanonicalDagCborValue(KIND_UNSIGNED, head.argument.toString());
    if (head.major == 1) {
      assert(head.argument < u64.MAX_VALUE, "negative DAG-CBOR integer exceeds deterministic range");
      return new CanonicalDagCborValue(KIND_INTEGER, "-" + (head.argument + 1).toString());
    }
    assert(head.major != 2, "unlinked byte strings are not supported in governance payloads");
    if (head.major == 3) return new CanonicalDagCborValue(KIND_TEXT, this.readTextBody(head.argument));
    if (head.major == 4) {
      assert(head.argument <= <u64>MAX_ITEMS, "DAG-CBOR array exceeds deterministic limit");
      const result = new CanonicalDagCborValue(KIND_ARRAY);
      for (let i: u64 = 0; i < head.argument; i++) result.arrayValues.push(this.readValue(depth + 1));
      return result;
    }
    if (head.major == 5) {
      const result = new CanonicalDagCborValue(KIND_MAP);
      result.mapValues = this.readMapBody(head.argument, depth).values;
      return result;
    }
    if (head.major == 6) {
      assert(head.argument == 42, "only DAG-CBOR CID link tag 42 is supported");
      const bytesHead = this.readHead();
      assert(bytesHead.major == 2 && bytesHead.argument == 37, "DAG-CBOR CID link has invalid byte encoding");
      const linked = this.copyRange(this.offset, this.offset + 37);
      this.offset += 37;
      assert(linked[0] == 0, "DAG-CBOR CID link is missing the identity prefix");
      assert(linked[1] == 1, "DAG-CBOR CID link must use CIDv1");
      assert(linked[2] == 0x71 || linked[2] == 0x55, "DAG-CBOR CID link uses an unsupported codec");
      assert(linked[3] == 0x12 && linked[4] == 0x20, "DAG-CBOR CID link must use SHA2-256");
      const cidBytes = this.copyRange(this.offset - 36, this.offset);
      return new CanonicalDagCborValue(KIND_LINK, "b" + base32Lower(cidBytes));
    }
    assert(head.major == 7, "unsupported DAG-CBOR major type");
    if (head.argument == 20) return new CanonicalDagCborValue(KIND_BOOL, "", false);
    if (head.argument == 21) return new CanonicalDagCborValue(KIND_BOOL, "", true);
    if (head.argument == 22) return new CanonicalDagCborValue(KIND_NULL);
    assert(false, "floats and unsupported simple DAG-CBOR values are forbidden");
    return new CanonicalDagCborValue(KIND_NULL);
  }

  private readText(): string {
    const head = this.readHead();
    assert(head.major == 3, "DAG-CBOR map keys must be text");
    return this.readTextBody(head.argument);
  }

  private readTextBody(length: u64): string {
    assert(length <= <u64>(this.bytes.length - this.offset), "truncated DAG-CBOR text");
    const encoded = this.copyRange(this.offset, this.offset + <i32>length);
    this.offset += <i32>length;
    const value = bytesToString(encoded);
    const roundTrip = stringToBytes(value);
    assert(bytesEqual(encoded, roundTrip), "DAG-CBOR text is not valid canonical UTF-8");
    return value;
  }

  private readHead(): CborHead {
    assert(this.offset < this.bytes.length, "truncated DAG-CBOR value");
    const initial = this.bytes[this.offset++];
    const major = initial >> 5;
    const additional = initial & 31;
    if (additional < 24) return new CborHead(major, additional);
    assert(additional <= 27, "indefinite or reserved DAG-CBOR lengths are forbidden");
    const width = 1 << (additional - 24);
    assert(this.offset + width <= this.bytes.length, "truncated DAG-CBOR argument");
    let argument: u64 = 0;
    for (let i = 0; i < width; i++) argument = (argument << 8) | this.bytes[this.offset++];
    if (width == 1) assert(argument >= 24, "non-minimal DAG-CBOR integer or length");
    if (width == 2) assert(argument > u8.MAX_VALUE, "non-minimal DAG-CBOR integer or length");
    if (width == 4) assert(argument > u16.MAX_VALUE, "non-minimal DAG-CBOR integer or length");
    if (width == 8) assert(argument > u32.MAX_VALUE, "non-minimal DAG-CBOR integer or length");
    return new CborHead(major, argument);
  }

  private copyRange(start: i32, end: i32): Uint8Array {
    assert(start >= 0 && end >= start && end <= this.bytes.length, "invalid DAG-CBOR byte range");
    const result = new Uint8Array(end - start);
    if (result.length > 0) memory.copy(result.dataStart, this.bytes.dataStart + start, result.length);
    return result;
  }
}

export function verifiedCanonicalDagCborMap(cid: string, hexBytes: string): CanonicalDagCborMap {
  assert(isCanonicalManifestCid(cid), "content CID must be canonical DAG-CBOR CIDv1");
  assert(hexBytes.length > 0 && hexBytes.length <= MAX_DAG_CBOR_BYTES * 2, "DAG-CBOR payload exceeds contract limit");
  const bytes = hexToBytes(hexBytes);
  assert(bytes.length <= MAX_DAG_CBOR_BYTES, "DAG-CBOR payload exceeds contract limit");
  assert(cidForDagCbor(bytes) == cid, "DAG-CBOR payload does not match its declared CID");
  return new CanonicalCborReader(bytes).readTopLevelMap();
}

export function cidForDagCbor(bytes: Uint8Array): string {
  const digest = sha256(bytes);
  const multicodec = new Uint8Array(36);
  multicodec[0] = 0x01;
  multicodec[1] = 0x71;
  multicodec[2] = 0x12;
  multicodec[3] = 0x20;
  memory.copy(multicodec.dataStart + 4, digest.dataStart, digest.length);
  return "b" + base32Lower(multicodec);
}

export function verifiedFalseResult(cid: string, hexBytes: string, field: string): void {
  assert(field == "passed" || field == "available", "unsupported objective-result field");
  assert(hexBytes.length > 0 && hexBytes.length <= MAX_OBJECTIVE_RESULT_BYTES * 2, "objective result exceeds contract limit");
  const bytes = hexToBytes(hexBytes);
  assert(bytes.length <= MAX_OBJECTIVE_RESULT_BYTES, "objective result exceeds contract limit");
  assert(cidForRaw(bytes) == cid, "objective result does not match its declared raw CID");
  const expected = field == "passed" ? "{\"passed\":false}" : "{\"available\":false}";
  assert(bytesToString(bytes) == expected, "objective result is not the canonical false-result payload");
}

export function cidForRaw(bytes: Uint8Array): string {
  const digest = sha256(bytes);
  const multicodec = new Uint8Array(36);
  multicodec[0] = 0x01;
  multicodec[1] = 0x55;
  multicodec[2] = 0x12;
  multicodec[3] = 0x20;
  memory.copy(multicodec.dataStart + 4, digest.dataStart, digest.length);
  return "b" + base32Lower(multicodec);
}

function base32Lower(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let accumulator: u32 = 0;
  let bits: i32 = 0;
  let output = "";
  for (let i = 0; i < bytes.length; i++) {
    accumulator = (accumulator << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet.charAt(<i32>((accumulator >> bits) & 31));
      accumulator &= bits == 0 ? 0 : (1 << bits) - 1;
    }
  }
  if (bits > 0) output += alphabet.charAt(<i32>((accumulator << (5 - bits)) & 31));
  return output;
}

function compareCanonicalKeys(left: Uint8Array, right: Uint8Array): i32 {
  if (left.length < right.length) return -1;
  if (left.length > right.length) return 1;
  for (let i = 0; i < left.length; i++) {
    if (left[i] < right[i]) return -1;
    if (left[i] > right[i]) return 1;
  }
  return 0;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): bool {
  if (left.length != right.length) return false;
  let difference: u8 = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference == 0;
}
