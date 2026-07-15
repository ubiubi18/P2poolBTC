import { u128Safe as u128 } from "as-bignum/assembly";

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

export function parseU32(value: string): u32 {
  assert(value.length > 0 && value.length <= 10, "u32 must be a bounded decimal string");
  assert(value == "0" || value.charCodeAt(0) != 48, "u32 must use canonical decimal encoding");
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    assert(code >= 48 && code <= 57, "u32 must contain decimal digits only");
  }
  const parsed = U32.parseInt(value);
  assert(parsed.toString() == value, "u32 value is out of range");
  return parsed;
}

export function parseU64(value: string): u64 {
  assert(value.length > 0 && value.length <= 20, "u64 must be a bounded decimal string");
  assert(value == "0" || value.charCodeAt(0) != 48, "u64 must use canonical decimal encoding");
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    assert(code >= 48 && code <= 57, "u64 must contain decimal digits only");
  }
  const parsed = U64.parseInt(value);
  assert(parsed.toString() == value, "u64 value is out of range");
  return parsed;
}
