import { u128Safe as u128 } from "as-bignum/assembly";

@external("env", "set_storage")
declare function envSetStorage(key: usize, value: usize): void;

@external("env", "get_storage")
declare function envGetStorage(key: usize): usize;

@external("env", "remove_storage")
declare function envRemoveStorage(key: usize): void;

@external("env", "caller")
declare function envCaller(): usize;

@external("env", "pay_amount")
declare function envPayAmount(): usize;

@external("env", "create_transfer_promise")
declare function envCreateTransferPromise(address: usize, amount: usize): void;

@external("env", "emit_event")
declare function envEmitEvent(name: usize, args: usize): void;

@external("env", "epoch")
declare function envEpoch(): u16;

@external("env", "block_number")
declare function envBlockNumber(): u64;

@external("env", "block_timestamp")
declare function envBlockTimestamp(): i64;

@external("env", "burn")
declare function envBurn(amount: usize): void;

@unmanaged
class Region {
  offset: u32;
  len: u32;
  capacity: u32;

  constructor(data: Uint8Array) {
    // Idena keeps only the numeric Region pointer between `allocate` calls.
    // Pin the backing view for the lifetime of this short-lived invocation so
    // AssemblyScript GC cannot recycle argument bytes before the export runs.
    __pin(changetype<usize>(data));
    this.offset = data.dataStart as u32;
    this.len = data.length as u32;
    this.capacity = data.length as u32;
  }

  read(): Uint8Array {
    const data = new Uint8Array(this.len);
    memory.copy(data.dataStart, this.offset, this.len);
    return data;
  }
}

export function allocate(size: u32): usize {
  return changetype<usize>(new Region(new Uint8Array(size)));
}

export function argumentString(ptr: usize, maxBytes: u32 = 4096): string {
  assert(ptr != 0, "missing argument");
  const bytes = ptrToBytes(ptr);
  assert(<u32>bytes.length <= maxBytes, "argument exceeds size limit");
  return bytesToString(bytes);
}

export function optionalArgumentString(ptr: usize, maxBytes: u32 = 4096): string {
  if (ptr == 0) return "";
  const bytes = ptrToBytes(ptr);
  assert(<u32>bytes.length <= maxBytes, "argument exceeds size limit");
  return bytesToString(bytes);
}

export function returnString(value: string): usize {
  return bytesToPtr(stringToBytes(value));
}

export function setString(key: string, value: string): void {
  assert(stringToBytes(key).length <= 512, "storage key exceeds contract limit");
  assert(stringToBytes(value).length <= 16384, "storage value exceeds contract limit");
  envSetStorage(stringToPtr(key), stringToPtr(value));
}

export function getString(key: string): string {
  const ptr = envGetStorage(stringToPtr(key));
  return ptr == 0 ? "" : bytesToString(ptrToBytes(ptr));
}

export function hasKey(key: string): bool {
  return envGetStorage(stringToPtr(key)) != 0;
}

export function removeKey(key: string): void {
  envRemoveStorage(stringToPtr(key));
}

export function callerBytes(): Uint8Array {
  const value = ptrToBytes(envCaller());
  assert(value.length == 20, "caller address must be 20 bytes");
  return value;
}

export function callerHex(): string {
  return bytesToHex(callerBytes());
}

export function attachedAmount(): u128 {
  const ptr = envPayAmount();
  if (ptr == 0) return u128.Zero;
  const bytes = ptrToBytes(ptr);
  assert(bytes.length <= 16, "attached amount exceeds u128");
  const padded = new Uint8Array(16);
  memory.copy(padded.dataStart + 16 - bytes.length, bytes.dataStart, bytes.length);
  return u128.fromUint8ArrayBE(padded);
}

export function requireNoPayment(): void {
  assert(attachedAmount().isZero(), "method does not accept attached payment");
}

export function transfer(address: Uint8Array, amount: u128): void {
  assert(address.length == 20, "transfer address must be 20 bytes");
  assert(!amount.isZero(), "transfer amount must be nonzero");
  envCreateTransferPromise(bytesToPtr(address), bytesToPtr(amount.toUint8Array(true)));
}

export function burn(amount: u128): void {
  assert(!amount.isZero(), "burn amount must be nonzero");
  envBurn(bytesToPtr(amount.toUint8Array(true)));
}

export function currentEpoch(): u16 {
  return envEpoch();
}

export function currentBlock(): u64 {
  return envBlockNumber();
}

export function currentTimestamp(): i64 {
  return envBlockTimestamp();
}

export function emitVersionedEvent(name: string, args: string[]): void {
  assert(name.length > 0 && name.length <= 32, "invalid event name length");
  const encoded = packArguments(args);
  assert(encoded.length <= 10240, "event arguments exceed runtime limit");
  envEmitEvent(stringToPtr(name), bytesToPtr(encoded));
}

export function ptrToBytes(ptr: usize): Uint8Array {
  if (ptr == 0) return new Uint8Array(0);
  return changetype<Region>(ptr).read();
}

export function bytesToPtr(data: Uint8Array): usize {
  if (data.length == 0) return 0;
  return changetype<usize>(new Region(data));
}

export function stringToPtr(value: string): usize {
  return bytesToPtr(stringToBytes(value));
}

export function stringToBytes(value: string): Uint8Array {
  const length = String.UTF8.byteLength(value, false);
  const bytes = new Uint8Array(length);
  memory.copy(bytes.dataStart, changetype<usize>(String.UTF8.encode(value, false)), length);
  return bytes;
}

export function bytesToString(bytes: Uint8Array): string {
  return String.UTF8.decode(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    true,
  );
}

export function bytesToHex(bytes: Uint8Array): string {
  const chars = "0123456789abcdef";
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    result += chars.charAt(bytes[i] >> 4);
    result += chars.charAt(bytes[i] & 15);
  }
  return result;
}

export function hexToBytes(value: string): Uint8Array {
  assert(value.length % 2 == 0, "hex value must have even length");
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i++) {
    const high = hexNibble(value.charCodeAt(i * 2));
    const low = hexNibble(value.charCodeAt(i * 2 + 1));
    assert(high >= 0 && low >= 0, "hex value must be lowercase ASCII");
    result[i] = <u8>((high << 4) | low);
  }
  return result;
}

function hexNibble(code: i32): i32 {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function packArguments(values: string[]): Uint8Array {
  let total = 1;
  const encoded = new Array<Uint8Array>();
  for (let i = 0; i < values.length; i++) {
    const value = stringToBytes(values[i]);
    const nestedLength = 1 + varintLength(<u32>value.length) + value.length;
    const itemLength = 1 + varintLength(<u32>nestedLength) + nestedLength;
    const item = new Uint8Array(itemLength);
    let offset = 0;
    item[offset++] = 0x0a;
    offset = writeVarint(item, offset, <u32>nestedLength);
    item[offset++] = 0x0a;
    offset = writeVarint(item, offset, <u32>value.length);
    memory.copy(item.dataStart + offset, value.dataStart, value.length);
    encoded.push(item);
    total += item.length;
  }
  const result = new Uint8Array(total);
  result[0] = 1;
  let offset = 1;
  for (let i = 0; i < encoded.length; i++) {
    memory.copy(result.dataStart + offset, encoded[i].dataStart, encoded[i].length);
    offset += encoded[i].length;
  }
  return result;
}

function varintLength(value: u32): i32 {
  let length = 1;
  while (value >= 128) {
    value >>= 7;
    length++;
  }
  return length;
}

function writeVarint(output: Uint8Array, offset: i32, value: u32): i32 {
  while (value >= 128) {
    output[offset++] = <u8>((value & 127) | 128);
    value >>= 7;
  }
  output[offset++] = <u8>value;
  return offset;
}
