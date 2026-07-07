// Minimal Idena host adapter, matching idena-sdk-core's storage and payment ABI
// without importing the SDK's legacy dependency graph.

@external("env", "set_storage")
declare function envSetStorage(key: usize, value: usize): void;

@external("env", "get_storage")
declare function envGetStorage(key: usize): usize;

@external("env", "pay_amount")
declare function envPayAmount(): usize;

@external("env", "burn")
declare function envBurn(amount: usize): void;

@unmanaged
class Region {
  offset: u32;
  len: u32;
  capacity: u32;

  constructor(data: Uint8Array) {
    this.offset = data.dataStart as u32;
    this.len = data.length as u32;
    this.capacity = data.length as u32;
  }

  read(): Uint8Array {
    let data = new Uint8Array(this.len);
    memory.copy(data.dataStart, this.offset, this.len);
    return data;
  }
}

export function allocate(size: u32): usize {
  let data = new Uint8Array(size);
  return changetype<usize>(new Region(data));
}

export function writeString(key: string, value: string): void {
  envSetStorage(stringToPtr(key), stringToPtr(value));
}

export function readString(key: string): string {
  let ptr = envGetStorage(stringToPtr(key));
  if (ptr == 0) {
    return "";
  }
  return ptrToString(ptr);
}

export function hasString(key: string): bool {
  return envGetStorage(stringToPtr(key)) != 0;
}

export function burnAttachedPayment(): bool {
  let amount = envPayAmount();
  if (!regionHasNonZeroBytes(amount)) {
    return false;
  }
  envBurn(amount);
  return true;
}

function stringToPtr(value: string): usize {
  if (value.length == 0) {
    return 0;
  }
  return changetype<usize>(new Region(stringToBytes(value)));
}

function ptrToString(ptr: usize): string {
  let data = changetype<Region>(ptr).read();
  return String.UTF8.decode(
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
    true
  );
}

function stringToBytes(value: string): Uint8Array {
  let len = String.UTF8.byteLength(value, true) - 1;
  let bytes = new Uint8Array(len);
  memory.copy(bytes.dataStart, changetype<usize>(String.UTF8.encode(value)), len);
  return bytes;
}

function regionHasNonZeroBytes(ptr: usize): bool {
  if (ptr == 0) {
    return false;
  }
  let region = changetype<Region>(ptr);
  for (let i: u32 = 0; i < region.len; i++) {
    if (load<u8>(region.offset + i) != 0) {
      return true;
    }
  }
  return false;
}
