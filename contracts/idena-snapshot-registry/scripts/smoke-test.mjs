import { readFile } from "node:fs/promises";
import { TextDecoder, TextEncoder } from "node:util";

const wasmPath = new URL("../build/snapshot-registry-smoke.wasm", import.meta.url);
const wasm = await readFile(wasmPath);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const storage = new Map();
let attachedPayment = new Uint8Array();
let burnCount = 0;

let exports;

const imports = {
  env: {
    abort(messagePtr, filePtr, line, column) {
      throw new Error(
        `abort at ${readString(filePtr)}:${line}:${column}: ${readString(messagePtr)}`,
      );
    },
    get_storage(keyPtr) {
      const key = readString(keyPtr);
      const value = storage.get(key);
      if (!value) {
        return 0;
      }
      return writeBytes(value);
    },
    set_storage(keyPtr, valuePtr) {
      storage.set(readString(keyPtr), readBytes(valuePtr));
    },
    pay_amount() {
      return attachedPayment.length === 0 ? 0 : writeBytes(attachedPayment);
    },
    burn(amountPtr) {
      const amount = readBytes(amountPtr);
      if (amount.every((byte) => byte === 0)) {
        throw new Error("burn called with zero payment");
      }
      burnCount += 1;
    },
  },
};

const instance = await WebAssembly.instantiate(wasm, imports);
exports = instance.instance.exports;

for (const [name, payment] of [
  ["smokeStrictDateValidation", []],
  ["smokeRejectsAmbiguousDataRef", []],
  ["smokeRequiresPaymentForNewRecord", []],
  ["smokeStoresReadsAndRepeats", [1]],
  ["smokeRejectsSameRootConflict", [2]],
  ["smokeRejectsInvalidLookups", []],
]) {
  attachedPayment = new Uint8Array(payment);
  if (exports[name]() !== 1) {
    throw new Error(`${name} failed`);
  }
}

if (burnCount !== 2) {
  throw new Error(`expected 2 burns for 2 new records, got ${burnCount}`);
}

function readRegion(ptr) {
  if (ptr === 0) {
    return { offset: 0, len: 0 };
  }
  const view = new DataView(exports.memory.buffer);
  return {
    offset: view.getUint32(ptr, true),
    len: view.getUint32(ptr + 4, true),
  };
}

function readBytes(ptr) {
  const { offset, len } = readRegion(ptr);
  return new Uint8Array(exports.memory.buffer.slice(offset, offset + len));
}

function readString(ptr) {
  return decoder.decode(readBytes(ptr));
}

function writeBytes(bytes) {
  const ptr = exports.allocate(bytes.length);
  const { offset, len } = readRegion(ptr);
  if (len !== bytes.length) {
    throw new Error(`allocated region length ${len} does not match ${bytes.length}`);
  }
  new Uint8Array(exports.memory.buffer, offset, len).set(bytes);
  return ptr;
}
