import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { TextDecoder, TextEncoder } from "node:util";

const vectors = JSON.parse(await readFile(
  new URL("../../../tests/governance/voting-vectors-v1.json", import.meta.url),
  "utf8",
));
const wasm = await readFile(new URL("../build/test-probe.wasm", import.meta.url));
let exports;
const instance = await WebAssembly.instantiate(wasm, {
  env: {
    abort() { throw new Error("WASM assertion failed"); },
  },
});
exports = instance.instance.exports;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

assert.equal(
  call("parseU64Vector", ["18446744073709551615"]),
  "18446744073709551615",
  "maximum u64 must remain valid",
);
assert.throws(
  () => call("parseU64Vector", ["18446744073709551616"]),
  /WASM assertion failed/,
  "u64 overflow must fail closed",
);
assert.equal(
  call("parseAmountVector", ["340282366920938463463374607431768211455"]),
  "340282366920938463463374607431768211455",
  "maximum u128 must remain valid",
);
assert.throws(
  () => call("parseAmountVector", ["340282366920938463463374607431768211456"]),
  /WASM assertion failed/,
  "u128 overflow must fail closed",
);
assert.equal(
  call("merkleLevelsVector", ["18446744073709551615"]),
  "64",
  "maximum u64 leaf count must not overflow ceil-halving",
);

for (const item of vectors.flipTrustCases) {
  assert.equal(
    call("flipTrustVector", [item.finalized, item.reported]),
    String(item.expectedTrustBps),
    item.name,
  );
}
for (const item of vectors.invalidFlipTrustCases) {
  assert.throws(
    () => call("flipTrustVector", [item.finalized, item.reported]),
    /WASM assertion failed/,
    item.name,
  );
}
for (const item of vectors.weightCases) {
  const [score, trust, weight] = call("weightVector", [
    item.stakeAtoms, item.state, item.finalized, item.reported,
  ]).split("|");
  assert.equal(score, item.expectedStakeScore, `${item.name}: stake score`);
  assert.equal(trust, String(item.expectedTrustBps), `${item.name}: trust`);
  assert.equal(weight, item.expectedWeight, `${item.name}: weight`);
}
for (const item of vectors.ageInvarianceCases) {
  const args = [item.stakeAtoms, item.state, item.finalized, item.reported];
  const first = call("weightVector", args);
  const second = call("weightVector", args);
  assert.equal(first, second, "ignored age metadata changed the result");
  assert.equal(first.split("|")[2], item.expectedWeight);
}

console.log(`AssemblyScript vectors passed: ${vectors.flipTrustCases.length} trust, ${vectors.weightCases.length} weight, ${vectors.ageInvarianceCases.length} age-invariance`);

function call(method, args) {
  const pointers = args.map((value) => writeBytes(encoder.encode(String(value))));
  return readString(exports[method](...pointers));
}

function region(ptr) {
  const view = new DataView(exports.memory.buffer);
  return { offset: view.getUint32(ptr, true), length: view.getUint32(ptr + 4, true) };
}

function writeBytes(bytes) {
  const ptr = exports.allocate(bytes.length);
  const { offset, length } = region(ptr);
  new Uint8Array(exports.memory.buffer, offset, length).set(bytes);
  return ptr;
}

function readString(ptr) {
  const { offset, length } = region(ptr);
  return decoder.decode(new Uint8Array(exports.memory.buffer.slice(offset, offset + length)));
}
