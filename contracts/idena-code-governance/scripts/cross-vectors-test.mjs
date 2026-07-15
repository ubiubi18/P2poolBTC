import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { TextDecoder, TextEncoder } from "node:util";

const vectors = JSON.parse(await readFile(
  new URL("../../../tests/governance/voting-vectors-v1.json", import.meta.url),
  "utf8",
));
const ballotVectors = JSON.parse(await readFile(
  new URL("../../../tests/governance/epoch-ballot-vectors-v1.json", import.meta.url),
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
for (const item of ballotVectors.cases) {
  const chainId = Buffer.from(item.chainId);
  const u32 = (value) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32BE(value);
    return bytes;
  };
  const u64 = (value) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(BigInt(value));
    return bytes;
  };
  const commitment = createHash("sha256").update(Buffer.concat([
    Buffer.from(ballotVectors.domain),
    u32(chainId.length),
    chainId,
    Buffer.from(item.contractAddress.slice(2), "hex"),
    u64(item.governanceEpoch),
    Buffer.from(item.voterAddress.slice(2), "hex"),
    Buffer.from(item.frozenProposalSetRoot, "hex"),
    u32(item.choices.length),
    Buffer.from(item.choices.map((choice) => ({ yes: 1, no: 2, abstain: 3 })[choice])),
    u64(item.ballotNonce),
    Buffer.from(item.salt, "hex"),
  ])).digest("hex");
  assert.equal(commitment, item.expectedCommitment, item.name);
}

console.log(`AssemblyScript/JS vectors passed: ${vectors.flipTrustCases.length} trust, ${vectors.weightCases.length} weight, ${vectors.ageInvarianceCases.length} age-invariance, ${ballotVectors.cases.length} epoch-ballot`);

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
