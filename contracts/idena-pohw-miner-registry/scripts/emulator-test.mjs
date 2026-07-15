import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { TextDecoder, TextEncoder } from "node:util";

const wasm = await readFile(new URL("../build/idena-pohw-miner-registry.wasm", import.meta.url));
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const storage = new Map();
const events = [];
const burns = [];
const transfers = [];
const identityReads = [];
const identities = new Map();
let caller = Buffer.alloc(20, 1);
let originalCaller = caller;
let payment = 0n;
let epoch = 7;
let block = 100n;
let timestamp = 1_700_000_000n;
let pendingPromises = [];
let activePromiseResult = null;
let exports;

const imports = {
  env: {
    abort(messagePtr, filePtr, line, column) {
      throw new Error(`WASM assertion failed: ${readAssemblyScriptString(messagePtr)} at ${readAssemblyScriptString(filePtr)}:${line}:${column}`);
    },
    get_storage(keyPtr) {
      const value = storage.get(readString(keyPtr));
      return value === undefined ? 0 : writeBytes(value);
    },
    set_storage(keyPtr, valuePtr) {
      storage.set(readString(keyPtr), Buffer.from(readBytes(valuePtr)));
    },
    remove_storage(keyPtr) { storage.delete(readString(keyPtr)); },
    caller() { return writeBytes(caller); },
    original_caller() { return writeBytes(originalCaller); },
    pay_amount() { return payment === 0n ? 0 : writeBytes(bigEndian(payment)); },
    burn(amountPtr) { burns.push(fromBigEndian(readBytes(amountPtr))); },
    create_transfer_promise(addressPtr, amountPtr) {
      transfers.push({
        address: Buffer.from(readBytes(addressPtr)),
        amount: fromBigEndian(readBytes(amountPtr)),
      });
    },
    create_get_identity_promise(addressPtr, gasLimit) {
      const address = Buffer.from(readBytes(addressPtr));
      identityReads.push({ address, gasLimit });
      pendingPromises.push({ address, callback: null });
      return pendingPromises.length - 1;
    },
    promise_then(index, methodPtr, argsPtr, amountPtr, gasLimit) {
      assert.ok(index >= 0 && index < pendingPromises.length, "invalid promise index");
      assert.equal(amountPtr, 0, "identity callback must not transfer a deposit");
      assert.deepEqual(Buffer.from(readBytes(argsPtr)), Buffer.from([1]));
      pendingPromises[index].callback = { method: readString(methodPtr), gasLimit };
    },
    promise_result(statusPtr) {
      assert.ok(activePromiseResult, "promise_result called outside a callback");
      writeRegionByte(statusPtr, activePromiseResult.status);
      return activePromiseResult.status === 2 ? writeBytes(activePromiseResult.data) : 0;
    },
    emit_event(namePtr, argsPtr) {
      events.push({ name: readString(namePtr), args: Buffer.from(readBytes(argsPtr)) });
    },
    epoch() { return epoch; },
    block_number() { return block; },
    block_timestamp() { return timestamp; },
  },
};

const instance = await WebAssembly.instantiate(wasm, imports);
exports = instance.instance.exports;

const ecosystemCid = "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm";
call("deploy", ["p2poolbtc-experiment-1", ecosystemCid, "1000"]);
assert.equal(events.at(-1).name, "PohwMinerRegistryDeployedV1");

expectFailure(() => call("registerMiner", ["genesis-01", "aa".repeat(32)], { payment: 999n }));
expectFailure(() => call("registerMiner", ["genesis:01", "aa".repeat(32)], { payment: 1000n }));
assert.equal(burns.length, 0, "underpayment must not burn or write state");

const ineligibleCaller = Buffer.alloc(20, 9);
identities.set(ineligibleCaller.toString("hex"), protoIdentity(2));
const rejected = JSON.parse(call("registerMiner", ["candidate", "99".repeat(32)], {
  caller: ineligibleCaller,
  payment: 1000n,
}));
assert.equal(rejected.pending, true);
assert.equal(JSON.parse(call("currentRegistration", [`0x${ineligibleCaller.toString("hex")}`])).registration, null);
assert.deepEqual(transfers.at(-1), { address: ineligibleCaller, amount: 1000n });
assert.equal(burns.length, 0, "an ineligible identity must receive a refund, not a burn");

identities.set(caller.toString("hex"), protoIdentityWithIgnoredHistory(8));
const firstPending = JSON.parse(call("registerMiner", ["genesis-01", "aa".repeat(32)], { payment: 1000n }));
assert.equal(firstPending.pending, true);
const first = JSON.parse(call("currentRegistration", [`0x${"01".repeat(20)}`]));
assert.equal(first.address, `0x${"01".repeat(20)}`);
assert.equal(first.record, `1|genesis-01|${"aa".repeat(32)}|1|100|7|1700000000`);
assert.deepEqual(burns, [1000n]);
expectFailure(() => call("registerMiner", ["second", "bb".repeat(32)], { payment: 1000n }));

const queried = JSON.parse(call("registration", [first.address, "1"]));
assert.equal(queried.record, first.record);

const secondCaller = Buffer.alloc(20, 2);
identities.set(secondCaller.toString("hex"), protoIdentity(3));
expectFailure(() => call("registerMiner", ["genesis-01", "bb".repeat(32)], {
  caller: secondCaller,
  payment: 1000n,
}));

expectFailure(() => call("rotateMinerCommitment", ["aa".repeat(32)], { payment: 1000n }));
const rotated = JSON.parse(call("rotateMinerCommitment", ["bb".repeat(32)], {
  payment: 1000n,
  block: 101n,
  epoch: 8,
  timestamp: 1_700_000_020n,
}));
assert.equal(rotated.record, `1|genesis-01|${"bb".repeat(32)}|2|101|8|1700000020`);
assert.equal(JSON.parse(call("currentRegistration", [first.address])).record, rotated.record);
assert.equal(JSON.parse(call("registration", [first.address, "1"])).record, first.record);
assert.equal(events.filter((event) => event.name === "PohwMinerRegisteredV1").length, 1);
assert.equal(events.filter((event) => event.name === "PohwMinerCommitmentRotatedV1").length, 1);

expectFailure(() => call("contractParameters", [], { payment: 1n }));
const parameters = JSON.parse(call("contractParameters", []));
assert.equal(parameters.experimentId, "p2poolbtc-experiment-1");
assert.equal(parameters.minimumRegistrationBurnAtoms, "1000");
assert.equal(parameters.schemaVersion, 3);
assert.equal(parameters.contractVersion, "0.3.0");
assert.deepEqual(parameters.eligibleIdentityStates, ["Newbie", "Verified", "Human"]);
assert.equal(parameters.checkpointQuorumNumerator, 2);
assert.equal(parameters.checkpointQuorumDenominator, 3);
assert.equal(parameters.checkpointMinIntervalBlocks, "6");

const thirdCaller = Buffer.alloc(20, 3);
identities.set(thirdCaller.toString("hex"), protoIdentity(7));
call("registerMiner", ["second", "cc".repeat(32)], {
  caller: secondCaller,
  payment: 1000n,
  block: 102n,
  epoch: 8,
  timestamp: 1_700_000_040n,
});
call("registerMiner", ["third", "dd".repeat(32)], {
  caller: thirdCaller,
  payment: 1000n,
  block: 102n,
  epoch: 8,
  timestamp: 1_700_000_040n,
});
const secondRegistration = JSON.parse(call("currentRegistration", [`0x${"02".repeat(20)}`]));
const thirdRegistration = JSON.parse(call("currentRegistration", [`0x${"03".repeat(20)}`]));
assert.match(secondRegistration.record, /^1\|second\|/);
assert.match(thirdRegistration.record, /^1\|third\|/);

const unavailableCaller = Buffer.alloc(20, 4);
call("registerMiner", ["unavailable", "ee".repeat(32)], {
  caller: unavailableCaller,
  payment: 1000n,
});
assert.deepEqual(transfers.at(-1), { address: unavailableCaller, amount: 1000n });
assert.equal(JSON.parse(call("currentRegistration", [`0x${"04".repeat(20)}`])).registration, null);

const malformedCaller = Buffer.alloc(20, 5);
identities.set(malformedCaller.toString("hex"), Buffer.from([0x20, 0x80]));
call("registerMiner", ["malformed", "ef".repeat(32)], {
  caller: malformedCaller,
  payment: 1000n,
});
assert.deepEqual(transfers.at(-1), { address: malformedCaller, amount: 1000n });

const cancelledCaller = Buffer.alloc(20, 6);
identities.set(cancelledCaller.toString("hex"), protoIdentity(8));
const stranded = JSON.parse(call("registerMiner", ["cancelled", "f0".repeat(32)], {
  caller: cancelledCaller,
  payment: 1000n,
  flushPromises: false,
}));
assert.equal(stranded.pending, true);
assert.equal(JSON.parse(call("pendingRegistration", [], { caller: cancelledCaller })).pending, true);
assert.equal(JSON.parse(call("cancelPendingRegistration", [], { caller: cancelledCaller })).status, "refunded");
assert.deepEqual(transfers.at(-1), { address: cancelledCaller, amount: 1000n });
assert.equal(JSON.parse(call("pendingRegistration", [], { caller: cancelledCaller })).pending, null);

assert.ok(identityReads.every((read) => read.gasLimit === parameters.identityReadGasLimit));

const zeroHash = "00".repeat(32);
const firstTip = "11".repeat(32);
identities.set(Buffer.alloc(20, 1).toString("hex"), protoIdentity(2));
const staleVote = JSON.parse(call("voteCheckpoint", ["1", firstTip, "12", "345", zeroHash], {
  block: 103n,
  epoch: 8,
  timestamp: 1_700_000_060n,
}));
assert.equal(staleVote.pending, true);
assert.equal(JSON.parse(call("latestCheckpoint", [])).checkpoint, null);
assert.equal(events.at(-1).name, "PohwCheckpointVoteRejectedV1");
identities.set(Buffer.alloc(20, 1).toString("hex"), protoIdentity(8));
const firstVote = JSON.parse(call("voteCheckpoint", ["1", firstTip, "12", "345", zeroHash], {
  block: 103n,
  epoch: 8,
  timestamp: 1_700_000_060n,
}));
assert.equal(firstVote.pending, true);
assert.equal(JSON.parse(call("latestCheckpoint", [])).checkpoint, null);

const finalizingVote = JSON.parse(call("voteCheckpoint", ["1", firstTip, "12", "345", zeroHash], {
  caller: secondCaller,
  block: 103n,
  epoch: 8,
  timestamp: 1_700_000_060n,
}));
assert.equal(finalizingVote.pending, true);
const checkpointOne = JSON.parse(call("checkpoint", ["1"])).record;
assert.equal(
  checkpointOne,
  `1|1|${firstTip}|12|345|${zeroHash}|103|8|1700000060|2|3|genesis-01,second,third|genesis-01,second`,
);
assert.equal(JSON.parse(call("latestCheckpoint", [])).record, checkpointOne);
assert.equal(
  JSON.parse(call("voteCheckpoint", ["1", firstTip, "12", "345", zeroHash], {
    block: 104n,
  })).finalized,
  true,
  "retrying a finalized vote must be idempotent",
);
expectFailure(() => call("voteCheckpoint", ["2", "22".repeat(32), "13", "400", firstTip], {
  block: 108n,
}));

const secondTipA = "22".repeat(32);
const secondTipB = "33".repeat(32);
assert.equal(JSON.parse(call("voteCheckpoint", ["2", secondTipA, "13", "400", firstTip], {
  block: 109n,
})).pending, true);
assert.equal(JSON.parse(call("voteCheckpoint", ["2", secondTipB, "13", "401", firstTip], {
  block: 109n,
})).pending, true, "a voter may converge on a different candidate before finalization");
assert.equal(JSON.parse(call("voteCheckpoint", ["2", secondTipB, "13", "401", firstTip], {
  caller: secondCaller,
  block: 109n,
})).pending, true);
assert.match(JSON.parse(call("checkpoint", ["2"])).record, new RegExp(`^1\\|2\\|${secondTipB}\\|`));
expectFailure(() => call("voteCheckpoint", ["2", secondTipA, "13", "400", firstTip], {
  caller: thirdCaller,
  block: 110n,
}));

console.log("miner registry emulator tests passed");

function call(method, args, context = {}) {
  caller = context.caller ?? Buffer.alloc(20, 1);
  originalCaller = caller;
  payment = context.payment ?? 0n;
  block = context.block ?? 100n;
  epoch = context.epoch ?? 7;
  timestamp = context.timestamp ?? 1_700_000_000n;
  pendingPromises = [];
  const pointers = args.map((value) => writeBytes(encoder.encode(String(value))));
  const result = exports[method](...pointers);
  const output = result === undefined ? "" : readString(result);
  if (context.flushPromises !== false) flushPromises(originalCaller);
  pendingPromises = [];
  return output;
}

function flushPromises(origin) {
  for (const promise of pendingPromises) {
    assert.ok(promise.callback, "identity promise is missing its callback");
    assert.ok(
      promise.callback.method === "_completeRegistration"
        || promise.callback.method === "_completeCheckpointVote",
      `unexpected identity callback: ${promise.callback.method}`,
    );
    const identity = identities.get(promise.address.toString("hex"));
    activePromiseResult = identity === undefined
      ? { status: 1, data: Buffer.alloc(0) }
      : { status: 2, data: identity };
    caller = Buffer.alloc(20, 0xcc);
    originalCaller = origin;
    payment = 0n;
    exports[promise.callback.method]();
    activePromiseResult = null;
  }
}

function expectFailure(callback) {
  assert.throws(callback, /WASM assertion failed/);
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

function writeRegionByte(ptr, value) {
  const { offset, length } = region(ptr);
  assert.equal(length, 1);
  new Uint8Array(exports.memory.buffer, offset, length)[0] = value;
}

function readBytes(ptr) {
  if (ptr === 0) return new Uint8Array();
  const { offset, length } = region(ptr);
  return new Uint8Array(exports.memory.buffer.slice(offset, offset + length));
}

function readString(ptr) {
  return decoder.decode(readBytes(ptr));
}

function readAssemblyScriptString(ptr) {
  if (!ptr) return "";
  const view = new DataView(exports.memory.buffer);
  const length = view.getUint32(ptr - 4, true);
  return decoder.decode(new Uint8Array(exports.memory.buffer, ptr, length));
}

function bigEndian(value) {
  if (value === 0n) return Buffer.alloc(0);
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, "hex");
}

function fromBigEndian(bytes) {
  const hex = Buffer.from(bytes).toString("hex");
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function protoIdentity(state) {
  assert.ok(Number.isInteger(state) && state >= 0 && state < 128);
  return Buffer.from([0x20, state]);
}

function protoIdentityWithIgnoredHistory(state) {
  // Birthday (field 3) and generation (field 10) are deliberately present;
  // eligibility reads only the consensus identity state in field 4.
  return Buffer.from([0x18, 0xac, 0x02, 0x20, state, 0x50, 0x7f]);
}
