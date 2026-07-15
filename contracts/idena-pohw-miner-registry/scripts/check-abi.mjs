import { readFile } from "node:fs/promises";

const wasm = await readFile(new URL("../build/idena-pohw-miner-registry.wasm", import.meta.url));
const module = new WebAssembly.Module(wasm);
const asconfig = JSON.parse(await readFile(new URL("../asconfig.json", import.meta.url), "utf8"));
if (!asconfig?.targets?.release?.disable?.includes("bulk-memory")) {
  throw new Error("release target must disable bulk-memory for the pinned Idena runtime");
}

const allowedImports = new Set([
  "env.abort",
  "env.get_storage",
  "env.remove_storage",
  "env.pay_amount",
  "env.set_storage",
  "env.emit_event",
  "env.caller",
  "env.original_caller",
  "env.create_get_identity_promise",
  "env.promise_then",
  "env.promise_result",
  "env.create_transfer_promise",
  "env.epoch",
  "env.block_number",
  "env.block_timestamp",
  "env.burn",
]);
for (const item of WebAssembly.Module.imports(module)) {
  const key = `${item.module}.${item.name}`;
  if (item.kind !== "function" || !allowedImports.has(key)) {
    throw new Error(`unexpected WASM import: ${key} (${item.kind})`);
  }
}

const requiredExports = new Set([
  "memory",
  "allocate",
  "deploy",
  "registerMiner",
  "_completeRegistration",
  "pendingRegistration",
  "cancelPendingRegistration",
  "rotateMinerCommitment",
  "currentRegistration",
  "registration",
  "voteCheckpoint",
  "_completeCheckpointVote",
  "cancelPendingCheckpointVote",
  "checkpoint",
  "latestCheckpoint",
  "contractParameters",
]);
const exports = new Set(WebAssembly.Module.exports(module).map((item) => item.name));
for (const name of requiredExports) {
  if (!exports.has(name)) throw new Error(`required WASM export is missing: ${name}`);
}
for (const name of exports) {
  if (!requiredExports.has(name)) throw new Error(`unexpected WASM export: ${name}`);
}

console.log(`ABI check passed: ${allowedImports.size} allowlisted imports, ${exports.size} exports`);
