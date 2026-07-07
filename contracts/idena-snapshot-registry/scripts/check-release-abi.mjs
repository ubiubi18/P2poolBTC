import { readFile } from "node:fs/promises";

const wasmPath = new URL("../build/snapshot-registry.wasm", import.meta.url);
const wasm = await readFile(wasmPath);
const module = new WebAssembly.Module(wasm);

const expectedImports = [
  "env.abort:function",
  "env.burn:function",
  "env.get_storage:function",
  "env.pay_amount:function",
  "env.set_storage:function",
];
const expectedExports = [
  "allocate:function",
  "canonicalRecordLine:function",
  "getSnapshotRecordLine:function",
  "hasSnapshotRecord:function",
  "isValidSnapshotRecord:function",
  "memory:memory",
  "putSnapshotRecord:function",
  "schemaVersion:function",
  "snapshotDayPrefix:function",
  "snapshotKey:function",
];

assertList(
  "imports",
  WebAssembly.Module.imports(module).map((item) => `${item.module}.${item.name}:${item.kind}`),
  expectedImports,
);
assertList(
  "exports",
  WebAssembly.Module.exports(module).map((item) => `${item.name}:${item.kind}`),
  expectedExports,
);

function assertList(label, actual, expected) {
  const sortedActual = [...actual].sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(sortedActual) !== JSON.stringify(sortedExpected)) {
    throw new Error(
      `${label} mismatch\nexpected ${JSON.stringify(sortedExpected, null, 2)}\nactual ${JSON.stringify(sortedActual, null, 2)}`,
    );
  }
}
