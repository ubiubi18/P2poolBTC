# Idena Snapshot Registry

AssemblyScript WASM contract for anchoring PoHW Idena snapshot records.

This contract is not a source of truth for payouts. P2Pool nodes still verify
snapshot roots locally from `idena-go` RPC and sharechain votes. The contract is
only a public timestamp/data-availability anchor.

## Storage

Records are stored through Idena host imports matching `idena-sdk-core`:

- `env.get_storage`
- `env.set_storage`

The key is:

```text
snapshot:<snapshot_day>:<score_root>
```

This allows multiple candidate roots for the same day. A public caller cannot
block a day by writing a different root first. Repeating the exact same record is
idempotent; writing a different record to the same key returns `false`.

Creating a new key requires a non-zero attached payment. The contract burns that
payment before writing storage, so public state growth is not free. Exact repeat
submissions do not burn again because they do not create new storage.

Input validation is deliberately narrow:

- `snapshot_day` must be a real `YYYY-MM-DD` calendar date.
- hashes and roots must be 32-byte hex strings.
- `formula_version` and `idena_height` must be non-zero.
- `data_hash_or_cid` must be printable ASCII, at most 256 characters, and
  cannot contain `|` because that is the canonical-record delimiter.

## ABI

Important exports:

- `allocate(size)`
- `schemaVersion()`
- `snapshotKey(snapshotDay, scoreRoot)`
- `putSnapshotRecord(...)`
- `hasSnapshotRecord(snapshotDay, scoreRoot)`
- `getSnapshotRecordLine(snapshotDay, scoreRoot)`
- `canonicalRecordLine(...)`

`canonicalRecordLine` format:

```text
snapshot_day|idena_height|idena_block_hash|identity_root|score_root|formula_version|data_hash_or_cid
```

## Build

```sh
pnpm --dir contracts/idena-snapshot-registry install --frozen-lockfile
pnpm --dir contracts/idena-snapshot-registry build
pnpm --dir contracts/idena-snapshot-registry test
```

The test command runs a WASM smoke test against emulated Idena host storage and
checks the release WASM import/export surface.

`idena-sdk-as@0.0.29` is not imported directly because it currently pulls a
large legacy dependency graph through runtime dependencies. The storage adapter
uses the same host import ABI as `idena-sdk-core` while keeping this package
small and reproducible.
