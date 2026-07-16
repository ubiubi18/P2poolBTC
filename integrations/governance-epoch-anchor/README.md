# Governance epoch anchor runtime integration

This directory records an **inactive experimental fork candidate** for the
`env.epoch_block` governance-contract import. It must not be applied to the
legacy-compatible Idena profile or deployed to mainnet.

The enabled import returns `State.EpochBlock()`, charges the existing
`ReadGlobalStateGas`, and has no side effects. The post-audit contract artifact
is exactly 302419 bytes, SHA-256
`976000dfc3a1e309550d77ace079e19d9547544f7e6029b58e0a48493535285a`, raw
CID `bafkreiexmaan7q5b4mevkdlxvtqhtym5svdvit36mau3ldqkjbetknjili`, with 13
imports and 64 exports. The historical governance-fork lock and its d894
artifact remain unchanged.

## Feature and ABI contract

- Existing binding `Execute` and `Deploy` entry points use a zero feature mask.
- New `ExecuteWithFeatures` and `DeployWithFeatures` entry points accept the
  explicit `FeatureEpochBlock` bit. Unknown bits fail closed.
- With the bit disabled, the Rust resolver does not register
  `env.epoch_block`; modules importing it fail as unresolved. A callback error
  is not used as a substitute for omission.
- The feature mask propagates through nested contract calls and deployments.
- The legacy C `GoApi` layout and its 31 callback offsets are unchanged.
  `GoApi_v2` appends ABI version, ABI size, and the epoch callback after the
  complete legacy prefix. Version, size, and required callback mismatches fail
  before execution.
- The node enables no feature today. Its fixed reviewed activation source is
  restricted to candidate network 10002 and returns no authorized height or
  genesis, so every network and height resolves to a zero mask. Mainnet network
  1 is permanently disabled by this candidate.

## Exact bases

| Repository | Base commit | Patch |
| --- | --- | --- |
| `ubiubi18/idena-go` | `aafb254786ac3c82308550a7a82642019f077d6b` | `idena-go.patch` |
| `ubiubi18/idena-wasm-binding` | `67ba065fdb02aa07cced2a43a261e481ca5b39d9` | `idena-wasm-binding.patch` |
| `ubiubi18/idena-wasm` | `7e1138959f9f96f59d20efa11f2c27b134067541` | `idena-wasm.patch` |
| `ubiubi18/wasmer` | `1637dea03c0110f7dd800f2d9781193caf820074` | unchanged |

Exact patch digests, deterministic patched-source CIDs and CAR hashes,
toolchains, ABI facts, artifact identity, and the production-test overlay are
recorded in `compatibility/governance-day-fork-candidate-lock.json`. Candidate
commits remain `null`; deployment and release authorization remain false.

## Disposable application

Run the matching pair from each repository at its exact base commit:

```sh
git apply --check /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-wasm.patch
git apply /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-wasm.patch

git apply --check /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-wasm-binding.patch
git apply /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-wasm-binding.patch

git apply --check /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-go.patch
git apply /path/to/P2poolBTC/integrations/governance-epoch-anchor/idena-go.patch
```

Use Rust 1.97.0 and Go 1.26.5. Rebuild the native archive from patched
`idena-wasm`, install only that platform archive into a disposable binding
checkout, refresh its `lib/SHA256SUMS` row, and add a local binding replacement
to the disposable `idena-go/go.mod`.

The historical runtime-test source stays immutable. The gate reconstructs the
candidate test by applying `idena-go-runtime-test.patch` to that digest-bound
base. Run the exact candidate source and production-runtime checks with:

```sh
python3 scripts/pohw-governance-runtime-gate.py \
  --idena-go /tmp/idena-go \
  --fork-candidate-lock compatibility/governance-day-fork-candidate-lock.json \
  --component-repo idena-wasm-binding=/tmp/idena-wasm-binding \
  --component-repo idena-wasm=/tmp/idena-wasm \
  --verify-candidate-sources-only \
  --governance-cli target/debug/pohw-governance

python3 scripts/pohw-governance-runtime-gate.py \
  --idena-go /tmp/idena-go \
  --fork-candidate-lock compatibility/governance-day-fork-candidate-lock.json \
  --component-repo idena-wasm-binding=/tmp/idena-wasm-binding \
  --component-repo idena-wasm=/tmp/idena-wasm
```

Without `--fork-candidate-lock`, the gate intentionally verifies the historical
prototype lock and artifact. Current Governance Day build and CI records must
use the candidate lock; they must not reinterpret the historical metadata as
the current contract.

## Remaining blockers

Only the local Darwin ARM64 native archive has been rebuilt in this validation.
Every supported archive still needs independent reproducible builds. No
activation height or genesis is authorized, no preactivation chain replay or
rollback rehearsal has been attested, and no candidate component has a final
commit. These are deliberate release blockers, not implied future values.

Supplying the host value does not authorize a proposal, choose an epoch
boundary, replace a canonical ecosystem CID, or grant deployment authority.
