# Governance Vertical-Slice Baseline

Recorded before governance edits on 2026-07-13 (Europe/Berlin). Revisions are
immutable commit IDs. No repository was fetched, reset, checked out, or cleaned
to create this record.

Absolute host paths are intentionally omitted from this shareable record. The
checkout labels below are stable operator-supplied names, not filesystem paths.

| Repository | Checkout label | Commit | Branch | Worktree |
| --- | --- | --- | --- | --- |
| `ubiubi18/P2poolBTC` | `P2poolBTC` | `473525c39c00ef9a6abb2602a9186f796695c6fe` | `vibe/bootstrap-difficulty-handoff-master` | dirty, 61 porcelain entries; existing work preserved |
| `ubiubi18/idena-go` | `idena-go` | `7e03b62a9e9b7d946a556c3ff8cb52d90faab615` | `vibe/legacy-compat-release-train` | clean |
| `ubiubi18/idena-desktop` | `idena-desktop` | `5d5bc47d90f90f21c8d19e2a99d783646f3ed02b` | `vibe/legacy-compat-release-train` | clean |
| `ubiubi18/idena-compat-stack` | `idena-compat-stack` | `cdee81b675fc2378f7e932b16ec465981bd047e0` | `vibe/rc3-gate-attestation` | clean |
| `ubiubi18/idena-wasm-binding` | `idena-wasm-binding` | `f2919cb3a2765f8b808ab5ae197d6d948910f45d` | `vibe/legacy-compat-release-train` | clean |
| `ubiubi18/idena-wasm` | `idena-wasm` | `bac21ef8e1bd1a54f867d7356eac1ba76dc7b8b3` | `vibe/legacy-compat-release-train` | clean |
| `ubiubi18/wasmer` | `wasmer` | `b537fb88764706488628b57ae9d17e367b1cd64a` | `vibe/legacy-compat-release-train` | clean |
| `ubiubi18/idena-sdk-js-lite` | `idena-sdk-js-lite` | `567d3f45cc7b1cacc6bf59eb43b2a60dbdf92aff` | `vibe/legacy-compat-release-train` | clean |

## Compatibility Pins

The unchanged legacy profile is
`idena-mainnet-legacy-compat-2026.07.12-rc3`. Its lock digest is
`e83f01033b1f2d5be1d404ef4c340fc9fd5736bf6ffd6c16c754167632807b98`.
It sets `consensusChangesAllowed=false` and pins:

| Component | Locked commit | Relation to inspected worktree |
| --- | --- | --- |
| `idena-go` | `aafb254786ac3c82308550a7a82642019f077d6b` | present; inspected worktree is 1 commit ahead |
| `idena-wasm-binding` | `67ba065fdb02aa07cced2a43a261e481ca5b39d9` | present; inspected worktree is 2 commits ahead |
| `idena-wasm` | `7e1138959f9f96f59d20efa11f2c27b134067541` | present; inspected worktree is 3 commits ahead |
| `wasmer` | `1637dea03c0110f7dd800f2d9781193caf820074` | present; inspected worktree is 2 commits ahead |
| `idena-sdk-js-lite` | `cc6e69b9b87aa381398b7839050a4640f46eb5ba` | present; inspected worktree is 3 commits ahead |

Direct consumers declared by the lock are `idena-desktop`,
`idena-social-contract-runner`, `idena-social-ui`, `idena-web`,
`idena-indexer`, and `P2poolBTC`. The latter four consumer repositories are
inventory-only for this vertical slice and are not modified.

The desktop source manifest pins `idena-go` to
`aafb254786ac3c82308550a7a82642019f077d6b` and `idena-wasm-binding` to
`67ba065fdb02aa07cced2a43a261e481ca5b39d9`; both match the compatibility lock.

## Lockfile Digests

All digests use SHA-256.

- P2poolBTC: `Cargo.lock` `74dd4684674a2b5d4a846c215de26db9fc6ceed4b5e641d05f38907394858430`;
  snapshot contract pnpm lock `defd5300f080b16ceb970bf5862a241705fd71511503606c97eeb771f74fc3f7`;
  dashboard pnpm lock `13d9c6354e4a797aeb267a42cfdab31f5e4f6234e181b1dc1494f992267cfec2`.
- idena-go: `go.mod` `2c893f802ab84d345c9fb116469145c546ddd4b2a2892d5a83bdd067f5a3834b`;
  `go.sum` `a4f322b4674765b85a22c78ff1aa0b4a70390fc07f83072d8ec365e5ebf7b708`.
- idena-desktop: `package-lock.json`
  `24f0180d013fbbb307f0e196b9113886e0ddc5ea1fb5f7601c4f9a6ed0afeb19`;
  `scripts/source-manifest.json`
  `9cc0fba7e682de898ce5c6696564a2e40db36762a5b728d8ee1e5f5392e1b3c6`.
- idena-wasm-binding: `go.mod`
  `11f36cc6a58e55f48b26f800ebd55cbcdf4c23b1fb8a433a08f37d1c219c21af`;
  `go.sum` `1c2d26a41ae556883e6df99696b1b48723b2d27d997c037b5314de600276ccae`.
- idena-wasm: `Cargo.lock`
  `8c0b62c5822d53a1562ab418717fe43b451ccce55917ac25e9b95700077955ae`;
  `rust-toolchain.toml`
  `404f81071062a23f245fc19302d4d0e68185bea2e4d31c520790ddd40d467fc0`.
- wasmer: `Cargo.lock`
  `1ca7e4ccd48bb14d486a4e82c0d5d1c4f896fec9b2e7d5606909e58dd4d38c2e`;
  `rust-toolchain` `2b92ea252be0fbc26f70317cdaa7b6411ea634b50d55338cd8c495e4dbf25d1d`.
- idena-sdk-js-lite: `package-lock.json`
  `9842b48134ccfe1ff97da1bd76882cf65dc421a954053a4ca82ff08a95bff8cc`.

## Toolchains Observed

- Git `2.52.0`
- Rust/Cargo `1.96.1`
- Go `1.26.1 darwin/arm64`
- Node.js `24.18.0`
- npm `11.16.0`
- Corepack `0.35.0`
- pnpm `11.11.0`
- Python `3.9.6`
- Docker `29.2.1`
- no host `ipfs` executable

The compatibility lock requests Rust `1.97.0` and Go `1.26.5`; exact locked
toolchain rebuilds are therefore a pending gate. Node and npm match.

## IPFS Separation Finding

The inspected idena-go runtime is not a public governance IPFS node. Its default
configuration sets a fixed swarm key in `config/flags.go`, and
`ipfs/configureIpfs` writes that key to `<idena-datadir>/ipfs/swarm.key` with
mode `0600` before constructing the Kubo node. Governance data must use a
different repository and process. No governance command may reuse the embedded
flip/block IPFS repository or its swarm key.
