# Experiment 1: Full-Consensus Bitcoin Fork

Experiment 1 is the no-value successor to the immutable, coinbase-only
Experiment 0 prototype. It runs a pinned patch over Bitcoin Core v31.1 and
inherits Bitcoin mainnet history through block `958016`. It does not alter
Bitcoin mainnet, Idena consensus, or Experiment 0 history.

The canonical local manifest is
[`compatibility/experiment-1-full-consensus.json`](compatibility/experiment-1-full-consensus.json).
New participants should follow the source-first
[Community Experiment 1 Guide](COMMUNITY-EXPERIMENT-1.md); this document remains
the complete operator and consensus runbook.
That guide joins the existing experiment from exact pinned source by default;
it does not trust a coordinator signature or lead-developer release key. A new
manifest or activation ID creates a separate experiment and must be an explicit
operator choice.
Read the current profile revision, activation ID, superseded activation ID,
and fork pin directly from that exact file; do not copy an activation ID from
an older runbook revision:

```sh
python3 - <<'PY'
import json
manifest = json.load(open("compatibility/experiment-1-full-consensus.json"))
for field in ("profile_revision", "activation_id", "supersedes_activation_id"):
    print(f"{field}={manifest[field]}")
print(f"first_fork_hash={manifest['fork_point']['first_fork_hash']}")
PY
```

Compare that value and the manifest bytes through independent participant
channels before connecting a node or miner. A different activation ID is a
different experiment.

> [!WARNING]
> Fork coins and inherited fork balances have no promised monetary value, but
> inherited scripts use the same private keys and address encodings as Bitcoin
> mainnet. An exposed or reused key can still lose real BTC. Mixed-input replay
> protection prevents ordinary exact replay; it does not make a reused private
> key independent. Do not import a valuable Bitcoin mainnet key.

The coordinator and intended first participants report no valuable Bitcoin
mainnet outputs under the test keys. That is an operational assertion, not a
consensus guarantee. Every participant must verify their own mainnet exposure.
The software deliberately does not disable inherited spending based on wallet
balance, address history, or a coordinator policy.

> [!WARNING]
> Idena remains a live chain. Identity signatures are public proofs, and
> delegation, stake, validation participation, transactions, and contract calls
> can change real IDNA balances or identity state. P2poolBTC must never receive
> an Idena private key, node key, backup, password, or API key.

## Consensus Scope

Experiment 1 delegates transaction, script, mempool, wallet, PSBT, and UTXO
validation to the complete upstream Bitcoin Core v31.1 engine. It supports all
upstream consensus-valid forms, including:

- legacy P2PK, P2PKH, multisig, P2SH, CLTV, and CSV;
- SegWit v0 P2WPKH, P2WSH, and nested SegWit;
- Taproot key-path and script-path spends and Tapscript;
- arbitrary other scripts accepted by the pinned upstream consensus rules;
- post-fork transactions and spends of inherited mainnet UTXOs.

Upstream relay policy still applies. "Consensus-valid" does not mean every
nonstandard script is relayed by the default mempool or created by the wallet.

Experiment 0 remains coinbase-only. Its activation and existing history are
not upgraded or reinterpreted.

## Replay Isolation

The exact consensus rule activates at height `958018`, not at the first fork
height. At or above activation, every non-coinbase transaction that consumes
an output created at or below height `958016` must also consume an activated,
zero-value coinbase output whose spent script is exactly the fork-only marker
script `5150`. An ordinary post-fork output does **not** satisfy this rule. The
first fork block is pinned as an immutable consensus checkpoint in the current
manifest. The marker executes
`OP_RESERVED` and is invalid on Bitcoin mainnet even if an outpoint collides.
The rule is enforced in mempool admission and block connection.

Height `958017` predates marker enforcement. Operators must not admit or mine
an inherited-input transaction at that height. The first supported live
inherited spend requires a marker emitted by an activated fork coinbase and
then 100 confirmations under Bitcoin Core's unchanged coinbase-maturity rule.
This is a replay separator, not a ban on inherited spending.

Do not broadcast an Experiment 1 transaction to Bitcoin mainnet. Do not assume
that an address showing an inherited balance is safe to test with.

## Network And Fork Point

| Field | Value |
| --- | --- |
| Core source | Bitcoin Core `v31.1` |
| Exact source commit | `9be056a8a72b624dae9623b2f7bded92c2a21c91` |
| Last inherited height | `958016` |
| First fork height | `958017` |
| Chain argument | `pohw` |
| Datadir subdirectory | `pohw-experiment-1` |
| P2P port | `40412` |
| RPC port | `40414`, loopback only |
| Bootstrap target | `207fffff` |
| Handoff threshold | target-implied `1 PH/s` |
| Post-handoff DAA | Bitcoin 2016-block retarget |

The full inherited block hash and network magic live in the manifest and
compiled patch. Operational status output may redact them; validation does not.

## Build From Source

Do not install a coordinator-provided binary. Build the exact pinned upstream
revision and verify the tracked patch:

```sh
git clone https://github.com/bitcoin/bitcoin.git bitcoin-pohw-v31.1
git -C bitcoin-pohw-v31.1 checkout --detach \
  9be056a8a72b624dae9623b2f7bded92c2a21c91

python3 scripts/pohw-experiment-1-manifest.py verify \
  compatibility/experiment-1-full-consensus.json

scripts/pohw-build-bitcoin-core-fork.sh \
  --source-dir "$PWD/bitcoin-pohw-v31.1" \
  --build-dir "$PWD/bitcoin-pohw-v31.1/build-pohw-check"
```

The check build first creates and hashes a byte-identical working copy of
Bitcoin Core's pinned `depends` subtree, then runs its recipes in two recorded
phases: `download-one` and `install`. The downloaded archives are checked by
the upstream recipes, the installed dependency prefix is sealed read-only, and
its complete tree hash plus `toolchain.cmake` hash are committed to
`pohw-build-evidence.json`. CMake must use that exact toolchain. The build then
runs the complete CTest suite against the unstripped binaries, then records a
platform-aware CMake install with stripping and binds those release-artifact
hashes to the exact source commit, patch, dependency source, dependency prefix,
CMake configuration, commands, and toolchain versions. Darwin builds disable
the otherwise path-sensitive linker UUID before the ad-hoc signature is
created. C and C++ compilation map the immutable source and scratch build
directories to `/pohw/source` and `/pohw/build`, preventing dependency headers
and generated sources from embedding a builder's local paths. Platform signing
and notarization remain separate external steps.

This evidence proves what one builder used; it is not by itself a
reproducibility claim. Release acceptance still requires matching artifact
digests from the required independent clean-room builders. Enforce network
isolation around `depends_build`, configure, build, and test at the container or
host boundary; the script records the fetch boundary but cannot implement a
portable operating-system firewall.

On a dedicated Linux host, install from a separate new or empty scratch build
directory. By default the privileged installer rebuilds the source itself; it
does not trust a caller-provided prebuilt binary. It installs the daemon and
unit without starting either service:

```sh
sudo scripts/pohw-install-bitcoin-core-fork.sh \
  --source-dir "$PWD/bitcoin-pohw-v31.1" \
  --build-dir "$PWD/bitcoin-pohw-v31.1/build-pohw-install"
```

The installer refuses a source tree containing anything beyond the exact
pinned patch, rejects a nonempty install-build directory, reruns all tests,
verifies build evidence, rejects symlinked destinations, and refuses to replace
binaries while the service is active. It stages the complete installation on
the destination filesystem, swaps it into place atomically, and retains the
previous binary directory and unit for rollback. It does not enable or start a
service.

The installer deliberately rejects `--use-verified-build`. A reusable
self-authored evidence file cannot prove to the privileged installer that the
recorded commands actually ran, so installation always uses a new empty build
and reruns the tests under the unprivileged build account.

After the fork has reached replay-marker activation, verify the live mempool
gate without signing or broadcasting a transaction. The probe uses one
unspent inherited coinbase output and one unspent marker output only as inputs
to `testmempoolaccept`; it never changes either UTXO:

```sh
sudo -u bitcoin-pohw \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/pohw-experiment-1-replay-probe
```

Success requires the unprotected inherited spend to fail specifically at the
replay gate. The otherwise identical marker-protected probe must pass that gate
and either reach a later consensus rule, such as coinbase maturity, or be
accepted by the mempool simulation. Transaction IDs and raw transactions are
never printed.

Once the chain has a mature replay marker, a participant who controls an
inherited output can run the stronger wallet/PSBT acceptance test. Use only a
dedicated fork wallet and an address owned by that same wallet. The command
signs locally, submits both forms only to `testmempoolaccept`, passes signed
PSBT material to `bitcoin-cli` over stdin, prints no transaction material, and
has no broadcast mode:

```sh
read -r -p 'Inherited TXID:VOUT: ' INHERITED_OUTPOINT
read -r -p 'Fork-wallet destination: ' FORK_DESTINATION
sudo -u bitcoin-pohw \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/pohw-experiment-1-wallet-acceptance \
  --wallet experiment-1-only \
  --inherited-outpoint "$INHERITED_OUTPOINT" \
  --destination "$FORK_DESTINATION"
unset INHERITED_OUTPOINT FORK_DESTINATION
```

Success means the Core-signed unprotected PSBT is rejected specifically by the
replay gate and the otherwise equivalent marker-protected PSBT is accepted by
mempool simulation. It does not move any coin. The test fails closed if the
node is not on the pinned `pohw` chain, the destination is not owned by the
selected wallet, the supplied output was created after the fork point, the
marker is immature or spent, a non-marker input is not finalized, or any
outpoint changes during PSBT processing.

Bitcoin Core's generic PSBT finalizer represents an empty final script field as
"not finalized." The replay marker intentionally requires an empty scriptSig
and witness. The acceptance tool therefore performs one narrow extraction
step: it accepts Core's finalized data for every ordinary input and leaves only
the independently verified marker input empty. It is not a general-purpose
PSBT finalizer.

## First-Seed Bootstrap

This procedure is only for a host whose full Bitcoin mainnet node can be
stopped exactly at the pinned fork point. It stops and temporarily masks the
source service, reopens it offline to verify the tip, and holds the datadir lock
for the entire copy. It refuses a moved tip or symlinked state. A root-owned,
unpublished staging tree receives chainstate, indexes, and independently owned
block files. Historical files use copy-on-write reflinks when available and
ordinary copies otherwise; the active blk/rev tail is always byte-copied
without a reflink. No source file is hard-linked or has its ownership or mode
changed. The service account receives ownership only after the staged tree is
complete and atomically published. Wallets, cookies, credentials, peer state,
logs, settings, and mempool data are excluded.

```sh
sudo scripts/pohw-bootstrap-bitcoin-core-fork.sh \
  --source-datadir /srv/bitcoin/mainnet \
  --target-base /srv/bitcoin/pohw \
  --source-service bitcoind-mainnet.service \
  --restart-main

sudo systemctl enable --now bitcoind-pohw-experiment-1.service
```

Never point both daemons at one writable datadir. Never copy a mainnet wallet
into the fork datadir.

A later participant can synchronize from Experiment 1 peers using the same
source-built binary and an empty datadir. That requires full historical
validation unless a separately specified, hash-verified AssumeUTXO snapshot is
added. A pruned node remains a consensus node but serves less history. A
participant using somebody else's remote Core RPC is trusting that operator
and is not independently validating the fork.

## Verify Success

On the full node host:

```sh
sudo -u bitcoin-pohw \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw getblockchaininfo

sudo -u bitcoin-pohw \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw getnetworkinfo
```

Success requires:

- `chain` is exactly `pohw`, never `main`;
- `pohw_experiment.fork_height` is `958016`;
- `pohw_experiment.inherited_utxo_spending` is `true`;
- the replay-protection name matches the manifest;
- the active block height advances above `958016` after mining starts;
- peers report the fork-specific network, not Bitcoin mainnet peers.

After an accepted submission, compare this Core height with the dashboard Fork
blocks count and compare local sharechain status with the dashboard Sharechain
count. A screenshot is not independent evidence. A Core wallet balance proves
control only when a loaded fork-only wallet owns the payout descriptor; an
explorer or pool balance is not automatically wallet balance.

Bitcoin Core Qt can display the fork only when the separately built
`bitcoin-qt` is launched with `-chain=pohw -datadir=<fork-base>`. A wallet shows
only outputs controlled by its descriptors. An explorer balance is not
automatically a wallet balance.

## Idena Registry Launch Interlock

Experiment 1 is still blocked pending deployment and independent review of the
ownerless Idena miner registry. The exact local candidate is
[`compatibility/experiment-1-miner-registry-candidate.json`](compatibility/experiment-1-miner-registry-candidate.json).
It binds every source file, the WASM SHA-256 and raw CID, the production-runtime
test, toolchains, and pinned `idena-wasm-binding`. It explicitly reports one
local builder, no external review, no verified deployment, and no deployment
authorization.

The v0.3 contract reads `RawIdentity` through Idena's existing promise ABI and
parses only identity-state protobuf field 4. Registration and each checkpoint
vote finalize only for Newbie, Verified, or Human. Age, birthday, generation,
and validation history are ignored. Failed, malformed, or ineligible
registrations are refunded; transaction fees remain spent. A vote from an
identity that became ineligible is discarded before it can add support.

Verify the exact candidate against a local idena-go checkout with:

```sh
corepack pnpm@11.11.0 --dir contracts/idena-pohw-miner-registry \
  install --frozen-lockfile
corepack pnpm@11.11.0 --dir contracts/idena-pohw-miner-registry test
PYTHONDONTWRITEBYTECODE=1 python3 \
  scripts/pohw-miner-registry-runtime-gate.py \
  --idena-go /path/to/exact/idena-go-worktree
```

Do not deploy from one local result. Activation requires at least two
independent matching builds, explicit review of the immutable deploy arguments,
a finalized Idena deployment receipt, and a replacement launch-policy sidecar
whose status is `ready`. The current
[`compatibility/experiment-1-launch-policy.json`](compatibility/experiment-1-launch-policy.json)
remains fail-closed.

Registration-time eligibility prevents arbitrary paid accounts from filling
the registry, but it does not eliminate eligible identity farming. The quorum
denominator remains the registered set; abandoned or later-ineligible
registrations can stall checkpoints because this ownerless version has no
administrator that can eject them. See
[`docs/idena-miner-registry.md`](docs/idena-miner-registry.md) for the complete
call flow and residual risks.

## P2Pool Adapter

Build the adapter with the keyless clean-room procedure in
[`docs/governance/OPERATIONS.md`](docs/governance/OPERATIONS.md), selecting the
`rust-workspace` target. Keep `build-evidence.json`,
`source-verification.json`, `test-results.json`, and `build-environment.json`
in one evidence directory. Verify its evidence and source CIDs through an
independent channel. Record those independently obtained values without
recomputing them from the local evidence directory; otherwise the comparison
does not establish a trust boundary. Then stop both processes that may execute
the adapter and install the exact evidence-bound release binary atomically:

```sh
python3 scripts/pohw-governance-build-evidence.py validate-plan \
  --plan compatibility/governance-build-plan-v1.json
test -f /protected/rust-workspace-evidence/build-evidence.json
EXPECTED_EVIDENCE_SHA256='<lowercase SHA-256 from the independent channel>'
EXPECTED_SOURCE_CID='<base32 CIDv1 from the independent channel>'
sudo systemctl stop pohw-mining-adapter.service pohw-gossip-mesh.service
sudo scripts/pohw-install-experiment-1-adapter.sh \
  --source-root "$PWD" \
  --build-plan compatibility/governance-build-plan-v1.json \
  --build-evidence /protected/rust-workspace-evidence/build-evidence.json \
  --expected-evidence-sha256 "$EXPECTED_EVIDENCE_SHA256" \
  --expected-source-cid "$EXPECTED_SOURCE_CID" \
  --binary "$PWD/target/release/p2pool-node"
```

The installer refuses symlinked inputs and destinations, checks that both
services are inactive, verifies the artifact digest, dependency lock, source
CID evidence, clean-room properties, allowlisted command results, and exact
build-plan reference before and after replacement, and retains one
`p2pool-node.previous` rollback copy. It never executes caller-supplied code as
root and never starts a service. It also requires the selected evidence digest
and source CID as explicit inputs, but evidence is still not a signature or
trust root; those values must come from an independent channel.

Copy non-secret settings from
[`deploy/pohw-experiment-1.env.example`](deploy/pohw-experiment-1.env.example).
The critical binding is:

```sh
EXPERIMENT_MANIFEST="$PWD/compatibility/experiment-1-full-consensus.json"
ACTIVATION_ID=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["activation_id"])' \
  "$EXPERIMENT_MANIFEST")
DATA_SUBDIRECTORY=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["network"]["data_subdirectory"])' \
  "$EXPERIMENT_MANIFEST")
ACTIVATION_PREFIX=${ACTIVATION_ID:0:8}
EXPERIMENT_DATADIR="/srv/sharechain/${DATA_SUBDIRECTORY}-${ACTIVATION_PREFIX}"

POHW_BITCOIN_RPC_URL=http://127.0.0.1:40414
POHW_BITCOIN_EXPECTED_CHAIN=pohw
POHW_BITCOIN_RPC_COOKIE_FILE=/run/bitcoin-pohw-rpc/.cookie
POHW_DATADIR="$EXPERIMENT_DATADIR"
POHW_GOSSIP_NETWORK_ID="$ACTIVATION_ID"
POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true
POHW_STRATUM_ALLOW_MAINNET_SUBMIT=false
```

The manifest-derived values above are authoritative. The separately owned
`deploy/pohw-experiment-1.env.example` must be regenerated for the current
profile before it can be treated as a copy-ready example.

The adapter fails closed when RPC reports any other chain. Both the mining and
gossip services require read-only access through `bitcoin-pohw-rpc` when peer
template admission is enabled; never copy the cookie into Git or an environment
file.

On an existing Experiment 0 host, switch profiles without displaying or
rewriting identity values by hand:

```sh
EXPERIMENT_MANIFEST="$PWD/compatibility/experiment-1-full-consensus.json"
ACTIVATION_ID=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["activation_id"])' \
  "$EXPERIMENT_MANIFEST")
DATA_SUBDIRECTORY=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["network"]["data_subdirectory"])' \
  "$EXPERIMENT_MANIFEST")
ACTIVATION_PREFIX=${ACTIVATION_ID:0:8}
EXPERIMENT_DATADIR="/srv/sharechain/${DATA_SUBDIRECTORY}-${ACTIVATION_PREFIX}"

sudo install -m 0644 deploy/systemd/pohw-mining-experiment-1.conf \
  /etc/systemd/system/pohw-mining-adapter.service.d/experiment-1.conf
sudo install -d -m 0755 \
  /etc/systemd/system/pohw-gossip-mesh.service.d
sudo install -m 0644 deploy/systemd/pohw-gossip-experiment-1.conf \
  /etc/systemd/system/pohw-gossip-mesh.service.d/experiment-1.conf
sudo scripts/pohw-activate-experiment-1-profile.py \
  --manifest "$EXPERIMENT_MANIFEST" \
  --env-file /etc/pohw/p2pool.env
sudo scripts/pohw-activate-experiment-1-profile.py \
  --manifest "$EXPERIMENT_MANIFEST" \
  --env-file /etc/pohw/p2pool.env --check
sudo -u pohw /usr/local/libexec/p2pool-experiment-1/p2pool-node \
  migrate-gossip-seed \
  --source-datadir /srv/sharechain/pohw-p2pool \
  --target-datadir "$EXPERIMENT_DATADIR" \
  --network-id "$ACTIVATION_ID" \
  --miner-id '<existing-miner-id>' \
  --node-secret-key-file '<existing-gossip-node-key-path>'
sudo install -m 0600 /dev/null /etc/pohw/enable-experiment-1-mining
sudo systemctl daemon-reload
sudo systemctl restart pohw-gossip-mesh.service pohw-mining-adapter.service
sudo systemctl is-active --quiet \
  pohw-gossip-mesh.service pohw-mining-adapter.service
```

The profile switch derives its network binding and datadir suffix from the
selected manifest. It is atomic, preserves file ownership and mode, saves the
exact pre-change file as `p2pool.env.experiment-1.previous`, and binds a fresh
Experiment 1 sharechain datadir to the exact activation ID, removes the
old custom fork RPC settings and stale Experiment 0 share-target overrides,
and keeps mainnet submission disabled. It refuses to reinterpret a nonempty
legacy datadir; Experiment 0 remains an immutable archive. After the adapter verifies that RPC
reports exactly `chain=pohw`, it derives the initial Stratum share target from
the live block template. The new gate name prevents an old Experiment 0
approval marker from starting this adapter accidentally.

To roll back the environment profile, stop both consumers and atomically
restore the backup. It contains the same private operator values as the
original environment and must keep restrictive permissions:

```sh
sudo systemctl stop pohw-mining-adapter.service pohw-gossip-mesh.service
sudo scripts/pohw-activate-experiment-1-profile.py \
  --env-file /etc/pohw/p2pool.env --rollback
sudo systemctl restart pohw-gossip-mesh.service pohw-mining-adapter.service
```

`migrate-gossip-seed` verifies the stored legacy gossip signatures, copies only
the selected miner registration and its latest snapshot vote, wraps both in
network-bound gossip envelopes, and requires the target to contain no shares,
templates, payouts, or withdrawals. It never copies legacy shares or rewrites
the old signed history.

Before the first Experiment 1 share exists, the payout commitment uses the
all-zero share parent as the explicit genesis anchor. The first accepted share
also uses that parent. For that first job only, the configured miner receives a
provisional nonzero hashrate score when constructing the 50% hashrate payout
pool; after acceptance, its real first-share score produces the same sole-miner
allocation. Every later job and commitment must use the active
Experiment 1 share tip; the zero anchor cannot reappear after a share exists.

The SD-only Pi is observer-only and deliberately kept at low load. It does not
run this Core fork, gossip mesh, Stratum adapter, or any miner. It reaches the
Hetzner services over the existing private tunnel for observation and remote
status only.

### Bounded Stratum Acceptance Check

The bounded smoke miner connects only to a numeric loopback address, requests
one live Stratum job, performs at most the configured number of hashes, and
submits through P2Pool. It does not call Bitcoin Core generation RPC and does
not access a wallet. Run it only on the dedicated Hetzner host, at low process
priority, never on the Pi. The Stratum adapter itself waits idle for miners and
is not a continuous CPU miner:

```sh
nice -n 19 python3 scripts/pohw-stratum-smoke-mine.py \
  --host 127.0.0.1 --port 3333 \
  --max-hashes 1000000 --timeout-seconds 30 --allow-no-solution
```

The attempt may exhaust either bound without finding work. Success requires
both an accepted Stratum response and an independent
`bitcoin-cli -chain=pohw getblockcount` increase. The sharechain,
block-candidate evidence, and payout evidence must all be persisted. No block
hash, wallet address, or private identity data is required to verify this
height transition.

The initial operator may install `pohw-bootstrap-miner.timer` while the network
is below the manifest's bootstrap handoff threshold. It performs at most one
loopback-only, ten-second bounded attempt every ten minutes under a 5% CPU
quota. The runner refuses Raspberry Pi hardware and exits without hashing once
Core reports `handoff_active=true`; ordinary mining hardware must use the
normal Stratum path after that point.

## Transactions And FROST

New fork-only outputs can exercise all ordinary wallet and PSBT paths after
coinbase maturity. The FROST vault uses Taproot key-path outputs and can now be
tested against actual Experiment 1 UTXOs rather than a separate regtest chain.
Keep signer shares off the coordinator and treat all current vault code as
experimental.

Legacy, P2SH, SegWit v0, P2WSH, nested SegWit, Taproot key-path, Taproot
script-path, Tapscript, CLTV, CSV, multisig, nonstandard-but-consensus-valid
scripts, wallet transactions, raw transactions, and PSBT workflows all use the
pinned upstream Bitcoin Core engine. The project does not maintain an
allowlist that can silently remove one of those classes from Experiment 1.
For an inherited mixed-input PSBT, the marker-specific empty-input extraction
described above is the sole wrapper around that engine.

An inherited-spend live test additionally needs a real unspent output present
at the fork point and its signing key. The current coordinator has no such
mainnet funds, so the deterministic Core test proves rule enforcement without
pretending a nonexistent live UTXO was spent.

This lack of a coordinator-owned inherited UTXO is not a protocol restriction.
After 100 successor blocks make a fork coinbase spendable, any participant who
controls an inherited output may build the required mixed-input transaction.
That participant must assume the inherited private key can control real BTC,
must inspect the transaction before signing, and must never broadcast the
fork transaction to Bitcoin mainnet. The recommended ordinary transaction and
FROST tests use fresh fork-only descriptors; inherited-spend tests are a
separate, explicit key-risk exercise.

## Mainnet Handoff

Experiment 1 does not delete itself or switch to Bitcoin mainnet at 20
participants. The older Experiment 0 handoff controller is a separate,
explicitly armed mechanism and must remain disabled for this experiment.

## Stop And Roll Back

```sh
sudo systemctl disable --now bitcoind-pohw-experiment-1.service
sudo systemctl stop pohw-mining-adapter.service 2>/dev/null || true
```

Keep the manifest and logs needed for audit. Delete `/srv/bitcoin/pohw` only
after confirming it is the fork datadir and not `/srv/bitcoin/mainnet`.

This implementation is suitable only for local and controlled public-testnet
experimentation until the Core patch, replay rule, P2Pool integration, and
FROST transaction path receive independent review.
