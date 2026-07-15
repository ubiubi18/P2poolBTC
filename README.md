# P2poolBTC

P2poolBTC is a no-value Bitcoin P2Pool-style experiment with Idena proof-of-human-work accounting.
It explores a voluntary mining layer where every node can replay the same sharechain, Idena snapshots, reward scores, payout schedules, and vault claims locally.

Bitcoin mainnet and Idena consensus stay unchanged. This repo builds the
experimental coordination layer and a separately identified no-value Bitcoin
Core fork used by Experiment 1.

`compatibility/stack-lock.json` pins the reviewed Idena candidate consumed by
PoHW. Run `python3 scripts/pohw-idena-compatibility-lock.py` before deployment;
the production installers additionally require root-owned source provenance
files for both modern and legacy binaries.

The idea is simple:

- Bitcoin hashrate still mines the block.
- Idena human-work history adds a second reward signal.
- Pool rewards are split 50/50 between hashrate score and Idena reward-accounting score.
- Large unpaid balances can be paid directly in the coinbase.
- Smaller balances become non-transferable withdrawal claims against a weekly FROST vault epoch.

This repo is not a production Bitcoin node, not a token bridge, and not ready for real funds.

> **Experiment 1 is the current full-consensus successor.** It uses a pinned
> Bitcoin Core v31.1 patch, supports all upstream transaction and script paths,
> and explicitly permits inherited-mainnet UTXO spending under a mixed-input
> replay rule. Experiment 0 remains immutable and coinbase-only. Read
> [Experiment 1](EXPERIMENT-1.md) before building or connecting a miner.

> **Public-join status: blocked technical preview.** The idea, source, tests,
> and sanitized screenshots may be shared for review. Do not advertise an open
> mining network yet. The checked-in launch policy remains
> `blocked-release-readiness`: it machine-records the missing exact source
> release, CID/CAR/build evidence, second independent build operator, external
> review, finalized ownerless-registry policy, and independent second-node
> acceptance. Two matching registry builds by one operator are reproducibility
> evidence, but do not satisfy builder independence. Runtime wrappers fail
> closed for `chain=pohw` unless the reviewed Idena anchor policy is mandatory.
> A ready policy must also bind the canonical deployment-readiness report CID
> and CAR digest; editable status flags alone cannot open public joining.

> **Bitcoin and Idena risk remain real.** Fork coins have no promised value,
> but inherited Bitcoin scripts use mainnet keys; exposing one can lose real
> BTC. A participant saying that an address is empty does not make key reuse
> safe: verify the mainnet history independently and use a fork-only wallet for
> ordinary testing. Idena is not a disposable testnet: signatures are public
> and delegation, stake, validation, transactions, and contracts can change
> real IDNA balances or identity state. Never give this software a Bitcoin or
> Idena private key.

> **Archived Experiment 0 only: one-way mainnet handoff.** This mechanism is
> not part of Experiment 1. On Experiment 0 nodes that explicitly
> install and arm the handoff controller, reaching 20 distinct verified Idena
> identities with accepted work on the active sharechain stops the no-value
> fork, starts payout-aware mining against Bitcoin mainnet, and deletes that
> node's dedicated fork-chain datadir. Mainnet submissions can create blocks
> with real value. Read [The 20-participant mainnet handoff](#the-20-participant-mainnet-handoff)
> before enabling it.

## Live Preview

These are the intended sanitized Experiment 1 dashboard views. They contain
aggregate public experiment data only and must not contain identities, wallet
addresses, peer addresses, RPC credentials, signatures, or block hashes. A
screenshot proves only what the UI rendered at capture time; it is not proof
of consensus, ownership, payout, or value. Verify the local Core and
sharechain state as described in the
[Community Experiment 1 Guide](COMMUNITY-EXPERIMENT-1.md).

Experiment 1 fork coins and inherited fork balances have no promised value.
Inherited outputs remain controlled by Bitcoin-mainnet keys, and the
mixed-input replay rule does not make key reuse safe. Use fresh fork-only keys
for ordinary testing.

### Network overview

![Sanitized P2poolBTC Experiment 1 network overview](docs/assets/experiment-1-overview.png)

### Active fork blocks

![Sanitized Experiment 1 fork-block view](docs/assets/experiment-1-fork-blocks.png)

### Live sharechain

![Sanitized P2poolBTC Experiment 1 sharechain](docs/assets/experiment-1-sharechain.png)

Live acceptance on 2026-07-15 used bounded, low-priority loopback mining
attempts on the dedicated host. Each accepted submission advanced both the
Experiment 1 Core height and the sharechain stored-share count by one. The
bootstrap timer performs at most one ten-second attempt every ten minutes under
a 5% CPU quota and skips all hashing after Core reports the normal-difficulty
handoff. The adapter otherwise waits idle when no miner is connected. The
SD-only Pi remained observer-only throughout the check.

![PoHW pool flow: solve flips, join p2pool, mine Bitcoin, decentralize Bitcoin mining](docs/assets/pohw-flow.png)

## Start Here

For new full transaction, inherited UTXO, wallet, and FROST testing, use the
[Experiment 1 runbook](EXPERIMENT-1.md). It builds the fork from exact Bitcoin
Core source and keeps the heavy chainstate on the dedicated host, not the Pi.

The [Community Experiment 1 Guide](COMMUNITY-EXPERIMENT-1.md) is the staged
source-first join procedure. Its public-join interlock intentionally stops at
the current blocked launch policy. Once the required release, registry, review,
and second-node evidence exists, the same guide builds both Core and P2poolBTC
from exact source, supports a pruned miner node without an explorer index, and
verifies Core, sharechain, and block progress locally. No coordinator-signed
installer or lead-developer release key is trusted.

Experiment 1 runs in its own source-built Bitcoin Core profile. Always pass
`-chain=pohw` and use the dedicated fork datadir; never point the experiment at
a Bitcoin-mainnet wallet or datadir. Its fork height and fork-only wallet
balance are visible through that Core instance. A wallet shows only outputs
controlled by its descriptors, so a dashboard or explorer balance is not
automatically a Core wallet balance.

The current SD-only Pi is an observer-only, low-load endpoint. It does not run
Experiment 1 Core, gossip, Stratum, or mining. Those services run on the
dedicated Hetzner host. The Stratum adapter waits idle for miners and is not a
continuous CPU miner. A separately gated Hetzner-only bootstrap timer runs one
bounded attempt every ten minutes, refuses Raspberry Pi hardware, and stops
attempting after the consensus handoff. See the
[Community Experiment 1 Guide](COMMUNITY-EXPERIMENT-1.md) for its exact limits
and disable command.

The old Experiment 0 fork was implemented outside Bitcoin Core and therefore
does not appear in Bitcoin Core Qt or `bitcoin-cli getbalance`. This historical
limitation does not describe Experiment 1.

The old [Community Experiment 0 Guide](COMMUNITY-README.md) is retained only
for reproducing the frozen coinbase-only predecessor. Do not use its launcher
or activation values for Experiment 1.

The detailed trust boundary and current limitations are in
[Source-First Onboarding](docs/source-first-onboarding.md).

[Beta Testing P2poolBTC](BETA-TESTING.md) explains the tester roles and safety
boundaries in more detail.

[Experiment 0](EXPERIMENT-0.md) documents the frozen predecessor for historical
reproduction only. Do not use its activation, launcher, or handoff instructions
for an Experiment 1 review or future join.

## Governance Day (Local-Only Candidate)

The governance work is a separate experimental vertical slice. It does not
control the live Experiment 1 deployment and has not been deployed to Idena,
published as a release, or authorized as a canonical ecosystem manifest.

The current candidate implements:

- one on-chain proposal slot per eligible Idena identity and governance epoch;
  cancellation, rejection, expiration, and no quorum do not restore the slot,
- one deterministic frozen proposal set and one bounded commit/reveal epoch
  ballot covering every proposal in the exact frozen order,
- sublinear voting based on the integer square root of active locked IDNA,
  bounded Human/Verified/Newbie status multipliers, and finalized authored-flip
  trust; identity age, birthday, generation, and repository status are ignored,
- independent stake, identity-breadth, AI-review, reproducible-build, and public
  data-availability gates,
- grace-delayed, permissionless execution with objective challenges,
  append-only canonical history, decentralized revert proposals, and a local
  last-known-good recovery flow that never installs software automatically,
- deterministic source-tree, patch, parameter, attestation, and CAR packaging
  with CID and SHA-256 verification,
- a content-addressed, MIT-licensed human/AI development policy adapted from
  the exact `ai-driven-dev/framework` source revision. It preserves the useful
  specify, plan, implement, and review sequence, then adds independent builds,
  public availability, Idena voting, and permissionless execution. Neither an
  AI agent, GitHub account, maintainer, nor deployer can make a candidate
  canonical, and
- an exact-base IdenaAI integration in which `idena.AI` is the primary
  governance interface. Agents can prepare reviews, discussions, and ballot
  drafts, but every file disclosure, mutation, signature, vote, reveal,
  publication, execution, and recovery action requires explicit user approval.
  Manual community review remains available and is displayed separately from
  AI findings.

The locked local parameter-set CID is
`bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq`. The locally
built WASM candidate is 289,547 bytes with CID
`bafkreihluzhutpge75k4cp7ah7ljjvw2plv7zj43gjpwfa7x4hn7favpzq` and SHA-256
`eba64f49bcc4ff55c13fe03fd694d6da7aebfca79b325f6283f7e1dbf282afcc`.
These values identify test artifacts; they are not deployment authorization.
The contract derives normal/critical risk and scope counters from exact,
bounded base-to-candidate source transitions; proposer labels cannot downgrade
the derived class. The separate disabled Governance Day fork candidate adds an
authenticated read-only `epoch_block` host import. Its deterministic patched-
source CIDs and CAR digests are locked and reconstructed in CI, but candidate
commits remain unset until the patches are reviewed and committed, so deployment
still fails closed. Independent builders,
public pin operators, external auditors, replay/migration evidence, and DAO
authorization are also absent. Do not replace any of those gates with a
maintainer flag or trusted key.

Package and inspect the active development policy with:

```sh
cargo run -p governance-cli -- development-policy-package \
  --input integrations/decentralized-aidd/policy.json \
  --output-dir /tmp/pohw-development-policy

cargo run -p governance-cli -- development-policy-inspect \
  --car /tmp/pohw-development-policy/development-policy.car
```

The expected policy CID is
`bafyreid56pzxhbjuhonxsl5b2a2jjrgrzydgyyvvyfboucqh53y7hzyare`. An AI review
must bind that exact CID in `agentPolicyCid`; changing the policy creates a new
content-addressed proposal rather than a silent workflow update.

Run the local protocol demo and the exact-base 33-step IdenaAI flow with:

```sh
cargo run -p governance-cli -- demo-epoch-governance \
  --output-dir "$PWD/target/governance-day-demo"

env POHW_CONFIRM_LOCAL_TEST_PATCH=YES \
  IDENA_AI_ROOT=/absolute/path/to/idena-ai \
  tests/governance/governance-day-e2e.sh
```

The second command applies the checked IdenaAI patch only to a disposable
archive, verifies its deterministic source CID, and performs no deployment,
Git push, release publication, installation, or automatic rollback. See
[Governance Day](docs/governance/GOVERNANCE-DAY.md),
[human/AI development](docs/governance/HUMAN-AI-DEVELOPMENT.md),
[Governance operations](docs/governance/OPERATIONS.md),
[known limitations](docs/governance/KNOWN-LIMITATIONS.md), and
[chain-liveness recovery](docs/governance/chain-liveness-recovery.md).

## Status

Working prototype pieces:

- deterministic `POHW1` commitment model,
- reproducible Bitcoin-mainnet-history fork activation manifest generation,
- complete Experiment 0 coinbase-only fork consensus with durable replay,
  cumulative-work fork choice, bootstrap difficulty, irreversible Bitcoin-2016
  difficulty handoff, peer synchronization, and a loopback control RPC,
- pinned Experiment 1 Bitcoin Core v31.1 full-consensus fork with all upstream
  script paths, wallet/PSBT support, inherited UTXO spending, mixed-input replay
  isolation, fork-specific network identity, and a permanent difficulty-handoff marker,
- live fork templates and fork-only block submission wired into the Stratum adapter,
- local append-only sharechain replay,
- signed miner registrations, shares, snapshot votes, payout schedules, withdrawal requests, and withdrawal batches,
- signed TCP gossip mesh with inventory sync, peer exchange, rebroadcast, rate limits, and private-network defaults,
- operator commands to preflight a multi-node setup and publish signed registrations, snapshot votes, work templates, and shares,
- local Stratum v1 mining adapter for real Bitcoin miners or rented hashrate to submit sharechain work to their own node,
- local Idena snapshot builder using `idena-go` RPC,
- deterministic 50/50 payout schedule logic,
- confirmed payout replay log for vault claim balances,
- automatic payout confirmer that watches local candidate files and calls the RPC-confirmed payout flow,
- Taproot FROST vault primitives, real local DKG/signing CLI commands, demos, and RPC-validated vault input checks,
- AssemblyScript snapshot registry with Idena host-storage imports, record validation, and deterministic encoding,
- read-only local dashboard API,
- versioned public explorer API for decoded fork transactions, scripts, addresses,
  UTXOs, inherited Bitcoin history, sharechain shares, and aggregate Idena snapshots,
- bounded host-only Experiment 1 address index with active-chain/reorg checks,
  inherited-input attribution, and fork-created UTXO history,
- optional host-only Esplora index integration; pool participants do not run a
  Bitcoin address index or enable Bitcoin Core `txindex`,
- Vite/React combined explorer and participant dashboard,
- Raspberry Pi systemd helpers for snapshots, gossip mesh, dashboard API, and dashboard UI,
- Rust and AssemblyScript Governance Day state machines with one proposal per
  identity per epoch, deterministic batch ballots, sublinear stake weighting,
  grace periods, paginated canonical history, and decentralized revert
  proposals,
- governance source/CAR tooling, strict schemas, local candidate locks, a
  read-only governance API/dashboard, and a 33-step cross-repository test, and
- provider-neutral IdenaAI governance operations, AI-first Builder/DAO/Social
  navigation, optional manual review, disclosure confirmation, and local ballot
  preparation without automatic signing or submission, and
- a deterministic MIT human/AI policy CAR, policy-bound review attestations,
  and a dashboard lifecycle from specification through permissionless
  execution without maintainer, GitHub, or autonomous-agent authority.

Not done yet:

- independent external review and multi-node soak testing of Experiment 1,
- an exact public source release descriptor and a complete evidence-bound
  fresh-host service installation path,
- two independent matching miner-registry builds, a verified ownerless Idena
  deployment receipt, and an activated immutable anchor policy,
- a public hash-verified fast-sync snapshot for later Experiment 1 participants,
- production P2Pool fork-choice and anti-eclipse logic,
- long-running networked ChillDKG/FROST signer daemon,
- complete idena-go reward extraction for every reward source,
- committed component revisions, public replication of the locked source CIDs,
  replay/migration evidence, and activation parameters for the disabled
  authenticated-epoch fork candidate,
- independent clean-room governance builders, public IPFS replication and
  availability attestations, external audit, and WASM deployment, and
- Idena SDK/bindgen packaging decision for the eventual governed client path.

## Repository Layout

```text
crates/pohw-core          consensus/accounting/vault primitives
crates/p2pool-node        local node, gossip, dashboard API, Bitcoin RPC checks
crates/idena-lite-indexer local idena-go snapshot builder
crates/pohw-agent         source verifier and loopback community join wizard
crates/governance-core    deterministic governance math, lifecycle, and manifests
crates/governance-cli     source/CAR, proposal, attestation, simulation, and demo CLI
ui/pohw-dashboard         React dashboard
contracts/                Idena snapshot, miner-registry, and governance WASM contracts
schemas/governance/       canonical governance object schemas
integrations/             exact-base local integration patches; never credentials
deploy/systemd            Raspberry Pi service templates
scripts/                  Pi helper scripts
docs/governance/          architecture, operations, security, and recovery boundaries
```

## Defaults

| Component | Default | Purpose |
| --- | --- | --- |
| Gossip mesh | `127.0.0.1:40406` | Signed sharechain envelope exchange |
| Experiment 1 Core P2P | `127.0.0.1:40412` | Full-consensus fork synchronization |
| Experiment 1 Core RPC | `127.0.0.1:40414` | Loopback-only fork templates, submission, and wallet RPC |
| Legacy Experiment 0 fork control RPC | `127.0.0.1:40408` | Archived custom-fork templates and submission |
| Legacy Experiment 0 fork P2P | disabled | Archived custom-fork synchronization |
| Mining adapter | `127.0.0.1:3333` | Local Stratum v1 frontend |
| Dashboard UI | `127.0.0.1:5176` | Browser UI, tunnel from a workstation |
| Dashboard API | `127.0.0.1:40407` | Read-only local status |
| Fork address index | dashboard API process | Optional bounded host read model; disabled on participant nodes |
| Bitcoin history index | `127.0.0.1:3002` | Optional host-only Esplora HTTP source |
| Dashboard dev server | Vite | Local frontend development |
| Idena RPC | `http://127.0.0.1:9009` | Local `idena-go` source |
| Bitcoin mainnet RPC | `http://127.0.0.1:8332` | Local mainnet source for explicitly separate tools |
| Sharechain data | `.pohw-p2pool/` or `/srv/sharechain/...` | Local replay logs |
| Snapshots | `./snapshots/` or `/mnt/ssd/pohw-p2pool/snapshots` | Verified Idena snapshot JSON |

Keep Bitcoin and Idena RPC on loopback. Expose gossip, dashboard, or Stratum only to trusted peers, with firewall rules. Non-loopback dashboard needs a token; non-loopback Stratum needs a protected password file.

The combined explorer can be deployed locally or on a dedicated host. See
[PoHW Network Explorer](docs/explorer.md) for the public API, privacy boundary,
systemd/Caddy host profile, smoke tests, and rollback procedure.

Only the dedicated explorer operator needs the Bitcoin history index. A miner,
Pi, or observer can use the hosted versioned API and never downloads the full
Bitcoin chain or either address index. The bounded Experiment 1 index scans only
the active fork from its pinned first block and is independent of the optional
multi-terabyte Bitcoin-history index. Fork consensus validation remains
independent from both read models.

## Community Experiment

Start with the [Community Experiment 1 Guide](COMMUNITY-EXPERIMENT-1.md) when
reviewing the candidate or preparing a future join. Its checked launch-policy
interlock currently blocks public participation. It gives the reproducible
source-first path, pruned-node option, local success ladder, and safe
issue-reporting workflow for use after the release gates pass.
[Beta Testing P2poolBTC](BETA-TESTING.md) describes the available tester roles.

[Experiment 0](EXPERIMENT-0.md) retains the frozen predecessor's scope,
preflight, report, and stop procedures for historical reproduction. Its
activation and services are not the current community join path.

Build a participant source package:

```sh
scripts/pohw-experiment-package.sh --output-root output
```

The archive includes the runbook, source, scripts, tests, env template, `QUICKSTART.md`, `MANIFEST.json`, and `SHA256SUMS`; it excludes local datadirs, build output, generated frontend/WASM artifacts, env files, keys, cookies, logs, and reports.

## Quick Start

```sh
cargo test --workspace
cargo build --workspace
```

Run a local replay-only node:

```sh
cargo run -p p2pool-node -- run --datadir .pohw-p2pool
cargo run -p p2pool-node -- status --datadir .pohw-p2pool
```

Run the dashboard API:

```sh
cargo run -p p2pool-node -- serve-dashboard-api \
  --datadir .pohw-p2pool \
  --snapshot-dir ./snapshots \
  --dashboard-idena-address 0x... \
  --bind-addr 127.0.0.1:40407
```

Set one local account selector (`--dashboard-idena-address`, `--dashboard-miner-id`, or `--dashboard-claim-owner-id`) once more than one miner exists in the sharechain.

Run the UI:

```sh
corepack pnpm@11.11.0 --dir ui/pohw-dashboard install
corepack pnpm@11.11.0 --dir ui/pohw-dashboard dev
```

When both dashboard services run on the Pi, keep them bound to Pi loopback and open an SSH tunnel from your workstation:

```sh
scripts/pohw-dashboard-tunnel.sh <pi-ssh-host>
```

Then open `http://127.0.0.1:5176/` locally. The tunnel forwards workstation `127.0.0.1:5176` to the Pi UI and workstation `127.0.0.1:40407` to the Pi dashboard API, without exposing either service to the WLAN or Internet.

Do not put the dashboard bearer token in a Vite environment variable or a
compiled UI bundle. The production wrapper reads it from the configured token
file and writes a short-lived runtime browser configuration only while both the
UI and API are bound to loopback. Use the SSH tunnel above for remote access;
do not send the token over an unencrypted WLAN connection.

The dashboard intentionally shows an offline state if the local API is unavailable. Demo data is opt-in:

```sh
VITE_POHW_DASHBOARD_DEMO=true corepack pnpm@11.11.0 --dir ui/pohw-dashboard dev
```

## Core Commands

To create a deliberately separate no-value fork/testnet, derive a new
activation manifest from local Bitcoin Core:

```sh
cargo run -p p2pool-node -- prepare-fork-activation \
  --chain-name my-separate-experiment \
  --launch-timestamp-utc <future-rfc3339-time> \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --manifest-out ./fork-activation.json
```

The command derives the first Bitcoin mainnet block at or after the launch
timestamp, records the inherited parent tip, starts at the no-value bootstrap
PoW limit `0x207fffff`, and emits an `activation_id`. Bootstrap difficulty
adjusts every block. At a difficulty-implied hashrate of `1 PH/s` by default,
the chain irreversibly hands descendants to Bitcoin's normal 2016-block
retarget mechanism. Set `--bootstrap-handoff-hashrate-hps` before activation to
choose another threshold. The algorithm, threshold, and spacing are committed
by the manifest, so every participant must use the identical
`fork-activation.json`. Inherited-mainnet UTXO spending remains disabled unless
`--inherited-utxo-spending-enabled` is explicitly set, and it should stay
disabled until replay protection exists.

Run the activation-bound Experiment 0 chain and inspect its live status:

```sh
scripts/pohw-run-fork-chain-node.sh
target/release/p2pool-node fork-chain-status \
  --activation-manifest .pohw-p2pool/fork-activation.json
```

The fork node validates scheduled-target PoW, ancestry, merkle and witness
roots, block weight, BIP34 height, subsidy, time, and coinbase-only transaction
rules; persists every accepted branch; selects cumulative work; and
synchronizes fork blocks with configured peers. See
[Experiment 0 Fork-Chain Node](docs/fork-chain-node.md).

The normal Experiment 0 participant path does not run that command. Initialize
in the default `join-existing` mode and use the canonical tracked manifest:

```sh
scripts/pohw-experiment-init.sh --miner-id alice
cmp compatibility/experiment-0-activation.json \
  .pohw-p2pool/fork-activation.json
```

Its activation ID is
`0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e`.
The wrapper `pohw-experiment-prepare-fork-activation.sh` refuses to generate a
manifest unless initialization used `--separate-experiment`. See
[Experiment 0](EXPERIMENT-0.md) for peer checks and both network workflows.

## The 20-participant Mainnet Handoff

The canonical Experiment 0 controller has a fixed threshold of **20 active
Idena participants**. A participant counts once when:

- its `MinerRegistration` has valid mining and Idena ownership signatures;
- its Idena address is distinct from every other counted participant; and
- at least one accepted share from that identity's miner is on the active
  sharechain branch and references a locally accepted template no older than
  the configured one-hour default; and
- the address is `Newbie`, `Verified`, or `Human` in the latest locally
  verified Idena snapshot.

Raw connections and raw miner IDs do not count. Twenty miner IDs controlled by
one Idena identity count as one participant. The controller requires the
threshold in three distinct replay observations by default. Reusing the same
replay tip does not advance the count, and accepted observations are separated
by ten minutes by default. This prevents one partial replay, a tight polling
loop, or a short reorganization from immediately triggering the transition.
The selected snapshot must be no more than two days old by default and must
have signed votes from at least three distinct registered Idena identities.
This prevents twenty arbitrary address keypairs or one uncorroborated local
snapshot from triggering the real-value transition.

The handoff is local to every node that installs the controller. A canonical
seed deleting its fork data cannot delete data on somebody else's machine, so
every Experiment 0 fork operator must install the same controller or stop their
fork node when the explorer reports `20 / 20` active identities.

On an armed host there is no second confirmation prompt at `20 / 20`: after the
configured consecutive checks and preflight pass, the controller automatically
stops the fork, starts real Bitcoin mainnet template mining, verifies the live
process mode, and recursively removes only that host's dedicated fork datadir.
The durable activation marker prevents the fork service from starting again.

This does not change or fork Bitcoin mainnet consensus. After the handoff, the
adapter consumes ordinary Bitcoin Core mainnet templates and any submitted
block must satisfy Bitcoin's existing consensus and network difficulty. The
PoHW payout outputs and commitment are carried in that candidate's coinbase.

Before changing anything, the controller requires all of the following:

- Bitcoin Core RPC reports `chain=main`, matching block/header heights,
  `initialblockdownload=false`, and complete verification progress;
- `getblocktemplate` succeeds;
- the current sharechain, latest verified Idena snapshot, miner registration,
  and PoHW commitment template produce a complete payout-aware mainnet Stratum
  job; and
- the explicit real-Bitcoin acknowledgement is configured.

Install and arm it on a systemd host from the protected runtime checkout:

```sh
sudo /opt/p2pool/scripts/pohw-install-mainnet-handoff.sh --enable
```

The installer refuses a missing or symlinked release binary and copies both the
controller and the current `p2pool-node` build into root-owned
`/usr/local/libexec/pohw`. Re-run it after upgrading the binary. Use
`--p2pool-bin /absolute/path/to/p2pool-node` only when the release build is in a
different protected location.

Set these values in root-owned `/etc/pohw/p2pool.env`:

```sh
POHW_MAINNET_HANDOFF_ENABLED=true
POHW_MAINNET_HANDOFF_ACK=I_UNDERSTAND_REAL_BITCOIN
POHW_MAINNET_HANDOFF_CONFIRMATIONS=3
POHW_MAINNET_HANDOFF_SETTLE_SECONDS=15
POHW_MAINNET_HANDOFF_MAX_SNAPSHOT_AGE_DAYS=2
POHW_MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS=3
POHW_MAINNET_HANDOFF_MAX_SHARE_AGE_SECONDS=3600
POHW_MAINNET_HANDOFF_MIN_CONFIRMATION_INTERVAL_SECONDS=600
POHW_MAINNET_HANDOFF_STATE_DIR=/var/lib/pohw-p2pool/mainnet-handoff
POHW_PAYOUT_CANDIDATE_DIR=/var/lib/pohw-p2pool/payout-candidates
```

Also configure `POHW_MINER_ID`, `POHW_SNAPSHOT_DIR`, the Bitcoin RPC URL/cookie,
and a valid `POHW_STRATUM_POHW_COMMITMENT_FILE`. The commitment file is a
template: its miner identity must match the registration, and its vault epoch
and FROST key are retained. Snapshot, sharechain-state, payout-root, and fee
dependent fields are derived again for every Bitcoin template. A static
`POHW_STRATUM_PAYOUT_SCHEDULE_FILE` is deliberately not used after handoff.
Keep RPC loopback-only on a host running Bitcoin Core. A node using a remote
Bitcoin host must use a private tunnel and explicitly set
`POHW_BITCOIN_RPC_ALLOW_REMOTE=true`; never expose Bitcoin RPC to the public
Internet.

Inspect the sanitized controller state without exposing identities or RPC
credentials:

```sh
systemctl status pohw-mainnet-handoff.timer
sudo cat /var/lib/pohw-p2pool/mainnet-handoff/status.json
```

At the confirmed threshold the controller performs one transaction-like
sequence:

1. Preflight Bitcoin mainnet and derive a payout-aware candidate job from the
   current sharechain and verified Idena snapshot.
2. Stop the mining adapter and fork node.
3. Persist the one-way activation marker before creating the mainnet environment
   or starting any mainnet-capable Stratum process. A systemd condition prevents
   the fork service from restarting after this commit point.
4. Remove the fork launch marker and start the adapter with Bitcoin RPC refresh,
   per-template dynamic payouts, automatic target-meeting block submission,
   and the separate `--allow-mainnet-submit` interlock. Inspect its live
   arguments and require the expected datadir, snapshot, payout-evidence, RPC,
   miner, and commitment-template paths with no static job or fork RPC argument.
5. Persist the completion receipt, disable the fork service, and delete only
   `POHW_FORK_CHAIN_DATADIR`.

The sharechain, signed registrations, Idena snapshots, reward accounting,
commitment template, generated mainnet payout evidence, keys, and Bitcoin Core
datadir are preserved.
Fork deletion means filesystem removal, not forensic secure erasure, and does
not remove operator backups. If preflight or transition setup fails before the
activation marker is written, the controller restores fork mode and keeps all
fork data. Once that durable marker exists, it never recreates the fork;
mainnet startup or cleanup failures preserve fork data, are reported as
`mainnet_active_cleanup_pending`, and are retried.

Bitcoin transaction fees change `getblocktemplate.coinbasevalue`, so the
mainnet adapter never reuses one fixed payout schedule. Each refreshed template
gets a deterministic schedule that sums to that template's exact coinbase
value and a matching `POHW1` commitment. If a miner finds a target-meeting
block, the adapter writes the exact snapshot, schedule, commitment, and payout
confirmation descriptor under `POHW_PAYOUT_CANDIDATE_DIR`, publishes that
commitment to the sharechain, and only then submits the block. Failure to
preserve or publish this evidence fails closed instead of submitting an
unaccountable block.

Before activation, disarm the host with
`systemctl disable --now pohw-mainnet-handoff.timer` and set
`POHW_MAINNET_HANDOFF_ENABLED=false`. After `mainnet-activated.json` exists,
there is intentionally no automatic rollback to the fork; restoring a backup
would be a manual, explicitly separate experiment.

This handoff does not make finding a Bitcoin block likely. Afterward miners
work at Bitcoin's real network difficulty; a small experiment may produce
shares indefinitely without finding a mainnet block. Because any accepted
mainnet block has real value, treat this mode as experimental and do not rely
on its unfinished vault and payout operations for production funds.

Prepare a miner pledge locally:

```sh
cargo run -p p2pool-node -- prepare-miner-registration \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --idena-address 0x...
```

The first run creates protected local keys, derives a default Taproot payout script, and prints the Idena ownership challenge. After signing that challenge in Idena, rerun with `--idena-signature-hex`, plus `--append` or `--peer-addr` when ready to publish the registration.

An experimental ownerless Idena miner-registry profile is also implemented but
not deployed or activated. It replaces developer-signed admission packets with
a public contract timestamp, binds the complete anchor policy into version-3
work templates, and uses a two-phase challenge so the signed registration
includes the finalized contract receipt. Build, threat limits, registration,
activation, and rollback are documented in
[docs/idena-miner-registry.md](docs/idena-miner-registry.md). Do not use the
one-step command above after that policy is activated.

For Experiment 0, prefer the env-file wrapper:

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env --idena-address 0x...
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env \
  --idena-address 0x... \
  --idena-signature-hex <signature>
```

Create and verify gossip:

```sh
cargo run -p p2pool-node -- create-gossip-envelope \
  --message-file ./message.json \
  --node-secret-key-file ./node.key \
  > envelope.json

cargo run -p p2pool-node -- verify-gossip-envelope \
  --envelope-file ./envelope.json
```

Run the local gossip mesh:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool
```

Expose gossip to trusted WLAN peers only when your firewall rules are ready:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool \
  --bind-addr <node-lan-ip>:40406 \
  --advertise-addr <node-lan-ip>:40406 \
  --peer-addr <peer-lan-ip>:40406
```

Preflight a multi-node experiment:

```sh
scripts/pohw-experiment-init.sh \
  --miner-id alice \
  --bind-addr 127.0.0.1:40406

scripts/pohw-experiment-preflight.sh .pohw-experiment.env
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

Or call the node command directly:

```sh
cargo run -p p2pool-node -- multinode-preflight \
  --datadir .pohw-p2pool \
  --snapshot-dir ./snapshots \
  --miner-id alice \
  --peer-addr <peer-lan-ip>:40406
```

Publish locally verified data into the signed gossip layer:

```sh
cargo run -p p2pool-node -- publish-snapshot-vote \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --snapshot-file ./snapshots/latest.json \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406

cargo run -p p2pool-node -- publish-bitcoin-work-template \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --bitcoin-header-hex <80-byte-header-hex> \
  --share-target <32-byte-target-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --validate-with-bitcoin-rpc \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --accept-locally \
  --append \
  --peer-addr <peer-lan-ip>:40406

cargo run -p p2pool-node -- publish-share \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --bitcoin-header-hex <80-byte-header-hex> \
  --target <32-byte-target-hex> \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --block-candidate-dir .pohw-p2pool/block-candidates \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Each node still verifies the append locally. Use `--accept-locally` only after Bitcoin RPC validation, unless you deliberately pass `--allow-unverified-local-accept` for a controlled test fixture.
`publish-share` defaults `--parent-share-hash` to the local best share tip; on an empty sharechain it uses the zero parent.

Bootstrap the remaining readiness checks from one command once miner registration
and a verified Idena snapshot exist:

```sh
scripts/pohw-bootstrap-readiness.sh .pohw-experiment.env --mode real
```

Real mode builds the Bitcoin work candidate from local Bitcoin Core RPC, publishes
and locally accepts a signed `BitcoinWorkTemplate` only after RPC validation, then
publishes the first share bound to the selected Idena snapshot. The default
bootstrap share target is the maximum accepted rehearsal target; set
`POHW_BOOTSTRAP_SHARE_TARGET` or pass `--share-target` for stricter accounting.
If Bitcoin Core is still in initial block download, it writes `status.json` with
`bitcoin_not_ready` and exits without appending synthetic work.

For isolated single-node plumbing tests only, use:

```sh
scripts/pohw-bootstrap-readiness.sh .pohw-experiment.env \
  --mode dev \
  --dev-ack I_UNDERSTAND_DEV_ONLY
```

Dev mode uses synthetic local work and must not be used for Bitcoin mining or
shared experiment consensus.

Mesh sync can admit peer work templates automatically when it has local Bitcoin RPC access:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:40406 \
  --peer-addr <peer-lan-ip>:40406 \
  --admit-peer-work-templates \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --allow-mutable-time \
  --expected-header-merkle-root-hex <32-byte-coinbase-merkle-root-hex>
```

This does not trust the peer. During sync the node can fetch missing miner registrations by `miner_id` and missing work templates by `bitcoin_template_hash` before replaying a share, verifies the registration signature, template mining signature, and Bitcoin Core template policy locally, then records only admitted templates.
Use `--allow-unverified-merkle-root` only for controlled development fixtures where no local block builder/fork validator can provide the expected header merkle root.

For one-off diagnostics, run the same admission pass manually:

```sh
cargo run -p p2pool-node -- admit-peer-work-templates \
  --datadir .pohw-p2pool \
  --peer-addr <peer-lan-ip>:40406 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --allow-mutable-time \
  --expected-header-merkle-root-hex <32-byte-coinbase-merkle-root-hex>
```

Run the local Stratum mining adapter:

```sh
cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:3333 \
  --miner-id alice \
  --job-file ./mining-job.json \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Point a miner at `stratum+tcp://127.0.0.1:3333`. The worker name is informational; accepted shares are credited to `--miner-id`, after local replay confirms that miner registration owns the mining key. The adapter verifies share difficulty locally, signs `BitcoinWorkTemplate` and `Share` messages, appends them to the local sharechain, and gossips them to configured peers.

By default, `--stratum-difficulty 1` uses the Bitcoin Stratum diff-1 target for sharechain accounting. If you raise `--stratum-difficulty`, set the matching `--share-target` too; the adapter refuses to infer a custom target because wrong target accounting would miscredit miners. Job file fields are Stratum notify wire values, not human display block hashes. The packaged example job is refused by the binary unless `--allow-example-mining-job` is passed for an explicit local dry-run.

Build a fresh Experiment 0 mining job from your local Bitcoin RPC before starting Stratum:

```sh
cargo run -p p2pool-node -- build-stratum-job-rpc \
  --job-out .pohw-p2pool/mining-job.json \
  --replace \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

The generated job uses local `getblocktemplate` for version, previous block, time, bits, and transaction merkle branches. It is enough for sharechain work accounting and multi-node rehearsal, but it is not yet the final PoHW block-submission coinbase with payout outputs.

For the live Experiment 0 fork feed, do not use Bitcoin RPC job refresh. Start the
fork node, then run the adapter with:

```sh
cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:3333 \
  --miner-id alice \
  --fork-chain-rpc-addr 127.0.0.1:40408 \
  --fork-chain-activation-manifest .pohw-p2pool/fork-activation.json \
  --idena-snapshot-id <snapshot-id> \
  --idena-snapshot-proof-root <root> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --auto-submit-blocks
```

The adapter derives the easy fork target and Stratum difficulty from each live
template. Target-meeting blocks go only to the activation-bound fork RPC.
When using `--replace`, keep the job file in a private node directory that is not group/world writable.

For a long-running adapter, add `--refresh-job-from-rpc --rpc-cookie-file ~/.bitcoin/.cookie`. It polls `getblocktemplate`, atomically swaps changed jobs, and sends a clean `mining.notify` to subscribed miners without restarting their connection. The default refresh interval is five seconds and can be changed with `--job-refresh-interval-seconds`.

When a locally verified payout schedule and POHW commitment are available, build the payout-aware Stratum job instead:

```sh
cargo run -p p2pool-node -- build-pohw-stratum-job-rpc \
  --job-out .pohw-p2pool/mining-job.json \
  --replace \
  --payout-schedule-file .pohw-p2pool/payout-schedule.json \
  --pohw-commitment-file .pohw-p2pool/pohw-commitment.json \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

That job places the deterministic direct outputs, the current vault output, and the `POHW1` OP_RETURN commitment into the coinbase split miners receive over Stratum. The command refuses schedules whose positive coinbase outputs do not exactly match the local `getblocktemplate` `coinbasevalue`.

Build a reproducible candidate artifact from a Stratum submit tuple:

```sh
cargo run -p p2pool-node -- build-stratum-block-candidate \
  --job-file .pohw-p2pool/mining-job.json \
  --candidate-out .pohw-p2pool/block-candidate.json \
  --replace \
  --extranonce1 <from-adapter-log> \
  --extranonce2 <from-miner-submit> \
  --ntime <from-miner-submit> \
  --nonce <from-miner-submit> \
  --require-block-target
```

The artifact contains the exact coinbase tx, header, block hash, target check, and complete `block_hex` when the job carries the raw non-coinbase transactions. Jobs built by this repository from Bitcoin RPC include that transaction data. Manually supplied legacy jobs with merkle branches but no transaction data remain audit-only and produce an incomplete artifact.

When `run-mining-adapter` has `--block-candidate-dir`, every accepted submit that meets the advertised block target is also written as `block-<hash>.json` in that directory. Existing matching files are kept; different content at the same path is refused. The Pi wrapper enables this by default under `$POHW_DATADIR/block-candidates`, configurable with `POHW_STRATUM_BLOCK_CANDIDATE_DIR`.

Add `--auto-submit-blocks` only when the job coinbase and RPC target are ready for real block submission. A complete target-meeting candidate is sent to `submitblock` immediately; the result is logged, while an RPC rejection or transient error does not erase the accepted share or its candidate artifact. The Pi setting is the explicit opt-in `POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true`.

Submit a complete target-meeting candidate to a local fork/testnet Bitcoin RPC:

```sh
cargo run -p p2pool-node -- submit-stratum-block-candidate \
  --candidate-file .pohw-p2pool/block-candidate.json \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

The submit command refuses incomplete artifacts, candidates that do not meet the advertised block target, and Bitcoin mainnet RPC unless `--allow-mainnet-submit` is explicitly set.

For a LAN miner or rented hashrate endpoint, bind to the node IP and require a password file:

```sh
openssl rand -hex 24 > .pohw-p2pool/stratum.password
chmod 600 .pohw-p2pool/stratum.password

cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr <node-lan-ip>:3333 \
  --allow-non-loopback-stratum \
  --stratum-password-file .pohw-p2pool/stratum.password \
  --miner-id alice \
  --job-file ./mining-job.json \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key
```

Use the password as the miner's Stratum password and firewall `3333/tcp` to the miner or rental provider IP when possible. Version rolling is intentionally rejected in this first adapter. The example job file is dry-run material; for live rehearsal set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` for a generic RPC job, or `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus `POHW_STRATUM_PAYOUT_SCHEDULE_FILE` and `POHW_STRATUM_POHW_COMMITMENT_FILE` for a payout-aware job. Both wrapper modes now keep refreshing the job after startup.

Exercise the signed/encrypted DKG transport envelope demo:

```sh
cargo run -p p2pool-node -- demo-dkg-transport \
  --epoch-id 1
```

Build an Idena snapshot from local `idena-go`:

```sh
cargo run -p idena-lite-indexer -- snapshot-now \
  --api-key-file /mnt/ssd/idena/idena-data/api.key \
  --rpc-url http://127.0.0.1:9009 \
  --reward-events-file ./reward-events.json
```

Exact reward pipeline from official `idena-indexer`:

```sh
install -d -m 700 /mnt/ssd/pohw-p2pool/rewards
install -m 600 /dev/null /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url
printf '%s\n' 'postgres://user:password@127.0.0.1:5432/idena_indexer' \
  > /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url

python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  sync-official-indexer \
  --database-url-file /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url

python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  export-replay \
  --latest-epoch \
  --require-exact \
  > /mnt/ssd/pohw-p2pool/rewards/reward-events.json
```

`sync-official-indexer` runs `scripts/pohw-export-idena-indexer-rewards.sql` against the official `idena-indexer` Postgres schema and imports exact StatsCollector-derived rewards from completed epochs. `export-replay --latest-epoch` selects one canonical epoch instead of accumulating all imported history. Set `IDENA_REWARD_EPOCH` to pin a specific epoch for reproducible backfills; otherwise the snapshot timer selects the latest canonical epoch. The snapshot timer can run the sync automatically when `IDENA_INDEXER_DATABASE_URL_FILE` or `IDENA_INDEXER_DATABASE_URL` is configured.

If local Postgres `idena-indexer` data is not available yet, import completed-epoch rewards from the official public Idena API:

```sh
python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  sync-official-api \
  --completed-epochs 10
```

`sync-official-api` defaults to ten completed epochs so invitation liabilities can be reconstructed across their full clawback window. It imports exact validation/staking/session reward categories from `/Epoch/{epoch}/IdentityRewards`, aggregate epoch mining summaries from `/Address/{address}/MiningRewardSummaries`, and invitation/invitee credits plus later kill reversals into the liability ledger. Consensus scoring remains one epoch because the snapshot path exports only `--latest-epoch` (or the explicitly pinned `IDENA_REWARD_EPOCH`). Set `IDENA_OFFICIAL_API_SYNC=true` in the snapshot environment to let `pohw-idena-snapshot.service` run this fallback automatically when no Postgres URL is configured.

The first writable open of an existing large reward ledger after this upgrade builds a partial index over exact events and performs one canonical-source reconciliation. Keep the live indexer stopped for that migration and retain a database/WAL backup. Later starts and exact imports reconcile only the epochs they touch.

Build the snapshot registry ABI:

```sh
corepack pnpm@11.11.0 --dir contracts/idena-snapshot-registry install --frozen-lockfile
corepack pnpm@11.11.0 --dir contracts/idena-snapshot-registry build
corepack pnpm@11.11.0 --dir contracts/idena-snapshot-registry test
```

Propose a payout schedule:

```sh
cargo run -p p2pool-node -- propose-payout-schedule \
  --datadir .pohw-p2pool \
  --snapshot-file ./snapshot.json \
  --reward-sats 312500000 \
  --direct-limit 50
```

Confirm a mined Bitcoin-mainnet block payout after an explicitly armed
mainnet handoff:

```sh
cargo run -p p2pool-node -- confirm-payout-from-block \
  --datadir .pohw-p2pool \
  --snapshot-file ./snapshot.json \
  --payout-schedule-file ./payout-schedule.json \
  --pohw-commitment-file ./pohw-commitment.json \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --block-hash <bitcoin-mainnet-block-hash>
```

This verifies the coinbase outputs and `POHW1` commitment, then credits the replay log from the confirmed output total. Supplying `--reward-sats` is optional and must match the verified total.

Run the automatic confirmer:

```sh
mkdir -p .pohw-p2pool/payout-candidates
cat > .pohw-p2pool/payout-candidates/block-000001.json <<'JSON'
{
  "block_hash": "<bitcoin-mainnet-block-hash>",
  "snapshot_file": "../../snapshot.json",
  "payout_schedule_file": "../../payout-schedule.json",
  "pohw_commitment_file": "../../pohw-commitment.json",
  "min_confirmations": 100
}
JSON

cargo run -p p2pool-node -- run-payout-confirmer \
  --datadir .pohw-p2pool \
  --candidate-dir .pohw-p2pool/payout-candidates \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

Use `--once` for a single scan. This command is not an Experiment 0 fork
viewer: it queries Bitcoin Core for a Bitcoin-mainnet block produced only
after the separately armed mainnet handoff. The confirmer does not trust the
candidate file: it verifies Bitcoin Core block confirmations, coinbase
outputs, the `POHW1` commitment, and local replay before appending
`confirmed-payouts.ndjson`. Relative paths in a candidate are resolved from
the candidate file directory.

Validate a vault input with Bitcoin Core:

```sh
cargo run -p p2pool-node -- validate-vault-input \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --txid <txid> \
  --vout 0 \
  --vault-key-xonly <xonly-taproot-internal-key>
```

Build a vault rotation plan after revalidating current-vault UTXOs:

```sh
cargo run -p p2pool-node -- build-validated-vault-rotation \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --current-vault-key-xonly <current-xonly-taproot-internal-key> \
  --next-vault-key-xonly <next-xonly-taproot-internal-key> \
  --outpoint <txid:vout> \
  --fee-sats 1000
```

Create a non-transferable withdrawal claim request:

```sh
cargo run -p p2pool-node -- create-withdrawal-request \
  --datadir .pohw-p2pool \
  --request-id alice-001 \
  --claim-owner-secret-key-file .pohw-p2pool/keys/alice/claim-owner.key \
  --destination-script-hex <p2tr-or-p2wpkh-scriptpubkey-hex> \
  --amount-sats 20000 \
  --max-fee-rate-sat-vb 5 \
  --nonce 1 \
  --expiry-height <fork-height> \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Replay accepts a withdrawal request only after the claim owner key already has enough confirmed local vault-claim balance. This keeps unfunded or overdrawn requests out of the sharechain instead of letting them wait for future rewards.

Build the withdrawal spend plan and publish the pending batch before FROST signing:

```sh
cargo run -p p2pool-node -- build-withdrawal-spend-plan \
  --datadir .pohw-p2pool \
  --dkg-transcript-file ./current-vault-transcript.json \
  --request-id alice-001 \
  --outpoint <vault-funding-txid:vout> \
  --fee-rate-sat-vb 1 \
  --current-height <fork-height> \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --spend-plan-out ./withdrawal-plan.json \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Every FROST signer must sync that `WithdrawalBatch` first. `frost-create-commitments` and `frost-sign-shares` refuse withdrawal plans unless local replay already reserved the exact batch and Bitcoin Core still sees the vault inputs.

Useful vault demos:

```sh
cargo run -p p2pool-node -- vault-threshold --signers 21
cargo run -p p2pool-node -- demo-vault-peer-dkg-sign \
  --signers 4 \
  --input-sats 100000 \
  --fee-sats 1000 \
  --allow-unsafe-demo-vault-signing
cargo run -p p2pool-node -- demo-dkg-transport --epoch-id 1
```

## Raspberry Pi

Expected layout:

```text
/mnt/ssd/p2pool              repository
/mnt/ssd/pohw-p2pool         P2Pool replay data and Idena snapshots
/mnt/ssd/idena/idena-data    idena-go data and API key
```

Install snapshot timer:

```sh
cargo build --release -p idena-lite-indexer
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/snapshots
sudo cp deploy/systemd/pohw-idena-snapshot.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-idena-snapshot.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-idena-snapshot.timer
```

Install gossip mesh, dashboard API, and optional mining adapter:

```sh
cargo build --release -p p2pool-node
corepack pnpm@11.11.0 --dir ui/pohw-dashboard install
corepack pnpm@11.11.0 --dir ui/pohw-dashboard build
sudo install -d -m 755 -o root -g root /etc/pohw
sudo install -m 600 -o root -g root deploy/pohw-experiment.env.example /etc/pohw/p2pool.env
sudoedit /etc/pohw/p2pool.env
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/dashboard-ui-cache
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/health
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/auto-bootstrap
openssl rand -hex 32 | sudo tee /etc/pohw/dashboard-api.token >/dev/null
openssl rand -hex 24 | sudo tee /etc/pohw/stratum.password >/dev/null
sudo chmod 640 /etc/pohw/dashboard-api.token /etc/pohw/stratum.password
sudo chown root:ubuntu /etc/pohw/dashboard-api.token /etc/pohw/stratum.password
sudo install -m 600 -o ubuntu -g ubuntu deploy/mining-adapter-job.example.json /mnt/ssd/pohw-p2pool/mining-job.example.json
sudo cp deploy/systemd/pohw-health-status.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-health-status.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh-local-peer.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-ui.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-mining-adapter.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-fork-chain-node.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.path /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch@.path /etc/systemd/system/
sudo /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-health-status.timer pohw-auto-bootstrap.timer pohw-gossip-mesh.service pohw-dashboard-api.service pohw-dashboard-ui.service pohw-dashboard-api-cookie-watch.path
```

Or reinstall only the self-recovery layer idempotently. It always enables the network watchdog, but installs the two resource guards without changing their enablement:

```sh
sudo /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
```

Opt into either resource guard or the post-sync worker watcher explicitly when its policy matches the current workload:

```sh
sudo POHW_INSTALL_ENABLE_IDENA_PRIORITY_GUARD=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo POHW_INSTALL_ENABLE_BITCOIN_PRESSURE_GUARD=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo POHW_INSTALL_ENABLE_IDENA_WORKERS_WATCHER=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
```

The installer copies all root-run helpers to root-owned `/usr/local/libexec/pohw`, keeps their state under root-owned `/var/lib/pohw`, and enforces root ownership with mode `0600` on `/etc/pohw/p2pool.env`. Root services never execute scripts from the writable Git checkout.

Enable `pohw-mining-adapter.service` only after miner registration and snapshot fields are set in `/etc/pohw/p2pool.env`. For live rehearsal, set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` plus the local Bitcoin RPC cookie path for a generic RPC job, or set `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus payout schedule and PoHW commitment file paths for a static payout-aware rehearsal job. These modes refresh changed RPC jobs continuously. Target-meeting submission needs `POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true`; Bitcoin mainnet additionally requires the independent `POHW_STRATUM_ALLOW_MAINNET_SUBMIT=true` interlock. After its preflight, the handoff controller instead enables `POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE=true` with both submission interlocks so changing Bitcoin fees produce a fresh deterministic schedule. The packaged `mining-job.example.json` is dry-run material; the Rust adapter refuses it unless `--allow-example-mining-job` is passed, and `scripts/pohw-run-mining-adapter.sh` only passes that flag when `POHW_ALLOW_EXAMPLE_MINING_JOB=true` is set explicitly for a local dry-run.

For Experiment 0 fork mining, start `pohw-fork-chain-node.service` first and set
`POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408`. Set
`POHW_ADMIT_PEER_WORK_TEMPLATES=true` when exchanging signed work templates with
other participants. This mode consumes live fork templates, validates peer work
through fork RPC, and submits target blocks only to fork RPC; it cannot be
combined with the Bitcoin RPC job-builder flags. Leave
`POHW_STRATUM_SHARE_TARGET` empty to derive the fork's PoW-limit share target
and matching Stratum difficulty from the pinned activation manifest. This keeps
the share policy valid while the bootstrap DAA changes the block target.

Use `/etc/pohw/p2pool.env` for Pi-specific paths, peer hints, allowed dashboard origins, Stratum settings, and local RPC cookie paths. The systemd helpers bind gossip, dashboard, and Stratum to loopback unless you explicitly expose them. For trusted WLAN access, bind to the Pi WLAN IP instead of all interfaces:

```sh
POHW_SNAPSHOT_DIR=/mnt/ssd/pohw-p2pool/snapshots
POHW_GOSSIP_BIND_ADDR=<pi-wlan-ip>:40406
POHW_PEER_ADDRS=<peer-host-or-ip>:40406
POHW_LOCAL_GOSSIP_BIND_ADDR=<pi-wlan-ip>:40416
POHW_LOCAL_GOSSIP_ADVERTISE_ADDR=<pi-wlan-ip>:40416
POHW_LOCAL_GOSSIP_PEER_ADDRS=<pi-wlan-ip>:40406
POHW_DASHBOARD_ALLOW_NON_LOOPBACK=true
POHW_DASHBOARD_BIND_ADDR=<pi-wlan-ip>:40407
POHW_DASHBOARD_API_TOKEN_FILE=/etc/pohw/dashboard-api.token
POHW_DASHBOARD_ALLOWED_ORIGINS=http://127.0.0.1:5176,http://localhost:5176
POHW_DASHBOARD_UI_BIND_HOST=127.0.0.1
POHW_DASHBOARD_UI_PORT=5176
POHW_DASHBOARD_UI_API_URL=http://127.0.0.1:40407/dashboard.json
POHW_DASHBOARD_UI_CACHE_DIR=/mnt/ssd/pohw-p2pool/dashboard-ui-cache
POHW_DASHBOARD_IDENA_ADDRESS=0x...
POHW_IDENA_DATADIR=/mnt/ssd/idena/idena-data
POHW_HEALTH_IDENA_MIN_PEERS=3
POHW_HEALTH_STATUS_FILE=/mnt/ssd/pohw-p2pool/health/status.json
POHW_AUTO_BOOTSTRAP_DIR=/mnt/ssd/pohw-p2pool/auto-bootstrap
POHW_AUTO_BOOTSTRAP_OUTPUT_ROOT=/mnt/ssd/pohw-p2pool/output
POHW_AUTO_BOOTSTRAP_APPEND=true
POHW_AUTO_BOOTSTRAP_LOCK_STALE_SECONDS=3600
POHW_NETWORK_WATCHDOG_STATE_DIR=/var/lib/pohw/network-watchdog
POHW_NETWORK_WATCHDOG_TARGETS=
POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD=3
POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD=8
POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS=300
POHW_NETWORK_WATCHDOG_DRY_RUN=false
POHW_IDENA_PRIORITY_STATE_DIR=/var/lib/pohw/idena-priority
POHW_IDENA_PRIORITY_LEAD_SECONDS=3600
POHW_IDENA_PRIORITY_COOLDOWN_SECONDS=1800
POHW_IDENA_PRIORITY_RESTORE_BITCOIN=true
POHW_IDENA_PRIORITY_FORCE=false
POHW_IDENA_PRIORITY_DRY_RUN=false
POHW_BITCOIN_PRESSURE_STATE_DIR=/var/lib/pohw/bitcoin-pressure
POHW_BITCOIN_PRESSURE_HIGH_IOWAIT_PERCENT=40
POHW_BITCOIN_PRESSURE_HIGH_UTIL_PERCENT=85
POHW_BITCOIN_PRESSURE_LOW_IOWAIT_PERCENT=20
POHW_BITCOIN_PRESSURE_LOW_UTIL_PERCENT=60
POHW_BITCOIN_PRESSURE_HIGH_STREAK=2
POHW_BITCOIN_PRESSURE_LOW_STREAK=3
POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS=1800
POHW_BITCOIN_PRESSURE_RESTORE_BITCOIN=true
POHW_BITCOIN_PRESSURE_STOP_WHEN_MINING_READY=false
POHW_BITCOIN_PRESSURE_FORCE=false
POHW_BITCOIN_PRESSURE_DRY_RUN=false
POHW_TAILSCALE_CONFIGURE_UFW=true
POHW_TAILSCALE_UFW_INTERFACE=tailscale0
POHW_STRATUM_BIND_ADDR=<pi-wlan-ip>:3333
POHW_STRATUM_ALLOW_NON_LOOPBACK=true
POHW_STRATUM_PASSWORD_FILE=/etc/pohw/stratum.password
POHW_STRATUM_JOB_FILE=/mnt/ssd/pohw-p2pool/mining-job.json
POHW_STRATUM_BLOCK_CANDIDATE_DIR=/mnt/ssd/pohw-p2pool/block-candidates
POHW_IDENA_SNAPSHOT_ID=<snapshot-day-or-id>
POHW_IDENA_SNAPSHOT_PROOF_ROOT=<32-byte-root-hex>
```

Keep `POHW_DASHBOARD_UI_BIND_HOST` on loopback when the participant dashboard
is enabled. Its generated browser configuration contains the dashboard API
token, so the runner refuses to expose participant mode on a non-loopback UI.
Use SSH forwarding for remote participant access. A public explorer must set
`POHW_DASHBOARD_UI_PARTICIPANT_ENABLED=false` and never embeds that token.

Set `POHW_DASHBOARD_ALLOWED_ORIGINS` to the browser UI origin you actually use, for example `http://<pi-wlan-ip>:5176` if the UI is served from the Pi.

`pohw-gossip-mesh-local-peer.service` is optional. It runs a second local gossip
node with its own datadir so a single Pi can exercise peer inventory, sync, and
rebroadcast plumbing. Bind it to the specific Pi LAN IP instead of `0.0.0.0`,
and keep it off public interfaces. For real multi-node testing, replace
`POHW_PEER_ADDRS` with actual trusted participant peers and disable the local
test peer.

For remote workstation access, prefer SSH forwarding instead of non-loopback dashboard binds:

```sh
scripts/pohw-dashboard-tunnel.sh <pi-ssh-host>
open http://127.0.0.1:5176/
```

This requires SSH reachability to the Pi. Away from home, use a private VPN such as WireGuard/Tailscale, or expose only SSH with key auth and firewalling; do not expose `5176` or `40407` directly.

For holiday-safe access from changing networks, use Tailscale instead of router port forwarding:

```sh
# On the Mac: install Tailscale from https://tailscale.com/download and sign in.
# On the Pi, create a reusable or ephemeral auth key in the Tailscale admin UI,
# paste it into a protected local file, then install/connect:
sudo install -d -m 700 /etc/pohw
sudo install -m 600 -o root -g root /dev/null /etc/pohw/tailscale.authkey
sudo python3 - <<'PY'
import getpass
import os
from pathlib import Path

path = Path("/etc/pohw/tailscale.authkey")
key = getpass.getpass("Paste Tailscale auth key: ").strip()
if not key.startswith("tskey-"):
    raise SystemExit("Tailscale auth key should start with tskey-")
path.write_text(key + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY
sudo POHW_TAILSCALE_AUTHKEY_FILE=/etc/pohw/tailscale.authkey \
  /mnt/ssd/p2pool/scripts/pohw-install-tailscale-remote-access.sh
```

The installer also adds an SSH allow rule on `tailscale0` when UFW is present. Set `POHW_TAILSCALE_CONFIGURE_UFW=false` only if another firewall policy already permits Tailscale SSH.

Tailscale SSH policy can require a periodic browser identity check. For unattended key-based access, optionally publish the Pi's existing OpenSSH daemon on a separate tailnet-only TCP port:

```sh
sudo POHW_TAILSCALE_ENABLE_KEY_SSH_SERVE=true \
  POHW_TAILSCALE_KEY_SSH_SERVE_PORT=2222 \
  /mnt/ssd/p2pool/scripts/pohw-install-tailscale-remote-access.sh

ssh -p 2222 ubuntu@pibtc
POHW_PI_SSH_PORT=2222 scripts/pohw-dashboard-tunnel.sh ubuntu@pibtc
```

This fallback still requires an authorized Tailscale device and the OpenSSH private key. Before enabling it, the installer verifies that public-key authentication is enabled, password and keyboard-interactive authentication are disabled, root login is disabled, and the configured user is allowed. Tailscale Serve keeps port `2222` inside the tailnet; do not add a router-forward or public UFW rule for it.

After both the Mac and Pi are in the same tailnet, SSH and the dashboard tunnel work from any IP range:

```sh
ssh ubuntu@pibtc
scripts/pohw-dashboard-tunnel.sh ubuntu@pibtc
open http://127.0.0.1:5176/
```

If MagicDNS is disabled in Tailscale, replace `pibtc` with the Pi's `100.x.y.z` Tailscale IPv4 from `tailscale ip -4`. Keep the Tailscale auth key out of Git and delete it from `/etc/pohw/tailscale.authkey` after the Pi is connected if it is not reusable.

For a vacation-safe command-line status that avoids keys, cookies, addresses, and blockchain data, use the health monitor summary:

```sh
ssh <pi-ssh-host> '/usr/bin/python3 /opt/p2pool/scripts/pohw-health-status.py --format summary'
```

The legacy SSD timer writes the same sanitized state to `/mnt/ssd/pohw-p2pool/health/status.json`. Bootstrap and Stratum RPC-job refresh use `POHW_HEALTH_STATUS_FILE` when it exists, so they stop before calling Bitcoin RPC while the health state says Bitcoin is still in IBD, `NODE_NETWORK_LIMITED`, RPC timeout, or `getblocktemplate` failure. The health monitor also reports warning-only Idena P2P state from local config/log files, including active IPFS port drift and consensus-loop peer counts below `POHW_HEALTH_IDENA_MIN_PEERS`. If the summary reports `idena_ipfs_port_drift`, allow and router-forward the reported active port, or restart Idena during a non-validation window to return to the configured port.

On the SD-card runtime, the sanitized health state is stored at `/var/lib/pohw-p2pool/health/status.json`. `pohw-idena-workers-if-synced.timer` is an explicit opt-in that checks `bcn_syncing` every two minutes and starts only `idena-reward-indexer.service` and `idena-session-recorder.service` after the local node reaches the reported head with a valid clock. It never starts `idena.service`, so an operator pause remains in effect. Its secret-free status is `/var/lib/pohw/idena-workers/status.json`.

For an SD-only Pi that consumes Bitcoin from the Hetzner host, install the
persistent load guard:

```sh
sudo scripts/pohw-install-pi-load-guard.sh
```

It caps Idena at 2.5 CPU cores, starts 1 GB of compressed RAM swap without SD
writes, keeps 1 GB of RAM available to the operating system through cgroup
memory limits, disables Bitcoin restart timers, and blocks local Bitcoin Core
unless `/etc/pohw/enable-local-bitcoin` is deliberately created. Re-enable a
local Core only as an explicit maintenance action:

```sh
sudo touch /etc/pohw/enable-local-bitcoin
sudo systemctl daemon-reload
sudo systemctl enable --now bitcoind-mainnet.service
```

`pohw-auto-bootstrap.timer` checks the health file once per minute and runs `scripts/pohw-bootstrap-readiness.sh --mode real` once after the health monitor reports `miningReady=true`. Successful bootstrap writes `/mnt/ssd/pohw-p2pool/auto-bootstrap/bootstrap.done.json`; remove that marker only if you intentionally want another automatic bootstrap run.

`pohw-network-watchdog.timer` is the host self-recovery layer for cases where the Pi stays powered but disappears from the LAN. By default it pings the current default gateway once per minute, restarts the active network manager after 3 failed checks, and requests a reboot after 8 failed checks. A missing default route now follows those same thresholds instead of stalling in a diagnostic-only state. Set `POHW_NETWORK_WATCHDOG_TARGETS` to comma-separated stable targets if the default gateway is not enough for your network. The timer writes secret-free state to `/var/lib/pohw/network-watchdog/status.json`.

`pohw-idena-priority-guard.timer` protects validation/flip sessions from Bitcoin background validation load. It checks local `dna_epoch` once per minute, stops `bitcoind-mainnet.service` when the current Idena period looks like a flip, short, long, or validation period, or when `nextValidation` is inside `POHW_IDENA_PRIORITY_LEAD_SECONDS`, and restarts Bitcoin after `POHW_IDENA_PRIORITY_COOLDOWN_SECONDS` only if the guard stopped it itself. It does not depend on or start `idena.service`, so an operator pause remains a pause. The default lead is 1 hour and the default cooldown is 30 minutes. For an emergency manual pause, set `POHW_IDENA_PRIORITY_FORCE=true` in `/etc/pohw/p2pool.env` and restart the timer service; set it back to `false` after validation.

```sh
sudo systemctl start pohw-idena-priority-guard.service
sudo cat /var/lib/pohw/idena-priority/status.json
```

`pohw-bitcoin-pressure-guard.timer` is an optional last-resort protection against harmful Bitcoin background-validation I/O pressure. High disk utilization alone no longer trips it: pressure requires both high iowait and utilization, or critical utilization combined with high read/write latency, for `POHW_BITCOIN_PRESSURE_HIGH_STREAK` checks. It restarts Bitcoin after `POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS` once iowait, utilization, and latency remain below their low thresholds for `POHW_BITCOIN_PRESSURE_LOW_STREAK` checks. By default it will not stop Bitcoin after the health monitor reports `miningReady=true`, and the installer does not enable this timer without explicit opt-in.

```sh
sudo systemctl start pohw-bitcoin-pressure-guard.service
sudo cat /var/lib/pohw/bitcoin-pressure/status.json
```

The hardware watchdog config in `deploy/systemd/system.conf.d/10-pohw-watchdog.conf` lets systemd feed the Raspberry Pi watchdog device. After the next reboot, the host should reboot itself if PID 1 or the kernel stops scheduling long enough that the watchdog is no longer fed. Check support with:

```sh
ls -l /dev/watchdog*
systemctl show -p RuntimeWatchdogUSec -p RebootWatchdogUSec
```

The default cookie watcher assumes `BITCOIN_RPC_COOKIE_FILE=/mnt/ssd/bitcoin/bitcoin-core-mainnet/.cookie`. If you use a different Bitcoin cookie path, enable the templated watcher for that path instead:

```sh
COOKIE_UNIT="$(systemd-escape --path "$BITCOIN_RPC_COOKIE_FILE")"
sudo systemctl disable --now pohw-dashboard-api-cookie-watch.path
sudo systemctl enable --now "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
```

Install host hardening drop-ins after Bitcoin Core and idena-go are already configured:

```sh
sudo install -d -m 755 /etc/ssh/sshd_config.d /etc/systemd/system/bitcoind-mainnet.service.d /etc/systemd/system/idena.service.d
sudo install -m 644 deploy/ssh/sshd-pohw-hardening.conf /etc/ssh/sshd_config.d/99-pohw-hardening.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-hardening.conf /etc/systemd/system/bitcoind-mainnet.service.d/30-hardening.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-runtime.conf /etc/systemd/system/bitcoind-mainnet.service.d/50-runtime.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-resource.conf /etc/systemd/system/bitcoind-mainnet.service.d/60-resource.conf
sudo install -m 644 deploy/systemd/idena-hardening.conf /etc/systemd/system/idena.service.d/30-hardening.conf
sudo sshd -t
sudo systemctl daemon-reload
```

For a Pi with Bitcoin Core on `/mnt/ssd`, start from `deploy/bitcoin/bitcoin-mainnet.conf.example` and copy only non-secret settings into the live `bitcoin.conf`. The template keeps RPC local-only, keeps a full unpruned chain for fork/testing work, and uses `dbcache=1536` for a 4 GiB Pi to reduce SSD pressure during AssumeUTXO background validation. The `60-resource.conf` drop-in lowers Bitcoin CPU/I/O priority so Idena and PoHW control services stay responsive while background validation runs. Reduce `dbcache` if the host shows real memory pressure.

### Dedicated Bitcoin Disk

For a split-disk Pi, keep the repository, Idena, and PoHW state under `/mnt/ssd`, and mount the Bitcoin disk separately at `/mnt/bitcoin-wd`. Use a filesystem UUID in the Pi's local `/etc/fstab`; do not commit the UUID or a `/dev/sdX` name. A suitable local entry is:

```text
UUID=REPLACE_WITH_LOCAL_UUID /mnt/bitcoin-wd ext4 defaults,noatime,nofail,x-systemd.automount,x-systemd.device-timeout=30s 0 2
```

Before allowing a newer Bitcoin Core version to write an older datadir, stop Core and preserve at least `chainstate`, `blocks/index`, the live configuration, and the mutable tail of `blk*.dat`/`rev*.dat`. Keep the previous Bitcoin disk unchanged until the replacement node has survived a clean restart. The dedicated datadir used by the supplied drop-ins is `/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet`.

Install the dedicated-disk overrides after the standard hardening/runtime drop-ins:

```sh
sudo install -d -m 755 \
  /etc/systemd/system/bitcoind-mainnet.service.d \
  /etc/systemd/system/pohw-auto-bootstrap.service.d \
  /etc/systemd/system/pohw-dashboard-api.service.d \
  /etc/systemd/system/pohw-health-status.service.d
sudo install -m 644 deploy/systemd/bitcoind-mainnet-wd.conf \
  /etc/systemd/system/bitcoind-mainnet.service.d/70-wd-datadir.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-sync-priority.conf \
  /etc/systemd/system/bitcoind-mainnet.service.d/80-sync-priority.conf
for service in pohw-auto-bootstrap pohw-dashboard-api pohw-health-status; do
  sudo install -m 644 deploy/systemd/pohw-bitcoin-wd-readonly.conf \
    "/etc/systemd/system/${service}.service.d/50-bitcoin-wd.conf"
done
```

Archive any older drop-in that still adds `RequiresMountsFor=/mnt/ssd` to `bitcoind-mainnet.service`; systemd dependencies from that file cannot be removed by a later drop-in. Set these three path-only values in `/etc/pohw/p2pool.env`, preserving all other protected values:

```text
POHW_BITCOIN_DATADIR=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet
POHW_BITCOIN_RPC_COOKIE_FILE=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie
BITCOIN_RPC_COOKIE_FILE=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie
```

Use the templated cookie watcher for the new location. The watcher intentionally has no `Wants=` or `After=` dependency on runtime services; adding those dependencies can pull Bitcoin and the dashboard into `paths.target` and create a boot ordering cycle.

```sh
sudo install -m 644 deploy/systemd/pohw-dashboard-api-cookie-watch@.path /etc/systemd/system/
sudo systemctl disable --now pohw-dashboard-api-cookie-watch.path
COOKIE_UNIT="$(systemd-escape --path /mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie)"
sudo systemctl daemon-reload
sudo systemctl enable --now "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
sudo systemd-analyze verify bitcoind-mainnet.service "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
sudo systemctl enable --now bitcoind-mainnet.service
```

During an intentional Bitcoin-only sync window, the `80-sync-priority.conf` override cancels the normal Idena-friendly CPU/I/O de-prioritization. Keep Idena and both priority/pressure guard timers disabled during that window. Remove the override and reload systemd before resuming Idena:

```sh
sudo rm /etc/systemd/system/bitcoind-mainnet.service.d/80-sync-priority.conf
sudo systemctl daemon-reload
```

Validate the migration with a clean reboot. The acceptance checks are: both mounts are read-write, `bitcoind-mainnet.service` starts without restarts from the dedicated datadir, Idena remains in the intended state, the cookie watcher and dashboard are active, and the tailnet SSH path returns after boot.

If UFW is enabled, expose only the intended ports:

```sh
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 22 proto tcp comment "SSH WLAN only"
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 40406 proto tcp comment "PoHW P2Pool gossip LAN"
sudo ufw allow in on wlan0 from <trusted-mac-ip> to any port 40407 proto tcp comment "PoHW dashboard API trusted client only"
sudo ufw allow in on wlan0 from <miner-or-rental-ip> to any port 3333 proto tcp comment "PoHW Stratum trusted miner only"
sudo ufw allow in on wlan0 to any port 8333 proto tcp comment "Bitcoin mainnet P2P"
sudo ufw allow in on wlan0 to any port 40405 proto tcp comment "Idena P2P active port"
sudo ufw allow in on tailscale0 to any port 22 proto tcp comment "SSH over Tailscale"
```

## Reward And Payout Rules

- Reward weight = 50% Bitcoin hashrate score + 50% Idena score.
- Idena score includes validation, mining, proposer, and final committee rewards.
- Idena score excludes invitation, generic contract, and oracle rewards unless explicitly added later.
- Accounting credits the identity that earned the reward.
- Direct payouts require at least `10_000 sats`.
- The direct payout count is configurable; the current default is 100.
- Everything else goes to the current FROST vault as a non-transferable withdrawal claim.

## FROST Vault Model

- Signer membership is dynamic per weekly epoch.
- Each epoch runs its own DKG and creates one Taproot vault key.
- Threshold is `ceil(0.67 * n)` for that epoch.
- New signers join the next epoch, not an existing vault key.
- Signers must replay the ledger and revalidate vault inputs before releasing signature shares.

## Security Boundaries

Do not use real funds.

Important boundaries:

- The dashboard is not an authority.
- Sharechain logs and indexes are local replay artifacts.
- Gossip peers forward signed messages, but every node still verifies locally.
- Non-loopback dashboard API mode requires a strong token and explicit allowed origins.
- RPC URLs are loopback-only by default.
- Do not use size-only verified Bitcoin chainstate snapshots. If using AssumeUTXO, import through Bitcoin Core so the built-in snapshot metadata/hash is validated.
- The project intentionally has no transferable iBTC token, no user BTC deposits, and no secondary-market claim object.
- Replay protection is required before inherited Bitcoin UTXO spending can be meaningful on a fork.
- Experiment 1 implements that replay protection and permits inherited spends;
  it does not protect a reused or disclosed private key. Treat every inherited
  script as a possible real-Bitcoin key boundary.
- Idena eligibility is read from the live Idena chain. Registration should sign
  only the displayed domain-separated ownership challenge; never import an
  Idena node key, identity backup, password, or API key into P2poolBTC.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s pohw_idena_rpc/tests -p 'test_*.py' -v
corepack pnpm@11.11.0 --dir ui/pohw-dashboard build
corepack pnpm@11.11.0 --dir contracts/idena-snapshot-registry test
corepack pnpm --dir contracts/idena-code-governance install --frozen-lockfile
corepack pnpm --dir contracts/idena-code-governance build
corepack pnpm --dir contracts/idena-code-governance test
bash -n scripts/*.sh
gitleaks git . --redact
```

The Governance Day cross-repository test is opt-in because it requires an
exact IdenaAI checkout and applies a patch to a disposable archive:

```sh
env POHW_CONFIRM_LOCAL_TEST_PATCH=YES \
  IDENA_AI_ROOT=/absolute/path/to/idena-ai \
  tests/governance/governance-day-e2e.sh
```

## License

MIT. See [`LICENSE`](LICENSE).
