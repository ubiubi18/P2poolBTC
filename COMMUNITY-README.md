# Join P2poolBTC Experiment 0

> [!IMPORTANT]
> This guide reproduces the frozen coinbase-only Experiment 0. It cannot test
> general transactions, inherited UTXOs, Bitcoin Core wallets, or live FROST
> spends. Use [Experiment 1](EXPERIMENT-1.md) for that successor network; do not
> silently reuse Experiment 0 data or activation parameters.

This is the shortest safe path for a community member to build P2poolBTC from
source, register an Idena identity, join the existing no-value fork, and later
connect a Stratum miner.

The onboarding path does **not** download a P2poolBTC executable and does not
trust a signature from `ubiubi18`, a coordinator, or any lead developer. It
compiles the checked-out source with the tracked `Cargo.lock`, computes the
deterministic source-tree CID locally, hashes the resulting executable, and
uses the activation manifest inside that same source tree.

> [!WARNING]
> Experiment 0 is an experimental fork with no monetary value. Do not deposit
> BTC or IDNA. The source-first wizard never arms the separate 20-participant
> Bitcoin-mainnet handoff and never passes `--allow-mainnet-submit`.
>
> Idena itself is live. Signing proves control publicly, while delegation,
> stake, validation, transactions, and contracts can affect real balances or
> identity state. The wizard must never receive an Idena private key, backup,
> password, or API key.

## What You Need

- Git and a current stable Rust toolchain from [rustup](https://rustup.rs/).
- About 3 GB of free space for source, dependencies, and local builds.
- Current gossip, fork RPC, and fork P2P endpoints from an existing participant.
- An eligible Idena identity if you want to register or mine.
- A Stratum v1 miner only when the experiment has entered its mining phase.

You do not need Bitcoin Core, a Bitcoin transaction index, a full explorer, an
Idena private key file, or an Idena API key for the basic join flow. Idena Web
or Desktop signs the ownership challenge without giving the key to P2poolBTC.

## Five-Step Fast Path: Source-First Join

### 1. Obtain And Inspect The Source

GitHub is currently a convenient mirror, not a release authority. Clone it,
then check out the exact commit independently agreed by participants:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
git checkout --detach '<40-character-community-agreed-commit>'
git status --short
```

The final command must print nothing. The launcher also rejects ignored files
and directories because a build script could consume them without changing the
source CID. Use a fresh checkout; do not continue from a locally used worktree.
Compare the commit through at least two independent community channels. After
the build, compare the stronger source CID printed by `pohw-agent`; a Git commit
is metadata and does not replace the source CID.

### 2. Get Peer Hints

Ask any current participant for these three public transport endpoints:

```text
gossip host:port
fork RPC host:port
fork P2P host:port
```

Peer hints are not governance authority. They cannot replace the local
activation manifest. In fork-sync and mining modes the agent queries the fork
RPC and refuses peers that do not report the locally pinned activation ID:

A different activation ID is a different experiment.

```text
0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e
```

Prefer hints confirmed by more than one participant. A malicious hint can
still waste time or attempt an eclipse, even though it cannot make a different
activation pass local validation.

### 3. Build Locally And Open The Wizard

On macOS, Linux, or Raspberry Pi:

```sh
scripts/pohw-community-join.sh \
  --gossip-peer '<gossip-host:port>' \
  --fork-rpc-peer '<fork-rpc-host:port>' \
  --fork-p2p-peer '<fork-p2p-host:port>'
```

On Windows PowerShell:

```powershell
.\scripts\pohw-community-join.ps1 `
  -GossipPeer '<gossip-host:port>' `
  -ForkRpcPeer '<fork-rpc-host:port>' `
  -ForkP2pPeer '<fork-p2p-host:port>'
```

The launcher creates a new private temporary Cargo target directory for every
run, removes build-injection environment variables, and accepts binaries only
from that fresh build root:

```sh
CARGO_TARGET_DIR='<new-private-temporary-directory>' \
  cargo build --locked --release -p p2pool-node -p pohw-agent
```

The agent rejects ignored inputs, any tracked file omitted from the source CID,
and any packaged file that is not tracked. It then verifies that both
executables came from the declared fresh build root and displays:

- deterministic CIDv1/SHA2-256 source-tree CID;
- source-tree SHA-256 and Git commit metadata;
- `Cargo.lock` SHA-256;
- deterministic CycloneDX 1.5 dependency SBOM and its SHA-256;
- local `p2pool-node` SHA-256;
- Rust and Cargo versions;
- activation ID and activation-manifest SHA-256.

Its private build receipt is stored under
`~/.pohw-agent/pohw-experiment-0/`. Compare the source CID with independent
participants before mining. A mismatch means the source bytes or normalized
file modes differ; stop and investigate.

### 4. Register The Idena Identity

The launcher opens a loopback-only browser wizard, normally at
`http://127.0.0.1:8765/`.

1. Enter a lowercase public miner name and your public `0x...` Idena address.
2. Select **Sign in Idena Web** or **Open Idena Desktop**.
3. Review and approve the exact ownership challenge in Idena.
4. Return to the wizard. It verifies the signature and stores three new local
   P2Pool keys with private file permissions.
5. Confirm the no-value warning and select **Start node**.

The registration phase starts signed gossip only. It does not start the fork,
Stratum, Bitcoin Core, or Bitcoin-mainnet submission. Never send anyone the
Idena backup, private key, password, API key, or the generated P2Pool keys.

### 5. Progress To Fork Sync And Mining

When participants agree that fork sync is open, stop the current agent with
`Ctrl-C` and rerun the same source command with:

```sh
scripts/pohw-community-join.sh \
  --gossip-peer '<gossip-host:port>' \
  --fork-rpc-peer '<fork-rpc-host:port>' \
  --fork-p2p-peer '<fork-p2p-host:port>' \
  --launch-phase fork-sync
```

The existing verified registration and local keys are reused. The agent starts
the fork node only after a fork RPC peer proves the matching activation ID.

Mining additionally requires a local directory containing the currently
agreed Idena snapshot JSON and a positive signed-voter quorum. Obtain the same
snapshot through independent participants, keep it outside the source tree,
and allow gossip to import the corresponding signed `SnapshotVote` messages.
Then run:

```sh
scripts/pohw-community-join.sh \
  --gossip-peer '<gossip-host:port>' \
  --fork-rpc-peer '<fork-rpc-host:port>' \
  --fork-p2p-peer '<fork-p2p-host:port>' \
  --launch-phase mining \
  --snapshot-dir '<private-snapshot-directory>' \
  --snapshot-min-voters '<independently-agreed-positive-quorum>'
```

The agent does not accept a caller-declared snapshot ID, root, height, count,
or identity status. `p2pool-node` recomputes the snapshot root, rejects future
or stale snapshots and ambiguous snapshot directories, counts distinct signed
snapshot voters from local sharechain replay, and checks that the registered
identity is present as `Newbie`, `Verified`, or `Human`. It repeats this check
immediately before Stratum starts. Signed votes reduce unilateral snapshot
substitution risk, but they do not replace independently checking the snapshot
against Idena chain data; choose the quorum and snapshot sources accordingly.

After the explicit no-value confirmation, the wizard shows the loopback
Stratum URL, worker name, and a locally generated password once. Point the
miner at that URL. The adapter submits only to the local fork RPC.

## How To Know You Succeeded

Keep the source-first launcher running. In a second terminal, run this
sanitized local check on macOS, Linux, or Raspberry Pi:

```sh
python3 scripts/pohw-community-status.py
```

On Windows with the Python launcher:

```powershell
py -3 .\scripts\pohw-community-status.py
```

If you selected a different agent datadir, add `--datadir '<same-path>'`. The
command rechecks the source receipt, local binary digest, activation manifest,
and signed registration before reading aggregate node state. It deliberately
does not print identity addresses, signatures, peer endpoints, local paths,
keys, passwords, wallet data, or block hashes. Exit code `0` means the local
checks required for the selected phase are ready, `2` means setup is
incomplete, and `1` means an integrity or command check failed.

Use this success ladder. A later row does not replace the earlier checks:

| Stage | What you see locally | Independent confirmation |
| --- | --- | --- |
| Source verified | Wizard says **Source build: Verified** and shows a source CID | At least two independent participants report the same full source CID and activation ID |
| Identity registered | Wizard says **Idena ownership verified and registration created**; status says `Idena registration: VERIFIED` | Another node or the explorer eventually lists your public miner ID, without needing your Idena key |
| Fork synchronized | Status says `Fork chain: RUNNING` and reports a fork height and active fork-block count | The height and active tip agree with the experiment explorer or another independently operated node after sync settles |
| Miner connected | Your miner shows an authorized worker and receives jobs from the loopback Stratum URL | The miner begins reporting accepted shares without repeated authorization or stale-job failures |
| Share credited | Local `active shares` increases after accepted work | The explorer **Sharechain** tab shows your public miner ID on an active share |
| Fork block accepted | Local fork height and active fork-block count increase | The explorer **Fork blocks** tab shows the same active block and its PoHW commitment |
| Idena gate passed | Mining phase starts without an eligibility or snapshot error | Explorer aggregate snapshot fields match the independently agreed snapshot; individual addresses remain private by default |

A miner share is not necessarily a fork block. It is normal to see accepted
shares before the fork height changes. Fork synchronization is also stronger
than merely having a nonzero height: compare the current height with another
node, and stop if equal input produces a different active tip or cumulative
work.

If an HTTPS explorer was supplied with `--explorer-url`, the wizard displays
an **Open experiment explorer** link. In the explorer:

1. **Overview** must show Fork, Sharechain, Idena, and API as connected or
   verified as applicable.
2. **Fork blocks** must show active blocks at the same height as the local
   status command.
3. **Sharechain** must eventually show your chosen public miner ID and an
   active share after the miner submits accepted work.
4. Opening a fork block shows its coinbase value, outputs, and PoHW commitment.
   Those values are no-value test accounting, not spendable Bitcoin.

Do not treat one hosted explorer as consensus. The local check plus one or more
independently operated nodes is the meaningful confirmation.

### Bitcoin Core Will Not Show Experiment 0 Coins

Experiment 0 does **not** install or modify a Bitcoin Core fork. Its temporary
coinbase-only chain is validated and stored by `p2pool-node`. Bitcoin Core,
when present, remains a Bitcoin mainnet node and is not required for the basic
community join flow.

Consequently:

- Bitcoin Core Qt will not show Experiment 0 transactions or a fork balance;
- `bitcoin-cli getbalance`, `listunspent`, and wallet history will not show
  Experiment 0 coinbase outputs;
- `bitcoin-cli getblockcount` continues to report the Bitcoin mainnet height,
  not the Experiment 0 fork height;
- `bitcoin-cli getblockchaininfo` should continue to report `"chain":
  "main"` on a mainnet node.

See fork blocks and coinbase outputs through `pohw-community-status.py`, the
PoHW explorer, or `p2pool-node fork-chain-status`. Current Experiment 0
consensus disables spending both inherited and post-fork outputs, so the
displayed fork coinbase is not a spendable wallet balance. If ordinary
source-first onboarding appears to submit fork blocks to Bitcoin Core or arms
Bitcoin-mainnet submission, stop immediately and report a security issue.

## What Is And Is Not Decentralized Yet

No developer signature selects or installs the executable. Every participant
builds and hashes their own artifact. The activation ID is enforced locally,
and source CIDs can be compared independently.

This does not yet solve initial source discovery. Until the experimental DAO
governance contract is deployed and its canonical ecosystem CID is broadly
observed, participants still choose a source CID socially. GitHub can censor
or serve source, and one participant can lie about a CID. Use several mirrors
and independent participants; do not treat repository ownership as authority.
See [the source-first trust model](docs/source-first-onboarding.md).

## Advanced And Operator Paths

The one-command wizard intentionally omits:

- creating a separate fork;
- bootstrapping the first network seed;
- the Bitcoin-mainnet handoff controller;
- public Stratum exposure;
- unattended system-service installation;
- source updates inside an existing datadir.

Operators needing those features must read [`EXPERIMENT-0.md`](EXPERIMENT-0.md)
and use a separate reviewed configuration. The ordinary join command rejects
any activation file other than the tracked Experiment 0 manifest.

## Report A Problem

Search [existing issues](https://github.com/ubiubi18/P2poolBTC/issues) first.
For a normal bug, use the
[Experiment 0 issue form](https://github.com/ubiubi18/P2poolBTC/issues/new?template=experiment-0-bug.yml).

Before opening an issue:

1. Stop the agent and miner if activation, replay, payout, signature, or network
   exposure is involved. Preserve the datadir.
2. Record UTC time, operating system, architecture, Git commit, source CID,
   `Cargo.lock` digest, command, expected result, and actual result.
3. Include only the smallest sanitized error. Never paste the private build
   receipt blindly because it contains local filesystem paths.
4. Reproduce once only when doing so cannot expose data or submit value.

Use this public template:

```text
Title: [Experiment 0] <component>: <short failure>

Role:
Git commit metadata:
Source CID:
Cargo.lock SHA-256:
Operating system and architecture:
UTC occurrence time:
Command or action:
Expected result:
Actual result:
Minimal reproduction:
Frequency:
Fork and mining stopped if consensus-related: yes/no/not applicable
```

Do not paste `.env` files, API requests, RPC cookies, IP addresses, hostnames,
Idena addresses, Idena API keys, wallet data, backups, seed phrases, private
keys, passwords, callback URLs, signatures not intentionally published, core
dumps, raw logs, or screenshots that reveal those values.

### Security Or Privacy Problems

Do not open a public issue for a suspected secret leak, authentication bypass,
remote-code execution, consensus bypass, signature failure, or deanonymization
problem. Use the repository's private
[Security page](https://github.com/ubiubi18/P2poolBTC/security) and follow
[`SECURITY.md`](SECURITY.md).

## Stop Conditions

Stop the affected service and report immediately if:

- another participant reports a different source CID for the same agreed state;
- a fork peer reports a different activation ID;
- honest peers replay the same messages to different roots;
- an unsigned or invalidly signed message is accepted;
- the source-first agent starts Bitcoin Core or passes `--allow-mainnet-submit`;
- a participant is asked for a key, backup, seed phrase, cookie, API key, or deposit;
- a report or screenshot contains data its owner did not intend to publish.

The full protocol and recovery details are in
[`EXPERIMENT-0.md`](EXPERIMENT-0.md). Tester roles are in
[`BETA-TESTING.md`](BETA-TESTING.md).
