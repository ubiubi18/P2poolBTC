# Experiment 0 Fork-Chain Node

The Experiment 0 fork-chain node is the consensus and live-template source for
the no-value PoHW test chain. It inherits one Bitcoin mainnet block hash as its
parent, but it does not modify Bitcoin Core and it never submits fork blocks to
Bitcoin mainnet.

## Consensus Contract

Every node loads the same canonical `fork-activation.json`. The activation ID
commits to the inherited tip, first fork height, launch time, post-fork PoW
limit, target spacing, difficulty algorithm, bootstrap handoff hashrate, and
inherited-UTXO policy.

Experiment 0 deliberately has a small complete consensus surface:

- the first fork block must extend the manifest's inherited Bitcoin tip;
- every later block must extend a known fork block;
- header `nBits` must equal the branch's deterministic next target;
- SHA256d proof of work, merkle root, witness commitment, block weight, future
  time, and median-time-past are validated;
- the coinbase must begin with the minimally encoded BIP34 height;
- the coinbase may not create more than the absolute-height Bitcoin subsidy;
- a block contains exactly one transaction, the coinbase;
- inherited and post-fork output spending is disabled;
- fork choice uses cumulative work, then the lexicographically smaller tip hash
  as a deterministic equal-work tie break.

Coinbase-only consensus is intentional. It makes the current chain complete for
the no-value payout-accounting experiment without pretending that this Rust
prototype reimplements Bitcoin Core's script, UTXO, mempool, and policy engines.

### Difficulty Schedule

Manifest schema 2 uses `bootstrap_then_bitcoin_2016_v1`:

1. The first fork block uses the manifest PoW limit.
2. During bootstrap, every child target is the parent target multiplied by the
   timestamp delta divided by target spacing. The delta is bounded to 1/4x..4x
   spacing and the target is capped at the manifest PoW limit.
3. When target work divided by target spacing reaches
   `bootstrap_handoff_hashrate_hps`, that block becomes a Bitcoin retarget epoch
   anchor. The default threshold is `1000000000000000` hashes/second (`1 PH/s`).
4. Descendants then keep one target for 2016 blocks and apply Bitcoin Core's
   bounded retarget formula at each epoch boundary. They cannot return to the
   bootstrap DAA. A reorg that removes the handoff block also removes its state,
   as with any other branch-local consensus transition.

The 512-bit intermediate preserves Bitcoin's multiply-then-divide result even
at the intentionally easy bootstrap target. Status reports `difficulty_phase`,
the manifest threshold, estimated target-implied hashrate, and blocks remaining
until the next Bitcoin retarget.

## Ports

| Port | Default | Exposure |
| --- | --- | --- |
| Fork control RPC | `127.0.0.1:40408` | Loopback only |
| Fork P2P | disabled | Set an explicit bind; trusted peers or firewalled public test port |
| Sharechain gossip | `127.0.0.1:40406` | Separate signed PoHW message network |
| Stratum | `127.0.0.1:3333` | Loopback unless password-protected and firewalled |

The fork protocol uses bounded length-prefixed JSON frames. Every request carries
the activation ID. Blocks received over RPC or P2P pass the same consensus
validator before durable append. Loopback control RPC and configured fork-peer
IPs may submit blocks. Unconfigured P2P clients may read and synchronize chain
data, but block submission is rejected.

## Prepare

Build and initialize the default existing-network configuration. Initialization
installs the repository's canonical Experiment 0 activation manifest:

```sh
cargo build --release -p p2pool-node
scripts/pohw-experiment-init.sh \
  --miner-id alice \
  --fork-peer-addrs <current-experiment-0-peer>:40409
```

Do not run `pohw-experiment-prepare-fork-activation.sh` when joining Experiment
0. It now requires the explicit `create-separate` mode documented in
[`EXPERIMENT-0.md`](../EXPERIMENT-0.md#start-a-separate-experiment-explicit-opt-in).

Set these values in the protected node environment:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
POHW_EXPERIMENT_NETWORK_MODE=join-existing
POHW_FORK_ACTIVATION_MANIFEST=/var/lib/pohw-p2pool/fork-activation.json
POHW_FORK_BOOTSTRAP_HANDOFF_HASHRATE_HPS=1000000000000000
POHW_FORK_CHAIN_DATADIR=/var/lib/pohw-p2pool/fork-chain
POHW_FORK_RPC_BIND_ADDR=127.0.0.1:40408
POHW_FORK_P2P_BIND_ADDR=<node-address>:40409
POHW_FORK_ALLOW_NON_LOOPBACK_P2P=true
POHW_FORK_PEER_ADDRS=<current-experiment-0-peer>:40409
POHW_FORK_BOOTSTRAP_FIRST_SEED=false
POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408
POHW_ADMIT_PEER_WORK_TEMPLATES=true
```

An outbound-only joining node may keep `POHW_FORK_P2P_BIND_ADDR` empty, but it
must configure and reach an existing fork peer before mining. A deliberate
single-node test belongs in `create-separate` mode. When P2P is public, allow
only the selected fork P2P TCP port from announced participant IPs through the
host firewall. Never expose the control RPC. The configured peer IPs form the
temporary remote block-submission allowlist for the easy bootstrap phase; this
is not a substitute for authenticated production peering.

Only the designated coordinator may initialize the canonical first seed with:

```sh
scripts/pohw-experiment-init.sh \
  --miner-id coordinator \
  --bootstrap-first-seed
```

That writes `POHW_FORK_BOOTSTRAP_FIRST_SEED=true` and permits a peerless fork
service, not Stratum or block production. When an independent second endpoint
exists, set the flag to `false`, add that endpoint to `POHW_FORK_PEER_ADDRS`,
and restart. The runner rejects both ordinary peerless joins and a stale
first-seed exception combined with configured peers.

## Run

Foreground:

```sh
scripts/pohw-run-fork-chain-node.sh
```

Systemd:

```sh
sudo install -d -m 700 -o ubuntu -g ubuntu /var/lib/pohw-p2pool/fork-chain
sudo install -m 0644 deploy/systemd/pohw-fork-chain-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-fork-chain-node.service
```

On a server that uses the dedicated `pohw` account and `/srv/sharechain`,
install the matching server drop-ins after the base units:

```sh
sudo install -d -m 0755 /etc/systemd/system/pohw-fork-chain-node.service.d \
  /etc/systemd/system/pohw-gossip-mesh.service.d \
  /etc/systemd/system/pohw-mining-adapter.service.d
sudo install -m 0644 deploy/systemd/pohw-fork-chain-node-server.conf \
  /etc/systemd/system/pohw-fork-chain-node.service.d/server.conf
sudo install -m 0644 deploy/systemd/pohw-gossip-mesh-server.conf \
  /etc/systemd/system/pohw-gossip-mesh.service.d/server.conf
sudo install -m 0644 deploy/systemd/pohw-mining-adapter-server.conf \
  /etc/systemd/system/pohw-mining-adapter.service.d/server.conf
```

Keep Stratum disabled until miner registration, snapshot fields, and the
bootstrap handoff threshold have been selected. Keep the easy `207fffff`
bootstrap phase on trusted, firewalled peers; do not expose it as a public
permissionless network.

Read status through the activation-bound loopback RPC:

```sh
target/release/p2pool-node fork-chain-status \
  --activation-manifest /var/lib/pohw-p2pool/fork-activation.json
```

## Live Stratum Feed

After miner registration and snapshot selection, configure:

```sh
POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408
POHW_FORK_ACTIVATION_MANIFEST=/var/lib/pohw-p2pool/fork-activation.json
POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true
```

Then start `pohw-mining-adapter.service`. In fork mode the adapter:

1. obtains the initial template from the fork node;
2. derives the Stratum coinbase and target from that template;
3. refreshes and pushes clean jobs when the active fork tip changes;
4. persists target-meeting candidate artifacts;
5. submits complete target-meeting blocks only to fork RPC.

Fork mode is mutually exclusive with Bitcoin RPC template refresh. The adapter
does not forward Bitcoin RPC credentials and cannot submit a fork block through
Bitcoin Core.

`POHW_ADMIT_PEER_WORK_TEMPLATES=true` makes the gossip mesh validate every
signed peer template through the same loopback fork RPC before admitting it.
Leave it false only for a single-node Stratum smoke test that does not exchange
work templates.

For a manual candidate submission:

```sh
target/release/p2pool-node submit-fork-chain-block-candidate \
  --candidate-file /var/lib/pohw-p2pool/block-candidates/block-<hash>.json \
  --activation-manifest /var/lib/pohw-p2pool/fork-activation.json
```

## Smoke Test

```sh
cargo test -p p2pool-node fork_chain
bash -n scripts/pohw-run-fork-chain-node.sh scripts/pohw-run-mining-adapter.sh
systemctl is-active pohw-fork-chain-node.service
target/release/p2pool-node fork-chain-status \
  --activation-manifest /var/lib/pohw-p2pool/fork-activation.json
```

Across two nodes, compare `activation_id`, `tip_height`, `tip_hash`, and
`cumulative_work`. After one node accepts a block, the other must converge to the
same active tip through fork P2P.

## Recovery And Rollback

`fork-blocks.ndjson` is append-only and replayed through the full validator on
every startup. If a crash leaves only an incomplete final JSON record, startup
removes that non-durable tail and replays the last complete record. A complete
record written before its final newline is preserved. Complete malformed,
wrong-activation, duplicate, and out-of-order records still fail closed. Do not
edit the log while the service is running.

Before deployment:

```sh
sudo systemctl stop pohw-mining-adapter.service pohw-fork-chain-node.service
sudo cp -a /var/lib/pohw-p2pool/fork-chain \
  /var/lib/pohw-p2pool/fork-chain.backup-$(date -u +%Y%m%dT%H%M%SZ)
```

To roll back the binary, stop both services, restore the previous release, and
restart the fork node before Stratum. To reset this no-value experiment, stop
both services and move the entire fork-chain datadir aside. Never reuse a block
log with a different activation manifest.

## Remaining Production Work

- general post-fork transaction and script/UTXO consensus;
- inherited UTXO replay protection and spending;
- production anti-eclipse, authenticated peer policy, and network diversity;
- production FROST signer operation and real-value payouts.
