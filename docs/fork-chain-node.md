# Experiment 0 Fork-Chain Node

The Experiment 0 fork-chain node is the consensus and live-template source for
the no-value PoHW test chain. It inherits one Bitcoin mainnet block hash as its
parent, but it does not modify Bitcoin Core and it never submits fork blocks to
Bitcoin mainnet.

## Consensus Contract

Every node loads the same canonical `fork-activation.json`. The activation ID
commits to the inherited tip, first fork height, launch time, fixed post-fork
target, target spacing, and inherited-UTXO policy.

Experiment 0 deliberately has a small complete consensus surface:

- the first fork block must extend the manifest's inherited Bitcoin tip;
- every later block must extend a known fork block;
- header `nBits` must equal the manifest's fixed post-fork PoW limit;
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

## Ports

| Port | Default | Exposure |
| --- | --- | --- |
| Fork control RPC | `127.0.0.1:40408` | Loopback only |
| Fork P2P | disabled | Set an explicit bind; trusted peers or firewalled public test port |
| Sharechain gossip | `127.0.0.1:40406` | Separate signed PoHW message network |
| Stratum | `127.0.0.1:3333` | Loopback unless password-protected and firewalled |

The fork protocol uses bounded length-prefixed JSON frames. Every request carries
the activation ID. Blocks received over RPC or P2P pass the same consensus
validator before durable append.

## Prepare

Build and create the activation manifest from synchronized Bitcoin Core:

```sh
cargo build --release -p p2pool-node
scripts/pohw-experiment-prepare-fork-activation.sh .pohw-experiment.env
```

Set these values in the protected node environment:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
POHW_FORK_ACTIVATION_MANIFEST=/var/lib/pohw-p2pool/fork-activation.json
POHW_FORK_CHAIN_DATADIR=/var/lib/pohw-p2pool/fork-chain
POHW_FORK_RPC_BIND_ADDR=127.0.0.1:40408
POHW_FORK_P2P_BIND_ADDR=<node-address>:40409
POHW_FORK_ALLOW_NON_LOOPBACK_P2P=true
POHW_FORK_PEER_ADDRS=<peer-a>:40409,<peer-b>:40409
POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408
POHW_ADMIT_PEER_WORK_TEMPLATES=true
```

Keep `POHW_FORK_P2P_BIND_ADDR` empty for a single-node test. When it is public,
allow only the selected fork P2P TCP port through the host firewall. Never expose
the control RPC.

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

Keep Stratum disabled until miner registration, snapshot fields, and a fixed
target appropriate for the expected hashrate have been selected. The easy
`207fffff` development target must not be exposed to untrusted public peers.

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
every startup. A malformed, truncated, wrong-activation, or out-of-order record
fails closed. Do not edit the log while the service is running.

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
- adaptive difficulty adjustment beyond the fixed Experiment 0 target;
- production anti-eclipse, authenticated peer policy, and network diversity;
- production FROST signer operation and real-value payouts.
