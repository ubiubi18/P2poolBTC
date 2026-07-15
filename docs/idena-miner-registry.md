# Ownerless Idena Miner Registry

Status: experimental source code only. No contract address, activation height, or
live policy is canonical yet. Nothing in this repository change deploys a
contract or starts mining.

## Purpose

The registry gives every miner registration a public lower-bound timestamp on
the existing Idena chain. It replaces developer-signed admission packets with
state that every P2PoolBTC node can read from its own synchronized Idena node.

The contract has no owner, administrator, upgrade key, allowlist, or deletion
method. The deployer sets the experiment ID, source ecosystem CID, and minimum
registration burn in the deployment transaction. After that transaction, the
deployer has no special capability.

This is an application-layer Idena WASM contract. It does not change Idena
consensus, network ID, genesis, validation processing, or the legacy chain.

## What Nodes Verify

An activated P2PoolBTC node verifies all of the following:

1. The miner registration uses version 2 and contains `MinerRegistryAnchorV1`.
2. The contract address and experiment ID match the active policy.
3. The contract registration block is at or after policy activation.
4. The commitment recomputed from miner ID, Idena address, payout script, claim
   key, mining key, and experiment ID exactly matches the contract record.
5. `contract_readData` on the node's local Idena RPC returns the exact canonical
   append-only record.
6. For live admission, `dna_identity` reports the same address in state Newbie,
   Verified, or Human. Historical replay does not reapply current eligibility,
   so a later identity-state change cannot invalidate old accepted history.
7. Every version-3 work template contains a finalized Idena block height/hash.
8. Every version-3 work template commits to the complete normalized V2 anchor
   policy. Different deployment bytes, immutable parameters, finality,
   freshness, activation, handoff bit, experiment, or contract settings produce
   a different policy commitment and are rejected.
9. Live anchors are no older than `max_anchor_age_blocks`.
10. Before the immutable Bitcoin header-version handoff bit is set, bootstrap
    branches contain at most one share for a miner and Idena anchor, and the
    anchor height strictly increases along the branch. A miner-selected target
    cannot disable this rule.

The canonical contract record is:

```text
1|miner_id|registration_commitment|sequence|Idena_block|Idena_epoch|Idena_timestamp
```

The storage key is:

```text
miner:<lowercase-Idena-address-without-0x>:<sequence>
```

## Security Boundary

This design prevents a miner from claiming work before the miner's public
contract registration. It also prevents arbitrary anchor reuse, policy
substitution, block-hash substitution, and live submission with stale anchors.

It does not prove when every historical share was first disclosed. A miner who
registered earlier can still withhold work and later offer a fabricated
historical branch during historical synchronization. The target-independent
one-share-per-anchor rule bounds the fabrication rate, but the bound grows with
elapsed Idena blocks. `max_anchor_age_blocks` limits live admission only; it is
not a permanent-data-availability proof.

Before it creates a registration, the ownerless contract reads the caller's
current identity through the pinned runtime's `create_get_identity_promise`
API. The protected callback parses only protobuf field 4 from `RawIdentity`
and accepts exactly Newbie, Verified, or Human. It ignores birthday,
generation, age, and validation history. An unavailable, malformed, or
ineligible result creates no registration and refunds the attached registration
payment; normal Idena transaction fees are not refundable.

The contract also repeats that live identity check for every checkpoint vote.
An identity that became ineligible after registration cannot add support or
finalize a checkpoint. The ownerless contract supports periodic two-thirds checkpoint rounds.
Every finalized record publishes the exact share tip, height, cumulative score,
parent checkpoint, registered set, supporter set, and Idena finalization data.
P2Pool replay requires the record to match local contract state and requires
the checkpoint tip to descend from the prior checkpoint. A higher-score branch
outside that ancestry remains stored for audit but cannot become active or
receive payouts.

Do not describe this as instant publication proof. A registered miner can still
withhold work between checkpoints. The checkpoint denominator is the immutable
set of registrations, while every new vote requires current eligibility.
Eligible identity farming, abandoned registrations, or identities that later
become ineligible can therefore stall the two-thirds threshold. They cannot
contribute a vote after becoming ineligible, but the ownerless v0.3 contract
has no administrator or subjective ejection path that can remove them. The
48-miner cap, registration burn, exact voter lists, and six-Idena-block interval
bound the experiment; they do not remove this liveness risk.

Other residual risks:

- Idena identity farming is reduced by live eligibility checks, not eliminated.
- The contract does not assess miner software, hash rate, or Bitcoin validity.
- Idena reorganization risk is controlled by confirmations, not removed.
- Every participant must verify the same policy commitment before activation.
- Registering and rotating burns real IDNA. Contract calls and addresses are
  public and permanent.

Never place an Idena node key, wallet backup, password, Bitcoin private key,
RPC cookie, or API key in a contract argument, policy file, issue, or repository.

## Build From Source

Use the exact reviewed repository revision. The contract locks Node.js 24 and
pnpm through `package.json` and `pnpm-lock.yaml`.

```sh
git rev-parse HEAD
node --version
corepack pnpm --version
corepack pnpm --dir contracts/idena-pohw-miner-registry install --frozen-lockfile
corepack pnpm --dir contracts/idena-pohw-miner-registry build
corepack pnpm --dir contracts/idena-pohw-miner-registry test
shasum -a 256 contracts/idena-pohw-miner-registry/build/idena-pohw-miner-registry.wasm

PYTHONDONTWRITEBYTECODE=1 python3 scripts/pohw-miner-registry-runtime-gate.py \
  --idena-go /path/to/exact/idena-go-worktree
```

The runtime gate verifies every source digest, artifact size, SHA-256, raw CID,
runtime test digest, Go toolchain, and exact `idena-wasm-binding` revision in
[`compatibility/experiment-1-miner-registry-candidate.json`](../compatibility/experiment-1-miner-registry-candidate.json),
then runs registration and checkpoint identity transitions through idena-go's
production WASM engine. Independent builders should compare the WASM SHA-256
and raw CID before anyone proposes a deployment. One local passing build is not
independent release evidence. The build output is:

```text
contracts/idena-pohw-miner-registry/build/idena-pohw-miner-registry.wasm
```

## Deployment Review

Deployment is deliberately not automated here because it creates permanent
public state and burns real IDNA. Before an explicit deployment decision:

1. Compare at least two independently built WASM SHA-256 digests and raw CIDs
   against the exact candidate manifest.
2. Review the exact immutable experiment ID, ecosystem CID, and burn amount.
3. Confirm the Idena wallet is on the intended live chain.
4. Deploy through a reviewed Idena contract interface using export `deploy`
   with exactly three UTF-8 arguments:

```text
<experiment-id>
<lowercase-CIDv1-base32-ecosystem-CID>
<minimum-registration-burn-in-atomic-IDNA>
```

5. Read `contractParameters` from at least two independently operated Idena
   nodes. Require schema `3`, contract version `0.3.0`, the exact eligibility
   list, promise gas limits, and all immutable values to match the candidate.
6. Record the contract address and deployment block. Do not enable P2Pool policy
   at the deployment block; choose a later public activation height.

There is no post-deployment correction key. A deployment with wrong parameters
must be abandoned and replaced by a new contract plus a new explicit policy.

## Create And Compare A Policy

Create one reviewed `IdenaAnchorPolicyV2` file only after deployment. The
template below is intentionally not valid JSON: every angle-bracket value must
be replaced with independently verified public evidence before it can be used.

```json
{
  "schema_version": 2,
  "experiment_id": "p2poolbtc-experiment-1",
  "registry_contract_address": "0x<40-lowercase-hex>",
  "registry_deployment_tx_hash": "0x<64-lowercase-hex>",
  "registry_deployment_payload_sha256": "<64-lowercase-hex>",
  "registry_contract_code_hash": "<64-lowercase-hex>",
  "registry_contract_wasm_sha256": "<64-lowercase-hex>",
  "registry_ecosystem_cid": "<lowercase-cidv1-base32>",
  "minimum_registration_burn_atoms": "<positive-canonical-decimal>",
  "activation_idena_height": <finalized-height-after-deployment>,
  "finality_confirmations": 6,
  "max_anchor_age_blocks": 12,
  "handoff_version_bit": 27
}
```

The runtime rejects the zero address, noncanonical values, wrong deployment
payload, wrong inline WASM, wrong code hash, wrong deploy arguments, failed
receipt, nonfinalized deployment, and mismatching contract storage. Inspect the
real file with:

```sh
cargo run -p p2pool-node -- inspect-idena-anchor-policy \
  --policy-file /etc/pohw/idena-anchor-policy.json
```

Every participant must compare both the normalized JSON and the printed
`policy_commitment`. Version-3 work templates cryptographically bind this
commitment.

## Two-Phase Miner Registration

The contract receipt changes the ownership challenge. Do not sign the legacy
challenge first.

### 1. Generate local keys and the public commitment

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env \
  --idena-address 0xYOUR_PUBLIC_IDENA_ADDRESS \
  --registry-experiment-id p2poolbtc-experiment-1
```

The output status must be `needs_registry_transaction`. Keep the generated key
files private. Only `miner_id` and `registration_commitment` are contract call
arguments.

### 2. Register through Idena

From the same Idena identity, call:

```text
registerMiner(<miner_id>, <registration_commitment>)
```

Attach at least the immutable minimum burn. Wait for the public policy's
finality depth. The immediate method output says `pending: true`; that is not a
registration receipt. The protected callback must read the identity, burn the
payment, emit `PohwMinerRegisteredV1`, and create the append-only record in the
same transaction. Candidate, Invite, Suspended, Zombie, Killed, undefined,
missing, and malformed identities are rejected and refunded. Never provide a
node key, wallet key, payout script, or password to the contract.

If a callback runs out of gas or otherwise leaves a pending record, do not send
a second payment. Call `pendingRegistration()` first. The same identity may
call `cancelPendingRegistration()` to remove the reservation and schedule a
refund. Transaction fees remain spent.

### 3. Read the finalized receipt from a local Idena node

```sh
cargo run -p p2pool-node -- read-miner-registry-anchor \
  --contract-address 0xPUBLIC_CONTRACT_ADDRESS \
  --experiment-id p2poolbtc-experiment-1 \
  --idena-address 0xYOUR_PUBLIC_IDENA_ADDRESS \
  --miner-id YOUR_MINER_ID \
  --registration-sequence 1 \
  --idena-rpc-url http://127.0.0.1:9009 \
  --idena-api-key-file /path/to/private/idena-api.key \
  > miner-registry-anchor.json
```

The API-key file must be private. The resulting anchor JSON is public.

### 4. Generate and sign the anchored challenge

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env \
  --idena-address 0xYOUR_PUBLIC_IDENA_ADDRESS \
  --registry-experiment-id p2poolbtc-experiment-1 \
  --registry-anchor-file ./miner-registry-anchor.json
```

The status must be `needs_idena_signature`. Sign the exact
`idena_ownership_challenge` in Idena.

### 5. Publish the anchored registration

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env \
  --idena-address 0xYOUR_PUBLIC_IDENA_ADDRESS \
  --registry-experiment-id p2poolbtc-experiment-1 \
  --registry-anchor-file ./miner-registry-anchor.json \
  --idena-signature-hex 0xPUBLIC_SIGNATURE
```

The status must be `registration_ready`, `registration_version` must be `2`,
and `registry_anchor` must match the contract receipt.

## Periodic Sharechain Checkpoints

Checkpoint voting is a public Idena contract call. It burns no registration
payment, but normal Idena transaction fees and public metadata still apply.
Before voting, obtain the active replay tip, height, and cumulative score from
your local P2Pool node and compare them with at least one independent peer.

Call `voteCheckpoint` with exactly five UTF-8 arguments:

```text
<next-round>
<64-hex-share-tip>
<canonical-decimal-share-height>
<canonical-decimal-cumulative-score>
<previous-finalized-share-tip-or-64-zeroes-for-round-1>
```

The caller must already own a miner registration in this contract. The
immediate output says `pending: true`; the callback re-reads the caller's
current identity and records support only for Newbie, Verified, or Human. A
candidate finalizes automatically at `ceil(2 * registered_count / 3)` support.
A vote may move to another candidate before finalization; retrying the already
finalized candidate is idempotent. Rounds must be at least six Idena blocks
apart. A stranded vote can be cleared with `cancelPendingCheckpointVote()`;
clearing it never adds support.

After finality, reconstruct the exact public sharechain message through your
local Idena RPC:

```sh
cargo run -p p2pool-node -- read-sharechain-checkpoint \
  --contract-address 0xPUBLIC_CONTRACT_ADDRESS \
  --experiment-id p2poolbtc-experiment-1 \
  --round 1 \
  --idena-rpc-url http://127.0.0.1:9009 \
  --idena-api-key-file /path/to/private/idena-api.key \
  > sharechain-checkpoint-1.json
```

Publish that JSON as a normal signed gossip envelope. Receiving nodes fetch all
listed registrations and the checkpoint share ancestry first, verify the exact
contract record and finalized Idena block through local RPC, then apply it
atomically. Never hand-edit the checkpoint JSON.

## Activation

Activation is an explicit coordinated configuration change, not a contract
side effect. On every participant node:

```sh
POHW_ADMIT_PEER_WORK_TEMPLATES=true
POHW_IDENA_ANCHOR_POLICY=/etc/pohw/idena-anchor-policy.json
IDENA_RPC_URL=http://127.0.0.1:9009
IDENA_API_KEY_FILE=/path/to/private/idena-api.key
POHW_IDENA_RPC_ALLOW_REMOTE=false
```

The gossip mesh and mining adapter both fail closed if the policy is configured
without the API-key file. Remote Idena RPC is rejected unless separately and
explicitly enabled. Prefer a local synchronized node.

Do not activate until all existing miners have version-2 registrations and all
participants have compared the policy commitment. Legacy sharechain history is
not rewritten. After activation, new registrations, templates, and shares must
pass the ownerless registry and anchor policy.

## Rollback

Before public activation, rollback is simply leaving
`POHW_IDENA_ANCHOR_POLICY` blank. After participants have accepted version-3
history, unilateral rollback can split the network. Coordinate a new explicit
policy/profile instead. The contract remains public and immutable even if the
experiment stops using it.
