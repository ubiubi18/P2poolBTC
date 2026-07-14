# Source-First Onboarding Trust Model

The community onboarding path removes the single-developer binary and release
signature from the trust root. It does not replace that key with another
permanent maintainer key.

## Local Verification Chain

`pohw-community-join.sh` and `pohw-community-join.ps1` perform this sequence:

1. Require a clean committed Git worktree with no ignored files or directories.
2. Create a private one-run Cargo target directory, remove common build
   injection environment variables, and build `p2pool-node` and `pohw-agent`
   locally with `cargo --locked`.
3. Have `pohw-agent` independently package the normalized source tree using
   the governance source packager, requiring exact equality between tracked
   files and packaged files.
4. Record the CIDv1/SHA2-256 source CID, source-manifest SHA-256, Git commit
   metadata, `Cargo.lock` digest, a deterministic CycloneDX 1.5 dependency
   SBOM digest, compiler versions, and local binary digest.
5. Copy the tracked activation manifest into the private agent datadir without
   replacing a different existing file.
6. Treat all supplied network endpoints as transport hints.
7. Require both running executables to resolve inside the declared fresh build
   root.
8. Before fork sync or mining, query fork RPC and require the exact local
   activation ID.
9. Before mining, derive the snapshot ID, root, height, voter count, and miner
   eligibility from a verified local snapshot plus signed sharechain votes;
   repeat the check immediately before Stratum starts.
10. Start only loopback services, unless the user explicitly opts into private
   LAN peers.

The resulting `pohw-source-join/v1` receipt is described by
[`schemas/pohw-source-join-v1.schema.json`](../schemas/pohw-source-join-v1.schema.json).
It has no authorization or signer field.

## Why A Source Build Is Better But Not Sufficient

Building locally prevents a release operator from silently substituting a
binary that does not correspond to visible source. A deterministic source CID
also gives participants a stronger comparison value than a Git commit alone.

It does not prove that the selected source is safe, reviewed, or governed. A
malicious source tree can compile a malicious binary, a compromised compiler
can alter output, and a single mirror can censor updates. Participants should:

- compare the source CID through several independently operated channels;
- review changes or rely on several independent reviews;
- use clean toolchains and compare local artifact digests where reproducibility
  permits;
- obtain peer hints from more than one participant;
- stop when source CIDs, activation IDs, or replay roots disagree.

The planned DAO canonical ecosystem CID, independent build attestations, and
public-IPFS availability attestations address source selection and release
authorization. They are not yet deployed authority for Experiment 0, so the
current source CID is selected socially. Repository ownership is not a vote.

## Peer And Activation Boundary

Peer addresses can change without changing the experiment. The activation
manifest cannot. A malicious peer may refuse service, delay synchronization,
or attempt to isolate a participant, but its blocks and status must still pass
the activation-bound local validation.

The first run defaults to registration mode and starts only gossip. Fork sync
requires at least one reachable fork RPC with the matching activation and one
fork P2P endpoint. Mining additionally requires a structurally verified,
non-stale Idena snapshot, a configured distinct signed-voter quorum, and an
eligible registered identity in that snapshot. The source-first path never
enables the Bitcoin-mainnet handoff.

## Local Secrets

The agent binds the wizard to loopback, validates `Host` and CSRF tokens, uses a
one-time Idena callback state, and stores local key material and Stratum
credentials with private permissions. It passes the Idena signature through a
bounded child-process stdin pipe rather than process arguments or a temporary
signature file. Persisted registration state is revalidated against its signed
envelope, local sharechain replay, and protected local public keys on restart.

The Idena private key remains in Idena Web or Desktop. Only the public address,
challenge, and returned signature enter P2poolBTC. Stop the agent with `Ctrl-C`
to stop all children it launched. Unix signal handling and Windows console
control handling both trigger child cleanup; unsupported platforms fail closed.

## Current Limitations

- The source build is reproducible at the source-CID level; native Rust binary
  byte-for-byte reproducibility is not yet guaranteed across hosts.
- The generated CycloneDX SBOM covers locked Cargo packages and dependency
  relationships. It is not a whole-host or operating-system package inventory.
- Signed snapshot-vote quorum is an attestation layer, not an Idena light-client
  proof. Participants should independently compare the snapshot to Idena chain
  data and use multiple snapshot sources.
- Initial source-CID selection is social until DAO governance is deployed.
- The wizard is process-scoped and does not install an unattended service.
- Windows console cleanup is implemented but still needs broader hardware and
  shell testing; browser-opening behavior also varies by host policy.
- A single matching fork peer still leaves eclipse risk; use several peers.
- No public production bootstrap endpoint is embedded in the source.
