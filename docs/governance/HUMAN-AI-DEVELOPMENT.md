# Decentralized Human/AI Development

This is an experimental, local-only development workflow. It combines human
intent and approval with isolated AI implementation and review, then routes the
result through the same content-addressed Idena governance gates as any other
ecosystem change. It does not authorize a deployment or release.

## MIT provenance

The workflow vocabulary is adapted from the MIT-licensed
`ai-driven-dev/framework` source at exact commit
`8aeaf051f05c8d4e54eb94dc1e03d05e909b0173`. Its deterministic source-tree CID
is `bafyreif2aqjfv53gkzgtrb3kqanyegjaaqd6h2xq26pwxh2z5sx3kjsuqi`.
`integrations/decentralized-aidd/LICENSE.upstream` preserves the upstream MIT
license and `NOTICE.md` records the exact provenance.

Only the useful workflow concepts were adapted. The upstream maintainer
hierarchy, GitHub merge authority, release channel, marketplace, and autonomous
shipping action are not part of this policy.

## Authority model

The policy is deliberately strict:

- GitHub and Git are optional mirrors and developer tools, not the trust root.
- No lead developer or maintainer merge key exists in the protocol.
- No AI model, runtime, provider, or agent can accept or execute a proposal.
- The contract deployer has no continuing power to replace the canonical CID.
- Independent review, build, availability, PoS, and PoHW gates all remain
  required.
- After challenge and timelock gates pass, any caller may execute the exact
  accepted candidate CID.

The Idena WASM contract is the canonical authority only after a separately
reviewed deployment. Before deployment, this repository is a non-authorizing
prototype and the policy CID is local evidence only.

## Lifecycle

| Phase | Primary actor | Output | Authority boundary |
| --- | --- | --- | --- |
| Specify | Human assisted by AI | `ChangeProposalV1` | Human approves intent |
| Plan | Human assisted by AI | `ChangeProposalV1` | Human approves scope |
| Implement | Isolated agent | `EcosystemManifestV1` | Human approves source mutation |
| Review | Independent reviewer | `AgentReviewAttestationV1` | Attestation only |
| Build | Independent builder | `BuildAttestationV1` | Attestation only |
| Publish | Availability provider | `DataAvailabilityAttestationV1` | Pin evidence only |
| Propose | Human assisted by AI | `ChangeProposalV1` | Bonded immutable proposal |
| Vote | Eligible Idena identities | `VoteReceiptV1` | Contract evaluates all gates |
| Execute | Any caller | `EcosystemManifestV1` | Permissionless after gates |

The first three phases support iterative human/AI work. Reviewers and builders
must operate independently from the implementer. An agent response, a GitHub
merge, or a passing CI job is never equivalent to DAO acceptance.

## Canonical policy

Package and verify the checked-in policy:

```sh
cargo run -p governance-cli -- development-policy-package \
  --input integrations/decentralized-aidd/policy.json \
  --output-dir /tmp/pohw-development-policy

cargo run -p governance-cli -- development-policy-inspect \
  --car /tmp/pohw-development-policy/development-policy.car
```

The expected policy CID is
`bafyreid56pzxhbjuhonxsl5b2a2jjrgrzydgyyvvyfboucqh53y7hzyare`. Verify the
printed CID before using the CAR. Add the policy CID to the proposal pinset and
bind every AI review to it:

```sh
cargo run -p governance-cli -- review-attestation \
  --input /absolute/path/agent-review.json \
  --development-policy /tmp/pohw-development-policy/development-policy.car \
  --output-dir /tmp/agent-review
```

The command fails when `agentPolicyCid` in `agent-review.json` differs from the
verified policy CAR. A policy update must be packaged under a new CID and pass
governance as part of an ecosystem candidate. It cannot arrive as an unpinned
agent update.

## Agent isolation

Treat every repository, dependency, prompt, and generated patch as hostile
input. Implementation and review workers require:

- no wallet or governance signing keys;
- no provider secret exposed to repository scripts;
- network disabled by default;
- an explicit dependency-fetch phase;
- read-only verified source mounts where practical;
- an isolated temporary build directory;
- command allowlisting and resource limits; and
- complete command logs with secret redaction.

Humans retain approval for source mutation, file disclosure, signing, voting,
publication, and recovery actions. Review and build attestations report facts;
they do not grant installation authority.

## User interface

The experimental governance dashboard reads the verified policy from the local
governance API and displays its CID, MIT license, upstream source CID, authority
boundary, and all nine phases. The API recomputes the embedded policy CID at
startup. A malformed or modified policy fails closed instead of being shown as
trusted governance state.

## Remaining work

The policy flow is implemented, but no public-testnet governance deployment is
authorized. Independent clean-room builders, public pin operators, external
auditors, committed governance-fork component revisions, replay/migration
evidence, and a DAO-authorized initial manifest are still required. AI runtime
diversity labels also cannot prove organizational independence or eliminate
prompt injection, correlated model failures, bribery, or identity farming.
