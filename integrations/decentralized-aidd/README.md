# Decentralized human/AI development policy

This integration adapts the useful `specify -> plan -> implement -> review`
workflow vocabulary from the MIT-licensed AI-Driven Dev framework, then
continues through independent builds, public availability, an Idena vote, and
permissionless execution.

It does not install the upstream marketplace and does not grant authority to
GitHub, a maintainer, an AI provider, an agent, or the contract deployer.

Package and inspect the canonical policy:

```sh
cargo run -p governance-cli -- development-policy-package \
  --input integrations/decentralized-aidd/policy.json \
  --output-dir /tmp/pohw-development-policy

cargo run -p governance-cli -- development-policy-inspect \
  --car /tmp/pohw-development-policy/development-policy.car
```

Every AI reviewer must put the resulting policy CID in
`AgentReviewAttestationV1.agentPolicyCid`. The policy CID must also be included
in the proposal pinset. A policy update is therefore a normal content-addressed
ecosystem proposal, not a silent marketplace update.

Repository content remains hostile input. Implementers and reviewers run in
separate sandboxes without wallet keys, with network disabled by default and
with complete redacted command logs. AI output can propose or attest; it cannot
accept or execute a proposal.
