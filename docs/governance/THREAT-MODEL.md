# Threat Model

The system protects an experimental canonical software reference. It does not
claim to make identities, AI, IPFS, software supply chains, or governance
trustless.

| Threat | Current mitigation | Residual risk |
| --- | --- | --- |
| Cheap identity farming | Eligible states, minimum stake, delayed activation, flip trust, breadth | Farms may mature and coordinate |
| AI-assisted identity farming | Same on-chain gates; no AI-specific privilege | Automation can lower farming cost |
| Stake splitting | Square-root weight plus eligibility, bonds, unbonding | Concavity can reward splitting across eligible identities |
| Whale capture | Sublinear stake, turnout, breadth, four gates | A whale with many identities or bribed voters remains powerful |
| Bribery | Public receipts, delays, broad gates | Private side payments cannot be prevented |
| Proposer spam | Bond, review delay, rejected fee, expiry slash | Wealthy attackers can still consume attention |
| Malicious CID | Local CID/multihash recomputation and schema validation | Valid content can still be malicious code |
| Unavailable CID | Multiple pins, expiry, bonds, old CID retention | CIDs do not guarantee persistence; global absence is hard to prove |
| Gateway substitution | HTTPS plus local CID and digest verification | Gateways can censor or correlate clients |
| Malicious pin provider | Independent providers and committed probes | Providers can collude or disappear later |
| Stale-base proposal | Parent CID snapshot and stale settlement | Rebase effort and proposal churn remain |
| Dependency confusion | Exact locks, explicit fetch phase, no network during build | Compromised upstream content pinned before discovery remains harmful |
| Typosquatting | Exact package names, locks, SBOM, dependency audit | Reviewer error remains possible |
| Prompt injection | Hostile-input policy, read-only source, command allowlist | Model behavior can still be manipulated |
| Compromised AI provider | Family/runtime and owner diversity | Providers may share infrastructure or training failures |
| Duplicate AI agents | Owner identity and family deduplication | Hidden common control is difficult to prove |
| Forged build attestation | Authentication, bond, source binding, raw-result CID challenge | Key compromise can produce valid-looking fraud not captured by the implemented predicates |
| Withheld adverse evidence | Permissionless fixed review window; any caller freezes roots derived from every registered CID | Review discovery or network access can be censored; unsubmitted evidence is not knowable on-chain |
| Review-set saturation | Each entry is bonded and duplicate CID/owner constraints apply | The 256-entry class cap can be exhausted before honest late submissions |
| Tampered legacy metrics index | Canonical-height checks, exact replay commitment, and three distinct eligible operator attestations; conflicting quorums fail closed | Legacy block hashes do not commit author/outcome mappings, so correlated or colluding operators remain an oracle |
| Non-reproducible build | Multiple builders and digest matching | Platform installers can retain nondeterminism |
| Malicious updater metadata | DAO-authorized ReleaseManifest, CID and SHA checks, anti-downgrade | OS signing channels remain centralized |
| Contract arithmetic or ABI bug | Integer-only math, checked operations, vectors, emulator, and exact-artifact production `WasmVM` differential/gas gate | The smoke gate is not a formal proof, exhaustive maximum-state gas analysis, cross-architecture run, or external audit |
| Slashing abuse | CID-recomputed exact false-result payloads only; no committee discretion | The intentionally narrow predicates leave other fraud classes unslashable |
| Governance apathy | Turnout quorum and expiry | Low participation can stall all changes |
| Low-quorum capture | 20/30 percent turnout plus breadth | Registered-weight denominator and inactivity can still be gamed |
| Simultaneous proposals | Atomic parent CID; obsolete parents become stale | Rebase churn and strategic proposal ordering remain |
| Consensus-fork incompatibility | Legacy lock unchanged; separate disabled fork profile | A future activation can still split peers if operational controls fail |
| Platform signing centralization | Explicitly documented external constraint | Apple and Microsoft can block distribution |

## Trust boundaries

The governance contract trusts the pinned Idena WASM host and chain execution.
It cannot fetch IPFS. Post-integration indexer roots and replay commitments are
deterministic over the exact records each operator observed, and source block
hashes detect reorgs, but legacy blocks do not authenticate the author/outcome
mapping itself. Roots need threshold operator agreement until a separately
activated consensus-maintained counter exists. Public IPFS is isolated from
Idena's private swarm. GitHub is optional infrastructure, not canonical
authority.

There is no lead developer bypass, maintainer merge key, permanent signer
group, emergency installer, or AI execution authority. A bug in the contract
still matters, so this vertical slice is local-test only pending an external
contract, runtime, and economic review.
