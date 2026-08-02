import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Bitcoin,
  Brain,
  Blocks,
  CheckCircle2,
  CircleHelp,
  Clock3,
  Copy,
  Cpu,
  Database,
  Gauge,
  GitBranch,
  HardDrive,
  KeyRound,
  Network,
  Percent,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Wallet
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  SATS_PER_BTC,
  acceptedSharePercent,
  calculateRewardView,
  chancePercentForDays,
  expectedBlocksForChancePercent
} from "./miningEconomics";
import type { ProspectMode, RewardView } from "./miningEconomics";
import "./styles.css";

type ServiceState = "connected" | "syncing" | "pending" | "warning";
type TimeWindow = "24h" | "7d" | "epoch";
type SectionId = "overview" | "sharechain" | "idena" | "payouts" | "vault" | "next-step" | "audit-numbers";
type AppView = "dashboard" | "explorer" | "governance";
type ExplorerTab = "overview" | "bitcoin" | "fork" | "sharechain" | "idena";
type ExplorerLoadState = "loading" | "ready" | "unavailable";

const README_CAPTURE_MODE = new URLSearchParams(window.location.search).get("capture") === "final";
const CAPTURE_MASK = "[masked]";

interface ServiceStatus {
  label: string;
  state: ServiceState;
  detail: string;
}

interface SharePoint {
  label: string;
  accepted: number;
  stale: number;
}

interface ShareWindow {
  acceptedShares: number;
  staleShares: number;
  poolAcceptedShares: number;
  poolStaleShares: number;
  userHashrateThs: number;
  poolHashrateThs: number;
  measurementSeconds: number;
  userMeasurementSeconds?: number;
  poolMeasurementSeconds?: number;
  recentShares: SharePoint[];
}

interface PoolSnapshot {
  identity: {
    idenaAddress: string;
    pledgeDetail: string;
    pledgeStatus: "pending" | "verified";
    status: "Human" | "Verified" | "Newbie" | "Unknown";
    snapshotHeight: number;
    snapshotDay: string;
    snapshotRoot: string;
  };
  sharechain: {
    acceptedShares: number;
    staleShares: number;
    poolAcceptedShares?: number;
    poolStaleShares?: number;
    hashrateScore: number;
    poolHashrateScore: number;
    poolHashrateThs: number;
    userHashrateThs: number;
    relativeHashrateShare: number;
    recentShares: SharePoint[];
    windows?: Record<TimeWindow, ShareWindow>;
  };
  idenaAccounting: {
    validationScore: number;
    proposerCommitteeScore: number;
    invitationScoreIgnored: number;
    poolEligibleScore: number;
    relativeIdenaShare: number;
    formula: string;
    source: string;
  };
  payout: {
    combinedRewardWeight: number;
    blockSubsidyBtc: number;
    estimatedFeesBtc: number;
    directPayoutEligible: boolean;
    directRank: number;
    directLimit: number;
    nextDirectThresholdSats: number;
    coinbaseOutputBudgetVb: number;
    directFeeBasisSatVb: number;
    vaultClaimSats: number;
    estimatedWithdrawalFeeSats: number | null;
    minPayoutSats: number;
    blockRewardSource?: string;
  };
  pool: {
    expectedBlockInterval: string;
    chance30d: number;
    expectedBlocks30d?: number;
    bitcoinNetworkHashrateEhs: number;
    vaultEpoch: string;
    frostThreshold: string;
    signerCount: number;
    thresholdCount: number;
    pendingWithdrawals: number;
    lastVaultRotation: string;
    vaultKey: string;
    activeNodes: number;
    miningEstimateSource?: string;
  };
}

interface DashboardApiResponse {
  generatedAtUnix: number | null;
  source: string;
  serviceStatuses: ServiceStatus[];
  account: PoolSnapshot;
}

interface GovernanceDashboardResponse {
  apiVersion: string;
  schemaVersion: number;
  experimental: boolean;
  status: "unconfigured" | "operator-validated-local-snapshot";
  safetyLabel: string;
  governanceContractAddress: string | null;
  currentCanonicalEcosystemCid: string | null;
  developmentPolicyCid: string | null;
  developmentPolicy: DevelopmentPolicy | null;
  identityMetrics: {
    metricsRoot: string;
    sourceEpoch: number;
    replayCommitment: string;
    independentAttestors: number;
    requiredAttestors: number;
    conflict: boolean;
    certified: boolean;
  } | null;
  communityActivation: {
    active: boolean;
    participantCount: number;
    participantThreshold: number;
    participantDefinition: "eligible-current-metrics-and-minimum-active-stake";
    permissionlessActivation: true;
    automaticDeployment: false;
    activationBlock: number | null;
  };
  repositories: Array<{
    name: string;
    sourceTreeCid: string;
  }>;
  proposals: GovernanceProposal[];
  epochGovernance?: GovernanceEpochView | null;
  canonicalHistory?: GovernanceCanonicalExecution[];
  recovery?: GovernanceRecoveryView | null;
}

interface DevelopmentPolicy {
  schemaVersion: number;
  kind: "pohw-decentralized-human-ai-development-policy-v1";
  policyId: string;
  ecosystemId: string;
  licenseSpdx: "MIT";
  upstream: Array<{
    repositoryUrl: string;
    commit: string;
    sourceTreeCid: string;
    licenseSpdx: "MIT";
  }>;
  authority: {
    canonicalAuthority: "idena-wasm-governance-contract";
    githubIsCanonical: false;
    maintainerMergeKeyExists: false;
    agentMayAcceptProposal: false;
    agentMayExecuteProposal: false;
    contractOwnerMayReplaceCanonicalCid: false;
    acceptedExecutionIsPermissionless: true;
  };
  sandbox: {
    networkDisabledByDefault: true;
    walletKeysExposed: false;
    providerSecretsExposedToRepositoryScripts: false;
    readOnlySourceMount: true;
    isolatedTemporaryBuildDirectory: true;
    explicitDependencyFetchPhase: true;
    commandAllowlisting: true;
    resourceLimitsRequired: true;
    completeRedactedCommandLog: true;
  };
  phases: Array<{
    id: "specify" | "plan" | "implement" | "review" | "build" | "publish" | "propose" | "vote" | "execute";
    actor: "human-ai" | "isolated-agent" | "independent-reviewer" | "independent-builder" | "availability-provider" | "eligible-identities" | "any-caller";
    humanApprovalRequired: boolean;
    mutatesCandidateSource: boolean;
    outputSchema: string;
  }>;
}

type GovernanceEpochPhase =
  | "ProposalSubmission"
  | "FrozenReview"
  | "VotingCommit"
  | "VotingReveal"
  | "Finalization"
  | "Grace"
  | "Execution"
  | "Closed";

interface GovernanceEpochView {
  governanceEpoch: number;
  currentBlock: number;
  phase: GovernanceEpochPhase;
  schedule: {
    epochAnchorBlock: number;
    proposalCutoffBlock: number;
    commitStartBlock: number;
    commitEndBlock: number;
    revealEndBlock: number;
  };
  frozenProposalSetRoot: string | null;
  orderedProposalIds: string[];
  frozenAtBlock: number | null;
  reviewedProposals: number;
  unresolvedProposals: number;
  validAgentAttestations: number;
  committedBallots: number;
  revealedBallots: number;
  votingPowerSnapshotReady: boolean;
  graceEndBlock: number | null;
  openChallenges: number;
  executionReadyProposals: number;
}

interface GovernanceCanonicalExecution {
  executionId: string;
  previousCanonicalEcosystemCid: string;
  newCanonicalEcosystemCid: string;
  proposalId: string;
  governanceEpoch: number;
  decisionRecordCid: string;
  executionBlock: number;
  rollbackManifestCid: string;
  releaseRollbackInstructionsCid: string;
  observationWindowEndBlock: number;
  revertsExecutionId: string | null;
}

interface GovernanceRecoveryView {
  chainRpcAvailable: boolean;
  localLastKnownGoodStaged: boolean;
  stagedEcosystemCid: string | null;
  recoveryManifestCid: string | null;
  explicitUserConfirmationRequired: boolean;
  automaticInstallEnabled: boolean;
  automaticRollbackEnabled: boolean;
  onChainRevertAvailable: boolean;
  warning: string;
}

interface GovernanceProposal {
  proposalId: string;
  proposalCid: string;
  scopeEvidenceCid: string;
  scopeEvidenceVerified: boolean;
  parentCanonicalEcosystemCid?: string | null;
  candidateEcosystemCid: string;
  patchCid?: string | null;
  proposerAddress?: string | null;
  parameterSetCid: string;
  reviewRoundId: string;
  reviewRoundState: "Open" | "Frozen" | "Claimed" | "Expired";
  reviewRoundAgentAttestations: number;
  reviewRoundBuildAttestations: number;
  reviewRoundAvailabilityAttestations: number;
  affectedRepositories: string[];
  changedFileCount: number;
  patchBytes: number;
  sourcePackageBytes: number;
  descriptionBytes: number;
  migrationOperationCount: number;
  diffSummary: string;
  riskClass: "normal" | "critical" | "consensus" | "migration";
  bondAtoms: string;
  agentReviewRoot: string;
  buildAttestationRoot: string;
  dataAvailabilityRoot: string;
  criticalFindingWaiverCid?: string | null;
  reviewRoundCriticalFindingWaiverCid?: string | null;
  criticalFindingWaiver?: {
    schemaVersion: number;
    reviewRoundId: string;
    parentEcosystemCid: string;
    candidateEcosystemCid: string;
    patchCid: string;
    riskClass: "critical" | "consensus" | "migration";
    agentReviewRoot: string;
    unresolvedCriticalOwnerCount: number;
    scope: string;
    rationaleCid: string;
    authorIdenaAddress: string;
    creationBlock: number;
  } | null;
  aiReviews: {
    validAttestations: number;
    requiredAttestations: number;
    distinctRuntimeGroups: number;
    requiredRuntimeGroups: number;
    distinctModelFamilies: number;
    requiredModelFamilies: number;
    distinctOwnerIdentities: number;
    requiredOwnerIdentities: number;
    unresolvedCriticalFindings: number;
    passed: boolean;
  };
  builds: {
    independentBuilders: number;
    requiredBuilders: number;
    distinctPlatforms: number;
    requiredPlatforms: number;
    matchingCoreArtifactDigests: boolean;
    passed: boolean;
  };
  dataAvailability: {
    independentAttestors: number;
    requiredAttestors: number;
    validUntilBlock: number;
    requiredValidUntilBlock: number;
    passed: boolean;
  };
  pos: {
    yesWeight: string;
    noWeight: string;
    abstainWeight: string;
    snapshottedRegisteredWeight: string;
    turnoutQuorumBps: number;
    yesThresholdBps: number;
    passed: boolean;
  };
  pohw: {
    distinctParticipatingIdentities: number;
    requiredParticipatingIdentities: number;
    distinctYesIdentities: number;
    requiredYesIdentities: number;
    verifiedOrHumanYesIdentities: number;
    requiredVerifiedOrHumanYes: number;
    passed: boolean;
  };
  challengeStatus: string;
  executionStatus: string;
  state: string;
}

interface ForkChainStatus {
  protocolVersion: number;
  chainName: string;
  activationId: string;
  inheritedTipHeight: number;
  inheritedTipHash: string;
  tipHeight: number;
  tipHash: string;
  cumulativeWork: string;
  storedBlockCount: number;
  activeForkBlockCount: number;
  postForkPowLimitBits: string;
  targetSpacingSeconds: number;
  difficultyAlgorithm: string;
  difficultyPhase: string;
  bootstrapHandoffHashrateHps: number;
  estimatedHashrateHps: string;
  blocksUntilBitcoinRetarget: number | null;
  transactionConsensus: string;
}

interface ExplorerOverview {
  apiVersion: string;
  generatedAtUnix: number;
  fork: {
    state: string;
    status: ForkChainStatus | null;
    addressIndex: {
      state: string;
      coverage: string;
      firstIndexedHeight: number | null;
      indexedTipHeight: number | null;
      indexedBlockCount: number | null;
      transactionCount: number | null;
      outputCount: number | null;
      addressCount: number | null;
      maxBlocks: number | null;
      maxTransactions: number | null;
      maxOutputs: number | null;
      maxAddresses: number | null;
      accountedRetainedBytes: number | null;
      maxRetainedBytes: number | null;
      workUnits: number | null;
      maxWorkUnits: number | null;
      maxBlockBytes: number | null;
      maxScriptBytes: number | null;
    };
  };
  bitcoinHistory: {
    state: string;
    backend: string;
    indexedTipHeight: number | null;
    inheritedTipHeight: number | null;
    inheritedHistoryReady: boolean;
    hostOnly: boolean;
    participantIndexRequired: boolean;
  };
  sharechain: {
    appliedMessageCount: number;
    registeredMinerCount: number;
    uniqueRegisteredIdenaCount: number;
    activeIdenaParticipantCount: number;
    eligibleActiveIdenaParticipantCount: number | null;
    mainnetHandoffParticipantCount: number | null;
    mainnetHandoffParticipantThreshold: number;
    snapshotVoterIdenaCount: number | null;
    mainnetHandoffSnapshotVoterThreshold: number;
    mainnetHandoffMaxSnapshotAgeDays: number;
    bitcoinWorkTemplateCount: number;
    storedShareCount: number;
    activeShareCount: number;
    inactiveShareCount: number;
    activeShareScoreTotal: string;
    bestShareTip: string | null;
    bestShareHeight: number | null;
    snapshotVoteRootCount: number;
    payoutScheduleCount: number;
    pendingWithdrawalCount: number;
  };
  idena: ExplorerIdenaOverview;
  limitations: string[];
  safetyBoundaries: string[];
}

interface ExplorerIdenaOverview {
  state: string;
  snapshotDay: string | null;
  snapshotHeight: number | null;
  scoreRoot: string | null;
  identityRoot: string | null;
  formulaVersion: number | null;
  identityCount: number;
  eligibleIdentityCount: number;
  validationScoreTotal: string;
  proposerScoreTotal: string;
  committeeScoreTotal: string;
  ignoredInvitationScoreTotal: string;
  rewardSourceCoverage: string;
}

interface ForkBlockSummary {
  blockHash: string;
  previousBlockHash: string;
  height: number;
  active: boolean;
  timestamp: number;
  bits: string;
  difficultyPhase: string;
  cumulativeWork: string;
  version: number;
  nonce: number;
  merkleRoot: string;
  transactionCount: number;
  sizeBytes: number;
  weightWu: number;
  coinbaseTxid: string;
  coinbaseValueSats: number;
  coinbaseOutputCount: number;
  pohwCommitmentHash: string | null;
}

interface ExplorerForkBlockPage {
  state: string;
  tipHeight: number | null;
  total: number;
  items: ForkBlockSummary[];
  nextCursor: string | null;
}

interface ForkPreviousOutput {
  valueSats: number;
  scriptPubkeyHex: string;
  scriptPubkeyAsm: string;
  scriptType: string;
  address: string | null;
  scriptHash: string;
}

interface ForkTransactionDetail {
  txid: string;
  wtxid: string;
  blockHash: string;
  height: number;
  active: boolean;
  transactionIndex: number;
  coinbase: boolean;
  version: number;
  lockTime: number;
  sizeBytes: number;
  weightWu: number;
  inputCount: number;
  outputCount: number;
  totalInputSats: number | null;
  totalOutputSats: number;
  feeSats: number | null;
  spendStateComplete: boolean;
  inputs: Array<{
    vin: number;
    coinbase: boolean;
    previousTxid: string | null;
    previousVout: number | null;
    scriptSigHex: string;
    scriptSigAsm: string;
    sequence: number;
    witness: string[];
    previousOutput: ForkPreviousOutput | null;
  }>;
  outputs: Array<ForkPreviousOutput & {
    vout: number;
    spentBy: { txid: string; vin: number; height: number } | null;
  }>;
}

interface ForkTransactionRef {
  txid: string;
  blockHash: string;
  height: number;
  active: boolean;
  transactionIndex: number;
  coinbase: boolean;
  totalOutputSats: number;
  feeSats: number | null;
}

interface ForkTransactionPage {
  blockHash: string;
  total: number;
  items: ForkTransactionRef[];
  nextCursor: number | null;
}

interface ForkAddressSummary {
  address: string;
  transactionCount: number;
  fundedOutputCount: number;
  fundedTotalSats: number;
  spentOutputCount: number;
  spentTotalSats: number;
  inheritedInputCount: number;
  inheritedInputTotalSats: number;
  balanceSats: number;
  balanceScope: string;
  firstSeenHeight: number | null;
  lastSeenHeight: number | null;
}

interface ForkAddressTransactionPage {
  address: string;
  total: number;
  items: ForkTransactionRef[];
  nextCursor: number | null;
}

interface ForkUtxo {
  txid: string;
  vout: number;
  valueSats: number;
  scriptPubkeyHex: string;
  scriptType: string;
  height: number;
  coinbase: boolean;
}

interface ForkUtxoPage {
  address: string;
  total: number;
  items: ForkUtxo[];
  nextCursor: number | null;
}

interface BitcoinIndexObject<T = Record<string, unknown>> {
  scope: string;
  forkRelation: string;
  data: T;
}

interface BitcoinBlockData {
  id: string;
  height: number;
  version: number;
  timestamp: number;
  bits: number;
  nonce: number;
  merkle_root: string;
  tx_count: number;
  size: number;
  weight: number;
  previousblockhash?: string;
}

interface BitcoinTransactionData {
  txid: string;
  version: number;
  locktime: number;
  size: number;
  weight: number;
  fee: number;
  vin: Array<{
    txid?: string;
    vout?: number;
    prevout?: {
      scriptpubkey: string;
      scriptpubkey_asm: string;
      scriptpubkey_type: string;
      scriptpubkey_address?: string;
      value: number;
    } | null;
    scriptsig: string;
    scriptsig_asm: string;
    witness?: string[];
    is_coinbase: boolean;
    sequence: number;
  }>;
  vout: Array<{
    scriptpubkey: string;
    scriptpubkey_asm: string;
    scriptpubkey_type: string;
    scriptpubkey_address?: string;
    value: number;
  }>;
  status: {
    confirmed: boolean;
    block_height?: number;
    block_hash?: string;
    block_time?: number;
  };
}

interface BitcoinAddressData {
  address: string;
  chain_stats: {
    tx_count: number;
    funded_txo_count: number;
    funded_txo_sum: number;
    spent_txo_count: number;
    spent_txo_sum: number;
  };
  mempool_stats: {
    tx_count: number;
    funded_txo_count: number;
    funded_txo_sum: number;
    spent_txo_count: number;
    spent_txo_sum: number;
  };
}

interface ExplorerBitcoinBlockPage {
  scope: string;
  items: Array<BitcoinIndexObject<BitcoinBlockData>>;
}

interface ExplorerBitcoinBlockTransactionPage {
  scope: string;
  blockHash: string;
  startIndex: number;
  totalInPage: number;
  items: Array<BitcoinIndexObject<BitcoinTransactionData>>;
  nextCursor: number | null;
}

interface BitcoinOutspend {
  spent: boolean;
  txid?: string;
  vin?: number;
  status?: BitcoinTransactionData["status"];
}

interface ExplorerBitcoinOutspendPage {
  scope: string;
  txid: string;
  items: BitcoinOutspend[];
}

interface ExplorerBitcoinTransactionPage {
  scope: string;
  address: string;
  totalInPage: number;
  items: Array<BitcoinIndexObject<BitcoinTransactionData>>;
  nextCursor: string | null;
}

interface BitcoinUtxo {
  txid: string;
  vout: number;
  status: BitcoinTransactionData["status"];
  value: number;
}

interface SharechainShareSummary {
  shareHash: string;
  height: number;
  active: boolean;
  minerId: string;
  parentShareHash: string;
  bitcoinTemplateHash: string;
  workHash: string;
  target: string;
  hashrateScoreDelta: string;
  cumulativeScore: string | null;
  idenaSnapshotId: string;
  idenaSnapshotProofRoot: string;
  templateCreatedAtUnix: number | null;
}

interface ExplorerSharePage {
  total: number;
  items: SharechainShareSummary[];
  nextCursor: string | null;
}

type ExplorerSearchResult =
  | { kind: "block"; item: ForkBlockSummary; transactions: ForkTransactionPage | null }
  | { kind: "fork-transaction"; item: ForkTransactionDetail }
  | {
      kind: "bitcoin-block";
      item: BitcoinIndexObject<BitcoinBlockData>;
      transactions: ExplorerBitcoinBlockTransactionPage | null;
    }
  | {
      kind: "bitcoin-transaction";
      item: BitcoinIndexObject<BitcoinTransactionData>;
      outspends: ExplorerBitcoinOutspendPage | null;
    }
  | {
      kind: "address";
      address: string;
      fork: ForkAddressSummary | null;
      forkTransactions: ForkAddressTransactionPage | null;
      forkUtxos: ForkUtxoPage | null;
      bitcoin: BitcoinIndexObject<BitcoinAddressData> | null;
      bitcoinTransactions: ExplorerBitcoinTransactionPage | null;
      bitcoinUtxos: Array<BitcoinIndexObject<BitcoinUtxo>> | null;
    }
  | { kind: "share"; item: SharechainShareSummary };

type ExplorerLoadMoreTarget =
  | "fork-block-transactions"
  | "bitcoin-block-transactions"
  | "fork-address-transactions"
  | "fork-address-utxos"
  | "bitcoin-address-transactions";

interface RuntimeDashboardConfig {
  apiToken?: string;
  apiUrl?: string;
  demo?: string;
  explorerApiBase?: string;
  defaultView?: AppView;
  participantDashboard?: boolean;
}

declare global {
  interface Window {
    __POHW_DASHBOARD_CONFIG__?: RuntimeDashboardConfig;
  }
}

const dashboardEnv =
  (import.meta as unknown as {
    env?: {
      VITE_POHW_DASHBOARD_API_URL?: string;
      VITE_POHW_DASHBOARD_DEMO?: string;
      VITE_POHW_EXPLORER_API_BASE?: string;
      VITE_POHW_DASHBOARD_DEFAULT_VIEW?: string;
      VITE_POHW_PARTICIPANT_DASHBOARD?: string;
    };
  }).env ?? {};
const runtimeDashboardConfig = window.__POHW_DASHBOARD_CONFIG__ ?? {};
const dashboardApiUrl =
  runtimeDashboardConfig.apiUrl ?? dashboardEnv.VITE_POHW_DASHBOARD_API_URL ?? "http://127.0.0.1:40407/dashboard.json";
const dashboardApiToken = runtimeDashboardConfig.apiToken?.trim() || undefined;
const dashboardDemoMode = ["1", "true", "yes"].includes(
  (runtimeDashboardConfig.demo ?? dashboardEnv.VITE_POHW_DASHBOARD_DEMO ?? "").toLowerCase()
);
const explorerApiBase = (
  runtimeDashboardConfig.explorerApiBase ??
  dashboardEnv.VITE_POHW_EXPLORER_API_BASE ??
  "http://127.0.0.1:40407/api/v1"
).replace(/\/$/, "");
const configuredDefaultView: AppView = (() => {
  const requested = runtimeDashboardConfig.defaultView ?? dashboardEnv.VITE_POHW_DASHBOARD_DEFAULT_VIEW;
  return requested === "explorer" || requested === "governance" ? requested : "dashboard";
})();
const participantDashboardEnabled =
  runtimeDashboardConfig.participantDashboard ??
  !["0", "false", "no"].includes((dashboardEnv.VITE_POHW_PARTICIPANT_DASHBOARD ?? "true").toLowerCase());
const explorerSharesDashboardOrigin = (() => {
  try {
    return new URL(explorerApiBase, globalThis.location.href).origin ===
      new URL(dashboardApiUrl, globalThis.location.href).origin;
  } catch {
    return false;
  }
})();

const fallbackServiceStatuses: ServiceStatus[] = [
  { label: "P2Pool", state: "connected", detail: "8 peers / tip 18,402" },
  { label: "Bitcoin", state: "syncing", detail: "Pi IBD running" },
  { label: "Idena", state: "syncing", detail: "local replay catching up" },
  { label: "Snapshot", state: "pending", detail: "gated until sync" }
];

const sampleSharePoints: SharePoint[] = [
  { label: "00", accepted: 18, stale: 1 },
  { label: "03", accepted: 24, stale: 0 },
  { label: "06", accepted: 31, stale: 2 },
  { label: "09", accepted: 28, stale: 0 },
  { label: "12", accepted: 36, stale: 1 },
  { label: "15", accepted: 39, stale: 0 },
  { label: "18", accepted: 41, stale: 1 },
  { label: "21", accepted: 34, stale: 0 }
];

const emptySharePoints: SharePoint[] = ["00", "03", "06", "09", "12", "15", "18", "21"].map(
  (label) => ({ label, accepted: 0, stale: 0 })
);

const sampleShareWindow: ShareWindow = {
  acceptedShares: 251,
  staleShares: 5,
  poolAcceptedShares: 64_830,
  poolStaleShares: 940,
  userHashrateThs: 5.19,
  poolHashrateThs: 1340,
  measurementSeconds: 7 * 24 * 60 * 60,
  userMeasurementSeconds: 7 * 24 * 60 * 60,
  poolMeasurementSeconds: 7 * 24 * 60 * 60,
  recentShares: sampleSharePoints
};

const emptyShareWindow: ShareWindow = {
  acceptedShares: 0,
  staleShares: 0,
  poolAcceptedShares: 0,
  poolStaleShares: 0,
  userHashrateThs: 0,
  poolHashrateThs: 0,
  measurementSeconds: 0,
  userMeasurementSeconds: 0,
  poolMeasurementSeconds: 0,
  recentShares: emptySharePoints
};

const fallbackAccount: PoolSnapshot = {
  identity: {
    idenaAddress: "0xc0Bc...3c9B",
    pledgeDetail: "local pledge script pending",
    pledgeStatus: "pending",
    status: "Human",
    snapshotHeight: 4_832_112,
    snapshotDay: "2026-06-29 UTC",
    snapshotRoot: "846a3923...2cdb7"
  },
  sharechain: {
    acceptedShares: 1284,
    staleShares: 17,
    poolAcceptedShares: 331_280,
    poolStaleShares: 4_270,
    hashrateScore: 920420,
    poolHashrateScore: 237_645_236,
    poolHashrateThs: 1340,
    userHashrateThs: 5.19,
    relativeHashrateShare: 0.003873,
    recentShares: sampleSharePoints,
    windows: {
      "24h": {
        ...sampleShareWindow,
        measurementSeconds: 24 * 60 * 60,
        userMeasurementSeconds: 24 * 60 * 60,
        poolMeasurementSeconds: 24 * 60 * 60
      },
      "7d": sampleShareWindow,
      epoch: {
        ...sampleShareWindow,
        measurementSeconds: 14 * 24 * 60 * 60,
        userMeasurementSeconds: 14 * 24 * 60 * 60,
        poolMeasurementSeconds: 14 * 24 * 60 * 60
      }
    }
  },
  idenaAccounting: {
    validationScore: 712300,
    proposerCommitteeScore: 291100,
    invitationScoreIgnored: 18400,
    poolEligibleScore: 243_057_910,
    relativeIdenaShare: 0.004127,
    formula: "validation + proposer + final committee",
    source: "local idena-go RPC replay"
  },
  payout: {
    combinedRewardWeight: 0.004,
    blockSubsidyBtc: 3.125,
    estimatedFeesBtc: 0,
    directPayoutEligible: true,
    directRank: 42,
    directLimit: 100,
    nextDirectThresholdSats: 214000,
    coinbaseOutputBudgetVb: 3100,
    directFeeBasisSatVb: 3,
    vaultClaimSats: 0,
    estimatedWithdrawalFeeSats: 96,
    minPayoutSats: 10000,
    blockRewardSource: "sample fork reward context"
  },
  pool: {
    expectedBlockInterval: "~9.7 years at current pool rate",
    chance30d: 0.84,
    expectedBlocks30d: 0.00843548,
    bitcoinNetworkHashrateEhs: 690,
    vaultEpoch: "2026-W27",
    frostThreshold: "67% of online epoch signers",
    signerCount: 13,
    thresholdCount: 9,
    pendingWithdrawals: 6,
    lastVaultRotation: "2026-06-24",
    vaultKey: "tr(frost...9a4c)",
    activeNodes: 19,
    miningEstimateSource: "sample 24h submitted share work"
  }
};

const offlineDashboardData: DashboardApiResponse = {
  generatedAtUnix: null,
  source: "local-api-offline",
  serviceStatuses: [
    { label: "P2Pool", state: "warning", detail: "local API offline" },
    { label: "Bitcoin", state: "pending", detail: "not queried" },
    { label: "Idena", state: "pending", detail: "not queried" },
    { label: "Snapshot", state: "pending", detail: "not available" }
  ],
  account: {
    identity: {
      idenaAddress: "not connected",
      pledgeDetail: "local API unavailable",
      pledgeStatus: "pending",
      status: "Unknown",
      snapshotHeight: 0,
      snapshotDay: "not available",
      snapshotRoot: "not available"
    },
    sharechain: {
      acceptedShares: 0,
      staleShares: 0,
      poolAcceptedShares: 0,
      poolStaleShares: 0,
      hashrateScore: 0,
      poolHashrateScore: 0,
      poolHashrateThs: 0,
      userHashrateThs: 0,
      relativeHashrateShare: 0,
      recentShares: emptySharePoints,
      windows: {
        "24h": emptyShareWindow,
        "7d": emptyShareWindow,
        epoch: emptyShareWindow
      }
    },
    idenaAccounting: {
      validationScore: 0,
      proposerCommitteeScore: 0,
      invitationScoreIgnored: 0,
      poolEligibleScore: 0,
      relativeIdenaShare: 0,
      formula: "local API unavailable",
      source: "offline"
    },
    payout: {
      combinedRewardWeight: 0,
      blockSubsidyBtc: 0,
      estimatedFeesBtc: 0,
      directPayoutEligible: false,
      directRank: 0,
      directLimit: 100,
      nextDirectThresholdSats: 10_000,
      coinbaseOutputBudgetVb: 3_100,
      directFeeBasisSatVb: 3,
      vaultClaimSats: 0,
      estimatedWithdrawalFeeSats: null,
      minPayoutSats: 10_000,
      blockRewardSource: "fork explorer unavailable"
    },
    pool: {
      expectedBlockInterval: "local API offline",
      chance30d: 0,
      expectedBlocks30d: 0,
      bitcoinNetworkHashrateEhs: 0,
      vaultEpoch: "not available",
      frostThreshold: "not available",
      signerCount: 0,
      thresholdCount: 0,
      pendingWithdrawals: 0,
      lastVaultRotation: "not available",
      vaultKey: "not available",
      activeNodes: 0,
      miningEstimateSource: "fork explorer unavailable"
    }
  }
};

const dashboardAuthRequiredData: DashboardApiResponse = {
  ...offlineDashboardData,
  source: "dashboard-auth-required",
  serviceStatuses: [
    { label: "P2Pool", state: "warning", detail: "dashboard token required" },
    { label: "Bitcoin", state: "pending", detail: "not queried" },
    { label: "Idena", state: "pending", detail: "not queried" },
    { label: "Snapshot", state: "pending", detail: "not available" }
  ],
  account: {
    ...offlineDashboardData.account,
    identity: {
      ...offlineDashboardData.account.identity,
      pledgeDetail: "dashboard API rejected request"
    },
    idenaAccounting: {
      ...offlineDashboardData.account.idenaAccounting,
      formula: "dashboard API token missing or rejected",
      source: "auth-required"
    },
    pool: {
      ...offlineDashboardData.account.pool,
      expectedBlockInterval: "dashboard token required"
    }
  }
};

const demoDashboardData: DashboardApiResponse = {
  generatedAtUnix: null,
  source: "demo-fallback",
  serviceStatuses: fallbackServiceStatuses,
  account: fallbackAccount
};

const initialDashboardData = dashboardDemoMode ? demoDashboardData : offlineDashboardData;

const initialAppView: AppView =
  window.location.hash === "#governance"
    ? "governance"
    : window.location.hash === "#explorer" || !participantDashboardEnabled
      ? "explorer"
      : configuredDefaultView;
const emptyForkPage: ExplorerForkBlockPage = {
  state: "not_configured",
  tipHeight: null,
  total: 0,
  items: [],
  nextCursor: null
};
const emptySharePage: ExplorerSharePage = { total: 0, items: [], nextCursor: null };
const emptyBitcoinBlockPage: ExplorerBitcoinBlockPage = { scope: "bitcoin_mainnet_history", items: [] };

function explorerRequestHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (dashboardApiToken && explorerSharesDashboardOrigin) {
    headers["X-PoHW-Dashboard-Token"] = dashboardApiToken;
  }
  return headers;
}

async function fetchExplorerJson<T>(path: string): Promise<T> {
  const response = await fetch(`${explorerApiBase}${path}`, {
    cache: "no-store",
    headers: explorerRequestHeaders()
  });
  if (!response.ok) {
    throw new Error(`explorer API returned ${response.status}`);
  }
  return (await response.json()) as T;
}

async function fetchExplorerOptional<T>(path: string): Promise<T | null> {
  const response = await fetch(`${explorerApiBase}${path}`, {
    cache: "no-store",
    headers: explorerRequestHeaders()
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`explorer API returned ${response.status}`);
  }
  return (await response.json()) as T;
}

async function tryExplorerOptional<T>(path: string): Promise<T | null> {
  try {
    return await fetchExplorerOptional<T>(path);
  } catch {
    return null;
  }
}

const DashboardDataContext = React.createContext<DashboardApiResponse>(initialDashboardData);

function useDashboardData() {
  return React.useContext(DashboardDataContext);
}

function App() {
  const [dashboardData, setDashboardData] = useState<DashboardApiResponse>(initialDashboardData);
  const [activeView, setActiveView] = useState<AppView>(initialAppView);
  const [auditOpen, setAuditOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionId>("overview");
  const [window, setWindow] = useState<TimeWindow>("7d");
  const [explorerOverview, setExplorerOverview] = useState<ExplorerOverview | null>(null);
  const [forkBlocks, setForkBlocks] = useState<ExplorerForkBlockPage>(emptyForkPage);
  const [bitcoinBlocks, setBitcoinBlocks] = useState<ExplorerBitcoinBlockPage>(emptyBitcoinBlockPage);
  const [shares, setShares] = useState<ExplorerSharePage>(emptySharePage);
  const [explorerLoadState, setExplorerLoadState] = useState<ExplorerLoadState>("loading");
  const [governance, setGovernance] = useState<GovernanceDashboardResponse | null>(null);
  const [governanceLoadState, setGovernanceLoadState] = useState<ExplorerLoadState>("loading");
  const [loadingMoreFork, setLoadingMoreFork] = useState(false);
  const [loadingMoreShares, setLoadingMoreShares] = useState(false);
  const [prospectMode, setProspectMode] = useState<ProspectMode>("block-now");
  const account = dashboardData.account;
  const participation = useMemo(() => getParticipationStatus(account), [account]);

  useEffect(() => {
    if (!participantDashboardEnabled) return;
    let cancelled = false;
    async function loadDashboardData() {
      try {
        const headers: Record<string, string> = { Accept: "application/json" };
        if (dashboardApiToken) {
          headers["X-PoHW-Dashboard-Token"] = dashboardApiToken;
        }
        const response = await fetch(dashboardApiUrl, {
          headers
        });
        if (response.status === 401 || response.status === 403) {
          if (!cancelled) {
            setDashboardData(dashboardAuthRequiredData);
          }
          return;
        }
        if (!response.ok) {
          throw new Error(`dashboard API returned ${response.status}`);
        }
        const data = (await response.json()) as DashboardApiResponse;
        if (!cancelled) {
          setDashboardData(data);
        }
      } catch {
        if (!cancelled) {
          setDashboardData(dashboardDemoMode ? demoDashboardData : offlineDashboardData);
        }
      }
    }

    loadDashboardData();
    const interval = globalThis.setInterval(loadDashboardData, 15_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function loadGovernance() {
      try {
        const data = await fetchExplorerJson<GovernanceDashboardResponse>("/governance");
        if (!cancelled) {
          setGovernance(data);
          setGovernanceLoadState("ready");
        }
      } catch {
        if (!cancelled) {
          setGovernance(null);
          setGovernanceLoadState("unavailable");
        }
      }
    }
    void loadGovernance();
    const interval = globalThis.setInterval(loadGovernance, 15_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadOverview() {
      try {
        const overview = await fetchExplorerJson<ExplorerOverview>("/overview");
        if (!cancelled) {
          setExplorerOverview(overview);
          setExplorerLoadState("ready");
        }
      } catch {
        if (!cancelled) {
          setExplorerLoadState("unavailable");
        }
      }
    }

    async function loadPages() {
      try {
        const [forkPage, sharePage, bitcoinPage] = await Promise.all([
          fetchExplorerJson<ExplorerForkBlockPage>("/fork/blocks?limit=25"),
          fetchExplorerJson<ExplorerSharePage>("/sharechain/shares?limit=25"),
          tryExplorerOptional<ExplorerBitcoinBlockPage>("/bitcoin/blocks")
        ]);
        if (!cancelled) {
          setForkBlocks(forkPage);
          setShares(sharePage);
          setBitcoinBlocks(bitcoinPage ?? emptyBitcoinBlockPage);
        }
      } catch {
        if (!cancelled) {
          setExplorerLoadState("unavailable");
        }
      }
    }

    void loadOverview();
    void loadPages();
    const interval = globalThis.setInterval(() => {
      void loadOverview();
      void loadPages();
    }, 15_000);
    return () => {
      cancelled = true;
      globalThis.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const handleHashChange = () => {
      setActiveView(globalThis.location.hash === "#governance"
        ? "governance"
        : globalThis.location.hash === "#explorer" || !participantDashboardEnabled
          ? "explorer"
          : "dashboard");
    };
    globalThis.addEventListener("hashchange", handleHashChange);
    return () => globalThis.removeEventListener("hashchange", handleHashChange);
  }, []);

  const changeView = (view: AppView) => {
    if (view === "dashboard" && !participantDashboardEnabled) return;
    setActiveView(view);
    globalThis.history.replaceState(null, "", "#" + view);
  };

  const navigateToSection = (sectionId: SectionId, revealAudit = false) => {
    setActiveSection(sectionId);
    if (revealAudit) {
      setAuditOpen(true);
    }
    globalThis.requestAnimationFrame(() => {
      globalThis.requestAnimationFrame(() => {
        document.getElementById(sectionId)?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  };

  const startPledge = () => {
    changeView("dashboard");
    navigateToSection("next-step");
  };

  const refreshExplorer = async () => {
    setExplorerLoadState("loading");
    try {
      const [overview, forkPage, sharePage, bitcoinPage] = await Promise.all([
        fetchExplorerJson<ExplorerOverview>("/overview"),
        fetchExplorerJson<ExplorerForkBlockPage>("/fork/blocks?limit=25"),
        fetchExplorerJson<ExplorerSharePage>("/sharechain/shares?limit=25"),
        tryExplorerOptional<ExplorerBitcoinBlockPage>("/bitcoin/blocks")
      ]);
      setExplorerOverview(overview);
      setForkBlocks(forkPage);
      setShares(sharePage);
      setBitcoinBlocks(bitcoinPage ?? emptyBitcoinBlockPage);
      setExplorerLoadState("ready");
    } catch {
      setExplorerLoadState("unavailable");
    }
  };

  const loadMoreForkBlocks = async () => {
    if (!forkBlocks.nextCursor || loadingMoreFork) return;
    setLoadingMoreFork(true);
    try {
      const page = await fetchExplorerJson<ExplorerForkBlockPage>(
        `/fork/blocks?limit=25&cursor=${forkBlocks.nextCursor}`
      );
      setForkBlocks((current) => ({
        ...page,
        items: [...current.items, ...page.items]
      }));
    } finally {
      setLoadingMoreFork(false);
    }
  };

  const loadMoreShares = async () => {
    if (!shares.nextCursor || loadingMoreShares) return;
    setLoadingMoreShares(true);
    try {
      const page = await fetchExplorerJson<ExplorerSharePage>(
        `/sharechain/shares?limit=25&cursor=${shares.nextCursor}`
      );
      setShares((current) => ({
        ...page,
        items: [...current.items, ...page.items]
      }));
    } finally {
      setLoadingMoreShares(false);
    }
  };

  const blockNowView = useMemo(() => getRewardView(account, "block-now"), [account]);
  const expected30dView = useMemo(() => getRewardView(account, "30d-ev"), [account]);
  const forecastView = useMemo(() => getRewardView(account, prospectMode), [account, prospectMode]);
  const totals = useMemo(() => getContributionTotals(account), [account]);

  return (
    <DashboardDataContext.Provider value={dashboardData}>
      <main
        className={README_CAPTURE_MODE ? "app-shell capture-final" : "app-shell"}
        data-capture={README_CAPTURE_MODE ? "final" : undefined}
      >
        <Navigation
          activeSection={activeSection}
          activeView={activeView}
          onNavigate={navigateToSection}
          onViewChange={changeView}
          participantDashboardEnabled={participantDashboardEnabled}
        />
        <section className="workspace">
          <TopBar
            activeView={activeView}
            explorerOverview={explorerOverview}
            explorerState={explorerLoadState}
            governance={governance}
            governanceState={governanceLoadState}
          />
          {activeView === "dashboard" ? (
            <div className="dashboard-grid">
              <section className="main-column">
                <DashboardIntro
                  onStartPledge={startPledge}
                  participation={participation}
                />

                {dashboardData.source !== "local-p2pool-node" ? (
                  <SourceNotice source={dashboardData.source} />
                ) : null}

                <MiningSnapshot
                  blockView={blockNowView}
                  expected30dView={expected30dView}
                  participation={participation}
                  totals={totals}
                />

                <JourneyStrip participation={participation} view={blockNowView} />

                <section className="focus-grid">
                  <RewardForecast
                    onProspectModeChange={setProspectMode}
                    participation={participation}
                    prospectMode={prospectMode}
                    view={forecastView}
                  />
                  <ContributionSplit totals={totals} />
                </section>
                <DetailsPanel
                  auditOpen={auditOpen}
                  onAuditOpenChange={setAuditOpen}
                  onWindowChange={setWindow}
                  participation={participation}
                  view={blockNowView}
                  window={window}
                />
              </section>

              <NextStepPanel
                participation={participation}
                view={blockNowView}
              />
            </div>
          ) : activeView === "explorer" ? (
            <ExplorerWorkspace
              bitcoinBlocks={bitcoinBlocks}
              forkBlocks={forkBlocks}
              loadingMoreFork={loadingMoreFork}
              loadingMoreShares={loadingMoreShares}
              loadState={explorerLoadState}
              onLoadMoreFork={loadMoreForkBlocks}
              onLoadMoreShares={loadMoreShares}
              onRefresh={refreshExplorer}
              overview={explorerOverview}
              shares={shares}
            />
          ) : (
            <GovernanceWorkspace data={governance} loadState={governanceLoadState} />
          )}
        </section>
      </main>
    </DashboardDataContext.Provider>
  );
}

function GovernanceWorkspace({
  data,
  loadState
}: {
  data: GovernanceDashboardResponse | null;
  loadState: ExplorerLoadState;
}) {
  const unavailable = loadState === "unavailable";
  const configured = data?.status === "operator-validated-local-snapshot";
  return (
    <section className="governance-workspace">
      <header className="governance-header">
        <div>
          <span className="governance-kicker">Software governance</span>
          <h1>Canonical ecosystem</h1>
          <p>Sublinear locked IDNA stake with independent identity, review, build, and availability gates.</p>
        </div>
        <span className="governance-safety">{data?.safetyLabel ?? "EXPERIMENTAL / NO-VALUE"}</span>
      </header>

      {loadState === "loading" ? (
        <div className="governance-empty"><RefreshCw className="spin" size={18} /><span>Loading local governance snapshot</span></div>
      ) : unavailable || !data ? (
        <div className="governance-empty warning"><AlertTriangle size={18} /><span>Governance snapshot unavailable</span></div>
      ) : !configured ? (
        <div className="governance-empty"><Database size={18} /><span>No governance contract snapshot configured</span></div>
      ) : (
        <>
          <div className="governance-empty warning">
            <AlertTriangle size={18} />
            <span>Operator-local snapshot: content bindings and gate arithmetic are checked locally, but contract state is not queried yet</span>
          </div>
          {!data.communityActivation.active ? (
            <div className="governance-empty warning">
              <ShieldCheck size={18} />
              <span>
                Community DAO dormant: {data.communityActivation.participantCount}/
                {data.communityActivation.participantThreshold} qualifying participants. Source review and stake setup are available; proposals and voting are locked.
              </span>
            </div>
          ) : null}
          <section className="governance-canonical">
            <div>
              <span>Canonical ecosystem CID</span>
              <code title={captureSafeTitle(data.currentCanonicalEcosystemCid)}>
                {captureIdentifier(data.currentCanonicalEcosystemCid, "Unavailable")}
              </code>
            </div>
            <div>
              <span>Contract</span>
              <code title={captureSafeTitle(data.governanceContractAddress)}>
                {captureIdentifier(data.governanceContractAddress, "Not deployed")}
              </code>
            </div>
            <div>
              <span>Identity metrics</span>
              <code title={captureSafeTitle(data.identityMetrics?.metricsRoot)}>
                {data.identityMetrics
                  ? shortHash(data.identityMetrics.metricsRoot) + " / "
                    + data.identityMetrics.independentAttestors + "/"
                    + data.identityMetrics.requiredAttestors
                  : "Unavailable"}
              </code>
              <small>
                {data.identityMetrics?.conflict
                  ? "Conflicting operator quorums"
                  : data.identityMetrics?.certified
                    ? "Replay commitment certified"
                    : "Certification pending"}
              </small>
            </div>
            <div>
              <span>Community activation</span>
              <code>
                {data.communityActivation.participantCount}/
                {data.communityActivation.participantThreshold} participants
              </code>
              <small>
                {data.communityActivation.active
                  ? `Active at block ${data.communityActivation.activationBlock ?? "unknown"}`
                  : "Dormant / permissionless at threshold"}
              </small>
            </div>
          </section>

          {data.developmentPolicy && data.developmentPolicyCid ? (
            <DevelopmentJourney
              policy={data.developmentPolicy}
              policyCid={data.developmentPolicyCid}
            />
          ) : (
            <div className="governance-empty warning">
              <AlertTriangle size={18} />
              <span>No verified human/AI development policy is attached</span>
            </div>
          )}

          {data.epochGovernance ? (
            <GovernanceDayOverview epoch={data.epochGovernance} />
          ) : (
            <div className="governance-empty">
              <Clock3 size={18} />
              <span>Governance Day schedule is not present in this verified snapshot</span>
            </div>
          )}

          <section className="governance-repositories">
            <div className="governance-section-heading">
              <h2>Repository sources</h2>
              <span>{data.repositories.length} pinned</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Repository</th><th>Canonical source CID</th></tr></thead>
                <tbody>
                  {data.repositories.map((repository) => (
                    <tr key={repository.name}>
                      <td data-label="Repository"><strong>{repository.name}</strong></td>
                      <td data-label="Canonical source CID">
                        <code title={captureSafeTitle(repository.sourceTreeCid)}>
                          {captureIdentifier(repository.sourceTreeCid)}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="governance-proposals">
            <div className="governance-section-heading">
              <h2>Proposals</h2>
              <span>{data.proposals.length} tracked</span>
            </div>
            {data.proposals.length === 0 ? (
              <div className="governance-empty"><GitBranch size={18} /><span>No proposals in this snapshot</span></div>
            ) : data.proposals.map((proposal) => (
              <GovernanceProposalCard key={proposal.proposalId} proposal={proposal} />
            ))}
          </section>

          <GovernanceHistory entries={data.canonicalHistory ?? []} />
          {data.recovery ? <GovernanceRecovery recovery={data.recovery} /> : null}
        </>
      )}
    </section>
  );
}

function DevelopmentJourney({
  policy,
  policyCid
}: {
  policy: DevelopmentPolicy;
  policyCid: string;
}) {
  const upstream = policy.upstream[0];
  return (
    <section className="governance-development">
      <div className="governance-section-heading">
        <div>
          <span>Content-addressed workflow</span>
          <h2>Human + AI development</h2>
        </div>
        <strong className="development-license">{policy.licenseSpdx}</strong>
      </div>
      <div className="development-policy-meta">
        <span>Policy <code title={captureSafeTitle(policyCid)}>{captureIdentifier(policyCid)}</code></span>
        <span>Authority <strong>Idena WASM</strong></span>
        <span>Upstream <code title={captureSafeTitle(upstream?.sourceTreeCid)}>{captureIdentifier(upstream?.sourceTreeCid, "Unavailable")}</code></span>
      </div>
      <div className="development-flow" role="list" aria-label="Decentralized development phases">
        {policy.phases.map((phase, index) => (
          <div className="development-phase" role="listitem" key={phase.id}>
            <span className="development-phase-index">{String(index + 1).padStart(2, "0")}</span>
            <strong>{splitGovernancePhase(phase.id)}</strong>
            <small>{splitGovernancePhase(phase.actor)}</small>
            <code>{phase.outputSchema}</code>
            <span className={phase.humanApprovalRequired ? "development-human-gate required" : "development-human-gate"}>
              {phase.humanApprovalRequired ? "Human approval" : "Objective gate"}
            </span>
          </div>
        ))}
      </div>
      <p className="governance-boundary">
        GitHub is a mirror. Agents can propose and attest, but cannot accept or execute. Any caller may execute only after every contract gate passes.
      </p>
    </section>
  );
}

function GovernanceDayOverview({ epoch }: { epoch: GovernanceEpochView }) {
  const schedule = epoch.schedule;
  const milestones = [
    ["Proposal cutoff", schedule.proposalCutoffBlock],
    ["Commit opens", schedule.commitStartBlock],
    ["Commit closes", schedule.commitEndBlock],
    ["Reveal closes", schedule.revealEndBlock]
  ] as const;
  return (
    <section className="governance-day">
      <div className="governance-section-heading">
        <div>
          <span>Shared epoch ballot</span>
          <h2>Governance Day - Epoch {epoch.governanceEpoch}</h2>
        </div>
        <strong className="governance-phase">{splitGovernancePhase(epoch.phase)}</strong>
      </div>
      <div className="governance-day-grid">
        <div><span>Frozen proposals</span><strong>{epoch.orderedProposalIds.length}</strong><small>{epoch.frozenProposalSetRoot ? shortHash(epoch.frozenProposalSetRoot) : "Not frozen"}</small></div>
        <div><span>Review status</span><strong>{epoch.reviewedProposals} reviewed</strong><small>{epoch.unresolvedProposals} unresolved / {epoch.validAgentAttestations} AI attestations</small></div>
        <div><span>Ballots</span><strong>{epoch.committedBallots} committed</strong><small>{epoch.revealedBallots} revealed; one ballot covers the frozen set</small></div>
        <div><span>Voting power</span><strong>{epoch.votingPowerSnapshotReady ? "Snapshot ready" : "Snapshot pending"}</strong><small>Sublinear locked IDNA; identity age ignored</small></div>
        <div><span>Challenges</span><strong>{epoch.openChallenges} open</strong><small>{epoch.executionReadyProposals} proposals execution-ready</small></div>
      </div>
      <div className="governance-timeline" aria-label="Governance epoch block schedule">
        {milestones.map(([label, block]) => (
          <div className={epoch.currentBlock >= block ? "passed" : "pending"} key={label}>
            <span>{label}</span>
            <strong>Block {block}</strong>
            <small>{epoch.currentBlock >= block ? "Reached" : `${block - epoch.currentBlock} blocks remaining`}</small>
          </div>
        ))}
        {epoch.graceEndBlock ? (
          <div className={epoch.currentBlock >= epoch.graceEndBlock ? "passed" : "pending"}>
            <span>Grace ends</span>
            <strong>Block {epoch.graceEndBlock}</strong>
            <small>{epoch.currentBlock >= epoch.graceEndBlock ? "Reached" : `${epoch.graceEndBlock - epoch.currentBlock} blocks remaining`}</small>
          </div>
        ) : null}
      </div>
      <p className="governance-boundary">
        Chain block {epoch.currentBlock}. The frozen proposal set cannot change during commit or reveal. Finalization and execution never install software automatically.
      </p>
    </section>
  );
}

function GovernanceHistory({ entries }: { entries: GovernanceCanonicalExecution[] }) {
  return (
    <section className="governance-history">
      <div className="governance-section-heading">
        <h2>Canonical history</h2>
        <span>{entries.length} append-only executions</span>
      </div>
      {entries.length === 0 ? (
        <div className="governance-empty"><GitBranch size={18} /><span>No canonical execution has been recorded</span></div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Epoch / block</th><th>Previous CID</th><th>New CID</th><th>Execution</th><th>Recovery</th></tr></thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.executionId}>
                  <td data-label="Epoch / block"><strong>{entry.governanceEpoch}</strong> / {entry.executionBlock}</td>
                  <td data-label="Previous CID"><code title={captureSafeTitle(entry.previousCanonicalEcosystemCid)}>{shortHash(entry.previousCanonicalEcosystemCid)}</code></td>
                  <td data-label="New CID"><code title={captureSafeTitle(entry.newCanonicalEcosystemCid)}>{shortHash(entry.newCanonicalEcosystemCid)}</code></td>
                  <td data-label="Execution"><code title={captureSafeTitle(entry.executionId)}>{shortHash(entry.executionId)}</code></td>
                  <td data-label="Recovery">{entry.revertsExecutionId ? `Reverts ${shortHash(entry.revertsExecutionId)}` : `Observe through ${entry.observationWindowEndBlock}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function GovernanceRecovery({ recovery }: { recovery: GovernanceRecoveryView }) {
  return (
    <section className={recovery.chainRpcAvailable ? "governance-recovery" : "governance-recovery chain-stuck"}>
      <AlertTriangle size={19} />
      <div>
        <strong>{recovery.chainRpcAvailable ? "Recovery boundary" : "Chain RPC unavailable"}</strong>
        <p>{recovery.warning}</p>
        <small>
          {recovery.localLastKnownGoodStaged ? "Verified last-known-good content is staged. " : "No last-known-good content is staged. "}
          Explicit confirmation is required; automatic install and automatic rollback are disabled.
          {!recovery.chainRpcAvailable ? " An on-chain revert cannot execute while the chain is stuck." : ""}
        </small>
      </div>
    </section>
  );
}

function splitGovernancePhase(phase: string): string {
  const label = phase.replace(/-/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function GovernanceProposalCard({ proposal }: { proposal: GovernanceProposal }) {
  const gates = [
    {
      detail: proposal.pos.yesWeight + " yes / " + proposal.pos.noWeight + " no",
      label: "PoS",
      passed: proposal.pos.passed,
      value: (proposal.pos.yesThresholdBps / 100).toFixed(2) + "% threshold"
    },
    {
      detail: proposal.pohw.distinctParticipatingIdentities + "/" + proposal.pohw.requiredParticipatingIdentities + " participants; " + proposal.pohw.verifiedOrHumanYesIdentities + "/" + proposal.pohw.requiredVerifiedOrHumanYes + " Verified or Human",
      label: "PoHW",
      passed: proposal.pohw.passed,
      value: proposal.pohw.distinctYesIdentities + "/" + proposal.pohw.requiredYesIdentities + " identities"
    },
    {
      detail: proposal.aiReviews.distinctRuntimeGroups + "/" + proposal.aiReviews.requiredRuntimeGroups + " owner-bound runtime groups; "
        + proposal.aiReviews.distinctModelFamilies + "/" + proposal.aiReviews.requiredModelFamilies + " model families; "
        + proposal.aiReviews.distinctOwnerIdentities + "/" + proposal.aiReviews.requiredOwnerIdentities + " owners",
      label: "PoAW",
      passed: proposal.aiReviews.passed,
      value: proposal.aiReviews.validAttestations + "/" + proposal.aiReviews.requiredAttestations + " reviews"
    },
    {
      detail: proposal.builds.matchingCoreArtifactDigests ? "core digests match" : "digest mismatch",
      label: "Verification",
      passed: proposal.builds.passed,
      value: proposal.builds.independentBuilders + "/" + proposal.builds.requiredBuilders + " builders"
    },
    {
      detail: "valid through block " + proposal.dataAvailability.validUntilBlock
        + " (required " + proposal.dataAvailability.requiredValidUntilBlock + ")",
      label: "Availability",
      passed: proposal.dataAvailability.passed,
      value: proposal.dataAvailability.independentAttestors + "/" + proposal.dataAvailability.requiredAttestors + " attestations"
    }
  ];
  return (
    <article className="governance-proposal">
      <header>
        <div>
          <span className={"risk-label " + proposal.riskClass}>{proposal.riskClass}</span>
          <h3>{proposal.diffSummary}</h3>
          <code title={captureSafeTitle(proposal.proposalId)}>{shortHash(proposal.proposalId)}</code>
        </div>
        <div className="proposal-state">
          <strong>{proposal.state}</strong>
          <span>{formatIdnaAtoms(proposal.bondAtoms)} IDNA bond</span>
        </div>
      </header>
      <div className="proposal-cids">
        <span>Candidate <code title={captureSafeTitle(proposal.candidateEcosystemCid)}>{shortHash(proposal.candidateEcosystemCid)}</code></span>
        <span>Parameters <code title={captureSafeTitle(proposal.parameterSetCid)}>{shortHash(proposal.parameterSetCid)}</code></span>
        <span>Review round <code title={captureSafeTitle(proposal.reviewRoundId)}>{shortHash(proposal.reviewRoundId)}</code> <strong>{proposal.reviewRoundState}</strong></span>
        <span>Scope evidence <code title={captureSafeTitle(proposal.scopeEvidenceCid)}>{shortHash(proposal.scopeEvidenceCid)}</code> <strong>{proposal.scopeEvidenceVerified ? "verified" : "invalid"}</strong></span>
        <span>Repositories <strong>{proposal.affectedRepositories.join(", ")}</strong></span>
        <span>Scope <strong>{proposal.changedFileCount} files / {formatBytes(proposal.patchBytes)} patch / {proposal.migrationOperationCount} migrations</strong></span>
      </div>
      <div className="governance-gates">
        {gates.map((gate) => (
          <div className={gate.passed ? "governance-gate passed" : "governance-gate pending"} key={gate.label}>
            {gate.passed ? <CheckCircle2 size={17} /> : <Clock3 size={17} />}
            <div><span>{gate.label}</span><strong>{gate.value}</strong><small>{gate.detail}</small></div>
          </div>
        ))}
      </div>
      <footer>
        <span>Challenge <strong>{proposal.challengeStatus}</strong></span>
        <span>Execution <strong>{proposal.executionStatus}</strong></span>
        <span>Critical findings <strong>{proposal.aiReviews.unresolvedCriticalFindings}</strong></span>
        <span>Frozen set <strong>{proposal.reviewRoundAgentAttestations} reviews / {proposal.reviewRoundBuildAttestations} builds / {proposal.reviewRoundAvailabilityAttestations} pins</strong></span>
      </footer>
    </article>
  );
}

function ExplorerWorkspace({
  bitcoinBlocks,
  forkBlocks,
  loadingMoreFork,
  loadingMoreShares,
  loadState,
  onLoadMoreFork,
  onLoadMoreShares,
  onRefresh,
  overview,
  shares
}: {
  bitcoinBlocks: ExplorerBitcoinBlockPage;
  forkBlocks: ExplorerForkBlockPage;
  loadingMoreFork: boolean;
  loadingMoreShares: boolean;
  loadState: ExplorerLoadState;
  onLoadMoreFork: () => Promise<void>;
  onLoadMoreShares: () => Promise<void>;
  onRefresh: () => Promise<void>;
  overview: ExplorerOverview | null;
  shares: ExplorerSharePage;
}) {
  const [tab, setTab] = useState<ExplorerTab>("overview");
  const [query, setQuery] = useState("");
  const [searchResult, setSearchResult] = useState<ExplorerSearchResult | null>(null);
  const [searchState, setSearchState] = useState<"idle" | "searching" | "invalid" | "not-found" | "error">("idle");

  const showForkBlock = async (item: ForkBlockSummary) => {
    setQuery(item.blockHash);
    setSearchState("searching");
    const transactions = await tryExplorerOptional<ForkTransactionPage>(
      `/fork/blocks/${item.blockHash}/transactions?limit=100`
    );
    setSearchResult({ kind: "block", item, transactions });
    setSearchState("idle");
  };

  const showBitcoinBlock = async (item: BitcoinIndexObject<BitcoinBlockData>) => {
    setQuery(item.data.id);
    setSearchState("searching");
    const transactions = await tryExplorerOptional<ExplorerBitcoinBlockTransactionPage>(
      `/bitcoin/blocks/${item.data.id}/transactions`
    );
    setSearchResult({ kind: "bitcoin-block", item, transactions });
    setSearchState("idle");
  };

  const showBitcoinTransaction = async (item: BitcoinIndexObject<BitcoinTransactionData>) => {
    setQuery(item.data.txid);
    setSearchState("searching");
    const outspends = await tryExplorerOptional<ExplorerBitcoinOutspendPage>(
      `/bitcoin/transactions/${item.data.txid}/outspends`
    );
    setSearchResult({ kind: "bitcoin-transaction", item, outspends });
    setSearchState("idle");
  };

  const loadMoreSearchDetail = async (target: ExplorerLoadMoreTarget) => {
    const current = searchResult;
    if (target === "fork-block-transactions" && current?.kind === "block" && current.transactions?.nextCursor != null) {
      const page = await tryExplorerOptional<ForkTransactionPage>(
        `/fork/blocks/${current.item.blockHash}/transactions?cursor=${current.transactions.nextCursor}&limit=100`
      );
      if (page) {
        setSearchResult((active) => active?.kind === "block" && active.item.blockHash === current.item.blockHash
          ? { ...active, transactions: { ...page, items: [...(active.transactions?.items ?? []), ...page.items] } }
          : active);
      }
      return;
    }
    if (target === "bitcoin-block-transactions" && current?.kind === "bitcoin-block" && current.transactions?.nextCursor != null) {
      const page = await tryExplorerOptional<ExplorerBitcoinBlockTransactionPage>(
        `/bitcoin/blocks/${current.item.data.id}/transactions?cursor=${current.transactions.nextCursor}`
      );
      if (page) {
        setSearchResult((active) => active?.kind === "bitcoin-block" && active.item.data.id === current.item.data.id
          ? { ...active, transactions: { ...page, startIndex: 0, items: [...(active.transactions?.items ?? []), ...page.items] } }
          : active);
      }
      return;
    }
    if (current?.kind !== "address") return;
    if (target === "fork-address-transactions" && current.forkTransactions?.nextCursor != null) {
      const page = await tryExplorerOptional<ForkAddressTransactionPage>(
        `/fork/addresses/${current.address}/transactions?cursor=${current.forkTransactions.nextCursor}&limit=100`
      );
      if (page) {
        setSearchResult((active) => active?.kind === "address" && active.address === current.address
          ? { ...active, forkTransactions: { ...page, items: [...(active.forkTransactions?.items ?? []), ...page.items] } }
          : active);
      }
      return;
    }
    if (target === "fork-address-utxos" && current.forkUtxos?.nextCursor != null) {
      const page = await tryExplorerOptional<ForkUtxoPage>(
        `/fork/addresses/${current.address}/utxos?cursor=${current.forkUtxos.nextCursor}&limit=100`
      );
      if (page) {
        setSearchResult((active) => active?.kind === "address" && active.address === current.address
          ? { ...active, forkUtxos: { ...page, items: [...(active.forkUtxos?.items ?? []), ...page.items] } }
          : active);
      }
      return;
    }
    if (target === "bitcoin-address-transactions" && current.bitcoinTransactions?.nextCursor) {
      const page = await tryExplorerOptional<ExplorerBitcoinTransactionPage>(
        `/bitcoin/addresses/${current.address}/transactions?cursor=${current.bitcoinTransactions.nextCursor}`
      );
      if (page) {
        setSearchResult((active) => active?.kind === "address" && active.address === current.address
          ? { ...active, bitcoinTransactions: { ...page, items: [...(active.bitcoinTransactions?.items ?? []), ...page.items] } }
          : active);
      }
    }
  };

  const search = async (searchQuery: string) => {
    const rawQuery = searchQuery.trim();
    setQuery(rawQuery);
    const normalized = rawQuery.toLowerCase();
    const isHeight = /^[0-9]+$/.test(normalized);
    const isHash = /^[0-9a-f]{64}$/.test(normalized);
    const isAddress = /^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[ac-hj-np-z02-9]{11,87})$/.test(rawQuery);
    setSearchResult(null);
    if (!isHeight && !isHash && !isAddress) {
      setSearchState("invalid");
      return;
    }
    setSearchState("searching");
    try {
      if (isAddress) {
        const [fork, forkTransactions, forkUtxos, bitcoin, bitcoinTransactions, bitcoinUtxos] = await Promise.all([
          tryExplorerOptional<ForkAddressSummary>(`/fork/addresses/${rawQuery}`),
          tryExplorerOptional<ForkAddressTransactionPage>(`/fork/addresses/${rawQuery}/transactions?limit=100`),
          tryExplorerOptional<ForkUtxoPage>(`/fork/addresses/${rawQuery}/utxos?limit=100`),
          tryExplorerOptional<BitcoinIndexObject<BitcoinAddressData>>(`/bitcoin/addresses/${rawQuery}`),
          tryExplorerOptional<ExplorerBitcoinTransactionPage>(`/bitcoin/addresses/${rawQuery}/transactions`),
          tryExplorerOptional<Array<BitcoinIndexObject<BitcoinUtxo>>>(`/bitcoin/addresses/${rawQuery}/utxos`)
        ]);
        if (fork || bitcoin) {
          setSearchResult({
            kind: "address",
            address: rawQuery,
            fork,
            forkTransactions,
            forkUtxos,
            bitcoin,
            bitcoinTransactions,
            bitcoinUtxos
          });
          setSearchState("idle");
        } else {
          setSearchState("not-found");
        }
        return;
      }
      if (isHeight) {
        const block = await tryExplorerOptional<ForkBlockSummary>(`/fork/heights/${normalized}`);
        if (block) {
          await showForkBlock(block);
        } else {
          const bitcoinBlock = await tryExplorerOptional<BitcoinIndexObject<BitcoinBlockData>>(
            `/bitcoin/heights/${normalized}`
          );
          if (bitcoinBlock) {
            await showBitcoinBlock(bitcoinBlock);
          } else {
            setSearchState("not-found");
          }
        }
        return;
      }
      const block = await tryExplorerOptional<ForkBlockSummary>(`/fork/blocks/${normalized}`);
      if (block) {
        await showForkBlock(block);
        return;
      }
      const forkTransaction = await tryExplorerOptional<ForkTransactionDetail>(
        `/fork/transactions/${normalized}`
      );
      if (forkTransaction) {
        setSearchResult({ kind: "fork-transaction", item: forkTransaction });
        setSearchState("idle");
        return;
      }
      const share = await tryExplorerOptional<SharechainShareSummary>(`/sharechain/shares/${normalized}`);
      if (share) {
        setSearchResult({ kind: "share", item: share });
        setSearchState("idle");
        return;
      }
      const bitcoinTransaction = await tryExplorerOptional<BitcoinIndexObject<BitcoinTransactionData>>(
        `/bitcoin/transactions/${normalized}`
      );
      if (bitcoinTransaction) {
        await showBitcoinTransaction(bitcoinTransaction);
        return;
      }
      const bitcoinBlock = await tryExplorerOptional<BitcoinIndexObject<BitcoinBlockData>>(
        `/bitcoin/blocks/${normalized}`
      );
      if (bitcoinBlock) {
        await showBitcoinBlock(bitcoinBlock);
        return;
      }
      setSearchState("not-found");
    } catch {
      setSearchState("error");
    }
  };

  const submitSearch = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void search(query);
  };

  const forkStatus = overview?.fork.status ?? null;
  const idena = overview?.idena ?? null;
  const maskSearchQuery = README_CAPTURE_MODE && query !== "" && !/^\d+$/.test(query);

  return (
    <div className="explorer-workspace">
      <header className="explorer-header">
        <div>
          <span className="eyebrow">{getExplorerNetworkLabel(overview)}</span>
          <h1>Network Explorer</h1>
          <p>Fork transactions, inherited Bitcoin history, sharechain and Idena state</p>
        </div>
        <div className="explorer-actions">
          <form className="explorer-search" onSubmit={submitSearch}>
            <Search aria-hidden="true" size={17} />
            <input
              aria-label="Search by height, block hash, transaction ID, share hash or Bitcoin address"
              className={maskSearchQuery ? "capture-search-mask" : undefined}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Height, hash, txid or address"
              spellCheck={false}
              type={maskSearchQuery ? "password" : "text"}
              value={query}
            />
            <button aria-label="Search explorer" title="Search" type="submit">
              <Search size={17} />
            </button>
          </form>
          <button
            aria-label="Refresh explorer"
            className="icon-action"
            disabled={loadState === "loading"}
            onClick={() => void onRefresh()}
            title="Refresh"
            type="button"
          >
            <RefreshCw className={loadState === "loading" ? "spin" : undefined} size={17} />
          </button>
        </div>
      </header>

      {loadState === "unavailable" ? (
        <section className="explorer-alert error">
          <AlertTriangle size={17} />
          <strong>Explorer API unavailable</strong>
        </section>
      ) : null}

      {searchState !== "idle" || searchResult ? (
        <ExplorerSearchPanel
          inheritedSpendingEnabled={forkStatus?.transactionConsensus === "bitcoin-core-v31.1-full"}
          onInspect={(value) => void search(value)}
          onLoadMore={(target) => void loadMoreSearchDetail(target)}
          result={searchResult}
          state={searchState}
        />
      ) : null}

      <div className="explorer-tabs" role="tablist" aria-label="Explorer data">
        {([
          ["overview", "Overview", Activity],
          ["bitcoin", "Bitcoin history", Bitcoin],
          ["fork", "Fork blocks", Blocks],
          ["sharechain", "Sharechain", GitBranch],
          ["idena", "Idena", ShieldCheck]
        ] as const).map(([value, label, Icon]) => (
          <button
            aria-selected={tab === value}
            className={tab === value ? "selected" : undefined}
            key={value}
            onClick={() => setTab(value)}
            role="tab"
            type="button"
          >
            <Icon size={16} />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {tab === "overview" ? (
        <ExplorerOverviewView forkStatus={forkStatus} overview={overview} />
      ) : null}
      {tab === "bitcoin" ? (
        <BitcoinHistoryView
          blocks={bitcoinBlocks}
          onInspect={(item) => void showBitcoinBlock(item)}
          overview={overview?.bitcoinHistory ?? null}
        />
      ) : null}
      {tab === "fork" ? (
        <ForkBlocksView
          loadingMore={loadingMoreFork}
          onInspect={(item) => void showForkBlock(item)}
          onLoadMore={onLoadMoreFork}
          page={forkBlocks}
        />
      ) : null}
      {tab === "sharechain" ? (
        <SharechainExplorerView
          loadingMore={loadingMoreShares}
          onInspect={(item) => {
            setQuery(item.shareHash);
            setSearchResult({ kind: "share", item });
            setSearchState("idle");
          }}
          onLoadMore={onLoadMoreShares}
          page={shares}
        />
      ) : null}
      {tab === "idena" ? <IdenaExplorerView idena={idena} /> : null}
    </div>
  );
}

function ExplorerOverviewView({
  forkStatus,
  overview
}: {
  forkStatus: ForkChainStatus | null;
  overview: ExplorerOverview | null;
}) {
  const sharechain = overview?.sharechain;
  const idena = overview?.idena;
  let participantMetric: readonly [string, string, LucideIcon];
  let snapshotMetric: readonly [string, string, LucideIcon];
  if (sharechain?.mainnetHandoffParticipantCount != null) {
    participantMetric = [
      "Mainnet handoff",
      `${formatInt(sharechain.mainnetHandoffParticipantCount)} / ${formatInt(sharechain.mainnetHandoffParticipantThreshold)}`,
      Users
    ];
    snapshotMetric = [
      "Handoff snapshot quorum",
      sharechain.snapshotVoterIdenaCount == null
        ? "Unavailable"
        : `${formatInt(sharechain.snapshotVoterIdenaCount)} / ${formatInt(sharechain.mainnetHandoffSnapshotVoterThreshold)}`,
      ShieldCheck
    ];
  } else {
    participantMetric = [
      "Pool miners",
      sharechain ? formatInt(sharechain.registeredMinerCount) : "Unavailable",
      Users
    ];
    snapshotMetric = [
      "Snapshot voters",
      sharechain?.snapshotVoterIdenaCount == null
        ? "Unavailable"
        : formatInt(sharechain.snapshotVoterIdenaCount),
      ShieldCheck
    ];
  }
  const metrics: ReadonlyArray<readonly [string, string, LucideIcon]> = [
    ["Fork height", forkStatus ? formatInt(forkStatus.tipHeight) : "Not connected", Blocks],
    ["Bitcoin index", overview?.bitcoinHistory?.indexedTipHeight == null ? "Not ready" : formatInt(overview.bitcoinHistory.indexedTipHeight), Database],
    ["Active shares", sharechain ? formatInt(sharechain.activeShareCount) : "Unavailable", GitBranch],
    participantMetric,
    snapshotMetric,
    ["Eligible identities", idena ? formatInt(idena.eligibleIdentityCount) : "Unavailable", ShieldCheck]
  ];
  return (
    <section className="explorer-view" aria-label="Combined chain overview">
      <div className="explorer-metrics">
        {metrics.map(([label, value, Icon]) => (
          <div className="explorer-metric" key={label}>
            <Icon size={18} />
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <section className="cross-layer-band">
        <div className="cross-layer-step">
          <Bitcoin size={18} />
          <span>Fork tip</span>
          <strong>{forkStatus ? shortHash(forkStatus.tipHash) : "Unavailable"}</strong>
        </div>
        <span className="cross-layer-arrow" aria-hidden="true">&rarr;</span>
        <div className="cross-layer-step">
          <GitBranch size={18} />
          <span>Share tip</span>
          <strong>{shortHash(sharechain?.bestShareTip)}</strong>
        </div>
        <span className="cross-layer-arrow" aria-hidden="true">&rarr;</span>
        <div className="cross-layer-step">
          <ShieldCheck size={18} />
          <span>Idena score root</span>
          <strong>{shortHash(idena?.scoreRoot)}</strong>
        </div>
        <span className="cross-layer-arrow" aria-hidden="true">&rarr;</span>
        <div className="cross-layer-step">
          <Wallet size={18} />
          <span>Payout schedules</span>
          <strong>{formatInt(sharechain?.payoutScheduleCount ?? 0)}</strong>
        </div>
      </section>

      <div className="explorer-summary-grid">
        <section className="explorer-summary-section">
          <div className="explorer-section-heading">
            <h2>Bitcoin history</h2>
            <ExplorerStateBadge state={overview?.bitcoinHistory?.state ?? "not_configured"} />
          </div>
          <ExplorerDefinitionList
            rows={[
              ["Backend", overview?.bitcoinHistory?.backend ?? "Not configured"],
              ["Indexed tip", overview?.bitcoinHistory?.indexedTipHeight == null ? "Unavailable" : formatInt(overview.bitcoinHistory.indexedTipHeight)],
              ["Fork parent", overview?.bitcoinHistory?.inheritedTipHeight == null ? "Unavailable" : formatInt(overview.bitcoinHistory.inheritedTipHeight)],
              ["Inherited history", overview?.bitcoinHistory?.inheritedHistoryReady ? "Ready" : "Not ready"],
              ["Participant requirement", overview?.bitcoinHistory?.participantIndexRequired ? "Full index" : "API only"]
            ]}
          />
        </section>
        <section className="explorer-summary-section">
          <div className="explorer-section-heading">
            <h2>Fork consensus</h2>
            <ExplorerStateBadge state={overview?.fork.state ?? "unavailable"} />
          </div>
          <ExplorerDefinitionList
            rows={[
              ["Chain", getExplorerChainLabel(overview)],
              ["Difficulty phase", forkStatus?.difficultyPhase ?? "Unavailable"],
              ["Estimated hashrate", formatHashrate(forkStatus?.estimatedHashrateHps)],
              ["Active blocks", formatInt(forkStatus?.activeForkBlockCount ?? 0)],
              ["Address history", formatStateLabel(overview?.fork.addressIndex.state ?? "not_configured")],
              ["Target spacing", forkStatus ? `${formatInt(forkStatus.targetSpacingSeconds)} s` : "Unavailable"],
              ["Transaction scope", forkStatus?.transactionConsensus ?? "Unavailable"]
            ]}
          />
        </section>
        <section className="explorer-summary-section">
          <div className="explorer-section-heading">
            <h2>Sharechain</h2>
            <ExplorerStateBadge state={sharechain ? "connected" : "unavailable"} />
          </div>
          <ExplorerDefinitionList
            rows={[
              ["Best height", sharechain?.bestShareHeight == null ? "No shares" : formatInt(sharechain.bestShareHeight)],
              ["Stored shares", formatInt(sharechain?.storedShareCount ?? 0)],
              ["Inactive shares", formatInt(sharechain?.inactiveShareCount ?? 0)],
              ["Templates", formatInt(sharechain?.bitcoinWorkTemplateCount ?? 0)],
              ["Snapshot vote roots", formatInt(sharechain?.snapshotVoteRootCount ?? 0)],
              ["Active score", formatIntegerString(sharechain?.activeShareScoreTotal ?? "0")]
            ]}
          />
        </section>
        <section className="explorer-summary-section">
          <div className="explorer-section-heading">
            <h2>Idena snapshot</h2>
            <ExplorerStateBadge state={idena?.state ?? "unavailable"} />
          </div>
          <ExplorerDefinitionList
            rows={[
              ["Snapshot day", idena?.snapshotDay ?? "Unavailable"],
              ["Height", idena?.snapshotHeight == null ? "Unavailable" : formatInt(idena.snapshotHeight)],
              ["Identities", formatInt(idena?.identityCount ?? 0)],
              ["Eligible", formatInt(idena?.eligibleIdentityCount ?? 0)],
              ["Formula", idena?.formulaVersion == null ? "Unavailable" : `v${idena.formulaVersion}`],
              ["Reward coverage", formatCoverage(idena?.rewardSourceCoverage)]
            ]}
          />
        </section>
      </div>

      {overview?.limitations.map((limitation) => (
        <div className="explorer-limitation" key={limitation}>
          <AlertTriangle size={15} />
          <span>{maskIdentifierLikeText(limitation)}</span>
        </div>
      ))}
      {overview?.safetyBoundaries.map((boundary) => (
        <div className="explorer-boundary" key={boundary}>
          <ShieldCheck size={15} />
          <span>{maskIdentifierLikeText(boundary)}</span>
        </div>
      ))}
    </section>
  );
}

function BitcoinHistoryView({
  blocks,
  onInspect,
  overview
}: {
  blocks: ExplorerBitcoinBlockPage;
  onInspect: (item: BitcoinIndexObject<BitcoinBlockData>) => void;
  overview: ExplorerOverview["bitcoinHistory"] | null;
}) {
  return (
    <section className="explorer-view">
      <div className="explorer-section-heading">
        <div>
          <h2>Bitcoin history index</h2>
          <span>Hosted once for the network</span>
        </div>
        <ExplorerStateBadge state={overview?.state ?? "not_configured"} />
      </div>
      <div className="explorer-summary-grid compact">
        <section className="explorer-summary-section">
          <ExplorerDefinitionList
            rows={[
              ["Indexed tip", overview?.indexedTipHeight == null ? "Unavailable" : formatInt(overview.indexedTipHeight)],
              ["Fork parent", overview?.inheritedTipHeight == null ? "Unavailable" : formatInt(overview.inheritedTipHeight)],
              ["Inherited history", overview?.inheritedHistoryReady ? "Ready" : "Syncing or unavailable"],
              ["Participant index", overview?.participantIndexRequired ? "Required" : "Not required"]
            ]}
          />
        </section>
      </div>
      {blocks.items.length === 0 ? (
        <ExplorerEmptyState icon={Database} label="Bitcoin history index is not ready" />
      ) : (
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead>
              <tr>
                <th>Height</th>
                <th>Branch relation</th>
                <th>Block</th>
                <th>Time</th>
                <th>Transactions</th>
                <th>Size</th>
              </tr>
            </thead>
            <tbody>
              {blocks.items.map((block) => (
                <tr key={block.data.id}>
                  <td>{formatInt(block.data.height)}</td>
                  <td><ExplorerStateBadge state={block.forkRelation} /></td>
                  <td>
                    <button className="hash-button" onClick={() => onInspect(block)} type="button">
                      {shortHash(block.data.id)}
                    </button>
                  </td>
                  <td>{formatUnixTime(block.data.timestamp)}</td>
                  <td>{formatInt(block.data.tx_count)}</td>
                  <td>{formatInt(block.data.size)} bytes</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ForkBlocksView({
  loadingMore,
  onInspect,
  onLoadMore,
  page
}: {
  loadingMore: boolean;
  onInspect: (item: ForkBlockSummary) => void;
  onLoadMore: () => Promise<void>;
  page: ExplorerForkBlockPage;
}) {
  return (
    <section className="explorer-view">
      <div className="explorer-section-heading">
        <div>
          <h2>Fork blocks</h2>
          <span>{formatInt(page.total)} stored</span>
        </div>
        <ExplorerStateBadge state={page.state} />
      </div>
      {page.items.length === 0 ? (
        <ExplorerEmptyState icon={Blocks} label={page.state === "not_configured" ? "Fork RPC not configured" : "No fork blocks yet"} />
      ) : (
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead>
              <tr>
                <th>Height</th>
                <th>Status</th>
                <th>Block</th>
                <th>Time</th>
                <th>Phase</th>
                <th>Bits</th>
                <th>PoHW commitment</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((block) => (
                <tr key={block.blockHash}>
                  <td>{formatInt(block.height)}</td>
                  <td><ExplorerStateBadge state={block.active ? "active" : "orphan"} /></td>
                  <td><button className="hash-button" onClick={() => onInspect(block)} type="button">{shortHash(block.blockHash)}</button></td>
                  <td>{formatUnixTime(block.timestamp)}</td>
                  <td>{formatStateLabel(block.difficultyPhase)}</td>
                  <td><code>{block.bits}</code></td>
                  <td><code>{shortHash(block.pohwCommitmentHash)}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page.nextCursor ? (
        <button className="load-more" disabled={loadingMore} onClick={() => void onLoadMore()} type="button">
          {loadingMore ? <RefreshCw className="spin" size={15} /> : <Database size={15} />}
          <span>{loadingMore ? "Loading" : "Load more"}</span>
        </button>
      ) : null}
    </section>
  );
}

function SharechainExplorerView({
  loadingMore,
  onInspect,
  onLoadMore,
  page
}: {
  loadingMore: boolean;
  onInspect: (item: SharechainShareSummary) => void;
  onLoadMore: () => Promise<void>;
  page: ExplorerSharePage;
}) {
  return (
    <section className="explorer-view">
      <div className="explorer-section-heading">
        <div>
          <h2>Sharechain</h2>
          <span>{formatInt(page.total)} stored</span>
        </div>
        <ExplorerStateBadge state="connected" />
      </div>
      {page.items.length === 0 ? (
        <ExplorerEmptyState icon={GitBranch} label="No shares yet" />
      ) : (
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead>
              <tr>
                <th>Height</th>
                <th>Status</th>
                <th>Share</th>
                <th>Miner</th>
                <th>Score</th>
                <th>Template</th>
                <th>Snapshot</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((share) => (
                <tr key={share.shareHash}>
                  <td>{formatInt(share.height)}</td>
                  <td><ExplorerStateBadge state={share.active ? "active" : "inactive"} /></td>
                  <td><button className="hash-button" onClick={() => onInspect(share)} type="button">{shortHash(share.shareHash)}</button></td>
                  <td>{captureIdentifier(share.minerId)}</td>
                  <td>{formatIntegerString(share.hashrateScoreDelta)}</td>
                  <td><code>{shortHash(share.bitcoinTemplateHash)}</code></td>
                  <td>{captureIdentifier(share.idenaSnapshotId)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page.nextCursor ? (
        <button className="load-more" disabled={loadingMore} onClick={() => void onLoadMore()} type="button">
          {loadingMore ? <RefreshCw className="spin" size={15} /> : <Database size={15} />}
          <span>{loadingMore ? "Loading" : "Load more"}</span>
        </button>
      ) : null}
    </section>
  );
}

function IdenaExplorerView({ idena }: { idena: ExplorerIdenaOverview | null }) {
  return (
    <section className="explorer-view">
      <div className="explorer-section-heading">
        <div>
          <h2>Idena snapshot</h2>
          <span>{idena?.snapshotDay ?? "No verified snapshot"}</span>
        </div>
        <ExplorerStateBadge state={idena?.state ?? "unavailable"} />
      </div>
      <div className="idena-explorer-grid">
        <ExplorerDefinitionList
          rows={[
            ["Snapshot height", idena?.snapshotHeight == null ? "Unavailable" : formatInt(idena.snapshotHeight)],
            ["Score root", shortHash(idena?.scoreRoot)],
            ["Identity root", shortHash(idena?.identityRoot)],
            ["Formula version", idena?.formulaVersion == null ? "Unavailable" : `v${idena.formulaVersion}`],
            ["All identities", formatInt(idena?.identityCount ?? 0)],
            ["Eligible identities", formatInt(idena?.eligibleIdentityCount ?? 0)]
          ]}
        />
        <ExplorerDefinitionList
          rows={[
            ["Validation score", formatIntegerString(idena?.validationScoreTotal ?? "0")],
            ["Proposer score", formatIntegerString(idena?.proposerScoreTotal ?? "0")],
            ["Committee score", formatIntegerString(idena?.committeeScoreTotal ?? "0")],
            ["Invitation score ignored", formatIntegerString(idena?.ignoredInvitationScoreTotal ?? "0")],
            ["Reward coverage", formatCoverage(idena?.rewardSourceCoverage)],
            ["Address exposure", "Aggregate only"]
          ]}
        />
      </div>
    </section>
  );
}

function ExplorerSearchPanel({
  inheritedSpendingEnabled,
  onInspect,
  onLoadMore,
  result,
  state
}: {
  inheritedSpendingEnabled: boolean;
  onInspect: (value: string) => void;
  onLoadMore: (target: ExplorerLoadMoreTarget) => void;
  result: ExplorerSearchResult | null;
  state: "idle" | "searching" | "invalid" | "not-found" | "error";
}) {
  if (!result) {
    const messages = {
      idle: "",
      searching: "Searching",
      invalid: "Enter a height, 64-character hash, transaction ID or Bitcoin address",
      "not-found": "No matching block, transaction, share or address",
      error: "Search unavailable"
    } as const;
    return (
      <section className={`explorer-alert ${state === "error" || state === "invalid" ? "error" : ""}`}>
        {state === "searching" ? <RefreshCw className="spin" size={17} /> : <Search size={17} />}
        <strong>{messages[state]}</strong>
      </section>
    );
  }
  if (result.kind === "block") {
    const block = result.item;
    return (
      <section className="explorer-detail">
        <div className="explorer-section-heading">
          <div><h2>Fork block {formatInt(block.height)}</h2><code>{captureIdentifier(block.blockHash)}</code></div>
          <ExplorerStateBadge state={block.active ? "active" : "orphan"} />
        </div>
        <ExplorerDefinitionList rows={[
          ["Previous block", captureIdentifier(block.previousBlockHash)],
          ["Timestamp", formatUnixTime(block.timestamp, true)],
          ["Difficulty", `${formatStateLabel(block.difficultyPhase)} / ${block.bits}`],
          ["Cumulative work", captureIdentifier(block.cumulativeWork)],
          ["Transactions", formatInt(block.transactionCount)],
          ["Coinbase txid", captureIdentifier(block.coinbaseTxid)],
          ["Coinbase", `${formatSats(block.coinbaseValueSats)} sats / ${block.coinbaseOutputCount} outputs`],
          ["PoHW commitment", captureIdentifier(block.pohwCommitmentHash, "Not present")],
          ["Size", `${formatInt(block.sizeBytes)} bytes / ${formatInt(block.weightWu)} WU`],
          ["Merkle root", captureIdentifier(block.merkleRoot)]
        ]} longValues />
        <div className="explorer-section-heading subsection-heading">
          <h3>Transactions</h3>
          <span>{formatInt(result.transactions?.total ?? block.transactionCount)} total</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Transaction</th><th>Type</th><th>Output</th><th>Fee</th></tr></thead>
            <tbody>
              {(result.transactions?.items ?? []).map((transaction) => (
                <tr key={transaction.txid}>
                  <td>{formatInt(transaction.transactionIndex)}</td>
                  <td><button className="hash-button" onClick={() => onInspect(transaction.txid)} type="button">{shortHash(transaction.txid)}</button></td>
                  <td>{transaction.coinbase ? "Coinbase" : "Standard"}</td>
                  <td>{formatSats(transaction.totalOutputSats)} sats</td>
                  <td>{transaction.feeSats == null ? "N/A" : `${formatSats(transaction.feeSats)} sats`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.transactions?.nextCursor != null ? (
          <button className="load-more" onClick={() => onLoadMore("fork-block-transactions")} type="button">
            <Database size={15} /><span>Load more transactions</span>
          </button>
        ) : null}
      </section>
    );
  }
  if (result.kind === "fork-transaction") {
    const transaction = result.item;
    return (
      <section className="explorer-detail">
        <div className="explorer-section-heading">
          <div><h2>Fork transaction</h2><code>{captureIdentifier(transaction.txid)}</code></div>
          <ExplorerStateBadge state={transaction.active ? "active" : "orphan"} />
        </div>
        <ExplorerDefinitionList rows={[
          ["Block", `${formatInt(transaction.height)} / ${captureIdentifier(transaction.blockHash)}`],
          ["Type", transaction.coinbase ? "Coinbase" : "Standard transaction"],
          ["Version / locktime", `${transaction.version} / ${transaction.lockTime}`],
          ["Inputs / outputs", `${formatInt(transaction.inputCount)} / ${formatInt(transaction.outputCount)}`],
          ["Input value", transaction.totalInputSats == null ? "Not applicable" : `${formatSats(transaction.totalInputSats)} sats`],
          ["Output value", `${formatSats(transaction.totalOutputSats)} sats`],
          ["Fee", transaction.feeSats == null ? "Not applicable" : `${formatSats(transaction.feeSats)} sats`],
          ["Size", `${formatInt(transaction.sizeBytes)} bytes / ${formatInt(transaction.weightWu)} WU`],
          ["Witness txid", captureIdentifier(transaction.wtxid)]
        ]} longValues />
        <div className="explorer-section-heading subsection-heading">
          <h3>Inputs</h3>
          <span>{formatInt(transaction.inputs.length)} inputs</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Previous output</th><th>Value</th><th>Address or script</th><th>Witness</th></tr></thead>
            <tbody>
              {transaction.inputs.map((input) => (
                <tr key={`${transaction.txid}:vin:${input.vin}`}>
                  <td>{input.vin}</td>
                  <td>{input.coinbase ? "Coinbase" : <button className="hash-button" onClick={() => { if (input.previousTxid) onInspect(input.previousTxid); }} type="button">{shortHash(input.previousTxid)}:{input.previousVout}</button>}</td>
                  <td>{input.previousOutput ? `${formatSats(input.previousOutput.valueSats)} sats` : "N/A"}</td>
                  <td>
                    <code>
                      {captureIdentifier(
                        input.previousOutput?.address
                          ?? input.previousOutput?.scriptHash
                          ?? shortHash(input.scriptSigHex)
                      )}
                    </code>
                  </td>
                  <td>{formatInt(input.witness.length)} items</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="explorer-section-heading subsection-heading">
          <h3>Outputs</h3>
          <span>{formatInt(transaction.outputs.length)} outputs</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Value</th><th>Type</th><th>Address or script hash</th><th>State</th></tr></thead>
            <tbody>
              {transaction.outputs.map((output) => (
                <tr key={`${transaction.txid}:${output.vout}`}>
                  <td>{output.vout}</td>
                  <td>{formatSats(output.valueSats)} sats</td>
                  <td>{formatStateLabel(output.scriptType)}</td>
                  <td><code>{captureIdentifier(output.address ?? output.scriptHash)}</code></td>
                  <td><ExplorerStateBadge state={transaction.spendStateComplete ? (output.spentBy ? "spent" : "unspent") : "unknown"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    );
  }
  if (result.kind === "bitcoin-block") {
    const block = result.item;
    return (
      <section className="explorer-detail">
        <div className="explorer-section-heading">
          <div><h2>Bitcoin history block {formatInt(block.data.height)}</h2><code>{captureIdentifier(block.data.id)}</code></div>
          <ExplorerStateBadge state={block.forkRelation} />
        </div>
        <ExplorerDefinitionList rows={[
          ["Previous block", captureIdentifier(block.data.previousblockhash, "Genesis")],
          ["Timestamp", formatUnixTime(block.data.timestamp, true)],
          ["Transactions", formatInt(block.data.tx_count)],
          ["Version / nonce", `${block.data.version} / ${block.data.nonce}`],
          ["Size", `${formatInt(block.data.size)} bytes / ${formatInt(block.data.weight)} WU`],
          ["Merkle root", captureIdentifier(block.data.merkle_root)]
        ]} longValues />
        <div className="explorer-section-heading subsection-heading">
          <h3>Transactions</h3>
          <span>{formatInt(block.data.tx_count)} total</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Transaction</th><th>Inputs</th><th>Outputs</th><th>Fee</th></tr></thead>
            <tbody>
              {(result.transactions?.items ?? []).map((transaction, offset) => (
                <tr key={transaction.data.txid}>
                  <td>{formatInt((result.transactions?.startIndex ?? 0) + offset)}</td>
                  <td><button className="hash-button" onClick={() => onInspect(transaction.data.txid)} type="button">{shortHash(transaction.data.txid)}</button></td>
                  <td>{formatInt(transaction.data.vin.length)}</td>
                  <td>{formatInt(transaction.data.vout.length)}</td>
                  <td>{formatSats(transaction.data.fee)} sats</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.transactions?.nextCursor != null ? (
          <button className="load-more" onClick={() => onLoadMore("bitcoin-block-transactions")} type="button">
            <Database size={15} /><span>Load more transactions</span>
          </button>
        ) : null}
      </section>
    );
  }
  if (result.kind === "bitcoin-transaction") {
    const transaction = result.item;
    return (
      <section className="explorer-detail">
        <div className="explorer-section-heading">
          <div><h2>Bitcoin history transaction</h2><code>{captureIdentifier(transaction.data.txid)}</code></div>
          <ExplorerStateBadge state={transaction.forkRelation} />
        </div>
        <ExplorerDefinitionList rows={[
          ["Confirmation", transaction.data.status.confirmed ? `Height ${formatInt(transaction.data.status.block_height ?? 0)}` : "Unconfirmed"],
          ["Block", captureIdentifier(transaction.data.status.block_hash, "Not confirmed")],
          ["Version / locktime", `${transaction.data.version} / ${transaction.data.locktime}`],
          ["Inputs / outputs", `${formatInt(transaction.data.vin.length)} / ${formatInt(transaction.data.vout.length)}`],
          ["Fee", `${formatSats(transaction.data.fee)} sats`],
          ["Size", `${formatInt(transaction.data.size)} bytes / ${formatInt(transaction.data.weight)} WU`]
        ]} longValues />
        <div className="explorer-section-heading subsection-heading">
          <h3>Inputs</h3>
          <span>{formatInt(transaction.data.vin.length)} inputs</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Previous output</th><th>Value</th><th>Address or script</th><th>Witness</th></tr></thead>
            <tbody>
              {transaction.data.vin.map((input, index) => (
                <tr key={`${transaction.data.txid}:vin:${index}`}>
                  <td>{index}</td>
                  <td>{input.is_coinbase ? "Coinbase" : <button className="hash-button" onClick={() => { if (input.txid) onInspect(input.txid); }} type="button">{shortHash(input.txid)}:{input.vout}</button>}</td>
                  <td>{input.prevout ? `${formatSats(input.prevout.value)} sats` : "N/A"}</td>
                  <td>
                    <code>
                      {captureIdentifier(
                        input.prevout?.scriptpubkey_address
                          ?? shortHash(input.prevout?.scriptpubkey ?? input.scriptsig)
                      )}
                    </code>
                  </td>
                  <td>{formatInt(input.witness?.length ?? 0)} items</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="explorer-section-heading subsection-heading">
          <h3>Outputs</h3>
          <span>{formatInt(transaction.data.vout.length)} outputs</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Index</th><th>Value</th><th>Type</th><th>Address or script</th><th>State</th></tr></thead>
            <tbody>
              {transaction.data.vout.map((output, index) => (
                <tr key={`${transaction.data.txid}:${index}`}>
                  <td>{index}</td>
                  <td>{formatSats(output.value)} sats</td>
                  <td>{formatStateLabel(output.scriptpubkey_type)}</td>
                  <td><code>{captureIdentifier(output.scriptpubkey_address ?? shortHash(output.scriptpubkey))}</code></td>
                  <td><ExplorerStateBadge state={result.outspends ? (result.outspends.items[index]?.spent ? "spent" : "unspent") : "unknown"} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    );
  }
  if (result.kind === "address") {
    const bitcoinStats = result.bitcoin?.data.chain_stats;
    return (
      <section className="explorer-detail">
        <div className="explorer-section-heading">
          <div><h2>Bitcoin address</h2><code>{captureIdentifier(result.address)}</code></div>
          <ExplorerStateBadge state={result.fork ? "fork_activity" : result.bitcoin?.forkRelation ?? "not_found"} />
        </div>
        <div className="idena-explorer-grid">
          <ExplorerDefinitionList rows={[
            ["Fork transactions", formatInt(result.fork?.transactionCount ?? 0)],
            ["Fork funded outputs", formatInt(result.fork?.fundedOutputCount ?? 0)],
            ["Fork spent outputs", formatInt(result.fork?.spentOutputCount ?? 0)],
            ["Fork-created UTXOs", `${formatSats(result.fork?.balanceSats ?? 0)} sats`],
            ["Inherited inputs consumed", `${formatInt(result.fork?.inheritedInputCount ?? 0)} / ${formatSats(result.fork?.inheritedInputTotalSats ?? 0)} sats`],
            ["Fork first height", result.fork?.firstSeenHeight == null ? "No activity" : formatInt(result.fork.firstSeenHeight)],
            ["Fork last height", result.fork?.lastSeenHeight == null ? "No activity" : formatInt(result.fork.lastSeenHeight)]
          ]} />
          <ExplorerDefinitionList rows={[
            ["Bitcoin history transactions", formatInt(bitcoinStats?.tx_count ?? 0)],
            ["Bitcoin history funded", `${formatSats(bitcoinStats?.funded_txo_sum ?? 0)} sats`],
            ["Bitcoin history spent", `${formatSats(bitcoinStats?.spent_txo_sum ?? 0)} sats`],
            ["Current mainnet balance", `${formatSats((bitcoinStats?.funded_txo_sum ?? 0) - (bitcoinStats?.spent_txo_sum ?? 0))} sats`],
            ["Fork spendability", inheritedSpendingEnabled ? "Replay-protected inherited spends enabled" : "Inherited outputs locked"],
            ["Participant index", "Not required"]
          ]} />
        </div>
        <div className="explorer-section-heading subsection-heading">
          <h3>Fork transactions</h3>
          <span>{formatInt(result.forkTransactions?.total ?? 0)} total</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Height</th><th>Transaction</th><th>Type</th><th>Output</th><th>Fee</th></tr></thead>
            <tbody>
              {(result.forkTransactions?.items ?? []).map((transaction) => (
                <tr key={`fork:${transaction.txid}`}>
                  <td>{formatInt(transaction.height)}</td>
                  <td><button className="hash-button" onClick={() => onInspect(transaction.txid)} type="button">{shortHash(transaction.txid)}</button></td>
                  <td>{transaction.coinbase ? "Coinbase" : "Standard"}</td>
                  <td>{formatSats(transaction.totalOutputSats)} sats</td>
                  <td>{transaction.feeSats == null ? "N/A" : `${formatSats(transaction.feeSats)} sats`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.forkTransactions?.nextCursor != null ? (
          <button className="load-more" onClick={() => onLoadMore("fork-address-transactions")} type="button">
            <Database size={15} /><span>Load more fork transactions</span>
          </button>
        ) : null}
        <div className="explorer-section-heading subsection-heading">
          <h3>Fork UTXOs</h3>
          <span>{formatInt(result.forkUtxos?.total ?? 0)} total</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Height</th><th>Outpoint</th><th>Value</th><th>Type</th><th>Source</th></tr></thead>
            <tbody>
              {(result.forkUtxos?.items ?? []).map((utxo) => (
                <tr key={`fork:${utxo.txid}:${utxo.vout}`}>
                  <td>{formatInt(utxo.height)}</td>
                  <td><button className="hash-button" onClick={() => onInspect(utxo.txid)} type="button">{shortHash(utxo.txid)}:{utxo.vout}</button></td>
                  <td>{formatSats(utxo.valueSats)} sats</td>
                  <td>{formatStateLabel(utxo.scriptType)}</td>
                  <td>{utxo.coinbase ? "Coinbase" : "Transaction"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.forkUtxos?.nextCursor != null ? (
          <button className="load-more" onClick={() => onLoadMore("fork-address-utxos")} type="button">
            <Database size={15} /><span>Load more fork UTXOs</span>
          </button>
        ) : null}
        <div className="explorer-section-heading subsection-heading">
          <h3>Bitcoin history transactions</h3>
          <span>{formatInt(result.bitcoinTransactions?.items.length ?? 0)} loaded</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Status</th><th>Transaction</th><th>Inputs</th><th>Outputs</th><th>Fee</th></tr></thead>
            <tbody>
              {(result.bitcoinTransactions?.items ?? []).map((transaction) => (
                <tr key={`bitcoin:${transaction.data.txid}`}>
                  <td><ExplorerStateBadge state={transaction.forkRelation} /></td>
                  <td><button className="hash-button" onClick={() => onInspect(transaction.data.txid)} type="button">{shortHash(transaction.data.txid)}</button></td>
                  <td>{formatInt(transaction.data.vin.length)}</td>
                  <td>{formatInt(transaction.data.vout.length)}</td>
                  <td>{formatSats(transaction.data.fee)} sats</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.bitcoinTransactions?.nextCursor ? (
          <button className="load-more" onClick={() => onLoadMore("bitcoin-address-transactions")} type="button">
            <Database size={15} /><span>Load more Bitcoin transactions</span>
          </button>
        ) : null}
        <div className="explorer-section-heading subsection-heading">
          <h3>Current Bitcoin mainnet UTXOs</h3>
          <span>Read-only history view</span>
        </div>
        <div className="explorer-table-wrap">
          <table className="explorer-table">
            <thead><tr><th>Height</th><th>Outpoint</th><th>Value</th><th>Relation</th><th>Fork spendability</th></tr></thead>
            <tbody>
              {(result.bitcoinUtxos ?? []).map((utxo) => (
                <tr key={`bitcoin:${utxo.data.txid}:${utxo.data.vout}`}>
                  <td>{utxo.data.status.block_height == null ? "Mempool" : formatInt(utxo.data.status.block_height)}</td>
                  <td><button className="hash-button" onClick={() => onInspect(utxo.data.txid)} type="button">{shortHash(utxo.data.txid)}:{utxo.data.vout}</button></td>
                  <td>{formatSats(utxo.data.value)} sats</td>
                  <td><ExplorerStateBadge state={utxo.forkRelation} /></td>
                  <td>Locked</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    );
  }
  const share = result.item;
  return (
    <section className="explorer-detail">
      <div className="explorer-section-heading">
        <div><h2>Share {formatInt(share.height)}</h2><code>{captureIdentifier(share.shareHash)}</code></div>
        <ExplorerStateBadge state={share.active ? "active" : "inactive"} />
      </div>
      <ExplorerDefinitionList rows={[
        ["Miner", captureIdentifier(share.minerId)],
        ["Parent share", captureIdentifier(share.parentShareHash)],
        ["Bitcoin template", captureIdentifier(share.bitcoinTemplateHash)],
        ["Work hash", captureIdentifier(share.workHash)],
        ["Target", captureIdentifier(share.target)],
        ["Score delta", formatIntegerString(share.hashrateScoreDelta)],
        ["Cumulative score", formatIntegerString(share.cumulativeScore ?? "0")],
        ["Idena snapshot", captureIdentifier(share.idenaSnapshotId)],
        ["Snapshot proof root", captureIdentifier(share.idenaSnapshotProofRoot)]
      ]} longValues />
    </section>
  );
}

function ExplorerDefinitionList({ rows, longValues = false }: { rows: [string, string][]; longValues?: boolean }) {
  return (
    <dl className={longValues ? "explorer-definition-list long-values" : "explorer-definition-list"}>
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{maskIdentifierLikeText(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function ExplorerStateBadge({ state }: { state: string }) {
  const normalized = state.replaceAll("_", "-");
  return <span className={`explorer-state ${normalized}`}>{formatStateLabel(state)}</span>;
}

function ExplorerEmptyState({ icon: Icon, label }: { icon: typeof Activity; label: string }) {
  return (
    <div className="explorer-empty">
      <Icon size={22} />
      <strong>{label}</strong>
    </div>
  );
}

function DashboardIntro({
  onStartPledge,
  participation
}: {
  onStartPledge: () => void;
  participation: ParticipationStatus;
}) {
  return (
    <section className="intro-panel" id="overview">
      <div className="intro-copy">
        <div className="intro-title-row">
          <h1>Mine Bitcoin with your Brain</h1>
          <div className="why-pool">
            <button
              aria-describedby="why-pool-popover"
              aria-label="Why this pool exists"
              className="why-pool-trigger"
              type="button"
            >
              <CircleHelp size={18} aria-hidden="true" />
            </button>
            <div className="why-pool-popover" id="why-pool-popover" role="tooltip">
              <strong>Why this pool exists</strong>
              <p>
                Since around 2010/11, normal computers stopped being competitive for Bitcoin
                mining. ASICs still do the hashing here, but the pool adds a human-work share:
                solve a small human puzzle, join the pool, and earn a reward share when a block is
                found.
              </p>
              <p>
                The task is easy for humans and takes only a few minutes to create or solve. Cheap
                AI tends to make mistakes, while capable AI has a cost, so human brain work can
                compete in this part of the reward split.
              </p>
            </div>
          </div>
        </div>
        <p>
          PoHW reopens Bitcoin mining to people: solve puzzles that are cheap for human brains and
          costly for AI.
        </p>
      </div>

      <div className={participation.isReady ? "intro-status ready" : "intro-status pending"}>
        {participation.isReady ? <CheckCircle2 size={18} /> : <KeyRound size={18} />}
        <div>
          <span>{participation.isReady ? "Ready" : "Start here"}</span>
          <strong>
            {participation.isReady ? "Puzzle + miner linked" : "Prove human ownership"}
          </strong>
          <small>
            {participation.isReady
              ? "Your shares can earn payout."
              : "Then point your miner."}
          </small>
        </div>
      </div>

      <div className="intro-actions">
        <button className="primary-action" onClick={onStartPledge} type="button">
          {participation.isReady ? <CheckCircle2 size={17} /> : <KeyRound size={17} />}
          <span>{participation.isReady ? "View route" : "Join pool"}</span>
        </button>
      </div>
    </section>
  );
}

function SourceNotice({ source }: { source: string }) {
  const demo = source === "demo-fallback";
  const auth = source === "dashboard-auth-required";
  return (
    <section
      className={auth ? "source-notice auth" : demo ? "source-notice demo" : "source-notice offline"}
    >
      <AlertTriangle size={17} />
      <div>
        <strong>{demo ? "Demo mode" : auth ? "Dashboard token required" : "Local node API offline"}</strong>
        <span>
          {demo
            ? "Numbers are sample data. Disable VITE_POHW_DASHBOARD_DEMO for verification."
            : auth
              ? "Start the loopback dashboard UI wrapper with its runtime token file before trusting payout, pledge, or sync status."
              : "Start the local dashboard API before trusting payout, pledge, or sync status."}
        </span>
      </div>
    </section>
  );
}

function MiningSnapshot({
  blockView,
  expected30dView,
  participation,
  totals
}: {
  blockView: RewardView;
  expected30dView: RewardView;
  participation: ParticipationStatus;
  totals: ContributionTotals;
}) {
  const { account, source } = useDashboardData();
  const hasHashrate = hasLiveHashrateEstimate(account);
  const hasChance = account.pool.chance30d > 0;
  const isLiveEstimate = hasHashrate && source === "local-p2pool-node";
  const estimateLabel = isLiveEstimate
    ? "Live hashrate estimate"
    : source === "demo-fallback" && hasHashrate
      ? "Sample estimate"
      : hasHashrate
        ? "Local estimate"
        : "Awaiting accepted shares";
  const shareQuality = acceptedSharePercent(
    account.sharechain.acceptedShares,
    account.sharechain.staleShares
  );
  const userMeasurementSeconds = account.sharechain.windows?.["24h"]?.userMeasurementSeconds ?? 0;
  const metrics: {
    detail: string;
    icon: LucideIcon;
    label: string;
    value: string;
  }[] = [
    {
      detail: hasHashrate
        ? `${formatPercent(account.sharechain.relativeHashrateShare * 100, 3)} of active score; ${formatMeasurementSpan(userMeasurementSeconds)} observed`
        : "Measured after accepted sharechain work",
      icon: Gauge,
      label: "Your hashrate",
      value: formatHashrateOrPending(account.sharechain.userHashrateThs)
    },
    {
      detail: account.pool.bitcoinNetworkHashrateEhs > 0
        ? `Compared with ${formatInt(account.pool.bitcoinNetworkHashrateEhs)} EH/s Bitcoin network`
        : account.pool.miningEstimateSource ?? "Fork mining estimate unavailable",
      icon: Network,
      label: "Pool hashrate",
      value: formatHashrateOrPending(account.sharechain.poolHashrateThs)
    },
    {
      detail: account.sharechain.acceptedShares > 0
        ? `${formatPercent(shareQuality, 2)} accepted; ${formatInt(account.sharechain.staleShares)} stale`
        : "No accepted shares recorded yet",
      icon: Activity,
      label: "Accepted work",
      value: `${formatInt(account.sharechain.acceptedShares)} shares`
    },
    {
      detail: "50% Bitcoin work + 50% verified human-work score",
      icon: Percent,
      label: "Your payout weight",
      value: formatPercent(totals.combinedPercent, 3)
    }
  ];
  const chanceWindows = [
    ["24 hours", chancePercentForDays(account.pool.chance30d, 1)],
    ["7 days", chancePercentForDays(account.pool.chance30d, 7)],
    ["30 days", chancePercentForDays(account.pool.chance30d, 30)],
    ["1 year", chancePercentForDays(account.pool.chance30d, 365)]
  ] as const;
  const payoutRoute = blockView.direct ? "Direct coinbase payout" : "FROST vault claim";
  const blockDisplaySats = blockView.netSats ?? blockView.grossSats;
  const expected30dDisplaySats = expected30dView.netSats ?? expected30dView.grossSats;
  const blockAmountLabel = blockView.netSats === null
    ? "gross before withdrawal fee"
    : "estimated net";

  return (
    <section className="mining-snapshot" aria-labelledby="mining-snapshot-title">
      <header className="mining-snapshot-heading">
        <div>
          <span className="section-kicker">Your mining outlook</span>
          <h2 id="mining-snapshot-title">Hashrate, odds and payout at a glance</h2>
          <p>Live sharechain measurements and transparent probability, not a guaranteed return.</p>
        </div>
        <span className={isLiveEstimate ? "snapshot-state live" : "snapshot-state waiting"}>
          <span className="state-dot" />
          {estimateLabel}
        </span>
      </header>

      <div className="mining-snapshot-grid">
        <section className="mining-reward" aria-label="Potential block reward">
          <div className="mining-reward-label">
            <Bitcoin size={20} />
            <span>{participation.isReady ? "Your reward if the pool finds a block" : "Potential reward after registration"}</span>
          </div>
          <strong>{formatBtcFromSats(blockDisplaySats)} BTC</strong>
          <span className="mining-reward-sats">{formatSats(blockDisplaySats)} sats {blockAmountLabel}</span>
          <div className="mining-reward-equation" aria-label="Reward calculation">
            <span>{formatBtc(blockView.blockValueBtc)} BTC block value</span>
            <span>x {formatPercent(totals.combinedPercent, 3)} payout weight</span>
            <strong>= {formatSats(blockView.blockGrossSats)} sats gross</strong>
          </div>
          <div className={participation.isReady ? "mining-route active" : "mining-route pending"}>
            {participation.isReady ? <CheckCircle2 size={16} /> : <KeyRound size={16} />}
            <span>{participation.isReady ? payoutRoute : "Registration required before rewards are active"}</span>
          </div>
        </section>

        <section className="mining-capacity" aria-label="Mining capacity">
          <div className="mining-column-heading">
            <Gauge size={18} />
            <div>
              <span>Current capability</span>
              <strong>Your miner versus the pool</strong>
            </div>
          </div>
          <dl className="capacity-grid">
            {metrics.map((metric) => (
              <div key={metric.label}>
                <metric.icon size={17} />
                <dt>{metric.label}</dt>
                <dd>{metric.value}</dd>
                <small>{metric.detail}</small>
              </div>
            ))}
          </dl>
        </section>

        <section className="mining-chance" aria-label="Block probability">
          <div className="mining-column-heading">
            <Clock3 size={18} />
            <div>
              <span>Pool block chance</span>
              <strong>{hasChance ? `${formatChancePercent(account.pool.chance30d)} in 30 days` : "Not available yet"}</strong>
            </div>
          </div>
          <div className="chance-grid">
            {chanceWindows.map(([label, chance]) => (
              <div key={label}>
                <span>{label}</span>
                <strong>{hasChance ? formatChancePercent(chance) : "Pending"}</strong>
              </div>
            ))}
          </div>
          <dl className="chance-summary">
            <div>
              <dt>Expected block interval</dt>
              <dd>{account.pool.expectedBlockInterval}</dd>
            </div>
            <div>
              <dt>Your 30 day {expected30dView.netSats === null ? "gross estimate" : "expected value"}</dt>
              <dd>{formatBtcFromSats(expected30dDisplaySats)} BTC</dd>
            </div>
          </dl>
          <p>The chance applies to the whole pool. Your payout then follows the weight shown at left.</p>
        </section>
      </div>

      <div className="mining-disclosure">
        <AlertTriangle size={16} />
        <span>
          Experiment fork BTC has no promised market value. Hardware, electricity, tax and downtime
          are excluded, so this is a possible reward estimate, not profit.
        </span>
      </div>
    </section>
  );
}

function JourneyStrip({ participation, view }: { participation: ParticipationStatus; view: RewardView }) {
  const { account } = useDashboardData();
  const items = [
    {
      icon: ShieldCheck,
      label: "Human proof",
      value: participation.isReady ? `${account.identity.status} pledged` : "Pledge pending",
      state: participation.isReady ? "connected" : "pending"
    },
    {
      icon: Bitcoin,
      label: "Mining work",
      value: miningWorkValue(account),
      state: participation.isReady ? "connected" : "muted"
    },
    {
      icon: Wallet,
      label: "Payout route",
      value: participation.isReady
        ? view.direct
          ? `Direct coinbase, rank #${account.payout.directRank}`
          : "Vault withdrawal claim"
        : "Not active until pledge",
      state: participation.isReady ? (view.direct ? "connected" : "pending") : "muted"
    }
  ];

  return (
    <section className="journey-strip">
      {items.map((item) => (
        <div className={`journey-item ${item.state}`} key={item.label}>
          <item.icon size={17} />
          <div>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        </div>
      ))}
    </section>
  );
}

function Navigation({
  activeSection,
  activeView,
  onNavigate,
  onViewChange,
  participantDashboardEnabled
}: {
  activeSection: SectionId;
  activeView: AppView;
  onNavigate: (sectionId: SectionId, revealAudit?: boolean) => void;
  onViewChange: (view: AppView) => void;
  participantDashboardEnabled: boolean;
}) {
  const items: {
    icon: typeof Activity;
    label: string;
    sectionId: SectionId;
    revealAudit: boolean;
  }[] = [
    { icon: Activity, label: "Overview", sectionId: "overview", revealAudit: false },
    { icon: KeyRound, label: "Join", sectionId: "next-step", revealAudit: false },
    { icon: SlidersHorizontal, label: "Details", sectionId: "audit-numbers", revealAudit: true }
  ];

  return (
    <aside className="nav-rail">
      <div className="brand">
        <div className="brand-mark">
          <Brain size={18} />
        </div>
        <span>PoHW Network</span>
      </div>
      <nav>
        <button
          aria-current={activeView === "governance" ? "page" : undefined}
          aria-label="Open software governance"
          className={activeView === "governance" ? "nav-item active" : "nav-item"}
          onClick={() => onViewChange("governance")}
          title="Governance"
          type="button"
        >
          <GitBranch size={17} />
          <span>Governance</span>
        </button>
        <button
          aria-current={activeView === "explorer" ? "page" : undefined}
          aria-label="Open network explorer"
          className={activeView === "explorer" ? "nav-item active" : "nav-item"}
          onClick={() => onViewChange("explorer")}
          title="Explorer"
          type="button"
        >
          <Blocks size={17} />
          <span>Explorer</span>
        </button>
        {participantDashboardEnabled ? items.map((item) => (
          <button
            aria-current={activeView === "dashboard" && activeSection === item.sectionId ? "page" : undefined}
            aria-label={`Go to ${item.label}`}
            className={activeView === "dashboard" && activeSection === item.sectionId ? "nav-item active" : "nav-item"}
            key={item.label}
            onClick={() => {
              onViewChange("dashboard");
              onNavigate(item.sectionId, item.revealAudit);
            }}
            title={item.label}
            type="button"
          >
            <item.icon size={17} />
            <span>{item.label}</span>
          </button>
        )) : null}
      </nav>
      <div className="nav-footer">
        <HardDrive size={16} />
        <span>Hosted + local</span>
      </div>
    </aside>
  );
}

function TopBar({
  activeView,
  explorerOverview,
  explorerState,
  governance,
  governanceState
}: {
  activeView: AppView;
  explorerOverview: ExplorerOverview | null;
  explorerState: ExplorerLoadState;
  governance: GovernanceDashboardResponse | null;
  governanceState: ExplorerLoadState;
}) {
  const { serviceStatuses } = useDashboardData();
  const explorerStatuses: ServiceStatus[] = [
    {
      label: "Fork",
      state: explorerOverview?.fork.state === "connected" ? "connected" : "warning",
      detail: explorerOverview?.fork.status ? `height ${formatInt(explorerOverview.fork.status.tipHeight)}` : "unavailable"
    },
    {
      label: "Sharechain",
      state: explorerOverview ? "connected" : "warning",
      detail: explorerOverview ? `${formatInt(explorerOverview.sharechain.activeShareCount)} active` : "unavailable"
    },
    {
      label: "Idena",
      state: explorerOverview?.idena.state === "verified_snapshot" ? "connected" : "pending",
      detail: explorerOverview?.idena.snapshotHeight == null ? "no snapshot" : `height ${formatInt(explorerOverview.idena.snapshotHeight)}`
    },
    {
      label: "API",
      state: explorerState === "ready" ? "connected" : explorerState === "loading" ? "syncing" : "warning",
      detail: explorerState
    }
  ];
  const governanceStatuses: ServiceStatus[] = [
    {
      label: "Governance snapshot",
      state: governance?.status === "operator-validated-local-snapshot" ? "warning" : governanceState === "loading" ? "syncing" : "pending",
      detail: governance?.status === "operator-validated-local-snapshot" ? "operator-local / structurally checked" : governanceState
    },
    {
      label: "Canonical CID",
      state: governance?.currentCanonicalEcosystemCid ? "warning" : "pending",
      detail: shortHash(governance?.currentCanonicalEcosystemCid)
    },
    {
      label: "Proposals",
      state: governance ? "warning" : "pending",
      detail: governance ? governance.proposals.length + " tracked" : "unavailable"
    },
    {
      label: "Mode",
      state: "warning",
      detail: "experimental / no-value"
    }
  ];
  const statuses = activeView === "explorer"
    ? explorerStatuses
    : activeView === "governance"
      ? governanceStatuses
      : serviceStatuses;
  return (
    <header className="top-bar">
      <div className="network-title">
        <Network size={18} />
        <span>proof of human work pool</span>
      </div>
      <div className="service-row">
        {statuses.map((status) => (
          <div className="service-pill" key={status.label}>
            <span className={`state-dot ${status.state}`} />
            <span className="service-label">{status.label}</span>
            <span className="service-detail">{maskIdentifierLikeText(status.detail)}</span>
          </div>
        ))}
      </div>
    </header>
  );
}

function RewardForecast({
  onProspectModeChange,
  participation,
  prospectMode,
  view
}: {
  onProspectModeChange: (mode: ProspectMode) => void;
  participation: ParticipationStatus;
  prospectMode: ProspectMode;
  view: RewardView;
}) {
  const { account } = useDashboardData();
  const isExpectedValue = prospectMode === "30d-ev";
  const displaySats = view.netSats ?? view.grossSats;
  const amountLabel = view.netSats === null
    ? isExpectedValue
      ? "30-day gross estimate before withdrawal fee"
      : "gross before withdrawal fee"
    : isExpectedValue
      ? "30-day expected value"
      : "estimated net";
  const routeCopy = view.direct
    ? `Direct coinbase payout, current unpaid rank #${account.payout.directRank}`
    : "Vault claim, manual withdrawal needed";
  const expectedBlocks30d = account.pool.expectedBlocks30d
    ?? expectedBlocksForChancePercent(account.pool.chance30d);
  const headline = isExpectedValue
    ? participation.isReady
      ? "30 Day Expected Value"
      : "Potential 30 Day EV"
    : participation.isReady
      ? "If A Bitcoin Block Lands Now"
      : "Potential Block Payout";

  return (
    <section className="forecast-panel" id="reward-forecast">
      <div className="forecast-heading">
        <div className="forecast-icon">
          <Bitcoin size={24} />
        </div>
        <div>
          <h2>{headline}</h2>
          <p>
            {!participation.isReady
              ? "Estimate only. Complete the pledge before these shares can earn payout."
              : isExpectedValue
                ? "Your block-now claim multiplied by the current 30 day expected block count."
                : "Block value multiplied by your combined 50/50 reward weight."}
          </p>
        </div>
      </div>

      <div className="forecast-controls">
        <span>Estimate</span>
        <SegmentedControl<ProspectMode>
          value={prospectMode}
          onChange={onProspectModeChange}
          options={[
            { value: "block-now", label: "If block found" },
            { value: "30d-ev", label: "30 day EV" }
          ]}
        />
      </div>

      <div className="forecast-amount">
        <strong>{formatBtcFromSats(displaySats)} BTC</strong>
        <span>{formatSats(displaySats)} sats {amountLabel}</span>
      </div>

      <div className="forecast-equation">
        <span>{formatBtc(view.blockValueBtc)} BTC block</span>{" "}
        <span>x {formatPercent(account.payout.combinedRewardWeight * 100, 3)} share</span>{" "}
        {isExpectedValue ? (
          <>
            <span>x {formatExpectedBlocks(expectedBlocks30d)} expected blocks / 30d</span>{" "}
          </>
        ) : null}
        <strong>= {formatBtcFromSats(displaySats)} BTC</strong>
      </div>

      <div className="forecast-sats">
        {formatSats(displaySats)} sats {amountLabel}
      </div>

      <div className="forecast-sats">
        Reward source: {account.payout.blockRewardSource ?? "not reported by the local API"}
      </div>

      <div className={participation.isReady ? "forecast-route" : "forecast-route warning"}>
        {participation.isReady ? <CheckCircle2 size={17} /> : <KeyRound size={17} />}
        <span>
          {participation.isReady
            ? isExpectedValue
              ? `If a block lands: ${routeCopy}`
              : routeCopy
            : "Pledge required. This payout is not active yet."}
        </span>
      </div>
    </section>
  );
}

function ContributionSplit({ totals }: { totals: ContributionTotals }) {
  const { account } = useDashboardData();
  return (
    <section className="split-panel">
      <div className="panel-heading flat">
        <h2>Human + Hashrate</h2>
        <span>50/50</span>
      </div>

      <div className="combined-weight">
        <span>Combined reward weight</span>
        <strong>{formatPercent(totals.combinedPercent, 3)}</strong>
        <small>Half from Bitcoin work, half from verified human-work score.</small>
      </div>

      <div className="formula-stack">
        <FormulaRow
          accent="green"
          label="Work share"
          denominator={formatScore(account.sharechain.poolHashrateScore)}
          score={formatScore(account.sharechain.hashrateScore)}
          share={totals.hashratePercent}
          weight="50%"
          weightedShare={totals.hashrateWeightedPercent}
        />
        <FormulaRow
          accent="amber"
          label="Human work score"
          denominator={formatScore(account.idenaAccounting.poolEligibleScore)}
          score={formatScore(totals.idenaTotal)}
          share={totals.idenaPercent}
          weight="50%"
          weightedShare={totals.idenaWeightedPercent}
        />
      </div>

      <div className="split-note">
        <SlidersHorizontal size={15} />
        <span>Small miners keep human and hashrate credit before payout routing.</span>
      </div>
    </section>
  );
}

function FormulaRow({
  accent,
  denominator,
  label,
  score,
  share,
  weight,
  weightedShare
}: {
  accent: "green" | "amber";
  denominator: string;
  label: string;
  score: string;
  share: number;
  weight: string;
  weightedShare: number;
}) {
  return (
    <div className={`formula-row ${accent}`}>
      <div className="formula-top">
        <span>{label}</span>
        <strong>{formatPercent(share, 3)}</strong>
      </div>
      <div className="formula-track">
        <i style={{ minWidth: share > 0 ? undefined : 0, width: `${Math.min(100, share * 18)}%` }} />
      </div>
      <div className="formula-meta">
        <span>{weight} weight</span>
        <span>adds {formatPercent(weightedShare, 3)}</span>
      </div>
    </div>
  );
}

function Panel({
  id,
  title,
  action,
  children
}: {
  id?: string;
  title: string;
  action?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="panel" id={id}>
      <div className="panel-heading">
        <h2>{title}</h2>
        {action ? <span>{action}</span> : null}
      </div>
      {children}
    </section>
  );
}

function SharechainChart({ shares }: { shares: SharePoint[] }) {
  const max = Math.max(1, ...shares.map((share) => share.accepted + share.stale));

  return (
    <div className="share-chart" aria-label="recent sharechain contribution chart">
      {shares.map((share) => {
        const acceptedHeight = share.accepted > 0 ? `${Math.max(8, (share.accepted / max) * 100)}%` : "0%";
        const staleHeight = share.stale > 0 ? `${Math.max(2, (share.stale / max) * 100)}%` : "0%";
        return (
          <div className="share-bar" key={share.label}>
            <div className="bar-stack">
              <span
                className="bar-stale"
                style={{ height: staleHeight, minHeight: share.stale > 0 ? undefined : 0 }}
              />
              <span
                className="bar-accepted"
                style={{ height: acceptedHeight, minHeight: share.accepted > 0 ? undefined : 0 }}
              />
            </div>
            <small>{share.label}</small>
          </div>
        );
      })}
    </div>
  );
}

function MetricGrid({ metrics }: { metrics: [string, string][] }) {
  return (
    <div className="metric-grid">
      {metrics.map(([label, value]) => (
        <div className="metric" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function IdenaBridge() {
  return (
    <div className="idena-bridge">
      <div>
        <Cpu size={17} />
        <span>BTC mental model</span>
      </div>
      <strong>Idena is the human-eligibility score; Bitcoin hashrate still proves work.</strong>
      <p>
        Eligible statuses are Newbie, Verified, or Human. Invitations and generic contract rewards
        are excluded from payout weight. This pool uses earned Idena rewards as a production-cost
        signal, not as one-human-one-vote governance.
      </p>
    </div>
  );
}

function IdentityHeader() {
  const { account } = useDashboardData();
  return (
    <div className="identity-card">
      <div className="identity-mark">
        <ShieldCheck size={22} />
      </div>
      <div>
        <strong>{captureIdentifier(account.identity.idenaAddress)}</strong>
        <span>
          {account.identity.status} identity, snapshot {account.identity.snapshotDay}
        </span>
      </div>
    </div>
  );
}

function IdenaBreakdown() {
  const { account } = useDashboardData();
  const entries = [
    ["Validation", account.idenaAccounting.validationScore, "green"],
    ["Proposer + committee", account.idenaAccounting.proposerCommitteeScore, "amber"]
  ] as const;
  const total = Math.max(1, entries.reduce((sum, [, value]) => sum + value, 0));

  return (
    <div className="idena-stack">
      {entries.map(([label, value, accent]) => (
        <div className={`idena-row ${accent}`} key={label}>
          <div>
            <span>{label}</span>
            <strong>{formatScore(value)}</strong>
          </div>
          <div className="progress">
            <i style={{ minWidth: value > 0 ? undefined : 0, width: `${(value / total) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function AuditList({ rows }: { rows: [string, string][] }) {
  return (
    <div className="audit-list">
      {rows.map(([label, value]) => (
        <div className="audit-row" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function PayoutTable({
  participation,
  view
}: {
  participation: ParticipationStatus;
  view: RewardView;
}) {
  const { account } = useDashboardData();
  const effectiveDirect = participation.isReady && view.direct;
  const activeVaultSats = participation.isReady ? view.vaultSats : 0;
  const activeFeeSats = participation.isReady ? view.feeSats : 0;
  const activeNetSats = participation.isReady ? view.netSats : 0;
  const rows = [
    ["Block value", `${formatBtc(view.blockValueBtc)} BTC`, `${formatSats(view.blockValueSats)} sats`],
    ["Combined share", formatPercent(account.payout.combinedRewardWeight * 100, 3), "50% hashrate + 50% Idena"],
    [
      participation.isReady ? "Gross claim" : "Potential gross claim",
      `${formatSats(view.grossSats)} sats`,
      `${formatBtcFromSats(view.grossSats)} BTC`
    ],
    [
      "Direct coinbase",
      effectiveDirect ? `${formatSats(view.grossSats)} sats` : "0 sats",
      participation.isReady
        ? view.direct
          ? `rank #${account.payout.directRank}`
          : "below direct set"
        : "pledge required"
    ],
    ["Direct cutoff now", `${formatSats(account.payout.nextDirectThresholdSats)} sats`, `rank ${account.payout.directLimit} unpaid balance`],
    ["Coinbase budget", `~${formatInt(account.payout.coinbaseOutputBudgetVb)} vB`, `top ${account.payout.directLimit} at ~${formatSats(account.payout.coinbaseOutputBudgetVb * account.payout.directFeeBasisSatVb)} sats @ ${account.payout.directFeeBasisSatVb} sat/vB`],
    [
      "FROST vault claim",
      `${formatSats(activeVaultSats)} sats`,
      participation.isReady
        ? view.vaultSats > 0
          ? "manual withdrawal"
          : "not needed"
        : "pledge required"
    ],
    [
      "Withdrawal fee",
      activeFeeSats === null ? "Pending" : `${formatSats(activeFeeSats)} sats`,
      participation.isReady
        ? activeFeeSats === null
          ? "known only when a withdrawal batch and fee rate are selected"
          : "deducted from vault claim"
        : "not active"
    ],
    [
      "Estimated net",
      activeNetSats === null ? "Pending" : `${formatSats(activeNetSats)} sats`,
      participation.isReady
        ? view.netSats === null
          ? "gross claim shown above; withdrawal fee is not known"
          : `${formatBtcFromSats(view.netSats)} BTC`
        : "not active until pledge"
    ]
  ];

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Line item</th>
            <th>Amount</th>
            <th>Rule</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, amount, rule]) => (
            <tr key={label}>
              <td data-label="Line item">{label}</td>
              <td data-label="Amount">{amount}</td>
              <td data-label="Rule">{rule}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DetailsPanel({
  auditOpen,
  onAuditOpenChange,
  onWindowChange,
  participation,
  view,
  window
}: {
  auditOpen: boolean;
  onAuditOpenChange: (open: boolean) => void;
  onWindowChange: (value: TimeWindow) => void;
  participation: ParticipationStatus;
  view: RewardView;
  window: TimeWindow;
}) {
  const { account, serviceStatuses } = useDashboardData();
  const serviceByLabel = new Map(serviceStatuses.map((status) => [status.label, status]));
  const bitcoinStatus = serviceByLabel.get("Bitcoin") ?? {
    detail: "not configured",
    label: "Bitcoin",
    state: "pending" as const
  };
  const idenaStatus = serviceByLabel.get("Idena") ?? {
    detail: "not configured",
    label: "Idena",
    state: "pending" as const
  };
  const p2poolStatus = serviceByLabel.get("P2Pool") ?? {
    detail: "local replay unavailable",
    label: "P2Pool",
    state: "warning" as const
  };
  const shareWindow = account.sharechain.windows?.[window] ?? {
    acceptedShares: account.sharechain.acceptedShares,
    staleShares: account.sharechain.staleShares,
    poolAcceptedShares: account.sharechain.poolAcceptedShares ?? 0,
    poolStaleShares: account.sharechain.poolStaleShares ?? 0,
    userHashrateThs: account.sharechain.userHashrateThs,
    poolHashrateThs: account.sharechain.poolHashrateThs,
    measurementSeconds: 0,
    userMeasurementSeconds: 0,
    poolMeasurementSeconds: 0,
    recentShares: account.sharechain.recentShares
  };
  const windowLabel = window === "epoch" ? "active chain" : window;
  return (
    <details
      className="details-panel"
      id="audit-numbers"
      onToggle={(event) => onAuditOpenChange(event.currentTarget.open)}
      open={auditOpen}
    >
      <summary aria-label="Audit my numbers: contribution and verification">
        <span>Audit my numbers</span>
        <small aria-hidden="true">contribution and verification</small>
      </summary>
      <div className="details-toolbar">
        <div>
          <span>Contribution window</span>
          <SegmentedControl<TimeWindow>
            value={window}
            onChange={onWindowChange}
            options={[
              { value: "24h", label: "24h" },
              { value: "7d", label: "7d" },
              { value: "epoch", label: "Active chain" }
            ]}
          />
        </div>
      </div>
      <div className="details-grid">
        <Panel id="sharechain" title="Sharechain Work" action={`${windowLabel} window`}>
          <SharechainChart shares={shareWindow.recentShares} />
          <MetricGrid
            metrics={[
              ["My accepted shares", formatInt(shareWindow.acceptedShares)],
              ["My stale shares", formatInt(shareWindow.staleShares)],
              ["Pool accepted shares", formatInt(shareWindow.poolAcceptedShares)],
              ["Pool stale shares", formatInt(shareWindow.poolStaleShares)],
              ["Chart window", formatMeasurementSpan(shareWindow.measurementSeconds)],
              ["My observed span", formatMeasurementSpan(shareWindow.userMeasurementSeconds)],
              ["Pool observed span", formatMeasurementSpan(shareWindow.poolMeasurementSeconds)],
              ["My hashrate", formatHashrateOrPending(shareWindow.userHashrateThs)],
              ["Pool hashrate", formatHashrateOrPending(shareWindow.poolHashrateThs)],
              ["My score", formatScore(account.sharechain.hashrateScore)],
              ["Pool score", formatScore(account.sharechain.poolHashrateScore)]
            ]}
          />
        </Panel>
        <Panel id="idena" title="Idena Reward Replay" action={account.identity.status}>
          <IdenaBridge />
          <IdentityHeader />
          <IdenaBreakdown />
          <AuditList
            rows={[
              ["Formula", account.idenaAccounting.formula],
              ["Snapshot height", formatInt(account.identity.snapshotHeight)],
              ["Snapshot root", captureIdentifier(account.identity.snapshotRoot)],
              ["Source", account.idenaAccounting.source],
              ["Excluded", `${formatScore(account.idenaAccounting.invitationScoreIgnored)} invitation score`]
            ]}
          />
        </Panel>
        <Panel id="payouts" title="Payout Route And Costs" action="Deterministic">
          <PayoutTable participation={participation} view={view} />
        </Panel>
        <Panel id="proof-sources" title="Proof Sources" action="Local">
          <StatusList
            rows={[
              { label: "Bitcoin Core", state: bitcoinStatus.state, value: bitcoinStatus.detail, detail: "fork point and block templates" },
              { label: "Idena Go", state: idenaStatus.state, value: idenaStatus.detail, detail: "human-work snapshot source" },
              { label: "P2Pool", state: p2poolStatus.state, value: p2poolStatus.detail, detail: `${account.pool.activeNodes} local/known nodes` },
              {
                label: "Pledge",
                state: account.identity.pledgeStatus === "verified" ? "connected" : "pending",
                value: account.identity.pledgeDetail,
                detail: "owner signatures required"
              }
            ]}
          />
        </Panel>
        <Panel id="vault" title="Vault Context" action={account.pool.vaultEpoch}>
          <VaultContext />
        </Panel>
      </div>
    </details>
  );
}

function NextStepPanel({
  participation,
  view
}: {
  participation: ParticipationStatus;
  view: RewardView;
}) {
  const { account } = useDashboardData();
  const route = participation.isReady ? (view.direct ? "Direct coinbase" : "Vault claim") : "Not active";
  const facts = (
    <div className="next-step-facts">
      <SummaryRow icon={ShieldCheck} label="Identity" value={account.identity.status} />
      <SummaryRow
        icon={GitBranch}
        label="Sharechain"
        value={`${formatInt(account.sharechain.acceptedShares)} shares`}
      />
      <SummaryRow icon={Wallet} label="Route" value={route} />
      <SummaryRow icon={Database} label="Proof source" value="Local RPC" />
    </div>
  );
  return (
    <aside className="inspector">
      <section className="next-step-panel" id="next-step">
        <div className="next-step-icon">
          {participation.isReady ? <CheckCircle2 size={22} /> : <KeyRound size={22} />}
        </div>
        <div>
          <span>{participation.isReady ? "Ready" : "Start here"}</span>
          <h2>{participation.isReady ? "Payout-ready" : "Join in 5 steps"}</h2>
          <p>{participation.nextAction}</p>
        </div>
        {!participation.isReady ? (
          <>
            <PledgeGuide />
            {facts}
          </>
        ) : (
          <>
            {facts}
            <ReadyGuide />
          </>
        )}
      </section>
    </aside>
  );
}

function PledgeGuide() {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "shown">("idle");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const commands = [
    {
      label: "Key",
      value: "p2pool-node derive-xonly-pubkey --secret-key-file ./mining.key"
    },
    {
      label: "Challenge",
      value:
        "p2pool-node idena-registration-challenge --miner-id <name> --idena-address <0x...> --btc-payout-script-hex <script> --claim-owner-pubkey-hex <xonly> --mining-pubkey-hex <xonly>"
    },
    {
      label: "Register",
      value:
        "p2pool-node create-miner-registration --miner-id <name> --idena-address <0x...> --btc-payout-script-hex <script> --claim-owner-pubkey-hex <xonly> --mining-secret-key-file ./mining.key --idena-signature-hex <sig> > registration.json"
    },
    {
      label: "Apply",
      value: "p2pool-node append-message --datadir .pohw-p2pool --message-file ./registration.json"
    }
  ];
  const commandText = commands.map((command) => `# ${command.label}\n${command.value}`).join("\n\n");
  const steps = [
    ["Prove human", "Open Idena, sign the pledge challenge."],
    ["Choose payout", "Use your Bitcoin payout script and claim key."],
    ["Publish pledge", "Append the registration to your local sharechain."],
    ["Point miner", "Use the local Stratum address from your node."],
    ["Watch payout", "This dashboard shows share, route, and estimate."]
  ];

  const copyCommands = async () => {
    let copiedToClipboard = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(commandText);
        copiedToClipboard = true;
      }
    } catch {
      copiedToClipboard = false;
    }
    if (!copiedToClipboard) {
      setAdvancedOpen(true);
      setCopyState("shown");
      return;
    }
    setCopyState("copied");
    globalThis.setTimeout(() => setCopyState("idle"), 1800);
  };

  return (
    <div className="pledge-guide">
      <div className="simple-explainer">
        <ShieldCheck size={16} />
        <p>
          Idena proves the human owner. Bitcoin mining still does the work. The pledge binds both
          to your payout route.
        </p>
      </div>
      <ol className="join-checklist">
        {steps.map(([label, detail], index) => (
          <li key={label}>
            <strong>{index + 1}</strong>
            <div>
              <span>{label}</span>
              <p>{detail}</p>
            </div>
          </li>
        ))}
      </ol>
      <button
        aria-live="polite"
        className="copy-command"
        onClick={copyCommands}
        type="button"
      >
        <Copy size={15} />
        <span>
          {copyState === "copied"
            ? "Copied"
            : copyState === "shown"
              ? "Commands shown"
              : "Copy command checklist"}
        </span>
      </button>
      {advancedOpen ? (
        <details
          className="advanced-commands"
          onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
          open
        >
          <summary>Commands</summary>
          <p>Run locally, sign the Idena challenge, then publish the registration.</p>
          <ol>
            {commands.map((command) => (
              <li key={command.label}>
                <span>{command.label}</span>
                <code>{command.value}</code>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </div>
  );
}

function ReadyGuide() {
  return (
    <div className="ready-guide">
      <CheckCircle2 size={16} />
      <span>Keep the node online; new shares and snapshots update the estimate.</span>
    </div>
  );
}

function StatusList({
  rows
}: {
  rows: { label: string; state: ServiceState; value: string; detail: string }[];
}) {
  return (
    <div className="status-list">
      {rows.map((row) => (
        <div className="status-row" key={row.label}>
          <span className={`state-dot ${row.state}`} />
          <div>
            <span>{row.label}</span>
            <strong>{row.value}</strong>
            <small>{row.detail}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

function VaultContext() {
  const { account } = useDashboardData();
  const rows: [string, string][] = [
    ["Signers", `${account.pool.thresholdCount} of ${account.pool.signerCount} required`],
    ["Vault key", captureIdentifier(account.pool.vaultKey)],
    ["Rotation", `weekly, last ${account.pool.lastVaultRotation}`],
    ["Pending", `${account.pool.pendingWithdrawals} withdrawal requests`],
    ["Risk", "if threshold is offline, withdrawals wait"]
  ];

  return (
    <div className="vault-stack">
      <div className="vault-box">
        <Users size={20} />
        <div>
          <strong>{account.pool.frostThreshold}</strong>
          <span>Claims are BTC withdrawal rights, not transferable pool tokens.</span>
        </div>
      </div>
      <AuditList rows={rows} />
    </div>
  );
}

function SummaryRow({
  icon: Icon,
  label,
  value
}: {
  icon: typeof Gauge;
  label: string;
  value: string;
}) {
  return (
    <div className="summary-row">
      <Icon size={17} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SegmentedControl<T extends string>({
  value,
  options,
  onChange
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div className="segmented">
      {options.map((option) => (
        <button
          className={option.value === value ? "selected" : ""}
          key={option.value}
          onClick={() => onChange(option.value)}
          type="button"
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

interface ContributionTotals {
  idenaTotal: number;
  hashratePercent: number;
  hashrateWeightedPercent: number;
  idenaPercent: number;
  idenaWeightedPercent: number;
  combinedPercent: number;
}

interface ParticipationStatus {
  isReady: boolean;
  nextAction: string;
}

function getParticipationStatus(account: PoolSnapshot): ParticipationStatus {
  const pledgeReady = account.identity.pledgeStatus === "verified";
  return {
    isReady: pledgeReady,
    nextAction: pledgeReady
      ? "Shares are eligible for payout accounting."
      : "Bind your Idena identity, payout script, claim key, and mining key."
  };
}

function getContributionTotals(account: PoolSnapshot): ContributionTotals {
  const idenaTotal =
    account.idenaAccounting.validationScore +
    account.idenaAccounting.proposerCommitteeScore;
  return {
    idenaTotal,
    hashratePercent: account.sharechain.relativeHashrateShare * 100,
    hashrateWeightedPercent: account.sharechain.relativeHashrateShare * 50,
    idenaPercent: account.idenaAccounting.relativeIdenaShare * 100,
    idenaWeightedPercent: account.idenaAccounting.relativeIdenaShare * 50,
    combinedPercent: account.payout.combinedRewardWeight * 100
  };
}

function getRewardView(account: PoolSnapshot, prospectMode: ProspectMode): RewardView {
  return calculateRewardView({
    blockSubsidyBtc: account.payout.blockSubsidyBtc,
    estimatedFeesBtc: account.payout.estimatedFeesBtc,
    combinedRewardWeight: account.payout.combinedRewardWeight,
    expectedBlocks30d: account.pool.expectedBlocks30d
      ?? expectedBlocksForChancePercent(account.pool.chance30d),
    directPayoutEligible: account.payout.directPayoutEligible,
    directRank: account.payout.directRank,
    directLimit: account.payout.directLimit,
    minPayoutSats: account.payout.minPayoutSats,
    estimatedWithdrawalFeeSats: account.payout.estimatedWithdrawalFeeSats
  }, prospectMode);
}

function isConnectedExperimentOne(overview: ExplorerOverview | null) {
  return overview?.fork.state === "connected"
    && overview.fork.status?.chainName.trim().toLowerCase() === "pohw";
}

function getExplorerNetworkLabel(overview: ExplorerOverview | null) {
  return isConnectedExperimentOne(overview) ? "PoHW Experiment 1" : "PoHW testnet";
}

function getExplorerChainLabel(overview: ExplorerOverview | null) {
  const chainName = overview?.fork.status?.chainName;
  if (!chainName) return "Not configured";
  return isConnectedExperimentOne(overview) ? `Experiment 1 (${chainName})` : chainName;
}

function isIdentifierStatus(value: string) {
  return /^(?:genesis|n\/a|not (?:available|configured|connected|confirmed|deployed|found|present)|unavailable|unknown)$/i
    .test(value.trim());
}

function captureIdentifier(value?: string | null, fallback = "Not available") {
  if (!value) return fallback;
  if (!README_CAPTURE_MODE || isIdentifierStatus(value)) return value;
  return CAPTURE_MASK;
}

function captureSafeTitle(value?: string | null) {
  return README_CAPTURE_MODE ? undefined : value ?? undefined;
}

function maskIdentifierLikeText(value: string) {
  if (!README_CAPTURE_MODE) return value;
  return value
    .replace(/\b(?:bc1[ac-hj-np-z02-9]{11,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b/gi, CAPTURE_MASK)
    .replace(/\b(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[a-z2-7]{20,})\b/g, CAPTURE_MASK)
    .replace(/\b(?:0x[0-9a-f]{16,}|(?=[0-9a-f]{32,}\b)(?=[0-9a-f]*[a-f])[0-9a-f]{32,})\b/gi, CAPTURE_MASK)
    .replace(/\b(?:0x)?[0-9a-f]{4,}\.\.\.[0-9a-f]{4,}\b/gi, CAPTURE_MASK);
}

function shortHash(value?: string | null) {
  if (!value) return "Not available";
  if (README_CAPTURE_MODE && !isIdentifierStatus(value)) return CAPTURE_MASK;
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function formatIntegerString(value: string) {
  try {
    return new Intl.NumberFormat("en-US").format(BigInt(value));
  } catch {
    return value;
  }
}

function formatIdnaAtoms(value: string) {
  try {
    const atoms = BigInt(value);
    const unit = 1_000_000_000_000_000_000n;
    const whole = atoms / unit;
    const fraction = (atoms % unit).toString().padStart(18, "0").slice(0, 4).replace(/0+$/, "");
    return fraction ? `${whole}.${fraction}` : whole.toString();
  } catch {
    return value;
  }
}

function formatUnixTime(value: number, includeDate = false) {
  if (!Number.isFinite(value) || value <= 0) return "Unavailable";
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: includeDate ? "medium" : undefined,
    timeStyle: includeDate ? "medium" : "short",
    timeZone: "UTC"
  }).format(new Date(value * 1000));
}

function formatHashrate(value?: string | null) {
  if (!value) return "Unavailable";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return `${value} H/s`;
  if (numeric >= 1e18) return `${(numeric / 1e18).toFixed(2)} EH/s`;
  if (numeric >= 1e15) return `${(numeric / 1e15).toFixed(2)} PH/s`;
  if (numeric >= 1e12) return `${(numeric / 1e12).toFixed(2)} TH/s`;
  if (numeric >= 1e9) return `${(numeric / 1e9).toFixed(2)} GH/s`;
  if (numeric >= 1e6) return `${(numeric / 1e6).toFixed(2)} MH/s`;
  if (numeric > 0 && numeric < 1) return "<1 H/s";
  return `${formatInt(Math.round(numeric))} H/s`;
}

function formatStateLabel(value?: string | null) {
  if (!value) return "Unavailable";
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatCoverage(value?: string | null) {
  if (value === "verified_snapshot_partial_sources") return "Verified snapshot / partial sources";
  return formatStateLabel(value);
}

function formatInt(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value < 0) return "unknown";
  if (value < 1024) return `${Math.round(value)} B`;
  const units = ["KiB", "MiB", "GiB"];
  let scaled = value / 1024;
  let index = 0;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  return `${scaled.toFixed(scaled >= 10 ? 0 : 1)} ${units[index]}`;
}

function formatScore(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return value.toString();
}

function formatSats(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatHashrateThs(value: number) {
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)} PH/s`;
  return `${value.toFixed(2)} TH/s`;
}

function formatHashrateOrPending(value: number) {
  return value > 0 ? formatHashrateThs(value) : "not estimated yet";
}

function hasLiveHashrateEstimate(account: PoolSnapshot) {
  return account.sharechain.poolHashrateThs > 0 || account.sharechain.userHashrateThs > 0;
}

function miningWorkValue(account: PoolSnapshot) {
  if (hasLiveHashrateEstimate(account)) {
    return `${formatHashrateThs(account.sharechain.userHashrateThs)} accepted`;
  }
  if (account.sharechain.acceptedShares > 0) {
    return `${formatInt(account.sharechain.acceptedShares)} accepted shares`;
  }
  return "No accepted shares yet";
}

function formatMeasurementSpan(seconds?: number) {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) {
    return "Not available";
  }
  const days = seconds / (24 * 60 * 60);
  if (days >= 1) return `${days.toFixed(days < 10 ? 1 : 0)} days`;
  const hours = seconds / (60 * 60);
  if (hours >= 1) return `${hours.toFixed(hours < 10 ? 1 : 0)} hours`;
  return `${Math.max(1, Math.round(seconds / 60))} minutes`;
}

function formatPercent(value: number, digits = 2) {
  return `${value.toFixed(digits)}%`;
}

function formatChancePercent(value: number) {
  const digits = value < 0.01 ? 4 : value < 1 ? 2 : 1;
  return formatPercent(value, digits);
}

function formatExpectedBlocks(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0";
  if (value < 0.01) return value.toFixed(4);
  if (value < 1) return value.toFixed(3);
  return value.toFixed(2);
}

function formatBtc(value: number) {
  return value.toLocaleString("en-US", {
    maximumFractionDigits: 8,
    minimumFractionDigits: 0
  });
}

function formatBtcFromSats(value: number) {
  return formatBtc(value / SATS_PER_BTC);
}

const rootElement = document.getElementById("root") as HTMLElement;
const rootWindow = window as typeof window & {
  __pohwDashboardRoot?: ReturnType<typeof createRoot>;
};
const root = rootWindow.__pohwDashboardRoot ?? createRoot(rootElement);
rootWindow.__pohwDashboardRoot = root;
root.render(<App />);
