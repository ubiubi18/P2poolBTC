import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Bitcoin,
  Brain,
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
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Wallet
} from "lucide-react";
import "./styles.css";

type ServiceState = "connected" | "syncing" | "pending" | "warning";
type TimeWindow = "24h" | "7d" | "epoch";
type ProspectMode = "block-now" | "30d-ev";
type SectionId = "overview" | "sharechain" | "idena" | "payouts" | "vault" | "next-step" | "audit-numbers";

const SATS_PER_BTC = 100_000_000;

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
    hashrateScore: number;
    poolHashrateScore: number;
    poolHashrateThs: number;
    userHashrateThs: number;
    relativeHashrateShare: number;
    recentShares: SharePoint[];
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
    estimatedWithdrawalFeeSats: number;
    minPayoutSats: number;
  };
  pool: {
    expectedBlockInterval: string;
    chance30d: number;
    bitcoinNetworkHashrateEhs: number;
    vaultEpoch: string;
    frostThreshold: string;
    signerCount: number;
    thresholdCount: number;
    pendingWithdrawals: number;
    lastVaultRotation: string;
    vaultKey: string;
    activeNodes: number;
  };
}

interface DashboardApiResponse {
  generatedAtUnix: number | null;
  source: string;
  serviceStatuses: ServiceStatus[];
  account: PoolSnapshot;
}

interface RuntimeDashboardConfig {
  apiToken?: string;
  apiUrl?: string;
  demo?: string;
}

declare global {
  interface Window {
    __POHW_DASHBOARD_CONFIG__?: RuntimeDashboardConfig;
  }
}

const dashboardEnv =
  (import.meta as unknown as {
    env?: {
      VITE_POHW_DASHBOARD_API_TOKEN?: string;
      VITE_POHW_DASHBOARD_API_URL?: string;
      VITE_POHW_DASHBOARD_DEMO?: string;
    };
  }).env ?? {};
const runtimeDashboardConfig = window.__POHW_DASHBOARD_CONFIG__ ?? {};
const dashboardApiUrl =
  runtimeDashboardConfig.apiUrl ?? dashboardEnv.VITE_POHW_DASHBOARD_API_URL ?? "http://127.0.0.1:40407/dashboard.json";
const dashboardApiToken =
  runtimeDashboardConfig.apiToken?.trim() || dashboardEnv.VITE_POHW_DASHBOARD_API_TOKEN?.trim() || undefined;
const dashboardDemoMode = ["1", "true", "yes"].includes(
  (runtimeDashboardConfig.demo ?? dashboardEnv.VITE_POHW_DASHBOARD_DEMO ?? "").toLowerCase()
);

const fallbackServiceStatuses: ServiceStatus[] = [
  { label: "P2Pool", state: "connected", detail: "8 peers / tip 18,402" },
  { label: "Bitcoin", state: "syncing", detail: "Pi IBD running" },
  { label: "Idena", state: "syncing", detail: "local replay catching up" },
  { label: "Snapshot", state: "pending", detail: "gated until sync" }
];

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
    hashrateScore: 920420,
    poolHashrateScore: 237_645_236,
    poolHashrateThs: 1340,
    userHashrateThs: 5.19,
    relativeHashrateShare: 0.003873,
    recentShares: [
      { label: "00", accepted: 18, stale: 1 },
      { label: "03", accepted: 24, stale: 0 },
      { label: "06", accepted: 31, stale: 2 },
      { label: "09", accepted: 28, stale: 0 },
      { label: "12", accepted: 36, stale: 1 },
      { label: "15", accepted: 39, stale: 0 },
      { label: "18", accepted: 41, stale: 1 },
      { label: "21", accepted: 34, stale: 0 }
    ]
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
    minPayoutSats: 10000
  },
  pool: {
    expectedBlockInterval: "~9.7 years at current pool rate",
    chance30d: 0.84,
    bitcoinNetworkHashrateEhs: 690,
    vaultEpoch: "2026-W27",
    frostThreshold: "67% of online epoch signers",
    signerCount: 13,
    thresholdCount: 9,
    pendingWithdrawals: 6,
    lastVaultRotation: "2026-06-24",
    vaultKey: "tr(frost...9a4c)",
    activeNodes: 19
  }
};

const emptySharePoints: SharePoint[] = ["00", "03", "06", "09", "12", "15", "18", "21"].map(
  (label) => ({ label, accepted: 0, stale: 0 })
);

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
      hashrateScore: 0,
      poolHashrateScore: 0,
      poolHashrateThs: 0,
      userHashrateThs: 0,
      relativeHashrateShare: 0,
      recentShares: emptySharePoints
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
      blockSubsidyBtc: 3.125,
      estimatedFeesBtc: 0,
      directPayoutEligible: false,
      directRank: 0,
      directLimit: 100,
      nextDirectThresholdSats: 10_000,
      coinbaseOutputBudgetVb: 3_100,
      directFeeBasisSatVb: 3,
      vaultClaimSats: 0,
      estimatedWithdrawalFeeSats: 0,
      minPayoutSats: 10_000
    },
    pool: {
      expectedBlockInterval: "local API offline",
      chance30d: 0,
      bitcoinNetworkHashrateEhs: 0,
      vaultEpoch: "not available",
      frostThreshold: "not available",
      signerCount: 0,
      thresholdCount: 0,
      pendingWithdrawals: 0,
      lastVaultRotation: "not available",
      vaultKey: "not available",
      activeNodes: 0
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

const DashboardDataContext = React.createContext<DashboardApiResponse>(initialDashboardData);

function useDashboardData() {
  return React.useContext(DashboardDataContext);
}

function App() {
  const [dashboardData, setDashboardData] = useState<DashboardApiResponse>(initialDashboardData);
  const [auditOpen, setAuditOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionId>("overview");
  const [window, setWindow] = useState<TimeWindow>("7d");
  const prospectMode: ProspectMode = "block-now";
  const account = dashboardData.account;
  const participation = useMemo(() => getParticipationStatus(account), [account]);

  useEffect(() => {
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
    navigateToSection("next-step");
  };

  const blockNowView = useMemo(() => getRewardView(account, "block-now"), [account]);
  const forecastView = useMemo(() => getRewardView(account, prospectMode), [account, prospectMode]);
  const totals = useMemo(() => getContributionTotals(account), [account]);

  return (
    <DashboardDataContext.Provider value={dashboardData}>
      <main className="app-shell">
        <Navigation activeSection={activeSection} onNavigate={navigateToSection} />
        <section className="workspace">
          <TopBar />
          <div className="dashboard-grid">
            <section className="main-column">
              <DashboardIntro
                onStartPledge={startPledge}
                participation={participation}
              />

              {dashboardData.source !== "local-p2pool-node" ? (
                <SourceNotice source={dashboardData.source} />
              ) : null}

              <JoinSummary participation={participation} totals={totals} view={blockNowView} />

              <JourneyStrip participation={participation} view={blockNowView} />

              <section className="focus-grid">
                <RewardForecast
                  participation={participation}
                  prospectMode={prospectMode}
                  view={forecastView}
                />
                <ContributionSplit totals={totals} />
              </section>

              <PoolNote />

              <DetailsPanel
                auditOpen={auditOpen}
                onAuditOpenChange={setAuditOpen}
                onWindowChange={setWindow}
                participation={participation}
                view={forecastView}
                window={window}
              />
            </section>

            <NextStepPanel
              participation={participation}
              view={blockNowView}
            />
          </div>
        </section>
      </main>
    </DashboardDataContext.Provider>
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
              ? "Set VITE_POHW_DASHBOARD_API_TOKEN before trusting payout, pledge, or sync status."
              : "Start the local dashboard API before trusting payout, pledge, or sync status."}
        </span>
      </div>
    </section>
  );
}

function JoinSummary({
  participation,
  totals,
  view
}: {
  participation: ParticipationStatus;
  totals: ContributionTotals;
  view: RewardView;
}) {
  const metrics = [
    {
      detail: `${formatSats(view.grossSats)} sats before route fees`,
      icon: Bitcoin,
      label: participation.isReady ? "BTC if block lands" : "Possible BTC reward",
      tone: "orange",
      value: `${formatBtcFromSats(view.grossSats)} BTC`
    },
    {
      detail: "50% hashrate + 50% human score",
      icon: Percent,
      label: "Your pool share",
      tone: "green",
      value: formatPercent(totals.combinedPercent, 3)
    },
    {
      detail: participation.isReady ? "Ready for payout accounting" : "Finish pledge before shares count",
      icon: participation.isReady ? CheckCircle2 : KeyRound,
      label: participation.isReady ? "Status" : "Next action",
      tone: "blue",
      value: participation.isReady ? "Ready" : "Pledge"
    }
  ] as const;

  return (
    <section className="join-summary" aria-label="Simple joining summary">
      {metrics.map((metric) => (
        <div className={`key-metric ${metric.tone}`} key={metric.label}>
          <metric.icon size={20} />
          <div>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
            <small>{metric.detail}</small>
          </div>
        </div>
      ))}
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
  onNavigate
}: {
  activeSection: SectionId;
  onNavigate: (sectionId: SectionId, revealAudit?: boolean) => void;
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
        <span>PoHW Pool</span>
      </div>
      <nav>
        {items.map((item) => (
          <button
            aria-current={activeSection === item.sectionId ? "page" : undefined}
            aria-label={`Go to ${item.label}`}
            className={activeSection === item.sectionId ? "nav-item active" : "nav-item"}
            key={item.label}
            onClick={() => onNavigate(item.sectionId, item.revealAudit)}
            title={item.label}
            type="button"
          >
            <item.icon size={17} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="nav-footer">
        <HardDrive size={16} />
        <span>Local-first node UI</span>
      </div>
    </aside>
  );
}

function TopBar() {
  const { serviceStatuses } = useDashboardData();
  return (
    <header className="top-bar">
      <div className="network-title">
        <Network size={18} />
        <span>proof of human work pool</span>
      </div>
      <div className="service-row">
        {serviceStatuses.map((status) => (
          <div className="service-pill" key={status.label}>
            <span className={`state-dot ${status.state}`} />
            <span className="service-label">{status.label}</span>
            <span className="service-detail">{status.detail}</span>
          </div>
        ))}
      </div>
    </header>
  );
}

function RewardForecast({
  participation,
  prospectMode,
  view
}: {
  participation: ParticipationStatus;
  prospectMode: ProspectMode;
  view: RewardView;
}) {
  const { account } = useDashboardData();
  const isExpectedValue = prospectMode === "30d-ev";
  const routeCopy = view.direct
    ? `Direct coinbase payout, current unpaid rank #${account.payout.directRank}`
    : "Vault claim, manual withdrawal needed";
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
                ? "Your block-now claim weighted by the current 30 day pool chance."
                : "Block value multiplied by your combined 50/50 reward weight."}
          </p>
        </div>
      </div>

      <div className="forecast-amount">
        <strong>{formatBtcFromSats(view.netSats)} BTC</strong>
        <span>{formatSats(view.netSats)} sats estimated net</span>
      </div>

      <div className="forecast-equation">
        <span>{formatBtc(view.blockValueBtc)} BTC block</span>{" "}
        <span>x {formatPercent(account.payout.combinedRewardWeight * 100, 3)} share</span>{" "}
        {isExpectedValue ? (
          <>
            <span>x {account.pool.chance30d.toFixed(2)}% 30 day chance</span>{" "}
          </>
        ) : null}
        <strong>= {formatBtcFromSats(view.netSats)} BTC</strong>
      </div>

      <div className="forecast-sats">
        {formatSats(view.netSats)} sats {isExpectedValue ? "probability-weighted EV" : "estimated net"}
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

function PoolNote() {
  const { account } = useDashboardData();
  return (
    <div className="pool-note">
      <Clock3 size={16} />
      <span>{poolChanceCopy(account)}</span>
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
        <strong>{account.identity.idenaAddress}</strong>
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
      `${formatSats(activeFeeSats)} sats`,
      participation.isReady ? "deducted from vault claim" : "not active"
    ],
    [
      "Estimated net",
      `${formatSats(activeNetSats)} sats`,
      participation.isReady
        ? `${formatBtcFromSats(view.netSats)} BTC`
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
              { value: "epoch", label: "Epoch" }
            ]}
          />
        </div>
      </div>
      <div className="details-grid">
        <Panel id="sharechain" title="Sharechain Work" action={`${window} window`}>
          <SharechainChart shares={account.sharechain.recentShares} />
          <MetricGrid
            metrics={[
              ["Accepted shares", formatInt(account.sharechain.acceptedShares)],
              ["Stale shares", formatInt(account.sharechain.staleShares)],
              ["My hashrate", formatHashrateOrPending(account.sharechain.userHashrateThs)],
              ["Pool hashrate", formatHashrateOrPending(account.sharechain.poolHashrateThs)],
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
              ["Snapshot root", account.identity.snapshotRoot],
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
    ["Vault key", account.pool.vaultKey],
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

interface RewardView {
  blockValueBtc: number;
  blockValueSats: number;
  direct: boolean;
  feeSats: number;
  grossSats: number;
  netSats: number;
  vaultSats: number;
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
  const multiplier = prospectMode === "30d-ev" ? account.pool.chance30d / 100 : 1;
  const blockValueBtc = account.payout.blockSubsidyBtc + account.payout.estimatedFeesBtc;
  const blockValueSats = Math.round(blockValueBtc * SATS_PER_BTC);
  const grossSats = Math.round(blockValueSats * account.payout.combinedRewardWeight * multiplier);
  const direct =
    account.payout.directPayoutEligible &&
    account.payout.directRank <= account.payout.directLimit &&
    grossSats >= account.payout.minPayoutSats;
  const vaultSats = direct ? 0 : grossSats;
  const feeSats = vaultSats > 0 ? Math.min(account.payout.estimatedWithdrawalFeeSats, vaultSats) : 0;
  const netSats = direct ? grossSats : Math.max(0, vaultSats - feeSats);

  return {
    blockValueBtc,
    blockValueSats,
    direct,
    feeSats,
    grossSats,
    netSats,
    vaultSats
  };
}

function formatInt(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
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

function miningWorkDetail(account: PoolSnapshot) {
  if (hasLiveHashrateEstimate(account)) {
    return `${formatHashrateThs(account.sharechain.userHashrateThs)} of ${formatHashrateThs(
      account.sharechain.poolHashrateThs
    )}`;
  }
  if (account.sharechain.poolHashrateScore > 0) {
    return `${formatScore(account.sharechain.hashrateScore)} of ${formatScore(
      account.sharechain.poolHashrateScore
    )} share score`;
  }
  return "waiting for accepted sharechain work";
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

function poolChanceCopy(account: PoolSnapshot) {
  if (hasLiveHashrateEstimate(account) && account.pool.chance30d > 0) {
    return `Pool chance is ${account.pool.chance30d.toFixed(2)}% in 30 days at ${formatHashrateThs(
      account.sharechain.poolHashrateThs
    )}.`;
  }
  return "Block chance waits for live pool hashrate and Bitcoin work templates.";
}

function formatNetworkHashrate(valueEhs: number) {
  return `${formatInt(valueEhs)} EH/s network`;
}

function formatPercent(value: number, digits = 2) {
  return `${value.toFixed(digits)}%`;
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
