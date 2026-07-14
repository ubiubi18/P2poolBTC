use crate::bitcoin_explorer_index::BitcoinExplorerIndexClient;
use crate::bitcoin_rpc::{BitcoinRpcAuth, BitcoinRpcClient};
use crate::explorer_api;
use crate::fork_chain::ForkChainClient;
use crate::governance_api;
use crate::local_node;
use anyhow::{bail, Context, Result};
use idena_lite_indexer::rpc::{EpochResponse, IdenaRpcClient, SyncingResponse};
use pohw_core::payout::{build_payout_schedule, ParticipantAccount};
use pohw_core::sharechain::MinerRegistration;
use pohw_core::snapshot::Snapshot;
use pohw_core::{Score, DIRECT_PAYOUT_LIMIT, MIN_DIRECT_PAYOUT_SATS};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const DEFAULT_BLOCK_SUBSIDY_BTC: f64 = 3.125;
const DEFAULT_BLOCK_REWARD_SATS: u64 = 312_500_000;
const DEFAULT_BTC_USD_REFERENCE: u64 = 59_520;
const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;
const MAX_SAFE_JS_INTEGER: u128 = 9_007_199_254_740_991;
const MIN_NON_LOOPBACK_API_TOKEN_BYTES: usize = 24;
const MAX_API_TOKEN_BYTES: usize = 512;
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DASHBOARD_CONNECTIONS: usize = 128;
const MAX_DASHBOARD_CONNECTIONS_PER_IP: usize = 16;
const DASHBOARD_HEADER_TIMEOUT_SECONDS: u64 = 5;
const DASHBOARD_READ_IDLE_TIMEOUT_SECONDS: u64 = 5;
const DASHBOARD_WRITE_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5176",
    "http://localhost:5176",
    "http://127.0.0.1:5177",
    "http://localhost:5177",
    "http://127.0.0.1:4173",
    "http://localhost:4173",
];

#[derive(Debug, Clone)]
pub struct DashboardApiConfig {
    pub datadir: PathBuf,
    pub snapshot_dir: Option<PathBuf>,
    pub bind_addr: SocketAddr,
    pub allow_non_loopback: bool,
    pub allowed_origins: Vec<String>,
    pub api_token: Option<String>,
    pub account_selector: DashboardAccountSelector,
    pub probe_timeout: Duration,
    pub allow_remote_rpc: bool,
    pub bitcoin_rpc_url: Option<String>,
    pub bitcoin_rpc_auth: Option<BitcoinRpcAuth>,
    pub idena_rpc_url: Option<String>,
    pub idena_api_key_file: Option<PathBuf>,
    pub public_explorer: bool,
    pub fork_chain_client: Option<ForkChainClient>,
    pub bitcoin_index_client: Option<BitcoinExplorerIndexClient>,
    pub governance_state_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DashboardAccountSelector {
    pub miner_id: Option<String>,
    pub claim_owner_id: Option<String>,
    pub idena_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardApiServerStatus {
    pub listening_on: SocketAddr,
    pub datadir: PathBuf,
    pub protocol: &'static str,
    pub note: &'static str,
    pub public_explorer: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardApiResponse {
    pub generated_at_unix: i64,
    pub source: String,
    pub service_statuses: Vec<DashboardServiceStatus>,
    pub account: DashboardPoolSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardServiceStatus {
    pub label: String,
    pub state: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardPoolSnapshot {
    pub identity: DashboardIdentity,
    pub sharechain: DashboardSharechain,
    pub idena_accounting: DashboardIdenaAccounting,
    pub payout: DashboardPayout,
    pub pool: DashboardPoolContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardIdentity {
    pub idena_address: String,
    pub pledge_detail: String,
    pub pledge_status: String,
    pub status: String,
    pub snapshot_height: u64,
    pub snapshot_day: String,
    pub snapshot_root: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSharechain {
    pub accepted_shares: usize,
    pub stale_shares: usize,
    pub hashrate_score: u64,
    pub pool_hashrate_score: u64,
    pub pool_hashrate_ths: f64,
    pub user_hashrate_ths: f64,
    pub relative_hashrate_share: f64,
    pub recent_shares: Vec<DashboardSharePoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSharePoint {
    pub label: String,
    pub accepted: usize,
    pub stale: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardIdenaAccounting {
    pub validation_score: u64,
    pub proposer_committee_score: u64,
    pub invitation_score_ignored: u64,
    pub pool_eligible_score: u64,
    pub relative_idena_share: f64,
    pub formula: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardPayout {
    pub combined_reward_weight: f64,
    pub block_subsidy_btc: f64,
    pub estimated_fees_btc: f64,
    pub btc_usd_reference: u64,
    pub btc_usd_reference_label: String,
    pub direct_payout_eligible: bool,
    pub direct_rank: usize,
    pub direct_limit: usize,
    pub next_direct_threshold_sats: u64,
    pub coinbase_output_budget_vb: u64,
    pub direct_fee_basis_sat_vb: u64,
    pub vault_claim_sats: u64,
    pub estimated_withdrawal_fee_sats: u64,
    pub min_payout_sats: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardPoolContext {
    pub expected_block_interval: String,
    pub chance30d: f64,
    pub bitcoin_network_hashrate_ehs: u64,
    pub vault_epoch: String,
    pub frost_threshold: String,
    pub signer_count: usize,
    pub threshold_count: usize,
    pub pending_withdrawals: usize,
    pub last_vault_rotation: String,
    pub vault_key: String,
    pub active_nodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotScoreMaterial {
    status: String,
    validation_score: Score,
    proposer_score: Score,
    committee_score: Score,
    ignored_invitation_score: Score,
    eligible_score: Score,
    block_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectedPayoutRoute {
    direct_payout_eligible: bool,
    direct_rank: usize,
    direct_cutoff_sats: u64,
    projected_vault_claim_sats: u64,
    estimated_withdrawal_fee_sats: u64,
}

pub fn default_allowed_origins() -> Vec<String> {
    DEFAULT_ALLOWED_ORIGINS
        .iter()
        .map(|origin| (*origin).to_string())
        .collect()
}

pub async fn run_dashboard_api_server(config: DashboardApiConfig) -> Result<()> {
    validate_dashboard_api_config(&config)?;
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind dashboard API {}", config.bind_addr))?;
    let local_addr = listener
        .local_addr()
        .context("failed to read dashboard API listener local address")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&DashboardApiServerStatus {
            listening_on: local_addr,
            datadir: config.datadir.clone(),
            protocol: "pohw-dashboard-http-json-v1",
            note: "read-only dashboard and explorer API",
            public_explorer: config.public_explorer,
        })?
    );

    let shared = Arc::new(config);
    let connections =
        ConnectionLimiter::new(MAX_DASHBOARD_CONNECTIONS, MAX_DASHBOARD_CONNECTIONS_PER_IP);
    loop {
        let (stream, remote_addr) = listener
            .accept()
            .await
            .context("failed to accept dashboard API connection")?;
        let Some(connection_guard) = connections.try_acquire(remote_addr.ip()) else {
            continue;
        };
        let config = Arc::clone(&shared);
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Err(err) = handle_dashboard_connection(stream, config).await {
                eprintln!("warning: dashboard API request failed: {err:#}");
            }
        });
    }
}

fn validate_dashboard_api_config(config: &DashboardApiConfig) -> Result<()> {
    validate_allowed_origins(&config.allowed_origins)?;
    validate_account_selector(&config.account_selector)?;
    if !config.bind_addr.ip().is_loopback() && !config.allow_non_loopback {
        bail!(
            "refusing to bind dashboard API to {}; use --allow-non-loopback only on a trusted LAN",
            config.bind_addr
        );
    }
    if !config.bind_addr.ip().is_loopback() && config.api_token.is_none() {
        bail!("refusing non-loopback dashboard API without --dashboard-api-token or --dashboard-api-token-file");
    }
    if config.probe_timeout.is_zero() || config.probe_timeout > MAX_PROBE_TIMEOUT {
        bail!(
            "dashboard probe timeout must be between 1ms and {}s",
            MAX_PROBE_TIMEOUT.as_secs()
        );
    }
    if let Some(token) = &config.api_token {
        validate_dashboard_api_token(token, !config.bind_addr.ip().is_loopback())?;
    }
    Ok(())
}

pub async fn build_dashboard_snapshot(config: &DashboardApiConfig) -> Result<DashboardApiResponse> {
    let (bitcoin_status, (idena_status, idena_syncing, idena_epoch)) =
        tokio::join!(bitcoin_service_status(config), idena_service_status(config));
    let snapshot_directory = config
        .snapshot_dir
        .as_deref()
        .map(local_node::latest_verified_snapshot)
        .transpose()?;
    let snapshot_status = snapshot_service_status(
        &idena_status,
        idena_syncing.as_ref(),
        idena_epoch.as_ref(),
        snapshot_directory.as_ref(),
    );
    build_dashboard_snapshot_with_statuses(
        &config.datadir,
        config.snapshot_dir.as_deref(),
        bitcoin_status,
        idena_status,
        snapshot_status,
        &config.account_selector,
        snapshot_directory
            .as_ref()
            .and_then(|directory| directory.latest.as_ref()),
    )
}

fn build_dashboard_snapshot_with_statuses(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    bitcoin_status: DashboardServiceStatus,
    idena_status: DashboardServiceStatus,
    snapshot_status: DashboardServiceStatus,
    account_selector: &DashboardAccountSelector,
    verified_snapshot: Option<&local_node::VerifiedSnapshotFile>,
) -> Result<DashboardApiResponse> {
    let local_status = local_node::local_node_status(datadir)?;
    let state = local_node::replay_state_with_confirmed_payouts(datadir, snapshot_dir)?;
    let replay_summary = state.summary();
    let peers = local_node::list_gossip_peers(datadir)?;
    let mut accounts = state.participant_accounts();
    let snapshot_scores = verified_snapshot
        .map(|snapshot| snapshot_scores_by_idena_address(&snapshot.snapshot))
        .transpose()?;
    if let Some(scores) = snapshot_scores.as_ref() {
        for account in &mut accounts {
            let Some(registration) = state.registrations().get(&account.miner_id) else {
                continue;
            };
            let idena_address = registration.idena_address.to_ascii_lowercase();
            let score = scores
                .get(&idena_address)
                .map(|score| score.eligible_score)
                .unwrap_or(0);
            if score > 0 {
                registration
                    .verify_idena_ownership_signature()
                    .with_context(|| {
                        format!(
                            "failed to verify Idena ownership proof for miner {} at {}",
                            account.miner_id, idena_address
                        )
                    })?;
            }
            account.idena_score = score;
        }
    }
    let selected = select_dashboard_account(&accounts, state.registrations(), account_selector);
    let total_hashrate_score = accounts.iter().fold(0u128, |sum, account| {
        sum.saturating_add(account.hashrate_score)
    });
    let total_idena_score = accounts.iter().fold(0u128, |sum, account| {
        sum.saturating_add(account.idena_score)
    });
    let user_hashrate_score = selected
        .as_ref()
        .map(|account| account.hashrate_score)
        .unwrap_or(0);
    let user_idena_score = selected
        .as_ref()
        .map(|account| account.idena_score)
        .unwrap_or(0);
    let relative_hashrate_share = ratio(user_hashrate_score, total_hashrate_score);
    let relative_idena_share = ratio(user_idena_score, total_idena_score);
    let combined_reward_weight = (relative_hashrate_share * 0.5) + (relative_idena_share * 0.5);
    let payout_route = projected_payout_route(&accounts, selected.as_ref());
    let selected_registration = selected
        .as_ref()
        .and_then(|account| state.registrations().get(&account.miner_id));
    let selected_snapshot_score = selected_registration.and_then(|registration| {
        snapshot_scores
            .as_ref()
            .and_then(|scores| scores.get(&registration.idena_address.to_ascii_lowercase()))
    });
    let identity = selected
        .as_ref()
        .and_then(|account| {
            state
                .registrations()
                .get(&account.miner_id)
                .map(|registration| {
                    let snapshot = verified_snapshot.map(|verified| &verified.snapshot);
                    let snapshot_day = snapshot
                        .map(|snapshot| snapshot.snapshot_day.to_string())
                        .unwrap_or_else(|| "not available".to_string());
                    let snapshot_height = snapshot.map(|snapshot| snapshot.idena_height).unwrap_or(0);
                    let snapshot_root = snapshot
                        .map(|snapshot| snapshot.score_root.clone())
                        .unwrap_or_else(|| "not available".to_string());
                    let status = selected_snapshot_score
                        .map(|score| score.status.clone())
                        .unwrap_or_else(|| "Unknown".to_string());
                    let (pledge_status, pledge_detail) = match selected_snapshot_score {
                        Some(score) if score.block_eligible => (
                            "verified".to_string(),
                            "registration and latest snapshot replayed locally".to_string(),
                        ),
                        Some(_) => (
                            "pending".to_string(),
                            "registration replayed; identity is not payout-eligible in the latest snapshot"
                                .to_string(),
                        ),
                        None if verified_snapshot.is_some() => (
                            "pending".to_string(),
                            "registration replayed; no latest snapshot leaf for this Idena address"
                                .to_string(),
                        ),
                        None => (
                            "pending".to_string(),
                            "local registration replayed; waiting for local snapshot".to_string(),
                        ),
                    };
                    DashboardIdentity {
                        idena_address: registration.idena_address.clone(),
                        pledge_detail,
                        pledge_status,
                        status,
                        snapshot_height,
                        snapshot_day,
                        snapshot_root,
                    }
                })
        })
        .unwrap_or_else(|| DashboardIdentity {
            idena_address: "not registered".to_string(),
            pledge_detail: "no local miner registration".to_string(),
            pledge_status: "pending".to_string(),
            status: "Unknown".to_string(),
            snapshot_height: 0,
            snapshot_day: "not available".to_string(),
            snapshot_root: "not available".to_string(),
        });

    Ok(DashboardApiResponse {
        generated_at_unix: current_unix_timestamp()?,
        source: "local-p2pool-node".to_string(),
        service_statuses: vec![
            DashboardServiceStatus {
                label: "P2Pool".to_string(),
                state: "connected".to_string(),
                detail: format!(
                    "{} messages / {} peers",
                    local_status.replay.applied_message_count,
                    peers.len()
                ),
            },
            DashboardServiceStatus {
                label: "Bitcoin".to_string(),
                state: bitcoin_status.state,
                detail: bitcoin_status.detail,
            },
            DashboardServiceStatus {
                label: "Idena".to_string(),
                state: idena_status.state,
                detail: idena_status.detail,
            },
            DashboardServiceStatus {
                label: "Snapshot".to_string(),
                state: snapshot_status.state,
                detail: snapshot_status.detail,
            },
        ],
        account: DashboardPoolSnapshot {
            identity,
            sharechain: DashboardSharechain {
                accepted_shares: replay_summary.active_share_count,
                stale_shares: replay_summary.inactive_share_count,
                hashrate_score: safe_score(user_hashrate_score),
                pool_hashrate_score: safe_score(total_hashrate_score),
                pool_hashrate_ths: 0.0,
                user_hashrate_ths: 0.0,
                relative_hashrate_share,
                recent_shares: recent_share_points(replay_summary.active_share_count),
            },
            idena_accounting: DashboardIdenaAccounting {
                validation_score: selected_snapshot_score
                    .map(|score| safe_score(score.validation_score))
                    .unwrap_or(0),
                proposer_committee_score: selected_snapshot_score
                    .map(|score| {
                        safe_score(score.proposer_score.saturating_add(score.committee_score))
                    })
                    .unwrap_or(0),
                invitation_score_ignored: selected_snapshot_score
                    .map(|score| safe_score(score.ignored_invitation_score))
                    .unwrap_or(0),
                pool_eligible_score: safe_score(total_idena_score),
                relative_idena_share,
                formula: "50% hashrate + 50% validation/proposer/final-committee score".to_string(),
                source: snapshot_accounting_source(verified_snapshot, selected_snapshot_score),
            },
            payout: DashboardPayout {
                combined_reward_weight,
                block_subsidy_btc: DEFAULT_BLOCK_SUBSIDY_BTC,
                estimated_fees_btc: 0.0,
                btc_usd_reference: DEFAULT_BTC_USD_REFERENCE,
                btc_usd_reference_label: "local display reference".to_string(),
                direct_payout_eligible: payout_route.direct_payout_eligible,
                direct_rank: payout_route.direct_rank,
                direct_limit: DIRECT_PAYOUT_LIMIT,
                next_direct_threshold_sats: payout_route.direct_cutoff_sats,
                coinbase_output_budget_vb: 3_100,
                direct_fee_basis_sat_vb: 3,
                vault_claim_sats: payout_route.projected_vault_claim_sats,
                estimated_withdrawal_fee_sats: payout_route.estimated_withdrawal_fee_sats,
                min_payout_sats: MIN_DIRECT_PAYOUT_SATS,
            },
            pool: DashboardPoolContext {
                expected_block_interval: "waiting for live pool hashrate".to_string(),
                chance30d: 0.0,
                bitcoin_network_hashrate_ehs: 0,
                vault_epoch: "not active".to_string(),
                frost_threshold: "no active vault epoch".to_string(),
                signer_count: 0,
                threshold_count: 0,
                pending_withdrawals: replay_summary.pending_withdrawal_count,
                last_vault_rotation: "not available".to_string(),
                vault_key: "not active".to_string(),
                active_nodes: peers.len() + 1,
            },
        },
    })
}

fn projected_payout_route(
    accounts: &[ParticipantAccount],
    selected: Option<&ParticipantAccount>,
) -> ProjectedPayoutRoute {
    let Some(selected) = selected else {
        return ProjectedPayoutRoute {
            direct_payout_eligible: false,
            direct_rank: 0,
            direct_cutoff_sats: MIN_DIRECT_PAYOUT_SATS,
            projected_vault_claim_sats: 0,
            estimated_withdrawal_fee_sats: 0,
        };
    };
    let selected_miner_id = selected.miner_id.to_ascii_lowercase();
    let Ok(schedule) = build_payout_schedule(
        accounts,
        DEFAULT_BLOCK_REWARD_SATS,
        DIRECT_PAYOUT_LIMIT,
        MIN_DIRECT_PAYOUT_SATS,
    ) else {
        return ProjectedPayoutRoute {
            direct_payout_eligible: false,
            direct_rank: 0,
            direct_cutoff_sats: MIN_DIRECT_PAYOUT_SATS,
            projected_vault_claim_sats: selected.unpaid_sats,
            estimated_withdrawal_fee_sats: 0,
        };
    };

    let mut delta_by_miner = BTreeMap::<String, u64>::new();
    for output in &schedule.direct_outputs {
        delta_by_miner.insert(output.miner_id.to_ascii_lowercase(), output.amount_sats);
    }
    for allocation in &schedule.vault_allocations {
        delta_by_miner.insert(
            allocation.miner_id.to_ascii_lowercase(),
            allocation.amount_sats,
        );
    }
    let direct_miner_ids = schedule
        .direct_outputs
        .iter()
        .map(|output| output.miner_id.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();

    let mut ranked = accounts
        .iter()
        .map(|account| {
            let miner_id = account.miner_id.to_ascii_lowercase();
            let delta = delta_by_miner.get(&miner_id).copied().unwrap_or(0);
            let rank_balance = account.unpaid_sats.saturating_add(delta);
            (miner_id, delta, rank_balance)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(a_id, a_delta, a_rank), (b_id, b_delta, b_rank)| {
        b_rank
            .cmp(a_rank)
            .then_with(|| b_delta.cmp(a_delta))
            .then_with(|| a_id.cmp(b_id))
    });

    let direct_rank = ranked
        .iter()
        .position(|(miner_id, _, _)| miner_id == &selected_miner_id)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let direct_payout_eligible = direct_miner_ids.contains(&selected_miner_id);
    let selected_delta = delta_by_miner.get(&selected_miner_id).copied().unwrap_or(0);
    let direct_cutoff_sats = if direct_miner_ids.len() >= DIRECT_PAYOUT_LIMIT {
        ranked
            .iter()
            .filter(|(miner_id, _, _)| direct_miner_ids.contains(miner_id))
            .map(|(_, _, rank_balance)| *rank_balance)
            .min()
            .unwrap_or(MIN_DIRECT_PAYOUT_SATS)
            .max(MIN_DIRECT_PAYOUT_SATS)
    } else {
        MIN_DIRECT_PAYOUT_SATS
    };
    let projected_vault_claim_sats = if direct_payout_eligible {
        selected.unpaid_sats
    } else {
        selected.unpaid_sats.saturating_add(selected_delta)
    };

    ProjectedPayoutRoute {
        direct_payout_eligible,
        direct_rank,
        direct_cutoff_sats,
        projected_vault_claim_sats,
        estimated_withdrawal_fee_sats: 0,
    }
}

async fn bitcoin_service_status(config: &DashboardApiConfig) -> DashboardServiceStatus {
    let Some(rpc_url) = config.bitcoin_rpc_url.as_ref() else {
        return service_status("Bitcoin", "pending", "not configured");
    };
    let Ok(client) = BitcoinRpcClient::new_with_remote_policy(
        rpc_url,
        config.bitcoin_rpc_auth.clone(),
        config.allow_remote_rpc,
    ) else {
        return service_status("Bitcoin", "warning", "invalid RPC URL");
    };
    match timeout(config.probe_timeout, client.get_blockchain_info()).await {
        Ok(info) => {
            let Ok(info) = info else {
                return service_status("Bitcoin", "warning", "RPC unavailable");
            };
            let progress = (info.verificationprogress * 100.0).clamp(0.0, 100.0);
            let state = if info.initial_block_download || info.blocks < info.headers {
                "syncing"
            } else {
                "connected"
            };
            let pruned = if info.pruned { ", pruned" } else { "" };
            service_status(
                "Bitcoin",
                state,
                format!(
                    "{} {}/{} blocks, {:.2}%{}",
                    info.chain, info.blocks, info.headers, progress, pruned
                ),
            )
        }
        Err(_) => service_status("Bitcoin", "warning", "RPC timed out"),
    }
}

async fn idena_service_status(
    config: &DashboardApiConfig,
) -> (
    DashboardServiceStatus,
    Option<SyncingResponse>,
    Option<EpochResponse>,
) {
    let (Some(rpc_url), Some(api_key_file)) = (
        config.idena_rpc_url.as_ref(),
        config.idena_api_key_file.as_ref(),
    ) else {
        return (
            service_status("Idena", "pending", "not configured"),
            None,
            None,
        );
    };
    let Ok(client) = IdenaRpcClient::from_api_key_file_with_remote_policy(
        rpc_url,
        api_key_file,
        config.allow_remote_rpc,
    ) else {
        return (
            service_status("Idena", "warning", "API key unavailable"),
            None,
            None,
        );
    };
    let syncing = match timeout(config.probe_timeout, client.syncing()).await {
        Ok(Ok(syncing)) => syncing,
        Ok(Err(_)) => {
            return (
                service_status("Idena", "warning", "RPC unavailable"),
                None,
                None,
            )
        }
        Err(_) => {
            return (
                service_status("Idena", "warning", "RPC timed out"),
                None,
                None,
            )
        }
    };
    let epoch = timeout(config.probe_timeout, client.epoch())
        .await
        .ok()
        .and_then(|result| result.ok());
    let progress = if syncing.highest_block == 0 {
        0.0
    } else {
        (syncing.current_block as f64 / syncing.highest_block as f64 * 100.0).clamp(0.0, 100.0)
    };
    let state = if syncing.is_effectively_syncing() {
        "syncing"
    } else {
        "connected"
    };
    let epoch_detail = epoch
        .as_ref()
        .map(|epoch| format!(", epoch {} {}", epoch.epoch, epoch.current_period))
        .unwrap_or_default();
    let time_warning = if syncing.wrong_time {
        ", clock warning"
    } else {
        ""
    };
    let status = service_status(
        "Idena",
        state,
        format!(
            "{}/{} blocks, {:.2}%{}{}",
            syncing.current_block, syncing.highest_block, progress, epoch_detail, time_warning
        ),
    );
    (status, Some(syncing), epoch)
}

fn snapshot_service_status(
    idena_status: &DashboardServiceStatus,
    idena_syncing: Option<&SyncingResponse>,
    idena_epoch: Option<&EpochResponse>,
    snapshot_directory: Option<&local_node::SnapshotDirectoryStatus>,
) -> DashboardServiceStatus {
    if let Some(directory) = snapshot_directory {
        if let Some(latest) = directory.latest.as_ref() {
            let mut detail = format!(
                "local root {} height {}",
                latest.snapshot.snapshot_day, latest.snapshot.idena_height
            );
            if directory.invalid_file_count > 0 {
                detail.push_str(&format!(
                    ", {} invalid ignored",
                    directory.invalid_file_count
                ));
            }
            if directory.skipped_file_count > 0 {
                detail.push_str(&format!(
                    ", {} skipped over scan cap",
                    directory.skipped_file_count
                ));
            }
            let state = if directory.invalid_file_count > 0 || directory.skipped_file_count > 0 {
                "warning"
            } else {
                "connected"
            };
            return service_status("Snapshot", state, detail);
        }
        if directory.invalid_file_count > 0 {
            return service_status(
                "Snapshot",
                "warning",
                format!(
                    "no valid local root; {} invalid files ignored",
                    directory.invalid_file_count
                ),
            );
        }
        if directory.skipped_file_count > 0 {
            return service_status(
                "Snapshot",
                "warning",
                format!(
                    "no valid local root; {} files skipped over scan cap",
                    directory.skipped_file_count
                ),
            );
        }
    }
    match idena_status.state.as_str() {
        "connected" => {
            let detail = idena_epoch
                .map(|epoch| {
                    format!(
                        "Idena ready at epoch {} {}; waiting for local root",
                        epoch.epoch, epoch.current_period
                    )
                })
                .or_else(|| {
                    idena_syncing.map(|syncing| {
                        format!(
                            "Idena ready at {}; waiting for local root",
                            syncing.current_block
                        )
                    })
                })
                .unwrap_or_else(|| "waiting for local root".to_string());
            service_status("Snapshot", "pending", detail)
        }
        "syncing" => {
            let detail = idena_syncing
                .map(|syncing| format!("waiting for Idena sync at {}", syncing.current_block))
                .unwrap_or_else(|| "waiting for Idena sync".to_string());
            service_status("Snapshot", "pending", detail)
        }
        "warning" => service_status("Snapshot", "warning", "Idena RPC required"),
        _ => service_status("Snapshot", "pending", "not configured"),
    }
}

fn snapshot_scores_by_idena_address(
    snapshot: &Snapshot,
) -> Result<BTreeMap<String, SnapshotScoreMaterial>> {
    snapshot.verify_score_root()?;
    let mut scores = BTreeMap::new();
    for leaf in &snapshot.leaves {
        let idena_address = leaf.idena_address.to_ascii_lowercase();
        let raw_eligible_score = leaf.eligible_score()?;
        let block_eligible = leaf.is_block_eligible();
        scores.insert(
            idena_address,
            SnapshotScoreMaterial {
                status: idena_status_label(&leaf.status),
                validation_score: leaf.validation_reward_score,
                proposer_score: leaf.proposer_reward_score,
                committee_score: leaf.committee_reward_score,
                ignored_invitation_score: leaf.ignored_invitation_score,
                eligible_score: if block_eligible {
                    raw_eligible_score
                } else {
                    0
                },
                block_eligible,
            },
        );
    }
    Ok(scores)
}

fn idena_status_label(status: &pohw_core::snapshot::IdenaStatus) -> String {
    match status {
        pohw_core::snapshot::IdenaStatus::Newbie => "Newbie",
        pohw_core::snapshot::IdenaStatus::Verified => "Verified",
        pohw_core::snapshot::IdenaStatus::Human => "Human",
        _ => "Unknown",
    }
    .to_string()
}

fn snapshot_accounting_source(
    verified_snapshot: Option<&local_node::VerifiedSnapshotFile>,
    selected_snapshot_score: Option<&SnapshotScoreMaterial>,
) -> String {
    match (verified_snapshot, selected_snapshot_score) {
        (Some(snapshot), Some(_)) => format!(
            "local verified snapshot {} height {}",
            snapshot.snapshot.snapshot_day, snapshot.snapshot.idena_height
        ),
        (Some(snapshot), None) => format!(
            "local verified snapshot {} height {}; no matching leaf",
            snapshot.snapshot.snapshot_day, snapshot.snapshot.idena_height
        ),
        (None, _) => "pending idena-lite-indexer snapshot".to_string(),
    }
}

fn service_status(
    label: impl Into<String>,
    state: impl Into<String>,
    detail: impl Into<String>,
) -> DashboardServiceStatus {
    DashboardServiceStatus {
        label: label.into(),
        state: state.into(),
        detail: detail.into(),
    }
}

async fn handle_dashboard_connection(
    mut stream: TcpStream,
    config: Arc<DashboardApiConfig>,
) -> Result<()> {
    let response = match timeout(
        Duration::from_secs(DASHBOARD_HEADER_TIMEOUT_SECONDS),
        read_http_request_headers(&mut stream),
    )
    .await
    {
        Ok(headers) => match headers? {
            Ok(request) => handle_http_request(&request, &config).await?,
            Err(response) => response,
        },
        Err(_) => http_response(
            "408 Request Timeout",
            "application/json",
            br#"{"error":"request headers timed out"}"#,
            None,
        ),
    };
    timeout(
        Duration::from_secs(DASHBOARD_WRITE_TIMEOUT_SECONDS),
        stream.write_all(&response),
    )
    .await
    .context("dashboard API write timed out")?
    .context("failed to write dashboard API response")?;
    Ok(())
}

async fn read_http_request_headers(
    stream: &mut TcpStream,
) -> Result<std::result::Result<String, Vec<u8>>> {
    let mut request = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let read = timeout(
            Duration::from_secs(DASHBOARD_READ_IDLE_TIMEOUT_SECONDS),
            stream.read(&mut chunk),
        )
        .await
        .context("dashboard API read timed out")?
        .context("failed to read dashboard API request")?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_HEADER_BYTES {
            return Ok(Err(http_response(
                "431 Request Header Fields Too Large",
                "application/json",
                br#"{"error":"request headers too large"}"#,
                None,
            )));
        }
        if http_headers_complete(&request) {
            break;
        }
    }

    if request.is_empty() {
        return Ok(Err(http_response(
            "400 Bad Request",
            "application/json",
            br#"{"error":"empty request"}"#,
            None,
        )));
    }
    match String::from_utf8(request) {
        Ok(request) => Ok(Ok(request)),
        Err(_) => Ok(Err(http_response(
            "400 Bad Request",
            "application/json",
            br#"{"error":"request headers are not valid UTF-8"}"#,
            None,
        ))),
    }
}

fn http_headers_complete(request: &[u8]) -> bool {
    request.windows(4).any(|window| window == b"\r\n\r\n")
        || request.windows(2).any(|window| window == b"\n\n")
}

async fn handle_http_request(request: &str, config: &DashboardApiConfig) -> Result<Vec<u8>> {
    let Some(first_line) = request.lines().next() else {
        return Ok(http_response(
            "400 Bad Request",
            "application/json",
            br#"{"error":"empty request"}"#,
            None,
        ));
    };
    let cors_origin = match checked_cors_origin(request, config) {
        Ok(origin) => origin,
        Err(response) => return Ok(response),
    };
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let target = match parse_request_target(raw_target) {
        Ok(target) => target,
        Err(_) => {
            return Ok(http_response(
                "400 Bad Request",
                "application/json",
                br#"{"error":"invalid request target"}"#,
                cors_origin.as_deref(),
            ));
        }
    };
    let public_explorer_request =
        method == "GET" && config.public_explorer && target.path.starts_with("/api/v1/");
    if method != "OPTIONS" && !public_explorer_request && !request_is_authorized(request, config) {
        return Ok(http_response(
            "401 Unauthorized",
            "application/json",
            br#"{"error":"unauthorized"}"#,
            cors_origin.as_deref(),
        ));
    }
    match (method, target.path.as_str()) {
        ("OPTIONS", _) => Ok(http_response(
            "204 No Content",
            "text/plain",
            b"",
            cors_origin.as_deref(),
        )),
        ("GET", "/health") => Ok(http_response(
            "200 OK",
            "application/json",
            br#"{"ok":true}"#,
            cors_origin.as_deref(),
        )),
        ("GET", "/") => Ok(http_response(
            "200 OK",
            "text/plain; charset=utf-8",
            b"PoHW dashboard and explorer API\n",
            cors_origin.as_deref(),
        )),
        ("GET", "/dashboard.json") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let snapshot = match build_dashboard_snapshot(config).await {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    eprintln!("warning: failed to build dashboard snapshot: {err:#}");
                    return Ok(http_response(
                        "503 Service Unavailable",
                        "application/json",
                        br#"{"error":"dashboard snapshot unavailable"}"#,
                        cors_origin.as_deref(),
                    ));
                }
            };
            let body = serde_json::to_vec_pretty(&snapshot)
                .context("failed to encode dashboard snapshot")?;
            Ok(http_response(
                "200 OK",
                "application/json",
                &body,
                cors_origin.as_deref(),
            ))
        }
        ("GET", "/api/v1/overview") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let overview = match explorer_api::build_overview(
                &config.datadir,
                config.snapshot_dir.as_deref(),
                config.fork_chain_client.as_ref(),
                config.bitcoin_index_client.as_ref(),
            )
            .await
            {
                Ok(overview) => overview,
                Err(err) => {
                    eprintln!("warning: failed to build public explorer overview: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            json_http_response("200 OK", &overview, cors_origin.as_deref())
        }
        ("GET", "/api/v1/governance") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            match governance_api::load_dashboard(config.governance_state_file.as_deref()) {
                Ok(snapshot) => json_http_response("200 OK", &snapshot, cors_origin.as_deref()),
                Err(err) => {
                    eprintln!("warning: governance dashboard snapshot failed validation: {err:#}");
                    Ok(explorer_unavailable(cors_origin.as_deref()))
                }
            }
        }
        ("GET", "/api/v1/fork/blocks") => {
            let (cursor, limit) = match explorer_pagination(&target.query) {
                Ok(page) => page,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let page = match explorer_api::fork_block_page(
                config.fork_chain_client.as_ref(),
                cursor,
                limit,
            )
            .await
            {
                Ok(page) => page,
                Err(err) => {
                    eprintln!("warning: failed to build public fork block page: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            json_http_response("200 OK", &page, cors_origin.as_deref())
        }
        ("GET", path)
            if path.starts_with("/api/v1/fork/blocks/") && path.ends_with("/transactions") =>
        {
            let block_hash =
                &path["/api/v1/fork/blocks/".len()..path.len() - "/transactions".len()];
            if explorer_api::validate_hash(block_hash, "fork block hash").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let (cursor, limit) = match explorer_numeric_pagination(&target.query) {
                Ok(page) => page,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let page = match explorer_api::fork_block_transactions(
                config.fork_chain_client.as_ref(),
                block_hash,
                cursor,
                limit,
            )
            .await
            {
                Ok(page) => page,
                Err(err) => {
                    eprintln!("warning: failed to build public fork transaction page: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            match page {
                Some(page) => json_http_response("200 OK", &page, cors_origin.as_deref()),
                None => Ok(explorer_not_found(cors_origin.as_deref())),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/fork/transactions/") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let txid = &path["/api/v1/fork/transactions/".len()..];
            if explorer_api::validate_hash(txid, "fork transaction id").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let transaction = match explorer_api::fork_transaction_detail(
                config.fork_chain_client.as_ref(),
                txid,
            )
            .await
            {
                Ok(transaction) => transaction,
                Err(err) => {
                    eprintln!("warning: failed to build public fork transaction detail: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            match transaction {
                Some(transaction) => {
                    json_http_response("200 OK", &transaction, cors_origin.as_deref())
                }
                None => Ok(explorer_not_found(cors_origin.as_deref())),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/fork/addresses/") => {
            let address_path = &path["/api/v1/fork/addresses/".len()..];
            let (address, resource) =
                if let Some(address) = address_path.strip_suffix("/transactions") {
                    (address, "transactions")
                } else if let Some(address) = address_path.strip_suffix("/utxos") {
                    (address, "utxos")
                } else {
                    (address_path, "summary")
                };
            if explorer_api::validate_bitcoin_address(address).is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            match resource {
                "summary" => {
                    if !target.query.is_empty() {
                        return Ok(bad_explorer_request(cors_origin.as_deref()));
                    }
                    match explorer_api::fork_address_summary(
                        config.fork_chain_client.as_ref(),
                        address,
                    )
                    .await
                    {
                        Ok(Some(summary)) => {
                            json_http_response("200 OK", &summary, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: failed to build public fork address summary: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "transactions" => {
                    let (cursor, limit) = match explorer_numeric_pagination(&target.query) {
                        Ok(page) => page,
                        Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
                    };
                    match explorer_api::fork_address_transactions(
                        config.fork_chain_client.as_ref(),
                        address,
                        cursor,
                        limit,
                    )
                    .await
                    {
                        Ok(Some(page)) => {
                            json_http_response("200 OK", &page, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: failed to build public fork address history: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "utxos" => {
                    let (cursor, limit) = match explorer_numeric_pagination(&target.query) {
                        Ok(page) => page,
                        Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
                    };
                    match explorer_api::fork_address_utxos(
                        config.fork_chain_client.as_ref(),
                        address,
                        cursor,
                        limit,
                    )
                    .await
                    {
                        Ok(Some(page)) => {
                            json_http_response("200 OK", &page, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: failed to build public fork address UTXOs: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        ("GET", "/api/v1/bitcoin/blocks") => {
            if target.query.keys().any(|key| key != "startHeight") {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let start_height = match target
                .query
                .get("startHeight")
                .map(|value| value.parse::<u64>())
                .transpose()
            {
                Ok(height) => height,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let inherited_tip = explorer_inherited_tip(config).await;
            match explorer_api::indexed_bitcoin_blocks(
                config.bitcoin_index_client.as_ref(),
                start_height,
                inherited_tip,
            )
            .await
            {
                Ok(Some(page)) => json_http_response("200 OK", &page, cors_origin.as_deref()),
                Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                Err(err) => {
                    eprintln!("warning: Bitcoin history block page failed: {err:#}");
                    Ok(explorer_unavailable(cors_origin.as_deref()))
                }
            }
        }
        ("GET", path) if path.starts_with("/api/v1/bitcoin/transactions/") => {
            let transaction_path = &path["/api/v1/bitcoin/transactions/".len()..];
            let (txid, resource) = if let Some(txid) = transaction_path.strip_suffix("/outspends") {
                (txid, "outspends")
            } else {
                (transaction_path, "transaction")
            };
            if explorer_api::validate_hash(txid, "Bitcoin transaction id").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            match resource {
                "transaction" => {
                    let inherited_tip = explorer_inherited_tip(config).await;
                    match explorer_api::indexed_bitcoin_transaction(
                        config.bitcoin_index_client.as_ref(),
                        txid,
                        inherited_tip,
                    )
                    .await
                    {
                        Ok(Some(transaction)) => {
                            json_http_response("200 OK", &transaction, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: Bitcoin history transaction lookup failed: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "outspends" => {
                    match explorer_api::indexed_bitcoin_transaction_outspends(
                        config.bitcoin_index_client.as_ref(),
                        txid,
                    )
                    .await
                    {
                        Ok(Some(outspends)) => {
                            json_http_response("200 OK", &outspends, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: Bitcoin history transaction outspends failed: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/bitcoin/heights/") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let height = match path["/api/v1/bitcoin/heights/".len()..].parse::<u64>() {
                Ok(height) => height,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let inherited_tip = explorer_inherited_tip(config).await;
            match explorer_api::indexed_bitcoin_block_at_height(
                config.bitcoin_index_client.as_ref(),
                height,
                inherited_tip,
            )
            .await
            {
                Ok(Some(block)) => json_http_response("200 OK", &block, cors_origin.as_deref()),
                Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                Err(err) => {
                    eprintln!("warning: Bitcoin history height lookup failed: {err:#}");
                    Ok(explorer_unavailable(cors_origin.as_deref()))
                }
            }
        }
        ("GET", path) if path.starts_with("/api/v1/bitcoin/blocks/") => {
            let block_path = &path["/api/v1/bitcoin/blocks/".len()..];
            let (block_hash, resource) =
                if let Some(block_hash) = block_path.strip_suffix("/transactions") {
                    (block_hash, "transactions")
                } else {
                    (block_path, "block")
                };
            if explorer_api::validate_hash(block_hash, "Bitcoin block hash").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let inherited_tip = explorer_inherited_tip(config).await;
            match resource {
                "block" => {
                    if !target.query.is_empty() {
                        return Ok(bad_explorer_request(cors_origin.as_deref()));
                    }
                    match explorer_api::indexed_bitcoin_block(
                        config.bitcoin_index_client.as_ref(),
                        block_hash,
                        inherited_tip,
                    )
                    .await
                    {
                        Ok(Some(block)) => {
                            json_http_response("200 OK", &block, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!("warning: Bitcoin history block lookup failed: {err:#}");
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "transactions" => {
                    let start_index = match bitcoin_block_transaction_cursor(&target.query) {
                        Ok(cursor) => cursor,
                        Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
                    };
                    match explorer_api::indexed_bitcoin_block_transactions(
                        config.bitcoin_index_client.as_ref(),
                        block_hash,
                        start_index,
                        inherited_tip,
                    )
                    .await
                    {
                        Ok(Some(page)) => {
                            json_http_response("200 OK", &page, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: Bitcoin history block transactions failed: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/bitcoin/addresses/") => {
            let address_path = &path["/api/v1/bitcoin/addresses/".len()..];
            let (address, resource) =
                if let Some(address) = address_path.strip_suffix("/transactions") {
                    (address, "transactions")
                } else if let Some(address) = address_path.strip_suffix("/utxos") {
                    (address, "utxos")
                } else {
                    (address_path, "summary")
                };
            if explorer_api::validate_bitcoin_address(address).is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let inherited_tip = explorer_inherited_tip(config).await;
            match resource {
                "summary" => {
                    if !target.query.is_empty() {
                        return Ok(bad_explorer_request(cors_origin.as_deref()));
                    }
                    match explorer_api::indexed_bitcoin_address(
                        config.bitcoin_index_client.as_ref(),
                        address,
                    )
                    .await
                    {
                        Ok(Some(summary)) => {
                            json_http_response("200 OK", &summary, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!("warning: Bitcoin history address lookup failed: {err:#}");
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "transactions" => {
                    let cursor = match bitcoin_history_cursor(&target.query) {
                        Ok(cursor) => cursor,
                        Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
                    };
                    match explorer_api::indexed_bitcoin_address_transactions(
                        config.bitcoin_index_client.as_ref(),
                        address,
                        cursor.as_deref(),
                        inherited_tip,
                    )
                    .await
                    {
                        Ok(Some(page)) => {
                            json_http_response("200 OK", &page, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!(
                                "warning: Bitcoin history address transactions failed: {err:#}"
                            );
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                "utxos" => {
                    if !target.query.is_empty() {
                        return Ok(bad_explorer_request(cors_origin.as_deref()));
                    }
                    match explorer_api::indexed_bitcoin_address_utxos(
                        config.bitcoin_index_client.as_ref(),
                        address,
                        inherited_tip,
                    )
                    .await
                    {
                        Ok(Some(utxos)) => {
                            json_http_response("200 OK", &utxos, cors_origin.as_deref())
                        }
                        Ok(None) => Ok(explorer_not_found(cors_origin.as_deref())),
                        Err(err) => {
                            eprintln!("warning: Bitcoin history address UTXOs failed: {err:#}");
                            Ok(explorer_unavailable(cors_origin.as_deref()))
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        ("GET", "/api/v1/sharechain/shares") => {
            let (cursor, limit) = match explorer_pagination(&target.query) {
                Ok(page) => page,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let page = match explorer_api::share_page(
                &config.datadir,
                config.snapshot_dir.as_deref(),
                cursor.as_deref(),
                limit,
            )
            .await
            {
                Ok(page) => page,
                Err(err) => {
                    eprintln!("warning: failed to build public share page: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            json_http_response("200 OK", &page, cors_origin.as_deref())
        }
        ("GET", "/api/v1/idena/snapshot") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let overview = match explorer_api::build_overview(
                &config.datadir,
                config.snapshot_dir.as_deref(),
                config.fork_chain_client.as_ref(),
                config.bitcoin_index_client.as_ref(),
            )
            .await
            {
                Ok(overview) => overview,
                Err(err) => {
                    eprintln!("warning: failed to build public Idena snapshot: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            json_http_response("200 OK", &overview.idena, cors_origin.as_deref())
        }
        ("GET", path) if path.starts_with("/api/v1/fork/heights/") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let height = match path["/api/v1/fork/heights/".len()..].parse::<u64>() {
                Ok(height) => height,
                Err(_) => return Ok(bad_explorer_request(cors_origin.as_deref())),
            };
            let block =
                match explorer_api::fork_block_at_height(config.fork_chain_client.as_ref(), height)
                    .await
                {
                    Ok(block) => block,
                    Err(err) => {
                        eprintln!("warning: failed to build public fork height detail: {err:#}");
                        return Ok(explorer_unavailable(cors_origin.as_deref()));
                    }
                };
            match block {
                Some(block) => json_http_response("200 OK", &block, cors_origin.as_deref()),
                None => Ok(explorer_not_found(cors_origin.as_deref())),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/fork/blocks/") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let block_hash = &path["/api/v1/fork/blocks/".len()..];
            if explorer_api::validate_hash(block_hash, "fork block hash").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let block = match explorer_api::fork_block_summary(
                config.fork_chain_client.as_ref(),
                block_hash,
            )
            .await
            {
                Ok(block) => block,
                Err(err) => {
                    eprintln!("warning: failed to build public fork block detail: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            match block {
                Some(block) => json_http_response("200 OK", &block, cors_origin.as_deref()),
                None => Ok(explorer_not_found(cors_origin.as_deref())),
            }
        }
        ("GET", path) if path.starts_with("/api/v1/sharechain/shares/") => {
            if !target.query.is_empty() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let share_hash = &path["/api/v1/sharechain/shares/".len()..];
            if explorer_api::validate_hash(share_hash, "share hash").is_err() {
                return Ok(bad_explorer_request(cors_origin.as_deref()));
            }
            let share = match explorer_api::share_summary(
                &config.datadir,
                config.snapshot_dir.as_deref(),
                share_hash,
            )
            .await
            {
                Ok(share) => share,
                Err(err) => {
                    eprintln!("warning: failed to build public share detail: {err:#}");
                    return Ok(explorer_unavailable(cors_origin.as_deref()));
                }
            };
            match share {
                Some(share) => json_http_response("200 OK", &share, cors_origin.as_deref()),
                None => Ok(explorer_not_found(cors_origin.as_deref())),
            }
        }
        ("GET", _) => Ok(http_response(
            "404 Not Found",
            "application/json",
            br#"{"error":"not found"}"#,
            cors_origin.as_deref(),
        )),
        _ => Ok(http_response(
            "405 Method Not Allowed",
            "application/json",
            br#"{"error":"method not allowed"}"#,
            cors_origin.as_deref(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRequestTarget {
    path: String,
    query: BTreeMap<String, String>,
}

fn parse_request_target(raw: &str) -> Result<ParsedRequestTarget> {
    if !raw.starts_with('/') || raw.contains('#') || raw.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("request target must use HTTP origin form");
    }
    let (path, raw_query) = raw.split_once('?').unwrap_or((raw, ""));
    if path.is_empty() || path.contains('%') {
        bail!("request path is invalid");
    }
    let mut query = BTreeMap::new();
    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key.is_empty()
                || key.contains('%')
                || value.contains('%')
                || key.contains('+')
                || value.contains('+')
                || query.insert(key.to_string(), value.to_string()).is_some()
            {
                bail!("request query is invalid");
            }
        }
    }
    Ok(ParsedRequestTarget {
        path: path.to_string(),
        query,
    })
}

fn explorer_pagination(query: &BTreeMap<String, String>) -> Result<(Option<String>, usize)> {
    if query.keys().any(|key| key != "cursor" && key != "limit") {
        bail!("unsupported explorer query parameter");
    }
    let cursor = query
        .get("cursor")
        .cloned()
        .filter(|value| !value.is_empty());
    if let Some(cursor) = cursor.as_deref() {
        explorer_api::validate_hash(cursor, "explorer cursor")?;
    }
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>().context("invalid explorer limit"))
        .transpose()?
        .unwrap_or(explorer_api::DEFAULT_PAGE_LIMIT);
    explorer_api::validate_page_limit(limit)?;
    Ok((cursor, limit))
}

fn explorer_numeric_pagination(query: &BTreeMap<String, String>) -> Result<(usize, usize)> {
    if query.keys().any(|key| key != "cursor" && key != "limit") {
        bail!("unsupported explorer query parameter");
    }
    let cursor = query
        .get("cursor")
        .map(|value| value.parse::<usize>().context("invalid explorer cursor"))
        .transpose()?
        .unwrap_or(0);
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>().context("invalid explorer limit"))
        .transpose()?
        .unwrap_or(explorer_api::DEFAULT_PAGE_LIMIT);
    explorer_api::validate_numeric_page(cursor, limit)?;
    Ok((cursor, limit))
}

fn bitcoin_history_cursor(query: &BTreeMap<String, String>) -> Result<Option<String>> {
    if query.keys().any(|key| key != "cursor") {
        bail!("unsupported Bitcoin history query parameter");
    }
    let cursor = query
        .get("cursor")
        .cloned()
        .filter(|value| !value.is_empty());
    if let Some(cursor) = cursor.as_deref() {
        explorer_api::validate_hash(cursor, "Bitcoin history cursor")?;
    }
    Ok(cursor)
}

fn bitcoin_block_transaction_cursor(query: &BTreeMap<String, String>) -> Result<usize> {
    if query.keys().any(|key| key != "cursor") {
        bail!("unsupported Bitcoin block transaction query parameter");
    }
    let cursor = query
        .get("cursor")
        .map(|value| {
            value
                .parse::<usize>()
                .context("invalid Bitcoin block cursor")
        })
        .transpose()?
        .unwrap_or(0);
    if cursor > 10_000_000 {
        bail!("Bitcoin block transaction cursor exceeds the supported range");
    }
    Ok(cursor)
}

async fn explorer_inherited_tip(config: &DashboardApiConfig) -> Option<u64> {
    let client = config.fork_chain_client.as_ref()?;
    client
        .status()
        .await
        .ok()
        .map(|status| status.inherited_tip_height)
}

fn json_http_response<T: Serialize>(
    status: &str,
    value: &T,
    cors_origin: Option<&str>,
) -> Result<Vec<u8>> {
    let body = serde_json::to_vec_pretty(value).context("failed to encode API response")?;
    Ok(http_response(
        status,
        "application/json",
        &body,
        cors_origin,
    ))
}

fn bad_explorer_request(cors_origin: Option<&str>) -> Vec<u8> {
    http_response(
        "400 Bad Request",
        "application/json",
        br#"{"error":"invalid explorer request"}"#,
        cors_origin,
    )
}

fn explorer_not_found(cors_origin: Option<&str>) -> Vec<u8> {
    http_response(
        "404 Not Found",
        "application/json",
        br#"{"error":"explorer object not found"}"#,
        cors_origin,
    )
}

fn explorer_unavailable(cors_origin: Option<&str>) -> Vec<u8> {
    http_response(
        "503 Service Unavailable",
        "application/json",
        br#"{"error":"explorer data unavailable"}"#,
        cors_origin,
    )
}

fn checked_cors_origin(
    request: &str,
    config: &DashboardApiConfig,
) -> std::result::Result<Option<String>, Vec<u8>> {
    let origin = match request_header(request, "origin") {
        Ok(Some(origin)) => origin,
        Ok(None) => return Ok(None),
        Err(_) => {
            return Err(http_response(
                "403 Forbidden",
                "application/json",
                br#"{"error":"duplicate origin header"}"#,
                None,
            ));
        }
    };
    if validate_origin(origin).is_err() {
        return Err(http_response(
            "403 Forbidden",
            "application/json",
            br#"{"error":"origin malformed"}"#,
            None,
        ));
    }
    if config
        .allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == origin)
    {
        Ok(Some(origin.to_string()))
    } else {
        Err(http_response(
            "403 Forbidden",
            "application/json",
            br#"{"error":"origin not allowed"}"#,
            None,
        ))
    }
}

fn validate_allowed_origins(origins: &[String]) -> Result<()> {
    for origin in origins {
        validate_origin(origin).map_err(|reason| {
            anyhow::anyhow!("invalid dashboard allowed origin {origin:?}: {reason}")
        })?;
    }
    Ok(())
}

fn validate_dashboard_api_token(token: &str, require_strong: bool) -> Result<()> {
    if token.is_empty() || token.len() > MAX_API_TOKEN_BYTES {
        bail!("dashboard API token must be 1-{MAX_API_TOKEN_BYTES} bytes");
    }
    if token
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("dashboard API token must not contain whitespace or control characters");
    }
    if require_strong && token.len() < MIN_NON_LOOPBACK_API_TOKEN_BYTES {
        bail!(
            "non-loopback dashboard API token must be at least {MIN_NON_LOOPBACK_API_TOKEN_BYTES} bytes"
        );
    }
    Ok(())
}

fn validate_account_selector(selector: &DashboardAccountSelector) -> Result<()> {
    let configured_count = [
        selector.miner_id.as_ref(),
        selector.claim_owner_id.as_ref(),
        selector.idena_address.as_ref(),
    ]
    .into_iter()
    .filter(|value| value.is_some())
    .count();
    if configured_count > 1 {
        bail!(
            "configure only one dashboard account selector: miner id, claim owner id, or Idena address"
        );
    }

    for (label, value) in [
        ("dashboard miner id", selector.miner_id.as_deref()),
        (
            "dashboard claim owner id",
            selector.claim_owner_id.as_deref(),
        ),
        ("dashboard Idena address", selector.idena_address.as_deref()),
    ] {
        if let Some(value) = value {
            if value.is_empty() || value.len() > 256 {
                bail!("{label} must be 1-256 bytes");
            }
            if value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                bail!("{label} must not contain whitespace or control characters");
            }
            if label == "dashboard Idena address" {
                let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                else {
                    bail!("{label} must be a 20-byte 0x-prefixed hex address");
                };
                if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    bail!("{label} must be a 20-byte 0x-prefixed hex address");
                }
            }
        }
    }
    Ok(())
}

fn validate_origin(origin: &str) -> std::result::Result<(), String> {
    if origin.is_empty() || origin.len() > 256 {
        return Err("origin must be 1-256 bytes".to_string());
    }
    if origin
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\t')
    {
        return Err("origin must not contain whitespace or control characters".to_string());
    }
    let parsed = Url::parse(origin).map_err(|err| err.to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("origin scheme must be http or https".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("origin must include a host".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("origin must not include userinfo".to_string());
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("origin must not include path, query, or fragment".to_string());
    }
    Ok(())
}

fn select_dashboard_account(
    accounts: &[ParticipantAccount],
    registrations: &BTreeMap<String, MinerRegistration>,
    selector: &DashboardAccountSelector,
) -> Option<ParticipantAccount> {
    if let Some(miner_id) = selector.miner_id.as_ref() {
        let miner_id = miner_id.to_ascii_lowercase();
        return accounts
            .iter()
            .find(|account| account.miner_id.eq_ignore_ascii_case(&miner_id))
            .cloned();
    }
    if let Some(claim_owner_id) = selector.claim_owner_id.as_ref() {
        let claim_owner_id = claim_owner_id.to_ascii_lowercase();
        return accounts
            .iter()
            .find(|account| account.claim_owner_id.eq_ignore_ascii_case(&claim_owner_id))
            .cloned();
    }
    if let Some(idena_address) = selector.idena_address.as_ref() {
        let idena_address = idena_address.to_ascii_lowercase();
        let miner_id = registrations
            .values()
            .find(|registration| {
                registration
                    .idena_address
                    .eq_ignore_ascii_case(&idena_address)
            })
            .map(|registration| registration.miner_id.to_ascii_lowercase())?;
        return accounts
            .iter()
            .find(|account| account.miner_id.eq_ignore_ascii_case(&miner_id))
            .cloned();
    }
    if accounts.len() == 1 {
        return accounts.first().cloned();
    }
    None
}

fn request_is_authorized(request: &str, config: &DashboardApiConfig) -> bool {
    let Some(expected_token) = config.api_token.as_ref() else {
        return true;
    };
    request_header(request, "x-pohw-dashboard-token")
        .ok()
        .flatten()
        .map(|provided_token| {
            constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes())
        })
        .unwrap_or(false)
}

fn request_header<'a>(request: &'a str, name: &str) -> std::result::Result<Option<&'a str>, ()> {
    let mut values = request
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        });
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    Ok(first)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn http_response(
    status: &str,
    content_type: &str,
    body: &[u8],
    cors_origin: Option<&str>,
) -> Vec<u8> {
    let cors_headers = cors_origin
        .map(|origin| {
            format!(
                "Access-Control-Allow-Origin: {origin}\r\n\
                 Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                 Access-Control-Allow-Headers: Accept, Content-Type, X-PoHW-Dashboard-Token\r\n"
            )
        })
        .unwrap_or_default();
    let headers = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Vary: Origin\r\n\
         {cors_headers}\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut response = headers.into_bytes();
    response.extend_from_slice(body);
    response
}

fn recent_share_points(applied_message_count: usize) -> Vec<DashboardSharePoint> {
    ["00", "03", "06", "09", "12", "15", "18", "21"]
        .into_iter()
        .enumerate()
        .map(|(idx, label)| DashboardSharePoint {
            label: label.to_string(),
            accepted: if idx == 7 { applied_message_count } else { 0 },
            stale: 0,
        })
        .collect()
}

fn ratio(value: u128, total: u128) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64).clamp(0.0, 1.0)
    }
}

fn safe_score(score: u128) -> u64 {
    score.min(MAX_SAFE_JS_INTEGER) as u64
}

fn current_unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(duration.as_secs()).context("system timestamp does not fit in i64")
}

#[derive(Debug, Clone)]
struct ConnectionLimiter {
    max_connections: usize,
    max_connections_per_ip: usize,
    state: Arc<StdMutex<ConnectionLimiterState>>,
}

#[derive(Debug, Default)]
struct ConnectionLimiterState {
    total: usize,
    by_ip: BTreeMap<IpAddr, usize>,
}

#[derive(Debug)]
struct ConnectionGuard {
    ip: IpAddr,
    state: Arc<StdMutex<ConnectionLimiterState>>,
}

impl ConnectionLimiter {
    fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self {
            max_connections,
            max_connections_per_ip,
            state: Arc::new(StdMutex::new(ConnectionLimiterState::default())),
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        let mut state = self.state.lock().ok()?;
        let ip_count = state.by_ip.get(&ip).copied().unwrap_or(0);
        if state.total >= self.max_connections || ip_count >= self.max_connections_per_ip {
            return None;
        }
        state.total += 1;
        *state.by_ip.entry(ip).or_default() += 1;
        Some(ConnectionGuard {
            ip,
            state: Arc::clone(&self.state),
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.total = state.total.saturating_sub(1);
        let mut remove_ip = false;
        if let Some(count) = state.by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            remove_ip = *count == 0;
        }
        if remove_ip {
            state.by_ip.remove(&self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use pohw_core::snapshot::{IdenaStatus, Snapshot, SnapshotLeaf};
    use pohw_core::FORMULA_VERSION;
    use std::fs;

    #[test]
    fn empty_datadir_snapshot_is_pending_and_local() {
        let datadir = temp_datadir("empty_datadir_snapshot_is_pending_and_local");
        let snapshot = build_dashboard_snapshot_with_statuses(
            &datadir,
            None,
            service_status("Bitcoin", "pending", "not configured"),
            service_status("Idena", "pending", "not configured"),
            service_status("Snapshot", "pending", "not configured"),
            &DashboardAccountSelector::default(),
            None,
        )
        .unwrap();
        assert_eq!(snapshot.source, "local-p2pool-node");
        assert_eq!(snapshot.account.identity.pledge_status, "pending");
        assert_eq!(snapshot.account.identity.idena_address, "not registered");
        assert_eq!(snapshot.account.sharechain.accepted_shares, 0);
        assert_eq!(snapshot.account.pool.active_nodes, 1);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_returns_without_cors_for_no_origin() {
        let datadir = temp_datadir("dashboard_json_route_returns_without_cors_for_no_origin");
        let config = test_config(datadir.clone());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(!response.contains("Access-Control-Allow-Origin"));
        assert!(response.contains("X-Content-Type-Options: nosniff"));
        assert!(response.contains("X-Frame-Options: DENY"));
        assert!(response.contains("Referrer-Policy: no-referrer"));
        assert!(response.contains("Cross-Origin-Opener-Policy: same-origin"));
        assert!(response.contains("\"source\": \"local-p2pool-node\""));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_allows_configured_origin() {
        let datadir = temp_datadir("dashboard_json_route_allows_configured_origin");
        let config = test_config(datadir.clone());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5176\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:5176"));
        assert!(response.contains("Vary: Origin"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_rejects_unknown_origin() {
        let datadir = temp_datadir("dashboard_json_route_rejects_unknown_origin");
        let config = test_config(datadir.clone());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(!response.contains("Access-Control-Allow-Origin"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_rejects_malformed_origin() {
        let datadir = temp_datadir("dashboard_json_route_rejects_malformed_origin");
        let mut config = test_config(datadir.clone());
        config
            .allowed_origins
            .push("http://127.0.0.1:5177\rX-Injected: yes".to_string());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\rX-Injected: yes\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(!response.contains("X-Injected"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_rejects_duplicate_origin_headers() {
        let datadir = temp_datadir("dashboard_json_route_rejects_duplicate_origin_headers");
        let config = test_config(datadir.clone());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\r\nOrigin: https://evil.example\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(!response.contains("Access-Control-Allow-Origin"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_returns_503_when_snapshot_build_fails() {
        let datadir = temp_datadir("dashboard_json_route_returns_503_when_snapshot_build_fails");
        fs::write(
            datadir.join("sharechain.ndjson"),
            "not-json\nstill-not-json\n",
        )
        .unwrap();
        let config = test_config(datadir.clone());

        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:5177"));
        assert!(response.contains(r#"{"error":"dashboard snapshot unavailable"}"#));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn allowed_origin_validation_rejects_header_injection() {
        assert!(validate_allowed_origins(&["http://127.0.0.1:5177".to_string()]).is_ok());
        assert!(
            validate_allowed_origins(&["http://127.0.0.1:5177\r\nX-Bad: 1".to_string()]).is_err()
        );
        assert!(validate_allowed_origins(&["http://127.0.0.1:5177/path".to_string()]).is_err());
    }

    #[test]
    fn dashboard_config_requires_strong_token_for_non_loopback() {
        let datadir = temp_datadir("dashboard_config_requires_strong_token_for_non_loopback");
        let mut config = test_config(datadir.clone());
        config.bind_addr = "0.0.0.0:0".parse().unwrap();
        config.allow_non_loopback = true;
        config.api_token = None;
        assert!(validate_dashboard_api_config(&config).is_err());

        config.api_token = Some("short".to_string());
        assert!(validate_dashboard_api_config(&config).is_err());

        config.api_token = Some("0123456789abcdef01234567".to_string());
        assert!(validate_dashboard_api_config(&config).is_ok());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn dashboard_token_validation_rejects_ambiguous_values() {
        assert!(validate_dashboard_api_token("abc def", false).is_err());
        assert!(validate_dashboard_api_token("abc\rdef", false).is_err());
        assert!(validate_dashboard_api_token("", false).is_err());
        assert!(validate_dashboard_api_token("short", true).is_err());
        assert!(validate_dashboard_api_token("0123456789abcdef01234567", true).is_ok());
    }

    #[test]
    fn http_header_completion_detects_lf_and_crlf_terminators() {
        assert!(http_headers_complete(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(http_headers_complete(b"GET / HTTP/1.1\nHost: x\n\n"));
        assert!(!http_headers_complete(b"GET / HTTP/1.1\r\nHost: x\r\n"));
    }

    #[test]
    fn connection_limiter_enforces_total_and_per_ip_limits() {
        let limiter = ConnectionLimiter::new(2, 1);
        let first_ip = IpAddr::from([127, 0, 0, 1]);
        let second_ip = IpAddr::from([127, 0, 0, 2]);

        let first = limiter.try_acquire(first_ip).unwrap();
        assert!(limiter.try_acquire(first_ip).is_none());
        let second = limiter.try_acquire(second_ip).unwrap();
        assert!(limiter.try_acquire(IpAddr::from([127, 0, 0, 3])).is_none());

        drop(first);
        let replacement = limiter.try_acquire(first_ip).unwrap();
        drop(second);
        drop(replacement);
    }

    #[test]
    fn snapshot_status_uses_latest_verified_local_root() {
        let snapshot = test_snapshot(vec![snapshot_leaf(
            "0x1111111111111111111111111111111111111111",
            IdenaStatus::Human,
            7,
        )]);
        let directory = local_node::SnapshotDirectoryStatus {
            snapshot_dir: PathBuf::from("/tmp/snapshots"),
            scanned_file_count: 2,
            invalid_file_count: 1,
            skipped_file_count: 0,
            latest: Some(local_node::VerifiedSnapshotFile {
                path: PathBuf::from("/tmp/snapshots/latest.json"),
                snapshot,
            }),
        };

        let status = snapshot_service_status(
            &service_status("Idena", "syncing", "still syncing"),
            None,
            None,
            Some(&directory),
        );

        assert_eq!(status.state, "warning");
        assert!(status.detail.contains("local root 2026-06-30 height 42"));
        assert!(status.detail.contains("1 invalid ignored"));
    }

    #[test]
    fn snapshot_scores_only_count_block_eligible_identities() {
        let human = "0x1111111111111111111111111111111111111111";
        let candidate = "0x2222222222222222222222222222222222222222";
        let snapshot = test_snapshot(vec![
            snapshot_leaf(human, IdenaStatus::Human, 7),
            snapshot_leaf(candidate, IdenaStatus::Candidate, 11),
        ]);

        let scores = snapshot_scores_by_idena_address(&snapshot).unwrap();

        assert_eq!(scores[human].status, "Human");
        assert_eq!(scores[human].eligible_score, 7);
        assert_eq!(scores[candidate].status, "Unknown");
        assert_eq!(scores[candidate].eligible_score, 0);
    }

    #[test]
    fn dashboard_payout_route_uses_deterministic_direct_rank() {
        let mut accounts = (0..100)
            .map(|idx| ParticipantAccount {
                miner_id: format!("competitor-{idx:03}"),
                btc_payout_script_hex:
                    "51200000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                claim_owner_id: format!("claim-{idx:03}"),
                unpaid_sats: 1_000_000,
                hashrate_score: 1,
                idena_score: 1,
            })
            .collect::<Vec<_>>();
        let selected = ParticipantAccount {
            miner_id: "local-miner".to_string(),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_id: "local-claim".to_string(),
            unpaid_sats: 0,
            hashrate_score: 1,
            idena_score: 1,
        };
        accounts.push(selected.clone());

        let route = projected_payout_route(&accounts, Some(&selected));

        assert_eq!(route.direct_rank, 101);
        assert!(!route.direct_payout_eligible);
        assert!(route.projected_vault_claim_sats >= MIN_DIRECT_PAYOUT_SATS);
        assert!(route.direct_cutoff_sats > MIN_DIRECT_PAYOUT_SATS);
    }

    #[test]
    fn dashboard_account_selector_requires_explicit_local_account_when_ambiguous() {
        let accounts = vec![
            participant_account("local-miner", "claim-local", 10),
            participant_account("large-remote-miner", "claim-remote", 1_000),
        ];
        let registrations = std::collections::BTreeMap::new();

        assert!(select_dashboard_account(
            &accounts,
            &registrations,
            &DashboardAccountSelector::default()
        )
        .is_none());

        let selected = select_dashboard_account(
            &accounts,
            &registrations,
            &DashboardAccountSelector {
                miner_id: Some("local-miner".to_string()),
                ..DashboardAccountSelector::default()
            },
        )
        .unwrap();
        assert_eq!(selected.miner_id, "local-miner");

        let selected = select_dashboard_account(
            &accounts,
            &registrations,
            &DashboardAccountSelector {
                claim_owner_id: Some("claim-remote".to_string()),
                ..DashboardAccountSelector::default()
            },
        )
        .unwrap();
        assert_eq!(selected.miner_id, "large-remote-miner");
    }

    #[test]
    fn dashboard_account_selector_can_use_idena_address() {
        let accounts = vec![
            participant_account("local-miner", "claim-local", 10),
            participant_account("remote-miner", "claim-remote", 1_000),
        ];
        let mut registrations = std::collections::BTreeMap::new();
        registrations.insert(
            "local-miner".to_string(),
            miner_registration(
                "local-miner",
                "0x1111111111111111111111111111111111111111",
                "claim-local",
            ),
        );

        let selected = select_dashboard_account(
            &accounts,
            &registrations,
            &DashboardAccountSelector {
                idena_address: Some("0x1111111111111111111111111111111111111111".to_string()),
                ..DashboardAccountSelector::default()
            },
        )
        .unwrap();

        assert_eq!(selected.miner_id, "local-miner");
    }

    #[test]
    fn dashboard_account_selector_keeps_single_account_convenience() {
        let accounts = vec![participant_account("only-miner", "claim-only", 10)];
        let registrations = std::collections::BTreeMap::new();

        let selected = select_dashboard_account(
            &accounts,
            &registrations,
            &DashboardAccountSelector::default(),
        )
        .unwrap();

        assert_eq!(selected.miner_id, "only-miner");
    }

    #[test]
    fn dashboard_account_selector_rejects_multiple_selectors() {
        let err = validate_account_selector(&DashboardAccountSelector {
            miner_id: Some("local-miner".to_string()),
            claim_owner_id: Some("claim-local".to_string()),
            idena_address: None,
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("configure only one"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn dashboard_account_selector_rejects_invalid_idena_address() {
        let err = validate_account_selector(&DashboardAccountSelector {
            idena_address: Some("0x1234".to_string()),
            ..DashboardAccountSelector::default()
        })
        .unwrap_err();

        assert!(
            err.to_string().contains("20-byte"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn dashboard_json_route_requires_token_when_configured() {
        let datadir = temp_datadir("dashboard_json_route_requires_token_when_configured");
        let mut config = test_config(datadir.clone());
        config.api_token = Some("secret".to_string());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:5177"));

        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\r\nX-PoHW-Dashboard-Token: secret\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn public_explorer_routes_are_anonymous_but_dashboard_stays_private() {
        let datadir = temp_datadir("public_explorer_routes_are_anonymous");
        let mut config = test_config(datadir.clone());
        config.api_token = Some("secret".to_string());
        config.public_explorer = true;

        let response = handle_http_request(
            "GET /api/v1/overview HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"apiVersion\": \"pohw-explorer-v1\""));
        assert!(response.contains("\"registeredMinerCount\": 0"));
        assert!(response.contains("\"bitcoinHistory\""));
        assert!(response.contains("\"participantIndexRequired\": false"));
        assert!(response.contains("\"safetyBoundaries\""));
        assert!(!response.contains("idenaAddress"));
        assert!(!response.contains("payoutScript"));

        let governance = handle_http_request(
            "GET /api/v1/governance HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let governance = String::from_utf8(governance).unwrap();
        assert!(governance.starts_with("HTTP/1.1 200 OK"));
        assert!(governance.contains("pohw-governance-dashboard-v1"));
        assert!(governance.contains("EXPERIMENTAL / NO-VALUE"));
        assert!(governance.contains("\"status\": \"unconfigured\""));

        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 401 Unauthorized"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn private_explorer_route_requires_dashboard_token() {
        let datadir = temp_datadir("private_explorer_route_requires_dashboard_token");
        let mut config = test_config(datadir.clone());
        config.api_token = Some("secret".to_string());

        let response = handle_http_request(
            "GET /api/v1/overview HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 401 Unauthorized"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn explorer_routes_paginate_and_reject_invalid_inputs() {
        let datadir = temp_datadir("explorer_share_page_is_paginated");
        let config = test_config(datadir.clone());

        let response = handle_http_request(
            "GET /api/v1/sharechain/shares?limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"total\": 0"));
        assert!(response.contains("\"items\": []"));

        let response = handle_http_request(
            "GET /api/v1/sharechain/shares?unknown=1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 400 Bad Request"));

        for target in [
            "/api/v1/fork/blocks/not-a-hash",
            "/api/v1/fork/transactions/not-a-hash",
            "/api/v1/fork/addresses/not-an-address",
            "/api/v1/bitcoin/transactions/not-a-hash",
            "/api/v1/bitcoin/transactions/not-a-hash/outspends",
            "/api/v1/bitcoin/blocks/not-a-hash/transactions",
            "/api/v1/bitcoin/addresses/not-an-address",
            "/api/v1/sharechain/shares/not-a-hash",
        ] {
            let response = handle_http_request(
                &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                &config,
            )
            .await
            .unwrap();
            assert!(String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 400 Bad Request"));
        }

        let hash = "ab".repeat(32);
        let response = handle_http_request(
            &format!(
                "GET /api/v1/bitcoin/blocks/{hash}/transactions?cursor=invalid HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ),
            &config,
        )
        .await
        .unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 400 Bad Request"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn bitcoin_history_route_proxies_bounded_loopback_index_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let txid = "ab".repeat(32);
        let expected_path = format!("GET /tx/{txid} HTTP/1.1");
        let server_txid = txid.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let count = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with(&expected_path));
            let body = format!(
                r#"{{"txid":"{server_txid}","version":2,"locktime":0,"size":100,"weight":400,"fee":10,"vin":[],"vout":[],"status":{{"confirmed":true,"block_height":42,"block_hash":"{}"}}}}"#,
                "cd".repeat(32)
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let datadir = temp_datadir("bitcoin_history_route_proxies_index_data");
        let mut config = test_config(datadir.clone());
        config.public_explorer = true;
        config.bitcoin_index_client =
            Some(BitcoinExplorerIndexClient::new(&format!("http://{addr}"), false).unwrap());
        let response = handle_http_request(
            &format!("GET /api/v1/bitcoin/transactions/{txid} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            &config,
        )
        .await
        .unwrap();
        server.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"scope\": \"bitcoin_mainnet_history\""));
        assert!(response.contains("\"forkRelation\": \"fork_point_unavailable\""));
        assert!(response.contains(&format!("\"txid\": \"{txid}\"")));
        assert!(!response.contains("cookie"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn bitcoin_history_nested_routes_proxy_block_transactions_and_outspends() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hash = "ab".repeat(32);
        let block_path = format!("GET /block/{hash}/txs/0 HTTP/1.1");
        let outspend_path = format!("GET /tx/{hash}/outspends HTTP/1.1");
        let server = tokio::spawn(async move {
            for expected in [block_path, outspend_path] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 4096];
                let count = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                assert!(request.starts_with(&expected));
                let body = "[]";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let datadir = temp_datadir("bitcoin_history_nested_routes");
        let mut config = test_config(datadir.clone());
        config.public_explorer = true;
        config.bitcoin_index_client =
            Some(BitcoinExplorerIndexClient::new(&format!("http://{addr}"), false).unwrap());
        let block_response = handle_http_request(
            &format!(
                "GET /api/v1/bitcoin/blocks/{hash}/transactions HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ),
            &config,
        )
        .await
        .unwrap();
        let outspend_response = handle_http_request(
            &format!(
                "GET /api/v1/bitcoin/transactions/{hash}/outspends HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ),
            &config,
        )
        .await
        .unwrap();
        server.await.unwrap();
        let block_response = String::from_utf8(block_response).unwrap();
        assert!(block_response.starts_with("HTTP/1.1 200 OK"));
        assert!(block_response.contains("\"blockHash\""));
        assert!(block_response.contains("\"nextCursor\": null"));
        let outspend_response = String::from_utf8(outspend_response).unwrap();
        assert!(outspend_response.starts_with("HTTP/1.1 200 OK"));
        assert!(outspend_response.contains("\"items\": []"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn dashboard_json_route_rejects_duplicate_token_headers() {
        let datadir = temp_datadir("dashboard_json_route_rejects_duplicate_token_headers");
        let mut config = test_config(datadir.clone());
        config.api_token = Some("secret".to_string());
        let response = handle_http_request(
            "GET /dashboard.json HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:5177\r\nX-PoHW-Dashboard-Token: secret\r\nX-PoHW-Dashboard-Token: secret\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn refuses_unknown_route() {
        let datadir = temp_datadir("refuses_unknown_route");
        let config = test_config(datadir.clone());
        let response = handle_http_request(
            "POST /dashboard.json HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &config,
        )
        .await
        .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
        fs::remove_dir_all(datadir).unwrap();
    }

    fn temp_datadir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pohw-dashboard-api-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn snapshot_leaf(address: &str, status: IdenaStatus, score: u128) -> SnapshotLeaf {
        SnapshotLeaf {
            idena_address: address.to_string(),
            status,
            pubkey: "02".repeat(33),
            validation_reward_score: score,
            proposer_reward_score: 0,
            committee_reward_score: 0,
            ignored_invitation_score: 0,
            identity_root: "11".repeat(32),
            formula_version: FORMULA_VERSION,
        }
    }

    fn test_snapshot(leaves: Vec<SnapshotLeaf>) -> Snapshot {
        Snapshot::build(
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
            42,
            "aa".repeat(32),
            "11".repeat(32),
            FORMULA_VERSION,
            leaves,
        )
    }

    fn participant_account(
        miner_id: &str,
        claim_owner_id: &str,
        hashrate_score: u128,
    ) -> ParticipantAccount {
        ParticipantAccount {
            miner_id: miner_id.to_string(),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_id: claim_owner_id.to_string(),
            unpaid_sats: 0,
            hashrate_score,
            idena_score: 0,
        }
    }

    fn miner_registration(
        miner_id: &str,
        idena_address: &str,
        claim_owner_id: &str,
    ) -> MinerRegistration {
        MinerRegistration {
            miner_id: miner_id.to_string(),
            idena_address: idena_address.to_string(),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_owner_id.to_string(),
            mining_pubkey_hex: "02".repeat(33),
            idena_signature_hex: "00".repeat(65),
            mining_signature_hex: "00".repeat(64),
        }
    }

    fn test_config(datadir: PathBuf) -> DashboardApiConfig {
        DashboardApiConfig {
            datadir,
            snapshot_dir: None,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            allow_non_loopback: false,
            allowed_origins: default_allowed_origins(),
            api_token: None,
            account_selector: DashboardAccountSelector::default(),
            probe_timeout: Duration::from_secs(1),
            allow_remote_rpc: false,
            bitcoin_rpc_url: None,
            bitcoin_rpc_auth: None,
            idena_rpc_url: None,
            idena_api_key_file: None,
            public_explorer: false,
            fork_chain_client: None,
            bitcoin_index_client: None,
            governance_state_file: None,
        }
    }
}
