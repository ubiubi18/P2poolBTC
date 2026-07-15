use crate::{
    bitcoin_rpc::{
        BitcoinMiningJobTemplate, BitcoinRpcClient, SubmitBlockOutcome,
        POHW_REPLAY_MARKER_SCRIPT_HEX,
    },
    default_parent_share_hash,
    fork_chain::ForkChainClient,
    idena_anchor_verifier::IdenaAnchorVerifier,
    local_node, publish_sharechain_message, random_nonce_hex, read_keypair_from_file,
    sign_hash_hex, validate_protected_secret_file, PublishSharechainMessageInput,
    MAINNET_HANDOFF_MAX_SNAPSHOT_AGE_DAYS, MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{Block, ScriptBuf, Transaction};
use chrono::{NaiveDate, Utc};
use pohw_core::commitment::{
    validate_pohw_commitment, PohwCommitment, PohwCommitmentParams, PohwCommitmentValidationContext,
};
use pohw_core::payout::PayoutSchedule;
use pohw_core::sharechain::{BitcoinWorkTemplate, Share, SharechainMessage};
use pohw_core::snapshot::Snapshot;
use pohw_core::vault::vault_script_pubkey_hex;
use pohw_core::{Sats, DIRECT_PAYOUT_LIMIT, MIN_DIRECT_PAYOUT_SATS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{interval, sleep, timeout, Duration, Instant, MissedTickBehavior};

const DEFAULT_STRATUM_DIFFICULTY: f64 = 1.0;
const DEFAULT_EXTRANONCE2_SIZE: usize = 4;
const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024;
const DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 900;
const DEFAULT_JOB_REFRESH_INTERVAL_SECONDS: u64 = 5;
const MAX_IDLE_TIMEOUT_SECONDS: u64 = 86_400;
const MAX_JOB_REFRESH_INTERVAL_SECONDS: u64 = 3_600;
const MIN_NON_LOOPBACK_PASSWORD_BYTES: usize = 16;
const MAX_STRATUM_PASSWORD_BYTES: usize = 512;
const MAX_STRATUM_PASSWORD_FILE_BYTES: u64 = MAX_STRATUM_PASSWORD_BYTES as u64 + 2;
const MAX_STRATUM_CONNECTIONS: usize = 128;
const MAX_STRATUM_CONNECTIONS_PER_IP: usize = 32;
const STRATUM_READ_TIMEOUT_SECONDS: u64 = 30;
const STRATUM_WRITE_TIMEOUT_SECONDS: u64 = 5;
const STRATUM_RATE_WINDOW_SECONDS: u64 = 1;
const MAX_STRATUM_REQUESTS_PER_WINDOW: usize = 256;
const MAX_STRATUM_SUBMITS_PER_WINDOW: usize = 128;
const MAX_SUBMITTED_KEYS_PER_JOB: usize = 8_192;
const MAX_JOB_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MERKLE_BRANCHES: usize = 512;
const MAX_COINBASE_HEX_BYTES: usize = 512 * 1024;
const MAX_COMPLETE_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_CANDIDATE_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PAYOUT_EVIDENCE_SNAPSHOT_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAYOUT_EVIDENCE_SCHEDULE_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PAYOUT_EVIDENCE_COMMITMENT_JSON_BYTES: u64 = 256 * 1024;
const MAX_PAYOUT_EVIDENCE_CANDIDATE_JSON_BYTES: u64 = 64 * 1024;
const PACKAGED_EXAMPLE_JOB_ID: &str = "experiment-0-example";
const STRATUM_EXTRANONCE1_BYTES: usize = 4;
const MAX_COINBASE_OUTPUTS: usize = 1_000;

struct StratumRateWindow {
    started_at: Instant,
    requests: usize,
    submits: usize,
}

impl StratumRateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            requests: 0,
            submits: 0,
        }
    }

    fn observe_request(&mut self, now: Instant) -> Result<()> {
        self.reset_if_elapsed(now);
        self.requests = self.requests.saturating_add(1);
        if self.requests > MAX_STRATUM_REQUESTS_PER_WINDOW {
            bail!(
                "Stratum request rate exceeded {MAX_STRATUM_REQUESTS_PER_WINDOW} requests per {STRATUM_RATE_WINDOW_SECONDS}s"
            );
        }
        Ok(())
    }

    fn observe_submit(&mut self, now: Instant) -> Result<()> {
        self.reset_if_elapsed(now);
        self.submits = self.submits.saturating_add(1);
        if self.submits > MAX_STRATUM_SUBMITS_PER_WINDOW {
            bail!(
                "Stratum submit rate exceeded {MAX_STRATUM_SUBMITS_PER_WINDOW} shares per {STRATUM_RATE_WINDOW_SECONDS}s"
            );
        }
        Ok(())
    }

    fn reset_if_elapsed(&mut self, now: Instant) {
        if now.duration_since(self.started_at) >= Duration::from_secs(STRATUM_RATE_WINDOW_SECONDS) {
            self.started_at = now;
            self.requests = 0;
            self.submits = 0;
        }
    }
}

fn remember_stratum_submission(
    submitted: &mut BTreeSet<String>,
    key: String,
    max_entries: usize,
) -> Result<bool> {
    if submitted.contains(&key) {
        return Ok(false);
    }
    if submitted.len() >= max_entries {
        bail!("Stratum job submission cache reached {max_entries} entries");
    }
    submitted.insert(key);
    Ok(true)
}

#[derive(Clone)]
pub(crate) struct MiningAdapterConfig {
    pub datadir: PathBuf,
    pub bind_addr: SocketAddr,
    pub allow_non_loopback_stratum: bool,
    pub allow_example_mining_job: bool,
    pub miner_id: String,
    pub job_file: Option<PathBuf>,
    pub share_target: Option<String>,
    pub idena_snapshot_id: String,
    pub idena_snapshot_proof_root: String,
    pub mining_secret_key_file: PathBuf,
    pub node_secret_key_file: PathBuf,
    pub stratum_password_file: Option<PathBuf>,
    pub block_candidate_dir: Option<PathBuf>,
    pub payout_candidate_dir: Option<PathBuf>,
    pub peer_addrs: Vec<SocketAddr>,
    pub stratum_difficulty: f64,
    pub extranonce2_size: usize,
    pub max_line_bytes: usize,
    pub idle_timeout_seconds: u64,
    pub append: bool,
    pub bitcoin_rpc_client: Option<BitcoinRpcClient>,
    pub fork_chain_client: Option<ForkChainClient>,
    pub refresh_job_from_rpc: bool,
    pub job_refresh_interval_seconds: u64,
    pub auto_submit_blocks: bool,
    pub payout_schedule: Option<PayoutSchedule>,
    pub pohw_commitment: Option<PohwCommitment>,
    pub dynamic_pohw_payout: Option<DynamicPohwPayoutConfig>,
    pub enforce_mainnet_snapshot_quorum: bool,
    pub derive_share_target_from_block: bool,
    pub idena_anchor_verifier: Option<IdenaAnchorVerifier>,
}

#[derive(Clone)]
pub(crate) struct DynamicPohwPayoutConfig {
    pub snapshot_dir: PathBuf,
    pub commitment_template: PohwCommitment,
    pub min_snapshot_voters: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StratumJob {
    pub job_id: String,
    pub version: String,
    #[serde(alias = "previous_block_hash")]
    pub prevhash: String,
    pub coinbase1: String,
    pub coinbase2: String,
    #[serde(default)]
    pub merkle_branches: Vec<String>,
    #[serde(default)]
    pub transaction_data: Vec<String>,
    pub nbits: String,
    pub ntime: String,
    #[serde(default = "default_clean_jobs")]
    pub clean_jobs: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BuiltStratumJob {
    pub job: StratumJob,
    pub source_height: u64,
    pub source_previous_block_hash: String,
    pub source_transaction_count: usize,
    pub source_coinbase_value_sats: u64,
    pub extranonce1_bytes: usize,
    pub extranonce2_bytes: usize,
    pub note: String,
}

#[derive(Debug, Clone)]
pub(crate) struct BuiltDynamicPohwStratumJob {
    pub built: BuiltStratumJob,
    pub snapshot: Snapshot,
    pub payout_schedule: PayoutSchedule,
    pub pohw_commitment: PohwCommitment,
}

#[derive(Debug, Clone)]
struct ActivePayoutEvidence {
    snapshot: Snapshot,
    payout_schedule: PayoutSchedule,
    pohw_commitment: PohwCommitment,
    reward_sats: u64,
}

#[derive(Debug, Clone)]
struct ActiveStratumJob {
    job: StratumJob,
    payout_evidence: Option<ActivePayoutEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StratumBlockCandidate {
    pub job_id: String,
    pub extranonce1: String,
    pub extranonce2: String,
    pub ntime: String,
    pub nonce: String,
    pub coinbase_tx_hex: String,
    pub coinbase_txid: String,
    pub bitcoin_header_hex: String,
    pub header_merkle_root_hex: String,
    pub block_hash: String,
    pub block_target: String,
    pub meets_block_target: bool,
    pub merkle_branch_count: usize,
    pub block_hex: Option<String>,
    pub block_hex_status: String,
}

struct AdapterState {
    config: MiningAdapterConfig,
    job: RwLock<ActiveStratumJob>,
    job_updates: broadcast::Sender<StratumJob>,
    mining_pubkey_hex: String,
    stratum_password: Option<String>,
    share_target: String,
    block_submission_lock: Mutex<()>,
    idena_anchor_submission_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
struct SubmitWork {
    worker_name: String,
    job_id: String,
    extranonce2: String,
    ntime: String,
    nonce: String,
}

#[derive(Debug, thiserror::Error)]
#[error("share submission rejected at {0} stage")]
struct ShareSubmitStage(&'static str);

fn submit_stage<T, E>(result: std::result::Result<T, E>, stage: &'static str) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    result.map_err(Into::into).context(ShareSubmitStage(stage))
}

fn submit_rejection_stage(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<ShareSubmitStage>()
        .map_or("unclassified", |stage| stage.0)
}

#[derive(Debug, Clone, Serialize)]
struct AcceptedShareSummary {
    worker_name: String,
    job_id: String,
    extranonce1: String,
    extranonce2: String,
    ntime: String,
    nonce: String,
    bitcoin_header_hex: String,
    work_hash: String,
    block_target: String,
    meets_block_target: bool,
    block_candidate_file: Option<PathBuf>,
    payout_candidate_file: Option<PathBuf>,
    block_submit: Option<BlockSubmitSummary>,
    target: String,
    template_hash: String,
    share_hash: String,
    template_publish: Value,
    share_publish: Value,
}

#[derive(Debug, Clone, Serialize)]
struct BlockSubmitSummary {
    outcome: Option<SubmitBlockOutcome>,
    error: Option<String>,
}

fn default_clean_jobs() -> bool {
    true
}

pub(crate) async fn run_mining_adapter(mut config: MiningAdapterConfig) -> Result<()> {
    validate_bind_addr(config.bind_addr, config.allow_non_loopback_stratum)?;
    if !config.bind_addr.ip().is_loopback() && config.stratum_password_file.is_none() {
        bail!("refusing non-loopback Stratum adapter without --stratum-password-file");
    }
    if config.stratum_difficulty <= 0.0 || !config.stratum_difficulty.is_finite() {
        bail!("--stratum-difficulty must be a positive finite number");
    }
    validate_extranonce2_size(config.extranonce2_size)?;
    if config.max_line_bytes < 1024 || config.max_line_bytes > 1024 * 1024 {
        bail!("--max-stratum-line-bytes must be between 1024 and 1048576");
    }
    if config.idle_timeout_seconds == 0 || config.idle_timeout_seconds > MAX_IDLE_TIMEOUT_SECONDS {
        bail!("--stratum-idle-timeout-seconds must be between 1 and {MAX_IDLE_TIMEOUT_SECONDS}");
    }
    if config.job_refresh_interval_seconds == 0
        || config.job_refresh_interval_seconds > MAX_JOB_REFRESH_INTERVAL_SECONDS
    {
        bail!(
            "--job-refresh-interval-seconds must be between 1 and {MAX_JOB_REFRESH_INTERVAL_SECONDS}"
        );
    }
    if config.fork_chain_client.is_some()
        && (config.refresh_job_from_rpc || config.bitcoin_rpc_client.is_some())
    {
        bail!("fork-chain template mode cannot be combined with Bitcoin RPC job refresh");
    }
    if (config.refresh_job_from_rpc || config.auto_submit_blocks)
        && config.bitcoin_rpc_client.is_none()
        && config.fork_chain_client.is_none()
    {
        bail!(
            "Bitcoin RPC or fork-chain RPC is required for job refresh or automatic block submission"
        );
    }
    if config.auto_submit_blocks && !config.append {
        bail!("automatic block submission requires durable local sharechain append");
    }
    if config.payout_schedule.is_some() != config.pohw_commitment.is_some() {
        bail!("payout schedule and PoHW commitment must be supplied together");
    }
    if config.dynamic_pohw_payout.is_some()
        && (config.payout_schedule.is_some() || config.pohw_commitment.is_some())
    {
        bail!("dynamic PoHW payouts cannot be combined with a static payout schedule");
    }
    if let Some(dynamic) = config.dynamic_pohw_payout.as_ref() {
        validate_dynamic_payout_voter_floor(
            dynamic.min_snapshot_voters,
            config.enforce_mainnet_snapshot_quorum,
        )?;
    }
    if config.dynamic_pohw_payout.is_some()
        && !config.refresh_job_from_rpc
        && config.fork_chain_client.is_none()
    {
        bail!("dynamic PoHW payouts require Bitcoin RPC refresh or fork-chain templates");
    }
    if config.dynamic_pohw_payout.is_some() && config.payout_candidate_dir.is_none() {
        bail!("dynamic PoHW payouts require --payout-candidate-dir");
    }
    if config.dynamic_pohw_payout.is_some() && !config.append {
        bail!("dynamic PoHW payouts require local sharechain append");
    }
    if config.dynamic_pohw_payout.is_some()
        && config.block_candidate_dir.is_some()
        && config.block_candidate_dir == config.payout_candidate_dir
    {
        bail!("block candidate dir and payout candidate dir must be different");
    }
    if let Some(verifier) = config.idena_anchor_verifier.as_ref() {
        verifier
            .verify_registry_deployment()
            .await
            .context("Idena miner registry deployment verification failed")?;
        local_node::bind_idena_anchor_policy(&config.datadir, verifier.policy())
            .context("failed to bind Idena anchor policy to mining sharechain datadir")?;
    }
    if config.payout_schedule.is_some()
        && !config.refresh_job_from_rpc
        && config.fork_chain_client.is_none()
    {
        bail!("payout schedule and PoHW commitment require a live template source");
    }
    let active_job = if let Some(client) = config.fork_chain_client.as_ref() {
        let material = client.mining_template().await?;
        if let Some(dynamic) = config.dynamic_pohw_payout.as_ref() {
            build_dynamic_active_job(
                config.datadir.clone(),
                dynamic.clone(),
                config.miner_id.clone(),
                material,
                config.extranonce2_size,
            )
            .await?
        } else {
            ActiveStratumJob {
                job: build_job_for_template_source(
                    &material,
                    config.payout_schedule.as_ref(),
                    config.pohw_commitment.as_ref(),
                    config.extranonce2_size,
                )?
                .job,
                payout_evidence: None,
            }
        }
    } else if let Some(dynamic) = config.dynamic_pohw_payout.as_ref() {
        let material = config
            .bitcoin_rpc_client
            .as_ref()
            .context("Bitcoin RPC is required for dynamic PoHW payouts")?
            .mining_job_template()
            .await?;
        build_dynamic_active_job(
            config.datadir.clone(),
            dynamic.clone(),
            config.miner_id.clone(),
            material,
            config.extranonce2_size,
        )
        .await?
    } else {
        let job_file = config
            .job_file
            .as_deref()
            .context("--job-file is required without --fork-chain-rpc-addr")?;
        ActiveStratumJob {
            job: read_stratum_job_file(job_file)?,
            payout_evidence: None,
        }
    };
    let job = &active_job.job;
    job.validate()?;
    job.validate_example_policy(config.allow_example_mining_job)?;
    let block_target = block_target_hex_from_job_nbits(&job.nbits)?;
    let (share_target, stratum_difficulty) = resolve_share_policy(
        config.share_target.as_deref(),
        config.stratum_difficulty,
        &block_target,
        config.fork_chain_client.is_some() || config.derive_share_target_from_block,
    )?;
    config.stratum_difficulty = stratum_difficulty;
    Share::expected_hashrate_score_delta_for_target(&share_target)
        .context("invalid share target")?;
    ensure_share_target_not_stricter_than_block_target(&share_target, &block_target)?;
    let stratum_password = read_optional_stratum_password(
        config.stratum_password_file.as_deref(),
        !config.bind_addr.ip().is_loopback(),
    )?;
    let mining_keypair = read_keypair_from_file(&config.mining_secret_key_file)?;
    let mining_pubkey_hex = mining_keypair.x_only_public_key().0.to_string();
    ensure_registered_miner_matches_key(&config.datadir, &config.miner_id, &mining_pubkey_hex)?;
    if let Some(verifier) = config.idena_anchor_verifier.as_ref() {
        let replay = local_node::replay_state(&config.datadir)?;
        let registration = replay
            .registrations()
            .get(&config.miner_id.to_ascii_lowercase())
            .context("anchored mining requires a local miner registration")?;
        verifier
            .verify_registration(registration)
            .await
            .context("local Idena miner registry rejected the configured miner")?;
    }

    let initial_job_id = job.job_id.clone();
    let (job_updates, _) = broadcast::channel(16);
    let state = Arc::new(AdapterState {
        config,
        job: RwLock::new(active_job),
        job_updates,
        mining_pubkey_hex,
        stratum_password,
        share_target,
        block_submission_lock: Mutex::new(()),
        idena_anchor_submission_lock: Mutex::new(()),
    });
    let listener = TcpListener::bind(state.config.bind_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind Stratum adapter on {}",
                state.config.bind_addr
            )
        })?;
    eprintln!(
        "PoHW mining adapter listening on {} for miner_id={} job_id={}",
        state.config.bind_addr, state.config.miner_id, initial_job_id
    );

    if state.config.refresh_job_from_rpc || state.config.fork_chain_client.is_some() {
        let refresh_state = Arc::clone(&state);
        tokio::spawn(async move {
            refresh_job_loop(refresh_state).await;
        });
    }

    let connections =
        ConnectionLimiter::new(MAX_STRATUM_CONNECTIONS, MAX_STRATUM_CONNECTIONS_PER_IP);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Some(connection_guard) = connections.try_acquire(peer_addr.ip()) else {
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Err(err) = handle_stratum_connection(stream, peer_addr, state).await {
                eprintln!("Stratum connection {peer_addr} closed: {err:#}");
            }
        });
    }
}

fn validate_dynamic_payout_voter_floor(
    min_snapshot_voters: usize,
    enforce_mainnet_snapshot_quorum: bool,
) -> Result<()> {
    if min_snapshot_voters == 0 {
        bail!("dynamic PoHW payouts require at least one snapshot voter");
    }
    if enforce_mainnet_snapshot_quorum && min_snapshot_voters < MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS
    {
        bail!(
            "Bitcoin mainnet dynamic PoHW payouts require at least {} snapshot voters",
            MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS
        );
    }
    Ok(())
}

async fn refresh_job_loop(state: Arc<AdapterState>) {
    let mut ticker = interval(Duration::from_secs(
        state.config.job_refresh_interval_seconds,
    ));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match refresh_job_once(&state).await {
            Ok(Some(job_id)) => {
                eprintln!("published refreshed Stratum job {job_id}");
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("failed to refresh Stratum job from live template source: {err:#}");
            }
        }
    }
}

async fn refresh_job_once(state: &AdapterState) -> Result<Option<String>> {
    let material = if let Some(client) = state.config.fork_chain_client.as_ref() {
        client.mining_template().await?
    } else {
        state
            .config
            .bitcoin_rpc_client
            .as_ref()
            .context("live mining template source is not configured")?
            .mining_job_template()
            .await?
    };
    let active_job = if let Some(dynamic) = state.config.dynamic_pohw_payout.as_ref() {
        build_dynamic_active_job(
            state.config.datadir.clone(),
            dynamic.clone(),
            state.config.miner_id.clone(),
            material,
            state.config.extranonce2_size,
        )
        .await?
    } else {
        ActiveStratumJob {
            job: build_job_for_template_source(
                &material,
                state.config.payout_schedule.as_ref(),
                state.config.pohw_commitment.as_ref(),
                state.config.extranonce2_size,
            )?
            .job,
            payout_evidence: None,
        }
    };
    let job = &active_job.job;
    job.validate()?;
    job.validate_example_policy(false)?;
    let block_target = block_target_hex_from_job_nbits(&job.nbits)?;
    ensure_share_target_not_stricter_than_block_target(&state.share_target, &block_target)?;

    let mut current = state.job.write().await;
    if current.job == *job {
        return Ok(None);
    }
    let job_id = job.job_id.clone();
    let notification_job = job.clone();
    *current = active_job;
    drop(current);
    let _ = state.job_updates.send(notification_job);
    Ok(Some(job_id))
}

async fn build_dynamic_active_job(
    datadir: PathBuf,
    dynamic: DynamicPohwPayoutConfig,
    miner_id: String,
    material: BitcoinMiningJobTemplate,
    extranonce2_size: usize,
) -> Result<ActiveStratumJob> {
    let dynamic_job = tokio::task::spawn_blocking(move || {
        build_dynamic_pohw_stratum_job_from_template(
            &datadir,
            &dynamic.snapshot_dir,
            &miner_id,
            &dynamic.commitment_template,
            &material,
            extranonce2_size,
            dynamic.min_snapshot_voters,
        )
    })
    .await
    .context("dynamic PoHW payout derivation task failed")??;
    Ok(ActiveStratumJob {
        job: dynamic_job.built.job,
        payout_evidence: Some(ActivePayoutEvidence {
            snapshot: dynamic_job.snapshot,
            payout_schedule: dynamic_job.payout_schedule,
            pohw_commitment: dynamic_job.pohw_commitment,
            reward_sats: dynamic_job.built.source_coinbase_value_sats,
        }),
    })
}

fn build_job_for_template_source(
    material: &BitcoinMiningJobTemplate,
    payout_schedule: Option<&PayoutSchedule>,
    pohw_commitment: Option<&PohwCommitment>,
    extranonce2_size: usize,
) -> Result<BuiltStratumJob> {
    match (payout_schedule, pohw_commitment) {
        (Some(schedule), Some(commitment)) => {
            build_pohw_stratum_job_from_template(material, schedule, commitment, extranonce2_size)
        }
        (None, None) => build_stratum_job_from_template(material, extranonce2_size),
        _ => Err(anyhow!(
            "payout schedule and PoHW commitment must be supplied together"
        )),
    }
}

pub(crate) async fn build_stratum_job_from_rpc(
    client: &BitcoinRpcClient,
    extranonce2_size: usize,
) -> Result<BuiltStratumJob> {
    let material = client.mining_job_template().await?;
    build_stratum_job_from_template(&material, extranonce2_size)
}

pub(crate) fn build_stratum_job_from_template(
    material: &BitcoinMiningJobTemplate,
    extranonce2_size: usize,
) -> Result<BuiltStratumJob> {
    validate_extranonce2_size(extranonce2_size)?;
    let (coinbase1, coinbase2) = coinbase_split_for_extranonces(
        material.height,
        extranonce2_size,
        material.default_witness_commitment.as_deref(),
        material.pohw_replay_marker.as_deref(),
    )?;
    build_stratum_job_from_parts(
        material,
        extranonce2_size,
        coinbase1,
        coinbase2,
        "Experiment 0 sharechain job derived from local Bitcoin getblocktemplate; it is not a final PoHW payout coinbase block-submission template".to_string(),
    )
}

pub(crate) fn build_pohw_stratum_job_from_template(
    material: &BitcoinMiningJobTemplate,
    payout_schedule: &PayoutSchedule,
    pohw_commitment: &PohwCommitment,
    extranonce2_size: usize,
) -> Result<BuiltStratumJob> {
    validate_extranonce2_size(extranonce2_size)?;
    let (coinbase1, coinbase2) = coinbase_split_for_pohw_payouts(
        material.height,
        extranonce2_size,
        material.coinbase_value_sats,
        payout_schedule,
        pohw_commitment,
        material.default_witness_commitment.as_deref(),
        material.pohw_replay_marker.as_deref(),
    )?;
    build_stratum_job_from_parts(
        material,
        extranonce2_size,
        coinbase1,
        coinbase2,
        "PoHW payout-aware sharechain job derived from Bitcoin getblocktemplate; target-meeting submission still requires explicit RPC submission opt-in".to_string(),
    )
}

pub(crate) fn build_dynamic_pohw_stratum_job_from_template(
    datadir: &Path,
    snapshot_dir: &Path,
    miner_id: &str,
    commitment_template: &PohwCommitment,
    material: &BitcoinMiningJobTemplate,
    extranonce2_size: usize,
    min_snapshot_voters: usize,
) -> Result<BuiltDynamicPohwStratumJob> {
    let state = local_node::replay_state_with_confirmed_payouts(datadir, Some(snapshot_dir))?;
    let snapshot_status = local_node::latest_verified_snapshot(snapshot_dir)?;
    let verified = snapshot_status
        .latest
        .context("no verified Idena snapshot is available for dynamic PoHW payouts")?;
    validate_dynamic_payout_snapshot(
        &state,
        &verified.snapshot,
        Utc::now().date_naive(),
        min_snapshot_voters,
    )?;

    let normalized_miner_id = miner_id.to_ascii_lowercase();
    let registration = state
        .registrations()
        .get(&normalized_miner_id)
        .with_context(|| format!("miner {normalized_miner_id} is not registered"))?;
    registration
        .verify_idena_ownership_signature()
        .context("dynamic PoHW payout miner has an invalid Idena ownership proof")?;
    if !commitment_template
        .miner_idena_address
        .eq_ignore_ascii_case(&registration.idena_address)
    {
        bail!("PoHW commitment template miner identity does not match the registered miner");
    }
    let miner_leaf = verified
        .snapshot
        .leaves
        .iter()
        .find(|leaf| {
            leaf.idena_address
                .eq_ignore_ascii_case(&registration.idena_address)
        })
        .context("registered miner identity is absent from the latest verified snapshot")?;
    if !miner_leaf.is_block_eligible() {
        bail!("registered miner identity is not eligible in the latest verified snapshot");
    }

    let sharechain_summary = state.summary();
    let sharechain_tip = match state.best_share_tip() {
        Some(tip) => tip.to_string(),
        None if sharechain_summary.stored_share_count == 0 => "00".repeat(32),
        None => bail!("dynamic PoHW payouts found shares but no active sharechain tip"),
    };
    let mut accounts = state.participant_accounts();
    local_node::apply_snapshot_scores_to_accounts(&state, &mut accounts, &verified.snapshot)?;
    if sharechain_summary.stored_share_count == 0 {
        let account = accounts
            .iter_mut()
            .find(|account| account.miner_id == normalized_miner_id)
            .context("genesis payout miner account is absent")?;
        account.hashrate_score = 1;
    }
    let payout_schedule = state.expected_payout_schedule(
        &accounts,
        material.coinbase_value_sats,
        DIRECT_PAYOUT_LIMIT,
        MIN_DIRECT_PAYOUT_SATS,
    )?;
    let sharechain_state_root = state.accounting_state_root();
    let snapshot_day = verified.snapshot.snapshot_day.to_string();
    let identity_proof_root = verified
        .snapshot
        .identity_proof_root_hex()
        .context("verified snapshot has an invalid identity proof root")?;
    let pohw_commitment = PohwCommitment::new_pohw1(PohwCommitmentParams {
        idena_snapshot_id: snapshot_day.clone(),
        idena_score_root: verified.snapshot.score_root.clone(),
        miner_idena_address: registration.idena_address.clone(),
        identity_proof_root: identity_proof_root.clone(),
        sharechain_tip: sharechain_tip.clone(),
        sharechain_state_root: Some(sharechain_state_root.clone()),
        payout_schedule_root: payout_schedule.payout_root.clone(),
        vault_epoch_id: commitment_template.vault_epoch_id,
        frost_vault_key_xonly: commitment_template.frost_vault_key_xonly.clone(),
    });
    validate_pohw_commitment(
        &pohw_commitment,
        PohwCommitmentValidationContext {
            idena_snapshot_id: &snapshot_day,
            idena_score_root: &verified.snapshot.score_root,
            miner_leaf,
            identity_proof_root: &identity_proof_root,
            sharechain_tip: &sharechain_tip,
            sharechain_state_root: Some(&sharechain_state_root),
            payout_schedule_root: &payout_schedule.payout_root,
            vault_epoch_id: commitment_template.vault_epoch_id,
            frost_vault_key_xonly: &commitment_template.frost_vault_key_xonly,
        },
    )
    .context("derived PoHW commitment failed validation")?;
    let built = build_pohw_stratum_job_from_template(
        material,
        &payout_schedule,
        &pohw_commitment,
        extranonce2_size,
    )?;
    Ok(BuiltDynamicPohwStratumJob {
        built,
        snapshot: verified.snapshot,
        payout_schedule,
        pohw_commitment,
    })
}

fn validate_dynamic_payout_snapshot(
    state: &pohw_core::sharechain_state::SharechainReplayState,
    snapshot: &Snapshot,
    today: NaiveDate,
    min_snapshot_voters: usize,
) -> Result<()> {
    if min_snapshot_voters == 0 {
        bail!("dynamic PoHW payouts require at least one snapshot voter");
    }
    let snapshot_age_days = (today - snapshot.snapshot_day).num_days();
    if snapshot_age_days < 0 {
        bail!("latest verified Idena snapshot is dated in the future");
    }
    if u64::try_from(snapshot_age_days).unwrap_or(u64::MAX) > MAINNET_HANDOFF_MAX_SNAPSHOT_AGE_DAYS
    {
        bail!(
            "latest verified Idena snapshot is too old for dynamic PoHW payouts: {snapshot_age_days} days"
        );
    }
    let snapshot_day = snapshot.snapshot_day.to_string();
    let voter_count = state.unique_snapshot_voter_idena_count(
        &snapshot_day,
        snapshot.idena_height,
        &snapshot.score_root,
    );
    if voter_count < min_snapshot_voters {
        bail!(
            "verified Idena snapshot has {voter_count} distinct identity voters; {} required",
            min_snapshot_voters
        );
    }
    Ok(())
}

fn build_stratum_job_from_parts(
    material: &BitcoinMiningJobTemplate,
    extranonce2_size: usize,
    coinbase1: String,
    coinbase2: String,
    note: String,
) -> Result<BuiltStratumJob> {
    if material.transaction_hashes.len() != material.transactions.len() {
        bail!(
            "mining job material has {} transaction hashes but {} transaction data entries",
            material.transaction_hashes.len(),
            material.transactions.len()
        );
    }
    for (index, (txid, transaction)) in material
        .transaction_hashes
        .iter()
        .zip(material.transactions.iter())
        .enumerate()
    {
        if !txid.eq_ignore_ascii_case(&transaction.txid) {
            bail!(
                "mining job material transaction {index} txid {} does not match transaction data txid {}",
                txid,
                transaction.txid
            );
        }
    }
    let merkle_branches = coinbase_merkle_branches(&material.transaction_hashes)?;
    let job_fingerprint_payload = serde_json::to_vec(&(
        material.version,
        &material.previous_block_hash,
        material.curtime,
        &material.bits,
        material.height,
        material.coinbase_value_sats,
        &coinbase1,
        &coinbase2,
        &merkle_branches,
        &material.transactions,
    ))
    .context("failed to encode Stratum job fingerprint")?;
    let job_fingerprint = sha256d::Hash::hash(&job_fingerprint_payload).to_string();
    let job = StratumJob {
        job_id: format!("gbt-{}-{}", material.height, &job_fingerprint[..16]),
        version: hex::encode(material.version.to_le_bytes()),
        prevhash: display_hash_to_header_order_hex(&material.previous_block_hash)?,
        coinbase1,
        coinbase2,
        merkle_branches,
        transaction_data: material
            .transactions
            .iter()
            .map(|tx| tx.data_hex.clone())
            .collect(),
        nbits: compact_bits_to_header_order_hex(&material.bits)?,
        ntime: hex::encode(material.curtime.to_le_bytes()),
        clean_jobs: true,
    };
    job.validate()?;
    job.validate_example_policy(false)?;
    Ok(BuiltStratumJob {
        job,
        source_height: material.height,
        source_previous_block_hash: material.previous_block_hash.clone(),
        source_transaction_count: material.transaction_hashes.len(),
        source_coinbase_value_sats: material.coinbase_value_sats,
        extranonce1_bytes: STRATUM_EXTRANONCE1_BYTES,
        extranonce2_bytes: extranonce2_size,
        note,
    })
}

fn read_optional_stratum_password(
    path: Option<&Path>,
    require_strong: bool,
) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    validate_protected_secret_file(path, "Stratum password")?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Stratum password file {}", path.display()))?;
    if metadata.len() > MAX_STRATUM_PASSWORD_FILE_BYTES {
        bail!(
            "Stratum password file {} is too large: {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            MAX_STRATUM_PASSWORD_FILE_BYTES
        );
    }
    let password = fs::read_to_string(path)
        .with_context(|| format!("failed to read Stratum password file {}", path.display()))?;
    validate_stratum_password(password, require_strong).map(Some)
}

fn validate_stratum_password(password: String, require_strong: bool) -> Result<String> {
    let password = password.trim().to_string();
    if password.is_empty() || password.len() > MAX_STRATUM_PASSWORD_BYTES {
        bail!("Stratum password must be 1-{MAX_STRATUM_PASSWORD_BYTES} bytes");
    }
    if require_strong && password.len() < MIN_NON_LOOPBACK_PASSWORD_BYTES {
        bail!(
            "non-loopback Stratum password must be at least {MIN_NON_LOOPBACK_PASSWORD_BYTES} bytes"
        );
    }
    if password.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("Stratum password must not contain control characters");
    }
    Ok(password)
}

fn resolve_share_target(configured: Option<&str>, stratum_difficulty: f64) -> Result<String> {
    if let Some(configured) = configured {
        return Ok(configured.to_ascii_lowercase());
    }
    if (stratum_difficulty - DEFAULT_STRATUM_DIFFICULTY).abs() > f64::EPSILON {
        bail!("--share-target is required when --stratum-difficulty is not the default diff-1");
    }
    Ok(default_share_target_hex())
}

fn resolve_share_policy(
    configured: Option<&str>,
    stratum_difficulty: f64,
    block_target: &str,
    derive_from_block: bool,
) -> Result<(String, f64)> {
    if let Some(configured) = configured {
        return Ok((configured.to_ascii_lowercase(), stratum_difficulty));
    }
    if derive_from_block {
        return Ok((
            block_target.to_ascii_lowercase(),
            difficulty_float_from_target_hex(block_target)?,
        ));
    }
    Ok((
        resolve_share_target(None, stratum_difficulty)?,
        stratum_difficulty,
    ))
}

fn difficulty_float_from_target_hex(target_hex: &str) -> Result<f64> {
    let bytes = decode_hex_exact_bytes("fork block target", target_hex, 32)?;
    let target = Target::from_be_bytes(
        bytes
            .try_into()
            .expect("target byte length was validated as exactly 32"),
    );
    if target == Target::ZERO {
        bail!("fork block target must not be zero");
    }
    let difficulty = target.difficulty_float();
    if difficulty <= 0.0 || !difficulty.is_finite() {
        bail!("fork block target produced an invalid Stratum difficulty");
    }
    Ok(difficulty)
}

fn ensure_share_target_not_stricter_than_block_target(
    share_target: &str,
    block_target: &str,
) -> Result<()> {
    let share_target = decode_hex_exact_bytes("share target", share_target, 32)?;
    let block_target = decode_hex_exact_bytes("block target", block_target, 32)?;
    if share_target.iter().all(|byte| *byte == 0) {
        bail!("share target must not be zero");
    }
    if share_target < block_target {
        bail!(
            "share target is stricter than the job block target; lower --stratum-difficulty and set a matching --share-target so miners submit block-valid work"
        );
    }
    Ok(())
}

fn validate_extranonce2_size(extranonce2_size: usize) -> Result<()> {
    if extranonce2_size == 0 || extranonce2_size > 32 {
        bail!("--extranonce2-size must be 1..=32 bytes");
    }
    Ok(())
}

fn validate_bind_addr(bind_addr: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    let ip = bind_addr.ip();
    if allow_non_loopback {
        return Ok(());
    }
    let safe = match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if !safe {
        bail!(
            "Stratum bind address {bind_addr} is not loopback; pass --allow-non-loopback-stratum only for a trusted LAN or explicitly firewalled endpoint"
        );
    }
    Ok(())
}

fn ensure_registered_miner_matches_key(
    datadir: &Path,
    miner_id: &str,
    mining_pubkey_hex: &str,
) -> Result<()> {
    let state = local_node::replay_state(datadir)?;
    let miner_id = miner_id.to_ascii_lowercase();
    let registration = state.registrations().get(&miner_id).ok_or_else(|| {
        anyhow!("miner_id {miner_id} is not registered in local sharechain replay")
    })?;
    if !registration
        .mining_pubkey_hex
        .eq_ignore_ascii_case(mining_pubkey_hex)
    {
        bail!(
            "mining key does not match registered mining_pubkey_hex for miner_id {}",
            miner_id
        );
    }
    Ok(())
}

pub(crate) fn read_stratum_job_file(path: &Path) -> Result<StratumJob> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Stratum job file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("Stratum job file must not be a symlink: {}", path.display());
    }
    if !metadata.is_file() {
        bail!("Stratum job path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_JOB_FILE_BYTES {
        bail!(
            "Stratum job file {} is too large: {} bytes",
            path.display(),
            metadata.len()
        );
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read Stratum job file {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse Stratum job file {}", path.display()))
}

pub(crate) fn build_stratum_block_candidate(
    job: &StratumJob,
    extranonce1: &str,
    extranonce2: &str,
    ntime: &str,
    nonce: &str,
    extranonce2_size: usize,
    require_block_target: bool,
) -> Result<StratumBlockCandidate> {
    job.validate()?;
    validate_extranonce2_size(extranonce2_size)?;
    validate_hex_exact("extranonce1", extranonce1, STRATUM_EXTRANONCE1_BYTES)?;
    validate_hex_exact("extranonce2", extranonce2, extranonce2_size)?;
    validate_hex_exact("ntime", ntime, 4)?;
    validate_hex_exact("nonce", nonce, 4)?;
    let submit = SubmitWork {
        worker_name: "offline-candidate".to_string(),
        job_id: job.job_id.clone(),
        extranonce2: extranonce2.to_ascii_lowercase(),
        ntime: ntime.to_ascii_lowercase(),
        nonce: nonce.to_ascii_lowercase(),
    };
    let coinbase_tx_hex = coinbase_tx_hex_from_submit(job, &submit, extranonce1)?;
    let bitcoin_header_hex = build_header_hex_from_submit(job, &submit, extranonce1)?;
    let header = decode_hex_exact_bytes("bitcoin_header", &bitcoin_header_hex, 80)?;
    let coinbase = hex::decode(&coinbase_tx_hex).context("failed to decode coinbase tx")?;
    let coinbase_tx = decode_coinbase_transaction(&coinbase)?;
    let block_hash = sha256d::Hash::hash(&header).to_string();
    let block_target = block_target_hex_from_job_nbits(&job.nbits)?;
    let meets_block_target = block_hash <= block_target;
    if require_block_target && !meets_block_target {
        bail!("candidate block hash {block_hash} does not meet block target {block_target}");
    }
    let (block_hex, block_hex_status) = complete_block_hex(job, &header, &coinbase)?;
    Ok(StratumBlockCandidate {
        job_id: job.job_id.clone(),
        extranonce1: extranonce1.to_ascii_lowercase(),
        extranonce2: extranonce2.to_ascii_lowercase(),
        ntime: ntime.to_ascii_lowercase(),
        nonce: nonce.to_ascii_lowercase(),
        coinbase_tx_hex,
        coinbase_txid: coinbase_tx.compute_txid().to_string(),
        bitcoin_header_hex,
        header_merkle_root_hex: hex::encode(&header[36..68]),
        block_hash,
        block_target,
        meets_block_target,
        merkle_branch_count: job.merkle_branches.len(),
        block_hex,
        block_hex_status,
    })
}

pub(crate) fn block_hex_for_stratum_candidate_submission(
    candidate: &StratumBlockCandidate,
) -> Result<&str> {
    let header = decode_hex_exact_bytes("bitcoin_header", &candidate.bitcoin_header_hex, 80)?;
    let computed_block_hash = sha256d::Hash::hash(&header).to_string();
    if !candidate
        .block_hash
        .eq_ignore_ascii_case(&computed_block_hash)
    {
        bail!(
            "candidate block_hash {} does not match recomputed header hash {}",
            candidate.block_hash,
            computed_block_hash
        );
    }

    let expected_block_target = block_target_hex_from_job_nbits(&hex::encode(&header[72..76]))?;
    if !candidate
        .block_target
        .eq_ignore_ascii_case(&expected_block_target)
    {
        bail!(
            "candidate block_target {} does not match header bits target {}",
            candidate.block_target,
            expected_block_target
        );
    }

    let recomputed_meets_block_target = computed_block_hash <= expected_block_target;
    if candidate.meets_block_target != recomputed_meets_block_target {
        bail!(
            "candidate meets_block_target {} does not match recomputed value {}",
            candidate.meets_block_target,
            recomputed_meets_block_target
        );
    }
    if !recomputed_meets_block_target {
        bail!(
            "refusing to submit candidate {} because it does not meet the advertised block target",
            candidate.block_hash
        );
    }

    if !matches!(
        candidate.block_hex_status.as_str(),
        "complete_coinbase_only" | "complete_with_non_coinbase_transactions"
    ) {
        bail!(
            "refusing to submit candidate {} because block_hex_status is {}; only complete block_hex candidates can be submitted",
            candidate.block_hash,
            candidate.block_hex_status
        );
    }
    let block_hex = candidate.block_hex.as_deref().ok_or_else(|| {
        anyhow!(
            "candidate {} has no complete block_hex",
            candidate.block_hash
        )
    })?;
    validate_candidate_block_hex(candidate, block_hex, &header)?;

    Ok(block_hex)
}

impl StratumJob {
    fn validate(&self) -> Result<()> {
        validate_label("job_id", &self.job_id, 64)?;
        validate_hex_exact("version", &self.version, 4)?;
        validate_hex_exact("prevhash", &self.prevhash, 32)?;
        validate_hex_even("coinbase1", &self.coinbase1, MAX_COINBASE_HEX_BYTES)?;
        validate_hex_even("coinbase2", &self.coinbase2, MAX_COINBASE_HEX_BYTES)?;
        if self.merkle_branches.len() > MAX_MERKLE_BRANCHES {
            bail!(
                "merkle_branches contains {} entries; maximum is {}",
                self.merkle_branches.len(),
                MAX_MERKLE_BRANCHES
            );
        }
        for branch in &self.merkle_branches {
            validate_hex_exact("merkle branch", branch, 32)?;
        }
        let mut transaction_data_bytes = 0usize;
        for data_hex in &self.transaction_data {
            validate_hex_even("transaction_data entry", data_hex, MAX_COMPLETE_BLOCK_BYTES)?;
            transaction_data_bytes = transaction_data_bytes
                .checked_add(data_hex.len() / 2)
                .ok_or_else(|| anyhow!("transaction_data size overflow"))?;
        }
        if transaction_data_bytes > MAX_COMPLETE_BLOCK_BYTES {
            bail!(
                "transaction_data contains {transaction_data_bytes} bytes; maximum is {MAX_COMPLETE_BLOCK_BYTES}"
            );
        }
        if !self.transaction_data.is_empty() {
            let (txids, _) = decode_non_coinbase_transaction_data(&self.transaction_data)?;
            let expected_branches = coinbase_merkle_branches(&txids)?;
            if expected_branches != normalized_merkle_branches(&self.merkle_branches)? {
                bail!("transaction_data does not match advertised merkle branches");
            }
        }
        validate_hex_exact("nbits", &self.nbits, 4)?;
        validate_hex_exact("ntime", &self.ntime, 4)?;
        Ok(())
    }

    fn validate_example_policy(&self, allow_example_mining_job: bool) -> Result<()> {
        if self.job_id == PACKAGED_EXAMPLE_JOB_ID && !allow_example_mining_job {
            bail!(
                "refusing packaged example Stratum job; provide a locally verified fork/testnet job file or pass --allow-example-mining-job for an explicit local dry-run"
            );
        }
        Ok(())
    }

    fn notify_params(&self) -> Vec<Value> {
        vec![
            Value::String(self.job_id.clone()),
            Value::String(self.prevhash.to_ascii_lowercase()),
            Value::String(self.coinbase1.to_ascii_lowercase()),
            Value::String(self.coinbase2.to_ascii_lowercase()),
            Value::Array(
                self.merkle_branches
                    .iter()
                    .map(|branch| Value::String(branch.to_ascii_lowercase()))
                    .collect(),
            ),
            Value::String(self.version.to_ascii_lowercase()),
            Value::String(self.nbits.to_ascii_lowercase()),
            Value::String(self.ntime.to_ascii_lowercase()),
            Value::Bool(self.clean_jobs),
        ]
    }
}

async fn handle_stratum_connection(
    stream: TcpStream,
    _peer_addr: SocketAddr,
    state: Arc<AdapterState>,
) -> Result<()> {
    let extranonce1 = random_nonce_hex()[..8].to_string();
    let mut authorized = false;
    let mut subscribed = false;
    let mut submitted = BTreeSet::new();
    let mut rate_window = StratumRateWindow::new(Instant::now());
    let mut job_updates = state.job_updates.subscribe();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let idle_duration = Duration::from_secs(state.config.idle_timeout_seconds);
    let idle_timer = sleep(idle_duration);
    tokio::pin!(idle_timer);

    loop {
        let read_result = tokio::select! {
            _ = &mut idle_timer => {
                bail!(
                    "Stratum idle timeout after {} seconds",
                    state.config.idle_timeout_seconds
                );
            }
            update = job_updates.recv(), if subscribed => {
                let job = match update {
                    Ok(job) => job,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        state.job.read().await.job.clone()
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                submitted.clear();
                send_notification(&mut write_half, "mining.notify", job.notify_params()).await?;
                continue;
            }
            read_result = read_stratum_line_with_timeout(
                &mut reader,
                state.config.max_line_bytes,
                Duration::from_secs(STRATUM_READ_TIMEOUT_SECONDS),
            ) => {
                read_result?
            }
        };
        idle_timer.as_mut().reset(Instant::now() + idle_duration);
        let Some(line) = read_result else {
            return Ok(());
        };
        if line.trim().is_empty() {
            continue;
        }
        rate_window.observe_request(Instant::now())?;
        let request: Value = match serde_json::from_str(line.trim()) {
            Ok(request) => request,
            Err(err) => {
                send_response(
                    &mut write_half,
                    Value::Null,
                    Value::Null,
                    Some(stratum_error(20, &format!("invalid JSON: {err}"))),
                )
                .await?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match method {
            "mining.configure" => {
                send_response(&mut write_half, id, json!({}), None).await?;
            }
            "mining.subscribe" => {
                subscribed = true;
                job_updates = state.job_updates.subscribe();
                let result = json!([
                    [
                        ["mining.set_difficulty", "pohw-diff"],
                        ["mining.notify", "pohw-job"]
                    ],
                    extranonce1,
                    state.config.extranonce2_size
                ]);
                send_response(&mut write_half, id, result, None).await?;
                send_notification(
                    &mut write_half,
                    "mining.set_difficulty",
                    vec![json!(state.config.stratum_difficulty)],
                )
                .await?;
                let job = state.job.read().await.job.clone();
                send_notification(&mut write_half, "mining.notify", job.notify_params()).await?;
            }
            "mining.authorize" => {
                match authorize_password_matches(&request, state.stratum_password.as_deref()) {
                    Ok(result) => {
                        authorized = result;
                        send_response(&mut write_half, id, Value::Bool(authorized), None).await?;
                    }
                    Err(err) => {
                        send_response(
                            &mut write_half,
                            id,
                            Value::Null,
                            Some(stratum_error(20, &err.to_string())),
                        )
                        .await?;
                    }
                }
            }
            "mining.extranonce.subscribe" | "mining.suggest_difficulty" => {
                send_response(&mut write_half, id, Value::Bool(true), None).await?;
            }
            "mining.submit" => {
                rate_window.observe_submit(Instant::now())?;
                if !authorized {
                    send_response(
                        &mut write_half,
                        id,
                        Value::Null,
                        Some(stratum_error(24, "worker is not authorized")),
                    )
                    .await?;
                    continue;
                }
                let submit = match parse_submit(&request, state.config.extranonce2_size) {
                    Ok(submit) => submit,
                    Err(err) => {
                        send_response(
                            &mut write_half,
                            id,
                            Value::Null,
                            Some(stratum_error(20, &err.to_string())),
                        )
                        .await?;
                        continue;
                    }
                };
                let duplicate_key = format!(
                    "{}:{}:{}:{}",
                    submit.job_id, submit.extranonce2, submit.ntime, submit.nonce
                );
                match remember_stratum_submission(
                    &mut submitted,
                    duplicate_key.clone(),
                    MAX_SUBMITTED_KEYS_PER_JOB,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        send_response(
                            &mut write_half,
                            id,
                            Value::Null,
                            Some(stratum_error(22, "duplicate share")),
                        )
                        .await?;
                        continue;
                    }
                    Err(err) => {
                        send_response(
                            &mut write_half,
                            id,
                            Value::Null,
                            Some(stratum_error(20, "too many unique submissions for one job")),
                        )
                        .await?;
                        return Err(err);
                    }
                }
                let active_job = state.job.read().await.clone();
                match accept_submit(&state, &active_job, &submit, &extranonce1).await {
                    Ok(summary) => {
                        eprintln!(
                            "accepted Stratum share: meets_block_target={}",
                            summary.meets_block_target
                        );
                        if summary.block_candidate_file.is_some() {
                            eprintln!("persisted target-meeting block candidate");
                        }
                        if summary.payout_candidate_file.is_some() {
                            eprintln!("persisted target-meeting payout evidence");
                        }
                        if let Some(submission) = &summary.block_submit {
                            let destination = if state.config.fork_chain_client.is_some() {
                                "fork-chain RPC"
                            } else {
                                "Bitcoin RPC"
                            };
                            if let Some(outcome) = &submission.outcome {
                                eprintln!(
                                    "submitted block candidate to {destination}: status={}",
                                    outcome.status
                                );
                            } else if submission.error.is_some() {
                                eprintln!("failed to submit block candidate to {destination}");
                            }
                        }
                        send_response(&mut write_half, id, Value::Bool(true), None).await?;
                    }
                    Err(err) => {
                        eprintln!(
                            "rejected Stratum share: stage={}",
                            submit_rejection_stage(&err)
                        );
                        if err.downcast_ref::<local_node::LocalAppendError>().is_some() {
                            submitted.remove(&duplicate_key);
                        }
                        send_response(
                            &mut write_half,
                            id,
                            Value::Null,
                            Some(stratum_error(23, "share rejected by node policy")),
                        )
                        .await?;
                    }
                }
            }
            "mining.ping" => {
                send_response(&mut write_half, id, Value::Bool(true), None).await?;
            }
            "" => {
                send_response(
                    &mut write_half,
                    id,
                    Value::Null,
                    Some(stratum_error(20, "missing method")),
                )
                .await?;
            }
            other => {
                send_response(
                    &mut write_half,
                    id,
                    Value::Null,
                    Some(stratum_error(20, &format!("unsupported method {other}"))),
                )
                .await?;
            }
        }
    }
}

async fn read_bounded_line<R>(reader: &mut R, max_bytes: usize) -> Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        buf.push(byte[0]);
        if buf.len() > max_bytes {
            bail!("Stratum line exceeded {max_bytes} bytes");
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(buf)
        .map(Some)
        .context("Stratum line is not UTF-8")
}

async fn read_stratum_line_with_timeout<R>(
    reader: &mut R,
    max_bytes: usize,
    read_timeout: Duration,
) -> Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    timeout(read_timeout, read_bounded_line(reader, max_bytes))
        .await
        .context("Stratum request read timed out")?
}

async fn send_response<W>(
    writer: &mut W,
    id: Value,
    result: Value,
    error: Option<Value>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let response = json!({
        "id": id,
        "result": if error.is_some() { Value::Null } else { result },
        "error": error,
    });
    send_json_line(writer, &response).await
}

async fn send_notification<W>(writer: &mut W, method: &str, params: Vec<Value>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send_json_line(
        writer,
        &json!({
            "id": Value::Null,
            "method": method,
            "params": params,
        }),
    )
    .await
}

async fn send_json_line<W>(writer: &mut W, value: &Value) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send_json_line_with_timeout(
        writer,
        value,
        Duration::from_secs(STRATUM_WRITE_TIMEOUT_SECONDS),
    )
    .await
}

async fn send_json_line_with_timeout<W>(
    writer: &mut W,
    value: &Value,
    write_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    timeout(write_timeout, async {
        writer.write_all(&line).await?;
        writer.flush().await
    })
    .await
    .context("Stratum response write timed out")??;
    Ok(())
}

fn stratum_error(code: i64, message: &str) -> Value {
    Value::Array(vec![
        Value::Number(code.into()),
        Value::String(message.to_string()),
        Value::Null,
    ])
}

fn parse_submit(request: &Value, extranonce2_size: usize) -> Result<SubmitWork> {
    let params = request
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mining.submit params must be an array"))?;
    if params.len() < 5 {
        bail!("mining.submit requires worker, job_id, extranonce2, ntime, nonce");
    }
    if params.len() > 5 && !params[5].as_str().unwrap_or_default().is_empty() {
        bail!("Stratum version rolling submit is not supported by this adapter");
    }
    let worker_name = string_param(params, 0, "worker")?;
    let job_id = string_param(params, 1, "job_id")?;
    let extranonce2 = string_param(params, 2, "extranonce2")?.to_ascii_lowercase();
    let ntime = string_param(params, 3, "ntime")?.to_ascii_lowercase();
    let nonce = string_param(params, 4, "nonce")?.to_ascii_lowercase();
    validate_hex_exact("extranonce2", &extranonce2, extranonce2_size)?;
    validate_hex_exact("ntime", &ntime, 4)?;
    validate_hex_exact("nonce", &nonce, 4)?;
    Ok(SubmitWork {
        worker_name,
        job_id,
        extranonce2,
        ntime,
        nonce,
    })
}

fn string_param(params: &[Value], index: usize, label: &str) -> Result<String> {
    params
        .get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("mining.submit {label} must be a string"))
}

fn authorize_password_matches(request: &Value, expected_password: Option<&str>) -> Result<bool> {
    let params = request
        .get("params")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mining.authorize params must be an array"))?;
    let _worker_name = params
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("mining.authorize worker must be a string"))?;
    let Some(expected_password) = expected_password else {
        return Ok(true);
    };
    let supplied = params
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("mining.authorize password must be a string"))?;
    Ok(constant_time_eq(
        supplied.as_bytes(),
        expected_password.as_bytes(),
    ))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for idx in 0..left.len().max(right.len()) {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

async fn accept_submit(
    state: &AdapterState,
    active_job: &ActiveStratumJob,
    submit: &SubmitWork,
    extranonce1: &str,
) -> Result<AcceptedShareSummary> {
    let job = &active_job.job;
    if submit.job_id != job.job_id {
        return Err(anyhow!("unknown Stratum job id").context(ShareSubmitStage("job")));
    }
    let bitcoin_header_hex = submit_stage(
        build_header_hex_from_submit(job, submit, extranonce1),
        "header",
    )?;
    let header_bytes = submit_stage(
        decode_hex_exact_bytes("bitcoin_header", &bitcoin_header_hex, 80),
        "header",
    )?;
    let work_hash = sha256d::Hash::hash(&header_bytes).to_string();
    submit_stage(
        ensure_hash_meets_target(&work_hash, &state.share_target),
        "target",
    )?;
    let _idena_anchor_submission_guard = if state.config.idena_anchor_verifier.is_some() {
        Some(state.idena_anchor_submission_lock.lock().await)
    } else {
        None
    };
    let block_candidate = submit_stage(
        build_stratum_block_candidate(
            job,
            extranonce1,
            &submit.extranonce2,
            &submit.ntime,
            &submit.nonce,
            state.config.extranonce2_size,
            false,
        ),
        "candidate",
    )?;
    let _block_submission_guard =
        if block_candidate.meets_block_target && state.config.auto_submit_blocks {
            Some(state.block_submission_lock.lock().await)
        } else {
            None
        };
    let block_candidate_file = submit_stage(
        persist_target_block_candidate(
            state.config.block_candidate_dir.as_deref(),
            &block_candidate,
        ),
        "candidate-persistence",
    )?;
    let payout_candidate_file = match (
        block_candidate.meets_block_target,
        active_job.payout_evidence.as_ref(),
    ) {
        (true, Some(evidence)) => {
            let candidate_dir = state
                .config
                .payout_candidate_dir
                .as_deref()
                .context("dynamic PoHW payout candidate dir is not configured")?;
            let path = submit_stage(
                persist_payout_confirmation_evidence(candidate_dir, &block_candidate, evidence),
                "payout-persistence",
            )?;
            Some(path)
        }
        _ => None,
    };
    let template_created_at = submit_stage(
        template_created_at_unix_from_header_hex(&bitcoin_header_hex),
        "template",
    )?;
    let idena_anchor = if let Some(verifier) = state.config.idena_anchor_verifier.as_ref() {
        let replay = submit_stage(
            local_node::replay_state(&state.config.datadir),
            "idena-anchor",
        )?;
        let registration = submit_stage(
            replay
                .registrations()
                .get(&state.config.miner_id.to_ascii_lowercase())
                .context("anchored mining requires a local miner registration"),
            "idena-anchor",
        )?;
        Some((
            submit_stage(
                verifier.fresh_finalized_anchor(registration).await,
                "idena-anchor",
            )?,
            submit_stage(verifier.policy().commitment_hash(), "idena-anchor")?,
        ))
    } else {
        None
    };
    let mut template = submit_stage(
        match idena_anchor {
            Some((anchor, policy_hash)) => {
                BitcoinWorkTemplate::from_bitcoin_header_hex_with_share_target_and_idena_anchor(
                    state.config.miner_id.clone(),
                    &bitcoin_header_hex,
                    state.share_target.clone(),
                    anchor,
                    policy_hash,
                    template_created_at,
                )
            }
            None => BitcoinWorkTemplate::from_bitcoin_header_hex_with_share_target(
                state.config.miner_id.clone(),
                &bitcoin_header_hex,
                state.share_target.clone(),
                template_created_at,
            ),
        },
        "template",
    )?;
    let mining_keypair = submit_stage(
        read_keypair_from_file(&state.config.mining_secret_key_file),
        "signing",
    )?;
    template.mining_signature_hex = sign_hash_hex(template.signing_hash(), &mining_keypair);
    submit_stage(
        template.verify_mining_signature(&state.mining_pubkey_hex),
        "signing",
    )?;
    let template_hash = template.template_hash.clone();

    let (idena_snapshot_id, idena_snapshot_proof_root) = active_job
        .payout_evidence
        .as_ref()
        .map(|evidence| {
            (
                evidence.snapshot.snapshot_day.to_string(),
                evidence.snapshot.score_root.clone(),
            )
        })
        .unwrap_or_else(|| {
            (
                state.config.idena_snapshot_id.clone(),
                state.config.idena_snapshot_proof_root.clone(),
            )
        });
    let mut share = Share {
        miner_id: state.config.miner_id.clone(),
        bitcoin_header_hex,
        bitcoin_template_hash: template_hash.clone(),
        nonce_hex: submit.nonce.clone(),
        work_hash,
        target: state.share_target.clone(),
        idena_snapshot_id,
        idena_snapshot_proof_root,
        hashrate_score_delta: submit_stage(
            Share::expected_hashrate_score_delta_for_target(&state.share_target),
            "share",
        )?,
        parent_share_hash: submit_stage(default_parent_share_hash(&state.config.datadir), "share")?,
        mining_signature_hex: String::new(),
    };
    share.mining_signature_hex = sign_hash_hex(share.signing_hash(), &mining_keypair);
    submit_stage(
        share.verify_mining_signature_for_template(&state.mining_pubkey_hex, &template),
        "signing",
    )?;
    if let Some(verifier) = state.config.idena_anchor_verifier.as_ref() {
        let replay = submit_stage(
            local_node::replay_state(&state.config.datadir),
            "idena-anchor",
        )?;
        submit_stage(
            replay.validate_idena_anchor_policy(
                &SharechainMessage::BitcoinWorkTemplate(template.clone()),
                verifier.policy(),
            ),
            "idena-anchor",
        )?;
        submit_stage(
            replay.validate_idena_anchor_policy(
                &SharechainMessage::Share(share.clone()),
                verifier.policy(),
            ),
            "idena-anchor",
        )?;
    }
    if block_candidate.meets_block_target && state.config.auto_submit_blocks {
        if let Some(client) = state.config.fork_chain_client.as_ref() {
            submit_stage(
                client
                    .validate_work_template(&template)
                    .await
                    .context("target-meeting share no longer extends the active fork-chain tip"),
                "tip-validation",
            )?;
        } else {
            let client = submit_stage(
                state
                    .config
                    .bitcoin_rpc_client
                    .as_ref()
                    .context("block-submission client is not configured"),
                "tip-validation",
            )?;
            submit_stage(
                client
                    .validate_bitcoin_share(
                        &template,
                        &share,
                        crate::bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                            allow_mutable_time: true,
                            max_time_drift_seconds: 7_200,
                            expected_header_merkle_root_hex: Some(
                                block_candidate.header_merkle_root_hex.clone(),
                            ),
                            allow_unverified_merkle_root: false,
                        },
                        state.config.derive_share_target_from_block,
                    )
                    .await
                    .context("target-meeting share no longer extends the active Bitcoin tip"),
                "tip-validation",
            )?;
        }
    }
    let block_submit = maybe_submit_block_candidate(state, &block_candidate).await;
    if block_candidate.meets_block_target && state.config.auto_submit_blocks {
        submit_stage(
            require_successful_block_submission(block_submit.as_ref()),
            "block-submission",
        )?;
    }
    submit_stage(
        local_node::accept_bitcoin_work_template(&state.config.datadir, template.clone()),
        "publication",
    )?;
    let template_publish = submit_stage(
        publish_sharechain_message(PublishSharechainMessageInput {
            datadir: state.config.datadir.clone(),
            message: SharechainMessage::BitcoinWorkTemplate(template),
            node_secret_key_file: state.config.node_secret_key_file.clone(),
            message_out: None,
            envelope_out: None,
            append: state.config.append,
            peer_addrs: state.config.peer_addrs.clone(),
        })
        .await,
        "publication",
    )?;
    if let Some(evidence) = active_job
        .payout_evidence
        .as_ref()
        .filter(|_| block_candidate.meets_block_target)
    {
        for (message, label) in target_block_payout_messages(evidence) {
            submit_stage(
                publish_sharechain_message(PublishSharechainMessageInput {
                    datadir: state.config.datadir.clone(),
                    message,
                    node_secret_key_file: state.config.node_secret_key_file.clone(),
                    message_out: None,
                    envelope_out: None,
                    append: true,
                    peer_addrs: state.config.peer_addrs.clone(),
                })
                .await
                .with_context(|| format!("failed to publish target block's {label}")),
                "publication",
            )?;
        }
    }
    let share_hash = share.share_hash();
    let bitcoin_header_hex = share.bitcoin_header_hex.clone();
    let work_hash = share.work_hash.clone();
    let share_publish = submit_stage(
        publish_sharechain_message(PublishSharechainMessageInput {
            datadir: state.config.datadir.clone(),
            message: SharechainMessage::Share(share),
            node_secret_key_file: state.config.node_secret_key_file.clone(),
            message_out: None,
            envelope_out: None,
            append: state.config.append,
            peer_addrs: state.config.peer_addrs.clone(),
        })
        .await,
        "publication",
    )?;
    if block_submit.as_ref().is_some_and(|submission| {
        submission
            .outcome
            .as_ref()
            .is_some_and(|outcome| matches!(outcome.status.as_str(), "accepted" | "duplicate"))
    }) {
        match refresh_job_once(state).await {
            Ok(Some(job_id)) => eprintln!("published replacement Stratum job {job_id}"),
            Ok(None) => {}
            Err(err) => eprintln!("failed immediate post-block Stratum refresh: {err:#}"),
        }
    }

    Ok(AcceptedShareSummary {
        worker_name: submit.worker_name.clone(),
        job_id: submit.job_id.clone(),
        extranonce1: extranonce1.to_ascii_lowercase(),
        extranonce2: submit.extranonce2.clone(),
        ntime: submit.ntime.clone(),
        nonce: submit.nonce.clone(),
        bitcoin_header_hex,
        work_hash,
        block_target: block_candidate.block_target,
        meets_block_target: block_candidate.meets_block_target,
        block_candidate_file,
        payout_candidate_file,
        block_submit,
        target: state.share_target.clone(),
        template_hash,
        share_hash,
        template_publish,
        share_publish,
    })
}

fn target_block_payout_messages(
    evidence: &ActivePayoutEvidence,
) -> [(SharechainMessage, &'static str); 2] {
    [
        (
            SharechainMessage::PayoutSchedule(evidence.payout_schedule.clone()),
            "payout schedule",
        ),
        (
            SharechainMessage::PohwCommitment(evidence.pohw_commitment.clone()),
            "PoHW commitment",
        ),
    ]
}

async fn maybe_submit_block_candidate(
    state: &AdapterState,
    candidate: &StratumBlockCandidate,
) -> Option<BlockSubmitSummary> {
    if !state.config.auto_submit_blocks || !candidate.meets_block_target {
        return None;
    }
    let result = async {
        if let Some(verifier) = state.config.idena_anchor_verifier.as_ref() {
            let replay = local_node::replay_state(&state.config.datadir)
                .context("failed to replay checkpointed sharechain before block submission")?;
            let checkpoint = replay.latest_sharechain_checkpoint().cloned().context(
                "block submission is locked until sharechain checkpoint round 1 finalizes",
            )?;
            if replay.best_share_tip() != Some(checkpoint.share_tip_hash.as_str()) {
                bail!(
                    "active payout tip does not match the latest finalized sharechain checkpoint"
                );
            }
            let supporter_registrations = checkpoint
                .supporters
                .iter()
                .map(|miner_id| {
                    replay
                        .registrations()
                        .get(miner_id)
                        .cloned()
                        .with_context(|| {
                            format!("checkpoint supporter {miner_id} is absent from local replay")
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            drop(replay);
            verifier
                .verify_checkpoint(&checkpoint, true)
                .await
                .context("latest sharechain checkpoint is no longer fresh or verifiable")?;
            for registration in supporter_registrations {
                verifier
                    .verify_registration(&registration)
                    .await
                    .with_context(|| {
                        format!(
                            "checkpoint supporter {} is no longer eligible",
                            registration.miner_id
                        )
                    })?;
            }
        }
        let block_hex = block_hex_for_stratum_candidate_submission(candidate)?;
        if let Some(client) = state.config.fork_chain_client.as_ref() {
            client.submit_block(block_hex).await
        } else {
            state
                .config
                .bitcoin_rpc_client
                .as_ref()
                .context("block-submission client is not configured")?
                .submit_block(block_hex)
                .await
        }
    }
    .await;
    Some(match result {
        Ok(outcome) => BlockSubmitSummary {
            outcome: Some(outcome),
            error: None,
        },
        Err(err) => BlockSubmitSummary {
            outcome: None,
            error: Some(format!("{err:#}")),
        },
    })
}

fn require_successful_block_submission(submission: Option<&BlockSubmitSummary>) -> Result<()> {
    let accepted = submission
        .and_then(|submission| submission.outcome.as_ref())
        .is_some_and(|outcome| matches!(outcome.status.as_str(), "accepted" | "duplicate"));
    if !accepted {
        bail!("block submission failed before sharechain publication");
    }
    Ok(())
}

fn persist_target_block_candidate(
    candidate_dir: Option<&Path>,
    candidate: &StratumBlockCandidate,
) -> Result<Option<PathBuf>> {
    if !candidate.meets_block_target {
        return Ok(None);
    }
    let Some(candidate_dir) = candidate_dir else {
        return Ok(None);
    };
    ensure_block_candidate_dir(candidate_dir)?;
    validate_hex_exact("candidate block_hash", &candidate.block_hash, 32)?;
    let path = candidate_dir.join(format!(
        "block-{}.json",
        candidate.block_hash.to_ascii_lowercase()
    ));
    write_block_candidate_file_create_new_or_matching(&path, candidate)?;
    Ok(Some(path))
}

#[derive(Serialize)]
struct GeneratedPayoutConfirmationCandidate {
    block_hash: String,
    snapshot_file: PathBuf,
    payout_schedule_file: PathBuf,
    pohw_commitment_file: PathBuf,
    reward_sats: u64,
    direct_limit: usize,
    min_direct_payout_sats: u64,
}

fn persist_payout_confirmation_evidence(
    candidate_dir: &Path,
    candidate: &StratumBlockCandidate,
    evidence: &ActivePayoutEvidence,
) -> Result<PathBuf> {
    if !candidate.meets_block_target {
        bail!("refusing to persist payout evidence for a non-target block candidate");
    }
    ensure_block_candidate_dir(candidate_dir)?;
    validate_hex_exact("candidate block_hash", &candidate.block_hash, 32)?;
    let block_hash = candidate.block_hash.to_ascii_lowercase();
    let evidence_dir_name = format!("evidence-{block_hash}");
    let evidence_dir = candidate_dir.join(&evidence_dir_name);
    ensure_block_candidate_dir(&evidence_dir)?;

    let snapshot_file = evidence_dir.join("snapshot.json");
    let payout_schedule_file = evidence_dir.join("payout-schedule.json");
    let pohw_commitment_file = evidence_dir.join("pohw-commitment.json");
    write_json_create_new_or_matching(
        &snapshot_file,
        &evidence.snapshot,
        "payout evidence snapshot",
        MAX_PAYOUT_EVIDENCE_SNAPSHOT_JSON_BYTES,
    )?;
    write_json_create_new_or_matching(
        &payout_schedule_file,
        &evidence.payout_schedule,
        "payout evidence schedule",
        MAX_PAYOUT_EVIDENCE_SCHEDULE_JSON_BYTES,
    )?;
    write_json_create_new_or_matching(
        &pohw_commitment_file,
        &evidence.pohw_commitment,
        "payout evidence commitment",
        MAX_PAYOUT_EVIDENCE_COMMITMENT_JSON_BYTES,
    )?;

    let descriptor = GeneratedPayoutConfirmationCandidate {
        block_hash: block_hash.clone(),
        snapshot_file: PathBuf::from(&evidence_dir_name).join("snapshot.json"),
        payout_schedule_file: PathBuf::from(&evidence_dir_name).join("payout-schedule.json"),
        pohw_commitment_file: PathBuf::from(&evidence_dir_name).join("pohw-commitment.json"),
        reward_sats: evidence.reward_sats,
        direct_limit: DIRECT_PAYOUT_LIMIT,
        min_direct_payout_sats: MIN_DIRECT_PAYOUT_SATS,
    };
    let descriptor_path = candidate_dir.join(format!("block-{block_hash}.json"));
    write_json_create_new_or_matching(
        &descriptor_path,
        &descriptor,
        "payout confirmation candidate",
        MAX_PAYOUT_EVIDENCE_CANDIDATE_JSON_BYTES,
    )?;
    Ok(descriptor_path)
}

fn write_json_create_new_or_matching<T: Serialize>(
    path: &Path,
    value: &T,
    label: &str,
    max_bytes: u64,
) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).with_context(|| format!("failed to encode {label}"))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!("{label} exceeds the maximum size of {max_bytes} bytes");
    }
    validate_no_unsafe_block_candidate_symlink_ancestors(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)
                .with_context(|| format!("failed to write {label} {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync {label} {}", path.display()))?;
            drop(file);
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).with_context(|| {
                format!("failed to inspect existing {label} {}", path.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "existing {label} path is not a regular file: {}",
                    path.display()
                );
            }
            if metadata.len() > max_bytes {
                bail!(
                    "existing {label} {} exceeds the maximum size",
                    path.display()
                );
            }
            let existing = fs::read(path)
                .with_context(|| format!("failed to read existing {label} {}", path.display()))?;
            if existing != bytes {
                bail!(
                    "existing {label} {} differs from current evidence",
                    path.display()
                );
            }
            Ok(())
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to create {label} {}", path.display()))
        }
    }
}

fn ensure_block_candidate_dir(candidate_dir: &Path) -> Result<()> {
    validate_no_unsafe_block_candidate_symlink_ancestors(candidate_dir)?;
    match fs::symlink_metadata(candidate_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!(
                    "block candidate dir must not be a symlink: {}",
                    candidate_dir.display()
                );
            }
            if !metadata.is_dir() {
                bail!(
                    "block candidate path is not a directory: {}",
                    candidate_dir.display()
                );
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(candidate_dir).with_context(|| {
                format!(
                    "failed to create block candidate dir {}",
                    candidate_dir.display()
                )
            })?;
            sync_directory(candidate_dir.parent().unwrap_or_else(|| Path::new(".")))?;
            let metadata = fs::symlink_metadata(candidate_dir).with_context(|| {
                format!(
                    "failed to inspect block candidate dir {}",
                    candidate_dir.display()
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "block candidate dir is not a regular directory after creation: {}",
                    candidate_dir.display()
                );
            }
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to inspect block candidate dir {}",
                    candidate_dir.display()
                )
            });
        }
    }
    Ok(())
}

fn write_block_candidate_file_create_new_or_matching(
    path: &Path,
    candidate: &StratumBlockCandidate,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(candidate).context("failed to encode block candidate")?;
    validate_no_unsafe_block_candidate_symlink_ancestors(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&bytes)
                .with_context(|| format!("failed to write block candidate {}", path.display()))?;
            file.write_all(b"\n")
                .with_context(|| format!("failed to finish block candidate {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync block candidate {}", path.display()))?;
            drop(file);
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).with_context(|| {
                format!(
                    "failed to inspect existing block candidate {}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "existing block candidate path is not a regular file: {}",
                    path.display()
                );
            }
            if metadata.len() > MAX_BLOCK_CANDIDATE_JSON_BYTES {
                bail!(
                    "existing block candidate {} is too large: {} bytes",
                    path.display(),
                    metadata.len()
                );
            }
            let existing_raw = fs::read_to_string(path).with_context(|| {
                format!("failed to read existing block candidate {}", path.display())
            })?;
            let existing: StratumBlockCandidate = serde_json::from_str(&existing_raw)
                .with_context(|| {
                    format!(
                        "failed to parse existing block candidate {}",
                        path.display()
                    )
                })?;
            if &existing != candidate {
                bail!(
                    "existing block candidate {} differs from current target-meeting candidate",
                    path.display()
                );
            }
            Ok(())
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to create block candidate {}", path.display()))
        }
    }
}

#[cfg(unix)]
fn validate_no_unsafe_block_candidate_symlink_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for block candidate path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect block candidate symlink ancestor {}",
                        ancestor.display()
                    )
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = ancestor.parent().unwrap_or_else(|| Path::new("/"));
        let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect block candidate symlink ancestor parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            bail!(
                "block candidate path {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_block_candidate_symlink_ancestors(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    let dir = fs::File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?;
    dir.sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn template_created_at_unix_from_header_hex(bitcoin_header_hex: &str) -> Result<i64> {
    let header = decode_hex_exact_bytes("bitcoin_header", bitcoin_header_hex, 80)?;
    let ntime = u32::from_le_bytes(
        header[68..72]
            .try_into()
            .expect("slice length checked by decode"),
    );
    Ok(i64::from(ntime.max(1)))
}

fn build_header_hex_from_submit(
    job: &StratumJob,
    submit: &SubmitWork,
    extranonce1: &str,
) -> Result<String> {
    if !submit.ntime.eq_ignore_ascii_case(&job.ntime) {
        bail!("submitted ntime does not match advertised job ntime; mutable time is not supported");
    }
    let coinbase_hex = coinbase_tx_hex_from_submit(job, submit, extranonce1)?;
    let coinbase = hex::decode(&coinbase_hex)?;
    let coinbase_tx = decode_coinbase_transaction(&coinbase)?;
    let mut merkle = display_hash_to_header_order_bytes(&coinbase_tx.compute_txid().to_string())?;
    for branch_hex in &job.merkle_branches {
        let branch = decode_hex_exact_bytes("merkle branch", branch_hex, 32)?;
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&merkle);
        payload.extend_from_slice(&branch);
        merkle = sha256d::Hash::hash(&payload).to_byte_array();
    }
    let header_hex = format!(
        "{}{}{}{}{}{}",
        job.version.to_ascii_lowercase(),
        job.prevhash.to_ascii_lowercase(),
        hex::encode(merkle),
        submit.ntime.to_ascii_lowercase(),
        job.nbits.to_ascii_lowercase(),
        submit.nonce.to_ascii_lowercase()
    );
    validate_hex_exact("bitcoin header", &header_hex, 80)?;
    Ok(header_hex)
}

fn coinbase_tx_hex_from_submit(
    job: &StratumJob,
    submit: &SubmitWork,
    extranonce1: &str,
) -> Result<String> {
    let coinbase_hex = format!(
        "{}{}{}{}",
        job.coinbase1.to_ascii_lowercase(),
        extranonce1.to_ascii_lowercase(),
        submit.extranonce2.to_ascii_lowercase(),
        job.coinbase2.to_ascii_lowercase()
    );
    validate_hex_even("coinbase", &coinbase_hex, MAX_COINBASE_HEX_BYTES)?;
    Ok(coinbase_hex)
}

fn decode_coinbase_transaction(bytes: &[u8]) -> Result<Transaction> {
    let tx: Transaction =
        deserialize(bytes).context("coinbase bytes are not a valid Bitcoin transaction")?;
    if !tx.is_coinbase() {
        bail!("coinbase bytes do not decode to a coinbase transaction");
    }
    Ok(tx)
}

fn complete_block_hex(
    job: &StratumJob,
    header: &[u8],
    coinbase: &[u8],
) -> Result<(Option<String>, String)> {
    if job.transaction_data.is_empty() && !job.merkle_branches.is_empty() {
        return Ok((
            None,
            "incomplete_missing_non_coinbase_transaction_data".to_string(),
        ));
    }
    let (non_coinbase_txids, non_coinbase_txs) =
        decode_non_coinbase_transaction_data(&job.transaction_data)?;
    let expected_branches = coinbase_merkle_branches(&non_coinbase_txids)?;
    if expected_branches != normalized_merkle_branches(&job.merkle_branches)? {
        bail!("transaction_data does not match advertised merkle branches");
    }

    let transaction_count = 1usize
        .checked_add(non_coinbase_txs.len())
        .ok_or_else(|| anyhow!("block transaction count overflow"))?;
    let mut block = Vec::with_capacity(header.len() + 1 + coinbase.len());
    block.extend_from_slice(header);
    append_compact_size(&mut block, transaction_count as u64);
    block.extend_from_slice(coinbase);
    for tx in non_coinbase_txs {
        block.extend_from_slice(&tx);
    }
    if block.len() > MAX_COMPLETE_BLOCK_BYTES {
        bail!(
            "complete block is too large: {} bytes; maximum is {MAX_COMPLETE_BLOCK_BYTES}",
            block.len()
        );
    }
    let parsed: Block = deserialize(&block).context("complete block bytes do not decode")?;
    if serialize(&parsed) != block {
        bail!("complete block bytes are not canonical Bitcoin block encoding");
    }
    if !parsed.check_merkle_root() {
        bail!("complete block merkle root does not match header");
    }
    if !parsed.check_witness_commitment() {
        bail!("complete block witness commitment is missing or invalid");
    }
    let status = if job.transaction_data.is_empty() {
        "complete_coinbase_only"
    } else {
        "complete_with_non_coinbase_transactions"
    };
    Ok((Some(hex::encode(block)), status.to_string()))
}

fn decode_non_coinbase_transaction_data(
    transaction_data: &[String],
) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
    let mut txids = Vec::with_capacity(transaction_data.len());
    let mut transactions = Vec::with_capacity(transaction_data.len());
    for (index, data_hex) in transaction_data.iter().enumerate() {
        validate_hex_even("transaction_data entry", data_hex, MAX_COMPLETE_BLOCK_BYTES)?;
        let tx_bytes = hex::decode(data_hex.to_ascii_lowercase())
            .with_context(|| format!("failed to decode transaction_data entry {index}"))?;
        let tx: Transaction = deserialize(&tx_bytes).with_context(|| {
            format!("transaction_data entry {index} is not a Bitcoin transaction")
        })?;
        if tx.is_coinbase() {
            bail!("transaction_data entry {index} must not be a coinbase transaction");
        }
        txids.push(tx.compute_txid().to_string());
        transactions.push(tx_bytes);
    }
    Ok((txids, transactions))
}

fn normalized_merkle_branches(branches: &[String]) -> Result<Vec<String>> {
    branches
        .iter()
        .map(|branch| {
            validate_hex_exact("merkle branch", branch, 32)?;
            Ok(branch.to_ascii_lowercase())
        })
        .collect()
}

fn validate_candidate_block_hex(
    candidate: &StratumBlockCandidate,
    block_hex: &str,
    header: &[u8],
) -> Result<()> {
    validate_hex_even("block_hex", block_hex, MAX_COMPLETE_BLOCK_BYTES)?;
    let block_bytes =
        hex::decode(block_hex.to_ascii_lowercase()).context("failed to decode block_hex")?;
    if block_bytes.len() < 81 {
        bail!("candidate block_hex is too short to contain a block");
    }
    if &block_bytes[..80] != header {
        bail!("candidate block_hex header does not match bitcoin_header_hex");
    }

    let block: Block =
        deserialize(&block_bytes).context("block_hex is not a valid Bitcoin block")?;
    if serialize(&block) != block_bytes {
        bail!("candidate block_hex is not canonical Bitcoin block encoding");
    }
    if !block.check_merkle_root() {
        bail!("candidate block_hex merkle root does not match header");
    }
    if !block.check_witness_commitment() {
        bail!("candidate block_hex witness commitment is missing or invalid");
    }

    let coinbase_tx = block
        .txdata
        .first()
        .ok_or_else(|| anyhow!("candidate block_hex has no coinbase transaction"))?;
    if !coinbase_tx.is_coinbase() {
        bail!("candidate block_hex first transaction is not a coinbase transaction");
    }
    let coinbase_tx_bytes = hex::decode(candidate.coinbase_tx_hex.to_ascii_lowercase())
        .context("failed to decode coinbase tx")?;
    if serialize(coinbase_tx) != coinbase_tx_bytes {
        bail!("candidate block_hex coinbase transaction does not match coinbase_tx_hex");
    }
    let computed_coinbase_txid = coinbase_tx.compute_txid().to_string();
    if !candidate
        .coinbase_txid
        .eq_ignore_ascii_case(&computed_coinbase_txid)
    {
        bail!(
            "candidate coinbase_txid {} does not match recomputed txid {}",
            candidate.coinbase_txid,
            computed_coinbase_txid
        );
    }
    Ok(())
}

fn block_target_hex_from_job_nbits(nbits_header_order_hex: &str) -> Result<String> {
    validate_hex_exact("nbits", nbits_header_order_hex, 4)?;
    let mut bits = hex::decode(nbits_header_order_hex.to_ascii_lowercase())?;
    bits.reverse();
    let compact = CompactTarget::from_unprefixed_hex(&hex::encode(bits))
        .context("failed to parse compact target bits")?;
    let target = Target::from_compact(compact);
    Ok(hex::encode(target.to_be_bytes()))
}

fn coinbase_split_for_extranonces(
    height: u64,
    extranonce2_size: usize,
    default_witness_commitment: Option<&str>,
    pohw_replay_marker: Option<&str>,
) -> Result<(String, String)> {
    let mut outputs = vec![CoinbaseOutputSpec {
        amount_sats: 0,
        script_pubkey_hex: "6a".to_string(),
    }];
    if let Some(script_pubkey_hex) = pohw_replay_marker {
        outputs.push(CoinbaseOutputSpec {
            amount_sats: 0,
            script_pubkey_hex: validate_pohw_replay_marker_script(script_pubkey_hex)?,
        });
    }
    if let Some(script_pubkey_hex) = default_witness_commitment {
        outputs.push(CoinbaseOutputSpec {
            amount_sats: 0,
            script_pubkey_hex: validate_witness_commitment_script(script_pubkey_hex)?,
        });
    }
    coinbase_split_for_outputs(
        height,
        extranonce2_size,
        &outputs,
        default_witness_commitment.is_some(),
    )
}

fn coinbase_split_for_pohw_payouts(
    height: u64,
    extranonce2_size: usize,
    coinbase_value_sats: Sats,
    payout_schedule: &PayoutSchedule,
    pohw_commitment: &PohwCommitment,
    default_witness_commitment: Option<&str>,
    pohw_replay_marker: Option<&str>,
) -> Result<(String, String)> {
    payout_schedule.validate()?;
    let pohw_commitment = pohw_commitment.clone().normalized();
    if pohw_commitment.version != "POHW1" {
        bail!(
            "POHW commitment version must be POHW1, got {}",
            pohw_commitment.version
        );
    }
    if !pohw_commitment
        .payout_schedule_root
        .eq_ignore_ascii_case(&payout_schedule.payout_root)
    {
        bail!(
            "POHW commitment payout root {} does not match schedule root {}",
            pohw_commitment.payout_schedule_root,
            payout_schedule.payout_root
        );
    }

    let mut outputs = Vec::new();
    for output in &payout_schedule.direct_outputs {
        validate_direct_coinbase_script(&output.btc_payout_script_hex)?;
        outputs.push(CoinbaseOutputSpec {
            amount_sats: output.amount_sats,
            script_pubkey_hex: output.btc_payout_script_hex.to_ascii_lowercase(),
        });
    }
    if payout_schedule.vault_output_sats > 0 {
        outputs.push(CoinbaseOutputSpec {
            amount_sats: payout_schedule.vault_output_sats,
            script_pubkey_hex: vault_script_pubkey_hex(&pohw_commitment.frost_vault_key_xonly)?,
        });
    }
    let positive_output_total = coinbase_positive_output_total(&outputs)?;
    if positive_output_total == 0 {
        bail!("PoHW payout coinbase must contain at least one positive payout output");
    }
    if positive_output_total != coinbase_value_sats {
        bail!(
            "PoHW payout coinbase positive output total {positive_output_total} sats does not match Bitcoin getblocktemplate coinbasevalue {coinbase_value_sats} sats"
        );
    }
    outputs.push(CoinbaseOutputSpec {
        amount_sats: 0,
        script_pubkey_hex: pohw_commitment.op_return_script_pubkey_hex(),
    });
    if let Some(script_pubkey_hex) = pohw_replay_marker {
        outputs.push(CoinbaseOutputSpec {
            amount_sats: 0,
            script_pubkey_hex: validate_pohw_replay_marker_script(script_pubkey_hex)?,
        });
    }
    if let Some(script_pubkey_hex) = default_witness_commitment {
        outputs.push(CoinbaseOutputSpec {
            amount_sats: 0,
            script_pubkey_hex: validate_witness_commitment_script(script_pubkey_hex)?,
        });
    }
    coinbase_split_for_outputs(
        height,
        extranonce2_size,
        &outputs,
        default_witness_commitment.is_some(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoinbaseOutputSpec {
    amount_sats: Sats,
    script_pubkey_hex: String,
}

fn coinbase_split_for_outputs(
    height: u64,
    extranonce2_size: usize,
    outputs: &[CoinbaseOutputSpec],
    include_witness_reserved_value: bool,
) -> Result<(String, String)> {
    if outputs.is_empty() || outputs.len() > MAX_COINBASE_OUTPUTS {
        bail!(
            "coinbase output count must be 1..={MAX_COINBASE_OUTPUTS}, got {}",
            outputs.len()
        );
    }
    let height_push = small_push(&minimal_script_number(height)?)?;
    let tag_push = small_push(b"POHW0")?;
    let extranonce_bytes = STRATUM_EXTRANONCE1_BYTES
        .checked_add(extranonce2_size)
        .ok_or_else(|| anyhow!("extranonce length overflow"))?;
    let script_sig_len = height_push
        .len()
        .checked_add(tag_push.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(extranonce_bytes))
        .ok_or_else(|| anyhow!("coinbase script length overflow"))?;
    if script_sig_len > 100 {
        bail!("coinbase scriptSig would exceed 100 bytes");
    }
    let mut coinbase1 = Vec::new();
    coinbase1.extend_from_slice(&2u32.to_le_bytes());
    if include_witness_reserved_value {
        coinbase1.extend_from_slice(&[0x00, 0x01]);
    }
    coinbase1.push(1);
    coinbase1.extend_from_slice(&[0u8; 32]);
    coinbase1.extend_from_slice(&u32::MAX.to_le_bytes());
    coinbase1.push(u8::try_from(script_sig_len).expect("script length checked"));
    coinbase1.extend_from_slice(&height_push);
    coinbase1.extend_from_slice(&tag_push);
    coinbase1.push(u8::try_from(extranonce_bytes).expect("extranonce length checked"));

    let mut coinbase2 = Vec::new();
    coinbase2.extend_from_slice(&u32::MAX.to_le_bytes());
    append_compact_size(&mut coinbase2, outputs.len() as u64);
    for output in outputs {
        append_coinbase_output(&mut coinbase2, output)?;
    }
    if include_witness_reserved_value {
        coinbase2.push(1);
        coinbase2.push(32);
        coinbase2.extend_from_slice(&[0u8; 32]);
    }
    coinbase2.extend_from_slice(&0u32.to_le_bytes());
    Ok((hex::encode(coinbase1), hex::encode(coinbase2)))
}

fn append_coinbase_output(bytes: &mut Vec<u8>, output: &CoinbaseOutputSpec) -> Result<()> {
    bytes.extend_from_slice(&output.amount_sats.to_le_bytes());
    let script = decode_script_hex("coinbase output script", &output.script_pubkey_hex)?;
    append_compact_size(bytes, script.len() as u64);
    bytes.extend_from_slice(&script);
    Ok(())
}

fn append_compact_size(bytes: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        bytes.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        bytes.push(0xfd);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u64::from(u32::MAX) {
        bytes.push(0xfe);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        bytes.push(0xff);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

fn decode_script_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    validate_hex_even(label, value, MAX_COINBASE_HEX_BYTES)?;
    hex::decode(value.to_ascii_lowercase()).with_context(|| format!("failed to decode {label}"))
}

fn validate_direct_coinbase_script(script_hex: &str) -> Result<()> {
    let script = ScriptBuf::from_bytes(decode_script_hex("direct payout script", script_hex)?);
    if script.is_p2wpkh() || script.is_p2tr() {
        Ok(())
    } else {
        bail!("direct payout script must be P2WPKH or P2TR");
    }
}

fn validate_witness_commitment_script(script_hex: &str) -> Result<String> {
    let script_hex = script_hex.to_ascii_lowercase();
    validate_hex_even(
        "default_witness_commitment",
        &script_hex,
        MAX_COINBASE_HEX_BYTES,
    )?;
    if script_hex.len() != 38 * 2 || !script_hex.starts_with("6a24aa21a9ed") {
        bail!("default_witness_commitment must be the BIP141 OP_RETURN witness commitment script");
    }
    Ok(script_hex)
}

fn validate_pohw_replay_marker_script(script_hex: &str) -> Result<String> {
    let script_hex = script_hex.to_ascii_lowercase();
    validate_hex_even("pohw_replay_marker", &script_hex, MAX_COINBASE_HEX_BYTES)?;
    if script_hex != POHW_REPLAY_MARKER_SCRIPT_HEX {
        bail!("pohw_replay_marker must be the exact fork-only replay marker script");
    }
    Ok(script_hex)
}

fn coinbase_positive_output_total(outputs: &[CoinbaseOutputSpec]) -> Result<Sats> {
    let mut total = 0u64;
    for output in outputs {
        total = total
            .checked_add(output.amount_sats)
            .ok_or_else(|| anyhow!("coinbase output amount overflow"))?;
    }
    Ok(total)
}

fn minimal_script_number(value: u64) -> Result<Vec<u8>> {
    if value == 0 {
        return Ok(Vec::new());
    }
    let mut remaining = value;
    let mut bytes = Vec::new();
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    if bytes.len() > 75 {
        bail!("script number is too large for a small push");
    }
    Ok(bytes)
}

fn small_push(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > 75 {
        bail!("small push data exceeds 75 bytes");
    }
    let mut out = Vec::with_capacity(data.len() + 1);
    out.push(u8::try_from(data.len()).expect("length checked"));
    out.extend_from_slice(data);
    Ok(out)
}

fn coinbase_merkle_branches(transaction_hashes: &[String]) -> Result<Vec<String>> {
    let mut level = Vec::with_capacity(transaction_hashes.len() + 1);
    level.push([0u8; 32]);
    for hash in transaction_hashes {
        level.push(display_hash_to_header_order_bytes(hash)?);
    }
    let mut branch = Vec::new();
    let mut coinbase_index = 0usize;
    while level.len() > 1 {
        let sibling_index = if coinbase_index % 2 == 0 {
            if coinbase_index + 1 < level.len() {
                coinbase_index + 1
            } else {
                coinbase_index
            }
        } else {
            coinbase_index - 1
        };
        branch.push(hex::encode(level[sibling_index]));

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&left);
            payload.extend_from_slice(&right);
            next.push(sha256d::Hash::hash(&payload).to_byte_array());
        }
        coinbase_index /= 2;
        level = next;
    }
    if branch.len() > MAX_MERKLE_BRANCHES {
        bail!(
            "coinbase merkle branch contains {} entries; maximum supported is {}",
            branch.len(),
            MAX_MERKLE_BRANCHES
        );
    }
    Ok(branch)
}

fn display_hash_to_header_order_hex(hash: &str) -> Result<String> {
    display_hash_to_header_order_bytes(hash).map(hex::encode)
}

fn display_hash_to_header_order_bytes(hash: &str) -> Result<[u8; 32]> {
    validate_hex_exact("display hash", hash, 32)?;
    let mut bytes = hex::decode(hash.to_ascii_lowercase())?;
    bytes.reverse();
    Ok(bytes.try_into().expect("hash length checked"))
}

fn compact_bits_to_header_order_hex(bits: &str) -> Result<String> {
    validate_hex_exact("compact target bits", bits, 4)?;
    let mut bytes = hex::decode(bits.to_ascii_lowercase())?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}

fn ensure_hash_meets_target(work_hash: &str, target: &str) -> Result<()> {
    let work = decode_hex_exact_bytes("work_hash", work_hash, 32)?;
    let target = decode_hex_exact_bytes("target", target, 32)?;
    if target.iter().all(|byte| *byte == 0) {
        bail!("share target must not be zero");
    }
    if work > target {
        bail!("share does not meet adapter target");
    }
    Ok(())
}

fn validate_label(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        bail!("{label} must be 1-{max_len} printable characters");
    }
    Ok(())
}

fn validate_hex_even(label: &str, value: &str, max_hex_bytes: usize) -> Result<()> {
    if value.len() % 2 != 0 {
        bail!("{label} must have an even hex length");
    }
    if value.len() > max_hex_bytes * 2 {
        bail!("{label} exceeds {max_hex_bytes} bytes");
    }
    if !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be hex");
    }
    Ok(())
}

fn validate_hex_exact(label: &str, value: &str, bytes: usize) -> Result<()> {
    if value.len() != bytes * 2 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be exactly {bytes} bytes encoded as hex");
    }
    Ok(())
}

fn decode_hex_exact_bytes(label: &str, value: &str, bytes: usize) -> Result<Vec<u8>> {
    validate_hex_exact(label, value, bytes)?;
    hex::decode(value.to_ascii_lowercase()).with_context(|| format!("failed to decode {label}"))
}

pub(crate) fn default_share_target_hex() -> String {
    hex::encode(Target::MAX_ATTAINABLE_MAINNET.to_be_bytes())
}

pub(crate) fn default_stratum_difficulty() -> f64 {
    DEFAULT_STRATUM_DIFFICULTY
}

pub(crate) fn default_extranonce2_size() -> usize {
    DEFAULT_EXTRANONCE2_SIZE
}

pub(crate) fn default_max_line_bytes() -> usize {
    DEFAULT_MAX_LINE_BYTES
}

pub(crate) fn default_idle_timeout_seconds() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECONDS
}

pub(crate) fn default_job_refresh_interval_seconds() -> u64 {
    DEFAULT_JOB_REFRESH_INTERVAL_SECONDS
}

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
    use crate::bitcoin_rpc::BitcoinMiningJobTransaction;
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
    use bitcoin::{absolute, transaction, Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};
    use pohw_core::commitment::PohwCommitmentParams;
    use pohw_core::payout::{DirectPayout, VaultAllocation};
    use pohw_core::sharechain::{MinerRegistration, SnapshotVote};
    use pohw_core::snapshot::{IdenaStatus, SnapshotLeaf};
    use pohw_core::FORMULA_VERSION;
    use tiny_keccak::{Hasher, Keccak};

    #[test]
    fn stratum_rate_window_bounds_requests_and_submits() {
        let start = Instant::now();
        let mut requests = StratumRateWindow::new(start);
        for _ in 0..MAX_STRATUM_REQUESTS_PER_WINDOW {
            requests.observe_request(start).unwrap();
        }
        assert!(requests.observe_request(start).is_err());
        requests
            .observe_request(start + Duration::from_secs(STRATUM_RATE_WINDOW_SECONDS))
            .unwrap();

        let mut submits = StratumRateWindow::new(start);
        for _ in 0..MAX_STRATUM_SUBMITS_PER_WINDOW {
            submits.observe_submit(start).unwrap();
        }
        assert!(submits.observe_submit(start).is_err());
        submits
            .observe_submit(start + Duration::from_secs(STRATUM_RATE_WINDOW_SECONDS))
            .unwrap();
    }

    #[test]
    fn stratum_submission_memory_is_bounded_and_deduplicated() {
        let mut submitted = BTreeSet::new();
        assert!(remember_stratum_submission(&mut submitted, "one".into(), 2).unwrap());
        assert!(!remember_stratum_submission(&mut submitted, "one".into(), 2).unwrap());
        assert!(remember_stratum_submission(&mut submitted, "two".into(), 2).unwrap());
        assert!(remember_stratum_submission(&mut submitted, "three".into(), 2).is_err());
        assert_eq!(submitted.len(), 2);
    }

    #[test]
    fn block_submission_must_succeed_before_sharechain_publication() {
        for status in ["accepted", "duplicate"] {
            let submission = BlockSubmitSummary {
                outcome: Some(SubmitBlockOutcome {
                    status: status.to_string(),
                    reject_reason: None,
                }),
                error: None,
            };
            require_successful_block_submission(Some(&submission)).unwrap();
        }

        let rejected = BlockSubmitSummary {
            outcome: Some(SubmitBlockOutcome {
                status: "rejected".to_string(),
                reject_reason: Some("test rejection".to_string()),
            }),
            error: None,
        };
        assert!(require_successful_block_submission(Some(&rejected)).is_err());

        let transport_error = BlockSubmitSummary {
            outcome: None,
            error: Some("test transport error".to_string()),
        };
        assert!(require_successful_block_submission(Some(&transport_error)).is_err());
        assert!(require_successful_block_submission(None).is_err());
    }

    #[test]
    fn dynamic_payout_voter_floor_distinguishes_fork_from_mainnet() {
        assert!(validate_dynamic_payout_voter_floor(1, false).is_ok());
        assert!(validate_dynamic_payout_voter_floor(0, false).is_err());
        assert!(
            validate_dynamic_payout_voter_floor(MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS, true,).is_ok()
        );
        assert!(
            validate_dynamic_payout_voter_floor(MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS - 1, true,)
                .is_err()
        );
    }

    fn test_job() -> StratumJob {
        let mut job = build_stratum_job_from_template(&mining_job_material(), 4)
            .expect("valid generated test job")
            .job;
        job.job_id = "job-1".to_string();
        job
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pohw-{label}-{}", random_nonce_hex()))
    }

    fn target_meeting_candidate() -> StratumBlockCandidate {
        let job = test_job();
        for nonce in 0u32..100_000 {
            let candidate = build_stratum_block_candidate(
                &job,
                "aabbccdd",
                "01020304",
                &job.ntime,
                &hex::encode(nonce.to_le_bytes()),
                4,
                false,
            )
            .expect("build candidate");
            if candidate.meets_block_target {
                return candidate;
            }
        }
        panic!("test did not find a target-meeting candidate");
    }

    fn payout_schedule() -> PayoutSchedule {
        let mut schedule = PayoutSchedule {
            direct_outputs: vec![DirectPayout {
                miner_id: "miner-a".to_string(),
                btc_payout_script_hex: "00141111111111111111111111111111111111111111".to_string(),
                amount_sats: 20_000,
            }],
            vault_allocations: vec![VaultAllocation {
                miner_id: "miner-b".to_string(),
                claim_owner_id: "claim-owner".to_string(),
                amount_sats: 30_000,
            }],
            vault_output_sats: 30_000,
            payout_root: String::new(),
        };
        schedule.payout_root = schedule.expected_payout_root();
        schedule
    }

    fn pohw_commitment(schedule: &PayoutSchedule) -> PohwCommitment {
        PohwCommitment::new_pohw1(PohwCommitmentParams {
            idena_snapshot_id: "2026-07-05".to_string(),
            idena_score_root: "11".repeat(32),
            miner_idena_address: "0x1111111111111111111111111111111111111111".to_string(),
            identity_proof_root: "22".repeat(32),
            sharechain_tip: "33".repeat(32),
            sharechain_state_root: Some("44".repeat(32)),
            payout_schedule_root: schedule.payout_root.clone(),
            vault_epoch_id: 1,
            frost_vault_key_xonly: "44".repeat(32),
        })
    }

    fn coinbase_tx_from_job(job: &StratumJob) -> Transaction {
        let coinbase_hex = format!(
            "{}{}{}{}",
            job.coinbase1, "aabbccdd", "01020304", job.coinbase2
        );
        let coinbase = hex::decode(coinbase_hex).unwrap();
        deserialize(&coinbase).unwrap()
    }

    fn mining_job_material() -> BitcoinMiningJobTemplate {
        BitcoinMiningJobTemplate {
            version: 0x2000_0000,
            previous_block_hash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            curtime: 0x0102_0304,
            bits: "207fffff".to_string(),
            height: 840_000,
            coinbase_value_sats: 50_000,
            transaction_hashes: Vec::new(),
            transactions: Vec::new(),
            default_witness_commitment: None,
            pohw_replay_marker: None,
        }
    }

    fn test_keypair(byte: u8) -> Keypair {
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&Secp256k1::new(), &secret_key)
    }

    fn sign_test_schnorr(hash: [u8; 32], keypair: &Keypair) -> String {
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
        hex::encode(signature.serialize())
    }

    fn test_keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }

    fn test_idena_signin_hash(challenge: &str) -> [u8; 32] {
        test_keccak256(&test_keccak256(challenge.as_bytes()))
    }

    fn test_idena_address(secret_key: &SecretKey) -> String {
        let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        let serialized = pubkey.serialize_uncompressed();
        let hash = test_keccak256(&serialized[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    fn test_idena_signature(challenge: &str, secret_key: &SecretKey) -> String {
        let signature = Secp256k1::new().sign_ecdsa_recoverable(
            &Message::from_digest(test_idena_signin_hash(challenge)),
            secret_key,
        );
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        hex::encode(bytes)
    }

    fn signed_test_registration(
        miner_id: &str,
        mining_key_byte: u8,
        claim_key_byte: u8,
        idena_key_byte: u8,
    ) -> (MinerRegistration, Keypair) {
        let mining_keypair = test_keypair(mining_key_byte);
        let claim_keypair = test_keypair(claim_key_byte);
        let idena_secret = SecretKey::from_slice(&[idena_key_byte; 32]).unwrap();
        let claim_xonly = claim_keypair.x_only_public_key().0.to_string();
        let mut registration = MinerRegistration {
            version: pohw_core::sharechain::LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: miner_id.to_string(),
            idena_address: test_idena_address(&idena_secret),
            btc_payout_script_hex: format!("5120{claim_xonly}"),
            claim_owner_pubkey_hex: claim_xonly,
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            test_idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex =
            sign_test_schnorr(registration.signing_hash(), &mining_keypair);
        (registration, mining_keypair)
    }

    fn test_share(miner_id: &str, mining_keypair: &Keypair) -> Share {
        let target = "7fffff0000000000000000000000000000000000000000000000000000000000";
        for nonce in 0..10_000u32 {
            let mut header = [0u8; 80];
            header[0..4].copy_from_slice(&1u32.to_le_bytes());
            header[36..68].copy_from_slice(&[0x33; 32]);
            header[68..72].copy_from_slice(&1_231_006_505u32.to_le_bytes());
            header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let mut share = Share {
                miner_id: miner_id.to_string(),
                bitcoin_header_hex: hex::encode(header),
                bitcoin_template_hash: String::new(),
                nonce_hex: String::new(),
                work_hash: String::new(),
                target: target.to_string(),
                idena_snapshot_id: Utc::now().date_naive().to_string(),
                idena_snapshot_proof_root: "11".repeat(32),
                hashrate_score_delta: 1,
                parent_share_hash: "00".repeat(32),
                mining_signature_hex: String::new(),
            };
            share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash().unwrap();
            share.nonce_hex = share.recomputed_nonce_hex().unwrap();
            share.work_hash = share.recomputed_work_hash().unwrap();
            if share.work_hash.as_str() <= target {
                share.mining_signature_hex =
                    sign_test_schnorr(share.signing_hash(), mining_keypair);
                return share;
            }
        }
        panic!("test target did not yield a valid share");
    }

    fn append_dynamic_payout_fixture(
        datadir: &Path,
        snapshot_dir: &Path,
        include_active_share: bool,
    ) -> (MinerRegistration, PohwCommitment) {
        let (miner, miner_keypair) = signed_test_registration("miner-a", 9, 19, 29);
        let (voter_b, voter_b_keypair) = signed_test_registration("voter-b", 10, 20, 30);
        let (voter_c, voter_c_keypair) = signed_test_registration("voter-c", 11, 21, 31);
        for registration in [&miner, &voter_b, &voter_c] {
            local_node::append_message(
                datadir,
                SharechainMessage::MinerRegistration(registration.clone()),
            )
            .unwrap();
        }

        if include_active_share {
            let share = test_share(&miner.miner_id, &miner_keypair);
            let mut template = BitcoinWorkTemplate::new_unsigned(
                &share.miner_id,
                share.bitcoin_header_prefix_hex().unwrap(),
                1,
            )
            .unwrap();
            template.mining_signature_hex =
                sign_test_schnorr(template.signing_hash(), &miner_keypair);
            local_node::accept_bitcoin_work_template(datadir, template.clone()).unwrap();
            local_node::append_message(datadir, SharechainMessage::BitcoinWorkTemplate(template))
                .unwrap();
            local_node::append_message(datadir, SharechainMessage::Share(share)).unwrap();
        }

        let identity_root = "11".repeat(32);
        let snapshot = Snapshot::build(
            Utc::now().date_naive(),
            1_000,
            "aa".repeat(32),
            identity_root.clone(),
            FORMULA_VERSION,
            [&miner, &voter_b, &voter_c]
                .into_iter()
                .map(|registration| SnapshotLeaf {
                    idena_address: registration.idena_address.clone(),
                    status: IdenaStatus::Human,
                    pubkey: "02".repeat(33),
                    validation_reward_score: 1,
                    proposer_reward_score: 0,
                    committee_reward_score: 0,
                    ignored_invitation_score: 0,
                    identity_root: identity_root.clone(),
                    formula_version: FORMULA_VERSION,
                })
                .collect(),
        );
        fs::create_dir_all(snapshot_dir).unwrap();
        fs::write(
            snapshot_dir.join("snapshot.json"),
            serde_json::to_vec_pretty(&snapshot).unwrap(),
        )
        .unwrap();
        for (registration, keypair) in [
            (&miner, &miner_keypair),
            (&voter_b, &voter_b_keypair),
            (&voter_c, &voter_c_keypair),
        ] {
            let mut vote = SnapshotVote {
                voter_miner_id: registration.miner_id.clone(),
                snapshot_day: snapshot.snapshot_day.to_string(),
                idena_height: snapshot.idena_height,
                score_root: snapshot.score_root.clone(),
                signature_hex: String::new(),
            };
            vote.signature_hex = sign_test_schnorr(vote.signing_hash(), keypair);
            local_node::append_message(datadir, SharechainMessage::SnapshotVote(vote)).unwrap();
        }

        let template = PohwCommitment::new_pohw1(PohwCommitmentParams {
            idena_snapshot_id: snapshot.snapshot_day.to_string(),
            idena_score_root: snapshot.score_root,
            miner_idena_address: miner.idena_address.clone(),
            identity_proof_root: identity_root,
            sharechain_tip: "00".repeat(32),
            sharechain_state_root: Some("00".repeat(32)),
            payout_schedule_root: "00".repeat(32),
            vault_epoch_id: 1,
            frost_vault_key_xonly: test_keypair(40).x_only_public_key().0.to_string(),
        });
        (miner, template)
    }

    fn non_coinbase_transaction(seed: u8) -> BitcoinMiningJobTransaction {
        let tx = unsigned_non_coinbase_transaction(seed, Witness::new());
        BitcoinMiningJobTransaction {
            txid: tx.compute_txid().to_string(),
            data_hex: hex::encode(serialize(&tx)),
        }
    }

    fn witness_non_coinbase_transaction(seed: u8) -> (Transaction, BitcoinMiningJobTransaction) {
        let mut witness = Witness::new();
        witness.push(vec![seed; 32]);
        let tx = unsigned_non_coinbase_transaction(seed, witness);
        let material = BitcoinMiningJobTransaction {
            txid: tx.compute_txid().to_string(),
            data_hex: hex::encode(serialize(&tx)),
        };
        (tx, material)
    }

    fn unsigned_non_coinbase_transaction(seed: u8, witness: Witness) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_slice(&[seed; 32]).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn witness_commitment_script_for(transactions: &[Transaction]) -> String {
        let mut level = Vec::with_capacity(transactions.len() + 1);
        level.push([0u8; 32]);
        for tx in transactions {
            level.push(tx.compute_wtxid().to_byte_array());
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                let mut payload = Vec::with_capacity(64);
                payload.extend_from_slice(&left);
                payload.extend_from_slice(&right);
                next.push(sha256d::Hash::hash(&payload).to_byte_array());
            }
            level = next;
        }
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&level[0]);
        payload.extend_from_slice(&[0u8; 32]);
        let commitment = sha256d::Hash::hash(&payload).to_byte_array();
        format!("6a24aa21a9ed{}", hex::encode(commitment))
    }

    #[test]
    fn rpc_material_builds_header_order_stratum_job() {
        let material = mining_job_material();
        let built = build_stratum_job_from_template(&material, 4).unwrap();
        let job = built.job;

        assert!(job.job_id.starts_with("gbt-840000-"));
        assert_eq!(job.job_id.len(), "gbt-840000-".len() + 16);
        assert_eq!(job.version, "00000020");
        assert_eq!(
            job.prevhash,
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
        assert_eq!(job.nbits, "ffff7f20");
        assert_eq!(job.ntime, "04030201");
        assert_eq!(job.merkle_branches, Vec::<String>::new());
        assert_eq!(job.transaction_data, Vec::<String>::new());
        assert_ne!(job.job_id, PACKAGED_EXAMPLE_JOB_ID);
        job.validate().unwrap();
    }

    #[test]
    fn rpc_job_id_changes_when_template_transactions_change() {
        let first = build_stratum_job_from_template(&mining_job_material(), 4)
            .unwrap()
            .job;
        let mut changed = mining_job_material();
        let transaction = non_coinbase_transaction(7);
        changed.transaction_hashes.push(transaction.txid.clone());
        changed.transactions.push(transaction);
        let second = build_stratum_job_from_template(&changed, 4).unwrap().job;

        assert_ne!(first.job_id, second.job_id);
        assert_eq!(
            first.job_id,
            build_stratum_job_from_template(&mining_job_material(), 4)
                .unwrap()
                .job
                .job_id
        );
    }

    #[test]
    fn pohw_job_coinbase_contains_schedule_vault_and_commitment_outputs() {
        let material = mining_job_material();
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);
        let built =
            build_pohw_stratum_job_from_template(&material, &schedule, &commitment, 4).unwrap();
        let tx = coinbase_tx_from_job(&built.job);
        let output_map = tx
            .output
            .iter()
            .map(|output| (output.value.to_sat(), output.script_pubkey.to_hex_string()))
            .collect::<Vec<_>>();

        assert!(built.note.contains("PoHW payout-aware"));
        assert!(output_map.contains(&(
            20_000,
            "00141111111111111111111111111111111111111111".to_string()
        )));
        assert!(output_map.contains(&(
            30_000,
            vault_script_pubkey_hex(&commitment.frost_vault_key_xonly).unwrap()
        )));
        assert!(output_map.contains(&(0, commitment.op_return_script_pubkey_hex())));
        assert_eq!(
            output_map
                .iter()
                .filter(|(_, script)| !script.starts_with("6a"))
                .map(|(amount, _)| *amount)
                .sum::<u64>(),
            50_000
        );
    }

    #[test]
    fn pohw_job_rejects_commitment_for_wrong_payout_root() {
        let material = mining_job_material();
        let schedule = payout_schedule();
        let mut commitment = pohw_commitment(&schedule);
        commitment.payout_schedule_root = "99".repeat(32);

        let err =
            build_pohw_stratum_job_from_template(&material, &schedule, &commitment, 4).unwrap_err();

        assert!(err.to_string().contains("does not match schedule root"));
    }

    #[test]
    fn pohw_job_rejects_payout_total_that_does_not_match_coinbase_value() {
        let mut material = mining_job_material();
        material.coinbase_value_sats = 49_999;
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);

        let err =
            build_pohw_stratum_job_from_template(&material, &schedule, &commitment, 4).unwrap_err();

        assert!(err
            .to_string()
            .contains("does not match Bitcoin getblocktemplate coinbasevalue"));
    }

    #[test]
    fn dynamic_pohw_jobs_follow_each_template_value_and_persist_exact_evidence() {
        let root = temp_dir("dynamic-payouts");
        let datadir = root.join("sharechain");
        let snapshot_dir = root.join("snapshots");
        let (_miner, commitment_template) =
            append_dynamic_payout_fixture(&datadir, &snapshot_dir, true);

        let first_material = mining_job_material();
        let first = build_dynamic_pohw_stratum_job_from_template(
            &datadir,
            &snapshot_dir,
            "miner-a",
            &commitment_template,
            &first_material,
            4,
            MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS,
        )
        .unwrap();
        let mut second_material = first_material.clone();
        second_material.coinbase_value_sats = 75_000;
        let second = build_dynamic_pohw_stratum_job_from_template(
            &datadir,
            &snapshot_dir,
            "miner-a",
            &commitment_template,
            &second_material,
            4,
            MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS,
        )
        .unwrap();

        let payout_total = |schedule: &PayoutSchedule| {
            schedule
                .direct_outputs
                .iter()
                .map(|output| output.amount_sats)
                .sum::<u64>()
                + schedule.vault_output_sats
        };
        assert_eq!(payout_total(&first.payout_schedule), 50_000);
        assert_eq!(payout_total(&second.payout_schedule), 75_000);
        assert_ne!(
            first.payout_schedule.payout_root,
            second.payout_schedule.payout_root
        );
        assert_ne!(first.built.job.job_id, second.built.job.job_id);
        assert_eq!(
            first.pohw_commitment.payout_schedule_root,
            first.payout_schedule.payout_root
        );
        assert_eq!(
            second.pohw_commitment.payout_schedule_root,
            second.payout_schedule.payout_root
        );

        let candidate = (0u32..100_000)
            .find_map(|nonce| {
                let candidate = build_stratum_block_candidate(
                    &first.built.job,
                    "aabbccdd",
                    "01020304",
                    &first.built.job.ntime,
                    &hex::encode(nonce.to_le_bytes()),
                    4,
                    false,
                )
                .unwrap();
                candidate.meets_block_target.then_some(candidate)
            })
            .expect("easy test target must yield a candidate");
        let evidence = ActivePayoutEvidence {
            snapshot: first.snapshot.clone(),
            payout_schedule: first.payout_schedule.clone(),
            pohw_commitment: first.pohw_commitment.clone(),
            reward_sats: first.built.source_coinbase_value_sats,
        };
        let messages = target_block_payout_messages(&evidence);
        assert!(matches!(
            &messages[0].0,
            SharechainMessage::PayoutSchedule(schedule)
                if schedule.payout_root == first.payout_schedule.payout_root
        ));
        assert!(matches!(
            &messages[1].0,
            SharechainMessage::PohwCommitment(commitment)
                if commitment.payout_schedule_root == first.payout_schedule.payout_root
        ));
        let payout_candidate_dir = root.join("payout-candidates");
        let descriptor_path =
            persist_payout_confirmation_evidence(&payout_candidate_dir, &candidate, &evidence)
                .unwrap();
        assert_eq!(
            persist_payout_confirmation_evidence(&payout_candidate_dir, &candidate, &evidence)
                .unwrap(),
            descriptor_path
        );
        let mut conflicting_evidence = evidence.clone();
        conflicting_evidence.reward_sats += 1;
        assert!(persist_payout_confirmation_evidence(
            &payout_candidate_dir,
            &candidate,
            &conflicting_evidence
        )
        .unwrap_err()
        .to_string()
        .contains("differs from current evidence"));
        let descriptor: Value =
            serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
        assert_eq!(descriptor["block_hash"], candidate.block_hash);
        assert_eq!(descriptor["reward_sats"], 50_000);
        let evidence_dir = payout_candidate_dir.join(format!(
            "evidence-{}",
            candidate.block_hash.to_ascii_lowercase()
        ));
        let persisted_snapshot: Snapshot =
            serde_json::from_slice(&fs::read(evidence_dir.join("snapshot.json")).unwrap()).unwrap();
        let persisted_schedule: PayoutSchedule =
            serde_json::from_slice(&fs::read(evidence_dir.join("payout-schedule.json")).unwrap())
                .unwrap();
        let persisted_commitment: PohwCommitment =
            serde_json::from_slice(&fs::read(evidence_dir.join("pohw-commitment.json")).unwrap())
                .unwrap();
        assert_eq!(persisted_snapshot, first.snapshot);
        assert_eq!(persisted_schedule, first.payout_schedule);
        assert_eq!(persisted_commitment, first.pohw_commitment);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dynamic_pohw_genesis_job_uses_zero_tip_before_the_first_share() {
        let root = temp_dir("dynamic-payout-genesis");
        let datadir = root.join("sharechain");
        let snapshot_dir = root.join("snapshots");
        let (_miner, commitment_template) =
            append_dynamic_payout_fixture(&datadir, &snapshot_dir, false);

        let genesis = build_dynamic_pohw_stratum_job_from_template(
            &datadir,
            &snapshot_dir,
            "miner-a",
            &commitment_template,
            &mining_job_material(),
            4,
            MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS,
        )
        .unwrap();

        assert_eq!(genesis.pohw_commitment.sharechain_tip, "00".repeat(32));
        assert_eq!(
            local_node::replay_state(&datadir)
                .unwrap()
                .summary()
                .stored_share_count,
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dynamic_pohw_snapshot_requires_distinct_identity_voter_quorum() {
        let state = pohw_core::sharechain_state::SharechainReplayState::default();
        let snapshot = Snapshot::build(
            Utc::now().date_naive(),
            1_000,
            "aa".repeat(32),
            "11".repeat(32),
            FORMULA_VERSION,
            Vec::new(),
        );

        let err = validate_dynamic_payout_snapshot(
            &state,
            &snapshot,
            Utc::now().date_naive(),
            MAINNET_HANDOFF_MIN_SNAPSHOT_VOTERS,
        )
        .unwrap_err();

        assert!(err.to_string().contains("distinct identity voters"));
    }

    #[test]
    fn dynamic_pohw_snapshot_rejects_zero_voter_requirement() {
        let state = pohw_core::sharechain_state::SharechainReplayState::default();
        let snapshot = Snapshot::build(
            Utc::now().date_naive(),
            1_000,
            "aa".repeat(32),
            "11".repeat(32),
            FORMULA_VERSION,
            Vec::new(),
        );

        let err = validate_dynamic_payout_snapshot(&state, &snapshot, Utc::now().date_naive(), 0)
            .unwrap_err();

        assert!(err.to_string().contains("at least one snapshot voter"));
    }

    #[test]
    fn generated_coinbase_split_matches_configured_extranonce_sizes() {
        let (coinbase1, coinbase2) =
            coinbase_split_for_extranonces(840_000, 4, None, None).unwrap();
        let coinbase_hex = format!("{}{}{}{}", coinbase1, "aabbccdd", "01020304", coinbase2);
        let coinbase = hex::decode(&coinbase_hex).unwrap();

        assert_eq!(&coinbase[0..4], &2u32.to_le_bytes());
        assert_eq!(coinbase[4], 1);
        assert_eq!(&coinbase[5..37], &[0u8; 32]);
        assert_eq!(&coinbase[37..41], &u32::MAX.to_le_bytes());
        let script_len = usize::from(coinbase[41]);
        let sequence_start = 42 + script_len;
        assert_eq!(
            &coinbase[sequence_start..sequence_start + 4],
            &u32::MAX.to_le_bytes()
        );
        assert_eq!(
            &coinbase[sequence_start + 4..],
            hex::decode("010000000000000000016a00000000").unwrap()
        );
    }

    #[test]
    fn generated_coinbase_includes_exact_required_replay_marker() {
        let (coinbase1, coinbase2) =
            coinbase_split_for_extranonces(840_000, 4, None, Some(POHW_REPLAY_MARKER_SCRIPT_HEX))
                .unwrap();
        let coinbase_hex = format!("{}{}{}{}", coinbase1, "aabbccdd", "01020304", coinbase2);
        let transaction: Transaction = deserialize(&hex::decode(coinbase_hex).unwrap()).unwrap();

        assert!(transaction.output.iter().any(|output| {
            output.value.to_sat() == 0
                && hex::encode(output.script_pubkey.as_bytes()) == POHW_REPLAY_MARKER_SCRIPT_HEX
        }));
    }

    #[test]
    fn generated_coinbase_rejects_replay_marker_substitution() {
        let err = coinbase_split_for_extranonces(840_000, 4, None, Some("5161")).unwrap_err();
        assert!(err.to_string().contains("exact fork-only replay marker"));
    }

    #[test]
    fn merkle_branch_uses_header_order_transaction_hashes() {
        let tx1 = "11".repeat(32);
        let tx2 = "22".repeat(32);
        let tx3 = "33".repeat(32);
        let branch = coinbase_merkle_branches(&[tx1.clone(), tx2.clone(), tx3.clone()]).unwrap();

        let tx1_internal = display_hash_to_header_order_hex(&tx1).unwrap();
        let tx2_internal = display_hash_to_header_order_bytes(&tx2).unwrap();
        let tx3_internal = display_hash_to_header_order_bytes(&tx3).unwrap();
        let mut right_subtree_payload = Vec::new();
        right_subtree_payload.extend_from_slice(&tx2_internal);
        right_subtree_payload.extend_from_slice(&tx3_internal);
        let right_subtree =
            hex::encode(sha256d::Hash::hash(&right_subtree_payload).to_byte_array());

        assert_eq!(branch, vec![tx1_internal, right_subtree]);
    }

    #[test]
    fn block_candidate_builds_complete_coinbase_only_block_hex() {
        let built = build_stratum_job_from_template(&mining_job_material(), 4).unwrap();
        let job = built.job;
        let candidate = build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, false,
        )
        .unwrap();

        assert_eq!(candidate.job_id, job.job_id);
        assert_eq!(candidate.extranonce1, "aabbccdd");
        assert_eq!(candidate.extranonce2, "01020304");
        assert_eq!(candidate.nonce, "05060708");
        assert_eq!(candidate.merkle_branch_count, 0);
        assert_eq!(candidate.block_hex_status, "complete_coinbase_only");
        let expected_block_hex = format!(
            "{}01{}",
            candidate.bitcoin_header_hex, candidate.coinbase_tx_hex
        );
        assert_eq!(
            candidate.block_hex.as_deref(),
            Some(expected_block_hex.as_str())
        );
        assert_eq!(
            candidate.block_target,
            "7fffff".to_string() + &"00".repeat(29)
        );
        assert_eq!(
            candidate.header_merkle_root_hex,
            candidate.bitcoin_header_hex[72..136]
        );
    }

    #[test]
    fn block_candidate_marks_block_hex_incomplete_when_job_has_merkle_branches() {
        let mut job = test_job();
        job.merkle_branches = vec!["11".repeat(32)];
        let candidate = build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, false,
        )
        .unwrap();

        assert_eq!(candidate.merkle_branch_count, 1);
        assert_eq!(candidate.block_hex, None);
        assert_eq!(
            candidate.block_hex_status,
            "incomplete_missing_non_coinbase_transaction_data"
        );
    }

    #[test]
    fn block_candidate_builds_complete_block_hex_with_non_coinbase_transactions() {
        let tx = non_coinbase_transaction(7);
        let mut material = mining_job_material();
        material.transaction_hashes = vec![tx.txid.clone()];
        material.transactions = vec![tx.clone()];
        let built = build_stratum_job_from_template(&material, 4).unwrap();
        let job = built.job;

        let mut candidate = None;
        for nonce in 0u32..100_000 {
            let next = build_stratum_block_candidate(
                &job,
                "aabbccdd",
                "01020304",
                &job.ntime,
                &hex::encode(nonce.to_le_bytes()),
                4,
                false,
            )
            .unwrap();
            if next.meets_block_target {
                candidate = Some(next);
                break;
            }
        }
        let candidate = candidate.expect("target-meeting candidate");

        assert_eq!(candidate.merkle_branch_count, 1);
        assert_eq!(
            candidate.block_hex_status,
            "complete_with_non_coinbase_transactions"
        );
        let block_hex = block_hex_for_stratum_candidate_submission(&candidate).unwrap();
        let block: Block = deserialize(&hex::decode(block_hex).unwrap()).unwrap();
        assert_eq!(block.txdata.len(), 2);
        assert!(block.txdata[0].is_coinbase());
        assert_eq!(block.txdata[1].compute_txid().to_string(), tx.txid);
        assert!(block.check_merkle_root());
    }

    #[test]
    fn block_candidate_builds_complete_block_hex_with_witness_transactions() {
        let (tx, material_tx) = witness_non_coinbase_transaction(9);
        let mut material = mining_job_material();
        material.transaction_hashes = vec![material_tx.txid.clone()];
        material.transactions = vec![material_tx.clone()];
        material.default_witness_commitment =
            Some(witness_commitment_script_for(std::slice::from_ref(&tx)));
        let built = build_stratum_job_from_template(&material, 4).unwrap();
        let job = built.job;
        let coinbase = coinbase_tx_from_job(&job);
        assert_eq!(coinbase.input[0].witness.len(), 1);

        let mut candidate = None;
        for nonce in 0u32..100_000 {
            let next = build_stratum_block_candidate(
                &job,
                "aabbccdd",
                "01020304",
                &job.ntime,
                &hex::encode(nonce.to_le_bytes()),
                4,
                false,
            )
            .unwrap();
            if next.meets_block_target {
                candidate = Some(next);
                break;
            }
        }
        let candidate = candidate.expect("target-meeting candidate");

        assert_eq!(
            candidate.block_hex_status,
            "complete_with_non_coinbase_transactions"
        );
        let block_hex = block_hex_for_stratum_candidate_submission(&candidate).unwrap();
        let block: Block = deserialize(&hex::decode(block_hex).unwrap()).unwrap();
        assert_eq!(block.txdata.len(), 2);
        assert_eq!(block.txdata[1].compute_txid().to_string(), material_tx.txid);
        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());
    }

    #[test]
    fn block_candidate_rejects_witness_transactions_without_commitment() {
        let (_tx, material_tx) = witness_non_coinbase_transaction(10);
        let mut material = mining_job_material();
        material.transaction_hashes = vec![material_tx.txid.clone()];
        material.transactions = vec![material_tx];
        let built = build_stratum_job_from_template(&material, 4).unwrap();

        let err = build_stratum_block_candidate(
            &built.job,
            "aabbccdd",
            "01020304",
            &built.job.ntime,
            "05060708",
            4,
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("witness commitment"));
    }

    #[test]
    fn stratum_job_validation_rejects_tampered_transaction_data() {
        let tx = non_coinbase_transaction(11);
        let replacement = non_coinbase_transaction(12);
        let mut material = mining_job_material();
        material.transaction_hashes = vec![tx.txid.clone()];
        material.transactions = vec![tx];
        let mut job = build_stratum_job_from_template(&material, 4).unwrap().job;
        job.transaction_data = vec![replacement.data_hex];

        let err = job.validate().unwrap_err();

        assert!(err.to_string().contains("transaction_data does not match"));
    }

    #[test]
    fn target_meeting_block_candidate_is_persisted_without_overwrite() {
        let dir = temp_dir("block-candidate-persist");
        let candidate = target_meeting_candidate();

        let path = persist_target_block_candidate(Some(&dir), &candidate)
            .unwrap()
            .expect("candidate file");

        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(format!("block-{}.json", candidate.block_hash).as_str())
        );
        let parsed: StratumBlockCandidate =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed, candidate);
        assert_eq!(
            persist_target_block_candidate(Some(&dir), &candidate).unwrap(),
            Some(path.clone())
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn block_candidate_dir_rejects_unsafe_symlink_ancestor() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("block-candidate-symlink-root");
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        symlink(&real, &link).unwrap();

        let err = ensure_block_candidate_dir(&link.join("candidates")).unwrap_err();

        assert!(
            err.to_string().contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn block_candidate_persistence_skips_non_target_share() {
        let dir = temp_dir("block-candidate-non-target");
        let mut job = test_job();
        job.nbits = "00000101".to_string();
        let candidate = build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, false,
        )
        .unwrap();

        assert!(!candidate.meets_block_target);
        assert_eq!(
            persist_target_block_candidate(Some(&dir), &candidate).unwrap(),
            None
        );
        assert!(!dir.exists());
    }

    #[test]
    fn block_candidate_rejects_wrong_extranonce2_size() {
        let built = build_stratum_job_from_template(&mining_job_material(), 4).unwrap();

        let err = build_stratum_block_candidate(
            &built.job,
            "aabbccdd",
            "010203",
            &built.job.ntime,
            "05060708",
            4,
            false,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("extranonce2 must be exactly 4 bytes"));
    }

    #[test]
    fn block_candidate_require_block_target_rejects_above_target() {
        let mut job = test_job();
        job.nbits = "00000101".to_string();

        let err = build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not meet block target"));
    }

    #[test]
    fn block_candidate_rejects_invalid_coinbase_transaction_bytes() {
        let mut job = test_job();
        job.coinbase1 = "abcd".to_string();
        job.coinbase2 = "ef".to_string();

        let err = build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, false,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("coinbase bytes are not a valid Bitcoin transaction"));
    }

    #[test]
    fn stratum_job_builds_expected_80_byte_header() {
        let job = test_job();
        job.validate().unwrap();
        let submit = SubmitWork {
            worker_name: "worker.1".to_string(),
            job_id: "job-1".to_string(),
            extranonce2: "00000001".to_string(),
            ntime: job.ntime.clone(),
            nonce: "01020304".to_string(),
        };

        let header = build_header_hex_from_submit(&job, &submit, "aabbccdd").unwrap();

        assert_eq!(header.len(), 160);
        assert!(header.starts_with(&format!("{}{}", job.version, job.prevhash)));
        assert!(header.ends_with(&format!("{}{}01020304", job.ntime, job.nbits)));
    }

    #[test]
    fn stratum_submit_rejects_mutable_ntime() {
        let job = test_job();
        let submit = SubmitWork {
            worker_name: "worker.1".to_string(),
            job_id: "job-1".to_string(),
            extranonce2: "00000001".to_string(),
            ntime: "05030201".to_string(),
            nonce: "01020304".to_string(),
        };

        let err = build_header_hex_from_submit(&job, &submit, "aabbccdd").unwrap_err();

        assert!(err.to_string().contains("mutable time is not supported"));
    }

    #[test]
    fn packaged_example_job_requires_explicit_dry_run_flag() {
        let mut job = test_job();
        job.job_id = PACKAGED_EXAMPLE_JOB_ID.to_string();

        assert!(job
            .validate_example_policy(false)
            .unwrap_err()
            .to_string()
            .contains("refusing packaged example Stratum job"));
        assert!(job.validate_example_policy(true).is_ok());
    }

    #[test]
    fn submit_parser_rejects_wrong_extranonce2_size_and_version_rolling() {
        let request = json!({
            "id": 1,
            "method": "mining.submit",
            "params": ["worker", "job-1", "00", "5f5e1001", "01020304"]
        });
        assert!(parse_submit(&request, 4)
            .unwrap_err()
            .to_string()
            .contains("extranonce2"));

        let request = json!({
            "id": 1,
            "method": "mining.submit",
            "params": ["worker", "job-1", "00000000", "5f5e1001", "01020304", "20000000"]
        });
        assert!(parse_submit(&request, 4)
            .unwrap_err()
            .to_string()
            .contains("version rolling"));
    }

    #[test]
    fn target_check_rejects_above_target_work() {
        let target = "00".repeat(31) + "01";
        assert!(ensure_hash_meets_target(&"ff".repeat(32), &target)
            .unwrap_err()
            .to_string()
            .contains("does not meet"));
        assert!(ensure_hash_meets_target(&"00".repeat(32), &target).is_ok());
    }

    #[test]
    fn template_created_at_is_deterministic_for_same_header_prefix() {
        let job = test_job();
        let first = SubmitWork {
            worker_name: "worker.1".to_string(),
            job_id: "job-1".to_string(),
            extranonce2: "00000001".to_string(),
            ntime: job.ntime.clone(),
            nonce: "01020304".to_string(),
        };
        let second = SubmitWork {
            nonce: "05060708".to_string(),
            ..first.clone()
        };

        let first_header = build_header_hex_from_submit(&job, &first, "aabbccdd").unwrap();
        let second_header = build_header_hex_from_submit(&job, &second, "aabbccdd").unwrap();

        assert_eq!(&first_header[..152], &second_header[..152]);
        assert_ne!(&first_header[152..], &second_header[152..]);
        assert_eq!(
            template_created_at_unix_from_header_hex(&first_header).unwrap(),
            template_created_at_unix_from_header_hex(&second_header).unwrap()
        );
    }

    #[test]
    fn default_share_target_matches_bitcoin_stratum_diff_one() {
        assert_eq!(
            default_share_target_hex(),
            "00000000ffff0000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn share_target_must_be_explicit_when_stratum_difficulty_changes() {
        assert_eq!(
            resolve_share_target(None, 1.0).unwrap(),
            default_share_target_hex()
        );
        assert!(resolve_share_target(None, 32.0)
            .unwrap_err()
            .to_string()
            .contains("--share-target"));
        assert_eq!(
            resolve_share_target(Some(&"01".repeat(32)), 32.0).unwrap(),
            "01".repeat(32)
        );
    }

    #[test]
    fn share_target_must_not_be_stricter_than_job_block_target() {
        let easy_fork_target = block_target_hex_from_job_nbits("ffff7f20").unwrap();
        let err = ensure_share_target_not_stricter_than_block_target(
            &default_share_target_hex(),
            &easy_fork_target,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("stricter than the job block target"));

        assert!(ensure_share_target_not_stricter_than_block_target(
            &easy_fork_target,
            &easy_fork_target
        )
        .is_ok());
    }

    #[test]
    fn easy_fork_target_maps_to_positive_fractional_stratum_difficulty() {
        let easy_fork_target = block_target_hex_from_job_nbits("ffff7f20").unwrap();
        let difficulty = difficulty_float_from_target_hex(&easy_fork_target).unwrap();
        assert!(difficulty > 0.0);
        assert!(difficulty < 1.0);
    }

    #[test]
    fn verified_fork_rpc_derives_share_policy_from_block_target() {
        let easy_fork_target = block_target_hex_from_job_nbits("ffff7f20").unwrap();
        let (share_target, difficulty) =
            resolve_share_policy(None, DEFAULT_STRATUM_DIFFICULTY, &easy_fork_target, true)
                .unwrap();
        assert_eq!(share_target, easy_fork_target);
        assert!(difficulty > 0.0);
        assert!(difficulty < 1.0);

        let explicit = "01".repeat(32);
        let (share_target, difficulty) =
            resolve_share_policy(Some(&explicit), 32.0, &easy_fork_target, true).unwrap();
        assert_eq!(share_target, explicit);
        assert_eq!(difficulty, 32.0);
    }

    #[test]
    fn submit_rejection_logs_only_a_fixed_stage() {
        let error =
            submit_stage::<(), _>(Err(anyhow!("sensitive runtime detail")), "target").unwrap_err();

        assert_eq!(submit_rejection_stage(&error), "target");
        assert!(!submit_rejection_stage(&error).contains("sensitive"));
        assert_eq!(
            submit_rejection_stage(&anyhow!("unmarked failure")),
            "unclassified"
        );
    }

    #[test]
    fn non_loopback_bind_requires_explicit_override() {
        let bind_addr: SocketAddr = "198.51.100.10:3333".parse().unwrap();
        assert!(validate_bind_addr(bind_addr, false)
            .unwrap_err()
            .to_string()
            .contains("not loopback"));
        assert!(validate_bind_addr(bind_addr, true).is_ok());
    }

    #[test]
    fn stratum_password_validation_requires_strength_for_non_loopback() {
        assert!(validate_stratum_password("short".to_string(), true)
            .unwrap_err()
            .to_string()
            .contains("at least"));
        assert!(validate_stratum_password("0123456789abcdef".to_string(), true).is_ok());
        assert!(validate_stratum_password("abc\rdef".to_string(), false)
            .unwrap_err()
            .to_string()
            .contains("control"));
    }

    #[test]
    fn stratum_password_file_rejects_large_file_before_reading() {
        let dir =
            std::env::temp_dir().join(format!("pohw-stratum-password-{}", random_nonce_hex()));
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let password = dir.join("stratum.password");
        fs::File::create(&password)
            .unwrap()
            .set_len(MAX_STRATUM_PASSWORD_FILE_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = read_optional_stratum_password(Some(&password), false).unwrap_err();

        assert!(
            format!("{err:#}").contains("too large"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authorize_checks_configured_password_without_accepting_missing_param() {
        let request = json!({
            "id": 1,
            "method": "mining.authorize",
            "params": ["worker.1", "secret-password"]
        });
        assert!(authorize_password_matches(&request, Some("secret-password")).unwrap());
        assert!(!authorize_password_matches(&request, Some("wrong-password")).unwrap());

        let missing = json!({
            "id": 1,
            "method": "mining.authorize",
            "params": ["worker.1"]
        });
        assert!(authorize_password_matches(&missing, Some("secret-password")).is_err());
        assert!(authorize_password_matches(&missing, None).unwrap());

        let malformed = json!({
            "id": 1,
            "method": "mining.authorize",
            "params": []
        });
        assert!(authorize_password_matches(&malformed, None).is_err());
    }

    #[test]
    fn connection_limiter_caps_total_and_per_ip_and_releases_on_drop() {
        let limiter = ConnectionLimiter::new(2, 1);
        let first_ip: IpAddr = "198.51.100.20".parse().unwrap();
        let second_ip: IpAddr = "198.51.100.21".parse().unwrap();
        let first = limiter.try_acquire(first_ip).unwrap();
        assert!(limiter.try_acquire(first_ip).is_none());
        let second = limiter.try_acquire(second_ip).unwrap();
        let third_ip: IpAddr = "198.51.100.22".parse().unwrap();
        assert!(limiter.try_acquire(third_ip).is_none());
        drop(first);
        assert!(limiter.try_acquire(third_ip).is_some());
        drop(second);
    }

    #[tokio::test]
    async fn stratum_line_read_has_a_completion_deadline() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let error = read_stratum_line_with_timeout(
            &mut reader,
            DEFAULT_MAX_LINE_BYTES,
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("read timed out"));
    }

    #[tokio::test]
    async fn stratum_response_write_times_out_for_a_slow_reader() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let response = Value::String("x".repeat(1024));
        let error = send_json_line_with_timeout(&mut writer, &response, Duration::from_millis(10))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("write timed out"));
    }
}
