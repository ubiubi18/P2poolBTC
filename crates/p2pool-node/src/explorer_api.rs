use crate::bitcoin_explorer_index::BitcoinExplorerIndexClient;
use crate::fork_chain::{
    ForkAddressSummary, ForkAddressTransactionPage, ForkBlockPage, ForkBlockSummary,
    ForkChainClient, ForkChainStatus, ForkTransactionDetail, ForkTransactionPage, ForkUtxoPage,
};
use crate::local_node;
use anyhow::{bail, Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use pohw_core::sharechain_state::{SharechainReplaySummary, SharechainShareSummary};
use pohw_core::snapshot::Snapshot;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;
use tokio::time::{timeout, Duration};

pub(crate) const EXPLORER_API_VERSION: &str = "pohw-explorer-v1";
pub(crate) const DEFAULT_PAGE_LIMIT: usize = 25;
pub(crate) const MAX_PAGE_LIMIT: usize = 100;
const MAX_CONCURRENT_REPLAYS: usize = 2;
const REPLAY_QUEUE_TIMEOUT_SECONDS: u64 = 2;
static EXPLORER_REPLAY_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_REPLAYS)));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerOverview {
    pub api_version: String,
    pub generated_at_unix: i64,
    pub fork: ExplorerForkOverview,
    pub bitcoin_history: ExplorerBitcoinIndexOverview,
    pub sharechain: ExplorerSharechainOverview,
    pub idena: ExplorerIdenaOverview,
    pub limitations: Vec<String>,
    pub safety_boundaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinIndexOverview {
    pub state: String,
    pub backend: String,
    pub indexed_tip_height: Option<u64>,
    pub inherited_tip_height: Option<u64>,
    pub inherited_history_ready: bool,
    pub host_only: bool,
    pub participant_index_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinObject {
    pub scope: String,
    pub fork_relation: String,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinTransactionPage {
    pub scope: String,
    pub address: String,
    pub total_in_page: usize,
    pub items: Vec<ExplorerBitcoinObject>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinBlockPage {
    pub scope: String,
    pub items: Vec<ExplorerBitcoinObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinBlockTransactionPage {
    pub scope: String,
    pub block_hash: String,
    pub start_index: usize,
    pub total_in_page: usize,
    pub items: Vec<ExplorerBitcoinObject>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerBitcoinOutspendPage {
    pub scope: String,
    pub txid: String,
    pub items: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerForkOverview {
    pub state: String,
    pub status: Option<ExplorerForkStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerForkStatus {
    pub protocol_version: u16,
    pub chain_name: String,
    pub activation_id: String,
    pub inherited_tip_height: u64,
    pub inherited_tip_hash: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub cumulative_work: String,
    pub stored_block_count: usize,
    pub active_fork_block_count: usize,
    pub post_fork_pow_limit_bits: String,
    pub target_spacing_seconds: u64,
    pub difficulty_algorithm: String,
    pub difficulty_phase: String,
    pub bootstrap_handoff_hashrate_hps: u64,
    pub estimated_hashrate_hps: String,
    pub blocks_until_bitcoin_retarget: Option<u64>,
    pub transaction_consensus: String,
}

impl From<ForkChainStatus> for ExplorerForkStatus {
    fn from(status: ForkChainStatus) -> Self {
        Self {
            protocol_version: status.protocol_version,
            chain_name: status.chain_name,
            activation_id: status.activation_id,
            inherited_tip_height: status.inherited_tip_height,
            inherited_tip_hash: status.inherited_tip_hash,
            tip_height: status.tip_height,
            tip_hash: status.tip_hash,
            cumulative_work: status.cumulative_work,
            stored_block_count: status.stored_block_count,
            active_fork_block_count: status.active_fork_block_count,
            post_fork_pow_limit_bits: status.post_fork_pow_limit_bits,
            target_spacing_seconds: status.target_spacing_seconds,
            difficulty_algorithm: status.difficulty_algorithm,
            difficulty_phase: status.difficulty_phase,
            bootstrap_handoff_hashrate_hps: status.bootstrap_handoff_hashrate_hps,
            estimated_hashrate_hps: status.estimated_hashrate_hps,
            blocks_until_bitcoin_retarget: status.blocks_until_bitcoin_retarget,
            transaction_consensus: status.transaction_consensus,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerSharechainOverview {
    pub applied_message_count: usize,
    pub registered_miner_count: usize,
    pub bitcoin_work_template_count: usize,
    pub stored_share_count: usize,
    pub active_share_count: usize,
    pub inactive_share_count: usize,
    pub active_share_score_total: String,
    pub best_share_tip: Option<String>,
    pub best_share_height: Option<u64>,
    pub snapshot_vote_root_count: usize,
    pub payout_schedule_count: usize,
    pub pending_withdrawal_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerIdenaOverview {
    pub state: String,
    pub snapshot_day: Option<String>,
    pub snapshot_height: Option<u64>,
    pub score_root: Option<String>,
    pub identity_root: Option<String>,
    pub formula_version: Option<u16>,
    pub identity_count: usize,
    pub eligible_identity_count: usize,
    pub validation_score_total: String,
    pub proposer_score_total: String,
    pub committee_score_total: String,
    pub ignored_invitation_score_total: String,
    pub reward_source_coverage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerForkBlockPage {
    pub state: String,
    pub tip_height: Option<u64>,
    pub total: usize,
    pub items: Vec<ForkBlockSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExplorerSharePage {
    pub total: usize,
    pub items: Vec<SharechainShareSummary>,
    pub next_cursor: Option<String>,
}

pub(crate) async fn build_overview(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    fork_client: Option<&ForkChainClient>,
    bitcoin_index_client: Option<&BitcoinExplorerIndexClient>,
) -> Result<ExplorerOverview> {
    let replay_datadir = datadir.to_path_buf();
    let replay_snapshot_dir = snapshot_dir.map(Path::to_path_buf);
    let (summary, best_share_height, idena) = run_replay_work(move || {
        let replay = local_node::replay_state_with_confirmed_payouts(
            &replay_datadir,
            replay_snapshot_dir.as_deref(),
        )?;
        let summary = replay.summary();
        let best_share_height = replay.best_share_height();
        let idena = match replay_snapshot_dir.as_deref() {
            Some(snapshot_dir) => {
                let status = local_node::latest_verified_snapshot(snapshot_dir)?;
                status
                    .latest
                    .as_ref()
                    .map(|latest| idena_overview(&latest.snapshot))
                    .transpose()?
                    .unwrap_or_else(|| unavailable_idena_overview("unavailable"))
            }
            None => unavailable_idena_overview("not_configured"),
        };
        Ok((summary, best_share_height, idena))
    })
    .await?;
    let fork = match fork_client {
        Some(client) => match client.status().await {
            Ok(status) => ExplorerForkOverview {
                state: "connected".to_string(),
                status: Some(status.into()),
            },
            Err(_) => ExplorerForkOverview {
                state: "unavailable".to_string(),
                status: None,
            },
        },
        None => ExplorerForkOverview {
            state: "not_configured".to_string(),
            status: None,
        },
    };
    let inherited_tip_height = fork
        .status
        .as_ref()
        .map(|status| status.inherited_tip_height);
    let bitcoin_history = bitcoin_index_overview(bitcoin_index_client, inherited_tip_height).await;
    let mut limitations = vec!["Idena reward-source coverage is reported from the latest verified snapshot and may be incomplete".to_string()];
    if bitcoin_index_client.is_some_and(BitcoinExplorerIndexClient::is_remote) {
        limitations.push("Bitcoin history uses an external HTTPS Esplora provider; searched hashes and addresses are visible to that provider and its availability limits apply".to_string());
    }
    Ok(ExplorerOverview {
        api_version: EXPLORER_API_VERSION.to_string(),
        generated_at_unix: current_unix_timestamp()?,
        fork,
        bitcoin_history,
        sharechain: sharechain_overview(&summary, best_share_height),
        idena,
        limitations,
        safety_boundaries: vec![
            "Experiment 0 consensus admits coinbase transactions only; the explorer fully decodes accepted fork transactions without enabling inherited-value spending".to_string(),
            "The optional host Bitcoin history index is not required on participant nodes".to_string(),
        ],
    })
}

pub(crate) async fn fork_block_page(
    fork_client: Option<&ForkChainClient>,
    cursor: Option<String>,
    limit: usize,
) -> Result<ExplorerForkBlockPage> {
    validate_page_limit(limit)?;
    let Some(client) = fork_client else {
        return Ok(ExplorerForkBlockPage {
            state: "not_configured".to_string(),
            tip_height: None,
            total: 0,
            items: Vec::new(),
            next_cursor: None,
        });
    };
    let limit = u16::try_from(limit).context("explorer block page limit exceeds u16")?;
    let ForkBlockPage {
        tip_height,
        total,
        items,
        next_cursor,
    } = client.block_page(cursor, limit).await?;
    Ok(ExplorerForkBlockPage {
        state: "connected".to_string(),
        tip_height: Some(tip_height),
        total,
        items,
        next_cursor,
    })
}

pub(crate) async fn fork_block_summary(
    fork_client: Option<&ForkChainClient>,
    block_hash: &str,
) -> Result<Option<ForkBlockSummary>> {
    validate_hash(block_hash, "fork block hash")?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client.block_summary(block_hash.to_ascii_lowercase()).await
}

pub(crate) async fn fork_block_at_height(
    fork_client: Option<&ForkChainClient>,
    height: u64,
) -> Result<Option<ForkBlockSummary>> {
    let Some(client) = fork_client else {
        return Ok(None);
    };
    let Some(block_hash) = client.active_block_hash(height).await? else {
        return Ok(None);
    };
    client.block_summary(block_hash).await
}

pub(crate) async fn fork_block_transactions(
    fork_client: Option<&ForkChainClient>,
    block_hash: &str,
    cursor: usize,
    limit: usize,
) -> Result<Option<ForkTransactionPage>> {
    validate_hash(block_hash, "fork block hash")?;
    validate_numeric_page(cursor, limit)?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client
        .block_transactions(
            block_hash.to_ascii_lowercase(),
            cursor,
            u16::try_from(limit).context("fork transaction page limit exceeds u16")?,
        )
        .await
}

pub(crate) async fn fork_transaction_detail(
    fork_client: Option<&ForkChainClient>,
    txid: &str,
) -> Result<Option<ForkTransactionDetail>> {
    validate_hash(txid, "fork transaction id")?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client.transaction_detail(txid.to_ascii_lowercase()).await
}

pub(crate) async fn fork_address_summary(
    fork_client: Option<&ForkChainClient>,
    address: &str,
) -> Result<Option<ForkAddressSummary>> {
    let address = validate_bitcoin_address(address)?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client.address_summary(address).await.map(Some)
}

pub(crate) async fn fork_address_transactions(
    fork_client: Option<&ForkChainClient>,
    address: &str,
    cursor: usize,
    limit: usize,
) -> Result<Option<ForkAddressTransactionPage>> {
    validate_numeric_page(cursor, limit)?;
    let address = validate_bitcoin_address(address)?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client
        .address_transactions(
            address,
            cursor,
            u16::try_from(limit).context("fork address transaction page limit exceeds u16")?,
        )
        .await
        .map(Some)
}

pub(crate) async fn fork_address_utxos(
    fork_client: Option<&ForkChainClient>,
    address: &str,
    cursor: usize,
    limit: usize,
) -> Result<Option<ForkUtxoPage>> {
    validate_numeric_page(cursor, limit)?;
    let address = validate_bitcoin_address(address)?;
    let Some(client) = fork_client else {
        return Ok(None);
    };
    client
        .address_utxos(
            address,
            cursor,
            u16::try_from(limit).context("fork address UTXO page limit exceeds u16")?,
        )
        .await
        .map(Some)
}

pub(crate) async fn indexed_bitcoin_transaction(
    client: Option<&BitcoinExplorerIndexClient>,
    txid: &str,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinObject>> {
    validate_hash(txid, "Bitcoin transaction id")?;
    let Some(client) = client else {
        return Ok(None);
    };
    Ok(client
        .transaction(txid)
        .await?
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height)))
}

pub(crate) async fn indexed_bitcoin_block(
    client: Option<&BitcoinExplorerIndexClient>,
    block_hash: &str,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinObject>> {
    validate_hash(block_hash, "Bitcoin block hash")?;
    let Some(client) = client else {
        return Ok(None);
    };
    Ok(client
        .block(block_hash)
        .await?
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height)))
}

pub(crate) async fn indexed_bitcoin_block_transactions(
    client: Option<&BitcoinExplorerIndexClient>,
    block_hash: &str,
    start_index: usize,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinBlockTransactionPage>> {
    validate_hash(block_hash, "Bitcoin block hash")?;
    if start_index > 10_000_000 {
        bail!("Bitcoin block transaction cursor exceeds the supported range");
    }
    let Some(client) = client else {
        return Ok(None);
    };
    let Some(data) = client.block_transactions(block_hash, start_index).await? else {
        return Ok(None);
    };
    let raw_items = data
        .as_array()
        .context("Bitcoin index block transactions response is not an array")?;
    let items = raw_items
        .iter()
        .cloned()
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height))
        .collect::<Vec<_>>();
    let next_cursor = (raw_items.len() == DEFAULT_PAGE_LIMIT)
        .then(|| start_index.checked_add(raw_items.len()))
        .flatten();
    Ok(Some(ExplorerBitcoinBlockTransactionPage {
        scope: "bitcoin_mainnet_history".to_string(),
        block_hash: block_hash.to_ascii_lowercase(),
        start_index,
        total_in_page: items.len(),
        items,
        next_cursor,
    }))
}

pub(crate) async fn indexed_bitcoin_transaction_outspends(
    client: Option<&BitcoinExplorerIndexClient>,
    txid: &str,
) -> Result<Option<ExplorerBitcoinOutspendPage>> {
    validate_hash(txid, "Bitcoin transaction id")?;
    let Some(client) = client else {
        return Ok(None);
    };
    let Some(data) = client.transaction_outspends(txid).await? else {
        return Ok(None);
    };
    let items = data
        .as_array()
        .context("Bitcoin index outspends response is not an array")?
        .to_vec();
    Ok(Some(ExplorerBitcoinOutspendPage {
        scope: "bitcoin_mainnet_history".to_string(),
        txid: txid.to_ascii_lowercase(),
        items,
    }))
}

pub(crate) async fn indexed_bitcoin_blocks(
    client: Option<&BitcoinExplorerIndexClient>,
    start_height: Option<u64>,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinBlockPage>> {
    let Some(client) = client else {
        return Ok(None);
    };
    let Some(data) = client.blocks(start_height).await? else {
        return Ok(None);
    };
    let items = data
        .as_array()
        .context("Bitcoin index block page is not an array")?
        .iter()
        .cloned()
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height))
        .collect();
    Ok(Some(ExplorerBitcoinBlockPage {
        scope: "bitcoin_mainnet_history".to_string(),
        items,
    }))
}

pub(crate) async fn indexed_bitcoin_block_at_height(
    client: Option<&BitcoinExplorerIndexClient>,
    height: u64,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinObject>> {
    let Some(client) = client else {
        return Ok(None);
    };
    Ok(client
        .block_at_height(height)
        .await?
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height)))
}

pub(crate) async fn indexed_bitcoin_address(
    client: Option<&BitcoinExplorerIndexClient>,
    address: &str,
) -> Result<Option<ExplorerBitcoinObject>> {
    let address = validate_bitcoin_address(address)?;
    let Some(client) = client else {
        return Ok(None);
    };
    Ok(client
        .address(&address)
        .await?
        .map(|data| ExplorerBitcoinObject {
            scope: "bitcoin_mainnet_history".to_string(),
            fork_relation: "current_mainnet_aggregate_not_fork_balance".to_string(),
            data,
        }))
}

pub(crate) async fn indexed_bitcoin_address_transactions(
    client: Option<&BitcoinExplorerIndexClient>,
    address: &str,
    cursor: Option<&str>,
    inherited_tip_height: Option<u64>,
) -> Result<Option<ExplorerBitcoinTransactionPage>> {
    let address = validate_bitcoin_address(address)?;
    if let Some(cursor) = cursor {
        validate_hash(cursor, "Bitcoin address-history cursor")?;
    }
    let Some(client) = client else {
        return Ok(None);
    };
    let Some(data) = client.address_transactions(&address, cursor).await? else {
        return Ok(None);
    };
    let raw_items = data
        .as_array()
        .context("Bitcoin index address history is not an array")?;
    let items = raw_items
        .iter()
        .cloned()
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height))
        .collect::<Vec<_>>();
    let next_cursor = (raw_items.len() == DEFAULT_PAGE_LIMIT)
        .then(|| {
            raw_items
                .last()
                .and_then(|value| value.get("txid"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .flatten();
    Ok(Some(ExplorerBitcoinTransactionPage {
        scope: "bitcoin_mainnet_history".to_string(),
        address,
        total_in_page: items.len(),
        items,
        next_cursor,
    }))
}

pub(crate) async fn indexed_bitcoin_address_utxos(
    client: Option<&BitcoinExplorerIndexClient>,
    address: &str,
    inherited_tip_height: Option<u64>,
) -> Result<Option<Vec<ExplorerBitcoinObject>>> {
    let address = validate_bitcoin_address(address)?;
    let Some(client) = client else {
        return Ok(None);
    };
    let Some(data) = client.address_utxos(&address).await? else {
        return Ok(None);
    };
    let items = data
        .as_array()
        .context("Bitcoin index address UTXO response is not an array")?
        .iter()
        .cloned()
        .map(|data| bitcoin_object("bitcoin_mainnet_history", data, inherited_tip_height))
        .collect();
    Ok(Some(items))
}

pub(crate) async fn share_page(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    cursor: Option<&str>,
    limit: usize,
) -> Result<ExplorerSharePage> {
    validate_page_limit(limit)?;
    if let Some(cursor) = cursor {
        validate_hash(cursor, "share cursor")?;
    }
    let datadir = datadir.to_path_buf();
    let snapshot_dir = snapshot_dir.map(Path::to_path_buf);
    let cursor = cursor.map(str::to_string);
    run_replay_work(move || {
        let replay =
            local_node::replay_state_with_confirmed_payouts(&datadir, snapshot_dir.as_deref())?;
        paginate_shares(replay.share_summaries(), cursor.as_deref(), limit)
    })
    .await
}

pub(crate) async fn share_summary(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    share_hash: &str,
) -> Result<Option<SharechainShareSummary>> {
    validate_hash(share_hash, "share hash")?;
    let datadir = datadir.to_path_buf();
    let snapshot_dir = snapshot_dir.map(Path::to_path_buf);
    let share_hash = share_hash.to_string();
    run_replay_work(move || {
        Ok(
            local_node::replay_state_with_confirmed_payouts(&datadir, snapshot_dir.as_deref())?
                .share_summary(&share_hash),
        )
    })
    .await
}

async fn run_replay_work<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    run_replay_work_with_slots(Arc::clone(&EXPLORER_REPLAY_SLOTS), work).await
}

async fn run_replay_work_with_slots<T, F>(slots: Arc<Semaphore>, work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let permit = timeout(
        Duration::from_secs(REPLAY_QUEUE_TIMEOUT_SECONDS),
        slots.acquire_owned(),
    )
    .await
    .context("explorer replay queue is saturated")?
    .context("explorer replay limiter is closed")?;
    spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .context("explorer replay worker failed")?
}

pub(crate) fn validate_hash(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be 32 bytes encoded as hexadecimal");
    }
    Ok(())
}

pub(crate) fn validate_page_limit(limit: usize) -> Result<()> {
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        bail!("explorer page limit must be between 1 and {MAX_PAGE_LIMIT}");
    }
    Ok(())
}

pub(crate) fn validate_numeric_page(cursor: usize, limit: usize) -> Result<()> {
    validate_page_limit(limit)?;
    if cursor > 10_000_000 {
        bail!("explorer cursor exceeds the supported range");
    }
    Ok(())
}

pub(crate) fn validate_bitcoin_address(raw: &str) -> Result<String> {
    if raw.trim() != raw || raw.len() > 128 {
        bail!("Bitcoin address is malformed");
    }
    Address::<NetworkUnchecked>::from_str(raw)
        .context("invalid Bitcoin address")?
        .require_network(Network::Bitcoin)
        .context("Bitcoin address is not for mainnet")
        .map(|address| address.to_string())
}

async fn bitcoin_index_overview(
    client: Option<&BitcoinExplorerIndexClient>,
    inherited_tip_height: Option<u64>,
) -> ExplorerBitcoinIndexOverview {
    let Some(client) = client else {
        return ExplorerBitcoinIndexOverview {
            state: "not_configured".to_string(),
            backend: "not_configured".to_string(),
            indexed_tip_height: None,
            inherited_tip_height,
            inherited_history_ready: false,
            host_only: true,
            participant_index_required: false,
        };
    };
    match client.tip_height().await {
        Ok(indexed_tip_height) => {
            let inherited_history_ready =
                inherited_tip_height.is_some_and(|height| indexed_tip_height >= height);
            ExplorerBitcoinIndexOverview {
                state: if inherited_history_ready {
                    "ready".to_string()
                } else {
                    "syncing".to_string()
                },
                backend: client.backend_label().to_string(),
                indexed_tip_height: Some(indexed_tip_height),
                inherited_tip_height,
                inherited_history_ready,
                host_only: true,
                participant_index_required: false,
            }
        }
        Err(_) => ExplorerBitcoinIndexOverview {
            state: "unavailable".to_string(),
            backend: client.backend_label().to_string(),
            indexed_tip_height: None,
            inherited_tip_height,
            inherited_history_ready: false,
            host_only: true,
            participant_index_required: false,
        },
    }
}

fn bitcoin_object(
    scope: &str,
    data: Value,
    inherited_tip_height: Option<u64>,
) -> ExplorerBitcoinObject {
    let object_height = data
        .get("height")
        .and_then(Value::as_u64)
        .or_else(|| data.get("block_height").and_then(Value::as_u64))
        .or_else(|| {
            data.get("status")
                .and_then(|status| status.get("block_height"))
                .and_then(Value::as_u64)
        });
    let fork_relation = match (object_height, inherited_tip_height) {
        (Some(height), Some(inherited)) if height <= inherited => "inherited_history",
        (Some(_), Some(_)) => "bitcoin_mainnet_after_fork",
        (None, Some(_)) => "bitcoin_mainnet_unconfirmed",
        _ => "fork_point_unavailable",
    };
    ExplorerBitcoinObject {
        scope: scope.to_string(),
        fork_relation: fork_relation.to_string(),
        data,
    }
}

fn paginate_shares(
    shares: Vec<SharechainShareSummary>,
    cursor: Option<&str>,
    limit: usize,
) -> Result<ExplorerSharePage> {
    let start = match cursor {
        Some(cursor) => {
            validate_hash(cursor, "share cursor")?;
            shares
                .iter()
                .position(|share| share.share_hash.eq_ignore_ascii_case(cursor))
                .map(|position| position + 1)
                .context("share cursor is not present in local replay")?
        }
        None => 0,
    };
    let end = start.saturating_add(limit).min(shares.len());
    let items = shares[start..end].to_vec();
    let next_cursor = (end < shares.len())
        .then(|| items.last().map(|share| share.share_hash.clone()))
        .flatten();
    Ok(ExplorerSharePage {
        total: shares.len(),
        items,
        next_cursor,
    })
}

fn sharechain_overview(
    summary: &SharechainReplaySummary,
    best_share_height: Option<u64>,
) -> ExplorerSharechainOverview {
    ExplorerSharechainOverview {
        applied_message_count: summary.applied_message_count,
        registered_miner_count: summary.registered_miner_count,
        bitcoin_work_template_count: summary.bitcoin_work_template_count,
        stored_share_count: summary.stored_share_count,
        active_share_count: summary.active_share_count,
        inactive_share_count: summary.inactive_share_count,
        active_share_score_total: summary.active_share_score_total.to_string(),
        best_share_tip: summary.best_share_tip.clone(),
        best_share_height,
        snapshot_vote_root_count: summary.snapshot_vote_root_count,
        payout_schedule_count: summary.proposed_payout_schedule_count,
        pending_withdrawal_count: summary.pending_withdrawal_count,
    }
}

fn idena_overview(snapshot: &Snapshot) -> Result<ExplorerIdenaOverview> {
    let mut eligible_identity_count = 0usize;
    let mut validation_score_total = 0u128;
    let mut proposer_score_total = 0u128;
    let mut committee_score_total = 0u128;
    let mut ignored_invitation_score_total = 0u128;
    for leaf in snapshot
        .leaves
        .iter()
        .filter(|leaf| leaf.is_block_eligible())
    {
        eligible_identity_count += 1;
        validation_score_total = validation_score_total
            .checked_add(leaf.validation_reward_score)
            .context("Idena validation score total overflow")?;
        proposer_score_total = proposer_score_total
            .checked_add(leaf.proposer_reward_score)
            .context("Idena proposer score total overflow")?;
        committee_score_total = committee_score_total
            .checked_add(leaf.committee_reward_score)
            .context("Idena committee score total overflow")?;
        ignored_invitation_score_total = ignored_invitation_score_total
            .checked_add(leaf.ignored_invitation_score)
            .context("Idena invitation score total overflow")?;
    }
    Ok(ExplorerIdenaOverview {
        state: "verified_snapshot".to_string(),
        snapshot_day: Some(snapshot.snapshot_day.to_string()),
        snapshot_height: Some(snapshot.idena_height),
        score_root: Some(snapshot.score_root.clone()),
        identity_root: Some(snapshot.identity_root.clone()),
        formula_version: Some(snapshot.formula_version),
        identity_count: snapshot.leaves.len(),
        eligible_identity_count,
        validation_score_total: validation_score_total.to_string(),
        proposer_score_total: proposer_score_total.to_string(),
        committee_score_total: committee_score_total.to_string(),
        ignored_invitation_score_total: ignored_invitation_score_total.to_string(),
        reward_source_coverage: "verified_snapshot_partial_sources".to_string(),
    })
}

fn unavailable_idena_overview(state: &str) -> ExplorerIdenaOverview {
    ExplorerIdenaOverview {
        state: state.to_string(),
        snapshot_day: None,
        snapshot_height: None,
        score_root: None,
        identity_root: None,
        formula_version: None,
        identity_count: 0,
        eligible_identity_count: 0,
        validation_score_total: "0".to_string(),
        proposer_score_total: "0".to_string(),
        committee_score_total: "0".to_string(),
        ignored_invitation_score_total: "0".to_string(),
        reward_source_coverage: "unavailable".to_string(),
    }
}

fn current_unix_timestamp() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("Unix timestamp exceeds i64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn share(hash_byte: char, height: u64) -> SharechainShareSummary {
        SharechainShareSummary {
            share_hash: hash_byte.to_string().repeat(64),
            height,
            active: true,
            miner_id: "miner-a".to_string(),
            parent_share_hash: "0".repeat(64),
            bitcoin_template_hash: "1".repeat(64),
            work_hash: "2".repeat(64),
            target: "3".repeat(64),
            hashrate_score_delta: "1".to_string(),
            cumulative_score: Some(height.to_string()),
            idena_snapshot_id: "2026-07-13".to_string(),
            idena_snapshot_proof_root: "4".repeat(64),
            template_created_at_unix: Some(1_700_000_000),
        }
    }

    #[test]
    fn share_pages_use_opaque_hash_cursors_without_duplication() {
        let shares = vec![share('a', 3), share('b', 2), share('c', 1)];
        let first = paginate_shares(shares.clone(), None, 2).unwrap();
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.next_cursor, Some("b".repeat(64)));

        let second = paginate_shares(shares, Some(&"b".repeat(64)), 2).unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].share_hash, "c".repeat(64));
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn public_share_summary_contains_no_identity_or_payout_fields() {
        let encoded = serde_json::to_string(&share('a', 1)).unwrap();
        assert!(!encoded.contains("idenaAddress"));
        assert!(!encoded.contains("payout"));
        assert!(!encoded.contains("signature"));
        assert!(!encoded.contains("bitcoinHeader"));
    }

    #[test]
    fn public_fork_status_uses_camel_case_without_changing_wire_status() {
        let status = ExplorerForkStatus::from(ForkChainStatus {
            protocol_version: 2,
            chain_name: "pohw-test".to_string(),
            activation_id: "a".repeat(64),
            inherited_tip_height: 100,
            inherited_tip_hash: "b".repeat(64),
            tip_height: 101,
            tip_hash: "c".repeat(64),
            cumulative_work: "1".to_string(),
            stored_block_count: 1,
            active_fork_block_count: 1,
            post_fork_pow_limit_bits: "207fffff".to_string(),
            target_spacing_seconds: 60,
            difficulty_algorithm: "bootstrap".to_string(),
            difficulty_phase: "bootstrap".to_string(),
            bootstrap_handoff_hashrate_hps: 1_000,
            estimated_hashrate_hps: "500".to_string(),
            blocks_until_bitcoin_retarget: None,
            transaction_consensus: "coinbase_only".to_string(),
        });
        let encoded = serde_json::to_string(&status).unwrap();
        assert!(encoded.contains("\"tipHeight\":101"));
        assert!(encoded.contains("\"activeForkBlockCount\":1"));
        assert!(!encoded.contains("tip_height"));
    }

    #[tokio::test]
    async fn cancelled_replay_keeps_its_slot_until_blocking_work_finishes() {
        let slots = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_slots = Arc::clone(&slots);
        let request = tokio::spawn(async move {
            run_replay_work_with_slots(worker_slots, move || {
                let _ = started_tx.send(());
                release_rx.recv().context("release replay worker")?;
                Ok(())
            })
            .await
        });

        started_rx.await.unwrap();
        request.abort();
        assert!(
            timeout(Duration::from_millis(100), slots.clone().acquire_owned())
                .await
                .is_err()
        );

        release_tx.send(()).unwrap();
        let permit = timeout(Duration::from_secs(1), slots.acquire_owned())
            .await
            .expect("replay slot should be released")
            .expect("replay limiter should remain open");
        drop(permit);
    }
}
