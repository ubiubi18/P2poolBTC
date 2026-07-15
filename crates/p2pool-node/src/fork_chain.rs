use crate::{
    bitcoin_rpc::{BitcoinMiningJobTemplate, BitcoinMiningJobTransaction, SubmitBlockOutcome},
    p2p_node::ConnectionLimiter,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{
    hmac::{Hmac, HmacEngine},
    sha256, sha256d, Hash as BitcoinHash, HashEngine,
};
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    ecdsa, taproot, Address, Block, BlockHash, CompressedPublicKey, Network, OutPoint, Transaction,
    TxOut, Txid, Weight,
};
use chrono::Utc;
use crypto_bigint::{NonZero, U256 as CryptoU256, U512 as CryptoU512};
use fs2::FileExt;
use pohw_core::fork::{
    ForkActivationManifest, ForkConfig, ForkDifficultyAlgorithm, ForkTransactionConsensus,
    ForkTransactionUpgradeManifest, BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL,
};
use pohw_core::sharechain::{BitcoinWorkTemplate, Share};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::future::pending;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};

const FORK_BLOCK_RECORD_SCHEMA_VERSION: u16 = 1;
const MAX_ACTIVATION_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_TRANSACTION_UPGRADE_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_HEX_BYTES: usize = MAX_BLOCK_BYTES * 2;
const MAX_WIRE_FRAME_BYTES: usize = MAX_BLOCK_HEX_BYTES + 64 * 1024;
const MAX_BLOCK_LOG_LINE_BYTES: usize = MAX_BLOCK_HEX_BYTES + 64 * 1024;
const MAX_FUTURE_BLOCK_SECONDS: u64 = 2 * 60 * 60;
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;
const MAX_CONNECTIONS: usize = 128;
const MAX_CONNECTIONS_PER_IP: usize = 16;
const MAX_PEERS: usize = 64;
const MAX_MEMPOOL_TRANSACTIONS: usize = 10_000;
const MAX_MEMPOOL_BYTES: usize = 3 * 1024 * 1024;
const MAX_MEMPOOL_TRANSACTION_BYTES: usize = 400_000;
const MAX_TEMPLATE_NON_COINBASE_WEIGHT_WU: u64 = 3_500_000;
const DEFAULT_NETWORK_TIMEOUT_SECONDS: u64 = 15;
const FORK_P2P_CAPABILITY_FILE_ENV: &str = "POHW_FORK_P2P_CAPABILITY_FILE";
const DEFAULT_FORK_P2P_CAPABILITY_FILE: &str = "fork-p2p.capability";
const MIN_FORK_P2P_CAPABILITY_BYTES: usize = 32;
const MAX_FORK_P2P_CAPABILITY_BYTES: usize = 512;
const FORK_P2P_AUTH_WINDOW_SECONDS: u64 = 120;
const FORK_P2P_RATE_WINDOW_SECONDS: u64 = 60;
const MAX_P2P_BLOCK_SUBMISSIONS_PER_WINDOW: usize = 12;
const MAX_P2P_TRANSACTION_SUBMISSIONS_PER_WINDOW: usize = 120;
const MAX_P2P_MEMPOOL_REQUESTS_PER_WINDOW: usize = 12;
const MAX_P2P_AUTH_NONCES: usize = 65_536;
const MAX_P2P_RATE_LIMIT_IPS: usize = MAX_CONNECTIONS;
const FORK_PROTOCOL_VERSION: u16 = 3;
const FORK_BLOCK_VERSION: i32 = 0x2000_0000;

#[derive(Debug, Clone)]
pub(crate) struct ForkChainNodeConfig {
    pub datadir: PathBuf,
    pub activation_manifest: PathBuf,
    pub transaction_upgrade_manifest: Option<PathBuf>,
    pub rpc_bind_addr: SocketAddr,
    pub p2p_bind_addr: Option<SocketAddr>,
    pub allow_non_loopback_p2p: bool,
    pub peer_addrs: Vec<SocketAddr>,
    pub sync_interval_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkChainStatus {
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
    pub transaction_upgrade_id: Option<String>,
    pub transaction_activation_height: Option<u64>,
    pub mempool_transaction_count: usize,
    pub transaction_consensus: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkBlockSummary {
    pub block_hash: String,
    pub previous_block_hash: String,
    pub height: u64,
    pub active: bool,
    pub timestamp: u32,
    pub bits: String,
    pub difficulty_phase: String,
    pub cumulative_work: String,
    pub version: i32,
    pub nonce: u32,
    pub merkle_root: String,
    pub transaction_count: usize,
    pub size_bytes: usize,
    pub weight_wu: u64,
    pub coinbase_txid: String,
    pub coinbase_value_sats: u64,
    pub coinbase_output_count: usize,
    pub pohw_commitment_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkBlockPage {
    pub tip_height: u64,
    pub total: usize,
    pub items: Vec<ForkBlockSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkTransactionRef {
    pub txid: String,
    pub block_hash: String,
    pub height: u64,
    pub active: bool,
    pub transaction_index: usize,
    pub coinbase: bool,
    pub total_output_sats: u64,
    pub fee_sats: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkPreviousOutput {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_pubkey_asm: String,
    pub script_type: String,
    pub address: Option<String>,
    pub script_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkTransactionInput {
    pub vin: usize,
    pub coinbase: bool,
    pub previous_txid: Option<String>,
    pub previous_vout: Option<u32>,
    pub script_sig_hex: String,
    pub script_sig_asm: String,
    pub sequence: u32,
    pub witness: Vec<String>,
    pub previous_output: Option<ForkPreviousOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkOutputSpend {
    pub txid: String,
    pub vin: usize,
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkTransactionOutput {
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_pubkey_asm: String,
    pub script_type: String,
    pub address: Option<String>,
    pub script_hash: String,
    pub spent_by: Option<ForkOutputSpend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkTransactionDetail {
    pub txid: String,
    pub wtxid: String,
    pub block_hash: String,
    pub height: u64,
    pub active: bool,
    pub transaction_index: usize,
    pub coinbase: bool,
    pub version: i32,
    pub lock_time: u32,
    pub size_bytes: usize,
    pub weight_wu: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub total_input_sats: Option<u64>,
    pub total_output_sats: u64,
    pub fee_sats: Option<u64>,
    pub inputs: Vec<ForkTransactionInput>,
    pub outputs: Vec<ForkTransactionOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkTransactionPage {
    pub block_hash: String,
    pub total: usize,
    pub items: Vec<ForkTransactionRef>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkAddressSummary {
    pub address: String,
    pub transaction_count: usize,
    pub funded_output_count: usize,
    pub funded_total_sats: u64,
    pub spent_output_count: usize,
    pub spent_total_sats: u64,
    pub balance_sats: u64,
    pub first_seen_height: Option<u64>,
    pub last_seen_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkAddressTransactionPage {
    pub address: String,
    pub total: usize,
    pub items: Vec<ForkTransactionRef>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    pub height: u64,
    pub coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkUtxoPage {
    pub address: String,
    pub total: usize,
    pub items: Vec<ForkUtxo>,
    pub next_cursor: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ForkUnspentOutput {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub height: u64,
    pub confirmations: u64,
    pub coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkBlockAcceptance {
    pub accepted: bool,
    pub became_active_tip: bool,
    pub block_hash: String,
    pub height: u64,
    pub tip_hash: String,
    pub tip_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkTransactionAcceptance {
    pub accepted: bool,
    pub txid: String,
    pub fee_sats: u64,
    pub mempool_transaction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkWorkTemplateValidation {
    pub template_hash: String,
    pub previous_block_hash: String,
    pub height: u64,
    pub header_time: u32,
    pub bits: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkShareValidation {
    pub template: ForkWorkTemplateValidation,
    pub work_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForkBlockRecord {
    schema_version: u16,
    activation_id: String,
    block_hex: String,
}

#[derive(Debug, Clone)]
struct BlockNode {
    block: Block,
    block_hex: String,
    height: u64,
    cumulative_work: Work,
    difficulty_phase: DifficultyPhase,
}

#[derive(Debug, Clone)]
struct IndexedForkOutput {
    output: TxOut,
    height: u64,
    coinbase: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForkTransactionLocation {
    block_hash: BlockHash,
    transaction_index: usize,
}

#[derive(Debug, Default)]
struct ForkAddressAccumulator {
    transaction_ids: BTreeSet<Txid>,
    funded_output_count: usize,
    funded_total_sats: u64,
    spent_output_count: usize,
    spent_total_sats: u64,
    first_seen_height: Option<u64>,
    last_seen_height: Option<u64>,
}

#[derive(Debug, Clone)]
struct ForkAddressIndexEntry {
    summary: ForkAddressSummary,
    transactions: Vec<ForkTransactionRef>,
    utxos: Vec<ForkUtxo>,
}

#[derive(Debug, Default)]
struct ForkExplorerIndex {
    outputs: BTreeMap<OutPoint, IndexedForkOutput>,
    spends: BTreeMap<OutPoint, ForkOutputSpend>,
    addresses: BTreeMap<String, ForkAddressIndexEntry>,
}

#[derive(Debug, Default)]
struct ForkBranchState {
    utxos: BTreeMap<OutPoint, IndexedForkOutput>,
    txids: BTreeSet<Txid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DifficultyPhase {
    Bootstrap,
    Bitcoin {
        epoch_start_height: u64,
        epoch_start_time: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NextDifficulty {
    bits: CompactTarget,
    phase: DifficultyPhase,
}

pub(crate) struct ForkChainStore {
    datadir: PathBuf,
    manifest: ForkActivationManifest,
    transaction_upgrade: Option<ForkTransactionUpgradeManifest>,
    inherited_tip_hash: BlockHash,
    blocks: BTreeMap<BlockHash, BlockNode>,
    active_tip: Option<BlockHash>,
    active_by_height: BTreeMap<u64, BlockHash>,
    stored_block_order: BTreeSet<(Reverse<u64>, BlockHash)>,
    transaction_locations: BTreeMap<Txid, Vec<ForkTransactionLocation>>,
    explorer: ForkExplorerIndex,
    mempool: BTreeMap<Txid, Transaction>,
    mempool_bytes: usize,
    _lock: File,
}

impl ForkChainStore {
    #[cfg(test)]
    pub(crate) fn open(datadir: &Path, activation_manifest: &Path) -> Result<Self> {
        Self::open_with_transaction_upgrade(datadir, activation_manifest, None)
    }

    pub(crate) fn open_with_transaction_upgrade(
        datadir: &Path,
        activation_manifest: &Path,
        transaction_upgrade_manifest: Option<&Path>,
    ) -> Result<Self> {
        let manifest = read_activation_manifest(activation_manifest)?;
        manifest
            .validate()
            .context("invalid fork activation manifest")?;
        if manifest.config.inherited_utxo_spending_enabled {
            bail!("Experiment 0 fork node requires inherited_utxo_spending_enabled=false");
        }
        let transaction_upgrade = transaction_upgrade_manifest
            .map(read_transaction_upgrade_manifest)
            .transpose()?;
        if let Some(upgrade) = &transaction_upgrade {
            upgrade
                .validate_for(&manifest)
                .context("fork transaction upgrade does not match the activation manifest")?;
        }
        ensure_private_directory(datadir)?;
        let lock_path = datadir.join("fork-chain.lock");
        let lock = open_private_file(&lock_path, true)?;
        lock.try_lock_exclusive().with_context(|| {
            format!(
                "fork-chain datadir {} is already locked by another writer",
                datadir.display()
            )
        })?;
        let inherited_tip_hash = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash)
            .context("invalid inherited tip block hash")?;
        let mut store = Self {
            datadir: datadir.to_path_buf(),
            manifest,
            transaction_upgrade,
            inherited_tip_hash,
            blocks: BTreeMap::new(),
            active_tip: None,
            active_by_height: BTreeMap::new(),
            stored_block_order: BTreeSet::new(),
            transaction_locations: BTreeMap::new(),
            explorer: ForkExplorerIndex::default(),
            mempool: BTreeMap::new(),
            mempool_bytes: 0,
            _lock: lock,
        };
        store.replay_block_log()?;
        Ok(store)
    }

    pub(crate) fn manifest(&self) -> &ForkActivationManifest {
        &self.manifest
    }

    fn transaction_upgrade_id(&self) -> Option<String> {
        self.transaction_upgrade
            .as_ref()
            .map(|upgrade| upgrade.upgrade_id.clone())
    }

    fn transactions_active_at(&self, height: u64) -> bool {
        self.transaction_upgrade
            .as_ref()
            .is_some_and(|upgrade| height >= upgrade.activation_height)
    }

    pub(crate) fn status(&self) -> ForkChainStatus {
        let (tip_height, tip_hash, cumulative_work, phase, current_bits) = match self.active_tip {
            Some(hash) => {
                let node = self
                    .blocks
                    .get(&hash)
                    .expect("active fork tip must exist in block map");
                (
                    node.height,
                    hash.to_string(),
                    node.cumulative_work,
                    node.difficulty_phase,
                    node.block.header.bits,
                )
            }
            None => (
                self.manifest.fork_point.inherited_tip_height,
                self.inherited_tip_hash.to_string(),
                Work::from_be_bytes([0u8; 32]),
                DifficultyPhase::Bootstrap,
                CompactTarget::from_consensus(self.manifest.config.post_fork_pow_limit_bits),
            ),
        };
        let blocks_until_bitcoin_retarget = match phase {
            DifficultyPhase::Bootstrap => None,
            DifficultyPhase::Bitcoin {
                epoch_start_height, ..
            } => Some(
                BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL
                    .saturating_sub(tip_height.saturating_sub(epoch_start_height)),
            ),
        };
        ForkChainStatus {
            protocol_version: FORK_PROTOCOL_VERSION,
            chain_name: self.manifest.config.chain_name.clone(),
            activation_id: self.manifest.activation_id.clone(),
            inherited_tip_height: self.manifest.fork_point.inherited_tip_height,
            inherited_tip_hash: self.inherited_tip_hash.to_string(),
            tip_height,
            tip_hash,
            cumulative_work: format!("{cumulative_work:064x}"),
            stored_block_count: self.blocks.len(),
            active_fork_block_count: self.active_by_height.len(),
            post_fork_pow_limit_bits: self.manifest.config.post_fork_pow_limit_bits_hex(),
            target_spacing_seconds: self.manifest.config.target_spacing_seconds,
            difficulty_algorithm: self
                .manifest
                .config
                .difficulty_algorithm
                .as_str()
                .to_string(),
            difficulty_phase: phase.as_str().to_string(),
            bootstrap_handoff_hashrate_hps: self.manifest.config.bootstrap_handoff_hashrate_hps,
            estimated_hashrate_hps: estimated_hashrate_hps(
                Target::from_compact(current_bits),
                self.manifest.config.target_spacing_seconds,
            )
            .to_string(),
            blocks_until_bitcoin_retarget,
            transaction_upgrade_id: self.transaction_upgrade_id(),
            transaction_activation_height: self
                .transaction_upgrade
                .as_ref()
                .map(|upgrade| upgrade.activation_height),
            mempool_transaction_count: self.mempool.len(),
            transaction_consensus: match &self.transaction_upgrade {
                Some(upgrade) if tip_height >= upgrade.activation_height => format!(
                    "{} active; fork-created P2WPKH and P2TR key-path UTXOs only; inherited UTXOs disabled",
                    upgrade.transaction_consensus.as_str()
                ),
                Some(upgrade) => format!(
                    "coinbase-only through height {}; {} activates at height {}; inherited UTXOs disabled",
                    upgrade.activation_height - 1,
                    upgrade.transaction_consensus.as_str(),
                    upgrade.activation_height
                ),
                None => {
                    "coinbase-only; inherited and post-fork spends disabled".to_string()
                }
            },
        }
    }

    pub(crate) fn mining_template(&self, now_unix: u64) -> Result<BitcoinMiningJobTemplate> {
        let status = self.status();
        let height = status
            .tip_height
            .checked_add(1)
            .context("fork-chain height overflow")?;
        let median_time_past = self.median_time_past(self.active_tip)?;
        let minimum_time = median_time_past
            .checked_add(1)
            .context("fork-chain median-time-past overflow")?;
        let curtime = now_unix.max(minimum_time);
        let curtime = u32::try_from(curtime).context("fork-chain template time exceeds u32")?;
        let next_difficulty = self.next_difficulty(self.active_tip, height, curtime)?;
        let (selected_transactions, fees_sats) = self.template_transactions(height)?;
        let coinbase_value_sats = block_subsidy_sats(height)
            .checked_add(fees_sats)
            .context("fork-chain template coinbase value overflow")?;
        let default_witness_commitment = (!selected_transactions.is_empty())
            .then(|| witness_commitment_script(&selected_transactions))
            .transpose()?;
        let transaction_hashes = selected_transactions
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        let transactions = selected_transactions
            .iter()
            .map(|tx| BitcoinMiningJobTransaction {
                txid: tx.compute_txid().to_string(),
                data_hex: hex::encode(serialize(tx)),
            })
            .collect();
        Ok(BitcoinMiningJobTemplate {
            version: FORK_BLOCK_VERSION,
            previous_block_hash: status.tip_hash,
            curtime,
            bits: format!("{:08x}", next_difficulty.bits.to_consensus()),
            height,
            coinbase_value_sats,
            transaction_hashes,
            transactions,
            default_witness_commitment,
            pohw_replay_marker: None,
        })
    }

    pub(crate) fn submit_transaction(
        &mut self,
        transaction_hex: &str,
    ) -> Result<ForkTransactionAcceptance> {
        let normalized = normalize_transaction_hex(transaction_hex)?;
        let transaction = decode_transaction(&normalized)?;
        let txid = transaction.compute_txid();
        if self.mempool.contains_key(&txid) {
            return Ok(ForkTransactionAcceptance {
                accepted: false,
                txid: txid.to_string(),
                fee_sats: 0,
                mempool_transaction_count: self.mempool.len(),
            });
        }
        if self.mempool.len() >= MAX_MEMPOOL_TRANSACTIONS {
            bail!("fork transaction mempool is full");
        }
        let transaction_bytes = normalized.len() / 2;
        let next_mempool_bytes = checked_mempool_bytes(self.mempool_bytes, transaction_bytes)?;
        let next_height = self
            .status()
            .tip_height
            .checked_add(1)
            .context("fork-chain mempool height overflow")?;
        if !self.transactions_active_at(next_height) {
            let activation_height = self
                .transaction_upgrade
                .as_ref()
                .map(|upgrade| upgrade.activation_height)
                .context("fork transaction consensus upgrade is not configured")?;
            bail!("fork transactions are not active until block height {activation_height}");
        }
        let mut branch_state = self.branch_state(self.active_tip)?;
        if branch_state.txids.contains(&txid) {
            bail!("fork transaction {txid} is already confirmed on the active chain");
        }
        let mempool_spends = self
            .mempool
            .values()
            .flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
            .collect::<BTreeSet<_>>();
        if transaction
            .input
            .iter()
            .any(|input| mempool_spends.contains(&input.previous_output))
        {
            bail!("fork transaction conflicts with an existing mempool spend");
        }
        let fee_sats =
            self.validate_and_apply_transaction(&transaction, next_height, &mut branch_state)?;
        self.mempool.insert(txid, transaction);
        self.mempool_bytes = next_mempool_bytes;
        Ok(ForkTransactionAcceptance {
            accepted: true,
            txid: txid.to_string(),
            fee_sats,
            mempool_transaction_count: self.mempool.len(),
        })
    }

    pub(crate) fn mempool_transactions(&self) -> Vec<String> {
        self.mempool
            .values()
            .map(|transaction| hex::encode(serialize(transaction)))
            .collect()
    }

    pub(crate) fn submit_block(&mut self, block_hex: &str) -> Result<ForkBlockAcceptance> {
        self.submit_block_at_time(block_hex, current_unix_time())
    }

    fn submit_block_at_time(
        &mut self,
        block_hex: &str,
        now_unix: u64,
    ) -> Result<ForkBlockAcceptance> {
        let normalized = normalize_block_hex(block_hex)?;
        let block = decode_block(&normalized)?;
        let hash = block.block_hash();
        if let Some(existing) = self.blocks.get(&hash) {
            let status = self.status();
            return Ok(ForkBlockAcceptance {
                accepted: false,
                became_active_tip: self.active_tip == Some(hash),
                block_hash: hash.to_string(),
                height: existing.height,
                tip_hash: status.tip_hash,
                tip_height: status.tip_height,
            });
        }
        let node = self.validate_block(block, normalized.clone(), now_unix)?;
        let previous_tip = self.active_tip;
        self.append_record(&normalized)?;
        let height = node.height;
        self.blocks.insert(hash, node);
        self.index_stored_block(hash)?;
        self.consider_active_tip(hash)?;
        if previous_tip != self.active_tip {
            self.revalidate_mempool()?;
        }
        let status = self.status();
        Ok(ForkBlockAcceptance {
            accepted: true,
            became_active_tip: self.active_tip == Some(hash) && previous_tip != self.active_tip,
            block_hash: hash.to_string(),
            height,
            tip_hash: status.tip_hash,
            tip_height: status.tip_height,
        })
    }

    pub(crate) fn active_block_hash(&self, height: u64) -> Option<String> {
        if height == self.manifest.fork_point.inherited_tip_height {
            return Some(self.inherited_tip_hash.to_string());
        }
        self.active_by_height.get(&height).map(ToString::to_string)
    }

    pub(crate) fn active_block_hex(&self, height: u64) -> Option<String> {
        self.active_by_height
            .get(&height)
            .and_then(|hash| self.blocks.get(hash))
            .map(|node| node.block_hex.clone())
    }

    pub(crate) fn block_page(&self, cursor: Option<&str>, limit: usize) -> Result<ForkBlockPage> {
        if !(1..=100).contains(&limit) {
            bail!("fork block page limit must be between 1 and 100");
        }
        use std::ops::Bound::{Excluded, Unbounded};

        let ordered: Box<dyn Iterator<Item = &(Reverse<u64>, BlockHash)> + '_> = match cursor {
            Some(cursor) => {
                let cursor = BlockHash::from_str(cursor)
                    .context("fork block cursor is not a valid block hash")?;
                let node = self
                    .blocks
                    .get(&cursor)
                    .context("fork block cursor is not present in local replay")?;
                let key = (Reverse(node.height), cursor);
                if !self.stored_block_order.contains(&key) {
                    bail!("fork block cursor is not present in the explorer index");
                }
                Box::new(self.stored_block_order.range((Excluded(key), Unbounded)))
            }
            None => Box::new(self.stored_block_order.iter()),
        };
        let mut page_hashes = ordered
            .take(limit.saturating_add(1))
            .map(|(_, hash)| *hash)
            .collect::<Vec<_>>();
        let has_more = page_hashes.len() > limit;
        page_hashes.truncate(limit);
        let items = page_hashes
            .iter()
            .map(|hash| {
                let node = self
                    .blocks
                    .get(hash)
                    .expect("indexed fork block must exist in block map");
                self.block_summary_for_node(*hash, node)
            })
            .collect::<Vec<_>>();
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.block_hash.clone()))
            .flatten();
        Ok(ForkBlockPage {
            tip_height: self.status().tip_height,
            total: self.stored_block_order.len(),
            items,
            next_cursor,
        })
    }

    pub(crate) fn block_summary(&self, block_hash: &str) -> Result<Option<ForkBlockSummary>> {
        let hash = BlockHash::from_str(block_hash).context("invalid fork block hash")?;
        Ok(self
            .blocks
            .get(&hash)
            .map(|node| self.block_summary_for_node(hash, node)))
    }

    pub(crate) fn block_transactions(
        &self,
        block_hash: &str,
        cursor: usize,
        limit: usize,
    ) -> Result<Option<ForkTransactionPage>> {
        validate_numeric_page(cursor, limit)?;
        let hash = BlockHash::from_str(block_hash).context("invalid fork block hash")?;
        let Some(node) = self.blocks.get(&hash) else {
            return Ok(None);
        };
        let active = self.active_by_height.get(&node.height) == Some(&hash);
        let total = node.block.txdata.len();
        let end = cursor.saturating_add(limit).min(total);
        let items = if cursor >= total {
            Vec::new()
        } else {
            node.block.txdata[cursor..end]
                .iter()
                .enumerate()
                .map(|(offset, tx)| {
                    transaction_ref(
                        tx,
                        hash,
                        node.height,
                        active,
                        cursor + offset,
                        &self.explorer.outputs,
                    )
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(Some(ForkTransactionPage {
            block_hash: hash.to_string(),
            total,
            items,
            next_cursor: (end < total).then_some(end),
        }))
    }

    pub(crate) fn transaction_detail(&self, txid: &str) -> Result<Option<ForkTransactionDetail>> {
        let txid = Txid::from_str(txid).context("invalid fork transaction id")?;
        let Some(locations) = self.transaction_locations.get(&txid) else {
            return Ok(None);
        };
        let mut matches = locations
            .iter()
            .map(|location| {
                let node = self
                    .blocks
                    .get(&location.block_hash)
                    .expect("indexed transaction block must exist");
                let tx = node
                    .block
                    .txdata
                    .get(location.transaction_index)
                    .expect("indexed transaction position must exist");
                (location.block_hash, node, location.transaction_index, tx)
            })
            .collect::<Vec<_>>();
        matches.sort_by(
            |(left_hash, left, left_index, _), (right_hash, right, right_index, _)| {
                let left_active = self.active_by_height.get(&left.height) == Some(left_hash);
                let right_active = self.active_by_height.get(&right.height) == Some(right_hash);
                right_active
                    .cmp(&left_active)
                    .then_with(|| right.height.cmp(&left.height))
                    .then_with(|| left_index.cmp(right_index))
                    .then_with(|| left_hash.to_string().cmp(&right_hash.to_string()))
            },
        );
        let Some((block_hash, node, transaction_index, tx)) = matches.into_iter().next() else {
            return Ok(None);
        };
        let active = self.active_by_height.get(&node.height) == Some(&block_hash);
        Ok(Some(transaction_detail(
            tx,
            block_hash,
            node.height,
            active,
            transaction_index,
            &self.explorer.outputs,
            &self.explorer.spends,
        )?))
    }

    pub(crate) fn address_summary(&self, address: &str) -> Result<ForkAddressSummary> {
        let address = normalize_mainnet_address(address)?;
        Ok(self
            .explorer
            .addresses
            .get(&address)
            .map(|entry| entry.summary.clone())
            .unwrap_or(ForkAddressSummary {
                address,
                transaction_count: 0,
                funded_output_count: 0,
                funded_total_sats: 0,
                spent_output_count: 0,
                spent_total_sats: 0,
                balance_sats: 0,
                first_seen_height: None,
                last_seen_height: None,
            }))
    }

    pub(crate) fn address_transactions(
        &self,
        address: &str,
        cursor: usize,
        limit: usize,
    ) -> Result<ForkAddressTransactionPage> {
        validate_numeric_page(cursor, limit)?;
        let address = normalize_mainnet_address(address)?;
        let items = self
            .explorer
            .addresses
            .get(&address)
            .map(|entry| entry.transactions.as_slice())
            .unwrap_or_default();
        let total = items.len();
        let end = cursor.saturating_add(limit).min(total);
        let page_items = if cursor >= total {
            Vec::new()
        } else {
            items[cursor..end].to_vec()
        };
        Ok(ForkAddressTransactionPage {
            address,
            total,
            items: page_items,
            next_cursor: (end < total).then_some(end),
        })
    }

    pub(crate) fn address_utxos(
        &self,
        address: &str,
        cursor: usize,
        limit: usize,
    ) -> Result<ForkUtxoPage> {
        validate_numeric_page(cursor, limit)?;
        let address = normalize_mainnet_address(address)?;
        let items = self
            .explorer
            .addresses
            .get(&address)
            .map(|entry| entry.utxos.as_slice())
            .unwrap_or_default();
        let total = items.len();
        let end = cursor.saturating_add(limit).min(total);
        let page_items = if cursor >= total {
            Vec::new()
        } else {
            items[cursor..end].to_vec()
        };
        Ok(ForkUtxoPage {
            address,
            total,
            items: page_items,
            next_cursor: (end < total).then_some(end),
        })
    }

    pub(crate) fn unspent_output(
        &self,
        txid: &str,
        vout: u32,
    ) -> Result<Option<ForkUnspentOutput>> {
        let txid = Txid::from_str(txid).context("invalid fork transaction id")?;
        let outpoint = OutPoint { txid, vout };
        if self.explorer.spends.contains_key(&outpoint) {
            return Ok(None);
        }
        let Some(indexed) = self.explorer.outputs.get(&outpoint) else {
            return Ok(None);
        };
        let tip_height = self.status().tip_height;
        let confirmations = tip_height
            .checked_sub(indexed.height)
            .and_then(|depth| depth.checked_add(1))
            .context("fork UTXO confirmation depth overflow")?;
        Ok(Some(ForkUnspentOutput {
            txid: txid.to_string(),
            vout,
            value_sats: indexed.output.value.to_sat(),
            script_pubkey_hex: hex::encode(indexed.output.script_pubkey.as_bytes()),
            height: indexed.height,
            confirmations,
            coinbase: indexed.coinbase,
        }))
    }

    fn branch_state(&self, parent: Option<BlockHash>) -> Result<ForkBranchState> {
        let mut branch = Vec::new();
        let mut cursor = parent;
        while let Some(hash) = cursor {
            let node = self
                .blocks
                .get(&hash)
                .ok_or_else(|| anyhow!("fork UTXO traversal found missing block {hash}"))?;
            branch.push((hash, node));
            cursor = if node.block.header.prev_blockhash == self.inherited_tip_hash {
                None
            } else {
                Some(node.block.header.prev_blockhash)
            };
        }
        branch.reverse();

        let mut state = ForkBranchState::default();
        for (block_hash, node) in branch {
            for transaction in &node.block.txdata {
                let txid = transaction.compute_txid();
                if !state.txids.insert(txid) {
                    bail!(
                        "fork branch contains duplicate transaction id {txid} at block {block_hash}"
                    );
                }
                if !transaction.is_coinbase() {
                    for input in &transaction.input {
                        state.utxos.remove(&input.previous_output).ok_or_else(|| {
                            anyhow!(
                                "fork branch transaction {txid} spends missing output {}",
                                input.previous_output
                            )
                        })?;
                    }
                }
                add_transaction_outputs(&mut state, transaction, node.height)?;
            }
        }
        Ok(state)
    }

    fn validate_and_apply_transaction(
        &self,
        transaction: &Transaction,
        height: u64,
        state: &mut ForkBranchState,
    ) -> Result<u64> {
        let upgrade = self
            .transaction_upgrade
            .as_ref()
            .filter(|upgrade| height >= upgrade.activation_height)
            .context("fork transaction validation requested before activation")?;
        match upgrade.transaction_consensus {
            ForkTransactionConsensus::SegwitKeypathV1 => {}
        }
        if transaction.is_coinbase() {
            bail!("fork non-coinbase transaction set contains a coinbase");
        }
        if transaction.version.0 != 2 {
            bail!("fork transaction version must be 2");
        }
        if transaction.lock_time.to_consensus_u32() != 0 {
            bail!("fork transaction lock_time must be zero in segwit-keypath-v1");
        }
        if transaction.input.is_empty() {
            bail!("fork transaction has no inputs");
        }
        if transaction.output.is_empty() {
            bail!("fork transaction has no outputs");
        }
        if transaction.weight().to_wu() > upgrade.max_transaction_weight_wu {
            bail!(
                "fork transaction exceeds the {} weight-unit limit",
                upgrade.max_transaction_weight_wu
            );
        }
        let txid = transaction.compute_txid();
        if state.txids.contains(&txid) {
            bail!("fork branch already contains transaction id {txid}");
        }

        let mut output_total = 0u64;
        for output in &transaction.output {
            let amount = output.value.to_sat();
            if amount > MAX_MONEY_SATS {
                bail!("fork transaction output exceeds MAX_MONEY");
            }
            output_total = output_total
                .checked_add(amount)
                .context("fork transaction output total overflow")?;
            if output_total > MAX_MONEY_SATS {
                bail!("fork transaction output total exceeds MAX_MONEY");
            }
        }

        let mut seen_inputs = BTreeSet::new();
        let mut prevouts = Vec::with_capacity(transaction.input.len());
        let mut input_total = 0u64;
        for input in &transaction.input {
            if !input.script_sig.is_empty() {
                bail!("fork segwit key-path input scriptSig must be empty");
            }
            if !seen_inputs.insert(input.previous_output) {
                bail!("fork transaction repeats input {}", input.previous_output);
            }
            let previous = state.utxos.get(&input.previous_output).ok_or_else(|| {
                anyhow!(
                    "fork transaction input {} is not an unspent fork-created output",
                    input.previous_output
                )
            })?;
            if previous.coinbase
                && height.saturating_sub(previous.height) < upgrade.coinbase_maturity
            {
                bail!(
                    "fork transaction spends immature coinbase {} at depth {}; {} required",
                    input.previous_output,
                    height.saturating_sub(previous.height),
                    upgrade.coinbase_maturity
                );
            }
            input_total = input_total
                .checked_add(previous.output.value.to_sat())
                .context("fork transaction input total overflow")?;
            if input_total > MAX_MONEY_SATS {
                bail!("fork transaction input total exceeds MAX_MONEY");
            }
            prevouts.push(previous.output.clone());
        }
        let fee_sats = input_total.checked_sub(output_total).ok_or_else(|| {
            anyhow!("fork transaction outputs {output_total} sats exceed inputs {input_total} sats")
        })?;
        validate_segwit_keypath_signatures(transaction, &prevouts)?;

        for input in &transaction.input {
            state
                .utxos
                .remove(&input.previous_output)
                .expect("validated fork transaction input remains unspent");
        }
        state.txids.insert(txid);
        add_transaction_outputs(state, transaction, height)?;
        Ok(fee_sats)
    }

    fn template_transactions(&self, height: u64) -> Result<(Vec<Transaction>, u64)> {
        if !self.transactions_active_at(height) || self.mempool.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let upgrade = self
            .transaction_upgrade
            .as_ref()
            .expect("active transaction consensus has an upgrade manifest");
        let max_non_coinbase = usize::try_from(upgrade.max_block_transactions - 1)
            .context("fork max transaction count exceeds usize")?;
        let mut state = self.branch_state(self.active_tip)?;
        let mut selected = Vec::new();
        let mut total_weight = 0u64;
        let mut total_fees = 0u64;
        for transaction in self.mempool.values() {
            if selected.len() >= max_non_coinbase {
                break;
            }
            let weight = transaction.weight().to_wu();
            if total_weight.saturating_add(weight) > MAX_TEMPLATE_NON_COINBASE_WEIGHT_WU {
                continue;
            }
            let fee = match self.validate_and_apply_transaction(transaction, height, &mut state) {
                Ok(fee) => fee,
                Err(_) => continue,
            };
            total_weight = total_weight
                .checked_add(weight)
                .context("fork template transaction weight overflow")?;
            total_fees = total_fees
                .checked_add(fee)
                .context("fork template fee total overflow")?;
            selected.push(transaction.clone());
        }
        Ok((selected, total_fees))
    }

    fn revalidate_mempool(&mut self) -> Result<()> {
        let next_height = self
            .status()
            .tip_height
            .checked_add(1)
            .context("fork-chain mempool revalidation height overflow")?;
        let pending = std::mem::take(&mut self.mempool);
        self.mempool_bytes = 0;
        if !self.transactions_active_at(next_height) {
            return Ok(());
        }
        let mut state = self.branch_state(self.active_tip)?;
        for (txid, transaction) in pending {
            if state.txids.contains(&txid) {
                continue;
            }
            if self
                .validate_and_apply_transaction(&transaction, next_height, &mut state)
                .is_ok()
            {
                let transaction_bytes = serialize(&transaction).len();
                let Ok(next_mempool_bytes) =
                    checked_mempool_bytes(self.mempool_bytes, transaction_bytes)
                else {
                    continue;
                };
                self.mempool.insert(txid, transaction);
                self.mempool_bytes = next_mempool_bytes;
            }
        }
        Ok(())
    }

    fn block_summary_for_node(&self, hash: BlockHash, node: &BlockNode) -> ForkBlockSummary {
        let coinbase = node
            .block
            .txdata
            .first()
            .expect("validated fork blocks always contain a coinbase");
        ForkBlockSummary {
            block_hash: hash.to_string(),
            previous_block_hash: node.block.header.prev_blockhash.to_string(),
            height: node.height,
            active: self.active_by_height.get(&node.height) == Some(&hash),
            timestamp: node.block.header.time,
            bits: format!("{:08x}", node.block.header.bits.to_consensus()),
            difficulty_phase: node.difficulty_phase.as_str().to_string(),
            cumulative_work: format!("{:064x}", node.cumulative_work),
            version: node.block.header.version.to_consensus(),
            nonce: node.block.header.nonce,
            merkle_root: node.block.header.merkle_root.to_string(),
            transaction_count: node.block.txdata.len(),
            size_bytes: node.block_hex.len() / 2,
            weight_wu: node.block.weight().to_wu(),
            coinbase_txid: coinbase.compute_txid().to_string(),
            coinbase_value_sats: coinbase
                .output
                .iter()
                .map(|output| output.value.to_sat())
                .sum(),
            coinbase_output_count: coinbase.output.len(),
            pohw_commitment_hash: pohw_commitment_hash(&node.block),
        }
    }

    pub(crate) fn validate_work_template(
        &self,
        template: &BitcoinWorkTemplate,
        now_unix: u64,
    ) -> Result<ForkWorkTemplateValidation> {
        template
            .verify_template_hash()
            .context("fork work template hash is invalid")?;
        let header = decode_header_prefix(&template.header_prefix_hex)?;
        if header.version.to_consensus() != FORK_BLOCK_VERSION {
            bail!("fork work template has an unsupported block version");
        }
        let previous = header.prev_blockhash;
        let (height, parent) = if previous == self.inherited_tip_hash {
            (self.manifest.fork_point.first_fork_height, None)
        } else {
            let node = self
                .blocks
                .get(&previous)
                .ok_or_else(|| anyhow!("fork work template parent is unknown"))?;
            if self.active_by_height.get(&node.height) != Some(&previous) {
                bail!("fork work template parent is not on the active chain");
            }
            (
                node.height
                    .checked_add(1)
                    .context("fork work template height overflow")?,
                Some(previous),
            )
        };
        let required_bits = self.next_difficulty(parent, height, header.time)?.bits;
        if header.bits != required_bits {
            bail!("fork work template difficulty bits do not match consensus schedule");
        }
        let median_time_past = self.median_time_past(parent)?;
        if u64::from(header.time) <= median_time_past {
            bail!("fork work template time is not greater than median-time-past");
        }
        if u64::from(header.time)
            > now_unix
                .checked_add(MAX_FUTURE_BLOCK_SECONDS)
                .context("fork work template future-time limit overflow")?
        {
            bail!("fork work template time is more than two hours in the future");
        }
        Ok(ForkWorkTemplateValidation {
            template_hash: template.template_hash.to_ascii_lowercase(),
            previous_block_hash: previous.to_string(),
            height,
            header_time: header.time,
            bits: format!("{:08x}", required_bits.to_consensus()),
        })
    }

    pub(crate) fn validate_share(
        &self,
        template: &BitcoinWorkTemplate,
        share: &Share,
        now_unix: u64,
    ) -> Result<ForkShareValidation> {
        if !share
            .bitcoin_template_hash
            .eq_ignore_ascii_case(&template.template_hash)
        {
            bail!("fork share references a different work template");
        }
        let header_prefix = share
            .bitcoin_header_prefix_hex()
            .context("fork share Bitcoin header is invalid")?;
        if !header_prefix.eq_ignore_ascii_case(&template.header_prefix_hex) {
            bail!("fork share header does not match its work template");
        }
        let recomputed_work_hash = share
            .recomputed_work_hash()
            .context("fork share work hash cannot be recomputed")?;
        if !share.work_hash.eq_ignore_ascii_case(&recomputed_work_hash) {
            bail!("fork share work hash does not match its Bitcoin header");
        }

        let validation = self.validate_work_template(template, now_unix)?;
        let active_parent = self.active_tip.unwrap_or(self.inherited_tip_hash);
        let work_status = if validation
            .previous_block_hash
            .eq_ignore_ascii_case(&active_parent.to_string())
        {
            "current-active-tip-share"
        } else {
            let active_block = self
                .active_block_hash(validation.height)
                .context("stale fork share has no active-chain block at its height")?;
            if !share.work_hash.eq_ignore_ascii_case(&active_block) {
                bail!(
                    "stale fork share is not the exact active-chain block at height {}",
                    validation.height
                );
            }
            "historical-exact-active-block"
        };
        Ok(ForkShareValidation {
            template: validation,
            work_status: work_status.to_string(),
        })
    }

    fn replay_block_log(&mut self) -> Result<()> {
        let path = self.block_log_path();
        let mut file = open_private_file(&path, true)?;
        repair_truncated_block_log_tail(&mut file, &path)?;
        let mut reader = BufReader::new(file);
        let mut index = 0usize;
        while let Some(line) = read_bounded_line(&mut reader, MAX_BLOCK_LOG_LINE_BYTES)? {
            index += 1;
            if line.is_empty() {
                continue;
            }
            let record: ForkBlockRecord = serde_json::from_slice(&line)
                .with_context(|| format!("fork block log line {index} is invalid JSON"))?;
            if record.schema_version != FORK_BLOCK_RECORD_SCHEMA_VERSION {
                bail!(
                    "fork block log line {} has unsupported schema version {}",
                    index,
                    record.schema_version
                );
            }
            if record.activation_id != self.manifest.activation_id {
                bail!(
                    "fork block log line {} belongs to another activation",
                    index
                );
            }
            let normalized = normalize_block_hex(&record.block_hex)?;
            let block = decode_block(&normalized)?;
            let hash = block.block_hash();
            if self.blocks.contains_key(&hash) {
                bail!("fork block log contains duplicate block {hash}");
            }
            // Future-time policy is checked when a block first enters the log. Replay must
            // remain deterministic even if the host clock later moves backwards.
            let node =
                self.validate_block(block, normalized, u64::MAX - MAX_FUTURE_BLOCK_SECONDS)?;
            self.blocks.insert(hash, node);
            self.index_stored_block(hash)?;
            self.consider_active_tip(hash)?;
        }
        Ok(())
    }

    fn validate_block(&self, block: Block, block_hex: String, now_unix: u64) -> Result<BlockNode> {
        if block.weight() > Weight::MAX_BLOCK {
            bail!("fork block exceeds the 4,000,000 weight-unit consensus limit");
        }
        if block.txdata.is_empty() {
            bail!("fork block has no coinbase transaction");
        }
        let coinbase = &block.txdata[0];
        if !coinbase.is_coinbase() {
            bail!("fork block first transaction is not a coinbase");
        }
        if !block.check_merkle_root() {
            bail!("fork block transaction merkle root is invalid");
        }
        if !block.check_witness_commitment() {
            bail!("fork block witness commitment is invalid");
        }
        if block.header.version.to_consensus() != FORK_BLOCK_VERSION {
            bail!("fork block has an unsupported version");
        }
        let previous_hash = block.header.prev_blockhash;
        let (height, parent_work, parent_tip) = if previous_hash == self.inherited_tip_hash {
            (
                self.manifest.fork_point.first_fork_height,
                Work::from_be_bytes([0u8; 32]),
                None,
            )
        } else {
            let parent = self
                .blocks
                .get(&previous_hash)
                .ok_or_else(|| anyhow!("fork block parent {previous_hash} is unknown"))?;
            (
                parent
                    .height
                    .checked_add(1)
                    .context("fork block height overflow")?,
                parent.cumulative_work,
                Some(previous_hash),
            )
        };
        let next_difficulty = self.next_difficulty(parent_tip, height, block.header.time)?;
        let required_target = Target::from_compact(next_difficulty.bits);
        block
            .header
            .validate_pow(required_target)
            .context("fork block has invalid difficulty bits or proof of work")?;
        let median_time_past = self.median_time_past(parent_tip)?;
        if u64::from(block.header.time) <= median_time_past {
            bail!(
                "fork block time {} is not greater than median-time-past {}",
                block.header.time,
                median_time_past
            );
        }
        if u64::from(block.header.time)
            > now_unix
                .checked_add(MAX_FUTURE_BLOCK_SECONDS)
                .context("fork block future-time limit overflow")?
        {
            bail!("fork block time is more than two hours in the future");
        }
        let fees_sats = self.validate_block_transactions(&block, height, parent_tip)?;
        validate_coinbase_height(coinbase, height)?;
        validate_coinbase_reward(coinbase, height, fees_sats)?;
        let cumulative_work = parent_work + required_target.to_work();
        Ok(BlockNode {
            block,
            block_hex,
            height,
            cumulative_work,
            difficulty_phase: next_difficulty.phase,
        })
    }

    fn validate_block_transactions(
        &self,
        block: &Block,
        height: u64,
        parent: Option<BlockHash>,
    ) -> Result<u64> {
        if !self.transactions_active_at(height) {
            if block.txdata.len() != 1 {
                bail!(
                    "fork blocks before the transaction activation height must contain exactly one coinbase transaction"
                );
            }
            return Ok(0);
        }
        let upgrade = self
            .transaction_upgrade
            .as_ref()
            .expect("active transaction rules have an upgrade manifest");
        if block.txdata.len()
            > usize::try_from(upgrade.max_block_transactions)
                .context("fork max block transaction count exceeds usize")?
        {
            bail!(
                "fork block contains {} transactions; {} allowed",
                block.txdata.len(),
                upgrade.max_block_transactions
            );
        }
        if block.txdata.iter().skip(1).any(Transaction::is_coinbase) {
            bail!("fork block contains more than one coinbase transaction");
        }

        let coinbase = &block.txdata[0];
        let coinbase_txid = coinbase.compute_txid();
        let mut state = self.branch_state(parent)?;
        if !state.txids.insert(coinbase_txid) {
            bail!("fork branch already contains coinbase transaction id {coinbase_txid}");
        }
        add_transaction_outputs(&mut state, coinbase, height)?;

        let mut fees_sats = 0u64;
        for transaction in block.txdata.iter().skip(1) {
            let fee = self.validate_and_apply_transaction(transaction, height, &mut state)?;
            fees_sats = fees_sats
                .checked_add(fee)
                .context("fork block fee total overflow")?;
        }
        Ok(fees_sats)
    }

    fn next_difficulty(
        &self,
        parent_hash: Option<BlockHash>,
        child_height: u64,
        child_time: u32,
    ) -> Result<NextDifficulty> {
        let pow_limit_bits =
            CompactTarget::from_consensus(self.manifest.config.post_fork_pow_limit_bits);
        let Some(parent_hash) = parent_hash else {
            return Ok(NextDifficulty {
                bits: pow_limit_bits,
                phase: self.phase_after_bootstrap_block(pow_limit_bits, child_height, child_time),
            });
        };
        let parent = self
            .blocks
            .get(&parent_hash)
            .ok_or_else(|| anyhow!("fork-chain difficulty parent is unknown"))?;
        match parent.difficulty_phase {
            DifficultyPhase::Bootstrap => {
                let elapsed = child_time.saturating_sub(parent.block.header.time);
                let bits = next_work_required(
                    parent.block.header.bits,
                    u64::from(elapsed),
                    self.manifest.config.target_spacing_seconds,
                    &self.manifest.config,
                )?;
                Ok(NextDifficulty {
                    bits,
                    phase: self.phase_after_bootstrap_block(bits, child_height, child_time),
                })
            }
            phase @ DifficultyPhase::Bitcoin {
                epoch_start_height,
                epoch_start_time,
            } => {
                let epoch_offset = child_height
                    .checked_sub(epoch_start_height)
                    .context("fork-chain Bitcoin retarget height underflow")?;
                if epoch_offset < BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL {
                    return Ok(NextDifficulty {
                        bits: parent.block.header.bits,
                        phase,
                    });
                }
                if epoch_offset != BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL {
                    bail!("fork-chain Bitcoin retarget state skipped an epoch boundary");
                }
                let actual_timespan = parent.block.header.time.saturating_sub(epoch_start_time);
                let bits = next_work_required(
                    parent.block.header.bits,
                    u64::from(actual_timespan),
                    self.manifest
                        .config
                        .bitcoin_retarget_timespan_seconds()
                        .context("validated fork config lost its Bitcoin retarget timespan")?,
                    &self.manifest.config,
                )?;
                Ok(NextDifficulty {
                    bits,
                    phase: DifficultyPhase::Bitcoin {
                        epoch_start_height: child_height,
                        epoch_start_time: child_time,
                    },
                })
            }
        }
    }

    fn phase_after_bootstrap_block(
        &self,
        bits: CompactTarget,
        height: u64,
        time: u32,
    ) -> DifficultyPhase {
        if Target::from_compact(bits).to_work() >= bootstrap_handoff_work(&self.manifest.config) {
            DifficultyPhase::Bitcoin {
                epoch_start_height: height,
                epoch_start_time: time,
            }
        } else {
            DifficultyPhase::Bootstrap
        }
    }

    fn median_time_past(&self, parent: Option<BlockHash>) -> Result<u64> {
        let launch = self.manifest.config.launch_timestamp_utc.timestamp();
        let anchor = u64::try_from(launch.saturating_sub(1))
            .context("fork launch timestamp predates Unix epoch")?;
        let mut times = vec![anchor];
        let mut cursor = parent;
        while let Some(hash) = cursor {
            if times.len() >= 11 {
                break;
            }
            let node = self
                .blocks
                .get(&hash)
                .ok_or_else(|| anyhow!("fork-chain parent traversal found missing block {hash}"))?;
            times.push(u64::from(node.block.header.time));
            cursor = if node.block.header.prev_blockhash == self.inherited_tip_hash {
                None
            } else {
                Some(node.block.header.prev_blockhash)
            };
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    fn consider_active_tip(&mut self, candidate_hash: BlockHash) -> Result<()> {
        let candidate = self
            .blocks
            .get(&candidate_hash)
            .expect("new candidate must exist in block map");
        let better = match self.active_tip {
            None => true,
            Some(current_hash) => {
                let current = self
                    .blocks
                    .get(&current_hash)
                    .expect("active tip must exist in block map");
                candidate.cumulative_work > current.cumulative_work
                    || (candidate.cumulative_work == current.cumulative_work
                        && candidate_hash.to_string() < current_hash.to_string())
            }
        };
        if better {
            self.active_tip = Some(candidate_hash);
            self.rebuild_active_index()?;
        }
        Ok(())
    }

    fn index_stored_block(&mut self, hash: BlockHash) -> Result<()> {
        let node = self
            .blocks
            .get(&hash)
            .context("cannot index a fork block that is not stored")?;
        let height = node.height;
        let txids = node
            .block
            .txdata
            .iter()
            .map(Transaction::compute_txid)
            .collect::<Vec<_>>();
        if !self.stored_block_order.insert((Reverse(height), hash)) {
            bail!("fork block is already present in explorer ordering index");
        }
        for (transaction_index, txid) in txids.into_iter().enumerate() {
            self.transaction_locations
                .entry(txid)
                .or_default()
                .push(ForkTransactionLocation {
                    block_hash: hash,
                    transaction_index,
                });
        }
        Ok(())
    }

    fn rebuild_active_index(&mut self) -> Result<()> {
        let mut active = BTreeMap::new();
        let mut cursor = self.active_tip;
        while let Some(hash) = cursor {
            let node = self
                .blocks
                .get(&hash)
                .ok_or_else(|| anyhow!("active fork chain contains missing block {hash}"))?;
            active.insert(node.height, hash);
            cursor = if node.block.header.prev_blockhash == self.inherited_tip_hash {
                None
            } else {
                Some(node.block.header.prev_blockhash)
            };
        }
        self.active_by_height = active;
        self.rebuild_explorer_index()?;
        Ok(())
    }

    fn rebuild_explorer_index(&mut self) -> Result<()> {
        let mut outputs = BTreeMap::new();
        let mut spends = BTreeMap::new();
        let mut accumulators = BTreeMap::<String, ForkAddressAccumulator>::new();

        for (height, block_hash) in &self.active_by_height {
            let node = self
                .blocks
                .get(block_hash)
                .expect("active fork block must exist");
            for tx in &node.block.txdata {
                let txid = tx.compute_txid();
                for (vout, output) in tx.output.iter().enumerate() {
                    let vout =
                        u32::try_from(vout).context("fork transaction output index exceeds u32")?;
                    let outpoint = OutPoint { txid, vout };
                    outputs.insert(
                        outpoint,
                        IndexedForkOutput {
                            output: output.clone(),
                            height: *height,
                            coinbase: tx.is_coinbase(),
                        },
                    );
                    let Some(address) = output_address(output) else {
                        continue;
                    };
                    let accumulator = accumulators.entry(address).or_default();
                    accumulator.transaction_ids.insert(txid);
                    accumulator.funded_output_count =
                        accumulator.funded_output_count.saturating_add(1);
                    accumulator.funded_total_sats = accumulator
                        .funded_total_sats
                        .checked_add(output.value.to_sat())
                        .context("fork address funded total overflow")?;
                    update_height_range(
                        &mut accumulator.first_seen_height,
                        &mut accumulator.last_seen_height,
                        *height,
                    );
                }
            }
        }

        for (height, block_hash) in &self.active_by_height {
            let node = self
                .blocks
                .get(block_hash)
                .expect("active fork block must exist");
            for tx in &node.block.txdata {
                if tx.is_coinbase() {
                    continue;
                }
                let txid = tx.compute_txid();
                for (vin, input) in tx.input.iter().enumerate() {
                    spends.insert(
                        input.previous_output,
                        ForkOutputSpend {
                            txid: txid.to_string(),
                            vin,
                            height: *height,
                        },
                    );
                    let Some(indexed) = outputs.get(&input.previous_output) else {
                        continue;
                    };
                    let Some(address) = output_address(&indexed.output) else {
                        continue;
                    };
                    let accumulator = accumulators.entry(address).or_default();
                    accumulator.transaction_ids.insert(txid);
                    accumulator.spent_output_count =
                        accumulator.spent_output_count.saturating_add(1);
                    accumulator.spent_total_sats = accumulator
                        .spent_total_sats
                        .checked_add(indexed.output.value.to_sat())
                        .context("fork address spent total overflow")?;
                    update_height_range(
                        &mut accumulator.first_seen_height,
                        &mut accumulator.last_seen_height,
                        *height,
                    );
                }
            }
        }

        let mut addresses = accumulators
            .into_iter()
            .map(|(address, accumulator)| {
                let balance_sats = accumulator
                    .funded_total_sats
                    .checked_sub(accumulator.spent_total_sats)
                    .context("fork address balance underflow")?;
                Ok((
                    address.clone(),
                    ForkAddressIndexEntry {
                        summary: ForkAddressSummary {
                            address,
                            transaction_count: accumulator.transaction_ids.len(),
                            funded_output_count: accumulator.funded_output_count,
                            funded_total_sats: accumulator.funded_total_sats,
                            spent_output_count: accumulator.spent_output_count,
                            spent_total_sats: accumulator.spent_total_sats,
                            balance_sats,
                            first_seen_height: accumulator.first_seen_height,
                            last_seen_height: accumulator.last_seen_height,
                        },
                        transactions: Vec::new(),
                        utxos: Vec::new(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;

        for (height, block_hash) in self.active_by_height.iter().rev() {
            let node = self
                .blocks
                .get(block_hash)
                .expect("active fork block must exist");
            for (transaction_index, tx) in node.block.txdata.iter().enumerate().rev() {
                let mut related_addresses = BTreeSet::new();
                for output in &tx.output {
                    if let Some(address) = output_address(output) {
                        related_addresses.insert(address);
                    }
                }
                for input in &tx.input {
                    if let Some(address) = outputs
                        .get(&input.previous_output)
                        .and_then(|indexed| output_address(&indexed.output))
                    {
                        related_addresses.insert(address);
                    }
                }
                if related_addresses.is_empty() {
                    continue;
                }
                let transaction =
                    transaction_ref(tx, *block_hash, *height, true, transaction_index, &outputs)?;
                for address in related_addresses {
                    if let Some(entry) = addresses.get_mut(&address) {
                        entry.transactions.push(transaction.clone());
                    }
                }
            }
        }

        for (outpoint, indexed) in &outputs {
            if spends.contains_key(outpoint) {
                continue;
            }
            let Some(address) = output_address(&indexed.output) else {
                continue;
            };
            if let Some(entry) = addresses.get_mut(&address) {
                entry.utxos.push(ForkUtxo {
                    txid: outpoint.txid.to_string(),
                    vout: outpoint.vout,
                    value_sats: indexed.output.value.to_sat(),
                    script_pubkey_hex: hex::encode(indexed.output.script_pubkey.as_bytes()),
                    script_type: script_type(&indexed.output),
                    height: indexed.height,
                    coinbase: indexed.coinbase,
                });
            }
        }
        for entry in addresses.values_mut() {
            entry.utxos.sort_by(|left, right| {
                right
                    .height
                    .cmp(&left.height)
                    .then_with(|| left.txid.cmp(&right.txid))
                    .then_with(|| left.vout.cmp(&right.vout))
            });
        }

        self.explorer = ForkExplorerIndex {
            outputs,
            spends,
            addresses,
        };
        Ok(())
    }

    fn append_record(&self, block_hex: &str) -> Result<()> {
        let record = ForkBlockRecord {
            schema_version: FORK_BLOCK_RECORD_SCHEMA_VERSION,
            activation_id: self.manifest.activation_id.clone(),
            block_hex: block_hex.to_string(),
        };
        let encoded = serde_json::to_vec(&record).context("failed to encode fork block record")?;
        if encoded.len() > MAX_BLOCK_LOG_LINE_BYTES {
            bail!("fork block record exceeds size limit");
        }
        let path = self.block_log_path();
        let mut file = open_private_append_file(&path)?;
        file.write_all(&encoded)
            .with_context(|| format!("failed to append fork block log {}", path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed to finish fork block log {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync fork block log {}", path.display()))?;
        sync_directory(&self.datadir)?;
        Ok(())
    }

    fn block_log_path(&self) -> PathBuf {
        self.datadir.join("fork-blocks.ndjson")
    }
}

impl DifficultyPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Bitcoin { .. } => "bitcoin_2016",
        }
    }
}

fn next_work_required(
    previous_bits: CompactTarget,
    actual_timespan: u64,
    target_timespan: u64,
    config: &ForkConfig,
) -> Result<CompactTarget> {
    match config.difficulty_algorithm {
        ForkDifficultyAlgorithm::BootstrapThenBitcoin2016V1 => next_work_required_v1(
            previous_bits,
            actual_timespan,
            target_timespan,
            config.post_fork_pow_limit_bits,
        ),
    }
}

fn next_work_required_v1(
    previous_bits: CompactTarget,
    actual_timespan: u64,
    target_timespan: u64,
    pow_limit_bits: u32,
) -> Result<CompactTarget> {
    let min_timespan = target_timespan >> 2;
    let max_timespan = target_timespan
        .checked_mul(4)
        .context("fork difficulty maximum retarget timespan overflow")?;
    let actual_timespan = actual_timespan.clamp(min_timespan, max_timespan);

    // The bootstrap target can be close to 2^255. Bitcoin Core's formula is
    // target * timespan / target_timespan, so use a wide intermediate here.
    let previous = CryptoU256::from_be_slice(&Target::from_compact(previous_bits).to_be_bytes());
    let previous_wide: CryptoU512 = previous.resize();
    let scaled = previous_wide.wrapping_mul(&CryptoU512::from_u64(actual_timespan));
    let target_timespan = NonZero::new(CryptoU512::from_u64(target_timespan))
        .into_option()
        .context("fork difficulty target timespan must be non-zero")?;
    let adjusted = scaled.wrapping_div(&target_timespan);

    let pow_limit = CryptoU256::from_be_slice(
        &Target::from_compact(CompactTarget::from_consensus(pow_limit_bits)).to_be_bytes(),
    );
    let pow_limit_wide: CryptoU512 = pow_limit.resize();
    let bounded = if adjusted > pow_limit_wide {
        pow_limit_wide
    } else {
        adjusted
    };
    let bounded: CryptoU256 = bounded.resize();
    Ok(Target::from_be_bytes(bounded.to_be_bytes().into()).to_compact_lossy())
}

fn bootstrap_handoff_work(config: &ForkConfig) -> Work {
    let expected_hashes = u128::from(config.bootstrap_handoff_hashrate_hps)
        * u128::from(config.target_spacing_seconds);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&expected_hashes.to_be_bytes());
    Work::from_be_bytes(bytes)
}

fn estimated_hashrate_hps(target: Target, target_spacing_seconds: u64) -> u128 {
    let bytes = target.to_work().to_be_bytes();
    let expected_hashes = if bytes[..16].iter().any(|byte| *byte != 0) {
        u128::MAX
    } else {
        u128::from_be_bytes(
            bytes[16..]
                .try_into()
                .expect("a Work value always has a 16-byte low half"),
        )
    };
    expected_hashes / u128::from(target_spacing_seconds)
}

#[derive(Debug, Clone)]
pub(crate) struct ForkChainClient {
    addr: SocketAddr,
    activation_id: String,
    transaction_upgrade_id: Option<String>,
    peer_capability: Option<Arc<Vec<u8>>>,
}

impl ForkChainClient {
    pub(crate) fn new(
        addr: SocketAddr,
        activation_id: String,
        allow_non_loopback: bool,
    ) -> Result<Self> {
        validate_peer_addr(addr)?;
        if !allow_non_loopback && !addr.ip().is_loopback() {
            bail!("fork-chain RPC address must be loopback unless explicitly allowed");
        }
        validate_activation_id(&activation_id)?;
        Ok(Self {
            addr,
            activation_id,
            transaction_upgrade_id: None,
            peer_capability: None,
        })
    }

    fn new_peer(
        addr: SocketAddr,
        activation_id: String,
        transaction_upgrade_id: Option<String>,
        peer_capability: Option<Arc<Vec<u8>>>,
    ) -> Result<Self> {
        let mut client = Self::new(addr, activation_id, true)?;
        if let Some(upgrade_id) = &transaction_upgrade_id {
            validate_activation_id(upgrade_id).context("fork transaction upgrade id is invalid")?;
        }
        client.transaction_upgrade_id = transaction_upgrade_id;
        client.peer_capability = peer_capability;
        Ok(client)
    }

    pub(crate) async fn status(&self) -> Result<ForkChainStatus> {
        let value = self.request(ForkWireMethod::Status).await?;
        serde_json::from_value(value).context("fork-chain status response has invalid shape")
    }

    pub(crate) async fn mining_template(&self) -> Result<BitcoinMiningJobTemplate> {
        let value = self.request(ForkWireMethod::MiningTemplate).await?;
        serde_json::from_value(value)
            .context("fork-chain mining template response has invalid shape")
    }

    pub(crate) async fn submit_block(&self, block_hex: &str) -> Result<SubmitBlockOutcome> {
        let value = self
            .request(ForkWireMethod::SubmitBlock {
                block_hex: block_hex.to_string(),
            })
            .await?;
        let accepted: ForkBlockAcceptance = serde_json::from_value(value)
            .context("fork-chain submit response has invalid shape")?;
        Ok(SubmitBlockOutcome {
            status: if accepted.accepted {
                "accepted".to_string()
            } else {
                "duplicate".to_string()
            },
            reject_reason: None,
        })
    }

    pub(crate) async fn submit_transaction(
        &self,
        transaction_hex: &str,
    ) -> Result<ForkTransactionAcceptance> {
        let value = self
            .request(ForkWireMethod::SubmitTransaction {
                transaction_hex: transaction_hex.to_string(),
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain transaction submission response has invalid shape")
    }

    async fn mempool_transactions(&self) -> Result<Vec<String>> {
        let value = self.request(ForkWireMethod::MempoolTransactions).await?;
        serde_json::from_value(value)
            .context("fork-chain mempool transaction response has invalid shape")
    }

    pub(crate) async fn validate_work_template(
        &self,
        template: &BitcoinWorkTemplate,
    ) -> Result<ForkWorkTemplateValidation> {
        let value = self
            .request(ForkWireMethod::ValidateWorkTemplate {
                template: template.clone(),
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain work-template validation response has invalid shape")
    }

    pub(crate) async fn validate_share(
        &self,
        template: &BitcoinWorkTemplate,
        share: &Share,
    ) -> Result<ForkShareValidation> {
        let value = self
            .request(ForkWireMethod::ValidateShare {
                template: template.clone(),
                share: Box::new(share.clone()),
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain share validation response has invalid shape")
    }

    pub(crate) async fn active_block_hash(&self, height: u64) -> Result<Option<String>> {
        let value = self
            .request(ForkWireMethod::ActiveBlockHash { height })
            .await?;
        serde_json::from_value(value).context("fork-chain block-hash response has invalid shape")
    }

    async fn active_block_hex(&self, height: u64) -> Result<Option<String>> {
        let value = self.request(ForkWireMethod::ActiveBlock { height }).await?;
        serde_json::from_value(value).context("fork-chain block response has invalid shape")
    }

    pub(crate) async fn block_page(
        &self,
        cursor: Option<String>,
        limit: u16,
    ) -> Result<ForkBlockPage> {
        let value = self
            .request(ForkWireMethod::BlockPage { cursor, limit })
            .await?;
        serde_json::from_value(value).context("fork-chain block page response has invalid shape")
    }

    pub(crate) async fn block_summary(
        &self,
        block_hash: String,
    ) -> Result<Option<ForkBlockSummary>> {
        let value = self
            .request(ForkWireMethod::BlockSummary { block_hash })
            .await?;
        serde_json::from_value(value).context("fork-chain block summary response has invalid shape")
    }

    pub(crate) async fn block_transactions(
        &self,
        block_hash: String,
        cursor: usize,
        limit: u16,
    ) -> Result<Option<ForkTransactionPage>> {
        let value = self
            .request(ForkWireMethod::BlockTransactions {
                block_hash,
                cursor,
                limit,
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain block transaction page response has invalid shape")
    }

    pub(crate) async fn transaction_detail(
        &self,
        txid: String,
    ) -> Result<Option<ForkTransactionDetail>> {
        let value = self
            .request(ForkWireMethod::TransactionDetail { txid })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain transaction detail response has invalid shape")
    }

    pub(crate) async fn address_summary(&self, address: String) -> Result<ForkAddressSummary> {
        let value = self
            .request(ForkWireMethod::AddressSummary { address })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain address summary response has invalid shape")
    }

    pub(crate) async fn address_transactions(
        &self,
        address: String,
        cursor: usize,
        limit: u16,
    ) -> Result<ForkAddressTransactionPage> {
        let value = self
            .request(ForkWireMethod::AddressTransactions {
                address,
                cursor,
                limit,
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain address transaction page response has invalid shape")
    }

    pub(crate) async fn address_utxos(
        &self,
        address: String,
        cursor: usize,
        limit: u16,
    ) -> Result<ForkUtxoPage> {
        let value = self
            .request(ForkWireMethod::AddressUtxos {
                address,
                cursor,
                limit,
            })
            .await?;
        serde_json::from_value(value)
            .context("fork-chain address UTXO page response has invalid shape")
    }

    async fn request(&self, method: ForkWireMethod) -> Result<Value> {
        let mut request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: self.activation_id.clone(),
            transaction_upgrade_id: self.transaction_upgrade_id.clone(),
            auth: None,
            method,
        };
        if let Some(capability) = self.peer_capability.as_deref() {
            request.auth = Some(create_peer_request_auth(&request, capability)?);
        }
        let payload =
            serde_json::to_vec(&request).context("failed to encode fork-chain request")?;
        let response = timeout(
            Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
            async {
                let mut stream = TcpStream::connect(self.addr).await.with_context(|| {
                    format!("failed to connect to fork-chain RPC at {}", self.addr)
                })?;
                write_frame(&mut stream, &payload).await?;
                read_frame(&mut stream).await
            },
        )
        .await
        .context("fork-chain request timed out")??;
        let response: ForkWireResponse =
            serde_json::from_slice(&response).context("fork-chain response is invalid JSON")?;
        if response.ok {
            response
                .result
                .ok_or_else(|| anyhow!("fork-chain response omitted result"))
        } else {
            bail!(
                "fork-chain request failed [{}]: {}",
                response.error_code.unwrap_or_else(|| "unknown".to_string()),
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForkWireRequest {
    protocol_version: u16,
    activation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_upgrade_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<ForkWireAuth>,
    #[serde(flatten)]
    method: ForkWireMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForkWireAuth {
    timestamp_unix: u64,
    nonce_hex: String,
    mac_hex: String,
}

#[derive(Serialize)]
struct ForkWireAuthPayload<'a> {
    protocol_version: u16,
    activation_id: &'a str,
    transaction_upgrade_id: &'a Option<String>,
    timestamp_unix: u64,
    nonce_hex: &'a str,
    method: &'a ForkWireMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum ForkWireMethod {
    Status,
    MiningTemplate,
    ValidateWorkTemplate {
        template: BitcoinWorkTemplate,
    },
    ValidateShare {
        template: BitcoinWorkTemplate,
        share: Box<Share>,
    },
    SubmitBlock {
        block_hex: String,
    },
    SubmitTransaction {
        transaction_hex: String,
    },
    MempoolTransactions,
    ActiveBlockHash {
        height: u64,
    },
    ActiveBlock {
        height: u64,
    },
    BlockPage {
        cursor: Option<String>,
        limit: u16,
    },
    BlockSummary {
        block_hash: String,
    },
    BlockTransactions {
        block_hash: String,
        cursor: usize,
        limit: u16,
    },
    TransactionDetail {
        txid: String,
    },
    AddressSummary {
        address: String,
    },
    AddressTransactions {
        address: String,
        cursor: usize,
        limit: u16,
    },
    AddressUtxos {
        address: String,
        cursor: usize,
        limit: u16,
    },
    UnspentOutput {
        txid: String,
        vout: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForkWireResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ForkWireResponse {
    fn success<T: Serialize>(value: T) -> Result<Self> {
        Ok(Self {
            ok: true,
            result: Some(serde_json::to_value(value)?),
            error_code: None,
            error: None,
        })
    }

    fn error(code: &str, error: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error_code: Some(code.to_string()),
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Default)]
struct ForkPeerReplayState {
    nonces: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy)]
enum ForkPeerMutationKind {
    Block,
    Transaction,
    MempoolRead,
}

#[derive(Debug, Default)]
struct ForkPeerRateWindow {
    started_at_unix: u64,
    blocks: usize,
    transactions: usize,
    mempool_reads: usize,
}

#[derive(Debug, Default)]
struct ForkPeerRateLimiter {
    by_ip: StdMutex<BTreeMap<IpAddr, ForkPeerRateWindow>>,
}

struct ForkListenerSecurity {
    allow_templates: bool,
    allow_unauthenticated_mutations: bool,
    peer_capability: Option<Arc<Vec<u8>>>,
    replay_state: StdMutex<ForkPeerReplayState>,
    rate_limiter: ForkPeerRateLimiter,
}

impl ForkPeerRateLimiter {
    fn observe(&self, ip: IpAddr, kind: ForkPeerMutationKind, now_unix: u64) -> Result<()> {
        let mut peers = self
            .by_ip
            .lock()
            .map_err(|_| anyhow!("fork peer rate limiter lock is poisoned"))?;
        peers.retain(|_, window| {
            now_unix.saturating_sub(window.started_at_unix) < FORK_P2P_RATE_WINDOW_SECONDS
        });
        if !peers.contains_key(&ip) && peers.len() >= MAX_P2P_RATE_LIMIT_IPS {
            bail!("fork peer rate limiter capacity exceeded");
        }
        let window = peers.entry(ip).or_insert_with(|| ForkPeerRateWindow {
            started_at_unix: now_unix,
            ..ForkPeerRateWindow::default()
        });
        if now_unix.saturating_sub(window.started_at_unix) >= FORK_P2P_RATE_WINDOW_SECONDS {
            *window = ForkPeerRateWindow {
                started_at_unix: now_unix,
                ..ForkPeerRateWindow::default()
            };
        }
        let (counter, maximum) = match kind {
            ForkPeerMutationKind::Block => {
                (&mut window.blocks, MAX_P2P_BLOCK_SUBMISSIONS_PER_WINDOW)
            }
            ForkPeerMutationKind::Transaction => (
                &mut window.transactions,
                MAX_P2P_TRANSACTION_SUBMISSIONS_PER_WINDOW,
            ),
            ForkPeerMutationKind::MempoolRead => (
                &mut window.mempool_reads,
                MAX_P2P_MEMPOOL_REQUESTS_PER_WINDOW,
            ),
        };
        *counter = counter.saturating_add(1);
        if *counter > maximum {
            bail!("fork peer request rate exceeded");
        }
        Ok(())
    }
}

impl ForkWireMethod {
    fn peer_mutation_kind(&self) -> Option<ForkPeerMutationKind> {
        match self {
            Self::SubmitBlock { .. } => Some(ForkPeerMutationKind::Block),
            Self::SubmitTransaction { .. } => Some(ForkPeerMutationKind::Transaction),
            Self::MempoolTransactions => Some(ForkPeerMutationKind::MempoolRead),
            _ => None,
        }
    }
}

fn create_peer_request_auth(request: &ForkWireRequest, capability: &[u8]) -> Result<ForkWireAuth> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let timestamp_unix = current_unix_time();
    let nonce_hex = hex::encode(nonce);
    let mac_hex = peer_request_mac(request, timestamp_unix, &nonce_hex, capability)?;
    Ok(ForkWireAuth {
        timestamp_unix,
        nonce_hex,
        mac_hex,
    })
}

fn peer_request_mac(
    request: &ForkWireRequest,
    timestamp_unix: u64,
    nonce_hex: &str,
    capability: &[u8],
) -> Result<String> {
    let payload = ForkWireAuthPayload {
        protocol_version: request.protocol_version,
        activation_id: &request.activation_id,
        transaction_upgrade_id: &request.transaction_upgrade_id,
        timestamp_unix,
        nonce_hex,
        method: &request.method,
    };
    let payload =
        serde_json::to_vec(&payload).context("failed to encode fork peer auth payload")?;
    let mut engine = HmacEngine::<sha256::Hash>::new(capability);
    engine.input(&payload);
    Ok(Hmac::<sha256::Hash>::from_engine(engine).to_string())
}

fn verify_peer_request_auth(
    request: &ForkWireRequest,
    capability: &[u8],
    replay_state: &StdMutex<ForkPeerReplayState>,
    now_unix: u64,
) -> Result<()> {
    let auth = request
        .auth
        .as_ref()
        .context("fork peer mutation request omitted authentication")?;
    if now_unix.abs_diff(auth.timestamp_unix) > FORK_P2P_AUTH_WINDOW_SECONDS {
        bail!("fork peer authentication timestamp is outside the allowed window");
    }
    if auth.nonce_hex.len() != 32
        || !auth
            .nonce_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("fork peer authentication nonce must be canonical lowercase hex");
    }
    let nonce =
        hex::decode(&auth.nonce_hex).context("fork peer authentication nonce is invalid")?;
    if nonce.len() != 16 {
        bail!("fork peer authentication nonce must be 16 bytes");
    }
    if auth.mac_hex.len() != 64
        || !auth
            .mac_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("fork peer authentication MAC must be canonical lowercase hex");
    }
    let provided_mac =
        hex::decode(&auth.mac_hex).context("fork peer authentication MAC is invalid")?;
    let expected_mac = peer_request_mac(request, auth.timestamp_unix, &auth.nonce_hex, capability)?;
    let expected_mac = hex::decode(expected_mac).expect("generated HMAC is valid hex");
    if !constant_time_bytes_eq(&provided_mac, &expected_mac) {
        bail!("fork peer authentication MAC does not match");
    }
    let mut replay = replay_state
        .lock()
        .map_err(|_| anyhow!("fork peer replay lock is poisoned"))?;
    replay
        .nonces
        .retain(|_, timestamp| now_unix.abs_diff(*timestamp) <= FORK_P2P_AUTH_WINDOW_SECONDS);
    if replay.nonces.contains_key(&auth.nonce_hex) {
        bail!("fork peer authentication nonce was already used");
    }
    if replay.nonces.len() >= MAX_P2P_AUTH_NONCES {
        bail!("fork peer authentication replay cache capacity exceeded");
    }
    replay
        .nonces
        .insert(auth.nonce_hex.clone(), auth.timestamp_unix);
    Ok(())
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn load_fork_peer_capability(datadir: &Path) -> Result<Option<Arc<Vec<u8>>>> {
    let configured = std::env::var_os(FORK_P2P_CAPABILITY_FILE_ENV).map(PathBuf::from);
    let path = configured
        .clone()
        .unwrap_or_else(|| datadir.join(DEFAULT_FORK_P2P_CAPABILITY_FILE));
    if configured.is_none() && !path.exists() {
        return Ok(None);
    }
    if path.as_os_str().is_empty() {
        bail!("{FORK_P2P_CAPABILITY_FILE_ENV} must not be empty");
    }
    let file = open_readonly_regular_file(&path, "fork peer capability")?;
    let metadata = file.metadata()?;
    validate_private_file_mode(&metadata, &path)?;
    if metadata.len() > u64::try_from(MAX_FORK_P2P_CAPABILITY_BYTES.saturating_add(2))? {
        bail!("fork peer capability file is too large");
    }
    let mut capability = Vec::new();
    file.take(u64::try_from(
        MAX_FORK_P2P_CAPABILITY_BYTES.saturating_add(3),
    )?)
    .read_to_end(&mut capability)
    .context("failed to read fork peer capability")?;
    while capability
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        capability.pop();
    }
    if !(MIN_FORK_P2P_CAPABILITY_BYTES..=MAX_FORK_P2P_CAPABILITY_BYTES).contains(&capability.len())
    {
        bail!(
            "fork peer capability must contain {MIN_FORK_P2P_CAPABILITY_BYTES}-{MAX_FORK_P2P_CAPABILITY_BYTES} bytes"
        );
    }
    Ok(Some(Arc::new(capability)))
}

pub(crate) async fn run_fork_chain_node(config: ForkChainNodeConfig) -> Result<()> {
    if config.rpc_bind_addr.port() == 0 {
        bail!("fork-chain control RPC port must not be zero");
    }
    if !config.rpc_bind_addr.ip().is_loopback() {
        bail!("fork-chain control RPC must bind to loopback");
    }
    if let Some(p2p_bind) = config.p2p_bind_addr {
        if p2p_bind.port() == 0 {
            bail!("fork-chain P2P port must not be zero");
        }
        if p2p_bind == config.rpc_bind_addr {
            bail!("fork-chain control RPC and P2P must use different bind addresses");
        }
        if !p2p_bind.ip().is_loopback() && !config.allow_non_loopback_p2p {
            bail!("non-loopback fork-chain P2P bind requires --allow-non-loopback-fork-p2p");
        }
    }
    if config.peer_addrs.len() > MAX_PEERS {
        bail!("fork-chain peer count exceeds maximum {MAX_PEERS}");
    }
    for peer in &config.peer_addrs {
        validate_peer_addr(*peer)?;
    }
    if config.sync_interval_seconds == 0 || config.sync_interval_seconds > 3_600 {
        bail!("fork-chain sync interval must be 1..=3600 seconds");
    }
    let peer_capability = load_fork_peer_capability(&config.datadir)?;
    if config
        .p2p_bind_addr
        .is_some_and(|bind_addr| !bind_addr.ip().is_loopback())
        && peer_capability.is_none()
    {
        bail!(
            "non-loopback fork-chain P2P requires a private capability file via {FORK_P2P_CAPABILITY_FILE_ENV} or {}",
            config.datadir.join(DEFAULT_FORK_P2P_CAPABILITY_FILE).display()
        );
    }
    if config
        .peer_addrs
        .iter()
        .any(|peer| !peer.ip().is_loopback())
        && peer_capability.is_none()
    {
        bail!("non-loopback fork-chain peers require an authenticated P2P capability");
    }
    let store = Arc::new(RwLock::new(ForkChainStore::open_with_transaction_upgrade(
        &config.datadir,
        &config.activation_manifest,
        config.transaction_upgrade_manifest.as_deref(),
    )?));
    let (activation_id, transaction_upgrade_id) = {
        let store = store.read().await;
        (
            store.manifest().activation_id.clone(),
            store.transaction_upgrade_id(),
        )
    };
    let peers = Arc::new(deduplicate_peers(config.peer_addrs));
    let rpc_listener = TcpListener::bind(config.rpc_bind_addr)
        .await
        .with_context(|| format!("failed to bind fork-chain RPC on {}", config.rpc_bind_addr))?;
    eprintln!(
        "fork-chain RPC listening on {} activation_id={} transaction_upgrade_id={}",
        config.rpc_bind_addr,
        activation_id,
        transaction_upgrade_id.as_deref().unwrap_or("none")
    );
    let rpc_task = tokio::spawn(serve_listener(
        rpc_listener,
        Arc::clone(&store),
        Arc::clone(&peers),
        true,
        true,
        None,
    ));
    let p2p_task = if let Some(bind_addr) = config.p2p_bind_addr {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind fork-chain P2P on {bind_addr}"))?;
        eprintln!("fork-chain P2P listening on {bind_addr}");
        Some(tokio::spawn(serve_listener(
            listener,
            Arc::clone(&store),
            Arc::clone(&peers),
            false,
            bind_addr.ip().is_loopback(),
            peer_capability.clone(),
        )))
    } else {
        None
    };
    let sync_task = if peers.is_empty() {
        None
    } else {
        Some(tokio::spawn(peer_sync_loop(
            Arc::clone(&store),
            Arc::clone(&peers),
            peer_capability.clone(),
            Duration::from_secs(config.sync_interval_seconds),
        )))
    };
    tokio::select! {
        result = supervise_task(Some(rpc_task), "fork-chain RPC") => result,
        result = supervise_task(p2p_task, "fork-chain P2P") => result,
        result = supervise_task(sync_task, "fork-chain peer sync") => result,
    }
}

async fn supervise_task(task: Option<JoinHandle<Result<()>>>, label: &str) -> Result<()> {
    let Some(task) = task else {
        return pending::<Result<()>>().await;
    };
    task.await
        .with_context(|| format!("{label} task failed"))??;
    bail!("{label} task exited unexpectedly")
}

async fn serve_listener(
    listener: TcpListener,
    store: Arc<RwLock<ForkChainStore>>,
    peers: Arc<Vec<SocketAddr>>,
    allow_templates: bool,
    allow_unauthenticated_mutations: bool,
    peer_capability: Option<Arc<Vec<u8>>>,
) -> Result<()> {
    let connections = ConnectionLimiter::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP);
    let security = Arc::new(ForkListenerSecurity {
        allow_templates,
        allow_unauthenticated_mutations,
        peer_capability,
        replay_state: StdMutex::new(ForkPeerReplayState::default()),
        rate_limiter: ForkPeerRateLimiter::default(),
    });
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Some(connection_guard) = connections.try_acquire(peer_addr.ip()) else {
            continue;
        };
        let store = Arc::clone(&store);
        let peers = Arc::clone(&peers);
        let security = Arc::clone(&security);
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Ok(Err(err)) = timeout(
                Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
                handle_connection(stream, peer_addr, store, peers, security),
            )
            .await
            {
                eprintln!("fork-chain connection failed: {err:#}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    store: Arc<RwLock<ForkChainStore>>,
    peers: Arc<Vec<SocketAddr>>,
    security: Arc<ForkListenerSecurity>,
) -> Result<()> {
    let payload = read_frame(&mut stream).await?;
    let request: ForkWireRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(err) => {
            let response = ForkWireResponse::error("invalid_request", err.to_string());
            return write_wire_response(&mut stream, &response).await;
        }
    };
    let mutation_kind = request.method.peer_mutation_kind();
    // Throttle by the TCP peer address before spending HMAC work or consuming
    // replay-cache capacity. A capability holder cannot bypass this ordering.
    let mutation_rate_limited = match mutation_kind {
        Some(kind) if !security.allow_templates => security
            .rate_limiter
            .observe(peer_addr.ip(), kind, current_unix_time())
            .is_err(),
        _ => false,
    };
    let allow_mutations = if mutation_rate_limited {
        false
    } else if security.allow_templates || security.allow_unauthenticated_mutations {
        true
    } else if mutation_kind.is_some() {
        security
            .peer_capability
            .as_deref()
            .is_some_and(|capability| {
                verify_peer_request_auth(
                    &request,
                    capability,
                    &security.replay_state,
                    current_unix_time(),
                )
                .is_ok()
            })
    } else {
        false
    };
    let response = if mutation_kind.is_some() {
        if mutation_rate_limited {
            Ok(ForkWireResponse::error(
                "rate_limited",
                "fork peer request rate exceeded",
            ))
        } else if !allow_mutations {
            Ok(ForkWireResponse::error(
                "peer_authentication",
                "fork peer mutation requires an authenticated capability",
            ))
        } else {
            handle_wire_request(&request, &store, security.allow_templates, true).await
        }
    } else {
        handle_wire_request(&request, &store, security.allow_templates, false).await
    };
    let accepted_block = match (&request.method, &response) {
        (ForkWireMethod::SubmitBlock { block_hex }, Ok(response)) if response.ok => response
            .result
            .as_ref()
            .and_then(|value| serde_json::from_value::<ForkBlockAcceptance>(value.clone()).ok())
            .filter(|accepted| accepted.accepted)
            .map(|_| block_hex.clone()),
        _ => None,
    };
    let accepted_transaction = match (&request.method, &response) {
        (ForkWireMethod::SubmitTransaction { transaction_hex }, Ok(response)) if response.ok => {
            response
                .result
                .as_ref()
                .and_then(|value| {
                    serde_json::from_value::<ForkTransactionAcceptance>(value.clone()).ok()
                })
                .filter(|accepted| accepted.accepted)
                .map(|_| transaction_hex.clone())
        }
        _ => None,
    };
    let response = response
        .unwrap_or_else(|err| ForkWireResponse::error("consensus_rejected", format!("{err:#}")));
    write_wire_response(&mut stream, &response).await?;
    if let Some(block_hex) = accepted_block {
        let (activation_id, transaction_upgrade_id) = {
            let store = store.read().await;
            (
                store.manifest().activation_id.clone(),
                store.transaction_upgrade_id(),
            )
        };
        tokio::spawn(broadcast_block(
            peers,
            activation_id,
            transaction_upgrade_id,
            security.peer_capability.clone(),
            block_hex,
        ));
    } else if let Some(transaction_hex) = accepted_transaction {
        let (activation_id, transaction_upgrade_id) = {
            let store = store.read().await;
            (
                store.manifest().activation_id.clone(),
                store.transaction_upgrade_id(),
            )
        };
        tokio::spawn(broadcast_transaction(
            peers,
            activation_id,
            transaction_upgrade_id,
            security.peer_capability.clone(),
            transaction_hex,
        ));
    }
    Ok(())
}

async fn handle_wire_request(
    request: &ForkWireRequest,
    store: &Arc<RwLock<ForkChainStore>>,
    allow_templates: bool,
    allow_mutations: bool,
) -> Result<ForkWireResponse> {
    if request.protocol_version != FORK_PROTOCOL_VERSION {
        return Ok(ForkWireResponse::error(
            "protocol_version",
            "unsupported fork-chain protocol version",
        ));
    }
    let expected_activation = store.read().await.manifest().activation_id.clone();
    if request.activation_id != expected_activation {
        return Ok(ForkWireResponse::error(
            "activation_mismatch",
            "peer uses a different fork activation",
        ));
    }
    let expected_upgrade = store.read().await.transaction_upgrade_id();
    if (!allow_templates || request.transaction_upgrade_id.is_some())
        && request.transaction_upgrade_id != expected_upgrade
    {
        return Ok(ForkWireResponse::error(
            "transaction_upgrade_mismatch",
            "peer uses a different fork transaction upgrade",
        ));
    }
    match &request.method {
        ForkWireMethod::Status => ForkWireResponse::success(store.read().await.status()),
        ForkWireMethod::MiningTemplate if allow_templates => {
            ForkWireResponse::success(store.read().await.mining_template(current_unix_time())?)
        }
        ForkWireMethod::MiningTemplate => Ok(ForkWireResponse::error(
            "method_not_allowed",
            "mining templates are available only on loopback control RPC",
        )),
        ForkWireMethod::ValidateWorkTemplate { template } if allow_templates => {
            ForkWireResponse::success(
                store
                    .read()
                    .await
                    .validate_work_template(template, current_unix_time())?,
            )
        }
        ForkWireMethod::ValidateWorkTemplate { .. } => Ok(ForkWireResponse::error(
            "method_not_allowed",
            "work-template validation is available only on loopback control RPC",
        )),
        ForkWireMethod::ValidateShare { template, share } if allow_templates => {
            ForkWireResponse::success(store.read().await.validate_share(
                template,
                share.as_ref(),
                current_unix_time(),
            )?)
        }
        ForkWireMethod::ValidateShare { .. } => Ok(ForkWireResponse::error(
            "method_not_allowed",
            "share validation is available only on loopback control RPC",
        )),
        ForkWireMethod::SubmitBlock { block_hex } if allow_mutations => {
            let result = store.write().await.submit_block(block_hex)?;
            ForkWireResponse::success(result)
        }
        ForkWireMethod::SubmitBlock { .. } => Ok(ForkWireResponse::error(
            "peer_authentication",
            "block submission requires loopback control RPC or authenticated fork P2P",
        )),
        ForkWireMethod::SubmitTransaction { transaction_hex } if allow_mutations => {
            let result = store.write().await.submit_transaction(transaction_hex)?;
            ForkWireResponse::success(result)
        }
        ForkWireMethod::SubmitTransaction { .. } => Ok(ForkWireResponse::error(
            "peer_authentication",
            "transaction submission requires loopback control RPC or authenticated fork P2P",
        )),
        ForkWireMethod::MempoolTransactions if allow_mutations => {
            ForkWireResponse::success(store.read().await.mempool_transactions())
        }
        ForkWireMethod::MempoolTransactions => Ok(ForkWireResponse::error(
            "peer_authentication",
            "mempool relay requires loopback control RPC or authenticated fork P2P",
        )),
        ForkWireMethod::ActiveBlockHash { height } => {
            ForkWireResponse::success(store.read().await.active_block_hash(*height))
        }
        ForkWireMethod::ActiveBlock { height } => {
            ForkWireResponse::success(store.read().await.active_block_hex(*height))
        }
        ForkWireMethod::BlockPage { cursor, limit } if allow_templates => {
            ForkWireResponse::success(
                store
                    .read()
                    .await
                    .block_page(cursor.as_deref(), usize::from(*limit))?,
            )
        }
        ForkWireMethod::BlockSummary { block_hash } if allow_templates => {
            ForkWireResponse::success(store.read().await.block_summary(block_hash)?)
        }
        ForkWireMethod::BlockTransactions {
            block_hash,
            cursor,
            limit,
        } if allow_templates => ForkWireResponse::success(store.read().await.block_transactions(
            block_hash,
            *cursor,
            usize::from(*limit),
        )?),
        ForkWireMethod::TransactionDetail { txid } if allow_templates => {
            ForkWireResponse::success(store.read().await.transaction_detail(txid)?)
        }
        ForkWireMethod::AddressSummary { address } if allow_templates => {
            ForkWireResponse::success(store.read().await.address_summary(address)?)
        }
        ForkWireMethod::AddressTransactions {
            address,
            cursor,
            limit,
        } if allow_templates => ForkWireResponse::success(
            store
                .read()
                .await
                .address_transactions(address, *cursor, usize::from(*limit))?,
        ),
        ForkWireMethod::AddressUtxos {
            address,
            cursor,
            limit,
        } if allow_templates => ForkWireResponse::success(store.read().await.address_utxos(
            address,
            *cursor,
            usize::from(*limit),
        )?),
        ForkWireMethod::UnspentOutput { txid, vout } if allow_templates => {
            ForkWireResponse::success(store.read().await.unspent_output(txid, *vout)?)
        }
        ForkWireMethod::BlockPage { .. }
        | ForkWireMethod::BlockSummary { .. }
        | ForkWireMethod::BlockTransactions { .. }
        | ForkWireMethod::TransactionDetail { .. }
        | ForkWireMethod::AddressSummary { .. }
        | ForkWireMethod::AddressTransactions { .. }
        | ForkWireMethod::AddressUtxos { .. }
        | ForkWireMethod::UnspentOutput { .. } => Ok(ForkWireResponse::error(
            "method_not_allowed",
            "explorer queries are available only on loopback control RPC",
        )),
    }
}

async fn peer_sync_loop(
    store: Arc<RwLock<ForkChainStore>>,
    peers: Arc<Vec<SocketAddr>>,
    peer_capability: Option<Arc<Vec<u8>>>,
    cadence: Duration,
) -> Result<()> {
    let mut ticker = interval(cadence);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        for peer in peers.iter().copied() {
            if let Err(err) = sync_from_peer(&store, peer, peer_capability.clone()).await {
                eprintln!("fork-chain peer sync from {peer} failed: {err:#}");
            }
        }
    }
}

async fn sync_from_peer(
    store: &Arc<RwLock<ForkChainStore>>,
    peer: SocketAddr,
    peer_capability: Option<Arc<Vec<u8>>>,
) -> Result<()> {
    let (activation_id, transaction_upgrade_id) = {
        let store = store.read().await;
        (
            store.manifest().activation_id.clone(),
            store.transaction_upgrade_id(),
        )
    };
    let client = ForkChainClient::new_peer(
        peer,
        activation_id,
        transaction_upgrade_id.clone(),
        peer_capability,
    )?;
    let remote = client.status().await?;
    let local = store.read().await.status();
    if remote.transaction_upgrade_id != transaction_upgrade_id {
        bail!("peer uses a different fork transaction upgrade");
    }
    let shared_floor = local.inherited_tip_height;
    let mut low = shared_floor;
    let mut high = local.tip_height.min(remote.tip_height);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let local_hash = store.read().await.active_block_hash(middle);
        let remote_hash = client.active_block_hash(middle).await?;
        if local_hash.is_some() && local_hash == remote_hash {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    for height in (low + 1)..=remote.tip_height {
        let Some(block_hex) = client.active_block_hex(height).await? else {
            bail!("peer omitted active fork block at height {height}");
        };
        store.write().await.submit_block(&block_hex)?;
    }
    for transaction_hex in client.mempool_transactions().await? {
        if let Err(err) = store.write().await.submit_transaction(&transaction_hex) {
            eprintln!("fork-chain rejected relayed mempool transaction: {err:#}");
        }
    }
    Ok(())
}

async fn broadcast_block(
    peers: Arc<Vec<SocketAddr>>,
    activation_id: String,
    transaction_upgrade_id: Option<String>,
    peer_capability: Option<Arc<Vec<u8>>>,
    block_hex: String,
) {
    for peer in peers.iter().copied() {
        let Ok(client) = ForkChainClient::new_peer(
            peer,
            activation_id.clone(),
            transaction_upgrade_id.clone(),
            peer_capability.clone(),
        ) else {
            continue;
        };
        let _ = client.submit_block(&block_hex).await;
    }
}

async fn broadcast_transaction(
    peers: Arc<Vec<SocketAddr>>,
    activation_id: String,
    transaction_upgrade_id: Option<String>,
    peer_capability: Option<Arc<Vec<u8>>>,
    transaction_hex: String,
) {
    for peer in peers.iter().copied() {
        let Ok(client) = ForkChainClient::new_peer(
            peer,
            activation_id.clone(),
            transaction_upgrade_id.clone(),
            peer_capability.clone(),
        ) else {
            continue;
        };
        let _ = client.submit_transaction(&transaction_hex).await;
    }
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let length = timeout(
        Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
        stream.read_u32(),
    )
    .await
    .context("fork-chain frame length read timed out")??;
    let length = usize::try_from(length).context("fork-chain frame length overflow")?;
    if length == 0 || length > MAX_WIRE_FRAME_BYTES {
        bail!("fork-chain frame length {length} is outside allowed bounds");
    }
    let mut payload = vec![0u8; length];
    timeout(
        Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
        stream.read_exact(&mut payload),
    )
    .await
    .context("fork-chain frame read timed out")??;
    Ok(payload)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_WIRE_FRAME_BYTES {
        bail!("fork-chain response frame is outside allowed bounds");
    }
    let length = u32::try_from(payload.len()).context("fork-chain frame length exceeds u32")?;
    timeout(
        Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
        async {
            stream.write_u32(length).await?;
            stream.write_all(payload).await?;
            stream.flush().await
        },
    )
    .await
    .context("fork-chain frame write timed out")??;
    Ok(())
}

async fn write_wire_response(stream: &mut TcpStream, response: &ForkWireResponse) -> Result<()> {
    let payload = serde_json::to_vec(response).context("failed to encode fork-chain response")?;
    write_frame(stream, &payload).await
}

pub(crate) fn read_activation_manifest(path: &Path) -> Result<ForkActivationManifest> {
    let mut file = open_readonly_regular_file(path, "fork activation manifest")?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_ACTIVATION_MANIFEST_BYTES {
        bail!("fork activation manifest exceeds size limit");
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_ACTIVATION_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("failed to read fork activation manifest {}", path.display()))?;
    if raw.len() as u64 > MAX_ACTIVATION_MANIFEST_BYTES {
        bail!("fork activation manifest exceeds size limit");
    }
    let manifest: ForkActivationManifest =
        serde_json::from_slice(&raw).context("fork activation manifest is invalid JSON")?;
    manifest
        .validate()
        .context("fork activation manifest failed integrity validation")?;
    Ok(manifest)
}

pub(crate) fn read_transaction_upgrade_manifest(
    path: &Path,
) -> Result<ForkTransactionUpgradeManifest> {
    let mut file = open_readonly_regular_file(path, "fork transaction upgrade manifest")?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_TRANSACTION_UPGRADE_MANIFEST_BYTES {
        bail!("fork transaction upgrade manifest exceeds size limit");
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_TRANSACTION_UPGRADE_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
        .with_context(|| {
            format!(
                "failed to read fork transaction upgrade manifest {}",
                path.display()
            )
        })?;
    if raw.len() as u64 > MAX_TRANSACTION_UPGRADE_MANIFEST_BYTES {
        bail!("fork transaction upgrade manifest exceeds size limit");
    }
    let manifest: ForkTransactionUpgradeManifest = serde_json::from_slice(&raw)
        .context("fork transaction upgrade manifest is invalid JSON")?;
    manifest
        .validate()
        .context("fork transaction upgrade manifest failed integrity validation")?;
    Ok(manifest)
}

fn decode_block(block_hex: &str) -> Result<Block> {
    let bytes = hex::decode(block_hex).context("fork block is invalid hex")?;
    if bytes.len() > MAX_BLOCK_BYTES {
        bail!("fork block exceeds serialized size limit");
    }
    let block: Block = deserialize(&bytes).context("fork block is not Bitcoin consensus data")?;
    if serialize(&block) != bytes {
        bail!("fork block encoding is not canonical");
    }
    Ok(block)
}

fn decode_transaction(transaction_hex: &str) -> Result<Transaction> {
    let bytes = hex::decode(transaction_hex).context("fork transaction is invalid hex")?;
    if bytes.len() > MAX_BLOCK_BYTES {
        bail!("fork transaction exceeds serialized size limit");
    }
    let transaction: Transaction =
        deserialize(&bytes).context("fork transaction is not Bitcoin consensus data")?;
    if serialize(&transaction) != bytes {
        bail!("fork transaction encoding is not canonical");
    }
    Ok(transaction)
}

fn add_transaction_outputs(
    state: &mut ForkBranchState,
    transaction: &Transaction,
    height: u64,
) -> Result<()> {
    let txid = transaction.compute_txid();
    for (vout, output) in transaction.output.iter().enumerate() {
        let vout = u32::try_from(vout).context("fork transaction output index exceeds u32")?;
        let replaced = state.utxos.insert(
            OutPoint { txid, vout },
            IndexedForkOutput {
                output: output.clone(),
                height,
                coinbase: transaction.is_coinbase(),
            },
        );
        if replaced.is_some() {
            bail!("fork transaction output collision for {txid}:{vout}");
        }
    }
    Ok(())
}

fn validate_segwit_keypath_signatures(transaction: &Transaction, prevouts: &[TxOut]) -> Result<()> {
    if prevouts.len() != transaction.input.len() {
        bail!("fork transaction previous-output count mismatch");
    }
    let secp = Secp256k1::verification_only();
    let all_prevouts = Prevouts::All(prevouts);
    for (input_index, (input, previous)) in
        transaction.input.iter().zip(prevouts.iter()).enumerate()
    {
        if previous.script_pubkey.is_p2tr() {
            if input.witness.len() != 1 {
                bail!("fork P2TR input {input_index} must contain exactly one key-path signature");
            }
            let signature_bytes = input
                .witness
                .nth(0)
                .expect("P2TR witness length was checked");
            if signature_bytes.len() != 64 {
                bail!("fork P2TR input {input_index} requires a 64-byte SIGHASH_DEFAULT signature");
            }
            let signature = taproot::Signature::from_slice(signature_bytes)
                .with_context(|| format!("fork P2TR input {input_index} signature is invalid"))?;
            if signature.sighash_type != TapSighashType::Default {
                bail!("fork P2TR input {input_index} must use SIGHASH_DEFAULT");
            }
            let script = previous.script_pubkey.as_bytes();
            let output_key = XOnlyPublicKey::from_slice(&script[2..34])
                .context("fork P2TR output key is invalid")?;
            let sighash = SighashCache::new(transaction)
                .taproot_key_spend_signature_hash(
                    input_index,
                    &all_prevouts,
                    TapSighashType::Default,
                )
                .with_context(|| {
                    format!("failed to compute fork P2TR input {input_index} sighash")
                })?;
            secp.verify_schnorr(&signature.signature, &Message::from(sighash), &output_key)
                .with_context(|| {
                    format!("fork P2TR input {input_index} signature verification failed")
                })?;
        } else if previous.script_pubkey.is_p2wpkh() {
            if input.witness.len() != 2 {
                bail!("fork P2WPKH input {input_index} must contain a signature and public key");
            }
            let signature = ecdsa::Signature::from_slice(
                input
                    .witness
                    .nth(0)
                    .expect("P2WPKH witness length was checked"),
            )
            .with_context(|| format!("fork P2WPKH input {input_index} signature is invalid"))?;
            if signature.sighash_type != bitcoin::EcdsaSighashType::All {
                bail!("fork P2WPKH input {input_index} must use SIGHASH_ALL");
            }
            let public_key = CompressedPublicKey::from_slice(
                input
                    .witness
                    .nth(1)
                    .expect("P2WPKH witness length was checked"),
            )
            .with_context(|| format!("fork P2WPKH input {input_index} public key is invalid"))?;
            let expected_script = bitcoin::ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash());
            if expected_script != previous.script_pubkey {
                bail!("fork P2WPKH input {input_index} public key does not match its output");
            }
            let sighash = SighashCache::new(transaction)
                .p2wpkh_signature_hash(
                    input_index,
                    &previous.script_pubkey,
                    previous.value,
                    bitcoin::EcdsaSighashType::All,
                )
                .with_context(|| {
                    format!("failed to compute fork P2WPKH input {input_index} sighash")
                })?;
            public_key
                .verify(&secp, &Message::from(sighash), &signature)
                .with_context(|| {
                    format!("fork P2WPKH input {input_index} signature verification failed")
                })?;
        } else {
            bail!(
                "fork input {input_index} spends an unsupported script; segwit-keypath-v1 permits only P2WPKH and P2TR key-path outputs"
            );
        }
    }
    Ok(())
}

fn witness_commitment_script(transactions: &[Transaction]) -> Result<String> {
    if transactions.is_empty() {
        bail!("fork witness commitment requires at least one non-coinbase transaction");
    }
    let mut level = Vec::with_capacity(transactions.len() + 1);
    level.push([0u8; 32]);
    for transaction in transactions {
        level.push(transaction.compute_wtxid().to_byte_array());
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
    Ok(format!("6a24aa21a9ed{}", hex::encode(commitment)))
}

fn pohw_commitment_hash(block: &Block) -> Option<String> {
    const POHW1_PAYLOAD_LEN: usize = 5 + 32;
    let coinbase = block.txdata.first()?;
    coinbase.output.iter().find_map(|output| {
        let script = output.script_pubkey.as_bytes();
        if script.len() != POHW1_PAYLOAD_LEN + 2
            || script[0] != 0x6a
            || usize::from(script[1]) != POHW1_PAYLOAD_LEN
            || &script[2..7] != b"POHW1"
        {
            return None;
        }
        Some(hex::encode(&script[7..]))
    })
}

fn validate_numeric_page(cursor: usize, limit: usize) -> Result<()> {
    if !(1..=100).contains(&limit) {
        bail!("fork explorer page limit must be between 1 and 100");
    }
    if cursor > 10_000_000 {
        bail!("fork explorer cursor exceeds the supported range");
    }
    Ok(())
}

fn transaction_ref(
    tx: &Transaction,
    block_hash: BlockHash,
    height: u64,
    active: bool,
    transaction_index: usize,
    outputs: &BTreeMap<OutPoint, IndexedForkOutput>,
) -> Result<ForkTransactionRef> {
    let (_, total_output_sats, fee_sats) = transaction_amounts(tx, outputs)?;
    Ok(ForkTransactionRef {
        txid: tx.compute_txid().to_string(),
        block_hash: block_hash.to_string(),
        height,
        active,
        transaction_index,
        coinbase: tx.is_coinbase(),
        total_output_sats,
        fee_sats,
    })
}

fn transaction_detail(
    tx: &Transaction,
    block_hash: BlockHash,
    height: u64,
    active: bool,
    transaction_index: usize,
    outputs: &BTreeMap<OutPoint, IndexedForkOutput>,
    spends: &BTreeMap<OutPoint, ForkOutputSpend>,
) -> Result<ForkTransactionDetail> {
    let (total_input_sats, total_output_sats, fee_sats) = transaction_amounts(tx, outputs)?;
    let inputs = tx
        .input
        .iter()
        .enumerate()
        .map(|(vin, input)| {
            let coinbase = tx.is_coinbase();
            ForkTransactionInput {
                vin,
                coinbase,
                previous_txid: (!coinbase).then(|| input.previous_output.txid.to_string()),
                previous_vout: (!coinbase).then_some(input.previous_output.vout),
                script_sig_hex: hex::encode(input.script_sig.as_bytes()),
                script_sig_asm: input.script_sig.to_asm_string(),
                sequence: input.sequence.0,
                witness: input.witness.iter().map(hex::encode).collect(),
                previous_output: (!coinbase)
                    .then(|| outputs.get(&input.previous_output))
                    .flatten()
                    .map(|indexed| previous_output(&indexed.output)),
            }
        })
        .collect();
    let txid = tx.compute_txid();
    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(vout, output)| {
            let vout = u32::try_from(vout).expect("Bitcoin transaction output count fits u32");
            ForkTransactionOutput {
                vout,
                value_sats: output.value.to_sat(),
                script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                script_pubkey_asm: output.script_pubkey.to_asm_string(),
                script_type: script_type(output),
                address: output_address(output),
                script_hash: output_script_hash(output),
                spent_by: active
                    .then(|| spends.get(&OutPoint { txid, vout }).cloned())
                    .flatten(),
            }
        })
        .collect::<Vec<_>>();
    Ok(ForkTransactionDetail {
        txid: txid.to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        block_hash: block_hash.to_string(),
        height,
        active,
        transaction_index,
        coinbase: tx.is_coinbase(),
        version: tx.version.0,
        lock_time: tx.lock_time.to_consensus_u32(),
        size_bytes: serialize(tx).len(),
        weight_wu: tx.weight().to_wu(),
        input_count: tx.input.len(),
        output_count: tx.output.len(),
        total_input_sats,
        total_output_sats,
        fee_sats,
        inputs,
        outputs,
    })
}

fn transaction_amounts(
    tx: &Transaction,
    outputs: &BTreeMap<OutPoint, IndexedForkOutput>,
) -> Result<(Option<u64>, u64, Option<u64>)> {
    let total_output_sats = tx.output.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value.to_sat())
            .context("fork transaction output total overflow")
    })?;
    if tx.is_coinbase() {
        return Ok((None, total_output_sats, None));
    }
    let mut total_input_sats = 0u64;
    for input in &tx.input {
        let Some(previous) = outputs.get(&input.previous_output) else {
            return Ok((None, total_output_sats, None));
        };
        total_input_sats = total_input_sats
            .checked_add(previous.output.value.to_sat())
            .context("fork transaction input total overflow")?;
    }
    let fee_sats = total_input_sats.checked_sub(total_output_sats);
    Ok((Some(total_input_sats), total_output_sats, fee_sats))
}

fn previous_output(output: &TxOut) -> ForkPreviousOutput {
    ForkPreviousOutput {
        value_sats: output.value.to_sat(),
        script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
        script_pubkey_asm: output.script_pubkey.to_asm_string(),
        script_type: script_type(output),
        address: output_address(output),
        script_hash: output_script_hash(output),
    }
}

fn output_address(output: &TxOut) -> Option<String> {
    Address::from_script(&output.script_pubkey, Network::Bitcoin)
        .ok()
        .map(|address| address.to_string())
}

fn normalize_mainnet_address(raw: &str) -> Result<String> {
    if raw.len() > 128 || raw.trim() != raw {
        bail!("fork explorer address is malformed");
    }
    let address = Address::<NetworkUnchecked>::from_str(raw)
        .context("fork explorer address is not a Bitcoin address")?
        .require_network(Network::Bitcoin)
        .context("fork explorer address is not a Bitcoin mainnet address")?;
    Ok(address.to_string())
}

fn script_type(output: &TxOut) -> String {
    let script = &output.script_pubkey;
    let kind = if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "v0_p2wpkh"
    } else if script.is_p2wsh() {
        "v0_p2wsh"
    } else if script.is_p2tr() {
        "v1_p2tr"
    } else if script.is_p2pk() {
        "p2pk"
    } else if script.is_op_return() {
        "op_return"
    } else if script.is_witness_program() {
        "witness_unknown"
    } else {
        "nonstandard"
    };
    kind.to_string()
}

fn output_script_hash(output: &TxOut) -> String {
    sha256::Hash::hash(output.script_pubkey.as_bytes()).to_string()
}

fn update_height_range(first: &mut Option<u64>, last: &mut Option<u64>, height: u64) {
    *first = Some(first.map_or(height, |current| current.min(height)));
    *last = Some(last.map_or(height, |current| current.max(height)));
}

fn decode_header_prefix(header_prefix_hex: &str) -> Result<bitcoin::block::Header> {
    if header_prefix_hex.len() != 76 * 2
        || !header_prefix_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("fork work template header prefix must be 76 bytes encoded as hex");
    }
    let mut bytes = hex::decode(header_prefix_hex).context("invalid fork header prefix hex")?;
    bytes.extend_from_slice(&[0u8; 4]);
    deserialize(&bytes).context("fork work template header prefix is invalid")
}

fn normalize_block_hex(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() % 2 != 0 || raw.len() > MAX_BLOCK_HEX_BYTES {
        bail!("fork block hex length is outside allowed bounds");
    }
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("fork block contains non-hex characters");
    }
    Ok(raw.to_ascii_lowercase())
}

fn normalize_transaction_hex(raw: &str) -> Result<String> {
    if raw.is_empty()
        || raw.len() % 2 != 0
        || raw.len() > MAX_MEMPOOL_TRANSACTION_BYTES.saturating_mul(2)
    {
        bail!("fork transaction hex length is outside allowed bounds");
    }
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("fork transaction contains non-hex characters");
    }
    Ok(raw.to_ascii_lowercase())
}

fn checked_mempool_bytes(current: usize, transaction_bytes: usize) -> Result<usize> {
    let next = current
        .checked_add(transaction_bytes)
        .context("fork transaction mempool byte count overflow")?;
    if next > MAX_MEMPOOL_BYTES {
        bail!("fork transaction mempool byte limit exceeded");
    }
    Ok(next)
}

fn validate_coinbase_height(coinbase: &bitcoin::Transaction, height: u64) -> Result<()> {
    let input = coinbase
        .input
        .first()
        .ok_or_else(|| anyhow!("fork coinbase has no input"))?;
    let script = input.script_sig.as_bytes();
    if !(2..=100).contains(&script.len()) {
        bail!("fork coinbase scriptSig length must be 2..=100 bytes");
    }
    let encoded_height = minimal_script_number(height);
    if encoded_height.len() > 75 {
        bail!("fork block height script number is too large");
    }
    let mut expected = Vec::with_capacity(encoded_height.len() + 1);
    expected.push(encoded_height.len() as u8);
    expected.extend_from_slice(&encoded_height);
    if !script.starts_with(&expected) {
        bail!("fork coinbase does not begin with the minimally encoded BIP34 height {height}");
    }
    Ok(())
}

fn validate_coinbase_reward(
    coinbase: &bitcoin::Transaction,
    height: u64,
    fees_sats: u64,
) -> Result<()> {
    let mut total = 0u64;
    for output in &coinbase.output {
        let amount = output.value.to_sat();
        if amount > MAX_MONEY_SATS {
            bail!("fork coinbase output exceeds MAX_MONEY");
        }
        total = total
            .checked_add(amount)
            .context("fork coinbase output sum overflow")?;
    }
    let allowed = block_subsidy_sats(height)
        .checked_add(fees_sats)
        .context("fork coinbase subsidy plus fees overflow")?;
    if total > allowed {
        bail!("fork coinbase pays {total} sats but subsidy plus fees are only {allowed} sats");
    }
    Ok(())
}

fn block_subsidy_sats(height: u64) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        0
    } else {
        50u64.saturating_mul(100_000_000) >> halvings
    }
}

fn minimal_script_number(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
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
    bytes
}

fn validate_activation_id(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("fork activation id must be 32 bytes encoded as hex");
    }
    Ok(())
}

fn deduplicate_peers(peers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    peers
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn validate_peer_addr(addr: SocketAddr) -> Result<()> {
    if addr.port() == 0 {
        bail!("fork-chain peer port must not be zero");
    }
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() => {
            bail!("fork-chain peer address is not usable unicast")
        }
        IpAddr::V6(ip) if ip.is_unspecified() || ip.is_multicast() => {
            bail!("fork-chain peer address is not usable unicast")
        }
        _ => Ok(()),
    }
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("fork-chain datadir must not be empty");
    }
    reject_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("fork-chain datadir must be a regular directory");
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(path).with_context(|| {
                    format!("failed to create fork-chain datadir {}", path.display())
                })?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(path).with_context(|| {
                format!("failed to create fork-chain datadir {}", path.display())
            })?;
        }
        Err(err) => return Err(err).context("failed to inspect fork-chain datadir"),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!("fork-chain datadir must not be group/world writable");
        }
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool) -> Result<File> {
    reject_symlink_ancestors(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open fork-chain file {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("fork-chain path is not a regular file: {}", path.display());
    }
    validate_private_file_mode(&metadata, path)?;
    Ok(file)
}

fn open_private_append_file(path: &Path) -> Result<File> {
    reject_symlink_ancestors(path)?;
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open fork-chain log {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("fork-chain log is not a regular file: {}", path.display());
    }
    validate_private_file_mode(&metadata, path)?;
    Ok(file)
}

fn open_readonly_regular_file(path: &Path, label: &str) -> Result<File> {
    reject_symlink_ancestors(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_private_file_mode(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "fork-chain file {} is too permissive ({mode:o}); use chmod 600",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_mode(_metadata: &fs::Metadata, _path: &Path) -> Result<()> {
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for fork-chain path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.uid() == 0 {
                        continue;
                    }
                }
                bail!(
                    "fork-chain path has unsafe symlink ancestor {}",
                    ancestor.display()
                )
            }
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect fork-chain ancestor {}",
                        ancestor.display()
                    )
                })
            }
        }
    }
    Ok(())
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .context("failed to buffer fork block log")?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(buffer.len());
        if line.len().saturating_add(take) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fork block log line exceeds size limit",
            )
            .into());
        }
        line.extend_from_slice(&buffer[..take]);
        let consumed = take + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn repair_truncated_block_log_tail(file: &mut File, path: &Path) -> Result<()> {
    const SCAN_CHUNK_BYTES: u64 = 64 * 1024;

    let length = file.metadata()?.len();
    if length == 0 {
        file.seek(SeekFrom::Start(0))?;
        return Ok(());
    }

    file.seek(SeekFrom::End(-1))?;
    let mut final_byte = [0u8; 1];
    file.read_exact(&mut final_byte)?;
    if final_byte[0] == b'\n' {
        file.seek(SeekFrom::Start(0))?;
        return Ok(());
    }

    let mut search_end = length;
    let mut truncate_to = 0u64;
    while search_end > 0 {
        let search_start = search_end.saturating_sub(SCAN_CHUNK_BYTES);
        let chunk_length = usize::try_from(search_end - search_start)
            .context("fork block log tail scan length overflow")?;
        let mut chunk = vec![0u8; chunk_length];
        file.seek(SeekFrom::Start(search_start))?;
        file.read_exact(&mut chunk)?;
        if let Some(position) = chunk.iter().rposition(|byte| *byte == b'\n') {
            truncate_to = search_start
                .checked_add(u64::try_from(position + 1)?)
                .context("fork block log recovery offset overflow")?;
            break;
        }
        search_end = search_start;
    }

    let tail_length = length
        .checked_sub(truncate_to)
        .context("fork block log recovery length underflow")?;
    if tail_length > u64::try_from(MAX_BLOCK_LOG_LINE_BYTES)? {
        file.seek(SeekFrom::Start(0))?;
        return Ok(());
    }
    let mut tail = vec![0u8; usize::try_from(tail_length)?];
    file.seek(SeekFrom::Start(truncate_to))?;
    file.read_exact(&mut tail)?;
    match serde_json::from_slice::<ForkBlockRecord>(&tail) {
        Ok(_) => {
            // A crash after the record write but before the newline leaves a complete
            // record, but the delimiter must be restored before the next append.
            file.seek(SeekFrom::End(0))?;
            file.write_all(b"\n").with_context(|| {
                format!(
                    "failed to restore fork block log delimiter {}",
                    path.display()
                )
            })?;
            file.sync_all().with_context(|| {
                format!(
                    "failed to sync restored fork block log delimiter {}",
                    path.display()
                )
            })?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            file.seek(SeekFrom::Start(0))?;
            return Ok(());
        }
        Err(error) if error.classify() == serde_json::error::Category::Eof => {}
        Err(_) => {
            // Non-EOF corruption remains in place so normal replay fails closed.
            file.seek(SeekFrom::Start(0))?;
            return Ok(());
        }
    }

    file.set_len(truncate_to).with_context(|| {
        format!(
            "failed to remove incomplete fork block log tail {}",
            path.display()
        )
    })?;
    file.sync_all()
        .with_context(|| format!("failed to sync recovered fork block log {}", path.display()))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    file.seek(SeekFrom::Start(0))?;
    eprintln!("warning: removed an incomplete final fork block log record after restart");
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

fn current_unix_time() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining_adapter::{build_stratum_block_candidate, build_stratum_job_from_template};
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::hashes::Hash;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::transaction::Version as TransactionVersion;
    use bitcoin::{
        Amount, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use chrono::{TimeZone, Utc};
    use pohw_core::fork::{
        ForkConfig, ForkPoint, ForkTransactionConsensus, ForkTransactionUpgradeManifest,
        MainnetBlockRef,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn manifest() -> ForkActivationManifest {
        let launch = Utc.with_ymd_and_hms(2026, 7, 13, 0, 0, 0).unwrap();
        manifest_with_config(ForkConfig::no_value_testnet("pohw-experiment-0", launch))
    }

    fn manifest_with_config(config: ForkConfig) -> ForkActivationManifest {
        let launch = config.launch_timestamp_utc;
        ForkActivationManifest::new(
            config,
            ForkPoint {
                inherited_tip_height: 957_774,
                inherited_tip_hash: "11".repeat(32),
                first_fork_height: 957_775,
                launch_timestamp_utc: launch,
            },
            MainnetBlockRef {
                height: 957_775,
                block_hash: "22".repeat(32),
                timestamp: launch,
            },
        )
        .unwrap()
    }

    fn write_manifest(dir: &Path) -> PathBuf {
        write_manifest_value(dir, &manifest())
    }

    fn write_manifest_value(dir: &Path, manifest: &ForkActivationManifest) -> PathBuf {
        let path = dir.join("fork-activation.json");
        fs::write(&path, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
        path
    }

    fn write_transaction_upgrade(
        dir: &Path,
        activation: &ForkActivationManifest,
        activation_height: u64,
        coinbase_maturity: u64,
    ) -> PathBuf {
        let manifest = ForkTransactionUpgradeManifest::new(
            &activation.activation_id,
            activation_height,
            ForkTransactionConsensus::SegwitKeypathV1,
            coinbase_maturity,
            1_000,
            400_000,
        )
        .unwrap();
        let path = dir.join("fork-transaction-upgrade.json");
        fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        path
    }

    fn coinbase(height: u64, amount: u64) -> Transaction {
        coinbase_to_script(height, amount, ScriptBuf::new_op_return([]))
    }

    fn coinbase_to_script(height: u64, amount: u64, script_pubkey: ScriptBuf) -> Transaction {
        let height_number = minimal_script_number(height);
        let mut script = vec![height_number.len() as u8];
        script.extend_from_slice(&height_number);
        script.extend_from_slice(b"POHW0-test");
        Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey,
            }],
        }
    }

    fn mine_block(previous: BlockHash, height: u64, time: u32, amount: u64) -> Block {
        mine_block_with_bits(previous, height, time, amount, 0x207f_ffff)
    }

    fn mine_block_with_bits(
        previous: BlockHash,
        height: u64,
        time: u32,
        amount: u64,
        bits: u32,
    ) -> Block {
        let tx = coinbase(height, amount);
        let mut block = Block {
            header: Header {
                version: BlockVersion::from_consensus(0x2000_0000),
                prev_blockhash: previous,
                merkle_root: tx.compute_txid().to_raw_hash().into(),
                time,
                bits: CompactTarget::from_consensus(bits),
                nonce: test_nonce_seed(time, bits),
            },
            txdata: vec![tx],
        };
        let target = Target::from_compact(block.header.bits);
        while !target.is_met_by(block.block_hash()) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    }

    fn mine_block_to_script(
        previous: BlockHash,
        height: u64,
        time: u32,
        amount: u64,
        script_pubkey: ScriptBuf,
    ) -> Block {
        let tx = coinbase_to_script(height, amount, script_pubkey);
        let mut block = Block {
            header: Header {
                version: BlockVersion::from_consensus(FORK_BLOCK_VERSION),
                prev_blockhash: previous,
                merkle_root: tx.compute_txid().to_raw_hash().into(),
                time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: test_nonce_seed(time, 0x207f_ffff),
            },
            txdata: vec![tx],
        };
        let target = Target::from_compact(block.header.bits);
        while !target.is_met_by(block.block_hash()) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    }

    fn signed_p2tr_spend(
        keypair: &Keypair,
        previous_output: OutPoint,
        previous_txout: TxOut,
        output_value_sats: u64,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let mut transaction = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value_sats),
                script_pubkey: previous_txout.script_pubkey.clone(),
            }],
        };
        let prevouts = [previous_txout];
        let sighash = SighashCache::new(&transaction)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = keypair.tap_tweak(&secp, None);
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from(sighash), tweaked.as_keypair());
        transaction.input[0].witness = Witness::p2tr_key_spend(&taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
        transaction
    }

    fn test_nonce_seed(time: u32, bits: u32) -> u32 {
        time.rotate_left(13) ^ bits.rotate_right(7)
    }

    fn reset_test_nonce(block: &mut Block) {
        block.header.nonce = test_nonce_seed(block.header.time, block.header.bits.to_consensus());
    }

    #[test]
    fn accepts_and_replays_coinbase_only_fork_blocks() {
        let dir = test_dir("pohw-fork-chain-store");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let first = mine_block(inherited, 957_775, 1_783_900_801, 0);
        let first_hex = hex::encode(serialize(&first));
        {
            let mut store = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
            let accepted = store.submit_block(&first_hex).unwrap();
            assert!(accepted.accepted);
            assert_eq!(accepted.height, 957_775);
            assert_eq!(store.status().active_fork_block_count, 1);
            let template = store.mining_template(1_783_900_802).unwrap();
            assert_eq!(template.height, 957_776);
            assert_eq!(template.previous_block_hash, first.block_hash().to_string());
            assert!(template.transactions.is_empty());

            let page = store.block_page(None, 25).unwrap();
            assert_eq!(page.total, 1);
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].block_hash, first.block_hash().to_string());
            assert_eq!(page.items[0].height, 957_775);
            assert!(page.items[0].active);
            assert_eq!(page.items[0].transaction_count, 1);
            assert_eq!(page.items[0].coinbase_value_sats, 0);
            assert!(page.items[0].pohw_commitment_hash.is_none());
            assert!(page.next_cursor.is_none());
            assert_eq!(
                store
                    .block_summary(&first.block_hash().to_string())
                    .unwrap()
                    .map(|block| block.block_hash),
                Some(first.block_hash().to_string())
            );
        }
        let reopened = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        assert_eq!(reopened.status().tip_hash, first.block_hash().to_string());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn transaction_upgrade_spends_fork_created_p2tr_utxo_and_replays() {
        let dir = test_dir("pohw-fork-chain-transactions");
        let activation = manifest();
        let manifest_path = write_manifest_value(&dir, &activation);
        let upgrade_path = write_transaction_upgrade(&dir, &activation, 957_776, 1);
        let chain_dir = dir.join("chain");
        let inherited = BlockHash::from_str(&activation.fork_point.inherited_tip_hash).unwrap();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let internal_key = keypair.x_only_public_key().0;
        let vault_script = ScriptBuf::new_p2tr(&secp, internal_key, None);
        let first = mine_block_to_script(
            inherited,
            957_775,
            1_783_900_801,
            50_000,
            vault_script.clone(),
        );
        let first_txid = first.txdata[0].compute_txid();
        let previous_txout = first.txdata[0].output[0].clone();

        {
            let mut store = ForkChainStore::open_with_transaction_upgrade(
                &chain_dir,
                &manifest_path,
                Some(&upgrade_path),
            )
            .unwrap();
            store.submit_block(&hex::encode(serialize(&first))).unwrap();
            assert_eq!(store.status().transaction_activation_height, Some(957_776));

            let mut invalid = signed_p2tr_spend(
                &keypair,
                OutPoint::new(first_txid, 0),
                previous_txout.clone(),
                48_999,
            );
            let mut invalid_signature = invalid.input[0].witness.nth(0).unwrap().to_vec();
            invalid_signature[0] ^= 1;
            invalid.input[0].witness = Witness::from_slice(&[invalid_signature]);
            assert!(store
                .submit_transaction(&hex::encode(serialize(&invalid)))
                .unwrap_err()
                .to_string()
                .contains("signature verification failed"));

            let spend = signed_p2tr_spend(
                &keypair,
                OutPoint::new(first_txid, 0),
                previous_txout,
                49_000,
            );
            let accepted = store
                .submit_transaction(&hex::encode(serialize(&spend)))
                .unwrap();
            assert!(accepted.accepted);
            assert_eq!(accepted.fee_sats, 1_000);
            assert_eq!(store.status().mempool_transaction_count, 1);

            let material = store.mining_template(1_783_900_802).unwrap();
            assert_eq!(material.height, 957_776);
            assert_eq!(
                material.transaction_hashes,
                vec![spend.compute_txid().to_string()]
            );
            assert_eq!(
                material.coinbase_value_sats,
                block_subsidy_sats(material.height) + 1_000
            );
            assert!(material.default_witness_commitment.is_some());
            let job = build_stratum_job_from_template(&material, 4).unwrap().job;
            let candidate = build_stratum_block_candidate(
                &job, "01020304", "05060708", &job.ntime, "00000000", 4, false,
            )
            .unwrap();
            let mut block = decode_block(candidate.block_hex.as_deref().unwrap()).unwrap();
            let target = Target::from_compact(block.header.bits);
            while !target.is_met_by(block.block_hash()) {
                block.header.nonce = block.header.nonce.wrapping_add(1);
            }
            store.submit_block(&hex::encode(serialize(&block))).unwrap();
            assert_eq!(store.status().mempool_transaction_count, 0);
            assert!(store
                .unspent_output(&first_txid.to_string(), 0)
                .unwrap()
                .is_none());
            let spend_output = store
                .unspent_output(&spend.compute_txid().to_string(), 0)
                .unwrap()
                .unwrap();
            assert_eq!(spend_output.value_sats, 49_000);
            assert_eq!(spend_output.confirmations, 1);
        }

        let reopened = ForkChainStore::open_with_transaction_upgrade(
            &chain_dir,
            &manifest_path,
            Some(&upgrade_path),
        )
        .unwrap();
        assert_eq!(reopened.status().active_fork_block_count, 2);
        drop(reopened);
        let legacy_open_error = match ForkChainStore::open(&chain_dir, &manifest_path) {
            Ok(_) => panic!("legacy store unexpectedly opened upgraded fork history"),
            Err(error) => error,
        };
        assert!(legacy_open_error
            .to_string()
            .contains("exactly one coinbase"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_repairs_only_an_incomplete_final_block_record() {
        let dir = test_dir("pohw-fork-chain-truncated-tail");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let first = mine_block(inherited, 957_775, 1_783_900_801, 0);
        {
            let mut store = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
            store.submit_block(&hex::encode(serialize(&first))).unwrap();
        }

        let log_path = chain_dir.join("fork-blocks.ndjson");
        let durable_length = fs::metadata(&log_path).unwrap().len();
        {
            let mut log = OpenOptions::new().append(true).open(&log_path).unwrap();
            log.write_all(br#"{"schema_version":1"#).unwrap();
            log.sync_all().unwrap();
        }

        let reopened = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        assert_eq!(reopened.status().tip_hash, first.block_hash().to_string());
        assert_eq!(fs::metadata(&log_path).unwrap().len(), durable_length);
        assert!(fs::read(&log_path).unwrap().ends_with(b"\n"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_restores_the_delimiter_after_a_complete_final_record() {
        let dir = test_dir("pohw-fork-chain-complete-tail");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let first = mine_block(inherited, 957_775, 1_783_900_801, 0);
        {
            let mut store = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
            store.submit_block(&hex::encode(serialize(&first))).unwrap();
        }

        let log_path = chain_dir.join("fork-blocks.ndjson");
        let length_with_newline = fs::metadata(&log_path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&log_path)
            .unwrap()
            .set_len(length_with_newline - 1)
            .unwrap();

        let second = {
            let mut reopened = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
            assert_eq!(reopened.status().tip_hash, first.block_hash().to_string());
            assert_eq!(fs::metadata(&log_path).unwrap().len(), length_with_newline);
            assert!(fs::read(&log_path).unwrap().ends_with(b"\n"));
            let template = reopened.mining_template(1_783_900_802).unwrap();
            let bits = u32::from_str_radix(&template.bits, 16).unwrap();
            let second = mine_block_with_bits(
                first.block_hash(),
                template.height,
                template.curtime,
                0,
                bits,
            );
            reopened
                .submit_block(&hex::encode(serialize(&second)))
                .unwrap();
            second
        };

        let reopened_again = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        assert_eq!(
            reopened_again.status().tip_hash,
            second.block_hash().to_string()
        );
        assert_eq!(fs::read_to_string(&log_path).unwrap().lines().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_fails_closed_on_complete_malformed_record() {
        let dir = test_dir("pohw-fork-chain-malformed-tail");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        fs::create_dir_all(&chain_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&chain_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let log_path = chain_dir.join("fork-blocks.ndjson");
        fs::write(&log_path, b"not-json\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = ForkChainStore::open(&chain_dir, &manifest_path)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("invalid JSON"));
        assert_eq!(fs::read(&log_path).unwrap(), b"not-json\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn block_summary_detects_pohw1_commitment_without_exposing_coinbase_hex() {
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let mut block = mine_block(inherited, 957_775, 1_783_900_801, 0);
        let commitment_hash = "ab".repeat(32);
        let mut script = vec![0x6a, 37];
        script.extend_from_slice(b"POHW1");
        script.extend_from_slice(&hex::decode(&commitment_hash).unwrap());
        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(script);
        assert_eq!(pohw_commitment_hash(&block), Some(commitment_hash));
    }

    #[test]
    fn fork_explorer_decodes_transactions_addresses_and_utxos() {
        let dir = test_dir("pohw-fork-transaction-explorer");
        let manifest = manifest();
        let manifest_path = write_manifest_value(&dir, &manifest);
        let mut store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
        let inherited = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash).unwrap();
        let mut block = mine_block(
            inherited,
            manifest.fork_point.first_fork_height,
            1_783_900_801,
            123,
        );
        block.txdata[0].output[0].script_pubkey =
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([7u8; 20]));
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        reset_test_nonce(&mut block);
        let target = Target::from_compact(block.header.bits);
        while !target.is_met_by(block.block_hash()) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        store
            .submit_block_at_time(
                &hex::encode(serialize(&block)),
                u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
            )
            .unwrap();

        let txid = block.txdata[0].compute_txid().to_string();
        let page = store
            .block_transactions(&block.block_hash().to_string(), 0, 25)
            .unwrap()
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].txid, txid);
        assert!(page.items[0].coinbase);

        let detail = store.transaction_detail(&txid).unwrap().unwrap();
        assert!(detail.active);
        assert!(detail.coinbase);
        assert_eq!(detail.total_output_sats, 123);
        assert_eq!(detail.outputs[0].script_type, "p2pkh");
        assert!(detail.outputs[0].spent_by.is_none());
        let address = detail.outputs[0].address.clone().unwrap();

        let summary = store.address_summary(&address).unwrap();
        assert_eq!(summary.transaction_count, 1);
        assert_eq!(summary.funded_output_count, 1);
        assert_eq!(summary.balance_sats, 123);
        let transactions = store.address_transactions(&address, 0, 25).unwrap();
        assert_eq!(transactions.total, 1);
        assert_eq!(transactions.items[0].txid, txid);
        let utxos = store.address_utxos(&address, 0, 25).unwrap();
        assert_eq!(utxos.total, 1);
        assert_eq!(utxos.items[0].value_sats, 123);
        assert!(store.address_summary("not-an-address").is_err());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bootstrap_daa_adjusts_each_block_and_rejects_stale_bits() {
        let dir = test_dir("pohw-fork-chain-bootstrap-daa");
        let manifest = manifest();
        let manifest_path = write_manifest_value(&dir, &manifest);
        let mut store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
        let inherited = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash).unwrap();
        let first_time =
            u32::try_from(manifest.config.launch_timestamp_utc.timestamp()).unwrap() + 1;
        let first = mine_block(
            inherited,
            manifest.fork_point.first_fork_height,
            first_time,
            0,
        );
        store
            .submit_block_at_time(
                &hex::encode(serialize(&first)),
                u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
            )
            .unwrap();

        let second_height = manifest.fork_point.first_fork_height + 1;
        let second_time = first_time + 1;
        let expected_harder = store
            .next_difficulty(Some(first.block_hash()), second_height, second_time)
            .unwrap()
            .bits;
        assert_eq!(
            expected_harder,
            Target::from_compact(first.header.bits)
                .min_transition_threshold()
                .to_compact_lossy()
        );

        let stale = mine_block(first.block_hash(), second_height, second_time, 0);
        assert!(store
            .submit_block_at_time(
                &hex::encode(serialize(&stale)),
                u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
            )
            .unwrap_err()
            .to_string()
            .contains("difficulty"));

        let second = mine_block_with_bits(
            first.block_hash(),
            second_height,
            second_time,
            0,
            expected_harder.to_consensus(),
        );
        store
            .submit_block_at_time(
                &hex::encode(serialize(&second)),
                u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
            )
            .unwrap();
        assert_eq!(store.status().difficulty_phase, "bootstrap");

        let third_height = second_height + 1;
        let third_time =
            second_time + u32::try_from(4 * manifest.config.target_spacing_seconds).unwrap();
        let expected_easier = store
            .next_difficulty(Some(second.block_hash()), third_height, third_time)
            .unwrap()
            .bits;
        assert!(Target::from_compact(expected_easier) > Target::from_compact(expected_harder));
        assert!(
            Target::from_compact(expected_easier)
                <= Target::from_compact(CompactTarget::from_consensus(
                    manifest.config.post_fork_pow_limit_bits
                ))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hashrate_handoff_is_irreversible_and_survives_replay() {
        let dir = test_dir("pohw-fork-chain-handoff");
        let launch = Utc.with_ymd_and_hms(2026, 7, 13, 0, 0, 0).unwrap();
        let mut config = ForkConfig::no_value_testnet("pohw-experiment-0", launch);
        config.target_spacing_seconds = 4;
        config.bootstrap_handoff_hashrate_hps = 2;
        let manifest = manifest_with_config(config);
        let manifest_path = write_manifest_value(&dir, &manifest);
        let chain_dir = dir.join("chain");
        let inherited = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash).unwrap();
        let first_height = manifest.fork_point.first_fork_height;
        let first_time = u32::try_from(launch.timestamp()).unwrap() + 1;

        {
            let mut store = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
            let first = mine_block(inherited, first_height, first_time, 0);
            store
                .submit_block_at_time(
                    &hex::encode(serialize(&first)),
                    u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
                )
                .unwrap();
            assert_eq!(store.status().difficulty_phase, "bootstrap");

            let second_height = first_height + 1;
            let second_time = first_time + 1;
            let second_bits = store
                .next_difficulty(Some(first.block_hash()), second_height, second_time)
                .unwrap()
                .bits;
            let second = mine_block_with_bits(
                first.block_hash(),
                second_height,
                second_time,
                0,
                second_bits.to_consensus(),
            );
            store
                .submit_block_at_time(
                    &hex::encode(serialize(&second)),
                    u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
                )
                .unwrap();
            let handoff_status = store.status();
            assert_eq!(handoff_status.difficulty_phase, "bitcoin_2016");
            assert_eq!(
                handoff_status.blocks_until_bitcoin_retarget,
                Some(BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL)
            );

            let third_height = second_height + 1;
            let third_time = second_time + 1_000;
            let third_difficulty = store
                .next_difficulty(Some(second.block_hash()), third_height, third_time)
                .unwrap();
            assert_eq!(third_difficulty.bits, second_bits);
            assert!(matches!(
                third_difficulty.phase,
                DifficultyPhase::Bitcoin { .. }
            ));
            let third = mine_block_with_bits(
                second.block_hash(),
                third_height,
                third_time,
                0,
                third_difficulty.bits.to_consensus(),
            );
            store
                .submit_block_at_time(
                    &hex::encode(serialize(&third)),
                    u64::MAX - MAX_FUTURE_BLOCK_SECONDS,
                )
                .unwrap();
            assert_eq!(store.status().difficulty_phase, "bitcoin_2016");
        }

        let reopened = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        assert_eq!(reopened.status().difficulty_phase, "bitcoin_2016");
        assert_eq!(
            reopened.status().blocks_until_bitcoin_retarget,
            Some(BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_zero_difficulty_retarget_timespan() {
        let err = next_work_required_v1(
            CompactTarget::from_consensus(0x1d00_ffff),
            1,
            0,
            0x1d00_ffff,
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("fork difficulty target timespan must be non-zero"));
    }

    #[test]
    fn bitcoin_phase_uses_the_standard_2016_block_retarget_boundary() {
        let dir = test_dir("pohw-fork-chain-bitcoin-retarget");
        let manifest_path = write_manifest(&dir);
        let mut store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
        let epoch_start_height = manifest().fork_point.first_fork_height;
        let epoch_start_time = 1_700_000_000;
        let parent_height = epoch_start_height + BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL - 1;
        let parent_time =
            epoch_start_time + (BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL as u32 - 1) * 300;
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let early_height = epoch_start_height + 99;
        let early_time = epoch_start_time + 99 * 600;
        let mut early_block = mine_block(inherited, early_height, early_time, 0);
        early_block.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
        let early_hash = early_block.block_hash();
        let early_bits = early_block.header.bits;
        store.blocks.insert(
            early_hash,
            BlockNode {
                block: early_block,
                block_hex: String::new(),
                height: early_height,
                cumulative_work: Target::from_compact(early_bits).to_work(),
                difficulty_phase: DifficultyPhase::Bitcoin {
                    epoch_start_height,
                    epoch_start_time,
                },
            },
        );
        let mut parent_block = mine_block(inherited, parent_height, parent_time, 0);
        parent_block.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
        let parent_hash = parent_block.block_hash();
        let parent_bits = parent_block.header.bits;
        store.blocks.insert(
            parent_hash,
            BlockNode {
                block: parent_block,
                block_hex: String::new(),
                height: parent_height,
                cumulative_work: Target::from_compact(parent_bits).to_work(),
                difficulty_phase: DifficultyPhase::Bitcoin {
                    epoch_start_height,
                    epoch_start_time,
                },
            },
        );

        let before_boundary = store
            .next_difficulty(Some(early_hash), early_height + 1, early_time + 600)
            .unwrap();
        assert_eq!(before_boundary.bits, early_bits);
        assert_eq!(
            before_boundary.phase,
            DifficultyPhase::Bitcoin {
                epoch_start_height,
                epoch_start_time,
            }
        );

        let boundary_height = epoch_start_height + BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL;
        let boundary_time = parent_time + 600;
        let boundary = store
            .next_difficulty(Some(parent_hash), boundary_height, boundary_time)
            .unwrap();
        let expected = CompactTarget::from_next_work_required(
            parent_bits,
            u64::from(parent_time - epoch_start_time),
            bitcoin::consensus::Params::MAINNET,
        );
        assert_eq!(boundary.bits, expected);
        assert_ne!(boundary.bits, parent_bits);
        assert_eq!(
            boundary.phase,
            DifficultyPhase::Bitcoin {
                epoch_start_height: boundary_height,
                epoch_start_time: boundary_time,
            }
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_wrong_parent_reward_height_and_merkle_root() {
        let dir = test_dir("pohw-fork-chain-reject");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        let mut store = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();

        let wrong_parent = mine_block(BlockHash::all_zeros(), 957_775, 1_783_900_801, 0);
        assert!(store
            .submit_block(&hex::encode(serialize(&wrong_parent)))
            .is_err());

        let wrong_height = mine_block(inherited, 957_776, 1_783_900_801, 0);
        assert!(store
            .submit_block(&hex::encode(serialize(&wrong_height)))
            .is_err());

        let excessive = mine_block(
            inherited,
            957_775,
            1_783_900_801,
            block_subsidy_sats(957_775) + 1,
        );
        assert!(store
            .submit_block(&hex::encode(serialize(&excessive)))
            .is_err());

        let mut bad_merkle = mine_block(inherited, 957_775, 1_783_900_801, 0);
        bad_merkle.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
        while !bad_merkle
            .header
            .target()
            .is_met_by(bad_merkle.block_hash())
        {
            bad_merkle.header.nonce = bad_merkle.header.nonce.wrapping_add(1);
        }
        assert!(store
            .submit_block(&hex::encode(serialize(&bad_merkle)))
            .is_err());

        let future_time =
            u32::try_from(current_unix_time() + MAX_FUTURE_BLOCK_SECONDS + 1).unwrap();
        let future = mine_block(inherited, 957_775, future_time, 0);
        assert!(store
            .submit_block(&hex::encode(serialize(&future)))
            .unwrap_err()
            .to_string()
            .contains("future"));

        let mut wrong_bits = mine_block(inherited, 957_775, 1_783_900_801, 0);
        wrong_bits.header.bits = CompactTarget::from_consensus(0x207f_fffe);
        reset_test_nonce(&mut wrong_bits);
        while !wrong_bits
            .header
            .target()
            .is_met_by(wrong_bits.block_hash())
        {
            wrong_bits.header.nonce = wrong_bits.header.nonce.wrapping_add(1);
        }
        assert!(store
            .submit_block(&hex::encode(serialize(&wrong_bits)))
            .unwrap_err()
            .to_string()
            .contains("difficulty"));

        let mut multiple_transactions = mine_block(inherited, 957_775, 1_783_900_801, 0);
        multiple_transactions
            .txdata
            .push(multiple_transactions.txdata[0].clone());
        multiple_transactions.header.merkle_root =
            multiple_transactions.compute_merkle_root().unwrap();
        reset_test_nonce(&mut multiple_transactions);
        while !multiple_transactions
            .header
            .target()
            .is_met_by(multiple_transactions.block_hash())
        {
            multiple_transactions.header.nonce = multiple_transactions.header.nonce.wrapping_add(1);
        }
        assert!(store
            .submit_block(&hex::encode(serialize(&multiple_transactions)))
            .unwrap_err()
            .to_string()
            .contains("exactly one coinbase"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_user_controlled_symlink_ancestors_and_permissive_logs() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = test_dir("pohw-fork-chain-path-safety");
        let manifest_path = write_manifest(&dir);
        let real_parent = dir.join("real");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = dir.join("linked");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(
            ForkChainStore::open(&linked_parent.join("chain"), &manifest_path)
                .err()
                .unwrap()
                .to_string()
                .contains("symlink ancestor")
        );

        let chain_dir = dir.join("permissive-chain");
        fs::create_dir(&chain_dir).unwrap();
        fs::set_permissions(&chain_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let log = chain_dir.join("fork-blocks.ndjson");
        fs::write(&log, b"").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ForkChainStore::open(&chain_dir, &manifest_path)
            .err()
            .unwrap()
            .to_string()
            .contains("too permissive"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bounded_log_reader_rejects_oversized_line_without_unbounded_read() {
        let mut input = std::io::Cursor::new(vec![b'x'; 33]);
        let error = read_bounded_line(&mut input, 32).unwrap_err();
        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn cumulative_work_fork_choice_reorganizes_and_breaks_ties_deterministically() {
        let dir = test_dir("pohw-fork-chain-reorg");
        let manifest_path = write_manifest(&dir);
        let mut store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let left = mine_block(inherited, 957_775, 1_783_900_801, 0);
        let right = mine_block(inherited, 957_775, 1_783_900_802, 0);
        let (smaller, larger) = if left.block_hash().to_string() < right.block_hash().to_string() {
            (left, right)
        } else {
            (right, left)
        };
        store
            .submit_block(&hex::encode(serialize(&larger)))
            .unwrap();
        store
            .submit_block(&hex::encode(serialize(&smaller)))
            .unwrap();
        assert_eq!(store.status().tip_hash, smaller.block_hash().to_string());

        let extension_bits = store
            .next_difficulty(Some(larger.block_hash()), 957_776, 1_783_900_803)
            .unwrap()
            .bits
            .to_consensus();
        let extension = mine_block_with_bits(
            larger.block_hash(),
            957_776,
            1_783_900_803,
            0,
            extension_bits,
        );
        store
            .submit_block(&hex::encode(serialize(&extension)))
            .unwrap();
        assert_eq!(store.status().tip_hash, extension.block_hash().to_string());
        assert_eq!(
            store.active_block_hash(957_775).unwrap(),
            larger.block_hash().to_string()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn live_stratum_template_is_admissible_against_fork_consensus() {
        let dir = test_dir("pohw-fork-chain-template-admission");
        let manifest_path = write_manifest(&dir);
        let mut store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
        let material = store.mining_template(1_783_900_801).unwrap();
        let job = build_stratum_job_from_template(&material, 4).unwrap().job;
        let runtime_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
            ^ std::process::id();
        let extranonce1 = format!("{:08x}", runtime_seed.rotate_left(7));
        let extranonce2 = format!("{:08x}", runtime_seed.rotate_left(17));
        let nonce = format!("{:08x}", runtime_seed.rotate_left(29));
        let candidate = build_stratum_block_candidate(
            &job,
            &extranonce1,
            &extranonce2,
            &job.ntime,
            &nonce,
            4,
            false,
        )
        .unwrap();
        let template = BitcoinWorkTemplate::from_bitcoin_header_hex(
            "alice",
            &candidate.bitcoin_header_hex,
            i64::from(material.curtime),
        )
        .unwrap();
        let admitted = store
            .validate_work_template(&template, u64::from(material.curtime))
            .unwrap();
        assert_eq!(admitted.height, material.height);
        assert_eq!(admitted.previous_block_hash, material.previous_block_hash);

        let current_share = Share {
            miner_id: "alice".to_string(),
            bitcoin_header_hex: candidate.bitcoin_header_hex.clone(),
            bitcoin_template_hash: template.template_hash.clone(),
            nonce_hex: candidate.bitcoin_header_hex[152..].to_string(),
            work_hash: candidate.block_hash.clone(),
            target: "7f".repeat(32),
            idena_snapshot_id: "2026-07-14".to_string(),
            idena_snapshot_proof_root: "11".repeat(32),
            hashrate_score_delta: 1,
            parent_share_hash: "00".repeat(32),
            mining_signature_hex: String::new(),
        };
        let share_admission = store
            .validate_share(&template, &current_share, u64::from(material.curtime))
            .unwrap();
        assert_eq!(share_admission.work_status, "current-active-tip-share");

        let inherited = BlockHash::from_str(&material.previous_block_hash).unwrap();
        let block = mine_block(inherited, material.height, material.curtime, 0);
        store
            .submit_block_at_time(&hex::encode(serialize(&block)), u64::from(material.curtime))
            .unwrap();
        assert!(store
            .validate_share(&template, &current_share, u64::from(material.curtime))
            .unwrap_err()
            .to_string()
            .contains("not the exact active-chain block"));

        let block_header_hex = hex::encode(serialize(&block.header));
        let historical_template = BitcoinWorkTemplate::from_bitcoin_header_hex(
            "alice",
            &block_header_hex,
            i64::from(block.header.time),
        )
        .unwrap();
        let historical_share = Share {
            miner_id: "alice".to_string(),
            bitcoin_header_hex: block_header_hex.clone(),
            bitcoin_template_hash: historical_template.template_hash.clone(),
            nonce_hex: block_header_hex[152..].to_string(),
            work_hash: block.block_hash().to_string(),
            target: "7f".repeat(32),
            idena_snapshot_id: "2026-07-14".to_string(),
            idena_snapshot_proof_root: "11".repeat(32),
            hashrate_score_delta: 1,
            parent_share_hash: "00".repeat(32),
            mining_signature_hex: String::new(),
        };
        let historical = store
            .validate_share(
                &historical_template,
                &historical_share,
                u64::from(block.header.time),
            )
            .unwrap();
        assert_eq!(historical.work_status, "historical-exact-active-block");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mempool_byte_budget_rejects_oversize_transactions_and_aggregate_growth() {
        assert_eq!(
            checked_mempool_bytes(MAX_MEMPOOL_BYTES - 1, 1).unwrap(),
            MAX_MEMPOOL_BYTES
        );
        assert!(checked_mempool_bytes(MAX_MEMPOOL_BYTES, 1).is_err());
        assert!(checked_mempool_bytes(usize::MAX, 1).is_err());
        assert!(normalize_transaction_hex(&"00".repeat(MAX_MEMPOOL_TRANSACTION_BYTES)).is_ok());
        assert!(
            normalize_transaction_hex(&"00".repeat(MAX_MEMPOOL_TRANSACTION_BYTES + 1)).is_err()
        );
    }

    #[test]
    fn peer_capability_auth_rejects_wrong_keys_expiry_and_replay() {
        let capability = vec![0x41; MIN_FORK_P2P_CAPABILITY_BYTES];
        let now = current_unix_time();
        let mut request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: manifest().activation_id,
            transaction_upgrade_id: None,
            auth: None,
            method: ForkWireMethod::SubmitTransaction {
                transaction_hex: "00".to_string(),
            },
        };
        request.auth = Some(create_peer_request_auth(&request, &capability).unwrap());
        let replay = StdMutex::new(ForkPeerReplayState::default());
        verify_peer_request_auth(&request, &capability, &replay, now).unwrap();
        assert!(verify_peer_request_auth(&request, &capability, &replay, now).is_err());

        let wrong_key_replay = StdMutex::new(ForkPeerReplayState::default());
        assert!(verify_peer_request_auth(
            &request,
            &[0x42; MIN_FORK_P2P_CAPABILITY_BYTES],
            &wrong_key_replay,
            now,
        )
        .is_err());

        let expired_timestamp = now.saturating_sub(FORK_P2P_AUTH_WINDOW_SECONDS + 1);
        let nonce_hex = "11".repeat(16);
        request.auth = Some(ForkWireAuth {
            timestamp_unix: expired_timestamp,
            nonce_hex: nonce_hex.clone(),
            mac_hex: peer_request_mac(&request, expired_timestamp, &nonce_hex, &capability)
                .unwrap(),
        });
        assert!(verify_peer_request_auth(
            &request,
            &capability,
            &StdMutex::new(ForkPeerReplayState::default()),
            now,
        )
        .is_err());

        let uppercase_nonce = "AB".repeat(16);
        request.auth = Some(ForkWireAuth {
            timestamp_unix: now,
            nonce_hex: uppercase_nonce.clone(),
            mac_hex: peer_request_mac(&request, now, &uppercase_nonce, &capability).unwrap(),
        });
        let error = verify_peer_request_auth(
            &request,
            &capability,
            &StdMutex::new(ForkPeerReplayState::default()),
            now,
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical lowercase hex"));

        let replay = StdMutex::new(ForkPeerReplayState {
            nonces: (0..MAX_P2P_AUTH_NONCES)
                .map(|index| (format!("{index:032x}"), now))
                .collect(),
        });
        let unused_nonce = "ff".repeat(16);
        request.auth = Some(ForkWireAuth {
            timestamp_unix: now,
            nonce_hex: unused_nonce.clone(),
            mac_hex: peer_request_mac(&request, now, &unused_nonce, &capability).unwrap(),
        });
        let error = verify_peer_request_auth(&request, &capability, &replay, now).unwrap_err();
        assert!(error.to_string().contains("replay cache capacity"));
    }

    #[test]
    fn peer_mutation_rate_limiter_is_per_ip_and_per_operation() {
        let limiter = ForkPeerRateLimiter::default();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..MAX_P2P_BLOCK_SUBMISSIONS_PER_WINDOW {
            limiter
                .observe(first, ForkPeerMutationKind::Block, 100)
                .unwrap();
        }
        assert!(limiter
            .observe(first, ForkPeerMutationKind::Block, 100)
            .is_err());
        limiter
            .observe(second, ForkPeerMutationKind::Block, 100)
            .unwrap();
        limiter
            .observe(
                first,
                ForkPeerMutationKind::Block,
                100 + FORK_P2P_RATE_WINDOW_SECONDS,
            )
            .unwrap();
    }

    #[test]
    fn peer_mutation_rate_limiter_caps_and_expires_ip_state() {
        let limiter = ForkPeerRateLimiter::default();
        {
            let mut peers = limiter.by_ip.lock().unwrap();
            for index in 0..MAX_P2P_RATE_LIMIT_IPS {
                peers.insert(
                    IpAddr::V6(std::net::Ipv6Addr::from(index as u128)),
                    ForkPeerRateWindow {
                        started_at_unix: 100,
                        ..ForkPeerRateWindow::default()
                    },
                );
            }
        }
        let new_peer = IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX));
        assert!(limiter
            .observe(new_peer, ForkPeerMutationKind::Transaction, 100)
            .is_err());
        limiter
            .observe(
                new_peer,
                ForkPeerMutationKind::Transaction,
                100 + FORK_P2P_RATE_WINDOW_SECONDS,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn loopback_rpc_serves_live_template_and_accepts_block() {
        let dir = test_dir("pohw-fork-chain-rpc");
        let manifest_path = write_manifest(&dir);
        let chain_dir = dir.join("chain");
        let store = Arc::new(RwLock::new(
            ForkChainStore::open(&chain_dir, &manifest_path).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(
            listener,
            Arc::clone(&store),
            Arc::new(Vec::new()),
            true,
            true,
            None,
        ));
        let activation_id = manifest().activation_id;
        let client = ForkChainClient::new(addr, activation_id, false).unwrap();
        let initial = client.mining_template().await.unwrap();
        assert_eq!(initial.height, 957_775);
        let inherited = BlockHash::from_str(&initial.previous_block_hash).unwrap();
        let block = mine_block(inherited, initial.height, initial.curtime, 0);
        let result = client
            .submit_block(&hex::encode(serialize(&block)))
            .await
            .unwrap();
        assert_eq!(result.status, "accepted");
        let next = client.mining_template().await.unwrap();
        assert_eq!(next.height, initial.height + 1);
        assert_eq!(next.previous_block_hash, block.block_hash().to_string());
        task.abort();
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn unconfigured_p2p_peer_cannot_submit_low_difficulty_blocks() {
        let dir = test_dir("pohw-fork-chain-submit-gate");
        let manifest = manifest();
        let manifest_path = write_manifest_value(&dir, &manifest);
        let store = Arc::new(RwLock::new(
            ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap(),
        ));
        let inherited = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash).unwrap();
        let block = mine_block(inherited, 957_775, 1_783_900_801, 0);
        let request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: manifest.activation_id,
            transaction_upgrade_id: None,
            auth: None,
            method: ForkWireMethod::SubmitBlock {
                block_hex: hex::encode(serialize(&block)),
            },
        };

        let denied = handle_wire_request(&request, &store, false, false)
            .await
            .unwrap();
        assert!(!denied.ok);
        assert_eq!(denied.error_code.as_deref(), Some("peer_authentication"));
        assert_eq!(store.read().await.status().active_fork_block_count, 0);

        let accepted = handle_wire_request(&request, &store, false, true)
            .await
            .unwrap();
        assert!(accepted.ok);
        assert_eq!(store.read().await.status().active_fork_block_count, 1);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn p2p_mutation_requires_the_configured_capability_on_the_wire() {
        let dir = test_dir("pohw-fork-chain-p2p-capability");
        let manifest = manifest();
        let manifest_path = write_manifest_value(&dir, &manifest);
        let store = Arc::new(RwLock::new(
            ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap(),
        ));
        let capability = Arc::new(vec![0x51; MIN_FORK_P2P_CAPABILITY_BYTES]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(
            listener,
            Arc::clone(&store),
            Arc::new(Vec::new()),
            false,
            false,
            Some(Arc::clone(&capability)),
        ));
        let inherited = BlockHash::from_str(&manifest.fork_point.inherited_tip_hash).unwrap();
        let block = mine_block(inherited, 957_775, 1_783_900_801, 0);
        let block_hex = hex::encode(serialize(&block));

        let unauthenticated =
            ForkChainClient::new_peer(addr, manifest.activation_id.clone(), None, None).unwrap();
        let error = unauthenticated.submit_block(&block_hex).await.unwrap_err();
        assert!(error.to_string().contains("peer_authentication"));
        assert_eq!(store.read().await.status().active_fork_block_count, 0);

        let authenticated =
            ForkChainClient::new_peer(addr, manifest.activation_id, None, Some(capability))
                .unwrap();
        assert_eq!(
            authenticated.submit_block(&block_hex).await.unwrap().status,
            "accepted"
        );
        assert_eq!(store.read().await.status().active_fork_block_count, 1);

        task.abort();
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn p2p_clients_cannot_run_explorer_scans() {
        let dir = test_dir("pohw-fork-chain-explorer-gate");
        let manifest = manifest();
        let manifest_path = write_manifest_value(&dir, &manifest);
        let store = Arc::new(RwLock::new(
            ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap(),
        ));
        let request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: manifest.activation_id,
            transaction_upgrade_id: None,
            auth: None,
            method: ForkWireMethod::BlockPage {
                cursor: None,
                limit: 25,
            },
        };

        let denied = handle_wire_request(&request, &store, false, true)
            .await
            .unwrap();
        assert!(!denied.ok);
        assert_eq!(denied.error_code.as_deref(), Some("method_not_allowed"));

        let allowed = handle_wire_request(&request, &store, true, true)
            .await
            .unwrap();
        assert!(allowed.ok);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn peer_sync_downloads_and_validates_the_active_fork() {
        let dir = test_dir("pohw-fork-chain-peer-sync");
        let manifest_path = write_manifest(&dir);
        let source = Arc::new(RwLock::new(
            ForkChainStore::open(&dir.join("source"), &manifest_path).unwrap(),
        ));
        let destination = Arc::new(RwLock::new(
            ForkChainStore::open(&dir.join("destination"), &manifest_path).unwrap(),
        ));
        let inherited = BlockHash::from_str(&manifest().fork_point.inherited_tip_hash).unwrap();
        let first = mine_block(inherited, 957_775, 1_783_900_801, 0);
        source
            .write()
            .await
            .submit_block(&hex::encode(serialize(&first)))
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_listener(
            listener,
            Arc::clone(&source),
            Arc::new(vec![addr]),
            false,
            true,
            None,
        ));
        sync_from_peer(&destination, addr, None).await.unwrap();
        assert_eq!(
            destination.read().await.status().tip_hash,
            first.block_hash().to_string()
        );
        task.abort();
        drop(source);
        drop(destination);
        fs::remove_dir_all(dir).unwrap();
    }
}
