use crate::{
    bitcoin_rpc::{BitcoinMiningJobTemplate, SubmitBlockOutcome},
    p2p_node::ConnectionLimiter,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::{Address, Block, BlockHash, Network, OutPoint, Transaction, TxOut, Txid, Weight};
use chrono::Utc;
use crypto_bigint::{NonZero, U256 as CryptoU256, U512 as CryptoU512};
use fs2::FileExt;
use pohw_core::fork::{
    ForkActivationManifest, ForkConfig, ForkDifficultyAlgorithm,
    BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL,
};
use pohw_core::sharechain::BitcoinWorkTemplate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::future::pending;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};

const FORK_BLOCK_RECORD_SCHEMA_VERSION: u16 = 1;
const MAX_ACTIVATION_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_HEX_BYTES: usize = MAX_BLOCK_BYTES * 2;
const MAX_WIRE_FRAME_BYTES: usize = MAX_BLOCK_HEX_BYTES + 64 * 1024;
const MAX_BLOCK_LOG_LINE_BYTES: usize = MAX_BLOCK_HEX_BYTES + 64 * 1024;
const MAX_FUTURE_BLOCK_SECONDS: u64 = 2 * 60 * 60;
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;
const MAX_CONNECTIONS: usize = 128;
const MAX_CONNECTIONS_PER_IP: usize = 16;
const MAX_PEERS: usize = 64;
const DEFAULT_NETWORK_TIMEOUT_SECONDS: u64 = 15;
const FORK_PROTOCOL_VERSION: u16 = 2;
const FORK_BLOCK_VERSION: i32 = 0x2000_0000;

#[derive(Debug, Clone)]
pub(crate) struct ForkChainNodeConfig {
    pub datadir: PathBuf,
    pub activation_manifest: PathBuf,
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
pub(crate) struct ForkBlockAcceptance {
    pub accepted: bool,
    pub became_active_tip: bool,
    pub block_hash: String,
    pub height: u64,
    pub tip_hash: String,
    pub tip_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkWorkTemplateValidation {
    pub template_hash: String,
    pub previous_block_hash: String,
    pub height: u64,
    pub header_time: u32,
    pub bits: String,
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
    inherited_tip_hash: BlockHash,
    blocks: BTreeMap<BlockHash, BlockNode>,
    active_tip: Option<BlockHash>,
    active_by_height: BTreeMap<u64, BlockHash>,
    _lock: File,
}

impl ForkChainStore {
    pub(crate) fn open(datadir: &Path, activation_manifest: &Path) -> Result<Self> {
        let manifest = read_activation_manifest(activation_manifest)?;
        manifest
            .validate()
            .context("invalid fork activation manifest")?;
        if manifest.config.inherited_utxo_spending_enabled {
            bail!("Experiment 0 fork node requires inherited_utxo_spending_enabled=false");
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
            inherited_tip_hash,
            blocks: BTreeMap::new(),
            active_tip: None,
            active_by_height: BTreeMap::new(),
            _lock: lock,
        };
        store.replay_block_log()?;
        Ok(store)
    }

    pub(crate) fn manifest(&self) -> &ForkActivationManifest {
        &self.manifest
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
            transaction_consensus: "coinbase-only; inherited and post-fork spends disabled"
                .to_string(),
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
        Ok(BitcoinMiningJobTemplate {
            version: FORK_BLOCK_VERSION,
            previous_block_hash: status.tip_hash,
            curtime,
            bits: format!("{:08x}", next_difficulty.bits.to_consensus()),
            height,
            coinbase_value_sats: block_subsidy_sats(height),
            transaction_hashes: Vec::new(),
            transactions: Vec::new(),
            default_witness_commitment: None,
        })
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
        self.consider_active_tip(hash)?;
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
        let mut blocks = self.blocks.iter().collect::<Vec<_>>();
        blocks.sort_by(|(left_hash, left), (right_hash, right)| {
            right
                .height
                .cmp(&left.height)
                .then_with(|| left_hash.to_string().cmp(&right_hash.to_string()))
        });
        let start = match cursor {
            Some(cursor) => {
                let cursor = BlockHash::from_str(cursor)
                    .context("fork block cursor is not a valid block hash")?;
                blocks
                    .iter()
                    .position(|(hash, _)| **hash == cursor)
                    .map(|position| position + 1)
                    .context("fork block cursor is not present in local replay")?
            }
            None => 0,
        };
        let end = start.saturating_add(limit).min(blocks.len());
        let items = blocks[start..end]
            .iter()
            .map(|(hash, node)| self.block_summary_for_node(**hash, node))
            .collect::<Vec<_>>();
        let next_cursor = (end < blocks.len())
            .then(|| items.last().map(|item| item.block_hash.clone()))
            .flatten();
        Ok(ForkBlockPage {
            tip_height: self.status().tip_height,
            total: blocks.len(),
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
        let outputs = self.active_output_index()?;
        let total = node.block.txdata.len();
        let end = cursor.saturating_add(limit).min(total);
        let items = if cursor >= total {
            Vec::new()
        } else {
            node.block.txdata[cursor..end]
                .iter()
                .enumerate()
                .map(|(offset, tx)| {
                    transaction_ref(tx, hash, node.height, active, cursor + offset, &outputs)
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
        let outputs = self.active_output_index()?;
        let spends = self.active_spend_index();
        let mut matches = self
            .blocks
            .iter()
            .flat_map(|(block_hash, node)| {
                node.block
                    .txdata
                    .iter()
                    .enumerate()
                    .filter(|(_, tx)| tx.compute_txid() == txid)
                    .map(move |(index, tx)| (*block_hash, node, index, tx))
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
            &outputs,
            &spends,
        )?))
    }

    pub(crate) fn address_summary(&self, address: &str) -> Result<ForkAddressSummary> {
        let address = normalize_mainnet_address(address)?;
        let outputs = self.active_output_index()?;
        let spends = self.active_spend_index();
        let mut transactions = BTreeSet::new();
        let mut funded_output_count = 0usize;
        let mut funded_total_sats = 0u64;
        let mut spent_output_count = 0usize;
        let mut spent_total_sats = 0u64;
        let mut first_seen_height = None;
        let mut last_seen_height = None;
        for (outpoint, indexed) in &outputs {
            if output_address(&indexed.output).as_deref() != Some(address.as_str()) {
                continue;
            }
            transactions.insert(outpoint.txid);
            funded_output_count = funded_output_count.saturating_add(1);
            funded_total_sats = funded_total_sats
                .checked_add(indexed.output.value.to_sat())
                .context("fork address funded total overflow")?;
            update_height_range(
                &mut first_seen_height,
                &mut last_seen_height,
                indexed.height,
            );
            if let Some(spend) = spends.get(outpoint) {
                transactions
                    .insert(Txid::from_str(&spend.txid).expect("indexed spend txid is valid"));
                spent_output_count = spent_output_count.saturating_add(1);
                spent_total_sats = spent_total_sats
                    .checked_add(indexed.output.value.to_sat())
                    .context("fork address spent total overflow")?;
                update_height_range(&mut first_seen_height, &mut last_seen_height, spend.height);
            }
        }
        Ok(ForkAddressSummary {
            address,
            transaction_count: transactions.len(),
            funded_output_count,
            funded_total_sats,
            spent_output_count,
            spent_total_sats,
            balance_sats: funded_total_sats
                .checked_sub(spent_total_sats)
                .context("fork address balance underflow")?,
            first_seen_height,
            last_seen_height,
        })
    }

    pub(crate) fn address_transactions(
        &self,
        address: &str,
        cursor: usize,
        limit: usize,
    ) -> Result<ForkAddressTransactionPage> {
        validate_numeric_page(cursor, limit)?;
        let address = normalize_mainnet_address(address)?;
        let outputs = self.active_output_index()?;
        let mut items = Vec::new();
        for (height, block_hash) in self.active_by_height.iter().rev() {
            let node = self
                .blocks
                .get(block_hash)
                .expect("active fork block must exist");
            for (transaction_index, tx) in node.block.txdata.iter().enumerate().rev() {
                let related_output = tx
                    .output
                    .iter()
                    .any(|output| output_address(output).as_deref() == Some(address.as_str()));
                let related_input = tx.input.iter().any(|input| {
                    outputs
                        .get(&input.previous_output)
                        .and_then(|indexed| output_address(&indexed.output))
                        .as_deref()
                        == Some(address.as_str())
                });
                if related_output || related_input {
                    items.push(transaction_ref(
                        tx,
                        *block_hash,
                        *height,
                        true,
                        transaction_index,
                        &outputs,
                    )?);
                }
            }
        }
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
        let outputs = self.active_output_index()?;
        let spends = self.active_spend_index();
        let mut items = outputs
            .iter()
            .filter(|(outpoint, indexed)| {
                !spends.contains_key(outpoint)
                    && output_address(&indexed.output).as_deref() == Some(address.as_str())
            })
            .map(|(outpoint, indexed)| ForkUtxo {
                txid: outpoint.txid.to_string(),
                vout: outpoint.vout,
                value_sats: indexed.output.value.to_sat(),
                script_pubkey_hex: hex::encode(indexed.output.script_pubkey.as_bytes()),
                script_type: script_type(&indexed.output),
                height: indexed.height,
                coinbase: indexed.coinbase,
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .height
                .cmp(&left.height)
                .then_with(|| left.txid.cmp(&right.txid))
                .then_with(|| left.vout.cmp(&right.vout))
        });
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

    fn active_output_index(&self) -> Result<BTreeMap<OutPoint, IndexedForkOutput>> {
        let mut outputs = BTreeMap::new();
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
                    outputs.insert(
                        OutPoint { txid, vout },
                        IndexedForkOutput {
                            output: output.clone(),
                            height: *height,
                            coinbase: tx.is_coinbase(),
                        },
                    );
                }
            }
        }
        Ok(outputs)
    }

    fn active_spend_index(&self) -> BTreeMap<OutPoint, ForkOutputSpend> {
        let mut spends = BTreeMap::new();
        for (height, block_hash) in &self.active_by_height {
            let node = self
                .blocks
                .get(block_hash)
                .expect("active fork block must exist");
            for tx in &node.block.txdata {
                if tx.is_coinbase() {
                    continue;
                }
                for (vin, input) in tx.input.iter().enumerate() {
                    spends.insert(
                        input.previous_output,
                        ForkOutputSpend {
                            txid: tx.compute_txid().to_string(),
                            vin,
                            height: *height,
                        },
                    );
                }
            }
        }
        spends
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
            self.consider_active_tip(hash)?;
        }
        Ok(())
    }

    fn validate_block(&self, block: Block, block_hex: String, now_unix: u64) -> Result<BlockNode> {
        if block.weight() > Weight::MAX_BLOCK {
            bail!("fork block exceeds the 4,000,000 weight-unit consensus limit");
        }
        if block.txdata.len() != 1 {
            bail!("Experiment 0 fork blocks must contain exactly one coinbase transaction");
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
        validate_coinbase_height(coinbase, height)?;
        validate_coinbase_reward(coinbase, height)?;
        let cumulative_work = parent_work + required_target.to_work();
        Ok(BlockNode {
            block,
            block_hex,
            height,
            cumulative_work,
            difficulty_phase: next_difficulty.phase,
        })
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
        })
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
        let request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: self.activation_id.clone(),
            method,
        };
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
    #[serde(flatten)]
    method: ForkWireMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum ForkWireMethod {
    Status,
    MiningTemplate,
    ValidateWorkTemplate {
        template: BitcoinWorkTemplate,
    },
    SubmitBlock {
        block_hex: String,
    },
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
    let store = Arc::new(RwLock::new(ForkChainStore::open(
        &config.datadir,
        &config.activation_manifest,
    )?));
    let activation_id = store.read().await.manifest().activation_id.clone();
    let peers = Arc::new(deduplicate_peers(config.peer_addrs));
    let rpc_listener = TcpListener::bind(config.rpc_bind_addr)
        .await
        .with_context(|| format!("failed to bind fork-chain RPC on {}", config.rpc_bind_addr))?;
    eprintln!(
        "fork-chain RPC listening on {} activation_id={}",
        config.rpc_bind_addr, activation_id
    );
    let rpc_task = tokio::spawn(serve_listener(
        rpc_listener,
        Arc::clone(&store),
        Arc::clone(&peers),
        true,
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
) -> Result<()> {
    let connections = ConnectionLimiter::new(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Some(connection_guard) = connections.try_acquire(peer_addr.ip()) else {
            continue;
        };
        let store = Arc::clone(&store);
        let peers = Arc::clone(&peers);
        let allow_submit_blocks = allow_templates
            || peers
                .iter()
                .any(|configured_peer| configured_peer.ip() == peer_addr.ip());
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Ok(Err(err)) = timeout(
                Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
                handle_connection(stream, store, peers, allow_templates, allow_submit_blocks),
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
    store: Arc<RwLock<ForkChainStore>>,
    peers: Arc<Vec<SocketAddr>>,
    allow_templates: bool,
    allow_submit_blocks: bool,
) -> Result<()> {
    let payload = read_frame(&mut stream).await?;
    let request: ForkWireRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(err) => {
            let response = ForkWireResponse::error("invalid_request", err.to_string());
            return write_wire_response(&mut stream, &response).await;
        }
    };
    let response =
        handle_wire_request(&request, &store, allow_templates, allow_submit_blocks).await;
    let accepted_block = match (&request.method, &response) {
        (ForkWireMethod::SubmitBlock { block_hex }, Ok(response)) if response.ok => response
            .result
            .as_ref()
            .and_then(|value| serde_json::from_value::<ForkBlockAcceptance>(value.clone()).ok())
            .filter(|accepted| accepted.accepted)
            .map(|_| block_hex.clone()),
        _ => None,
    };
    let response = response
        .unwrap_or_else(|err| ForkWireResponse::error("consensus_rejected", format!("{err:#}")));
    write_wire_response(&mut stream, &response).await?;
    if let Some(block_hex) = accepted_block {
        let activation_id = store.read().await.manifest().activation_id.clone();
        tokio::spawn(broadcast_block(peers, activation_id, block_hex));
    }
    Ok(())
}

async fn handle_wire_request(
    request: &ForkWireRequest,
    store: &Arc<RwLock<ForkChainStore>>,
    allow_templates: bool,
    allow_submit_blocks: bool,
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
        ForkWireMethod::SubmitBlock { block_hex } if allow_submit_blocks => {
            let result = store.write().await.submit_block(block_hex)?;
            ForkWireResponse::success(result)
        }
        ForkWireMethod::SubmitBlock { .. } => Ok(ForkWireResponse::error(
            "peer_not_configured",
            "block submission is limited to loopback control RPC and configured peer IPs",
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
        ForkWireMethod::BlockPage { .. }
        | ForkWireMethod::BlockSummary { .. }
        | ForkWireMethod::BlockTransactions { .. }
        | ForkWireMethod::TransactionDetail { .. }
        | ForkWireMethod::AddressSummary { .. }
        | ForkWireMethod::AddressTransactions { .. }
        | ForkWireMethod::AddressUtxos { .. } => Ok(ForkWireResponse::error(
            "method_not_allowed",
            "explorer queries are available only on loopback control RPC",
        )),
    }
}

async fn peer_sync_loop(
    store: Arc<RwLock<ForkChainStore>>,
    peers: Arc<Vec<SocketAddr>>,
    cadence: Duration,
) -> Result<()> {
    let mut ticker = interval(cadence);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        for peer in peers.iter().copied() {
            if let Err(err) = sync_from_peer(&store, peer).await {
                eprintln!("fork-chain peer sync from {peer} failed: {err:#}");
            }
        }
    }
}

async fn sync_from_peer(store: &Arc<RwLock<ForkChainStore>>, peer: SocketAddr) -> Result<()> {
    let activation_id = store.read().await.manifest().activation_id.clone();
    let client = ForkChainClient::new(peer, activation_id, true)?;
    let remote = client.status().await?;
    let local = store.read().await.status();
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
    Ok(())
}

async fn broadcast_block(peers: Arc<Vec<SocketAddr>>, activation_id: String, block_hex: String) {
    for peer in peers.iter().copied() {
        let Ok(client) = ForkChainClient::new(peer, activation_id.clone(), true) else {
            continue;
        };
        let _ = client.submit_block(&block_hex).await;
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

fn validate_coinbase_reward(coinbase: &bitcoin::Transaction, height: u64) -> Result<()> {
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
    let subsidy = block_subsidy_sats(height);
    if total > subsidy {
        bail!("fork coinbase pays {total} sats but subsidy is only {subsidy} sats");
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
    use bitcoin::transaction::Version as TransactionVersion;
    use bitcoin::{
        Amount, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use chrono::{TimeZone, Utc};
    use pohw_core::fork::{ForkConfig, ForkPoint, MainnetBlockRef};
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

    fn coinbase(height: u64, amount: u64) -> Transaction {
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
                script_pubkey: ScriptBuf::new_op_return([]),
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
        let store = ForkChainStore::open(&dir.join("chain"), &manifest_path).unwrap();
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
        fs::remove_dir_all(dir).unwrap();
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
            method: ForkWireMethod::SubmitBlock {
                block_hex: hex::encode(serialize(&block)),
            },
        };

        let denied = handle_wire_request(&request, &store, false, false)
            .await
            .unwrap();
        assert!(!denied.ok);
        assert_eq!(denied.error_code.as_deref(), Some("peer_not_configured"));
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
            Arc::new(Vec::new()),
            false,
        ));
        sync_from_peer(&destination, addr).await.unwrap();
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
