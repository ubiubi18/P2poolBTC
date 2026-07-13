use crate::{
    bitcoin_rpc::{BitcoinMiningJobTemplate, SubmitBlockOutcome},
    p2p_node::ConnectionLimiter,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::{Block, BlockHash, Weight};
use chrono::Utc;
use crypto_bigint::{Encoding, U256 as CryptoU256, U512 as CryptoU512};
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
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
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
        let file = open_private_file(&path, true)?;
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
    let adjusted = scaled.wrapping_div(&CryptoU512::from_u64(target_timespan));

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
    Ok(Target::from_be_bytes(bounded.to_be_bytes()).to_compact_lossy())
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

    async fn active_block_hash(&self, height: u64) -> Result<Option<String>> {
        let value = self
            .request(ForkWireMethod::ActiveBlockHash { height })
            .await?;
        serde_json::from_value(value).context("fork-chain block-hash response has invalid shape")
    }

    async fn active_block_hex(&self, height: u64) -> Result<Option<String>> {
        let value = self.request(ForkWireMethod::ActiveBlock { height }).await?;
        serde_json::from_value(value).context("fork-chain block response has invalid shape")
    }

    async fn request(&self, method: ForkWireMethod) -> Result<Value> {
        let request = ForkWireRequest {
            protocol_version: FORK_PROTOCOL_VERSION,
            activation_id: self.activation_id.clone(),
            method,
        };
        let payload =
            serde_json::to_vec(&request).context("failed to encode fork-chain request")?;
        let mut stream = timeout(
            Duration::from_secs(DEFAULT_NETWORK_TIMEOUT_SECONDS),
            TcpStream::connect(self.addr),
        )
        .await
        .context("fork-chain RPC connect timed out")?
        .with_context(|| format!("failed to connect to fork-chain RPC at {}", self.addr))?;
        write_frame(&mut stream, &payload).await?;
        let response = read_frame(&mut stream).await?;
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
    ValidateWorkTemplate { template: BitcoinWorkTemplate },
    SubmitBlock { block_hex: String },
    ActiveBlockHash { height: u64 },
    ActiveBlock { height: u64 },
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
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Err(err) = handle_connection(stream, store, peers, allow_templates).await {
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
) -> Result<()> {
    let payload = read_frame(&mut stream).await?;
    let request: ForkWireRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(err) => {
            let response = ForkWireResponse::error("invalid_request", err.to_string());
            return write_wire_response(&mut stream, &response).await;
        }
    };
    let response = handle_wire_request(&request, &store, allow_templates).await;
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
        ForkWireMethod::SubmitBlock { block_hex } => {
            let result = store.write().await.submit_block(block_hex)?;
            ForkWireResponse::success(result)
        }
        ForkWireMethod::ActiveBlockHash { height } => {
            ForkWireResponse::success(store.read().await.active_block_hash(*height))
        }
        ForkWireMethod::ActiveBlock { height } => {
            ForkWireResponse::success(store.read().await.active_block_hex(*height))
        }
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
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
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
                nonce: 0,
            },
            txdata: vec![tx],
        };
        let target = Target::from_compact(block.header.bits);
        while !target.is_met_by(block.block_hash()) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
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
        }
        let reopened = ForkChainStore::open(&chain_dir, &manifest_path).unwrap();
        assert_eq!(reopened.status().tip_hash, first.block_hash().to_string());
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
        wrong_bits.header.nonce = 0;
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
        multiple_transactions.header.nonce = 0;
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
