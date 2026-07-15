use crate::bitcoin_rpc::{BitcoinRpcClient, BlockchainInfoResponse, PohwExperimentInfoResponse};
use crate::fork_chain::{
    ForkAddressSummary, ForkAddressTransactionPage, ForkBlockPage, ForkBlockSummary,
    ForkChainClient, ForkChainStatus, ForkPreviousOutput, ForkTransactionDetail,
    ForkTransactionInput, ForkTransactionOutput, ForkTransactionPage, ForkTransactionRef,
    ForkUtxoPage,
};
use anyhow::{anyhow, bail, Context, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::{Address, Block, Network, OutPoint, Transaction, TxOut};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BLOCK_HEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRANSACTION_INPUTS: usize = 10_000;
const CORE_EXPLORER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub(crate) enum ExplorerForkClient {
    Legacy(ForkChainClient),
    PohwCore(Box<PohwCoreExplorerClient>),
}

#[derive(Debug, Clone)]
pub(crate) struct PohwCoreExplorerClient {
    rpc: BitcoinRpcClient,
    profile: PohwCoreProfile,
}

#[derive(Debug, Clone, Deserialize)]
struct PohwCoreProfile {
    schema_version: String,
    experiment_id: String,
    profile_revision: u64,
    status: String,
    activation_id: String,
    fork_point: ForkPoint,
    network: NetworkProfile,
    consensus: ConsensusProfile,
}

#[derive(Debug, Clone, Deserialize)]
struct ForkPoint {
    inherited_tip_height: u64,
    inherited_tip_hash: String,
    first_fork_height: u64,
    first_fork_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct NetworkProfile {
    chain_argument: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConsensusProfile {
    engine: String,
    all_upstream_transaction_and_script_rules_enabled: bool,
    inherited_utxo_spending_enabled: bool,
    replay_protection: ReplayProtectionProfile,
    proof_of_work: ProofOfWorkProfile,
}

#[derive(Debug, Clone, Deserialize)]
struct ReplayProtectionProfile {
    rule: String,
    required: bool,
    marker_activation_height: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ProofOfWorkProfile {
    algorithm: String,
    bootstrap_pow_limit_bits: String,
    bootstrap_handoff_hashrate_hps: u64,
    handoff_version_bit: u8,
    target_spacing_seconds: u64,
    post_handoff_retarget_interval: u64,
}

#[derive(Debug, Deserialize)]
struct RpcBlockHeader {
    hash: String,
    height: u64,
    #[serde(default)]
    chainwork: String,
}

#[derive(Debug, Deserialize)]
struct RpcRawTransactionLocation {
    #[serde(default)]
    blockhash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpcMempoolInfo {
    size: usize,
}

#[derive(Debug, Deserialize)]
struct RpcIndexInfo {
    synced: bool,
    best_block_height: u64,
}

struct ValidatedChain {
    info: BlockchainInfoResponse,
    experiment: PohwExperimentInfoResponse,
    tip_hash: String,
}

impl ExplorerForkClient {
    pub(crate) fn supports_address_index(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    pub(crate) async fn status(&self) -> Result<ForkChainStatus> {
        match self {
            Self::Legacy(client) => client.status().await,
            Self::PohwCore(client) => client.status().await,
        }
    }

    pub(crate) async fn active_block_hash(&self, height: u64) -> Result<Option<String>> {
        match self {
            Self::Legacy(client) => client.active_block_hash(height).await,
            Self::PohwCore(client) => client.active_block_hash(height).await,
        }
    }

    pub(crate) async fn block_page(
        &self,
        cursor: Option<String>,
        limit: u16,
    ) -> Result<ForkBlockPage> {
        match self {
            Self::Legacy(client) => client.block_page(cursor, limit).await,
            Self::PohwCore(client) => client.block_page(cursor, limit).await,
        }
    }

    pub(crate) async fn block_summary(
        &self,
        block_hash: String,
    ) -> Result<Option<ForkBlockSummary>> {
        match self {
            Self::Legacy(client) => client.block_summary(block_hash).await,
            Self::PohwCore(client) => client.block_summary(&block_hash).await,
        }
    }

    pub(crate) async fn block_transactions(
        &self,
        block_hash: String,
        cursor: usize,
        limit: u16,
    ) -> Result<Option<ForkTransactionPage>> {
        match self {
            Self::Legacy(client) => client.block_transactions(block_hash, cursor, limit).await,
            Self::PohwCore(client) => client.block_transactions(&block_hash, cursor, limit).await,
        }
    }

    pub(crate) async fn transaction_detail(
        &self,
        txid: String,
    ) -> Result<Option<ForkTransactionDetail>> {
        match self {
            Self::Legacy(client) => client.transaction_detail(txid).await,
            Self::PohwCore(client) => client.transaction_detail(&txid).await,
        }
    }

    pub(crate) async fn address_summary(&self, address: String) -> Result<ForkAddressSummary> {
        match self {
            Self::Legacy(client) => client.address_summary(address).await,
            Self::PohwCore(_) => bail!(
                "Experiment 1 fork address history requires the optional host transaction index"
            ),
        }
    }

    pub(crate) async fn address_transactions(
        &self,
        address: String,
        cursor: usize,
        limit: u16,
    ) -> Result<ForkAddressTransactionPage> {
        match self {
            Self::Legacy(client) => client.address_transactions(address, cursor, limit).await,
            Self::PohwCore(_) => bail!(
                "Experiment 1 fork address history requires the optional host transaction index"
            ),
        }
    }

    pub(crate) async fn address_utxos(
        &self,
        address: String,
        cursor: usize,
        limit: u16,
    ) -> Result<ForkUtxoPage> {
        match self {
            Self::Legacy(client) => client.address_utxos(address, cursor, limit).await,
            Self::PohwCore(_) => {
                bail!("Experiment 1 fork address UTXOs require the optional host transaction index")
            }
        }
    }
}

impl PohwCoreExplorerClient {
    pub(crate) fn from_manifest(rpc: BitcoinRpcClient, path: &Path) -> Result<Self> {
        let profile = read_profile(path)?;
        validate_profile(&profile)?;
        Ok(Self { rpc, profile })
    }

    async fn validate_chain(&self) -> Result<ValidatedChain> {
        let info = self.rpc.get_blockchain_info().await?;
        if info.chain != self.profile.network.chain_argument || info.chain != "pohw" {
            bail!("fork explorer RPC is not bound to the pohw chain");
        }
        if info.initial_block_download || info.blocks != info.headers {
            bail!("fork explorer RPC is not synchronized");
        }
        if info.pruned {
            bail!("host Experiment 1 explorer requires unpruned Core history");
        }
        if info.blocks < self.profile.fork_point.first_fork_height {
            bail!("fork explorer RPC has not reached the first Experiment 1 block");
        }
        let experiment = info
            .pohw_experiment
            .clone()
            .context("Bitcoin Core did not expose Experiment 1 consensus metadata")?;
        self.validate_runtime_metadata(&experiment)?;
        let indexes: BTreeMap<String, RpcIndexInfo> =
            self.rpc.call("getindexinfo", json!(["txindex"])).await?;
        let txindex = indexes
            .get("txindex")
            .context("host Experiment 1 explorer requires txindex")?;
        if !txindex.synced || txindex.best_block_height != info.blocks {
            bail!("host Experiment 1 transaction index is not synchronized");
        }
        let inherited = self
            .block_hash(self.profile.fork_point.inherited_tip_height)
            .await?;
        if inherited != self.profile.fork_point.inherited_tip_hash {
            bail!("fork explorer inherited checkpoint does not match the manifest");
        }
        let first = self
            .block_hash(self.profile.fork_point.first_fork_height)
            .await?;
        if first != self.profile.fork_point.first_fork_hash {
            bail!("fork explorer first-block checkpoint does not match the manifest");
        }
        let tip_hash = self.block_hash(info.blocks).await?;
        Ok(ValidatedChain {
            info,
            experiment,
            tip_hash,
        })
    }

    fn validate_runtime_metadata(&self, runtime: &PohwExperimentInfoResponse) -> Result<()> {
        let replay = &self.profile.consensus.replay_protection;
        if runtime.fork_height != self.profile.fork_point.inherited_tip_height
            || normalize_hash(&runtime.fork_hash, "runtime inherited tip hash")?
                != self.profile.fork_point.inherited_tip_hash
            || normalize_hash(&runtime.first_fork_hash, "runtime first fork hash")?
                != self.profile.fork_point.first_fork_hash
            || runtime.inherited_utxo_spending
                != self.profile.consensus.inherited_utxo_spending_enabled
            || runtime.replay_protection != replay.rule
            || runtime.replay_marker_activation_height != replay.marker_activation_height
            || runtime.bootstrap_handoff_hashrate_hps
                != self
                    .profile
                    .consensus
                    .proof_of_work
                    .bootstrap_handoff_hashrate_hps
        {
            bail!("Bitcoin Core Experiment 1 metadata does not match the manifest");
        }
        Ok(())
    }

    async fn require_same_tip(&self, chain: &ValidatedChain) -> Result<()> {
        let current = self.rpc.get_blockchain_info().await?;
        if current.chain != "pohw"
            || current.blocks != chain.info.blocks
            || current.headers != chain.info.headers
            || self.block_hash(current.blocks).await? != chain.tip_hash
        {
            bail!("Experiment 1 chain tip changed while the explorer response was assembled");
        }
        Ok(())
    }

    async fn status(&self) -> Result<ForkChainStatus> {
        let chain = self.validate_chain().await?;
        let tip_header = self.block_header(&chain.tip_hash).await?;
        let bitcoin_retarget = chain.experiment.handoff_active;
        let active_fork_blocks = chain
            .info
            .blocks
            .saturating_sub(self.profile.fork_point.inherited_tip_height);
        let estimated_hashrate = self
            .rpc
            .call::<Value>("getnetworkhashps", json!([active_fork_blocks]))
            .await?;
        let mempool = self
            .rpc
            .call::<RpcMempoolInfo>("getmempoolinfo", json!([]))
            .await
            .context("failed to read Experiment 1 mempool status")?;
        let status = ForkChainStatus {
            protocol_version: CORE_EXPLORER_PROTOCOL_VERSION,
            chain_name: "pohw".to_string(),
            activation_id: self.profile.activation_id.clone(),
            inherited_tip_height: self.profile.fork_point.inherited_tip_height,
            inherited_tip_hash: self.profile.fork_point.inherited_tip_hash.clone(),
            tip_height: chain.info.blocks,
            tip_hash: chain.tip_hash.clone(),
            cumulative_work: normalize_hash(&tip_header.chainwork, "chainwork")?,
            stored_block_count: usize::try_from(active_fork_blocks)
                .context("fork block count does not fit usize")?,
            active_fork_block_count: usize::try_from(active_fork_blocks)
                .context("active fork block count does not fit usize")?,
            post_fork_pow_limit_bits: self
                .profile
                .consensus
                .proof_of_work
                .bootstrap_pow_limit_bits
                .clone(),
            target_spacing_seconds: self.profile.consensus.proof_of_work.target_spacing_seconds,
            difficulty_algorithm: self.profile.consensus.proof_of_work.algorithm.clone(),
            difficulty_phase: if bitcoin_retarget {
                "bitcoin-retarget".to_string()
            } else {
                "bootstrap".to_string()
            },
            bootstrap_handoff_hashrate_hps: self
                .profile
                .consensus
                .proof_of_work
                .bootstrap_handoff_hashrate_hps,
            estimated_hashrate_hps: rpc_number_string(&estimated_hashrate),
            blocks_until_bitcoin_retarget: bitcoin_retarget.then(|| {
                let interval = self
                    .profile
                    .consensus
                    .proof_of_work
                    .post_handoff_retarget_interval;
                interval - (active_fork_blocks % interval)
            }),
            transaction_upgrade_id: Some("experiment-1-full-consensus".to_string()),
            transaction_activation_height: Some(self.profile.fork_point.first_fork_height),
            mempool_transaction_count: mempool.size,
            transaction_consensus: self.profile.consensus.engine.clone(),
        };
        self.require_same_tip(&chain).await?;
        Ok(status)
    }

    async fn active_block_hash(&self, height: u64) -> Result<Option<String>> {
        let chain = self.validate_chain().await?;
        if height > chain.info.blocks || height < self.profile.fork_point.first_fork_height {
            return Ok(None);
        }
        let hash = self.block_hash(height).await?;
        self.require_same_tip(&chain).await?;
        Ok(Some(hash))
    }

    async fn block_page(&self, cursor: Option<String>, limit: u16) -> Result<ForkBlockPage> {
        let chain = self.validate_chain().await?;
        if limit == 0 || limit > 100 {
            bail!("fork block page limit must be between 1 and 100");
        }
        let first = self.profile.fork_point.first_fork_height;
        let start = match cursor {
            Some(cursor) => {
                self.block_header(&normalize_hash(&cursor, "cursor")?)
                    .await?
                    .height
            }
            None => chain.info.blocks,
        };
        let mut items = Vec::new();
        let mut height = start;
        while height >= first && items.len() < usize::from(limit) {
            let hash = self.block_hash(height).await?;
            items.push(self.required_block_summary(&hash).await?);
            if height == 0 {
                break;
            }
            height -= 1;
        }
        let next_cursor = if height >= first && items.len() == usize::from(limit) {
            Some(self.block_hash(height).await?)
        } else {
            None
        };
        let page = ForkBlockPage {
            tip_height: chain.info.blocks,
            total: usize::try_from(chain.info.blocks.saturating_sub(first).saturating_add(1))
                .context("fork block page total does not fit usize")?,
            items,
            next_cursor,
        };
        self.require_same_tip(&chain).await?;
        Ok(page)
    }

    async fn block_summary(&self, block_hash: &str) -> Result<Option<ForkBlockSummary>> {
        let chain = self.validate_chain().await?;
        let hash = normalize_hash(block_hash, "block hash")?;
        let Some(header) = self.block_header_optional(&hash).await? else {
            return Ok(None);
        };
        if header.height < self.profile.fork_point.first_fork_height {
            return Ok(None);
        }
        let summary = self.required_block_summary(&hash).await?;
        self.require_same_tip(&chain).await?;
        Ok(Some(summary))
    }

    async fn required_block_summary(&self, block_hash: &str) -> Result<ForkBlockSummary> {
        let header = self.block_header(block_hash).await?;
        let block = self.raw_block(block_hash).await?;
        let coinbase = block
            .txdata
            .first()
            .ok_or_else(|| anyhow!("fork block has no coinbase transaction"))?;
        let active = self.block_hash(header.height).await? == block_hash;
        let handoff_mask = 1i32
            .checked_shl(u32::from(
                self.profile.consensus.proof_of_work.handoff_version_bit,
            ))
            .context("Experiment 1 handoff version bit is invalid")?;
        Ok(ForkBlockSummary {
            block_hash: block_hash.to_string(),
            previous_block_hash: block.header.prev_blockhash.to_string(),
            height: header.height,
            active,
            timestamp: block.header.time,
            bits: format!("{:08x}", block.header.bits.to_consensus()),
            difficulty_phase: if block.header.version.to_consensus() & handoff_mask != 0 {
                "bitcoin-retarget".to_string()
            } else {
                "bootstrap".to_string()
            },
            cumulative_work: normalize_hash(&header.chainwork, "chainwork")?,
            version: block.header.version.to_consensus(),
            nonce: block.header.nonce,
            merkle_root: block.header.merkle_root.to_string(),
            transaction_count: block.txdata.len(),
            size_bytes: serialize(&block).len(),
            weight_wu: block.weight().to_wu(),
            coinbase_txid: coinbase.compute_txid().to_string(),
            coinbase_value_sats: checked_output_total(coinbase)?,
            coinbase_output_count: coinbase.output.len(),
            pohw_commitment_hash: pohw_commitment_hash(coinbase),
        })
    }

    async fn block_transactions(
        &self,
        block_hash: &str,
        cursor: usize,
        limit: u16,
    ) -> Result<Option<ForkTransactionPage>> {
        let chain = self.validate_chain().await?;
        if limit == 0 || limit > 100 || cursor > 10_000_000 {
            bail!("fork transaction page is outside supported bounds");
        }
        let hash = normalize_hash(block_hash, "block hash")?;
        let Some(header) = self.block_header_optional(&hash).await? else {
            return Ok(None);
        };
        if header.height < self.profile.fork_point.first_fork_height {
            return Ok(None);
        }
        let block = self.raw_block(&hash).await?;
        let active = self.block_hash(header.height).await? == hash;
        let items = block
            .txdata
            .iter()
            .enumerate()
            .skip(cursor)
            .take(usize::from(limit))
            .map(|(index, tx)| transaction_ref(tx, &hash, header.height, active, index))
            .collect::<Result<Vec<_>>>()?;
        let next = cursor.saturating_add(items.len());
        let page = ForkTransactionPage {
            block_hash: hash,
            total: block.txdata.len(),
            items,
            next_cursor: (next < block.txdata.len()).then_some(next),
        };
        self.require_same_tip(&chain).await?;
        Ok(Some(page))
    }

    async fn transaction_detail(&self, txid: &str) -> Result<Option<ForkTransactionDetail>> {
        let chain = self.validate_chain().await?;
        let txid = normalize_hash(txid, "transaction id")?;
        let Some(location) = self
            .rpc
            .call_optional::<RpcRawTransactionLocation>("getrawtransaction", json!([&txid, true]))
            .await?
        else {
            return Ok(None);
        };
        let Some(block_hash) = location.blockhash else {
            return Ok(None);
        };
        let block_hash = normalize_hash(&block_hash, "transaction block hash")?;
        let header = self.block_header(&block_hash).await?;
        if header.height < self.profile.fork_point.first_fork_height {
            return Ok(None);
        }
        let block = self.raw_block(&block_hash).await?;
        let Some((transaction_index, transaction)) = block
            .txdata
            .iter()
            .enumerate()
            .find(|(_, transaction)| transaction.compute_txid().to_string() == txid)
        else {
            bail!("transaction index returned a block that does not contain the transaction");
        };
        if transaction.input.len() > MAX_TRANSACTION_INPUTS {
            bail!("transaction exceeds the explorer input limit");
        }
        let previous = self.previous_outputs(transaction).await?;
        let active = self.block_hash(header.height).await? == block_hash;
        let detail = transaction_detail(
            transaction,
            &block_hash,
            header.height,
            active,
            transaction_index,
            &previous,
        )?;
        self.require_same_tip(&chain).await?;
        Ok(Some(detail))
    }

    async fn previous_outputs(&self, tx: &Transaction) -> Result<BTreeMap<OutPoint, TxOut>> {
        let mut result = BTreeMap::new();
        if tx.is_coinbase() {
            return Ok(result);
        }
        for input in &tx.input {
            let raw: String = self
                .rpc
                .call(
                    "getrawtransaction",
                    json!([input.previous_output.txid.to_string(), false]),
                )
                .await
                .context("failed to resolve a previous transaction for fork detail")?;
            let previous: Transaction = decode_hex_consensus(&raw, "previous transaction")?;
            let output = previous
                .output
                .get(input.previous_output.vout as usize)
                .cloned()
                .context("previous transaction output is missing")?;
            result.insert(input.previous_output, output);
        }
        Ok(result)
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        let hash: String = self.rpc.call("getblockhash", json!([height])).await?;
        normalize_hash(&hash, "block hash")
    }

    async fn block_header(&self, hash: &str) -> Result<RpcBlockHeader> {
        self.block_header_optional(hash)
            .await?
            .context("Bitcoin Core block header was not found")
    }

    async fn block_header_optional(&self, hash: &str) -> Result<Option<RpcBlockHeader>> {
        let Some(header) = self
            .rpc
            .call_optional::<RpcBlockHeader>("getblockheader", json!([hash, true]))
            .await?
        else {
            return Ok(None);
        };
        if normalize_hash(&header.hash, "returned block hash")? != hash {
            bail!("Bitcoin Core returned a different block header");
        }
        Ok(Some(header))
    }

    async fn raw_block(&self, hash: &str) -> Result<Block> {
        let raw: String = self.rpc.call("getblock", json!([hash, 0])).await?;
        let block: Block = decode_hex_consensus(&raw, "block")?;
        if block.block_hash().to_string() != hash {
            bail!("Bitcoin Core returned a different raw block");
        }
        Ok(block)
    }
}

fn read_profile(path: &Path) -> Result<PohwCoreProfile> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Experiment 1 manifest {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Experiment 1 manifest must be a regular non-symlink file");
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        bail!("Experiment 1 manifest exceeds 1 MiB");
    }
    let payload = fs::read(path)
        .with_context(|| format!("failed to read Experiment 1 manifest {}", path.display()))?;
    let strict: StrictJson =
        serde_json::from_slice(&payload).context("Experiment 1 manifest is not strict JSON")?;
    validate_activation_id(&strict.0)?;
    serde_json::from_value(strict.0).context("Experiment 1 manifest has an invalid shape")
}

fn validate_profile(profile: &PohwCoreProfile) -> Result<()> {
    if profile.schema_version != "pohw-bitcoin-core-fork-manifest/v1"
        || profile.experiment_id != "pohw-experiment-1-full-consensus"
        || profile.profile_revision != 2
        || profile.status != "experimental-no-value"
        || profile.network.chain_argument != "pohw"
        || profile.consensus.engine != "bitcoin-core-v31.1-full"
        || !profile
            .consensus
            .all_upstream_transaction_and_script_rules_enabled
        || !profile.consensus.inherited_utxo_spending_enabled
        || !profile.consensus.replay_protection.required
    {
        bail!("manifest is not the supported no-value Experiment 1 profile");
    }
    normalize_hash(&profile.activation_id, "activation id")?;
    normalize_hash(&profile.fork_point.inherited_tip_hash, "inherited tip hash")?;
    normalize_hash(&profile.fork_point.first_fork_hash, "first fork hash")?;
    if profile.fork_point.first_fork_height
        != profile.fork_point.inherited_tip_height.saturating_add(1)
        || profile.consensus.proof_of_work.target_spacing_seconds == 0
        || profile
            .consensus
            .proof_of_work
            .post_handoff_retarget_interval
            == 0
        || profile.consensus.proof_of_work.handoff_version_bit > 30
    {
        bail!("Experiment 1 manifest has invalid fork or proof-of-work parameters");
    }
    let bits = &profile.consensus.proof_of_work.bootstrap_pow_limit_bits;
    if bits.len() != 8 || !bits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Experiment 1 manifest has invalid bootstrap bits");
    }
    Ok(())
}

fn validate_activation_id(manifest: &Value) -> Result<()> {
    const TAG: &[u8] = b"POHW_EXPERIMENT_1_ACTIVATION_V1\0";
    let object = manifest
        .as_object()
        .context("Experiment 1 manifest root must be an object")?;
    let declared = object
        .get("activation_id")
        .and_then(Value::as_str)
        .context("Experiment 1 manifest has no activation ID")?;
    normalize_hash(declared, "activation id")?;
    let mut payload = manifest.clone();
    payload
        .as_object_mut()
        .expect("manifest root was validated")
        .remove("activation_id");
    let mut canonical = Vec::new();
    write_canonical_json(&payload, &mut canonical)?;
    let mut tagged = Vec::with_capacity(TAG.len() + canonical.len());
    tagged.extend_from_slice(TAG);
    tagged.extend_from_slice(&canonical);
    let computed = sha256::Hash::hash(&tagged).to_string();
    if computed != declared {
        bail!("Experiment 1 activation ID does not match the canonical manifest payload");
    }
    Ok(())
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .context("failed to encode canonical manifest key")?;
                output.push(b':');
                write_canonical_json(item, output)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value)
            .context("failed to encode canonical manifest value")?,
    }
    Ok(())
}

fn normalize_hash(raw: &str, label: &str) -> Result<String> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be 32 bytes encoded as hex");
    }
    Ok(raw.to_ascii_lowercase())
}

fn decode_hex_consensus<T: bitcoin::consensus::Decodable>(raw: &str, label: &str) -> Result<T> {
    if raw.is_empty()
        || raw.len() % 2 != 0
        || raw.len() > MAX_BLOCK_HEX_BYTES.saturating_mul(2)
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{label} hex is outside supported bounds");
    }
    let bytes = hex::decode(raw).with_context(|| format!("{label} contains invalid hex"))?;
    deserialize(&bytes).with_context(|| format!("{label} is not consensus encoded"))
}

fn checked_output_total(transaction: &Transaction) -> Result<u64> {
    transaction.output.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value.to_sat())
            .context("transaction output total overflow")
    })
}

fn transaction_ref(
    tx: &Transaction,
    block_hash: &str,
    height: u64,
    active: bool,
    transaction_index: usize,
) -> Result<ForkTransactionRef> {
    Ok(ForkTransactionRef {
        txid: tx.compute_txid().to_string(),
        block_hash: block_hash.to_string(),
        height,
        active,
        transaction_index,
        coinbase: tx.is_coinbase(),
        total_output_sats: checked_output_total(tx)?,
        fee_sats: None,
    })
}

fn transaction_detail(
    tx: &Transaction,
    block_hash: &str,
    height: u64,
    active: bool,
    transaction_index: usize,
    previous: &BTreeMap<OutPoint, TxOut>,
) -> Result<ForkTransactionDetail> {
    let total_output_sats = checked_output_total(tx)?;
    let total_input_sats = if tx.is_coinbase() {
        None
    } else {
        Some(tx.input.iter().try_fold(0u64, |total, input| {
            total
                .checked_add(
                    previous
                        .get(&input.previous_output)
                        .context("previous output is unavailable")?
                        .value
                        .to_sat(),
                )
                .context("transaction input total overflow")
        })?)
    };
    let fee_sats = total_input_sats.and_then(|total| total.checked_sub(total_output_sats));
    let inputs = tx
        .input
        .iter()
        .enumerate()
        .map(|(vin, input)| ForkTransactionInput {
            vin,
            coinbase: tx.is_coinbase(),
            previous_txid: (!tx.is_coinbase()).then(|| input.previous_output.txid.to_string()),
            previous_vout: (!tx.is_coinbase()).then_some(input.previous_output.vout),
            script_sig_hex: hex::encode(input.script_sig.as_bytes()),
            script_sig_asm: input.script_sig.to_asm_string(),
            sequence: input.sequence.0,
            witness: input.witness.iter().map(hex::encode).collect(),
            previous_output: previous.get(&input.previous_output).map(previous_output),
        })
        .collect();
    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| ForkTransactionOutput {
            vout: u32::try_from(index).expect("Bitcoin output count fits u32"),
            value_sats: output.value.to_sat(),
            script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
            script_pubkey_asm: output.script_pubkey.to_asm_string(),
            script_type: script_type(output),
            address: output_address(output),
            script_hash: output_script_hash(output),
            spent_by: None,
        })
        .collect();
    Ok(ForkTransactionDetail {
        txid: tx.compute_txid().to_string(),
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

fn script_type(output: &TxOut) -> String {
    let script = &output.script_pubkey;
    if script.is_p2pkh() {
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
    }
    .to_string()
}

fn output_script_hash(output: &TxOut) -> String {
    sha256::Hash::hash(output.script_pubkey.as_bytes()).to_string()
}

fn pohw_commitment_hash(coinbase: &Transaction) -> Option<String> {
    const PAYLOAD_LEN: usize = 5 + 32;
    coinbase.output.iter().find_map(|output| {
        let script = output.script_pubkey.as_bytes();
        if script.len() != PAYLOAD_LEN + 2
            || script[0] != 0x6a
            || usize::from(script[1]) != PAYLOAD_LEN
            || &script[2..7] != b"POHW1"
        {
            return None;
        }
        Some(hex::encode(&script[7..]))
    })
}

fn rpc_number_string(value: &Value) -> String {
    match value {
        Value::Number(number) => number.to_string(),
        _ => "0".to_string(),
    }
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value.0);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key: {key}"
                )));
            }
        }
        Ok(StrictJson(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pohw-fork-explorer-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn strict_json_rejects_nested_duplicate_keys() {
        let error = serde_json::from_str::<StrictJson>(r#"{"a":{"b":1,"b":2}}"#)
            .err()
            .expect("duplicate key must fail");
        assert!(error.to_string().contains("duplicate JSON key: b"));
    }

    #[test]
    fn experiment_1_manifest_loads_as_supported_profile() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("compatibility/experiment-1-full-consensus.json");
        let profile = read_profile(&path).expect("profile loads");
        validate_profile(&profile).expect("profile is supported");
    }

    #[test]
    fn symlink_manifest_is_rejected() {
        let target = temp_path("target");
        let directory = temp_path("directory");
        fs::write(&target, b"{}\n").expect("write target");
        fs::create_dir(&directory).expect("create directory");
        let link = directory.join("manifest.json");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).expect("create symlink");
            assert!(read_profile(&link).is_err());
        }
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir(&directory);
        let _ = fs::remove_file(&target);
    }
}
