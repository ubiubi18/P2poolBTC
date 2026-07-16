use anyhow::{anyhow, bail, Context, Result};
use bitcoin::consensus::encode::deserialize;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::Transaction;
use chrono::{DateTime, Utc};
use pohw_core::commitment::PohwCommitment;
use pohw_core::fork::MainnetBlockRef;
use pohw_core::payout::PayoutSchedule;
use pohw_core::sharechain::{BitcoinWorkTemplate, Share};
use pohw_core::vault::{vault_script_pubkey_hex, VaultInput, VaultSpendPlan};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_RPC_CREDENTIAL_BYTES: usize = 512;
const MAX_RPC_COOKIE_FILE_BYTES: u64 = (MAX_RPC_CREDENTIAL_BYTES as u64 * 2) + 2;
const MAX_BITCOIN_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SUBMIT_BLOCK_BYTES: usize = 8 * 1024 * 1024;
const MAX_GBT_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUBMIT_BLOCK_REJECT_REASON_BYTES: usize = 1024;
pub(crate) const POHW_REPLAY_MARKER_SCRIPT_HEX: &str = "5150";
pub(crate) const POHW_EXPERIMENT_1_REPLAY_PROTECTION_RULE: &str =
    "inherited-input-requires-fork-marker-and-signature-domain-v3";
pub(crate) const POHW_EXPERIMENT_1_REPLAY_SIGHASH_DOMAIN: &str =
    "pohw-experiment-1-full-consensus/replay-sighash-v3";
pub(crate) const POHW_EXPERIMENT_1_FORK_HEIGHT: u64 = 958_016;
pub(crate) const POHW_EXPERIMENT_1_FORK_HASH: &str =
    "00000000000000000001d0f198da4adf33b597782a36c766685b2f217110cfc8";
pub(crate) const POHW_EXPERIMENT_1_FIRST_FORK_HASH: &str =
    "64d2122b44c111f2f593869ce404117d34c6c830f4390eb70245c11dcc503d01";
pub(crate) const POHW_EXPERIMENT_1_REPLAY_MARKER_ACTIVATION_HEIGHT: u64 = 958_018;
pub(crate) const POHW_EXPERIMENT_1_REPLAY_SIGHASH_ACTIVATION_HEIGHT: u64 = 958_176;
pub(crate) const POHW_EXPERIMENT_1_REPLAY_SIGHASH_PARENT_HASH: &str =
    "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6";
pub(crate) const POHW_EXPERIMENT_1_REPLAY_SIGHASH_VERSION_BIT: u32 = 1 << 30;
pub(crate) const POHW_EXPERIMENT_1_BOOTSTRAP_HANDOFF_HASHRATE_HPS: u64 = 1_000_000_000_000_000;

#[derive(Debug, Clone)]
pub struct BitcoinRpcClient {
    url: Url,
    auth: Option<BitcoinRpcAuth>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct BitcoinRpcAuth {
    username: String,
    password: String,
    cookie_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfoResponse {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    pub verificationprogress: f64,
    #[serde(default)]
    pub pruned: bool,
    #[serde(default)]
    pub pohw_experiment: Option<PohwExperimentInfoResponse>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PohwExperimentInfoResponse {
    pub fork_height: u64,
    pub fork_hash: String,
    pub first_fork_hash: String,
    pub inherited_utxo_spending: bool,
    pub replay_protection: String,
    pub replay_marker_activation_height: u64,
    pub replay_sighash_activation_height: u64,
    pub replay_sighash_parent_hash: String,
    pub replay_sighash_version_bit: u32,
    pub replay_sighash_domain: String,
    pub bootstrap_handoff_hashrate_hps: u64,
    pub handoff_active: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResponse {
    pub confirmations: u32,
    pub value: serde_json::Value,
    pub script_pub_key: ScriptPubKeyResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPubKeyResponse {
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbasePayoutConfirmation {
    pub fork_block_height: u64,
    pub fork_block_hash: String,
    pub coinbase_txid: String,
    pub pohw_commitment_hash: String,
    pub expected_output_total_sats: u64,
    pub confirmed_output_total_sats: u64,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinWorkTemplateValidationPolicy {
    pub allow_mutable_time: bool,
    pub max_time_drift_seconds: u32,
    pub expected_header_merkle_root_hex: Option<String>,
    pub allow_unverified_merkle_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitcoinWorkTemplateValidation {
    pub template_hash: String,
    pub previous_block_hash: String,
    pub height: u64,
    pub header_version: i32,
    pub header_time: u32,
    pub bits: String,
    pub target: String,
    pub header_merkle_root_hex: String,
    pub merkle_root_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinMiningJobTemplate {
    pub version: i32,
    pub previous_block_hash: String,
    pub curtime: u32,
    pub bits: String,
    pub height: u64,
    pub coinbase_value_sats: u64,
    pub transaction_hashes: Vec<String>,
    pub transactions: Vec<BitcoinMiningJobTransaction>,
    pub default_witness_commitment: Option<String>,
    #[serde(default)]
    pub pohw_replay_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinMiningJobTransaction {
    pub txid: String,
    pub data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubmitBlockOutcome {
    pub status: String,
    pub reject_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GetBlockTemplateResponse {
    version: i32,
    previousblockhash: String,
    curtime: u32,
    bits: String,
    target: String,
    height: u64,
    #[serde(default)]
    coinbasevalue: Option<u64>,
    #[serde(default)]
    default_witness_commitment: Option<String>,
    #[serde(default)]
    pohw_replay_marker: Option<String>,
    #[serde(default)]
    mintime: Option<u32>,
    #[serde(default)]
    mutable: Vec<String>,
    #[serde(default)]
    transactions: Option<Vec<GetBlockTemplateTransactionResponse>>,
}

#[derive(Debug, Clone, Deserialize)]
struct GetBlockTemplateTransactionResponse {
    #[serde(default)]
    txid: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GetBlockVerbose1Response {
    hash: String,
    height: u64,
    #[serde(default)]
    confirmations: Option<i64>,
    tx: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GetBlockHeaderResponse {
    hash: String,
    height: u64,
    version: i32,
    merkleroot: String,
    time: i64,
    #[serde(default)]
    bits: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawTransactionVerboseResponse {
    txid: String,
    #[serde(default)]
    vin: Vec<BlockTransactionInputResponse>,
    #[serde(default)]
    vout: Vec<BlockTransactionOutputResponse>,
}

#[derive(Debug, Clone, Deserialize)]
struct BlockTransactionInputResponse {
    #[serde(default)]
    coinbase: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BlockTransactionOutputResponse {
    value: serde_json::Value,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKeyResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoinbasePayoutOutput {
    script_pubkey_hex: String,
    amount_sats: u64,
}

impl BitcoinRpcClient {
    pub fn new(url: impl AsRef<str>, auth: Option<BitcoinRpcAuth>) -> Result<Self> {
        Self::new_with_remote_policy(url, auth, false)
    }

    pub fn new_with_remote_policy(
        url: impl AsRef<str>,
        auth: Option<BitcoinRpcAuth>,
        allow_remote_rpc: bool,
    ) -> Result<Self> {
        let url = validate_rpc_url(
            Url::parse(url.as_ref()).context("invalid Bitcoin RPC URL")?,
            allow_remote_rpc,
        )?;
        Ok(Self {
            url,
            auth,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .context("failed to build Bitcoin RPC HTTP client")?,
        })
    }

    pub fn auth_from_user_password(
        username: Option<String>,
        password: Option<String>,
        cookie_file: Option<impl AsRef<Path>>,
    ) -> Result<Option<BitcoinRpcAuth>> {
        match (username, password, cookie_file) {
            (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                bail!("Bitcoin RPC cookie file cannot be combined with username/password auth")
            }
            (None, None, Some(path)) => BitcoinRpcAuth::from_cookie_file(path).map(Some),
            (Some(username), Some(password), None) => {
                BitcoinRpcAuth::new(username, password).map(Some)
            }
            (None, None, None) => Ok(None),
            _ => bail!("Bitcoin RPC username and password must be supplied together"),
        }
    }

    pub async fn get_tx_out(
        &self,
        txid: &str,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<GetTxOutResponse>> {
        self.call("gettxout", json!([txid, vout, include_mempool]))
            .await
    }

    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfoResponse> {
        self.call("getblockchaininfo", json!([])).await
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let hash: String = self.call("getblockhash", json!([height])).await?;
        normalize_hash_hex("block hash", &hash)
    }

    pub async fn mainnet_block_ref_by_height(&self, height: u64) -> Result<MainnetBlockRef> {
        let block_hash = self.get_block_hash(height).await?;
        let header: GetBlockHeaderResponse = self
            .call("getblockheader", json!([&block_hash, true]))
            .await?;
        let returned_hash = normalize_hash_hex("block header hash", &header.hash)?;
        if returned_hash != block_hash {
            bail!(
                "Bitcoin RPC returned block header {}, expected {}",
                returned_hash,
                block_hash
            );
        }
        if header.height != height {
            bail!(
                "Bitcoin RPC returned block height {}, expected {} for {}",
                header.height,
                height,
                block_hash
            );
        }
        let timestamp = unix_timestamp_to_utc(header.time).with_context(|| {
            format!(
                "Bitcoin RPC block header {} has invalid timestamp {}",
                block_hash, header.time
            )
        })?;
        Ok(MainnetBlockRef {
            height,
            block_hash,
            timestamp,
        })
    }

    pub async fn validate_bitcoin_work_template(
        &self,
        template: &BitcoinWorkTemplate,
        policy: BitcoinWorkTemplateValidationPolicy,
    ) -> Result<BitcoinWorkTemplateValidation> {
        self.validate_bitcoin_work_template_with_time_dependent_bits(template, policy, false)
            .await
    }

    async fn validate_bitcoin_work_template_with_time_dependent_bits(
        &self,
        template: &BitcoinWorkTemplate,
        policy: BitcoinWorkTemplateValidationPolicy,
        allow_pohw_time_dependent_bits: bool,
    ) -> Result<BitcoinWorkTemplateValidation> {
        let block_template: GetBlockTemplateResponse = self
            .call("getblocktemplate", json!([{ "rules": ["segwit"] }]))
            .await?;
        validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
            template,
            &block_template,
            &policy,
            allow_pohw_time_dependent_bits,
        )
    }

    pub async fn validate_historical_bitcoin_work_template(
        &self,
        template: &BitcoinWorkTemplate,
    ) -> Result<BitcoinWorkTemplateValidation> {
        let parsed = ParsedHeaderPrefix::parse(&template.header_prefix_hex)?;
        let previous: GetBlockHeaderResponse = self
            .call("getblockheader", json!([&parsed.previous_block_hash, true]))
            .await
            .context("failed to read historical template previous block")?;
        let active_previous_hash: String = self
            .call("getblockhash", json!([previous.height]))
            .await
            .context("failed to locate historical template previous block on active chain")?;
        let active_previous_hash =
            normalize_hash_hex("active previous block", &active_previous_hash)?;
        let height = previous
            .height
            .checked_add(1)
            .context("historical template height overflow")?;
        let next_hash: String = self
            .call("getblockhash", json!([height]))
            .await
            .context("historical template has no active-chain successor")?;
        let next_hash = normalize_hash_hex("historical successor block", &next_hash)?;
        let next: GetBlockHeaderResponse = self
            .call("getblockheader", json!([&next_hash, true]))
            .await
            .context("failed to read historical template successor block")?;
        validate_historical_bitcoin_work_template_against_active_chain(
            template,
            &active_previous_hash,
            &previous,
            &next_hash,
            &next,
        )
    }

    pub async fn validate_bitcoin_share(
        &self,
        template: &BitcoinWorkTemplate,
        share: &Share,
        policy: BitcoinWorkTemplateValidationPolicy,
        allow_pohw_time_dependent_bits: bool,
    ) -> Result<BitcoinWorkTemplateValidation> {
        if !share
            .bitcoin_template_hash
            .eq_ignore_ascii_case(&template.template_hash)
        {
            bail!("share references a different Bitcoin work template");
        }

        match self
            .validate_bitcoin_work_template_with_time_dependent_bits(
                template,
                policy,
                allow_pohw_time_dependent_bits,
            )
            .await
        {
            Ok(validation) => Ok(validation),
            Err(current_error) => {
                let validation = self
                    .validate_historical_bitcoin_work_template(template)
                    .await
                    .with_context(|| {
                        format!(
                            "Bitcoin work template is neither current nor an exact active-chain block: {current_error}"
                        )
                    })?;
                let active_hash: String = self
                    .call("getblockhash", json!([validation.height]))
                    .await
                    .context("failed to resolve historical share block on active chain")?;
                let active_hash = normalize_hash_hex("historical share block", &active_hash)?;
                let work_hash = normalize_hash_hex("share work hash", &share.work_hash)?;
                if work_hash != active_hash {
                    bail!(
                        "stale share work hash {work_hash} is not the active-chain block {active_hash} at height {}",
                        validation.height
                    );
                }
                Ok(validation)
            }
        }
    }

    pub(super) async fn mining_job_template_unchecked(&self) -> Result<BitcoinMiningJobTemplate> {
        let block_template: GetBlockTemplateResponse = self
            .call("getblocktemplate", json!([{ "rules": ["segwit"] }]))
            .await?;
        mining_job_template_from_getblocktemplate(&block_template)
    }

    pub async fn submit_block(&self, block_hex: &str) -> Result<SubmitBlockOutcome> {
        let block_hex = normalize_block_hex("block hex", block_hex)?;
        let result = self.call_value("submitblock", json!([block_hex])).await?;
        let reject_reason = submitblock_reject_reason_from_result(result)?;
        let status = if reject_reason.is_some() {
            "rejected"
        } else {
            "accepted"
        };
        Ok(SubmitBlockOutcome {
            status: status.to_string(),
            reject_reason,
        })
    }

    pub async fn block_confirmations(&self, block_hash: &str) -> Result<u32> {
        let requested_block_hash = normalize_hash_hex("requested block hash", block_hash)?;
        let block: GetBlockVerbose1Response = self.call("getblock", json!([block_hash, 1])).await?;
        let returned_block_hash = normalize_hash_hex("block hash", &block.hash)?;
        if returned_block_hash != requested_block_hash {
            bail!(
                "Bitcoin RPC returned block hash {}, expected {}",
                returned_block_hash,
                requested_block_hash
            );
        }
        let confirmations = block.confirmations.unwrap_or(0);
        if confirmations < 0 {
            bail!(
                "block {} is not on the active chain; confirmations={}",
                block.hash,
                confirmations
            );
        }
        u32::try_from(confirmations).context("confirmations do not fit u32")
    }

    pub async fn confirm_coinbase_payout(
        &self,
        block_hash: &str,
        schedule: &PayoutSchedule,
        pohw_commitment: &PohwCommitment,
        min_confirmations: u32,
    ) -> Result<CoinbasePayoutConfirmation> {
        let requested_block_hash = normalize_hash_hex("requested block hash", block_hash)?;
        let block: GetBlockVerbose1Response = self.call("getblock", json!([block_hash, 1])).await?;
        let returned_block_hash = normalize_hash_hex("block hash", &block.hash)?;
        if returned_block_hash != requested_block_hash {
            bail!(
                "Bitcoin RPC returned block hash {}, expected {}",
                returned_block_hash,
                requested_block_hash
            );
        }
        let confirmations = block.confirmations.unwrap_or(0);
        if confirmations < i64::from(min_confirmations) {
            bail!(
                "block {} has {} confirmations; minimum is {}",
                block.hash,
                confirmations,
                min_confirmations
            );
        }
        let coinbase_txid = block
            .tx
            .first()
            .ok_or_else(|| anyhow!("block {} has no transactions", block.hash))?;
        let coinbase: RawTransactionVerboseResponse = self
            .call(
                "getrawtransaction",
                json!([coinbase_txid, true, &returned_block_hash]),
            )
            .await?;
        let returned_coinbase_txid = normalize_hash_hex("coinbase txid", &coinbase.txid)?;
        let expected_coinbase_txid = normalize_hash_hex("coinbase txid", coinbase_txid)?;
        if returned_coinbase_txid != expected_coinbase_txid {
            bail!(
                "Bitcoin RPC returned coinbase transaction {}, expected {}",
                returned_coinbase_txid,
                expected_coinbase_txid
            );
        }
        if !coinbase
            .vin
            .first()
            .is_some_and(|input| input.coinbase.is_some())
        {
            bail!("first transaction in block {} is not coinbase", block.hash);
        }
        let outputs = coinbase
            .vout
            .iter()
            .map(|output| {
                Ok(CoinbasePayoutOutput {
                    script_pubkey_hex: normalize_script_pubkey_hex(
                        "coinbase output scriptPubKey",
                        &output.script_pub_key.hex,
                    )?,
                    amount_sats: btc_value_to_sats(&output.value)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let vault_script_pubkey_hex =
            vault_script_pubkey_hex(&pohw_commitment.frost_vault_key_xonly)
                .context("invalid FROST vault key in POHW commitment")?;
        let output_totals = verify_coinbase_payout_outputs(
            schedule,
            &vault_script_pubkey_hex,
            pohw_commitment,
            &outputs,
        )?;
        Ok(CoinbasePayoutConfirmation {
            fork_block_height: block.height,
            fork_block_hash: returned_block_hash,
            coinbase_txid: normalize_hash_hex("coinbase txid", &coinbase.txid)?,
            pohw_commitment_hash: pohw_commitment.commitment_hash(),
            expected_output_total_sats: output_totals.expected_output_total_sats,
            confirmed_output_total_sats: output_totals.confirmed_output_total_sats,
            confirmations: u32::try_from(confirmations).context("confirmations do not fit u32")?,
        })
    }

    pub async fn validate_vault_input(
        &self,
        txid: &str,
        vout: u32,
        frost_group_key_xonly: &str,
        min_confirmations: u32,
    ) -> Result<VaultInput> {
        let expected_script_pubkey_hex = vault_script_pubkey_hex(frost_group_key_xonly)?;
        let txout = self.get_tx_out(txid, vout, false).await?.ok_or_else(|| {
            anyhow!("Bitcoin RPC gettxout returned no spendable UTXO for {txid}:{vout}")
        })?;

        if txout.confirmations < min_confirmations {
            bail!(
                "vault input {txid}:{vout} has {} confirmations; minimum is {min_confirmations}",
                txout.confirmations
            );
        }

        let script_pubkey_hex = txout.script_pub_key.hex.to_ascii_lowercase();
        if script_pubkey_hex != expected_script_pubkey_hex {
            bail!(
                "vault input {txid}:{vout} scriptPubKey mismatch: expected {expected_script_pubkey_hex}, got {script_pubkey_hex}"
            );
        }

        Ok(VaultInput {
            txid: txid.to_ascii_lowercase(),
            vout,
            amount_sats: btc_value_to_sats(&txout.value)?,
            confirmations: txout.confirmations,
            script_pubkey_hex,
        })
    }

    pub async fn revalidate_vault_spend_plan_inputs(
        &self,
        plan: &VaultSpendPlan,
        min_confirmations: u32,
    ) -> Result<Vec<VaultInput>> {
        let mut fresh_inputs = Vec::with_capacity(plan.inputs.len());
        for planned_input in &plan.inputs {
            let fresh_input = self
                .validate_vault_input(
                    &planned_input.txid,
                    planned_input.vout,
                    &plan.frost_group_key_xonly,
                    min_confirmations,
                )
                .await?;
            ensure_fresh_input_matches_plan(planned_input, &fresh_input)?;
            fresh_inputs.push(fresh_input);
        }
        Ok(fresh_inputs)
    }

    pub(crate) async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let result = self.call_value(method, params).await?;
        serde_json::from_value(result)
            .with_context(|| format!("Bitcoin RPC response {method} result has unexpected shape"))
    }

    pub(crate) async fn call_optional<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Option<T>> {
        self.call_value_optional(method, params, &[-5])
            .await?
            .map(|result| {
                serde_json::from_value(result).with_context(|| {
                    format!("Bitcoin RPC response {method} result has unexpected shape")
                })
            })
            .transpose()
    }

    async fn call_value(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.call_value_optional(method, params, &[])
            .await?
            .ok_or_else(|| anyhow!("Bitcoin RPC {method} returned no result"))
    }

    async fn call_value_optional(
        &self,
        method: &str,
        params: serde_json::Value,
        not_found_codes: &[i64],
    ) -> Result<Option<serde_json::Value>> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "pohw-p2pool",
            "method": method,
            "params": params,
        });
        let mut request = self.client.post(self.url.clone()).json(&body);
        if let Some(auth) = &self.auth {
            let credentials = auth
                .credentials()
                .with_context(|| format!("failed to load Bitcoin RPC credentials for {method}"))?;
            request = request.basic_auth(credentials.username, Some(credentials.password));
        }
        let mut response = request
            .send()
            .await
            .with_context(|| format!("Bitcoin RPC request {method} failed"))?
            .error_for_status()
            .with_context(|| format!("Bitcoin RPC request {method} returned HTTP error"))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BITCOIN_RPC_RESPONSE_BYTES as u64)
        {
            bail!("Bitcoin RPC response {method} is too large");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("Bitcoin RPC response {method} failed while reading body"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_BITCOIN_RPC_RESPONSE_BYTES {
                bail!("Bitcoin RPC response {method} is too large");
            }
            body.extend_from_slice(&chunk);
        }
        let response: JsonRpcResponse = serde_json::from_slice(&body)
            .with_context(|| format!("Bitcoin RPC response {method} is not valid JSON"))?;

        if let Some(error) = response.error {
            if not_found_codes.contains(&error.code) {
                return Ok(None);
            }
            return Err(anyhow!(
                "Bitcoin RPC {method} error {}: {}",
                error.code,
                error.message
            ));
        }
        match response.result {
            JsonRpcResult::Present(result) => Ok(Some(result)),
            JsonRpcResult::Missing => Err(anyhow!("Bitcoin RPC {method} returned no result")),
        }
    }
}

impl BitcoinRpcAuth {
    fn new(username: String, password: String) -> Result<Self> {
        Ok(Self {
            username: validate_rpc_credential(username, "Bitcoin RPC username")?,
            password: validate_rpc_credential(password, "Bitcoin RPC password")?,
            cookie_file: None,
        })
    }

    pub fn from_cookie_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let credentials = read_cookie_credentials(path)?;
        Ok(Self {
            username: credentials.username,
            password: credentials.password,
            cookie_file: Some(path.to_path_buf()),
        })
    }

    fn credentials(&self) -> Result<BitcoinRpcCredentials> {
        if let Some(path) = &self.cookie_file {
            read_cookie_credentials(path)
        } else {
            Ok(BitcoinRpcCredentials {
                username: self.username.clone(),
                password: self.password.clone(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitcoinRpcCredentials {
    username: String,
    password: String,
}

fn read_cookie_credentials(path: &Path) -> Result<BitcoinRpcCredentials> {
    validate_protected_secret_file(path, "Bitcoin RPC cookie")?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Bitcoin RPC cookie {}", path.display()))?;
    if metadata.len() > MAX_RPC_COOKIE_FILE_BYTES {
        bail!(
            "Bitcoin RPC cookie {} is too large: {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            MAX_RPC_COOKIE_FILE_BYTES
        );
    }
    let cookie = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read Bitcoin RPC cookie {}", path.display()))?;
    let (username, password) = cookie
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow!("Bitcoin RPC cookie must contain username:password"))?;
    Ok(BitcoinRpcCredentials {
        username: validate_rpc_credential(username.to_string(), "Bitcoin RPC username")?,
        password: validate_rpc_credential(password.to_string(), "Bitcoin RPC password")?,
    })
}

fn validate_rpc_url(url: Url, allow_remote_rpc: bool) -> Result<Url> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("Bitcoin RPC URL scheme must be http or https");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Bitcoin RPC URL must include a host"))?;
    if !allow_remote_rpc && !is_loopback_rpc_host(host) {
        bail!("Bitcoin RPC URL host must be loopback unless remote RPC is explicitly allowed");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Bitcoin RPC URL must not include userinfo; use RPC auth options instead");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("Bitcoin RPC URL must not include query or fragment data");
    }
    Ok(url)
}

fn is_loopback_rpc_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip_address| ip_address.is_loopback())
}

fn validate_rpc_credential(value: String, label: &str) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > MAX_RPC_CREDENTIAL_BYTES {
        bail!("{label} must be 1-{MAX_RPC_CREDENTIAL_BYTES} bytes");
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("{label} must not contain control characters");
    }
    Ok(value)
}

fn validate_protected_secret_file(path: &Path, label: &str) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        validate_private_file_parent(parent, label)?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} file {} must not be a symlink", path.display());
    }
    if !metadata.file_type().is_file() {
        bail!("{label} path {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o640 {
            bail!(
                "{label} file {} has unsupported permissions ({mode:o}); use 600 for one service or 640 with a dedicated RPC-reader group",
                path.display(),
            );
        }
    }
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn validate_private_file_parent(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect {label} file directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        bail!(
            "{label} file directory {} must not be a symlink",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!(
            "{label} file directory path {} is not a directory",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            bail!(
                "{label} file directory {} is writable by group or others ({mode:o}); use a private directory or chmod go-w {}",
                path.display(),
                path.display()
            );
        }
    }
    validate_no_unsafe_symlink_ancestors(path, label)?;
    Ok(())
}

#[cfg(unix)]
fn validate_no_unsafe_symlink_ancestors(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for RPC secret path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect {label} symlink ancestor {}",
                        ancestor.display()
                    )
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = ancestor.parent().unwrap_or_else(|| Path::new("/"));
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect {label} symlink ancestor parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            bail!(
                "{label} file directory {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_symlink_ancestors(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default, deserialize_with = "deserialize_json_rpc_result")]
    result: JsonRpcResult,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum JsonRpcResult {
    #[default]
    Missing,
    Present(serde_json::Value),
}

fn deserialize_json_rpc_result<'de, D>(
    deserializer: D,
) -> std::result::Result<JsonRpcResult, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(JsonRpcResult::Present)
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoinbasePayoutOutputTotals {
    expected_output_total_sats: u64,
    confirmed_output_total_sats: u64,
}

fn verify_coinbase_payout_outputs(
    schedule: &PayoutSchedule,
    vault_script_pubkey_hex: &str,
    pohw_commitment: &PohwCommitment,
    outputs: &[CoinbasePayoutOutput],
) -> Result<CoinbasePayoutOutputTotals> {
    schedule.validate()?;
    if pohw_commitment.version != "POHW1" {
        bail!(
            "POHW commitment version must be POHW1, got {}",
            pohw_commitment.version
        );
    }
    if !pohw_commitment
        .payout_schedule_root
        .eq_ignore_ascii_case(&schedule.payout_root)
    {
        bail!(
            "POHW commitment payout root {} does not match schedule root {}",
            pohw_commitment.payout_schedule_root,
            schedule.payout_root
        );
    }
    let expected_commitment_script = normalize_script_pubkey_hex(
        "POHW commitment script",
        &pohw_commitment.op_return_script_pubkey_hex(),
    )?;
    if !outputs.iter().any(|output| {
        output.amount_sats == 0
            && normalize_script_pubkey_hex("coinbase output script", &output.script_pubkey_hex)
                .is_ok_and(|script| script == expected_commitment_script)
    }) {
        bail!(
            "coinbase is missing zero-value POHW1 commitment output for {}",
            pohw_commitment.commitment_hash()
        );
    }

    let mut expected = BTreeMap::<(String, u64), u32>::new();
    for output in &schedule.direct_outputs {
        add_output_multiset(
            &mut expected,
            normalize_script_pubkey_hex("direct payout script", &output.btc_payout_script_hex)?,
            output.amount_sats,
        )?;
    }
    if schedule.vault_output_sats > 0 {
        add_output_multiset(
            &mut expected,
            normalize_script_pubkey_hex("vault script", vault_script_pubkey_hex)?,
            schedule.vault_output_sats,
        )?;
    }

    let mut actual = BTreeMap::<(String, u64), u32>::new();
    for output in outputs {
        if output.amount_sats == 0 {
            continue;
        }
        add_output_multiset(
            &mut actual,
            normalize_script_pubkey_hex("coinbase output script", &output.script_pubkey_hex)?,
            output.amount_sats,
        )?;
    }

    if actual != expected {
        bail!(
            "coinbase positive-value outputs do not match payout schedule: expected {}, got {}",
            format_output_multiset(&expected),
            format_output_multiset(&actual)
        );
    }
    Ok(CoinbasePayoutOutputTotals {
        expected_output_total_sats: output_multiset_total_sats(
            "expected payout outputs",
            &expected,
        )?,
        confirmed_output_total_sats: output_multiset_total_sats(
            "confirmed coinbase outputs",
            &actual,
        )?,
    })
}

#[cfg(test)]
fn validate_bitcoin_work_template_against_getblocktemplate(
    template: &BitcoinWorkTemplate,
    block_template: &GetBlockTemplateResponse,
    policy: &BitcoinWorkTemplateValidationPolicy,
) -> Result<BitcoinWorkTemplateValidation> {
    validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
        template,
        block_template,
        policy,
        false,
    )
}

fn validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
    template: &BitcoinWorkTemplate,
    block_template: &GetBlockTemplateResponse,
    policy: &BitcoinWorkTemplateValidationPolicy,
    allow_pohw_time_dependent_bits: bool,
) -> Result<BitcoinWorkTemplateValidation> {
    template.verify_template_hash()?;
    let parsed = ParsedHeaderPrefix::parse(&template.header_prefix_hex)?;

    if parsed.version != block_template.version {
        bail!(
            "Bitcoin work template version {} does not match getblocktemplate version {}",
            parsed.version,
            block_template.version
        );
    }

    let previousblockhash = normalize_hash_hex(
        "getblocktemplate previousblockhash",
        &block_template.previousblockhash,
    )?;
    if parsed.previous_block_hash != previousblockhash {
        bail!(
            "Bitcoin work template previous block {} does not match getblocktemplate previous block {}",
            parsed.previous_block_hash,
            previousblockhash
        );
    }

    let current_bits = normalize_bits_hex(&block_template.bits)?;
    let current_target = target_hex_from_bits(&current_bits)?;
    let gbt_target = normalize_hash_hex("getblocktemplate target", &block_template.target)?;
    if current_target != gbt_target {
        bail!(
            "getblocktemplate target {} does not match bits-derived target {}",
            gbt_target,
            current_target
        );
    }

    let (validated_bits, validated_target) = if parsed.bits == current_bits {
        (current_bits, current_target)
    } else {
        let time_is_mutable = block_template.mutable.iter().any(|value| value == "time");
        if !allow_pohw_time_dependent_bits
            || !policy.allow_mutable_time
            || !time_is_mutable
            || parsed.time > block_template.curtime
        {
            bail!(
                "Bitcoin work template bits {} does not match getblocktemplate bits {}",
                parsed.bits,
                current_bits
            );
        }
        let stale_target = target_from_bits(&parsed.bits)?;
        let active_target = target_from_bits(&current_bits)?;
        if stale_target > active_target {
            bail!("time-dependent PoHW template target is easier than the current target");
        }
        (parsed.bits.clone(), hex::encode(stale_target.to_be_bytes()))
    };

    validate_template_time(parsed.time, block_template, policy)?;
    let merkle_root_status = validate_template_merkle_root(&parsed.merkle_root_hex, policy)?;

    Ok(BitcoinWorkTemplateValidation {
        template_hash: template.template_hash.to_ascii_lowercase(),
        previous_block_hash: previousblockhash,
        height: block_template.height,
        header_version: parsed.version,
        header_time: parsed.time,
        bits: validated_bits,
        target: validated_target,
        header_merkle_root_hex: parsed.merkle_root_hex,
        merkle_root_status,
    })
}

fn validate_historical_bitcoin_work_template_against_active_chain(
    template: &BitcoinWorkTemplate,
    active_previous_hash: &str,
    previous: &GetBlockHeaderResponse,
    active_next_hash: &str,
    next: &GetBlockHeaderResponse,
) -> Result<BitcoinWorkTemplateValidation> {
    template.verify_template_hash()?;
    let parsed = ParsedHeaderPrefix::parse(&template.header_prefix_hex)?;
    let active_previous_hash = normalize_hash_hex("active previous block", active_previous_hash)?;
    let returned_previous_hash = normalize_hash_hex("previous block header", &previous.hash)?;
    if parsed.previous_block_hash != returned_previous_hash
        || parsed.previous_block_hash != active_previous_hash
    {
        bail!(
            "historical template previous block {} is not the active block at height {}",
            parsed.previous_block_hash,
            previous.height
        );
    }
    let height = previous
        .height
        .checked_add(1)
        .context("historical template height overflow")?;
    let active_next_hash = normalize_hash_hex("historical successor block", active_next_hash)?;
    if next.height != height
        || normalize_hash_hex("historical successor header", &next.hash)? != active_next_hash
    {
        bail!("Bitcoin RPC returned inconsistent historical successor header");
    }
    let next_bits = normalize_bits_hex(
        next.bits
            .as_deref()
            .context("historical successor header is missing bits")?,
    )?;
    if parsed.bits != next_bits {
        bail!(
            "historical template bits {} do not match active successor bits {}",
            parsed.bits,
            next_bits
        );
    }
    if parsed.version != next.version {
        bail!(
            "historical template version {} does not match active successor version {}",
            parsed.version,
            next.version
        );
    }
    let next_time =
        u32::try_from(next.time).context("historical successor time is out of range")?;
    if parsed.time != next_time {
        bail!(
            "historical template time {} does not match active successor time {}",
            parsed.time,
            next_time
        );
    }
    let next_merkle_root =
        display_hash_to_header_order_hex("historical successor merkle root", &next.merkleroot)?;
    if parsed.merkle_root_hex != next_merkle_root {
        bail!(
            "historical template merkle root {} does not match active successor merkle root {}",
            parsed.merkle_root_hex,
            next_merkle_root
        );
    }
    let target = target_hex_from_bits(&next_bits)?;
    Ok(BitcoinWorkTemplateValidation {
        template_hash: template.template_hash.to_ascii_lowercase(),
        previous_block_hash: parsed.previous_block_hash,
        height,
        header_version: parsed.version,
        header_time: parsed.time,
        bits: next_bits,
        target,
        header_merkle_root_hex: parsed.merkle_root_hex,
        merkle_root_status: "historical-exact-active-chain-header".to_string(),
    })
}

fn mining_job_template_from_getblocktemplate(
    block_template: &GetBlockTemplateResponse,
) -> Result<BitcoinMiningJobTemplate> {
    let previous_block_hash = normalize_hash_hex(
        "getblocktemplate previousblockhash",
        &block_template.previousblockhash,
    )?;
    let bits = normalize_bits_hex(&block_template.bits)?;
    let expected_target = target_hex_from_bits(&bits)?;
    let gbt_target = normalize_hash_hex("getblocktemplate target", &block_template.target)?;
    if expected_target != gbt_target {
        bail!(
            "getblocktemplate target {} does not match bits-derived target {}",
            gbt_target,
            expected_target
        );
    }
    let transactions = block_template
        .transactions
        .as_ref()
        .ok_or_else(|| anyhow!("getblocktemplate response is missing transactions"))?;
    let mut transaction_hashes = Vec::with_capacity(transactions.len());
    let mut transaction_data = Vec::with_capacity(transactions.len());
    for (index, tx) in transactions.iter().enumerate() {
        let txid = tx
            .txid
            .as_ref()
            .ok_or_else(|| anyhow!("getblocktemplate transaction {index} is missing txid"))?;
        let txid =
            normalize_hash_hex("getblocktemplate transaction txid", txid).with_context(|| {
                format!("invalid getblocktemplate transaction txid at index {index}")
            })?;
        let data_hex = tx
            .data
            .as_ref()
            .ok_or_else(|| anyhow!("getblocktemplate transaction {index} is missing data"))?;
        let data_hex = normalize_transaction_hex(data_hex).with_context(|| {
            format!("invalid getblocktemplate transaction data at index {index}")
        })?;
        let tx_bytes = hex::decode(&data_hex).context("normalized transaction hex must decode")?;
        let decoded: Transaction = deserialize(&tx_bytes).with_context(|| {
            format!(
                "getblocktemplate transaction data at index {index} is not a Bitcoin transaction"
            )
        })?;
        let decoded_txid = decoded.compute_txid().to_string();
        if decoded_txid != txid {
            bail!(
                "getblocktemplate transaction {index} data txid {decoded_txid} does not match advertised txid {txid}"
            );
        }
        transaction_hashes.push(txid.clone());
        transaction_data.push(BitcoinMiningJobTransaction { txid, data_hex });
    }
    let coinbase_value_sats = block_template
        .coinbasevalue
        .ok_or_else(|| anyhow!("getblocktemplate response is missing coinbasevalue"))?;
    let default_witness_commitment = block_template
        .default_witness_commitment
        .as_deref()
        .map(normalize_witness_commitment_script_hex)
        .transpose()?;
    let pohw_replay_marker = block_template
        .pohw_replay_marker
        .as_deref()
        .map(normalize_pohw_replay_marker_script_hex)
        .transpose()?;
    Ok(BitcoinMiningJobTemplate {
        version: block_template.version,
        previous_block_hash,
        curtime: block_template.curtime,
        bits,
        height: block_template.height,
        coinbase_value_sats,
        transaction_hashes,
        transactions: transaction_data,
        default_witness_commitment,
        pohw_replay_marker,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHeaderPrefix {
    version: i32,
    previous_block_hash: String,
    merkle_root_hex: String,
    time: u32,
    bits: String,
}

impl ParsedHeaderPrefix {
    fn parse(header_prefix_hex: &str) -> Result<Self> {
        let normalized = normalize_fixed_hex("Bitcoin header prefix", header_prefix_hex, 76)?;
        let bytes = hex::decode(&normalized).context("Bitcoin header prefix is invalid hex")?;
        let version = i32::from_le_bytes(bytes[0..4].try_into().expect("slice length checked"));
        let previous_block_hash = reversed_display_hash(&bytes[4..36]);
        let merkle_root_hex = hex::encode(&bytes[36..68]);
        let time = u32::from_le_bytes(bytes[68..72].try_into().expect("slice length checked"));
        let bits_value =
            u32::from_le_bytes(bytes[72..76].try_into().expect("slice length checked"));
        Ok(Self {
            version,
            previous_block_hash,
            merkle_root_hex,
            time,
            bits: format!("{bits_value:08x}"),
        })
    }
}

fn validate_template_time(
    header_time: u32,
    block_template: &GetBlockTemplateResponse,
    policy: &BitcoinWorkTemplateValidationPolicy,
) -> Result<()> {
    let time_is_mutable = block_template.mutable.iter().any(|value| value == "time");
    if !policy.allow_mutable_time || !time_is_mutable {
        if header_time != block_template.curtime {
            bail!(
                "Bitcoin work template time {} does not match getblocktemplate curtime {}",
                header_time,
                block_template.curtime
            );
        }
        return Ok(());
    }

    let min_time = block_template.mintime.unwrap_or(block_template.curtime);
    let max_time = block_template
        .curtime
        .checked_add(policy.max_time_drift_seconds)
        .ok_or_else(|| anyhow!("getblocktemplate time drift overflows u32"))?;
    if header_time < min_time || header_time > max_time {
        bail!(
            "Bitcoin work template mutable time {} is outside allowed range {}..={}",
            header_time,
            min_time,
            max_time
        );
    }
    Ok(())
}

fn validate_template_merkle_root(
    header_merkle_root_hex: &str,
    policy: &BitcoinWorkTemplateValidationPolicy,
) -> Result<String> {
    if header_merkle_root_hex == "00".repeat(32) {
        bail!("Bitcoin work template merkle root must not be all zero");
    }
    if let Some(expected) = &policy.expected_header_merkle_root_hex {
        let expected = normalize_hash_hex("expected header merkle root", expected)?;
        if header_merkle_root_hex != expected {
            bail!(
                "Bitcoin work template header merkle root {} does not match expected {}",
                header_merkle_root_hex,
                expected
            );
        }
        return Ok("matched_expected_header_merkle_root".to_string());
    }
    if policy.allow_unverified_merkle_root {
        return Ok("unverified_by_getblocktemplate".to_string());
    }
    bail!(
        "getblocktemplate cannot verify the header merkle root; pass --expected-header-merkle-root-hex from the local block builder/fork validator, or --allow-unverified-merkle-root for development"
    );
}

fn target_hex_from_bits(bits: &str) -> Result<String> {
    Ok(hex::encode(target_from_bits(bits)?.to_be_bytes()))
}

fn target_from_bits(bits: &str) -> Result<Target> {
    let bits = normalize_bits_hex(bits)?;
    let compact =
        CompactTarget::from_unprefixed_hex(&bits).context("failed to parse compact target bits")?;
    Ok(Target::from_compact(compact))
}

fn reversed_display_hash(header_order_bytes: &[u8]) -> String {
    let mut bytes = header_order_bytes.to_vec();
    bytes.reverse();
    hex::encode(bytes)
}

fn display_hash_to_header_order_hex(field: &str, display_hash: &str) -> Result<String> {
    let normalized = normalize_hash_hex(field, display_hash)?;
    let mut bytes = hex::decode(normalized).context("normalized display hash must decode")?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}

fn add_output_multiset(
    outputs: &mut BTreeMap<(String, u64), u32>,
    script_pubkey_hex: String,
    amount_sats: u64,
) -> Result<()> {
    let key = (script_pubkey_hex, amount_sats);
    let count = outputs.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| anyhow!("coinbase output multiset count overflow"))?;
    Ok(())
}

fn format_output_multiset(outputs: &BTreeMap<(String, u64), u32>) -> String {
    if outputs.is_empty() {
        return "[]".to_string();
    }
    let entries = outputs
        .iter()
        .map(|((script, amount), count)| format!("{count}x {amount} sats to {script}"))
        .collect::<Vec<_>>();
    format!("[{}]", entries.join(", "))
}

fn output_multiset_total_sats(label: &str, outputs: &BTreeMap<(String, u64), u32>) -> Result<u64> {
    outputs
        .iter()
        .try_fold(0u64, |total, ((_, amount), count)| {
            let amount = amount
                .checked_mul(u64::from(*count))
                .ok_or_else(|| anyhow!("{label} overflow"))?;
            total
                .checked_add(amount)
                .ok_or_else(|| anyhow!("{label} overflow"))
        })
}

fn normalize_hash_hex(field: &str, value: &str) -> Result<String> {
    normalize_fixed_hex(field, value, 32)
}

fn normalize_bits_hex(value: &str) -> Result<String> {
    normalize_fixed_hex("Bitcoin compact target bits", value, 4)
}

fn normalize_fixed_hex(field: &str, value: &str, expected_bytes: usize) -> Result<String> {
    let value = value.to_ascii_lowercase();
    let expected_len = expected_bytes * 2;
    if value.len() != expected_len || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} must be {expected_bytes} bytes encoded as {expected_len} hex characters");
    }
    Ok(value)
}

fn normalize_script_pubkey_hex(field: &str, value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} must be non-empty even-length hex");
    }
    Ok(value)
}

fn normalize_transaction_hex(value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Bitcoin transaction data must be non-empty even-length hex");
    }
    let byte_len = value.len() / 2;
    if byte_len > MAX_GBT_TRANSACTION_BYTES {
        bail!(
            "Bitcoin transaction data is too large: {byte_len} bytes; maximum is {MAX_GBT_TRANSACTION_BYTES}"
        );
    }
    Ok(value)
}

fn normalize_witness_commitment_script_hex(value: &str) -> Result<String> {
    let value = normalize_script_pubkey_hex("default_witness_commitment", value)?;
    if value.len() != 38 * 2 || !value.starts_with("6a24aa21a9ed") {
        bail!("default_witness_commitment must be the BIP141 OP_RETURN witness commitment script");
    }
    Ok(value)
}

fn normalize_pohw_replay_marker_script_hex(value: &str) -> Result<String> {
    let value = normalize_script_pubkey_hex("pohw_replay_marker", value)?;
    if value != POHW_REPLAY_MARKER_SCRIPT_HEX {
        bail!("pohw_replay_marker must be the exact fork-only replay marker script");
    }
    Ok(value)
}

fn normalize_block_hex(field: &str, value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} must be non-empty even-length hex");
    }
    let byte_len = value.len() / 2;
    if byte_len > MAX_SUBMIT_BLOCK_BYTES {
        bail!("{field} is too large: {byte_len} bytes; maximum is {MAX_SUBMIT_BLOCK_BYTES}");
    }
    Ok(value)
}

fn submitblock_reject_reason_from_result(value: serde_json::Value) -> Result<Option<String>> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(reason) => {
            let reason = reason.trim().to_string();
            if reason.is_empty() {
                bail!("Bitcoin RPC submitblock returned an empty rejection reason");
            }
            if reason.len() > MAX_SUBMIT_BLOCK_REJECT_REASON_BYTES {
                bail!(
                    "Bitcoin RPC submitblock rejection reason is too large: {} bytes; maximum is {}",
                    reason.len(),
                    MAX_SUBMIT_BLOCK_REJECT_REASON_BYTES
                );
            }
            if reason.chars().any(char::is_control) {
                bail!("Bitcoin RPC submitblock rejection reason contains control characters");
            }
            Ok(Some(reason))
        }
        other => bail!("Bitcoin RPC submitblock returned unexpected result: {other}"),
    }
}

fn btc_value_to_sats(value: &serde_json::Value) -> Result<u64> {
    let value = match value {
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(value) => value.clone(),
        _ => bail!("Bitcoin RPC value is not a number or string"),
    };
    parse_btc_decimal_to_sats(&value)
}

fn unix_timestamp_to_utc(timestamp: i64) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .ok_or_else(|| anyhow!("timestamp is outside chrono range"))
}

fn parse_btc_decimal_to_sats(value: &str) -> Result<u64> {
    if value.starts_with('-') {
        bail!("Bitcoin RPC value cannot be negative");
    }
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() || !whole.chars().all(|ch| ch.is_ascii_digit()) {
        bail!("Bitcoin RPC value has invalid whole-BTC part");
    }
    if fractional.len() > 8 || !fractional.chars().all(|ch| ch.is_ascii_digit()) {
        bail!("Bitcoin RPC value has invalid fractional-BTC part");
    }

    let whole_sats = whole
        .parse::<u64>()
        .context("Bitcoin RPC whole-BTC value is too large")?
        .checked_mul(100_000_000)
        .ok_or_else(|| anyhow!("Bitcoin RPC value overflows sats"))?;
    let mut fractional_padded = fractional.to_string();
    while fractional_padded.len() < 8 {
        fractional_padded.push('0');
    }
    let fractional_sats = if fractional_padded.is_empty() {
        0
    } else {
        fractional_padded
            .parse::<u64>()
            .context("Bitcoin RPC fractional-BTC value is invalid")?
    };
    whole_sats
        .checked_add(fractional_sats)
        .ok_or_else(|| anyhow!("Bitcoin RPC value overflows sats"))
}

fn ensure_fresh_input_matches_plan(planned: &VaultInput, fresh: &VaultInput) -> Result<()> {
    if planned.txid != fresh.txid || planned.vout != fresh.vout {
        bail!(
            "fresh Bitcoin RPC UTXO {}:{} does not match planned outpoint {}:{}",
            fresh.txid,
            fresh.vout,
            planned.txid,
            planned.vout
        );
    }
    if planned.amount_sats != fresh.amount_sats {
        bail!(
            "vault input {}:{} amount changed: planned {} sats, current {} sats",
            planned.txid,
            planned.vout,
            planned.amount_sats,
            fresh.amount_sats
        );
    }
    if planned.script_pubkey_hex != fresh.script_pubkey_hex {
        bail!(
            "vault input {}:{} scriptPubKey changed: planned {}, current {}",
            planned.txid,
            planned.vout,
            planned.script_pubkey_hex,
            fresh.script_pubkey_hex
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
    };
    use pohw_core::commitment::{PohwCommitment, PohwCommitmentParams};
    use pohw_core::payout::{DirectPayout, PayoutSchedule, VaultAllocation};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pohw-bitcoin-rpc-{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn write_secret_file(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn header_prefix_hex(
        version: i32,
        previous_block_hash: &str,
        header_merkle_root_hex: &str,
        time: u32,
        bits: &str,
    ) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&version.to_le_bytes());
        let mut previous = hex::decode(previous_block_hash).unwrap();
        previous.reverse();
        bytes.extend_from_slice(&previous);
        bytes.extend_from_slice(&hex::decode(header_merkle_root_hex).unwrap());
        bytes.extend_from_slice(&time.to_le_bytes());
        let bits = u32::from_str_radix(bits, 16).unwrap();
        bytes.extend_from_slice(&bits.to_le_bytes());
        hex::encode(bytes)
    }

    fn gbt(previous_block_hash: &str, curtime: u32, bits: &str) -> GetBlockTemplateResponse {
        GetBlockTemplateResponse {
            version: 0x2000_0000,
            previousblockhash: previous_block_hash.to_string(),
            curtime,
            bits: bits.to_string(),
            target: target_hex_from_bits(bits).unwrap(),
            height: 123,
            coinbasevalue: Some(3_125_000_000),
            default_witness_commitment: None,
            pohw_replay_marker: None,
            mintime: None,
            mutable: Vec::new(),
            transactions: Some(Vec::new()),
        }
    }

    fn gbt_transaction(seed: u8) -> GetBlockTemplateTransactionResponse {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_slice(&[seed; 32]).unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        GetBlockTemplateTransactionResponse {
            txid: Some(tx.compute_txid().to_string()),
            data: Some(hex::encode(serialize(&tx))),
        }
    }

    fn merkle_checked_policy(header_merkle_root_hex: &str) -> BitcoinWorkTemplateValidationPolicy {
        BitcoinWorkTemplateValidationPolicy {
            allow_mutable_time: false,
            max_time_drift_seconds: 0,
            expected_header_merkle_root_hex: Some(header_merkle_root_hex.to_string()),
            allow_unverified_merkle_root: false,
        }
    }

    #[test]
    fn getblocktemplate_validation_accepts_matching_header_prefix() {
        let previous = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let merkle = "11".repeat(32);
        let bits = "207fffff";
        let prefix = header_prefix_hex(0x2000_0000, previous, &merkle, 1_700_000_000, bits);
        let template = BitcoinWorkTemplate::new_unsigned("miner-a", prefix, 1).unwrap();

        let validation = validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &gbt(previous, 1_700_000_000, bits),
            &merkle_checked_policy(&merkle),
        )
        .unwrap();

        assert_eq!(validation.previous_block_hash, previous);
        assert_eq!(validation.header_merkle_root_hex, merkle);
        assert_eq!(
            validation.merkle_root_status,
            "matched_expected_header_merkle_root"
        );
    }

    #[test]
    fn getblocktemplate_validation_preserves_target_bound_template_hash() {
        let previous = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let merkle = "11".repeat(32);
        let bits = "207fffff";
        let prefix = header_prefix_hex(0x2000_0000, previous, &merkle, 1_700_000_000, bits);
        let template = BitcoinWorkTemplate::new_target_bound_unsigned(
            "miner-a",
            prefix,
            pohw_core::sharechain::MAX_ACCEPTED_SHARE_TARGET_HEX,
            1,
        )
        .unwrap();

        let validation = validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &gbt(previous, 1_700_000_000, bits),
            &merkle_checked_policy(&merkle),
        )
        .unwrap();

        assert_eq!(validation.template_hash, template.template_hash);
        assert!(template.is_target_bound());
    }

    #[test]
    fn historical_template_validation_binds_active_chain_and_difficulty() {
        let previous_hash = "10".repeat(32);
        let next_hash = "20".repeat(32);
        let merkle = "30".repeat(32);
        let bits = "207fffff";
        let template = BitcoinWorkTemplate::new_unsigned(
            "miner-a",
            header_prefix_hex(0x2000_0000, &previous_hash, &merkle, 1_700_000_000, bits),
            1,
        )
        .unwrap();
        let previous = GetBlockHeaderResponse {
            hash: previous_hash.clone(),
            height: 122,
            version: 0x2000_0000,
            merkleroot: "40".repeat(32),
            time: 1_699_999_800,
            bits: Some(bits.to_string()),
        };
        let next = GetBlockHeaderResponse {
            hash: next_hash.clone(),
            height: 123,
            version: 0x2000_0000,
            merkleroot: reversed_display_hash(&hex::decode(&merkle).unwrap()),
            time: 1_700_000_000,
            bits: Some(bits.to_string()),
        };

        let validation = validate_historical_bitcoin_work_template_against_active_chain(
            &template,
            &previous_hash,
            &previous,
            &next_hash,
            &next,
        )
        .unwrap();

        assert_eq!(validation.height, 123);
        assert_eq!(validation.bits, bits);
        let mut wrong_version = next.clone();
        wrong_version.version += 1;
        assert!(
            validate_historical_bitcoin_work_template_against_active_chain(
                &template,
                &previous_hash,
                &previous,
                &next_hash,
                &wrong_version,
            )
            .is_err()
        );
        let mut wrong_merkle = next.clone();
        wrong_merkle.merkleroot = "31".repeat(32);
        assert!(
            validate_historical_bitcoin_work_template_against_active_chain(
                &template,
                &previous_hash,
                &previous,
                &next_hash,
                &wrong_merkle,
            )
            .is_err()
        );
        let mut wrong_time = next.clone();
        wrong_time.time += 1;
        assert!(
            validate_historical_bitcoin_work_template_against_active_chain(
                &template,
                &previous_hash,
                &previous,
                &next_hash,
                &wrong_time,
            )
            .is_err()
        );
        let mut wrong_bits = next;
        wrong_bits.bits = Some("1d00ffff".to_string());
        assert!(
            validate_historical_bitcoin_work_template_against_active_chain(
                &template,
                &previous_hash,
                &previous,
                &next_hash,
                &wrong_bits,
            )
            .is_err()
        );
    }

    #[test]
    fn getblocktemplate_validation_rejects_previous_block_mismatch() {
        let previous = "00".repeat(32);
        let merkle = "11".repeat(32);
        let bits = "207fffff";
        let prefix = header_prefix_hex(0x2000_0000, &previous, &merkle, 1_700_000_000, bits);
        let template = BitcoinWorkTemplate::new_unsigned("miner-a", prefix, 1).unwrap();

        let err = validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &gbt(&"22".repeat(32), 1_700_000_000, bits),
            &merkle_checked_policy(&merkle),
        )
        .unwrap_err();

        assert!(err.to_string().contains("previous block"));
    }

    #[test]
    fn getblocktemplate_validation_requires_merkle_root_policy() {
        let previous = "00".repeat(32);
        let merkle = "11".repeat(32);
        let bits = "207fffff";
        let prefix = header_prefix_hex(0x2000_0000, &previous, &merkle, 1_700_000_000, bits);
        let template = BitcoinWorkTemplate::new_unsigned("miner-a", prefix, 1).unwrap();

        let err = validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &gbt(&previous, 1_700_000_000, bits),
            &BitcoinWorkTemplateValidationPolicy {
                allow_mutable_time: false,
                max_time_drift_seconds: 0,
                expected_header_merkle_root_hex: None,
                allow_unverified_merkle_root: false,
            },
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("cannot verify the header merkle root"));
    }

    #[test]
    fn getblocktemplate_validation_allows_bounded_mutable_time() {
        let previous = "00".repeat(32);
        let merkle = "11".repeat(32);
        let bits = "207fffff";
        let prefix = header_prefix_hex(0x2000_0000, &previous, &merkle, 1_700_000_030, bits);
        let template = BitcoinWorkTemplate::new_unsigned("miner-a", prefix, 1).unwrap();
        let mut block_template = gbt(&previous, 1_700_000_000, bits);
        block_template.mintime = Some(1_699_999_999);
        block_template.mutable = vec!["time".to_string()];

        validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &block_template,
            &BitcoinWorkTemplateValidationPolicy {
                allow_mutable_time: true,
                max_time_drift_seconds: 60,
                expected_header_merkle_root_hex: Some(merkle.clone()),
                allow_unverified_merkle_root: false,
            },
        )
        .unwrap();

        let err = validate_bitcoin_work_template_against_getblocktemplate(
            &template,
            &block_template,
            &BitcoinWorkTemplateValidationPolicy {
                allow_mutable_time: true,
                max_time_drift_seconds: 10,
                expected_header_merkle_root_hex: Some(merkle),
                allow_unverified_merkle_root: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside allowed range"));
    }

    #[test]
    fn pohw_validation_accepts_only_stricter_time_dependent_stale_bits() {
        let previous = "00".repeat(32);
        let merkle = "11".repeat(32);
        let stale_bits = "202740d9";
        let current_bits = "2027bbba";
        let stale_time = 1_700_000_000;
        let prefix = header_prefix_hex(0x2000_0000, &previous, &merkle, stale_time, stale_bits);
        let template = BitcoinWorkTemplate::new_unsigned("miner-a", prefix, 1).unwrap();
        let mut block_template = gbt(&previous, stale_time + 9, current_bits);
        block_template.mintime = Some(stale_time - 1);
        block_template.mutable = vec!["time".to_string()];
        let policy = BitcoinWorkTemplateValidationPolicy {
            allow_mutable_time: true,
            max_time_drift_seconds: 60,
            expected_header_merkle_root_hex: Some(merkle.clone()),
            allow_unverified_merkle_root: false,
        };

        let validation = validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
            &template,
            &block_template,
            &policy,
            true,
        )
        .unwrap();
        assert_eq!(validation.bits, stale_bits);
        assert_eq!(validation.target, target_hex_from_bits(stale_bits).unwrap());

        assert!(
            validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
                &template,
                &block_template,
                &policy,
                false,
            )
            .is_err()
        );

        let easier_prefix =
            header_prefix_hex(0x2000_0000, &previous, &merkle, stale_time, current_bits);
        let easier_template =
            BitcoinWorkTemplate::new_unsigned("miner-a", easier_prefix, 1).unwrap();
        let mut stricter_current = gbt(&previous, stale_time + 9, stale_bits);
        stricter_current.mintime = Some(stale_time - 1);
        stricter_current.mutable = vec!["time".to_string()];
        let error = validate_bitcoin_work_template_against_getblocktemplate_with_bits_policy(
            &easier_template,
            &stricter_current,
            &policy,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("easier than the current target"));
    }

    #[test]
    fn mining_job_template_normalizes_getblocktemplate_material() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        let tx1 = gbt_transaction(0xbb);
        let tx2 = gbt_transaction(0xcc);
        block_template.transactions = Some(vec![tx1.clone(), tx2.clone()]);

        let material = mining_job_template_from_getblocktemplate(&block_template).unwrap();

        assert_eq!(material.version, 0x2000_0000);
        assert_eq!(material.previous_block_hash, "aa".repeat(32));
        assert_eq!(material.bits, "207fffff");
        assert_eq!(material.coinbase_value_sats, 3_125_000_000);
        assert_eq!(
            material.transaction_hashes,
            vec![tx1.txid.clone().unwrap(), tx2.txid.clone().unwrap()]
        );
        assert_eq!(
            material.transactions,
            vec![
                BitcoinMiningJobTransaction {
                    txid: tx1.txid.unwrap(),
                    data_hex: tx1.data.unwrap(),
                },
                BitcoinMiningJobTransaction {
                    txid: tx2.txid.unwrap(),
                    data_hex: tx2.data.unwrap(),
                },
            ]
        );
        assert_eq!(material.default_witness_commitment, None);
    }

    #[test]
    fn mining_job_template_requires_coinbase_value() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        block_template.coinbasevalue = None;

        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();

        assert!(err.to_string().contains("missing coinbasevalue"));
    }

    #[test]
    fn mining_job_template_requires_transactions_field() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        block_template.transactions = None;

        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();

        assert!(err.to_string().contains("missing transactions"));
    }

    #[test]
    fn mining_job_template_requires_transaction_txids_for_merkle_work() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        block_template.transactions = Some(vec![GetBlockTemplateTransactionResponse {
            txid: None,
            data: None,
        }]);

        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();

        assert!(err.to_string().contains("missing txid"));
    }

    #[test]
    fn mining_job_template_requires_transaction_data_for_block_submission() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        let tx = gbt_transaction(0xaa);
        block_template.transactions = Some(vec![GetBlockTemplateTransactionResponse {
            txid: tx.txid,
            data: None,
        }]);

        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();

        assert!(err.to_string().contains("missing data"));
    }

    #[test]
    fn mining_job_template_rejects_transaction_data_txid_mismatch() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        let tx = gbt_transaction(0xaa);
        block_template.transactions = Some(vec![GetBlockTemplateTransactionResponse {
            txid: Some("bb".repeat(32)),
            data: tx.data,
        }]);

        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();

        assert!(err.to_string().contains("does not match advertised txid"));
    }

    #[test]
    fn mining_job_template_normalizes_default_witness_commitment() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        block_template.default_witness_commitment =
            Some(format!("6A24AA21A9ED{}", "11".repeat(32)));

        let material = mining_job_template_from_getblocktemplate(&block_template).unwrap();

        assert_eq!(
            material.default_witness_commitment,
            Some(format!("6a24aa21a9ed{}", "11".repeat(32)))
        );

        block_template.default_witness_commitment = Some("6a".to_string());
        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();
        assert!(err.to_string().contains("default_witness_commitment"));
    }

    #[test]
    fn mining_job_template_requires_exact_pohw_replay_marker() {
        let mut block_template = gbt(&"AA".repeat(32), 1_700_000_000, "207fffff");
        block_template.pohw_replay_marker = Some("5150".to_string());

        let material = mining_job_template_from_getblocktemplate(&block_template).unwrap();
        assert_eq!(material.pohw_replay_marker.as_deref(), Some("5150"));

        block_template.pohw_replay_marker = Some("5161".to_string());
        let err = mining_job_template_from_getblocktemplate(&block_template).unwrap_err();
        assert!(err.to_string().contains("exact fork-only replay marker"));
    }

    #[test]
    fn submitblock_result_parser_accepts_null_and_rejection_string() {
        assert_eq!(
            submitblock_reject_reason_from_result(serde_json::Value::Null).unwrap(),
            None
        );
        assert_eq!(
            submitblock_reject_reason_from_result(serde_json::json!("bad-txnmrklroot")).unwrap(),
            Some("bad-txnmrklroot".to_string())
        );
    }

    #[test]
    fn json_rpc_response_distinguishes_explicit_null_from_missing_result() {
        let explicit_null: JsonRpcResponse =
            serde_json::from_str(r#"{"result":null,"error":null}"#).unwrap();
        assert_eq!(
            explicit_null.result,
            JsonRpcResult::Present(serde_json::Value::Null)
        );
        let JsonRpcResult::Present(result) = explicit_null.result else {
            panic!("explicit null must be preserved as a present result");
        };
        let parsed: Option<serde_json::Value> = serde_json::from_value(result).unwrap();
        assert_eq!(parsed, None);

        let missing_result: JsonRpcResponse = serde_json::from_str(r#"{"error":null}"#).unwrap();
        assert_eq!(missing_result.result, JsonRpcResult::Missing);
    }

    #[test]
    fn submitblock_validation_rejects_bad_block_hex_or_reason() {
        assert!(normalize_block_hex("block hex", "").is_err());
        assert!(normalize_block_hex("block hex", "abc").is_err());
        assert!(normalize_block_hex("block hex", "zz").is_err());
        assert!(submitblock_reject_reason_from_result(serde_json::json!("bad\nreason")).is_err());
        assert!(submitblock_reject_reason_from_result(serde_json::json!({ "bad": true })).is_err());
    }

    #[test]
    fn rpc_url_validation_rejects_unsafe_forms() {
        assert!(BitcoinRpcClient::new("http://127.0.0.1:8332", None).is_ok());
        assert!(BitcoinRpcClient::new("ftp://127.0.0.1:8332", None).is_err());
        assert!(BitcoinRpcClient::new("http://user:pass@127.0.0.1:8332", None).is_err());
        assert!(BitcoinRpcClient::new("http://127.0.0.1:8332/?cookie=leak", None).is_err());
        assert!(BitcoinRpcClient::new("http://127.0.0.1:8332/#fragment", None).is_err());
        assert!(BitcoinRpcClient::new("http://198.51.100.10:8332", None).is_err());
        assert!(
            BitcoinRpcClient::new_with_remote_policy("http://198.51.100.10:8332", None, true)
                .is_ok()
        );
    }

    #[test]
    fn rpc_auth_rejects_ambiguous_or_invalid_credentials() {
        let datadir = temp_dir("auth-validation");
        let cookie = datadir.join("cookie");
        write_secret_file(&cookie, "user:password");

        assert!(BitcoinRpcClient::auth_from_user_password(
            Some("user".to_string()),
            Some("password".to_string()),
            Some(&cookie),
        )
        .is_err());
        assert!(BitcoinRpcClient::auth_from_user_password(
            Some("user".to_string()),
            None::<String>,
            None::<&Path>,
        )
        .is_err());
        assert!(BitcoinRpcClient::auth_from_user_password(
            Some("user\nbad".to_string()),
            Some("password".to_string()),
            None::<&Path>,
        )
        .is_err());
        assert!(BitcoinRpcClient::auth_from_user_password(
            Some("user".to_string()),
            Some("password".to_string()),
            None::<&Path>,
        )
        .unwrap()
        .is_some());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn cookie_auth_rejects_empty_or_control_credentials() {
        let datadir = temp_dir("cookie-validation");
        let empty_password = datadir.join("empty-password");
        write_secret_file(&empty_password, "user:");
        assert!(BitcoinRpcAuth::from_cookie_file(&empty_password).is_err());

        let control_username = datadir.join("control-username");
        write_secret_file(&control_username, "bad\nuser:password");
        assert!(BitcoinRpcAuth::from_cookie_file(&control_username).is_err());

        let valid = datadir.join("valid-cookie");
        write_secret_file(&valid, "user:password");
        let auth = BitcoinRpcAuth::from_cookie_file(&valid).unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "password");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn cookie_auth_reloads_rotated_cookie_file() {
        let datadir = temp_dir("cookie-rotation");
        let cookie = datadir.join("cookie");
        write_secret_file(&cookie, "first:password-a");
        let auth = BitcoinRpcAuth::from_cookie_file(&cookie).unwrap();

        write_secret_file(&cookie, "second:password-b");
        let credentials = auth.credentials().unwrap();

        assert_eq!(credentials.username, "second");
        assert_eq!(credentials.password, "password-b");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cookie_auth_accepts_dedicated_group_read_but_rejects_other_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let datadir = temp_dir("cookie-group-read");
        let cookie = datadir.join("cookie");
        write_secret_file(&cookie, "user:password");

        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(BitcoinRpcAuth::from_cookie_file(&cookie).is_ok());

        for unsafe_mode in [0o660, 0o644, 0o440] {
            fs::set_permissions(&cookie, fs::Permissions::from_mode(unsafe_mode)).unwrap();
            assert!(BitcoinRpcAuth::from_cookie_file(&cookie).is_err());
        }

        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn cookie_auth_rejects_large_cookie_file_before_reading() {
        let datadir = temp_dir("cookie-large-file");
        let cookie = datadir.join("cookie");
        fs::File::create(&cookie)
            .unwrap()
            .set_len(MAX_RPC_COOKIE_FILE_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = BitcoinRpcAuth::from_cookie_file(&cookie).unwrap_err();

        assert!(
            format!("{err:#}").contains("too large"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cookie_auth_rejects_group_or_world_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let datadir = temp_dir("cookie-writable-parent");
        let cookie = datadir.join("cookie");
        write_secret_file(&cookie, "user:password");
        fs::set_permissions(&datadir, fs::Permissions::from_mode(0o777)).unwrap();

        let err = BitcoinRpcAuth::from_cookie_file(&cookie).unwrap_err();

        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "unexpected error: {err:#}"
        );
        fs::set_permissions(&datadir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cookie_auth_rejects_symlink_ancestor_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let datadir = temp_dir("cookie-symlink-ancestor");
        let real = datadir.join("real");
        let child = real.join("child");
        let link = datadir.join("link");
        fs::create_dir_all(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, &link).unwrap();
        let cookie = child.join("cookie");
        write_secret_file(&cookie, "user:password");

        let err = BitcoinRpcAuth::from_cookie_file(link.join("child").join("cookie")).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn btc_decimal_parser_is_exact() {
        assert_eq!(parse_btc_decimal_to_sats("0").unwrap(), 0);
        assert_eq!(parse_btc_decimal_to_sats("0.00000001").unwrap(), 1);
        assert_eq!(
            parse_btc_decimal_to_sats("1.23456789").unwrap(),
            123_456_789
        );
        assert_eq!(
            parse_btc_decimal_to_sats("3.12500000").unwrap(),
            312_500_000
        );
    }

    #[test]
    fn btc_decimal_parser_rejects_unsafe_precision() {
        assert!(parse_btc_decimal_to_sats("0.000000001").is_err());
        assert!(parse_btc_decimal_to_sats("-1").is_err());
        assert!(parse_btc_decimal_to_sats("abc").is_err());
    }

    #[test]
    fn fresh_input_match_allows_confirmation_growth() {
        let planned = VaultInput {
            txid: "aa".repeat(32),
            vout: 0,
            amount_sats: 50_000,
            confirmations: 100,
            script_pubkey_hex: "5120".to_string() + &"11".repeat(32),
        };
        let mut fresh = planned.clone();
        fresh.confirmations = 105;

        ensure_fresh_input_matches_plan(&planned, &fresh).unwrap();
    }

    #[test]
    fn fresh_input_match_rejects_amount_or_script_change() {
        let planned = VaultInput {
            txid: "aa".repeat(32),
            vout: 0,
            amount_sats: 50_000,
            confirmations: 100,
            script_pubkey_hex: "5120".to_string() + &"11".repeat(32),
        };

        let mut changed_amount = planned.clone();
        changed_amount.amount_sats = 49_999;
        assert!(ensure_fresh_input_matches_plan(&planned, &changed_amount).is_err());

        let mut changed_script = planned.clone();
        changed_script.script_pubkey_hex = "5120".to_string() + &"22".repeat(32);
        assert!(ensure_fresh_input_matches_plan(&planned, &changed_script).is_err());
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
            idena_snapshot_id: "2026-06-30".to_string(),
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

    #[test]
    fn coinbase_payout_verifier_allows_exact_outputs_and_zero_commitment() {
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);
        let outputs = vec![
            CoinbasePayoutOutput {
                script_pubkey_hex: commitment.op_return_script_pubkey_hex(),
                amount_sats: 0,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex: "00141111111111111111111111111111111111111111".to_string(),
                amount_sats: 20_000,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex:
                    "51202222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                amount_sats: 30_000,
            },
        ];

        let totals = verify_coinbase_payout_outputs(
            &schedule,
            "51202222222222222222222222222222222222222222222222222222222222222222",
            &commitment,
            &outputs,
        )
        .unwrap();
        assert_eq!(
            totals,
            CoinbasePayoutOutputTotals {
                expected_output_total_sats: 50_000,
                confirmed_output_total_sats: 50_000,
            }
        );
    }

    #[test]
    fn coinbase_payout_verifier_rejects_missing_vault_output() {
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);
        let outputs = vec![
            CoinbasePayoutOutput {
                script_pubkey_hex: commitment.op_return_script_pubkey_hex(),
                amount_sats: 0,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex: "00141111111111111111111111111111111111111111".to_string(),
                amount_sats: 20_000,
            },
        ];

        let err = verify_coinbase_payout_outputs(
            &schedule,
            "51202222222222222222222222222222222222222222222222222222222222222222",
            &commitment,
            &outputs,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("do not match payout schedule"));
    }

    #[test]
    fn coinbase_payout_verifier_rejects_unexpected_positive_output() {
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);
        let outputs = vec![
            CoinbasePayoutOutput {
                script_pubkey_hex: commitment.op_return_script_pubkey_hex(),
                amount_sats: 0,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex: "00141111111111111111111111111111111111111111".to_string(),
                amount_sats: 20_000,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex:
                    "51202222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                amount_sats: 30_000,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex: "00143333333333333333333333333333333333333333".to_string(),
                amount_sats: 1,
            },
        ];

        assert!(verify_coinbase_payout_outputs(
            &schedule,
            "51202222222222222222222222222222222222222222222222222222222222222222",
            &commitment,
            &outputs,
        )
        .is_err());
    }

    #[test]
    fn coinbase_payout_verifier_rejects_missing_pohw_commitment() {
        let schedule = payout_schedule();
        let commitment = pohw_commitment(&schedule);
        let outputs = vec![
            CoinbasePayoutOutput {
                script_pubkey_hex: "00141111111111111111111111111111111111111111".to_string(),
                amount_sats: 20_000,
            },
            CoinbasePayoutOutput {
                script_pubkey_hex:
                    "51202222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                amount_sats: 30_000,
            },
        ];

        let err = verify_coinbase_payout_outputs(
            &schedule,
            "51202222222222222222222222222222222222222222222222222222222222222222",
            &commitment,
            &outputs,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("missing zero-value POHW1 commitment output"));
    }
}
