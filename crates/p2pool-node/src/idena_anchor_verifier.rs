use anyhow::{anyhow, bail, Context, Result};
use idena_lite_indexer::rpc::{
    BlockResponse, IdenaRpcClient, IdentityResponse, SyncingResponse, TransactionResponse,
    TxReceiptResponse,
};
use pohw_core::idena_anchor::{
    normalize_idena_hash, IdenaAnchorPolicyV2, IdenaBlockAnchorV1, SharechainCheckpointAnchorV1,
};
use pohw_core::sharechain::{BitcoinWorkTemplate, MinerRegistration};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::OnceCell;

const MAX_IDENA_ANCHOR_POLICY_BYTES: u64 = 64 * 1024;
const MAX_REGISTRY_DEPLOYMENT_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct IdenaAnchorVerifier {
    client: IdenaRpcClient,
    policy: IdenaAnchorPolicyV2,
    deployment_verified: Arc<OnceCell<()>>,
}

impl IdenaAnchorVerifier {
    pub(crate) fn new(client: IdenaRpcClient, policy: IdenaAnchorPolicyV2) -> Result<Self> {
        let policy = policy.normalized();
        policy.validate().context("invalid Idena anchor policy")?;
        Ok(Self {
            client,
            policy,
            deployment_verified: Arc::new(OnceCell::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_verified_deployment_for_test(
        client: IdenaRpcClient,
        policy: IdenaAnchorPolicyV2,
    ) -> Result<Self> {
        let verifier = Self::new(client, policy)?;
        verifier
            .deployment_verified
            .set(())
            .map_err(|_| anyhow!("failed to seed test deployment verification"))?;
        Ok(verifier)
    }

    pub(crate) fn policy(&self) -> &IdenaAnchorPolicyV2 {
        &self.policy
    }

    pub(crate) async fn verify_registry_deployment(&self) -> Result<()> {
        self.deployment_verified
            .get_or_try_init(|| async { self.verify_registry_deployment_uncached().await })
            .await?;
        Ok(())
    }

    async fn verify_registry_deployment_uncached(&self) -> Result<()> {
        let syncing = self
            .client
            .syncing()
            .await
            .context("failed to read Idena sync state for registry deployment")?;
        ensure_idena_ready(&syncing)?;
        let transaction = self
            .client
            .transaction(&self.policy.registry_deployment_tx_hash)
            .await
            .context("failed to read registry deployment transaction")?
            .context("registry deployment transaction is unavailable")?;
        verify_registry_deployment_transaction(&self.policy, &transaction)?;

        let payload = decode_prefixed_hex(
            "registry deployment payload",
            &transaction.payload,
            MAX_REGISTRY_DEPLOYMENT_PAYLOAD_BYTES,
        )?;
        let payload_sha256 = hex::encode(Sha256::digest(&payload));
        if payload_sha256 != self.policy.registry_deployment_payload_sha256 {
            bail!("registry deployment payload SHA-256 does not match active policy");
        }
        let attachment = parse_deploy_contract_attachment(&payload)?;
        if hex::encode(&attachment.code_hash) != self.policy.registry_contract_code_hash {
            bail!("registry deployment code hash does not match active policy");
        }
        if attachment.code.is_empty() {
            bail!("registry deployment must carry inline WASM bytes");
        }
        let wasm_sha256 = hex::encode(Sha256::digest(&attachment.code));
        if wasm_sha256 != self.policy.registry_contract_wasm_sha256 {
            bail!("registry deployment WASM SHA-256 does not match active policy");
        }
        verify_registry_deployment_arguments(&self.policy, &attachment.args)?;

        let receipt = self
            .client
            .transaction_receipt(&self.policy.registry_deployment_tx_hash)
            .await
            .context("failed to read registry deployment receipt")?
            .context("registry deployment receipt is unavailable")?;
        verify_registry_deployment_receipt(&self.policy, &receipt)?;

        let block = self
            .client
            .block(&transaction.block_hash)
            .await
            .context("failed to read registry deployment block")?
            .context("registry deployment block is unavailable")?;
        verify_registry_deployment_block(&self.policy, &transaction, &block, &syncing)?;

        let experiment_id = self
            .client
            .contract_read_string(
                &self.policy.registry_contract_address,
                "registry:experiment-id",
            )
            .await
            .context("failed to read immutable registry experiment id")?;
        let ecosystem_cid = self
            .client
            .contract_read_string(
                &self.policy.registry_contract_address,
                "registry:ecosystem-cid",
            )
            .await
            .context("failed to read immutable registry ecosystem CID")?;
        let minimum_burn = self
            .client
            .contract_read_string(&self.policy.registry_contract_address, "registry:min-burn")
            .await
            .context("failed to read immutable registry minimum burn")?;
        if experiment_id != self.policy.experiment_id
            || ecosystem_cid != self.policy.registry_ecosystem_cid
            || minimum_burn != self.policy.minimum_registration_burn_atoms
        {
            bail!("registry immutable storage does not match active policy");
        }
        Ok(())
    }

    pub(crate) async fn verify_registration(&self, registration: &MinerRegistration) -> Result<()> {
        self.verify_registration_with_eligibility(registration, true)
            .await
    }

    pub(crate) async fn verify_historical_registration(
        &self,
        registration: &MinerRegistration,
    ) -> Result<()> {
        self.verify_registration_with_eligibility(registration, false)
            .await
    }

    pub(crate) async fn current_identity_is_eligible(
        &self,
        registration: &MinerRegistration,
    ) -> Result<bool> {
        let identity = self
            .client
            .identity(&registration.idena_address)
            .await
            .context("failed to read registered Idena identity state")?;
        identity_response_is_currently_eligible(&registration.idena_address, &identity)
    }

    async fn verify_registration_with_eligibility(
        &self,
        registration: &MinerRegistration,
        require_current_eligibility: bool,
    ) -> Result<()> {
        self.verify_registry_deployment().await?;
        let anchor = registration
            .require_registry_anchor()
            .context("miner registration is not contract anchored")?;
        self.policy
            .validate_registry_anchor(anchor)
            .context("miner registry anchor does not match active policy")?;
        let expected_commitment = registration
            .registry_commitment_hash(&self.policy.experiment_id)
            .context("failed to recompute miner registry commitment")?;
        if expected_commitment != anchor.registration_commitment {
            bail!("miner registry commitment does not match registration material");
        }
        let storage_key = anchor
            .storage_key(&registration.idena_address)
            .context("invalid miner registry storage key")?;
        let actual_record = self
            .client
            .contract_read_string(&self.policy.registry_contract_address, &storage_key)
            .await
            .context("failed to read miner registry record from local Idena RPC")?;
        let expected_record = anchor
            .canonical_record_line(&registration.miner_id)
            .context("invalid miner registry record fields")?;
        verify_contract_record(&actual_record, &expected_record)?;
        if require_current_eligibility && !self.current_identity_is_eligible(registration).await? {
            bail!("registered Idena identity is not Newbie, Verified, or Human");
        }
        Ok(())
    }

    pub(crate) async fn fresh_finalized_anchor(
        &self,
        registration: &MinerRegistration,
    ) -> Result<IdenaBlockAnchorV1> {
        self.verify_registration(registration).await?;
        let syncing = self
            .client
            .syncing()
            .await
            .context("failed to read Idena sync state")?;
        ensure_idena_ready(&syncing)?;
        let finalized_height = syncing
            .current_block
            .checked_sub(self.policy.finality_confirmations)
            .context("Idena chain has not reached the configured finality depth")?;
        let block = self
            .client
            .block_at(finalized_height)
            .await
            .context("failed to read finalized Idena anchor block")?
            .with_context(|| format!("finalized Idena block {finalized_height} is unavailable"))?;
        let anchor = anchor_from_block(&block)?;
        self.policy
            .validate_live_block_anchor(&anchor, syncing.current_block)
            .context("finalized Idena anchor fails active policy")?;
        let registry_anchor = registration
            .require_registry_anchor()
            .context("miner registration is not contract anchored")?;
        if registry_anchor.registration_block > finalized_height {
            bail!("miner registry record is not finalized yet");
        }
        Ok(anchor)
    }

    pub(crate) async fn verify_template(
        &self,
        registration: &MinerRegistration,
        template: &BitcoinWorkTemplate,
        require_fresh_anchor: bool,
    ) -> Result<()> {
        self.verify_registration_with_eligibility(registration, require_fresh_anchor)
            .await?;
        let anchor = template
            .require_idena_anchor()
            .context("Bitcoin work template has no Idena block anchor")?;
        let template_policy_hash = template
            .require_idena_anchor_policy_hash()
            .context("Bitcoin work template has no Idena anchor policy commitment")?;
        if template_policy_hash != self.policy.commitment_hash()? {
            bail!("Bitcoin work template commits to a different Idena anchor policy");
        }
        let syncing = self
            .client
            .syncing()
            .await
            .context("failed to read Idena sync state")?;
        ensure_idena_ready(&syncing)?;
        if require_fresh_anchor {
            self.policy
                .validate_live_block_anchor(anchor, syncing.current_block)
                .context("Bitcoin work template Idena anchor is not recent and finalized")?;
        } else {
            self.policy
                .validate_finalized_block_anchor(anchor, syncing.current_block)
                .context("historical Bitcoin work template Idena anchor is not finalized")?;
        }
        let registry_anchor = registration
            .require_registry_anchor()
            .context("miner registration is not contract anchored")?;
        if anchor.height < registry_anchor.registration_block {
            bail!("Bitcoin work template Idena anchor predates miner registration");
        }
        let block = self
            .client
            .block_at(anchor.height)
            .await
            .context("failed to read referenced Idena block")?
            .with_context(|| format!("referenced Idena block {} is unavailable", anchor.height))?;
        verify_block_anchor(anchor, &block)?;
        Ok(())
    }

    pub(crate) async fn verify_checkpoint(
        &self,
        checkpoint: &SharechainCheckpointAnchorV1,
        require_fresh_anchor: bool,
    ) -> Result<()> {
        self.verify_registry_deployment().await?;
        self.policy
            .validate_checkpoint_anchor(checkpoint)
            .context("sharechain checkpoint does not match active policy")?;
        let syncing = self
            .client
            .syncing()
            .await
            .context("failed to read Idena sync state for sharechain checkpoint")?;
        ensure_idena_ready(&syncing)?;
        let anchor = checkpoint.finalization_anchor();
        if require_fresh_anchor {
            self.policy
                .validate_live_block_anchor(&anchor, syncing.current_block)
                .context("sharechain checkpoint finalization is not recent and finalized")?;
        } else {
            self.policy
                .validate_finalized_block_anchor(&anchor, syncing.current_block)
                .context("historical sharechain checkpoint finalization is not finalized")?;
        }
        let block = self
            .client
            .block_at(checkpoint.finalization_block)
            .await
            .context("failed to read sharechain checkpoint finalization block")?
            .with_context(|| {
                format!(
                    "sharechain checkpoint finalization block {} is unavailable",
                    checkpoint.finalization_block
                )
            })?;
        verify_block_anchor(&anchor, &block)?;
        if block.timestamp != checkpoint.finalization_timestamp {
            bail!("sharechain checkpoint timestamp does not match its Idena block");
        }
        let actual_record = self
            .client
            .contract_read_string(
                &self.policy.registry_contract_address,
                &checkpoint.storage_key(),
            )
            .await
            .context("failed to read finalized sharechain checkpoint from local Idena RPC")?;
        let expected_record = checkpoint
            .canonical_record_line()
            .context("invalid sharechain checkpoint fields")?;
        verify_exact_contract_record(
            &actual_record,
            &expected_record,
            4096,
            "sharechain checkpoint",
        )?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DeployContractAttachment {
    code_hash: Vec<u8>,
    args: Vec<Vec<u8>>,
    code: Vec<u8>,
    nonce: Vec<u8>,
}

fn verify_registry_deployment_transaction(
    policy: &IdenaAnchorPolicyV2,
    transaction: &TransactionResponse,
) -> Result<()> {
    if !transaction
        .hash
        .eq_ignore_ascii_case(&policy.registry_deployment_tx_hash)
    {
        bail!("Idena RPC returned a different registry deployment transaction");
    }
    if transaction.transaction_type != "deployContract" {
        bail!("registry deployment transaction has the wrong transaction type");
    }
    if transaction.to.is_some() {
        bail!("registry deployment transaction unexpectedly has a recipient");
    }
    validate_nonzero_prefixed_hash("registry deployment block hash", &transaction.block_hash)?;
    if transaction.timestamp <= 0 {
        bail!("registry deployment transaction has no confirmed timestamp");
    }
    Ok(())
}

fn verify_registry_deployment_receipt(
    policy: &IdenaAnchorPolicyV2,
    receipt: &TxReceiptResponse,
) -> Result<()> {
    if !receipt.success {
        bail!("registry deployment receipt reports failure");
    }
    if !receipt
        .contract
        .eq_ignore_ascii_case(&policy.registry_contract_address)
    {
        bail!("registry deployment receipt created a different contract address");
    }
    if !receipt
        .tx_hash
        .as_deref()
        .is_some_and(|hash| hash.eq_ignore_ascii_case(&policy.registry_deployment_tx_hash))
    {
        bail!("registry deployment receipt is bound to a different transaction");
    }
    Ok(())
}

fn verify_registry_deployment_block(
    policy: &IdenaAnchorPolicyV2,
    transaction: &TransactionResponse,
    block: &BlockResponse,
    syncing: &SyncingResponse,
) -> Result<()> {
    if !block.hash.eq_ignore_ascii_case(&transaction.block_hash) {
        bail!("Idena RPC returned a different registry deployment block");
    }
    if block.height == 0 || block.height >= policy.activation_idena_height {
        bail!("registry deployment block must precede policy activation height");
    }
    let finalized_height = syncing
        .current_block
        .checked_sub(policy.finality_confirmations)
        .context("Idena chain has not reached the policy finality depth")?;
    if block.height > finalized_height {
        bail!("registry deployment block is not finalized under active policy");
    }
    if transaction.timestamp != block.timestamp {
        bail!("registry deployment transaction timestamp does not match its block");
    }
    Ok(())
}

fn verify_registry_deployment_arguments(
    policy: &IdenaAnchorPolicyV2,
    args: &[Vec<u8>],
) -> Result<()> {
    let expected = [
        policy.experiment_id.as_bytes(),
        policy.registry_ecosystem_cid.as_bytes(),
        policy.minimum_registration_burn_atoms.as_bytes(),
    ];
    if args.len() != expected.len()
        || args
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_slice() != expected)
    {
        bail!("registry deployment arguments do not match active policy");
    }
    Ok(())
}

fn parse_deploy_contract_attachment(payload: &[u8]) -> Result<DeployContractAttachment> {
    let mut offset = 0usize;
    let mut code_hash = None;
    let mut args = Vec::new();
    let mut code = None;
    let mut nonce = None;
    while offset < payload.len() {
        let key = read_protobuf_varint(payload, &mut offset)?;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if wire_type != 2 {
            bail!("registry deployment attachment contains a non-bytes protobuf field");
        }
        let len = usize::try_from(read_protobuf_varint(payload, &mut offset)?)
            .context("registry deployment protobuf field length does not fit usize")?;
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= payload.len())
            .context("registry deployment protobuf field exceeds payload")?;
        let value = payload[offset..end].to_vec();
        offset = end;
        match field_number {
            1 => {
                if code_hash.is_some() {
                    bail!("registry deployment attachment contains a duplicate field");
                }
                code_hash = Some(value);
            }
            2 => args.push(value),
            3 => {
                if code.is_some() {
                    bail!("registry deployment attachment contains a duplicate field");
                }
                code = Some(value);
            }
            4 => {
                if nonce.is_some() {
                    bail!("registry deployment attachment contains a duplicate field");
                }
                nonce = Some(value);
            }
            _ => bail!("registry deployment attachment contains an unknown field"),
        }
    }
    let attachment = DeployContractAttachment {
        code_hash: code_hash.context("registry deployment attachment has no code hash")?,
        args,
        code: code.context("registry deployment attachment has no inline code field")?,
        nonce: nonce.unwrap_or_default(),
    };
    if attachment.code_hash.len() != 32 {
        bail!("registry deployment code hash must be 32 bytes");
    }
    Ok(attachment)
}

fn read_protobuf_varint(payload: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *payload
            .get(*offset)
            .context("truncated registry deployment protobuf varint")?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            bail!("registry deployment protobuf varint overflows u64");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("registry deployment protobuf varint is too long")
}

fn decode_prefixed_hex(label: &str, value: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let hex_value = value
        .strip_prefix("0x")
        .with_context(|| format!("{label} must be 0x-prefixed"))?;
    if value != value.to_ascii_lowercase()
        || hex_value.len() % 2 != 0
        || hex_value.len() / 2 > max_bytes
        || hex_value.bytes().any(|byte| !byte.is_ascii_hexdigit())
    {
        bail!("{label} is not canonical bounded lowercase hex");
    }
    hex::decode(hex_value).with_context(|| format!("failed to decode {label}"))
}

fn validate_nonzero_prefixed_hash(label: &str, value: &str) -> Result<()> {
    let decoded = decode_prefixed_hex(label, value, 32)?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        bail!("{label} must be a nonzero 32-byte hash");
    }
    Ok(())
}

pub(crate) fn read_idena_anchor_policy(path: &Path) -> Result<IdenaAnchorPolicyV2> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect Idena anchor policy {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Idena anchor policy must be a regular non-symlink file");
    }
    if metadata.len() > MAX_IDENA_ANCHOR_POLICY_BYTES {
        bail!("Idena anchor policy exceeds {MAX_IDENA_ANCHOR_POLICY_BYTES} bytes");
    }
    let payload = fs::read(path)
        .with_context(|| format!("failed to read Idena anchor policy {}", path.display()))?;
    let policy: IdenaAnchorPolicyV2 =
        serde_json::from_slice(&payload).context("Idena anchor policy is not valid strict JSON")?;
    let policy = policy.normalized();
    policy.validate().context("invalid Idena anchor policy")?;
    Ok(policy)
}

fn ensure_idena_ready(syncing: &SyncingResponse) -> Result<()> {
    if syncing.wrong_time {
        bail!("Idena node reports invalid local clock");
    }
    if syncing.is_effectively_syncing() || syncing.current_block < syncing.highest_block {
        bail!(
            "Idena node is not synchronized: current {} highest {}",
            syncing.current_block,
            syncing.highest_block
        );
    }
    Ok(())
}

fn identity_response_is_currently_eligible(
    expected_address: &str,
    identity: &IdentityResponse,
) -> Result<bool> {
    if !identity.address.eq_ignore_ascii_case(expected_address) {
        bail!("Idena RPC returned a different identity address");
    }
    Ok(identity.state.is_block_eligible())
}

fn anchor_from_block(block: &BlockResponse) -> Result<IdenaBlockAnchorV1> {
    if block.height == 0 {
        bail!("Idena anchor block height must be nonzero");
    }
    Ok(IdenaBlockAnchorV1 {
        height: block.height,
        hash: normalize_idena_hash(&block.hash)
            .context("Idena RPC returned a noncanonical block hash")?,
    })
}

fn verify_block_anchor(anchor: &IdenaBlockAnchorV1, block: &BlockResponse) -> Result<()> {
    if block.height != anchor.height {
        bail!(
            "Idena RPC returned height {} for requested anchor {}",
            block.height,
            anchor.height
        );
    }
    let actual_hash = normalize_idena_hash(&block.hash)
        .context("Idena RPC returned a noncanonical block hash")?;
    if actual_hash != anchor.hash.to_ascii_lowercase() {
        bail!("Idena block hash does not match the signed work-template anchor");
    }
    Ok(())
}

fn verify_contract_record(actual: &str, expected: &str) -> Result<()> {
    verify_exact_contract_record(actual, expected, 512, "miner registration")
}

fn verify_exact_contract_record(
    actual: &str,
    expected: &str,
    max_bytes: usize,
    label: &str,
) -> Result<()> {
    if actual.len() > max_bytes || actual.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(anyhow!("registry returned an invalid {label} encoding"));
    }
    if actual != expected {
        bail!("local Idena contract {label} does not match the anchored record");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use idena_lite_indexer::rpc::IdenaRpcClient;
    use pohw_core::snapshot::IdenaStatus;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn policy() -> IdenaAnchorPolicyV2 {
        IdenaAnchorPolicyV2 {
            schema_version: 2,
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registry_contract_address: format!("0x{}", "11".repeat(20)),
            registry_deployment_tx_hash: format!("0x{}", "12".repeat(32)),
            registry_deployment_payload_sha256: "13".repeat(32),
            registry_contract_code_hash: "14".repeat(32),
            registry_contract_wasm_sha256: "15".repeat(32),
            registry_ecosystem_cid: "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
                .to_string(),
            minimum_registration_burn_atoms: "1000".to_string(),
            activation_idena_height: 200,
            finality_confirmations: 6,
            max_anchor_age_blocks: 12,
            handoff_version_bit: 27,
        }
    }

    fn registration(address: String) -> MinerRegistration {
        MinerRegistration {
            version: pohw_core::sharechain::LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: "eligibility-test".to_string(),
            idena_address: address,
            btc_payout_script_hex: "6a".to_string(),
            claim_owner_pubkey_hex: "11".repeat(32),
            mining_pubkey_hex: "22".repeat(32),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        }
    }

    async fn current_eligibility_from_mock_rpc(state: IdenaStatus) -> bool {
        let address = format!("0x{}", "11".repeat(20));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = listener.local_addr().unwrap();
        let response_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "address": address.clone(),
                "state": state,
                "pubkey": "",
                "delegatee": null,
                "isPool": false
            }
        })
        .to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8 * 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let client = IdenaRpcClient::new(format!("http://{socket}"), "test-api-key").unwrap();
        let verifier = IdenaAnchorVerifier::new(client, policy()).unwrap();
        let result = verifier
            .current_identity_is_eligible(&registration(address))
            .await
            .unwrap();
        server.await.unwrap();
        result
    }

    fn append_protobuf_bytes_field(payload: &mut Vec<u8>, field: u8, value: &[u8]) {
        payload.push((field << 3) | 2);
        let mut len = value.len() as u64;
        loop {
            let mut byte = (len & 0x7f) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            payload.push(byte);
            if len == 0 {
                break;
            }
        }
        payload.extend_from_slice(value);
    }

    #[test]
    fn contract_record_match_is_exact_and_bounded() {
        let expected = format!("1|miner-1|{}|1|100|7|1700000000", "aa".repeat(32));
        assert!(verify_contract_record(&expected, &expected).is_ok());
        assert!(verify_contract_record(&format!("{expected}\n"), &expected).is_err());
        assert!(verify_contract_record(&"x".repeat(513), &expected).is_err());
    }

    #[test]
    fn live_identity_gate_accepts_only_newbie_verified_and_human() {
        let address = format!("0x{}", "11".repeat(20));
        for state in [
            IdenaStatus::Newbie,
            IdenaStatus::Verified,
            IdenaStatus::Human,
        ] {
            let identity = IdentityResponse {
                address: address.clone(),
                state,
                pubkey: String::new(),
                delegatee: None,
                is_pool: false,
            };
            assert!(identity_response_is_currently_eligible(&address, &identity).unwrap());
        }
        for state in [
            IdenaStatus::Invite,
            IdenaStatus::Candidate,
            IdenaStatus::Suspended,
            IdenaStatus::Zombie,
            IdenaStatus::Killed,
            IdenaStatus::Undefined,
        ] {
            let identity = IdentityResponse {
                address: address.clone(),
                state,
                pubkey: String::new(),
                delegatee: None,
                is_pool: false,
            };
            assert!(!identity_response_is_currently_eligible(&address, &identity).unwrap());
        }
        let wrong_address = IdentityResponse {
            address: format!("0x{}", "22".repeat(20)),
            state: IdenaStatus::Human,
            pubkey: String::new(),
            delegatee: None,
            is_pool: false,
        };
        assert!(identity_response_is_currently_eligible(&address, &wrong_address).is_err());
    }

    #[tokio::test]
    async fn live_identity_rpc_reports_eligibility_transitions() {
        assert!(current_eligibility_from_mock_rpc(IdenaStatus::Human).await);
        assert!(!current_eligibility_from_mock_rpc(IdenaStatus::Candidate).await);
    }

    #[test]
    fn block_anchor_rejects_height_and_hash_substitution() {
        let anchor = IdenaBlockAnchorV1 {
            height: 100,
            hash: format!("0x{}", "11".repeat(32)),
        };
        let block = BlockResponse {
            coinbase: String::new(),
            hash: anchor.hash.clone(),
            parent_hash: format!("0x{}", "22".repeat(32)),
            height: 100,
            timestamp: 1,
            root: format!("0x{}", "33".repeat(32)),
            identity_root: format!("0x{}", "44".repeat(32)),
            transactions: None,
            is_empty: false,
        };
        assert!(verify_block_anchor(&anchor, &block).is_ok());
        assert!(verify_block_anchor(
            &IdenaBlockAnchorV1 {
                height: 99,
                ..anchor.clone()
            },
            &block
        )
        .is_err());
        assert!(verify_block_anchor(
            &IdenaBlockAnchorV1 {
                hash: format!("0x{}", "55".repeat(32)),
                ..anchor
            },
            &block,
        )
        .is_err());
    }

    #[test]
    fn deployment_attachment_parser_binds_code_and_argument_order() {
        let policy = policy();
        let mut payload = Vec::new();
        append_protobuf_bytes_field(&mut payload, 1, &[0x14; 32]);
        append_protobuf_bytes_field(&mut payload, 2, policy.experiment_id.as_bytes());
        append_protobuf_bytes_field(&mut payload, 2, policy.registry_ecosystem_cid.as_bytes());
        append_protobuf_bytes_field(
            &mut payload,
            2,
            policy.minimum_registration_burn_atoms.as_bytes(),
        );
        append_protobuf_bytes_field(&mut payload, 3, b"wasm");
        append_protobuf_bytes_field(&mut payload, 4, b"nonce");

        let attachment = parse_deploy_contract_attachment(&payload).unwrap();
        assert_eq!(attachment.code_hash, vec![0x14; 32]);
        assert_eq!(attachment.code, b"wasm");
        assert_eq!(attachment.nonce, b"nonce");
        verify_registry_deployment_arguments(&policy, &attachment.args).unwrap();

        let mut reordered = attachment.args;
        reordered.swap(0, 1);
        assert!(verify_registry_deployment_arguments(&policy, &reordered).is_err());
        append_protobuf_bytes_field(&mut payload, 5, b"unknown");
        assert!(parse_deploy_contract_attachment(&payload).is_err());
    }

    #[test]
    fn deployment_receipt_and_finality_checks_fail_closed() {
        let policy = policy();
        let transaction = TransactionResponse {
            hash: policy.registry_deployment_tx_hash.clone(),
            transaction_type: "deployContract".to_string(),
            to: None,
            payload: "0x00".to_string(),
            block_hash: format!("0x{}", "31".repeat(32)),
            timestamp: 1_700_000_000,
        };
        verify_registry_deployment_transaction(&policy, &transaction).unwrap();
        let receipt = TxReceiptResponse {
            contract: policy.registry_contract_address.clone(),
            success: true,
            tx_hash: Some(policy.registry_deployment_tx_hash.clone()),
            error: String::new(),
        };
        verify_registry_deployment_receipt(&policy, &receipt).unwrap();
        let block = BlockResponse {
            coinbase: String::new(),
            hash: transaction.block_hash.clone(),
            parent_hash: format!("0x{}", "30".repeat(32)),
            height: 150,
            timestamp: transaction.timestamp,
            root: format!("0x{}", "32".repeat(32)),
            identity_root: format!("0x{}", "33".repeat(32)),
            transactions: None,
            is_empty: false,
        };
        let syncing = SyncingResponse {
            syncing: false,
            current_block: 200,
            highest_block: 200,
            wrong_time: false,
            genesis_block: 1,
            message: String::new(),
        };
        verify_registry_deployment_block(&policy, &transaction, &block, &syncing).unwrap();

        let mut unfinalized = block;
        unfinalized.height = 199;
        assert!(
            verify_registry_deployment_block(&policy, &transaction, &unfinalized, &syncing)
                .is_err()
        );
        let mut failed_receipt = receipt;
        failed_receipt.success = false;
        assert!(verify_registry_deployment_receipt(&policy, &failed_receipt).is_err());
    }

    #[test]
    fn policy_reader_rejects_symlinks_and_unknown_fields() {
        let base = std::env::temp_dir().join(format!(
            "pohw-idena-anchor-policy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let path = base.join("policy.json");
        let mut value = serde_json::to_value(policy()).unwrap();
        value["unknown"] = serde_json::json!(true);
        let mut file = fs::File::create(&path).unwrap();
        serde_json::to_writer(&mut file, &value).unwrap();
        assert!(read_idena_anchor_policy(&path).is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
