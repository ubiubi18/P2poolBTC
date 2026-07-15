use crate::{canonical_json, hash_hex, sha256_tagged};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const IDENA_HASH_HEX_LEN: usize = 66;
pub const IDENA_ADDRESS_HEX_LEN: usize = 42;
pub const ZERO_SHARE_PARENT_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const CHECKPOINT_QUORUM_NUMERATOR: u32 = 2;
pub const CHECKPOINT_QUORUM_DENOMINATOR: u32 = 3;
pub const CHECKPOINT_MIN_INTERVAL_BLOCKS: u64 = 6;
pub const MAX_CHECKPOINT_MINERS: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdenaBlockAnchorV1 {
    pub height: u64,
    pub hash: String,
}

impl IdenaBlockAnchorV1 {
    pub fn normalized(mut self) -> Self {
        self.hash = self.hash.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), IdenaAnchorError> {
        if self.height == 0 {
            return Err(IdenaAnchorError::InvalidBlockHeight);
        }
        validate_prefixed_hex("Idena block hash", &self.hash, 32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinerRegistryAnchorV1 {
    pub contract_address: String,
    pub experiment_id: String,
    pub registration_sequence: u32,
    pub registration_block: u64,
    pub registration_epoch: u16,
    pub registration_timestamp: i64,
    pub registration_commitment: String,
}

impl MinerRegistryAnchorV1 {
    pub fn from_canonical_record_line(
        contract_address: impl Into<String>,
        experiment_id: impl Into<String>,
        record: &str,
    ) -> Result<(String, Self), IdenaAnchorError> {
        if record.len() > 512 || record.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(IdenaAnchorError::InvalidRegistryRecord);
        }
        let fields = record.split('|').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != "1" {
            return Err(IdenaAnchorError::InvalidRegistryRecord);
        }
        let miner_id = fields[1].to_string();
        validate_miner_id(&miner_id)?;
        let anchor = Self {
            contract_address: contract_address.into(),
            experiment_id: experiment_id.into(),
            registration_commitment: fields[2].to_string(),
            registration_sequence: fields[3]
                .parse()
                .map_err(|_| IdenaAnchorError::InvalidRegistryRecord)?,
            registration_block: fields[4]
                .parse()
                .map_err(|_| IdenaAnchorError::InvalidRegistryRecord)?,
            registration_epoch: fields[5]
                .parse()
                .map_err(|_| IdenaAnchorError::InvalidRegistryRecord)?,
            registration_timestamp: fields[6]
                .parse()
                .map_err(|_| IdenaAnchorError::InvalidRegistryRecord)?,
        }
        .normalized();
        anchor.validate()?;
        if anchor.canonical_record_line(&miner_id)? != record {
            return Err(IdenaAnchorError::InvalidRegistryRecord);
        }
        Ok((miner_id, anchor))
    }

    pub fn normalized(mut self) -> Self {
        self.contract_address = self.contract_address.to_ascii_lowercase();
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.registration_commitment = self.registration_commitment.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), IdenaAnchorError> {
        validate_prefixed_hex("registry contract address", &self.contract_address, 20)?;
        validate_experiment_id(&self.experiment_id)?;
        if self.registration_sequence == 0 {
            return Err(IdenaAnchorError::InvalidRegistrationSequence);
        }
        if self.registration_block == 0 {
            return Err(IdenaAnchorError::InvalidRegistrationBlock);
        }
        if self.registration_timestamp <= 0 {
            return Err(IdenaAnchorError::InvalidRegistrationTimestamp);
        }
        validate_unprefixed_hex("registration commitment", &self.registration_commitment, 32)
    }

    pub fn storage_key(&self, idena_address: &str) -> Result<String, IdenaAnchorError> {
        miner_registry_storage_key(idena_address, self.registration_sequence)
    }

    pub fn canonical_record_line(&self, miner_id: &str) -> Result<String, IdenaAnchorError> {
        validate_miner_id(miner_id)?;
        self.validate()?;
        Ok(format!(
            "1|{}|{}|{}|{}|{}|{}",
            miner_id.to_ascii_lowercase(),
            self.registration_commitment.to_ascii_lowercase(),
            self.registration_sequence,
            self.registration_block,
            self.registration_epoch,
            self.registration_timestamp,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharechainCheckpointAnchorV1 {
    pub contract_address: String,
    pub experiment_id: String,
    pub round: u32,
    pub share_tip_hash: String,
    pub share_height: u64,
    pub cumulative_score: String,
    pub parent_checkpoint_tip: String,
    pub finalization_block: u64,
    pub finalization_block_hash: String,
    pub finalization_epoch: u16,
    pub finalization_timestamp: i64,
    pub support_count: u32,
    pub registered_count: u32,
    pub registered_miners: Vec<String>,
    pub supporters: Vec<String>,
}

impl SharechainCheckpointAnchorV1 {
    pub fn from_canonical_record_line(
        contract_address: impl Into<String>,
        experiment_id: impl Into<String>,
        finalization_block_hash: impl Into<String>,
        record: &str,
    ) -> Result<Self, IdenaAnchorError> {
        if record.len() > 4096 || record.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        let fields = record.split('|').collect::<Vec<_>>();
        if fields.len() != 13 || fields[0] != "1" {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        let checkpoint = Self {
            contract_address: contract_address.into(),
            experiment_id: experiment_id.into(),
            round: parse_checkpoint_field(fields[1])?,
            share_tip_hash: fields[2].to_string(),
            share_height: parse_checkpoint_field(fields[3])?,
            cumulative_score: fields[4].to_string(),
            parent_checkpoint_tip: fields[5].to_string(),
            finalization_block: parse_checkpoint_field(fields[6])?,
            finalization_block_hash: finalization_block_hash.into(),
            finalization_epoch: parse_checkpoint_field(fields[7])?,
            finalization_timestamp: parse_checkpoint_field(fields[8])?,
            support_count: parse_checkpoint_field(fields[9])?,
            registered_count: parse_checkpoint_field(fields[10])?,
            registered_miners: parse_checkpoint_miner_list(fields[11])?,
            supporters: parse_checkpoint_miner_list(fields[12])?,
        }
        .normalized();
        checkpoint.validate()?;
        if checkpoint.canonical_record_line()? != record {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        Ok(checkpoint)
    }

    pub fn normalized(mut self) -> Self {
        self.contract_address = self.contract_address.to_ascii_lowercase();
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.share_tip_hash = self.share_tip_hash.to_ascii_lowercase();
        self.parent_checkpoint_tip = self.parent_checkpoint_tip.to_ascii_lowercase();
        self.finalization_block_hash = self.finalization_block_hash.to_ascii_lowercase();
        self.registered_miners = self
            .registered_miners
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        self.supporters = self
            .supporters
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        self
    }

    pub fn validate(&self) -> Result<(), IdenaAnchorError> {
        validate_prefixed_hex("registry contract address", &self.contract_address, 20)?;
        validate_experiment_id(&self.experiment_id)?;
        if self.round == 0 || self.share_height == 0 || self.finalization_block == 0 {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        if self.finalization_timestamp <= 0 {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        validate_unprefixed_hex("checkpoint share tip", &self.share_tip_hash, 32)?;
        if self.share_tip_hash == ZERO_SHARE_PARENT_HASH {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        validate_unprefixed_hex(
            "checkpoint parent share tip",
            &self.parent_checkpoint_tip,
            32,
        )?;
        if (self.round == 1) != (self.parent_checkpoint_tip == ZERO_SHARE_PARENT_HASH) {
            return Err(IdenaAnchorError::InvalidCheckpointParent);
        }
        validate_prefixed_hex(
            "checkpoint finalization block hash",
            &self.finalization_block_hash,
            32,
        )?;
        validate_positive_checkpoint_score(&self.cumulative_score)?;
        validate_checkpoint_miner_list(&self.registered_miners)?;
        validate_checkpoint_miner_list(&self.supporters)?;
        if self.registered_miners.is_empty()
            || self.registered_miners.len() > MAX_CHECKPOINT_MINERS
            || self.support_count as usize != self.supporters.len()
            || self.registered_count as usize != self.registered_miners.len()
            || !self
                .supporters
                .iter()
                .all(|miner| self.registered_miners.binary_search(miner).is_ok())
            || self.support_count < checkpoint_quorum_threshold(self.registered_count)?
        {
            return Err(IdenaAnchorError::InvalidCheckpointQuorum);
        }
        Ok(())
    }

    pub fn canonical_record_line(&self) -> Result<String, IdenaAnchorError> {
        self.validate()?;
        Ok(format!(
            "1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.round,
            self.share_tip_hash,
            self.share_height,
            self.cumulative_score,
            self.parent_checkpoint_tip,
            self.finalization_block,
            self.finalization_epoch,
            self.finalization_timestamp,
            self.support_count,
            self.registered_count,
            self.registered_miners.join(","),
            self.supporters.join(","),
        ))
    }

    pub fn storage_key(&self) -> String {
        format!("checkpoint:final:{}", self.round)
    }

    pub fn finalization_anchor(&self) -> IdenaBlockAnchorV1 {
        IdenaBlockAnchorV1 {
            height: self.finalization_block,
            hash: self.finalization_block_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdenaAnchorPolicyV2 {
    pub schema_version: u16,
    pub experiment_id: String,
    pub registry_contract_address: String,
    pub registry_deployment_tx_hash: String,
    pub registry_deployment_payload_sha256: String,
    pub registry_contract_code_hash: String,
    pub registry_contract_wasm_sha256: String,
    pub registry_ecosystem_cid: String,
    pub minimum_registration_burn_atoms: String,
    pub activation_idena_height: u64,
    pub finality_confirmations: u64,
    pub max_anchor_age_blocks: u64,
    pub handoff_version_bit: u8,
}

impl IdenaAnchorPolicyV2 {
    pub fn normalized(mut self) -> Self {
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.registry_contract_address = self.registry_contract_address.to_ascii_lowercase();
        self.registry_deployment_tx_hash = self.registry_deployment_tx_hash.to_ascii_lowercase();
        self.registry_deployment_payload_sha256 =
            self.registry_deployment_payload_sha256.to_ascii_lowercase();
        self.registry_contract_code_hash = self.registry_contract_code_hash.to_ascii_lowercase();
        self.registry_contract_wasm_sha256 =
            self.registry_contract_wasm_sha256.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), IdenaAnchorError> {
        if self.schema_version != 2 {
            return Err(IdenaAnchorError::UnsupportedPolicyVersion(
                self.schema_version,
            ));
        }
        validate_experiment_id(&self.experiment_id)?;
        validate_prefixed_hex(
            "registry contract address",
            &self.registry_contract_address,
            20,
        )?;
        if self.registry_contract_address[2..]
            .bytes()
            .all(|byte| byte == b'0')
        {
            return Err(IdenaAnchorError::ZeroRegistryContractAddress);
        }
        validate_prefixed_hex(
            "registry deployment transaction hash",
            &self.registry_deployment_tx_hash,
            32,
        )?;
        validate_unprefixed_hex(
            "registry deployment payload SHA-256",
            &self.registry_deployment_payload_sha256,
            32,
        )?;
        validate_unprefixed_hex(
            "registry contract WASM SHA-256",
            &self.registry_contract_wasm_sha256,
            32,
        )?;
        validate_unprefixed_hex(
            "registry contract code hash",
            &self.registry_contract_code_hash,
            32,
        )?;
        validate_canonical_cid_v1(&self.registry_ecosystem_cid)?;
        validate_positive_canonical_u128(&self.minimum_registration_burn_atoms)?;
        if self.activation_idena_height == 0 {
            return Err(IdenaAnchorError::InvalidActivationHeight);
        }
        if self.finality_confirmations == 0 {
            return Err(IdenaAnchorError::InvalidFinalityConfirmations);
        }
        if self.max_anchor_age_blocks < self.finality_confirmations {
            return Err(IdenaAnchorError::InvalidAnchorAgeWindow);
        }
        if self.handoff_version_bit > 28 {
            return Err(IdenaAnchorError::InvalidHandoffVersionBit(
                self.handoff_version_bit,
            ));
        }
        Ok(())
    }

    pub fn commitment_hash(&self) -> Result<String, IdenaAnchorError> {
        let policy = self.clone().normalized();
        policy.validate()?;
        Ok(hash_hex(sha256_tagged(
            b"POHW_IDENA_ANCHOR_POLICY_V2",
            &canonical_json(&policy),
        )))
    }

    pub fn validate_registry_anchor(
        &self,
        anchor: &MinerRegistryAnchorV1,
    ) -> Result<(), IdenaAnchorError> {
        self.validate()?;
        anchor.validate()?;
        if !anchor
            .experiment_id
            .eq_ignore_ascii_case(&self.experiment_id)
        {
            return Err(IdenaAnchorError::ExperimentMismatch);
        }
        if !anchor
            .contract_address
            .eq_ignore_ascii_case(&self.registry_contract_address)
        {
            return Err(IdenaAnchorError::RegistryContractMismatch);
        }
        if anchor.registration_block < self.activation_idena_height {
            return Err(IdenaAnchorError::RegistrationBeforeActivation);
        }
        Ok(())
    }

    pub fn validate_checkpoint_anchor(
        &self,
        checkpoint: &SharechainCheckpointAnchorV1,
    ) -> Result<(), IdenaAnchorError> {
        self.validate()?;
        checkpoint.validate()?;
        if !checkpoint
            .experiment_id
            .eq_ignore_ascii_case(&self.experiment_id)
        {
            return Err(IdenaAnchorError::ExperimentMismatch);
        }
        if !checkpoint
            .contract_address
            .eq_ignore_ascii_case(&self.registry_contract_address)
        {
            return Err(IdenaAnchorError::RegistryContractMismatch);
        }
        if checkpoint.finalization_block < self.activation_idena_height {
            return Err(IdenaAnchorError::CheckpointBeforeActivation);
        }
        Ok(())
    }

    pub fn validate_live_block_anchor(
        &self,
        anchor: &IdenaBlockAnchorV1,
        current_idena_height: u64,
    ) -> Result<u64, IdenaAnchorError> {
        let finalized_height =
            self.validate_finalized_block_anchor(anchor, current_idena_height)?;
        let age = finalized_height - anchor.height;
        if age > self.max_anchor_age_blocks {
            return Err(IdenaAnchorError::StaleAnchor {
                age,
                maximum: self.max_anchor_age_blocks,
            });
        }
        Ok(finalized_height)
    }

    pub fn validate_finalized_block_anchor(
        &self,
        anchor: &IdenaBlockAnchorV1,
        current_idena_height: u64,
    ) -> Result<u64, IdenaAnchorError> {
        self.validate()?;
        anchor.validate()?;
        let finalized_height = current_idena_height
            .checked_sub(self.finality_confirmations)
            .ok_or(IdenaAnchorError::IdenaTipNotFinalized)?;
        if anchor.height > finalized_height {
            return Err(IdenaAnchorError::AnchorNotFinalized {
                anchor_height: anchor.height,
                finalized_height,
            });
        }
        if anchor.height < self.activation_idena_height {
            return Err(IdenaAnchorError::AnchorBeforeActivation);
        }
        Ok(finalized_height)
    }

    pub fn bootstrap_limits_active(&self, bitcoin_header_version: u32) -> bool {
        bitcoin_header_version & (1u32 << self.handoff_version_bit) == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdenaAnchorError {
    #[error("unsupported Idena anchor policy version {0}")]
    UnsupportedPolicyVersion(u16),
    #[error("invalid Idena block height")]
    InvalidBlockHeight,
    #[error("invalid miner registration sequence")]
    InvalidRegistrationSequence,
    #[error("invalid miner registration block")]
    InvalidRegistrationBlock,
    #[error("invalid miner registration timestamp")]
    InvalidRegistrationTimestamp,
    #[error("invalid or noncanonical miner registry record")]
    InvalidRegistryRecord,
    #[error("invalid or noncanonical sharechain checkpoint record")]
    InvalidCheckpointRecord,
    #[error("checkpoint parent does not match its round")]
    InvalidCheckpointParent,
    #[error("checkpoint registered/supporting miner quorum is invalid")]
    InvalidCheckpointQuorum,
    #[error("checkpoint cumulative score must be a positive canonical u128 decimal")]
    InvalidCheckpointScore,
    #[error("invalid Idena anchor activation height")]
    InvalidActivationHeight,
    #[error("Idena anchor finality confirmations must be greater than zero")]
    InvalidFinalityConfirmations,
    #[error("Idena anchor age window must cover the finality confirmation depth")]
    InvalidAnchorAgeWindow,
    #[error("registry contract address must not be the zero address")]
    ZeroRegistryContractAddress,
    #[error("registry ecosystem CID must be canonical CIDv1 base32 with SHA2-256 multihash")]
    InvalidRegistryEcosystemCid,
    #[error("minimum registration burn must be a positive canonical u128 decimal")]
    InvalidMinimumRegistrationBurn,
    #[error("Bitcoin handoff version bit {0} is outside the versionbits range 0-28")]
    InvalidHandoffVersionBit(u8),
    #[error("invalid experiment id")]
    InvalidExperimentId,
    #[error("invalid miner id")]
    InvalidMinerId,
    #[error("invalid Idena address")]
    InvalidIdenaAddress,
    #[error("invalid {field}: expected {bytes} lowercase hexadecimal bytes")]
    InvalidHex { field: String, bytes: usize },
    #[error("miner registry experiment does not match the active policy")]
    ExperimentMismatch,
    #[error("miner registry contract does not match the active policy")]
    RegistryContractMismatch,
    #[error("Idena anchor policy commitment does not match the active policy")]
    PolicyCommitmentMismatch,
    #[error("miner registration predates Idena anchor-policy activation")]
    RegistrationBeforeActivation,
    #[error("sharechain checkpoint predates Idena anchor-policy activation")]
    CheckpointBeforeActivation,
    #[error("Idena block anchor predates policy activation")]
    AnchorBeforeActivation,
    #[error("Idena tip does not have the configured finality depth")]
    IdenaTipNotFinalized,
    #[error(
        "Idena block anchor {anchor_height} is newer than finalized height {finalized_height}"
    )]
    AnchorNotFinalized {
        anchor_height: u64,
        finalized_height: u64,
    },
    #[error("Idena block anchor is {age} blocks old, above maximum {maximum}")]
    StaleAnchor { age: u64, maximum: u64 },
}

pub fn normalize_idena_hash(value: &str) -> Result<String, IdenaAnchorError> {
    validate_prefixed_hex("Idena block hash", value, 32)?;
    Ok(value.to_ascii_lowercase())
}

pub fn normalize_idena_address(value: &str) -> Result<String, IdenaAnchorError> {
    if validate_prefixed_hex("Idena address", value, 20).is_err() {
        return Err(IdenaAnchorError::InvalidIdenaAddress);
    }
    Ok(value.to_ascii_lowercase())
}

pub fn miner_registry_storage_key(
    idena_address: &str,
    registration_sequence: u32,
) -> Result<String, IdenaAnchorError> {
    if registration_sequence == 0 {
        return Err(IdenaAnchorError::InvalidRegistrationSequence);
    }
    let address = normalize_idena_address(idena_address)?;
    Ok(format!(
        "miner:{}:{}",
        address.trim_start_matches("0x"),
        registration_sequence
    ))
}

pub fn validate_experiment_id(value: &str) -> Result<(), IdenaAnchorError> {
    if value.is_empty()
        || value.len() > 64
        || value != value.to_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:/-".contains(&byte)
        })
    {
        return Err(IdenaAnchorError::InvalidExperimentId);
    }
    Ok(())
}

pub fn validate_miner_id(value: &str) -> Result<(), IdenaAnchorError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdenaAnchorError::InvalidMinerId);
    }
    Ok(())
}

fn validate_prefixed_hex(field: &str, value: &str, bytes: usize) -> Result<(), IdenaAnchorError> {
    if value.len() != bytes * 2 + 2
        || !value.starts_with("0x")
        || value[2..].bytes().any(|byte| !byte.is_ascii_hexdigit())
        || value != value.to_ascii_lowercase()
    {
        return Err(IdenaAnchorError::InvalidHex {
            field: field.to_string(),
            bytes,
        });
    }
    Ok(())
}

fn validate_unprefixed_hex(field: &str, value: &str, bytes: usize) -> Result<(), IdenaAnchorError> {
    if value.len() != bytes * 2
        || value.bytes().any(|byte| !byte.is_ascii_hexdigit())
        || value != value.to_ascii_lowercase()
    {
        return Err(IdenaAnchorError::InvalidHex {
            field: field.to_string(),
            bytes,
        });
    }
    Ok(())
}

fn validate_canonical_cid_v1(value: &str) -> Result<(), IdenaAnchorError> {
    let cid = value
        .parse::<Cid>()
        .map_err(|_| IdenaAnchorError::InvalidRegistryEcosystemCid)?;
    if cid.version() != Version::V1
        || cid.to_string() != value
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
    {
        return Err(IdenaAnchorError::InvalidRegistryEcosystemCid);
    }
    Ok(())
}

fn validate_positive_canonical_u128(value: &str) -> Result<(), IdenaAnchorError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || value
            .parse::<u128>()
            .ok()
            .filter(|amount| *amount > 0)
            .is_none()
    {
        return Err(IdenaAnchorError::InvalidMinimumRegistrationBurn);
    }
    Ok(())
}

fn validate_positive_checkpoint_score(value: &str) -> Result<(), IdenaAnchorError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || value
            .parse::<u128>()
            .ok()
            .filter(|score| *score > 0)
            .is_none()
    {
        return Err(IdenaAnchorError::InvalidCheckpointScore);
    }
    Ok(())
}

fn parse_checkpoint_field<T: std::str::FromStr>(value: &str) -> Result<T, IdenaAnchorError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(IdenaAnchorError::InvalidCheckpointRecord);
    }
    value
        .parse()
        .map_err(|_| IdenaAnchorError::InvalidCheckpointRecord)
}

fn parse_checkpoint_miner_list(value: &str) -> Result<Vec<String>, IdenaAnchorError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let miners = value.split(',').map(str::to_string).collect::<Vec<_>>();
    validate_checkpoint_miner_list(&miners)?;
    Ok(miners)
}

fn validate_checkpoint_miner_list(miners: &[String]) -> Result<(), IdenaAnchorError> {
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for miner in miners {
        validate_miner_id(miner)?;
        if miner != &miner.to_ascii_lowercase()
            || previous.is_some_and(|value| value >= miner.as_str())
            || !seen.insert(miner)
        {
            return Err(IdenaAnchorError::InvalidCheckpointRecord);
        }
        previous = Some(miner);
    }
    Ok(())
}

pub fn checkpoint_quorum_threshold(registered_count: u32) -> Result<u32, IdenaAnchorError> {
    if registered_count == 0 || registered_count as usize > MAX_CHECKPOINT_MINERS {
        return Err(IdenaAnchorError::InvalidCheckpointQuorum);
    }
    registered_count
        .checked_mul(CHECKPOINT_QUORUM_NUMERATOR)
        .and_then(|value| value.checked_add(CHECKPOINT_QUORUM_DENOMINATOR - 1))
        .map(|value| value / CHECKPOINT_QUORUM_DENOMINATOR)
        .ok_or(IdenaAnchorError::InvalidCheckpointQuorum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> IdenaAnchorPolicyV2 {
        IdenaAnchorPolicyV2 {
            schema_version: 2,
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registry_contract_address: format!("0x{}", "11".repeat(20)),
            registry_deployment_tx_hash: format!("0x{}", "12".repeat(32)),
            registry_deployment_payload_sha256: "13".repeat(32),
            registry_contract_code_hash: "15".repeat(32),
            registry_contract_wasm_sha256: "14".repeat(32),
            registry_ecosystem_cid: "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
                .to_string(),
            minimum_registration_burn_atoms: "1000".to_string(),
            activation_idena_height: 100,
            finality_confirmations: 6,
            max_anchor_age_blocks: 120,
            handoff_version_bit: 27,
        }
    }

    #[test]
    fn freshness_requires_finalized_recent_anchor() {
        let policy = policy();
        let anchor = IdenaBlockAnchorV1 {
            height: 190,
            hash: format!("0x{}", "22".repeat(32)),
        };
        assert_eq!(policy.validate_live_block_anchor(&anchor, 200), Ok(194));
        assert!(matches!(
            policy.validate_live_block_anchor(
                &IdenaBlockAnchorV1 {
                    height: 195,
                    ..anchor.clone()
                },
                200
            ),
            Err(IdenaAnchorError::AnchorNotFinalized { .. })
        ));
        assert!(matches!(
            policy.validate_live_block_anchor(
                &IdenaBlockAnchorV1 {
                    height: 70,
                    ..anchor
                },
                200
            ),
            Err(IdenaAnchorError::AnchorBeforeActivation)
        ));
    }

    #[test]
    fn canonical_registry_record_and_key_are_unambiguous() {
        let anchor = MinerRegistryAnchorV1 {
            contract_address: format!("0x{}", "11".repeat(20)),
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registration_sequence: 2,
            registration_block: 123,
            registration_epoch: 77,
            registration_timestamp: 1_700_000_000,
            registration_commitment: "aa".repeat(32),
        };
        assert_eq!(
            anchor
                .storage_key(&format!("0x{}", "bb".repeat(20)))
                .unwrap(),
            format!("miner:{}:2", "bb".repeat(20))
        );
        assert_eq!(
            anchor.canonical_record_line("miner-1").unwrap(),
            format!("1|miner-1|{}|2|123|77|1700000000", "aa".repeat(32))
        );
        let record = anchor.canonical_record_line("miner-1").unwrap();
        let (miner_id, parsed) = MinerRegistryAnchorV1::from_canonical_record_line(
            anchor.contract_address.clone(),
            anchor.experiment_id.clone(),
            &record,
        )
        .unwrap();
        assert_eq!(miner_id, "miner-1");
        assert_eq!(parsed, anchor);
        assert!(MinerRegistryAnchorV1::from_canonical_record_line(
            format!("0x{}", "11".repeat(20)),
            "p2poolbtc-experiment-1",
            &record.replace("|2|", "|02|"),
        )
        .is_err());
        assert!(anchor.canonical_record_line("miner:1").is_err());
    }

    #[test]
    fn bootstrap_phase_is_bound_to_the_committed_header_version() {
        let policy = policy();
        assert!(policy.bootstrap_limits_active(1));
        assert!(!policy.bootstrap_limits_active(1 | (1 << 27)));
    }

    #[test]
    fn checkpoint_record_is_canonical_and_requires_two_thirds() {
        let record = format!(
            "1|1|{}|12|345|{}|123|8|1700000060|2|3|alice,bob,carol|alice,bob",
            "11".repeat(32),
            ZERO_SHARE_PARENT_HASH
        );
        let checkpoint = SharechainCheckpointAnchorV1::from_canonical_record_line(
            format!("0x{}", "22".repeat(20)),
            "p2poolbtc-experiment-1",
            format!("0x{}", "33".repeat(32)),
            &record,
        )
        .unwrap();

        assert_eq!(checkpoint.canonical_record_line().unwrap(), record);
        assert_eq!(checkpoint.storage_key(), "checkpoint:final:1");
        assert_eq!(checkpoint_quorum_threshold(3).unwrap(), 2);
        assert_eq!(checkpoint_quorum_threshold(4).unwrap(), 3);

        let mut insufficient = checkpoint.clone();
        insufficient.supporters = vec!["alice".to_string()];
        insufficient.support_count = 1;
        assert_eq!(
            insufficient.validate(),
            Err(IdenaAnchorError::InvalidCheckpointQuorum)
        );

        let mut unsorted = checkpoint;
        unsorted.registered_miners.swap(0, 1);
        assert_eq!(
            unsorted.validate(),
            Err(IdenaAnchorError::InvalidCheckpointRecord)
        );
    }

    #[test]
    fn policy_rejects_zero_finality_and_mixed_case_identifiers() {
        let mut invalid = policy();
        invalid.finality_confirmations = 0;
        assert_eq!(
            invalid.validate(),
            Err(IdenaAnchorError::InvalidFinalityConfirmations)
        );
        invalid = policy();
        invalid.experiment_id = "Experiment-1".to_string();
        assert_eq!(
            invalid.validate(),
            Err(IdenaAnchorError::InvalidExperimentId)
        );
        invalid = policy();
        invalid.handoff_version_bit = 29;
        assert_eq!(
            invalid.validate(),
            Err(IdenaAnchorError::InvalidHandoffVersionBit(29))
        );
    }

    #[test]
    fn policy_commitment_is_deterministic_and_binds_all_fields() {
        let policy = policy();
        let commitment = policy.commitment_hash().unwrap();
        assert_eq!(commitment.len(), 64);
        assert_eq!(
            commitment,
            policy.clone().normalized().commitment_hash().unwrap()
        );

        let mut changed = policy;
        changed.max_anchor_age_blocks += 1;
        assert_ne!(commitment, changed.commitment_hash().unwrap());
    }
}
