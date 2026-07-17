use crate::commitment::PohwCommitment;
use crate::idena_anchor::{
    validate_experiment_id, IdenaBlockAnchorV1, MinerRegistryAnchorV1, SharechainCheckpointAnchorV1,
};
use crate::payout::PayoutSchedule;
use crate::share_work::{ShareWorkBindingError, ShareWorkBindingPolicyV1, ShareWorkBindingV1};
use crate::withdrawal::{WithdrawalBatch, WithdrawalRequest};
use crate::{canonical_json, hash_hex, sha256_tagged, Score};
use bitcoin::consensus::Params;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::key::{Secp256k1, XOnlyPublicKey};
use bitcoin::pow::Target;
use bitcoin::secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    schnorr::Signature,
    Message, PublicKey,
};
use bitcoin::ScriptBuf;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

const MAX_MINER_ID_LEN: usize = 64;
const MAX_SNAPSHOT_ID_LEN: usize = 64;
const SCHNORR_SIGNATURE_HEX_LEN: usize = 128;
const IDENA_RECOVERABLE_SIGNATURE_HEX_LEN: usize = 130;
const P2WPKH_SCRIPT_HEX_LEN: usize = 44;
const P2TR_SCRIPT_HEX_LEN: usize = 68;
const BITCOIN_HEADER_BYTES: usize = 80;
const BITCOIN_HEADER_HEX_LEN: usize = BITCOIN_HEADER_BYTES * 2;
const BITCOIN_TEMPLATE_PREFIX_BYTES: usize = 76;
const BITCOIN_NONCE_BYTES: usize = 4;
const BITCOIN_NONCE_HEX_LEN: usize = BITCOIN_NONCE_BYTES * 2;
pub const MAX_ACCEPTED_SHARE_TARGET_HEX: &str =
    "7fffff0000000000000000000000000000000000000000000000000000000000";
pub const LEGACY_BITCOIN_WORK_TEMPLATE_VERSION: u16 = 1;
pub const TARGET_BOUND_BITCOIN_WORK_TEMPLATE_VERSION: u16 = 2;
pub const IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION: u16 = 3;
pub const LEGACY_MINER_REGISTRATION_VERSION: u16 = 1;
pub const IDENA_ANCHORED_MINER_REGISTRATION_VERSION: u16 = 2;

fn legacy_miner_registration_version() -> u16 {
    LEGACY_MINER_REGISTRATION_VERSION
}

fn is_legacy_miner_registration_version(version: &u16) -> bool {
    *version == LEGACY_MINER_REGISTRATION_VERSION
}

fn legacy_bitcoin_work_template_version() -> u16 {
    LEGACY_BITCOIN_WORK_TEMPLATE_VERSION
}

fn is_legacy_bitcoin_work_template_version(version: &u16) -> bool {
    *version == LEGACY_BITCOIN_WORK_TEMPLATE_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerRegistration {
    #[serde(
        default = "legacy_miner_registration_version",
        skip_serializing_if = "is_legacy_miner_registration_version"
    )]
    pub version: u16,
    pub miner_id: String,
    pub idena_address: String,
    pub btc_payout_script_hex: String,
    pub claim_owner_pubkey_hex: String,
    pub mining_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_anchor: Option<MinerRegistryAnchorV1>,
    pub idena_signature_hex: String,
    pub mining_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinWorkTemplate {
    #[serde(
        default = "legacy_bitcoin_work_template_version",
        skip_serializing_if = "is_legacy_bitcoin_work_template_version"
    )]
    pub version: u16,
    pub miner_id: String,
    pub header_prefix_hex: String,
    pub template_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_share_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idena_anchor: Option<IdenaBlockAnchorV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idena_anchor_policy_hash: Option<String>,
    pub created_at_unix: i64,
    pub mining_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub miner_id: String,
    pub bitcoin_header_hex: String,
    pub bitcoin_template_hash: String,
    pub nonce_hex: String,
    pub work_hash: String,
    pub target: String,
    pub idena_snapshot_id: String,
    pub idena_snapshot_proof_root: String,
    pub hashrate_score_delta: Score,
    pub parent_share_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_binding: Option<Box<ShareWorkBindingV1>>,
    pub mining_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotVote {
    pub voter_miner_id: String,
    pub snapshot_day: String,
    pub idena_height: u64,
    pub score_root: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SharechainMessage {
    MinerRegistration(MinerRegistration),
    BitcoinWorkTemplate(BitcoinWorkTemplate),
    Share(Share),
    SharechainCheckpoint(SharechainCheckpointAnchorV1),
    SnapshotVote(SnapshotVote),
    PayoutSchedule(PayoutSchedule),
    WithdrawalRequest(WithdrawalRequest),
    WithdrawalBatch(WithdrawalBatch),
    PohwCommitment(PohwCommitment),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SharechainError {
    #[error("invalid mining pubkey: {0}")]
    InvalidMiningPubkey(String),
    #[error("missing mining signature")]
    MissingMiningSignature,
    #[error("invalid mining signature: {0}")]
    InvalidMiningSignature(String),
    #[error("invalid idena signature hex")]
    InvalidIdenaSignature(String),
    #[error("idena signature recovered address {recovered_address} but registration claims {claimed_address}")]
    IdenaAddressSignatureMismatch {
        claimed_address: String,
        recovered_address: String,
    },
    #[error("invalid Bitcoin payout script: {0}")]
    InvalidPayoutScript(String),
    #[error("invalid claim owner pubkey: {0}")]
    InvalidClaimOwnerPubkey(String),
    #[error("invalid miner id in {field}: {reason}")]
    InvalidMinerId { field: String, reason: String },
    #[error("invalid Idena address: {0}")]
    InvalidIdenaAddress(String),
    #[error("invalid {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("share hashrate score delta must be greater than zero")]
    ZeroShareScore,
    #[error("share target must not be zero")]
    ZeroShareTarget,
    #[error("share target is easier than the maximum accepted share target")]
    ShareTargetAboveLimit,
    #[error("unsupported Bitcoin work template version {0}")]
    UnsupportedBitcoinWorkTemplateVersion(u16),
    #[error("unsupported miner registration version {0}")]
    UnsupportedMinerRegistrationVersion(u16),
    #[error("legacy miner registration must not carry a registry anchor")]
    UnexpectedMinerRegistryAnchor,
    #[error("Idena-anchored miner registration is missing its registry anchor")]
    MissingMinerRegistryAnchor,
    #[error("miner registry commitment does not match the registration keys and payout policy")]
    MinerRegistryCommitmentMismatch,
    #[error("invalid miner registry anchor: {0}")]
    InvalidMinerRegistryAnchor(String),
    #[error("legacy Bitcoin work template must not carry an assigned share target")]
    UnexpectedAssignedShareTarget,
    #[error("target-bound Bitcoin work template is missing its assigned share target")]
    MissingAssignedShareTarget,
    #[error("legacy or target-bound Bitcoin work template must not carry an Idena block anchor")]
    UnexpectedIdenaBlockAnchor,
    #[error("Idena-anchored Bitcoin work template is missing its block anchor")]
    MissingIdenaBlockAnchor,
    #[error(
        "legacy or target-bound Bitcoin work template must not carry an Idena anchor policy hash"
    )]
    UnexpectedIdenaAnchorPolicyHash,
    #[error("Idena-anchored Bitcoin work template is missing its policy hash")]
    MissingIdenaAnchorPolicyHash,
    #[error("invalid Idena block anchor: {0}")]
    InvalidIdenaBlockAnchor(String),
    #[error("Bitcoin work template must use target-bound version 2")]
    TargetBoundBitcoinWorkTemplateRequired,
    #[error("share target {actual} does not match template-assigned target {expected}")]
    AssignedShareTargetMismatch { expected: String, actual: String },
    #[error("share Bitcoin template hash {actual} does not match header prefix hash {expected}")]
    ShareTemplateHashMismatch { expected: String, actual: String },
    #[error("share nonce {actual} does not match Bitcoin header nonce {expected}")]
    ShareNonceMismatch { expected: String, actual: String },
    #[error("share work hash {actual} does not match recomputed hash {expected}")]
    ShareWorkHashMismatch { expected: String, actual: String },
    #[error("share work hash does not meet target")]
    ShareWorkAboveTarget,
    #[error("share hashrate score delta {actual} does not match target-derived score {expected}")]
    ShareScoreMismatch { expected: Score, actual: Score },
    #[error("share-work binding is required by the active successor policy")]
    MissingShareWorkBinding,
    #[error("share-work binding field {0} does not match the share or work template")]
    ShareWorkBindingMismatch(&'static str),
    #[error("invalid share-work binding: {0}")]
    InvalidShareWorkBinding(#[from] ShareWorkBindingError),
}

#[derive(Debug, Clone, Serialize)]
struct MinerRegistrationSigningPayload {
    #[serde(skip_serializing_if = "is_legacy_miner_registration_version")]
    version: u16,
    miner_id: String,
    idena_address: String,
    btc_payout_script_hex: String,
    claim_owner_pubkey_hex: String,
    mining_pubkey_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_anchor: Option<MinerRegistryAnchorV1>,
}

#[derive(Debug, Clone, Serialize)]
struct MinerRegistryCommitmentPayload {
    schema_version: u16,
    experiment_id: String,
    miner_id: String,
    idena_address: String,
    btc_payout_script_hex: String,
    claim_owner_pubkey_hex: String,
    mining_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct BitcoinWorkTemplateSigningPayload {
    #[serde(skip_serializing_if = "is_legacy_bitcoin_work_template_version")]
    version: u16,
    miner_id: String,
    header_prefix_hex: String,
    template_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    assigned_share_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idena_anchor: Option<IdenaBlockAnchorV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idena_anchor_policy_hash: Option<String>,
    created_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
struct TargetBoundBitcoinWorkTemplateHashPayload {
    version: u16,
    header_prefix_hex: String,
    assigned_share_target: String,
}

#[derive(Debug, Clone, Serialize)]
struct IdenaAnchoredBitcoinWorkTemplateHashPayload {
    version: u16,
    header_prefix_hex: String,
    assigned_share_target: String,
    idena_anchor: IdenaBlockAnchorV1,
    idena_anchor_policy_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct ShareSigningPayload {
    miner_id: String,
    bitcoin_header_hex: String,
    bitcoin_template_hash: String,
    nonce_hex: String,
    work_hash: String,
    target: String,
    idena_snapshot_id: String,
    idena_snapshot_proof_root: String,
    hashrate_score_delta: Score,
    parent_share_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    work_binding: Option<ShareWorkBindingV1>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotVoteSigningPayload {
    voter_miner_id: String,
    snapshot_day: String,
    idena_height: u64,
    score_root: String,
}

impl MinerRegistration {
    pub fn normalized(mut self) -> Self {
        self.miner_id = self.miner_id.to_ascii_lowercase();
        self.idena_address = self.idena_address.to_ascii_lowercase();
        self.btc_payout_script_hex = self.btc_payout_script_hex.to_ascii_lowercase();
        self.claim_owner_pubkey_hex = self.claim_owner_pubkey_hex.to_ascii_lowercase();
        self.mining_pubkey_hex = self.mining_pubkey_hex.to_ascii_lowercase();
        self.registry_anchor = self.registry_anchor.map(MinerRegistryAnchorV1::normalized);
        self.idena_signature_hex = self.idena_signature_hex.to_ascii_lowercase();
        self.mining_signature_hex = self.mining_signature_hex.to_ascii_lowercase();
        self
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let tag = if self.version == LEGACY_MINER_REGISTRATION_VERSION {
            b"POHW1_MINER_REGISTRATION".as_slice()
        } else {
            b"POHW2_MINER_REGISTRATION".as_slice()
        };
        sha256_tagged(
            tag,
            &canonical_json(&MinerRegistrationSigningPayload {
                version: self.version,
                miner_id: self.miner_id.to_ascii_lowercase(),
                idena_address: self.idena_address.to_ascii_lowercase(),
                btc_payout_script_hex: self.btc_payout_script_hex.to_ascii_lowercase(),
                claim_owner_pubkey_hex: self.claim_owner_pubkey_hex.to_ascii_lowercase(),
                mining_pubkey_hex: self.mining_pubkey_hex.to_ascii_lowercase(),
                registry_anchor: self
                    .registry_anchor
                    .clone()
                    .map(MinerRegistryAnchorV1::normalized),
            }),
        )
    }

    pub fn registry_commitment_hash(&self, experiment_id: &str) -> Result<String, SharechainError> {
        let experiment_id = experiment_id.to_ascii_lowercase();
        validate_experiment_id(&experiment_id)
            .map_err(|err| SharechainError::InvalidMinerRegistryAnchor(err.to_string()))?;
        Ok(hash_hex(sha256_tagged(
            b"POHW_MINER_REGISTRY_COMMITMENT_V1",
            &canonical_json(&MinerRegistryCommitmentPayload {
                schema_version: 1,
                experiment_id,
                miner_id: self.miner_id.to_ascii_lowercase(),
                idena_address: self.idena_address.to_ascii_lowercase(),
                btc_payout_script_hex: self.btc_payout_script_hex.to_ascii_lowercase(),
                claim_owner_pubkey_hex: self.claim_owner_pubkey_hex.to_ascii_lowercase(),
                mining_pubkey_hex: self.mining_pubkey_hex.to_ascii_lowercase(),
            }),
        )))
    }

    pub fn attach_registry_anchor(
        mut self,
        anchor: MinerRegistryAnchorV1,
    ) -> Result<Self, SharechainError> {
        let anchor = anchor.normalized();
        anchor
            .validate()
            .map_err(|err| SharechainError::InvalidMinerRegistryAnchor(err.to_string()))?;
        let expected = self.registry_commitment_hash(&anchor.experiment_id)?;
        if expected != anchor.registration_commitment {
            return Err(SharechainError::MinerRegistryCommitmentMismatch);
        }
        self.version = IDENA_ANCHORED_MINER_REGISTRATION_VERSION;
        self.registry_anchor = Some(anchor);
        Ok(self)
    }

    pub fn require_registry_anchor(&self) -> Result<&MinerRegistryAnchorV1, SharechainError> {
        self.validate_registry_anchor()?;
        self.registry_anchor
            .as_ref()
            .ok_or(SharechainError::MissingMinerRegistryAnchor)
    }

    fn validate_registry_anchor(&self) -> Result<(), SharechainError> {
        match self.version {
            LEGACY_MINER_REGISTRATION_VERSION => {
                if self.registry_anchor.is_some() {
                    return Err(SharechainError::UnexpectedMinerRegistryAnchor);
                }
            }
            IDENA_ANCHORED_MINER_REGISTRATION_VERSION => {
                let anchor = self
                    .registry_anchor
                    .as_ref()
                    .ok_or(SharechainError::MissingMinerRegistryAnchor)?;
                anchor
                    .validate()
                    .map_err(|err| SharechainError::InvalidMinerRegistryAnchor(err.to_string()))?;
                if self.registry_commitment_hash(&anchor.experiment_id)?
                    != anchor.registration_commitment
                {
                    return Err(SharechainError::MinerRegistryCommitmentMismatch);
                }
            }
            version => {
                return Err(SharechainError::UnsupportedMinerRegistrationVersion(
                    version,
                ));
            }
        }
        Ok(())
    }

    pub fn idena_ownership_challenge(&self) -> String {
        format!(
            "signin-pohw1-miner-registration-{}",
            hex::encode(self.signing_hash())
        )
    }

    pub fn verify_idena_ownership_signature(&self) -> Result<(), SharechainError> {
        let recovered_address = recover_idena_signin_address(
            &self.idena_ownership_challenge(),
            &self.idena_signature_hex,
        )?;
        let claimed_address = self.idena_address.to_ascii_lowercase();
        if recovered_address != claimed_address {
            return Err(SharechainError::IdenaAddressSignatureMismatch {
                claimed_address,
                recovered_address,
            });
        }
        Ok(())
    }

    pub fn verify_mining_signature(&self) -> Result<(), SharechainError> {
        validate_miner_id("miner_id", &self.miner_id)?;
        validate_idena_address(&self.idena_address)?;
        self.validate_registry_anchor()?;
        decode_recoverable_idena_signature(&self.idena_signature_hex)
            .map_err(SharechainError::InvalidIdenaSignature)?;
        validate_direct_payout_script(&self.btc_payout_script_hex)?;
        XOnlyPublicKey::from_str(&self.claim_owner_pubkey_hex.to_ascii_lowercase())
            .map_err(|err| SharechainError::InvalidClaimOwnerPubkey(err.to_string()))?;
        verify_mining_signature(
            &self.mining_pubkey_hex,
            &self.mining_signature_hex,
            self.signing_hash(),
        )
    }
}

impl BitcoinWorkTemplate {
    pub fn normalized(mut self) -> Self {
        self.miner_id = self.miner_id.to_ascii_lowercase();
        self.header_prefix_hex = self.header_prefix_hex.to_ascii_lowercase();
        self.template_hash = self.template_hash.to_ascii_lowercase();
        self.assigned_share_target = self
            .assigned_share_target
            .map(|target| target.to_ascii_lowercase());
        self.idena_anchor = self.idena_anchor.map(IdenaBlockAnchorV1::normalized);
        self.idena_anchor_policy_hash = self
            .idena_anchor_policy_hash
            .map(|hash| hash.to_ascii_lowercase());
        self.mining_signature_hex = self.mining_signature_hex.to_ascii_lowercase();
        self
    }

    pub fn new_unsigned(
        miner_id: impl Into<String>,
        header_prefix_hex: impl Into<String>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header_prefix_hex = header_prefix_hex.into();
        let template_hash = Self::template_hash_for_header_prefix_hex(&header_prefix_hex)?;
        Ok(Self {
            version: LEGACY_BITCOIN_WORK_TEMPLATE_VERSION,
            miner_id: miner_id.into(),
            header_prefix_hex,
            template_hash,
            assigned_share_target: None,
            idena_anchor: None,
            idena_anchor_policy_hash: None,
            created_at_unix,
            mining_signature_hex: String::new(),
        })
    }

    pub fn new_target_bound_unsigned(
        miner_id: impl Into<String>,
        header_prefix_hex: impl Into<String>,
        assigned_share_target: impl Into<String>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header_prefix_hex = header_prefix_hex.into();
        let assigned_share_target = assigned_share_target.into().to_ascii_lowercase();
        validate_share_target_hex(&assigned_share_target)?;
        let template_hash = Self::target_bound_template_hash_for_header_prefix_hex(
            &header_prefix_hex,
            &assigned_share_target,
        )?;
        Ok(Self {
            version: TARGET_BOUND_BITCOIN_WORK_TEMPLATE_VERSION,
            miner_id: miner_id.into(),
            header_prefix_hex,
            template_hash,
            assigned_share_target: Some(assigned_share_target),
            idena_anchor: None,
            idena_anchor_policy_hash: None,
            created_at_unix,
            mining_signature_hex: String::new(),
        })
    }

    pub fn new_idena_anchored_target_bound_unsigned(
        miner_id: impl Into<String>,
        header_prefix_hex: impl Into<String>,
        assigned_share_target: impl Into<String>,
        idena_anchor: IdenaBlockAnchorV1,
        idena_anchor_policy_hash: impl Into<String>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header_prefix_hex = header_prefix_hex.into();
        let assigned_share_target = assigned_share_target.into().to_ascii_lowercase();
        let idena_anchor = idena_anchor.normalized();
        let idena_anchor_policy_hash = idena_anchor_policy_hash.into().to_ascii_lowercase();
        validate_share_target_hex(&assigned_share_target)?;
        validate_hex_32("idena_anchor_policy_hash", &idena_anchor_policy_hash)?;
        idena_anchor
            .validate()
            .map_err(|err| SharechainError::InvalidIdenaBlockAnchor(err.to_string()))?;
        let template_hash = Self::idena_anchored_template_hash_for_header_prefix_hex(
            &header_prefix_hex,
            &assigned_share_target,
            &idena_anchor,
            &idena_anchor_policy_hash,
        )?;
        Ok(Self {
            version: IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION,
            miner_id: miner_id.into(),
            header_prefix_hex,
            template_hash,
            assigned_share_target: Some(assigned_share_target),
            idena_anchor: Some(idena_anchor),
            idena_anchor_policy_hash: Some(idena_anchor_policy_hash),
            created_at_unix,
            mining_signature_hex: String::new(),
        })
    }

    pub fn from_bitcoin_header_hex(
        miner_id: impl Into<String>,
        bitcoin_header_hex: impl AsRef<str>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header = decode_bitcoin_header_hex(bitcoin_header_hex.as_ref())?;
        Self::new_unsigned(
            miner_id,
            hex::encode(&header[..BITCOIN_TEMPLATE_PREFIX_BYTES]),
            created_at_unix,
        )
    }

    pub fn from_bitcoin_header_hex_with_share_target(
        miner_id: impl Into<String>,
        bitcoin_header_hex: impl AsRef<str>,
        assigned_share_target: impl Into<String>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header = decode_bitcoin_header_hex(bitcoin_header_hex.as_ref())?;
        Self::new_target_bound_unsigned(
            miner_id,
            hex::encode(&header[..BITCOIN_TEMPLATE_PREFIX_BYTES]),
            assigned_share_target,
            created_at_unix,
        )
    }

    pub fn from_bitcoin_header_hex_with_share_target_and_idena_anchor(
        miner_id: impl Into<String>,
        bitcoin_header_hex: impl AsRef<str>,
        assigned_share_target: impl Into<String>,
        idena_anchor: IdenaBlockAnchorV1,
        idena_anchor_policy_hash: impl Into<String>,
        created_at_unix: i64,
    ) -> Result<Self, SharechainError> {
        let header = decode_bitcoin_header_hex(bitcoin_header_hex.as_ref())?;
        Self::new_idena_anchored_target_bound_unsigned(
            miner_id,
            hex::encode(&header[..BITCOIN_TEMPLATE_PREFIX_BYTES]),
            assigned_share_target,
            idena_anchor,
            idena_anchor_policy_hash,
            created_at_unix,
        )
    }

    pub fn template_hash_for_header_prefix_hex(
        header_prefix_hex: &str,
    ) -> Result<String, SharechainError> {
        let header_prefix = decode_bitcoin_header_prefix_hex(header_prefix_hex)?;
        Ok(hash_hex(sha256_tagged(
            b"POHW1_BTC_TEMPLATE",
            &header_prefix,
        )))
    }

    pub fn target_bound_template_hash_for_header_prefix_hex(
        header_prefix_hex: &str,
        assigned_share_target: &str,
    ) -> Result<String, SharechainError> {
        let header_prefix = decode_bitcoin_header_prefix_hex(header_prefix_hex)?;
        let assigned_share_target = assigned_share_target.to_ascii_lowercase();
        validate_share_target_hex(&assigned_share_target)?;
        Ok(hash_hex(sha256_tagged(
            b"POHW2_BTC_TEMPLATE",
            &canonical_json(&TargetBoundBitcoinWorkTemplateHashPayload {
                version: TARGET_BOUND_BITCOIN_WORK_TEMPLATE_VERSION,
                header_prefix_hex: hex::encode(header_prefix),
                assigned_share_target,
            }),
        )))
    }

    pub fn idena_anchored_template_hash_for_header_prefix_hex(
        header_prefix_hex: &str,
        assigned_share_target: &str,
        idena_anchor: &IdenaBlockAnchorV1,
        idena_anchor_policy_hash: &str,
    ) -> Result<String, SharechainError> {
        let header_prefix = decode_bitcoin_header_prefix_hex(header_prefix_hex)?;
        let assigned_share_target = assigned_share_target.to_ascii_lowercase();
        let idena_anchor_policy_hash = idena_anchor_policy_hash.to_ascii_lowercase();
        validate_share_target_hex(&assigned_share_target)?;
        validate_hex_32("idena_anchor_policy_hash", &idena_anchor_policy_hash)?;
        let idena_anchor = idena_anchor.clone().normalized();
        idena_anchor
            .validate()
            .map_err(|err| SharechainError::InvalidIdenaBlockAnchor(err.to_string()))?;
        Ok(hash_hex(sha256_tagged(
            b"POHW3_BTC_TEMPLATE",
            &canonical_json(&IdenaAnchoredBitcoinWorkTemplateHashPayload {
                version: IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION,
                header_prefix_hex: hex::encode(header_prefix),
                assigned_share_target,
                idena_anchor,
                idena_anchor_policy_hash,
            }),
        )))
    }

    pub fn verify_template_hash(&self) -> Result<(), SharechainError> {
        validate_miner_id("miner_id", &self.miner_id)?;
        if self.created_at_unix <= 0 {
            return Err(SharechainError::InvalidField {
                field: "created_at_unix".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        let expected = match self.version {
            LEGACY_BITCOIN_WORK_TEMPLATE_VERSION => {
                if self.assigned_share_target.is_some() {
                    return Err(SharechainError::UnexpectedAssignedShareTarget);
                }
                if self.idena_anchor.is_some() {
                    return Err(SharechainError::UnexpectedIdenaBlockAnchor);
                }
                if self.idena_anchor_policy_hash.is_some() {
                    return Err(SharechainError::UnexpectedIdenaAnchorPolicyHash);
                }
                Self::template_hash_for_header_prefix_hex(&self.header_prefix_hex)?
            }
            TARGET_BOUND_BITCOIN_WORK_TEMPLATE_VERSION => {
                if self.idena_anchor.is_some() {
                    return Err(SharechainError::UnexpectedIdenaBlockAnchor);
                }
                if self.idena_anchor_policy_hash.is_some() {
                    return Err(SharechainError::UnexpectedIdenaAnchorPolicyHash);
                }
                let assigned_share_target = self
                    .assigned_share_target
                    .as_deref()
                    .ok_or(SharechainError::MissingAssignedShareTarget)?;
                Self::target_bound_template_hash_for_header_prefix_hex(
                    &self.header_prefix_hex,
                    assigned_share_target,
                )?
            }
            IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION => {
                let assigned_share_target = self
                    .assigned_share_target
                    .as_deref()
                    .ok_or(SharechainError::MissingAssignedShareTarget)?;
                let idena_anchor = self
                    .idena_anchor
                    .as_ref()
                    .ok_or(SharechainError::MissingIdenaBlockAnchor)?;
                let idena_anchor_policy_hash = self
                    .idena_anchor_policy_hash
                    .as_deref()
                    .ok_or(SharechainError::MissingIdenaAnchorPolicyHash)?;
                Self::idena_anchored_template_hash_for_header_prefix_hex(
                    &self.header_prefix_hex,
                    assigned_share_target,
                    idena_anchor,
                    idena_anchor_policy_hash,
                )?
            }
            version => {
                return Err(SharechainError::UnsupportedBitcoinWorkTemplateVersion(
                    version,
                ));
            }
        };
        if !self.template_hash.eq_ignore_ascii_case(&expected) {
            return Err(SharechainError::ShareTemplateHashMismatch {
                expected,
                actual: self.template_hash.to_ascii_lowercase(),
            });
        }
        Ok(())
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        sha256_tagged(
            b"POHW1_BITCOIN_WORK_TEMPLATE",
            &canonical_json(&BitcoinWorkTemplateSigningPayload {
                version: self.version,
                miner_id: self.miner_id.to_ascii_lowercase(),
                header_prefix_hex: self.header_prefix_hex.to_ascii_lowercase(),
                template_hash: self.template_hash.to_ascii_lowercase(),
                assigned_share_target: self
                    .assigned_share_target
                    .as_ref()
                    .map(|target| target.to_ascii_lowercase()),
                idena_anchor: self
                    .idena_anchor
                    .clone()
                    .map(IdenaBlockAnchorV1::normalized),
                idena_anchor_policy_hash: self
                    .idena_anchor_policy_hash
                    .as_ref()
                    .map(|hash| hash.to_ascii_lowercase()),
                created_at_unix: self.created_at_unix,
            }),
        )
    }

    pub fn is_target_bound(&self) -> bool {
        matches!(
            self.version,
            TARGET_BOUND_BITCOIN_WORK_TEMPLATE_VERSION
                | IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION
        ) && self.assigned_share_target.is_some()
    }

    pub fn is_idena_anchored(&self) -> bool {
        self.version == IDENA_ANCHORED_BITCOIN_WORK_TEMPLATE_VERSION
            && self.idena_anchor.is_some()
            && self.idena_anchor_policy_hash.is_some()
    }

    pub fn bitcoin_header_version(&self) -> Result<u32, SharechainError> {
        let prefix = decode_bitcoin_header_prefix_hex(&self.header_prefix_hex)?;
        Ok(u32::from_le_bytes(prefix[..4].try_into().expect(
            "validated Bitcoin header prefix always contains a version",
        )))
    }

    pub fn require_idena_anchor(&self) -> Result<&IdenaBlockAnchorV1, SharechainError> {
        self.verify_template_hash()?;
        if !self.is_idena_anchored() {
            return Err(SharechainError::MissingIdenaBlockAnchor);
        }
        self.idena_anchor
            .as_ref()
            .ok_or(SharechainError::MissingIdenaBlockAnchor)
    }

    pub fn require_idena_anchor_policy_hash(&self) -> Result<&str, SharechainError> {
        self.verify_template_hash()?;
        if !self.is_idena_anchored() {
            return Err(SharechainError::MissingIdenaAnchorPolicyHash);
        }
        self.idena_anchor_policy_hash
            .as_deref()
            .ok_or(SharechainError::MissingIdenaAnchorPolicyHash)
    }

    pub fn require_target_bound(&self) -> Result<(), SharechainError> {
        self.verify_template_hash()?;
        if !self.is_target_bound() {
            return Err(SharechainError::TargetBoundBitcoinWorkTemplateRequired);
        }
        Ok(())
    }

    pub fn verify_assigned_share_target(
        &self,
        claimed_target: &str,
    ) -> Result<(), SharechainError> {
        self.verify_template_hash()?;
        if self.version == LEGACY_BITCOIN_WORK_TEMPLATE_VERSION {
            return Ok(());
        }
        let expected = self
            .assigned_share_target
            .as_deref()
            .ok_or(SharechainError::MissingAssignedShareTarget)?
            .to_ascii_lowercase();
        let actual = claimed_target.to_ascii_lowercase();
        validate_share_target_hex(&actual)?;
        if actual != expected {
            return Err(SharechainError::AssignedShareTargetMismatch { expected, actual });
        }
        Ok(())
    }

    pub fn verify_mining_signature(&self, mining_pubkey_hex: &str) -> Result<(), SharechainError> {
        self.verify_template_hash()?;
        verify_mining_signature(
            mining_pubkey_hex,
            &self.mining_signature_hex,
            self.signing_hash(),
        )
    }
}

impl Share {
    pub fn share_hash(&self) -> String {
        SharechainMessage::Share(self.clone()).message_hash()
    }

    pub fn normalized(mut self) -> Self {
        self.miner_id = self.miner_id.to_ascii_lowercase();
        self.bitcoin_header_hex = self.bitcoin_header_hex.to_ascii_lowercase();
        self.bitcoin_template_hash = self.bitcoin_template_hash.to_ascii_lowercase();
        self.nonce_hex = self.nonce_hex.to_ascii_lowercase();
        self.work_hash = self.work_hash.to_ascii_lowercase();
        self.target = self.target.to_ascii_lowercase();
        self.idena_snapshot_id = self.idena_snapshot_id.to_ascii_lowercase();
        self.idena_snapshot_proof_root = self.idena_snapshot_proof_root.to_ascii_lowercase();
        self.parent_share_hash = self.parent_share_hash.to_ascii_lowercase();
        self.work_binding = self
            .work_binding
            .map(|binding| Box::new((*binding).normalized()));
        self.mining_signature_hex = self.mining_signature_hex.to_ascii_lowercase();
        self
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        sha256_tagged(
            b"POHW1_SHARE",
            &canonical_json(&ShareSigningPayload {
                miner_id: self.miner_id.to_ascii_lowercase(),
                bitcoin_header_hex: self.bitcoin_header_hex.to_ascii_lowercase(),
                bitcoin_template_hash: self.bitcoin_template_hash.to_ascii_lowercase(),
                nonce_hex: self.nonce_hex.to_ascii_lowercase(),
                work_hash: self.work_hash.to_ascii_lowercase(),
                target: self.target.to_ascii_lowercase(),
                idena_snapshot_id: self.idena_snapshot_id.to_ascii_lowercase(),
                idena_snapshot_proof_root: self.idena_snapshot_proof_root.to_ascii_lowercase(),
                hashrate_score_delta: self.hashrate_score_delta,
                parent_share_hash: self.parent_share_hash.to_ascii_lowercase(),
                work_binding: self
                    .work_binding
                    .clone()
                    .map(|binding| (*binding).normalized()),
            }),
        )
    }

    pub fn recomputed_bitcoin_template_hash(&self) -> Result<String, SharechainError> {
        BitcoinWorkTemplate::template_hash_for_header_prefix_hex(&self.bitcoin_header_prefix_hex()?)
    }

    pub fn recomputed_target_bound_bitcoin_template_hash(&self) -> Result<String, SharechainError> {
        BitcoinWorkTemplate::target_bound_template_hash_for_header_prefix_hex(
            &self.bitcoin_header_prefix_hex()?,
            &self.target,
        )
    }

    pub fn recomputed_idena_anchored_bitcoin_template_hash(
        &self,
        anchor: &IdenaBlockAnchorV1,
        policy_hash: &str,
    ) -> Result<String, SharechainError> {
        BitcoinWorkTemplate::idena_anchored_template_hash_for_header_prefix_hex(
            &self.bitcoin_header_prefix_hex()?,
            &self.target,
            anchor,
            policy_hash,
        )
    }

    pub fn bitcoin_header_prefix_hex(&self) -> Result<String, SharechainError> {
        let header = decode_bitcoin_header_hex(&self.bitcoin_header_hex)?;
        Ok(hex::encode(&header[..BITCOIN_TEMPLATE_PREFIX_BYTES]))
    }

    pub fn recomputed_nonce_hex(&self) -> Result<String, SharechainError> {
        let header = decode_bitcoin_header_hex(&self.bitcoin_header_hex)?;
        Ok(hex::encode(
            &header[BITCOIN_TEMPLATE_PREFIX_BYTES..BITCOIN_HEADER_BYTES],
        ))
    }

    pub fn recomputed_work_hash(&self) -> Result<String, SharechainError> {
        let header = decode_bitcoin_header_hex(&self.bitcoin_header_hex)?;
        Ok(sha256d::Hash::hash(&header).to_string())
    }

    pub fn verify_mining_signature(&self, mining_pubkey_hex: &str) -> Result<(), SharechainError> {
        self.validate_fields()?;
        self.verify_bitcoin_header_binding()?;
        self.verify_nonce_binding()?;
        self.verify_work_score()?;
        self.verify_present_work_binding_fields()?;
        verify_mining_signature(
            mining_pubkey_hex,
            &self.mining_signature_hex,
            self.signing_hash(),
        )
    }

    pub fn verify_mining_signature_for_template(
        &self,
        mining_pubkey_hex: &str,
        template: &BitcoinWorkTemplate,
    ) -> Result<(), SharechainError> {
        self.validate_fields()?;
        template.verify_template_hash()?;
        if !self
            .bitcoin_template_hash
            .eq_ignore_ascii_case(&template.template_hash)
        {
            return Err(SharechainError::ShareTemplateHashMismatch {
                expected: template.template_hash.to_ascii_lowercase(),
                actual: self.bitcoin_template_hash.to_ascii_lowercase(),
            });
        }
        if !self
            .bitcoin_header_prefix_hex()?
            .eq_ignore_ascii_case(&template.header_prefix_hex)
        {
            return Err(SharechainError::ShareTemplateHashMismatch {
                expected: template.template_hash.to_ascii_lowercase(),
                actual: self.bitcoin_template_hash.to_ascii_lowercase(),
            });
        }
        template.verify_assigned_share_target(&self.target)?;
        self.verify_nonce_binding()?;
        self.verify_work_score()?;
        self.verify_present_work_binding_for_template(template)?;
        verify_mining_signature(
            mining_pubkey_hex,
            &self.mining_signature_hex,
            self.signing_hash(),
        )
    }

    fn validate_fields(&self) -> Result<(), SharechainError> {
        validate_miner_id("miner_id", &self.miner_id)?;
        validate_bitcoin_header_hex(&self.bitcoin_header_hex)?;
        validate_hex_32("bitcoin_template_hash", &self.bitcoin_template_hash)?;
        validate_hex_exact_len("nonce_hex", &self.nonce_hex, BITCOIN_NONCE_HEX_LEN)?;
        validate_hex_32("work_hash", &self.work_hash)?;
        validate_hex_32("target", &self.target)?;
        validate_snapshot_id(&self.idena_snapshot_id)?;
        validate_hex_32("idena_snapshot_proof_root", &self.idena_snapshot_proof_root)?;
        validate_hex_32("parent_share_hash", &self.parent_share_hash)?;
        if self.hashrate_score_delta == 0 {
            return Err(SharechainError::ZeroShareScore);
        }
        Ok(())
    }

    pub fn verify_required_work_binding(
        &self,
        template: &BitcoinWorkTemplate,
        policy: &ShareWorkBindingPolicyV1,
    ) -> Result<(), SharechainError> {
        self.verify_present_work_binding_for_template(template)?;
        let binding = self
            .work_binding
            .as_ref()
            .ok_or(SharechainError::MissingShareWorkBinding)?;
        binding.verify_policy(policy)?;
        Ok(())
    }

    fn verify_present_work_binding_fields(&self) -> Result<(), SharechainError> {
        let Some(binding) = self.work_binding.as_ref() else {
            return Ok(());
        };
        binding.validate_commitment_fields()?;
        if !binding.miner_id.eq_ignore_ascii_case(&self.miner_id) {
            return Err(SharechainError::ShareWorkBindingMismatch("miner_id"));
        }
        if !binding
            .assigned_share_target
            .eq_ignore_ascii_case(&self.target)
        {
            return Err(SharechainError::ShareWorkBindingMismatch(
                "assigned_share_target",
            ));
        }
        if !binding
            .parent_share_hash
            .eq_ignore_ascii_case(&self.parent_share_hash)
        {
            return Err(SharechainError::ShareWorkBindingMismatch(
                "parent_share_hash",
            ));
        }
        if !binding
            .idena_snapshot_id
            .eq_ignore_ascii_case(&self.idena_snapshot_id)
        {
            return Err(SharechainError::ShareWorkBindingMismatch(
                "idena_snapshot_id",
            ));
        }
        if !binding
            .idena_snapshot_proof_root
            .eq_ignore_ascii_case(&self.idena_snapshot_proof_root)
        {
            return Err(SharechainError::ShareWorkBindingMismatch(
                "idena_snapshot_proof_root",
            ));
        }
        binding.verify_header_commitment(&self.bitcoin_header_hex)?;
        Ok(())
    }

    fn verify_present_work_binding_for_template(
        &self,
        template: &BitcoinWorkTemplate,
    ) -> Result<(), SharechainError> {
        self.verify_present_work_binding_fields()?;
        let Some(binding) = self.work_binding.as_ref() else {
            return Ok(());
        };
        let anchor = template
            .idena_anchor
            .as_ref()
            .ok_or(SharechainError::ShareWorkBindingMismatch("idena_anchor"))?;
        if &binding.idena_anchor != anchor {
            return Err(SharechainError::ShareWorkBindingMismatch("idena_anchor"));
        }
        let template_policy_hash = template.idena_anchor_policy_hash.as_deref().ok_or(
            SharechainError::ShareWorkBindingMismatch("idena_anchor_policy_hash"),
        )?;
        if !binding
            .idena_anchor_policy_hash
            .eq_ignore_ascii_case(template_policy_hash)
        {
            return Err(SharechainError::ShareWorkBindingMismatch(
                "idena_anchor_policy_hash",
            ));
        }
        Ok(())
    }

    pub fn expected_hashrate_score_delta(&self) -> Result<Score, SharechainError> {
        Self::expected_hashrate_score_delta_for_target(&self.target)
    }

    pub fn expected_hashrate_score_delta_for_target(
        target_hex: &str,
    ) -> Result<Score, SharechainError> {
        share_score_from_target(&decode_hex_32("target", target_hex)?)
    }

    fn verify_work_score(&self) -> Result<(), SharechainError> {
        let expected_work_hash = self.recomputed_work_hash()?;
        if !self.work_hash.eq_ignore_ascii_case(&expected_work_hash) {
            return Err(SharechainError::ShareWorkHashMismatch {
                expected: expected_work_hash,
                actual: self.work_hash.to_ascii_lowercase(),
            });
        }
        let work_hash = decode_hex_32("work_hash", &self.work_hash)?;
        let target = decode_hex_32("target", &self.target)?;
        if target.iter().all(|byte| *byte == 0) {
            return Err(SharechainError::ZeroShareTarget);
        }
        if target > max_share_target_bytes() {
            return Err(SharechainError::ShareTargetAboveLimit);
        }
        if work_hash > target {
            return Err(SharechainError::ShareWorkAboveTarget);
        }
        let expected = share_score_from_target(&target)?;
        if self.hashrate_score_delta != expected {
            return Err(SharechainError::ShareScoreMismatch {
                expected,
                actual: self.hashrate_score_delta,
            });
        }
        Ok(())
    }

    fn verify_nonce_binding(&self) -> Result<(), SharechainError> {
        let expected_nonce = self.recomputed_nonce_hex()?;
        if !self.nonce_hex.eq_ignore_ascii_case(&expected_nonce) {
            return Err(SharechainError::ShareNonceMismatch {
                expected: expected_nonce,
                actual: self.nonce_hex.to_ascii_lowercase(),
            });
        }
        Ok(())
    }

    fn verify_bitcoin_header_binding(&self) -> Result<(), SharechainError> {
        let legacy_template_hash = self.recomputed_bitcoin_template_hash()?;
        let target_bound_template_hash = self.recomputed_target_bound_bitcoin_template_hash()?;
        if !self
            .bitcoin_template_hash
            .eq_ignore_ascii_case(&legacy_template_hash)
            && !self
                .bitcoin_template_hash
                .eq_ignore_ascii_case(&target_bound_template_hash)
        {
            return Err(SharechainError::ShareTemplateHashMismatch {
                expected: target_bound_template_hash,
                actual: self.bitcoin_template_hash.to_ascii_lowercase(),
            });
        }
        Ok(())
    }
}

impl SnapshotVote {
    pub fn normalized(mut self) -> Self {
        self.voter_miner_id = self.voter_miner_id.to_ascii_lowercase();
        self.score_root = self.score_root.to_ascii_lowercase();
        self.signature_hex = self.signature_hex.to_ascii_lowercase();
        self
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        sha256_tagged(
            b"POHW1_SNAPSHOT_VOTE",
            &canonical_json(&SnapshotVoteSigningPayload {
                voter_miner_id: self.voter_miner_id.to_ascii_lowercase(),
                snapshot_day: self.snapshot_day.clone(),
                idena_height: self.idena_height,
                score_root: self.score_root.to_ascii_lowercase(),
            }),
        )
    }

    pub fn verify_mining_signature(&self, mining_pubkey_hex: &str) -> Result<(), SharechainError> {
        validate_miner_id("voter_miner_id", &self.voter_miner_id)?;
        NaiveDate::parse_from_str(&self.snapshot_day, "%Y-%m-%d").map_err(|err| {
            SharechainError::InvalidField {
                field: "snapshot_day".to_string(),
                reason: err.to_string(),
            }
        })?;
        if self.idena_height == 0 {
            return Err(SharechainError::InvalidField {
                field: "idena_height".to_string(),
                reason: "height must be greater than zero".to_string(),
            });
        }
        validate_hex_32("score_root", &self.score_root)?;
        verify_mining_signature(mining_pubkey_hex, &self.signature_hex, self.signing_hash())
    }
}

impl SharechainMessage {
    pub fn message_hash(&self) -> String {
        hash_hex(sha256_tagged(
            b"POHW1_SHARECHAIN_MESSAGE",
            &canonical_json(&self.clone().normalized_for_hash()),
        ))
    }

    pub fn normalized(self) -> Self {
        self.normalized_for_hash()
    }

    fn normalized_for_hash(mut self) -> Self {
        match &mut self {
            SharechainMessage::MinerRegistration(registration) => {
                *registration = registration.clone().normalized();
            }
            SharechainMessage::BitcoinWorkTemplate(template) => {
                *template = template.clone().normalized();
            }
            SharechainMessage::Share(share) => {
                *share = share.clone().normalized();
            }
            SharechainMessage::SharechainCheckpoint(checkpoint) => {
                *checkpoint = checkpoint.clone().normalized();
            }
            SharechainMessage::SnapshotVote(vote) => {
                *vote = vote.clone().normalized();
            }
            SharechainMessage::PayoutSchedule(schedule) => {
                for output in &mut schedule.direct_outputs {
                    output.miner_id = output.miner_id.to_ascii_lowercase();
                    output.btc_payout_script_hex =
                        output.btc_payout_script_hex.to_ascii_lowercase();
                }
                for allocation in &mut schedule.vault_allocations {
                    allocation.miner_id = allocation.miner_id.to_ascii_lowercase();
                    allocation.claim_owner_id = allocation.claim_owner_id.to_ascii_lowercase();
                }
                schedule.payout_root = schedule.payout_root.to_ascii_lowercase();
            }
            SharechainMessage::WithdrawalRequest(request) => {
                *request = request.clone().normalized();
            }
            SharechainMessage::WithdrawalBatch(batch) => {
                *batch = batch.clone().normalized();
            }
            SharechainMessage::PohwCommitment(commitment) => {
                *commitment = commitment.clone().normalized();
            }
        }
        self
    }
}

fn verify_mining_signature(
    mining_pubkey_hex: &str,
    signature_hex: &str,
    signing_hash: [u8; 32],
) -> Result<(), SharechainError> {
    if signature_hex.is_empty() {
        return Err(SharechainError::MissingMiningSignature);
    }
    if signature_hex.len() != SCHNORR_SIGNATURE_HEX_LEN
        || !signature_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SharechainError::InvalidMiningSignature(format!(
            "signature must be {SCHNORR_SIGNATURE_HEX_LEN} hex characters"
        )));
    }
    let mining_pubkey = XOnlyPublicKey::from_str(&mining_pubkey_hex.to_ascii_lowercase())
        .map_err(|err| SharechainError::InvalidMiningPubkey(err.to_string()))?;
    let signature_bytes = hex::decode(signature_hex.to_ascii_lowercase())
        .map_err(|err| SharechainError::InvalidMiningSignature(err.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| SharechainError::InvalidMiningSignature(err.to_string()))?;
    let message = Message::from_digest(signing_hash);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &mining_pubkey)
        .map_err(|err| SharechainError::InvalidMiningSignature(err.to_string()))
}

fn recover_idena_signin_address(
    challenge: &str,
    signature_hex: &str,
) -> Result<String, SharechainError> {
    let signature_bytes = decode_recoverable_idena_signature(signature_hex)
        .map_err(SharechainError::InvalidIdenaSignature)?;
    let recovery_id =
        idena_recovery_id(signature_bytes[64]).map_err(SharechainError::InvalidIdenaSignature)?;
    let signature = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)
        .map_err(|err| SharechainError::InvalidIdenaSignature(err.to_string()))?;
    let message = Message::from_digest(idena_signin_hash(challenge));
    let pubkey = Secp256k1::verification_only()
        .recover_ecdsa(&message, &signature)
        .map_err(|err| SharechainError::InvalidIdenaSignature(err.to_string()))?;
    Ok(idena_address_from_pubkey(&pubkey))
}

fn decode_recoverable_idena_signature(signature_hex: &str) -> Result<[u8; 65], String> {
    let normalized = signature_hex
        .strip_prefix("0x")
        .unwrap_or(signature_hex)
        .to_ascii_lowercase();
    if normalized.len() != IDENA_RECOVERABLE_SIGNATURE_HEX_LEN
        || !normalized
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "signature must be 65 bytes encoded as {IDENA_RECOVERABLE_SIGNATURE_HEX_LEN} hex characters"
        ));
    }
    let bytes = hex::decode(normalized).map_err(|err| err.to_string())?;
    <[u8; 65]>::try_from(bytes.as_slice())
        .map_err(|_| "signature must be 65 bytes encoded as 130 hex characters".to_string())
}

fn idena_recovery_id(v: u8) -> Result<RecoveryId, String> {
    let id = match v {
        0..=3 => i32::from(v),
        27..=30 => i32::from(v - 27),
        _ => return Err(format!("unsupported recovery id {v}")),
    };
    RecoveryId::from_i32(id).map_err(|err| err.to_string())
}

fn idena_signin_hash(challenge: &str) -> [u8; 32] {
    keccak256(&keccak256(challenge.as_bytes()))
}

fn idena_address_from_pubkey(pubkey: &PublicKey) -> String {
    let serialized = pubkey.serialize_uncompressed();
    let hash = keccak256(&serialized[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn validate_direct_payout_script(script_hex: &str) -> Result<(), SharechainError> {
    if !matches!(
        script_hex.len(),
        P2WPKH_SCRIPT_HEX_LEN | P2TR_SCRIPT_HEX_LEN
    ) || !script_hex
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SharechainError::InvalidPayoutScript(
            "direct payout script must be P2WPKH or P2TR hex".to_string(),
        ));
    }
    let script_bytes = hex::decode(script_hex.to_ascii_lowercase())
        .map_err(|err| SharechainError::InvalidPayoutScript(err.to_string()))?;
    let script = ScriptBuf::from_bytes(script_bytes);
    if script.is_p2wpkh() || script.is_p2tr() {
        Ok(())
    } else {
        Err(SharechainError::InvalidPayoutScript(
            "only P2WPKH and P2TR direct payout scripts are supported".to_string(),
        ))
    }
}

fn validate_miner_id(field: &str, value: &str) -> Result<(), SharechainError> {
    if value.is_empty() || value.len() > MAX_MINER_ID_LEN {
        return Err(SharechainError::InvalidMinerId {
            field: field.to_string(),
            reason: format!("length must be 1..={MAX_MINER_ID_LEN}"),
        });
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SharechainError::InvalidMinerId {
            field: field.to_string(),
            reason: "only ASCII letters, digits, '-', '_', and '.' are allowed".to_string(),
        });
    }
    Ok(())
}

fn validate_idena_address(value: &str) -> Result<(), SharechainError> {
    let Some(hex_part) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return Err(SharechainError::InvalidIdenaAddress(
            "address must start with 0x".to_string(),
        ));
    };
    if hex_part.len() != 40
        || !hex_part
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SharechainError::InvalidIdenaAddress(
            "address must contain 20 bytes encoded as 40 hex characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot_id(value: &str) -> Result<(), SharechainError> {
    if value.is_empty() || value.len() > MAX_SNAPSHOT_ID_LEN {
        return Err(SharechainError::InvalidField {
            field: "idena_snapshot_id".to_string(),
            reason: format!("length must be 1..={MAX_SNAPSHOT_ID_LEN}"),
        });
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SharechainError::InvalidField {
            field: "idena_snapshot_id".to_string(),
            reason: "contains unsupported characters".to_string(),
        });
    }
    Ok(())
}

fn validate_hex_32(field: &str, value: &str) -> Result<(), SharechainError> {
    validate_hex_exact_len(field, value, 64)
}

fn validate_bitcoin_header_hex(value: &str) -> Result<(), SharechainError> {
    validate_hex_exact_len("bitcoin_header_hex", value, BITCOIN_HEADER_HEX_LEN)
}

fn validate_bitcoin_header_prefix_hex(value: &str) -> Result<(), SharechainError> {
    validate_hex_exact_len(
        "header_prefix_hex",
        value,
        BITCOIN_TEMPLATE_PREFIX_BYTES * 2,
    )
}

fn validate_hex_exact_len(
    field: &str,
    value: &str,
    expected_hex_len: usize,
) -> Result<(), SharechainError> {
    if value.len() != expected_hex_len
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SharechainError::InvalidField {
            field: field.to_string(),
            reason: format!(
                "must be {} bytes encoded as {expected_hex_len} hex characters",
                expected_hex_len / 2
            ),
        });
    }
    Ok(())
}

fn decode_hex_32(field: &str, value: &str) -> Result<[u8; 32], SharechainError> {
    validate_hex_32(field, value)?;
    let bytes =
        hex::decode(value.to_ascii_lowercase()).map_err(|err| SharechainError::InvalidField {
            field: field.to_string(),
            reason: err.to_string(),
        })?;
    bytes.try_into().map_err(|_| SharechainError::InvalidField {
        field: field.to_string(),
        reason: "must be exactly 32 bytes".to_string(),
    })
}

fn decode_bitcoin_header_hex(value: &str) -> Result<[u8; BITCOIN_HEADER_BYTES], SharechainError> {
    validate_bitcoin_header_hex(value)?;
    let bytes =
        hex::decode(value.to_ascii_lowercase()).map_err(|err| SharechainError::InvalidField {
            field: "bitcoin_header_hex".to_string(),
            reason: err.to_string(),
        })?;
    bytes.try_into().map_err(|_| SharechainError::InvalidField {
        field: "bitcoin_header_hex".to_string(),
        reason: format!("must be exactly {BITCOIN_HEADER_BYTES} bytes"),
    })
}

fn decode_bitcoin_header_prefix_hex(
    value: &str,
) -> Result<[u8; BITCOIN_TEMPLATE_PREFIX_BYTES], SharechainError> {
    validate_bitcoin_header_prefix_hex(value)?;
    let bytes =
        hex::decode(value.to_ascii_lowercase()).map_err(|err| SharechainError::InvalidField {
            field: "header_prefix_hex".to_string(),
            reason: err.to_string(),
        })?;
    bytes.try_into().map_err(|_| SharechainError::InvalidField {
        field: "header_prefix_hex".to_string(),
        reason: format!("must be exactly {BITCOIN_TEMPLATE_PREFIX_BYTES} bytes"),
    })
}

fn max_share_target_bytes() -> [u8; 32] {
    Target::MAX_ATTAINABLE_REGTEST.to_be_bytes()
}

fn validate_share_target_hex(target_hex: &str) -> Result<(), SharechainError> {
    let target = decode_hex_32("target", target_hex)?;
    if target.iter().all(|byte| *byte == 0) {
        return Err(SharechainError::ZeroShareTarget);
    }
    if target > max_share_target_bytes() {
        return Err(SharechainError::ShareTargetAboveLimit);
    }
    Ok(())
}

fn share_score_from_target(target: &[u8; 32]) -> Result<Score, SharechainError> {
    if target.iter().all(|byte| *byte == 0) {
        return Err(SharechainError::ZeroShareTarget);
    }
    if *target > max_share_target_bytes() {
        return Err(SharechainError::ShareTargetAboveLimit);
    }
    Ok(Target::from_be_bytes(*target).difficulty(Params::REGTEST))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    fn mining_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[11; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    const MAX_SHARE_TARGET_HEX: &str = MAX_ACCEPTED_SHARE_TARGET_HEX;

    fn sign(hash: [u8; 32], keypair: &Keypair) -> String {
        let secp = Secp256k1::new();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
        hex::encode(signature.serialize())
    }

    fn idena_signature(challenge: &str, secret_key: &SecretKey) -> (String, String) {
        let secp = Secp256k1::new();
        let message = Message::from_digest(idena_signin_hash(challenge));
        let signature = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        let pubkey = PublicKey::from_secret_key(&secp, secret_key);
        (hex::encode(bytes), idena_address_from_pubkey(&pubkey))
    }

    fn registration_for_idena(secret_key: &SecretKey) -> MinerRegistration {
        let mining_keypair = mining_keypair();
        let claim_keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[12; 32]).unwrap(),
        );
        let mut registration = MinerRegistration {
            version: LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: "miner".to_string(),
            idena_address: idena_address_from_pubkey(&PublicKey::from_secret_key(
                &Secp256k1::new(),
                secret_key,
            )),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), secret_key).0;
        registration.mining_signature_hex = sign(registration.signing_hash(), &mining_keypair);
        registration
    }

    fn test_bitcoin_header_hex(nonce: u32) -> String {
        let mut header = [0u8; BITCOIN_HEADER_BYTES];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[36..68].copy_from_slice(&[0x11; 32]);
        header[68..72].copy_from_slice(&1_231_006_505u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        hex::encode(header)
    }

    fn test_share(target: &str, nonce: u32, score: Score) -> Share {
        let mut share = Share {
            miner_id: "miner".to_string(),
            bitcoin_header_hex: test_bitcoin_header_hex(nonce),
            bitcoin_template_hash: String::new(),
            nonce_hex: String::new(),
            work_hash: String::new(),
            target: target.to_string(),
            idena_snapshot_id: "2026-06-30".to_string(),
            idena_snapshot_proof_root: "11".repeat(32),
            hashrate_score_delta: score,
            parent_share_hash: "22".repeat(32),
            work_binding: None,
            mining_signature_hex: String::new(),
        };
        share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash().unwrap();
        share.nonce_hex = share.recomputed_nonce_hex().unwrap();
        share.work_hash = share.recomputed_work_hash().unwrap();
        share
    }

    fn mined_test_share(target: &str, score: Score) -> Share {
        for nonce in 0..10_000 {
            let share = test_share(target, nonce, score);
            if share.work_hash <= target.to_ascii_lowercase() {
                return share;
            }
        }
        panic!("test target did not yield a valid share quickly");
    }

    fn above_target_test_share(target: &str, score: Score) -> Share {
        for nonce in 0..10_000 {
            let share = test_share(target, nonce, score);
            if share.work_hash > target.to_ascii_lowercase() {
                return share;
            }
        }
        panic!("test target did not yield an above-target share quickly");
    }

    fn genesis_header_share() -> Share {
        Share {
            miner_id: "miner".to_string(),
            bitcoin_header_hex: concat!(
                "01000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
                "29ab5f49",
                "ffff001d",
                "1dac2b7c"
            )
            .to_string(),
            bitcoin_template_hash: String::new(),
            nonce_hex: String::new(),
            work_hash: String::new(),
            target: MAX_SHARE_TARGET_HEX.to_string(),
            idena_snapshot_id: "2026-06-30".to_string(),
            idena_snapshot_proof_root: "11".repeat(32),
            hashrate_score_delta: 1,
            parent_share_hash: "22".repeat(32),
            work_binding: None,
            mining_signature_hex: String::new(),
        }
    }

    #[test]
    fn message_hash_is_stable() {
        let msg = SharechainMessage::SnapshotVote(SnapshotVote {
            voter_miner_id: "miner".to_string(),
            snapshot_day: "2026-06-29".to_string(),
            idena_height: 1,
            score_root: "11".repeat(32),
            signature_hex: "sig".to_string(),
        });

        assert_eq!(msg.message_hash(), msg.message_hash());
    }

    #[test]
    fn bitcoin_header_hash_matches_known_genesis_display_order() {
        let share = genesis_header_share();

        assert_eq!(share.recomputed_nonce_hex().unwrap(), "1dac2b7c");
        assert_eq!(
            share.recomputed_work_hash().unwrap(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn legacy_work_template_wire_encoding_is_unchanged_and_defaults_to_v1() {
        let share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        let template = BitcoinWorkTemplate::new_unsigned(
            "miner",
            share.bitcoin_header_prefix_hex().unwrap(),
            1,
        )
        .unwrap();
        let json = serde_json::to_value(&template).unwrap();

        assert_eq!(template.version, LEGACY_BITCOIN_WORK_TEMPLATE_VERSION);
        assert!(!json.as_object().unwrap().contains_key("version"));
        assert!(!json
            .as_object()
            .unwrap()
            .contains_key("assigned_share_target"));
        assert_eq!(
            serde_json::from_value::<BitcoinWorkTemplate>(json)
                .unwrap()
                .version,
            LEGACY_BITCOIN_WORK_TEMPLATE_VERSION
        );
    }

    #[test]
    fn legacy_miner_registration_wire_and_signing_hash_are_stable() {
        let registration = MinerRegistration {
            version: LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: "miner".to_string(),
            idena_address: "0x1111111111111111111111111111111111111111".to_string(),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            mining_pubkey_hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            registry_anchor: None,
            idena_signature_hex: "00".to_string(),
            mining_signature_hex: "00".to_string(),
        };
        let json = serde_json::to_value(&registration).unwrap();

        assert!(!json.as_object().unwrap().contains_key("version"));
        assert!(!json.as_object().unwrap().contains_key("registry_anchor"));
        assert_eq!(
            hex::encode(registration.signing_hash()),
            "7def8d1e61bff415f662f53d3a957831e517cf5886f9f5e13c895edaf954085c"
        );
        assert_eq!(
            serde_json::from_value::<MinerRegistration>(json)
                .unwrap()
                .version,
            LEGACY_MINER_REGISTRATION_VERSION
        );
    }

    #[test]
    fn registry_commitment_binds_identity_keys_and_payout_policy() {
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let registration = registration_for_idena(&idena_secret);
        let commitment = registration
            .registry_commitment_hash("p2poolbtc-experiment-1")
            .unwrap();
        let anchor = MinerRegistryAnchorV1 {
            contract_address: format!("0x{}", "21".repeat(20)),
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registration_sequence: 1,
            registration_block: 100,
            registration_epoch: 7,
            registration_timestamp: 1_700_000_000,
            registration_commitment: commitment,
        };

        let anchored = registration
            .clone()
            .attach_registry_anchor(anchor.clone())
            .unwrap();
        assert_eq!(anchored.version, IDENA_ANCHORED_MINER_REGISTRATION_VERSION);
        let mut tampered = registration;
        tampered.btc_payout_script_hex =
            "51201111111111111111111111111111111111111111111111111111111111111111".to_string();
        assert!(matches!(
            tampered.attach_registry_anchor(anchor),
            Err(SharechainError::MinerRegistryCommitmentMismatch)
        ));
    }

    #[test]
    fn idena_anchored_template_binds_anchor_and_verifies_share_with_template() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let anchor = IdenaBlockAnchorV1 {
            height: 101,
            hash: format!("0x{}", "31".repeat(32)),
        };
        let policy_hash = "ab".repeat(32);
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.bitcoin_template_hash = share
            .recomputed_idena_anchored_bitcoin_template_hash(&anchor, &policy_hash)
            .unwrap();
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);
        let mut template = BitcoinWorkTemplate::new_idena_anchored_target_bound_unsigned(
            "miner",
            share.bitcoin_header_prefix_hex().unwrap(),
            MAX_SHARE_TARGET_HEX,
            anchor.clone(),
            policy_hash.clone(),
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign(template.signing_hash(), &keypair);

        share
            .verify_mining_signature_for_template(&mining_pubkey, &template)
            .unwrap();
        assert!(share.verify_mining_signature(&mining_pubkey).is_err());

        let substituted = IdenaBlockAnchorV1 {
            height: 102,
            hash: format!("0x{}", "32".repeat(32)),
        };
        assert_ne!(
            template.template_hash,
            BitcoinWorkTemplate::idena_anchored_template_hash_for_header_prefix_hex(
                &template.header_prefix_hex,
                MAX_SHARE_TARGET_HEX,
                &substituted,
                &policy_hash,
            )
            .unwrap()
        );
        assert_ne!(
            template.template_hash,
            BitcoinWorkTemplate::idena_anchored_template_hash_for_header_prefix_hex(
                &template.header_prefix_hex,
                MAX_SHARE_TARGET_HEX,
                &anchor,
                &"cd".repeat(32),
            )
            .unwrap()
        );
    }

    #[test]
    fn target_bound_work_template_commits_to_assigned_target() {
        let share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        let prefix = share.bitcoin_header_prefix_hex().unwrap();
        let easy = BitcoinWorkTemplate::new_target_bound_unsigned(
            "miner",
            &prefix,
            MAX_SHARE_TARGET_HEX,
            1,
        )
        .unwrap();
        let harder_target = "3fffff0000000000000000000000000000000000000000000000000000000000";
        let harder =
            BitcoinWorkTemplate::new_target_bound_unsigned("miner", prefix, harder_target, 1)
                .unwrap();

        assert_ne!(easy.template_hash, harder.template_hash);
        assert_ne!(easy.signing_hash(), harder.signing_hash());
        assert!(easy.is_target_bound());
        easy.verify_assigned_share_target(MAX_SHARE_TARGET_HEX)
            .unwrap();
        assert!(matches!(
            easy.verify_assigned_share_target(harder_target),
            Err(SharechainError::AssignedShareTargetMismatch { .. })
        ));
    }

    #[test]
    fn target_bound_share_header_uses_target_bound_template_hash() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.bitcoin_template_hash = share
            .recomputed_target_bound_bitcoin_template_hash()
            .unwrap();
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        share.verify_mining_signature(&mining_pubkey).unwrap();
    }

    #[test]
    fn snapshot_vote_requires_valid_mining_signature() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut vote = SnapshotVote {
            voter_miner_id: "miner".to_string(),
            snapshot_day: "2026-06-29".to_string(),
            idena_height: 1,
            score_root: "11".repeat(32),
            signature_hex: String::new(),
        };
        vote.signature_hex = sign(vote.signing_hash(), &keypair);

        assert!(vote.verify_mining_signature(&mining_pubkey).is_ok());

        vote.score_root = "22".repeat(32);
        assert!(matches!(
            vote.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::InvalidMiningSignature(_))
        ));
    }

    #[test]
    fn idena_ownership_signature_recovers_claimed_address() {
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let registration = registration_for_idena(&idena_secret);

        registration.verify_idena_ownership_signature().unwrap();
        registration.verify_mining_signature().unwrap();
    }

    #[test]
    fn idena_ownership_signature_rejects_wrong_address() {
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let mut registration = registration_for_idena(&idena_secret);
        registration.idena_address = idena_address_from_pubkey(&PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[14; 32]).unwrap(),
        ));

        assert!(matches!(
            registration.verify_idena_ownership_signature(),
            Err(SharechainError::IdenaAddressSignatureMismatch { .. })
        ));
    }

    #[test]
    fn registration_rejects_malformed_idena_signature_length() {
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let mut registration = registration_for_idena(&idena_secret);
        registration.idena_signature_hex = "aa".to_string();

        assert!(matches!(
            registration.verify_mining_signature(),
            Err(SharechainError::InvalidIdenaSignature(_))
        ));
    }

    #[test]
    fn registration_rejects_oversized_payout_script_before_decode() {
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let mut registration = registration_for_idena(&idena_secret);
        registration.btc_payout_script_hex = "00".repeat(10_000);

        assert!(matches!(
            registration.verify_mining_signature(),
            Err(SharechainError::InvalidPayoutScript(_))
        ));
    }

    #[test]
    fn share_rejects_malformed_mining_signature_length() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.mining_signature_hex = "aa".to_string();

        assert!(matches!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::InvalidMiningSignature(_))
        ));
    }

    #[test]
    fn share_rejects_zero_score_even_with_valid_signature() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.hashrate_score_delta = 0;
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert_eq!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ZeroShareScore)
        );
    }

    #[test]
    fn share_rejects_work_hash_above_target() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = above_target_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert_eq!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareWorkAboveTarget)
        );
    }

    #[test]
    fn share_rejects_fabricated_work_hash_even_with_valid_signature() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.work_hash = "00".repeat(32);
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert!(matches!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareWorkHashMismatch { .. })
        ));
    }

    #[test]
    fn share_rejects_template_hash_not_bound_to_bitcoin_header() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.bitcoin_template_hash = "00".repeat(32);
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert!(matches!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareTemplateHashMismatch { .. })
        ));
    }

    #[test]
    fn share_rejects_nonce_not_bound_to_bitcoin_header() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 1);
        share.nonce_hex = "00000000".to_string();
        if share.recomputed_nonce_hex().unwrap() == share.nonce_hex {
            share.nonce_hex = "01000000".to_string();
        }
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert!(matches!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareNonceMismatch { .. })
        ));
    }

    #[test]
    fn share_score_must_match_target_difficulty() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = mined_test_share(MAX_SHARE_TARGET_HEX, 2);
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert_eq!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareScoreMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn share_rejects_target_above_limit() {
        let keypair = mining_keypair();
        let mining_pubkey = keypair.x_only_public_key().0.to_string();
        let mut share = test_share(&"ff".repeat(32), 0, 1);
        share.mining_signature_hex = sign(share.signing_hash(), &keypair);

        assert_eq!(
            share.verify_mining_signature(&mining_pubkey),
            Err(SharechainError::ShareTargetAboveLimit)
        );
    }
}
