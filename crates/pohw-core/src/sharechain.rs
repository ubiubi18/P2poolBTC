use crate::commitment::PohwCommitment;
use crate::payout::PayoutSchedule;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerRegistration {
    pub miner_id: String,
    pub idena_address: String,
    pub btc_payout_script_hex: String,
    pub claim_owner_pubkey_hex: String,
    pub mining_pubkey_hex: String,
    pub idena_signature_hex: String,
    pub mining_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinWorkTemplate {
    pub miner_id: String,
    pub header_prefix_hex: String,
    pub template_hash: String,
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
}

#[derive(Debug, Clone, Serialize)]
struct MinerRegistrationSigningPayload {
    miner_id: String,
    idena_address: String,
    btc_payout_script_hex: String,
    claim_owner_pubkey_hex: String,
    mining_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct BitcoinWorkTemplateSigningPayload {
    miner_id: String,
    header_prefix_hex: String,
    template_hash: String,
    created_at_unix: i64,
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
        self.idena_signature_hex = self.idena_signature_hex.to_ascii_lowercase();
        self.mining_signature_hex = self.mining_signature_hex.to_ascii_lowercase();
        self
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        sha256_tagged(
            b"POHW1_MINER_REGISTRATION",
            &canonical_json(&MinerRegistrationSigningPayload {
                miner_id: self.miner_id.to_ascii_lowercase(),
                idena_address: self.idena_address.to_ascii_lowercase(),
                btc_payout_script_hex: self.btc_payout_script_hex.to_ascii_lowercase(),
                claim_owner_pubkey_hex: self.claim_owner_pubkey_hex.to_ascii_lowercase(),
                mining_pubkey_hex: self.mining_pubkey_hex.to_ascii_lowercase(),
            }),
        )
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
            miner_id: miner_id.into(),
            header_prefix_hex,
            template_hash,
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

    pub fn template_hash_for_header_prefix_hex(
        header_prefix_hex: &str,
    ) -> Result<String, SharechainError> {
        let header_prefix = decode_bitcoin_header_prefix_hex(header_prefix_hex)?;
        Ok(hash_hex(sha256_tagged(
            b"POHW1_BTC_TEMPLATE",
            &header_prefix,
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
        let expected = Self::template_hash_for_header_prefix_hex(&self.header_prefix_hex)?;
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
                miner_id: self.miner_id.to_ascii_lowercase(),
                header_prefix_hex: self.header_prefix_hex.to_ascii_lowercase(),
                template_hash: self.template_hash.to_ascii_lowercase(),
                created_at_unix: self.created_at_unix,
            }),
        )
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
            }),
        )
    }

    pub fn recomputed_bitcoin_template_hash(&self) -> Result<String, SharechainError> {
        BitcoinWorkTemplate::template_hash_for_header_prefix_hex(&self.bitcoin_header_prefix_hex()?)
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
        self.verify_work_score()?;
        verify_mining_signature(
            mining_pubkey_hex,
            &self.mining_signature_hex,
            self.signing_hash(),
        )
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
        self.verify_bitcoin_header_binding()?;
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

    fn verify_bitcoin_header_binding(&self) -> Result<(), SharechainError> {
        let expected_template_hash = self.recomputed_bitcoin_template_hash()?;
        if !self
            .bitcoin_template_hash
            .eq_ignore_ascii_case(&expected_template_hash)
        {
            return Err(SharechainError::ShareTemplateHashMismatch {
                expected: expected_template_hash,
                actual: self.bitcoin_template_hash.to_ascii_lowercase(),
            });
        }
        let expected_nonce = self.recomputed_nonce_hex()?;
        if !self.nonce_hex.eq_ignore_ascii_case(&expected_nonce) {
            return Err(SharechainError::ShareNonceMismatch {
                expected: expected_nonce,
                actual: self.nonce_hex.to_ascii_lowercase(),
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
            miner_id: "miner".to_string(),
            idena_address: idena_address_from_pubkey(&PublicKey::from_secret_key(
                &Secp256k1::new(),
                secret_key,
            )),
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
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
