use crate::snapshot::SnapshotLeaf;
use crate::{canonical_json, hash_hex, sha256_tagged};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohwCommitment {
    pub version: String,
    pub idena_snapshot_id: String,
    pub idena_score_root: String,
    pub miner_idena_address: String,
    pub identity_proof_root: String,
    pub sharechain_tip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharechain_state_root: Option<String>,
    pub payout_schedule_root: String,
    pub vault_epoch_id: u64,
    pub frost_vault_key_xonly: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PohwCommitmentParams {
    pub idena_snapshot_id: String,
    pub idena_score_root: String,
    pub miner_idena_address: String,
    pub identity_proof_root: String,
    pub sharechain_tip: String,
    pub sharechain_state_root: Option<String>,
    pub payout_schedule_root: String,
    pub vault_epoch_id: u64,
    pub frost_vault_key_xonly: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PohwCommitmentValidationContext<'a> {
    pub idena_snapshot_id: &'a str,
    pub idena_score_root: &'a str,
    pub miner_leaf: &'a SnapshotLeaf,
    pub identity_proof_root: &'a str,
    pub sharechain_tip: &'a str,
    pub sharechain_state_root: Option<&'a str>,
    pub payout_schedule_root: &'a str,
    pub vault_epoch_id: u64,
    pub frost_vault_key_xonly: &'a str,
}

impl PohwCommitment {
    pub fn new_pohw1(params: PohwCommitmentParams) -> Self {
        Self {
            version: "POHW1".to_string(),
            idena_snapshot_id: params.idena_snapshot_id,
            idena_score_root: params.idena_score_root,
            miner_idena_address: params.miner_idena_address.to_ascii_lowercase(),
            identity_proof_root: params.identity_proof_root,
            sharechain_tip: params.sharechain_tip,
            sharechain_state_root: params.sharechain_state_root,
            payout_schedule_root: params.payout_schedule_root,
            vault_epoch_id: params.vault_epoch_id,
            frost_vault_key_xonly: params.frost_vault_key_xonly,
        }
    }

    pub fn normalized(mut self) -> Self {
        self.version = self.version.to_ascii_uppercase();
        self.idena_snapshot_id = self.idena_snapshot_id.to_ascii_lowercase();
        self.idena_score_root = self.idena_score_root.to_ascii_lowercase();
        self.miner_idena_address = self.miner_idena_address.to_ascii_lowercase();
        self.identity_proof_root = self.identity_proof_root.to_ascii_lowercase();
        self.sharechain_tip = self.sharechain_tip.to_ascii_lowercase();
        self.sharechain_state_root = self
            .sharechain_state_root
            .map(|root| root.to_ascii_lowercase());
        self.payout_schedule_root = self.payout_schedule_root.to_ascii_lowercase();
        self.frost_vault_key_xonly = self.frost_vault_key_xonly.to_ascii_lowercase();
        self
    }

    pub fn commitment_hash(&self) -> String {
        hash_hex(sha256_tagged(
            b"POHW1_COMMITMENT",
            &canonical_json(&self.clone().normalized()),
        ))
    }

    pub fn op_return_payload(&self) -> Vec<u8> {
        let mut payload = b"POHW1".to_vec();
        payload.extend_from_slice(&hex::decode(self.commitment_hash()).expect("hash hex is valid"));
        payload
    }

    pub fn op_return_script_pubkey_hex(&self) -> String {
        let payload = self.op_return_payload();
        assert!(
            payload.len() <= 75,
            "POHW1 commitment payload must fit in direct push"
        );
        let mut script = Vec::with_capacity(2 + payload.len());
        script.push(0x6a);
        script.push(payload.len() as u8);
        script.extend_from_slice(&payload);
        hex::encode(script)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitmentError {
    #[error("unsupported commitment version {0}")]
    UnsupportedVersion(String),
    #[error("miner identity is not eligible for block proposal")]
    IneligibleIdentity,
    #[error("miner commitment address {commitment_address} does not match snapshot leaf {snapshot_address}")]
    MinerAddressMismatch {
        commitment_address: String,
        snapshot_address: String,
    },
    #[error("commitment snapshot id {actual} does not match expected {expected}")]
    SnapshotIdMismatch { expected: String, actual: String },
    #[error("commitment Idena score root {actual} does not match expected {expected}")]
    IdenaScoreRootMismatch { expected: String, actual: String },
    #[error("commitment identity proof root {actual} does not match expected {expected}")]
    IdentityProofRootMismatch { expected: String, actual: String },
    #[error("commitment sharechain tip {actual} does not match expected {expected}")]
    SharechainTipMismatch { expected: String, actual: String },
    #[error("commitment is missing sharechain state root")]
    MissingSharechainStateRoot,
    #[error("commitment sharechain state root {actual} does not match expected {expected}")]
    SharechainStateRootMismatch { expected: String, actual: String },
    #[error("commitment payout schedule root {actual} does not match expected {expected}")]
    PayoutScheduleRootMismatch { expected: String, actual: String },
    #[error("commitment vault epoch {actual} does not match expected {expected}")]
    VaultEpochMismatch { expected: u64, actual: u64 },
    #[error("commitment FROST vault key {actual} does not match expected {expected}")]
    FrostVaultKeyMismatch { expected: String, actual: String },
}

pub fn validate_pohw_commitment(
    commitment: &PohwCommitment,
    context: PohwCommitmentValidationContext<'_>,
) -> Result<(), CommitmentError> {
    validate_commitment_identity(commitment, context.miner_leaf)?;
    require_case_insensitive_match(
        "snapshot id",
        &commitment.idena_snapshot_id,
        context.idena_snapshot_id,
        CommitmentError::SnapshotIdMismatch {
            expected: context.idena_snapshot_id.to_string(),
            actual: commitment.idena_snapshot_id.clone(),
        },
    )?;
    require_case_insensitive_match(
        "Idena score root",
        &commitment.idena_score_root,
        context.idena_score_root,
        CommitmentError::IdenaScoreRootMismatch {
            expected: context.idena_score_root.to_string(),
            actual: commitment.idena_score_root.clone(),
        },
    )?;
    require_case_insensitive_match(
        "identity proof root",
        &commitment.identity_proof_root,
        context.identity_proof_root,
        CommitmentError::IdentityProofRootMismatch {
            expected: context.identity_proof_root.to_string(),
            actual: commitment.identity_proof_root.clone(),
        },
    )?;
    require_case_insensitive_match(
        "sharechain tip",
        &commitment.sharechain_tip,
        context.sharechain_tip,
        CommitmentError::SharechainTipMismatch {
            expected: context.sharechain_tip.to_string(),
            actual: commitment.sharechain_tip.clone(),
        },
    )?;
    if let Some(expected_state_root) = context.sharechain_state_root {
        let actual_state_root = commitment
            .sharechain_state_root
            .as_deref()
            .ok_or(CommitmentError::MissingSharechainStateRoot)?;
        require_case_insensitive_match(
            "sharechain state root",
            actual_state_root,
            expected_state_root,
            CommitmentError::SharechainStateRootMismatch {
                expected: expected_state_root.to_string(),
                actual: actual_state_root.to_string(),
            },
        )?;
    }
    require_case_insensitive_match(
        "payout schedule root",
        &commitment.payout_schedule_root,
        context.payout_schedule_root,
        CommitmentError::PayoutScheduleRootMismatch {
            expected: context.payout_schedule_root.to_string(),
            actual: commitment.payout_schedule_root.clone(),
        },
    )?;
    if commitment.vault_epoch_id != context.vault_epoch_id {
        return Err(CommitmentError::VaultEpochMismatch {
            expected: context.vault_epoch_id,
            actual: commitment.vault_epoch_id,
        });
    }
    require_case_insensitive_match(
        "FROST vault key",
        &commitment.frost_vault_key_xonly,
        context.frost_vault_key_xonly,
        CommitmentError::FrostVaultKeyMismatch {
            expected: context.frost_vault_key_xonly.to_string(),
            actual: commitment.frost_vault_key_xonly.clone(),
        },
    )?;
    Ok(())
}

pub fn validate_commitment_identity(
    commitment: &PohwCommitment,
    miner_leaf: &SnapshotLeaf,
) -> Result<(), CommitmentError> {
    if commitment.version != "POHW1" {
        return Err(CommitmentError::UnsupportedVersion(
            commitment.version.clone(),
        ));
    }
    if commitment.miner_idena_address != miner_leaf.idena_address.to_ascii_lowercase() {
        return Err(CommitmentError::MinerAddressMismatch {
            commitment_address: commitment.miner_idena_address.clone(),
            snapshot_address: miner_leaf.idena_address.clone(),
        });
    }
    if !miner_leaf.is_block_eligible() {
        return Err(CommitmentError::IneligibleIdentity);
    }
    Ok(())
}

fn require_case_insensitive_match(
    _label: &str,
    actual: &str,
    expected: &str,
    error: CommitmentError,
) -> Result<(), CommitmentError> {
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{IdenaStatus, SnapshotLeaf};
    use crate::FORMULA_VERSION;

    fn leaf(status: IdenaStatus) -> SnapshotLeaf {
        SnapshotLeaf {
            idena_address: "0xabc".to_string(),
            status,
            pubkey: "00".to_string(),
            validation_reward_score: 1,
            proposer_reward_score: 0,
            committee_reward_score: 0,
            ignored_invitation_score: 0,
            identity_root: "0x00".to_string(),
            formula_version: FORMULA_VERSION,
        }
    }

    #[test]
    fn eligible_identity_accepts_commitment() {
        let commitment = PohwCommitment::new_pohw1(commitment_params());
        validate_commitment_identity(&commitment, &leaf(IdenaStatus::Human)).unwrap();
    }

    #[test]
    fn full_commitment_validation_binds_all_block_material() {
        let commitment = PohwCommitment::new_pohw1(commitment_params());

        validate_pohw_commitment(
            &commitment,
            PohwCommitmentValidationContext {
                idena_snapshot_id: "day",
                idena_score_root: "root",
                miner_leaf: &leaf(IdenaStatus::Human),
                identity_proof_root: "proof",
                sharechain_tip: "tip",
                sharechain_state_root: Some("state"),
                payout_schedule_root: "payout",
                vault_epoch_id: 1,
                frost_vault_key_xonly: "key",
            },
        )
        .unwrap();
    }

    #[test]
    fn full_commitment_validation_rejects_wrong_payout_root() {
        let commitment = PohwCommitment::new_pohw1(commitment_params());
        let err = validate_pohw_commitment(
            &commitment,
            PohwCommitmentValidationContext {
                idena_snapshot_id: "day",
                idena_score_root: "root",
                miner_leaf: &leaf(IdenaStatus::Human),
                identity_proof_root: "proof",
                sharechain_tip: "tip",
                sharechain_state_root: Some("state"),
                payout_schedule_root: "wrong",
                vault_epoch_id: 1,
                frost_vault_key_xonly: "key",
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CommitmentError::PayoutScheduleRootMismatch { .. }
        ));
    }

    #[test]
    fn full_commitment_validation_rejects_missing_state_root_when_required() {
        let mut params = commitment_params();
        params.sharechain_state_root = None;
        let commitment = PohwCommitment::new_pohw1(params);
        let err = validate_pohw_commitment(
            &commitment,
            PohwCommitmentValidationContext {
                idena_snapshot_id: "day",
                idena_score_root: "root",
                miner_leaf: &leaf(IdenaStatus::Human),
                identity_proof_root: "proof",
                sharechain_tip: "tip",
                sharechain_state_root: Some("state"),
                payout_schedule_root: "payout",
                vault_epoch_id: 1,
                frost_vault_key_xonly: "key",
            },
        )
        .unwrap_err();

        assert_eq!(err, CommitmentError::MissingSharechainStateRoot);
    }

    #[test]
    fn candidate_identity_rejects_commitment() {
        let commitment = PohwCommitment::new_pohw1(commitment_params());
        let err =
            validate_commitment_identity(&commitment, &leaf(IdenaStatus::Candidate)).unwrap_err();
        assert_eq!(err, CommitmentError::IneligibleIdentity);
    }

    #[test]
    fn op_return_script_binds_normalized_commitment_hash() {
        let lower = PohwCommitment::new_pohw1(commitment_params());
        let mut upper = lower.clone();
        upper.idena_score_root = upper.idena_score_root.to_ascii_uppercase();
        upper.frost_vault_key_xonly = upper.frost_vault_key_xonly.to_ascii_uppercase();

        assert_eq!(lower.commitment_hash(), upper.commitment_hash());
        assert_eq!(
            lower.op_return_script_pubkey_hex(),
            format!("6a25{}", hex::encode(lower.op_return_payload()))
        );
    }

    fn commitment_params() -> PohwCommitmentParams {
        PohwCommitmentParams {
            idena_snapshot_id: "day".to_string(),
            idena_score_root: "root".to_string(),
            miner_idena_address: "0xABC".to_string(),
            identity_proof_root: "proof".to_string(),
            sharechain_tip: "tip".to_string(),
            sharechain_state_root: Some("state".to_string()),
            payout_schedule_root: "payout".to_string(),
            vault_epoch_id: 1,
            frost_vault_key_xonly: "key".to_string(),
        }
    }
}
