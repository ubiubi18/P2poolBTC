use crate::gossip::normalize_gossip_network_id;
use crate::idena_anchor::{validate_experiment_id, IdenaBlockAnchorV1};
use crate::{canonical_json, hash_hex, sha256_tagged};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

pub const SHARE_WORK_BINDING_POLICY_SCHEMA_VERSION: u16 = 1;
pub const SHARE_WORK_BINDING_SCHEMA_VERSION: u16 = 1;
pub const SHARE_WORK_ACTIVATION_SCHEMA: &str = "pohw-share-work-activation/v1";
const SHARE_WORK_COMMITMENT_TAG: &[u8] = b"P2POOLBTC_SHARE_WORK_V1";
const SHARE_WORK_POLICY_TAG: &[u8] = b"P2POOLBTC_SHARE_WORK_POLICY_V1";
const SHARE_WORK_ACTIVATION_TAG: &[u8] = b"P2POOLBTC_SHARE_WORK_ACTIVATION_V1";
const SHARE_WORK_OP_RETURN_PREFIX: &[u8] = b"P2SW1";
const MAX_MINER_ID_BYTES: usize = 64;
const MAX_SNAPSHOT_ID_BYTES: usize = 64;
// The binding is carried as hex inside a bounded gossip record. Keep enough
// headroom for the surrounding share, Merkle proof, and envelope metadata.
const MAX_COINBASE_BYTES: usize = 256 * 1024;
const MAX_MERKLE_BRANCHES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareWorkActivationManifestV1 {
    pub schema_version: String,
    pub profile_revision: u16,
    pub status: String,
    pub launch_enabled: bool,
    pub activation_id: String,
    pub experiment_id: String,
    pub bitcoin_fork_activation_id: String,
    pub sharechain_network_id: String,
    pub require_binding_from_genesis: bool,
    pub require_fresh_datadir: bool,
    pub history_reinterpreted: bool,
    pub coinbase_commitment_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ShareWorkActivationPayloadV1<'a> {
    schema_version: &'a str,
    profile_revision: u16,
    status: &'a str,
    launch_enabled: bool,
    experiment_id: &'a str,
    bitcoin_fork_activation_id: &'a str,
    sharechain_network_id: &'a str,
    require_binding_from_genesis: bool,
    require_fresh_datadir: bool,
    history_reinterpreted: bool,
    coinbase_commitment_tag: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareWorkBindingPolicyV1 {
    pub schema_version: u16,
    pub experiment_id: String,
    pub fork_activation_id: String,
    pub sharechain_network_id: String,
    pub require_binding_from_genesis: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareWorkBindingV1 {
    pub schema_version: u16,
    pub policy_hash: String,
    pub miner_id: String,
    pub assigned_share_target: String,
    pub parent_share_hash: String,
    pub idena_snapshot_id: String,
    pub idena_snapshot_proof_root: String,
    pub idena_anchor: IdenaBlockAnchorV1,
    pub idena_anchor_policy_hash: String,
    pub coinbase_tx_hex: String,
    pub coinbase_merkle_branches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ShareWorkCommitmentPayloadV1<'a> {
    schema_version: u16,
    policy_hash: &'a str,
    miner_id: &'a str,
    assigned_share_target: &'a str,
    parent_share_hash: &'a str,
    idena_snapshot_id: &'a str,
    idena_snapshot_proof_root: &'a str,
    idena_anchor: &'a IdenaBlockAnchorV1,
    idena_anchor_policy_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareWorkBindingError {
    #[error("unsupported share-work activation schema {0}")]
    UnsupportedActivationSchema(String),
    #[error("unsupported share-work policy schema version {0}")]
    UnsupportedPolicyVersion(u16),
    #[error("unsupported share-work binding schema version {0}")]
    UnsupportedBindingVersion(u16),
    #[error("invalid share-work field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("share-work policy requires bindings from genesis")]
    LegacyReplayPolicyRejected,
    #[error("share-work policy hash {actual} does not match expected {expected}")]
    PolicyMismatch { expected: String, actual: String },
    #[error("share-work commitment output count must be exactly one, got {0}")]
    CommitmentOutputCount(usize),
    #[error("share-work commitment output does not match the committed share fields")]
    CommitmentOutputMismatch,
    #[error("share-work coinbase is invalid: {0}")]
    InvalidCoinbase(String),
    #[error("share-work coinbase merkle proof does not match the Bitcoin header")]
    MerkleRootMismatch,
    #[error("share-work activation id {actual} does not match canonical payload {expected}")]
    ActivationIdMismatch { expected: String, actual: String },
    #[error("share-work activation profile is not launchable: {0}")]
    ActivationNotLaunchable(String),
}

impl ShareWorkActivationManifestV1 {
    pub fn normalized(mut self) -> Self {
        self.schema_version = self.schema_version.to_ascii_lowercase();
        self.status = self.status.to_ascii_lowercase();
        self.activation_id = self.activation_id.to_ascii_lowercase();
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.bitcoin_fork_activation_id = self.bitcoin_fork_activation_id.to_ascii_lowercase();
        self.sharechain_network_id = self.sharechain_network_id.to_ascii_lowercase();
        self
    }

    pub fn recomputed_activation_id(&self) -> Result<String, ShareWorkBindingError> {
        let manifest = self.clone().normalized();
        manifest.validate_fields()?;
        Ok(hash_hex(sha256_tagged(
            SHARE_WORK_ACTIVATION_TAG,
            &canonical_json(&ShareWorkActivationPayloadV1 {
                schema_version: &manifest.schema_version,
                profile_revision: manifest.profile_revision,
                status: &manifest.status,
                launch_enabled: manifest.launch_enabled,
                experiment_id: &manifest.experiment_id,
                bitcoin_fork_activation_id: &manifest.bitcoin_fork_activation_id,
                sharechain_network_id: &manifest.sharechain_network_id,
                require_binding_from_genesis: manifest.require_binding_from_genesis,
                require_fresh_datadir: manifest.require_fresh_datadir,
                history_reinterpreted: manifest.history_reinterpreted,
                coinbase_commitment_tag: &manifest.coinbase_commitment_tag,
            }),
        )))
    }

    pub fn validate(&self) -> Result<(), ShareWorkBindingError> {
        self.validate_fields()?;
        let expected = self.recomputed_activation_id()?;
        let actual = self.activation_id.to_ascii_lowercase();
        if actual != expected {
            return Err(ShareWorkBindingError::ActivationIdMismatch { expected, actual });
        }
        Ok(())
    }

    pub fn validate_for_launch(&self) -> Result<(), ShareWorkBindingError> {
        self.validate()?;
        if self.status != "experimental-active" || !self.launch_enabled {
            return Err(ShareWorkBindingError::ActivationNotLaunchable(format!(
                "status={} launch_enabled={}",
                self.status, self.launch_enabled
            )));
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), ShareWorkBindingError> {
        if self.schema_version != SHARE_WORK_ACTIVATION_SCHEMA {
            return Err(ShareWorkBindingError::UnsupportedActivationSchema(
                self.schema_version.clone(),
            ));
        }
        if self.profile_revision == 0 {
            return Err(invalid_field("profile_revision", "must be positive"));
        }
        match (self.status.as_str(), self.launch_enabled) {
            ("experimental-candidate", false) | ("experimental-active", true) => {}
            _ => {
                return Err(invalid_field(
                    "status",
                    "must be experimental-candidate with launch disabled or experimental-active with launch enabled",
                ));
            }
        }
        validate_hash("activation_id", &self.activation_id)?;
        validate_experiment_id(&self.experiment_id).map_err(|error| {
            ShareWorkBindingError::InvalidField {
                field: "experiment_id".to_string(),
                reason: error.to_string(),
            }
        })?;
        validate_hash(
            "bitcoin_fork_activation_id",
            &self.bitcoin_fork_activation_id,
        )?;
        if self
            .bitcoin_fork_activation_id
            .bytes()
            .all(|byte| byte == b'0')
        {
            return Err(invalid_field(
                "bitcoin_fork_activation_id",
                "must not be zero",
            ));
        }
        let network_id =
            normalize_gossip_network_id(&self.sharechain_network_id).map_err(|error| {
                ShareWorkBindingError::InvalidField {
                    field: "sharechain_network_id".to_string(),
                    reason: error.to_string(),
                }
            })?;
        if network_id != self.sharechain_network_id
            || self.sharechain_network_id.bytes().all(|byte| byte == b'0')
        {
            return Err(invalid_field(
                "sharechain_network_id",
                "must be nonzero canonical lowercase network id",
            ));
        }
        if !self.require_binding_from_genesis {
            return Err(invalid_field(
                "require_binding_from_genesis",
                "must be true",
            ));
        }
        if !self.require_fresh_datadir {
            return Err(invalid_field("require_fresh_datadir", "must be true"));
        }
        if self.history_reinterpreted {
            return Err(invalid_field("history_reinterpreted", "must be false"));
        }
        if self.coinbase_commitment_tag != "P2SW1" {
            return Err(invalid_field("coinbase_commitment_tag", "must be P2SW1"));
        }
        Ok(())
    }
}

impl ShareWorkBindingPolicyV1 {
    pub fn normalized(mut self) -> Self {
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.fork_activation_id = self.fork_activation_id.to_ascii_lowercase();
        self.sharechain_network_id = self.sharechain_network_id.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), ShareWorkBindingError> {
        if self.schema_version != SHARE_WORK_BINDING_POLICY_SCHEMA_VERSION {
            return Err(ShareWorkBindingError::UnsupportedPolicyVersion(
                self.schema_version,
            ));
        }
        validate_experiment_id(&self.experiment_id).map_err(|error| {
            ShareWorkBindingError::InvalidField {
                field: "experiment_id".to_string(),
                reason: error.to_string(),
            }
        })?;
        validate_hash("fork_activation_id", &self.fork_activation_id)?;
        if self.fork_activation_id.bytes().all(|byte| byte == b'0') {
            return Err(ShareWorkBindingError::InvalidField {
                field: "fork_activation_id".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        let normalized_network_id = normalize_gossip_network_id(&self.sharechain_network_id)
            .map_err(|error| ShareWorkBindingError::InvalidField {
                field: "sharechain_network_id".to_string(),
                reason: error.to_string(),
            })?;
        if normalized_network_id != self.sharechain_network_id {
            return Err(ShareWorkBindingError::InvalidField {
                field: "sharechain_network_id".to_string(),
                reason: "must use canonical lowercase form".to_string(),
            });
        }
        if !self.require_binding_from_genesis {
            return Err(ShareWorkBindingError::LegacyReplayPolicyRejected);
        }
        Ok(())
    }

    pub fn commitment_hash(&self) -> Result<String, ShareWorkBindingError> {
        let policy = self.clone().normalized();
        policy.validate()?;
        Ok(hash_hex(sha256_tagged(
            SHARE_WORK_POLICY_TAG,
            &canonical_json(&policy),
        )))
    }
}

impl ShareWorkBindingV1 {
    pub fn normalized(mut self) -> Self {
        self.policy_hash = self.policy_hash.to_ascii_lowercase();
        self.miner_id = self.miner_id.to_ascii_lowercase();
        self.assigned_share_target = self.assigned_share_target.to_ascii_lowercase();
        self.parent_share_hash = self.parent_share_hash.to_ascii_lowercase();
        self.idena_snapshot_id = self.idena_snapshot_id.to_ascii_lowercase();
        self.idena_snapshot_proof_root = self.idena_snapshot_proof_root.to_ascii_lowercase();
        self.idena_anchor = self.idena_anchor.normalized();
        self.idena_anchor_policy_hash = self.idena_anchor_policy_hash.to_ascii_lowercase();
        self.coinbase_tx_hex = self.coinbase_tx_hex.to_ascii_lowercase();
        self.coinbase_merkle_branches = self
            .coinbase_merkle_branches
            .into_iter()
            .map(|branch| branch.to_ascii_lowercase())
            .collect();
        self
    }

    pub fn validate_commitment_fields(&self) -> Result<(), ShareWorkBindingError> {
        if self.schema_version != SHARE_WORK_BINDING_SCHEMA_VERSION {
            return Err(ShareWorkBindingError::UnsupportedBindingVersion(
                self.schema_version,
            ));
        }
        validate_hash("policy_hash", &self.policy_hash)?;
        validate_label("miner_id", &self.miner_id, MAX_MINER_ID_BYTES)?;
        validate_hash("assigned_share_target", &self.assigned_share_target)?;
        if self.assigned_share_target.bytes().all(|byte| byte == b'0') {
            return Err(ShareWorkBindingError::InvalidField {
                field: "assigned_share_target".to_string(),
                reason: "must not be zero".to_string(),
            });
        }
        validate_hash("parent_share_hash", &self.parent_share_hash)?;
        validate_label(
            "idena_snapshot_id",
            &self.idena_snapshot_id,
            MAX_SNAPSHOT_ID_BYTES,
        )?;
        validate_hash("idena_snapshot_proof_root", &self.idena_snapshot_proof_root)?;
        self.idena_anchor
            .validate()
            .map_err(|error| ShareWorkBindingError::InvalidField {
                field: "idena_anchor".to_string(),
                reason: error.to_string(),
            })?;
        validate_hash("idena_anchor_policy_hash", &self.idena_anchor_policy_hash)?;
        Ok(())
    }

    pub fn commitment_hash(&self) -> Result<String, ShareWorkBindingError> {
        let binding = self.clone().normalized();
        binding.validate_commitment_fields()?;
        Ok(hash_hex(sha256_tagged(
            SHARE_WORK_COMMITMENT_TAG,
            &canonical_json(&ShareWorkCommitmentPayloadV1 {
                schema_version: binding.schema_version,
                policy_hash: &binding.policy_hash,
                miner_id: &binding.miner_id,
                assigned_share_target: &binding.assigned_share_target,
                parent_share_hash: &binding.parent_share_hash,
                idena_snapshot_id: &binding.idena_snapshot_id,
                idena_snapshot_proof_root: &binding.idena_snapshot_proof_root,
                idena_anchor: &binding.idena_anchor,
                idena_anchor_policy_hash: &binding.idena_anchor_policy_hash,
            }),
        )))
    }

    pub fn op_return_script_pubkey_hex(&self) -> Result<String, ShareWorkBindingError> {
        let mut payload = SHARE_WORK_OP_RETURN_PREFIX.to_vec();
        payload
            .extend_from_slice(&hex::decode(self.commitment_hash()?).expect("hash is valid hex"));
        let mut script = Vec::with_capacity(payload.len() + 2);
        script.push(0x6a);
        script.push(u8::try_from(payload.len()).expect("share-work payload fits a direct push"));
        script.extend_from_slice(&payload);
        Ok(hex::encode(script))
    }

    pub fn verify_policy(
        &self,
        policy: &ShareWorkBindingPolicyV1,
    ) -> Result<(), ShareWorkBindingError> {
        let expected = policy.commitment_hash()?;
        let actual = self.policy_hash.to_ascii_lowercase();
        if actual != expected {
            return Err(ShareWorkBindingError::PolicyMismatch { expected, actual });
        }
        Ok(())
    }

    pub fn verify_header_commitment(
        &self,
        bitcoin_header_hex: &str,
    ) -> Result<(), ShareWorkBindingError> {
        self.validate_commitment_fields()?;
        let header = decode_exact_hex("bitcoin_header_hex", bitcoin_header_hex, 80)?;
        if self.coinbase_tx_hex.is_empty()
            || self.coinbase_tx_hex.len() % 2 != 0
            || self.coinbase_tx_hex.len() > MAX_COINBASE_BYTES.saturating_mul(2)
            || !self
                .coinbase_tx_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ShareWorkBindingError::InvalidField {
                field: "coinbase_tx_hex".to_string(),
                reason: "must be nonempty canonical transaction hex within the size limit"
                    .to_string(),
            });
        }
        if self.coinbase_merkle_branches.len() > MAX_MERKLE_BRANCHES {
            return Err(ShareWorkBindingError::InvalidField {
                field: "coinbase_merkle_branches".to_string(),
                reason: format!("must contain at most {MAX_MERKLE_BRANCHES} entries"),
            });
        }
        let coinbase_bytes = hex::decode(&self.coinbase_tx_hex)
            .map_err(|error| ShareWorkBindingError::InvalidCoinbase(error.to_string()))?;
        let coinbase: Transaction = deserialize(&coinbase_bytes)
            .map_err(|error| ShareWorkBindingError::InvalidCoinbase(error.to_string()))?;
        if !coinbase.is_coinbase() || serialize(&coinbase) != coinbase_bytes {
            return Err(ShareWorkBindingError::InvalidCoinbase(
                "transaction is not a canonical coinbase".to_string(),
            ));
        }

        let expected_script = hex::decode(self.op_return_script_pubkey_hex()?).expect("valid hex");
        let commitment_outputs = coinbase
            .output
            .iter()
            .filter(|output| {
                let script = output.script_pubkey.as_bytes();
                script.first() == Some(&0x6a)
                    && script[1..]
                        .windows(SHARE_WORK_OP_RETURN_PREFIX.len())
                        .any(|window| window == SHARE_WORK_OP_RETURN_PREFIX)
            })
            .collect::<Vec<_>>();
        if commitment_outputs.len() != 1 {
            return Err(ShareWorkBindingError::CommitmentOutputCount(
                commitment_outputs.len(),
            ));
        }
        if commitment_outputs[0].script_pubkey.as_bytes() != expected_script {
            return Err(ShareWorkBindingError::CommitmentOutputMismatch);
        }

        let mut merkle = coinbase.compute_txid().to_byte_array();
        for branch in &self.coinbase_merkle_branches {
            let branch = decode_exact_hex("coinbase_merkle_branch", branch, 32)?;
            let mut pair = Vec::with_capacity(64);
            pair.extend_from_slice(&merkle);
            pair.extend_from_slice(&branch);
            merkle = sha256d::Hash::hash(&pair).to_byte_array();
        }
        if merkle.as_slice() != &header[36..68] {
            return Err(ShareWorkBindingError::MerkleRootMismatch);
        }
        Ok(())
    }
}

fn invalid_field(field: &str, reason: &str) -> ShareWorkBindingError {
    ShareWorkBindingError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

fn validate_label(field: &str, value: &str, max_bytes: usize) -> Result<(), ShareWorkBindingError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(ShareWorkBindingError::InvalidField {
            field: field.to_string(),
            reason: format!("length must be 1..={max_bytes} bytes"),
        });
    }
    if value != value.to_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ShareWorkBindingError::InvalidField {
            field: field.to_string(),
            reason: "must use canonical lowercase ASCII label characters".to_string(),
        });
    }
    Ok(())
}

fn validate_hash(field: &str, value: &str) -> Result<(), ShareWorkBindingError> {
    if value.len() != 64
        || value != value.to_ascii_lowercase()
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ShareWorkBindingError::InvalidField {
            field: field.to_string(),
            reason: "must be 32-byte lowercase hex".to_string(),
        });
    }
    Ok(())
}

fn decode_exact_hex(
    field: &str,
    value: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, ShareWorkBindingError> {
    if value.len() != expected_bytes.saturating_mul(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ShareWorkBindingError::InvalidField {
            field: field.to_string(),
            reason: format!("must be exactly {expected_bytes} bytes of hex"),
        });
    }
    hex::decode(value).map_err(|error| ShareWorkBindingError::InvalidField {
        field: field.to_string(),
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation_manifest(status: &str, launch_enabled: bool) -> ShareWorkActivationManifestV1 {
        let mut manifest = ShareWorkActivationManifestV1 {
            schema_version: SHARE_WORK_ACTIVATION_SCHEMA.to_string(),
            profile_revision: 1,
            status: status.to_string(),
            launch_enabled,
            activation_id: "00".repeat(32),
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            bitcoin_fork_activation_id: "11".repeat(32),
            sharechain_network_id: "22".repeat(32),
            require_binding_from_genesis: true,
            require_fresh_datadir: true,
            history_reinterpreted: false,
            coinbase_commitment_tag: "P2SW1".to_string(),
        };
        manifest.activation_id = manifest.recomputed_activation_id().unwrap();
        manifest
    }

    #[test]
    fn activation_id_commits_every_launch_relevant_field() {
        let candidate = activation_manifest("experimental-candidate", false);
        candidate.validate().unwrap();
        assert!(matches!(
            candidate.validate_for_launch(),
            Err(ShareWorkBindingError::ActivationNotLaunchable(_))
        ));

        let active = activation_manifest("experimental-active", true);
        active.validate_for_launch().unwrap();
        assert_ne!(candidate.activation_id, active.activation_id);

        let mut tampered = active;
        tampered.sharechain_network_id = "33".repeat(32);
        assert!(matches!(
            tampered.validate(),
            Err(ShareWorkBindingError::ActivationIdMismatch { .. })
        ));
    }

    #[test]
    fn activation_rejects_legacy_history_and_unsafe_status_combinations() {
        let mut manifest = activation_manifest("experimental-active", true);
        manifest.history_reinterpreted = true;
        assert!(matches!(
            manifest.recomputed_activation_id(),
            Err(ShareWorkBindingError::InvalidField { field, .. }) if field == "history_reinterpreted"
        ));

        let manifest = ShareWorkActivationManifestV1 {
            status: "experimental-active".to_string(),
            launch_enabled: false,
            ..activation_manifest("experimental-candidate", false)
        };
        assert!(matches!(
            manifest.recomputed_activation_id(),
            Err(ShareWorkBindingError::InvalidField { field, .. }) if field == "status"
        ));
    }
}
