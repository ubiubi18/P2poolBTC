use crate::idena_anchor::{validate_experiment_id, MinerRegistryAnchorV1, MAX_CHECKPOINT_MINERS};
use crate::sharechain::MinerRegistration;
use crate::snapshot::IdenaStatus;
use crate::{canonical_json, hash_hex, sha256_tagged};
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr::Signature, Message};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

pub const CONSENSUS_IDENTITY_POLICY_VERSION: u16 = 1;
pub const CONSENSUS_IDENTITY_AUTHORIZATION_VERSION: u8 = 1;
pub const CONSENSUS_IDENTITY_ACTIVATION_SCHEMA: &str = "pohw-consensus-identity-activation/v1";
pub const CONSENSUS_IDENTITY_MAGIC: &[u8; 5] = b"P2IA1";
pub const SHARE_WORK_MAGIC: &[u8; 5] = b"P2SW1";
pub const CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA: &str =
    "pohw-consensus-identity-snapshot-input/v1";
pub const CONSENSUS_IDENTITY_SNAPSHOT_BUNDLE_SCHEMA: &str =
    "pohw-consensus-identity-snapshot-bundle/v1";
pub const CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN: &str =
    "compatible-rpc-unproven";
pub const MAX_CONSENSUS_IDENTITY_PROOF_DEPTH: usize = 16;
pub const MAX_CONSENSUS_IDENTITY_SNAPSHOT_SECONDS: u64 = 31 * 24 * 60 * 60;
pub const MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS: u16 = 6;
pub const MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS: u16 = 120;

const POLICY_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_POLICY_V1";
const ACTIVATION_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_ACTIVATION_V1";
const LEAF_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_LEAF_V1";
const NODE_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_NODE_V1";
const TXSET_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_TXSET_V1";
const OUTPUTS_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_OUTPUTS_V1";
const SIGNING_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_SIGNING_V1";
const SNAPSHOT_INPUT_TAG: &[u8] = b"P2POOLBTC_IDENA_AUTH_SNAPSHOT_INPUT_V1";
const MAX_EXPERIMENT_ID_BYTES: usize = 64;
const MAX_NETWORK_ID_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityPolicyV1 {
    pub schema_version: u16,
    pub experiment_id: String,
    pub bitcoin_network: String,
    pub bitcoin_fork_activation_id: String,
    pub share_work_activation_id: String,
    pub registry_contract_address: String,
    pub idena_finalized_height: u64,
    pub idena_finalized_timestamp: u64,
    pub idena_finalized_block_hash: String,
    pub idena_next_validation_timestamp: u64,
    pub authorization_root: String,
    pub authorized_identity_count: u32,
    pub bitcoin_activation_height: u64,
    pub bitcoin_expiry_height: u64,
    pub bitcoin_expiry_mtp: u64,
    pub max_proof_depth: u8,
    pub require_share_work_commitment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityActivationManifestV1 {
    pub schema_version: String,
    pub profile_revision: u16,
    pub status: String,
    pub launch_enabled: bool,
    pub activation_id: String,
    pub experiment_id: String,
    pub predecessor_activation_id: String,
    pub consensus_ruleset: String,
    pub bitcoin_core_upstream_commit: String,
    pub bitcoin_core_patch_series_sha256: String,
    pub authorization_parent_height: u64,
    pub authorization_parent_hash: String,
    pub bitcoin_network: String,
    pub bitcoin_datadir: String,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub message_start_hex: String,
    pub consensus_policy_hash: String,
    pub require_fresh_datadir: bool,
    pub history_reinterpreted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityLeafV1 {
    pub idena_address: String,
    pub identity_state: IdenaStatus,
    pub mining_pubkey_xonly: String,
    pub registry_commitment: String,
    pub registration_sequence: u32,
    pub registration_block: u64,
    pub registration_epoch: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityProofV1 {
    pub leaf_index: u32,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityAuthorizationV1 {
    pub schema_version: u8,
    pub policy_hash: String,
    pub leaf: ConsensusIdentityLeafV1,
    pub proof: ConsensusIdentityProofV1,
    pub block_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentitySnapshotBlockV1 {
    pub height: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub identity_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityStateRecordV1 {
    pub address: String,
    pub state: IdenaStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentityRegistrationRecordV1 {
    pub owner_address: String,
    pub current_sequence: u32,
    pub contract_record: String,
    pub registration: MinerRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentitySnapshotInputV1 {
    pub schema_version: String,
    pub status: String,
    pub experiment_id: String,
    pub identity_rows_assurance: String,
    pub registry_contract_address: String,
    pub capture_epoch: u16,
    pub next_validation_timestamp: u64,
    pub finality_confirmations: u16,
    pub capture_block: ConsensusIdentitySnapshotBlockV1,
    pub finality_chain: Vec<ConsensusIdentitySnapshotBlockV1>,
    pub identities: Vec<ConsensusIdentityStateRecordV1>,
    pub registry_registered_count: u32,
    pub registry_registered_miners: Vec<String>,
    pub registrations: Vec<ConsensusIdentityRegistrationRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentitySnapshotEntryV1 {
    pub leaf: ConsensusIdentityLeafV1,
    pub proof: ConsensusIdentityProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusIdentitySnapshotBundleV1 {
    pub schema_version: String,
    pub status: String,
    pub experiment_id: String,
    pub registry_contract_address: String,
    pub source_input_hash: String,
    pub idena_finalized_height: u64,
    pub idena_finalized_timestamp: u64,
    pub idena_finalized_block_hash: String,
    pub idena_identity_root: String,
    pub idena_finality_height: u64,
    pub idena_finality_block_hash: String,
    pub finality_confirmations: u16,
    pub idena_next_validation_timestamp: u64,
    pub authorization_root: String,
    pub authorized_identity_count: u32,
    pub entries: Vec<ConsensusIdentitySnapshotEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusIdentitySigningContext {
    pub activation_id: String,
    pub previous_block_hash: String,
    pub block_height: u64,
    pub block_version: i32,
    pub block_bits: u32,
    pub median_time_past: u64,
    pub transaction_set_hash: [u8; 32],
    pub coinbase_outputs_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsensusIdentityError {
    #[error("unsupported consensus identity policy version {0}")]
    UnsupportedPolicyVersion(u16),
    #[error("unsupported consensus identity authorization version {0}")]
    UnsupportedAuthorizationVersion(u8),
    #[error("invalid consensus identity field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("identity state is not eligible for Bitcoin block production")]
    IneligibleIdentity,
    #[error("authorization policy hash {actual} does not match expected {expected}")]
    PolicyMismatch { expected: String, actual: String },
    #[error("authorization proof does not match the pinned root")]
    InvalidMerkleProof,
    #[error("authorization signature is invalid")]
    InvalidSignature,
    #[error("authorization is outside its Bitcoin activation window")]
    OutsideActivationWindow,
    #[error("coinbase must contain exactly one P2IA1 authorization output, got {0}")]
    AuthorizationOutputCount(usize),
    #[error("coinbase must contain exactly one P2SW1 share-work output, got {0}")]
    ShareWorkOutputCount(usize),
    #[error("authorization output is malformed")]
    MalformedAuthorizationOutput,
    #[error("authorization Merkle set is empty")]
    EmptyAuthorizationSet,
}

impl ConsensusIdentityPolicyV1 {
    pub fn normalized(mut self) -> Self {
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.bitcoin_network = self.bitcoin_network.to_ascii_lowercase();
        self.bitcoin_fork_activation_id = self.bitcoin_fork_activation_id.to_ascii_lowercase();
        self.share_work_activation_id = self.share_work_activation_id.to_ascii_lowercase();
        self.registry_contract_address = self.registry_contract_address.to_ascii_lowercase();
        self.idena_finalized_block_hash = self.idena_finalized_block_hash.to_ascii_lowercase();
        self.authorization_root = self.authorization_root.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), ConsensusIdentityError> {
        if self.schema_version != CONSENSUS_IDENTITY_POLICY_VERSION {
            return Err(ConsensusIdentityError::UnsupportedPolicyVersion(
                self.schema_version,
            ));
        }
        validate_experiment_id(&self.experiment_id)
            .map_err(|error| invalid("experiment_id", error.to_string()))?;
        validate_ascii_identifier(
            "bitcoin_network",
            &self.bitcoin_network,
            MAX_NETWORK_ID_BYTES,
        )?;
        validate_hex(
            "bitcoin_fork_activation_id",
            &self.bitcoin_fork_activation_id,
            32,
            false,
        )?;
        validate_hex(
            "share_work_activation_id",
            &self.share_work_activation_id,
            32,
            false,
        )?;
        validate_hex(
            "registry_contract_address",
            &self.registry_contract_address,
            20,
            true,
        )?;
        if self.idena_finalized_height == 0 {
            return Err(invalid("idena_finalized_height", "must be positive"));
        }
        if self.idena_finalized_timestamp == 0
            || self.idena_next_validation_timestamp <= self.idena_finalized_timestamp
            || self.idena_next_validation_timestamp - self.idena_finalized_timestamp
                > MAX_CONSENSUS_IDENTITY_SNAPSHOT_SECONDS
        {
            return Err(invalid(
                "idena_snapshot_window",
                format!(
                    "must be positive, ordered, and no longer than {MAX_CONSENSUS_IDENTITY_SNAPSHOT_SECONDS} seconds"
                ),
            ));
        }
        validate_hex(
            "idena_finalized_block_hash",
            &self.idena_finalized_block_hash,
            32,
            true,
        )?;
        validate_hex("authorization_root", &self.authorization_root, 32, false)?;
        if self.authorized_identity_count == 0 {
            return Err(invalid("authorized_identity_count", "must be positive"));
        }
        if self.authorized_identity_count > (1u32 << MAX_CONSENSUS_IDENTITY_PROOF_DEPTH) {
            return Err(invalid(
                "authorized_identity_count",
                format!(
                    "must fit within the {MAX_CONSENSUS_IDENTITY_PROOF_DEPTH}-level authorization tree"
                ),
            ));
        }
        if self.bitcoin_activation_height == 0
            || self.bitcoin_expiry_height < self.bitcoin_activation_height
        {
            return Err(invalid(
                "bitcoin_activation_height",
                "must be positive and no later than bitcoin_expiry_height",
            ));
        }
        if self.bitcoin_expiry_mtp <= self.idena_finalized_timestamp
            || self.bitcoin_expiry_mtp > self.idena_next_validation_timestamp
        {
            return Err(invalid(
                "bitcoin_expiry_mtp",
                "must be after the finalized snapshot and no later than the next Idena validation",
            ));
        }
        if self.max_proof_depth as usize > MAX_CONSENSUS_IDENTITY_PROOF_DEPTH {
            return Err(invalid(
                "max_proof_depth",
                format!("must be <= {MAX_CONSENSUS_IDENTITY_PROOF_DEPTH}"),
            ));
        }
        if required_merkle_proof_depth(self.authorized_identity_count)?
            > self.max_proof_depth as usize
        {
            return Err(invalid(
                "max_proof_depth",
                "is too small for authorized_identity_count",
            ));
        }
        if !self.require_share_work_commitment {
            return Err(invalid(
                "require_share_work_commitment",
                "must be true for the consensus-enforced successor",
            ));
        }
        Ok(())
    }

    pub fn commitment_hash(&self) -> Result<String, ConsensusIdentityError> {
        Ok(hash_hex(self.commitment_hash_bytes()?))
    }

    pub fn commitment_hash_bytes(&self) -> Result<[u8; 32], ConsensusIdentityError> {
        let policy = self.clone().normalized();
        policy.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&policy.schema_version.to_le_bytes());
        append_bounded_ascii(&mut bytes, &policy.experiment_id, MAX_EXPERIMENT_ID_BYTES)?;
        append_bounded_ascii(&mut bytes, &policy.bitcoin_network, MAX_NETWORK_ID_BYTES)?;
        bytes.extend_from_slice(&decode_hex_exact(
            "bitcoin_fork_activation_id",
            &policy.bitcoin_fork_activation_id,
            32,
            false,
        )?);
        bytes.extend_from_slice(&decode_hex_exact(
            "share_work_activation_id",
            &policy.share_work_activation_id,
            32,
            false,
        )?);
        bytes.extend_from_slice(&decode_hex_exact(
            "registry_contract_address",
            &policy.registry_contract_address,
            20,
            true,
        )?);
        bytes.extend_from_slice(&policy.idena_finalized_height.to_le_bytes());
        bytes.extend_from_slice(&policy.idena_finalized_timestamp.to_le_bytes());
        bytes.extend_from_slice(&decode_hex_exact(
            "idena_finalized_block_hash",
            &policy.idena_finalized_block_hash,
            32,
            true,
        )?);
        bytes.extend_from_slice(&policy.idena_next_validation_timestamp.to_le_bytes());
        bytes.extend_from_slice(&decode_hex_exact(
            "authorization_root",
            &policy.authorization_root,
            32,
            false,
        )?);
        bytes.extend_from_slice(&policy.authorized_identity_count.to_le_bytes());
        bytes.extend_from_slice(&policy.bitcoin_activation_height.to_le_bytes());
        bytes.extend_from_slice(&policy.bitcoin_expiry_height.to_le_bytes());
        bytes.extend_from_slice(&policy.bitcoin_expiry_mtp.to_le_bytes());
        bytes.push(policy.max_proof_depth);
        bytes.push(u8::from(policy.require_share_work_commitment));
        Ok(sha256_tagged(POLICY_TAG, &bytes))
    }

    pub fn validate_height(&self, height: u64) -> Result<(), ConsensusIdentityError> {
        if height < self.bitcoin_activation_height || height > self.bitcoin_expiry_height {
            return Err(ConsensusIdentityError::OutsideActivationWindow);
        }
        Ok(())
    }

    pub fn validate_block_window(
        &self,
        height: u64,
        median_time_past: u64,
    ) -> Result<(), ConsensusIdentityError> {
        self.validate_height(height)?;
        if median_time_past < self.idena_finalized_timestamp
            || median_time_past >= self.bitcoin_expiry_mtp
        {
            return Err(ConsensusIdentityError::OutsideActivationWindow);
        }
        Ok(())
    }
}

impl ConsensusIdentityActivationManifestV1 {
    pub fn normalized(mut self) -> Self {
        self.schema_version = self.schema_version.to_ascii_lowercase();
        self.status = self.status.to_ascii_lowercase();
        self.activation_id = self.activation_id.to_ascii_lowercase();
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.predecessor_activation_id = self.predecessor_activation_id.to_ascii_lowercase();
        self.consensus_ruleset = self.consensus_ruleset.to_ascii_lowercase();
        self.bitcoin_core_upstream_commit = self.bitcoin_core_upstream_commit.to_ascii_lowercase();
        self.bitcoin_core_patch_series_sha256 =
            self.bitcoin_core_patch_series_sha256.to_ascii_lowercase();
        self.authorization_parent_hash = self.authorization_parent_hash.to_ascii_lowercase();
        self.bitcoin_network = self.bitcoin_network.to_ascii_lowercase();
        self.bitcoin_datadir = self.bitcoin_datadir.to_ascii_lowercase();
        self.message_start_hex = self.message_start_hex.to_ascii_lowercase();
        self.consensus_policy_hash = self.consensus_policy_hash.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), ConsensusIdentityError> {
        let manifest = self.clone().normalized();
        if &manifest != self {
            return Err(invalid(
                "canonical_encoding",
                "manifest fields must already use canonical lowercase encoding",
            ));
        }
        if manifest.schema_version != CONSENSUS_IDENTITY_ACTIVATION_SCHEMA {
            return Err(invalid(
                "schema_version",
                format!("must be {CONSENSUS_IDENTITY_ACTIVATION_SCHEMA}"),
            ));
        }
        if manifest.profile_revision == 0 {
            return Err(invalid("profile_revision", "must be positive"));
        }
        match (manifest.status.as_str(), manifest.launch_enabled) {
            ("experimental-candidate", false) | ("experimental-active", true) => {}
            _ => {
                return Err(invalid(
                    "status",
                    "must be experimental-candidate with launch disabled or experimental-active with launch enabled",
                ));
            }
        }
        validate_experiment_id(&manifest.experiment_id)
            .map_err(|error| invalid("experiment_id", error.to_string()))?;
        validate_hex(
            "predecessor_activation_id",
            &manifest.predecessor_activation_id,
            32,
            false,
        )?;
        validate_ascii_identifier("consensus_ruleset", &manifest.consensus_ruleset, 64)?;
        validate_hex(
            "bitcoin_core_upstream_commit",
            &manifest.bitcoin_core_upstream_commit,
            20,
            false,
        )?;
        validate_hex(
            "bitcoin_core_patch_series_sha256",
            &manifest.bitcoin_core_patch_series_sha256,
            32,
            false,
        )?;
        if manifest.authorization_parent_height == 0 {
            return Err(invalid("authorization_parent_height", "must be positive"));
        }
        validate_hex(
            "authorization_parent_hash",
            &manifest.authorization_parent_hash,
            32,
            false,
        )?;
        if manifest.bitcoin_network != "pohw2" {
            return Err(invalid("bitcoin_network", "must be pohw2"));
        }
        validate_ascii_identifier("bitcoin_datadir", &manifest.bitcoin_datadir, 64)?;
        if manifest.p2p_port == 0
            || manifest.rpc_port == 0
            || manifest.p2p_port == manifest.rpc_port
        {
            return Err(invalid(
                "ports",
                "P2P and RPC ports must be distinct and nonzero",
            ));
        }
        validate_hex("message_start_hex", &manifest.message_start_hex, 4, false)?;
        validate_hex(
            "consensus_policy_hash",
            &manifest.consensus_policy_hash,
            32,
            false,
        )?;
        if !manifest.require_fresh_datadir || manifest.history_reinterpreted {
            return Err(invalid(
                "history",
                "successor must require a fresh datadir and must not reinterpret prior history",
            ));
        }
        let expected = manifest.recomputed_activation_id()?;
        if manifest.activation_id != expected {
            return Err(invalid(
                "activation_id",
                format!("must match canonical activation hash {expected}"),
            ));
        }
        Ok(())
    }

    pub fn validate_for_launch(&self) -> Result<(), ConsensusIdentityError> {
        self.validate()?;
        if !self.launch_enabled || self.status != "experimental-active" {
            return Err(invalid(
                "launch_enabled",
                "candidate manifest is intentionally not launchable",
            ));
        }
        Ok(())
    }

    pub fn recomputed_activation_id(&self) -> Result<String, ConsensusIdentityError> {
        let manifest = self.clone().normalized();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&manifest.profile_revision.to_le_bytes());
        append_bounded_ascii(&mut bytes, &manifest.schema_version, 64)?;
        append_bounded_ascii(&mut bytes, &manifest.status, 32)?;
        bytes.push(u8::from(manifest.launch_enabled));
        append_bounded_ascii(&mut bytes, &manifest.experiment_id, MAX_EXPERIMENT_ID_BYTES)?;
        bytes.extend_from_slice(&decode_hash(&manifest.predecessor_activation_id)?);
        append_bounded_ascii(&mut bytes, &manifest.consensus_ruleset, 64)?;
        bytes.extend_from_slice(&decode_hex_exact(
            "bitcoin_core_upstream_commit",
            &manifest.bitcoin_core_upstream_commit,
            20,
            false,
        )?);
        bytes.extend_from_slice(&decode_hash(&manifest.bitcoin_core_patch_series_sha256)?);
        bytes.extend_from_slice(&manifest.authorization_parent_height.to_le_bytes());
        bytes.extend_from_slice(&decode_hash(&manifest.authorization_parent_hash)?);
        append_bounded_ascii(&mut bytes, &manifest.bitcoin_network, MAX_NETWORK_ID_BYTES)?;
        append_bounded_ascii(&mut bytes, &manifest.bitcoin_datadir, 64)?;
        bytes.extend_from_slice(&manifest.p2p_port.to_le_bytes());
        bytes.extend_from_slice(&manifest.rpc_port.to_le_bytes());
        bytes.extend_from_slice(&decode_hex_exact(
            "message_start_hex",
            &manifest.message_start_hex,
            4,
            false,
        )?);
        bytes.extend_from_slice(&decode_hash(&manifest.consensus_policy_hash)?);
        bytes.push(u8::from(manifest.require_fresh_datadir));
        bytes.push(u8::from(manifest.history_reinterpreted));
        Ok(hash_hex(sha256_tagged(ACTIVATION_TAG, &bytes)))
    }

    pub fn validate_policy(
        &self,
        policy: &ConsensusIdentityPolicyV1,
    ) -> Result<(), ConsensusIdentityError> {
        self.validate()?;
        policy.validate()?;
        if self.experiment_id != policy.experiment_id
            || self.bitcoin_network != policy.bitcoin_network
            || self.consensus_policy_hash != policy.commitment_hash()?
        {
            return Err(invalid(
                "consensus_policy_hash",
                "activation manifest and consensus policy do not match",
            ));
        }
        Ok(())
    }
}

impl ConsensusIdentitySnapshotBlockV1 {
    pub fn normalized(mut self) -> Self {
        self.hash = self.hash.to_ascii_lowercase();
        self.parent_hash = self.parent_hash.to_ascii_lowercase();
        self.identity_root = self.identity_root.to_ascii_lowercase();
        self
    }

    fn validate(&self, label: &str) -> Result<(), ConsensusIdentityError> {
        if self.height == 0 || self.timestamp == 0 {
            return Err(invalid(label, "height and timestamp must be positive"));
        }
        validate_hex(&format!("{label}.hash"), &self.hash, 32, true)?;
        validate_hex(&format!("{label}.parent_hash"), &self.parent_hash, 32, true)?;
        validate_hex(
            &format!("{label}.identity_root"),
            &self.identity_root,
            32,
            true,
        )
    }
}

impl ConsensusIdentitySnapshotInputV1 {
    pub fn normalized(mut self) -> Self {
        self.schema_version = self.schema_version.to_ascii_lowercase();
        self.status = self.status.to_ascii_lowercase();
        self.experiment_id = self.experiment_id.to_ascii_lowercase();
        self.identity_rows_assurance = self.identity_rows_assurance.to_ascii_lowercase();
        self.registry_contract_address = self.registry_contract_address.to_ascii_lowercase();
        self.capture_block = self.capture_block.normalized();
        self.finality_chain = self
            .finality_chain
            .into_iter()
            .map(ConsensusIdentitySnapshotBlockV1::normalized)
            .collect();
        self.identities = self
            .identities
            .into_iter()
            .map(|mut identity| {
                identity.address = identity.address.to_ascii_lowercase();
                identity
            })
            .collect();
        self.identities
            .sort_by(|left, right| left.address.cmp(&right.address));
        self.registry_registered_miners = self
            .registry_registered_miners
            .into_iter()
            .map(|miner| miner.to_ascii_lowercase())
            .collect();
        self.registry_registered_miners.sort();
        self.registrations = self
            .registrations
            .into_iter()
            .map(|mut record| {
                record.owner_address = record.owner_address.to_ascii_lowercase();
                record.registration = record.registration.normalized();
                record
            })
            .collect();
        self.registrations
            .sort_by(|left, right| left.registration.miner_id.cmp(&right.registration.miner_id));
        self
    }

    pub fn validate(&self) -> Result<(), ConsensusIdentityError> {
        let normalized = self.clone().normalized();
        if &normalized != self {
            return Err(invalid(
                "snapshot_input.canonical_encoding",
                "snapshot fields and arrays must already use canonical lowercase ordering",
            ));
        }
        if self.schema_version != CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA {
            return Err(invalid(
                "snapshot_input.schema_version",
                format!("must be {CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA}"),
            ));
        }
        if self.status != "finalized-candidate-input" {
            return Err(invalid(
                "snapshot_input.status",
                "must be finalized-candidate-input",
            ));
        }
        if self.identity_rows_assurance != CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN
        {
            return Err(invalid(
                "snapshot_input.identity_rows_assurance",
                format!(
                    "v1 captures must declare {CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN} and remain inactive"
                ),
            ));
        }
        validate_experiment_id(&self.experiment_id)
            .map_err(|error| invalid("snapshot_input.experiment_id", error.to_string()))?;
        validate_hex(
            "snapshot_input.registry_contract_address",
            &self.registry_contract_address,
            20,
            true,
        )?;
        if !(MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS
            ..=MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS)
            .contains(&self.finality_confirmations)
        {
            return Err(invalid(
                "snapshot_input.finality_confirmations",
                format!(
                    "must be between {MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS} and {MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS}"
                ),
            ));
        }
        self.capture_block
            .validate("snapshot_input.capture_block")?;
        if self.next_validation_timestamp <= self.capture_block.timestamp
            || self.next_validation_timestamp - self.capture_block.timestamp
                > MAX_CONSENSUS_IDENTITY_SNAPSHOT_SECONDS
        {
            return Err(invalid(
                "snapshot_input.next_validation_timestamp",
                "must follow the capture block by no more than the snapshot limit",
            ));
        }
        let expected_chain_len = usize::from(self.finality_confirmations) + 1;
        if self.finality_chain.len() != expected_chain_len
            || self.finality_chain.first() != Some(&self.capture_block)
        {
            return Err(invalid(
                "snapshot_input.finality_chain",
                "must start at the capture block and contain exactly the declared confirmations",
            ));
        }
        for (index, block) in self.finality_chain.iter().enumerate() {
            block.validate(&format!("snapshot_input.finality_chain[{index}]"))?;
            if block.timestamp >= self.next_validation_timestamp {
                return Err(invalid(
                    "snapshot_input.finality_chain",
                    "must finalize before the next Idena validation",
                ));
            }
            if let Some(parent) = index
                .checked_sub(1)
                .and_then(|parent_index| self.finality_chain.get(parent_index))
            {
                if block.height != parent.height + 1
                    || block.parent_hash != parent.hash
                    || block.timestamp < parent.timestamp
                {
                    return Err(invalid(
                        "snapshot_input.finality_chain",
                        "is not a contiguous nondecreasing hash-linked chain",
                    ));
                }
            }
        }
        if self.identities.is_empty() {
            return Err(invalid(
                "snapshot_input.identities",
                "complete identity export must not be empty",
            ));
        }
        let mut previous_identity: Option<&str> = None;
        let mut identity_states = BTreeMap::new();
        for identity in &self.identities {
            validate_hex(
                "snapshot_input.identities.address",
                &identity.address,
                20,
                true,
            )?;
            if previous_identity.is_some_and(|previous| previous >= identity.address.as_str()) {
                return Err(invalid(
                    "snapshot_input.identities",
                    "must be strictly sorted without duplicate addresses",
                ));
            }
            previous_identity = Some(&identity.address);
            identity_states.insert(identity.address.as_str(), &identity.state);
        }
        if self.registry_registered_count as usize > MAX_CHECKPOINT_MINERS
            || self.registry_registered_count as usize != self.registry_registered_miners.len()
            || self.registry_registered_count as usize != self.registrations.len()
        {
            return Err(invalid(
                "snapshot_input.registry_registered_count",
                "must exactly cover the bounded contract miner index and registration records",
            ));
        }
        let mut previous_miner: Option<&str> = None;
        for miner in &self.registry_registered_miners {
            validate_ascii_identifier("snapshot_input.registry_miner", miner, 64)?;
            if previous_miner.is_some_and(|previous| previous >= miner.as_str()) {
                return Err(invalid(
                    "snapshot_input.registry_registered_miners",
                    "must be strictly sorted without duplicate miner IDs",
                ));
            }
            previous_miner = Some(miner);
        }
        if self
            .registrations
            .iter()
            .map(|record| record.registration.miner_id.as_str())
            .ne(self.registry_registered_miners.iter().map(String::as_str))
        {
            return Err(invalid(
                "snapshot_input.registrations",
                "must exactly cover the contract registered-miner index",
            ));
        }
        let mut owners = BTreeSet::new();
        let mut mining_keys = BTreeSet::new();
        for record in &self.registrations {
            validate_hex(
                "snapshot_input.registration.owner_address",
                &record.owner_address,
                20,
                true,
            )?;
            if !owners.insert(record.owner_address.as_str()) {
                return Err(invalid(
                    "snapshot_input.registrations",
                    "must not contain duplicate owner identities",
                ));
            }
            if !mining_keys.insert(record.registration.mining_pubkey_hex.as_str()) {
                return Err(invalid(
                    "snapshot_input.registrations",
                    "must not assign one mining key to multiple registrations",
                ));
            }
            if record.registration.idena_address != record.owner_address {
                return Err(invalid(
                    "snapshot_input.registration.owner_address",
                    "does not match the signed registration identity",
                ));
            }
            record
                .registration
                .verify_mining_signature()
                .map_err(|error| invalid("snapshot_input.registration", error.to_string()))?;
            record
                .registration
                .verify_idena_ownership_signature()
                .map_err(|error| invalid("snapshot_input.registration", error.to_string()))?;
            let anchor = record
                .registration
                .require_registry_anchor()
                .map_err(|error| invalid("snapshot_input.registration", error.to_string()))?;
            let registration_timestamp =
                u64::try_from(anchor.registration_timestamp).map_err(|_| {
                    invalid(
                        "snapshot_input.registration.registry_anchor",
                        "registration timestamp must not be negative",
                    )
                })?;
            if anchor.contract_address != self.registry_contract_address
                || anchor.experiment_id != self.experiment_id
                || anchor.registration_sequence != record.current_sequence
                || anchor.registration_block > self.capture_block.height
                || registration_timestamp > self.capture_block.timestamp
            {
                return Err(invalid(
                    "snapshot_input.registration.registry_anchor",
                    "does not match the captured contract, sequence, experiment, or block boundary",
                ));
            }
            let (record_miner, parsed_anchor) = MinerRegistryAnchorV1::from_canonical_record_line(
                self.registry_contract_address.clone(),
                self.experiment_id.clone(),
                &record.contract_record,
            )
            .map_err(|error| invalid("snapshot_input.contract_record", error.to_string()))?;
            if record_miner != record.registration.miner_id || &parsed_anchor != anchor {
                return Err(invalid(
                    "snapshot_input.contract_record",
                    "does not match the signed latest registration",
                ));
            }
            if !identity_states.contains_key(record.owner_address.as_str()) {
                return Err(invalid(
                    "snapshot_input.identities",
                    "is missing a registered owner identity",
                ));
            }
        }
        Ok(())
    }

    pub fn source_input_hash(&self) -> Result<String, ConsensusIdentityError> {
        self.validate()?;
        Ok(hash_hex(sha256_tagged(
            SNAPSHOT_INPUT_TAG,
            &canonical_json(self),
        )))
    }

    pub fn build_bundle(
        &self,
    ) -> Result<ConsensusIdentitySnapshotBundleV1, ConsensusIdentityError> {
        self.validate()?;
        let identity_states = self
            .identities
            .iter()
            .map(|identity| (identity.address.as_str(), identity.state.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut leaves = Vec::new();
        for record in &self.registrations {
            let state = identity_states
                .get(record.owner_address.as_str())
                .ok_or_else(|| {
                    invalid("snapshot_input.identities", "missing registration owner")
                })?;
            if state.is_block_eligible() {
                leaves.push(ConsensusIdentityLeafV1::from_registration(
                    &record.registration,
                    state.clone(),
                )?);
            }
        }
        leaves.sort_by(|left, right| left.idena_address.cmp(&right.idena_address));
        let (root, proofs) = build_authorization_root_and_proofs(&leaves)?;
        let finality = self
            .finality_chain
            .last()
            .ok_or(ConsensusIdentityError::EmptyAuthorizationSet)?;
        let bundle = ConsensusIdentitySnapshotBundleV1 {
            schema_version: CONSENSUS_IDENTITY_SNAPSHOT_BUNDLE_SCHEMA.to_string(),
            status: "finalized-inactive-input".to_string(),
            experiment_id: self.experiment_id.clone(),
            registry_contract_address: self.registry_contract_address.clone(),
            source_input_hash: self.source_input_hash()?,
            idena_finalized_height: self.capture_block.height,
            idena_finalized_timestamp: self.capture_block.timestamp,
            idena_finalized_block_hash: self.capture_block.hash.clone(),
            idena_identity_root: self.capture_block.identity_root.clone(),
            idena_finality_height: finality.height,
            idena_finality_block_hash: finality.hash.clone(),
            finality_confirmations: self.finality_confirmations,
            idena_next_validation_timestamp: self.next_validation_timestamp,
            authorization_root: hex::encode(root),
            authorized_identity_count: u32::try_from(leaves.len())
                .map_err(|_| invalid("snapshot_bundle.entries", "entry count exceeds u32"))?,
            entries: leaves
                .into_iter()
                .zip(proofs)
                .map(|(leaf, proof)| ConsensusIdentitySnapshotEntryV1 { leaf, proof })
                .collect(),
        };
        bundle.validate()?;
        Ok(bundle)
    }
}

impl ConsensusIdentitySnapshotBundleV1 {
    pub fn validate(&self) -> Result<(), ConsensusIdentityError> {
        if self.schema_version != CONSENSUS_IDENTITY_SNAPSHOT_BUNDLE_SCHEMA {
            return Err(invalid(
                "snapshot_bundle.schema_version",
                format!("must be {CONSENSUS_IDENTITY_SNAPSHOT_BUNDLE_SCHEMA}"),
            ));
        }
        if self.status != "finalized-inactive-input" {
            return Err(invalid(
                "snapshot_bundle.status",
                "must be finalized-inactive-input",
            ));
        }
        validate_experiment_id(&self.experiment_id)
            .map_err(|error| invalid("snapshot_bundle.experiment_id", error.to_string()))?;
        validate_hex(
            "snapshot_bundle.registry_contract_address",
            &self.registry_contract_address,
            20,
            true,
        )?;
        validate_hex(
            "snapshot_bundle.source_input_hash",
            &self.source_input_hash,
            32,
            false,
        )?;
        if self.idena_finalized_height == 0 || self.idena_finalized_timestamp == 0 {
            return Err(invalid(
                "snapshot_bundle.idena_finalized_height",
                "finalized height and timestamp must be positive",
            ));
        }
        validate_hex(
            "snapshot_bundle.idena_finalized_block_hash",
            &self.idena_finalized_block_hash,
            32,
            true,
        )?;
        validate_hex(
            "snapshot_bundle.idena_identity_root",
            &self.idena_identity_root,
            32,
            true,
        )?;
        validate_hex(
            "snapshot_bundle.idena_finality_block_hash",
            &self.idena_finality_block_hash,
            32,
            true,
        )?;
        if !(MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS
            ..=MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS)
            .contains(&self.finality_confirmations)
            || self
                .idena_finalized_height
                .checked_add(u64::from(self.finality_confirmations))
                != Some(self.idena_finality_height)
        {
            return Err(invalid(
                "snapshot_bundle.finality_confirmations",
                "must exactly connect the finalized and finality heights",
            ));
        }
        if self.idena_next_validation_timestamp <= self.idena_finalized_timestamp
            || self.idena_next_validation_timestamp - self.idena_finalized_timestamp
                > MAX_CONSENSUS_IDENTITY_SNAPSHOT_SECONDS
        {
            return Err(invalid(
                "snapshot_bundle.idena_next_validation_timestamp",
                "must follow the finalized timestamp by no more than the snapshot limit",
            ));
        }
        validate_hex(
            "snapshot_bundle.authorization_root",
            &self.authorization_root,
            32,
            false,
        )?;
        if self.authorized_identity_count == 0
            || self.authorized_identity_count as usize != self.entries.len()
            || self.entries.len() > MAX_CHECKPOINT_MINERS
        {
            return Err(invalid(
                "snapshot_bundle.authorized_identity_count",
                "must exactly match a nonempty bounded entry set",
            ));
        }
        let required_depth = required_merkle_proof_depth(self.authorized_identity_count)?;
        let expected_root = decode_hash(&self.authorization_root)?;
        let mut previous_identity: Option<&str> = None;
        let mut mining_keys = BTreeSet::new();
        for (position, entry) in self.entries.iter().enumerate() {
            entry.leaf.validate()?;
            if previous_identity
                .is_some_and(|previous| previous >= entry.leaf.idena_address.as_str())
                || !mining_keys.insert(entry.leaf.mining_pubkey_xonly.as_str())
            {
                return Err(invalid(
                    "snapshot_bundle.entries",
                    "must be strictly identity-sorted with unique mining keys",
                ));
            }
            previous_identity = Some(&entry.leaf.idena_address);
            if usize::try_from(entry.proof.leaf_index).ok() != Some(position)
                || entry.proof.siblings.len() != required_depth
            {
                return Err(ConsensusIdentityError::InvalidMerkleProof);
            }
            let mut hash = entry.leaf.leaf_hash()?;
            let mut index = entry.proof.leaf_index;
            for sibling in &entry.proof.siblings {
                let sibling = decode_hash(sibling)?;
                hash = if index & 1 == 0 {
                    merkle_parent(hash, sibling)
                } else {
                    merkle_parent(sibling, hash)
                };
                index >>= 1;
            }
            if index != 0 || hash != expected_root {
                return Err(ConsensusIdentityError::InvalidMerkleProof);
            }
        }
        Ok(())
    }

    pub fn validate_against_input(
        &self,
        input: &ConsensusIdentitySnapshotInputV1,
    ) -> Result<(), ConsensusIdentityError> {
        if &input.build_bundle()? != self {
            return Err(invalid(
                "snapshot_bundle.source_input_hash",
                "bundle does not exactly reproduce from the supplied snapshot input",
            ));
        }
        Ok(())
    }
}

impl ConsensusIdentityLeafV1 {
    pub fn from_registration(
        registration: &MinerRegistration,
        identity_state: IdenaStatus,
    ) -> Result<Self, ConsensusIdentityError> {
        let anchor = registration
            .registry_anchor
            .as_ref()
            .ok_or_else(|| invalid("registry_anchor", "is required"))?;
        let leaf = Self {
            idena_address: registration.idena_address.clone(),
            identity_state,
            mining_pubkey_xonly: registration.mining_pubkey_hex.clone(),
            registry_commitment: anchor.registration_commitment.clone(),
            registration_sequence: anchor.registration_sequence,
            registration_block: anchor.registration_block,
            registration_epoch: anchor.registration_epoch,
        }
        .normalized();
        leaf.validate()?;
        Ok(leaf)
    }

    pub fn validate_registration(
        &self,
        registration: &MinerRegistration,
    ) -> Result<(), ConsensusIdentityError> {
        let expected = Self::from_registration(registration, self.identity_state.clone())?;
        if self.clone().normalized() != expected {
            return Err(invalid(
                "authorization_leaf",
                "does not match the complete anchored miner registration",
            ));
        }
        Ok(())
    }

    pub fn normalized(mut self) -> Self {
        self.idena_address = self.idena_address.to_ascii_lowercase();
        self.mining_pubkey_xonly = self.mining_pubkey_xonly.to_ascii_lowercase();
        self.registry_commitment = self.registry_commitment.to_ascii_lowercase();
        self
    }

    pub fn validate(&self) -> Result<(), ConsensusIdentityError> {
        validate_hex("idena_address", &self.idena_address, 20, true)?;
        if !self.identity_state.is_block_eligible() {
            return Err(ConsensusIdentityError::IneligibleIdentity);
        }
        validate_hex("mining_pubkey_xonly", &self.mining_pubkey_xonly, 32, false)?;
        XOnlyPublicKey::from_str(&self.mining_pubkey_xonly)
            .map_err(|error| invalid("mining_pubkey_xonly", error.to_string()))?;
        validate_hex("registry_commitment", &self.registry_commitment, 32, false)?;
        if self.registration_sequence == 0 || self.registration_block == 0 {
            return Err(invalid(
                "registration",
                "sequence and block must be positive",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConsensusIdentityError> {
        let leaf = self.clone().normalized();
        leaf.validate()?;
        let mut bytes = Vec::with_capacity(99);
        bytes.extend_from_slice(&decode_hex_exact(
            "idena_address",
            &leaf.idena_address,
            20,
            true,
        )?);
        bytes.push(identity_state_code(&leaf.identity_state)?);
        bytes.extend_from_slice(&decode_hex_exact(
            "mining_pubkey_xonly",
            &leaf.mining_pubkey_xonly,
            32,
            false,
        )?);
        bytes.extend_from_slice(&decode_hex_exact(
            "registry_commitment",
            &leaf.registry_commitment,
            32,
            false,
        )?);
        bytes.extend_from_slice(&leaf.registration_sequence.to_le_bytes());
        bytes.extend_from_slice(&leaf.registration_block.to_le_bytes());
        bytes.extend_from_slice(&leaf.registration_epoch.to_le_bytes());
        Ok(bytes)
    }

    pub fn leaf_hash(&self) -> Result<[u8; 32], ConsensusIdentityError> {
        Ok(sha256_tagged(LEAF_TAG, &self.canonical_bytes()?))
    }
}

impl ConsensusIdentityAuthorizationV1 {
    pub fn unsigned(
        policy: &ConsensusIdentityPolicyV1,
        leaf: ConsensusIdentityLeafV1,
        proof: ConsensusIdentityProofV1,
    ) -> Result<Self, ConsensusIdentityError> {
        let authorization = Self {
            schema_version: CONSENSUS_IDENTITY_AUTHORIZATION_VERSION,
            policy_hash: policy.commitment_hash()?,
            leaf: leaf.normalized(),
            proof,
            block_signature_hex: "00".repeat(64),
        };
        authorization.validate_membership(policy)?;
        Ok(authorization)
    }

    pub fn sign(
        &mut self,
        policy: &ConsensusIdentityPolicyV1,
        context: &ConsensusIdentitySigningContext,
        keypair: &Keypair,
    ) -> Result<(), ConsensusIdentityError> {
        self.validate_membership(policy)?;
        let expected_pubkey = XOnlyPublicKey::from_keypair(keypair).0.to_string();
        if expected_pubkey != self.leaf.mining_pubkey_xonly {
            return Err(invalid(
                "mining_pubkey_xonly",
                "does not match the signing key",
            ));
        }
        let signature = Secp256k1::new().sign_schnorr_no_aux_rand(
            &Message::from_digest(self.signing_hash(policy, context)?),
            keypair,
        );
        self.block_signature_hex = signature.to_string();
        Ok(())
    }

    pub fn verify(
        &self,
        policy: &ConsensusIdentityPolicyV1,
        context: &ConsensusIdentitySigningContext,
    ) -> Result<(), ConsensusIdentityError> {
        self.validate_membership(policy)?;
        policy.validate_height(context.block_height)?;
        validate_hex(
            "previous_block_hash",
            &context.previous_block_hash,
            32,
            false,
        )?;
        validate_hex("block_signature_hex", &self.block_signature_hex, 64, false)?;
        let signature = Signature::from_str(&self.block_signature_hex)
            .map_err(|_| ConsensusIdentityError::InvalidSignature)?;
        let pubkey = XOnlyPublicKey::from_str(&self.leaf.mining_pubkey_xonly)
            .map_err(|_| ConsensusIdentityError::InvalidSignature)?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.signing_hash(policy, context)?),
                &pubkey,
            )
            .map_err(|_| ConsensusIdentityError::InvalidSignature)
    }

    pub fn signing_hash(
        &self,
        policy: &ConsensusIdentityPolicyV1,
        context: &ConsensusIdentitySigningContext,
    ) -> Result<[u8; 32], ConsensusIdentityError> {
        policy.validate_block_window(context.block_height, context.median_time_past)?;
        let mut bytes = Vec::with_capacity(216);
        bytes.extend_from_slice(&decode_hex_exact(
            "activation_id",
            &context.activation_id,
            32,
            false,
        )?);
        bytes.extend_from_slice(&policy.commitment_hash_bytes()?);
        bytes.extend_from_slice(&self.leaf.leaf_hash()?);
        bytes.extend_from_slice(&decode_hex_exact(
            "previous_block_hash",
            &context.previous_block_hash,
            32,
            false,
        )?);
        bytes.extend_from_slice(&context.block_height.to_le_bytes());
        bytes.extend_from_slice(&context.block_version.to_le_bytes());
        bytes.extend_from_slice(&context.block_bits.to_le_bytes());
        bytes.extend_from_slice(&context.transaction_set_hash);
        bytes.extend_from_slice(&context.coinbase_outputs_hash);
        Ok(sha256_tagged(SIGNING_TAG, &bytes))
    }

    pub fn validate_membership(
        &self,
        policy: &ConsensusIdentityPolicyV1,
    ) -> Result<(), ConsensusIdentityError> {
        if self.schema_version != CONSENSUS_IDENTITY_AUTHORIZATION_VERSION {
            return Err(ConsensusIdentityError::UnsupportedAuthorizationVersion(
                self.schema_version,
            ));
        }
        policy.validate()?;
        self.leaf.validate()?;
        let expected_policy = policy.commitment_hash()?;
        validate_hex("policy_hash", &self.policy_hash, 32, false)?;
        if self.policy_hash != expected_policy {
            return Err(ConsensusIdentityError::PolicyMismatch {
                expected: expected_policy,
                actual: self.policy_hash.clone(),
            });
        }
        if self.proof.siblings.len() > policy.max_proof_depth as usize
            || self.proof.siblings.len() > MAX_CONSENSUS_IDENTITY_PROOF_DEPTH
            || self.proof.leaf_index >= policy.authorized_identity_count
            || self.proof.siblings.len()
                != required_merkle_proof_depth(policy.authorized_identity_count)?
        {
            return Err(ConsensusIdentityError::InvalidMerkleProof);
        }
        let mut hash = self.leaf.leaf_hash()?;
        let mut index = self.proof.leaf_index;
        for sibling in &self.proof.siblings {
            let sibling = decode_hash(sibling)?;
            hash = if index & 1 == 0 {
                merkle_parent(hash, sibling)
            } else {
                merkle_parent(sibling, hash)
            };
            index >>= 1;
        }
        if index != 0
            || hash
                != decode_hash(&policy.authorization_root)
                    .map_err(|_| ConsensusIdentityError::InvalidMerkleProof)?
        {
            return Err(ConsensusIdentityError::InvalidMerkleProof);
        }
        Ok(())
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, ConsensusIdentityError> {
        validate_hex("block_signature_hex", &self.block_signature_hex, 64, false)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CONSENSUS_IDENTITY_MAGIC);
        bytes.push(self.schema_version);
        bytes.extend_from_slice(&decode_hash(&self.policy_hash)?);
        bytes.extend_from_slice(&self.leaf.canonical_bytes()?);
        bytes.extend_from_slice(&self.proof.leaf_index.to_le_bytes());
        bytes.push(
            u8::try_from(self.proof.siblings.len())
                .map_err(|_| invalid("siblings", "proof depth does not fit in one byte"))?,
        );
        for sibling in &self.proof.siblings {
            bytes.extend_from_slice(&decode_hash(sibling)?);
        }
        bytes.extend_from_slice(&decode_hex_exact(
            "block_signature_hex",
            &self.block_signature_hex,
            64,
            false,
        )?);
        Ok(bytes)
    }

    pub fn op_return_script_pubkey_hex(&self) -> Result<String, ConsensusIdentityError> {
        let payload = self.payload_bytes()?;
        let mut script = vec![0x6a];
        append_minimal_push(&mut script, &payload)?;
        Ok(hex::encode(script))
    }

    pub fn from_op_return_script(script_hex: &str) -> Result<Self, ConsensusIdentityError> {
        let script = hex::decode(script_hex)
            .map_err(|_| ConsensusIdentityError::MalformedAuthorizationOutput)?;
        let payload = parse_single_minimal_op_return(&script)?;
        Self::from_payload_bytes(payload)
    }

    pub fn from_payload_bytes(bytes: &[u8]) -> Result<Self, ConsensusIdentityError> {
        const LEAF_BYTES: usize = 99;
        const FIXED_BYTES: usize = 5 + 1 + 32 + LEAF_BYTES + 4 + 1 + 64;
        if bytes.len() < FIXED_BYTES || &bytes[..5] != CONSENSUS_IDENTITY_MAGIC {
            return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
        }
        let version = bytes[5];
        let mut cursor = 6usize;
        let policy_hash = take(bytes, &mut cursor, 32)?;
        let leaf_bytes = take(bytes, &mut cursor, LEAF_BYTES)?;
        let leaf = decode_leaf(leaf_bytes)?;
        let leaf_index = u32::from_le_bytes(take_array(bytes, &mut cursor)?);
        let depth = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(ConsensusIdentityError::MalformedAuthorizationOutput)?
            as usize;
        if depth > MAX_CONSENSUS_IDENTITY_PROOF_DEPTH || bytes.len() != FIXED_BYTES + depth * 32 {
            return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
        }
        let mut siblings = Vec::with_capacity(depth);
        for _ in 0..depth {
            siblings.push(hex::encode(take(bytes, &mut cursor, 32)?));
        }
        let signature = take(bytes, &mut cursor, 64)?;
        if cursor != bytes.len() {
            return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
        }
        Ok(Self {
            schema_version: version,
            policy_hash: hex::encode(policy_hash),
            leaf,
            proof: ConsensusIdentityProofV1 {
                leaf_index,
                siblings,
            },
            block_signature_hex: hex::encode(signature),
        })
    }
}

pub fn build_authorization_root_and_proofs(
    leaves: &[ConsensusIdentityLeafV1],
) -> Result<([u8; 32], Vec<ConsensusIdentityProofV1>), ConsensusIdentityError> {
    if leaves.is_empty() {
        return Err(ConsensusIdentityError::EmptyAuthorizationSet);
    }
    if leaves.len() > (1usize << MAX_CONSENSUS_IDENTITY_PROOF_DEPTH) {
        return Err(invalid(
            "leaves",
            format!(
                "authorization set exceeds {} entries",
                1usize << MAX_CONSENSUS_IDENTITY_PROOF_DEPTH
            ),
        ));
    }
    let mut previous_address: Option<String> = None;
    let mut mining_keys = std::collections::BTreeSet::new();
    for leaf in leaves {
        let leaf = leaf.clone().normalized();
        leaf.validate()?;
        if previous_address
            .as_ref()
            .is_some_and(|previous| previous >= &leaf.idena_address)
        {
            return Err(invalid(
                "leaves",
                "must be strictly sorted by normalized Idena address without duplicates",
            ));
        }
        previous_address = Some(leaf.idena_address);
        if !mining_keys.insert(leaf.mining_pubkey_xonly) {
            return Err(invalid(
                "leaves",
                "must not assign one mining key to multiple Idena identities",
            ));
        }
    }
    let mut nodes = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| Ok((leaf.leaf_hash()?, vec![index])))
        .collect::<Result<Vec<_>, ConsensusIdentityError>>()?;
    let mut proofs = vec![Vec::<[u8; 32]>::new(); leaves.len()];
    while nodes.len() > 1 {
        let mut next_nodes = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut pair = 0usize;
        while pair < nodes.len() {
            let right_index = (pair + 1).min(nodes.len() - 1);
            let (left_hash, left_members) = &nodes[pair];
            let (right_hash, right_members) = &nodes[right_index];
            for original in left_members {
                proofs[*original].push(*right_hash);
            }
            if right_index != pair {
                for original in right_members {
                    proofs[*original].push(*left_hash);
                }
            }
            let mut members = left_members.clone();
            if right_index != pair {
                members.extend_from_slice(right_members);
            }
            next_nodes.push((merkle_parent(*left_hash, *right_hash), members));
            pair += 2;
        }
        nodes = next_nodes;
    }
    let encoded = proofs
        .into_iter()
        .enumerate()
        .map(|(leaf_index, siblings)| ConsensusIdentityProofV1 {
            leaf_index: leaf_index as u32,
            siblings: siblings.into_iter().map(hex::encode).collect(),
        })
        .collect();
    Ok((nodes[0].0, encoded))
}

pub fn transaction_set_hash(
    txids_display_hex: &[String],
) -> Result<[u8; 32], ConsensusIdentityError> {
    let mut bytes = Vec::with_capacity(4 + txids_display_hex.len() * 32);
    bytes.extend_from_slice(
        &u32::try_from(txids_display_hex.len())
            .map_err(|_| invalid("transaction_set", "too many transactions"))?
            .to_le_bytes(),
    );
    for txid in txids_display_hex {
        bytes.extend_from_slice(&decode_hex_exact("txid", txid, 32, false)?);
    }
    Ok(sha256_tagged(TXSET_TAG, &bytes))
}

pub fn coinbase_outputs_hash(
    outputs: &[(u64, Vec<u8>)],
) -> Result<[u8; 32], ConsensusIdentityError> {
    let mut bytes = Vec::new();
    let filtered = outputs
        .iter()
        .filter(|(_, script)| !is_consensus_identity_script(script))
        .collect::<Vec<_>>();
    bytes.extend_from_slice(
        &u32::try_from(filtered.len())
            .map_err(|_| invalid("coinbase_outputs", "too many outputs"))?
            .to_le_bytes(),
    );
    for (value, script) in filtered {
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(script.len())
                .map_err(|_| invalid("coinbase_output_script", "script too large"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(script);
    }
    Ok(sha256_tagged(OUTPUTS_TAG, &bytes))
}

pub fn count_magic_outputs(outputs: &[(u64, Vec<u8>)], magic: &[u8; 5]) -> usize {
    outputs
        .iter()
        .filter(|(value, script)| *value == 0 && is_magic_op_return(script, magic))
        .count()
}

pub fn is_magic_op_return(script: &[u8], magic: &[u8; 5]) -> bool {
    op_return_payload(script).is_some_and(|payload| payload.starts_with(magic))
}

pub fn is_share_work_script(script: &[u8]) -> bool {
    op_return_payload(script)
        .is_some_and(|payload| payload.len() == 37 && payload.starts_with(SHARE_WORK_MAGIC))
}

fn identity_state_code(state: &IdenaStatus) -> Result<u8, ConsensusIdentityError> {
    match state {
        IdenaStatus::Verified => Ok(3),
        IdenaStatus::Newbie => Ok(7),
        IdenaStatus::Human => Ok(8),
        _ => Err(ConsensusIdentityError::IneligibleIdentity),
    }
}

fn identity_state_from_code(code: u8) -> Result<IdenaStatus, ConsensusIdentityError> {
    match code {
        3 => Ok(IdenaStatus::Verified),
        7 => Ok(IdenaStatus::Newbie),
        8 => Ok(IdenaStatus::Human),
        _ => Err(ConsensusIdentityError::IneligibleIdentity),
    }
}

fn decode_leaf(bytes: &[u8]) -> Result<ConsensusIdentityLeafV1, ConsensusIdentityError> {
    if bytes.len() != 99 {
        return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
    }
    let registration_sequence = u32::from_le_bytes(bytes[85..89].try_into().unwrap());
    let registration_block = u64::from_le_bytes(bytes[89..97].try_into().unwrap());
    let registration_epoch = u16::from_le_bytes(bytes[97..99].try_into().unwrap());
    let leaf = ConsensusIdentityLeafV1 {
        idena_address: format!("0x{}", hex::encode(&bytes[..20])),
        identity_state: identity_state_from_code(bytes[20])?,
        mining_pubkey_xonly: hex::encode(&bytes[21..53]),
        registry_commitment: hex::encode(&bytes[53..85]),
        registration_sequence,
        registration_block,
        registration_epoch,
    };
    leaf.validate()?;
    Ok(leaf)
}

fn merkle_parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    sha256_tagged(NODE_TAG, &bytes)
}

fn required_merkle_proof_depth(
    authorized_identity_count: u32,
) -> Result<usize, ConsensusIdentityError> {
    if authorized_identity_count == 0 {
        return Err(ConsensusIdentityError::EmptyAuthorizationSet);
    }
    let mut remaining = authorized_identity_count - 1;
    let mut depth = 0usize;
    while remaining != 0 {
        depth += 1;
        remaining >>= 1;
    }
    Ok(depth)
}

pub fn is_consensus_identity_script(script: &[u8]) -> bool {
    is_magic_op_return(script, CONSENSUS_IDENTITY_MAGIC)
}

fn op_return_payload(script: &[u8]) -> Option<&[u8]> {
    parse_single_minimal_op_return(script).ok()
}

fn append_minimal_push(script: &mut Vec<u8>, payload: &[u8]) -> Result<(), ConsensusIdentityError> {
    match payload.len() {
        0..=75 => script.push(payload.len() as u8),
        76..=255 => {
            script.push(0x4c);
            script.push(payload.len() as u8);
        }
        256..=65_535 => {
            script.push(0x4d);
            script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        }
        _ => return Err(invalid("authorization_payload", "exceeds 65535 bytes")),
    }
    script.extend_from_slice(payload);
    Ok(())
}

fn parse_single_minimal_op_return(script: &[u8]) -> Result<&[u8], ConsensusIdentityError> {
    if script.len() < 2 || script[0] != 0x6a {
        return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
    }
    let (offset, length) = match script[1] {
        0..=75 => (2usize, script[1] as usize),
        0x4c if script.len() >= 3 && script[2] >= 76 => (3usize, script[2] as usize),
        0x4d if script.len() >= 4 => {
            let length = u16::from_le_bytes([script[2], script[3]]) as usize;
            if length <= 255 {
                return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
            }
            (4usize, length)
        }
        _ => return Err(ConsensusIdentityError::MalformedAuthorizationOutput),
    };
    if offset.checked_add(length) != Some(script.len()) {
        return Err(ConsensusIdentityError::MalformedAuthorizationOutput);
    }
    Ok(&script[offset..])
}

fn append_bounded_ascii(
    bytes: &mut Vec<u8>,
    value: &str,
    max: usize,
) -> Result<(), ConsensusIdentityError> {
    validate_ascii_identifier("identifier", value, max)?;
    bytes.push(value.len() as u8);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_ascii_identifier(
    field: &str,
    value: &str,
    max: usize,
) -> Result<(), ConsensusIdentityError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._/".contains(&byte)
        })
    {
        return Err(invalid(field, "must be bounded canonical lowercase ASCII"));
    }
    Ok(())
}

fn validate_hex(
    field: &str,
    value: &str,
    bytes: usize,
    prefixed: bool,
) -> Result<(), ConsensusIdentityError> {
    decode_hex_exact(field, value, bytes, prefixed).map(|_| ())
}

fn decode_hash(value: &str) -> Result<[u8; 32], ConsensusIdentityError> {
    decode_hex_exact("hash", value, 32, false)?
        .try_into()
        .map_err(|_| invalid("hash", "must contain 32 bytes"))
}

fn decode_hex_exact(
    field: &str,
    value: &str,
    bytes: usize,
    prefixed: bool,
) -> Result<Vec<u8>, ConsensusIdentityError> {
    let payload = if prefixed {
        value
            .strip_prefix("0x")
            .ok_or_else(|| invalid(field, "must use a lowercase 0x prefix"))?
    } else {
        value
    };
    if payload.len() != bytes * 2
        || payload
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(invalid(
            field,
            format!("must contain exactly {bytes} lowercase hexadecimal bytes"),
        ));
    }
    hex::decode(payload).map_err(|error| invalid(field, error.to_string()))
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ConsensusIdentityError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ConsensusIdentityError::MalformedAuthorizationOutput)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ConsensusIdentityError::MalformedAuthorizationOutput)?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ConsensusIdentityError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| ConsensusIdentityError::MalformedAuthorizationOutput)
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ConsensusIdentityError {
    ConsensusIdentityError::InvalidField {
        field: field.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{ecdsa::RecoverableSignature, Keypair, PublicKey, SecretKey};
    use tiny_keccak::{Hasher, Keccak};

    fn keypair(byte: u8) -> Keypair {
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).unwrap(),
        )
    }

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }

    fn idena_address(secret_key: &SecretKey) -> String {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        let serialized = public_key.serialize_uncompressed();
        let digest = keccak256(&serialized[1..]);
        format!("0x{}", hex::encode(&digest[12..]))
    }

    fn idena_sign(challenge: &str, secret_key: &SecretKey) -> String {
        let first = keccak256(challenge.as_bytes());
        let signature: RecoverableSignature = Secp256k1::new()
            .sign_ecdsa_recoverable(&Message::from_digest(keccak256(&first)), secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut encoded = compact.to_vec();
        encoded.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        hex::encode(encoded)
    }

    fn anchored_registration(
        index: u8,
        miner_id: &str,
        contract_address: &str,
        experiment_id: &str,
        registration_block: u64,
        registration_timestamp: i64,
    ) -> ConsensusIdentityRegistrationRecordV1 {
        let secp = Secp256k1::new();
        let identity_secret = SecretKey::from_slice(&[20 + index; 32]).unwrap();
        let mining_keypair = keypair(40 + index);
        let claim_keypair = keypair(60 + index);
        let mut registration = MinerRegistration {
            version: crate::sharechain::LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: miner_id.to_string(),
            idena_address: idena_address(&identity_secret),
            btc_payout_script_hex: format!("0014{}", hex::encode([80 + index; 20])),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        let registration_commitment = registration
            .registry_commitment_hash(experiment_id)
            .unwrap();
        let anchor = MinerRegistryAnchorV1 {
            contract_address: contract_address.to_string(),
            experiment_id: experiment_id.to_string(),
            registration_sequence: u32::from(index),
            registration_block,
            registration_epoch: 77,
            registration_timestamp,
            registration_commitment,
        };
        registration = registration.attach_registry_anchor(anchor.clone()).unwrap();
        registration.idena_signature_hex =
            idena_sign(&registration.idena_ownership_challenge(), &identity_secret);
        registration.mining_signature_hex = secp
            .sign_schnorr_no_aux_rand(
                &Message::from_digest(registration.signing_hash()),
                &mining_keypair,
            )
            .to_string();
        registration.verify_mining_signature().unwrap();
        registration.verify_idena_ownership_signature().unwrap();
        ConsensusIdentityRegistrationRecordV1 {
            owner_address: registration.idena_address.clone(),
            current_sequence: u32::from(index),
            contract_record: anchor.canonical_record_line(miner_id).unwrap(),
            registration,
        }
    }

    fn snapshot_input() -> ConsensusIdentitySnapshotInputV1 {
        const CAPTURE_HEIGHT: u64 = 12_345;
        const CAPTURE_TIMESTAMP: u64 = 1_784_404_800;
        const CONFIRMATIONS: u16 = 6;
        let experiment_id = "p2poolbtc-experiment-2";
        let contract_address = format!("0x{}", "44".repeat(20));
        let registrations = vec![
            anchored_registration(
                1,
                "miner-a",
                &contract_address,
                experiment_id,
                CAPTURE_HEIGHT - 10,
                CAPTURE_TIMESTAMP as i64 - 600,
            ),
            anchored_registration(
                2,
                "miner-b",
                &contract_address,
                experiment_id,
                CAPTURE_HEIGHT - 9,
                CAPTURE_TIMESTAMP as i64 - 540,
            ),
            anchored_registration(
                3,
                "miner-c",
                &contract_address,
                experiment_id,
                CAPTURE_HEIGHT - 8,
                CAPTURE_TIMESTAMP as i64 - 480,
            ),
        ];
        let mut finality_chain = Vec::new();
        for offset in 0..=CONFIRMATIONS {
            let hash = format!("0x{:064x}", 10_000 + u64::from(offset));
            let parent_hash = if offset == 0 {
                format!("0x{:064x}", 9_999)
            } else {
                finality_chain
                    .last()
                    .map(|block: &ConsensusIdentitySnapshotBlockV1| block.hash.clone())
                    .unwrap()
            };
            finality_chain.push(ConsensusIdentitySnapshotBlockV1 {
                height: CAPTURE_HEIGHT + u64::from(offset),
                hash,
                parent_hash,
                timestamp: CAPTURE_TIMESTAMP + u64::from(offset) * 20,
                identity_root: format!("0x{}", "55".repeat(32)),
            });
        }
        ConsensusIdentitySnapshotInputV1 {
            schema_version: CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA.to_string(),
            status: "finalized-candidate-input".to_string(),
            experiment_id: experiment_id.to_string(),
            identity_rows_assurance: CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN
                .to_string(),
            registry_contract_address: contract_address,
            capture_epoch: 121,
            next_validation_timestamp: 1_786_219_200,
            finality_confirmations: CONFIRMATIONS,
            capture_block: finality_chain[0].clone(),
            finality_chain,
            identities: vec![
                ConsensusIdentityStateRecordV1 {
                    address: registrations[0].owner_address.clone(),
                    state: IdenaStatus::Human,
                },
                ConsensusIdentityStateRecordV1 {
                    address: registrations[1].owner_address.clone(),
                    state: IdenaStatus::Newbie,
                },
                ConsensusIdentityStateRecordV1 {
                    address: registrations[2].owner_address.clone(),
                    state: IdenaStatus::Zombie,
                },
                ConsensusIdentityStateRecordV1 {
                    address: format!("0x{}", "ff".repeat(20)),
                    state: IdenaStatus::Verified,
                },
            ],
            registry_registered_count: 3,
            registry_registered_miners: vec![
                "miner-a".to_string(),
                "miner-b".to_string(),
                "miner-c".to_string(),
            ],
            registrations,
        }
        .normalized()
    }

    fn leaf(index: u8, state: IdenaStatus) -> ConsensusIdentityLeafV1 {
        ConsensusIdentityLeafV1 {
            idena_address: format!("0x{:040x}", index),
            identity_state: state,
            mining_pubkey_xonly: XOnlyPublicKey::from_keypair(&keypair(index + 1))
                .0
                .to_string(),
            registry_commitment: format!("{:064x}", index as u64 + 10),
            registration_sequence: index as u32 + 1,
            registration_block: 10_000 + index as u64,
            registration_epoch: 120 + index as u16,
        }
    }

    fn policy(root: [u8; 32], count: usize) -> ConsensusIdentityPolicyV1 {
        ConsensusIdentityPolicyV1 {
            schema_version: 1,
            experiment_id: "p2poolbtc-experiment-2".to_string(),
            bitcoin_network: "pohw2".to_string(),
            bitcoin_fork_activation_id:
                "86dfc3ff2736717781cdf007727bfc6bc3ec56a87f27a1d09703885adca434d8".to_string(),
            share_work_activation_id:
                "6528bfa616769d93d67b89aa4df7a3580949d610a4f7eb4711e791ca61dc3380".to_string(),
            registry_contract_address: format!("0x{}", "33".repeat(20)),
            idena_finalized_height: 12_345,
            idena_finalized_timestamp: 1_784_404_800,
            idena_finalized_block_hash: format!("0x{}", "44".repeat(32)),
            idena_next_validation_timestamp: 1_786_219_200,
            authorization_root: hex::encode(root),
            authorized_identity_count: count as u32,
            bitcoin_activation_height: 958_176,
            bitcoin_expiry_height: 959_184,
            bitcoin_expiry_mtp: 1_786_219_200,
            max_proof_depth: 8,
            require_share_work_commitment: true,
        }
    }

    fn context() -> ConsensusIdentitySigningContext {
        let share_work = hex::decode(format!(
            "6a25{}{}",
            hex::encode(SHARE_WORK_MAGIC),
            "88".repeat(32)
        ))
        .unwrap();
        ConsensusIdentitySigningContext {
            activation_id: "aa".repeat(32),
            previous_block_hash: "55".repeat(32),
            block_height: 958_176,
            block_version: 0x2000_0000,
            block_bits: 0x207f_ffff,
            median_time_past: 1_784_404_900,
            transaction_set_hash: transaction_set_hash(&[]).unwrap(),
            coinbase_outputs_hash: coinbase_outputs_hash(&[
                (
                    5_000_000_000,
                    hex::decode(format!("0014{}", "77".repeat(20))).unwrap(),
                ),
                (0, share_work),
            ])
            .unwrap(),
        }
    }

    #[test]
    fn authorization_round_trip_and_fixed_vector() {
        let leaves = vec![
            leaf(1, IdenaStatus::Newbie),
            leaf(2, IdenaStatus::Verified),
            leaf(3, IdenaStatus::Human),
        ];
        let (root, proofs) = build_authorization_root_and_proofs(&leaves).unwrap();
        let policy = policy(root, leaves.len());
        for (leaf, proof) in leaves.iter().zip(proofs.iter()) {
            ConsensusIdentityAuthorizationV1::unsigned(&policy, leaf.clone(), proof.clone())
                .unwrap();
        }
        let mut auth = ConsensusIdentityAuthorizationV1::unsigned(
            &policy,
            leaves[1].clone(),
            proofs[1].clone(),
        )
        .unwrap();
        auth.sign(&policy, &context(), &keypair(3)).unwrap();
        auth.verify(&policy, &context()).unwrap();
        let script = auth.op_return_script_pubkey_hex().unwrap();
        assert_eq!(
            ConsensusIdentityAuthorizationV1::from_op_return_script(&script).unwrap(),
            auth
        );

        assert_eq!(
            policy.commitment_hash().unwrap(),
            "4f727128f49d0f4cd1e1fcca85cbfcb5b9b5f0f3877787be8d33f4c0384d5ab3"
        );
        assert_eq!(
            hex::encode(root),
            "2430c7f7ab395c27c67ed7d4bfc6e55f4db2cbd72ce8dc1876b1c5ebc9411e38"
        );
        assert_eq!(
            hex::encode(auth.signing_hash(&policy, &context()).unwrap()),
            "f4663bd69894696e26f2f83d0a2424f2901f2f4eb29fac8b83b1f11a3b735d04"
        );
        assert_eq!(
            hex::encode(context().transaction_set_hash),
            "df9a71eb4114cfd21da50ff75e28a82ab23d451ba009253d2d18712dbc013ec3"
        );
        assert_eq!(
            hex::encode(context().coinbase_outputs_hash),
            "675d77960d702e5870df9d1b6723b018395e03c49448dccd7022de1efb569da8"
        );
        assert_eq!(
            script,
            "6a4d0e015032494131014f727128f49d0f4cd1e1fcca85cbfcb5b9b5f0f3877787be8d33f4c0384d5ab3000000000000000000000000000000000000000203531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337000000000000000000000000000000000000000000000000000000000000000c0300000012270000000000007a000100000002700120a51a4650ccc1193ef4d4a379a79db691390dd66547eb2a7d1788fe37f548332a7eacc21076edca496211fb712f6bc05fb1c3774284e891adc5b949bf37bb43d5dd70663f1994010931912a5fee6a5154b6da8c6ec8175fff4ce05e376884ed83dde50b0d11eaac36bf625510195d2d08bf0eb48dea120257379416ceb0"
        );
    }

    #[test]
    fn inactive_successor_manifest_is_valid_but_not_launchable() {
        let leaves = vec![
            leaf(1, IdenaStatus::Newbie),
            leaf(2, IdenaStatus::Verified),
            leaf(3, IdenaStatus::Human),
        ];
        let (root, _) = build_authorization_root_and_proofs(&leaves).unwrap();
        let policy = policy(root, leaves.len());
        let mut manifest = ConsensusIdentityActivationManifestV1 {
            schema_version: CONSENSUS_IDENTITY_ACTIVATION_SCHEMA.to_string(),
            profile_revision: 1,
            status: "experimental-candidate".to_string(),
            launch_enabled: false,
            activation_id: "00".repeat(32),
            experiment_id: policy.experiment_id.clone(),
            predecessor_activation_id:
                "86dfc3ff2736717781cdf007727bfc6bc3ec56a87f27a1d09703885adca434d8".to_string(),
            consensus_ruleset: "pohw2-p2ia1-p2sw1-v1".to_string(),
            bitcoin_core_upstream_commit: "9be056a8a72b624dae9623b2f7bded92c2a21c91".to_string(),
            bitcoin_core_patch_series_sha256: "aa".repeat(32),
            authorization_parent_height: 958_175,
            authorization_parent_hash:
                "09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6".to_string(),
            bitcoin_network: "pohw2".to_string(),
            bitcoin_datadir: "pohw-experiment-2".to_string(),
            p2p_port: 40422,
            rpc_port: 40424,
            message_start_hex: "f2b1d4c3".to_string(),
            consensus_policy_hash: policy.commitment_hash().unwrap(),
            require_fresh_datadir: true,
            history_reinterpreted: false,
        };
        manifest.activation_id = manifest.recomputed_activation_id().unwrap();
        manifest.validate_policy(&policy).unwrap();
        assert!(manifest.validate_for_launch().is_err());
        let mut noncanonical = manifest.clone();
        noncanonical.activation_id = noncanonical.activation_id.to_ascii_uppercase();
        assert!(matches!(
            noncanonical.validate(),
            Err(ConsensusIdentityError::InvalidField { ref field, .. })
                if field == "canonical_encoding"
        ));
        assert_eq!(
            manifest.activation_id,
            "b51516091e506c50ec0d3a9ac8731f5f4a4faed273772e319d826df65c4601cf"
        );
    }

    #[test]
    fn all_ineligible_states_are_rejected() {
        for state in [
            IdenaStatus::Invite,
            IdenaStatus::Candidate,
            IdenaStatus::Suspended,
            IdenaStatus::Zombie,
            IdenaStatus::Killed,
            IdenaStatus::Undefined,
        ] {
            assert_eq!(
                leaf(1, state).validate(),
                Err(ConsensusIdentityError::IneligibleIdentity)
            );
        }
    }

    #[test]
    fn authorization_leaf_binds_the_complete_anchored_registration() {
        let registration = MinerRegistration {
            version: crate::sharechain::IDENA_ANCHORED_MINER_REGISTRATION_VERSION,
            miner_id: "miner-a".to_string(),
            idena_address: format!("0x{}", "11".repeat(20)),
            btc_payout_script_hex: format!("0014{}", "22".repeat(20)),
            claim_owner_pubkey_hex: "33".repeat(32),
            mining_pubkey_hex: XOnlyPublicKey::from_keypair(&keypair(7)).0.to_string(),
            registry_anchor: Some(crate::idena_anchor::MinerRegistryAnchorV1 {
                contract_address: format!("0x{}", "44".repeat(20)),
                experiment_id: "p2poolbtc-experiment-2".to_string(),
                registration_sequence: 3,
                registration_block: 12_345,
                registration_epoch: 77,
                registration_timestamp: 1_784_404_800,
                registration_commitment: "55".repeat(32),
            }),
            idena_signature_hex: "66".repeat(65),
            mining_signature_hex: "77".repeat(64),
        };
        let leaf = ConsensusIdentityLeafV1::from_registration(&registration, IdenaStatus::Verified)
            .unwrap();
        leaf.validate_registration(&registration).unwrap();

        let mut substituted = leaf;
        substituted.idena_address = format!("0x{}", "88".repeat(20));
        assert!(matches!(
            substituted.validate_registration(&registration),
            Err(ConsensusIdentityError::InvalidField { ref field, .. })
                if field == "authorization_leaf"
        ));
    }

    #[test]
    fn proof_signature_and_context_tampering_fail_closed() {
        let leaves = vec![leaf(1, IdenaStatus::Newbie), leaf(2, IdenaStatus::Human)];
        let (root, proofs) = build_authorization_root_and_proofs(&leaves).unwrap();
        let policy = policy(root, leaves.len());
        let mut auth = ConsensusIdentityAuthorizationV1::unsigned(
            &policy,
            leaves[0].clone(),
            proofs[0].clone(),
        )
        .unwrap();
        auth.sign(&policy, &context(), &keypair(2)).unwrap();

        let mut bad_proof = auth.clone();
        bad_proof.proof.siblings[0] = "ff".repeat(32);
        assert_eq!(
            bad_proof.verify(&policy, &context()),
            Err(ConsensusIdentityError::InvalidMerkleProof)
        );

        let mut short_proof = auth.clone();
        short_proof.proof.siblings.clear();
        assert_eq!(
            short_proof.verify(&policy, &context()),
            Err(ConsensusIdentityError::InvalidMerkleProof)
        );

        let mut long_proof = auth.clone();
        long_proof.proof.siblings.push("00".repeat(32));
        assert_eq!(
            long_proof.verify(&policy, &context()),
            Err(ConsensusIdentityError::InvalidMerkleProof)
        );

        let mut altered = context();
        altered.coinbase_outputs_hash[0] ^= 1;
        assert_eq!(
            auth.verify(&policy, &altered),
            Err(ConsensusIdentityError::InvalidSignature)
        );

        let mut substituted_activation = context();
        substituted_activation.activation_id = "bb".repeat(32);
        assert_eq!(
            auth.verify(&policy, &substituted_activation),
            Err(ConsensusIdentityError::InvalidSignature)
        );

        let mut expired = context();
        expired.block_height = policy.bitcoin_expiry_height + 1;
        assert_eq!(
            auth.verify(&policy, &expired),
            Err(ConsensusIdentityError::OutsideActivationWindow)
        );

        let mut before_snapshot = context();
        before_snapshot.median_time_past = policy.idena_finalized_timestamp - 1;
        assert_eq!(
            auth.verify(&policy, &before_snapshot),
            Err(ConsensusIdentityError::OutsideActivationWindow)
        );

        let mut time_expired = context();
        time_expired.median_time_past = policy.bitcoin_expiry_mtp;
        assert_eq!(
            auth.verify(&policy, &time_expired),
            Err(ConsensusIdentityError::OutsideActivationWindow)
        );
    }

    #[test]
    fn output_hash_excludes_only_well_formed_authorization_output() {
        let normal = (42, vec![0x51]);
        let fake = (0, vec![0x6a, 5, b'P', b'2', b'I', b'A', b'1']);
        let malformed = (0, vec![0x6a, 0x4c, 5, b'P', b'2', b'I', b'A', b'1']);
        let embedded = (0, vec![0x6a, 6, b'x', b'P', b'2', b'I', b'A', b'1']);
        let malformed_share = (0, vec![0x6a, 6, b'P', b'2', b'S', b'W', b'1', b'x']);
        assert!(is_consensus_identity_script(&fake.1));
        assert!(!is_consensus_identity_script(&malformed.1));
        assert!(!is_consensus_identity_script(&embedded.1));
        assert!(is_share_work_script(
            &hex::decode(format!(
                "6a25{}{}",
                hex::encode(SHARE_WORK_MAGIC),
                "11".repeat(32)
            ))
            .unwrap()
        ));
        assert!(!is_share_work_script(&fake.1));
        assert!(is_magic_op_return(&malformed_share.1, SHARE_WORK_MAGIC));
        assert!(!is_share_work_script(&malformed_share.1));
        assert_eq!(
            coinbase_outputs_hash(std::slice::from_ref(&normal)).unwrap(),
            coinbase_outputs_hash(&[normal.clone(), fake]).unwrap()
        );
        assert_ne!(
            coinbase_outputs_hash(std::slice::from_ref(&normal)).unwrap(),
            coinbase_outputs_hash(&[normal, malformed]).unwrap()
        );
    }

    #[test]
    fn authorization_tree_requires_canonical_order_and_capacity() {
        let sorted = vec![leaf(1, IdenaStatus::Newbie), leaf(2, IdenaStatus::Human)];
        assert!(build_authorization_root_and_proofs(&sorted).is_ok());

        let unsorted = vec![sorted[1].clone(), sorted[0].clone()];
        assert!(matches!(
            build_authorization_root_and_proofs(&unsorted),
            Err(ConsensusIdentityError::InvalidField { ref field, .. }) if field == "leaves"
        ));

        let duplicate = vec![sorted[0].clone(), sorted[0].clone()];
        assert!(matches!(
            build_authorization_root_and_proofs(&duplicate),
            Err(ConsensusIdentityError::InvalidField { ref field, .. }) if field == "leaves"
        ));

        let mut duplicate_key = sorted[1].clone();
        duplicate_key.mining_pubkey_xonly = sorted[0].mining_pubkey_xonly.clone();
        assert!(matches!(
            build_authorization_root_and_proofs(&[sorted[0].clone(), duplicate_key]),
            Err(ConsensusIdentityError::InvalidField { ref field, .. }) if field == "leaves"
        ));

        let mut insufficient_depth = policy([1; 32], 3);
        insufficient_depth.max_proof_depth = 1;
        assert!(matches!(
            insufficient_depth.validate(),
            Err(ConsensusIdentityError::InvalidField { ref field, .. })
                if field == "max_proof_depth"
        ));

        let oversized = policy([1; 32], (1usize << MAX_CONSENSUS_IDENTITY_PROOF_DEPTH) + 1);
        assert!(matches!(
            oversized.validate(),
            Err(ConsensusIdentityError::InvalidField { ref field, .. })
                if field == "authorized_identity_count"
        ));
    }

    #[test]
    fn snapshot_input_builds_a_self_verifying_eligible_authorization_bundle() {
        let input = snapshot_input();
        input.validate().unwrap();
        assert_eq!(
            input.identity_rows_assurance,
            CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN
        );
        let bundle = input.build_bundle().unwrap();
        bundle.validate().unwrap();
        bundle.validate_against_input(&input).unwrap();
        assert_eq!(bundle.authorized_identity_count, 2);
        assert_eq!(bundle.entries.len(), 2);
        assert!(bundle
            .entries
            .iter()
            .all(|entry| entry.leaf.identity_state.is_block_eligible()));
        assert_eq!(
            bundle.idena_finality_height,
            bundle.idena_finalized_height + u64::from(bundle.finality_confirmations)
        );

        let mut policy = policy(
            decode_hash(&bundle.authorization_root).unwrap(),
            bundle.entries.len(),
        );
        policy.registry_contract_address = bundle.registry_contract_address.clone();
        policy.idena_finalized_height = bundle.idena_finalized_height;
        policy.idena_finalized_timestamp = bundle.idena_finalized_timestamp;
        policy.idena_finalized_block_hash = bundle.idena_finalized_block_hash.clone();
        policy.idena_next_validation_timestamp = bundle.idena_next_validation_timestamp;
        for entry in bundle.entries {
            ConsensusIdentityAuthorizationV1::unsigned(&policy, entry.leaf, entry.proof).unwrap();
        }
    }

    #[test]
    fn snapshot_input_rejects_chain_registry_and_bundle_tampering() {
        let mut broken_chain = snapshot_input();
        broken_chain.finality_chain[2].parent_hash = format!("0x{}", "aa".repeat(32));
        assert!(broken_chain.validate().is_err());

        let mut missing_registry_entry = snapshot_input();
        missing_registry_entry.registry_registered_miners.pop();
        assert!(missing_registry_entry.validate().is_err());

        let mut stale_contract_record = snapshot_input();
        stale_contract_record.registrations[0]
            .contract_record
            .push('0');
        assert!(stale_contract_record.validate().is_err());

        let mut false_assurance = snapshot_input();
        false_assurance.identity_rows_assurance = "merkle-proven".to_string();
        assert!(false_assurance.validate().is_err());

        let input = snapshot_input();
        let mut tampered_bundle = input.build_bundle().unwrap();
        tampered_bundle.entries[0].proof.siblings[0] = "aa".repeat(32);
        assert_eq!(
            tampered_bundle.validate(),
            Err(ConsensusIdentityError::InvalidMerkleProof)
        );
    }

    #[test]
    fn snapshot_input_fails_closed_when_no_registered_identity_is_eligible() {
        let mut input = snapshot_input();
        for identity in &mut input.identities {
            identity.state = IdenaStatus::Candidate;
        }
        input.validate().unwrap();
        assert_eq!(
            input.build_bundle(),
            Err(ConsensusIdentityError::EmptyAuthorizationSet)
        );
    }

    #[test]
    fn snapshot_identity_records_reject_age_and_history_fields() {
        let mut value = serde_json::to_value(snapshot_input()).unwrap();
        value["identities"][0]["age"] = serde_json::json!(999);
        let error = serde_json::from_value::<ConsensusIdentitySnapshotInputV1>(value)
            .expect_err("identity age must not enter the consensus snapshot");
        assert!(error.to_string().contains("unknown field `age`"));
    }

    #[test]
    fn checked_in_experiment_2_candidate_matches_the_rust_consensus_model() {
        let manifest: ConsensusIdentityActivationManifestV1 = serde_json::from_str(include_str!(
            "../../../compatibility/experiment-2-consensus-identity-candidate.json"
        ))
        .unwrap();
        let policy: ConsensusIdentityPolicyV1 = serde_json::from_str(include_str!(
            "../../../compatibility/experiment-2-consensus-identity-policy.fixture.json"
        ))
        .unwrap();
        manifest.validate_policy(&policy).unwrap();
        assert_eq!(
            manifest.activation_id,
            "194a60f81ecf2719d4c47b129311a181b81172d3e1742b2b3f4c53707d2d499f"
        );
        assert!(manifest.validate_for_launch().is_err());
    }
}
