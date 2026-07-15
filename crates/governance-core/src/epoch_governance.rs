//! Deterministic, epoch-batched governance for the experimental Idena code DAO.
//!
//! This module is deliberately separate from the legacy per-proposal lifecycle.
//! It models one proposal slot per authenticated identity and one commit/reveal
//! ballot over a frozen proposal set per Idena epoch. It changes only the
//! canonical content-addressed reference; installing software is out of scope.

use crate::{
    cid_for, effective_vote_weight, flip_trust_bps, normalize_address, IdentityState, RiskClass,
    VoteChoice,
};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const DAG_CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;
const SHA2_256_CODE: u64 = 0x12;
const BALLOT_DOMAIN: &[u8] = b"IDENA_CODE_DAO_EPOCH_BALLOT_V1";
const PROPOSAL_SET_DOMAIN: &[u8] = b"IDENA_CODE_DAO_PROPOSAL_SET_V1";
const PROPOSAL_ID_DOMAIN: &[u8] = b"IDENA_CODE_DAO_PROPOSAL_ID_V1";
const MAX_CHALLENGE_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochGovernanceClock {
    pub epoch: u64,
    pub block: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochScheduleOffsetsV1 {
    pub proposal_cutoff: u64,
    pub commit_start: u64,
    pub commit_end: u64,
    pub reveal_end: u64,
    pub normal_grace_blocks: u64,
    pub critical_grace_blocks: u64,
    pub execution_window_blocks: u64,
    pub observation_window_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceScheduleV1 {
    pub schema_version: u16,
    pub governance_epoch: u64,
    pub epoch_anchor_block: u64,
    pub proposal_cutoff_block: u64,
    pub commit_start_block: u64,
    pub commit_end_block: u64,
    pub reveal_end_block: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposalLimitsV1 {
    pub max_affected_repositories: u32,
    pub max_changed_files: u32,
    pub max_patch_bytes: u64,
    pub max_source_package_bytes: u64,
    pub max_description_bytes: u32,
    pub max_migration_operations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochGateParametersV1 {
    pub turnout_quorum_bps: u16,
    pub yes_threshold_bps: u16,
    pub minimum_participating_identities: u32,
    pub minimum_yes_identities: u32,
    pub minimum_verified_or_human_yes: u32,
    pub minimum_ai_attestations: u32,
    pub minimum_ai_independence_groups: u32,
    pub minimum_ai_families: u32,
    pub minimum_builders: u32,
    pub minimum_builder_platforms: u32,
    pub minimum_data_availability_providers: u32,
    pub require_matching_build_digests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochGovernanceParameterSetV1 {
    pub schema_version: u16,
    pub stake_quantum_atoms: String,
    pub minimum_active_stake_atoms: String,
    pub normal_proposal_bond_atoms: String,
    pub critical_proposal_bond_atoms: String,
    pub rejected_bond_burn_bps: u16,
    pub rejected_bond_treasury_bps: u16,
    pub no_quorum_fee_atoms: String,
    pub cancellation_fee_atoms: String,
    pub maximum_proposals_per_epoch: u32,
    pub schedule: EpochScheduleOffsetsV1,
    pub normal_limits: ProposalLimitsV1,
    pub critical_limits: ProposalLimitsV1,
    pub normal: EpochGateParametersV1,
    pub critical: EpochGateParametersV1,
}

impl EpochGovernanceParameterSetV1 {
    pub fn experimental_defaults() -> Self {
        Self {
            schema_version: 1,
            stake_quantum_atoms: "1000000000000".to_string(),
            minimum_active_stake_atoms: "1000000000000000000".to_string(),
            normal_proposal_bond_atoms: "10000000000000000000".to_string(),
            critical_proposal_bond_atoms: "25000000000000000000".to_string(),
            rejected_bond_burn_bps: 5_000,
            rejected_bond_treasury_bps: 5_000,
            no_quorum_fee_atoms: "100000000000000000".to_string(),
            cancellation_fee_atoms: "100000000000000000".to_string(),
            maximum_proposals_per_epoch: 64,
            schedule: EpochScheduleOffsetsV1 {
                proposal_cutoff: 40,
                commit_start: 80,
                commit_end: 100,
                reveal_end: 120,
                normal_grace_blocks: 60,
                critical_grace_blocks: 180,
                execution_window_blocks: 600,
                observation_window_blocks: 600,
            },
            normal_limits: ProposalLimitsV1 {
                max_affected_repositories: 4,
                max_changed_files: 128,
                max_patch_bytes: 2 * 1024 * 1024,
                max_source_package_bytes: 256 * 1024 * 1024,
                max_description_bytes: 16 * 1024,
                max_migration_operations: 8,
            },
            critical_limits: ProposalLimitsV1 {
                max_affected_repositories: 16,
                max_changed_files: 1_024,
                max_patch_bytes: 16 * 1024 * 1024,
                max_source_package_bytes: 1024 * 1024 * 1024,
                max_description_bytes: 64 * 1024,
                max_migration_operations: 64,
            },
            normal: EpochGateParametersV1 {
                turnout_quorum_bps: 2_000,
                yes_threshold_bps: 6_667,
                minimum_participating_identities: 7,
                minimum_yes_identities: 7,
                minimum_verified_or_human_yes: 3,
                minimum_ai_attestations: 2,
                minimum_ai_independence_groups: 2,
                minimum_ai_families: 1,
                minimum_builders: 2,
                minimum_builder_platforms: 1,
                minimum_data_availability_providers: 2,
                require_matching_build_digests: true,
            },
            critical: EpochGateParametersV1 {
                turnout_quorum_bps: 3_000,
                yes_threshold_bps: 7_500,
                minimum_participating_identities: 12,
                minimum_yes_identities: 12,
                minimum_verified_or_human_yes: 5,
                minimum_ai_attestations: 3,
                minimum_ai_independence_groups: 3,
                minimum_ai_families: 2,
                minimum_builders: 3,
                minimum_builder_platforms: 2,
                minimum_data_availability_providers: 3,
                require_matching_build_digests: true,
            },
        }
    }

    fn validate(&self) -> Result<ParsedEpochParameters, EpochGovernanceError> {
        if self.schema_version != 1
            || self.stake_quantum_atoms != "1000000000000"
            || self.rejected_bond_burn_bps as u32 + self.rejected_bond_treasury_bps as u32 != 10_000
            || self.maximum_proposals_per_epoch == 0
            || !(self.schedule.proposal_cutoff < self.schedule.commit_start
                && self.schedule.commit_start < self.schedule.commit_end
                && self.schedule.commit_end < self.schedule.reveal_end)
            || self.schedule.normal_grace_blocks == 0
            || self.schedule.critical_grace_blocks < self.schedule.normal_grace_blocks
            || self.schedule.execution_window_blocks == 0
        {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        validate_gate(self.normal)?;
        validate_gate(self.critical)?;
        Ok(ParsedEpochParameters {
            minimum_active_stake_atoms: parse_atoms(&self.minimum_active_stake_atoms)?,
            normal_proposal_bond_atoms: parse_atoms(&self.normal_proposal_bond_atoms)?,
            critical_proposal_bond_atoms: parse_atoms(&self.critical_proposal_bond_atoms)?,
            no_quorum_fee_atoms: parse_atoms(&self.no_quorum_fee_atoms)?,
            cancellation_fee_atoms: parse_atoms(&self.cancellation_fee_atoms)?,
        })
    }
}

pub fn validate_epoch_governance_parameters(
    parameters: &EpochGovernanceParameterSetV1,
) -> Result<(), EpochGovernanceError> {
    parameters.validate().map(|_| ())
}

#[derive(Debug, Clone, Copy)]
struct ParsedEpochParameters {
    minimum_active_stake_atoms: u128,
    normal_proposal_bond_atoms: u128,
    critical_proposal_bond_atoms: u128,
    no_quorum_fee_atoms: u128,
    cancellation_fee_atoms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochProposalState {
    LocalDraft,
    Submitted,
    ReviewOpen,
    ProposalSetFrozen,
    VotingCommit,
    VotingReveal,
    Rejected,
    NoQuorum,
    AcceptedPendingGrace,
    Challenged,
    AcceptedPendingExecution,
    Executed,
    RevertProposed,
    Reverted,
    Stale,
    Expired,
    CancelledBeforeCutoff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SocialDiscussionReferenceV1 {
    pub post_id: Option<String>,
    pub discussion_cid: Option<String>,
    pub contract_reference: Option<String>,
    pub creation_transaction_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevertProposalV1 {
    pub schema_version: u16,
    pub execution_id: String,
    pub current_canonical_cid: String,
    pub replacement_canonical_cid: String,
    pub reason_cid: String,
    pub evidence_cid: String,
    pub affected_repositories: Vec<String>,
    pub rollback_instructions_cid: String,
    pub compatibility_checks_cid: String,
    pub expedited_recovery: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "details")]
pub enum EpochProposalKindV1 {
    Change,
    Revert(RevertProposalV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochProposalContentV1 {
    pub schema_version: u16,
    pub title: String,
    pub parent_canonical_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub candidate_manifest_sha256: String,
    pub parameter_set_cid: String,
    pub affected_repositories: Vec<String>,
    pub changed_file_count: u32,
    pub patch_bytes: u64,
    pub source_package_bytes: u64,
    pub description_bytes: u32,
    pub migration_operation_count: u32,
    pub risk_class: RiskClass,
    pub rationale_cid: String,
    pub test_plan_cid: String,
    pub rollback_manifest_cid: String,
    pub rollback_instructions_cid: String,
    pub social_discussion: Option<SocialDiscussionReferenceV1>,
    pub proposal_kind: EpochProposalKindV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiReviewEvidenceV1 {
    pub root: String,
    pub valid_attestations: u32,
    pub independent_runtime_groups: u32,
    pub distinct_provider_families: u32,
    pub unresolved_critical_findings: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManualReviewEvidenceV1 {
    pub review_cid: String,
    pub reviewer_address: String,
    pub blocker: bool,
    pub comment_cid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRootEvidenceV1 {
    pub root: String,
    pub valid_builders: u32,
    pub distinct_platforms: u32,
    pub matching_core_artifact_digests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataAvailabilityEvidenceV1 {
    pub root: String,
    pub independent_providers: u32,
    pub valid_until_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VotingPowerSnapshotV1 {
    pub schema_version: u16,
    pub governance_epoch: u64,
    pub voter_address: String,
    pub identity_state: IdentityState,
    pub finalized_authored_flips: u64,
    pub consensus_reported_authored_flips: u64,
    pub flip_trust_bps: u16,
    #[serde(with = "decimal_u128")]
    pub active_stake_atoms: u128,
    #[serde(with = "decimal_u128")]
    pub effective_vote_weight: u128,
    pub source_block_height: u64,
    pub source_block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochBallotChoiceV1 {
    pub proposal_id: String,
    pub choice: VoteChoice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochBallotV1 {
    pub schema_version: u16,
    pub governance_epoch: u64,
    pub voter_address: String,
    pub voting_power_snapshot_reference: String,
    pub ordered_choices: Vec<EpochBallotChoiceV1>,
    /// Local-only notes. The commitment function intentionally excludes them.
    #[serde(default)]
    pub local_notes: BTreeMap<String, String>,
    pub ballot_nonce: u64,
    pub commitment_salt: String,
    pub commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochBallotReceiptV1 {
    pub schema_version: u16,
    pub governance_epoch: u64,
    pub voter_address: String,
    pub commitment: String,
    pub committed_at_block: u64,
    pub revealed_at_block: Option<u64>,
    pub voting_power_snapshot_reference: String,
    #[serde(with = "decimal_u128")]
    pub effective_vote_weight: u128,
    pub revealed_choices: Option<Vec<EpochBallotChoiceV1>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochProposalDecisionV1 {
    pub schema_version: u16,
    pub proposal_id: String,
    pub parameter_set_cid: String,
    pub governance_epoch: u64,
    pub proposal_set_root: String,
    #[serde(with = "decimal_u128")]
    pub yes_weight: u128,
    #[serde(with = "decimal_u128")]
    pub no_weight: u128,
    #[serde(with = "decimal_u128")]
    pub abstain_weight: u128,
    #[serde(with = "decimal_u128")]
    pub total_registered_weight: u128,
    pub distinct_participants: u32,
    pub distinct_yes_identities: u32,
    pub verified_or_human_yes_identities: u32,
    pub turnout_bps: u16,
    pub approval_bps: u16,
    pub state: EpochProposalState,
    pub finalized_at_block: u64,
    pub grace_end_block: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochDecisionRecordV1 {
    pub schema_version: u16,
    pub proposal_id: String,
    pub parameter_set_cid: String,
    pub governance_epoch: u64,
    pub proposal_set_root: String,
    #[serde(with = "decimal_u128")]
    pub yes_weight: u128,
    #[serde(with = "decimal_u128")]
    pub no_weight: u128,
    #[serde(with = "decimal_u128")]
    pub abstain_weight: u128,
    #[serde(with = "decimal_u128")]
    pub total_registered_weight: u128,
    pub distinct_participants: u32,
    pub distinct_yes_identities: u32,
    pub verified_or_human_yes_identities: u32,
    pub state: EpochProposalState,
    pub finalized_at_block: u64,
    pub grace_end_block: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalHistoryEntryV1 {
    pub schema_version: u16,
    pub execution_id: String,
    pub previous_canonical_ecosystem_cid: String,
    pub new_canonical_ecosystem_cid: String,
    pub proposal_id: String,
    pub governance_epoch: u64,
    pub decision_record_cid: String,
    pub execution_block: u64,
    pub rollback_manifest_cid: String,
    pub release_rollback_instructions_cid: String,
    pub observation_window_end_block: u64,
    pub reverts_execution_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryManifestV1 {
    pub schema_version: u16,
    pub canonical_history_cid: String,
    pub last_known_good_ecosystem_cid: String,
    pub release_manifest_cid: String,
    pub artifact_cid: String,
    pub artifact_sha256: String,
    pub compatibility_metadata_cid: String,
    pub rollback_instructions_cid: String,
    pub chain_rpc_required_for_on_chain_revert: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalRollbackPlanV1 {
    pub schema_version: u16,
    pub recovery_manifest_cid: String,
    pub staged_artifact_path: String,
    pub verified_artifact_sha256: String,
    pub explicit_user_confirmation_required: bool,
    pub unattended_install_enabled: bool,
    pub unattended_rollback_enabled: bool,
    pub chain_rpc_available: bool,
    pub on_chain_revert_available: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EpochGovernanceError {
    #[error("epoch governance parameters are invalid")]
    InvalidParameters,
    #[error("address is not a canonical Idena address")]
    InvalidAddress,
    #[error("CID or digest is invalid")]
    InvalidContentAddress,
    #[error("operation is outside the deterministic epoch window")]
    InvalidWindow,
    #[error("epoch anchor does not match the observed epoch")]
    InvalidEpochAnchor,
    #[error("identity is not eligible")]
    IneligibleIdentity,
    #[error("voter has no active snapshotted governance weight")]
    IneligibleVoter,
    #[error("proposal content is malformed or exceeds its risk-class limits")]
    InvalidProposal,
    #[error("proposal parent is stale")]
    StaleParent,
    #[error("the authenticated identity already consumed its proposal slot")]
    ProposalSlotUsed,
    #[error("proposal or epoch record already exists")]
    Duplicate,
    #[error("proposal or epoch record was not found")]
    NotFound,
    #[error("operation is invalid in the current proposal state")]
    InvalidState,
    #[error("attached proposal bond is insufficient")]
    InsufficientBond,
    #[error("frozen proposal set is full")]
    ProposalSetFull,
    #[error("ballot does not exactly match the frozen proposal set")]
    InvalidBallot,
    #[error("ballot commitment is invalid")]
    InvalidCommitment,
    #[error("ballot has already been committed or revealed")]
    BallotAlreadySubmitted,
    #[error("checked arithmetic overflow")]
    Overflow,
    #[error("objective challenge payload is invalid")]
    InvalidChallenge,
    #[error("grace period or execution condition has not passed")]
    ExecutionBlocked,
    #[error("refund is unavailable")]
    NoRefund,
}

#[derive(Debug, Clone)]
struct ProposalRecord {
    proposal_id: String,
    proposal_cid: String,
    proposer: String,
    epoch: u64,
    state: EpochProposalState,
    content: EpochProposalContentV1,
    bond_atoms: u128,
    bond_settled: bool,
    ai_review: Option<AiReviewEvidenceV1>,
    manual_reviews: Vec<ManualReviewEvidenceV1>,
    build: Option<BuildRootEvidenceV1>,
    data_availability: Option<DataAvailabilityEvidenceV1>,
    decision: Option<EpochProposalDecisionV1>,
    pending_challenge: Option<ObjectiveChallengeV1>,
    execution_not_before: u64,
    execution_expires: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochProposalViewV1 {
    pub proposal_id: String,
    pub proposal_cid: String,
    pub proposer: String,
    pub governance_epoch: u64,
    pub state: EpochProposalState,
    pub content: EpochProposalContentV1,
    pub ai_review: Option<AiReviewEvidenceV1>,
    pub manual_reviews: Vec<ManualReviewEvidenceV1>,
    pub build: Option<BuildRootEvidenceV1>,
    pub data_availability: Option<DataAvailabilityEvidenceV1>,
    pub decision: Option<EpochProposalDecisionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochProposalSetViewV1 {
    pub governance_epoch: u64,
    pub frozen_root: String,
    pub ordered_proposal_ids: Vec<String>,
    pub frozen_at_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ObjectiveChallengeV1 {
    CandidateManifestDigestMismatch {
        proposal_id: String,
        candidate_manifest_bytes: Vec<u8>,
        evidence_cid: String,
    },
}

#[derive(Debug, Clone)]
struct EpochRecord {
    schedule: GovernanceScheduleV1,
    frozen_root: Option<String>,
    ordered_proposal_ids: Vec<String>,
    frozen_at_block: Option<u64>,
    total_registered_weight: Option<u128>,
    commitments: BTreeMap<String, EpochBallotReceiptV1>,
    finalized: bool,
}

#[derive(Debug, Clone)]
pub struct EpochGovernanceEngine {
    chain_id: String,
    contract_address: String,
    canonical_ecosystem_cid: String,
    parameter_set_cid: String,
    parameters: EpochGovernanceParameterSetV1,
    parsed: ParsedEpochParameters,
    epochs: BTreeMap<u64, EpochRecord>,
    proposal_slots: BTreeMap<(u64, String), String>,
    proposals: BTreeMap<String, ProposalRecord>,
    voting_power: BTreeMap<(u64, String), VotingPowerSnapshotV1>,
    refunds: BTreeMap<String, u128>,
    treasury_atoms: u128,
    burned_atoms: u128,
    canonical_history: Vec<CanonicalHistoryEntryV1>,
}

impl EpochGovernanceEngine {
    pub fn initialize(
        chain_id: &str,
        contract_address: &str,
        initial_canonical_ecosystem_cid: &str,
        parameter_set_cid: &str,
        parameters: EpochGovernanceParameterSetV1,
    ) -> Result<Self, EpochGovernanceError> {
        if chain_id.is_empty() || chain_id.len() > 128 {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        let contract_address = canonical_address(contract_address)?;
        validate_dag_cbor_cid(initial_canonical_ecosystem_cid)?;
        validate_dag_cbor_cid(parameter_set_cid)?;
        let parsed = parameters.validate()?;
        Ok(Self {
            chain_id: chain_id.to_string(),
            contract_address,
            canonical_ecosystem_cid: initial_canonical_ecosystem_cid.to_string(),
            parameter_set_cid: parameter_set_cid.to_string(),
            parameters,
            parsed,
            epochs: BTreeMap::new(),
            proposal_slots: BTreeMap::new(),
            proposals: BTreeMap::new(),
            voting_power: BTreeMap::new(),
            refunds: BTreeMap::new(),
            treasury_atoms: 0,
            burned_atoms: 0,
            canonical_history: Vec::new(),
        })
    }

    pub fn anchor_governance_epoch(
        &mut self,
        clock: EpochGovernanceClock,
    ) -> Result<GovernanceScheduleV1, EpochGovernanceError> {
        if let Some(existing) = self.epochs.get(&clock.epoch) {
            if existing.schedule.epoch_anchor_block != clock.block {
                return Err(EpochGovernanceError::InvalidEpochAnchor);
            }
            return Ok(existing.schedule.clone());
        }
        let offsets = self.parameters.schedule;
        let schedule = GovernanceScheduleV1 {
            schema_version: 1,
            governance_epoch: clock.epoch,
            epoch_anchor_block: clock.block,
            proposal_cutoff_block: checked_add(clock.block, offsets.proposal_cutoff)?,
            commit_start_block: checked_add(clock.block, offsets.commit_start)?,
            commit_end_block: checked_add(clock.block, offsets.commit_end)?,
            reveal_end_block: checked_add(clock.block, offsets.reveal_end)?,
        };
        self.epochs.insert(
            clock.epoch,
            EpochRecord {
                schedule: schedule.clone(),
                frozen_root: None,
                ordered_proposal_ids: Vec::new(),
                frozen_at_block: None,
                total_registered_weight: None,
                commitments: BTreeMap::new(),
                finalized: false,
            },
        );
        Ok(schedule)
    }

    pub fn governance_schedule(&self, epoch: u64) -> Option<&GovernanceScheduleV1> {
        self.epochs.get(&epoch).map(|record| &record.schedule)
    }

    pub fn canonical_ecosystem_cid(&self) -> &str {
        &self.canonical_ecosystem_cid
    }

    pub fn canonical_history(&self) -> &[CanonicalHistoryEntryV1] {
        &self.canonical_history
    }

    pub fn treasury_atoms(&self) -> u128 {
        self.treasury_atoms
    }

    pub fn burned_atoms(&self) -> u128 {
        self.burned_atoms
    }

    pub fn register_voting_power_snapshot(
        &mut self,
        snapshot: VotingPowerSnapshotV1,
    ) -> Result<(), EpochGovernanceError> {
        if self
            .epochs
            .get(&snapshot.governance_epoch)
            .is_some_and(|record| record.frozen_root.is_some())
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        if snapshot.schema_version != 1
            || snapshot.consensus_reported_authored_flips > snapshot.finalized_authored_flips
        {
            return Err(EpochGovernanceError::IneligibleIdentity);
        }
        validate_sha256(&snapshot.source_block_hash)
            .map_err(|_| EpochGovernanceError::IneligibleIdentity)?;
        let expected_trust = flip_trust_bps(
            snapshot.finalized_authored_flips,
            snapshot.consensus_reported_authored_flips,
        )
        .map_err(|_| EpochGovernanceError::IneligibleIdentity)?;
        if snapshot.flip_trust_bps != expected_trust {
            return Err(EpochGovernanceError::IneligibleIdentity);
        }
        let address = canonical_address(&snapshot.voter_address)?;
        let status_bps = snapshot
            .identity_state
            .status_bps()
            .ok_or(EpochGovernanceError::IneligibleIdentity)?;
        if snapshot.active_stake_atoms < self.parsed.minimum_active_stake_atoms {
            return Err(EpochGovernanceError::IneligibleVoter);
        }
        let expected = effective_vote_weight(
            snapshot.active_stake_atoms,
            status_bps,
            snapshot.flip_trust_bps,
        )
        .map_err(|_| EpochGovernanceError::Overflow)?;
        if expected == 0 || expected != snapshot.effective_vote_weight {
            return Err(EpochGovernanceError::IneligibleVoter);
        }
        let mut canonical = snapshot;
        canonical.voter_address = address.clone();
        let key = (canonical.governance_epoch, address);
        if self.voting_power.contains_key(&key) {
            return Err(EpochGovernanceError::Duplicate);
        }
        self.voting_power.insert(key, canonical);
        Ok(())
    }

    pub fn proposal_slot(
        &self,
        epoch: u64,
        address: &str,
    ) -> Result<Option<&str>, EpochGovernanceError> {
        let address = canonical_address(address)?;
        Ok(self
            .proposal_slots
            .get(&(epoch, address))
            .map(String::as_str))
    }

    pub fn create_proposal(
        &mut self,
        authenticated_caller: &str,
        content: EpochProposalContentV1,
        attached_bond_atoms: u128,
        clock: EpochGovernanceClock,
    ) -> Result<String, EpochGovernanceError> {
        let caller = canonical_address(authenticated_caller)?;
        let epoch = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        if clock.block < epoch.schedule.epoch_anchor_block
            || clock.block >= epoch.schedule.proposal_cutoff_block
            || epoch.frozen_root.is_some()
        {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let snapshot = self
            .voting_power
            .get(&(clock.epoch, caller.clone()))
            .ok_or(EpochGovernanceError::IneligibleIdentity)?;
        if snapshot.identity_state.status_bps().is_none() {
            return Err(EpochGovernanceError::IneligibleIdentity);
        }
        if self
            .proposal_slots
            .contains_key(&(clock.epoch, caller.clone()))
        {
            return Err(EpochGovernanceError::ProposalSlotUsed);
        }
        self.validate_proposal_content(&content)?;
        if content.parent_canonical_ecosystem_cid != self.canonical_ecosystem_cid {
            return Err(EpochGovernanceError::StaleParent);
        }
        let minimum_bond = if content.risk_class.is_critical() {
            self.parsed.critical_proposal_bond_atoms
        } else {
            self.parsed.normal_proposal_bond_atoms
        };
        if attached_bond_atoms < minimum_bond {
            return Err(EpochGovernanceError::InsufficientBond);
        }
        let (proposal_id, proposal_cid) = proposal_identity(clock.epoch, &caller, &content)?;
        if self.proposals.contains_key(&proposal_id) {
            return Err(EpochGovernanceError::Duplicate);
        }

        // No fallible work occurs after this point: slot consumption and proposal
        // insertion form one atomic state transition in the contract model.
        self.proposal_slots
            .insert((clock.epoch, caller.clone()), proposal_id.clone());
        self.proposals.insert(
            proposal_id.clone(),
            ProposalRecord {
                proposal_id: proposal_id.clone(),
                proposal_cid,
                proposer: caller,
                epoch: clock.epoch,
                state: match content.proposal_kind {
                    EpochProposalKindV1::Revert(_) => EpochProposalState::RevertProposed,
                    EpochProposalKindV1::Change => EpochProposalState::Submitted,
                },
                content,
                bond_atoms: attached_bond_atoms,
                bond_settled: false,
                ai_review: None,
                manual_reviews: Vec::new(),
                build: None,
                data_availability: None,
                decision: None,
                pending_challenge: None,
                execution_not_before: 0,
                execution_expires: 0,
            },
        );
        Ok(proposal_id)
    }

    pub fn create_revert_proposal(
        &mut self,
        authenticated_caller: &str,
        mut content: EpochProposalContentV1,
        attached_bond_atoms: u128,
        clock: EpochGovernanceClock,
    ) -> Result<String, EpochGovernanceError> {
        let EpochProposalKindV1::Revert(revert) = &content.proposal_kind else {
            return Err(EpochGovernanceError::InvalidProposal);
        };
        let execution = self
            .canonical_history
            .iter()
            .find(|entry| entry.execution_id == revert.execution_id)
            .ok_or(EpochGovernanceError::InvalidProposal)?;
        if revert.schema_version != 1
            || revert.current_canonical_cid != self.canonical_ecosystem_cid
            || execution.new_canonical_ecosystem_cid != self.canonical_ecosystem_cid
            || revert.replacement_canonical_cid != execution.previous_canonical_ecosystem_cid
        {
            return Err(EpochGovernanceError::InvalidProposal);
        }
        content.parent_canonical_ecosystem_cid = revert.current_canonical_cid.clone();
        content.candidate_ecosystem_cid = revert.replacement_canonical_cid.clone();
        self.create_proposal(authenticated_caller, content, attached_bond_atoms, clock)
    }

    pub fn cancel_proposal_before_cutoff(
        &mut self,
        authenticated_caller: &str,
        proposal_id: &str,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        let caller = canonical_address(authenticated_caller)?;
        let schedule = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .schedule
            .clone();
        if clock.block >= schedule.proposal_cutoff_block {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.epoch != clock.epoch
            || proposal.proposer != caller
            || !matches!(
                proposal.state,
                EpochProposalState::Submitted
                    | EpochProposalState::ReviewOpen
                    | EpochProposalState::RevertProposed
            )
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        proposal.state = EpochProposalState::CancelledBeforeCutoff;
        let refund = proposal
            .bond_atoms
            .saturating_sub(self.parsed.cancellation_fee_atoms);
        let fee = proposal.bond_atoms - refund;
        proposal.bond_settled = true;
        add_balance(&mut self.refunds, &caller, refund)?;
        self.treasury_atoms = self
            .treasury_atoms
            .checked_add(fee)
            .ok_or(EpochGovernanceError::Overflow)?;
        Ok(())
    }

    pub fn attach_ai_review_root(
        &mut self,
        proposal_id: &str,
        evidence: AiReviewEvidenceV1,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        validate_sha256(&evidence.root)?;
        if evidence.valid_attestations == 0
            || evidence.valid_attestations > 256
            || evidence.independent_runtime_groups == 0
            || evidence.independent_runtime_groups > evidence.valid_attestations
            || evidence.distinct_provider_families == 0
            || evidence.distinct_provider_families > evidence.valid_attestations
            || evidence.unresolved_critical_findings > 256
        {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        let schedule = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .schedule
            .clone();
        if clock.block >= schedule.commit_start_block {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.epoch != clock.epoch
            || !matches!(
                proposal.state,
                EpochProposalState::Submitted
                    | EpochProposalState::ReviewOpen
                    | EpochProposalState::ProposalSetFrozen
                    | EpochProposalState::RevertProposed
            )
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        proposal.ai_review = Some(evidence);
        if proposal.state == EpochProposalState::Submitted {
            proposal.state = EpochProposalState::ReviewOpen;
        }
        Ok(())
    }

    pub fn attach_manual_review(
        &mut self,
        proposal_id: &str,
        mut review: ManualReviewEvidenceV1,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        validate_content_cid(&review.review_cid)?;
        review.reviewer_address = canonical_address(&review.reviewer_address)?;
        let schedule = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .schedule
            .clone();
        if clock.block >= schedule.commit_start_block {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.epoch != clock.epoch
            || proposal
                .manual_reviews
                .iter()
                .any(|item| item.reviewer_address == review.reviewer_address)
        {
            return Err(EpochGovernanceError::Duplicate);
        }
        proposal.manual_reviews.push(review);
        Ok(())
    }

    pub fn attach_build_root(
        &mut self,
        proposal_id: &str,
        evidence: BuildRootEvidenceV1,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        validate_sha256(&evidence.root)?;
        if evidence.valid_builders == 0
            || evidence.valid_builders > 256
            || evidence.distinct_platforms == 0
            || evidence.distinct_platforms > evidence.valid_builders
        {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        let schedule = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .schedule
            .clone();
        if clock.block >= schedule.commit_start_block {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.epoch != clock.epoch
            || matches!(proposal.state, EpochProposalState::CancelledBeforeCutoff)
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        proposal.build = Some(evidence);
        Ok(())
    }

    pub fn attach_data_availability_root(
        &mut self,
        proposal_id: &str,
        evidence: DataAvailabilityEvidenceV1,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        validate_sha256(&evidence.root)?;
        if evidence.independent_providers == 0 || evidence.independent_providers > 256 {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        let schedule = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .schedule
            .clone();
        if clock.block >= schedule.commit_start_block {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        let grace = if proposal.content.risk_class.is_critical() {
            self.parameters.schedule.critical_grace_blocks
        } else {
            self.parameters.schedule.normal_grace_blocks
        };
        let required_valid_until = schedule
            .reveal_end_block
            .checked_add(grace)
            .and_then(|value| value.checked_add(self.parameters.schedule.execution_window_blocks))
            .ok_or(EpochGovernanceError::Overflow)?;
        if evidence.valid_until_block < required_valid_until {
            return Err(EpochGovernanceError::InvalidParameters);
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.epoch != clock.epoch
            || matches!(proposal.state, EpochProposalState::CancelledBeforeCutoff)
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        proposal.data_availability = Some(evidence);
        Ok(())
    }

    pub fn freeze_epoch_proposal_set(
        &mut self,
        clock: EpochGovernanceClock,
    ) -> Result<EpochProposalSetViewV1, EpochGovernanceError> {
        let epoch = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        if clock.block < epoch.schedule.proposal_cutoff_block
            || clock.block >= epoch.schedule.commit_start_block
        {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        if epoch.frozen_root.is_some() {
            return Err(EpochGovernanceError::Duplicate);
        }
        let mut ids: Vec<String> = self
            .proposals
            .values()
            .filter(|proposal| {
                proposal.epoch == clock.epoch
                    && proposal.state != EpochProposalState::CancelledBeforeCutoff
            })
            .map(|proposal| proposal.proposal_id.clone())
            .collect();
        ids.sort();
        if ids.len() > self.parameters.maximum_proposals_per_epoch as usize {
            return Err(EpochGovernanceError::ProposalSetFull);
        }
        let root = frozen_proposal_set_root(clock.epoch, &ids)?;
        let total_registered_weight = self.current_registered_weight(clock.epoch)?;
        let epoch = self
            .epochs
            .get_mut(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        epoch.frozen_root = Some(root.clone());
        epoch.ordered_proposal_ids = ids.clone();
        epoch.frozen_at_block = Some(clock.block);
        epoch.total_registered_weight = Some(total_registered_weight);
        for id in &ids {
            let proposal = self
                .proposals
                .get_mut(id)
                .ok_or(EpochGovernanceError::NotFound)?;
            proposal.state = EpochProposalState::ProposalSetFrozen;
        }
        Ok(EpochProposalSetViewV1 {
            governance_epoch: clock.epoch,
            frozen_root: root,
            ordered_proposal_ids: ids,
            frozen_at_block: clock.block,
        })
    }

    pub fn epoch_proposal_set(&self, epoch: u64) -> Option<EpochProposalSetViewV1> {
        let record = self.epochs.get(&epoch)?;
        Some(EpochProposalSetViewV1 {
            governance_epoch: epoch,
            frozen_root: record.frozen_root.clone()?,
            ordered_proposal_ids: record.ordered_proposal_ids.clone(),
            frozen_at_block: record.frozen_at_block?,
        })
    }

    pub fn prepare_epoch_ballot(
        &self,
        epoch: u64,
        voter_address: &str,
        choices: Vec<EpochBallotChoiceV1>,
        local_notes: BTreeMap<String, String>,
        ballot_nonce: u64,
        commitment_salt: &str,
    ) -> Result<EpochBallotV1, EpochGovernanceError> {
        let voter = canonical_address(voter_address)?;
        let snapshot = self
            .voting_power
            .get(&(epoch, voter.clone()))
            .ok_or(EpochGovernanceError::IneligibleVoter)?;
        let epoch_record = self
            .epochs
            .get(&epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        validate_ballot_choices(&epoch_record.ordered_proposal_ids, &choices)?;
        let root = epoch_record
            .frozen_root
            .as_ref()
            .ok_or(EpochGovernanceError::InvalidState)?;
        let commitment = ballot_commitment(&BallotCommitmentInputV1 {
            chain_id: &self.chain_id,
            contract_address: &self.contract_address,
            governance_epoch: epoch,
            voter_address: &voter,
            frozen_proposal_set_root: root,
            choices: &choices,
            ballot_nonce,
            salt: commitment_salt,
        })?;
        Ok(EpochBallotV1 {
            schema_version: 1,
            governance_epoch: epoch,
            voter_address: voter,
            voting_power_snapshot_reference: voting_power_reference(snapshot),
            ordered_choices: choices,
            local_notes,
            ballot_nonce,
            commitment_salt: commitment_salt.to_string(),
            commitment,
        })
    }

    pub fn commit_epoch_ballot(
        &mut self,
        authenticated_caller: &str,
        epoch: u64,
        commitment: &str,
        clock: EpochGovernanceClock,
    ) -> Result<EpochBallotReceiptV1, EpochGovernanceError> {
        if clock.epoch != epoch {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        validate_sha256(commitment)?;
        let voter = canonical_address(authenticated_caller)?;
        let snapshot = self
            .voting_power
            .get(&(epoch, voter.clone()))
            .ok_or(EpochGovernanceError::IneligibleVoter)?;
        let record = self
            .epochs
            .get_mut(&epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        if record.frozen_root.is_none()
            || clock.block < record.schedule.commit_start_block
            || clock.block >= record.schedule.commit_end_block
        {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        if record.commitments.contains_key(&voter) {
            return Err(EpochGovernanceError::BallotAlreadySubmitted);
        }
        for proposal_id in &record.ordered_proposal_ids {
            let proposal = self
                .proposals
                .get_mut(proposal_id)
                .ok_or(EpochGovernanceError::NotFound)?;
            if proposal.state == EpochProposalState::ProposalSetFrozen {
                proposal.state = EpochProposalState::VotingCommit;
            }
        }
        let receipt = EpochBallotReceiptV1 {
            schema_version: 1,
            governance_epoch: epoch,
            voter_address: voter.clone(),
            commitment: commitment.to_string(),
            committed_at_block: clock.block,
            revealed_at_block: None,
            voting_power_snapshot_reference: voting_power_reference(snapshot),
            effective_vote_weight: snapshot.effective_vote_weight,
            revealed_choices: None,
        };
        record.commitments.insert(voter, receipt.clone());
        Ok(receipt)
    }

    pub fn reveal_epoch_ballot(
        &mut self,
        authenticated_caller: &str,
        ballot: &EpochBallotV1,
        clock: EpochGovernanceClock,
    ) -> Result<EpochBallotReceiptV1, EpochGovernanceError> {
        if ballot.schema_version != 1 || clock.epoch != ballot.governance_epoch {
            return Err(EpochGovernanceError::InvalidBallot);
        }
        let voter = canonical_address(authenticated_caller)?;
        if voter != canonical_address(&ballot.voter_address)? {
            return Err(EpochGovernanceError::InvalidBallot);
        }
        let record = self
            .epochs
            .get_mut(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        if clock.block < record.schedule.commit_end_block
            || clock.block >= record.schedule.reveal_end_block
        {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        validate_ballot_choices(&record.ordered_proposal_ids, &ballot.ordered_choices)?;
        let root = record
            .frozen_root
            .as_ref()
            .ok_or(EpochGovernanceError::InvalidState)?;
        let expected = ballot_commitment(&BallotCommitmentInputV1 {
            chain_id: &self.chain_id,
            contract_address: &self.contract_address,
            governance_epoch: clock.epoch,
            voter_address: &voter,
            frozen_proposal_set_root: root,
            choices: &ballot.ordered_choices,
            ballot_nonce: ballot.ballot_nonce,
            salt: &ballot.commitment_salt,
        })?;
        if expected != ballot.commitment {
            return Err(EpochGovernanceError::InvalidCommitment);
        }
        let receipt = record
            .commitments
            .get_mut(&voter)
            .ok_or(EpochGovernanceError::InvalidCommitment)?;
        if receipt.revealed_at_block.is_some() {
            return Err(EpochGovernanceError::BallotAlreadySubmitted);
        }
        if receipt.commitment != expected
            || receipt.voting_power_snapshot_reference != ballot.voting_power_snapshot_reference
        {
            return Err(EpochGovernanceError::InvalidCommitment);
        }
        receipt.revealed_at_block = Some(clock.block);
        receipt.revealed_choices = Some(ballot.ordered_choices.clone());
        for proposal_id in &record.ordered_proposal_ids {
            let proposal = self
                .proposals
                .get_mut(proposal_id)
                .ok_or(EpochGovernanceError::NotFound)?;
            if matches!(
                proposal.state,
                EpochProposalState::VotingCommit | EpochProposalState::ProposalSetFrozen
            ) {
                proposal.state = EpochProposalState::VotingReveal;
            }
        }
        Ok(receipt.clone())
    }

    pub fn finalize_epoch_voting(
        &mut self,
        clock: EpochGovernanceClock,
    ) -> Result<Vec<EpochProposalDecisionV1>, EpochGovernanceError> {
        let record = self
            .epochs
            .get(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?;
        if clock.block < record.schedule.reveal_end_block || record.finalized {
            return Err(EpochGovernanceError::InvalidWindow);
        }
        let proposal_ids = record.ordered_proposal_ids.clone();
        let proposal_set_root = record
            .frozen_root
            .clone()
            .ok_or(EpochGovernanceError::InvalidState)?;
        let receipts: Vec<EpochBallotReceiptV1> = record.commitments.values().cloned().collect();
        let total_registered_weight = self.frozen_registered_weight(clock.epoch)?;
        let mut decisions = Vec::with_capacity(proposal_ids.len());
        for (proposal_index, proposal_id) in proposal_ids.iter().enumerate() {
            let proposal = self
                .proposals
                .get(proposal_id)
                .ok_or(EpochGovernanceError::NotFound)?;
            let mut tally = Tally::default();
            for receipt in &receipts {
                let Some(choices) = &receipt.revealed_choices else {
                    continue;
                };
                let choice = choices
                    .get(proposal_index)
                    .ok_or(EpochGovernanceError::InvalidBallot)?
                    .choice;
                let snapshot = self
                    .voting_power
                    .get(&(clock.epoch, receipt.voter_address.clone()))
                    .ok_or(EpochGovernanceError::IneligibleVoter)?;
                tally.add(choice, snapshot)?;
            }
            let gate = if proposal.content.risk_class.is_critical() {
                self.parameters.critical
            } else {
                self.parameters.normal
            };
            let grace = if proposal.content.risk_class.is_critical() {
                self.parameters.schedule.critical_grace_blocks
            } else {
                self.parameters.schedule.normal_grace_blocks
            };
            let required_availability_until = clock
                .block
                .checked_add(grace)
                .and_then(|value| {
                    value.checked_add(self.parameters.schedule.execution_window_blocks)
                })
                .ok_or(EpochGovernanceError::Overflow)?;
            let evidence_ready =
                proposal_evidence_ready(proposal, gate, required_availability_until);
            let turnout = tally
                .yes
                .checked_add(tally.no)
                .and_then(|v| v.checked_add(tally.abstain))
                .ok_or(EpochGovernanceError::Overflow)?;
            let turnout_bps = ratio_bps(turnout, total_registered_weight);
            let approval_bps = ratio_bps(
                tally.yes,
                tally
                    .yes
                    .checked_add(tally.no)
                    .ok_or(EpochGovernanceError::Overflow)?,
            );
            let quorum = turnout_bps >= gate.turnout_quorum_bps
                && tally.participants.len() >= gate.minimum_participating_identities as usize;
            let approved = quorum
                && evidence_ready
                && approval_bps >= gate.yes_threshold_bps
                && tally.yes_identities.len() >= gate.minimum_yes_identities as usize
                && tally.verified_or_human_yes >= gate.minimum_verified_or_human_yes;
            let state = if !evidence_ready {
                EpochProposalState::Expired
            } else if !quorum {
                EpochProposalState::NoQuorum
            } else if approved {
                EpochProposalState::AcceptedPendingGrace
            } else {
                EpochProposalState::Rejected
            };
            let grace_end_block = if approved {
                Some(checked_add(clock.block, grace)?)
            } else {
                None
            };
            decisions.push(EpochProposalDecisionV1 {
                schema_version: 1,
                proposal_id: proposal_id.clone(),
                parameter_set_cid: proposal.content.parameter_set_cid.clone(),
                governance_epoch: clock.epoch,
                proposal_set_root: proposal_set_root.clone(),
                yes_weight: tally.yes,
                no_weight: tally.no,
                abstain_weight: tally.abstain,
                total_registered_weight,
                distinct_participants: tally.participants.len() as u32,
                distinct_yes_identities: tally.yes_identities.len() as u32,
                verified_or_human_yes_identities: tally.verified_or_human_yes,
                turnout_bps,
                approval_bps,
                state,
                finalized_at_block: clock.block,
                grace_end_block,
            });
        }
        for decision in &decisions {
            self.apply_decision(decision.clone())?;
        }
        self.epochs
            .get_mut(&clock.epoch)
            .ok_or(EpochGovernanceError::NotFound)?
            .finalized = true;
        Ok(decisions)
    }

    pub fn enter_execution_ready_state(
        &mut self,
        proposal_id: &str,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.state != EpochProposalState::AcceptedPendingGrace
            || proposal.pending_challenge.is_some()
            || clock.block < proposal.execution_not_before
        {
            return Err(EpochGovernanceError::ExecutionBlocked);
        }
        proposal.state = EpochProposalState::AcceptedPendingExecution;
        Ok(())
    }

    pub fn open_objective_challenge(
        &mut self,
        proposal_id: &str,
        challenge: ObjectiveChallengeV1,
        clock: EpochGovernanceClock,
    ) -> Result<(), EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.state != EpochProposalState::AcceptedPendingGrace
            || clock.block >= proposal.execution_not_before
            || proposal.pending_challenge.is_some()
        {
            return Err(EpochGovernanceError::InvalidState);
        }
        match &challenge {
            ObjectiveChallengeV1::CandidateManifestDigestMismatch {
                proposal_id: bound,
                candidate_manifest_bytes,
                evidence_cid,
            } => {
                if bound != proposal_id || candidate_manifest_bytes.len() > MAX_CHALLENGE_BYTES {
                    return Err(EpochGovernanceError::InvalidChallenge);
                }
                validate_content_cid(evidence_cid)?;
            }
        }
        proposal.pending_challenge = Some(challenge);
        proposal.state = EpochProposalState::Challenged;
        Ok(())
    }

    pub fn resolve_objective_challenge(
        &mut self,
        proposal_id: &str,
    ) -> Result<bool, EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.state != EpochProposalState::Challenged {
            return Err(EpochGovernanceError::InvalidState);
        }
        let challenge = proposal
            .pending_challenge
            .take()
            .ok_or(EpochGovernanceError::InvalidChallenge)?;
        let upheld = match challenge {
            ObjectiveChallengeV1::CandidateManifestDigestMismatch {
                candidate_manifest_bytes,
                ..
            } => {
                let computed_cid = cid_for(DAG_CBOR_CODEC, &candidate_manifest_bytes).to_string();
                if computed_cid != proposal.content.candidate_ecosystem_cid {
                    return Err(EpochGovernanceError::InvalidChallenge);
                }
                hex::encode(Sha256::digest(&candidate_manifest_bytes))
                    != proposal.content.candidate_manifest_sha256
            }
        };
        if upheld {
            proposal.state = EpochProposalState::Rejected;
            self.settle_rejected_bond(proposal_id)?;
        } else {
            let grace_end = proposal.execution_not_before;
            proposal.state = EpochProposalState::AcceptedPendingGrace;
            proposal.execution_not_before = grace_end;
        }
        Ok(upheld)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        clock: EpochGovernanceClock,
    ) -> Result<CanonicalHistoryEntryV1, EpochGovernanceError> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.state != EpochProposalState::AcceptedPendingExecution
            || clock.block < proposal.execution_not_before
            || clock.block > proposal.execution_expires
            || proposal.pending_challenge.is_some()
        {
            return Err(EpochGovernanceError::ExecutionBlocked);
        }
        if proposal.content.parent_canonical_ecosystem_cid != self.canonical_ecosystem_cid {
            self.proposals.get_mut(proposal_id).unwrap().state = EpochProposalState::Stale;
            self.settle_no_quorum_like_bond(proposal_id)?;
            return Err(EpochGovernanceError::StaleParent);
        }
        let previous = self.canonical_ecosystem_cid.clone();
        let new = proposal.content.candidate_ecosystem_cid.clone();
        let decision_record_cid = epoch_decision_record_cid(
            proposal
                .decision
                .as_ref()
                .ok_or(EpochGovernanceError::InvalidState)?,
        )?;
        let reverts_execution_id = match &proposal.content.proposal_kind {
            EpochProposalKindV1::Revert(revert) => Some(revert.execution_id.clone()),
            EpochProposalKindV1::Change => None,
        };
        let execution_id = execution_id(
            self.canonical_history.len() as u64,
            proposal_id,
            &previous,
            &new,
        );
        let entry = CanonicalHistoryEntryV1 {
            schema_version: 1,
            execution_id,
            previous_canonical_ecosystem_cid: previous,
            new_canonical_ecosystem_cid: new.clone(),
            proposal_id: proposal_id.to_string(),
            governance_epoch: proposal.epoch,
            decision_record_cid,
            execution_block: clock.block,
            rollback_manifest_cid: proposal.content.rollback_manifest_cid.clone(),
            release_rollback_instructions_cid: proposal.content.rollback_instructions_cid.clone(),
            observation_window_end_block: checked_add(
                clock.block,
                self.parameters.schedule.observation_window_blocks,
            )?,
            reverts_execution_id,
        };
        self.canonical_ecosystem_cid = new;
        self.canonical_history.push(entry.clone());
        let proposal = self.proposals.get_mut(proposal_id).unwrap();
        proposal.state = if matches!(
            proposal.content.proposal_kind,
            EpochProposalKindV1::Revert(_)
        ) {
            EpochProposalState::Reverted
        } else {
            EpochProposalState::Executed
        };
        if !proposal.bond_settled {
            proposal.bond_settled = true;
            add_balance(&mut self.refunds, &proposal.proposer, proposal.bond_atoms)?;
        }
        Ok(entry)
    }

    pub fn proposal(&self, proposal_id: &str) -> Option<EpochProposalViewV1> {
        self.proposals.get(proposal_id).map(proposal_view)
    }

    pub fn ballot_receipt(
        &self,
        epoch: u64,
        voter: &str,
    ) -> Result<Option<&EpochBallotReceiptV1>, EpochGovernanceError> {
        let voter = canonical_address(voter)?;
        Ok(self
            .epochs
            .get(&epoch)
            .and_then(|record| record.commitments.get(&voter)))
    }

    pub fn claim_refund(
        &mut self,
        authenticated_caller: &str,
    ) -> Result<u128, EpochGovernanceError> {
        let caller = canonical_address(authenticated_caller)?;
        let value = self
            .refunds
            .remove(&caller)
            .ok_or(EpochGovernanceError::NoRefund)?;
        if value == 0 {
            return Err(EpochGovernanceError::NoRefund);
        }
        Ok(value)
    }

    fn validate_proposal_content(
        &self,
        content: &EpochProposalContentV1,
    ) -> Result<(), EpochGovernanceError> {
        if content.schema_version != 1
            || content.title.is_empty()
            || content.title.len() > 200
            || content.parameter_set_cid != self.parameter_set_cid
        {
            return Err(EpochGovernanceError::InvalidProposal);
        }
        validate_dag_cbor_cid(&content.parent_canonical_ecosystem_cid)?;
        validate_dag_cbor_cid(&content.candidate_ecosystem_cid)?;
        validate_dag_cbor_cid(&content.parameter_set_cid)?;
        validate_content_cid(&content.rationale_cid)?;
        validate_content_cid(&content.test_plan_cid)?;
        validate_content_cid(&content.rollback_manifest_cid)?;
        validate_content_cid(&content.rollback_instructions_cid)?;
        validate_sha256(&content.candidate_manifest_sha256)?;
        if content.parent_canonical_ecosystem_cid == content.candidate_ecosystem_cid
            || content.affected_repositories.is_empty()
        {
            return Err(EpochGovernanceError::InvalidProposal);
        }
        let mut repositories = content.affected_repositories.clone();
        repositories.sort();
        repositories.dedup();
        if repositories != content.affected_repositories {
            return Err(EpochGovernanceError::InvalidProposal);
        }
        let limits = if content.risk_class.is_critical() {
            self.parameters.critical_limits
        } else {
            self.parameters.normal_limits
        };
        if repositories.len() > limits.max_affected_repositories as usize
            || content.changed_file_count == 0
            || content.changed_file_count > limits.max_changed_files
            || content.patch_bytes == 0
            || content.patch_bytes > limits.max_patch_bytes
            || content.source_package_bytes == 0
            || content.source_package_bytes > limits.max_source_package_bytes
            || content.description_bytes == 0
            || content.description_bytes > limits.max_description_bytes
            || content.migration_operation_count > limits.max_migration_operations
        {
            return Err(EpochGovernanceError::InvalidProposal);
        }
        if let Some(discussion) = &content.social_discussion {
            if let Some(cid) = &discussion.discussion_cid {
                validate_content_cid(cid)?;
            }
        }
        if let EpochProposalKindV1::Revert(revert) = &content.proposal_kind {
            let mut revert_repositories = revert.affected_repositories.clone();
            revert_repositories.sort();
            revert_repositories.dedup();
            if revert.schema_version != 1
                || revert_repositories != revert.affected_repositories
                || revert.affected_repositories != content.affected_repositories
                || (revert.expedited_recovery && !content.risk_class.is_critical())
            {
                return Err(EpochGovernanceError::InvalidProposal);
            }
            for cid in [
                &revert.reason_cid,
                &revert.evidence_cid,
                &revert.rollback_instructions_cid,
                &revert.compatibility_checks_cid,
            ] {
                validate_content_cid(cid)?;
            }
        }
        Ok(())
    }

    fn current_registered_weight(&self, epoch: u64) -> Result<u128, EpochGovernanceError> {
        self.voting_power
            .iter()
            .filter(|((snapshot_epoch, _), _)| *snapshot_epoch == epoch)
            .try_fold(0u128, |total, (_, snapshot)| {
                total
                    .checked_add(snapshot.effective_vote_weight)
                    .ok_or(EpochGovernanceError::Overflow)
            })
    }

    fn frozen_registered_weight(&self, epoch: u64) -> Result<u128, EpochGovernanceError> {
        self.epochs
            .get(&epoch)
            .and_then(|record| record.total_registered_weight)
            .ok_or(EpochGovernanceError::InvalidState)
    }

    fn apply_decision(
        &mut self,
        decision: EpochProposalDecisionV1,
    ) -> Result<(), EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&decision.proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        proposal.state = decision.state;
        if let Some(grace_end) = decision.grace_end_block {
            proposal.execution_not_before = grace_end;
            proposal.execution_expires =
                checked_add(grace_end, self.parameters.schedule.execution_window_blocks)?;
        }
        proposal.decision = Some(decision.clone());
        match decision.state {
            EpochProposalState::Rejected => self.settle_rejected_bond(&decision.proposal_id)?,
            EpochProposalState::NoQuorum | EpochProposalState::Expired => {
                self.settle_no_quorum_like_bond(&decision.proposal_id)?
            }
            _ => {}
        }
        Ok(())
    }

    fn settle_rejected_bond(&mut self, proposal_id: &str) -> Result<(), EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.bond_settled {
            return Ok(());
        }
        let burned = mul_bps(proposal.bond_atoms, self.parameters.rejected_bond_burn_bps)?;
        let treasury = proposal
            .bond_atoms
            .checked_sub(burned)
            .ok_or(EpochGovernanceError::Overflow)?;
        self.burned_atoms = self
            .burned_atoms
            .checked_add(burned)
            .ok_or(EpochGovernanceError::Overflow)?;
        self.treasury_atoms = self
            .treasury_atoms
            .checked_add(treasury)
            .ok_or(EpochGovernanceError::Overflow)?;
        proposal.bond_settled = true;
        Ok(())
    }

    fn settle_no_quorum_like_bond(
        &mut self,
        proposal_id: &str,
    ) -> Result<(), EpochGovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(EpochGovernanceError::NotFound)?;
        if proposal.bond_settled {
            return Ok(());
        }
        let fee = proposal.bond_atoms.min(self.parsed.no_quorum_fee_atoms);
        let refund = proposal.bond_atoms - fee;
        self.treasury_atoms = self
            .treasury_atoms
            .checked_add(fee)
            .ok_or(EpochGovernanceError::Overflow)?;
        add_balance(&mut self.refunds, &proposal.proposer, refund)?;
        proposal.bond_settled = true;
        Ok(())
    }
}

#[derive(Default)]
struct Tally {
    yes: u128,
    no: u128,
    abstain: u128,
    participants: BTreeSet<String>,
    yes_identities: BTreeSet<String>,
    verified_or_human_yes: u32,
}

impl Tally {
    fn add(
        &mut self,
        choice: VoteChoice,
        snapshot: &VotingPowerSnapshotV1,
    ) -> Result<(), EpochGovernanceError> {
        self.participants.insert(snapshot.voter_address.clone());
        match choice {
            VoteChoice::Yes => {
                self.yes = self
                    .yes
                    .checked_add(snapshot.effective_vote_weight)
                    .ok_or(EpochGovernanceError::Overflow)?;
                if self.yes_identities.insert(snapshot.voter_address.clone())
                    && snapshot.identity_state.is_verified_or_human()
                {
                    self.verified_or_human_yes = self
                        .verified_or_human_yes
                        .checked_add(1)
                        .ok_or(EpochGovernanceError::Overflow)?;
                }
            }
            VoteChoice::No => {
                self.no = self
                    .no
                    .checked_add(snapshot.effective_vote_weight)
                    .ok_or(EpochGovernanceError::Overflow)?
            }
            VoteChoice::Abstain => {
                self.abstain = self
                    .abstain
                    .checked_add(snapshot.effective_vote_weight)
                    .ok_or(EpochGovernanceError::Overflow)?
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BallotCommitmentInputV1<'a> {
    pub chain_id: &'a str,
    pub contract_address: &'a str,
    pub governance_epoch: u64,
    pub voter_address: &'a str,
    pub frozen_proposal_set_root: &'a str,
    pub choices: &'a [EpochBallotChoiceV1],
    pub ballot_nonce: u64,
    pub salt: &'a str,
}

pub fn ballot_commitment(
    input: &BallotCommitmentInputV1<'_>,
) -> Result<String, EpochGovernanceError> {
    if input.chain_id.is_empty() || input.chain_id.len() > 128 {
        return Err(EpochGovernanceError::InvalidCommitment);
    }
    let contract = address_bytes(input.contract_address)?;
    let voter = address_bytes(input.voter_address)?;
    let root = decode_hash(input.frozen_proposal_set_root)?;
    let salt = decode_hash(input.salt)?;
    let count: u32 = input
        .choices
        .len()
        .try_into()
        .map_err(|_| EpochGovernanceError::InvalidBallot)?;
    let mut bytes = Vec::with_capacity(256 + input.choices.len());
    bytes.extend_from_slice(BALLOT_DOMAIN);
    push_len_prefixed(&mut bytes, input.chain_id.as_bytes())?;
    bytes.extend_from_slice(&contract);
    bytes.extend_from_slice(&input.governance_epoch.to_be_bytes());
    bytes.extend_from_slice(&voter);
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&count.to_be_bytes());
    for item in input.choices {
        bytes.push(match item.choice {
            VoteChoice::Yes => 1,
            VoteChoice::No => 2,
            VoteChoice::Abstain => 3,
        });
    }
    bytes.extend_from_slice(&input.ballot_nonce.to_be_bytes());
    bytes.extend_from_slice(&salt);
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn frozen_proposal_set_root(
    epoch: u64,
    ordered_ids: &[String],
) -> Result<String, EpochGovernanceError> {
    let count: u32 = ordered_ids
        .len()
        .try_into()
        .map_err(|_| EpochGovernanceError::ProposalSetFull)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROPOSAL_SET_DOMAIN);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<&str> = None;
    for proposal_id in ordered_ids {
        if proposal_id.is_empty() || previous.is_some_and(|value| value >= proposal_id.as_str()) {
            return Err(EpochGovernanceError::InvalidBallot);
        }
        push_len_prefixed(&mut bytes, proposal_id.as_bytes())?;
        previous = Some(proposal_id);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn stage_local_rollback(
    recovery_manifest_cid: &str,
    manifest: &RecoveryManifestV1,
    staged_artifact_path: &str,
    staged_artifact_bytes: &[u8],
    chain_rpc_available: bool,
) -> Result<LocalRollbackPlanV1, EpochGovernanceError> {
    validate_content_cid(recovery_manifest_cid)?;
    if manifest.schema_version != 1 || staged_artifact_path.is_empty() {
        return Err(EpochGovernanceError::InvalidProposal);
    }
    let digest = hex::encode(Sha256::digest(staged_artifact_bytes));
    if digest != manifest.artifact_sha256 {
        return Err(EpochGovernanceError::InvalidContentAddress);
    }
    Ok(LocalRollbackPlanV1 {
        schema_version: 1,
        recovery_manifest_cid: recovery_manifest_cid.to_string(),
        staged_artifact_path: staged_artifact_path.to_string(),
        verified_artifact_sha256: digest,
        explicit_user_confirmation_required: true,
        unattended_install_enabled: false,
        unattended_rollback_enabled: false,
        chain_rpc_available,
        on_chain_revert_available: chain_rpc_available
            && manifest.chain_rpc_required_for_on_chain_revert,
    })
}

fn proposal_view(record: &ProposalRecord) -> EpochProposalViewV1 {
    EpochProposalViewV1 {
        proposal_id: record.proposal_id.clone(),
        proposal_cid: record.proposal_cid.clone(),
        proposer: record.proposer.clone(),
        governance_epoch: record.epoch,
        state: record.state,
        content: record.content.clone(),
        ai_review: record.ai_review.clone(),
        manual_reviews: record.manual_reviews.clone(),
        build: record.build.clone(),
        data_availability: record.data_availability.clone(),
        decision: record.decision.clone(),
    }
}

pub fn epoch_decision_record(
    decision: &EpochProposalDecisionV1,
) -> Result<EpochDecisionRecordV1, EpochGovernanceError> {
    validate_dag_cbor_cid(&decision.parameter_set_cid)?;
    validate_sha256(&decision.proposal_set_root)?;
    if !matches!(
        decision.state,
        EpochProposalState::Stale
            | EpochProposalState::NoQuorum
            | EpochProposalState::Rejected
            | EpochProposalState::AcceptedPendingGrace
            | EpochProposalState::Expired
    ) || (decision.state == EpochProposalState::AcceptedPendingGrace)
        != decision.grace_end_block.is_some()
    {
        return Err(EpochGovernanceError::InvalidState);
    }
    Ok(EpochDecisionRecordV1 {
        schema_version: 1,
        proposal_id: decision.proposal_id.clone(),
        parameter_set_cid: decision.parameter_set_cid.clone(),
        governance_epoch: decision.governance_epoch,
        proposal_set_root: decision.proposal_set_root.clone(),
        yes_weight: decision.yes_weight,
        no_weight: decision.no_weight,
        abstain_weight: decision.abstain_weight,
        total_registered_weight: decision.total_registered_weight,
        distinct_participants: decision.distinct_participants,
        distinct_yes_identities: decision.distinct_yes_identities,
        verified_or_human_yes_identities: decision.verified_or_human_yes_identities,
        state: decision.state,
        finalized_at_block: decision.finalized_at_block,
        grace_end_block: decision.grace_end_block,
    })
}

pub fn epoch_decision_record_bytes(
    decision: &EpochProposalDecisionV1,
) -> Result<Vec<u8>, EpochGovernanceError> {
    serde_json::to_vec(&epoch_decision_record(decision)?)
        .map_err(|_| EpochGovernanceError::InvalidState)
}

pub fn epoch_decision_record_cid(
    decision: &EpochProposalDecisionV1,
) -> Result<String, EpochGovernanceError> {
    Ok(cid_for(RAW_CODEC, &epoch_decision_record_bytes(decision)?).to_string())
}

fn proposal_identity(
    epoch: u64,
    caller: &str,
    content: &EpochProposalContentV1,
) -> Result<(String, String), EpochGovernanceError> {
    let bytes =
        serde_ipld_dagcbor::to_vec(content).map_err(|_| EpochGovernanceError::InvalidProposal)?;
    let proposal_cid = cid_for(DAG_CBOR_CODEC, &bytes).to_string();
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_ID_DOMAIN);
    hasher.update(epoch.to_be_bytes());
    hasher.update(address_bytes(caller)?);
    hasher.update(Sha256::digest(&bytes));
    let digest = hex::encode(hasher.finalize());
    Ok((format!("GOV-{epoch}-{}", &digest[..16]), proposal_cid))
}

fn execution_id(index: u64, proposal_id: &str, old: &str, new: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"IDENA_CODE_DAO_EXECUTION_V1");
    hasher.update(index.to_be_bytes());
    hasher.update(proposal_id.as_bytes());
    hasher.update(old.as_bytes());
    hasher.update(new.as_bytes());
    format!("exec-{}", &hex::encode(hasher.finalize())[..24])
}

fn proposal_evidence_ready(
    proposal: &ProposalRecord,
    gate: EpochGateParametersV1,
    required_availability_until: u64,
) -> bool {
    let ai = proposal.ai_review.as_ref();
    let build = proposal.build.as_ref();
    let availability = proposal.data_availability.as_ref();
    ai.is_some_and(|value| {
        value.valid_attestations >= gate.minimum_ai_attestations
            && value.independent_runtime_groups >= gate.minimum_ai_independence_groups
            && value.distinct_provider_families >= gate.minimum_ai_families
            && value.unresolved_critical_findings == 0
    }) && build.is_some_and(|value| {
        value.valid_builders >= gate.minimum_builders
            && value.distinct_platforms >= gate.minimum_builder_platforms
            && (!gate.require_matching_build_digests || value.matching_core_artifact_digests)
    }) && availability.is_some_and(|value| {
        value.independent_providers >= gate.minimum_data_availability_providers
            && value.valid_until_block >= required_availability_until
    })
}

fn validate_ballot_choices(
    frozen_ids: &[String],
    choices: &[EpochBallotChoiceV1],
) -> Result<(), EpochGovernanceError> {
    if choices.len() != frozen_ids.len() {
        return Err(EpochGovernanceError::InvalidBallot);
    }
    for (expected, actual) in frozen_ids.iter().zip(choices) {
        if expected != &actual.proposal_id {
            return Err(EpochGovernanceError::InvalidBallot);
        }
    }
    Ok(())
}

fn voting_power_reference(snapshot: &VotingPowerSnapshotV1) -> String {
    let bytes = serde_ipld_dagcbor::to_vec(snapshot)
        .expect("serializing an in-memory voting snapshot cannot fail");
    cid_for(DAG_CBOR_CODEC, &bytes).to_string()
}

fn validate_gate(gate: EpochGateParametersV1) -> Result<(), EpochGovernanceError> {
    if gate.turnout_quorum_bps == 0
        || gate.turnout_quorum_bps > 10_000
        || gate.yes_threshold_bps == 0
        || gate.yes_threshold_bps > 10_000
        || gate.minimum_participating_identities == 0
        || gate.minimum_yes_identities == 0
        || gate.minimum_ai_attestations == 0
        || gate.minimum_ai_independence_groups == 0
        || gate.minimum_ai_families == 0
        || gate.minimum_builders == 0
        || gate.minimum_builder_platforms == 0
        || gate.minimum_data_availability_providers == 0
        || gate.minimum_verified_or_human_yes > gate.minimum_yes_identities
        || gate.minimum_yes_identities > gate.minimum_participating_identities
    {
        return Err(EpochGovernanceError::InvalidParameters);
    }
    Ok(())
}

fn canonical_address(value: &str) -> Result<String, EpochGovernanceError> {
    normalize_address(value).map_err(|_| EpochGovernanceError::InvalidAddress)
}

fn address_bytes(value: &str) -> Result<[u8; 20], EpochGovernanceError> {
    let canonical = canonical_address(value)?;
    let decoded = hex::decode(&canonical[2..]).map_err(|_| EpochGovernanceError::InvalidAddress)?;
    decoded
        .try_into()
        .map_err(|_| EpochGovernanceError::InvalidAddress)
}

fn validate_dag_cbor_cid(value: &str) -> Result<(), EpochGovernanceError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| EpochGovernanceError::InvalidContentAddress)?;
    if cid.version() != Version::V1
        || cid.codec() != DAG_CBOR_CODEC
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return Err(EpochGovernanceError::InvalidContentAddress);
    }
    Ok(())
}

fn validate_content_cid(value: &str) -> Result<(), EpochGovernanceError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| EpochGovernanceError::InvalidContentAddress)?;
    if cid.version() != Version::V1
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return Err(EpochGovernanceError::InvalidContentAddress);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), EpochGovernanceError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(EpochGovernanceError::InvalidContentAddress);
    }
    Ok(())
}

fn decode_hash(value: &str) -> Result<[u8; 32], EpochGovernanceError> {
    validate_sha256(value)?;
    hex::decode(value)
        .map_err(|_| EpochGovernanceError::InvalidContentAddress)?
        .try_into()
        .map_err(|_| EpochGovernanceError::InvalidContentAddress)
}

fn push_len_prefixed(target: &mut Vec<u8>, value: &[u8]) -> Result<(), EpochGovernanceError> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| EpochGovernanceError::Overflow)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn parse_atoms(value: &str) -> Result<u128, EpochGovernanceError> {
    if value.is_empty()
        || value.len() > 39
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(EpochGovernanceError::InvalidParameters);
    }
    value
        .parse()
        .map_err(|_| EpochGovernanceError::InvalidParameters)
}

fn checked_add(left: u64, right: u64) -> Result<u64, EpochGovernanceError> {
    left.checked_add(right)
        .ok_or(EpochGovernanceError::Overflow)
}

fn add_balance(
    balances: &mut BTreeMap<String, u128>,
    address: &str,
    value: u128,
) -> Result<(), EpochGovernanceError> {
    if value == 0 {
        return Ok(());
    }
    let current = balances.get(address).copied().unwrap_or(0);
    balances.insert(
        address.to_string(),
        current
            .checked_add(value)
            .ok_or(EpochGovernanceError::Overflow)?,
    );
    Ok(())
}

fn mul_bps(amount: u128, bps: u16) -> Result<u128, EpochGovernanceError> {
    if bps > 10_000 {
        return Err(EpochGovernanceError::InvalidParameters);
    }
    let whole = (amount / 10_000)
        .checked_mul(u128::from(bps))
        .ok_or(EpochGovernanceError::Overflow)?;
    let remainder = (amount % 10_000)
        .checked_mul(u128::from(bps))
        .ok_or(EpochGovernanceError::Overflow)?
        / 10_000;
    whole
        .checked_add(remainder)
        .ok_or(EpochGovernanceError::Overflow)
}

fn ratio_bps(numerator: u128, denominator: u128) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let numerator = numerator.min(denominator);
    let whole = numerator / denominator;
    let addend = numerator % denominator;
    let mut remainder = 0u128;
    let mut fractional = 0u16;
    for _ in 0..10_000 {
        if addend != 0 && remainder >= denominator - addend {
            remainder -= denominator - addend;
            fractional += 1;
        } else {
            remainder += addend;
        }
    }
    ((whole as u16) * 10_000 + fractional).min(10_000)
}

mod decimal_u128 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 39
            || (value.len() > 1 && value.starts_with('0'))
            || value.bytes().any(|byte| !byte.is_ascii_digit())
        {
            return Err(D::Error::custom("expected a canonical u128 decimal string"));
        }
        value
            .parse()
            .map_err(|_| D::Error::custom("u128 decimal string is out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flip_trust_bps, package_dag_cbor};

    const ADDRESS_A: &str = "0x1111111111111111111111111111111111111111";
    const ADDRESS_B: &str = "0x2222222222222222222222222222222222222222";
    const ADDRESS_C: &str = "0x3333333333333333333333333333333333333333";
    const CONTRACT: &str = "0x9999999999999999999999999999999999999999";
    const CID_A: &str = "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm";
    const CID_B: &str = "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    const RAW_CID: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

    #[test]
    fn experimental_parameter_set_has_the_locked_cid() {
        let package = package_dag_cbor(EpochGovernanceParameterSetV1::experimental_defaults())
            .expect("default Governance Day parameters must package");
        assert_eq!(
            package.root_cid.to_string(),
            "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq"
        );
        assert_eq!(
            package.root_sha256,
            "788782538cbcb9137d4b9e9feb6b5ed368a7017067dda158c4383e68da73a02c"
        );
    }

    fn parameters() -> EpochGovernanceParameterSetV1 {
        let mut value = EpochGovernanceParameterSetV1::experimental_defaults();
        value.normal.minimum_participating_identities = 1;
        value.normal.minimum_yes_identities = 1;
        value.normal.minimum_verified_or_human_yes = 1;
        value.critical.minimum_participating_identities = 1;
        value.critical.minimum_yes_identities = 1;
        value.critical.minimum_verified_or_human_yes = 1;
        value
    }

    fn engine() -> EpochGovernanceEngine {
        let mut engine = EpochGovernanceEngine::initialize(
            "idena-governance-local-v1",
            CONTRACT,
            CID_A,
            CID_A,
            parameters(),
        )
        .unwrap();
        engine
            .anchor_governance_epoch(EpochGovernanceClock {
                epoch: 421,
                block: 1_000,
            })
            .unwrap();
        register_snapshot(
            &mut engine,
            421,
            ADDRESS_A,
            IdentityState::Human,
            10_000_000_000_000_000_000,
        );
        register_snapshot(
            &mut engine,
            421,
            ADDRESS_B,
            IdentityState::Verified,
            10_000_000_000_000_000_000,
        );
        engine
    }

    fn register_snapshot(
        engine: &mut EpochGovernanceEngine,
        epoch: u64,
        address: &str,
        state: IdentityState,
        stake: u128,
    ) {
        let trust = flip_trust_bps(20, 0).unwrap();
        let weight = effective_vote_weight(stake, state.status_bps().unwrap(), trust).unwrap();
        engine
            .register_voting_power_snapshot(VotingPowerSnapshotV1 {
                schema_version: 1,
                governance_epoch: epoch,
                voter_address: address.to_string(),
                identity_state: state,
                finalized_authored_flips: 20,
                consensus_reported_authored_flips: 0,
                flip_trust_bps: trust,
                active_stake_atoms: stake,
                effective_vote_weight: weight,
                source_block_height: 123,
                source_block_hash: "11".repeat(32),
            })
            .unwrap();
    }

    fn proposal(title: &str) -> EpochProposalContentV1 {
        EpochProposalContentV1 {
            schema_version: 1,
            title: title.to_string(),
            parent_canonical_ecosystem_cid: CID_A.to_string(),
            candidate_ecosystem_cid: CID_B.to_string(),
            candidate_manifest_sha256: "22".repeat(32),
            parameter_set_cid: CID_A.to_string(),
            affected_repositories: vec!["P2poolBTC".to_string()],
            changed_file_count: 1,
            patch_bytes: 100,
            source_package_bytes: 1_000,
            description_bytes: 100,
            migration_operation_count: 0,
            risk_class: RiskClass::Normal,
            rationale_cid: RAW_CID.to_string(),
            test_plan_cid: RAW_CID.to_string(),
            rollback_manifest_cid: RAW_CID.to_string(),
            rollback_instructions_cid: RAW_CID.to_string(),
            social_discussion: Some(SocialDiscussionReferenceV1 {
                post_id: Some("post-1".into()),
                discussion_cid: Some(RAW_CID.into()),
                contract_reference: None,
                creation_transaction_reference: None,
            }),
            proposal_kind: EpochProposalKindV1::Change,
        }
    }

    fn attach_evidence(engine: &mut EpochGovernanceEngine, proposal_id: &str) {
        engine
            .attach_ai_review_root(
                proposal_id,
                AiReviewEvidenceV1 {
                    root: "33".repeat(32),
                    valid_attestations: 2,
                    independent_runtime_groups: 2,
                    distinct_provider_families: 1,
                    unresolved_critical_findings: 0,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_050,
                },
            )
            .unwrap();
        engine
            .attach_build_root(
                proposal_id,
                BuildRootEvidenceV1 {
                    root: "44".repeat(32),
                    valid_builders: 2,
                    distinct_platforms: 1,
                    matching_core_artifact_digests: true,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_050,
                },
            )
            .unwrap();
        engine
            .attach_data_availability_root(
                proposal_id,
                DataAvailabilityEvidenceV1 {
                    root: "55".repeat(32),
                    independent_providers: 2,
                    valid_until_block: 1_780,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_050,
                },
            )
            .unwrap();
    }

    #[test]
    fn proposal_slot_is_atomic_and_persists_after_cancellation() {
        let mut engine = engine();
        let malformed = EpochProposalContentV1 {
            title: "".into(),
            ..proposal("bad")
        };
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                malformed,
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010
                }
            ),
            Err(EpochGovernanceError::InvalidProposal)
        );
        assert_eq!(engine.proposal_slot(421, ADDRESS_A).unwrap(), None);
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("one"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                proposal("two"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_011
                }
            ),
            Err(EpochGovernanceError::ProposalSlotUsed)
        );
        engine
            .cancel_proposal_before_cutoff(
                ADDRESS_A,
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_020,
                },
            )
            .unwrap();
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                proposal("three"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_021
                }
            ),
            Err(EpochGovernanceError::ProposalSlotUsed)
        );
        assert!(engine
            .create_proposal(
                ADDRESS_B,
                proposal("independent"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_021
                }
            )
            .is_ok());
    }

    #[test]
    fn next_epoch_restores_one_slot() {
        let mut engine = engine();
        engine
            .create_proposal(
                ADDRESS_A,
                proposal("first"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        engine
            .anchor_governance_epoch(EpochGovernanceClock {
                epoch: 422,
                block: 2_000,
            })
            .unwrap();
        register_snapshot(
            &mut engine,
            422,
            ADDRESS_A,
            IdentityState::Human,
            10_000_000_000_000_000_000,
        );
        assert!(engine
            .create_proposal(
                ADDRESS_A,
                proposal("next"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 422,
                    block: 2_010
                }
            )
            .is_ok());
    }

    #[test]
    fn cutoff_and_frozen_set_reject_late_insertion_without_consuming_a_slot() {
        let mut engine = engine();
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                proposal("at-cutoff"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_040,
                },
            ),
            Err(EpochGovernanceError::InvalidWindow)
        );
        assert_eq!(engine.proposal_slot(421, ADDRESS_A).unwrap(), None);

        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        assert_eq!(
            engine.create_proposal(
                ADDRESS_B,
                proposal("after-freeze"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_041,
                },
            ),
            Err(EpochGovernanceError::InvalidWindow)
        );
        assert_eq!(engine.proposal_slot(421, ADDRESS_B).unwrap(), None);
    }

    #[test]
    fn voting_snapshot_recomputes_flip_trust_and_validates_source_hash() {
        let mut engine = engine();
        let stake = 10_000_000_000_000_000_000;
        let honest_trust = flip_trust_bps(20, 4).unwrap();
        let honest_weight = effective_vote_weight(stake, 10_000, honest_trust).unwrap();
        let mut snapshot = VotingPowerSnapshotV1 {
            schema_version: 1,
            governance_epoch: 421,
            voter_address: ADDRESS_C.to_string(),
            identity_state: IdentityState::Human,
            finalized_authored_flips: 20,
            consensus_reported_authored_flips: 4,
            flip_trust_bps: 10_000,
            active_stake_atoms: stake,
            effective_vote_weight: effective_vote_weight(stake, 10_000, 10_000).unwrap(),
            source_block_height: 123,
            source_block_hash: "33".repeat(32),
        };
        assert_eq!(
            engine.register_voting_power_snapshot(snapshot.clone()),
            Err(EpochGovernanceError::IneligibleIdentity)
        );
        snapshot.flip_trust_bps = honest_trust;
        snapshot.effective_vote_weight = honest_weight;
        snapshot.source_block_hash = "not-a-canonical-hash".into();
        assert_eq!(
            engine.register_voting_power_snapshot(snapshot.clone()),
            Err(EpochGovernanceError::IneligibleIdentity)
        );
        snapshot.source_block_hash = "33".repeat(32);
        engine.register_voting_power_snapshot(snapshot).unwrap();
    }

    #[test]
    fn frozen_weight_denominator_rejects_late_snapshot_insertion() {
        let mut engine = engine();
        let expected = engine.current_registered_weight(421).unwrap();
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        assert_eq!(engine.frozen_registered_weight(421).unwrap(), expected);

        let trust = flip_trust_bps(20, 0).unwrap();
        let stake = 10_000_000_000_000_000_000;
        let weight = effective_vote_weight(stake, 10_000, trust).unwrap();
        assert_eq!(
            engine.register_voting_power_snapshot(VotingPowerSnapshotV1 {
                schema_version: 1,
                governance_epoch: 421,
                voter_address: ADDRESS_C.to_string(),
                identity_state: IdentityState::Human,
                finalized_authored_flips: 20,
                consensus_reported_authored_flips: 0,
                flip_trust_bps: trust,
                active_stake_atoms: stake,
                effective_vote_weight: weight,
                source_block_height: 123,
                source_block_hash: "33".repeat(32),
            }),
            Err(EpochGovernanceError::InvalidState)
        );
        assert_eq!(engine.frozen_registered_weight(421).unwrap(), expected);
    }

    #[test]
    fn no_op_and_inconsistent_revert_proposals_are_rejected_without_using_slot() {
        let mut engine = engine();
        let mut no_op = proposal("no-op");
        no_op.candidate_ecosystem_cid = no_op.parent_canonical_ecosystem_cid.clone();
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                no_op,
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            ),
            Err(EpochGovernanceError::InvalidProposal)
        );
        assert_eq!(engine.proposal_slot(421, ADDRESS_A).unwrap(), None);

        let mut inconsistent = proposal("bad-revert");
        inconsistent.proposal_kind = EpochProposalKindV1::Revert(RevertProposalV1 {
            schema_version: 1,
            execution_id: "missing-execution".into(),
            current_canonical_cid: CID_A.into(),
            replacement_canonical_cid: CID_B.into(),
            reason_cid: RAW_CID.into(),
            evidence_cid: RAW_CID.into(),
            affected_repositories: vec!["idena-go".into()],
            rollback_instructions_cid: RAW_CID.into(),
            compatibility_checks_cid: RAW_CID.into(),
            expedited_recovery: false,
        });
        assert_eq!(
            engine.create_proposal(
                ADDRESS_A,
                inconsistent,
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            ),
            Err(EpochGovernanceError::InvalidProposal)
        );
        assert_eq!(engine.proposal_slot(421, ADDRESS_A).unwrap(), None);
    }

    #[test]
    fn frozen_order_and_batch_ballot_are_exact() {
        let mut engine = engine();
        let first = engine
            .create_proposal(
                ADDRESS_A,
                proposal("z"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        let second = engine
            .create_proposal(
                ADDRESS_B,
                proposal("a"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_011,
                },
            )
            .unwrap();
        attach_evidence(&mut engine, &first);
        attach_evidence(&mut engine, &second);
        let frozen = engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let mut expected = vec![first, second];
        expected.sort();
        assert_eq!(frozen.ordered_proposal_ids, expected);
        let choices: Vec<_> = expected
            .iter()
            .map(|id| EpochBallotChoiceV1 {
                proposal_id: id.clone(),
                choice: VoteChoice::Yes,
            })
            .collect();
        let ballot = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                choices.clone(),
                BTreeMap::from([(expected[0].clone(), "private note".into())]),
                7,
                &"55".repeat(32),
            )
            .unwrap();
        let mut reordered = choices;
        reordered.reverse();
        assert_eq!(
            engine.prepare_epoch_ballot(
                421,
                ADDRESS_A,
                reordered,
                BTreeMap::new(),
                7,
                &"55".repeat(32)
            ),
            Err(EpochGovernanceError::InvalidBallot)
        );
        assert_eq!(
            engine.prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![EpochBallotChoiceV1 {
                    proposal_id: expected[0].clone(),
                    choice: VoteChoice::Yes,
                }],
                BTreeMap::new(),
                7,
                &"55".repeat(32),
            ),
            Err(EpochGovernanceError::InvalidBallot)
        );
        assert_eq!(
            engine.prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![
                    EpochBallotChoiceV1 {
                        proposal_id: expected[0].clone(),
                        choice: VoteChoice::Yes,
                    },
                    EpochBallotChoiceV1 {
                        proposal_id: "unknown-proposal".into(),
                        choice: VoteChoice::No,
                    },
                ],
                BTreeMap::new(),
                7,
                &"55".repeat(32),
            ),
            Err(EpochGovernanceError::InvalidBallot)
        );
        let mut extra = expected
            .iter()
            .map(|id| EpochBallotChoiceV1 {
                proposal_id: id.clone(),
                choice: VoteChoice::Yes,
            })
            .collect::<Vec<_>>();
        extra.push(EpochBallotChoiceV1 {
            proposal_id: "extra-proposal".into(),
            choice: VoteChoice::Abstain,
        });
        assert_eq!(
            engine.prepare_epoch_ballot(
                421,
                ADDRESS_A,
                extra,
                BTreeMap::new(),
                7,
                &"55".repeat(32),
            ),
            Err(EpochGovernanceError::InvalidBallot)
        );
        engine
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &ballot.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        engine
            .reveal_epoch_ballot(
                ADDRESS_A,
                &ballot,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_100,
                },
            )
            .unwrap();
        assert_eq!(
            engine.reveal_epoch_ballot(
                ADDRESS_A,
                &ballot,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_101
                }
            ),
            Err(EpochGovernanceError::BallotAlreadySubmitted)
        );
        let decisions = engine
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap();
        assert!(decisions
            .iter()
            .all(|item| item.state == EpochProposalState::AcceptedPendingGrace));
    }

    #[test]
    fn local_notes_are_not_committed_and_wrong_secret_is_rejected() {
        let mut engine = engine();
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("one"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        attach_evidence(&mut engine, &id);
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let choices = vec![EpochBallotChoiceV1 {
            proposal_id: id.clone(),
            choice: VoteChoice::Yes,
        }];
        let one = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                choices.clone(),
                BTreeMap::new(),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        let two = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                choices,
                BTreeMap::from([(id, "different".into())]),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        assert_eq!(one.commitment, two.commitment);
        engine
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &one.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        let mut wrong = one;
        wrong.commitment_salt = "66".repeat(32);
        assert_eq!(
            engine.reveal_epoch_ballot(
                ADDRESS_A,
                &wrong,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_100
                }
            ),
            Err(EpochGovernanceError::InvalidCommitment)
        );
    }

    #[test]
    fn missed_reveal_does_not_count_and_no_quorum_refunds_less_fee() {
        let mut engine = engine();
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("one"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        attach_evidence(&mut engine, &id);
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let ballot = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![EpochBallotChoiceV1 {
                    proposal_id: id.clone(),
                    choice: VoteChoice::Yes,
                }],
                BTreeMap::new(),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        engine
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &ballot.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        let decision = engine
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap()
            .remove(0);
        assert_eq!(decision.state, EpochProposalState::NoQuorum);
        assert_eq!(decision.distinct_participants, 0);
        assert_eq!(
            engine.claim_refund(ADDRESS_A).unwrap(),
            9_900_000_000_000_000_000
        );
        assert_eq!(
            engine.proposal_slot(421, ADDRESS_A).unwrap(),
            Some(id.as_str())
        );
    }

    #[test]
    fn rejection_and_expiration_do_not_restore_the_epoch_slot() {
        let mut rejected = engine();
        let rejected_id = rejected
            .create_proposal(
                ADDRESS_A,
                proposal("rejected"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        attach_evidence(&mut rejected, &rejected_id);
        rejected
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let no_ballot = rejected
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![EpochBallotChoiceV1 {
                    proposal_id: rejected_id.clone(),
                    choice: VoteChoice::No,
                }],
                BTreeMap::new(),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        rejected
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &no_ballot.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        rejected
            .reveal_epoch_ballot(
                ADDRESS_A,
                &no_ballot,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_100,
                },
            )
            .unwrap();
        let decision = rejected
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap()
            .remove(0);
        assert_eq!(decision.state, EpochProposalState::Rejected);
        assert_eq!(
            rejected.proposal_slot(421, ADDRESS_A).unwrap(),
            Some(rejected_id.as_str())
        );

        let mut expired = engine();
        let expired_id = expired
            .create_proposal(
                ADDRESS_A,
                proposal("expired"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        expired
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let decision = expired
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap()
            .remove(0);
        assert_eq!(decision.state, EpochProposalState::Expired);
        assert_eq!(
            expired.proposal_slot(421, ADDRESS_A).unwrap(),
            Some(expired_id.as_str())
        );
    }

    #[test]
    fn evidence_diversity_is_bounded_and_availability_is_mandatory() {
        let mut engine = engine();
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("missing-availability"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        assert_eq!(
            engine.attach_ai_review_root(
                &id,
                AiReviewEvidenceV1 {
                    root: "33".repeat(32),
                    valid_attestations: 2,
                    independent_runtime_groups: 3,
                    distinct_provider_families: 1,
                    unresolved_critical_findings: 0,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_020,
                },
            ),
            Err(EpochGovernanceError::InvalidParameters)
        );
        engine
            .attach_ai_review_root(
                &id,
                AiReviewEvidenceV1 {
                    root: "33".repeat(32),
                    valid_attestations: 2,
                    independent_runtime_groups: 2,
                    distinct_provider_families: 1,
                    unresolved_critical_findings: 0,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_020,
                },
            )
            .unwrap();
        assert_eq!(
            engine.attach_build_root(
                &id,
                BuildRootEvidenceV1 {
                    root: "44".repeat(32),
                    valid_builders: 2,
                    distinct_platforms: 3,
                    matching_core_artifact_digests: true,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_020,
                },
            ),
            Err(EpochGovernanceError::InvalidParameters)
        );
        engine
            .attach_build_root(
                &id,
                BuildRootEvidenceV1 {
                    root: "44".repeat(32),
                    valid_builders: 2,
                    distinct_platforms: 1,
                    matching_core_artifact_digests: true,
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_020,
                },
            )
            .unwrap();
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let decision = engine
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap()
            .remove(0);
        assert_eq!(decision.state, EpochProposalState::Expired);
    }

    #[test]
    fn grace_blocks_execution_and_history_is_append_only() {
        let mut engine = engine();
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("one"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        attach_evidence(&mut engine, &id);
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let ballot = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![EpochBallotChoiceV1 {
                    proposal_id: id.clone(),
                    choice: VoteChoice::Yes,
                }],
                BTreeMap::new(),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        engine
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &ballot.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        engine
            .reveal_epoch_ballot(
                ADDRESS_A,
                &ballot,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_100,
                },
            )
            .unwrap();
        let decision = engine
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap()
            .remove(0);
        assert_eq!(
            engine.enter_execution_ready_state(
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_179
                }
            ),
            Err(EpochGovernanceError::ExecutionBlocked)
        );
        engine
            .enter_execution_ready_state(
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_180,
                },
            )
            .unwrap();
        let history = engine
            .execute_proposal(
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_180,
                },
            )
            .unwrap();
        assert_eq!(
            history.decision_record_cid,
            epoch_decision_record_cid(&decision).unwrap()
        );
        assert_eq!(history.previous_canonical_ecosystem_cid, CID_A);
        assert_eq!(history.new_canonical_ecosystem_cid, CID_B);
        assert_eq!(engine.canonical_history().len(), 1);
        assert_eq!(
            engine.execute_proposal(
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_181
                }
            ),
            Err(EpochGovernanceError::ExecutionBlocked)
        );
        assert_eq!(
            engine.claim_refund(ADDRESS_A).unwrap(),
            10_000_000_000_000_000_000
        );
    }

    #[test]
    fn objective_challenge_blocks_epoch_execution_and_is_deterministically_resolved() {
        let mut engine = engine();
        let id = engine
            .create_proposal(
                ADDRESS_A,
                proposal("challenged"),
                10_000_000_000_000_000_000,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_010,
                },
            )
            .unwrap();
        attach_evidence(&mut engine, &id);
        engine
            .freeze_epoch_proposal_set(EpochGovernanceClock {
                epoch: 421,
                block: 1_040,
            })
            .unwrap();
        let ballot = engine
            .prepare_epoch_ballot(
                421,
                ADDRESS_A,
                vec![EpochBallotChoiceV1 {
                    proposal_id: id.clone(),
                    choice: VoteChoice::Yes,
                }],
                BTreeMap::new(),
                1,
                &"55".repeat(32),
            )
            .unwrap();
        engine
            .commit_epoch_ballot(
                ADDRESS_A,
                421,
                &ballot.commitment,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_080,
                },
            )
            .unwrap();
        engine
            .reveal_epoch_ballot(
                ADDRESS_A,
                &ballot,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_100,
                },
            )
            .unwrap();
        engine
            .finalize_epoch_voting(EpochGovernanceClock {
                epoch: 421,
                block: 1_120,
            })
            .unwrap();
        engine
            .open_objective_challenge(
                &id,
                ObjectiveChallengeV1::CandidateManifestDigestMismatch {
                    proposal_id: id.clone(),
                    candidate_manifest_bytes: Vec::new(),
                    evidence_cid: RAW_CID.into(),
                },
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_121,
                },
            )
            .unwrap();
        assert_eq!(
            engine.enter_execution_ready_state(
                &id,
                EpochGovernanceClock {
                    epoch: 421,
                    block: 1_180,
                },
            ),
            Err(EpochGovernanceError::ExecutionBlocked)
        );
        assert!(engine.resolve_objective_challenge(&id).unwrap());
        assert_eq!(
            engine.proposal(&id).unwrap().state,
            EpochProposalState::Rejected
        );
        assert_eq!(engine.canonical_history().len(), 0);
    }

    #[test]
    fn local_rollback_only_stages_and_never_claims_chain_recovery_when_stuck() {
        let bytes = b"known-good-binary";
        let manifest = RecoveryManifestV1 {
            schema_version: 1,
            canonical_history_cid: RAW_CID.into(),
            last_known_good_ecosystem_cid: CID_A.into(),
            release_manifest_cid: RAW_CID.into(),
            artifact_cid: RAW_CID.into(),
            artifact_sha256: hex::encode(Sha256::digest(bytes)),
            compatibility_metadata_cid: RAW_CID.into(),
            rollback_instructions_cid: RAW_CID.into(),
            chain_rpc_required_for_on_chain_revert: true,
        };
        let plan = stage_local_rollback(RAW_CID, &manifest, "/staging/node", bytes, false).unwrap();
        assert!(plan.explicit_user_confirmation_required);
        assert!(!plan.unattended_install_enabled);
        assert!(!plan.unattended_rollback_enabled);
        assert!(!plan.on_chain_revert_available);
    }

    #[test]
    fn social_activity_never_changes_commitment_or_tally() {
        let choices = vec![EpochBallotChoiceV1 {
            proposal_id: "GOV-1-a".into(),
            choice: VoteChoice::Yes,
        }];
        let one = ballot_commitment(&BallotCommitmentInputV1 {
            chain_id: "chain",
            contract_address: CONTRACT,
            governance_epoch: 1,
            voter_address: ADDRESS_A,
            frozen_proposal_set_root: &"11".repeat(32),
            choices: &choices,
            ballot_nonce: 1,
            salt: &"22".repeat(32),
        })
        .unwrap();
        let two = ballot_commitment(&BallotCommitmentInputV1 {
            chain_id: "chain",
            contract_address: CONTRACT,
            governance_epoch: 1,
            voter_address: ADDRESS_A,
            frozen_proposal_set_root: &"11".repeat(32),
            choices: &choices,
            ballot_nonce: 1,
            salt: &"22".repeat(32),
        })
        .unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn shared_epoch_ballot_vector_is_stable() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/governance/epoch-ballot-vectors-v1.json"
        ))
        .unwrap();
        let case = &vectors["cases"][0];
        let labels = ["a", "b", "c"];
        let choices = case["choices"]
            .as_array()
            .unwrap()
            .iter()
            .zip(labels)
            .map(|(choice, label)| EpochBallotChoiceV1 {
                proposal_id: label.to_string(),
                choice: match choice.as_str().unwrap() {
                    "yes" => VoteChoice::Yes,
                    "no" => VoteChoice::No,
                    "abstain" => VoteChoice::Abstain,
                    _ => unreachable!(),
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ballot_commitment(&BallotCommitmentInputV1 {
                chain_id: case["chainId"].as_str().unwrap(),
                contract_address: case["contractAddress"].as_str().unwrap(),
                governance_epoch: case["governanceEpoch"].as_u64().unwrap(),
                voter_address: case["voterAddress"].as_str().unwrap(),
                frozen_proposal_set_root: case["frozenProposalSetRoot"].as_str().unwrap(),
                choices: &choices,
                ballot_nonce: case["ballotNonce"].as_u64().unwrap(),
                salt: case["salt"].as_str().unwrap(),
            })
            .unwrap(),
            case["expectedCommitment"].as_str().unwrap()
        );
    }
}
