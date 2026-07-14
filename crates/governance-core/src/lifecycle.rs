use crate::{
    cid_for, effective_vote_weight, evaluate_gates, normalize_address, package_dag_cbor,
    package_toolchain_manifest_for_ecosystem, stake_score, verify_agent_review_attestation_car,
    verify_build_attestation_car, verify_dag_cbor_car, verify_data_availability_attestation_car,
    verify_ecosystem_manifest_car, verify_ecosystem_patch_manifest_car,
    verify_ecosystem_transition, verify_identity_metrics_attestation_car,
    verify_identity_metrics_proof, verify_pinset_manifest_car,
    verify_pinset_manifest_for_transition, AcceptanceEvidence, ArtifactManifestV1, BuildArtifactV1,
    DagCborPackage, GateResults, GovernanceIdentityMetricsLeafV1, GovernanceIdentityMetricsProofV1,
    GovernanceParameterSetV1, IdentityState, RepositoryCidV1, ReviewVerdictV1, RiskClass,
    VoteChoice,
};
use cid::Cid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const RAW_CODEC: u64 = 0x55;
const DAG_CBOR_CODEC: u64 = 0x71;
const MAX_OBJECTIVE_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_REVIEW_ATTESTATIONS_PER_CLASS: usize = 256;
const MAX_ATTESTATIONS_PER_OWNER_PER_CLASS: usize = 2;
const MAX_CONTRACT_DAG_CBOR_BYTES: usize = 65_536;
const MAX_REQUIRED_AVAILABILITY_CIDS: usize = 4_096;
pub const GOVERNANCE_CONTRACT_VERSION: &str = "0.1.0";
pub const AGENT_REVIEW_COMMITMENT_DOMAIN: &str = "agent_review_v1";
pub const BUILD_ATTESTATION_COMMITMENT_DOMAIN: &str = "build_attestation_v1";
pub const DATA_AVAILABILITY_COMMITMENT_DOMAIN: &str = "data_availability_v1";
const ATTESTATION_NODE_DOMAIN: &[u8] = b"IDENA_GOV_ATTESTATION_MERKLE_V1\0";
const ATTESTATION_ROOT_DOMAIN: &[u8] = b"IDENA_GOV_ATTESTATION_ROOT_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceClock {
    pub block: u64,
    pub epoch: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct OpenReviewRoundInputV1<'a> {
    pub parent_car: &'a [u8],
    pub candidate_car: &'a [u8],
    pub patch_car: &'a [u8],
    pub pinset_car: &'a [u8],
    pub opener_address: &'a str,
    pub attached_bond_atoms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    Draft,
    ReviewOpen,
    VotingOpen,
    AcceptedPendingChallenge,
    Rejected,
    Challenged,
    AcceptedPendingExecution,
    Executed,
    Stale,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewRoundState {
    Open,
    Frozen,
    Claimed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CidCommitmentProofV1 {
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltCidCommitment {
    pub root: String,
    pub proofs: BTreeMap<String, CidCommitmentProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationCommitmentEntryV1 {
    pub attestation_cid: String,
    pub canonical_fields: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeProposalContentV1 {
    pub schema_version: u16,
    pub parent_canonical_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub affected_repositories: Vec<String>,
    pub base_source_cids: BTreeMap<String, String>,
    pub candidate_source_cids: BTreeMap<String, String>,
    pub patch_cid: String,
    pub review_round_id: String,
    pub proposer_address: String,
    #[serde(with = "decimal_u128")]
    pub proposal_bond_atoms: u128,
    pub risk_class: RiskClass,
    pub rationale_cid: String,
    pub migration_notes_cid: String,
    pub test_plan_cid: String,
    pub release_manifest_cid: Option<String>,
    pub critical_finding_waiver_cid: Option<String>,
    pub agent_review_root: String,
    pub build_attestation_root: String,
    pub data_availability_root: String,
    pub creation_block: u64,
    pub creation_epoch: u16,
    pub staking_epoch: u16,
    pub identity_metrics_epoch: u16,
    pub candidate_identity_metrics_root: Option<String>,
    pub candidate_identity_metrics_epoch: Option<u16>,
    pub voting_start: u64,
    pub voting_end: u64,
    pub challenge_end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentAttestationInputV1 {
    pub attestation_cid: String,
    pub attestation_car: Vec<u8>,
    pub parent_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub patch_cid: String,
    pub owner_address: String,
    pub model_identifier: String,
    pub model_revision: Option<String>,
    pub runtime_identifier: String,
    pub independence_group: String,
    pub verdict: AttestationVerdict,
    pub unresolved_critical_findings: u32,
    pub test_result_cid: String,
    pub tests_passed_claim: bool,
    pub bond_atoms: u128,
    pub commitment_proof: CidCommitmentProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildAttestationInputV1 {
    pub attestation_cid: String,
    pub attestation_car: Vec<u8>,
    pub candidate_ecosystem_cid: String,
    pub builder_address: String,
    pub runtime_family: String,
    pub architecture: String,
    pub core_artifact_digest: String,
    pub test_result_cid: String,
    pub tests_passed_claim: bool,
    pub bond_atoms: u128,
    pub commitment_proof: CidCommitmentProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataAvailabilityAttestationInputV1 {
    pub attestation_cid: String,
    pub attestation_car: Vec<u8>,
    pub candidate_ecosystem_cid: String,
    pub provider_id: String,
    pub operator_address: String,
    pub pinset_cid: String,
    pub verified_cids: Vec<String>,
    pub probe_result_cid: String,
    pub available_claim: bool,
    pub expires_at_block: u64,
    pub bond_atoms: u128,
    pub commitment_proof: CidCommitmentProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceVoteReceiptV1 {
    pub schema_version: u16,
    pub proposal_id: String,
    pub voter_address: String,
    pub choice: VoteChoice,
    pub staking_epoch: u16,
    pub identity_metrics_epoch: u16,
    #[serde(with = "decimal_u128")]
    pub active_stake_atoms: u128,
    #[serde(with = "decimal_u128")]
    pub stake_score: u128,
    pub identity_status_bps: u16,
    pub flip_trust_bps: u16,
    #[serde(with = "decimal_u128")]
    pub effective_vote_weight: u128,
    pub cast_at_block: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObjectiveChallengeTarget {
    AgentTestResult,
    BuilderTestResult,
    DataAvailabilityProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectiveChallengeInputV1 {
    pub challenger_address: String,
    pub target: ObjectiveChallengeTarget,
    pub attestation_cid: String,
    pub evidence_cid: String,
    pub evidence_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GovernanceEvent {
    CanonicalEcosystemChanged {
        old_cid: String,
        new_cid: String,
        proposal_id: String,
        agent_review_root: String,
        build_attestation_root: String,
        data_availability_root: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakePositionView {
    pub pending_activation_atoms: u128,
    pub active_atoms: u128,
    pub scheduled_withdrawal_atoms: u128,
    pub unbonding_atoms: u128,
}

#[derive(Debug, Clone)]
pub struct ProposalView {
    pub proposal_id: String,
    pub state: ProposalState,
    pub content: ChangeProposalContentV1,
    pub gates: Option<GateResults>,
    pub vote_count: usize,
    pub challenge_end: u64,
    pub execution_not_before: u64,
    pub execution_expires: u64,
}

#[derive(Debug, Clone)]
pub struct ReviewRoundView {
    pub review_round_id: String,
    pub state: ReviewRoundState,
    pub parent_cid: String,
    pub candidate_cid: String,
    pub patch_cid: String,
    pub opener_address: String,
    pub opened_block: u64,
    pub end_block: u64,
    pub claim_deadline: u64,
    pub proposal_id: Option<String>,
    pub agent_review_root: Option<String>,
    pub build_attestation_root: Option<String>,
    pub data_availability_root: Option<String>,
    pub agent_attestations: usize,
    pub build_attestations: usize,
    pub data_availability_attestations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMetricsCertificationView {
    pub metrics_root: String,
    pub source_epoch: u16,
    pub attestation_count: usize,
    pub minimum_required: u32,
    pub certified: bool,
    pub conflict: bool,
    pub descriptor_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChangeProposalPackage {
    pub proposal_id: String,
    pub content_cid: Cid,
    pub content_sha256: String,
    pub content: ChangeProposalContentV1,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    #[error("governance parameters are invalid: {0}")]
    InvalidParameters(String),
    #[error("address is invalid")]
    InvalidAddress,
    #[error("CID or digest is invalid: {0}")]
    InvalidContentAddress(String),
    #[error("arithmetic overflow")]
    Overflow,
    #[error("attached amount is below the required bond or stake minimum")]
    InsufficientAmount,
    #[error("identity metrics proof is invalid or ineligible")]
    InvalidIdentityProof,
    #[error("proposal content is malformed or not immutable")]
    InvalidProposal,
    #[error("proposal parent is stale")]
    StaleParent,
    #[error("proposal or attestation already exists")]
    Duplicate,
    #[error("proposal was not found")]
    ProposalNotFound,
    #[error("review round was not found")]
    ReviewRoundNotFound,
    #[error("review round attestation class reached its bounded capacity")]
    ReviewRoundFull,
    #[error("operation is invalid in review round state {0:?}")]
    InvalidReviewRoundState(ReviewRoundState),
    #[error("operation is invalid in proposal state {0:?}")]
    InvalidState(ProposalState),
    #[error("operation is outside its deterministic block or epoch boundary")]
    InvalidDeadline,
    #[error("attestation is not committed or is bound to different content")]
    InvalidAttestation,
    #[error("voter has no snapshotted eligible governance weight")]
    IneligibleVoter,
    #[error("withdrawal exceeds unscheduled active stake")]
    InsufficientActiveStake,
    #[error("objective challenge payload is malformed")]
    InvalidChallenge,
    #[error("refund balance is empty")]
    NoRefund,
}

#[derive(Debug, Clone)]
struct StakeLot {
    atoms: u128,
    activation_epoch: u16,
}

#[derive(Debug, Clone)]
struct ScheduledWithdrawal {
    atoms: u128,
    start_epoch: u16,
    release_epoch: u16,
}

#[derive(Debug, Clone, Default)]
struct StakePosition {
    active_atoms: u128,
    pending: Vec<StakeLot>,
    scheduled: Vec<ScheduledWithdrawal>,
    unbonding: Vec<ScheduledWithdrawal>,
}

#[derive(Debug, Clone)]
struct VoterSnapshot {
    stake_atoms: u128,
    status_bps: u16,
    state: IdentityState,
    trust_bps: u16,
    weight: u128,
}

#[derive(Debug, Clone)]
struct BondedAgentAttestation {
    input: AgentAttestationInputV1,
    settled: bool,
}

#[derive(Debug, Clone)]
struct BondedBuildAttestation {
    input: BuildAttestationInputV1,
    settled: bool,
}

#[derive(Debug, Clone)]
struct BondedDataAvailabilityAttestation {
    input: DataAvailabilityAttestationInputV1,
    settled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BondTarget {
    Agent,
    Builder,
    Availability,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    input: ObjectiveChallengeInputV1,
    target_type: BondTarget,
}

#[derive(Debug, Clone)]
struct ProposalRecord {
    id: String,
    state: ProposalState,
    content: ChangeProposalContentV1,
    proposal_bond_settled: bool,
    agents: BTreeMap<String, BondedAgentAttestation>,
    builders: BTreeMap<String, BondedBuildAttestation>,
    availability: BTreeMap<String, BondedDataAvailabilityAttestation>,
    required_availability_cids: BTreeSet<String>,
    voter_snapshot: BTreeMap<String, VoterSnapshot>,
    votes: BTreeMap<String, GovernanceVoteReceiptV1>,
    yes_weight: u128,
    no_weight: u128,
    abstain_weight: u128,
    total_registered_weight: u128,
    gates: Option<GateResults>,
    pending_challenge: Option<PendingChallenge>,
    challenge_end: u64,
    execution_not_before: u64,
    execution_expires: u64,
}

#[derive(Debug, Clone)]
struct ReviewRoundRecord {
    id: String,
    state: ReviewRoundState,
    parent_cid: String,
    candidate_cid: String,
    patch_cid: String,
    affected_repositories: Vec<String>,
    base_source_cids: BTreeMap<String, String>,
    candidate_source_cids: BTreeMap<String, String>,
    all_candidate_source_cids: Vec<RepositoryCidV1>,
    candidate_artifact_keys: BTreeSet<String>,
    toolchain_cid: String,
    pinset_cid: String,
    pinset_cids: Vec<String>,
    required_availability_cids: BTreeSet<String>,
    opener_address: String,
    opened_block: u64,
    end_block: u64,
    claim_deadline: u64,
    proposal_id: Option<String>,
    bond_atoms: u128,
    bond_settled: bool,
    agent_review_root: Option<String>,
    build_attestation_root: Option<String>,
    data_availability_root: Option<String>,
    agents: BTreeMap<String, BondedAgentAttestation>,
    builders: BTreeMap<String, BondedBuildAttestation>,
    availability: BTreeMap<String, BondedDataAvailabilityAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityMetricsCertificationDescriptor {
    snapshot_cid: String,
    snapshot_sha256: String,
    source_block_height: u64,
    source_block_hash: String,
    replay_start_height: u64,
    replay_commitment: String,
    indexer_implementation_cid: String,
}

#[derive(Debug, Clone, Default)]
struct IdentityMetricsCertificationRecord {
    descriptors: BTreeMap<String, IdentityMetricsCertificationDescriptor>,
    descriptor_operators: BTreeMap<String, BTreeSet<String>>,
    operator_attestations: BTreeMap<String, (String, String)>,
    finalized_descriptor: Option<String>,
    conflict: bool,
}

#[derive(Debug, Clone)]
pub struct GovernanceEngine {
    canonical_ecosystem_cid: String,
    governance_parameter_set_cid: String,
    parameters: GovernanceParameterSetV1,
    metrics_root: String,
    metrics_epoch: u16,
    stakes: BTreeMap<String, StakePosition>,
    registered_metrics: BTreeMap<String, GovernanceIdentityMetricsLeafV1>,
    metrics_certifications: BTreeMap<(String, u16), IdentityMetricsCertificationRecord>,
    review_rounds: BTreeMap<String, ReviewRoundRecord>,
    active_review_candidates: BTreeMap<String, String>,
    proposals: BTreeMap<String, ProposalRecord>,
    refunds: BTreeMap<String, u128>,
    burned_atoms: u128,
    events: Vec<GovernanceEvent>,
}

impl GovernanceEngine {
    pub fn initialize(
        initial_canonical_ecosystem_cid: &str,
        governance_parameter_set_cid: &str,
        parameters: GovernanceParameterSetV1,
        metrics_root: &str,
        metrics_epoch: u16,
    ) -> Result<Self, GovernanceError> {
        validate_canonical_cid(initial_canonical_ecosystem_cid)?;
        validate_canonical_cid(governance_parameter_set_cid)?;
        validate_sha256(metrics_root)?;
        validate_governance_parameters(&parameters)?;
        Ok(Self {
            canonical_ecosystem_cid: initial_canonical_ecosystem_cid.to_string(),
            governance_parameter_set_cid: governance_parameter_set_cid.to_string(),
            parameters,
            metrics_root: metrics_root.to_string(),
            metrics_epoch,
            stakes: BTreeMap::new(),
            registered_metrics: BTreeMap::new(),
            metrics_certifications: BTreeMap::new(),
            review_rounds: BTreeMap::new(),
            active_review_candidates: BTreeMap::new(),
            proposals: BTreeMap::new(),
            refunds: BTreeMap::new(),
            burned_atoms: 0,
            events: Vec::new(),
        })
    }

    pub fn canonical_ecosystem_cid(&self) -> &str {
        &self.canonical_ecosystem_cid
    }

    pub fn governance_parameter_set_cid(&self) -> &str {
        &self.governance_parameter_set_cid
    }

    pub fn burned_atoms(&self) -> u128 {
        self.burned_atoms
    }

    pub fn events(&self) -> &[GovernanceEvent] {
        &self.events
    }

    pub fn register_identity_metrics(
        &mut self,
        caller: &str,
        proof: GovernanceIdentityMetricsProofV1,
    ) -> Result<(), GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        if normalize_governance_address(&proof.leaf.address)? != caller
            || proof.leaf.source_epoch != self.metrics_epoch
            || proof.leaf.identity_state.status_bps().is_none()
            || verify_identity_metrics_proof(&proof, &self.metrics_root).is_err()
        {
            return Err(GovernanceError::InvalidIdentityProof);
        }
        self.registered_metrics.insert(caller, proof.leaf);
        Ok(())
    }

    pub fn submit_identity_metrics_attestation(
        &mut self,
        caller: &str,
        attestation_cid: &str,
        attestation_car: &[u8],
        clock: GovernanceClock,
    ) -> Result<IdentityMetricsCertificationView, GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        if !self.registered_metrics.get(&caller).is_some_and(|metrics| {
            metrics.source_epoch == self.metrics_epoch
                && metrics.identity_state.status_bps().is_some()
        }) {
            return Err(GovernanceError::InvalidIdentityProof);
        }
        let package = verify_identity_metrics_attestation_car(attestation_car)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        let value = &package.value;
        if package.root_cid.to_string() != attestation_cid
            || normalize_governance_address(&value.operator_idena_address)? != caller
            || value.observed_at_block_or_timestamp > clock.block
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        let descriptor = IdentityMetricsCertificationDescriptor {
            snapshot_cid: value.snapshot_cid.clone(),
            snapshot_sha256: value.snapshot_sha256.clone(),
            source_block_height: value.source_block_height,
            source_block_hash: value.source_block_hash.clone(),
            replay_start_height: value.replay_start_height,
            replay_commitment: value.replay_commitment.clone(),
            indexer_implementation_cid: value.indexer_implementation_cid.clone(),
        };
        let descriptor_hash = identity_metrics_certification_descriptor_hash(&descriptor);
        let key = (value.metrics_root.clone(), value.source_epoch);
        let minimum = self.parameters.minimum_identity_metrics_attestations;
        let record = self.metrics_certifications.entry(key.clone()).or_default();
        if record.operator_attestations.contains_key(&caller) {
            return Err(GovernanceError::Duplicate);
        }
        if record
            .descriptors
            .get(&descriptor_hash)
            .is_some_and(|existing| existing != &descriptor)
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        record
            .descriptors
            .entry(descriptor_hash.clone())
            .or_insert(descriptor);
        record.operator_attestations.insert(
            caller.clone(),
            (attestation_cid.to_string(), descriptor_hash.clone()),
        );
        let count = record
            .descriptor_operators
            .entry(descriptor_hash.clone())
            .or_default();
        count.insert(caller);
        if count.len() >= minimum as usize {
            match &record.finalized_descriptor {
                None => record.finalized_descriptor = Some(descriptor_hash),
                Some(finalized) if finalized != &descriptor_hash => record.conflict = true,
                Some(_) => {}
            }
        }
        Ok(identity_metrics_certification_view(
            &key.0, key.1, record, minimum,
        ))
    }

    pub fn identity_metrics_certification(
        &self,
        metrics_root: &str,
        source_epoch: u16,
    ) -> Result<IdentityMetricsCertificationView, GovernanceError> {
        validate_sha256(metrics_root)?;
        let empty = IdentityMetricsCertificationRecord::default();
        let record = self
            .metrics_certifications
            .get(&(metrics_root.to_string(), source_epoch))
            .unwrap_or(&empty);
        Ok(identity_metrics_certification_view(
            metrics_root,
            source_epoch,
            record,
            self.parameters.minimum_identity_metrics_attestations,
        ))
    }

    pub fn register_stake(
        &mut self,
        caller: &str,
        attached_atoms: u128,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        self.with_atomic_state(|engine| engine.register_stake_inner(caller, attached_atoms, clock))
    }

    fn register_stake_inner(
        &mut self,
        caller: &str,
        attached_atoms: u128,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        if attached_atoms == 0 {
            return Err(GovernanceError::InsufficientAmount);
        }
        let caller = normalize_governance_address(caller)?;
        let activation_epoch = clock
            .epoch
            .checked_add(self.parameters.activation_delay_epochs)
            .ok_or(GovernanceError::Overflow)?;
        let position = self.stakes.entry(caller).or_default();
        sync_position(position, clock.epoch)?;
        position.pending.push(StakeLot {
            atoms: attached_atoms,
            activation_epoch,
        });
        Ok(())
    }

    pub fn schedule_withdrawal(
        &mut self,
        caller: &str,
        atoms: u128,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        self.with_atomic_state(|engine| engine.schedule_withdrawal_inner(caller, atoms, clock))
    }

    fn schedule_withdrawal_inner(
        &mut self,
        caller: &str,
        atoms: u128,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        if atoms == 0 {
            return Err(GovernanceError::InsufficientAmount);
        }
        let caller = normalize_governance_address(caller)?;
        let position = self.stakes.entry(caller).or_default();
        sync_position(position, clock.epoch)?;
        let already_scheduled = checked_sum(position.scheduled.iter().map(|item| item.atoms))?;
        if position.active_atoms.saturating_sub(already_scheduled) < atoms {
            return Err(GovernanceError::InsufficientActiveStake);
        }
        let start_epoch = clock
            .epoch
            .checked_add(1)
            .ok_or(GovernanceError::Overflow)?;
        let release_epoch = start_epoch
            .checked_add(self.parameters.unbonding_delay_epochs)
            .ok_or(GovernanceError::Overflow)?;
        position.scheduled.push(ScheduledWithdrawal {
            atoms,
            start_epoch,
            release_epoch,
        });
        Ok(())
    }

    pub fn finalize_unbonding(
        &mut self,
        caller: &str,
        clock: GovernanceClock,
    ) -> Result<u128, GovernanceError> {
        self.with_atomic_state(|engine| engine.finalize_unbonding_inner(caller, clock))
    }

    fn finalize_unbonding_inner(
        &mut self,
        caller: &str,
        clock: GovernanceClock,
    ) -> Result<u128, GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        let position = self.stakes.entry(caller.clone()).or_default();
        sync_position(position, clock.epoch)?;
        let mut released = 0u128;
        position.unbonding.retain(|item| {
            if item.release_epoch <= clock.epoch {
                released = released
                    .checked_add(item.atoms)
                    .expect("unbonding sum was bounded by deposits");
                false
            } else {
                true
            }
        });
        if released == 0 {
            return Err(GovernanceError::NoRefund);
        }
        self.credit_refund(&caller, released)?;
        Ok(released)
    }

    pub fn stake_position(
        &mut self,
        caller: &str,
        epoch: u16,
    ) -> Result<StakePositionView, GovernanceError> {
        self.with_atomic_state(|engine| engine.stake_position_inner(caller, epoch))
    }

    fn stake_position_inner(
        &mut self,
        caller: &str,
        epoch: u16,
    ) -> Result<StakePositionView, GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        let position = self.stakes.entry(caller).or_default();
        sync_position(position, epoch)?;
        Ok(StakePositionView {
            pending_activation_atoms: checked_sum(position.pending.iter().map(|item| item.atoms))?,
            active_atoms: position.active_atoms,
            scheduled_withdrawal_atoms: checked_sum(
                position.scheduled.iter().map(|item| item.atoms),
            )?,
            unbonding_atoms: checked_sum(position.unbonding.iter().map(|item| item.atoms))?,
        })
    }

    pub fn open_review_round(
        &mut self,
        input: OpenReviewRoundInputV1<'_>,
        clock: GovernanceClock,
    ) -> Result<String, GovernanceError> {
        let OpenReviewRoundInputV1 {
            parent_car,
            candidate_car,
            patch_car,
            pinset_car,
            opener_address,
            attached_bond_atoms,
        } = input;
        let parent = verify_ecosystem_manifest_car(parent_car)
            .map_err(|_| GovernanceError::InvalidProposal)?;
        let candidate = verify_ecosystem_manifest_car(candidate_car)
            .map_err(|_| GovernanceError::InvalidProposal)?;
        let patch = verify_ecosystem_patch_manifest_car(patch_car)
            .map_err(|_| GovernanceError::InvalidProposal)?;
        let pinset =
            verify_pinset_manifest_car(pinset_car).map_err(|_| GovernanceError::InvalidProposal)?;
        let affected_repositories = verify_ecosystem_transition(&parent, &candidate, &patch)
            .map_err(|_| GovernanceError::InvalidProposal)?;
        verify_pinset_manifest_for_transition(&pinset, &candidate, &patch)
            .map_err(|_| GovernanceError::InvalidProposal)?;
        let parent_cid = parent.root_cid.to_string();
        let candidate_cid = candidate.root_cid.to_string();
        let patch_cid = patch.root_cid.to_string();
        if parent_cid != self.canonical_ecosystem_cid {
            return Err(GovernanceError::StaleParent);
        }
        if parent.manifest.governance_parameter_set_cid != self.governance_parameter_set_cid
            || candidate.manifest.governance_parameter_set_cid != self.governance_parameter_set_cid
            || parent.manifest.governance_contract_version != GOVERNANCE_CONTRACT_VERSION
            || candidate.manifest.governance_contract_version != GOVERNANCE_CONTRACT_VERSION
        {
            return Err(GovernanceError::InvalidProposal);
        }
        let parent_sources = parent
            .manifest
            .repositories
            .iter()
            .map(|repository| (repository.name.clone(), repository.source_tree_cid.clone()))
            .collect::<BTreeMap<_, _>>();
        let candidate_sources = candidate
            .manifest
            .repositories
            .iter()
            .map(|repository| (repository.name.clone(), repository.source_tree_cid.clone()))
            .collect::<BTreeMap<_, _>>();
        let base_source_cids = affected_repositories
            .iter()
            .map(|name| (name.clone(), parent_sources[name].clone()))
            .collect::<BTreeMap<_, _>>();
        let candidate_source_cids = affected_repositories
            .iter()
            .map(|name| (name.clone(), candidate_sources[name].clone()))
            .collect::<BTreeMap<_, _>>();
        let all_candidate_source_cids = candidate
            .manifest
            .repositories
            .iter()
            .map(|repository| RepositoryCidV1 {
                repository: repository.name.clone(),
                cid: repository.source_tree_cid.clone(),
            })
            .collect::<Vec<_>>();
        let candidate_artifact_keys = candidate
            .manifest
            .repositories
            .iter()
            .flat_map(|repository| repository.artifacts.iter())
            .map(candidate_artifact_key)
            .collect::<BTreeSet<_>>();
        let toolchain_cid = package_toolchain_manifest_for_ecosystem(&candidate.manifest)
            .map_err(|_| GovernanceError::InvalidProposal)?
            .root_cid
            .to_string();
        let pinset_cid = pinset.root_cid.to_string();
        let pinset_cids = pinset.manifest.cids;
        let required_availability_cids = pinset_cids.iter().cloned().collect();
        let opener_address = normalize_governance_address(opener_address)?;
        if !self
            .registered_metrics
            .get(&opener_address)
            .is_some_and(|metrics| {
                metrics.source_epoch == self.metrics_epoch
                    && metrics.identity_state.status_bps().is_some()
            })
        {
            return Err(GovernanceError::InvalidIdentityProof);
        }
        let minimum = parse_atoms(&self.parameters.proposal_bond_policy.minimum_bond_atoms)?;
        if attached_bond_atoms < minimum {
            return Err(GovernanceError::InsufficientAmount);
        }
        let candidate_key = review_candidate_key(&parent_cid, &candidate_cid, &patch_cid);
        if self.active_review_candidates.contains_key(&candidate_key) {
            return Err(GovernanceError::Duplicate);
        }
        let end_block = clock
            .block
            .checked_add(self.parameters.review_period_blocks)
            .ok_or(GovernanceError::Overflow)?;
        let claim_deadline = end_block
            .checked_add(self.parameters.review_period_blocks)
            .ok_or(GovernanceError::Overflow)?;
        let id = review_round_id(
            &parent_cid,
            &candidate_cid,
            &patch_cid,
            &opener_address,
            clock.block,
        );
        if self.review_rounds.contains_key(&id) {
            return Err(GovernanceError::Duplicate);
        }
        self.review_rounds.insert(
            id.clone(),
            ReviewRoundRecord {
                id: id.clone(),
                state: ReviewRoundState::Open,
                parent_cid,
                candidate_cid,
                patch_cid,
                affected_repositories,
                base_source_cids,
                candidate_source_cids,
                all_candidate_source_cids,
                candidate_artifact_keys,
                toolchain_cid,
                pinset_cid,
                pinset_cids,
                required_availability_cids,
                opener_address,
                opened_block: clock.block,
                end_block,
                claim_deadline,
                proposal_id: None,
                bond_atoms: attached_bond_atoms,
                bond_settled: false,
                agent_review_root: None,
                build_attestation_root: None,
                data_availability_root: None,
                agents: BTreeMap::new(),
                builders: BTreeMap::new(),
                availability: BTreeMap::new(),
            },
        );
        self.active_review_candidates
            .insert(candidate_key, id.clone());
        Ok(id)
    }

    pub fn freeze_review_round(
        &mut self,
        review_round_id: &str,
        clock: GovernanceClock,
    ) -> Result<ReviewRoundView, GovernanceError> {
        let (agent_root, build_root, availability_root) = {
            let round = self
                .review_rounds
                .get(review_round_id)
                .ok_or(GovernanceError::ReviewRoundNotFound)?;
            require_review_round_state(round, ReviewRoundState::Open)?;
            if clock.block < round.end_block || clock.block > round.claim_deadline {
                return Err(GovernanceError::InvalidDeadline);
            }
            if round.parent_cid != self.canonical_ecosystem_cid {
                return Err(GovernanceError::StaleParent);
            }
            let (agents, builders, availability) = review_round_commitments(round)?;
            (agents.root, builders.root, availability.root)
        };
        let round = self
            .review_rounds
            .get_mut(review_round_id)
            .ok_or(GovernanceError::ReviewRoundNotFound)?;
        round.agent_review_root = Some(agent_root);
        round.build_attestation_root = Some(build_root);
        round.data_availability_root = Some(availability_root);
        round.state = ReviewRoundState::Frozen;
        Ok(review_round_view(round))
    }

    pub fn expire_review_round(
        &mut self,
        review_round_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        self.with_atomic_state(|engine| engine.expire_review_round_inner(review_round_id, clock))
    }

    fn expire_review_round_inner(
        &mut self,
        review_round_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let canonical = self.canonical_ecosystem_cid.clone();
        let expired_slash_bps = self.parameters.proposal_bond_policy.expired_slash_bps;
        let stale_fee = parse_atoms(
            &self
                .parameters
                .proposal_bond_policy
                .stale_processing_fee_atoms,
        )?;
        let (candidate_key, settlements, bond_refund, burned) = {
            let round = self
                .review_rounds
                .get_mut(review_round_id)
                .ok_or(GovernanceError::ReviewRoundNotFound)?;
            if !matches!(
                round.state,
                ReviewRoundState::Open | ReviewRoundState::Frozen
            ) {
                return Err(GovernanceError::InvalidReviewRoundState(round.state));
            }
            let stale = round.parent_cid != canonical;
            if !stale && clock.block <= round.claim_deadline {
                return Err(GovernanceError::InvalidDeadline);
            }
            let burned = if stale {
                stale_fee.min(round.bond_atoms)
            } else {
                apply_bps(round.bond_atoms, expired_slash_bps)?
            };
            let mut settlements = Vec::new();
            for item in round.agents.values_mut() {
                if !item.settled {
                    item.settled = true;
                    settlements.push((item.input.owner_address.clone(), item.input.bond_atoms));
                }
            }
            for item in round.builders.values_mut() {
                if !item.settled {
                    item.settled = true;
                    settlements.push((item.input.builder_address.clone(), item.input.bond_atoms));
                }
            }
            for item in round.availability.values_mut() {
                if !item.settled {
                    item.settled = true;
                    settlements.push((item.input.operator_address.clone(), item.input.bond_atoms));
                }
            }
            round.state = ReviewRoundState::Expired;
            round.bond_settled = true;
            (
                review_candidate_key(&round.parent_cid, &round.candidate_cid, &round.patch_cid),
                settlements,
                (round.opener_address.clone(), round.bond_atoms - burned),
                burned,
            )
        };
        self.active_review_candidates.remove(&candidate_key);
        self.credit_refund(&bond_refund.0, bond_refund.1)?;
        for (address, amount) in settlements {
            self.credit_refund(&address, amount)?;
        }
        self.burned_atoms = self
            .burned_atoms
            .checked_add(burned)
            .ok_or(GovernanceError::Overflow)?;
        Ok(())
    }

    pub fn review_round(&self, review_round_id: &str) -> Result<ReviewRoundView, GovernanceError> {
        self.review_rounds
            .get(review_round_id)
            .map(review_round_view)
            .ok_or(GovernanceError::ReviewRoundNotFound)
    }

    pub fn create_proposal_draft(
        &mut self,
        content: ChangeProposalContentV1,
        attached_bond_atoms: u128,
        clock: GovernanceClock,
    ) -> Result<String, GovernanceError> {
        self.with_atomic_state(|engine| {
            engine.create_proposal_draft_inner(content, attached_bond_atoms, clock)
        })
    }

    fn create_proposal_draft_inner(
        &mut self,
        mut content: ChangeProposalContentV1,
        attached_bond_atoms: u128,
        clock: GovernanceClock,
    ) -> Result<String, GovernanceError> {
        self.sync_all_stakes(clock.epoch)?;
        content.proposer_address = normalize_governance_address(&content.proposer_address)?;
        validate_proposal_content(&content, &self.parameters, clock)?;
        if content.parent_canonical_ecosystem_cid != self.canonical_ecosystem_cid {
            return Err(GovernanceError::StaleParent);
        }
        if content.identity_metrics_epoch != self.metrics_epoch
            || match self.registered_metrics.get(&content.proposer_address) {
                Some(metrics) => metrics.source_epoch != content.identity_metrics_epoch,
                None => true,
            }
        {
            return Err(GovernanceError::InvalidIdentityProof);
        }
        let minimum_metrics_attestations = self.parameters.minimum_identity_metrics_attestations;
        if !self
            .metrics_certifications
            .get(&(self.metrics_root.clone(), self.metrics_epoch))
            .is_some_and(|record| {
                identity_metrics_certification_passes(record, minimum_metrics_attestations)
            })
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        if let (Some(root), Some(epoch)) = (
            &content.candidate_identity_metrics_root,
            content.candidate_identity_metrics_epoch,
        ) {
            if !self
                .metrics_certifications
                .get(&(root.clone(), epoch))
                .is_some_and(|record| {
                    identity_metrics_certification_passes(record, minimum_metrics_attestations)
                })
            {
                return Err(GovernanceError::InvalidAttestation);
            }
        }
        if attached_bond_atoms != 0 {
            return Err(GovernanceError::InsufficientAmount);
        }
        let (agents, builders, availability, required_availability_cids) = {
            let round = self
                .review_rounds
                .get(&content.review_round_id)
                .ok_or(GovernanceError::ReviewRoundNotFound)?;
            require_review_round_state(round, ReviewRoundState::Frozen)?;
            if clock.block > round.claim_deadline {
                return Err(GovernanceError::InvalidDeadline);
            }
            if round.opener_address != content.proposer_address
                || round.parent_cid != content.parent_canonical_ecosystem_cid
                || round.candidate_cid != content.candidate_ecosystem_cid
                || round.patch_cid != content.patch_cid
                || round.affected_repositories != content.affected_repositories
                || round.base_source_cids != content.base_source_cids
                || round.candidate_source_cids != content.candidate_source_cids
                || ![
                    content.rationale_cid.as_str(),
                    content.migration_notes_cid.as_str(),
                    content.test_plan_cid.as_str(),
                ]
                .iter()
                .all(|cid| round.pinset_cids.iter().any(|member| member == *cid))
                || content
                    .release_manifest_cid
                    .as_ref()
                    .is_some_and(|cid| !round.pinset_cids.contains(cid))
                || content
                    .critical_finding_waiver_cid
                    .as_ref()
                    .is_some_and(|cid| !round.pinset_cids.contains(cid))
                || round.bond_atoms != content.proposal_bond_atoms
                || round.agent_review_root.as_deref() != Some(content.agent_review_root.as_str())
                || round.build_attestation_root.as_deref()
                    != Some(content.build_attestation_root.as_str())
                || round.data_availability_root.as_deref()
                    != Some(content.data_availability_root.as_str())
            {
                return Err(GovernanceError::InvalidProposal);
            }
            (
                round.agents.clone(),
                round.builders.clone(),
                round.availability.clone(),
                round.required_availability_cids.clone(),
            )
        };
        let id = proposal_id(&content)?;
        if self.proposals.contains_key(&id) {
            return Err(GovernanceError::Duplicate);
        }
        let challenge_end = content.challenge_end;
        let execution_not_before = content
            .challenge_end
            .checked_add(self.parameters.timelock_blocks)
            .ok_or(GovernanceError::Overflow)?;
        let execution_expires = execution_not_before
            .checked_add(self.parameters.execution_window_blocks)
            .ok_or(GovernanceError::Overflow)?;
        let (voter_snapshot, total_registered_weight) =
            self.build_voter_snapshot(content.identity_metrics_epoch)?;
        let proposal = ProposalRecord {
            id: id.clone(),
            state: ProposalState::Draft,
            content,
            proposal_bond_settled: false,
            agents,
            builders,
            availability,
            required_availability_cids,
            voter_snapshot,
            votes: BTreeMap::new(),
            yes_weight: 0,
            no_weight: 0,
            abstain_weight: 0,
            total_registered_weight,
            gates: None,
            pending_challenge: None,
            challenge_end,
            execution_not_before,
            execution_expires,
        };
        verify_attestation_roots(&proposal)?;
        let evidence = acceptance_evidence(&proposal);
        let gates = evaluate_gates(
            proposal.content.risk_class,
            &self.parameters.normal,
            &self.parameters.critical,
            &evidence,
        );
        if !gates.poaw.passed || !gates.verification_work.passed || !gates.data_availability.passed
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        let round = self
            .review_rounds
            .get_mut(&proposal.content.review_round_id)
            .ok_or(GovernanceError::ReviewRoundNotFound)?;
        round.state = ReviewRoundState::Claimed;
        round.proposal_id = Some(id.clone());
        self.proposals.insert(id.clone(), proposal);
        Ok(id)
    }

    pub fn open_review(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let canonical = self.canonical_ecosystem_cid.clone();
        let stale = self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?
            .content
            .parent_canonical_ecosystem_cid
            != canonical;
        if stale {
            self.mark_stale(proposal_id)?;
            return Err(GovernanceError::StaleParent);
        }
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::Draft)?;
        if clock.block < proposal.content.creation_block
            || clock.block >= proposal.content.voting_start
        {
            return Err(GovernanceError::InvalidDeadline);
        }
        proposal.state = ProposalState::ReviewOpen;
        Ok(())
    }

    pub fn submit_agent_attestation(
        &mut self,
        review_round_id: &str,
        mut input: AgentAttestationInputV1,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let package = verify_agent_review_attestation_car(&input.attestation_car)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        let payload = &package.value;
        let payload_owner = normalize_governance_address(&payload.owner_idena_address)?;
        let payload_bond = parse_atoms(&payload.reviewer_bond_atoms)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        let payload_verdict = match payload.verdict {
            ReviewVerdictV1::Approve => AttestationVerdict::Approve,
            ReviewVerdictV1::Reject => AttestationVerdict::Reject,
            ReviewVerdictV1::Abstain => AttestationVerdict::Abstain,
        };
        input.owner_address = normalize_governance_address(&input.owner_address)?;
        let minimum = parse_atoms(&self.parameters.minimum_reviewer_bond_atoms)?;
        let metrics_valid = self
            .registered_metrics
            .get(&input.owner_address)
            .is_some_and(|value| value.source_epoch == self.metrics_epoch);
        let round = self.review_round_mut(review_round_id)?;
        require_review_round_submission(round, clock)?;
        let _commitment_fields = agent_attestation_commitment_fields(
            &input.attestation_cid,
            &input.independence_group,
            &input.owner_address,
            input.unresolved_critical_findings,
        )?;
        if input.bond_atoms < minimum
            || !metrics_valid
            || package.root_cid.to_string() != input.attestation_cid
            || payload_owner != input.owner_address
            || payload.parent_ecosystem_cid != input.parent_ecosystem_cid
            || payload.candidate_ecosystem_cid != input.candidate_ecosystem_cid
            || payload.patch_cid != input.patch_cid
            || payload.model_identifier != input.model_identifier
            || payload.model_revision != input.model_revision
            || payload.provider_or_runtime_identifier != input.runtime_identifier
            || payload.model_family != input.independence_group
            || payload_verdict != input.verdict
            || payload.unresolved_critical_findings != input.unresolved_critical_findings
            || payload.test_results_cid != input.test_result_cid
            || payload.tests_passed != input.tests_passed_claim
            || payload_bond != input.bond_atoms
            || payload.creation_block_or_timestamp > clock.block
            || payload.authentication != "on-chain-submitter"
            || input.parent_ecosystem_cid != round.parent_cid
            || input.candidate_ecosystem_cid != round.candidate_cid
            || input.patch_cid != round.patch_cid
            || payload.affected_repositories
                != round
                    .affected_repositories
                    .iter()
                    .map(|repository| RepositoryCidV1 {
                        repository: repository.clone(),
                        cid: round.candidate_source_cids[repository].clone(),
                    })
                    .collect::<Vec<_>>()
            || input.model_identifier.is_empty()
            || input.runtime_identifier.is_empty()
            || input.independence_group.is_empty()
            || validate_raw_content_cid(&input.test_result_cid).is_err()
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        validate_canonical_cid(&input.attestation_cid)?;
        if round.agents.contains_key(&input.attestation_cid) {
            return Err(GovernanceError::Duplicate);
        }
        if round
            .agents
            .values()
            .filter(|item| item.input.owner_address == input.owner_address)
            .count()
            >= MAX_ATTESTATIONS_PER_OWNER_PER_CLASS
        {
            return Err(GovernanceError::ReviewRoundFull);
        }
        if round.agents.len() >= MAX_REVIEW_ATTESTATIONS_PER_CLASS {
            return Err(GovernanceError::ReviewRoundFull);
        }
        let mut required_availability_cids = round.required_availability_cids.clone();
        for cid in [
            input.attestation_cid.as_str(),
            payload.agent_policy_cid.as_str(),
            payload.system_prompt_policy_cid.as_str(),
            payload.test_results_cid.as_str(),
            payload.static_analysis_results_cid.as_str(),
            payload.dependency_findings_cid.as_str(),
        ] {
            required_availability_cids.insert(cid.to_string());
        }
        for finding in &payload.security_findings {
            if let Some(cid) = &finding.evidence_cid {
                required_availability_cids.insert(cid.clone());
            }
        }
        if required_availability_cids.len() > MAX_REQUIRED_AVAILABILITY_CIDS {
            return Err(GovernanceError::ReviewRoundFull);
        }
        round.required_availability_cids = required_availability_cids;
        round.agents.insert(
            input.attestation_cid.clone(),
            BondedAgentAttestation {
                input,
                settled: false,
            },
        );
        Ok(())
    }

    pub fn submit_build_attestation(
        &mut self,
        review_round_id: &str,
        mut input: BuildAttestationInputV1,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let package = verify_build_attestation_car(&input.attestation_car)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        let payload = &package.value;
        let payload_owner = normalize_governance_address(&payload.builder_identity)?;
        let payload_bond = parse_atoms(&payload.builder_bond_atoms)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        input.builder_address = normalize_governance_address(&input.builder_address)?;
        let minimum = parse_atoms(&self.parameters.minimum_builder_bond_atoms)?;
        let metrics_valid = self
            .registered_metrics
            .get(&input.builder_address)
            .is_some_and(|value| value.source_epoch == self.metrics_epoch);
        let round = self.review_round_mut(review_round_id)?;
        require_review_round_submission(round, clock)?;
        let _commitment_fields = build_attestation_commitment_fields(
            &input.attestation_cid,
            &input.core_artifact_digest,
            &input.runtime_family,
            &input.architecture,
            &input.builder_address,
        )?;
        if input.bond_atoms < minimum
            || !metrics_valid
            || package.root_cid.to_string() != input.attestation_cid
            || payload_owner != input.builder_address
            || payload.candidate_ecosystem_cid != input.candidate_ecosystem_cid
            || payload.runtime_family != input.runtime_family
            || payload.architecture != input.architecture
            || payload.core_artifact_digest != input.core_artifact_digest
            || payload.test_results_cid != input.test_result_cid
            || payload.tests_passed != input.tests_passed_claim
            || payload_bond != input.bond_atoms
            || payload.creation_block_or_timestamp > clock.block
            || payload.authentication != "on-chain-submitter"
            || input.candidate_ecosystem_cid != round.candidate_cid
            || payload.source_cids != round.all_candidate_source_cids
            || payload.toolchain_cid != round.toolchain_cid
            || payload.artifacts.iter().any(|artifact| {
                !round
                    .candidate_artifact_keys
                    .contains(&build_artifact_key(artifact))
            })
            || input.runtime_family.is_empty()
            || input.architecture.is_empty()
            || validate_sha256(&input.core_artifact_digest).is_err()
            || validate_raw_content_cid(&input.test_result_cid).is_err()
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        validate_canonical_cid(&input.attestation_cid)?;
        if round.builders.contains_key(&input.attestation_cid) {
            return Err(GovernanceError::Duplicate);
        }
        if round
            .builders
            .values()
            .filter(|item| item.input.builder_address == input.builder_address)
            .count()
            >= MAX_ATTESTATIONS_PER_OWNER_PER_CLASS
        {
            return Err(GovernanceError::ReviewRoundFull);
        }
        if round.builders.len() >= MAX_REVIEW_ATTESTATIONS_PER_CLASS {
            return Err(GovernanceError::ReviewRoundFull);
        }
        let mut required_availability_cids = round.required_availability_cids.clone();
        for cid in [
            input.attestation_cid.as_str(),
            payload.toolchain_cid.as_str(),
            payload.test_results_cid.as_str(),
            payload.sbom_cid.as_str(),
        ] {
            required_availability_cids.insert(cid.to_string());
        }
        for artifact in &payload.artifacts {
            required_availability_cids.insert(artifact.cid.clone());
        }
        if required_availability_cids.len() > MAX_REQUIRED_AVAILABILITY_CIDS {
            return Err(GovernanceError::ReviewRoundFull);
        }
        round.required_availability_cids = required_availability_cids;
        round.builders.insert(
            input.attestation_cid.clone(),
            BondedBuildAttestation {
                input,
                settled: false,
            },
        );
        Ok(())
    }

    pub fn submit_data_availability_attestation(
        &mut self,
        review_round_id: &str,
        mut input: DataAvailabilityAttestationInputV1,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let package = verify_data_availability_attestation_car(&input.attestation_car)
            .map_err(|_| GovernanceError::InvalidAttestation)?;
        let payload = &package.value;
        let payload_owner = normalize_governance_address(&payload.operator_identity)?;
        let payload_bond =
            parse_atoms(&payload.bond_atoms).map_err(|_| GovernanceError::InvalidAttestation)?;
        input.operator_address = normalize_governance_address(&input.operator_address)?;
        let minimum = parse_atoms(&self.parameters.minimum_data_availability_bond_atoms)?;
        let metrics_valid = self
            .registered_metrics
            .get(&input.operator_address)
            .is_some_and(|value| value.source_epoch == self.metrics_epoch);
        let lifecycle_after_claim = self
            .parameters
            .review_period_blocks
            .checked_add(self.parameters.voting_period_blocks)
            .and_then(|value| value.checked_add(self.parameters.challenge_period_blocks))
            .ok_or(GovernanceError::Overflow)?;
        let challenge_period_blocks = self.parameters.challenge_period_blocks;
        let round = self.review_round_mut(review_round_id)?;
        require_review_round_submission(round, clock)?;
        let latest_challenge_end = round
            .claim_deadline
            .checked_add(lifecycle_after_claim)
            .and_then(|value| value.checked_add(challenge_period_blocks))
            .ok_or(GovernanceError::Overflow)?;
        let _commitment_fields = data_availability_commitment_fields(
            &input.attestation_cid,
            &input.candidate_ecosystem_cid,
            &input.pinset_cid,
            &input.provider_id,
            &input.operator_address,
        )?;
        if input.bond_atoms < minimum
            || !metrics_valid
            || package.root_cid.to_string() != input.attestation_cid
            || payload_owner != input.operator_address
            || payload.candidate_ecosystem_cid != input.candidate_ecosystem_cid
            || payload.provider_id != input.provider_id
            || payload.pinset_cid != input.pinset_cid
            || payload.verified_cids != input.verified_cids
            || payload.probe_result_cid != input.probe_result_cid
            || payload.available != input.available_claim
            || payload.expires_at_block != input.expires_at_block
            || payload_bond != input.bond_atoms
            || payload.observed_at_block_or_timestamp > clock.block
            || payload.authentication != "on-chain-submitter"
            || input.candidate_ecosystem_cid != round.candidate_cid
            || input.pinset_cid != round.pinset_cid
            || input.verified_cids.len() > MAX_REQUIRED_AVAILABILITY_CIDS
            || !round
                .pinset_cids
                .iter()
                .all(|cid| input.verified_cids.contains(cid))
            || !input.verified_cids.contains(&input.probe_result_cid)
            || input.provider_id.is_empty()
            || input.expires_at_block < latest_challenge_end
            || validate_canonical_cid(&input.pinset_cid).is_err()
            || validate_raw_content_cid(&input.probe_result_cid).is_err()
        {
            return Err(GovernanceError::InvalidAttestation);
        }
        let mut unique = BTreeSet::new();
        for cid in &input.verified_cids {
            validate_content_cid(cid)?;
            if !unique.insert(cid) {
                return Err(GovernanceError::InvalidAttestation);
            }
        }
        validate_canonical_cid(&input.attestation_cid)?;
        if round.availability.contains_key(&input.attestation_cid) {
            return Err(GovernanceError::Duplicate);
        }
        if round.availability.values().any(|item| {
            item.input.provider_id == input.provider_id
                || item.input.operator_address == input.operator_address
        }) {
            return Err(GovernanceError::Duplicate);
        }
        if round.availability.len() >= MAX_REVIEW_ATTESTATIONS_PER_CLASS {
            return Err(GovernanceError::ReviewRoundFull);
        }
        round.availability.insert(
            input.attestation_cid.clone(),
            BondedDataAvailabilityAttestation {
                input,
                settled: false,
            },
        );
        Ok(())
    }

    pub fn open_voting(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let canonical = self.canonical_ecosystem_cid.clone();
        let stale = self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?
            .content
            .parent_canonical_ecosystem_cid
            != canonical;
        if stale {
            self.mark_stale(proposal_id)?;
            return Err(GovernanceError::StaleParent);
        }
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::ReviewOpen)?;
        if clock.block < proposal.content.voting_start
            || clock.block >= proposal.content.voting_end
            || clock.epoch != proposal.content.staking_epoch
        {
            return Err(GovernanceError::InvalidDeadline);
        }
        verify_attestation_roots(proposal)?;
        proposal.state = ProposalState::VotingOpen;
        Ok(())
    }

    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        voter: &str,
        choice: VoteChoice,
        clock: GovernanceClock,
    ) -> Result<GovernanceVoteReceiptV1, GovernanceError> {
        self.with_atomic_state(|engine| engine.cast_vote_inner(proposal_id, voter, choice, clock))
    }

    fn cast_vote_inner(
        &mut self,
        proposal_id: &str,
        voter: &str,
        choice: VoteChoice,
        clock: GovernanceClock,
    ) -> Result<GovernanceVoteReceiptV1, GovernanceError> {
        let voter = normalize_governance_address(voter)?;
        let canonical = self.canonical_ecosystem_cid.clone();
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::VotingOpen)?;
        if proposal.content.parent_canonical_ecosystem_cid != canonical {
            return Err(GovernanceError::StaleParent);
        }
        if clock.block < proposal.content.voting_start || clock.block >= proposal.content.voting_end
        {
            return Err(GovernanceError::InvalidDeadline);
        }
        let snapshot = proposal
            .voter_snapshot
            .get(&voter)
            .ok_or(GovernanceError::IneligibleVoter)?
            .clone();
        if let Some(previous) = proposal.votes.get(&voter) {
            subtract_vote_weight(proposal, previous.choice, previous.effective_vote_weight)?;
        }
        add_vote_weight(proposal, choice, snapshot.weight)?;
        let receipt = GovernanceVoteReceiptV1 {
            schema_version: 1,
            proposal_id: proposal.id.clone(),
            voter_address: voter.clone(),
            choice,
            staking_epoch: proposal.content.staking_epoch,
            identity_metrics_epoch: proposal.content.identity_metrics_epoch,
            active_stake_atoms: snapshot.stake_atoms,
            stake_score: stake_score(snapshot.stake_atoms),
            identity_status_bps: snapshot.status_bps,
            flip_trust_bps: snapshot.trust_bps,
            effective_vote_weight: snapshot.weight,
            cast_at_block: clock.block,
        };
        proposal.votes.insert(voter, receipt.clone());
        Ok(receipt)
    }

    pub fn finalize_voting(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<GateResults, GovernanceError> {
        let parent = self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?
            .content
            .parent_canonical_ecosystem_cid
            .clone();
        if parent != self.canonical_ecosystem_cid {
            self.mark_stale(proposal_id)?;
            return Err(GovernanceError::StaleParent);
        }
        self.with_atomic_state(|engine| engine.finalize_voting_inner(proposal_id, clock))
    }

    fn finalize_voting_inner(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<GateResults, GovernanceError> {
        let parameters = self.parameters.clone();
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::VotingOpen)?;
        if clock.block < proposal.content.voting_end {
            return Err(GovernanceError::InvalidDeadline);
        }
        if clock.block > proposal.content.challenge_end {
            return Err(GovernanceError::InvalidDeadline);
        }
        proposal.challenge_end = clock
            .block
            .checked_add(parameters.challenge_period_blocks)
            .ok_or(GovernanceError::Overflow)?;
        proposal.execution_not_before = proposal
            .challenge_end
            .checked_add(parameters.timelock_blocks)
            .ok_or(GovernanceError::Overflow)?;
        proposal.execution_expires = proposal
            .execution_not_before
            .checked_add(parameters.execution_window_blocks)
            .ok_or(GovernanceError::Overflow)?;
        let evidence = acceptance_evidence(proposal);
        let gates = evaluate_gates(
            proposal.content.risk_class,
            &parameters.normal,
            &parameters.critical,
            &evidence,
        );
        proposal.gates = Some(gates.clone());
        if gates.accepted {
            proposal.state = ProposalState::AcceptedPendingChallenge;
        } else {
            proposal.state = ProposalState::Rejected;
        }
        if !gates.accepted {
            self.settle_normal_rejection(proposal_id)?;
        }
        Ok(gates)
    }

    pub fn submit_objective_challenge(
        &mut self,
        proposal_id: &str,
        mut input: ObjectiveChallengeInputV1,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        input.challenger_address = normalize_governance_address(&input.challenger_address)?;
        if input.evidence_bytes.is_empty()
            || input.evidence_bytes.len() > MAX_OBJECTIVE_EVIDENCE_BYTES
        {
            return Err(GovernanceError::InvalidChallenge);
        }
        validate_raw_content_cid(&input.evidence_cid)?;
        let evidence_cid = cid_for(RAW_CODEC, &input.evidence_bytes).to_string();
        if evidence_cid != input.evidence_cid {
            return Err(GovernanceError::InvalidChallenge);
        }
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::AcceptedPendingChallenge)?;
        if clock.block >= proposal.challenge_end {
            return Err(GovernanceError::InvalidDeadline);
        }
        let target_type = match input.target {
            ObjectiveChallengeTarget::AgentTestResult => {
                let attestation = proposal
                    .agents
                    .get(&input.attestation_cid)
                    .ok_or(GovernanceError::InvalidChallenge)?;
                if attestation.input.test_result_cid != input.evidence_cid {
                    return Err(GovernanceError::InvalidChallenge);
                }
                BondTarget::Agent
            }
            ObjectiveChallengeTarget::BuilderTestResult => {
                let attestation = proposal
                    .builders
                    .get(&input.attestation_cid)
                    .ok_or(GovernanceError::InvalidChallenge)?;
                if attestation.input.test_result_cid != input.evidence_cid {
                    return Err(GovernanceError::InvalidChallenge);
                }
                BondTarget::Builder
            }
            ObjectiveChallengeTarget::DataAvailabilityProbe => {
                let attestation = proposal
                    .availability
                    .get(&input.attestation_cid)
                    .ok_or(GovernanceError::InvalidChallenge)?;
                if attestation.input.probe_result_cid != input.evidence_cid {
                    return Err(GovernanceError::InvalidChallenge);
                }
                BondTarget::Availability
            }
        };
        verify_canonical_false_result(target_type, &input.evidence_bytes)?;
        proposal.pending_challenge = Some(PendingChallenge { input, target_type });
        proposal.state = ProposalState::Challenged;
        Ok(())
    }

    pub fn resolve_objective_challenge(
        &mut self,
        proposal_id: &str,
    ) -> Result<bool, GovernanceError> {
        self.with_atomic_state(|engine| engine.resolve_objective_challenge_inner(proposal_id))
    }

    fn resolve_objective_challenge_inner(
        &mut self,
        proposal_id: &str,
    ) -> Result<bool, GovernanceError> {
        let challenge = {
            let proposal = self.proposal_mut(proposal_id)?;
            require_state(proposal, ProposalState::Challenged)?;
            proposal
                .pending_challenge
                .clone()
                .ok_or(GovernanceError::InvalidChallenge)?
        };
        let successful = objective_challenge_succeeds(
            self.proposals
                .get(proposal_id)
                .ok_or(GovernanceError::ProposalNotFound)?,
            &challenge,
        )?;
        if successful {
            self.settle_successful_challenge(proposal_id, &challenge)?;
            let proposal = self.proposal_mut(proposal_id)?;
            proposal.pending_challenge = None;
            proposal.state = ProposalState::Rejected;
        } else {
            let proposal = self.proposal_mut(proposal_id)?;
            proposal.pending_challenge = None;
            proposal.state = ProposalState::AcceptedPendingChallenge;
        }
        Ok(successful)
    }

    pub fn close_challenge_period(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let proposal = self.proposal_mut(proposal_id)?;
        require_state(proposal, ProposalState::AcceptedPendingChallenge)?;
        if clock.block < proposal.challenge_end {
            return Err(GovernanceError::InvalidDeadline);
        }
        proposal.state = ProposalState::AcceptedPendingExecution;
        Ok(())
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<GovernanceEvent, GovernanceError> {
        let old_canonical = self.canonical_ecosystem_cid.clone();
        let (state, parent, execution_not_before, execution_expires) = {
            let proposal = self
                .proposals
                .get(proposal_id)
                .ok_or(GovernanceError::ProposalNotFound)?;
            (
                proposal.state,
                proposal.content.parent_canonical_ecosystem_cid.clone(),
                proposal.execution_not_before,
                proposal.execution_expires,
            )
        };
        if state != ProposalState::AcceptedPendingExecution {
            return Err(GovernanceError::InvalidState(state));
        }
        if parent != old_canonical {
            self.mark_stale(proposal_id)?;
            return Err(GovernanceError::StaleParent);
        }
        if clock.block < execution_not_before {
            return Err(GovernanceError::InvalidDeadline);
        }
        if clock.block > execution_expires {
            self.expire_proposal(proposal_id, clock)?;
            return Err(GovernanceError::InvalidDeadline);
        }
        self.with_atomic_state(|engine| engine.execute_ready_proposal(proposal_id, old_canonical))
    }

    fn execute_ready_proposal(
        &mut self,
        proposal_id: &str,
        old_canonical: String,
    ) -> Result<GovernanceEvent, GovernanceError> {
        let (new_canonical, candidate_metrics, event) = {
            let proposal = self.proposal_mut(proposal_id)?;
            let new_canonical = proposal.content.candidate_ecosystem_cid.clone();
            let candidate_metrics = proposal
                .content
                .candidate_identity_metrics_root
                .clone()
                .zip(proposal.content.candidate_identity_metrics_epoch);
            let event = GovernanceEvent::CanonicalEcosystemChanged {
                old_cid: old_canonical,
                new_cid: new_canonical.clone(),
                proposal_id: proposal.id.clone(),
                agent_review_root: proposal.content.agent_review_root.clone(),
                build_attestation_root: proposal.content.build_attestation_root.clone(),
                data_availability_root: proposal.content.data_availability_root.clone(),
            };
            proposal.state = ProposalState::Executed;
            (new_canonical, candidate_metrics, event)
        };
        self.canonical_ecosystem_cid = new_canonical;
        if let Some((root, epoch)) = candidate_metrics {
            self.metrics_root = root;
            self.metrics_epoch = epoch;
            self.registered_metrics.clear();
        }
        self.settle_full_refund(proposal_id)?;
        self.events.push(event.clone());
        Ok(event)
    }

    pub fn expire_proposal(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        self.with_atomic_state(|engine| engine.expire_proposal_inner(proposal_id, clock))
    }

    fn expire_proposal_inner(
        &mut self,
        proposal_id: &str,
        clock: GovernanceClock,
    ) -> Result<(), GovernanceError> {
        let (proposer, bond, already_settled) = {
            let proposal = self.proposal_mut(proposal_id)?;
            let expired = match proposal.state {
                ProposalState::Draft => clock.block > proposal.content.voting_start,
                ProposalState::ReviewOpen => clock.block >= proposal.content.voting_end,
                ProposalState::AcceptedPendingExecution => clock.block > proposal.execution_expires,
                _ => false,
            };
            if !expired {
                return Err(GovernanceError::InvalidDeadline);
            }
            proposal.state = ProposalState::Expired;
            let settled = proposal.proposal_bond_settled;
            proposal.proposal_bond_settled = true;
            (
                proposal.content.proposer_address.clone(),
                proposal.content.proposal_bond_atoms,
                settled,
            )
        };
        if !already_settled {
            let slash = apply_bps(bond, self.parameters.proposal_bond_policy.expired_slash_bps)?;
            self.burned_atoms = self
                .burned_atoms
                .checked_add(slash)
                .ok_or(GovernanceError::Overflow)?;
            self.credit_refund(&proposer, bond - slash)?;
        }
        self.refund_unsettled_attestations(proposal_id, None)?;
        self.release_review_candidate_for_proposal(proposal_id)
    }

    pub fn mark_stale(&mut self, proposal_id: &str) -> Result<(), GovernanceError> {
        self.with_atomic_state(|engine| engine.mark_stale_inner(proposal_id))
    }

    fn mark_stale_inner(&mut self, proposal_id: &str) -> Result<(), GovernanceError> {
        let canonical = self.canonical_ecosystem_cid.clone();
        let (proposer, bond, settled) = {
            let proposal = self.proposal_mut(proposal_id)?;
            if proposal.content.parent_canonical_ecosystem_cid == canonical {
                return Err(GovernanceError::InvalidProposal);
            }
            if is_terminal(proposal.state) {
                return Err(GovernanceError::InvalidState(proposal.state));
            }
            proposal.state = ProposalState::Stale;
            let settled = proposal.proposal_bond_settled;
            proposal.proposal_bond_settled = true;
            (
                proposal.content.proposer_address.clone(),
                proposal.content.proposal_bond_atoms,
                settled,
            )
        };
        if !settled {
            let fee = parse_atoms(
                &self
                    .parameters
                    .proposal_bond_policy
                    .stale_processing_fee_atoms,
            )?
            .min(bond);
            self.burned_atoms = self
                .burned_atoms
                .checked_add(fee)
                .ok_or(GovernanceError::Overflow)?;
            self.credit_refund(&proposer, bond - fee)?;
        }
        self.refund_unsettled_attestations(proposal_id, None)?;
        self.release_review_candidate_for_proposal(proposal_id)
    }

    pub fn withdraw_refund(&mut self, caller: &str) -> Result<u128, GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        let amount = self.refunds.remove(&caller).unwrap_or(0);
        if amount == 0 {
            return Err(GovernanceError::NoRefund);
        }
        Ok(amount)
    }

    pub fn refund_balance(&self, caller: &str) -> Result<u128, GovernanceError> {
        let caller = normalize_governance_address(caller)?;
        Ok(self.refunds.get(&caller).copied().unwrap_or(0))
    }

    pub fn proposal(&self, proposal_id: &str) -> Result<ProposalView, GovernanceError> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;
        Ok(ProposalView {
            proposal_id: proposal.id.clone(),
            state: proposal.state,
            content: proposal.content.clone(),
            gates: proposal.gates.clone(),
            vote_count: proposal.votes.len(),
            challenge_end: proposal.challenge_end,
            execution_not_before: proposal.execution_not_before,
            execution_expires: proposal.execution_expires,
        })
    }

    pub fn voter_receipt(
        &self,
        proposal_id: &str,
        voter: &str,
    ) -> Result<Option<GovernanceVoteReceiptV1>, GovernanceError> {
        let voter = normalize_governance_address(voter)?;
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;
        Ok(proposal.votes.get(&voter).cloned())
    }

    fn proposal_mut(&mut self, proposal_id: &str) -> Result<&mut ProposalRecord, GovernanceError> {
        self.proposals
            .get_mut(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)
    }

    fn with_atomic_state<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, GovernanceError>,
    ) -> Result<T, GovernanceError> {
        let checkpoint = self.clone();
        match operation(self) {
            Ok(value) => Ok(value),
            Err(error) => {
                *self = checkpoint;
                Err(error)
            }
        }
    }

    fn review_round_mut(
        &mut self,
        review_round_id: &str,
    ) -> Result<&mut ReviewRoundRecord, GovernanceError> {
        self.review_rounds
            .get_mut(review_round_id)
            .ok_or(GovernanceError::ReviewRoundNotFound)
    }

    fn release_review_candidate_for_proposal(
        &mut self,
        proposal_id: &str,
    ) -> Result<(), GovernanceError> {
        let content = &self
            .proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?
            .content;
        let key = review_candidate_key(
            &content.parent_canonical_ecosystem_cid,
            &content.candidate_ecosystem_cid,
            &content.patch_cid,
        );
        self.active_review_candidates.remove(&key);
        Ok(())
    }

    fn sync_all_stakes(&mut self, epoch: u16) -> Result<(), GovernanceError> {
        for position in self.stakes.values_mut() {
            sync_position(position, epoch)?;
        }
        Ok(())
    }

    fn build_voter_snapshot(
        &self,
        identity_metrics_epoch: u16,
    ) -> Result<(BTreeMap<String, VoterSnapshot>, u128), GovernanceError> {
        let minimum_stake = parse_atoms(&self.parameters.minimum_active_stake_atoms)?;
        let mut snapshot = BTreeMap::new();
        let mut total = 0u128;
        for (address, position) in &self.stakes {
            if position.active_atoms < minimum_stake {
                continue;
            }
            let Some(metrics) = self.registered_metrics.get(address) else {
                continue;
            };
            if metrics.source_epoch != identity_metrics_epoch {
                continue;
            }
            let Some(status_bps) = metrics.identity_state.status_bps() else {
                continue;
            };
            let weight =
                effective_vote_weight(position.active_atoms, status_bps, metrics.flip_trust_bps)
                    .map_err(|_| GovernanceError::Overflow)?;
            total = total.checked_add(weight).ok_or(GovernanceError::Overflow)?;
            snapshot.insert(
                address.clone(),
                VoterSnapshot {
                    stake_atoms: position.active_atoms,
                    status_bps,
                    state: metrics.identity_state,
                    trust_bps: metrics.flip_trust_bps,
                    weight,
                },
            );
        }
        Ok((snapshot, total))
    }

    fn credit_refund(&mut self, address: &str, amount: u128) -> Result<(), GovernanceError> {
        if amount == 0 {
            return Ok(());
        }
        let balance = self.refunds.entry(address.to_string()).or_default();
        *balance = balance
            .checked_add(amount)
            .ok_or(GovernanceError::Overflow)?;
        Ok(())
    }

    fn settle_normal_rejection(&mut self, proposal_id: &str) -> Result<(), GovernanceError> {
        let (proposer, bond, settled) = {
            let proposal = self.proposal_mut(proposal_id)?;
            let settled = proposal.proposal_bond_settled;
            proposal.proposal_bond_settled = true;
            (
                proposal.content.proposer_address.clone(),
                proposal.content.proposal_bond_atoms,
                settled,
            )
        };
        if !settled {
            let refund = apply_bps(
                bond,
                self.parameters.proposal_bond_policy.rejected_return_bps,
            )?;
            self.credit_refund(&proposer, refund)?;
            self.burned_atoms = self
                .burned_atoms
                .checked_add(bond - refund)
                .ok_or(GovernanceError::Overflow)?;
        }
        self.refund_unsettled_attestations(proposal_id, None)?;
        self.release_review_candidate_for_proposal(proposal_id)
    }

    fn settle_full_refund(&mut self, proposal_id: &str) -> Result<(), GovernanceError> {
        let (proposer, bond, settled) = {
            let proposal = self.proposal_mut(proposal_id)?;
            let settled = proposal.proposal_bond_settled;
            proposal.proposal_bond_settled = true;
            (
                proposal.content.proposer_address.clone(),
                proposal.content.proposal_bond_atoms,
                settled,
            )
        };
        if !settled {
            self.credit_refund(&proposer, bond)?;
        }
        self.refund_unsettled_attestations(proposal_id, None)?;
        self.release_review_candidate_for_proposal(proposal_id)
    }

    fn settle_successful_challenge(
        &mut self,
        proposal_id: &str,
        challenge: &PendingChallenge,
    ) -> Result<(), GovernanceError> {
        let (proposer, offender, proposal_bond, settled) = {
            let proposal = self.proposal_mut(proposal_id)?;
            let settled = proposal.proposal_bond_settled;
            proposal.proposal_bond_settled = true;
            let offender = match challenge.target_type {
                BondTarget::Agent => proposal
                    .agents
                    .get(&challenge.input.attestation_cid)
                    .map(|item| item.input.owner_address.clone()),
                BondTarget::Builder => proposal
                    .builders
                    .get(&challenge.input.attestation_cid)
                    .map(|item| item.input.builder_address.clone()),
                BondTarget::Availability => proposal
                    .availability
                    .get(&challenge.input.attestation_cid)
                    .map(|item| item.input.operator_address.clone()),
            }
            .ok_or(GovernanceError::InvalidChallenge)?;
            (
                proposal.content.proposer_address.clone(),
                offender,
                proposal.content.proposal_bond_atoms,
                settled,
            )
        };
        let proposer_is_offender = proposer == offender;
        if !settled {
            let slash = if proposer_is_offender {
                apply_bps(
                    proposal_bond,
                    self.parameters
                        .objective_slash_policy
                        .fraudulent_proposal_slash_bps,
                )?
            } else {
                let refund = apply_bps(
                    proposal_bond,
                    self.parameters.proposal_bond_policy.rejected_return_bps,
                )?;
                proposal_bond - refund
            };
            self.burned_atoms = self
                .burned_atoms
                .checked_add(slash)
                .ok_or(GovernanceError::Overflow)?;
            self.credit_refund(&proposer, proposal_bond - slash)?;
        }
        self.refund_unsettled_attestations(
            proposal_id,
            Some((
                challenge.target_type,
                challenge.input.attestation_cid.as_str(),
            )),
        )?;
        let slash_bps = self
            .parameters
            .objective_slash_policy
            .fraudulent_actor_stake_slash_bps;
        self.slash_governance_stake(&offender, slash_bps)?;
        self.release_review_candidate_for_proposal(proposal_id)
    }

    fn refund_unsettled_attestations(
        &mut self,
        proposal_id: &str,
        slash: Option<(BondTarget, &str)>,
    ) -> Result<(), GovernanceError> {
        let mut settlements = Vec::<(String, u128, u128)>::new();
        let reviewer_slash_bps = self
            .parameters
            .objective_slash_policy
            .fraudulent_reviewer_slash_bps;
        let builder_slash_bps = self
            .parameters
            .objective_slash_policy
            .fraudulent_builder_slash_bps;
        let availability_slash_bps = self
            .parameters
            .objective_slash_policy
            .unavailable_data_slash_bps;
        {
            let proposal = self.proposal_mut(proposal_id)?;
            for (cid, attestation) in &mut proposal.agents {
                if attestation.settled {
                    continue;
                }
                attestation.settled = true;
                let slash_bps = if slash == Some((BondTarget::Agent, cid.as_str())) {
                    reviewer_slash_bps
                } else {
                    0
                };
                let burned = apply_bps(attestation.input.bond_atoms, slash_bps)?;
                settlements.push((
                    attestation.input.owner_address.clone(),
                    attestation.input.bond_atoms - burned,
                    burned,
                ));
            }
            for (cid, attestation) in &mut proposal.builders {
                if attestation.settled {
                    continue;
                }
                attestation.settled = true;
                let slash_bps = if slash == Some((BondTarget::Builder, cid.as_str())) {
                    builder_slash_bps
                } else {
                    0
                };
                let burned = apply_bps(attestation.input.bond_atoms, slash_bps)?;
                settlements.push((
                    attestation.input.builder_address.clone(),
                    attestation.input.bond_atoms - burned,
                    burned,
                ));
            }
            for (cid, attestation) in &mut proposal.availability {
                if attestation.settled {
                    continue;
                }
                attestation.settled = true;
                let slash_bps = if slash == Some((BondTarget::Availability, cid.as_str())) {
                    availability_slash_bps
                } else {
                    0
                };
                let burned = apply_bps(attestation.input.bond_atoms, slash_bps)?;
                settlements.push((
                    attestation.input.operator_address.clone(),
                    attestation.input.bond_atoms - burned,
                    burned,
                ));
            }
        }
        for (address, refund, burned) in settlements {
            self.credit_refund(&address, refund)?;
            self.burned_atoms = self
                .burned_atoms
                .checked_add(burned)
                .ok_or(GovernanceError::Overflow)?;
        }
        Ok(())
    }

    fn slash_governance_stake(
        &mut self,
        address: &str,
        slash_bps: u16,
    ) -> Result<u128, GovernanceError> {
        let Some(position) = self.stakes.get_mut(address) else {
            return Ok(0);
        };
        let pending = checked_sum(position.pending.iter().map(|item| item.atoms))?;
        let unbonding = checked_sum(position.unbonding.iter().map(|item| item.atoms))?;
        let total = position
            .active_atoms
            .checked_add(pending)
            .and_then(|value| value.checked_add(unbonding))
            .ok_or(GovernanceError::Overflow)?;
        let slash = apply_bps(total, slash_bps)?;
        let mut remaining = slash;

        for item in &mut position.unbonding {
            let reduction = item.atoms.min(remaining);
            item.atoms -= reduction;
            remaining -= reduction;
        }
        position.unbonding.retain(|item| item.atoms > 0);
        for item in &mut position.pending {
            let reduction = item.atoms.min(remaining);
            item.atoms -= reduction;
            remaining -= reduction;
        }
        position.pending.retain(|item| item.atoms > 0);
        let active_reduction = position.active_atoms.min(remaining);
        position.active_atoms -= active_reduction;
        remaining -= active_reduction;
        if remaining != 0 {
            return Err(GovernanceError::Overflow);
        }

        let scheduled = checked_sum(position.scheduled.iter().map(|item| item.atoms))?;
        let mut scheduled_excess = scheduled.saturating_sub(position.active_atoms);
        for item in position.scheduled.iter_mut().rev() {
            let reduction = item.atoms.min(scheduled_excess);
            item.atoms -= reduction;
            scheduled_excess -= reduction;
        }
        position.scheduled.retain(|item| item.atoms > 0);
        if scheduled_excess != 0 {
            return Err(GovernanceError::Overflow);
        }
        self.burned_atoms = self
            .burned_atoms
            .checked_add(slash)
            .ok_or(GovernanceError::Overflow)?;
        Ok(slash)
    }
}

pub fn build_cid_commitment(cids: &[String]) -> Result<BuiltCidCommitment, GovernanceError> {
    if cids.is_empty() {
        return Err(GovernanceError::InvalidAttestation);
    }
    let mut canonical = cids.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical.len() != cids.len() {
        return Err(GovernanceError::Duplicate);
    }
    let mut hashes = Vec::with_capacity(canonical.len());
    for cid in &canonical {
        validate_canonical_cid(cid)?;
        hashes.push(hash_commitment_leaf(cid)?);
    }
    let root = commitment_merkle_root(&hashes);
    let mut proofs = BTreeMap::new();
    for (index, cid) in canonical.iter().enumerate() {
        proofs.insert(
            cid.clone(),
            CidCommitmentProofV1 {
                index: index as u64,
                leaf_count: canonical.len() as u64,
                siblings: commitment_siblings(&hashes, index)
                    .into_iter()
                    .map(hex::encode)
                    .collect(),
            },
        );
    }
    Ok(BuiltCidCommitment {
        root: hex::encode(root),
        proofs,
    })
}

pub fn build_attestation_commitment(
    domain: &str,
    entries: &[AttestationCommitmentEntryV1],
) -> Result<BuiltCidCommitment, GovernanceError> {
    validate_attestation_domain(domain)?;
    if entries.is_empty() {
        return Err(GovernanceError::InvalidAttestation);
    }
    if entries.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS {
        return Err(GovernanceError::ReviewRoundFull);
    }
    let mut canonical = entries.to_vec();
    canonical.sort_by(|left, right| left.attestation_cid.cmp(&right.attestation_cid));
    let mut seen = BTreeSet::new();
    let mut hashes = Vec::with_capacity(canonical.len());
    for entry in &canonical {
        validate_canonical_cid(&entry.attestation_cid)?;
        validate_canonical_attestation_fields(&entry.canonical_fields)?;
        if !seen.insert(entry.attestation_cid.clone()) {
            return Err(GovernanceError::Duplicate);
        }
        hashes.push(hash_attestation_commitment_leaf(
            domain,
            &entry.canonical_fields,
        ));
    }
    let tree_root = attestation_commitment_merkle_root(&hashes);
    let root = committed_attestation_root(domain, canonical.len() as u64, &tree_root);
    let mut proofs = BTreeMap::new();
    for (index, entry) in canonical.iter().enumerate() {
        proofs.insert(
            entry.attestation_cid.clone(),
            CidCommitmentProofV1 {
                index: index as u64,
                leaf_count: canonical.len() as u64,
                siblings: attestation_commitment_siblings(&hashes, index)
                    .into_iter()
                    .map(hex::encode)
                    .collect(),
            },
        );
    }
    Ok(BuiltCidCommitment {
        root: hex::encode(root),
        proofs,
    })
}

pub fn agent_attestation_commitment_fields(
    attestation_cid: &str,
    model_family: &str,
    owner_address: &str,
    unresolved_critical_findings: u32,
) -> Result<String, GovernanceError> {
    validate_canonical_cid(attestation_cid)?;
    validate_safe_label(model_family, 64)?;
    let owner = commitment_address(owner_address)?;
    Ok(format!(
        "{attestation_cid}|{model_family}|{owner}|{unresolved_critical_findings}"
    ))
}

pub fn build_attestation_commitment_fields(
    attestation_cid: &str,
    artifact_digest: &str,
    runtime_family: &str,
    architecture: &str,
    owner_address: &str,
) -> Result<String, GovernanceError> {
    validate_canonical_cid(attestation_cid)?;
    validate_sha256(artifact_digest)?;
    validate_safe_label(runtime_family, 31)?;
    validate_safe_label(architecture, 31)?;
    let platform = format!("{runtime_family}-{architecture}");
    validate_safe_label(&platform, 64)?;
    let owner = commitment_address(owner_address)?;
    Ok(format!(
        "{attestation_cid}|{artifact_digest}|{platform}|{owner}"
    ))
}

pub fn data_availability_commitment_fields(
    attestation_cid: &str,
    candidate_ecosystem_cid: &str,
    pinset_cid: &str,
    provider_id: &str,
    owner_address: &str,
) -> Result<String, GovernanceError> {
    validate_canonical_cid(attestation_cid)?;
    validate_canonical_cid(candidate_ecosystem_cid)?;
    validate_canonical_cid(pinset_cid)?;
    validate_safe_label(provider_id, 80)?;
    let owner = commitment_address(owner_address)?;
    Ok(format!(
        "{attestation_cid}|{candidate_ecosystem_cid}|{pinset_cid}|{provider_id}|{owner}"
    ))
}

pub fn proposal_id(content: &ChangeProposalContentV1) -> Result<String, GovernanceError> {
    proposal_id_from_review_round(&content.review_round_id)
}

pub fn proposal_id_from_review_round(review_round_id: &str) -> Result<String, GovernanceError> {
    validate_sha256(review_round_id)?;
    let mut hash = Sha256::new();
    hash.update(b"IDENA_GOV_PROPOSAL_ID_V2\0");
    hash.update(review_round_id.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

pub fn proposal_id_from_cid(proposal_cid: &str) -> Result<String, GovernanceError> {
    validate_canonical_cid(proposal_cid)?;
    let mut hash = Sha256::new();
    hash.update(b"IDENA_GOV_PROPOSAL_ID_V1\0");
    hash.update(proposal_cid.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

fn review_round_id(
    parent_cid: &str,
    candidate_cid: &str,
    patch_cid: &str,
    opener_address: &str,
    opened_block: u64,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"IDENA_GOV_REVIEW_ROUND_V1\0");
    hash.update(parent_cid.as_bytes());
    hash.update(b"|");
    hash.update(candidate_cid.as_bytes());
    hash.update(b"|");
    hash.update(patch_cid.as_bytes());
    hash.update(b"|");
    hash.update(opener_address.trim_start_matches("0x").as_bytes());
    hash.update(b"|");
    hash.update(opened_block.to_string().as_bytes());
    hex::encode(hash.finalize())
}

fn review_candidate_key(parent_cid: &str, candidate_cid: &str, patch_cid: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"IDENA_GOV_REVIEW_CANDIDATE_V1\0");
    hash.update(parent_cid.as_bytes());
    hash.update(b"|");
    hash.update(candidate_cid.as_bytes());
    hash.update(b"|");
    hash.update(patch_cid.as_bytes());
    hex::encode(hash.finalize())
}

fn candidate_artifact_key(artifact: &ArtifactManifestV1) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        artifact.name, artifact.cid, artifact.sha256, artifact.size
    )
}

fn build_artifact_key(artifact: &BuildArtifactV1) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        artifact.name, artifact.cid, artifact.sha256, artifact.size
    )
}

pub fn package_change_proposal(
    mut content: ChangeProposalContentV1,
    parameters: &GovernanceParameterSetV1,
) -> Result<ChangeProposalPackage, GovernanceError> {
    content.proposer_address = normalize_governance_address(&content.proposer_address)?;
    validate_change_proposal_content(&content, parameters)?;
    let package =
        package_dag_cbor(content.clone()).map_err(|_| GovernanceError::InvalidProposal)?;
    if package.dag_cbor_bytes.len() > MAX_CONTRACT_DAG_CBOR_BYTES {
        return Err(GovernanceError::InvalidProposal);
    }
    let proposal_id = proposal_id(&content)?;
    Ok(ChangeProposalPackage {
        proposal_id,
        content_cid: package.root_cid,
        content_sha256: package.root_sha256,
        content,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

pub fn verify_change_proposal_car(
    bytes: &[u8],
    parameters: &GovernanceParameterSetV1,
) -> Result<ChangeProposalPackage, GovernanceError> {
    let package: DagCborPackage<ChangeProposalContentV1> =
        verify_dag_cbor_car(bytes).map_err(|_| GovernanceError::InvalidProposal)?;
    let expected = package_change_proposal(package.value, parameters)?;
    if expected.content_cid != package.root_cid || expected.car_bytes != bytes {
        return Err(GovernanceError::InvalidProposal);
    }
    Ok(expected)
}

pub fn validate_change_proposal_content(
    content: &ChangeProposalContentV1,
    parameters: &GovernanceParameterSetV1,
) -> Result<(), GovernanceError> {
    validate_governance_parameters(parameters)?;
    validate_proposal_content(
        content,
        parameters,
        GovernanceClock {
            block: content.creation_block,
            epoch: content.creation_epoch,
        },
    )?;
    normalize_governance_address(&content.proposer_address)?;
    let minimum = parse_atoms(&parameters.proposal_bond_policy.minimum_bond_atoms)?;
    if content.proposal_bond_atoms < minimum {
        return Err(GovernanceError::InsufficientAmount);
    }
    Ok(())
}

fn validate_proposal_content(
    content: &ChangeProposalContentV1,
    parameters: &GovernanceParameterSetV1,
    clock: GovernanceClock,
) -> Result<(), GovernanceError> {
    if content.schema_version != 1
        || content.creation_block != clock.block
        || content.creation_epoch != clock.epoch
        || content.staking_epoch != content.creation_epoch
        // Until an objective source/path classifier is committed on-chain, a
        // proposer must not be able to select the lower normal-proposal gates.
        || content.risk_class == RiskClass::Normal
    {
        return Err(GovernanceError::InvalidProposal);
    }
    let voting_start = content
        .creation_block
        .checked_add(parameters.review_period_blocks)
        .ok_or(GovernanceError::Overflow)?;
    let voting_end = voting_start
        .checked_add(parameters.voting_period_blocks)
        .ok_or(GovernanceError::Overflow)?;
    let challenge_end = voting_end
        .checked_add(parameters.challenge_period_blocks)
        .ok_or(GovernanceError::Overflow)?;
    if content.voting_start != voting_start
        || content.voting_end != voting_end
        || content.challenge_end != challenge_end
    {
        return Err(GovernanceError::InvalidProposal);
    }
    for cid in [
        &content.parent_canonical_ecosystem_cid,
        &content.candidate_ecosystem_cid,
        &content.patch_cid,
    ] {
        validate_canonical_cid(cid)?;
    }
    for cid in [
        &content.rationale_cid,
        &content.migration_notes_cid,
        &content.test_plan_cid,
    ] {
        validate_content_cid(cid)?;
    }
    if let Some(cid) = &content.release_manifest_cid {
        validate_canonical_cid(cid)?;
    }
    validate_sha256(&content.review_round_id)?;
    if let Some(cid) = &content.critical_finding_waiver_cid {
        validate_canonical_cid(cid)?;
        if !content.risk_class.is_critical() {
            return Err(GovernanceError::InvalidProposal);
        }
    }
    for digest in [
        &content.agent_review_root,
        &content.build_attestation_root,
        &content.data_availability_root,
    ] {
        validate_sha256(digest)?;
    }
    match (
        &content.candidate_identity_metrics_root,
        content.candidate_identity_metrics_epoch,
    ) {
        (None, None) => {}
        (Some(root), Some(epoch)) => {
            if content.risk_class != RiskClass::Migration || epoch <= content.identity_metrics_epoch
            {
                return Err(GovernanceError::InvalidProposal);
            }
            validate_sha256(root)?;
        }
        _ => return Err(GovernanceError::InvalidProposal),
    }
    if content.affected_repositories.is_empty()
        || content.affected_repositories.len() > 64
        || !strict_sorted_unique(&content.affected_repositories)
        || content
            .affected_repositories
            .iter()
            .any(|name| !valid_repository_name(name))
    {
        return Err(GovernanceError::InvalidProposal);
    }
    let affected = content
        .affected_repositories
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if content
        .base_source_cids
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != affected
        || content
            .candidate_source_cids
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != affected
    {
        return Err(GovernanceError::InvalidProposal);
    }
    for cid in content
        .base_source_cids
        .values()
        .chain(content.candidate_source_cids.values())
    {
        validate_canonical_cid(cid)?;
    }
    Ok(())
}

pub fn validate_governance_parameters(
    parameters: &GovernanceParameterSetV1,
) -> Result<(), GovernanceError> {
    if parameters.schema_version != 1
        || parameters.idna_atoms_per_unit != "1000000000000000000"
        || parameters.stake_quantum_atoms != "1000000000000"
        || parameters.status_bps.human != 10_000
        || parameters.status_bps.verified != 8_500
        || parameters.status_bps.newbie != 7_000
        || !(parameters.status_bps.human > parameters.status_bps.verified
            && parameters.status_bps.verified > parameters.status_bps.newbie)
        || parameters.flip_prior_reported != 1
        || parameters.flip_prior_total != 20
        || parameters.flip_trust_floor_bps != 4_000
        || parameters.flip_trust_ceiling_bps != 10_000
        || parameters.flip_penalty_scale != 15_000
        || parameters.activation_delay_epochs == 0
        || parameters.unbonding_delay_epochs <= parameters.activation_delay_epochs
        || parameters.review_period_blocks == 0
        || parameters.voting_period_blocks == 0
        || parameters.challenge_period_blocks == 0
        || parameters.timelock_blocks == 0
        || parameters.execution_window_blocks == 0
        || parameters.minimum_identity_metrics_attestations == 0
        || parameters.proposal_bond_policy.rejected_return_bps > 10_000
        || parameters.proposal_bond_policy.expired_slash_bps > 10_000
        || parameters
            .objective_slash_policy
            .fraudulent_proposal_slash_bps
            > 10_000
        || parameters
            .objective_slash_policy
            .fraudulent_reviewer_slash_bps
            > 10_000
        || parameters
            .objective_slash_policy
            .fraudulent_builder_slash_bps
            > 10_000
        || parameters.objective_slash_policy.unavailable_data_slash_bps > 10_000
        || parameters
            .objective_slash_policy
            .fraudulent_actor_stake_slash_bps
            > 10_000
    {
        return Err(GovernanceError::InvalidParameters(
            "fixed formula or lifecycle invariant violated".to_string(),
        ));
    }
    for value in [
        &parameters.minimum_active_stake_atoms,
        &parameters.minimum_reviewer_bond_atoms,
        &parameters.minimum_builder_bond_atoms,
        &parameters.minimum_data_availability_bond_atoms,
        &parameters.proposal_bond_policy.minimum_bond_atoms,
        &parameters.proposal_bond_policy.stale_processing_fee_atoms,
    ] {
        let _ = parse_atoms(value)?;
    }
    Ok(())
}

fn acceptance_evidence(proposal: &ProposalRecord) -> AcceptanceEvidence {
    let yes_voters = proposal
        .votes
        .values()
        .filter(|receipt| receipt.choice == VoteChoice::Yes)
        .collect::<Vec<_>>();
    let verified_or_human = yes_voters
        .iter()
        .filter(|receipt| {
            proposal
                .voter_snapshot
                .get(&receipt.voter_address)
                .is_some_and(|snapshot| snapshot.state.is_verified_or_human())
        })
        .count();

    let approved_agents = proposal
        .agents
        .values()
        .filter(|item| {
            item.input.verdict == AttestationVerdict::Approve && item.input.tests_passed_claim
        })
        .collect::<Vec<_>>();
    let unique_agent_instances = approved_agents
        .iter()
        .map(|item| {
            format!(
                "{}\0{}",
                item.input.owner_address, item.input.independence_group
            )
        })
        .collect::<BTreeSet<_>>();
    let agent_families = approved_agents
        .iter()
        .map(|item| item.input.independence_group.clone())
        .collect::<BTreeSet<_>>();
    let agent_owners = approved_agents
        .iter()
        .map(|item| item.input.owner_address.clone())
        .collect::<BTreeSet<_>>();
    let unresolved = proposal
        .agents
        .values()
        .map(|item| item.input.unresolved_critical_findings)
        .sum::<u32>();
    let unresolved = if unresolved > 0
        && proposal.content.risk_class.is_critical()
        && proposal.content.critical_finding_waiver_cid.is_some()
    {
        0
    } else {
        unresolved
    };

    let mut build_groups = BTreeMap::<String, (BTreeSet<String>, BTreeSet<String>)>::new();
    for item in proposal
        .builders
        .values()
        .filter(|item| item.input.tests_passed_claim)
    {
        let group = build_groups
            .entry(item.input.core_artifact_digest.clone())
            .or_default();
        group.0.insert(item.input.builder_address.clone());
        group.1.insert(format!(
            "{}-{}",
            item.input.runtime_family, item.input.architecture
        ));
    }
    let selected_build_group = build_groups.into_iter().max_by(|left, right| {
        left.1
             .0
            .len()
            .cmp(&right.1 .0.len())
            .then_with(|| left.1 .1.len().cmp(&right.1 .1.len()))
            // A lexical minimum is the deterministic winner of an exact tie.
            .then_with(|| right.0.cmp(&left.0))
    });
    let (builder_owners, builder_platforms) = selected_build_group
        .as_ref()
        .map(|(_, (owners, platforms))| (owners.len(), platforms.len()))
        .unwrap_or((0, 0));

    let valid_availability = proposal
        .availability
        .values()
        .filter(|item| {
            item.input.available_claim
                && item.input.expires_at_block >= proposal.challenge_end
                && proposal
                    .required_availability_cids
                    .iter()
                    .all(|cid| item.input.verified_cids.contains(cid))
        })
        .collect::<Vec<_>>();
    let provider_owners = valid_availability
        .iter()
        .map(|item| item.input.operator_address.clone())
        .collect::<BTreeSet<_>>();

    AcceptanceEvidence {
        yes_weight: proposal.yes_weight,
        no_weight: proposal.no_weight,
        abstain_weight: proposal.abstain_weight,
        total_registered_weight: proposal.total_registered_weight,
        distinct_yes_identities: yes_voters.len() as u32,
        verified_or_human_yes_identities: verified_or_human as u32,
        valid_agent_attestations: unique_agent_instances.len() as u32,
        distinct_agent_families: agent_families.len() as u32,
        distinct_agent_owner_identities: agent_owners.len() as u32,
        unresolved_critical_findings: unresolved,
        valid_builders: builder_owners as u32,
        distinct_builder_platforms: builder_platforms as u32,
        matching_core_artifact_digests: selected_build_group.is_some(),
        independent_data_availability_providers: provider_owners.len() as u32,
    }
}

fn objective_challenge_succeeds(
    proposal: &ProposalRecord,
    challenge: &PendingChallenge,
) -> Result<bool, GovernanceError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct TestResult {
        passed: bool,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct AvailabilityResult {
        available: bool,
    }
    match challenge.target_type {
        BondTarget::Agent => {
            let attestation = proposal
                .agents
                .get(&challenge.input.attestation_cid)
                .ok_or(GovernanceError::InvalidChallenge)?;
            let result: TestResult = serde_json::from_slice(&challenge.input.evidence_bytes)
                .map_err(|_| GovernanceError::InvalidChallenge)?;
            Ok(attestation.input.tests_passed_claim && !result.passed)
        }
        BondTarget::Builder => {
            let attestation = proposal
                .builders
                .get(&challenge.input.attestation_cid)
                .ok_or(GovernanceError::InvalidChallenge)?;
            let result: TestResult = serde_json::from_slice(&challenge.input.evidence_bytes)
                .map_err(|_| GovernanceError::InvalidChallenge)?;
            Ok(attestation.input.tests_passed_claim && !result.passed)
        }
        BondTarget::Availability => {
            let attestation = proposal
                .availability
                .get(&challenge.input.attestation_cid)
                .ok_or(GovernanceError::InvalidChallenge)?;
            let result: AvailabilityResult =
                serde_json::from_slice(&challenge.input.evidence_bytes)
                    .map_err(|_| GovernanceError::InvalidChallenge)?;
            Ok(attestation.input.available_claim && !result.available)
        }
    }
}

fn verify_canonical_false_result(
    target: BondTarget,
    evidence_bytes: &[u8],
) -> Result<(), GovernanceError> {
    let expected = match target {
        BondTarget::Agent | BondTarget::Builder => br#"{"passed":false}"#.as_slice(),
        BondTarget::Availability => br#"{"available":false}"#.as_slice(),
    };
    if evidence_bytes != expected {
        return Err(GovernanceError::InvalidChallenge);
    }
    Ok(())
}

fn verify_attestation_roots(proposal: &ProposalRecord) -> Result<(), GovernanceError> {
    if proposal.agents.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
        || proposal.builders.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
        || proposal.availability.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
    {
        return Err(GovernanceError::ReviewRoundFull);
    }
    let agent_entries = proposal
        .agents
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: agent_attestation_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.independence_group,
                    &item.input.owner_address,
                    item.input.unresolved_critical_findings,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    let build_entries = proposal
        .builders
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: build_attestation_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.core_artifact_digest,
                    &item.input.runtime_family,
                    &item.input.architecture,
                    &item.input.builder_address,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    let availability_entries = proposal
        .availability
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: data_availability_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.candidate_ecosystem_cid,
                    &item.input.pinset_cid,
                    &item.input.provider_id,
                    &item.input.operator_address,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    let agent = build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &agent_entries)?;
    let build = build_attestation_commitment(BUILD_ATTESTATION_COMMITMENT_DOMAIN, &build_entries)?;
    let availability =
        build_attestation_commitment(DATA_AVAILABILITY_COMMITMENT_DOMAIN, &availability_entries)?;
    if agent.root != proposal.content.agent_review_root
        || build.root != proposal.content.build_attestation_root
        || availability.root != proposal.content.data_availability_root
    {
        return Err(GovernanceError::InvalidAttestation);
    }
    Ok(())
}

fn review_round_commitments(
    round: &ReviewRoundRecord,
) -> Result<(BuiltCidCommitment, BuiltCidCommitment, BuiltCidCommitment), GovernanceError> {
    if round.agents.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
        || round.builders.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
        || round.availability.len() > MAX_REVIEW_ATTESTATIONS_PER_CLASS
    {
        return Err(GovernanceError::ReviewRoundFull);
    }
    let agent_entries = round
        .agents
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: agent_attestation_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.independence_group,
                    &item.input.owner_address,
                    item.input.unresolved_critical_findings,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    let build_entries = round
        .builders
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: build_attestation_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.core_artifact_digest,
                    &item.input.runtime_family,
                    &item.input.architecture,
                    &item.input.builder_address,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    let availability_entries = round
        .availability
        .values()
        .map(|item| {
            Ok(AttestationCommitmentEntryV1 {
                attestation_cid: item.input.attestation_cid.clone(),
                canonical_fields: data_availability_commitment_fields(
                    &item.input.attestation_cid,
                    &item.input.candidate_ecosystem_cid,
                    &item.input.pinset_cid,
                    &item.input.provider_id,
                    &item.input.operator_address,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GovernanceError>>()?;
    Ok((
        build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &agent_entries)?,
        build_attestation_commitment(BUILD_ATTESTATION_COMMITMENT_DOMAIN, &build_entries)?,
        build_attestation_commitment(DATA_AVAILABILITY_COMMITMENT_DOMAIN, &availability_entries)?,
    ))
}

fn identity_metrics_certification_descriptor_hash(
    descriptor: &IdentityMetricsCertificationDescriptor,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        descriptor.snapshot_cid,
        descriptor.snapshot_sha256,
        descriptor.source_block_height,
        descriptor.source_block_hash,
        descriptor.replay_start_height,
        descriptor.replay_commitment,
        descriptor.indexer_implementation_cid,
    );
    let mut hasher = Sha256::new();
    hasher.update(b"IDENA_GOV_METRICS_CERTIFICATION_V1\0");
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn identity_metrics_certification_passes(
    record: &IdentityMetricsCertificationRecord,
    minimum: u32,
) -> bool {
    if record.conflict {
        return false;
    }
    record
        .finalized_descriptor
        .as_ref()
        .is_some_and(|descriptor| {
            record
                .descriptor_operators
                .get(descriptor)
                .is_some_and(|operators| operators.len() >= minimum as usize)
        })
}

fn identity_metrics_certification_view(
    metrics_root: &str,
    source_epoch: u16,
    record: &IdentityMetricsCertificationRecord,
    minimum: u32,
) -> IdentityMetricsCertificationView {
    let attestation_count = if record.conflict {
        0
    } else {
        record
            .finalized_descriptor
            .as_ref()
            .and_then(|descriptor| record.descriptor_operators.get(descriptor))
            .map_or(0, BTreeSet::len)
    };
    IdentityMetricsCertificationView {
        metrics_root: metrics_root.to_string(),
        source_epoch,
        attestation_count,
        minimum_required: minimum,
        certified: identity_metrics_certification_passes(record, minimum),
        conflict: record.conflict,
        descriptor_hash: record.finalized_descriptor.clone(),
    }
}

fn review_round_view(round: &ReviewRoundRecord) -> ReviewRoundView {
    ReviewRoundView {
        review_round_id: round.id.clone(),
        state: round.state,
        parent_cid: round.parent_cid.clone(),
        candidate_cid: round.candidate_cid.clone(),
        patch_cid: round.patch_cid.clone(),
        opener_address: round.opener_address.clone(),
        opened_block: round.opened_block,
        end_block: round.end_block,
        claim_deadline: round.claim_deadline,
        proposal_id: round.proposal_id.clone(),
        agent_review_root: round.agent_review_root.clone(),
        build_attestation_root: round.build_attestation_root.clone(),
        data_availability_root: round.data_availability_root.clone(),
        agent_attestations: round.agents.len(),
        build_attestations: round.builders.len(),
        data_availability_attestations: round.availability.len(),
    }
}

fn require_review_round_submission(
    round: &ReviewRoundRecord,
    clock: GovernanceClock,
) -> Result<(), GovernanceError> {
    require_review_round_state(round, ReviewRoundState::Open)?;
    if clock.block >= round.end_block {
        return Err(GovernanceError::InvalidDeadline);
    }
    Ok(())
}

fn require_review_round_state(
    round: &ReviewRoundRecord,
    expected: ReviewRoundState,
) -> Result<(), GovernanceError> {
    if round.state != expected {
        return Err(GovernanceError::InvalidReviewRoundState(round.state));
    }
    Ok(())
}

fn require_state(
    proposal: &ProposalRecord,
    expected: ProposalState,
) -> Result<(), GovernanceError> {
    if proposal.state != expected {
        return Err(GovernanceError::InvalidState(proposal.state));
    }
    Ok(())
}

fn sync_position(position: &mut StakePosition, epoch: u16) -> Result<(), GovernanceError> {
    let mut still_pending = Vec::new();
    for lot in position.pending.drain(..) {
        if lot.activation_epoch <= epoch {
            position.active_atoms = position
                .active_atoms
                .checked_add(lot.atoms)
                .ok_or(GovernanceError::Overflow)?;
        } else {
            still_pending.push(lot);
        }
    }
    position.pending = still_pending;
    let mut still_scheduled = Vec::new();
    for withdrawal in position.scheduled.drain(..) {
        if withdrawal.start_epoch <= epoch {
            position.active_atoms = position
                .active_atoms
                .checked_sub(withdrawal.atoms)
                .ok_or(GovernanceError::Overflow)?;
            position.unbonding.push(withdrawal);
        } else {
            still_scheduled.push(withdrawal);
        }
    }
    position.scheduled = still_scheduled;
    Ok(())
}

fn add_vote_weight(
    proposal: &mut ProposalRecord,
    choice: VoteChoice,
    weight: u128,
) -> Result<(), GovernanceError> {
    let target = match choice {
        VoteChoice::Yes => &mut proposal.yes_weight,
        VoteChoice::No => &mut proposal.no_weight,
        VoteChoice::Abstain => &mut proposal.abstain_weight,
    };
    *target = target
        .checked_add(weight)
        .ok_or(GovernanceError::Overflow)?;
    Ok(())
}

fn subtract_vote_weight(
    proposal: &mut ProposalRecord,
    choice: VoteChoice,
    weight: u128,
) -> Result<(), GovernanceError> {
    let target = match choice {
        VoteChoice::Yes => &mut proposal.yes_weight,
        VoteChoice::No => &mut proposal.no_weight,
        VoteChoice::Abstain => &mut proposal.abstain_weight,
    };
    *target = target
        .checked_sub(weight)
        .ok_or(GovernanceError::Overflow)?;
    Ok(())
}

fn normalize_governance_address(value: &str) -> Result<String, GovernanceError> {
    normalize_address(value).map_err(|_| GovernanceError::InvalidAddress)
}

fn validate_canonical_cid(value: &str) -> Result<(), GovernanceError> {
    validate_profile_cid(value, Some(DAG_CBOR_CODEC))
}

fn validate_raw_content_cid(value: &str) -> Result<(), GovernanceError> {
    validate_profile_cid(value, Some(RAW_CODEC))
}

fn validate_content_cid(value: &str) -> Result<(), GovernanceError> {
    validate_profile_cid(value, None)
}

fn validate_profile_cid(value: &str, expected_codec: Option<u64>) -> Result<(), GovernanceError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| GovernanceError::InvalidContentAddress(value.to_string()))?;
    if cid.version() != cid::Version::V1
        || expected_codec.is_some_and(|codec| cid.codec() != codec)
        || (expected_codec.is_none() && !matches!(cid.codec(), RAW_CODEC | DAG_CBOR_CODEC))
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return Err(GovernanceError::InvalidContentAddress(value.to_string()));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), GovernanceError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GovernanceError::InvalidContentAddress(value.to_string()));
    }
    Ok(())
}

fn validate_safe_label(value: &str, max_length: usize) -> Result<(), GovernanceError> {
    if value.is_empty()
        || value.len() > max_length
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._".contains(&byte)
        })
    {
        return Err(GovernanceError::InvalidAttestation);
    }
    Ok(())
}

fn validate_attestation_domain(domain: &str) -> Result<(), GovernanceError> {
    validate_safe_label(domain, 40)?;
    if !matches!(
        domain,
        AGENT_REVIEW_COMMITMENT_DOMAIN
            | BUILD_ATTESTATION_COMMITMENT_DOMAIN
            | DATA_AVAILABILITY_COMMITMENT_DOMAIN
    ) {
        return Err(GovernanceError::InvalidAttestation);
    }
    Ok(())
}

fn validate_canonical_attestation_fields(value: &str) -> Result<(), GovernanceError> {
    if value.is_empty()
        || value.len() > 2_048
        || value
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || byte == b'\\')
    {
        return Err(GovernanceError::InvalidAttestation);
    }
    Ok(())
}

fn commitment_address(value: &str) -> Result<String, GovernanceError> {
    Ok(normalize_governance_address(value)?[2..].to_string())
}

fn parse_atoms(value: &str) -> Result<u128, GovernanceError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(GovernanceError::InvalidParameters(
            "atomic amount is not canonical decimal".to_string(),
        ));
    }
    value.parse().map_err(|_| GovernanceError::Overflow)
}

fn valid_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn strict_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn checked_sum(mut values: impl Iterator<Item = u128>) -> Result<u128, GovernanceError> {
    values.try_fold(0u128, |sum, value| {
        sum.checked_add(value).ok_or(GovernanceError::Overflow)
    })
}

fn apply_bps(value: u128, bps: u16) -> Result<u128, GovernanceError> {
    let bps = u128::from(bps);
    let whole = (value / 10_000)
        .checked_mul(bps)
        .ok_or(GovernanceError::Overflow)?;
    let remainder = (value % 10_000) * bps / 10_000;
    whole
        .checked_add(remainder)
        .ok_or(GovernanceError::Overflow)
}

fn is_terminal(state: ProposalState) -> bool {
    matches!(
        state,
        ProposalState::Rejected
            | ProposalState::Executed
            | ProposalState::Stale
            | ProposalState::Expired
    )
}

fn hash_commitment_leaf(cid: &str) -> Result<[u8; 32], GovernanceError> {
    let cid: Cid = cid
        .parse()
        .map_err(|_| GovernanceError::InvalidContentAddress(cid.to_string()))?;
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(b"POHW_GOV_ATTESTATION_V1\0");
    data.extend_from_slice(&cid.to_bytes());
    Ok(Sha256::digest(data).into())
}

fn hash_commitment_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(90);
    data.extend_from_slice(b"POHW_GOV_ATTESTATION_NODE_V1\0");
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    Sha256::digest(data).into()
}

fn commitment_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| hash_commitment_node(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    level[0]
}

fn commitment_siblings(hashes: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = hashes.to_vec();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if index % 2 == 0 {
            level.get(index + 1).copied().unwrap_or(level[index])
        } else {
            level[index - 1]
        };
        siblings.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| hash_commitment_node(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
        index /= 2;
    }
    siblings
}

fn hash_attestation_commitment_leaf(domain: &str, canonical_fields: &str) -> [u8; 32] {
    let mut data = Vec::with_capacity(domain.len() + canonical_fields.len() + 1);
    data.extend_from_slice(domain.as_bytes());
    data.push(0);
    data.extend_from_slice(canonical_fields.as_bytes());
    Sha256::digest(data).into()
}

fn hash_attestation_commitment_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(ATTESTATION_NODE_DOMAIN.len() + 64);
    data.extend_from_slice(ATTESTATION_NODE_DOMAIN);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    Sha256::digest(data).into()
}

fn attestation_commitment_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| hash_attestation_commitment_node(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    level[0]
}

fn attestation_commitment_siblings(hashes: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = hashes.to_vec();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if index % 2 == 0 {
            level.get(index + 1).copied().unwrap_or(level[index])
        } else {
            level[index - 1]
        };
        siblings.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| hash_attestation_commitment_node(&pair[0], pair.get(1).unwrap_or(&pair[0])))
            .collect();
        index /= 2;
    }
    siblings
}

fn committed_attestation_root(domain: &str, leaf_count: u64, tree_root: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(
        ATTESTATION_ROOT_DOMAIN.len() + domain.len() + 1 + size_of::<u64>() + tree_root.len(),
    );
    data.extend_from_slice(ATTESTATION_ROOT_DOMAIN);
    data.extend_from_slice(domain.as_bytes());
    data.push(0);
    data.extend_from_slice(&leaf_count.to_be_bytes());
    data.extend_from_slice(tree_root);
    Sha256::digest(data).into()
}

pub fn verify_attestation_commitment(
    domain: &str,
    attestation_cid: &str,
    canonical_fields: &str,
    proof: &CidCommitmentProofV1,
    root: &str,
) -> bool {
    if validate_attestation_domain(domain).is_err()
        || validate_canonical_cid(attestation_cid).is_err()
        || validate_canonical_attestation_fields(canonical_fields).is_err()
        || !canonical_fields.starts_with(attestation_cid)
        || canonical_fields.as_bytes().get(attestation_cid.len()) != Some(&b'|')
        || proof.leaf_count == 0
        || proof.index >= proof.leaf_count
        || validate_sha256(root).is_err()
    {
        return false;
    }
    let mut levels = 0;
    let mut count = proof.leaf_count;
    while count > 1 {
        levels += 1;
        count = count.div_ceil(2);
    }
    if proof.siblings.len() != levels {
        return false;
    }
    let mut current = hash_attestation_commitment_leaf(domain, canonical_fields);
    let mut index = proof.index;
    let mut count = proof.leaf_count;
    for sibling in &proof.siblings {
        let Ok(bytes) = hex::decode(sibling) else {
            return false;
        };
        let Ok(sibling): Result<[u8; 32], _> = bytes.try_into() else {
            return false;
        };
        if index % 2 == 0 {
            if index + 1 >= count && sibling != current {
                return false;
            }
            current = hash_attestation_commitment_node(&current, &sibling);
        } else {
            current = hash_attestation_commitment_node(&sibling, &current);
        }
        index /= 2;
        count = count.div_ceil(2);
    }
    hex::encode(committed_attestation_root(
        domain,
        proof.leaf_count,
        &current,
    )) == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_identity_metrics_snapshot, flip_trust_bps, package_agent_review_attestation,
        package_build_attestation, package_data_availability_attestation,
        package_ecosystem_manifest, package_ecosystem_patch_manifest,
        package_identity_metrics_attestation,
        package_pinset_manifest_for_transition_with_additional, AgentReviewAttestationV1,
        BuildArtifactV1, BuildAttestationV1, BuiltIdentityMetricsSnapshot, CommandExecutionV1,
        DataAvailabilityAttestationV1, EcosystemManifestPackage, EcosystemManifestV1,
        EcosystemPatchManifestPackage, EcosystemPatchManifestV1, IdentityMetricsAttestationV1,
        RepositoryManifestV1, RepositoryPatchManifestV1, ReviewVerdictV1,
    };

    fn cid(label: &str) -> String {
        cid_for(DAG_CBOR_CODEC, label.as_bytes()).to_string()
    }

    fn raw_cid(label: &str) -> String {
        cid_for(RAW_CODEC, label.as_bytes()).to_string()
    }

    struct ReviewFixture {
        parent: EcosystemManifestPackage,
        candidate: EcosystemManifestPackage,
        patch: EcosystemPatchManifestPackage,
        toolchain_cid: String,
        pinset_cid: String,
        pinset_cids: Vec<String>,
        pinset_car: Vec<u8>,
    }

    fn review_fixture(prefix: &str) -> ReviewFixture {
        let base_source = cid("p2pool-base");
        let base_source_sha = hex::encode(base_source.parse::<Cid>().unwrap().hash().digest());
        let artifact_cid = raw_cid("deterministic-artifact");
        let artifact_sha = hex::encode(artifact_cid.parse::<Cid>().unwrap().hash().digest());
        let repository = RepositoryManifestV1 {
            schema_version: 1,
            name: "P2poolBTC".to_string(),
            source_tree_cid: base_source.clone(),
            source_tree_sha256: base_source_sha,
            git_bundle_cid: None,
            git_commit_metadata: None,
            dependency_locks: vec![],
            toolchain_locks: BTreeMap::from([("cargo".to_string(), "1.97.0".to_string())]),
            build_instructions: vec!["cargo build --workspace --locked".to_string()],
            artifacts: vec![ArtifactManifestV1 {
                name: "core".to_string(),
                cid: artifact_cid,
                sha256: artifact_sha,
                size: b"deterministic-artifact".len() as u64,
            }],
        };
        let parent = package_ecosystem_manifest(EcosystemManifestV1 {
            schema_version: 1,
            ecosystem_id: "pohw-parent".to_string(),
            parent_ecosystem_cid: None,
            repositories: vec![repository],
            compatibility_pins: BTreeMap::new(),
            toolchain_locks: BTreeMap::from([
                ("node".to_string(), "24.18.0".to_string()),
                ("rust".to_string(), "1.97.0".to_string()),
            ]),
            governance_contract_version: "0.1.0".to_string(),
            governance_parameter_set_cid: cid("parameters"),
        })
        .unwrap();
        let mut candidate_manifest = parent.manifest.clone();
        candidate_manifest.ecosystem_id = format!("pohw-{prefix}");
        candidate_manifest.parent_ecosystem_cid = Some(parent.root_cid.to_string());
        let candidate_source = cid(&format!("{prefix}-candidate-source"));
        candidate_manifest.repositories[0].source_tree_sha256 =
            hex::encode(candidate_source.parse::<Cid>().unwrap().hash().digest());
        candidate_manifest.repositories[0].source_tree_cid = candidate_source.clone();
        let candidate = package_ecosystem_manifest(candidate_manifest).unwrap();
        let repository_patch_cid = cid(&format!("{prefix}-repository-patch"));
        let repository_patch_sha =
            hex::encode(repository_patch_cid.parse::<Cid>().unwrap().hash().digest());
        let patch = package_ecosystem_patch_manifest(EcosystemPatchManifestV1 {
            schema_version: 1,
            kind: "pohw-ecosystem-patch-v1".to_string(),
            parent_ecosystem_cid: parent.root_cid.to_string(),
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            repository_patches: vec![RepositoryPatchManifestV1 {
                repository: "P2poolBTC".to_string(),
                base_source_cid: base_source,
                candidate_source_cid: candidate_source,
                patch_cid: repository_patch_cid,
                patch_sha256: repository_patch_sha,
            }],
        })
        .unwrap();
        let toolchain_cid = package_toolchain_manifest_for_ecosystem(&candidate.manifest)
            .unwrap()
            .root_cid
            .to_string();
        let pinset = package_pinset_manifest_for_transition_with_additional(
            &candidate,
            &patch,
            &[cid("rationale"), cid("migration"), cid("test-plan")],
        )
        .unwrap();
        ReviewFixture {
            parent,
            candidate,
            patch,
            toolchain_cid,
            pinset_cid: pinset.root_cid.to_string(),
            pinset_cids: pinset.manifest.cids,
            pinset_car: pinset.car_bytes,
        }
    }

    fn address(index: u8) -> String {
        format!("0x{index:040x}")
    }

    fn command(command: &str) -> CommandExecutionV1 {
        CommandExecutionV1 {
            command: command.to_string(),
            exit_code: 0,
            stdout_sha256: "11".repeat(32),
            stderr_sha256: "22".repeat(32),
        }
    }

    fn leaf(index: u8, state: IdentityState) -> GovernanceIdentityMetricsLeafV1 {
        GovernanceIdentityMetricsLeafV1 {
            address: address(index),
            identity_state: state,
            total_finalized_authored_flips: 20,
            total_consensus_reported_authored_flips: 1,
            flip_trust_bps: flip_trust_bps(20, 1).unwrap(),
            source_epoch: 2,
            source_block_height: 100,
            source_block_hash: "11".repeat(32),
        }
    }

    fn setup_engine() -> (GovernanceEngine, BuiltIdentityMetricsSnapshot) {
        let fixture = review_fixture("main");
        let snapshot = build_identity_metrics_snapshot(
            (1..=12)
                .map(|index| {
                    leaf(
                        index,
                        if index <= 5 {
                            IdentityState::Human
                        } else {
                            IdentityState::Newbie
                        },
                    )
                })
                .collect(),
        )
        .unwrap();
        let engine = GovernanceEngine::initialize(
            &fixture.parent.root_cid.to_string(),
            &cid("parameters"),
            GovernanceParameterSetV1::experimental_defaults(),
            &snapshot.root,
            2,
        )
        .unwrap();
        (engine, snapshot)
    }

    fn certify_current_metrics(
        engine: &mut GovernanceEngine,
        snapshot: &BuiltIdentityMetricsSnapshot,
        operators: &[u8],
    ) {
        let snapshot_cid = cid("identity-metrics-snapshot");
        let parsed_snapshot_cid: Cid = snapshot_cid.parse().unwrap();
        let snapshot_sha256 = hex::encode(parsed_snapshot_cid.hash().digest());
        for operator in operators {
            let package = package_identity_metrics_attestation(IdentityMetricsAttestationV1 {
                schema_version: 1,
                metrics_root: snapshot.root.clone(),
                snapshot_cid: snapshot_cid.clone(),
                snapshot_sha256: snapshot_sha256.clone(),
                source_epoch: 2,
                source_block_height: 100,
                source_block_hash: "11".repeat(32),
                replay_start_height: 1,
                replay_commitment: "33".repeat(32),
                indexer_implementation_cid: cid("metrics-indexer-implementation"),
                operator_idena_address: address(*operator),
                observed_at_block_or_timestamp: 9,
                authentication: "on-chain-submitter".to_string(),
            })
            .unwrap();
            engine
                .submit_identity_metrics_attestation(
                    &address(*operator),
                    &package.root_cid.to_string(),
                    &package.car_bytes,
                    GovernanceClock { block: 9, epoch: 2 },
                )
                .unwrap();
        }
        assert!(
            engine
                .identity_metrics_certification(&snapshot.root, 2)
                .unwrap()
                .certified
        );
    }

    fn proposal_content(
        proposer: &str,
        agents: &BuiltCidCommitment,
        builders: &BuiltCidCommitment,
        availability: &BuiltCidCommitment,
    ) -> ChangeProposalContentV1 {
        let fixture = review_fixture("main");
        let base_source = fixture.parent.manifest.repositories[0]
            .source_tree_cid
            .clone();
        let candidate_source = fixture.candidate.manifest.repositories[0]
            .source_tree_cid
            .clone();
        ChangeProposalContentV1 {
            schema_version: 1,
            parent_canonical_ecosystem_cid: fixture.parent.root_cid.to_string(),
            candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
            affected_repositories: vec!["P2poolBTC".to_string()],
            base_source_cids: BTreeMap::from([("P2poolBTC".to_string(), base_source)]),
            candidate_source_cids: BTreeMap::from([("P2poolBTC".to_string(), candidate_source)]),
            patch_cid: fixture.patch.root_cid.to_string(),
            review_round_id: "00".repeat(32),
            proposer_address: proposer.to_string(),
            proposal_bond_atoms: 10_000_000_000_000_000_000,
            risk_class: RiskClass::Critical,
            rationale_cid: cid("rationale"),
            migration_notes_cid: cid("migration"),
            test_plan_cid: cid("test-plan"),
            release_manifest_cid: None,
            critical_finding_waiver_cid: None,
            agent_review_root: agents.root.clone(),
            build_attestation_root: builders.root.clone(),
            data_availability_root: availability.root.clone(),
            creation_block: 50,
            creation_epoch: 2,
            staking_epoch: 2,
            identity_metrics_epoch: 2,
            candidate_identity_metrics_root: None,
            candidate_identity_metrics_epoch: None,
            voting_start: 90,
            voting_end: 210,
            challenge_end: 270,
        }
    }

    fn insert_test_proposal(
        engine: &mut GovernanceEngine,
        content: ChangeProposalContentV1,
        state: ProposalState,
    ) -> String {
        let id = proposal_id(&content).unwrap();
        let challenge_end = content.challenge_end;
        let execution_not_before = content.challenge_end + engine.parameters.timelock_blocks;
        let execution_expires = execution_not_before + engine.parameters.execution_window_blocks;
        engine.proposals.insert(
            id.clone(),
            ProposalRecord {
                id: id.clone(),
                state,
                content,
                proposal_bond_settled: false,
                agents: BTreeMap::new(),
                builders: BTreeMap::new(),
                availability: BTreeMap::new(),
                required_availability_cids: BTreeSet::new(),
                voter_snapshot: BTreeMap::new(),
                votes: BTreeMap::new(),
                yes_weight: 0,
                no_weight: 0,
                abstain_weight: 0,
                total_registered_weight: 0,
                gates: None,
                pending_challenge: None,
                challenge_end,
                execution_not_before,
                execution_expires,
            },
        );
        id
    }

    #[test]
    fn commitment_rejects_duplicates_and_tampering() {
        let values = vec![cid("a"), cid("b"), cid("c")];
        let commitment = build_cid_commitment(&values).unwrap();
        for value in &values {
            let proof = commitment.proofs.get(value).unwrap();
            assert_eq!(proof.leaf_count, 3);
            assert!(proof.index < proof.leaf_count);
        }
        assert_eq!(
            build_cid_commitment(&[cid("a"), cid("a")]),
            Err(GovernanceError::Duplicate)
        );

        let entries = values
            .iter()
            .enumerate()
            .map(|(index, value)| AttestationCommitmentEntryV1 {
                attestation_cid: value.clone(),
                canonical_fields: agent_attestation_commitment_fields(
                    value,
                    &format!("family-{index}"),
                    &address((index + 1) as u8),
                    0,
                )
                .unwrap(),
            })
            .collect::<Vec<_>>();
        let commitment =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &entries).unwrap();
        for entry in &entries {
            assert!(verify_attestation_commitment(
                AGENT_REVIEW_COMMITMENT_DOMAIN,
                &entry.attestation_cid,
                &entry.canonical_fields,
                &commitment.proofs[&entry.attestation_cid],
                &commitment.root,
            ));
        }
        let tampered = entries[0].canonical_fields.replace("family-0", "family-x");
        assert!(!verify_attestation_commitment(
            AGENT_REVIEW_COMMITMENT_DOMAIN,
            &entries[0].attestation_cid,
            &tampered,
            &commitment.proofs[&entries[0].attestation_cid],
            &commitment.root,
        ));

        let oversized = (0..=MAX_REVIEW_ATTESTATIONS_PER_CLASS)
            .map(|index| {
                let attestation_cid = cid(&format!("oversized-{index}"));
                AttestationCommitmentEntryV1 {
                    canonical_fields: agent_attestation_commitment_fields(
                        &attestation_cid,
                        "family-a",
                        &address(1),
                        0,
                    )
                    .unwrap(),
                    attestation_cid,
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &oversized),
            Err(GovernanceError::ReviewRoundFull)
        );
    }

    #[test]
    fn metrics_certification_resists_first_writer_poisoning_and_fails_on_quorum_conflict() {
        let (mut engine, snapshot) = setup_engine();
        for index in 1..=6 {
            engine
                .register_identity_metrics(
                    &address(index),
                    snapshot.proofs[&address(index)].clone(),
                )
                .unwrap();
        }
        let snapshot_cid = cid("identity-metrics-snapshot");
        let parsed_snapshot_cid: Cid = snapshot_cid.parse().unwrap();
        let snapshot_sha256 = hex::encode(parsed_snapshot_cid.hash().digest());
        let mut submit = |operator: u8, replay_byte: &str| {
            let package = package_identity_metrics_attestation(IdentityMetricsAttestationV1 {
                schema_version: 1,
                metrics_root: snapshot.root.clone(),
                snapshot_cid: snapshot_cid.clone(),
                snapshot_sha256: snapshot_sha256.clone(),
                source_epoch: 2,
                source_block_height: 100,
                source_block_hash: "11".repeat(32),
                replay_start_height: 1,
                replay_commitment: replay_byte.repeat(32),
                indexer_implementation_cid: cid("metrics-indexer-implementation"),
                operator_idena_address: address(operator),
                observed_at_block_or_timestamp: 9,
                authentication: "on-chain-submitter".to_string(),
            })
            .unwrap();
            engine
                .submit_identity_metrics_attestation(
                    &address(operator),
                    &package.root_cid.to_string(),
                    &package.car_bytes,
                    GovernanceClock { block: 9, epoch: 2 },
                )
                .unwrap()
        };

        submit(1, "44");
        submit(2, "33");
        submit(3, "33");
        let certified = submit(4, "33");
        assert!(certified.certified);
        assert!(!certified.conflict);

        submit(5, "44");
        let conflicted = submit(6, "44");
        assert!(conflicted.conflict);
        assert!(!conflicted.certified);
        assert_eq!(conflicted.attestation_count, 0);
    }

    #[test]
    fn frozen_review_round_cannot_omit_an_adverse_builder_digest() {
        let (mut engine, snapshot) = setup_engine();
        for index in 1..=3 {
            engine
                .register_identity_metrics(
                    &address(index),
                    snapshot.proofs[&address(index)].clone(),
                )
                .unwrap();
        }
        certify_current_metrics(&mut engine, &snapshot, &[1, 2, 3]);
        let fixture = review_fixture("main");
        let round_id = engine
            .open_review_round(
                OpenReviewRoundInputV1 {
                    parent_car: &fixture.parent.car_bytes,
                    candidate_car: &fixture.candidate.car_bytes,
                    patch_car: &fixture.patch.car_bytes,
                    pinset_car: &fixture.pinset_car,
                    opener_address: &address(1),
                    attached_bond_atoms: 10_000_000_000_000_000_000,
                },
                GovernanceClock {
                    block: 10,
                    epoch: 2,
                },
            )
            .unwrap();
        let proof = CidCommitmentProofV1 {
            index: 0,
            leaf_count: 1,
            siblings: vec![],
        };
        let clean_build_cid = cid("clean-build");
        let adverse_build_cid = cid("adverse-build");
        let clean_digest = "11".repeat(32);
        let adverse_digest = "22".repeat(32);
        let agent_cid = cid("agent");
        let availability_cid = cid("availability");
        {
            let round = engine.review_rounds.get_mut(&round_id).unwrap();
            round.agents.insert(
                agent_cid.clone(),
                BondedAgentAttestation {
                    input: AgentAttestationInputV1 {
                        attestation_cid: agent_cid,
                        attestation_car: vec![],
                        parent_ecosystem_cid: cid("initial-ecosystem"),
                        candidate_ecosystem_cid: cid("candidate-ecosystem"),
                        patch_cid: cid("patch"),
                        owner_address: address(1),
                        model_identifier: "model-a".to_string(),
                        model_revision: None,
                        runtime_identifier: "runtime-a".to_string(),
                        independence_group: "family-a".to_string(),
                        verdict: AttestationVerdict::Approve,
                        unresolved_critical_findings: 0,
                        test_result_cid: raw_cid("agent-result"),
                        tests_passed_claim: true,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: proof.clone(),
                    },
                    settled: false,
                },
            );
            for (attestation_cid, digest, owner) in [
                (clean_build_cid.clone(), clean_digest.clone(), address(1)),
                (adverse_build_cid, adverse_digest, address(2)),
            ] {
                round.builders.insert(
                    attestation_cid.clone(),
                    BondedBuildAttestation {
                        input: BuildAttestationInputV1 {
                            attestation_cid,
                            attestation_car: vec![],
                            candidate_ecosystem_cid: cid("candidate-ecosystem"),
                            builder_address: owner,
                            runtime_family: "linux".to_string(),
                            architecture: "x86_64".to_string(),
                            core_artifact_digest: digest,
                            test_result_cid: raw_cid("build-result"),
                            tests_passed_claim: true,
                            bond_atoms: 1_000_000_000_000_000_000,
                            commitment_proof: proof.clone(),
                        },
                        settled: false,
                    },
                );
            }
            round.availability.insert(
                availability_cid.clone(),
                BondedDataAvailabilityAttestation {
                    input: DataAvailabilityAttestationInputV1 {
                        attestation_cid: availability_cid,
                        attestation_car: vec![],
                        candidate_ecosystem_cid: cid("candidate-ecosystem"),
                        provider_id: "provider-a".to_string(),
                        operator_address: address(1),
                        pinset_cid: cid("pinset"),
                        verified_cids: vec![cid("candidate-ecosystem")],
                        probe_result_cid: raw_cid("probe-result"),
                        available_claim: true,
                        expires_at_block: 400,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: proof,
                    },
                    settled: false,
                },
            );
        }
        let frozen = engine
            .freeze_review_round(
                &round_id,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(frozen.build_attestations, 2);
        let clean_only = build_attestation_commitment(
            BUILD_ATTESTATION_COMMITMENT_DOMAIN,
            &[AttestationCommitmentEntryV1 {
                attestation_cid: clean_build_cid.clone(),
                canonical_fields: build_attestation_commitment_fields(
                    &clean_build_cid,
                    &clean_digest,
                    "linux",
                    "x86_64",
                    &address(1),
                )
                .unwrap(),
            }],
        )
        .unwrap();
        assert_ne!(
            frozen.build_attestation_root.as_deref(),
            Some(clean_only.root.as_str())
        );
        let round = engine.review_rounds.get(&round_id).unwrap();
        let (agents, _, availability) = review_round_commitments(round).unwrap();
        let mut content = proposal_content(&address(1), &agents, &clean_only, &availability);
        content.review_round_id = round_id;
        assert_eq!(
            engine.create_proposal_draft(
                content,
                0,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidProposal)
        );
    }

    #[test]
    fn review_round_capacity_matches_the_wasm_bound() {
        let (mut engine, snapshot) = setup_engine();
        engine
            .register_identity_metrics(&address(1), snapshot.proofs[&address(1)].clone())
            .unwrap();
        let fixture = review_fixture("capacity");
        let round_id = engine
            .open_review_round(
                OpenReviewRoundInputV1 {
                    parent_car: &fixture.parent.car_bytes,
                    candidate_car: &fixture.candidate.car_bytes,
                    patch_car: &fixture.patch.car_bytes,
                    pinset_car: &fixture.pinset_car,
                    opener_address: &address(1),
                    attached_bond_atoms: 10_000_000_000_000_000_000,
                },
                GovernanceClock {
                    block: 10,
                    epoch: 2,
                },
            )
            .unwrap();
        let proof = CidCommitmentProofV1 {
            index: 0,
            leaf_count: 1,
            siblings: vec![],
        };
        let round = engine.review_rounds.get_mut(&round_id).unwrap();
        for index in 0..=MAX_REVIEW_ATTESTATIONS_PER_CLASS {
            let attestation_cid = cid(&format!("capacity-review-{index}"));
            round.agents.insert(
                attestation_cid.clone(),
                BondedAgentAttestation {
                    input: AgentAttestationInputV1 {
                        attestation_cid,
                        attestation_car: vec![],
                        parent_ecosystem_cid: cid("initial-ecosystem"),
                        candidate_ecosystem_cid: cid("capacity-candidate"),
                        patch_cid: cid("capacity-patch"),
                        owner_address: address(1),
                        model_identifier: "model-a".to_string(),
                        model_revision: None,
                        runtime_identifier: "runtime-a".to_string(),
                        independence_group: "family-a".to_string(),
                        verdict: AttestationVerdict::Approve,
                        unresolved_critical_findings: 0,
                        test_result_cid: raw_cid("capacity-result"),
                        tests_passed_claim: true,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: proof.clone(),
                    },
                    settled: false,
                },
            );
        }
        assert!(matches!(
            engine.freeze_review_round(
                &round_id,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::ReviewRoundFull)
        ));
    }

    #[test]
    fn review_round_rejects_attestations_for_substituted_candidate_content() {
        let (mut engine, snapshot) = setup_engine();
        for index in 1..=3 {
            engine
                .register_identity_metrics(
                    &address(index),
                    snapshot.proofs[&address(index)].clone(),
                )
                .unwrap();
        }
        certify_current_metrics(&mut engine, &snapshot, &[1, 2, 3]);
        let fixture = review_fixture("main");
        let round_id = engine
            .open_review_round(
                OpenReviewRoundInputV1 {
                    parent_car: &fixture.parent.car_bytes,
                    candidate_car: &fixture.candidate.car_bytes,
                    patch_car: &fixture.patch.car_bytes,
                    pinset_car: &fixture.pinset_car,
                    opener_address: &address(1),
                    attached_bond_atoms: 10_000_000_000_000_000_000,
                },
                GovernanceClock {
                    block: 10,
                    epoch: 2,
                },
            )
            .unwrap();
        let proof = CidCommitmentProofV1 {
            index: 0,
            leaf_count: 1,
            siblings: vec![],
        };
        let clock = GovernanceClock {
            block: 20,
            epoch: 2,
        };

        let agent = package_agent_review_attestation(AgentReviewAttestationV1 {
            schema_version: 1,
            parent_ecosystem_cid: fixture.parent.root_cid.to_string(),
            candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
            patch_cid: fixture.patch.root_cid.to_string(),
            affected_repositories: vec![RepositoryCidV1 {
                repository: "P2poolBTC".to_string(),
                cid: cid("substituted-source"),
            }],
            model_identifier: "model-a".to_string(),
            model_revision: None,
            provider_or_runtime_identifier: "runtime-a".to_string(),
            model_family: "family-a".to_string(),
            agent_policy_cid: cid("agent-policy"),
            system_prompt_policy_cid: cid("prompt-policy"),
            tool_versions: BTreeMap::from([("cargo".to_string(), "1.97.0".to_string())]),
            commands_executed: vec![command("cargo test --workspace")],
            test_results_cid: raw_cid("agent-substitution-result"),
            tests_passed: true,
            static_analysis_results_cid: cid("static-analysis"),
            dependency_findings_cid: cid("dependency-findings"),
            security_findings: vec![],
            unresolved_critical_findings: 0,
            verdict: ReviewVerdictV1::Approve,
            owner_idena_address: address(1),
            reviewer_bond_atoms: "1000000000000000000".to_string(),
            creation_block_or_timestamp: 20,
            authentication: "on-chain-submitter".to_string(),
        })
        .unwrap();
        assert_eq!(
            engine.submit_agent_attestation(
                &round_id,
                AgentAttestationInputV1 {
                    attestation_cid: agent.root_cid.to_string(),
                    attestation_car: agent.car_bytes,
                    parent_ecosystem_cid: agent.value.parent_ecosystem_cid,
                    candidate_ecosystem_cid: agent.value.candidate_ecosystem_cid,
                    patch_cid: agent.value.patch_cid,
                    owner_address: agent.value.owner_idena_address,
                    model_identifier: agent.value.model_identifier,
                    model_revision: agent.value.model_revision,
                    runtime_identifier: agent.value.provider_or_runtime_identifier,
                    independence_group: agent.value.model_family,
                    verdict: AttestationVerdict::Approve,
                    unresolved_critical_findings: 0,
                    test_result_cid: agent.value.test_results_cid,
                    tests_passed_claim: true,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: proof.clone(),
                },
                clock,
            ),
            Err(GovernanceError::InvalidAttestation)
        );

        for (label, source_cid, toolchain_cid, artifact_cid) in [
            (
                "source",
                cid("substituted-source"),
                fixture.toolchain_cid.clone(),
                raw_cid("deterministic-artifact"),
            ),
            (
                "toolchain",
                fixture.candidate.manifest.repositories[0]
                    .source_tree_cid
                    .clone(),
                cid("substituted-toolchain"),
                raw_cid("deterministic-artifact"),
            ),
            (
                "artifact",
                fixture.candidate.manifest.repositories[0]
                    .source_tree_cid
                    .clone(),
                fixture.toolchain_cid.clone(),
                raw_cid("substituted-artifact"),
            ),
        ] {
            let artifact_sha = hex::encode(artifact_cid.parse::<Cid>().unwrap().hash().digest());
            let artifacts = vec![BuildArtifactV1 {
                name: "core".to_string(),
                cid: artifact_cid,
                sha256: artifact_sha,
                size: b"deterministic-artifact".len() as u64,
                core: true,
            }];
            let build = package_build_attestation(BuildAttestationV1 {
                schema_version: 1,
                candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
                source_cids: vec![RepositoryCidV1 {
                    repository: "P2poolBTC".to_string(),
                    cid: source_cid,
                }],
                toolchain_cid,
                builder_identity: address(2),
                runtime_family: "linux".to_string(),
                architecture: "x86_64".to_string(),
                commands: vec![command("cargo build --workspace --locked")],
                test_results_cid: raw_cid(&format!("build-{label}-result")),
                tests_passed: true,
                sbom_cid: raw_cid(&format!("build-{label}-sbom")),
                core_artifact_digest: crate::core_artifact_set_digest(&artifacts).unwrap(),
                artifacts,
                builder_bond_atoms: "1000000000000000000".to_string(),
                creation_block_or_timestamp: 20,
                authentication: "on-chain-submitter".to_string(),
            })
            .unwrap();
            assert_eq!(
                engine.submit_build_attestation(
                    &round_id,
                    BuildAttestationInputV1 {
                        attestation_cid: build.root_cid.to_string(),
                        attestation_car: build.car_bytes,
                        candidate_ecosystem_cid: build.value.candidate_ecosystem_cid,
                        builder_address: build.value.builder_identity,
                        runtime_family: build.value.runtime_family,
                        architecture: build.value.architecture,
                        core_artifact_digest: build.value.core_artifact_digest,
                        test_result_cid: build.value.test_results_cid,
                        tests_passed_claim: true,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: proof.clone(),
                    },
                    clock,
                ),
                Err(GovernanceError::InvalidAttestation),
                "{label} substitution was accepted"
            );
        }

        let availability = package_data_availability_attestation(DataAvailabilityAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
            pinset_cid: cid("substituted-pinset"),
            provider_id: "provider-a".to_string(),
            operator_identity: address(3),
            verified_cids: vec![fixture.candidate.root_cid.to_string()],
            probe_result_cid: raw_cid("availability-substitution-result"),
            available: true,
            observed_at_block_or_timestamp: 20,
            expires_at_block: 400,
            bond_atoms: "1000000000000000000".to_string(),
            authentication: "on-chain-submitter".to_string(),
        })
        .unwrap();
        assert_eq!(
            engine.submit_data_availability_attestation(
                &round_id,
                DataAvailabilityAttestationInputV1 {
                    attestation_cid: availability.root_cid.to_string(),
                    attestation_car: availability.car_bytes,
                    candidate_ecosystem_cid: availability.value.candidate_ecosystem_cid,
                    provider_id: availability.value.provider_id,
                    operator_address: availability.value.operator_identity,
                    pinset_cid: availability.value.pinset_cid,
                    verified_cids: availability.value.verified_cids,
                    probe_result_cid: availability.value.probe_result_cid,
                    available_claim: true,
                    expires_at_block: availability.value.expires_at_block,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: proof,
                },
                clock,
            ),
            Err(GovernanceError::InvalidAttestation)
        );
    }

    #[test]
    fn stake_activates_next_epoch_and_unbonding_is_delayed() {
        let (mut engine, _) = setup_engine();
        engine
            .register_stake(
                &address(1),
                10_000_000_000_000_000_000,
                GovernanceClock { block: 1, epoch: 1 },
            )
            .unwrap();
        assert_eq!(
            engine.stake_position(&address(1), 1).unwrap().active_atoms,
            0
        );
        assert_eq!(
            engine.stake_position(&address(1), 2).unwrap().active_atoms,
            10_000_000_000_000_000_000
        );
        engine
            .schedule_withdrawal(
                &address(1),
                5_000_000_000_000_000_000,
                GovernanceClock { block: 2, epoch: 2 },
            )
            .unwrap();
        assert_eq!(
            engine.stake_position(&address(1), 2).unwrap().active_atoms,
            10_000_000_000_000_000_000
        );
        assert_eq!(
            engine.stake_position(&address(1), 3).unwrap().active_atoms,
            5_000_000_000_000_000_000
        );
        assert_eq!(
            engine.finalize_unbonding(&address(1), GovernanceClock { block: 3, epoch: 6 }),
            Err(GovernanceError::NoRefund)
        );
        assert_eq!(
            engine
                .finalize_unbonding(&address(1), GovernanceClock { block: 4, epoch: 7 })
                .unwrap(),
            5_000_000_000_000_000_000
        );
    }

    #[test]
    fn end_to_end_four_gate_execution_has_no_admin_path() {
        let (mut engine, snapshot) = setup_engine();
        for index in 1..=12 {
            engine
                .register_identity_metrics(
                    &address(index),
                    snapshot.proofs.get(&address(index)).unwrap().clone(),
                )
                .unwrap();
            engine
                .register_stake(
                    &address(index),
                    1_000_000_000_000_000_000,
                    GovernanceClock { block: 1, epoch: 1 },
                )
                .unwrap();
        }
        certify_current_metrics(&mut engine, &snapshot, &[1, 2, 3]);
        let fixture = review_fixture("main");
        let repository_cids = vec![RepositoryCidV1 {
            repository: "P2poolBTC".to_string(),
            cid: fixture.candidate.manifest.repositories[0]
                .source_tree_cid
                .clone(),
        }];
        let agent_packages = (0..5)
            .map(|index| {
                let owner = address((index % 3 + 1) as u8);
                package_agent_review_attestation(AgentReviewAttestationV1 {
                    schema_version: 1,
                    parent_ecosystem_cid: fixture.parent.root_cid.to_string(),
                    candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
                    patch_cid: fixture.patch.root_cid.to_string(),
                    affected_repositories: repository_cids.clone(),
                    model_identifier: format!("model-{index}"),
                    model_revision: None,
                    provider_or_runtime_identifier: format!("runtime-{index}"),
                    model_family: format!("family-{index}"),
                    agent_policy_cid: cid("agent-policy"),
                    system_prompt_policy_cid: cid("prompt-policy"),
                    tool_versions: BTreeMap::from([("cargo".to_string(), "1.97.0".to_string())]),
                    commands_executed: vec![command("cargo test --workspace")],
                    test_results_cid: raw_cid(&format!("agent-result-{index}")),
                    tests_passed: true,
                    static_analysis_results_cid: cid(&format!("static-{index}")),
                    dependency_findings_cid: cid(&format!("dependencies-{index}")),
                    security_findings: vec![],
                    unresolved_critical_findings: 0,
                    verdict: ReviewVerdictV1::Approve,
                    owner_idena_address: owner,
                    reviewer_bond_atoms: "1000000000000000000".to_string(),
                    creation_block_or_timestamp: 20,
                    authentication: "on-chain-submitter".to_string(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let artifact_bytes = b"deterministic-artifact";
        let artifact_digest = hex::encode(Sha256::digest(artifact_bytes));
        let build_packages = (0..3)
            .map(|index| {
                let artifacts = vec![BuildArtifactV1 {
                    name: "core".to_string(),
                    cid: cid_for(RAW_CODEC, artifact_bytes).to_string(),
                    sha256: artifact_digest.clone(),
                    size: artifact_bytes.len() as u64,
                    core: true,
                }];
                let core_artifact_digest = crate::core_artifact_set_digest(&artifacts).unwrap();
                package_build_attestation(BuildAttestationV1 {
                    schema_version: 1,
                    candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
                    source_cids: repository_cids.clone(),
                    toolchain_cid: fixture.toolchain_cid.clone(),
                    builder_identity: address((index + 1) as u8),
                    runtime_family: if index == 1 { "macos" } else { "linux" }.to_string(),
                    architecture: if index == 1 { "arm64" } else { "x86_64" }.to_string(),
                    commands: vec![command("cargo build --workspace --locked")],
                    test_results_cid: raw_cid(&format!("builder-result-{index}")),
                    tests_passed: true,
                    sbom_cid: raw_cid(&format!("sbom-{index}")),
                    artifacts,
                    core_artifact_digest,
                    builder_bond_atoms: "1000000000000000000".to_string(),
                    creation_block_or_timestamp: 20,
                    authentication: "on-chain-submitter".to_string(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut required_availability_cids =
            fixture.pinset_cids.iter().cloned().collect::<BTreeSet<_>>();
        for package in &agent_packages {
            required_availability_cids.extend([
                package.root_cid.to_string(),
                package.value.agent_policy_cid.clone(),
                package.value.system_prompt_policy_cid.clone(),
                package.value.test_results_cid.clone(),
                package.value.static_analysis_results_cid.clone(),
                package.value.dependency_findings_cid.clone(),
            ]);
        }
        for package in &build_packages {
            required_availability_cids.extend([
                package.root_cid.to_string(),
                package.value.toolchain_cid.clone(),
                package.value.test_results_cid.clone(),
                package.value.sbom_cid.clone(),
            ]);
            required_availability_cids.extend(
                package
                    .value
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.cid.clone()),
            );
        }
        let availability_packages = (0..3)
            .map(|index| {
                let probe_result_cid = raw_cid(&format!("probe-{index}"));
                let mut verified_cids = required_availability_cids.clone();
                verified_cids.insert(probe_result_cid.clone());
                package_data_availability_attestation(DataAvailabilityAttestationV1 {
                    schema_version: 1,
                    candidate_ecosystem_cid: fixture.candidate.root_cid.to_string(),
                    pinset_cid: fixture.pinset_cid.clone(),
                    provider_id: format!("provider-{index}"),
                    operator_identity: address((index + 1) as u8),
                    verified_cids: verified_cids.into_iter().collect(),
                    probe_result_cid,
                    available: true,
                    observed_at_block_or_timestamp: 20,
                    expires_at_block: 400,
                    bond_atoms: "1000000000000000000".to_string(),
                    authentication: "on-chain-submitter".to_string(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let agent_entries = agent_packages
            .iter()
            .map(|package| AttestationCommitmentEntryV1 {
                attestation_cid: package.root_cid.to_string(),
                canonical_fields: agent_attestation_commitment_fields(
                    &package.root_cid.to_string(),
                    &package.value.model_family,
                    &package.value.owner_idena_address,
                    package.value.unresolved_critical_findings,
                )
                .unwrap(),
            })
            .collect::<Vec<_>>();
        let builder_entries = build_packages
            .iter()
            .map(|package| AttestationCommitmentEntryV1 {
                attestation_cid: package.root_cid.to_string(),
                canonical_fields: build_attestation_commitment_fields(
                    &package.root_cid.to_string(),
                    &package.value.core_artifact_digest,
                    &package.value.runtime_family,
                    &package.value.architecture,
                    &package.value.builder_identity,
                )
                .unwrap(),
            })
            .collect::<Vec<_>>();
        let availability_entries = availability_packages
            .iter()
            .map(|package| AttestationCommitmentEntryV1 {
                attestation_cid: package.root_cid.to_string(),
                canonical_fields: data_availability_commitment_fields(
                    &package.root_cid.to_string(),
                    &package.value.candidate_ecosystem_cid,
                    &package.value.pinset_cid,
                    &package.value.provider_id,
                    &package.value.operator_identity,
                )
                .unwrap(),
            })
            .collect::<Vec<_>>();
        let agents =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &agent_entries).unwrap();
        let builders =
            build_attestation_commitment(BUILD_ATTESTATION_COMMITMENT_DOMAIN, &builder_entries)
                .unwrap();
        let availability = build_attestation_commitment(
            DATA_AVAILABILITY_COMMITMENT_DOMAIN,
            &availability_entries,
        )
        .unwrap();
        let review_round_id = engine
            .open_review_round(
                OpenReviewRoundInputV1 {
                    parent_car: &fixture.parent.car_bytes,
                    candidate_car: &fixture.candidate.car_bytes,
                    patch_car: &fixture.patch.car_bytes,
                    pinset_car: &fixture.pinset_car,
                    opener_address: &address(1),
                    attached_bond_atoms: 10_000_000_000_000_000_000,
                },
                GovernanceClock {
                    block: 10,
                    epoch: 2,
                },
            )
            .unwrap();
        for package in &agent_packages {
            let attestation_cid = package.root_cid.to_string();
            if package.root_cid == agent_packages[0].root_cid {
                let false_claim = AgentAttestationInputV1 {
                    attestation_cid: attestation_cid.clone(),
                    attestation_car: package.car_bytes.clone(),
                    parent_ecosystem_cid: package.value.parent_ecosystem_cid.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    patch_cid: package.value.patch_cid.clone(),
                    owner_address: package.value.owner_idena_address.clone(),
                    model_identifier: package.value.model_identifier.clone(),
                    model_revision: package.value.model_revision.clone(),
                    runtime_identifier: package.value.provider_or_runtime_identifier.clone(),
                    independence_group: package.value.model_family.clone(),
                    verdict: AttestationVerdict::Approve,
                    unresolved_critical_findings: package.value.unresolved_critical_findings,
                    test_result_cid: package.value.test_results_cid.clone(),
                    tests_passed_claim: false,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: agents.proofs[&attestation_cid].clone(),
                };
                assert_eq!(
                    engine.submit_agent_attestation(
                        &review_round_id,
                        false_claim,
                        GovernanceClock {
                            block: 20,
                            epoch: 2,
                        },
                    ),
                    Err(GovernanceError::InvalidAttestation)
                );
            }
            engine
                .submit_agent_attestation(
                    &review_round_id,
                    AgentAttestationInputV1 {
                        attestation_cid: attestation_cid.clone(),
                        attestation_car: package.car_bytes.clone(),
                        parent_ecosystem_cid: package.value.parent_ecosystem_cid.clone(),
                        candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                        patch_cid: package.value.patch_cid.clone(),
                        owner_address: package.value.owner_idena_address.clone(),
                        model_identifier: package.value.model_identifier.clone(),
                        model_revision: package.value.model_revision.clone(),
                        runtime_identifier: package.value.provider_or_runtime_identifier.clone(),
                        independence_group: package.value.model_family.clone(),
                        verdict: AttestationVerdict::Approve,
                        unresolved_critical_findings: package.value.unresolved_critical_findings,
                        test_result_cid: package.value.test_results_cid.clone(),
                        tests_passed_claim: package.value.tests_passed,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: agents.proofs[&attestation_cid].clone(),
                    },
                    GovernanceClock {
                        block: 20,
                        epoch: 2,
                    },
                )
                .unwrap();
        }
        let mut owner_capped_agent = agent_packages[0].value.clone();
        owner_capped_agent.model_identifier = "owner-cap-model".to_string();
        owner_capped_agent.provider_or_runtime_identifier = "owner-cap-runtime".to_string();
        owner_capped_agent.model_family = "owner-cap-family".to_string();
        owner_capped_agent.test_results_cid = raw_cid("owner-cap-agent-result");
        owner_capped_agent.static_analysis_results_cid = cid("owner-cap-static");
        owner_capped_agent.dependency_findings_cid = cid("owner-cap-dependencies");
        let owner_capped_agent = package_agent_review_attestation(owner_capped_agent).unwrap();
        assert_eq!(
            engine.submit_agent_attestation(
                &review_round_id,
                AgentAttestationInputV1 {
                    attestation_cid: owner_capped_agent.root_cid.to_string(),
                    attestation_car: owner_capped_agent.car_bytes,
                    parent_ecosystem_cid: owner_capped_agent.value.parent_ecosystem_cid,
                    candidate_ecosystem_cid: owner_capped_agent.value.candidate_ecosystem_cid,
                    patch_cid: owner_capped_agent.value.patch_cid,
                    owner_address: owner_capped_agent.value.owner_idena_address,
                    model_identifier: owner_capped_agent.value.model_identifier,
                    model_revision: owner_capped_agent.value.model_revision,
                    runtime_identifier: owner_capped_agent.value.provider_or_runtime_identifier,
                    independence_group: owner_capped_agent.value.model_family,
                    verdict: AttestationVerdict::Approve,
                    unresolved_critical_findings: 0,
                    test_result_cid: owner_capped_agent.value.test_results_cid,
                    tests_passed_claim: true,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: CidCommitmentProofV1 {
                        index: 0,
                        leaf_count: 1,
                        siblings: vec![],
                    },
                },
                GovernanceClock {
                    block: 20,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::ReviewRoundFull)
        );
        for package in &build_packages {
            let attestation_cid = package.root_cid.to_string();
            if package.root_cid == build_packages[0].root_cid {
                let false_claim = BuildAttestationInputV1 {
                    attestation_cid: attestation_cid.clone(),
                    attestation_car: package.car_bytes.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    builder_address: package.value.builder_identity.clone(),
                    runtime_family: package.value.runtime_family.clone(),
                    architecture: package.value.architecture.clone(),
                    core_artifact_digest: package.value.core_artifact_digest.clone(),
                    test_result_cid: package.value.test_results_cid.clone(),
                    tests_passed_claim: false,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: builders.proofs[&attestation_cid].clone(),
                };
                assert_eq!(
                    engine.submit_build_attestation(
                        &review_round_id,
                        false_claim,
                        GovernanceClock {
                            block: 20,
                            epoch: 2,
                        },
                    ),
                    Err(GovernanceError::InvalidAttestation)
                );
            }
            engine
                .submit_build_attestation(
                    &review_round_id,
                    BuildAttestationInputV1 {
                        attestation_cid: attestation_cid.clone(),
                        attestation_car: package.car_bytes.clone(),
                        candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                        builder_address: package.value.builder_identity.clone(),
                        runtime_family: package.value.runtime_family.clone(),
                        architecture: package.value.architecture.clone(),
                        core_artifact_digest: package.value.core_artifact_digest.clone(),
                        test_result_cid: package.value.test_results_cid.clone(),
                        tests_passed_claim: package.value.tests_passed,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: builders.proofs[&attestation_cid].clone(),
                    },
                    GovernanceClock {
                        block: 20,
                        epoch: 2,
                    },
                )
                .unwrap();
        }
        for package in &availability_packages {
            let attestation_cid = package.root_cid.to_string();
            if package.root_cid == availability_packages[0].root_cid {
                let false_claim = DataAvailabilityAttestationInputV1 {
                    attestation_cid: attestation_cid.clone(),
                    attestation_car: package.car_bytes.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    provider_id: package.value.provider_id.clone(),
                    operator_address: package.value.operator_identity.clone(),
                    pinset_cid: package.value.pinset_cid.clone(),
                    verified_cids: package.value.verified_cids.clone(),
                    probe_result_cid: package.value.probe_result_cid.clone(),
                    available_claim: false,
                    expires_at_block: package.value.expires_at_block,
                    bond_atoms: 1_000_000_000_000_000_000,
                    commitment_proof: availability.proofs[&attestation_cid].clone(),
                };
                assert_eq!(
                    engine.submit_data_availability_attestation(
                        &review_round_id,
                        false_claim,
                        GovernanceClock {
                            block: 20,
                            epoch: 2,
                        },
                    ),
                    Err(GovernanceError::InvalidAttestation)
                );
            }
            engine
                .submit_data_availability_attestation(
                    &review_round_id,
                    DataAvailabilityAttestationInputV1 {
                        attestation_cid: attestation_cid.clone(),
                        attestation_car: package.car_bytes.clone(),
                        candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                        provider_id: package.value.provider_id.clone(),
                        operator_address: package.value.operator_identity.clone(),
                        pinset_cid: package.value.pinset_cid.clone(),
                        verified_cids: package.value.verified_cids.clone(),
                        probe_result_cid: package.value.probe_result_cid.clone(),
                        available_claim: package.value.available,
                        expires_at_block: package.value.expires_at_block,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: availability.proofs[&attestation_cid].clone(),
                    },
                    GovernanceClock {
                        block: 20,
                        epoch: 2,
                    },
                )
                .unwrap();
        }
        let frozen = engine
            .freeze_review_round(
                &review_round_id,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(
            frozen.agent_review_root.as_deref(),
            Some(agents.root.as_str())
        );
        assert_eq!(
            frozen.build_attestation_root.as_deref(),
            Some(builders.root.as_str())
        );
        assert_eq!(
            frozen.data_availability_root.as_deref(),
            Some(availability.root.as_str())
        );
        let mut content = proposal_content(&address(1), &agents, &builders, &availability);
        content.review_round_id = review_round_id;
        let proposal_id = engine
            .create_proposal_draft(
                content.clone(),
                0,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            )
            .unwrap();
        engine
            .open_review(
                &proposal_id,
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            )
            .unwrap();
        engine
            .open_voting(
                &proposal_id,
                GovernanceClock {
                    block: 90,
                    epoch: 2,
                },
            )
            .unwrap();
        for index in 1..=12 {
            engine
                .cast_vote(
                    &proposal_id,
                    &address(index),
                    VoteChoice::Yes,
                    GovernanceClock {
                        block: 100,
                        epoch: 2,
                    },
                )
                .unwrap();
        }
        let gates = engine
            .finalize_voting(
                &proposal_id,
                GovernanceClock {
                    block: 220,
                    epoch: 2,
                },
            )
            .unwrap();
        assert!(gates.accepted);
        assert_eq!(engine.proposal(&proposal_id).unwrap().challenge_end, 280);
        assert_eq!(
            engine.close_challenge_period(
                &proposal_id,
                GovernanceClock {
                    block: 270,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidDeadline)
        );
        engine
            .close_challenge_period(
                &proposal_id,
                GovernanceClock {
                    block: 280,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(
            engine.execute_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 339,
                    epoch: 2
                }
            ),
            Err(GovernanceError::InvalidDeadline)
        );
        engine
            .execute_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 340,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(
            engine.canonical_ecosystem_cid(),
            content.candidate_ecosystem_cid
        );
        assert_eq!(
            engine.execute_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 341,
                    epoch: 2
                }
            ),
            Err(GovernanceError::InvalidState(ProposalState::Executed))
        );
        let first_refund = engine.withdraw_refund(&address(1)).unwrap();
        assert!(first_refund > content.proposal_bond_atoms);
        assert_eq!(
            engine.withdraw_refund(&address(1)),
            Err(GovernanceError::NoRefund)
        );
    }

    #[test]
    fn proposal_content_accepts_only_portable_content_cid_profiles() {
        let entries = vec![AttestationCommitmentEntryV1 {
            attestation_cid: cid("attestation"),
            canonical_fields: agent_attestation_commitment_fields(
                &cid("attestation"),
                "family-a",
                &address(1),
                0,
            )
            .unwrap(),
        }];
        let commitment =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &entries).unwrap();
        let mut content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        content.rationale_cid = raw_cid("rationale-text");
        validate_proposal_content(
            &content,
            &GovernanceParameterSetV1::experimental_defaults(),
            GovernanceClock {
                block: 50,
                epoch: 2,
            },
        )
        .unwrap();

        content.rationale_cid = cid_for(0x70, b"unsupported-codec").to_string();
        assert!(matches!(
            validate_proposal_content(
                &content,
                &GovernanceParameterSetV1::experimental_defaults(),
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidContentAddress(_))
        ));
    }

    #[test]
    fn only_migration_execution_can_rotate_identity_metrics() {
        let (mut engine, snapshot) = setup_engine();
        engine
            .register_identity_metrics(&address(1), snapshot.proofs[&address(1)].clone())
            .unwrap();
        let entries = vec![AttestationCommitmentEntryV1 {
            attestation_cid: cid("attestation"),
            canonical_fields: agent_attestation_commitment_fields(
                &cid("attestation"),
                "family-a",
                &address(1),
                0,
            )
            .unwrap(),
        }];
        let commitment =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &entries).unwrap();
        let mut content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        content.candidate_identity_metrics_root = Some("44".repeat(32));
        content.candidate_identity_metrics_epoch = Some(3);
        assert_eq!(
            validate_proposal_content(
                &content,
                &GovernanceParameterSetV1::experimental_defaults(),
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidProposal)
        );

        content.risk_class = RiskClass::Migration;
        validate_proposal_content(
            &content,
            &GovernanceParameterSetV1::experimental_defaults(),
            GovernanceClock {
                block: 50,
                epoch: 2,
            },
        )
        .unwrap();
        let proposal_id = insert_test_proposal(
            &mut engine,
            content,
            ProposalState::AcceptedPendingExecution,
        );
        engine
            .execute_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 330,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(engine.metrics_root, "44".repeat(32));
        assert_eq!(engine.metrics_epoch, 3);
        assert!(engine.registered_metrics.is_empty());
    }

    #[test]
    fn raw_result_challenge_is_reachable_and_deadline_is_half_open() {
        let (mut engine, snapshot) = setup_engine();
        engine
            .register_identity_metrics(&address(1), snapshot.proofs[&address(1)].clone())
            .unwrap();
        let entries = vec![AttestationCommitmentEntryV1 {
            attestation_cid: cid("attestation"),
            canonical_fields: agent_attestation_commitment_fields(
                &cid("attestation"),
                "family-a",
                &address(1),
                1,
            )
            .unwrap(),
        }];
        let commitment =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &entries).unwrap();
        let content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        let proposal_id = insert_test_proposal(
            &mut engine,
            content,
            ProposalState::AcceptedPendingChallenge,
        );
        let evidence_bytes = br#"{"passed":false}"#.to_vec();
        let evidence_cid = cid_for(RAW_CODEC, &evidence_bytes).to_string();
        let attestation_cid = cid("attestation");
        let attestation = BondedAgentAttestation {
            input: AgentAttestationInputV1 {
                attestation_cid: attestation_cid.clone(),
                attestation_car: Vec::new(),
                parent_ecosystem_cid: cid("initial-ecosystem"),
                candidate_ecosystem_cid: cid("candidate-ecosystem"),
                patch_cid: cid("patch"),
                owner_address: address(2),
                model_identifier: "model-a".to_string(),
                model_revision: None,
                runtime_identifier: "runtime-a".to_string(),
                independence_group: "family-a".to_string(),
                verdict: AttestationVerdict::Approve,
                unresolved_critical_findings: 0,
                test_result_cid: evidence_cid.clone(),
                tests_passed_claim: true,
                bond_atoms: 1_000_000_000_000_000_000,
                commitment_proof: commitment.proofs[&attestation_cid].clone(),
            },
            settled: false,
        };
        {
            let proposal = engine.proposals.get_mut(&proposal_id).unwrap();
            proposal.agents.insert(attestation_cid.clone(), attestation);
            assert_eq!(
                acceptance_evidence(proposal).unresolved_critical_findings,
                0
            );
        }
        engine.stakes.insert(
            address(1),
            StakePosition {
                active_atoms: 10_000_000_000_000_000_000,
                ..StakePosition::default()
            },
        );
        engine.stakes.insert(
            address(2),
            StakePosition {
                active_atoms: 10_000_000_000_000_000_000,
                ..StakePosition::default()
            },
        );
        let proposer_stake = engine.stake_position(&address(1), 2).unwrap().active_atoms;
        let offender_stake = engine.stake_position(&address(2), 2).unwrap().active_atoms;
        let challenge = ObjectiveChallengeInputV1 {
            challenger_address: address(3),
            target: ObjectiveChallengeTarget::AgentTestResult,
            attestation_cid,
            evidence_cid,
            evidence_bytes,
        };
        assert_eq!(
            engine.submit_objective_challenge(
                &proposal_id,
                challenge.clone(),
                GovernanceClock {
                    block: 270,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidDeadline)
        );
        engine
            .submit_objective_challenge(
                &proposal_id,
                challenge,
                GovernanceClock {
                    block: 269,
                    epoch: 2,
                },
            )
            .unwrap();
        assert!(engine.resolve_objective_challenge(&proposal_id).unwrap());
        assert_eq!(
            engine.proposal(&proposal_id).unwrap().state,
            ProposalState::Rejected
        );
        assert_eq!(
            engine.stake_position(&address(1), 2).unwrap().active_atoms,
            proposer_stake
        );
        assert!(engine.stake_position(&address(2), 2).unwrap().active_atoms < offender_stake);
        assert_eq!(
            engine.withdraw_refund(&address(1)).unwrap(),
            9_000_000_000_000_000_000
        );
    }

    #[test]
    fn malformed_objective_challenge_is_side_effect_free() {
        let (mut engine, snapshot) = setup_engine();
        engine
            .register_identity_metrics(&address(1), snapshot.proofs[&address(1)].clone())
            .unwrap();
        let malformed = br#"{"passed": false}"#.to_vec();
        let evidence_cid = cid_for(RAW_CODEC, &malformed).to_string();
        let attestation_cid = cid("malformed-challenge-attestation");
        let entries = vec![AttestationCommitmentEntryV1 {
            attestation_cid: attestation_cid.clone(),
            canonical_fields: agent_attestation_commitment_fields(
                &attestation_cid,
                "family-a",
                &address(2),
                0,
            )
            .unwrap(),
        }];
        let commitment =
            build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &entries).unwrap();
        let content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        let proposal_id = insert_test_proposal(
            &mut engine,
            content,
            ProposalState::AcceptedPendingChallenge,
        );
        engine
            .proposals
            .get_mut(&proposal_id)
            .unwrap()
            .agents
            .insert(
                attestation_cid.clone(),
                BondedAgentAttestation {
                    input: AgentAttestationInputV1 {
                        attestation_cid: attestation_cid.clone(),
                        attestation_car: Vec::new(),
                        parent_ecosystem_cid: cid("initial-ecosystem"),
                        candidate_ecosystem_cid: cid("candidate-ecosystem"),
                        patch_cid: cid("patch"),
                        owner_address: address(2),
                        model_identifier: "model-a".to_string(),
                        model_revision: None,
                        runtime_identifier: "runtime-a".to_string(),
                        independence_group: "family-a".to_string(),
                        verdict: AttestationVerdict::Approve,
                        unresolved_critical_findings: 0,
                        test_result_cid: evidence_cid.clone(),
                        tests_passed_claim: true,
                        bond_atoms: 1_000_000_000_000_000_000,
                        commitment_proof: commitment.proofs[&attestation_cid].clone(),
                    },
                    settled: false,
                },
            );
        assert_eq!(
            engine.submit_objective_challenge(
                &proposal_id,
                ObjectiveChallengeInputV1 {
                    challenger_address: address(3),
                    target: ObjectiveChallengeTarget::AgentTestResult,
                    attestation_cid,
                    evidence_cid,
                    evidence_bytes: malformed,
                },
                GovernanceClock {
                    block: 269,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidChallenge)
        );
        let proposal = engine.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.state, ProposalState::AcceptedPendingChallenge);
        assert!(proposal.pending_challenge.is_none());
    }

    #[test]
    fn normal_risk_is_rejected_until_objective_classification_exists() {
        let commitment = build_attestation_commitment(
            AGENT_REVIEW_COMMITMENT_DOMAIN,
            &[AttestationCommitmentEntryV1 {
                attestation_cid: cid("normal-risk-attestation"),
                canonical_fields: "fields".to_string(),
            }],
        )
        .unwrap();
        let mut content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        content.risk_class = RiskClass::Normal;
        assert_eq!(
            validate_proposal_content(
                &content,
                &GovernanceParameterSetV1::experimental_defaults(),
                GovernanceClock {
                    block: 50,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidProposal)
        );
    }

    #[test]
    fn review_open_expiration_uses_voting_end_not_voting_start() {
        let (mut engine, _) = setup_engine();
        let commitment = build_attestation_commitment(
            AGENT_REVIEW_COMMITMENT_DOMAIN,
            &[AttestationCommitmentEntryV1 {
                attestation_cid: cid("expiry-attestation"),
                canonical_fields: "fields".to_string(),
            }],
        )
        .unwrap();
        let content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        let proposal_id = insert_test_proposal(&mut engine, content, ProposalState::ReviewOpen);
        assert_eq!(
            engine.expire_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 90,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::InvalidDeadline)
        );
        engine
            .expire_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 210,
                    epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(
            engine.proposal(&proposal_id).unwrap().state,
            ProposalState::Expired
        );
    }

    #[test]
    fn failed_vote_update_restores_the_previous_receipt_and_totals() {
        let (mut engine, _) = setup_engine();
        let commitment = build_attestation_commitment(
            AGENT_REVIEW_COMMITMENT_DOMAIN,
            &[AttestationCommitmentEntryV1 {
                attestation_cid: cid("vote-rollback-attestation"),
                canonical_fields: "fields".to_string(),
            }],
        )
        .unwrap();
        let content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        let proposal_id = insert_test_proposal(&mut engine, content, ProposalState::VotingOpen);
        let voter = address(1);
        let previous = GovernanceVoteReceiptV1 {
            schema_version: 1,
            proposal_id: proposal_id.clone(),
            voter_address: voter.clone(),
            choice: VoteChoice::No,
            staking_epoch: 2,
            identity_metrics_epoch: 2,
            active_stake_atoms: 1_000_000_000_000,
            stake_score: 1,
            identity_status_bps: 10_000,
            flip_trust_bps: 10_000,
            effective_vote_weight: 1,
            cast_at_block: 99,
        };
        {
            let proposal = engine.proposals.get_mut(&proposal_id).unwrap();
            proposal.voter_snapshot.insert(
                voter.clone(),
                VoterSnapshot {
                    stake_atoms: previous.active_stake_atoms,
                    status_bps: previous.identity_status_bps,
                    state: IdentityState::Human,
                    trust_bps: previous.flip_trust_bps,
                    weight: previous.effective_vote_weight,
                },
            );
            proposal.votes.insert(voter.clone(), previous.clone());
            proposal.no_weight = previous.effective_vote_weight;
            proposal.yes_weight = u128::MAX;
        }

        assert_eq!(
            engine.cast_vote(
                &proposal_id,
                &voter,
                VoteChoice::Yes,
                GovernanceClock {
                    block: 100,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::Overflow)
        );
        let proposal = engine.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.yes_weight, u128::MAX);
        assert_eq!(proposal.no_weight, previous.effective_vote_weight);
        assert_eq!(proposal.votes.get(&voter), Some(&previous));
    }

    #[test]
    fn failed_execution_restores_canonical_state_and_bond_accounting() {
        let (mut engine, _) = setup_engine();
        let commitment = build_attestation_commitment(
            AGENT_REVIEW_COMMITMENT_DOMAIN,
            &[AttestationCommitmentEntryV1 {
                attestation_cid: cid("execution-rollback-attestation"),
                canonical_fields: "fields".to_string(),
            }],
        )
        .unwrap();
        let content = proposal_content(&address(1), &commitment, &commitment, &commitment);
        let proposer = content.proposer_address.clone();
        let initial_canonical = engine.canonical_ecosystem_cid.clone();
        let proposal_id = insert_test_proposal(
            &mut engine,
            content,
            ProposalState::AcceptedPendingExecution,
        );
        engine.refunds.insert(proposer.clone(), u128::MAX);

        assert_eq!(
            engine.execute_proposal(
                &proposal_id,
                GovernanceClock {
                    block: 330,
                    epoch: 2,
                },
            ),
            Err(GovernanceError::Overflow)
        );
        assert_eq!(engine.canonical_ecosystem_cid, initial_canonical);
        assert_eq!(engine.refunds.get(&proposer), Some(&u128::MAX));
        assert!(engine.events.is_empty());
        let proposal = engine.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.state, ProposalState::AcceptedPendingExecution);
        assert!(!proposal.proposal_bond_settled);
    }
}
