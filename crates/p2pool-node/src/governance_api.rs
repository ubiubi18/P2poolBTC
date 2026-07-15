use anyhow::{bail, Context, Result};
use cid::{Cid, Version};
use governance_core::{
    evaluate_gates, frozen_proposal_set_root, package_development_policy, AcceptanceEvidence,
    DevelopmentPolicyBundleV1, EpochGateParametersV1, EpochGovernanceParameterSetV1,
    GateParameterSet, RiskClass,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MAX_GOVERNANCE_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GOVERNANCE_PROPOSALS: usize = 256;
const MAX_GOVERNANCE_REPOSITORIES: usize = 64;
const MAX_AFFECTED_REPOSITORIES: usize = 16;
const MAX_GATE_ATTESTATIONS: u32 = 256;
const MAX_CANONICAL_HISTORY_ENTRIES: usize = 1_024;
const EXPERIMENTAL_LABEL: &str = "EXPERIMENTAL / NO-VALUE / NOT DAO-DEPLOYED";
const EXPECTED_GOVERNANCE_PARAMETER_SET_CID: &str =
    "bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceDashboardResponseV1 {
    pub api_version: String,
    pub schema_version: u16,
    pub experimental: bool,
    pub status: String,
    pub safety_label: String,
    pub governance_contract_address: Option<String>,
    pub current_canonical_ecosystem_cid: Option<String>,
    #[serde(default)]
    pub development_policy_cid: Option<String>,
    #[serde(default)]
    pub development_policy: Option<DevelopmentPolicyBundleV1>,
    pub identity_metrics: Option<GovernanceIdentityMetricsCertificationV1>,
    pub repositories: Vec<GovernanceRepositoryViewV1>,
    pub proposals: Vec<GovernanceProposalViewV1>,
    #[serde(default)]
    pub epoch_governance: Option<GovernanceEpochViewV1>,
    #[serde(default)]
    pub canonical_history: Vec<GovernanceCanonicalExecutionViewV1>,
    #[serde(default)]
    pub recovery: Option<GovernanceRecoveryViewV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceEpochViewV1 {
    pub governance_epoch: u64,
    pub current_block: u64,
    pub phase: String,
    pub schedule: GovernanceScheduleViewV1,
    pub frozen_proposal_set_root: Option<String>,
    pub ordered_proposal_ids: Vec<String>,
    pub frozen_at_block: Option<u64>,
    pub reviewed_proposals: u32,
    pub unresolved_proposals: u32,
    pub valid_agent_attestations: u32,
    pub committed_ballots: u32,
    pub revealed_ballots: u32,
    pub voting_power_snapshot_ready: bool,
    pub grace_end_block: Option<u64>,
    pub open_challenges: u32,
    pub execution_ready_proposals: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceScheduleViewV1 {
    pub epoch_anchor_block: u64,
    pub proposal_cutoff_block: u64,
    pub commit_start_block: u64,
    pub commit_end_block: u64,
    pub reveal_end_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceCanonicalExecutionViewV1 {
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
pub struct GovernanceRecoveryViewV1 {
    pub chain_rpc_available: bool,
    pub local_last_known_good_staged: bool,
    pub staged_ecosystem_cid: Option<String>,
    pub recovery_manifest_cid: Option<String>,
    pub explicit_user_confirmation_required: bool,
    pub automatic_install_enabled: bool,
    pub automatic_rollback_enabled: bool,
    pub on_chain_revert_available: bool,
    pub warning: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceRepositoryViewV1 {
    pub name: String,
    pub source_tree_cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceIdentityMetricsCertificationV1 {
    pub metrics_root: String,
    pub source_epoch: u16,
    pub replay_commitment: String,
    pub independent_attestors: u32,
    pub required_attestors: u32,
    pub conflict: bool,
    pub certified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceProposalViewV1 {
    pub proposal_id: String,
    pub proposal_cid: String,
    pub scope_evidence_cid: String,
    pub scope_evidence_verified: bool,
    pub candidate_ecosystem_cid: String,
    pub parameter_set_cid: String,
    pub review_round_id: String,
    pub review_round_state: String,
    pub review_round_agent_attestations: u32,
    pub review_round_build_attestations: u32,
    pub review_round_availability_attestations: u32,
    pub affected_repositories: Vec<String>,
    pub changed_file_count: u32,
    pub patch_bytes: u64,
    pub source_package_bytes: u64,
    pub description_bytes: u32,
    pub migration_operation_count: u32,
    pub diff_summary: String,
    pub risk_class: String,
    pub bond_atoms: String,
    pub agent_review_root: String,
    pub build_attestation_root: String,
    pub data_availability_root: String,
    #[serde(default)]
    pub critical_finding_waiver_cid: Option<String>,
    #[serde(default)]
    pub critical_finding_waiver_verified: bool,
    pub ai_reviews: GovernanceReviewGateV1,
    pub builds: GovernanceBuildGateV1,
    pub data_availability: GovernanceAvailabilityGateV1,
    pub pos: GovernancePosGateV1,
    pub pohw: GovernancePohwGateV1,
    pub challenge_status: String,
    pub execution_status: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceReviewGateV1 {
    pub valid_attestations: u32,
    pub required_attestations: u32,
    pub distinct_model_families: u32,
    pub required_model_families: u32,
    pub distinct_owner_identities: u32,
    pub required_owner_identities: u32,
    pub unresolved_critical_findings: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceBuildGateV1 {
    pub independent_builders: u32,
    pub required_builders: u32,
    pub distinct_platforms: u32,
    pub required_platforms: u32,
    pub matching_core_artifact_digests: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceAvailabilityGateV1 {
    pub independent_attestors: u32,
    pub required_attestors: u32,
    pub valid_until_block: u64,
    pub required_valid_until_block: u64,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernancePosGateV1 {
    pub yes_weight: String,
    pub no_weight: String,
    pub abstain_weight: String,
    pub snapshotted_registered_weight: String,
    pub turnout_quorum_bps: u16,
    pub yes_threshold_bps: u16,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernancePohwGateV1 {
    pub distinct_participating_identities: u32,
    pub required_participating_identities: u32,
    pub distinct_yes_identities: u32,
    pub required_yes_identities: u32,
    pub verified_or_human_yes_identities: u32,
    pub required_verified_or_human_yes: u32,
    pub passed: bool,
}

pub fn load_dashboard(path: Option<&Path>) -> Result<GovernanceDashboardResponseV1> {
    let Some(path) = path else {
        return Ok(unconfigured());
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(unconfigured()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_GOVERNANCE_SNAPSHOT_BYTES
    {
        bail!("governance dashboard snapshot must be a small non-symlink regular file");
    }
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read governance snapshot {}", path.display()))?;
    let value: GovernanceDashboardResponseV1 =
        serde_json::from_slice(&bytes).context("governance dashboard snapshot is invalid JSON")?;
    validate_dashboard(&value)?;
    Ok(value)
}

fn unconfigured() -> GovernanceDashboardResponseV1 {
    GovernanceDashboardResponseV1 {
        api_version: "pohw-governance-dashboard-v1".to_string(),
        schema_version: 1,
        experimental: true,
        status: "unconfigured".to_string(),
        safety_label: EXPERIMENTAL_LABEL.to_string(),
        governance_contract_address: None,
        current_canonical_ecosystem_cid: None,
        development_policy_cid: None,
        development_policy: None,
        identity_metrics: None,
        repositories: vec![],
        proposals: vec![],
        epoch_governance: None,
        canonical_history: vec![],
        recovery: None,
    }
}

fn validate_dashboard(value: &GovernanceDashboardResponseV1) -> Result<()> {
    if value.api_version != "pohw-governance-dashboard-v1"
        || value.schema_version != 1
        || !value.experimental
        || value.status != "operator-validated-local-snapshot"
        || value.safety_label != EXPERIMENTAL_LABEL
    {
        bail!("governance dashboard header or safety label is invalid");
    }
    validate_address(
        value
            .governance_contract_address
            .as_deref()
            .context("configured governance snapshot has no contract address")?,
    )?;
    validate_object_cid(
        value
            .current_canonical_ecosystem_cid
            .as_deref()
            .context("configured governance snapshot has no canonical ecosystem CID")?,
    )?;
    let development_policy = value
        .development_policy
        .clone()
        .context("configured governance snapshot has no decentralized development policy")?;
    let declared_policy_cid = value
        .development_policy_cid
        .as_deref()
        .context("configured governance snapshot has no development policy CID")?;
    validate_object_cid(declared_policy_cid)?;
    let verified_policy = package_development_policy(development_policy)
        .context("configured governance development policy is invalid")?;
    if verified_policy.root_cid.to_string() != declared_policy_cid {
        bail!("configured governance development policy CID is not canonical");
    }
    let metrics = value
        .identity_metrics
        .as_ref()
        .context("configured governance snapshot has no identity metrics certification")?;
    validate_sha256(&metrics.metrics_root)?;
    validate_sha256(&metrics.replay_commitment)?;
    if metrics.required_attestors < 2
        || metrics.certified
            != (!metrics.conflict && metrics.independent_attestors >= metrics.required_attestors)
    {
        bail!("governance identity metrics certification is inconsistent");
    }
    if value.repositories.is_empty() || value.repositories.len() > MAX_GOVERNANCE_REPOSITORIES {
        bail!("configured governance snapshot has no repositories");
    }
    let mut previous_repository = None;
    for repository in &value.repositories {
        validate_label(&repository.name, 80)?;
        validate_object_cid(&repository.source_tree_cid)?;
        if previous_repository.is_some_and(|name: &str| name >= repository.name.as_str()) {
            bail!("governance repositories are not uniquely sorted");
        }
        previous_repository = Some(repository.name.as_str());
    }
    if value.proposals.len() > MAX_GOVERNANCE_PROPOSALS {
        bail!("governance snapshot exceeds the proposal limit");
    }
    let mut proposal_ids = BTreeSet::new();
    for proposal in &value.proposals {
        validate_sha256(&proposal.proposal_id)?;
        validate_object_cid(&proposal.proposal_cid)?;
        validate_object_cid(&proposal.scope_evidence_cid)?;
        if !proposal.scope_evidence_verified {
            bail!("proposal scope evidence was not verified against source and patch CARs");
        }
        validate_object_cid(&proposal.candidate_ecosystem_cid)?;
        validate_object_cid(&proposal.parameter_set_cid)?;
        if proposal.parameter_set_cid != EXPECTED_GOVERNANCE_PARAMETER_SET_CID {
            bail!("proposal parameter set does not match this dashboard build");
        }
        validate_sha256(&proposal.review_round_id)?;
        if !matches!(
            proposal.review_round_state.as_str(),
            "Open" | "Frozen" | "Claimed" | "Expired"
        ) || proposal.review_round_agent_attestations > 256
            || proposal.review_round_build_attestations > 256
            || proposal.review_round_availability_attestations > 256
        {
            bail!("proposal review round is invalid");
        }
        for digest in [
            &proposal.agent_review_root,
            &proposal.build_attestation_root,
            &proposal.data_availability_root,
        ] {
            validate_sha256(digest)?;
        }
        if !proposal_ids.insert(proposal.proposal_id.clone()) {
            bail!("duplicate governance proposal ID");
        }
        if !matches!(
            proposal.risk_class.as_str(),
            "normal" | "critical" | "consensus" | "migration"
        ) {
            bail!("proposal risk class is invalid");
        }
        let profile = EpochGovernanceParameterSetV1::experimental_defaults();
        let limits = if proposal.risk_class == "normal" {
            profile.normal_limits
        } else {
            profile.critical_limits
        };
        if proposal.affected_repositories.is_empty()
            || proposal.affected_repositories.len() > limits.max_affected_repositories as usize
            || proposal.affected_repositories.len() > MAX_AFFECTED_REPOSITORIES
            || !is_sorted_unique_labels(&proposal.affected_repositories)
            || proposal.changed_file_count == 0
            || proposal.changed_file_count > limits.max_changed_files
            || proposal.patch_bytes == 0
            || proposal.patch_bytes > limits.max_patch_bytes
            || proposal.source_package_bytes == 0
            || proposal.source_package_bytes > limits.max_source_package_bytes
            || proposal.description_bytes == 0
            || proposal.description_bytes > limits.max_description_bytes
            || proposal.migration_operation_count > limits.max_migration_operations
        {
            bail!("proposal scope exceeds its parameter-set limits");
        }
        validate_text(&proposal.diff_summary, 1, 4_096)?;
        let bond = parse_amount(&proposal.bond_atoms)?;
        let minimum_bond = if proposal.risk_class == "normal" {
            parse_amount(&profile.normal_proposal_bond_atoms)?
        } else {
            parse_amount(&profile.critical_proposal_bond_atoms)?
        };
        if bond < minimum_bond {
            bail!("proposal bond is below its locked risk-class minimum");
        }
        for amount in [
            &proposal.pos.yes_weight,
            &proposal.pos.no_weight,
            &proposal.pos.abstain_weight,
            &proposal.pos.snapshotted_registered_weight,
        ] {
            validate_amount(amount)?;
        }
        if proposal.pos.turnout_quorum_bps > 10_000
            || proposal.pos.yes_threshold_bps > 10_000
            || !matches!(
                proposal.state.as_str(),
                "Draft"
                    | "Submitted"
                    | "ReviewOpen"
                    | "VotingOpen"
                    | "ProposalSetFrozen"
                    | "VotingCommit"
                    | "VotingReveal"
                    | "AcceptedPendingChallenge"
                    | "AcceptedPendingGrace"
                    | "Rejected"
                    | "NoQuorum"
                    | "Challenged"
                    | "AcceptedPendingExecution"
                    | "Executed"
                    | "CancelledBeforeCutoff"
                    | "RevertProposed"
                    | "Reverted"
                    | "Stale"
                    | "Expired"
            )
        {
            bail!("proposal gate or state is invalid");
        }
        validate_text(&proposal.challenge_status, 1, 160)?;
        validate_text(&proposal.execution_status, 1, 160)?;
        validate_proposal_gates(proposal)?;
    }
    validate_epoch_governance(value.epoch_governance.as_ref(), &proposal_ids)?;
    validate_canonical_history(value)?;
    validate_recovery(value.recovery.as_ref())?;
    Ok(())
}

fn validate_epoch_governance(
    epoch: Option<&GovernanceEpochViewV1>,
    proposal_ids: &BTreeSet<String>,
) -> Result<()> {
    let Some(epoch) = epoch else {
        return Ok(());
    };
    let schedule = &epoch.schedule;
    if !(schedule.epoch_anchor_block < schedule.proposal_cutoff_block
        && schedule.proposal_cutoff_block < schedule.commit_start_block
        && schedule.commit_start_block < schedule.commit_end_block
        && schedule.commit_end_block < schedule.reveal_end_block)
    {
        bail!("governance epoch schedule is not strictly ordered");
    }
    if !matches!(
        epoch.phase.as_str(),
        "ProposalSubmission"
            | "FrozenReview"
            | "VotingCommit"
            | "VotingReveal"
            | "Finalization"
            | "Grace"
            | "Execution"
            | "Closed"
    ) {
        bail!("governance epoch phase is invalid");
    }
    let expected_window_phase = if epoch.current_block < schedule.proposal_cutoff_block {
        Some("ProposalSubmission")
    } else if epoch.current_block < schedule.commit_start_block {
        Some("FrozenReview")
    } else if epoch.current_block < schedule.commit_end_block {
        Some("VotingCommit")
    } else if epoch.current_block < schedule.reveal_end_block {
        Some("VotingReveal")
    } else {
        None
    };
    if expected_window_phase.is_some_and(|expected| expected != epoch.phase) {
        bail!("governance epoch phase does not match its chain block window");
    }
    if epoch.reviewed_proposals as usize > epoch.ordered_proposal_ids.len()
        || epoch.unresolved_proposals as usize > epoch.ordered_proposal_ids.len()
        || epoch.reviewed_proposals as usize + epoch.unresolved_proposals as usize
            > epoch.ordered_proposal_ids.len()
        || epoch.valid_agent_attestations > MAX_GATE_ATTESTATIONS.saturating_mul(64)
        || epoch.revealed_ballots > epoch.committed_ballots
        || epoch.open_challenges > MAX_GOVERNANCE_PROPOSALS as u32
        || epoch.execution_ready_proposals > MAX_GOVERNANCE_PROPOSALS as u32
    {
        bail!("governance epoch counters are inconsistent");
    }
    if epoch.ordered_proposal_ids.len() > MAX_GOVERNANCE_PROPOSALS
        || !is_sorted_unique_sha256(&epoch.ordered_proposal_ids)
        || epoch
            .ordered_proposal_ids
            .iter()
            .any(|proposal_id| !proposal_ids.contains(proposal_id))
    {
        bail!("frozen governance proposal set is invalid");
    }
    match (
        epoch.frozen_proposal_set_root.as_deref(),
        epoch.frozen_at_block,
    ) {
        (None, None) if epoch.ordered_proposal_ids.is_empty() => {
            if epoch.current_block >= schedule.proposal_cutoff_block {
                bail!("governance proposal set was not frozen at cutoff");
            }
        }
        (Some(root), Some(frozen_at)) => {
            validate_sha256(root)?;
            let expected_root =
                frozen_proposal_set_root(epoch.governance_epoch, &epoch.ordered_proposal_ids)
                    .context("could not derive the canonical frozen proposal-set root")?;
            if root != expected_root {
                bail!("frozen governance proposal-set root does not bind its ordered IDs");
            }
            if frozen_at < schedule.proposal_cutoff_block
                || frozen_at >= schedule.commit_start_block
                || epoch.ordered_proposal_ids.is_empty()
            {
                bail!("governance proposal set freeze metadata is invalid");
            }
        }
        _ => bail!("governance proposal set freeze metadata is incomplete"),
    }
    if epoch.phase == "Grace" && epoch.grace_end_block.is_none()
        || epoch
            .grace_end_block
            .is_some_and(|block| block <= schedule.reveal_end_block)
    {
        bail!("governance grace-period metadata is invalid");
    }
    Ok(())
}

fn validate_canonical_history(value: &GovernanceDashboardResponseV1) -> Result<()> {
    if value.canonical_history.len() > MAX_CANONICAL_HISTORY_ENTRIES {
        bail!("canonical governance history exceeds the display limit");
    }
    let mut execution_ids = BTreeSet::new();
    let mut previous_execution_block = None;
    let mut expected_previous_cid = None;
    for entry in &value.canonical_history {
        validate_sha256(&entry.execution_id)?;
        validate_sha256(&entry.proposal_id)?;
        validate_object_cid(&entry.previous_canonical_ecosystem_cid)?;
        validate_object_cid(&entry.new_canonical_ecosystem_cid)?;
        validate_content_cid(&entry.decision_record_cid)?;
        validate_content_cid(&entry.rollback_manifest_cid)?;
        validate_content_cid(&entry.release_rollback_instructions_cid)?;
        if !execution_ids.insert(entry.execution_id.as_str())
            || previous_execution_block.is_some_and(|block| block >= entry.execution_block)
            || expected_previous_cid
                .is_some_and(|cid: &str| cid != entry.previous_canonical_ecosystem_cid)
            || entry.previous_canonical_ecosystem_cid == entry.new_canonical_ecosystem_cid
            || entry.observation_window_end_block < entry.execution_block
        {
            bail!("canonical governance history is not append-only and continuous");
        }
        if let Some(reverted_execution) = entry.reverts_execution_id.as_deref() {
            validate_sha256(reverted_execution)?;
            if !execution_ids.contains(reverted_execution)
                || reverted_execution == entry.execution_id
            {
                bail!("canonical governance revert does not reference prior history");
            }
        }
        previous_execution_block = Some(entry.execution_block);
        expected_previous_cid = Some(entry.new_canonical_ecosystem_cid.as_str());
    }
    if let (Some(canonical), Some(last)) = (
        value.current_canonical_ecosystem_cid.as_deref(),
        value.canonical_history.last(),
    ) {
        if canonical != last.new_canonical_ecosystem_cid {
            bail!("canonical governance history tip does not match the current CID");
        }
    }
    Ok(())
}

fn validate_recovery(recovery: Option<&GovernanceRecoveryViewV1>) -> Result<()> {
    let Some(recovery) = recovery else {
        return Ok(());
    };
    if recovery.automatic_install_enabled
        || recovery.automatic_rollback_enabled
        || !recovery.explicit_user_confirmation_required
        || recovery.on_chain_revert_available && !recovery.chain_rpc_available
    {
        bail!("governance recovery state would imply an unsafe automatic action");
    }
    if let Some(cid) = recovery.staged_ecosystem_cid.as_deref() {
        validate_object_cid(cid)?;
    }
    if let Some(cid) = recovery.recovery_manifest_cid.as_deref() {
        validate_object_cid(cid)?;
    }
    if recovery.local_last_known_good_staged
        != (recovery.staged_ecosystem_cid.is_some() && recovery.recovery_manifest_cid.is_some())
    {
        bail!("governance recovery staging metadata is inconsistent");
    }
    validate_text(&recovery.warning, 1, 512)?;
    Ok(())
}

fn validate_proposal_gates(proposal: &GovernanceProposalViewV1) -> Result<()> {
    let counts = [
        proposal.ai_reviews.valid_attestations,
        proposal.ai_reviews.required_attestations,
        proposal.ai_reviews.distinct_model_families,
        proposal.ai_reviews.required_model_families,
        proposal.ai_reviews.distinct_owner_identities,
        proposal.ai_reviews.required_owner_identities,
        proposal.ai_reviews.unresolved_critical_findings,
        proposal.builds.independent_builders,
        proposal.builds.required_builders,
        proposal.builds.distinct_platforms,
        proposal.builds.required_platforms,
        proposal.data_availability.independent_attestors,
        proposal.data_availability.required_attestors,
        proposal.pohw.distinct_participating_identities,
        proposal.pohw.required_participating_identities,
        proposal.pohw.distinct_yes_identities,
        proposal.pohw.required_yes_identities,
        proposal.pohw.verified_or_human_yes_identities,
        proposal.pohw.required_verified_or_human_yes,
    ];
    if counts.iter().any(|count| *count > MAX_GATE_ATTESTATIONS)
        || proposal.ai_reviews.required_attestations == 0
        || proposal.ai_reviews.required_model_families == 0
        || proposal.ai_reviews.required_owner_identities == 0
        || proposal.builds.required_builders == 0
        || proposal.builds.required_platforms == 0
        || proposal.data_availability.required_attestors == 0
        || proposal.pohw.required_participating_identities == 0
        || proposal.pohw.required_yes_identities == 0
        || proposal.ai_reviews.distinct_model_families > proposal.ai_reviews.valid_attestations
        || proposal.ai_reviews.distinct_owner_identities > proposal.ai_reviews.valid_attestations
        || proposal.builds.distinct_platforms > proposal.builds.independent_builders
        || proposal.ai_reviews.valid_attestations > proposal.review_round_agent_attestations
        || proposal.builds.independent_builders > proposal.review_round_build_attestations
        || proposal.data_availability.independent_attestors
            > proposal.review_round_availability_attestations
        || proposal.pohw.distinct_yes_identities > proposal.pohw.distinct_participating_identities
        || proposal.pohw.verified_or_human_yes_identities > proposal.pohw.distinct_yes_identities
        || proposal.pohw.required_yes_identities > proposal.pohw.required_participating_identities
        || proposal.pohw.required_verified_or_human_yes > proposal.pohw.required_yes_identities
    {
        bail!("proposal gate evidence is inconsistent");
    }

    let yes_weight = parse_amount(&proposal.pos.yes_weight)?;
    let no_weight = parse_amount(&proposal.pos.no_weight)?;
    let abstain_weight = parse_amount(&proposal.pos.abstain_weight)?;
    let registered_weight = parse_amount(&proposal.pos.snapshotted_registered_weight)?;
    let turnout = yes_weight
        .checked_add(no_weight)
        .and_then(|value| value.checked_add(abstain_weight))
        .context("proposal vote totals overflow")?;
    if turnout > registered_weight {
        bail!("proposal turnout exceeds snapshotted registered weight");
    }

    let profile = EpochGovernanceParameterSetV1::experimental_defaults();
    let risk = match proposal.risk_class.as_str() {
        "normal" => RiskClass::Normal,
        "critical" => RiskClass::Critical,
        "consensus" => RiskClass::Consensus,
        "migration" => RiskClass::Migration,
        _ => bail!("proposal risk class is invalid"),
    };
    let valid_critical_finding_waiver = match (
        proposal.critical_finding_waiver_cid.as_deref(),
        proposal.critical_finding_waiver_verified,
    ) {
        (None, false) => false,
        (Some(cid), true) => {
            if !risk.is_critical() {
                bail!("normal proposals cannot carry a critical-finding waiver");
            }
            validate_object_cid(cid)
                .context("critical-finding waiver CID is not a canonical immutable object")?;
            true
        }
        _ => bail!("critical-finding waiver CID and verification state are incomplete"),
    };
    let evidence = AcceptanceEvidence {
        yes_weight,
        no_weight,
        abstain_weight,
        total_registered_weight: registered_weight,
        distinct_yes_identities: proposal.pohw.distinct_yes_identities,
        verified_or_human_yes_identities: proposal.pohw.verified_or_human_yes_identities,
        valid_agent_attestations: proposal.ai_reviews.valid_attestations,
        distinct_agent_families: proposal.ai_reviews.distinct_model_families,
        distinct_agent_owner_identities: proposal.ai_reviews.distinct_owner_identities,
        unresolved_critical_findings: if valid_critical_finding_waiver {
            0
        } else {
            proposal.ai_reviews.unresolved_critical_findings
        },
        valid_builders: proposal.builds.independent_builders,
        distinct_builder_platforms: proposal.builds.distinct_platforms,
        matching_core_artifact_digests: proposal.builds.matching_core_artifact_digests,
        independent_data_availability_providers: proposal.data_availability.independent_attestors,
    };
    let expected = if risk.is_critical() {
        profile.critical
    } else {
        profile.normal
    };
    if proposal.pos.turnout_quorum_bps != expected.turnout_quorum_bps
        || proposal.pos.yes_threshold_bps != expected.yes_threshold_bps
        || proposal.pohw.required_participating_identities
            != expected.minimum_participating_identities
        || proposal.pohw.required_yes_identities != expected.minimum_yes_identities
        || proposal.pohw.required_verified_or_human_yes != expected.minimum_verified_or_human_yes
        || proposal.ai_reviews.required_attestations != expected.minimum_ai_attestations
        || proposal.ai_reviews.required_model_families != expected.minimum_ai_families
        || proposal.ai_reviews.required_owner_identities != expected.minimum_ai_independence_groups
        || proposal.builds.required_builders != expected.minimum_builders
        || proposal.builds.required_platforms != expected.minimum_builder_platforms
        || proposal.data_availability.required_attestors
            != expected.minimum_data_availability_providers
    {
        bail!("proposal declares gate minima that differ from its parameter-set profile");
    }
    let normal = acceptance_parameters(profile.normal);
    let critical = acceptance_parameters(profile.critical);
    let recomputed = evaluate_gates(risk, &normal, &critical, &evidence);
    let participant_quorum_passed = proposal.pohw.distinct_participating_identities
        >= expected.minimum_participating_identities;
    let pohw_passed = recomputed.pohw.passed && participant_quorum_passed;
    let availability_fresh = proposal.data_availability.required_valid_until_block > 0
        && proposal.data_availability.valid_until_block
            >= proposal.data_availability.required_valid_until_block;
    if proposal.pos.passed != recomputed.pos.passed
        || proposal.pohw.passed != pohw_passed
        || proposal.ai_reviews.passed != recomputed.poaw.passed
        || proposal.builds.passed != recomputed.verification_work.passed
        || proposal.data_availability.passed
            != (recomputed.data_availability.passed && availability_fresh)
    {
        bail!("proposal gate result does not match its evidence");
    }
    if matches!(
        proposal.state.as_str(),
        "AcceptedPendingChallenge"
            | "AcceptedPendingGrace"
            | "Challenged"
            | "AcceptedPendingExecution"
            | "Executed"
            | "Reverted"
    ) && !(recomputed.accepted && participant_quorum_passed && availability_fresh)
    {
        bail!("accepted proposal state does not satisfy every gate");
    }
    Ok(())
}

fn acceptance_parameters(parameters: EpochGateParametersV1) -> GateParameterSet {
    GateParameterSet {
        turnout_quorum_bps: parameters.turnout_quorum_bps,
        yes_threshold_bps: parameters.yes_threshold_bps,
        minimum_yes_identities: parameters.minimum_yes_identities,
        minimum_verified_or_human_yes: parameters.minimum_verified_or_human_yes,
        minimum_agent_attestations: parameters.minimum_ai_attestations,
        minimum_agent_families: parameters.minimum_ai_families,
        minimum_agent_owners: parameters.minimum_ai_independence_groups,
        minimum_builders: parameters.minimum_builders,
        minimum_builder_platforms: parameters.minimum_builder_platforms,
        minimum_data_availability_providers: parameters.minimum_data_availability_providers,
    }
}

fn validate_object_cid(value: &str) -> Result<()> {
    let cid: Cid = value.parse().context("invalid governance CID")?;
    if cid.version() != Version::V1
        || cid.codec() != 0x71
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        bail!("governance CID does not use canonical CIDv1/DAG-CBOR/SHA2-256");
    }
    Ok(())
}

fn validate_content_cid(value: &str) -> Result<()> {
    let cid: Cid = value.parse().context("invalid governance content CID")?;
    if cid.version() != Version::V1
        || !matches!(cid.codec(), 0x55 | 0x71)
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        bail!("governance content CID does not use canonical CIDv1/SHA2-256");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("governance digest is not canonical SHA-256");
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<()> {
    if value.len() != 42
        || !value.starts_with("0x")
        || value[2..]
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("governance contract address is invalid");
    }
    Ok(())
}

fn validate_amount(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 39
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || value.parse::<u128>().is_err()
    {
        bail!("governance amount is not a canonical u128 decimal string");
    }
    Ok(())
}

fn parse_amount(value: &str) -> Result<u128> {
    validate_amount(value)?;
    value
        .parse::<u128>()
        .context("governance amount is outside the u128 range")
}

fn validate_label(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        bail!("governance label is invalid");
    }
    Ok(())
}

fn validate_text(value: &str, minimum: usize, maximum: usize) -> Result<()> {
    if value.len() < minimum || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("governance display text is invalid");
    }
    Ok(())
}

fn is_sorted_unique_labels(values: &[String]) -> bool {
    let mut previous = None;
    for value in values {
        if validate_label(value, 80).is_err()
            || previous.is_some_and(|item: &str| item >= value.as_str())
        {
            return false;
        }
        previous = Some(value.as_str());
    }
    true
}

fn is_sorted_unique_sha256(values: &[String]) -> bool {
    let mut previous = None;
    for value in values {
        if validate_sha256(value).is_err()
            || previous.is_some_and(|item: &str| item >= value.as_str())
        {
            return false;
        }
        previous = Some(value.as_str());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use governance_core::cid_for;

    fn cid(label: &str) -> String {
        cid_for(0x71, label.as_bytes()).to_string()
    }

    fn raw_cid(label: &str) -> String {
        cid_for(0x55, label.as_bytes()).to_string()
    }

    fn certified_metrics() -> GovernanceIdentityMetricsCertificationV1 {
        GovernanceIdentityMetricsCertificationV1 {
            metrics_root: "2".repeat(64),
            source_epoch: 1,
            replay_commitment: "3".repeat(64),
            independent_attestors: 3,
            required_attestors: 3,
            conflict: false,
            certified: true,
        }
    }

    fn passing_proposal() -> GovernanceProposalViewV1 {
        GovernanceProposalViewV1 {
            proposal_id: "4".repeat(64),
            proposal_cid: cid("proposal"),
            scope_evidence_cid: cid("scope-evidence"),
            scope_evidence_verified: true,
            candidate_ecosystem_cid: cid("candidate"),
            parameter_set_cid: EXPECTED_GOVERNANCE_PARAMETER_SET_CID.to_string(),
            review_round_id: "5".repeat(64),
            review_round_state: "Claimed".to_string(),
            review_round_agent_attestations: 3,
            review_round_build_attestations: 3,
            review_round_availability_attestations: 3,
            affected_repositories: vec!["P2poolBTC".to_string()],
            changed_file_count: 1,
            patch_bytes: 1_024,
            source_package_bytes: 4_096,
            description_bytes: 512,
            migration_operation_count: 0,
            diff_summary: "governance fixture".to_string(),
            risk_class: "critical".to_string(),
            bond_atoms: "25000000000000000000".to_string(),
            agent_review_root: "6".repeat(64),
            build_attestation_root: "7".repeat(64),
            data_availability_root: "8".repeat(64),
            critical_finding_waiver_cid: None,
            critical_finding_waiver_verified: false,
            ai_reviews: GovernanceReviewGateV1 {
                valid_attestations: 3,
                required_attestations: 3,
                distinct_model_families: 2,
                required_model_families: 2,
                distinct_owner_identities: 3,
                required_owner_identities: 3,
                unresolved_critical_findings: 0,
                passed: true,
            },
            builds: GovernanceBuildGateV1 {
                independent_builders: 3,
                required_builders: 3,
                distinct_platforms: 2,
                required_platforms: 2,
                matching_core_artifact_digests: true,
                passed: true,
            },
            data_availability: GovernanceAvailabilityGateV1 {
                independent_attestors: 3,
                required_attestors: 3,
                valid_until_block: 1_000,
                required_valid_until_block: 900,
                passed: true,
            },
            pos: GovernancePosGateV1 {
                yes_weight: "30".to_string(),
                no_weight: "0".to_string(),
                abstain_weight: "0".to_string(),
                snapshotted_registered_weight: "100".to_string(),
                turnout_quorum_bps: 3_000,
                yes_threshold_bps: 7_500,
                passed: true,
            },
            pohw: GovernancePohwGateV1 {
                distinct_participating_identities: 12,
                required_participating_identities: 12,
                distinct_yes_identities: 12,
                required_yes_identities: 12,
                verified_or_human_yes_identities: 5,
                required_verified_or_human_yes: 5,
                passed: true,
            },
            challenge_status: "closed".to_string(),
            execution_status: "executed".to_string(),
            state: "Executed".to_string(),
        }
    }

    fn configured_dashboard() -> GovernanceDashboardResponseV1 {
        let mut value = unconfigured();
        value.status = "operator-validated-local-snapshot".to_string();
        value.governance_contract_address = Some(format!("0x{}", "1".repeat(40)));
        value.current_canonical_ecosystem_cid = Some(cid("ecosystem"));
        let development_policy = DevelopmentPolicyBundleV1::experimental_default();
        value.development_policy_cid = Some(
            package_development_policy(development_policy.clone())
                .unwrap()
                .root_cid
                .to_string(),
        );
        value.development_policy = Some(development_policy);
        value.identity_metrics = Some(certified_metrics());
        value.repositories.push(GovernanceRepositoryViewV1 {
            name: "P2poolBTC".to_string(),
            source_tree_cid: cid("source"),
        });
        value
    }

    #[test]
    fn checked_in_governance_day_ui_fixture_has_a_bound_proposal_set_root() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/governance/fixtures/governance-dashboard-v1.json");
        let bytes = fs::read(&fixture).unwrap();
        let value: GovernanceDashboardResponseV1 = serde_json::from_slice(&bytes).unwrap();
        validate_dashboard(&value).unwrap();
        assert_eq!(value.status, "operator-validated-local-snapshot");
        assert_eq!(value.proposals.len(), 1);
        assert_eq!(value.epoch_governance.unwrap().phase, "Grace");
    }

    fn epoch_view(proposal_id: String) -> GovernanceEpochViewV1 {
        GovernanceEpochViewV1 {
            governance_epoch: 421,
            current_block: 90,
            phase: "VotingCommit".to_string(),
            schedule: GovernanceScheduleViewV1 {
                epoch_anchor_block: 1,
                proposal_cutoff_block: 40,
                commit_start_block: 80,
                commit_end_block: 100,
                reveal_end_block: 120,
            },
            frozen_proposal_set_root: Some(
                frozen_proposal_set_root(421, std::slice::from_ref(&proposal_id)).unwrap(),
            ),
            ordered_proposal_ids: vec![proposal_id],
            frozen_at_block: Some(40),
            reviewed_proposals: 1,
            unresolved_proposals: 0,
            valid_agent_attestations: 3,
            committed_ballots: 1,
            revealed_ballots: 0,
            voting_power_snapshot_ready: true,
            grace_end_block: None,
            open_challenges: 0,
            execution_ready_proposals: 0,
        }
    }

    #[test]
    fn missing_snapshot_is_explicitly_unconfigured() {
        let value = load_dashboard(None).unwrap();
        assert_eq!(value.status, "unconfigured");
        assert!(value.experimental);
        assert!(value.current_canonical_ecosystem_cid.is_none());
    }

    #[test]
    fn strict_snapshot_rejects_unsafe_or_mismatched_fields() {
        let mut value = configured_dashboard();
        assert!(validate_dashboard(&value).is_ok());
        value.repositories[0].source_tree_cid = "not-a-cid".to_string();
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn dashboard_rejects_privileged_or_cid_mismatched_development_policy() {
        let mut value = configured_dashboard();
        value
            .development_policy
            .as_mut()
            .unwrap()
            .authority
            .agent_may_execute_proposal = true;
        assert!(validate_dashboard(&value).is_err());

        let mut value = configured_dashboard();
        value.development_policy_cid = Some(cid("substituted-policy"));
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn configured_snapshot_requires_a_canonical_contract_address() {
        let mut value = unconfigured();
        value.status = "operator-validated-local-snapshot".to_string();
        value.current_canonical_ecosystem_cid = Some(cid("ecosystem"));
        value.identity_metrics = Some(certified_metrics());
        value.repositories.push(GovernanceRepositoryViewV1 {
            name: "P2poolBTC".to_string(),
            source_tree_cid: cid("source"),
        });
        assert!(validate_dashboard(&value).is_err());
        value.governance_contract_address = Some(format!("0x{}", "A".repeat(40)));
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn proposal_gate_results_are_recomputed_from_bounded_evidence() {
        let proposal = passing_proposal();
        assert!(validate_proposal_gates(&proposal).is_ok());

        let mut forged_result = proposal.clone();
        forged_result.ai_reviews.valid_attestations = 2;
        assert!(validate_proposal_gates(&forged_result).is_err());

        let mut impossible_turnout = proposal.clone();
        impossible_turnout.pos.yes_weight = "101".to_string();
        assert!(validate_proposal_gates(&impossible_turnout).is_err());

        let mut inflated_diversity = proposal;
        inflated_diversity.builds.distinct_platforms = 4;
        assert!(validate_proposal_gates(&inflated_diversity).is_err());

        let mut stale_availability = passing_proposal();
        stale_availability.data_availability.valid_until_block = stale_availability
            .data_availability
            .required_valid_until_block
            - 1;
        assert!(validate_proposal_gates(&stale_availability).is_err());
    }

    #[test]
    fn accepted_proposal_requires_an_explicit_verified_critical_finding_waiver() {
        let mut proposal = passing_proposal();
        proposal.ai_reviews.unresolved_critical_findings = 1;
        assert!(validate_proposal_gates(&proposal).is_err());

        proposal.critical_finding_waiver_cid = Some(cid("critical-finding-waiver"));
        assert!(validate_proposal_gates(&proposal).is_err());

        proposal.critical_finding_waiver_verified = true;
        assert!(validate_proposal_gates(&proposal).is_ok());

        proposal.critical_finding_waiver_cid = Some(raw_cid("raw-waiver-is-not-a-manifest"));
        assert!(validate_proposal_gates(&proposal).is_err());

        proposal.critical_finding_waiver_cid = None;
        assert!(validate_proposal_gates(&proposal).is_err());
    }

    #[test]
    fn proposal_cannot_self_declare_weaker_gate_minima() {
        let mut proposal = passing_proposal();
        proposal.pos.turnout_quorum_bps = 1;
        proposal.pos.yes_threshold_bps = 1;
        proposal.pohw.required_participating_identities = 1;
        proposal.pohw.required_yes_identities = 1;
        proposal.pohw.required_verified_or_human_yes = 0;
        proposal.ai_reviews.required_attestations = 1;
        proposal.ai_reviews.required_model_families = 1;
        proposal.ai_reviews.required_owner_identities = 1;
        proposal.builds.required_builders = 1;
        proposal.builds.required_platforms = 1;
        proposal.data_availability.required_attestors = 1;
        assert!(validate_proposal_gates(&proposal).is_err());
    }

    #[test]
    fn dashboard_rejects_unverified_scope_and_underfunded_critical_bonds() {
        let mut value = configured_dashboard();
        let mut proposal = passing_proposal();
        proposal.scope_evidence_verified = false;
        value.proposals.push(proposal);
        assert!(validate_dashboard(&value).is_err());

        let mut value = configured_dashboard();
        let mut proposal = passing_proposal();
        proposal.bond_atoms = "10000000000000000000".to_string();
        value.proposals.push(proposal);
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn distinct_participation_is_independent_from_yes_breadth() {
        let mut proposal = passing_proposal();
        proposal.pohw.distinct_participating_identities = 11;
        proposal.pohw.distinct_yes_identities = 11;
        proposal.pohw.passed = false;
        proposal.state = "Rejected".to_string();
        assert!(validate_proposal_gates(&proposal).is_ok());

        proposal.pohw.passed = true;
        assert!(validate_proposal_gates(&proposal).is_err());
    }

    #[test]
    fn dashboard_collections_match_manifest_repository_limits() {
        let mut value = unconfigured();
        value.status = "operator-validated-local-snapshot".to_string();
        value.governance_contract_address = Some(format!("0x{}", "1".repeat(40)));
        value.current_canonical_ecosystem_cid = Some(cid("ecosystem"));
        value.identity_metrics = Some(certified_metrics());
        value.repositories = (0..=MAX_GOVERNANCE_REPOSITORIES)
            .map(|index| GovernanceRepositoryViewV1 {
                name: format!("repo-{index:03}"),
                source_tree_cid: cid(&format!("source-{index}")),
            })
            .collect();
        assert!(validate_dashboard(&value).is_err());

        let mut proposal = passing_proposal();
        proposal.affected_repositories = (0..=MAX_AFFECTED_REPOSITORIES)
            .map(|index| format!("repo-{index:03}"))
            .collect();
        value.repositories.truncate(1);
        value.proposals = vec![proposal];
        assert!(validate_dashboard(&value).is_err());

        let mut oversized_scope = passing_proposal();
        oversized_scope.changed_file_count = 1_025;
        value.proposals = vec![oversized_scope];
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn epoch_snapshot_requires_a_frozen_sorted_proposal_set() {
        let mut value = configured_dashboard();
        let proposal = passing_proposal();
        value.epoch_governance = Some(epoch_view(proposal.proposal_id.clone()));
        value.proposals = vec![proposal];
        assert!(validate_dashboard(&value).is_ok());

        value
            .epoch_governance
            .as_mut()
            .unwrap()
            .frozen_proposal_set_root = Some("9".repeat(64));
        assert!(validate_dashboard(&value).is_err());

        let epoch = value.epoch_governance.as_mut().unwrap();
        epoch.frozen_proposal_set_root = Some(
            frozen_proposal_set_root(epoch.governance_epoch, &epoch.ordered_proposal_ids).unwrap(),
        );

        value
            .epoch_governance
            .as_mut()
            .unwrap()
            .ordered_proposal_ids
            .push("3".repeat(64));
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn canonical_history_is_continuous_and_reverts_only_prior_executions() {
        let mut value = configured_dashboard();
        let first_canonical = value.current_canonical_ecosystem_cid.clone().unwrap();
        let second_canonical = cid("second-canonical");
        value.current_canonical_ecosystem_cid = Some(second_canonical.clone());
        value
            .canonical_history
            .push(GovernanceCanonicalExecutionViewV1 {
                execution_id: "a".repeat(64),
                previous_canonical_ecosystem_cid: first_canonical,
                new_canonical_ecosystem_cid: second_canonical,
                proposal_id: "4".repeat(64),
                governance_epoch: 421,
                decision_record_cid: raw_cid("decision"),
                execution_block: 200,
                rollback_manifest_cid: cid("rollback"),
                release_rollback_instructions_cid: cid("instructions"),
                observation_window_end_block: 800,
                reverts_execution_id: None,
            });
        assert!(validate_dashboard(&value).is_ok());

        value.canonical_history[0].previous_canonical_ecosystem_cid = raw_cid("not-a-manifest");
        assert!(validate_dashboard(&value).is_err());
        value.canonical_history[0].previous_canonical_ecosystem_cid = cid("ecosystem");

        value.canonical_history[0].reverts_execution_id = Some("a".repeat(64));
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn recovery_snapshot_never_authorizes_automatic_install_or_fake_on_chain_revert() {
        let mut value = configured_dashboard();
        value.recovery = Some(GovernanceRecoveryViewV1 {
            chain_rpc_available: false,
            local_last_known_good_staged: true,
            staged_ecosystem_cid: Some(cid("last-known-good")),
            recovery_manifest_cid: Some(cid("recovery")),
            explicit_user_confirmation_required: true,
            automatic_install_enabled: false,
            automatic_rollback_enabled: false,
            on_chain_revert_available: false,
            warning: "Chain RPC is unavailable; only an explicitly confirmed local rollback is available."
                .to_string(),
        });
        assert!(validate_dashboard(&value).is_ok());

        value.recovery.as_mut().unwrap().automatic_install_enabled = true;
        assert!(validate_dashboard(&value).is_err());
        value.recovery.as_mut().unwrap().automatic_install_enabled = false;
        value.recovery.as_mut().unwrap().on_chain_revert_available = true;
        assert!(validate_dashboard(&value).is_err());
    }
}
