use anyhow::{bail, Context, Result};
use cid::{Cid, Version};
use governance_core::{evaluate_gates, AcceptanceEvidence, GateParameterSet, RiskClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const MAX_GOVERNANCE_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GOVERNANCE_PROPOSALS: usize = 256;
const MAX_GOVERNANCE_REPOSITORIES: usize = 64;
const MAX_AFFECTED_REPOSITORIES: usize = 64;
const MAX_GATE_ATTESTATIONS: u32 = 256;
const EXPERIMENTAL_LABEL: &str = "EXPERIMENTAL / NO-VALUE / NOT DAO-DEPLOYED";

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
    pub identity_metrics: Option<GovernanceIdentityMetricsCertificationV1>,
    pub repositories: Vec<GovernanceRepositoryViewV1>,
    pub proposals: Vec<GovernanceProposalViewV1>,
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
    pub candidate_ecosystem_cid: String,
    pub review_round_id: String,
    pub review_round_state: String,
    pub review_round_agent_attestations: u32,
    pub review_round_build_attestations: u32,
    pub review_round_availability_attestations: u32,
    pub affected_repositories: Vec<String>,
    pub diff_summary: String,
    pub risk_class: String,
    pub bond_atoms: String,
    pub agent_review_root: String,
    pub build_attestation_root: String,
    pub data_availability_root: String,
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
        identity_metrics: None,
        repositories: vec![],
        proposals: vec![],
    }
}

fn validate_dashboard(value: &GovernanceDashboardResponseV1) -> Result<()> {
    if value.api_version != "pohw-governance-dashboard-v1"
        || value.schema_version != 1
        || !value.experimental
        || value.status != "verified-local-snapshot"
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
        validate_object_cid(&proposal.candidate_ecosystem_cid)?;
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
        if !proposal_ids.insert(&proposal.proposal_id) {
            bail!("duplicate governance proposal ID");
        }
        if proposal.affected_repositories.is_empty()
            || proposal.affected_repositories.len() > MAX_AFFECTED_REPOSITORIES
            || !is_sorted_unique_labels(&proposal.affected_repositories)
        {
            bail!("proposal affected repositories are invalid");
        }
        validate_text(&proposal.diff_summary, 1, 4_096)?;
        if !matches!(
            proposal.risk_class.as_str(),
            "normal" | "critical" | "consensus" | "migration"
        ) {
            bail!("proposal risk class is invalid");
        }
        validate_amount(&proposal.bond_atoms)?;
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
                    | "ReviewOpen"
                    | "VotingOpen"
                    | "AcceptedPendingChallenge"
                    | "Rejected"
                    | "Challenged"
                    | "AcceptedPendingExecution"
                    | "Executed"
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
    ];
    if counts.iter().any(|count| *count > MAX_GATE_ATTESTATIONS)
        || proposal.ai_reviews.required_attestations == 0
        || proposal.ai_reviews.required_model_families == 0
        || proposal.ai_reviews.required_owner_identities == 0
        || proposal.builds.required_builders == 0
        || proposal.builds.required_platforms == 0
        || proposal.data_availability.required_attestors == 0
        || proposal.ai_reviews.distinct_model_families > proposal.ai_reviews.valid_attestations
        || proposal.ai_reviews.distinct_owner_identities > proposal.ai_reviews.valid_attestations
        || proposal.builds.distinct_platforms > proposal.builds.independent_builders
        || proposal.ai_reviews.valid_attestations > proposal.review_round_agent_attestations
        || proposal.builds.independent_builders > proposal.review_round_build_attestations
        || proposal.data_availability.independent_attestors
            > proposal.review_round_availability_attestations
        || proposal.pohw.verified_or_human_yes_identities > proposal.pohw.distinct_yes_identities
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

    let parameters = GateParameterSet {
        turnout_quorum_bps: proposal.pos.turnout_quorum_bps,
        yes_threshold_bps: proposal.pos.yes_threshold_bps,
        minimum_yes_identities: proposal.pohw.required_yes_identities,
        minimum_verified_or_human_yes: proposal.pohw.required_verified_or_human_yes,
        minimum_agent_attestations: proposal.ai_reviews.required_attestations,
        minimum_agent_families: proposal.ai_reviews.required_model_families,
        minimum_agent_owners: proposal.ai_reviews.required_owner_identities,
        minimum_builders: proposal.builds.required_builders,
        minimum_builder_platforms: proposal.builds.required_platforms,
        minimum_data_availability_providers: proposal.data_availability.required_attestors,
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
        unresolved_critical_findings: proposal.ai_reviews.unresolved_critical_findings,
        valid_builders: proposal.builds.independent_builders,
        distinct_builder_platforms: proposal.builds.distinct_platforms,
        matching_core_artifact_digests: proposal.builds.matching_core_artifact_digests,
        independent_data_availability_providers: proposal.data_availability.independent_attestors,
    };
    let risk = match proposal.risk_class.as_str() {
        "normal" => RiskClass::Normal,
        "critical" => RiskClass::Critical,
        "consensus" => RiskClass::Consensus,
        "migration" => RiskClass::Migration,
        _ => unreachable!("risk class was validated before gate recomputation"),
    };
    let recomputed = evaluate_gates(risk, &parameters, &parameters, &evidence);
    if proposal.pos.passed != recomputed.pos.passed
        || proposal.pohw.passed != recomputed.pohw.passed
        || proposal.ai_reviews.passed != recomputed.poaw.passed
        || proposal.builds.passed != recomputed.verification_work.passed
        || proposal.data_availability.passed != recomputed.data_availability.passed
    {
        bail!("proposal gate result does not match its evidence");
    }
    if matches!(
        proposal.state.as_str(),
        "AcceptedPendingChallenge" | "Challenged" | "AcceptedPendingExecution" | "Executed"
    ) && !recomputed.accepted
    {
        bail!("accepted proposal state does not satisfy every gate");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use governance_core::cid_for;

    fn cid(label: &str) -> String {
        cid_for(0x71, label.as_bytes()).to_string()
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
            candidate_ecosystem_cid: cid("candidate"),
            review_round_id: "5".repeat(64),
            review_round_state: "Claimed".to_string(),
            review_round_agent_attestations: 3,
            review_round_build_attestations: 2,
            review_round_availability_attestations: 2,
            affected_repositories: vec!["P2poolBTC".to_string()],
            diff_summary: "governance fixture".to_string(),
            risk_class: "critical".to_string(),
            bond_atoms: "10000000000000000000".to_string(),
            agent_review_root: "6".repeat(64),
            build_attestation_root: "7".repeat(64),
            data_availability_root: "8".repeat(64),
            ai_reviews: GovernanceReviewGateV1 {
                valid_attestations: 3,
                required_attestations: 3,
                distinct_model_families: 2,
                required_model_families: 2,
                distinct_owner_identities: 2,
                required_owner_identities: 2,
                unresolved_critical_findings: 0,
                passed: true,
            },
            builds: GovernanceBuildGateV1 {
                independent_builders: 2,
                required_builders: 2,
                distinct_platforms: 1,
                required_platforms: 1,
                matching_core_artifact_digests: true,
                passed: true,
            },
            data_availability: GovernanceAvailabilityGateV1 {
                independent_attestors: 2,
                required_attestors: 2,
                passed: true,
            },
            pos: GovernancePosGateV1 {
                yes_weight: "30".to_string(),
                no_weight: "0".to_string(),
                abstain_weight: "0".to_string(),
                snapshotted_registered_weight: "100".to_string(),
                turnout_quorum_bps: 2_000,
                yes_threshold_bps: 6_667,
                passed: true,
            },
            pohw: GovernancePohwGateV1 {
                distinct_yes_identities: 7,
                required_yes_identities: 7,
                verified_or_human_yes_identities: 3,
                required_verified_or_human_yes: 3,
                passed: true,
            },
            challenge_status: "closed".to_string(),
            execution_status: "executed".to_string(),
            state: "Executed".to_string(),
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
        let mut value = unconfigured();
        value.status = "verified-local-snapshot".to_string();
        value.governance_contract_address = Some(format!("0x{}", "1".repeat(40)));
        value.current_canonical_ecosystem_cid = Some(cid("ecosystem"));
        value.identity_metrics = Some(certified_metrics());
        value.repositories.push(GovernanceRepositoryViewV1 {
            name: "P2poolBTC".to_string(),
            source_tree_cid: cid("source"),
        });
        assert!(validate_dashboard(&value).is_ok());
        value.repositories[0].source_tree_cid = "not-a-cid".to_string();
        assert!(validate_dashboard(&value).is_err());
    }

    #[test]
    fn configured_snapshot_requires_a_canonical_contract_address() {
        let mut value = unconfigured();
        value.status = "verified-local-snapshot".to_string();
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
        inflated_diversity.builds.distinct_platforms = 3;
        assert!(validate_proposal_gates(&inflated_diversity).is_err());
    }

    #[test]
    fn dashboard_collections_match_manifest_repository_limits() {
        let mut value = unconfigured();
        value.status = "verified-local-snapshot".to_string();
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
    }
}
