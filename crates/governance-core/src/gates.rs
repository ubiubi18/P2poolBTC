use crate::types::{GateParameterSet, RiskClass, VoteChoice};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptanceEvidence {
    pub yes_weight: u128,
    pub no_weight: u128,
    pub abstain_weight: u128,
    pub total_registered_weight: u128,
    pub distinct_yes_identities: u32,
    pub verified_or_human_yes_identities: u32,
    pub valid_agent_attestations: u32,
    pub distinct_agent_families: u32,
    pub distinct_agent_owner_identities: u32,
    pub unresolved_critical_findings: u32,
    pub valid_builders: u32,
    pub distinct_builder_platforms: u32,
    pub matching_core_artifact_digests: bool,
    pub independent_data_availability_providers: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResult {
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResults {
    pub pos: GateResult,
    pub pohw: GateResult,
    pub poaw: GateResult,
    pub verification_work: GateResult,
    pub data_availability: GateResult,
    pub accepted: bool,
}

pub fn evaluate_gates(
    risk: RiskClass,
    normal: &GateParameterSet,
    critical: &GateParameterSet,
    evidence: &AcceptanceEvidence,
) -> GateResults {
    let parameters = if risk.is_critical() { critical } else { normal };
    let Some(turnout) = evidence
        .yes_weight
        .checked_add(evidence.no_weight)
        .and_then(|value| value.checked_add(evidence.abstain_weight))
    else {
        return overflow_results();
    };
    let turnout_bps = ratio_bps(turnout, evidence.total_registered_weight);
    let Some(decisive) = evidence.yes_weight.checked_add(evidence.no_weight) else {
        return overflow_results();
    };
    let approval_bps = ratio_bps(evidence.yes_weight, decisive);

    let pos_passed = turnout_bps >= parameters.turnout_quorum_bps
        && approval_bps >= parameters.yes_threshold_bps;
    let pohw_passed = evidence.distinct_yes_identities >= parameters.minimum_yes_identities
        && evidence.verified_or_human_yes_identities >= parameters.minimum_verified_or_human_yes;
    let poaw_passed = evidence.valid_agent_attestations >= parameters.minimum_agent_attestations
        && evidence.distinct_agent_families >= parameters.minimum_agent_families
        && evidence.distinct_agent_owner_identities >= parameters.minimum_agent_owners
        && evidence.unresolved_critical_findings == 0;
    let build_passed = evidence.valid_builders >= parameters.minimum_builders
        && evidence.distinct_builder_platforms >= parameters.minimum_builder_platforms
        && evidence.matching_core_artifact_digests;
    let availability_passed = evidence.independent_data_availability_providers
        >= parameters.minimum_data_availability_providers;

    GateResults {
        pos: gate(
            pos_passed,
            format!("turnout={turnout_bps}bps approval={approval_bps}bps"),
        ),
        pohw: gate(
            pohw_passed,
            format!(
                "yes-identities={} verified-or-human={}",
                evidence.distinct_yes_identities, evidence.verified_or_human_yes_identities
            ),
        ),
        poaw: gate(
            poaw_passed,
            format!(
                "attestations={} families={} owners={} unresolved-critical={}",
                evidence.valid_agent_attestations,
                evidence.distinct_agent_families,
                evidence.distinct_agent_owner_identities,
                evidence.unresolved_critical_findings
            ),
        ),
        verification_work: gate(
            build_passed,
            format!(
                "builders={} platforms={} matching={}",
                evidence.valid_builders,
                evidence.distinct_builder_platforms,
                evidence.matching_core_artifact_digests
            ),
        ),
        data_availability: gate(
            availability_passed,
            format!(
                "providers={}",
                evidence.independent_data_availability_providers
            ),
        ),
        accepted: pos_passed && pohw_passed && poaw_passed && build_passed && availability_passed,
    }
}

fn overflow_results() -> GateResults {
    let failed = || GateResult {
        passed: false,
        reason: "arithmetic overflow in acceptance evidence".to_string(),
    };
    GateResults {
        pos: failed(),
        pohw: failed(),
        poaw: failed(),
        verification_work: failed(),
        data_availability: failed(),
        accepted: false,
    }
}

fn gate(passed: bool, reason: String) -> GateResult {
    GateResult { passed, reason }
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

#[allow(dead_code)]
fn _choice_is_explicit(choice: VoteChoice) -> bool {
    matches!(
        choice,
        VoteChoice::Yes | VoteChoice::No | VoteChoice::Abstain
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GovernanceParameterSetV1;

    #[test]
    fn every_gate_is_independent() {
        let parameters = GovernanceParameterSetV1::experimental_defaults();
        let evidence = AcceptanceEvidence {
            yes_weight: 25,
            no_weight: 5,
            abstain_weight: 0,
            total_registered_weight: 100,
            distinct_yes_identities: 7,
            verified_or_human_yes_identities: 3,
            valid_agent_attestations: 3,
            distinct_agent_families: 2,
            distinct_agent_owner_identities: 2,
            unresolved_critical_findings: 0,
            valid_builders: 2,
            distinct_builder_platforms: 1,
            matching_core_artifact_digests: true,
            independent_data_availability_providers: 2,
        };
        assert!(
            evaluate_gates(
                RiskClass::Normal,
                &parameters.normal,
                &parameters.critical,
                &evidence
            )
            .accepted
        );

        let mut missing_review = evidence.clone();
        missing_review.valid_agent_attestations = 2;
        let result = evaluate_gates(
            RiskClass::Normal,
            &parameters.normal,
            &parameters.critical,
            &missing_review,
        );
        assert!(result.pos.passed);
        assert!(!result.poaw.passed);
        assert!(!result.accepted);
    }

    #[test]
    fn ratio_handles_maximum_weights_without_saturation_bias() {
        assert_eq!(ratio_bps(u128::MAX / 2, u128::MAX), 4_999);
        assert_eq!(ratio_bps(u128::MAX, u128::MAX), 10_000);
        assert_eq!(ratio_bps(u128::MAX, 0), 0);
    }
}
