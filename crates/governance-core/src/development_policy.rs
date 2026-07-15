use crate::{package_dag_cbor, verify_dag_cbor_car, DagCborPackage, SourceError};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const DECENTRALIZED_AIDD_POLICY_KIND: &str =
    "pohw-decentralized-human-ai-development-policy-v1";
pub const DECENTRALIZED_AIDD_POLICY_LICENSE: &str = "MIT";
pub const DECENTRALIZED_AIDD_CANONICAL_AUTHORITY: &str = "idena-wasm-governance-contract";
const MAX_POLICY_DAG_CBOR_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyUpstreamV1 {
    pub repository_url: String,
    pub commit: String,
    pub source_tree_cid: String,
    pub license_spdx: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DevelopmentActorV1 {
    HumanAi,
    IsolatedAgent,
    IndependentReviewer,
    IndependentBuilder,
    AvailabilityProvider,
    EligibleIdentities,
    AnyCaller,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevelopmentPhaseV1 {
    pub id: String,
    pub actor: DevelopmentActorV1,
    pub human_approval_required: bool,
    pub mutates_candidate_source: bool,
    pub output_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevelopmentAuthorityV1 {
    pub canonical_authority: String,
    pub github_is_canonical: bool,
    pub maintainer_merge_key_exists: bool,
    pub agent_may_accept_proposal: bool,
    pub agent_may_execute_proposal: bool,
    pub contract_owner_may_replace_canonical_cid: bool,
    pub accepted_execution_is_permissionless: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSandboxPolicyV1 {
    pub network_disabled_by_default: bool,
    pub wallet_keys_exposed: bool,
    pub provider_secrets_exposed_to_repository_scripts: bool,
    pub read_only_source_mount: bool,
    pub isolated_temporary_build_directory: bool,
    pub explicit_dependency_fetch_phase: bool,
    pub command_allowlisting: bool,
    pub resource_limits_required: bool,
    pub complete_redacted_command_log: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevelopmentPolicyBundleV1 {
    pub schema_version: u16,
    pub kind: String,
    pub policy_id: String,
    pub ecosystem_id: String,
    pub license_spdx: String,
    pub upstream: Vec<PolicyUpstreamV1>,
    pub authority: DevelopmentAuthorityV1,
    pub sandbox: AgentSandboxPolicyV1,
    pub phases: Vec<DevelopmentPhaseV1>,
}

impl DevelopmentPolicyBundleV1 {
    pub fn experimental_default() -> Self {
        Self {
            schema_version: 1,
            kind: DECENTRALIZED_AIDD_POLICY_KIND.to_owned(),
            policy_id: "pohw-aidd-human-ai-v1".to_owned(),
            ecosystem_id: "ubiubi18-pohw".to_owned(),
            license_spdx: DECENTRALIZED_AIDD_POLICY_LICENSE.to_owned(),
            upstream: vec![PolicyUpstreamV1 {
                repository_url: "https://github.com/ai-driven-dev/framework".to_owned(),
                commit: "8aeaf051f05c8d4e54eb94dc1e03d05e909b0173".to_owned(),
                source_tree_cid: "bafyreif2aqjfv53gkzgtrb3kqanyegjaaqd6h2xq26pwxh2z5sx3kjsuqi"
                    .to_owned(),
                license_spdx: "MIT".to_owned(),
            }],
            authority: DevelopmentAuthorityV1 {
                canonical_authority: DECENTRALIZED_AIDD_CANONICAL_AUTHORITY.to_owned(),
                github_is_canonical: false,
                maintainer_merge_key_exists: false,
                agent_may_accept_proposal: false,
                agent_may_execute_proposal: false,
                contract_owner_may_replace_canonical_cid: false,
                accepted_execution_is_permissionless: true,
            },
            sandbox: AgentSandboxPolicyV1 {
                network_disabled_by_default: true,
                wallet_keys_exposed: false,
                provider_secrets_exposed_to_repository_scripts: false,
                read_only_source_mount: true,
                isolated_temporary_build_directory: true,
                explicit_dependency_fetch_phase: true,
                command_allowlisting: true,
                resource_limits_required: true,
                complete_redacted_command_log: true,
            },
            phases: expected_phases()
                .into_iter()
                .map(
                    |(id, actor, approval, mutates, output_schema)| DevelopmentPhaseV1 {
                        id: id.to_owned(),
                        actor,
                        human_approval_required: approval,
                        mutates_candidate_source: mutates,
                        output_schema: output_schema.to_owned(),
                    },
                )
                .collect(),
        }
    }
}

pub type DevelopmentPolicyPackage = DagCborPackage<DevelopmentPolicyBundleV1>;

#[derive(Debug, Error)]
pub enum DevelopmentPolicyError {
    #[error("development policy is invalid: {0}")]
    Invalid(String),
    #[error(transparent)]
    Source(#[from] SourceError),
}

pub fn package_development_policy(
    policy: DevelopmentPolicyBundleV1,
) -> Result<DevelopmentPolicyPackage, DevelopmentPolicyError> {
    validate_development_policy(&policy)?;
    let package = package_dag_cbor(policy)?;
    if package.dag_cbor_bytes.len() > MAX_POLICY_DAG_CBOR_BYTES {
        return invalid("canonical policy exceeds the contract-compatible payload limit");
    }
    Ok(package)
}

pub fn verify_development_policy_car(
    bytes: &[u8],
) -> Result<DevelopmentPolicyPackage, DevelopmentPolicyError> {
    let package: DevelopmentPolicyPackage = verify_dag_cbor_car(bytes)?;
    if package.dag_cbor_bytes.len() > MAX_POLICY_DAG_CBOR_BYTES {
        return invalid("canonical policy exceeds the contract-compatible payload limit");
    }
    validate_development_policy(&package.value)?;
    Ok(package)
}

pub fn validate_development_policy(
    policy: &DevelopmentPolicyBundleV1,
) -> Result<(), DevelopmentPolicyError> {
    if policy.schema_version != 1 || policy.kind != DECENTRALIZED_AIDD_POLICY_KIND {
        return invalid("unsupported schemaVersion or policy kind");
    }
    validate_label(&policy.policy_id, 96, "policyId")?;
    validate_label(&policy.ecosystem_id, 96, "ecosystemId")?;
    if policy.license_spdx != DECENTRALIZED_AIDD_POLICY_LICENSE {
        return invalid("the active policy must remain MIT licensed");
    }
    if policy.upstream.is_empty() || policy.upstream.len() > 16 {
        return invalid("upstream provenance must contain between 1 and 16 exact sources");
    }
    let mut previous = None;
    for upstream in &policy.upstream {
        if !upstream.repository_url.starts_with("https://")
            || upstream.repository_url.len() > 512
            || upstream.repository_url.contains('#')
            || upstream.repository_url.contains('?')
        {
            return invalid("upstream repository URL must be a stable HTTPS repository URL");
        }
        if previous.is_some_and(|value: &str| value >= upstream.repository_url.as_str()) {
            return invalid("upstream provenance must be uniquely sorted by repository URL");
        }
        previous = Some(upstream.repository_url.as_str());
        if !is_lower_hex_revision(&upstream.commit) {
            return invalid("upstream commit must be an exact lowercase 40 or 64 byte revision");
        }
        validate_dag_cbor_cid(&upstream.source_tree_cid)?;
        if upstream.license_spdx != "MIT" {
            return invalid("every adapted upstream policy source must be MIT licensed");
        }
    }

    let authority = &policy.authority;
    if authority.canonical_authority != DECENTRALIZED_AIDD_CANONICAL_AUTHORITY
        || authority.github_is_canonical
        || authority.maintainer_merge_key_exists
        || authority.agent_may_accept_proposal
        || authority.agent_may_execute_proposal
        || authority.contract_owner_may_replace_canonical_cid
        || !authority.accepted_execution_is_permissionless
    {
        return invalid("authority model reintroduces a privileged development or execution path");
    }

    let sandbox = &policy.sandbox;
    if !sandbox.network_disabled_by_default
        || sandbox.wallet_keys_exposed
        || sandbox.provider_secrets_exposed_to_repository_scripts
        || !sandbox.read_only_source_mount
        || !sandbox.isolated_temporary_build_directory
        || !sandbox.explicit_dependency_fetch_phase
        || !sandbox.command_allowlisting
        || !sandbox.resource_limits_required
        || !sandbox.complete_redacted_command_log
    {
        return invalid("agent sandbox policy weakens a mandatory isolation control");
    }

    let expected = expected_phases();
    if policy.phases.len() != expected.len() {
        return invalid("development policy must contain the complete ordered lifecycle");
    }
    let mut phase_ids = BTreeSet::new();
    for (phase, (id, actor, approval, mutates, output_schema)) in policy.phases.iter().zip(expected)
    {
        if !phase_ids.insert(phase.id.as_str())
            || phase.id != id
            || phase.actor != actor
            || phase.human_approval_required != approval
            || phase.mutates_candidate_source != mutates
            || phase.output_schema != output_schema
        {
            return invalid("development phases differ from the decentralized lifecycle");
        }
    }
    Ok(())
}

fn expected_phases() -> [(&'static str, DevelopmentActorV1, bool, bool, &'static str); 9] {
    [
        (
            "specify",
            DevelopmentActorV1::HumanAi,
            true,
            false,
            "ChangeProposalV1",
        ),
        (
            "plan",
            DevelopmentActorV1::HumanAi,
            true,
            false,
            "ChangeProposalV1",
        ),
        (
            "implement",
            DevelopmentActorV1::IsolatedAgent,
            true,
            true,
            "EcosystemManifestV1",
        ),
        (
            "review",
            DevelopmentActorV1::IndependentReviewer,
            false,
            false,
            "AgentReviewAttestationV1",
        ),
        (
            "build",
            DevelopmentActorV1::IndependentBuilder,
            false,
            false,
            "BuildAttestationV1",
        ),
        (
            "publish",
            DevelopmentActorV1::AvailabilityProvider,
            false,
            false,
            "DataAvailabilityAttestationV1",
        ),
        (
            "propose",
            DevelopmentActorV1::HumanAi,
            true,
            false,
            "ChangeProposalV1",
        ),
        (
            "vote",
            DevelopmentActorV1::EligibleIdentities,
            false,
            false,
            "VoteReceiptV1",
        ),
        (
            "execute",
            DevelopmentActorV1::AnyCaller,
            false,
            false,
            "EcosystemManifestV1",
        ),
    ]
}

fn validate_dag_cbor_cid(value: &str) -> Result<(), DevelopmentPolicyError> {
    let cid = Cid::try_from(value)
        .map_err(|_| DevelopmentPolicyError::Invalid("sourceTreeCid is malformed".to_owned()))?;
    if cid.version() != Version::V1
        || cid.codec() != 0x71
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || !value.starts_with('b')
        || cid.to_string() != value
    {
        return invalid("sourceTreeCid must be base32 CIDv1 DAG-CBOR SHA2-256");
    }
    Ok(())
}

fn validate_label(value: &str, maximum: usize, field: &str) -> Result<(), DevelopmentPolicyError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid(&format!("{field} is not a portable identifier"));
    }
    Ok(())
}

fn is_lower_hex_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid<T>(message: &str) -> Result<T, DevelopmentPolicyError> {
    Err(DevelopmentPolicyError::Invalid(message.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy() -> DevelopmentPolicyBundleV1 {
        DevelopmentPolicyBundleV1::experimental_default()
    }

    #[test]
    fn decentralized_policy_round_trips_as_canonical_car() {
        let package = package_development_policy(valid_policy()).unwrap();
        let verified = verify_development_policy_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);
        assert_eq!(verified.value, package.value);
    }

    #[test]
    fn privileged_or_non_mit_policy_is_rejected() {
        let mut policy = valid_policy();
        policy.authority.agent_may_execute_proposal = true;
        assert!(validate_development_policy(&policy).is_err());
        policy.authority.agent_may_execute_proposal = false;
        policy.license_spdx = "Proprietary".to_owned();
        assert!(validate_development_policy(&policy).is_err());
    }

    #[test]
    fn lifecycle_cannot_skip_human_or_independent_evidence_gates() {
        let mut policy = valid_policy();
        policy.phases.remove(3);
        assert!(validate_development_policy(&policy).is_err());

        let mut policy = valid_policy();
        policy.phases[2].human_approval_required = false;
        assert!(validate_development_policy(&policy).is_err());
    }
}
