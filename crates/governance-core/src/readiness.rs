use crate::{
    validate_proposal_scope_evidence, BuildAttestationV1, DataAvailabilityAttestationV1,
    ExternalAuditAttestationV1, ExternalAuditVerdictV1, ProposalScopeEvidenceV1, RepositoryCidV1,
    RiskClass,
};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressedAttestationV1<T> {
    pub cid: String,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentReadinessReportV1 {
    pub schema_version: u16,
    pub candidate_ecosystem_cid: String,
    pub scope_evidence_cid: String,
    pub risk_class: RiskClass,
    pub ready: bool,
    pub builder_threshold: u32,
    pub matching_builder_count: u32,
    pub builder_platform_threshold: u32,
    pub matching_builder_platform_count: u32,
    pub selected_core_artifact_digest: Option<String>,
    pub availability_threshold: u32,
    pub complete_availability_count: u32,
    pub external_audit_threshold: u32,
    pub passing_external_audit_count: u32,
    pub required_content_cid_count: u32,
    pub failure_codes: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReadinessError {
    #[error("deployment readiness input is invalid: {0}")]
    Invalid(String),
}

pub fn evaluate_deployment_readiness(
    scope_evidence_cid: &str,
    scope: &ProposalScopeEvidenceV1,
    builds: &[AddressedAttestationV1<BuildAttestationV1>],
    availability: &[AddressedAttestationV1<DataAvailabilityAttestationV1>],
    audits: &[AddressedAttestationV1<ExternalAuditAttestationV1>],
    required_availability_through_block: u64,
) -> Result<DeploymentReadinessReportV1, ReadinessError> {
    validate_proposal_scope_evidence(scope)
        .map_err(|error| ReadinessError::Invalid(error.to_string()))?;
    validate_dag_cbor_cid(scope_evidence_cid, "scope evidence")?;
    let risk = scope.derived_risk_class;
    let (builder_threshold, platform_threshold, availability_threshold, audit_threshold) =
        if risk.is_critical() {
            (3usize, 2usize, 3usize, 2usize)
        } else {
            (2usize, 1usize, 2usize, 1usize)
        };
    let expected_sources = scope
        .repositories
        .iter()
        .map(|repository| RepositoryCidV1 {
            repository: repository.repository.clone(),
            cid: repository.candidate_source_cid.clone(),
        })
        .collect::<Vec<_>>();
    let mut failures = BTreeSet::new();
    let mut required_content = scope_required_content(scope_evidence_cid, scope);
    let mut evidence_cids = BTreeSet::new();
    let mut builder_groups: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    let mut builder_owners = BTreeSet::new();

    if builds.is_empty() {
        failures.insert("build.none".to_string());
    }
    for build in builds {
        validate_evidence_cid(&build.cid, &mut evidence_cids, &mut failures, "build")?;
        required_content.insert(build.cid.clone());
        required_content.insert(build.value.toolchain_cid.clone());
        required_content.insert(build.value.test_results_cid.clone());
        required_content.insert(build.value.sbom_cid.clone());
        required_content.extend(
            build
                .value
                .source_cids
                .iter()
                .map(|value| value.cid.clone()),
        );
        required_content.extend(
            build
                .value
                .artifacts
                .iter()
                .map(|artifact| artifact.cid.clone()),
        );
        if build.value.candidate_ecosystem_cid != scope.candidate_ecosystem_cid {
            failures.insert("build.candidate-mismatch".to_string());
            continue;
        }
        if build.value.scope_evidence_cid != scope_evidence_cid {
            failures.insert("build.scope-mismatch".to_string());
            continue;
        }
        if build.value.source_cids != expected_sources {
            failures.insert("build.source-set-mismatch".to_string());
            continue;
        }
        if !build.value.tests_passed {
            failures.insert("build.tests-failed".to_string());
            continue;
        }
        let platform = format!(
            "{}-{}",
            build.value.runtime_family, build.value.architecture
        );
        let group = builder_groups
            .entry(build.value.core_artifact_digest.clone())
            .or_default();
        if !group.0.insert(build.value.builder_identity.clone()) {
            failures.insert("build.duplicate-owner".to_string());
        }
        group.1.insert(platform);
        builder_owners.insert(build.value.builder_identity.clone());
    }
    if builder_groups.len() > 1 {
        failures.insert("build.conflicting-core-digests".to_string());
    }
    let selected = builder_groups.iter().max_by(|left, right| {
        let left_score = ((left.1).0.len(), (left.1).1.len());
        let right_score = ((right.1).0.len(), (right.1).1.len());
        left_score
            .cmp(&right_score)
            .then_with(|| right.0.cmp(left.0))
    });
    let (selected_digest, matching_builders, matching_platforms) = selected
        .map(|(digest, (owners, platforms))| (Some(digest.clone()), owners.len(), platforms.len()))
        .unwrap_or((None, 0, 0));
    if matching_builders < builder_threshold {
        failures.insert("build.insufficient-independent-builders".to_string());
    }
    if matching_platforms < platform_threshold {
        failures.insert("build.insufficient-platform-diversity".to_string());
    }

    let mut audit_owners = BTreeSet::new();
    let mut audit_organizations = BTreeSet::new();
    let mut passing_audits = 0usize;
    if audits.is_empty() {
        failures.insert("audit.none".to_string());
    }
    for audit in audits {
        validate_evidence_cid(&audit.cid, &mut evidence_cids, &mut failures, "audit")?;
        required_content.extend([
            audit.cid.clone(),
            audit.value.audit_policy_cid.clone(),
            audit.value.report_cid.clone(),
            audit.value.independence_statement_cid.clone(),
        ]);
        required_content.extend(
            audit
                .value
                .covered_repository_cids
                .iter()
                .map(|value| value.cid.clone()),
        );
        if audit.value.candidate_ecosystem_cid != scope.candidate_ecosystem_cid {
            failures.insert("audit.candidate-mismatch".to_string());
            continue;
        }
        if audit.value.scope_evidence_cid != scope_evidence_cid {
            failures.insert("audit.scope-mismatch".to_string());
            continue;
        }
        if audit.value.covered_repository_cids != expected_sources {
            failures.insert("audit.source-set-mismatch".to_string());
            continue;
        }
        if audit.value.verdict != ExternalAuditVerdictV1::Pass
            || audit.value.unresolved_critical_findings != 0
            || audit.value.unresolved_high_findings != 0
        {
            failures.insert("audit.unresolved-severe-finding".to_string());
            continue;
        }
        if !audit_owners.insert(audit.value.auditor_identity.clone()) {
            failures.insert("audit.duplicate-owner".to_string());
            continue;
        }
        if !audit_organizations.insert(audit.value.auditor_organization_id.clone()) {
            failures.insert("audit.duplicate-organization".to_string());
            continue;
        }
        if builder_owners.contains(&audit.value.auditor_identity) {
            failures.insert("audit.builder-owner-overlap".to_string());
            continue;
        }
        passing_audits += 1;
    }
    if passing_audits < audit_threshold {
        failures.insert("audit.insufficient-independent-audits".to_string());
    }

    let pinset_cids = availability
        .iter()
        .map(|item| item.value.pinset_cid.clone())
        .collect::<BTreeSet<_>>();
    required_content.extend(pinset_cids.iter().cloned());
    if pinset_cids.len() != 1 {
        failures.insert("availability.pinset-mismatch".to_string());
    }
    let mut availability_owners = BTreeSet::new();
    let mut availability_providers = BTreeSet::new();
    let mut complete_availability = 0usize;
    if availability.is_empty() {
        failures.insert("availability.none".to_string());
    }
    for item in availability {
        validate_evidence_cid(&item.cid, &mut evidence_cids, &mut failures, "availability")?;
        if item.value.candidate_ecosystem_cid != scope.candidate_ecosystem_cid {
            failures.insert("availability.candidate-mismatch".to_string());
            continue;
        }
        if !item.value.available {
            failures.insert("availability.unavailable".to_string());
            continue;
        }
        if item.value.expires_at_block < required_availability_through_block {
            failures.insert("availability.expires-too-early".to_string());
            continue;
        }
        let verified = item.value.verified_cids.iter().collect::<BTreeSet<_>>();
        if !required_content.iter().all(|cid| verified.contains(cid))
            || !verified.contains(&item.value.probe_result_cid)
        {
            failures.insert("availability.incomplete-content-coverage".to_string());
            continue;
        }
        if !availability_owners.insert(item.value.operator_identity.clone()) {
            failures.insert("availability.duplicate-owner".to_string());
            continue;
        }
        if !availability_providers.insert(item.value.provider_id.clone()) {
            failures.insert("availability.duplicate-provider".to_string());
            continue;
        }
        if audit_owners.contains(&item.value.operator_identity) {
            failures.insert("audit.availability-owner-overlap".to_string());
            continue;
        }
        complete_availability += 1;
    }
    if complete_availability < availability_threshold {
        failures.insert("availability.insufficient-independent-providers".to_string());
    }

    let required_content_cid_count = u32::try_from(required_content.len())
        .map_err(|_| ReadinessError::Invalid("required content set is too large".to_string()))?;
    let failure_codes = failures.into_iter().collect::<Vec<_>>();
    Ok(DeploymentReadinessReportV1 {
        schema_version: 1,
        candidate_ecosystem_cid: scope.candidate_ecosystem_cid.clone(),
        scope_evidence_cid: scope_evidence_cid.to_string(),
        risk_class: risk,
        ready: failure_codes.is_empty(),
        builder_threshold: builder_threshold as u32,
        matching_builder_count: matching_builders as u32,
        builder_platform_threshold: platform_threshold as u32,
        matching_builder_platform_count: matching_platforms as u32,
        selected_core_artifact_digest: selected_digest,
        availability_threshold: availability_threshold as u32,
        complete_availability_count: complete_availability as u32,
        external_audit_threshold: audit_threshold as u32,
        passing_external_audit_count: passing_audits as u32,
        required_content_cid_count,
        failure_codes,
    })
}

fn scope_required_content(
    scope_evidence_cid: &str,
    scope: &ProposalScopeEvidenceV1,
) -> BTreeSet<String> {
    let mut result = BTreeSet::from([
        scope_evidence_cid.to_string(),
        scope.parent_ecosystem_cid.clone(),
        scope.candidate_ecosystem_cid.clone(),
        scope.patch_cid.clone(),
    ]);
    for repository in &scope.repositories {
        result.extend([
            repository.base_source_cid.clone(),
            repository.candidate_source_cid.clone(),
            repository.patch_cid.clone(),
        ]);
    }
    result
}

fn validate_evidence_cid(
    value: &str,
    seen: &mut BTreeSet<String>,
    failures: &mut BTreeSet<String>,
    kind: &str,
) -> Result<(), ReadinessError> {
    validate_dag_cbor_cid(value, kind)?;
    if !seen.insert(value.to_string()) {
        failures.insert(format!("{kind}.duplicate-attestation-cid"));
    }
    Ok(())
}

fn validate_dag_cbor_cid(value: &str, label: &str) -> Result<(), ReadinessError> {
    let cid = Cid::try_from(value)
        .map_err(|_| ReadinessError::Invalid(format!("{label} CID is malformed")))?;
    if cid.version() != Version::V1
        || cid.codec() != DAG_CBOR_CODEC
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return Err(ReadinessError::Invalid(format!(
            "{label} CID must be canonical DAG-CBOR CIDv1/SHA2-256"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cid_for, core_artifact_set_digest, package_build_attestation,
        package_data_availability_attestation, package_external_audit_attestation,
        package_proposal_scope_evidence,
        source::{encode_source_manifest, encode_source_patch},
        BuildArtifactV1, CommandExecutionV1, RepositoryScopeEvidenceV1, ScopeChangeV1,
        SourceFileEntryV1, SourcePatchV1, SourceTreeManifestV1,
    };
    use sha2::{Digest, Sha256};

    fn dag(label: &str) -> String {
        cid_for(0x71, label.as_bytes()).to_string()
    }

    fn raw(label: &str) -> String {
        cid_for(0x55, label.as_bytes()).to_string()
    }

    fn address(index: u8) -> String {
        format!("0x{}", format!("{index:02x}").repeat(20))
    }

    fn command() -> CommandExecutionV1 {
        CommandExecutionV1 {
            command: "cargo test --workspace".to_string(),
            exit_code: 0,
            stdout_sha256: "11".repeat(32),
            stderr_sha256: "22".repeat(32),
        }
    }

    #[test]
    fn readiness_requires_independent_matching_builds_pins_and_external_audit() {
        let base_content = b"old documentation";
        let candidate_content = b"new documentation";
        let source_entry = |content: &[u8]| SourceFileEntryV1 {
            path: "docs/guide.md".to_string(),
            mode: 0o644,
            size: content.len() as u64,
            cid: cid_for(0x55, content).to_string(),
            sha256: hex::encode(Sha256::digest(content)),
        };
        let base_manifest = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "P2poolBTC".to_string(),
            files: vec![source_entry(base_content)],
        };
        let candidate_entry = source_entry(candidate_content);
        let candidate_manifest = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "P2poolBTC".to_string(),
            files: vec![candidate_entry.clone()],
        };
        let base_bytes = encode_source_manifest(&base_manifest).unwrap();
        let candidate_bytes = encode_source_manifest(&candidate_manifest).unwrap();
        let patch = SourcePatchV1 {
            schema_version: 1,
            kind: "pohw-source-patch-v1".to_string(),
            repository: "P2poolBTC".to_string(),
            base_source_cid: cid_for(0x71, &base_bytes).to_string(),
            candidate_source_cid: cid_for(0x71, &candidate_bytes).to_string(),
            removed_paths: vec![],
            upserted_files: vec![candidate_entry],
        };
        let patch_bytes = encode_source_patch(&patch).unwrap();
        let patch_cid = cid_for(0x71, &patch_bytes);
        let scope = ProposalScopeEvidenceV1 {
            schema_version: 1,
            classifier_version: crate::OBJECTIVE_RISK_CLASSIFIER_V2.to_string(),
            parent_ecosystem_cid: dag("parent"),
            candidate_ecosystem_cid: dag("candidate"),
            patch_cid: dag("aggregate-patch"),
            repositories: vec![RepositoryScopeEvidenceV1 {
                repository: "P2poolBTC".to_string(),
                base_source_cid: patch.base_source_cid.clone(),
                candidate_source_cid: patch.candidate_source_cid.clone(),
                patch_cid: patch_cid.to_string(),
                patch_sha256: hex::encode(patch_cid.hash().digest()),
                base_manifest_dag_cbor_hex: hex::encode(&base_bytes),
                candidate_manifest_dag_cbor_hex: hex::encode(&candidate_bytes),
                patch_dag_cbor_hex: hex::encode(&patch_bytes),
                patch_content_bytes: candidate_content.len() as u64,
                candidate_content_bytes: candidate_content.len() as u64,
                changes: vec![ScopeChangeV1 {
                    path: "docs/guide.md".to_string(),
                    change_kind: "upsert".to_string(),
                    size: candidate_content.len() as u64,
                }],
            }],
            rationale_bytes: 4,
            migration_notes_bytes: 0,
            test_plan_bytes: 5,
            changed_file_count: 1,
            patch_bytes: candidate_content.len() as u64,
            source_package_bytes: candidate_content.len() as u64,
            description_bytes: 9,
            migration_operation_count: 0,
            derived_risk_class: RiskClass::Normal,
        };
        let scope_package = package_proposal_scope_evidence(scope.clone()).unwrap();
        let scope_cid = scope_package.root_cid.to_string();
        let artifact_bytes = b"matching-core";
        let artifact = BuildArtifactV1 {
            name: "core".to_string(),
            cid: cid_for(0x55, artifact_bytes).to_string(),
            sha256: hex::encode(Sha256::digest(artifact_bytes)),
            size: artifact_bytes.len() as u64,
            core: true,
        };
        let digest = core_artifact_set_digest(std::slice::from_ref(&artifact)).unwrap();
        let builds = (1..=2)
            .map(|index| {
                let package = package_build_attestation(BuildAttestationV1 {
                    schema_version: 1,
                    candidate_ecosystem_cid: scope.candidate_ecosystem_cid.clone(),
                    source_cids: vec![RepositoryCidV1 {
                        repository: "P2poolBTC".to_string(),
                        cid: scope.repositories[0].candidate_source_cid.clone(),
                    }],
                    toolchain_cid: dag("toolchain"),
                    scope_evidence_cid: scope_cid.clone(),
                    builder_identity: address(index),
                    runtime_family: "linux".to_string(),
                    architecture: "x86_64".to_string(),
                    commands: vec![command()],
                    test_results_cid: raw(&format!("tests-{index}")),
                    tests_passed: true,
                    sbom_cid: raw(&format!("sbom-{index}")),
                    artifacts: vec![artifact.clone()],
                    core_artifact_digest: digest.clone(),
                    builder_bond_atoms: "1".to_string(),
                    creation_block_or_timestamp: 10,
                    authentication: "on-chain-submitter".to_string(),
                })
                .unwrap();
                AddressedAttestationV1 {
                    cid: package.root_cid.to_string(),
                    value: package.value,
                }
            })
            .collect::<Vec<_>>();
        let audit_package = package_external_audit_attestation(ExternalAuditAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: scope.candidate_ecosystem_cid.clone(),
            scope_evidence_cid: scope_cid.clone(),
            auditor_identity: address(3),
            auditor_organization_id: "audit-lab-a".to_string(),
            audit_policy_cid: dag("audit-policy"),
            report_cid: raw("audit-report"),
            independence_statement_cid: dag("audit-independence"),
            covered_repository_cids: vec![RepositoryCidV1 {
                repository: "P2poolBTC".to_string(),
                cid: scope.repositories[0].candidate_source_cid.clone(),
            }],
            unresolved_critical_findings: 0,
            unresolved_high_findings: 0,
            verdict: ExternalAuditVerdictV1::Pass,
            creation_block_or_timestamp: 11,
            authentication: "on-chain-submitter".to_string(),
        })
        .unwrap();
        let audits = vec![AddressedAttestationV1 {
            cid: audit_package.root_cid.to_string(),
            value: audit_package.value,
        }];
        let pinset_cid = dag("pinset");
        let mut required = scope_required_content(&scope_cid, &scope);
        required.insert(pinset_cid.clone());
        for build in &builds {
            required.extend([
                build.cid.clone(),
                build.value.toolchain_cid.clone(),
                build.value.test_results_cid.clone(),
                build.value.sbom_cid.clone(),
                build.value.artifacts[0].cid.clone(),
                build.value.source_cids[0].cid.clone(),
            ]);
        }
        for audit in &audits {
            required.extend([
                audit.cid.clone(),
                audit.value.audit_policy_cid.clone(),
                audit.value.report_cid.clone(),
                audit.value.independence_statement_cid.clone(),
                audit.value.covered_repository_cids[0].cid.clone(),
            ]);
        }
        let availability = (4..=5)
            .map(|index| {
                let probe = raw(&format!("probe-{index}"));
                let mut verified = required.clone();
                verified.insert(probe.clone());
                let package =
                    package_data_availability_attestation(DataAvailabilityAttestationV1 {
                        schema_version: 1,
                        candidate_ecosystem_cid: scope.candidate_ecosystem_cid.clone(),
                        pinset_cid: pinset_cid.clone(),
                        provider_id: format!("provider-{index}"),
                        operator_identity: address(index),
                        verified_cids: verified.into_iter().collect(),
                        probe_result_cid: probe,
                        available: true,
                        observed_at_block_or_timestamp: 12,
                        expires_at_block: 100,
                        bond_atoms: "1".to_string(),
                        authentication: "on-chain-submitter".to_string(),
                    })
                    .unwrap();
                AddressedAttestationV1 {
                    cid: package.root_cid.to_string(),
                    value: package.value,
                }
            })
            .collect::<Vec<_>>();

        let report =
            evaluate_deployment_readiness(&scope_cid, &scope, &builds, &availability, &audits, 90)
                .unwrap();
        assert!(report.ready, "{:?}", report.failure_codes);

        let report =
            evaluate_deployment_readiness(&scope_cid, &scope, &builds, &availability, &[], 90)
                .unwrap();
        assert!(!report.ready);
        assert!(report
            .failure_codes
            .contains(&"audit.insufficient-independent-audits".to_string()));
    }
}
