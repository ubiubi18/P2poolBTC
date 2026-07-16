use crate::{
    normalize_address, package_dag_cbor, verify_dag_cbor_car, DagCborPackage, SourceError,
};
use bitcoin::secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

const SHA2_256_CODE: u64 = 0x12;
const CORE_ARTIFACT_SET_DOMAIN: &[u8] = b"IDENA_GOV_CORE_ARTIFACT_SET_V1\0";
const MAX_PORTABLE_ARTIFACT_SIZE: u64 = 9_007_199_254_740_991;
const MAX_REPOSITORY_CIDS: usize = 64;
const MAX_TOOL_VERSIONS: usize = 256;
const MAX_BUILD_ARTIFACTS: usize = 4_096;
const MAX_VERIFIED_CIDS: usize = 4_096;
const MAX_ARTIFACT_NAME_BYTES: usize = 128;
const MAX_CONTRACT_DAG_CBOR_BYTES: usize = 65_536;
const ATTESTATION_AUTHENTICATION_DOMAIN: &[u8] = b"IDENA_GOV_ATTESTATION_AUTH_V1\0";
const ATTESTATION_SIGNIN_PREFIX: &str = "signin-pohw1-governance-attestation-";
const IDENA_RECOVERABLE_SIGNATURE_HEX_LEN: usize = 130;
pub const DETACHED_IDENA_SIGNATURE_AUTHENTICATION: &str = "detached-idena-signature-v1";
pub const ON_CHAIN_SUBMITTER_AUTHENTICATION: &str = "on-chain-submitter";
pub const EXTERNAL_AUDIT_ATTESTATION_DOMAIN: &str = "external_audit_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryCidV1 {
    pub repository: String,
    pub cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandExecutionV1 {
    pub command: String,
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityFindingV1 {
    pub severity: FindingSeverity,
    pub summary: String,
    pub evidence_cid: Option<String>,
    pub resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewVerdictV1 {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternalAuditVerdictV1 {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentReviewAttestationV1 {
    pub schema_version: u16,
    pub parent_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub patch_cid: String,
    pub affected_repositories: Vec<RepositoryCidV1>,
    pub model_identifier: String,
    pub model_revision: Option<String>,
    pub provider_or_runtime_identifier: String,
    pub model_family: String,
    pub agent_policy_cid: String,
    pub system_prompt_policy_cid: String,
    pub tool_versions: BTreeMap<String, String>,
    pub commands_executed: Vec<CommandExecutionV1>,
    pub test_results_cid: String,
    pub tests_passed: bool,
    pub static_analysis_results_cid: String,
    pub dependency_findings_cid: String,
    pub security_findings: Vec<SecurityFindingV1>,
    pub unresolved_critical_findings: u32,
    pub verdict: ReviewVerdictV1,
    pub owner_idena_address: String,
    pub reviewer_bond_atoms: String,
    pub creation_block_or_timestamp: u64,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildArtifactV1 {
    pub name: String,
    pub cid: String,
    pub sha256: String,
    pub size: u64,
    pub core: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildAttestationV1 {
    pub schema_version: u16,
    pub candidate_ecosystem_cid: String,
    pub source_cids: Vec<RepositoryCidV1>,
    pub toolchain_cid: String,
    pub scope_evidence_cid: String,
    pub builder_identity: String,
    pub runtime_family: String,
    pub architecture: String,
    pub commands: Vec<CommandExecutionV1>,
    pub test_results_cid: String,
    pub tests_passed: bool,
    pub sbom_cid: String,
    pub artifacts: Vec<BuildArtifactV1>,
    pub core_artifact_digest: String,
    pub builder_bond_atoms: String,
    pub creation_block_or_timestamp: u64,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataAvailabilityAttestationV1 {
    pub schema_version: u16,
    pub candidate_ecosystem_cid: String,
    pub pinset_cid: String,
    pub provider_id: String,
    pub operator_identity: String,
    pub verified_cids: Vec<String>,
    pub probe_result_cid: String,
    pub available: bool,
    pub observed_at_block_or_timestamp: u64,
    pub expires_at_block: u64,
    pub bond_atoms: String,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalAuditAttestationV1 {
    pub schema_version: u16,
    pub candidate_ecosystem_cid: String,
    pub scope_evidence_cid: String,
    pub auditor_identity: String,
    pub auditor_organization_id: String,
    pub audit_policy_cid: String,
    pub report_cid: String,
    pub independence_statement_cid: String,
    pub covered_repository_cids: Vec<RepositoryCidV1>,
    pub unresolved_critical_findings: u32,
    pub unresolved_high_findings: u32,
    pub verdict: ExternalAuditVerdictV1,
    pub creation_block_or_timestamp: u64,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityMetricsAttestationV1 {
    pub schema_version: u16,
    pub metrics_root: String,
    pub snapshot_cid: String,
    pub snapshot_sha256: String,
    pub source_epoch: u16,
    pub source_block_height: u64,
    pub source_block_hash: String,
    pub replay_start_height: u64,
    pub replay_commitment: String,
    pub indexer_implementation_cid: String,
    pub operator_idena_address: String,
    pub observed_at_block_or_timestamp: u64,
    pub authentication: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationAuthenticationRequestV1 {
    pub schema_version: u16,
    pub attestation_kind: String,
    pub attestation_cid: String,
    pub attestation_sha256: String,
    pub candidate_ecosystem_cid: String,
    pub identity: String,
    pub binding_sha256: String,
    pub challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationAuthenticationV1 {
    pub schema_version: u16,
    pub attestation_kind: String,
    pub attestation_cid: String,
    pub attestation_sha256: String,
    pub candidate_ecosystem_cid: String,
    pub identity: String,
    pub binding_sha256: String,
    pub proof: AttestationAuthenticationProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub enum AttestationAuthenticationProofV1 {
    #[serde(rename = "idena-signature-v1")]
    IdenaSignature {
        #[serde(rename = "signatureHex")]
        signature_hex: String,
    },
    #[serde(rename = "finalized-on-chain-receipt-v1")]
    FinalizedOnChainReceipt {
        receipt: FinalizedOnChainAttestationReceiptV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedOnChainAttestationReceiptV1 {
    pub schema_version: u16,
    pub chain_id: String,
    pub contract_address: String,
    pub transaction_hash: String,
    pub transaction_block_height: u64,
    pub transaction_block_hash: String,
    pub finalized_at_height: u64,
    pub finality_confirmations: u64,
    pub submitter_identity: String,
    pub call_data_commitment: String,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct AttestationPackage<T> {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub value: T,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation is invalid: {0}")]
    Invalid(String),
    #[error(transparent)]
    Source(#[from] SourceError),
}

pub fn attestation_authentication_request(
    attestation_kind: &str,
    attestation_cid: &str,
    attestation_sha256: &str,
    candidate_ecosystem_cid: &str,
    identity: &str,
) -> Result<AttestationAuthenticationRequestV1, AttestationError> {
    validate_attestation_kind(attestation_kind)?;
    let cid = validate_dag_cbor_cid(attestation_cid, "attestationCid")?;
    validate_sha256(attestation_sha256)?;
    if hex::encode(cid.hash().digest()) != attestation_sha256 {
        return invalid("attestationCid and attestationSha256 disagree");
    }
    validate_dag_cbor_cid(candidate_ecosystem_cid, "candidateEcosystemCid")?;
    let identity = normalize_attestation_address(identity)?;
    let binding_sha256 = attestation_authentication_binding_sha256(
        attestation_kind,
        attestation_cid,
        attestation_sha256,
        candidate_ecosystem_cid,
        &identity,
    )?;
    Ok(AttestationAuthenticationRequestV1 {
        schema_version: 1,
        attestation_kind: attestation_kind.to_string(),
        attestation_cid: attestation_cid.to_string(),
        attestation_sha256: attestation_sha256.to_string(),
        candidate_ecosystem_cid: candidate_ecosystem_cid.to_string(),
        identity,
        challenge: format!("{ATTESTATION_SIGNIN_PREFIX}{binding_sha256}"),
        binding_sha256,
    })
}

pub fn signature_attestation_authentication(
    request: &AttestationAuthenticationRequestV1,
    signature_hex: impl Into<String>,
) -> Result<AttestationAuthenticationV1, AttestationError> {
    validate_authentication_request(request)?;
    let authentication = authentication_for_request(
        request,
        AttestationAuthenticationProofV1::IdenaSignature {
            signature_hex: signature_hex.into(),
        },
    );
    verify_attestation_authentication(
        request,
        DETACHED_IDENA_SIGNATURE_AUTHENTICATION,
        &authentication,
    )?;
    Ok(authentication)
}

pub fn receipt_attestation_authentication(
    request: &AttestationAuthenticationRequestV1,
    _receipt: FinalizedOnChainAttestationReceiptV1,
) -> Result<AttestationAuthenticationV1, AttestationError> {
    validate_authentication_request(request)?;
    invalid(
        "on-chain receipt authentication is disabled until an authenticated Idena inclusion and finality proof verifier is available",
    )
}

pub fn verify_attestation_authentication(
    expected: &AttestationAuthenticationRequestV1,
    authentication_intent: &str,
    authentication: &AttestationAuthenticationV1,
) -> Result<(), AttestationError> {
    validate_authentication_request(expected)?;
    if authentication.schema_version != 1
        || authentication.attestation_kind != expected.attestation_kind
        || authentication.attestation_cid != expected.attestation_cid
        || authentication.attestation_sha256 != expected.attestation_sha256
        || authentication.candidate_ecosystem_cid != expected.candidate_ecosystem_cid
        || authentication.identity != expected.identity
        || authentication.binding_sha256 != expected.binding_sha256
    {
        return invalid(
            "authentication does not bind the exact attestation kind, CID, content, candidate, and identity",
        );
    }
    match &authentication.proof {
        AttestationAuthenticationProofV1::IdenaSignature { signature_hex } => {
            if authentication_intent != DETACHED_IDENA_SIGNATURE_AUTHENTICATION {
                return invalid(
                    "signature proof contradicts the attestation authentication intent",
                );
            }
            let recovered = recover_idena_signin_address(&expected.challenge, signature_hex)?;
            if recovered != expected.identity {
                return invalid("Idena signature does not recover the attested identity");
            }
        }
        AttestationAuthenticationProofV1::FinalizedOnChainReceipt { receipt } => {
            if authentication_intent != ON_CHAIN_SUBMITTER_AUTHENTICATION {
                return invalid(
                    "on-chain receipt contradicts the attestation authentication intent",
                );
            }
            let _ = receipt;
            return invalid(
                "on-chain receipt authentication is disabled until an authenticated Idena inclusion and finality proof verifier is available",
            );
        }
    }
    Ok(())
}

fn authentication_for_request(
    request: &AttestationAuthenticationRequestV1,
    proof: AttestationAuthenticationProofV1,
) -> AttestationAuthenticationV1 {
    AttestationAuthenticationV1 {
        schema_version: 1,
        attestation_kind: request.attestation_kind.clone(),
        attestation_cid: request.attestation_cid.clone(),
        attestation_sha256: request.attestation_sha256.clone(),
        candidate_ecosystem_cid: request.candidate_ecosystem_cid.clone(),
        identity: request.identity.clone(),
        binding_sha256: request.binding_sha256.clone(),
        proof,
    }
}

pub fn package_agent_review_attestation(
    mut value: AgentReviewAttestationV1,
) -> Result<AttestationPackage<AgentReviewAttestationV1>, AttestationError> {
    value.owner_idena_address = normalize_attestation_address(&value.owner_idena_address)?;
    validate_agent_review(&value)?;
    package(value)
}

pub fn verify_agent_review_attestation_car(
    bytes: &[u8],
) -> Result<AttestationPackage<AgentReviewAttestationV1>, AttestationError> {
    verify_package(bytes, validate_agent_review)
}

pub fn package_build_attestation(
    mut value: BuildAttestationV1,
) -> Result<AttestationPackage<BuildAttestationV1>, AttestationError> {
    value.builder_identity = normalize_attestation_address(&value.builder_identity)?;
    validate_build(&value)?;
    package(value)
}

pub fn verify_build_attestation_car(
    bytes: &[u8],
) -> Result<AttestationPackage<BuildAttestationV1>, AttestationError> {
    verify_package(bytes, validate_build)
}

pub fn package_data_availability_attestation(
    mut value: DataAvailabilityAttestationV1,
) -> Result<AttestationPackage<DataAvailabilityAttestationV1>, AttestationError> {
    value.operator_identity = normalize_attestation_address(&value.operator_identity)?;
    validate_availability(&value)?;
    package(value)
}

pub fn verify_data_availability_attestation_car(
    bytes: &[u8],
) -> Result<AttestationPackage<DataAvailabilityAttestationV1>, AttestationError> {
    verify_package(bytes, validate_availability)
}

pub fn package_external_audit_attestation(
    mut value: ExternalAuditAttestationV1,
) -> Result<AttestationPackage<ExternalAuditAttestationV1>, AttestationError> {
    value.auditor_identity = normalize_attestation_address(&value.auditor_identity)?;
    validate_external_audit(&value)?;
    package(value)
}

pub fn verify_external_audit_attestation_car(
    bytes: &[u8],
) -> Result<AttestationPackage<ExternalAuditAttestationV1>, AttestationError> {
    verify_package(bytes, validate_external_audit)
}

pub fn package_identity_metrics_attestation(
    mut value: IdentityMetricsAttestationV1,
) -> Result<AttestationPackage<IdentityMetricsAttestationV1>, AttestationError> {
    value.operator_idena_address = normalize_attestation_address(&value.operator_idena_address)?;
    validate_identity_metrics_attestation(&value)?;
    package(value)
}

pub fn verify_identity_metrics_attestation_car(
    bytes: &[u8],
) -> Result<AttestationPackage<IdentityMetricsAttestationV1>, AttestationError> {
    verify_package(bytes, validate_identity_metrics_attestation)
}

fn package<T>(value: T) -> Result<AttestationPackage<T>, AttestationError>
where
    T: Clone + Serialize + for<'de> Deserialize<'de>,
{
    let package = package_dag_cbor(value.clone())?;
    if package.dag_cbor_bytes.len() > MAX_CONTRACT_DAG_CBOR_BYTES {
        return invalid("attestation DAG-CBOR exceeds the contract payload limit");
    }
    Ok(AttestationPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        value,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

fn verify_package<T>(
    bytes: &[u8],
    validate: fn(&T) -> Result<(), AttestationError>,
) -> Result<AttestationPackage<T>, AttestationError>
where
    T: Clone + Serialize + for<'de> Deserialize<'de>,
{
    let package: DagCborPackage<T> = verify_dag_cbor_car(bytes)?;
    if package.dag_cbor_bytes.len() > MAX_CONTRACT_DAG_CBOR_BYTES {
        return invalid("attestation DAG-CBOR exceeds the contract payload limit");
    }
    validate(&package.value)?;
    Ok(AttestationPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        value: package.value,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

fn validate_agent_review(value: &AgentReviewAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    for (cid, field) in [
        (&value.parent_ecosystem_cid, "parentEcosystemCid"),
        (&value.candidate_ecosystem_cid, "candidateEcosystemCid"),
        (&value.patch_cid, "patchCid"),
    ] {
        validate_dag_cbor_cid(cid, field)?;
    }
    for cid in [
        &value.agent_policy_cid,
        &value.system_prompt_policy_cid,
        &value.static_analysis_results_cid,
        &value.dependency_findings_cid,
    ] {
        validate_content_cid(cid)?;
    }
    validate_raw_cid(&value.test_results_cid, "testResultsCid")?;
    validate_repository_cids(&value.affected_repositories)?;
    validate_text(&value.model_identifier, 1, 160, "modelIdentifier")?;
    if let Some(revision) = &value.model_revision {
        validate_text(revision, 1, 160, "modelRevision")?;
    }
    validate_text(
        &value.provider_or_runtime_identifier,
        1,
        160,
        "providerOrRuntimeIdentifier",
    )?;
    validate_lower_label(&value.model_family, 64, "modelFamily")?;
    validate_string_map(&value.tool_versions, "toolVersions")?;
    validate_commands(&value.commands_executed, value.tests_passed)?;
    if value.security_findings.len() > 10_000 {
        return invalid("securityFindings exceeds the deterministic limit");
    }
    for finding in &value.security_findings {
        validate_text(&finding.summary, 1, 4_096, "finding summary")?;
        if finding.severity == FindingSeverity::Critical
            && !finding.resolved
            && finding.evidence_cid.is_none()
        {
            return invalid("unresolved critical findings require immutable evidence");
        }
        if let Some(cid) = &finding.evidence_cid {
            validate_content_cid(cid)?;
        }
    }
    let unresolved = value
        .security_findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::Critical && !finding.resolved)
        .count();
    if unresolved > u32::MAX as usize || value.unresolved_critical_findings != unresolved as u32 {
        return invalid("unresolvedCriticalFindings does not match securityFindings");
    }
    normalize_attestation_address(&value.owner_idena_address)?;
    validate_amount(&value.reviewer_bond_atoms)?;
    validate_authentication(&value.authentication)
}

fn validate_build(value: &BuildAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_dag_cbor_cid(&value.candidate_ecosystem_cid, "candidateEcosystemCid")?;
    validate_dag_cbor_cid(&value.toolchain_cid, "toolchainCid")?;
    validate_dag_cbor_cid(&value.scope_evidence_cid, "scopeEvidenceCid")?;
    validate_raw_cid(&value.sbom_cid, "sbomCid")?;
    validate_raw_cid(&value.test_results_cid, "testResultsCid")?;
    validate_repository_cids(&value.source_cids)?;
    normalize_attestation_address(&value.builder_identity)?;
    validate_lower_label(&value.runtime_family, 31, "runtimeFamily")?;
    validate_lower_label(&value.architecture, 31, "architecture")?;
    validate_commands(&value.commands, value.tests_passed)?;
    validate_sha256(&value.core_artifact_digest)?;
    if value.artifacts.is_empty() || value.artifacts.len() > MAX_BUILD_ARTIFACTS {
        return invalid("artifacts must contain between 1 and 4096 entries");
    }
    let mut previous = None;
    for artifact in &value.artifacts {
        validate_artifact_name(&artifact.name)?;
        if previous.is_some_and(|name: &str| name >= artifact.name.as_str()) {
            return invalid("artifacts must be uniquely sorted by name");
        }
        previous = Some(artifact.name.as_str());
        let cid = validate_raw_cid(&artifact.cid, "artifact CID")?;
        validate_sha256(&artifact.sha256)?;
        if hex::encode(cid.hash().digest()) != artifact.sha256 {
            return invalid("artifact CID and SHA-256 disagree");
        }
        if artifact.size > MAX_PORTABLE_ARTIFACT_SIZE {
            return invalid("artifact size exceeds the portable integer limit");
        }
    }
    if core_artifact_set_digest(&value.artifacts)? != value.core_artifact_digest {
        return invalid("coreArtifactDigest does not match the declared core artifact set");
    }
    validate_amount(&value.builder_bond_atoms)?;
    validate_authentication(&value.authentication)
}

pub fn core_artifact_set_digest(artifacts: &[BuildArtifactV1]) -> Result<String, AttestationError> {
    let mut core = artifacts
        .iter()
        .filter(|artifact| artifact.core)
        .collect::<Vec<_>>();
    core.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let core_count = u32::try_from(core.len())
        .map_err(|_| AttestationError::Invalid("too many core artifacts".to_owned()))?;
    if core_count == 0 {
        return invalid("at least one core artifact is required");
    }

    let mut hasher = Sha256::new();
    hasher.update(CORE_ARTIFACT_SET_DOMAIN);
    hasher.update(core_count.to_be_bytes());
    for artifact in core {
        update_length_prefixed(&mut hasher, artifact.name.as_bytes(), "artifact name")?;
        update_length_prefixed(&mut hasher, artifact.cid.as_bytes(), "artifact CID")?;
        let digest = hex::decode(&artifact.sha256)
            .map_err(|_| AttestationError::Invalid("artifact SHA-256 is invalid".to_owned()))?;
        if digest.len() != 32 {
            return invalid("artifact SHA-256 is invalid");
        }
        hasher.update(digest);
        hasher.update(artifact.size.to_be_bytes());
    }
    Ok(hex::encode(hasher.finalize()))
}

fn update_length_prefixed(
    hasher: &mut Sha256,
    value: &[u8],
    field: &str,
) -> Result<(), AttestationError> {
    let length = u32::try_from(value.len())
        .map_err(|_| AttestationError::Invalid(format!("{field} is too large")))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn attestation_authentication_binding_sha256(
    attestation_kind: &str,
    attestation_cid: &str,
    attestation_sha256: &str,
    candidate_ecosystem_cid: &str,
    identity: &str,
) -> Result<String, AttestationError> {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTATION_AUTHENTICATION_DOMAIN);
    for (value, field) in [
        (attestation_kind, "attestation kind"),
        (attestation_cid, "attestation CID"),
        (attestation_sha256, "attestation SHA-256"),
        (candidate_ecosystem_cid, "candidate ecosystem CID"),
        (identity, "attested identity"),
    ] {
        update_length_prefixed(&mut hasher, value.as_bytes(), field)?;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_authentication_request(
    request: &AttestationAuthenticationRequestV1,
) -> Result<(), AttestationError> {
    if request.schema_version != 1 {
        return invalid("authentication request schemaVersion must be 1");
    }
    let expected = attestation_authentication_request(
        &request.attestation_kind,
        &request.attestation_cid,
        &request.attestation_sha256,
        &request.candidate_ecosystem_cid,
        &request.identity,
    )?;
    if &expected != request {
        return invalid("authentication request binding or challenge is not canonical");
    }
    Ok(())
}

fn validate_attestation_kind(value: &str) -> Result<(), AttestationError> {
    if !matches!(
        value,
        "agent_review_v1"
            | "build_attestation_v1"
            | "data_availability_v1"
            | EXTERNAL_AUDIT_ATTESTATION_DOMAIN
    ) {
        return invalid("unsupported attestation authentication kind");
    }
    Ok(())
}

fn recover_idena_signin_address(
    challenge: &str,
    signature_hex: &str,
) -> Result<String, AttestationError> {
    let normalized = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    if normalized.len() != IDENA_RECOVERABLE_SIGNATURE_HEX_LEN
        || normalized.bytes().any(|byte| !byte.is_ascii_hexdigit())
    {
        return invalid("Idena signature must be 65 bytes encoded as hexadecimal");
    }
    let bytes = hex::decode(normalized)
        .map_err(|_| AttestationError::Invalid("Idena signature is invalid".to_string()))?;
    let recovery_id = idena_recovery_id(bytes[64])?;
    let signature = RecoverableSignature::from_compact(&bytes[..64], recovery_id)
        .map_err(|_| AttestationError::Invalid("Idena signature is invalid".to_string()))?;
    let message = Message::from_digest(idena_signin_hash(challenge));
    let public_key = Secp256k1::verification_only()
        .recover_ecdsa(&message, &signature)
        .map_err(|_| AttestationError::Invalid("Idena signature recovery failed".to_string()))?;
    Ok(idena_address_from_pubkey(&public_key))
}

fn idena_recovery_id(value: u8) -> Result<RecoveryId, AttestationError> {
    let id = match value {
        0..=3 => i32::from(value),
        27..=30 => i32::from(value - 27),
        _ => return invalid("Idena signature has an unsupported recovery id"),
    };
    RecoveryId::from_i32(id).map_err(|_| {
        AttestationError::Invalid("Idena signature recovery id is invalid".to_string())
    })
}

fn idena_signin_hash(challenge: &str) -> [u8; 32] {
    keccak256(&keccak256(challenge.as_bytes()))
}

fn idena_address_from_pubkey(public_key: &PublicKey) -> String {
    let serialized = public_key.serialize_uncompressed();
    let hash = keccak256(&serialized[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

fn keccak256(value: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(value);
    hasher.finalize(&mut output);
    output
}

fn validate_availability(value: &DataAvailabilityAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_dag_cbor_cid(&value.candidate_ecosystem_cid, "candidateEcosystemCid")?;
    validate_dag_cbor_cid(&value.pinset_cid, "pinsetCid")?;
    validate_raw_cid(&value.probe_result_cid, "probeResultCid")?;
    validate_safe_label(&value.provider_id, 80, "providerId")?;
    normalize_attestation_address(&value.operator_identity)?;
    if value.verified_cids.is_empty()
        || value.verified_cids.len() > MAX_VERIFIED_CIDS
        || !value
            .verified_cids
            .iter()
            .any(|cid| cid == &value.candidate_ecosystem_cid)
        || !value
            .verified_cids
            .iter()
            .any(|cid| cid == &value.probe_result_cid)
        || !strict_sorted_unique(&value.verified_cids)
    {
        return invalid(
            "verifiedCids must be sorted, unique, and include the candidate and probe-result CIDs",
        );
    }
    for cid in &value.verified_cids {
        validate_content_cid(cid)?;
    }
    if value.expires_at_block <= value.observed_at_block_or_timestamp {
        return invalid("expiresAtBlock must be later than the observation boundary");
    }
    validate_amount(&value.bond_atoms)?;
    validate_authentication(&value.authentication)
}

fn validate_external_audit(value: &ExternalAuditAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_dag_cbor_cid(&value.candidate_ecosystem_cid, "candidateEcosystemCid")?;
    validate_dag_cbor_cid(&value.scope_evidence_cid, "scopeEvidenceCid")?;
    validate_lower_label(&value.auditor_organization_id, 80, "auditorOrganizationId")?;
    normalize_attestation_address(&value.auditor_identity)?;
    for cid in [
        &value.audit_policy_cid,
        &value.report_cid,
        &value.independence_statement_cid,
    ] {
        validate_content_cid(cid)?;
    }
    validate_repository_cids(&value.covered_repository_cids)?;
    if value.verdict == ExternalAuditVerdictV1::Pass
        && (value.unresolved_critical_findings != 0 || value.unresolved_high_findings != 0)
    {
        return invalid(
            "a passing external audit cannot contain unresolved high or critical findings",
        );
    }
    validate_authentication(&value.authentication)
}

fn validate_identity_metrics_attestation(
    value: &IdentityMetricsAttestationV1,
) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    for digest in [
        &value.metrics_root,
        &value.snapshot_sha256,
        &value.source_block_hash,
        &value.replay_commitment,
    ] {
        validate_sha256(digest)?;
    }
    let snapshot_cid = validate_cid(&value.snapshot_cid)?;
    if snapshot_cid.codec() != 0x71 {
        return invalid("snapshotCid must use canonical DAG-CBOR");
    }
    if hex::encode(snapshot_cid.hash().digest()) != value.snapshot_sha256 {
        return invalid("snapshotCid and snapshotSha256 disagree");
    }
    let implementation_cid = validate_cid(&value.indexer_implementation_cid)?;
    if implementation_cid.codec() != 0x71 {
        return invalid("indexerImplementationCid must use canonical DAG-CBOR");
    }
    normalize_attestation_address(&value.operator_idena_address)?;
    if value.replay_start_height > value.source_block_height {
        return invalid("replayStartHeight exceeds sourceBlockHeight");
    }
    validate_authentication(&value.authentication)
}

fn validate_repository_cids(values: &[RepositoryCidV1]) -> Result<(), AttestationError> {
    if values.is_empty() || values.len() > MAX_REPOSITORY_CIDS {
        return invalid("repository CID list must contain between 1 and 64 entries");
    }
    let mut previous = None;
    for value in values {
        validate_safe_label(&value.repository, 80, "repository")?;
        validate_dag_cbor_cid(&value.cid, "repository source CID")?;
        if previous.is_some_and(|name: &str| name >= value.repository.as_str()) {
            return invalid("repository CID list must be uniquely sorted by repository");
        }
        previous = Some(value.repository.as_str());
    }
    Ok(())
}

fn validate_commands(
    values: &[CommandExecutionV1],
    require_success: bool,
) -> Result<(), AttestationError> {
    if values.is_empty() || values.len() > 2_000 {
        return invalid("command log must contain between 1 and 2000 commands");
    }
    for value in values {
        if require_success && value.exit_code != 0 {
            return invalid("testsPassed contradicts a nonzero command exit code");
        }
        validate_text(&value.command, 1, 8_192, "command")?;
        validate_sha256(&value.stdout_sha256)?;
        validate_sha256(&value.stderr_sha256)?;
        reject_unredacted_secret(&value.command)?;
    }
    Ok(())
}

fn reject_unredacted_secret(value: &str) -> Result<(), AttestationError> {
    let lower = value.to_ascii_lowercase();
    let assignments = [
        "private_key=",
        "private-key=",
        "api_key=",
        "apikey=",
        "auth_token=",
        "access_token=",
        "secret_key=",
        "--password=",
        "--token=",
    ];
    if assignments
        .iter()
        .any(|needle| has_unredacted_assignment(value, &lower, needle))
        || ["tskey-", "ghp_", "github_pat_"]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        return invalid("command log appears to contain an unredacted secret");
    }
    Ok(())
}

fn has_unredacted_assignment(value: &str, lower: &str, needle: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = lower[offset..].find(needle) {
        let value_offset = offset + relative + needle.len();
        let suffix = &value[value_offset..];
        let Some(rest) = suffix.strip_prefix("[REDACTED]") else {
            return true;
        };
        if rest
            .chars()
            .next()
            .is_some_and(|character| !is_redaction_boundary(character))
        {
            return true;
        }
        offset = value_offset;
    }
    false
}

fn is_redaction_boundary(value: char) -> bool {
    value.is_ascii_whitespace()
        || matches!(value, '\'' | '"' | ';' | '|' | '&' | ')' | ']' | '}' | ',')
}

fn validate_string_map(
    values: &BTreeMap<String, String>,
    field: &str,
) -> Result<(), AttestationError> {
    if values.is_empty() || values.len() > MAX_TOOL_VERSIONS {
        return invalid(&format!("{field} must contain between 1 and 256 entries"));
    }
    for (key, value) in values {
        validate_safe_label(key, 80, field)?;
        validate_text(value, 1, 160, field)?;
    }
    Ok(())
}

fn validate_authentication(value: &str) -> Result<(), AttestationError> {
    if !matches!(
        value,
        ON_CHAIN_SUBMITTER_AUTHENTICATION | DETACHED_IDENA_SIGNATURE_AUTHENTICATION
    ) {
        return invalid(
            "authentication must declare an on-chain submitter or detached Idena signature",
        );
    }
    Ok(())
}

fn validate_amount(value: &str) -> Result<(), AttestationError> {
    if value.is_empty()
        || value.len() > 39
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || value.parse::<u128>().is_err()
    {
        return invalid("atomic amount is invalid");
    }
    Ok(())
}

fn validate_cid(value: &str) -> Result<Cid, AttestationError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| AttestationError::Invalid(format!("invalid CID: {value}")))?;
    if cid.version() != Version::V1
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return invalid("CID must be CIDv1 base32 with SHA2-256");
    }
    Ok(cid)
}

fn validate_raw_cid(value: &str, field: &str) -> Result<Cid, AttestationError> {
    let cid = validate_cid(value)?;
    if cid.codec() != 0x55 {
        return invalid(&format!("{field} must use the raw multicodec"));
    }
    Ok(cid)
}

fn validate_dag_cbor_cid(value: &str, field: &str) -> Result<Cid, AttestationError> {
    let cid = validate_cid(value)?;
    if cid.codec() != 0x71 {
        return invalid(&format!("{field} must use the DAG-CBOR multicodec"));
    }
    Ok(cid)
}

fn validate_content_cid(value: &str) -> Result<Cid, AttestationError> {
    let cid = validate_cid(value)?;
    if !matches!(cid.codec(), 0x55 | 0x71) {
        return invalid("content CID must use the raw or DAG-CBOR multicodec");
    }
    Ok(cid)
}

fn normalize_attestation_address(value: &str) -> Result<String, AttestationError> {
    normalize_address(value)
        .map_err(|_| AttestationError::Invalid("invalid Idena address".to_string()))
}

fn validate_sha256(value: &str) -> Result<(), AttestationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return invalid("SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_safe_label(
    value: &str,
    max_length: usize,
    field: &str,
) -> Result<(), AttestationError> {
    if value.is_empty()
        || value.len() > max_length
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
        })
    {
        return invalid(&format!("{field} is not a safe deterministic label"));
    }
    Ok(())
}

fn validate_lower_label(
    value: &str,
    max_length: usize,
    field: &str,
) -> Result<(), AttestationError> {
    if value.is_empty()
        || value.len() > max_length
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_')
        })
    {
        return invalid(&format!("{field} is not a lowercase deterministic label"));
    }
    Ok(())
}

fn validate_artifact_name(value: &str) -> Result<(), AttestationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ARTIFACT_NAME_BYTES
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return invalid("artifact name is not a portable deterministic label");
    }
    Ok(())
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &str,
) -> Result<(), AttestationError> {
    if value.len() < minimum
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return invalid(&format!("{field} contains invalid text"));
    }
    Ok(())
}

fn strict_sorted_unique(values: &[String]) -> bool {
    let mut previous = None;
    let mut seen = BTreeSet::new();
    for value in values {
        if previous.is_some_and(|item: &str| item >= value.as_str()) || !seen.insert(value) {
            return false;
        }
        previous = Some(value.as_str());
    }
    true
}

fn invalid<T>(message: &str) -> Result<T, AttestationError> {
    Err(AttestationError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid_for;
    use bitcoin::secp256k1::{PublicKey, SecretKey};

    fn cid(label: &str) -> String {
        cid_for(0x71, label.as_bytes()).to_string()
    }

    fn raw_cid(label: &str) -> String {
        cid_for(0x55, label.as_bytes()).to_string()
    }

    fn cid_sha256(value: &str) -> String {
        let parsed: Cid = value.parse().unwrap();
        hex::encode(parsed.hash().digest())
    }

    fn command() -> CommandExecutionV1 {
        CommandExecutionV1 {
            command: "cargo test --workspace".to_string(),
            exit_code: 0,
            stdout_sha256: "11".repeat(32),
            stderr_sha256: "22".repeat(32),
        }
    }

    fn identity_for(secret_key: &SecretKey) -> String {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        idena_address_from_pubkey(&public_key)
    }

    fn sign_authentication_request(
        request: &AttestationAuthenticationRequestV1,
        secret_key: &SecretKey,
    ) -> String {
        let signature = Secp256k1::new().sign_ecdsa_recoverable(
            &Message::from_digest(idena_signin_hash(&request.challenge)),
            secret_key,
        );
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(recovery_id.to_i32() as u8 + 27);
        hex::encode(bytes)
    }

    fn agent_attestation() -> AgentReviewAttestationV1 {
        AgentReviewAttestationV1 {
            schema_version: 1,
            parent_ecosystem_cid: cid("parent"),
            candidate_ecosystem_cid: cid("candidate"),
            patch_cid: cid("patch"),
            affected_repositories: vec![RepositoryCidV1 {
                repository: "P2poolBTC".to_string(),
                cid: cid("source"),
            }],
            model_identifier: "review-model".to_string(),
            model_revision: Some("2026-07".to_string()),
            provider_or_runtime_identifier: "local-runtime".to_string(),
            model_family: "family-a".to_string(),
            agent_policy_cid: cid("agent-policy"),
            system_prompt_policy_cid: cid("prompt-policy"),
            tool_versions: BTreeMap::from([("cargo".to_string(), "1.96.1".to_string())]),
            commands_executed: vec![command()],
            test_results_cid: raw_cid("tests"),
            tests_passed: true,
            static_analysis_results_cid: cid("static"),
            dependency_findings_cid: cid("dependencies"),
            security_findings: vec![],
            unresolved_critical_findings: 0,
            verdict: ReviewVerdictV1::Approve,
            owner_idena_address: format!("0x{}", "01".repeat(20)),
            reviewer_bond_atoms: "100000000000000000".to_string(),
            creation_block_or_timestamp: 42,
            authentication: "on-chain-submitter".to_string(),
        }
    }

    #[test]
    fn agent_attestation_is_content_addressed_and_rejects_secrets() {
        let mut value = agent_attestation();
        let package = package_agent_review_attestation(value.clone()).unwrap();
        let verified = verify_agent_review_attestation_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);

        value.agent_policy_cid = raw_cid("raw-agent-policy");
        package_agent_review_attestation(value.clone()).unwrap();

        value.agent_policy_cid = cid_for(0x70, b"unsupported-codec").to_string();
        assert!(matches!(
            package_agent_review_attestation(value.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("raw or DAG-CBOR")
        ));
        value.agent_policy_cid = cid("agent-policy");

        value.model_family = "Family-A".to_string();
        assert!(matches!(
            package_agent_review_attestation(value.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("lowercase")
        ));
        value.model_family = "family-a".to_string();

        value.affected_repositories = (0..=MAX_REPOSITORY_CIDS)
            .map(|index| RepositoryCidV1 {
                repository: format!("repo-{index:03}"),
                cid: cid(&format!("source-{index}")),
            })
            .collect();
        assert!(matches!(
            package_agent_review_attestation(value.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("between 1 and 64")
        ));
        value.affected_repositories.truncate(1);

        value.commands_executed[0].exit_code = 1;
        assert!(matches!(
            package_agent_review_attestation(value.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("testsPassed")
        ));
        value.tests_passed = false;
        package_agent_review_attestation(value.clone()).unwrap();
        value.tests_passed = true;
        value.commands_executed[0].exit_code = 0;

        value.commands_executed[0].command = "tool --token=unredacted".to_string();
        assert!(matches!(
            package_agent_review_attestation(value),
            Err(AttestationError::Invalid(message)) if message.contains("secret")
        ));
    }

    #[test]
    fn unresolved_critical_review_requires_immutable_evidence() {
        let mut value = agent_attestation();
        value.unresolved_critical_findings = 1;
        value.security_findings = vec![SecurityFindingV1 {
            severity: FindingSeverity::Critical,
            summary: "reproducible critical finding".to_string(),
            evidence_cid: None,
            resolved: false,
        }];
        assert!(matches!(
            package_agent_review_attestation(value.clone()),
            Err(AttestationError::Invalid(message))
                if message.contains("immutable evidence")
        ));

        value.security_findings[0].evidence_cid = Some(raw_cid("critical-evidence"));
        assert!(package_agent_review_attestation(value).is_ok());
    }

    #[test]
    fn build_attestation_binds_the_complete_core_artifact_set() {
        let artifact_bytes = b"deterministic-artifact";
        let artifact_cid = cid_for(0x55, artifact_bytes).to_string();
        let artifacts = vec![BuildArtifactV1 {
            name: "core".to_string(),
            cid: artifact_cid,
            sha256: hex::encode(Sha256::digest(artifact_bytes)),
            size: artifact_bytes.len() as u64,
            core: true,
        }];
        let core_digest = core_artifact_set_digest(&artifacts).unwrap();
        assert_eq!(
            core_digest,
            "2cc1819daf00a581b5ee8b9380d9d4c01a13e54dc481c8e5a5ae61c349c30da8"
        );
        let mut value = BuildAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: cid("candidate"),
            source_cids: vec![RepositoryCidV1 {
                repository: "P2poolBTC".to_string(),
                cid: cid("source"),
            }],
            toolchain_cid: cid("toolchain"),
            scope_evidence_cid: cid("scope-evidence"),
            builder_identity: format!("0x{}", "01".repeat(20)),
            runtime_family: "linux".to_string(),
            architecture: "x86_64".to_string(),
            commands: vec![command()],
            test_results_cid: raw_cid("tests"),
            tests_passed: true,
            sbom_cid: raw_cid("sbom"),
            artifacts,
            core_artifact_digest: core_digest,
            builder_bond_atoms: "100000000000000000".to_string(),
            creation_block_or_timestamp: 42,
            authentication: "on-chain-submitter".to_string(),
        };
        package_build_attestation(value.clone()).unwrap();

        let mut contradictory_result = value.clone();
        contradictory_result.commands[0].exit_code = 1;
        assert!(matches!(
            package_build_attestation(contradictory_result.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("testsPassed")
        ));
        contradictory_result.tests_passed = false;
        package_build_attestation(contradictory_result).unwrap();

        let mut wrong_codec = value.clone();
        wrong_codec.artifacts[0].cid = cid("dag-cbor-artifact");
        wrong_codec.artifacts[0].sha256 = cid_sha256(&wrong_codec.artifacts[0].cid);
        wrong_codec.core_artifact_digest =
            core_artifact_set_digest(&wrong_codec.artifacts).unwrap();
        assert!(matches!(
            package_build_attestation(wrong_codec),
            Err(AttestationError::Invalid(message)) if message.contains("raw multicodec")
        ));

        let mut oversized = value.clone();
        oversized.artifacts[0].size = MAX_PORTABLE_ARTIFACT_SIZE + 1;
        oversized.core_artifact_digest = core_artifact_set_digest(&oversized.artifacts).unwrap();
        assert!(matches!(
            package_build_attestation(oversized),
            Err(AttestationError::Invalid(message)) if message.contains("portable integer")
        ));

        let mut non_portable_name = value.clone();
        non_portable_name.artifacts[0].name = "cöre".to_string();
        non_portable_name.core_artifact_digest =
            core_artifact_set_digest(&non_portable_name.artifacts).unwrap();
        assert!(matches!(
            package_build_attestation(non_portable_name),
            Err(AttestationError::Invalid(message)) if message.contains("portable deterministic label")
        ));

        let mut uppercase_runtime = value.clone();
        uppercase_runtime.runtime_family = "Linux".to_string();
        assert!(matches!(
            package_build_attestation(uppercase_runtime),
            Err(AttestationError::Invalid(message)) if message.contains("lowercase")
        ));

        value.artifacts[0].size += 1;
        assert!(matches!(
            package_build_attestation(value),
            Err(AttestationError::Invalid(message)) if message.contains("coreArtifactDigest")
        ));
    }

    #[test]
    fn command_secret_redaction_is_scoped_to_each_assignment() {
        assert!(reject_unredacted_secret("tool --token=[REDACTED]").is_ok());
        assert!(
            reject_unredacted_secret("tool --token=[REDACTED] --password=still-visible").is_err()
        );
        assert!(reject_unredacted_secret("tool api_key=[REDACTED]suffix").is_err());
        assert!(reject_unredacted_secret("tool ghp_not-a-placeholder").is_err());
    }

    #[test]
    fn detached_signature_binds_exact_attestation_content_candidate_and_identity() {
        let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
        let mut value = agent_attestation();
        value.owner_idena_address = identity_for(&secret_key);
        value.authentication = DETACHED_IDENA_SIGNATURE_AUTHENTICATION.to_string();
        let package = package_agent_review_attestation(value).unwrap();
        let request = attestation_authentication_request(
            "agent_review_v1",
            &package.root_cid.to_string(),
            &package.root_sha256,
            &package.value.candidate_ecosystem_cid,
            &package.value.owner_idena_address,
        )
        .unwrap();
        let authentication = signature_attestation_authentication(
            &request,
            sign_authentication_request(&request, &secret_key),
        )
        .unwrap();
        verify_attestation_authentication(&request, &package.value.authentication, &authentication)
            .unwrap();
        let encoded = serde_json::to_value(&authentication).unwrap();
        assert!(encoded["proof"].get("signatureHex").is_some());
        assert!(encoded["proof"].get("signature_hex").is_none());
        let decoded: AttestationAuthenticationV1 = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, authentication);

        let mut substituted = authentication.clone();
        substituted.attestation_cid = cid("different-attestation");
        assert!(verify_attestation_authentication(
            &request,
            &package.value.authentication,
            &substituted
        )
        .is_err());

        let mut substituted = authentication.clone();
        substituted.attestation_sha256 = "44".repeat(32);
        assert!(verify_attestation_authentication(
            &request,
            &package.value.authentication,
            &substituted
        )
        .is_err());

        let mut substituted = authentication.clone();
        substituted.candidate_ecosystem_cid = cid("different-candidate");
        assert!(verify_attestation_authentication(
            &request,
            &package.value.authentication,
            &substituted
        )
        .is_err());

        let mut substituted = authentication.clone();
        substituted.identity = format!("0x{}", "08".repeat(20));
        assert!(verify_attestation_authentication(
            &request,
            &package.value.authentication,
            &substituted
        )
        .is_err());

        assert!(verify_attestation_authentication(
            &request,
            ON_CHAIN_SUBMITTER_AUTHENTICATION,
            &authentication
        )
        .is_err());
    }

    #[test]
    fn unverified_receipt_json_cannot_authenticate_an_attestation() {
        let package = package_agent_review_attestation(agent_attestation()).unwrap();
        let request = attestation_authentication_request(
            "agent_review_v1",
            &package.root_cid.to_string(),
            &package.root_sha256,
            &package.value.candidate_ecosystem_cid,
            &package.value.owner_idena_address,
        )
        .unwrap();
        let receipt = FinalizedOnChainAttestationReceiptV1 {
            schema_version: 1,
            chain_id: "idena-mainnet".to_string(),
            contract_address: format!("0x{}", "a1".repeat(20)),
            transaction_hash: format!("0x{}", "b2".repeat(32)),
            transaction_block_height: 100,
            transaction_block_hash: format!("0x{}", "c3".repeat(32)),
            finalized_at_height: 106,
            finality_confirmations: 6,
            submitter_identity: request.identity.clone(),
            call_data_commitment: request.binding_sha256.clone(),
            success: true,
        };
        assert!(receipt_attestation_authentication(&request, receipt.clone()).is_err());
        let authentication = authentication_for_request(
            &request,
            AttestationAuthenticationProofV1::FinalizedOnChainReceipt { receipt },
        );
        assert!(verify_attestation_authentication(
            &request,
            ON_CHAIN_SUBMITTER_AUTHENTICATION,
            &authentication,
        )
        .is_err());
    }

    #[test]
    fn attestation_package_respects_the_wasm_payload_ceiling() {
        let mut value = agent_attestation();
        value.commands_executed = (0..9)
            .map(|index| CommandExecutionV1 {
                command: format!("tool-{index} {}", "x".repeat(8_000)),
                exit_code: 0,
                stdout_sha256: "1".repeat(64),
                stderr_sha256: "2".repeat(64),
            })
            .collect();
        assert!(matches!(
            package_agent_review_attestation(value),
            Err(AttestationError::Invalid(message)) if message.contains("contract payload limit")
        ));
    }

    #[test]
    fn availability_attestation_enforces_manifest_and_content_cid_profiles() {
        let candidate = cid("candidate");
        let probe = raw_cid("probe");
        let mut verified_cids = vec![candidate.clone(), probe.clone()];
        verified_cids.sort();
        let mut value = DataAvailabilityAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: candidate.clone(),
            pinset_cid: cid("pinset"),
            provider_id: "provider-a".to_string(),
            operator_identity: format!("0x{}", "01".repeat(20)),
            verified_cids,
            probe_result_cid: probe,
            available: true,
            observed_at_block_or_timestamp: 42,
            expires_at_block: 100,
            bond_atoms: "100000000000000000".to_string(),
            authentication: "on-chain-submitter".to_string(),
        };
        package_data_availability_attestation(value.clone()).unwrap();

        value.pinset_cid = raw_cid("raw-pinset");
        assert!(matches!(
            package_data_availability_attestation(value.clone()),
            Err(AttestationError::Invalid(message)) if message.contains("DAG-CBOR")
        ));

        value.pinset_cid = cid("pinset");
        value
            .verified_cids
            .push(cid_for(0x70, b"unsupported-codec").to_string());
        value.verified_cids.sort();
        assert!(matches!(
            package_data_availability_attestation(value),
            Err(AttestationError::Invalid(message)) if message.contains("raw or DAG-CBOR")
        ));
    }

    #[test]
    fn external_audit_is_content_addressed_and_cannot_pass_with_open_severe_findings() {
        let mut value = ExternalAuditAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: cid("candidate"),
            scope_evidence_cid: cid("scope"),
            auditor_identity: format!("0x{}", "02".repeat(20)),
            auditor_organization_id: "independent-audit-lab".to_string(),
            audit_policy_cid: cid("audit-policy"),
            report_cid: raw_cid("audit-report"),
            independence_statement_cid: cid("independence-statement"),
            covered_repository_cids: vec![RepositoryCidV1 {
                repository: "P2poolBTC".to_string(),
                cid: cid("source"),
            }],
            unresolved_critical_findings: 0,
            unresolved_high_findings: 0,
            verdict: ExternalAuditVerdictV1::Pass,
            creation_block_or_timestamp: 42,
            authentication: "on-chain-submitter".to_string(),
        };
        let package = package_external_audit_attestation(value.clone()).unwrap();
        let verified = verify_external_audit_attestation_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);

        value.unresolved_high_findings = 1;
        assert!(matches!(
            package_external_audit_attestation(value),
            Err(AttestationError::Invalid(message)) if message.contains("passing external audit")
        ));
    }

    #[test]
    fn identity_metrics_attestation_binds_snapshot_digest_and_replay() {
        let snapshot_cid = cid("metrics-snapshot");
        let mut value = IdentityMetricsAttestationV1 {
            schema_version: 1,
            metrics_root: "11".repeat(32),
            snapshot_sha256: cid_sha256(&snapshot_cid),
            snapshot_cid,
            source_epoch: 7,
            source_block_height: 1_000,
            source_block_hash: "22".repeat(32),
            replay_start_height: 10,
            replay_commitment: "33".repeat(32),
            indexer_implementation_cid: cid("metrics-indexer"),
            operator_idena_address: format!("0x{}", "01".repeat(20)),
            observed_at_block_or_timestamp: 42,
            authentication: "on-chain-submitter".to_string(),
        };
        let package = package_identity_metrics_attestation(value.clone()).unwrap();
        let verified = verify_identity_metrics_attestation_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);

        value.replay_start_height = 1_001;
        assert!(package_identity_metrics_attestation(value).is_err());
    }
}
