use crate::{
    normalize_address, package_dag_cbor, verify_dag_cbor_car, DagCborPackage, SourceError,
};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const SHA2_256_CODE: u64 = 0x12;
const CORE_ARTIFACT_SET_DOMAIN: &[u8] = b"IDENA_GOV_CORE_ARTIFACT_SET_V1\0";
const MAX_PORTABLE_ARTIFACT_SIZE: u64 = 9_007_199_254_740_991;
const MAX_REPOSITORY_CIDS: usize = 64;
const MAX_TOOL_VERSIONS: usize = 256;
const MAX_BUILD_ARTIFACTS: usize = 4_096;
const MAX_VERIFIED_CIDS: usize = 4_096;
const MAX_ARTIFACT_NAME_BYTES: usize = 128;
const MAX_CONTRACT_DAG_CBOR_BYTES: usize = 65_536;

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
    validate_amount(&value.reviewer_bond_atoms)?;
    validate_authentication(&value.authentication)
}

fn validate_build(value: &BuildAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_dag_cbor_cid(&value.candidate_ecosystem_cid, "candidateEcosystemCid")?;
    validate_dag_cbor_cid(&value.toolchain_cid, "toolchainCid")?;
    validate_raw_cid(&value.sbom_cid, "sbomCid")?;
    validate_raw_cid(&value.test_results_cid, "testResultsCid")?;
    validate_repository_cids(&value.source_cids)?;
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

fn validate_availability(value: &DataAvailabilityAttestationV1) -> Result<(), AttestationError> {
    if value.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_dag_cbor_cid(&value.candidate_ecosystem_cid, "candidateEcosystemCid")?;
    validate_dag_cbor_cid(&value.pinset_cid, "pinsetCid")?;
    validate_raw_cid(&value.probe_result_cid, "probeResultCid")?;
    validate_safe_label(&value.provider_id, 80, "providerId")?;
    if value.verified_cids.is_empty()
        || value.verified_cids.len() > MAX_VERIFIED_CIDS
        || !value
            .verified_cids
            .iter()
            .any(|cid| cid == &value.candidate_ecosystem_cid)
        || !strict_sorted_unique(&value.verified_cids)
    {
        return invalid("verifiedCids must be sorted, unique, and include the candidate CID");
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
    if value != "on-chain-submitter" {
        return invalid("authentication must be on-chain-submitter in the experimental slice");
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
        let mut value = DataAvailabilityAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: candidate.clone(),
            pinset_cid: cid("pinset"),
            provider_id: "provider-a".to_string(),
            operator_identity: format!("0x{}", "01".repeat(20)),
            verified_cids: vec![candidate],
            probe_result_cid: raw_cid("probe"),
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
