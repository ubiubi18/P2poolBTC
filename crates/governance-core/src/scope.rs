use crate::{
    cid_for, package_dag_cbor,
    source::{
        decode_source_manifest, decode_source_patch, encode_source_manifest, encode_source_patch,
    },
    verify_dag_cbor_car, DagCborPackage, RiskClass, SourceFileEntryV1, SourceTreeManifestV1,
};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const OBJECTIVE_RISK_CLASSIFIER_V2: &str = "pohw-objective-risk-classifier-v2";
const MAX_SCOPE_DAG_CBOR_BYTES: usize = 1_400_000;
const MAX_SCOPE_PROOF_BYTES: usize = 600_000;
const MAX_SCOPE_FILES_PER_REPOSITORY: usize = 2_048;
const MAX_SOURCE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SOURCE_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeChangeV1 {
    pub path: String,
    pub change_kind: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryScopeEvidenceV1 {
    pub repository: String,
    pub base_source_cid: String,
    pub candidate_source_cid: String,
    pub patch_cid: String,
    pub patch_sha256: String,
    pub base_manifest_dag_cbor_hex: String,
    pub candidate_manifest_dag_cbor_hex: String,
    pub patch_dag_cbor_hex: String,
    pub patch_content_bytes: u64,
    pub candidate_content_bytes: u64,
    pub changes: Vec<ScopeChangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposalScopeEvidenceV1 {
    pub schema_version: u16,
    pub classifier_version: String,
    pub parent_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub patch_cid: String,
    pub repositories: Vec<RepositoryScopeEvidenceV1>,
    pub rationale_bytes: u32,
    pub migration_notes_bytes: u32,
    pub test_plan_bytes: u32,
    pub changed_file_count: u32,
    pub patch_bytes: u64,
    pub source_package_bytes: u64,
    pub description_bytes: u32,
    pub migration_operation_count: u32,
    pub derived_risk_class: RiskClass,
}

pub type ProposalScopePackage = DagCborPackage<ProposalScopeEvidenceV1>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScopeError {
    #[error("invalid proposal scope evidence: {0}")]
    Invalid(String),
    #[error("proposal scope arithmetic overflow")]
    Overflow,
    #[error("proposal scope packaging failed: {0}")]
    Packaging(String),
}

pub fn package_proposal_scope_evidence(
    evidence: ProposalScopeEvidenceV1,
) -> Result<ProposalScopePackage, ScopeError> {
    validate_proposal_scope_evidence(&evidence)?;
    let package =
        package_dag_cbor(evidence).map_err(|error| ScopeError::Packaging(error.to_string()))?;
    if package.dag_cbor_bytes.len() > MAX_SCOPE_DAG_CBOR_BYTES {
        return invalid("scope evidence exceeds the contract payload limit");
    }
    Ok(package)
}

pub fn verify_proposal_scope_evidence_car(
    bytes: &[u8],
) -> Result<ProposalScopePackage, ScopeError> {
    let package: ProposalScopePackage =
        verify_dag_cbor_car(bytes).map_err(|error| ScopeError::Packaging(error.to_string()))?;
    if package.dag_cbor_bytes.len() > MAX_SCOPE_DAG_CBOR_BYTES {
        return invalid("scope evidence exceeds the contract payload limit");
    }
    validate_proposal_scope_evidence(&package.value)?;
    Ok(package)
}

pub fn validate_proposal_scope_evidence(
    evidence: &ProposalScopeEvidenceV1,
) -> Result<(), ScopeError> {
    if evidence.schema_version != 1 || evidence.classifier_version != OBJECTIVE_RISK_CLASSIFIER_V2 {
        return invalid("unsupported schema or classifier version");
    }
    for cid in [
        &evidence.parent_ecosystem_cid,
        &evidence.candidate_ecosystem_cid,
        &evidence.patch_cid,
    ] {
        validate_canonical_cid(cid)?;
    }
    if evidence.parent_ecosystem_cid == evidence.candidate_ecosystem_cid {
        return invalid("parent and candidate ecosystem CIDs must differ");
    }
    if evidence.repositories.is_empty() || evidence.repositories.len() > 64 {
        return invalid("repository evidence count is outside deterministic limits");
    }

    let mut previous_repository = None;
    let mut changed_file_count = 0u32;
    let mut patch_bytes = 0u64;
    let mut source_package_bytes = 0u64;
    let mut migration_operation_count = 0u32;
    let mut derived_risk = RiskClass::Normal;
    let mut proof_bytes = 0usize;
    for repository in &evidence.repositories {
        if !valid_repository_name(&repository.repository) {
            return invalid("invalid repository name");
        }
        if previous_repository.is_some_and(|value: &str| value >= repository.repository.as_str()) {
            return invalid("repositories must be uniquely sorted");
        }
        previous_repository = Some(&repository.repository);
        for cid in [
            &repository.base_source_cid,
            &repository.candidate_source_cid,
            &repository.patch_cid,
        ] {
            validate_canonical_cid(cid)?;
        }
        if repository.base_source_cid == repository.candidate_source_cid {
            return invalid("repository source transition does not change");
        }
        if !is_lower_hex_64(&repository.patch_sha256) {
            return invalid("repository patch digest must be lowercase SHA-256");
        }
        let base_bytes = decode_hex_proof(&repository.base_manifest_dag_cbor_hex)?;
        let candidate_bytes = decode_hex_proof(&repository.candidate_manifest_dag_cbor_hex)?;
        let patch_root_bytes = decode_hex_proof(&repository.patch_dag_cbor_hex)?;
        proof_bytes = proof_bytes
            .checked_add(base_bytes.len())
            .and_then(|value| value.checked_add(candidate_bytes.len()))
            .and_then(|value| value.checked_add(patch_root_bytes.len()))
            .ok_or(ScopeError::Overflow)?;
        if proof_bytes > MAX_SCOPE_PROOF_BYTES {
            return invalid("source-manifest proof bytes exceed the contract limit");
        }
        let (derived_changes, patch_content, candidate_content) = verify_repository_scope_proof(
            repository,
            &base_bytes,
            &candidate_bytes,
            &patch_root_bytes,
        )?;
        if repository.changes != derived_changes
            || repository.patch_content_bytes != patch_content
            || repository.candidate_content_bytes != candidate_content
        {
            return invalid("repository scope differs from the verified source transition");
        }
        if repository.changes.is_empty() || repository.changes.len() > 1_024 {
            return invalid("changed path count is outside deterministic limits");
        }
        let mut previous_path = None;
        let mut unique_paths = BTreeSet::new();
        for change in &repository.changes {
            if !valid_scope_path(&change.path) {
                return invalid("invalid changed path");
            }
            if previous_path.is_some_and(|value: &str| value >= change.path.as_str())
                || !unique_paths.insert(&change.path)
            {
                return invalid("changed paths must be uniquely sorted");
            }
            previous_path = Some(&change.path);
            if change.change_kind != "remove" && change.change_kind != "upsert" {
                return invalid("change kind must be remove or upsert");
            }
            if change.change_kind == "remove" && change.size != 0 {
                return invalid("removed paths must have size zero");
            }
            changed_file_count = changed_file_count
                .checked_add(1)
                .ok_or(ScopeError::Overflow)?;
            if is_migration_path(&change.path) {
                migration_operation_count = migration_operation_count
                    .checked_add(1)
                    .ok_or(ScopeError::Overflow)?;
            }
            derived_risk = max_risk(
                derived_risk,
                classify_repository_path(&repository.repository, &change.path),
            );
        }
        patch_bytes = patch_bytes
            .checked_add(repository.patch_content_bytes)
            .ok_or(ScopeError::Overflow)?;
        source_package_bytes = source_package_bytes
            .checked_add(repository.candidate_content_bytes)
            .ok_or(ScopeError::Overflow)?;
    }
    let description_bytes = evidence
        .rationale_bytes
        .checked_add(evidence.migration_notes_bytes)
        .and_then(|value| value.checked_add(evidence.test_plan_bytes))
        .ok_or(ScopeError::Overflow)?;
    if evidence.rationale_bytes == 0 || evidence.test_plan_bytes == 0 {
        return invalid("rationale and test plan must be nonempty");
    }
    if evidence.changed_file_count != changed_file_count
        || evidence.patch_bytes != patch_bytes
        || evidence.source_package_bytes != source_package_bytes
        || evidence.description_bytes != description_bytes
        || evidence.migration_operation_count != migration_operation_count
        || evidence.derived_risk_class != derived_risk
    {
        return invalid("declared scope counters or risk differ from recomputed values");
    }
    Ok(())
}

fn decode_hex_proof(value: &str) -> Result<Vec<u8>, ScopeError> {
    if value.is_empty() || value.len() % 2 != 0 {
        return invalid("source-manifest proof hex is empty or malformed");
    }
    hex::decode(value)
        .map_err(|_| ScopeError::Invalid("source-manifest proof hex is invalid".into()))
}

fn verify_repository_scope_proof(
    evidence: &RepositoryScopeEvidenceV1,
    base_bytes: &[u8],
    candidate_bytes: &[u8],
    patch_bytes: &[u8],
) -> Result<(Vec<ScopeChangeV1>, u64, u64), ScopeError> {
    if cid_for(0x71, base_bytes).to_string() != evidence.base_source_cid
        || cid_for(0x71, candidate_bytes).to_string() != evidence.candidate_source_cid
        || cid_for(0x71, patch_bytes).to_string() != evidence.patch_cid
        || hex::encode(cid_for(0x71, patch_bytes).hash().digest()) != evidence.patch_sha256
    {
        return invalid("source-manifest proof CID or digest mismatch");
    }
    let base = decode_source_manifest(base_bytes)
        .map_err(|error| ScopeError::Invalid(error.to_string()))?;
    let candidate = decode_source_manifest(candidate_bytes)
        .map_err(|error| ScopeError::Invalid(error.to_string()))?;
    let patch =
        decode_source_patch(patch_bytes).map_err(|error| ScopeError::Invalid(error.to_string()))?;
    if encode_source_manifest(&base).map_err(|error| ScopeError::Invalid(error.to_string()))?
        != base_bytes
        || encode_source_manifest(&candidate)
            .map_err(|error| ScopeError::Invalid(error.to_string()))?
            != candidate_bytes
        || encode_source_patch(&patch).map_err(|error| ScopeError::Invalid(error.to_string()))?
            != patch_bytes
    {
        return invalid("source-manifest proof is not canonical DAG-CBOR");
    }
    validate_source_manifest_metadata(&base, &evidence.repository)?;
    let candidate_content = validate_source_manifest_metadata(&candidate, &evidence.repository)?;
    if patch.schema_version != 1
        || patch.kind != "pohw-source-patch-v1"
        || patch.repository != evidence.repository
        || patch.base_source_cid != evidence.base_source_cid
        || patch.candidate_source_cid != evidence.candidate_source_cid
    {
        return invalid("source patch metadata does not bind the declared transition");
    }
    let base_files = base
        .files
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let candidate_files = candidate
        .files
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let removed = base_files
        .keys()
        .filter(|path| !candidate_files.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>();
    let upserted = candidate_files
        .iter()
        .filter(|(path, entry)| base_files.get(*path) != Some(*entry))
        .map(|(_, entry)| entry.clone())
        .collect::<Vec<_>>();
    if patch.removed_paths != removed || patch.upserted_files != upserted {
        return invalid("source patch does not exactly reconstruct the candidate manifest");
    }
    let mut changes = removed
        .into_iter()
        .map(|path| ScopeChangeV1 {
            path,
            change_kind: "remove".to_string(),
            size: 0,
        })
        .chain(upserted.iter().map(|entry| ScopeChangeV1 {
            path: entry.path.clone(),
            change_kind: "upsert".to_string(),
            size: entry.size,
        }))
        .collect::<Vec<_>>();
    changes.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let patch_content = upserted.iter().try_fold(0u64, |total, entry| {
        total.checked_add(entry.size).ok_or(ScopeError::Overflow)
    })?;
    Ok((changes, patch_content, candidate_content))
}

fn validate_source_manifest_metadata(
    manifest: &SourceTreeManifestV1,
    repository: &str,
) -> Result<u64, ScopeError> {
    if manifest.schema_version != 1
        || manifest.kind != "pohw-source-tree-v1"
        || manifest.repository != repository
        || manifest.files.len() > MAX_SCOPE_FILES_PER_REPOSITORY
    {
        return invalid("source manifest schema, repository, or file count is invalid");
    }
    let mut previous = None;
    let mut portable_paths = BTreeSet::new();
    let mut total = 0u64;
    for entry in &manifest.files {
        validate_source_entry(entry)?;
        if previous.is_some_and(|path: &str| path >= entry.path.as_str())
            || !portable_paths.insert(entry.path.to_ascii_lowercase())
        {
            return invalid("source manifest paths are not portable and strictly sorted");
        }
        previous = Some(entry.path.as_str());
        total = total.checked_add(entry.size).ok_or(ScopeError::Overflow)?;
        if total > MAX_SOURCE_TREE_BYTES {
            return invalid("source manifest content exceeds the deterministic limit");
        }
    }
    Ok(total)
}

fn validate_source_entry(entry: &SourceFileEntryV1) -> Result<(), ScopeError> {
    if !valid_scope_path(&entry.path)
        || !matches!(entry.mode, 0o644 | 0o755)
        || entry.size > MAX_SOURCE_FILE_BYTES
        || !is_lower_hex_64(&entry.sha256)
    {
        return invalid("source manifest file entry is invalid");
    }
    let cid = Cid::try_from(entry.cid.as_str())
        .map_err(|_| ScopeError::Invalid("source file CID is malformed".into()))?;
    if cid.version() != Version::V1
        || cid.codec() != 0x55
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || cid.to_string() != entry.cid
        || hex::encode(cid.hash().digest()) != entry.sha256
    {
        return invalid("source file CID and digest are inconsistent");
    }
    Ok(())
}

pub fn classify_repository_path(repository: &str, path: &str) -> RiskClass {
    if matches!(repository, "idena-wasm" | "idena-wasm-binding" | "wasmer") {
        return RiskClass::Consensus;
    }
    if repository == "idena-go"
        && ["blockchain/", "core/", "vm/", "consensus/", "config/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
    {
        return RiskClass::Consensus;
    }
    if repository == "P2poolBTC"
        && (path.starts_with("contracts/idena-code-governance/")
            || path.starts_with("compatibility/governance-fork")
            || path.starts_with("compatibility/governance-day-fork")
            || path.starts_with("integrations/governance-epoch-anchor/")
            || path.contains("fork_chain")
            || path.contains("sharechain")
            || path.contains("consensus"))
    {
        return RiskClass::Consensus;
    }
    if is_migration_path(path) {
        return RiskClass::Migration;
    }
    if is_documentation_path(path) {
        return RiskClass::Normal;
    }
    RiskClass::Critical
}

fn is_documentation_path(path: &str) -> bool {
    let allowed_extension = path.ends_with(".md") || path.ends_with(".txt");
    allowed_extension
        && (path.starts_with("docs/")
            || !path.contains('/')
                && matches!(
                    path,
                    "README.md" | "CONTRIBUTING.md" | "SECURITY.md" | "CODE_OF_CONDUCT.md"
                ))
}

fn is_migration_path(path: &str) -> bool {
    path.starts_with("migrations/")
        || path.contains("/migrations/")
        || path.starts_with("migration/")
        || path.contains("/migration/")
}

fn max_risk(left: RiskClass, right: RiskClass) -> RiskClass {
    if risk_rank(right) > risk_rank(left) {
        right
    } else {
        left
    }
}

fn risk_rank(risk: RiskClass) -> u8 {
    match risk {
        RiskClass::Normal => 0,
        RiskClass::Critical => 1,
        RiskClass::Migration => 2,
        RiskClass::Consensus => 3,
    }
}

fn valid_repository_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_scope_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1_024
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\0')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_canonical_cid(value: &str) -> Result<(), ScopeError> {
    let cid = Cid::try_from(value).map_err(|_| ScopeError::Invalid("invalid CID".into()))?;
    if cid.version() != Version::V1
        || cid.codec() != 0x71
        || cid.hash().code() != 0x12
        || cid.hash().size() != 32
        || !value.starts_with('b')
        || cid.to_string() != value
    {
        return invalid("CID must be canonical base32 CIDv1 DAG-CBOR SHA2-256");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, ScopeError> {
    Err(ScopeError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_is_conservative_and_deterministic() {
        assert_eq!(
            classify_repository_path("P2poolBTC", "docs/guide.md"),
            RiskClass::Normal
        );
        assert_eq!(
            classify_repository_path("P2poolBTC", "README.md"),
            RiskClass::Normal
        );
        assert_eq!(
            classify_repository_path("P2poolBTC", "scripts/release.rs"),
            RiskClass::Critical
        );
        assert_eq!(
            classify_repository_path("P2poolBTC", "migrations/v2.json"),
            RiskClass::Migration
        );
        assert_eq!(
            classify_repository_path("idena-go", "blockchain/blockchain.go"),
            RiskClass::Consensus
        );
        assert_eq!(
            classify_repository_path("idena-wasm", "README.md"),
            RiskClass::Consensus
        );
        assert_eq!(
            classify_repository_path(
                "P2poolBTC",
                "compatibility/governance-day-fork-candidate-lock.json"
            ),
            RiskClass::Consensus
        );
        assert_eq!(
            classify_repository_path(
                "P2poolBTC",
                "integrations/governance-epoch-anchor/idena-go.patch"
            ),
            RiskClass::Consensus
        );
    }
}
