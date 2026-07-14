use crate::{package_dag_cbor, verify_dag_cbor_car, DagCborPackage, SourceError};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const DAG_CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;
const SHA2_256_CODE: u64 = 0x12;
const MAX_PORTABLE_ARTIFACT_SIZE: u64 = 9_007_199_254_740_991;
const MAX_REPOSITORIES: usize = 64;
const MAX_REPOSITORY_PATCHES: usize = 64;
const MAX_DEPENDENCY_LOCKS: usize = 4_096;
const MAX_BUILD_INSTRUCTIONS: usize = 256;
const MAX_REPOSITORY_ARTIFACTS: usize = 4_096;
const MAX_PINSET_CIDS: usize = 4_096;
const MAX_STRING_MAP_ENTRIES: usize = 256;
const MAX_COMPATIBILITY_CONSUMERS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DependencyLockV1 {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactManifestV1 {
    pub name: String,
    pub cid: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryManifestV1 {
    pub schema_version: u16,
    pub name: String,
    pub source_tree_cid: String,
    pub source_tree_sha256: String,
    pub git_bundle_cid: Option<String>,
    pub git_commit_metadata: Option<String>,
    pub dependency_locks: Vec<DependencyLockV1>,
    pub toolchain_locks: BTreeMap<String, String>,
    pub build_instructions: Vec<String>,
    pub artifacts: Vec<ArtifactManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcosystemManifestV1 {
    pub schema_version: u16,
    pub ecosystem_id: String,
    pub parent_ecosystem_cid: Option<String>,
    pub repositories: Vec<RepositoryManifestV1>,
    pub compatibility_pins: BTreeMap<String, BTreeMap<String, String>>,
    pub toolchain_locks: BTreeMap<String, String>,
    pub governance_contract_version: String,
    pub governance_parameter_set_cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryPatchManifestV1 {
    pub repository: String,
    pub base_source_cid: String,
    pub candidate_source_cid: String,
    pub patch_cid: String,
    pub patch_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcosystemPatchManifestV1 {
    pub schema_version: u16,
    pub kind: String,
    pub parent_ecosystem_cid: String,
    pub candidate_ecosystem_cid: String,
    pub repository_patches: Vec<RepositoryPatchManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryToolchainLocksV1 {
    pub repository: String,
    pub toolchain_locks: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolchainManifestV1 {
    pub schema_version: u16,
    pub ecosystem_locks: BTreeMap<String, String>,
    pub repository_locks: Vec<RepositoryToolchainLocksV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinsetManifestV1 {
    pub schema_version: u16,
    pub ecosystem_cid: String,
    pub cids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalArtifactManifestV1 {
    name: String,
    cid: Cid,
    sha256: String,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalRepositoryManifestV1 {
    schema_version: u16,
    name: String,
    source_tree_cid: Cid,
    source_tree_sha256: String,
    git_bundle_cid: Option<Cid>,
    git_commit_metadata: Option<String>,
    dependency_locks: Vec<DependencyLockV1>,
    toolchain_locks: BTreeMap<String, String>,
    build_instructions: Vec<String>,
    artifacts: Vec<CanonicalArtifactManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalEcosystemManifestV1 {
    schema_version: u16,
    ecosystem_id: String,
    parent_ecosystem_cid: Option<Cid>,
    repositories: Vec<CanonicalRepositoryManifestV1>,
    compatibility_pins: BTreeMap<String, BTreeMap<String, String>>,
    toolchain_locks: BTreeMap<String, String>,
    governance_contract_version: String,
    governance_parameter_set_cid: Cid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalRepositoryPatchManifestV1 {
    repository: String,
    base_source_cid: Cid,
    candidate_source_cid: Cid,
    patch_cid: Cid,
    patch_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalEcosystemPatchManifestV1 {
    schema_version: u16,
    kind: String,
    parent_ecosystem_cid: Cid,
    candidate_ecosystem_cid: Cid,
    repository_patches: Vec<CanonicalRepositoryPatchManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalPinsetManifestV1 {
    schema_version: u16,
    ecosystem_cid: Cid,
    cids: Vec<Cid>,
}

#[derive(Debug, Clone)]
pub struct EcosystemManifestPackage {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub manifest: EcosystemManifestV1,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EcosystemPatchManifestPackage {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub manifest: EcosystemPatchManifestV1,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

pub type ToolchainManifestPackage = DagCborPackage<ToolchainManifestV1>;

#[derive(Debug, Clone)]
pub struct PinsetManifestPackage {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub manifest: PinsetManifestV1,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("ecosystem manifest is invalid: {0}")]
    Invalid(String),
    #[error(transparent)]
    Source(#[from] SourceError),
}

pub fn package_ecosystem_manifest(
    manifest: EcosystemManifestV1,
) -> Result<EcosystemManifestPackage, ManifestError> {
    validate_ecosystem_manifest(&manifest)?;
    let canonical = canonical_ecosystem(&manifest)?;
    let package = package_dag_cbor(canonical)?;
    Ok(human_package(package, manifest))
}

pub fn verify_ecosystem_manifest_car(
    bytes: &[u8],
) -> Result<EcosystemManifestPackage, ManifestError> {
    let package: DagCborPackage<CanonicalEcosystemManifestV1> = verify_dag_cbor_car(bytes)?;
    let manifest = human_ecosystem(&package.value);
    validate_ecosystem_manifest(&manifest)?;
    Ok(human_package(package, manifest))
}

pub fn package_ecosystem_patch_manifest(
    manifest: EcosystemPatchManifestV1,
) -> Result<EcosystemPatchManifestPackage, ManifestError> {
    validate_ecosystem_patch_manifest(&manifest)?;
    let canonical = canonical_ecosystem_patch(&manifest)?;
    let package = package_dag_cbor(canonical)?;
    Ok(human_patch_package(package, manifest))
}

pub fn verify_ecosystem_patch_manifest_car(
    bytes: &[u8],
) -> Result<EcosystemPatchManifestPackage, ManifestError> {
    let package: DagCborPackage<CanonicalEcosystemPatchManifestV1> = verify_dag_cbor_car(bytes)?;
    let manifest = human_ecosystem_patch(&package.value);
    validate_ecosystem_patch_manifest(&manifest)?;
    Ok(human_patch_package(package, manifest))
}

pub fn package_toolchain_manifest_for_ecosystem(
    ecosystem: &EcosystemManifestV1,
) -> Result<ToolchainManifestPackage, ManifestError> {
    validate_ecosystem_manifest(ecosystem)?;
    let value = ToolchainManifestV1 {
        schema_version: 1,
        ecosystem_locks: ecosystem.toolchain_locks.clone(),
        repository_locks: ecosystem
            .repositories
            .iter()
            .map(|repository| RepositoryToolchainLocksV1 {
                repository: repository.name.clone(),
                toolchain_locks: repository.toolchain_locks.clone(),
            })
            .collect(),
    };
    validate_toolchain_manifest(&value)?;
    Ok(package_dag_cbor(value)?)
}

pub fn verify_toolchain_manifest_car(
    bytes: &[u8],
) -> Result<ToolchainManifestPackage, ManifestError> {
    let package: ToolchainManifestPackage = verify_dag_cbor_car(bytes)?;
    validate_toolchain_manifest(&package.value)?;
    Ok(package)
}

pub fn package_pinset_manifest_for_transition(
    candidate: &EcosystemManifestPackage,
    patch: &EcosystemPatchManifestPackage,
) -> Result<PinsetManifestPackage, ManifestError> {
    package_pinset_manifest_for_transition_with_additional(candidate, patch, &[])
}

pub fn package_pinset_manifest_for_transition_with_additional(
    candidate: &EcosystemManifestPackage,
    patch: &EcosystemPatchManifestPackage,
    additional_cids: &[String],
) -> Result<PinsetManifestPackage, ManifestError> {
    let candidate_cid = candidate.root_cid.to_string();
    if patch.manifest.candidate_ecosystem_cid != candidate_cid {
        return invalid("pinset transition does not target the candidate ecosystem");
    }
    let mut cids = required_pinset_cids(candidate, patch)?;
    for cid in additional_cids {
        parse_profile_cid(cid, None)?;
        cids.insert(cid.clone());
    }
    let manifest = PinsetManifestV1 {
        schema_version: 1,
        ecosystem_cid: candidate_cid,
        cids: cids.into_iter().collect(),
    };
    validate_pinset_manifest(&manifest)?;
    let canonical = CanonicalPinsetManifestV1 {
        schema_version: manifest.schema_version,
        ecosystem_cid: parse_profile_cid(&manifest.ecosystem_cid, Some(DAG_CBOR_CODEC))?,
        cids: manifest
            .cids
            .iter()
            .map(|value| parse_profile_cid(value, None))
            .collect::<Result<_, _>>()?,
    };
    let package = package_dag_cbor(canonical)?;
    Ok(PinsetManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

pub fn verify_pinset_manifest_car(bytes: &[u8]) -> Result<PinsetManifestPackage, ManifestError> {
    let package: DagCborPackage<CanonicalPinsetManifestV1> = verify_dag_cbor_car(bytes)?;
    let manifest = PinsetManifestV1 {
        schema_version: package.value.schema_version,
        ecosystem_cid: package.value.ecosystem_cid.to_string(),
        cids: package.value.cids.iter().map(ToString::to_string).collect(),
    };
    validate_pinset_manifest(&manifest)?;
    Ok(PinsetManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

pub fn verify_pinset_manifest_for_transition(
    pinset: &PinsetManifestPackage,
    candidate: &EcosystemManifestPackage,
    patch: &EcosystemPatchManifestPackage,
) -> Result<(), ManifestError> {
    if pinset.manifest.ecosystem_cid != candidate.root_cid.to_string() {
        return invalid("pinset ecosystem CID does not match the candidate ecosystem");
    }
    let actual = pinset
        .manifest
        .cids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required = required_pinset_cids(candidate, patch)?;
    if !required.is_subset(&actual) {
        return invalid("pinset omits candidate, patch, source, artifact, or parameter content");
    }
    Ok(())
}

fn required_pinset_cids(
    candidate: &EcosystemManifestPackage,
    patch: &EcosystemPatchManifestPackage,
) -> Result<BTreeSet<String>, ManifestError> {
    let candidate_cid = candidate.root_cid.to_string();
    if patch.manifest.candidate_ecosystem_cid != candidate_cid {
        return invalid("pinset transition does not target the candidate ecosystem");
    }
    let mut cids = BTreeSet::from([
        candidate_cid,
        patch.root_cid.to_string(),
        candidate.manifest.governance_parameter_set_cid.clone(),
    ]);
    for repository in &candidate.manifest.repositories {
        cids.insert(repository.source_tree_cid.clone());
        for artifact in &repository.artifacts {
            cids.insert(artifact.cid.clone());
        }
    }
    for repository_patch in &patch.manifest.repository_patches {
        cids.insert(repository_patch.patch_cid.clone());
    }
    Ok(cids)
}

pub fn verify_ecosystem_transition(
    parent: &EcosystemManifestPackage,
    candidate: &EcosystemManifestPackage,
    patch: &EcosystemPatchManifestPackage,
) -> Result<Vec<String>, ManifestError> {
    let parent_cid = parent.root_cid.to_string();
    let candidate_cid = candidate.root_cid.to_string();
    if candidate.manifest.parent_ecosystem_cid.as_deref() != Some(parent_cid.as_str()) {
        return invalid("candidate parentEcosystemCid does not match the verified parent CAR");
    }
    if patch.manifest.parent_ecosystem_cid != parent_cid
        || patch.manifest.candidate_ecosystem_cid != candidate_cid
    {
        return invalid("aggregate patch does not bind the verified parent and candidate CARs");
    }
    let parent_sources = parent
        .manifest
        .repositories
        .iter()
        .map(|repository| {
            (
                repository.name.as_str(),
                repository.source_tree_cid.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let candidate_sources = candidate
        .manifest
        .repositories
        .iter()
        .map(|repository| {
            (
                repository.name.as_str(),
                repository.source_tree_cid.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if parent_sources.keys().ne(candidate_sources.keys()) {
        return invalid("candidate repository source set differs from its parent");
    }
    let changed = parent_sources
        .iter()
        .filter_map(|(name, source)| {
            (candidate_sources.get(name).copied() != Some(*source)).then_some(*name)
        })
        .collect::<Vec<_>>();
    if changed.len() != patch.manifest.repository_patches.len() {
        return invalid("aggregate patch does not exactly cover candidate source changes");
    }
    for (name, repository_patch) in changed.iter().zip(patch.manifest.repository_patches.iter()) {
        if repository_patch.repository != *name
            || parent_sources.get(name).copied() != Some(repository_patch.base_source_cid.as_str())
            || candidate_sources.get(name).copied()
                != Some(repository_patch.candidate_source_cid.as_str())
        {
            return invalid(
                "aggregate patch source transition differs from the ecosystem manifests",
            );
        }
    }
    Ok(changed.into_iter().map(str::to_string).collect())
}

pub fn validate_ecosystem_patch_manifest(
    manifest: &EcosystemPatchManifestV1,
) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 || manifest.kind != "pohw-ecosystem-patch-v1" {
        return invalid("ecosystem patch schemaVersion or kind is invalid");
    }
    parse_profile_cid(&manifest.parent_ecosystem_cid, Some(DAG_CBOR_CODEC))?;
    parse_profile_cid(&manifest.candidate_ecosystem_cid, Some(DAG_CBOR_CODEC))?;
    if manifest.parent_ecosystem_cid == manifest.candidate_ecosystem_cid {
        return invalid("ecosystem patch must change the ecosystem CID");
    }
    if manifest.repository_patches.is_empty()
        || manifest.repository_patches.len() > MAX_REPOSITORY_PATCHES
    {
        return invalid("repositoryPatches count is outside the deterministic limits");
    }
    let mut previous = None;
    for patch in &manifest.repository_patches {
        validate_portable_name(&patch.repository, 80, "repository")?;
        if previous.is_some_and(|name: &str| name >= patch.repository.as_str()) {
            return invalid("repositoryPatches must be uniquely sorted by repository");
        }
        previous = Some(patch.repository.as_str());
        parse_profile_cid(&patch.base_source_cid, Some(DAG_CBOR_CODEC))?;
        parse_profile_cid(&patch.candidate_source_cid, Some(DAG_CBOR_CODEC))?;
        if patch.base_source_cid == patch.candidate_source_cid {
            return invalid("repository patch base and candidate CIDs must differ");
        }
        let patch_cid = parse_profile_cid(&patch.patch_cid, Some(DAG_CBOR_CODEC))?;
        validate_sha256(&patch.patch_sha256)?;
        if hex::encode(patch_cid.hash().digest()) != patch.patch_sha256 {
            return invalid("repository patch CID and SHA-256 disagree");
        }
    }
    Ok(())
}

pub fn validate_toolchain_manifest(manifest: &ToolchainManifestV1) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return invalid("toolchain manifest schemaVersion must be 1");
    }
    validate_string_map(&manifest.ecosystem_locks, "ecosystemLocks")?;
    if manifest.repository_locks.is_empty() || manifest.repository_locks.len() > MAX_REPOSITORIES {
        return invalid("repositoryLocks count is outside the deterministic limits");
    }
    let mut previous = None;
    for repository in &manifest.repository_locks {
        validate_portable_name(&repository.repository, 80, "toolchain repository")?;
        if previous.is_some_and(|name: &str| name >= repository.repository.as_str()) {
            return invalid("repositoryLocks must be uniquely sorted by repository");
        }
        previous = Some(repository.repository.as_str());
        validate_string_map(&repository.toolchain_locks, "repository toolchainLocks")?;
    }
    Ok(())
}

pub fn validate_pinset_manifest(manifest: &PinsetManifestV1) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return invalid("pinset manifest schemaVersion must be 1");
    }
    parse_profile_cid(&manifest.ecosystem_cid, Some(DAG_CBOR_CODEC))?;
    if manifest.cids.is_empty() || manifest.cids.len() > MAX_PINSET_CIDS {
        return invalid("pinset CID count is outside the deterministic limits");
    }
    let mut previous = None;
    for cid in &manifest.cids {
        parse_profile_cid(cid, None)?;
        if previous.is_some_and(|value: &str| value >= cid.as_str()) {
            return invalid("pinset CIDs must be uniquely sorted");
        }
        previous = Some(cid.as_str());
    }
    Ok(())
}

pub fn validate_ecosystem_manifest(manifest: &EcosystemManifestV1) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    validate_identifier(&manifest.ecosystem_id, 3, 80, true)?;
    if let Some(parent) = &manifest.parent_ecosystem_cid {
        parse_profile_cid(parent, Some(DAG_CBOR_CODEC))?;
    }
    parse_profile_cid(&manifest.governance_parameter_set_cid, Some(DAG_CBOR_CODEC))?;
    validate_semver(&manifest.governance_contract_version)?;
    if manifest.repositories.is_empty() || manifest.repositories.len() > MAX_REPOSITORIES {
        return invalid("repository count is outside the deterministic limits");
    }
    let mut previous_name: Option<&str> = None;
    let mut names = BTreeSet::new();
    let mut artifact_names = BTreeSet::new();
    for repository in &manifest.repositories {
        if previous_name.is_some_and(|previous| previous >= repository.name.as_str()) {
            return invalid("repositories must be uniquely sorted by name");
        }
        previous_name = Some(&repository.name);
        if !names.insert(repository.name.as_str()) {
            return invalid("repository names must be unique");
        }
        validate_repository_manifest(repository)?;
        for artifact in &repository.artifacts {
            if !artifact_names.insert(artifact.name.as_str()) {
                return invalid("artifact names must be unique across the ecosystem");
            }
        }
    }
    validate_string_map(&manifest.toolchain_locks, "toolchainLocks")?;
    if manifest.compatibility_pins.len() > MAX_COMPATIBILITY_CONSUMERS {
        return invalid("compatibilityPins has too many consumers");
    }
    for (consumer, pins) in &manifest.compatibility_pins {
        validate_identifier(consumer, 1, 120, false)?;
        validate_string_map(pins, "compatibilityPins")?;
    }
    Ok(())
}

fn validate_repository_manifest(repository: &RepositoryManifestV1) -> Result<(), ManifestError> {
    if repository.schema_version != 1 {
        return invalid("repository schemaVersion must be 1");
    }
    validate_portable_name(&repository.name, 80, "repository")?;
    let source = parse_profile_cid(&repository.source_tree_cid, Some(DAG_CBOR_CODEC))?;
    validate_sha256(&repository.source_tree_sha256)?;
    if hex::encode(source.hash().digest()) != repository.source_tree_sha256 {
        return invalid("sourceTreeSha256 must equal the source-tree CID digest");
    }
    if let Some(bundle) = &repository.git_bundle_cid {
        parse_profile_cid(bundle, Some(RAW_CODEC))?;
    }
    if let Some(commit) = &repository.git_commit_metadata {
        if !matches!(commit.len(), 40 | 64) || !is_lower_hex(commit) {
            return invalid("gitCommitMetadata must be a lowercase 40- or 64-digit hash");
        }
    }
    if repository.dependency_locks.len() > MAX_DEPENDENCY_LOCKS {
        return invalid("dependencyLocks exceeds the deterministic limit");
    }
    let mut previous_lock: Option<&str> = None;
    for lock in &repository.dependency_locks {
        validate_relative_path(&lock.path)?;
        validate_sha256(&lock.sha256)?;
        if previous_lock.is_some_and(|previous| previous >= lock.path.as_str()) {
            return invalid("dependencyLocks must be uniquely sorted by path");
        }
        previous_lock = Some(&lock.path);
    }
    validate_string_map(&repository.toolchain_locks, "repository toolchainLocks")?;
    if repository.build_instructions.is_empty()
        || repository.build_instructions.len() > MAX_BUILD_INSTRUCTIONS
    {
        return invalid("buildInstructions count is outside the deterministic limits");
    }
    for command in &repository.build_instructions {
        validate_text(command, 1, 4096, "build instruction")?;
    }
    if repository.artifacts.len() > MAX_REPOSITORY_ARTIFACTS {
        return invalid("artifacts exceeds the deterministic limit");
    }
    let mut previous_artifact: Option<&str> = None;
    for artifact in &repository.artifacts {
        validate_artifact_name(&artifact.name)?;
        validate_sha256(&artifact.sha256)?;
        let cid = parse_profile_cid(&artifact.cid, Some(RAW_CODEC))?;
        if hex::encode(cid.hash().digest()) != artifact.sha256 {
            return invalid("artifact SHA-256 must equal its raw CID digest");
        }
        if artifact.size > MAX_PORTABLE_ARTIFACT_SIZE {
            return invalid("artifact size exceeds the portable integer limit");
        }
        if previous_artifact.is_some_and(|previous| previous >= artifact.name.as_str()) {
            return invalid("artifacts must be uniquely sorted by name");
        }
        previous_artifact = Some(&artifact.name);
    }
    Ok(())
}

fn canonical_ecosystem(
    manifest: &EcosystemManifestV1,
) -> Result<CanonicalEcosystemManifestV1, ManifestError> {
    Ok(CanonicalEcosystemManifestV1 {
        schema_version: manifest.schema_version,
        ecosystem_id: manifest.ecosystem_id.clone(),
        parent_ecosystem_cid: manifest
            .parent_ecosystem_cid
            .as_deref()
            .map(|value| parse_profile_cid(value, Some(DAG_CBOR_CODEC)))
            .transpose()?,
        repositories: manifest
            .repositories
            .iter()
            .map(canonical_repository)
            .collect::<Result<_, _>>()?,
        compatibility_pins: manifest.compatibility_pins.clone(),
        toolchain_locks: manifest.toolchain_locks.clone(),
        governance_contract_version: manifest.governance_contract_version.clone(),
        governance_parameter_set_cid: parse_profile_cid(
            &manifest.governance_parameter_set_cid,
            Some(DAG_CBOR_CODEC),
        )?,
    })
}

fn canonical_ecosystem_patch(
    manifest: &EcosystemPatchManifestV1,
) -> Result<CanonicalEcosystemPatchManifestV1, ManifestError> {
    Ok(CanonicalEcosystemPatchManifestV1 {
        schema_version: manifest.schema_version,
        kind: manifest.kind.clone(),
        parent_ecosystem_cid: parse_profile_cid(
            &manifest.parent_ecosystem_cid,
            Some(DAG_CBOR_CODEC),
        )?,
        candidate_ecosystem_cid: parse_profile_cid(
            &manifest.candidate_ecosystem_cid,
            Some(DAG_CBOR_CODEC),
        )?,
        repository_patches: manifest
            .repository_patches
            .iter()
            .map(|patch| {
                Ok(CanonicalRepositoryPatchManifestV1 {
                    repository: patch.repository.clone(),
                    base_source_cid: parse_profile_cid(
                        &patch.base_source_cid,
                        Some(DAG_CBOR_CODEC),
                    )?,
                    candidate_source_cid: parse_profile_cid(
                        &patch.candidate_source_cid,
                        Some(DAG_CBOR_CODEC),
                    )?,
                    patch_cid: parse_profile_cid(&patch.patch_cid, Some(DAG_CBOR_CODEC))?,
                    patch_sha256: patch.patch_sha256.clone(),
                })
            })
            .collect::<Result<_, ManifestError>>()?,
    })
}

fn canonical_repository(
    repository: &RepositoryManifestV1,
) -> Result<CanonicalRepositoryManifestV1, ManifestError> {
    Ok(CanonicalRepositoryManifestV1 {
        schema_version: repository.schema_version,
        name: repository.name.clone(),
        source_tree_cid: parse_profile_cid(&repository.source_tree_cid, Some(DAG_CBOR_CODEC))?,
        source_tree_sha256: repository.source_tree_sha256.clone(),
        git_bundle_cid: repository
            .git_bundle_cid
            .as_deref()
            .map(|value| parse_profile_cid(value, Some(RAW_CODEC)))
            .transpose()?,
        git_commit_metadata: repository.git_commit_metadata.clone(),
        dependency_locks: repository.dependency_locks.clone(),
        toolchain_locks: repository.toolchain_locks.clone(),
        build_instructions: repository.build_instructions.clone(),
        artifacts: repository
            .artifacts
            .iter()
            .map(|artifact| {
                Ok(CanonicalArtifactManifestV1 {
                    name: artifact.name.clone(),
                    cid: parse_profile_cid(&artifact.cid, Some(RAW_CODEC))?,
                    sha256: artifact.sha256.clone(),
                    size: artifact.size,
                })
            })
            .collect::<Result<_, ManifestError>>()?,
    })
}

fn human_ecosystem(canonical: &CanonicalEcosystemManifestV1) -> EcosystemManifestV1 {
    EcosystemManifestV1 {
        schema_version: canonical.schema_version,
        ecosystem_id: canonical.ecosystem_id.clone(),
        parent_ecosystem_cid: canonical.parent_ecosystem_cid.map(|cid| cid.to_string()),
        repositories: canonical
            .repositories
            .iter()
            .map(|repository| RepositoryManifestV1 {
                schema_version: repository.schema_version,
                name: repository.name.clone(),
                source_tree_cid: repository.source_tree_cid.to_string(),
                source_tree_sha256: repository.source_tree_sha256.clone(),
                git_bundle_cid: repository.git_bundle_cid.map(|cid| cid.to_string()),
                git_commit_metadata: repository.git_commit_metadata.clone(),
                dependency_locks: repository.dependency_locks.clone(),
                toolchain_locks: repository.toolchain_locks.clone(),
                build_instructions: repository.build_instructions.clone(),
                artifacts: repository
                    .artifacts
                    .iter()
                    .map(|artifact| ArtifactManifestV1 {
                        name: artifact.name.clone(),
                        cid: artifact.cid.to_string(),
                        sha256: artifact.sha256.clone(),
                        size: artifact.size,
                    })
                    .collect(),
            })
            .collect(),
        compatibility_pins: canonical.compatibility_pins.clone(),
        toolchain_locks: canonical.toolchain_locks.clone(),
        governance_contract_version: canonical.governance_contract_version.clone(),
        governance_parameter_set_cid: canonical.governance_parameter_set_cid.to_string(),
    }
}

fn human_ecosystem_patch(
    canonical: &CanonicalEcosystemPatchManifestV1,
) -> EcosystemPatchManifestV1 {
    EcosystemPatchManifestV1 {
        schema_version: canonical.schema_version,
        kind: canonical.kind.clone(),
        parent_ecosystem_cid: canonical.parent_ecosystem_cid.to_string(),
        candidate_ecosystem_cid: canonical.candidate_ecosystem_cid.to_string(),
        repository_patches: canonical
            .repository_patches
            .iter()
            .map(|patch| RepositoryPatchManifestV1 {
                repository: patch.repository.clone(),
                base_source_cid: patch.base_source_cid.to_string(),
                candidate_source_cid: patch.candidate_source_cid.to_string(),
                patch_cid: patch.patch_cid.to_string(),
                patch_sha256: patch.patch_sha256.clone(),
            })
            .collect(),
    }
}

fn human_package(
    package: DagCborPackage<CanonicalEcosystemManifestV1>,
    manifest: EcosystemManifestV1,
) -> EcosystemManifestPackage {
    EcosystemManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    }
}

fn human_patch_package(
    package: DagCborPackage<CanonicalEcosystemPatchManifestV1>,
    manifest: EcosystemPatchManifestV1,
) -> EcosystemPatchManifestPackage {
    EcosystemPatchManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    }
}

fn parse_profile_cid(value: &str, codec: Option<u64>) -> Result<Cid, ManifestError> {
    let cid =
        Cid::try_from(value).map_err(|_| ManifestError::Invalid("invalid CID".to_string()))?;
    if cid.version() != Version::V1
        || cid.to_string() != value
        || !value.starts_with('b')
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || codec.is_some_and(|expected| cid.codec() != expected)
    {
        return invalid("CID must be canonical base32 CIDv1 with SHA2-256 and the expected codec");
    }
    Ok(cid)
}

fn validate_sha256(value: &str) -> Result<(), ManifestError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return invalid("SHA-256 values must be 64 lowercase hexadecimal digits");
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_identifier(
    value: &str,
    minimum: usize,
    maximum: usize,
    ecosystem: bool,
) -> Result<(), ManifestError> {
    if value.len() < minimum || value.len() > maximum {
        return invalid("identifier length is outside the schema bounds");
    }
    for (index, byte) in value.bytes().enumerate() {
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (!ecosystem && matches!(byte, b'/' | b':'));
        if !allowed
            || (ecosystem && byte.is_ascii_uppercase())
            || (ecosystem && index == 0 && !byte.is_ascii_alphanumeric())
        {
            return invalid("identifier contains forbidden characters");
        }
    }
    Ok(())
}

fn validate_semver(value: &str) -> Result<(), ManifestError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return invalid("governanceContractVersion must be canonical major.minor.patch");
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 1_024
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return invalid("dependency lock path must be a normalized relative path");
    }
    Ok(())
}

fn validate_text(value: &str, min: usize, max: usize, label: &str) -> Result<(), ManifestError> {
    if value.len() < min
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return invalid(&format!(
            "{label} is empty, too long, or contains control characters"
        ));
    }
    Ok(())
}

fn validate_artifact_name(value: &str) -> Result<(), ManifestError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return invalid("artifact name is not a portable deterministic label");
    }
    Ok(())
}

fn validate_portable_name(value: &str, maximum: usize, label: &str) -> Result<(), ManifestError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return invalid(&format!("{label} is not a portable deterministic label"));
    }
    Ok(())
}

fn validate_string_map(
    values: &BTreeMap<String, String>,
    label: &str,
) -> Result<(), ManifestError> {
    if values.len() > MAX_STRING_MAP_ENTRIES {
        return invalid(&format!("{label} has too many entries"));
    }
    for (key, value) in values {
        validate_identifier(key, 1, 120, false)?;
        validate_text(value, 1, 4096, label)?;
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, ManifestError> {
    Err(ManifestError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cid_for, sha256_hex};

    fn dag_cid(label: &str) -> String {
        cid_for(DAG_CBOR_CODEC, label.as_bytes()).to_string()
    }

    fn raw_artifact(label: &str) -> ArtifactManifestV1 {
        let bytes = label.as_bytes();
        ArtifactManifestV1 {
            name: label.to_string(),
            cid: cid_for(RAW_CODEC, bytes).to_string(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        }
    }

    fn manifest() -> EcosystemManifestV1 {
        let source_bytes = b"source";
        EcosystemManifestV1 {
            schema_version: 1,
            ecosystem_id: "ubiubi18.pohw-testnet".to_string(),
            parent_ecosystem_cid: None,
            repositories: vec![RepositoryManifestV1 {
                schema_version: 1,
                name: "P2poolBTC".to_string(),
                source_tree_cid: cid_for(DAG_CBOR_CODEC, source_bytes).to_string(),
                source_tree_sha256: sha256_hex(source_bytes),
                git_bundle_cid: None,
                git_commit_metadata: Some("0".repeat(40)),
                dependency_locks: vec![DependencyLockV1 {
                    path: "Cargo.lock".to_string(),
                    sha256: "1".repeat(64),
                }],
                toolchain_locks: BTreeMap::from([("rust".to_string(), "1.97.0".to_string())]),
                build_instructions: vec!["cargo build --workspace --locked".to_string()],
                artifacts: vec![raw_artifact("pohw-governance")],
            }],
            compatibility_pins: BTreeMap::new(),
            toolchain_locks: BTreeMap::from([("node".to_string(), "24.18.0".to_string())]),
            governance_contract_version: "0.1.0".to_string(),
            governance_parameter_set_cid: dag_cid("parameters"),
        }
    }

    #[test]
    fn ecosystem_car_round_trips_with_native_cid_links() {
        let first = package_ecosystem_manifest(manifest()).unwrap();
        let second = package_ecosystem_manifest(manifest()).unwrap();
        assert_eq!(first.root_cid, second.root_cid);
        assert_eq!(first.car_bytes, second.car_bytes);
        let verified = verify_ecosystem_manifest_car(&first.car_bytes).unwrap();
        assert_eq!(verified.manifest, first.manifest);
        assert_eq!(verified.root_cid, first.root_cid);
    }

    #[test]
    fn ecosystem_map_keys_follow_the_governance_schema_grammar() {
        let mut value = manifest();
        value.toolchain_locks = BTreeMap::from([
            ("/node".to_string(), "24.18.0".to_string()),
            ("rust:compiler".to_string(), "1.97.0".to_string()),
        ]);
        value.compatibility_pins = BTreeMap::from([(
            "/consumer:v1".to_string(),
            BTreeMap::from([("source/pin".to_string(), "exact-revision".to_string())]),
        )]);

        package_ecosystem_manifest(value).unwrap();
    }

    #[test]
    fn transition_derives_canonical_toolchain_and_exact_pinset_manifests() {
        let parent = package_ecosystem_manifest(manifest()).unwrap();
        let mut candidate_value = parent.manifest.clone();
        candidate_value.parent_ecosystem_cid = Some(parent.root_cid.to_string());
        let candidate_source = dag_cid("candidate-source");
        candidate_value.repositories[0].source_tree_sha256 =
            hex::encode(candidate_source.parse::<Cid>().unwrap().hash().digest());
        candidate_value.repositories[0].source_tree_cid = candidate_source.clone();
        let candidate = package_ecosystem_manifest(candidate_value).unwrap();
        let repository_patch = b"repository-patch";
        let patch = package_ecosystem_patch_manifest(EcosystemPatchManifestV1 {
            schema_version: 1,
            kind: "pohw-ecosystem-patch-v1".to_string(),
            parent_ecosystem_cid: parent.root_cid.to_string(),
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            repository_patches: vec![RepositoryPatchManifestV1 {
                repository: "P2poolBTC".to_string(),
                base_source_cid: parent.manifest.repositories[0].source_tree_cid.clone(),
                candidate_source_cid: candidate_source.clone(),
                patch_cid: cid_for(DAG_CBOR_CODEC, repository_patch).to_string(),
                patch_sha256: sha256_hex(repository_patch),
            }],
        })
        .unwrap();

        let toolchain = package_toolchain_manifest_for_ecosystem(&candidate.manifest).unwrap();
        assert_eq!(
            toolchain.value.ecosystem_locks,
            candidate.manifest.toolchain_locks
        );
        assert_eq!(toolchain.value.repository_locks.len(), 1);
        let verified_toolchain = verify_toolchain_manifest_car(&toolchain.car_bytes).unwrap();
        assert_eq!(verified_toolchain.root_cid, toolchain.root_cid);
        assert_eq!(verified_toolchain.value, toolchain.value);

        let additional = cid_for(RAW_CODEC, b"rationale").to_string();
        let pinset = package_pinset_manifest_for_transition_with_additional(
            &candidate,
            &patch,
            std::slice::from_ref(&additional),
        )
        .unwrap();
        let expected = BTreeSet::from([
            candidate.root_cid.to_string(),
            patch.root_cid.to_string(),
            candidate_source,
            candidate.manifest.governance_parameter_set_cid.clone(),
            candidate.manifest.repositories[0].artifacts[0].cid.clone(),
            patch.manifest.repository_patches[0].patch_cid.clone(),
            additional,
        ]);
        assert_eq!(
            pinset.manifest.cids,
            expected.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            pinset.manifest.ecosystem_cid,
            candidate.root_cid.to_string()
        );
        let verified = verify_pinset_manifest_car(&pinset.car_bytes).unwrap();
        verify_pinset_manifest_for_transition(&verified, &candidate, &patch).unwrap();
    }

    #[test]
    fn semantic_array_reordering_is_rejected() {
        let mut value = manifest();
        value.repositories[0].artifacts = vec![raw_artifact("z"), raw_artifact("a")];
        assert!(package_ecosystem_manifest(value).is_err());
    }

    #[test]
    fn ecosystem_artifact_names_are_globally_unambiguous() {
        let mut value = manifest();
        let mut second = value.repositories[0].clone();
        second.name = "idena-go".to_string();
        second.source_tree_cid = dag_cid("idena-source");
        second.source_tree_sha256 = hex::encode(
            second
                .source_tree_cid
                .parse::<Cid>()
                .unwrap()
                .hash()
                .digest(),
        );
        value.repositories.push(second);
        assert!(package_ecosystem_manifest(value).is_err());
    }

    #[test]
    fn ecosystem_transition_rejects_an_unlisted_repository_change() {
        let mut parent_manifest = manifest();
        let mut second = parent_manifest.repositories[0].clone();
        second.name = "idena-go".to_string();
        second.source_tree_cid = dag_cid("idena-base");
        second.source_tree_sha256 = hex::encode(
            second
                .source_tree_cid
                .parse::<Cid>()
                .unwrap()
                .hash()
                .digest(),
        );
        second.artifacts = vec![raw_artifact("idena-go")];
        parent_manifest.repositories.push(second);
        let parent = package_ecosystem_manifest(parent_manifest).unwrap();

        let mut candidate_manifest = parent.manifest.clone();
        candidate_manifest.parent_ecosystem_cid = Some(parent.root_cid.to_string());
        for repository in &mut candidate_manifest.repositories {
            let source = dag_cid(&format!("{}-candidate", repository.name));
            repository.source_tree_sha256 =
                hex::encode(source.parse::<Cid>().unwrap().hash().digest());
            repository.source_tree_cid = source;
        }
        let candidate = package_ecosystem_manifest(candidate_manifest).unwrap();
        let repository = &parent.manifest.repositories[0];
        let candidate_repository = &candidate.manifest.repositories[0];
        let patch_bytes = b"p2pool-patch";
        let incomplete = package_ecosystem_patch_manifest(EcosystemPatchManifestV1 {
            schema_version: 1,
            kind: "pohw-ecosystem-patch-v1".to_string(),
            parent_ecosystem_cid: parent.root_cid.to_string(),
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            repository_patches: vec![RepositoryPatchManifestV1 {
                repository: repository.name.clone(),
                base_source_cid: repository.source_tree_cid.clone(),
                candidate_source_cid: candidate_repository.source_tree_cid.clone(),
                patch_cid: cid_for(DAG_CBOR_CODEC, patch_bytes).to_string(),
                patch_sha256: sha256_hex(patch_bytes),
            }],
        })
        .unwrap();

        assert!(verify_ecosystem_transition(&parent, &candidate, &incomplete).is_err());
    }

    #[test]
    fn ecosystem_manifest_enforces_collection_limits() {
        let mut value = manifest();
        value.repositories = vec![value.repositories[0].clone(); MAX_REPOSITORIES + 1];
        assert!(package_ecosystem_manifest(value).is_err());

        let mut value = manifest();
        value.repositories[0].dependency_locks =
            vec![value.repositories[0].dependency_locks[0].clone(); MAX_DEPENDENCY_LOCKS + 1];
        assert!(package_ecosystem_manifest(value).is_err());

        let mut value = manifest();
        value.repositories[0].artifacts =
            vec![value.repositories[0].artifacts[0].clone(); MAX_REPOSITORY_ARTIFACTS + 1];
        assert!(package_ecosystem_manifest(value).is_err());
    }

    #[test]
    fn aggregate_patch_is_atomic_and_ordered() {
        let patch_one = b"patch-one";
        let patch_two = b"patch-two";
        let manifest = EcosystemPatchManifestV1 {
            schema_version: 1,
            kind: "pohw-ecosystem-patch-v1".to_string(),
            parent_ecosystem_cid: dag_cid("parent"),
            candidate_ecosystem_cid: dag_cid("candidate"),
            repository_patches: vec![
                RepositoryPatchManifestV1 {
                    repository: "P2poolBTC".to_string(),
                    base_source_cid: dag_cid("p2pool-base"),
                    candidate_source_cid: dag_cid("p2pool-candidate"),
                    patch_cid: cid_for(DAG_CBOR_CODEC, patch_one).to_string(),
                    patch_sha256: sha256_hex(patch_one),
                },
                RepositoryPatchManifestV1 {
                    repository: "idena-go".to_string(),
                    base_source_cid: dag_cid("idena-base"),
                    candidate_source_cid: dag_cid("idena-candidate"),
                    patch_cid: cid_for(DAG_CBOR_CODEC, patch_two).to_string(),
                    patch_sha256: sha256_hex(patch_two),
                },
            ],
        };
        let package = package_ecosystem_patch_manifest(manifest.clone()).unwrap();
        let verified = verify_ecosystem_patch_manifest_car(&package.car_bytes).unwrap();
        assert_eq!(verified.manifest, manifest);

        let mut reordered = manifest;
        reordered.repository_patches.reverse();
        assert!(package_ecosystem_patch_manifest(reordered).is_err());
    }
}
