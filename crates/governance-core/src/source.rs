use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use regex::bytes::Regex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

const RAW_CODEC: u64 = 0x55;
const DAG_CBOR_CODEC: u64 = 0x71;
const MAX_SOURCE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SOURCE_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CAR_SECTION_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 100_000;
const MAX_CAR_BLOCKS: usize = MAX_SOURCE_FILES + 1;
const MAX_SOURCE_PATH_BYTES: usize = 4_096;
const MAX_SOURCE_PATH_DEPTH: usize = 64;
const MAX_SOURCE_COMPONENT_BYTES: usize = 255;
const GENERATED_ECOSYSTEM_LOCK_PATH: &str = "ecosystem-lock.json";
const GENERATED_COMPONENT_CHECKOUTS: &[&str] = &[
    "idena-go",
    "idena-sdk-js-lite",
    "idena-wasm",
    "idena-wasm-binding",
    "wasmer",
];
const GENERATED_OUTPUT_DIRECTORIES: &[&str] = &["renderer/out"];
const VCS_CONTROL_NAMES: &[&str] = &[".git", ".hg", ".svn"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFileEntryV1 {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    pub cid: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceTreeManifestV1 {
    pub schema_version: u16,
    pub kind: String,
    pub repository: String,
    pub files: Vec<SourceFileEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePatchV1 {
    pub schema_version: u16,
    pub kind: String,
    pub repository: String,
    pub base_source_cid: String,
    pub candidate_source_cid: String,
    pub removed_paths: Vec<String>,
    pub upserted_files: Vec<SourceFileEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalSourceFileEntryV1 {
    path: String,
    mode: u32,
    size: u64,
    cid: Cid,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalSourceTreeManifestV1 {
    schema_version: u16,
    kind: String,
    repository: String,
    files: Vec<CanonicalSourceFileEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalSourcePatchV1 {
    schema_version: u16,
    kind: String,
    repository: String,
    base_source_cid: Cid,
    candidate_source_cid: Cid,
    removed_paths: Vec<String>,
    upserted_files: Vec<CanonicalSourceFileEntryV1>,
}

#[derive(Debug, Clone)]
pub struct SourcePackage {
    pub root_cid: Cid,
    pub source_tree_sha256: String,
    pub manifest: SourceTreeManifestV1,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SourcePatchPackage {
    pub patch_cid: Cid,
    pub patch_sha256: String,
    pub patch: SourcePatchV1,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSourcePatch {
    pub patch_cid: Cid,
    pub patch_sha256: String,
    pub patch: SourcePatchV1,
}

#[derive(Debug, Clone)]
pub struct VerifiedSourcePackage {
    pub root_cid: Cid,
    pub source_tree_sha256: String,
    pub manifest: SourceTreeManifestV1,
    blocks: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DagCborPackage<T> {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub value: T,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

impl VerifiedSourcePackage {
    pub fn file_bytes(&self, entry: &SourceFileEntryV1) -> Result<&[u8], SourceError> {
        self.blocks
            .get(&entry.cid)
            .map(Vec::as_slice)
            .ok_or_else(|| SourceError::MissingBlock(entry.cid.clone()))
    }
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("source root must be a non-symlink directory: {0}")]
    InvalidRoot(String),
    #[error("repository name is invalid: {0}")]
    InvalidRepository(String),
    #[error("source path is unsafe or non-portable: {0}")]
    UnsafePath(String),
    #[error("source path is a symlink or special file: {0}")]
    UnsafeFileType(String),
    #[error("source path is forbidden by the secret/local-state policy: {0}")]
    ForbiddenPath(String),
    #[error("source file appears to contain a secret ({reason}): {path}")]
    SecretContent { path: String, reason: &'static str },
    #[error("source file exceeds {MAX_SOURCE_FILE_BYTES} bytes: {0}")]
    FileTooLarge(String),
    #[error("source tree exceeds {MAX_SOURCE_TREE_BYTES} bytes")]
    TreeTooLarge,
    #[error("source manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("CAR file is malformed: {0}")]
    InvalidCar(String),
    #[error("CID verification failed for {0}")]
    CidMismatch(String),
    #[error("CAR is missing block {0}")]
    MissingBlock(String),
    #[error("output directory must be absent or empty and contain no symlinks: {0}")]
    UnsafeOutput(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("DAG-CBOR error: {0}")]
    Cbor(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CarHeader {
    roots: Vec<Cid>,
    version: u64,
}

#[derive(Debug)]
struct ParsedCar {
    root: Cid,
    order: Vec<Cid>,
    blocks: BTreeMap<String, Vec<u8>>,
}

pub fn package_source_tree(root: &Path, repository: &str) -> Result<SourcePackage, SourceError> {
    package_source_tree_with_artifact_exclusions(root, repository, &BTreeMap::new())
}

pub fn package_source_tree_with_artifact_exclusions(
    root: &Path,
    repository: &str,
    artifact_exclusions: &BTreeMap<String, String>,
) -> Result<SourcePackage, SourceError> {
    validate_repository(repository)?;
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceError::InvalidRoot(root.display().to_string()));
    }

    validate_artifact_exclusions(artifact_exclusions)?;
    let mut collected = Vec::new();
    let mut total_bytes = 0u64;
    let mut seen_exclusions = BTreeSet::new();
    collect_source_files(
        root,
        Path::new(""),
        &mut collected,
        &mut total_bytes,
        artifact_exclusions,
        &mut seen_exclusions,
    )?;
    if seen_exclusions.len() != artifact_exclusions.len() {
        let missing = artifact_exclusions
            .keys()
            .find(|path| !seen_exclusions.contains(*path))
            .expect("exclusion cardinality mismatch implies a missing path");
        return Err(SourceError::InvalidManifest(format!(
            "declared artifact exclusion was not found: {missing}"
        )));
    }
    collected.sort_by(|left, right| left.0.cmp(&right.0));

    let mut files = Vec::with_capacity(collected.len());
    let mut raw_blocks = BTreeMap::<String, Vec<u8>>::new();
    for (path, mode, bytes) in collected {
        let cid = cid_for(RAW_CODEC, &bytes);
        let cid_text = cid.to_string();
        let entry = SourceFileEntryV1 {
            path,
            mode,
            size: bytes.len() as u64,
            cid: cid_text.clone(),
            sha256: sha256_hex(&bytes),
        };
        files.push(entry);
        raw_blocks.entry(cid_text).or_insert(bytes);
    }

    let manifest = SourceTreeManifestV1 {
        schema_version: 1,
        kind: "pohw-source-tree-v1".to_string(),
        repository: repository.to_string(),
        files,
    };
    validate_manifest(&manifest, &raw_blocks)?;
    let root_bytes = encode_source_manifest(&manifest)?;
    let root_cid = cid_for(DAG_CBOR_CODEC, &root_bytes);
    let car_bytes = encode_source_car(&root_cid, &root_bytes, &manifest, &raw_blocks)?;
    Ok(SourcePackage {
        root_cid,
        source_tree_sha256: sha256_hex(&root_bytes),
        manifest,
        car_bytes,
    })
}

pub fn package_dag_cbor<T>(value: T) -> Result<DagCborPackage<T>, SourceError>
where
    T: Serialize,
{
    let dag_cbor_bytes = canonical_dag_cbor(&value)?;
    let root_cid = cid_for(DAG_CBOR_CODEC, &dag_cbor_bytes);
    let car_bytes = encode_single_block_car(&root_cid, &dag_cbor_bytes)?;
    Ok(DagCborPackage {
        root_cid,
        root_sha256: sha256_hex(&dag_cbor_bytes),
        value,
        dag_cbor_bytes,
        car_bytes,
    })
}

pub fn verify_dag_cbor_car<T>(bytes: &[u8]) -> Result<DagCborPackage<T>, SourceError>
where
    T: Serialize + DeserializeOwned,
{
    let parsed = parse_car(bytes)?;
    validate_cid_profile(&parsed.root, DAG_CBOR_CODEC)?;
    if parsed.order != vec![parsed.root] || parsed.blocks.len() != 1 {
        return Err(SourceError::InvalidCar(
            "canonical object CAR must contain exactly its root block".to_string(),
        ));
    }
    let root_bytes = parsed
        .blocks
        .get(&parsed.root.to_string())
        .ok_or_else(|| SourceError::MissingBlock(parsed.root.to_string()))?;
    let value: T = serde_ipld_dagcbor::from_slice(root_bytes)
        .map_err(|error| SourceError::Cbor(error.to_string()))?;
    if canonical_dag_cbor(&value)? != *root_bytes {
        return Err(SourceError::InvalidCar(
            "root object is not canonical DAG-CBOR".to_string(),
        ));
    }
    Ok(DagCborPackage {
        root_cid: parsed.root,
        root_sha256: sha256_hex(root_bytes),
        value,
        dag_cbor_bytes: root_bytes.clone(),
        car_bytes: bytes.to_vec(),
    })
}

pub fn verify_car_integrity(bytes: &[u8]) -> Result<Cid, SourceError> {
    Ok(parse_car(bytes)?.root)
}

pub fn verify_source_car(bytes: &[u8]) -> Result<VerifiedSourcePackage, SourceError> {
    let parsed = parse_car(bytes)?;
    validate_cid_profile(&parsed.root, DAG_CBOR_CODEC)?;
    let root_text = parsed.root.to_string();
    let root_bytes = parsed
        .blocks
        .get(&root_text)
        .ok_or_else(|| SourceError::MissingBlock(root_text.clone()))?;
    verify_block_cid(&parsed.root, root_bytes)?;
    let manifest = decode_source_manifest(root_bytes)?;
    if encode_source_manifest(&manifest)? != *root_bytes {
        return Err(SourceError::InvalidManifest(
            "root block is not canonical DAG-CBOR".to_string(),
        ));
    }
    validate_manifest(&manifest, &parsed.blocks)?;

    let mut expected_order = vec![parsed.root];
    let mut seen = BTreeSet::new();
    for entry in &manifest.files {
        if seen.insert(entry.cid.clone()) {
            expected_order.push(parse_cid(&entry.cid)?);
        }
    }
    if parsed.order != expected_order {
        return Err(SourceError::InvalidCar(
            "block order must be root first followed by unique file CIDs in sorted path order"
                .to_string(),
        ));
    }
    if parsed.blocks.len() != expected_order.len() {
        return Err(SourceError::InvalidCar(
            "CAR contains duplicate or unreferenced blocks".to_string(),
        ));
    }

    let raw_blocks = manifest
        .files
        .iter()
        .map(|entry| {
            let bytes = parsed
                .blocks
                .get(&entry.cid)
                .expect("validated manifest block must exist")
                .clone();
            (entry.cid.clone(), bytes)
        })
        .collect::<BTreeMap<_, _>>();
    let canonical_car = encode_source_car(&parsed.root, root_bytes, &manifest, &raw_blocks)?;
    if canonical_car != bytes {
        return Err(SourceError::InvalidCar(
            "CAR encoding is valid but not deterministic canonical CARv1".to_string(),
        ));
    }

    Ok(VerifiedSourcePackage {
        root_cid: parsed.root,
        source_tree_sha256: sha256_hex(root_bytes),
        manifest,
        blocks: parsed.blocks,
    })
}

pub fn verify_tree_matches_car(
    root: &Path,
    repository: &str,
    car_bytes: &[u8],
) -> Result<VerifiedSourcePackage, SourceError> {
    verify_tree_matches_car_with_artifact_exclusions(root, repository, car_bytes, &BTreeMap::new())
}

pub fn verify_tree_matches_car_with_artifact_exclusions(
    root: &Path,
    repository: &str,
    car_bytes: &[u8],
    artifact_exclusions: &BTreeMap<String, String>,
) -> Result<VerifiedSourcePackage, SourceError> {
    let verified = verify_source_car(car_bytes)?;
    let current =
        package_source_tree_with_artifact_exclusions(root, repository, artifact_exclusions)?;
    if current.root_cid != verified.root_cid || current.car_bytes != car_bytes {
        return Err(SourceError::CidMismatch(verified.root_cid.to_string()));
    }
    Ok(verified)
}

pub fn create_source_patch(
    base_car: &[u8],
    candidate_car: &[u8],
) -> Result<SourcePatchPackage, SourceError> {
    let base = verify_source_car(base_car)?;
    let candidate = verify_source_car(candidate_car)?;
    if base.manifest.repository != candidate.manifest.repository {
        return Err(SourceError::InvalidManifest(
            "base and candidate repositories differ".to_string(),
        ));
    }
    let base_files = base
        .manifest
        .files
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let candidate_files = candidate
        .manifest
        .files
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let removed_paths = base_files
        .keys()
        .filter(|path| !candidate_files.contains_key(**path))
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    let upserted_files = candidate_files
        .iter()
        .filter(|(path, entry)| match base_files.get(**path) {
            Some(base) => base != *entry,
            None => true,
        })
        .map(|(_, entry)| (*entry).clone())
        .collect::<Vec<_>>();
    if removed_paths.is_empty() && upserted_files.is_empty() {
        return Err(SourceError::InvalidManifest(
            "source patch must contain at least one change".to_string(),
        ));
    }
    let patch = SourcePatchV1 {
        schema_version: 1,
        kind: "pohw-source-patch-v1".to_string(),
        repository: base.manifest.repository.clone(),
        base_source_cid: base.root_cid.to_string(),
        candidate_source_cid: candidate.root_cid.to_string(),
        removed_paths,
        upserted_files,
    };
    let root_bytes = encode_source_patch(&patch)?;
    let patch_cid = cid_for(DAG_CBOR_CODEC, &root_bytes);
    let mut blocks = BTreeMap::new();
    for entry in &patch.upserted_files {
        blocks.insert(entry.cid.clone(), candidate.file_bytes(entry)?.to_vec());
    }
    let car_bytes = encode_patch_car(&patch_cid, &root_bytes, &patch, &blocks)?;
    verify_source_patch(base_car, candidate_car, &car_bytes)?;
    Ok(SourcePatchPackage {
        patch_cid,
        patch_sha256: sha256_hex(&root_bytes),
        patch,
        car_bytes,
    })
}

pub fn verify_source_patch(
    base_car: &[u8],
    candidate_car: &[u8],
    patch_car: &[u8],
) -> Result<VerifiedSourcePatch, SourceError> {
    let base = verify_source_car(base_car)?;
    let candidate = verify_source_car(candidate_car)?;
    let parsed = parse_car(patch_car)?;
    validate_cid_profile(&parsed.root, DAG_CBOR_CODEC)?;
    let root_text = parsed.root.to_string();
    let root_bytes = parsed
        .blocks
        .get(&root_text)
        .ok_or_else(|| SourceError::MissingBlock(root_text.clone()))?;
    let patch = decode_source_patch(root_bytes)?;
    if encode_source_patch(&patch)? != *root_bytes {
        return Err(SourceError::InvalidManifest(
            "patch root is not canonical DAG-CBOR".to_string(),
        ));
    }
    validate_patch(&patch, &base, &candidate, &parsed.blocks)?;

    let mut expected_order = vec![parsed.root];
    let mut seen = BTreeSet::new();
    for entry in &patch.upserted_files {
        if seen.insert(entry.cid.clone()) {
            expected_order.push(parse_cid(&entry.cid)?);
        }
    }
    if parsed.order != expected_order || parsed.blocks.len() != expected_order.len() {
        return Err(SourceError::InvalidCar(
            "patch CAR contains noncanonical, duplicate, or unreferenced blocks".to_string(),
        ));
    }
    let blocks = patch
        .upserted_files
        .iter()
        .map(|entry| {
            (
                entry.cid.clone(),
                parsed
                    .blocks
                    .get(&entry.cid)
                    .expect("validated patch block")
                    .clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if encode_patch_car(&parsed.root, root_bytes, &patch, &blocks)? != patch_car {
        return Err(SourceError::InvalidCar(
            "patch CAR is not deterministic canonical CARv1".to_string(),
        ));
    }
    Ok(VerifiedSourcePatch {
        patch_cid: parsed.root,
        patch_sha256: sha256_hex(root_bytes),
        patch,
    })
}

pub fn checkout_source_car(bytes: &[u8], output: &Path) -> Result<Cid, SourceError> {
    let verified = verify_source_car(bytes)?;
    prepare_output_directory(output)?;
    for entry in &verified.manifest.files {
        let relative = validated_relative_path(&entry.path)?;
        let destination = output.join(&relative);
        let parent = destination
            .parent()
            .ok_or_else(|| SourceError::UnsafeOutput(destination.display().to_string()))?;
        create_checkout_directories(output, parent)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(entry.mode);
        }
        let mut file = options.open(&destination)?;
        file.write_all(verified.file_bytes(entry)?)?;
        file.sync_all()?;
        set_normalized_mode(&destination, entry.mode)?;
    }
    Ok(verified.root_cid)
}

pub fn canonical_dag_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, SourceError> {
    serde_ipld_dagcbor::to_vec(value).map_err(|error| SourceError::Cbor(error.to_string()))
}

fn encode_source_manifest(manifest: &SourceTreeManifestV1) -> Result<Vec<u8>, SourceError> {
    let canonical = CanonicalSourceTreeManifestV1 {
        schema_version: manifest.schema_version,
        kind: manifest.kind.clone(),
        repository: manifest.repository.clone(),
        files: manifest
            .files
            .iter()
            .map(canonical_file_entry)
            .collect::<Result<_, _>>()?,
    };
    canonical_dag_cbor(&canonical)
}

fn decode_source_manifest(bytes: &[u8]) -> Result<SourceTreeManifestV1, SourceError> {
    let canonical: CanonicalSourceTreeManifestV1 = serde_ipld_dagcbor::from_slice(bytes)
        .map_err(|error| SourceError::Cbor(error.to_string()))?;
    Ok(SourceTreeManifestV1 {
        schema_version: canonical.schema_version,
        kind: canonical.kind,
        repository: canonical.repository,
        files: canonical.files.into_iter().map(human_file_entry).collect(),
    })
}

fn encode_source_patch(patch: &SourcePatchV1) -> Result<Vec<u8>, SourceError> {
    let canonical = CanonicalSourcePatchV1 {
        schema_version: patch.schema_version,
        kind: patch.kind.clone(),
        repository: patch.repository.clone(),
        base_source_cid: parse_cid(&patch.base_source_cid)?,
        candidate_source_cid: parse_cid(&patch.candidate_source_cid)?,
        removed_paths: patch.removed_paths.clone(),
        upserted_files: patch
            .upserted_files
            .iter()
            .map(canonical_file_entry)
            .collect::<Result<_, _>>()?,
    };
    canonical_dag_cbor(&canonical)
}

fn decode_source_patch(bytes: &[u8]) -> Result<SourcePatchV1, SourceError> {
    let canonical: CanonicalSourcePatchV1 = serde_ipld_dagcbor::from_slice(bytes)
        .map_err(|error| SourceError::Cbor(error.to_string()))?;
    Ok(SourcePatchV1 {
        schema_version: canonical.schema_version,
        kind: canonical.kind,
        repository: canonical.repository,
        base_source_cid: canonical.base_source_cid.to_string(),
        candidate_source_cid: canonical.candidate_source_cid.to_string(),
        removed_paths: canonical.removed_paths,
        upserted_files: canonical
            .upserted_files
            .into_iter()
            .map(human_file_entry)
            .collect(),
    })
}

fn canonical_file_entry(
    entry: &SourceFileEntryV1,
) -> Result<CanonicalSourceFileEntryV1, SourceError> {
    Ok(CanonicalSourceFileEntryV1 {
        path: entry.path.clone(),
        mode: entry.mode,
        size: entry.size,
        cid: parse_cid(&entry.cid)?,
        sha256: entry.sha256.clone(),
    })
}

fn human_file_entry(entry: CanonicalSourceFileEntryV1) -> SourceFileEntryV1 {
    SourceFileEntryV1 {
        path: entry.path,
        mode: entry.mode,
        size: entry.size,
        cid: entry.cid.to_string(),
        sha256: entry.sha256,
    }
}

pub fn cid_for(codec: u64, bytes: &[u8]) -> Cid {
    Cid::new_v1(codec, Code::Sha2_256.digest(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn collect_source_files(
    root: &Path,
    relative: &Path,
    output: &mut Vec<(String, u32, Vec<u8>)>,
    total_bytes: &mut u64,
    artifact_exclusions: &BTreeMap<String, String>,
    seen_exclusions: &mut BTreeSet<String>,
) -> Result<(), SourceError> {
    let directory = root.join(relative);
    let mut entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SourceError::UnsafePath(entry.path().display().to_string()))?;
        validate_component(&name)?;
        let child_relative = relative.join(&name);
        let display = portable_path(&child_relative)?;
        if VCS_CONTROL_NAMES.contains(&name.as_str()) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            if artifact_exclusions.contains_key(&display) {
                return Err(SourceError::UnsafeFileType(display));
            }
            let target = fs::read_link(entry.path())?;
            if target.is_absolute() {
                return Err(SourceError::UnsafeFileType(display));
            }
            let canonical_root = fs::canonicalize(root)?;
            let canonical_target = fs::canonicalize(
                entry
                    .path()
                    .parent()
                    .ok_or_else(|| SourceError::UnsafeFileType(display.clone()))?
                    .join(target),
            )?;
            if canonical_target == canonical_root || !canonical_target.starts_with(&canonical_root)
            {
                return Err(SourceError::UnsafeFileType(display));
            }
            let target_metadata = fs::metadata(&canonical_target)?;
            if !target_metadata.is_file() {
                return Err(SourceError::UnsafeFileType(display));
            }
            reject_forbidden_file(&display, &name)?;
            let (bytes, mode) =
                read_stable_regular_file(&canonical_target, &target_metadata, &display)?;
            *total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(SourceError::TreeTooLarge)?;
            if *total_bytes > MAX_SOURCE_TREE_BYTES {
                return Err(SourceError::TreeTooLarge);
            }
            scan_secret_content(&display, &bytes)?;
            push_source_file(output, (display, mode, bytes))?;
            continue;
        }
        if metadata.is_dir() {
            if should_skip_directory(relative, &name)
                || should_skip_generated_component_checkout(relative, &name)
                || should_skip_generated_output_directory(&display)
            {
                continue;
            }
            collect_source_files(
                root,
                &child_relative,
                output,
                total_bytes,
                artifact_exclusions,
                seen_exclusions,
            )?;
            continue;
        }
        if !metadata.is_file() {
            return Err(SourceError::UnsafeFileType(display));
        }
        if should_skip_benign_file(&name) {
            continue;
        }
        if should_skip_generated_control_file(&display) {
            continue;
        }
        if let Some(expected_sha256) = artifact_exclusions.get(&display) {
            if !is_excludable_binary_artifact(&name) {
                return Err(SourceError::InvalidManifest(format!(
                    "artifact exclusion is not an approved binary/archive type: {display}"
                )));
            }
            let (bytes, _) = read_stable_regular_file(&entry.path(), &metadata, &display)?;
            if sha256_hex(&bytes) != *expected_sha256 {
                return Err(SourceError::CidMismatch(display));
            }
            seen_exclusions.insert(display);
            continue;
        }
        reject_forbidden_file(&display, &name)?;
        let (bytes, mode) = read_stable_regular_file(&entry.path(), &metadata, &display)?;
        *total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(SourceError::TreeTooLarge)?;
        if *total_bytes > MAX_SOURCE_TREE_BYTES {
            return Err(SourceError::TreeTooLarge);
        }
        scan_secret_content(&display, &bytes)?;
        push_source_file(output, (display, mode, bytes))?;
    }
    Ok(())
}

fn push_source_file(
    output: &mut Vec<(String, u32, Vec<u8>)>,
    entry: (String, u32, Vec<u8>),
) -> Result<(), SourceError> {
    if output.len() >= MAX_SOURCE_FILES {
        return Err(SourceError::InvalidManifest(format!(
            "source tree exceeds the {MAX_SOURCE_FILES}-file limit"
        )));
    }
    output.push(entry);
    Ok(())
}

fn read_stable_regular_file(
    path: &Path,
    expected: &fs::Metadata,
    display: &str,
) -> Result<(Vec<u8>, u32), SourceError> {
    if !expected.is_file() || expected.len() > MAX_SOURCE_FILE_BYTES {
        return Err(if expected.len() > MAX_SOURCE_FILE_BYTES {
            SourceError::FileTooLarge(display.to_string())
        } else {
            SourceError::UnsafeFileType(display.to_string())
        });
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || !same_file_metadata(expected, &opened) {
        return Err(SourceError::UnsafeFileType(display.to_string()));
    }
    if opened.len() > MAX_SOURCE_FILE_BYTES {
        return Err(SourceError::FileTooLarge(display.to_string()));
    }
    let mut bytes = Vec::with_capacity(opened.len().min(1024 * 1024) as usize);
    (&mut file)
        .take(MAX_SOURCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
        return Err(SourceError::UnsafeFileType(display.to_string()));
    }
    Ok((bytes, normalized_mode(&opened)))
}

#[cfg(unix)]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type() && left.len() == right.len()
}

fn validate_artifact_exclusions(
    artifact_exclusions: &BTreeMap<String, String>,
) -> Result<(), SourceError> {
    for (path, sha256) in artifact_exclusions {
        let relative = validated_relative_path(path)?;
        let name = relative
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !is_excludable_binary_artifact(name)
            || sha256.len() != 64
            || sha256
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(SourceError::InvalidManifest(format!(
                "invalid binary artifact exclusion: {path}"
            )));
        }
    }
    Ok(())
}

fn is_excludable_binary_artifact(name: &str) -> bool {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "tar"
            | "tgz"
            | "gz"
            | "zip"
            | "7z"
            | "exe"
            | "dll"
            | "dylib"
            | "so"
            | "o"
            | "a"
            | "class"
            | "wasm"
    )
}

fn validate_manifest(
    manifest: &SourceTreeManifestV1,
    blocks: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SourceError> {
    if manifest.schema_version != 1 || manifest.kind != "pohw-source-tree-v1" {
        return Err(SourceError::InvalidManifest(
            "unsupported source-tree schema or kind".to_string(),
        ));
    }
    validate_repository(&manifest.repository)?;
    if manifest.files.len() > MAX_SOURCE_FILES {
        return Err(SourceError::InvalidManifest(format!(
            "source manifest exceeds the {MAX_SOURCE_FILES}-file limit"
        )));
    }
    let mut previous: Option<&str> = None;
    let mut portable_paths = BTreeSet::new();
    let mut total_bytes = 0u64;
    for entry in &manifest.files {
        let _ = validated_relative_path(&entry.path)?;
        if previous.is_some_and(|value| value >= entry.path.as_str()) {
            return Err(SourceError::InvalidManifest(
                "file paths must be unique and strictly sorted".to_string(),
            ));
        }
        previous = Some(&entry.path);
        if !portable_paths.insert(entry.path.to_lowercase()) {
            return Err(SourceError::InvalidManifest(
                "file paths collide on a case-insensitive filesystem".to_string(),
            ));
        }
        if entry.mode != 0o644 && entry.mode != 0o755 {
            return Err(SourceError::InvalidManifest(format!(
                "invalid normalized mode for {}",
                entry.path
            )));
        }
        reject_forbidden_file(
            &entry.path,
            Path::new(&entry.path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default(),
        )?;
        let cid = parse_cid(&entry.cid)?;
        validate_cid_profile(&cid, RAW_CODEC)?;
        let bytes = blocks
            .get(&entry.cid)
            .ok_or_else(|| SourceError::MissingBlock(entry.cid.clone()))?;
        verify_block_cid(&cid, bytes)?;
        if entry.size > MAX_SOURCE_FILE_BYTES || bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
            return Err(SourceError::FileTooLarge(entry.path.clone()));
        }
        total_bytes = total_bytes
            .checked_add(entry.size)
            .ok_or(SourceError::TreeTooLarge)?;
        if total_bytes > MAX_SOURCE_TREE_BYTES {
            return Err(SourceError::TreeTooLarge);
        }
        if entry.size != bytes.len() as u64 || entry.sha256 != sha256_hex(bytes) {
            return Err(SourceError::InvalidManifest(format!(
                "size or SHA-256 mismatch for {}",
                entry.path
            )));
        }
        scan_secret_content(&entry.path, bytes)?;
    }
    Ok(())
}

fn validate_patch(
    patch: &SourcePatchV1,
    base: &VerifiedSourcePackage,
    candidate: &VerifiedSourcePackage,
    blocks: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SourceError> {
    if patch.schema_version != 1 || patch.kind != "pohw-source-patch-v1" {
        return Err(SourceError::InvalidManifest(
            "unsupported source-patch schema or kind".to_string(),
        ));
    }
    validate_repository(&patch.repository)?;
    if patch.repository != base.manifest.repository
        || patch.repository != candidate.manifest.repository
        || patch.base_source_cid != base.root_cid.to_string()
        || patch.candidate_source_cid != candidate.root_cid.to_string()
    {
        return Err(SourceError::InvalidManifest(
            "patch repository or source CID binding is invalid".to_string(),
        ));
    }
    validate_strictly_sorted_paths(&patch.removed_paths, "removed")?;
    let upserted_paths = patch
        .upserted_files
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    validate_strictly_sorted_paths(&upserted_paths, "upserted")?;
    if patch.removed_paths.is_empty() && patch.upserted_files.is_empty() {
        return Err(SourceError::InvalidManifest(
            "source patch contains no changes".to_string(),
        ));
    }
    if patch
        .removed_paths
        .iter()
        .any(|path| upserted_paths.binary_search(path).is_ok())
    {
        return Err(SourceError::InvalidManifest(
            "a patch path cannot be both removed and upserted".to_string(),
        ));
    }

    let mut reconstructed = base
        .manifest
        .files
        .iter()
        .map(|entry| (entry.path.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    for path in &patch.removed_paths {
        let _ = validated_relative_path(path)?;
        if reconstructed.remove(path).is_none() {
            return Err(SourceError::InvalidManifest(format!(
                "patch removes missing path {path}"
            )));
        }
    }
    for entry in &patch.upserted_files {
        validate_patch_entry(entry, blocks)?;
        reconstructed.insert(entry.path.clone(), entry.clone());
    }
    let reconstructed_manifest = SourceTreeManifestV1 {
        schema_version: 1,
        kind: "pohw-source-tree-v1".to_string(),
        repository: patch.repository.clone(),
        files: reconstructed.into_values().collect(),
    };
    let reconstructed_bytes = encode_source_manifest(&reconstructed_manifest)?;
    let reconstructed_cid = cid_for(DAG_CBOR_CODEC, &reconstructed_bytes);
    if reconstructed_manifest != candidate.manifest
        || reconstructed_cid != candidate.root_cid
        || reconstructed_cid.to_string() != patch.candidate_source_cid
    {
        return Err(SourceError::CidMismatch(patch.candidate_source_cid.clone()));
    }
    Ok(())
}

fn validate_patch_entry(
    entry: &SourceFileEntryV1,
    blocks: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SourceError> {
    let _ = validated_relative_path(&entry.path)?;
    if entry.mode != 0o644 && entry.mode != 0o755 {
        return Err(SourceError::InvalidManifest(format!(
            "invalid normalized mode for {}",
            entry.path
        )));
    }
    let name = Path::new(&entry.path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    reject_forbidden_file(&entry.path, name)?;
    let cid = parse_cid(&entry.cid)?;
    validate_cid_profile(&cid, RAW_CODEC)?;
    let bytes = blocks
        .get(&entry.cid)
        .ok_or_else(|| SourceError::MissingBlock(entry.cid.clone()))?;
    verify_block_cid(&cid, bytes)?;
    if entry.size > MAX_SOURCE_FILE_BYTES || bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
        return Err(SourceError::FileTooLarge(entry.path.clone()));
    }
    if entry.size != bytes.len() as u64 || entry.sha256 != sha256_hex(bytes) {
        return Err(SourceError::InvalidManifest(format!(
            "patch size or SHA-256 mismatch for {}",
            entry.path
        )));
    }
    scan_secret_content(&entry.path, bytes)
}

fn validate_strictly_sorted_paths(paths: &[String], label: &str) -> Result<(), SourceError> {
    let mut previous: Option<&str> = None;
    for path in paths {
        let _ = validated_relative_path(path)?;
        if previous.is_some_and(|value| value >= path.as_str()) {
            return Err(SourceError::InvalidManifest(format!(
                "{label} paths must be unique and strictly sorted"
            )));
        }
        previous = Some(path);
    }
    Ok(())
}

fn encode_source_car(
    root: &Cid,
    root_bytes: &[u8],
    manifest: &SourceTreeManifestV1,
    raw_blocks: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, SourceError> {
    let header = canonical_dag_cbor(&CarHeader {
        roots: vec![*root],
        version: 1,
    })?;
    let mut output = Vec::new();
    write_uvarint(header.len() as u64, &mut output);
    output.extend_from_slice(&header);
    write_car_block(root, root_bytes, &mut output);
    let mut seen = BTreeSet::new();
    for entry in &manifest.files {
        if seen.insert(entry.cid.clone()) {
            let cid = parse_cid(&entry.cid)?;
            let bytes = raw_blocks
                .get(&entry.cid)
                .ok_or_else(|| SourceError::MissingBlock(entry.cid.clone()))?;
            write_car_block(&cid, bytes, &mut output);
        }
    }
    Ok(output)
}

fn encode_single_block_car(root: &Cid, root_bytes: &[u8]) -> Result<Vec<u8>, SourceError> {
    let header = canonical_dag_cbor(&CarHeader {
        roots: vec![*root],
        version: 1,
    })?;
    let mut output = Vec::new();
    write_uvarint(header.len() as u64, &mut output);
    output.extend_from_slice(&header);
    write_car_block(root, root_bytes, &mut output);
    Ok(output)
}

fn encode_patch_car(
    root: &Cid,
    root_bytes: &[u8],
    patch: &SourcePatchV1,
    raw_blocks: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, SourceError> {
    let header = canonical_dag_cbor(&CarHeader {
        roots: vec![*root],
        version: 1,
    })?;
    let mut output = Vec::new();
    write_uvarint(header.len() as u64, &mut output);
    output.extend_from_slice(&header);
    write_car_block(root, root_bytes, &mut output);
    let mut seen = BTreeSet::new();
    for entry in &patch.upserted_files {
        if seen.insert(entry.cid.clone()) {
            let cid = parse_cid(&entry.cid)?;
            let bytes = raw_blocks
                .get(&entry.cid)
                .ok_or_else(|| SourceError::MissingBlock(entry.cid.clone()))?;
            write_car_block(&cid, bytes, &mut output);
        }
    }
    Ok(output)
}

fn parse_car(bytes: &[u8]) -> Result<ParsedCar, SourceError> {
    let mut cursor = Cursor::new(bytes);
    let header_len = read_uvarint(&mut cursor)?;
    if header_len == 0 || header_len > MAX_CAR_SECTION_BYTES {
        return Err(SourceError::InvalidCar("invalid header length".to_string()));
    }
    let header_bytes = read_exact_section(&mut cursor, header_len)?;
    let header: CarHeader = serde_ipld_dagcbor::from_slice(&header_bytes)
        .map_err(|error| SourceError::Cbor(error.to_string()))?;
    if canonical_dag_cbor(&header)? != header_bytes {
        return Err(SourceError::InvalidCar(
            "header is not canonical DAG-CBOR".to_string(),
        ));
    }
    if header.version != 1 || header.roots.len() != 1 {
        return Err(SourceError::InvalidCar(
            "CARv1 requires exactly one source root".to_string(),
        ));
    }
    let root = header.roots[0];
    let mut order = Vec::new();
    let mut blocks = BTreeMap::new();
    while cursor.position() < bytes.len() as u64 {
        if order.len() >= MAX_CAR_BLOCKS {
            return Err(SourceError::InvalidCar(format!(
                "CAR exceeds the {MAX_CAR_BLOCKS}-block limit"
            )));
        }
        let section_len = read_uvarint(&mut cursor)?;
        if section_len == 0 || section_len > MAX_CAR_SECTION_BYTES {
            return Err(SourceError::InvalidCar("invalid block length".to_string()));
        }
        let section = read_exact_section(&mut cursor, section_len)?;
        let mut block_cursor = Cursor::new(section.as_slice());
        let cid = Cid::read_bytes(&mut block_cursor)
            .map_err(|err| SourceError::InvalidCar(format!("invalid block CID: {err}")))?;
        let offset = block_cursor.position() as usize;
        if offset > section.len() {
            return Err(SourceError::InvalidCar(
                "block CID exceeds section length".to_string(),
            ));
        }
        let data = section[offset..].to_vec();
        verify_block_cid(&cid, &data)?;
        let key = cid.to_string();
        if blocks.insert(key.clone(), data).is_some() {
            return Err(SourceError::InvalidCar(format!("duplicate block {key}")));
        }
        order.push(cid);
    }
    if order.first() != Some(&root) {
        return Err(SourceError::InvalidCar(
            "root block must be the first block".to_string(),
        ));
    }
    Ok(ParsedCar {
        root,
        order,
        blocks,
    })
}

fn write_car_block(cid: &Cid, bytes: &[u8], output: &mut Vec<u8>) {
    let cid_bytes = cid.to_bytes();
    write_uvarint((cid_bytes.len() + bytes.len()) as u64, output);
    output.extend_from_slice(&cid_bytes);
    output.extend_from_slice(bytes);
}

fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn read_uvarint(cursor: &mut Cursor<&[u8]>) -> Result<u64, SourceError> {
    let mut result = 0u64;
    for (index, shift) in (0..70).step_by(7).enumerate() {
        let mut byte = [0u8; 1];
        cursor
            .read_exact(&mut byte)
            .map_err(|_| SourceError::InvalidCar("truncated varint".to_string()))?;
        if shift == 63 && byte[0] > 1 {
            return Err(SourceError::InvalidCar("varint overflow".to_string()));
        }
        result |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            if index > 0 && result < (1u64 << (index * 7)) {
                return Err(SourceError::InvalidCar(
                    "non-minimal varint encoding".to_string(),
                ));
            }
            return Ok(result);
        }
    }
    Err(SourceError::InvalidCar("varint overflow".to_string()))
}

fn read_exact_section(cursor: &mut Cursor<&[u8]>, length: u64) -> Result<Vec<u8>, SourceError> {
    let length = usize::try_from(length)
        .map_err(|_| SourceError::InvalidCar("section length overflow".to_string()))?;
    let mut result = vec![0u8; length];
    cursor
        .read_exact(&mut result)
        .map_err(|_| SourceError::InvalidCar("truncated CAR section".to_string()))?;
    Ok(result)
}

fn parse_cid(value: &str) -> Result<Cid, SourceError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| SourceError::InvalidManifest(format!("invalid CID {value}")))?;
    if cid.to_string() != value {
        return Err(SourceError::InvalidManifest(format!(
            "CID must use canonical CIDv1 base32 display: {value}"
        )));
    }
    Ok(cid)
}

fn validate_cid_profile(cid: &Cid, codec: u64) -> Result<(), SourceError> {
    if cid.version() != cid::Version::V1
        || cid.codec() != codec
        || cid.hash().code() != u64::from(Code::Sha2_256)
        || cid.hash().digest().len() != 32
    {
        return Err(SourceError::InvalidManifest(format!(
            "CID does not use CIDv1/{codec:#x}/SHA2-256: {cid}"
        )));
    }
    Ok(())
}

fn verify_block_cid(cid: &Cid, bytes: &[u8]) -> Result<(), SourceError> {
    validate_cid_profile(cid, cid.codec())?;
    if cid_for(cid.codec(), bytes) != *cid {
        return Err(SourceError::CidMismatch(cid.to_string()));
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), SourceError> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(SourceError::InvalidRepository(value.to_string()));
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String, SourceError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(SourceError::UnsafePath(path.display().to_string()));
        };
        let value = value
            .to_str()
            .ok_or_else(|| SourceError::UnsafePath(path.display().to_string()))?;
        validate_component(value)?;
        parts.push(value);
    }
    if parts.is_empty() || parts.len() > MAX_SOURCE_PATH_DEPTH {
        return Err(SourceError::UnsafePath(path.display().to_string()));
    }
    let value = parts.join("/");
    if value.len() > MAX_SOURCE_PATH_BYTES {
        return Err(SourceError::UnsafePath(path.display().to_string()));
    }
    Ok(value)
}

fn validated_relative_path(value: &str) -> Result<PathBuf, SourceError> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        return Err(SourceError::UnsafePath(value.to_string()));
    }
    let path = PathBuf::from(value);
    let canonical_display = portable_path(&path)?;
    if canonical_display != value {
        return Err(SourceError::UnsafePath(value.to_string()));
    }
    Ok(path)
}

fn validate_component(value: &str) -> Result<(), SourceError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_COMPONENT_BYTES
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.ends_with(' ')
        || value.ends_with('.')
        || value.chars().any(char::is_control)
        || value.nfc().collect::<String>() != value
    {
        return Err(SourceError::UnsafePath(value.to_string()));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err(SourceError::UnsafePath(value.to_string()));
    }
    Ok(())
}

fn should_skip_directory(relative: &Path, name: &str) -> bool {
    let always_generated = matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".idea"
            | ".vscode"
            | ".cache"
            | ".mypy_cache"
            | ".next"
            | ".nox"
            | ".parcel-cache"
            | ".pnpm-store"
            | ".pohw-p2pool"
            | ".pytest_cache"
            | ".ruff_cache"
            | ".tox"
            | ".turbo"
            | "__pycache__"
            | "target"
            | "node_modules"
            | "datadir"
            | "idena-data"
            | "bitcoin-data"
    );
    let root_generated = relative.as_os_str().is_empty()
        && matches!(
            name,
            "dist" | "build" | "coverage" | "output" | "tmp" | "temp" | "logs"
        );
    always_generated || root_generated
}

fn should_skip_benign_file(name: &str) -> bool {
    matches!(name, ".DS_Store" | "Thumbs.db") || name.ends_with('~')
}

fn should_skip_generated_control_file(path: &str) -> bool {
    path == GENERATED_ECOSYSTEM_LOCK_PATH
}

fn should_skip_generated_component_checkout(relative: &Path, name: &str) -> bool {
    relative.as_os_str().is_empty() && GENERATED_COMPONENT_CHECKOUTS.contains(&name)
}

fn should_skip_generated_output_directory(path: &str) -> bool {
    GENERATED_OUTPUT_DIRECTORIES.contains(&path)
}

fn is_generated_component_path(path: &str) -> bool {
    path.split_once('/')
        .is_some_and(|(root, _)| GENERATED_COMPONENT_CHECKOUTS.contains(&root))
}

fn is_generated_output_path(path: &str) -> bool {
    GENERATED_OUTPUT_DIRECTORIES.iter().any(|directory| {
        path.strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn is_vcs_control_path(path: &str) -> bool {
    path.split('/')
        .any(|component| VCS_CONTROL_NAMES.contains(&component))
}

fn reject_forbidden_file(path: &str, name: &str) -> Result<(), SourceError> {
    if should_skip_generated_control_file(path)
        || is_generated_component_path(path)
        || is_generated_output_path(path)
        || is_vcs_control_path(path)
    {
        return Err(SourceError::ForbiddenPath(path.to_string()));
    }
    let lower = name.to_ascii_lowercase();
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let env_template = lower == ".env.example" || lower == ".env.template";
    let forbidden_name = (lower == ".env" || lower.starts_with(".env.")) && !env_template;
    let forbidden_extension = matches!(
        extension.as_str(),
        "key"
            | "pem"
            | "p12"
            | "pfx"
            | "keystore"
            | "wallet"
            | "cookie"
            | "pid"
            | "log"
            | "db"
            | "sqlite"
            | "sqlite3"
            | "bak"
            | "tmp"
            | "tar"
            | "tgz"
            | "gz"
            | "zip"
            | "7z"
            | "exe"
            | "dll"
            | "dylib"
            | "so"
            | "o"
            | "a"
            | "class"
            | "wasm"
    );
    if forbidden_name || forbidden_extension {
        return Err(SourceError::ForbiddenPath(path.to_string()));
    }
    Ok(())
}

fn scan_secret_content(path: &str, bytes: &[u8]) -> Result<(), SourceError> {
    for (reason, pattern) in secret_patterns() {
        if pattern.is_match(bytes) {
            return Err(SourceError::SecretContent {
                path: path.to_string(),
                reason,
            });
        }
    }
    Ok(())
}

fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            (
                "private-key PEM",
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            ),
            (
                "GitHub token",
                r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",
            ),
            ("Tailscale key", r"tskey-(?:auth|api)-[A-Za-z0-9_-]{16,}"),
            ("AWS access key", r"AKIA[0-9A-Z]{16}"),
            ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{20,}"),
        ]
        .into_iter()
        .map(|(reason, pattern)| (reason, Regex::new(pattern).expect("static secret regex")))
        .collect()
    })
}

fn prepare_output_directory(output: &Path) -> Result<(), SourceError> {
    if !output.is_absolute() {
        return Err(SourceError::UnsafeOutput(output.display().to_string()));
    }
    validate_existing_ancestors(output)?;
    match fs::symlink_metadata(output) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(SourceError::UnsafeOutput(output.display().to_string()));
            }
            if fs::read_dir(output)?.next().is_some() {
                return Err(SourceError::UnsafeOutput(output.display().to_string()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(output)?;
            set_normalized_mode(output, 0o755)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_existing_ancestors(path: &Path) -> Result<(), SourceError> {
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if !trusted_system_symlink(ancestor, &metadata)? {
                    return Err(SourceError::UnsafeOutput(path.display().to_string()));
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_system_symlink(path: &Path, metadata: &fs::Metadata) -> Result<bool, SourceError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let parent_metadata = fs::metadata(parent)?;
    Ok(metadata.uid() == 0 && parent_metadata.permissions().mode() & 0o022 == 0)
}

#[cfg(not(unix))]
fn trusted_system_symlink(_path: &Path, _metadata: &fs::Metadata) -> Result<bool, SourceError> {
    Ok(false)
}

fn create_checkout_directories(root: &Path, parent: &Path) -> Result<(), SourceError> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| SourceError::UnsafeOutput(parent.display().to_string()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SourceError::UnsafeOutput(parent.display().to_string()));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SourceError::UnsafeOutput(current.display().to_string()));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                set_normalized_mode(&current, 0o755)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        0o755
    } else {
        0o644
    }
}

#[cfg(not(unix))]
fn normalized_mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn set_normalized_mode(path: &Path, mode: u32) -> Result<(), SourceError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_normalized_mode(_path: &Path, _mode: u32) -> Result<(), SourceError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pohw-governance-source-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temp directory");
        path
    }

    #[test]
    fn source_cid_and_car_ignore_timestamps_and_creation_order() {
        let first = temp_dir("first");
        let second = temp_dir("second");
        fs::create_dir(first.join("src")).unwrap();
        fs::write(first.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        fs::write(first.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();

        fs::write(second.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
        fs::create_dir(second.join("src")).unwrap();
        fs::write(second.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();

        let a = package_source_tree(&first, "fixture").unwrap();
        let b = package_source_tree(&second, "fixture").unwrap();
        assert_eq!(a.root_cid, b.root_cid);
        assert_eq!(a.car_bytes, b.car_bytes);
        let verified = verify_source_car(&a.car_bytes).unwrap();
        assert_eq!(verified.root_cid, a.root_cid);

        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }

    #[test]
    fn source_package_excludes_known_local_cache_directories() {
        let root = temp_dir("cache-exclusions");
        fs::write(root.join("README.md"), "fixture\n").unwrap();
        fs::write(root.join(".git"), "gitdir: /private/control/path\n").unwrap();
        fs::create_dir_all(root.join(".pnpm-store/v11")).unwrap();
        fs::write(root.join(".pnpm-store/v11/index.db"), "local cache").unwrap();
        fs::create_dir_all(root.join(".pytest_cache/v/cache")).unwrap();
        fs::write(root.join(".pytest_cache/v/cache/nodeids"), "[]").unwrap();
        fs::create_dir_all(root.join("src/__pycache__")).unwrap();
        fs::write(root.join("src/__pycache__/module.pyc"), "local cache").unwrap();
        fs::create_dir_all(root.join("core/state/datadir/test.db")).unwrap();
        fs::write(root.join("core/state/datadir/test.db/LOG"), "local state").unwrap();

        let package = package_source_tree(&root, "fixture").unwrap();
        assert_eq!(package.manifest.files.len(), 1);
        assert_eq!(package.manifest.files[0].path, "README.md");

        let bytes = b"private control metadata\n".to_vec();
        let cid = cid_for(RAW_CODEC, &bytes).to_string();
        let forged = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "fixture".to_string(),
            files: vec![SourceFileEntryV1 {
                path: ".git/config".to_string(),
                mode: 0o644,
                size: bytes.len() as u64,
                cid: cid.clone(),
                sha256: sha256_hex(&bytes),
            }],
        };
        assert!(matches!(
            validate_manifest(&forged, &BTreeMap::from([(cid, bytes)])),
            Err(SourceError::ForbiddenPath(path)) if path == ".git/config"
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_source_directories_named_like_build_outputs_are_not_silently_omitted() {
        let root = temp_dir("nested-build-names");
        fs::write(root.join("README.md"), "fixture\n").unwrap();
        fs::create_dir_all(root.join("src/build/dist/tmp")).unwrap();
        fs::write(
            root.join("src/build/dist/tmp/module.rs"),
            "pub const VALUE: u8 = 1;\n",
        )
        .unwrap();
        fs::create_dir(root.join("build")).unwrap();
        fs::write(root.join("build/generated.bin"), "ignored root output\n").unwrap();

        let first = package_source_tree(&root, "fixture").unwrap();
        assert!(first
            .manifest
            .files
            .iter()
            .any(|entry| entry.path == "src/build/dist/tmp/module.rs"));
        assert!(!first
            .manifest
            .files
            .iter()
            .any(|entry| entry.path.starts_with("build/")));

        fs::write(
            root.join("src/build/dist/tmp/module.rs"),
            "pub const VALUE: u8 = 2;\n",
        )
        .unwrap();
        let second = package_source_tree(&root, "fixture").unwrap();
        assert_ne!(first.root_cid, second.root_cid);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_package_omits_only_the_root_generated_ecosystem_lock() {
        let root = temp_dir("generated-control-file");
        fs::write(root.join("README.md"), "fixture\n").unwrap();
        fs::write(root.join(GENERATED_ECOSYSTEM_LOCK_PATH), "generated\n").unwrap();
        fs::create_dir(root.join("fixtures")).unwrap();
        fs::write(
            root.join("fixtures").join(GENERATED_ECOSYSTEM_LOCK_PATH),
            "source fixture\n",
        )
        .unwrap();

        let package = package_source_tree(&root, "fixture").unwrap();
        assert_eq!(
            package
                .manifest
                .files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["README.md", "fixtures/ecosystem-lock.json"]
        );

        let bytes = b"generated\n".to_vec();
        let cid = cid_for(RAW_CODEC, &bytes).to_string();
        let forged = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "fixture".to_string(),
            files: vec![SourceFileEntryV1 {
                path: GENERATED_ECOSYSTEM_LOCK_PATH.to_string(),
                mode: 0o644,
                size: bytes.len() as u64,
                cid: cid.clone(),
                sha256: sha256_hex(&bytes),
            }],
        };
        assert!(matches!(
            validate_manifest(&forged, &BTreeMap::from([(cid, bytes)])),
            Err(SourceError::ForbiddenPath(path)) if path == GENERATED_ECOSYSTEM_LOCK_PATH
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_package_omits_only_root_generated_component_checkouts() {
        let root = temp_dir("generated-component-checkout");
        fs::write(root.join("README.md"), "fixture\n").unwrap();
        fs::create_dir(root.join("idena-go")).unwrap();
        fs::write(root.join("idena-go/generated.go"), "package generated\n").unwrap();
        fs::create_dir_all(root.join("fixtures/idena-go")).unwrap();
        fs::write(
            root.join("fixtures/idena-go/source.go"),
            "package fixture\n",
        )
        .unwrap();

        let package = package_source_tree(&root, "fixture").unwrap();
        assert_eq!(
            package
                .manifest
                .files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["README.md", "fixtures/idena-go/source.go"]
        );

        let bytes = b"package generated\n".to_vec();
        let cid = cid_for(RAW_CODEC, &bytes).to_string();
        let forged = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "fixture".to_string(),
            files: vec![SourceFileEntryV1 {
                path: "idena-go/generated.go".to_string(),
                mode: 0o644,
                size: bytes.len() as u64,
                cid: cid.clone(),
                sha256: sha256_hex(&bytes),
            }],
        };
        assert!(matches!(
            validate_manifest(&forged, &BTreeMap::from([(cid, bytes)])),
            Err(SourceError::ForbiddenPath(path)) if path == "idena-go/generated.go"
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_package_omits_only_the_desktop_generated_renderer_output() {
        let root = temp_dir("generated-renderer-output");
        fs::write(root.join("README.md"), "fixture\n").unwrap();
        fs::create_dir_all(root.join("renderer/out")).unwrap();
        fs::write(root.join("renderer/out/index.html"), "generated\n").unwrap();
        fs::create_dir_all(root.join("fixtures/renderer/out")).unwrap();
        fs::write(
            root.join("fixtures/renderer/out/source.html"),
            "source fixture\n",
        )
        .unwrap();

        let package = package_source_tree(&root, "fixture").unwrap();
        assert_eq!(
            package
                .manifest
                .files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["README.md", "fixtures/renderer/out/source.html"]
        );

        let bytes = b"generated\n".to_vec();
        let cid = cid_for(RAW_CODEC, &bytes).to_string();
        let forged = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "fixture".to_string(),
            files: vec![SourceFileEntryV1 {
                path: "renderer/out/index.html".to_string(),
                mode: 0o644,
                size: bytes.len() as u64,
                cid: cid.clone(),
                sha256: sha256_hex(&bytes),
            }],
        };
        assert!(matches!(
            validate_manifest(&forged, &BTreeMap::from([(cid, bytes)])),
            Err(SourceError::ForbiddenPath(path)) if path == "renderer/out/index.html"
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_paths_and_manifests_enforce_portable_resource_bounds() {
        let too_deep = (0..=MAX_SOURCE_PATH_DEPTH)
            .map(|_| "a")
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            validated_relative_path(&too_deep),
            Err(SourceError::UnsafePath(_))
        ));
        assert!(matches!(
            validate_component(&"a".repeat(MAX_SOURCE_COMPONENT_BYTES + 1)),
            Err(SourceError::UnsafePath(_))
        ));

        let bytes = b"same contents".to_vec();
        let cid = cid_for(RAW_CODEC, &bytes).to_string();
        let entry = |path: &str| SourceFileEntryV1 {
            path: path.to_string(),
            mode: 0o644,
            size: bytes.len() as u64,
            cid: cid.clone(),
            sha256: sha256_hex(&bytes),
        };
        let manifest = SourceTreeManifestV1 {
            schema_version: 1,
            kind: "pohw-source-tree-v1".to_string(),
            repository: "fixture".to_string(),
            files: vec![entry("README.md"), entry("readme.md")],
        };
        let blocks = BTreeMap::from([(cid, bytes)]);
        assert!(matches!(
            validate_manifest(&manifest, &blocks),
            Err(SourceError::InvalidManifest(message))
                if message.contains("case-insensitive")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stable_file_read_rejects_a_swapped_inode() {
        let root = temp_dir("stable-read");
        let expected_path = root.join("expected.txt");
        let replacement_path = root.join("replacement.txt");
        fs::write(&expected_path, b"expected").unwrap();
        fs::write(&replacement_path, b"replacement").unwrap();
        let expected = fs::metadata(&expected_path).unwrap();

        assert!(matches!(
            read_stable_regular_file(&replacement_path, &expected, "expected.txt"),
            Err(SourceError::UnsafeFileType(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_rejects_secrets_symlinks_and_local_state() {
        let secret = temp_dir("secret");
        fs::write(
            secret.join("credentials.txt"),
            format!(
                "-----BEGIN {} PRIVATE KEY-----\nnot-a-real-key\n",
                "OPENSSH"
            ),
        )
        .unwrap();
        assert!(matches!(
            package_source_tree(&secret, "fixture"),
            Err(SourceError::SecretContent { .. })
        ));
        fs::remove_dir_all(secret).unwrap();

        let state = temp_dir("state");
        fs::write(state.join("wallet.db"), b"local").unwrap();
        assert!(matches!(
            package_source_tree(&state, "fixture"),
            Err(SourceError::ForbiddenPath(_))
        ));
        fs::remove_dir_all(state).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = temp_dir("symlink");
            fs::write(linked.join("real.txt"), b"source").unwrap();
            symlink(linked.join("real.txt"), linked.join("linked.txt")).unwrap();
            assert!(matches!(
                package_source_tree(&linked, "fixture"),
                Err(SourceError::UnsafeFileType(_))
            ));
            fs::remove_dir_all(linked).unwrap();

            let internal = temp_dir("internal-symlink");
            fs::write(internal.join("real.txt"), b"source").unwrap();
            symlink("real.txt", internal.join("linked.txt")).unwrap();
            let package = package_source_tree(&internal, "fixture").unwrap();
            assert_eq!(package.manifest.files.len(), 2);
            assert_eq!(package.manifest.files[0].path, "linked.txt");
            fs::remove_dir_all(internal).unwrap();

            let escape_parent = temp_dir("escaping-symlink");
            let escape_root = escape_parent.join("source");
            fs::create_dir(&escape_root).unwrap();
            fs::write(escape_parent.join("outside.txt"), b"outside").unwrap();
            symlink("../outside.txt", escape_root.join("escape.txt")).unwrap();
            assert!(matches!(
                package_source_tree(&escape_root, "fixture"),
                Err(SourceError::UnsafeFileType(_))
            ));
            fs::remove_dir_all(escape_parent).unwrap();
        }
    }

    #[test]
    fn reviewed_binary_artifact_exclusions_are_exact_and_fail_closed() {
        let root = temp_dir("artifact-exclusion");
        fs::write(root.join("README.md"), b"fixture\n").unwrap();
        fs::write(root.join("runtime.wasm"), b"reviewed-binary").unwrap();
        let artifact_sha256 = sha256_hex(b"reviewed-binary");
        let exclusions = BTreeMap::from([("runtime.wasm".to_string(), artifact_sha256.clone())]);

        let package =
            package_source_tree_with_artifact_exclusions(&root, "fixture", &exclusions).unwrap();
        assert_eq!(package.manifest.files.len(), 1);
        assert_eq!(package.manifest.files[0].path, "README.md");

        let wrong_digest = BTreeMap::from([("runtime.wasm".to_string(), "0".repeat(64))]);
        assert!(matches!(
            package_source_tree_with_artifact_exclusions(&root, "fixture", &wrong_digest),
            Err(SourceError::CidMismatch(path)) if path == "runtime.wasm"
        ));

        let missing = BTreeMap::from([
            ("missing.wasm".to_string(), artifact_sha256),
            ("runtime.wasm".to_string(), sha256_hex(b"reviewed-binary")),
        ]);
        assert!(matches!(
            package_source_tree_with_artifact_exclusions(&root, "fixture", &missing),
            Err(SourceError::InvalidManifest(message))
                if message.contains("was not found")
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_exclusions_cannot_hide_source_secrets_or_local_state() {
        let root = temp_dir("artifact-exclusion-policy");
        fs::write(root.join("source.rs"), b"source\n").unwrap();
        fs::write(root.join("wallet.db"), b"local-state").unwrap();
        fs::write(root.join("identity.pem"), b"secret-material").unwrap();

        for (path, bytes) in [
            ("source.rs", b"source\n".as_slice()),
            ("wallet.db", b"local-state".as_slice()),
            ("identity.pem", b"secret-material".as_slice()),
        ] {
            let exclusions = BTreeMap::from([(path.to_string(), sha256_hex(bytes))]);
            assert!(matches!(
                package_source_tree_with_artifact_exclusions(&root, "fixture", &exclusions),
                Err(SourceError::InvalidManifest(_))
            ));
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_and_noncanonical_cars_fail_closed() {
        let root = temp_dir("tamper");
        fs::write(root.join("README.md"), b"fixture\n").unwrap();
        let package = package_source_tree(&root, "fixture").unwrap();
        let mut tampered = package.car_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_source_car(&tampered).is_err());

        assert!(package.car_bytes[0] < 0x80);
        let mut non_minimal_varint = vec![package.car_bytes[0] | 0x80, 0];
        non_minimal_varint.extend_from_slice(&package.car_bytes[1..]);
        assert!(matches!(
            verify_source_car(&non_minimal_varint),
            Err(SourceError::InvalidCar(message)) if message.contains("non-minimal varint")
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkout_recreates_exact_tree_and_modes() {
        let root = temp_dir("checkout-source");
        fs::write(root.join("README.md"), b"fixture\n").unwrap();
        let package = package_source_tree(&root, "fixture").unwrap();
        let parent = temp_dir("checkout-parent");
        let output = parent.join("result");
        let cid = checkout_source_car(&package.car_bytes, &output).unwrap();
        assert_eq!(cid, package.root_cid);
        assert_eq!(fs::read(output.join("README.md")).unwrap(), b"fixture\n");
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn source_car_round_trips_zero_byte_files() {
        let root = temp_dir("zero-byte-source");
        fs::write(root.join("empty.txt"), b"").unwrap();
        let package = package_source_tree(&root, "fixture").unwrap();
        let verified = verify_source_car(&package.car_bytes).unwrap();
        assert_eq!(verified.manifest.files.len(), 1);
        assert_eq!(verified.manifest.files[0].size, 0);

        let parent = temp_dir("zero-byte-checkout");
        let output = parent.join("result");
        checkout_source_car(&package.car_bytes, &output).unwrap();
        assert!(fs::read(output.join("empty.txt")).unwrap().is_empty());

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn patch_proves_exact_base_to_candidate_transition() {
        let base = temp_dir("patch-base");
        let candidate = temp_dir("patch-candidate");
        fs::write(base.join("keep.txt"), b"same\n").unwrap();
        fs::write(base.join("modify.txt"), b"before\n").unwrap();
        fs::write(base.join("remove.txt"), b"remove\n").unwrap();
        fs::write(candidate.join("keep.txt"), b"same\n").unwrap();
        fs::write(candidate.join("modify.txt"), b"after\n").unwrap();
        fs::write(candidate.join("new.txt"), b"new\n").unwrap();
        let base_package = package_source_tree(&base, "fixture").unwrap();
        let candidate_package = package_source_tree(&candidate, "fixture").unwrap();
        let patch = create_source_patch(&base_package.car_bytes, &candidate_package.car_bytes)
            .expect("patch");
        assert_eq!(patch.patch.removed_paths, vec!["remove.txt"]);
        assert_eq!(
            patch
                .patch
                .upserted_files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["modify.txt", "new.txt"]
        );
        let verified = verify_source_patch(
            &base_package.car_bytes,
            &candidate_package.car_bytes,
            &patch.car_bytes,
        )
        .unwrap();
        assert_eq!(verified.patch_cid, patch.patch_cid);

        let wrong_candidate = package_source_tree(&base, "fixture").unwrap();
        assert!(verify_source_patch(
            &base_package.car_bytes,
            &wrong_candidate.car_bytes,
            &patch.car_bytes
        )
        .is_err());
        fs::remove_dir_all(base).unwrap();
        fs::remove_dir_all(candidate).unwrap();
    }
}
