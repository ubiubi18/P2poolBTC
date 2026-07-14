use crate::{package_dag_cbor, verify_dag_cbor_car, DagCborPackage, SourceError};
use cid::{Cid, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_PORTABLE_ARTIFACT_SIZE: u64 = 9_007_199_254_740_991;
const MAX_PORTABLE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_RELEASE_ARTIFACTS: usize = 4_096;
const MAX_BUILDER_ATTESTATIONS: usize = 256;

const DAG_CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;
const SHA2_256_CODE: u64 = 0x12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseArtifactV1 {
    pub name: String,
    pub cid: String,
    pub sha256: String,
    pub size: u64,
    pub platform: String,
    pub architecture: String,
    pub minimum_builder_attestations: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema_version: u16,
    pub ecosystem_cid: String,
    pub proposal_id: String,
    pub version: String,
    pub sequence: u64,
    pub artifacts: Vec<ReleaseArtifactV1>,
    pub builder_attestation_root: String,
    pub builder_attestation_cids: Vec<String>,
    pub minimum_builder_attestations: u16,
    pub minimum_builder_platforms: u16,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalReleaseArtifactV1 {
    name: String,
    cid: Cid,
    sha256: String,
    size: u64,
    platform: String,
    architecture: String,
    minimum_builder_attestations: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalReleaseManifestV1 {
    schema_version: u16,
    ecosystem_cid: Cid,
    proposal_id: String,
    version: String,
    sequence: u64,
    artifacts: Vec<CanonicalReleaseArtifactV1>,
    builder_attestation_root: String,
    builder_attestation_cids: Vec<Cid>,
    minimum_builder_attestations: u16,
    minimum_builder_platforms: u16,
    created_at: u64,
}

#[derive(Debug, Clone)]
pub struct ReleaseManifestPackage {
    pub root_cid: Cid,
    pub root_sha256: String,
    pub manifest: ReleaseManifestV1,
    pub dag_cbor_bytes: Vec<u8>,
    pub car_bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("release manifest is invalid: {0}")]
    Invalid(String),
    #[error(transparent)]
    Source(#[from] SourceError),
}

pub fn package_release_manifest(
    manifest: ReleaseManifestV1,
) -> Result<ReleaseManifestPackage, ReleaseError> {
    validate_release_manifest(&manifest)?;
    let canonical = canonical_release(&manifest)?;
    let package = package_dag_cbor(canonical)?;
    Ok(ReleaseManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

pub fn verify_release_manifest_car(bytes: &[u8]) -> Result<ReleaseManifestPackage, ReleaseError> {
    let package: DagCborPackage<CanonicalReleaseManifestV1> = verify_dag_cbor_car(bytes)?;
    let manifest = human_release(&package.value);
    validate_release_manifest(&manifest)?;
    Ok(ReleaseManifestPackage {
        root_cid: package.root_cid,
        root_sha256: package.root_sha256,
        manifest,
        dag_cbor_bytes: package.dag_cbor_bytes,
        car_bytes: package.car_bytes,
    })
}

pub fn validate_release_manifest(manifest: &ReleaseManifestV1) -> Result<(), ReleaseError> {
    if manifest.schema_version != 1 {
        return invalid("schemaVersion must be 1");
    }
    parse_profile_cid(&manifest.ecosystem_cid, DAG_CBOR_CODEC)?;
    validate_sha256(&manifest.proposal_id)?;
    validate_semver(&manifest.version)?;
    validate_sha256(&manifest.builder_attestation_root)?;
    if manifest.sequence > MAX_PORTABLE_INTEGER || manifest.created_at > MAX_PORTABLE_INTEGER {
        return invalid("release sequence or timestamp exceeds the portable integer limit");
    }
    if manifest.minimum_builder_attestations < 2
        || manifest.minimum_builder_platforms == 0
        || manifest.minimum_builder_platforms > manifest.minimum_builder_attestations
    {
        return invalid("builder thresholds are invalid");
    }
    if manifest.builder_attestation_cids.len() < usize::from(manifest.minimum_builder_attestations)
        || manifest.builder_attestation_cids.len() > MAX_BUILDER_ATTESTATIONS
    {
        return invalid("builder attestation CID count is outside the deterministic limits");
    }
    let mut previous_cid: Option<&str> = None;
    for value in &manifest.builder_attestation_cids {
        parse_profile_cid(value, DAG_CBOR_CODEC)?;
        if previous_cid.is_some_and(|previous| previous >= value.as_str()) {
            return invalid("builder attestation CIDs must be uniquely sorted");
        }
        previous_cid = Some(value);
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_RELEASE_ARTIFACTS {
        return invalid("artifact count is outside the deterministic limits");
    }
    let mut previous_name: Option<&str> = None;
    let mut artifact_cids = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_artifact_name(&artifact.name)?;
        validate_label(&artifact.platform, 31, "platform")?;
        validate_label(&artifact.architecture, 31, "architecture")?;
        validate_sha256(&artifact.sha256)?;
        let cid = parse_profile_cid(&artifact.cid, RAW_CODEC)?;
        if hex::encode(cid.hash().digest()) != artifact.sha256 {
            return invalid("artifact CID and SHA-256 disagree");
        }
        if artifact.size > MAX_PORTABLE_ARTIFACT_SIZE {
            return invalid("artifact size exceeds the portable integer limit");
        }
        if artifact.minimum_builder_attestations < manifest.minimum_builder_attestations {
            return invalid("artifact builder threshold is below the release threshold");
        }
        if previous_name.is_some_and(|previous| previous >= artifact.name.as_str()) {
            return invalid("artifacts must be uniquely sorted by name");
        }
        previous_name = Some(&artifact.name);
        if !artifact_cids.insert(&artifact.cid) {
            return invalid("artifact CIDs must be unique");
        }
    }
    Ok(())
}

fn canonical_release(
    manifest: &ReleaseManifestV1,
) -> Result<CanonicalReleaseManifestV1, ReleaseError> {
    Ok(CanonicalReleaseManifestV1 {
        schema_version: manifest.schema_version,
        ecosystem_cid: parse_profile_cid(&manifest.ecosystem_cid, DAG_CBOR_CODEC)?,
        proposal_id: manifest.proposal_id.clone(),
        version: manifest.version.clone(),
        sequence: manifest.sequence,
        artifacts: manifest
            .artifacts
            .iter()
            .map(|artifact| {
                Ok(CanonicalReleaseArtifactV1 {
                    name: artifact.name.clone(),
                    cid: parse_profile_cid(&artifact.cid, RAW_CODEC)?,
                    sha256: artifact.sha256.clone(),
                    size: artifact.size,
                    platform: artifact.platform.clone(),
                    architecture: artifact.architecture.clone(),
                    minimum_builder_attestations: artifact.minimum_builder_attestations,
                })
            })
            .collect::<Result<_, ReleaseError>>()?,
        builder_attestation_root: manifest.builder_attestation_root.clone(),
        builder_attestation_cids: manifest
            .builder_attestation_cids
            .iter()
            .map(|value| parse_profile_cid(value, DAG_CBOR_CODEC))
            .collect::<Result<_, _>>()?,
        minimum_builder_attestations: manifest.minimum_builder_attestations,
        minimum_builder_platforms: manifest.minimum_builder_platforms,
        created_at: manifest.created_at,
    })
}

fn human_release(value: &CanonicalReleaseManifestV1) -> ReleaseManifestV1 {
    ReleaseManifestV1 {
        schema_version: value.schema_version,
        ecosystem_cid: value.ecosystem_cid.to_string(),
        proposal_id: value.proposal_id.clone(),
        version: value.version.clone(),
        sequence: value.sequence,
        artifacts: value
            .artifacts
            .iter()
            .map(|artifact| ReleaseArtifactV1 {
                name: artifact.name.clone(),
                cid: artifact.cid.to_string(),
                sha256: artifact.sha256.clone(),
                size: artifact.size,
                platform: artifact.platform.clone(),
                architecture: artifact.architecture.clone(),
                minimum_builder_attestations: artifact.minimum_builder_attestations,
            })
            .collect(),
        builder_attestation_root: value.builder_attestation_root.clone(),
        builder_attestation_cids: value
            .builder_attestation_cids
            .iter()
            .map(ToString::to_string)
            .collect(),
        minimum_builder_attestations: value.minimum_builder_attestations,
        minimum_builder_platforms: value.minimum_builder_platforms,
        created_at: value.created_at,
    }
}

fn parse_profile_cid(value: &str, codec: u64) -> Result<Cid, ReleaseError> {
    let cid: Cid = value
        .parse()
        .map_err(|_| ReleaseError::Invalid("CID is malformed".to_string()))?;
    if cid.version() != Version::V1
        || cid.codec() != codec
        || cid.hash().code() != SHA2_256_CODE
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        return invalid("CID profile must be CIDv1/base32/SHA2-256");
    }
    Ok(cid)
}

fn validate_sha256(value: &str) -> Result<(), ReleaseError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return invalid("SHA-256 must be canonical lowercase hexadecimal");
    }
    Ok(())
}

fn validate_semver(value: &str) -> Result<(), ReleaseError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || part.bytes().any(|byte| !byte.is_ascii_digit())
        })
    {
        return invalid("version must be canonical major.minor.patch");
    }
    Ok(())
}

fn validate_label(value: &str, maximum: usize, label: &str) -> Result<(), ReleaseError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return invalid(&format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_artifact_name(value: &str) -> Result<(), ReleaseError> {
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

fn invalid<T>(message: &str) -> Result<T, ReleaseError> {
    Err(ReleaseError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid_for;

    fn dag(label: &str) -> String {
        cid_for(DAG_CBOR_CODEC, label.as_bytes()).to_string()
    }

    fn raw(label: &str) -> (String, String) {
        let cid = cid_for(RAW_CODEC, label.as_bytes());
        (cid.to_string(), hex::encode(cid.hash().digest()))
    }

    fn manifest() -> ReleaseManifestV1 {
        let (artifact_cid, artifact_sha256) = raw("artifact");
        let mut builders = vec![dag("builder-a"), dag("builder-b")];
        builders.sort();
        ReleaseManifestV1 {
            schema_version: 1,
            ecosystem_cid: dag("ecosystem"),
            proposal_id: "1".repeat(64),
            version: "0.1.0".to_string(),
            sequence: 1,
            artifacts: vec![ReleaseArtifactV1 {
                name: "idena-desktop-linux".to_string(),
                cid: artifact_cid,
                sha256: artifact_sha256,
                size: 8,
                platform: "linux".to_string(),
                architecture: "x86_64".to_string(),
                minimum_builder_attestations: 2,
            }],
            builder_attestation_root: "2".repeat(64),
            builder_attestation_cids: builders,
            minimum_builder_attestations: 2,
            minimum_builder_platforms: 1,
            created_at: 1,
        }
    }

    #[test]
    fn release_round_trip_preserves_native_cid_links() {
        let package = package_release_manifest(manifest()).unwrap();
        let verified = verify_release_manifest_car(&package.car_bytes).unwrap();
        assert_eq!(verified.root_cid, package.root_cid);
        assert_eq!(verified.manifest, package.manifest);
    }

    #[test]
    fn release_rejects_weak_or_inconsistent_builder_and_artifact_claims() {
        let mut value = manifest();
        value.minimum_builder_attestations = 1;
        assert!(validate_release_manifest(&value).is_err());

        let mut value = manifest();
        value.artifacts[0].sha256 = "0".repeat(64);
        assert!(validate_release_manifest(&value).is_err());

        let mut value = manifest();
        value.artifacts[0].minimum_builder_attestations = 1;
        assert!(validate_release_manifest(&value).is_err());

        let mut value = manifest();
        value.builder_attestation_cids = vec![dag("builder"); MAX_BUILDER_ATTESTATIONS + 1];
        assert!(validate_release_manifest(&value).is_err());

        let mut value = manifest();
        value.artifacts = vec![value.artifacts[0].clone(); MAX_RELEASE_ARTIFACTS + 1];
        assert!(validate_release_manifest(&value).is_err());
    }
}
