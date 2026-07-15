use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const JOIN_MANIFEST_SCHEMA: &str = "pohw-source-join/v1";
pub const AGENT_CONFIG_SCHEMA: &str = "pohw-agent-config/v2";
pub const TRUST_MODEL: &str = "local-source-build";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceJoinManifestV1 {
    pub schema_version: String,
    pub experiment_id: String,
    pub network_mode: String,
    pub trust_model: String,
    pub source: SourceBuildV1,
    pub activation: ActivationPinV1,
    pub launch: LaunchPolicyV1,
    pub peers: PeerSetV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotPinV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceBuildV1 {
    pub repository_url: String,
    pub git_commit: String,
    pub source_tree_cid: String,
    pub source_tree_sha256: String,
    pub cargo_lock_sha256: String,
    pub cyclonedx_sbom_sha256: String,
    pub local_artifact: LocalArtifactV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalArtifactV1 {
    pub target: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationPinV1 {
    pub activation_id: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchPhase {
    Registration,
    ForkSync,
    Mining,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicyV1 {
    pub phase: LaunchPhase,
    pub no_value: bool,
    pub mainnet_handoff_armed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerSetV1 {
    pub gossip: Vec<String>,
    pub fork_rpc: Vec<String>,
    pub fork_p2p: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPinV1 {
    pub snapshot_id: String,
    pub proof_root: String,
    pub source_height: u64,
    pub distinct_voter_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceJoinSummary {
    pub schema_version: String,
    pub experiment_id: String,
    pub trust_model: String,
    pub git_commit: String,
    pub source_tree_cid: String,
    pub source_tree_sha256: String,
    pub cargo_lock_sha256: String,
    pub cyclonedx_sbom_sha256: String,
    pub artifact_target: String,
    pub artifact_sha256: String,
    pub activation_id: String,
    pub activation_manifest_sha256: String,
    pub launch_phase: LaunchPhase,
    pub no_value: bool,
    pub mainnet_handoff_armed: bool,
    pub gossip_peer_count: usize,
    pub fork_rpc_peer_count: usize,
    pub fork_p2p_peer_count: usize,
    pub snapshot_pinned: bool,
    pub join_manifest_sha256: String,
    pub join_manifest_raw_cid: String,
}

impl SourceJoinManifestV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).context("serialize canonical source-join JSON")?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn sha256_hex(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn raw_cid(&self) -> Result<Cid> {
        Ok(raw_cid(&self.canonical_bytes()?))
    }

    pub fn validate(&self, allow_private_peers: bool) -> Result<()> {
        if self.schema_version != JOIN_MANIFEST_SCHEMA {
            bail!(
                "unsupported source-join schema {}; expected {JOIN_MANIFEST_SCHEMA}",
                self.schema_version
            );
        }
        validate_identifier("experiment_id", &self.experiment_id, 64)?;
        if self.network_mode != "join-existing" {
            bail!("source-join network_mode must be join-existing");
        }
        if self.trust_model != TRUST_MODEL {
            bail!("source-join trust_model must be {TRUST_MODEL}");
        }
        validate_https_url("source.repository_url", &self.source.repository_url)?;
        validate_lower_hex("source.git_commit", &self.source.git_commit, 40)?;
        validate_cid("source.source_tree_cid", &self.source.source_tree_cid)?;
        validate_lower_hex(
            "source.source_tree_sha256",
            &self.source.source_tree_sha256,
            64,
        )?;
        validate_lower_hex(
            "source.cargo_lock_sha256",
            &self.source.cargo_lock_sha256,
            64,
        )?;
        validate_lower_hex(
            "source.cyclonedx_sbom_sha256",
            &self.source.cyclonedx_sbom_sha256,
            64,
        )?;
        validate_identifier(
            "source.local_artifact.target",
            &self.source.local_artifact.target,
            64,
        )?;
        validate_lower_hex(
            "source.local_artifact.sha256",
            &self.source.local_artifact.sha256,
            64,
        )?;

        validate_lower_hex(
            "activation.activation_id",
            &self.activation.activation_id,
            64,
        )?;
        validate_lower_hex(
            "activation.manifest_sha256",
            &self.activation.manifest_sha256,
            64,
        )?;
        if !self.launch.no_value {
            bail!("source-join v1 only supports the no-value experiment phase");
        }
        if self.launch.mainnet_handoff_armed {
            bail!("source-join v1 refuses an armed Bitcoin-mainnet handoff");
        }

        validate_peer_list("peers.gossip", &self.peers.gossip, allow_private_peers)?;
        validate_peer_list("peers.fork_rpc", &self.peers.fork_rpc, allow_private_peers)?;
        validate_peer_list("peers.fork_p2p", &self.peers.fork_p2p, allow_private_peers)?;
        if let Some(explorer_url) = &self.peers.explorer_url {
            validate_https_url("peers.explorer_url", explorer_url)?;
        }

        if matches!(self.launch.phase, LaunchPhase::Mining) && self.snapshot.is_none() {
            bail!("mining phase requires a pinned identity snapshot");
        }
        if let Some(snapshot) = &self.snapshot {
            validate_identifier("snapshot.snapshot_id", &snapshot.snapshot_id, 128)?;
            validate_lower_hex("snapshot.proof_root", &snapshot.proof_root, 64)?;
            if snapshot.source_height == 0 {
                bail!("snapshot.source_height must be positive");
            }
            if snapshot.distinct_voter_count == 0 {
                bail!("snapshot.distinct_voter_count must be positive");
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> Result<SourceJoinSummary> {
        Ok(SourceJoinSummary {
            schema_version: self.schema_version.clone(),
            experiment_id: self.experiment_id.clone(),
            trust_model: self.trust_model.clone(),
            git_commit: self.source.git_commit.clone(),
            source_tree_cid: self.source.source_tree_cid.clone(),
            source_tree_sha256: self.source.source_tree_sha256.clone(),
            cargo_lock_sha256: self.source.cargo_lock_sha256.clone(),
            cyclonedx_sbom_sha256: self.source.cyclonedx_sbom_sha256.clone(),
            artifact_target: self.source.local_artifact.target.clone(),
            artifact_sha256: self.source.local_artifact.sha256.clone(),
            activation_id: self.activation.activation_id.clone(),
            activation_manifest_sha256: self.activation.manifest_sha256.clone(),
            launch_phase: self.launch.phase.clone(),
            no_value: self.launch.no_value,
            mainnet_handoff_armed: self.launch.mainnet_handoff_armed,
            gossip_peer_count: self.peers.gossip.len(),
            fork_rpc_peer_count: self.peers.fork_rpc.len(),
            fork_p2p_peer_count: self.peers.fork_p2p.len(),
            snapshot_pinned: self.snapshot.is_some(),
            join_manifest_sha256: self.sha256_hex()?,
            join_manifest_raw_cid: self.raw_cid()?.to_string(),
        })
    }
}

pub fn parse_canonical_manifest(bytes: &[u8]) -> Result<SourceJoinManifestV1> {
    let manifest: SourceJoinManifestV1 =
        serde_json::from_slice(bytes).context("parse source-join manifest")?;
    if bytes != manifest.canonical_bytes()? {
        bail!("source-join manifest is not canonical compact JSON with one trailing newline");
    }
    Ok(manifest)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

pub fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
}

fn validate_identifier(name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_len {
        bail!("{name} must contain between 1 and {max_len} characters");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-:/".contains(&byte))
    {
        bail!("{name} contains unsupported characters");
    }
    Ok(())
}

fn validate_lower_hex(name: &str, value: &str, expected_len: usize) -> Result<()> {
    if value.len() != expected_len
        || value != value.to_ascii_lowercase()
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{name} must be {expected_len} lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_cid(name: &str, value: &str) -> Result<()> {
    let cid = Cid::from_str(value).with_context(|| format!("{name} is invalid"))?;
    if cid.version() != cid::Version::V1 || value != cid.to_string() {
        bail!("{name} must use canonical lowercase CIDv1 display");
    }
    if cid.hash().code() != 0x12 || cid.hash().digest().len() != 32 {
        bail!("{name} must use a SHA2-256 multihash");
    }
    Ok(())
}

fn validate_https_url(name: &str, value: &str) -> Result<()> {
    let url = Url::parse(value).with_context(|| format!("{name} is not a valid URL"))?;
    if url.scheme() != "https" {
        bail!("{name} must use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{name} must not include credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("{name} must not include a query or fragment");
    }
    Ok(())
}

fn validate_peer_list(name: &str, peers: &[String], allow_private: bool) -> Result<()> {
    if peers.is_empty() || peers.len() > 32 {
        bail!("{name} must contain between 1 and 32 peers");
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for peer in peers {
        validate_peer_endpoint(name, peer, allow_private)?;
        if !seen.insert(peer) {
            bail!("{name} contains a duplicate endpoint");
        }
        if previous.is_some_and(|item| item > peer.as_str()) {
            bail!("{name} must be sorted lexicographically");
        }
        previous = Some(peer);
    }
    Ok(())
}

fn validate_peer_endpoint(name: &str, peer: &str, allow_private: bool) -> Result<()> {
    let url = Url::parse(&format!("tcp://{peer}"))
        .with_context(|| format!("{name} contains invalid endpoint {peer:?}"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none()
        || !matches!(url.path(), "" | "/")
    {
        bail!("{name} endpoint {peer:?} must be host:port without credentials or paths");
    }
    let host = url.host_str().context("peer endpoint has no host")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private && !is_public_ip(ip) {
            bail!("{name} endpoint {peer:?} is not publicly routable");
        }
    } else {
        let lower = host.to_ascii_lowercase();
        if lower.len() > 253
            || !lower.contains('.')
            || lower.ends_with(".local")
            || lower.ends_with(".localhost")
            || lower.ends_with(".invalid")
        {
            bail!("{name} endpoint {peer:?} is not a public DNS name");
        }
    }
    Ok(())
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [first, second, third, _] = ip.octets();
            !(first == 0
                || first == 10
                || first == 127
                || (first == 100 && (64..=127).contains(&second))
                || (first == 169 && second == 254)
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192
                    && (second == 168
                        || (second == 0 && third == 0)
                        || (second == 0 && third == 2)
                        || (second == 88 && third == 99)))
                || (first == 198
                    && ((second == 18 || second == 19) || (second == 51 && third == 100)))
                || (first == 203 && second == 0 && third == 113)
                || first >= 224)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(segments[0] == 0
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xff00) == 0xff00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SourceJoinManifestV1 {
        SourceJoinManifestV1 {
            schema_version: JOIN_MANIFEST_SCHEMA.to_string(),
            experiment_id: "pohw-experiment-0".to_string(),
            network_mode: "join-existing".to_string(),
            trust_model: TRUST_MODEL.to_string(),
            source: SourceBuildV1 {
                repository_url: "https://github.com/ubiubi18/P2poolBTC".to_string(),
                git_commit: "11".repeat(20),
                source_tree_cid: raw_cid(b"source").to_string(),
                source_tree_sha256: "22".repeat(32),
                cargo_lock_sha256: "33".repeat(32),
                cyclonedx_sbom_sha256: "34".repeat(32),
                local_artifact: LocalArtifactV1 {
                    target: "test-target".to_string(),
                    sha256: "44".repeat(32),
                },
            },
            activation: ActivationPinV1 {
                activation_id: "55".repeat(32),
                manifest_sha256: "66".repeat(32),
            },
            launch: LaunchPolicyV1 {
                phase: LaunchPhase::Registration,
                no_value: true,
                mainnet_handoff_armed: false,
            },
            peers: PeerSetV1 {
                gossip: vec!["gossip.example.com:40406".to_string()],
                fork_rpc: vec!["fork-rpc.example.com:40408".to_string()],
                fork_p2p: vec!["fork-p2p.example.com:40409".to_string()],
                explorer_url: Some("https://explorer.example.com".to_string()),
            },
            snapshot: None,
        }
    }

    #[test]
    fn local_source_manifest_round_trips_canonically() {
        let manifest = manifest();
        manifest.validate(false).unwrap();
        let bytes = manifest.canonical_bytes().unwrap();
        assert_eq!(parse_canonical_manifest(&bytes).unwrap(), manifest);
    }

    #[test]
    fn manifest_rejects_noncanonical_json() {
        let pretty = serde_json::to_vec_pretty(&manifest()).unwrap();
        assert!(parse_canonical_manifest(&pretty).is_err());
    }

    #[test]
    fn manifest_rejects_private_peer_by_default() {
        let mut value = manifest();
        value.peers.gossip = vec!["127.0.0.1:40406".to_string()];
        assert!(value.validate(false).is_err());
        assert!(value.validate(true).is_ok());
    }

    #[test]
    fn mining_requires_snapshot_and_never_arms_mainnet() {
        let mut value = manifest();
        value.launch.phase = LaunchPhase::Mining;
        assert!(value.validate(false).is_err());
        value.snapshot = Some(SnapshotPinV1 {
            snapshot_id: "snapshot-1".to_string(),
            proof_root: "77".repeat(32),
            source_height: 1,
            distinct_voter_count: 1,
        });
        assert!(value.validate(false).is_ok());
        value.launch.mainnet_handoff_armed = true;
        assert!(value.validate(false).is_err());
    }

    #[test]
    fn source_cid_is_mandatory_and_canonical() {
        let mut value = manifest();
        value.source.source_tree_cid = "not-a-cid".to_string();
        assert!(value.validate(false).is_err());
    }
}
