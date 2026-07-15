use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::bootstrap::AGENT_CONFIG_SCHEMA;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigV1 {
    pub schema_version: String,
    pub created_at_utc: String,
    pub trust_model: String,
    pub source_root: PathBuf,
    pub source_tree_cid: String,
    pub source_tree_sha256: String,
    pub git_commit: String,
    pub cargo_lock_sha256: String,
    pub cyclonedx_sbom_sha256: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub join_manifest_sha256: String,
    pub join_manifest_raw_cid: String,
    pub allow_private_peers: bool,
    pub p2pool_node_path: PathBuf,
    pub p2pool_node_artifact_target: String,
    pub p2pool_node_sha256: String,
    pub datadir: PathBuf,
    pub activation_manifest_path: PathBuf,
    #[serde(default)]
    pub snapshot_dir: Option<PathBuf>,
    #[serde(default)]
    pub snapshot_min_voters: Option<usize>,
    pub wizard_bind_addr: String,
    pub stratum_bind_addr: String,
}

impl AgentConfigV1 {
    pub fn validate_schema(&self) -> anyhow::Result<()> {
        if self.schema_version != AGENT_CONFIG_SCHEMA {
            anyhow::bail!(
                "unsupported agent config schema {}; expected {AGENT_CONFIG_SCHEMA}",
                self.schema_version
            );
        }
        Ok(())
    }
}
