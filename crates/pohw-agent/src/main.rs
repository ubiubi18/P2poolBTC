mod bootstrap;
mod config;
mod files;
mod node;
mod wizard;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use governance_core::package_source_tree;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use bootstrap::{
    sha256_hex, ActivationPinV1, LaunchPhase, LaunchPolicyV1, LocalArtifactV1, PeerSetV1,
    SourceBuildV1, SourceJoinManifestV1, AGENT_CONFIG_SCHEMA, JOIN_MANIFEST_SCHEMA, TRUST_MODEL,
};
use config::AgentConfigV1;
use files::{
    atomic_replace_private, create_private_file, ensure_private_dir, install_private_if_absent,
    is_link_like, read_limited_regular,
};
use node::{hash_file, NodeDriver};
use wizard::WizardConfig;

const CANONICAL_EXPERIMENT_ID: &str = "pohw-experiment-0";
const CANONICAL_EXPERIMENT_0_ACTIVATION_ID: &str =
    "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e";
const MAX_ACTIVATION_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "pohw-agent",
    version,
    about = "Source-built P2PoolBTC experiment onboarding"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify a clean source tree, record its CID, and open the local join wizard.
    JoinSource(Box<JoinSourceArgs>),
}

#[derive(Debug, Clone, ValueEnum)]
enum CliLaunchPhase {
    Registration,
    ForkSync,
    Mining,
}

impl From<CliLaunchPhase> for LaunchPhase {
    fn from(value: CliLaunchPhase) -> Self {
        match value {
            CliLaunchPhase::Registration => Self::Registration,
            CliLaunchPhase::ForkSync => Self::ForkSync,
            CliLaunchPhase::Mining => Self::Mining,
        }
    }
}

#[derive(Debug, Args)]
struct JoinSourceArgs {
    #[arg(long)]
    source_root: PathBuf,
    #[arg(long)]
    build_root: PathBuf,
    #[arg(long)]
    p2pool_node: PathBuf,
    #[arg(long)]
    activation_manifest: PathBuf,
    #[arg(long, default_value = CANONICAL_EXPERIMENT_ID)]
    experiment_id: String,
    #[arg(long, default_value = "https://github.com/ubiubi18/P2poolBTC")]
    repository_url: String,
    #[arg(long = "gossip-peer", required = true)]
    gossip_peers: Vec<String>,
    #[arg(long = "fork-rpc-peer", required = true)]
    fork_rpc_peers: Vec<String>,
    #[arg(long = "fork-p2p-peer", required = true)]
    fork_p2p_peers: Vec<String>,
    #[arg(long)]
    explorer_url: Option<String>,
    #[arg(long, value_enum, default_value_t = CliLaunchPhase::Registration)]
    launch_phase: CliLaunchPhase,
    #[arg(long)]
    snapshot_dir: Option<PathBuf>,
    #[arg(long)]
    snapshot_min_voters: Option<usize>,
    #[arg(long)]
    datadir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8765")]
    bind: std::net::SocketAddr,
    #[arg(long, default_value = "127.0.0.1:3333")]
    stratum_bind: std::net::SocketAddr,
    #[arg(long)]
    allow_private_peers: bool,
    /// Required to use any activation manifest other than Experiment 0's tracked manifest.
    #[arg(long)]
    separate_experiment: bool,
    #[arg(long)]
    no_open: bool,
}

#[derive(Debug)]
struct SourceInspection {
    root: PathBuf,
    git_commit: String,
    source_tree_cid: String,
    source_tree_sha256: String,
    cargo_lock_sha256: String,
    cyclonedx_sbom: Vec<u8>,
    cyclonedx_sbom_sha256: String,
    rustc_version: String,
    cargo_version: String,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    resolve: Option<CargoResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    license: Option<String>,
    manifest_path: String,
}

#[derive(Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoResolveNode>,
}

#[derive(Debug, Deserialize)]
struct CargoResolveNode {
    id: String,
    dependencies: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<CycloneDxLicenseChoice>,
    properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Serialize)]
struct CycloneDxLicenseChoice {
    expression: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxProperty {
    name: &'static str,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    reference: String,
    depends_on: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::JoinSource(args) => join_source(*args).await,
    }
}

async fn join_source(args: JoinSourceArgs) -> Result<()> {
    if !args.bind.ip().is_loopback() {
        bail!("--bind must use a loopback address");
    }

    let source = inspect_source_tree(&args.source_root)?;
    let activation_path = std::fs::canonicalize(&args.activation_manifest).with_context(|| {
        format!(
            "resolve activation manifest {}",
            args.activation_manifest.display()
        )
    })?;
    let tracked_activation = source
        .root
        .join("compatibility/experiment-0-activation.json");
    let tracked_activation = std::fs::canonicalize(&tracked_activation).with_context(|| {
        format!(
            "resolve tracked Experiment 0 activation {}",
            tracked_activation.display()
        )
    })?;
    if !args.separate_experiment && activation_path != tracked_activation {
        bail!(
            "joining Experiment 0 requires its tracked activation manifest; use --separate-experiment only to create a different network"
        );
    }

    let activation_bytes = read_limited_regular(&activation_path, MAX_ACTIVATION_MANIFEST_BYTES)?;
    let activation_id = activation_id(&activation_bytes)?;
    if !args.separate_experiment {
        if args.experiment_id != CANONICAL_EXPERIMENT_ID {
            bail!("the default join path must use experiment ID {CANONICAL_EXPERIMENT_ID}");
        }
        if activation_id != CANONICAL_EXPERIMENT_0_ACTIVATION_ID {
            bail!("tracked activation ID is not the canonical Experiment 0 activation");
        }
    } else if args.experiment_id == CANONICAL_EXPERIMENT_ID {
        bail!("a separate experiment must use a distinct --experiment-id");
    }

    let build_root = canonicalize_directory(&args.build_root, "source build root")?;
    if build_root == source.root || build_root.starts_with(&source.root) {
        bail!("--build-root must be outside the source tree");
    }
    let p2pool_node = std::fs::canonicalize(&args.p2pool_node)
        .with_context(|| format!("resolve p2pool-node path {}", args.p2pool_node.display()))?;
    let current_exe = std::fs::canonicalize(std::env::current_exe()?)
        .context("resolve running pohw-agent executable")?;
    if !p2pool_node.starts_with(&build_root) || !current_exe.starts_with(&build_root) {
        bail!(
            "pohw-agent and p2pool-node must both come from the declared fresh build root {}",
            build_root.display()
        );
    }
    validate_regular_file(&current_exe, "pohw-agent executable")?;
    let binary_sha256 = hash_file(&p2pool_node)?;
    let datadir = prepare_datadir(&args.datadir, &source.root)?;
    let driver = NodeDriver::new(
        p2pool_node.clone(),
        binary_sha256.clone(),
        datadir.join("node"),
        args.allow_private_peers,
    )?;
    let launch_phase: LaunchPhase = args.launch_phase.clone().into();
    let (snapshot_dir, snapshot_min_voters, snapshot) = match (
        &launch_phase,
        args.snapshot_dir.as_ref(),
        args.snapshot_min_voters,
    ) {
        (LaunchPhase::Mining, Some(path), Some(min_voters)) if min_voters > 0 => {
            let path = canonicalize_directory(path, "Idena snapshot directory")?;
            if path == source.root || path.starts_with(&source.root) {
                bail!("--snapshot-dir must be outside the source tree");
            }
            let evidence = driver.mining_snapshot_evidence(&path, None, min_voters)?;
            let pin = evidence.snapshot_pin();
            (Some(path), Some(min_voters), Some(pin))
        }
        (LaunchPhase::Mining, _, _) => {
            bail!("mining requires --snapshot-dir and a positive --snapshot-min-voters")
        }
        (_, None, None) => (None, None, None),
        _ => bail!("snapshot options are accepted only with --launch-phase mining"),
    };
    let mut gossip = args.gossip_peers;
    let mut fork_rpc = args.fork_rpc_peers;
    let mut fork_p2p = args.fork_p2p_peers;
    sort_and_deduplicate(&mut gossip);
    sort_and_deduplicate(&mut fork_rpc);
    sort_and_deduplicate(&mut fork_p2p);

    let manifest = SourceJoinManifestV1 {
        schema_version: JOIN_MANIFEST_SCHEMA.to_string(),
        experiment_id: args.experiment_id,
        network_mode: "join-existing".to_string(),
        trust_model: TRUST_MODEL.to_string(),
        source: SourceBuildV1 {
            repository_url: args.repository_url,
            git_commit: source.git_commit.clone(),
            source_tree_cid: source.source_tree_cid.clone(),
            source_tree_sha256: source.source_tree_sha256.clone(),
            cargo_lock_sha256: source.cargo_lock_sha256.clone(),
            cyclonedx_sbom_sha256: source.cyclonedx_sbom_sha256.clone(),
            local_artifact: LocalArtifactV1 {
                target: default_artifact_target(),
                sha256: binary_sha256.clone(),
            },
        },
        activation: ActivationPinV1 {
            activation_id,
            manifest_sha256: sha256_hex(&activation_bytes),
        },
        launch: LaunchPolicyV1 {
            phase: launch_phase,
            no_value: true,
            mainnet_handoff_armed: false,
        },
        peers: PeerSetV1 {
            gossip,
            fork_rpc,
            fork_p2p,
            explorer_url: args.explorer_url,
        },
        snapshot,
    };
    manifest.validate(args.allow_private_peers)?;
    let manifest_bytes = manifest.canonical_bytes()?;
    let manifest = bootstrap::parse_canonical_manifest(&manifest_bytes)?;
    println!("{}", serde_json::to_string_pretty(&manifest.summary()?)?);

    let receipt_dir = datadir.join("build-receipt");
    ensure_private_dir(&receipt_dir)?;
    let join_manifest_path = receipt_dir.join("source-join-manifest.json");
    install_or_update_join_manifest(
        &join_manifest_path,
        &manifest,
        &manifest_bytes,
        args.allow_private_peers,
    )?;
    let installed_activation = receipt_dir.join("fork-activation.json");
    install_private_if_absent(&installed_activation, &activation_bytes)?;
    install_private_if_absent(
        &receipt_dir.join("cyclonedx-sbom.json"),
        &source.cyclonedx_sbom,
    )?;

    let config = AgentConfigV1 {
        schema_version: AGENT_CONFIG_SCHEMA.to_string(),
        created_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trust_model: TRUST_MODEL.to_string(),
        source_root: source.root,
        source_tree_cid: source.source_tree_cid,
        source_tree_sha256: source.source_tree_sha256,
        git_commit: source.git_commit,
        cargo_lock_sha256: source.cargo_lock_sha256,
        cyclonedx_sbom_sha256: source.cyclonedx_sbom_sha256,
        rustc_version: source.rustc_version,
        cargo_version: source.cargo_version,
        join_manifest_sha256: sha256_hex(&manifest_bytes),
        join_manifest_raw_cid: manifest.raw_cid()?.to_string(),
        allow_private_peers: args.allow_private_peers,
        p2pool_node_path: p2pool_node,
        p2pool_node_artifact_target: manifest.source.local_artifact.target.clone(),
        p2pool_node_sha256: driver.binary_sha256().to_string(),
        datadir: datadir.clone(),
        activation_manifest_path: installed_activation.clone(),
        snapshot_dir: snapshot_dir.clone(),
        snapshot_min_voters,
        wizard_bind_addr: args.bind.to_string(),
        stratum_bind_addr: args.stratum_bind.to_string(),
    };
    install_or_verify_config(&datadir.join("agent-config.json"), config)?;

    wizard::run(WizardConfig {
        descriptor: manifest,
        driver,
        activation_manifest_path: installed_activation,
        snapshot_dir,
        snapshot_min_voters,
        bind_addr: args.bind,
        stratum_bind_addr: args.stratum_bind,
        open_browser: !args.no_open,
    })
    .await
}

fn inspect_source_tree(root: &Path) -> Result<SourceInspection> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("resolve source root {}", root.display()))?;
    for required in ["Cargo.toml", "Cargo.lock"] {
        let path = root.join(required);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect required source file {}", path.display()))?;
        if is_link_like(&metadata) || !metadata.is_file() {
            bail!(
                "required source file {} must be a regular non-symlink file",
                path.display()
            );
        }
    }

    let status = command_output(
        ProcessCommand::new("git").arg("-C").arg(&root).args([
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ]),
        "inspect source worktree",
    )?;
    if !status.trim().is_empty() {
        bail!(
            "source worktree is dirty; commit or remove every change before community onboarding"
        );
    }
    let ignored = command_output_bytes(
        ProcessCommand::new("git").arg("-C").arg(&root).args([
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        ]),
        "inspect ignored source files",
    )?;
    if ignored.iter().any(|byte| *byte != 0) {
        bail!(
            "source tree contains ignored files or directories; use a fresh checkout so uncommitted build inputs cannot affect the local artifact"
        );
    }
    let git_commit = command_output(
        ProcessCommand::new("git").arg("-C").arg(&root).args([
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]),
        "resolve source commit",
    )?;
    let git_commit = git_commit.trim().to_ascii_lowercase();
    if git_commit.len() != 40 || !git_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("git returned an invalid source commit");
    }

    let package = package_source_tree(&root, "P2poolBTC")
        .context("package deterministic local source tree")?;
    let tracked = command_output_bytes(
        ProcessCommand::new("git")
            .arg("-C")
            .arg(&root)
            .args(["ls-files", "--cached", "-z"]),
        "enumerate tracked source files",
    )?;
    let tracked = tracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| std::str::from_utf8(path).context("tracked source path is not UTF-8"))
        .collect::<Result<BTreeSet<_>>>()?;
    let packaged = package
        .manifest
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let nontracked = packaged.difference(&tracked).copied().collect::<Vec<_>>();
    let omitted = tracked.difference(&packaged).copied().collect::<Vec<_>>();
    if !nontracked.is_empty() || !omitted.is_empty() {
        bail!(
            "source CID closure mismatch: {} packaged paths are not tracked and {} tracked paths are omitted; remove ignored inputs and tracked files under excluded output paths",
            nontracked.len(),
            omitted.len()
        );
    }
    let cargo_lock_sha256 = hash_file(&root.join("Cargo.lock"))?;
    let metadata_bytes = command_output_bytes(
        ProcessCommand::new("cargo")
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(root.join("Cargo.toml")),
        "read locked Cargo dependency metadata",
    )?;
    if metadata_bytes.len() > 32 * 1024 * 1024 {
        bail!("Cargo dependency metadata exceeds 32 MiB");
    }
    let metadata: CargoMetadata =
        serde_json::from_slice(&metadata_bytes).context("parse Cargo dependency metadata")?;
    let cyclonedx_sbom = build_cyclonedx_sbom(&root, &package.root_cid.to_string(), metadata)?;
    let cyclonedx_sbom_sha256 = sha256_hex(&cyclonedx_sbom);
    Ok(SourceInspection {
        root,
        git_commit,
        source_tree_cid: package.root_cid.to_string(),
        source_tree_sha256: package.source_tree_sha256,
        cargo_lock_sha256,
        cyclonedx_sbom,
        cyclonedx_sbom_sha256,
        rustc_version: command_output(
            ProcessCommand::new("rustc").arg("--version"),
            "read rustc version",
        )?
        .trim()
        .to_string(),
        cargo_version: command_output(
            ProcessCommand::new("cargo").arg("--version"),
            "read Cargo version",
        )?
        .trim()
        .to_string(),
    })
}

fn build_cyclonedx_sbom(
    source_root: &Path,
    source_tree_cid: &str,
    metadata: CargoMetadata,
) -> Result<Vec<u8>> {
    let workspace_members = metadata
        .workspace_members
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut id_to_ref = std::collections::BTreeMap::new();
    let mut components = Vec::with_capacity(metadata.packages.len());
    for package in metadata.packages {
        let source_identity = if let Some(source) = &package.source {
            format!("{source}|{}|{}", package.name, package.version)
        } else {
            let manifest_path = Path::new(&package.manifest_path);
            let relative = manifest_path.strip_prefix(source_root).with_context(|| {
                format!(
                    "path dependency {} is outside the verified source tree",
                    package.name
                )
            })?;
            let relative = relative
                .to_str()
                .context("workspace manifest path is not UTF-8")?
                .replace('\\', "/");
            format!("workspace:{relative}|{}|{}", package.name, package.version)
        };
        let bom_ref = format!("urn:pohw:cargo:{}", sha256_hex(source_identity.as_bytes()));
        if id_to_ref
            .insert(package.id.clone(), bom_ref.clone())
            .is_some()
        {
            bail!("Cargo metadata contains a duplicate package ID");
        }
        let licenses = package
            .license
            .filter(|license| !license.trim().is_empty())
            .map(|expression| vec![CycloneDxLicenseChoice { expression }])
            .unwrap_or_default();
        components.push(CycloneDxComponent {
            component_type: if workspace_members.contains(&package.id) {
                "application"
            } else {
                "library"
            },
            bom_ref,
            name: package.name,
            version: package.version,
            licenses,
            properties: vec![CycloneDxProperty {
                name: "pohw:cargo-source-kind",
                value: if package.source.is_some() {
                    "external-locked".to_string()
                } else {
                    "workspace".to_string()
                },
            }],
        });
    }
    components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));

    let mut dependencies = Vec::new();
    let resolve = metadata
        .resolve
        .context("Cargo metadata omits the dependency graph")?;
    for node in resolve.nodes {
        let reference = id_to_ref
            .get(&node.id)
            .with_context(|| format!("Cargo dependency node has no package for {}", node.id))?
            .clone();
        let mut depends_on = node
            .dependencies
            .iter()
            .map(|id| {
                id_to_ref
                    .get(id)
                    .cloned()
                    .with_context(|| format!("Cargo dependency edge has no package for {id}"))
            })
            .collect::<Result<Vec<_>>>()?;
        depends_on.sort();
        depends_on.dedup();
        dependencies.push(CycloneDxDependency {
            reference,
            depends_on,
        });
    }
    dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));

    let root_ref = format!("urn:pohw:source:{source_tree_cid}");
    let mut workspace_refs = workspace_members
        .iter()
        .map(|id| {
            id_to_ref
                .get(id)
                .cloned()
                .with_context(|| format!("workspace member has no package for {id}"))
        })
        .collect::<Result<Vec<_>>>()?;
    workspace_refs.sort();
    dependencies.push(CycloneDxDependency {
        reference: root_ref.clone(),
        depends_on: workspace_refs,
    });
    dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));

    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": format!("urn:pohw:source:{source_tree_cid}"),
                "name": "P2poolBTC",
                "version": source_tree_cid,
                "properties": [
                    {"name": "pohw:source-tree-cid", "value": source_tree_cid}
                ]
            }
        },
        "components": components,
        "dependencies": dependencies
    });
    let mut bytes =
        serde_json::to_vec(&document).context("serialize deterministic CycloneDX SBOM")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonicalize_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if is_link_like(&metadata) || !metadata.is_dir() {
        bail!("{label} must be a non-symlink directory");
    }
    std::fs::canonicalize(path).with_context(|| format!("resolve {label} {}", path.display()))
}

fn validate_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if is_link_like(&metadata) || !metadata.is_file() {
        bail!("{label} must be a regular non-symlink file");
    }
    Ok(())
}

fn prepare_datadir(path: &Path, source_root: &Path) -> Result<PathBuf> {
    let path = absolutize(path)?;
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        bail!("--datadir must not contain '.' or '..' components");
    }
    if path == source_root || path.starts_with(source_root) {
        bail!("--datadir must be outside the source tree so it cannot change the source CID");
    }
    ensure_private_dir(&path)?;
    let canonical = std::fs::canonicalize(&path)
        .with_context(|| format!("resolve agent datadir {}", path.display()))?;
    if canonical == source_root || canonical.starts_with(source_root) {
        bail!("--datadir resolves inside the source tree");
    }
    Ok(canonical)
}

fn activation_id(bytes: &[u8]) -> Result<String> {
    let value: Value =
        serde_json::from_slice(bytes).context("activation manifest is invalid JSON")?;
    let id = value
        .get("activation_id")
        .and_then(Value::as_str)
        .context("activation manifest omits activation_id")?
        .to_ascii_lowercase();
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("activation manifest contains an invalid activation_id");
    }
    Ok(id)
}

fn install_or_verify_config(path: &Path, mut expected: AgentConfigV1) -> Result<()> {
    if path.exists() {
        let bytes = read_limited_regular(path, 128 * 1024)?;
        let existing: AgentConfigV1 =
            serde_json::from_slice(&bytes).context("parse existing agent config")?;
        existing.validate_schema()?;
        expected.created_at_utc = existing.created_at_utc.clone();
        let mut comparable = existing.clone();
        comparable.join_manifest_sha256 = expected.join_manifest_sha256.clone();
        comparable.join_manifest_raw_cid = expected.join_manifest_raw_cid.clone();
        comparable.allow_private_peers = expected.allow_private_peers;
        comparable.p2pool_node_path = expected.p2pool_node_path.clone();
        comparable.snapshot_dir = expected.snapshot_dir.clone();
        comparable.snapshot_min_voters = expected.snapshot_min_voters;
        comparable.wizard_bind_addr = expected.wizard_bind_addr.clone();
        comparable.stratum_bind_addr = expected.stratum_bind_addr.clone();
        if comparable != expected {
            bail!(
                "existing agent config {} belongs to a different source build or activation",
                path.display()
            );
        }
        let mut updated = serde_json::to_vec_pretty(&expected)?;
        updated.push(b'\n');
        return atomic_replace_private(path, &updated);
    }
    let mut bytes = serde_json::to_vec_pretty(&expected)?;
    bytes.push(b'\n');
    create_private_file(path, &bytes)
}

fn install_or_update_join_manifest(
    path: &Path,
    expected: &SourceJoinManifestV1,
    bytes: &[u8],
    allow_private_peers: bool,
) -> Result<()> {
    if !path.exists() {
        return install_private_if_absent(path, bytes);
    }
    let existing_bytes = read_limited_regular(path, 256 * 1024)?;
    let existing = bootstrap::parse_canonical_manifest(&existing_bytes)?;
    existing.validate(allow_private_peers)?;
    if existing.schema_version != expected.schema_version
        || existing.experiment_id != expected.experiment_id
        || existing.network_mode != expected.network_mode
        || existing.trust_model != expected.trust_model
        || existing.source != expected.source
        || existing.activation != expected.activation
    {
        bail!(
            "existing source-join manifest {} belongs to a different source build or activation",
            path.display()
        );
    }
    atomic_replace_private(path, bytes)
}

fn command_output(command: &mut ProcessCommand, description: &str) -> Result<String> {
    let output = command_output_bytes(command, description)?;
    String::from_utf8(output).with_context(|| format!("{description} returned non-UTF-8"))
}

fn command_output_bytes(command: &mut ProcessCommand, description: &str) -> Result<Vec<u8>> {
    let output = command
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| description.to_string())?;
    if !output.status.success() {
        bail!("{description} failed");
    }
    Ok(output.stdout)
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn sort_and_deduplicate(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn default_artifact_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(root: &Path, args: &[&str]) {
        let status = ProcessCommand::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }

    fn create_source_fixture(root: &Path) {
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join(".gitignore"), "ignored.txt\ntarget/\n").unwrap();
        run_git(root, &["init", "-q"]);
        run_git(root, &["config", "user.email", "fixture@example.invalid"]);
        run_git(root, &["config", "user.name", "Fixture"]);
        run_git(root, &["add", "."]);
        run_git(root, &["commit", "-qm", "fixture"]);
    }

    #[test]
    fn activation_id_is_strict() {
        let id = "aa".repeat(32);
        let bytes = format!(r#"{{"activation_id":"{id}"}}"#);
        assert_eq!(activation_id(bytes.as_bytes()).unwrap(), id);
        assert!(activation_id(b"{}").is_err());
        assert!(activation_id(br#"{"activation_id":"no"}"#).is_err());
    }

    #[test]
    fn artifact_target_is_platform_specific() {
        let target = default_artifact_target();
        assert!(target.contains('-'));
        assert!(!target.contains(char::is_whitespace));
    }

    #[test]
    fn source_inspection_rejects_ignored_build_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        create_source_fixture(root);

        let inspection = inspect_source_tree(root).unwrap();
        let sbom = String::from_utf8(inspection.cyclonedx_sbom).unwrap();
        assert!(sbom.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(!sbom.contains(root.to_string_lossy().as_ref()));
        assert_eq!(inspection.cyclonedx_sbom_sha256.len(), 64);
        std::fs::write(root.join("ignored.txt"), "local ignored data\n").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(root.join("target/hidden-build-input"), "local input\n").unwrap();
        let error = inspect_source_tree(root).unwrap_err();
        assert!(error
            .to_string()
            .contains("source tree contains ignored files"));
    }

    #[test]
    fn source_inspection_rejects_tracked_files_omitted_from_the_cid() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        create_source_fixture(root);
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::write(
            root.join("target/tracked-build-input.txt"),
            "must be hashed\n",
        )
        .unwrap();
        run_git(root, &["add", "-f", "target/tracked-build-input.txt"]);
        run_git(root, &["commit", "-qm", "tracked build input"]);

        let error = inspect_source_tree(root).unwrap_err();
        assert!(error.to_string().contains("tracked paths are omitted"));
    }

    #[cfg(unix)]
    #[test]
    fn datadir_rejects_a_symlinked_ancestor_into_the_source_tree() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let source_state = source.join("state");
        std::fs::create_dir_all(&source_state).unwrap();
        let source = std::fs::canonicalize(source).unwrap();
        let link = temp.path().join("external-looking-state");
        std::os::unix::fs::symlink(&source_state, &link).unwrap();

        let error = prepare_datadir(&link.join("agent"), &source).unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }
}
