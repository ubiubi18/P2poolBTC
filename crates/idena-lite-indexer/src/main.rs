use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use idena_lite_indexer::consensus_identity_snapshot::{
    capture_consensus_identity_snapshot, ConsensusIdentityCaptureOptions,
};
use idena_lite_indexer::rpc::IdenaRpcClient;
use idena_lite_indexer::snapshot_builder::{build_current_snapshot, SnapshotBuildOptions};
use pohw_core::consensus_identity::{
    ConsensusIdentitySnapshotBundleV1, ConsensusIdentitySnapshotInputV1,
};
use pohw_core::replay::{RewardEvent, RewardReplay};
use pohw_core::sharechain::MinerRegistration;
use pohw_core::FORMULA_VERSION;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_REWARD_EVENTS_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REGISTRATIONS_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONSENSUS_SNAPSHOT_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CONSENSUS_SNAPSHOT_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "idena-lite-indexer")]
#[command(about = "Build locally verifiable Idena PoHW snapshots from a local idena-go RPC")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    SnapshotNow {
        #[arg(long, default_value = "http://127.0.0.1:9009", env = "IDENA_RPC_URL")]
        rpc_url: String,
        #[arg(long, default_value_t = false)]
        allow_remote_rpc: bool,
        #[arg(long, env = "IDENA_API_KEY_FILE")]
        api_key_file: PathBuf,
        #[arg(long, default_value_t = FORMULA_VERSION)]
        formula_version: u16,
        #[arg(long, default_value_t = false)]
        allow_syncing: bool,
        #[arg(long)]
        reward_events_file: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        allow_empty_reward_replay: bool,
    },
    /// Capture a stable public identity/registry view and wait for an exact confirmation chain.
    ConsensusIdentityCapture {
        #[arg(long, default_value = "http://127.0.0.1:9009", env = "IDENA_RPC_URL")]
        rpc_url: String,
        #[arg(long, default_value_t = false)]
        allow_remote_rpc: bool,
        #[arg(long, env = "IDENA_API_KEY_FILE")]
        api_key_file: PathBuf,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        registry_contract_address: String,
        #[arg(long)]
        registrations_file: PathBuf,
        #[arg(long, default_value_t = 6)]
        finality_confirmations: u16,
        #[arg(long, default_value_t = 15)]
        poll_seconds: u64,
        #[arg(long, default_value_t = 1_800)]
        max_wait_seconds: u64,
    },
    /// Verify a captured input and derive the canonical authorization root and proofs offline.
    ConsensusIdentityBuild {
        #[arg(long)]
        input_file: PathBuf,
    },
    /// Rebuild and verify an externally supplied inactive snapshot bundle offline.
    ConsensusIdentityVerify {
        #[arg(long)]
        input_file: PathBuf,
        #[arg(long)]
        bundle_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SnapshotNow {
            rpc_url,
            allow_remote_rpc,
            api_key_file,
            formula_version,
            allow_syncing,
            reward_events_file,
            allow_empty_reward_replay,
        } => {
            let client = IdenaRpcClient::from_api_key_file_with_remote_policy(
                rpc_url,
                api_key_file,
                allow_remote_rpc,
            )?;
            let replay = load_reward_replay(reward_events_file, allow_empty_reward_replay)?;
            let snapshot = build_current_snapshot(
                &client,
                &replay,
                SnapshotBuildOptions {
                    formula_version,
                    require_synced: !allow_syncing,
                    ..SnapshotBuildOptions::default()
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::ConsensusIdentityCapture {
            rpc_url,
            allow_remote_rpc,
            api_key_file,
            experiment_id,
            registry_contract_address,
            registrations_file,
            finality_confirmations,
            poll_seconds,
            max_wait_seconds,
        } => {
            let client = IdenaRpcClient::from_api_key_file_with_remote_policy(
                rpc_url,
                api_key_file,
                allow_remote_rpc,
            )?;
            let registrations: Vec<MinerRegistration> = read_strict_json_file(
                &registrations_file,
                "public miner registrations file",
                MAX_REGISTRATIONS_FILE_BYTES,
            )?;
            let input = capture_consensus_identity_snapshot(
                &client,
                registrations,
                ConsensusIdentityCaptureOptions {
                    experiment_id,
                    registry_contract_address,
                    finality_confirmations,
                    poll_interval: Duration::from_secs(poll_seconds),
                    max_wait: Duration::from_secs(max_wait_seconds),
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&input)?);
        }
        Command::ConsensusIdentityBuild { input_file } => {
            let input: ConsensusIdentitySnapshotInputV1 = read_strict_json_file(
                &input_file,
                "consensus identity snapshot input",
                MAX_CONSENSUS_SNAPSHOT_INPUT_BYTES,
            )?;
            let bundle = input.build_bundle()?;
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Command::ConsensusIdentityVerify {
            input_file,
            bundle_file,
        } => {
            let input: ConsensusIdentitySnapshotInputV1 = read_strict_json_file(
                &input_file,
                "consensus identity snapshot input",
                MAX_CONSENSUS_SNAPSHOT_INPUT_BYTES,
            )?;
            let bundle: ConsensusIdentitySnapshotBundleV1 = read_strict_json_file(
                &bundle_file,
                "consensus identity snapshot bundle",
                MAX_CONSENSUS_SNAPSHOT_BUNDLE_BYTES,
            )?;
            bundle.validate_against_input(&input)?;
            let report = serde_json::json!({
                "schema_version": "pohw-consensus-identity-snapshot-verification/v1",
                "status": "verified-inactive-input",
                "experiment_id": bundle.experiment_id,
                "registry_contract_address": bundle.registry_contract_address,
                "source_input_hash": bundle.source_input_hash,
                "idena_finalized_height": bundle.idena_finalized_height,
                "idena_finalized_timestamp": bundle.idena_finalized_timestamp,
                "idena_finalized_block_hash": bundle.idena_finalized_block_hash,
                "idena_identity_root": bundle.idena_identity_root,
                "idena_finality_height": bundle.idena_finality_height,
                "idena_finality_block_hash": bundle.idena_finality_block_hash,
                "finality_confirmations": bundle.finality_confirmations,
                "idena_next_validation_timestamp": bundle.idena_next_validation_timestamp,
                "authorization_root": bundle.authorization_root,
                "authorized_identity_count": bundle.authorized_identity_count,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn read_strict_json_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<T> {
    let value = read_bounded_regular_text_file(path, label, max_bytes)?;
    idena_lite_indexer::strict_json::from_str(&value)
        .with_context(|| format!("failed to parse {label} {}", path.display()))
}

fn load_reward_replay(
    reward_events_file: Option<PathBuf>,
    allow_empty_reward_replay: bool,
) -> Result<RewardReplay> {
    let Some(path) = reward_events_file else {
        if allow_empty_reward_replay {
            return Ok(RewardReplay::default());
        }
        bail!(
            "refusing to build a consensus snapshot without --reward-events-file; use --allow-empty-reward-replay only for identity-only development snapshots"
        );
    };

    let json =
        read_bounded_regular_text_file(&path, "reward events file", MAX_REWARD_EVENTS_FILE_BYTES)?;
    let events: Vec<RewardEvent> = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse reward events file {}", path.display()))?;
    let mut replay = RewardReplay::default();
    for event in events {
        replay.apply(event)?;
    }
    Ok(replay)
}

fn read_bounded_regular_text_file(path: &Path, label: &str, max_bytes: u64) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} {} must not be a symlink", path.display());
    }
    if !metadata.file_type().is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{label} {} is {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            max_bytes
        );
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pohw_core::replay::RewardKind;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pohw-idena-lite-indexer-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn reward_replay_loader_applies_events() {
        let dir = test_dir("reward-replay");
        let path = dir.join("events.json");
        let events = vec![
            RewardEvent {
                idena_address: "0xAbc".to_string(),
                kind: RewardKind::Validation,
                amount_atoms: 7,
                source_height: 42,
                source_hash: "aa".repeat(32),
            },
            RewardEvent {
                idena_address: "0xabc".to_string(),
                kind: RewardKind::Invitation,
                amount_atoms: 100,
                source_height: 43,
                source_hash: "bb".repeat(32),
            },
        ];
        std::fs::write(&path, serde_json::to_string(&events).unwrap()).unwrap();

        let replay = load_reward_replay(Some(path), false).unwrap();

        let score = replay.score_for("0xabc");
        assert_eq!(score.validation_reward_score, 7);
        assert_eq!(score.ignored_invitation_score, 100);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reward_replay_loader_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("reward-replay-symlink");
        let target = dir.join("target.json");
        let link = dir.join("events.json");
        std::fs::write(&target, "[]\n").unwrap();
        symlink(&target, &link).unwrap();

        let err = load_reward_replay(Some(link), false).unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reward_replay_loader_rejects_large_file() {
        let dir = test_dir("reward-replay-large");
        let path = dir.join("events.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_REWARD_EVENTS_FILE_BYTES + 1)
            .unwrap();

        let err = load_reward_replay(Some(path), false).unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
