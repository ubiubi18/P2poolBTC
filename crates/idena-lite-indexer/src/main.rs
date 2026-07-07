use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use idena_lite_indexer::rpc::IdenaRpcClient;
use idena_lite_indexer::snapshot_builder::{build_current_snapshot, SnapshotBuildOptions};
use pohw_core::replay::{RewardEvent, RewardReplay};
use pohw_core::FORMULA_VERSION;
use std::path::{Path, PathBuf};

const MAX_REWARD_EVENTS_FILE_BYTES: u64 = 512 * 1024 * 1024;

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
    }
    Ok(())
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
