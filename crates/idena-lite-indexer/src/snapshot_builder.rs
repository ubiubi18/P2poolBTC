use crate::rpc::{BlockResponse, IdenaRpcClient, IdentityResponse};
use anyhow::{bail, Context, Result};
use chrono::{NaiveDate, Utc};
use pohw_core::replay::RewardReplay;
use pohw_core::snapshot::{Snapshot, SnapshotLeaf};
use pohw_core::FORMULA_VERSION;

#[derive(Debug, Clone)]
pub struct SnapshotBuildOptions {
    pub snapshot_day: NaiveDate,
    pub formula_version: u16,
    pub require_synced: bool,
}

impl Default for SnapshotBuildOptions {
    fn default() -> Self {
        Self {
            snapshot_day: Utc::now().date_naive(),
            formula_version: FORMULA_VERSION,
            require_synced: true,
        }
    }
}

pub async fn build_current_snapshot(
    client: &IdenaRpcClient,
    replay: &RewardReplay,
    options: SnapshotBuildOptions,
) -> Result<Snapshot> {
    let syncing = client
        .syncing()
        .await
        .context("failed to read Idena sync status")?;
    if options.require_synced && syncing.syncing {
        bail!(
            "Idena node is still syncing at block {} of {}; refusing consensus snapshot",
            syncing.current_block,
            syncing.highest_block
        );
    }

    let block = client
        .block_at(syncing.current_block)
        .await
        .context("failed to read current Idena block")?
        .with_context(|| format!("Idena block {} is unavailable", syncing.current_block))?;
    let identities = client
        .identities()
        .await
        .context("failed to read identities")?;

    Ok(snapshot_from_rpc(
        options.snapshot_day,
        options.formula_version,
        &block,
        identities,
        replay,
    ))
}

pub fn snapshot_from_rpc(
    snapshot_day: NaiveDate,
    formula_version: u16,
    block: &BlockResponse,
    identities: Vec<IdentityResponse>,
    replay: &RewardReplay,
) -> Snapshot {
    let leaves = identities
        .into_iter()
        .map(|identity| {
            let score = replay.score_for(&identity.address);
            SnapshotLeaf {
                idena_address: identity.address,
                status: identity.state,
                pubkey: identity.pubkey,
                validation_reward_score: score.validation_reward_score,
                proposer_reward_score: score.proposer_reward_score,
                committee_reward_score: score.committee_reward_score,
                ignored_invitation_score: score.ignored_invitation_score,
                identity_root: block.identity_root.clone(),
                formula_version,
            }
        })
        .collect();

    Snapshot::build(
        snapshot_day,
        block.height,
        block.hash.clone(),
        block.identity_root.clone(),
        formula_version,
        leaves,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use pohw_core::replay::{RewardEvent, RewardKind};
    use pohw_core::snapshot::IdenaStatus;

    #[test]
    fn snapshot_builder_applies_replayed_scores() {
        let block = BlockResponse {
            coinbase: "0xcoinbase".to_string(),
            hash: "0xhash".to_string(),
            parent_hash: "0xparent".to_string(),
            height: 42,
            timestamp: 0,
            root: "0xroot".to_string(),
            identity_root: "0xidentity".to_string(),
            transactions: None,
            is_empty: false,
        };
        let identities = vec![IdentityResponse {
            address: "0xABC".to_string(),
            state: IdenaStatus::Human,
            pubkey: "PUB".to_string(),
            delegatee: None,
            is_pool: false,
        }];
        let mut replay = RewardReplay::default();
        replay
            .apply(RewardEvent {
                idena_address: "0xabc".to_string(),
                kind: RewardKind::Validation,
                amount_atoms: 123,
                source_height: 1,
                source_hash: "0x1".to_string(),
            })
            .unwrap();
        replay
            .apply(RewardEvent {
                idena_address: "0xabc".to_string(),
                kind: RewardKind::Invitation,
                amount_atoms: 456,
                source_height: 2,
                source_hash: "0x2".to_string(),
            })
            .unwrap();

        let snapshot = snapshot_from_rpc(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            FORMULA_VERSION,
            &block,
            identities,
            &replay,
        );

        assert_eq!(snapshot.leaves[0].idena_address, "0xabc");
        assert_eq!(snapshot.leaves[0].validation_reward_score, 123);
        assert_eq!(snapshot.leaves[0].ignored_invitation_score, 456);
        assert_eq!(snapshot.idena_height, 42);
    }
}
