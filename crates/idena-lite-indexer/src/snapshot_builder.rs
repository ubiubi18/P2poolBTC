use crate::rpc::{BlockResponse, IdenaRpcClient, IdentityResponse};
use anyhow::{bail, Context, Result};
use chrono::{NaiveDate, Utc};
use pohw_core::replay::{RewardReplay, RewardScore};
use pohw_core::snapshot::{IdenaStatus, Snapshot, SnapshotLeaf};
use pohw_core::FORMULA_VERSION;
use std::collections::BTreeMap;

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
    let mut effective_leaves: BTreeMap<String, EffectiveLeaf> = BTreeMap::new();
    for identity in identities {
        let effective_address = effective_idena_address(&identity);
        let score = replay.score_for(&identity.address);
        let entry = effective_leaves
            .entry(effective_address)
            .or_insert_with(|| EffectiveLeaf {
                status: identity.state.clone(),
                pubkey: String::new(),
                score: RewardScore::default(),
            });
        entry.status = stronger_status(&entry.status, &identity.state);
        if entry.pubkey.is_empty() && !identity.pubkey.is_empty() {
            entry.pubkey = identity.pubkey;
        }
        add_score(&mut entry.score, score);
    }

    let leaves = effective_leaves
        .into_iter()
        .map(|(idena_address, leaf)| SnapshotLeaf {
            idena_address,
            status: leaf.status,
            pubkey: leaf.pubkey,
            validation_reward_score: leaf.score.validation_reward_score,
            proposer_reward_score: leaf.score.proposer_reward_score,
            committee_reward_score: leaf.score.committee_reward_score,
            ignored_invitation_score: leaf.score.ignored_invitation_score,
            identity_root: block.identity_root.clone(),
            formula_version,
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

#[derive(Debug, Clone)]
struct EffectiveLeaf {
    status: IdenaStatus,
    pubkey: String,
    score: RewardScore,
}

fn effective_idena_address(identity: &IdentityResponse) -> String {
    if identity.state.is_block_eligible() {
        if let Some(delegatee) = identity
            .delegatee
            .as_deref()
            .map(str::trim)
            .filter(|delegatee| !delegatee.is_empty())
        {
            return delegatee.to_ascii_lowercase();
        }
    }
    identity.address.to_ascii_lowercase()
}

fn stronger_status(left: &IdenaStatus, right: &IdenaStatus) -> IdenaStatus {
    if status_rank(right) > status_rank(left) {
        right.clone()
    } else {
        left.clone()
    }
}

fn status_rank(status: &IdenaStatus) -> u8 {
    match status {
        IdenaStatus::Human => 3,
        IdenaStatus::Verified => 2,
        IdenaStatus::Newbie => 1,
        _ => 0,
    }
}

fn add_score(total: &mut RewardScore, delta: RewardScore) {
    total.validation_reward_score = total
        .validation_reward_score
        .checked_add(delta.validation_reward_score)
        .expect("validation reward score overflow while merging delegated identities");
    total.proposer_reward_score = total
        .proposer_reward_score
        .checked_add(delta.proposer_reward_score)
        .expect("proposer reward score overflow while merging delegated identities");
    total.committee_reward_score = total
        .committee_reward_score
        .checked_add(delta.committee_reward_score)
        .expect("committee reward score overflow while merging delegated identities");
    total.ignored_invitation_score = total
        .ignored_invitation_score
        .checked_add(delta.ignored_invitation_score)
        .expect("invitation reward score overflow while merging delegated identities");
    total.ignored_other_score = total
        .ignored_other_score
        .checked_add(delta.ignored_other_score)
        .expect("other reward score overflow while merging delegated identities");
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

    #[test]
    fn snapshot_builder_rolls_eligible_delegated_identity_to_pool_address() {
        let block = BlockResponse {
            coinbase: "0xpool".to_string(),
            hash: "0xhash".to_string(),
            parent_hash: "0xparent".to_string(),
            height: 42,
            timestamp: 0,
            root: "0xroot".to_string(),
            identity_root: "0xidentity".to_string(),
            transactions: None,
            is_empty: false,
        };
        let pool = "0x1111111111111111111111111111111111111111";
        let delegator = "0x2222222222222222222222222222222222222222";
        let identities = vec![
            IdentityResponse {
                address: pool.to_string(),
                state: IdenaStatus::Undefined,
                pubkey: "pool-pubkey".to_string(),
                delegatee: None,
                is_pool: true,
            },
            IdentityResponse {
                address: delegator.to_string(),
                state: IdenaStatus::Newbie,
                pubkey: "delegator-pubkey".to_string(),
                delegatee: Some(pool.to_string()),
                is_pool: false,
            },
        ];
        let mut replay = RewardReplay::default();
        replay
            .apply(RewardEvent {
                idena_address: delegator.to_string(),
                kind: RewardKind::Validation,
                amount_atoms: 123,
                source_height: 1,
                source_hash: "0x1".to_string(),
            })
            .unwrap();

        let snapshot = snapshot_from_rpc(
            NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            FORMULA_VERSION,
            &block,
            identities,
            &replay,
        );

        assert_eq!(snapshot.leaves.len(), 1);
        assert_eq!(snapshot.leaves[0].idena_address, pool);
        assert_eq!(snapshot.leaves[0].status, IdenaStatus::Newbie);
        assert!(snapshot.leaves[0].is_block_eligible());
        assert_eq!(snapshot.leaves[0].validation_reward_score, 123);
    }
}
