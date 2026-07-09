use crate::rpc::{BlockResponse, IdenaRpcClient, IdentityResponse, SyncingResponse};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{NaiveDate, Utc};
use pohw_core::replay::{RewardReplay, RewardScore};
use pohw_core::snapshot::{IdenaStatus, Snapshot, SnapshotLeaf};
use pohw_core::FORMULA_VERSION;
use std::collections::BTreeMap;

const SNAPSHOT_HEAD_STABILITY_ATTEMPTS: usize = 5;

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
    build_current_snapshot_with_rpc(client, replay, options).await
}

#[async_trait]
trait SnapshotRpc {
    async fn syncing(&self) -> Result<SyncingResponse>;
    async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>>;
    async fn identities(&self) -> Result<Vec<IdentityResponse>>;
}

#[async_trait]
impl SnapshotRpc for IdenaRpcClient {
    async fn syncing(&self) -> Result<SyncingResponse> {
        self.syncing().await
    }

    async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>> {
        self.block_at(height).await
    }

    async fn identities(&self) -> Result<Vec<IdentityResponse>> {
        self.identities().await
    }
}

async fn build_current_snapshot_with_rpc<R: SnapshotRpc + Sync>(
    client: &R,
    replay: &RewardReplay,
    options: SnapshotBuildOptions,
) -> Result<Snapshot> {
    for attempt in 1..=SNAPSHOT_HEAD_STABILITY_ATTEMPTS {
        let before_syncing = client
            .syncing()
            .await
            .context("failed to read Idena sync status before identity snapshot")?;
        ensure_snapshot_sync_ready(&before_syncing, options.require_synced)?;
        let before_block = read_snapshot_block(client, before_syncing.current_block).await?;
        let identities = client
            .identities()
            .await
            .context("failed to read identities")?;
        let after_syncing = client
            .syncing()
            .await
            .context("failed to read Idena sync status after identity snapshot")?;
        ensure_snapshot_sync_ready(&after_syncing, options.require_synced)?;

        if before_syncing.current_block != after_syncing.current_block {
            if attempt < SNAPSHOT_HEAD_STABILITY_ATTEMPTS {
                continue;
            }
            break;
        }

        let after_block = read_snapshot_block(client, after_syncing.current_block).await?;
        if same_snapshot_head(&before_block, &after_block) {
            return Ok(snapshot_from_rpc(
                options.snapshot_day,
                options.formula_version,
                &before_block,
                identities,
                replay,
            ));
        }
    }

    bail!(
        "Idena head changed while identities were being read for {} consecutive attempts; refusing consensus snapshot",
        SNAPSHOT_HEAD_STABILITY_ATTEMPTS
    )
}

fn ensure_snapshot_sync_ready(syncing: &SyncingResponse, require_synced: bool) -> Result<()> {
    if require_synced && syncing.is_effectively_syncing() {
        bail!(
            "Idena node is still syncing at block {} of {}; refusing consensus snapshot",
            syncing.current_block,
            syncing.highest_block
        );
    }
    Ok(())
}

async fn read_snapshot_block<R: SnapshotRpc + Sync>(
    client: &R,
    height: u64,
) -> Result<BlockResponse> {
    let block = client
        .block_at(height)
        .await
        .context("failed to read current Idena block")?
        .with_context(|| format!("Idena block {height} is unavailable"))?;
    if block.height != height {
        bail!(
            "Idena RPC returned block height {} while block {} was requested",
            block.height,
            height
        );
    }
    Ok(block)
}

fn same_snapshot_head(left: &BlockResponse, right: &BlockResponse) -> bool {
    left.height == right.height
        && left.hash.eq_ignore_ascii_case(&right.hash)
        && left
            .identity_root
            .eq_ignore_ascii_case(&right.identity_root)
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
    use anyhow::anyhow;
    use chrono::NaiveDate;
    use pohw_core::replay::{RewardEvent, RewardKind};
    use pohw_core::snapshot::IdenaStatus;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockSnapshotRpc {
        syncing: Mutex<VecDeque<SyncingResponse>>,
        blocks: Mutex<VecDeque<BlockResponse>>,
        identities: Mutex<VecDeque<Vec<IdentityResponse>>>,
    }

    impl MockSnapshotRpc {
        fn new(
            syncing: Vec<SyncingResponse>,
            blocks: Vec<BlockResponse>,
            identities: Vec<Vec<IdentityResponse>>,
        ) -> Self {
            Self {
                syncing: Mutex::new(syncing.into()),
                blocks: Mutex::new(blocks.into()),
                identities: Mutex::new(identities.into()),
            }
        }
    }

    #[async_trait]
    impl SnapshotRpc for MockSnapshotRpc {
        async fn syncing(&self) -> Result<SyncingResponse> {
            self.syncing
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("missing mocked sync response"))
        }

        async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>> {
            let block = self
                .blocks
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("missing mocked block response"))?;
            if block.height != height {
                return Err(anyhow!(
                    "mock expected block request {} but received {}",
                    block.height,
                    height
                ));
            }
            Ok(Some(block))
        }

        async fn identities(&self) -> Result<Vec<IdentityResponse>> {
            self.identities
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("missing mocked identity response"))
        }
    }

    fn syncing(height: u64) -> SyncingResponse {
        SyncingResponse {
            syncing: false,
            current_block: height,
            highest_block: height,
            wrong_time: false,
            genesis_block: 0,
            message: String::new(),
        }
    }

    fn block(height: u64, discriminator: &str) -> BlockResponse {
        BlockResponse {
            coinbase: "0xcoinbase".to_string(),
            hash: format!("0xhash-{height}-{discriminator}"),
            parent_hash: "0xparent".to_string(),
            height,
            timestamp: 0,
            root: "0xroot".to_string(),
            identity_root: format!("0xidentity-{height}-{discriminator}"),
            transactions: None,
            is_empty: false,
        }
    }

    fn identity(address: &str) -> IdentityResponse {
        IdentityResponse {
            address: address.to_string(),
            state: IdenaStatus::Human,
            pubkey: "PUB".to_string(),
            delegatee: None,
            is_pool: false,
        }
    }

    fn snapshot_options() -> SnapshotBuildOptions {
        SnapshotBuildOptions {
            snapshot_day: NaiveDate::from_ymd_opt(2026, 6, 29).unwrap(),
            formula_version: FORMULA_VERSION,
            require_synced: true,
        }
    }

    #[tokio::test]
    async fn current_snapshot_retries_when_height_changes_during_identity_read() {
        let block_42 = block(42, "a");
        let block_43 = block(43, "a");
        let rpc = MockSnapshotRpc::new(
            vec![syncing(42), syncing(43), syncing(43), syncing(43)],
            vec![block_42, block_43.clone(), block_43],
            vec![vec![identity("0xabc")], vec![identity("0xdef")]],
        );

        let snapshot =
            build_current_snapshot_with_rpc(&rpc, &RewardReplay::default(), snapshot_options())
                .await
                .unwrap();

        assert_eq!(snapshot.idena_height, 43);
        assert_eq!(snapshot.leaves[0].idena_address, "0xdef");
    }

    #[tokio::test]
    async fn current_snapshot_retries_same_height_reorganization() {
        let old = block(42, "old");
        let new = block(42, "new");
        let rpc = MockSnapshotRpc::new(
            vec![syncing(42), syncing(42), syncing(42), syncing(42)],
            vec![old, new.clone(), new.clone(), new.clone()],
            vec![vec![identity("0xabc")], vec![identity("0xdef")]],
        );

        let snapshot =
            build_current_snapshot_with_rpc(&rpc, &RewardReplay::default(), snapshot_options())
                .await
                .unwrap();

        assert_eq!(snapshot.idena_block_hash, new.hash);
        assert_eq!(snapshot.identity_root, new.identity_root);
        assert_eq!(snapshot.leaves[0].idena_address, "0xdef");
    }

    #[tokio::test]
    async fn current_snapshot_refuses_continuously_moving_head() {
        let mut sync_responses = Vec::new();
        let mut blocks = Vec::new();
        let mut identities = Vec::new();
        for attempt in 0..SNAPSHOT_HEAD_STABILITY_ATTEMPTS {
            let height = 100 + attempt as u64 * 2;
            sync_responses.push(syncing(height));
            sync_responses.push(syncing(height + 1));
            blocks.push(block(height, "moving"));
            identities.push(vec![identity("0xabc")]);
        }
        let rpc = MockSnapshotRpc::new(sync_responses, blocks, identities);

        let error =
            build_current_snapshot_with_rpc(&rpc, &RewardReplay::default(), snapshot_options())
                .await
                .unwrap_err();

        assert!(error.to_string().contains("head changed"));
    }

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
