use crate::commitment::CommitmentError;
use crate::idena_anchor::{
    IdenaAnchorError, IdenaAnchorPolicyV2, SharechainCheckpointAnchorV1,
    CHECKPOINT_MIN_INTERVAL_BLOCKS, ZERO_SHARE_PARENT_HASH,
};
use crate::ledger::{ClaimLedger, LedgerError};
use crate::payout::{build_payout_schedule, ParticipantAccount, PayoutError, PayoutSchedule};
use crate::sharechain::{
    BitcoinWorkTemplate, MinerRegistration, Share, SharechainError, SharechainMessage, SnapshotVote,
};
use crate::withdrawal::{
    build_withdrawal_batch, WithdrawalBatch, WithdrawalError, WithdrawalRequest,
};
use crate::{canonical_json, hash_hex, sha256_tagged, Sats, Score};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyOutcome {
    Applied,
    DuplicateIgnored,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharechainReplayState {
    applied_message_hashes: BTreeSet<String>,
    accepted_bitcoin_work_template_prefixes: BTreeMap<String, String>,
    bitcoin_work_templates: BTreeMap<String, BitcoinWorkTemplate>,
    registrations: BTreeMap<String, MinerRegistration>,
    #[serde(default)]
    sharechain_checkpoints: BTreeMap<u32, SharechainCheckpointAnchorV1>,
    shares: BTreeMap<String, ShareNode>,
    #[serde(default)]
    share_hash_by_work_hash: BTreeMap<String, String>,
    #[serde(default)]
    children_by_parent: BTreeMap<String, BTreeSet<String>>,
    active_share_hashes: BTreeSet<String>,
    active_share_score_total: Score,
    best_share_tip: Option<String>,
    hashrate_scores: BTreeMap<String, Score>,
    snapshot_votes: BTreeMap<SnapshotVoteKey, BTreeSet<String>>,
    proposed_payout_schedules: BTreeMap<String, PayoutSchedule>,
    withdrawal_requests: BTreeMap<String, WithdrawalRequest>,
    withdrawal_batches: BTreeMap<String, WithdrawalBatch>,
    claim_ledger: ClaimLedger,
    last_message_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SnapshotVoteKey {
    pub snapshot_day: String,
    pub idena_height: u64,
    pub score_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharechainReplaySummary {
    pub applied_message_count: usize,
    pub registered_miner_count: usize,
    pub unique_registered_idena_count: usize,
    pub active_idena_participant_count: usize,
    pub accepted_bitcoin_work_template_count: usize,
    pub bitcoin_work_template_count: usize,
    pub stored_share_count: usize,
    pub active_share_count: usize,
    pub inactive_share_count: usize,
    pub share_miner_count: usize,
    pub active_share_score_total: Score,
    pub best_share_tip: Option<String>,
    pub finalized_checkpoint_count: usize,
    pub latest_checkpoint_round: Option<u32>,
    pub latest_checkpoint_tip: Option<String>,
    pub snapshot_vote_root_count: usize,
    pub proposed_payout_schedule_count: usize,
    pub withdrawal_request_count: usize,
    pub withdrawal_batch_count: usize,
    pub pending_withdrawal_count: usize,
    pub vault_claim_owner_count: usize,
    pub last_message_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharechainShareSummary {
    pub share_hash: String,
    pub height: u64,
    pub active: bool,
    pub miner_id: String,
    pub parent_share_hash: String,
    pub bitcoin_template_hash: String,
    pub work_hash: String,
    pub target: String,
    pub hashrate_score_delta: String,
    pub cumulative_score: Option<String>,
    pub idena_snapshot_id: String,
    pub idena_snapshot_proof_root: String,
    pub template_created_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AccountingStateRootMaterial {
    version: &'static str,
    best_share_tip: Option<String>,
    active_share_hashes: Vec<String>,
    active_share_score_total: Score,
    hashrate_scores: BTreeMap<String, Score>,
    registrations: BTreeMap<String, MinerRegistration>,
    sharechain_checkpoints: BTreeMap<u32, SharechainCheckpointAnchorV1>,
    snapshot_votes: BTreeMap<String, BTreeSet<String>>,
    proposed_payout_schedules: BTreeMap<String, PayoutSchedule>,
    withdrawal_requests: BTreeMap<String, WithdrawalRequest>,
    withdrawal_batches: BTreeMap<String, WithdrawalBatch>,
    claim_ledger: ClaimLedger,
}

fn accounting_snapshot_vote_key(key: &SnapshotVoteKey) -> String {
    serde_json::to_string(&(
        key.snapshot_day.as_str(),
        key.idena_height,
        key.score_root.to_ascii_lowercase(),
    ))
    .expect("snapshot vote key serialization cannot fail")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShareNode {
    share: Share,
    parent_share_hash: String,
    cumulative_score: Option<Score>,
    height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SharechainReplayError {
    #[error("conflicting registration for miner {0}")]
    ConflictingRegistration(String),
    #[error("Idena anchor policy rejected the message: {0}")]
    IdenaAnchorPolicy(#[from] IdenaAnchorError),
    #[error("miner {0} has no contract-anchored registration")]
    UnanchoredMinerRegistration(String),
    #[error("Bitcoin work template {0} has no finalized Idena block anchor")]
    UnanchoredBitcoinWorkTemplate(String),
    #[error("Bitcoin work template anchor predates miner registration")]
    TemplateAnchorBeforeRegistration,
    #[error("bootstrap share reuses Idena anchor {anchor_height} for miner {miner_id}")]
    DuplicateBootstrapAnchor {
        miner_id: String,
        anchor_height: u64,
    },
    #[error("bootstrap share Idena anchor must advance beyond its anchored parent")]
    NonIncreasingBootstrapAnchor,
    #[error("bootstrap share references missing anchored parent {0}")]
    MissingAnchoredShareParent(String),
    #[error("bootstrap share parent references missing Bitcoin work template {0}")]
    MissingAnchoredParentBitcoinWorkTemplate(String),
    #[error("share references unknown miner {0}")]
    UnknownShareMiner(String),
    #[error("Bitcoin work template references unknown miner {0}")]
    UnknownBitcoinWorkTemplateMiner(String),
    #[error("Bitcoin work template {0} has not been locally accepted")]
    UnacceptedBitcoinWorkTemplate(String),
    #[error("conflicting Bitcoin work template {0}")]
    ConflictingBitcoinWorkTemplate(String),
    #[error("share references unknown Bitcoin work template {0}")]
    UnknownShareBitcoinWorkTemplate(String),
    #[error("share header prefix does not match accepted Bitcoin work template {0}")]
    ShareBitcoinWorkTemplateMismatch(String),
    #[error(
        "sharechain already has root {existing_share_hash}; cannot admit distinct root {candidate_share_hash}"
    )]
    AdditionalSharechainRoot {
        existing_share_hash: String,
        candidate_share_hash: String,
    },
    #[error("conflicting share for hash {0}")]
    ConflictingShare(String),
    #[error("Bitcoin work hash {work_hash} is already credited to share {existing_share_hash}")]
    DuplicateShareWork {
        work_hash: String,
        existing_share_hash: String,
    },
    #[error("checkpoint round {0} conflicts with an existing finalized checkpoint")]
    ConflictingCheckpoint(u32),
    #[error("checkpoint round {actual} must follow finalized round {expected_parent}")]
    NonSequentialCheckpoint { expected_parent: u32, actual: u32 },
    #[error("checkpoint parent share tip does not match the previous finalized checkpoint")]
    CheckpointParentMismatch,
    #[error("checkpoint finalization block does not satisfy the minimum interval")]
    CheckpointIntervalNotElapsed,
    #[error("checkpoint registered miner set does not match anchored sharechain registrations")]
    CheckpointRegistrationSetMismatch,
    #[error("checkpoint references unknown or unresolved share tip {0}")]
    UnknownCheckpointShareTip(String),
    #[error("checkpoint share height or cumulative score does not match local replay")]
    CheckpointShareMetadataMismatch,
    #[error("checkpoint share tip does not descend from the previous finalized checkpoint")]
    CheckpointNotDescendant,
    #[error("snapshot vote references unknown miner {0}")]
    UnknownSnapshotVoter(String),
    #[error("hashrate score overflow for miner {0}")]
    HashrateScoreOverflow(String),
    #[error("sharechain branch score overflow at share {0}")]
    ShareBranchScoreOverflow(String),
    #[error("conflicting payout schedule for root {0}")]
    ConflictingPayoutSchedule(String),
    #[error("payout schedule references unknown miner {0}")]
    UnknownPayoutMiner(String),
    #[error("payout script mismatch for miner {miner_id}")]
    PayoutScriptMismatch { miner_id: String },
    #[error("payout claim owner mismatch for miner {miner_id}")]
    PayoutClaimOwnerMismatch { miner_id: String },
    #[error("payout schedule does not match deterministic local replay")]
    PayoutScheduleMismatch,
    #[error("conflicting withdrawal request {0}")]
    ConflictingWithdrawalRequest(String),
    #[error("conflicting withdrawal batch {0}")]
    ConflictingWithdrawalBatch(String),
    #[error("withdrawal batch references unknown request {0}")]
    UnknownWithdrawalRequest(String),
    #[error("withdrawal batch {0} is not present in local sharechain replay")]
    UnknownWithdrawalBatch(String),
    #[error("withdrawal batch references unreserved request {0}")]
    UnreservedWithdrawalRequest(String),
    #[error("withdrawal batch {0} does not match deterministic local replay")]
    WithdrawalBatchMismatch(String),
    #[error("withdrawal batch output {request_id} does not match the signed request")]
    WithdrawalBatchRequestMismatch { request_id: String },
    #[error("invalid sharechain signature: {0}")]
    InvalidSharechainSignature(#[from] SharechainError),
    #[error("invalid PoHW commitment: {0}")]
    InvalidCommitment(#[from] CommitmentError),
    #[error("invalid withdrawal request: {0}")]
    InvalidWithdrawal(#[from] WithdrawalError),
    #[error("invalid payout schedule: {0}")]
    InvalidPayoutSchedule(#[from] PayoutError),
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),
}

impl SharechainReplayState {
    pub fn validate_idena_anchor_policy(
        &self,
        message: &SharechainMessage,
        policy: &IdenaAnchorPolicyV2,
    ) -> Result<(), SharechainReplayError> {
        policy.validate()?;
        match message {
            SharechainMessage::MinerRegistration(registration) => {
                let anchor = registration.require_registry_anchor().map_err(|_| {
                    SharechainReplayError::UnanchoredMinerRegistration(
                        registration.miner_id.to_ascii_lowercase(),
                    )
                })?;
                policy.validate_registry_anchor(anchor)?;
            }
            SharechainMessage::BitcoinWorkTemplate(template) => {
                let miner_id = template.miner_id.to_ascii_lowercase();
                let registration = self.registrations.get(&miner_id).ok_or_else(|| {
                    SharechainReplayError::UnknownBitcoinWorkTemplateMiner(miner_id.clone())
                })?;
                let registry_anchor = registration.require_registry_anchor().map_err(|_| {
                    SharechainReplayError::UnanchoredMinerRegistration(miner_id.clone())
                })?;
                policy.validate_registry_anchor(registry_anchor)?;
                let block_anchor = template.require_idena_anchor().map_err(|_| {
                    SharechainReplayError::UnanchoredBitcoinWorkTemplate(
                        template.template_hash.to_ascii_lowercase(),
                    )
                })?;
                let policy_hash = policy.commitment_hash()?;
                if template.require_idena_anchor_policy_hash()? != policy_hash {
                    return Err(IdenaAnchorError::PolicyCommitmentMismatch.into());
                }
                if block_anchor.height < registry_anchor.registration_block {
                    return Err(SharechainReplayError::TemplateAnchorBeforeRegistration);
                }
            }
            SharechainMessage::Share(share) => {
                self.validate_anchored_share(share, policy)?;
            }
            SharechainMessage::SharechainCheckpoint(checkpoint) => {
                policy.validate_checkpoint_anchor(checkpoint)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn apply_message(
        &mut self,
        message: &SharechainMessage,
    ) -> Result<ApplyOutcome, SharechainReplayError> {
        let message_hash = message.message_hash();
        if self.applied_message_hashes.contains(&message_hash) {
            return Ok(ApplyOutcome::DuplicateIgnored);
        }

        match message {
            SharechainMessage::MinerRegistration(registration) => {
                self.apply_registration(registration)?;
            }
            SharechainMessage::BitcoinWorkTemplate(template) => {
                self.apply_bitcoin_work_template(template)?;
            }
            SharechainMessage::Share(share) => {
                let miner_id = share.miner_id.to_ascii_lowercase();
                let registration = self
                    .registrations
                    .get(&miner_id)
                    .ok_or_else(|| SharechainReplayError::UnknownShareMiner(miner_id.clone()))?;
                let template_hash = share.bitcoin_template_hash.to_ascii_lowercase();
                let template = self.bitcoin_work_templates.get(&template_hash).ok_or(
                    SharechainReplayError::UnknownShareBitcoinWorkTemplate(template_hash),
                )?;
                share.verify_mining_signature_for_template(
                    &registration.mining_pubkey_hex,
                    template,
                )?;
                self.validate_share_bitcoin_work_template(share)?;
                self.apply_share(share)?;
            }
            SharechainMessage::SharechainCheckpoint(checkpoint) => {
                self.apply_sharechain_checkpoint(checkpoint)?;
            }
            SharechainMessage::SnapshotVote(vote) => {
                self.apply_snapshot_vote(vote)?;
            }
            SharechainMessage::PayoutSchedule(schedule) => {
                self.apply_payout_schedule_proposal(schedule)?;
            }
            SharechainMessage::WithdrawalRequest(request) => {
                self.apply_withdrawal_request(request)?;
            }
            SharechainMessage::WithdrawalBatch(batch) => {
                self.apply_withdrawal_batch(batch)?;
            }
            SharechainMessage::PohwCommitment(commitment) => {
                commitment.validate_fields()?;
                // Commitment verification depends on the fork-chain block that carried it.
                // The sharechain log records it, but replay does not credit funds from it.
            }
        }

        self.applied_message_hashes.insert(message_hash.clone());
        self.last_message_hash = Some(message_hash);
        Ok(ApplyOutcome::Applied)
    }

    pub fn apply_confirmed_payout_schedule(
        &mut self,
        schedule: &PayoutSchedule,
        accounts: &[ParticipantAccount],
        reward_sats: Sats,
        direct_limit: usize,
        min_direct_payout_sats: Sats,
    ) -> Result<(), SharechainReplayError> {
        self.validate_deterministic_payout_schedule(
            schedule,
            accounts,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
        )?;
        self.claim_ledger.apply_payout_schedule(schedule)?;
        Ok(())
    }

    pub fn summary(&self) -> SharechainReplaySummary {
        let unique_registered_idena_count = self
            .registrations
            .values()
            .map(|registration| registration.idena_address.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .len();
        let active_idena_participant_count = self.active_idena_addresses().len();
        SharechainReplaySummary {
            applied_message_count: self.applied_message_hashes.len(),
            registered_miner_count: self.registrations.len(),
            unique_registered_idena_count,
            active_idena_participant_count,
            accepted_bitcoin_work_template_count: self
                .accepted_bitcoin_work_template_prefixes
                .len(),
            bitcoin_work_template_count: self.bitcoin_work_templates.len(),
            stored_share_count: self.shares.len(),
            active_share_count: self.active_share_hashes.len(),
            inactive_share_count: self
                .shares
                .len()
                .saturating_sub(self.active_share_hashes.len()),
            share_miner_count: self.hashrate_scores.len(),
            active_share_score_total: self.active_share_score_total,
            best_share_tip: self.best_share_tip.clone(),
            finalized_checkpoint_count: self.sharechain_checkpoints.len(),
            latest_checkpoint_round: self
                .sharechain_checkpoints
                .last_key_value()
                .map(|(round, _)| *round),
            latest_checkpoint_tip: self
                .sharechain_checkpoints
                .last_key_value()
                .map(|(_, checkpoint)| checkpoint.share_tip_hash.clone()),
            snapshot_vote_root_count: self.snapshot_votes.len(),
            proposed_payout_schedule_count: self.proposed_payout_schedules.len(),
            withdrawal_request_count: self.withdrawal_requests.len(),
            withdrawal_batch_count: self.withdrawal_batches.len(),
            pending_withdrawal_count: self.claim_ledger.pending_withdrawal_count(),
            vault_claim_owner_count: self.claim_balances().len(),
            last_message_hash: self.last_message_hash.clone(),
        }
    }

    pub fn registrations(&self) -> &BTreeMap<String, MinerRegistration> {
        &self.registrations
    }

    pub fn bitcoin_work_templates(&self) -> &BTreeMap<String, BitcoinWorkTemplate> {
        &self.bitcoin_work_templates
    }

    pub fn accept_bitcoin_work_template_prefix(
        &mut self,
        header_prefix_hex: &str,
    ) -> Result<String, SharechainReplayError> {
        let template_hash =
            BitcoinWorkTemplate::template_hash_for_header_prefix_hex(header_prefix_hex)?;
        let normalized_prefix = header_prefix_hex.to_ascii_lowercase();
        if let Some(existing_prefix) = self
            .accepted_bitcoin_work_template_prefixes
            .insert(template_hash.clone(), normalized_prefix.clone())
        {
            if existing_prefix != normalized_prefix {
                return Err(SharechainReplayError::ConflictingBitcoinWorkTemplate(
                    template_hash,
                ));
            }
        }
        Ok(template_hash)
    }

    pub fn accept_bitcoin_work_template(
        &mut self,
        template: &BitcoinWorkTemplate,
    ) -> Result<String, SharechainReplayError> {
        template.verify_template_hash()?;
        let template_hash = template.template_hash.to_ascii_lowercase();
        let normalized_prefix = template.header_prefix_hex.to_ascii_lowercase();
        if let Some(existing_prefix) = self
            .accepted_bitcoin_work_template_prefixes
            .insert(template_hash.clone(), normalized_prefix.clone())
        {
            if existing_prefix != normalized_prefix {
                return Err(SharechainReplayError::ConflictingBitcoinWorkTemplate(
                    template_hash,
                ));
            }
        }
        Ok(template_hash)
    }

    pub fn validate_target_bound_message(
        &self,
        message: &SharechainMessage,
    ) -> Result<(), SharechainReplayError> {
        match message {
            SharechainMessage::BitcoinWorkTemplate(template) => template.require_target_bound()?,
            SharechainMessage::Share(share) => {
                let template_hash = share.bitcoin_template_hash.to_ascii_lowercase();
                let template =
                    self.bitcoin_work_templates
                        .get(&template_hash)
                        .ok_or_else(|| {
                            SharechainReplayError::UnknownShareBitcoinWorkTemplate(
                                template_hash.clone(),
                            )
                        })?;
                template.require_target_bound()?;
                template.verify_assigned_share_target(&share.target)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn hashrate_scores(&self) -> &BTreeMap<String, Score> {
        &self.hashrate_scores
    }

    pub fn active_idena_addresses(&self) -> BTreeSet<String> {
        self.hashrate_scores
            .iter()
            .filter(|(_, score)| **score > 0)
            .filter_map(|(miner_id, _)| self.registrations.get(miner_id))
            .map(|registration| registration.idena_address.to_ascii_lowercase())
            .collect()
    }

    pub fn recent_active_idena_addresses(
        &self,
        minimum_template_created_at_unix: i64,
    ) -> BTreeSet<String> {
        self.active_share_hashes
            .iter()
            .filter_map(|share_hash| self.shares.get(share_hash))
            .filter(|node| {
                self.bitcoin_work_templates
                    .get(&node.share.bitcoin_template_hash)
                    .is_some_and(|template| {
                        template.created_at_unix >= minimum_template_created_at_unix
                    })
            })
            .filter_map(|node| {
                self.registrations
                    .get(&node.share.miner_id.to_ascii_lowercase())
            })
            .map(|registration| registration.idena_address.to_ascii_lowercase())
            .collect()
    }

    pub fn unique_snapshot_voter_idena_count(
        &self,
        snapshot_day: &str,
        idena_height: u64,
        score_root: &str,
    ) -> usize {
        let key = SnapshotVoteKey {
            snapshot_day: snapshot_day.to_string(),
            idena_height,
            score_root: score_root.to_ascii_lowercase(),
        };
        self.snapshot_votes
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(|miner_id| self.registrations.get(miner_id))
            .map(|registration| registration.idena_address.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn best_share_tip(&self) -> Option<&str> {
        self.best_share_tip.as_deref()
    }

    pub fn latest_sharechain_checkpoint(&self) -> Option<&SharechainCheckpointAnchorV1> {
        self.sharechain_checkpoints
            .last_key_value()
            .map(|(_, checkpoint)| checkpoint)
    }

    pub fn best_share_height(&self) -> Option<u64> {
        self.best_share_tip
            .as_deref()
            .and_then(|share_hash| self.shares.get(share_hash))
            .map(|node| node.height)
    }

    pub fn active_share_hashes(&self) -> &BTreeSet<String> {
        &self.active_share_hashes
    }

    pub fn active_share_score_total(&self) -> Score {
        self.active_share_score_total
    }

    pub fn share_summaries(&self) -> Vec<SharechainShareSummary> {
        let mut summaries = self
            .shares
            .iter()
            .map(|(share_hash, node)| self.share_summary_for_node(share_hash, node))
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| {
            right
                .height
                .cmp(&left.height)
                .then_with(|| left.share_hash.cmp(&right.share_hash))
        });
        summaries
    }

    pub fn share_summary(&self, share_hash: &str) -> Option<SharechainShareSummary> {
        let normalized = share_hash.to_ascii_lowercase();
        self.shares
            .get(&normalized)
            .map(|node| self.share_summary_for_node(&normalized, node))
    }

    fn share_summary_for_node(&self, share_hash: &str, node: &ShareNode) -> SharechainShareSummary {
        SharechainShareSummary {
            share_hash: share_hash.to_string(),
            height: node.height,
            active: self.active_share_hashes.contains(share_hash),
            miner_id: node.share.miner_id.clone(),
            parent_share_hash: node.parent_share_hash.clone(),
            bitcoin_template_hash: node.share.bitcoin_template_hash.clone(),
            work_hash: node.share.work_hash.clone(),
            target: node.share.target.clone(),
            hashrate_score_delta: node.share.hashrate_score_delta.to_string(),
            cumulative_score: node.cumulative_score.map(|score| score.to_string()),
            idena_snapshot_id: node.share.idena_snapshot_id.clone(),
            idena_snapshot_proof_root: node.share.idena_snapshot_proof_root.clone(),
            template_created_at_unix: self
                .bitcoin_work_templates
                .get(&node.share.bitcoin_template_hash)
                .map(|template| template.created_at_unix),
        }
    }

    pub fn claim_ledger(&self) -> &ClaimLedger {
        &self.claim_ledger
    }

    pub fn withdrawal_requests(&self) -> &BTreeMap<String, WithdrawalRequest> {
        &self.withdrawal_requests
    }

    pub fn withdrawal_batches(&self) -> &BTreeMap<String, WithdrawalBatch> {
        &self.withdrawal_batches
    }

    pub fn replace_claim_ledger(&mut self, claim_ledger: ClaimLedger) {
        self.claim_ledger = claim_ledger;
    }

    pub fn claim_ledger_after_withdrawal_batch(
        &self,
        batch: &WithdrawalBatch,
        current_height: u64,
    ) -> Result<ClaimLedger, SharechainReplayError> {
        let batch = self.expected_withdrawal_batch(batch, current_height)?;
        let mut ledger = self.claim_ledger.clone();
        for output in &batch.outputs {
            let request = self
                .withdrawal_requests
                .get(&output.request_id)
                .ok_or_else(|| {
                    SharechainReplayError::UnknownWithdrawalRequest(output.request_id.clone())
                })?;
            if !request
                .destination_script_hex
                .eq_ignore_ascii_case(&output.destination_script_hex)
                || request.output_kind != output.output_kind
                || request.amount_sats != output.gross_amount_sats
            {
                return Err(SharechainReplayError::WithdrawalBatchRequestMismatch {
                    request_id: output.request_id.clone(),
                });
            }
            let pending = ledger.reserve_withdrawal(request, output.fee_sats, current_height)?;
            if pending.request_id != output.request_id
                || pending.gross_amount_sats != output.gross_amount_sats
                || pending.fee_sats != output.fee_sats
                || pending.net_amount_sats != output.net_amount_sats
            {
                return Err(SharechainReplayError::WithdrawalBatchRequestMismatch {
                    request_id: output.request_id.clone(),
                });
            }
        }
        Ok(ledger)
    }

    fn expected_withdrawal_batch(
        &self,
        batch: &WithdrawalBatch,
        current_height: u64,
    ) -> Result<WithdrawalBatch, SharechainReplayError> {
        let batch = batch.clone().normalized();
        let mut requests = Vec::with_capacity(batch.outputs.len());
        for output in &batch.outputs {
            let request = self
                .withdrawal_requests
                .get(&output.request_id)
                .ok_or_else(|| {
                    SharechainReplayError::UnknownWithdrawalRequest(output.request_id.clone())
                })?;
            requests.push(request.clone());
        }
        let expected = build_withdrawal_batch(
            requests,
            batch.inputs,
            batch.fee_rate_sat_vb,
            current_height,
        )?;
        if expected != batch {
            return Err(SharechainReplayError::WithdrawalBatchMismatch(
                batch.batch_hash(),
            ));
        }
        Ok(expected)
    }

    pub fn withdrawal_batch_is_reserved(
        &self,
        batch: &WithdrawalBatch,
        current_height: u64,
    ) -> Result<(), SharechainReplayError> {
        let batch = self.expected_withdrawal_batch(batch, current_height)?;
        let batch_hash = batch.batch_hash();
        let accepted = self
            .withdrawal_batches
            .get(&batch_hash)
            .ok_or_else(|| SharechainReplayError::UnknownWithdrawalBatch(batch_hash.clone()))?;
        if accepted != &batch {
            return Err(SharechainReplayError::ConflictingWithdrawalBatch(
                batch_hash,
            ));
        }
        for output in &batch.outputs {
            let request = self
                .withdrawal_requests
                .get(&output.request_id)
                .ok_or_else(|| {
                    SharechainReplayError::UnknownWithdrawalRequest(output.request_id.clone())
                })?;
            if !request
                .destination_script_hex
                .eq_ignore_ascii_case(&output.destination_script_hex)
                || request.output_kind != output.output_kind
                || request.amount_sats != output.gross_amount_sats
            {
                return Err(SharechainReplayError::WithdrawalBatchRequestMismatch {
                    request_id: output.request_id.clone(),
                });
            }
            request.validate(current_height)?;
            let pending = self
                .claim_ledger
                .pending_withdrawal(&output.request_id)
                .ok_or_else(|| {
                    SharechainReplayError::UnreservedWithdrawalRequest(output.request_id.clone())
                })?;
            if pending.request_id != output.request_id
                || pending.claim_owner_id != request.claim_owner_id
                || pending.gross_amount_sats != output.gross_amount_sats
                || pending.fee_sats != output.fee_sats
                || pending.net_amount_sats != output.net_amount_sats
            {
                return Err(SharechainReplayError::WithdrawalBatchRequestMismatch {
                    request_id: output.request_id.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn has_message_hash(&self, message_hash: &str) -> bool {
        self.applied_message_hashes
            .contains(&message_hash.to_ascii_lowercase())
    }

    pub fn accounting_state_root(&self) -> String {
        let material = AccountingStateRootMaterial {
            version: "POHW1_ACCOUNTING_STATE",
            best_share_tip: self.best_share_tip.clone(),
            active_share_hashes: self.active_share_hashes.iter().cloned().collect(),
            active_share_score_total: self.active_share_score_total,
            hashrate_scores: self.hashrate_scores.clone(),
            registrations: self
                .registrations
                .iter()
                .map(|(miner_id, registration)| {
                    (miner_id.clone(), registration.clone().normalized())
                })
                .collect(),
            sharechain_checkpoints: self.sharechain_checkpoints.clone(),
            snapshot_votes: self
                .snapshot_votes
                .iter()
                .map(|(key, voters)| (accounting_snapshot_vote_key(key), voters.clone()))
                .collect(),
            proposed_payout_schedules: self.proposed_payout_schedules.clone(),
            withdrawal_requests: self
                .withdrawal_requests
                .iter()
                .map(|(request_id, request)| (request_id.clone(), request.clone().normalized()))
                .collect(),
            withdrawal_batches: self.withdrawal_batches.clone(),
            claim_ledger: self.claim_ledger.clone(),
        };
        hash_hex(sha256_tagged(
            b"POHW1_ACCOUNTING_STATE",
            &canonical_json(&material),
        ))
    }

    pub fn claim_balances(&self) -> BTreeMap<String, Sats> {
        self.registrations
            .values()
            .map(|registration| {
                let owner = registration.claim_owner_pubkey_hex.to_ascii_lowercase();
                let balance = self.claim_ledger.balance(&owner);
                (owner, balance)
            })
            .filter(|(_, balance)| *balance > 0)
            .collect()
    }

    pub fn participant_accounts(&self) -> Vec<ParticipantAccount> {
        self.registrations
            .values()
            .map(|registration| {
                let miner_id = registration.miner_id.to_ascii_lowercase();
                let claim_owner_id = registration.claim_owner_pubkey_hex.to_ascii_lowercase();
                ParticipantAccount {
                    miner_id: miner_id.clone(),
                    btc_payout_script_hex: registration.btc_payout_script_hex.to_ascii_lowercase(),
                    claim_owner_id: claim_owner_id.clone(),
                    unpaid_sats: self.claim_ledger.balance(&claim_owner_id),
                    hashrate_score: self.hashrate_scores.get(&miner_id).copied().unwrap_or(0),
                    idena_score: 0,
                }
            })
            .collect()
    }

    pub fn expected_payout_schedule(
        &self,
        accounts: &[ParticipantAccount],
        reward_sats: Sats,
        direct_limit: usize,
        min_direct_payout_sats: Sats,
    ) -> Result<PayoutSchedule, SharechainReplayError> {
        let schedule =
            build_payout_schedule(accounts, reward_sats, direct_limit, min_direct_payout_sats)?;
        self.validate_payout_schedule_bindings(&schedule)?;
        Ok(schedule)
    }

    pub fn validate_deterministic_payout_schedule(
        &self,
        schedule: &PayoutSchedule,
        accounts: &[ParticipantAccount],
        reward_sats: Sats,
        direct_limit: usize,
        min_direct_payout_sats: Sats,
    ) -> Result<(), SharechainReplayError> {
        self.validate_payout_schedule_bindings(schedule)?;
        let expected = self.expected_payout_schedule(
            accounts,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
        )?;
        if &expected != schedule {
            return Err(SharechainReplayError::PayoutScheduleMismatch);
        }
        Ok(())
    }

    fn apply_registration(
        &mut self,
        registration: &MinerRegistration,
    ) -> Result<(), SharechainReplayError> {
        registration.verify_mining_signature()?;
        registration.verify_idena_ownership_signature()?;
        let mut registration = registration.clone();
        registration.miner_id = registration.miner_id.to_ascii_lowercase();
        registration.idena_address = registration.idena_address.to_ascii_lowercase();
        registration.btc_payout_script_hex =
            registration.btc_payout_script_hex.to_ascii_lowercase();
        registration.claim_owner_pubkey_hex =
            registration.claim_owner_pubkey_hex.to_ascii_lowercase();
        registration.mining_pubkey_hex = registration.mining_pubkey_hex.to_ascii_lowercase();
        registration.idena_signature_hex = registration.idena_signature_hex.to_ascii_lowercase();
        registration.mining_signature_hex = registration.mining_signature_hex.to_ascii_lowercase();

        if let Some(existing) = self.registrations.get(&registration.miner_id) {
            if existing == &registration {
                return Ok(());
            }
            if !is_valid_registry_registration_upgrade(existing, &registration) {
                return Err(SharechainReplayError::ConflictingRegistration(
                    registration.miner_id,
                ));
            }
        }
        self.registrations
            .insert(registration.miner_id.clone(), registration);
        Ok(())
    }

    fn apply_bitcoin_work_template(
        &mut self,
        template: &BitcoinWorkTemplate,
    ) -> Result<(), SharechainReplayError> {
        let miner_id = template.miner_id.to_ascii_lowercase();
        let registration = self.registrations.get(&miner_id).ok_or_else(|| {
            SharechainReplayError::UnknownBitcoinWorkTemplateMiner(miner_id.clone())
        })?;
        template.verify_mining_signature(&registration.mining_pubkey_hex)?;
        let template_hash = template.template_hash.to_ascii_lowercase();
        let accepted_prefix = self
            .accepted_bitcoin_work_template_prefixes
            .get(&template_hash)
            .ok_or_else(|| {
                SharechainReplayError::UnacceptedBitcoinWorkTemplate(template_hash.clone())
            })?;
        if !template
            .header_prefix_hex
            .eq_ignore_ascii_case(accepted_prefix)
        {
            return Err(SharechainReplayError::ConflictingBitcoinWorkTemplate(
                template_hash,
            ));
        }
        let normalized = template.clone().normalized();
        if let Some(existing) = self
            .bitcoin_work_templates
            .insert(template_hash.clone(), normalized.clone())
        {
            if existing != normalized {
                return Err(SharechainReplayError::ConflictingBitcoinWorkTemplate(
                    template_hash,
                ));
            }
        }
        Ok(())
    }

    fn validate_share_bitcoin_work_template(
        &self,
        share: &crate::sharechain::Share,
    ) -> Result<(), SharechainReplayError> {
        let template_hash = share.bitcoin_template_hash.to_ascii_lowercase();
        let template = self
            .bitcoin_work_templates
            .get(&template_hash)
            .ok_or_else(|| {
                SharechainReplayError::UnknownShareBitcoinWorkTemplate(template_hash.clone())
            })?;
        let share_prefix = share.bitcoin_header_prefix_hex()?;
        if !share_prefix.eq_ignore_ascii_case(&template.header_prefix_hex) {
            return Err(SharechainReplayError::ShareBitcoinWorkTemplateMismatch(
                template_hash,
            ));
        }
        template.verify_assigned_share_target(&share.target)?;
        Ok(())
    }

    fn validate_anchored_share(
        &self,
        share: &Share,
        policy: &IdenaAnchorPolicyV2,
    ) -> Result<(), SharechainReplayError> {
        let miner_id = share.miner_id.to_ascii_lowercase();
        let registration = self
            .registrations
            .get(&miner_id)
            .ok_or_else(|| SharechainReplayError::UnknownShareMiner(miner_id.clone()))?;
        let registry_anchor = registration
            .require_registry_anchor()
            .map_err(|_| SharechainReplayError::UnanchoredMinerRegistration(miner_id.clone()))?;
        policy.validate_registry_anchor(registry_anchor)?;

        let template_hash = share.bitcoin_template_hash.to_ascii_lowercase();
        let template = self
            .bitcoin_work_templates
            .get(&template_hash)
            .ok_or_else(|| {
                SharechainReplayError::UnknownShareBitcoinWorkTemplate(template_hash.clone())
            })?;
        let anchor = template.require_idena_anchor().map_err(|_| {
            SharechainReplayError::UnanchoredBitcoinWorkTemplate(template_hash.clone())
        })?;
        if anchor.height < registry_anchor.registration_block {
            return Err(SharechainReplayError::TemplateAnchorBeforeRegistration);
        }

        let parent_hash = share.parent_share_hash.to_ascii_lowercase();
        self.validate_unique_sharechain_root(&share.share_hash(), &parent_hash)?;

        if !policy.bootstrap_limits_active(template.bitcoin_header_version()?) {
            return Ok(());
        }
        for node in self.shares.values() {
            if !node.share.miner_id.eq_ignore_ascii_case(&miner_id) {
                continue;
            }
            let Some(existing_template) = self
                .bitcoin_work_templates
                .get(&node.share.bitcoin_template_hash.to_ascii_lowercase())
            else {
                continue;
            };
            if existing_template
                .idena_anchor
                .as_ref()
                .is_some_and(|existing| existing == anchor)
            {
                return Err(SharechainReplayError::DuplicateBootstrapAnchor {
                    miner_id,
                    anchor_height: anchor.height,
                });
            }
        }

        if parent_hash == ZERO_SHARE_PARENT_HASH {
            return Ok(());
        }
        let parent = self.shares.get(&parent_hash).ok_or_else(|| {
            SharechainReplayError::MissingAnchoredShareParent(parent_hash.clone())
        })?;
        let parent_template = self
            .bitcoin_work_templates
            .get(&parent.share.bitcoin_template_hash.to_ascii_lowercase())
            .ok_or_else(|| {
                SharechainReplayError::MissingAnchoredParentBitcoinWorkTemplate(
                    parent.share.bitcoin_template_hash.to_ascii_lowercase(),
                )
            })?;
        if let Some(parent_anchor) = parent_template.idena_anchor.as_ref() {
            if anchor.height <= parent_anchor.height {
                return Err(SharechainReplayError::NonIncreasingBootstrapAnchor);
            }
        }
        Ok(())
    }

    fn validate_unique_sharechain_root(
        &self,
        candidate_share_hash: &str,
        parent_share_hash: &str,
    ) -> Result<(), SharechainReplayError> {
        if !parent_share_hash.eq_ignore_ascii_case(ZERO_SHARE_PARENT_HASH) {
            return Ok(());
        }

        let candidate_share_hash = candidate_share_hash.to_ascii_lowercase();
        if let Some(existing_share_hash) = self.shares.iter().find_map(|(share_hash, node)| {
            (node
                .parent_share_hash
                .eq_ignore_ascii_case(ZERO_SHARE_PARENT_HASH)
                && !share_hash.eq_ignore_ascii_case(&candidate_share_hash))
            .then(|| share_hash.to_ascii_lowercase())
        }) {
            return Err(SharechainReplayError::AdditionalSharechainRoot {
                existing_share_hash,
                candidate_share_hash,
            });
        }
        Ok(())
    }

    fn apply_sharechain_checkpoint(
        &mut self,
        checkpoint: &SharechainCheckpointAnchorV1,
    ) -> Result<(), SharechainReplayError> {
        let checkpoint = checkpoint.clone().normalized();
        checkpoint.validate()?;
        if let Some(existing) = self.sharechain_checkpoints.get(&checkpoint.round) {
            return if existing == &checkpoint {
                Ok(())
            } else {
                Err(SharechainReplayError::ConflictingCheckpoint(
                    checkpoint.round,
                ))
            };
        }

        let previous = self.sharechain_checkpoints.last_key_value();
        let expected_round = previous
            .map(|(round, _)| round.saturating_add(1))
            .unwrap_or(1);
        if checkpoint.round != expected_round {
            return Err(SharechainReplayError::NonSequentialCheckpoint {
                expected_parent: expected_round.saturating_sub(1),
                actual: checkpoint.round,
            });
        }
        match previous {
            None if checkpoint.parent_checkpoint_tip != ZERO_SHARE_PARENT_HASH => {
                return Err(SharechainReplayError::CheckpointParentMismatch);
            }
            Some((_, prior)) => {
                if checkpoint.parent_checkpoint_tip != prior.share_tip_hash {
                    return Err(SharechainReplayError::CheckpointParentMismatch);
                }
                if checkpoint.finalization_block
                    < prior
                        .finalization_block
                        .checked_add(CHECKPOINT_MIN_INTERVAL_BLOCKS)
                        .ok_or(SharechainReplayError::CheckpointIntervalNotElapsed)?
                {
                    return Err(SharechainReplayError::CheckpointIntervalNotElapsed);
                }
            }
            None => {}
        }

        let registered_miners = self.registrations.keys().cloned().collect::<Vec<_>>();
        if registered_miners != checkpoint.registered_miners {
            return Err(SharechainReplayError::CheckpointRegistrationSetMismatch);
        }
        for miner_id in &checkpoint.registered_miners {
            let registration = self
                .registrations
                .get(miner_id)
                .ok_or(SharechainReplayError::CheckpointRegistrationSetMismatch)?;
            let registry_anchor = registration
                .require_registry_anchor()
                .map_err(|_| SharechainReplayError::CheckpointRegistrationSetMismatch)?;
            if !registry_anchor
                .contract_address
                .eq_ignore_ascii_case(&checkpoint.contract_address)
                || !registry_anchor
                    .experiment_id
                    .eq_ignore_ascii_case(&checkpoint.experiment_id)
            {
                return Err(SharechainReplayError::CheckpointRegistrationSetMismatch);
            }
        }

        let checkpoint_tip = self
            .shares
            .get(&checkpoint.share_tip_hash)
            .filter(|node| node.cumulative_score.is_some())
            .ok_or_else(|| {
                SharechainReplayError::UnknownCheckpointShareTip(checkpoint.share_tip_hash.clone())
            })?;
        let expected_score = checkpoint
            .cumulative_score
            .parse::<Score>()
            .map_err(|_| SharechainReplayError::CheckpointShareMetadataMismatch)?;
        if checkpoint_tip.height != checkpoint.share_height
            || checkpoint_tip.cumulative_score != Some(expected_score)
        {
            return Err(SharechainReplayError::CheckpointShareMetadataMismatch);
        }
        if let Some((_, prior)) = previous {
            if !self.share_descends_from(&checkpoint.share_tip_hash, &prior.share_tip_hash) {
                return Err(SharechainReplayError::CheckpointNotDescendant);
            }
        }

        let finalized_tip = checkpoint.share_tip_hash.clone();
        self.sharechain_checkpoints
            .insert(checkpoint.round, checkpoint);
        self.rebuild_active_branch(&finalized_tip)
    }

    fn apply_share(&mut self, share: &Share) -> Result<(), SharechainReplayError> {
        let share = share.clone().normalized();
        let share_hash = share.share_hash();
        if let Some(existing) = self.shares.get(&share_hash) {
            if existing.share != share {
                return Err(SharechainReplayError::ConflictingShare(share_hash));
            }
            return Ok(());
        }

        let work_hash = share.work_hash.to_ascii_lowercase();
        if let Some(existing_share_hash) = self.share_hash_by_work_hash.get(&work_hash) {
            return Err(SharechainReplayError::DuplicateShareWork {
                work_hash,
                existing_share_hash: existing_share_hash.clone(),
            });
        }

        let parent_share_hash = share.parent_share_hash.to_ascii_lowercase();
        self.validate_unique_sharechain_root(&share_hash, &parent_share_hash)?;

        self.shares.insert(
            share_hash.clone(),
            ShareNode {
                parent_share_hash: parent_share_hash.clone(),
                share,
                cumulative_score: None,
                height: 0,
            },
        );
        self.children_by_parent
            .entry(parent_share_hash)
            .or_default()
            .insert(share_hash.clone());
        self.resolve_share_and_descendants(&share_hash)?;
        self.share_hash_by_work_hash.insert(work_hash, share_hash);
        Ok(())
    }

    fn resolve_share_and_descendants(
        &mut self,
        share_hash: &str,
    ) -> Result<(), SharechainReplayError> {
        let mut queue = VecDeque::from([share_hash.to_string()]);
        while let Some(candidate_hash) = queue.pop_front() {
            let Some(candidate) = self.shares.get(&candidate_hash) else {
                continue;
            };
            let branch_score = if candidate.parent_share_hash == ZERO_SHARE_PARENT_HASH {
                Some((candidate.share.hashrate_score_delta, 1))
            } else {
                match self.shares.get(&candidate.parent_share_hash) {
                    Some(parent) => match parent.cumulative_score {
                        Some(parent_score) => Some((
                            parent_score
                                .checked_add(candidate.share.hashrate_score_delta)
                                .ok_or_else(|| {
                                    SharechainReplayError::ShareBranchScoreOverflow(
                                        candidate_hash.clone(),
                                    )
                                })?,
                            parent.height.checked_add(1).ok_or_else(|| {
                                SharechainReplayError::ShareBranchScoreOverflow(
                                    candidate_hash.clone(),
                                )
                            })?,
                        )),
                        None => None,
                    },
                    None => None,
                }
            };
            let Some((cumulative_score, height)) = branch_score else {
                continue;
            };
            if height == 0 {
                return Err(SharechainReplayError::ShareBranchScoreOverflow(
                    candidate_hash,
                ));
            }
            if let Some(candidate) = self.shares.get_mut(&candidate_hash) {
                candidate.cumulative_score = Some(cumulative_score);
                candidate.height = height;
            }
            self.consider_resolved_share(&candidate_hash)?;
            if let Some(children) = self.children_by_parent.get(&candidate_hash) {
                queue.extend(children.iter().cloned());
            }
        }
        Ok(())
    }

    fn consider_resolved_share(&mut self, share_hash: &str) -> Result<(), SharechainReplayError> {
        if self.latest_sharechain_checkpoint().is_some() {
            // Post-checkpoint shares remain pending until a later on-chain round
            // finalizes an exact descendant. This keeps uncheckpointed work out
            // of payout accounting even when it has a higher cumulative score.
            return Ok(());
        }
        let node = self
            .shares
            .get(share_hash)
            .expect("resolved share remains in replay state");
        let score = node
            .cumulative_score
            .expect("resolved share has cumulative score");
        let current_tip = self.best_share_tip.as_deref();
        let is_better = match current_tip.and_then(|tip| self.shares.get(tip)) {
            Some(current) => {
                let current_score = current
                    .cumulative_score
                    .expect("best share tip has cumulative score");
                score > current_score
                    || (score == current_score && share_hash < current_tip.unwrap())
            }
            None => true,
        };
        if !is_better {
            return Ok(());
        }

        if current_tip.is_some_and(|tip| node.parent_share_hash == tip)
            && self.active_share_hashes.contains(&node.parent_share_hash)
        {
            let miner_id = node.share.miner_id.to_ascii_lowercase();
            let entry = self.hashrate_scores.entry(miner_id.clone()).or_default();
            *entry = entry
                .checked_add(node.share.hashrate_score_delta)
                .ok_or(SharechainReplayError::HashrateScoreOverflow(miner_id))?;
            self.active_share_score_total = self
                .active_share_score_total
                .checked_add(node.share.hashrate_score_delta)
                .ok_or_else(|| {
                    SharechainReplayError::ShareBranchScoreOverflow(share_hash.to_string())
                })?;
            self.active_share_hashes.insert(share_hash.to_string());
            self.best_share_tip = Some(share_hash.to_string());
            return Ok(());
        }

        self.rebuild_active_branch(share_hash)
    }

    fn share_descends_from(&self, candidate_hash: &str, ancestor_hash: &str) -> bool {
        let mut cursor = Some(candidate_hash.to_ascii_lowercase());
        let ancestor_hash = ancestor_hash.to_ascii_lowercase();
        let mut seen = BTreeSet::new();
        while let Some(share_hash) = cursor {
            if share_hash == ancestor_hash {
                return true;
            }
            if !seen.insert(share_hash.clone()) {
                return false;
            }
            let Some(node) = self.shares.get(&share_hash) else {
                return false;
            };
            if node.parent_share_hash == ZERO_SHARE_PARENT_HASH {
                return false;
            }
            cursor = Some(node.parent_share_hash.clone());
        }
        false
    }

    fn rebuild_active_branch(&mut self, best_share_tip: &str) -> Result<(), SharechainReplayError> {
        let mut active_branch = Vec::new();
        let mut cursor = Some(best_share_tip.to_string());
        let mut seen = BTreeSet::new();
        while let Some(share_hash) = cursor {
            if !seen.insert(share_hash.clone()) {
                break;
            }
            let Some(node) = self.shares.get(&share_hash) else {
                break;
            };
            active_branch.push(share_hash);
            if node.parent_share_hash == ZERO_SHARE_PARENT_HASH {
                break;
            }
            cursor = Some(node.parent_share_hash.clone());
        }

        self.active_share_hashes = active_branch.iter().cloned().collect();
        self.hashrate_scores.clear();
        self.active_share_score_total = 0;
        for share_hash in active_branch {
            let node = self
                .shares
                .get(&share_hash)
                .expect("active branch share remains in replay state");
            let miner_id = node.share.miner_id.to_ascii_lowercase();
            let entry = self.hashrate_scores.entry(miner_id.clone()).or_default();
            *entry = entry
                .checked_add(node.share.hashrate_score_delta)
                .ok_or(SharechainReplayError::HashrateScoreOverflow(miner_id))?;
            self.active_share_score_total = self
                .active_share_score_total
                .checked_add(node.share.hashrate_score_delta)
                .ok_or_else(|| {
                    SharechainReplayError::ShareBranchScoreOverflow(share_hash.clone())
                })?;
        }
        self.best_share_tip = Some(best_share_tip.to_string());
        Ok(())
    }

    pub fn rebuild_derived_share_state(&mut self) -> Result<(), SharechainReplayError> {
        self.share_hash_by_work_hash.clear();
        for (share_hash, node) in &self.shares {
            self.validate_unique_sharechain_root(share_hash, &node.parent_share_hash)?;
            let work_hash = node.share.work_hash.to_ascii_lowercase();
            if let Some(existing_share_hash) = self
                .share_hash_by_work_hash
                .insert(work_hash.clone(), share_hash.clone())
            {
                return Err(SharechainReplayError::DuplicateShareWork {
                    work_hash,
                    existing_share_hash,
                });
            }
        }
        self.children_by_parent.clear();
        for (share_hash, node) in &self.shares {
            self.children_by_parent
                .entry(node.parent_share_hash.clone())
                .or_default()
                .insert(share_hash.clone());
        }
        let mut branch_scores: BTreeMap<String, Option<(Score, u64)>> = BTreeMap::new();
        for share_hash in self.shares.keys() {
            let mut visiting = BTreeSet::new();
            Self::compute_share_branch_score(
                share_hash,
                &self.shares,
                &mut branch_scores,
                &mut visiting,
            )?;
        }

        for node in self.shares.values_mut() {
            node.cumulative_score = None;
            node.height = 0;
        }
        for (share_hash, branch_score) in &branch_scores {
            if let (Some((cumulative_score, height)), Some(node)) =
                (branch_score, self.shares.get_mut(share_hash))
            {
                node.cumulative_score = Some(*cumulative_score);
                node.height = *height;
            }
        }

        self.best_share_tip = branch_scores
            .iter()
            .filter_map(|(share_hash, branch_score)| {
                branch_score.map(|(score, _height)| (share_hash, score))
            })
            .max_by(|(left_hash, left_score), (right_hash, right_score)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| right_hash.cmp(left_hash))
            })
            .map(|(share_hash, _score)| share_hash.clone());

        let mut active_branch = Vec::new();
        if let Some(best_share_tip) = self.best_share_tip.clone() {
            let mut cursor = Some(best_share_tip);
            let mut seen = BTreeSet::new();
            while let Some(share_hash) = cursor {
                if !seen.insert(share_hash.clone()) {
                    break;
                }
                let Some(node) = self.shares.get(&share_hash) else {
                    break;
                };
                active_branch.push(share_hash);
                if node.parent_share_hash == ZERO_SHARE_PARENT_HASH {
                    break;
                }
                cursor = Some(node.parent_share_hash.clone());
            }
        }

        self.active_share_hashes = active_branch.iter().cloned().collect();
        self.hashrate_scores.clear();
        self.active_share_score_total = 0;
        for share_hash in active_branch {
            let Some(node) = self.shares.get(&share_hash) else {
                continue;
            };
            let miner_id = node.share.miner_id.to_ascii_lowercase();
            let entry = self.hashrate_scores.entry(miner_id.clone()).or_default();
            *entry = entry
                .checked_add(node.share.hashrate_score_delta)
                .ok_or(SharechainReplayError::HashrateScoreOverflow(miner_id))?;
            self.active_share_score_total = self
                .active_share_score_total
                .checked_add(node.share.hashrate_score_delta)
                .ok_or_else(|| {
                    SharechainReplayError::ShareBranchScoreOverflow(share_hash.clone())
                })?;
        }

        Ok(())
    }

    fn compute_share_branch_score(
        share_hash: &str,
        shares: &BTreeMap<String, ShareNode>,
        memo: &mut BTreeMap<String, Option<(Score, u64)>>,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<(Score, u64)>, SharechainReplayError> {
        if let Some(cached) = memo.get(share_hash).copied() {
            return Ok(cached);
        }
        if !visiting.insert(share_hash.to_string()) {
            memo.insert(share_hash.to_string(), None);
            return Ok(None);
        }

        let result = if let Some(node) = shares.get(share_hash) {
            if node.parent_share_hash == ZERO_SHARE_PARENT_HASH {
                Some((node.share.hashrate_score_delta, 1))
            } else if shares.contains_key(&node.parent_share_hash) {
                match Self::compute_share_branch_score(
                    &node.parent_share_hash,
                    shares,
                    memo,
                    visiting,
                )? {
                    Some((parent_score, parent_height)) => {
                        let cumulative_score = parent_score
                            .checked_add(node.share.hashrate_score_delta)
                            .ok_or_else(|| {
                                SharechainReplayError::ShareBranchScoreOverflow(
                                    share_hash.to_string(),
                                )
                            })?;
                        let height = parent_height.checked_add(1).ok_or_else(|| {
                            SharechainReplayError::ShareBranchScoreOverflow(share_hash.to_string())
                        })?;
                        Some((cumulative_score, height))
                    }
                    None => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        visiting.remove(share_hash);
        memo.insert(share_hash.to_string(), result);
        Ok(result)
    }

    fn apply_snapshot_vote(&mut self, vote: &SnapshotVote) -> Result<(), SharechainReplayError> {
        let voter_miner_id = vote.voter_miner_id.to_ascii_lowercase();
        let registration = self
            .registrations
            .get(&voter_miner_id)
            .ok_or_else(|| SharechainReplayError::UnknownSnapshotVoter(voter_miner_id.clone()))?;
        vote.verify_mining_signature(&registration.mining_pubkey_hex)?;
        let key = SnapshotVoteKey {
            snapshot_day: vote.snapshot_day.clone(),
            idena_height: vote.idena_height,
            score_root: vote.score_root.to_ascii_lowercase(),
        };
        self.snapshot_votes
            .entry(key)
            .or_default()
            .insert(voter_miner_id);
        Ok(())
    }

    fn apply_payout_schedule_proposal(
        &mut self,
        schedule: &PayoutSchedule,
    ) -> Result<(), SharechainReplayError> {
        self.validate_payout_schedule_bindings(schedule)?;
        let payout_root = schedule.payout_root.to_ascii_lowercase();
        if let Some(existing) = self.proposed_payout_schedules.get(&payout_root) {
            if existing != schedule {
                return Err(SharechainReplayError::ConflictingPayoutSchedule(
                    payout_root,
                ));
            }
            return Ok(());
        }
        self.proposed_payout_schedules
            .insert(payout_root, schedule.clone());
        Ok(())
    }

    fn validate_payout_schedule_bindings(
        &self,
        schedule: &PayoutSchedule,
    ) -> Result<(), SharechainReplayError> {
        schedule.validate()?;
        for output in &schedule.direct_outputs {
            let miner_id = output.miner_id.to_ascii_lowercase();
            let registration = self
                .registrations
                .get(&miner_id)
                .ok_or_else(|| SharechainReplayError::UnknownPayoutMiner(miner_id.clone()))?;
            if output.btc_payout_script_hex.to_ascii_lowercase()
                != registration.btc_payout_script_hex
            {
                return Err(SharechainReplayError::PayoutScriptMismatch { miner_id });
            }
        }
        for allocation in &schedule.vault_allocations {
            let miner_id = allocation.miner_id.to_ascii_lowercase();
            let registration = self
                .registrations
                .get(&miner_id)
                .ok_or_else(|| SharechainReplayError::UnknownPayoutMiner(miner_id.clone()))?;
            if allocation.claim_owner_id.to_ascii_lowercase() != registration.claim_owner_pubkey_hex
            {
                return Err(SharechainReplayError::PayoutClaimOwnerMismatch { miner_id });
            }
        }
        Ok(())
    }

    fn apply_withdrawal_request(
        &mut self,
        request: &WithdrawalRequest,
    ) -> Result<(), SharechainReplayError> {
        request.validate(0)?;
        let request = request.clone().normalized();
        let available_sats = self.claim_ledger.balance(&request.claim_owner_id);
        if request.amount_sats > available_sats {
            return Err(SharechainReplayError::Ledger(
                LedgerError::InsufficientBalance {
                    claim_owner_id: request.claim_owner_id.clone(),
                    requested_sats: request.amount_sats,
                    available_sats,
                },
            ));
        }
        if let Some(existing) = self.withdrawal_requests.get(&request.request_id) {
            if existing != &request {
                return Err(SharechainReplayError::ConflictingWithdrawalRequest(
                    request.request_id,
                ));
            }
            return Ok(());
        }
        self.withdrawal_requests
            .insert(request.request_id.clone(), request);
        Ok(())
    }

    fn apply_withdrawal_batch(
        &mut self,
        batch: &WithdrawalBatch,
    ) -> Result<(), SharechainReplayError> {
        let batch = batch.clone().normalized();
        let batch_hash = batch.batch_hash();
        if let Some(existing) = self.withdrawal_batches.get(&batch_hash) {
            if existing != &batch {
                return Err(SharechainReplayError::ConflictingWithdrawalBatch(
                    batch_hash,
                ));
            }
            return Ok(());
        }
        let ledger = self.claim_ledger_after_withdrawal_batch(&batch, 0)?;
        self.claim_ledger = ledger;
        self.withdrawal_batches.insert(batch_hash, batch);
        Ok(())
    }
}

fn is_valid_registry_registration_upgrade(
    existing: &MinerRegistration,
    candidate: &MinerRegistration,
) -> bool {
    if candidate.version != crate::sharechain::IDENA_ANCHORED_MINER_REGISTRATION_VERSION
        || !existing.miner_id.eq_ignore_ascii_case(&candidate.miner_id)
        || !existing
            .idena_address
            .eq_ignore_ascii_case(&candidate.idena_address)
        || !existing
            .btc_payout_script_hex
            .eq_ignore_ascii_case(&candidate.btc_payout_script_hex)
        || !existing
            .claim_owner_pubkey_hex
            .eq_ignore_ascii_case(&candidate.claim_owner_pubkey_hex)
        || !existing
            .mining_pubkey_hex
            .eq_ignore_ascii_case(&candidate.mining_pubkey_hex)
    {
        return false;
    }
    let Some(candidate_anchor) = candidate.registry_anchor.as_ref() else {
        return false;
    };
    match existing.registry_anchor.as_ref() {
        None => true,
        Some(existing_anchor) => {
            candidate_anchor
                .contract_address
                .eq_ignore_ascii_case(&existing_anchor.contract_address)
                && candidate_anchor
                    .experiment_id
                    .eq_ignore_ascii_case(&existing_anchor.experiment_id)
                && candidate_anchor.registration_sequence > existing_anchor.registration_sequence
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idena_anchor::{IdenaBlockAnchorV1, MinerRegistryAnchorV1};
    use crate::sharechain::{BitcoinWorkTemplate, MinerRegistration, Share, SnapshotVote};
    use crate::withdrawal::{build_withdrawal_batch, WithdrawalOutputKind, WithdrawalRequest};
    use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
    use tiny_keccak::{Hasher, Keccak};

    const MAX_SHARE_TARGET_HEX: &str =
        "7fffff0000000000000000000000000000000000000000000000000000000000";

    fn keypair(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn sign(hash: [u8; 32], keypair: &Keypair) -> String {
        let secp = Secp256k1::new();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
        hex::encode(signature.serialize())
    }

    fn signed_registration_for(
        miner_id: &str,
        mining_key_byte: u8,
        claim_key_byte: u8,
        idena_key_byte: u8,
    ) -> (MinerRegistration, Keypair) {
        let mining_keypair = keypair(mining_key_byte);
        let claim_keypair = keypair(claim_key_byte);
        let idena_secret = SecretKey::from_slice(&[idena_key_byte; 32]).unwrap();
        let idena_address = idena_address_from_pubkey(&PublicKey::from_secret_key(
            &Secp256k1::new(),
            &idena_secret,
        ));
        let mut registration = MinerRegistration {
            version: crate::sharechain::LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: miner_id.to_string(),
            idena_address,
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex = sign(registration.signing_hash(), &mining_keypair);
        (registration, mining_keypair)
    }

    fn signed_registration() -> (MinerRegistration, Keypair) {
        signed_registration_for("Miner-A", 9, 10, 13)
    }

    fn signed_withdrawal_request(
        request_id: &str,
        amount_sats: Sats,
        nonce: u64,
        claim_keypair: &Keypair,
    ) -> WithdrawalRequest {
        let claim_owner_pubkey_hex = claim_keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: request_id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            amount_sats,
            max_fee_rate_sat_vb: 10,
            nonce,
            expiry_height: 100,
            signature_hex: None,
            output_kind: WithdrawalOutputKind::P2tr,
        };
        request.signature_hex = Some(sign(request.signing_hash(), claim_keypair));
        request
    }

    fn test_bitcoin_header_hex(nonce: u32) -> String {
        test_bitcoin_header_hex_with_merkle(nonce, 0x22)
    }

    fn test_bitcoin_header_hex_with_merkle(nonce: u32, merkle_byte: u8) -> String {
        test_bitcoin_header_hex_with_version_and_merkle(nonce, 1, merkle_byte)
    }

    fn test_bitcoin_header_hex_with_version_and_merkle(
        nonce: u32,
        version: u32,
        merkle_byte: u8,
    ) -> String {
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&version.to_le_bytes());
        header[36..68].copy_from_slice(&[merkle_byte; 32]);
        header[68..72].copy_from_slice(&1_231_006_505u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        hex::encode(header)
    }

    fn test_share(
        miner_id: &str,
        target: &str,
        nonce: u32,
        proof_root: &str,
        parent_hash: &str,
    ) -> Share {
        let mut share = Share {
            miner_id: miner_id.to_string(),
            bitcoin_header_hex: test_bitcoin_header_hex(nonce),
            bitcoin_template_hash: String::new(),
            nonce_hex: String::new(),
            work_hash: String::new(),
            target: target.to_string(),
            idena_snapshot_id: "2026-06-30".to_string(),
            idena_snapshot_proof_root: proof_root.to_string(),
            hashrate_score_delta: 1,
            parent_share_hash: parent_hash.to_string(),
            mining_signature_hex: String::new(),
        };
        share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash().unwrap();
        share.nonce_hex = share.recomputed_nonce_hex().unwrap();
        share.work_hash = share.recomputed_work_hash().unwrap();
        share
    }

    fn mined_test_share(
        miner_id: &str,
        target: &str,
        proof_root: &str,
        parent_hash: &str,
    ) -> Share {
        let nonce_seed = sha256_tagged(
            b"POHW_TEST_SHARE_NONCE",
            format!("{miner_id}|{proof_root}|{parent_hash}").as_bytes(),
        );
        let start_nonce =
            u32::from_le_bytes(nonce_seed[..4].try_into().unwrap()) % (u32::MAX - 10_000);
        mined_test_share_from_nonce(miner_id, target, proof_root, parent_hash, start_nonce, 0x22)
    }

    fn mined_test_share_from_nonce(
        miner_id: &str,
        target: &str,
        proof_root: &str,
        parent_hash: &str,
        start_nonce: u32,
        merkle_byte: u8,
    ) -> Share {
        mined_test_share_from_nonce_with_version(
            miner_id,
            target,
            proof_root,
            parent_hash,
            start_nonce,
            merkle_byte,
            1,
        )
    }

    fn mined_test_share_from_nonce_with_version(
        miner_id: &str,
        target: &str,
        proof_root: &str,
        parent_hash: &str,
        start_nonce: u32,
        merkle_byte: u8,
        version: u32,
    ) -> Share {
        for nonce in start_nonce..start_nonce.saturating_add(10_000) {
            let mut share = test_share(miner_id, target, nonce, proof_root, parent_hash);
            share.bitcoin_header_hex =
                test_bitcoin_header_hex_with_version_and_merkle(nonce, version, merkle_byte);
            share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash().unwrap();
            share.work_hash = share.recomputed_work_hash().unwrap();
            if share.work_hash <= target.to_ascii_lowercase() {
                return share;
            }
        }
        panic!("test target did not yield a valid share quickly");
    }

    fn signed_work_template(share: &Share, keypair: &Keypair) -> BitcoinWorkTemplate {
        let mut template = BitcoinWorkTemplate::new_unsigned(
            share.miner_id.clone(),
            share.bitcoin_header_prefix_hex().unwrap(),
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign(template.signing_hash(), keypair);
        template
    }

    fn signed_target_bound_work_template(share: &Share, keypair: &Keypair) -> BitcoinWorkTemplate {
        let mut template = BitcoinWorkTemplate::new_target_bound_unsigned(
            share.miner_id.clone(),
            share.bitcoin_header_prefix_hex().unwrap(),
            share.target.clone(),
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign(template.signing_hash(), keypair);
        template
    }

    fn anchor_policy() -> IdenaAnchorPolicyV2 {
        IdenaAnchorPolicyV2 {
            schema_version: 2,
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registry_contract_address: format!("0x{}", "21".repeat(20)),
            registry_deployment_tx_hash: format!("0x{}", "22".repeat(32)),
            registry_deployment_payload_sha256: "23".repeat(32),
            registry_contract_code_hash: "25".repeat(32),
            registry_contract_wasm_sha256: "24".repeat(32),
            registry_ecosystem_cid: "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
                .to_string(),
            minimum_registration_burn_atoms: "1000".to_string(),
            activation_idena_height: 90,
            finality_confirmations: 2,
            max_anchor_age_blocks: 4,
            handoff_version_bit: 27,
        }
    }

    fn anchored_registration(
        registration: MinerRegistration,
        mining_keypair: &Keypair,
        idena_key_byte: u8,
        sequence: u32,
        registration_block: u64,
    ) -> MinerRegistration {
        let commitment = registration
            .registry_commitment_hash("p2poolbtc-experiment-1")
            .unwrap();
        let mut registration = registration
            .attach_registry_anchor(MinerRegistryAnchorV1 {
                contract_address: format!("0x{}", "21".repeat(20)),
                experiment_id: "p2poolbtc-experiment-1".to_string(),
                registration_sequence: sequence,
                registration_block,
                registration_epoch: 7,
                registration_timestamp: 1_700_000_000,
                registration_commitment: commitment,
            })
            .unwrap();
        let idena_secret = SecretKey::from_slice(&[idena_key_byte; 32]).unwrap();
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex = sign(registration.signing_hash(), mining_keypair);
        registration
    }

    fn signed_anchored_work_template(
        share: &mut Share,
        keypair: &Keypair,
        policy: &IdenaAnchorPolicyV2,
        anchor_height: u64,
        anchor_byte: u8,
    ) -> BitcoinWorkTemplate {
        let anchor = IdenaBlockAnchorV1 {
            height: anchor_height,
            hash: format!("0x{}", format!("{anchor_byte:02x}").repeat(32)),
        };
        let policy_hash = policy.commitment_hash().unwrap();
        share.bitcoin_template_hash = share
            .recomputed_idena_anchored_bitcoin_template_hash(&anchor, &policy_hash)
            .unwrap();
        share.mining_signature_hex = sign(share.signing_hash(), keypair);
        let mut template = BitcoinWorkTemplate::new_idena_anchored_target_bound_unsigned(
            share.miner_id.clone(),
            share.bitcoin_header_prefix_hex().unwrap(),
            share.target.clone(),
            anchor,
            policy_hash,
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign(template.signing_hash(), keypair);
        template
    }

    fn apply_anchored_template(
        state: &mut SharechainReplayState,
        template: BitcoinWorkTemplate,
        policy: &IdenaAnchorPolicyV2,
    ) {
        let message = SharechainMessage::BitcoinWorkTemplate(template.clone());
        state
            .validate_idena_anchor_policy(&message, policy)
            .unwrap();
        state.accept_bitcoin_work_template(&template).unwrap();
        state.apply_message(&message).unwrap();
    }

    fn assert_distinct_second_root_rejected(version: u32) {
        let (legacy, mining_keypair) = signed_registration();
        let registration = anchored_registration(legacy, &mining_keypair, 13, 1, 100);
        let policy = anchor_policy();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();

        let mut first = mined_test_share_from_nonce_with_version(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"81".repeat(32),
            ZERO_SHARE_PARENT_HASH,
            1,
            0x71,
            version,
        );
        let first_template =
            signed_anchored_work_template(&mut first, &mining_keypair, &policy, 101, 0x51);
        apply_anchored_template(&mut state, first_template, &policy);
        let first_message = SharechainMessage::Share(first.clone());
        state
            .validate_idena_anchor_policy(&first_message, &policy)
            .unwrap();
        assert_eq!(
            state.apply_message(&first_message).unwrap(),
            ApplyOutcome::Applied
        );
        let first_hash = first.share_hash();
        assert_eq!(state.best_share_tip(), Some(first_hash.as_str()));

        let mut second = mined_test_share_from_nonce_with_version(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"82".repeat(32),
            ZERO_SHARE_PARENT_HASH,
            2,
            0x72,
            version,
        );
        let second_template =
            signed_anchored_work_template(&mut second, &mining_keypair, &policy, 102, 0x52);
        apply_anchored_template(&mut state, second_template, &policy);
        let second_hash = second.share_hash();
        let second_message = SharechainMessage::Share(second);

        let admission_err = state
            .validate_idena_anchor_policy(&second_message, &policy)
            .unwrap_err();
        assert!(matches!(
            admission_err,
            SharechainReplayError::AdditionalSharechainRoot {
                existing_share_hash,
                candidate_share_hash,
            } if existing_share_hash == first_hash && candidate_share_hash == second_hash
        ));
        let replay_err = state.apply_message(&second_message).unwrap_err();
        assert!(matches!(
            replay_err,
            SharechainReplayError::AdditionalSharechainRoot {
                existing_share_hash,
                candidate_share_hash,
            } if existing_share_hash == first_hash && candidate_share_hash == second_hash
        ));
        assert_eq!(state.summary().stored_share_count, 1);
        assert_eq!(state.best_share_tip(), Some(first_hash.as_str()));
    }

    fn signed_snapshot_vote(miner_id: &str, keypair: &Keypair) -> SnapshotVote {
        let mut vote = SnapshotVote {
            voter_miner_id: miner_id.to_string(),
            snapshot_day: "2026-07-13".to_string(),
            idena_height: 1_000,
            score_root: "44".repeat(32),
            signature_hex: String::new(),
        };
        vote.signature_hex = sign(vote.signing_hash(), keypair);
        vote
    }

    fn apply_registration_and_template(
        state: &mut SharechainReplayState,
        registration: MinerRegistration,
        share: &Share,
        keypair: &Keypair,
    ) {
        let template = signed_work_template(share, keypair);
        state
            .accept_bitcoin_work_template_prefix(&template.header_prefix_hex)
            .unwrap();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();
        state
            .apply_message(&SharechainMessage::BitcoinWorkTemplate(template))
            .unwrap();
    }

    fn idena_signature(challenge: &str, secret_key: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let message = Message::from_digest(idena_signin_hash(challenge));
        let signature = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        hex::encode(bytes)
    }

    fn idena_signin_hash(challenge: &str) -> [u8; 32] {
        keccak256(&keccak256(challenge.as_bytes()))
    }

    fn idena_address_from_pubkey(pubkey: &PublicKey) -> String {
        let serialized = pubkey.serialize_uncompressed();
        let hash = keccak256(&serialized[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }

    #[test]
    fn replay_applies_registration_and_share_once() {
        let (registration, mining_keypair) = signed_registration();
        let mut share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        share.mining_signature_hex = sign(share.signing_hash(), &mining_keypair);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &share, &mining_keypair);
        let share_message = SharechainMessage::Share(share);
        assert_eq!(
            state.apply_message(&share_message).unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(
            state.apply_message(&share_message).unwrap(),
            ApplyOutcome::DuplicateIgnored
        );

        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&1));
        let accounts = state.participant_accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].hashrate_score, 1);
    }

    #[test]
    fn replay_counts_distinct_active_idena_identities_not_miner_ids() {
        let (registration_a, mining_keypair_a) = signed_registration_for("Miner-A", 9, 10, 13);
        let mut share_a = mined_test_share(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        share_a.mining_signature_hex = sign(share_a.signing_hash(), &mining_keypair_a);

        let (registration_b, mining_keypair_b) = signed_registration_for("Miner-B", 14, 15, 13);
        let mut share_b = mined_test_share_from_nonce(
            "Miner-B",
            MAX_SHARE_TARGET_HEX,
            &"22".repeat(32),
            &share_a.share_hash(),
            100,
            0x23,
        );
        share_b.mining_signature_hex = sign(share_b.signing_hash(), &mining_keypair_b);

        let (registration_c, _) = signed_registration_for("Miner-C", 16, 17, 18);
        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration_a, &share_a, &mining_keypair_a);
        state
            .apply_message(&SharechainMessage::Share(share_a))
            .unwrap();
        apply_registration_and_template(&mut state, registration_b, &share_b, &mining_keypair_b);
        state
            .apply_message(&SharechainMessage::Share(share_b))
            .unwrap();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration_c))
            .unwrap();

        let summary = state.summary();
        assert_eq!(summary.registered_miner_count, 3);
        assert_eq!(summary.unique_registered_idena_count, 2);
        assert_eq!(summary.active_idena_participant_count, 1);
    }

    #[test]
    fn snapshot_voter_quorum_counts_distinct_idena_identities() {
        let (registration_a, mining_keypair_a) = signed_registration_for("Miner-A", 9, 10, 13);
        let (registration_b, mining_keypair_b) = signed_registration_for("Miner-B", 14, 15, 13);
        let (registration_c, mining_keypair_c) = signed_registration_for("Miner-C", 16, 17, 18);
        let mut state = SharechainReplayState::default();
        for registration in [registration_a, registration_b, registration_c] {
            state
                .apply_message(&SharechainMessage::MinerRegistration(registration))
                .unwrap();
        }
        for vote in [
            signed_snapshot_vote("Miner-A", &mining_keypair_a),
            signed_snapshot_vote("Miner-B", &mining_keypair_b),
            signed_snapshot_vote("Miner-C", &mining_keypair_c),
        ] {
            state
                .apply_message(&SharechainMessage::SnapshotVote(vote))
                .unwrap();
        }

        assert_eq!(
            state.unique_snapshot_voter_idena_count("2026-07-13", 1_000, &"44".repeat(32)),
            2
        );
        let state_root = state.accounting_state_root();
        assert_eq!(state_root.len(), 64);
        assert_eq!(state.accounting_state_root(), state_root);
    }

    #[test]
    fn target_bound_template_rejects_post_selected_share_target() {
        let (registration, mining_keypair) = signed_registration();
        let mut share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"ab".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        share.bitcoin_template_hash = share
            .recomputed_target_bound_bitcoin_template_hash()
            .unwrap();
        share.mining_signature_hex = sign(share.signing_hash(), &mining_keypair);
        let template = signed_target_bound_work_template(&share, &mining_keypair);

        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();
        state.accept_bitcoin_work_template(&template).unwrap();
        state
            .apply_message(&SharechainMessage::BitcoinWorkTemplate(template.clone()))
            .unwrap();
        state
            .validate_target_bound_message(&SharechainMessage::Share(share.clone()))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(share.clone()))
            .unwrap();

        let harder_target = "3fffff0000000000000000000000000000000000000000000000000000000000";
        let mut post_selected = share;
        post_selected.target = harder_target.to_string();
        post_selected.hashrate_score_delta =
            Share::expected_hashrate_score_delta_for_target(harder_target).unwrap();
        post_selected.mining_signature_hex = sign(post_selected.signing_hash(), &mining_keypair);
        let admission_err = state
            .validate_target_bound_message(&SharechainMessage::Share(post_selected.clone()))
            .unwrap_err();
        assert!(matches!(
            admission_err,
            SharechainReplayError::InvalidSharechainSignature(
                SharechainError::AssignedShareTargetMismatch { .. }
            )
        ));
        let err = state
            .apply_message(&SharechainMessage::Share(post_selected))
            .unwrap_err();
        assert!(matches!(
            err,
            SharechainReplayError::InvalidSharechainSignature(
                SharechainError::AssignedShareTargetMismatch { .. }
            )
        ));
    }

    #[test]
    fn anchored_registration_upgrades_legacy_without_changing_miner_keys() {
        let (legacy, mining_keypair) = signed_registration();
        let legacy_for_conflict = legacy.clone();
        let anchored = anchored_registration(legacy.clone(), &mining_keypair, 13, 1, 100);
        let policy = anchor_policy();
        let mut state = SharechainReplayState::default();

        state
            .apply_message(&SharechainMessage::MinerRegistration(legacy))
            .unwrap();
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::MinerRegistration(anchored.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::MinerRegistration(anchored.clone()))
            .unwrap();
        assert_eq!(
            state
                .registrations()
                .get("miner-a")
                .unwrap()
                .registry_anchor
                .as_ref()
                .unwrap()
                .registration_sequence,
            1
        );

        let changed_mining_keypair = keypair(42);
        let mut changed_base = legacy_for_conflict;
        changed_base.mining_pubkey_hex = changed_mining_keypair.x_only_public_key().0.to_string();
        let changed_key = anchored_registration(changed_base, &changed_mining_keypair, 13, 2, 101);
        assert!(matches!(
            state.apply_message(&SharechainMessage::MinerRegistration(changed_key)),
            Err(SharechainReplayError::ConflictingRegistration(_))
        ));
    }

    #[test]
    fn anchored_policy_rejects_templates_before_registry_registration() {
        let (legacy, mining_keypair) = signed_registration();
        let registration = anchored_registration(legacy, &mining_keypair, 13, 1, 100);
        let policy = anchor_policy();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();
        let mut share = mined_test_share(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"71".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        let template =
            signed_anchored_work_template(&mut share, &mining_keypair, &policy, 99, 0x31);

        assert!(matches!(
            state.validate_idena_anchor_policy(
                &SharechainMessage::BitcoinWorkTemplate(template),
                &policy,
            ),
            Err(SharechainReplayError::TemplateAnchorBeforeRegistration)
        ));
    }

    #[test]
    fn finalized_checkpoint_prevents_non_descendant_score_takeover() {
        let (legacy, mining_keypair) = signed_registration();
        let registration = anchored_registration(legacy, &mining_keypair, 13, 1, 100);
        let policy = anchor_policy();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();

        let mut checkpoint_root = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"61".repeat(32),
            ZERO_SHARE_PARENT_HASH,
            1,
            0x61,
        );
        let template = signed_anchored_work_template(
            &mut checkpoint_root,
            &mining_keypair,
            &policy,
            101,
            0x41,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(checkpoint_root.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(checkpoint_root.clone()))
            .unwrap();
        let checkpoint_root_hash = checkpoint_root.share_hash();

        let mut checkpoint_branch = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"62".repeat(32),
            &checkpoint_root_hash,
            2,
            0x62,
        );
        let template = signed_anchored_work_template(
            &mut checkpoint_branch,
            &mining_keypair,
            &policy,
            102,
            0x42,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(checkpoint_branch.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(checkpoint_branch.clone()))
            .unwrap();
        let checkpoint_branch_hash = checkpoint_branch.share_hash();

        let mut competing_branch = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"63".repeat(32),
            &checkpoint_root_hash,
            3,
            0x63,
        );
        let template = signed_anchored_work_template(
            &mut competing_branch,
            &mining_keypair,
            &policy,
            103,
            0x43,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(competing_branch.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(competing_branch.clone()))
            .unwrap();
        let competing_branch_hash = competing_branch.share_hash();

        let mut competing_child = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"64".repeat(32),
            &competing_branch_hash,
            4,
            0x64,
        );
        let template = signed_anchored_work_template(
            &mut competing_child,
            &mining_keypair,
            &policy,
            104,
            0x44,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(competing_child.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(competing_child.clone()))
            .unwrap();
        let competing_child_hash = competing_child.share_hash();
        assert_eq!(state.best_share_tip(), Some(competing_child_hash.as_str()));

        let checkpoint_summary = state.share_summary(&checkpoint_branch_hash).unwrap();
        let checkpoint = SharechainCheckpointAnchorV1 {
            contract_address: policy.registry_contract_address.clone(),
            experiment_id: policy.experiment_id.clone(),
            round: 1,
            share_tip_hash: checkpoint_branch_hash.clone(),
            share_height: checkpoint_summary.height,
            cumulative_score: checkpoint_summary.cumulative_score.unwrap(),
            parent_checkpoint_tip: ZERO_SHARE_PARENT_HASH.to_string(),
            finalization_block: 110,
            finalization_block_hash: format!("0x{}", "51".repeat(32)),
            finalization_epoch: 8,
            finalization_timestamp: 1_700_000_100,
            support_count: 1,
            registered_count: 1,
            registered_miners: vec!["miner-a".to_string()],
            supporters: vec!["miner-a".to_string()],
        };
        let checkpoint_message = SharechainMessage::SharechainCheckpoint(checkpoint);
        state
            .validate_idena_anchor_policy(&checkpoint_message, &policy)
            .unwrap();
        state.apply_message(&checkpoint_message).unwrap();
        assert_eq!(
            state.best_share_tip(),
            Some(checkpoint_branch_hash.as_str())
        );

        let mut fabricated_extension = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"65".repeat(32),
            &competing_child_hash,
            5,
            0x65,
        );
        let template = signed_anchored_work_template(
            &mut fabricated_extension,
            &mining_keypair,
            &policy,
            105,
            0x45,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(fabricated_extension.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(fabricated_extension))
            .unwrap();
        assert_eq!(
            state.best_share_tip(),
            Some(checkpoint_branch_hash.as_str())
        );

        let mut checkpoint_child = mined_test_share_from_nonce(
            "miner-a",
            MAX_SHARE_TARGET_HEX,
            &"66".repeat(32),
            &checkpoint_branch_hash,
            6,
            0x66,
        );
        let template = signed_anchored_work_template(
            &mut checkpoint_child,
            &mining_keypair,
            &policy,
            106,
            0x46,
        );
        apply_anchored_template(&mut state, template, &policy);
        state
            .validate_idena_anchor_policy(
                &SharechainMessage::Share(checkpoint_child.clone()),
                &policy,
            )
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(checkpoint_child.clone()))
            .unwrap();
        let checkpoint_child_hash = checkpoint_child.share_hash();
        assert_eq!(
            state.best_share_tip(),
            Some(checkpoint_branch_hash.as_str())
        );

        let checkpoint_child_summary = state.share_summary(&checkpoint_child_hash).unwrap();
        let checkpoint_two = SharechainCheckpointAnchorV1 {
            contract_address: policy.registry_contract_address.clone(),
            experiment_id: policy.experiment_id.clone(),
            round: 2,
            share_tip_hash: checkpoint_child_hash.clone(),
            share_height: checkpoint_child_summary.height,
            cumulative_score: checkpoint_child_summary.cumulative_score.unwrap(),
            parent_checkpoint_tip: checkpoint_branch_hash,
            finalization_block: 116,
            finalization_block_hash: format!("0x{}", "52".repeat(32)),
            finalization_epoch: 8,
            finalization_timestamp: 1_700_000_160,
            support_count: 1,
            registered_count: 1,
            registered_miners: vec!["miner-a".to_string()],
            supporters: vec!["miner-a".to_string()],
        };
        let checkpoint_two_message = SharechainMessage::SharechainCheckpoint(checkpoint_two);
        state
            .validate_idena_anchor_policy(&checkpoint_two_message, &policy)
            .unwrap();
        state.apply_message(&checkpoint_two_message).unwrap();
        assert_eq!(state.best_share_tip(), Some(checkpoint_child_hash.as_str()));
        assert_eq!(state.summary().latest_checkpoint_round, Some(2));
    }

    #[test]
    fn bootstrap_rejects_distinct_second_zero_parent_share() {
        let policy = anchor_policy();
        let version = 1;
        assert!(policy.bootstrap_limits_active(version));
        assert_distinct_second_root_rejected(version);
    }

    #[test]
    fn post_handoff_rejects_distinct_second_zero_parent_share() {
        let policy = anchor_policy();
        let version = 1 | (1 << policy.handoff_version_bit);
        assert!(!policy.bootstrap_limits_active(version));
        assert_distinct_second_root_rejected(version);
    }

    #[test]
    fn bootstrap_shares_require_unique_and_increasing_idena_anchors() {
        let (legacy, mining_keypair) = signed_registration();
        let registration = anchored_registration(legacy, &mining_keypair, 13, 1, 100);
        let policy = anchor_policy();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();

        let mut first = mined_test_share(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"72".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        let first_template =
            signed_anchored_work_template(&mut first, &mining_keypair, &policy, 101, 0x32);
        let mut mismatched_policy = policy.clone();
        mismatched_policy.max_anchor_age_blocks += 1;
        assert!(matches!(
            state.validate_idena_anchor_policy(
                &SharechainMessage::BitcoinWorkTemplate(first_template.clone()),
                &mismatched_policy,
            ),
            Err(SharechainReplayError::IdenaAnchorPolicy(
                IdenaAnchorError::PolicyCommitmentMismatch
            ))
        ));
        apply_anchored_template(&mut state, first_template, &policy);
        state
            .validate_idena_anchor_policy(&SharechainMessage::Share(first.clone()), &policy)
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(first.clone()))
            .unwrap();

        // The old V1 policy selected bootstrap checks by target. A target one
        // unit below the configured floor was effectively just as cheap but
        // skipped duplicate-anchor enforcement entirely.
        let target_below_old_floor = format!("7ffffe{}", "ff".repeat(29));
        let mut duplicate = mined_test_share_from_nonce(
            "Miner-A",
            &target_below_old_floor,
            &"73".repeat(32),
            &first.share_hash(),
            100,
            0x33,
        );
        let duplicate_template =
            signed_anchored_work_template(&mut duplicate, &mining_keypair, &policy, 101, 0x32);
        apply_anchored_template(&mut state, duplicate_template, &policy);
        assert!(matches!(
            state.validate_idena_anchor_policy(&SharechainMessage::Share(duplicate), &policy,),
            Err(SharechainReplayError::DuplicateBootstrapAnchor { .. })
        ));

        let mut backwards = mined_test_share_from_nonce(
            "Miner-A",
            MAX_SHARE_TARGET_HEX,
            &"74".repeat(32),
            &first.share_hash(),
            200,
            0x34,
        );
        let backwards_template =
            signed_anchored_work_template(&mut backwards, &mining_keypair, &policy, 100, 0x35);
        apply_anchored_template(&mut state, backwards_template, &policy);
        assert!(matches!(
            state.validate_idena_anchor_policy(&SharechainMessage::Share(backwards), &policy,),
            Err(SharechainReplayError::NonIncreasingBootstrapAnchor)
        ));
    }

    #[test]
    fn network_bound_policy_rejects_legacy_template_without_rewriting_replay() {
        let (registration, mining_keypair) = signed_registration();
        let share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"ac".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        let template = signed_work_template(&share, &mining_keypair);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();
        state.accept_bitcoin_work_template(&template).unwrap();

        let message = SharechainMessage::BitcoinWorkTemplate(template.clone());
        assert!(matches!(
            state.validate_target_bound_message(&message),
            Err(SharechainReplayError::InvalidSharechainSignature(
                SharechainError::TargetBoundBitcoinWorkTemplateRequired
            ))
        ));
        state.apply_message(&message).unwrap();
    }

    #[test]
    fn replay_ignores_duplicate_share_with_different_hex_casing() {
        let (registration, mining_keypair) = signed_registration();
        let mut share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"bb".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        share.mining_signature_hex = sign(share.signing_hash(), &mining_keypair);

        let mut alternate = share.clone();
        alternate.miner_id = alternate.miner_id.to_ascii_lowercase();
        alternate.bitcoin_header_hex = alternate.bitcoin_header_hex.to_ascii_uppercase();
        alternate.bitcoin_template_hash = alternate.bitcoin_template_hash.to_ascii_uppercase();
        alternate.nonce_hex = alternate.nonce_hex.to_ascii_uppercase();
        alternate.work_hash = alternate.work_hash.to_ascii_uppercase();
        alternate.target = alternate.target.to_ascii_uppercase();
        alternate.idena_snapshot_proof_root =
            alternate.idena_snapshot_proof_root.to_ascii_uppercase();
        alternate.parent_share_hash = alternate.parent_share_hash.to_ascii_uppercase();
        alternate.mining_signature_hex = alternate.mining_signature_hex.to_ascii_uppercase();

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &share, &mining_keypair);
        assert_eq!(
            state
                .apply_message(&SharechainMessage::Share(share))
                .unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(
            state
                .apply_message(&SharechainMessage::Share(alternate))
                .unwrap(),
            ApplyOutcome::DuplicateIgnored
        );

        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&1));
    }

    #[test]
    fn replay_rejects_recrediting_the_same_bitcoin_work_hash() {
        let (registration, mining_keypair) = signed_registration();
        let mut first = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"bb".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        first.mining_signature_hex = sign(first.signing_hash(), &mining_keypair);

        let mut replay = first.clone();
        replay.idena_snapshot_proof_root = "cc".repeat(32);
        replay.mining_signature_hex = sign(replay.signing_hash(), &mining_keypair);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &first, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(first.clone()))
            .unwrap();

        let err = state
            .apply_message(&SharechainMessage::Share(replay))
            .unwrap_err();
        assert!(matches!(
            err,
            SharechainReplayError::DuplicateShareWork {
                work_hash,
                existing_share_hash,
            } if work_hash == first.work_hash && existing_share_hash == first.share_hash()
        ));
        assert_eq!(state.summary().stored_share_count, 1);
        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&1));
    }

    #[test]
    fn fork_choice_counts_only_best_cumulative_branch() {
        let (registration, mining_keypair) = signed_registration();
        let mut root = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root.mining_signature_hex = sign(root.signing_hash(), &mining_keypair);
        let root_hash = root.share_hash();
        let mut child_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"12".repeat(32),
            &root_hash,
        );
        child_a.mining_signature_hex = sign(child_a.signing_hash(), &mining_keypair);
        let child_a_hash = child_a.share_hash();
        let mut grandchild_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"13".repeat(32),
            &child_a_hash,
        );
        grandchild_a.mining_signature_hex = sign(grandchild_a.signing_hash(), &mining_keypair);
        let grandchild_a_hash = grandchild_a.share_hash();
        let mut child_b = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"22".repeat(32),
            &root_hash,
        );
        child_b.mining_signature_hex = sign(child_b.signing_hash(), &mining_keypair);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &root, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(child_b))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(root))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(child_a))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(grandchild_a))
            .unwrap();

        let summary = state.summary();
        assert_eq!(summary.stored_share_count, 4);
        assert_eq!(summary.active_share_count, 3);
        assert_eq!(summary.inactive_share_count, 1);
        assert_eq!(summary.active_share_score_total, 3);
        assert_eq!(
            summary.best_share_tip.as_deref(),
            Some(grandchild_a_hash.as_str())
        );
        assert_eq!(state.best_share_height(), Some(3));
        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&3));

        let shares = state.share_summaries();
        assert_eq!(shares.len(), 4);
        assert_eq!(shares[0].share_hash, grandchild_a_hash);
        assert_eq!(shares[0].height, 3);
        assert!(shares[0].active);
        assert_eq!(shares[0].hashrate_score_delta, "1");
        assert_eq!(shares[0].cumulative_score.as_deref(), Some("3"));
        assert!(shares[0].template_created_at_unix.is_some());
        let template_time = shares[0].template_created_at_unix.unwrap();
        assert_eq!(state.recent_active_idena_addresses(template_time).len(), 1);
        assert!(state
            .recent_active_idena_addresses(template_time.saturating_add(1))
            .is_empty());
        assert_eq!(
            state
                .share_summary(&shares[0].share_hash.to_ascii_uppercase())
                .as_ref()
                .map(|share| share.share_hash.as_str()),
            Some(shares[0].share_hash.as_str())
        );
    }

    #[test]
    fn orphan_share_becomes_active_when_parent_arrives() {
        let (registration, mining_keypair) = signed_registration();
        let mut parent = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        parent.mining_signature_hex = sign(parent.signing_hash(), &mining_keypair);
        let parent_hash = parent.share_hash();
        let mut child = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"12".repeat(32),
            &parent_hash,
        );
        child.mining_signature_hex = sign(child.signing_hash(), &mining_keypair);
        let child_hash = child.share_hash();

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &parent, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(child))
            .unwrap();
        assert_eq!(state.summary().stored_share_count, 1);
        assert_eq!(state.summary().active_share_count, 0);
        assert_eq!(state.hashrate_scores().get("miner-a"), None);
        assert_eq!(state.best_share_tip(), None);

        state
            .apply_message(&SharechainMessage::Share(parent))
            .unwrap();
        let summary = state.summary();
        assert_eq!(summary.stored_share_count, 2);
        assert_eq!(summary.active_share_count, 2);
        assert_eq!(summary.inactive_share_count, 0);
        assert_eq!(summary.active_share_score_total, 2);
        assert_eq!(summary.best_share_tip.as_deref(), Some(child_hash.as_str()));
        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&2));
    }

    #[test]
    fn fork_choice_tie_breaks_by_share_hash_not_arrival_order() {
        let (registration, mining_keypair) = signed_registration();
        let mut root = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root.mining_signature_hex = sign(root.signing_hash(), &mining_keypair);
        let root_hash = root.share_hash();
        let mut child_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"12".repeat(32),
            &root_hash,
        );
        child_a.mining_signature_hex = sign(child_a.signing_hash(), &mining_keypair);
        let child_a_hash = child_a.share_hash();
        let mut child_b = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"22".repeat(32),
            &root_hash,
        );
        child_b.mining_signature_hex = sign(child_b.signing_hash(), &mining_keypair);
        let child_b_hash = child_b.share_hash();
        let expected_tip = child_a_hash.min(child_b_hash);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &root, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(root))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(child_b))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(child_a))
            .unwrap();

        let summary = state.summary();
        assert_eq!(summary.active_share_count, 2);
        assert_eq!(summary.inactive_share_count, 1);
        assert_eq!(
            summary.best_share_tip.as_deref(),
            Some(expected_tip.as_str())
        );
    }

    #[test]
    fn bitcoin_work_template_must_be_locally_accepted() {
        let (registration, mining_keypair) = signed_registration();
        let share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"bb".repeat(32),
            &"cc".repeat(32),
        );
        let template = signed_work_template(&share, &mining_keypair);

        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();

        assert_eq!(
            state.apply_message(&SharechainMessage::BitcoinWorkTemplate(template)),
            Err(SharechainReplayError::UnacceptedBitcoinWorkTemplate(
                share.bitcoin_template_hash
            ))
        );
    }

    #[test]
    fn share_requires_published_accepted_bitcoin_work_template() {
        let (registration, mining_keypair) = signed_registration();
        let mut share = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"bb".repeat(32),
            &"cc".repeat(32),
        );
        share.mining_signature_hex = sign(share.signing_hash(), &mining_keypair);

        let mut state = SharechainReplayState::default();
        state
            .accept_bitcoin_work_template_prefix(&share.bitcoin_header_prefix_hex().unwrap())
            .unwrap();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();

        assert_eq!(
            state.apply_message(&SharechainMessage::Share(share.clone())),
            Err(SharechainReplayError::UnknownShareBitcoinWorkTemplate(
                share.bitcoin_template_hash
            ))
        );
    }

    #[test]
    fn payout_proposal_does_not_credit_claims_until_confirmed() {
        let (registration, _) = signed_registration();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut schedule = PayoutSchedule {
            direct_outputs: vec![],
            vault_allocations: vec![crate::payout::VaultAllocation {
                miner_id: registration.miner_id,
                claim_owner_id: registration.claim_owner_pubkey_hex.clone(),
                amount_sats: 20_000,
            }],
            vault_output_sats: 20_000,
            payout_root: String::new(),
        };
        schedule.payout_root = schedule.expected_payout_root();

        state
            .apply_message(&SharechainMessage::PayoutSchedule(schedule.clone()))
            .unwrap();
        assert_eq!(
            state
                .claim_ledger()
                .balance(&registration.claim_owner_pubkey_hex),
            0
        );

        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let schedule = state
            .expected_payout_schedule(&accounts, 20_000, 0, 10_000)
            .unwrap();
        state
            .apply_confirmed_payout_schedule(&schedule, &accounts, 20_000, 0, 10_000)
            .unwrap();
        assert_eq!(
            state
                .claim_ledger()
                .balance(&registration.claim_owner_pubkey_hex),
            20_000
        );
    }

    #[test]
    fn confirmed_payout_rejects_wrong_claim_owner() {
        let (registration, _) = signed_registration();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut schedule = PayoutSchedule {
            direct_outputs: vec![],
            vault_allocations: vec![crate::payout::VaultAllocation {
                miner_id: registration.miner_id,
                claim_owner_id: keypair(20).x_only_public_key().0.to_string(),
                amount_sats: 20_000,
            }],
            vault_output_sats: 20_000,
            payout_root: String::new(),
        };
        schedule.payout_root = schedule.expected_payout_root();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;

        assert!(matches!(
            state.apply_confirmed_payout_schedule(&schedule, &accounts, 20_000, 0, 10_000),
            Err(SharechainReplayError::PayoutClaimOwnerMismatch { .. })
        ));
    }

    #[test]
    fn withdrawal_request_requires_confirmed_claim_balance() {
        let (registration, _) = signed_registration();
        let claim_keypair = keypair(10);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration))
            .unwrap();
        let request = signed_withdrawal_request("req-1", 20_000, 1, &claim_keypair);

        let err = state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap_err();

        assert!(matches!(
            err,
            SharechainReplayError::Ledger(LedgerError::InsufficientBalance {
                claim_owner_id,
                requested_sats: 20_000,
                available_sats: 0,
            }) if claim_owner_id == request.claim_owner_id
        ));
        assert!(!state.withdrawal_requests().contains_key("req-1"));
    }

    #[test]
    fn withdrawal_request_cannot_exceed_confirmed_claim_balance() {
        let (registration, _) = signed_registration();
        let claim_keypair = keypair(10);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let schedule = state
            .expected_payout_schedule(&accounts, 20_000, 0, 10_000)
            .unwrap();
        state
            .apply_confirmed_payout_schedule(&schedule, &accounts, 20_000, 0, 10_000)
            .unwrap();
        let request = signed_withdrawal_request("req-1", 30_000, 1, &claim_keypair);

        let err = state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap_err();

        assert!(matches!(
            err,
            SharechainReplayError::Ledger(LedgerError::InsufficientBalance {
                claim_owner_id,
                requested_sats: 30_000,
                available_sats: 20_000,
            }) if claim_owner_id == request.claim_owner_id
        ));
        assert!(!state.withdrawal_requests().contains_key("req-1"));
    }

    #[test]
    fn withdrawal_batch_reservation_debits_confirmed_claims() {
        let (registration, _) = signed_registration();
        let claim_keypair = keypair(10);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let schedule = state
            .expected_payout_schedule(&accounts, 50_000, 0, 10_000)
            .unwrap();
        state
            .apply_confirmed_payout_schedule(&schedule, &accounts, 50_000, 0, 10_000)
            .unwrap();
        let request = signed_withdrawal_request("req-1", 20_000, 1, &claim_keypair);
        state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap();
        let batch = build_withdrawal_batch(vec![request.clone()], 1, 1, 1).unwrap();

        let ledger = state
            .claim_ledger_after_withdrawal_batch(&batch, 1)
            .unwrap();

        assert_eq!(ledger.balance(&request.claim_owner_id), 30_000);
    }

    #[test]
    fn withdrawal_batch_message_reserves_claims_in_replay() {
        let (registration, _) = signed_registration();
        let claim_keypair = keypair(10);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let schedule = state
            .expected_payout_schedule(&accounts, 50_000, 0, 10_000)
            .unwrap();
        state
            .apply_confirmed_payout_schedule(&schedule, &accounts, 50_000, 0, 10_000)
            .unwrap();
        let request = signed_withdrawal_request("req-1", 20_000, 1, &claim_keypair);
        state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap();
        let batch = build_withdrawal_batch(vec![request.clone()], 1, 1, 1).unwrap();
        let batch_hash = batch.batch_hash();

        state
            .apply_message(&SharechainMessage::WithdrawalBatch(batch.clone()))
            .unwrap();

        assert_eq!(
            state.claim_ledger().balance(&request.claim_owner_id),
            30_000
        );
        assert!(state.withdrawal_batches().contains_key(&batch_hash));
        state.withdrawal_batch_is_reserved(&batch, 1).unwrap();
        assert!(matches!(
            state.claim_ledger_after_withdrawal_batch(&batch, 1),
            Err(SharechainReplayError::Ledger(_))
        ));
    }

    #[test]
    fn withdrawal_batch_message_rejects_tampered_fee_math() {
        let (registration, _) = signed_registration();
        let claim_keypair = keypair(10);
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let schedule = state
            .expected_payout_schedule(&accounts, 50_000, 0, 10_000)
            .unwrap();
        state
            .apply_confirmed_payout_schedule(&schedule, &accounts, 50_000, 0, 10_000)
            .unwrap();
        let request = signed_withdrawal_request("req-1", 20_000, 1, &claim_keypair);
        state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap();
        let mut batch = build_withdrawal_batch(vec![request.clone()], 1, 1, 1).unwrap();
        batch.outputs[0].fee_sats = 0;
        batch.outputs[0].net_amount_sats = batch.outputs[0].gross_amount_sats;

        assert!(matches!(
            state.apply_message(&SharechainMessage::WithdrawalBatch(batch)),
            Err(SharechainReplayError::WithdrawalBatchMismatch(_))
        ));
        assert_eq!(
            state.claim_ledger().balance(&request.claim_owner_id),
            50_000
        );
        assert_eq!(state.summary().pending_withdrawal_count, 0);
    }

    #[test]
    fn deterministic_payout_validation_rejects_unfair_schedule() {
        let (registration, _) = signed_registration();
        let mut state = SharechainReplayState::default();
        state
            .apply_message(&SharechainMessage::MinerRegistration(registration.clone()))
            .unwrap();
        let mut accounts = state.participant_accounts();
        accounts[0].hashrate_score = 1;
        accounts[0].idena_score = 1;
        let mut unfair_schedule = PayoutSchedule {
            direct_outputs: vec![],
            vault_allocations: vec![crate::payout::VaultAllocation {
                miner_id: registration.miner_id,
                claim_owner_id: registration.claim_owner_pubkey_hex,
                amount_sats: 20_000,
            }],
            vault_output_sats: 20_000,
            payout_root: String::new(),
        };
        unfair_schedule.payout_root = unfair_schedule.expected_payout_root();

        assert_eq!(unfair_schedule.validate(), Ok(()));
        assert_eq!(
            state.validate_deterministic_payout_schedule(
                &unfair_schedule,
                &accounts,
                100_000,
                100,
                10_000,
            ),
            Err(SharechainReplayError::PayoutScheduleMismatch)
        );
    }
}
