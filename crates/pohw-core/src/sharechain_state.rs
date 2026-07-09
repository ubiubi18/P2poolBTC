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

const ZERO_SHARE_PARENT_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
    shares: BTreeMap<String, ShareNode>,
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
    pub accepted_bitcoin_work_template_count: usize,
    pub bitcoin_work_template_count: usize,
    pub stored_share_count: usize,
    pub active_share_count: usize,
    pub inactive_share_count: usize,
    pub share_miner_count: usize,
    pub active_share_score_total: Score,
    pub best_share_tip: Option<String>,
    pub snapshot_vote_root_count: usize,
    pub proposed_payout_schedule_count: usize,
    pub withdrawal_request_count: usize,
    pub withdrawal_batch_count: usize,
    pub pending_withdrawal_count: usize,
    pub vault_claim_owner_count: usize,
    pub last_message_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AccountingStateRootMaterial {
    version: &'static str,
    best_share_tip: Option<String>,
    active_share_hashes: Vec<String>,
    active_share_score_total: Score,
    hashrate_scores: BTreeMap<String, Score>,
    registrations: BTreeMap<String, MinerRegistration>,
    snapshot_votes: BTreeMap<SnapshotVoteKey, BTreeSet<String>>,
    proposed_payout_schedules: BTreeMap<String, PayoutSchedule>,
    withdrawal_requests: BTreeMap<String, WithdrawalRequest>,
    withdrawal_batches: BTreeMap<String, WithdrawalBatch>,
    claim_ledger: ClaimLedger,
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
    #[error("conflicting share for hash {0}")]
    ConflictingShare(String),
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
    #[error("invalid withdrawal request: {0}")]
    InvalidWithdrawal(#[from] WithdrawalError),
    #[error("invalid payout schedule: {0}")]
    InvalidPayoutSchedule(#[from] PayoutError),
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),
}

impl SharechainReplayState {
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
                share.verify_mining_signature(&registration.mining_pubkey_hex)?;
                self.validate_share_bitcoin_work_template(share)?;
                self.apply_share(share)?;
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
            SharechainMessage::PohwCommitment(_) => {
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
        SharechainReplaySummary {
            applied_message_count: self.applied_message_hashes.len(),
            registered_miner_count: self.registrations.len(),
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

    pub fn hashrate_scores(&self) -> &BTreeMap<String, Score> {
        &self.hashrate_scores
    }

    pub fn best_share_tip(&self) -> Option<&str> {
        self.best_share_tip.as_deref()
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
            snapshot_votes: self.snapshot_votes.clone(),
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
            if existing != &registration {
                return Err(SharechainReplayError::ConflictingRegistration(
                    registration.miner_id,
                ));
            }
            return Ok(());
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
        Ok(())
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

        let parent_share_hash = share.parent_share_hash.to_ascii_lowercase();
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
        self.resolve_share_and_descendants(&share_hash)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharechain::{BitcoinWorkTemplate, MinerRegistration, Share};
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

    fn signed_registration() -> (MinerRegistration, Keypair) {
        let mining_keypair = keypair(9);
        let claim_keypair = keypair(10);
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let idena_address = idena_address_from_pubkey(&PublicKey::from_secret_key(
            &Secp256k1::new(),
            &idena_secret,
        ));
        let mut registration = MinerRegistration {
            miner_id: "Miner-A".to_string(),
            idena_address,
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex = sign(registration.signing_hash(), &mining_keypair);
        (registration, mining_keypair)
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
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[36..68].copy_from_slice(&[0x22; 32]);
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
        for nonce in 0..10_000 {
            let share = test_share(miner_id, target, nonce, proof_root, parent_hash);
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
    fn fork_choice_counts_only_best_cumulative_branch() {
        let (registration, mining_keypair) = signed_registration();
        let mut root_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root_a.mining_signature_hex = sign(root_a.signing_hash(), &mining_keypair);
        let root_a_hash = root_a.share_hash();
        let mut child_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"12".repeat(32),
            &root_a_hash,
        );
        child_a.mining_signature_hex = sign(child_a.signing_hash(), &mining_keypair);
        let child_a_hash = child_a.share_hash();
        let mut root_b = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"22".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root_b.mining_signature_hex = sign(root_b.signing_hash(), &mining_keypair);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &root_a, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(root_b))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(root_a))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(child_a))
            .unwrap();

        let summary = state.summary();
        assert_eq!(summary.stored_share_count, 3);
        assert_eq!(summary.active_share_count, 2);
        assert_eq!(summary.inactive_share_count, 1);
        assert_eq!(summary.active_share_score_total, 2);
        assert_eq!(
            summary.best_share_tip.as_deref(),
            Some(child_a_hash.as_str())
        );
        assert_eq!(state.best_share_height(), Some(2));
        assert_eq!(state.hashrate_scores().get("miner-a"), Some(&2));
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
        let mut root_a = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"11".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root_a.mining_signature_hex = sign(root_a.signing_hash(), &mining_keypair);
        let root_a_hash = root_a.share_hash();
        let mut root_b = mined_test_share(
            "MINER-A",
            MAX_SHARE_TARGET_HEX,
            &"22".repeat(32),
            ZERO_SHARE_PARENT_HASH,
        );
        root_b.mining_signature_hex = sign(root_b.signing_hash(), &mining_keypair);
        let root_b_hash = root_b.share_hash();
        let expected_tip = root_a_hash.min(root_b_hash);

        let mut state = SharechainReplayState::default();
        apply_registration_and_template(&mut state, registration, &root_a, &mining_keypair);
        state
            .apply_message(&SharechainMessage::Share(root_b))
            .unwrap();
        state
            .apply_message(&SharechainMessage::Share(root_a))
            .unwrap();

        let summary = state.summary();
        assert_eq!(summary.active_share_count, 1);
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
