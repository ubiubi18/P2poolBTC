use bitcoin::key::{Secp256k1, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use crate::dkg_transport::normalize_dkg_signer_id;
use crate::sharechain_state::{SharechainReplayError, SharechainReplayState};
use crate::withdrawal::{
    estimate_batch_vsize, estimate_fee_sats, validate_destination_script_policy, WithdrawalBatch,
    WithdrawalOutput,
};
use crate::{canonical_json, hash_hex, sha256_tagged, Sats};

pub const MIN_VAULT_INPUT_CONFIRMATIONS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerHeartbeat {
    pub signer_id: String,
    pub idena_address: String,
    pub host_pubkey: String,
    pub last_seen: DateTime<Utc>,
    pub eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEpoch {
    pub epoch_id: u64,
    pub starts_at: DateTime<Utc>,
    pub signer_ids: Vec<String>,
    pub threshold: usize,
    pub frost_group_key_xonly: Option<String>,
    pub dkg_transcript_hash: Option<String>,
    pub dkg_public_key_package_hash: Option<String>,
    pub frost_signer_bindings: Vec<DkgSignerBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgTranscript {
    pub epoch_id: u64,
    pub threshold: usize,
    pub signer_ids: Vec<String>,
    pub frost_group_key_xonly: String,
    pub public_key_package_hash: String,
    pub signer_bindings: Vec<DkgSignerBinding>,
    pub round1_packages_root: String,
    pub round2_packages_root: String,
    pub signer_ack_root: String,
    pub recovery_data_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgSignerBinding {
    pub signer_id: String,
    pub frost_identifier_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: Sats,
    pub confirmations: u32,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultRemainderKind {
    SameEpochChange,
    NextEpochRotation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRemainderOutput {
    pub epoch_id: u64,
    pub frost_group_key_xonly: String,
    pub amount_sats: Sats,
    pub kind: VaultRemainderKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSpendPlan {
    pub epoch_id: u64,
    pub frost_group_key_xonly: String,
    pub inputs: Vec<VaultInput>,
    pub withdrawal_batch: Option<WithdrawalBatch>,
    pub tx_fee_sats: Sats,
    pub vault_remainder: Option<VaultRemainderOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignatureShare {
    pub signer_id: String,
    pub frost_identifier_hex: String,
    pub public_key_package_hash: String,
    pub spend_plan_hash: String,
    pub input_index: usize,
    pub sighash_hex: String,
    pub signature_share_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFrostSignatureShare {
    share: FrostSignatureShare,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSigningSession {
    pub epoch_id: u64,
    pub threshold: usize,
    pub signer_ids: Vec<String>,
    pub dkg_public_key_package_hash: String,
    pub spend_plan_hash: String,
    pub input_sighashes: Vec<String>,
    pub spend_plan: VaultSpendPlan,
    signer_frost_identifiers: BTreeMap<String, String>,
    signature_shares: BTreeMap<String, FrostSignatureShare>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSignerApproval {
    pub input_index: usize,
    pub sighash_hex: String,
    pub signer_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSpendApproval {
    pub epoch_id: u64,
    pub threshold: usize,
    pub dkg_public_key_package_hash: String,
    pub spend_plan_hash: String,
    pub input_sighashes: Vec<String>,
    pub signer_ids: Vec<String>,
    pub input_signer_ids: Vec<InputSignerApproval>,
    pub signature_shares: Vec<FrostSignatureShare>,
}

impl VaultEpoch {
    pub fn from_online_signers(
        epoch_id: u64,
        starts_at: DateTime<Utc>,
        mut heartbeats: Vec<SignerHeartbeat>,
        max_age_seconds: i64,
    ) -> Self {
        heartbeats.retain(|h| {
            let age_seconds = starts_at.signed_duration_since(h.last_seen).num_seconds();
            h.eligible && age_seconds >= 0 && age_seconds <= max_age_seconds
        });
        let mut signer_ids: Vec<_> = heartbeats
            .into_iter()
            .filter_map(|h| normalize_dkg_signer_id(&h.signer_id).ok())
            .collect();
        signer_ids.sort();
        signer_ids.dedup();
        let threshold = threshold_67_percent(signer_ids.len());

        Self {
            epoch_id,
            starts_at,
            signer_ids,
            threshold,
            frost_group_key_xonly: None,
            dkg_transcript_hash: None,
            dkg_public_key_package_hash: None,
            frost_signer_bindings: Vec::new(),
        }
    }

    pub fn signer_count(&self) -> usize {
        self.signer_ids.len()
    }

    pub fn attach_dkg_transcript(&mut self, transcript: DkgTranscript) -> Result<(), VaultError> {
        let transcript = transcript.normalized()?;
        if transcript.epoch_id != self.epoch_id {
            return Err(VaultError::WrongEpoch {
                expected: self.epoch_id,
                actual: transcript.epoch_id,
            });
        }
        if transcript.threshold != self.threshold || transcript.signer_ids != self.signer_ids {
            return Err(VaultError::SignerSetMismatch);
        }

        let transcript_hash = transcript.transcript_hash();
        self.frost_group_key_xonly = Some(transcript.frost_group_key_xonly);
        self.dkg_public_key_package_hash = Some(transcript.public_key_package_hash);
        self.frost_signer_bindings = transcript.signer_bindings;
        self.dkg_transcript_hash = Some(transcript_hash);
        Ok(())
    }

    pub fn required_group_key(&self) -> Result<String, VaultError> {
        let key = self
            .frost_group_key_xonly
            .as_deref()
            .ok_or(VaultError::MissingGroupKey {
                epoch_id: self.epoch_id,
            })?;
        validate_xonly_hex(key)
    }

    pub fn required_public_key_package_hash(&self) -> Result<String, VaultError> {
        self.dkg_public_key_package_hash
            .as_deref()
            .ok_or(VaultError::MissingDkgTranscript {
                epoch_id: self.epoch_id,
            })
            .and_then(validate_hash_hex)
    }

    pub fn signer_frost_identifier_map(&self) -> Result<BTreeMap<String, String>, VaultError> {
        if self.frost_signer_bindings.is_empty() {
            return Err(VaultError::MissingDkgTranscript {
                epoch_id: self.epoch_id,
            });
        }
        let bindings = normalize_signer_bindings(self.frost_signer_bindings.clone())?;
        let binding_signer_ids: Vec<_> = bindings
            .iter()
            .map(|binding| binding.signer_id.clone())
            .collect();
        if binding_signer_ids != self.signer_ids {
            return Err(VaultError::SignerBindingMismatch);
        }
        Ok(bindings
            .into_iter()
            .map(|binding| (binding.signer_id, binding.frost_identifier_hex))
            .collect())
    }
}

impl DkgTranscript {
    pub fn normalized(mut self) -> Result<Self, VaultError> {
        self.signer_ids = normalize_signer_ids(self.signer_ids)?;
        if self.signer_ids.is_empty() {
            return Err(VaultError::EmptyTranscriptSignerSet);
        }
        let expected_threshold = threshold_67_percent(self.signer_ids.len());
        if self.threshold == 0
            || self.threshold > self.signer_ids.len()
            || self.threshold != expected_threshold
        {
            return Err(VaultError::InvalidTranscriptThreshold {
                threshold: self.threshold,
                signer_count: self.signer_ids.len(),
                expected_threshold,
            });
        }
        self.frost_group_key_xonly = validate_xonly_hex(&self.frost_group_key_xonly)?;
        self.public_key_package_hash = validate_hash_hex(&self.public_key_package_hash)?;
        self.signer_bindings = normalize_signer_bindings(self.signer_bindings)?;
        let binding_signer_ids: Vec<_> = self
            .signer_bindings
            .iter()
            .map(|binding| binding.signer_id.clone())
            .collect();
        if binding_signer_ids != self.signer_ids {
            return Err(VaultError::SignerBindingMismatch);
        }
        for (idx, binding) in self.signer_bindings.iter().enumerate() {
            if binding.frost_identifier_hex != deterministic_frost_identifier_hex(idx) {
                return Err(VaultError::SignerBindingMismatch);
            }
        }
        self.round1_packages_root = validate_hash_hex(&self.round1_packages_root)?;
        self.round2_packages_root = validate_hash_hex(&self.round2_packages_root)?;
        self.signer_ack_root = validate_hash_hex(&self.signer_ack_root)?;
        self.recovery_data_hash = validate_hash_hex(&self.recovery_data_hash)?;
        Ok(self)
    }

    pub fn transcript_hash(&self) -> String {
        hash_hex(sha256_tagged(
            b"POHW1_CHILLDKG_TRANSCRIPT",
            &canonical_json(self),
        ))
    }
}

impl DkgSignerBinding {
    pub fn normalized(mut self) -> Result<Self, VaultError> {
        self.signer_id = normalize_dkg_signer_id(&self.signer_id)
            .map_err(|_| VaultError::InvalidSignerId(self.signer_id.clone()))?;
        self.frost_identifier_hex = validate_frost_identifier_hex(&self.frost_identifier_hex)?;
        Ok(self)
    }
}

impl VaultInput {
    pub fn normalized(mut self) -> Self {
        self.txid = self.txid.to_ascii_lowercase();
        self.script_pubkey_hex = self.script_pubkey_hex.to_ascii_lowercase();
        self
    }
}

impl VaultRemainderOutput {
    pub fn same_epoch_change(
        epoch_id: u64,
        frost_group_key_xonly: impl Into<String>,
        amount_sats: Sats,
    ) -> Self {
        Self {
            epoch_id,
            frost_group_key_xonly: frost_group_key_xonly.into(),
            amount_sats,
            kind: VaultRemainderKind::SameEpochChange,
        }
    }

    pub fn next_epoch_rotation(
        epoch_id: u64,
        frost_group_key_xonly: impl Into<String>,
        amount_sats: Sats,
    ) -> Self {
        Self {
            epoch_id,
            frost_group_key_xonly: frost_group_key_xonly.into(),
            amount_sats,
            kind: VaultRemainderKind::NextEpochRotation,
        }
    }

    fn normalized(mut self) -> Result<Self, VaultError> {
        self.frost_group_key_xonly = validate_xonly_hex(&self.frost_group_key_xonly)?;
        Ok(self)
    }
}

impl VaultSpendPlan {
    pub fn withdrawal_batch(
        epoch: &VaultEpoch,
        inputs: Vec<VaultInput>,
        batch: WithdrawalBatch,
        vault_remainder: Option<VaultRemainderOutput>,
    ) -> Result<Self, VaultError> {
        let frost_group_key_xonly = epoch.required_group_key()?;
        let plan = Self {
            epoch_id: epoch.epoch_id,
            frost_group_key_xonly,
            inputs,
            tx_fee_sats: batch.total_fee_sats,
            withdrawal_batch: Some(batch),
            vault_remainder,
        }
        .normalized()?;
        plan.validate_against_epoch(epoch)?;
        Ok(plan)
    }

    pub fn rotation(
        current_epoch: &VaultEpoch,
        next_epoch: &VaultEpoch,
        inputs: Vec<VaultInput>,
        tx_fee_sats: Sats,
    ) -> Result<Self, VaultError> {
        let frost_group_key_xonly = current_epoch.required_group_key()?;
        let next_group_key = next_epoch.required_group_key()?;
        let inputs: Vec<_> = inputs.into_iter().map(VaultInput::normalized).collect();
        let input_total_sats = sum_sats(inputs.iter().map(|input| input.amount_sats))?;
        if input_total_sats <= tx_fee_sats {
            return Err(VaultError::FeeExceedsInputs {
                input_total_sats,
                tx_fee_sats,
            });
        }

        let plan = Self {
            epoch_id: current_epoch.epoch_id,
            frost_group_key_xonly,
            inputs,
            withdrawal_batch: None,
            tx_fee_sats,
            vault_remainder: Some(VaultRemainderOutput::next_epoch_rotation(
                next_epoch.epoch_id,
                next_group_key,
                input_total_sats - tx_fee_sats,
            )),
        }
        .normalized()?;
        plan.validate_against_epoch(current_epoch)?;
        Ok(plan)
    }

    pub fn plan_hash(&self) -> String {
        let plan = self.canonicalized_for_hash();
        hash_hex(sha256_tagged(
            b"POHW1_VAULT_SPEND_PLAN",
            &canonical_json(&plan),
        ))
    }

    pub fn input_total_sats(&self) -> Result<Sats, VaultError> {
        sum_sats(self.inputs.iter().map(|input| input.amount_sats))
    }

    pub fn withdrawal_net_total_sats(&self) -> Result<Sats, VaultError> {
        let Some(batch) = &self.withdrawal_batch else {
            return Ok(0);
        };
        sum_sats(batch.outputs.iter().map(|output| output.net_amount_sats))
    }

    pub fn vault_remainder_sats(&self) -> Sats {
        self.vault_remainder
            .as_ref()
            .map(|output| output.amount_sats)
            .unwrap_or(0)
    }

    pub fn validate_against_epoch(&self, epoch: &VaultEpoch) -> Result<(), VaultError> {
        if self.epoch_id != epoch.epoch_id {
            return Err(VaultError::WrongEpoch {
                expected: epoch.epoch_id,
                actual: self.epoch_id,
            });
        }
        let epoch_key = epoch.required_group_key()?;
        if validate_xonly_hex(&self.frost_group_key_xonly)? != epoch_key {
            return Err(VaultError::WrongGroupKey {
                epoch_id: epoch.epoch_id,
            });
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if self.inputs.is_empty() {
            return Err(VaultError::EmptyVaultInputs);
        }
        let expected_vault_script_pubkey_hex =
            vault_script_pubkey_hex(&self.frost_group_key_xonly)?;
        for input in &self.inputs {
            validate_input_txid(&input.txid)?;
            let input_script_pubkey_hex = validate_script_hex(&input.script_pubkey_hex)?;
            if input_script_pubkey_hex != expected_vault_script_pubkey_hex {
                return Err(VaultError::VaultInputScriptMismatch {
                    txid: input.txid.clone(),
                    vout: input.vout,
                    expected_script_pubkey_hex: expected_vault_script_pubkey_hex.clone(),
                    actual_script_pubkey_hex: input_script_pubkey_hex,
                });
            }
            if input.amount_sats == 0 {
                return Err(VaultError::ZeroValueInput {
                    txid: input.txid.clone(),
                    vout: input.vout,
                });
            }
            if input.confirmations < MIN_VAULT_INPUT_CONFIRMATIONS {
                return Err(VaultError::InsufficientInputConfirmations {
                    txid: input.txid.clone(),
                    vout: input.vout,
                    confirmations: input.confirmations,
                    minimum_confirmations: MIN_VAULT_INPUT_CONFIRMATIONS,
                });
            }
        }
        let mut outpoints = BTreeSet::new();
        for input in &self.inputs {
            if !outpoints.insert((input.txid.clone(), input.vout)) {
                return Err(VaultError::DuplicateVaultInput {
                    txid: input.txid.clone(),
                    vout: input.vout,
                });
            }
        }

        if self.withdrawal_batch.is_none() && self.vault_remainder.is_none() {
            return Err(VaultError::NoSpendOutputs);
        }

        let tx_fee_sats = self.tx_fee_sats;
        let withdrawal_net_total_sats = self.withdrawal_net_total_sats()?;
        if let Some(batch) = &self.withdrawal_batch {
            self.validate_withdrawal_batch(batch)?;
            if batch.total_fee_sats != tx_fee_sats {
                return Err(VaultError::BatchFeeMismatch {
                    batch_fee_sats: batch.total_fee_sats,
                    tx_fee_sats,
                });
            }
            let output_fee_total_sats = sum_sats(batch.outputs.iter().map(|o| o.fee_sats))?;
            if output_fee_total_sats != batch.total_fee_sats {
                return Err(VaultError::BatchOutputFeeMismatch {
                    output_fee_total_sats,
                    batch_fee_sats: batch.total_fee_sats,
                });
            }
        }

        if let Some(remainder) = &self.vault_remainder {
            match remainder.kind {
                VaultRemainderKind::SameEpochChange => {
                    if remainder.epoch_id != self.epoch_id
                        || validate_xonly_hex(&remainder.frost_group_key_xonly)?
                            != validate_xonly_hex(&self.frost_group_key_xonly)?
                    {
                        return Err(VaultError::InvalidRemainderTarget);
                    }
                }
                VaultRemainderKind::NextEpochRotation => {
                    if remainder.epoch_id <= self.epoch_id
                        || validate_xonly_hex(&remainder.frost_group_key_xonly)?
                            == validate_xonly_hex(&self.frost_group_key_xonly)?
                    {
                        return Err(VaultError::InvalidRemainderTarget);
                    }
                }
            }
        }

        let expected_spend = sum_sats([
            withdrawal_net_total_sats,
            tx_fee_sats,
            self.vault_remainder_sats(),
        ])?;
        let input_total_sats = self.input_total_sats()?;
        if input_total_sats != expected_spend {
            return Err(VaultError::AmountMismatch {
                input_total_sats,
                expected_spend_sats: expected_spend,
            });
        }

        Ok(())
    }

    fn validate_withdrawal_batch(&self, batch: &WithdrawalBatch) -> Result<(), VaultError> {
        if batch.outputs.is_empty() {
            return Err(VaultError::EmptyWithdrawalBatch);
        }
        if batch.inputs != self.inputs.len() {
            return Err(VaultError::BatchInputCountMismatch {
                batch_inputs: batch.inputs,
                vault_inputs: self.inputs.len(),
            });
        }

        let mut request_ids = BTreeSet::new();
        let mut p2wpkh_outputs = 0usize;
        let mut p2tr_outputs = 0usize;
        for output in &batch.outputs {
            if !request_ids.insert(output.request_id.clone()) {
                return Err(VaultError::DuplicateWithdrawalOutput {
                    request_id: output.request_id.clone(),
                });
            }
            if output.fee_sats >= output.gross_amount_sats {
                return Err(VaultError::WithdrawalOutputFeeExceedsAmount {
                    request_id: output.request_id.clone(),
                    gross_amount_sats: output.gross_amount_sats,
                    fee_sats: output.fee_sats,
                });
            }
            let expected_net_sats = output.gross_amount_sats - output.fee_sats;
            if output.net_amount_sats != expected_net_sats {
                return Err(VaultError::WithdrawalOutputNetMismatch {
                    request_id: output.request_id.clone(),
                    gross_amount_sats: output.gross_amount_sats,
                    fee_sats: output.fee_sats,
                    net_amount_sats: output.net_amount_sats,
                });
            }
            validate_destination_script_policy(
                &output.request_id,
                &output.destination_script_hex,
                &output.output_kind,
                output.net_amount_sats,
            )
            .map_err(|err| VaultError::WithdrawalOutputPolicy {
                request_id: output.request_id.clone(),
                reason: err.to_string(),
            })?;
            match output.output_kind {
                crate::withdrawal::WithdrawalOutputKind::P2wpkh => p2wpkh_outputs += 1,
                crate::withdrawal::WithdrawalOutputKind::P2tr => p2tr_outputs += 1,
            }
        }

        let expected_vsize = estimate_batch_vsize(self.inputs.len(), p2wpkh_outputs, p2tr_outputs)
            .map_err(|err| VaultError::WithdrawalBatchEstimate(err.to_string()))?;
        if batch.estimated_vsize != expected_vsize {
            return Err(VaultError::BatchVsizeMismatch {
                batch_vsize: batch.estimated_vsize,
                expected_vsize,
            });
        }
        let expected_fee_sats = estimate_fee_sats(expected_vsize, batch.fee_rate_sat_vb)
            .map_err(|err| VaultError::WithdrawalBatchEstimate(err.to_string()))?;
        if batch.total_fee_sats != expected_fee_sats {
            return Err(VaultError::BatchFeeEstimateMismatch {
                batch_fee_sats: batch.total_fee_sats,
                expected_fee_sats,
            });
        }
        Ok(())
    }

    fn normalized(mut self) -> Result<Self, VaultError> {
        self.frost_group_key_xonly = validate_xonly_hex(&self.frost_group_key_xonly)?;
        self.inputs = normalize_inputs(self.inputs);
        if let Some(batch) = &mut self.withdrawal_batch {
            batch.outputs = normalize_withdrawal_outputs(std::mem::take(&mut batch.outputs));
        }
        if let Some(remainder) = self.vault_remainder.take() {
            self.vault_remainder = Some(remainder.normalized()?);
        }
        Ok(self)
    }

    fn canonicalized_for_hash(&self) -> Self {
        let mut plan = self.clone();
        plan.frost_group_key_xonly = plan.frost_group_key_xonly.to_ascii_lowercase();
        plan.inputs = normalize_inputs(plan.inputs);
        if let Some(batch) = &mut plan.withdrawal_batch {
            batch.outputs = normalize_withdrawal_outputs(std::mem::take(&mut batch.outputs));
        }
        if let Some(remainder) = &mut plan.vault_remainder {
            remainder.frost_group_key_xonly = remainder.frost_group_key_xonly.to_ascii_lowercase();
        }
        plan
    }
}

impl FrostSignatureShare {
    pub fn normalized(mut self) -> Result<Self, VaultError> {
        self.signer_id = normalize_dkg_signer_id(&self.signer_id)
            .map_err(|_| VaultError::InvalidSignerId(self.signer_id.clone()))?;
        self.frost_identifier_hex = validate_frost_identifier_hex(&self.frost_identifier_hex)?;
        self.public_key_package_hash = validate_hash_hex(&self.public_key_package_hash)?;
        self.spend_plan_hash = self.spend_plan_hash.to_ascii_lowercase();
        self.sighash_hex = validate_hash_hex(&self.sighash_hex)?;
        self.signature_share_hex = validate_frost_signature_share_hex(&self.signature_share_hex)?;
        Ok(self)
    }
}

impl VerifiedFrostSignatureShare {
    pub fn share(&self) -> &FrostSignatureShare {
        &self.share
    }

    pub(crate) fn from_verified_share(share: FrostSignatureShare) -> Result<Self, VaultError> {
        Ok(Self {
            share: share.normalized()?,
        })
    }
}

impl VaultSigningSession {
    pub fn new(
        epoch: &VaultEpoch,
        spend_plan: VaultSpendPlan,
        input_sighashes: Vec<String>,
    ) -> Result<Self, VaultError> {
        if spend_plan.withdrawal_batch.is_some() {
            return Err(VaultError::UnreservedWithdrawalBatch);
        }
        Self::new_after_policy_checks(epoch, spend_plan, input_sighashes)
    }

    pub fn new_with_reserved_withdrawals(
        epoch: &VaultEpoch,
        spend_plan: VaultSpendPlan,
        input_sighashes: Vec<String>,
        replay_state: &SharechainReplayState,
        current_height: u64,
    ) -> Result<Self, VaultError> {
        let Some(batch) = spend_plan.withdrawal_batch.as_ref() else {
            return Self::new_after_policy_checks(epoch, spend_plan, input_sighashes);
        };
        replay_state
            .withdrawal_batch_is_reserved(batch, current_height)
            .map_err(VaultError::UnverifiedWithdrawalBatch)?;
        Self::new_after_policy_checks(epoch, spend_plan, input_sighashes)
    }

    fn new_after_policy_checks(
        epoch: &VaultEpoch,
        spend_plan: VaultSpendPlan,
        input_sighashes: Vec<String>,
    ) -> Result<Self, VaultError> {
        let signer_ids = normalize_signer_ids(epoch.signer_ids.clone())?;
        if epoch.threshold == 0 || signer_ids.is_empty() {
            return Err(VaultError::EmptySignerSet);
        }
        if epoch.threshold > signer_ids.len() {
            return Err(VaultError::ThresholdExceedsSignerCount {
                threshold: epoch.threshold,
                signer_count: signer_ids.len(),
            });
        }
        let dkg_public_key_package_hash = epoch.required_public_key_package_hash()?;
        let signer_frost_identifiers = epoch.signer_frost_identifier_map()?;
        let spend_plan = spend_plan.normalized()?;
        spend_plan.validate_against_epoch(epoch)?;
        let input_sighashes = normalize_input_sighashes(input_sighashes)?;
        if input_sighashes.is_empty() {
            return Err(VaultError::MissingInputSighashes);
        }
        if input_sighashes.len() != spend_plan.inputs.len() {
            return Err(VaultError::InputSighashCountMismatch {
                input_count: spend_plan.inputs.len(),
                sighash_count: input_sighashes.len(),
            });
        }
        let spend_plan_hash = spend_plan.plan_hash();

        Ok(Self {
            epoch_id: epoch.epoch_id,
            threshold: epoch.threshold,
            signer_ids,
            dkg_public_key_package_hash,
            spend_plan_hash,
            input_sighashes,
            spend_plan,
            signer_frost_identifiers,
            signature_shares: BTreeMap::new(),
        })
    }

    pub fn add_signature_share(&mut self, share: FrostSignatureShare) -> Result<usize, VaultError> {
        let share = share.normalized()?;
        self.validate_share_identity(&share)?;
        Err(VaultError::UnverifiedSignatureShare {
            signer_id: share.signer_id,
        })
    }

    pub fn add_verified_signature_share(
        &mut self,
        share: VerifiedFrostSignatureShare,
    ) -> Result<usize, VaultError> {
        let share = share.share;
        self.validate_share_identity(&share)?;
        self.signature_shares.insert(
            signature_share_key(share.input_index, &share.signer_id),
            share,
        );
        Ok(self.signature_shares.len())
    }

    fn validate_share_identity(&self, share: &FrostSignatureShare) -> Result<(), VaultError> {
        if share.spend_plan_hash != self.spend_plan_hash {
            return Err(VaultError::WrongSpendPlanHash);
        }
        if !self.signer_ids.contains(&share.signer_id) {
            return Err(VaultError::SignerNotInEpoch {
                signer_id: share.signer_id.clone(),
                epoch_id: self.epoch_id,
            });
        }
        if share.public_key_package_hash != self.dkg_public_key_package_hash {
            return Err(VaultError::WrongPublicKeyPackageHash {
                expected_public_key_package_hash: self.dkg_public_key_package_hash.clone(),
                actual_public_key_package_hash: share.public_key_package_hash.clone(),
            });
        }
        let expected_identifier = self.signer_frost_identifiers.get(&share.signer_id).ok_or(
            VaultError::MissingSignerBinding {
                signer_id: share.signer_id.clone(),
                epoch_id: self.epoch_id,
            },
        )?;
        if share.frost_identifier_hex != *expected_identifier {
            return Err(VaultError::WrongFrostIdentifier {
                signer_id: share.signer_id.clone(),
                expected_frost_identifier_hex: expected_identifier.clone(),
                actual_frost_identifier_hex: share.frost_identifier_hex.clone(),
            });
        }
        let expected_sighash = self.input_sighashes.get(share.input_index).ok_or(
            VaultError::InputIndexOutOfRange {
                input_index: share.input_index,
                input_count: self.input_sighashes.len(),
            },
        )?;
        if share.sighash_hex != *expected_sighash {
            return Err(VaultError::InputSighashMismatch {
                input_index: share.input_index,
                expected_sighash: expected_sighash.clone(),
                actual_sighash: share.sighash_hex.clone(),
            });
        }
        if self
            .signature_shares
            .contains_key(&signature_share_key(share.input_index, &share.signer_id))
        {
            return Err(VaultError::DuplicateSignatureShare {
                signer_id: share.signer_id.clone(),
                input_index: share.input_index,
            });
        }
        Ok(())
    }

    pub fn signature_share_count(&self) -> usize {
        self.signature_shares.len()
    }

    pub fn is_ready(&self) -> bool {
        (0..self.input_sighashes.len()).all(|input_index| {
            self.signature_shares
                .values()
                .filter(|share| share.input_index == input_index)
                .count()
                >= self.threshold
        })
    }

    pub fn approval(&self) -> Result<VaultSpendApproval, VaultError> {
        if !self.is_ready() {
            return Err(VaultError::NotEnoughSignatureShares {
                threshold: self.threshold,
                actual: self.signature_share_count(),
            });
        }

        Ok(VaultSpendApproval {
            epoch_id: self.epoch_id,
            threshold: self.threshold,
            dkg_public_key_package_hash: self.dkg_public_key_package_hash.clone(),
            spend_plan_hash: self.spend_plan_hash.clone(),
            input_sighashes: self.input_sighashes.clone(),
            signer_ids: self
                .signature_shares
                .values()
                .map(|share| share.signer_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            input_signer_ids: (0..self.input_sighashes.len())
                .map(|input_index| InputSignerApproval {
                    input_index,
                    sighash_hex: self.input_sighashes[input_index].clone(),
                    signer_ids: self
                        .signature_shares
                        .values()
                        .filter(|share| share.input_index == input_index)
                        .map(|share| share.signer_id.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                })
                .collect(),
            signature_shares: self.signature_shares.values().cloned().collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    #[error("DKG transcript epoch mismatch: expected {expected}, got {actual}")]
    WrongEpoch { expected: u64, actual: u64 },
    #[error("DKG transcript signer set or threshold does not match vault epoch")]
    SignerSetMismatch,
    #[error("DKG transcript has no signers")]
    EmptyTranscriptSignerSet,
    #[error("DKG transcript threshold {threshold} is invalid for {signer_count} signers; expected {expected_threshold}")]
    InvalidTranscriptThreshold {
        threshold: usize,
        signer_count: usize,
        expected_threshold: usize,
    },
    #[error("DKG transcript signer bindings do not match the epoch signer set")]
    SignerBindingMismatch,
    #[error("vault signer id {0:?} is invalid")]
    InvalidSignerId(String),
    #[error("vault signer id {signer_id} appears more than once")]
    DuplicateSignerId { signer_id: String },
    #[error("signer {signer_id} appears more than once in DKG signer bindings")]
    DuplicateSignerBinding { signer_id: String },
    #[error(
        "FROST identifier {frost_identifier_hex} appears more than once in DKG signer bindings"
    )]
    DuplicateFrostIdentifierBinding { frost_identifier_hex: String },
    #[error("vault epoch {epoch_id} does not have an attached FROST group key")]
    MissingGroupKey { epoch_id: u64 },
    #[error("vault epoch {epoch_id} does not have an attached DKG transcript")]
    MissingDkgTranscript { epoch_id: u64 },
    #[error("invalid FROST x-only group key: {0}")]
    InvalidXOnlyGroupKey(String),
    #[error("invalid FROST identifier payload: {0}")]
    InvalidFrostIdentifier(String),
    #[error("invalid hex payload")]
    InvalidHexPayload,
    #[error("invalid transcript hash payload: {0}")]
    InvalidHashPayload(String),
    #[error("vault spend needs at least one input")]
    EmptyVaultInputs,
    #[error("vault input {txid}:{vout} has zero sats")]
    ZeroValueInput { txid: String, vout: u32 },
    #[error("vault input txid is invalid: {0}")]
    InvalidVaultInputTxid(String),
    #[error("vault input scriptPubKey is invalid hex: {0}")]
    InvalidVaultInputScript(String),
    #[error("vault input {txid}:{vout} scriptPubKey mismatch: expected {expected_script_pubkey_hex}, got {actual_script_pubkey_hex}")]
    VaultInputScriptMismatch {
        txid: String,
        vout: u32,
        expected_script_pubkey_hex: String,
        actual_script_pubkey_hex: String,
    },
    #[error("vault input {txid}:{vout} appears more than once")]
    DuplicateVaultInput { txid: String, vout: u32 },
    #[error("vault input {txid}:{vout} has {confirmations} confirmations; minimum is {minimum_confirmations}")]
    InsufficientInputConfirmations {
        txid: String,
        vout: u32,
        confirmations: u32,
        minimum_confirmations: u32,
    },
    #[error("vault spend has no withdrawal outputs and no vault remainder output")]
    NoSpendOutputs,
    #[error("withdrawal batch has no outputs")]
    EmptyWithdrawalBatch,
    #[error("withdrawal batch declares {batch_inputs} inputs but vault plan has {vault_inputs}")]
    BatchInputCountMismatch {
        batch_inputs: usize,
        vault_inputs: usize,
    },
    #[error("withdrawal output {request_id} appears more than once")]
    DuplicateWithdrawalOutput { request_id: String },
    #[error("withdrawal output {request_id} gross amount {gross_amount_sats} cannot pay assigned fee {fee_sats}")]
    WithdrawalOutputFeeExceedsAmount {
        request_id: String,
        gross_amount_sats: Sats,
        fee_sats: Sats,
    },
    #[error("withdrawal output {request_id} net amount {net_amount_sats} does not equal gross {gross_amount_sats} minus fee {fee_sats}")]
    WithdrawalOutputNetMismatch {
        request_id: String,
        gross_amount_sats: Sats,
        fee_sats: Sats,
        net_amount_sats: Sats,
    },
    #[error("withdrawal output {request_id} violates script policy: {reason}")]
    WithdrawalOutputPolicy { request_id: String, reason: String },
    #[error("withdrawal batch estimate is invalid: {0}")]
    WithdrawalBatchEstimate(String),
    #[error(
        "withdrawal batch vsize {batch_vsize} does not match recomputed vsize {expected_vsize}"
    )]
    BatchVsizeMismatch {
        batch_vsize: u64,
        expected_vsize: u64,
    },
    #[error(
        "withdrawal batch fee {batch_fee_sats} does not match recomputed fee {expected_fee_sats}"
    )]
    BatchFeeEstimateMismatch {
        batch_fee_sats: Sats,
        expected_fee_sats: Sats,
    },
    #[error("withdrawal batch fee {batch_fee_sats} does not match vault tx fee {tx_fee_sats}")]
    BatchFeeMismatch {
        batch_fee_sats: Sats,
        tx_fee_sats: Sats,
    },
    #[error(
        "withdrawal output fees {output_fee_total_sats} do not match batch fee {batch_fee_sats}"
    )]
    BatchOutputFeeMismatch {
        output_fee_total_sats: Sats,
        batch_fee_sats: Sats,
    },
    #[error(
        "vault input total {input_total_sats} does not equal spend total {expected_spend_sats}"
    )]
    AmountMismatch {
        input_total_sats: Sats,
        expected_spend_sats: Sats,
    },
    #[error("vault tx fee {tx_fee_sats} spends all inputs {input_total_sats}")]
    FeeExceedsInputs {
        input_total_sats: Sats,
        tx_fee_sats: Sats,
    },
    #[error("sats addition overflow")]
    AmountOverflow,
    #[error("vault remainder target does not match its declared kind")]
    InvalidRemainderTarget,
    #[error("vault spend plan uses a different FROST group key for epoch {epoch_id}")]
    WrongGroupKey { epoch_id: u64 },
    #[error("vault epoch has no signers")]
    EmptySignerSet,
    #[error("vault threshold {threshold} exceeds signer count {signer_count}")]
    ThresholdExceedsSignerCount {
        threshold: usize,
        signer_count: usize,
    },
    #[error("vault signing session needs one sighash per input")]
    MissingInputSighashes,
    #[error("vault signing session got {sighash_count} sighashes for {input_count} inputs")]
    InputSighashCountMismatch {
        input_count: usize,
        sighash_count: usize,
    },
    #[error("signature share input index {input_index} is out of range for {input_count} inputs")]
    InputIndexOutOfRange {
        input_index: usize,
        input_count: usize,
    },
    #[error("signature share sighash mismatch for input {input_index}: expected {expected_sighash}, got {actual_sighash}")]
    InputSighashMismatch {
        input_index: usize,
        expected_sighash: String,
        actual_sighash: String,
    },
    #[error("signature share is for a different vault spend plan")]
    WrongSpendPlanHash,
    #[error("signer {signer_id} is not in vault epoch {epoch_id}")]
    SignerNotInEpoch { signer_id: String, epoch_id: u64 },
    #[error("signer {signer_id} has no DKG FROST identifier binding in epoch {epoch_id}")]
    MissingSignerBinding { signer_id: String, epoch_id: u64 },
    #[error("signature share for signer {signer_id} uses FROST identifier {actual_frost_identifier_hex}; expected {expected_frost_identifier_hex}")]
    WrongFrostIdentifier {
        signer_id: String,
        expected_frost_identifier_hex: String,
        actual_frost_identifier_hex: String,
    },
    #[error("signature share uses FROST public key package {actual_public_key_package_hash}; expected {expected_public_key_package_hash}")]
    WrongPublicKeyPackageHash {
        expected_public_key_package_hash: String,
        actual_public_key_package_hash: String,
    },
    #[error("signer {signer_id} already submitted a signature share for input {input_index}")]
    DuplicateSignatureShare {
        signer_id: String,
        input_index: usize,
    },
    #[error(
        "raw FROST signature share from signer {signer_id} was not cryptographically verified"
    )]
    UnverifiedSignatureShare { signer_id: String },
    #[error("withdrawal FROST signing requires ledger reservation against local replay state")]
    UnreservedWithdrawalBatch,
    #[error("withdrawal batch failed local ledger reservation: {0}")]
    UnverifiedWithdrawalBatch(SharechainReplayError),
    #[error("not enough signature shares: need {threshold}, got {actual}")]
    NotEnoughSignatureShares { threshold: usize, actual: usize },
}

pub fn threshold_67_percent(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (67 * n).div_ceil(100)
}

pub fn vault_script_pubkey_hex(frost_group_key_xonly: &str) -> Result<String, VaultError> {
    let secp = Secp256k1::verification_only();
    let internal_key = XOnlyPublicKey::from_str(&validate_xonly_hex(frost_group_key_xonly)?)
        .map_err(|err| VaultError::InvalidXOnlyGroupKey(err.to_string()))?;
    Ok(ScriptBuf::new_p2tr(&secp, internal_key, None).to_hex_string())
}

fn validate_xonly_hex(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(VaultError::InvalidXOnlyGroupKey(value.to_string()))
    }
}

fn validate_input_txid(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(VaultError::InvalidVaultInputTxid(value.to_string()))
    }
}

fn validate_script_hex(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    hex::decode(&normalized)
        .map(|_| normalized)
        .map_err(|err| VaultError::InvalidVaultInputScript(err.to_string()))
}

fn validate_frost_signature_share_hex(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(VaultError::InvalidHexPayload)
    }
}

fn validate_frost_identifier_hex(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(VaultError::InvalidFrostIdentifier(value.to_string()))
    }
}

fn deterministic_frost_identifier_hex(idx: usize) -> String {
    format!("{:064x}", idx + 1)
}

fn validate_hash_hex(value: &str) -> Result<String, VaultError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(VaultError::InvalidHashPayload(value.to_string()))
    }
}

fn normalize_signer_ids(signer_ids: Vec<String>) -> Result<Vec<String>, VaultError> {
    let mut signer_ids: Vec<_> = signer_ids
        .into_iter()
        .map(|signer_id| {
            normalize_dkg_signer_id(&signer_id).map_err(|_| VaultError::InvalidSignerId(signer_id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    signer_ids.sort();
    for window in signer_ids.windows(2) {
        if window[0] == window[1] {
            return Err(VaultError::DuplicateSignerId {
                signer_id: window[0].clone(),
            });
        }
    }
    Ok(signer_ids)
}

fn normalize_signer_bindings(
    bindings: Vec<DkgSignerBinding>,
) -> Result<Vec<DkgSignerBinding>, VaultError> {
    let mut bindings = bindings
        .into_iter()
        .map(DkgSignerBinding::normalized)
        .collect::<Result<Vec<_>, _>>()?;
    bindings.sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
    let mut signer_ids = BTreeSet::new();
    let mut frost_identifiers = BTreeSet::new();
    for binding in &bindings {
        if !signer_ids.insert(binding.signer_id.clone()) {
            return Err(VaultError::DuplicateSignerBinding {
                signer_id: binding.signer_id.clone(),
            });
        }
        if !frost_identifiers.insert(binding.frost_identifier_hex.clone()) {
            return Err(VaultError::DuplicateFrostIdentifierBinding {
                frost_identifier_hex: binding.frost_identifier_hex.clone(),
            });
        }
    }
    Ok(bindings)
}

fn normalize_inputs(inputs: Vec<VaultInput>) -> Vec<VaultInput> {
    let mut inputs: Vec<_> = inputs.into_iter().map(VaultInput::normalized).collect();
    inputs.sort_by(|a, b| a.txid.cmp(&b.txid).then_with(|| a.vout.cmp(&b.vout)));
    inputs
}

fn normalize_withdrawal_outputs(outputs: Vec<WithdrawalOutput>) -> Vec<WithdrawalOutput> {
    let mut outputs = outputs;
    outputs.sort_by(|a, b| a.request_id.cmp(&b.request_id));
    outputs
}

fn normalize_input_sighashes(input_sighashes: Vec<String>) -> Result<Vec<String>, VaultError> {
    input_sighashes
        .into_iter()
        .map(|sighash| validate_hash_hex(&sighash))
        .collect()
}

fn signature_share_key(input_index: usize, signer_id: &str) -> String {
    format!("{input_index}:{signer_id}")
}

fn sum_sats<I>(values: I) -> Result<Sats, VaultError>
where
    I: IntoIterator<Item = Sats>,
{
    values.into_iter().try_fold(0u64, |total, value| {
        total.checked_add(value).ok_or(VaultError::AmountOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::{build_withdrawal_batch, WithdrawalOutputKind, WithdrawalRequest};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use chrono::TimeZone;

    fn key(byte: &str) -> String {
        byte.repeat(32)
    }

    fn xonly_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        keypair.x_only_public_key().0.to_string()
    }

    fn hash(byte: &str) -> String {
        byte.repeat(32)
    }

    fn dkg_package_hash() -> String {
        hash("99")
    }

    fn frost_identifier(idx: usize) -> String {
        format!("{:064x}", idx + 1)
    }

    fn signer_bindings(signer_count: usize) -> Vec<DkgSignerBinding> {
        (0..signer_count)
            .map(|idx| DkgSignerBinding {
                signer_id: format!("signer-{idx:02}"),
                frost_identifier_hex: frost_identifier(idx),
            })
            .collect()
    }

    fn signature_share(byte: &str) -> String {
        byte.repeat(32)
    }

    fn sighash(byte: &str) -> String {
        byte.repeat(32)
    }

    fn make_epoch(epoch_id: u64, signer_count: usize, group_key: &str) -> VaultEpoch {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        VaultEpoch {
            epoch_id,
            starts_at,
            signer_ids: (0..signer_count)
                .map(|idx| format!("signer-{idx:02}"))
                .collect(),
            threshold: threshold_67_percent(signer_count),
            frost_group_key_xonly: Some(group_key.to_string()),
            dkg_transcript_hash: Some("transcript".to_string()),
            dkg_public_key_package_hash: Some(dkg_package_hash()),
            frost_signer_bindings: signer_bindings(signer_count),
        }
    }

    fn input(
        txid_prefix: &str,
        vout: u32,
        amount_sats: Sats,
        frost_group_key_xonly: &str,
    ) -> VaultInput {
        VaultInput {
            txid: format!("{txid_prefix:0<64}"),
            vout,
            amount_sats,
            confirmations: 144,
            script_pubkey_hex: vault_script_pubkey_hex(frost_group_key_xonly).unwrap(),
        }
    }

    fn withdrawal_request(id: &str, amount_sats: Sats) -> WithdrawalRequest {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[9; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let claim_owner_pubkey_hex = keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex: "00140000000000000000000000000000000000000000".to_string(),
            amount_sats,
            max_fee_rate_sat_vb: 10,
            nonce: 1,
            expiry_height: 1_000,
            signature_hex: None,
            output_kind: WithdrawalOutputKind::P2wpkh,
        };
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(request.signing_hash()), &keypair);
        request.signature_hex = Some(hex::encode(signature.serialize()));
        request
    }

    #[test]
    fn threshold_is_ceiling_of_sixty_seven_percent() {
        assert_eq!(threshold_67_percent(0), 0);
        assert_eq!(threshold_67_percent(1), 1);
        assert_eq!(threshold_67_percent(2), 2);
        assert_eq!(threshold_67_percent(3), 3);
        assert_eq!(threshold_67_percent(10), 7);
        assert_eq!(threshold_67_percent(15), 11);
        assert_eq!(threshold_67_percent(21), 15);
    }

    #[test]
    fn epoch_uses_all_online_eligible_signers_without_fixed_cap() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let heartbeats = (0..25)
            .map(|idx| SignerHeartbeat {
                signer_id: format!("signer-{idx:02}"),
                idena_address: format!("0x{idx:040x}"),
                host_pubkey: format!("host-{idx}"),
                last_seen: starts_at,
                eligible: true,
            })
            .collect();

        let epoch = VaultEpoch::from_online_signers(1, starts_at, heartbeats, 60);

        assert_eq!(epoch.signer_count(), 25);
        assert_eq!(epoch.threshold, 17);
    }

    #[test]
    fn epoch_rejects_future_heartbeats() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let heartbeats = vec![
            SignerHeartbeat {
                signer_id: "ok".to_string(),
                idena_address: "0x0000000000000000000000000000000000000000".to_string(),
                host_pubkey: "host-ok".to_string(),
                last_seen: starts_at,
                eligible: true,
            },
            SignerHeartbeat {
                signer_id: "future".to_string(),
                idena_address: "0x0000000000000000000000000000000000000001".to_string(),
                host_pubkey: "host-future".to_string(),
                last_seen: starts_at + chrono::Duration::seconds(1),
                eligible: true,
            },
        ];

        let epoch = VaultEpoch::from_online_signers(1, starts_at, heartbeats, 60);

        assert_eq!(epoch.signer_ids, vec!["ok"]);
    }

    #[test]
    fn epoch_ignores_invalid_signer_ids_from_heartbeats() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let heartbeats = vec![
            SignerHeartbeat {
                signer_id: "signer-00".to_string(),
                idena_address: "0x0000000000000000000000000000000000000000".to_string(),
                host_pubkey: "host-ok".to_string(),
                last_seen: starts_at,
                eligible: true,
            },
            SignerHeartbeat {
                signer_id: "../signer-01".to_string(),
                idena_address: "0x0000000000000000000000000000000000000001".to_string(),
                host_pubkey: "host-bad".to_string(),
                last_seen: starts_at,
                eligible: true,
            },
        ];

        let epoch = VaultEpoch::from_online_signers(1, starts_at, heartbeats, 60);

        assert_eq!(epoch.signer_ids, vec!["signer-00"]);
        assert_eq!(epoch.threshold, 1);
    }

    #[test]
    fn dkg_transcript_attaches_only_to_matching_epoch() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let mut epoch = VaultEpoch {
            epoch_id: 7,
            starts_at,
            signer_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            threshold: 3,
            frost_group_key_xonly: None,
            dkg_transcript_hash: None,
            dkg_public_key_package_hash: None,
            frost_signer_bindings: Vec::new(),
        };
        let transcript = DkgTranscript {
            epoch_id: 7,
            threshold: 3,
            signer_ids: epoch.signer_ids.clone(),
            frost_group_key_xonly: key("ab"),
            public_key_package_hash: hash("01"),
            signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: frost_identifier(1),
                },
                DkgSignerBinding {
                    signer_id: "c".to_string(),
                    frost_identifier_hex: frost_identifier(2),
                },
            ],
            round1_packages_root: hash("02"),
            round2_packages_root: hash("03"),
            signer_ack_root: hash("04"),
            recovery_data_hash: hash("05"),
        };

        epoch.attach_dkg_transcript(transcript).unwrap();

        assert_eq!(
            epoch.frost_group_key_xonly.as_deref(),
            Some(key("ab").as_str())
        );
        assert!(epoch.dkg_transcript_hash.is_some());
        assert_eq!(epoch.dkg_public_key_package_hash, Some(hash("01")));
        assert_eq!(
            epoch
                .frost_signer_bindings
                .iter()
                .map(|binding| binding.signer_id.clone())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn dkg_transcript_threshold_must_match_dynamic_epoch_rule() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let mut epoch = VaultEpoch {
            epoch_id: 7,
            starts_at,
            signer_ids: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            threshold: 3,
            frost_group_key_xonly: None,
            dkg_transcript_hash: None,
            dkg_public_key_package_hash: None,
            frost_signer_bindings: Vec::new(),
        };
        let transcript = DkgTranscript {
            epoch_id: 7,
            threshold: 2,
            signer_ids: epoch.signer_ids.clone(),
            frost_group_key_xonly: key("ab"),
            public_key_package_hash: hash("01"),
            signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: frost_identifier(1),
                },
                DkgSignerBinding {
                    signer_id: "c".to_string(),
                    frost_identifier_hex: frost_identifier(2),
                },
                DkgSignerBinding {
                    signer_id: "d".to_string(),
                    frost_identifier_hex: frost_identifier(3),
                },
            ],
            round1_packages_root: hash("02"),
            round2_packages_root: hash("03"),
            signer_ack_root: hash("04"),
            recovery_data_hash: hash("05"),
        };

        let err = epoch.attach_dkg_transcript(transcript).unwrap_err();

        assert!(matches!(err, VaultError::InvalidTranscriptThreshold { .. }));
    }

    #[test]
    fn dkg_transcript_must_bind_every_signer_to_unique_frost_identifier() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let mut epoch = VaultEpoch {
            epoch_id: 8,
            starts_at,
            signer_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            threshold: 3,
            frost_group_key_xonly: None,
            dkg_transcript_hash: None,
            dkg_public_key_package_hash: None,
            frost_signer_bindings: Vec::new(),
        };
        let transcript = DkgTranscript {
            epoch_id: 8,
            threshold: 3,
            signer_ids: epoch.signer_ids.clone(),
            frost_group_key_xonly: key("ab"),
            public_key_package_hash: hash("01"),
            signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "c".to_string(),
                    frost_identifier_hex: frost_identifier(2),
                },
            ],
            round1_packages_root: hash("02"),
            round2_packages_root: hash("03"),
            signer_ack_root: hash("04"),
            recovery_data_hash: hash("05"),
        };

        let err = epoch.attach_dkg_transcript(transcript).unwrap_err();

        assert!(matches!(
            err,
            VaultError::DuplicateFrostIdentifierBinding { .. }
        ));
    }

    #[test]
    fn dkg_transcript_rejects_duplicate_signer_ids() {
        let transcript = DkgTranscript {
            epoch_id: 8,
            threshold: 2,
            signer_ids: vec!["a".to_string(), "a".to_string(), "b".to_string()],
            frost_group_key_xonly: key("ab"),
            public_key_package_hash: hash("01"),
            signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: frost_identifier(1),
                },
            ],
            round1_packages_root: hash("02"),
            round2_packages_root: hash("03"),
            signer_ack_root: hash("04"),
            recovery_data_hash: hash("05"),
        };

        let err = transcript.normalized().unwrap_err();

        assert!(matches!(err, VaultError::DuplicateSignerId { .. }));
    }

    #[test]
    fn dkg_transcript_must_use_deterministic_frost_identifier_order() {
        let starts_at = Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap();
        let mut epoch = VaultEpoch {
            epoch_id: 8,
            starts_at,
            signer_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            threshold: 3,
            frost_group_key_xonly: None,
            dkg_transcript_hash: None,
            dkg_public_key_package_hash: None,
            frost_signer_bindings: Vec::new(),
        };
        let transcript = DkgTranscript {
            epoch_id: 8,
            threshold: 3,
            signer_ids: epoch.signer_ids.clone(),
            frost_group_key_xonly: key("ab"),
            public_key_package_hash: hash("01"),
            signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: frost_identifier(1),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                },
                DkgSignerBinding {
                    signer_id: "c".to_string(),
                    frost_identifier_hex: frost_identifier(2),
                },
            ],
            round1_packages_root: hash("02"),
            round2_packages_root: hash("03"),
            signer_ack_root: hash("04"),
            recovery_data_hash: hash("05"),
        };

        let err = epoch.attach_dkg_transcript(transcript).unwrap_err();

        assert!(matches!(err, VaultError::SignerBindingMismatch));
    }

    #[test]
    fn withdrawal_spend_plan_conserves_amounts_and_hashes_deterministically() {
        let group_key = xonly_key(1);
        let epoch = make_epoch(9, 4, &group_key);
        let batch = build_withdrawal_batch(
            vec![
                withdrawal_request("b", 20_000),
                withdrawal_request("a", 10_000),
            ],
            2,
            1,
            1,
        )
        .unwrap();
        let input_total = 50_000;
        let remainder = input_total - 30_000;

        let left = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![
                input("ff", 1, 25_000, &group_key),
                input("aa", 0, 25_000, &group_key),
            ],
            batch.clone(),
            Some(VaultRemainderOutput::same_epoch_change(
                epoch.epoch_id,
                group_key.to_ascii_uppercase(),
                remainder,
            )),
        )
        .unwrap();
        let right = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![
                input("aa", 0, 25_000, &group_key),
                input("ff", 1, 25_000, &group_key),
            ],
            batch,
            Some(VaultRemainderOutput::same_epoch_change(
                epoch.epoch_id,
                group_key.clone(),
                remainder,
            )),
        )
        .unwrap();

        assert_eq!(left.input_total_sats().unwrap(), input_total);
        assert_eq!(
            left.withdrawal_net_total_sats().unwrap(),
            30_000 - left.tx_fee_sats
        );
        assert_eq!(left.plan_hash(), right.plan_hash());
    }

    #[test]
    fn withdrawal_signing_session_requires_ledger_reservation() {
        let group_key = xonly_key(12);
        let epoch = make_epoch(9, 4, &group_key);
        let request = withdrawal_request("a", 20_000);
        let batch = build_withdrawal_batch(vec![request.clone()], 1, 1, 1).unwrap();
        let plan = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![input("aa", 0, 25_000, &group_key)],
            batch.clone(),
            Some(VaultRemainderOutput::same_epoch_change(
                epoch.epoch_id,
                group_key,
                5_000,
            )),
        )
        .unwrap();

        let err = VaultSigningSession::new(&epoch, plan.clone(), vec![sighash("01")]).unwrap_err();

        assert_eq!(err, VaultError::UnreservedWithdrawalBatch);

        let mut state = SharechainReplayState::default();
        let mut ledger = crate::ledger::ClaimLedger::default();
        ledger
            .apply_vault_allocation(&crate::payout::VaultAllocation {
                miner_id: request.claim_owner_id.clone(),
                claim_owner_id: request.claim_owner_id.clone(),
                amount_sats: 25_000,
            })
            .unwrap();
        state.replace_claim_ledger(ledger);
        state
            .apply_message(&crate::sharechain::SharechainMessage::WithdrawalRequest(
                request,
            ))
            .unwrap();

        let plan_with_unaccepted_batch = plan.clone();
        let err = VaultSigningSession::new_with_reserved_withdrawals(
            &epoch,
            plan_with_unaccepted_batch,
            vec![sighash("01")],
            &state,
            1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VaultError::UnverifiedWithdrawalBatch(SharechainReplayError::UnknownWithdrawalBatch(_))
        ));

        state
            .apply_message(&crate::sharechain::SharechainMessage::WithdrawalBatch(
                batch,
            ))
            .unwrap();
        let session = VaultSigningSession::new_with_reserved_withdrawals(
            &epoch,
            plan,
            vec![sighash("01")],
            &state,
            1,
        )
        .unwrap();
        assert_eq!(session.spend_plan_hash, session.spend_plan.plan_hash());
    }

    #[test]
    fn vault_spend_rejects_batch_input_count_mismatch() {
        let group_key = xonly_key(13);
        let epoch = make_epoch(9, 4, &group_key);
        let batch = build_withdrawal_batch(vec![withdrawal_request("a", 20_000)], 1, 1, 1).unwrap();

        let err = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![
                input("aa", 0, 10_000, &group_key),
                input("bb", 0, 10_000, &group_key),
            ],
            batch,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::BatchInputCountMismatch { .. }));
    }

    #[test]
    fn vault_spend_rejects_tampered_withdrawal_output_math() {
        let group_key = xonly_key(14);
        let epoch = make_epoch(9, 4, &group_key);
        let mut batch =
            build_withdrawal_batch(vec![withdrawal_request("a", 20_000)], 1, 1, 1).unwrap();
        batch.outputs[0].net_amount_sats += 1;

        let err = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![input("aa", 0, 20_000, &group_key)],
            batch,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VaultError::WithdrawalOutputNetMismatch { .. }
        ));
    }

    #[test]
    fn vault_spend_rejects_tampered_withdrawal_batch_estimate() {
        let group_key = xonly_key(15);
        let epoch = make_epoch(9, 4, &group_key);
        let mut batch =
            build_withdrawal_batch(vec![withdrawal_request("a", 20_000)], 1, 1, 1).unwrap();
        batch.estimated_vsize += 1;

        let err = VaultSpendPlan::withdrawal_batch(
            &epoch,
            vec![input("aa", 0, 20_000, &group_key)],
            batch,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::BatchVsizeMismatch { .. }));
    }

    #[test]
    fn rotation_moves_all_matured_inputs_to_next_epoch_after_fee() {
        let current_key = xonly_key(2);
        let next_key = xonly_key(3);
        let current = make_epoch(10, 4, &current_key);
        let next = make_epoch(11, 5, &next_key);

        let plan = VaultSpendPlan::rotation(
            &current,
            &next,
            vec![
                input("cc", 0, 40_000, &current_key),
                input("dd", 1, 10_000, &current_key),
            ],
            750,
        )
        .unwrap();

        assert!(plan.withdrawal_batch.is_none());
        assert_eq!(plan.tx_fee_sats, 750);
        assert_eq!(
            plan.vault_remainder,
            Some(VaultRemainderOutput::next_epoch_rotation(
                11, next_key, 49_250
            ))
        );
        assert!(plan.validate_against_epoch(&current).is_ok());
    }

    #[test]
    fn vault_spend_rejects_immature_or_duplicate_inputs() {
        let current_key = xonly_key(4);
        let next_key = xonly_key(5);
        let current = make_epoch(10, 4, &current_key);
        let next = make_epoch(11, 5, &next_key);
        let mut immature = input("cc", 0, 100_000, &current_key);
        immature.confirmations = MIN_VAULT_INPUT_CONFIRMATIONS - 1;

        let err = VaultSpendPlan::rotation(&current, &next, vec![immature], 750).unwrap_err();

        assert!(matches!(
            err,
            VaultError::InsufficientInputConfirmations { .. }
        ));

        let duplicate = input("dd", 0, 50_000, &current_key);
        let err =
            VaultSpendPlan::rotation(&current, &next, vec![duplicate.clone(), duplicate], 750)
                .unwrap_err();

        assert!(matches!(err, VaultError::DuplicateVaultInput { .. }));
    }

    #[test]
    fn vault_spend_rejects_wrong_input_script_pubkey() {
        let current_key = xonly_key(10);
        let wrong_key = xonly_key(11);
        let next_key = xonly_key(12);
        let current = make_epoch(10, 4, &current_key);
        let next = make_epoch(11, 5, &next_key);
        let input = input("ee", 0, 100_000, &wrong_key);

        let err = VaultSpendPlan::rotation(&current, &next, vec![input], 750).unwrap_err();

        assert!(matches!(err, VaultError::VaultInputScriptMismatch { .. }));
    }

    #[test]
    fn signing_session_rejects_raw_shares_even_from_epoch_signers() {
        let current_key = xonly_key(6);
        let next_key = xonly_key(7);
        let epoch = make_epoch(12, 4, &current_key);
        let plan = VaultSpendPlan::rotation(
            &epoch,
            &make_epoch(13, 4, &next_key),
            vec![input("aa", 0, 100_000, &current_key)],
            1_000,
        )
        .unwrap();
        let mut session = VaultSigningSession::new(&epoch, plan, vec![sighash("01")]).unwrap();
        let plan_hash = session.spend_plan_hash.clone();

        assert_eq!(session.threshold, 3);
        assert!(matches!(
            session.approval(),
            Err(VaultError::NotEnoughSignatureShares { .. })
        ));
        assert!(matches!(
            session.add_signature_share(FrostSignatureShare {
                signer_id: "outsider".to_string(),
                frost_identifier_hex: frost_identifier(0),
                public_key_package_hash: dkg_package_hash(),
                spend_plan_hash: plan_hash.clone(),
                input_index: 0,
                sighash_hex: sighash("01"),
                signature_share_hex: signature_share("aa"),
            }),
            Err(VaultError::SignerNotInEpoch { .. })
        ));
        assert!(matches!(
            session.add_signature_share(FrostSignatureShare {
                signer_id: "signer-00".to_string(),
                frost_identifier_hex: frost_identifier(0),
                public_key_package_hash: dkg_package_hash(),
                spend_plan_hash: "00".repeat(32),
                input_index: 0,
                sighash_hex: sighash("01"),
                signature_share_hex: signature_share("aa"),
            }),
            Err(VaultError::WrongSpendPlanHash)
        ));

        assert!(matches!(
            session.add_signature_share(FrostSignatureShare {
                signer_id: "signer-00".to_string(),
                frost_identifier_hex: frost_identifier(0),
                public_key_package_hash: dkg_package_hash(),
                spend_plan_hash: plan_hash.clone(),
                input_index: 0,
                sighash_hex: sighash("01"),
                signature_share_hex: signature_share("aa"),
            }),
            Err(VaultError::UnverifiedSignatureShare { .. })
        ));
        assert_eq!(session.signature_share_count(), 0);
        assert!(!session.is_ready());
        assert!(matches!(
            session.approval(),
            Err(VaultError::NotEnoughSignatureShares { .. })
        ));
    }

    #[test]
    fn verified_signature_shares_can_form_internal_approval() {
        let current_key = xonly_key(8);
        let next_key = xonly_key(9);
        let epoch = make_epoch(12, 4, &current_key);
        let plan = VaultSpendPlan::rotation(
            &epoch,
            &make_epoch(13, 4, &next_key),
            vec![input("aa", 0, 100_000, &current_key)],
            1_000,
        )
        .unwrap();
        let mut session = VaultSigningSession::new(&epoch, plan, vec![sighash("02")]).unwrap();
        let plan_hash = session.spend_plan_hash.clone();

        for (signer_id, byte) in [
            ("signer-00", "aa"),
            ("signer-01", "bb"),
            ("signer-02", "cc"),
        ] {
            let share = VerifiedFrostSignatureShare::from_verified_share(FrostSignatureShare {
                signer_id: signer_id.to_string(),
                frost_identifier_hex: frost_identifier(
                    signer_id
                        .strip_prefix("signer-")
                        .unwrap()
                        .parse::<usize>()
                        .unwrap(),
                ),
                public_key_package_hash: dkg_package_hash(),
                spend_plan_hash: plan_hash.clone(),
                input_index: 0,
                sighash_hex: sighash("02"),
                signature_share_hex: signature_share(byte),
            })
            .unwrap();
            session.add_verified_signature_share(share).unwrap();
        }

        assert!(matches!(
            session.add_verified_signature_share(
                VerifiedFrostSignatureShare::from_verified_share(FrostSignatureShare {
                    signer_id: "signer-00".to_string(),
                    frost_identifier_hex: frost_identifier(0),
                    public_key_package_hash: dkg_package_hash(),
                    spend_plan_hash: plan_hash.clone(),
                    input_index: 0,
                    sighash_hex: sighash("02"),
                    signature_share_hex: signature_share("dd"),
                })
                .unwrap()
            ),
            Err(VaultError::DuplicateSignatureShare { .. })
        ));
        assert!(session.is_ready());

        let approval = session.approval().unwrap();
        assert_eq!(approval.spend_plan_hash, plan_hash);
        assert_eq!(approval.signature_shares.len(), 3);
        assert_eq!(
            approval.signer_ids,
            vec!["signer-00", "signer-01", "signer-02"]
        );
        assert_eq!(approval.input_signer_ids.len(), 1);
        assert_eq!(
            approval.input_signer_ids[0].signer_ids,
            vec!["signer-00", "signer-01", "signer-02"]
        );
    }

    #[test]
    fn signing_session_rejects_verified_share_with_wrong_dkg_binding() {
        let current_key = xonly_key(13);
        let next_key = xonly_key(14);
        let epoch = make_epoch(14, 4, &current_key);
        let plan = VaultSpendPlan::rotation(
            &epoch,
            &make_epoch(15, 4, &next_key),
            vec![input("aa", 0, 100_000, &current_key)],
            1_000,
        )
        .unwrap();
        let mut session =
            VaultSigningSession::new(&epoch, plan.clone(), vec![sighash("03")]).unwrap();

        let wrong_identifier =
            VerifiedFrostSignatureShare::from_verified_share(FrostSignatureShare {
                signer_id: "signer-00".to_string(),
                frost_identifier_hex: frost_identifier(1),
                public_key_package_hash: dkg_package_hash(),
                spend_plan_hash: plan.plan_hash(),
                input_index: 0,
                sighash_hex: sighash("03"),
                signature_share_hex: signature_share("aa"),
            })
            .unwrap();
        assert!(matches!(
            session.add_verified_signature_share(wrong_identifier),
            Err(VaultError::WrongFrostIdentifier { .. })
        ));

        let wrong_package = VerifiedFrostSignatureShare::from_verified_share(FrostSignatureShare {
            signer_id: "signer-00".to_string(),
            frost_identifier_hex: frost_identifier(0),
            public_key_package_hash: hash("98"),
            spend_plan_hash: plan.plan_hash(),
            input_index: 0,
            sighash_hex: sighash("03"),
            signature_share_hex: signature_share("aa"),
        })
        .unwrap();
        assert!(matches!(
            session.add_verified_signature_share(wrong_package),
            Err(VaultError::WrongPublicKeyPackageHash { .. })
        ));
    }

    #[test]
    fn signing_session_rejects_duplicate_epoch_signer_ids() {
        let current_key = xonly_key(15);
        let mut epoch = make_epoch(16, 3, &current_key);
        epoch.signer_ids = vec![
            "signer-00".to_string(),
            "signer-00".to_string(),
            "signer-01".to_string(),
        ];
        let plan = VaultSpendPlan::rotation(
            &make_epoch(16, 3, &current_key),
            &make_epoch(17, 3, &xonly_key(16)),
            vec![input("ee", 0, 100_000, &current_key)],
            1_000,
        )
        .unwrap();

        let err = VaultSigningSession::new(&epoch, plan, vec![sighash("15")]).unwrap_err();

        assert!(matches!(err, VaultError::DuplicateSignerId { .. }));
    }

    #[test]
    fn frost_signature_share_rejects_invalid_signer_id() {
        let share = FrostSignatureShare {
            signer_id: "../signer-00".to_string(),
            frost_identifier_hex: frost_identifier(0),
            public_key_package_hash: hash("10"),
            spend_plan_hash: hash("11"),
            input_index: 0,
            sighash_hex: sighash("12"),
            signature_share_hex: signature_share("aa"),
        };

        let err = share.normalized().unwrap_err();

        assert!(matches!(err, VaultError::InvalidSignerId(_)));
    }
}
