use bitcoin::key::{Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr::Signature, Message};
use bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::{canonical_json, hash_hex, sha256_tagged, Sats};

pub const MIN_WITHDRAWAL_REQUEST_SATS: Sats = 10_000;
pub const P2WPKH_DUST_SATS: Sats = 546;
pub const P2TR_DUST_SATS: Sats = 330;
const MAX_WITHDRAWAL_REQUEST_ID_LEN: usize = 64;
const SCHNORR_SIGNATURE_HEX_LEN: usize = 128;
const P2WPKH_SCRIPT_HEX_LEN: usize = 44;
const P2TR_SCRIPT_HEX_LEN: usize = 68;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalOutputKind {
    P2wpkh,
    P2tr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub request_id: String,
    pub claim_owner_id: String,
    pub claim_owner_pubkey_hex: String,
    pub destination_script_hex: String,
    pub amount_sats: Sats,
    pub max_fee_rate_sat_vb: u64,
    pub nonce: u64,
    pub expiry_height: u64,
    pub signature_hex: Option<String>,
    pub output_kind: WithdrawalOutputKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalOutput {
    pub request_id: String,
    pub destination_script_hex: String,
    pub output_kind: WithdrawalOutputKind,
    pub gross_amount_sats: Sats,
    pub fee_sats: Sats,
    pub net_amount_sats: Sats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalBatch {
    pub inputs: usize,
    pub fee_rate_sat_vb: u64,
    pub estimated_vsize: u64,
    pub total_fee_sats: Sats,
    pub outputs: Vec<WithdrawalOutput>,
}

impl WithdrawalOutput {
    pub fn normalized(mut self) -> Self {
        self.destination_script_hex = self.destination_script_hex.to_ascii_lowercase();
        self
    }
}

impl WithdrawalBatch {
    pub fn normalized(mut self) -> Self {
        self.outputs = self
            .outputs
            .into_iter()
            .map(WithdrawalOutput::normalized)
            .collect();
        self.outputs
            .sort_by(|left, right| left.request_id.cmp(&right.request_id));
        self
    }

    pub fn batch_hash(&self) -> String {
        let batch = self.clone().normalized();
        hash_hex(sha256_tagged(
            b"POHW1_WITHDRAWAL_BATCH",
            &canonical_json(&batch),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WithdrawalError {
    #[error("withdrawal batch needs at least one request")]
    EmptyBatch,
    #[error("withdrawal batch needs at least one input")]
    InputCountZero,
    #[error("withdrawal request {request_id} appears more than once in a batch")]
    DuplicateRequest { request_id: String },
    #[error("withdrawal request id {request_id:?} is invalid: {reason}")]
    InvalidRequestId { request_id: String, reason: String },
    #[error("withdrawal {request_id} has expired at height {expiry_height}, current height {current_height}")]
    Expired {
        request_id: String,
        expiry_height: u64,
        current_height: u64,
    },
    #[error("withdrawal {request_id} amount {amount_sats} is below minimum {minimum_sats}")]
    AmountBelowMinimum {
        request_id: String,
        amount_sats: Sats,
        minimum_sats: Sats,
    },
    #[error("withdrawal {request_id} net output {net_amount_sats} is dust for {output_kind:?}")]
    DustOutput {
        request_id: String,
        net_amount_sats: Sats,
        output_kind: WithdrawalOutputKind,
    },
    #[error("withdrawal {request_id} destination script is invalid for {output_kind:?}: {reason}")]
    InvalidDestinationScript {
        request_id: String,
        output_kind: WithdrawalOutputKind,
        reason: String,
    },
    #[error("withdrawal {request_id} is missing an owner signature")]
    MissingSignature { request_id: String },
    #[error("withdrawal {request_id} owner pubkey is invalid: {reason}")]
    InvalidOwnerPubkey { request_id: String, reason: String },
    #[error("withdrawal {request_id} claim owner id must equal the owner x-only pubkey used as the non-transferable claim key")]
    OwnerIdPubkeyMismatch { request_id: String },
    #[error("withdrawal {request_id} owner signature is invalid: {reason}")]
    InvalidSignature { request_id: String, reason: String },
    #[error("fee rate {fee_rate_sat_vb} exceeds request {request_id} max {max_fee_rate_sat_vb}")]
    FeeRateTooHigh {
        request_id: String,
        fee_rate_sat_vb: u64,
        max_fee_rate_sat_vb: u64,
    },
    #[error("withdrawal {request_id} amount {amount_sats} cannot pay assigned fee {fee_sats}")]
    FeeExceedsAmount {
        request_id: String,
        amount_sats: Sats,
        fee_sats: Sats,
    },
    #[error("withdrawal batch vsize estimate overflow")]
    VsizeOverflow,
    #[error("withdrawal fee estimate overflow")]
    FeeOverflow,
}

#[derive(Debug, Clone, Serialize)]
struct WithdrawalSigningPayload {
    request_id: String,
    claim_owner_id: String,
    claim_owner_pubkey_hex: String,
    destination_script_hex: String,
    amount_sats: Sats,
    max_fee_rate_sat_vb: u64,
    nonce: u64,
    expiry_height: u64,
    output_kind: WithdrawalOutputKind,
}

impl WithdrawalRequest {
    pub fn normalized(mut self) -> Self {
        self.claim_owner_id = self.claim_owner_id.to_ascii_lowercase();
        self.claim_owner_pubkey_hex = self.claim_owner_pubkey_hex.to_ascii_lowercase();
        self.destination_script_hex = self.destination_script_hex.to_ascii_lowercase();
        if let Some(signature_hex) = &mut self.signature_hex {
            *signature_hex = signature_hex.to_ascii_lowercase();
        }
        self
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let payload = WithdrawalSigningPayload {
            request_id: self.request_id.clone(),
            claim_owner_id: self.claim_owner_id.to_ascii_lowercase(),
            claim_owner_pubkey_hex: self.claim_owner_pubkey_hex.to_ascii_lowercase(),
            destination_script_hex: self.destination_script_hex.to_ascii_lowercase(),
            amount_sats: self.amount_sats,
            max_fee_rate_sat_vb: self.max_fee_rate_sat_vb,
            nonce: self.nonce,
            expiry_height: self.expiry_height,
            output_kind: self.output_kind.clone(),
        };
        sha256_tagged(b"POHW1_WITHDRAWAL_REQUEST", &canonical_json(&payload))
    }

    pub fn validate(&self, current_height: u64) -> Result<(), WithdrawalError> {
        let request = self.clone().normalized();
        validate_request_id(&request.request_id)?;
        if current_height > request.expiry_height {
            return Err(WithdrawalError::Expired {
                request_id: request.request_id,
                expiry_height: request.expiry_height,
                current_height,
            });
        }
        if request.amount_sats < MIN_WITHDRAWAL_REQUEST_SATS {
            return Err(WithdrawalError::AmountBelowMinimum {
                request_id: request.request_id,
                amount_sats: request.amount_sats,
                minimum_sats: MIN_WITHDRAWAL_REQUEST_SATS,
            });
        }
        if request.claim_owner_id != request.claim_owner_pubkey_hex {
            return Err(WithdrawalError::OwnerIdPubkeyMismatch {
                request_id: request.request_id,
            });
        }
        request.validate_destination_script(request.amount_sats)?;
        request.verify_owner_signature()
    }

    fn validate_destination_script(&self, net_amount_sats: Sats) -> Result<(), WithdrawalError> {
        validate_destination_script_policy(
            &self.request_id,
            &self.destination_script_hex,
            &self.output_kind,
            net_amount_sats,
        )
    }

    fn verify_owner_signature(&self) -> Result<(), WithdrawalError> {
        let signature_hex =
            self.signature_hex
                .as_deref()
                .ok_or_else(|| WithdrawalError::MissingSignature {
                    request_id: self.request_id.clone(),
                })?;
        validate_hex_exact(signature_hex, SCHNORR_SIGNATURE_HEX_LEN, || {
            WithdrawalError::InvalidSignature {
                request_id: self.request_id.clone(),
                reason: format!("signature must be {SCHNORR_SIGNATURE_HEX_LEN} hex characters"),
            }
        })?;
        let owner_pubkey =
            XOnlyPublicKey::from_str(&self.claim_owner_pubkey_hex).map_err(|err| {
                WithdrawalError::InvalidOwnerPubkey {
                    request_id: self.request_id.clone(),
                    reason: err.to_string(),
                }
            })?;
        let signature_bytes =
            hex::decode(signature_hex).map_err(|err| WithdrawalError::InvalidSignature {
                request_id: self.request_id.clone(),
                reason: err.to_string(),
            })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|err| {
            WithdrawalError::InvalidSignature {
                request_id: self.request_id.clone(),
                reason: err.to_string(),
            }
        })?;
        let message = Message::from_digest(self.signing_hash());
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &owner_pubkey)
            .map_err(|err| WithdrawalError::InvalidSignature {
                request_id: self.request_id.clone(),
                reason: err.to_string(),
            })
    }
}

pub fn estimate_batch_vsize(
    inputs: usize,
    p2wpkh_outputs: usize,
    p2tr_outputs: usize,
) -> Result<u64, WithdrawalError> {
    let inputs = u64::try_from(inputs).map_err(|_| WithdrawalError::VsizeOverflow)?;
    let p2wpkh_outputs =
        u64::try_from(p2wpkh_outputs).map_err(|_| WithdrawalError::VsizeOverflow)?;
    let p2tr_outputs = u64::try_from(p2tr_outputs).map_err(|_| WithdrawalError::VsizeOverflow)?;
    let input_weight = 115u64
        .checked_mul(inputs)
        .ok_or(WithdrawalError::VsizeOverflow)?;
    let p2wpkh_weight = 62u64
        .checked_mul(p2wpkh_outputs)
        .ok_or(WithdrawalError::VsizeOverflow)?;
    let p2tr_weight = 86u64
        .checked_mul(p2tr_outputs)
        .ok_or(WithdrawalError::VsizeOverflow)?;
    let weight_x2 = 21u64
        .checked_add(input_weight)
        .and_then(|weight| weight.checked_add(p2wpkh_weight))
        .and_then(|weight| weight.checked_add(p2tr_weight))
        .ok_or(WithdrawalError::VsizeOverflow)?;
    Ok(weight_x2.div_ceil(2))
}

pub fn estimate_fee_sats(vsize: u64, fee_rate_sat_vb: u64) -> Result<Sats, WithdrawalError> {
    vsize
        .checked_mul(fee_rate_sat_vb)
        .ok_or(WithdrawalError::FeeOverflow)
}

pub fn validate_destination_script_policy(
    request_id: &str,
    destination_script_hex: &str,
    output_kind: &WithdrawalOutputKind,
    net_amount_sats: Sats,
) -> Result<(), WithdrawalError> {
    validate_request_id(request_id)?;
    if net_amount_sats < dust_threshold(output_kind) {
        return Err(WithdrawalError::DustOutput {
            request_id: request_id.to_string(),
            net_amount_sats,
            output_kind: output_kind.clone(),
        });
    }

    let expected_hex_len = match output_kind {
        WithdrawalOutputKind::P2wpkh => P2WPKH_SCRIPT_HEX_LEN,
        WithdrawalOutputKind::P2tr => P2TR_SCRIPT_HEX_LEN,
    };
    validate_hex_exact(destination_script_hex, expected_hex_len, || {
        WithdrawalError::InvalidDestinationScript {
            request_id: request_id.to_string(),
            output_kind: output_kind.clone(),
            reason: format!("script must be {expected_hex_len} hex characters"),
        }
    })?;
    let script_bytes = hex::decode(destination_script_hex).map_err(|err| {
        WithdrawalError::InvalidDestinationScript {
            request_id: request_id.to_string(),
            output_kind: output_kind.clone(),
            reason: err.to_string(),
        }
    })?;
    let script = ScriptBuf::from_bytes(script_bytes);
    let matches_kind = match output_kind {
        WithdrawalOutputKind::P2wpkh => script.is_p2wpkh(),
        WithdrawalOutputKind::P2tr => script.is_p2tr(),
    };
    if !matches_kind {
        return Err(WithdrawalError::InvalidDestinationScript {
            request_id: request_id.to_string(),
            output_kind: output_kind.clone(),
            reason: "script template does not match output kind".to_string(),
        });
    }
    Ok(())
}

pub fn build_withdrawal_batch(
    mut requests: Vec<WithdrawalRequest>,
    inputs: usize,
    fee_rate_sat_vb: u64,
    current_height: u64,
) -> Result<WithdrawalBatch, WithdrawalError> {
    if requests.is_empty() {
        return Err(WithdrawalError::EmptyBatch);
    }
    if inputs == 0 {
        return Err(WithdrawalError::InputCountZero);
    }

    requests = requests
        .into_iter()
        .map(WithdrawalRequest::normalized)
        .collect();
    requests.sort_by(|a, b| a.request_id.cmp(&b.request_id));
    for pair in requests.windows(2) {
        if pair[0].request_id == pair[1].request_id {
            return Err(WithdrawalError::DuplicateRequest {
                request_id: pair[0].request_id.clone(),
            });
        }
    }

    for request in &requests {
        request.validate(current_height)?;
        if fee_rate_sat_vb > request.max_fee_rate_sat_vb {
            return Err(WithdrawalError::FeeRateTooHigh {
                request_id: request.request_id.clone(),
                fee_rate_sat_vb,
                max_fee_rate_sat_vb: request.max_fee_rate_sat_vb,
            });
        }
    }

    let p2wpkh_outputs = requests
        .iter()
        .filter(|r| r.output_kind == WithdrawalOutputKind::P2wpkh)
        .count();
    let p2tr_outputs = requests.len() - p2wpkh_outputs;
    let estimated_vsize = estimate_batch_vsize(inputs, p2wpkh_outputs, p2tr_outputs)?;
    let total_fee_sats = estimate_fee_sats(estimated_vsize, fee_rate_sat_vb)?;
    let base_fee = total_fee_sats / requests.len() as Sats;
    let mut remainder = total_fee_sats % requests.len() as Sats;

    let mut outputs = Vec::with_capacity(requests.len());
    for request in requests {
        let mut fee_sats = base_fee;
        if remainder > 0 {
            fee_sats += 1;
            remainder -= 1;
        }
        if request.amount_sats <= fee_sats {
            return Err(WithdrawalError::FeeExceedsAmount {
                request_id: request.request_id,
                amount_sats: request.amount_sats,
                fee_sats,
            });
        }
        request.validate_destination_script(request.amount_sats - fee_sats)?;

        outputs.push(WithdrawalOutput {
            request_id: request.request_id,
            destination_script_hex: request.destination_script_hex,
            output_kind: request.output_kind,
            gross_amount_sats: request.amount_sats,
            fee_sats,
            net_amount_sats: request.amount_sats - fee_sats,
        });
    }

    Ok(WithdrawalBatch {
        inputs,
        fee_rate_sat_vb,
        estimated_vsize,
        total_fee_sats,
        outputs,
    })
}

fn validate_request_id(request_id: &str) -> Result<(), WithdrawalError> {
    if request_id.is_empty() || request_id.len() > MAX_WITHDRAWAL_REQUEST_ID_LEN {
        return Err(WithdrawalError::InvalidRequestId {
            request_id: request_id.to_string(),
            reason: format!("must be 1-{MAX_WITHDRAWAL_REQUEST_ID_LEN} characters"),
        });
    }
    if !request_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WithdrawalError::InvalidRequestId {
            request_id: request_id.to_string(),
            reason: "must contain only ASCII letters, digits, '-', '_' or '.'".to_string(),
        });
    }
    Ok(())
}

fn validate_hex_exact<E>(
    value: &str,
    expected_len: usize,
    error: impl FnOnce() -> E,
) -> Result<(), E> {
    if value.len() != expected_len || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error());
    }
    Ok(())
}

fn dust_threshold(output_kind: &WithdrawalOutputKind) -> Sats {
    match output_kind {
        WithdrawalOutputKind::P2wpkh => P2WPKH_DUST_SATS,
        WithdrawalOutputKind::P2tr => P2TR_DUST_SATS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn request(id: &str, amount_sats: Sats) -> WithdrawalRequest {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let claim_owner_pubkey_hex = keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex: "00140000000000000000000000000000000000000000".to_string(),
            amount_sats,
            max_fee_rate_sat_vb: 100,
            nonce: 1,
            expiry_height: 100,
            signature_hex: None,
            output_kind: WithdrawalOutputKind::P2wpkh,
        };
        sign_request(&mut request, &keypair);
        request
    }

    fn sign_request(request: &mut WithdrawalRequest, keypair: &Keypair) {
        let secp = Secp256k1::new();
        let message = Message::from_digest(request.signing_hash());
        let signature = secp.sign_schnorr_no_aux_rand(&message, keypair);
        request.signature_hex = Some(hex::encode(signature.serialize()));
    }

    fn unsigned_request(id: &str, amount_sats: Sats) -> WithdrawalRequest {
        let claim_owner_pubkey_hex = "00".repeat(32);
        WithdrawalRequest {
            request_id: id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex: "00140000000000000000000000000000000000000000".to_string(),
            amount_sats,
            max_fee_rate_sat_vb: 100,
            nonce: 0,
            expiry_height: 100,
            signature_hex: None,
            output_kind: WithdrawalOutputKind::P2wpkh,
        }
    }

    #[test]
    fn vsize_formula_matches_plan_example() {
        assert_eq!(estimate_batch_vsize(1, 100, 0).unwrap(), 3_168);
    }

    #[test]
    fn fees_are_deducted_from_withdrawals() {
        let batch =
            build_withdrawal_batch(vec![request("b", 10_000), request("a", 10_000)], 1, 1, 1)
                .unwrap();

        assert_eq!(batch.total_fee_sats, estimate_batch_vsize(1, 2, 0).unwrap());
        assert_eq!(batch.outputs[0].request_id, "a");
        assert_eq!(
            batch.outputs.iter().map(|o| o.fee_sats).sum::<Sats>(),
            batch.total_fee_sats
        );
    }

    #[test]
    fn fee_spike_can_make_small_withdrawal_uneconomic() {
        let mut request = request("a", 10_000);
        request.max_fee_rate_sat_vb = 200;
        sign_request(
            &mut request,
            &Keypair::from_seckey_slice(&Secp256k1::new(), &[7; 32]).unwrap(),
        );
        let err = build_withdrawal_batch(vec![request], 1, 150, 1).unwrap_err();
        assert!(matches!(err, WithdrawalError::FeeExceedsAmount { .. }));
    }

    #[test]
    fn withdrawal_batch_rejects_zero_inputs() {
        let err = build_withdrawal_batch(vec![request("a", 10_000)], 0, 1, 1).unwrap_err();
        assert!(matches!(err, WithdrawalError::InputCountZero));
    }

    #[test]
    fn withdrawal_batch_rejects_duplicate_request_ids() {
        let err = build_withdrawal_batch(
            vec![request("duplicate", 10_000), request("duplicate", 20_000)],
            1,
            1,
            1,
        )
        .unwrap_err();

        assert!(matches!(err, WithdrawalError::DuplicateRequest { .. }));
    }

    #[test]
    fn unsigned_withdrawal_is_rejected() {
        let err = build_withdrawal_batch(vec![unsigned_request("a", 10_000)], 1, 1, 1).unwrap_err();
        assert!(matches!(err, WithdrawalError::MissingSignature { .. }));
    }

    #[test]
    fn malformed_withdrawal_identifiers_and_signatures_are_rejected() {
        let err = build_withdrawal_batch(vec![request("bad id", 10_000)], 1, 1, 1).unwrap_err();
        assert!(matches!(err, WithdrawalError::InvalidRequestId { .. }));

        let mut request = request("a", 10_000);
        request.signature_hex = Some("aa".to_string());
        let err = build_withdrawal_batch(vec![request], 1, 1, 1).unwrap_err();
        assert!(matches!(err, WithdrawalError::InvalidSignature { .. }));
    }

    #[test]
    fn oversized_destination_script_is_rejected_before_decode() {
        let mut request = request("a", 10_000);
        request.destination_script_hex = "00".repeat(10_000);
        let keypair = Keypair::from_seckey_slice(&Secp256k1::new(), &[7; 32]).unwrap();
        sign_request(&mut request, &keypair);

        let err = build_withdrawal_batch(vec![request], 1, 1, 1).unwrap_err();

        assert!(matches!(
            err,
            WithdrawalError::InvalidDestinationScript { .. }
        ));
    }

    #[test]
    fn expired_withdrawal_is_rejected() {
        let err = build_withdrawal_batch(vec![request("a", 10_000)], 1, 1, 101).unwrap_err();
        assert!(matches!(err, WithdrawalError::Expired { .. }));
    }

    #[test]
    fn output_kind_must_match_script_template() {
        let mut request = request("a", 10_000);
        request.output_kind = WithdrawalOutputKind::P2tr;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
        sign_request(&mut request, &keypair);
        let err = build_withdrawal_batch(vec![request], 1, 1, 1).unwrap_err();
        assert!(matches!(
            err,
            WithdrawalError::InvalidDestinationScript { .. }
        ));
    }

    #[test]
    fn claim_owner_id_must_be_bound_to_owner_pubkey_claim_key() {
        let mut request = request("a", 10_000);
        request.claim_owner_id = "victim".to_string();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap());
        sign_request(&mut request, &keypair);

        let err = build_withdrawal_batch(vec![request], 1, 1, 1).unwrap_err();

        assert!(matches!(err, WithdrawalError::OwnerIdPubkeyMismatch { .. }));
    }

    #[test]
    fn fee_estimate_rejects_overflow() {
        assert!(matches!(
            estimate_fee_sats(u64::MAX, 2),
            Err(WithdrawalError::FeeOverflow)
        ));
    }
}
