use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::psbt::Psbt;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use std::str::FromStr;

use crate::vault::{VaultInput, VaultSpendPlan};
use crate::withdrawal::validate_destination_script_policy;
use crate::Sats;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTransactionPlan {
    pub spend_plan_hash: String,
    pub vault_script_pubkey: ScriptBuf,
    pub unsigned_tx: Transaction,
    pub psbt: Psbt,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultTxError {
    #[error("invalid vault FROST x-only key: {0}")]
    InvalidVaultKey(String),
    #[error("invalid vault input txid {txid}: {reason}")]
    InvalidInputTxid { txid: String, reason: String },
    #[error("invalid destination script for withdrawal {request_id}: {reason}")]
    InvalidDestinationScript { request_id: String, reason: String },
    #[error("withdrawal output {request_id} violates script or dust policy: {reason}")]
    WithdrawalOutputPolicy { request_id: String, reason: String },
    #[error("vault spend plan is internally invalid: {0}")]
    InvalidSpendPlan(String),
    #[error("failed to build PSBT: {0}")]
    Psbt(String),
    #[error("transaction output total overflow")]
    AmountOverflow,
    #[error("missing witness UTXO for input {0}")]
    MissingWitnessUtxo(usize),
    #[error("PSBT input count {psbt_inputs} does not match transaction input count {tx_inputs}")]
    PsbtInputCountMismatch {
        psbt_inputs: usize,
        tx_inputs: usize,
    },
    #[error("taproot sighash error: {0}")]
    TaprootSighash(String),
}

pub fn build_vault_psbt(plan: &VaultSpendPlan) -> Result<VaultTransactionPlan, VaultTxError> {
    plan.validate()
        .map_err(|err| VaultTxError::InvalidSpendPlan(err.to_string()))?;

    let secp = Secp256k1::verification_only();
    let internal_key = XOnlyPublicKey::from_str(&plan.frost_group_key_xonly)
        .map_err(|err| VaultTxError::InvalidVaultKey(err.to_string()))?;
    let vault_script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);

    let inputs = sorted_inputs(&plan.inputs);
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let txid = Txid::from_str(&input.txid).map_err(|err| VaultTxError::InvalidInputTxid {
            txid: input.txid.clone(),
            reason: err.to_string(),
        })?;
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, input.vout),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });
    }

    let mut tx_outputs = Vec::new();
    if let Some(batch) = &plan.withdrawal_batch {
        let mut outputs = batch.outputs.clone();
        outputs.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        for output in outputs {
            validate_destination_script_policy(
                &output.request_id,
                &output.destination_script_hex,
                &output.output_kind,
                output.net_amount_sats,
            )
            .map_err(|err| VaultTxError::WithdrawalOutputPolicy {
                request_id: output.request_id.clone(),
                reason: err.to_string(),
            })?;
            let script_bytes = hex::decode(&output.destination_script_hex).map_err(|err| {
                VaultTxError::InvalidDestinationScript {
                    request_id: output.request_id.clone(),
                    reason: err.to_string(),
                }
            })?;
            tx_outputs.push(TxOut {
                value: Amount::from_sat(output.net_amount_sats),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            });
        }
    }
    if let Some(remainder) = &plan.vault_remainder {
        let remainder_key = XOnlyPublicKey::from_str(&remainder.frost_group_key_xonly)
            .map_err(|err| VaultTxError::InvalidVaultKey(err.to_string()))?;
        tx_outputs.push(TxOut {
            value: Amount::from_sat(remainder.amount_sats),
            script_pubkey: ScriptBuf::new_p2tr(&secp, remainder_key, None),
        });
    }

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx.clone())
        .map_err(|err| VaultTxError::Psbt(err.to_string()))?;
    for (psbt_input, input) in psbt.inputs.iter_mut().zip(inputs) {
        let script_bytes = hex::decode(&input.script_pubkey_hex).map_err(|err| {
            VaultTxError::InvalidSpendPlan(format!(
                "vault input {}:{} scriptPubKey is invalid hex: {err}",
                input.txid, input.vout
            ))
        })?;
        psbt_input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(input.amount_sats),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        });
        psbt_input.tap_internal_key = Some(internal_key);
        psbt_input.sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));
    }

    Ok(VaultTransactionPlan {
        spend_plan_hash: plan.plan_hash(),
        vault_script_pubkey,
        unsigned_tx,
        psbt,
    })
}

pub fn transaction_output_total_sats(tx: &Transaction) -> Result<Sats, VaultTxError> {
    tx.output.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value.to_sat())
            .ok_or(VaultTxError::AmountOverflow)
    })
}

pub fn vault_input_sighashes(tx_plan: &VaultTransactionPlan) -> Result<Vec<String>, VaultTxError> {
    if tx_plan.psbt.inputs.len() != tx_plan.unsigned_tx.input.len() {
        return Err(VaultTxError::PsbtInputCountMismatch {
            psbt_inputs: tx_plan.psbt.inputs.len(),
            tx_inputs: tx_plan.unsigned_tx.input.len(),
        });
    }
    let prevouts = tx_plan
        .psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(VaultTxError::MissingWitnessUtxo(input_index))
        })
        .collect::<Result<Vec<TxOut>, _>>()?;
    let prevouts = Prevouts::All(prevouts.as_slice());
    let mut sighashes = Vec::with_capacity(tx_plan.unsigned_tx.input.len());
    for input_index in 0..tx_plan.unsigned_tx.input.len() {
        let sighash = {
            let mut cache = SighashCache::new(&tx_plan.unsigned_tx);
            cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
                .map_err(|err| VaultTxError::TaprootSighash(err.to_string()))?
        };
        sighashes.push(hex::encode(sighash.to_byte_array()));
    }
    Ok(sighashes)
}

fn sorted_inputs(inputs: &[VaultInput]) -> Vec<VaultInput> {
    let mut inputs = inputs.to_vec();
    inputs.sort_by(|a, b| a.txid.cmp(&b.txid).then_with(|| a.vout.cmp(&b.vout)));
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        vault_script_pubkey_hex, DkgSignerBinding, VaultEpoch, VaultRemainderOutput, VaultSpendPlan,
    };
    use crate::withdrawal::{build_withdrawal_batch, WithdrawalOutputKind, WithdrawalRequest};
    use bitcoin::secp256k1::{Keypair, Message, SecretKey};
    use chrono::{TimeZone, Utc};

    fn xonly_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);
        keypair.x_only_public_key().0.to_string()
    }

    fn epoch(epoch_id: u64, key: &str) -> VaultEpoch {
        VaultEpoch {
            epoch_id,
            starts_at: Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap(),
            signer_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            threshold: 3,
            frost_group_key_xonly: Some(key.to_string()),
            dkg_transcript_hash: Some("transcript".to_string()),
            dkg_public_key_package_hash: Some("99".repeat(32)),
            frost_signer_bindings: vec![
                DkgSignerBinding {
                    signer_id: "a".to_string(),
                    frost_identifier_hex: "01".repeat(32),
                },
                DkgSignerBinding {
                    signer_id: "b".to_string(),
                    frost_identifier_hex: "02".repeat(32),
                },
                DkgSignerBinding {
                    signer_id: "c".to_string(),
                    frost_identifier_hex: "03".repeat(32),
                },
            ],
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

    fn request(id: &str, amount_sats: Sats, destination_script_hex: &str) -> WithdrawalRequest {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[10; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let claim_owner_pubkey_hex = keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex: destination_script_hex.to_string(),
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
    fn withdrawal_plan_builds_unsigned_tx_and_psbt_witness_utxos() {
        let current_key = xonly_key(1);
        let current = epoch(1, &current_key);
        let batch = build_withdrawal_batch(
            vec![
                request("b", 20_000, "00142222222222222222222222222222222222222222"),
                request("a", 10_000, "00141111111111111111111111111111111111111111"),
            ],
            2,
            1,
            1,
        )
        .unwrap();
        let plan = VaultSpendPlan::withdrawal_batch(
            &current,
            vec![
                input("ff", 1, 25_000, &current_key),
                input("aa", 0, 25_000, &current_key),
            ],
            batch,
            Some(VaultRemainderOutput::same_epoch_change(
                1,
                current_key.clone(),
                20_000,
            )),
        )
        .unwrap();

        let tx_plan = build_vault_psbt(&plan).unwrap();

        assert_eq!(tx_plan.spend_plan_hash, plan.plan_hash());
        assert_eq!(tx_plan.unsigned_tx.input.len(), 2);
        assert_eq!(tx_plan.unsigned_tx.output.len(), 3);
        assert_eq!(tx_plan.unsigned_tx.input[0].previous_output.vout, 0);
        assert_eq!(
            transaction_output_total_sats(&tx_plan.unsigned_tx).unwrap(),
            50_000 - plan.tx_fee_sats
        );
        assert!(tx_plan.vault_script_pubkey.is_p2tr());
        assert_eq!(tx_plan.psbt.inputs.len(), 2);
        assert_eq!(vault_input_sighashes(&tx_plan).unwrap().len(), 2);

        for input in &tx_plan.psbt.inputs {
            assert_eq!(
                input.witness_utxo.as_ref().unwrap().script_pubkey,
                tx_plan.vault_script_pubkey
            );
            assert!(input.tap_internal_key.is_some());
            assert_eq!(
                input.sighash_type.unwrap().taproot_hash_ty().unwrap(),
                TapSighashType::Default
            );
        }
    }

    #[test]
    fn rotation_plan_builds_single_next_epoch_output() {
        let current = epoch(5, &xonly_key(2));
        let next_key = xonly_key(3);
        let next = epoch(6, &next_key);
        let plan = VaultSpendPlan::rotation(
            &current,
            &next,
            vec![input(
                "aa",
                0,
                100_000,
                current.required_group_key().unwrap().as_str(),
            )],
            1_000,
        )
        .unwrap();

        let tx_plan = build_vault_psbt(&plan).unwrap();

        assert_eq!(tx_plan.unsigned_tx.input.len(), 1);
        assert_eq!(tx_plan.unsigned_tx.output.len(), 1);
        assert_eq!(tx_plan.unsigned_tx.output[0].value.to_sat(), 99_000);
        assert_eq!(
            tx_plan.unsigned_tx.output[0].script_pubkey,
            ScriptBuf::new_p2tr(
                &Secp256k1::verification_only(),
                XOnlyPublicKey::from_str(&next_key).unwrap(),
                None
            )
        );
    }
}
