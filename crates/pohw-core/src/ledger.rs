use crate::payout::{PayoutSchedule, VaultAllocation};
use crate::withdrawal::{validate_destination_script_policy, WithdrawalError, WithdrawalRequest};
use crate::Sats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimLedger {
    balances: BTreeMap<String, Sats>,
    pending_withdrawals: BTreeMap<String, PendingWithdrawal>,
    last_withdrawal_nonce_by_owner: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    pub request_id: String,
    pub claim_owner_id: String,
    pub gross_amount_sats: Sats,
    pub fee_sats: Sats,
    pub net_amount_sats: Sats,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("insufficient claim balance for {claim_owner_id}: requested {requested_sats}, available {available_sats}")]
    InsufficientBalance {
        claim_owner_id: String,
        requested_sats: Sats,
        available_sats: Sats,
    },
    #[error("withdrawal request {0} already exists")]
    DuplicateWithdrawal(String),
    #[error(
        "stale withdrawal nonce for {claim_owner_id}: got {nonce}, last accepted {last_nonce}"
    )]
    StaleNonce {
        claim_owner_id: String,
        nonce: u64,
        last_nonce: u64,
    },
    #[error("claim balance addition overflow for {claim_owner_id}")]
    BalanceOverflow { claim_owner_id: String },
    #[error("invalid withdrawal request: {0}")]
    InvalidWithdrawal(#[from] WithdrawalError),
}

impl ClaimLedger {
    pub fn balance(&self, claim_owner_id: &str) -> Sats {
        self.balances
            .get(&claim_owner_id.to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
    }

    pub fn apply_payout_schedule(&mut self, schedule: &PayoutSchedule) -> Result<(), LedgerError> {
        for allocation in &schedule.vault_allocations {
            self.apply_vault_allocation(allocation)?;
        }
        Ok(())
    }

    pub fn apply_vault_allocation(
        &mut self,
        allocation: &VaultAllocation,
    ) -> Result<(), LedgerError> {
        let key = allocation.claim_owner_id.to_ascii_lowercase();
        let entry = self.balances.entry(key).or_default();
        *entry = entry.checked_add(allocation.amount_sats).ok_or_else(|| {
            LedgerError::BalanceOverflow {
                claim_owner_id: allocation.claim_owner_id.to_ascii_lowercase(),
            }
        })?;
        Ok(())
    }

    pub fn reserve_withdrawal(
        &mut self,
        request: &WithdrawalRequest,
        fee_sats: Sats,
        current_height: u64,
    ) -> Result<PendingWithdrawal, LedgerError> {
        request.validate(current_height)?;
        let key = request.claim_owner_id.to_ascii_lowercase();
        let available = self.balance(&key);
        if request.amount_sats > available {
            return Err(LedgerError::InsufficientBalance {
                claim_owner_id: key,
                requested_sats: request.amount_sats,
                available_sats: available,
            });
        }
        if self.pending_withdrawals.contains_key(&request.request_id) {
            return Err(LedgerError::DuplicateWithdrawal(request.request_id.clone()));
        }
        if fee_sats >= request.amount_sats {
            return Err(LedgerError::InvalidWithdrawal(
                WithdrawalError::FeeExceedsAmount {
                    request_id: request.request_id.clone(),
                    amount_sats: request.amount_sats,
                    fee_sats,
                },
            ));
        }
        validate_destination_script_policy(
            &request.request_id,
            &request.destination_script_hex,
            &request.output_kind,
            request.amount_sats - fee_sats,
        )?;
        if let Some(last_nonce) = self.last_withdrawal_nonce_by_owner.get(&key) {
            if request.nonce <= *last_nonce {
                return Err(LedgerError::StaleNonce {
                    claim_owner_id: key,
                    nonce: request.nonce,
                    last_nonce: *last_nonce,
                });
            }
        }

        let balance = self.balances.entry(key.clone()).or_default();
        *balance -= request.amount_sats;
        let pending = PendingWithdrawal {
            request_id: request.request_id.clone(),
            claim_owner_id: key.clone(),
            gross_amount_sats: request.amount_sats,
            fee_sats,
            net_amount_sats: request.amount_sats - fee_sats,
        };
        self.pending_withdrawals
            .insert(request.request_id.clone(), pending.clone());
        self.last_withdrawal_nonce_by_owner
            .insert(key, request.nonce);
        Ok(pending)
    }

    pub fn mark_paid(&mut self, request_id: &str) -> Option<PendingWithdrawal> {
        self.pending_withdrawals.remove(request_id)
    }

    pub fn pending_withdrawal(&self, request_id: &str) -> Option<&PendingWithdrawal> {
        self.pending_withdrawals.get(request_id)
    }

    pub fn pending_withdrawal_count(&self) -> usize {
        self.pending_withdrawals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawal::{WithdrawalOutputKind, WithdrawalRequest};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    fn signed_request(id: &str, amount_sats: Sats, nonce: u64) -> WithdrawalRequest {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let claim_owner_pubkey_hex = keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: id.to_string(),
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
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(request.signing_hash()), &keypair);
        request.signature_hex = Some(hex::encode(signature.serialize()));
        request
    }

    #[test]
    fn ledger_tracks_vault_claims_and_reserves_withdrawals() {
        let mut ledger = ClaimLedger::default();
        let request = signed_request("req-1", 20_000, 1);
        ledger
            .apply_vault_allocation(&VaultAllocation {
                miner_id: request.claim_owner_id.clone(),
                claim_owner_id: request.claim_owner_id.clone(),
                amount_sats: 50_000,
            })
            .unwrap();

        let pending = ledger.reserve_withdrawal(&request, 500, 1).unwrap();

        assert_eq!(pending.net_amount_sats, 19_500);
        assert_eq!(ledger.balance(&request.claim_owner_id), 30_000);
        assert!(ledger.mark_paid("req-1").is_some());
    }

    #[test]
    fn ledger_rejects_overdrawn_claims() {
        let mut ledger = ClaimLedger::default();
        let request = signed_request("req-1", 10_000, 1);

        assert!(matches!(
            ledger.reserve_withdrawal(&request, 0, 1),
            Err(LedgerError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn ledger_rejects_replayed_or_stale_nonce() {
        let mut ledger = ClaimLedger::default();
        let first = signed_request("req-1", 10_000, 2);
        ledger
            .apply_vault_allocation(&VaultAllocation {
                miner_id: first.claim_owner_id.clone(),
                claim_owner_id: first.claim_owner_id.clone(),
                amount_sats: 50_000,
            })
            .unwrap();
        ledger.reserve_withdrawal(&first, 500, 1).unwrap();
        let replay = signed_request("req-2", 10_000, 2);

        assert!(matches!(
            ledger.reserve_withdrawal(&replay, 500, 1),
            Err(LedgerError::StaleNonce { .. })
        ));
    }

    #[test]
    fn ledger_rejects_balance_overflow() {
        let mut ledger = ClaimLedger::default();
        let allocation = VaultAllocation {
            miner_id: "owner".to_string(),
            claim_owner_id: "claim-owner".to_string(),
            amount_sats: Sats::MAX,
        };
        ledger.apply_vault_allocation(&allocation).unwrap();

        let err = ledger.apply_vault_allocation(&VaultAllocation {
            miner_id: "OWNER".to_string(),
            claim_owner_id: "CLAIM-OWNER".to_string(),
            amount_sats: 1,
        });

        assert!(matches!(err, Err(LedgerError::BalanceOverflow { .. })));
    }

    #[test]
    fn ledger_rejects_dust_after_fee_deduction() {
        let mut ledger = ClaimLedger::default();
        let request = signed_request("req-1", 10_000, 1);
        ledger
            .apply_vault_allocation(&VaultAllocation {
                miner_id: request.claim_owner_id.clone(),
                claim_owner_id: request.claim_owner_id.clone(),
                amount_sats: 50_000,
            })
            .unwrap();

        let err = ledger.reserve_withdrawal(&request, 9_800, 1);

        assert!(matches!(
            err,
            Err(LedgerError::InvalidWithdrawal(
                WithdrawalError::DustOutput { .. }
            ))
        ));
    }
}
