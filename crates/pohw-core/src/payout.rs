use crate::{merkle, Sats, Score, DIRECT_PAYOUT_LIMIT, MIN_DIRECT_PAYOUT_SATS};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantAccount {
    pub miner_id: String,
    pub btc_payout_script_hex: String,
    pub claim_owner_id: String,
    pub unpaid_sats: Sats,
    pub hashrate_score: Score,
    pub idena_score: Score,
}

impl ParticipantAccount {
    pub fn normalized(mut self) -> Self {
        self.miner_id = self.miner_id.to_ascii_lowercase();
        self.btc_payout_script_hex = self.btc_payout_script_hex.to_ascii_lowercase();
        self.claim_owner_id = self.claim_owner_id.to_ascii_lowercase();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectPayout {
    pub miner_id: String,
    pub btc_payout_script_hex: String,
    pub amount_sats: Sats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAllocation {
    pub miner_id: String,
    pub claim_owner_id: String,
    pub amount_sats: Sats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutSchedule {
    pub direct_outputs: Vec<DirectPayout>,
    pub vault_allocations: Vec<VaultAllocation>,
    pub vault_output_sats: Sats,
    pub payout_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayoutError {
    #[error("sats addition overflow")]
    AmountOverflow,
    #[error("score addition overflow")]
    ScoreOverflow,
    #[error("score multiplication overflow")]
    ScoreMultiplicationOverflow,
    #[error("reward component {component} has no eligible score")]
    ZeroScorePool { component: &'static str },
    #[error("payout root mismatch: expected {expected}, got {actual}")]
    PayoutRootMismatch { expected: String, actual: String },
    #[error("vault output total mismatch: expected {expected_sats}, got {actual_sats}")]
    VaultOutputMismatch {
        expected_sats: Sats,
        actual_sats: Sats,
    },
    #[error("payout schedule contains a zero amount")]
    ZeroAmount,
    #[error("payout schedule {field} are not in canonical order")]
    NonCanonicalOrder { field: &'static str },
    #[error("payout schedule contains a duplicate {field}")]
    DuplicateEntry { field: &'static str },
}

impl PayoutSchedule {
    pub fn expected_payout_root(&self) -> String {
        merkle::merkle_root(&[PayoutRootMaterial {
            direct_outputs: self.direct_outputs.clone(),
            vault_allocations: self.vault_allocations.clone(),
            vault_output_sats: self.vault_output_sats,
        }])
    }

    pub fn validate(&self) -> Result<(), PayoutError> {
        let expected_root = self.expected_payout_root();
        if self.payout_root != expected_root {
            return Err(PayoutError::PayoutRootMismatch {
                expected: expected_root,
                actual: self.payout_root.clone(),
            });
        }

        if self
            .direct_outputs
            .iter()
            .any(|output| output.amount_sats == 0)
            || self
                .vault_allocations
                .iter()
                .any(|allocation| allocation.amount_sats == 0)
        {
            return Err(PayoutError::ZeroAmount);
        }

        if !self
            .direct_outputs
            .windows(2)
            .all(|pair| compare_direct_outputs(&pair[0], &pair[1]) != Ordering::Greater)
        {
            return Err(PayoutError::NonCanonicalOrder {
                field: "direct_outputs",
            });
        }

        if !self
            .vault_allocations
            .windows(2)
            .all(|pair| compare_vault_allocations(&pair[0], &pair[1]) != Ordering::Greater)
        {
            return Err(PayoutError::NonCanonicalOrder {
                field: "vault_allocations",
            });
        }

        let mut direct_miner_ids = BTreeSet::new();
        for output in &self.direct_outputs {
            if !direct_miner_ids.insert(output.miner_id.to_ascii_lowercase()) {
                return Err(PayoutError::DuplicateEntry {
                    field: "direct miner",
                });
            }
        }

        let mut vault_miner_ids = BTreeSet::new();
        for allocation in &self.vault_allocations {
            if !vault_miner_ids.insert(allocation.miner_id.to_ascii_lowercase()) {
                return Err(PayoutError::DuplicateEntry {
                    field: "vault miner",
                });
            }
        }

        if direct_miner_ids
            .iter()
            .any(|miner_id| vault_miner_ids.contains(miner_id))
        {
            return Err(PayoutError::DuplicateEntry {
                field: "miner across direct and vault outputs",
            });
        }

        let expected_vault_total = sum_sats(
            self.vault_allocations
                .iter()
                .map(|allocation| allocation.amount_sats),
        )?;
        if self.vault_output_sats != expected_vault_total {
            return Err(PayoutError::VaultOutputMismatch {
                expected_sats: expected_vault_total,
                actual_sats: self.vault_output_sats,
            });
        }

        Ok(())
    }
}

pub fn build_payout_schedule(
    accounts: &[ParticipantAccount],
    reward_sats: Sats,
    direct_limit: usize,
    min_direct_payout_sats: Sats,
) -> Result<PayoutSchedule, PayoutError> {
    let mut accounts: Vec<_> = accounts
        .iter()
        .cloned()
        .map(ParticipantAccount::normalized)
        .collect();
    accounts.sort_by(|a, b| a.miner_id.cmp(&b.miner_id));

    let deltas = reward_deltas(&accounts, reward_sats)?;
    let mut ranked: Vec<_> = accounts
        .iter()
        .zip(deltas.iter())
        .map(|(account, delta)| {
            let rank_balance = account
                .unpaid_sats
                .checked_add(*delta)
                .ok_or(PayoutError::AmountOverflow)?;
            Ok((account, *delta, rank_balance))
        })
        .collect::<Result<_, PayoutError>>()?;

    ranked.sort_by(|(a, a_delta, a_rank), (b, b_delta, b_rank)| {
        b_rank
            .cmp(a_rank)
            .then_with(|| b_delta.cmp(a_delta))
            .then_with(|| a.miner_id.cmp(&b.miner_id))
    });

    let selected_ids: std::collections::BTreeSet<_> = ranked
        .iter()
        .filter(|(_, delta, _)| *delta >= min_direct_payout_sats)
        .take(direct_limit)
        .map(|(account, _, _)| account.miner_id.clone())
        .collect();

    let mut direct_outputs = Vec::new();
    let mut vault_allocations = Vec::new();

    for (account, delta) in accounts.iter().zip(deltas) {
        if delta == 0 {
            continue;
        }
        if selected_ids.contains(&account.miner_id) {
            direct_outputs.push(DirectPayout {
                miner_id: account.miner_id.clone(),
                btc_payout_script_hex: account.btc_payout_script_hex.clone(),
                amount_sats: delta,
            });
        } else {
            vault_allocations.push(VaultAllocation {
                miner_id: account.miner_id.clone(),
                claim_owner_id: account.claim_owner_id.clone(),
                amount_sats: delta,
            });
        }
    }

    direct_outputs.sort_by(compare_direct_outputs);
    vault_allocations.sort_by(compare_vault_allocations);

    let direct_total = sum_sats(direct_outputs.iter().map(|o| o.amount_sats))?;
    let vault_output_sats = reward_sats
        .checked_sub(direct_total)
        .ok_or(PayoutError::AmountOverflow)?;
    let payout_root = merkle::merkle_root(&[PayoutRootMaterial {
        direct_outputs: direct_outputs.clone(),
        vault_allocations: vault_allocations.clone(),
        vault_output_sats,
    }]);

    Ok(PayoutSchedule {
        direct_outputs,
        vault_allocations,
        vault_output_sats,
        payout_root,
    })
}

fn reward_deltas(
    accounts: &[ParticipantAccount],
    reward_sats: Sats,
) -> Result<Vec<Sats>, PayoutError> {
    let hash_pool = reward_sats / 2;
    let idena_pool = reward_sats - hash_pool;

    let mut deltas = vec![0; accounts.len()];
    add_component(accounts, &mut deltas, hash_pool, "hashrate", |account| {
        account.hashrate_score
    })?;
    add_component(accounts, &mut deltas, idena_pool, "idena", |account| {
        account.idena_score
    })?;
    Ok(deltas)
}

fn add_component<F>(
    accounts: &[ParticipantAccount],
    deltas: &mut [Sats],
    pool: Sats,
    component: &'static str,
    score: F,
) -> Result<(), PayoutError>
where
    F: Fn(&ParticipantAccount) -> Score,
{
    if pool == 0 {
        return Ok(());
    }
    let total_score = sum_scores(accounts.iter().map(&score))?;
    if total_score == 0 {
        return Err(PayoutError::ZeroScorePool { component });
    }

    let mut allocated: Sats = 0;
    let mut remainders = Vec::new();

    for (idx, account) in accounts.iter().enumerate() {
        let account_score = score(account);
        let numerator = account_score
            .checked_mul(pool as Score)
            .ok_or(PayoutError::ScoreMultiplicationOverflow)?;
        let whole = (numerator / total_score) as Sats;
        let remainder = numerator % total_score;
        deltas[idx] = deltas[idx]
            .checked_add(whole)
            .ok_or(PayoutError::AmountOverflow)?;
        allocated = allocated
            .checked_add(whole)
            .ok_or(PayoutError::AmountOverflow)?;
        remainders.push((idx, remainder, account.miner_id.clone()));
    }

    remainders.sort_by(|(_, a_rem, a_id), (_, b_rem, b_id)| {
        b_rem.cmp(a_rem).then_with(|| a_id.cmp(b_id))
    });

    let mut left = pool
        .checked_sub(allocated)
        .ok_or(PayoutError::AmountOverflow)?;
    for (idx, _, _) in remainders {
        if left == 0 {
            break;
        }
        deltas[idx] = deltas[idx]
            .checked_add(1)
            .ok_or(PayoutError::AmountOverflow)?;
        left -= 1;
    }
    Ok(())
}

fn compare_direct_outputs(a: &DirectPayout, b: &DirectPayout) -> Ordering {
    b.amount_sats
        .cmp(&a.amount_sats)
        .then_with(|| a.miner_id.cmp(&b.miner_id))
}

fn compare_vault_allocations(a: &VaultAllocation, b: &VaultAllocation) -> Ordering {
    a.claim_owner_id
        .cmp(&b.claim_owner_id)
        .then_with(|| a.miner_id.cmp(&b.miner_id))
}

#[derive(Debug, Clone, Serialize)]
struct PayoutRootMaterial {
    direct_outputs: Vec<DirectPayout>,
    vault_allocations: Vec<VaultAllocation>,
    vault_output_sats: Sats,
}

impl Default for PayoutSchedule {
    fn default() -> Self {
        build_payout_schedule(&[], 0, DIRECT_PAYOUT_LIMIT, MIN_DIRECT_PAYOUT_SATS)
            .expect("empty payout schedule cannot overflow")
    }
}

fn sum_sats<I>(values: I) -> Result<Sats, PayoutError>
where
    I: IntoIterator<Item = Sats>,
{
    values.into_iter().try_fold(0u64, |total, value| {
        total.checked_add(value).ok_or(PayoutError::AmountOverflow)
    })
}

fn sum_scores<I>(values: I) -> Result<Score, PayoutError>
where
    I: IntoIterator<Item = Score>,
{
    values.into_iter().try_fold(0u128, |total, value| {
        total.checked_add(value).ok_or(PayoutError::ScoreOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(
        id: &str,
        unpaid_sats: Sats,
        hashrate_score: Score,
        idena_score: Score,
    ) -> ParticipantAccount {
        ParticipantAccount {
            miner_id: id.to_string(),
            btc_payout_script_hex: format!("51{id}"),
            claim_owner_id: format!("claim-{id}"),
            unpaid_sats,
            hashrate_score,
            idena_score,
        }
    }

    #[test]
    fn payout_splits_50_50_and_ranks_by_unpaid_balance() {
        let accounts = vec![
            account("a", 1_000_000, 1, 0),
            account("b", 0, 1, 100),
            account("c", 500_000, 0, 0),
        ];

        let schedule = build_payout_schedule(&accounts, 100_000, 1, 10_000).unwrap();

        assert_eq!(schedule.direct_outputs.len(), 1);
        assert_eq!(schedule.direct_outputs[0].miner_id, "a");
        assert_eq!(schedule.direct_outputs[0].amount_sats, 25_000);
        assert_eq!(schedule.vault_output_sats, 75_000);
    }

    #[test]
    fn dust_sized_current_delta_goes_to_vault() {
        let accounts = vec![account("a", 1_000_000, 1, 1)];
        let schedule = build_payout_schedule(&accounts, 9_999, 100, 10_000).unwrap();

        assert!(schedule.direct_outputs.is_empty());
        assert_eq!(schedule.vault_output_sats, 9_999);
        assert_eq!(schedule.vault_allocations[0].amount_sats, 9_999);
    }

    #[test]
    fn roots_are_deterministic_for_input_order() {
        let a = account("a", 0, 1, 1);
        let b = account("b", 0, 2, 2);
        let left = build_payout_schedule(&[a.clone(), b.clone()], 100_000, 100, 10_000).unwrap();
        let right = build_payout_schedule(&[b, a], 100_000, 100, 10_000).unwrap();

        assert_eq!(left.payout_root, right.payout_root);
    }

    #[test]
    fn payout_rejects_score_sum_overflow() {
        let accounts = vec![account("a", 0, Score::MAX, 0), account("b", 0, 1, 0)];

        let err = build_payout_schedule(&accounts, 100_000, 100, 10_000).unwrap_err();

        assert_eq!(err, PayoutError::ScoreOverflow);
    }

    #[test]
    fn payout_rejects_score_multiplication_overflow() {
        let accounts = vec![account("a", 0, Score::MAX, 0)];

        let err = build_payout_schedule(&accounts, 100_000, 100, 10_000).unwrap_err();

        assert_eq!(err, PayoutError::ScoreMultiplicationOverflow);
    }

    #[test]
    fn payout_rejects_unpaid_rank_overflow() {
        let accounts = vec![account("a", Sats::MAX, 1, 1)];

        let err = build_payout_schedule(&accounts, 100_000, 100, 10_000).unwrap_err();

        assert_eq!(err, PayoutError::AmountOverflow);
    }

    #[test]
    fn payout_rejects_unowned_component_pool() {
        let accounts = vec![account("a", 0, 1, 0)];

        let err = build_payout_schedule(&accounts, 100_000, 100, 10_000).unwrap_err();

        assert_eq!(err, PayoutError::ZeroScorePool { component: "idena" });
    }

    #[test]
    fn payout_schedule_validation_rejects_tampered_root() {
        let accounts = vec![account("a", 0, 1, 1)];
        let mut schedule = build_payout_schedule(&accounts, 100_000, 100, 10_000).unwrap();
        schedule.payout_root = "00".repeat(32);

        assert!(matches!(
            schedule.validate(),
            Err(PayoutError::PayoutRootMismatch { .. })
        ));
    }

    #[test]
    fn payout_schedule_validation_rejects_unbalanced_vault_total() {
        let accounts = vec![account("a", 0, 1, 1)];
        let mut schedule = build_payout_schedule(&accounts, 9_999, 100, 10_000).unwrap();
        schedule.vault_output_sats += 1;
        schedule.payout_root = schedule.expected_payout_root();

        assert!(matches!(
            schedule.validate(),
            Err(PayoutError::VaultOutputMismatch { .. })
        ));
    }

    #[test]
    fn payout_schedule_validation_rejects_duplicate_miner_entries() {
        let mut schedule = PayoutSchedule {
            direct_outputs: vec![DirectPayout {
                miner_id: "a".to_string(),
                btc_payout_script_hex: "51".to_string(),
                amount_sats: 10_000,
            }],
            vault_allocations: vec![VaultAllocation {
                miner_id: "A".to_string(),
                claim_owner_id: "claim-a".to_string(),
                amount_sats: 10_000,
            }],
            vault_output_sats: 10_000,
            payout_root: String::new(),
        };
        schedule.payout_root = schedule.expected_payout_root();

        assert_eq!(
            schedule.validate(),
            Err(PayoutError::DuplicateEntry {
                field: "miner across direct and vault outputs"
            })
        );
    }
}
