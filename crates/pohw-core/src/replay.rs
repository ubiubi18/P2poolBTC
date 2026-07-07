use crate::Score;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewardKind {
    Validation,
    Proposer,
    FinalCommittee,
    Invitation,
    Invitee,
    ContractOracle,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardEvent {
    pub idena_address: String,
    pub kind: RewardKind,
    pub amount_atoms: Score,
    pub source_height: u64,
    pub source_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardScore {
    pub validation_reward_score: Score,
    pub proposer_reward_score: Score,
    pub committee_reward_score: Score,
    pub ignored_invitation_score: Score,
    pub ignored_other_score: Score,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewardReplayError {
    #[error("reward score addition overflow for {idena_address}")]
    ScoreOverflow { idena_address: String },
}

impl RewardScore {
    pub fn eligible_score(&self) -> Result<Score, RewardReplayError> {
        self.validation_reward_score
            .checked_add(self.proposer_reward_score)
            .and_then(|score| score.checked_add(self.committee_reward_score))
            .ok_or_else(|| RewardReplayError::ScoreOverflow {
                idena_address: "<score>".to_string(),
            })
    }
}

#[derive(Debug, Clone, Default)]
pub struct RewardReplay {
    scores: BTreeMap<String, RewardScore>,
}

impl RewardReplay {
    pub fn apply(&mut self, event: RewardEvent) -> Result<(), RewardReplayError> {
        let idena_address = event.idena_address.to_ascii_lowercase();
        let entry = self.scores.entry(idena_address.clone()).or_default();

        match event.kind {
            RewardKind::Validation => {
                entry.validation_reward_score = entry
                    .validation_reward_score
                    .checked_add(event.amount_atoms)
                    .ok_or_else(|| RewardReplayError::ScoreOverflow {
                        idena_address: idena_address.clone(),
                    })?;
            }
            RewardKind::Proposer => {
                entry.proposer_reward_score = entry
                    .proposer_reward_score
                    .checked_add(event.amount_atoms)
                    .ok_or_else(|| RewardReplayError::ScoreOverflow {
                        idena_address: idena_address.clone(),
                    })?;
            }
            RewardKind::FinalCommittee => {
                entry.committee_reward_score = entry
                    .committee_reward_score
                    .checked_add(event.amount_atoms)
                    .ok_or_else(|| RewardReplayError::ScoreOverflow {
                        idena_address: idena_address.clone(),
                    })?;
            }
            RewardKind::Invitation | RewardKind::Invitee => {
                entry.ignored_invitation_score = entry
                    .ignored_invitation_score
                    .checked_add(event.amount_atoms)
                    .ok_or_else(|| RewardReplayError::ScoreOverflow {
                        idena_address: idena_address.clone(),
                    })?;
            }
            RewardKind::ContractOracle | RewardKind::Other => {
                entry.ignored_other_score = entry
                    .ignored_other_score
                    .checked_add(event.amount_atoms)
                    .ok_or_else(|| RewardReplayError::ScoreOverflow {
                        idena_address: idena_address.clone(),
                    })?;
            }
        }
        Ok(())
    }

    pub fn score_for(&self, idena_address: &str) -> RewardScore {
        self.scores
            .get(&idena_address.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub fn scores(&self) -> &BTreeMap<String, RewardScore> {
        &self.scores
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_excludes_invitation_and_contract_rewards() {
        let mut replay = RewardReplay::default();
        let addr = "0xABC";
        for (kind, amount_atoms) in [
            (RewardKind::Validation, 10),
            (RewardKind::Proposer, 20),
            (RewardKind::FinalCommittee, 30),
            (RewardKind::Invitation, 40),
            (RewardKind::ContractOracle, 50),
        ] {
            replay
                .apply(RewardEvent {
                    idena_address: addr.to_string(),
                    kind,
                    amount_atoms,
                    source_height: 1,
                    source_hash: "0x00".to_string(),
                })
                .unwrap();
        }

        let score = replay.score_for(addr);
        assert_eq!(score.eligible_score().unwrap(), 60);
        assert_eq!(score.ignored_invitation_score, 40);
        assert_eq!(score.ignored_other_score, 50);
    }

    #[test]
    fn replay_rejects_score_overflow() {
        let mut replay = RewardReplay::default();
        replay
            .apply(RewardEvent {
                idena_address: "0xabc".to_string(),
                kind: RewardKind::Validation,
                amount_atoms: Score::MAX,
                source_height: 1,
                source_hash: "0x00".to_string(),
            })
            .unwrap();

        let err = replay
            .apply(RewardEvent {
                idena_address: "0xABC".to_string(),
                kind: RewardKind::Validation,
                amount_atoms: 1,
                source_height: 2,
                source_hash: "0x01".to_string(),
            })
            .unwrap_err();

        assert!(matches!(err, RewardReplayError::ScoreOverflow { .. }));
    }
}
