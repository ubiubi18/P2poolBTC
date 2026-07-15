use crate::{merkle, Score, FORMULA_VERSION};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IdenaStatus {
    Invite,
    Candidate,
    Newbie,
    Verified,
    Suspended,
    Zombie,
    Killed,
    Human,
    Undefined,
}

impl IdenaStatus {
    pub fn is_block_eligible(&self) -> bool {
        matches!(self, Self::Newbie | Self::Verified | Self::Human)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLeaf {
    pub idena_address: String,
    pub status: IdenaStatus,
    pub pubkey: String,
    pub validation_reward_score: Score,
    pub proposer_reward_score: Score,
    pub committee_reward_score: Score,
    #[serde(default)]
    pub ignored_invitation_score: Score,
    pub identity_root: String,
    pub formula_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot score addition overflow for {idena_address}")]
    ScoreOverflow { idena_address: String },
    #[error("snapshot formula version {actual} does not match expected {expected}")]
    FormulaVersionMismatch { expected: u16, actual: u16 },
    #[error("snapshot leaf formula version {actual} for {idena_address} does not match expected {expected}")]
    LeafFormulaVersionMismatch {
        idena_address: String,
        expected: u16,
        actual: u16,
    },
    #[error("snapshot contains duplicate Idena address {0}")]
    DuplicateAddress(String),
    #[error("snapshot leaf {idena_address} identity root {actual} does not match snapshot identity root {expected}")]
    IdentityRootMismatch {
        idena_address: String,
        expected: String,
        actual: String,
    },
    #[error("snapshot score root mismatch: expected {expected}, got {actual}")]
    ScoreRootMismatch { expected: String, actual: String },
    #[error("invalid Idena address {idena_address}: {reason}")]
    InvalidIdenaAddress {
        idena_address: String,
        reason: String,
    },
    #[error("identity root must contain exactly 32 hexadecimal bytes")]
    InvalidIdentityRoot,
}

impl SnapshotLeaf {
    pub fn normalized(mut self) -> Self {
        self.idena_address = self.idena_address.to_ascii_lowercase();
        self.pubkey = self.pubkey.to_ascii_lowercase();
        self.identity_root = self.identity_root.to_ascii_lowercase();
        self
    }

    pub fn eligible_score(&self) -> Result<Score, SnapshotError> {
        self.validation_reward_score
            .checked_add(self.proposer_reward_score)
            .and_then(|score| score.checked_add(self.committee_reward_score))
            .ok_or_else(|| SnapshotError::ScoreOverflow {
                idena_address: self.idena_address.clone(),
            })
    }

    pub fn is_block_eligible(&self) -> bool {
        self.formula_version == FORMULA_VERSION && self.status.is_block_eligible()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_day: NaiveDate,
    pub idena_height: u64,
    pub idena_block_hash: String,
    pub identity_root: String,
    pub score_root: String,
    pub formula_version: u16,
    pub leaves: Vec<SnapshotLeaf>,
}

impl Snapshot {
    pub fn build(
        snapshot_day: NaiveDate,
        idena_height: u64,
        idena_block_hash: impl Into<String>,
        identity_root: impl Into<String>,
        formula_version: u16,
        leaves: Vec<SnapshotLeaf>,
    ) -> Self {
        let mut leaves: Vec<_> = leaves.into_iter().map(SnapshotLeaf::normalized).collect();
        leaves.sort_by(compare_leaves);
        let score_root = merkle::merkle_root(&leaves);
        let idena_block_hash = idena_block_hash.into().to_ascii_lowercase();
        let identity_root = identity_root.into().to_ascii_lowercase();

        Self {
            snapshot_day,
            idena_height,
            idena_block_hash,
            identity_root,
            score_root,
            formula_version,
            leaves,
        }
    }

    pub fn verify_score_root(&self) -> Result<(), SnapshotError> {
        if self.formula_version != FORMULA_VERSION {
            return Err(SnapshotError::FormulaVersionMismatch {
                expected: FORMULA_VERSION,
                actual: self.formula_version,
            });
        }

        let mut leaves: Vec<_> = self
            .leaves
            .iter()
            .cloned()
            .map(SnapshotLeaf::normalized)
            .collect();
        leaves.sort_by(compare_leaves);

        let mut previous_address: Option<String> = None;
        let expected_identity_root = self.identity_root.to_ascii_lowercase();
        for leaf in &leaves {
            validate_idena_address(&leaf.idena_address)?;
            if leaf.formula_version != self.formula_version {
                return Err(SnapshotError::LeafFormulaVersionMismatch {
                    idena_address: leaf.idena_address.clone(),
                    expected: self.formula_version,
                    actual: leaf.formula_version,
                });
            }
            if previous_address.as_deref() == Some(leaf.idena_address.as_str()) {
                return Err(SnapshotError::DuplicateAddress(leaf.idena_address.clone()));
            }
            if leaf.identity_root != expected_identity_root {
                return Err(SnapshotError::IdentityRootMismatch {
                    idena_address: leaf.idena_address.clone(),
                    expected: expected_identity_root.clone(),
                    actual: leaf.identity_root.clone(),
                });
            }
            previous_address = Some(leaf.idena_address.clone());
        }

        let expected = merkle::merkle_root(&leaves);
        if self.score_root != expected {
            return Err(SnapshotError::ScoreRootMismatch {
                expected,
                actual: self.score_root.clone(),
            });
        }
        Ok(())
    }

    /// Return the chain identity root in the canonical unprefixed form used by
    /// PoHW commitments. Idena RPC snapshots may encode the same 32 bytes with
    /// a `0x` prefix; accepting that representation here avoids commitment
    /// malleability while keeping snapshot source data unchanged.
    pub fn identity_proof_root_hex(&self) -> Result<String, SnapshotError> {
        let normalized = self.identity_root.to_ascii_lowercase();
        let value = normalized.strip_prefix("0x").unwrap_or(&normalized);
        if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(SnapshotError::InvalidIdentityRoot);
        }
        Ok(value.to_string())
    }
}

pub fn compare_leaves(left: &SnapshotLeaf, right: &SnapshotLeaf) -> Ordering {
    left.idena_address.cmp(&right.idena_address)
}

fn validate_idena_address(value: &str) -> Result<(), SnapshotError> {
    let Some(hex_part) = value.strip_prefix("0x") else {
        return Err(SnapshotError::InvalidIdenaAddress {
            idena_address: value.to_string(),
            reason: "address must start with 0x".to_string(),
        });
    };
    if hex_part.len() != 40
        || !hex_part
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SnapshotError::InvalidIdenaAddress {
            idena_address: value.to_string(),
            reason: "address must contain 20 bytes encoded as 40 hex characters".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
impl Snapshot {
    fn expected_duplicate_root_for_test(&self) -> String {
        let mut leaves: Vec<_> = self
            .leaves
            .iter()
            .cloned()
            .map(SnapshotLeaf::normalized)
            .collect();
        leaves.sort_by(compare_leaves);
        merkle::merkle_root(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(address: &str, score: Score) -> SnapshotLeaf {
        SnapshotLeaf {
            idena_address: address.to_string(),
            status: IdenaStatus::Human,
            pubkey: "ABC".to_string(),
            validation_reward_score: score,
            proposer_reward_score: 0,
            committee_reward_score: 0,
            ignored_invitation_score: 0,
            identity_root: "0xbb".to_string(),
            formula_version: FORMULA_VERSION,
        }
    }

    #[test]
    fn snapshot_sorts_leaves_before_rooting() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let left = Snapshot::build(
            day,
            1,
            "0xaa",
            "0xbb",
            FORMULA_VERSION,
            vec![leaf("0xB", 1), leaf("0xA", 2)],
        );
        let right = Snapshot::build(
            day,
            1,
            "0xaa",
            "0xbb",
            FORMULA_VERSION,
            vec![leaf("0xA", 2), leaf("0xB", 1)],
        );

        assert_eq!(left.score_root, right.score_root);
        assert_eq!(left.leaves[0].idena_address, "0xa");
    }

    #[test]
    fn only_newbie_verified_human_are_block_eligible() {
        assert!(IdenaStatus::Newbie.is_block_eligible());
        assert!(IdenaStatus::Verified.is_block_eligible());
        assert!(IdenaStatus::Human.is_block_eligible());
        assert!(!IdenaStatus::Candidate.is_block_eligible());
        assert!(!IdenaStatus::Killed.is_block_eligible());
    }

    #[test]
    fn snapshot_leaf_rejects_score_overflow() {
        let mut leaf = leaf("0xA", Score::MAX);
        leaf.proposer_reward_score = 1;

        let err = leaf.eligible_score().unwrap_err();

        assert!(matches!(err, SnapshotError::ScoreOverflow { .. }));
    }

    #[test]
    fn snapshot_verifies_score_root_from_normalized_sorted_leaves() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let snapshot = Snapshot::build(
            day,
            1,
            "0xaa",
            "0xbb",
            FORMULA_VERSION,
            vec![
                leaf("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
                leaf("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2),
            ],
        );

        snapshot.verify_score_root().unwrap();
    }

    #[test]
    fn snapshot_rejects_tampered_score_root() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let mut snapshot = Snapshot::build(
            day,
            1,
            "0xaa",
            "0xbb",
            FORMULA_VERSION,
            vec![leaf("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2)],
        );
        snapshot.score_root = "00".repeat(32);

        assert!(matches!(
            snapshot.verify_score_root(),
            Err(SnapshotError::ScoreRootMismatch { .. })
        ));
    }

    #[test]
    fn snapshot_rejects_duplicate_identity_leaves() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let mut snapshot = Snapshot::build(
            day,
            1,
            "0xaa",
            "0xbb",
            FORMULA_VERSION,
            vec![
                leaf("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
                leaf("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
            ],
        );
        snapshot.score_root = snapshot.expected_duplicate_root_for_test();

        assert!(matches!(
            snapshot.verify_score_root(),
            Err(SnapshotError::DuplicateAddress(_))
        ));
    }

    #[test]
    fn snapshot_rejects_leaf_identity_root_mismatch() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let mut leaf = leaf("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
        leaf.identity_root = "0xwrong".to_string();
        let snapshot = Snapshot::build(day, 1, "0xaa", "0xbb", FORMULA_VERSION, vec![leaf]);

        assert!(matches!(
            snapshot.verify_score_root(),
            Err(SnapshotError::IdentityRootMismatch { .. })
        ));
    }

    #[test]
    fn commitment_identity_root_canonicalizes_optional_prefix() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let expected = "ab".repeat(32);
        let snapshot = Snapshot::build(
            day,
            1,
            "0xaa",
            format!("0x{expected}"),
            FORMULA_VERSION,
            Vec::new(),
        );

        assert_eq!(snapshot.identity_proof_root_hex().unwrap(), expected);
    }

    #[test]
    fn commitment_identity_root_rejects_wrong_length() {
        let day = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let snapshot = Snapshot::build(day, 1, "0xaa", "0x1234", FORMULA_VERSION, Vec::new());

        assert_eq!(
            snapshot.identity_proof_root_hex(),
            Err(SnapshotError::InvalidIdentityRoot)
        );
    }
}
