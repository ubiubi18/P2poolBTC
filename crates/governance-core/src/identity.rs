use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PRIOR_REPORTED: u128 = 1;
pub const PRIOR_TOTAL: u128 = 20;
pub const FLIP_TRUST_MIN_BPS: u16 = 4_000;
pub const FLIP_TRUST_MAX_BPS: u16 = 10_000;
pub const FLIP_PENALTY_SCALE: u128 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityState {
    Human,
    Verified,
    Newbie,
    Candidate,
    Invite,
    Suspended,
    Zombie,
    Killed,
    Undefined,
}

impl IdentityState {
    pub fn status_bps(self) -> Option<u16> {
        match self {
            Self::Human => Some(10_000),
            Self::Verified => Some(8_500),
            Self::Newbie => Some(7_000),
            Self::Candidate
            | Self::Invite
            | Self::Suspended
            | Self::Zombie
            | Self::Killed
            | Self::Undefined => None,
        }
    }

    pub fn is_verified_or_human(self) -> bool {
        matches!(self, Self::Human | Self::Verified)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MetricsError {
    #[error("consensus-reported authored flips cannot exceed finalized authored flips")]
    ReportedExceedsFinalized,
}

pub fn flip_trust_bps(finalized: u64, reported: u64) -> Result<u16, MetricsError> {
    if reported > finalized {
        return Err(MetricsError::ReportedExceedsFinalized);
    }
    let numerator = (u128::from(reported) + PRIOR_REPORTED) * 10_000;
    let denominator = u128::from(finalized) + PRIOR_TOTAL;
    let reported_rate_bps = numerator / denominator;
    let penalty = FLIP_PENALTY_SCALE * reported_rate_bps / 10_000;
    let raw = 10_000u128.saturating_sub(penalty);
    Ok(raw.clamp(FLIP_TRUST_MIN_BPS as u128, FLIP_TRUST_MAX_BPS as u128) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn fixed_flip_examples() {
        assert_eq!(flip_trust_bps(0, 0), Ok(9_250));
        assert_eq!(flip_trust_bps(1, 0), Ok(9_286));
        assert_eq!(flip_trust_bps(1, 1), Ok(8_572));
        assert_eq!(flip_trust_bps(20, 0), Ok(9_625));
        assert_eq!(flip_trust_bps(20, 20), Ok(4_000));
        assert_eq!(flip_trust_bps(u64::MAX, u64::MAX), Ok(4_000));
        assert_eq!(
            flip_trust_bps(2, 3),
            Err(MetricsError::ReportedExceedsFinalized)
        );
    }

    #[test]
    fn eligible_status_order_is_fixed() {
        assert!(IdentityState::Human.status_bps() > IdentityState::Verified.status_bps());
        assert!(IdentityState::Verified.status_bps() > IdentityState::Newbie.status_bps());
        assert_eq!(IdentityState::Candidate.status_bps(), None);
    }

    proptest! {
        #[test]
        fn more_reports_never_increase_trust(n in any::<u32>(), a in any::<u32>(), b in any::<u32>()) {
            let n = u64::from(n);
            let low = u64::from(a.min(b)).min(n);
            let high = u64::from(a.max(b)).min(n);
            prop_assert!(flip_trust_bps(n, high).unwrap() <= flip_trust_bps(n, low).unwrap());
        }

        #[test]
        fn non_reported_finalized_flip_never_decreases_trust(n in any::<u32>(), r in any::<u32>()) {
            let n = u64::from(n);
            let r = u64::from(r).min(n);
            prop_assert!(flip_trust_bps(n + 1, r).unwrap() >= flip_trust_bps(n, r).unwrap());
        }

        #[test]
        fn trust_is_bounded(n in any::<u32>(), r in any::<u32>()) {
            let n = u64::from(n);
            let trust = flip_trust_bps(n, u64::from(r).min(n)).unwrap();
            prop_assert!((4_000..=10_000).contains(&trust));
        }
    }
}
