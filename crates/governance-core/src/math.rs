use thiserror::Error;

pub const IDNA_ATOMS_PER_UNIT: u128 = 1_000_000_000_000_000_000;
pub const STAKE_QUANTUM_ATOMS: u128 = 1_000_000_000_000;
pub const BASIS_POINTS_SQUARED: u128 = 100_000_000;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MathError {
    #[error("basis-point multiplier is outside 0..=10000")]
    InvalidBasisPoints,
    #[error("vote-weight multiplication overflowed")]
    Overflow,
}

pub fn integer_sqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }

    let mut low = 1u128;
    let mut high = 1u128 << ((128 - value.leading_zeros() as usize).div_ceil(2));
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if middle <= value / middle {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

pub fn stake_score(active_stake_atoms: u128) -> u128 {
    integer_sqrt(active_stake_atoms / STAKE_QUANTUM_ATOMS)
}

pub fn effective_vote_weight(
    active_stake_atoms: u128,
    identity_status_bps: u16,
    flip_trust_bps: u16,
) -> Result<u128, MathError> {
    if identity_status_bps > 10_000 || flip_trust_bps > 10_000 {
        return Err(MathError::InvalidBasisPoints);
    }
    let weighted = stake_score(active_stake_atoms)
        .checked_mul(identity_status_bps as u128)
        .and_then(|value| value.checked_mul(flip_trust_bps as u128))
        .ok_or(MathError::Overflow)?;
    Ok(weighted / BASIS_POINTS_SQUARED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn square_root_boundaries() {
        let values = [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (15, 3),
            (16, 4),
            (17, 4),
            (u64::MAX as u128, 4_294_967_295),
            (u128::MAX, 18_446_744_073_709_551_615),
        ];
        for (input, expected) in values {
            assert_eq!(integer_sqrt(input), expected);
        }
    }

    #[test]
    fn fixed_weight_examples() {
        assert_eq!(stake_score(IDNA_ATOMS_PER_UNIT), 1_000);
        assert_eq!(
            effective_vote_weight(IDNA_ATOMS_PER_UNIT, 10_000, 10_000),
            Ok(1_000)
        );
        assert_eq!(
            effective_vote_weight(IDNA_ATOMS_PER_UNIT, 8_500, 10_000),
            Ok(850)
        );
        assert_eq!(
            effective_vote_weight(IDNA_ATOMS_PER_UNIT, 7_000, 10_000),
            Ok(700)
        );
        assert_eq!(
            effective_vote_weight(STAKE_QUANTUM_ATOMS - 1, 10_000, 10_000),
            Ok(0)
        );
    }

    proptest! {
        #[test]
        fn sqrt_is_floor(value in any::<u128>()) {
            let root = integer_sqrt(value);
            prop_assert!(root <= value.checked_div(root.max(1)).unwrap_or(0) || value == 0);
            if root < u128::MAX {
                let next = root + 1;
                prop_assert!(next > value / next);
            }
        }

        #[test]
        fn stake_weight_is_monotonic(a in any::<u64>(), b in any::<u64>()) {
            let lower = u128::from(a.min(b)) * STAKE_QUANTUM_ATOMS;
            let upper = u128::from(a.max(b)) * STAKE_QUANTUM_ATOMS;
            let lower_weight = effective_vote_weight(lower, 10_000, 10_000).unwrap();
            let upper_weight = effective_vote_weight(upper, 10_000, 10_000).unwrap();
            prop_assert!(lower_weight <= upper_weight);
        }
    }
}
