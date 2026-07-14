use governance_core::{effective_vote_weight, flip_trust_bps, stake_score, IdentityState};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    flip_trust_cases: Vec<FlipCase>,
    invalid_flip_trust_cases: Vec<FlipCase>,
    weight_cases: Vec<WeightCase>,
    age_invariance_cases: Vec<WeightCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlipCase {
    name: String,
    finalized: String,
    reported: String,
    #[serde(default)]
    expected_trust_bps: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeightCase {
    name: Option<String>,
    stake_atoms: String,
    state: String,
    finalized: String,
    reported: String,
    #[serde(default)]
    expected_stake_score: Option<String>,
    expected_trust_bps: u16,
    expected_weight: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../../tests/governance/voting-vectors-v1.json"
    ))
    .expect("shared governance vectors must parse")
}

fn state(value: &str) -> IdentityState {
    match value {
        "Human" => IdentityState::Human,
        "Verified" => IdentityState::Verified,
        "Newbie" => IdentityState::Newbie,
        other => panic!("unsupported vector state: {other}"),
    }
}

fn assert_weight(case: &WeightCase) {
    let atoms = case.stake_atoms.parse::<u128>().unwrap();
    let trust = flip_trust_bps(
        case.finalized.parse().unwrap(),
        case.reported.parse().unwrap(),
    )
    .unwrap();
    let weight =
        effective_vote_weight(atoms, state(&case.state).status_bps().unwrap(), trust).unwrap();
    if let Some(expected) = &case.expected_stake_score {
        assert_eq!(stake_score(atoms).to_string(), *expected, "{:?}", case.name);
    }
    assert_eq!(trust, case.expected_trust_bps, "{:?}", case.name);
    assert_eq!(weight.to_string(), case.expected_weight, "{:?}", case.name);
}

#[test]
fn rust_matches_shared_vectors() {
    let vectors = vectors();
    for case in &vectors.flip_trust_cases {
        assert_eq!(
            flip_trust_bps(
                case.finalized.parse().unwrap(),
                case.reported.parse().unwrap(),
            )
            .unwrap(),
            case.expected_trust_bps,
            "{}",
            case.name
        );
    }
    for case in &vectors.invalid_flip_trust_cases {
        assert!(
            flip_trust_bps(
                case.finalized.parse().unwrap(),
                case.reported.parse().unwrap(),
            )
            .is_err(),
            "{}",
            case.name
        );
    }
    for case in &vectors.weight_cases {
        assert_weight(case);
    }
    for case in &vectors.age_invariance_cases {
        assert_weight(case);
    }
}
