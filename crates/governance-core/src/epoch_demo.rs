//! Deterministic local-only Governance Day protocol demonstration.
//!
//! This runs real state transitions in the in-memory contract model. It does
//! not claim to open desktop windows, contact Idena, publish to IPFS, or install
//! code. The cross-repository harness supplies those boundaries separately.

use crate::{
    cid_for, effective_vote_weight, flip_trust_bps, stage_local_rollback, AiReviewEvidenceV1,
    BuildRootEvidenceV1, CanonicalHistoryEntryV1, DataAvailabilityEvidenceV1, EpochBallotChoiceV1,
    EpochGovernanceClock, EpochGovernanceEngine, EpochGovernanceError,
    EpochGovernanceParameterSetV1, EpochProposalContentV1, EpochProposalKindV1, EpochProposalState,
    IdentityState, LocalRollbackPlanV1, RecoveryManifestV1, RevertProposalV1, RiskClass,
    SocialDiscussionReferenceV1, VoteChoice, VotingPowerSnapshotV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DAG_CBOR_CODEC: u64 = 0x71;
const RAW_CODEC: u64 = 0x55;
const LOCAL_CHAIN_ID: &str = "idena-code-dao-local-test-v1";
const LOCAL_CONTRACT: &str = "0x9999999999999999999999999999999999999999";
const LOCAL_IDENTITY_A: &str = "0x1111111111111111111111111111111111111111";
const LOCAL_IDENTITY_B: &str = "0x2222222222222222222222222222222222222222";
const PROPOSAL_BOND_ATOMS: u128 = 10_000_000_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceDayProtocolStepV1 {
    pub step: u8,
    pub label: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceDayProtocolDemoV1 {
    pub schema_version: u16,
    pub local_test_data: bool,
    pub governance_epoch: u64,
    pub accepted_proposal_id: String,
    pub rejected_proposal_id: String,
    pub revert_proposal_id: String,
    pub identity_a_weight: String,
    pub identity_b_weight: String,
    pub accepted_bond_refund_atoms: String,
    pub rejected_bond_burn_atoms: String,
    pub rejected_bond_treasury_atoms: String,
    pub canonical_before: String,
    pub canonical_after: String,
    pub canonical_history: Vec<CanonicalHistoryEntryV1>,
    pub local_rollback: LocalRollbackPlanV1,
    pub code_installed_automatically: bool,
    pub protocol_steps: Vec<GovernanceDayProtocolStepV1>,
    pub desktop_harness_steps_required: Vec<u8>,
}

pub fn run_local_governance_day_protocol_demo(
) -> Result<GovernanceDayProtocolDemoV1, EpochGovernanceError> {
    let canonical_before = dag_cbor_cid("canonical-before");
    let canonical_after = dag_cbor_cid("canonical-after");
    let rejected_candidate = dag_cbor_cid("rejected-candidate");
    let support_cid = raw_cid("supporting-evidence");
    let mut parameters = EpochGovernanceParameterSetV1::experimental_defaults();
    parameters.normal.minimum_participating_identities = 1;
    parameters.normal.minimum_yes_identities = 1;
    parameters.normal.minimum_verified_or_human_yes = 1;
    parameters.critical.minimum_participating_identities = 1;
    parameters.critical.minimum_yes_identities = 1;
    parameters.critical.minimum_verified_or_human_yes = 1;
    let parameter_set_cid = crate::package_dag_cbor(&parameters)
        .map_err(|_| EpochGovernanceError::InvalidParameters)?
        .root_cid
        .to_string();

    let mut engine = EpochGovernanceEngine::initialize(
        LOCAL_CHAIN_ID,
        LOCAL_CONTRACT,
        &canonical_before,
        &parameter_set_cid,
        parameters,
    )?;
    engine.anchor_governance_epoch(EpochGovernanceClock {
        epoch: 421,
        block: 1_000,
    })?;
    let identity_a_weight = register_local_snapshot(
        &mut engine,
        421,
        LOCAL_IDENTITY_A,
        IdentityState::Human,
        PROPOSAL_BOND_ATOMS,
    )?;
    let identity_b_weight = register_local_snapshot(
        &mut engine,
        421,
        LOCAL_IDENTITY_B,
        IdentityState::Verified,
        PROPOSAL_BOND_ATOMS,
    )?;

    let accepted_proposal_id = engine.create_proposal(
        LOCAL_IDENTITY_A,
        change_proposal(
            "Accept local fixture",
            &canonical_before,
            &canonical_after,
            &parameter_set_cid,
            &support_cid,
        ),
        PROPOSAL_BOND_ATOMS,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_010,
        },
    )?;
    let second_attempt = engine.create_proposal(
        LOCAL_IDENTITY_A,
        change_proposal(
            "Forbidden second slot",
            &canonical_before,
            &rejected_candidate,
            &parameter_set_cid,
            &support_cid,
        ),
        PROPOSAL_BOND_ATOMS,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_011,
        },
    );
    if second_attempt != Err(EpochGovernanceError::ProposalSlotUsed) {
        return Err(EpochGovernanceError::InvalidState);
    }
    let rejected_proposal_id = engine.create_proposal(
        LOCAL_IDENTITY_B,
        change_proposal(
            "Reject local fixture",
            &canonical_before,
            &rejected_candidate,
            &parameter_set_cid,
            &support_cid,
        ),
        PROPOSAL_BOND_ATOMS,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_012,
        },
    )?;
    for proposal_id in [&accepted_proposal_id, &rejected_proposal_id] {
        attach_local_evidence(&mut engine, proposal_id)?;
    }

    let frozen = engine.freeze_epoch_proposal_set(EpochGovernanceClock {
        epoch: 421,
        block: 1_040,
    })?;
    let choices = frozen
        .ordered_proposal_ids
        .iter()
        .map(|proposal_id| EpochBallotChoiceV1 {
            proposal_id: proposal_id.clone(),
            choice: if proposal_id == &accepted_proposal_id {
                VoteChoice::Yes
            } else {
                VoteChoice::No
            },
        })
        .collect();
    let ballot = engine.prepare_epoch_ballot(
        421,
        LOCAL_IDENTITY_A,
        choices,
        BTreeMap::from([(
            accepted_proposal_id.clone(),
            "LOCAL TEST DATA: user note excluded from commitment".to_string(),
        )]),
        7,
        &"55".repeat(32),
    )?;
    engine.commit_epoch_ballot(
        LOCAL_IDENTITY_A,
        421,
        &ballot.commitment,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_080,
        },
    )?;
    engine.reveal_epoch_ballot(
        LOCAL_IDENTITY_A,
        &ballot,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_100,
        },
    )?;
    let decisions = engine.finalize_epoch_voting(EpochGovernanceClock {
        epoch: 421,
        block: 1_120,
    })?;
    if decision_state(&decisions, &accepted_proposal_id)
        != Some(EpochProposalState::AcceptedPendingGrace)
        || decision_state(&decisions, &rejected_proposal_id) != Some(EpochProposalState::Rejected)
    {
        return Err(EpochGovernanceError::InvalidState);
    }
    let rejected_bond_burn_atoms = engine.burned_atoms();
    let rejected_bond_treasury_atoms = engine.treasury_atoms();
    if rejected_bond_burn_atoms + rejected_bond_treasury_atoms != PROPOSAL_BOND_ATOMS {
        return Err(EpochGovernanceError::InvalidState);
    }
    if engine.enter_execution_ready_state(
        &accepted_proposal_id,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_179,
        },
    ) != Err(EpochGovernanceError::ExecutionBlocked)
    {
        return Err(EpochGovernanceError::InvalidState);
    }
    engine.enter_execution_ready_state(
        &accepted_proposal_id,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_180,
        },
    )?;
    engine.execute_proposal(
        &accepted_proposal_id,
        EpochGovernanceClock {
            epoch: 421,
            block: 1_180,
        },
    )?;
    let accepted_bond_refund_atoms = engine.claim_refund(LOCAL_IDENTITY_A)?;
    if accepted_bond_refund_atoms != PROPOSAL_BOND_ATOMS
        || engine.canonical_ecosystem_cid() != canonical_after
        || engine.canonical_history().len() != 1
    {
        return Err(EpochGovernanceError::InvalidState);
    }

    engine.anchor_governance_epoch(EpochGovernanceClock {
        epoch: 422,
        block: 2_000,
    })?;
    register_local_snapshot(
        &mut engine,
        422,
        LOCAL_IDENTITY_A,
        IdentityState::Human,
        PROPOSAL_BOND_ATOMS,
    )?;
    let execution = engine
        .canonical_history()
        .first()
        .cloned()
        .ok_or(EpochGovernanceError::InvalidState)?;
    let revert_proposal_id = engine.create_revert_proposal(
        LOCAL_IDENTITY_A,
        revert_proposal(
            &execution,
            &canonical_after,
            &canonical_before,
            &parameter_set_cid,
            &support_cid,
        ),
        25_000_000_000_000_000_000,
        EpochGovernanceClock {
            epoch: 422,
            block: 2_010,
        },
    )?;

    let artifact = b"LOCAL TEST DATA: last-known-good deterministic artifact";
    let recovery_manifest = RecoveryManifestV1 {
        schema_version: 1,
        canonical_history_cid: support_cid.clone(),
        last_known_good_ecosystem_cid: canonical_before.clone(),
        release_manifest_cid: support_cid.clone(),
        artifact_cid: raw_cid("last-known-good-artifact"),
        artifact_sha256: hex::encode(Sha256::digest(artifact)),
        compatibility_metadata_cid: support_cid.clone(),
        rollback_instructions_cid: support_cid.clone(),
        chain_rpc_required_for_on_chain_revert: true,
    };
    let local_rollback = stage_local_rollback(
        &raw_cid("recovery-manifest"),
        &recovery_manifest,
        "/local-test/staging/p2pool-node",
        artifact,
        false,
    )?;
    if local_rollback.unattended_install_enabled
        || local_rollback.unattended_rollback_enabled
        || local_rollback.on_chain_revert_available
        || !local_rollback.explicit_user_confirmation_required
    {
        return Err(EpochGovernanceError::InvalidState);
    }

    Ok(GovernanceDayProtocolDemoV1 {
        schema_version: 1,
        local_test_data: true,
        governance_epoch: 421,
        accepted_proposal_id,
        rejected_proposal_id,
        revert_proposal_id,
        identity_a_weight: identity_a_weight.to_string(),
        identity_b_weight: identity_b_weight.to_string(),
        accepted_bond_refund_atoms: accepted_bond_refund_atoms.to_string(),
        rejected_bond_burn_atoms: rejected_bond_burn_atoms.to_string(),
        rejected_bond_treasury_atoms: rejected_bond_treasury_atoms.to_string(),
        canonical_before,
        canonical_after,
        canonical_history: engine.canonical_history().to_vec(),
        local_rollback,
        code_installed_automatically: false,
        protocol_steps: protocol_steps(),
        desktop_harness_steps_required: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 17, 18, 19],
    })
}

fn register_local_snapshot(
    engine: &mut EpochGovernanceEngine,
    epoch: u64,
    address: &str,
    state: IdentityState,
    stake_atoms: u128,
) -> Result<u128, EpochGovernanceError> {
    let trust = flip_trust_bps(20, 0).map_err(|_| EpochGovernanceError::InvalidState)?;
    let weight = effective_vote_weight(stake_atoms, state.status_bps().unwrap(), trust)
        .map_err(|_| EpochGovernanceError::Overflow)?;
    engine.register_voting_power_snapshot(VotingPowerSnapshotV1 {
        schema_version: 1,
        governance_epoch: epoch,
        voter_address: address.to_string(),
        identity_state: state,
        finalized_authored_flips: 20,
        consensus_reported_authored_flips: 0,
        flip_trust_bps: trust,
        active_stake_atoms: stake_atoms,
        effective_vote_weight: weight,
        source_block_height: 123,
        source_block_hash: "11".repeat(32),
    })?;
    Ok(weight)
}

fn change_proposal(
    title: &str,
    parent: &str,
    candidate: &str,
    parameters: &str,
    support_cid: &str,
) -> EpochProposalContentV1 {
    EpochProposalContentV1 {
        schema_version: 1,
        title: title.to_string(),
        review_round_id: "44".repeat(32),
        parent_canonical_ecosystem_cid: parent.to_string(),
        candidate_ecosystem_cid: candidate.to_string(),
        patch_cid: dag_cbor_cid(&format!("{title}-patch")),
        candidate_manifest_sha256: "22".repeat(32),
        parameter_set_cid: parameters.to_string(),
        affected_repositories: vec!["P2poolBTC".to_string()],
        changed_file_count: 1,
        patch_bytes: 128,
        source_package_bytes: 1_024,
        description_bytes: 128,
        migration_operation_count: 0,
        risk_class: RiskClass::Normal,
        rationale_cid: support_cid.to_string(),
        test_plan_cid: support_cid.to_string(),
        rollback_manifest_cid: support_cid.to_string(),
        rollback_instructions_cid: support_cid.to_string(),
        critical_finding_waiver_cid: None,
        social_discussion: Some(SocialDiscussionReferenceV1 {
            post_id: Some("LOCAL-TEST-DISCUSSION".to_string()),
            discussion_cid: Some(support_cid.to_string()),
            contract_reference: None,
            creation_transaction_reference: None,
        }),
        proposal_kind: EpochProposalKindV1::Change,
    }
}

fn revert_proposal(
    execution: &CanonicalHistoryEntryV1,
    current: &str,
    replacement: &str,
    parameters: &str,
    support_cid: &str,
) -> EpochProposalContentV1 {
    let mut content = change_proposal(
        "Revert local test execution",
        current,
        replacement,
        parameters,
        support_cid,
    );
    content.risk_class = RiskClass::Critical;
    content.proposal_kind = EpochProposalKindV1::Revert(RevertProposalV1 {
        schema_version: 1,
        execution_id: execution.execution_id.clone(),
        current_canonical_cid: current.to_string(),
        replacement_canonical_cid: replacement.to_string(),
        reason_cid: support_cid.to_string(),
        evidence_cid: support_cid.to_string(),
        affected_repositories: vec!["P2poolBTC".to_string()],
        rollback_instructions_cid: support_cid.to_string(),
        compatibility_checks_cid: support_cid.to_string(),
        expedited_recovery: false,
    });
    content
}

fn attach_local_evidence(
    engine: &mut EpochGovernanceEngine,
    proposal_id: &str,
) -> Result<(), EpochGovernanceError> {
    engine.attach_ai_review_root(
        proposal_id,
        AiReviewEvidenceV1 {
            root: "33".repeat(32),
            valid_attestations: 3,
            independent_runtime_groups: 2,
            distinct_provider_families: 2,
            distinct_owner_identities: 2,
            unresolved_critical_findings: 0,
        },
        EpochGovernanceClock {
            epoch: 421,
            block: 1_050,
        },
    )?;
    engine.attach_build_root(
        proposal_id,
        BuildRootEvidenceV1 {
            root: "44".repeat(32),
            valid_builders: 2,
            distinct_platforms: 1,
            matching_core_artifact_digests: true,
        },
        EpochGovernanceClock {
            epoch: 421,
            block: 1_050,
        },
    )?;
    engine.attach_data_availability_root(
        proposal_id,
        DataAvailabilityEvidenceV1 {
            root: "55".repeat(32),
            independent_providers: 2,
            valid_until_block: 1_780,
        },
        EpochGovernanceClock {
            epoch: 421,
            block: 1_050,
        },
    )
}

fn decision_state(
    decisions: &[crate::EpochProposalDecisionV1],
    proposal_id: &str,
) -> Option<EpochProposalState> {
    decisions
        .iter()
        .find(|decision| decision.proposal_id == proposal_id)
        .map(|decision| decision.state)
}

fn dag_cbor_cid(label: &str) -> String {
    cid_for(DAG_CBOR_CODEC, label.as_bytes()).to_string()
}

fn raw_cid(label: &str) -> String {
    cid_for(RAW_CODEC, label.as_bytes()).to_string()
}

fn protocol_steps() -> Vec<GovernanceDayProtocolStepV1> {
    [
        (12, "Submit one proposal for identity A", "authenticated local identity A consumed its epoch slot"),
        (13, "Reject identity A's second proposal", "ProposalSlotUsed returned without storing another proposal"),
        (14, "Submit one proposal for identity B", "independent authenticated local identity B consumed its own slot"),
        (15, "Reach proposal cutoff", "chain block advanced to the configured cutoff"),
        (16, "Freeze epoch proposal set", "proposal IDs sorted and committed by one frozen root"),
        (20, "Prepare complete epoch ballot", "ordered Yes/No choices cover every frozen proposal"),
        (21, "Commit ballot", "domain-separated commitment stored for local identity A"),
        (22, "Reveal ballot", "salt and ordered choices matched the prior commitment"),
        (23, "Show sublinear voting weights", "weights derived from integer square root, identity status, and flip trust"),
        (24, "Finalize accepted and rejected proposals", "all gates passed for one proposal and weighted No rejected the other"),
        (25, "Settle proposal bonds", "accepted bond refundable after execution; rejected bond split between burn and treasury"),
        (26, "Enter grace period", "accepted proposal remained AcceptedPendingGrace"),
        (27, "Block execution during grace", "ExecutionBlocked returned one block before grace expiry"),
        (28, "Advance beyond grace", "chain block advanced to the exact eligibility boundary"),
        (29, "Execute accepted proposal", "permissionless state transition changed only the canonical CID"),
        (30, "Preserve canonical history", "history retains both previous and new canonical CIDs"),
        (31, "Create revert proposal", "next-epoch proposal references the real historical execution"),
        (32, "Stage local last-known-good rollback", "chain-offline plan requires explicit user confirmation and cannot claim on-chain recovery"),
        (33, "Prove no automatic installation", "unattended install and rollback flags remain false"),
    ]
    .into_iter()
    .map(|(step, label, evidence)| GovernanceDayProtocolStepV1 {
        step,
        label: label.to_string(),
        evidence: evidence.to_string(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_protocol_demo_runs_real_transitions_without_installing_code() {
        let report = run_local_governance_day_protocol_demo().unwrap();
        assert!(report.local_test_data);
        assert!(!report.code_installed_automatically);
        assert_eq!(report.protocol_steps.len(), 19);
        assert_eq!(report.canonical_history.len(), 1);
        assert_eq!(
            report.canonical_history[0].previous_canonical_ecosystem_cid,
            report.canonical_before
        );
        assert_eq!(
            report.canonical_history[0].new_canonical_ecosystem_cid,
            report.canonical_after
        );
        assert!(!report.local_rollback.chain_rpc_available);
        assert!(!report.local_rollback.on_chain_revert_available);
        assert!(report.local_rollback.explicit_user_confirmation_required);
    }
}
