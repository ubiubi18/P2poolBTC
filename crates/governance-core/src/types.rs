use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskClass {
    Normal,
    Critical,
    Consensus,
    Migration,
}

impl RiskClass {
    pub fn is_critical(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateParameterSet {
    pub turnout_quorum_bps: u16,
    pub yes_threshold_bps: u16,
    pub minimum_yes_identities: u32,
    pub minimum_verified_or_human_yes: u32,
    pub minimum_agent_attestations: u32,
    pub minimum_agent_runtime_groups: u32,
    pub minimum_agent_families: u32,
    pub minimum_agent_owners: u32,
    pub critical_finding_owner_threshold: u32,
    pub minimum_builders: u32,
    pub minimum_builder_platforms: u32,
    pub minimum_data_availability_providers: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusBps {
    #[serde(rename = "Human")]
    pub human: u16,
    #[serde(rename = "Verified")]
    pub verified: u16,
    #[serde(rename = "Newbie")]
    pub newbie: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalBondPolicy {
    pub minimum_bond_atoms: String,
    pub rejected_return_bps: u16,
    pub stale_processing_fee_atoms: String,
    pub expired_slash_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectiveSlashPolicy {
    pub fraudulent_proposal_slash_bps: u16,
    pub fraudulent_reviewer_slash_bps: u16,
    pub fraudulent_builder_slash_bps: u16,
    pub unavailable_data_slash_bps: u16,
    pub fraudulent_actor_stake_slash_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceParameterSetV1 {
    pub schema_version: u16,
    pub idna_atoms_per_unit: String,
    pub stake_quantum_atoms: String,
    pub minimum_active_stake_atoms: String,
    pub status_bps: StatusBps,
    pub flip_prior_reported: u16,
    pub flip_prior_total: u16,
    pub flip_trust_floor_bps: u16,
    pub flip_trust_ceiling_bps: u16,
    pub flip_penalty_scale: u16,
    pub activation_delay_epochs: u16,
    pub unbonding_delay_epochs: u16,
    pub review_period_blocks: u64,
    pub voting_period_blocks: u64,
    pub challenge_period_blocks: u64,
    pub timelock_blocks: u64,
    pub execution_window_blocks: u64,
    pub minimum_identity_metrics_attestations: u32,
    pub minimum_reviewer_bond_atoms: String,
    pub minimum_builder_bond_atoms: String,
    pub minimum_data_availability_bond_atoms: String,
    pub normal: GateParameterSet,
    pub critical: GateParameterSet,
    pub proposal_bond_policy: ProposalBondPolicy,
    pub objective_slash_policy: ObjectiveSlashPolicy,
}

impl GovernanceParameterSetV1 {
    pub fn experimental_defaults() -> Self {
        Self {
            schema_version: 1,
            idna_atoms_per_unit: "1000000000000000000".to_string(),
            stake_quantum_atoms: "1000000000000".to_string(),
            minimum_active_stake_atoms: "1000000000000000000".to_string(),
            status_bps: StatusBps {
                human: 10_000,
                verified: 8_500,
                newbie: 7_000,
            },
            flip_prior_reported: 1,
            flip_prior_total: 20,
            flip_trust_floor_bps: 4_000,
            flip_trust_ceiling_bps: 10_000,
            flip_penalty_scale: 15_000,
            activation_delay_epochs: 1,
            unbonding_delay_epochs: 4,
            review_period_blocks: 40,
            voting_period_blocks: 120,
            challenge_period_blocks: 60,
            timelock_blocks: 60,
            execution_window_blocks: 600,
            minimum_identity_metrics_attestations: 3,
            minimum_reviewer_bond_atoms: "1000000000000000000".to_string(),
            minimum_builder_bond_atoms: "1000000000000000000".to_string(),
            minimum_data_availability_bond_atoms: "1000000000000000000".to_string(),
            normal: GateParameterSet {
                turnout_quorum_bps: 2_000,
                yes_threshold_bps: 6_667,
                minimum_yes_identities: 7,
                minimum_verified_or_human_yes: 3,
                minimum_agent_attestations: 3,
                minimum_agent_runtime_groups: 2,
                minimum_agent_families: 2,
                minimum_agent_owners: 2,
                critical_finding_owner_threshold: 2,
                minimum_builders: 2,
                minimum_builder_platforms: 1,
                minimum_data_availability_providers: 2,
            },
            critical: GateParameterSet {
                turnout_quorum_bps: 3_000,
                yes_threshold_bps: 7_500,
                minimum_yes_identities: 12,
                minimum_verified_or_human_yes: 5,
                minimum_agent_attestations: 5,
                minimum_agent_runtime_groups: 3,
                minimum_agent_families: 3,
                minimum_agent_owners: 3,
                critical_finding_owner_threshold: 3,
                minimum_builders: 3,
                minimum_builder_platforms: 2,
                minimum_data_availability_providers: 3,
            },
            proposal_bond_policy: ProposalBondPolicy {
                minimum_bond_atoms: "10000000000000000000".to_string(),
                rejected_return_bps: 9_000,
                stale_processing_fee_atoms: "100000000000000000".to_string(),
                expired_slash_bps: 2_500,
            },
            objective_slash_policy: ObjectiveSlashPolicy {
                fraudulent_proposal_slash_bps: 5_000,
                fraudulent_reviewer_slash_bps: 10_000,
                fraudulent_builder_slash_bps: 10_000,
                unavailable_data_slash_bps: 5_000,
                fraudulent_actor_stake_slash_bps: 500,
            },
        }
    }
}
