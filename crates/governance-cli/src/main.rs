mod ipfs;
mod output;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use governance_core::{
    agent_attestation_commitment_fields, build_attestation_commitment,
    build_attestation_commitment_fields, checkout_source_car, cid_for, create_source_patch,
    data_availability_commitment_fields, effective_vote_weight, evaluate_deployment_readiness,
    flip_trust_bps, package_agent_review_attestation, package_build_attestation,
    package_change_proposal_with_scope, package_dag_cbor, package_data_availability_attestation,
    package_development_policy, package_ecosystem_manifest, package_ecosystem_patch_manifest,
    package_external_audit_attestation, package_governance_parameters,
    package_identity_metrics_attestation, package_identity_metrics_snapshot,
    package_pinset_manifest_for_transition_with_additional, package_proposal_scope_evidence,
    package_release_manifest, package_source_tree_with_artifact_exclusions,
    package_toolchain_manifest_for_ecosystem, run_local_governance_day_protocol_demo, sha256_hex,
    stake_score, validate_epoch_governance_parameters, validate_proposal_scope_evidence,
    verify_agent_review_attestation_car, verify_build_attestation_car, verify_car_integrity,
    verify_change_proposal_car_with_scope, verify_dag_cbor_car,
    verify_data_availability_attestation_car, verify_development_policy_car,
    verify_ecosystem_manifest_car, verify_ecosystem_patch_manifest_car,
    verify_ecosystem_transition, verify_external_audit_attestation_car,
    verify_governance_parameters_car, verify_identity_metrics_attestation_car,
    verify_identity_metrics_snapshot_car, verify_pinset_manifest_car,
    verify_pinset_manifest_for_transition, verify_proposal_scope_evidence_car,
    verify_release_manifest_car, verify_source_car, verify_source_patch,
    verify_toolchain_manifest_car, verify_tree_matches_car_with_artifact_exclusions,
    AcceptanceEvidence, AddressedAttestationV1, AgentReviewAttestationV1,
    AttestationCommitmentEntryV1, BuildAttestationV1, ChangeProposalContentV1,
    DataAvailabilityAttestationV1, DevelopmentPolicyBundleV1, EcosystemManifestV1,
    EcosystemPatchManifestV1, EpochGovernanceParameterSetV1, ExternalAuditAttestationV1,
    ExternalAuditVerdictV1, GateResults, GovernanceParameterSetV1, IdentityMetricsAttestationV1,
    IdentityMetricsSnapshotV1, IdentityState, PinsetManifestV1, ProposalScopeEvidenceV1,
    ReleaseManifestV1, RepositoryScopeEvidenceV1, RiskClass, ScopeChangeV1, SourcePatchV1,
    SourceTreeManifestV1, ToolchainManifestV1, AGENT_REVIEW_COMMITMENT_DOMAIN,
    BUILD_ATTESTATION_COMMITMENT_DOMAIN, DATA_AVAILABILITY_COMMITMENT_DOMAIN,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ipfs::{
    fetch_car_from_gateways, http_client, import_to_public_kubo, parse_external_provider,
    pin_locally, request_external_pins,
};
use crate::output::{deterministic_json, secure_output_directory, write_new};

const RAW_CODEC: u64 = 0x55;

#[derive(Debug, Parser)]
#[command(
    name = "pohw-governance",
    about = "Experimental IPFS-native governance tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Package a repository as a deterministic linked DAG-CBOR source tree and CARv1.
    Package {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        output_dir: PathBuf,
        /// Strict JSON policy listing tracked binary artifacts omitted from the source CID.
        #[arg(long)]
        artifact_exclusions: Option<PathBuf>,
    },
    /// Inspect and cryptographically verify a deterministic source CAR.
    Inspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Verify a CAR alone or against a local source tree.
    Verify {
        #[arg(long)]
        car: PathBuf,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long)]
        artifact_exclusions: Option<PathBuf>,
    },
    /// Produce a deterministic patch CAR and prove it reconstructs the candidate CID.
    Diff {
        #[arg(long)]
        base_car: PathBuf,
        #[arg(long)]
        candidate_car: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Package a canonical multi-repository ecosystem manifest with native CID links.
    EcosystemPackage {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical ecosystem-manifest CAR.
    EcosystemInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package a canonical aggregate multi-repository ecosystem patch.
    EcosystemPatchPackage {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical aggregate ecosystem-patch CAR.
    EcosystemPatchInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Verify that an aggregate patch exactly covers a parent-to-candidate ecosystem transition.
    EcosystemVerify {
        #[arg(long)]
        parent_car: PathBuf,
        #[arg(long)]
        candidate_car: PathBuf,
        #[arg(long)]
        patch_car: PathBuf,
    },
    /// Derive objective path, byte-count, and risk evidence from verified CARs.
    ScopePackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and recompute all counters and the risk class in scope evidence.
    ScopeInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package an MIT-licensed human/AI workflow with no maintainer or agent authority.
    DevelopmentPolicyPackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a decentralized development-policy CAR.
    DevelopmentPolicyInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Derive and package the exact toolchain locks authorized by an ecosystem CAR.
    ToolchainPackage {
        #[arg(long)]
        ecosystem_car: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical toolchain-manifest CAR.
    ToolchainInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package the opening availability pinset for an exact ecosystem transition.
    PinsetPackage {
        #[arg(long)]
        parent_car: PathBuf,
        #[arg(long)]
        candidate_car: PathBuf,
        #[arg(long)]
        patch_car: PathBuf,
        /// Additional proposal metadata or policy CID. Repeat for every required object.
        #[arg(long = "additional-cid")]
        additional_cids: Vec<String>,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical pinset-manifest CAR.
    PinsetInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package the exact immutable experimental governance parameters as DAG-CBOR.
    ParametersPackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical governance-parameter CAR.
    ParametersInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package the exact immutable Governance Day parameters as DAG-CBOR.
    EpochParametersPackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical Governance Day parameter CAR.
    EpochParametersInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package a DAO-authorized release manifest as canonical DAG-CBOR.
    ReleasePackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Inspect and verify a canonical release-manifest CAR.
    ReleaseInspect {
        #[arg(long)]
        car: PathBuf,
    },
    /// Compute the canonical CIDv1/raw/SHA2-256 identity of an artifact.
    ArtifactInspect {
        #[arg(long)]
        file: PathBuf,
    },
    /// Create an immutable content-addressed proposal from a strict JSON input.
    ProposalCreate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        scope_car: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a proposal CAR, or verify an exact source patch transition.
    ProposalVerify {
        #[arg(long)]
        proposal_car: Option<PathBuf>,
        #[arg(long)]
        parameters: Option<PathBuf>,
        #[arg(long)]
        scope_car: Option<PathBuf>,
        #[arg(long)]
        base_car: Option<PathBuf>,
        #[arg(long)]
        candidate_car: Option<PathBuf>,
        #[arg(long)]
        patch_car: Option<PathBuf>,
    },
    /// Package a content-addressed AI review and emit its contract commitment entry.
    ReviewAttestation {
        #[arg(long)]
        input: PathBuf,
        /// Verify that agentPolicyCid equals this decentralized policy CAR.
        #[arg(long)]
        development_policy: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Package a content-addressed clean-room build attestation.
    BuildAttestation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Package a content-addressed public-IPFS availability attestation.
    DataAvailabilityAttestation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Package a content-addressed external security-audit attestation.
    ExternalAuditAttestation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Fail unless independent build, public-pin, and external-audit evidence is complete.
    DeploymentReadinessVerify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Package an independently operated identity-metrics replay attestation.
    IdentityMetricsAttestation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a canonical identity-metrics attestation CAR.
    IdentityMetricsAttestationVerify {
        #[arg(long)]
        car: PathBuf,
    },
    /// Package a strict idena-go identity-metrics snapshot as canonical DAG-CBOR and CAR.
    IdentityMetricsSnapshotPackage {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a canonical identity-metrics snapshot CAR and recompute its Merkle root.
    IdentityMetricsSnapshotVerify {
        #[arg(long)]
        car: PathBuf,
    },
    /// Verify a typed attestation CAR without trusting its filename or transport.
    AttestationVerify {
        #[arg(long, value_enum)]
        kind: CliAttestationKind,
        #[arg(long)]
        car: PathBuf,
    },
    /// Build a deterministic contract-compatible Merkle root and inclusion proofs.
    AttestationCommitment {
        #[arg(long, value_enum)]
        kind: CliAttestationKind,
        #[arg(long)]
        entries: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Check out an exact verified source CAR without consulting Git or GitHub.
    Checkout {
        #[arg(long)]
        car: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Pin a verified CAR locally and optionally import it into an explicit public Kubo sidecar.
    Pin {
        #[arg(long)]
        car: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        ecosystem_cid: Option<String>,
        #[arg(long, env = "POHW_PUBLIC_IPFS_API")]
        kubo_api: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_remote_api: bool,
        #[arg(long = "external-pin-provider")]
        external_pin_providers: Vec<String>,
    },
    /// Fetch any CAR using independent gateways and verify every returned CID locally.
    Fetch {
        #[arg(long)]
        cid: String,
        #[arg(
            long = "gateway",
            env = "POHW_PUBLIC_IPFS_GATEWAYS",
            value_delimiter = ','
        )]
        gateways: Vec<String>,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Show exact sublinear stake and bounded identity components.
    SimulateVoting {
        #[arg(long)]
        stake_atoms: u128,
        #[arg(long, value_enum)]
        state: CliIdentityState,
        #[arg(long)]
        finalized_authored_flips: u64,
        #[arg(long)]
        reported_authored_flips: u64,
    },
    /// Compare fixed stake-farming, whale, turnout, AI, and builder scenarios.
    SimulateScenarios,
    /// Run the deterministic local-only Governance Day protocol demonstration.
    DemoEpochGovernance {
        /// Optional absolute directory for the deterministic JSON report.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CliIdentityState {
    Human,
    Verified,
    Newbie,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CliAttestationKind {
    AgentReview,
    Build,
    DataAvailability,
    ExternalAudit,
}

impl CliAttestationKind {
    fn domain(self) -> &'static str {
        match self {
            Self::AgentReview => AGENT_REVIEW_COMMITMENT_DOMAIN,
            Self::Build => BUILD_ATTESTATION_COMMITMENT_DOMAIN,
            Self::DataAvailability => DATA_AVAILABILITY_COMMITMENT_DOMAIN,
            Self::ExternalAudit => "external_audit_v1",
        }
    }

    fn filename(self) -> &'static str {
        match self {
            Self::AgentReview => "agent-review-attestation",
            Self::Build => "build-attestation",
            Self::DataAvailability => "data-availability-attestation",
            Self::ExternalAudit => "external-audit-attestation",
        }
    }
}

impl From<CliIdentityState> for IdentityState {
    fn from(value: CliIdentityState) -> Self {
        match value {
            CliIdentityState::Human => Self::Human,
            CliIdentityState::Verified => Self::Verified,
            CliIdentityState::Newbie => Self::Newbie,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceView {
    schema_version: u16,
    source_tree_cid: String,
    source_tree_sha256: String,
    car_sha256: String,
    manifest: SourceTreeManifestV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactExclusionPolicyV1 {
    schema_version: u16,
    artifacts: Vec<ArtifactExclusionV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactExclusionV1 {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchView {
    schema_version: u16,
    patch_cid: String,
    patch_sha256: String,
    car_sha256: String,
    patch: SourcePatchV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EcosystemView {
    schema_version: u16,
    ecosystem_cid: String,
    ecosystem_sha256: String,
    car_sha256: String,
    manifest: EcosystemManifestV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EcosystemTransitionView {
    verified: bool,
    parent_ecosystem_cid: String,
    candidate_ecosystem_cid: String,
    patch_cid: String,
    affected_repositories: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EcosystemPatchView {
    schema_version: u16,
    ecosystem_patch_cid: String,
    ecosystem_patch_sha256: String,
    car_sha256: String,
    manifest: EcosystemPatchManifestV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopePackageInputV1 {
    schema_version: u16,
    parent_ecosystem_car: PathBuf,
    candidate_ecosystem_car: PathBuf,
    ecosystem_patch_car: PathBuf,
    rationale_file: PathBuf,
    migration_notes_file: PathBuf,
    test_plan_file: PathBuf,
    repositories: Vec<ScopeRepositoryInputV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeRepositoryInputV1 {
    repository: String,
    base_car: PathBuf,
    candidate_car: PathBuf,
    patch_car: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeploymentReadinessInputV1 {
    schema_version: u16,
    scope_car: PathBuf,
    build_attestation_cars: Vec<PathBuf>,
    data_availability_attestation_cars: Vec<PathBuf>,
    external_audit_attestation_cars: Vec<PathBuf>,
    required_availability_through_block: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeView {
    schema_version: u16,
    scope_evidence_cid: String,
    scope_evidence_sha256: String,
    car_sha256: String,
    evidence: ProposalScopeEvidenceV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolchainView {
    schema_version: u16,
    toolchain_manifest_cid: String,
    toolchain_manifest_sha256: String,
    car_sha256: String,
    manifest: ToolchainManifestV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinsetView {
    schema_version: u16,
    pinset_cid: String,
    pinset_sha256: String,
    car_sha256: String,
    manifest: PinsetManifestV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalView {
    proposal_id: String,
    proposal_cid: String,
    proposal_sha256: String,
    car_sha256: String,
    #[serde(flatten)]
    content: ChangeProposalContentV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParametersView {
    schema_version: u16,
    parameter_set_cid: String,
    parameter_set_sha256: String,
    car_sha256: String,
    parameters: GovernanceParameterSetV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EpochParametersView {
    schema_version: u16,
    parameter_set_cid: String,
    parameter_set_sha256: String,
    car_sha256: String,
    parameters: EpochGovernanceParameterSetV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseView {
    schema_version: u16,
    release_manifest_cid: String,
    release_manifest_sha256: String,
    car_sha256: String,
    manifest: ReleaseManifestV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DevelopmentPolicyView {
    schema_version: u16,
    policy_cid: String,
    policy_sha256: String,
    car_sha256: String,
    policy: DevelopmentPolicyBundleV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactView {
    schema_version: u16,
    cid: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationView<T> {
    schema_version: u16,
    attestation_kind: &'static str,
    attestation_cid: String,
    attestation_sha256: String,
    car_sha256: String,
    payload: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityMetricsSnapshotView<T> {
    schema_version: u16,
    snapshot_cid: String,
    snapshot_sha256: String,
    car_sha256: String,
    snapshot: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationOutput {
    verified: bool,
    source_tree_cid: String,
    source_tree_sha256: String,
    repository: String,
    files: usize,
    local_tree_match: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PatchVerificationOutput {
    verified: bool,
    patch_cid: String,
    patch_sha256: String,
    base_source_cid: String,
    candidate_source_cid: String,
    removed_paths: usize,
    upserted_files: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SimulationOutput {
    stake_atoms: String,
    stake_score: String,
    identity_status_bps: u16,
    flip_trust_bps: u16,
    effective_vote_weight: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StakeScenarioOutput {
    name: &'static str,
    identities: u32,
    stake_atoms_per_identity: String,
    state: &'static str,
    finalized_authored_flips: u64,
    reported_authored_flips: u64,
    stake_score_per_identity: String,
    identity_status_bps: u16,
    flip_trust_bps: u16,
    weight_per_identity: String,
    aggregate_weight: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateScenarioOutput {
    name: &'static str,
    risk_class: RiskClass,
    evidence: AcceptanceEvidence,
    result: GateResults,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScenarioReport {
    schema_version: u16,
    stake_scenarios: Vec<StakeScenarioOutput>,
    gate_scenarios: Vec<GateScenarioOutput>,
    residual_risk: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Package {
            root,
            repository,
            output_dir,
            artifact_exclusions,
        } => package_command(
            &root,
            &repository,
            &output_dir,
            artifact_exclusions.as_deref(),
        ),
        Command::Inspect { car } => inspect_command(&car),
        Command::Verify {
            car,
            root,
            repository,
            artifact_exclusions,
        } => verify_command(
            &car,
            root.as_deref(),
            repository.as_deref(),
            artifact_exclusions.as_deref(),
        ),
        Command::Diff {
            base_car,
            candidate_car,
            output_dir,
        } => diff_command(&base_car, &candidate_car, &output_dir),
        Command::EcosystemPackage {
            manifest,
            output_dir,
        } => ecosystem_package_command(&manifest, &output_dir),
        Command::EcosystemInspect { car } => ecosystem_inspect_command(&car),
        Command::EcosystemPatchPackage {
            manifest,
            output_dir,
        } => ecosystem_patch_package_command(&manifest, &output_dir),
        Command::EcosystemPatchInspect { car } => ecosystem_patch_inspect_command(&car),
        Command::EcosystemVerify {
            parent_car,
            candidate_car,
            patch_car,
        } => ecosystem_verify_command(&parent_car, &candidate_car, &patch_car),
        Command::ScopePackage { input, output_dir } => scope_package_command(&input, &output_dir),
        Command::ScopeInspect { car } => scope_inspect_command(&car),
        Command::DevelopmentPolicyPackage { input, output_dir } => {
            development_policy_package_command(&input, &output_dir)
        }
        Command::DevelopmentPolicyInspect { car } => development_policy_inspect_command(&car),
        Command::ToolchainPackage {
            ecosystem_car,
            output_dir,
        } => toolchain_package_command(&ecosystem_car, &output_dir),
        Command::ToolchainInspect { car } => toolchain_inspect_command(&car),
        Command::PinsetPackage {
            parent_car,
            candidate_car,
            patch_car,
            additional_cids,
            output_dir,
        } => pinset_package_command(
            &parent_car,
            &candidate_car,
            &patch_car,
            &additional_cids,
            &output_dir,
        ),
        Command::PinsetInspect { car } => pinset_inspect_command(&car),
        Command::ParametersPackage { input, output_dir } => {
            parameters_package_command(&input, &output_dir)
        }
        Command::ParametersInspect { car } => parameters_inspect_command(&car),
        Command::EpochParametersPackage { input, output_dir } => {
            epoch_parameters_package_command(&input, &output_dir)
        }
        Command::EpochParametersInspect { car } => epoch_parameters_inspect_command(&car),
        Command::ReleasePackage { input, output_dir } => {
            release_package_command(&input, &output_dir)
        }
        Command::ReleaseInspect { car } => release_inspect_command(&car),
        Command::ArtifactInspect { file } => artifact_inspect_command(&file),
        Command::ProposalCreate {
            input,
            parameters,
            scope_car,
            output_dir,
        } => proposal_create_command(&input, &parameters, &scope_car, &output_dir),
        Command::ProposalVerify {
            proposal_car,
            parameters,
            scope_car,
            base_car,
            candidate_car,
            patch_car,
        } => proposal_verify_command(
            proposal_car.as_deref(),
            parameters.as_deref(),
            scope_car.as_deref(),
            base_car.as_deref(),
            candidate_car.as_deref(),
            patch_car.as_deref(),
        ),
        Command::ReviewAttestation {
            input,
            development_policy,
            output_dir,
        } => review_attestation_command(&input, development_policy.as_deref(), &output_dir),
        Command::BuildAttestation { input, output_dir } => {
            build_attestation_command(&input, &output_dir)
        }
        Command::DataAvailabilityAttestation { input, output_dir } => {
            data_availability_attestation_command(&input, &output_dir)
        }
        Command::ExternalAuditAttestation { input, output_dir } => {
            external_audit_attestation_command(&input, &output_dir)
        }
        Command::DeploymentReadinessVerify { input } => deployment_readiness_verify_command(&input),
        Command::IdentityMetricsAttestation { input, output_dir } => {
            identity_metrics_attestation_command(&input, &output_dir)
        }
        Command::IdentityMetricsAttestationVerify { car } => {
            identity_metrics_attestation_verify_command(&car)
        }
        Command::IdentityMetricsSnapshotPackage { input, output_dir } => {
            identity_metrics_snapshot_package_command(&input, &output_dir)
        }
        Command::IdentityMetricsSnapshotVerify { car } => {
            identity_metrics_snapshot_verify_command(&car)
        }
        Command::AttestationVerify { kind, car } => attestation_verify_command(kind, &car),
        Command::AttestationCommitment {
            kind,
            entries,
            output_dir,
        } => attestation_commitment_command(kind, &entries, &output_dir),
        Command::Checkout { car, output } => checkout_command(&car, &output),
        Command::Pin {
            car,
            store,
            ecosystem_cid,
            kubo_api,
            allow_remote_api,
            external_pin_providers,
        } => {
            pin_command(
                &car,
                &store,
                ecosystem_cid.as_deref(),
                kubo_api.as_deref(),
                allow_remote_api,
                &external_pin_providers,
            )
            .await
        }
        Command::Fetch {
            cid,
            gateways,
            output_dir,
        } => fetch_command(&cid, &gateways, &output_dir).await,
        Command::SimulateVoting {
            stake_atoms,
            state,
            finalized_authored_flips,
            reported_authored_flips,
        } => simulate_command(
            stake_atoms,
            state,
            finalized_authored_flips,
            reported_authored_flips,
        ),
        Command::SimulateScenarios => print_json(&build_scenario_report()?),
        Command::DemoEpochGovernance { output_dir } => {
            demo_epoch_governance_command(output_dir.as_deref())
        }
    }
}

fn demo_epoch_governance_command(output_dir: Option<&Path>) -> Result<()> {
    let report = run_local_governance_day_protocol_demo()
        .context("local Governance Day protocol demonstration failed")?;
    if let Some(output_dir) = output_dir {
        require_absolute(output_dir, "demo output directory")?;
        let output = secure_output_directory(output_dir)?;
        write_new(
            &output.join("governance-day-protocol-demo.json"),
            &deterministic_json(&report)?,
        )?;
    }
    print_json(&report)
}

fn package_command(
    root: &Path,
    repository: &str,
    output_dir: &Path,
    artifact_exclusions: Option<&Path>,
) -> Result<()> {
    require_absolute(root, "source root")?;
    let exclusions = read_artifact_exclusions(artifact_exclusions)?;
    let package = package_source_tree_with_artifact_exclusions(root, repository, &exclusions)?;
    let view = SourceView {
        schema_version: 1,
        source_tree_cid: package.root_cid.to_string(),
        source_tree_sha256: package.source_tree_sha256.clone(),
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.manifest,
    };
    let output = secure_output_directory(output_dir)?;
    write_source_artifacts(&output, repository, &package.car_bytes, &view)?;
    print_json(&view)
}

fn inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "source CAR")?;
    let verified = verify_source_car(&bytes)?;
    let view = SourceView {
        schema_version: 1,
        source_tree_cid: verified.root_cid.to_string(),
        source_tree_sha256: verified.source_tree_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: verified.manifest,
    };
    print_json(&view)
}

fn verify_command(
    car: &Path,
    root: Option<&Path>,
    repository: Option<&str>,
    artifact_exclusions: Option<&Path>,
) -> Result<()> {
    let bytes = read_regular_file(car, "source CAR")?;
    let verified = match root {
        Some(root) => {
            require_absolute(root, "source root")?;
            let repository = repository.context("--repository is required with --root")?;
            let exclusions = read_artifact_exclusions(artifact_exclusions)?;
            verify_tree_matches_car_with_artifact_exclusions(root, repository, &bytes, &exclusions)?
        }
        None => {
            if repository.is_some() {
                bail!("--repository is only valid together with --root");
            }
            if artifact_exclusions.is_some() {
                bail!("--artifact-exclusions is only valid together with --root");
            }
            verify_source_car(&bytes)?
        }
    };
    print_json(&VerificationOutput {
        verified: true,
        source_tree_cid: verified.root_cid.to_string(),
        source_tree_sha256: verified.source_tree_sha256,
        repository: verified.manifest.repository,
        files: verified.manifest.files.len(),
        local_tree_match: root.is_some(),
    })
}

fn read_artifact_exclusions(path: Option<&Path>) -> Result<BTreeMap<String, String>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let policy: ArtifactExclusionPolicyV1 = read_json_file(path, "artifact exclusion policy")?;
    if policy.schema_version != 1 {
        bail!("artifact exclusion policy schemaVersion must be 1");
    }
    let mut exclusions = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for artifact in &policy.artifacts {
        if previous.is_some_and(|path| path >= artifact.path.as_str()) {
            bail!("artifact exclusions must be unique and strictly sorted by path");
        }
        previous = Some(&artifact.path);
        exclusions.insert(artifact.path.clone(), artifact.sha256.clone());
    }
    Ok(exclusions)
}

fn diff_command(base_car: &Path, candidate_car: &Path, output_dir: &Path) -> Result<()> {
    let base = read_regular_file(base_car, "base source CAR")?;
    let candidate = read_regular_file(candidate_car, "candidate source CAR")?;
    let package = create_source_patch(&base, &candidate)?;
    let repository = package.patch.repository.clone();
    let view = PatchView {
        schema_version: 1,
        patch_cid: package.patch_cid.to_string(),
        patch_sha256: package.patch_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        patch: package.patch,
    };
    let output = secure_output_directory(output_dir)?;
    write_patch_artifacts(&output, &repository, &package.car_bytes, &view)?;
    print_json(&view)
}

fn ecosystem_package_command(manifest_path: &Path, output_dir: &Path) -> Result<()> {
    let manifest: EcosystemManifestV1 = read_json_file(manifest_path, "ecosystem manifest")?;
    let package = package_ecosystem_manifest(manifest)?;
    let view = EcosystemView {
        schema_version: 1,
        ecosystem_cid: package.root_cid.to_string(),
        ecosystem_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.manifest,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("ecosystem.car"), &package.car_bytes)?;
    write_new(&output.join("ecosystem.json"), &deterministic_json(&view)?)?;
    write_new(
        &output.join("ecosystem.cid"),
        format!("{}\n", view.ecosystem_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn ecosystem_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "ecosystem CAR")?;
    let package = verify_ecosystem_manifest_car(&bytes)?;
    print_json(&EcosystemView {
        schema_version: 1,
        ecosystem_cid: package.root_cid.to_string(),
        ecosystem_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: package.manifest,
    })
}

fn ecosystem_patch_package_command(manifest_path: &Path, output_dir: &Path) -> Result<()> {
    let manifest: EcosystemPatchManifestV1 =
        read_json_file(manifest_path, "ecosystem patch manifest")?;
    let package = package_ecosystem_patch_manifest(manifest)?;
    let view = EcosystemPatchView {
        schema_version: 1,
        ecosystem_patch_cid: package.root_cid.to_string(),
        ecosystem_patch_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.manifest,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("ecosystem-patch.car"), &package.car_bytes)?;
    write_new(
        &output.join("ecosystem-patch.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("ecosystem-patch.cid"),
        format!("{}\n", view.ecosystem_patch_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn ecosystem_patch_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "ecosystem-patch CAR")?;
    let package = verify_ecosystem_patch_manifest_car(&bytes)?;
    print_json(&EcosystemPatchView {
        schema_version: 1,
        ecosystem_patch_cid: package.root_cid.to_string(),
        ecosystem_patch_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: package.manifest,
    })
}

fn ecosystem_verify_command(
    parent_car: &Path,
    candidate_car: &Path,
    patch_car: &Path,
) -> Result<()> {
    let parent_bytes = read_regular_file(parent_car, "parent ecosystem CAR")?;
    let candidate_bytes = read_regular_file(candidate_car, "candidate ecosystem CAR")?;
    let patch_bytes = read_regular_file(patch_car, "aggregate ecosystem patch CAR")?;
    let parent = verify_ecosystem_manifest_car(&parent_bytes)?;
    let candidate = verify_ecosystem_manifest_car(&candidate_bytes)?;
    let patch = verify_ecosystem_patch_manifest_car(&patch_bytes)?;
    let affected_repositories = verify_ecosystem_transition(&parent, &candidate, &patch)?;
    print_json(&EcosystemTransitionView {
        verified: true,
        parent_ecosystem_cid: parent.root_cid.to_string(),
        candidate_ecosystem_cid: candidate.root_cid.to_string(),
        patch_cid: patch.root_cid.to_string(),
        affected_repositories,
    })
}

fn scope_package_command(input_path: &Path, output_dir: &Path) -> Result<()> {
    let input: ScopePackageInputV1 = read_json_file(input_path, "scope package input")?;
    if input.schema_version != 1 {
        bail!("scope package input schemaVersion must be 1");
    }
    let base_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let parent_bytes = read_regular_file(
        &resolve_input_path(base_dir, &input.parent_ecosystem_car),
        "parent ecosystem CAR",
    )?;
    let candidate_bytes = read_regular_file(
        &resolve_input_path(base_dir, &input.candidate_ecosystem_car),
        "candidate ecosystem CAR",
    )?;
    let ecosystem_patch_bytes = read_regular_file(
        &resolve_input_path(base_dir, &input.ecosystem_patch_car),
        "ecosystem patch CAR",
    )?;
    let parent = verify_ecosystem_manifest_car(&parent_bytes)?;
    let candidate = verify_ecosystem_manifest_car(&candidate_bytes)?;
    let ecosystem_patch = verify_ecosystem_patch_manifest_car(&ecosystem_patch_bytes)?;
    let affected = verify_ecosystem_transition(&parent, &candidate, &ecosystem_patch)?;
    if input.repositories.len() != affected.len() {
        bail!("scope repository inputs do not exactly cover the ecosystem transition");
    }

    let mut repository_inputs = input.repositories;
    repository_inputs.sort_by(|left, right| left.repository.cmp(&right.repository));
    let mut repositories = Vec::with_capacity(repository_inputs.len());
    for (index, repository_input) in repository_inputs.iter().enumerate() {
        if repository_input.repository != affected[index] {
            bail!("scope repository inputs do not exactly cover the ecosystem transition");
        }
        let expected = ecosystem_patch
            .manifest
            .repository_patches
            .iter()
            .find(|entry| entry.repository == repository_input.repository)
            .context("aggregate patch is missing an affected repository")?;
        let base_car = read_regular_file(
            &resolve_input_path(base_dir, &repository_input.base_car),
            "repository base CAR",
        )?;
        let candidate_car = read_regular_file(
            &resolve_input_path(base_dir, &repository_input.candidate_car),
            "repository candidate CAR",
        )?;
        let patch_car = read_regular_file(
            &resolve_input_path(base_dir, &repository_input.patch_car),
            "repository patch CAR",
        )?;
        let base_source = verify_source_car(&base_car)?;
        let candidate_source = verify_source_car(&candidate_car)?;
        let verified_patch = verify_source_patch(&base_car, &candidate_car, &patch_car)?;
        if base_source.manifest.repository != repository_input.repository
            || candidate_source.manifest.repository != repository_input.repository
            || verified_patch.patch.repository != repository_input.repository
            || base_source.root_cid.to_string() != expected.base_source_cid
            || candidate_source.root_cid.to_string() != expected.candidate_source_cid
            || verified_patch.patch_cid.to_string() != expected.patch_cid
            || verified_patch.patch_sha256 != expected.patch_sha256
        {
            bail!("repository scope CARs do not match the aggregate ecosystem patch");
        }
        let mut changes = verified_patch
            .patch
            .removed_paths
            .iter()
            .map(|path| ScopeChangeV1 {
                path: path.clone(),
                change_kind: "remove".to_string(),
                size: 0,
            })
            .chain(
                verified_patch
                    .patch
                    .upserted_files
                    .iter()
                    .map(|entry| ScopeChangeV1 {
                        path: entry.path.clone(),
                        change_kind: "upsert".to_string(),
                        size: entry.size,
                    }),
            )
            .collect::<Vec<_>>();
        changes.sort_by(|left, right| left.path.cmp(&right.path));
        let patch_content_bytes = verified_patch
            .patch
            .upserted_files
            .iter()
            .try_fold(0u64, |total, entry| total.checked_add(entry.size))
            .context("patch content-byte counter overflow")?;
        let candidate_content_bytes = candidate_source
            .manifest
            .files
            .iter()
            .try_fold(0u64, |total, entry| total.checked_add(entry.size))
            .context("candidate content-byte counter overflow")?;
        repositories.push(RepositoryScopeEvidenceV1 {
            repository: repository_input.repository.clone(),
            base_source_cid: expected.base_source_cid.clone(),
            candidate_source_cid: expected.candidate_source_cid.clone(),
            patch_cid: expected.patch_cid.clone(),
            patch_sha256: expected.patch_sha256.clone(),
            base_manifest_dag_cbor_hex: hex::encode(&base_source.dag_cbor_bytes),
            candidate_manifest_dag_cbor_hex: hex::encode(&candidate_source.dag_cbor_bytes),
            patch_dag_cbor_hex: hex::encode(&verified_patch.dag_cbor_bytes),
            patch_content_bytes,
            candidate_content_bytes,
            changes,
        });
    }

    let rationale_bytes = metadata_file_size(base_dir, &input.rationale_file, "rationale")?;
    let migration_notes_bytes =
        metadata_file_size(base_dir, &input.migration_notes_file, "migration notes")?;
    let test_plan_bytes = metadata_file_size(base_dir, &input.test_plan_file, "test plan")?;
    let mut evidence = ProposalScopeEvidenceV1 {
        schema_version: 1,
        classifier_version: governance_core::OBJECTIVE_RISK_CLASSIFIER_V2.to_string(),
        parent_ecosystem_cid: parent.root_cid.to_string(),
        candidate_ecosystem_cid: candidate.root_cid.to_string(),
        patch_cid: ecosystem_patch.root_cid.to_string(),
        repositories,
        rationale_bytes,
        migration_notes_bytes,
        test_plan_bytes,
        changed_file_count: 0,
        patch_bytes: 0,
        source_package_bytes: 0,
        description_bytes: 0,
        migration_operation_count: 0,
        derived_risk_class: RiskClass::Normal,
    };
    populate_scope_derived_fields(&mut evidence)?;
    let package = package_proposal_scope_evidence(evidence)?;
    let view = ScopeView {
        schema_version: 1,
        scope_evidence_cid: package.root_cid.to_string(),
        scope_evidence_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        evidence: package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("proposal-scope.car"), &package.car_bytes)?;
    write_new(
        &output.join("proposal-scope.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("proposal-scope.cid"),
        format!("{}\n", view.scope_evidence_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn scope_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "proposal scope CAR")?;
    let package = verify_proposal_scope_evidence_car(&bytes)?;
    print_json(&ScopeView {
        schema_version: 1,
        scope_evidence_cid: package.root_cid.to_string(),
        scope_evidence_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        evidence: package.value,
    })
}

fn development_policy_package_command(input: &Path, output_dir: &Path) -> Result<()> {
    let policy: DevelopmentPolicyBundleV1 =
        read_json_file(input, "decentralized development policy")?;
    let package = package_development_policy(policy)?;
    let view = DevelopmentPolicyView {
        schema_version: 1,
        policy_cid: package.root_cid.to_string(),
        policy_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        policy: package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("development-policy.car"), &package.car_bytes)?;
    write_new(
        &output.join("development-policy.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("development-policy.cid"),
        format!("{}\n", view.policy_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn development_policy_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "decentralized development-policy CAR")?;
    let package = verify_development_policy_car(&bytes)?;
    print_json(&DevelopmentPolicyView {
        schema_version: 1,
        policy_cid: package.root_cid.to_string(),
        policy_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        policy: package.value,
    })
}

fn populate_scope_derived_fields(evidence: &mut ProposalScopeEvidenceV1) -> Result<()> {
    let mut count = 0u32;
    let mut patch_bytes = 0u64;
    let mut source_bytes = 0u64;
    let mut migration_count = 0u32;
    let mut risk = RiskClass::Normal;
    for repository in &evidence.repositories {
        count = count
            .checked_add(u32::try_from(repository.changes.len())?)
            .context("changed-file counter overflow")?;
        patch_bytes = patch_bytes
            .checked_add(repository.patch_content_bytes)
            .context("patch-byte counter overflow")?;
        source_bytes = source_bytes
            .checked_add(repository.candidate_content_bytes)
            .context("source-byte counter overflow")?;
        for change in &repository.changes {
            if change.path.starts_with("migrations/")
                || change.path.contains("/migrations/")
                || change.path.starts_with("migration/")
                || change.path.contains("/migration/")
            {
                migration_count = migration_count
                    .checked_add(1)
                    .context("migration counter overflow")?;
            }
            risk = max_scope_risk(
                risk,
                governance_core::classify_repository_path(&repository.repository, &change.path),
            );
        }
    }
    evidence.changed_file_count = count;
    evidence.patch_bytes = patch_bytes;
    evidence.source_package_bytes = source_bytes;
    evidence.description_bytes = evidence
        .rationale_bytes
        .checked_add(evidence.migration_notes_bytes)
        .and_then(|value| value.checked_add(evidence.test_plan_bytes))
        .context("description-byte counter overflow")?;
    evidence.migration_operation_count = migration_count;
    evidence.derived_risk_class = risk;
    Ok(())
}

fn max_scope_risk(left: RiskClass, right: RiskClass) -> RiskClass {
    let rank = |risk| match risk {
        RiskClass::Normal => 0,
        RiskClass::Critical => 1,
        RiskClass::Migration => 2,
        RiskClass::Consensus => 3,
    };
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

fn metadata_file_size(base_dir: &Path, path: &Path, label: &str) -> Result<u32> {
    let bytes = read_regular_file(&resolve_input_path(base_dir, path), label)?;
    u32::try_from(bytes.len()).with_context(|| format!("{label} exceeds the u32 size limit"))
}

fn resolve_input_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn toolchain_package_command(ecosystem_car: &Path, output_dir: &Path) -> Result<()> {
    let ecosystem_bytes = read_regular_file(ecosystem_car, "ecosystem CAR")?;
    let ecosystem = verify_ecosystem_manifest_car(&ecosystem_bytes)?;
    let package = package_toolchain_manifest_for_ecosystem(&ecosystem.manifest)?;
    let view = ToolchainView {
        schema_version: 1,
        toolchain_manifest_cid: package.root_cid.to_string(),
        toolchain_manifest_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("toolchain-manifest.car"), &package.car_bytes)?;
    write_new(
        &output.join("toolchain-manifest.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("toolchain-manifest.cid"),
        format!("{}\n", view.toolchain_manifest_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn toolchain_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "toolchain-manifest CAR")?;
    let package = verify_toolchain_manifest_car(&bytes)?;
    print_json(&ToolchainView {
        schema_version: 1,
        toolchain_manifest_cid: package.root_cid.to_string(),
        toolchain_manifest_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: package.value,
    })
}

fn pinset_package_command(
    parent_car: &Path,
    candidate_car: &Path,
    patch_car: &Path,
    additional_cids: &[String],
    output_dir: &Path,
) -> Result<()> {
    let parent_bytes = read_regular_file(parent_car, "parent ecosystem CAR")?;
    let candidate_bytes = read_regular_file(candidate_car, "candidate ecosystem CAR")?;
    let patch_bytes = read_regular_file(patch_car, "aggregate ecosystem patch CAR")?;
    let parent = verify_ecosystem_manifest_car(&parent_bytes)?;
    let candidate = verify_ecosystem_manifest_car(&candidate_bytes)?;
    let patch = verify_ecosystem_patch_manifest_car(&patch_bytes)?;
    verify_ecosystem_transition(&parent, &candidate, &patch)?;
    let package = package_pinset_manifest_for_transition_with_additional(
        &candidate,
        &patch,
        additional_cids,
    )?;
    verify_pinset_manifest_for_transition(&package, &candidate, &patch)?;
    let view = PinsetView {
        schema_version: 1,
        pinset_cid: package.root_cid.to_string(),
        pinset_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.manifest,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("pinset-manifest.car"), &package.car_bytes)?;
    write_new(
        &output.join("pinset-manifest.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("pinset-manifest.cid"),
        format!("{}\n", view.pinset_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn pinset_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "pinset-manifest CAR")?;
    let package = verify_pinset_manifest_car(&bytes)?;
    print_json(&PinsetView {
        schema_version: 1,
        pinset_cid: package.root_cid.to_string(),
        pinset_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: package.manifest,
    })
}

fn parameters_package_command(input: &Path, output_dir: &Path) -> Result<()> {
    let parameters: GovernanceParameterSetV1 = read_json_file(input, "governance parameter set")?;
    let package = package_governance_parameters(parameters)?;
    let view = ParametersView {
        schema_version: 1,
        parameter_set_cid: package.root_cid.to_string(),
        parameter_set_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        parameters: package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(
        &output.join("governance-parameters.car"),
        &package.car_bytes,
    )?;
    write_new(
        &output.join("governance-parameters.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("governance-parameters.cid"),
        format!("{}\n", view.parameter_set_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn parameters_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "governance parameter CAR")?;
    let package = verify_governance_parameters_car(&bytes)?;
    print_json(&ParametersView {
        schema_version: 1,
        parameter_set_cid: package.root_cid.to_string(),
        parameter_set_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        parameters: package.value,
    })
}

fn epoch_parameters_package_command(input: &Path, output_dir: &Path) -> Result<()> {
    let parameters: EpochGovernanceParameterSetV1 =
        read_json_file(input, "Governance Day parameter set")?;
    validate_epoch_governance_parameters(&parameters)?;
    let package = package_dag_cbor(parameters)?;
    let view = EpochParametersView {
        schema_version: 1,
        parameter_set_cid: package.root_cid.to_string(),
        parameter_set_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        parameters: package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(
        &output.join("governance-day-parameters.car"),
        &package.car_bytes,
    )?;
    write_new(
        &output.join("governance-day-parameters.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("governance-day-parameters.cid"),
        format!("{}\n", view.parameter_set_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn epoch_parameters_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "Governance Day parameter CAR")?;
    let package = verify_dag_cbor_car::<EpochGovernanceParameterSetV1>(&bytes)?;
    validate_epoch_governance_parameters(&package.value)?;
    print_json(&EpochParametersView {
        schema_version: 1,
        parameter_set_cid: package.root_cid.to_string(),
        parameter_set_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        parameters: package.value,
    })
}

fn release_package_command(input: &Path, output_dir: &Path) -> Result<()> {
    let manifest: ReleaseManifestV1 = read_json_file(input, "release manifest")?;
    let package = package_release_manifest(manifest)?;
    let view = ReleaseView {
        schema_version: 1,
        release_manifest_cid: package.root_cid.to_string(),
        release_manifest_sha256: package.root_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        manifest: package.manifest,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("release-manifest.car"), &package.car_bytes)?;
    write_new(
        &output.join("release-manifest.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("release-manifest.cid"),
        format!("{}\n", view.release_manifest_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn release_inspect_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "release-manifest CAR")?;
    let package = verify_release_manifest_car(&bytes)?;
    print_json(&ReleaseView {
        schema_version: 1,
        release_manifest_cid: package.root_cid.to_string(),
        release_manifest_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        manifest: package.manifest,
    })
}

fn artifact_inspect_command(file: &Path) -> Result<()> {
    let bytes = read_regular_file(file, "artifact")?;
    let size = u64::try_from(bytes.len()).context("artifact size exceeds u64")?;
    print_json(&ArtifactView {
        schema_version: 1,
        cid: cid_for(RAW_CODEC, &bytes).to_string(),
        sha256: sha256_hex(&bytes),
        size,
    })
}

fn proposal_create_command(
    input: &Path,
    parameters: &Path,
    scope_car: &Path,
    output_dir: &Path,
) -> Result<()> {
    let content: ChangeProposalContentV1 = read_json_file(input, "proposal input")?;
    let parameters: GovernanceParameterSetV1 =
        read_json_file(parameters, "governance parameter set")?;
    let scope_bytes = read_regular_file(scope_car, "proposal scope CAR")?;
    let scope: governance_core::ProposalScopePackage = verify_dag_cbor_car(&scope_bytes)?;
    validate_proposal_scope_evidence(&scope.value)?;
    let package = package_change_proposal_with_scope(
        content,
        &parameters,
        &scope.root_cid.to_string(),
        &scope.value,
    )?;
    let view = ProposalView {
        proposal_id: package.proposal_id,
        proposal_cid: package.content_cid.to_string(),
        proposal_sha256: package.content_sha256,
        car_sha256: sha256_hex(&package.car_bytes),
        content: package.content,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(&output.join("proposal.car"), &package.car_bytes)?;
    write_new(
        &output.join("proposal.dag-cbor.hex"),
        format!("{}\n", hex::encode(&package.dag_cbor_bytes)).as_bytes(),
    )?;
    write_new(&output.join("proposal.json"), &deterministic_json(&view)?)?;
    write_new(
        &output.join("proposal.cid"),
        format!("{}\n", view.proposal_cid).as_bytes(),
    )?;
    print_json(&view)
}

fn proposal_verify_command(
    proposal_car: Option<&Path>,
    parameters: Option<&Path>,
    scope_car: Option<&Path>,
    base_car: Option<&Path>,
    candidate_car: Option<&Path>,
    patch_car: Option<&Path>,
) -> Result<()> {
    if let Some(proposal_car) = proposal_car {
        if base_car.is_some() || candidate_car.is_some() || patch_car.is_some() {
            bail!("proposal verification and patch verification are separate modes");
        }
        let parameters = parameters.context("--parameters is required with --proposal-car")?;
        let scope_car = scope_car.context("--scope-car is required with --proposal-car")?;
        let parameters: GovernanceParameterSetV1 =
            read_json_file(parameters, "governance parameter set")?;
        let bytes = read_regular_file(proposal_car, "proposal CAR")?;
        let scope_bytes = read_regular_file(scope_car, "proposal scope CAR")?;
        let scope = verify_proposal_scope_evidence_car(&scope_bytes)?;
        let package = verify_change_proposal_car_with_scope(
            &bytes,
            &parameters,
            &scope.root_cid.to_string(),
            &scope.value,
        )?;
        return print_json(&ProposalView {
            proposal_id: package.proposal_id,
            proposal_cid: package.content_cid.to_string(),
            proposal_sha256: package.content_sha256,
            car_sha256: sha256_hex(&bytes),
            content: package.content,
        });
    }
    if parameters.is_some() || scope_car.is_some() {
        bail!("--parameters and --scope-car are only valid with --proposal-car");
    }
    let base_car = base_car.context("--base-car is required in patch verification mode")?;
    let candidate_car =
        candidate_car.context("--candidate-car is required in patch verification mode")?;
    let patch_car = patch_car.context("--patch-car is required in patch verification mode")?;
    let base = read_regular_file(base_car, "base source CAR")?;
    let candidate = read_regular_file(candidate_car, "candidate source CAR")?;
    let patch = read_regular_file(patch_car, "source patch CAR")?;
    let verified = verify_source_patch(&base, &candidate, &patch)?;
    print_json(&PatchVerificationOutput {
        verified: true,
        patch_cid: verified.patch_cid.to_string(),
        patch_sha256: verified.patch_sha256,
        base_source_cid: verified.patch.base_source_cid,
        candidate_source_cid: verified.patch.candidate_source_cid,
        removed_paths: verified.patch.removed_paths.len(),
        upserted_files: verified.patch.upserted_files.len(),
    })
}

fn review_attestation_command(
    input: &Path,
    development_policy: Option<&Path>,
    output_dir: &Path,
) -> Result<()> {
    let payload: AgentReviewAttestationV1 = read_json_file(input, "agent review attestation")?;
    if let Some(policy_path) = development_policy {
        let policy_bytes = read_regular_file(policy_path, "decentralized development-policy CAR")?;
        let policy = verify_development_policy_car(&policy_bytes)?;
        if payload.agent_policy_cid != policy.root_cid.to_string() {
            bail!("agentPolicyCid does not match the verified decentralized policy CAR");
        }
    }
    let package = package_agent_review_attestation(payload)?;
    let unresolved_critical = package.value.unresolved_critical_findings;
    let fields = agent_attestation_commitment_fields(
        &package.root_cid.to_string(),
        &package.value.model_family,
        &package.value.owner_idena_address,
        unresolved_critical,
    )?;
    write_attestation_artifacts(
        CliAttestationKind::AgentReview,
        output_dir,
        &package,
        fields,
    )
}

fn build_attestation_command(input: &Path, output_dir: &Path) -> Result<()> {
    let payload: BuildAttestationV1 = read_json_file(input, "build attestation")?;
    let package = package_build_attestation(payload)?;
    let fields = build_attestation_commitment_fields(
        &package.root_cid.to_string(),
        &package.value.core_artifact_digest,
        &package.value.runtime_family,
        &package.value.architecture,
        &package.value.builder_identity,
    )?;
    write_attestation_artifacts(CliAttestationKind::Build, output_dir, &package, fields)
}

fn data_availability_attestation_command(input: &Path, output_dir: &Path) -> Result<()> {
    let payload: DataAvailabilityAttestationV1 =
        read_json_file(input, "data availability attestation")?;
    let package = package_data_availability_attestation(payload)?;
    let fields = data_availability_commitment_fields(
        &package.root_cid.to_string(),
        &package.value.candidate_ecosystem_cid,
        &package.value.pinset_cid,
        &package.value.provider_id,
        &package.value.operator_identity,
    )?;
    write_attestation_artifacts(
        CliAttestationKind::DataAvailability,
        output_dir,
        &package,
        fields,
    )
}

fn external_audit_attestation_command(input: &Path, output_dir: &Path) -> Result<()> {
    let payload: ExternalAuditAttestationV1 = read_json_file(input, "external audit attestation")?;
    let package = package_external_audit_attestation(payload)?;
    let verdict = match package.value.verdict {
        ExternalAuditVerdictV1::Pass => "pass",
        ExternalAuditVerdictV1::Fail => "fail",
    };
    let fields = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        package.root_cid,
        package.value.candidate_ecosystem_cid,
        package.value.scope_evidence_cid,
        package.value.auditor_organization_id,
        package.value.auditor_identity,
        verdict,
        package.value.unresolved_critical_findings,
        package.value.unresolved_high_findings,
    );
    write_attestation_artifacts(
        CliAttestationKind::ExternalAudit,
        output_dir,
        &package,
        fields,
    )
}

fn deployment_readiness_verify_command(input_path: &Path) -> Result<()> {
    let input: DeploymentReadinessInputV1 =
        read_json_file(input_path, "deployment readiness input")?;
    if input.schema_version != 1 {
        bail!("deployment readiness schemaVersion must be 1");
    }
    if input.build_attestation_cars.len() > 256
        || input.data_availability_attestation_cars.len() > 256
        || input.external_audit_attestation_cars.len() > 64
    {
        bail!("deployment readiness evidence list exceeds its deterministic limit");
    }
    let base = input_path.parent().unwrap_or_else(|| Path::new("."));
    let resolve = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    };
    let scope_bytes = read_regular_file(&resolve(&input.scope_car), "scope evidence CAR")?;
    let scope = verify_proposal_scope_evidence_car(&scope_bytes)?;
    let builds = input
        .build_attestation_cars
        .iter()
        .map(|path| {
            let bytes = read_regular_file(&resolve(path), "build attestation CAR")?;
            let package = verify_build_attestation_car(&bytes)?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let availability = input
        .data_availability_attestation_cars
        .iter()
        .map(|path| {
            let bytes = read_regular_file(&resolve(path), "availability attestation CAR")?;
            let package = verify_data_availability_attestation_car(&bytes)?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let audits = input
        .external_audit_attestation_cars
        .iter()
        .map(|path| {
            let bytes = read_regular_file(&resolve(path), "external audit attestation CAR")?;
            let package = verify_external_audit_attestation_car(&bytes)?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let report = evaluate_deployment_readiness(
        &scope.root_cid.to_string(),
        &scope.value,
        &builds,
        &availability,
        &audits,
        input.required_availability_through_block,
    )?;
    print_json(&report)?;
    if !report.ready {
        bail!(
            "deployment readiness gate failed: {}",
            report.failure_codes.join(", ")
        );
    }
    Ok(())
}

fn identity_metrics_attestation_command(input: &Path, output_dir: &Path) -> Result<()> {
    let payload: IdentityMetricsAttestationV1 =
        read_json_file(input, "identity metrics attestation")?;
    let package = package_identity_metrics_attestation(payload)?;
    write_identity_metrics_attestation_artifacts(output_dir, &package)
}

fn identity_metrics_attestation_verify_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "identity metrics attestation CAR")?;
    let package = verify_identity_metrics_attestation_car(&bytes)?;
    print_json(&AttestationView {
        schema_version: 1,
        attestation_kind: "identity_metrics_v1",
        attestation_cid: package.root_cid.to_string(),
        attestation_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        payload: package.value,
    })
}

fn identity_metrics_snapshot_package_command(input: &Path, output_dir: &Path) -> Result<()> {
    let payload: IdentityMetricsSnapshotV1 = read_json_file(input, "identity metrics snapshot")?;
    let package = package_identity_metrics_snapshot(payload)?;
    let cid = package.root_cid.to_string();
    let view = IdentityMetricsSnapshotView {
        schema_version: 1,
        snapshot_cid: cid.clone(),
        snapshot_sha256: package.root_sha256.clone(),
        car_sha256: sha256_hex(&package.car_bytes),
        snapshot: &package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(
        &output.join("identity-metrics-snapshot.car"),
        &package.car_bytes,
    )?;
    write_new(
        &output.join("identity-metrics-snapshot.dag-cbor.hex"),
        format!("{}\n", hex::encode(&package.dag_cbor_bytes)).as_bytes(),
    )?;
    write_new(
        &output.join("identity-metrics-snapshot.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("identity-metrics-snapshot.cid"),
        format!("{cid}\n").as_bytes(),
    )?;
    print_json(&view)
}

fn identity_metrics_snapshot_verify_command(car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "identity metrics snapshot CAR")?;
    let package = verify_identity_metrics_snapshot_car(&bytes)?;
    print_json(&IdentityMetricsSnapshotView {
        schema_version: 1,
        snapshot_cid: package.root_cid.to_string(),
        snapshot_sha256: package.root_sha256,
        car_sha256: sha256_hex(&bytes),
        snapshot: package.value,
    })
}

fn attestation_verify_command(kind: CliAttestationKind, car: &Path) -> Result<()> {
    let bytes = read_regular_file(car, "attestation CAR")?;
    match kind {
        CliAttestationKind::AgentReview => {
            let package = verify_agent_review_attestation_car(&bytes)?;
            print_json(&AttestationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                payload: package.value,
            })
        }
        CliAttestationKind::Build => {
            let package = verify_build_attestation_car(&bytes)?;
            print_json(&AttestationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                payload: package.value,
            })
        }
        CliAttestationKind::DataAvailability => {
            let package = verify_data_availability_attestation_car(&bytes)?;
            print_json(&AttestationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                payload: package.value,
            })
        }
        CliAttestationKind::ExternalAudit => {
            let package = verify_external_audit_attestation_car(&bytes)?;
            print_json(&AttestationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                payload: package.value,
            })
        }
    }
}

fn attestation_commitment_command(
    kind: CliAttestationKind,
    entries: &Path,
    output_dir: &Path,
) -> Result<()> {
    let entries: Vec<AttestationCommitmentEntryV1> =
        read_json_file(entries, "attestation commitment entries")?;
    let commitment = build_attestation_commitment(kind.domain(), &entries)?;
    let output = secure_output_directory(output_dir)?;
    let bytes = deterministic_json(&serde_json::json!({
        "schemaVersion": 1,
        "domain": kind.domain(),
        "root": commitment.root,
        "proofs": commitment.proofs,
    }))?;
    write_new(&output.join("attestation-commitment.json"), &bytes)?;
    print!("{}", String::from_utf8(bytes)?);
    Ok(())
}

fn write_attestation_artifacts<T: Serialize>(
    kind: CliAttestationKind,
    output_dir: &Path,
    package: &governance_core::AttestationPackage<T>,
    canonical_fields: String,
) -> Result<()> {
    let cid = package.root_cid.to_string();
    let view = AttestationView {
        schema_version: 1,
        attestation_kind: kind.domain(),
        attestation_cid: cid.clone(),
        attestation_sha256: package.root_sha256.clone(),
        car_sha256: sha256_hex(&package.car_bytes),
        payload: &package.value,
    };
    let entry = AttestationCommitmentEntryV1 {
        attestation_cid: cid.clone(),
        canonical_fields,
    };
    let output = secure_output_directory(output_dir)?;
    let prefix = kind.filename();
    write_new(&output.join(format!("{prefix}.car")), &package.car_bytes)?;
    write_new(
        &output.join(format!("{prefix}.dag-cbor.hex")),
        format!("{}\n", hex::encode(&package.dag_cbor_bytes)).as_bytes(),
    )?;
    write_new(
        &output.join(format!("{prefix}.json")),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join(format!("{prefix}.cid")),
        format!("{cid}\n").as_bytes(),
    )?;
    write_new(
        &output.join("commitment-entry.json"),
        &deterministic_json(&entry)?,
    )?;
    print_json(&view)
}

fn write_identity_metrics_attestation_artifacts(
    output_dir: &Path,
    package: &governance_core::AttestationPackage<IdentityMetricsAttestationV1>,
) -> Result<()> {
    let cid = package.root_cid.to_string();
    let view = AttestationView {
        schema_version: 1,
        attestation_kind: "identity_metrics_v1",
        attestation_cid: cid.clone(),
        attestation_sha256: package.root_sha256.clone(),
        car_sha256: sha256_hex(&package.car_bytes),
        payload: &package.value,
    };
    let output = secure_output_directory(output_dir)?;
    write_new(
        &output.join("identity-metrics-attestation.car"),
        &package.car_bytes,
    )?;
    write_new(
        &output.join("identity-metrics-attestation.dag-cbor.hex"),
        format!("{}\n", hex::encode(&package.dag_cbor_bytes)).as_bytes(),
    )?;
    write_new(
        &output.join("identity-metrics-attestation.json"),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join("identity-metrics-attestation.cid"),
        format!("{cid}\n").as_bytes(),
    )?;
    print_json(&view)
}

fn checkout_command(car: &Path, output: &Path) -> Result<()> {
    require_absolute(output, "checkout output")?;
    let bytes = read_regular_file(car, "source CAR")?;
    let cid = checkout_source_car(&bytes, output)?;
    print_json(&serde_json::json!({"checkedOut": true, "sourceTreeCid": cid.to_string()}))
}

async fn pin_command(
    car: &Path,
    store: &Path,
    ecosystem_cid: Option<&str>,
    kubo_api: Option<&str>,
    allow_remote_api: bool,
    external_provider_values: &[String],
) -> Result<()> {
    let bytes = read_regular_file(car, "CAR")?;
    let root_cid = verify_car_integrity(&bytes)?.to_string();
    pin_locally(store, ecosystem_cid, &root_cid, &bytes)?;
    let client = http_client()?;
    if let Some(api) = kubo_api {
        import_to_public_kubo(&client, api, allow_remote_api, &root_cid, &bytes).await?;
    }
    let providers = external_provider_values
        .iter()
        .map(|value| parse_external_provider(value))
        .collect::<Result<Vec<_>>>()?;
    if !providers.is_empty() {
        if kubo_api.is_none() {
            bail!("external pin requests require --kubo-api so content is first published");
        }
        request_external_pins(&client, &root_cid, &providers).await?;
    }
    print_json(&serde_json::json!({
        "pinned": true,
        "rootCid": root_cid,
        "localStore": store,
        "publicKuboImported": kubo_api.is_some(),
        "externalProvidersRequested": providers.len()
    }))
}

async fn fetch_command(cid: &str, gateways: &[String], output_dir: &Path) -> Result<()> {
    let client = http_client()?;
    let bytes = fetch_car_from_gateways(&client, cid, gateways).await?;
    let output = secure_output_directory(output_dir)?;
    let path = output.join(format!("{cid}.car"));
    write_new(&path, &bytes)?;
    print_json(&serde_json::json!({
        "fetched": true,
        "rootCid": cid,
        "carSha256": sha256_hex(&bytes),
        "output": path
    }))
}

fn simulate_command(
    stake_atoms: u128,
    state: CliIdentityState,
    finalized_authored_flips: u64,
    reported_authored_flips: u64,
) -> Result<()> {
    let state = IdentityState::from(state);
    let Some(status_bps) = state.status_bps() else {
        bail!("selected identity state is not eligible for governance");
    };
    let trust_bps = flip_trust_bps(finalized_authored_flips, reported_authored_flips)?;
    let weight = effective_vote_weight(stake_atoms, status_bps, trust_bps)?;
    print_json(&SimulationOutput {
        stake_atoms: stake_atoms.to_string(),
        stake_score: stake_score(stake_atoms).to_string(),
        identity_status_bps: status_bps,
        flip_trust_bps: trust_bps,
        effective_vote_weight: weight.to_string(),
    })
}

fn stake_scenario(
    name: &'static str,
    identities: u32,
    idna_per_identity: u128,
    state: IdentityState,
    finalized: u64,
    reported: u64,
) -> Result<StakeScenarioOutput> {
    const IDNA_ATOMS: u128 = 1_000_000_000_000_000_000;
    let stake_atoms = idna_per_identity
        .checked_mul(IDNA_ATOMS)
        .context("scenario stake overflow")?;
    let status = state
        .status_bps()
        .context("scenario identity must be eligible")?;
    let trust = flip_trust_bps(finalized, reported)?;
    let weight = effective_vote_weight(stake_atoms, status, trust)?;
    let aggregate = weight
        .checked_mul(u128::from(identities))
        .context("scenario aggregate overflow")?;
    let state_name = match state {
        IdentityState::Human => "Human",
        IdentityState::Verified => "Verified",
        IdentityState::Newbie => "Newbie",
        _ => bail!("scenario identity must be eligible"),
    };
    Ok(StakeScenarioOutput {
        name,
        identities,
        stake_atoms_per_identity: stake_atoms.to_string(),
        state: state_name,
        finalized_authored_flips: finalized,
        reported_authored_flips: reported,
        stake_score_per_identity: stake_score(stake_atoms).to_string(),
        identity_status_bps: status,
        flip_trust_bps: trust,
        weight_per_identity: weight.to_string(),
        aggregate_weight: aggregate.to_string(),
    })
}

fn passing_normal_evidence(yes_weight: u128, no_weight: u128, total: u128) -> AcceptanceEvidence {
    AcceptanceEvidence {
        yes_weight,
        no_weight,
        abstain_weight: 0,
        total_registered_weight: total,
        distinct_yes_identities: 10,
        verified_or_human_yes_identities: 10,
        valid_agent_attestations: 3,
        distinct_agent_families: 2,
        distinct_agent_owner_identities: 2,
        unresolved_critical_findings: 0,
        valid_builders: 2,
        distinct_builder_platforms: 1,
        matching_core_artifact_digests: true,
        independent_data_availability_providers: 2,
    }
}

fn gate_scenario(
    name: &'static str,
    risk_class: RiskClass,
    evidence: AcceptanceEvidence,
    parameters: &GovernanceParameterSetV1,
) -> GateScenarioOutput {
    let result = governance_core::evaluate_gates(
        risk_class,
        &parameters.normal,
        &parameters.critical,
        &evidence,
    );
    GateScenarioOutput {
        name,
        risk_class,
        evidence,
        result,
    }
}

fn build_scenario_report() -> Result<ScenarioReport> {
    let parameters = GovernanceParameterSetV1::experimental_defaults();
    let stake_scenarios = vec![
        stake_scenario(
            "one-human-10000-idna",
            1,
            10_000,
            IdentityState::Human,
            0,
            0,
        )?,
        stake_scenario(
            "ten-newbies-1000-idna",
            10,
            1_000,
            IdentityState::Newbie,
            0,
            0,
        )?,
        stake_scenario(
            "ten-humans-1000-idna",
            10,
            1_000,
            IdentityState::Human,
            0,
            0,
        )?,
        stake_scenario(
            "human-no-reported-flips",
            1,
            1_000,
            IdentityState::Human,
            100,
            0,
        )?,
        stake_scenario(
            "human-ten-percent-reported",
            1,
            1_000,
            IdentityState::Human,
            100,
            10,
        )?,
        stake_scenario("human-all-reported", 1, 1_000, IdentityState::Human, 20, 20)?,
    ];

    let whale = stake_scenarios[0]
        .aggregate_weight
        .parse::<u128>()
        .context("invalid internal whale weight")?;
    let coalition = stake_scenarios[2]
        .aggregate_weight
        .parse::<u128>()
        .context("invalid internal coalition weight")?;
    let total = whale
        .checked_add(coalition)
        .context("whale scenario overflow")?;

    let broad_coalition = passing_normal_evidence(coalition, whale, total);
    let mut low_turnout = passing_normal_evidence(10, 0, 100);
    low_turnout.distinct_yes_identities = 7;
    low_turnout.verified_or_human_yes_identities = 3;
    let mut ai_collusion = passing_normal_evidence(70, 10, 100);
    ai_collusion.distinct_agent_families = 1;
    ai_collusion.distinct_agent_owner_identities = 1;
    let mut builder_collusion = passing_normal_evidence(70, 10, 100);
    builder_collusion.matching_core_artifact_digests = false;
    let mut critical_underprovisioned = passing_normal_evidence(80, 10, 100);
    critical_underprovisioned.distinct_yes_identities = 12;
    critical_underprovisioned.verified_or_human_yes_identities = 5;

    let gate_scenarios = vec![
        gate_scenario(
            "broad-human-coalition-versus-one-whale",
            RiskClass::Normal,
            broad_coalition,
            &parameters,
        ),
        gate_scenario("low-turnout", RiskClass::Normal, low_turnout, &parameters),
        gate_scenario(
            "ai-owner-and-family-collusion",
            RiskClass::Normal,
            ai_collusion,
            &parameters,
        ),
        gate_scenario(
            "builder-digest-collusion",
            RiskClass::Normal,
            builder_collusion,
            &parameters,
        ),
        gate_scenario(
            "critical-proposal-with-normal-attestation-counts",
            RiskClass::Critical,
            critical_underprovisioned,
            &parameters,
        ),
    ];

    Ok(ScenarioReport {
        schema_version: 1,
        stake_scenarios,
        gate_scenarios,
        residual_risk: "Concave per-identity weighting does not eliminate stake splitting, identity farming, bribery, or hidden common control.",
    })
}

fn write_source_artifacts(
    output: &Path,
    repository: &str,
    car: &[u8],
    view: &SourceView,
) -> Result<()> {
    let prefix = output.join(format!("{repository}.source"));
    write_new(&prefix.with_extension("source.car"), car)?;
    write_new(
        &prefix.with_extension("source.json"),
        &deterministic_json(view)?,
    )?;
    write_new(
        &prefix.with_extension("source.cid"),
        format!("{}\n", view.source_tree_cid).as_bytes(),
    )?;
    write_new(
        &prefix.with_extension("source.sha256"),
        format!("{}  {}.source.car\n", view.car_sha256, repository).as_bytes(),
    )?;
    Ok(())
}

fn write_patch_artifacts(
    output: &Path,
    repository: &str,
    car: &[u8],
    view: &PatchView,
) -> Result<()> {
    let prefix = output.join(format!("{repository}.patch"));
    write_new(&prefix.with_extension("patch.car"), car)?;
    write_new(
        &prefix.with_extension("patch.json"),
        &deterministic_json(view)?,
    )?;
    write_new(
        &prefix.with_extension("patch.cid"),
        format!("{}\n", view.patch_cid).as_bytes(),
    )?;
    write_new(
        &prefix.with_extension("patch.sha256"),
        format!("{}  {}.patch.car\n", view.car_sha256, repository).as_bytes(),
    )?;
    Ok(())
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{label} must be a non-symlink regular file: {}",
            path.display()
        );
    }
    fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let bytes = read_regular_file(path, label)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {label} as strict JSON"))
}

fn require_absolute(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} must be absolute: {}", path.display());
    }
    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    print!("{}", String::from_utf8(deterministic_json(value)?)?);
    Ok(())
}

#[cfg(test)]
mod scenario_tests {
    use super::*;

    #[test]
    fn canonical_transition_artifact_commands_require_explicit_inputs() {
        let pinset = Cli::try_parse_from([
            "pohw-governance",
            "pinset-package",
            "--parent-car",
            "/tmp/parent.car",
            "--candidate-car",
            "/tmp/candidate.car",
            "--patch-car",
            "/tmp/patch.car",
            "--additional-cid",
            "bafkreiatest",
            "--output-dir",
            "/tmp/pinset",
        ])
        .unwrap();
        match pinset.command {
            Command::PinsetPackage {
                additional_cids, ..
            } => assert_eq!(additional_cids, vec!["bafkreiatest"]),
            _ => panic!("pinset-package parsed as the wrong command"),
        }

        let toolchain = Cli::try_parse_from([
            "pohw-governance",
            "toolchain-package",
            "--ecosystem-car",
            "/tmp/candidate.car",
            "--output-dir",
            "/tmp/toolchain",
        ])
        .unwrap();
        assert!(matches!(
            toolchain.command,
            Command::ToolchainPackage { .. }
        ));

        let patch = Cli::try_parse_from([
            "pohw-governance",
            "ecosystem-patch-package",
            "--manifest",
            "/tmp/ecosystem-patch.json",
            "--output-dir",
            "/tmp/ecosystem-patch",
        ])
        .unwrap();
        assert!(matches!(
            patch.command,
            Command::EcosystemPatchPackage { .. }
        ));
    }

    #[test]
    fn fixed_capture_scenarios_expose_independent_failures() {
        let report = build_scenario_report().unwrap();
        assert_eq!(report.stake_scenarios.len(), 6);
        assert!(report.gate_scenarios[0].result.accepted);
        assert!(!report.gate_scenarios[1].result.pos.passed);
        assert!(!report.gate_scenarios[2].result.poaw.passed);
        assert!(!report.gate_scenarios[3].result.verification_work.passed);
        assert!(!report.gate_scenarios[4].result.accepted);
        assert!(
            report.stake_scenarios[1]
                .aggregate_weight
                .parse::<u128>()
                .unwrap()
                > report.stake_scenarios[0]
                    .aggregate_weight
                    .parse::<u128>()
                    .unwrap()
        );
    }

    #[test]
    fn epoch_governance_demo_command_is_explicitly_local() {
        let command = Cli::try_parse_from([
            "pohw-governance",
            "demo-epoch-governance",
            "--output-dir",
            "/tmp/governance-demo",
        ])
        .unwrap();
        assert!(matches!(
            command.command,
            Command::DemoEpochGovernance { .. }
        ));
        let report = run_local_governance_day_protocol_demo().unwrap();
        assert!(report.local_test_data);
        assert!(!report.code_installed_automatically);
    }

    #[test]
    fn executable_proposal_verification_requires_scope_evidence() {
        let error = proposal_verify_command(
            Some(Path::new("/not/read/proposal.car")),
            Some(Path::new("/not/read/parameters.json")),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("--scope-car is required with --proposal-car"));
    }
}
