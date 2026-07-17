mod ipfs;
mod output;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use governance_core::{
    agent_attestation_commitment_fields, attestation_authentication_request,
    build_attestation_commitment, build_attestation_commitment_fields, checkout_source_car,
    cid_for, create_source_patch, data_availability_commitment_fields, effective_vote_weight,
    evaluate_deployment_readiness_evidence, flip_trust_bps, migration_rehearsal_digest,
    package_agent_review_attestation, package_build_attestation,
    package_change_proposal_with_scope, package_dag_cbor, package_data_availability_attestation,
    package_deployment_readiness_evidence, package_development_policy, package_ecosystem_manifest,
    package_ecosystem_patch_manifest, package_external_audit_attestation,
    package_governance_parameters, package_identity_metrics_attestation,
    package_identity_metrics_snapshot, package_migration_rehearsal_attestation,
    package_pinset_manifest_for_transition_with_additional, package_proposal_scope_evidence,
    package_release_manifest, package_source_commit_receipt,
    package_source_files_with_artifact_exclusions, package_source_tree_with_artifact_exclusions,
    package_toolchain_manifest_for_ecosystem, run_local_governance_day_protocol_demo, sha256_hex,
    signature_attestation_authentication, stake_score, validate_epoch_governance_parameters,
    validate_proposal_scope_evidence, verify_agent_review_attestation_car,
    verify_attestation_authentication, verify_build_attestation_car, verify_car_integrity,
    verify_change_proposal_car_with_scope, verify_dag_cbor_car,
    verify_data_availability_attestation_car, verify_deployment_readiness_evidence_car,
    verify_development_policy_car, verify_ecosystem_manifest_car,
    verify_ecosystem_patch_manifest_car, verify_ecosystem_transition,
    verify_external_audit_attestation_car, verify_governance_parameters_car,
    verify_identity_metrics_attestation_car, verify_identity_metrics_snapshot_car,
    verify_migration_rehearsal_attestation_car, verify_pinset_manifest_car,
    verify_pinset_manifest_for_transition, verify_proposal_scope_evidence_car,
    verify_release_manifest_car, verify_source_car, verify_source_commit_receipt_car,
    verify_source_patch, verify_toolchain_manifest_car,
    verify_tree_matches_car_with_artifact_exclusions, AcceptanceEvidence, AddressedAttestationV1,
    AddressedSourceCommitReceiptV1, AgentReviewAttestationV1, AttestationAuthenticationRequestV1,
    AttestationAuthenticationV1, AttestationCommitmentEntryV1, BuildAttestationV1,
    ChangeProposalContentV1, DataAvailabilityAttestationV1, DeploymentReadinessEvidenceV1,
    DevelopmentPolicyBundleV1, EcosystemManifestV1, EcosystemPatchManifestV1,
    EpochGovernanceParameterSetV1, ExternalAuditAttestationV1, ExternalAuditVerdictV1, GateResults,
    GovernanceParameterSetV1, IdentityMetricsAttestationV1, IdentityMetricsSnapshotV1,
    IdentityState, MigrationRehearsalAttestationV1, PinsetManifestV1, ProposalScopeEvidenceV1,
    ReleaseManifestV1, RepositoryScopeEvidenceV1, RiskClass, ScopeChangeV1, SourceCommitReceiptV1,
    SourceInputFile, SourcePatchV1, SourceTreeManifestV1, ToolchainManifestV1,
    AGENT_REVIEW_COMMITMENT_DOMAIN, BUILD_ATTESTATION_COMMITMENT_DOMAIN,
    DATA_AVAILABILITY_COMMITMENT_DOMAIN, EXTERNAL_AUDIT_ATTESTATION_DOMAIN, MAX_SOURCE_FILES,
    MAX_SOURCE_FILE_BYTES, MIGRATION_REHEARSAL_ATTESTATION_DOMAIN,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

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
    /// Package files directly from one exact Git commit without using the worktree.
    PackageCommit {
        #[arg(long)]
        git_repository: PathBuf,
        /// Full lowercase SHA-1 or SHA-256 commit object id; branches and tags are rejected.
        #[arg(long)]
        commit: String,
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
    /// Package one independently observed deployed migration and rollback rehearsal.
    MigrationRehearsalAttestation {
        #[arg(long)]
        input: PathBuf,
        /// Replace rehearsalDigest with the deterministic digest derived from the payload.
        #[arg(long)]
        derive_rehearsal_digest: bool,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Fail unless independent build, public-pin, and external-audit evidence is complete.
    DeploymentReadinessVerify {
        #[arg(long)]
        input: PathBuf,
        /// Emit the verified canonical readiness report CAR and digest sidecars.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Recompute a readiness report from its canonical authenticated evidence bundle.
    DeploymentReadinessEvidenceVerify {
        #[arg(long)]
        car: PathBuf,
    },
    /// Bind a detached Idena signature to an exact attestation CAR.
    AttestationAuthenticate {
        #[arg(long, value_enum)]
        kind: CliAttestationKind,
        #[arg(long)]
        car: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
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
        /// Detached authentication envelope; omission verifies content only.
        #[arg(long)]
        authentication: Option<PathBuf>,
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
    MigrationRehearsal,
}

impl CliAttestationKind {
    fn domain(self) -> &'static str {
        match self {
            Self::AgentReview => AGENT_REVIEW_COMMITMENT_DOMAIN,
            Self::Build => BUILD_ATTESTATION_COMMITMENT_DOMAIN,
            Self::DataAvailability => DATA_AVAILABILITY_COMMITMENT_DOMAIN,
            Self::ExternalAudit => EXTERNAL_AUDIT_ATTESTATION_DOMAIN,
            Self::MigrationRehearsal => MIGRATION_REHEARSAL_ATTESTATION_DOMAIN,
        }
    }

    fn filename(self) -> &'static str {
        match self {
            Self::AgentReview => "agent-review-attestation",
            Self::Build => "build-attestation",
            Self::DataAvailability => "data-availability-attestation",
            Self::ExternalAudit => "external-audit-attestation",
            Self::MigrationRehearsal => "migration-rehearsal-attestation",
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceCommitView {
    schema_version: u16,
    receipt_cid: String,
    receipt_sha256: String,
    receipt_car_sha256: String,
    receipt: SourceCommitReceiptV1,
    source: SourceView,
}

#[derive(Debug)]
struct GitTreeEntry {
    path: String,
    mode: u32,
    object_id: String,
    size: u64,
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
    #[serde(default)]
    source_commit_receipts: Vec<SourceCommitReceiptInputV1>,
    build_attestations: Vec<AuthenticatedAttestationInputV1>,
    data_availability_attestations: Vec<AuthenticatedAttestationInputV1>,
    external_audit_attestations: Vec<AuthenticatedAttestationInputV1>,
    #[serde(default)]
    migration_rehearsal_attestations: Vec<AuthenticatedAttestationInputV1>,
    required_availability_through_block: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceCommitReceiptInputV1 {
    car: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticatedAttestationInputV1 {
    car: PathBuf,
    authentication: PathBuf,
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
struct AttestationVerificationView<T> {
    schema_version: u16,
    attestation_kind: &'static str,
    attestation_cid: String,
    attestation_sha256: String,
    car_sha256: String,
    content_verified: bool,
    authentication_verified: bool,
    authenticated_identity: Option<String>,
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
struct DeploymentReadinessReportView<T> {
    schema_version: u16,
    report_cid: String,
    report_sha256: String,
    car_sha256: String,
    report: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentReadinessEvidenceVerificationView<T> {
    schema_version: u16,
    evidence_bundle_cid: String,
    report_cid: String,
    report_sha256: String,
    report: T,
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
        Command::PackageCommit {
            git_repository,
            commit,
            repository,
            output_dir,
            artifact_exclusions,
        } => package_commit_command(
            &git_repository,
            &commit,
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
        Command::MigrationRehearsalAttestation {
            input,
            derive_rehearsal_digest,
            output_dir,
        } => migration_rehearsal_attestation_command(&input, derive_rehearsal_digest, &output_dir),
        Command::DeploymentReadinessVerify { input, output_dir } => {
            deployment_readiness_verify_command(&input, output_dir.as_deref())
        }
        Command::DeploymentReadinessEvidenceVerify { car } => {
            deployment_readiness_evidence_verify_command(&car)
        }
        Command::AttestationAuthenticate {
            kind,
            car,
            signature_file,
            output_dir,
        } => attestation_authenticate_command(kind, &car, &signature_file, &output_dir),
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
        Command::AttestationVerify {
            kind,
            car,
            authentication,
        } => attestation_verify_command(kind, &car, authentication.as_deref()),
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

fn package_commit_command(
    git_repository: &Path,
    commit: &str,
    repository: &str,
    output_dir: &Path,
    artifact_exclusions: Option<&Path>,
) -> Result<()> {
    require_absolute(git_repository, "Git repository")?;
    let metadata = fs::symlink_metadata(git_repository)
        .with_context(|| format!("cannot inspect Git repository {}", git_repository.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Git repository must be a non-symlink directory");
    }
    let object_format = git_text(git_repository, &["rev-parse", "--show-object-format"])?;
    let oid_length = match object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => bail!("Git repository uses unsupported object format {object_format}"),
    };
    validate_exact_git_oid(commit, oid_length, "commit")?;
    let commit_expression = format!("{commit}^{{commit}}");
    let resolved_commit = git_text(
        git_repository,
        &["rev-parse", "--verify", commit_expression.as_str()],
    )?;
    if resolved_commit != commit {
        bail!("Git commit did not resolve to the exact requested object id");
    }
    let tree_expression = format!("{commit}^{{tree}}");
    let git_tree = git_text(
        git_repository,
        &["rev-parse", "--verify", tree_expression.as_str()],
    )?;
    validate_exact_git_oid(&git_tree, oid_length, "tree")?;

    let entries = read_git_tree(git_repository, commit, oid_length)?;
    let tracked_file_count = u32::try_from(entries.len())
        .context("Git tree contains too many tracked files for a portable receipt")?;
    let files = read_git_blobs(git_repository, &object_format, &entries)?;
    let exclusions = read_artifact_exclusions(artifact_exclusions)?;
    let package =
        package_source_files_with_artifact_exclusions(repository, files.clone(), &exclusions)?;
    let repeated = package_source_files_with_artifact_exclusions(repository, files, &exclusions)?;
    if package.root_cid != repeated.root_cid || package.car_bytes != repeated.car_bytes {
        bail!("exact-commit source packaging was not byte-for-byte deterministic");
    }
    let car_sha256 = sha256_hex(&package.car_bytes);
    let receipt_package = package_source_commit_receipt(SourceCommitReceiptV1 {
        schema_version: 1,
        repository: repository.to_string(),
        git_object_format: object_format,
        git_commit: resolved_commit,
        git_tree,
        source_tree_cid: package.root_cid.to_string(),
        source_tree_sha256: package.source_tree_sha256.clone(),
        car_sha256: car_sha256.clone(),
        tracked_file_count,
        packaged_file_count: u32::try_from(package.manifest.files.len())
            .context("source package contains too many files for a portable receipt")?,
    })?;
    let source = SourceView {
        schema_version: 1,
        source_tree_cid: package.root_cid.to_string(),
        source_tree_sha256: package.source_tree_sha256.clone(),
        car_sha256,
        manifest: package.manifest,
    };
    let view = SourceCommitView {
        schema_version: 1,
        receipt_cid: receipt_package.root_cid.to_string(),
        receipt_sha256: receipt_package.root_sha256.clone(),
        receipt_car_sha256: sha256_hex(&receipt_package.car_bytes),
        receipt: receipt_package.value,
        source,
    };
    let output = secure_output_directory(output_dir)?;
    write_source_artifacts(&output, repository, &package.car_bytes, &view.source)?;
    write_new(
        &output.join(format!("{repository}.source-commit-receipt.car")),
        &receipt_package.car_bytes,
    )?;
    write_new(
        &output.join(format!("{repository}.source-commit-receipt.json")),
        &deterministic_json(&view)?,
    )?;
    write_new(
        &output.join(format!("{repository}.source-commit-receipt.cid")),
        format!("{}\n", view.receipt_cid).as_bytes(),
    )?;
    write_new(
        &output.join(format!("{repository}.source-commit-receipt.sha256")),
        format!(
            "{}  {}.source-commit-receipt.car\n",
            view.receipt_car_sha256, repository
        )
        .as_bytes(),
    )?;
    print_json(&view)
}

fn read_git_tree(
    git_repository: &Path,
    commit: &str,
    oid_length: usize,
) -> Result<Vec<GitTreeEntry>> {
    let output = git_output(
        git_repository,
        &["ls-tree", "-r", "-z", "--full-tree", "--long", commit],
    )?;
    let mut entries = Vec::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if entries.len() >= MAX_SOURCE_FILES {
            bail!("Git tree exceeds the {MAX_SOURCE_FILES}-file source limit");
        }
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("Git tree record is missing its path separator")?;
        let header =
            std::str::from_utf8(&record[..separator]).context("Git tree metadata is not UTF-8")?;
        let path = std::str::from_utf8(&record[separator + 1..])
            .context("Git source paths must be UTF-8")?
            .to_string();
        let fields = header.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            bail!("Git tree record has a noncanonical field count");
        }
        if fields[1] != "blob" {
            bail!("Git tree contains a non-blob entry at {path}");
        }
        let mode = match fields[0] {
            "100644" => 0o644,
            "100755" => 0o755,
            "120000" => bail!("Git source symlinks are rejected: {path}"),
            "160000" => bail!("Git submodules are rejected: {path}"),
            _ => bail!("Git source entry has an unsupported mode at {path}"),
        };
        validate_exact_git_oid(fields[2], oid_length, "blob")?;
        let size = fields[3]
            .parse::<u64>()
            .with_context(|| format!("Git blob size is invalid at {path}"))?;
        if size > MAX_SOURCE_FILE_BYTES {
            bail!("Git blob exceeds the source file limit at {path}");
        }
        entries.push(GitTreeEntry {
            path,
            mode,
            object_id: fields[2].to_string(),
            size,
        });
    }
    Ok(entries)
}

fn read_git_blobs(
    git_repository: &Path,
    object_format: &str,
    entries: &[GitTreeEntry],
) -> Result<Vec<SourceInputFile>> {
    let mut child = git_process(git_repository)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start Git object reader")?;
    let mut input = child
        .stdin
        .take()
        .context("Git object reader has no stdin")?;
    let output = child
        .stdout
        .take()
        .context("Git object reader has no stdout")?;
    let mut output = BufReader::new(output);
    let result = (|| -> Result<Vec<SourceInputFile>> {
        let mut files = Vec::with_capacity(entries.len());
        for entry in entries {
            writeln!(input, "{}", entry.object_id).context("cannot request Git blob")?;
            input.flush().context("cannot flush Git blob request")?;
            let mut header = String::new();
            if output
                .read_line(&mut header)
                .context("cannot read Git blob header")?
                == 0
            {
                bail!("Git object reader ended before returning every blob");
            }
            let fields = header.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 || fields[0] != entry.object_id || fields[1] != "blob" {
                bail!("Git object reader returned a mismatched blob header");
            }
            let size = fields[2]
                .parse::<u64>()
                .context("Git object reader returned an invalid blob size")?;
            if size != entry.size || size > MAX_SOURCE_FILE_BYTES {
                bail!(
                    "Git blob size disagrees with the committed tree at {}",
                    entry.path
                );
            }
            let size = usize::try_from(size).context("Git blob is too large for this platform")?;
            let mut bytes = vec![0u8; size];
            output
                .read_exact(&mut bytes)
                .with_context(|| format!("cannot read Git blob at {}", entry.path))?;
            let mut terminator = [0u8; 1];
            output
                .read_exact(&mut terminator)
                .context("Git blob response is missing its terminator")?;
            if terminator != *b"\n" {
                bail!("Git blob response has a noncanonical terminator");
            }
            if git_blob_object_id(object_format, &bytes)? != entry.object_id {
                bail!("Git blob hash verification failed at {}", entry.path);
            }
            files.push(SourceInputFile {
                path: entry.path.clone(),
                mode: entry.mode,
                bytes,
            });
        }
        Ok(files)
    })();
    drop(input);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().context("cannot wait for Git object reader")?;
    if !status.success() && result.is_ok() {
        bail!("Git object reader failed");
    }
    result
}

fn git_blob_object_id(object_format: &str, bytes: &[u8]) -> Result<String> {
    let header = format!("blob {}\0", bytes.len());
    match object_format {
        "sha1" => {
            let mut digest = Sha1::new();
            digest.update(header.as_bytes());
            digest.update(bytes);
            Ok(hex::encode(digest.finalize()))
        }
        "sha256" => {
            let mut digest = Sha256::new();
            digest.update(header.as_bytes());
            digest.update(bytes);
            Ok(hex::encode(digest.finalize()))
        }
        _ => bail!("unsupported Git object format"),
    }
}

fn validate_exact_git_oid(value: &str, expected_length: usize, label: &str) -> Result<()> {
    if value.len() != expected_length
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a full lowercase Git object id");
    }
    Ok(())
}

fn git_text(git_repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = git_output(git_repository, arguments)?;
    let value = String::from_utf8(output).context("Git output is not UTF-8")?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("Git returned a noncanonical single-line value");
    }
    Ok(value.to_string())
}

fn git_output(git_repository: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = git_process(git_repository)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .context("cannot run Git")?;
    if !output.status.success() {
        bail!("Git command failed while reading committed source objects");
    }
    Ok(output.stdout)
}

fn git_process(git_repository: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("git");
    command
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(git_repository)
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_CONFIG")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_NAMESPACE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_REPLACE_REF_BASE")
        .env_remove("GIT_WORK_TREE")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C");
    command
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
        &package.value.candidate_ecosystem_cid,
        &package.value.owner_idena_address,
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
    write_attestation_artifacts(
        CliAttestationKind::Build,
        output_dir,
        &package,
        fields,
        &package.value.candidate_ecosystem_cid,
        &package.value.builder_identity,
    )
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
        &package.value.candidate_ecosystem_cid,
        &package.value.operator_identity,
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
        &package.value.candidate_ecosystem_cid,
        &package.value.auditor_identity,
    )
}

fn migration_rehearsal_attestation_command(
    input: &Path,
    derive_rehearsal_digest: bool,
    output_dir: &Path,
) -> Result<()> {
    let mut payload: MigrationRehearsalAttestationV1 =
        read_json_file(input, "migration rehearsal attestation")?;
    if derive_rehearsal_digest {
        payload.rehearsal_digest = migration_rehearsal_digest(&payload)?;
    }
    let package = package_migration_rehearsal_attestation(payload)?;
    let fields = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        package.root_cid,
        package.value.candidate_ecosystem_cid,
        package.value.scope_evidence_cid,
        package.value.rehearsal_digest,
        package.value.runtime_family,
        package.value.architecture,
        package.value.operator_identity,
        package.value.tests_passed,
    );
    write_attestation_artifacts(
        CliAttestationKind::MigrationRehearsal,
        output_dir,
        &package,
        fields,
        &package.value.candidate_ecosystem_cid,
        &package.value.operator_identity,
    )
}

fn attestation_authenticate_command(
    kind: CliAttestationKind,
    car: &Path,
    signature_file: &Path,
    output_dir: &Path,
) -> Result<()> {
    let bytes = read_regular_file(car, "attestation CAR")?;
    let (request, authentication_intent) = attestation_authentication_context(kind, &bytes)?;
    let bytes = read_regular_file(signature_file, "Idena signature")?;
    let signature = String::from_utf8(bytes)
        .context("Idena signature file is not UTF-8")?
        .trim()
        .to_string();
    let authentication = signature_attestation_authentication(&request, signature)?;
    verify_attestation_authentication(&request, &authentication_intent, &authentication)?;
    let output = secure_output_directory(output_dir)?;
    write_new(
        &output.join(format!("{}.authentication.json", kind.filename())),
        &deterministic_json(&authentication)?,
    )?;
    print_json(&authentication)
}

fn deployment_readiness_verify_command(input_path: &Path, output_dir: Option<&Path>) -> Result<()> {
    const MAX_EVIDENCE_CAR_BYTES: usize = 16 * 1024 * 1024;
    let input: DeploymentReadinessInputV1 =
        read_json_file(input_path, "deployment readiness input")?;
    if input.schema_version != 1 {
        bail!("deployment readiness schemaVersion must be 1");
    }
    if input.source_commit_receipts.len() > 64
        || input.build_attestations.len() > 256
        || input.data_availability_attestations.len() > 256
        || input.external_audit_attestations.len() > 64
        || input.migration_rehearsal_attestations.len() > 64
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
    let source_commit_receipts = input
        .source_commit_receipts
        .iter()
        .map(|evidence| {
            let bytes = read_regular_file(&resolve(&evidence.car), "source commit receipt CAR")?;
            let package = verify_source_commit_receipt_car(&bytes)?;
            Ok(AddressedSourceCommitReceiptV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let builds = input
        .build_attestations
        .iter()
        .map(|evidence| {
            let bytes = read_regular_file(&resolve(&evidence.car), "build attestation CAR")?;
            let package = verify_build_attestation_car(&bytes)?;
            let authentication = read_json_file(
                &resolve(&evidence.authentication),
                "build attestation authentication",
            )?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
                authentication: Some(authentication),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let availability = input
        .data_availability_attestations
        .iter()
        .map(|evidence| {
            let bytes = read_regular_file(&resolve(&evidence.car), "availability attestation CAR")?;
            let package = verify_data_availability_attestation_car(&bytes)?;
            let authentication = read_json_file(
                &resolve(&evidence.authentication),
                "availability attestation authentication",
            )?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
                authentication: Some(authentication),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let audits = input
        .external_audit_attestations
        .iter()
        .map(|evidence| {
            let bytes =
                read_regular_file(&resolve(&evidence.car), "external audit attestation CAR")?;
            let package = verify_external_audit_attestation_car(&bytes)?;
            let authentication = read_json_file(
                &resolve(&evidence.authentication),
                "external audit attestation authentication",
            )?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
                authentication: Some(authentication),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let migration_rehearsals = input
        .migration_rehearsal_attestations
        .iter()
        .map(|evidence| {
            let bytes = read_regular_file(
                &resolve(&evidence.car),
                "migration rehearsal attestation CAR",
            )?;
            let package = verify_migration_rehearsal_attestation_car(&bytes)?;
            let authentication = read_json_file(
                &resolve(&evidence.authentication),
                "migration rehearsal attestation authentication",
            )?;
            Ok(AddressedAttestationV1 {
                cid: package.root_cid.to_string(),
                value: package.value,
                authentication: Some(authentication),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let evidence = DeploymentReadinessEvidenceV1 {
        schema_version: 1,
        scope_evidence_cid: scope.root_cid.to_string(),
        scope: scope.value,
        source_commit_receipts,
        build_attestations: builds,
        data_availability_attestations: availability,
        external_audit_attestations: audits,
        migration_rehearsal_attestations: migration_rehearsals,
        required_availability_through_block: input.required_availability_through_block,
    };
    let evidence_package = package_deployment_readiness_evidence(evidence)?;
    if evidence_package.car_bytes.len() > MAX_EVIDENCE_CAR_BYTES {
        bail!("deployment readiness evidence CAR exceeds 16 MiB");
    }
    let report = evaluate_deployment_readiness_evidence(&evidence_package.value)?;
    print_json(&report)?;
    if !report.ready {
        bail!(
            "deployment readiness gate failed: {}",
            report.failure_codes.join(", ")
        );
    }
    if let Some(output_dir) = output_dir {
        let package = package_dag_cbor(report.clone())?;
        let view = DeploymentReadinessReportView {
            schema_version: 1,
            report_cid: package.root_cid.to_string(),
            report_sha256: package.root_sha256.clone(),
            car_sha256: sha256_hex(&package.car_bytes),
            report: &package.value,
        };
        let output = secure_output_directory(output_dir)?;
        write_new(
            &output.join("deployment-readiness-report.car"),
            &package.car_bytes,
        )?;
        write_new(
            &output.join("deployment-readiness-evidence.car"),
            &evidence_package.car_bytes,
        )?;
        write_new(
            &output.join("deployment-readiness-report.json"),
            &deterministic_json(&view)?,
        )?;
        write_new(
            &output.join("deployment-readiness-report.cid"),
            format!("{}\n", view.report_cid).as_bytes(),
        )?;
        write_new(
            &output.join("deployment-readiness-report.car.sha256"),
            format!("{}  deployment-readiness-report.car\n", view.car_sha256).as_bytes(),
        )?;
        write_new(
            &output.join("deployment-readiness-evidence.cid"),
            format!("{}\n", evidence_package.root_cid).as_bytes(),
        )?;
        write_new(
            &output.join("deployment-readiness-evidence.car.sha256"),
            format!(
                "{}  deployment-readiness-evidence.car\n",
                sha256_hex(&evidence_package.car_bytes)
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

fn deployment_readiness_evidence_verify_command(car: &Path) -> Result<()> {
    const MAX_EVIDENCE_CAR_BYTES: usize = 16 * 1024 * 1024;
    let bytes = read_regular_file(car, "deployment readiness evidence CAR")?;
    if bytes.len() > MAX_EVIDENCE_CAR_BYTES {
        bail!("deployment readiness evidence CAR exceeds 16 MiB");
    }
    let evidence = verify_deployment_readiness_evidence_car(&bytes)?;
    let report = evaluate_deployment_readiness_evidence(&evidence.value)?;
    if !report.ready {
        bail!(
            "deployment readiness gate failed: {}",
            report.failure_codes.join(", ")
        );
    }
    let report_package = package_dag_cbor(report)?;
    print_json(&DeploymentReadinessEvidenceVerificationView {
        schema_version: 1,
        evidence_bundle_cid: evidence.root_cid.to_string(),
        report_cid: report_package.root_cid.to_string(),
        report_sha256: report_package.root_sha256,
        report: report_package.value,
    })
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

fn attestation_verify_command(
    kind: CliAttestationKind,
    car: &Path,
    authentication_path: Option<&Path>,
) -> Result<()> {
    let bytes = read_regular_file(car, "attestation CAR")?;
    let authenticated_identity = if let Some(path) = authentication_path {
        let authentication: AttestationAuthenticationV1 =
            read_json_file(path, "attestation authentication")?;
        let (request, authentication_intent) = attestation_authentication_context(kind, &bytes)?;
        verify_attestation_authentication(&request, &authentication_intent, &authentication)?;
        Some(request.identity)
    } else {
        None
    };
    let authentication_verified = authenticated_identity.is_some();
    match kind {
        CliAttestationKind::AgentReview => {
            let package = verify_agent_review_attestation_car(&bytes)?;
            print_json(&AttestationVerificationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                content_verified: true,
                authentication_verified,
                authenticated_identity,
                payload: package.value,
            })
        }
        CliAttestationKind::Build => {
            let package = verify_build_attestation_car(&bytes)?;
            print_json(&AttestationVerificationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                content_verified: true,
                authentication_verified,
                authenticated_identity,
                payload: package.value,
            })
        }
        CliAttestationKind::DataAvailability => {
            let package = verify_data_availability_attestation_car(&bytes)?;
            print_json(&AttestationVerificationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                content_verified: true,
                authentication_verified,
                authenticated_identity,
                payload: package.value,
            })
        }
        CliAttestationKind::ExternalAudit => {
            let package = verify_external_audit_attestation_car(&bytes)?;
            print_json(&AttestationVerificationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                content_verified: true,
                authentication_verified,
                authenticated_identity,
                payload: package.value,
            })
        }
        CliAttestationKind::MigrationRehearsal => {
            let package = verify_migration_rehearsal_attestation_car(&bytes)?;
            print_json(&AttestationVerificationView {
                schema_version: 1,
                attestation_kind: kind.domain(),
                attestation_cid: package.root_cid.to_string(),
                attestation_sha256: package.root_sha256,
                car_sha256: sha256_hex(&bytes),
                content_verified: true,
                authentication_verified,
                authenticated_identity,
                payload: package.value,
            })
        }
    }
}

fn attestation_authentication_context(
    kind: CliAttestationKind,
    bytes: &[u8],
) -> Result<(AttestationAuthenticationRequestV1, String)> {
    let context = match kind {
        CliAttestationKind::AgentReview => {
            let package = verify_agent_review_attestation_car(bytes)?;
            let request = attestation_authentication_request(
                kind.domain(),
                &package.root_cid.to_string(),
                &package.root_sha256,
                &package.value.candidate_ecosystem_cid,
                &package.value.owner_idena_address,
            )?;
            (request, package.value.authentication)
        }
        CliAttestationKind::Build => {
            let package = verify_build_attestation_car(bytes)?;
            let request = attestation_authentication_request(
                kind.domain(),
                &package.root_cid.to_string(),
                &package.root_sha256,
                &package.value.candidate_ecosystem_cid,
                &package.value.builder_identity,
            )?;
            (request, package.value.authentication)
        }
        CliAttestationKind::DataAvailability => {
            let package = verify_data_availability_attestation_car(bytes)?;
            let request = attestation_authentication_request(
                kind.domain(),
                &package.root_cid.to_string(),
                &package.root_sha256,
                &package.value.candidate_ecosystem_cid,
                &package.value.operator_identity,
            )?;
            (request, package.value.authentication)
        }
        CliAttestationKind::ExternalAudit => {
            let package = verify_external_audit_attestation_car(bytes)?;
            let request = attestation_authentication_request(
                kind.domain(),
                &package.root_cid.to_string(),
                &package.root_sha256,
                &package.value.candidate_ecosystem_cid,
                &package.value.auditor_identity,
            )?;
            (request, package.value.authentication)
        }
        CliAttestationKind::MigrationRehearsal => {
            let package = verify_migration_rehearsal_attestation_car(bytes)?;
            let request = attestation_authentication_request(
                kind.domain(),
                &package.root_cid.to_string(),
                &package.root_sha256,
                &package.value.candidate_ecosystem_cid,
                &package.value.operator_identity,
            )?;
            (request, package.value.authentication)
        }
    };
    Ok(context)
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
    candidate_ecosystem_cid: &str,
    identity: &str,
) -> Result<()> {
    let cid = package.root_cid.to_string();
    let authentication_request = attestation_authentication_request(
        kind.domain(),
        &cid,
        &package.root_sha256,
        candidate_ecosystem_cid,
        identity,
    )?;
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
    write_new(
        &output.join(format!("{prefix}.authentication-request.json")),
        &deterministic_json(&authentication_request)?,
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
        distinct_agent_runtime_groups: 2,
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
    fn deployment_readiness_accepts_a_canonical_report_output_directory() {
        let cli = Cli::try_parse_from([
            "pohw-governance",
            "deployment-readiness-verify",
            "--input",
            "/tmp/readiness.json",
            "--output-dir",
            "/tmp/readiness-report",
        ])
        .unwrap();
        match cli.command {
            Command::DeploymentReadinessVerify { input, output_dir } => {
                assert_eq!(input, PathBuf::from("/tmp/readiness.json"));
                assert_eq!(output_dir, Some(PathBuf::from("/tmp/readiness-report")));
            }
            _ => panic!("deployment-readiness-verify parsed as the wrong command"),
        }
    }

    #[test]
    fn deployment_readiness_evidence_verify_accepts_a_canonical_car() {
        let cli = Cli::try_parse_from([
            "pohw-governance",
            "deployment-readiness-evidence-verify",
            "--car",
            "/tmp/readiness-evidence.car",
        ])
        .unwrap();
        match cli.command {
            Command::DeploymentReadinessEvidenceVerify { car } => {
                assert_eq!(car, PathBuf::from("/tmp/readiness-evidence.car"));
            }
            _ => panic!("deployment-readiness-evidence-verify parsed as the wrong command"),
        }
    }

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
    fn exact_commit_packaging_ignores_dirty_state_and_rejects_moving_refs() {
        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "Governance Test"],
            vec!["config", "user.email", "governance-test@example.invalid"],
        ] {
            assert!(ProcessCommand::new("git")
                .arg("-C")
                .arg(&repository)
                .args(arguments)
                .status()
                .unwrap()
                .success());
        }
        fs::write(repository.join("README.md"), "committed source\n").unwrap();
        assert!(ProcessCommand::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["add", "README.md"])
            .status()
            .unwrap()
            .success());
        assert!(ProcessCommand::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["commit", "--quiet", "-m", "fixture"])
            .status()
            .unwrap()
            .success());
        let commit = git_text(&repository, &["rev-parse", "HEAD"]).unwrap();
        fs::write(repository.join("README.md"), "dirty source\n").unwrap();
        fs::write(repository.join(".env"), "TOKEN=never-package\n").unwrap();

        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        package_commit_command(&repository, &commit, "fixture", &first, None).unwrap();
        package_commit_command(&repository, &commit, "fixture", &second, None).unwrap();
        let first_car = fs::read(first.join("fixture.source.car")).unwrap();
        let second_car = fs::read(second.join("fixture.source.car")).unwrap();
        assert_eq!(first_car, second_car);
        let source = verify_source_car(&first_car).unwrap();
        assert_eq!(source.manifest.files.len(), 1);
        assert_eq!(source.manifest.files[0].path, "README.md");
        let receipt = verify_source_commit_receipt_car(
            &fs::read(first.join("fixture.source-commit-receipt.car")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.value.git_commit, commit);
        assert_eq!(receipt.value.source_tree_cid, source.root_cid.to_string());

        let moving_ref = temporary.path().join("moving-ref");
        assert!(
            package_commit_command(&repository, "HEAD", "fixture", &moving_ref, None)
                .unwrap_err()
                .to_string()
                .contains("full lowercase Git object id")
        );
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

    #[test]
    fn attestation_authentication_commands_take_detached_proof_files() {
        let authenticate = Cli::try_parse_from([
            "pohw-governance",
            "attestation-authenticate",
            "--kind",
            "build",
            "--car",
            "/tmp/build.car",
            "--signature-file",
            "/tmp/build.signature",
            "--output-dir",
            "/tmp/build-auth",
        ])
        .unwrap();
        assert!(matches!(
            authenticate.command,
            Command::AttestationAuthenticate {
                kind: CliAttestationKind::Build,
                ..
            }
        ));

        let verify = Cli::try_parse_from([
            "pohw-governance",
            "attestation-verify",
            "--kind",
            "external-audit",
            "--car",
            "/tmp/audit.car",
            "--authentication",
            "/tmp/audit.authentication.json",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Command::AttestationVerify {
                kind: CliAttestationKind::ExternalAudit,
                authentication: Some(_),
                ..
            }
        ));

        let rehearsal = Cli::try_parse_from([
            "pohw-governance",
            "attestation-authenticate",
            "--kind",
            "migration-rehearsal",
            "--car",
            "/tmp/rehearsal.car",
            "--signature-file",
            "/tmp/rehearsal.signature",
            "--output-dir",
            "/tmp/rehearsal-auth",
        ])
        .unwrap();
        assert!(matches!(
            rehearsal.command,
            Command::AttestationAuthenticate {
                kind: CliAttestationKind::MigrationRehearsal,
                ..
            }
        ));

        assert!(Cli::try_parse_from([
            "pohw-governance",
            "attestation-authenticate",
            "--kind",
            "build",
            "--car",
            "/tmp/build.car",
            "--receipt",
            "/tmp/build.receipt.json",
            "--output-dir",
            "/tmp/build-auth",
        ])
        .is_err());
    }
}
