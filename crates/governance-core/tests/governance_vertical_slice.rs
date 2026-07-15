use governance_core::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const ONE_IDNA: u128 = 1_000_000_000_000_000_000;

struct LocalVerifiedContentStore {
    root: PathBuf,
}

impl LocalVerifiedContentStore {
    fn new(root: PathBuf) -> Self {
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn put(&self, expected_cid: &str, car: &[u8]) {
        assert_eq!(verify_car_integrity(car).unwrap().to_string(), expected_cid);
        let path = self.root.join(format!("{expected_cid}.car"));
        if path.exists() {
            assert_eq!(fs::read(path).unwrap(), car);
        } else {
            fs::write(path, car).unwrap();
        }
    }

    fn get(&self, cid: &str) -> Vec<u8> {
        let bytes = fs::read(self.root.join(format!("{cid}.car"))).unwrap();
        assert_eq!(verify_car_integrity(&bytes).unwrap().to_string(), cid);
        bytes
    }
}

fn address(index: u8) -> String {
    format!("0x{index:040x}")
}

fn object_cid(label: &str) -> String {
    cid_for(0x71, label.as_bytes()).to_string()
}

fn raw_object_cid(label: &str) -> String {
    cid_for(0x55, label.as_bytes()).to_string()
}

fn command(command: &str) -> CommandExecutionV1 {
    CommandExecutionV1 {
        command: command.to_string(),
        exit_code: 0,
        stdout_sha256: "11".repeat(32),
        stderr_sha256: "22".repeat(32),
    }
}

fn repository_manifest(name: &str, source: &SourcePackage) -> RepositoryManifestV1 {
    RepositoryManifestV1 {
        schema_version: 1,
        name: name.to_string(),
        source_tree_cid: source.root_cid.to_string(),
        source_tree_sha256: source.source_tree_sha256.clone(),
        git_bundle_cid: None,
        git_commit_metadata: None,
        dependency_locks: vec![],
        toolchain_locks: BTreeMap::from([("test-runtime".to_string(), "1.0.0".to_string())]),
        build_instructions: vec!["sh verify-fixture.sh".to_string()],
        artifacts: vec![],
    }
}

fn metrics_leaf(index: u8) -> GovernanceIdentityMetricsLeafV1 {
    let state = if index <= 5 {
        IdentityState::Human
    } else {
        IdentityState::Newbie
    };
    GovernanceIdentityMetricsLeafV1 {
        address: address(index),
        identity_state: state,
        total_finalized_authored_flips: 20,
        total_consensus_reported_authored_flips: 1,
        flip_trust_bps: flip_trust_bps(20, 1).unwrap(),
        source_epoch: 2,
        source_block_height: 1_000,
        source_block_hash: "33".repeat(32),
    }
}

#[test]
fn executes_two_repository_candidate_and_retrieves_both_generations() {
    let temp = tempfile::tempdir().unwrap();
    let roots = temp.path().join("roots");
    let base_a = roots.join("base-a");
    let base_b = roots.join("base-b");
    let candidate_a = roots.join("candidate-a");
    let candidate_b = roots.join("candidate-b");
    for root in [&base_a, &base_b, &candidate_a, &candidate_b] {
        fs::create_dir_all(root).unwrap();
    }
    fs::write(base_a.join("fixture.txt"), b"p2pool base\n").unwrap();
    fs::write(base_b.join("fixture.txt"), b"idena base\n").unwrap();
    fs::write(candidate_a.join("fixture.txt"), b"p2pool candidate\n").unwrap();
    fs::write(candidate_b.join("fixture.txt"), b"idena candidate\n").unwrap();
    fs::write(candidate_b.join("added.txt"), b"atomic second repository\n").unwrap();

    let base_sources = [
        package_source_tree(&base_a, "P2poolBTC").unwrap(),
        package_source_tree(&base_b, "idena-go").unwrap(),
    ];
    let candidate_sources = [
        package_source_tree(&candidate_a, "P2poolBTC").unwrap(),
        package_source_tree(&candidate_b, "idena-go").unwrap(),
    ];
    let repository_patches = [
        create_source_patch(&base_sources[0].car_bytes, &candidate_sources[0].car_bytes).unwrap(),
        create_source_patch(&base_sources[1].car_bytes, &candidate_sources[1].car_bytes).unwrap(),
    ];
    for index in 0..2 {
        verify_source_patch(
            &base_sources[index].car_bytes,
            &candidate_sources[index].car_bytes,
            &repository_patches[index].car_bytes,
        )
        .unwrap();
    }

    let parameters = GovernanceParameterSetV1::experimental_defaults();
    let parameter_package = package_dag_cbor(parameters.clone()).unwrap();
    let artifact_bytes = b"deterministic-core-artifact";
    let artifact_digest = sha256_hex(artifact_bytes);
    let parent = package_ecosystem_manifest(EcosystemManifestV1 {
        schema_version: 1,
        ecosystem_id: "ubiubi18.vertical-slice".to_string(),
        parent_ecosystem_cid: None,
        repositories: vec![
            repository_manifest("P2poolBTC", &base_sources[0]),
            repository_manifest("idena-go", &base_sources[1]),
        ],
        compatibility_pins: BTreeMap::new(),
        toolchain_locks: BTreeMap::from([("rust".to_string(), "1.96.1".to_string())]),
        governance_contract_version: "0.1.0".to_string(),
        governance_parameter_set_cid: parameter_package.root_cid.to_string(),
    })
    .unwrap();
    let mut candidate_p2pool = repository_manifest("P2poolBTC", &candidate_sources[0]);
    candidate_p2pool.artifacts = vec![ArtifactManifestV1 {
        name: "governance-core".to_string(),
        cid: cid_for(0x55, artifact_bytes).to_string(),
        sha256: artifact_digest.clone(),
        size: artifact_bytes.len() as u64,
    }];
    let candidate = package_ecosystem_manifest(EcosystemManifestV1 {
        schema_version: 1,
        ecosystem_id: "ubiubi18.vertical-slice".to_string(),
        parent_ecosystem_cid: Some(parent.root_cid.to_string()),
        repositories: vec![
            candidate_p2pool,
            repository_manifest("idena-go", &candidate_sources[1]),
        ],
        compatibility_pins: BTreeMap::new(),
        toolchain_locks: BTreeMap::from([("rust".to_string(), "1.96.1".to_string())]),
        governance_contract_version: "0.1.0".to_string(),
        governance_parameter_set_cid: parameter_package.root_cid.to_string(),
    })
    .unwrap();
    let aggregate_patch = package_ecosystem_patch_manifest(EcosystemPatchManifestV1 {
        schema_version: 1,
        kind: "pohw-ecosystem-patch-v1".to_string(),
        parent_ecosystem_cid: parent.root_cid.to_string(),
        candidate_ecosystem_cid: candidate.root_cid.to_string(),
        repository_patches: repository_patches
            .iter()
            .map(|patch| RepositoryPatchManifestV1 {
                repository: patch.patch.repository.clone(),
                base_source_cid: patch.patch.base_source_cid.clone(),
                candidate_source_cid: patch.patch.candidate_source_cid.clone(),
                patch_cid: patch.patch_cid.to_string(),
                patch_sha256: patch.patch_sha256.clone(),
            })
            .collect(),
    })
    .unwrap();
    assert_eq!(
        verify_ecosystem_transition(&parent, &candidate, &aggregate_patch).unwrap(),
        vec!["P2poolBTC".to_string(), "idena-go".to_string()],
    );
    let rationale = package_dag_cbor("harmless two-repository fixture".to_string()).unwrap();
    let migration = package_dag_cbor("no migration".to_string()).unwrap();
    let test_plan = package_dag_cbor("rebuild both fixture repositories".to_string()).unwrap();
    let toolchain = package_toolchain_manifest_for_ecosystem(&candidate.manifest).unwrap();
    let pinset = package_pinset_manifest_for_transition_with_additional(
        &candidate,
        &aggregate_patch,
        &[
            rationale.root_cid.to_string(),
            migration.root_cid.to_string(),
            test_plan.root_cid.to_string(),
        ],
    )
    .unwrap();

    let store = LocalVerifiedContentStore::new(temp.path().join("public-ipfs-store"));
    store.put(
        &parameter_package.root_cid.to_string(),
        &parameter_package.car_bytes,
    );
    store.put(&parent.root_cid.to_string(), &parent.car_bytes);
    store.put(&candidate.root_cid.to_string(), &candidate.car_bytes);
    store.put(
        &aggregate_patch.root_cid.to_string(),
        &aggregate_patch.car_bytes,
    );
    store.put(&toolchain.root_cid.to_string(), &toolchain.car_bytes);
    store.put(&pinset.root_cid.to_string(), &pinset.car_bytes);
    for source in base_sources.iter().chain(candidate_sources.iter()) {
        store.put(&source.root_cid.to_string(), &source.car_bytes);
    }
    for patch in &repository_patches {
        store.put(&patch.patch_cid.to_string(), &patch.car_bytes);
    }

    for object in [&rationale, &migration, &test_plan] {
        store.put(&object.root_cid.to_string(), &object.car_bytes);
    }

    let affected = vec![
        RepositoryCidV1 {
            repository: "P2poolBTC".to_string(),
            cid: candidate_sources[0].root_cid.to_string(),
        },
        RepositoryCidV1 {
            repository: "idena-go".to_string(),
            cid: candidate_sources[1].root_cid.to_string(),
        },
    ];
    let mut agent_packages = Vec::new();
    for index in 0..5usize {
        let owner = address((index % 3 + 1) as u8);
        let family = format!("family-{index}");
        let payload = AgentReviewAttestationV1 {
            schema_version: 1,
            parent_ecosystem_cid: parent.root_cid.to_string(),
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            patch_cid: aggregate_patch.root_cid.to_string(),
            affected_repositories: affected.clone(),
            model_identifier: format!("review-model-{index}"),
            model_revision: None,
            provider_or_runtime_identifier: format!("isolated-runtime-{index}"),
            model_family: family,
            agent_policy_cid: object_cid("agent-policy"),
            system_prompt_policy_cid: object_cid("prompt-policy"),
            tool_versions: BTreeMap::from([("cargo".to_string(), "1.96.1".to_string())]),
            commands_executed: vec![command("cargo test --workspace")],
            test_results_cid: raw_object_cid(&format!("agent-tests-{index}")),
            tests_passed: true,
            static_analysis_results_cid: object_cid(&format!("static-{index}")),
            dependency_findings_cid: object_cid(&format!("dependencies-{index}")),
            security_findings: vec![],
            unresolved_critical_findings: 0,
            verdict: ReviewVerdictV1::Approve,
            owner_idena_address: owner,
            reviewer_bond_atoms: ONE_IDNA.to_string(),
            creation_block_or_timestamp: 20,
            authentication: "on-chain-submitter".to_string(),
        };
        let package = package_agent_review_attestation(payload).unwrap();
        store.put(&package.root_cid.to_string(), &package.car_bytes);
        agent_packages.push(package);
    }
    let mut build_packages = Vec::new();
    for index in 0..3usize {
        let artifacts = vec![BuildArtifactV1 {
            name: "governance-core".to_string(),
            cid: cid_for(0x55, artifact_bytes).to_string(),
            sha256: artifact_digest.clone(),
            size: artifact_bytes.len() as u64,
            core: true,
        }];
        let payload = BuildAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            source_cids: affected.clone(),
            toolchain_cid: toolchain.root_cid.to_string(),
            builder_identity: address((index + 1) as u8),
            runtime_family: if index == 1 { "macos" } else { "linux" }.to_string(),
            architecture: if index == 1 { "arm64" } else { "x86_64" }.to_string(),
            commands: vec![command("cargo build --workspace --locked")],
            test_results_cid: raw_object_cid(&format!("build-tests-{index}")),
            tests_passed: true,
            sbom_cid: raw_object_cid(&format!("sbom-{index}")),
            core_artifact_digest: core_artifact_set_digest(&artifacts).unwrap(),
            artifacts,
            builder_bond_atoms: ONE_IDNA.to_string(),
            creation_block_or_timestamp: 20,
            authentication: "on-chain-submitter".to_string(),
        };
        let package = package_build_attestation(payload).unwrap();
        store.put(&package.root_cid.to_string(), &package.car_bytes);
        build_packages.push(package);
    }
    let mut required_availability_cids = pinset
        .manifest
        .cids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for package in &agent_packages {
        required_availability_cids.extend([
            package.root_cid.to_string(),
            package.value.agent_policy_cid.clone(),
            package.value.system_prompt_policy_cid.clone(),
            package.value.test_results_cid.clone(),
            package.value.static_analysis_results_cid.clone(),
            package.value.dependency_findings_cid.clone(),
        ]);
    }
    for package in &build_packages {
        required_availability_cids.extend([
            package.root_cid.to_string(),
            package.value.toolchain_cid.clone(),
            package.value.test_results_cid.clone(),
            package.value.sbom_cid.clone(),
        ]);
        required_availability_cids.extend(
            package
                .value
                .artifacts
                .iter()
                .map(|artifact| artifact.cid.clone()),
        );
    }
    let mut availability_packages = Vec::new();
    for index in 0..3usize {
        let probe_result_cid = raw_object_cid(&format!("probe-{index}"));
        let mut verified_cids = required_availability_cids.clone();
        verified_cids.insert(probe_result_cid.clone());
        let payload = DataAvailabilityAttestationV1 {
            schema_version: 1,
            candidate_ecosystem_cid: candidate.root_cid.to_string(),
            pinset_cid: pinset.root_cid.to_string(),
            provider_id: format!("provider-{index}"),
            operator_identity: address((index + 1) as u8),
            verified_cids: verified_cids.into_iter().collect(),
            probe_result_cid,
            available: true,
            observed_at_block_or_timestamp: 20,
            expires_at_block: 400,
            bond_atoms: ONE_IDNA.to_string(),
            authentication: "on-chain-submitter".to_string(),
        };
        let package = package_data_availability_attestation(payload).unwrap();
        store.put(&package.root_cid.to_string(), &package.car_bytes);
        availability_packages.push(package);
    }

    let agent_entries = agent_packages
        .iter()
        .map(|package| AttestationCommitmentEntryV1 {
            attestation_cid: package.root_cid.to_string(),
            canonical_fields: agent_attestation_commitment_fields(
                &package.root_cid.to_string(),
                &package.value.model_family,
                &package.value.owner_idena_address,
                0,
            )
            .unwrap(),
        })
        .collect::<Vec<_>>();
    let build_entries = build_packages
        .iter()
        .map(|package| AttestationCommitmentEntryV1 {
            attestation_cid: package.root_cid.to_string(),
            canonical_fields: build_attestation_commitment_fields(
                &package.root_cid.to_string(),
                &package.value.core_artifact_digest,
                &package.value.runtime_family,
                &package.value.architecture,
                &package.value.builder_identity,
            )
            .unwrap(),
        })
        .collect::<Vec<_>>();
    let availability_entries = availability_packages
        .iter()
        .map(|package| AttestationCommitmentEntryV1 {
            attestation_cid: package.root_cid.to_string(),
            canonical_fields: data_availability_commitment_fields(
                &package.root_cid.to_string(),
                &package.value.candidate_ecosystem_cid,
                &package.value.pinset_cid,
                &package.value.provider_id,
                &package.value.operator_identity,
            )
            .unwrap(),
        })
        .collect::<Vec<_>>();
    let agent_commitment =
        build_attestation_commitment(AGENT_REVIEW_COMMITMENT_DOMAIN, &agent_entries).unwrap();
    let build_commitment =
        build_attestation_commitment(BUILD_ATTESTATION_COMMITMENT_DOMAIN, &build_entries).unwrap();
    let availability_commitment =
        build_attestation_commitment(DATA_AVAILABILITY_COMMITMENT_DOMAIN, &availability_entries)
            .unwrap();

    let snapshot = build_identity_metrics_snapshot((1..=12).map(metrics_leaf).collect()).unwrap();
    let mut engine = GovernanceEngine::initialize(
        &parent.root_cid.to_string(),
        &parameter_package.root_cid.to_string(),
        parameters.clone(),
        &snapshot.root,
        2,
    )
    .unwrap();
    for index in 1..=12u8 {
        engine
            .register_identity_metrics(&address(index), snapshot.proofs[&address(index)].clone())
            .unwrap();
        engine
            .register_stake(
                &address(index),
                ONE_IDNA,
                GovernanceClock { block: 1, epoch: 1 },
            )
            .unwrap();
    }
    let metrics_snapshot_cid = cid_for(0x71, b"identity-metrics-snapshot");
    let metrics_snapshot_sha256 = hex::encode(metrics_snapshot_cid.hash().digest());
    for index in 1..=3u8 {
        let package = package_identity_metrics_attestation(IdentityMetricsAttestationV1 {
            schema_version: 1,
            metrics_root: snapshot.root.clone(),
            snapshot_cid: metrics_snapshot_cid.to_string(),
            snapshot_sha256: metrics_snapshot_sha256.clone(),
            source_epoch: 2,
            source_block_height: 1_000,
            source_block_hash: "33".repeat(32),
            replay_start_height: 1,
            replay_commitment: "44".repeat(32),
            indexer_implementation_cid: object_cid("metrics-indexer-implementation"),
            operator_idena_address: address(index),
            observed_at_block_or_timestamp: 9,
            authentication: "on-chain-submitter".to_string(),
        })
        .unwrap();
        store.put(&package.root_cid.to_string(), &package.car_bytes);
        engine
            .submit_identity_metrics_attestation(
                &address(index),
                &package.root_cid.to_string(),
                &package.car_bytes,
                GovernanceClock { block: 9, epoch: 2 },
            )
            .unwrap();
    }
    assert!(
        engine
            .identity_metrics_certification(&snapshot.root, 2)
            .unwrap()
            .certified
    );
    let review_round_id = engine
        .open_review_round(
            OpenReviewRoundInputV1 {
                parent_car: &parent.car_bytes,
                candidate_car: &candidate.car_bytes,
                patch_car: &aggregate_patch.car_bytes,
                pinset_car: &pinset.car_bytes,
                opener_address: &address(1),
                attached_bond_atoms: 10 * ONE_IDNA,
            },
            GovernanceClock {
                block: 10,
                epoch: 2,
            },
        )
        .unwrap();
    for package in &agent_packages {
        engine
            .submit_agent_attestation(
                &review_round_id,
                AgentAttestationInputV1 {
                    attestation_cid: package.root_cid.to_string(),
                    attestation_car: package.car_bytes.clone(),
                    parent_ecosystem_cid: package.value.parent_ecosystem_cid.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    patch_cid: package.value.patch_cid.clone(),
                    owner_address: package.value.owner_idena_address.clone(),
                    model_identifier: package.value.model_identifier.clone(),
                    model_revision: package.value.model_revision.clone(),
                    runtime_identifier: package.value.provider_or_runtime_identifier.clone(),
                    independence_group: package.value.model_family.clone(),
                    verdict: AttestationVerdict::Approve,
                    unresolved_critical_findings: 0,
                    test_result_cid: package.value.test_results_cid.clone(),
                    tests_passed_claim: true,
                    bond_atoms: ONE_IDNA,
                    commitment_proof: agent_commitment.proofs[&package.root_cid.to_string()]
                        .clone(),
                },
                GovernanceClock {
                    block: 20,
                    epoch: 2,
                },
            )
            .unwrap();
    }
    for package in &build_packages {
        engine
            .submit_build_attestation(
                &review_round_id,
                BuildAttestationInputV1 {
                    attestation_cid: package.root_cid.to_string(),
                    attestation_car: package.car_bytes.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    builder_address: package.value.builder_identity.clone(),
                    runtime_family: package.value.runtime_family.clone(),
                    architecture: package.value.architecture.clone(),
                    core_artifact_digest: package.value.core_artifact_digest.clone(),
                    test_result_cid: package.value.test_results_cid.clone(),
                    tests_passed_claim: true,
                    bond_atoms: ONE_IDNA,
                    commitment_proof: build_commitment.proofs[&package.root_cid.to_string()]
                        .clone(),
                },
                GovernanceClock {
                    block: 20,
                    epoch: 2,
                },
            )
            .unwrap();
    }
    for package in &availability_packages {
        engine
            .submit_data_availability_attestation(
                &review_round_id,
                DataAvailabilityAttestationInputV1 {
                    attestation_cid: package.root_cid.to_string(),
                    attestation_car: package.car_bytes.clone(),
                    candidate_ecosystem_cid: package.value.candidate_ecosystem_cid.clone(),
                    provider_id: package.value.provider_id.clone(),
                    operator_address: package.value.operator_identity.clone(),
                    pinset_cid: package.value.pinset_cid.clone(),
                    verified_cids: package.value.verified_cids.clone(),
                    probe_result_cid: package.value.probe_result_cid.clone(),
                    available_claim: true,
                    expires_at_block: package.value.expires_at_block,
                    bond_atoms: ONE_IDNA,
                    commitment_proof: availability_commitment.proofs[&package.root_cid.to_string()]
                        .clone(),
                },
                GovernanceClock {
                    block: 20,
                    epoch: 2,
                },
            )
            .unwrap();
    }
    let frozen = engine
        .freeze_review_round(
            &review_round_id,
            GovernanceClock {
                block: 50,
                epoch: 2,
            },
        )
        .unwrap();
    assert_eq!(
        frozen.agent_review_root.as_deref(),
        Some(agent_commitment.root.as_str())
    );
    assert_eq!(
        frozen.build_attestation_root.as_deref(),
        Some(build_commitment.root.as_str())
    );
    assert_eq!(
        frozen.data_availability_root.as_deref(),
        Some(availability_commitment.root.as_str())
    );
    let content = ChangeProposalContentV1 {
        schema_version: 1,
        governance_parameter_set_cid: parameter_package.root_cid.to_string(),
        parent_canonical_ecosystem_cid: parent.root_cid.to_string(),
        candidate_ecosystem_cid: candidate.root_cid.to_string(),
        affected_repositories: vec!["P2poolBTC".to_string(), "idena-go".to_string()],
        changed_file_count: 2,
        patch_bytes: aggregate_patch.car_bytes.len() as u64,
        source_package_bytes: candidate_sources
            .iter()
            .map(|package| package.car_bytes.len() as u64)
            .sum(),
        description_bytes: rationale.car_bytes.len() as u32,
        migration_operation_count: 0,
        base_source_cids: BTreeMap::from([
            (
                "P2poolBTC".to_string(),
                base_sources[0].root_cid.to_string(),
            ),
            ("idena-go".to_string(), base_sources[1].root_cid.to_string()),
        ]),
        candidate_source_cids: BTreeMap::from([
            (
                "P2poolBTC".to_string(),
                candidate_sources[0].root_cid.to_string(),
            ),
            (
                "idena-go".to_string(),
                candidate_sources[1].root_cid.to_string(),
            ),
        ]),
        patch_cid: aggregate_patch.root_cid.to_string(),
        review_round_id,
        proposer_address: address(1),
        proposal_bond_atoms: 10 * ONE_IDNA,
        risk_class: RiskClass::Critical,
        rationale_cid: rationale.root_cid.to_string(),
        migration_notes_cid: migration.root_cid.to_string(),
        test_plan_cid: test_plan.root_cid.to_string(),
        rollback_manifest_cid: migration.root_cid.to_string(),
        rollback_instructions_cid: migration.root_cid.to_string(),
        release_manifest_cid: None,
        critical_finding_waiver_cid: None,
        agent_review_root: agent_commitment.root.clone(),
        build_attestation_root: build_commitment.root.clone(),
        data_availability_root: availability_commitment.root.clone(),
        creation_block: 50,
        creation_epoch: 2,
        staking_epoch: 2,
        identity_metrics_epoch: 2,
        candidate_identity_metrics_root: None,
        candidate_identity_metrics_epoch: None,
        voting_start: 90,
        voting_end: 210,
        challenge_end: 270,
    };
    let proposal_package = package_change_proposal(content.clone(), &parameters).unwrap();
    store.put(
        &proposal_package.content_cid.to_string(),
        &proposal_package.car_bytes,
    );
    let proposal_id = engine
        .create_proposal_draft(
            content.clone(),
            0,
            GovernanceClock {
                block: 50,
                epoch: 2,
            },
        )
        .unwrap();
    engine
        .open_review(
            &proposal_id,
            GovernanceClock {
                block: 50,
                epoch: 2,
            },
        )
        .unwrap();

    engine
        .open_voting(
            &proposal_id,
            GovernanceClock {
                block: 90,
                epoch: 2,
            },
        )
        .unwrap();
    for index in 1..=12u8 {
        engine
            .cast_vote(
                &proposal_id,
                &address(index),
                VoteChoice::Yes,
                GovernanceClock {
                    block: 100,
                    epoch: 2,
                },
            )
            .unwrap();
    }
    assert!(
        engine
            .finalize_voting(
                &proposal_id,
                GovernanceClock {
                    block: 210,
                    epoch: 2
                }
            )
            .unwrap()
            .accepted
    );
    engine
        .close_challenge_period(
            &proposal_id,
            GovernanceClock {
                block: 270,
                epoch: 2,
            },
        )
        .unwrap();
    engine
        .execute_proposal(
            &proposal_id,
            GovernanceClock {
                block: 330,
                epoch: 2,
            },
        )
        .unwrap();
    assert_eq!(
        engine.canonical_ecosystem_cid(),
        candidate.root_cid.to_string()
    );

    let resolved_candidate =
        verify_ecosystem_manifest_car(&store.get(engine.canonical_ecosystem_cid())).unwrap();
    fs::create_dir(temp.path().join("checkout")).unwrap();
    for repository in &resolved_candidate.manifest.repositories {
        let car = store.get(&repository.source_tree_cid);
        let checkout = temp.path().join("checkout").join(&repository.name);
        checkout_source_car(&car, &checkout).unwrap();
        verify_tree_matches_car(&checkout, &repository.name, &car).unwrap();
    }
    let old = verify_ecosystem_manifest_car(&store.get(&parent.root_cid.to_string())).unwrap();
    assert_eq!(old.root_cid, parent.root_cid);
    for repository in &old.manifest.repositories {
        verify_source_car(&store.get(&repository.source_tree_cid)).unwrap();
    }
}
