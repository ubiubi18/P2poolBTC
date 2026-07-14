use crate::{flip_trust_bps, package_dag_cbor, verify_dag_cbor_car, DagCborPackage, IdentityState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_IDENTITY_METRICS_LEAVES: usize = 262_144;
const MAX_SOURCE_BLOCK_HASHES: usize = 65_537;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceIdentityMetricsLeafV1 {
    pub address: String,
    pub identity_state: IdentityState,
    pub total_finalized_authored_flips: u64,
    pub total_consensus_reported_authored_flips: u64,
    pub flip_trust_bps: u16,
    pub source_epoch: u16,
    pub source_block_height: u64,
    pub source_block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceIdentityMetricsProofV1 {
    pub leaf: GovernanceIdentityMetricsLeafV1,
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltIdentityMetricsSnapshot {
    pub root: String,
    pub leaves: Vec<GovernanceIdentityMetricsLeafV1>,
    pub proofs: BTreeMap<String, GovernanceIdentityMetricsProofV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityMetricsSnapshotV1 {
    pub schema_version: u16,
    pub source_epoch: u16,
    pub source_block_height: u64,
    pub source_block_hash: String,
    pub replay_start_height: u64,
    pub replay_commitment: String,
    pub source_block_hashes: Vec<String>,
    pub leaves: Vec<GovernanceIdentityMetricsLeafV1>,
    pub merkle_root: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MetricsProofError {
    #[error("identity metrics address is invalid")]
    InvalidAddress,
    #[error("identity metrics source block hash is invalid")]
    InvalidBlockHash,
    #[error("identity is not eligible for governance")]
    IneligibleIdentity,
    #[error("identity metrics trust does not match the deterministic formula")]
    InvalidTrust,
    #[error("identity metrics leaves must have unique addresses and one source boundary")]
    InconsistentSnapshot,
    #[error("identity metrics proof shape is invalid")]
    InvalidProof,
    #[error("identity metrics snapshot package is invalid")]
    InvalidSnapshotPackage,
}

pub fn package_identity_metrics_snapshot(
    value: IdentityMetricsSnapshotV1,
) -> Result<DagCborPackage<IdentityMetricsSnapshotV1>, MetricsProofError> {
    validate_identity_metrics_snapshot(&value)?;
    package_dag_cbor(value).map_err(|_| MetricsProofError::InvalidSnapshotPackage)
}

pub fn verify_identity_metrics_snapshot_car(
    bytes: &[u8],
) -> Result<DagCborPackage<IdentityMetricsSnapshotV1>, MetricsProofError> {
    let package = verify_dag_cbor_car::<IdentityMetricsSnapshotV1>(bytes)
        .map_err(|_| MetricsProofError::InvalidSnapshotPackage)?;
    validate_identity_metrics_snapshot(&package.value)?;
    Ok(package)
}

pub fn validate_identity_metrics_snapshot(
    value: &IdentityMetricsSnapshotV1,
) -> Result<(), MetricsProofError> {
    if value.schema_version != 1
        || value.replay_start_height > value.source_block_height
        || value.leaves.len() > MAX_IDENTITY_METRICS_LEAVES
        || value.source_block_hashes.len() > MAX_SOURCE_BLOCK_HASHES
    {
        return Err(MetricsProofError::InvalidSnapshotPackage);
    }
    decode_hash(&value.source_block_hash).map_err(|_| MetricsProofError::InvalidSnapshotPackage)?;
    decode_hash(&value.replay_commitment).map_err(|_| MetricsProofError::InvalidSnapshotPackage)?;
    decode_hash(&value.merkle_root).map_err(|_| MetricsProofError::InvalidSnapshotPackage)?;
    if value.source_block_hashes.is_empty()
        || value.source_block_hashes.last() != Some(&value.source_block_hash)
    {
        return Err(MetricsProofError::InvalidSnapshotPackage);
    }
    let mut source_hashes = BTreeSet::new();
    for source_hash in &value.source_block_hashes {
        decode_hash(source_hash).map_err(|_| MetricsProofError::InvalidSnapshotPackage)?;
        if !source_hashes.insert(source_hash) {
            return Err(MetricsProofError::InvalidSnapshotPackage);
        }
    }
    for leaf in &value.leaves {
        if leaf.source_epoch != value.source_epoch
            || leaf.source_block_height != value.source_block_height
            || leaf.source_block_hash != value.source_block_hash
        {
            return Err(MetricsProofError::InconsistentSnapshot);
        }
    }
    let rebuilt = build_identity_metrics_snapshot(value.leaves.clone())?;
    if rebuilt.leaves != value.leaves || rebuilt.root != value.merkle_root {
        return Err(MetricsProofError::InconsistentSnapshot);
    }
    Ok(())
}

pub fn build_identity_metrics_snapshot(
    mut leaves: Vec<GovernanceIdentityMetricsLeafV1>,
) -> Result<BuiltIdentityMetricsSnapshot, MetricsProofError> {
    if leaves.len() > MAX_IDENTITY_METRICS_LEAVES {
        return Err(MetricsProofError::InconsistentSnapshot);
    }
    for leaf in &mut leaves {
        leaf.address = normalize_address(&leaf.address)?;
        validate_identity_leaf(leaf)?;
    }
    leaves.sort_by(|left, right| left.address.cmp(&right.address));
    let mut addresses = BTreeSet::new();
    let mut boundary = None;
    for leaf in &leaves {
        if !addresses.insert(leaf.address.clone()) {
            return Err(MetricsProofError::InconsistentSnapshot);
        }
        let value = (
            leaf.source_epoch,
            leaf.source_block_height,
            leaf.source_block_hash.as_str(),
        );
        if boundary.is_some_and(|expected| expected != value) {
            return Err(MetricsProofError::InconsistentSnapshot);
        }
        boundary = Some(value);
    }
    let hashes = leaves
        .iter()
        .map(hash_identity_metrics_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let root = committed_merkle_root(merkle_root(&hashes), hashes.len() as u64);
    let mut proofs = BTreeMap::new();
    for (index, leaf) in leaves.iter().enumerate() {
        let siblings = merkle_siblings(&hashes, index)
            .into_iter()
            .map(hex::encode)
            .collect();
        proofs.insert(
            leaf.address.clone(),
            GovernanceIdentityMetricsProofV1 {
                leaf: leaf.clone(),
                index: index as u64,
                leaf_count: leaves.len() as u64,
                siblings,
            },
        );
    }
    Ok(BuiltIdentityMetricsSnapshot {
        root: hex::encode(root),
        leaves,
        proofs,
    })
}

pub fn verify_identity_metrics_proof(
    proof: &GovernanceIdentityMetricsProofV1,
    expected_root: &str,
) -> Result<(), MetricsProofError> {
    validate_identity_leaf(&proof.leaf)?;
    if proof.leaf.address != normalize_address(&proof.leaf.address)?
        || proof.leaf_count == 0
        || proof.index >= proof.leaf_count
    {
        return Err(MetricsProofError::InvalidProof);
    }
    let expected_root = decode_hash(expected_root).map_err(|_| MetricsProofError::InvalidProof)?;
    let expected_levels = merkle_levels(proof.leaf_count);
    if proof.siblings.len() != expected_levels {
        return Err(MetricsProofError::InvalidProof);
    }
    let mut current = hash_identity_metrics_leaf(&proof.leaf)?;
    let mut index = proof.index;
    let mut count = proof.leaf_count;
    for sibling in &proof.siblings {
        let sibling = decode_hash(sibling).map_err(|_| MetricsProofError::InvalidProof)?;
        if index % 2 == 0 {
            if index + 1 >= count && sibling != current {
                return Err(MetricsProofError::InvalidProof);
            }
            current = hash_merkle_node(&current, &sibling);
        } else {
            current = hash_merkle_node(&sibling, &current);
        }
        index /= 2;
        count = count.div_ceil(2);
    }
    if committed_merkle_root(current, proof.leaf_count) != expected_root {
        return Err(MetricsProofError::InvalidProof);
    }
    Ok(())
}

pub fn hash_identity_metrics_leaf(
    leaf: &GovernanceIdentityMetricsLeafV1,
) -> Result<[u8; 32], MetricsProofError> {
    validate_identity_leaf(leaf)?;
    let address = decode_address(&leaf.address)?;
    let block_hash =
        decode_hash(&leaf.source_block_hash).map_err(|_| MetricsProofError::InvalidBlockHash)?;
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(b"IDENA_GOV_METRICS_V1\0");
    data.extend_from_slice(&address);
    data.push(match leaf.identity_state {
        IdentityState::Human => 3,
        IdentityState::Verified => 2,
        IdentityState::Newbie => 1,
        _ => return Err(MetricsProofError::IneligibleIdentity),
    });
    data.extend_from_slice(&leaf.total_finalized_authored_flips.to_be_bytes());
    data.extend_from_slice(&leaf.total_consensus_reported_authored_flips.to_be_bytes());
    data.extend_from_slice(&leaf.flip_trust_bps.to_be_bytes());
    data.extend_from_slice(&leaf.source_epoch.to_be_bytes());
    data.extend_from_slice(&leaf.source_block_height.to_be_bytes());
    data.extend_from_slice(&block_hash);
    Ok(Sha256::digest(data).into())
}

pub fn normalize_address(value: &str) -> Result<String, MetricsProofError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(MetricsProofError::InvalidAddress)?;
    let bytes = hex::decode(raw).map_err(|_| MetricsProofError::InvalidAddress)?;
    if bytes.len() != 20 {
        return Err(MetricsProofError::InvalidAddress);
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn validate_identity_leaf(leaf: &GovernanceIdentityMetricsLeafV1) -> Result<(), MetricsProofError> {
    let _ = decode_address(&leaf.address)?;
    let _ =
        decode_hash(&leaf.source_block_hash).map_err(|_| MetricsProofError::InvalidBlockHash)?;
    if leaf.identity_state.status_bps().is_none() {
        return Err(MetricsProofError::IneligibleIdentity);
    }
    let expected = flip_trust_bps(
        leaf.total_finalized_authored_flips,
        leaf.total_consensus_reported_authored_flips,
    )
    .map_err(|_| MetricsProofError::InvalidTrust)?;
    if expected != leaf.flip_trust_bps {
        return Err(MetricsProofError::InvalidTrust);
    }
    Ok(())
}

fn decode_address(value: &str) -> Result<[u8; 20], MetricsProofError> {
    let normalized = normalize_address(value)?;
    let bytes = hex::decode(&normalized[2..]).map_err(|_| MetricsProofError::InvalidAddress)?;
    bytes
        .try_into()
        .map_err(|_| MetricsProofError::InvalidAddress)
}

fn decode_hash(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let bytes = hex::decode(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn merkle_levels(mut count: u64) -> usize {
    let mut levels = 0;
    while count > 1 {
        levels += 1;
        count = count.div_ceil(2);
    }
    levels
}

fn merkle_siblings(hashes: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = hashes.to_vec();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if index % 2 == 0 {
            level.get(index + 1).copied().unwrap_or(level[index])
        } else {
            level[index - 1]
        };
        siblings.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(hash_merkle_node(&pair[0], &right));
        }
        index /= 2;
        level = next;
    }
    siblings
}

fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return Sha256::digest(b"IDENA_GOV_METRICS_EMPTY_V1").into();
    }
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(hash_merkle_node(&pair[0], &right));
        }
        level = next;
    }
    level[0]
}

fn committed_merkle_root(tree_root: [u8; 32], leaf_count: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(b"IDENA_GOV_METRICS_ROOT_V1\0");
    data.extend_from_slice(&leaf_count.to_be_bytes());
    data.extend_from_slice(&tree_root);
    Sha256::digest(data).into()
}

fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(85);
    data.extend_from_slice(b"IDENA_GOV_MERKLE_V1\0");
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(address: u8, state: IdentityState, n: u64, r: u64) -> GovernanceIdentityMetricsLeafV1 {
        GovernanceIdentityMetricsLeafV1 {
            address: format!("0x{:040x}", address),
            identity_state: state,
            total_finalized_authored_flips: n,
            total_consensus_reported_authored_flips: r,
            flip_trust_bps: flip_trust_bps(n, r).unwrap(),
            source_epoch: 8,
            source_block_height: 400,
            source_block_hash: "11".repeat(32),
        }
    }

    #[test]
    fn proofs_round_trip_for_odd_and_even_leaf_counts() {
        for count in 1..=5 {
            let leaves = (1..=count)
                .map(|address| leaf(address, IdentityState::Human, 10, 1))
                .collect();
            let snapshot = build_identity_metrics_snapshot(leaves).unwrap();
            for proof in snapshot.proofs.values() {
                verify_identity_metrics_proof(proof, &snapshot.root).unwrap();
            }
        }
    }

    #[test]
    fn proof_rejects_age_fields_by_construction_and_tampering() {
        let snapshot =
            build_identity_metrics_snapshot(vec![leaf(1, IdentityState::Verified, 10, 1)]).unwrap();
        let mut proof = snapshot.proofs.values().next().unwrap().clone();
        proof.leaf.flip_trust_bps += 1;
        assert_eq!(
            verify_identity_metrics_proof(&proof, &snapshot.root),
            Err(MetricsProofError::InvalidTrust)
        );
        let json = serde_json::to_value(&proof).unwrap();
        assert!(json.get("age").is_none());
        assert!(json.get("birthday").is_none());
        assert!(json.get("generation").is_none());
    }

    #[test]
    fn full_snapshot_packages_canonically_and_rejects_drift() {
        let built = build_identity_metrics_snapshot(vec![
            leaf(1, IdentityState::Human, 10, 1),
            leaf(2, IdentityState::Verified, 20, 2),
        ])
        .unwrap();
        let snapshot = IdentityMetricsSnapshotV1 {
            schema_version: 1,
            source_epoch: 8,
            source_block_height: 400,
            source_block_hash: "11".repeat(32),
            replay_start_height: 100,
            replay_commitment: "22".repeat(32),
            source_block_hashes: vec!["33".repeat(32), "11".repeat(32)],
            leaves: built.leaves,
            merkle_root: built.root,
        };
        let package = package_identity_metrics_snapshot(snapshot.clone()).unwrap();
        let verified = verify_identity_metrics_snapshot_car(&package.car_bytes).unwrap();
        assert_eq!(verified.value, snapshot);
        assert_eq!(
            verified.root_sha256,
            hex::encode(verified.root_cid.hash().digest())
        );

        let mut reordered = snapshot.clone();
        reordered.leaves.reverse();
        assert!(matches!(
            package_identity_metrics_snapshot(reordered),
            Err(MetricsProofError::InconsistentSnapshot)
        ));
        let mut too_many_anchors = snapshot.clone();
        too_many_anchors.source_block_hashes = vec!["33".repeat(32); MAX_SOURCE_BLOCK_HASHES + 1];
        assert!(matches!(
            package_identity_metrics_snapshot(too_many_anchors),
            Err(MetricsProofError::InvalidSnapshotPackage)
        ));
        let mut wrong_boundary = snapshot;
        wrong_boundary.leaves[0].source_block_height -= 1;
        assert!(matches!(
            package_identity_metrics_snapshot(wrong_boundary),
            Err(MetricsProofError::InconsistentSnapshot)
        ));
    }
}
