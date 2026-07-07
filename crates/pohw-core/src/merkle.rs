use crate::{canonical_json, hash_hex, sha256_tagged};
use serde::Serialize;

const LEAF_TAG: &[u8] = b"POHW1_MERKLE_LEAF";
const NODE_TAG: &[u8] = b"POHW1_MERKLE_NODE";
const EMPTY_TAG: &[u8] = b"POHW1_MERKLE_EMPTY";

pub fn leaf_hash<T: Serialize>(leaf: &T) -> [u8; 32] {
    sha256_tagged(LEAF_TAG, &canonical_json(leaf))
}

pub fn merkle_root_hashes(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256_tagged(EMPTY_TAG, &[]);
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&pair[0]);
            payload.extend_from_slice(&right);
            next.push(sha256_tagged(NODE_TAG, &payload));
        }
        leaves = next;
    }

    leaves[0]
}

pub fn merkle_root<T: Serialize>(leaves: &[T]) -> String {
    hash_hex(merkle_root_hashes(leaves.iter().map(leaf_hash).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_deterministic_and_order_sensitive() {
        let a = vec!["a", "b", "c"];
        let b = vec!["a", "b", "c"];
        let c = vec!["b", "a", "c"];

        assert_eq!(merkle_root(&a), merkle_root(&b));
        assert_ne!(merkle_root(&a), merkle_root(&c));
    }

    #[test]
    fn empty_root_is_stable() {
        assert_eq!(merkle_root::<String>(&[]), merkle_root::<String>(&[]));
    }
}
