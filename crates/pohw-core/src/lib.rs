pub mod commitment;
pub mod dkg_transport;
pub mod fork;
pub mod gossip;
pub mod idena_anchor;
pub mod ledger;
pub mod merkle;
pub mod payout;
pub mod replay;
pub mod sharechain;
pub mod sharechain_state;
pub mod snapshot;
pub mod vault;
pub mod vault_frost;
pub mod vault_tx;
pub mod withdrawal;

pub type Sats = u64;
pub type Score = u128;

pub const FORMULA_VERSION: u16 = 2;
pub const MIN_DIRECT_PAYOUT_SATS: Sats = 10_000;
pub const DIRECT_PAYOUT_LIMIT: usize = 100;

pub fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializing consensus structs must not fail")
}

pub fn sha256_tagged(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update([0]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn hash_hex(hash: [u8; 32]) -> String {
    hex::encode(hash)
}
