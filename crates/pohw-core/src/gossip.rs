use crate::sharechain::SharechainMessage;
use crate::{canonical_json, hash_hex, sha256_tagged};
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr::Signature, Message};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const GOSSIP_PROTOCOL_VERSION: &str = "POHW_GOSSIP_1";
pub const NETWORK_BOUND_GOSSIP_PROTOCOL_VERSION: &str = "POHW_GOSSIP_2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipEnvelope {
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    pub peer_pubkey_xonly_hex: String,
    pub created_at_unix: i64,
    pub nonce_hex: String,
    pub message: SharechainMessage,
    pub signature_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GossipSigningPayload {
    protocol_version: String,
    peer_pubkey_xonly_hex: String,
    created_at_unix: i64,
    nonce_hex: String,
    message_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NetworkBoundGossipSigningPayload {
    protocol_version: String,
    network_id: String,
    peer_pubkey_xonly_hex: String,
    created_at_unix: i64,
    nonce_hex: String,
    message_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GossipError {
    #[error("unsupported gossip protocol version {0}")]
    UnsupportedProtocol(String),
    #[error("legacy gossip protocol must not carry a network id")]
    UnexpectedNetworkId,
    #[error("network-bound gossip protocol requires a network id")]
    MissingNetworkId,
    #[error("invalid gossip network id: {0}")]
    InvalidNetworkId(String),
    #[error("gossip envelope network {actual} does not match expected network {expected}")]
    NetworkMismatch { expected: String, actual: String },
    #[error("invalid gossip peer pubkey: {0}")]
    InvalidPeerPubkey(String),
    #[error("invalid gossip nonce: {0}")]
    InvalidNonce(String),
    #[error("gossip envelope timestamp {created_at_unix} is too far in the future relative to {now_unix}")]
    FutureTimestamp { created_at_unix: i64, now_unix: i64 },
    #[error("gossip envelope timestamp {created_at_unix} is older than max age at {now_unix}")]
    StaleTimestamp { created_at_unix: i64, now_unix: i64 },
    #[error("missing gossip envelope signature")]
    MissingSignature,
    #[error("gossip signing key does not match envelope peer pubkey")]
    SigningKeyMismatch,
    #[error("invalid gossip envelope signature: {0}")]
    InvalidSignature(String),
}

impl GossipEnvelope {
    pub fn unsigned(
        peer_pubkey_xonly_hex: impl Into<String>,
        created_at_unix: i64,
        nonce_hex: impl Into<String>,
        message: SharechainMessage,
    ) -> Result<Self, GossipError> {
        let mut envelope = Self {
            protocol_version: GOSSIP_PROTOCOL_VERSION.to_string(),
            network_id: None,
            peer_pubkey_xonly_hex: peer_pubkey_xonly_hex.into().to_ascii_lowercase(),
            created_at_unix,
            nonce_hex: nonce_hex.into().to_ascii_lowercase(),
            message,
            signature_hex: None,
        };
        envelope.normalize_and_validate_static()?;
        Ok(envelope)
    }

    pub fn unsigned_for_network(
        network_id: impl Into<String>,
        peer_pubkey_xonly_hex: impl Into<String>,
        created_at_unix: i64,
        nonce_hex: impl Into<String>,
        message: SharechainMessage,
    ) -> Result<Self, GossipError> {
        let mut envelope = Self {
            protocol_version: NETWORK_BOUND_GOSSIP_PROTOCOL_VERSION.to_string(),
            network_id: Some(network_id.into()),
            peer_pubkey_xonly_hex: peer_pubkey_xonly_hex.into().to_ascii_lowercase(),
            created_at_unix,
            nonce_hex: nonce_hex.into().to_ascii_lowercase(),
            message,
            signature_hex: None,
        };
        envelope.normalize_and_validate_static()?;
        Ok(envelope)
    }

    pub fn envelope_hash(&self) -> String {
        let mut envelope = self.clone();
        let _ = envelope.normalize_and_validate_static();
        envelope.message = envelope.message.normalized();
        hash_hex(sha256_tagged(
            b"POHW1_GOSSIP_ENVELOPE",
            &canonical_json(&envelope),
        ))
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let payload = if self.protocol_version == NETWORK_BOUND_GOSSIP_PROTOCOL_VERSION {
            canonical_json(&NetworkBoundGossipSigningPayload {
                protocol_version: self.protocol_version.clone(),
                network_id: self
                    .network_id
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                peer_pubkey_xonly_hex: self.peer_pubkey_xonly_hex.to_ascii_lowercase(),
                created_at_unix: self.created_at_unix,
                nonce_hex: self.nonce_hex.to_ascii_lowercase(),
                message_hash: self.message.message_hash(),
            })
        } else {
            canonical_json(&GossipSigningPayload {
                protocol_version: self.protocol_version.clone(),
                peer_pubkey_xonly_hex: self.peer_pubkey_xonly_hex.to_ascii_lowercase(),
                created_at_unix: self.created_at_unix,
                nonce_hex: self.nonce_hex.to_ascii_lowercase(),
                message_hash: self.message.message_hash(),
            })
        };
        sha256_tagged(b"POHW1_GOSSIP_SIGNATURE", &payload)
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), GossipError> {
        self.normalize_and_validate_static()?;
        let signing_pubkey = keypair.x_only_public_key().0.to_string();
        if signing_pubkey != self.peer_pubkey_xonly_hex {
            return Err(GossipError::SigningKeyMismatch);
        }
        let secp = Secp256k1::new();
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(self.signing_hash()), keypair);
        self.signature_hex = Some(hex::encode(signature.serialize()));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), GossipError> {
        let mut envelope = self.clone();
        envelope.normalize_and_validate_static()?;
        let signature_hex = envelope
            .signature_hex
            .as_deref()
            .ok_or(GossipError::MissingSignature)?;
        let pubkey = XOnlyPublicKey::from_str(&envelope.peer_pubkey_xonly_hex)
            .map_err(|err| GossipError::InvalidPeerPubkey(err.to_string()))?;
        let signature_bytes = hex::decode(signature_hex.to_ascii_lowercase())
            .map_err(|err| GossipError::InvalidSignature(err.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|err| GossipError::InvalidSignature(err.to_string()))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(envelope.signing_hash()),
                &pubkey,
            )
            .map_err(|err| GossipError::InvalidSignature(err.to_string()))
    }

    pub fn verify_at(
        &self,
        now_unix: i64,
        max_future_skew_seconds: i64,
        max_age_seconds: i64,
    ) -> Result<(), GossipError> {
        self.verify_durable_at(now_unix, max_future_skew_seconds)?;
        if max_age_seconds > 0 && self.created_at_unix < now_unix.saturating_sub(max_age_seconds) {
            return Err(GossipError::StaleTimestamp {
                created_at_unix: self.created_at_unix,
                now_unix,
            });
        }
        Ok(())
    }

    pub fn verify_durable_at(
        &self,
        now_unix: i64,
        max_future_skew_seconds: i64,
    ) -> Result<(), GossipError> {
        self.verify_signature()?;
        if self.created_at_unix > now_unix.saturating_add(max_future_skew_seconds) {
            return Err(GossipError::FutureTimestamp {
                created_at_unix: self.created_at_unix,
                now_unix,
            });
        }
        Ok(())
    }

    pub fn verify_network(&self, expected_network_id: &str) -> Result<(), GossipError> {
        let expected = normalize_gossip_network_id(expected_network_id)?;
        let mut envelope = self.clone();
        envelope.normalize_and_validate_static()?;
        let actual = envelope.network_id.ok_or(GossipError::MissingNetworkId)?;
        if actual != expected {
            return Err(GossipError::NetworkMismatch { expected, actual });
        }
        Ok(())
    }

    fn normalize_and_validate_static(&mut self) -> Result<(), GossipError> {
        match self.protocol_version.as_str() {
            GOSSIP_PROTOCOL_VERSION => {
                if self.network_id.is_some() {
                    return Err(GossipError::UnexpectedNetworkId);
                }
            }
            NETWORK_BOUND_GOSSIP_PROTOCOL_VERSION => {
                let network_id = self
                    .network_id
                    .as_deref()
                    .ok_or(GossipError::MissingNetworkId)?;
                self.network_id = Some(normalize_gossip_network_id(network_id)?);
            }
            _ => {
                return Err(GossipError::UnsupportedProtocol(
                    self.protocol_version.clone(),
                ));
            }
        }
        self.peer_pubkey_xonly_hex =
            normalize_hex_32(&self.peer_pubkey_xonly_hex, GossipError::InvalidPeerPubkey)?;
        XOnlyPublicKey::from_str(&self.peer_pubkey_xonly_hex)
            .map_err(|err| GossipError::InvalidPeerPubkey(err.to_string()))?;
        self.nonce_hex = normalize_hex_32(&self.nonce_hex, GossipError::InvalidNonce)?;
        if let Some(signature_hex) = &mut self.signature_hex {
            *signature_hex = signature_hex.to_ascii_lowercase();
        }
        Ok(())
    }
}

pub fn normalize_gossip_network_id(value: &str) -> Result<String, GossipError> {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GossipError::InvalidNetworkId(
            "value must be 32 bytes encoded as 64 hex characters".to_string(),
        ));
    }
    Ok(value)
}

fn normalize_hex_32<F>(value: &str, err: F) -> Result<String, GossipError>
where
    F: Fn(String) -> GossipError,
{
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(err(
            "value must be 32 bytes encoded as 64 hex characters".to_string()
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharechain::SnapshotVote;
    use bitcoin::secp256k1::SecretKey;

    fn keypair(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn message() -> SharechainMessage {
        SharechainMessage::SnapshotVote(SnapshotVote {
            voter_miner_id: "miner".to_string(),
            snapshot_day: "2026-06-30".to_string(),
            idena_height: 1,
            score_root: "11".repeat(32),
            signature_hex: "00".to_string(),
        })
    }

    #[test]
    fn signed_gossip_envelope_verifies() {
        let keypair = keypair(40);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "22".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();

        envelope
            .verify_at(1_782_800_001, 60, 3_600)
            .expect("fresh signed envelope must verify");
    }

    #[test]
    fn signed_network_bound_gossip_envelope_verifies_only_for_its_network() {
        let keypair = keypair(42);
        let network_id = "ab".repeat(32);
        let mut envelope = GossipEnvelope::unsigned_for_network(
            &network_id,
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "24".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();

        envelope
            .verify_at(1_782_800_001, 60, 3_600)
            .expect("fresh signed network-bound envelope must verify");
        envelope
            .verify_network(&network_id.to_ascii_uppercase())
            .expect("network id comparison is normalized");
        assert!(matches!(
            envelope.verify_network(&"cd".repeat(32)),
            Err(GossipError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn network_id_is_covered_by_the_gossip_signature() {
        let keypair = keypair(43);
        let mut envelope = GossipEnvelope::unsigned_for_network(
            "ab".repeat(32),
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "25".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();
        envelope.network_id = Some("cd".repeat(32));

        assert!(matches!(
            envelope.verify_signature(),
            Err(GossipError::InvalidSignature(_))
        ));
    }

    #[test]
    fn legacy_gossip_serialization_remains_network_id_free() {
        let keypair = keypair(44);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "26".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("network_id"));
        envelope.verify_signature().unwrap();
        assert!(matches!(
            envelope.verify_network(&"ab".repeat(32)),
            Err(GossipError::MissingNetworkId)
        ));
    }

    #[test]
    fn durable_verification_accepts_old_signed_envelope_but_rejects_future_timestamp() {
        let keypair = keypair(41);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_700_000_000,
            "23".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();

        assert!(matches!(
            envelope.verify_at(1_800_000_000, 60, 3_600),
            Err(GossipError::StaleTimestamp { .. })
        ));
        envelope
            .verify_durable_at(1_800_000_000, 60)
            .expect("historical bootstrap verifies durable signature and future bound");
        assert!(matches!(
            envelope.verify_durable_at(1_600_000_000, 60),
            Err(GossipError::FutureTimestamp { .. })
        ));
    }

    #[test]
    fn signed_gossip_envelope_detects_message_tampering() {
        let keypair = keypair(40);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "22".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();
        if let SharechainMessage::SnapshotVote(vote) = &mut envelope.message {
            vote.score_root = "33".repeat(32);
        }

        assert!(matches!(
            envelope.verify_signature(),
            Err(GossipError::InvalidSignature(_))
        ));
    }

    #[test]
    fn gossip_envelope_rejects_stale_timestamp() {
        let keypair = keypair(40);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "22".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();

        assert!(matches!(
            envelope.verify_at(1_782_900_000, 60, 3_600),
            Err(GossipError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn gossip_envelope_hash_uses_normalized_hex_fields() {
        let keypair = keypair(40);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            1_782_800_000,
            "22".repeat(32),
            message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();
        let mut alternate = envelope.clone();
        alternate.peer_pubkey_xonly_hex =
            format!("0x{}", alternate.peer_pubkey_xonly_hex.to_uppercase());
        alternate.nonce_hex = format!("0x{}", alternate.nonce_hex.to_uppercase());
        alternate.signature_hex = alternate
            .signature_hex
            .as_ref()
            .map(|signature| signature.to_uppercase());
        if let SharechainMessage::SnapshotVote(vote) = &mut alternate.message {
            vote.score_root = vote.score_root.to_ascii_uppercase();
            vote.signature_hex = vote.signature_hex.to_ascii_uppercase();
        }

        assert_eq!(envelope.envelope_hash(), alternate.envelope_hash());
        alternate.verify_signature().unwrap();
    }
}
