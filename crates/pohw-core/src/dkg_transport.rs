use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::{ecdh::SharedSecret, schnorr::Signature, Message, PublicKey, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::{canonical_json, hash_hex, sha256_tagged};

const MAX_DKG_SIGNER_ID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgPeerIdentity {
    pub signer_id: String,
    pub auth_pubkey_xonly_hex: String,
    pub ecdh_pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgSessionId {
    pub epoch_id: u64,
    pub threshold: usize,
    pub signer_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_data_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDkgPayload {
    pub algorithm: String,
    pub ephemeral_pubkey_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgRound1BroadcastBody {
    pub frost_identifier_hex: String,
    pub package_hash: String,
    pub package_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgRound2DirectBody {
    pub receiver_signer_id: String,
    pub receiver_identifier_hex: String,
    pub package_hash: String,
    pub encrypted_package: EncryptedDkgPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgSignerAckBody {
    pub frost_identifier_hex: String,
    pub public_key_package_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgComplaintBody {
    pub accused_signer_id: String,
    pub reason: String,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload")]
pub enum DkgMessageBody {
    Round1Broadcast(DkgRound1BroadcastBody),
    Round2Direct(DkgRound2DirectBody),
    SignerAck(DkgSignerAckBody),
    Complaint(DkgComplaintBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgMessageEnvelope {
    pub session_id: String,
    pub epoch_id: u64,
    pub sequence: u64,
    pub sender: DkgPeerIdentity,
    pub receiver_signer_id: Option<String>,
    pub body: DkgMessageBody,
    pub signature_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DkgEnvelopeSigningPayload<'a> {
    session_id: &'a str,
    epoch_id: u64,
    sequence: u64,
    sender: &'a DkgPeerIdentity,
    receiver_signer_id: &'a Option<String>,
    body: &'a DkgMessageBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Round2EncryptionAad<'a> {
    session_id: &'a str,
    epoch_id: u64,
    sender_signer_id: &'a str,
    receiver_signer_id: &'a str,
    package_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DkgTransportError {
    #[error("invalid peer signer id")]
    InvalidSignerId,
    #[error("duplicate DKG signer id: {0}")]
    DuplicateSignerId(String),
    #[error("empty DKG signer set")]
    EmptySignerSet,
    #[error("invalid DKG threshold {threshold} for signer count {signer_count}")]
    InvalidThreshold {
        threshold: usize,
        signer_count: usize,
    },
    #[error("invalid Schnorr auth pubkey: {0}")]
    InvalidAuthPubkey(String),
    #[error("invalid secp256k1 ECDH pubkey: {0}")]
    InvalidEcdhPubkey(String),
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("invalid DKG recovery-data hash: {0}")]
    InvalidRecoveryDataHash(String),
    #[error("invalid message signature: {0}")]
    InvalidSignature(String),
    #[error("missing message signature")]
    MissingSignature,
    #[error("envelope sender auth pubkey does not match signing key")]
    SigningKeyMismatch,
    #[error("encrypted payload algorithm {0} is not supported")]
    UnsupportedEncryptionAlgorithm(String),
    #[error("invalid encrypted payload hex: {0}")]
    InvalidEncryptedPayload(String),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("decrypted DKG package hash {actual_hash} does not match expected {expected_hash}")]
    PackageHashMismatch {
        expected_hash: String,
        actual_hash: String,
    },
}

impl DkgSessionId {
    pub fn new(
        epoch_id: u64,
        threshold: usize,
        signer_ids: Vec<String>,
    ) -> Result<Self, DkgTransportError> {
        Self::new_inner(epoch_id, threshold, signer_ids, None)
    }

    pub fn new_with_recovery_data_hash(
        epoch_id: u64,
        threshold: usize,
        signer_ids: Vec<String>,
        recovery_data_hash: String,
    ) -> Result<Self, DkgTransportError> {
        let recovery_data_hash = normalize_hex(&recovery_data_hash, 32)
            .map_err(DkgTransportError::InvalidRecoveryDataHash)?;
        Self::new_inner(epoch_id, threshold, signer_ids, Some(recovery_data_hash))
    }

    fn new_inner(
        epoch_id: u64,
        threshold: usize,
        signer_ids: Vec<String>,
        recovery_data_hash: Option<String>,
    ) -> Result<Self, DkgTransportError> {
        let signer_ids = normalize_dkg_session_signer_ids(signer_ids)?;
        if threshold == 0 || threshold > signer_ids.len() {
            return Err(DkgTransportError::InvalidThreshold {
                threshold,
                signer_count: signer_ids.len(),
            });
        }
        Ok(Self {
            epoch_id,
            threshold,
            signer_ids,
            recovery_data_hash,
        })
    }

    pub fn session_id(&self) -> String {
        hash_hex(sha256_tagged(b"POHW1_DKG_SESSION", &canonical_json(self)))
    }
}

impl DkgPeerIdentity {
    pub fn normalized(mut self) -> Result<Self, DkgTransportError> {
        self.signer_id = normalize_dkg_signer_id(&self.signer_id)?;
        self.auth_pubkey_xonly_hex = normalize_hex(&self.auth_pubkey_xonly_hex, 32)
            .map_err(DkgTransportError::InvalidAuthPubkey)?;
        self.ecdh_pubkey_hex = normalize_compressed_pubkey_hex(&self.ecdh_pubkey_hex)?;
        Ok(self)
    }
}

impl DkgMessageEnvelope {
    pub fn unsigned(
        session_id: String,
        epoch_id: u64,
        sequence: u64,
        sender: DkgPeerIdentity,
        receiver_signer_id: Option<String>,
        body: DkgMessageBody,
    ) -> Result<Self, DkgTransportError> {
        Ok(Self {
            session_id: normalize_hex(&session_id, 32)
                .map_err(DkgTransportError::InvalidEncryptedPayload)?,
            epoch_id,
            sequence,
            sender: sender.normalized()?,
            receiver_signer_id: receiver_signer_id
                .map(|id| normalize_dkg_signer_id(&id))
                .transpose()?,
            body,
            signature_hex: None,
        })
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        sha256_tagged(
            b"POHW1_DKG_MESSAGE",
            &canonical_json(&DkgEnvelopeSigningPayload {
                session_id: &self.session_id,
                epoch_id: self.epoch_id,
                sequence: self.sequence,
                sender: &self.sender,
                receiver_signer_id: &self.receiver_signer_id,
                body: &self.body,
            }),
        )
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), DkgTransportError> {
        let secp = Secp256k1::new();
        let auth_pubkey = keypair.x_only_public_key().0.to_string();
        if auth_pubkey != self.sender.auth_pubkey_xonly_hex {
            return Err(DkgTransportError::SigningKeyMismatch);
        }
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(self.signing_hash()), keypair);
        self.signature_hex = Some(hex::encode(signature.serialize()));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), DkgTransportError> {
        let signature_hex = self
            .signature_hex
            .as_deref()
            .ok_or(DkgTransportError::MissingSignature)?;
        let pubkey = XOnlyPublicKey::from_str(&self.sender.auth_pubkey_xonly_hex)
            .map_err(|err| DkgTransportError::InvalidAuthPubkey(err.to_string()))?;
        let signature_bytes = hex::decode(signature_hex.to_ascii_lowercase())
            .map_err(|err| DkgTransportError::InvalidSignature(err.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|err| DkgTransportError::InvalidSignature(err.to_string()))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.signing_hash()),
                &pubkey,
            )
            .map_err(|err| DkgTransportError::InvalidSignature(err.to_string()))
    }
}

pub fn encrypt_round2_package<R>(
    session_id: &str,
    epoch_id: u64,
    sender: &DkgPeerIdentity,
    receiver: &DkgPeerIdentity,
    package_hash: &str,
    plaintext_package: &[u8],
    rng: &mut R,
) -> Result<EncryptedDkgPayload, DkgTransportError>
where
    R: RngCore + CryptoRng,
{
    let sender = sender.clone().normalized()?;
    let receiver = receiver.clone().normalized()?;
    let session_id =
        normalize_hex(session_id, 32).map_err(DkgTransportError::InvalidEncryptedPayload)?;
    let package_hash =
        normalize_hex(package_hash, 32).map_err(DkgTransportError::InvalidEncryptedPayload)?;
    let receiver_pubkey = PublicKey::from_str(&receiver.ecdh_pubkey_hex)
        .map_err(|err| DkgTransportError::InvalidEcdhPubkey(err.to_string()))?;
    let ephemeral_secret = random_secret_key(rng)?;
    let ephemeral_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral_secret);
    let shared_secret = SharedSecret::new(&receiver_pubkey, &ephemeral_secret);
    let key = derive_round2_key(
        &session_id,
        epoch_id,
        &sender.signer_id,
        &receiver.signer_id,
        &package_hash,
        shared_secret.secret_bytes(),
    );
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let aad = round2_aad(
        &session_id,
        epoch_id,
        &sender.signer_id,
        &receiver.signer_id,
        &package_hash,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext_package,
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| DkgTransportError::EncryptionFailed)?;

    Ok(EncryptedDkgPayload {
        algorithm: "secp256k1-ecdh+chacha20poly1305".to_string(),
        ephemeral_pubkey_hex: ephemeral_pubkey.to_string(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn decrypt_round2_package(
    session_id: &str,
    epoch_id: u64,
    sender: &DkgPeerIdentity,
    receiver: &DkgPeerIdentity,
    receiver_secret_key: &SecretKey,
    package_hash: &str,
    encrypted: &EncryptedDkgPayload,
) -> Result<Vec<u8>, DkgTransportError> {
    if encrypted.algorithm != "secp256k1-ecdh+chacha20poly1305" {
        return Err(DkgTransportError::UnsupportedEncryptionAlgorithm(
            encrypted.algorithm.clone(),
        ));
    }
    let sender = sender.clone().normalized()?;
    let receiver = receiver.clone().normalized()?;
    let expected_receiver_pubkey =
        PublicKey::from_secret_key(&Secp256k1::new(), receiver_secret_key);
    if expected_receiver_pubkey.to_string() != receiver.ecdh_pubkey_hex {
        return Err(DkgTransportError::InvalidSecretKey(
            "receiver secret key does not match receiver ECDH pubkey".to_string(),
        ));
    }
    let session_id =
        normalize_hex(session_id, 32).map_err(DkgTransportError::InvalidEncryptedPayload)?;
    let package_hash =
        normalize_hex(package_hash, 32).map_err(DkgTransportError::InvalidEncryptedPayload)?;
    let ephemeral_pubkey = PublicKey::from_str(&encrypted.ephemeral_pubkey_hex)
        .map_err(|err| DkgTransportError::InvalidEcdhPubkey(err.to_string()))?;
    let nonce_bytes = hex::decode(encrypted.nonce_hex.to_ascii_lowercase())
        .map_err(|err| DkgTransportError::InvalidEncryptedPayload(err.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(DkgTransportError::InvalidEncryptedPayload(
            "nonce must be 12 bytes".to_string(),
        ));
    }
    let ciphertext = hex::decode(encrypted.ciphertext_hex.to_ascii_lowercase())
        .map_err(|err| DkgTransportError::InvalidEncryptedPayload(err.to_string()))?;
    let shared_secret = SharedSecret::new(&ephemeral_pubkey, receiver_secret_key);
    let key = derive_round2_key(
        &session_id,
        epoch_id,
        &sender.signer_id,
        &receiver.signer_id,
        &package_hash,
        shared_secret.secret_bytes(),
    );
    let aad = round2_aad(
        &session_id,
        epoch_id,
        &sender.signer_id,
        &receiver.signer_id,
        &package_hash,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: ciphertext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| DkgTransportError::DecryptionFailed)?;
    let actual_hash = dkg_package_hash(&plaintext);
    if actual_hash != package_hash {
        return Err(DkgTransportError::PackageHashMismatch {
            expected_hash: package_hash,
            actual_hash,
        });
    }
    Ok(plaintext)
}

pub fn dkg_package_hash(bytes: &[u8]) -> String {
    hash_hex(sha256_tagged(b"POHW1_FROST_DKG_PACKAGE", bytes))
}

fn derive_round2_key(
    session_id: &str,
    epoch_id: u64,
    sender_signer_id: &str,
    receiver_signer_id: &str,
    package_hash: &str,
    shared_secret: [u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::new();
    payload.extend_from_slice(&shared_secret);
    payload.extend_from_slice(&canonical_json(&Round2EncryptionAad {
        session_id,
        epoch_id,
        sender_signer_id,
        receiver_signer_id,
        package_hash,
    }));
    sha256_tagged(b"POHW1_DKG_ROUND2_AEAD_KEY", &payload)
}

fn round2_aad(
    session_id: &str,
    epoch_id: u64,
    sender_signer_id: &str,
    receiver_signer_id: &str,
    package_hash: &str,
) -> Vec<u8> {
    canonical_json(&Round2EncryptionAad {
        session_id,
        epoch_id,
        sender_signer_id,
        receiver_signer_id,
        package_hash,
    })
}

fn random_secret_key<R>(rng: &mut R) -> Result<SecretKey, DkgTransportError>
where
    R: RngCore + CryptoRng,
{
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&bytes) {
            return Ok(secret_key);
        }
    }
}

fn normalize_hex(value: &str, expected_len_bytes: usize) -> Result<String, String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == expected_len_bytes * 2
        && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
    {
        Ok(normalized)
    } else {
        Err(value.to_string())
    }
}

pub fn normalize_dkg_signer_id(value: &str) -> Result<String, DkgTransportError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_DKG_SIGNER_ID_LEN
        || !normalized
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DkgTransportError::InvalidSignerId);
    }
    Ok(normalized)
}

fn normalize_dkg_session_signer_ids(
    signer_ids: Vec<String>,
) -> Result<Vec<String>, DkgTransportError> {
    if signer_ids.is_empty() {
        return Err(DkgTransportError::EmptySignerSet);
    }
    let mut signer_ids = signer_ids
        .into_iter()
        .map(|signer_id| normalize_dkg_signer_id(&signer_id))
        .collect::<Result<Vec<_>, _>>()?;
    signer_ids.sort();
    for window in signer_ids.windows(2) {
        if window[0] == window[1] {
            return Err(DkgTransportError::DuplicateSignerId(window[0].clone()));
        }
    }
    Ok(signer_ids)
}

fn normalize_compressed_pubkey_hex(value: &str) -> Result<String, DkgTransportError> {
    let normalized = value.to_ascii_lowercase();
    let pubkey = PublicKey::from_str(&normalized)
        .map_err(|err| DkgTransportError::InvalidEcdhPubkey(err.to_string()))?;
    if pubkey.serialize().len() != 33 {
        return Err(DkgTransportError::InvalidEcdhPubkey(
            "expected compressed secp256k1 pubkey".to_string(),
        ));
    }
    Ok(pubkey.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn auth_key(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn ecdh_secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn peer(signer_id: &str, auth: &Keypair, ecdh_secret: &SecretKey) -> DkgPeerIdentity {
        DkgPeerIdentity {
            signer_id: signer_id.to_string(),
            auth_pubkey_xonly_hex: auth.x_only_public_key().0.to_string(),
            ecdh_pubkey_hex: PublicKey::from_secret_key(&Secp256k1::new(), ecdh_secret).to_string(),
        }
    }

    #[test]
    fn dkg_peer_identity_rejects_unsafe_signer_ids() {
        let auth = auth_key(9);
        let ecdh = ecdh_secret(10);

        for signer_id in ["", "../alice", "alice/bob", "alice bob", "alice.bob"] {
            let err = peer(signer_id, &auth, &ecdh).normalized().unwrap_err();
            assert!(matches!(err, DkgTransportError::InvalidSignerId));
        }

        let normalized = peer("Alice_01", &auth, &ecdh).normalized().unwrap();
        assert_eq!(normalized.signer_id, "alice_01");
    }

    #[test]
    fn dkg_session_id_rejects_invalid_membership() {
        assert!(matches!(
            DkgSessionId::new(7, 1, Vec::new()),
            Err(DkgTransportError::EmptySignerSet)
        ));
        assert!(matches!(
            DkgSessionId::new(7, 0, vec!["alice".to_string()]),
            Err(DkgTransportError::InvalidThreshold {
                threshold: 0,
                signer_count: 1,
            })
        ));
        assert!(matches!(
            DkgSessionId::new(7, 2, vec!["alice".to_string()]),
            Err(DkgTransportError::InvalidThreshold {
                threshold: 2,
                signer_count: 1,
            })
        ));
        assert!(matches!(
            DkgSessionId::new(
                7,
                1,
                vec!["alice".to_string(), "Alice".to_string()]
            ),
            Err(DkgTransportError::DuplicateSignerId(signer_id)) if signer_id == "alice"
        ));
        assert!(matches!(
            DkgSessionId::new(7, 1, vec!["../alice".to_string()]),
            Err(DkgTransportError::InvalidSignerId)
        ));
    }

    #[test]
    fn dkg_session_id_canonicalizes_valid_membership() {
        let session =
            DkgSessionId::new(7, 2, vec!["Bob".to_string(), "alice".to_string()]).unwrap();

        assert_eq!(session.signer_ids, vec!["alice", "bob"]);
    }

    #[test]
    fn dkg_session_id_can_bind_recovery_data_hash() {
        let signer_ids = vec!["alice".to_string(), "bob".to_string()];
        let legacy = DkgSessionId::new(7, 2, signer_ids.clone())
            .unwrap()
            .session_id();
        let recovery_a =
            DkgSessionId::new_with_recovery_data_hash(7, 2, signer_ids.clone(), "aa".repeat(32))
                .unwrap();
        let recovery_b =
            DkgSessionId::new_with_recovery_data_hash(7, 2, signer_ids, "bb".repeat(32)).unwrap();

        assert_eq!(recovery_a.recovery_data_hash, Some("aa".repeat(32)));
        assert_ne!(legacy, recovery_a.session_id());
        assert_ne!(recovery_a.session_id(), recovery_b.session_id());
    }

    #[test]
    fn dkg_session_id_rejects_invalid_recovery_data_hash() {
        assert!(matches!(
            DkgSessionId::new_with_recovery_data_hash(
                7,
                2,
                vec!["alice".to_string(), "bob".to_string()],
                "not-hex".to_string(),
            ),
            Err(DkgTransportError::InvalidRecoveryDataHash(_))
        ));
    }

    #[test]
    fn dkg_envelope_signature_detects_tampering() {
        let auth = auth_key(1);
        let ecdh = ecdh_secret(2);
        let session_id = DkgSessionId::new(7, 2, vec!["alice".to_string(), "bob".to_string()])
            .unwrap()
            .session_id();
        let mut envelope = DkgMessageEnvelope::unsigned(
            session_id,
            7,
            1,
            peer("alice", &auth, &ecdh),
            None,
            DkgMessageBody::SignerAck(DkgSignerAckBody {
                frost_identifier_hex: "01".repeat(32),
                public_key_package_hash: "aa".repeat(32),
            }),
        )
        .unwrap();

        envelope.sign(&auth).unwrap();
        envelope.verify_signature().unwrap();

        envelope.sequence = 2;
        assert!(matches!(
            envelope.verify_signature(),
            Err(DkgTransportError::InvalidSignature(_))
        ));
    }

    #[test]
    fn round2_payload_decrypts_only_for_intended_receiver_and_aad() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let alice_auth = auth_key(3);
        let bob_auth = auth_key(4);
        let carol_auth = auth_key(5);
        let alice_ecdh = ecdh_secret(6);
        let bob_ecdh = ecdh_secret(7);
        let carol_ecdh = ecdh_secret(8);
        let alice = peer("alice", &alice_auth, &alice_ecdh);
        let bob = peer("bob", &bob_auth, &bob_ecdh);
        let carol = peer("carol", &carol_auth, &carol_ecdh);
        let session_id = DkgSessionId::new(
            9,
            2,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()],
        )
        .unwrap()
        .session_id();
        let plaintext = b"round2 secret share payload";
        let package_hash = dkg_package_hash(plaintext);

        let encrypted = encrypt_round2_package(
            &session_id,
            9,
            &alice,
            &bob,
            &package_hash,
            plaintext,
            &mut rng,
        )
        .unwrap();
        let decrypted = decrypt_round2_package(
            &session_id,
            9,
            &alice,
            &bob,
            &bob_ecdh,
            &package_hash,
            &encrypted,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);

        assert!(matches!(
            decrypt_round2_package(
                &session_id,
                9,
                &alice,
                &carol,
                &carol_ecdh,
                &package_hash,
                &encrypted,
            ),
            Err(DkgTransportError::DecryptionFailed)
        ));

        assert!(matches!(
            decrypt_round2_package(
                &session_id,
                10,
                &alice,
                &bob,
                &bob_ecdh,
                &package_hash,
                &encrypted,
            ),
            Err(DkgTransportError::DecryptionFailed)
        ));
    }
}
