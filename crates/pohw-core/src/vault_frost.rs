use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, TapTweak, XOnlyPublicKey};
use bitcoin::secp256k1::SecretKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot;
use bitcoin::{Transaction, TxOut, Witness};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{EvenY, Tweak};
use rand_core::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::dkg_transport::{
    decrypt_round2_package, dkg_package_hash, encrypt_round2_package, normalize_dkg_signer_id,
    DkgMessageBody, DkgMessageEnvelope, DkgPeerIdentity, DkgRound1BroadcastBody,
    DkgRound2DirectBody, DkgSignerAckBody,
};
use crate::merkle;
use crate::vault::{
    threshold_67_percent, DkgSignerBinding, DkgTranscript, FrostSignatureShare, VaultSpendPlan,
    VerifiedFrostSignatureShare,
};
use crate::vault_tx::{build_vault_psbt, VaultTransactionPlan};
use crate::{hash_hex, sha256_tagged};

#[derive(Debug, Clone)]
pub struct SimulatedFrostKeySet {
    key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: frost::keys::PublicKeyPackage,
    threshold: u16,
    signer_count: u16,
    dkg_roots: SimulatedDkgRoots,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulatedDkgRoots {
    pub public_key_package_hash: String,
    pub round1_packages_root: String,
    pub round2_packages_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerDkgRound1Broadcast {
    pub signer_id: String,
    pub frost_identifier_hex: String,
    pub package_hash: String,
    pub package_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerDkgRound2DirectPackage {
    pub sender_signer_id: String,
    pub sender_identifier_hex: String,
    pub receiver_signer_id: String,
    pub receiver_identifier_hex: String,
    pub package_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerDkgSignerAck {
    pub signer_id: String,
    pub frost_identifier_hex: String,
    pub public_key_package_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerDkgTranscriptArtifacts {
    pub round1_broadcasts: Vec<PeerDkgRound1Broadcast>,
    pub round2_direct_packages: Vec<PeerDkgRound2DirectPackage>,
    pub signer_acks: Vec<PeerDkgSignerAck>,
}

#[derive(Debug, Clone)]
pub struct PeerDkgCeremonyResult {
    pub key_set: SimulatedFrostKeySet,
    pub transcript: DkgTranscript,
    pub artifacts: PeerDkgTranscriptArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrostSignedInput {
    pub input_index: usize,
    pub sighash_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignedVaultTransaction {
    pub spend_plan_hash: String,
    pub internal_key_xonly: String,
    pub signed_tx: Transaction,
    pub signed_inputs: Vec<FrostSignedInput>,
}

#[derive(Debug, Clone)]
pub struct FrostSignatureShareVerificationRequest<'a> {
    pub signer_id: String,
    pub identifier: frost::Identifier,
    pub expected_public_key_package_hash: String,
    pub spend_plan_hash: String,
    pub input_index: usize,
    pub sighash_hex: String,
    pub signature_share_hex: String,
    pub signing_package: &'a frost::SigningPackage,
    pub public_key_package: &'a frost::keys::PublicKeyPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostDkgState {
    pub version: u16,
    pub epoch_id: u64,
    pub session_id: String,
    pub signer_id: String,
    pub signer_ids: Vec<String>,
    pub threshold: usize,
    pub frost_identifier_hex: String,
    pub recovery_data_hash: String,
    pub round1_secret_package_hex: Option<String>,
    pub round2_secret_package_hex: Option<String>,
    pub key_package_hex: Option<String>,
    pub public_key_package_hex: Option<String>,
    pub public_key_package_hash: Option<String>,
    pub frost_group_key_xonly: Option<String>,
    pub pending_nonces: Vec<RealFrostSigningNonce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostDkgRound1Output {
    pub state: RealFrostDkgState,
    pub body: crate::dkg_transport::DkgRound1BroadcastBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostDkgRound2Output {
    pub state: RealFrostDkgState,
    pub direct_messages: Vec<RealFrostDkgDirectMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostDkgDirectMessage {
    pub receiver_signer_id: String,
    pub body: crate::dkg_transport::DkgRound2DirectBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostDkgFinalizeOutput {
    pub state: RealFrostDkgState,
    pub body: crate::dkg_transport::DkgSignerAckBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostSigningNonce {
    pub spend_plan_hash: String,
    pub input_index: usize,
    pub sighash_hex: String,
    pub signing_nonces_hex: String,
    pub signing_commitments_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostSigningCommitment {
    pub signer_id: String,
    pub frost_identifier_hex: String,
    pub public_key_package_hash: String,
    pub spend_plan_hash: String,
    pub input_index: usize,
    pub sighash_hex: String,
    pub signing_commitments_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFrostNonceCommitmentOutput {
    pub state: RealFrostDkgState,
    pub commitments: Vec<RealFrostSigningCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RealFrostSignerMaterial {
    signer_id: String,
    frost_identifier: frost::Identifier,
    key_package: frost::keys::KeyPackage,
    public_key_package: frost::keys::PublicKeyPackage,
    public_key_package_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultFrostError {
    #[error("FROST error: {0}")]
    Frost(String),
    #[error("missing DKG package: {0}")]
    MissingDkgPackage(String),
    #[error("DKG participants produced inconsistent public key packages")]
    InconsistentDkgPublicKeyPackages,
    #[error("invalid FROST group key serialization")]
    InvalidGroupKeySerialization,
    #[error("FROST group key must serialize to an even-y compressed secp256k1 key")]
    GroupKeyNotEvenY,
    #[error("invalid FROST group x-only key: {0}")]
    InvalidGroupXOnlyKey(String),
    #[error("not enough key packages: threshold {threshold}, available {available}")]
    NotEnoughKeyPackages { threshold: usize, available: usize },
    #[error("DKG signer set is empty")]
    EmptyDkgSignerSet,
    #[error("DKG signer {signer_id} appears more than once")]
    DuplicateDkgSignerId { signer_id: String },
    #[error("DKG signer count {signer_count} exceeds u16::MAX")]
    TooManyDkgSigners { signer_count: usize },
    #[error("DKG threshold {threshold} is invalid for {signer_count} signers; expected dynamic threshold {expected_threshold}")]
    InvalidDkgThreshold {
        threshold: usize,
        signer_count: usize,
        expected_threshold: usize,
    },
    #[error("invalid DKG recovery-data hash: {0}")]
    InvalidDkgRecoveryDataHash(String),
    #[error("unknown FROST identifier")]
    UnknownFrostIdentifier,
    #[error("invalid FROST sighash hex: {0}")]
    InvalidSighashHex(String),
    #[error("FROST signing package message {signing_package_message_hex} does not match claimed input sighash {expected_sighash_hex}")]
    SigningPackageSighashMismatch {
        expected_sighash_hex: String,
        signing_package_message_hex: String,
    },
    #[error("FROST public key package hash {actual_public_key_package_hash} does not match expected DKG package hash {expected_public_key_package_hash}")]
    PublicKeyPackageHashMismatch {
        expected_public_key_package_hash: String,
        actual_public_key_package_hash: String,
    },
    #[error("invalid FROST signature share hex: {0}")]
    InvalidSignatureShareHex(String),
    #[error("verified FROST share rejected by vault policy: {0}")]
    VerifiedShareRejected(String),
    #[error("missing witness UTXO for input {0}")]
    MissingWitnessUtxo(usize),
    #[error("missing Taproot internal key for input {0}")]
    MissingTapInternalKey(usize),
    #[error("PSBT input count {psbt_inputs} does not match transaction input count {tx_inputs}")]
    PsbtInputCountMismatch {
        psbt_inputs: usize,
        tx_inputs: usize,
    },
    #[error("taproot sighash error: {0}")]
    TaprootSighash(String),
    #[error("vault transaction plan error: {0}")]
    VaultTransactionPlan(String),
    #[error("invalid aggregate Schnorr signature: {0}")]
    InvalidAggregateSignature(String),
    #[error("aggregate Schnorr signature verification failed: {0}")]
    AggregateSignatureVerification(String),
    #[error("real FROST state is not at DKG stage {0}")]
    WrongRealDkgStage(&'static str),
    #[error("real FROST signer {signer_id} is not in signer set")]
    RealSignerNotInSet { signer_id: String },
    #[error("real FROST DKG message is for another session")]
    RealDkgWrongSession,
    #[error("real FROST DKG message is for another epoch")]
    RealDkgWrongEpoch,
    #[error("real FROST DKG message has invalid sender {0}")]
    RealDkgInvalidSender(String),
    #[error("real FROST DKG message has invalid receiver {0}")]
    RealDkgInvalidReceiver(String),
    #[error("real FROST DKG message body has wrong kind")]
    RealDkgWrongMessageKind,
    #[error("real FROST DKG package hash mismatch")]
    RealDkgPackageHashMismatch,
    #[error("real FROST DKG is missing message from signer {0}")]
    RealDkgMissingSigner(String),
    #[error("real FROST DKG signer ack root needs all signer acks")]
    RealDkgMissingSignerAck,
    #[error("real FROST signer state has no finalized key package")]
    RealFrostMissingKeyPackage,
    #[error("real FROST signer state has no finalized public key package")]
    RealFrostMissingPublicKeyPackage,
    #[error("real FROST public key package does not match state hash")]
    RealFrostPublicKeyPackageHashMismatch,
    #[error("real FROST signer has no nonce for spend plan {spend_plan_hash} input {input_index}")]
    RealFrostMissingNonce {
        spend_plan_hash: String,
        input_index: usize,
    },
    #[error("real FROST signing commitments have no threshold set for input {0}")]
    RealFrostMissingSigningCommitments(usize),
    #[error("real FROST signing commitment from signer {0} is inconsistent")]
    RealFrostInvalidSigningCommitment(String),
    #[error("invalid real FROST signer state: {0}")]
    InvalidRealFrostState(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DkgPackageMaterial {
    sender_identifier_hex: String,
    receiver_identifier_hex: Option<String>,
    package_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DkgSignerAckMaterial {
    signer_id: String,
    frost_identifier_hex: String,
    public_key_package_hash: String,
}

impl RealFrostDkgState {
    pub fn new(
        epoch_id: u64,
        signer_id: String,
        signer_ids: Vec<String>,
        recovery_data_hash: String,
    ) -> Result<Self, VaultFrostError> {
        let signer_ids = normalize_peer_dkg_signer_ids(signer_ids)?;
        let signer_id = normalize_dkg_signer_id(&signer_id).map_err(dkg_transport_error)?;
        let signer_index = signer_ids
            .iter()
            .position(|id| id == &signer_id)
            .ok_or_else(|| VaultFrostError::RealSignerNotInSet {
                signer_id: signer_id.clone(),
            })?;
        let threshold = threshold_67_percent(signer_ids.len());
        let participant_index =
            u16::try_from(signer_index + 1).map_err(|_| VaultFrostError::TooManyDkgSigners {
                signer_count: signer_ids.len(),
            })?;
        let recovery_data_hash = normalize_hash_hex(&recovery_data_hash)
            .map_err(VaultFrostError::InvalidDkgRecoveryDataHash)?;
        let session_id = crate::dkg_transport::DkgSessionId::new_with_recovery_data_hash(
            epoch_id,
            threshold,
            signer_ids.clone(),
            recovery_data_hash.clone(),
        )
        .map_err(dkg_transport_error)?
        .session_id();

        Ok(Self {
            version: 1,
            epoch_id,
            session_id,
            signer_id,
            signer_ids,
            threshold,
            frost_identifier_hex: participant_frost_identifier_hex(participant_index)?,
            recovery_data_hash,
            round1_secret_package_hex: None,
            round2_secret_package_hex: None,
            key_package_hex: None,
            public_key_package_hex: None,
            public_key_package_hash: None,
            frost_group_key_xonly: None,
            pending_nonces: Vec::new(),
        })
    }

    pub fn signer_bindings(&self) -> Result<Vec<DkgSignerBinding>, VaultFrostError> {
        signer_bindings_for_ids(&self.signer_ids)
    }

    pub fn normalized(mut self) -> Result<Self, VaultFrostError> {
        if self.version != 1 {
            return Err(VaultFrostError::InvalidRealFrostState(format!(
                "unsupported version {}",
                self.version
            )));
        }
        self.signer_ids = normalize_peer_dkg_signer_ids(self.signer_ids)?;
        self.signer_id = normalize_dkg_signer_id(&self.signer_id).map_err(dkg_transport_error)?;
        let signer_index = self
            .signer_ids
            .iter()
            .position(|id| id == &self.signer_id)
            .ok_or_else(|| VaultFrostError::RealSignerNotInSet {
                signer_id: self.signer_id.clone(),
            })?;
        let expected_threshold = threshold_67_percent(self.signer_ids.len());
        if self.threshold != expected_threshold {
            return Err(VaultFrostError::InvalidDkgThreshold {
                threshold: self.threshold,
                signer_count: self.signer_ids.len(),
                expected_threshold,
            });
        }
        self.recovery_data_hash = normalize_hash_hex(&self.recovery_data_hash)
            .map_err(VaultFrostError::InvalidDkgRecoveryDataHash)?;
        let expected_session_id = crate::dkg_transport::DkgSessionId::new_with_recovery_data_hash(
            self.epoch_id,
            self.threshold,
            self.signer_ids.clone(),
            self.recovery_data_hash.clone(),
        )
        .map_err(dkg_transport_error)?
        .session_id();
        self.session_id =
            normalize_hash_hex(&self.session_id).map_err(VaultFrostError::InvalidSighashHex)?;
        if self.session_id != expected_session_id {
            return Err(VaultFrostError::RealDkgWrongSession);
        }
        let participant_index =
            u16::try_from(signer_index + 1).map_err(|_| VaultFrostError::TooManyDkgSigners {
                signer_count: self.signer_ids.len(),
            })?;
        let expected_identifier_hex = participant_frost_identifier_hex(participant_index)?;
        self.frost_identifier_hex = normalize_frost_identifier_hex(&self.frost_identifier_hex)?;
        if self.frost_identifier_hex != expected_identifier_hex {
            return Err(VaultFrostError::InvalidRealFrostState(
                "signer FROST identifier does not match signer set position".to_string(),
            ));
        }
        self.round1_secret_package_hex =
            normalize_optional_hex(self.round1_secret_package_hex, "round1 secret package")?;
        self.round2_secret_package_hex =
            normalize_optional_hex(self.round2_secret_package_hex, "round2 secret package")?;
        self.key_package_hex = normalize_optional_hex(self.key_package_hex, "key package")?;
        self.public_key_package_hex =
            normalize_optional_hex(self.public_key_package_hex, "public key package")?;
        self.public_key_package_hash = self
            .public_key_package_hash
            .map(|hash| normalize_hash_hex(&hash))
            .transpose()
            .map_err(|hash| {
                VaultFrostError::InvalidRealFrostState(format!(
                    "invalid public key package hash {hash}"
                ))
            })?;
        self.frost_group_key_xonly = self
            .frost_group_key_xonly
            .map(|key| {
                let key = key.to_ascii_lowercase();
                XOnlyPublicKey::from_str(&key)
                    .map_err(|err| VaultFrostError::InvalidGroupXOnlyKey(err.to_string()))?;
                Ok::<_, VaultFrostError>(key)
            })
            .transpose()?;
        validate_pending_real_frost_nonces(&mut self.pending_nonces)?;
        Ok(self)
    }
}

pub fn real_frost_dkg_round1<R>(
    epoch_id: u64,
    signer_id: String,
    signer_ids: Vec<String>,
    recovery_data_hash: String,
    rng: &mut R,
) -> Result<RealFrostDkgRound1Output, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let mut state = RealFrostDkgState::new(epoch_id, signer_id, signer_ids, recovery_data_hash)?;
    let signer_count =
        u16::try_from(state.signer_ids.len()).map_err(|_| VaultFrostError::TooManyDkgSigners {
            signer_count: state.signer_ids.len(),
        })?;
    let threshold =
        u16::try_from(state.threshold).map_err(|_| VaultFrostError::TooManyDkgSigners {
            signer_count: state.signer_ids.len(),
        })?;
    let identifier = identifier_from_hex(&state.frost_identifier_hex)?;
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(identifier, signer_count, threshold, rng).map_err(frost_error)?;
    let round1_secret_package_bytes = frost_package_bytes(&round1_secret_package)?;
    let round1_package_bytes = frost_package_bytes(&round1_package)?;
    let package_hash = frost_package_hash(&round1_package_bytes);
    state.round1_secret_package_hex = Some(hex::encode(round1_secret_package_bytes));

    Ok(RealFrostDkgRound1Output {
        state,
        body: DkgRound1BroadcastBody {
            frost_identifier_hex: identifier_hex(&identifier),
            package_hash,
            package_hex: hex::encode(round1_package_bytes),
        },
    })
}

pub fn real_frost_dkg_round2<R>(
    mut state: RealFrostDkgState,
    round1_envelopes: &[DkgMessageEnvelope],
    sender: &DkgPeerIdentity,
    peers: &[DkgPeerIdentity],
    rng: &mut R,
) -> Result<RealFrostDkgRound2Output, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    state = state.normalized()?;
    if state.round1_secret_package_hex.is_none() || state.round2_secret_package_hex.is_some() {
        return Err(VaultFrostError::WrongRealDkgStage("round1-complete"));
    }
    let sender = sender.clone().normalized().map_err(dkg_transport_error)?;
    if sender.signer_id != state.signer_id {
        return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
    }
    let peer_by_signer = peer_map_for_state(&state, peers)?;
    let signer_bindings = state.signer_bindings()?;
    let signer_id_by_identifier = signer_id_by_identifier(&signer_bindings)?;
    let own_identifier = identifier_from_hex(&state.frost_identifier_hex)?;
    let round1_package_bytes =
        validated_round1_package_bytes(&state, round1_envelopes, true, Some(&peer_by_signer))?;
    let received_round1_packages =
        decode_round1_packages_except(&round1_package_bytes, own_identifier)?;
    let round1_secret_package =
        decode_frost_package_from_hex::<frost::keys::dkg::round1::SecretPackage>(
            state
                .round1_secret_package_hex
                .as_deref()
                .ok_or(VaultFrostError::WrongRealDkgStage("round1-complete"))?,
        )?;
    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, &received_round1_packages)
            .map_err(frost_error)?;
    state.round1_secret_package_hex = None;
    state.round2_secret_package_hex =
        Some(hex::encode(frost_package_bytes(&round2_secret_package)?));

    let mut direct_messages = Vec::new();
    for (receiver_identifier, round2_package) in round2_packages {
        let receiver_signer_id = signer_id_by_identifier
            .get(&receiver_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "signer id for receiver {}",
                    identifier_hex(&receiver_identifier)
                ))
            })?
            .clone();
        let receiver = peer_by_signer
            .get(&receiver_signer_id)
            .ok_or_else(|| VaultFrostError::RealDkgMissingSigner(receiver_signer_id.clone()))?;
        let package_bytes = frost_package_bytes(&round2_package)?;
        let package_hash = frost_package_hash(&package_bytes);
        let encrypted_package = encrypt_round2_package(
            &state.session_id,
            state.epoch_id,
            &sender,
            receiver,
            &package_hash,
            &package_bytes,
            rng,
        )
        .map_err(dkg_transport_error)?;
        direct_messages.push(RealFrostDkgDirectMessage {
            receiver_signer_id: receiver_signer_id.clone(),
            body: DkgRound2DirectBody {
                receiver_signer_id,
                receiver_identifier_hex: identifier_hex(&receiver_identifier),
                package_hash,
                encrypted_package,
            },
        });
    }
    direct_messages.sort_by(|a, b| a.receiver_signer_id.cmp(&b.receiver_signer_id));

    Ok(RealFrostDkgRound2Output {
        state,
        direct_messages,
    })
}

pub fn real_frost_dkg_finalize(
    mut state: RealFrostDkgState,
    round1_envelopes: &[DkgMessageEnvelope],
    round2_envelopes: &[DkgMessageEnvelope],
    receiver: &DkgPeerIdentity,
    peers: &[DkgPeerIdentity],
    receiver_ecdh_secret: &SecretKey,
) -> Result<RealFrostDkgFinalizeOutput, VaultFrostError> {
    state = state.normalized()?;
    if state.round2_secret_package_hex.is_none() || state.key_package_hex.is_some() {
        return Err(VaultFrostError::WrongRealDkgStage("round2-complete"));
    }
    let receiver = receiver.clone().normalized().map_err(dkg_transport_error)?;
    if receiver.signer_id != state.signer_id {
        return Err(VaultFrostError::RealDkgInvalidReceiver(receiver.signer_id));
    }
    let peer_by_signer = peer_map_for_state(&state, peers)?;
    let own_identifier = identifier_from_hex(&state.frost_identifier_hex)?;
    let round1_package_bytes =
        validated_round1_package_bytes(&state, round1_envelopes, true, Some(&peer_by_signer))?;
    let received_round1_packages =
        decode_round1_packages_except(&round1_package_bytes, own_identifier)?;
    let received_round2_package_bytes = decrypted_round2_package_bytes_for_receiver(
        &state,
        round2_envelopes,
        &receiver,
        &peer_by_signer,
        receiver_ecdh_secret,
    )?;
    let received_round2_packages = received_round2_package_bytes
        .iter()
        .map(|(sender_identifier, package_bytes)| {
            Ok((*sender_identifier, decode_frost_package(package_bytes)?))
        })
        .collect::<Result<BTreeMap<_, frost::keys::dkg::round2::Package>, VaultFrostError>>()?;
    let round2_secret_package =
        decode_frost_package_from_hex::<frost::keys::dkg::round2::SecretPackage>(
            state
                .round2_secret_package_hex
                .as_deref()
                .ok_or(VaultFrostError::WrongRealDkgStage("round2-complete"))?,
        )?;
    let (key_package, public_key_package) = frost::keys::dkg::part3(
        &round2_secret_package,
        &received_round1_packages,
        &received_round2_packages,
    )
    .map_err(frost_error)?;
    let public_key_package_hash = public_key_package_hash(&public_key_package)?;
    let frost_group_key_xonly = frost_internal_key_xonly_hex(&public_key_package)?;

    state.round1_secret_package_hex = None;
    state.round2_secret_package_hex = None;
    state.key_package_hex = Some(hex::encode(frost_package_bytes(&key_package)?));
    state.public_key_package_hex = Some(hex::encode(frost_package_bytes(&public_key_package)?));
    state.public_key_package_hash = Some(public_key_package_hash.clone());
    state.frost_group_key_xonly = Some(frost_group_key_xonly);

    Ok(RealFrostDkgFinalizeOutput {
        state,
        body: DkgSignerAckBody {
            frost_identifier_hex: identifier_hex(&own_identifier),
            public_key_package_hash,
        },
    })
}

pub fn real_frost_dkg_transcript(
    state: &RealFrostDkgState,
    round1_envelopes: &[DkgMessageEnvelope],
    round2_envelopes: &[DkgMessageEnvelope],
    signer_ack_envelopes: &[DkgMessageEnvelope],
    peers: &[DkgPeerIdentity],
) -> Result<DkgTranscript, VaultFrostError> {
    let state = state.clone().normalized()?;
    let expected_public_key_package_hash = state
        .public_key_package_hash
        .clone()
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    let frost_group_key_xonly = state
        .frost_group_key_xonly
        .clone()
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    let peer_by_signer = peer_map_for_state(&state, peers)?;
    let signer_bindings = state.signer_bindings()?;
    let round1_package_bytes =
        validated_round1_package_bytes(&state, round1_envelopes, true, Some(&peer_by_signer))?;
    let round2_material =
        validated_round2_material(&state, round2_envelopes, true, Some(&peer_by_signer))?;
    let signer_ack_material = validated_signer_ack_material(
        &state,
        signer_ack_envelopes,
        &expected_public_key_package_hash,
        Some(&peer_by_signer),
    )?;

    let mut round1_material = round1_package_bytes
        .iter()
        .map(|(sender_identifier, package_bytes)| DkgPackageMaterial {
            sender_identifier_hex: identifier_hex(sender_identifier),
            receiver_identifier_hex: None,
            package_hash: frost_package_hash(package_bytes),
        })
        .collect::<Vec<_>>();
    round1_material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });

    Ok(DkgTranscript {
        epoch_id: state.epoch_id,
        threshold: state.threshold,
        signer_ids: state.signer_ids.clone(),
        frost_group_key_xonly,
        public_key_package_hash: expected_public_key_package_hash,
        signer_bindings,
        round1_packages_root: merkle::merkle_root(&round1_material),
        round2_packages_root: merkle::merkle_root(&round2_material),
        signer_ack_root: merkle::merkle_root(&signer_ack_material),
        recovery_data_hash: state.recovery_data_hash.clone(),
    })
}

pub fn real_frost_create_nonce_commitments<R>(
    mut state: RealFrostDkgState,
    spend_plan: &VaultSpendPlan,
    input_sighashes: Vec<String>,
    rng: &mut R,
) -> Result<RealFrostNonceCommitmentOutput, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    state = state.normalized()?;
    let material = load_real_frost_signer_material(&state)?;
    validate_state_matches_spend_plan(&state, spend_plan)?;
    let spend_plan_hash = spend_plan.plan_hash();
    let input_sighashes = normalize_input_sighashes(spend_plan, input_sighashes)?;
    let mut commitments = Vec::with_capacity(input_sighashes.len());

    for (input_index, sighash_hex) in input_sighashes.into_iter().enumerate() {
        if state.pending_nonces.iter().any(|nonce| {
            nonce.spend_plan_hash == spend_plan_hash && nonce.input_index == input_index
        }) {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(format!(
                "{} already has a pending nonce for input {input_index}",
                state.signer_id
            )));
        }
        let (signing_nonces, signing_commitments) =
            frost::round1::commit(material.key_package.signing_share(), rng);
        let signing_nonces_hex = hex::encode(frost_package_bytes(&signing_nonces)?);
        let signing_commitments_hex = hex::encode(frost_package_bytes(&signing_commitments)?);
        state.pending_nonces.push(RealFrostSigningNonce {
            spend_plan_hash: spend_plan_hash.clone(),
            input_index,
            sighash_hex: sighash_hex.clone(),
            signing_nonces_hex,
            signing_commitments_hex: signing_commitments_hex.clone(),
        });
        commitments.push(RealFrostSigningCommitment {
            signer_id: state.signer_id.clone(),
            frost_identifier_hex: state.frost_identifier_hex.clone(),
            public_key_package_hash: material.public_key_package_hash.clone(),
            spend_plan_hash: spend_plan_hash.clone(),
            input_index,
            sighash_hex,
            signing_commitments_hex,
        });
    }

    Ok(RealFrostNonceCommitmentOutput { state, commitments })
}

pub fn real_frost_sign_spend_plan(
    mut state: RealFrostDkgState,
    spend_plan: &VaultSpendPlan,
    input_sighashes: Vec<String>,
    commitments: &[RealFrostSigningCommitment],
) -> Result<(RealFrostDkgState, Vec<FrostSignatureShare>), VaultFrostError> {
    state = state.normalized()?;
    let material = load_real_frost_signer_material(&state)?;
    validate_state_matches_spend_plan(&state, spend_plan)?;
    let spend_plan_hash = spend_plan.plan_hash();
    let input_sighashes = normalize_input_sighashes(spend_plan, input_sighashes)?;
    let commitments_by_input =
        signing_commitments_by_input(&state, commitments, &spend_plan_hash, &input_sighashes)?;
    let mut signature_shares = Vec::with_capacity(input_sighashes.len());

    for (input_index, sighash_hex) in input_sighashes.iter().enumerate() {
        let signing_commitments = commitments_by_input.get(&input_index).ok_or(
            VaultFrostError::RealFrostMissingSigningCommitments(input_index),
        )?;
        if signing_commitments.len() < state.threshold {
            return Err(VaultFrostError::NotEnoughKeyPackages {
                threshold: state.threshold,
                available: signing_commitments.len(),
            });
        }
        let own_signing_commitments = signing_commitments.get(&material.frost_identifier).ok_or(
            VaultFrostError::RealFrostMissingSigningCommitments(input_index),
        )?;
        let nonce_position = state
            .pending_nonces
            .iter()
            .position(|nonce| {
                nonce.spend_plan_hash == spend_plan_hash
                    && nonce.input_index == input_index
                    && nonce.sighash_hex == *sighash_hex
            })
            .ok_or_else(|| VaultFrostError::RealFrostMissingNonce {
                spend_plan_hash: spend_plan_hash.clone(),
                input_index,
            })?;
        let nonce = state.pending_nonces[nonce_position].clone();
        let own_signing_commitments_hex =
            hex::encode(frost_package_bytes(own_signing_commitments)?);
        if own_signing_commitments_hex != nonce.signing_commitments_hex {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                material.signer_id.clone(),
            ));
        }
        let nonce = state.pending_nonces.remove(nonce_position);
        let signing_nonces = decode_frost_package_from_hex::<frost::round1::SigningNonces>(
            &nonce.signing_nonces_hex,
        )?;
        let sighash_bytes = hash_hex_to_bytes(sighash_hex)?;
        let signing_package =
            frost::SigningPackage::new(signing_commitments.clone(), &sighash_bytes);
        let signature_share = frost::round2::sign_with_tweak(
            &signing_package,
            &signing_nonces,
            &material.key_package,
            None,
        )
        .map_err(frost_error)?;
        let share = FrostSignatureShare {
            signer_id: material.signer_id.clone(),
            frost_identifier_hex: identifier_hex(&material.frost_identifier),
            public_key_package_hash: material.public_key_package_hash.clone(),
            spend_plan_hash: spend_plan_hash.clone(),
            input_index,
            sighash_hex: sighash_hex.clone(),
            signature_share_hex: hex::encode(signature_share.serialize()),
        }
        .normalized()
        .map_err(|err| VaultFrostError::VerifiedShareRejected(err.to_string()))?;
        signature_shares.push(share);
    }

    Ok((state, signature_shares))
}

pub fn aggregate_real_frost_vault_transaction_with_transcript(
    spend_plan: &VaultSpendPlan,
    transcript: &DkgTranscript,
    public_key_package_hex: &str,
    commitments: &[RealFrostSigningCommitment],
    shares: &[FrostSignatureShare],
) -> Result<FrostSignedVaultTransaction, VaultFrostError> {
    aggregate_real_frost_vault_transaction_checked(
        spend_plan,
        transcript,
        public_key_package_hex,
        commitments,
        shares,
    )
}

fn aggregate_real_frost_vault_transaction_checked(
    spend_plan: &VaultSpendPlan,
    transcript: &DkgTranscript,
    public_key_package_hex: &str,
    commitments: &[RealFrostSigningCommitment],
    shares: &[FrostSignatureShare],
) -> Result<FrostSignedVaultTransaction, VaultFrostError> {
    let public_key_package =
        decode_frost_package_from_hex::<frost::keys::PublicKeyPackage>(public_key_package_hex)?;
    let public_key_package_hash = public_key_package_hash(&public_key_package)?;
    let internal_key_xonly = frost_internal_key_xonly_hex(&public_key_package)?;
    let transcript = transcript
        .clone()
        .normalized()
        .map_err(|err| VaultFrostError::VaultTransactionPlan(err.to_string()))?;
    if transcript.epoch_id != spend_plan.epoch_id {
        return Err(VaultFrostError::RealDkgWrongEpoch);
    }
    if transcript.frost_group_key_xonly != internal_key_xonly {
        return Err(VaultFrostError::InvalidGroupXOnlyKey(format!(
            "transcript key {} does not match FROST group key {internal_key_xonly}",
            transcript.frost_group_key_xonly
        )));
    }
    if transcript.public_key_package_hash != public_key_package_hash {
        return Err(VaultFrostError::RealFrostPublicKeyPackageHashMismatch);
    }
    let expected_threshold = threshold_67_percent(transcript.signer_ids.len());
    if public_key_package.min_signers().map(usize::from) != Some(expected_threshold) {
        return Err(VaultFrostError::InvalidDkgThreshold {
            threshold: public_key_package
                .min_signers()
                .map(usize::from)
                .unwrap_or(0),
            signer_count: transcript.signer_ids.len(),
            expected_threshold,
        });
    }
    let transcript_signer_by_identifier = transcript
        .signer_bindings
        .iter()
        .map(|binding| {
            (
                binding.frost_identifier_hex.clone(),
                binding.signer_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if spend_plan.frost_group_key_xonly != internal_key_xonly {
        return Err(VaultFrostError::InvalidGroupXOnlyKey(format!(
            "spend plan key {} does not match FROST group key {internal_key_xonly}",
            spend_plan.frost_group_key_xonly
        )));
    }
    let tx_plan = build_vault_psbt(spend_plan)
        .map_err(|err| VaultFrostError::VaultTransactionPlan(err.to_string()))?;
    let input_sighashes = crate::vault_tx::vault_input_sighashes(&tx_plan)
        .map_err(|err| VaultFrostError::VaultTransactionPlan(err.to_string()))?;
    let spend_plan_hash = spend_plan.plan_hash();
    let commitments_by_input = signing_commitments_by_input_from_claims(
        commitments,
        &public_key_package_hash,
        &spend_plan_hash,
        &input_sighashes,
    )?;
    let shares_by_input = signature_shares_by_input(
        shares,
        &public_key_package_hash,
        &spend_plan_hash,
        &input_sighashes,
    )?;
    validate_commitment_share_signer_metadata(
        commitments,
        shares,
        &public_key_package_hash,
        &spend_plan_hash,
        &input_sighashes,
        Some(&transcript_signer_by_identifier),
    )?;
    sign_vault_transaction_plan_with_real_frost(
        &tx_plan,
        &public_key_package,
        &public_key_package_hash,
        &internal_key_xonly,
        &commitments_by_input,
        &shares_by_input,
    )
}

#[cfg(test)]
fn generate_trusted_dealer_test_key_set<R>(
    signer_count: u16,
    threshold: u16,
    rng: &mut R,
) -> Result<SimulatedFrostKeySet, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let (shares, public_key_package) = frost::keys::generate_with_dealer(
        signer_count,
        threshold,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .map_err(frost_error)?;

    let mut key_packages = BTreeMap::new();
    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).map_err(frost_error)?;
        key_packages.insert(identifier, key_package);
    }

    let public_key_package_hash = public_key_package_hash(&public_key_package)?;

    Ok(SimulatedFrostKeySet {
        key_packages,
        public_key_package,
        threshold,
        signer_count,
        dkg_roots: SimulatedDkgRoots {
            public_key_package_hash,
            round1_packages_root: merkle::merkle_root::<DkgPackageMaterial>(&[]),
            round2_packages_root: merkle::merkle_root::<DkgPackageMaterial>(&[]),
        },
    })
}

pub fn generate_simulated_dkg_frost_key_set<R>(
    signer_count: u16,
    threshold: u16,
    rng: &mut R,
) -> Result<SimulatedFrostKeySet, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let mut round1_secret_packages = BTreeMap::new();
    let mut round1_material = Vec::new();
    let mut received_round1_packages: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    > = BTreeMap::new();

    for participant_index in 1..=signer_count {
        let participant_identifier = frost_identifier(participant_index)?;
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, signer_count, threshold, &mut *rng)
                .map_err(frost_error)?;
        round1_material.push(DkgPackageMaterial {
            sender_identifier_hex: identifier_hex(&participant_identifier),
            receiver_identifier_hex: None,
            package_hash: frost_package_hash(&frost_package_bytes(&round1_package)?),
        });
        round1_secret_packages.insert(participant_identifier, round1_secret_package);

        for receiver_index in 1..=signer_count {
            if receiver_index == participant_index {
                continue;
            }
            let receiver_identifier = frost_identifier(receiver_index)?;
            received_round1_packages
                .entry(receiver_identifier)
                .or_default()
                .insert(participant_identifier, round1_package.clone());
        }
    }

    let mut round2_secret_packages = BTreeMap::new();
    let mut round2_material = Vec::new();
    let mut received_round2_packages: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();

    for participant_index in 1..=signer_count {
        let participant_identifier = frost_identifier(participant_index)?;
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 1 secret for participant {participant_index}"
                ))
            })?;
        let round1_packages = received_round1_packages
            .get(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 1 received packages for participant {participant_index}"
                ))
            })?;
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages).map_err(frost_error)?;
        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        for (receiver_identifier, round2_package) in round2_packages {
            round2_material.push(DkgPackageMaterial {
                sender_identifier_hex: identifier_hex(&participant_identifier),
                receiver_identifier_hex: Some(identifier_hex(&receiver_identifier)),
                package_hash: frost_package_hash(&frost_package_bytes(&round2_package)?),
            });
            received_round2_packages
                .entry(receiver_identifier)
                .or_default()
                .insert(participant_identifier, round2_package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_key_package = None;

    for participant_index in 1..=signer_count {
        let participant_identifier = frost_identifier(participant_index)?;
        let round2_secret_package = round2_secret_packages
            .get(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 2 secret for participant {participant_index}"
                ))
            })?;
        let round1_packages = received_round1_packages
            .get(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 1 final packages for participant {participant_index}"
                ))
            })?;
        let round2_packages = received_round2_packages
            .get(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 2 received packages for participant {participant_index}"
                ))
            })?;
        let (key_package, participant_public_key_package) =
            frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)
                .map_err(frost_error)?;
        if let Some(existing_public_key_package) = &public_key_package {
            if existing_public_key_package != &participant_public_key_package {
                return Err(VaultFrostError::InconsistentDkgPublicKeyPackages);
            }
        } else {
            public_key_package = Some(participant_public_key_package.clone());
        }
        key_packages.insert(participant_identifier, key_package);
    }

    let public_key_package = public_key_package.ok_or_else(|| {
        VaultFrostError::MissingDkgPackage("final public key package".to_string())
    })?;
    round1_material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });
    round2_material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });
    let public_key_package_hash = public_key_package_hash(&public_key_package)?;

    Ok(SimulatedFrostKeySet {
        key_packages,
        public_key_package,
        threshold,
        signer_count,
        dkg_roots: SimulatedDkgRoots {
            public_key_package_hash,
            round1_packages_root: merkle::merkle_root(&round1_material),
            round2_packages_root: merkle::merkle_root(&round2_material),
        },
    })
}

pub fn run_local_peer_dkg_ceremony<R>(
    epoch_id: u64,
    signer_ids: Vec<String>,
    threshold: u16,
    recovery_data_hash: String,
    rng: &mut R,
) -> Result<PeerDkgCeremonyResult, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let signer_ids = normalize_peer_dkg_signer_ids(signer_ids)?;
    let signer_count = signer_ids.len();
    let expected_threshold = threshold_67_percent(signer_count);
    if usize::from(threshold) != expected_threshold {
        return Err(VaultFrostError::InvalidDkgThreshold {
            threshold: usize::from(threshold),
            signer_count,
            expected_threshold,
        });
    }
    let signer_count_u16 = u16::try_from(signer_count)
        .map_err(|_| VaultFrostError::TooManyDkgSigners { signer_count })?;
    let recovery_data_hash = normalize_hash_hex(&recovery_data_hash)
        .map_err(VaultFrostError::InvalidDkgRecoveryDataHash)?;

    let signer_bindings = signer_ids
        .iter()
        .enumerate()
        .map(|(idx, signer_id)| {
            let participant_index = u16::try_from(idx + 1)
                .map_err(|_| VaultFrostError::TooManyDkgSigners { signer_count })?;
            Ok(DkgSignerBinding {
                signer_id: signer_id.clone(),
                frost_identifier_hex: participant_frost_identifier_hex(participant_index)?,
            })
        })
        .collect::<Result<Vec<_>, VaultFrostError>>()?;
    let signer_id_by_identifier = signer_id_by_identifier(&signer_bindings)?;

    let mut round1_secret_packages = BTreeMap::new();
    let mut round1_package_bytes = BTreeMap::new();
    let mut round1_material = Vec::new();
    let mut round1_broadcasts = Vec::new();

    for binding in &signer_bindings {
        let identifier = identifier_from_hex(&binding.frost_identifier_hex)?;
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(identifier, signer_count_u16, threshold, &mut *rng)
                .map_err(frost_error)?;
        let package_bytes = frost_package_bytes(&round1_package)?;
        let package_hash = frost_package_hash(&package_bytes);
        round1_material.push(DkgPackageMaterial {
            sender_identifier_hex: binding.frost_identifier_hex.clone(),
            receiver_identifier_hex: None,
            package_hash: package_hash.clone(),
        });
        round1_broadcasts.push(PeerDkgRound1Broadcast {
            signer_id: binding.signer_id.clone(),
            frost_identifier_hex: binding.frost_identifier_hex.clone(),
            package_hash,
            package_hex: hex::encode(&package_bytes),
        });
        round1_secret_packages.insert(identifier, round1_secret_package);
        round1_package_bytes.insert(identifier, package_bytes);
    }

    let mut round2_secret_packages = BTreeMap::new();
    let mut round2_package_bytes_by_receiver: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, Vec<u8>>,
    > = BTreeMap::new();
    let mut round2_material = Vec::new();
    let mut round2_direct_packages = Vec::new();

    for binding in &signer_bindings {
        let sender_identifier = identifier_from_hex(&binding.frost_identifier_hex)?;
        let round1_secret_package = round1_secret_packages
            .remove(&sender_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 1 secret for signer {}",
                    binding.signer_id
                ))
            })?;
        let received_round1_packages =
            decode_round1_packages_except(&round1_package_bytes, sender_identifier)?;
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, &received_round1_packages)
                .map_err(frost_error)?;
        round2_secret_packages.insert(sender_identifier, round2_secret_package);

        for (receiver_identifier, round2_package) in round2_packages {
            let package_bytes = frost_package_bytes(&round2_package)?;
            let package_hash = frost_package_hash(&package_bytes);
            let receiver_signer_id = signer_id_by_identifier
                .get(&receiver_identifier)
                .ok_or_else(|| {
                    VaultFrostError::MissingDkgPackage(format!(
                        "signer id for FROST identifier {}",
                        identifier_hex(&receiver_identifier)
                    ))
                })?
                .clone();
            round2_material.push(DkgPackageMaterial {
                sender_identifier_hex: binding.frost_identifier_hex.clone(),
                receiver_identifier_hex: Some(identifier_hex(&receiver_identifier)),
                package_hash: package_hash.clone(),
            });
            round2_direct_packages.push(PeerDkgRound2DirectPackage {
                sender_signer_id: binding.signer_id.clone(),
                sender_identifier_hex: binding.frost_identifier_hex.clone(),
                receiver_signer_id,
                receiver_identifier_hex: identifier_hex(&receiver_identifier),
                package_hash,
            });
            round2_package_bytes_by_receiver
                .entry(receiver_identifier)
                .or_default()
                .insert(sender_identifier, package_bytes);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_key_package = None;

    for binding in &signer_bindings {
        let participant_identifier = identifier_from_hex(&binding.frost_identifier_hex)?;
        let round2_secret_package = round2_secret_packages
            .get(&participant_identifier)
            .ok_or_else(|| {
                VaultFrostError::MissingDkgPackage(format!(
                    "round 2 secret for signer {}",
                    binding.signer_id
                ))
            })?;
        let received_round1_packages =
            decode_round1_packages_except(&round1_package_bytes, participant_identifier)?;
        let received_round2_packages = decode_round2_packages_for_receiver(
            &round2_package_bytes_by_receiver,
            participant_identifier,
        )?;
        let (key_package, participant_public_key_package) = frost::keys::dkg::part3(
            round2_secret_package,
            &received_round1_packages,
            &received_round2_packages,
        )
        .map_err(frost_error)?;
        if let Some(existing_public_key_package) = &public_key_package {
            if existing_public_key_package != &participant_public_key_package {
                return Err(VaultFrostError::InconsistentDkgPublicKeyPackages);
            }
        } else {
            public_key_package = Some(participant_public_key_package.clone());
        }
        key_packages.insert(participant_identifier, key_package);
    }

    round1_material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });
    round2_material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });

    let public_key_package = public_key_package.ok_or_else(|| {
        VaultFrostError::MissingDkgPackage("final public key package".to_string())
    })?;
    let public_key_package_hash = public_key_package_hash(&public_key_package)?;
    let signer_acks = signer_bindings
        .iter()
        .map(|binding| PeerDkgSignerAck {
            signer_id: binding.signer_id.clone(),
            frost_identifier_hex: binding.frost_identifier_hex.clone(),
            public_key_package_hash: public_key_package_hash.clone(),
        })
        .collect::<Vec<_>>();
    let signer_ack_material = signer_acks
        .iter()
        .map(|ack| DkgSignerAckMaterial {
            signer_id: ack.signer_id.clone(),
            frost_identifier_hex: ack.frost_identifier_hex.clone(),
            public_key_package_hash: ack.public_key_package_hash.clone(),
        })
        .collect::<Vec<_>>();
    let round1_packages_root = merkle::merkle_root(&round1_material);
    let round2_packages_root = merkle::merkle_root(&round2_material);

    let key_set = SimulatedFrostKeySet {
        key_packages,
        public_key_package,
        threshold,
        signer_count: signer_count_u16,
        dkg_roots: SimulatedDkgRoots {
            public_key_package_hash: public_key_package_hash.clone(),
            round1_packages_root: round1_packages_root.clone(),
            round2_packages_root: round2_packages_root.clone(),
        },
    };
    let transcript = DkgTranscript {
        epoch_id,
        threshold: usize::from(threshold),
        signer_ids,
        frost_group_key_xonly: key_set.internal_key_xonly_hex()?,
        public_key_package_hash,
        signer_bindings,
        round1_packages_root,
        round2_packages_root,
        signer_ack_root: merkle::merkle_root(&signer_ack_material),
        recovery_data_hash,
    };
    let artifacts = PeerDkgTranscriptArtifacts {
        round1_broadcasts,
        round2_direct_packages,
        signer_acks,
    };

    Ok(PeerDkgCeremonyResult {
        key_set,
        transcript,
        artifacts,
    })
}

impl SimulatedFrostKeySet {
    pub fn signer_count(&self) -> u16 {
        self.signer_count
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn public_key_package(&self) -> &frost::keys::PublicKeyPackage {
        &self.public_key_package
    }

    pub fn dkg_roots(&self) -> &SimulatedDkgRoots {
        &self.dkg_roots
    }

    pub fn internal_key_xonly_hex(&self) -> Result<String, VaultFrostError> {
        frost_internal_key_xonly_hex(&self.public_key_package)
    }

    pub fn simulated_transcript(
        &self,
        epoch_id: u64,
        signer_ids: Vec<String>,
        recovery_data_hash: String,
    ) -> Result<DkgTranscript, VaultFrostError> {
        let signer_bindings = signer_ids
            .iter()
            .enumerate()
            .map(|(idx, signer_id)| {
                let participant_index = u16::try_from(idx + 1).map_err(|_| {
                    VaultFrostError::MissingDkgPackage(
                        "too many signer ids for simulated DKG transcript".to_string(),
                    )
                })?;
                Ok(DkgSignerBinding {
                    signer_id: signer_id.to_ascii_lowercase(),
                    frost_identifier_hex: participant_frost_identifier_hex(participant_index)?,
                })
            })
            .collect::<Result<Vec<_>, VaultFrostError>>()?;
        let signer_ack_material: Vec<_> = signer_bindings
            .iter()
            .map(|binding| DkgSignerAckMaterial {
                signer_id: binding.signer_id.clone(),
                frost_identifier_hex: binding.frost_identifier_hex.clone(),
                public_key_package_hash: self.dkg_roots.public_key_package_hash.clone(),
            })
            .collect();

        Ok(DkgTranscript {
            epoch_id,
            threshold: usize::from(self.threshold),
            signer_ids,
            frost_group_key_xonly: self.internal_key_xonly_hex()?,
            public_key_package_hash: self.dkg_roots.public_key_package_hash.clone(),
            signer_bindings,
            round1_packages_root: self.dkg_roots.round1_packages_root.clone(),
            round2_packages_root: self.dkg_roots.round2_packages_root.clone(),
            signer_ack_root: merkle::merkle_root(&signer_ack_material),
            recovery_data_hash,
        })
    }
}

pub fn frost_internal_key_xonly_hex(
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<String, VaultFrostError> {
    let even_public_key_package = public_key_package.clone().into_even_y(None);
    let serialized = even_public_key_package
        .verifying_key()
        .serialize()
        .map_err(frost_error)?;
    let xonly = compressed_even_y_key_to_xonly(&serialized)?;
    Ok(hex::encode(xonly))
}

pub fn sign_vault_spend_plan_with_simulated_keyset<R>(
    spend_plan: &VaultSpendPlan,
    key_set: &SimulatedFrostKeySet,
    rng: &mut R,
) -> Result<FrostSignedVaultTransaction, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let tx_plan = build_vault_psbt(spend_plan)
        .map_err(|err| VaultFrostError::VaultTransactionPlan(err.to_string()))?;
    sign_vault_transaction_plan_with_simulated_keyset(&tx_plan, key_set, rng)
}

pub fn verify_frost_signature_share_for_input(
    request: FrostSignatureShareVerificationRequest<'_>,
) -> Result<VerifiedFrostSignatureShare, VaultFrostError> {
    let expected_sighash_hex =
        normalize_hash_hex(&request.sighash_hex).map_err(VaultFrostError::InvalidSighashHex)?;
    let expected_sighash_bytes = hex::decode(&expected_sighash_hex)
        .map_err(|err| VaultFrostError::InvalidSighashHex(err.to_string()))?;
    let signing_package_message = request.signing_package.message();
    if signing_package_message != expected_sighash_bytes.as_slice() {
        return Err(VaultFrostError::SigningPackageSighashMismatch {
            expected_sighash_hex,
            signing_package_message_hex: hex::encode(signing_package_message),
        });
    }

    let expected_public_key_package_hash =
        normalize_hash_hex(&request.expected_public_key_package_hash).map_err(|err| {
            VaultFrostError::PublicKeyPackageHashMismatch {
                expected_public_key_package_hash: request.expected_public_key_package_hash.clone(),
                actual_public_key_package_hash: err,
            }
        })?;
    let actual_public_key_package_hash = public_key_package_hash(request.public_key_package)?;
    if actual_public_key_package_hash != expected_public_key_package_hash {
        return Err(VaultFrostError::PublicKeyPackageHashMismatch {
            expected_public_key_package_hash,
            actual_public_key_package_hash,
        });
    }

    let signature_share_hex = request.signature_share_hex.to_ascii_lowercase();
    let signature_share_bytes = hex::decode(&signature_share_hex)
        .map_err(|err| VaultFrostError::InvalidSignatureShareHex(err.to_string()))?;
    let signature_share =
        frost::round2::SignatureShare::deserialize(&signature_share_bytes).map_err(frost_error)?;
    let tweaked_public_key_package = request.public_key_package.clone().tweak(None::<&[u8]>);
    let verifying_share = tweaked_public_key_package
        .verifying_shares()
        .get(&request.identifier)
        .ok_or(VaultFrostError::UnknownFrostIdentifier)?;

    frost_core::verify_signature_share::<frost::Secp256K1Sha256TR>(
        request.identifier,
        verifying_share,
        &signature_share,
        request.signing_package,
        tweaked_public_key_package.verifying_key(),
    )
    .map_err(frost_error)?;

    VerifiedFrostSignatureShare::from_verified_share(FrostSignatureShare {
        signer_id: request.signer_id,
        frost_identifier_hex: identifier_hex(&request.identifier),
        public_key_package_hash: actual_public_key_package_hash,
        spend_plan_hash: request.spend_plan_hash,
        input_index: request.input_index,
        sighash_hex: expected_sighash_hex,
        signature_share_hex,
    })
    .map_err(|err| VaultFrostError::VerifiedShareRejected(err.to_string()))
}

fn sign_vault_transaction_plan_with_simulated_keyset<R>(
    tx_plan: &VaultTransactionPlan,
    key_set: &SimulatedFrostKeySet,
    rng: &mut R,
) -> Result<FrostSignedVaultTransaction, VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let internal_key_xonly = frost_internal_key_xonly_hex(&key_set.public_key_package)?;
    if tx_plan.psbt.inputs.len() != tx_plan.unsigned_tx.input.len() {
        return Err(VaultFrostError::PsbtInputCountMismatch {
            psbt_inputs: tx_plan.psbt.inputs.len(),
            tx_inputs: tx_plan.unsigned_tx.input.len(),
        });
    }
    for (input_index, input) in tx_plan.psbt.inputs.iter().enumerate() {
        let plan_key = input
            .tap_internal_key
            .map(|key| key.to_string())
            .ok_or(VaultFrostError::MissingTapInternalKey(input_index))?;
        if plan_key != internal_key_xonly {
            return Err(VaultFrostError::InvalidGroupXOnlyKey(format!(
                "PSBT input {input_index} internal key {plan_key} does not match FROST group key {internal_key_xonly}"
            )));
        }
    }

    let prevouts = tx_plan
        .psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(VaultFrostError::MissingWitnessUtxo(input_index))
        })
        .collect::<Result<Vec<TxOut>, _>>()?;
    let prevouts = Prevouts::All(prevouts.as_slice());
    let mut signed_tx = tx_plan.unsigned_tx.clone();
    let mut signed_inputs = Vec::with_capacity(signed_tx.input.len());

    for input_index in 0..signed_tx.input.len() {
        let sighash = {
            let mut cache = SighashCache::new(&tx_plan.unsigned_tx);
            cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
                .map_err(|err| VaultFrostError::TaprootSighash(err.to_string()))?
        };
        let sighash_bytes = sighash.to_byte_array();
        let aggregate_signature = sign_digest_with_taproot_tweak(key_set, &sighash_bytes, rng)?;
        verify_taproot_signature(&internal_key_xonly, &sighash_bytes, &aggregate_signature)?;

        let schnorr_signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&aggregate_signature)
                .map_err(|err| VaultFrostError::InvalidAggregateSignature(err.to_string()))?;
        let taproot_signature = taproot::Signature {
            signature: schnorr_signature,
            sighash_type: TapSighashType::Default,
        };
        signed_tx.input[input_index].witness = Witness::p2tr_key_spend(&taproot_signature);

        signed_inputs.push(FrostSignedInput {
            input_index,
            sighash_hex: hex::encode(sighash_bytes),
            signature_hex: hex::encode(aggregate_signature),
        });
    }

    Ok(FrostSignedVaultTransaction {
        spend_plan_hash: tx_plan.spend_plan_hash.clone(),
        internal_key_xonly,
        signed_tx,
        signed_inputs,
    })
}

fn sign_digest_with_taproot_tweak<R>(
    key_set: &SimulatedFrostKeySet,
    digest: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; 64], VaultFrostError>
where
    R: RngCore + CryptoRng,
{
    let threshold = usize::from(key_set.threshold);
    if key_set.key_packages.len() < threshold {
        return Err(VaultFrostError::NotEnoughKeyPackages {
            threshold,
            available: key_set.key_packages.len(),
        });
    }

    let selected_signers: Vec<_> = key_set
        .key_packages
        .keys()
        .take(threshold)
        .copied()
        .collect();
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for identifier in &selected_signers {
        let key_package = &key_set.key_packages[identifier];
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
        nonces_map.insert(*identifier, nonces);
        commitments_map.insert(*identifier, commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, digest);
    let mut signature_shares = BTreeMap::new();
    for identifier in &selected_signers {
        let key_package = &key_set.key_packages[identifier];
        let nonces = &nonces_map[identifier];
        let signature_share =
            frost::round2::sign_with_tweak(&signing_package, nonces, key_package, None)
                .map_err(frost_error)?;
        signature_shares.insert(*identifier, signature_share);
    }

    let group_signature = frost::aggregate_with_tweak(
        &signing_package,
        &signature_shares,
        &key_set.public_key_package,
        None,
    )
    .map_err(frost_error)?;
    let signature_bytes = group_signature.serialize().map_err(frost_error)?;
    signature_bytes
        .try_into()
        .map_err(|_| VaultFrostError::InvalidAggregateSignature("expected 64 bytes".to_string()))
}

fn verify_taproot_signature(
    internal_key_xonly: &str,
    digest: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), VaultFrostError> {
    let secp = Secp256k1::verification_only();
    let internal_key = XOnlyPublicKey::from_str(internal_key_xonly)
        .map_err(|err| VaultFrostError::InvalidGroupXOnlyKey(err.to_string()))?;
    let (tweaked_key, _) = internal_key.tap_tweak(&secp, None);
    let message = bitcoin::secp256k1::Message::from_digest(*digest);
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature_bytes)
        .map_err(|err| VaultFrostError::InvalidAggregateSignature(err.to_string()))?;
    secp.verify_schnorr(&signature, &message, tweaked_key.as_x_only_public_key())
        .map_err(|err| VaultFrostError::AggregateSignatureVerification(err.to_string()))
}

fn compressed_even_y_key_to_xonly(bytes: &[u8]) -> Result<[u8; 32], VaultFrostError> {
    if bytes.len() != 33 {
        return Err(VaultFrostError::InvalidGroupKeySerialization);
    }
    if bytes[0] != 0x02 {
        return Err(VaultFrostError::GroupKeyNotEvenY);
    }
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&bytes[1..33]);
    Ok(xonly)
}

fn frost_error(err: frost::Error) -> VaultFrostError {
    VaultFrostError::Frost(err.to_string())
}

fn frost_identifier(participant_index: u16) -> Result<frost::Identifier, VaultFrostError> {
    frost::Identifier::try_from(participant_index).map_err(frost_error)
}

pub fn participant_frost_identifier_hex(participant_index: u16) -> Result<String, VaultFrostError> {
    Ok(identifier_hex(&frost_identifier(participant_index)?))
}

fn identifier_from_hex(value: &str) -> Result<frost::Identifier, VaultFrostError> {
    let bytes = hex::decode(value).map_err(|err| {
        VaultFrostError::MissingDkgPackage(format!("invalid FROST identifier hex: {err}"))
    })?;
    frost::Identifier::deserialize(&bytes).map_err(frost_error)
}

fn identifier_hex(identifier: &frost::Identifier) -> String {
    hex::encode(identifier.serialize())
}

fn normalize_peer_dkg_signer_ids(signer_ids: Vec<String>) -> Result<Vec<String>, VaultFrostError> {
    if signer_ids.is_empty() {
        return Err(VaultFrostError::EmptyDkgSignerSet);
    }
    let mut signer_ids = signer_ids
        .into_iter()
        .map(|signer_id| normalize_dkg_signer_id(&signer_id).map_err(dkg_transport_error))
        .collect::<Result<Vec<_>, _>>()?;
    signer_ids.sort();
    for window in signer_ids.windows(2) {
        if window[0] == window[1] {
            return Err(VaultFrostError::DuplicateDkgSignerId {
                signer_id: window[0].clone(),
            });
        }
    }
    Ok(signer_ids)
}

fn signer_id_by_identifier(
    signer_bindings: &[DkgSignerBinding],
) -> Result<BTreeMap<frost::Identifier, String>, VaultFrostError> {
    signer_bindings
        .iter()
        .map(|binding| {
            Ok((
                identifier_from_hex(&binding.frost_identifier_hex)?,
                binding.signer_id.clone(),
            ))
        })
        .collect()
}

fn decode_round1_packages_except(
    package_bytes_by_sender: &BTreeMap<frost::Identifier, Vec<u8>>,
    receiver_identifier: frost::Identifier,
) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, VaultFrostError> {
    package_bytes_by_sender
        .iter()
        .filter(|(sender_identifier, _)| **sender_identifier != receiver_identifier)
        .map(|(sender_identifier, package_bytes)| {
            Ok((*sender_identifier, decode_frost_package(package_bytes)?))
        })
        .collect()
}

fn decode_round2_packages_for_receiver(
    package_bytes_by_receiver: &BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, Vec<u8>>>,
    receiver_identifier: frost::Identifier,
) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>, VaultFrostError> {
    let package_bytes_by_sender = package_bytes_by_receiver
        .get(&receiver_identifier)
        .ok_or_else(|| {
            VaultFrostError::MissingDkgPackage(format!(
                "round 2 packages for receiver {}",
                identifier_hex(&receiver_identifier)
            ))
        })?;
    package_bytes_by_sender
        .iter()
        .map(|(sender_identifier, package_bytes)| {
            Ok((*sender_identifier, decode_frost_package(package_bytes)?))
        })
        .collect()
}

fn normalize_hash_hex(value: &str) -> Result<String, String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(value.to_string())
    }
}

fn frost_package_hash(bytes: &[u8]) -> String {
    hash_hex(sha256_tagged(b"POHW1_FROST_DKG_PACKAGE", bytes))
}

fn frost_package_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, VaultFrostError> {
    serde_json::to_vec(value).map_err(|err| VaultFrostError::Frost(err.to_string()))
}

fn decode_frost_package<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, VaultFrostError> {
    serde_json::from_slice(bytes).map_err(|err| VaultFrostError::Frost(err.to_string()))
}

fn public_key_package_hash(
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<String, VaultFrostError> {
    let bytes = frost_package_bytes(public_key_package)?;
    Ok(hash_hex(sha256_tagged(
        b"POHW1_FROST_PUBLIC_KEY_PACKAGE",
        &bytes,
    )))
}

fn dkg_transport_error(err: impl ToString) -> VaultFrostError {
    VaultFrostError::Frost(format!("DKG transport error: {}", err.to_string()))
}

fn normalize_frost_identifier_hex(value: &str) -> Result<String, VaultFrostError> {
    let identifier = identifier_from_hex(value)?;
    Ok(identifier_hex(&identifier))
}

fn normalize_optional_hex(
    value: Option<String>,
    label: &str,
) -> Result<Option<String>, VaultFrostError> {
    value
        .map(|value| normalize_hex_blob(&value, label))
        .transpose()
}

fn normalize_hex_blob(value: &str, label: &str) -> Result<String, VaultFrostError> {
    let value = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(VaultFrostError::InvalidRealFrostState(format!(
            "{label} must be non-empty even-length hex"
        )));
    }
    Ok(value)
}

fn validate_pending_real_frost_nonces(
    pending_nonces: &mut [RealFrostSigningNonce],
) -> Result<(), VaultFrostError> {
    let mut seen = BTreeSet::new();
    for nonce in pending_nonces {
        nonce.spend_plan_hash = normalize_hash_hex(&nonce.spend_plan_hash).map_err(|hash| {
            VaultFrostError::InvalidRealFrostState(format!(
                "invalid pending nonce spend plan hash {hash}"
            ))
        })?;
        nonce.sighash_hex = normalize_hash_hex(&nonce.sighash_hex).map_err(|hash| {
            VaultFrostError::InvalidRealFrostState(format!("invalid pending nonce sighash {hash}"))
        })?;
        nonce.signing_nonces_hex =
            normalize_hex_blob(&nonce.signing_nonces_hex, "pending signing nonces")?;
        nonce.signing_commitments_hex = normalize_hex_blob(
            &nonce.signing_commitments_hex,
            "pending signing commitments",
        )?;
        let signing_nonces = decode_frost_package_from_hex::<frost::round1::SigningNonces>(
            &nonce.signing_nonces_hex,
        )?;
        let expected_commitments: frost::round1::SigningCommitments = (&signing_nonces).into();
        let expected_commitments_hex = hex::encode(frost_package_bytes(&expected_commitments)?);
        if expected_commitments_hex != nonce.signing_commitments_hex {
            return Err(VaultFrostError::InvalidRealFrostState(
                "pending nonce commitments do not match pending nonce secret".to_string(),
            ));
        }
        let key = (
            nonce.spend_plan_hash.clone(),
            nonce.input_index,
            nonce.sighash_hex.clone(),
        );
        if !seen.insert(key) {
            return Err(VaultFrostError::InvalidRealFrostState(
                "duplicate pending nonce for spend plan input".to_string(),
            ));
        }
    }
    Ok(())
}

fn signer_bindings_for_ids(
    signer_ids: &[String],
) -> Result<Vec<DkgSignerBinding>, VaultFrostError> {
    signer_ids
        .iter()
        .enumerate()
        .map(|(idx, signer_id)| {
            let participant_index =
                u16::try_from(idx + 1).map_err(|_| VaultFrostError::TooManyDkgSigners {
                    signer_count: signer_ids.len(),
                })?;
            let signer_id = normalize_dkg_signer_id(signer_id).map_err(dkg_transport_error)?;
            Ok(DkgSignerBinding {
                signer_id,
                frost_identifier_hex: participant_frost_identifier_hex(participant_index)?,
            })
        })
        .collect()
}

fn expected_identifier_for_signer(
    state: &RealFrostDkgState,
    signer_id: &str,
) -> Result<frost::Identifier, VaultFrostError> {
    let signer_id = normalize_dkg_signer_id(signer_id).map_err(dkg_transport_error)?;
    let signer_index = state
        .signer_ids
        .iter()
        .position(|id| id == &signer_id)
        .ok_or_else(|| VaultFrostError::RealDkgInvalidSender(signer_id.clone()))?;
    let participant_index =
        u16::try_from(signer_index + 1).map_err(|_| VaultFrostError::TooManyDkgSigners {
            signer_count: state.signer_ids.len(),
        })?;
    frost_identifier(participant_index)
}

fn peer_map_for_state(
    state: &RealFrostDkgState,
    peers: &[DkgPeerIdentity],
) -> Result<BTreeMap<String, DkgPeerIdentity>, VaultFrostError> {
    let mut peer_by_signer = BTreeMap::new();
    for peer in peers {
        let peer = peer.clone().normalized().map_err(dkg_transport_error)?;
        if !state.signer_ids.contains(&peer.signer_id) {
            return Err(VaultFrostError::RealDkgInvalidSender(peer.signer_id));
        }
        if peer_by_signer
            .insert(peer.signer_id.clone(), peer.clone())
            .is_some()
        {
            return Err(VaultFrostError::DuplicateDkgSignerId {
                signer_id: peer.signer_id,
            });
        }
    }
    for signer_id in &state.signer_ids {
        if !peer_by_signer.contains_key(signer_id) {
            return Err(VaultFrostError::RealDkgMissingSigner(signer_id.clone()));
        }
    }
    Ok(peer_by_signer)
}

fn verify_envelope_for_state(
    state: &RealFrostDkgState,
    envelope: &DkgMessageEnvelope,
    peer_by_signer: Option<&BTreeMap<String, DkgPeerIdentity>>,
) -> Result<DkgPeerIdentity, VaultFrostError> {
    envelope.verify_signature().map_err(dkg_transport_error)?;
    if envelope.session_id != state.session_id {
        return Err(VaultFrostError::RealDkgWrongSession);
    }
    if envelope.epoch_id != state.epoch_id {
        return Err(VaultFrostError::RealDkgWrongEpoch);
    }
    let sender = envelope
        .sender
        .clone()
        .normalized()
        .map_err(dkg_transport_error)?;
    if sender != envelope.sender {
        return Err(VaultFrostError::RealDkgInvalidSender(
            envelope.sender.signer_id.clone(),
        ));
    }
    let normalized_receiver = envelope
        .receiver_signer_id
        .as_deref()
        .map(|receiver| {
            normalize_dkg_signer_id(receiver)
                .map_err(|_| VaultFrostError::RealDkgInvalidReceiver(receiver.to_string()))
        })
        .transpose()?;
    if normalized_receiver != envelope.receiver_signer_id {
        return Err(VaultFrostError::RealDkgInvalidReceiver(
            envelope
                .receiver_signer_id
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        ));
    }
    if !state.signer_ids.contains(&sender.signer_id) {
        return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
    }
    if let Some(peer_by_signer) = peer_by_signer {
        let expected_peer = peer_by_signer
            .get(&sender.signer_id)
            .ok_or_else(|| VaultFrostError::RealDkgMissingSigner(sender.signer_id.clone()))?;
        if expected_peer != &sender {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
    }
    Ok(sender)
}

fn validated_round1_package_bytes(
    state: &RealFrostDkgState,
    round1_envelopes: &[DkgMessageEnvelope],
    require_all: bool,
    peer_by_signer: Option<&BTreeMap<String, DkgPeerIdentity>>,
) -> Result<BTreeMap<frost::Identifier, Vec<u8>>, VaultFrostError> {
    let mut package_bytes_by_sender = BTreeMap::new();
    for envelope in round1_envelopes {
        let sender = verify_envelope_for_state(state, envelope, peer_by_signer)?;
        if envelope.receiver_signer_id.is_some() {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                envelope
                    .receiver_signer_id
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            ));
        }
        let DkgMessageBody::Round1Broadcast(body) = &envelope.body else {
            return Err(VaultFrostError::RealDkgWrongMessageKind);
        };
        let expected_identifier = expected_identifier_for_signer(state, &sender.signer_id)?;
        let claimed_identifier = identifier_from_hex(&body.frost_identifier_hex)?;
        if claimed_identifier != expected_identifier {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
        let package_bytes = hex::decode(body.package_hex.to_ascii_lowercase()).map_err(|err| {
            VaultFrostError::MissingDkgPackage(format!("invalid round1 package hex: {err}"))
        })?;
        let package_hash = normalize_hash_hex(&body.package_hash)
            .map_err(|_| VaultFrostError::RealDkgPackageHashMismatch)?;
        if dkg_package_hash(&package_bytes) != package_hash {
            return Err(VaultFrostError::RealDkgPackageHashMismatch);
        }
        if package_bytes_by_sender
            .insert(claimed_identifier, package_bytes)
            .is_some()
        {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
    }
    if require_all {
        for signer_id in &state.signer_ids {
            let identifier = expected_identifier_for_signer(state, signer_id)?;
            if !package_bytes_by_sender.contains_key(&identifier) {
                return Err(VaultFrostError::RealDkgMissingSigner(signer_id.clone()));
            }
        }
    }
    Ok(package_bytes_by_sender)
}

fn decrypted_round2_package_bytes_for_receiver(
    state: &RealFrostDkgState,
    round2_envelopes: &[DkgMessageEnvelope],
    receiver: &DkgPeerIdentity,
    peer_by_signer: &BTreeMap<String, DkgPeerIdentity>,
    receiver_ecdh_secret: &SecretKey,
) -> Result<BTreeMap<frost::Identifier, Vec<u8>>, VaultFrostError> {
    let mut package_bytes_by_sender = BTreeMap::new();
    for envelope in round2_envelopes {
        let Some(receiver_signer_id) = envelope.receiver_signer_id.as_deref() else {
            continue;
        };
        let normalized_receiver = normalize_dkg_signer_id(receiver_signer_id)
            .map_err(|_| VaultFrostError::RealDkgInvalidReceiver(receiver_signer_id.to_string()))?;
        if normalized_receiver.as_str() != receiver_signer_id {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                receiver_signer_id.to_string(),
            ));
        }
        if normalized_receiver != state.signer_id {
            continue;
        }
        let sender = verify_envelope_for_state(state, envelope, Some(peer_by_signer))?;
        if sender.signer_id == state.signer_id {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
        let DkgMessageBody::Round2Direct(body) = &envelope.body else {
            return Err(VaultFrostError::RealDkgWrongMessageKind);
        };
        let body_receiver_signer_id =
            normalize_dkg_signer_id(&body.receiver_signer_id).map_err(|_| {
                VaultFrostError::RealDkgInvalidReceiver(body.receiver_signer_id.clone())
            })?;
        if body_receiver_signer_id.as_str() != body.receiver_signer_id {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                body.receiver_signer_id.clone(),
            ));
        }
        if body_receiver_signer_id != state.signer_id {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                body.receiver_signer_id.clone(),
            ));
        }
        let receiver_identifier = identifier_from_hex(&body.receiver_identifier_hex)?;
        if receiver_identifier != identifier_from_hex(&state.frost_identifier_hex)? {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                body.receiver_signer_id.clone(),
            ));
        }
        let package_hash = normalize_hash_hex(&body.package_hash)
            .map_err(|_| VaultFrostError::RealDkgPackageHashMismatch)?;
        let plaintext = decrypt_round2_package(
            &state.session_id,
            state.epoch_id,
            &sender,
            receiver,
            receiver_ecdh_secret,
            &package_hash,
            &body.encrypted_package,
        )
        .map_err(dkg_transport_error)?;
        let sender_identifier = expected_identifier_for_signer(state, &sender.signer_id)?;
        if package_bytes_by_sender
            .insert(sender_identifier, plaintext)
            .is_some()
        {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
    }
    for signer_id in &state.signer_ids {
        if signer_id == &state.signer_id {
            continue;
        }
        let identifier = expected_identifier_for_signer(state, signer_id)?;
        if !package_bytes_by_sender.contains_key(&identifier) {
            return Err(VaultFrostError::RealDkgMissingSigner(signer_id.clone()));
        }
    }
    Ok(package_bytes_by_sender)
}

fn validated_round2_material(
    state: &RealFrostDkgState,
    round2_envelopes: &[DkgMessageEnvelope],
    require_all: bool,
    peer_by_signer: Option<&BTreeMap<String, DkgPeerIdentity>>,
) -> Result<Vec<DkgPackageMaterial>, VaultFrostError> {
    let mut material = Vec::new();
    let mut seen = BTreeSet::new();
    for envelope in round2_envelopes {
        let sender = verify_envelope_for_state(state, envelope, peer_by_signer)?;
        let Some(receiver_signer_id) = envelope.receiver_signer_id.as_deref() else {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                "<none>".to_string(),
            ));
        };
        let receiver_signer_id = normalize_dkg_signer_id(receiver_signer_id)
            .map_err(|_| VaultFrostError::RealDkgInvalidReceiver(receiver_signer_id.to_string()))?;
        if !state.signer_ids.contains(&receiver_signer_id) || receiver_signer_id == sender.signer_id
        {
            return Err(VaultFrostError::RealDkgInvalidReceiver(receiver_signer_id));
        }
        let DkgMessageBody::Round2Direct(body) = &envelope.body else {
            return Err(VaultFrostError::RealDkgWrongMessageKind);
        };
        let body_receiver_signer_id =
            normalize_dkg_signer_id(&body.receiver_signer_id).map_err(|_| {
                VaultFrostError::RealDkgInvalidReceiver(body.receiver_signer_id.clone())
            })?;
        if body_receiver_signer_id.as_str() != body.receiver_signer_id {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                body.receiver_signer_id.clone(),
            ));
        }
        if body_receiver_signer_id != receiver_signer_id {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                body.receiver_signer_id.clone(),
            ));
        }
        let sender_identifier = expected_identifier_for_signer(state, &sender.signer_id)?;
        let receiver_identifier = expected_identifier_for_signer(state, &receiver_signer_id)?;
        if identifier_from_hex(&body.receiver_identifier_hex)? != receiver_identifier {
            return Err(VaultFrostError::RealDkgInvalidReceiver(receiver_signer_id));
        }
        let package_hash = normalize_hash_hex(&body.package_hash)
            .map_err(|_| VaultFrostError::RealDkgPackageHashMismatch)?;
        let key = (sender.signer_id.clone(), body_receiver_signer_id);
        if !seen.insert(key) {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
        material.push(DkgPackageMaterial {
            sender_identifier_hex: identifier_hex(&sender_identifier),
            receiver_identifier_hex: Some(identifier_hex(&receiver_identifier)),
            package_hash,
        });
    }
    if require_all {
        for sender_id in &state.signer_ids {
            for receiver_id in &state.signer_ids {
                if sender_id == receiver_id {
                    continue;
                }
                if !seen.contains(&(sender_id.clone(), receiver_id.clone())) {
                    return Err(VaultFrostError::RealDkgMissingSigner(sender_id.clone()));
                }
            }
        }
    }
    material.sort_by(|a, b| {
        a.sender_identifier_hex
            .cmp(&b.sender_identifier_hex)
            .then_with(|| a.receiver_identifier_hex.cmp(&b.receiver_identifier_hex))
    });
    Ok(material)
}

fn validated_signer_ack_material(
    state: &RealFrostDkgState,
    signer_ack_envelopes: &[DkgMessageEnvelope],
    public_key_package_hash: &str,
    peer_by_signer: Option<&BTreeMap<String, DkgPeerIdentity>>,
) -> Result<Vec<DkgSignerAckMaterial>, VaultFrostError> {
    let mut material = Vec::new();
    let mut seen = BTreeSet::new();
    for envelope in signer_ack_envelopes {
        let sender = verify_envelope_for_state(state, envelope, peer_by_signer)?;
        if envelope.receiver_signer_id.is_some() {
            return Err(VaultFrostError::RealDkgInvalidReceiver(
                envelope
                    .receiver_signer_id
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            ));
        }
        let DkgMessageBody::SignerAck(body) = &envelope.body else {
            return Err(VaultFrostError::RealDkgWrongMessageKind);
        };
        let expected_identifier = expected_identifier_for_signer(state, &sender.signer_id)?;
        if identifier_from_hex(&body.frost_identifier_hex)? != expected_identifier {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
        let ack_hash = normalize_hash_hex(&body.public_key_package_hash)
            .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?;
        if ack_hash != public_key_package_hash {
            return Err(VaultFrostError::RealFrostPublicKeyPackageHashMismatch);
        }
        if !seen.insert(sender.signer_id.clone()) {
            return Err(VaultFrostError::RealDkgInvalidSender(sender.signer_id));
        }
        material.push(DkgSignerAckMaterial {
            signer_id: sender.signer_id,
            frost_identifier_hex: identifier_hex(&expected_identifier),
            public_key_package_hash: ack_hash,
        });
    }
    for signer_id in &state.signer_ids {
        if !seen.contains(signer_id) {
            return Err(VaultFrostError::RealDkgMissingSignerAck);
        }
    }
    material.sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
    Ok(material)
}

fn decode_frost_package_from_hex<T: DeserializeOwned>(value: &str) -> Result<T, VaultFrostError> {
    let bytes = hex::decode(value.to_ascii_lowercase())
        .map_err(|err| VaultFrostError::Frost(format!("invalid FROST package hex: {err}")))?;
    decode_frost_package(&bytes)
}

fn hash_hex_to_bytes(value: &str) -> Result<[u8; 32], VaultFrostError> {
    let normalized = normalize_hash_hex(value).map_err(VaultFrostError::InvalidSighashHex)?;
    let bytes = hex::decode(normalized)
        .map_err(|err| VaultFrostError::InvalidSighashHex(err.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| VaultFrostError::InvalidSighashHex(value.to_string()))
}

fn load_real_frost_signer_material(
    state: &RealFrostDkgState,
) -> Result<RealFrostSignerMaterial, VaultFrostError> {
    let key_package_hex = state
        .key_package_hex
        .as_deref()
        .ok_or(VaultFrostError::RealFrostMissingKeyPackage)?;
    let public_key_package_hex = state
        .public_key_package_hex
        .as_deref()
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    let expected_public_key_package_hash = state
        .public_key_package_hash
        .clone()
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    let key_package = decode_frost_package_from_hex::<frost::keys::KeyPackage>(key_package_hex)?;
    let public_key_package =
        decode_frost_package_from_hex::<frost::keys::PublicKeyPackage>(public_key_package_hex)?;
    if public_key_package_hash(&public_key_package)? != expected_public_key_package_hash {
        return Err(VaultFrostError::RealFrostPublicKeyPackageHashMismatch);
    }
    let frost_group_key_xonly = frost_internal_key_xonly_hex(&public_key_package)?;
    if state
        .frost_group_key_xonly
        .as_deref()
        .is_some_and(|key| key != frost_group_key_xonly)
    {
        return Err(VaultFrostError::RealFrostPublicKeyPackageHashMismatch);
    }
    let frost_identifier = identifier_from_hex(&state.frost_identifier_hex)?;
    if !public_key_package
        .verifying_shares()
        .contains_key(&frost_identifier)
    {
        return Err(VaultFrostError::UnknownFrostIdentifier);
    }
    Ok(RealFrostSignerMaterial {
        signer_id: state.signer_id.clone(),
        frost_identifier,
        key_package,
        public_key_package,
        public_key_package_hash: expected_public_key_package_hash,
    })
}

fn validate_state_matches_spend_plan(
    state: &RealFrostDkgState,
    spend_plan: &VaultSpendPlan,
) -> Result<(), VaultFrostError> {
    if state.epoch_id != spend_plan.epoch_id {
        return Err(VaultFrostError::RealDkgWrongEpoch);
    }
    let group_key = state
        .frost_group_key_xonly
        .as_deref()
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    if group_key != spend_plan.frost_group_key_xonly {
        return Err(VaultFrostError::InvalidGroupXOnlyKey(format!(
            "spend plan key {} does not match signer state key {group_key}",
            spend_plan.frost_group_key_xonly
        )));
    }
    Ok(())
}

fn normalize_input_sighashes(
    spend_plan: &VaultSpendPlan,
    input_sighashes: Vec<String>,
) -> Result<Vec<String>, VaultFrostError> {
    if input_sighashes.len() != spend_plan.inputs.len() {
        return Err(VaultFrostError::PsbtInputCountMismatch {
            psbt_inputs: input_sighashes.len(),
            tx_inputs: spend_plan.inputs.len(),
        });
    }
    input_sighashes
        .iter()
        .map(|sighash| normalize_hash_hex(sighash).map_err(VaultFrostError::InvalidSighashHex))
        .collect()
}

fn signing_commitments_by_input(
    state: &RealFrostDkgState,
    commitments: &[RealFrostSigningCommitment],
    spend_plan_hash: &str,
    input_sighashes: &[String],
) -> Result<
    BTreeMap<usize, BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>,
    VaultFrostError,
> {
    for commitment in commitments {
        let signer_id = commitment.signer_id.to_ascii_lowercase();
        let expected_identifier = expected_identifier_for_signer(state, &signer_id)?;
        let claimed_identifier = identifier_from_hex(&commitment.frost_identifier_hex)?;
        if claimed_identifier != expected_identifier {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
    }
    signing_commitments_by_input_from_claims(
        commitments,
        state
            .public_key_package_hash
            .as_deref()
            .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?,
        spend_plan_hash,
        input_sighashes,
    )
}

fn signing_commitments_by_input_from_claims(
    commitments: &[RealFrostSigningCommitment],
    public_key_package_hash: &str,
    spend_plan_hash: &str,
    input_sighashes: &[String],
) -> Result<
    BTreeMap<usize, BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>,
    VaultFrostError,
> {
    let public_key_package_hash = normalize_hash_hex(public_key_package_hash)
        .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?;
    let spend_plan_hash = normalize_hash_hex(spend_plan_hash).map_err(|_| {
        VaultFrostError::RealFrostInvalidSigningCommitment(spend_plan_hash.to_string())
    })?;
    let mut by_input: BTreeMap<
        usize,
        BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    > = BTreeMap::new();
    for commitment in commitments {
        let signer_id =
            normalize_dkg_signer_id(&commitment.signer_id).map_err(dkg_transport_error)?;
        if normalize_hash_hex(&commitment.public_key_package_hash)
            .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?
            != public_key_package_hash
        {
            return Err(VaultFrostError::RealFrostPublicKeyPackageHashMismatch);
        }
        if normalize_hash_hex(&commitment.spend_plan_hash)
            .map_err(|_| VaultFrostError::RealFrostInvalidSigningCommitment(signer_id.clone()))?
            != spend_plan_hash
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
        if commitment.input_index >= input_sighashes.len() {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                commitment.signer_id.clone(),
            ));
        }
        if normalize_hash_hex(&commitment.sighash_hex)
            .map_err(VaultFrostError::InvalidSighashHex)?
            != input_sighashes[commitment.input_index]
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                commitment.signer_id.clone(),
            ));
        }
        let identifier = identifier_from_hex(&commitment.frost_identifier_hex)?;
        let signing_commitments = decode_frost_package_from_hex::<frost::round1::SigningCommitments>(
            &commitment.signing_commitments_hex,
        )?;
        if by_input
            .entry(commitment.input_index)
            .or_default()
            .insert(identifier, signing_commitments)
            .is_some()
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                commitment.signer_id.clone(),
            ));
        }
    }
    Ok(by_input)
}

fn signature_shares_by_input(
    shares: &[FrostSignatureShare],
    public_key_package_hash: &str,
    spend_plan_hash: &str,
    input_sighashes: &[String],
) -> Result<BTreeMap<usize, BTreeMap<frost::Identifier, FrostSignatureShare>>, VaultFrostError> {
    let public_key_package_hash = normalize_hash_hex(public_key_package_hash)
        .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?;
    let spend_plan_hash = normalize_hash_hex(spend_plan_hash).map_err(|_| {
        VaultFrostError::RealFrostInvalidSigningCommitment(spend_plan_hash.to_string())
    })?;
    let mut by_input: BTreeMap<usize, BTreeMap<frost::Identifier, FrostSignatureShare>> =
        BTreeMap::new();
    for share in shares {
        let share = share
            .clone()
            .normalized()
            .map_err(|err| VaultFrostError::VerifiedShareRejected(err.to_string()))?;
        if share.public_key_package_hash != public_key_package_hash
            || share.spend_plan_hash != spend_plan_hash
            || share.input_index >= input_sighashes.len()
            || share.sighash_hex != input_sighashes[share.input_index]
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                share.signer_id,
            ));
        }
        let identifier = identifier_from_hex(&share.frost_identifier_hex)?;
        let input_index = share.input_index;
        if by_input
            .entry(input_index)
            .or_default()
            .insert(identifier, share)
            .is_some()
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                "duplicate signature share".to_string(),
            ));
        }
    }
    Ok(by_input)
}

fn validate_commitment_share_signer_metadata(
    commitments: &[RealFrostSigningCommitment],
    shares: &[FrostSignatureShare],
    public_key_package_hash: &str,
    spend_plan_hash: &str,
    input_sighashes: &[String],
    transcript_signer_by_identifier: Option<&BTreeMap<String, String>>,
) -> Result<(), VaultFrostError> {
    let public_key_package_hash = normalize_hash_hex(public_key_package_hash)
        .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?;
    let spend_plan_hash = normalize_hash_hex(spend_plan_hash).map_err(|_| {
        VaultFrostError::RealFrostInvalidSigningCommitment(spend_plan_hash.to_string())
    })?;
    let mut commitment_signer_by_input_identifier = BTreeMap::new();
    let mut commitment_signer_ids_by_input: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for commitment in commitments {
        let signer_id =
            normalize_dkg_signer_id(&commitment.signer_id).map_err(dkg_transport_error)?;
        if normalize_hash_hex(&commitment.public_key_package_hash)
            .map_err(|_| VaultFrostError::RealFrostPublicKeyPackageHashMismatch)?
            != public_key_package_hash
            || normalize_hash_hex(&commitment.spend_plan_hash).map_err(|_| {
                VaultFrostError::RealFrostInvalidSigningCommitment(signer_id.clone())
            })? != spend_plan_hash
            || commitment.input_index >= input_sighashes.len()
            || normalize_hash_hex(&commitment.sighash_hex)
                .map_err(VaultFrostError::InvalidSighashHex)?
                != input_sighashes[commitment.input_index]
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
        let identifier = identifier_from_hex(&commitment.frost_identifier_hex)?;
        let identifier_hex = identifier_hex(&identifier);
        if let Some(transcript_signer_by_identifier) = transcript_signer_by_identifier {
            let expected_signer_id = transcript_signer_by_identifier
                .get(&identifier_hex)
                .ok_or_else(|| {
                    VaultFrostError::RealFrostInvalidSigningCommitment(signer_id.clone())
                })?;
            if expected_signer_id != &signer_id {
                return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                    signer_id,
                ));
            }
        }
        if !commitment_signer_ids_by_input
            .entry(commitment.input_index)
            .or_default()
            .insert(signer_id.clone())
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
        if commitment_signer_by_input_identifier
            .insert((commitment.input_index, identifier), signer_id.clone())
            .is_some()
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
    }

    let mut share_signer_ids_by_input: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    for share in shares {
        let share = share
            .clone()
            .normalized()
            .map_err(|err| VaultFrostError::VerifiedShareRejected(err.to_string()))?;
        let signer_id = normalize_dkg_signer_id(&share.signer_id).map_err(dkg_transport_error)?;
        let identifier = identifier_from_hex(&share.frost_identifier_hex)?;
        let identifier_hex = identifier_hex(&identifier);
        if let Some(transcript_signer_by_identifier) = transcript_signer_by_identifier {
            let expected_signer_id = transcript_signer_by_identifier
                .get(&identifier_hex)
                .ok_or_else(|| {
                    VaultFrostError::RealFrostInvalidSigningCommitment(signer_id.clone())
                })?;
            if expected_signer_id != &signer_id {
                return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                    signer_id,
                ));
            }
        }
        let expected_signer_id = commitment_signer_by_input_identifier
            .get(&(share.input_index, identifier))
            .ok_or_else(|| VaultFrostError::RealFrostInvalidSigningCommitment(signer_id.clone()))?;
        if expected_signer_id != &signer_id {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
        if !share_signer_ids_by_input
            .entry(share.input_index)
            .or_default()
            .insert(signer_id.clone())
        {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(
                signer_id,
            ));
        }
    }
    Ok(())
}

fn sign_vault_transaction_plan_with_real_frost(
    tx_plan: &VaultTransactionPlan,
    public_key_package: &frost::keys::PublicKeyPackage,
    public_key_package_hash: &str,
    internal_key_xonly: &str,
    commitments_by_input: &BTreeMap<
        usize,
        BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    >,
    shares_by_input: &BTreeMap<usize, BTreeMap<frost::Identifier, FrostSignatureShare>>,
) -> Result<FrostSignedVaultTransaction, VaultFrostError> {
    if tx_plan.psbt.inputs.len() != tx_plan.unsigned_tx.input.len() {
        return Err(VaultFrostError::PsbtInputCountMismatch {
            psbt_inputs: tx_plan.psbt.inputs.len(),
            tx_inputs: tx_plan.unsigned_tx.input.len(),
        });
    }
    for (input_index, input) in tx_plan.psbt.inputs.iter().enumerate() {
        let plan_key = input
            .tap_internal_key
            .map(|key| key.to_string())
            .ok_or(VaultFrostError::MissingTapInternalKey(input_index))?;
        if plan_key != internal_key_xonly {
            return Err(VaultFrostError::InvalidGroupXOnlyKey(format!(
                "PSBT input {input_index} internal key {plan_key} does not match FROST group key {internal_key_xonly}"
            )));
        }
    }
    let threshold = public_key_package
        .min_signers()
        .map(usize::from)
        .ok_or(VaultFrostError::RealFrostMissingPublicKeyPackage)?;
    let prevouts = tx_plan
        .psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(VaultFrostError::MissingWitnessUtxo(input_index))
        })
        .collect::<Result<Vec<TxOut>, _>>()?;
    let prevouts = Prevouts::All(prevouts.as_slice());
    let mut signed_tx = tx_plan.unsigned_tx.clone();
    let mut signed_inputs = Vec::with_capacity(signed_tx.input.len());

    for input_index in 0..signed_tx.input.len() {
        let sighash = {
            let mut cache = SighashCache::new(&tx_plan.unsigned_tx);
            cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
                .map_err(|err| VaultFrostError::TaprootSighash(err.to_string()))?
        };
        let sighash_bytes = sighash.to_byte_array();
        let sighash_hex = hex::encode(sighash_bytes);
        let signing_commitments = commitments_by_input.get(&input_index).ok_or(
            VaultFrostError::RealFrostMissingSigningCommitments(input_index),
        )?;
        let shares = shares_by_input.get(&input_index).ok_or(
            VaultFrostError::RealFrostMissingSigningCommitments(input_index),
        )?;
        if signing_commitments.len() != shares.len() {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(format!(
                "input {input_index} commitment/share signer set mismatch"
            )));
        }
        if signing_commitments.len() < threshold {
            return Err(VaultFrostError::NotEnoughKeyPackages {
                threshold,
                available: signing_commitments.len(),
            });
        }
        if signing_commitments.keys().ne(shares.keys()) {
            return Err(VaultFrostError::RealFrostInvalidSigningCommitment(format!(
                "input {input_index} commitment/share signer set mismatch"
            )));
        }
        let signing_package =
            frost::SigningPackage::new(signing_commitments.clone(), &sighash_bytes);
        let mut signature_shares = BTreeMap::new();
        for (identifier, share) in shares {
            let verified =
                verify_frost_signature_share_for_input(FrostSignatureShareVerificationRequest {
                    signer_id: share.signer_id.clone(),
                    identifier: *identifier,
                    expected_public_key_package_hash: public_key_package_hash.to_string(),
                    spend_plan_hash: tx_plan.spend_plan_hash.clone(),
                    input_index,
                    sighash_hex: sighash_hex.clone(),
                    signature_share_hex: share.signature_share_hex.clone(),
                    signing_package: &signing_package,
                    public_key_package,
                })?;
            let share_bytes = hex::decode(&verified.share().signature_share_hex)
                .map_err(|err| VaultFrostError::InvalidSignatureShareHex(err.to_string()))?;
            let signature_share =
                frost::round2::SignatureShare::deserialize(&share_bytes).map_err(frost_error)?;
            signature_shares.insert(*identifier, signature_share);
        }
        let group_signature = frost::aggregate_with_tweak(
            &signing_package,
            &signature_shares,
            public_key_package,
            None,
        )
        .map_err(frost_error)?;
        let signature_bytes: [u8; 64] = group_signature
            .serialize()
            .map_err(frost_error)?
            .try_into()
            .map_err(|_| {
                VaultFrostError::InvalidAggregateSignature("expected 64 bytes".to_string())
            })?;
        verify_taproot_signature(internal_key_xonly, &sighash_bytes, &signature_bytes)?;
        let schnorr_signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&signature_bytes)
                .map_err(|err| VaultFrostError::InvalidAggregateSignature(err.to_string()))?;
        let taproot_signature = taproot::Signature {
            signature: schnorr_signature,
            sighash_type: TapSighashType::Default,
        };
        signed_tx.input[input_index].witness = Witness::p2tr_key_spend(&taproot_signature);
        signed_inputs.push(FrostSignedInput {
            input_index,
            sighash_hex,
            signature_hex: hex::encode(signature_bytes),
        });
    }

    Ok(FrostSignedVaultTransaction {
        spend_plan_hash: tx_plan.spend_plan_hash.clone(),
        internal_key_xonly: internal_key_xonly.to_string(),
        signed_tx,
        signed_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        threshold_67_percent, vault_script_pubkey_hex, VaultEpoch, VaultInput, VaultSigningSession,
        VaultSpendPlan,
    };
    use crate::vault_tx::{build_vault_psbt, vault_input_sighashes};
    use chrono::{TimeZone, Utc};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn epoch(epoch_id: u64, signer_count: usize, frost_group_key_xonly: &str) -> VaultEpoch {
        let frost_signer_bindings = (0..signer_count)
            .map(|idx| DkgSignerBinding {
                signer_id: format!("signer-{idx:02}"),
                frost_identifier_hex: participant_frost_identifier_hex(
                    u16::try_from(idx + 1).unwrap(),
                )
                .unwrap(),
            })
            .collect();
        VaultEpoch {
            epoch_id,
            starts_at: Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap(),
            signer_ids: (0..signer_count)
                .map(|idx| format!("signer-{idx:02}"))
                .collect(),
            threshold: threshold_67_percent(signer_count),
            frost_group_key_xonly: Some(frost_group_key_xonly.to_string()),
            dkg_transcript_hash: Some("demo".to_string()),
            dkg_public_key_package_hash: Some("99".repeat(32)),
            frost_signer_bindings,
        }
    }

    fn input(amount_sats: u64, frost_group_key_xonly: &str) -> VaultInput {
        VaultInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats,
            confirmations: 144,
            script_pubkey_hex: vault_script_pubkey_hex(frost_group_key_xonly).unwrap(),
        }
    }

    fn demo_xonly_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);
        keypair.x_only_public_key().0.to_string()
    }

    #[test]
    fn frost_group_key_derives_even_y_xonly_internal_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let key_set = generate_trusted_dealer_test_key_set(4, 3, &mut rng).unwrap();

        let internal_key = key_set.internal_key_xonly_hex().unwrap();

        assert_eq!(internal_key.len(), 64);
        XOnlyPublicKey::from_str(&internal_key).unwrap();
    }

    #[test]
    fn simulated_dkg_keyset_signs_taproot_vault_rotation_psbt() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let key_set = generate_simulated_dkg_frost_key_set(4, 3, &mut rng).unwrap();
        let current_key = key_set.internal_key_xonly_hex().unwrap();
        let current = epoch(20, 4, &current_key);
        let next = epoch(21, 4, &demo_xonly_key(3));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();

        let signed =
            sign_vault_spend_plan_with_simulated_keyset(&plan, &key_set, &mut rng).unwrap();

        assert_eq!(signed.spend_plan_hash, plan.plan_hash());
        assert_eq!(signed.signed_inputs.len(), 1);
        assert_eq!(signed.signed_inputs[0].signature_hex.len(), 128);
        assert_eq!(signed.signed_tx.input[0].witness.len(), 1);
    }

    #[test]
    fn demo_frost_keyset_signs_taproot_vault_rotation_psbt() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let key_set = generate_trusted_dealer_test_key_set(4, 3, &mut rng).unwrap();
        let current_key = key_set.internal_key_xonly_hex().unwrap();
        let current = epoch(10, 4, &current_key);
        let next = epoch(11, 4, &demo_xonly_key(2));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();

        let signed =
            sign_vault_spend_plan_with_simulated_keyset(&plan, &key_set, &mut rng).unwrap();

        assert_eq!(signed.spend_plan_hash, plan.plan_hash());
        assert_eq!(signed.signed_inputs.len(), 1);
        assert_eq!(signed.signed_inputs[0].signature_hex.len(), 128);
        assert_eq!(signed.signed_tx.input[0].witness.len(), 1);
    }

    #[test]
    fn verified_frost_signature_shares_can_satisfy_vault_session() {
        let mut rng = ChaCha20Rng::seed_from_u64(14);
        let key_set = generate_simulated_dkg_frost_key_set(4, 3, &mut rng).unwrap();
        let current_key = key_set.internal_key_xonly_hex().unwrap();
        let mut current = epoch(40, 4, &current_key);
        let transcript = key_set
            .simulated_transcript(40, current.signer_ids.clone(), "55".repeat(32))
            .unwrap();
        current.attach_dkg_transcript(transcript).unwrap();
        let next = epoch(41, 4, &demo_xonly_key(4));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();
        let tx_plan = build_vault_psbt(&plan).unwrap();
        let input_sighashes = vault_input_sighashes(&tx_plan).unwrap();
        let sighash = input_sighashes[0].clone();
        let sighash_bytes: [u8; 32] = hex::decode(&sighash).unwrap().try_into().unwrap();
        let selected_signers = key_set
            .key_packages
            .keys()
            .take(usize::from(key_set.threshold))
            .copied()
            .collect::<Vec<_>>();
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for identifier in &selected_signers {
            let key_package = &key_set.key_packages[identifier];
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(*identifier, nonces);
            commitments_map.insert(*identifier, commitments);
        }
        let signing_package = frost::SigningPackage::new(commitments_map, &sighash_bytes);
        let mut session =
            VaultSigningSession::new(&current, plan.clone(), input_sighashes).unwrap();

        for (idx, identifier) in selected_signers.iter().enumerate() {
            let key_package = &key_set.key_packages[identifier];
            let signature_share = frost::round2::sign_with_tweak(
                &signing_package,
                &nonces_map[identifier],
                key_package,
                None,
            )
            .unwrap();
            let verified =
                verify_frost_signature_share_for_input(FrostSignatureShareVerificationRequest {
                    signer_id: format!("signer-{idx:02}"),
                    identifier: *identifier,
                    expected_public_key_package_hash: current
                        .required_public_key_package_hash()
                        .unwrap(),
                    spend_plan_hash: plan.plan_hash(),
                    input_index: 0,
                    sighash_hex: sighash.clone(),
                    signature_share_hex: hex::encode(signature_share.serialize()),
                    signing_package: &signing_package,
                    public_key_package: key_set.public_key_package(),
                })
                .unwrap();
            session.add_verified_signature_share(verified).unwrap();
        }

        assert!(session.is_ready());
        assert_eq!(session.approval().unwrap().signature_shares.len(), 3);
    }

    #[test]
    fn verified_share_rejects_mismatched_claimed_sighash() {
        let mut rng = ChaCha20Rng::seed_from_u64(15);
        let key_set = generate_simulated_dkg_frost_key_set(4, 3, &mut rng).unwrap();
        let current_key = key_set.internal_key_xonly_hex().unwrap();
        let current = epoch(50, 4, &current_key);
        let next = epoch(51, 4, &demo_xonly_key(5));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();
        let tx_plan = build_vault_psbt(&plan).unwrap();
        let sighash = vault_input_sighashes(&tx_plan).unwrap()[0].clone();
        let sighash_bytes: [u8; 32] = hex::decode(&sighash).unwrap().try_into().unwrap();
        let selected_signers = key_set
            .key_packages
            .keys()
            .take(usize::from(key_set.threshold))
            .copied()
            .collect::<Vec<_>>();
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for identifier in &selected_signers {
            let key_package = &key_set.key_packages[identifier];
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(*identifier, nonces);
            commitments_map.insert(*identifier, commitments);
        }
        let signing_package = frost::SigningPackage::new(commitments_map, &sighash_bytes);
        let identifier = selected_signers[0];
        let key_package = &key_set.key_packages[&identifier];
        let signature_share = frost::round2::sign_with_tweak(
            &signing_package,
            &nonces_map[&identifier],
            key_package,
            None,
        )
        .unwrap();

        let err = verify_frost_signature_share_for_input(FrostSignatureShareVerificationRequest {
            signer_id: "signer-00".to_string(),
            identifier,
            expected_public_key_package_hash: key_set.dkg_roots().public_key_package_hash.clone(),
            spend_plan_hash: plan.plan_hash(),
            input_index: 0,
            sighash_hex: "aa".repeat(32),
            signature_share_hex: hex::encode(signature_share.serialize()),
            signing_package: &signing_package,
            public_key_package: key_set.public_key_package(),
        })
        .unwrap_err();

        assert!(matches!(
            err,
            VaultFrostError::SigningPackageSighashMismatch { .. }
        ));
    }

    #[test]
    fn verified_share_rejects_uncommitted_public_key_package_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(16);
        let key_set = generate_simulated_dkg_frost_key_set(4, 3, &mut rng).unwrap();
        let current_key = key_set.internal_key_xonly_hex().unwrap();
        let current = epoch(60, 4, &current_key);
        let next = epoch(61, 4, &demo_xonly_key(6));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();
        let tx_plan = build_vault_psbt(&plan).unwrap();
        let sighash = vault_input_sighashes(&tx_plan).unwrap()[0].clone();
        let sighash_bytes: [u8; 32] = hex::decode(&sighash).unwrap().try_into().unwrap();
        let selected_signers = key_set
            .key_packages
            .keys()
            .take(usize::from(key_set.threshold))
            .copied()
            .collect::<Vec<_>>();
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for identifier in &selected_signers {
            let key_package = &key_set.key_packages[identifier];
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(*identifier, nonces);
            commitments_map.insert(*identifier, commitments);
        }
        let signing_package = frost::SigningPackage::new(commitments_map, &sighash_bytes);
        let identifier = selected_signers[0];
        let key_package = &key_set.key_packages[&identifier];
        let signature_share = frost::round2::sign_with_tweak(
            &signing_package,
            &nonces_map[&identifier],
            key_package,
            None,
        )
        .unwrap();

        let err = verify_frost_signature_share_for_input(FrostSignatureShareVerificationRequest {
            signer_id: "signer-00".to_string(),
            identifier,
            expected_public_key_package_hash: "aa".repeat(32),
            spend_plan_hash: plan.plan_hash(),
            input_index: 0,
            sighash_hex: sighash,
            signature_share_hex: hex::encode(signature_share.serialize()),
            signing_package: &signing_package,
            public_key_package: key_set.public_key_package(),
        })
        .unwrap_err();

        assert!(matches!(
            err,
            VaultFrostError::PublicKeyPackageHashMismatch { .. }
        ));
    }

    #[test]
    fn local_peer_dkg_ceremony_builds_attachable_transcript_and_signs() {
        let mut rng = ChaCha20Rng::seed_from_u64(17);
        let signer_ids = (0..4)
            .map(|idx| format!("signer-{idx:02}"))
            .collect::<Vec<_>>();
        let ceremony =
            run_local_peer_dkg_ceremony(70, signer_ids, 3, "66".repeat(32), &mut rng).unwrap();

        assert_eq!(ceremony.artifacts.round1_broadcasts.len(), 4);
        assert_eq!(ceremony.artifacts.round2_direct_packages.len(), 12);
        assert_eq!(ceremony.artifacts.signer_acks.len(), 4);
        assert_eq!(
            ceremony.transcript.public_key_package_hash,
            ceremony.key_set.dkg_roots().public_key_package_hash
        );
        assert_eq!(
            ceremony.transcript.round1_packages_root,
            ceremony.key_set.dkg_roots().round1_packages_root
        );
        assert_eq!(
            ceremony.transcript.round2_packages_root,
            ceremony.key_set.dkg_roots().round2_packages_root
        );

        let current_key = ceremony.key_set.internal_key_xonly_hex().unwrap();
        let mut current = epoch(70, 4, &current_key);
        current
            .attach_dkg_transcript(ceremony.transcript.clone())
            .unwrap();
        let next = epoch(71, 4, &demo_xonly_key(7));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();
        let signed =
            sign_vault_spend_plan_with_simulated_keyset(&plan, &ceremony.key_set, &mut rng)
                .unwrap();

        assert_eq!(signed.spend_plan_hash, plan.plan_hash());
        assert_eq!(signed.signed_inputs.len(), 1);
        assert_eq!(signed.signed_tx.input[0].witness.len(), 1);
    }

    #[test]
    fn real_frost_signer_states_dkg_and_sign_vault_spend() {
        let mut rng = ChaCha20Rng::seed_from_u64(20);
        let epoch_id = 100;
        let signer_ids = (0..4)
            .map(|idx| format!("signer-{idx:02}"))
            .collect::<Vec<_>>();
        let mut auth_keypairs = Vec::new();
        let mut ecdh_secrets = Vec::new();
        let mut peers = Vec::new();
        for (idx, signer_id) in signer_ids.iter().enumerate() {
            let secp = bitcoin::key::Secp256k1::new();
            let auth_secret =
                bitcoin::secp256k1::SecretKey::from_slice(&[40 + idx as u8; 32]).unwrap();
            let ecdh_secret =
                bitcoin::secp256k1::SecretKey::from_slice(&[50 + idx as u8; 32]).unwrap();
            let auth_keypair = bitcoin::key::Keypair::from_secret_key(&secp, &auth_secret);
            let ecdh_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &ecdh_secret);
            peers.push(DkgPeerIdentity {
                signer_id: signer_id.clone(),
                auth_pubkey_xonly_hex: auth_keypair.x_only_public_key().0.to_string(),
                ecdh_pubkey_hex: ecdh_pubkey.to_string(),
            });
            auth_keypairs.push(auth_keypair);
            ecdh_secrets.push(ecdh_secret);
        }

        let mut round1_states = Vec::new();
        let mut round1_envelopes = Vec::new();
        for (idx, signer_id) in signer_ids.iter().enumerate() {
            let output = real_frost_dkg_round1(
                epoch_id,
                signer_id.clone(),
                signer_ids.clone(),
                "77".repeat(32),
                &mut rng,
            )
            .unwrap();
            let mut envelope = DkgMessageEnvelope::unsigned(
                output.state.session_id.clone(),
                epoch_id,
                1,
                peers[idx].clone(),
                None,
                DkgMessageBody::Round1Broadcast(output.body),
            )
            .unwrap();
            envelope.sign(&auth_keypairs[idx]).unwrap();
            round1_states.push(output.state);
            round1_envelopes.push(envelope);
        }

        let mut noncanonical_round1_envelopes = round1_envelopes.clone();
        noncanonical_round1_envelopes[0].sender.signer_id = "Signer-00".to_string();
        noncanonical_round1_envelopes[0].signature_hex = None;
        noncanonical_round1_envelopes[0]
            .sign(&auth_keypairs[0])
            .unwrap();
        let err = real_frost_dkg_round2(
            round1_states[1].clone(),
            &noncanonical_round1_envelopes,
            &peers[1],
            &peers,
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, VaultFrostError::RealDkgInvalidSender(_)));

        let mut round2_states = Vec::new();
        let mut round2_envelopes = Vec::new();
        for (idx, state) in round1_states.into_iter().enumerate() {
            let output =
                real_frost_dkg_round2(state, &round1_envelopes, &peers[idx], &peers, &mut rng)
                    .unwrap();
            for direct in output.direct_messages {
                let mut envelope = DkgMessageEnvelope::unsigned(
                    output.state.session_id.clone(),
                    epoch_id,
                    2,
                    peers[idx].clone(),
                    Some(direct.receiver_signer_id),
                    DkgMessageBody::Round2Direct(direct.body),
                )
                .unwrap();
                envelope.sign(&auth_keypairs[idx]).unwrap();
                round2_envelopes.push(envelope);
            }
            round2_states.push(output.state);
        }

        let mut noncanonical_round2_envelopes = round2_envelopes.clone();
        let noncanonical_round2 = noncanonical_round2_envelopes
            .iter_mut()
            .find(|envelope| envelope.receiver_signer_id.as_deref() == Some("signer-00"))
            .unwrap();
        noncanonical_round2.receiver_signer_id = Some("Signer-00".to_string());
        if let DkgMessageBody::Round2Direct(body) = &mut noncanonical_round2.body {
            body.receiver_signer_id = "Signer-00".to_string();
        }
        let noncanonical_sender_idx = signer_ids
            .iter()
            .position(|signer_id| signer_id == &noncanonical_round2.sender.signer_id)
            .unwrap();
        noncanonical_round2.signature_hex = None;
        noncanonical_round2
            .sign(&auth_keypairs[noncanonical_sender_idx])
            .unwrap();
        let err = real_frost_dkg_finalize(
            round2_states[0].clone(),
            &round1_envelopes,
            &noncanonical_round2_envelopes,
            &peers[0],
            &peers,
            &ecdh_secrets[0],
        )
        .unwrap_err();
        assert!(matches!(err, VaultFrostError::RealDkgInvalidReceiver(_)));

        let mut finalized_states = Vec::new();
        let mut ack_envelopes = Vec::new();
        for (idx, state) in round2_states.into_iter().enumerate() {
            let output = real_frost_dkg_finalize(
                state,
                &round1_envelopes,
                &round2_envelopes,
                &peers[idx],
                &peers,
                &ecdh_secrets[idx],
            )
            .unwrap();
            let mut envelope = DkgMessageEnvelope::unsigned(
                output.state.session_id.clone(),
                epoch_id,
                3,
                peers[idx].clone(),
                None,
                DkgMessageBody::SignerAck(output.body),
            )
            .unwrap();
            envelope.sign(&auth_keypairs[idx]).unwrap();
            ack_envelopes.push(envelope);
            finalized_states.push(output.state);
        }

        let transcript = real_frost_dkg_transcript(
            &finalized_states[0],
            &round1_envelopes,
            &round2_envelopes,
            &ack_envelopes,
            &peers,
        )
        .unwrap();
        let transcript_for_aggregate = transcript.clone();
        let current_key = transcript.frost_group_key_xonly.clone();
        let mut current = epoch(epoch_id, 4, &current_key);
        current.attach_dkg_transcript(transcript).unwrap();
        let next = epoch(epoch_id + 1, 4, &demo_xonly_key(8));
        let plan =
            VaultSpendPlan::rotation(&current, &next, vec![input(100_000, &current_key)], 1_000)
                .unwrap();
        let tx_plan = build_vault_psbt(&plan).unwrap();
        let input_sighashes = vault_input_sighashes(&tx_plan).unwrap();

        let mut selected_states = finalized_states.into_iter().take(3).collect::<Vec<_>>();
        let mut commitments = Vec::new();
        for state in selected_states.iter_mut() {
            let output = real_frost_create_nonce_commitments(
                state.clone(),
                &plan,
                input_sighashes.clone(),
                &mut rng,
            )
            .unwrap();
            *state = output.state;
            commitments.extend(output.commitments);
        }

        let public_key_package_hex = selected_states[0].public_key_package_hex.clone().unwrap();
        let mut shares = Vec::new();
        let mut duplicate_nonce_state = selected_states[0].clone();
        duplicate_nonce_state
            .pending_nonces
            .push(duplicate_nonce_state.pending_nonces[0].clone());
        let err = real_frost_sign_spend_plan(
            duplicate_nonce_state,
            &plan,
            input_sighashes.clone(),
            &commitments,
        )
        .unwrap_err();
        assert!(matches!(err, VaultFrostError::InvalidRealFrostState(_)));
        let mut mismatched_own_commitments = commitments.clone();
        let first_signer_id = selected_states[0].signer_id.clone();
        let other_commitment_hex = commitments
            .iter()
            .find(|commitment| commitment.signer_id != first_signer_id)
            .unwrap()
            .signing_commitments_hex
            .clone();
        mismatched_own_commitments
            .iter_mut()
            .find(|commitment| commitment.signer_id == first_signer_id)
            .unwrap()
            .signing_commitments_hex = other_commitment_hex;
        let err = real_frost_sign_spend_plan(
            selected_states[0].clone(),
            &plan,
            input_sighashes.clone(),
            &mismatched_own_commitments,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VaultFrostError::RealFrostInvalidSigningCommitment(_)
        ));
        for state in selected_states.iter_mut() {
            let (updated_state, signer_shares) = real_frost_sign_spend_plan(
                state.clone(),
                &plan,
                input_sighashes.clone(),
                &commitments,
            )
            .unwrap();
            assert!(updated_state.pending_nonces.is_empty());
            *state = updated_state;
            shares.extend(signer_shares);
        }

        let signed = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &transcript_for_aggregate,
            &public_key_package_hex,
            &commitments,
            &shares,
        )
        .unwrap();

        assert_eq!(signed.spend_plan_hash, plan.plan_hash());
        assert_eq!(signed.signed_inputs.len(), 1);
        assert_eq!(signed.signed_inputs[0].signature_hex.len(), 128);
        assert_eq!(signed.signed_tx.input[0].witness.len(), 1);

        let mut wrong_transcript = transcript_for_aggregate.clone();
        wrong_transcript.public_key_package_hash = "aa".repeat(32);
        let err = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &wrong_transcript,
            &public_key_package_hex,
            &commitments,
            &shares,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VaultFrostError::RealFrostPublicKeyPackageHashMismatch
        ));

        let mut mislabeled_shares = shares.clone();
        mislabeled_shares[0].signer_id = "signer-03".to_string();
        let err = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &transcript_for_aggregate,
            &public_key_package_hex,
            &commitments,
            &mislabeled_shares,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VaultFrostError::RealFrostInvalidSigningCommitment(_)
        ));

        let mut unsafe_commitments = commitments.clone();
        unsafe_commitments[0].signer_id = "../signer-00".to_string();
        let err = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &transcript_for_aggregate,
            &public_key_package_hex,
            &unsafe_commitments,
            &shares,
        )
        .unwrap_err();
        assert!(matches!(err, VaultFrostError::Frost(_)));

        let mut unsafe_shares = shares.clone();
        unsafe_shares[0].signer_id = "../signer-00".to_string();
        let err = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &transcript_for_aggregate,
            &public_key_package_hex,
            &commitments,
            &unsafe_shares,
        )
        .unwrap_err();
        assert!(matches!(err, VaultFrostError::VerifiedShareRejected(_)));

        let mut relabeled_commitments = commitments.clone();
        let mut relabeled_shares = shares.clone();
        relabeled_commitments[0].signer_id = "signer-03".to_string();
        relabeled_shares[0].signer_id = "signer-03".to_string();
        let err = aggregate_real_frost_vault_transaction_with_transcript(
            &plan,
            &transcript_for_aggregate,
            &public_key_package_hex,
            &relabeled_commitments,
            &relabeled_shares,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VaultFrostError::RealFrostInvalidSigningCommitment(_)
        ));
    }

    #[test]
    fn local_peer_dkg_rejects_duplicate_signer_ids() {
        let mut rng = ChaCha20Rng::seed_from_u64(18);
        let err = run_local_peer_dkg_ceremony(
            80,
            vec![
                "signer-00".to_string(),
                "signer-00".to_string(),
                "signer-01".to_string(),
            ],
            2,
            "66".repeat(32),
            &mut rng,
        )
        .unwrap_err();

        assert!(matches!(err, VaultFrostError::DuplicateDkgSignerId { .. }));
    }

    #[test]
    fn local_peer_dkg_rejects_unsafe_signer_ids() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let err = run_local_peer_dkg_ceremony(
            81,
            vec![
                "signer-00".to_string(),
                "../signer-01".to_string(),
                "signer-02".to_string(),
            ],
            3,
            "66".repeat(32),
            &mut rng,
        )
        .unwrap_err();

        assert!(matches!(err, VaultFrostError::Frost(_)));
    }

    #[test]
    fn real_frost_dkg_rejects_unsafe_local_signer_id() {
        let err = RealFrostDkgState::new(
            82,
            "../signer-00".to_string(),
            vec!["signer-00".to_string(), "signer-01".to_string()],
            "66".repeat(32),
        )
        .unwrap_err();

        assert!(matches!(err, VaultFrostError::Frost(_)));
    }

    #[test]
    fn real_frost_state_reload_rejects_unsafe_local_signer_id() {
        let mut state = RealFrostDkgState::new(
            83,
            "signer-00".to_string(),
            vec!["signer-00".to_string(), "signer-01".to_string()],
            "66".repeat(32),
        )
        .unwrap();
        state.signer_id = "../signer-00".to_string();

        let err = state.normalized().unwrap_err();

        assert!(matches!(err, VaultFrostError::Frost(_)));
    }

    #[test]
    fn real_frost_dkg_session_id_binds_recovery_data_hash() {
        let signer_ids = vec!["signer-00".to_string(), "signer-01".to_string()];
        let state_a = RealFrostDkgState::new(
            84,
            "signer-00".to_string(),
            signer_ids.clone(),
            "aa".repeat(32),
        )
        .unwrap();
        let state_b =
            RealFrostDkgState::new(84, "signer-00".to_string(), signer_ids, "bb".repeat(32))
                .unwrap();

        assert_ne!(state_a.session_id, state_b.session_id);
    }

    #[test]
    fn local_peer_dkg_enforces_dynamic_threshold() {
        let mut rng = ChaCha20Rng::seed_from_u64(19);
        let signer_ids = (0..4)
            .map(|idx| format!("signer-{idx:02}"))
            .collect::<Vec<_>>();
        let err =
            run_local_peer_dkg_ceremony(90, signer_ids, 2, "66".repeat(32), &mut rng).unwrap_err();

        assert!(matches!(err, VaultFrostError::InvalidDkgThreshold { .. }));
    }

    #[test]
    fn simulated_dkg_exposes_transcript_roots_for_epoch_attachment() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let key_set = generate_simulated_dkg_frost_key_set(4, 3, &mut rng).unwrap();
        let signer_ids = (0..4)
            .map(|idx| format!("signer-{idx:02}"))
            .collect::<Vec<_>>();

        let transcript = key_set
            .simulated_transcript(30, signer_ids.clone(), "55".repeat(32))
            .unwrap();

        assert_eq!(transcript.signer_ids, signer_ids);
        assert_eq!(transcript.signer_bindings.len(), 4);
        assert_eq!(transcript.signer_bindings[0].signer_id, "signer-00");
        assert_eq!(transcript.signer_bindings[0].frost_identifier_hex.len(), 64);
        assert_eq!(transcript.public_key_package_hash.len(), 64);
        assert_eq!(transcript.round1_packages_root.len(), 64);
        assert_eq!(transcript.round2_packages_root.len(), 64);
        assert_eq!(transcript.signer_ack_root.len(), 64);
    }
}
