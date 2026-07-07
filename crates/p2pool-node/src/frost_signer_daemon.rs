use anyhow::{anyhow, bail, Context, Result};
use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
use pohw_core::dkg_transport::{
    decrypt_round2_package, dkg_package_hash, DkgMessageBody, DkgMessageEnvelope, DkgPeerIdentity,
};
use pohw_core::vault::DkgTranscript;
use pohw_core::vault_frost::{
    participant_frost_identifier_hex, real_frost_dkg_finalize, real_frost_dkg_round1,
    real_frost_dkg_round2, real_frost_dkg_transcript, RealFrostDkgState,
};
use pohw_core::{canonical_json, hash_hex, sha256_tagged};
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const MAX_PRIVATE_JSON_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct RunFrostSignerConfig {
    pub datadir: PathBuf,
    pub bind_addr: SocketAddr,
    pub allow_non_loopback: bool,
    pub peer_addrs: Vec<SocketAddr>,
    pub peer: DkgPeerIdentity,
    pub peers: Vec<DkgPeerIdentity>,
    pub signer_ids: Vec<String>,
    pub epoch_id: u64,
    pub recovery_data_hash: String,
    pub auth_keypair: Keypair,
    pub ecdh_secret_key: SecretKey,
    pub sync_interval: Duration,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub once: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignerStatus {
    pub signer_id: String,
    pub epoch_id: u64,
    pub session_id: String,
    pub threshold: usize,
    pub signer_count: usize,
    pub signer_ids: Vec<String>,
    pub peer_count: usize,
    pub inbox_envelopes: usize,
    pub outbox_envelopes: usize,
    pub known_round1: usize,
    pub known_round2: usize,
    pub known_acks: usize,
    pub round1_ready: bool,
    pub round2_ready: bool,
    pub finalized: bool,
    pub transcript_ready: bool,
    pub frost_group_key_xonly: Option<String>,
    pub public_key_package_hash: Option<String>,
    pub transcript_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FrostSignerRequest {
    SubmitDkgEnvelope { envelope: Box<DkgMessageEnvelope> },
    Status,
    PeerIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FrostSignerResponse {
    ok: bool,
    accepted: bool,
    envelope_hash: Option<String>,
    status: Option<FrostSignerStatus>,
    peer: Option<DkgPeerIdentity>,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignerPaths {
    base_dir: PathBuf,
    inbox_dir: PathBuf,
    outbox_dir: PathBuf,
    state_file: PathBuf,
    peer_file: PathBuf,
    transcript_file: PathBuf,
}

#[derive(Debug, Default)]
struct EnvelopeCounts {
    round1_senders: BTreeSet<String>,
    round2_pairs: BTreeSet<(String, String)>,
    ack_senders: BTreeSet<String>,
}

#[derive(Debug)]
struct FrostSignerDaemon {
    config: RunFrostSignerConfig,
    paths: SignerPaths,
    expected_session_id: String,
    signer_ids: Vec<String>,
}

pub async fn run_frost_signer(config: RunFrostSignerConfig) -> Result<FrostSignerStatus> {
    validate_bind_policy(config.bind_addr, config.allow_non_loopback)?;
    let max_connections = config.max_connections.max(1);
    let sync_interval = config.sync_interval.max(Duration::from_millis(250));
    let max_frame_bytes = config.max_frame_bytes.max(1024);
    let peer_addrs = config.peer_addrs.clone();
    let bind_addr = config.bind_addr;
    let once = config.once;

    let mut daemon = FrostSignerDaemon::new(config)?;
    let status = daemon.advance()?;

    if once {
        return Ok(status);
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind FROST signer daemon on {bind_addr}"))?;
    eprintln!(
        "FROST signer daemon listening on {bind_addr} for signer {} epoch {}",
        status.signer_id, status.epoch_id
    );

    let daemon = Arc::new(Mutex::new(daemon));
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let mut ticker = tokio::time::interval(sync_interval);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, remote_addr) = accept_result.context("failed to accept FROST signer connection")?;
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(stream);
                        continue;
                    }
                };
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection(daemon, stream, max_frame_bytes).await {
                        eprintln!("FROST signer request from {remote_addr} failed: {err:#}");
                    }
                });
            }
            _ = ticker.tick() => {
                {
                    let mut daemon = daemon.lock().await;
                    if let Err(err) = daemon.advance() {
                        eprintln!("FROST signer advance failed: {err:#}");
                    }
                }
                for peer_addr in &peer_addrs {
                    let envelopes = {
                        let daemon = daemon.lock().await;
                        match daemon.load_outbox_envelopes() {
                            Ok(envelopes) => envelopes,
                            Err(err) => {
                                eprintln!("FROST signer could not load outbox for sync: {err:#}");
                                continue;
                            }
                        }
                    };
                    for envelope in envelopes {
                        if let Err(err) =
                            submit_envelope_to_peer(*peer_addr, &envelope, max_frame_bytes).await
                        {
                            eprintln!("FROST signer peer sync to {peer_addr} failed: {err:#}");
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl FrostSignerDaemon {
    fn new(config: RunFrostSignerConfig) -> Result<Self> {
        let state = RealFrostDkgState::new(
            config.epoch_id,
            config.peer.signer_id.clone(),
            config.signer_ids.clone(),
            config.recovery_data_hash.clone(),
        )
        .context("invalid FROST signer epoch configuration")?;
        let state = state
            .normalized()
            .context("invalid normalized FROST signer epoch configuration")?;
        let peer = config
            .peer
            .clone()
            .normalized()
            .map_err(|err| anyhow!("invalid own DKG peer identity: {err}"))?;
        if peer.signer_id != state.signer_id {
            bail!(
                "own peer signer {} does not match configured signer {}",
                peer.signer_id,
                state.signer_id
            );
        }
        if peer.auth_pubkey_xonly_hex != config.auth_keypair.x_only_public_key().0.to_string() {
            bail!("own peer auth pubkey does not match auth secret key");
        }
        let expected_ecdh_pubkey =
            PublicKey::from_secret_key(&bitcoin::key::Secp256k1::new(), &config.ecdh_secret_key)
                .to_string();
        if peer.ecdh_pubkey_hex != expected_ecdh_pubkey {
            bail!("own peer ECDH pubkey does not match ECDH secret key");
        }
        let mut config = config;
        config.peer = peer;
        config.peers =
            normalize_and_validate_peers(&state.signer_ids, &config.peer, &config.peers)?;

        let paths = signer_paths(&config.datadir, state.epoch_id, &state.signer_id);
        prepare_private_dir(&paths.base_dir)?;
        prepare_private_dir(&paths.inbox_dir)?;
        prepare_private_dir(&paths.outbox_dir)?;

        let daemon = Self {
            config,
            paths,
            expected_session_id: state.session_id,
            signer_ids: state.signer_ids,
        };
        daemon.write_peer_identity()?;
        Ok(daemon)
    }

    fn advance(&mut self) -> Result<FrostSignerStatus> {
        let mut state = match self.read_state()? {
            Some(state) => state,
            None => self.initialize_round1()?,
        };

        if state.round1_secret_package_hex.is_some()
            && state.round2_secret_package_hex.is_none()
            && self.have_all_round1()?
        {
            state = self.create_round2(state)?;
        }

        if state.round2_secret_package_hex.is_some()
            && state.key_package_hex.is_none()
            && self.have_round2_for_own_signer()?
        {
            state = self.finalize_dkg(state)?;
        }

        if state.key_package_hex.is_some()
            && state.public_key_package_hex.is_some()
            && !self.paths.transcript_file.exists()
            && self.have_complete_transcript_inputs()?
        {
            self.create_transcript(&state)?;
        }

        self.status()
    }

    fn initialize_round1(&self) -> Result<RealFrostDkgState> {
        let output = real_frost_dkg_round1(
            self.config.epoch_id,
            self.config.peer.signer_id.clone(),
            self.config.signer_ids.clone(),
            self.config.recovery_data_hash.clone(),
            &mut OsRng,
        )
        .context("failed to create real FROST DKG round 1")?;
        if output.state.session_id != self.expected_session_id {
            bail!("generated DKG state has unexpected session id");
        }
        let mut envelope = DkgMessageEnvelope::unsigned(
            output.state.session_id.clone(),
            output.state.epoch_id,
            1,
            self.config.peer.clone(),
            None,
            DkgMessageBody::Round1Broadcast(output.body),
        )
        .context("failed to build round 1 DKG envelope")?;
        envelope
            .sign(&self.config.auth_keypair)
            .context("failed to sign round 1 DKG envelope")?;
        self.write_outbox_envelope(&envelope)?;
        self.write_state(&output.state)?;
        Ok(output.state)
    }

    fn create_round2(&self, state: RealFrostDkgState) -> Result<RealFrostDkgState> {
        let round1 = self.round1_envelopes()?;
        let output = real_frost_dkg_round2(
            state,
            &round1,
            &self.config.peer,
            &self.config.peers,
            &mut OsRng,
        )
        .context("failed to create real FROST DKG round 2")?;
        for direct in &output.direct_messages {
            let mut envelope = DkgMessageEnvelope::unsigned(
                output.state.session_id.clone(),
                output.state.epoch_id,
                2,
                self.config.peer.clone(),
                Some(direct.receiver_signer_id.clone()),
                DkgMessageBody::Round2Direct(direct.body.clone()),
            )
            .context("failed to build round 2 DKG envelope")?;
            envelope
                .sign(&self.config.auth_keypair)
                .context("failed to sign round 2 DKG envelope")?;
            self.write_outbox_envelope(&envelope)?;
        }
        self.write_state(&output.state)?;
        Ok(output.state)
    }

    fn finalize_dkg(&self, state: RealFrostDkgState) -> Result<RealFrostDkgState> {
        let output = real_frost_dkg_finalize(
            state,
            &self.round1_envelopes()?,
            &self.round2_envelopes()?,
            &self.config.peer,
            &self.config.peers,
            &self.config.ecdh_secret_key,
        )
        .context("failed to finalize real FROST DKG")?;
        let mut envelope = DkgMessageEnvelope::unsigned(
            output.state.session_id.clone(),
            output.state.epoch_id,
            3,
            self.config.peer.clone(),
            None,
            DkgMessageBody::SignerAck(output.body),
        )
        .context("failed to build DKG signer ack envelope")?;
        envelope
            .sign(&self.config.auth_keypair)
            .context("failed to sign DKG signer ack envelope")?;
        self.write_outbox_envelope(&envelope)?;
        self.write_state(&output.state)?;
        Ok(output.state)
    }

    fn create_transcript(&self, state: &RealFrostDkgState) -> Result<()> {
        let transcript = real_frost_dkg_transcript(
            state,
            &self.round1_envelopes()?,
            &self.round2_envelopes()?,
            &self.ack_envelopes()?,
            &self.config.peers,
        )
        .context("failed to create real FROST DKG transcript")?;
        write_private_json_file(&self.paths.transcript_file, &transcript)?;
        Ok(())
    }

    fn accept_envelope(&mut self, envelope: DkgMessageEnvelope) -> Result<(bool, String)> {
        self.validate_envelope(&envelope)?;
        let hash = dkg_envelope_hash(&envelope);
        if self.envelope_exists(&hash) {
            return Ok((false, hash));
        }
        self.reject_conflicting_logical_envelope(&envelope, &hash)?;
        let path = self.paths.inbox_dir.join(format!("{hash}.json"));
        write_new_json_file(&path, &envelope)?;
        Ok((true, hash))
    }

    fn validate_envelope(&self, envelope: &DkgMessageEnvelope) -> Result<()> {
        envelope
            .verify_signature()
            .map_err(|err| anyhow!("invalid DKG envelope signature: {err}"))?;
        if envelope.session_id != self.expected_session_id {
            bail!("DKG envelope is for another session");
        }
        if envelope.epoch_id != self.config.epoch_id {
            bail!("DKG envelope is for another epoch");
        }
        let sender = envelope
            .sender
            .clone()
            .normalized()
            .map_err(|err| anyhow!("invalid DKG envelope sender: {err}"))?;
        if sender != envelope.sender {
            bail!("DKG envelope sender identity is not canonical");
        }
        let Some(expected_peer) = self
            .config
            .peers
            .iter()
            .find(|peer| peer.signer_id == sender.signer_id)
        else {
            bail!(
                "DKG envelope sender {} is not in this epoch",
                sender.signer_id
            );
        };
        if expected_peer != &sender {
            bail!(
                "DKG envelope sender {} does not match trusted epoch peer identity",
                sender.signer_id
            );
        }
        match &envelope.body {
            DkgMessageBody::Round1Broadcast(body) => {
                if envelope.sequence != 1 || envelope.receiver_signer_id.is_some() {
                    bail!("round 1 DKG envelope has invalid routing");
                }
                self.validate_round1_body(&sender.signer_id, body)?;
            }
            DkgMessageBody::Round2Direct(body) => {
                let Some(receiver) = envelope.receiver_signer_id.as_ref() else {
                    bail!("round 2 DKG envelope is missing receiver");
                };
                if envelope.sequence != 2 || receiver != &body.receiver_signer_id {
                    bail!("round 2 DKG envelope has invalid routing");
                }
                if !self.signer_ids.contains(receiver) || receiver == &sender.signer_id {
                    bail!("round 2 DKG envelope receiver is not valid for this epoch");
                }
                self.validate_round2_body(&sender, receiver, body)?;
            }
            DkgMessageBody::SignerAck(body) => {
                if envelope.sequence != 3 || envelope.receiver_signer_id.is_some() {
                    bail!("signer ack DKG envelope has invalid routing");
                }
                self.validate_ack_body(&sender.signer_id, body)?;
            }
            DkgMessageBody::Complaint(_) => {
                bail!("DKG complaint messages are not supported by this daemon yet");
            }
        }
        Ok(())
    }

    fn reject_conflicting_logical_envelope(
        &self,
        envelope: &DkgMessageEnvelope,
        envelope_hash: &str,
    ) -> Result<()> {
        let key = logical_envelope_key(envelope)?;
        for existing in self.load_all_envelopes()? {
            if logical_envelope_key(&existing)? == key
                && dkg_envelope_hash(&existing) != envelope_hash
            {
                bail!(
                    "conflicting DKG envelope for signer {} sequence {} receiver {}",
                    envelope.sender.signer_id,
                    envelope.sequence,
                    envelope
                        .receiver_signer_id
                        .as_deref()
                        .unwrap_or("<broadcast>")
                );
            }
        }
        Ok(())
    }

    fn validate_round1_body(
        &self,
        sender_signer_id: &str,
        body: &pohw_core::dkg_transport::DkgRound1BroadcastBody,
    ) -> Result<()> {
        let expected_identifier = self.expected_frost_identifier(sender_signer_id)?;
        if body.frost_identifier_hex != expected_identifier {
            bail!("round 1 DKG envelope has wrong FROST identifier for sender");
        }
        let package_hash = normalize_hash_hex(&body.package_hash)
            .map_err(|_| anyhow!("round 1 DKG package hash is not 32-byte hex"))?;
        let package = decode_hex_blob(&body.package_hex, "round 1 DKG package")?;
        let actual_hash = dkg_package_hash(&package);
        if actual_hash != package_hash {
            bail!("round 1 DKG package hash does not match package bytes");
        }
        Ok(())
    }

    fn validate_round2_body(
        &self,
        sender: &DkgPeerIdentity,
        receiver_signer_id: &str,
        body: &pohw_core::dkg_transport::DkgRound2DirectBody,
    ) -> Result<()> {
        let expected_receiver_identifier = self.expected_frost_identifier(receiver_signer_id)?;
        if body.receiver_identifier_hex != expected_receiver_identifier {
            bail!("round 2 DKG envelope has wrong FROST identifier for receiver");
        }
        let package_hash = normalize_hash_hex(&body.package_hash)
            .map_err(|_| anyhow!("round 2 DKG package hash is not 32-byte hex"))?;
        validate_encrypted_payload_shape(&body.encrypted_package)?;
        if receiver_signer_id == self.config.peer.signer_id {
            decrypt_round2_package(
                &self.expected_session_id,
                self.config.epoch_id,
                sender,
                &self.config.peer,
                &self.config.ecdh_secret_key,
                &package_hash,
                &body.encrypted_package,
            )
            .context("round 2 DKG package for this signer does not decrypt")?;
        }
        Ok(())
    }

    fn validate_ack_body(
        &self,
        sender_signer_id: &str,
        body: &pohw_core::dkg_transport::DkgSignerAckBody,
    ) -> Result<()> {
        let expected_identifier = self.expected_frost_identifier(sender_signer_id)?;
        if body.frost_identifier_hex != expected_identifier {
            bail!("DKG signer ack has wrong FROST identifier for sender");
        }
        let public_key_package_hash = normalize_hash_hex(&body.public_key_package_hash)
            .map_err(|_| anyhow!("DKG signer ack public key package hash is not 32-byte hex"))?;
        if let Some(state) = self.read_state()? {
            if let Some(expected_hash) = state.public_key_package_hash {
                if public_key_package_hash != expected_hash {
                    bail!("DKG signer ack public key package hash does not match local finalized key package");
                }
            }
        }
        Ok(())
    }

    fn expected_frost_identifier(&self, signer_id: &str) -> Result<String> {
        let index = self
            .signer_ids
            .iter()
            .position(|candidate| candidate == signer_id)
            .ok_or_else(|| anyhow!("DKG signer {signer_id} is not in this epoch"))?;
        participant_frost_identifier_hex(
            u16::try_from(index + 1).context("too many DKG signers for FROST identifier")?,
        )
        .context("failed to derive expected FROST identifier")
    }

    fn status(&self) -> Result<FrostSignerStatus> {
        let state = self
            .read_state()?
            .ok_or_else(|| anyhow!("FROST signer state is missing"))?;
        let counts = self.envelope_counts()?;
        let transcript = self.read_transcript()?;
        Ok(FrostSignerStatus {
            signer_id: state.signer_id,
            epoch_id: state.epoch_id,
            session_id: state.session_id,
            threshold: state.threshold,
            signer_count: state.signer_ids.len(),
            signer_ids: state.signer_ids,
            peer_count: self.config.peers.len(),
            inbox_envelopes: count_json_files(&self.paths.inbox_dir)?,
            outbox_envelopes: count_json_files(&self.paths.outbox_dir)?,
            known_round1: counts.round1_senders.len(),
            known_round2: counts.round2_pairs.len(),
            known_acks: counts.ack_senders.len(),
            round1_ready: counts.round1_senders.len() == self.signer_ids.len(),
            round2_ready: has_all_round2_pairs(&counts.round2_pairs, &self.signer_ids),
            finalized: state.key_package_hex.is_some(),
            transcript_ready: transcript.is_some(),
            frost_group_key_xonly: state.frost_group_key_xonly,
            public_key_package_hash: state.public_key_package_hash,
            transcript_hash: transcript.map(|transcript| transcript.transcript_hash()),
        })
    }

    fn have_all_round1(&self) -> Result<bool> {
        Ok(self.envelope_counts()?.round1_senders.len() == self.signer_ids.len())
    }

    fn have_round2_for_own_signer(&self) -> Result<bool> {
        let counts = self.envelope_counts()?;
        Ok(self
            .signer_ids
            .iter()
            .filter(|signer_id| *signer_id != &self.config.peer.signer_id)
            .all(|sender| {
                counts
                    .round2_pairs
                    .contains(&(sender.clone(), self.config.peer.signer_id.clone()))
            }))
    }

    fn have_complete_transcript_inputs(&self) -> Result<bool> {
        let counts = self.envelope_counts()?;
        Ok(counts.round1_senders.len() == self.signer_ids.len()
            && has_all_round2_pairs(&counts.round2_pairs, &self.signer_ids)
            && counts.ack_senders.len() == self.signer_ids.len())
    }

    fn round1_envelopes(&self) -> Result<Vec<DkgMessageEnvelope>> {
        Ok(self
            .load_all_envelopes()?
            .into_iter()
            .filter(|envelope| matches!(envelope.body, DkgMessageBody::Round1Broadcast(_)))
            .collect())
    }

    fn round2_envelopes(&self) -> Result<Vec<DkgMessageEnvelope>> {
        Ok(self
            .load_all_envelopes()?
            .into_iter()
            .filter(|envelope| matches!(envelope.body, DkgMessageBody::Round2Direct(_)))
            .collect())
    }

    fn ack_envelopes(&self) -> Result<Vec<DkgMessageEnvelope>> {
        Ok(self
            .load_all_envelopes()?
            .into_iter()
            .filter(|envelope| matches!(envelope.body, DkgMessageBody::SignerAck(_)))
            .collect())
    }

    fn envelope_counts(&self) -> Result<EnvelopeCounts> {
        let mut counts = EnvelopeCounts::default();
        for envelope in self.load_all_envelopes()? {
            match &envelope.body {
                DkgMessageBody::Round1Broadcast(_) => {
                    counts.round1_senders.insert(envelope.sender.signer_id);
                }
                DkgMessageBody::Round2Direct(_) => {
                    if let Some(receiver) = envelope.receiver_signer_id {
                        counts
                            .round2_pairs
                            .insert((envelope.sender.signer_id, receiver));
                    }
                }
                DkgMessageBody::SignerAck(_) => {
                    counts.ack_senders.insert(envelope.sender.signer_id);
                }
                DkgMessageBody::Complaint(_) => {}
            }
        }
        Ok(counts)
    }

    fn write_peer_identity(&self) -> Result<()> {
        write_private_json_file(&self.paths.peer_file, &self.config.peer)
    }

    fn read_state(&self) -> Result<Option<RealFrostDkgState>> {
        if !self.paths.state_file.exists() {
            return Ok(None);
        }
        let state: RealFrostDkgState = read_private_json_file(&self.paths.state_file)?;
        let state = state.normalized().context("invalid FROST signer state")?;
        if state.session_id != self.expected_session_id
            || state.epoch_id != self.config.epoch_id
            || state.signer_id != self.config.peer.signer_id
        {
            bail!("FROST signer state does not match daemon configuration");
        }
        Ok(Some(state))
    }

    fn write_state(&self, state: &RealFrostDkgState) -> Result<()> {
        let state = state
            .clone()
            .normalized()
            .context("refusing to persist invalid FROST signer state")?;
        write_private_json_file(&self.paths.state_file, &state)
    }

    fn read_transcript(&self) -> Result<Option<DkgTranscript>> {
        if !self.paths.transcript_file.exists() {
            return Ok(None);
        }
        let transcript: DkgTranscript = read_private_json_file(&self.paths.transcript_file)?;
        Ok(Some(
            transcript
                .normalized()
                .context("invalid persisted FROST transcript")?,
        ))
    }

    fn write_outbox_envelope(&self, envelope: &DkgMessageEnvelope) -> Result<bool> {
        self.validate_envelope(envelope)?;
        let hash = dkg_envelope_hash(envelope);
        if self.envelope_exists(&hash) {
            return Ok(false);
        }
        write_new_json_file(
            &self.paths.outbox_dir.join(format!("{hash}.json")),
            envelope,
        )?;
        Ok(true)
    }

    fn envelope_exists(&self, hash: &str) -> bool {
        self.paths.inbox_dir.join(format!("{hash}.json")).exists()
            || self.paths.outbox_dir.join(format!("{hash}.json")).exists()
    }

    fn load_all_envelopes(&self) -> Result<Vec<DkgMessageEnvelope>> {
        let mut envelopes = self.load_outbox_envelopes()?;
        envelopes.extend(load_envelopes_from_dir(&self.paths.inbox_dir)?);
        envelopes.sort_by_key(dkg_envelope_hash);
        for envelope in &envelopes {
            self.validate_envelope(envelope)?;
        }
        Ok(envelopes)
    }

    fn load_outbox_envelopes(&self) -> Result<Vec<DkgMessageEnvelope>> {
        load_envelopes_from_dir(&self.paths.outbox_dir)
    }
}

async fn handle_connection(
    daemon: Arc<Mutex<FrostSignerDaemon>>,
    mut stream: TcpStream,
    max_frame_bytes: usize,
) -> Result<()> {
    let frame = tokio::time::timeout(
        Duration::from_secs(10),
        read_bounded_json_line(&mut stream, max_frame_bytes),
    )
    .await
    .context("timed out reading FROST signer request")??;
    let request = parse_request(&frame)?;
    let response = match request {
        FrostSignerRequest::SubmitDkgEnvelope { envelope } => {
            let mut daemon = daemon.lock().await;
            match daemon.accept_envelope(*envelope) {
                Ok((accepted, hash)) => match daemon.advance() {
                    Ok(status) => FrostSignerResponse {
                        ok: true,
                        accepted,
                        envelope_hash: Some(hash),
                        status: Some(status),
                        peer: None,
                        error: None,
                    },
                    Err(err) => FrostSignerResponse {
                        ok: false,
                        accepted,
                        envelope_hash: Some(hash),
                        status: None,
                        peer: None,
                        error: Some(err.to_string()),
                    },
                },
                Err(err) => FrostSignerResponse {
                    ok: false,
                    accepted: false,
                    envelope_hash: None,
                    status: None,
                    peer: None,
                    error: Some(err.to_string()),
                },
            }
        }
        FrostSignerRequest::Status => {
            let daemon = daemon.lock().await;
            FrostSignerResponse {
                ok: true,
                accepted: false,
                envelope_hash: None,
                status: Some(daemon.status()?),
                peer: None,
                error: None,
            }
        }
        FrostSignerRequest::PeerIdentity => {
            let daemon = daemon.lock().await;
            FrostSignerResponse {
                ok: true,
                accepted: false,
                envelope_hash: None,
                status: Some(daemon.status()?),
                peer: Some(daemon.config.peer.clone()),
                error: None,
            }
        }
    };
    write_json_line(&mut stream, &response).await
}

async fn submit_envelope_to_peer(
    peer_addr: SocketAddr,
    envelope: &DkgMessageEnvelope,
    max_frame_bytes: usize,
) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(peer_addr))
        .await
        .with_context(|| format!("timed out connecting to {peer_addr}"))?
        .with_context(|| format!("failed to connect to {peer_addr}"))?;
    let request = FrostSignerRequest::SubmitDkgEnvelope {
        envelope: Box::new(envelope.clone()),
    };
    write_json_line(&mut stream, &request)
        .await
        .with_context(|| format!("failed to send DKG envelope to {peer_addr}"))?;
    let response_frame = tokio::time::timeout(
        Duration::from_secs(10),
        read_bounded_json_line(&mut stream, max_frame_bytes),
    )
    .await
    .with_context(|| format!("timed out reading FROST signer response from {peer_addr}"))??;
    let response: FrostSignerResponse = serde_json::from_slice(&response_frame)
        .with_context(|| format!("invalid FROST signer response from {peer_addr}"))?;
    if !response.ok {
        bail!(
            "peer {peer_addr} rejected DKG envelope: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    Ok(())
}

async fn read_bounded_json_line(stream: &mut TcpStream, max_frame_bytes: usize) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream
            .read(&mut byte)
            .await
            .context("failed to read FROST signer frame")?;
        if read == 0 {
            bail!("connection closed before newline");
        }
        if byte[0] == b'\n' {
            return Ok(frame);
        }
        if frame.len() >= max_frame_bytes {
            bail!("FROST signer frame exceeds {max_frame_bytes} bytes");
        }
        frame.push(byte[0]);
    }
}

async fn write_json_line<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(value).context("failed to serialize FROST signer message")?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(10), stream.write_all(&bytes))
        .await
        .context("timed out writing FROST signer message")?
        .context("failed to write FROST signer message")?;
    Ok(())
}

fn parse_request(frame: &[u8]) -> Result<FrostSignerRequest> {
    match serde_json::from_slice::<FrostSignerRequest>(frame) {
        Ok(request) => Ok(request),
        Err(request_err) => match serde_json::from_slice::<DkgMessageEnvelope>(frame) {
            Ok(envelope) => Ok(FrostSignerRequest::SubmitDkgEnvelope {
                envelope: Box::new(envelope),
            }),
            Err(envelope_err) => Err(anyhow!(
                "invalid FROST signer request: {request_err}; raw envelope parse failed: {envelope_err}"
            )),
        },
    }
}

fn validate_bind_policy(bind_addr: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    if !allow_non_loopback && !is_loopback_ip(bind_addr.ip()) {
        bail!(
            "refusing to bind FROST signer daemon on non-loopback address {bind_addr}; pass --allow-non-loopback only on a trusted network"
        );
    }
    Ok(())
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn normalize_and_validate_peers(
    signer_ids: &[String],
    own_peer: &DkgPeerIdentity,
    peers: &[DkgPeerIdentity],
) -> Result<Vec<DkgPeerIdentity>> {
    let signer_set = signer_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut by_signer = BTreeMap::new();
    by_signer.insert(own_peer.signer_id.clone(), own_peer.clone());
    for peer in peers {
        let peer = peer
            .clone()
            .normalized()
            .map_err(|err| anyhow!("invalid DKG peer identity: {err}"))?;
        if !signer_set.contains(&peer.signer_id) {
            bail!(
                "DKG peer {} is not in this epoch signer set",
                peer.signer_id
            );
        }
        if let Some(existing) = by_signer.insert(peer.signer_id.clone(), peer.clone()) {
            if existing != peer {
                bail!(
                    "conflicting DKG peer identity for signer {}",
                    peer.signer_id
                );
            }
        }
    }
    let missing = signer_ids
        .iter()
        .filter(|signer_id| !by_signer.contains_key(*signer_id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "missing trusted DKG peer identity files for signer(s): {}",
            missing.join(", ")
        );
    }
    Ok(by_signer.into_values().collect())
}

fn signer_paths(datadir: &Path, epoch_id: u64, signer_id: &str) -> SignerPaths {
    let base_dir = datadir
        .join("frost-signer")
        .join(format!("epoch-{epoch_id}"))
        .join(signer_id);
    SignerPaths {
        inbox_dir: base_dir.join("inbox"),
        outbox_dir: base_dir.join("outbox"),
        state_file: base_dir.join("state.json"),
        peer_file: base_dir.join("peer.json"),
        transcript_file: base_dir.join("transcript.json"),
        base_dir,
    }
}

fn dkg_envelope_hash(envelope: &DkgMessageEnvelope) -> String {
    hash_hex(sha256_tagged(
        b"POHW1_DKG_ENVELOPE",
        &canonical_json(envelope),
    ))
}

fn has_all_round2_pairs(pairs: &BTreeSet<(String, String)>, signer_ids: &[String]) -> bool {
    signer_ids.iter().all(|sender| {
        signer_ids
            .iter()
            .filter(|receiver| *receiver != sender)
            .all(|receiver| pairs.contains(&(sender.clone(), receiver.clone())))
    })
}

fn logical_envelope_key(envelope: &DkgMessageEnvelope) -> Result<(u64, String, Option<String>)> {
    let sender = envelope
        .sender
        .clone()
        .normalized()
        .map_err(|err| anyhow!("invalid DKG envelope sender: {err}"))?;
    Ok((
        envelope.sequence,
        sender.signer_id,
        envelope.receiver_signer_id.clone(),
    ))
}

fn normalize_hash_hex(value: &str) -> Result<String, String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() == 64
        && normalized
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(normalized)
    } else {
        Err(value.to_string())
    }
}

fn decode_hex_blob(value: &str, label: &str) -> Result<Vec<u8>> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() % 2 != 0
        || !normalized
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{label} must be non-empty even-length hex");
    }
    hex::decode(normalized).with_context(|| format!("failed to decode {label}"))
}

fn validate_encrypted_payload_shape(
    payload: &pohw_core::dkg_transport::EncryptedDkgPayload,
) -> Result<()> {
    if payload.algorithm != "secp256k1-ecdh+chacha20poly1305" {
        bail!(
            "unsupported round 2 DKG encryption algorithm {}",
            payload.algorithm
        );
    }
    PublicKey::from_str(&payload.ephemeral_pubkey_hex)
        .context("round 2 DKG encrypted payload has invalid ephemeral pubkey")?;
    let nonce = decode_hex_blob(&payload.nonce_hex, "round 2 DKG nonce")?;
    if nonce.len() != 12 {
        bail!("round 2 DKG nonce must be 12 bytes");
    }
    let ciphertext = decode_hex_blob(&payload.ciphertext_hex, "round 2 DKG ciphertext")?;
    if ciphertext.is_empty() {
        bail!("round 2 DKG ciphertext cannot be empty");
    }
    Ok(())
}

fn load_envelopes_from_dir(dir: &Path) -> Result<Vec<DkgMessageEnvelope>> {
    let mut envelopes = Vec::new();
    if !dir.exists() {
        return Ok(envelopes);
    }
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read DKG envelope directory {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry from {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        envelopes.push(read_private_json_file(&path)?);
    }
    Ok(envelopes)
}

fn count_json_files(dir: &Path) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry from {}", dir.display()))?;
        if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
            count += 1;
        }
    }
    Ok(count)
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect JSON file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("JSON file {} must not be a symlink", path.display());
    }
    if !metadata.file_type().is_file() {
        bail!("JSON path {} must be a regular file", path.display());
    }
    if metadata.len() > MAX_PRIVATE_JSON_FILE_BYTES {
        bail!(
            "JSON file {} is {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            MAX_PRIVATE_JSON_FILE_BYTES
        );
    }
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON file {}", path.display()))?;
    serde_json::from_str(&json).with_context(|| format!("failed to parse JSON {}", path.display()))
}

fn read_private_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    validate_private_file(path)?;
    read_json_file(path)
}

fn write_new_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_private_dir(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to overwrite existing JSON file {}",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to inspect JSON file {}", path.display()));
        }
    }
    let tmp_path = path.with_extension(format!("{}.tmp", random_hex_16()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp_path).with_context(|| {
        format!(
            "failed to create temporary JSON file {}",
            tmp_path.display()
        )
    })?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write JSON file {}", tmp_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to terminate JSON file {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync JSON file {}", tmp_path.display()))?;
    drop(file);
    if let Err(err) = std::fs::hard_link(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to publish JSON file {} without overwriting {}",
                tmp_path.display(),
                path.display()
            )
        });
    }
    std::fs::remove_file(&tmp_path).with_context(|| {
        format!(
            "failed to remove temporary JSON file {}",
            tmp_path.display()
        )
    })?;
    sync_parent_dir(path)?;
    Ok(())
}

fn write_private_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_private_dir(parent)?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", random_hex_16()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .with_context(|| format!("failed to create private JSON {}", tmp_path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write private JSON {}", tmp_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to terminate private JSON {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync private JSON {}", tmp_path.display()))?;
    drop(file);
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to move private JSON {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    sync_parent_dir(path)?;
    Ok(())
}

fn prepare_private_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_dir(path, &metadata)?;
            protect_private_dir(path)?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = non_empty_parent(path) {
                if parent != path {
                    prepare_private_dir(parent)?;
                }
            }
            match std::fs::create_dir(path) {
                Ok(()) => {
                    protect_private_dir(path)?;
                    Ok(())
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    prepare_private_dir(path)
                }
                Err(err) => Err(err).with_context(|| {
                    format!("failed to create private directory {}", path.display())
                }),
            }
        }
        Err(err) => Err(err)
            .with_context(|| format!("failed to inspect private directory {}", path.display())),
    }
}

fn validate_private_dir(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("private path {} must be a real directory", path.display());
    }
    validate_no_unsafe_symlink_ancestors(path)?;
    Ok(())
}

fn protect_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to protect private directory {}", path.display()))?;
    }
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!("failed to inspect private file parent {}", parent.display())
        })?;
        validate_private_dir(parent, &parent_metadata).with_context(|| {
            format!(
                "failed to validate private file parent {}",
                parent.display()
            )
        })?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("private file {} must be a real file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "private file {} is too permissive ({mode:o}); run chmod 600 {}",
                path.display(),
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_no_unsafe_symlink_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for FROST signer path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect private path symlink ancestor {}",
                        ancestor.display()
                    )
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = ancestor.parent().unwrap_or_else(|| Path::new("/"));
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect private path symlink ancestor parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            bail!(
                "private path {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_symlink_ancestors(_path: &Path) -> Result<()> {
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let dir = std::fs::File::open(parent)
            .with_context(|| format!("failed to open directory {}", parent.display()))?;
        dir.sync_all()
            .with_context(|| format!("failed to sync directory {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn random_hex_16() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_key(byte: u8) -> Keypair {
        let secp = bitcoin::key::Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn ecdh_secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn peer(signer_id: &str, auth: &Keypair, ecdh: &SecretKey) -> DkgPeerIdentity {
        DkgPeerIdentity {
            signer_id: signer_id.to_string(),
            auth_pubkey_xonly_hex: auth.x_only_public_key().0.to_string(),
            ecdh_pubkey_hex: PublicKey::from_secret_key(&bitcoin::key::Secp256k1::new(), ecdh)
                .to_string(),
        }
        .normalized()
        .unwrap()
    }

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("{label}-{}", random_hex_16()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn config(
        datadir: PathBuf,
        own_peer: DkgPeerIdentity,
        peers: Vec<DkgPeerIdentity>,
        signer_ids: Vec<String>,
        auth_keypair: Keypair,
        ecdh_secret_key: SecretKey,
    ) -> RunFrostSignerConfig {
        RunFrostSignerConfig {
            datadir,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            allow_non_loopback: false,
            peer_addrs: Vec::new(),
            peer: own_peer,
            peers,
            signer_ids,
            epoch_id: 42,
            recovery_data_hash: "11".repeat(32),
            auth_keypair,
            ecdh_secret_key,
            sync_interval: Duration::from_secs(1),
            max_frame_bytes: 1_048_576,
            max_connections: 8,
            once: true,
        }
    }

    fn exchange_all(daemons: &mut [FrostSignerDaemon]) {
        let envelopes = daemons
            .iter()
            .flat_map(|daemon| {
                let sender = daemon.config.peer.signer_id.clone();
                daemon
                    .load_outbox_envelopes()
                    .unwrap()
                    .into_iter()
                    .map(move |envelope| (sender.clone(), envelope))
            })
            .collect::<Vec<_>>();

        for (sender, envelope) in envelopes {
            for daemon in daemons.iter_mut() {
                if daemon.config.peer.signer_id != sender {
                    daemon.accept_envelope(envelope.clone()).unwrap();
                }
            }
        }
    }

    #[test]
    fn new_json_writer_refuses_existing_destination_without_clobbering() {
        let dir = test_dir("pohw-frost-signer-new-json");
        let path = dir.join("envelope.json");

        write_new_json_file(&path, &serde_json::json!({ "version": 1 })).unwrap();
        let err = write_new_json_file(&path, &serde_json::json!({ "version": 2 })).unwrap_err();

        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err:#}"
        );
        let written: serde_json::Value = read_private_json_file(&path).unwrap();
        assert_eq!(written["version"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn new_json_writer_refuses_symlink_ancestor_directory() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-frost-signer-new-json-symlink-ancestor");
        let real = dir.join("real");
        let child = real.join("child");
        let link = dir.join("link");
        std::fs::create_dir_all(&child).unwrap();
        symlink(&real, &link).unwrap();
        let path = link.join("child").join("envelope.json");

        let err = write_new_json_file(&path, &serde_json::json!({ "version": 1 })).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        assert!(!child.join("envelope.json").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_json_reader_refuses_symlink_ancestor_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = test_dir("pohw-frost-signer-private-json-symlink-ancestor");
        let real = dir.join("real");
        let child = real.join("child");
        let link = dir.join("link");
        std::fs::create_dir_all(&child).unwrap();
        symlink(&real, &link).unwrap();
        let path = child.join("state.json");
        std::fs::write(&path, "{\"version\":1}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let err =
            read_private_json_file::<serde_json::Value>(&link.join("child").join("state.json"))
                .unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_json_reader_rejects_large_files() {
        let dir = test_dir("pohw-frost-signer-private-json-large");
        let path = dir.join("state.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_PRIVATE_JSON_FILE_BYTES + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = read_private_json_file::<serde_json::Value>(&path).unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn json_reader_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-frost-signer-json-symlink");
        let target = dir.join("target.json");
        let link = dir.join("state.json");
        std::fs::write(&target, "{\"version\":1}\n").unwrap();
        symlink(&target, &link).unwrap();

        let err = read_json_file::<serde_json::Value>(&link).unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn signed_round1_envelope(
        signer_id: &str,
        signer_ids: Vec<String>,
        auth_keypair: &Keypair,
        peer: DkgPeerIdentity,
    ) -> DkgMessageEnvelope {
        let output = real_frost_dkg_round1(
            42,
            signer_id.to_string(),
            signer_ids,
            "11".repeat(32),
            &mut OsRng,
        )
        .unwrap();
        let mut envelope = DkgMessageEnvelope::unsigned(
            output.state.session_id,
            42,
            1,
            peer,
            None,
            DkgMessageBody::Round1Broadcast(output.body),
        )
        .unwrap();
        envelope.sign(auth_keypair).unwrap();
        envelope
    }

    #[test]
    fn daemon_completes_three_signer_dkg_from_exchanged_envelopes() {
        let dir = test_dir("pohw-frost-signer-daemon");
        let signer_ids = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let auth_keys = [auth_key(1), auth_key(2), auth_key(3)];
        let ecdh_keys = [ecdh_secret(4), ecdh_secret(5), ecdh_secret(6)];
        let peers = signer_ids
            .iter()
            .zip(auth_keys.iter())
            .zip(ecdh_keys.iter())
            .map(|((signer_id, auth), ecdh)| peer(signer_id, auth, ecdh))
            .collect::<Vec<_>>();

        let mut daemons = (0..signer_ids.len())
            .map(|idx| {
                FrostSignerDaemon::new(config(
                    dir.join(&signer_ids[idx]),
                    peers[idx].clone(),
                    peers.clone(),
                    signer_ids.clone(),
                    auth_keys[idx],
                    ecdh_keys[idx],
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();

        for _ in 0..6 {
            for daemon in &mut daemons {
                daemon.advance().unwrap();
            }
            exchange_all(&mut daemons);
        }

        let statuses = daemons
            .iter()
            .map(|daemon| daemon.status().unwrap())
            .collect::<Vec<_>>();
        assert!(statuses.iter().all(|status| status.finalized));
        assert!(statuses.iter().all(|status| status.transcript_ready));
        assert!(statuses.iter().all(|status| status.round1_ready));
        assert!(statuses.iter().all(|status| status.round2_ready));
        let transcript_hash = statuses[0].transcript_hash.clone();
        assert!(statuses
            .iter()
            .all(|status| status.transcript_hash == transcript_hash));
    }

    #[test]
    fn daemon_rejects_untrusted_peer_identity_for_known_signer_id() {
        let dir = test_dir("pohw-frost-signer-daemon-rejects-peer");
        let signer_ids = vec!["alice".to_string(), "bob".to_string()];
        let alice_auth = auth_key(10);
        let bob_auth = auth_key(11);
        let fake_bob_auth = auth_key(12);
        let alice_ecdh = ecdh_secret(13);
        let bob_ecdh = ecdh_secret(14);
        let fake_bob_ecdh = ecdh_secret(15);
        let alice = peer("alice", &alice_auth, &alice_ecdh);
        let bob = peer("bob", &bob_auth, &bob_ecdh);
        let fake_bob = peer("bob", &fake_bob_auth, &fake_bob_ecdh);
        let mut daemon = FrostSignerDaemon::new(config(
            dir,
            alice.clone(),
            vec![alice.clone(), bob],
            signer_ids.clone(),
            alice_auth,
            alice_ecdh,
        ))
        .unwrap();
        daemon.advance().unwrap();

        let state =
            RealFrostDkgState::new(42, "bob".to_string(), signer_ids, "11".repeat(32)).unwrap();
        let mut envelope = DkgMessageEnvelope::unsigned(
            state.session_id,
            42,
            1,
            fake_bob,
            None,
            DkgMessageBody::SignerAck(pohw_core::dkg_transport::DkgSignerAckBody {
                frost_identifier_hex: "01".repeat(32),
                public_key_package_hash: "22".repeat(32),
            }),
        )
        .unwrap();
        envelope.sign(&fake_bob_auth).unwrap();

        let err = daemon.accept_envelope(envelope).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match trusted epoch peer identity"));
    }

    #[test]
    fn daemon_rejects_conflicting_duplicate_round1_for_same_signer() {
        let dir = test_dir("pohw-frost-signer-daemon-conflict");
        let signer_ids = vec!["alice".to_string(), "bob".to_string()];
        let alice_auth = auth_key(20);
        let bob_auth = auth_key(21);
        let alice_ecdh = ecdh_secret(22);
        let bob_ecdh = ecdh_secret(23);
        let alice = peer("alice", &alice_auth, &alice_ecdh);
        let bob = peer("bob", &bob_auth, &bob_ecdh);
        let mut daemon = FrostSignerDaemon::new(config(
            dir,
            alice.clone(),
            vec![alice, bob.clone()],
            signer_ids.clone(),
            alice_auth,
            alice_ecdh,
        ))
        .unwrap();
        daemon.advance().unwrap();

        let first = signed_round1_envelope("bob", signer_ids.clone(), &bob_auth, bob.clone());
        let second = signed_round1_envelope("bob", signer_ids, &bob_auth, bob);

        assert!(daemon.accept_envelope(first).unwrap().0);
        let err = daemon.accept_envelope(second).unwrap_err();

        assert!(
            err.to_string().contains("conflicting DKG envelope"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn daemon_rejects_round1_package_hash_mismatch_before_persisting() {
        let dir = test_dir("pohw-frost-signer-daemon-bad-round1");
        let signer_ids = vec!["alice".to_string(), "bob".to_string()];
        let alice_auth = auth_key(30);
        let bob_auth = auth_key(31);
        let alice_ecdh = ecdh_secret(32);
        let bob_ecdh = ecdh_secret(33);
        let alice = peer("alice", &alice_auth, &alice_ecdh);
        let bob = peer("bob", &bob_auth, &bob_ecdh);
        let mut daemon = FrostSignerDaemon::new(config(
            dir,
            alice.clone(),
            vec![alice, bob.clone()],
            signer_ids.clone(),
            alice_auth,
            alice_ecdh,
        ))
        .unwrap();
        daemon.advance().unwrap();

        let output = real_frost_dkg_round1(
            42,
            "bob".to_string(),
            signer_ids,
            "11".repeat(32),
            &mut OsRng,
        )
        .unwrap();
        let mut body = output.body;
        body.package_hash = "22".repeat(32);
        let mut envelope = DkgMessageEnvelope::unsigned(
            output.state.session_id,
            42,
            1,
            bob,
            None,
            DkgMessageBody::Round1Broadcast(body),
        )
        .unwrap();
        envelope.sign(&bob_auth).unwrap();

        let err = daemon.accept_envelope(envelope).unwrap_err();

        assert!(
            err.to_string()
                .contains("package hash does not match package bytes"),
            "unexpected error: {err:#}"
        );
        assert_eq!(daemon.status().unwrap().inbox_envelopes, 0);
    }

    #[test]
    fn daemon_rejects_noncanonical_sender_identity_before_persisting() {
        let dir = test_dir("pohw-frost-signer-daemon-noncanonical");
        let signer_ids = vec!["alice".to_string(), "bob".to_string()];
        let alice_auth = auth_key(40);
        let bob_auth = auth_key(41);
        let alice_ecdh = ecdh_secret(42);
        let bob_ecdh = ecdh_secret(43);
        let alice = peer("alice", &alice_auth, &alice_ecdh);
        let bob = peer("bob", &bob_auth, &bob_ecdh);
        let mut daemon = FrostSignerDaemon::new(config(
            dir,
            alice.clone(),
            vec![alice, bob],
            signer_ids.clone(),
            alice_auth,
            alice_ecdh,
        ))
        .unwrap();
        daemon.advance().unwrap();

        let mut envelope = signed_round1_envelope(
            "bob",
            signer_ids,
            &bob_auth,
            peer("bob", &bob_auth, &bob_ecdh),
        );
        envelope.sender.signer_id = "Bob".to_string();
        envelope.sign(&bob_auth).unwrap();

        let err = daemon.accept_envelope(envelope).unwrap_err();

        assert!(
            err.to_string().contains("sender identity is not canonical"),
            "unexpected error: {err:#}"
        );
        assert_eq!(daemon.status().unwrap().inbox_envelopes, 0);
    }
}
