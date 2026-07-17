use anyhow::{Context, Result};
use pohw_core::commitment::{
    validate_pohw_commitment, PohwCommitment, PohwCommitmentValidationContext,
};
use pohw_core::gossip::{normalize_gossip_network_id, GossipEnvelope, GOSSIP_PROTOCOL_VERSION};
use pohw_core::idena_anchor::IdenaAnchorPolicyV2;
use pohw_core::ledger::ClaimLedger;
use pohw_core::payout::{ParticipantAccount, PayoutSchedule};
use pohw_core::share_work::{ShareWorkActivationManifestV1, ShareWorkBindingPolicyV1};
use pohw_core::sharechain::{BitcoinWorkTemplate, MinerRegistration, SharechainMessage};
use pohw_core::sharechain_state::{ApplyOutcome, SharechainReplayState, SharechainReplaySummary};
use pohw_core::snapshot::Snapshot;
use pohw_core::vault::vault_script_pubkey_hex;
use pohw_core::{canonical_json, hash_hex, sha256_tagged};
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex as StdMutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SHARECHAIN_LOG: &str = "sharechain.ndjson";
const SHARECHAIN_INDEX_FILE: &str = "sharechain-index.json";
const ACCEPTED_BITCOIN_WORK_TEMPLATES_LOG: &str = "accepted-bitcoin-work-templates.ndjson";
const CONFIRMED_PAYOUT_LOG: &str = "confirmed-payouts.ndjson";
const GOSSIP_ENVELOPE_LOG: &str = "gossip-envelopes.ndjson";
const GOSSIP_NETWORK_ID_FILE: &str = "gossip-network-id";
const GOSSIP_PEERS_FILE: &str = "gossip-peers.json";
const IDENA_ANCHOR_POLICY_FILE: &str = "idena-anchor-policy-v2.json";
const SHARE_WORK_BINDING_POLICY_FILE: &str = "share-work-binding-policy-v1.json";
const APPEND_LOCK: &str = "sharechain.append.lock";
const GOSSIP_PEERS_LOCK: &str = "gossip-peers.lock";
const CORRUPT_LOG_DIR: &str = "corrupt-log-lines";
const STALE_APPEND_LOCK_SECONDS: u64 = 300;
const APPEND_LOCK_ATTEMPTS: usize = 400;
const MAX_GOSSIP_PEERS: usize = 512;
const MAX_SNAPSHOT_FILES: usize = 512;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SHARECHAIN_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GOSSIP_NETWORK_ID_FILE_BYTES: u64 = 65;
const MAX_PERSISTED_GOSSIP_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_PERSISTED_GOSSIP_ENVELOPES: usize = 262_144;
const MAX_PERSISTED_GOSSIP_ENVELOPES_PER_PEER: usize = 65_536;
const MAX_PERSISTED_GOSSIP_LOG_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PERSISTED_SHARECHAIN_LOG_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PERSISTED_ACCEPTED_TEMPLATE_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IDENA_ANCHOR_POLICY_BYTES: u64 = 64 * 1024;
const MAX_SHARE_WORK_BINDING_POLICY_BYTES: u64 = 64 * 1024;

static GOSSIP_ENVELOPE_CACHE: OnceLock<StdMutex<BTreeMap<PathBuf, GossipEnvelopeCacheEntry>>> =
    OnceLock::new();
static SHARECHAIN_REPLAY_CACHE: OnceLock<StdMutex<BTreeMap<PathBuf, ReplayCacheEntry>>> =
    OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TruncatedTailRepair {
    Conservative,
    Force,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GossipEnvelopeLogStamp {
    len: u64,
    modified: Option<SystemTime>,
    network_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct GossipEnvelopeCacheEntry {
    stamp: Option<GossipEnvelopeLogStamp>,
    envelopes: Vec<StoredGossipEnvelope>,
    message_hashes: Vec<String>,
    envelopes_by_message_hash: BTreeMap<String, GossipEnvelope>,
    envelopes_by_bitcoin_template_hash: BTreeMap<String, GossipEnvelope>,
    envelopes_by_miner_registration_id: BTreeMap<String, GossipEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharechainLogStamp {
    pub len: u64,
    pub modified_unix_nanos: Option<String>,
}

#[derive(Debug)]
struct ReplayCacheEntry {
    log_stamp: Option<SharechainLogStamp>,
    accepted_template_stamp: Option<SharechainLogStamp>,
    message_count: usize,
    state: SharechainReplayState,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalAppendError {
    #[error("{label} lock at {path} is busy after bounded retry")]
    LockBusy { label: String, path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum GossipPersistenceError {
    #[error("{label} exceeds the per-record persistence limit of {limit} bytes")]
    RecordTooLarge { label: String, limit: u64 },
    #[error("gossip persistence reached the global envelope limit of {limit}")]
    EnvelopeLimit { limit: usize },
    #[error("gossip signing key reached the per-key envelope limit of {limit}")]
    PeerEnvelopeLimit { limit: usize },
    #[error("{label} would exceed the persistence limit of {limit} bytes")]
    ByteLimit { label: String, limit: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharechainIndex {
    pub schema_version: u32,
    pub generated_at_unix: i64,
    pub sharechain_log: PathBuf,
    pub log_stamp: Option<SharechainLogStamp>,
    pub accepted_bitcoin_work_templates_log_stamp: Option<SharechainLogStamp>,
    pub idena_anchor_policy_hash: Option<String>,
    pub share_work_binding_policy_hash: Option<String>,
    pub message_count: usize,
    pub replay: SharechainReplaySummary,
    pub registrations_by_miner: BTreeMap<String, MinerRegistration>,
    pub hashrate_scores_by_miner: BTreeMap<String, u128>,
    pub claim_balances_by_owner: BTreeMap<String, u64>,
    pub participant_accounts: Vec<ParticipantAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshotFile {
    pub path: PathBuf,
    pub snapshot: Snapshot,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotDirectoryStatus {
    pub snapshot_dir: PathBuf,
    pub scanned_file_count: usize,
    pub invalid_file_count: usize,
    pub skipped_file_count: usize,
    pub latest: Option<VerifiedSnapshotFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedPayoutRecord {
    pub schema_version: u32,
    pub fork_block_height: u64,
    pub fork_block_hash: String,
    pub coinbase_txid: String,
    pub pohw_commitment_hash: String,
    pub vault_epoch_id: u64,
    pub frost_vault_key_xonly: String,
    pub vault_script_pubkey_hex: String,
    pub reward_sats: u64,
    pub direct_limit: usize,
    pub min_direct_payout_sats: u64,
    pub idena_snapshot_day: String,
    pub idena_height: u64,
    pub idena_score_root: String,
    pub pohw_commitment: PohwCommitment,
    pub payout_schedule: PayoutSchedule,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendConfirmedPayoutResult {
    pub record_id: String,
    pub outcome: ApplyOutcome,
    pub record: ConfirmedPayoutRecord,
    pub replay: SharechainReplaySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcceptBitcoinWorkTemplateResult {
    pub template_hash: String,
    pub outcome: ApplyOutcome,
    pub accepted_template_count: usize,
}

#[derive(Debug, Clone)]
pub struct ConfirmedPayoutAppend {
    pub snapshot_file: PathBuf,
    pub payout_schedule: PayoutSchedule,
    pub reward_sats: u64,
    pub direct_limit: usize,
    pub min_direct_payout_sats: u64,
    pub fork_block_height: u64,
    pub fork_block_hash: String,
    pub coinbase_txid: String,
    pub pohw_commitment: PohwCommitment,
}

impl ConfirmedPayoutRecord {
    #[allow(clippy::too_many_arguments)]
    fn new(
        fork_block_height: u64,
        fork_block_hash: String,
        coinbase_txid: String,
        reward_sats: u64,
        direct_limit: usize,
        min_direct_payout_sats: u64,
        snapshot: &Snapshot,
        payout_schedule: PayoutSchedule,
        pohw_commitment: PohwCommitment,
    ) -> Result<Self> {
        let pohw_commitment = pohw_commitment.normalized();
        let frost_vault_key_xonly = pohw_commitment.frost_vault_key_xonly.clone();
        let vault_script_pubkey_hex =
            vault_script_pubkey_hex(&frost_vault_key_xonly).context("invalid FROST vault key")?;
        Self {
            schema_version: 2,
            fork_block_height,
            fork_block_hash,
            coinbase_txid,
            pohw_commitment_hash: pohw_commitment.commitment_hash(),
            vault_epoch_id: pohw_commitment.vault_epoch_id,
            frost_vault_key_xonly,
            vault_script_pubkey_hex,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
            idena_snapshot_day: snapshot.snapshot_day.to_string(),
            idena_height: snapshot.idena_height,
            idena_score_root: snapshot.score_root.clone(),
            pohw_commitment,
            payout_schedule,
        }
        .normalized()
    }

    pub fn record_id(&self) -> String {
        hash_hex(sha256_tagged(
            b"POHW1_CONFIRMED_PAYOUT_RECORD",
            &canonical_json(&self.clone().normalized_for_hash()),
        ))
    }

    fn normalized(mut self) -> Result<Self> {
        if self.schema_version != 2 {
            anyhow::bail!(
                "unsupported confirmed payout record schema version {}",
                self.schema_version
            );
        }
        self.fork_block_hash = normalize_hash_hex("fork_block_hash", &self.fork_block_hash)?;
        self.coinbase_txid = normalize_hash_hex("coinbase_txid", &self.coinbase_txid)?;
        self.pohw_commitment = self.pohw_commitment.normalized();
        self.pohw_commitment_hash =
            normalize_hash_hex("pohw_commitment_hash", &self.pohw_commitment_hash)?;
        let expected_commitment_hash = self.pohw_commitment.commitment_hash();
        if self.pohw_commitment_hash != expected_commitment_hash {
            anyhow::bail!(
                "confirmed payout commitment hash mismatch: expected {}, got {}",
                expected_commitment_hash,
                self.pohw_commitment_hash
            );
        }
        if self.vault_epoch_id != self.pohw_commitment.vault_epoch_id {
            anyhow::bail!(
                "confirmed payout vault epoch {} does not match commitment epoch {}",
                self.vault_epoch_id,
                self.pohw_commitment.vault_epoch_id
            );
        }
        self.frost_vault_key_xonly = self.frost_vault_key_xonly.to_ascii_lowercase();
        if self.frost_vault_key_xonly != self.pohw_commitment.frost_vault_key_xonly {
            anyhow::bail!("confirmed payout FROST vault key does not match commitment key");
        }
        let expected_vault_script = vault_script_pubkey_hex(&self.frost_vault_key_xonly)
            .context("invalid FROST vault key")?;
        self.vault_script_pubkey_hex =
            normalize_script_hex("vault_script_pubkey_hex", &self.vault_script_pubkey_hex)?;
        if self.vault_script_pubkey_hex != expected_vault_script {
            anyhow::bail!(
                "confirmed payout vault script mismatch: expected {}, got {}",
                expected_vault_script,
                self.vault_script_pubkey_hex
            );
        }
        self.idena_score_root = normalize_hash_hex("idena_score_root", &self.idena_score_root)?;
        self.payout_schedule.validate()?;
        Ok(self)
    }

    fn normalized_for_hash(mut self) -> Self {
        self.fork_block_hash = self.fork_block_hash.to_ascii_lowercase();
        self.coinbase_txid = self.coinbase_txid.to_ascii_lowercase();
        self.pohw_commitment_hash = self.pohw_commitment_hash.to_ascii_lowercase();
        self.frost_vault_key_xonly = self.frost_vault_key_xonly.to_ascii_lowercase();
        self.vault_script_pubkey_hex = self.vault_script_pubkey_hex.to_ascii_lowercase();
        self.idena_score_root = self.idena_score_root.to_ascii_lowercase();
        self.pohw_commitment = self.pohw_commitment.normalized();
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalNodeStatus {
    pub datadir: PathBuf,
    pub sharechain_log: PathBuf,
    pub gossip_envelope_log: PathBuf,
    pub log_line_count: usize,
    pub gossip_envelope_count: usize,
    pub replay: SharechainReplaySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendMessageResult {
    pub message_hash: String,
    pub outcome: ApplyOutcome,
    pub status: LocalNodeStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendGossipEnvelopeResult {
    pub envelope_hash: String,
    pub peer_pubkey_xonly_hex: String,
    pub message_result: AppendMessageResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGossipEnvelope {
    pub envelope_hash: String,
    pub message_hash: String,
    pub peer_pubkey_xonly_hex: String,
    pub envelope: GossipEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerEntry {
    pub addr: SocketAddr,
    pub source: String,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    pub last_success_unix: Option<i64>,
    pub failure_count: u32,
}

pub fn initialize_gossip_network(datadir: &Path, network_id: &str) -> Result<String> {
    ensure_datadir(datadir)?;
    let network_id = normalize_gossip_network_id(network_id)?;
    let _lock = acquire_append_lock(datadir)?;
    if let Some(existing) = gossip_network_id(datadir)? {
        if existing != network_id {
            anyhow::bail!(
                "gossip datadir is already bound to a different network; use a fresh datadir"
            );
        }
        return Ok(existing);
    }
    for (path, label) in [
        (log_path(datadir), "sharechain log"),
        (gossip_envelope_log_path(datadir), "gossip envelope log"),
        (
            accepted_bitcoin_work_templates_log_path(datadir),
            "accepted Bitcoin work template log",
        ),
        (confirmed_payout_log_path(datadir), "confirmed payout log"),
        (sharechain_index_path(datadir), "sharechain index"),
    ] {
        if validate_datadir_file(&path, label)?.is_some_and(|metadata| metadata.len() > 0) {
            anyhow::bail!(
                "cannot bind non-empty gossip datadir {} to a network; preserve it and use a fresh datadir",
                datadir.display()
            );
        }
    }

    let path = gossip_network_id_path(datadir);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("failed to create gossip network id file {}", path.display()))?;
    file.write_all(network_id.as_bytes())
        .context("failed to write gossip network id")?;
    file.write_all(b"\n")
        .context("failed to terminate gossip network id")?;
    file.flush().context("failed to flush gossip network id")?;
    file.sync_all()
        .context("failed to sync gossip network id")?;
    sync_dir(datadir)?;
    Ok(network_id)
}

pub fn gossip_network_id(datadir: &Path) -> Result<Option<String>> {
    ensure_datadir(datadir)?;
    let path = gossip_network_id_path(datadir);
    let Some(metadata) = validate_datadir_file(&path, "gossip network id")? else {
        return Ok(None);
    };
    if metadata.len() > MAX_GOSSIP_NETWORK_ID_FILE_BYTES {
        anyhow::bail!("gossip network id file exceeds the maximum size");
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read gossip network id file {}", path.display()))?;
    let value = contents.strip_suffix('\n').unwrap_or(&contents);
    let network_id = normalize_gossip_network_id(value)?;
    if contents != format!("{network_id}\n") {
        anyhow::bail!("gossip network id file is not in canonical format");
    }
    Ok(Some(network_id))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GossipPeerBook {
    peers: Vec<GossipPeerEntry>,
}

pub fn run_local_node(datadir: &Path, status_interval_seconds: u64, once: bool) -> Result<()> {
    ensure_datadir(datadir)?;
    loop {
        let status = local_node_status(datadir)?;
        println!("{}", serde_json::to_string_pretty(&status)?);
        if once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(status_interval_seconds.max(1)));
    }
}

pub fn bind_idena_anchor_policy(datadir: &Path, policy: &IdenaAnchorPolicyV2) -> Result<String> {
    ensure_datadir(datadir)?;
    let policy = policy.clone().normalized();
    policy.validate().context("invalid Idena anchor policy")?;
    let commitment = policy.commitment_hash()?;
    let _lock = acquire_append_lock(datadir)?;

    if let Some(existing) = read_bound_idena_anchor_policy(datadir)? {
        let existing_commitment = existing.commitment_hash()?;
        if existing_commitment != commitment {
            anyhow::bail!(
                "node datadir is already bound to Idena anchor policy {existing_commitment}; refusing replacement with {commitment}"
            );
        }
    }

    audit_sharechain_with_idena_anchor_policy(datadir, &policy)?;
    if read_bound_idena_anchor_policy(datadir)?.is_none() {
        write_bound_idena_anchor_policy(datadir, &policy)?;
    }
    if let Some(cache) = SHARECHAIN_REPLAY_CACHE.get() {
        cache
            .lock()
            .map_err(|_| anyhow::anyhow!("sharechain replay cache lock poisoned"))?
            .remove(&replay_cache_key(datadir));
    }
    Ok(commitment)
}

pub fn read_bound_idena_anchor_policy(datadir: &Path) -> Result<Option<IdenaAnchorPolicyV2>> {
    let path = idena_anchor_policy_path(datadir);
    let Some(metadata) = validate_datadir_file(&path, "Idena anchor policy")? else {
        return Ok(None);
    };
    if metadata.len() > MAX_IDENA_ANCHOR_POLICY_BYTES {
        anyhow::bail!(
            "Idena anchor policy {} exceeds {MAX_IDENA_ANCHOR_POLICY_BYTES} bytes",
            path.display()
        );
    }
    let payload = fs::read(&path)
        .with_context(|| format!("failed to read Idena anchor policy {}", path.display()))?;
    let policy: IdenaAnchorPolicyV2 = serde_json::from_slice(&payload)
        .with_context(|| format!("Idena anchor policy {} is not strict JSON", path.display()))?;
    let policy = policy.normalized();
    policy
        .validate()
        .with_context(|| format!("invalid Idena anchor policy {}", path.display()))?;
    Ok(Some(policy))
}

fn audit_sharechain_with_idena_anchor_policy(
    datadir: &Path,
    policy: &IdenaAnchorPolicyV2,
) -> Result<SharechainReplayState> {
    let mut state = replay_state_with_accepted_bitcoin_work_templates(
        datadir,
        TruncatedTailRepair::Conservative,
    )?;
    for message in read_messages_with_repair(datadir, TruncatedTailRepair::Conservative)? {
        state
            .validate_idena_anchor_policy(&message, policy)
            .context("existing sharechain history violates the Idena anchor policy")?;
        state.apply_message(&message)?;
    }
    Ok(state)
}

fn write_bound_idena_anchor_policy(datadir: &Path, policy: &IdenaAnchorPolicyV2) -> Result<()> {
    let path = idena_anchor_policy_path(datadir);
    let (tmp_path, mut file) = create_random_temp_file(datadir, IDENA_ANCHOR_POLICY_FILE)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut file, policy)
        .context("failed to encode bound Idena anchor policy")?;
    file.write_all(b"\n")
        .context("failed to terminate bound Idena anchor policy")?;
    file.flush()
        .context("failed to flush bound Idena anchor policy")?;
    file.sync_all()
        .context("failed to sync bound Idena anchor policy")?;
    fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "failed to install bound Idena anchor policy {} from {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    sync_dir(datadir)
}

pub fn read_share_work_binding_policy_file(path: &Path) -> Result<ShareWorkBindingPolicyV1> {
    let payload = read_bounded_regular_text_file(
        path,
        "share-work binding policy",
        MAX_SHARE_WORK_BINDING_POLICY_BYTES,
    )?;
    let policy: ShareWorkBindingPolicyV1 =
        crate::strict_json::from_str(&payload).with_context(|| {
            format!(
                "share-work binding policy {} is not strict JSON",
                path.display()
            )
        })?;
    let policy = policy.normalized();
    policy
        .validate()
        .with_context(|| format!("invalid share-work binding policy {}", path.display()))?;
    Ok(policy)
}

pub fn read_share_work_activation_manifest_file(
    path: &Path,
) -> Result<ShareWorkActivationManifestV1> {
    let payload = read_bounded_regular_text_file(
        path,
        "share-work activation manifest",
        MAX_SHARE_WORK_BINDING_POLICY_BYTES,
    )?;
    let manifest: ShareWorkActivationManifestV1 = crate::strict_json::from_str(&payload)
        .with_context(|| {
            format!(
                "share-work activation manifest {} is not strict JSON",
                path.display()
            )
        })?;
    let manifest = manifest.normalized();
    manifest
        .validate()
        .with_context(|| format!("invalid share-work activation manifest {}", path.display()))?;
    Ok(manifest)
}

pub fn bind_share_work_binding_policy(
    datadir: &Path,
    policy: &ShareWorkBindingPolicyV1,
) -> Result<String> {
    ensure_datadir(datadir)?;
    let policy = policy.clone().normalized();
    policy
        .validate()
        .context("invalid share-work binding policy")?;
    let commitment = policy.commitment_hash()?;
    let _lock = acquire_append_lock(datadir)?;

    let network_id = gossip_network_id(datadir)?
        .context("share-work binding requires an initialized gossip network datadir")?;
    if network_id != policy.sharechain_network_id {
        anyhow::bail!(
            "share-work policy network {} does not match datadir gossip network {}",
            policy.sharechain_network_id,
            network_id
        );
    }
    let idena_policy = read_bound_idena_anchor_policy(datadir)?
        .context("share-work binding requires a bound Idena anchor policy")?;
    if !idena_policy
        .experiment_id
        .eq_ignore_ascii_case(&policy.experiment_id)
    {
        anyhow::bail!(
            "share-work policy experiment {} does not match bound Idena experiment {}",
            policy.experiment_id,
            idena_policy.experiment_id
        );
    }
    if let Some(existing) = read_bound_share_work_binding_policy(datadir)? {
        let existing_commitment = existing.commitment_hash()?;
        if existing_commitment != commitment {
            anyhow::bail!(
                "node datadir is already bound to share-work policy {existing_commitment}; refusing replacement with {commitment}"
            );
        }
    }

    audit_sharechain_with_share_work_binding_policy(datadir, &policy)?;
    if read_bound_share_work_binding_policy(datadir)?.is_none() {
        write_bound_share_work_binding_policy(datadir, &policy)?;
    }
    if let Some(cache) = SHARECHAIN_REPLAY_CACHE.get() {
        cache
            .lock()
            .map_err(|_| anyhow::anyhow!("sharechain replay cache lock poisoned"))?
            .remove(&replay_cache_key(datadir));
    }
    Ok(commitment)
}

pub fn read_bound_share_work_binding_policy(
    datadir: &Path,
) -> Result<Option<ShareWorkBindingPolicyV1>> {
    let path = share_work_binding_policy_path(datadir);
    if validate_datadir_file(&path, "share-work binding policy")?.is_none() {
        return Ok(None);
    }
    read_share_work_binding_policy_file(&path).map(Some)
}

fn audit_sharechain_with_share_work_binding_policy(
    datadir: &Path,
    policy: &ShareWorkBindingPolicyV1,
) -> Result<SharechainReplayState> {
    let mut state = replay_state_with_accepted_bitcoin_work_templates(
        datadir,
        TruncatedTailRepair::Conservative,
    )?;
    for message in read_messages_with_repair(datadir, TruncatedTailRepair::Conservative)? {
        state
            .validate_share_work_binding_policy(&message, policy)
            .context("existing sharechain history violates the share-work binding policy")?;
        state.apply_message(&message)?;
    }
    Ok(state)
}

fn write_bound_share_work_binding_policy(
    datadir: &Path,
    policy: &ShareWorkBindingPolicyV1,
) -> Result<()> {
    let path = share_work_binding_policy_path(datadir);
    let (tmp_path, mut file) = create_random_temp_file(datadir, SHARE_WORK_BINDING_POLICY_FILE)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut file, policy)
        .context("failed to encode bound share-work binding policy")?;
    file.write_all(b"\n")
        .context("failed to terminate bound share-work binding policy")?;
    file.flush()
        .context("failed to flush bound share-work binding policy")?;
    file.sync_all()
        .context("failed to sync bound share-work binding policy")?;
    fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "failed to install bound share-work binding policy {} from {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    sync_dir(datadir)
}

pub fn append_message_file(datadir: &Path, message_file: &Path) -> Result<AppendMessageResult> {
    ensure_datadir(datadir)?;
    let message_json = read_bounded_regular_text_file(
        message_file,
        "message file",
        MAX_SHARECHAIN_INPUT_FILE_BYTES,
    )?;
    let message: SharechainMessage = serde_json::from_str(&message_json)
        .with_context(|| format!("failed to parse {}", message_file.display()))?;
    append_message(datadir, message)
}

pub fn accept_bitcoin_work_template_file(
    datadir: &Path,
    template_file: &Path,
) -> Result<AcceptBitcoinWorkTemplateResult> {
    ensure_datadir(datadir)?;
    let template = read_bitcoin_work_template_file(template_file)?;
    accept_bitcoin_work_template(datadir, template)
}

pub fn accept_bitcoin_work_template(
    datadir: &Path,
    template: BitcoinWorkTemplate,
) -> Result<AcceptBitcoinWorkTemplateResult> {
    ensure_datadir(datadir)?;
    template.verify_template_hash()?;
    let template = template.normalized();
    let template_hash = template.template_hash.clone();
    let _lock = acquire_append_lock(datadir)?;
    if gossip_network_id(datadir)?.is_some() {
        template.require_target_bound()?;
    }
    let existing_templates =
        read_accepted_bitcoin_work_templates_with_repair(datadir, TruncatedTailRepair::Force)?;
    for existing in &existing_templates {
        if existing.template_hash == template_hash {
            if existing.header_prefix_hex != template.header_prefix_hex {
                anyhow::bail!("accepted Bitcoin work template conflict for {template_hash}");
            }
            return Ok(AcceptBitcoinWorkTemplateResult {
                template_hash,
                outcome: ApplyOutcome::DuplicateIgnored,
                accepted_template_count: existing_templates.len(),
            });
        }
    }

    let encoded_template =
        serde_json::to_vec(&template).context("failed to encode accepted Bitcoin work template")?;
    ensure_record_size(
        "accepted Bitcoin work template",
        encoded_template.len(),
        MAX_PERSISTED_GOSSIP_RECORD_BYTES,
    )?;
    ensure_file_capacity(
        &accepted_bitcoin_work_templates_log_path(datadir),
        "accepted Bitcoin work template log",
        encoded_template.len().saturating_add(1),
        MAX_PERSISTED_ACCEPTED_TEMPLATE_LOG_BYTES,
    )?;

    let mut file = open_append_datadir_file(
        &accepted_bitcoin_work_templates_log_path(datadir),
        "accepted Bitcoin work template log",
    )?;
    serde_json::to_writer(&mut file, &template)
        .context("failed to encode accepted Bitcoin work template")?;
    file.write_all(b"\n")
        .context("failed to append newline to accepted Bitcoin work template log")?;
    file.flush()
        .context("failed to flush accepted Bitcoin work template log")?;
    file.sync_all()
        .context("failed to sync accepted Bitcoin work template log")?;
    sync_dir(datadir)?;
    if let Some(cache) = SHARECHAIN_REPLAY_CACHE.get() {
        let mut cache = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("sharechain replay cache lock poisoned"))?;
        let cache_key = replay_cache_key(datadir);
        if let Some(entry) = cache.get_mut(&cache_key) {
            if entry.state.accept_bitcoin_work_template(&template).is_ok() {
                entry.accepted_template_stamp = accepted_bitcoin_work_templates_log_stamp(datadir)?;
            } else {
                cache.remove(&cache_key);
            }
        }
    }
    Ok(AcceptBitcoinWorkTemplateResult {
        template_hash,
        outcome: ApplyOutcome::Applied,
        accepted_template_count: existing_templates.len() + 1,
    })
}

pub fn append_gossip_envelope_file(
    datadir: &Path,
    envelope_file: &Path,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
) -> Result<AppendGossipEnvelopeResult> {
    ensure_datadir(datadir)?;
    let envelope_json = read_bounded_regular_text_file(
        envelope_file,
        "envelope file",
        MAX_SHARECHAIN_INPUT_FILE_BYTES,
    )?;
    let envelope: GossipEnvelope = serde_json::from_str(&envelope_json)
        .with_context(|| format!("failed to parse {}", envelope_file.display()))?;
    append_gossip_envelope(datadir, envelope, max_future_skew_seconds, max_age_seconds)
}

pub fn append_gossip_envelope(
    datadir: &Path,
    envelope: GossipEnvelope,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
) -> Result<AppendGossipEnvelopeResult> {
    append_gossip_envelope_with_freshness(
        datadir,
        envelope,
        max_future_skew_seconds,
        Some(max_age_seconds),
    )
}

pub fn append_historical_gossip_envelope(
    datadir: &Path,
    envelope: GossipEnvelope,
    max_future_skew_seconds: i64,
) -> Result<AppendGossipEnvelopeResult> {
    append_gossip_envelope_with_freshness(datadir, envelope, max_future_skew_seconds, None)
}

fn append_gossip_envelope_with_freshness(
    datadir: &Path,
    envelope: GossipEnvelope,
    max_future_skew_seconds: i64,
    max_age_seconds: Option<i64>,
) -> Result<AppendGossipEnvelopeResult> {
    ensure_datadir(datadir)?;
    let now = current_unix_timestamp()?;
    if let Some(max_age_seconds) = max_age_seconds {
        envelope.verify_at(now, max_future_skew_seconds, max_age_seconds)?;
    } else {
        envelope.verify_durable_at(now, max_future_skew_seconds)?;
    }
    let envelope_hash = envelope.envelope_hash();
    let peer_pubkey_xonly_hex = envelope.peer_pubkey_xonly_hex.clone();
    let message_hash = envelope.message.message_hash();
    let message = envelope.message.clone();
    let stored = validate_stored_gossip_envelope(StoredGossipEnvelope {
        envelope_hash: envelope_hash.clone(),
        message_hash: message_hash.clone(),
        peer_pubkey_xonly_hex: peer_pubkey_xonly_hex.clone(),
        envelope,
    })?;
    let _lock = acquire_append_lock(datadir)?;
    let network_id = gossip_network_id(datadir)?;
    verify_gossip_network_binding(&stored.envelope, network_id.as_deref())?;
    let envelope_exists = stored_gossip_envelope_exists_locked(datadir, &message_hash)?;
    if !envelope_exists {
        validate_gossip_persistence_limits(datadir, &stored, &message)?;
    }
    let mut message_result = append_message_locked(datadir, message, network_id.is_some())?;
    if !envelope_exists {
        append_stored_gossip_envelope_locked(datadir, stored)?;
        message_result.status.gossip_envelope_count =
            read_gossip_envelopes_with_repair(datadir, TruncatedTailRepair::Force)?.len();
    }
    Ok(AppendGossipEnvelopeResult {
        envelope_hash,
        peer_pubkey_xonly_hex,
        message_result,
    })
}

pub fn append_message(datadir: &Path, message: SharechainMessage) -> Result<AppendMessageResult> {
    ensure_datadir(datadir)?;
    let _lock = acquire_append_lock(datadir)?;
    let require_target_bound = gossip_network_id(datadir)?.is_some();
    append_message_locked(datadir, message, require_target_bound)
}

fn append_message_locked(
    datadir: &Path,
    message: SharechainMessage,
    require_target_bound: bool,
) -> Result<AppendMessageResult> {
    let bound_policy = read_bound_idena_anchor_policy(datadir)?;
    let bound_share_work_policy = read_bound_share_work_binding_policy(datadir)?;
    let cache_key = replay_cache_key(datadir);
    let cache = SHARECHAIN_REPLAY_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("sharechain replay cache lock poisoned"))?;
    let mut entry = match cache.remove(&cache_key) {
        Some(mut entry) => {
            refresh_replay_cache_entry(
                datadir,
                &mut entry,
                bound_policy.as_ref(),
                bound_share_work_policy.as_ref(),
            )?;
            entry
        }
        None => build_replay_cache_entry_with_policy(
            datadir,
            bound_policy.as_ref(),
            bound_share_work_policy.as_ref(),
        )?,
    };
    let message_hash = message.message_hash();
    if require_target_bound {
        entry.state.validate_target_bound_message(&message)?;
    }
    validate_bound_sharechain_policies(
        &entry.state,
        &message,
        bound_policy.as_ref(),
        bound_share_work_policy.as_ref(),
    )?;
    let outcome = entry.state.apply_message(&message)?;
    if outcome == ApplyOutcome::Applied {
        let mut file = open_append_datadir_file(&log_path(datadir), "sharechain log")?;
        serde_json::to_writer(&mut file, &message)
            .context("failed to encode sharechain message")?;
        file.write_all(b"\n")
            .context("failed to append newline to sharechain log")?;
        file.flush().context("failed to flush sharechain log")?;
        file.sync_all().context("failed to sync sharechain log")?;
        sync_dir(datadir)?;
        entry.message_count = entry.message_count.saturating_add(1);
    }
    entry.log_stamp = sharechain_log_stamp(datadir)?;
    entry.accepted_template_stamp = accepted_bitcoin_work_templates_log_stamp(datadir)?;
    let index = build_sharechain_index(
        datadir,
        entry.log_stamp.clone(),
        entry.accepted_template_stamp.clone(),
        bound_policy
            .as_ref()
            .map(IdenaAnchorPolicyV2::commitment_hash)
            .transpose()?,
        bound_share_work_policy
            .as_ref()
            .map(ShareWorkBindingPolicyV1::commitment_hash)
            .transpose()?,
        entry.message_count,
        &entry.state,
    )?;
    write_sharechain_index(datadir, &index)?;
    let status = LocalNodeStatus {
        datadir: datadir.to_path_buf(),
        sharechain_log: log_path(datadir),
        gossip_envelope_log: gossip_envelope_log_path(datadir),
        log_line_count: entry.message_count,
        gossip_envelope_count: read_gossip_envelopes_with_repair(
            datadir,
            TruncatedTailRepair::Force,
        )?
        .len(),
        replay: entry.state.summary(),
    };
    cache.insert(cache_key, entry);
    Ok(AppendMessageResult {
        message_hash,
        outcome,
        status,
    })
}

fn validate_gossip_persistence_limits(
    datadir: &Path,
    stored: &StoredGossipEnvelope,
    message: &SharechainMessage,
) -> Result<()> {
    let existing = read_gossip_envelopes_with_repair(datadir, TruncatedTailRepair::Force)?;
    let peer_envelope_count = existing
        .iter()
        .filter(|candidate| {
            candidate
                .peer_pubkey_xonly_hex
                .eq_ignore_ascii_case(&stored.peer_pubkey_xonly_hex)
        })
        .count();
    ensure_gossip_count_capacity(
        existing.len(),
        peer_envelope_count,
        MAX_PERSISTED_GOSSIP_ENVELOPES,
        MAX_PERSISTED_GOSSIP_ENVELOPES_PER_PEER,
    )?;

    let encoded_message =
        serde_json::to_vec(message).context("failed to encode sharechain message")?;
    let encoded_envelope =
        serde_json::to_vec(stored).context("failed to encode stored gossip envelope")?;
    ensure_record_size(
        "sharechain message",
        encoded_message.len(),
        MAX_PERSISTED_GOSSIP_RECORD_BYTES,
    )?;
    ensure_record_size(
        "stored gossip envelope",
        encoded_envelope.len(),
        MAX_PERSISTED_GOSSIP_RECORD_BYTES,
    )?;
    ensure_file_capacity(
        &log_path(datadir),
        "sharechain log",
        encoded_message.len().saturating_add(1),
        MAX_PERSISTED_SHARECHAIN_LOG_BYTES,
    )?;
    ensure_file_capacity(
        &gossip_envelope_log_path(datadir),
        "gossip envelope log",
        encoded_envelope.len().saturating_add(1),
        MAX_PERSISTED_GOSSIP_LOG_BYTES,
    )
}

fn ensure_gossip_count_capacity(
    envelope_count: usize,
    peer_envelope_count: usize,
    envelope_limit: usize,
    peer_envelope_limit: usize,
) -> Result<()> {
    if envelope_count >= envelope_limit {
        return Err(GossipPersistenceError::EnvelopeLimit {
            limit: envelope_limit,
        }
        .into());
    }
    if peer_envelope_count >= peer_envelope_limit {
        return Err(GossipPersistenceError::PeerEnvelopeLimit {
            limit: peer_envelope_limit,
        }
        .into());
    }
    Ok(())
}

fn ensure_record_size(label: &str, size: usize, limit: u64) -> Result<()> {
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    if size > limit {
        return Err(GossipPersistenceError::RecordTooLarge {
            label: label.to_string(),
            limit,
        }
        .into());
    }
    Ok(())
}

fn ensure_file_capacity(
    path: &Path,
    label: &str,
    additional_bytes: usize,
    limit: u64,
) -> Result<()> {
    let current = validate_datadir_file(path, label)?.map_or(0, |metadata| metadata.len());
    let additional = u64::try_from(additional_bytes).unwrap_or(u64::MAX);
    if !matches!(current.checked_add(additional), Some(total) if total <= limit) {
        return Err(GossipPersistenceError::ByteLimit {
            label: label.to_string(),
            limit,
        }
        .into());
    }
    Ok(())
}

pub fn local_node_status(datadir: &Path) -> Result<LocalNodeStatus> {
    local_node_status_with_repair(datadir, TruncatedTailRepair::Conservative)
}

fn local_node_status_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<LocalNodeStatus> {
    ensure_datadir(datadir)?;
    let index = sharechain_index_with_repair(datadir, repair)?;
    let envelopes = read_gossip_envelopes_with_repair(datadir, repair)?;
    Ok(LocalNodeStatus {
        datadir: datadir.to_path_buf(),
        sharechain_log: log_path(datadir),
        gossip_envelope_log: gossip_envelope_log_path(datadir),
        log_line_count: index.message_count,
        gossip_envelope_count: envelopes.len(),
        replay: index.replay,
    })
}

pub fn sharechain_index(datadir: &Path) -> Result<SharechainIndex> {
    sharechain_index_with_repair(datadir, TruncatedTailRepair::Conservative)
}

pub fn rebuild_sharechain_index(datadir: &Path) -> Result<SharechainIndex> {
    sharechain_index_with_repair(datadir, TruncatedTailRepair::Force)
}

pub fn replay_state(datadir: &Path) -> Result<SharechainReplayState> {
    ensure_datadir(datadir)?;
    let bound_policy = read_bound_idena_anchor_policy(datadir)?;
    let bound_share_work_policy = read_bound_share_work_binding_policy(datadir)?;
    let mut state = replay_state_with_accepted_bitcoin_work_templates(
        datadir,
        TruncatedTailRepair::Conservative,
    )?;
    for message in read_messages(datadir)? {
        validate_bound_sharechain_policies(
            &state,
            &message,
            bound_policy.as_ref(),
            bound_share_work_policy.as_ref(),
        )?;
        state.apply_message(&message)?;
    }
    Ok(state)
}

pub fn replay_state_with_confirmed_payouts(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
) -> Result<SharechainReplayState> {
    replay_state_with_confirmed_payouts_and_repair(
        datadir,
        snapshot_dir,
        TruncatedTailRepair::Conservative,
    )
}

pub fn append_confirmed_payout_record(
    datadir: &Path,
    input: ConfirmedPayoutAppend,
) -> Result<AppendConfirmedPayoutResult> {
    ensure_datadir(datadir)?;
    let snapshot = read_verified_snapshot(&input.snapshot_file)?;
    let snapshot_dir = input
        .snapshot_file
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let record = ConfirmedPayoutRecord::new(
        input.fork_block_height,
        input.fork_block_hash,
        input.coinbase_txid,
        input.reward_sats,
        input.direct_limit,
        input.min_direct_payout_sats,
        &snapshot,
        input.payout_schedule,
        input.pohw_commitment,
    )?
    .normalized()?;
    let record_id = record.record_id();

    let _lock = acquire_append_lock(datadir)?;
    let existing_records =
        read_confirmed_payout_records_with_repair(datadir, TruncatedTailRepair::Force)?;
    if existing_records
        .iter()
        .any(|existing| existing.record_id() == record_id)
    {
        let state = replay_state_with_confirmed_payouts_and_repair(
            datadir,
            Some(snapshot_dir),
            TruncatedTailRepair::Force,
        )?;
        return Ok(AppendConfirmedPayoutResult {
            record_id,
            outcome: ApplyOutcome::DuplicateIgnored,
            record,
            replay: state.summary(),
        });
    }
    let mut records_for_validation = existing_records;
    records_for_validation.push(record.clone());
    let state = replay_state_with_confirmed_payout_records_and_repair(
        datadir,
        Some(snapshot_dir),
        TruncatedTailRepair::Force,
        records_for_validation,
    )?;

    let mut file =
        open_append_datadir_file(&confirmed_payout_log_path(datadir), "confirmed payout log")?;
    serde_json::to_writer(&mut file, &record)
        .context("failed to encode confirmed payout record")?;
    file.write_all(b"\n")
        .context("failed to append newline to confirmed payout log")?;
    file.flush()
        .context("failed to flush confirmed payout log")?;
    file.sync_all()
        .context("failed to sync confirmed payout log")?;
    sync_dir(datadir)?;

    Ok(AppendConfirmedPayoutResult {
        record_id,
        outcome: ApplyOutcome::Applied,
        record,
        replay: state.summary(),
    })
}

pub fn gossip_inventory(datadir: &Path) -> Result<Vec<String>> {
    ensure_datadir(datadir)?;
    read_gossip_message_hashes(datadir)
}

pub fn gossip_envelope_by_message_hash(
    datadir: &Path,
    message_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    ensure_datadir(datadir)?;
    read_gossip_envelope_by_hash(datadir, message_hash)
}

pub fn gossip_envelope_by_bitcoin_template_hash(
    datadir: &Path,
    template_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    ensure_datadir(datadir)?;
    let template_hash = normalize_hash_hex("Bitcoin work template hash", template_hash)?;
    read_gossip_envelope_by_bitcoin_template_hash(datadir, &template_hash)
}

pub fn gossip_envelope_by_miner_registration_id(
    datadir: &Path,
    miner_id: &str,
) -> Result<Option<GossipEnvelope>> {
    ensure_datadir(datadir)?;
    let miner_id = normalize_miner_id_for_lookup("miner id", miner_id)?;
    read_gossip_envelope_by_miner_registration_id(datadir, &miner_id)
}

pub fn recent_gossip_envelopes(datadir: &Path, limit: usize) -> Result<Vec<StoredGossipEnvelope>> {
    ensure_datadir(datadir)?;
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut envelopes = read_gossip_envelopes(datadir)?;
    let skip = envelopes.len().saturating_sub(limit);
    Ok(envelopes.drain(skip..).collect())
}

pub fn list_gossip_peers(datadir: &Path) -> Result<Vec<GossipPeerEntry>> {
    ensure_datadir(datadir)?;
    Ok(read_gossip_peer_book(datadir)?.peers)
}

pub fn upsert_gossip_peer(
    datadir: &Path,
    addr: SocketAddr,
    source: impl Into<String>,
) -> Result<GossipPeerEntry> {
    ensure_datadir(datadir)?;
    validate_peer_addr(addr)?;
    let _lock = acquire_peer_book_lock(datadir)?;
    let mut book = read_gossip_peer_book(datadir)?;
    let now = current_unix_timestamp()?;
    let source = source.into();
    if let Some(peer) = book.peers.iter_mut().find(|peer| peer.addr == addr) {
        peer.last_seen_unix = now;
        if peer.source == "discovered" && source == "seed" {
            peer.source = source;
        }
        let entry = peer.clone();
        write_gossip_peer_book_locked(datadir, &book)?;
        return Ok(entry);
    }
    let entry = GossipPeerEntry {
        addr,
        source,
        first_seen_unix: now,
        last_seen_unix: now,
        last_success_unix: None,
        failure_count: 0,
    };
    book.peers.push(entry.clone());
    write_gossip_peer_book_locked(datadir, &book)?;
    Ok(entry)
}

pub fn record_gossip_peer_success(datadir: &Path, addr: SocketAddr) -> Result<()> {
    ensure_datadir(datadir)?;
    let _lock = acquire_peer_book_lock(datadir)?;
    let mut book = read_gossip_peer_book(datadir)?;
    let now = current_unix_timestamp()?;
    if let Some(peer) = book.peers.iter_mut().find(|peer| peer.addr == addr) {
        peer.last_seen_unix = now;
        peer.last_success_unix = Some(now);
        peer.failure_count = 0;
        write_gossip_peer_book_locked(datadir, &book)?;
    }
    Ok(())
}

pub fn record_gossip_peer_failure(datadir: &Path, addr: SocketAddr) -> Result<()> {
    ensure_datadir(datadir)?;
    let _lock = acquire_peer_book_lock(datadir)?;
    let mut book = read_gossip_peer_book(datadir)?;
    let now = current_unix_timestamp()?;
    if let Some(peer) = book.peers.iter_mut().find(|peer| peer.addr == addr) {
        peer.last_seen_unix = now;
        peer.failure_count = peer.failure_count.saturating_add(1);
        write_gossip_peer_book_locked(datadir, &book)?;
    }
    Ok(())
}

pub fn latest_verified_snapshot(snapshot_dir: &Path) -> Result<SnapshotDirectoryStatus> {
    Ok(verified_snapshot_files(snapshot_dir)?.0)
}

pub fn read_verified_snapshot(path: &Path) -> Result<Snapshot> {
    read_verified_snapshot_file(path)?
        .with_context(|| format!("snapshot file {} did not verify", path.display()))
}

pub fn apply_snapshot_scores_to_accounts(
    state: &SharechainReplayState,
    accounts: &mut [ParticipantAccount],
    snapshot: &Snapshot,
) -> Result<()> {
    snapshot.verify_score_root()?;
    let mut scores_by_idena_address = BTreeMap::new();
    for leaf in &snapshot.leaves {
        if !leaf.is_block_eligible() {
            continue;
        }
        let idena_address = leaf.idena_address.to_ascii_lowercase();
        let score = leaf.eligible_score()?;
        if let Some(existing) = scores_by_idena_address.insert(idena_address.clone(), score) {
            if existing != score {
                anyhow::bail!("snapshot contains conflicting scores for {idena_address}");
            }
        }
    }

    for account in accounts {
        let registration = state
            .registrations()
            .get(&account.miner_id)
            .with_context(|| format!("missing registration for account {}", account.miner_id))?;
        let idena_address = registration.idena_address.to_ascii_lowercase();
        let score = scores_by_idena_address
            .get(&idena_address)
            .copied()
            .unwrap_or(0);
        if score > 0 {
            registration
                .verify_idena_ownership_signature()
                .with_context(|| {
                    format!(
                        "failed to verify Idena ownership proof for miner {} at {}",
                        account.miner_id, idena_address
                    )
                })?;
        }
        account.idena_score = score;
    }
    Ok(())
}

fn verified_snapshot_files(
    snapshot_dir: &Path,
) -> Result<(SnapshotDirectoryStatus, Vec<VerifiedSnapshotFile>)> {
    let mut status = SnapshotDirectoryStatus {
        snapshot_dir: snapshot_dir.to_path_buf(),
        ..SnapshotDirectoryStatus::default()
    };
    if !snapshot_dir.exists() {
        return Ok((status, Vec::new()));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(snapshot_dir)
        .with_context(|| format!("failed to read snapshot dir {}", snapshot_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", snapshot_dir.display()))?;
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                status.invalid_file_count += 1;
                continue;
            }
        };
        if !metadata.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        paths.push((path, metadata.len()));
    }
    paths.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut snapshots = Vec::new();
    for (path, len) in paths {
        if status.scanned_file_count >= MAX_SNAPSHOT_FILES {
            status.skipped_file_count += 1;
            continue;
        }
        status.scanned_file_count += 1;
        if len > MAX_SNAPSHOT_FILE_BYTES {
            status.invalid_file_count += 1;
            continue;
        }
        let Some(snapshot) = read_verified_snapshot_file(&path)? else {
            status.invalid_file_count += 1;
            continue;
        };
        let candidate = VerifiedSnapshotFile { path, snapshot };
        snapshots.push(candidate.clone());
        let is_newest = match status.latest.as_ref() {
            Some(latest) => {
                compare_verified_snapshot_files(&candidate, latest) == Ordering::Greater
            }
            None => true,
        };
        if is_newest {
            status.latest = Some(candidate);
        }
    }

    Ok((status, snapshots))
}

fn replay_state_with_confirmed_payouts_and_repair(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    repair: TruncatedTailRepair,
) -> Result<SharechainReplayState> {
    let records = read_confirmed_payout_records_with_repair(datadir, repair)?;
    replay_state_with_confirmed_payout_records_and_repair(datadir, snapshot_dir, repair, records)
}

fn replay_state_with_confirmed_payout_records_and_repair(
    datadir: &Path,
    snapshot_dir: Option<&Path>,
    repair: TruncatedTailRepair,
    records: Vec<ConfirmedPayoutRecord>,
) -> Result<SharechainReplayState> {
    let mut state = replay_state_for_repair(datadir, repair)?;
    if records.is_empty() {
        return Ok(state);
    }
    let snapshot_dir = snapshot_dir.with_context(|| {
        format!(
            "confirmed payout replay under {} requires a snapshot directory",
            datadir.display()
        )
    })?;
    let snapshots = verified_snapshots_by_score_root(snapshot_dir)?;
    let full_sharechain_state = state.clone();
    let mut confirmed_ledger = ClaimLedger::default();
    for record in canonical_confirmed_payout_records(records)? {
        let snapshot = snapshots.get(&record.idena_score_root).with_context(|| {
            format!(
                "confirmed payout for root {} requires a verified local snapshot in {}",
                record.idena_score_root,
                snapshot_dir.display()
            )
        })?;
        validate_confirmed_payout_snapshot_binding(&record, snapshot)?;
        let mut state_at_tip = replay_state_for_confirmed_payout_commitment_with_repair(
            datadir,
            &record.pohw_commitment,
            &confirmed_ledger,
            repair,
        )?;
        validate_confirmed_payout_pohw_binding(
            &record,
            snapshot,
            &state_at_tip,
            &full_sharechain_state,
        )?;
        let mut accounts = state_at_tip.participant_accounts();
        apply_snapshot_scores_to_accounts(&state_at_tip, &mut accounts, snapshot)?;
        state_at_tip.apply_confirmed_payout_schedule(
            &record.payout_schedule,
            &accounts,
            record.reward_sats,
            record.direct_limit,
            record.min_direct_payout_sats,
        )?;
        confirmed_ledger = state_at_tip.claim_ledger().clone();
    }
    state.replace_claim_ledger(confirmed_ledger);
    Ok(state)
}

fn replay_state_for_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<SharechainReplayState> {
    ensure_datadir(datadir)?;
    let bound_policy = read_bound_idena_anchor_policy(datadir)?;
    let bound_share_work_policy = read_bound_share_work_binding_policy(datadir)?;
    let mut state = replay_state_with_accepted_bitcoin_work_templates(datadir, repair)?;
    for message in read_messages_with_repair(datadir, repair)? {
        validate_bound_sharechain_policies(
            &state,
            &message,
            bound_policy.as_ref(),
            bound_share_work_policy.as_ref(),
        )?;
        state.apply_message(&message)?;
    }
    Ok(state)
}

fn replay_state_for_confirmed_payout_commitment_with_repair(
    datadir: &Path,
    commitment: &PohwCommitment,
    confirmed_ledger: &ClaimLedger,
    repair: TruncatedTailRepair,
) -> Result<SharechainReplayState> {
    ensure_datadir(datadir)?;
    let sharechain_tip =
        normalize_hash_hex("commitment sharechain_tip", &commitment.sharechain_tip)?;
    let expected_state_root = commitment
        .sharechain_state_root
        .as_deref()
        .with_context(|| "confirmed payout commitment is missing sharechain_state_root")?;
    let expected_state_root =
        normalize_hash_hex("commitment sharechain_state_root", expected_state_root)?;

    let bound_policy = read_bound_idena_anchor_policy(datadir)?;
    let bound_share_work_policy = read_bound_share_work_binding_policy(datadir)?;
    let mut state = replay_state_with_accepted_bitcoin_work_templates(datadir, repair)?;
    for message in read_messages_with_repair(datadir, repair)? {
        validate_bound_sharechain_policies(
            &state,
            &message,
            bound_policy.as_ref(),
            bound_share_work_policy.as_ref(),
        )?;
        state.apply_message(&message)?;
        if state.best_share_tip() != Some(sharechain_tip.as_str()) {
            continue;
        }
        let mut candidate = state.clone();
        candidate.replace_claim_ledger(confirmed_ledger.clone());
        if candidate.accounting_state_root() == expected_state_root {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "sharechain state root {} at best share tip {} was not found in local log",
        expected_state_root,
        sharechain_tip
    );
}

fn replay_cache_key(datadir: &Path) -> PathBuf {
    fs::canonicalize(datadir).unwrap_or_else(|_| datadir.to_path_buf())
}

fn validate_bound_sharechain_policies(
    state: &SharechainReplayState,
    message: &SharechainMessage,
    idena_policy: Option<&IdenaAnchorPolicyV2>,
    share_work_policy: Option<&ShareWorkBindingPolicyV1>,
) -> Result<()> {
    if let Some(policy) = idena_policy {
        state.validate_idena_anchor_policy(message, policy)?;
    }
    if let Some(policy) = share_work_policy {
        state.validate_share_work_binding_policy(message, policy)?;
    }
    Ok(())
}

fn build_replay_cache_entry_with_policy(
    datadir: &Path,
    bound_policy: Option<&IdenaAnchorPolicyV2>,
    bound_share_work_policy: Option<&ShareWorkBindingPolicyV1>,
) -> Result<ReplayCacheEntry> {
    ensure_datadir(datadir)?;
    let mut state =
        replay_state_with_accepted_bitcoin_work_templates(datadir, TruncatedTailRepair::Force)?;
    let messages = read_messages_with_repair(datadir, TruncatedTailRepair::Force)?;
    for message in &messages {
        validate_bound_sharechain_policies(&state, message, bound_policy, bound_share_work_policy)?;
        state.apply_message(message)?;
    }
    Ok(ReplayCacheEntry {
        log_stamp: sharechain_log_stamp(datadir)?,
        accepted_template_stamp: accepted_bitcoin_work_templates_log_stamp(datadir)?,
        message_count: messages.len(),
        state,
    })
}

fn refresh_replay_cache_entry(
    datadir: &Path,
    entry: &mut ReplayCacheEntry,
    bound_policy: Option<&IdenaAnchorPolicyV2>,
    bound_share_work_policy: Option<&ShareWorkBindingPolicyV1>,
) -> Result<()> {
    let current_template_stamp = accepted_bitcoin_work_templates_log_stamp(datadir)?;
    let cached_template_len = entry
        .accepted_template_stamp
        .as_ref()
        .map_or(0, |stamp| stamp.len);
    let current_template_len = current_template_stamp.as_ref().map_or(0, |stamp| stamp.len);
    if current_template_len < cached_template_len
        || (current_template_len == cached_template_len
            && current_template_stamp != entry.accepted_template_stamp)
    {
        *entry =
            build_replay_cache_entry_with_policy(datadir, bound_policy, bound_share_work_policy)?;
        return Ok(());
    }
    if current_template_len > cached_template_len {
        for template in read_ndjson_tail::<BitcoinWorkTemplate>(
            &accepted_bitcoin_work_templates_log_path(datadir),
            "accepted Bitcoin work template log",
            cached_template_len,
        )? {
            entry.state.accept_bitcoin_work_template(&template)?;
        }
        entry.accepted_template_stamp = current_template_stamp;
    }

    let current_log_stamp = sharechain_log_stamp(datadir)?;
    let cached_log_len = entry.log_stamp.as_ref().map_or(0, |stamp| stamp.len);
    let current_log_len = current_log_stamp.as_ref().map_or(0, |stamp| stamp.len);
    if current_log_len < cached_log_len
        || (current_log_len == cached_log_len && current_log_stamp != entry.log_stamp)
    {
        *entry =
            build_replay_cache_entry_with_policy(datadir, bound_policy, bound_share_work_policy)?;
        return Ok(());
    }
    if current_log_len > cached_log_len {
        let messages = read_ndjson_tail::<SharechainMessage>(
            &log_path(datadir),
            "sharechain log",
            cached_log_len,
        )?;
        for message in &messages {
            validate_bound_sharechain_policies(
                &entry.state,
                message,
                bound_policy,
                bound_share_work_policy,
            )?;
            entry.state.apply_message(message)?;
        }
        entry.message_count = entry.message_count.saturating_add(messages.len());
        entry.log_stamp = current_log_stamp;
    }
    Ok(())
}

fn read_ndjson_tail<T: DeserializeOwned>(path: &Path, label: &str, offset: u64) -> Result<Vec<T>> {
    let Some(metadata) = validate_datadir_file(path, label)? else {
        if offset == 0 {
            return Ok(Vec::new());
        }
        anyhow::bail!("{label} disappeared before byte offset {offset}");
    };
    if metadata.len() < offset {
        anyhow::bail!(
            "{label} shrank from cached byte offset {offset} to {}",
            metadata.len()
        );
    }
    let mut file = File::open(path).with_context(|| format!("failed to open {label}"))?;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek {label} to byte offset {offset}"))?;
    let mut reader = BufReader::new(file);
    let mut values = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .with_context(|| format!("failed to read {label} tail"))?;
        if read == 0 {
            break;
        }
        if read > MAX_SHARECHAIN_INPUT_FILE_BYTES as usize {
            anyhow::bail!("{label} tail line exceeds maximum size");
        }
        if !line.ends_with('\n') {
            anyhow::bail!("{label} has an incomplete appended line");
        }
        if line.trim().is_empty() {
            continue;
        }
        values.push(
            serde_json::from_str(&line)
                .with_context(|| format!("failed to parse appended {label} line"))?,
        );
    }
    Ok(values)
}

fn replay_state_with_accepted_bitcoin_work_templates(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<SharechainReplayState> {
    let mut state = SharechainReplayState::default();
    for template in read_accepted_bitcoin_work_templates_with_repair(datadir, repair)? {
        state.accept_bitcoin_work_template(&template)?;
    }
    Ok(state)
}

fn verified_snapshots_by_score_root(snapshot_dir: &Path) -> Result<BTreeMap<String, Snapshot>> {
    let (_, snapshots) = verified_snapshot_files(snapshot_dir)?;
    let mut by_root = BTreeMap::new();
    for verified in snapshots {
        let root = verified.snapshot.score_root.to_ascii_lowercase();
        if let Some(existing) = by_root.insert(root.clone(), verified.snapshot.clone()) {
            if existing != verified.snapshot {
                anyhow::bail!(
                    "snapshot directory {} contains conflicting snapshots for score root {}",
                    snapshot_dir.display(),
                    root
                );
            }
        }
    }
    Ok(by_root)
}

fn read_confirmed_payout_records_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<Vec<ConfirmedPayoutRecord>> {
    let path = confirmed_payout_log_path(datadir);
    let Some(content) = read_optional_datadir_file_to_string(&path, "confirmed payout log")? else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    let mut valid_prefix_len = 0usize;
    let mut lines = content.split_inclusive('\n').enumerate().peekable();
    while let Some((idx, line)) = lines.next() {
        if line.trim().is_empty() {
            valid_prefix_len += line.len();
            continue;
        }
        let record = match serde_json::from_str::<ConfirmedPayoutRecord>(line) {
            Ok(record) => record.normalized().with_context(|| {
                format!(
                    "invalid confirmed payout record at {} line {}",
                    path.display(),
                    idx + 1
                )
            })?,
            Err(err)
                if lines.peek().is_none() && err.classify() == serde_json::error::Category::Eof =>
            {
                maybe_repair_truncated_tail(
                    datadir,
                    TruncatedTail {
                        log_label: "confirmed-payout",
                        log: &path,
                        line,
                        line_number: idx + 1,
                        valid_prefix_len,
                        err,
                    },
                    repair,
                )?;
                break;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to parse confirmed payout record at {} line {}",
                        path.display(),
                        idx + 1
                    )
                });
            }
        };
        records.push(record);
        valid_prefix_len += line.len();
    }
    Ok(records)
}

fn reject_conflicting_confirmed_payout(
    existing_records: &[ConfirmedPayoutRecord],
    candidate: &ConfirmedPayoutRecord,
) -> Result<()> {
    for existing in existing_records {
        if existing.fork_block_hash == candidate.fork_block_hash && existing != candidate {
            anyhow::bail!(
                "confirmed payout conflict: block hash {} already has another record",
                candidate.fork_block_hash
            );
        }
        if existing.coinbase_txid == candidate.coinbase_txid && existing != candidate {
            anyhow::bail!(
                "confirmed payout conflict: coinbase txid {} already has another record",
                candidate.coinbase_txid
            );
        }
        if existing.payout_schedule.payout_root == candidate.payout_schedule.payout_root
            && existing != candidate
        {
            anyhow::bail!(
                "confirmed payout conflict: payout root {} already has another record",
                candidate.payout_schedule.payout_root
            );
        }
    }
    Ok(())
}

fn canonical_confirmed_payout_records(
    records: Vec<ConfirmedPayoutRecord>,
) -> Result<Vec<ConfirmedPayoutRecord>> {
    let mut seen_record_ids = BTreeSet::new();
    let mut unique = Vec::new();
    for record in records {
        let record = record.normalized()?;
        if seen_record_ids.insert(record.record_id()) {
            unique.push(record);
        }
    }
    unique.sort_by(|left, right| {
        left.fork_block_height
            .cmp(&right.fork_block_height)
            .then_with(|| left.fork_block_hash.cmp(&right.fork_block_hash))
            .then_with(|| left.coinbase_txid.cmp(&right.coinbase_txid))
    });

    let mut ordered = Vec::with_capacity(unique.len());
    for record in unique {
        reject_conflicting_confirmed_payout(&ordered, &record)?;
        if ordered
            .last()
            .is_some_and(|previous: &ConfirmedPayoutRecord| {
                previous.fork_block_height == record.fork_block_height
            })
        {
            anyhow::bail!(
                "confirmed payout conflict: fork block height {} already has another record",
                record.fork_block_height
            );
        }
        ordered.push(record);
    }
    Ok(ordered)
}

fn validate_confirmed_payout_pohw_binding(
    record: &ConfirmedPayoutRecord,
    snapshot: &Snapshot,
    tip_state: &SharechainReplayState,
    full_sharechain_state: &SharechainReplayState,
) -> Result<()> {
    let commitment = &record.pohw_commitment;
    let identity_proof_root = snapshot
        .identity_proof_root_hex()
        .context("confirmed payout snapshot has an invalid identity proof root")?;
    let miner_idena_address = commitment.miner_idena_address.to_ascii_lowercase();
    let miner_leaf = snapshot
        .leaves
        .iter()
        .find(|leaf| {
            leaf.idena_address
                .eq_ignore_ascii_case(&miner_idena_address)
        })
        .with_context(|| {
            format!(
                "confirmed payout commitment miner {} is not in snapshot {}",
                miner_idena_address, record.idena_score_root
            )
        })?;

    validate_pohw_commitment(
        commitment,
        PohwCommitmentValidationContext {
            idena_snapshot_id: &record.idena_snapshot_day,
            idena_score_root: &record.idena_score_root,
            miner_leaf,
            identity_proof_root: &identity_proof_root,
            sharechain_tip: &commitment.sharechain_tip,
            sharechain_state_root: Some(&tip_state.accounting_state_root()),
            payout_schedule_root: &record.payout_schedule.payout_root,
            vault_epoch_id: record.vault_epoch_id,
            frost_vault_key_xonly: &record.frost_vault_key_xonly,
        },
    )
    .context("confirmed payout POHW commitment does not match local replay material")?;

    let sharechain_tip =
        normalize_hash_hex("commitment sharechain_tip", &commitment.sharechain_tip)?;
    if tip_state.best_share_tip() != Some(sharechain_tip.as_str()) {
        anyhow::bail!(
            "confirmed payout was not replayed at active best share tip {}",
            sharechain_tip
        );
    }

    let commitment_message_hash =
        SharechainMessage::PohwCommitment(commitment.clone()).message_hash();
    if !full_sharechain_state.has_message_hash(&commitment_message_hash) {
        anyhow::bail!(
            "confirmed payout commitment {} is not present in the local sharechain log",
            commitment_message_hash
        );
    }
    Ok(())
}

fn validate_confirmed_payout_snapshot_binding(
    record: &ConfirmedPayoutRecord,
    snapshot: &Snapshot,
) -> Result<()> {
    if record.idena_snapshot_day != snapshot.snapshot_day.to_string()
        || record.idena_height != snapshot.idena_height
        || record.idena_score_root != snapshot.score_root
    {
        anyhow::bail!(
            "confirmed payout snapshot binding mismatch for root {}",
            record.idena_score_root
        );
    }
    Ok(())
}

fn read_verified_snapshot_file(path: &Path) -> Result<Option<Snapshot>> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(None);
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
        return Ok(None);
    }
    let Ok(json) = fs::read_to_string(path) else {
        return Ok(None);
    };
    let snapshot = match serde_json::from_str::<Snapshot>(&json) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(None),
    };
    if snapshot.verify_score_root().is_err() {
        return Ok(None);
    }
    if snapshot
        .leaves
        .iter()
        .any(|leaf| leaf.eligible_score().is_err())
    {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

fn compare_verified_snapshot_files(
    left: &VerifiedSnapshotFile,
    right: &VerifiedSnapshotFile,
) -> Ordering {
    left.snapshot
        .snapshot_day
        .cmp(&right.snapshot.snapshot_day)
        .then_with(|| left.snapshot.idena_height.cmp(&right.snapshot.idena_height))
        .then_with(|| {
            left.snapshot
                .idena_block_hash
                .cmp(&right.snapshot.idena_block_hash)
        })
        .then_with(|| left.path.cmp(&right.path))
}

fn sharechain_index_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<SharechainIndex> {
    ensure_datadir(datadir)?;
    let bound_policy = read_bound_idena_anchor_policy(datadir)?;
    let bound_policy_hash = bound_policy
        .as_ref()
        .map(IdenaAnchorPolicyV2::commitment_hash)
        .transpose()?;
    let bound_share_work_policy = read_bound_share_work_binding_policy(datadir)?;
    let bound_share_work_policy_hash = bound_share_work_policy
        .as_ref()
        .map(ShareWorkBindingPolicyV1::commitment_hash)
        .transpose()?;
    let before_stamp = sharechain_log_stamp(datadir)?;
    let before_template_stamp = accepted_bitcoin_work_templates_log_stamp(datadir)?;
    if repair == TruncatedTailRepair::Conservative {
        if let Some(index) = read_fresh_sharechain_index(
            datadir,
            &before_stamp,
            &before_template_stamp,
            bound_policy_hash.as_deref(),
            bound_share_work_policy_hash.as_deref(),
        )? {
            return Ok(index);
        }
    }

    let messages = read_messages_with_repair(datadir, repair)?;
    let after_stamp = sharechain_log_stamp(datadir)?;
    let after_template_stamp = accepted_bitcoin_work_templates_log_stamp(datadir)?;
    let mut state = replay_state_with_accepted_bitcoin_work_templates(datadir, repair)?;
    for message in &messages {
        validate_bound_sharechain_policies(
            &state,
            message,
            bound_policy.as_ref(),
            bound_share_work_policy.as_ref(),
        )?;
        state.apply_message(message)?;
    }
    let index = build_sharechain_index(
        datadir,
        after_stamp,
        after_template_stamp,
        bound_policy_hash,
        bound_share_work_policy_hash,
        messages.len(),
        &state,
    )?;
    write_sharechain_index(datadir, &index)?;
    Ok(index)
}

fn build_sharechain_index(
    datadir: &Path,
    log_stamp: Option<SharechainLogStamp>,
    accepted_bitcoin_work_templates_log_stamp: Option<SharechainLogStamp>,
    idena_anchor_policy_hash: Option<String>,
    share_work_binding_policy_hash: Option<String>,
    message_count: usize,
    state: &SharechainReplayState,
) -> Result<SharechainIndex> {
    Ok(SharechainIndex {
        schema_version: 4,
        generated_at_unix: current_unix_timestamp()?,
        sharechain_log: log_path(datadir),
        log_stamp,
        accepted_bitcoin_work_templates_log_stamp,
        idena_anchor_policy_hash,
        share_work_binding_policy_hash,
        message_count,
        replay: state.summary(),
        registrations_by_miner: state.registrations().clone(),
        hashrate_scores_by_miner: state.hashrate_scores().clone(),
        claim_balances_by_owner: state.claim_balances(),
        participant_accounts: state.participant_accounts(),
    })
}

fn read_fresh_sharechain_index(
    datadir: &Path,
    log_stamp: &Option<SharechainLogStamp>,
    accepted_bitcoin_work_templates_log_stamp: &Option<SharechainLogStamp>,
    idena_anchor_policy_hash: Option<&str>,
    share_work_binding_policy_hash: Option<&str>,
) -> Result<Option<SharechainIndex>> {
    let path = sharechain_index_path(datadir);
    let Some(json) = read_optional_datadir_file_to_string(&path, "sharechain index")? else {
        return Ok(None);
    };
    let index: SharechainIndex = match serde_json::from_str(&json) {
        Ok(index) => index,
        Err(_) => return Ok(None),
    };
    if index.schema_version != 4
        || &index.log_stamp != log_stamp
        || &index.accepted_bitcoin_work_templates_log_stamp
            != accepted_bitcoin_work_templates_log_stamp
        || index.idena_anchor_policy_hash.as_deref() != idena_anchor_policy_hash
        || index.share_work_binding_policy_hash.as_deref() != share_work_binding_policy_hash
    {
        return Ok(None);
    }
    Ok(Some(index))
}

fn create_random_temp_file(datadir: &Path, label: &str) -> Result<(PathBuf, File)> {
    for _ in 0..8 {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let tmp_path = datadir.join(format!("{label}.{}.tmp", hex::encode(nonce)));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create {}", tmp_path.display()));
            }
        }
    }
    anyhow::bail!("failed to allocate unique temporary file for {label}");
}

fn write_sharechain_index(datadir: &Path, index: &SharechainIndex) -> Result<()> {
    let path = sharechain_index_path(datadir);
    let (tmp_path, mut file) = create_random_temp_file(datadir, SHARECHAIN_INDEX_FILE)?;
    serde_json::to_writer_pretty(&mut file, index).context("failed to encode sharechain index")?;
    file.write_all(b"\n")
        .context("failed to append newline to sharechain index")?;
    file.flush().context("failed to flush sharechain index")?;
    file.sync_all().context("failed to sync sharechain index")?;
    fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "failed to replace sharechain index {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    sync_dir(datadir)?;
    Ok(())
}

fn sharechain_log_stamp(datadir: &Path) -> Result<Option<SharechainLogStamp>> {
    file_log_stamp(&log_path(datadir))
}

fn accepted_bitcoin_work_templates_log_stamp(datadir: &Path) -> Result<Option<SharechainLogStamp>> {
    file_log_stamp(&accepted_bitcoin_work_templates_log_path(datadir))
}

fn file_log_stamp(path: &Path) -> Result<Option<SharechainLogStamp>> {
    match validate_datadir_file(path, "sharechain log stamp")? {
        Some(metadata) => Ok(Some(SharechainLogStamp {
            len: metadata.len(),
            modified_unix_nanos: metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos().to_string()),
        })),
        None => Ok(None),
    }
}

fn validate_datadir_file(path: &Path, label: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("{label} {} must not be a symlink", path.display());
            }
            if !metadata.is_file() {
                anyhow::bail!("{label} path {} is not a regular file", path.display());
            }
            Ok(Some(metadata))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
}

fn read_optional_datadir_file_to_string(path: &Path, label: &str) -> Result<Option<String>> {
    if validate_datadir_file(path, label)?.is_none() {
        return Ok(None);
    }
    fs::read_to_string(path)
        .map(Some)
        .with_context(|| format!("failed to read {label} {}", path.display()))
}

fn open_append_datadir_file(path: &Path, label: &str) -> Result<File> {
    match validate_datadir_file(path, label)? {
        Some(_) => OpenOptions::new()
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open {label} {}", path.display())),
        None => {
            let mut options = OpenOptions::new();
            options.write(true).append(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(file) => Ok(file),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    open_append_datadir_file(path, label)
                }
                Err(err) => {
                    Err(err).with_context(|| format!("failed to create {label} {}", path.display()))
                }
            }
        }
    }
}

pub fn read_bitcoin_work_template_file(path: &Path) -> Result<BitcoinWorkTemplate> {
    let json = read_bounded_regular_text_file(
        path,
        "Bitcoin work template",
        MAX_SHARECHAIN_INPUT_FILE_BYTES,
    )?;
    if let Ok(template) = serde_json::from_str::<BitcoinWorkTemplate>(&json) {
        template.verify_template_hash()?;
        return Ok(template.normalized());
    }
    match serde_json::from_str::<SharechainMessage>(&json)
        .with_context(|| format!("failed to parse Bitcoin work template {}", path.display()))?
    {
        SharechainMessage::BitcoinWorkTemplate(template) => {
            template.verify_template_hash()?;
            Ok(template.normalized())
        }
        other => anyhow::bail!(
            "expected BitcoinWorkTemplate file {}, got {}",
            path.display(),
            sharechain_message_type(&other)
        ),
    }
}

fn read_bounded_regular_text_file(path: &Path, label: &str, max_bytes: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("{label} {} must not be a symlink", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        anyhow::bail!(
            "{label} {} is {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            max_bytes
        );
    }
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn sharechain_message_type(message: &SharechainMessage) -> &'static str {
    match message {
        SharechainMessage::MinerRegistration(_) => "MinerRegistration",
        SharechainMessage::BitcoinWorkTemplate(_) => "BitcoinWorkTemplate",
        SharechainMessage::Share(_) => "Share",
        SharechainMessage::SharechainCheckpoint(_) => "SharechainCheckpoint",
        SharechainMessage::SnapshotVote(_) => "SnapshotVote",
        SharechainMessage::PayoutSchedule(_) => "PayoutSchedule",
        SharechainMessage::WithdrawalRequest(_) => "WithdrawalRequest",
        SharechainMessage::WithdrawalBatch(_) => "WithdrawalBatch",
        SharechainMessage::PohwCommitment(_) => "PohwCommitment",
    }
}

fn read_accepted_bitcoin_work_templates_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<Vec<BitcoinWorkTemplate>> {
    let path = accepted_bitcoin_work_templates_log_path(datadir);
    let Some(content) =
        read_optional_datadir_file_to_string(&path, "accepted Bitcoin work template log")?
    else {
        return Ok(Vec::new());
    };
    let mut templates = Vec::new();
    let mut valid_prefix_len = 0usize;
    let mut lines = content.split_inclusive('\n').enumerate().peekable();
    while let Some((idx, line)) = lines.next() {
        if line.trim().is_empty() {
            valid_prefix_len += line.len();
            continue;
        }
        let template = match serde_json::from_str::<BitcoinWorkTemplate>(line) {
            Ok(template) => template,
            Err(err)
                if lines.peek().is_none() && err.classify() == serde_json::error::Category::Eof =>
            {
                maybe_repair_truncated_tail(
                    datadir,
                    TruncatedTail {
                        log_label: "accepted-bitcoin-work-template",
                        log: &path,
                        line,
                        line_number: idx + 1,
                        valid_prefix_len,
                        err,
                    },
                    repair,
                )?;
                break;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to parse accepted Bitcoin work template at {} line {}",
                        path.display(),
                        idx + 1
                    )
                });
            }
        };
        template.verify_template_hash().with_context(|| {
            format!(
                "invalid accepted Bitcoin work template at {} line {}",
                path.display(),
                idx + 1
            )
        })?;
        templates.push(template.normalized());
        valid_prefix_len += line.len();
    }
    Ok(templates)
}

fn read_messages(datadir: &Path) -> Result<Vec<SharechainMessage>> {
    read_messages_with_repair(datadir, TruncatedTailRepair::Conservative)
}

fn read_messages_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<Vec<SharechainMessage>> {
    let path = log_path(datadir);
    let Some(content) = read_optional_datadir_file_to_string(&path, "sharechain log")? else {
        return Ok(Vec::new());
    };
    let mut messages = Vec::new();
    let mut valid_prefix_len = 0usize;
    let mut lines = content.split_inclusive('\n').enumerate().peekable();
    while let Some((idx, line)) = lines.next() {
        if line.trim().is_empty() {
            valid_prefix_len += line.len();
            continue;
        }
        let message = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(err)
                if lines.peek().is_none() && err.classify() == serde_json::error::Category::Eof =>
            {
                maybe_repair_truncated_tail(
                    datadir,
                    TruncatedTail {
                        log_label: "sharechain",
                        log: &path,
                        line,
                        line_number: idx + 1,
                        valid_prefix_len,
                        err,
                    },
                    repair,
                )?;
                break;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to parse sharechain message at {} line {}",
                        path.display(),
                        idx + 1
                    )
                });
            }
        };
        messages.push(message);
        valid_prefix_len += line.len();
    }
    Ok(messages)
}

fn read_gossip_envelopes(datadir: &Path) -> Result<Vec<StoredGossipEnvelope>> {
    read_gossip_envelopes_with_repair(datadir, TruncatedTailRepair::Conservative)
}

fn read_gossip_message_hashes(datadir: &Path) -> Result<Vec<String>> {
    let cache_key = datadir.to_path_buf();
    let before_stamp = gossip_envelope_log_stamp(datadir)?;
    if let Some(message_hashes) = cached_gossip_message_hashes(&cache_key, &before_stamp)? {
        return Ok(message_hashes);
    }

    let envelopes = read_gossip_envelopes_uncached(datadir, TruncatedTailRepair::Conservative)?;
    let message_hashes = envelopes
        .iter()
        .map(|stored| stored.message_hash.clone())
        .collect();
    let after_stamp = gossip_envelope_log_stamp(datadir)?;
    update_gossip_envelope_cache(cache_key, after_stamp, envelopes)?;
    Ok(message_hashes)
}

fn read_gossip_envelope_by_hash(
    datadir: &Path,
    message_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    let message_hash = normalize_hash_hex("gossip message hash", message_hash)?;
    let cache_key = datadir.to_path_buf();
    let before_stamp = gossip_envelope_log_stamp(datadir)?;
    if let Some(envelope) =
        cached_gossip_envelope_by_message_hash(&cache_key, &before_stamp, &message_hash)?
    {
        return Ok(envelope);
    }

    let envelopes = read_gossip_envelopes_uncached(datadir, TruncatedTailRepair::Conservative)?;
    let envelope = envelopes
        .iter()
        .find(|stored| stored.message_hash == message_hash)
        .map(|stored| stored.envelope.clone());
    let after_stamp = gossip_envelope_log_stamp(datadir)?;
    update_gossip_envelope_cache(cache_key, after_stamp, envelopes)?;
    Ok(envelope)
}

fn read_gossip_envelopes_with_repair(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<Vec<StoredGossipEnvelope>> {
    let cache_key = datadir.to_path_buf();
    let before_stamp = gossip_envelope_log_stamp(datadir)?;
    if repair == TruncatedTailRepair::Conservative {
        if let Some(envelopes) = cached_gossip_envelopes(&cache_key, &before_stamp)? {
            return Ok(envelopes);
        }
    }

    let envelopes = read_gossip_envelopes_uncached(datadir, repair)?;
    let after_stamp = gossip_envelope_log_stamp(datadir)?;
    update_gossip_envelope_cache(cache_key, after_stamp, envelopes.clone())?;
    Ok(envelopes)
}

fn read_gossip_envelopes_uncached(
    datadir: &Path,
    repair: TruncatedTailRepair,
) -> Result<Vec<StoredGossipEnvelope>> {
    let path = gossip_envelope_log_path(datadir);
    let network_id = gossip_network_id(datadir)?;
    let Some(content) = read_optional_datadir_file_to_string(&path, "gossip envelope log")? else {
        return Ok(Vec::new());
    };
    let mut envelopes = Vec::new();
    let mut seen_message_hashes = BTreeSet::new();
    let mut valid_prefix_len = 0usize;
    let mut lines = content.split_inclusive('\n').enumerate().peekable();
    while let Some((idx, line)) = lines.next() {
        if line.trim().is_empty() {
            valid_prefix_len += line.len();
            continue;
        }
        let stored = match serde_json::from_str(line) {
            Ok(stored) => stored,
            Err(err)
                if lines.peek().is_none() && err.classify() == serde_json::error::Category::Eof =>
            {
                maybe_repair_truncated_tail(
                    datadir,
                    TruncatedTail {
                        log_label: "gossip-envelope",
                        log: &path,
                        line,
                        line_number: idx + 1,
                        valid_prefix_len,
                        err,
                    },
                    repair,
                )?;
                break;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to parse gossip envelope record at {} line {}",
                        path.display(),
                        idx + 1
                    )
                });
            }
        };
        let stored = validate_stored_gossip_envelope(stored).with_context(|| {
            format!(
                "invalid gossip envelope record at {} line {}",
                path.display(),
                idx + 1
            )
        })?;
        verify_gossip_network_binding(&stored.envelope, network_id.as_deref()).with_context(
            || {
                format!(
                    "gossip network binding failed at {} line {}",
                    path.display(),
                    idx + 1
                )
            },
        )?;
        if seen_message_hashes.insert(stored.message_hash.clone()) {
            envelopes.push(stored);
        }
        valid_prefix_len += line.len();
    }
    Ok(envelopes)
}

fn gossip_envelope_log_stamp(datadir: &Path) -> Result<Option<GossipEnvelopeLogStamp>> {
    let path = gossip_envelope_log_path(datadir);
    let network_id = gossip_network_id(datadir)?;
    match validate_datadir_file(&path, "gossip envelope log stamp")? {
        Some(metadata) => Ok(Some(GossipEnvelopeLogStamp {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            network_id,
        })),
        None => Ok(None),
    }
}

fn verify_gossip_network_binding(
    envelope: &GossipEnvelope,
    expected_network_id: Option<&str>,
) -> Result<()> {
    match expected_network_id {
        Some(network_id) => envelope
            .verify_network(network_id)
            .context("gossip envelope is not bound to the datadir network"),
        None if envelope.protocol_version == GOSSIP_PROTOCOL_VERSION => Ok(()),
        None => anyhow::bail!(
            "network-bound gossip envelope requires an initialized gossip network datadir"
        ),
    }
}

fn cached_gossip_envelopes(
    cache_key: &Path,
    stamp: &Option<GossipEnvelopeLogStamp>,
) -> Result<Option<Vec<StoredGossipEnvelope>>> {
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    Ok(cache
        .get(cache_key)
        .filter(|entry| &entry.stamp == stamp)
        .map(|entry| entry.envelopes.clone()))
}

fn cached_gossip_message_hashes(
    cache_key: &Path,
    stamp: &Option<GossipEnvelopeLogStamp>,
) -> Result<Option<Vec<String>>> {
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    Ok(cache
        .get(cache_key)
        .filter(|entry| &entry.stamp == stamp)
        .map(|entry| entry.message_hashes.clone()))
}

fn cached_gossip_envelope_by_message_hash(
    cache_key: &Path,
    stamp: &Option<GossipEnvelopeLogStamp>,
    message_hash: &str,
) -> Result<Option<Option<GossipEnvelope>>> {
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    Ok(cache
        .get(cache_key)
        .filter(|entry| &entry.stamp == stamp)
        .map(|entry| entry.envelopes_by_message_hash.get(message_hash).cloned()))
}

fn cached_gossip_envelope_by_bitcoin_template_hash(
    cache_key: &Path,
    stamp: &Option<GossipEnvelopeLogStamp>,
    template_hash: &str,
) -> Result<Option<Option<GossipEnvelope>>> {
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    Ok(cache
        .get(cache_key)
        .filter(|entry| &entry.stamp == stamp)
        .map(|entry| {
            entry
                .envelopes_by_bitcoin_template_hash
                .get(template_hash)
                .cloned()
        }))
}

fn cached_gossip_envelope_by_miner_registration_id(
    cache_key: &Path,
    stamp: &Option<GossipEnvelopeLogStamp>,
    miner_id: &str,
) -> Result<Option<Option<GossipEnvelope>>> {
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    Ok(cache
        .get(cache_key)
        .filter(|entry| &entry.stamp == stamp)
        .map(|entry| {
            entry
                .envelopes_by_miner_registration_id
                .get(miner_id)
                .cloned()
        }))
}

fn read_gossip_envelope_by_bitcoin_template_hash(
    datadir: &Path,
    template_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    let cache_key = datadir.to_path_buf();
    let before_stamp = gossip_envelope_log_stamp(datadir)?;
    if let Some(envelope) =
        cached_gossip_envelope_by_bitcoin_template_hash(&cache_key, &before_stamp, template_hash)?
    {
        return Ok(envelope);
    }

    let envelopes = read_gossip_envelopes_uncached(datadir, TruncatedTailRepair::Conservative)?;
    let envelope = envelopes.iter().find_map(|stored| {
        if let SharechainMessage::BitcoinWorkTemplate(template) = &stored.envelope.message {
            if template.template_hash.eq_ignore_ascii_case(template_hash) {
                return Some(stored.envelope.clone());
            }
        }
        None
    });
    let after_stamp = gossip_envelope_log_stamp(datadir)?;
    update_gossip_envelope_cache(cache_key, after_stamp, envelopes)?;
    Ok(envelope)
}

fn read_gossip_envelope_by_miner_registration_id(
    datadir: &Path,
    miner_id: &str,
) -> Result<Option<GossipEnvelope>> {
    let cache_key = datadir.to_path_buf();
    let before_stamp = gossip_envelope_log_stamp(datadir)?;
    if let Some(envelope) =
        cached_gossip_envelope_by_miner_registration_id(&cache_key, &before_stamp, miner_id)?
    {
        return Ok(envelope);
    }

    let envelopes = read_gossip_envelopes_uncached(datadir, TruncatedTailRepair::Conservative)?;
    let envelope = envelopes.iter().find_map(|stored| {
        if let SharechainMessage::MinerRegistration(registration) = &stored.envelope.message {
            if registration.miner_id.eq_ignore_ascii_case(miner_id) {
                return Some(stored.envelope.clone());
            }
        }
        None
    });
    let after_stamp = gossip_envelope_log_stamp(datadir)?;
    update_gossip_envelope_cache(cache_key, after_stamp, envelopes)?;
    Ok(envelope)
}

fn update_gossip_envelope_cache(
    cache_key: PathBuf,
    stamp: Option<GossipEnvelopeLogStamp>,
    envelopes: Vec<StoredGossipEnvelope>,
) -> Result<()> {
    let message_hashes = envelopes
        .iter()
        .map(|stored| stored.message_hash.clone())
        .collect();
    let envelopes_by_message_hash = envelopes
        .iter()
        .map(|stored| (stored.message_hash.clone(), stored.envelope.clone()))
        .collect();
    let mut envelopes_by_bitcoin_template_hash = BTreeMap::new();
    let mut envelopes_by_miner_registration_id = BTreeMap::new();
    for stored in &envelopes {
        match &stored.envelope.message {
            SharechainMessage::BitcoinWorkTemplate(template) => {
                envelopes_by_bitcoin_template_hash
                    .entry(template.template_hash.to_ascii_lowercase())
                    .or_insert_with(|| stored.envelope.clone());
            }
            SharechainMessage::MinerRegistration(registration) => {
                envelopes_by_miner_registration_id
                    .entry(registration.miner_id.to_ascii_lowercase())
                    .or_insert_with(|| stored.envelope.clone());
            }
            _ => {}
        }
    }
    let cache = GOSSIP_ENVELOPE_CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("gossip envelope cache lock poisoned"))?;
    cache.insert(
        cache_key,
        GossipEnvelopeCacheEntry {
            stamp,
            envelopes,
            message_hashes,
            envelopes_by_message_hash,
            envelopes_by_bitcoin_template_hash,
            envelopes_by_miner_registration_id,
        },
    );
    Ok(())
}

fn validate_stored_gossip_envelope(
    mut stored: StoredGossipEnvelope,
) -> Result<StoredGossipEnvelope> {
    stored.envelope_hash = stored.envelope_hash.to_ascii_lowercase();
    stored.message_hash = stored.message_hash.to_ascii_lowercase();
    stored.peer_pubkey_xonly_hex = stored.peer_pubkey_xonly_hex.to_ascii_lowercase();
    stored.envelope.peer_pubkey_xonly_hex =
        stored.envelope.peer_pubkey_xonly_hex.to_ascii_lowercase();
    stored.envelope.nonce_hex = stored.envelope.nonce_hex.to_ascii_lowercase();
    if let Some(signature_hex) = &mut stored.envelope.signature_hex {
        *signature_hex = signature_hex.to_ascii_lowercase();
    }
    stored
        .envelope
        .verify_signature()
        .context("stored gossip envelope signature is invalid")?;
    let expected_envelope_hash = stored.envelope.envelope_hash();
    if stored.envelope_hash != expected_envelope_hash {
        anyhow::bail!(
            "stored gossip envelope hash {} does not match envelope hash {}",
            stored.envelope_hash,
            expected_envelope_hash
        );
    }
    let expected_message_hash = stored.envelope.message.message_hash();
    if stored.message_hash != expected_message_hash {
        anyhow::bail!(
            "stored gossip message hash {} does not match envelope message hash {}",
            stored.message_hash,
            expected_message_hash
        );
    }
    let expected_peer_pubkey = stored.envelope.peer_pubkey_xonly_hex.to_ascii_lowercase();
    if stored.peer_pubkey_xonly_hex != expected_peer_pubkey {
        anyhow::bail!(
            "stored gossip peer pubkey {} does not match envelope peer pubkey {}",
            stored.peer_pubkey_xonly_hex,
            expected_peer_pubkey
        );
    }
    Ok(stored)
}

fn stored_gossip_envelope_exists_locked(datadir: &Path, message_hash: &str) -> Result<bool> {
    let message_hash = message_hash.to_ascii_lowercase();
    Ok(
        read_gossip_envelopes_with_repair(datadir, TruncatedTailRepair::Force)?
            .iter()
            .any(|stored| stored.message_hash == message_hash),
    )
}

fn read_gossip_peer_book(datadir: &Path) -> Result<GossipPeerBook> {
    let path = gossip_peers_path(datadir);
    let Some(json) = read_optional_datadir_file_to_string(&path, "gossip peer book")? else {
        return Ok(GossipPeerBook::default());
    };
    let mut book: GossipPeerBook = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    sort_and_dedup_gossip_peers(&mut book);
    Ok(book)
}

fn write_gossip_peer_book_locked(datadir: &Path, book: &GossipPeerBook) -> Result<()> {
    let mut book = book.clone();
    sort_and_dedup_gossip_peers(&mut book);
    let path = gossip_peers_path(datadir);
    let (tmp_path, mut file) = create_random_temp_file(datadir, GOSSIP_PEERS_FILE)?;
    serde_json::to_writer_pretty(&mut file, &book).context("failed to encode gossip peer book")?;
    file.write_all(b"\n")
        .context("failed to append newline to gossip peer book")?;
    file.flush().context("failed to flush gossip peer book")?;
    file.sync_all().context("failed to sync gossip peer book")?;
    fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "failed to replace gossip peer book {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    sync_dir(datadir)?;
    Ok(())
}

fn sort_and_dedup_gossip_peers(book: &mut GossipPeerBook) {
    let mut peers = BTreeMap::<SocketAddr, GossipPeerEntry>::new();
    for peer in book.peers.drain(..) {
        peers
            .entry(peer.addr)
            .and_modify(|existing| {
                existing.first_seen_unix = existing.first_seen_unix.min(peer.first_seen_unix);
                existing.last_seen_unix = existing.last_seen_unix.max(peer.last_seen_unix);
                existing.last_success_unix = existing
                    .last_success_unix
                    .into_iter()
                    .chain(peer.last_success_unix)
                    .max();
                existing.failure_count = existing.failure_count.min(peer.failure_count);
                if existing.source == "discovered" && peer.source == "seed" {
                    existing.source = peer.source.clone();
                }
            })
            .or_insert(peer);
    }
    book.peers = peers.into_values().collect();
    book.peers.sort_by(|left, right| {
        peer_retention_rank(right)
            .cmp(&peer_retention_rank(left))
            .then_with(|| left.addr.cmp(&right.addr))
    });
    book.peers.truncate(MAX_GOSSIP_PEERS);
    book.peers.sort_by_key(|peer| peer.addr);
}

fn peer_retention_rank(peer: &GossipPeerEntry) -> (u8, u8, i64, i64) {
    let source_rank = u8::from(peer.source == "seed");
    let success_rank = u8::from(peer.last_success_unix.is_some());
    let failure_rank = i64::from(u32::MAX.saturating_sub(peer.failure_count));
    (
        source_rank,
        success_rank,
        failure_rank,
        peer.last_success_unix.unwrap_or(peer.last_seen_unix),
    )
}

fn validate_peer_addr(addr: SocketAddr) -> Result<()> {
    if addr.port() == 0 {
        anyhow::bail!("gossip peer address {addr} has invalid port 0");
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                anyhow::bail!("gossip peer address {addr} is not a usable unicast address");
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_unspecified() || ip.is_multicast() {
                anyhow::bail!("gossip peer address {addr} is not a usable unicast address");
            }
        }
    }
    Ok(())
}

fn ensure_datadir(datadir: &Path) -> Result<()> {
    prepare_datadir_dir(datadir)
        .with_context(|| format!("failed to prepare node datadir {}", datadir.display()))
}

fn prepare_datadir_dir(path: &Path) -> Result<()> {
    validate_no_unsafe_symlink_ancestors(path, "node datadir")?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("node datadir {} must not be a symlink", path.display());
            }
            if !metadata.is_dir() {
                anyhow::bail!("node datadir path {} is not a directory", path.display());
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if let Some(parent) = non_empty_parent(path) {
                if parent != path {
                    prepare_datadir_dir(parent)?;
                }
            }
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => prepare_datadir_dir(path),
                Err(err) => Err(err)
                    .with_context(|| format!("failed to create node datadir {}", path.display())),
            }
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect node datadir {}", path.display()))
        }
    }
}

#[cfg(unix)]
fn validate_no_unsafe_symlink_ancestors(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for local node path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect {label} symlink ancestor {}",
                        ancestor.display()
                    )
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = ancestor.parent().unwrap_or_else(|| Path::new("/"));
        let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect {label} symlink ancestor parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            anyhow::bail!(
                "{label} {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_symlink_ancestors(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn append_stored_gossip_envelope_locked(
    datadir: &Path,
    stored: StoredGossipEnvelope,
) -> Result<()> {
    let mut file =
        open_append_datadir_file(&gossip_envelope_log_path(datadir), "gossip envelope log")?;
    serde_json::to_writer(&mut file, &stored).context("failed to encode gossip envelope record")?;
    file.write_all(b"\n")
        .context("failed to append newline to gossip envelope log")?;
    file.flush()
        .context("failed to flush gossip envelope log")?;
    file.sync_all()
        .context("failed to sync gossip envelope log")?;
    sync_dir(datadir)?;
    Ok(())
}

fn log_path(datadir: &Path) -> PathBuf {
    datadir.join(SHARECHAIN_LOG)
}

fn accepted_bitcoin_work_templates_log_path(datadir: &Path) -> PathBuf {
    datadir.join(ACCEPTED_BITCOIN_WORK_TEMPLATES_LOG)
}

fn sharechain_index_path(datadir: &Path) -> PathBuf {
    datadir.join(SHARECHAIN_INDEX_FILE)
}

fn confirmed_payout_log_path(datadir: &Path) -> PathBuf {
    datadir.join(CONFIRMED_PAYOUT_LOG)
}

fn gossip_envelope_log_path(datadir: &Path) -> PathBuf {
    datadir.join(GOSSIP_ENVELOPE_LOG)
}

fn gossip_network_id_path(datadir: &Path) -> PathBuf {
    datadir.join(GOSSIP_NETWORK_ID_FILE)
}

fn gossip_peers_path(datadir: &Path) -> PathBuf {
    datadir.join(GOSSIP_PEERS_FILE)
}

fn idena_anchor_policy_path(datadir: &Path) -> PathBuf {
    datadir.join(IDENA_ANCHOR_POLICY_FILE)
}

fn share_work_binding_policy_path(datadir: &Path) -> PathBuf {
    datadir.join(SHARE_WORK_BINDING_POLICY_FILE)
}

fn lock_path(datadir: &Path) -> PathBuf {
    datadir.join(APPEND_LOCK)
}

fn peer_book_lock_path(datadir: &Path) -> PathBuf {
    datadir.join(GOSSIP_PEERS_LOCK)
}

fn current_unix_timestamp() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(duration.as_secs()).context("system timestamp does not fit in i64")
}

fn normalize_hash_hex(field: &str, value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be 32 bytes encoded as 64 hex characters");
    }
    Ok(value)
}

fn normalize_script_hex(field: &str, value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("{field} must be non-empty even-length hex");
    }
    Ok(value)
}

fn normalize_miner_id_for_lookup(field: &str, value: &str) -> Result<String> {
    const MAX_MINER_ID_LEN: usize = 64;
    let value = value.to_ascii_lowercase();
    if value.is_empty() || value.len() > MAX_MINER_ID_LEN {
        anyhow::bail!("{field} length must be 1..={MAX_MINER_ID_LEN}");
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("{field} may only contain ASCII letters, digits, '-', '_', and '.'");
    }
    Ok(value)
}

fn acquire_append_lock(datadir: &Path) -> Result<AppendLock> {
    acquire_lock(
        datadir,
        lock_path(datadir),
        "sharechain append",
        APPEND_LOCK_ATTEMPTS,
    )
}

fn acquire_peer_book_lock(datadir: &Path) -> Result<AppendLock> {
    acquire_lock(
        datadir,
        peer_book_lock_path(datadir),
        "gossip peer book",
        40,
    )
}

fn acquire_lock(datadir: &Path, path: PathBuf, label: &str, attempts: usize) -> Result<AppendLock> {
    remove_stale_lock(&path, label)?;
    let attempts = attempts.max(1);
    for attempt in 0..attempts {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let owner_token = format!("{} {}", std::process::id(), current_unix_timestamp()?);
                file.write_all(owner_token.as_bytes())
                    .with_context(|| format!("failed to write {label} lock"))?;
                file.sync_all()
                    .with_context(|| format!("failed to sync {label} lock"))?;
                sync_dir(datadir)?;
                return Ok(AppendLock { path, owner_token });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if attempt + 1 < attempts {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                return Err(LocalAppendError::LockBusy {
                    label: label.to_string(),
                    path,
                }
                .into());
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to create {}", path.display()))
            }
        }
    }
    unreachable!("lock acquisition attempts is always at least one")
}

struct AppendLock {
    path: PathBuf,
    owner_token: String,
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).is_ok_and(|value| value.trim() == self.owner_token)
            && fs::remove_file(&self.path).is_ok()
        {
            if let Some(parent) = self.path.parent() {
                let _ = sync_dir(parent);
            }
        }
    }
}

fn remove_stale_lock(path: &Path, label: &str) -> Result<()> {
    let Some(metadata) = lock_file_metadata(path, label)? else {
        return Ok(());
    };
    if let Ok(lock_text) = fs::read_to_string(path) {
        if let Some((_, created_at_raw)) = lock_text.trim().split_once(' ') {
            if let Ok(created_at_unix) = created_at_raw.parse::<i64>() {
                let now = current_unix_timestamp()?;
                if now.saturating_sub(created_at_unix)
                    >= i64::try_from(STALE_APPEND_LOCK_SECONDS).unwrap_or(i64::MAX)
                {
                    if lock_owner_is_alive(&lock_text) {
                        return Ok(());
                    }
                    fs::remove_file(path).with_context(|| {
                        format!("failed to remove stale {label} lock {}", path.display())
                    })?;
                    return Ok(());
                }
            }
        }
    }
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    if age.is_some_and(|age| age >= Duration::from_secs(STALE_APPEND_LOCK_SECONDS)) {
        if fs::read_to_string(path).is_ok_and(|lock_text| lock_owner_is_alive(&lock_text)) {
            return Ok(());
        }
        fs::remove_file(path)
            .with_context(|| format!("failed to remove stale {label} lock {}", path.display()))?;
    }
    Ok(())
}

fn lock_owner_is_alive(lock_text: &str) -> bool {
    let Some(pid) = lock_text
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
}

fn lock_file_metadata(path: &Path, label: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("{label} lock {} must not be a symlink", path.display());
            }
            if !metadata.is_file() {
                anyhow::bail!("{label} lock {} is not a regular file", path.display());
            }
            Ok(Some(metadata))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect {label} lock {}", path.display()))
        }
    }
}

struct TruncatedTail<'a> {
    log_label: &'a str,
    log: &'a Path,
    line: &'a str,
    line_number: usize,
    valid_prefix_len: usize,
    err: serde_json::Error,
}

fn quarantine_truncated_tail(datadir: &Path, tail: TruncatedTail<'_>) -> Result<()> {
    let corrupt_dir = datadir.join(CORRUPT_LOG_DIR);
    prepare_datadir_dir(&corrupt_dir)
        .with_context(|| format!("failed to prepare {}", corrupt_dir.display()))?;
    let (quarantine_path, mut file) =
        create_truncated_tail_quarantine_file(&corrupt_dir, tail.log_label, tail.line_number)?;
    file.write_all(tail.line.as_bytes()).with_context(|| {
        format!(
            "failed to write truncated {} tail {}",
            tail.log_label,
            quarantine_path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "failed to sync truncated {} tail {}",
            tail.log_label,
            quarantine_path.display()
        )
    })?;
    sync_dir(&corrupt_dir)?;
    truncate_log(tail.log, tail.valid_prefix_len)?;
    eprintln!(
        "warning: ignored malformed final {} log line {}: {}; quarantined at {}",
        tail.log_label,
        tail.line_number,
        tail.err,
        quarantine_path.display()
    );
    Ok(())
}

fn create_truncated_tail_quarantine_file(
    corrupt_dir: &Path,
    log_label: &str,
    line_number: usize,
) -> Result<(PathBuf, File)> {
    let timestamp = current_unix_timestamp()?;
    for _ in 0..8 {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let path = corrupt_dir.join(format!(
            "{}-tail-line-{}-{}-{}.json",
            log_label,
            line_number,
            timestamp,
            hex::encode(nonce)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to create {}", path.display()));
            }
        }
    }
    anyhow::bail!("failed to allocate truncated tail quarantine file");
}

fn maybe_repair_truncated_tail(
    datadir: &Path,
    tail: TruncatedTail<'_>,
    repair: TruncatedTailRepair,
) -> Result<()> {
    let append_lock = lock_path(datadir);
    if repair == TruncatedTailRepair::Conservative {
        remove_stale_lock(&append_lock, "sharechain append")?;
        if lock_file_metadata(&append_lock, "sharechain append")?.is_some() {
            anyhow::bail!(
                "{} log has an incomplete final line while append lock exists; retry after the append finishes",
                tail.log_label
            );
        }
    }
    quarantine_truncated_tail(datadir, tail)
}

fn truncate_log(log: &Path, len: usize) -> Result<()> {
    validate_datadir_file(log, "sharechain log")?;
    let file = OpenOptions::new()
        .write(true)
        .open(log)
        .with_context(|| format!("failed to open {} for truncation", log.display()))?;
    file.set_len(u64::try_from(len).context("sharechain log length does not fit in u64")?)
        .with_context(|| format!("failed to truncate {}", log.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync truncated {}", log.display()))?;
    if let Some(parent) = log.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    let dir = File::open(path).with_context(|| format!("failed to open dir {}", path.display()))?;
    dir.sync_all()
        .with_context(|| format!("failed to sync dir {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
    use chrono::NaiveDate;
    use pohw_core::commitment::{PohwCommitment, PohwCommitmentParams};
    use pohw_core::payout::DirectPayout;
    use pohw_core::snapshot::{IdenaStatus, Snapshot, SnapshotLeaf};
    use pohw_core::FORMULA_VERSION;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tiny_keccak::{Hasher, Keccak};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pohw-local-node-{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn local_node_refuses_symlinked_datadir() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink-datadir");
        let real = dir.join("real");
        let link = dir.join("link");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();

        let err = local_node_status(&link).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_node_refuses_symlinked_datadir_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink-datadir-ancestor");
        let real = dir.join("real");
        let link = dir.join("link");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();
        let datadir = link.join("nested");

        let err = local_node_status(&datadir).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        assert!(!real.join("nested").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    fn keypair(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn sign_schnorr(hash: [u8; 32], keypair: &Keypair) -> String {
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
        hex::encode(signature.serialize())
    }

    fn idena_signature(challenge: &str, secret_key: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(
            &Message::from_digest(idena_signin_hash(challenge)),
            secret_key,
        );
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        hex::encode(bytes)
    }

    fn idena_signin_hash(challenge: &str) -> [u8; 32] {
        keccak256(&keccak256(challenge.as_bytes()))
    }

    fn idena_address_from_secret(secret_key: &SecretKey) -> String {
        let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
        let serialized = pubkey.serialize_uncompressed();
        let hash = keccak256(&serialized[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }

    fn signed_registration(
        miner_id: &str,
        mining_key_byte: u8,
        claim_key_byte: u8,
        idena_key_byte: u8,
    ) -> MinerRegistration {
        let mining_keypair = keypair(mining_key_byte);
        let claim_keypair = keypair(claim_key_byte);
        let idena_secret = SecretKey::from_slice(&[idena_key_byte; 32]).unwrap();
        let claim_xonly = claim_keypair.x_only_public_key().0.to_string();
        let mut registration = MinerRegistration {
            version: pohw_core::sharechain::LEGACY_MINER_REGISTRATION_VERSION,
            miner_id: miner_id.to_string(),
            idena_address: idena_address_from_secret(&idena_secret),
            btc_payout_script_hex: format!("5120{claim_xonly}"),
            claim_owner_pubkey_hex: claim_xonly,
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            registry_anchor: None,
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex =
            sign_schnorr(registration.signing_hash(), &mining_keypair);
        registration
    }

    fn idena_anchor_policy() -> IdenaAnchorPolicyV2 {
        IdenaAnchorPolicyV2 {
            schema_version: 2,
            experiment_id: "p2poolbtc-experiment-1".to_string(),
            registry_contract_address: format!("0x{}", "21".repeat(20)),
            registry_deployment_tx_hash: format!("0x{}", "22".repeat(32)),
            registry_deployment_payload_sha256: "23".repeat(32),
            registry_contract_code_hash: "25".repeat(32),
            registry_contract_wasm_sha256: "24".repeat(32),
            registry_ecosystem_cid: "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
                .to_string(),
            minimum_registration_burn_atoms: "1000".to_string(),
            activation_idena_height: 100,
            finality_confirmations: 6,
            max_anchor_age_blocks: 12,
            handoff_version_bit: 27,
        }
    }

    fn share_work_policy(network_id: &str) -> ShareWorkBindingPolicyV1 {
        ShareWorkBindingPolicyV1 {
            schema_version: 1,
            experiment_id: idena_anchor_policy().experiment_id,
            fork_activation_id: "26".repeat(32),
            sharechain_network_id: network_id.to_string(),
            require_binding_from_genesis: true,
        }
    }

    fn test_message() -> SharechainMessage {
        SharechainMessage::PohwCommitment(PohwCommitment {
            version: "POHW1".to_string(),
            idena_snapshot_id: "snapshot-day".to_string(),
            idena_score_root: "11".repeat(32),
            miner_idena_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            identity_proof_root: "22".repeat(32),
            sharechain_tip: "33".repeat(32),
            sharechain_state_root: Some("44".repeat(32)),
            payout_schedule_root: "44".repeat(32),
            vault_epoch_id: 1,
            frost_vault_key_xonly: "55".repeat(32),
        })
    }

    fn test_gossip_envelope() -> GossipEnvelope {
        let keypair = keypair(7);
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            current_unix_timestamp().unwrap(),
            "66".repeat(32),
            test_message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();
        envelope
    }

    #[test]
    fn bound_idena_anchor_policy_is_immutable_and_enforced_inside_append_lock() {
        let datadir = temp_dir("bound-idena-anchor-policy");
        let policy = idena_anchor_policy();
        let commitment = bind_idena_anchor_policy(&datadir, &policy).unwrap();

        assert_eq!(commitment, policy.commitment_hash().unwrap());
        assert_eq!(
            read_bound_idena_anchor_policy(&datadir).unwrap(),
            Some(policy.clone())
        );
        let err = append_message(
            &datadir,
            SharechainMessage::MinerRegistration(signed_registration("legacy", 1, 2, 3)),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("has no contract-anchored registration"),
            "unexpected error: {err:#}"
        );

        let mut replacement = policy;
        replacement.max_anchor_age_blocks += 1;
        let err = bind_idena_anchor_policy(&datadir, &replacement).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing replacement"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn policy_binding_audits_existing_history_before_writing_policy() {
        let datadir = temp_dir("idena-anchor-policy-audit");
        append_message(
            &datadir,
            SharechainMessage::MinerRegistration(signed_registration("legacy", 4, 5, 6)),
        )
        .unwrap();

        let err = bind_idena_anchor_policy(&datadir, &idena_anchor_policy()).unwrap_err();
        assert!(
            format!("{err:#}").contains("existing sharechain history violates"),
            "unexpected error: {err:#}"
        );
        assert!(read_bound_idena_anchor_policy(&datadir).unwrap().is_none());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn share_work_policy_is_network_bound_immutable_and_idempotent() {
        let datadir = temp_dir("share-work-policy-binding");
        let network_id = "ab".repeat(32);
        initialize_gossip_network(&datadir, &network_id).unwrap();
        bind_idena_anchor_policy(&datadir, &idena_anchor_policy()).unwrap();
        let policy = share_work_policy(&network_id);

        let commitment = bind_share_work_binding_policy(&datadir, &policy).unwrap();
        assert_eq!(commitment, policy.commitment_hash().unwrap());
        assert_eq!(
            read_bound_share_work_binding_policy(&datadir).unwrap(),
            Some(policy.clone())
        );
        assert_eq!(
            bind_share_work_binding_policy(&datadir, &policy).unwrap(),
            commitment
        );

        let mut replacement = policy;
        replacement.fork_activation_id = "27".repeat(32);
        let err = bind_share_work_binding_policy(&datadir, &replacement).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing replacement"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn share_work_policy_rejects_wrong_network_without_persisting() {
        let datadir = temp_dir("share-work-policy-wrong-network");
        initialize_gossip_network(&datadir, &"ab".repeat(32)).unwrap();
        bind_idena_anchor_policy(&datadir, &idena_anchor_policy()).unwrap();

        let err = bind_share_work_binding_policy(&datadir, &share_work_policy(&"cd".repeat(32)))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match datadir gossip network"),
            "unexpected error: {err:#}"
        );
        assert!(read_bound_share_work_binding_policy(&datadir)
            .unwrap()
            .is_none());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn share_work_policy_reader_rejects_duplicate_json_keys() {
        let datadir = temp_dir("share-work-policy-duplicate-key");
        let path = datadir.join("policy.json");
        fs::write(
            &path,
            format!(
                concat!(
                    "{{\"schema_version\":1,\"schema_version\":1,",
                    "\"experiment_id\":\"p2poolbtc-experiment-1\",",
                    "\"fork_activation_id\":\"{}\",",
                    "\"sharechain_network_id\":\"{}\",",
                    "\"require_binding_from_genesis\":true}}"
                ),
                "11".repeat(32),
                "22".repeat(32)
            ),
        )
        .unwrap();

        let err = read_share_work_binding_policy_file(&path).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate JSON key: schema_version"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn confirmed_payout_replay_enforces_bound_idena_anchor_policy() {
        let datadir = temp_dir("confirmed-payout-bound-policy");
        bind_idena_anchor_policy(&datadir, &idena_anchor_policy()).unwrap();
        let unanchored = SharechainMessage::MinerRegistration(signed_registration(
            "externally-appended",
            7,
            8,
            9,
        ));
        fs::write(
            log_path(&datadir),
            format!("{}\n", serde_json::to_string(&unanchored).unwrap()),
        )
        .unwrap();

        let err = replay_state_with_confirmed_payouts(&datadir, None).unwrap_err();

        assert!(
            format!("{err:#}").contains("has no contract-anchored registration"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    fn test_network_gossip_envelope(network_id: &str, nonce_byte: u8) -> GossipEnvelope {
        let keypair = keypair(7);
        let mut envelope = GossipEnvelope::unsigned_for_network(
            network_id,
            keypair.x_only_public_key().0.to_string(),
            current_unix_timestamp().unwrap(),
            format!("{nonce_byte:02x}{}", "00".repeat(31)),
            test_message(),
        )
        .unwrap();
        envelope.sign(&keypair).unwrap();
        envelope
    }

    fn gossip_envelope_for_message(
        message: SharechainMessage,
        keypair: &Keypair,
        nonce_byte: u8,
    ) -> GossipEnvelope {
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            current_unix_timestamp().unwrap(),
            format!("{nonce_byte:02x}{}", "00".repeat(31)),
            message,
        )
        .unwrap();
        envelope.sign(keypair).unwrap();
        envelope
    }

    fn test_bitcoin_header_hex(nonce: u32) -> String {
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        header[36..68].copy_from_slice(&[0x33; 32]);
        header[68..72].copy_from_slice(&1_231_006_505u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        hex::encode(header)
    }

    fn signed_share(miner_id: &str, mining_keypair: &Keypair) -> pohw_core::sharechain::Share {
        let target = "7fffff0000000000000000000000000000000000000000000000000000000000";
        for nonce in 0..10_000 {
            let mut share = pohw_core::sharechain::Share {
                miner_id: miner_id.to_string(),
                bitcoin_header_hex: test_bitcoin_header_hex(nonce),
                bitcoin_template_hash: String::new(),
                nonce_hex: String::new(),
                work_hash: String::new(),
                target: target.to_string(),
                idena_snapshot_id: "2026-06-30".to_string(),
                idena_snapshot_proof_root: "11".repeat(32),
                hashrate_score_delta: 1,
                parent_share_hash:
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                work_binding: None,
                mining_signature_hex: String::new(),
            };
            share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash().unwrap();
            share.nonce_hex = share.recomputed_nonce_hex().unwrap();
            share.work_hash = share.recomputed_work_hash().unwrap();
            if share.work_hash.as_str() <= target {
                share.mining_signature_hex = sign_schnorr(share.signing_hash(), mining_keypair);
                return share;
            }
        }
        panic!("test target did not yield a valid share quickly");
    }

    fn signed_work_template(
        share: &pohw_core::sharechain::Share,
        mining_keypair: &Keypair,
    ) -> BitcoinWorkTemplate {
        let mut template = BitcoinWorkTemplate::new_unsigned(
            &share.miner_id,
            share.bitcoin_header_prefix_hex().unwrap(),
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign_schnorr(template.signing_hash(), mining_keypair);
        template
    }

    fn signed_target_bound_work_template(
        share: &pohw_core::sharechain::Share,
        mining_keypair: &Keypair,
    ) -> BitcoinWorkTemplate {
        let mut template = BitcoinWorkTemplate::new_target_bound_unsigned(
            &share.miner_id,
            share.bitcoin_header_prefix_hex().unwrap(),
            &share.target,
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign_schnorr(template.signing_hash(), mining_keypair);
        template
    }

    fn stored_gossip_envelope(envelope: GossipEnvelope) -> StoredGossipEnvelope {
        StoredGossipEnvelope {
            envelope_hash: envelope.envelope_hash(),
            message_hash: envelope.message.message_hash(),
            peer_pubkey_xonly_hex: envelope.peer_pubkey_xonly_hex.clone(),
            envelope,
        }
    }

    fn snapshot_leaf(address: &str, score: u128) -> SnapshotLeaf {
        SnapshotLeaf {
            idena_address: address.to_string(),
            status: IdenaStatus::Human,
            pubkey: "02".repeat(33),
            validation_reward_score: score,
            proposer_reward_score: 0,
            committee_reward_score: 0,
            ignored_invitation_score: 0,
            identity_root: "11".repeat(32),
            formula_version: FORMULA_VERSION,
        }
    }

    fn test_snapshot(day: (i32, u32, u32), height: u64, score: u128) -> Snapshot {
        Snapshot::build(
            NaiveDate::from_ymd_opt(day.0, day.1, day.2).unwrap(),
            height,
            "aa".repeat(32),
            "11".repeat(32),
            FORMULA_VERSION,
            vec![snapshot_leaf(
                "0x1111111111111111111111111111111111111111",
                score,
            )],
        )
    }

    fn write_snapshot(path: &Path, snapshot: &Snapshot) {
        fs::write(path, serde_json::to_string_pretty(snapshot).unwrap()).unwrap();
    }

    #[test]
    fn local_template_acceptance_is_required_before_share_append() {
        let datadir = temp_dir("accepted-bitcoin-template");
        let registration = signed_registration("Miner-A", 9, 10, 13);
        let mining_keypair = keypair(9);
        let share = signed_share("Miner-A", &mining_keypair);
        let template = signed_work_template(&share, &mining_keypair);

        append_message(&datadir, SharechainMessage::MinerRegistration(registration)).unwrap();
        let err = append_message(
            &datadir,
            SharechainMessage::BitcoinWorkTemplate(template.clone()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("has not been locally accepted"));

        let accepted = accept_bitcoin_work_template(&datadir, template.clone()).unwrap();
        assert_eq!(accepted.outcome, ApplyOutcome::Applied);
        assert_eq!(accepted.accepted_template_count, 1);

        append_message(&datadir, SharechainMessage::BitcoinWorkTemplate(template)).unwrap();
        let appended_share = append_message(&datadir, SharechainMessage::Share(share)).unwrap();
        assert_eq!(appended_share.outcome, ApplyOutcome::Applied);
        assert_eq!(appended_share.status.replay.bitcoin_work_template_count, 1);
        assert_eq!(appended_share.status.replay.share_miner_count, 1);

        fs::remove_dir_all(datadir).unwrap();
    }

    fn test_confirmed_payout_record() -> ConfirmedPayoutRecord {
        let snapshot = test_snapshot((2026, 6, 30), 100, 0);
        let schedule = PayoutSchedule::default();
        let commitment = test_pohw_commitment(&snapshot, &schedule, "cc".repeat(32));
        ConfirmedPayoutRecord::new(
            42,
            "aa".repeat(32),
            "bb".repeat(32),
            0,
            100,
            10_000,
            &snapshot,
            schedule,
            commitment,
        )
        .unwrap()
    }

    fn test_pohw_commitment(
        snapshot: &Snapshot,
        schedule: &PayoutSchedule,
        sharechain_tip: String,
    ) -> PohwCommitment {
        PohwCommitment::new_pohw1(PohwCommitmentParams {
            idena_snapshot_id: snapshot.snapshot_day.to_string(),
            idena_score_root: snapshot.score_root.clone(),
            miner_idena_address: snapshot.leaves[0].idena_address.clone(),
            identity_proof_root: snapshot.identity_root.clone(),
            sharechain_tip,
            sharechain_state_root: None,
            payout_schedule_root: schedule.payout_root.clone(),
            vault_epoch_id: 1,
            frost_vault_key_xonly: keypair(12).x_only_public_key().0.to_string(),
        })
    }

    #[test]
    fn missing_snapshot_dir_returns_empty_status() {
        let datadir = temp_dir("missing-snapshot-dir");
        let missing = datadir.join("snapshots");

        let status = latest_verified_snapshot(&missing).unwrap();

        assert_eq!(status.snapshot_dir, missing);
        assert_eq!(status.scanned_file_count, 0);
        assert_eq!(status.invalid_file_count, 0);
        assert!(status.latest.is_none());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn latest_verified_snapshot_picks_newest_valid_snapshot() {
        let snapshot_dir = temp_dir("latest-snapshot");
        write_snapshot(
            &snapshot_dir.join("old.json"),
            &test_snapshot((2026, 6, 29), 10, 1),
        );
        write_snapshot(
            &snapshot_dir.join("new-height-1.json"),
            &test_snapshot((2026, 6, 30), 1, 2),
        );
        write_snapshot(
            &snapshot_dir.join("new-height-2.json"),
            &test_snapshot((2026, 6, 30), 2, 3),
        );

        let status = latest_verified_snapshot(&snapshot_dir).unwrap();

        assert_eq!(status.scanned_file_count, 3);
        assert_eq!(status.invalid_file_count, 0);
        let latest = status.latest.unwrap();
        assert_eq!(latest.snapshot.snapshot_day.to_string(), "2026-06-30");
        assert_eq!(latest.snapshot.idena_height, 2);
        fs::remove_dir_all(snapshot_dir).unwrap();
    }

    #[test]
    fn latest_verified_snapshot_ignores_invalid_files() {
        let snapshot_dir = temp_dir("snapshot-invalid-files");
        write_snapshot(
            &snapshot_dir.join("valid.json"),
            &test_snapshot((2026, 6, 30), 1, 2),
        );
        fs::write(snapshot_dir.join("broken.json"), "{not json").unwrap();
        let mut tampered = test_snapshot((2026, 7, 1), 1, 3);
        tampered.score_root = "00".repeat(32);
        write_snapshot(&snapshot_dir.join("tampered.json"), &tampered);

        let status = latest_verified_snapshot(&snapshot_dir).unwrap();

        assert_eq!(status.scanned_file_count, 3);
        assert_eq!(status.invalid_file_count, 2);
        assert_eq!(
            status.latest.unwrap().snapshot.snapshot_day.to_string(),
            "2026-06-30"
        );
        fs::remove_dir_all(snapshot_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn direct_snapshot_reader_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let snapshot_dir = temp_dir("snapshot-symlink");
        let target = snapshot_dir.join("target.json");
        let link = snapshot_dir.join("linked.json");
        write_snapshot(&target, &test_snapshot((2026, 6, 30), 1, 2));
        symlink(&target, &link).unwrap();

        let err = read_verified_snapshot(&link).unwrap_err();

        assert!(
            err.to_string().contains("did not verify"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(snapshot_dir).unwrap();
    }

    #[test]
    fn confirmed_payout_record_id_normalizes_hash_case() {
        let snapshot = test_snapshot((2026, 6, 30), 100, 0);
        let commitment =
            test_pohw_commitment(&snapshot, &PayoutSchedule::default(), "cc".repeat(32));
        let lower = ConfirmedPayoutRecord::new(
            42,
            "aa".repeat(32),
            "bb".repeat(32),
            0,
            100,
            10_000,
            &snapshot,
            PayoutSchedule::default(),
            commitment.clone(),
        )
        .unwrap();
        let upper = ConfirmedPayoutRecord::new(
            42,
            "AA".repeat(32),
            "BB".repeat(32),
            0,
            100,
            10_000,
            &snapshot,
            PayoutSchedule::default(),
            commitment,
        )
        .unwrap();

        assert_eq!(lower.fork_block_hash, "aa".repeat(32));
        assert_eq!(lower.coinbase_txid, "bb".repeat(32));
        assert_eq!(lower.record_id(), upper.record_id());
    }

    #[test]
    fn confirmed_payout_record_rejects_bad_hashes() {
        let snapshot = test_snapshot((2026, 6, 30), 100, 0);
        let commitment =
            test_pohw_commitment(&snapshot, &PayoutSchedule::default(), "cc".repeat(32));

        let err = ConfirmedPayoutRecord::new(
            42,
            "aa".to_string(),
            "bb".repeat(32),
            0,
            100,
            10_000,
            &snapshot,
            PayoutSchedule::default(),
            commitment,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("fork_block_hash"));
    }

    #[test]
    fn confirmed_payout_replays_at_committed_sharechain_tip() {
        let datadir = temp_dir("confirmed-payout-tip-state");
        let snapshot_dir = datadir.join("snapshots");
        fs::create_dir_all(&snapshot_dir).unwrap();
        let early = signed_registration("early", 20, 21, 22);
        let late = signed_registration("late", 23, 24, 25);
        let snapshot = Snapshot::build(
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
            100,
            "aa".repeat(32),
            "11".repeat(32),
            FORMULA_VERSION,
            vec![
                snapshot_leaf(&early.idena_address, 1),
                snapshot_leaf(&late.idena_address, 1),
            ],
        );
        let snapshot_file = snapshot_dir.join("snapshot.json");
        write_snapshot(&snapshot_file, &snapshot);

        let early_mining_keypair = keypair(20);
        let early_share = signed_share(&early.miner_id, &early_mining_keypair);
        let early_template = signed_work_template(&early_share, &early_mining_keypair);
        let sharechain_tip = early_share.share_hash();
        append_message(
            &datadir,
            SharechainMessage::MinerRegistration(early.clone()),
        )
        .unwrap();
        accept_bitcoin_work_template(&datadir, early_template.clone()).unwrap();
        append_message(
            &datadir,
            SharechainMessage::BitcoinWorkTemplate(early_template),
        )
        .unwrap();
        append_message(&datadir, SharechainMessage::Share(early_share)).unwrap();
        let state_root = replay_state(&datadir).unwrap().accounting_state_root();
        append_message(&datadir, SharechainMessage::MinerRegistration(late.clone())).unwrap();

        let mut schedule = PayoutSchedule {
            direct_outputs: vec![DirectPayout {
                miner_id: late.miner_id.clone(),
                btc_payout_script_hex: late.btc_payout_script_hex.clone(),
                amount_sats: 10_000,
            }],
            vault_allocations: Vec::new(),
            vault_output_sats: 0,
            payout_root: String::new(),
        };
        schedule.payout_root = schedule.expected_payout_root();
        schedule.validate().unwrap();
        let mut commitment = test_pohw_commitment(&snapshot, &schedule, sharechain_tip);
        commitment.sharechain_state_root = Some(state_root);
        append_message(
            &datadir,
            SharechainMessage::PohwCommitment(commitment.clone()),
        )
        .unwrap();

        let err = append_confirmed_payout_record(
            &datadir,
            ConfirmedPayoutAppend {
                snapshot_file,
                payout_schedule: schedule,
                reward_sats: 10_000,
                direct_limit: 100,
                min_direct_payout_sats: 10_000,
                fork_block_height: 1,
                fork_block_hash: "aa".repeat(32),
                coinbase_txid: "bb".repeat(32),
                pohw_commitment: commitment,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unknown miner late"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn confirmed_payout_log_repairs_truncated_tail() {
        let datadir = temp_dir("confirmed-payout-tail");
        let record = test_confirmed_payout_record();
        let line = serde_json::to_string(&record).unwrap();
        fs::write(
            confirmed_payout_log_path(&datadir),
            format!("{line}\n{{\"schema_version\":"),
        )
        .unwrap();

        let records =
            read_confirmed_payout_records_with_repair(&datadir, TruncatedTailRepair::Conservative)
                .unwrap();

        assert_eq!(records, vec![record]);
        assert!(datadir.join(CORRUPT_LOG_DIR).exists());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn replay_ignores_and_quarantines_truncated_tail_line() {
        let datadir = temp_dir("truncated-tail");
        let log = log_path(&datadir);
        fs::write(
            &log,
            concat!(
                "{\"type\":\"PohwCommitment\",\"payload\":{\"version\":\"POHW1\",\"idena_snapshot_id\":\"day\",\"idena_score_root\":\"root\",\"miner_idena_address\":\"0xabc\",\"identity_proof_root\":\"proof\",\"sharechain_tip\":\"tip\",\"payout_schedule_root\":\"payout\",\"vault_epoch_id\":1,\"frost_vault_key_xonly\":\"key\"}}\n",
                "{\"type\":\"PohwCommitment\",\"payload\":"
            ),
        )
        .unwrap();

        let messages = read_messages(&datadir).unwrap();

        assert_eq!(messages.len(), 1);
        let repaired_log = fs::read_to_string(&log).unwrap();
        assert!(repaired_log.ends_with('\n'));
        assert_eq!(repaired_log.lines().count(), 1);
        assert!(datadir.join(CORRUPT_LOG_DIR).exists());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn truncated_tail_quarantine_refuses_symlink_directory() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("truncated-tail-quarantine-symlink");
        let target = datadir.join("quarantine-target");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, datadir.join(CORRUPT_LOG_DIR)).unwrap();
        let log = log_path(&datadir);
        fs::write(
            &log,
            concat!(
                "{\"type\":\"PohwCommitment\",\"payload\":{\"version\":\"POHW1\",\"idena_snapshot_id\":\"day\",\"idena_score_root\":\"root\",\"miner_idena_address\":\"0xabc\",\"identity_proof_root\":\"proof\",\"sharechain_tip\":\"tip\",\"payout_schedule_root\":\"payout\",\"vault_epoch_id\":1,\"frost_vault_key_xonly\":\"key\"}}\n",
                "{\"type\":\"PohwCommitment\",\"payload\":"
            ),
        )
        .unwrap();

        let err = read_messages(&datadir).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sharechain_append_rejects_symlink_log_file() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("sharechain-symlink-log");
        let target = datadir.join("target.ndjson");
        fs::write(&target, "do-not-touch").unwrap();
        symlink(&target, log_path(&datadir)).unwrap();

        let err = append_message(&datadir, test_message()).unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "do-not-touch");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn gossip_append_rejects_symlink_envelope_log_file() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("gossip-symlink-log");
        let target = datadir.join("target.ndjson");
        fs::write(&target, "do-not-touch").unwrap();
        symlink(&target, gossip_envelope_log_path(&datadir)).unwrap();

        let err =
            append_gossip_envelope(&datadir, test_gossip_envelope(), 300, 86_400).unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "do-not-touch");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_network_initialization_is_idempotent_but_not_rebindable() {
        let datadir = temp_dir("gossip-network-init");
        let network_id = "ab".repeat(32);

        assert_eq!(
            initialize_gossip_network(&datadir, &network_id).unwrap(),
            network_id
        );
        assert_eq!(
            initialize_gossip_network(&datadir, &network_id.to_ascii_uppercase()).unwrap(),
            network_id
        );
        let err = initialize_gossip_network(&datadir, &"cd".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("different network"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn persistence_limits_reject_at_exact_count_and_byte_boundaries() {
        let global = ensure_gossip_count_capacity(2, 0, 2, 2).unwrap_err();
        assert!(matches!(
            global.downcast_ref::<GossipPersistenceError>(),
            Some(GossipPersistenceError::EnvelopeLimit { limit: 2 })
        ));
        let peer = ensure_gossip_count_capacity(1, 2, 3, 2).unwrap_err();
        assert!(matches!(
            peer.downcast_ref::<GossipPersistenceError>(),
            Some(GossipPersistenceError::PeerEnvelopeLimit { limit: 2 })
        ));

        let datadir = temp_dir("gossip-byte-limit");
        let path = datadir.join("bounded.log");
        fs::write(&path, b"1234").unwrap();
        ensure_file_capacity(&path, "bounded log", 3, 7).unwrap();
        let err = ensure_file_capacity(&path, "bounded log", 4, 7).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<GossipPersistenceError>(),
            Some(GossipPersistenceError::ByteLimit { limit: 7, .. })
        ));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn network_bound_datadir_requires_target_bound_templates_for_new_appends() {
        let datadir = temp_dir("target-bound-network");
        initialize_gossip_network(&datadir, &"ab".repeat(32)).unwrap();
        let mining_keypair = keypair(9);
        let registration = signed_registration("miner-a", 9, 10, 13);
        append_message(&datadir, SharechainMessage::MinerRegistration(registration)).unwrap();
        let mut share = signed_share("miner-a", &mining_keypair);
        let legacy = signed_work_template(&share, &mining_keypair);

        let err = accept_bitcoin_work_template(&datadir, legacy).unwrap_err();
        assert!(format!("{err:#}").contains("target-bound version"));

        share.bitcoin_template_hash = share
            .recomputed_target_bound_bitcoin_template_hash()
            .unwrap();
        share.mining_signature_hex = sign_schnorr(share.signing_hash(), &mining_keypair);
        let target_bound = signed_target_bound_work_template(&share, &mining_keypair);
        accept_bitcoin_work_template(&datadir, target_bound.clone()).unwrap();
        append_message(
            &datadir,
            SharechainMessage::BitcoinWorkTemplate(target_bound),
        )
        .unwrap();
        append_message(&datadir, SharechainMessage::Share(share)).unwrap();
        assert_eq!(
            local_node_status(&datadir)
                .unwrap()
                .replay
                .active_share_count,
            1
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_network_initialization_refuses_existing_sharechain_history() {
        let datadir = temp_dir("gossip-network-existing-history");
        append_message(&datadir, test_message()).unwrap();

        let err = initialize_gossip_network(&datadir, &"ab".repeat(32)).unwrap_err();

        assert!(err.to_string().contains("non-empty gossip datadir"));
        assert_eq!(gossip_network_id(&datadir).unwrap(), None);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn network_bound_datadir_accepts_only_matching_network_envelopes() {
        let datadir = temp_dir("gossip-network-admission");
        let network_id = "ab".repeat(32);
        initialize_gossip_network(&datadir, &network_id).unwrap();

        let legacy_err =
            append_gossip_envelope(&datadir, test_gossip_envelope(), 300, 86_400).unwrap_err();
        assert!(legacy_err.to_string().contains("not bound"));

        let wrong = test_network_gossip_envelope(&"cd".repeat(32), 0x67);
        let wrong_err = append_gossip_envelope(&datadir, wrong, 300, 86_400).unwrap_err();
        assert!(format!("{wrong_err:#}").contains("does not match expected network"));

        let matching = test_network_gossip_envelope(&network_id, 0x68);
        let result = append_gossip_envelope(&datadir, matching, 300, 86_400).unwrap();
        assert_eq!(result.message_result.outcome, ApplyOutcome::Applied);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn legacy_datadir_rejects_network_bound_envelopes_until_initialized() {
        let datadir = temp_dir("gossip-network-uninitialized");
        let envelope = test_network_gossip_envelope(&"ab".repeat(32), 0x69);

        let err = append_gossip_envelope(&datadir, envelope, 300, 86_400).unwrap_err();

        assert!(err.to_string().contains("requires an initialized"));
        assert!(gossip_inventory(&datadir).unwrap().is_empty());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn gossip_network_id_refuses_symlink_file() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("gossip-network-symlink");
        let target = datadir.join("target");
        fs::write(&target, format!("{}\n", "ab".repeat(32))).unwrap();
        symlink(&target, gossip_network_id_path(&datadir)).unwrap();

        let err = gossip_network_id(&datadir).unwrap_err();

        assert!(err.to_string().contains("must not be a symlink"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_node_readers_reject_symlink_state_files() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("state-file-symlinks");
        let target = datadir.join("target.json");
        fs::write(&target, "{}\n").unwrap();

        symlink(&target, accepted_bitcoin_work_templates_log_path(&datadir)).unwrap();
        let err = read_accepted_bitcoin_work_templates_with_repair(
            &datadir,
            TruncatedTailRepair::Conservative,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        symlink(&target, confirmed_payout_log_path(&datadir)).unwrap();
        let err =
            read_confirmed_payout_records_with_repair(&datadir, TruncatedTailRepair::Conservative)
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        symlink(&target, gossip_peers_path(&datadir)).unwrap();
        let err = list_gossip_peers(&datadir).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        symlink(&target, gossip_envelope_log_path(&datadir)).unwrap();
        let err = gossip_inventory(&datadir).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn input_file_readers_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("input-file-symlinks");
        let datadir = dir.join("node");
        fs::create_dir(&datadir).unwrap();
        let target = dir.join("target.json");
        fs::write(&target, "{}\n").unwrap();

        let message_link = dir.join("message.json");
        symlink(&target, &message_link).unwrap();
        let err = append_message_file(&datadir, &message_link).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        let envelope_link = dir.join("envelope.json");
        symlink(&target, &envelope_link).unwrap();
        let err = append_gossip_envelope_file(&datadir, &envelope_link, 300, 86_400).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        let template_link = dir.join("template.json");
        symlink(&target, &template_link).unwrap();
        let err = read_bitcoin_work_template_file(&template_link).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn input_file_readers_reject_large_files() {
        let dir = temp_dir("input-file-large");
        let datadir = dir.join("node");
        fs::create_dir(&datadir).unwrap();
        let input = dir.join("large.json");
        fs::File::create(&input)
            .unwrap()
            .set_len(MAX_SHARECHAIN_INPUT_FILE_BYTES + 1)
            .unwrap();

        let err = append_message_file(&datadir, &input).unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_gossip_append_restores_missing_envelope_record() {
        let datadir = temp_dir("gossip-heal-missing-envelope");
        let envelope = test_gossip_envelope();
        let message_hash = envelope.message.message_hash();
        append_message(&datadir, envelope.message.clone()).unwrap();

        let result = append_gossip_envelope(&datadir, envelope.clone(), 300, 86_400).unwrap();

        assert_eq!(
            result.message_result.outcome,
            ApplyOutcome::DuplicateIgnored
        );
        assert_eq!(
            gossip_inventory(&datadir).unwrap(),
            vec![message_hash.clone()]
        );
        assert_eq!(
            gossip_envelope_by_message_hash(&datadir, &message_hash).unwrap(),
            Some(envelope)
        );
        assert_eq!(
            local_node_status(&datadir).unwrap().gossip_envelope_count,
            1
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_envelope_log_rejects_tampered_record_hashes() {
        let datadir = temp_dir("gossip-tampered-record");
        let mut stored = stored_gossip_envelope(test_gossip_envelope());
        stored.message_hash = "00".repeat(32);
        let line = serde_json::to_string(&stored).unwrap();
        fs::write(gossip_envelope_log_path(&datadir), format!("{line}\n")).unwrap();

        let err = read_gossip_envelopes(&datadir).unwrap_err().to_string();

        assert!(err.contains("invalid gossip envelope record"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_envelope_log_deduplicates_message_hashes() {
        let datadir = temp_dir("gossip-deduplicates-records");
        let stored = stored_gossip_envelope(test_gossip_envelope());
        let line = serde_json::to_string(&stored).unwrap();
        fs::write(
            gossip_envelope_log_path(&datadir),
            format!("{line}\n{line}\n"),
        )
        .unwrap();

        let envelopes = read_gossip_envelopes(&datadir).unwrap();

        assert_eq!(envelopes.len(), 1);
        assert_eq!(
            gossip_inventory(&datadir).unwrap(),
            vec![stored.message_hash]
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn historical_append_accepts_old_signed_dependency_only() {
        let datadir = temp_dir("historical-gossip-envelope");
        let keypair = keypair(7);
        let mut envelope = test_gossip_envelope();
        envelope.created_at_unix = current_unix_timestamp().unwrap() - 172_800;
        envelope.sign(&keypair).unwrap();

        let live_error = append_gossip_envelope(&datadir, envelope.clone(), 300, 86_400)
            .expect_err("live submission must enforce max age");
        assert!(live_error.to_string().contains("older than max age"));

        let historical = append_historical_gossip_envelope(&datadir, envelope, 300).unwrap();
        assert_eq!(historical.message_result.outcome, ApplyOutcome::Applied);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_envelope_cache_refreshes_when_log_changes() {
        let datadir = temp_dir("gossip-cache-refreshes");
        assert!(gossip_inventory(&datadir).unwrap().is_empty());

        let envelope = test_gossip_envelope();
        let message_hash = envelope.message.message_hash();
        append_gossip_envelope(&datadir, envelope.clone(), 300, 86_400).unwrap();

        assert_eq!(
            gossip_inventory(&datadir).unwrap(),
            vec![message_hash.clone()]
        );
        assert_eq!(
            gossip_envelope_by_message_hash(&datadir, &message_hash).unwrap(),
            Some(envelope)
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_envelope_cache_indexes_templates_and_registrations() {
        let datadir = temp_dir("gossip-cache-secondary-indexes");
        let mining_keypair = keypair(9);
        let registration = signed_registration("Miner-A", 9, 10, 13);
        let share = signed_share(&registration.miner_id, &mining_keypair);
        let template = signed_work_template(&share, &mining_keypair);
        accept_bitcoin_work_template(&datadir, template.clone()).unwrap();

        let registration_envelope = gossip_envelope_for_message(
            SharechainMessage::MinerRegistration(registration.clone()),
            &keypair(70),
            0x70,
        );
        let template_envelope = gossip_envelope_for_message(
            SharechainMessage::BitcoinWorkTemplate(template.clone()),
            &keypair(71),
            0x71,
        );
        append_gossip_envelope(&datadir, registration_envelope.clone(), 300, 86_400).unwrap();
        append_gossip_envelope(&datadir, template_envelope.clone(), 300, 86_400).unwrap();

        assert_eq!(
            gossip_envelope_by_miner_registration_id(&datadir, "MINER-A").unwrap(),
            Some(registration_envelope)
        );
        assert_eq!(
            gossip_envelope_by_bitcoin_template_hash(
                &datadir,
                &template.template_hash.to_ascii_uppercase()
            )
            .unwrap(),
            Some(template_envelope)
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn sharechain_index_is_persisted_and_refreshes_when_log_changes() {
        let datadir = temp_dir("sharechain-index-refreshes");
        let empty = sharechain_index(&datadir).unwrap();
        assert_eq!(empty.message_count, 0);
        assert!(sharechain_index_path(&datadir).exists());

        append_message(&datadir, test_message()).unwrap();
        let refreshed = sharechain_index(&datadir).unwrap();

        assert_eq!(refreshed.message_count, 1);
        assert_eq!(refreshed.replay.applied_message_count, 1);
        assert!(refreshed.replay.last_message_hash.is_some());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn append_cache_replays_only_externally_appended_tail() {
        let datadir = temp_dir("sharechain-cache-tail");
        append_message(&datadir, test_message()).unwrap();

        let mut external = test_message();
        let SharechainMessage::PohwCommitment(external_commitment) = &mut external else {
            unreachable!()
        };
        external_commitment.vault_epoch_id = 2;
        let mut file = OpenOptions::new()
            .append(true)
            .open(log_path(&datadir))
            .unwrap();
        serde_json::to_writer(&mut file, &external).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();

        let mut local = test_message();
        let SharechainMessage::PohwCommitment(local_commitment) = &mut local else {
            unreachable!()
        };
        local_commitment.vault_epoch_id = 3;
        let result = append_message(&datadir, local).unwrap();

        assert_eq!(result.status.log_line_count, 3);
        assert_eq!(result.status.replay.applied_message_count, 3);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn append_waits_for_short_lived_lock_contention() {
        let datadir = temp_dir("sharechain-lock-contention");
        let lock = acquire_append_lock(&datadir).unwrap();
        let worker_datadir = datadir.clone();
        let worker = thread::spawn(move || append_message(&worker_datadir, test_message()));
        thread::sleep(Duration::from_millis(100));
        drop(lock);

        let result = worker.join().unwrap().unwrap();

        assert_eq!(result.outcome, ApplyOutcome::Applied);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn sharechain_index_corruption_rebuilds_from_append_only_log() {
        let datadir = temp_dir("sharechain-index-corrupt");
        append_message(&datadir, test_message()).unwrap();
        fs::write(sharechain_index_path(&datadir), "{not-json").unwrap();

        let rebuilt = sharechain_index(&datadir).unwrap();

        assert_eq!(rebuilt.message_count, 1);
        assert_eq!(rebuilt.replay.applied_message_count, 1);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cache_writers_do_not_follow_legacy_fixed_temp_symlinks() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("fixed-temp-symlink");
        let target = datadir.join("outside-target");
        fs::write(&target, "do-not-touch").unwrap();
        symlink(
            &target,
            datadir.join(format!("{SHARECHAIN_INDEX_FILE}.tmp")),
        )
        .unwrap();
        symlink(&target, datadir.join(format!("{GOSSIP_PEERS_FILE}.tmp"))).unwrap();

        sharechain_index(&datadir).unwrap();
        upsert_gossip_peer(&datadir, "127.0.0.2:40406".parse().unwrap(), "seed").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "do-not-touch");
        assert!(datadir
            .join(format!("{SHARECHAIN_INDEX_FILE}.tmp"))
            .exists());
        assert!(datadir.join(format!("{GOSSIP_PEERS_FILE}.tmp")).exists());

        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn stale_append_lock_is_replaced() {
        let datadir = temp_dir("stale-lock");
        let lock = lock_path(&datadir);
        fs::write(&lock, "999999 0").unwrap();

        let acquired = acquire_append_lock(&datadir);

        if acquired.is_ok() {
            drop(acquired);
            fs::remove_dir_all(datadir).unwrap();
        } else {
            fs::remove_dir_all(datadir).unwrap();
            panic!("fresh lock should be acquired after stale cleanup");
        }
    }

    #[cfg(unix)]
    #[test]
    fn append_lock_rejects_symlink_lock_file() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("append-lock-symlink");
        let target = datadir.join("target.lock");
        fs::write(&target, "999999 0").unwrap();
        symlink(&target, lock_path(&datadir)).unwrap();

        let err = match acquire_append_lock(&datadir) {
            Ok(lock) => {
                drop(lock);
                fs::remove_dir_all(datadir).unwrap();
                panic!("symlink lock should be rejected");
            }
            Err(err) => err,
        };

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "999999 0");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn peer_book_lock_rejects_symlink_lock_file() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("peer-book-lock-symlink");
        let target = datadir.join("target.lock");
        fs::write(&target, "999999 0").unwrap();
        symlink(&target, peer_book_lock_path(&datadir)).unwrap();

        let err =
            upsert_gossip_peer(&datadir, "127.0.0.2:40406".parse().unwrap(), "seed").unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "999999 0");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn peer_book_upserts_and_tracks_peer_health() {
        let datadir = temp_dir("peer-book");
        let addr = "127.0.0.1:40406".parse().unwrap();

        let first = upsert_gossip_peer(&datadir, addr, "discovered").unwrap();
        let second = upsert_gossip_peer(&datadir, addr, "seed").unwrap();
        record_gossip_peer_success(&datadir, addr).unwrap();
        record_gossip_peer_failure(&datadir, addr).unwrap();
        let peers = list_gossip_peers(&datadir).unwrap();

        assert_eq!(first.addr, addr);
        assert_eq!(second.source, "seed");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, addr);
        assert_eq!(peers[0].source, "seed");
        assert_eq!(peers[0].failure_count, 1);
        assert!(peers[0].last_success_unix.is_some());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn peer_book_retention_caps_entries_and_prefers_seeds() {
        let seed_addr = "198.51.100.1:40406".parse().unwrap();
        let mut book = GossipPeerBook {
            peers: vec![GossipPeerEntry {
                addr: seed_addr,
                source: "seed".to_string(),
                first_seen_unix: 1,
                last_seen_unix: 1,
                last_success_unix: None,
                failure_count: u32::MAX,
            }],
        };
        for idx in 0..(MAX_GOSSIP_PEERS + 20) {
            let second = u8::try_from(idx / 250).unwrap();
            let third = u8::try_from(idx % 250).unwrap();
            book.peers.push(GossipPeerEntry {
                addr: SocketAddr::from(([10, second, third, 1], 40406)),
                source: "discovered".to_string(),
                first_seen_unix: 2,
                last_seen_unix: 2,
                last_success_unix: Some(2),
                failure_count: 0,
            });
        }

        sort_and_dedup_gossip_peers(&mut book);

        assert_eq!(book.peers.len(), MAX_GOSSIP_PEERS);
        assert!(book.peers.iter().any(|peer| peer.addr == seed_addr));
    }
}
