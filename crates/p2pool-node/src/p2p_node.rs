use crate::bitcoin_rpc::{self, BitcoinRpcClient};
use crate::fork_chain::ForkChainClient;
use crate::local_node;
use crate::peer_policy::{PeerDecision, PeerPolicy, PeerPolicyConfig};
use anyhow::{bail, Context, Result};
use pohw_core::gossip::GossipEnvelope;
use pohw_core::sharechain::SharechainMessage;
use pohw_core::sharechain_state::ApplyOutcome;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{interval, timeout, Duration, Instant, MissedTickBehavior};

const DEFAULT_MAX_GOSSIP_LINE_BYTES: usize = 1_048_576;
const MAX_INVENTORY_LIMIT: usize = 1_024;
const MAX_KNOWN_HASHES: usize = 4_096;
const MAX_PEER_LIST_LIMIT: usize = 128;
const MAX_KNOWN_PEERS: usize = 1_024;
const MAX_SERVER_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_SERVER_CONNECTIONS: usize = 4_096;
const MAX_SERVER_CONNECTIONS_PER_IP: usize = 512;
const MAX_SERVER_TIMEOUT_SECONDS: u64 = 300;
const MAX_MESH_SYNC_INTERVAL_SECONDS: u64 = 86_400;
const MAX_GOSSIP_ENVELOPE_FILE_BYTES: u64 = MAX_SERVER_FRAME_BYTES as u64;
const DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_OUTBOUND_WRITE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_OUTBOUND_READ_TIMEOUT_SECONDS: u64 = 30;
const ZERO_SHARE_PARENT_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_SHARE_PARENT_FETCH_DEPTH: usize = 256;
const MAX_EXTRA_SHARE_PARENT_FETCHES_PER_SYNC: usize = 2_048;
const MAX_REGISTRATION_FETCHES_PER_SYNC: usize = 512;
const MAX_TEMPLATE_FETCHES_PER_SYNC: usize = 512;
const MAX_MINER_ID_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct GossipServerConfig {
    pub datadir: PathBuf,
    pub bind_addr: SocketAddr,
    pub max_future_skew_seconds: i64,
    pub max_age_seconds: i64,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub read_timeout_seconds: u64,
    pub write_timeout_seconds: u64,
    pub allow_public_peers: bool,
    pub peer_policy: PeerPolicyConfig,
}

#[derive(Debug, Clone)]
pub struct GossipPeerLoopConfig {
    pub datadir: PathBuf,
    pub initial_peers: Vec<SocketAddr>,
    pub advertise_addr: Option<SocketAddr>,
    pub sync_interval_seconds: u64,
    pub inventory_limit: usize,
    pub rebroadcast_limit: usize,
    pub peer_list_limit: usize,
    pub max_peers_per_round: usize,
    pub max_parallel_peers: usize,
    pub max_future_skew_seconds: i64,
    pub max_age_seconds: i64,
    pub allow_public_peers: bool,
    pub work_template_admission: Option<WorkTemplateAdmissionConfig>,
}

#[derive(Debug, Clone)]
pub struct WorkTemplateAdmissionConfig {
    pub bitcoin_rpc_client: Option<BitcoinRpcClient>,
    pub fork_chain_client: Option<ForkChainClient>,
    pub validation_policy: bitcoin_rpc::BitcoinWorkTemplateValidationPolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct GossipServerStatus {
    pub listening_on: SocketAddr,
    pub datadir: PathBuf,
    pub protocol: &'static str,
    pub note: &'static str,
    pub max_frame_bytes: usize,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerResponse {
    pub accepted: bool,
    pub peer_id: Option<String>,
    pub envelope_hash: Option<String>,
    pub message_hash: Option<String>,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub peer_decision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipInventoryRequest {
    pub known_hashes: Vec<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipEnvelopeRequest {
    pub message_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipBitcoinWorkTemplateRequest {
    pub template_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipMinerRegistrationRequest {
    pub miner_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipInventoryResponse {
    pub message_hashes: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipEnvelopePullResponse {
    pub requested_message_hash: String,
    pub envelope: Option<Box<GossipEnvelope>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipBitcoinWorkTemplatePullResponse {
    pub requested_template_hash: String,
    pub envelope: Option<Box<GossipEnvelope>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipMinerRegistrationPullResponse {
    pub requested_miner_id: String,
    pub envelope: Option<Box<GossipEnvelope>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipSyncFailure {
    pub message_hash: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipSyncSummary {
    pub peer_addr: SocketAddr,
    pub local_known_before: usize,
    pub offered_count: usize,
    pub skipped_known_count: usize,
    pub inventory_truncated: bool,
    pub fetched_count: usize,
    pub applied_count: usize,
    pub duplicate_count: usize,
    pub failed_count: usize,
    pub failures: Vec<GossipSyncFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParentFetchBudget {
    remaining: usize,
}

impl ParentFetchBudget {
    fn for_offer_count(offer_count: usize) -> Self {
        if offer_count == 0 {
            return Self { remaining: 0 };
        }
        let requested = offer_count.saturating_mul(4);
        Self {
            remaining: requested.clamp(
                MAX_SHARE_PARENT_FETCH_DEPTH,
                MAX_EXTRA_SHARE_PARENT_FETCHES_PER_SYNC,
            ),
        }
    }

    fn try_spend(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrationFetchBudget {
    remaining: usize,
}

impl RegistrationFetchBudget {
    fn for_offer_count(offer_count: usize) -> Self {
        if offer_count == 0 {
            return Self { remaining: 0 };
        }
        Self {
            remaining: MAX_REGISTRATION_FETCHES_PER_SYNC,
        }
    }

    fn try_spend(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemplateFetchBudget {
    remaining: usize,
}

impl TemplateFetchBudget {
    fn for_offer_count(offer_count: usize) -> Self {
        if offer_count == 0 {
            return Self { remaining: 0 };
        }
        let requested = offer_count.saturating_mul(2);
        Self {
            remaining: requested.clamp(1, MAX_TEMPLATE_FETCHES_PER_SYNC),
        }
    }

    fn try_spend(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Debug, Default)]
struct GossipWireResponseFields {
    accepted: bool,
    message_hashes: bool,
    requested_message_hash: bool,
    requested_template_hash: bool,
    requested_miner_id: bool,
    peer_addrs: bool,
}

impl<'de> Deserialize<'de> for GossipWireResponseFields {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldsVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldsVisitor {
            type Value = GossipWireResponseFields;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a gossip response object")
            }

            fn visit_map<A>(
                self,
                mut map: A,
            ) -> std::result::Result<GossipWireResponseFields, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut fields = GossipWireResponseFields::default();
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate gossip response field {key}"
                        )));
                    }
                    match key.as_str() {
                        "accepted" => fields.accepted = true,
                        "message_hashes" => fields.message_hashes = true,
                        "requested_message_hash" => fields.requested_message_hash = true,
                        "requested_template_hash" => fields.requested_template_hash = true,
                        "requested_miner_id" => fields.requested_miner_id = true,
                        "peer_addrs" => fields.peer_addrs = true,
                        _ => {}
                    }
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(fields)
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerListRequest {
    pub known_peers: Vec<SocketAddr>,
    pub listen_addr: Option<SocketAddr>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerListResponse {
    pub peer_addrs: Vec<SocketAddr>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipRebroadcastSummary {
    pub peer_addr: SocketAddr,
    pub offered_count: usize,
    pub accepted_count: usize,
    pub duplicate_count: usize,
    pub rejected_count: usize,
    pub failed_count: usize,
    pub failures: Vec<GossipSyncFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerRoundSummary {
    pub peer_addr: SocketAddr,
    pub discovered_peer_count: usize,
    pub peer_list_error: Option<String>,
    pub sync: Option<GossipSyncSummary>,
    pub sync_error: Option<String>,
    pub rebroadcast: Option<GossipRebroadcastSummary>,
    pub rebroadcast_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipPeerLoopRoundSummary {
    pub datadir: PathBuf,
    pub peer_count: usize,
    pub peer_summaries: Vec<GossipPeerRoundSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
enum GossipWireRequest {
    Envelope(Box<GossipEnvelope>),
    Inventory(GossipInventoryRequest),
    GetEnvelope(GossipEnvelopeRequest),
    GetBitcoinWorkTemplate(GossipBitcoinWorkTemplateRequest),
    GetMinerRegistration(GossipMinerRegistrationRequest),
    PeerList(GossipPeerListRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum GossipWireResponse {
    Submit(GossipPeerResponse),
    Inventory(GossipInventoryResponse),
    Envelope(GossipEnvelopePullResponse),
    BitcoinWorkTemplate(GossipBitcoinWorkTemplatePullResponse),
    MinerRegistration(GossipMinerRegistrationPullResponse),
    Peers(GossipPeerListResponse),
}

pub async fn run_gossip_server(config: GossipServerConfig) -> Result<()> {
    validate_gossip_server_config(&config)?;
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind gossip listener {}", config.bind_addr))?;
    let local_addr = listener
        .local_addr()
        .context("failed to read gossip listener local address")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&GossipServerStatus {
            listening_on: local_addr,
            datadir: config.datadir.clone(),
            protocol: "pohw-gossip-ndjson-v1",
            note: "send one signed GossipEnvelope, inventory request, envelope/template/registration fetch request, or peer-list request per line",
            max_frame_bytes: config.max_frame_bytes,
            max_connections: config.max_connections,
            max_connections_per_ip: config.max_connections_per_ip,
        })?
    );

    let policy = Arc::new(Mutex::new(PeerPolicy::new(config.peer_policy.clone())?));
    let connections = ConnectionLimiter::new(config.max_connections, config.max_connections_per_ip);
    let shared_config = Arc::new(config);
    loop {
        let (stream, remote_addr) = listener
            .accept()
            .await
            .context("failed to accept gossip peer connection")?;
        let Some(connection_guard) = connections.try_acquire(remote_addr.ip()) else {
            let write_timeout = duration_seconds(shared_config.write_timeout_seconds);
            tokio::spawn(async move {
                let response = rejected(None, "connection limit exceeded", None);
                let _ = write_response_to_stream(stream, &response, write_timeout).await;
            });
            continue;
        };
        let policy = Arc::clone(&policy);
        let config = Arc::clone(&shared_config);
        tokio::spawn(async move {
            let _connection_guard = connection_guard;
            if let Err(err) = handle_gossip_connection(stream, remote_addr, config, policy).await {
                eprintln!("warning: gossip peer {remote_addr} disconnected with error: {err:#}");
            }
        });
    }
}

pub async fn run_gossip_mesh(
    server_config: GossipServerConfig,
    peer_loop_config: GossipPeerLoopConfig,
) -> Result<()> {
    validate_gossip_server_config(&server_config)?;
    validate_gossip_peer_loop_config(&peer_loop_config)?;
    tokio::select! {
        result = run_gossip_server(server_config) => result,
        result = run_peer_sync_loop(peer_loop_config) => result,
    }
}

pub async fn run_peer_sync_loop(config: GossipPeerLoopConfig) -> Result<()> {
    validate_gossip_peer_loop_config(&config)?;
    local_node::list_gossip_peers(&config.datadir)?;
    for peer_addr in &config.initial_peers {
        if !is_allowed_peer_addr(*peer_addr, config.allow_public_peers) {
            eprintln!("warning: skipped disallowed seed gossip peer {peer_addr}");
            continue;
        }
        if let Err(err) = local_node::upsert_gossip_peer(&config.datadir, *peer_addr, "seed") {
            eprintln!("warning: failed to seed gossip peer {peer_addr}: {err:#}");
        }
    }

    let mut ticker = interval(duration_seconds(config.sync_interval_seconds));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match run_peer_sync_round(&config).await {
            Ok(summary) => println!("{}", serde_json::to_string_pretty(&summary)?),
            Err(err) => eprintln!("warning: gossip peer sync round failed: {err:#}"),
        }
    }
}

fn validate_gossip_server_config(config: &GossipServerConfig) -> Result<()> {
    if config.max_frame_bytes == 0 || config.max_frame_bytes > MAX_SERVER_FRAME_BYTES {
        bail!(
            "max_frame_bytes must be between 1 and {MAX_SERVER_FRAME_BYTES}, got {}",
            config.max_frame_bytes
        );
    }
    if config.max_connections == 0 || config.max_connections > MAX_SERVER_CONNECTIONS {
        bail!(
            "max_connections must be between 1 and {MAX_SERVER_CONNECTIONS}, got {}",
            config.max_connections
        );
    }
    if config.max_connections_per_ip == 0
        || config.max_connections_per_ip > MAX_SERVER_CONNECTIONS_PER_IP
    {
        bail!(
            "max_connections_per_ip must be between 1 and {MAX_SERVER_CONNECTIONS_PER_IP}, got {}",
            config.max_connections_per_ip
        );
    }
    if config.max_connections_per_ip > config.max_connections {
        bail!(
            "max_connections_per_ip ({}) must not exceed max_connections ({})",
            config.max_connections_per_ip,
            config.max_connections
        );
    }
    validate_gossip_time_window(
        "max_future_skew_seconds",
        config.max_future_skew_seconds,
        MAX_SERVER_TIMEOUT_SECONDS as i64,
    )?;
    validate_gossip_time_window("max_age_seconds", config.max_age_seconds, 86_400 * 30)?;
    validate_positive_timeout("read_timeout_seconds", config.read_timeout_seconds)?;
    validate_positive_timeout("write_timeout_seconds", config.write_timeout_seconds)?;
    PeerPolicy::new(config.peer_policy.clone())?;
    Ok(())
}

fn validate_gossip_peer_loop_config(config: &GossipPeerLoopConfig) -> Result<()> {
    if config.sync_interval_seconds == 0
        || config.sync_interval_seconds > MAX_MESH_SYNC_INTERVAL_SECONDS
    {
        bail!(
            "peer sync interval must be between 1 and {MAX_MESH_SYNC_INTERVAL_SECONDS} seconds, got {}",
            config.sync_interval_seconds
        );
    }
    if config.inventory_limit == 0 || config.inventory_limit > MAX_INVENTORY_LIMIT {
        bail!(
            "inventory_limit must be between 1 and {MAX_INVENTORY_LIMIT}, got {}",
            config.inventory_limit
        );
    }
    if config.peer_list_limit == 0 || config.peer_list_limit > MAX_PEER_LIST_LIMIT {
        bail!(
            "peer_list_limit must be between 1 and {MAX_PEER_LIST_LIMIT}, got {}",
            config.peer_list_limit
        );
    }
    if config.max_peers_per_round == 0 || config.max_peers_per_round > MAX_KNOWN_PEERS {
        bail!(
            "max_peers_per_round must be between 1 and {MAX_KNOWN_PEERS}, got {}",
            config.max_peers_per_round
        );
    }
    if config.max_parallel_peers == 0 || config.max_parallel_peers > MAX_KNOWN_PEERS {
        bail!(
            "max_parallel_peers must be between 1 and {MAX_KNOWN_PEERS}, got {}",
            config.max_parallel_peers
        );
    }
    if config.rebroadcast_limit > MAX_INVENTORY_LIMIT {
        bail!(
            "rebroadcast_limit must not exceed {MAX_INVENTORY_LIMIT}, got {}",
            config.rebroadcast_limit
        );
    }
    validate_gossip_time_window(
        "max_future_skew_seconds",
        config.max_future_skew_seconds,
        MAX_SERVER_TIMEOUT_SECONDS as i64,
    )?;
    validate_gossip_time_window("max_age_seconds", config.max_age_seconds, 86_400 * 30)?;
    if let Some(admission) = &config.work_template_admission {
        let source_count = usize::from(admission.bitcoin_rpc_client.is_some())
            + usize::from(admission.fork_chain_client.is_some());
        if source_count != 1 {
            bail!("work-template admission requires exactly one local validation source");
        }
    }
    Ok(())
}

fn validate_positive_timeout(label: &str, value: u64) -> Result<()> {
    if value == 0 || value > MAX_SERVER_TIMEOUT_SECONDS {
        bail!("{label} must be between 1 and {MAX_SERVER_TIMEOUT_SECONDS}, got {value}");
    }
    Ok(())
}

fn validate_gossip_time_window(label: &str, value: i64, max: i64) -> Result<()> {
    if value <= 0 || value > max {
        bail!("{label} must be between 1 and {max}, got {value}");
    }
    Ok(())
}

pub async fn run_peer_sync_round(
    config: &GossipPeerLoopConfig,
) -> Result<GossipPeerLoopRoundSummary> {
    for peer_addr in &config.initial_peers {
        if !is_allowed_peer_addr(*peer_addr, config.allow_public_peers) {
            eprintln!("warning: skipped disallowed seed gossip peer {peer_addr}");
            continue;
        }
        if let Err(err) = local_node::upsert_gossip_peer(&config.datadir, *peer_addr, "seed") {
            eprintln!("warning: failed to refresh seed gossip peer {peer_addr}: {err:#}");
        }
    }

    let mut peers = local_node::list_gossip_peers(&config.datadir)?;
    peers.retain(|peer| Some(peer.addr) != config.advertise_addr);
    peers.retain(|peer| is_allowed_peer_addr(peer.addr, config.allow_public_peers));
    peers.truncate(config.max_peers_per_round.max(1));

    let shared_config = Arc::new(config.clone());
    let semaphore = Arc::new(Semaphore::new(config.max_parallel_peers.max(1)));
    let mut tasks = Vec::with_capacity(peers.len());
    for peer in &peers {
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .context("gossip peer semaphore was closed")?;
        let config = Arc::clone(&shared_config);
        let peer_addr = peer.addr;
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            run_peer_sync_round_for_peer(config, peer_addr).await
        }));
    }

    let mut peer_summaries = Vec::with_capacity(tasks.len());
    for task in tasks {
        peer_summaries.push(task.await.context("gossip peer sync task panicked")?);
    }
    peer_summaries.sort_by_key(|summary| summary.peer_addr);

    Ok(GossipPeerLoopRoundSummary {
        datadir: config.datadir.clone(),
        peer_count: peers.len(),
        peer_summaries,
    })
}

async fn run_peer_sync_round_for_peer(
    config: Arc<GossipPeerLoopConfig>,
    peer_addr: SocketAddr,
) -> GossipPeerRoundSummary {
    let mut summary = GossipPeerRoundSummary {
        peer_addr,
        discovered_peer_count: 0,
        peer_list_error: None,
        sync: None,
        sync_error: None,
        rebroadcast: None,
        rebroadcast_error: None,
    };

    let known_peers = match local_node::list_gossip_peers(&config.datadir) {
        Ok(peers) => peers.into_iter().map(|peer| peer.addr).collect(),
        Err(err) => {
            summary.peer_list_error = Some(err.to_string());
            Vec::new()
        }
    };
    match request_gossip_peers(
        peer_addr,
        known_peers,
        config.advertise_addr,
        config.peer_list_limit,
    )
    .await
    {
        Ok(response) => {
            for discovered_addr in response.peer_addrs {
                if Some(discovered_addr) == config.advertise_addr {
                    continue;
                }
                if discovered_addr == peer_addr {
                    continue;
                }
                if !is_allowed_peer_addr(discovered_addr, config.allow_public_peers) {
                    continue;
                }
                if local_node::upsert_gossip_peer(&config.datadir, discovered_addr, "discovered")
                    .is_ok()
                {
                    summary.discovered_peer_count += 1;
                }
            }
        }
        Err(err) => {
            summary.peer_list_error = Some(err.to_string());
        }
    }

    let sync_result = if let Some(admission) = config.work_template_admission.as_ref() {
        sync_gossip_from_peer_with_work_template_admission(
            &config.datadir,
            peer_addr,
            config.inventory_limit,
            config.max_future_skew_seconds,
            config.max_age_seconds,
            admission,
        )
        .await
    } else {
        sync_gossip_from_peer(
            &config.datadir,
            peer_addr,
            config.inventory_limit,
            config.max_future_skew_seconds,
            config.max_age_seconds,
        )
        .await
    };

    match sync_result {
        Ok(sync) => {
            summary.sync = Some(sync);
        }
        Err(err) => {
            summary.sync_error = Some(err.to_string());
        }
    }

    match rebroadcast_recent_gossip_to_peer(&config.datadir, peer_addr, config.rebroadcast_limit)
        .await
    {
        Ok(rebroadcast) => {
            summary.rebroadcast = Some(rebroadcast);
        }
        Err(err) => {
            summary.rebroadcast_error = Some(err.to_string());
        }
    }

    if peer_round_is_successful(&summary) {
        if let Err(err) = local_node::record_gossip_peer_success(&config.datadir, peer_addr) {
            eprintln!("warning: failed to record gossip peer {peer_addr} success: {err:#}");
        }
    } else if let Err(err) = local_node::record_gossip_peer_failure(&config.datadir, peer_addr) {
        eprintln!("warning: failed to record gossip peer {peer_addr} failure: {err:#}");
    }

    summary
}

fn peer_round_is_successful(summary: &GossipPeerRoundSummary) -> bool {
    summary
        .sync
        .as_ref()
        .is_some_and(|sync| sync.failed_count == 0)
        || summary.rebroadcast.as_ref().is_some_and(|rebroadcast| {
            rebroadcast.failed_count == 0 && rebroadcast.rejected_count == 0
        })
}

pub async fn send_gossip_envelope_file(addr: SocketAddr, envelope_file: &Path) -> Result<()> {
    let envelope_json = read_bounded_regular_text_file(
        envelope_file,
        "gossip envelope file",
        MAX_GOSSIP_ENVELOPE_FILE_BYTES,
    )?;
    let envelope: GossipEnvelope = serde_json::from_str(&envelope_json).with_context(|| {
        format!(
            "failed to parse gossip envelope {}",
            envelope_file.display()
        )
    })?;
    let response = send_gossip_envelope(addr, &envelope).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn read_bounded_regular_text_file(path: &Path, label: &str, max_bytes: u64) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} {} must not be a symlink", path.display());
    }
    if !metadata.file_type().is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "{label} {} is {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            max_bytes
        );
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))
}

pub async fn send_gossip_envelope(
    addr: SocketAddr,
    envelope: &GossipEnvelope,
) -> Result<GossipPeerResponse> {
    let mut stream = connect_with_timeout(addr).await?;
    let mut payload = serde_json::to_vec(envelope).context("failed to encode gossip envelope")?;
    payload.push(b'\n');
    write_all_with_timeout(&mut stream, &payload)
        .await
        .with_context(|| format!("failed to send gossip envelope to {addr}"))?;

    let mut reader = stream;
    let response = read_bounded_line(
        &mut reader,
        DEFAULT_MAX_GOSSIP_LINE_BYTES,
        Duration::from_secs(DEFAULT_OUTBOUND_READ_TIMEOUT_SECONDS),
    )
    .await
    .with_context(|| format!("failed to read gossip response from {addr}"))?
    .ok_or_else(|| anyhow::anyhow!("gossip peer {addr} closed before sending a response"))?;
    parse_gossip_wire_response(&response)
        .map_err(|err| gossip_response_parse_error(addr, &response, err))
        .and_then(|response| match response {
            GossipWireResponse::Submit(response) => Ok(response),
            GossipWireResponse::Inventory(_)
            | GossipWireResponse::Envelope(_)
            | GossipWireResponse::BitcoinWorkTemplate(_)
            | GossipWireResponse::MinerRegistration(_)
            | GossipWireResponse::Peers(_) => {
                bail!("unexpected non-submit gossip response from {addr}")
            }
        })
}

pub async fn request_gossip_peers(
    addr: SocketAddr,
    known_peers: Vec<SocketAddr>,
    listen_addr: Option<SocketAddr>,
    limit: usize,
) -> Result<GossipPeerListResponse> {
    if known_peers.len() > MAX_KNOWN_PEERS {
        bail!("known peer list exceeds maximum {MAX_KNOWN_PEERS}");
    }
    for peer in &known_peers {
        validate_peer_addr(*peer).map_err(|err| anyhow::anyhow!(err))?;
    }
    if let Some(listen_addr) = listen_addr {
        validate_peer_addr(listen_addr).map_err(|err| anyhow::anyhow!(err))?;
    }
    let requested_limit = limit.clamp(1, MAX_PEER_LIST_LIMIT);
    let response = send_wire_request(
        addr,
        &GossipWireRequest::PeerList(GossipPeerListRequest {
            known_peers,
            listen_addr,
            limit: requested_limit,
        }),
    )
    .await?;
    match response {
        GossipWireResponse::Peers(response) => {
            validate_peer_list_response(response, requested_limit)
        }
        GossipWireResponse::Submit(response) => bail!(
            "gossip peer {addr} rejected peer-list request: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ),
        GossipWireResponse::Inventory(_)
        | GossipWireResponse::Envelope(_)
        | GossipWireResponse::MinerRegistration(_)
        | GossipWireResponse::BitcoinWorkTemplate(_) => {
            bail!("unexpected non-peer-list response from {addr}")
        }
    }
}

pub async fn pull_gossip_inventory(
    addr: SocketAddr,
    known_hashes: Vec<String>,
    limit: usize,
) -> Result<GossipInventoryResponse> {
    if known_hashes.len() > MAX_KNOWN_HASHES {
        bail!("known hash list exceeds maximum {MAX_KNOWN_HASHES}");
    }
    let known_hashes = normalize_hash_set(known_hashes)
        .map_err(|err| anyhow::anyhow!(err))?
        .into_iter()
        .collect();
    let requested_limit = limit.clamp(1, MAX_INVENTORY_LIMIT);
    let response = send_wire_request(
        addr,
        &GossipWireRequest::Inventory(GossipInventoryRequest {
            known_hashes,
            limit: requested_limit,
        }),
    )
    .await?;
    match response {
        GossipWireResponse::Inventory(response) => {
            validate_inventory_response(response, requested_limit)
        }
        GossipWireResponse::Submit(response) => bail!(
            "gossip peer {addr} rejected inventory request: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ),
        GossipWireResponse::Envelope(_) => {
            bail!("unexpected envelope response to inventory request from {addr}")
        }
        GossipWireResponse::BitcoinWorkTemplate(_) => {
            bail!("unexpected Bitcoin work template response to inventory request from {addr}")
        }
        GossipWireResponse::MinerRegistration(_) => {
            bail!("unexpected miner registration response to inventory request from {addr}")
        }
        GossipWireResponse::Peers(_) => {
            bail!("unexpected peer-list response to inventory request from {addr}")
        }
    }
}

pub async fn pull_gossip_envelope(
    addr: SocketAddr,
    message_hash: String,
) -> Result<Option<GossipEnvelope>> {
    let message_hash =
        normalize_hash(&message_hash, "message_hash").map_err(|err| anyhow::anyhow!(err))?;
    let response = send_wire_request(
        addr,
        &GossipWireRequest::GetEnvelope(GossipEnvelopeRequest {
            message_hash: message_hash.clone(),
        }),
    )
    .await?;
    match response {
        GossipWireResponse::Envelope(response) => {
            validate_envelope_fetch_response(response, &message_hash)
        }
        GossipWireResponse::Submit(response) => bail!(
            "gossip peer {addr} rejected envelope fetch for {message_hash}: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ),
        GossipWireResponse::Inventory(_) => {
            bail!("unexpected inventory response to envelope fetch from {addr}")
        }
        GossipWireResponse::BitcoinWorkTemplate(_) => {
            bail!("unexpected Bitcoin work template response to envelope fetch from {addr}")
        }
        GossipWireResponse::MinerRegistration(_) => {
            bail!("unexpected miner registration response to envelope fetch from {addr}")
        }
        GossipWireResponse::Peers(_) => {
            bail!("unexpected peer-list response to envelope fetch from {addr}")
        }
    }
}

pub async fn pull_bitcoin_work_template_envelope(
    addr: SocketAddr,
    template_hash: String,
) -> Result<Option<GossipEnvelope>> {
    let template_hash =
        normalize_hash(&template_hash, "template_hash").map_err(|err| anyhow::anyhow!(err))?;
    let response = send_wire_request(
        addr,
        &GossipWireRequest::GetBitcoinWorkTemplate(GossipBitcoinWorkTemplateRequest {
            template_hash: template_hash.clone(),
        }),
    )
    .await?;
    match response {
        GossipWireResponse::BitcoinWorkTemplate(response) => {
            validate_bitcoin_work_template_fetch_response(response, &template_hash)
        }
        GossipWireResponse::Submit(response) => bail!(
            "gossip peer {addr} rejected Bitcoin work template fetch for {template_hash}: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ),
        GossipWireResponse::Inventory(_) => {
            bail!("unexpected inventory response to Bitcoin work template fetch from {addr}")
        }
        GossipWireResponse::Envelope(_) => {
            bail!("unexpected envelope response to Bitcoin work template fetch from {addr}")
        }
        GossipWireResponse::MinerRegistration(_) => {
            bail!(
                "unexpected miner registration response to Bitcoin work template fetch from {addr}"
            )
        }
        GossipWireResponse::Peers(_) => {
            bail!("unexpected peer-list response to Bitcoin work template fetch from {addr}")
        }
    }
}

pub async fn pull_miner_registration_envelope(
    addr: SocketAddr,
    miner_id: String,
) -> Result<Option<GossipEnvelope>> {
    let miner_id = normalize_miner_id(&miner_id, "miner_id").map_err(|err| anyhow::anyhow!(err))?;
    let response = send_wire_request(
        addr,
        &GossipWireRequest::GetMinerRegistration(GossipMinerRegistrationRequest {
            miner_id: miner_id.clone(),
        }),
    )
    .await?;
    match response {
        GossipWireResponse::MinerRegistration(response) => {
            validate_miner_registration_fetch_response(response, &miner_id)
        }
        GossipWireResponse::Submit(response) => bail!(
            "gossip peer {addr} rejected miner registration fetch for {miner_id}: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ),
        GossipWireResponse::Inventory(_) => {
            bail!("unexpected inventory response to miner registration fetch from {addr}")
        }
        GossipWireResponse::Envelope(_) => {
            bail!("unexpected envelope response to miner registration fetch from {addr}")
        }
        GossipWireResponse::BitcoinWorkTemplate(_) => {
            bail!(
                "unexpected Bitcoin work template response to miner registration fetch from {addr}"
            )
        }
        GossipWireResponse::Peers(_) => {
            bail!("unexpected peer-list response to miner registration fetch from {addr}")
        }
    }
}

fn validate_inventory_response(
    mut response: GossipInventoryResponse,
    requested_limit: usize,
) -> Result<GossipInventoryResponse> {
    if response.message_hashes.len() > requested_limit {
        bail!(
            "gossip peer returned {} inventory hashes, above requested limit {requested_limit}",
            response.message_hashes.len()
        );
    }
    let mut seen = BTreeSet::new();
    for hash in &mut response.message_hashes {
        *hash = normalize_hash(hash, "message_hash").map_err(|err| anyhow::anyhow!(err))?;
        if !seen.insert(hash.clone()) {
            bail!("gossip peer returned duplicate inventory hash {hash}");
        }
    }
    Ok(response)
}

fn validate_envelope_fetch_response(
    response: GossipEnvelopePullResponse,
    requested_message_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    let echoed_message_hash = normalize_hash(&response.requested_message_hash, "message_hash")
        .map_err(|err| anyhow::anyhow!(err))?;
    if echoed_message_hash != requested_message_hash {
        bail!(
            "gossip peer response echoed requested hash {}, expected {requested_message_hash}",
            response.requested_message_hash
        );
    }
    if let Some(envelope) = response.envelope.as_deref() {
        let actual_hash = envelope.message.message_hash();
        if actual_hash != requested_message_hash {
            bail!(
                "gossip peer returned envelope for message hash {actual_hash}, expected {requested_message_hash}"
            );
        }
    }
    Ok(response.envelope.map(|envelope| *envelope))
}

fn validate_bitcoin_work_template_fetch_response(
    response: GossipBitcoinWorkTemplatePullResponse,
    requested_template_hash: &str,
) -> Result<Option<GossipEnvelope>> {
    let echoed_template_hash = normalize_hash(&response.requested_template_hash, "template_hash")
        .map_err(|err| anyhow::anyhow!(err))?;
    if echoed_template_hash != requested_template_hash {
        bail!(
            "gossip peer response echoed requested Bitcoin work template {}, expected {requested_template_hash}",
            response.requested_template_hash
        );
    }
    if let Some(envelope) = response.envelope.as_deref() {
        let SharechainMessage::BitcoinWorkTemplate(template) = &envelope.message else {
            bail!("gossip peer returned non-template envelope for Bitcoin work template fetch");
        };
        if !template
            .template_hash
            .eq_ignore_ascii_case(requested_template_hash)
        {
            bail!(
                "gossip peer returned Bitcoin work template {}, expected {requested_template_hash}",
                template.template_hash
            );
        }
    }
    Ok(response.envelope.map(|envelope| *envelope))
}

fn validate_miner_registration_fetch_response(
    response: GossipMinerRegistrationPullResponse,
    requested_miner_id: &str,
) -> Result<Option<GossipEnvelope>> {
    let echoed_miner_id = normalize_miner_id(&response.requested_miner_id, "miner_id")
        .map_err(|err| anyhow::anyhow!(err))?;
    if echoed_miner_id != requested_miner_id {
        bail!(
            "gossip peer response echoed requested miner id {}, expected {requested_miner_id}",
            response.requested_miner_id
        );
    }
    if let Some(envelope) = response.envelope.as_deref() {
        let SharechainMessage::MinerRegistration(registration) = &envelope.message else {
            bail!("gossip peer returned non-registration envelope for miner registration fetch");
        };
        if !registration
            .miner_id
            .eq_ignore_ascii_case(requested_miner_id)
        {
            bail!(
                "gossip peer returned miner registration {}, expected {requested_miner_id}",
                registration.miner_id
            );
        }
    }
    Ok(response.envelope.map(|envelope| *envelope))
}

fn validate_peer_list_response(
    mut response: GossipPeerListResponse,
    requested_limit: usize,
) -> Result<GossipPeerListResponse> {
    if response.peer_addrs.len() > requested_limit {
        bail!(
            "gossip peer returned {} peers, above requested limit {requested_limit}",
            response.peer_addrs.len()
        );
    }
    let mut seen = BTreeSet::new();
    for peer in &response.peer_addrs {
        validate_peer_addr(*peer).map_err(|err| anyhow::anyhow!(err))?;
        if !seen.insert(*peer) {
            bail!("gossip peer returned duplicate peer address {peer}");
        }
    }
    response.peer_addrs.sort();
    Ok(response)
}

pub async fn sync_gossip_from_peer(
    datadir: &Path,
    addr: SocketAddr,
    limit: usize,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
) -> Result<GossipSyncSummary> {
    sync_gossip_from_peer_inner(
        datadir,
        addr,
        limit,
        max_future_skew_seconds,
        max_age_seconds,
        None,
    )
    .await
}

pub async fn sync_gossip_from_peer_with_work_template_admission(
    datadir: &Path,
    addr: SocketAddr,
    limit: usize,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    work_template_admission: &WorkTemplateAdmissionConfig,
) -> Result<GossipSyncSummary> {
    sync_gossip_from_peer_inner(
        datadir,
        addr,
        limit,
        max_future_skew_seconds,
        max_age_seconds,
        Some(work_template_admission),
    )
    .await
}

async fn sync_gossip_from_peer_inner(
    datadir: &Path,
    addr: SocketAddr,
    limit: usize,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    work_template_admission: Option<&WorkTemplateAdmissionConfig>,
) -> Result<GossipSyncSummary> {
    let known_hashes = local_node::gossip_inventory(datadir)?;
    let local_known_before = known_hashes.len();
    let mut full_known_hashes = known_hashes.iter().cloned().collect::<BTreeSet<_>>();
    let known_hashes_for_request = bounded_recent_hashes(known_hashes, MAX_KNOWN_HASHES);
    let inventory = pull_gossip_inventory(addr, known_hashes_for_request, limit).await?;
    let offered_count = inventory.message_hashes.len();
    let (message_hashes, skipped_known_count) =
        filter_unknown_inventory_offers(&full_known_hashes, inventory.message_hashes);
    let mut fetched_count = 0usize;
    let mut applied_count = 0usize;
    let mut duplicate_count = 0usize;
    let mut failures = Vec::new();
    let mut attempted_hashes = BTreeSet::new();
    let mut parent_fetch_budget = ParentFetchBudget::for_offer_count(message_hashes.len());
    let mut registration_fetch_budget =
        RegistrationFetchBudget::for_offer_count(message_hashes.len());
    let mut template_fetch_budget = TemplateFetchBudget::for_offer_count(message_hashes.len());

    for message_hash in &message_hashes {
        let result = fetch_append_gossip_envelope_and_missing_parents(
            datadir,
            addr,
            message_hash.clone(),
            max_future_skew_seconds,
            max_age_seconds,
            &mut full_known_hashes,
            &mut attempted_hashes,
            &mut parent_fetch_budget,
            &mut registration_fetch_budget,
            &mut template_fetch_budget,
            work_template_admission,
        )
        .await;
        fetched_count += result.fetched_count;
        applied_count += result.applied_count;
        duplicate_count += result.duplicate_count;
        failures.extend(result.failures);
    }

    Ok(GossipSyncSummary {
        peer_addr: addr,
        local_known_before,
        offered_count,
        skipped_known_count,
        inventory_truncated: inventory.truncated,
        fetched_count,
        applied_count,
        duplicate_count,
        failed_count: failures.len(),
        failures,
    })
}

#[derive(Debug, Default)]
struct FetchAppendResult {
    fetched_count: usize,
    applied_count: usize,
    duplicate_count: usize,
    failures: Vec<GossipSyncFailure>,
}

#[allow(clippy::too_many_arguments)]
async fn fetch_append_gossip_envelope_and_missing_parents(
    datadir: &Path,
    addr: SocketAddr,
    message_hash: String,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    known_hashes: &mut BTreeSet<String>,
    attempted_hashes: &mut BTreeSet<String>,
    parent_fetch_budget: &mut ParentFetchBudget,
    registration_fetch_budget: &mut RegistrationFetchBudget,
    template_fetch_budget: &mut TemplateFetchBudget,
    work_template_admission: Option<&WorkTemplateAdmissionConfig>,
) -> FetchAppendResult {
    let mut result = FetchAppendResult::default();
    let mut pending = vec![(message_hash, 0usize)];

    while let Some((message_hash, depth)) = pending.pop() {
        if known_hashes.contains(&message_hash) || !attempted_hashes.insert(message_hash.clone()) {
            continue;
        }
        if depth > 0 && !parent_fetch_budget.try_spend() {
            result.failures.push(GossipSyncFailure {
                message_hash,
                error: "share parent fetch budget exhausted for this sync round".to_string(),
            });
            continue;
        }
        if depth > MAX_SHARE_PARENT_FETCH_DEPTH {
            result.failures.push(GossipSyncFailure {
                message_hash,
                error: format!(
                    "share parent dependency depth exceeds {MAX_SHARE_PARENT_FETCH_DEPTH}"
                ),
            });
            continue;
        }

        let envelope = match pull_gossip_envelope(addr, message_hash.clone()).await {
            Ok(Some(envelope)) => {
                result.fetched_count += 1;
                envelope
            }
            Ok(None) => {
                result.failures.push(GossipSyncFailure {
                    message_hash,
                    error: "peer returned no envelope for requested hash".to_string(),
                });
                continue;
            }
            Err(err) => {
                result.failures.push(GossipSyncFailure {
                    message_hash,
                    error: err.to_string(),
                });
                continue;
            }
        };

        if depth > 0 && !matches!(&envelope.message, SharechainMessage::Share(_)) {
            result.failures.push(GossipSyncFailure {
                message_hash,
                error: "share parent dependency resolved to a non-share message".to_string(),
            });
            continue;
        }

        if let Err(err) = fetch_append_missing_miner_registrations(
            datadir,
            addr,
            &envelope.message,
            max_future_skew_seconds,
            max_age_seconds,
            known_hashes,
            registration_fetch_budget,
            &mut result,
        )
        .await
        {
            result.failures.push(GossipSyncFailure {
                message_hash,
                error: err.to_string(),
            });
            continue;
        }

        if let Err(err) = fetch_append_missing_bitcoin_work_template(
            datadir,
            addr,
            &envelope.message,
            max_future_skew_seconds,
            max_age_seconds,
            known_hashes,
            registration_fetch_budget,
            template_fetch_budget,
            work_template_admission,
            &mut result,
        )
        .await
        {
            result.failures.push(GossipSyncFailure {
                message_hash,
                error: err.to_string(),
            });
            continue;
        }

        let parent_hash = share_parent_dependency(&envelope.message);
        match append_gossip_envelope_after_template_admission(
            datadir,
            envelope,
            max_future_skew_seconds,
            max_age_seconds,
            work_template_admission,
        )
        .await
        {
            Ok(append) => {
                known_hashes.insert(append.message_result.message_hash);
                if append.message_result.outcome == ApplyOutcome::Applied {
                    result.applied_count += 1;
                } else {
                    result.duplicate_count += 1;
                }
                if let Some(parent_hash) = parent_hash {
                    if !known_hashes.contains(&parent_hash) {
                        if depth >= MAX_SHARE_PARENT_FETCH_DEPTH {
                            result.failures.push(GossipSyncFailure {
                                message_hash: parent_hash,
                                error: format!(
                                    "share parent dependency depth exceeds {MAX_SHARE_PARENT_FETCH_DEPTH}"
                                ),
                            });
                        } else {
                            pending.push((parent_hash, depth + 1));
                        }
                    }
                }
            }
            Err(err) => result.failures.push(GossipSyncFailure {
                message_hash,
                error: err.to_string(),
            }),
        }
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn fetch_append_missing_miner_registrations(
    datadir: &Path,
    addr: SocketAddr,
    message: &SharechainMessage,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    known_hashes: &mut BTreeSet<String>,
    registration_fetch_budget: &mut RegistrationFetchBudget,
    result: &mut FetchAppendResult,
) -> Result<()> {
    let dependencies = miner_registration_dependencies(message)?;
    if dependencies.is_empty() {
        return Ok(());
    }

    for miner_id in dependencies {
        if local_node::replay_state(datadir)?
            .registrations()
            .contains_key(&miner_id)
        {
            continue;
        }
        if !registration_fetch_budget.try_spend() {
            bail!("miner registration fetch budget exhausted for this sync round");
        }

        let Some(registration_envelope) =
            pull_miner_registration_envelope(addr, miner_id.clone()).await?
        else {
            bail!("peer returned no miner registration envelope for {miner_id}");
        };
        result.fetched_count += 1;
        let registration_message_hash = registration_envelope.message.message_hash();
        let append = append_gossip_envelope_after_template_admission(
            datadir,
            registration_envelope,
            max_future_skew_seconds,
            max_age_seconds,
            None,
        )
        .await?;
        known_hashes.insert(append.message_result.message_hash);
        if append.message_result.outcome == ApplyOutcome::Applied {
            result.applied_count += 1;
        } else {
            result.duplicate_count += 1;
        }
        if !local_node::replay_state(datadir)?
            .registrations()
            .contains_key(&miner_id)
        {
            bail!(
                "fetched miner registration envelope {registration_message_hash} did not activate miner {miner_id}"
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn fetch_append_missing_bitcoin_work_template(
    datadir: &Path,
    addr: SocketAddr,
    message: &SharechainMessage,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    known_hashes: &mut BTreeSet<String>,
    registration_fetch_budget: &mut RegistrationFetchBudget,
    template_fetch_budget: &mut TemplateFetchBudget,
    work_template_admission: Option<&WorkTemplateAdmissionConfig>,
    result: &mut FetchAppendResult,
) -> Result<()> {
    let Some(template_hash) = bitcoin_template_dependency(message) else {
        return Ok(());
    };
    if local_node::replay_state(datadir)?
        .bitcoin_work_templates()
        .contains_key(&template_hash)
    {
        return Ok(());
    }
    if !template_fetch_budget.try_spend() {
        bail!("Bitcoin work template fetch budget exhausted for this sync round");
    }

    let Some(template_envelope) =
        pull_bitcoin_work_template_envelope(addr, template_hash.clone()).await?
    else {
        bail!("peer returned no Bitcoin work template envelope for {template_hash}");
    };
    result.fetched_count += 1;
    let template_message_hash = template_envelope.message.message_hash();
    fetch_append_missing_miner_registrations(
        datadir,
        addr,
        &template_envelope.message,
        max_future_skew_seconds,
        max_age_seconds,
        known_hashes,
        registration_fetch_budget,
        result,
    )
    .await?;
    let append = append_gossip_envelope_after_template_admission(
        datadir,
        template_envelope,
        max_future_skew_seconds,
        max_age_seconds,
        work_template_admission,
    )
    .await?;
    known_hashes.insert(append.message_result.message_hash);
    if append.message_result.outcome == ApplyOutcome::Applied {
        result.applied_count += 1;
    } else {
        result.duplicate_count += 1;
    }
    if !local_node::replay_state(datadir)?
        .bitcoin_work_templates()
        .contains_key(&template_hash)
    {
        bail!(
            "fetched Bitcoin work template envelope {template_message_hash} did not activate template {template_hash}"
        );
    }
    Ok(())
}

async fn append_gossip_envelope_after_template_admission(
    datadir: &Path,
    envelope: GossipEnvelope,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
    work_template_admission: Option<&WorkTemplateAdmissionConfig>,
) -> Result<local_node::AppendGossipEnvelopeResult> {
    let now = current_unix_timestamp()?;
    envelope.verify_durable_at(now, max_future_skew_seconds)?;
    let historical =
        max_age_seconds > 0 && envelope.created_at_unix < now.saturating_sub(max_age_seconds);
    if let SharechainMessage::BitcoinWorkTemplate(template) = &envelope.message {
        let Some(admission) = work_template_admission else {
            return local_node::append_historical_gossip_envelope(
                datadir,
                envelope,
                max_future_skew_seconds,
            );
        };
        admit_bitcoin_work_template(datadir, template, admission, historical).await?;
    }
    local_node::append_historical_gossip_envelope(datadir, envelope, max_future_skew_seconds)
}

async fn admit_bitcoin_work_template(
    datadir: &Path,
    template: &pohw_core::sharechain::BitcoinWorkTemplate,
    admission: &WorkTemplateAdmissionConfig,
    historical: bool,
) -> Result<()> {
    let template = template.clone().normalized();
    let miner_id = template.miner_id.to_ascii_lowercase();
    let state = local_node::replay_state(datadir)?;
    let registration = state
        .registrations()
        .get(&miner_id)
        .ok_or_else(|| anyhow::anyhow!("template miner is not registered in local replay"))?;
    template.verify_mining_signature(&registration.mining_pubkey_hex)?;
    if let Some(client) = admission.fork_chain_client.as_ref() {
        client
            .validate_work_template(&template)
            .await
            .context("fork-chain RPC rejected work template")?;
    } else if historical {
        admission
            .bitcoin_rpc_client
            .as_ref()
            .context("Bitcoin RPC admission source is not configured")?
            .validate_historical_bitcoin_work_template(&template)
            .await
            .context("Bitcoin RPC rejected historical work template")?;
    } else {
        admission
            .bitcoin_rpc_client
            .as_ref()
            .context("Bitcoin RPC admission source is not configured")?
            .validate_bitcoin_work_template(&template, admission.validation_policy.clone())
            .await
            .context("Bitcoin RPC rejected work template")?;
    }
    local_node::accept_bitcoin_work_template(datadir, template)?;
    Ok(())
}

fn share_parent_dependency(message: &SharechainMessage) -> Option<String> {
    let SharechainMessage::Share(share) = message else {
        return None;
    };
    let parent_hash = share.parent_share_hash.to_ascii_lowercase();
    (parent_hash != ZERO_SHARE_PARENT_HASH).then_some(parent_hash)
}

fn bitcoin_template_dependency(message: &SharechainMessage) -> Option<String> {
    let SharechainMessage::Share(share) = message else {
        return None;
    };
    Some(share.bitcoin_template_hash.to_ascii_lowercase())
}

fn miner_registration_dependencies(message: &SharechainMessage) -> Result<Vec<String>> {
    let mut dependencies = BTreeSet::new();
    match message {
        SharechainMessage::MinerRegistration(_) => {}
        SharechainMessage::BitcoinWorkTemplate(template) => {
            dependencies.insert(
                normalize_miner_id(&template.miner_id, "miner_id")
                    .map_err(|err| anyhow::anyhow!(err))?,
            );
        }
        SharechainMessage::Share(share) => {
            dependencies.insert(
                normalize_miner_id(&share.miner_id, "miner_id")
                    .map_err(|err| anyhow::anyhow!(err))?,
            );
        }
        SharechainMessage::SnapshotVote(vote) => {
            dependencies.insert(
                normalize_miner_id(&vote.voter_miner_id, "voter_miner_id")
                    .map_err(|err| anyhow::anyhow!(err))?,
            );
        }
        SharechainMessage::PayoutSchedule(schedule) => {
            for output in &schedule.direct_outputs {
                dependencies.insert(
                    normalize_miner_id(&output.miner_id, "direct payout miner_id")
                        .map_err(|err| anyhow::anyhow!(err))?,
                );
            }
            for allocation in &schedule.vault_allocations {
                dependencies.insert(
                    normalize_miner_id(&allocation.miner_id, "vault allocation miner_id")
                        .map_err(|err| anyhow::anyhow!(err))?,
                );
            }
        }
        SharechainMessage::WithdrawalRequest(_)
        | SharechainMessage::WithdrawalBatch(_)
        | SharechainMessage::PohwCommitment(_) => {}
    }
    Ok(dependencies.into_iter().collect())
}

fn bounded_recent_hashes(hashes: Vec<String>, max_hashes: usize) -> Vec<String> {
    if hashes.len() <= max_hashes {
        return hashes;
    }
    hashes
        .into_iter()
        .rev()
        .take(max_hashes)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn filter_unknown_inventory_offers(
    known_hashes: &BTreeSet<String>,
    offered_hashes: Vec<String>,
) -> (Vec<String>, usize) {
    let mut skipped_known_count = 0usize;
    let unknown = offered_hashes
        .into_iter()
        .filter(|hash| {
            let known = known_hashes.contains(hash);
            if known {
                skipped_known_count += 1;
            }
            !known
        })
        .collect();
    (unknown, skipped_known_count)
}

pub async fn rebroadcast_recent_gossip_to_peer(
    datadir: &Path,
    addr: SocketAddr,
    limit: usize,
) -> Result<GossipRebroadcastSummary> {
    let envelopes = local_node::recent_gossip_envelopes(datadir, limit)?;
    let offered_count = envelopes.len();
    let mut accepted_count = 0usize;
    let mut duplicate_count = 0usize;
    let mut rejected_count = 0usize;
    let mut failures = Vec::new();

    for stored in envelopes {
        match send_gossip_envelope(addr, &stored.envelope).await {
            Ok(response) if response.accepted => {
                if response.outcome.as_deref() == Some("DuplicateIgnored") {
                    duplicate_count += 1;
                } else {
                    accepted_count += 1;
                }
            }
            Ok(response) => {
                rejected_count += 1;
                failures.push(GossipSyncFailure {
                    message_hash: stored.message_hash,
                    error: response
                        .error
                        .unwrap_or_else(|| "peer rejected envelope".to_string()),
                });
            }
            Err(err) => failures.push(GossipSyncFailure {
                message_hash: stored.message_hash,
                error: err.to_string(),
            }),
        }
    }

    Ok(GossipRebroadcastSummary {
        peer_addr: addr,
        offered_count,
        accepted_count,
        duplicate_count,
        rejected_count,
        failed_count: failures.len(),
        failures,
    })
}

async fn connect_with_timeout(addr: SocketAddr) -> Result<TcpStream> {
    timeout(
        Duration::from_secs(DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECONDS),
        TcpStream::connect(addr),
    )
    .await
    .with_context(|| format!("timed out connecting to gossip peer {addr}"))?
    .with_context(|| format!("failed to connect to gossip peer {addr}"))
}

async fn write_all_with_timeout(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    timeout(
        Duration::from_secs(DEFAULT_OUTBOUND_WRITE_TIMEOUT_SECONDS),
        stream.write_all(payload),
    )
    .await
    .context("timed out writing gossip request")?
    .context("failed to write gossip request")
}

async fn send_wire_request(
    addr: SocketAddr,
    request: &GossipWireRequest,
) -> Result<GossipWireResponse> {
    let mut stream = connect_with_timeout(addr).await?;
    let mut payload = serde_json::to_vec(request).context("failed to encode gossip request")?;
    payload.push(b'\n');
    write_all_with_timeout(&mut stream, &payload)
        .await
        .with_context(|| format!("failed to send gossip request to {addr}"))?;
    let response = read_bounded_line(
        &mut stream,
        DEFAULT_MAX_GOSSIP_LINE_BYTES,
        Duration::from_secs(DEFAULT_OUTBOUND_READ_TIMEOUT_SECONDS),
    )
    .await
    .with_context(|| format!("failed to read gossip response from {addr}"))?
    .ok_or_else(|| anyhow::anyhow!("gossip peer {addr} closed before sending a response"))?;
    parse_gossip_wire_response(&response)
        .map_err(|err| gossip_response_parse_error(addr, &response, err))
}

fn response_snippet(response: &str) -> String {
    const MAX_SNIPPET_CHARS: usize = 512;
    let mut snippet = response
        .chars()
        .take(MAX_SNIPPET_CHARS)
        .flat_map(char::escape_default)
        .collect::<String>();
    if response.chars().count() > MAX_SNIPPET_CHARS {
        snippet.push_str("...");
    }
    snippet
}

fn gossip_response_parse_error(
    addr: SocketAddr,
    response: &str,
    err: anyhow::Error,
) -> anyhow::Error {
    anyhow::anyhow!(
        "failed to parse gossip response from {addr}: {err:#}; response={}",
        response_snippet(response)
    )
}

fn parse_gossip_wire_response(response: &str) -> Result<GossipWireResponse> {
    let fields: GossipWireResponseFields = serde_json::from_str(response)
        .map_err(|err| anyhow::anyhow!("invalid response shape: {err}"))?;
    let mut candidates = Vec::new();
    if fields.accepted {
        candidates.push("submit");
    }
    if fields.message_hashes {
        candidates.push("inventory");
    }
    if fields.requested_message_hash {
        candidates.push("envelope");
    }
    if fields.requested_template_hash {
        candidates.push("bitcoin_work_template");
    }
    if fields.requested_miner_id {
        candidates.push("miner_registration");
    }
    if fields.peer_addrs {
        candidates.push("peers");
    }

    match candidates.as_slice() {
        ["submit"] => serde_json::from_str(response)
            .map(GossipWireResponse::Submit)
            .context("invalid submit response"),
        ["inventory"] => serde_json::from_str(response)
            .map(GossipWireResponse::Inventory)
            .context("invalid inventory response"),
        ["envelope"] => serde_json::from_str(response)
            .map(GossipWireResponse::Envelope)
            .context("invalid envelope response"),
        ["bitcoin_work_template"] => serde_json::from_str(response)
            .map(GossipWireResponse::BitcoinWorkTemplate)
            .context("invalid Bitcoin work template response"),
        ["miner_registration"] => serde_json::from_str(response)
            .map(GossipWireResponse::MinerRegistration)
            .context("invalid miner registration response"),
        ["peers"] => serde_json::from_str(response)
            .map(GossipWireResponse::Peers)
            .context("invalid peer-list response"),
        [] => bail!("response does not match any gossip response shape"),
        _ => bail!("ambiguous gossip response fields: {}", candidates.join(",")),
    }
}

async fn handle_gossip_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    config: Arc<GossipServerConfig>,
    policy: Arc<Mutex<PeerPolicy>>,
) -> Result<()> {
    let remote_ip = remote_addr.ip();
    let (reader, mut writer) = stream.into_split();
    let mut reader = reader;
    let read_timeout = duration_seconds(config.read_timeout_seconds);
    let write_timeout = duration_seconds(config.write_timeout_seconds);

    loop {
        let line = match read_bounded_line(&mut reader, config.max_frame_bytes, read_timeout).await
        {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(err) => {
                let decision = if err.is_peer_fault() {
                    record_invalid_ip(&policy, remote_ip).await
                } else {
                    None
                };
                let response =
                    GossipWireResponse::Submit(rejected(None, err.to_string(), decision));
                write_response(&mut writer, &response, write_timeout).await?;
                return Ok(());
            }
        };
        let response =
            handle_gossip_line(line.as_str(), remote_ip, &config, Arc::clone(&policy)).await;
        write_response(&mut writer, &response, write_timeout).await?;
    }
}

async fn handle_gossip_line(
    line: &str,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let now = match current_unix_timestamp() {
        Ok(now) => now,
        Err(err) => return GossipWireResponse::Submit(rejected(None, err.to_string(), None)),
    };

    let ip_preflight = {
        let mut policy = policy.lock().await;
        policy.check_ip_not_banned(remote_ip, now)
    };
    match ip_preflight {
        Ok(PeerDecision::Allowed) => {}
        Ok(decision) => {
            return GossipWireResponse::Submit(rejected(
                None,
                "ip policy rejected gossip request",
                Some(decision),
            ));
        }
        Err(err) => return GossipWireResponse::Submit(rejected(None, err.to_string(), None)),
    }

    if line.is_empty() {
        let decision = record_invalid_ip(&policy, remote_ip).await;
        return GossipWireResponse::Submit(rejected(None, "empty gossip line", decision));
    }

    let request = match parse_gossip_request(line) {
        Ok(request) => request,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(
                None,
                format!("invalid gossip JSON/request: {err}"),
                decision,
            ));
        }
    };

    match request {
        GossipWireRequest::Envelope(envelope) => GossipWireResponse::Submit(
            handle_gossip_envelope(*envelope, remote_ip, config, policy, now).await,
        ),
        GossipWireRequest::Inventory(request) => {
            if let Some(response) = read_request_rejection(remote_ip, &policy, now).await {
                return response;
            }
            handle_inventory_request(request, remote_ip, config, policy).await
        }
        GossipWireRequest::GetEnvelope(request) => {
            if let Some(response) = read_request_rejection(remote_ip, &policy, now).await {
                return response;
            }
            handle_envelope_fetch_request(request, remote_ip, config, policy).await
        }
        GossipWireRequest::GetBitcoinWorkTemplate(request) => {
            if let Some(response) = read_request_rejection(remote_ip, &policy, now).await {
                return response;
            }
            handle_bitcoin_work_template_fetch_request(request, remote_ip, config, policy).await
        }
        GossipWireRequest::GetMinerRegistration(request) => {
            if let Some(response) = read_request_rejection(remote_ip, &policy, now).await {
                return response;
            }
            handle_miner_registration_fetch_request(request, remote_ip, config, policy).await
        }
        GossipWireRequest::PeerList(request) => {
            if let Some(response) = read_request_rejection(remote_ip, &policy, now).await {
                return response;
            }
            handle_peer_list_request(request, remote_ip, config, policy).await
        }
    }
}

fn parse_gossip_request(line: &str) -> serde_json::Result<GossipWireRequest> {
    match serde_json::from_str::<GossipWireRequest>(line) {
        Ok(request) => Ok(request),
        Err(request_err) => serde_json::from_str::<GossipEnvelope>(line)
            .map(|envelope| GossipWireRequest::Envelope(Box::new(envelope)))
            .map_err(|_| request_err),
    }
}

async fn handle_gossip_envelope(
    envelope: GossipEnvelope,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
    now: i64,
) -> GossipPeerResponse {
    let peer_id = match normalized_peer_id(&envelope.peer_pubkey_xonly_hex) {
        Ok(peer_id) => peer_id,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return rejected(None, err, decision);
        }
    };

    let preflight = {
        let mut policy = policy.lock().await;
        match policy.check_ip_envelope_allowed(remote_ip, now) {
            Ok(PeerDecision::Allowed) => {}
            Ok(decision) => {
                return rejected(Some(peer_id), "ip policy rejected envelope", Some(decision));
            }
            Err(err) => return rejected(Some(peer_id), err.to_string(), None),
        }
        match policy.admit_peer(&peer_id, Some(remote_ip), now) {
            Ok(PeerDecision::Allowed) => {}
            Ok(decision) => {
                return rejected(
                    Some(peer_id),
                    "peer policy rejected envelope",
                    Some(decision),
                );
            }
            Err(err) => {
                return rejected(Some(peer_id), err.to_string(), None);
            }
        }
        match policy.check_envelope_allowed(&peer_id, now) {
            Ok(PeerDecision::Allowed) => Ok(()),
            Ok(decision) => Err(decision),
            Err(err) => {
                return rejected(Some(peer_id), err.to_string(), None);
            }
        }
    };
    if let Err(decision) = preflight {
        return rejected(
            Some(peer_id),
            "peer policy rejected envelope",
            Some(decision),
        );
    }

    match local_node::append_gossip_envelope(
        &config.datadir,
        envelope,
        config.max_future_skew_seconds,
        config.max_age_seconds,
    ) {
        Ok(result) => {
            let mut policy = policy.lock().await;
            let _ = policy.record_valid_ip_envelope(remote_ip);
            let _ = policy.record_valid_envelope(&peer_id);
            GossipPeerResponse {
                accepted: true,
                peer_id: Some(peer_id),
                envelope_hash: Some(result.envelope_hash),
                message_hash: Some(result.message_result.message_hash),
                outcome: Some(format!("{:?}", result.message_result.outcome)),
                error: None,
                peer_decision: None,
            }
        }
        Err(err) => {
            if err.downcast_ref::<local_node::LocalAppendError>().is_some() {
                return rejected(
                    Some(peer_id),
                    format!("local append is temporarily busy: {err}"),
                    None,
                );
            }
            let decision = {
                let mut policy = policy.lock().await;
                let _ = policy.record_invalid_ip_envelope(remote_ip, now);
                policy.record_invalid_envelope(&peer_id, now).ok()
            };
            rejected(Some(peer_id), err.to_string(), decision)
        }
    }
}

async fn handle_inventory_request(
    request: GossipInventoryRequest,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let limit = request.limit.clamp(1, MAX_INVENTORY_LIMIT);
    if request.known_hashes.len() > MAX_KNOWN_HASHES {
        let decision = record_invalid_ip(&policy, remote_ip).await;
        return GossipWireResponse::Submit(rejected(
            None,
            format!("known hash list exceeds maximum {MAX_KNOWN_HASHES}"),
            decision,
        ));
    }

    let known_hashes = match normalize_hash_set(request.known_hashes) {
        Ok(known_hashes) => known_hashes,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(None, err, decision));
        }
    };
    let local_hashes = match local_node::gossip_inventory(&config.datadir) {
        Ok(local_hashes) => local_hashes,
        Err(err) => {
            return GossipWireResponse::Submit(rejected(None, err.to_string(), None));
        }
    };

    let mut message_hashes = Vec::new();
    let mut truncated = false;
    for message_hash in local_hashes.into_iter().rev() {
        if known_hashes.contains(&message_hash) {
            continue;
        }
        if message_hashes.len() >= limit {
            truncated = true;
            break;
        }
        message_hashes.push(message_hash);
    }
    GossipWireResponse::Inventory(GossipInventoryResponse {
        message_hashes,
        truncated,
    })
}

async fn handle_envelope_fetch_request(
    request: GossipEnvelopeRequest,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let message_hash = match normalize_hash(&request.message_hash, "message_hash") {
        Ok(message_hash) => message_hash,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(None, err, decision));
        }
    };
    match local_node::gossip_envelope_by_message_hash(&config.datadir, &message_hash) {
        Ok(envelope) => GossipWireResponse::Envelope(GossipEnvelopePullResponse {
            requested_message_hash: message_hash,
            envelope: envelope.map(Box::new),
        }),
        Err(err) => GossipWireResponse::Submit(rejected(None, err.to_string(), None)),
    }
}

async fn handle_bitcoin_work_template_fetch_request(
    request: GossipBitcoinWorkTemplateRequest,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let template_hash = match normalize_hash(&request.template_hash, "template_hash") {
        Ok(template_hash) => template_hash,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(None, err, decision));
        }
    };
    match local_node::gossip_envelope_by_bitcoin_template_hash(&config.datadir, &template_hash) {
        Ok(envelope) => {
            GossipWireResponse::BitcoinWorkTemplate(GossipBitcoinWorkTemplatePullResponse {
                requested_template_hash: template_hash,
                envelope: envelope.map(Box::new),
            })
        }
        Err(err) => GossipWireResponse::Submit(rejected(None, err.to_string(), None)),
    }
}

async fn handle_miner_registration_fetch_request(
    request: GossipMinerRegistrationRequest,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let miner_id = match normalize_miner_id(&request.miner_id, "miner_id") {
        Ok(miner_id) => miner_id,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(None, err, decision));
        }
    };
    match local_node::gossip_envelope_by_miner_registration_id(&config.datadir, &miner_id) {
        Ok(envelope) => {
            GossipWireResponse::MinerRegistration(GossipMinerRegistrationPullResponse {
                requested_miner_id: miner_id,
                envelope: envelope.map(Box::new),
            })
        }
        Err(err) => GossipWireResponse::Submit(rejected(None, err.to_string(), None)),
    }
}

async fn handle_peer_list_request(
    request: GossipPeerListRequest,
    remote_ip: IpAddr,
    config: &GossipServerConfig,
    policy: Arc<Mutex<PeerPolicy>>,
) -> GossipWireResponse {
    let limit = request.limit.clamp(1, MAX_PEER_LIST_LIMIT);
    if request.known_peers.len() > MAX_KNOWN_PEERS {
        let decision = record_invalid_ip(&policy, remote_ip).await;
        return GossipWireResponse::Submit(rejected(
            None,
            format!("known peer list exceeds maximum {MAX_KNOWN_PEERS}"),
            decision,
        ));
    }
    let known_peers = match normalize_peer_addr_set(request.known_peers) {
        Ok(known_peers) => known_peers,
        Err(err) => {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(None, err, decision));
        }
    };

    if let Some(listen_addr) = request.listen_addr {
        if !is_acceptable_announced_peer(remote_ip, listen_addr, config.allow_public_peers) {
            let decision = record_invalid_ip(&policy, remote_ip).await;
            return GossipWireResponse::Submit(rejected(
                None,
                format!(
                    "announced listen address {listen_addr} does not match remote IP {remote_ip}"
                ),
                decision,
            ));
        }
        if let Err(err) = local_node::upsert_gossip_peer(&config.datadir, listen_addr, "discovered")
        {
            return GossipWireResponse::Submit(rejected(None, err.to_string(), None));
        }
    }

    let peers = match local_node::list_gossip_peers(&config.datadir) {
        Ok(peers) => peers,
        Err(err) => {
            return GossipWireResponse::Submit(rejected(None, err.to_string(), None));
        }
    };

    let mut peer_addrs = Vec::new();
    let mut truncated = false;
    for peer in peers {
        if known_peers.contains(&peer.addr) {
            continue;
        }
        if peer.addr.ip() == remote_ip {
            continue;
        }
        if !is_allowed_peer_addr(peer.addr, config.allow_public_peers) {
            continue;
        }
        if peer_addrs.len() >= limit {
            truncated = true;
            break;
        }
        peer_addrs.push(peer.addr);
    }

    GossipWireResponse::Peers(GossipPeerListResponse {
        peer_addrs,
        truncated,
    })
}

fn rejected(
    peer_id: Option<String>,
    error: impl Into<String>,
    peer_decision: Option<PeerDecision>,
) -> GossipPeerResponse {
    GossipPeerResponse {
        accepted: false,
        peer_id,
        envelope_hash: None,
        message_hash: None,
        outcome: None,
        error: Some(error.into()),
        peer_decision: peer_decision.map(peer_decision_label),
    }
}

fn peer_decision_label(decision: PeerDecision) -> String {
    match decision {
        PeerDecision::Allowed => "allowed".to_string(),
        PeerDecision::RateLimited {
            retry_after_seconds,
        } => format!("rate_limited:{retry_after_seconds}"),
        PeerDecision::Banned { banned_until_unix } => format!("banned_until:{banned_until_unix}"),
        PeerDecision::IpGroupFull {
            ip_group,
            max_peers_per_ip_group,
        } => format!("ip_group_full:{ip_group}:{max_peers_per_ip_group}"),
    }
}

fn normalized_peer_id(raw: &str) -> Result<String, String> {
    let value = raw.strip_prefix("0x").unwrap_or(raw).to_ascii_lowercase();
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("gossip peer id must be 32 bytes encoded as 64 hex characters".to_string());
    }
    Ok(value)
}

fn normalize_hash(raw: &str, label: &str) -> Result<String, String> {
    let value = raw.strip_prefix("0x").unwrap_or(raw).to_ascii_lowercase();
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be 32 bytes encoded as 64 hex characters"
        ));
    }
    Ok(value)
}

fn normalize_miner_id(raw: &str, label: &str) -> Result<String, String> {
    let value = raw.to_ascii_lowercase();
    if value.is_empty() || value.len() > MAX_MINER_ID_LEN {
        return Err(format!("{label} length must be 1..={MAX_MINER_ID_LEN}"));
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{label} may only contain ASCII letters, digits, '-', '_', and '.'"
        ));
    }
    Ok(value)
}

fn normalize_hash_set(raw_hashes: Vec<String>) -> Result<BTreeSet<String>, String> {
    raw_hashes
        .into_iter()
        .map(|hash| normalize_hash(&hash, "known_hash"))
        .collect()
}

fn normalize_peer_addr_set(raw_peers: Vec<SocketAddr>) -> Result<BTreeSet<SocketAddr>, String> {
    raw_peers
        .into_iter()
        .map(|addr| {
            validate_peer_addr(addr)?;
            Ok(addr)
        })
        .collect()
}

fn validate_peer_addr(addr: SocketAddr) -> Result<(), String> {
    if addr.port() == 0 {
        return Err(format!("gossip peer address {addr} has invalid port 0"));
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(format!(
                    "gossip peer address {addr} is not a usable unicast address"
                ));
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!(
                    "gossip peer address {addr} is not a usable unicast address"
                ));
            }
        }
    }
    Ok(())
}

fn is_acceptable_announced_peer(
    remote_ip: IpAddr,
    listen_addr: SocketAddr,
    allow_public_peers: bool,
) -> bool {
    listen_addr.ip() == remote_ip && is_allowed_peer_addr(listen_addr, allow_public_peers)
}

fn is_allowed_peer_addr(addr: SocketAddr, allow_public_peers: bool) -> bool {
    if validate_peer_addr(addr).is_err() {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() || ip.is_private() {
                return true;
            }
            allow_public_peers && is_public_ipv4(ip.octets())
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            if ip.is_loopback() || is_unique_local_ipv6(octets) {
                return true;
            }
            allow_public_peers && is_public_ipv6(octets)
        }
    }
}

fn is_public_ipv4(octets: [u8; 4]) -> bool {
    if octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224
    {
        return false;
    }
    true
}

fn is_unique_local_ipv6(octets: [u8; 16]) -> bool {
    octets[0] & 0xfe == 0xfc
}

fn is_unicast_link_local_ipv6(octets: [u8; 16]) -> bool {
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

fn is_documentation_ipv6(octets: [u8; 16]) -> bool {
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8
}

fn is_public_ipv6(octets: [u8; 16]) -> bool {
    !(is_unique_local_ipv6(octets)
        || is_unicast_link_local_ipv6(octets)
        || is_documentation_ipv6(octets)
        || octets == [0; 16]
        || octets == {
            let mut loopback = [0u8; 16];
            loopback[15] = 1;
            loopback
        })
}

async fn record_invalid_ip(
    policy: &Arc<Mutex<PeerPolicy>>,
    remote_ip: IpAddr,
) -> Option<PeerDecision> {
    let now = current_unix_timestamp().ok()?;
    let mut policy = policy.lock().await;
    policy.record_invalid_ip_envelope(remote_ip, now).ok()
}

async fn read_request_rejection(
    remote_ip: IpAddr,
    policy: &Arc<Mutex<PeerPolicy>>,
    now: i64,
) -> Option<GossipWireResponse> {
    let mut policy = policy.lock().await;
    match policy.check_ip_read_request_allowed(remote_ip, now) {
        Ok(PeerDecision::Allowed) => None,
        Ok(decision) => Some(GossipWireResponse::Submit(rejected(
            None,
            "ip policy rejected read request",
            Some(decision),
        ))),
        Err(err) => Some(GossipWireResponse::Submit(rejected(
            None,
            err.to_string(),
            None,
        ))),
    }
}

async fn read_bounded_line<R>(
    reader: &mut R,
    max_bytes: usize,
    read_timeout: Duration,
) -> Result<Option<String>, GossipReadError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let deadline = Instant::now() + read_timeout;
    loop {
        let mut byte = [0u8; 1];
        let now = Instant::now();
        if now >= deadline {
            return Err(GossipReadError::Timeout);
        }
        let read = timeout(
            deadline.saturating_duration_since(now),
            reader.read(&mut byte),
        )
        .await
        .map_err(|_| GossipReadError::Timeout)??;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(GossipReadError::ClosedMidFrame);
        }
        buffer.push(byte[0]);
        if buffer.len() > max_bytes {
            return Err(GossipReadError::FrameTooLarge { max_bytes });
        }
        if byte[0] == b'\n' {
            break;
        }
    }

    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    String::from_utf8(buffer)
        .map(Some)
        .map_err(|err| GossipReadError::InvalidUtf8(err.to_string()))
}

async fn write_response<W, T>(writer: &mut W, response: &T, write_timeout: Duration) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(response).context("failed to encode gossip response")?;
    bytes.push(b'\n');
    timeout(write_timeout, writer.write_all(&bytes))
        .await
        .context("timed out writing gossip response")?
        .context("failed to write gossip response")
}

async fn write_response_to_stream(
    mut stream: TcpStream,
    response: &GossipPeerResponse,
    write_timeout: Duration,
) -> Result<()> {
    write_response(&mut stream, response, write_timeout).await
}

fn duration_seconds(seconds: u64) -> Duration {
    Duration::from_secs(seconds.max(1))
}

#[derive(Debug, thiserror::Error)]
enum GossipReadError {
    #[error("timed out waiting for gossip frame")]
    Timeout,
    #[error("gossip frame exceeds maximum size {max_bytes} bytes")]
    FrameTooLarge { max_bytes: usize },
    #[error("connection closed before gossip frame newline")]
    ClosedMidFrame,
    #[error("gossip frame is not valid UTF-8: {0}")]
    InvalidUtf8(String),
    #[error("failed to read gossip frame: {0}")]
    Io(#[from] io::Error),
}

impl GossipReadError {
    fn is_peer_fault(&self) -> bool {
        !matches!(self, Self::Io(_))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionLimiter {
    max_connections: usize,
    max_connections_per_ip: usize,
    state: Arc<StdMutex<ConnectionLimiterState>>,
}

#[derive(Debug, Default)]
struct ConnectionLimiterState {
    total: usize,
    by_ip: BTreeMap<IpAddr, usize>,
}

#[derive(Debug)]
pub(crate) struct ConnectionGuard {
    ip: IpAddr,
    state: Arc<StdMutex<ConnectionLimiterState>>,
}

impl ConnectionLimiter {
    pub(crate) fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self {
            max_connections,
            max_connections_per_ip,
            state: Arc::new(StdMutex::new(ConnectionLimiterState::default())),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        let mut state = self.state.lock().ok()?;
        let ip_count = state.by_ip.get(&ip).copied().unwrap_or(0);
        if state.total >= self.max_connections || ip_count >= self.max_connections_per_ip {
            return None;
        }
        state.total += 1;
        *state.by_ip.entry(ip).or_default() += 1;
        Some(ConnectionGuard {
            ip,
            state: Arc::clone(&self.state),
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.total = state.total.saturating_sub(1);
        let mut remove_ip = false;
        if let Some(count) = state.by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            remove_ip = *count == 0;
        }
        if remove_ip {
            state.by_ip.remove(&self.ip);
        }
    }
}

fn current_unix_timestamp() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(duration.as_secs()).context("system timestamp does not fit in i64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::{Message, PublicKey, SecretKey};
    use pohw_core::sharechain::{BitcoinWorkTemplate, MinerRegistration, Share, SharechainMessage};
    use std::fs;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tiny_keccak::{Hasher, Keccak};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pohw-p2p-node-{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn keypair(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn sign_schnorr(hash: [u8; 32], keypair: &Keypair) -> String {
        let secp = Secp256k1::new();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
        hex::encode(signature.serialize())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn send_gossip_envelope_file_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("send-envelope-symlink");
        let target = dir.join("target.json");
        let link = dir.join("envelope.json");
        fs::write(&target, "{}\n").unwrap();
        symlink(&target, &link).unwrap();

        let err = send_gossip_envelope_file("127.0.0.1:1".parse().unwrap(), &link)
            .await
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn send_gossip_envelope_file_rejects_large_file() {
        let dir = temp_dir("send-envelope-large");
        let path = dir.join("envelope.json");
        fs::File::create(&path)
            .unwrap()
            .set_len(MAX_GOSSIP_ENVELOPE_FILE_BYTES + 1)
            .unwrap();

        let err = send_gossip_envelope_file("127.0.0.1:1".parse().unwrap(), &path)
            .await
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn envelope(keypair: &Keypair) -> GossipEnvelope {
        let message = SharechainMessage::PohwCommitment(pohw_core::commitment::PohwCommitment {
            version: "POHW1".to_string(),
            idena_snapshot_id: "day".to_string(),
            idena_score_root: "11".repeat(32),
            miner_idena_address: "0xabc0000000000000000000000000000000000000".to_string(),
            identity_proof_root: "22".repeat(32),
            sharechain_tip: "33".repeat(32),
            sharechain_state_root: Some("44".repeat(32)),
            payout_schedule_root: "44".repeat(32),
            vault_epoch_id: 1,
            frost_vault_key_xonly: keypair.x_only_public_key().0.to_string(),
        });
        let mut envelope = GossipEnvelope::unsigned(
            keypair.x_only_public_key().0.to_string(),
            current_unix_timestamp().unwrap(),
            "55".repeat(32),
            message,
        )
        .unwrap();
        envelope.sign(keypair).unwrap();
        envelope
    }

    fn envelope_for_message(
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

    #[tokio::test]
    async fn historical_sync_append_accepts_stale_signed_non_template_envelope() {
        let datadir = temp_dir("historical-sync-envelope");
        let keypair = keypair(8);
        let mut old = envelope(&keypair);
        old.created_at_unix = current_unix_timestamp().unwrap() - 172_800;
        old.sign(&keypair).unwrap();

        let appended =
            append_gossip_envelope_after_template_admission(&datadir, old, 300, 86_400, None)
                .await
                .unwrap();

        assert_eq!(appended.message_result.outcome, ApplyOutcome::Applied);
        fs::remove_dir_all(datadir).unwrap();
    }

    fn signed_registration() -> (MinerRegistration, Keypair) {
        let mining_keypair = keypair(9);
        let claim_keypair = keypair(10);
        let idena_secret = SecretKey::from_slice(&[13; 32]).unwrap();
        let idena_address = idena_address_from_pubkey(&PublicKey::from_secret_key(
            &Secp256k1::new(),
            &idena_secret,
        ));
        let mut registration = MinerRegistration {
            miner_id: "Miner-A".to_string(),
            idena_address,
            btc_payout_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            claim_owner_pubkey_hex: claim_keypair.x_only_public_key().0.to_string(),
            mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
            idena_signature_hex: String::new(),
            mining_signature_hex: String::new(),
        };
        registration.idena_signature_hex =
            idena_signature(&registration.idena_ownership_challenge(), &idena_secret);
        registration.mining_signature_hex =
            sign_schnorr(registration.signing_hash(), &mining_keypair);
        (registration, mining_keypair)
    }

    fn signed_work_template(share: &Share, keypair: &Keypair) -> BitcoinWorkTemplate {
        let mut template = BitcoinWorkTemplate::new_unsigned(
            share.miner_id.clone(),
            share.bitcoin_header_prefix_hex().unwrap(),
            1,
        )
        .unwrap();
        template.mining_signature_hex = sign_schnorr(template.signing_hash(), keypair);
        template
    }

    fn setup_registration_and_template(
        datadir: &Path,
        registration: &MinerRegistration,
        template: &BitcoinWorkTemplate,
    ) {
        local_node::accept_bitcoin_work_template(datadir, template.clone()).unwrap();
        local_node::append_message(
            datadir,
            SharechainMessage::MinerRegistration(registration.clone()),
        )
        .unwrap();
        local_node::append_message(
            datadir,
            SharechainMessage::BitcoinWorkTemplate(template.clone()),
        )
        .unwrap();
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

    fn mined_test_share(proof_root: &str, parent_hash: &str, mining_keypair: &Keypair) -> Share {
        let target = "7fffff0000000000000000000000000000000000000000000000000000000000";
        for nonce in 0..10_000 {
            let mut share = Share {
                miner_id: "MINER-A".to_string(),
                bitcoin_header_hex: test_bitcoin_header_hex(nonce),
                bitcoin_template_hash: String::new(),
                nonce_hex: String::new(),
                work_hash: String::new(),
                target: target.to_string(),
                idena_snapshot_id: "2026-06-30".to_string(),
                idena_snapshot_proof_root: proof_root.to_string(),
                hashrate_score_delta: 1,
                parent_share_hash: parent_hash.to_string(),
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

    async fn spawn_test_gossip_server(
        datadir: PathBuf,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(config(datadir));
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, remote_addr)) = listener.accept().await else {
                    break;
                };
                let config = Arc::clone(&config);
                let policy = Arc::clone(&policy);
                tokio::spawn(async move {
                    let _ = handle_gossip_connection(stream, remote_addr, config, policy).await;
                });
            }
        });
        (addr, handle)
    }

    async fn spawn_mock_bitcoin_rpc() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _remote_addr)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut request_buf = [0u8; 4096];
                    let _ = stream.read(&mut request_buf).await;
                    let body = serde_json::json!({
                        "result": {
                            "version": 1,
                            "previousblockhash": "00".repeat(32),
                            "curtime": 1_231_006_505u32,
                            "bits": "207fffff",
                            "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
                            "height": 1,
                            "coinbasevalue": 3_125_000_000u64,
                            "mutable": []
                        },
                        "error": null,
                        "id": "pohw-test"
                    })
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), handle)
    }

    fn idena_signature(challenge: &str, secret_key: &SecretKey) -> String {
        let secp = Secp256k1::new();
        let message = Message::from_digest(idena_signin_hash(challenge));
        let signature = secp.sign_ecdsa_recoverable(&message, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut bytes = compact.to_vec();
        bytes.push(u8::try_from(recovery_id.to_i32()).unwrap() + 27);
        hex::encode(bytes)
    }

    fn idena_signin_hash(challenge: &str) -> [u8; 32] {
        keccak256(&keccak256(challenge.as_bytes()))
    }

    fn idena_address_from_pubkey(pubkey: &PublicKey) -> String {
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

    fn config(datadir: PathBuf) -> GossipServerConfig {
        GossipServerConfig {
            datadir,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_future_skew_seconds: 300,
            max_age_seconds: 86_400,
            max_frame_bytes: 1_048_576,
            max_connections: 8,
            max_connections_per_ip: 2,
            read_timeout_seconds: 10,
            write_timeout_seconds: 10,
            allow_public_peers: false,
            peer_policy: PeerPolicyConfig {
                max_envelopes_per_window: 2,
                max_read_requests_per_window: 8,
                rate_window_seconds: 60,
                max_invalid_envelopes: 1,
                ban_seconds: 60,
                max_peers_per_ip_group: 4,
            },
        }
    }

    fn one_envelope_per_ip_config(datadir: PathBuf) -> GossipServerConfig {
        let mut config = config(datadir);
        config.peer_policy.max_envelopes_per_window = 1;
        config.peer_policy.max_peers_per_ip_group = 1;
        config
    }

    fn peer_loop_config(datadir: PathBuf) -> GossipPeerLoopConfig {
        GossipPeerLoopConfig {
            datadir,
            initial_peers: Vec::new(),
            advertise_addr: None,
            sync_interval_seconds: 30,
            inventory_limit: 256,
            rebroadcast_limit: 64,
            peer_list_limit: 64,
            max_peers_per_round: 32,
            max_parallel_peers: 4,
            max_future_skew_seconds: 300,
            max_age_seconds: 86_400,
            allow_public_peers: false,
            work_template_admission: None,
        }
    }

    fn submit_response(response: GossipWireResponse) -> GossipPeerResponse {
        match response {
            GossipWireResponse::Submit(response) => response,
            other => panic!("expected submit response, got {other:?}"),
        }
    }

    #[test]
    fn gossip_server_config_rejects_unsafe_limits() {
        let datadir = temp_dir("server-config-validation");
        let mut invalid_connections = config(datadir.clone());
        invalid_connections.max_connections = 0;
        assert!(validate_gossip_server_config(&invalid_connections).is_err());

        let mut invalid_per_ip = config(datadir.clone());
        invalid_per_ip.max_connections_per_ip = invalid_per_ip.max_connections + 1;
        assert!(validate_gossip_server_config(&invalid_per_ip).is_err());

        let mut invalid_frame = config(datadir.clone());
        invalid_frame.max_frame_bytes = MAX_SERVER_FRAME_BYTES + 1;
        assert!(validate_gossip_server_config(&invalid_frame).is_err());

        let mut invalid_age = config(datadir.clone());
        invalid_age.max_age_seconds = 0;
        assert!(validate_gossip_server_config(&invalid_age).is_err());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn gossip_peer_loop_config_rejects_unsafe_limits() {
        let datadir = temp_dir("peer-loop-config-validation");
        let mut invalid_inventory = peer_loop_config(datadir.clone());
        invalid_inventory.inventory_limit = MAX_INVENTORY_LIMIT + 1;
        assert!(validate_gossip_peer_loop_config(&invalid_inventory).is_err());

        let mut invalid_parallelism = peer_loop_config(datadir.clone());
        invalid_parallelism.max_parallel_peers = 0;
        assert!(validate_gossip_peer_loop_config(&invalid_parallelism).is_err());

        let mut invalid_interval = peer_loop_config(datadir.clone());
        invalid_interval.sync_interval_seconds = 0;
        assert!(validate_gossip_peer_loop_config(&invalid_interval).is_err());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn gossip_line_accepts_valid_envelope_and_appends_message() {
        let datadir = temp_dir("accepts");
        let keypair = keypair(51);
        let envelope = envelope(&keypair);
        let line = serde_json::to_string(&envelope).unwrap();
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config(datadir.clone()).peer_policy).unwrap(),
        ));

        let response = submit_response(
            handle_gossip_line(
                &line,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &config(datadir.clone()),
                policy,
            )
            .await,
        );

        assert!(response.accepted);
        assert_eq!(
            local_node::local_node_status(&datadir)
                .unwrap()
                .replay
                .applied_message_count,
            1
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn inventory_and_fetch_return_accepted_signed_envelope() {
        let datadir = temp_dir("inventory");
        let keypair = keypair(54);
        let envelope = envelope(&keypair);
        let message_hash = envelope.message.message_hash();
        let line = serde_json::to_string(&envelope).unwrap();
        let config = config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let response =
            submit_response(handle_gossip_line(&line, ip, &config, Arc::clone(&policy)).await);
        assert!(response.accepted);

        let inventory_line =
            serde_json::to_string(&GossipWireRequest::Inventory(GossipInventoryRequest {
                known_hashes: Vec::new(),
                limit: 10,
            }))
            .unwrap();
        let inventory = handle_gossip_line(&inventory_line, ip, &config, Arc::clone(&policy)).await;
        let GossipWireResponse::Inventory(inventory) = inventory else {
            panic!("expected inventory response");
        };
        assert_eq!(inventory.message_hashes, vec![message_hash.clone()]);
        assert!(!inventory.truncated);

        let fetch_line =
            serde_json::to_string(&GossipWireRequest::GetEnvelope(GossipEnvelopeRequest {
                message_hash: message_hash.clone(),
            }))
            .unwrap();
        let fetched = handle_gossip_line(&fetch_line, ip, &config, policy).await;
        let GossipWireResponse::Envelope(fetched) = fetched else {
            panic!("expected envelope response");
        };
        assert_eq!(fetched.requested_message_hash, message_hash);
        assert_eq!(fetched.envelope.as_deref(), Some(&envelope));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn read_only_gossip_requests_do_not_consume_envelope_rate_limit() {
        let datadir = temp_dir("read-only-does-not-rate-limit");
        let config = one_envelope_per_ip_config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let known_envelope = envelope(&keypair(59));
        local_node::append_gossip_envelope(&datadir, known_envelope, 300, 86_400).unwrap();

        let inventory_line =
            serde_json::to_string(&GossipWireRequest::Inventory(GossipInventoryRequest {
                known_hashes: Vec::new(),
                limit: 10,
            }))
            .unwrap();
        for _ in 0..2 {
            let response =
                handle_gossip_line(&inventory_line, ip, &config, Arc::clone(&policy)).await;
            assert!(matches!(response, GossipWireResponse::Inventory(_)));
        }

        let submit_envelope = envelope(&keypair(60));
        let submit_line = serde_json::to_string(&submit_envelope).unwrap();
        let response = submit_response(handle_gossip_line(&submit_line, ip, &config, policy).await);

        assert!(response.accepted);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn read_only_gossip_requests_have_separate_ip_rate_limit() {
        let datadir = temp_dir("read-only-rate-limited");
        let mut config = config(datadir.clone());
        config.peer_policy.max_read_requests_per_window = 1;
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        local_node::append_gossip_envelope(&datadir, envelope(&keypair(59)), 300, 86_400).unwrap();

        let inventory_line =
            serde_json::to_string(&GossipWireRequest::Inventory(GossipInventoryRequest {
                known_hashes: Vec::new(),
                limit: 10,
            }))
            .unwrap();
        let first = handle_gossip_line(&inventory_line, ip, &config, Arc::clone(&policy)).await;
        assert!(matches!(first, GossipWireResponse::Inventory(_)));

        let second =
            submit_response(handle_gossip_line(&inventory_line, ip, &config, policy).await);
        assert!(!second.accepted);
        assert_eq!(
            second.error.as_deref(),
            Some("ip policy rejected read request")
        );
        assert!(second
            .peer_decision
            .as_deref()
            .unwrap_or_default()
            .starts_with("rate_limited:"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn envelope_submissions_are_still_ip_rate_limited() {
        let datadir = temp_dir("envelope-rate-limited");
        let config = one_envelope_per_ip_config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let first_line = serde_json::to_string(&envelope(&keypair(61))).unwrap();
        let second_line = serde_json::to_string(&envelope(&keypair(62))).unwrap();

        let first = submit_response(
            handle_gossip_line(&first_line, ip, &config, Arc::clone(&policy)).await,
        );
        let second = submit_response(handle_gossip_line(&second_line, ip, &config, policy).await);

        assert!(first.accepted);
        assert!(!second.accepted);
        assert_eq!(second.error.as_deref(), Some("ip policy rejected envelope"));
        assert!(second
            .peer_decision
            .as_deref()
            .unwrap_or_default()
            .starts_with("rate_limited:"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn inventory_returns_newest_missing_before_old_duplicates() {
        let datadir = temp_dir("inventory-newest");
        let config = config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let old_1 = envelope(&keypair(55));
        let old_2 = envelope(&keypair(56));
        let recent_known = envelope(&keypair(57));
        let newest = envelope(&keypair(58));
        let recent_known_hash = recent_known.message.message_hash();
        let newest_hash = newest.message.message_hash();
        for envelope in [old_1, old_2, recent_known, newest] {
            local_node::append_gossip_envelope(&datadir, envelope, 300, 86_400).unwrap();
        }

        let inventory_line =
            serde_json::to_string(&GossipWireRequest::Inventory(GossipInventoryRequest {
                known_hashes: vec![recent_known_hash],
                limit: 2,
            }))
            .unwrap();
        let response = handle_gossip_line(&inventory_line, ip, &config, policy).await;
        let GossipWireResponse::Inventory(response) = response else {
            panic!("expected inventory response");
        };

        assert_eq!(response.message_hashes.first(), Some(&newest_hash));
        assert!(response.truncated);
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn sync_fetches_missing_share_parent_not_returned_by_inventory() {
        let server_datadir = temp_dir("parent-sync-server");
        let client_datadir = temp_dir("parent-sync-client");
        let (registration, mining_keypair) = signed_registration();
        let parent = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        let parent_hash = parent.share_hash();
        let child = mined_test_share(&"22".repeat(32), &parent_hash, &mining_keypair);
        let child_hash = child.share_hash();
        let template = signed_work_template(&parent, &mining_keypair);
        setup_registration_and_template(&server_datadir, &registration, &template);
        setup_registration_and_template(&client_datadir, &registration, &template);

        let gossip_keypair = keypair(70);
        let parent_envelope =
            envelope_for_message(SharechainMessage::Share(parent), &gossip_keypair, 0x70);
        let child_envelope =
            envelope_for_message(SharechainMessage::Share(child), &gossip_keypair, 0x71);
        local_node::append_gossip_envelope(&server_datadir, parent_envelope, 300, 86_400).unwrap();
        local_node::append_gossip_envelope(&server_datadir, child_envelope, 300, 86_400).unwrap();
        let (server_addr, server_handle) = spawn_test_gossip_server(server_datadir.clone()).await;

        let summary = sync_gossip_from_peer(&client_datadir, server_addr, 1, 300, 86_400)
            .await
            .unwrap();
        let replay = local_node::replay_state(&client_datadir).unwrap().summary();

        assert_eq!(summary.offered_count, 1);
        assert!(summary.inventory_truncated);
        assert_eq!(summary.fetched_count, 2);
        assert_eq!(summary.applied_count, 2);
        assert_eq!(summary.failed_count, 0);
        assert!(summary.failures.is_empty());
        assert_eq!(replay.stored_share_count, 2);
        assert_eq!(replay.active_share_count, 2);
        assert_eq!(replay.inactive_share_count, 0);
        assert_eq!(replay.active_share_score_total, 2);
        assert_eq!(replay.best_share_tip.as_deref(), Some(child_hash.as_str()));

        server_handle.abort();
        fs::remove_dir_all(server_datadir).unwrap();
        fs::remove_dir_all(client_datadir).unwrap();
    }

    #[tokio::test]
    async fn sync_fetches_and_admits_missing_bitcoin_work_template_for_share() {
        let server_datadir = temp_dir("template-sync-server");
        let client_datadir = temp_dir("template-sync-client");
        let (registration, mining_keypair) = signed_registration();
        let share = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        let template = signed_work_template(&share, &mining_keypair);

        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::MinerRegistration(registration),
                &keypair(75),
                0x75,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::accept_bitcoin_work_template(&server_datadir, template.clone()).unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::BitcoinWorkTemplate(template),
                &keypair(76),
                0x76,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(SharechainMessage::Share(share), &keypair(77), 0x77),
            300,
            86_400,
        )
        .unwrap();
        let (server_addr, server_handle) = spawn_test_gossip_server(server_datadir.clone()).await;
        let (rpc_url, rpc_handle) = spawn_mock_bitcoin_rpc().await;
        let admission = WorkTemplateAdmissionConfig {
            bitcoin_rpc_client: Some(BitcoinRpcClient::new(rpc_url, None).unwrap()),
            fork_chain_client: None,
            validation_policy: bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                allow_mutable_time: false,
                max_time_drift_seconds: 7_200,
                expected_header_merkle_root_hex: None,
                allow_unverified_merkle_root: true,
            },
        };

        let summary = sync_gossip_from_peer_with_work_template_admission(
            &client_datadir,
            server_addr,
            1,
            300,
            86_400,
            &admission,
        )
        .await
        .unwrap();
        let replay = local_node::replay_state(&client_datadir).unwrap().summary();

        assert_eq!(summary.offered_count, 1);
        assert!(summary.inventory_truncated);
        assert_eq!(summary.fetched_count, 3);
        assert_eq!(summary.applied_count, 3);
        assert_eq!(summary.failed_count, 0);
        assert!(summary.failures.is_empty());
        assert_eq!(replay.registered_miner_count, 1);
        assert_eq!(replay.bitcoin_work_template_count, 1);
        assert_eq!(replay.stored_share_count, 1);
        assert_eq!(replay.active_share_count, 1);

        server_handle.abort();
        rpc_handle.abort();
        fs::remove_dir_all(server_datadir).unwrap();
        fs::remove_dir_all(client_datadir).unwrap();
    }

    #[tokio::test]
    async fn parent_dependency_fetch_budget_exhaustion_keeps_child_inactive() {
        let server_datadir = temp_dir("parent-budget-server");
        let client_datadir = temp_dir("parent-budget-client");
        let (registration, mining_keypair) = signed_registration();
        let parent = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        let parent_hash = parent.share_hash();
        let child = mined_test_share(&"22".repeat(32), &parent_hash, &mining_keypair);
        let child_hash = child.share_hash();
        let template = signed_work_template(&parent, &mining_keypair);
        setup_registration_and_template(&server_datadir, &registration, &template);
        setup_registration_and_template(&client_datadir, &registration, &template);

        let gossip_keypair = keypair(72);
        let parent_envelope =
            envelope_for_message(SharechainMessage::Share(parent), &gossip_keypair, 0x73);
        let child_envelope =
            envelope_for_message(SharechainMessage::Share(child), &gossip_keypair, 0x74);
        local_node::append_gossip_envelope(&server_datadir, parent_envelope, 300, 86_400).unwrap();
        local_node::append_gossip_envelope(&server_datadir, child_envelope, 300, 86_400).unwrap();
        let (server_addr, server_handle) = spawn_test_gossip_server(server_datadir.clone()).await;

        let mut known_hashes = local_node::gossip_inventory(&client_datadir)
            .unwrap()
            .into_iter()
            .collect();
        let mut attempted_hashes = BTreeSet::new();
        let mut parent_fetch_budget = ParentFetchBudget { remaining: 0 };
        let mut registration_fetch_budget = RegistrationFetchBudget { remaining: 8 };
        let mut template_fetch_budget = TemplateFetchBudget { remaining: 8 };
        let result = fetch_append_gossip_envelope_and_missing_parents(
            &client_datadir,
            server_addr,
            child_hash,
            300,
            86_400,
            &mut known_hashes,
            &mut attempted_hashes,
            &mut parent_fetch_budget,
            &mut registration_fetch_budget,
            &mut template_fetch_budget,
            None,
        )
        .await;
        let replay = local_node::replay_state(&client_datadir).unwrap().summary();

        assert_eq!(result.fetched_count, 1);
        assert_eq!(result.applied_count, 1);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(
            result.failures[0].error,
            "share parent fetch budget exhausted for this sync round"
        );
        assert_eq!(replay.stored_share_count, 1);
        assert_eq!(replay.active_share_count, 0);
        assert_eq!(replay.inactive_share_count, 1);

        server_handle.abort();
        fs::remove_dir_all(server_datadir).unwrap();
        fs::remove_dir_all(client_datadir).unwrap();
    }

    #[tokio::test]
    async fn template_fetch_budget_exhaustion_keeps_share_unapplied() {
        let server_datadir = temp_dir("template-budget-server");
        let client_datadir = temp_dir("template-budget-client");
        let (registration, mining_keypair) = signed_registration();
        let share = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        let share_hash = share.share_hash();
        let template = signed_work_template(&share, &mining_keypair);
        local_node::append_message(
            &client_datadir,
            SharechainMessage::MinerRegistration(registration.clone()),
        )
        .unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::MinerRegistration(registration),
                &keypair(78),
                0x78,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::accept_bitcoin_work_template(&server_datadir, template.clone()).unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::BitcoinWorkTemplate(template),
                &keypair(80),
                0x80,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(SharechainMessage::Share(share), &keypair(79), 0x79),
            300,
            86_400,
        )
        .unwrap();
        let (server_addr, server_handle) = spawn_test_gossip_server(server_datadir.clone()).await;
        let mut known_hashes = local_node::gossip_inventory(&client_datadir)
            .unwrap()
            .into_iter()
            .collect();
        let mut attempted_hashes = BTreeSet::new();
        let mut parent_fetch_budget = ParentFetchBudget { remaining: 8 };
        let mut registration_fetch_budget = RegistrationFetchBudget { remaining: 8 };
        let mut template_fetch_budget = TemplateFetchBudget { remaining: 0 };

        let result = fetch_append_gossip_envelope_and_missing_parents(
            &client_datadir,
            server_addr,
            share_hash,
            300,
            86_400,
            &mut known_hashes,
            &mut attempted_hashes,
            &mut parent_fetch_budget,
            &mut registration_fetch_budget,
            &mut template_fetch_budget,
            None,
        )
        .await;
        let replay = local_node::replay_state(&client_datadir).unwrap().summary();

        assert_eq!(result.fetched_count, 1);
        assert_eq!(result.applied_count, 0);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(
            result.failures[0].error,
            "Bitcoin work template fetch budget exhausted for this sync round"
        );
        assert_eq!(replay.stored_share_count, 0);
        assert_eq!(replay.bitcoin_work_template_count, 0);

        server_handle.abort();
        fs::remove_dir_all(server_datadir).unwrap();
        fs::remove_dir_all(client_datadir).unwrap();
    }

    #[tokio::test]
    async fn registration_fetch_budget_exhaustion_keeps_share_unapplied() {
        let server_datadir = temp_dir("registration-budget-server");
        let client_datadir = temp_dir("registration-budget-client");
        let (registration, mining_keypair) = signed_registration();
        let share = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        let share_hash = share.share_hash();
        let template = signed_work_template(&share, &mining_keypair);
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::MinerRegistration(registration),
                &keypair(81),
                0x81,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::accept_bitcoin_work_template(&server_datadir, template.clone()).unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(
                SharechainMessage::BitcoinWorkTemplate(template),
                &keypair(82),
                0x82,
            ),
            300,
            86_400,
        )
        .unwrap();
        local_node::append_gossip_envelope(
            &server_datadir,
            envelope_for_message(SharechainMessage::Share(share), &keypair(83), 0x83),
            300,
            86_400,
        )
        .unwrap();
        let (server_addr, server_handle) = spawn_test_gossip_server(server_datadir.clone()).await;
        let mut known_hashes = local_node::gossip_inventory(&client_datadir)
            .unwrap()
            .into_iter()
            .collect();
        let mut attempted_hashes = BTreeSet::new();
        let mut parent_fetch_budget = ParentFetchBudget { remaining: 8 };
        let mut registration_fetch_budget = RegistrationFetchBudget { remaining: 0 };
        let mut template_fetch_budget = TemplateFetchBudget { remaining: 8 };

        let result = fetch_append_gossip_envelope_and_missing_parents(
            &client_datadir,
            server_addr,
            share_hash,
            300,
            86_400,
            &mut known_hashes,
            &mut attempted_hashes,
            &mut parent_fetch_budget,
            &mut registration_fetch_budget,
            &mut template_fetch_budget,
            None,
        )
        .await;
        let replay = local_node::replay_state(&client_datadir).unwrap().summary();

        assert_eq!(result.fetched_count, 1);
        assert_eq!(result.applied_count, 0);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(
            result.failures[0].error,
            "miner registration fetch budget exhausted for this sync round"
        );
        assert_eq!(replay.registered_miner_count, 0);
        assert_eq!(replay.bitcoin_work_template_count, 0);
        assert_eq!(replay.stored_share_count, 0);

        server_handle.abort();
        fs::remove_dir_all(server_datadir).unwrap();
        fs::remove_dir_all(client_datadir).unwrap();
    }

    #[test]
    fn inventory_offer_filter_skips_already_known_hashes() {
        let known_hash = "11".repeat(32);
        let unknown_hash = "22".repeat(32);
        let known = std::collections::BTreeSet::from([known_hash.clone()]);

        let (unknown, skipped) =
            filter_unknown_inventory_offers(&known, vec![known_hash, unknown_hash.clone()]);

        assert_eq!(unknown, vec![unknown_hash]);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn inventory_response_validation_rejects_invalid_or_excess_hashes() {
        assert!(validate_inventory_response(
            GossipInventoryResponse {
                message_hashes: vec!["11".repeat(32), "22".repeat(32)],
                truncated: false,
            },
            1,
        )
        .is_err());

        assert!(validate_inventory_response(
            GossipInventoryResponse {
                message_hashes: vec!["not-a-hash".to_string()],
                truncated: false,
            },
            10,
        )
        .is_err());

        assert!(validate_inventory_response(
            GossipInventoryResponse {
                message_hashes: vec!["11".repeat(32), "11".repeat(32)],
                truncated: false,
            },
            10,
        )
        .is_err());
    }

    #[test]
    fn parent_fetch_budget_is_bounded_per_sync_round() {
        assert_eq!(ParentFetchBudget::for_offer_count(0).remaining, 0);
        assert_eq!(
            ParentFetchBudget::for_offer_count(1).remaining,
            MAX_SHARE_PARENT_FETCH_DEPTH
        );
        assert_eq!(
            ParentFetchBudget::for_offer_count(MAX_INVENTORY_LIMIT).remaining,
            MAX_EXTRA_SHARE_PARENT_FETCHES_PER_SYNC
        );
    }

    #[test]
    fn template_fetch_budget_is_bounded_per_sync_round() {
        assert_eq!(TemplateFetchBudget::for_offer_count(0).remaining, 0);
        assert_eq!(TemplateFetchBudget::for_offer_count(1).remaining, 2);
        assert_eq!(
            TemplateFetchBudget::for_offer_count(MAX_INVENTORY_LIMIT).remaining,
            MAX_TEMPLATE_FETCHES_PER_SYNC
        );
    }

    #[test]
    fn registration_fetch_budget_is_bounded_per_sync_round() {
        assert_eq!(RegistrationFetchBudget::for_offer_count(0).remaining, 0);
        assert_eq!(
            RegistrationFetchBudget::for_offer_count(1).remaining,
            MAX_REGISTRATION_FETCHES_PER_SYNC
        );
        assert_eq!(
            RegistrationFetchBudget::for_offer_count(MAX_INVENTORY_LIMIT).remaining,
            MAX_REGISTRATION_FETCHES_PER_SYNC
        );
    }

    #[test]
    fn gossip_response_parser_rejects_ambiguous_shapes() {
        let err = parse_gossip_wire_response(
            r#"{"accepted":true,"message_hashes":[],"truncated":false}"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("ambiguous gossip response fields"));

        let err = parse_gossip_wire_response(
            r#"{"accepted":null,"message_hashes":[],"truncated":false}"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("ambiguous gossip response fields"));
    }

    #[test]
    fn gossip_response_parser_rejects_duplicate_top_level_fields() {
        let err = parse_gossip_wire_response(
            r#"{"requested_message_hash":"1111111111111111111111111111111111111111111111111111111111111111","requested_message_hash":"2222222222222222222222222222222222222222222222222222222222222222","envelope":null}"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("duplicate gossip response field requested_message_hash"));
    }

    #[test]
    fn gossip_response_parser_preserves_large_u128_share_scores() {
        let mining_keypair = keypair(9);
        let mut share = mined_test_share(&"11".repeat(32), ZERO_SHARE_PARENT_HASH, &mining_keypair);
        share.hashrate_score_delta = u128::MAX;
        share.mining_signature_hex = sign_schnorr(share.signing_hash(), &mining_keypair);
        let envelope = envelope_for_message(SharechainMessage::Share(share), &keypair(71), 0x72);
        let response = serde_json::to_string(&GossipEnvelopePullResponse {
            requested_message_hash: envelope.message.message_hash(),
            envelope: Some(Box::new(envelope)),
        })
        .unwrap();

        let parsed = parse_gossip_wire_response(&response).unwrap();
        let GossipWireResponse::Envelope(parsed) = parsed else {
            panic!("expected envelope response");
        };
        let Some(envelope) = parsed.envelope else {
            panic!("expected envelope payload");
        };
        let SharechainMessage::Share(parsed_share) = envelope.message else {
            panic!("expected share message");
        };

        assert_eq!(parsed_share.hashrate_score_delta, u128::MAX);
    }

    #[test]
    fn envelope_fetch_response_must_match_requested_message_hash() {
        let envelope = envelope(&keypair(59));
        let actual_hash = envelope.message.message_hash();
        let wrong_hash = "00".repeat(32);

        assert!(validate_envelope_fetch_response(
            GossipEnvelopePullResponse {
                requested_message_hash: actual_hash.clone(),
                envelope: Some(Box::new(envelope.clone())),
            },
            &wrong_hash,
        )
        .is_err());

        assert!(validate_envelope_fetch_response(
            GossipEnvelopePullResponse {
                requested_message_hash: wrong_hash.clone(),
                envelope: Some(Box::new(envelope)),
            },
            &wrong_hash,
        )
        .is_err());

        assert!(validate_envelope_fetch_response(
            GossipEnvelopePullResponse {
                requested_message_hash: "not-a-hash".to_string(),
                envelope: None,
            },
            &actual_hash,
        )
        .is_err());

        assert!(validate_envelope_fetch_response(
            GossipEnvelopePullResponse {
                requested_message_hash: actual_hash.clone(),
                envelope: None,
            },
            &actual_hash,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn miner_registration_fetch_response_must_match_requested_miner_id() {
        let (registration, _) = signed_registration();
        let registration_envelope = envelope_for_message(
            SharechainMessage::MinerRegistration(registration),
            &keypair(84),
            0x84,
        );

        assert!(validate_miner_registration_fetch_response(
            GossipMinerRegistrationPullResponse {
                requested_miner_id: "MINER-A".to_string(),
                envelope: Some(Box::new(registration_envelope.clone())),
            },
            "miner-a",
        )
        .is_ok());

        assert!(validate_miner_registration_fetch_response(
            GossipMinerRegistrationPullResponse {
                requested_miner_id: "miner-b".to_string(),
                envelope: Some(Box::new(registration_envelope.clone())),
            },
            "miner-a",
        )
        .is_err());

        assert!(validate_miner_registration_fetch_response(
            GossipMinerRegistrationPullResponse {
                requested_miner_id: "miner-a".to_string(),
                envelope: Some(Box::new(envelope(&keypair(85)))),
            },
            "miner-a",
        )
        .is_err());

        assert!(validate_miner_registration_fetch_response(
            GossipMinerRegistrationPullResponse {
                requested_miner_id: "not valid".to_string(),
                envelope: None,
            },
            "miner-a",
        )
        .is_err());
    }

    #[test]
    fn peer_list_response_validation_rejects_excess_or_duplicate_peers() {
        assert!(validate_peer_list_response(
            GossipPeerListResponse {
                peer_addrs: vec![
                    "127.0.0.2:40406".parse().unwrap(),
                    "127.0.0.3:40406".parse().unwrap(),
                ],
                truncated: false,
            },
            1,
        )
        .is_err());

        assert!(validate_peer_list_response(
            GossipPeerListResponse {
                peer_addrs: vec![
                    "127.0.0.2:40406".parse().unwrap(),
                    "127.0.0.2:40406".parse().unwrap(),
                ],
                truncated: false,
            },
            10,
        )
        .is_err());
    }

    #[tokio::test]
    async fn peer_list_request_announces_and_returns_known_peers() {
        let datadir = temp_dir("peer-list");
        let config = config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        let remote_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let known_peer = "127.0.0.2:40406".parse().unwrap();
        local_node::upsert_gossip_peer(&datadir, known_peer, "seed").unwrap();

        let line = serde_json::to_string(&GossipWireRequest::PeerList(GossipPeerListRequest {
            known_peers: Vec::new(),
            listen_addr: Some("127.0.0.1:40406".parse().unwrap()),
            limit: 10,
        }))
        .unwrap();
        let response = handle_gossip_line(&line, remote_ip, &config, policy).await;
        let GossipWireResponse::Peers(response) = response else {
            panic!("expected peer-list response");
        };
        let peers = local_node::list_gossip_peers(&datadir).unwrap();

        assert_eq!(response.peer_addrs, vec![known_peer]);
        assert!(peers
            .iter()
            .any(|peer| peer.addr == "127.0.0.1:40406".parse().unwrap()));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn peer_list_filters_public_peers_by_default() {
        let datadir = temp_dir("peer-list-public-filter");
        let config = config(datadir.clone());
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config.peer_policy.clone()).unwrap(),
        ));
        local_node::upsert_gossip_peer(&datadir, "8.8.8.8:40406".parse().unwrap(), "seed").unwrap();

        let line = serde_json::to_string(&GossipWireRequest::PeerList(GossipPeerListRequest {
            known_peers: Vec::new(),
            listen_addr: Some("127.0.0.1:40406".parse().unwrap()),
            limit: 10,
        }))
        .unwrap();
        let response = handle_gossip_line(
            &line,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            &config,
            policy,
        )
        .await;
        let GossipWireResponse::Peers(response) = response else {
            panic!("expected peer-list response");
        };

        assert!(response.peer_addrs.is_empty());
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn peer_round_success_requires_clean_sync_or_rebroadcast() {
        let mut summary = GossipPeerRoundSummary {
            peer_addr: "127.0.0.1:40406".parse().unwrap(),
            discovered_peer_count: 1,
            peer_list_error: None,
            sync: None,
            sync_error: Some("sync failed".to_string()),
            rebroadcast: None,
            rebroadcast_error: Some("rebroadcast failed".to_string()),
        };
        assert!(!peer_round_is_successful(&summary));

        summary.sync = Some(GossipSyncSummary {
            peer_addr: summary.peer_addr,
            local_known_before: 0,
            offered_count: 0,
            skipped_known_count: 0,
            inventory_truncated: false,
            fetched_count: 0,
            applied_count: 0,
            duplicate_count: 0,
            failed_count: 0,
            failures: Vec::new(),
        });
        assert!(peer_round_is_successful(&summary));
    }

    #[test]
    fn bounded_recent_hashes_keeps_newest_hashes_in_original_order() {
        let hashes = ["01", "02", "03", "04"]
            .into_iter()
            .map(|prefix| format!("{prefix}{}", "00".repeat(31)))
            .collect();

        let bounded = bounded_recent_hashes(hashes, 2);

        assert_eq!(bounded[0], format!("03{}", "00".repeat(31)));
        assert_eq!(bounded[1], format!("04{}", "00".repeat(31)));
    }

    #[tokio::test]
    async fn gossip_line_bans_peer_after_invalid_envelope() {
        let datadir = temp_dir("rejects");
        let keypair = keypair(52);
        let mut envelope = envelope(&keypair);
        if let SharechainMessage::PohwCommitment(commitment) = &mut envelope.message {
            commitment.sharechain_tip = "66".repeat(32);
        }
        let line = serde_json::to_string(&envelope).unwrap();
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config(datadir.clone()).peer_policy).unwrap(),
        ));

        let response = submit_response(
            handle_gossip_line(
                &line,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &config(datadir.clone()),
                policy,
            )
            .await,
        );

        assert!(!response.accepted);
        assert!(response
            .error
            .unwrap()
            .contains("invalid gossip envelope signature"));
        assert!(response.peer_decision.unwrap().starts_with("banned_until:"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn gossip_line_bans_ip_after_malformed_json() {
        let datadir = temp_dir("malformed-json");
        let policy = Arc::new(Mutex::new(
            PeerPolicy::new(config(datadir.clone()).peer_policy).unwrap(),
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let response = submit_response(
            handle_gossip_line("{not-json", ip, &config(datadir.clone()), policy).await,
        );

        assert!(!response.accepted);
        assert!(response.error.unwrap().contains("invalid gossip JSON"));
        assert!(response.peer_decision.unwrap().starts_with("banned_until:"));
        fs::remove_dir_all(datadir).unwrap();
    }

    #[tokio::test]
    async fn bounded_line_reader_rejects_oversized_frame_before_newline() {
        let mut input = Cursor::new(vec![b'a'; 4]);

        let err = read_bounded_line(&mut input, 3, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            GossipReadError::FrameTooLarge { max_bytes: 3 }
        ));
    }

    #[test]
    fn connection_limiter_releases_slots_on_drop() {
        let limiter = ConnectionLimiter::new(1, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let guard = limiter.try_acquire(ip).unwrap();
        assert!(limiter.try_acquire(ip).is_none());
        drop(guard);
        assert!(limiter.try_acquire(ip).is_some());
    }

    #[test]
    fn peer_id_normalization_accepts_prefixed_uppercase_hex() {
        assert_eq!(
            normalized_peer_id(&format!("0x{}", "aa".repeat(32).to_ascii_uppercase())).unwrap(),
            "aa".repeat(32)
        );
    }
}
