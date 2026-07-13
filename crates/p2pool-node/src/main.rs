mod bitcoin_rpc;
mod dashboard_api;
mod fork_chain;
mod frost_signer_daemon;
mod local_node;
mod mining_adapter;
mod p2p_node;
mod peer_policy;

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, SecretKey};
use bitcoin_rpc::{BitcoinRpcClient, BlockchainInfoResponse};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use pohw_core::commitment::PohwCommitment;
use pohw_core::dkg_transport::{
    decrypt_round2_package, dkg_package_hash, encrypt_round2_package, DkgMessageBody,
    DkgMessageEnvelope, DkgPeerIdentity, DkgRound1BroadcastBody, DkgSessionId,
};
use pohw_core::fork::{select_fork_point, ForkActivationManifest, ForkConfig, MainnetBlockRef};
use pohw_core::gossip::GossipEnvelope;
use pohw_core::payout::{ParticipantAccount, PayoutSchedule};
use pohw_core::sharechain::{
    BitcoinWorkTemplate, MinerRegistration, Share, SharechainMessage, SnapshotVote,
};
use pohw_core::sharechain_state::SharechainReplayState;
use pohw_core::vault::{
    threshold_67_percent, vault_script_pubkey_hex, DkgTranscript, FrostSignatureShare,
    SignerHeartbeat, VaultEpoch, VaultInput, VaultRemainderKind, VaultRemainderOutput,
    VaultSigningSession, VaultSpendPlan, MIN_VAULT_INPUT_CONFIRMATIONS,
};
use pohw_core::vault_frost::{
    aggregate_real_frost_vault_transaction_with_transcript, generate_simulated_dkg_frost_key_set,
    participant_frost_identifier_hex, real_frost_create_nonce_commitments, real_frost_dkg_finalize,
    real_frost_dkg_round1, real_frost_dkg_round2, real_frost_dkg_transcript,
    real_frost_sign_spend_plan, run_local_peer_dkg_ceremony,
    sign_vault_spend_plan_with_simulated_keyset, RealFrostDkgState, RealFrostSigningCommitment,
};
use pohw_core::vault_tx::{build_vault_psbt, transaction_output_total_sats, vault_input_sighashes};
use pohw_core::withdrawal::{
    build_withdrawal_batch, estimate_batch_vsize, estimate_fee_sats, WithdrawalOutputKind,
    WithdrawalRequest, P2TR_DUST_SATS,
};
use pohw_core::{DIRECT_PAYOUT_LIMIT, MIN_DIRECT_PAYOUT_SATS};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_PAYOUT_CANDIDATE_DIR: &str = ".pohw-p2pool/payout-candidates";
const MAX_PAYOUT_CANDIDATES_PER_PASS: usize = 512;
const MAX_PAYOUT_CONFIRMATION_CANDIDATE_BYTES: u64 = 64 * 1024;
const MAX_PAYOUT_SCHEDULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_POHW_COMMITMENT_FILE_BYTES: u64 = 256 * 1024;
const MAX_JSON_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FORK_TIMESTAMP_SEARCH_WINDOW_BLOCKS: u64 = 50_000;
const MAX_OPTIONAL_SECRET_BYTES: usize = 512;
const MAX_OPTIONAL_SECRET_FILE_BYTES: u64 = MAX_OPTIONAL_SECRET_BYTES as u64 + 2;
const MAX_SECRET_KEY_FILE_BYTES: u64 = 68;

#[derive(Debug, Parser)]
#[command(name = "p2pool-node")]
#[command(about = "PoHW P2Pool testnet utility commands")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value_t = 30)]
        status_interval_seconds: u64,
        #[arg(long)]
        once: bool,
    },
    Status {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
    },
    RunForkChainNode {
        #[arg(long, default_value = ".pohw-p2pool/fork-chain")]
        datadir: PathBuf,
        #[arg(long)]
        activation_manifest: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40408")]
        rpc_bind_addr: SocketAddr,
        #[arg(long)]
        p2p_bind_addr: Option<SocketAddr>,
        #[arg(long)]
        allow_non_loopback_fork_p2p: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
        #[arg(long, default_value_t = 5)]
        sync_interval_seconds: u64,
    },
    ForkChainStatus {
        #[arg(long)]
        activation_manifest: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40408")]
        rpc_addr: SocketAddr,
        #[arg(long)]
        allow_non_loopback_fork_rpc: bool,
    },
    PrepareForkActivation {
        #[arg(long)]
        chain_name: String,
        #[arg(long)]
        launch_timestamp_utc: String,
        #[arg(long, default_value = "207fffff")]
        post_fork_pow_limit_bits: String,
        #[arg(long, default_value_t = 600)]
        target_spacing_seconds: u64,
        #[arg(long)]
        inherited_utxo_spending_enabled: bool,
        #[arg(long, default_value_t = 4096)]
        timestamp_search_window_blocks: u64,
        #[arg(long)]
        allow_non_mainnet_rpc: bool,
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
    },
    Index {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
    },
    RebuildIndex {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
    },
    AppendMessage {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        message_file: PathBuf,
    },
    CreateGossipEnvelope {
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        created_at_unix: Option<i64>,
        #[arg(long)]
        nonce_hex: Option<String>,
    },
    VerifyGossipEnvelope {
        #[arg(long)]
        envelope_file: PathBuf,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
    },
    VerifyMinerRegistrationEnvelope {
        #[arg(long)]
        envelope_file: PathBuf,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
    },
    AppendGossipEnvelope {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        envelope_file: PathBuf,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
    },
    ServeGossip {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40406")]
        bind_addr: SocketAddr,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
        #[arg(long, default_value_t = 1_048_576)]
        max_frame_bytes: usize,
        #[arg(long, default_value_t = 128)]
        max_connections: usize,
        #[arg(long, default_value_t = 16)]
        max_connections_per_ip: usize,
        #[arg(long, default_value_t = 10)]
        read_timeout_seconds: u64,
        #[arg(long, default_value_t = 10)]
        write_timeout_seconds: u64,
        #[arg(long)]
        allow_public_peers: bool,
        #[arg(long, default_value_t = 120)]
        max_envelopes_per_window: u32,
        #[arg(long, default_value_t = 600)]
        max_read_requests_per_window: u32,
        #[arg(long, default_value_t = 60)]
        rate_window_seconds: i64,
        #[arg(long, default_value_t = 10)]
        max_invalid_envelopes: u32,
        #[arg(long, default_value_t = 3_600)]
        ban_seconds: i64,
        #[arg(long, default_value_t = 4)]
        max_peers_per_ip_group: usize,
    },
    ServeDashboardApi {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, env = "POHW_SNAPSHOT_DIR")]
        snapshot_dir: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:40407")]
        bind_addr: SocketAddr,
        #[arg(long)]
        allow_non_loopback: bool,
        #[arg(long = "dashboard-allowed-origin")]
        dashboard_allowed_origins: Vec<String>,
        #[arg(long, env = "POHW_DASHBOARD_API_TOKEN")]
        dashboard_api_token: Option<String>,
        #[arg(long, env = "POHW_DASHBOARD_API_TOKEN_FILE")]
        dashboard_api_token_file: Option<PathBuf>,
        #[arg(long, env = "POHW_DASHBOARD_MINER_ID")]
        dashboard_miner_id: Option<String>,
        #[arg(long, env = "POHW_DASHBOARD_CLAIM_OWNER_ID")]
        dashboard_claim_owner_id: Option<String>,
        #[arg(long, env = "POHW_DASHBOARD_IDENA_ADDRESS")]
        dashboard_idena_address: Option<String>,
        #[arg(long, default_value_t = 3)]
        dashboard_probe_timeout_seconds: u64,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long)]
        enable_bitcoin_rpc: bool,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        bitcoin_rpc_url: String,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        bitcoin_rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        bitcoin_rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        bitcoin_rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:9009", env = "IDENA_RPC_URL")]
        idena_rpc_url: String,
        #[arg(long, env = "IDENA_API_KEY_FILE")]
        idena_api_key_file: Option<PathBuf>,
    },
    RunGossipMesh {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40406")]
        bind_addr: SocketAddr,
        #[arg(long)]
        advertise_addr: Option<SocketAddr>,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
        #[arg(long, default_value_t = 30)]
        peer_sync_interval_seconds: u64,
        #[arg(long, default_value_t = 256)]
        inventory_limit: usize,
        #[arg(long, default_value_t = 64)]
        rebroadcast_limit: usize,
        #[arg(long, default_value_t = 64)]
        peer_list_limit: usize,
        #[arg(long, default_value_t = 32)]
        max_peers_per_round: usize,
        #[arg(long, default_value_t = 4)]
        max_parallel_peers: usize,
        #[arg(long)]
        allow_public_peers: bool,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
        #[arg(long, default_value_t = 1_048_576)]
        max_frame_bytes: usize,
        #[arg(long, default_value_t = 128)]
        max_connections: usize,
        #[arg(long, default_value_t = 16)]
        max_connections_per_ip: usize,
        #[arg(long, default_value_t = 10)]
        read_timeout_seconds: u64,
        #[arg(long, default_value_t = 10)]
        write_timeout_seconds: u64,
        #[arg(long, default_value_t = 120)]
        max_envelopes_per_window: u32,
        #[arg(long, default_value_t = 600)]
        max_read_requests_per_window: u32,
        #[arg(long, default_value_t = 60)]
        rate_window_seconds: i64,
        #[arg(long, default_value_t = 10)]
        max_invalid_envelopes: u32,
        #[arg(long, default_value_t = 3_600)]
        ban_seconds: i64,
        #[arg(long, default_value_t = 4)]
        max_peers_per_ip_group: usize,
        #[arg(long)]
        admit_peer_work_templates: bool,
        #[arg(long)]
        fork_chain_rpc_addr: Option<SocketAddr>,
        #[arg(long)]
        fork_chain_activation_manifest: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        expected_header_merkle_root_hex: Option<String>,
        #[arg(long)]
        allow_unverified_merkle_root: bool,
        #[arg(long)]
        allow_mutable_time: bool,
        #[arg(long, default_value_t = 7_200)]
        max_template_time_drift_seconds: u32,
    },
    SendGossipEnvelope {
        #[arg(long)]
        peer_addr: SocketAddr,
        #[arg(long)]
        envelope_file: PathBuf,
    },
    GossipInventory {
        #[arg(long)]
        peer_addr: SocketAddr,
        #[arg(long = "known-hash")]
        known_hashes: Vec<String>,
        #[arg(long, default_value_t = 256)]
        limit: usize,
    },
    SyncGossip {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        peer_addr: SocketAddr,
        #[arg(long, default_value_t = 256)]
        limit: usize,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
    },
    AddGossipPeer {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        peer_addr: SocketAddr,
    },
    ListGossipPeers {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
    },
    MultinodePreflight {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        snapshot_dir: Option<PathBuf>,
        #[arg(long)]
        miner_id: Option<String>,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    DeriveXonlyPubkey {
        #[arg(long)]
        secret_key_file: PathBuf,
    },
    CreateMinerRegistration {
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        idena_address: String,
        #[arg(long)]
        btc_payout_script_hex: String,
        #[arg(long)]
        claim_owner_pubkey_hex: String,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long, default_value = "00")]
        idena_signature_hex: String,
    },
    PrepareMinerRegistration {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        idena_address: String,
        #[arg(long)]
        key_dir: Option<PathBuf>,
        #[arg(long)]
        mining_secret_key_file: Option<PathBuf>,
        #[arg(long)]
        claim_owner_secret_key_file: Option<PathBuf>,
        #[arg(long)]
        node_secret_key_file: Option<PathBuf>,
        #[arg(long)]
        btc_payout_script_hex: Option<String>,
        #[arg(long)]
        idena_signature_hex: Option<String>,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    IdenaRegistrationChallenge {
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        idena_address: String,
        #[arg(long)]
        btc_payout_script_hex: String,
        #[arg(long)]
        claim_owner_pubkey_hex: String,
        #[arg(long)]
        mining_pubkey_hex: String,
    },
    CreateShare {
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        bitcoin_header_hex: String,
        #[arg(long)]
        bitcoin_template_hash: Option<String>,
        #[arg(long)]
        nonce_hex: Option<String>,
        #[arg(long)]
        work_hash: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long)]
        idena_snapshot_id: String,
        #[arg(long)]
        idena_snapshot_proof_root: String,
        #[arg(long)]
        hashrate_score_delta: u128,
        #[arg(long)]
        parent_share_hash: String,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
    },
    CreateBitcoinWorkTemplate {
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        bitcoin_header_hex: String,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long)]
        created_at_unix: Option<i64>,
    },
    PublishSnapshotVote {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        snapshot_file: PathBuf,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    PublishBitcoinWorkTemplate {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        bitcoin_header_hex: String,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        created_at_unix: Option<i64>,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long)]
        accept_locally: bool,
        #[arg(long)]
        validate_with_bitcoin_rpc: bool,
        #[arg(long)]
        allow_unverified_local_accept: bool,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        expected_header_merkle_root_hex: Option<String>,
        #[arg(long)]
        allow_unverified_merkle_root: bool,
        #[arg(long)]
        allow_mutable_time: bool,
        #[arg(long, default_value_t = 7_200)]
        max_template_time_drift_seconds: u32,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    PublishShare {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        bitcoin_header_hex: String,
        #[arg(long)]
        bitcoin_template_hash: Option<String>,
        #[arg(long)]
        nonce_hex: Option<String>,
        #[arg(long)]
        work_hash: Option<String>,
        #[arg(long)]
        target: String,
        #[arg(long)]
        idena_snapshot_id: String,
        #[arg(long)]
        idena_snapshot_proof_root: String,
        #[arg(long)]
        hashrate_score_delta: Option<u128>,
        #[arg(long)]
        parent_share_hash: Option<String>,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    RunMiningAdapter {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:3333")]
        bind_addr: SocketAddr,
        #[arg(long)]
        allow_non_loopback_stratum: bool,
        #[arg(long)]
        allow_example_mining_job: bool,
        #[arg(long)]
        miner_id: String,
        #[arg(long)]
        job_file: Option<PathBuf>,
        #[arg(long)]
        fork_chain_rpc_addr: Option<SocketAddr>,
        #[arg(long)]
        fork_chain_activation_manifest: Option<PathBuf>,
        #[arg(long)]
        share_target: Option<String>,
        #[arg(long)]
        idena_snapshot_id: String,
        #[arg(long)]
        idena_snapshot_proof_root: String,
        #[arg(long)]
        mining_secret_key_file: PathBuf,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        stratum_password_file: Option<PathBuf>,
        #[arg(long)]
        block_candidate_dir: Option<PathBuf>,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
        #[arg(long, default_value_t = mining_adapter::default_stratum_difficulty())]
        stratum_difficulty: f64,
        #[arg(long, default_value_t = mining_adapter::default_extranonce2_size())]
        extranonce2_size: usize,
        #[arg(long, default_value_t = mining_adapter::default_max_line_bytes())]
        max_stratum_line_bytes: usize,
        #[arg(long, default_value_t = mining_adapter::default_idle_timeout_seconds())]
        stratum_idle_timeout_seconds: u64,
        #[arg(long)]
        refresh_job_from_rpc: bool,
        #[arg(long, default_value_t = mining_adapter::default_job_refresh_interval_seconds())]
        job_refresh_interval_seconds: u64,
        #[arg(long)]
        auto_submit_blocks: bool,
        #[arg(long)]
        payout_schedule_file: Option<PathBuf>,
        #[arg(long)]
        pohw_commitment_file: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long = "no-append", action = clap::ArgAction::SetFalse, default_value_t = true)]
        append: bool,
    },
    BuildStratumJobRpc {
        #[arg(long)]
        job_out: PathBuf,
        #[arg(long)]
        replace: bool,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = mining_adapter::default_extranonce2_size())]
        extranonce2_size: usize,
    },
    BuildPohwStratumJobRpc {
        #[arg(long)]
        job_out: PathBuf,
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        payout_schedule_file: PathBuf,
        #[arg(long)]
        pohw_commitment_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = mining_adapter::default_extranonce2_size())]
        extranonce2_size: usize,
    },
    BuildStratumBlockCandidate {
        #[arg(long)]
        job_file: PathBuf,
        #[arg(long)]
        candidate_out: Option<PathBuf>,
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        extranonce1: String,
        #[arg(long)]
        extranonce2: String,
        #[arg(long)]
        ntime: String,
        #[arg(long)]
        nonce: String,
        #[arg(long, default_value_t = mining_adapter::default_extranonce2_size())]
        extranonce2_size: usize,
        #[arg(long)]
        require_block_target: bool,
    },
    SubmitStratumBlockCandidate {
        #[arg(long)]
        candidate_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long)]
        allow_mainnet_submit: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
    },
    SubmitForkChainBlockCandidate {
        #[arg(long)]
        candidate_file: PathBuf,
        #[arg(long)]
        activation_manifest: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40408")]
        rpc_addr: SocketAddr,
    },
    CreateWithdrawalRequest {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        claim_owner_secret_key_file: PathBuf,
        #[arg(long)]
        destination_script_hex: String,
        #[arg(long)]
        amount_sats: u64,
        #[arg(long)]
        max_fee_rate_sat_vb: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        expiry_height: u64,
        #[arg(long, default_value = "p2tr")]
        output_kind: String,
        #[arg(long, default_value_t = 0)]
        current_height: u64,
        #[arg(long)]
        node_secret_key_file: PathBuf,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
    },
    AcceptBitcoinWorkTemplate {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        template_file: PathBuf,
    },
    AcceptBitcoinWorkTemplateRpc {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        template_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        expected_header_merkle_root_hex: Option<String>,
        #[arg(long)]
        allow_unverified_merkle_root: bool,
        #[arg(long)]
        allow_mutable_time: bool,
        #[arg(long, default_value_t = 7_200)]
        max_template_time_drift_seconds: u32,
    },
    AdmitPeerWorkTemplates {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        peer_addr: SocketAddr,
        #[arg(long, default_value_t = 256)]
        limit: usize,
        #[arg(long)]
        fork_chain_rpc_addr: Option<SocketAddr>,
        #[arg(long)]
        fork_chain_activation_manifest: Option<PathBuf>,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        expected_header_merkle_root_hex: Option<String>,
        #[arg(long)]
        allow_unverified_merkle_root: bool,
        #[arg(long)]
        allow_mutable_time: bool,
        #[arg(long, default_value_t = 7_200)]
        max_template_time_drift_seconds: u32,
        #[arg(long, default_value_t = 300)]
        max_future_skew_seconds: i64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: i64,
    },
    ShareScore {
        #[arg(long)]
        target: String,
    },
    ProposePayoutSchedule {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        snapshot_file: Option<PathBuf>,
        #[arg(long)]
        reward_sats: u64,
        #[arg(long, default_value_t = DIRECT_PAYOUT_LIMIT)]
        direct_limit: usize,
        #[arg(long, default_value_t = MIN_DIRECT_PAYOUT_SATS)]
        min_direct_payout_sats: u64,
    },
    ConfirmPayoutSchedule {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        snapshot_file: PathBuf,
        #[arg(long)]
        payout_schedule_file: PathBuf,
        #[arg(long)]
        pohw_commitment_file: PathBuf,
        #[arg(long)]
        reward_sats: u64,
        #[arg(long, default_value_t = DIRECT_PAYOUT_LIMIT)]
        direct_limit: usize,
        #[arg(long, default_value_t = MIN_DIRECT_PAYOUT_SATS)]
        min_direct_payout_sats: u64,
        #[arg(long)]
        fork_block_height: u64,
        #[arg(long)]
        fork_block_hash: String,
        #[arg(long)]
        coinbase_txid: String,
        #[arg(long)]
        allow_unverified_manual_confirmation: bool,
    },
    ConfirmPayoutFromBlock {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        snapshot_file: PathBuf,
        #[arg(long)]
        payout_schedule_file: PathBuf,
        #[arg(long)]
        pohw_commitment_file: PathBuf,
        #[arg(long)]
        reward_sats: Option<u64>,
        #[arg(long, default_value_t = DIRECT_PAYOUT_LIMIT)]
        direct_limit: usize,
        #[arg(long, default_value_t = MIN_DIRECT_PAYOUT_SATS)]
        min_direct_payout_sats: u64,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        block_hash: String,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
    },
    RunPayoutConfirmer {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value = DEFAULT_PAYOUT_CANDIDATE_DIR)]
        candidate_dir: PathBuf,
        #[arg(long, default_value_t = 30)]
        poll_interval_seconds: u64,
        #[arg(long)]
        once: bool,
        #[arg(long, default_value_t = MAX_PAYOUT_CANDIDATES_PER_PASS)]
        max_candidates: usize,
        #[arg(long)]
        reward_sats: Option<u64>,
        #[arg(long, default_value_t = DIRECT_PAYOUT_LIMIT)]
        direct_limit: usize,
        #[arg(long, default_value_t = MIN_DIRECT_PAYOUT_SATS)]
        min_direct_payout_sats: u64,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
    },
    VaultThreshold {
        #[arg(long)]
        signers: usize,
    },
    VaultScriptPubkey {
        #[arg(long)]
        vault_key_xonly: String,
    },
    EstimateWithdrawalCost {
        #[arg(long, default_value_t = 1)]
        inputs: usize,
        #[arg(long, default_value_t = 0)]
        p2wpkh_outputs: usize,
        #[arg(long, default_value_t = 0)]
        p2tr_outputs: usize,
        #[arg(long)]
        fee_rate_sat_vb: u64,
    },
    DemoVaultEpoch {
        #[arg(long)]
        epoch_id: u64,
        #[arg(long)]
        starts_at: DateTime<Utc>,
        #[arg(long, default_value_t = 300)]
        max_age_seconds: i64,
        #[arg(long, value_delimiter = ',')]
        signer_ids: Vec<String>,
    },
    DemoVaultRotation {
        #[arg(long, default_value_t = 1)]
        current_epoch_id: u64,
        #[arg(long, default_value_t = 2)]
        next_epoch_id: u64,
        #[arg(long, default_value_t = 4)]
        signers: usize,
        #[arg(long)]
        input_sats: u64,
        #[arg(long)]
        fee_sats: u64,
    },
    DemoVaultPsbt {
        #[arg(long, default_value_t = 1)]
        current_epoch_id: u64,
        #[arg(long, default_value_t = 2)]
        next_epoch_id: u64,
        #[arg(long, default_value_t = 4)]
        signers: usize,
        #[arg(long)]
        input_sats: u64,
        #[arg(long)]
        fee_sats: u64,
    },
    DemoVaultFrostSign {
        #[arg(long, default_value_t = 1)]
        current_epoch_id: u64,
        #[arg(long, default_value_t = 2)]
        next_epoch_id: u64,
        #[arg(long, default_value_t = 4)]
        signers: usize,
        #[arg(long)]
        input_sats: u64,
        #[arg(long)]
        fee_sats: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long)]
        allow_unsafe_demo_vault_signing: bool,
    },
    DemoVaultPeerDkgSign {
        #[arg(long, default_value_t = 1)]
        current_epoch_id: u64,
        #[arg(long, default_value_t = 2)]
        next_epoch_id: u64,
        #[arg(long, default_value_t = 4)]
        signers: usize,
        #[arg(long)]
        input_sats: u64,
        #[arg(long)]
        fee_sats: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long)]
        allow_unsafe_demo_vault_signing: bool,
    },
    DemoDkgTransport {
        #[arg(long, default_value_t = 1)]
        epoch_id: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    CreateFrostDkgPeer {
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        auth_secret_key_file: PathBuf,
        #[arg(long)]
        ecdh_secret_key_file: PathBuf,
        #[arg(long)]
        peer_out: PathBuf,
    },
    RunFrostSigner {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:40409")]
        bind_addr: SocketAddr,
        #[arg(long)]
        allow_non_loopback: bool,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        epoch_id: u64,
        #[arg(long, value_delimiter = ',')]
        signer_ids: Vec<String>,
        #[arg(long)]
        recovery_data_hash: String,
        #[arg(long)]
        auth_secret_key_file: PathBuf,
        #[arg(long)]
        ecdh_secret_key_file: PathBuf,
        #[arg(long = "peer-file")]
        peer_files: Vec<PathBuf>,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
        #[arg(long, default_value_t = 10)]
        sync_interval_seconds: u64,
        #[arg(long, default_value_t = 1_048_576)]
        max_frame_bytes: usize,
        #[arg(long, default_value_t = 64)]
        max_connections: usize,
        #[arg(long)]
        once: bool,
    },
    FrostDkgRound1 {
        #[arg(long)]
        epoch_id: u64,
        #[arg(long)]
        signer_id: String,
        #[arg(long, value_delimiter = ',')]
        signer_ids: Vec<String>,
        #[arg(long)]
        recovery_data_hash: String,
        #[arg(long)]
        auth_secret_key_file: PathBuf,
        #[arg(long)]
        peer_file: PathBuf,
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        envelope_out: PathBuf,
    },
    FrostDkgRound2 {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        auth_secret_key_file: PathBuf,
        #[arg(long = "own-peer-file")]
        peer_file: PathBuf,
        #[arg(long = "peer-file")]
        peer_files: Vec<PathBuf>,
        #[arg(long = "round1-envelope")]
        round1_envelope_files: Vec<PathBuf>,
        #[arg(long)]
        envelope_out_dir: PathBuf,
    },
    FrostDkgFinalize {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        auth_secret_key_file: PathBuf,
        #[arg(long)]
        ecdh_secret_key_file: PathBuf,
        #[arg(long = "own-peer-file")]
        peer_file: PathBuf,
        #[arg(long = "peer-file")]
        peer_files: Vec<PathBuf>,
        #[arg(long = "round1-envelope")]
        round1_envelope_files: Vec<PathBuf>,
        #[arg(long = "round2-envelope")]
        round2_envelope_files: Vec<PathBuf>,
        #[arg(long)]
        ack_out: PathBuf,
    },
    FrostDkgTranscript {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long = "peer-file")]
        peer_files: Vec<PathBuf>,
        #[arg(long = "round1-envelope")]
        round1_envelope_files: Vec<PathBuf>,
        #[arg(long = "round2-envelope")]
        round2_envelope_files: Vec<PathBuf>,
        #[arg(long = "ack-envelope")]
        ack_envelope_files: Vec<PathBuf>,
        #[arg(long)]
        transcript_out: Option<PathBuf>,
    },
    BuildWithdrawalSpendPlan {
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        dkg_transcript_file: PathBuf,
        #[arg(long = "request-id")]
        request_ids: Vec<String>,
        #[arg(long = "request-file")]
        request_files: Vec<PathBuf>,
        #[arg(long = "vault-input-file")]
        vault_input_files: Vec<PathBuf>,
        #[arg(long = "outpoint")]
        outpoints: Vec<String>,
        #[arg(long)]
        fee_rate_sat_vb: u64,
        #[arg(long)]
        current_height: u64,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
        #[arg(long)]
        node_secret_key_file: Option<PathBuf>,
        #[arg(long)]
        message_out: Option<PathBuf>,
        #[arg(long)]
        envelope_out: Option<PathBuf>,
        #[arg(long)]
        append: bool,
        #[arg(long = "peer-addr")]
        peer_addrs: Vec<SocketAddr>,
        #[arg(long)]
        spend_plan_out: PathBuf,
    },
    FrostCreateCommitments {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        spend_plan_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        current_height: Option<u64>,
        #[arg(long)]
        next_dkg_transcript_file: Option<PathBuf>,
        #[arg(long)]
        commitments_out: PathBuf,
    },
    FrostSignShares {
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        spend_plan_file: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
        #[arg(long, default_value = ".pohw-p2pool")]
        datadir: PathBuf,
        #[arg(long)]
        current_height: Option<u64>,
        #[arg(long)]
        next_dkg_transcript_file: Option<PathBuf>,
        #[arg(long = "commitments-file")]
        commitments_files: Vec<PathBuf>,
        #[arg(long)]
        shares_out: PathBuf,
    },
    FrostAggregateTransaction {
        #[arg(long)]
        spend_plan_file: PathBuf,
        #[arg(long)]
        dkg_transcript_file: PathBuf,
        #[arg(long)]
        public_key_package_hex: String,
        #[arg(long = "commitments-file")]
        commitments_files: Vec<PathBuf>,
        #[arg(long = "shares-file")]
        shares_files: Vec<PathBuf>,
        #[arg(long)]
        signed_tx_out: Option<PathBuf>,
    },
    ValidateVaultInput {
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        vout: u32,
        #[arg(long)]
        vault_key_xonly: String,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
    },
    BuildValidatedVaultRotation {
        #[arg(long, default_value = "http://127.0.0.1:8332", env = "BITCOIN_RPC_URL")]
        rpc_url: String,
        #[arg(long)]
        allow_remote_rpc: bool,
        #[arg(long, env = "BITCOIN_RPC_USER")]
        rpc_user: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
        rpc_password: Option<String>,
        #[arg(long, env = "BITCOIN_RPC_COOKIE_FILE")]
        rpc_cookie_file: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        current_epoch_id: u64,
        #[arg(long, default_value_t = 2)]
        next_epoch_id: u64,
        #[arg(long, default_value_t = 4)]
        signers: usize,
        #[arg(long)]
        current_vault_key_xonly: String,
        #[arg(long)]
        next_vault_key_xonly: String,
        #[arg(long)]
        fee_sats: u64,
        #[arg(long, value_name = "TXID:VOUT")]
        outpoint: Vec<String>,
        #[arg(long, default_value_t = MIN_VAULT_INPUT_CONFIRMATIONS)]
        min_confirmations: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutConfirmationCandidate {
    block_hash: String,
    snapshot_file: PathBuf,
    payout_schedule_file: PathBuf,
    pohw_commitment_file: PathBuf,
    #[serde(default)]
    reward_sats: Option<u64>,
    #[serde(default)]
    direct_limit: Option<usize>,
    #[serde(default)]
    min_direct_payout_sats: Option<u64>,
    #[serde(default)]
    min_confirmations: Option<u32>,
}

#[derive(Debug, Clone)]
struct LoadedPayoutConfirmationCandidate {
    path: PathBuf,
    candidate: PayoutConfirmationCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PayoutConfirmerCandidateStatus {
    Confirmed,
    Duplicate,
    Pending,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
struct PayoutConfirmerCandidateResult {
    candidate_file: PathBuf,
    block_hash: Option<String>,
    status: PayoutConfirmerCandidateStatus,
    detail: String,
    confirmations: Option<u32>,
    min_confirmations: Option<u32>,
    record_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PayoutConfirmerSummary {
    candidate_dir: PathBuf,
    scanned_file_count: usize,
    confirmed_count: usize,
    duplicate_count: usize,
    pending_count: usize,
    failed_count: usize,
    results: Vec<PayoutConfirmerCandidateResult>,
}

#[derive(Debug, Clone, Copy)]
struct PayoutConfirmerDefaults {
    reward_sats: Option<u64>,
    direct_limit: usize,
    min_direct_payout_sats: u64,
    min_confirmations: u32,
    max_candidates: usize,
}

#[derive(Debug, Clone, Copy)]
struct PublishBitcoinWorkTemplateFlags {
    append: bool,
    accept_locally: bool,
    validate_with_bitcoin_rpc: bool,
    allow_unverified_local_accept: bool,
    has_expected_header_merkle_root: bool,
    allow_unverified_merkle_root: bool,
    allow_mutable_time: bool,
}

fn validate_publish_bitcoin_work_template_flags(
    flags: PublishBitcoinWorkTemplateFlags,
) -> Result<()> {
    if flags.has_expected_header_merkle_root && flags.allow_unverified_merkle_root {
        anyhow::bail!(
            "--expected-header-merkle-root-hex cannot be combined with --allow-unverified-merkle-root"
        );
    }
    if flags.validate_with_bitcoin_rpc && flags.allow_unverified_local_accept {
        anyhow::bail!(
            "--validate-with-bitcoin-rpc cannot be combined with --allow-unverified-local-accept"
        );
    }
    if flags.allow_unverified_local_accept && !flags.accept_locally {
        anyhow::bail!("--allow-unverified-local-accept requires --accept-locally");
    }
    if flags.accept_locally
        && !flags.validate_with_bitcoin_rpc
        && !flags.allow_unverified_local_accept
    {
        anyhow::bail!(
            "--accept-locally requires --validate-with-bitcoin-rpc or --allow-unverified-local-accept"
        );
    }
    if flags.append && !flags.accept_locally {
        anyhow::bail!("--append for publish-bitcoin-work-template requires --accept-locally");
    }
    if !flags.validate_with_bitcoin_rpc
        && (flags.has_expected_header_merkle_root
            || flags.allow_unverified_merkle_root
            || flags.allow_mutable_time)
    {
        anyhow::bail!("Bitcoin RPC validation policy flags require --validate-with-bitcoin-rpc");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            datadir,
            status_interval_seconds,
            once,
        } => {
            local_node::run_local_node(&datadir, status_interval_seconds, once)?;
        }
        Command::Status { datadir } => {
            let status = local_node::local_node_status(&datadir)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::RunForkChainNode {
            datadir,
            activation_manifest,
            rpc_bind_addr,
            p2p_bind_addr,
            allow_non_loopback_fork_p2p,
            peer_addrs,
            sync_interval_seconds,
        } => {
            fork_chain::run_fork_chain_node(fork_chain::ForkChainNodeConfig {
                datadir,
                activation_manifest,
                rpc_bind_addr,
                p2p_bind_addr,
                allow_non_loopback_p2p: allow_non_loopback_fork_p2p,
                peer_addrs,
                sync_interval_seconds,
            })
            .await?;
        }
        Command::ForkChainStatus {
            activation_manifest,
            rpc_addr,
            allow_non_loopback_fork_rpc,
        } => {
            let manifest = fork_chain::read_activation_manifest(&activation_manifest)?;
            let client = fork_chain::ForkChainClient::new(
                rpc_addr,
                manifest.activation_id,
                allow_non_loopback_fork_rpc,
            )?;
            println!("{}", serde_json::to_string_pretty(&client.status().await?)?);
        }
        Command::PrepareForkActivation {
            chain_name,
            launch_timestamp_utc,
            post_fork_pow_limit_bits,
            target_spacing_seconds,
            inherited_utxo_spending_enabled,
            timestamp_search_window_blocks,
            allow_non_mainnet_rpc,
            manifest_out,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
        } => {
            let launch_timestamp_utc =
                parse_utc_datetime_arg("launch-timestamp-utc", &launch_timestamp_utc)?;
            let post_fork_pow_limit_bits =
                parse_compact_bits_arg("post-fork-pow-limit-bits", &post_fork_pow_limit_bits)?;
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let manifest = prepare_fork_activation(
                &client,
                PrepareForkActivationInput {
                    chain_name,
                    launch_timestamp_utc,
                    inherited_utxo_spending_enabled,
                    post_fork_pow_limit_bits,
                    target_spacing_seconds,
                    timestamp_search_window_blocks,
                    allow_non_mainnet_rpc,
                },
            )
            .await?;
            if let Some(path) = manifest_out {
                write_json_file(&path, &manifest)?;
            }
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::Index { datadir } => {
            let index = local_node::sharechain_index(&datadir)?;
            println!("{}", serde_json::to_string_pretty(&index)?);
        }
        Command::RebuildIndex { datadir } => {
            let index = local_node::rebuild_sharechain_index(&datadir)?;
            println!("{}", serde_json::to_string_pretty(&index)?);
        }
        Command::AppendMessage {
            datadir,
            message_file,
        } => {
            let result = local_node::append_message_file(&datadir, &message_file)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::CreateGossipEnvelope {
            message_file,
            node_secret_key_file,
            created_at_unix,
            nonce_hex,
        } => {
            let node_keypair = read_keypair_from_file(&node_secret_key_file)?;
            let message = read_sharechain_message_file(&message_file)?;
            let created_at_unix = created_at_unix.unwrap_or(current_unix_timestamp()?);
            let nonce_hex = nonce_hex.unwrap_or_else(random_nonce_hex);
            let mut envelope = GossipEnvelope::unsigned(
                node_keypair.x_only_public_key().0.to_string(),
                created_at_unix,
                nonce_hex,
                message,
            )?;
            envelope.sign(&node_keypair)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        }
        Command::VerifyGossipEnvelope {
            envelope_file,
            max_future_skew_seconds,
            max_age_seconds,
        } => {
            let envelope = read_gossip_envelope_file(&envelope_file)?;
            envelope.verify_at(
                current_unix_timestamp()?,
                max_future_skew_seconds,
                max_age_seconds,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "valid": true,
                    "envelope_hash": envelope.envelope_hash(),
                    "peer_pubkey_xonly_hex": envelope.peer_pubkey_xonly_hex,
                    "message_hash": envelope.message.message_hash(),
                }))?
            );
        }
        Command::VerifyMinerRegistrationEnvelope {
            envelope_file,
            max_future_skew_seconds,
            max_age_seconds,
        } => {
            let envelope = read_gossip_envelope_file(&envelope_file)?;
            let registration = verified_miner_registration_from_envelope(
                &envelope,
                max_future_skew_seconds,
                max_age_seconds,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "valid": true,
                    "proof_type": "MinerRegistration",
                    "envelope_hash": envelope.envelope_hash(),
                    "peer_pubkey_xonly_hex": envelope.peer_pubkey_xonly_hex,
                    "message_hash": envelope.message.message_hash(),
                    "miner_registration": {
                        "miner_id": registration.miner_id,
                        "idena_address": registration.idena_address,
                        "btc_payout_script_hex": registration.btc_payout_script_hex,
                        "claim_owner_pubkey_hex": registration.claim_owner_pubkey_hex,
                        "mining_pubkey_hex": registration.mining_pubkey_hex,
                    },
                }))?
            );
        }
        Command::AppendGossipEnvelope {
            datadir,
            envelope_file,
            max_future_skew_seconds,
            max_age_seconds,
        } => {
            let result = local_node::append_gossip_envelope_file(
                &datadir,
                &envelope_file,
                max_future_skew_seconds,
                max_age_seconds,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::ServeGossip {
            datadir,
            bind_addr,
            max_future_skew_seconds,
            max_age_seconds,
            max_frame_bytes,
            max_connections,
            max_connections_per_ip,
            read_timeout_seconds,
            write_timeout_seconds,
            allow_public_peers,
            max_envelopes_per_window,
            max_read_requests_per_window,
            rate_window_seconds,
            max_invalid_envelopes,
            ban_seconds,
            max_peers_per_ip_group,
        } => {
            p2p_node::run_gossip_server(p2p_node::GossipServerConfig {
                datadir,
                bind_addr,
                max_future_skew_seconds,
                max_age_seconds,
                max_frame_bytes,
                max_connections,
                max_connections_per_ip,
                read_timeout_seconds,
                write_timeout_seconds,
                allow_public_peers,
                peer_policy: peer_policy::PeerPolicyConfig {
                    max_envelopes_per_window,
                    max_read_requests_per_window,
                    rate_window_seconds,
                    max_invalid_envelopes,
                    ban_seconds,
                    max_peers_per_ip_group,
                },
            })
            .await?;
        }
        Command::ServeDashboardApi {
            datadir,
            snapshot_dir,
            bind_addr,
            allow_non_loopback,
            dashboard_allowed_origins,
            dashboard_api_token,
            dashboard_api_token_file,
            dashboard_miner_id,
            dashboard_claim_owner_id,
            dashboard_idena_address,
            dashboard_probe_timeout_seconds,
            allow_remote_rpc,
            enable_bitcoin_rpc,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            bitcoin_rpc_cookie_file,
            idena_rpc_url,
            idena_api_key_file,
        } => {
            let bitcoin_rpc_configured = enable_bitcoin_rpc
                || bitcoin_rpc_user.is_some()
                || bitcoin_rpc_password.is_some()
                || bitcoin_rpc_cookie_file.is_some();
            let bitcoin_rpc_auth = if bitcoin_rpc_configured {
                BitcoinRpcClient::auth_from_user_password(
                    bitcoin_rpc_user,
                    bitcoin_rpc_password,
                    bitcoin_rpc_cookie_file,
                )?
            } else {
                None
            };
            let api_token = read_optional_secret(
                dashboard_api_token,
                dashboard_api_token_file,
                "dashboard API token",
            )?;
            dashboard_api::run_dashboard_api_server(dashboard_api::DashboardApiConfig {
                datadir,
                snapshot_dir,
                bind_addr,
                allow_non_loopback,
                allowed_origins: if dashboard_allowed_origins.is_empty() {
                    dashboard_api::default_allowed_origins()
                } else {
                    dashboard_allowed_origins
                },
                api_token,
                account_selector: dashboard_api::DashboardAccountSelector {
                    miner_id: dashboard_miner_id,
                    claim_owner_id: dashboard_claim_owner_id,
                    idena_address: dashboard_idena_address,
                },
                probe_timeout: std::time::Duration::from_secs(dashboard_probe_timeout_seconds),
                allow_remote_rpc,
                bitcoin_rpc_url: bitcoin_rpc_configured.then_some(bitcoin_rpc_url),
                bitcoin_rpc_auth,
                idena_rpc_url: idena_api_key_file.as_ref().map(|_| idena_rpc_url),
                idena_api_key_file,
            })
            .await?;
        }
        Command::RunGossipMesh {
            datadir,
            bind_addr,
            advertise_addr,
            peer_addrs,
            peer_sync_interval_seconds,
            inventory_limit,
            rebroadcast_limit,
            peer_list_limit,
            max_peers_per_round,
            max_parallel_peers,
            allow_public_peers,
            max_future_skew_seconds,
            max_age_seconds,
            max_frame_bytes,
            max_connections,
            max_connections_per_ip,
            read_timeout_seconds,
            write_timeout_seconds,
            max_envelopes_per_window,
            max_read_requests_per_window,
            rate_window_seconds,
            max_invalid_envelopes,
            ban_seconds,
            max_peers_per_ip_group,
            admit_peer_work_templates,
            fork_chain_rpc_addr,
            fork_chain_activation_manifest,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            expected_header_merkle_root_hex,
            allow_unverified_merkle_root,
            allow_mutable_time,
            max_template_time_drift_seconds,
        } => {
            if expected_header_merkle_root_hex.is_some() && allow_unverified_merkle_root {
                anyhow::bail!(
                    "--expected-header-merkle-root-hex cannot be combined with --allow-unverified-merkle-root"
                );
            }
            let fork_chain_client = fork_chain_client_from_options(
                fork_chain_rpc_addr,
                fork_chain_activation_manifest,
            )?;
            if fork_chain_client.is_some()
                && (expected_header_merkle_root_hex.is_some()
                    || allow_unverified_merkle_root
                    || allow_mutable_time)
            {
                bail!("Bitcoin template-policy flags cannot be used with fork-chain admission");
            }
            let work_template_admission = if admit_peer_work_templates {
                let bitcoin_rpc_client = if fork_chain_client.is_none() {
                    Some(bitcoin_rpc_client(
                        rpc_url,
                        rpc_user,
                        rpc_password,
                        rpc_cookie_file,
                        allow_remote_rpc,
                    )?)
                } else {
                    None
                };
                Some(p2p_node::WorkTemplateAdmissionConfig {
                    bitcoin_rpc_client,
                    fork_chain_client,
                    validation_policy: bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                        allow_mutable_time,
                        max_time_drift_seconds: max_template_time_drift_seconds,
                        expected_header_merkle_root_hex,
                        allow_unverified_merkle_root,
                    },
                })
            } else {
                if fork_chain_client.is_some() {
                    bail!("fork-chain admission options require --admit-peer-work-templates");
                }
                None
            };
            p2p_node::run_gossip_mesh(
                p2p_node::GossipServerConfig {
                    datadir: datadir.clone(),
                    bind_addr,
                    max_future_skew_seconds,
                    max_age_seconds,
                    max_frame_bytes,
                    max_connections,
                    max_connections_per_ip,
                    read_timeout_seconds,
                    write_timeout_seconds,
                    allow_public_peers,
                    peer_policy: peer_policy::PeerPolicyConfig {
                        max_envelopes_per_window,
                        max_read_requests_per_window,
                        rate_window_seconds,
                        max_invalid_envelopes,
                        ban_seconds,
                        max_peers_per_ip_group,
                    },
                },
                p2p_node::GossipPeerLoopConfig {
                    datadir,
                    initial_peers: peer_addrs,
                    advertise_addr,
                    sync_interval_seconds: peer_sync_interval_seconds,
                    inventory_limit,
                    rebroadcast_limit,
                    peer_list_limit,
                    max_peers_per_round,
                    max_parallel_peers,
                    max_future_skew_seconds,
                    max_age_seconds,
                    allow_public_peers,
                    work_template_admission,
                },
            )
            .await?;
        }
        Command::SendGossipEnvelope {
            peer_addr,
            envelope_file,
        } => {
            p2p_node::send_gossip_envelope_file(peer_addr, &envelope_file).await?;
        }
        Command::GossipInventory {
            peer_addr,
            known_hashes,
            limit,
        } => {
            let response = p2p_node::pull_gossip_inventory(peer_addr, known_hashes, limit).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::SyncGossip {
            datadir,
            peer_addr,
            limit,
            max_future_skew_seconds,
            max_age_seconds,
        } => {
            let summary = p2p_node::sync_gossip_from_peer(
                &datadir,
                peer_addr,
                limit,
                max_future_skew_seconds,
                max_age_seconds,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::AddGossipPeer { datadir, peer_addr } => {
            let peer = local_node::upsert_gossip_peer(&datadir, peer_addr, "seed")?;
            println!("{}", serde_json::to_string_pretty(&peer)?);
        }
        Command::ListGossipPeers { datadir } => {
            let peers = local_node::list_gossip_peers(&datadir)?;
            println!("{}", serde_json::to_string_pretty(&peers)?);
        }
        Command::MultinodePreflight {
            datadir,
            snapshot_dir,
            miner_id,
            peer_addrs,
        } => {
            let report = multinode_preflight(datadir, snapshot_dir, miner_id, peer_addrs).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::DeriveXonlyPubkey { secret_key_file } => {
            let keypair = read_keypair_from_file(&secret_key_file)?;
            println!("{}", keypair.x_only_public_key().0);
        }
        Command::CreateMinerRegistration {
            miner_id,
            idena_address,
            btc_payout_script_hex,
            claim_owner_pubkey_hex,
            mining_secret_key_file,
            idena_signature_hex,
        } => {
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let mut registration = MinerRegistration {
                miner_id,
                idena_address,
                btc_payout_script_hex,
                claim_owner_pubkey_hex,
                mining_pubkey_hex: mining_keypair.x_only_public_key().0.to_string(),
                idena_signature_hex,
                mining_signature_hex: String::new(),
            };
            registration.mining_signature_hex =
                sign_hash_hex(registration.signing_hash(), &mining_keypair);
            registration.verify_mining_signature()?;
            registration.verify_idena_ownership_signature()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&SharechainMessage::MinerRegistration(registration))?
            );
        }
        Command::PrepareMinerRegistration {
            datadir,
            miner_id,
            idena_address,
            key_dir,
            mining_secret_key_file,
            claim_owner_secret_key_file,
            node_secret_key_file,
            btc_payout_script_hex,
            idena_signature_hex,
            message_out,
            envelope_out,
            append,
            peer_addrs,
        } => {
            let result = prepare_miner_registration(PrepareMinerRegistrationInput {
                datadir,
                miner_id,
                idena_address,
                key_dir,
                mining_secret_key_file,
                claim_owner_secret_key_file,
                node_secret_key_file,
                btc_payout_script_hex,
                idena_signature_hex,
                message_out,
                envelope_out,
                append,
                peer_addrs,
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::IdenaRegistrationChallenge {
            miner_id,
            idena_address,
            btc_payout_script_hex,
            claim_owner_pubkey_hex,
            mining_pubkey_hex,
        } => {
            let registration = MinerRegistration {
                miner_id,
                idena_address,
                btc_payout_script_hex,
                claim_owner_pubkey_hex,
                mining_pubkey_hex,
                idena_signature_hex: String::new(),
                mining_signature_hex: String::new(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "idena_ownership_challenge": registration.idena_ownership_challenge(),
                    "registration_binding_hash": hex::encode(registration.signing_hash()),
                    "signature_field": "idena_signature_hex"
                }))?
            );
        }
        Command::CreateShare {
            miner_id,
            bitcoin_header_hex,
            bitcoin_template_hash,
            nonce_hex,
            work_hash,
            target,
            idena_snapshot_id,
            idena_snapshot_proof_root,
            hashrate_score_delta,
            parent_share_hash,
            mining_secret_key_file,
        } => {
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let mut share = Share {
                miner_id,
                bitcoin_header_hex,
                bitcoin_template_hash: bitcoin_template_hash.unwrap_or_default(),
                nonce_hex: nonce_hex.unwrap_or_default(),
                work_hash: work_hash.unwrap_or_default(),
                target,
                idena_snapshot_id,
                idena_snapshot_proof_root,
                hashrate_score_delta,
                parent_share_hash,
                mining_signature_hex: String::new(),
            };
            if share.bitcoin_template_hash.is_empty() {
                share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash()?;
            }
            if share.nonce_hex.is_empty() {
                share.nonce_hex = share.recomputed_nonce_hex()?;
            }
            if share.work_hash.is_empty() {
                share.work_hash = share.recomputed_work_hash()?;
            }
            share.mining_signature_hex = sign_hash_hex(share.signing_hash(), &mining_keypair);
            let mining_pubkey = mining_keypair.x_only_public_key().0.to_string();
            share.verify_mining_signature(&mining_pubkey)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&SharechainMessage::Share(share))?
            );
        }
        Command::CreateBitcoinWorkTemplate {
            miner_id,
            bitcoin_header_hex,
            mining_secret_key_file,
            created_at_unix,
        } => {
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let mut template = BitcoinWorkTemplate::from_bitcoin_header_hex(
                miner_id,
                bitcoin_header_hex,
                created_at_unix.unwrap_or(current_unix_timestamp()?),
            )?;
            template.mining_signature_hex = sign_hash_hex(template.signing_hash(), &mining_keypair);
            let mining_pubkey = mining_keypair.x_only_public_key().0.to_string();
            template.verify_mining_signature(&mining_pubkey)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&SharechainMessage::BitcoinWorkTemplate(template))?
            );
        }
        Command::PublishSnapshotVote {
            datadir,
            miner_id,
            snapshot_file,
            mining_secret_key_file,
            node_secret_key_file,
            message_out,
            envelope_out,
            append,
            peer_addrs,
        } => {
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let snapshot = local_node::read_verified_snapshot(&snapshot_file)?;
            let mut vote = SnapshotVote {
                voter_miner_id: miner_id,
                snapshot_day: snapshot.snapshot_day.to_string(),
                idena_height: snapshot.idena_height,
                score_root: snapshot.score_root.clone(),
                signature_hex: String::new(),
            };
            vote.signature_hex = sign_hash_hex(vote.signing_hash(), &mining_keypair);
            let mining_pubkey = mining_keypair.x_only_public_key().0.to_string();
            vote.verify_mining_signature(&mining_pubkey)?;
            let result = publish_sharechain_message(PublishSharechainMessageInput {
                datadir,
                message: SharechainMessage::SnapshotVote(vote),
                node_secret_key_file,
                message_out,
                envelope_out,
                append,
                peer_addrs,
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::PublishBitcoinWorkTemplate {
            datadir,
            miner_id,
            bitcoin_header_hex,
            mining_secret_key_file,
            node_secret_key_file,
            created_at_unix,
            message_out,
            envelope_out,
            append,
            accept_locally,
            validate_with_bitcoin_rpc,
            allow_unverified_local_accept,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            expected_header_merkle_root_hex,
            allow_unverified_merkle_root,
            allow_mutable_time,
            max_template_time_drift_seconds,
            peer_addrs,
        } => {
            validate_publish_bitcoin_work_template_flags(PublishBitcoinWorkTemplateFlags {
                append,
                accept_locally,
                validate_with_bitcoin_rpc,
                allow_unverified_local_accept,
                has_expected_header_merkle_root: expected_header_merkle_root_hex.is_some(),
                allow_unverified_merkle_root,
                allow_mutable_time,
            })?;
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let mut template = BitcoinWorkTemplate::from_bitcoin_header_hex(
                miner_id,
                bitcoin_header_hex,
                created_at_unix.unwrap_or(current_unix_timestamp()?),
            )?;
            template.mining_signature_hex = sign_hash_hex(template.signing_hash(), &mining_keypair);
            let mining_pubkey = mining_keypair.x_only_public_key().0.to_string();
            template.verify_mining_signature(&mining_pubkey)?;
            let bitcoin_rpc_validation = if validate_with_bitcoin_rpc {
                let client = bitcoin_rpc_client(
                    rpc_url,
                    rpc_user,
                    rpc_password,
                    rpc_cookie_file,
                    allow_remote_rpc,
                )?;
                Some(
                    client
                        .validate_bitcoin_work_template(
                            &template,
                            bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                                allow_mutable_time,
                                max_time_drift_seconds: max_template_time_drift_seconds,
                                expected_header_merkle_root_hex,
                                allow_unverified_merkle_root,
                            },
                        )
                        .await?,
                )
            } else {
                None
            };
            let local_accept = if accept_locally {
                if bitcoin_rpc_validation.is_none() && !allow_unverified_local_accept {
                    anyhow::bail!(
                        "--accept-locally requires --validate-with-bitcoin-rpc or --allow-unverified-local-accept"
                    );
                }
                Some(local_node::accept_bitcoin_work_template(
                    &datadir,
                    template.clone(),
                )?)
            } else {
                None
            };
            let mut result = publish_sharechain_message(PublishSharechainMessageInput {
                datadir,
                message: SharechainMessage::BitcoinWorkTemplate(template),
                node_secret_key_file,
                message_out,
                envelope_out,
                append,
                peer_addrs,
            })
            .await?;
            if let Some(object) = result.as_object_mut() {
                object.insert(
                    "local_accept".to_string(),
                    serde_json::to_value(local_accept)?,
                );
                object.insert(
                    "bitcoin_rpc_validation".to_string(),
                    serde_json::to_value(bitcoin_rpc_validation)?,
                );
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::PublishShare {
            datadir,
            miner_id,
            bitcoin_header_hex,
            bitcoin_template_hash,
            nonce_hex,
            work_hash,
            target,
            idena_snapshot_id,
            idena_snapshot_proof_root,
            hashrate_score_delta,
            parent_share_hash,
            mining_secret_key_file,
            node_secret_key_file,
            message_out,
            envelope_out,
            append,
            peer_addrs,
        } => {
            let mining_keypair = read_keypair_from_file(&mining_secret_key_file)?;
            let mut share = Share {
                miner_id,
                bitcoin_header_hex,
                bitcoin_template_hash: bitcoin_template_hash.unwrap_or_default(),
                nonce_hex: nonce_hex.unwrap_or_default(),
                work_hash: work_hash.unwrap_or_default(),
                target,
                idena_snapshot_id,
                idena_snapshot_proof_root,
                hashrate_score_delta: hashrate_score_delta.unwrap_or(0),
                parent_share_hash: match parent_share_hash {
                    Some(parent_share_hash) => parent_share_hash,
                    None => default_parent_share_hash(&datadir)?,
                },
                mining_signature_hex: String::new(),
            };
            if share.bitcoin_template_hash.is_empty() {
                share.bitcoin_template_hash = share.recomputed_bitcoin_template_hash()?;
            }
            if share.nonce_hex.is_empty() {
                share.nonce_hex = share.recomputed_nonce_hex()?;
            }
            if share.work_hash.is_empty() {
                share.work_hash = share.recomputed_work_hash()?;
            }
            if share.hashrate_score_delta == 0 {
                share.hashrate_score_delta =
                    Share::expected_hashrate_score_delta_for_target(&share.target)?;
            }
            share.mining_signature_hex = sign_hash_hex(share.signing_hash(), &mining_keypair);
            let mining_pubkey = mining_keypair.x_only_public_key().0.to_string();
            share.verify_mining_signature(&mining_pubkey)?;
            let result = publish_sharechain_message(PublishSharechainMessageInput {
                datadir,
                message: SharechainMessage::Share(share),
                node_secret_key_file,
                message_out,
                envelope_out,
                append,
                peer_addrs,
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::RunMiningAdapter {
            datadir,
            bind_addr,
            allow_non_loopback_stratum,
            allow_example_mining_job,
            miner_id,
            job_file,
            fork_chain_rpc_addr,
            fork_chain_activation_manifest,
            share_target,
            idena_snapshot_id,
            idena_snapshot_proof_root,
            mining_secret_key_file,
            node_secret_key_file,
            stratum_password_file,
            block_candidate_dir,
            peer_addrs,
            stratum_difficulty,
            extranonce2_size,
            max_stratum_line_bytes,
            stratum_idle_timeout_seconds,
            refresh_job_from_rpc,
            job_refresh_interval_seconds,
            auto_submit_blocks,
            payout_schedule_file,
            pohw_commitment_file,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            append,
        } => {
            let fork_chain_client = match (
                fork_chain_rpc_addr,
                fork_chain_activation_manifest,
            ) {
                (Some(addr), Some(path)) => {
                    let manifest = fork_chain::read_activation_manifest(&path)?;
                    Some(fork_chain::ForkChainClient::new(
                        addr,
                        manifest.activation_id,
                        false,
                    )?)
                }
                (None, None) => None,
                _ => bail!(
                    "--fork-chain-rpc-addr and --fork-chain-activation-manifest must be supplied together"
                ),
            };
            if fork_chain_client.is_some() && refresh_job_from_rpc {
                bail!("--fork-chain-rpc-addr cannot be combined with --refresh-job-from-rpc");
            }
            let bitcoin_rpc_client =
                if fork_chain_client.is_none() && (refresh_job_from_rpc || auto_submit_blocks) {
                    Some(bitcoin_rpc_client(
                        rpc_url,
                        rpc_user,
                        rpc_password,
                        rpc_cookie_file,
                        allow_remote_rpc,
                    )?)
                } else {
                    None
                };
            let (payout_schedule, pohw_commitment) =
                match (payout_schedule_file, pohw_commitment_file) {
                    (Some(schedule_path), Some(commitment_path)) => (
                        Some(read_payout_schedule_file(&schedule_path)?),
                        Some(read_pohw_commitment_file(&commitment_path)?),
                    ),
                    (None, None) => (None, None),
                    _ => bail!(
                    "--payout-schedule-file and --pohw-commitment-file must be supplied together"
                ),
                };
            mining_adapter::run_mining_adapter(mining_adapter::MiningAdapterConfig {
                datadir,
                bind_addr,
                allow_non_loopback_stratum,
                allow_example_mining_job,
                miner_id,
                job_file,
                share_target,
                idena_snapshot_id,
                idena_snapshot_proof_root,
                mining_secret_key_file,
                node_secret_key_file,
                stratum_password_file,
                block_candidate_dir,
                peer_addrs,
                stratum_difficulty,
                extranonce2_size,
                max_line_bytes: max_stratum_line_bytes,
                idle_timeout_seconds: stratum_idle_timeout_seconds,
                append,
                bitcoin_rpc_client,
                fork_chain_client,
                refresh_job_from_rpc,
                job_refresh_interval_seconds,
                auto_submit_blocks,
                payout_schedule,
                pohw_commitment,
            })
            .await?;
        }
        Command::BuildStratumJobRpc {
            job_out,
            replace,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            extranonce2_size,
        } => {
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let built =
                mining_adapter::build_stratum_job_from_rpc(&client, extranonce2_size).await?;
            if replace {
                write_json_file_replace_existing_regular(&job_out, &built.job)?;
            } else {
                write_json_file(&job_out, &built.job)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job_out": display_path(&job_out),
                    "job_id": built.job.job_id,
                    "source_height": built.source_height,
                    "source_previous_block_hash": built.source_previous_block_hash,
                    "source_transaction_count": built.source_transaction_count,
                    "coinbase_value_sats": built.source_coinbase_value_sats,
                    "extranonce1_bytes": built.extranonce1_bytes,
                    "extranonce2_bytes": built.extranonce2_bytes,
                    "note": built.note,
                }))?
            );
        }
        Command::BuildPohwStratumJobRpc {
            job_out,
            replace,
            payout_schedule_file,
            pohw_commitment_file,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            extranonce2_size,
        } => {
            let payout_schedule = read_payout_schedule_file(&payout_schedule_file)?;
            let pohw_commitment = read_pohw_commitment_file(&pohw_commitment_file)?;
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let material = client.mining_job_template().await?;
            let built = mining_adapter::build_pohw_stratum_job_from_template(
                &material,
                &payout_schedule,
                &pohw_commitment,
                extranonce2_size,
            )?;
            if replace {
                write_json_file_replace_existing_regular(&job_out, &built.job)?;
            } else {
                write_json_file(&job_out, &built.job)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job_out": display_path(&job_out),
                    "job_id": built.job.job_id,
                    "source_height": built.source_height,
                    "source_previous_block_hash": built.source_previous_block_hash,
                    "source_transaction_count": built.source_transaction_count,
                    "coinbase_value_sats": built.source_coinbase_value_sats,
                    "payout_schedule_root": payout_schedule.payout_root,
                    "pohw_commitment_hash": pohw_commitment.commitment_hash(),
                    "coinbase_positive_output_sats": payout_schedule_coinbase_positive_output_sats(&payout_schedule)?,
                    "extranonce1_bytes": built.extranonce1_bytes,
                    "extranonce2_bytes": built.extranonce2_bytes,
                    "note": built.note,
                }))?
            );
        }
        Command::BuildStratumBlockCandidate {
            job_file,
            candidate_out,
            replace,
            extranonce1,
            extranonce2,
            ntime,
            nonce,
            extranonce2_size,
            require_block_target,
        } => {
            let job = mining_adapter::read_stratum_job_file(&job_file)?;
            let candidate = mining_adapter::build_stratum_block_candidate(
                &job,
                &extranonce1,
                &extranonce2,
                &ntime,
                &nonce,
                extranonce2_size,
                require_block_target,
            )?;
            if let Some(candidate_out) = candidate_out {
                if replace {
                    write_json_file_replace_existing_regular(&candidate_out, &candidate)?;
                } else {
                    write_json_file(&candidate_out, &candidate)?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "candidate_out": display_path(&candidate_out),
                        "job_id": candidate.job_id,
                        "block_hash": candidate.block_hash,
                        "block_target": candidate.block_target,
                        "meets_block_target": candidate.meets_block_target,
                        "coinbase_txid": candidate.coinbase_txid,
                        "block_hex_status": candidate.block_hex_status,
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&candidate)?);
            }
        }
        Command::SubmitStratumBlockCandidate {
            candidate_file,
            rpc_url,
            allow_remote_rpc,
            allow_mainnet_submit,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
        } => {
            let candidate = read_stratum_block_candidate_file(&candidate_file)?;
            let block_hex = block_hex_for_stratum_candidate_submission(&candidate)?;
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let chain_info = client.get_blockchain_info().await?;
            ensure_candidate_submit_chain_allowed(&chain_info, allow_mainnet_submit)?;
            let outcome = client.submit_block(block_hex).await?;
            if let Some(reason) = outcome.reject_reason {
                return Err(anyhow!(
                    "Bitcoin RPC submitblock rejected candidate {}: {}",
                    candidate.block_hash,
                    reason
                ));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "candidate_file": display_path(&candidate_file),
                    "job_id": candidate.job_id,
                    "block_hash": candidate.block_hash,
                    "coinbase_txid": candidate.coinbase_txid,
                    "rpc_chain": chain_info.chain,
                    "rpc_blocks": chain_info.blocks,
                    "rpc_initial_block_download": chain_info.initial_block_download,
                    "submit_status": outcome.status,
                }))?
            );
        }
        Command::SubmitForkChainBlockCandidate {
            candidate_file,
            activation_manifest,
            rpc_addr,
        } => {
            let candidate = read_stratum_block_candidate_file(&candidate_file)?;
            let block_hex = block_hex_for_stratum_candidate_submission(&candidate)?;
            let manifest = fork_chain::read_activation_manifest(&activation_manifest)?;
            let client = fork_chain::ForkChainClient::new(rpc_addr, manifest.activation_id, false)?;
            let outcome = client.submit_block(block_hex).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "candidate_file": display_path(&candidate_file),
                    "job_id": candidate.job_id,
                    "block_hash": candidate.block_hash,
                    "coinbase_txid": candidate.coinbase_txid,
                    "submit_status": outcome.status,
                }))?
            );
        }
        Command::CreateWithdrawalRequest {
            datadir,
            request_id,
            claim_owner_secret_key_file,
            destination_script_hex,
            amount_sats,
            max_fee_rate_sat_vb,
            nonce,
            expiry_height,
            output_kind,
            current_height,
            node_secret_key_file,
            message_out,
            envelope_out,
            append,
            peer_addrs,
        } => {
            let claim_owner_keypair = read_keypair_from_file(&claim_owner_secret_key_file)?;
            let claim_owner_pubkey_hex = claim_owner_keypair.x_only_public_key().0.to_string();
            let mut request = WithdrawalRequest {
                request_id,
                claim_owner_id: claim_owner_pubkey_hex.clone(),
                claim_owner_pubkey_hex,
                destination_script_hex,
                amount_sats,
                max_fee_rate_sat_vb,
                nonce,
                expiry_height,
                signature_hex: None,
                output_kind: parse_withdrawal_output_kind(&output_kind)?,
            };
            request.signature_hex =
                Some(sign_hash_hex(request.signing_hash(), &claim_owner_keypair));
            request.validate(current_height)?;
            let result = publish_sharechain_message(PublishSharechainMessageInput {
                datadir,
                message: SharechainMessage::WithdrawalRequest(request),
                node_secret_key_file,
                message_out,
                envelope_out,
                append,
                peer_addrs,
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::AcceptBitcoinWorkTemplate {
            datadir,
            template_file,
        } => {
            let result = local_node::accept_bitcoin_work_template_file(&datadir, &template_file)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::AcceptBitcoinWorkTemplateRpc {
            datadir,
            template_file,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            expected_header_merkle_root_hex,
            allow_unverified_merkle_root,
            allow_mutable_time,
            max_template_time_drift_seconds,
        } => {
            if expected_header_merkle_root_hex.is_some() && allow_unverified_merkle_root {
                anyhow::bail!(
                    "--expected-header-merkle-root-hex cannot be combined with --allow-unverified-merkle-root"
                );
            }
            let template = local_node::read_bitcoin_work_template_file(&template_file)?;
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let validation = client
                .validate_bitcoin_work_template(
                    &template,
                    bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                        allow_mutable_time,
                        max_time_drift_seconds: max_template_time_drift_seconds,
                        expected_header_merkle_root_hex,
                        allow_unverified_merkle_root,
                    },
                )
                .await?;
            let accepted = local_node::accept_bitcoin_work_template(&datadir, template)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "validation": validation,
                    "accepted": accepted
                }))?
            );
        }
        Command::AdmitPeerWorkTemplates {
            datadir,
            peer_addr,
            limit,
            fork_chain_rpc_addr,
            fork_chain_activation_manifest,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            expected_header_merkle_root_hex,
            allow_unverified_merkle_root,
            allow_mutable_time,
            max_template_time_drift_seconds,
            max_future_skew_seconds,
            max_age_seconds,
        } => {
            if expected_header_merkle_root_hex.is_some() && allow_unverified_merkle_root {
                anyhow::bail!(
                    "--expected-header-merkle-root-hex cannot be combined with --allow-unverified-merkle-root"
                );
            }
            let fork_chain_client = fork_chain_client_from_options(
                fork_chain_rpc_addr,
                fork_chain_activation_manifest,
            )?;
            if fork_chain_client.is_some()
                && (expected_header_merkle_root_hex.is_some()
                    || allow_unverified_merkle_root
                    || allow_mutable_time)
            {
                bail!("Bitcoin template-policy flags cannot be used with fork-chain admission");
            }
            let bitcoin_rpc_client = if fork_chain_client.is_none() {
                Some(bitcoin_rpc_client(
                    rpc_url,
                    rpc_user,
                    rpc_password,
                    rpc_cookie_file,
                    allow_remote_rpc,
                )?)
            } else {
                None
            };
            let admission = p2p_node::WorkTemplateAdmissionConfig {
                bitcoin_rpc_client,
                fork_chain_client,
                validation_policy: bitcoin_rpc::BitcoinWorkTemplateValidationPolicy {
                    allow_mutable_time,
                    max_time_drift_seconds: max_template_time_drift_seconds,
                    expected_header_merkle_root_hex,
                    allow_unverified_merkle_root,
                },
            };
            let report = p2p_node::sync_gossip_from_peer_with_work_template_admission(
                &datadir,
                peer_addr,
                limit,
                max_future_skew_seconds,
                max_age_seconds,
                &admission,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::ShareScore { target } => {
            let score = Share::expected_hashrate_score_delta_for_target(&target)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "target": target.to_ascii_lowercase(),
                    "hashrate_score_delta": score
                }))?
            );
        }
        Command::ProposePayoutSchedule {
            datadir,
            snapshot_file,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
        } => {
            let state = local_node::replay_state(&datadir)?;
            let mut accounts = state.participant_accounts();
            if let Some(snapshot_file) = snapshot_file {
                apply_snapshot_scores(&state, &mut accounts, &snapshot_file)?;
            }
            let schedule = state.expected_payout_schedule(
                &accounts,
                reward_sats,
                direct_limit,
                min_direct_payout_sats,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&SharechainMessage::PayoutSchedule(schedule))?
            );
        }
        Command::ConfirmPayoutSchedule {
            datadir,
            snapshot_file,
            payout_schedule_file,
            pohw_commitment_file,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
            fork_block_height,
            fork_block_hash,
            coinbase_txid,
            allow_unverified_manual_confirmation,
        } => {
            if !allow_unverified_manual_confirmation {
                return Err(anyhow!(
                    "manual payout confirmation is unverified; rerun with --allow-unverified-manual-confirmation or use confirm-payout-from-block"
                ));
            }
            let schedule = read_payout_schedule_file(&payout_schedule_file)?;
            let pohw_commitment = read_pohw_commitment_file(&pohw_commitment_file)?;
            let result = local_node::append_confirmed_payout_record(
                &datadir,
                local_node::ConfirmedPayoutAppend {
                    snapshot_file,
                    payout_schedule: schedule,
                    pohw_commitment,
                    reward_sats,
                    direct_limit,
                    min_direct_payout_sats,
                    fork_block_height,
                    fork_block_hash,
                    coinbase_txid,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::ConfirmPayoutFromBlock {
            datadir,
            snapshot_file,
            payout_schedule_file,
            pohw_commitment_file,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            block_hash,
            min_confirmations,
        } => {
            let schedule = read_payout_schedule_file(&payout_schedule_file)?;
            let pohw_commitment = read_pohw_commitment_file(&pohw_commitment_file)?;
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let confirmation = client
                .confirm_coinbase_payout(
                    &block_hash,
                    &schedule,
                    &pohw_commitment,
                    min_confirmations,
                )
                .await?;
            let confirmed_reward_sats = match reward_sats {
                Some(expected_reward_sats)
                    if expected_reward_sats != confirmation.confirmed_output_total_sats =>
                {
                    return Err(anyhow!(
                        "verified coinbase payout total is {} sats, but --reward-sats was {}",
                        confirmation.confirmed_output_total_sats,
                        expected_reward_sats
                    ));
                }
                Some(expected_reward_sats) => expected_reward_sats,
                None => confirmation.confirmed_output_total_sats,
            };
            let result = local_node::append_confirmed_payout_record(
                &datadir,
                local_node::ConfirmedPayoutAppend {
                    snapshot_file,
                    payout_schedule: schedule,
                    pohw_commitment,
                    reward_sats: confirmed_reward_sats,
                    direct_limit,
                    min_direct_payout_sats,
                    fork_block_height: confirmation.fork_block_height,
                    fork_block_hash: confirmation.fork_block_hash.clone(),
                    coinbase_txid: confirmation.coinbase_txid.clone(),
                },
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "confirmation": {
                        "fork_block_height": confirmation.fork_block_height,
                        "fork_block_hash": confirmation.fork_block_hash,
                        "coinbase_txid": confirmation.coinbase_txid,
                        "confirmations": confirmation.confirmations,
                        "min_confirmations": min_confirmations,
                        "pohw_commitment_hash": confirmation.pohw_commitment_hash,
                        "expected_output_total_sats": confirmation.expected_output_total_sats,
                        "confirmed_output_total_sats": confirmation.confirmed_output_total_sats,
                        "credited_reward_sats": confirmed_reward_sats
                    },
                    "confirmed_payout": result
                }))?
            );
        }
        Command::RunPayoutConfirmer {
            datadir,
            candidate_dir,
            poll_interval_seconds,
            once,
            max_candidates,
            reward_sats,
            direct_limit,
            min_direct_payout_sats,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            min_confirmations,
        } => {
            if !once && poll_interval_seconds == 0 {
                return Err(anyhow!(
                    "--poll-interval-seconds must be greater than zero unless --once is set"
                ));
            }
            if max_candidates == 0 {
                return Err(anyhow!("--max-candidates must be greater than zero"));
            }
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let defaults = PayoutConfirmerDefaults {
                reward_sats,
                direct_limit,
                min_direct_payout_sats,
                min_confirmations,
                max_candidates,
            };
            loop {
                let summary =
                    run_payout_confirmer_once(&datadir, &candidate_dir, &client, defaults).await?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
                if once {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(poll_interval_seconds)).await;
            }
        }
        Command::VaultThreshold { signers } => {
            println!("{}", threshold_67_percent(signers));
        }
        Command::VaultScriptPubkey { vault_key_xonly } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "vault_key_xonly": vault_key_xonly,
                    "script_pubkey_hex": vault_script_pubkey_hex(&vault_key_xonly)?
                }))?
            );
        }
        Command::EstimateWithdrawalCost {
            inputs,
            p2wpkh_outputs,
            p2tr_outputs,
            fee_rate_sat_vb,
        } => {
            let vsize = estimate_batch_vsize(inputs, p2wpkh_outputs, p2tr_outputs)?;
            let fee = estimate_fee_sats(vsize, fee_rate_sat_vb)?;
            println!(
                "{}",
                serde_json::json!({
                    "estimated_vsize": vsize,
                    "fee_rate_sat_vb": fee_rate_sat_vb,
                    "estimated_fee_sats": fee
                })
            );
        }
        Command::DemoVaultEpoch {
            epoch_id,
            starts_at,
            max_age_seconds,
            signer_ids,
        } => {
            let heartbeats = signer_ids
                .into_iter()
                .map(|signer_id| SignerHeartbeat {
                    signer_id,
                    idena_address: "0x0000000000000000000000000000000000000000".to_string(),
                    host_pubkey: "demo".to_string(),
                    last_seen: starts_at,
                    eligible: true,
                })
                .collect();
            let epoch =
                VaultEpoch::from_online_signers(epoch_id, starts_at, heartbeats, max_age_seconds);
            println!("{}", serde_json::to_string_pretty(&epoch)?);
        }
        Command::DemoVaultRotation {
            current_epoch_id,
            next_epoch_id,
            signers,
            input_sats,
            fee_sats,
        } => {
            let current = demo_epoch(current_epoch_id, signers, &demo_xonly_key(1));
            let next = demo_epoch(next_epoch_id, signers, &demo_xonly_key(2));
            let current_key = current.required_group_key()?;
            let plan = VaultSpendPlan::rotation(
                &current,
                &next,
                vec![demo_vault_input(input_sats, &current_key)?],
                fee_sats,
            )?;
            let tx_plan = build_vault_psbt(&plan)?;
            let session =
                VaultSigningSession::new(&current, plan.clone(), vault_input_sighashes(&tx_plan)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "spend_plan_hash": session.spend_plan_hash,
                    "threshold": session.threshold,
                    "signer_count": session.signer_ids.len(),
                    "plan": plan
                }))?
            );
        }
        Command::DemoVaultPsbt {
            current_epoch_id,
            next_epoch_id,
            signers,
            input_sats,
            fee_sats,
        } => {
            let current = demo_epoch(current_epoch_id, signers, &demo_xonly_key(1));
            let next = demo_epoch(next_epoch_id, signers, &demo_xonly_key(2));
            let current_key = current.required_group_key()?;
            let plan = VaultSpendPlan::rotation(
                &current,
                &next,
                vec![demo_vault_input(input_sats, &current_key)?],
                fee_sats,
            )?;
            let tx_plan = build_vault_psbt(&plan)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "spend_plan_hash": tx_plan.spend_plan_hash,
                    "unsigned_txid": tx_plan.unsigned_tx.compute_txid().to_string(),
                    "signer_revalidation_required": true,
                    "signer_revalidation_policy": "re-query every input with Bitcoin Core gettxout immediately before releasing any FROST signature share",
                    "input_count": tx_plan.unsigned_tx.input.len(),
                    "output_count": tx_plan.unsigned_tx.output.len(),
                    "output_total_sats": transaction_output_total_sats(&tx_plan.unsigned_tx)?,
                    "psbt_input_count": tx_plan.psbt.inputs.len(),
                    "vault_script_pubkey_hex": tx_plan.vault_script_pubkey.to_hex_string(),
                }))?
            );
        }
        Command::DemoVaultFrostSign {
            current_epoch_id,
            next_epoch_id,
            signers,
            input_sats,
            fee_sats,
            seed,
            allow_unsafe_demo_vault_signing,
        } => {
            require_unsafe_demo_vault_signing(allow_unsafe_demo_vault_signing)?;
            let signer_count = u16::try_from(signers)?;
            let threshold = u16::try_from(threshold_67_percent(signers))?;
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let key_set = generate_simulated_dkg_frost_key_set(signer_count, threshold, &mut rng)?;
            let current_key = key_set.internal_key_xonly_hex()?;
            let mut current = demo_epoch(current_epoch_id, signers, &current_key);
            let transcript = key_set.simulated_transcript(
                current_epoch_id,
                current.signer_ids.clone(),
                "00".repeat(32),
            )?;
            current.attach_dkg_transcript(transcript)?;
            let next = demo_epoch(next_epoch_id, signers, &demo_xonly_key(2));
            let plan = VaultSpendPlan::rotation(
                &current,
                &next,
                vec![demo_vault_input(input_sats, &current_key)?],
                fee_sats,
            )?;
            let tx_plan = build_vault_psbt(&plan)?;
            let signed = sign_vault_spend_plan_with_simulated_keyset(&plan, &key_set, &mut rng)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "spend_plan_hash": signed.spend_plan_hash,
                    "threshold": key_set.threshold(),
                    "signer_count": key_set.signer_count(),
                    "dkg_roots": key_set.dkg_roots(),
                    "internal_key_xonly": signed.internal_key_xonly,
                    "unsigned_txid": tx_plan.unsigned_tx.compute_txid().to_string(),
                    "signed_txid": signed.signed_tx.compute_txid().to_string(),
                    "signed_wtxid": signed.signed_tx.compute_wtxid().to_string(),
                    "input_count": signed.signed_tx.input.len(),
                    "output_count": signed.signed_tx.output.len(),
                    "output_total_sats": transaction_output_total_sats(&signed.signed_tx)?,
                    "signature_count": signed.signed_inputs.len(),
                    "first_signature_hex": signed.signed_inputs.first().map(|input| input.signature_hex.clone()),
                    "first_witness_items": signed.signed_tx.input.first().map(|input| input.witness.len()),
                    "vault_script_pubkey_hex": tx_plan.vault_script_pubkey.to_hex_string(),
                }))?
            );
        }
        Command::DemoVaultPeerDkgSign {
            current_epoch_id,
            next_epoch_id,
            signers,
            input_sats,
            fee_sats,
            seed,
            allow_unsafe_demo_vault_signing,
        } => {
            require_unsafe_demo_vault_signing(allow_unsafe_demo_vault_signing)?;
            let threshold = u16::try_from(threshold_67_percent(signers))?;
            let signer_ids = demo_signer_ids(signers);
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let ceremony = run_local_peer_dkg_ceremony(
                current_epoch_id,
                signer_ids,
                threshold,
                "00".repeat(32),
                &mut rng,
            )?;
            let current_key = ceremony.key_set.internal_key_xonly_hex()?;
            let mut current = demo_epoch(current_epoch_id, signers, &current_key);
            current.attach_dkg_transcript(ceremony.transcript.clone())?;
            let next = demo_epoch(next_epoch_id, signers, &demo_xonly_key(2));
            let plan = VaultSpendPlan::rotation(
                &current,
                &next,
                vec![demo_vault_input(input_sats, &current_key)?],
                fee_sats,
            )?;
            let tx_plan = build_vault_psbt(&plan)?;
            let signed =
                sign_vault_spend_plan_with_simulated_keyset(&plan, &ceremony.key_set, &mut rng)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "dkg_mode": "local-peer-roundtrip",
                    "round1_broadcast_count": ceremony.artifacts.round1_broadcasts.len(),
                    "round2_direct_package_count": ceremony.artifacts.round2_direct_packages.len(),
                    "signer_ack_count": ceremony.artifacts.signer_acks.len(),
                    "round2_payload_note": "round 2 DKG packages contain secret shares and are represented only by hashes here",
                    "transcript_hash": current.dkg_transcript_hash,
                    "transcript": ceremony.transcript,
                    "spend_plan_hash": signed.spend_plan_hash,
                    "threshold": ceremony.key_set.threshold(),
                    "signer_count": ceremony.key_set.signer_count(),
                    "dkg_roots": ceremony.key_set.dkg_roots(),
                    "internal_key_xonly": signed.internal_key_xonly,
                    "unsigned_txid": tx_plan.unsigned_tx.compute_txid().to_string(),
                    "signed_txid": signed.signed_tx.compute_txid().to_string(),
                    "signed_wtxid": signed.signed_tx.compute_wtxid().to_string(),
                    "input_count": signed.signed_tx.input.len(),
                    "output_count": signed.signed_tx.output.len(),
                    "output_total_sats": transaction_output_total_sats(&signed.signed_tx)?,
                    "signature_count": signed.signed_inputs.len(),
                    "first_signature_hex": signed.signed_inputs.first().map(|input| input.signature_hex.clone()),
                    "first_witness_items": signed.signed_tx.input.first().map(|input| input.witness.len()),
                    "vault_script_pubkey_hex": tx_plan.vault_script_pubkey.to_hex_string(),
                }))?
            );
        }
        Command::DemoDkgTransport { epoch_id, seed } => {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let alice_auth = demo_secret_key(30);
            let bob_auth = demo_secret_key(31);
            let alice_ecdh = demo_secret_key(32);
            let bob_ecdh = demo_secret_key(33);
            let alice_auth_keypair = demo_keypair_from_secret(&alice_auth);
            let bob_auth_keypair = demo_keypair_from_secret(&bob_auth);
            let alice = demo_peer("signer-00", &alice_auth_keypair, &alice_ecdh);
            let bob = demo_peer("signer-01", &bob_auth_keypair, &bob_ecdh);
            let session_id = DkgSessionId::new(
                epoch_id,
                2,
                vec![alice.signer_id.clone(), bob.signer_id.clone()],
            )?
            .session_id();
            let round1_package = b"demo round1 broadcast package";
            let round1_hash = dkg_package_hash(round1_package);
            let mut envelope = DkgMessageEnvelope::unsigned(
                session_id.clone(),
                epoch_id,
                1,
                alice.clone(),
                None,
                DkgMessageBody::Round1Broadcast(DkgRound1BroadcastBody {
                    frost_identifier_hex: participant_frost_identifier_hex(1)?,
                    package_hash: round1_hash.clone(),
                    package_hex: hex::encode(round1_package),
                }),
            )?;
            envelope.sign(&alice_auth_keypair)?;
            envelope.verify_signature()?;

            let round2_package = b"demo confidential round2 package";
            let round2_hash = dkg_package_hash(round2_package);
            let encrypted = encrypt_round2_package(
                &session_id,
                epoch_id,
                &alice,
                &bob,
                &round2_hash,
                round2_package,
                &mut rng,
            )?;
            let decrypted = decrypt_round2_package(
                &session_id,
                epoch_id,
                &alice,
                &bob,
                &bob_ecdh,
                &round2_hash,
                &encrypted,
            )?;

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "session_id": session_id,
                    "round1_envelope_signature_valid": true,
                    "round1_package_hash": round1_hash,
                    "round2_algorithm": encrypted.algorithm,
                    "round2_ciphertext_bytes": encrypted.ciphertext_hex.len() / 2,
                    "round2_decrypted_package_hash": dkg_package_hash(&decrypted),
                    "round2_decrypts_to_original": decrypted == round2_package,
                    "sender": alice,
                    "receiver": bob,
                }))?
            );
        }
        Command::CreateFrostDkgPeer {
            signer_id,
            auth_secret_key_file,
            ecdh_secret_key_file,
            peer_out,
        } => {
            let auth_key = read_or_create_keypair_from_file(&auth_secret_key_file)?;
            let ecdh_key = read_or_create_secret_key_from_file(&ecdh_secret_key_file)?;
            let peer = dkg_peer_from_keys(&signer_id, &auth_key.keypair, &ecdh_key.secret_key)?;
            write_json_file(&peer_out, &peer)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_dkg_peer_ready",
                    "peer": peer,
                    "peer_file": display_path(&peer_out),
                    "auth_secret_key_file": {
                        "path": display_path(&auth_key.path),
                        "created": auth_key.created
                    },
                    "ecdh_secret_key_file": {
                        "path": display_path(&ecdh_key.path),
                        "created": ecdh_key.created
                    }
                }))?
            );
        }
        Command::RunFrostSigner {
            datadir,
            bind_addr,
            allow_non_loopback,
            signer_id,
            epoch_id,
            signer_ids,
            recovery_data_hash,
            auth_secret_key_file,
            ecdh_secret_key_file,
            peer_files,
            peer_addrs,
            sync_interval_seconds,
            max_frame_bytes,
            max_connections,
            once,
        } => {
            let auth_key = read_or_create_keypair_from_file(&auth_secret_key_file)?;
            let ecdh_key = read_or_create_secret_key_from_file(&ecdh_secret_key_file)?;
            let own_peer = dkg_peer_from_keys(&signer_id, &auth_key.keypair, &ecdh_key.secret_key)?;
            let peers = read_peer_files_with_own(&own_peer, &peer_files)?;
            let status =
                frost_signer_daemon::run_frost_signer(frost_signer_daemon::RunFrostSignerConfig {
                    datadir: datadir.clone(),
                    bind_addr,
                    allow_non_loopback,
                    peer_addrs,
                    peer: own_peer,
                    peers,
                    signer_ids,
                    epoch_id,
                    recovery_data_hash,
                    auth_keypair: auth_key.keypair,
                    ecdh_secret_key: ecdh_key.secret_key,
                    sync_interval: Duration::from_secs(sync_interval_seconds),
                    max_frame_bytes,
                    max_connections,
                    once,
                })
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_signer_ready",
                    "datadir": display_path(&datadir),
                    "frost_signer": status,
                    "auth_secret_key_file": {
                        "path": display_path(&auth_key.path),
                        "created": auth_key.created
                    },
                    "ecdh_secret_key_file": {
                        "path": display_path(&ecdh_key.path),
                        "created": ecdh_key.created
                    }
                }))?
            );
        }
        Command::FrostDkgRound1 {
            epoch_id,
            signer_id,
            signer_ids,
            recovery_data_hash,
            auth_secret_key_file,
            peer_file,
            state_file,
            envelope_out,
        } => {
            let auth_keypair = read_keypair_from_file(&auth_secret_key_file)?;
            let peer: DkgPeerIdentity = read_json_file::<DkgPeerIdentity>(&peer_file)?
                .normalized()
                .map_err(|err| {
                    anyhow!("invalid DKG peer identity {}: {err}", peer_file.display())
                })?;
            let output = real_frost_dkg_round1(
                epoch_id,
                signer_id,
                signer_ids,
                recovery_data_hash,
                &mut OsRng,
            )?;
            if peer.signer_id != output.state.signer_id {
                return Err(anyhow!(
                    "peer file signer {} does not match DKG signer {}",
                    peer.signer_id,
                    output.state.signer_id
                ));
            }
            let mut envelope = DkgMessageEnvelope::unsigned(
                output.state.session_id.clone(),
                output.state.epoch_id,
                1,
                peer,
                None,
                DkgMessageBody::Round1Broadcast(output.body),
            )?;
            envelope.sign(&auth_keypair)?;
            let envelope_file = stage_json_file(&envelope_out, &envelope)?;
            write_private_json_file(&state_file, &output.state)?;
            envelope_file.publish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_dkg_round1_ready",
                    "session_id": output.state.session_id,
                    "epoch_id": output.state.epoch_id,
                    "signer_id": output.state.signer_id,
                    "threshold": output.state.threshold,
                    "state_file": display_path(&state_file),
                    "round1_envelope_file": display_path(&envelope_out)
                }))?
            );
        }
        Command::FrostDkgRound2 {
            state_file,
            auth_secret_key_file,
            peer_file,
            peer_files,
            round1_envelope_files,
            envelope_out_dir,
        } => {
            let state: RealFrostDkgState = read_private_json_file(&state_file)?;
            let auth_keypair = read_keypair_from_file(&auth_secret_key_file)?;
            let own_peer: DkgPeerIdentity = read_json_file(&peer_file)?;
            let peers = read_peer_files_with_own(&own_peer, &peer_files)?;
            let round1_envelopes = read_json_files::<DkgMessageEnvelope>(&round1_envelope_files)?;
            let output =
                real_frost_dkg_round2(state, &round1_envelopes, &own_peer, &peers, &mut OsRng)?;
            prepare_public_file_parent_dir(&envelope_out_dir).with_context(|| {
                format!(
                    "failed to prepare round2 output directory {}",
                    envelope_out_dir.display()
                )
            })?;
            let mut envelope_paths = Vec::new();
            let mut envelope_files = Vec::new();
            for direct in output.direct_messages {
                let receiver = direct.receiver_signer_id.clone();
                let mut envelope = DkgMessageEnvelope::unsigned(
                    output.state.session_id.clone(),
                    output.state.epoch_id,
                    2,
                    own_peer.clone(),
                    Some(receiver.clone()),
                    DkgMessageBody::Round2Direct(direct.body),
                )?;
                envelope.sign(&auth_keypair)?;
                let path = envelope_out_dir.join(format!(
                    "round2-{}-to-{}.json",
                    output.state.signer_id, receiver
                ));
                envelope_paths.push(display_path(&path));
                envelope_files.push(stage_json_file(&path, &envelope)?);
            }
            write_private_json_file(&state_file, &output.state)?;
            for envelope_file in envelope_files {
                envelope_file.publish()?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_dkg_round2_ready",
                    "session_id": output.state.session_id,
                    "signer_id": output.state.signer_id,
                    "state_file": display_path(&state_file),
                    "round2_envelope_files": envelope_paths
                }))?
            );
        }
        Command::FrostDkgFinalize {
            state_file,
            auth_secret_key_file,
            ecdh_secret_key_file,
            peer_file,
            peer_files,
            round1_envelope_files,
            round2_envelope_files,
            ack_out,
        } => {
            let state: RealFrostDkgState = read_private_json_file(&state_file)?;
            let auth_keypair = read_keypair_from_file(&auth_secret_key_file)?;
            let ecdh_secret = read_secret_key_from_file(&ecdh_secret_key_file)?;
            let own_peer: DkgPeerIdentity = read_json_file(&peer_file)?;
            let peers = read_peer_files_with_own(&own_peer, &peer_files)?;
            let round1_envelopes = read_json_files::<DkgMessageEnvelope>(&round1_envelope_files)?;
            let round2_envelopes = read_json_files::<DkgMessageEnvelope>(&round2_envelope_files)?;
            let output = real_frost_dkg_finalize(
                state,
                &round1_envelopes,
                &round2_envelopes,
                &own_peer,
                &peers,
                &ecdh_secret,
            )?;
            let mut envelope = DkgMessageEnvelope::unsigned(
                output.state.session_id.clone(),
                output.state.epoch_id,
                3,
                own_peer,
                None,
                DkgMessageBody::SignerAck(output.body),
            )?;
            envelope.sign(&auth_keypair)?;
            let ack_file = stage_json_file(&ack_out, &envelope)?;
            write_private_json_file(&state_file, &output.state)?;
            ack_file.publish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_dkg_finalized",
                    "session_id": output.state.session_id,
                    "signer_id": output.state.signer_id,
                    "frost_group_key_xonly": output.state.frost_group_key_xonly,
                    "public_key_package_hash": output.state.public_key_package_hash,
                    "public_key_package_hex": output.state.public_key_package_hex,
                    "state_file": display_path(&state_file),
                    "ack_envelope_file": display_path(&ack_out)
                }))?
            );
        }
        Command::FrostDkgTranscript {
            state_file,
            peer_files,
            round1_envelope_files,
            round2_envelope_files,
            ack_envelope_files,
            transcript_out,
        } => {
            let state: RealFrostDkgState = read_private_json_file(&state_file)?;
            let peers = read_json_files::<DkgPeerIdentity>(&peer_files)?;
            let round1_envelopes = read_json_files::<DkgMessageEnvelope>(&round1_envelope_files)?;
            let round2_envelopes = read_json_files::<DkgMessageEnvelope>(&round2_envelope_files)?;
            let ack_envelopes = read_json_files::<DkgMessageEnvelope>(&ack_envelope_files)?;
            let transcript = real_frost_dkg_transcript(
                &state,
                &round1_envelopes,
                &round2_envelopes,
                &ack_envelopes,
                &peers,
            )?;
            if let Some(path) = transcript_out.as_ref() {
                write_json_file(path, &transcript)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_dkg_transcript_ready",
                    "transcript_hash": transcript.transcript_hash(),
                    "transcript_out": transcript_out.as_ref().map(|path| display_path(path)),
                    "transcript": transcript
                }))?
            );
        }
        Command::BuildWithdrawalSpendPlan {
            datadir,
            dkg_transcript_file,
            request_ids,
            request_files,
            vault_input_files,
            outpoints,
            fee_rate_sat_vb,
            current_height,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            min_confirmations,
            node_secret_key_file,
            message_out,
            envelope_out,
            append,
            peer_addrs,
            spend_plan_out,
        } => {
            let state = local_node::replay_state(&datadir)?;
            let transcript: DkgTranscript = read_json_file(&dkg_transcript_file)?;
            let transcript = transcript.normalized()?;
            let epoch = vault_epoch_from_transcript(&transcript);
            let requests = select_withdrawal_requests(&state, &request_ids, &request_files)?;
            let mut inputs = read_vault_input_files(&vault_input_files)?;
            if !outpoints.is_empty() {
                let client = bitcoin_rpc_client(
                    rpc_url,
                    rpc_user,
                    rpc_password,
                    rpc_cookie_file,
                    allow_remote_rpc,
                )?;
                for raw_outpoint in outpoints {
                    let (txid, vout) = parse_outpoint(&raw_outpoint)?;
                    inputs.push(
                        client
                            .validate_vault_input(
                                &txid,
                                vout,
                                &transcript.frost_group_key_xonly,
                                min_confirmations,
                            )
                            .await?,
                    );
                }
            }
            let result = build_verified_withdrawal_spend_plan(
                &state,
                &epoch,
                requests,
                inputs,
                fee_rate_sat_vb,
                current_height,
            )?;
            let withdrawal_batch = result
                .plan
                .withdrawal_batch
                .clone()
                .ok_or_else(|| anyhow!("internal error: withdrawal spend plan has no batch"))?;
            let batch_publish = if append
                || !peer_addrs.is_empty()
                || message_out.is_some()
                || envelope_out.is_some()
            {
                let node_secret_key_file = node_secret_key_file.ok_or_else(|| {
                    anyhow!("--node-secret-key-file is required when publishing a withdrawal batch")
                })?;
                Some(
                    publish_sharechain_message(PublishSharechainMessageInput {
                        datadir,
                        message: SharechainMessage::WithdrawalBatch(withdrawal_batch),
                        node_secret_key_file,
                        message_out,
                        envelope_out,
                        append,
                        peer_addrs,
                    })
                    .await?,
                )
            } else {
                None
            };
            let plan_file = stage_json_file(&spend_plan_out, &result.plan)?;
            plan_file.publish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "withdrawal_spend_plan_ready",
                    "decentralization_model": "local replay verifies claim balances and signed withdrawal requests; FROST signers must re-run the same policy before signing",
                    "spend_plan_out": display_path(&spend_plan_out),
                    "spend_plan_hash": result.spend_plan_hash,
                    "unsigned_txid": result.unsigned_txid,
                    "input_sighashes": result.input_sighashes,
                    "request_count": result.request_count,
                    "input_count": result.input_count,
                    "output_count": result.output_count,
                    "input_total_sats": result.input_total_sats,
                    "withdrawal_gross_total_sats": result.withdrawal_gross_total_sats,
                    "withdrawal_net_total_sats": result.withdrawal_net_total_sats,
                    "withdrawal_fee_sats": result.withdrawal_fee_sats,
                    "vault_change_sats": result.vault_change_sats,
                    "current_height": current_height,
                    "withdrawal_batch_hash": result.withdrawal_batch_hash,
                    "withdrawal_batch_already_reserved": result.withdrawal_batch_already_reserved,
                    "withdrawal_batch_published": batch_publish.is_some(),
                    "withdrawal_batch_publish": batch_publish,
                    "next_steps": {
                        "sync": "Sync the WithdrawalBatch gossip message first; FROST signers require the batch in local replay before signing.",
                        "commitments": "Each FROST signer runs frost-create-commitments with this spend plan and current height after replay sees the batch.",
                        "signature_shares": "Each FROST signer runs frost-sign-shares after collecting threshold commitments.",
                        "aggregate": "Any node runs frost-aggregate-transaction with threshold valid shares and the DKG transcript."
                    },
                    "plan": result.plan
                }))?
            );
        }
        Command::FrostCreateCommitments {
            state_file,
            spend_plan_file,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            min_confirmations,
            datadir,
            current_height,
            next_dkg_transcript_file,
            commitments_out,
        } => {
            let state: RealFrostDkgState = read_private_json_file(&state_file)?;
            let spend_plan = read_spend_plan_file(&spend_plan_file)?;
            let tx_plan = build_vault_psbt(&spend_plan)?;
            let input_sighashes = vault_input_sighashes(&tx_plan)?;
            let bitcoin_client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            validate_real_frost_signing_policy(
                &state,
                &spend_plan,
                &input_sighashes,
                RealFrostSigningPolicyContext {
                    bitcoin_client: &bitcoin_client,
                    min_confirmations,
                    datadir: &datadir,
                    current_height,
                    next_dkg_transcript_file: next_dkg_transcript_file.as_deref(),
                },
            )
            .await?;
            let output = real_frost_create_nonce_commitments(
                state,
                &spend_plan,
                input_sighashes,
                &mut OsRng,
            )?;
            let commitments_file = stage_json_file(&commitments_out, &output.commitments)?;
            write_private_json_file(&state_file, &output.state)?;
            commitments_file.publish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_commitments_ready",
                    "signer_id": output.state.signer_id,
                    "pending_nonce_count": output.state.pending_nonces.len(),
                    "commitments_file": display_path(&commitments_out),
                    "commitment_count": output.commitments.len()
                }))?
            );
        }
        Command::FrostSignShares {
            state_file,
            spend_plan_file,
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            min_confirmations,
            datadir,
            current_height,
            next_dkg_transcript_file,
            commitments_files,
            shares_out,
        } => {
            let state: RealFrostDkgState = read_private_json_file(&state_file)?;
            let spend_plan = read_spend_plan_file(&spend_plan_file)?;
            let commitments = read_frost_commitment_files(&commitments_files)?;
            let tx_plan = build_vault_psbt(&spend_plan)?;
            let input_sighashes = vault_input_sighashes(&tx_plan)?;
            let bitcoin_client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            validate_real_frost_signing_policy(
                &state,
                &spend_plan,
                &input_sighashes,
                RealFrostSigningPolicyContext {
                    bitcoin_client: &bitcoin_client,
                    min_confirmations,
                    datadir: &datadir,
                    current_height,
                    next_dkg_transcript_file: next_dkg_transcript_file.as_deref(),
                },
            )
            .await?;
            let (state, shares) =
                real_frost_sign_spend_plan(state, &spend_plan, input_sighashes, &commitments)?;
            let shares_file = stage_json_file(&shares_out, &shares)?;
            write_private_json_file(&state_file, &state)?;
            shares_file.publish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_signature_shares_ready",
                    "signer_id": state.signer_id,
                    "remaining_pending_nonce_count": state.pending_nonces.len(),
                    "shares_file": display_path(&shares_out),
                    "share_count": shares.len()
                }))?
            );
        }
        Command::FrostAggregateTransaction {
            spend_plan_file,
            dkg_transcript_file,
            public_key_package_hex,
            commitments_files,
            shares_files,
            signed_tx_out,
        } => {
            let spend_plan = read_spend_plan_file(&spend_plan_file)?;
            let transcript: DkgTranscript = read_json_file(&dkg_transcript_file)?;
            let commitments = read_frost_commitment_files(&commitments_files)?;
            let shares = read_frost_share_files(&shares_files)?;
            let signed = aggregate_real_frost_vault_transaction_with_transcript(
                &spend_plan,
                &transcript,
                &public_key_package_hex,
                &commitments,
                &shares,
            )?;
            let signed_tx_hex = bitcoin::consensus::encode::serialize_hex(&signed.signed_tx);
            if let Some(path) = signed_tx_out.as_ref() {
                write_json_file(
                    path,
                    &serde_json::json!({
                        "signed_tx_hex": signed_tx_hex,
                        "signed_txid": signed.signed_tx.compute_txid().to_string(),
                        "signed_wtxid": signed.signed_tx.compute_wtxid().to_string(),
                        "signed_inputs": signed.signed_inputs
                    }),
                )?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "frost_transaction_signed",
                    "spend_plan_hash": signed.spend_plan_hash,
                    "internal_key_xonly": signed.internal_key_xonly,
                    "signed_txid": signed.signed_tx.compute_txid().to_string(),
                    "signed_wtxid": signed.signed_tx.compute_wtxid().to_string(),
                    "signed_tx_hex": signed_tx_hex,
                    "signed_tx_out": signed_tx_out.as_ref().map(|path| display_path(path)),
                    "signature_count": signed.signed_inputs.len()
                }))?
            );
        }
        Command::ValidateVaultInput {
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            txid,
            vout,
            vault_key_xonly,
            min_confirmations,
        } => {
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let input = client
                .validate_vault_input(&txid, vout, &vault_key_xonly, min_confirmations)
                .await?;
            println!("{}", serde_json::to_string_pretty(&input)?);
        }
        Command::BuildValidatedVaultRotation {
            rpc_url,
            allow_remote_rpc,
            rpc_user,
            rpc_password,
            rpc_cookie_file,
            current_epoch_id,
            next_epoch_id,
            signers,
            current_vault_key_xonly,
            next_vault_key_xonly,
            fee_sats,
            outpoint,
            min_confirmations,
        } => {
            if outpoint.is_empty() {
                return Err(anyhow!("at least one --outpoint TXID:VOUT is required"));
            }
            let client = bitcoin_rpc_client(
                rpc_url,
                rpc_user,
                rpc_password,
                rpc_cookie_file,
                allow_remote_rpc,
            )?;
            let mut inputs = Vec::with_capacity(outpoint.len());
            for raw_outpoint in outpoint {
                let (txid, vout) = parse_outpoint(&raw_outpoint)?;
                inputs.push(
                    client
                        .validate_vault_input(
                            &txid,
                            vout,
                            &current_vault_key_xonly,
                            min_confirmations,
                        )
                        .await?,
                );
            }
            let current = demo_epoch(current_epoch_id, signers, &current_vault_key_xonly);
            let next = demo_epoch(next_epoch_id, signers, &next_vault_key_xonly);
            let plan = VaultSpendPlan::rotation(&current, &next, inputs, fee_sats)?;
            let revalidated_inputs = client
                .revalidate_vault_spend_plan_inputs(&plan, min_confirmations)
                .await?;
            let tx_plan = build_vault_psbt(&plan)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "spend_plan_hash": tx_plan.spend_plan_hash,
                    "unsigned_txid": tx_plan.unsigned_tx.compute_txid().to_string(),
                    "signer_revalidation_required": true,
                    "signer_revalidation_policy": "re-query every input with Bitcoin Core gettxout immediately before releasing any FROST signature share",
                    "revalidated_input_count": revalidated_inputs.len(),
                    "input_count": tx_plan.unsigned_tx.input.len(),
                    "output_count": tx_plan.unsigned_tx.output.len(),
                    "output_total_sats": transaction_output_total_sats(&tx_plan.unsigned_tx)?,
                    "input_sighashes": vault_input_sighashes(&tx_plan)?,
                    "plan": plan,
                }))?
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct WithdrawalSpendPlanBuildResult {
    plan: VaultSpendPlan,
    spend_plan_hash: String,
    withdrawal_batch_hash: String,
    withdrawal_batch_already_reserved: bool,
    unsigned_txid: String,
    input_sighashes: Vec<String>,
    request_count: usize,
    input_count: usize,
    output_count: usize,
    input_total_sats: u64,
    withdrawal_gross_total_sats: u64,
    withdrawal_net_total_sats: u64,
    withdrawal_fee_sats: u64,
    vault_change_sats: u64,
}

fn parse_withdrawal_output_kind(raw: &str) -> Result<WithdrawalOutputKind> {
    match raw.to_ascii_lowercase().as_str() {
        "p2wpkh" | "wpkh" => Ok(WithdrawalOutputKind::P2wpkh),
        "p2tr" | "tr" | "taproot" => Ok(WithdrawalOutputKind::P2tr),
        other => Err(anyhow!(
            "unsupported withdrawal output kind {other:?}; use p2wpkh or p2tr"
        )),
    }
}

fn vault_epoch_from_transcript(transcript: &DkgTranscript) -> VaultEpoch {
    VaultEpoch {
        epoch_id: transcript.epoch_id,
        starts_at: Utc::now(),
        signer_ids: transcript.signer_ids.clone(),
        threshold: transcript.threshold,
        frost_group_key_xonly: Some(transcript.frost_group_key_xonly.clone()),
        dkg_transcript_hash: Some(transcript.transcript_hash()),
        dkg_public_key_package_hash: Some(transcript.public_key_package_hash.clone()),
        frost_signer_bindings: transcript.signer_bindings.clone(),
    }
}

fn select_withdrawal_requests(
    state: &SharechainReplayState,
    request_ids: &[String],
    request_files: &[PathBuf],
) -> Result<Vec<WithdrawalRequest>> {
    let mut requests = Vec::new();
    for request_id in request_ids {
        let request = state.withdrawal_requests().get(request_id).ok_or_else(|| {
            anyhow!("withdrawal request {request_id:?} is not present in local sharechain replay")
        })?;
        requests.push(request.clone().normalized());
    }
    for path in request_files {
        let request = read_withdrawal_request_file(path)?;
        let replayed = state
            .withdrawal_requests()
            .get(&request.request_id)
            .ok_or_else(|| {
                anyhow!(
                    "withdrawal request {:?} from {} is not present in local sharechain replay",
                    request.request_id,
                    path.display()
                )
            })?;
        if replayed.clone().normalized() != request {
            return Err(anyhow!(
                "withdrawal request {:?} in {} does not match local sharechain replay",
                request.request_id,
                path.display()
            ));
        }
        requests.push(request);
    }
    if requests.is_empty() {
        return Err(anyhow!(
            "at least one --request-id or --request-file is required"
        ));
    }
    Ok(requests)
}

fn read_withdrawal_request_file(path: &Path) -> Result<WithdrawalRequest> {
    let value: serde_json::Value = read_json_file(path)?;
    if let Ok(request) = serde_json::from_value::<WithdrawalRequest>(value.clone()) {
        return Ok(request.normalized());
    }
    if let Ok(message) = serde_json::from_value::<SharechainMessage>(value.clone()) {
        return match message {
            SharechainMessage::WithdrawalRequest(request) => Ok(request.normalized()),
            other => Err(anyhow!(
                "expected withdrawal request file {}, got {}",
                path.display(),
                sharechain_message_type(&other)
            )),
        };
    }
    if let Ok(envelope) = serde_json::from_value::<GossipEnvelope>(value) {
        return match envelope.message {
            SharechainMessage::WithdrawalRequest(request) => Ok(request.normalized()),
            other => Err(anyhow!(
                "expected withdrawal request envelope {}, got {}",
                path.display(),
                sharechain_message_type(&other)
            )),
        };
    }
    Err(anyhow!(
        "failed to parse withdrawal request file {}",
        path.display()
    ))
}

fn read_vault_input_files(paths: &[PathBuf]) -> Result<Vec<VaultInput>> {
    paths
        .iter()
        .map(|path| read_vault_input_file(path))
        .collect()
}

fn read_vault_input_file(path: &Path) -> Result<VaultInput> {
    let value: serde_json::Value = read_json_file(path)?;
    if let Ok(input) = serde_json::from_value::<VaultInput>(value.clone()) {
        return Ok(input.normalized());
    }
    let input_value = value
        .get("input")
        .cloned()
        .ok_or_else(|| anyhow!("expected VaultInput JSON or object with an input field"))?;
    serde_json::from_value::<VaultInput>(input_value)
        .map(VaultInput::normalized)
        .with_context(|| format!("failed to parse input field from {}", path.display()))
}

fn build_verified_withdrawal_spend_plan(
    state: &SharechainReplayState,
    epoch: &VaultEpoch,
    requests: Vec<WithdrawalRequest>,
    inputs: Vec<VaultInput>,
    fee_rate_sat_vb: u64,
    current_height: u64,
) -> Result<WithdrawalSpendPlanBuildResult> {
    if inputs.is_empty() {
        return Err(anyhow!(
            "at least one vault input is required; pass --vault-input-file or --outpoint"
        ));
    }
    if let Some(best_share_height) = state.best_share_height() {
        if current_height < best_share_height {
            return Err(anyhow!(
                "current height {} is behind local sharechain best height {}; refusing stale withdrawal expiry check",
                current_height,
                best_share_height
            ));
        }
    }

    let batch = build_withdrawal_batch(requests, inputs.len(), fee_rate_sat_vb, current_height)?;
    let withdrawal_batch_already_reserved = match state
        .withdrawal_batch_is_reserved(&batch, current_height)
    {
        Ok(()) => true,
        Err(pohw_core::sharechain_state::SharechainReplayError::UnknownWithdrawalBatch(_)) => {
            state
                .claim_ledger_after_withdrawal_batch(&batch, current_height)
                .context("withdrawal batch is not covered by locally confirmed claim balances")?;
            false
        }
        Err(err) => {
            return Err(err)
                .context("withdrawal batch conflicts with locally replayed pending claims")
        }
    };

    let input_total_sats = checked_sum_sats(inputs.iter().map(|input| input.amount_sats))?;
    let withdrawal_gross_total_sats =
        checked_sum_sats(batch.outputs.iter().map(|output| output.gross_amount_sats))?;
    let withdrawal_net_total_sats =
        checked_sum_sats(batch.outputs.iter().map(|output| output.net_amount_sats))?;
    if input_total_sats < withdrawal_gross_total_sats {
        return Err(anyhow!(
            "vault inputs total {input_total_sats} sats cannot fund requested gross withdrawals {withdrawal_gross_total_sats} sats"
        ));
    }
    let vault_change_sats = input_total_sats - withdrawal_gross_total_sats;
    let remainder = if vault_change_sats == 0 {
        None
    } else {
        if vault_change_sats < P2TR_DUST_SATS {
            return Err(anyhow!(
                "same-epoch vault change {vault_change_sats} sats is below P2TR dust threshold {P2TR_DUST_SATS}; add/remove inputs or adjust the batch"
            ));
        }
        Some(VaultRemainderOutput::same_epoch_change(
            epoch.epoch_id,
            epoch.required_group_key()?,
            vault_change_sats,
        ))
    };

    let plan = VaultSpendPlan::withdrawal_batch(epoch, inputs, batch.clone(), remainder)?;
    let tx_plan = build_vault_psbt(&plan)?;
    let input_sighashes = vault_input_sighashes(&tx_plan)?;
    let output_total_sats = transaction_output_total_sats(&tx_plan.unsigned_tx)?;
    let expected_output_total_sats = withdrawal_net_total_sats
        .checked_add(vault_change_sats)
        .ok_or_else(|| anyhow!("withdrawal output total overflow"))?;
    if output_total_sats != expected_output_total_sats {
        return Err(anyhow!(
            "withdrawal transaction output total {output_total_sats} sats does not match expected {expected_output_total_sats} sats"
        ));
    }

    Ok(WithdrawalSpendPlanBuildResult {
        plan,
        spend_plan_hash: tx_plan.spend_plan_hash,
        withdrawal_batch_hash: batch.batch_hash(),
        withdrawal_batch_already_reserved,
        unsigned_txid: tx_plan.unsigned_tx.compute_txid().to_string(),
        input_sighashes,
        request_count: batch.outputs.len(),
        input_count: tx_plan.unsigned_tx.input.len(),
        output_count: tx_plan.unsigned_tx.output.len(),
        input_total_sats,
        withdrawal_gross_total_sats,
        withdrawal_net_total_sats,
        withdrawal_fee_sats: batch.total_fee_sats,
        vault_change_sats,
    })
}

fn checked_sum_sats(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| anyhow!("sats addition overflow"))
    })
}

fn demo_epoch(epoch_id: u64, signer_count: usize, frost_group_key_xonly: &str) -> VaultEpoch {
    let frost_signer_bindings = (0..signer_count)
        .map(|idx| {
            let participant_index =
                u16::try_from(idx + 1).expect("demo signer count must fit into u16");
            Ok(pohw_core::vault::DkgSignerBinding {
                signer_id: format!("signer-{idx:02}"),
                frost_identifier_hex: participant_frost_identifier_hex(participant_index)?,
            })
        })
        .collect::<Result<Vec<_>, pohw_core::vault_frost::VaultFrostError>>()
        .expect("demo signer identifiers must be valid");

    VaultEpoch {
        epoch_id,
        starts_at: Utc::now(),
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

fn require_unsafe_demo_vault_signing(allowed: bool) -> Result<()> {
    if allowed {
        return Ok(());
    }
    Err(anyhow!(
        "demo vault signing keeps simulated FROST signer material in one process; rerun with --allow-unsafe-demo-vault-signing only for local testnet/demo use"
    ))
}

fn demo_signer_ids(signer_count: usize) -> Vec<String> {
    (0..signer_count)
        .map(|idx| format!("signer-{idx:02}"))
        .collect()
}

fn demo_xonly_key(byte: u8) -> String {
    let secp = bitcoin::key::Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32])
        .expect("demo key byte must produce valid secret key");
    let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);
    keypair.x_only_public_key().0.to_string()
}

fn demo_secret_key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("demo key byte must produce valid secret key")
}

fn demo_keypair_from_secret(secret_key: &SecretKey) -> Keypair {
    Keypair::from_secret_key(&bitcoin::key::Secp256k1::new(), secret_key)
}

fn demo_peer(signer_id: &str, auth_keypair: &Keypair, ecdh_secret: &SecretKey) -> DkgPeerIdentity {
    DkgPeerIdentity {
        signer_id: signer_id.to_string(),
        auth_pubkey_xonly_hex: auth_keypair.x_only_public_key().0.to_string(),
        ecdh_pubkey_hex: PublicKey::from_secret_key(&bitcoin::key::Secp256k1::new(), ecdh_secret)
            .to_string(),
    }
}

fn demo_vault_input(input_sats: u64, frost_group_key_xonly: &str) -> Result<VaultInput> {
    Ok(VaultInput {
        txid: "00".repeat(32),
        vout: 0,
        amount_sats: input_sats,
        confirmations: 144,
        script_pubkey_hex: vault_script_pubkey_hex(frost_group_key_xonly)?,
    })
}

#[derive(Debug)]
pub(crate) struct PublishSharechainMessageInput {
    pub(crate) datadir: PathBuf,
    pub(crate) message: SharechainMessage,
    pub(crate) node_secret_key_file: PathBuf,
    pub(crate) message_out: Option<PathBuf>,
    pub(crate) envelope_out: Option<PathBuf>,
    pub(crate) append: bool,
    pub(crate) peer_addrs: Vec<SocketAddr>,
}

pub(crate) async fn publish_sharechain_message(
    input: PublishSharechainMessageInput,
) -> Result<serde_json::Value> {
    let node_keypair = read_keypair_from_file(&input.node_secret_key_file)?;
    let message_type = sharechain_message_type(&input.message);
    let message_hash = input.message.message_hash();
    if let Some(path) = input.message_out.as_ref() {
        write_json_file(path, &input.message)?;
    }

    let mut envelope = GossipEnvelope::unsigned(
        node_keypair.x_only_public_key().0.to_string(),
        current_unix_timestamp()?,
        random_nonce_hex(),
        input.message,
    )?;
    envelope.sign(&node_keypair)?;
    let envelope_hash = envelope.envelope_hash();
    if let Some(path) = input.envelope_out.as_ref() {
        write_json_file(path, &envelope)?;
    }

    let append_result = if input.append {
        Some(local_node::append_gossip_envelope(
            &input.datadir,
            envelope.clone(),
            300,
            86_400,
        )?)
    } else {
        None
    };

    let mut peer_results = Vec::new();
    let mut peer_error_count = 0usize;
    let mut peer_rejection_count = 0usize;
    for peer_addr in input.peer_addrs {
        match p2p_node::send_gossip_envelope(peer_addr, &envelope).await {
            Ok(response) => {
                if !response.accepted {
                    peer_rejection_count += 1;
                }
                peer_results.push(serde_json::json!({
                    "peer_addr": peer_addr,
                    "accepted": response.accepted,
                    "outcome": response.outcome,
                    "error": response.error,
                    "peer_decision": response.peer_decision,
                }));
            }
            Err(err) => {
                peer_error_count += 1;
                peer_results.push(serde_json::json!({
                    "peer_addr": peer_addr,
                    "accepted": false,
                    "error": err.to_string(),
                }));
            }
        }
    }

    let status = match (peer_error_count, peer_rejection_count) {
        (0, 0) => "published",
        (0, _) => "published_with_peer_rejections",
        (_, 0) => "published_with_peer_errors",
        (_, _) => "published_with_peer_errors_and_rejections",
    };

    Ok(serde_json::json!({
        "status": status,
        "message_type": message_type,
        "message_hash": message_hash,
        "envelope_hash": envelope_hash,
        "peer_pubkey_xonly_hex": envelope.peer_pubkey_xonly_hex,
        "message_out": input.message_out.as_ref().map(|path| display_path(path)),
        "envelope_out": input.envelope_out.as_ref().map(|path| display_path(path)),
        "appended": append_result.is_some(),
        "append_outcome": append_result.map(|result| format!("{:?}", result.message_result.outcome)),
        "peer_error_count": peer_error_count,
        "peer_rejection_count": peer_rejection_count,
        "peer_results": peer_results,
    }))
}

pub(crate) fn default_parent_share_hash(datadir: &Path) -> Result<String> {
    Ok(local_node::replay_state(datadir)?
        .best_share_tip()
        .map(ToOwned::to_owned)
        .unwrap_or_else(zero_share_parent_hash))
}

fn zero_share_parent_hash() -> String {
    "0".repeat(64)
}

async fn multinode_preflight(
    datadir: PathBuf,
    snapshot_dir: Option<PathBuf>,
    miner_id: Option<String>,
    peer_addrs: Vec<SocketAddr>,
) -> Result<serde_json::Value> {
    let status = local_node::local_node_status(&datadir)?;
    let state = local_node::replay_state(&datadir)?;
    let peers = local_node::list_gossip_peers(&datadir)?;
    let known_hashes = local_node::gossip_inventory(&datadir)?;
    let known_hashes_for_probe: Vec<String> =
        known_hashes.iter().rev().take(256).cloned().collect();
    let explicit_peer_count = peer_addrs.len();

    let latest_snapshot = match snapshot_dir.as_ref() {
        Some(dir) => {
            let snapshot_status = local_node::latest_verified_snapshot(dir)?;
            let latest = snapshot_status.latest.as_ref().map(|entry| {
                serde_json::json!({
                    "path": display_path(&entry.path),
                    "snapshot_day": entry.snapshot.snapshot_day.to_string(),
                    "idena_height": entry.snapshot.idena_height,
                    "idena_block_hash": entry.snapshot.idena_block_hash.clone(),
                    "identity_root": entry.snapshot.identity_root.clone(),
                    "score_root": entry.snapshot.score_root.clone(),
                    "formula_version": entry.snapshot.formula_version,
                    "leaf_count": entry.snapshot.leaves.len(),
                })
            });
            serde_json::json!({
                "configured": true,
                "snapshot_dir": display_path(&snapshot_status.snapshot_dir),
                "scanned_file_count": snapshot_status.scanned_file_count,
                "invalid_file_count": snapshot_status.invalid_file_count,
                "skipped_file_count": snapshot_status.skipped_file_count,
                "latest": latest,
            })
        }
        None => serde_json::json!({
            "configured": false,
            "latest": null,
        }),
    };
    let has_latest_snapshot = latest_snapshot
        .get("latest")
        .is_some_and(|latest| !latest.is_null());

    let miner_registration = miner_id.as_ref().map(|id| {
        let normalized = id.to_ascii_lowercase();
        match state.registrations().get(&normalized) {
            Some(registration) => serde_json::json!({
                "miner_id": normalized,
                "registered": true,
                "idena_address": registration.idena_address.clone(),
                "mining_pubkey_hex": registration.mining_pubkey_hex.clone(),
                "claim_owner_pubkey_hex": registration.claim_owner_pubkey_hex.clone(),
                "btc_payout_script_hex": registration.btc_payout_script_hex.clone(),
            }),
            None => serde_json::json!({
                "miner_id": normalized,
                "registered": false,
            }),
        }
    });
    let miner_registered = miner_registration
        .as_ref()
        .and_then(|value| value.get("registered"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let probe_peers: Vec<SocketAddr> = if peer_addrs.is_empty() {
        peers.iter().map(|peer| peer.addr).collect()
    } else {
        peer_addrs
    };
    let mut peer_inventory = Vec::new();
    for peer_addr in probe_peers {
        match p2p_node::pull_gossip_inventory(peer_addr, known_hashes_for_probe.clone(), 1).await {
            Ok(response) => peer_inventory.push(serde_json::json!({
                "peer_addr": peer_addr,
                "reachable": true,
                "returned_message_count": response.message_hashes.len(),
                "truncated": response.truncated,
            })),
            Err(err) => peer_inventory.push(serde_json::json!({
                "peer_addr": peer_addr,
                "reachable": false,
                "error": err.to_string(),
            })),
        }
    }

    Ok(serde_json::json!({
        "datadir": display_path(&datadir),
        "decentralization_model": "local verification only; this command does not appoint a coordinator or trusted accountant",
        "local": {
            "sharechain_log": display_path(&status.sharechain_log),
            "gossip_envelope_log": display_path(&status.gossip_envelope_log),
            "sharechain_message_count": status.log_line_count,
            "gossip_envelope_count": status.gossip_envelope_count,
            "known_gossip_hash_count": known_hashes.len(),
            "replay": status.replay.clone(),
        },
        "readiness": {
            "has_registered_miner": miner_id.is_none() || miner_registered,
            "has_snapshot": snapshot_dir.is_none() || has_latest_snapshot,
            "has_gossip_peers": !peers.is_empty() || explicit_peer_count > 0,
            "has_accepted_bitcoin_work_template": status.replay.accepted_bitcoin_work_template_count > 0,
            "has_published_bitcoin_work_template": status.replay.bitcoin_work_template_count > 0,
            "has_share_tip": status.replay.best_share_tip.is_some(),
        },
        "miner_registration": miner_registration,
        "snapshot_directory": latest_snapshot,
        "peer_book": peers,
        "peer_inventory_probe": peer_inventory,
    }))
}

#[derive(Debug)]
struct PrepareMinerRegistrationInput {
    datadir: PathBuf,
    miner_id: String,
    idena_address: String,
    key_dir: Option<PathBuf>,
    mining_secret_key_file: Option<PathBuf>,
    claim_owner_secret_key_file: Option<PathBuf>,
    node_secret_key_file: Option<PathBuf>,
    btc_payout_script_hex: Option<String>,
    idena_signature_hex: Option<String>,
    message_out: Option<PathBuf>,
    envelope_out: Option<PathBuf>,
    append: bool,
    peer_addrs: Vec<SocketAddr>,
}

#[derive(Debug)]
struct LocalKeyMaterial {
    path: PathBuf,
    keypair: Keypair,
    created: bool,
}

#[derive(Debug)]
struct LocalSecretKeyMaterial {
    path: PathBuf,
    secret_key: SecretKey,
    created: bool,
}

async fn prepare_miner_registration(
    input: PrepareMinerRegistrationInput,
) -> Result<serde_json::Value> {
    let key_paths = registration_key_paths(
        &input.datadir,
        input.key_dir,
        &input.miner_id,
        input.mining_secret_key_file,
        input.claim_owner_secret_key_file,
        input.node_secret_key_file,
    )?;
    reject_duplicate_key_paths(&key_paths)?;

    let mining_key = read_or_create_keypair_from_file(&key_paths.mining)?;
    let claim_owner_key = read_or_create_keypair_from_file(&key_paths.claim_owner)?;
    let node_key = read_or_create_keypair_from_file(&key_paths.node)?;
    let claim_owner_pubkey_hex = claim_owner_key.keypair.x_only_public_key().0.to_string();
    let btc_payout_script_hex = match input.btc_payout_script_hex {
        Some(script) => script.to_ascii_lowercase(),
        None => p2tr_script_pubkey_hex_from_xonly(&claim_owner_pubkey_hex)?,
    };

    let mut registration = MinerRegistration {
        miner_id: input.miner_id,
        idena_address: input.idena_address,
        btc_payout_script_hex,
        claim_owner_pubkey_hex,
        mining_pubkey_hex: mining_key.keypair.x_only_public_key().0.to_string(),
        idena_signature_hex: input.idena_signature_hex.unwrap_or_default(),
        mining_signature_hex: String::new(),
    };
    let idena_ownership_challenge = registration.idena_ownership_challenge();
    let registration_binding_hash = hex::encode(registration.signing_hash());

    if registration.idena_signature_hex.is_empty() {
        if input.append || input.message_out.is_some() || input.envelope_out.is_some() {
            return Err(anyhow!(
                "--idena-signature-hex is required before writing, appending, or gossiping a registration"
            ));
        }
        return Ok(serde_json::json!({
            "status": "needs_idena_signature",
            "miner_id": registration.miner_id,
            "idena_address": registration.idena_address,
            "idena_ownership_challenge": idena_ownership_challenge,
            "registration_binding_hash": registration_binding_hash,
            "signature_field": "idena_signature_hex",
            "mining_pubkey_hex": registration.mining_pubkey_hex,
            "claim_owner_pubkey_hex": registration.claim_owner_pubkey_hex,
            "btc_payout_script_hex": registration.btc_payout_script_hex,
            "key_files": key_material_summary(&mining_key, &claim_owner_key, &node_key),
            "next_step": "Sign idena_ownership_challenge with the Idena address, then rerun with --idena-signature-hex."
        }));
    }

    registration.mining_signature_hex =
        sign_hash_hex(registration.signing_hash(), &mining_key.keypair);
    registration.verify_mining_signature()?;
    registration.verify_idena_ownership_signature()?;
    let message = SharechainMessage::MinerRegistration(registration.clone());
    let message_hash = message.message_hash();
    if let Some(path) = input.message_out.as_ref() {
        write_json_file(path, &message)?;
    }

    let mut envelope = GossipEnvelope::unsigned(
        node_key.keypair.x_only_public_key().0.to_string(),
        current_unix_timestamp()?,
        random_nonce_hex(),
        message,
    )?;
    envelope.sign(&node_key.keypair)?;
    let envelope_hash = envelope.envelope_hash();
    if let Some(path) = input.envelope_out.as_ref() {
        write_json_file(path, &envelope)?;
    }

    let append_result = if input.append {
        Some(local_node::append_gossip_envelope(
            &input.datadir,
            envelope.clone(),
            300,
            86_400,
        )?)
    } else {
        None
    };

    let mut peer_results = Vec::new();
    for peer_addr in input.peer_addrs {
        let response = p2p_node::send_gossip_envelope(peer_addr, &envelope).await?;
        peer_results.push(serde_json::json!({
            "peer_addr": peer_addr,
            "accepted": response.accepted,
            "outcome": response.outcome,
            "error": response.error,
        }));
    }

    Ok(serde_json::json!({
        "status": "registration_ready",
        "miner_id": registration.miner_id,
        "idena_address": registration.idena_address,
        "message_hash": message_hash,
        "envelope_hash": envelope_hash,
        "idena_ownership_challenge": idena_ownership_challenge,
        "registration_binding_hash": registration_binding_hash,
        "mining_pubkey_hex": registration.mining_pubkey_hex,
        "claim_owner_pubkey_hex": registration.claim_owner_pubkey_hex,
        "btc_payout_script_hex": registration.btc_payout_script_hex,
        "message_out": input.message_out.as_ref().map(|path| display_path(path)),
        "envelope_out": input.envelope_out.as_ref().map(|path| display_path(path)),
        "appended": append_result.is_some(),
        "append_outcome": append_result.map(|result| format!("{:?}", result.message_result.outcome)),
        "peer_results": peer_results,
        "key_files": key_material_summary(&mining_key, &claim_owner_key, &node_key),
    }))
}

#[derive(Debug)]
struct RegistrationKeyPaths {
    mining: PathBuf,
    claim_owner: PathBuf,
    node: PathBuf,
}

fn registration_key_paths(
    datadir: &Path,
    key_dir: Option<PathBuf>,
    miner_id: &str,
    mining_secret_key_file: Option<PathBuf>,
    claim_owner_secret_key_file: Option<PathBuf>,
    node_secret_key_file: Option<PathBuf>,
) -> Result<RegistrationKeyPaths> {
    let key_dir = match key_dir {
        Some(key_dir) => key_dir,
        None => datadir.join("keys").join(safe_key_stem(miner_id)?),
    };
    Ok(RegistrationKeyPaths {
        mining: mining_secret_key_file.unwrap_or_else(|| key_dir.join("mining.key")),
        claim_owner: claim_owner_secret_key_file.unwrap_or_else(|| key_dir.join("claim-owner.key")),
        node: node_secret_key_file.unwrap_or_else(|| key_dir.join("gossip-node.key")),
    })
}

fn safe_key_stem(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(anyhow!(
            "miner id must be 1-64 ASCII letters, digits, '-', '_', or '.' when deriving default key paths"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn reject_duplicate_key_paths(paths: &RegistrationKeyPaths) -> Result<()> {
    if paths.mining == paths.claim_owner
        || paths.mining == paths.node
        || paths.claim_owner == paths.node
    {
        return Err(anyhow!(
            "mining, claim-owner, and node secret key files must be different paths"
        ));
    }
    Ok(())
}

fn read_or_create_keypair_from_file(path: &PathBuf) -> Result<LocalKeyMaterial> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(LocalKeyMaterial {
            path: path.clone(),
            keypair: read_keypair_from_file(path)?,
            created: false,
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let secret_key = random_secret_key();
            write_secret_key_file(path, &secret_key)?;
            Ok(LocalKeyMaterial {
                path: path.clone(),
                keypair: read_keypair_from_file(path)?,
                created: true,
            })
        }
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn read_or_create_secret_key_from_file(path: &PathBuf) -> Result<LocalSecretKeyMaterial> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(LocalSecretKeyMaterial {
            path: path.clone(),
            secret_key: read_secret_key_from_file(path)?,
            created: false,
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let secret_key = random_secret_key();
            write_secret_key_file(path, &secret_key)?;
            Ok(LocalSecretKeyMaterial {
                path: path.clone(),
                secret_key,
                created: true,
            })
        }
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn random_secret_key() -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&bytes) {
            return secret_key;
        }
    }
}

fn write_secret_key_file(path: &Path, secret_key: &SecretKey) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_private_file_parent_dir(parent)
            .with_context(|| format!("failed to prepare key directory {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create secret key file {}", path.display()))?;
    file.write_all(hex::encode(secret_key.secret_bytes()).as_bytes())
        .with_context(|| format!("failed to write secret key file {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to terminate secret key file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync secret key file {}", path.display()))?;
    sync_parent_dir(path, "secret key file")?;
    Ok(())
}

fn prepare_private_file_parent_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => validate_existing_private_file_parent(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_private_dir_all(path),
        Err(err) => Err(err)
            .with_context(|| format!("failed to inspect private directory {}", path.display())),
    }
}

fn validate_existing_private_file_parent(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "private directory {} must not be a symlink",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(anyhow!(
            "private directory path {} is not a directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(anyhow!(
                "private directory {} is writable by group or others ({mode:o}); use a private directory or chmod go-w {}",
                path.display(),
                path.display()
            ));
        }
    }
    validate_no_unsafe_symlink_ancestors(path, "private directory")?;
    Ok(())
}

#[cfg(unix)]
fn validate_no_unsafe_symlink_ancestors(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for private path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
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
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect {label} symlink ancestor parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            return Err(anyhow!(
                "{label} {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_symlink_ancestors(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

fn create_private_dir_all(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "private directory {} must not be a symlink",
                    path.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(anyhow!(
                    "private directory path {} is not a directory",
                    path.display()
                ));
            }
            return Ok(());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect private directory {}", path.display())
            });
        }
    }

    if let Some(parent) = non_empty_parent(path) {
        if parent != path {
            create_private_dir_all(parent)?;
        }
    }

    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).with_context(|| {
                format!("failed to inspect private directory {}", path.display())
            })?;
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "private directory {} must not be a symlink",
                    path.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(anyhow!(
                    "private directory path {} is not a directory",
                    path.display()
                ));
            }
            return Ok(());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to create private directory {}", path.display()));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn p2tr_script_pubkey_hex_from_xonly(xonly_hex: &str) -> Result<String> {
    let normalized = xonly_hex
        .strip_prefix("0x")
        .unwrap_or(xonly_hex)
        .to_ascii_lowercase();
    if normalized.len() != 64
        || !normalized
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!(
            "x-only public key must be 32 bytes encoded as 64 hex characters"
        ));
    }
    normalized
        .parse::<bitcoin::key::XOnlyPublicKey>()
        .context("invalid x-only public key")?;
    Ok(format!("5120{normalized}"))
}

fn key_material_summary(
    mining_key: &LocalKeyMaterial,
    claim_owner_key: &LocalKeyMaterial,
    node_key: &LocalKeyMaterial,
) -> serde_json::Value {
    serde_json::json!({
        "mining_secret_key_file": {
            "path": display_path(&mining_key.path),
            "created": mining_key.created,
        },
        "claim_owner_secret_key_file": {
            "path": display_path(&claim_owner_key.path),
            "created": claim_owner_key.created,
        },
        "node_secret_key_file": {
            "path": display_path(&node_key.path),
            "created": node_key.created,
        }
    })
}

struct StagedJsonFile {
    path: PathBuf,
    tmp_path: PathBuf,
    published: bool,
    preserve_tmp: bool,
}

impl StagedJsonFile {
    fn publish(mut self) -> Result<()> {
        if let Err(err) = std::fs::hard_link(&self.tmp_path, &self.path) {
            self.preserve_tmp = true;
            return Err(err).with_context(|| {
                format!(
                    "failed to publish JSON {} without overwriting existing destination {}",
                    self.tmp_path.display(),
                    self.path.display()
                )
            });
        }
        self.published = true;
        std::fs::remove_file(&self.tmp_path).with_context(|| {
            format!(
                "failed to remove temporary JSON {}",
                self.tmp_path.display()
            )
        })?;
        sync_parent_dir(&self.path, "JSON artifact")?;
        Ok(())
    }
}

impl Drop for StagedJsonFile {
    fn drop(&mut self) {
        if !self.published && !self.preserve_tmp {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    stage_json_file(path, value)?.publish()
}

fn write_json_file_replace_existing_regular<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_private_file_parent_dir(parent)
            .with_context(|| format!("failed to prepare output directory {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to replace symlink JSON destination {}",
                    path.display()
                ));
            }
            if !metadata.is_file() {
                return Err(anyhow!(
                    "refusing to replace non-file JSON destination {}",
                    path.display()
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to inspect JSON destination {}", path.display()));
        }
    }
    let tmp_path = path.with_extension(format!("{}.replace", random_nonce_hex()));
    write_json_file(&tmp_path, value)?;
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to replace JSON {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    sync_parent_dir(path, "JSON artifact")?;
    Ok(())
}

fn stage_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<StagedJsonFile> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_public_file_parent_dir(parent)
            .with_context(|| format!("failed to prepare output directory {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(anyhow!(
                "refusing to overwrite existing JSON destination {}",
                path.display()
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to inspect JSON destination {}", path.display()));
        }
    }
    let tmp_path = path.with_extension(format!("{}.tmp", random_nonce_hex()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .with_context(|| format!("failed to create temporary JSON {}", tmp_path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write JSON {}", tmp_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to terminate JSON {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync JSON {}", tmp_path.display()))?;
    drop(file);
    Ok(StagedJsonFile {
        path: path.to_path_buf(),
        tmp_path,
        published: false,
        preserve_tmp: false,
    })
}

fn prepare_public_file_parent_dir(path: &Path) -> Result<()> {
    validate_no_unsafe_symlink_ancestors(path, "public output directory")?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "public output directory {} must not be a symlink",
                    path.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(anyhow!(
                    "public output directory path {} is not a directory",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = non_empty_parent(path) {
                if parent != path {
                    prepare_public_file_parent_dir(parent)?;
                }
            }
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    prepare_public_file_parent_dir(path)
                }
                Err(err) => Err(err).with_context(|| {
                    format!("failed to create output directory {}", path.display())
                }),
            }
        }
        Err(err) => Err(err)
            .with_context(|| format!("failed to inspect output directory {}", path.display())),
    }
}

fn write_private_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        prepare_private_file_parent_dir(parent)
            .with_context(|| format!("failed to prepare private directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", random_nonce_hex()));
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to protect private JSON {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to move private JSON {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    sync_parent_dir(path, "private JSON")?;
    Ok(())
}

fn sync_parent_dir(path: &Path, label: &str) -> Result<()> {
    let parent = non_empty_parent(path).unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(parent)
            .with_context(|| format!("failed to open {label} directory {}", parent.display()))?;
        dir.sync_all()
            .with_context(|| format!("failed to sync {label} directory {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, label);
    }
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let json = read_bounded_regular_text_file(path, "JSON file", MAX_JSON_INPUT_FILE_BYTES)?;
    serde_json::from_str(&json).with_context(|| format!("failed to parse JSON {}", path.display()))
}

fn read_private_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    validate_protected_secret_file(path, "private JSON")?;
    read_json_file(path)
}

fn read_json_files<T: serde::de::DeserializeOwned>(paths: &[PathBuf]) -> Result<Vec<T>> {
    if paths.is_empty() {
        return Err(anyhow!("at least one input file is required"));
    }
    paths.iter().map(|path| read_json_file(path)).collect()
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn bitcoin_rpc_client(
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpc_cookie_file: Option<PathBuf>,
    allow_remote_rpc: bool,
) -> Result<BitcoinRpcClient> {
    let auth = BitcoinRpcClient::auth_from_user_password(rpc_user, rpc_password, rpc_cookie_file)?;
    if allow_remote_rpc {
        BitcoinRpcClient::new_with_remote_policy(rpc_url, auth, true)
    } else {
        BitcoinRpcClient::new(rpc_url, auth)
    }
}

fn fork_chain_client_from_options(
    rpc_addr: Option<SocketAddr>,
    activation_manifest: Option<PathBuf>,
) -> Result<Option<fork_chain::ForkChainClient>> {
    match (rpc_addr, activation_manifest) {
        (Some(addr), Some(path)) => {
            let manifest = fork_chain::read_activation_manifest(&path)?;
            Ok(Some(fork_chain::ForkChainClient::new(
                addr,
                manifest.activation_id,
                false,
            )?))
        }
        (None, None) => Ok(None),
        _ => bail!(
            "--fork-chain-rpc-addr and --fork-chain-activation-manifest must be supplied together"
        ),
    }
}

fn read_stratum_block_candidate_file(path: &Path) -> Result<mining_adapter::StratumBlockCandidate> {
    read_json_file(path)
}

fn block_hex_for_stratum_candidate_submission(
    candidate: &mining_adapter::StratumBlockCandidate,
) -> Result<&str> {
    mining_adapter::block_hex_for_stratum_candidate_submission(candidate)
}

fn ensure_candidate_submit_chain_allowed(
    chain_info: &BlockchainInfoResponse,
    allow_mainnet_submit: bool,
) -> Result<()> {
    if chain_info.chain.eq_ignore_ascii_case("main") && !allow_mainnet_submit {
        bail!(
            "refusing to submit a block candidate to Bitcoin mainnet RPC without --allow-mainnet-submit"
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PrepareForkActivationInput {
    chain_name: String,
    launch_timestamp_utc: DateTime<Utc>,
    inherited_utxo_spending_enabled: bool,
    post_fork_pow_limit_bits: u32,
    target_spacing_seconds: u64,
    timestamp_search_window_blocks: u64,
    allow_non_mainnet_rpc: bool,
}

async fn prepare_fork_activation(
    client: &BitcoinRpcClient,
    input: PrepareForkActivationInput,
) -> Result<ForkActivationManifest> {
    let chain_name = validate_fork_chain_name(&input.chain_name)?;
    if input.target_spacing_seconds == 0 {
        return Err(anyhow!(
            "--target-spacing-seconds must be greater than zero"
        ));
    }
    if input.timestamp_search_window_blocks == 0
        || input.timestamp_search_window_blocks > MAX_FORK_TIMESTAMP_SEARCH_WINDOW_BLOCKS
    {
        return Err(anyhow!(
            "--timestamp-search-window-blocks must be 1..={}",
            MAX_FORK_TIMESTAMP_SEARCH_WINDOW_BLOCKS
        ));
    }

    let blockchain_info = client.get_blockchain_info().await?;
    if blockchain_info.chain != "main" && !input.allow_non_mainnet_rpc {
        return Err(anyhow!(
            "fork activation must be derived from Bitcoin mainnet RPC; got chain '{}'. Use --allow-non-mainnet-rpc only for local tests",
            blockchain_info.chain
        ));
    }
    if blockchain_info.headers < blockchain_info.blocks {
        return Err(anyhow!(
            "Bitcoin RPC reports headers {} behind blocks {}; refusing inconsistent chain status",
            blockchain_info.headers,
            blockchain_info.blocks
        ));
    }

    let launch_block = find_first_mainnet_block_at_or_after_timestamp(
        client,
        input.launch_timestamp_utc,
        blockchain_info.blocks,
        input.timestamp_search_window_blocks,
    )
    .await?;
    let inherited_height = launch_block
        .height
        .checked_sub(1)
        .ok_or_else(|| anyhow!("launch block height 0 cannot be used"))?;
    let inherited_tip = client.mainnet_block_ref_by_height(inherited_height).await?;
    let fork_point = select_fork_point(
        input.launch_timestamp_utc,
        &[inherited_tip, launch_block.clone()],
    )?;
    let config = ForkConfig {
        chain_name,
        launch_timestamp_utc: input.launch_timestamp_utc,
        inherited_utxo_spending_enabled: input.inherited_utxo_spending_enabled,
        post_fork_pow_limit_bits: input.post_fork_pow_limit_bits,
        target_spacing_seconds: input.target_spacing_seconds,
    };

    ForkActivationManifest::new(config, fork_point, launch_block).map_err(Into::into)
}

async fn find_first_mainnet_block_at_or_after_timestamp(
    client: &BitcoinRpcClient,
    launch_timestamp_utc: DateTime<Utc>,
    tip_height: u64,
    timestamp_search_window_blocks: u64,
) -> Result<MainnetBlockRef> {
    let tip = client.mainnet_block_ref_by_height(tip_height).await?;
    if tip.timestamp < launch_timestamp_utc {
        return Err(anyhow!(
            "Bitcoin RPC tip height {} timestamp {} is before launch timestamp {}; keep syncing or choose an earlier launch timestamp",
            tip.height,
            tip.timestamp.to_rfc3339(),
            launch_timestamp_utc.to_rfc3339()
        ));
    }

    let mut low = 0;
    let mut high = tip_height;
    while low < high {
        let mid = low + (high - low) / 2;
        let block = client.mainnet_block_ref_by_height(mid).await?;
        if block.timestamp >= launch_timestamp_utc {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    let candidate = low;
    let start = candidate.saturating_sub(timestamp_search_window_blocks);
    let end = candidate
        .saturating_add(timestamp_search_window_blocks)
        .min(tip_height);
    let mut selected = None;
    for height in start..=end {
        let block = client.mainnet_block_ref_by_height(height).await?;
        if block.timestamp >= launch_timestamp_utc {
            selected = Some(block);
            break;
        }
    }
    let mut selected = selected.ok_or_else(|| {
        anyhow!(
            "could not find a launch block in timestamp verification window {}..={}; increase --timestamp-search-window-blocks",
            start,
            end
        )
    })?;

    while selected.height > 0 {
        let previous_height = selected.height - 1;
        if previous_height < start {
            return Err(anyhow!(
                "timestamp verification window is too small to prove first launch block; increase --timestamp-search-window-blocks above {}",
                timestamp_search_window_blocks
            ));
        }
        let previous = client.mainnet_block_ref_by_height(previous_height).await?;
        if previous.timestamp < launch_timestamp_utc {
            break;
        }
        selected = previous;
    }

    Ok(selected)
}

fn validate_fork_chain_name(raw: &str) -> Result<String> {
    if raw.trim() != raw {
        return Err(anyhow!(
            "--chain-name must not contain leading or trailing whitespace"
        ));
    }
    if raw.is_empty() || raw.len() > 64 {
        return Err(anyhow!("--chain-name must be 1-64 characters"));
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(anyhow!(
            "--chain-name may contain only ASCII letters, digits, '.', '_' and '-'"
        ));
    }
    Ok(raw.to_string())
}

fn parse_utc_datetime_arg(label: &str, raw: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .with_context(|| format!("--{label} must be RFC3339, for example 2026-07-05T00:00:00Z"))
}

fn parse_compact_bits_arg(label: &str, raw: &str) -> Result<u32> {
    let raw = raw.trim();
    let value = raw.strip_prefix("0x").unwrap_or(raw);
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "--{label} must be 4 bytes encoded as 8 hex characters"
        ));
    }
    u32::from_str_radix(value, 16).with_context(|| format!("--{label} is not valid hex"))
}

fn read_optional_secret(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    label: &str,
) -> Result<Option<String>> {
    match (secret, secret_file) {
        (Some(_), Some(_)) => Err(anyhow!("{label} and {label} file cannot both be supplied")),
        (Some(secret), None) => validate_secret(secret, label).map(Some),
        (None, Some(path)) => {
            validate_protected_secret_file(&path, label)?;
            let secret =
                read_bounded_regular_text_file(&path, label, MAX_OPTIONAL_SECRET_FILE_BYTES)?;
            validate_secret(secret, label).map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn validate_secret(secret: String, label: &str) -> Result<String> {
    let secret = secret.trim().to_string();
    if secret.is_empty() || secret.len() > MAX_OPTIONAL_SECRET_BYTES {
        return Err(anyhow!(
            "{label} must be 1-{MAX_OPTIONAL_SECRET_BYTES} bytes"
        ));
    }
    if secret.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(anyhow!("{label} must not contain control characters"));
    }
    Ok(secret)
}

fn parse_outpoint(raw: &str) -> Result<(String, u32)> {
    let (txid, vout) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("outpoint must be formatted as TXID:VOUT"))?;
    if txid.len() != 64 || !txid.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("outpoint txid must be 64 hex characters"));
    }
    let vout = vout.parse::<u32>()?;
    Ok((txid.to_ascii_lowercase(), vout))
}

fn apply_snapshot_scores(
    state: &SharechainReplayState,
    accounts: &mut [ParticipantAccount],
    snapshot_file: &Path,
) -> Result<()> {
    let snapshot = local_node::read_verified_snapshot(snapshot_file)?;
    local_node::apply_snapshot_scores_to_accounts(state, accounts, &snapshot)
}

fn read_sharechain_message_file(path: &Path) -> Result<SharechainMessage> {
    let json = read_bounded_regular_text_file(path, "message file", MAX_JSON_INPUT_FILE_BYTES)?;
    serde_json::from_str(&json)
        .with_context(|| format!("failed to parse sharechain message {}", path.display()))
}

fn read_payout_schedule_file(path: &Path) -> Result<PayoutSchedule> {
    let json = read_bounded_regular_text_file(
        path,
        "payout schedule file",
        MAX_PAYOUT_SCHEDULE_FILE_BYTES,
    )?;
    if let Ok(schedule) = serde_json::from_str::<PayoutSchedule>(&json) {
        return Ok(schedule);
    }
    match serde_json::from_str::<SharechainMessage>(&json)
        .with_context(|| format!("failed to parse payout schedule {}", path.display()))?
    {
        SharechainMessage::PayoutSchedule(schedule) => Ok(schedule),
        other => Err(anyhow!(
            "expected payout schedule file {}, got {}",
            path.display(),
            sharechain_message_type(&other)
        )),
    }
}

fn read_pohw_commitment_file(path: &Path) -> Result<PohwCommitment> {
    let json = read_bounded_regular_text_file(
        path,
        "POHW commitment file",
        MAX_POHW_COMMITMENT_FILE_BYTES,
    )?;
    if let Ok(commitment) = serde_json::from_str::<PohwCommitment>(&json) {
        return Ok(commitment.normalized());
    }
    match serde_json::from_str::<SharechainMessage>(&json)
        .with_context(|| format!("failed to parse POHW commitment {}", path.display()))?
    {
        SharechainMessage::PohwCommitment(commitment) => Ok(commitment.normalized()),
        other => Err(anyhow!(
            "expected POHW commitment file {}, got {}",
            path.display(),
            sharechain_message_type(&other)
        )),
    }
}

fn payout_schedule_coinbase_positive_output_sats(schedule: &PayoutSchedule) -> Result<u64> {
    let mut total = 0u64;
    for output in &schedule.direct_outputs {
        total = total
            .checked_add(output.amount_sats)
            .ok_or_else(|| anyhow!("coinbase payout output total overflow"))?;
    }
    total = total
        .checked_add(schedule.vault_output_sats)
        .ok_or_else(|| anyhow!("coinbase payout output total overflow"))?;
    Ok(total)
}

async fn run_payout_confirmer_once(
    datadir: &Path,
    candidate_dir: &Path,
    client: &BitcoinRpcClient,
    defaults: PayoutConfirmerDefaults,
) -> Result<PayoutConfirmerSummary> {
    let candidate_paths =
        discover_payout_confirmation_candidate_files(candidate_dir, defaults.max_candidates)?;
    let mut summary = PayoutConfirmerSummary {
        candidate_dir: candidate_dir.to_path_buf(),
        scanned_file_count: candidate_paths.len(),
        confirmed_count: 0,
        duplicate_count: 0,
        pending_count: 0,
        failed_count: 0,
        results: Vec::with_capacity(candidate_paths.len()),
    };

    for path in candidate_paths {
        let result = match read_payout_confirmation_candidate_file(&path) {
            Ok(candidate) => {
                confirm_loaded_payout_candidate(
                    datadir,
                    client,
                    LoadedPayoutConfirmationCandidate { path, candidate },
                    defaults,
                )
                .await
            }
            Err(err) => PayoutConfirmerCandidateResult {
                candidate_file: path,
                block_hash: None,
                status: PayoutConfirmerCandidateStatus::Failed,
                detail: format!("{err:#}"),
                confirmations: None,
                min_confirmations: None,
                record_id: None,
            },
        };
        match result.status {
            PayoutConfirmerCandidateStatus::Confirmed => summary.confirmed_count += 1,
            PayoutConfirmerCandidateStatus::Duplicate => summary.duplicate_count += 1,
            PayoutConfirmerCandidateStatus::Pending => summary.pending_count += 1,
            PayoutConfirmerCandidateStatus::Failed => summary.failed_count += 1,
        }
        summary.results.push(result);
    }

    Ok(summary)
}

async fn confirm_loaded_payout_candidate(
    datadir: &Path,
    client: &BitcoinRpcClient,
    loaded: LoadedPayoutConfirmationCandidate,
    defaults: PayoutConfirmerDefaults,
) -> PayoutConfirmerCandidateResult {
    match try_confirm_loaded_payout_candidate(datadir, client, &loaded, defaults).await {
        Ok(result) => result,
        Err(err) => PayoutConfirmerCandidateResult {
            candidate_file: loaded.path,
            block_hash: Some(loaded.candidate.block_hash),
            status: PayoutConfirmerCandidateStatus::Failed,
            detail: format!("{err:#}"),
            confirmations: None,
            min_confirmations: Some(
                loaded
                    .candidate
                    .min_confirmations
                    .unwrap_or(defaults.min_confirmations),
            ),
            record_id: None,
        },
    }
}

async fn try_confirm_loaded_payout_candidate(
    datadir: &Path,
    client: &BitcoinRpcClient,
    loaded: &LoadedPayoutConfirmationCandidate,
    defaults: PayoutConfirmerDefaults,
) -> Result<PayoutConfirmerCandidateResult> {
    let candidate = &loaded.candidate;
    let min_confirmations = candidate
        .min_confirmations
        .unwrap_or(defaults.min_confirmations);
    let confirmations = client.block_confirmations(&candidate.block_hash).await?;
    if confirmations < min_confirmations {
        return Ok(PayoutConfirmerCandidateResult {
            candidate_file: loaded.path.clone(),
            block_hash: Some(candidate.block_hash.clone()),
            status: PayoutConfirmerCandidateStatus::Pending,
            detail: format!(
                "block has {confirmations} confirmations; waiting for {min_confirmations}"
            ),
            confirmations: Some(confirmations),
            min_confirmations: Some(min_confirmations),
            record_id: None,
        });
    }

    let snapshot_file = resolve_payout_candidate_path(&loaded.path, &candidate.snapshot_file);
    let payout_schedule_file =
        resolve_payout_candidate_path(&loaded.path, &candidate.payout_schedule_file);
    let pohw_commitment_file =
        resolve_payout_candidate_path(&loaded.path, &candidate.pohw_commitment_file);
    let schedule = read_payout_schedule_file(&payout_schedule_file)?;
    let pohw_commitment = read_pohw_commitment_file(&pohw_commitment_file)?;

    let confirmation = client
        .confirm_coinbase_payout(
            &candidate.block_hash,
            &schedule,
            &pohw_commitment,
            min_confirmations,
        )
        .await?;
    let expected_reward_sats = payout_candidate_expected_reward_sats(candidate, defaults)?;
    let reward_sats = match expected_reward_sats {
        Some(expected_reward_sats)
            if expected_reward_sats != confirmation.confirmed_output_total_sats =>
        {
            return Err(anyhow!(
                "verified coinbase payout total is {} sats, but configured reward_sats was {}",
                confirmation.confirmed_output_total_sats,
                expected_reward_sats
            ));
        }
        Some(expected_reward_sats) => expected_reward_sats,
        None => confirmation.confirmed_output_total_sats,
    };
    let result = local_node::append_confirmed_payout_record(
        datadir,
        local_node::ConfirmedPayoutAppend {
            snapshot_file,
            payout_schedule: schedule,
            pohw_commitment,
            reward_sats,
            direct_limit: candidate.direct_limit.unwrap_or(defaults.direct_limit),
            min_direct_payout_sats: candidate
                .min_direct_payout_sats
                .unwrap_or(defaults.min_direct_payout_sats),
            fork_block_height: confirmation.fork_block_height,
            fork_block_hash: confirmation.fork_block_hash,
            coinbase_txid: confirmation.coinbase_txid,
        },
    )?;
    let (status, detail) = match result.outcome {
        pohw_core::sharechain_state::ApplyOutcome::Applied => (
            PayoutConfirmerCandidateStatus::Confirmed,
            "confirmed payout appended".to_string(),
        ),
        pohw_core::sharechain_state::ApplyOutcome::DuplicateIgnored => (
            PayoutConfirmerCandidateStatus::Duplicate,
            "confirmed payout was already recorded".to_string(),
        ),
    };

    Ok(PayoutConfirmerCandidateResult {
        candidate_file: loaded.path.clone(),
        block_hash: Some(candidate.block_hash.clone()),
        status,
        detail,
        confirmations: Some(confirmation.confirmations),
        min_confirmations: Some(min_confirmations),
        record_id: Some(result.record_id),
    })
}

fn payout_candidate_expected_reward_sats(
    candidate: &PayoutConfirmationCandidate,
    defaults: PayoutConfirmerDefaults,
) -> Result<Option<u64>> {
    match (candidate.reward_sats, defaults.reward_sats) {
        (Some(candidate_reward_sats), Some(default_reward_sats))
            if candidate_reward_sats != default_reward_sats =>
        {
            Err(anyhow!(
                "candidate reward_sats {} conflicts with command reward_sats {}",
                candidate_reward_sats,
                default_reward_sats
            ))
        }
        (Some(reward_sats), _) | (_, Some(reward_sats)) => Ok(Some(reward_sats)),
        (None, None) => Ok(None),
    }
}

fn discover_payout_confirmation_candidate_files(
    candidate_dir: &Path,
    max_candidates: usize,
) -> Result<Vec<PathBuf>> {
    let metadata = match std::fs::symlink_metadata(candidate_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to inspect candidate dir {}",
                    candidate_dir.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "candidate dir {} must not be a symlink",
            candidate_dir.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(anyhow!(
            "candidate dir {} is not a directory",
            candidate_dir.display()
        ));
    }
    if max_candidates == 0 {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(candidate_dir)
        .with_context(|| format!("failed to read candidate dir {}", candidate_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read candidate dir entry under {}",
                candidate_dir.display()
            )
        })?;
        if !entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    if paths.len() > max_candidates {
        return Err(anyhow!(
            "candidate dir {} contains {} JSON files, exceeding --max-candidates {}",
            candidate_dir.display(),
            paths.len(),
            max_candidates
        ));
    }
    Ok(paths)
}

fn read_payout_confirmation_candidate_file(path: &Path) -> Result<PayoutConfirmationCandidate> {
    let json = read_bounded_regular_text_file(
        path,
        "candidate file",
        MAX_PAYOUT_CONFIRMATION_CANDIDATE_BYTES,
    )?;
    serde_json::from_str(&json)
        .with_context(|| format!("failed to parse candidate file {}", path.display()))
}

fn read_bounded_regular_text_file(path: &Path, label: &str, max_bytes: u64) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} {} is not a regular file", path.display()));
    }
    if metadata.len() > max_bytes {
        return Err(anyhow!(
            "{label} {} is {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    Ok(json)
}

fn resolve_payout_candidate_path(candidate_file: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        candidate_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn dkg_peer_from_keys(
    signer_id: &str,
    auth_keypair: &Keypair,
    ecdh_secret_key: &SecretKey,
) -> Result<DkgPeerIdentity> {
    let secp = bitcoin::key::Secp256k1::new();
    let ecdh_pubkey = PublicKey::from_secret_key(&secp, ecdh_secret_key);
    DkgPeerIdentity {
        signer_id: signer_id.to_ascii_lowercase(),
        auth_pubkey_xonly_hex: auth_keypair.x_only_public_key().0.to_string(),
        ecdh_pubkey_hex: ecdh_pubkey.to_string(),
    }
    .normalized()
    .map_err(|err| anyhow!("invalid DKG peer identity: {err}"))
}

fn read_peer_files_with_own(
    own_peer: &DkgPeerIdentity,
    peer_files: &[PathBuf],
) -> Result<Vec<DkgPeerIdentity>> {
    let mut peers = vec![own_peer
        .clone()
        .normalized()
        .map_err(|err| anyhow!("invalid own peer identity: {err}"))?];
    for path in peer_files {
        let peer: DkgPeerIdentity = read_json_file(path)?;
        let peer = peer
            .normalized()
            .map_err(|err| anyhow!("invalid peer identity {}: {err}", path.display()))?;
        if let Some(existing) = peers
            .iter()
            .find(|existing| existing.signer_id == peer.signer_id)
        {
            if existing != &peer {
                return Err(anyhow!(
                    "conflicting DKG peer identity for signer {}",
                    peer.signer_id
                ));
            }
            continue;
        }
        peers.push(peer);
    }
    Ok(peers)
}

fn read_spend_plan_file(path: &Path) -> Result<VaultSpendPlan> {
    let json = read_bounded_regular_text_file(path, "vault spend plan", MAX_JSON_INPUT_FILE_BYTES)?;
    if let Ok(plan) = serde_json::from_str::<VaultSpendPlan>(&json) {
        return Ok(plan);
    }
    let value: serde_json::Value = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse vault spend plan {}", path.display()))?;
    let plan_value = value
        .get("plan")
        .cloned()
        .ok_or_else(|| anyhow!("expected VaultSpendPlan JSON or object with a plan field"))?;
    serde_json::from_value(plan_value)
        .with_context(|| format!("failed to parse plan field from {}", path.display()))
}

struct RealFrostSigningPolicyContext<'a> {
    bitcoin_client: &'a BitcoinRpcClient,
    min_confirmations: u32,
    datadir: &'a Path,
    current_height: Option<u64>,
    next_dkg_transcript_file: Option<&'a Path>,
}

async fn validate_real_frost_signing_policy(
    state: &RealFrostDkgState,
    spend_plan: &VaultSpendPlan,
    input_sighashes: &[String],
    context: RealFrostSigningPolicyContext<'_>,
) -> Result<()> {
    let current_epoch = real_frost_epoch_from_state(state)?;
    context
        .bitcoin_client
        .revalidate_vault_spend_plan_inputs(spend_plan, context.min_confirmations)
        .await
        .context(
            "real FROST signing refused because local Bitcoin RPC did not validate vault inputs",
        )?;
    if spend_plan.withdrawal_batch.is_some() {
        let current_height = context.current_height.ok_or_else(|| {
            anyhow!(
                "real FROST withdrawal signing requires --current-height so local replay can reject expired or overdrawn claims"
            )
        })?;
        let replay_state = local_node::replay_state(context.datadir).with_context(|| {
            format!(
                "failed to replay local sharechain state from {} before withdrawal signing",
                context.datadir.display()
            )
        })?;
        if let Some(best_share_height) = replay_state.best_share_height() {
            if current_height < best_share_height {
                return Err(anyhow!(
                    "real FROST withdrawal signing current height {} is behind local sharechain best height {}; refusing stale expiry check",
                    current_height,
                    best_share_height
                ));
            }
        }
        VaultSigningSession::new_with_reserved_withdrawals(
            &current_epoch,
            spend_plan.clone(),
            input_sighashes.to_vec(),
            &replay_state,
            current_height,
        )
        .context("real FROST withdrawal signing refused by local ledger policy")?;
    } else {
        VaultSigningSession::new(&current_epoch, spend_plan.clone(), input_sighashes.to_vec())
            .context("real FROST signing refused by local vault policy")?;
    }

    if let Some(remainder) = &spend_plan.vault_remainder {
        if matches!(remainder.kind, VaultRemainderKind::NextEpochRotation) {
            let transcript_path = context.next_dkg_transcript_file.ok_or_else(|| {
                anyhow!(
                    "real FROST vault rotation signing requires --next-dkg-transcript-file for the destination epoch"
                )
            })?;
            let transcript: DkgTranscript = read_json_file(transcript_path)?;
            let transcript = transcript.normalized().with_context(|| {
                format!(
                    "next DKG transcript {} is invalid",
                    transcript_path.display()
                )
            })?;
            if transcript.epoch_id != remainder.epoch_id {
                return Err(anyhow!(
                    "next DKG transcript epoch {} does not match rotation target epoch {}",
                    transcript.epoch_id,
                    remainder.epoch_id
                ));
            }
            if transcript.frost_group_key_xonly
                != remainder.frost_group_key_xonly.to_ascii_lowercase()
            {
                return Err(anyhow!(
                    "next DKG transcript key {} does not match rotation target key {}",
                    transcript.frost_group_key_xonly,
                    remainder.frost_group_key_xonly
                ));
            }
        }
    }

    Ok(())
}

fn real_frost_epoch_from_state(state: &RealFrostDkgState) -> Result<VaultEpoch> {
    let state = state.clone().normalized()?;
    Ok(VaultEpoch {
        epoch_id: state.epoch_id,
        starts_at: Utc::now(),
        signer_ids: state.signer_ids.clone(),
        threshold: state.threshold,
        frost_group_key_xonly: Some(
            state
                .frost_group_key_xonly
                .clone()
                .ok_or_else(|| anyhow!("real FROST signer state has no finalized group key"))?,
        ),
        dkg_transcript_hash: None,
        dkg_public_key_package_hash: Some(
            state
                .public_key_package_hash
                .clone()
                .ok_or_else(|| anyhow!("real FROST signer state has no public key package hash"))?,
        ),
        frost_signer_bindings: state.signer_bindings()?,
    })
}

fn read_frost_commitment_files(paths: &[PathBuf]) -> Result<Vec<RealFrostSigningCommitment>> {
    if paths.is_empty() {
        return Err(anyhow!("at least one --commitments-file is required"));
    }
    let mut commitments = Vec::new();
    for path in paths {
        let value: serde_json::Value = read_json_file(path)?;
        if let Ok(items) = serde_json::from_value::<Vec<RealFrostSigningCommitment>>(value.clone())
        {
            commitments.extend(items);
        } else {
            commitments.push(
                serde_json::from_value::<RealFrostSigningCommitment>(value).with_context(|| {
                    format!("failed to parse FROST commitments {}", path.display())
                })?,
            );
        }
    }
    Ok(commitments)
}

fn read_frost_share_files(paths: &[PathBuf]) -> Result<Vec<FrostSignatureShare>> {
    if paths.is_empty() {
        return Err(anyhow!("at least one --shares-file is required"));
    }
    let mut shares = Vec::new();
    for path in paths {
        let value: serde_json::Value = read_json_file(path)?;
        if let Ok(items) = serde_json::from_value::<Vec<FrostSignatureShare>>(value.clone()) {
            shares.extend(items);
        } else {
            shares.push(
                serde_json::from_value::<FrostSignatureShare>(value)
                    .with_context(|| format!("failed to parse FROST shares {}", path.display()))?,
            );
        }
    }
    Ok(shares)
}

fn sharechain_message_type(message: &SharechainMessage) -> &'static str {
    match message {
        SharechainMessage::MinerRegistration(_) => "MinerRegistration",
        SharechainMessage::BitcoinWorkTemplate(_) => "BitcoinWorkTemplate",
        SharechainMessage::Share(_) => "Share",
        SharechainMessage::SnapshotVote(_) => "SnapshotVote",
        SharechainMessage::PayoutSchedule(_) => "PayoutSchedule",
        SharechainMessage::WithdrawalRequest(_) => "WithdrawalRequest",
        SharechainMessage::WithdrawalBatch(_) => "WithdrawalBatch",
        SharechainMessage::PohwCommitment(_) => "PohwCommitment",
    }
}

fn read_gossip_envelope_file(path: &Path) -> Result<GossipEnvelope> {
    let json =
        read_bounded_regular_text_file(path, "gossip envelope file", MAX_JSON_INPUT_FILE_BYTES)?;
    serde_json::from_str(&json)
        .with_context(|| format!("failed to parse gossip envelope {}", path.display()))
}

fn verified_miner_registration_from_envelope(
    envelope: &GossipEnvelope,
    max_future_skew_seconds: i64,
    max_age_seconds: i64,
) -> Result<&MinerRegistration> {
    envelope.verify_at(
        current_unix_timestamp()?,
        max_future_skew_seconds,
        max_age_seconds,
    )?;
    match &envelope.message {
        SharechainMessage::MinerRegistration(registration) => {
            registration.verify_mining_signature()?;
            registration.verify_idena_ownership_signature()?;
            Ok(registration)
        }
        other => Err(anyhow!(
            "expected MinerRegistration envelope, got {}",
            sharechain_message_type(other)
        )),
    }
}

pub(crate) fn read_keypair_from_file(path: &Path) -> Result<Keypair> {
    let secret_key = read_secret_key_from_file(path)?;
    Ok(Keypair::from_secret_key(
        &bitcoin::key::Secp256k1::new(),
        &secret_key,
    ))
}

fn read_secret_key_from_file(path: &Path) -> Result<SecretKey> {
    validate_secret_key_file(path)?;
    let raw = read_bounded_regular_text_file(path, "secret key file", MAX_SECRET_KEY_FILE_BYTES)?;
    parse_secret_key_hex(raw.trim())
}

fn parse_secret_key_hex(raw: &str) -> Result<SecretKey> {
    let value = raw.strip_prefix("0x").unwrap_or(raw);
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "secret key must be 32 bytes encoded as 64 hex characters"
        ));
    }
    let bytes = hex::decode(value)?;
    SecretKey::from_slice(&bytes).map_err(|err| anyhow!("invalid secp256k1 secret key: {err}"))
}

pub(crate) fn sign_hash_hex(hash: [u8; 32], keypair: &Keypair) -> String {
    let secp = bitcoin::key::Secp256k1::new();
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash), keypair);
    hex::encode(signature.serialize())
}

pub(crate) fn current_unix_timestamp() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(duration.as_secs()).context("system timestamp does not fit in i64")
}

pub(crate) fn random_nonce_hex() -> String {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn validate_secret_key_file(path: &Path) -> Result<()> {
    validate_protected_secret_file(path, "secret key")
}

pub(crate) fn validate_protected_secret_file(path: &Path, label: &str) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect {label} file directory {}",
                parent.display()
            )
        })?;
        validate_existing_private_file_parent(parent, &parent_metadata).with_context(|| {
            format!(
                "failed to validate {label} file directory {}",
                parent.display()
            )
        })?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "{label} file {} must not be a symlink",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "{label} path {} must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "{label} file {} is too permissive ({mode:o}); run chmod 600 {}",
                path.display(),
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("{label}-{}", random_nonce_hex()));
        std::fs::create_dir_all(&path).expect("create test dir");
        path
    }

    fn test_keypair(byte: u8) -> Keypair {
        let secret_key = SecretKey::from_slice(&[byte; 32]).expect("valid test key");
        Keypair::from_secret_key(&bitcoin::key::Secp256k1::new(), &secret_key)
    }

    fn signed_test_withdrawal_request(
        request_id: &str,
        amount_sats: u64,
        nonce: u64,
        claim_owner_keypair: &Keypair,
    ) -> WithdrawalRequest {
        let claim_owner_pubkey_hex = claim_owner_keypair.x_only_public_key().0.to_string();
        let mut request = WithdrawalRequest {
            request_id: request_id.to_string(),
            claim_owner_id: claim_owner_pubkey_hex.clone(),
            claim_owner_pubkey_hex,
            destination_script_hex:
                "51200000000000000000000000000000000000000000000000000000000000000000".to_string(),
            amount_sats,
            max_fee_rate_sat_vb: 10,
            nonce,
            expiry_height: 100,
            signature_hex: None,
            output_kind: WithdrawalOutputKind::P2tr,
        };
        request.signature_hex = Some(sign_hash_hex(request.signing_hash(), claim_owner_keypair));
        request
    }

    fn state_with_claim_and_request(
        request: WithdrawalRequest,
        balance_sats: u64,
    ) -> SharechainReplayState {
        let mut state = SharechainReplayState::default();
        let mut ledger = pohw_core::ledger::ClaimLedger::default();
        ledger
            .apply_vault_allocation(&pohw_core::payout::VaultAllocation {
                miner_id: request.claim_owner_id.clone(),
                claim_owner_id: request.claim_owner_id.clone(),
                amount_sats: balance_sats,
            })
            .expect("credit claim");
        state.replace_claim_ledger(ledger);
        state
            .apply_message(&SharechainMessage::WithdrawalRequest(request))
            .expect("accept withdrawal request");
        state
    }

    fn test_withdrawal_epoch() -> VaultEpoch {
        demo_epoch(42, 3, &demo_xonly_key(7))
    }

    fn test_vault_input(amount_sats: u64, epoch: &VaultEpoch) -> VaultInput {
        let frost_key = epoch.required_group_key().expect("epoch group key");
        VaultInput {
            txid: "11".repeat(32),
            vout: 0,
            amount_sats,
            confirmations: MIN_VAULT_INPUT_CONFIRMATIONS,
            script_pubkey_hex: vault_script_pubkey_hex(&frost_key).expect("vault script"),
        }
    }

    #[test]
    fn bare_relative_paths_have_no_parent_directory_to_create() {
        assert!(non_empty_parent(Path::new("artifact.json")).is_none());
        assert_eq!(
            non_empty_parent(Path::new("out/artifact.json")),
            Some(Path::new("out"))
        );
    }

    #[test]
    fn fork_activation_cli_parsers_accept_canonical_values() {
        let timestamp = parse_utc_datetime_arg("launch-timestamp-utc", "2026-07-05T00:00:00Z")
            .expect("timestamp");

        assert_eq!(timestamp.to_rfc3339(), "2026-07-05T00:00:00+00:00");
        assert_eq!(
            validate_fork_chain_name("pohw-experiment-0").expect("chain name"),
            "pohw-experiment-0"
        );
        assert_eq!(
            parse_compact_bits_arg("post-fork-pow-limit-bits", "0x207fffff").expect("bits"),
            0x207f_ffff
        );
    }

    #[test]
    fn fork_activation_cli_parsers_reject_ambiguous_values() {
        assert!(validate_fork_chain_name(" pohw").is_err());
        assert!(validate_fork_chain_name("pohw experiment").is_err());
        assert!(parse_compact_bits_arg("post-fork-pow-limit-bits", "207fff").is_err());
        assert!(parse_utc_datetime_arg("launch-timestamp-utc", "2026-07-05").is_err());
    }

    #[test]
    fn default_parent_share_hash_uses_zero_for_empty_node() {
        let dir = test_dir("pohw-default-parent-empty");

        assert_eq!(
            default_parent_share_hash(&dir).unwrap(),
            zero_share_parent_hash()
        );

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn withdrawal_spend_plan_reserves_confirmed_claims_and_vault_change() {
        let claim_owner_keypair = test_keypair(10);
        let request = signed_test_withdrawal_request("withdraw-1", 20_000, 1, &claim_owner_keypair);
        let state = state_with_claim_and_request(request.clone(), 50_000);
        let epoch = test_withdrawal_epoch();
        let input = test_vault_input(50_000, &epoch);

        let result =
            build_verified_withdrawal_spend_plan(&state, &epoch, vec![request], vec![input], 1, 1)
                .expect("build withdrawal spend plan");

        assert_eq!(result.request_count, 1);
        assert_eq!(result.input_count, 1);
        assert_eq!(result.input_total_sats, 50_000);
        assert_eq!(result.withdrawal_gross_total_sats, 20_000);
        assert_eq!(result.withdrawal_fee_sats, 111);
        assert_eq!(result.withdrawal_net_total_sats, 19_889);
        assert_eq!(result.vault_change_sats, 30_000);
        assert_eq!(result.output_count, 2);
        assert_eq!(result.input_sighashes.len(), 1);
        assert!(!result.withdrawal_batch_already_reserved);
        assert_eq!(result.spend_plan_hash, result.plan.plan_hash());
        assert_eq!(
            result.withdrawal_batch_hash,
            result.plan.withdrawal_batch.unwrap().batch_hash()
        );
    }

    #[test]
    fn withdrawal_spend_plan_can_be_rebuilt_after_batch_is_pending() {
        let claim_owner_keypair = test_keypair(13);
        let request = signed_test_withdrawal_request("withdraw-1", 20_000, 1, &claim_owner_keypair);
        let mut state = state_with_claim_and_request(request.clone(), 50_000);
        let batch = build_withdrawal_batch(vec![request.clone()], 1, 1, 1).unwrap();
        state
            .apply_message(&SharechainMessage::WithdrawalBatch(batch.clone()))
            .expect("accept pending withdrawal batch");
        let epoch = test_withdrawal_epoch();
        let input = test_vault_input(50_000, &epoch);

        let result =
            build_verified_withdrawal_spend_plan(&state, &epoch, vec![request], vec![input], 1, 1)
                .expect("rebuild withdrawal spend plan");

        assert!(result.withdrawal_batch_already_reserved);
        assert_eq!(result.withdrawal_batch_hash, batch.batch_hash());
    }

    #[test]
    fn withdrawal_spend_plan_rejects_request_not_in_local_replay() {
        let dir = test_dir("pohw-withdrawal-unreplayed");
        let claim_owner_keypair = test_keypair(11);
        let request = signed_test_withdrawal_request("withdraw-1", 20_000, 1, &claim_owner_keypair);
        let request_path = dir.join("request.json");
        write_json_file(&request_path, &request).expect("write request");
        let state = SharechainReplayState::default();

        let err = select_withdrawal_requests(&state, &[], &[request_path]).unwrap_err();

        assert!(
            err.to_string()
                .contains("not present in local sharechain replay"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn withdrawal_replay_rejects_overdrawn_claim_requests() {
        let claim_owner_keypair = test_keypair(12);
        let request = signed_test_withdrawal_request("withdraw-1", 40_000, 1, &claim_owner_keypair);
        let mut state = SharechainReplayState::default();
        let mut ledger = pohw_core::ledger::ClaimLedger::default();
        ledger
            .apply_vault_allocation(&pohw_core::payout::VaultAllocation {
                miner_id: request.claim_owner_id.clone(),
                claim_owner_id: request.claim_owner_id.clone(),
                amount_sats: 30_000,
            })
            .expect("credit claim");
        state.replace_claim_ledger(ledger);

        let err = state
            .apply_message(&SharechainMessage::WithdrawalRequest(request.clone()))
            .unwrap_err();

        assert!(matches!(
            err,
            pohw_core::sharechain_state::SharechainReplayError::Ledger(
                pohw_core::ledger::LedgerError::InsufficientBalance {
                    claim_owner_id,
                    requested_sats: 40_000,
                    available_sats: 30_000,
                }
            ) if claim_owner_id == request.claim_owner_id
        ));
    }

    fn test_payout_candidate(block_hash: &str) -> PayoutConfirmationCandidate {
        PayoutConfirmationCandidate {
            block_hash: block_hash.to_string(),
            snapshot_file: PathBuf::from("../snapshot.json"),
            payout_schedule_file: PathBuf::from("../payout-schedule.json"),
            pohw_commitment_file: PathBuf::from("../pohw-commitment.json"),
            reward_sats: Some(312_500_000),
            direct_limit: Some(50),
            min_direct_payout_sats: Some(10_000),
            min_confirmations: Some(6),
        }
    }

    fn test_stratum_job(bits: &str) -> mining_adapter::StratumJob {
        let material = bitcoin_rpc::BitcoinMiningJobTemplate {
            version: 0x2000_0000,
            previous_block_hash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_string(),
            curtime: 0x0102_0304,
            bits: bits.to_string(),
            height: 840_000,
            coinbase_value_sats: 50_000,
            transaction_hashes: Vec::new(),
            transactions: Vec::new(),
            default_witness_commitment: None,
        };
        mining_adapter::build_stratum_job_from_template(&material, 4)
            .expect("build test Stratum job")
            .job
    }

    fn test_submittable_stratum_block_candidate() -> mining_adapter::StratumBlockCandidate {
        let job = test_stratum_job("207fffff");
        for nonce in 0..1024u32 {
            let nonce_hex = hex::encode(nonce.to_le_bytes());
            let candidate = mining_adapter::build_stratum_block_candidate(
                &job, "aabbccdd", "01020304", &job.ntime, &nonce_hex, 4, false,
            )
            .expect("build candidate");
            if candidate.meets_block_target {
                return candidate;
            }
        }
        panic!("test did not find a target-meeting regtest candidate");
    }

    fn test_non_target_stratum_block_candidate() -> mining_adapter::StratumBlockCandidate {
        let job = test_stratum_job("01010000");
        let candidate = mining_adapter::build_stratum_block_candidate(
            &job, "aabbccdd", "01020304", &job.ntime, "05060708", 4, false,
        )
        .expect("build candidate");
        assert!(!candidate.meets_block_target);
        candidate
    }

    #[test]
    fn candidate_submission_requires_complete_target_meeting_artifact() {
        let valid = test_submittable_stratum_block_candidate();
        assert_eq!(
            block_hex_for_stratum_candidate_submission(&valid).unwrap(),
            valid.block_hex.as_deref().unwrap()
        );

        let err =
            block_hex_for_stratum_candidate_submission(&test_non_target_stratum_block_candidate())
                .unwrap_err();
        assert!(err.to_string().contains("does not meet"));

        let mut incomplete = valid.clone();
        incomplete.block_hex_status =
            "incomplete_missing_non_coinbase_transaction_data".to_string();
        incomplete.block_hex = None;
        let err = block_hex_for_stratum_candidate_submission(&incomplete).unwrap_err();
        assert!(err.to_string().contains("only complete block_hex"));

        let mut missing_block = valid.clone();
        missing_block.block_hex = None;
        let err = block_hex_for_stratum_candidate_submission(&missing_block).unwrap_err();
        assert!(err.to_string().contains("has no complete block_hex"));

        let mut tampered = valid;
        tampered.block_hash = "aa".repeat(32);
        let err = block_hex_for_stratum_candidate_submission(&tampered).unwrap_err();
        assert!(err.to_string().contains("does not match recomputed"));
    }

    #[test]
    fn candidate_submission_rejects_mainnet_without_override() {
        let chain_info = BlockchainInfoResponse {
            chain: "main".to_string(),
            blocks: 1,
            headers: 1,
            initial_block_download: false,
            verificationprogress: 1.0,
            pruned: false,
        };

        let err = ensure_candidate_submit_chain_allowed(&chain_info, false).unwrap_err();
        assert!(err.to_string().contains("--allow-mainnet-submit"));
        assert!(ensure_candidate_submit_chain_allowed(&chain_info, true).is_ok());

        let mut regtest = chain_info;
        regtest.chain = "regtest".to_string();
        assert!(ensure_candidate_submit_chain_allowed(&regtest, false).is_ok());
    }

    #[test]
    fn payout_candidate_paths_resolve_relative_to_candidate_file() {
        let candidate_file = Path::new("/tmp/pohw/candidates/block-1.json");

        assert_eq!(
            resolve_payout_candidate_path(candidate_file, Path::new("../snapshot.json")),
            PathBuf::from("/tmp/pohw/candidates/../snapshot.json")
        );
        assert_eq!(
            resolve_payout_candidate_path(candidate_file, Path::new("/var/pohw/snapshot.json")),
            PathBuf::from("/var/pohw/snapshot.json")
        );
    }

    #[test]
    fn payout_candidate_discovery_sorts_json_files_and_skips_noise() {
        let dir = test_dir("pohw-payout-candidates");
        std::fs::write(dir.join("b.json"), "{}\n").expect("write b");
        std::fs::write(dir.join("a.json"), "{}\n").expect("write a");
        std::fs::write(dir.join("notes.txt"), "{}\n").expect("write text");
        std::fs::create_dir(dir.join("nested")).expect("create nested");

        let files = discover_payout_confirmation_candidate_files(&dir, 10)
            .expect("discover candidate files");

        assert_eq!(files, vec![dir.join("a.json"), dir.join("b.json")]);
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn payout_candidate_discovery_rejects_symlink_directory() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-payout-candidate-dir-link");
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::create_dir(&target).expect("create target");
        symlink(&target, &link).expect("create symlink");

        let err = discover_payout_confirmation_candidate_files(&link, 10).unwrap_err();

        assert!(
            err.to_string().contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn payout_candidate_reader_parses_strict_schema() {
        let dir = test_dir("pohw-payout-candidate-read");
        let path = dir.join("candidate.json");
        let block_hash = "aa".repeat(32);
        let candidate = test_payout_candidate(&block_hash);
        write_json_file(&path, &candidate).expect("write candidate");

        let parsed = read_payout_confirmation_candidate_file(&path).expect("read candidate");

        assert_eq!(parsed, candidate);
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn payout_candidate_reader_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-payout-candidate-file-link");
        let target = dir.join("target.json");
        let link = dir.join("candidate.json");
        std::fs::write(&target, "{}\n").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = read_payout_confirmation_candidate_file(&link).unwrap_err();

        assert!(
            err.to_string().contains("not a regular file"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn json_reader_rejects_symlink_file() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-json-file-link");
        let target = dir.join("target.json");
        let link = dir.join("input.json");
        std::fs::write(&target, "{}\n").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = read_json_file::<serde_json::Value>(&link).unwrap_err();

        assert!(
            err.to_string().contains("not a regular file"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn payout_candidate_reward_sats_cannot_override_command_expectation() {
        let block_hash = "aa".repeat(32);
        let candidate = test_payout_candidate(&block_hash);
        let defaults = PayoutConfirmerDefaults {
            reward_sats: Some(1),
            direct_limit: 50,
            min_direct_payout_sats: 10_000,
            min_confirmations: 6,
            max_candidates: 10,
        };

        let err = payout_candidate_expected_reward_sats(&candidate, defaults).unwrap_err();

        assert!(
            err.to_string().contains("conflicts"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn payout_candidate_reader_rejects_large_files() {
        let dir = test_dir("pohw-payout-candidate-large");
        let path = dir.join("candidate.json");
        std::fs::write(
            &path,
            " ".repeat((MAX_PAYOUT_CONFIRMATION_CANDIDATE_BYTES + 1) as usize),
        )
        .expect("write large candidate");

        let err = read_payout_confirmation_candidate_file(&path).unwrap_err();

        assert!(
            err.to_string().contains("maximum"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn json_reader_rejects_large_files() {
        let dir = test_dir("pohw-json-large");
        let path = dir.join("input.json");
        std::fs::File::create(&path)
            .expect("create large JSON")
            .set_len(MAX_JSON_INPUT_FILE_BYTES + 1)
            .expect("resize large JSON");

        let err = read_json_file::<serde_json::Value>(&path).unwrap_err();

        assert!(
            err.to_string().contains("maximum"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn payout_schedule_reader_rejects_large_files() {
        let dir = test_dir("pohw-payout-schedule-large");
        let path = dir.join("payout-schedule.json");
        std::fs::write(
            &path,
            " ".repeat((MAX_PAYOUT_SCHEDULE_FILE_BYTES + 1) as usize),
        )
        .expect("write large schedule");

        let err = read_payout_schedule_file(&path).unwrap_err();

        assert!(
            err.to_string().contains("maximum"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn payout_candidate_discovery_limits_batch_size() {
        let dir = test_dir("pohw-payout-candidate-limit");
        std::fs::write(dir.join("a.json"), "{}\n").expect("write a");
        std::fs::write(dir.join("b.json"), "{}\n").expect("write b");

        let err = discover_payout_confirmation_candidate_files(&dir, 1).unwrap_err();

        assert!(
            err.to_string().contains("--max-candidates"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    fn default_work_template_flags() -> PublishBitcoinWorkTemplateFlags {
        PublishBitcoinWorkTemplateFlags {
            append: false,
            accept_locally: false,
            validate_with_bitcoin_rpc: false,
            allow_unverified_local_accept: false,
            has_expected_header_merkle_root: false,
            allow_unverified_merkle_root: false,
            allow_mutable_time: false,
        }
    }

    #[test]
    fn publish_bitcoin_work_template_append_requires_local_accept() {
        let mut flags = default_work_template_flags();
        flags.append = true;

        let err = validate_publish_bitcoin_work_template_flags(flags).unwrap_err();

        assert!(
            err.to_string().contains("--accept-locally"),
            "unexpected error: {err:#}"
        );

        flags.accept_locally = true;
        flags.allow_unverified_local_accept = true;
        validate_publish_bitcoin_work_template_flags(flags)
            .expect("append is valid after local accept");
    }

    #[test]
    fn public_json_writer_refuses_existing_destination() {
        let dir = test_dir("pohw-public-json-existing");
        let path = dir.join("artifact.json");

        write_json_file(&path, &serde_json::json!({ "version": 1 })).expect("first write");
        let err = write_json_file(&path, &serde_json::json!({ "version": 2 })).unwrap_err();

        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err:#}"
        );
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read artifact"))
                .expect("parse artifact");
        assert_eq!(written["version"], 1);

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn replace_json_writer_replaces_regular_file_in_private_parent() {
        let dir = test_dir("pohw-replace-json-existing");
        let path = dir.join("artifact.json");
        std::fs::write(&path, "{\"version\":1}\n").expect("write original");

        write_json_file_replace_existing_regular(&path, &serde_json::json!({ "version": 2 }))
            .expect("replace artifact");

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read artifact"))
                .expect("parse artifact");
        assert_eq!(written["version"], 2);

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn replace_json_writer_rejects_group_or_world_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("pohw-replace-json-writable-parent");
        let path = dir.join("artifact.json");
        std::fs::write(&path, "{\"version\":1}\n").expect("write original");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("set parent mode");

        let err =
            write_json_file_replace_existing_regular(&path, &serde_json::json!({ "version": 2 }))
                .unwrap_err();

        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "unexpected error: {err:#}"
        );
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read artifact"))
                .expect("parse artifact");
        assert_eq!(written["version"], 1);

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn staged_public_json_survives_publish_race() {
        let dir = test_dir("pohw-public-json-publish-race");
        let path = dir.join("artifact.json");
        let staged =
            stage_json_file(&path, &serde_json::json!({ "version": 2 })).expect("stage artifact");
        let tmp_path = staged.tmp_path.clone();
        std::fs::write(&path, "{\"version\":1}\n").expect("race destination into place");

        let err = staged.publish().unwrap_err();

        assert!(
            err.to_string().contains("failed to publish JSON"),
            "unexpected error: {err:#}"
        );
        assert!(
            tmp_path.exists(),
            "staged artifact should remain for manual recovery"
        );
        let staged_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&tmp_path).expect("read staged"))
                .expect("parse staged");
        assert_eq!(staged_value["version"], 2);

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn public_json_writer_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-public-json-symlink");
        let target = dir.join("target.json");
        let link = dir.join("artifact.json");
        std::fs::write(&target, "{\"version\":1}\n").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = write_json_file(&link, &serde_json::json!({ "version": 2 })).unwrap_err();

        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err:#}"
        );
        let target: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&target).expect("read target"))
                .expect("parse target");
        assert_eq!(target["version"], 1);

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn public_json_writer_refuses_symlink_ancestor_directory() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-public-json-symlink-ancestor");
        let real = dir.join("real");
        let child = real.join("child");
        let link = dir.join("link");
        std::fs::create_dir_all(&child).expect("create child");
        symlink(&real, &link).expect("create symlink");
        let path = link.join("child").join("artifact.json");

        let err = write_json_file(&path, &serde_json::json!({ "version": 2 })).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        assert!(!child.join("artifact.json").exists());

        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    fn unix_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .expect("stat path")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn private_file_writer_does_not_chmod_existing_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("pohw-private-existing-parent");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("set parent mode");
        let key_path = dir.join("node.key");
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid test key");

        write_secret_key_file(&key_path, &secret_key).expect("write secret key");

        assert_eq!(unix_mode(&dir), 0o755);
        assert_eq!(unix_mode(&key_path), 0o600);
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_writer_rejects_group_or_world_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("pohw-private-writable-parent");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("set parent mode");
        let key_path = dir.join("node.key");
        let secret_key = SecretKey::from_slice(&[3; 32]).expect("valid test key");

        let err = write_secret_key_file(&key_path, &secret_key).unwrap_err();

        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "unexpected error: {err:#}"
        );
        assert!(!key_path.exists());
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_reader_rejects_group_or_world_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("pohw-private-readable-writable-parent");
        let key_path = dir.join("node.key");
        let secret_key = SecretKey::from_slice(&[4; 32]).expect("valid test key");
        std::fs::write(&key_path, hex::encode(secret_key.secret_bytes())).expect("write key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("set key mode");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("set parent mode");

        let err = read_secret_key_from_file(&key_path).unwrap_err();

        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "unexpected error: {err:#}"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore parent mode for cleanup");
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn secret_key_file_rejects_large_files_before_reading() {
        let dir = test_dir("pohw-secret-key-large-file");
        let key_path = dir.join("node.key");
        std::fs::File::create(&key_path)
            .expect("create secret key")
            .set_len(MAX_SECRET_KEY_FILE_BYTES + 1)
            .expect("resize secret key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("set key mode");
        }

        let err = read_secret_key_from_file(&key_path).unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum is 68"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_writer_rejects_symlink_ancestor_directory() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("pohw-private-writer-symlink-ancestor");
        let real = dir.join("real");
        let child = real.join("child");
        let link = dir.join("link");
        std::fs::create_dir_all(&child).expect("create child");
        symlink(&real, &link).expect("create symlink");
        let key_path = link.join("child").join("node.key");
        let secret_key = SecretKey::from_slice(&[5; 32]).expect("valid test key");

        let err = write_secret_key_file(&key_path, &secret_key).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        assert!(!child.join("node.key").exists());
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_reader_rejects_symlink_ancestor_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = test_dir("pohw-private-reader-symlink-ancestor");
        let real = dir.join("real");
        let child = real.join("child");
        let link = dir.join("link");
        std::fs::create_dir_all(&child).expect("create child");
        symlink(&real, &link).expect("create symlink");
        let real_key_path = child.join("node.key");
        let secret_key = SecretKey::from_slice(&[6; 32]).expect("valid test key");
        std::fs::write(&real_key_path, hex::encode(secret_key.secret_bytes())).expect("write key");
        std::fs::set_permissions(&real_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("set key mode");

        let err = read_secret_key_from_file(&link.join("child").join("node.key")).unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[test]
    fn optional_secret_validation_rejects_large_or_control_values() {
        let too_long = "a".repeat(MAX_OPTIONAL_SECRET_BYTES + 1);
        let err = read_optional_secret(Some(too_long), None, "dashboard API token").unwrap_err();
        assert!(
            format!("{err:#}").contains("must be 1-512 bytes"),
            "unexpected error: {err:#}"
        );

        let err = read_optional_secret(Some("good\nbad".to_string()), None, "Bitcoin RPC password")
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("must not contain control characters"),
            "unexpected error: {err:#}"
        );

        let password = read_optional_secret(
            Some(" bitcoin rpc password with spaces ".to_string()),
            None,
            "Bitcoin RPC password",
        )
        .expect("valid password")
        .expect("password present");
        assert_eq!(password, "bitcoin rpc password with spaces");
    }

    #[test]
    fn optional_secret_file_rejects_large_files_before_reading() {
        let dir = test_dir("pohw-optional-secret-large-file");
        let path = dir.join("dashboard.token");
        std::fs::File::create(&path)
            .expect("create token")
            .set_len(MAX_OPTIONAL_SECRET_FILE_BYTES + 1)
            .expect("resize token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set token mode");
        }

        let err =
            read_optional_secret(None, Some(path.clone()), "dashboard API token").unwrap_err();

        assert!(
            format!("{err:#}").contains("maximum is 514"),
            "unexpected error: {err:#}"
        );
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_writer_chmods_only_new_directories() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("pohw-private-new-parent");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("set base mode");
        let created = dir.join("created");
        let nested = created.join("nested");
        let key_path = nested.join("node.key");
        let secret_key = SecretKey::from_slice(&[2; 32]).expect("valid test key");

        write_secret_key_file(&key_path, &secret_key).expect("write secret key");

        assert_eq!(unix_mode(&dir), 0o755);
        assert_eq!(unix_mode(&created), 0o700);
        assert_eq!(unix_mode(&nested), 0o700);
        assert_eq!(unix_mode(&key_path), 0o600);
        std::fs::remove_dir_all(dir).expect("cleanup test dir");
    }
}
