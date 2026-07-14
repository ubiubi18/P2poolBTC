use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::lookup_host;

use crate::bootstrap::{is_public_ip, LaunchPhase, SnapshotPinV1, SourceJoinManifestV1};
use crate::files::{
    atomic_replace_private, ensure_private_dir, install_private_if_absent, is_link_like,
    private_log_file, read_limited_regular,
};

const MAX_CHILD_JSON_BYTES: usize = 1024 * 1024;
const CHILD_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub status: String,
    pub miner_id: String,
    pub idena_address: String,
    pub idena_ownership_challenge: String,
    pub registration_binding_hash: String,
    pub mining_pubkey_hex: String,
    pub claim_owner_pubkey_hex: String,
    pub btc_payout_script_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    pub status: String,
    pub miner_id: String,
    pub idena_address: String,
    pub message_hash: String,
    pub envelope_hash: String,
    pub registration_binding_hash: String,
    pub mining_pubkey_hex: String,
    pub claim_owner_pubkey_hex: String,
    pub btc_payout_script_hex: String,
    pub gossip_delivery: Vec<GossipDelivery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipDelivery {
    pub endpoint: String,
    pub delivered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedForkPeers {
    pub rpc: Vec<SocketAddr>,
    pub p2p: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MiningSnapshotEvidence {
    schema_version: String,
    snapshot_id: String,
    proof_root: String,
    source_height: u64,
    distinct_voter_count: u32,
    miner_id: Option<String>,
    miner_eligible: Option<bool>,
    identity_status: Option<String>,
}

impl MiningSnapshotEvidence {
    pub fn snapshot_pin(&self) -> SnapshotPinV1 {
        SnapshotPinV1 {
            snapshot_id: self.snapshot_id.clone(),
            proof_root: self.proof_root.clone(),
            source_height: self.source_height,
            distinct_voter_count: self.distinct_voter_count,
        }
    }
}

pub struct MiningAdapterLaunch<'a> {
    pub descriptor: &'a SourceJoinManifestV1,
    pub activation_manifest: &'a Path,
    pub miner_id: &'a str,
    pub stratum_bind: SocketAddr,
    pub stratum_password_file: &'a Path,
    pub gossip_peers: &'a [SocketAddr],
    pub fork_rpc_addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct RegistrationReadyOutput {
    status: String,
    miner_id: String,
    idena_address: String,
    message_hash: String,
    envelope_hash: String,
    registration_binding_hash: String,
    mining_pubkey_hex: String,
    claim_owner_pubkey_hex: String,
    btc_payout_script_hex: String,
}

#[derive(Debug, Deserialize)]
struct VerifiedRegistrationEnvelopeOutput {
    valid: bool,
    envelope_hash: String,
    peer_pubkey_xonly_hex: String,
    message_hash: String,
    registration_binding_hash: String,
    miner_registration: VerifiedRegistrationFields,
}

#[derive(Debug, Deserialize)]
struct VerifiedRegistrationFields {
    miner_id: String,
    idena_address: String,
    btc_payout_script_hex: String,
    claim_owner_pubkey_hex: String,
    mining_pubkey_hex: String,
}

#[derive(Debug, Clone)]
pub struct NodeDriver {
    binary: PathBuf,
    binary_sha256: String,
    datadir: PathBuf,
    allow_private_peers: bool,
}

impl NodeDriver {
    pub fn new(
        binary: PathBuf,
        expected_binary_sha256: String,
        datadir: PathBuf,
        allow_private_peers: bool,
    ) -> Result<Self> {
        validate_binary(&binary)?;
        let actual = hash_file(&binary)?;
        if actual != expected_binary_sha256 {
            bail!(
                "p2pool-node binary digest changed: expected {expected_binary_sha256}, got {actual}"
            );
        }
        ensure_private_dir(&datadir)?;
        Ok(Self {
            binary,
            binary_sha256: expected_binary_sha256,
            datadir,
            allow_private_peers,
        })
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn datadir(&self) -> &Path {
        &self.datadir
    }

    pub fn existing_registration(&self) -> Result<Option<RegistrationResult>> {
        let registration_dir = self.datadir.join("agent-registration");
        let public_path = registration_dir.join("registration-public.json");
        match std::fs::symlink_metadata(&public_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect existing registration"),
            Ok(_) => {}
        }
        let bytes = read_limited_regular(&public_path, MAX_CHILD_JSON_BYTES)?;
        let registration: RegistrationResult =
            serde_json::from_slice(&bytes).context("parse existing registration")?;
        validate_registration_result(&registration)?;
        let message_path = registration_dir.join("miner-registration-message.json");
        let envelope_path = registration_dir.join("miner-registration-envelope.json");
        read_limited_regular(&message_path, MAX_CHILD_JSON_BYTES)
            .context("verify existing miner-registration-message.json")?;
        read_limited_regular(&envelope_path, MAX_CHILD_JSON_BYTES)
            .context("verify existing miner-registration-envelope.json")?;
        let args = vec![
            "verify-miner-registration-envelope".to_string(),
            "--envelope-file".to_string(),
            envelope_path.display().to_string(),
            "--message-file".to_string(),
            message_path.display().to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--durable".to_string(),
        ];
        let verified: VerifiedRegistrationEnvelopeOutput =
            serde_json::from_value(self.run_json(&args, CHILD_COMMAND_TIMEOUT)?)
                .context("parse verified persisted registration")?;
        verify_persisted_registration(&registration, &verified)?;
        let key_dir = self.datadir.join("keys").join(&registration.miner_id);
        let mining_pubkey = self.derive_xonly_pubkey(&key_dir.join("mining.key"))?;
        let claim_owner_pubkey = self.derive_xonly_pubkey(&key_dir.join("claim-owner.key"))?;
        let node_pubkey = self.derive_xonly_pubkey(&key_dir.join("gossip-node.key"))?;
        if mining_pubkey != registration.mining_pubkey_hex
            || claim_owner_pubkey != registration.claim_owner_pubkey_hex
            || node_pubkey != verified.peer_pubkey_xonly_hex
        {
            bail!("persisted registration does not match the protected local key files");
        }
        Ok(Some(registration))
    }

    fn derive_xonly_pubkey(&self, secret_key_file: &Path) -> Result<String> {
        let args = vec![
            "derive-xonly-pubkey".to_string(),
            "--secret-key-file".to_string(),
            secret_key_file.display().to_string(),
        ];
        let bytes = self.run_output(&args, CHILD_COMMAND_TIMEOUT)?;
        let value = String::from_utf8(bytes)
            .context("p2pool-node returned a non-UTF-8 public key")?
            .trim()
            .to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("p2pool-node returned an invalid x-only public key");
        }
        Ok(value)
    }

    pub fn prepare_registration(
        &self,
        miner_id: &str,
        idena_address: &str,
    ) -> Result<RegistrationChallenge> {
        validate_miner_id(miner_id)?;
        validate_idena_address(idena_address)?;
        let args = vec![
            "prepare-miner-registration".to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--miner-id".to_string(),
            miner_id.to_string(),
            "--idena-address".to_string(),
            idena_address.to_ascii_lowercase(),
        ];
        let value = self.run_json(&args, CHILD_COMMAND_TIMEOUT)?;
        let challenge: RegistrationChallenge =
            serde_json::from_value(value).context("parse registration challenge")?;
        if challenge.status != "needs_idena_signature"
            || challenge.miner_id != miner_id
            || challenge.idena_address != idena_address.to_ascii_lowercase()
        {
            bail!("p2pool-node returned an inconsistent registration challenge");
        }
        Ok(challenge)
    }

    pub async fn complete_registration(
        &self,
        challenge: &RegistrationChallenge,
        signature_hex: &str,
        gossip_endpoints: &[String],
    ) -> Result<RegistrationResult> {
        validate_idena_signature(signature_hex)?;
        let registration_dir = self.datadir.join("agent-registration");
        ensure_private_dir(&registration_dir)?;
        let nonce = random_hex(8);
        let message_attempt = registration_dir.join(format!("message-{nonce}.json"));
        let envelope_attempt = registration_dir.join(format!("envelope-{nonce}.json"));
        let args = vec![
            "prepare-miner-registration".to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--miner-id".to_string(),
            challenge.miner_id.clone(),
            "--idena-address".to_string(),
            challenge.idena_address.clone(),
            "--idena-signature-stdin".to_string(),
            "--message-out".to_string(),
            message_attempt.display().to_string(),
            "--envelope-out".to_string(),
            envelope_attempt.display().to_string(),
            "--append".to_string(),
        ];
        let value = self.run_json_with_input(
            &args,
            format!("{signature_hex}\n").as_bytes(),
            CHILD_COMMAND_TIMEOUT,
        )?;
        let output: RegistrationReadyOutput =
            serde_json::from_value(value).context("parse completed registration")?;
        if output.status != "registration_ready"
            || output.miner_id != challenge.miner_id
            || output.idena_address != challenge.idena_address
            || output.registration_binding_hash != challenge.registration_binding_hash
        {
            bail!("p2pool-node returned an inconsistent completed registration");
        }

        let canonical_message = registration_dir.join("miner-registration-message.json");
        let canonical_envelope = registration_dir.join("miner-registration-envelope.json");
        install_attempt(&message_attempt, &canonical_message)?;
        install_attempt(&envelope_attempt, &canonical_envelope)?;

        let resolved = resolve_peer_endpoints(gossip_endpoints, self.allow_private_peers).await?;
        let mut delivery = Vec::new();
        for (endpoint, address) in resolved {
            let send_args = vec![
                "send-gossip-envelope".to_string(),
                "--peer-addr".to_string(),
                address.to_string(),
                "--envelope-file".to_string(),
                canonical_envelope.display().to_string(),
            ];
            match self.run_status(&send_args, CHILD_COMMAND_TIMEOUT) {
                Ok(()) => delivery.push(GossipDelivery {
                    endpoint,
                    delivered: true,
                    error: None,
                }),
                Err(error) => delivery.push(GossipDelivery {
                    endpoint,
                    delivered: false,
                    error: Some(sanitized_error(&error)),
                }),
            }
        }

        let result = RegistrationResult {
            status: output.status,
            miner_id: output.miner_id,
            idena_address: output.idena_address,
            message_hash: output.message_hash,
            envelope_hash: output.envelope_hash,
            registration_binding_hash: output.registration_binding_hash,
            mining_pubkey_hex: output.mining_pubkey_hex,
            claim_owner_pubkey_hex: output.claim_owner_pubkey_hex,
            btc_payout_script_hex: output.btc_payout_script_hex,
            gossip_delivery: delivery,
        };
        let public_path = registration_dir.join("registration-public.json");
        let mut bytes = serde_json::to_vec_pretty(&result)?;
        bytes.push(b'\n');
        atomic_replace_private(&public_path, &bytes)?;
        Ok(result)
    }

    pub async fn add_gossip_peers(&self, endpoints: &[String]) -> Result<Vec<SocketAddr>> {
        let peers = resolve_peer_endpoints(endpoints, self.allow_private_peers).await?;
        let mut addresses = Vec::new();
        for (_, address) in peers {
            let args = vec![
                "add-gossip-peer".to_string(),
                "--datadir".to_string(),
                self.datadir.display().to_string(),
                "--peer-addr".to_string(),
                address.to_string(),
            ];
            self.run_json(&args, CHILD_COMMAND_TIMEOUT)?;
            addresses.push(address);
        }
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }

    pub async fn matching_fork_peers(
        &self,
        descriptor: &SourceJoinManifestV1,
        activation_manifest: &Path,
    ) -> Result<VerifiedForkPeers> {
        let rpc_peers =
            resolve_peer_endpoints(&descriptor.peers.fork_rpc, self.allow_private_peers).await?;
        let mut matching_rpc = Vec::new();
        for (_, address) in rpc_peers {
            let args = vec![
                "fork-chain-status".to_string(),
                "--activation-manifest".to_string(),
                activation_manifest.display().to_string(),
                "--rpc-addr".to_string(),
                address.to_string(),
                "--allow-non-loopback-fork-rpc".to_string(),
            ];
            if let Ok(value) = self.run_json(&args, CHILD_COMMAND_TIMEOUT) {
                if value.get("activation_id").and_then(|item| item.as_str())
                    == Some(descriptor.activation.activation_id.as_str())
                {
                    matching_rpc.push(address);
                }
            }
        }
        matching_rpc.sort();
        matching_rpc.dedup();
        if matching_rpc.is_empty() {
            bail!("no fork RPC peer serves the locally pinned activation ID");
        }
        let mut p2p = resolve_peer_endpoints(&descriptor.peers.fork_p2p, self.allow_private_peers)
            .await?
            .into_iter()
            .map(|(_, address)| address)
            .collect::<Vec<_>>();
        p2p.sort();
        p2p.dedup();
        Ok(VerifiedForkPeers {
            rpc: matching_rpc,
            p2p,
        })
    }

    pub fn mining_snapshot_evidence(
        &self,
        snapshot_dir: &Path,
        miner_id: Option<&str>,
        min_snapshot_voters: usize,
    ) -> Result<MiningSnapshotEvidence> {
        if min_snapshot_voters == 0 {
            bail!("snapshot voter quorum must be greater than zero");
        }
        let mut args = vec![
            "mining-snapshot-evidence".to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--snapshot-dir".to_string(),
            snapshot_dir.display().to_string(),
            "--min-snapshot-voters".to_string(),
            min_snapshot_voters.to_string(),
        ];
        if let Some(miner_id) = miner_id {
            validate_miner_id(miner_id)?;
            args.push("--miner-id".to_string());
            args.push(miner_id.to_string());
        }
        let value = self.run_json(&args, CHILD_COMMAND_TIMEOUT)?;
        let evidence: MiningSnapshotEvidence =
            serde_json::from_value(value).context("parse mining snapshot evidence")?;
        validate_mining_snapshot_evidence(&evidence, miner_id)?;
        Ok(evidence)
    }

    pub fn spawn_gossip(&self, peers: &[SocketAddr]) -> Result<ManagedChild> {
        let mut args = vec![
            "run-gossip-mesh".to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--bind-addr".to_string(),
            "127.0.0.1:0".to_string(),
        ];
        args.push("--allow-public-peers".to_string());
        for peer in peers {
            args.push("--peer-addr".to_string());
            args.push(peer.to_string());
        }
        self.spawn_logged("gossip", &args)
    }

    pub fn spawn_fork_node(
        &self,
        activation_manifest: &Path,
        peers: &[SocketAddr],
        rpc_addr: SocketAddr,
    ) -> Result<ManagedChild> {
        if peers.is_empty() {
            bail!("ordinary joiner refuses to start a fork node without a verified peer");
        }
        let fork_datadir = self.datadir.join("fork-chain");
        ensure_private_dir(&fork_datadir)?;
        let mut args = vec![
            "run-fork-chain-node".to_string(),
            "--datadir".to_string(),
            fork_datadir.display().to_string(),
            "--activation-manifest".to_string(),
            activation_manifest.display().to_string(),
            "--rpc-bind-addr".to_string(),
            rpc_addr.to_string(),
            "--p2p-bind-addr".to_string(),
            "127.0.0.1:0".to_string(),
        ];
        for peer in peers {
            args.push("--peer-addr".to_string());
            args.push(peer.to_string());
        }
        self.spawn_logged("fork", &args)
    }

    pub fn local_fork_status(
        &self,
        activation_manifest: &Path,
        rpc_addr: SocketAddr,
    ) -> Result<serde_json::Value> {
        let args = vec![
            "fork-chain-status".to_string(),
            "--activation-manifest".to_string(),
            activation_manifest.display().to_string(),
            "--rpc-addr".to_string(),
            rpc_addr.to_string(),
        ];
        self.run_json(&args, CHILD_COMMAND_TIMEOUT)
    }

    pub fn spawn_mining_adapter(&self, launch: MiningAdapterLaunch<'_>) -> Result<ManagedChild> {
        if !matches!(launch.descriptor.launch.phase, LaunchPhase::Mining) {
            bail!("local source-join phase does not enable fork mining");
        }
        let snapshot = launch
            .descriptor
            .snapshot
            .as_ref()
            .context("mining requires a pinned snapshot")?;
        if !launch.stratum_bind.ip().is_loopback() && !is_private_lan_ip(launch.stratum_bind.ip()) {
            bail!("Stratum may bind only to loopback or an explicit private LAN address");
        }
        let key_dir = self.datadir.join("keys").join(launch.miner_id);
        let mut args = vec![
            "run-mining-adapter".to_string(),
            "--datadir".to_string(),
            self.datadir.display().to_string(),
            "--bind-addr".to_string(),
            launch.stratum_bind.to_string(),
            "--miner-id".to_string(),
            launch.miner_id.to_string(),
            "--fork-chain-rpc-addr".to_string(),
            launch.fork_rpc_addr.to_string(),
            "--fork-chain-activation-manifest".to_string(),
            launch.activation_manifest.display().to_string(),
            "--idena-snapshot-id".to_string(),
            snapshot.snapshot_id.clone(),
            "--idena-snapshot-proof-root".to_string(),
            snapshot.proof_root.clone(),
            "--mining-secret-key-file".to_string(),
            key_dir.join("mining.key").display().to_string(),
            "--node-secret-key-file".to_string(),
            key_dir.join("gossip-node.key").display().to_string(),
            "--stratum-password-file".to_string(),
            launch.stratum_password_file.display().to_string(),
            "--block-candidate-dir".to_string(),
            self.datadir.join("block-candidates").display().to_string(),
            "--auto-submit-blocks".to_string(),
        ];
        if !launch.stratum_bind.ip().is_loopback() {
            args.push("--allow-non-loopback-stratum".to_string());
        }
        for peer in launch.gossip_peers {
            args.push("--peer-addr".to_string());
            args.push(peer.to_string());
        }
        self.spawn_logged("stratum", &args)
    }

    fn run_json(&self, args: &[String], timeout: Duration) -> Result<serde_json::Value> {
        let output = self.run_output(args, timeout)?;
        serde_json::from_slice(&output).context("p2pool-node returned invalid JSON")
    }

    fn run_json_with_input(
        &self,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<serde_json::Value> {
        let output = self.run_output_with_input(args, Some(input), timeout)?;
        serde_json::from_slice(&output).context("p2pool-node returned invalid JSON")
    }

    fn run_status(&self, args: &[String], timeout: Duration) -> Result<()> {
        self.run_output(args, timeout).map(|_| ())
    }

    fn run_output(&self, args: &[String], timeout: Duration) -> Result<Vec<u8>> {
        self.run_output_with_input(args, None, timeout)
    }

    fn run_output_with_input(
        &self,
        args: &[String],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.verify_binary_digest()?;
        let mut command = isolated_command(&self.binary);
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context("start p2pool-node")?;
        if let Some(input) = input {
            let write_result = (|| -> Result<()> {
                let mut stdin = child.stdin.take().context("open p2pool-node stdin")?;
                stdin
                    .write_all(input)
                    .context("write bounded p2pool-node stdin")
            })();
            if let Err(error) = write_result {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            bail!("capture p2pool-node stdout");
        };
        let Some(stderr) = child.stderr.take() else {
            let _ = child.kill();
            let _ = child.wait();
            bail!("capture p2pool-node stderr");
        };
        let stdout_reader = std::thread::spawn(move || drain_child_output(stdout));
        let stderr_reader = std::thread::spawn(move || drain_child_output(stderr));
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(error).context("poll p2pool-node command");
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                timed_out = true;
                break child.wait().context("reap timed-out p2pool-node command")?;
            }
            sleep(Duration::from_millis(25));
        };
        let (stdout, stdout_exceeded) = join_child_output(stdout_reader)?;
        let (stderr, stderr_exceeded) = join_child_output(stderr_reader)?;
        if timed_out {
            bail!("p2pool-node command timed out");
        }
        if stdout_exceeded || stderr_exceeded {
            bail!("p2pool-node command output exceeded the safety limit");
        }
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            bail!("p2pool-node command failed: {}", stderr.trim());
        }
        Ok(stdout)
    }

    fn spawn_logged(&self, name: &str, args: &[String]) -> Result<ManagedChild> {
        self.verify_binary_digest()?;
        let log_path = self.datadir.join("agent-logs").join(format!("{name}.log"));
        let stdout = private_log_file(&log_path)?;
        let stderr = stdout.try_clone()?;
        let mut command = isolated_command(&self.binary);
        command
            .args(args)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = command
            .spawn()
            .with_context(|| format!("start {name} process"))?;
        Ok(ManagedChild { child })
    }

    fn verify_binary_digest(&self) -> Result<()> {
        let actual = hash_file(&self.binary)?;
        if actual != self.binary_sha256 {
            bail!("p2pool-node binary changed after onboarding verification");
        }
        Ok(())
    }
}

pub struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    pub fn running(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.stop();
    }
}

pub async fn resolve_peer_endpoints(
    endpoints: &[String],
    allow_private: bool,
) -> Result<Vec<(String, SocketAddr)>> {
    let mut resolved = Vec::new();
    for endpoint in endpoints {
        let addresses = lookup_host(endpoint)
            .await
            .with_context(|| format!("resolve peer endpoint {endpoint}"))?;
        let mut accepted = Vec::new();
        for address in addresses {
            if allow_private || is_public_ip(address.ip()) {
                accepted.push(address);
            }
        }
        accepted.sort();
        accepted.dedup();
        if accepted.is_empty() {
            bail!("peer endpoint {endpoint} resolved to no permitted addresses");
        }
        for address in accepted {
            resolved.push((endpoint.clone(), address));
        }
    }
    resolved.sort_by_key(|item| item.1);
    resolved.dedup_by(|left, right| left.1 == right.1);
    Ok(resolved)
}

pub fn hash_file(path: &Path) -> Result<String> {
    validate_binary_file(path)?;
    let mut file = open_binary_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(unix)]
fn open_binary_nofollow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

#[cfg(not(unix))]
fn open_binary_nofollow(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("open {}", path.display()))
}

fn validate_binary(path: &Path) -> Result<()> {
    validate_binary_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o111 == 0 {
            bail!("p2pool-node binary is not executable");
        }
    }
    Ok(())
}

fn validate_binary_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect p2pool-node binary {}", path.display()))?;
    if is_link_like(&metadata) || !metadata.is_file() {
        bail!("p2pool-node binary must be a regular non-symlink file");
    }
    Ok(())
}

fn isolated_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.env_clear();
    for name in ["PATH", "SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

fn install_attempt(attempt: &Path, canonical: &Path) -> Result<()> {
    let bytes = read_limited_regular(attempt, MAX_CHILD_JSON_BYTES)?;
    install_private_if_absent(canonical, &bytes)
        .context("registration output conflicts with existing local registration")?;
    std::fs::remove_file(attempt)?;
    Ok(())
}

fn drain_child_output<R: Read>(mut reader: R) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CHILD_JSON_BYTES.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        if keep < read {
            exceeded = true;
        }
    }
    Ok((retained, exceeded))
}

fn join_child_output(
    reader: std::thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
) -> Result<(Vec<u8>, bool)> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("p2pool-node output reader panicked"))?
        .context("read p2pool-node output")
}

fn validate_miner_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("miner ID must be 1-64 lowercase letters, digits, dots, underscores, or dashes");
    }
    Ok(())
}

fn validate_idena_address(value: &str) -> Result<()> {
    let Some(normalized) = value.strip_prefix("0x") else {
        bail!("Idena address must be 20 bytes encoded as 0x-prefixed hex");
    };
    if normalized.len() != 40 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Idena address must be 20 bytes encoded as 0x-prefixed hex");
    }
    Ok(())
}

fn validate_idena_signature(value: &str) -> Result<()> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    if normalized.len() != 130 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Idena signature must be 65 bytes encoded as hex");
    }
    Ok(())
}

fn validate_registration_result(value: &RegistrationResult) -> Result<()> {
    if value.status != "registration_ready" {
        bail!("existing registration is not ready");
    }
    validate_miner_id(&value.miner_id)?;
    validate_idena_address(&value.idena_address)?;
    for (name, encoded) in [
        ("message_hash", value.message_hash.as_str()),
        ("envelope_hash", value.envelope_hash.as_str()),
        (
            "registration_binding_hash",
            value.registration_binding_hash.as_str(),
        ),
        ("mining_pubkey_hex", value.mining_pubkey_hex.as_str()),
        (
            "claim_owner_pubkey_hex",
            value.claim_owner_pubkey_hex.as_str(),
        ),
    ] {
        if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("existing registration has invalid {name}");
        }
    }
    if value.btc_payout_script_hex.is_empty()
        || value.btc_payout_script_hex.len() > 10_000
        || value.btc_payout_script_hex.len() % 2 != 0
        || !value
            .btc_payout_script_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("existing registration has invalid btc_payout_script_hex");
    }
    Ok(())
}

fn verify_persisted_registration(
    public: &RegistrationResult,
    verified: &VerifiedRegistrationEnvelopeOutput,
) -> Result<()> {
    let fields_match = verified.valid
        && verified.miner_registration.miner_id == public.miner_id
        && verified.miner_registration.idena_address == public.idena_address
        && verified.miner_registration.btc_payout_script_hex == public.btc_payout_script_hex
        && verified.miner_registration.claim_owner_pubkey_hex == public.claim_owner_pubkey_hex
        && verified.miner_registration.mining_pubkey_hex == public.mining_pubkey_hex
        && verified.message_hash == public.message_hash
        && verified.envelope_hash == public.envelope_hash
        && verified.registration_binding_hash == public.registration_binding_hash;
    if !fields_match {
        bail!("persisted registration receipt does not match its verified signed envelope");
    }
    Ok(())
}

fn validate_mining_snapshot_evidence(
    evidence: &MiningSnapshotEvidence,
    expected_miner_id: Option<&str>,
) -> Result<()> {
    if evidence.schema_version != "pohw-mining-snapshot-evidence/v1" {
        bail!("p2pool-node returned an unsupported mining snapshot evidence schema");
    }
    if evidence.snapshot_id.is_empty() || evidence.snapshot_id.len() > 128 {
        bail!("p2pool-node returned an invalid mining snapshot ID");
    }
    if evidence.proof_root.len() != 64
        || !evidence
            .proof_root
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || evidence.source_height == 0
        || evidence.distinct_voter_count == 0
    {
        bail!("p2pool-node returned invalid mining snapshot evidence");
    }
    match expected_miner_id {
        Some(expected) => {
            if evidence.miner_id.as_deref() != Some(expected)
                || evidence.miner_eligible != Some(true)
                || !matches!(
                    evidence.identity_status.as_deref(),
                    Some("Newbie" | "Verified" | "Human")
                )
            {
                bail!("p2pool-node did not prove the registered miner identity eligible");
            }
        }
        None => {
            if evidence.miner_id.is_some()
                || evidence.miner_eligible.is_some()
                || evidence.identity_status.is_some()
            {
                bail!("p2pool-node returned unexpected miner-specific snapshot evidence");
            }
        }
    }
    Ok(())
}

fn is_private_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn sanitized_error(error: &anyhow::Error) -> String {
    let text = error.to_string();
    let mut chars = text.chars();
    let prefix = chars.by_ref().take(240).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration_fixture() -> RegistrationResult {
        RegistrationResult {
            status: "registration_ready".to_string(),
            miner_id: "alice-01".to_string(),
            idena_address: format!("0x{}", "11".repeat(20)),
            message_hash: "22".repeat(32),
            envelope_hash: "33".repeat(32),
            registration_binding_hash: "44".repeat(32),
            mining_pubkey_hex: "55".repeat(32),
            claim_owner_pubkey_hex: "66".repeat(32),
            btc_payout_script_hex: "51".to_string(),
            gossip_delivery: Vec::new(),
        }
    }

    fn verified_registration_fixture(
        public: &RegistrationResult,
    ) -> VerifiedRegistrationEnvelopeOutput {
        VerifiedRegistrationEnvelopeOutput {
            valid: true,
            envelope_hash: public.envelope_hash.clone(),
            peer_pubkey_xonly_hex: "77".repeat(32),
            message_hash: public.message_hash.clone(),
            registration_binding_hash: public.registration_binding_hash.clone(),
            miner_registration: VerifiedRegistrationFields {
                miner_id: public.miner_id.clone(),
                idena_address: public.idena_address.clone(),
                btc_payout_script_hex: public.btc_payout_script_hex.clone(),
                claim_owner_pubkey_hex: public.claim_owner_pubkey_hex.clone(),
                mining_pubkey_hex: public.mining_pubkey_hex.clone(),
            },
        }
    }

    #[test]
    fn validates_public_registration_inputs() {
        assert!(validate_miner_id("alice-01").is_ok());
        assert!(validate_miner_id("Alice").is_err());
        assert!(validate_idena_address(&format!("0x{}", "11".repeat(20))).is_ok());
        assert!(validate_idena_signature(&format!("0x{}", "22".repeat(65))).is_ok());
    }

    #[test]
    fn rejects_public_stratum_bind() {
        assert!(is_private_lan_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, 1, 2
        ))));
        assert!(!is_private_lan_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn rejects_malformed_persisted_registration() {
        let value = registration_fixture();
        validate_registration_result(&value).unwrap();
        let mut malformed = value;
        malformed.message_hash = "no".to_string();
        assert!(validate_registration_result(&malformed).is_err());
    }

    #[test]
    fn persisted_registration_requires_exact_verified_envelope_fields() {
        let public = registration_fixture();
        let verified = verified_registration_fixture(&public);
        verify_persisted_registration(&public, &verified).unwrap();

        let mut tampered = verified;
        tampered.miner_registration.btc_payout_script_hex = "52".to_string();
        assert!(verify_persisted_registration(&public, &tampered).is_err());
    }

    #[test]
    fn mining_snapshot_evidence_requires_eligible_bound_miner() {
        let mut evidence = MiningSnapshotEvidence {
            schema_version: "pohw-mining-snapshot-evidence/v1".to_string(),
            snapshot_id: "2026-07-14".to_string(),
            proof_root: "aa".repeat(32),
            source_height: 42,
            distinct_voter_count: 3,
            miner_id: None,
            miner_eligible: None,
            identity_status: None,
        };
        validate_mining_snapshot_evidence(&evidence, None).unwrap();

        evidence.miner_id = Some("alice-01".to_string());
        evidence.miner_eligible = Some(true);
        evidence.identity_status = Some("Human".to_string());
        validate_mining_snapshot_evidence(&evidence, Some("alice-01")).unwrap();
        evidence.identity_status = Some("Candidate".to_string());
        assert!(validate_mining_snapshot_evidence(&evidence, Some("alice-01")).is_err());
    }
}
