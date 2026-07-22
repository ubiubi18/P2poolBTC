use crate::rpc::{BlockResponse, EpochResponse, IdenaRpcClient, IdentityResponse, SyncingResponse};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use pohw_core::consensus_identity::{
    ConsensusIdentityRegistrationRecordV1, ConsensusIdentitySnapshotBlockV1,
    ConsensusIdentitySnapshotInputV1, ConsensusIdentityStateRecordV1,
    CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN,
    CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA, MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS,
    MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS,
};
use pohw_core::sharechain::MinerRegistration;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::{sleep, Instant};

const CAPTURE_STABILITY_ATTEMPTS: usize = 5;
const CONTRACT_REGISTERED_COUNT_KEY: &str = "registry:registered-count";
const CONTRACT_REGISTERED_MINERS_KEY: &str = "registry:registered-miners";

#[derive(Debug, Clone)]
pub struct ConsensusIdentityCaptureOptions {
    pub experiment_id: String,
    pub registry_contract_address: String,
    pub finality_confirmations: u16,
    pub poll_interval: Duration,
    pub max_wait: Duration,
}

impl ConsensusIdentityCaptureOptions {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS
            ..=MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS)
            .contains(&self.finality_confirmations)
        {
            bail!(
                "finality confirmations must be between {} and {}",
                MIN_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS,
                MAX_CONSENSUS_IDENTITY_FINALITY_CONFIRMATIONS
            );
        }
        if self.poll_interval.is_zero() || self.max_wait < self.poll_interval {
            bail!("capture poll interval and maximum wait are invalid");
        }
        Ok(())
    }
}

#[async_trait]
trait ConsensusIdentityRpc {
    async fn syncing(&self) -> Result<SyncingResponse>;
    async fn epoch(&self) -> Result<EpochResponse>;
    async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>>;
    async fn identities(&self) -> Result<Vec<IdentityResponse>>;
    async fn contract_read_string(&self, contract: &str, key: &str) -> Result<String>;
}

#[async_trait]
impl ConsensusIdentityRpc for IdenaRpcClient {
    async fn syncing(&self) -> Result<SyncingResponse> {
        self.syncing().await
    }

    async fn epoch(&self) -> Result<EpochResponse> {
        self.epoch().await
    }

    async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>> {
        self.block_at(height).await
    }

    async fn identities(&self) -> Result<Vec<IdentityResponse>> {
        self.identities().await
    }

    async fn contract_read_string(&self, contract: &str, key: &str) -> Result<String> {
        self.contract_read_string(contract, key).await
    }
}

#[derive(Debug)]
struct StableCapture {
    block: BlockResponse,
    epoch: EpochResponse,
    identities: Vec<IdentityResponse>,
    registered_count: u32,
    registered_miners: Vec<String>,
    registrations: Vec<ConsensusIdentityRegistrationRecordV1>,
}

pub async fn capture_consensus_identity_snapshot(
    client: &IdenaRpcClient,
    registrations: Vec<MinerRegistration>,
    options: ConsensusIdentityCaptureOptions,
) -> Result<ConsensusIdentitySnapshotInputV1> {
    capture_with_rpc(client, registrations, options).await
}

async fn capture_with_rpc<R: ConsensusIdentityRpc + Sync>(
    client: &R,
    registrations: Vec<MinerRegistration>,
    options: ConsensusIdentityCaptureOptions,
) -> Result<ConsensusIdentitySnapshotInputV1> {
    options.validate()?;
    let registrations = index_registrations(registrations)?;
    let capture = stable_capture(client, &registrations, &options).await?;
    let target_height = capture
        .block
        .height
        .checked_add(u64::from(options.finality_confirmations))
        .context("Idena finality target height overflow")?;
    wait_for_height(client, target_height, &options).await?;

    let mut finality_chain = Vec::with_capacity(usize::from(options.finality_confirmations) + 1);
    for height in capture.block.height..=target_height {
        let block = read_block(client, height).await?;
        finality_chain.push(snapshot_block(block)?);
    }
    let capture_block = snapshot_block(capture.block)?;
    if finality_chain.first() != Some(&capture_block) {
        bail!("Idena capture block changed before the confirmation chain finalized");
    }

    let input = ConsensusIdentitySnapshotInputV1 {
        schema_version: CONSENSUS_IDENTITY_SNAPSHOT_INPUT_SCHEMA.to_string(),
        status: "finalized-candidate-input".to_string(),
        experiment_id: options.experiment_id,
        identity_rows_assurance: CONSENSUS_IDENTITY_ROWS_ASSURANCE_COMPATIBLE_RPC_UNPROVEN
            .to_string(),
        registry_contract_address: options.registry_contract_address,
        capture_epoch: capture.epoch.epoch,
        next_validation_timestamp: u64::try_from(capture.epoch.next_validation.timestamp())
            .context("next Idena validation timestamp is negative")?,
        finality_confirmations: options.finality_confirmations,
        capture_block,
        finality_chain,
        identities: capture
            .identities
            .into_iter()
            .map(|identity| ConsensusIdentityStateRecordV1 {
                address: identity.address,
                state: identity.state,
            })
            .collect(),
        registry_registered_count: capture.registered_count,
        registry_registered_miners: capture.registered_miners,
        registrations: capture.registrations,
    }
    .normalized();
    input.validate().map_err(|error| {
        anyhow::anyhow!("captured consensus identity input is invalid: {error}")
    })?;
    Ok(input)
}

fn index_registrations(
    registrations: Vec<MinerRegistration>,
) -> Result<BTreeMap<String, MinerRegistration>> {
    let mut indexed = BTreeMap::new();
    for registration in registrations {
        let registration = registration.normalized();
        registration
            .verify_mining_signature()
            .context("registration has an invalid mining signature")?;
        registration
            .verify_idena_ownership_signature()
            .context("registration has an invalid Idena ownership signature")?;
        let miner_id = registration.miner_id.clone();
        if indexed.insert(miner_id.clone(), registration).is_some() {
            bail!("registration input contains duplicate miner ID {miner_id}");
        }
    }
    Ok(indexed)
}

async fn stable_capture<R: ConsensusIdentityRpc + Sync>(
    client: &R,
    registrations: &BTreeMap<String, MinerRegistration>,
    options: &ConsensusIdentityCaptureOptions,
) -> Result<StableCapture> {
    for attempt in 1..=CAPTURE_STABILITY_ATTEMPTS {
        let before_sync = client
            .syncing()
            .await
            .context("failed to read Idena sync state before capture")?;
        ensure_ready(&before_sync)?;
        let before_block = read_block(client, before_sync.current_block).await?;
        let epoch = client
            .epoch()
            .await
            .context("failed to read Idena epoch before capture")?;
        let identities = client
            .identities()
            .await
            .context("failed to read complete Idena identity export")?;
        let (registered_count, registered_miners, captured_registrations) =
            read_registry(client, registrations, options).await?;
        let after_sync = client
            .syncing()
            .await
            .context("failed to read Idena sync state after capture")?;
        ensure_ready(&after_sync)?;
        if before_sync.current_block != after_sync.current_block {
            if attempt < CAPTURE_STABILITY_ATTEMPTS {
                continue;
            }
            break;
        }
        let after_block = read_block(client, after_sync.current_block).await?;
        let after_epoch = client
            .epoch()
            .await
            .context("failed to re-read Idena epoch after capture")?;
        if same_block(&before_block, &after_block)
            && epoch.epoch == after_epoch.epoch
            && epoch.next_validation == after_epoch.next_validation
        {
            return Ok(StableCapture {
                block: before_block,
                epoch,
                identities,
                registered_count,
                registered_miners,
                registrations: captured_registrations,
            });
        }
        if attempt == CAPTURE_STABILITY_ATTEMPTS {
            break;
        }
    }
    bail!(
        "Idena head or epoch changed during {} consecutive capture attempts",
        CAPTURE_STABILITY_ATTEMPTS
    )
}

async fn read_registry<R: ConsensusIdentityRpc + Sync>(
    client: &R,
    registrations: &BTreeMap<String, MinerRegistration>,
    options: &ConsensusIdentityCaptureOptions,
) -> Result<(u32, Vec<String>, Vec<ConsensusIdentityRegistrationRecordV1>)> {
    let count_raw = client
        .contract_read_string(
            &options.registry_contract_address,
            CONTRACT_REGISTERED_COUNT_KEY,
        )
        .await
        .context("failed to read registry miner count")?;
    let count = parse_canonical_u32(&count_raw, "registry miner count")?;
    let miners_raw = client
        .contract_read_string(
            &options.registry_contract_address,
            CONTRACT_REGISTERED_MINERS_KEY,
        )
        .await
        .context("failed to read registry miner index")?;
    let miners = parse_registered_miners(&miners_raw)?;
    if usize::try_from(count).ok() != Some(miners.len()) || miners.len() > 48 {
        bail!("registry miner count and bounded miner index differ");
    }
    if registrations.len() != miners.len()
        || registrations
            .keys()
            .map(String::as_str)
            .ne(miners.iter().map(String::as_str))
    {
        bail!("registration file does not exactly cover the contract miner index");
    }

    let mut captured = Vec::with_capacity(miners.len());
    for miner_id in &miners {
        let registration = registrations
            .get(miner_id)
            .context("registration disappeared from the verified input index")?;
        let owner_raw = client
            .contract_read_string(
                &options.registry_contract_address,
                &format!("miner-owner:{miner_id}"),
            )
            .await
            .with_context(|| format!("failed to read registry owner for {miner_id}"))?;
        let owner_address = normalize_contract_address(&owner_raw)?;
        if owner_address != registration.idena_address {
            bail!("registry owner does not match signed registration for {miner_id}");
        }
        let address_hex = owner_address
            .strip_prefix("0x")
            .context("normalized owner address lost its prefix")?;
        let sequence_raw = client
            .contract_read_string(
                &options.registry_contract_address,
                &format!("identity:{address_hex}:current"),
            )
            .await
            .with_context(|| format!("failed to read current sequence for {miner_id}"))?;
        let current_sequence = parse_canonical_u32(&sequence_raw, "registration sequence")?;
        if current_sequence == 0 {
            bail!("registry current sequence is zero for {miner_id}");
        }
        let contract_record = client
            .contract_read_string(
                &options.registry_contract_address,
                &format!("miner:{address_hex}:{current_sequence}"),
            )
            .await
            .with_context(|| format!("failed to read latest contract record for {miner_id}"))?;
        captured.push(ConsensusIdentityRegistrationRecordV1 {
            owner_address,
            current_sequence,
            contract_record,
            registration: registration.clone(),
        });
    }
    Ok((count, miners, captured))
}

async fn wait_for_height<R: ConsensusIdentityRpc + Sync>(
    client: &R,
    target_height: u64,
    options: &ConsensusIdentityCaptureOptions,
) -> Result<()> {
    let deadline = Instant::now() + options.max_wait;
    loop {
        let syncing = client
            .syncing()
            .await
            .context("failed to read Idena sync state while waiting for finality")?;
        ensure_ready(&syncing)?;
        if syncing.current_block >= target_height {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for Idena finality height {target_height}");
        }
        sleep(options.poll_interval).await;
    }
}

async fn read_block<R: ConsensusIdentityRpc + Sync>(
    client: &R,
    height: u64,
) -> Result<BlockResponse> {
    let block = client
        .block_at(height)
        .await
        .with_context(|| format!("failed to read Idena block {height}"))?
        .with_context(|| format!("Idena block {height} is unavailable"))?;
    if block.height != height {
        bail!(
            "Idena RPC returned block {} while block {height} was requested",
            block.height
        );
    }
    Ok(block)
}

fn snapshot_block(block: BlockResponse) -> Result<ConsensusIdentitySnapshotBlockV1> {
    Ok(ConsensusIdentitySnapshotBlockV1 {
        height: block.height,
        hash: block.hash,
        parent_hash: block.parent_hash,
        timestamp: u64::try_from(block.timestamp).context("Idena block timestamp is negative")?,
        identity_root: block.identity_root,
    }
    .normalized())
}

fn ensure_ready(syncing: &SyncingResponse) -> Result<()> {
    if syncing.wrong_time {
        bail!("Idena node clock is invalid");
    }
    if syncing.is_effectively_syncing() {
        bail!(
            "Idena node is still syncing at block {} of {}",
            syncing.current_block,
            syncing.highest_block
        );
    }
    Ok(())
}

fn same_block(left: &BlockResponse, right: &BlockResponse) -> bool {
    left.height == right.height
        && left.hash.eq_ignore_ascii_case(&right.hash)
        && left.parent_hash.eq_ignore_ascii_case(&right.parent_hash)
        && left
            .identity_root
            .eq_ignore_ascii_case(&right.identity_root)
        && left.timestamp == right.timestamp
}

fn parse_canonical_u32(value: &str, label: &str) -> Result<u32> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        bail!("{label} is not canonical unsigned decimal");
    }
    let parsed = value
        .parse::<u32>()
        .with_context(|| format!("{label} is not an unsigned 32-bit integer"))?;
    if parsed.to_string() != value {
        bail!("{label} is not canonical unsigned decimal");
    }
    Ok(parsed)
}

fn parse_registered_miners(value: &str) -> Result<Vec<String>> {
    if value == "~" {
        return Ok(Vec::new());
    }
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("registry miner index is malformed");
    }
    let miners = value.split(',').map(str::to_string).collect::<Vec<_>>();
    if miners
        .iter()
        .any(|miner| miner.is_empty() || miner != &miner.to_ascii_lowercase())
        || miners.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("registry miner index is not canonical and strictly sorted");
    }
    Ok(miners)
}

fn normalize_contract_address(value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    let payload = value.strip_prefix("0x").unwrap_or(&value);
    if payload.len() != 40 || !payload.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("registry owner address is malformed");
    }
    Ok(format!("0x{payload}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use pohw_core::consensus_identity::ConsensusIdentityError;
    use pohw_core::snapshot::IdenaStatus;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockRpc {
        sync_calls: AtomicUsize,
        blocks: BTreeMap<u64, BlockResponse>,
        wrong_time: bool,
    }

    impl MockRpc {
        fn new(broken_parent_at: Option<u64>) -> Self {
            let mut blocks = BTreeMap::new();
            for height in 100..=106 {
                let parent_height = height - 1;
                let parent_hash = if broken_parent_at == Some(height) {
                    format!("0x{}", "ff".repeat(32))
                } else {
                    format!("0x{parent_height:064x}")
                };
                blocks.insert(
                    height,
                    BlockResponse {
                        coinbase: format!("0x{}", "01".repeat(20)),
                        hash: format!("0x{height:064x}"),
                        parent_hash,
                        height,
                        timestamp: 1_784_404_800 + i64::try_from(height - 100).unwrap() * 20,
                        root: format!("0x{}", "02".repeat(32)),
                        identity_root: format!("0x{}", "03".repeat(32)),
                        transactions: Some(Vec::new()),
                        is_empty: true,
                    },
                );
            }
            Self {
                sync_calls: AtomicUsize::new(0),
                blocks,
                wrong_time: false,
            }
        }
    }

    #[async_trait]
    impl ConsensusIdentityRpc for MockRpc {
        async fn syncing(&self) -> Result<SyncingResponse> {
            let call = self.sync_calls.fetch_add(1, Ordering::SeqCst);
            let height = if call < 2 { 100 } else { 106 };
            Ok(SyncingResponse {
                syncing: false,
                current_block: height,
                highest_block: height,
                wrong_time: self.wrong_time,
                genesis_block: 1,
                message: String::new(),
            })
        }

        async fn epoch(&self) -> Result<EpochResponse> {
            Ok(EpochResponse {
                start_block: 90,
                epoch: 121,
                next_validation: Utc.timestamp_opt(1_786_219_200, 0).single().unwrap(),
                current_period: "None".to_string(),
            })
        }

        async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>> {
            Ok(self.blocks.get(&height).cloned())
        }

        async fn identities(&self) -> Result<Vec<IdentityResponse>> {
            Ok(vec![IdentityResponse {
                address: format!("0x{}", "11".repeat(20)),
                state: IdenaStatus::Human,
                pubkey: String::new(),
                delegatee: None,
                is_pool: false,
            }])
        }

        async fn contract_read_string(&self, _contract: &str, key: &str) -> Result<String> {
            match key {
                CONTRACT_REGISTERED_COUNT_KEY => Ok("0".to_string()),
                CONTRACT_REGISTERED_MINERS_KEY => Ok("~".to_string()),
                _ => bail!("unexpected contract key {key}"),
            }
        }
    }

    fn options() -> ConsensusIdentityCaptureOptions {
        ConsensusIdentityCaptureOptions {
            experiment_id: "p2poolbtc-experiment-2".to_string(),
            registry_contract_address: format!("0x{}", "22".repeat(20)),
            finality_confirmations: 6,
            poll_interval: Duration::from_millis(1),
            max_wait: Duration::from_millis(50),
        }
    }

    #[tokio::test]
    async fn capture_binds_a_stable_head_to_an_exact_confirmation_chain() {
        let input = capture_with_rpc(&MockRpc::new(None), Vec::new(), options())
            .await
            .unwrap();
        input.validate().unwrap();
        assert_eq!(input.capture_block.height, 100);
        assert_eq!(input.finality_chain.last().unwrap().height, 106);
        assert_eq!(input.registry_registered_count, 0);
        assert_eq!(
            input.build_bundle(),
            Err(ConsensusIdentityError::EmptyAuthorizationSet)
        );
    }

    #[tokio::test]
    async fn capture_rejects_a_noncontiguous_confirmation_chain() {
        let error = capture_with_rpc(&MockRpc::new(Some(103)), Vec::new(), options())
            .await
            .expect_err("broken finality parent must fail");
        assert!(format!("{error:#}").contains("hash-linked chain"));
    }

    #[test]
    fn registry_index_parser_requires_canonical_bounded_ordering() {
        assert_eq!(parse_registered_miners("~").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_registered_miners("miner-a,miner-b").unwrap(),
            vec!["miner-a".to_string(), "miner-b".to_string()]
        );
        assert!(parse_registered_miners("miner-b,miner-a").is_err());
        assert!(parse_registered_miners("miner-a,miner-a").is_err());
        assert!(parse_registered_miners("Miner-a").is_err());
    }
}
