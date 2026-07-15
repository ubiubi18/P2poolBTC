use crate::{canonical_json, hash_hex, sha256_tagged};
use bitcoin::pow::{CompactTarget, Target};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FORK_ACTIVATION_SCHEMA_VERSION: u16 = 2;
pub const FORK_TRANSACTION_UPGRADE_SCHEMA_VERSION: u16 = 1;
pub const BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2_016;
pub const DEFAULT_BOOTSTRAP_HANDOFF_HASHRATE_HPS: u64 = 1_000_000_000_000_000;
pub const DEFAULT_FORK_COINBASE_MATURITY: u64 = 100;
pub const DEFAULT_FORK_MAX_BLOCK_TRANSACTIONS: u32 = 1_000;
pub const DEFAULT_FORK_MAX_TRANSACTION_WEIGHT_WU: u64 = 400_000;
const FORK_ACTIVATION_HASH_TAG: &[u8] = b"POHW1_FORK_ACTIVATION";
const FORK_TRANSACTION_UPGRADE_HASH_TAG: &[u8] = b"POHW1_FORK_TRANSACTION_UPGRADE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkDifficultyAlgorithm {
    #[serde(rename = "bootstrap_then_bitcoin_2016_v1")]
    BootstrapThenBitcoin2016V1,
}

impl ForkDifficultyAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapThenBitcoin2016V1 => "bootstrap_then_bitcoin_2016_v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkTransactionConsensus {
    #[serde(rename = "pohw_segwit_keypath_v1")]
    SegwitKeypathV1,
}

impl ForkTransactionConsensus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SegwitKeypathV1 => "pohw_segwit_keypath_v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkConfig {
    pub chain_name: String,
    pub launch_timestamp_utc: DateTime<Utc>,
    pub inherited_utxo_spending_enabled: bool,
    pub post_fork_pow_limit_bits: u32,
    pub target_spacing_seconds: u64,
    pub difficulty_algorithm: ForkDifficultyAlgorithm,
    pub bootstrap_handoff_hashrate_hps: u64,
}

impl ForkConfig {
    pub fn no_value_testnet(
        chain_name: impl Into<String>,
        launch_timestamp_utc: DateTime<Utc>,
    ) -> Self {
        Self {
            chain_name: chain_name.into(),
            launch_timestamp_utc,
            inherited_utxo_spending_enabled: false,
            post_fork_pow_limit_bits: 0x207f_ffff,
            target_spacing_seconds: 600,
            difficulty_algorithm: ForkDifficultyAlgorithm::BootstrapThenBitcoin2016V1,
            bootstrap_handoff_hashrate_hps: DEFAULT_BOOTSTRAP_HANDOFF_HASHRATE_HPS,
        }
    }

    pub fn post_fork_pow_limit_bits_hex(&self) -> String {
        format!("{:08x}", self.post_fork_pow_limit_bits)
    }

    pub fn bitcoin_retarget_timespan_seconds(&self) -> Option<u64> {
        self.target_spacing_seconds
            .checked_mul(BITCOIN_DIFFICULTY_ADJUSTMENT_INTERVAL)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainnetBlockRef {
    pub height: u64,
    pub block_hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkPoint {
    pub inherited_tip_height: u64,
    pub inherited_tip_hash: String,
    pub first_fork_height: u64,
    pub launch_timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkActivationManifest {
    pub schema_version: u16,
    pub activation_id: String,
    pub config: ForkConfig,
    pub fork_point: ForkPoint,
    pub launch_block: MainnetBlockRef,
    pub replay_protection_required: bool,
}

#[derive(Debug, Serialize)]
struct ForkActivationPayload<'a> {
    schema_version: u16,
    config: &'a ForkConfig,
    fork_point: &'a ForkPoint,
    launch_block: &'a MainnetBlockRef,
    replay_protection_required: bool,
}

impl ForkActivationManifest {
    pub fn new(
        config: ForkConfig,
        fork_point: ForkPoint,
        launch_block: MainnetBlockRef,
    ) -> Result<Self, ForkError> {
        if fork_point.launch_timestamp_utc != config.launch_timestamp_utc {
            return Err(ForkError::ConfigLaunchTimestampMismatch);
        }
        let expected_first_fork_height = fork_point
            .inherited_tip_height
            .checked_add(1)
            .ok_or(ForkError::ForkPointHeightOverflow)?;
        if fork_point.first_fork_height != expected_first_fork_height {
            return Err(ForkError::ForkPointHeightMismatch {
                inherited_tip_height: fork_point.inherited_tip_height,
                first_fork_height: fork_point.first_fork_height,
            });
        }
        if launch_block.height != fork_point.first_fork_height {
            return Err(ForkError::LaunchBlockHeightMismatch {
                expected: fork_point.first_fork_height,
                actual: launch_block.height,
            });
        }
        if launch_block.timestamp < config.launch_timestamp_utc {
            return Err(ForkError::LaunchBlockBeforeLaunchTimestamp);
        }
        let chain_name = validate_chain_name(&config.chain_name)?;
        if config.target_spacing_seconds < 4 {
            return Err(ForkError::InvalidTargetSpacing);
        }
        if config
            .bitcoin_retarget_timespan_seconds()
            .and_then(|timespan| timespan.checked_mul(4))
            .is_none()
        {
            return Err(ForkError::BitcoinRetargetTimespanOverflow);
        }
        if config.bootstrap_handoff_hashrate_hps == 0 {
            return Err(ForkError::InvalidBootstrapHandoffHashrate);
        }
        let pow_limit_bits = CompactTarget::from_consensus(config.post_fork_pow_limit_bits);
        if config.post_fork_pow_limit_bits >> 24 > 32 {
            return Err(ForkError::InvalidPostForkPowLimitBits);
        }
        let pow_limit = Target::from_compact(pow_limit_bits);
        if pow_limit == Target::ZERO {
            return Err(ForkError::InvalidPostForkPowLimitBits);
        }
        if pow_limit.to_compact_lossy() != pow_limit_bits {
            return Err(ForkError::NonCanonicalPostForkPowLimitBits);
        }

        let config = ForkConfig {
            chain_name,
            launch_timestamp_utc: config.launch_timestamp_utc,
            inherited_utxo_spending_enabled: config.inherited_utxo_spending_enabled,
            post_fork_pow_limit_bits: config.post_fork_pow_limit_bits,
            target_spacing_seconds: config.target_spacing_seconds,
            difficulty_algorithm: config.difficulty_algorithm,
            bootstrap_handoff_hashrate_hps: config.bootstrap_handoff_hashrate_hps,
        };
        let fork_point = ForkPoint {
            inherited_tip_height: fork_point.inherited_tip_height,
            inherited_tip_hash: normalize_hash_hex(
                "fork_point.inherited_tip_hash",
                &fork_point.inherited_tip_hash,
            )?,
            first_fork_height: fork_point.first_fork_height,
            launch_timestamp_utc: fork_point.launch_timestamp_utc,
        };
        let launch_block = MainnetBlockRef {
            height: launch_block.height,
            block_hash: normalize_hash_hex("launch_block.block_hash", &launch_block.block_hash)?,
            timestamp: launch_block.timestamp,
        };
        let replay_protection_required = !config.inherited_utxo_spending_enabled;
        let payload = ForkActivationPayload {
            schema_version: FORK_ACTIVATION_SCHEMA_VERSION,
            config: &config,
            fork_point: &fork_point,
            launch_block: &launch_block,
            replay_protection_required,
        };
        let activation_id = hash_hex(sha256_tagged(
            FORK_ACTIVATION_HASH_TAG,
            &canonical_json(&payload),
        ));

        Ok(Self {
            schema_version: FORK_ACTIVATION_SCHEMA_VERSION,
            activation_id,
            config,
            fork_point,
            launch_block,
            replay_protection_required,
        })
    }

    pub fn validate(&self) -> Result<(), ForkError> {
        let canonical = Self::new(
            self.config.clone(),
            self.fork_point.clone(),
            self.launch_block.clone(),
        )?;
        if canonical != *self {
            return Err(ForkError::ManifestIntegrityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkTransactionUpgradeManifest {
    pub schema_version: u16,
    pub upgrade_id: String,
    pub base_activation_id: String,
    pub activation_height: u64,
    pub transaction_consensus: ForkTransactionConsensus,
    pub inherited_utxo_spending_enabled: bool,
    pub coinbase_maturity: u64,
    pub max_block_transactions: u32,
    pub max_transaction_weight_wu: u64,
}

#[derive(Debug, Serialize)]
struct ForkTransactionUpgradePayload<'a> {
    schema_version: u16,
    base_activation_id: &'a str,
    activation_height: u64,
    transaction_consensus: ForkTransactionConsensus,
    inherited_utxo_spending_enabled: bool,
    coinbase_maturity: u64,
    max_block_transactions: u32,
    max_transaction_weight_wu: u64,
}

impl ForkTransactionUpgradeManifest {
    pub fn segwit_keypath_v1(
        base_activation_id: impl AsRef<str>,
        activation_height: u64,
    ) -> Result<Self, ForkError> {
        Self::new(
            base_activation_id,
            activation_height,
            ForkTransactionConsensus::SegwitKeypathV1,
            DEFAULT_FORK_COINBASE_MATURITY,
            DEFAULT_FORK_MAX_BLOCK_TRANSACTIONS,
            DEFAULT_FORK_MAX_TRANSACTION_WEIGHT_WU,
        )
    }

    pub fn new(
        base_activation_id: impl AsRef<str>,
        activation_height: u64,
        transaction_consensus: ForkTransactionConsensus,
        coinbase_maturity: u64,
        max_block_transactions: u32,
        max_transaction_weight_wu: u64,
    ) -> Result<Self, ForkError> {
        let base_activation_id = normalize_hash_hex(
            "transaction_upgrade.base_activation_id",
            base_activation_id.as_ref(),
        )?;
        if activation_height == 0 {
            return Err(ForkError::InvalidTransactionActivationHeight);
        }
        if coinbase_maturity == 0 || coinbase_maturity > 10_000 {
            return Err(ForkError::InvalidCoinbaseMaturity);
        }
        if !(2..=100_000).contains(&max_block_transactions) {
            return Err(ForkError::InvalidMaxBlockTransactions);
        }
        if !(400..=4_000_000).contains(&max_transaction_weight_wu) {
            return Err(ForkError::InvalidMaxTransactionWeight);
        }
        let inherited_utxo_spending_enabled = false;
        let payload = ForkTransactionUpgradePayload {
            schema_version: FORK_TRANSACTION_UPGRADE_SCHEMA_VERSION,
            base_activation_id: &base_activation_id,
            activation_height,
            transaction_consensus,
            inherited_utxo_spending_enabled,
            coinbase_maturity,
            max_block_transactions,
            max_transaction_weight_wu,
        };
        let upgrade_id = hash_hex(sha256_tagged(
            FORK_TRANSACTION_UPGRADE_HASH_TAG,
            &canonical_json(&payload),
        ));
        Ok(Self {
            schema_version: FORK_TRANSACTION_UPGRADE_SCHEMA_VERSION,
            upgrade_id,
            base_activation_id,
            activation_height,
            transaction_consensus,
            inherited_utxo_spending_enabled,
            coinbase_maturity,
            max_block_transactions,
            max_transaction_weight_wu,
        })
    }

    pub fn validate(&self) -> Result<(), ForkError> {
        let canonical = Self::new(
            &self.base_activation_id,
            self.activation_height,
            self.transaction_consensus,
            self.coinbase_maturity,
            self.max_block_transactions,
            self.max_transaction_weight_wu,
        )?;
        if canonical != *self {
            return Err(ForkError::TransactionUpgradeIntegrityMismatch);
        }
        Ok(())
    }

    pub fn validate_for(&self, activation: &ForkActivationManifest) -> Result<(), ForkError> {
        self.validate()?;
        activation.validate()?;
        if self.base_activation_id != activation.activation_id {
            return Err(ForkError::TransactionUpgradeBaseMismatch);
        }
        if self.activation_height <= activation.fork_point.first_fork_height {
            return Err(ForkError::TransactionUpgradeDoesNotPreserveLaunchRules);
        }
        if self.inherited_utxo_spending_enabled {
            return Err(ForkError::InheritedUtxoSpendingNotAllowed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForkError {
    #[error("no Bitcoin mainnet block at or after launch timestamp was provided")]
    MissingLaunchBlock,
    #[error("launch block height 0 cannot be used because there is no inherited parent")]
    LaunchBlockHasNoParent,
    #[error("fork point first fork height overflows u64")]
    ForkPointHeightOverflow,
    #[error("fork point heights are not contiguous: inherited tip {inherited_tip_height}, first fork {first_fork_height}")]
    ForkPointHeightMismatch {
        inherited_tip_height: u64,
        first_fork_height: u64,
    },
    #[error("fork config launch timestamp does not match selected fork point")]
    ConfigLaunchTimestampMismatch,
    #[error("launch block height mismatch: expected {expected}, got {actual}")]
    LaunchBlockHeightMismatch { expected: u64, actual: u64 },
    #[error("launch block timestamp is before launch timestamp")]
    LaunchBlockBeforeLaunchTimestamp,
    #[error("chain name must be 1-64 ASCII letters, digits, '.', '_' or '-'")]
    InvalidChainName,
    #[error("target spacing seconds must be at least 4 so the 1/4x retarget bound is nonzero")]
    InvalidTargetSpacing,
    #[error("target spacing is too large for a 2016-block Bitcoin retarget period")]
    BitcoinRetargetTimespanOverflow,
    #[error("bootstrap handoff hashrate must be greater than zero")]
    InvalidBootstrapHandoffHashrate,
    #[error("post-fork compact PoW limit bits decode to an impossible zero target")]
    InvalidPostForkPowLimitBits,
    #[error("post-fork compact PoW limit bits are not canonically encoded")]
    NonCanonicalPostForkPowLimitBits,
    #[error("fork activation manifest fields or activation_id are not canonical")]
    ManifestIntegrityMismatch,
    #[error("fork transaction activation height must be greater than zero")]
    InvalidTransactionActivationHeight,
    #[error("fork coinbase maturity must be between 1 and 10000 blocks")]
    InvalidCoinbaseMaturity,
    #[error("fork max block transaction count must be between 2 and 100000")]
    InvalidMaxBlockTransactions,
    #[error("fork max transaction weight must be between 400 and 4000000 weight units")]
    InvalidMaxTransactionWeight,
    #[error("fork transaction upgrade fields or upgrade_id are not canonical")]
    TransactionUpgradeIntegrityMismatch,
    #[error("fork transaction upgrade belongs to another base activation")]
    TransactionUpgradeBaseMismatch,
    #[error("fork transaction upgrade must activate after the first fork block")]
    TransactionUpgradeDoesNotPreserveLaunchRules,
    #[error("fork transaction upgrade must not enable inherited Bitcoin UTXO spending")]
    InheritedUtxoSpendingNotAllowed,
    #[error("{field} must be 32 bytes encoded as 64 hex characters")]
    InvalidBlockHash { field: &'static str },
}

pub fn select_fork_point(
    launch_timestamp_utc: DateTime<Utc>,
    ordered_mainnet_blocks: &[MainnetBlockRef],
) -> Result<ForkPoint, ForkError> {
    let launch_idx = ordered_mainnet_blocks
        .iter()
        .position(|block| block.timestamp >= launch_timestamp_utc)
        .ok_or(ForkError::MissingLaunchBlock)?;

    if launch_idx == 0 {
        return Err(ForkError::LaunchBlockHasNoParent);
    }

    let inherited_tip = &ordered_mainnet_blocks[launch_idx - 1];
    let launch_block = &ordered_mainnet_blocks[launch_idx];
    let first_fork_height = inherited_tip
        .height
        .checked_add(1)
        .ok_or(ForkError::ForkPointHeightOverflow)?;
    if launch_block.height != first_fork_height {
        return Err(ForkError::ForkPointHeightMismatch {
            inherited_tip_height: inherited_tip.height,
            first_fork_height: launch_block.height,
        });
    }

    Ok(ForkPoint {
        inherited_tip_height: inherited_tip.height,
        inherited_tip_hash: normalize_hash_hex(
            "inherited_tip.block_hash",
            &inherited_tip.block_hash,
        )?,
        first_fork_height,
        launch_timestamp_utc,
    })
}

fn validate_chain_name(raw: &str) -> Result<String, ForkError> {
    if raw.is_empty() || raw.len() > 64 {
        return Err(ForkError::InvalidChainName);
    }
    if !raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ForkError::InvalidChainName);
    }
    Ok(raw.to_string())
}

fn normalize_hash_hex(field: &'static str, raw: &str) -> Result<String, ForkError> {
    let value = raw.to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ForkError::InvalidBlockHash { field });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn fork_point_uses_parent_before_first_block_after_launch() {
        let blocks = vec![
            MainnetBlockRef {
                height: 10,
                block_hash: "aa".repeat(32),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap(),
            },
            MainnetBlockRef {
                height: 11,
                block_hash: "bb".repeat(32),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 10, 0).unwrap(),
            },
        ];

        let point = select_fork_point(Utc.with_ymd_and_hms(2026, 6, 29, 0, 5, 0).unwrap(), &blocks)
            .unwrap();

        assert_eq!(point.inherited_tip_height, 10);
        assert_eq!(point.inherited_tip_hash, "aa".repeat(32));
        assert_eq!(point.first_fork_height, 11);
    }

    #[test]
    fn fork_point_rejects_non_contiguous_launch_blocks() {
        let blocks = vec![
            MainnetBlockRef {
                height: 10,
                block_hash: "aa".repeat(32),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap(),
            },
            MainnetBlockRef {
                height: 12,
                block_hash: "bb".repeat(32),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 10, 0).unwrap(),
            },
        ];

        assert_eq!(
            select_fork_point(Utc.with_ymd_and_hms(2026, 6, 29, 0, 5, 0).unwrap(), &blocks)
                .unwrap_err(),
            ForkError::ForkPointHeightMismatch {
                inherited_tip_height: 10,
                first_fork_height: 12
            }
        );
    }

    #[test]
    fn no_value_testnet_config_requires_replay_protection() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let config = ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp);
        let fork_point = ForkPoint {
            inherited_tip_height: 100,
            inherited_tip_hash: "AA".repeat(32),
            first_fork_height: 101,
            launch_timestamp_utc: launch_timestamp,
        };
        let launch_block = MainnetBlockRef {
            height: 101,
            block_hash: "BB".repeat(32),
            timestamp: Utc.with_ymd_and_hms(2026, 7, 5, 0, 1, 0).unwrap(),
        };

        let manifest =
            ForkActivationManifest::new(config, fork_point, launch_block).expect("manifest");

        assert!(manifest.replay_protection_required);
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.config.post_fork_pow_limit_bits_hex(), "207fffff");
        assert_eq!(
            manifest.config.difficulty_algorithm,
            ForkDifficultyAlgorithm::BootstrapThenBitcoin2016V1
        );
        assert_eq!(
            manifest.config.bootstrap_handoff_hashrate_hps,
            DEFAULT_BOOTSTRAP_HANDOFF_HASHRATE_HPS
        );
        assert_eq!(manifest.fork_point.inherited_tip_hash, "aa".repeat(32));
        assert_eq!(manifest.launch_block.block_hash, "bb".repeat(32));
    }

    #[test]
    fn activation_id_is_deterministic_and_commits_to_chain_params() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let config = ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp);
        let fork_point = ForkPoint {
            inherited_tip_height: 100,
            inherited_tip_hash: "aa".repeat(32),
            first_fork_height: 101,
            launch_timestamp_utc: launch_timestamp,
        };
        let launch_block = MainnetBlockRef {
            height: 101,
            block_hash: "bb".repeat(32),
            timestamp: Utc.with_ymd_and_hms(2026, 7, 5, 0, 1, 0).unwrap(),
        };

        let first =
            ForkActivationManifest::new(config.clone(), fork_point.clone(), launch_block.clone())
                .expect("manifest");
        let second =
            ForkActivationManifest::new(config.clone(), fork_point.clone(), launch_block.clone())
                .expect("manifest");
        let mut changed = config;
        changed.target_spacing_seconds = 120;
        let changed =
            ForkActivationManifest::new(changed, fork_point, launch_block).expect("manifest");

        let mut threshold_changed_config = first.config.clone();
        threshold_changed_config.bootstrap_handoff_hashrate_hps += 1;
        let threshold_changed = ForkActivationManifest::new(
            threshold_changed_config,
            first.fork_point.clone(),
            first.launch_block.clone(),
        )
        .expect("manifest");

        assert_eq!(first.activation_id, second.activation_id);
        assert_eq!(
            first.activation_id,
            "eaa1046d1f672b49edcb0fe31ae17545da98ea73405d65a81ac668bd6684a841"
        );
        assert_ne!(first.activation_id, changed.activation_id);
        assert_ne!(first.activation_id, threshold_changed.activation_id);
    }

    #[test]
    fn manifest_integrity_validation_rejects_tampering() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let mut manifest = ForkActivationManifest::new(
            ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp),
            ForkPoint {
                inherited_tip_height: 100,
                inherited_tip_hash: "aa".repeat(32),
                first_fork_height: 101,
                launch_timestamp_utc: launch_timestamp,
            },
            MainnetBlockRef {
                height: 101,
                block_hash: "bb".repeat(32),
                timestamp: launch_timestamp,
            },
        )
        .unwrap();
        manifest.activation_id = "cc".repeat(32);

        assert_eq!(
            manifest.validate().unwrap_err(),
            ForkError::ManifestIntegrityMismatch
        );
    }

    #[test]
    fn transaction_upgrade_is_deterministic_and_bound_to_base_activation() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let activation = ForkActivationManifest::new(
            ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp),
            ForkPoint {
                inherited_tip_height: 100,
                inherited_tip_hash: "aa".repeat(32),
                first_fork_height: 101,
                launch_timestamp_utc: launch_timestamp,
            },
            MainnetBlockRef {
                height: 101,
                block_hash: "bb".repeat(32),
                timestamp: launch_timestamp,
            },
        )
        .unwrap();

        let first =
            ForkTransactionUpgradeManifest::segwit_keypath_v1(&activation.activation_id, 110)
                .unwrap();
        let second =
            ForkTransactionUpgradeManifest::segwit_keypath_v1(&activation.activation_id, 110)
                .unwrap();
        let later =
            ForkTransactionUpgradeManifest::segwit_keypath_v1(&activation.activation_id, 111)
                .unwrap();

        first.validate_for(&activation).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.upgrade_id, later.upgrade_id);
        assert!(!first.inherited_utxo_spending_enabled);
        assert_eq!(
            first.transaction_consensus,
            ForkTransactionConsensus::SegwitKeypathV1
        );
    }

    #[test]
    fn transaction_upgrade_rejects_tampering_wrong_base_and_launch_rewrite() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let activation = ForkActivationManifest::new(
            ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp),
            ForkPoint {
                inherited_tip_height: 100,
                inherited_tip_hash: "aa".repeat(32),
                first_fork_height: 101,
                launch_timestamp_utc: launch_timestamp,
            },
            MainnetBlockRef {
                height: 101,
                block_hash: "bb".repeat(32),
                timestamp: launch_timestamp,
            },
        )
        .unwrap();
        let mut tampered =
            ForkTransactionUpgradeManifest::segwit_keypath_v1(&activation.activation_id, 110)
                .unwrap();
        tampered.coinbase_maturity += 1;
        assert_eq!(
            tampered.validate().unwrap_err(),
            ForkError::TransactionUpgradeIntegrityMismatch
        );

        let wrong_base =
            ForkTransactionUpgradeManifest::segwit_keypath_v1("cc".repeat(32), 110).unwrap();
        assert_eq!(
            wrong_base.validate_for(&activation).unwrap_err(),
            ForkError::TransactionUpgradeBaseMismatch
        );

        let launch_rewrite = ForkTransactionUpgradeManifest::segwit_keypath_v1(
            &activation.activation_id,
            activation.fork_point.first_fork_height,
        )
        .unwrap();
        assert_eq!(
            launch_rewrite.validate_for(&activation).unwrap_err(),
            ForkError::TransactionUpgradeDoesNotPreserveLaunchRules
        );
    }

    #[test]
    fn activation_manifest_rejects_malformed_coordination_fields() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let valid_config = ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp);
        let valid_fork_point = ForkPoint {
            inherited_tip_height: 100,
            inherited_tip_hash: "aa".repeat(32),
            first_fork_height: 101,
            launch_timestamp_utc: launch_timestamp,
        };
        let valid_launch_block = MainnetBlockRef {
            height: 101,
            block_hash: "bb".repeat(32),
            timestamp: Utc.with_ymd_and_hms(2026, 7, 5, 0, 1, 0).unwrap(),
        };

        let mut bad_config = valid_config.clone();
        bad_config.chain_name = "pohw experiment".to_string();
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidChainName
        );

        let mut bad_config = valid_config.clone();
        bad_config.target_spacing_seconds = 0;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidTargetSpacing
        );

        let mut bad_config = valid_config.clone();
        bad_config.target_spacing_seconds = 3;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidTargetSpacing
        );

        let mut bad_config = valid_config.clone();
        bad_config.target_spacing_seconds = u64::MAX;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::BitcoinRetargetTimespanOverflow
        );

        let mut bad_config = valid_config.clone();
        bad_config.bootstrap_handoff_hashrate_hps = 0;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidBootstrapHandoffHashrate
        );

        let mut bad_config = valid_config.clone();
        bad_config.post_fork_pow_limit_bits = 0;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidPostForkPowLimitBits
        );

        let mut bad_config = valid_config.clone();
        bad_config.post_fork_pow_limit_bits = 0xff00_0001;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidPostForkPowLimitBits
        );

        let mut bad_config = valid_config.clone();
        bad_config.post_fork_pow_limit_bits = 0x0200_0100;
        assert_eq!(
            ForkActivationManifest::new(
                bad_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::NonCanonicalPostForkPowLimitBits
        );

        let mut bad_fork_point = valid_fork_point.clone();
        bad_fork_point.first_fork_height = 102;
        assert_eq!(
            ForkActivationManifest::new(
                valid_config.clone(),
                bad_fork_point,
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::ForkPointHeightMismatch {
                inherited_tip_height: 100,
                first_fork_height: 102
            }
        );

        let mut bad_fork_point = valid_fork_point.clone();
        bad_fork_point.inherited_tip_hash = "0xaa".to_string();
        assert_eq!(
            ForkActivationManifest::new(
                valid_config.clone(),
                bad_fork_point,
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::InvalidBlockHash {
                field: "fork_point.inherited_tip_hash"
            }
        );

        let mut bad_launch_block = valid_launch_block.clone();
        bad_launch_block.block_hash = "not-hex".to_string();
        assert_eq!(
            ForkActivationManifest::new(valid_config, valid_fork_point, bad_launch_block)
                .unwrap_err(),
            ForkError::InvalidBlockHash {
                field: "launch_block.block_hash"
            }
        );
    }

    #[test]
    fn activation_manifest_rejects_inconsistent_launch_metadata() {
        let launch_timestamp = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        let valid_config = ForkConfig::no_value_testnet("pohw-experiment-0", launch_timestamp);
        let valid_fork_point = ForkPoint {
            inherited_tip_height: 100,
            inherited_tip_hash: "aa".repeat(32),
            first_fork_height: 101,
            launch_timestamp_utc: launch_timestamp,
        };
        let valid_launch_block = MainnetBlockRef {
            height: 101,
            block_hash: "bb".repeat(32),
            timestamp: Utc.with_ymd_and_hms(2026, 7, 5, 0, 1, 0).unwrap(),
        };

        let mut mismatched_config = valid_config.clone();
        mismatched_config.launch_timestamp_utc = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 1).unwrap();
        assert_eq!(
            ForkActivationManifest::new(
                mismatched_config,
                valid_fork_point.clone(),
                valid_launch_block.clone()
            )
            .unwrap_err(),
            ForkError::ConfigLaunchTimestampMismatch
        );

        let mut wrong_height_launch_block = valid_launch_block.clone();
        wrong_height_launch_block.height = 102;
        assert_eq!(
            ForkActivationManifest::new(
                valid_config.clone(),
                valid_fork_point.clone(),
                wrong_height_launch_block
            )
            .unwrap_err(),
            ForkError::LaunchBlockHeightMismatch {
                expected: 101,
                actual: 102
            }
        );

        let mut early_launch_block = valid_launch_block;
        early_launch_block.timestamp = Utc.with_ymd_and_hms(2026, 7, 4, 23, 59, 59).unwrap();
        assert_eq!(
            ForkActivationManifest::new(valid_config, valid_fork_point, early_launch_block)
                .unwrap_err(),
            ForkError::LaunchBlockBeforeLaunchTimestamp
        );
    }

    #[test]
    fn fork_point_rejects_malformed_inherited_tip_hash() {
        let blocks = vec![
            MainnetBlockRef {
                height: 10,
                block_hash: "not-a-block-hash".to_string(),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).unwrap(),
            },
            MainnetBlockRef {
                height: 11,
                block_hash: "bb".repeat(32),
                timestamp: Utc.with_ymd_and_hms(2026, 6, 29, 0, 10, 0).unwrap(),
            },
        ];

        assert_eq!(
            select_fork_point(Utc.with_ymd_and_hms(2026, 6, 29, 0, 5, 0).unwrap(), &blocks)
                .unwrap_err(),
            ForkError::InvalidBlockHash {
                field: "inherited_tip.block_hash"
            }
        );
    }
}
