use crate::fork_chain::{
    ForkAddressSummary, ForkAddressTransactionPage, ForkOutputSpend, ForkTransactionRef, ForkUtxo,
    ForkUtxoPage,
};
use anyhow::{bail, Context, Result};
use bitcoin::{Address, Block, BlockHash, Network, OutPoint, Transaction, TxOut};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const DEFAULT_MAX_BLOCKS: u64 = 60_000;
pub(crate) const DEFAULT_MAX_TRANSACTIONS: usize = 500_000;
pub(crate) const DEFAULT_MAX_OUTPUTS: usize = 2_000_000;
pub(crate) const DEFAULT_MAX_ADDRESSES: usize = 500_000;
pub(crate) const DEFAULT_MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_SCRIPT_BYTES: usize = 10_000;
pub(crate) const DEFAULT_MAX_RETAINED_BYTES: usize = 512 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_WORK_UNITS: u64 = 50_000_000;

// Deterministic payload accounting with headroom for container entries. It is a
// fail-closed budget, not an allocator-specific heap measurement.
const ACCOUNTED_MAP_ENTRY_BYTES: usize = 128;
const ACCOUNTED_ADDRESS_STATE_BYTES: usize = 256;
const ACCOUNTED_OUTPOINT_BYTES: usize = 36;
const ACCOUNTED_TXID_TEXT_BYTES: usize = 64;
const ACCOUNTED_BLOCK_HASH_TEXT_BYTES: usize = 64;
const ACCOUNTED_SCRIPT_TYPE_BYTES: usize = 16;
const SCRIPT_WORK_CHUNK_BYTES: usize = 32;
const BLOCK_WORK_CHUNK_BYTES: usize = 4 * 1024;

const ADDRESS_INDEX_COVERAGE: &str = "active_fork_activity_and_fork_created_utxos";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkAddressIndexLimits {
    pub max_blocks: u64,
    pub max_transactions: usize,
    pub max_outputs: usize,
    pub max_addresses: usize,
    pub max_block_bytes: usize,
    pub max_script_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_work_units: u64,
}

impl ForkAddressIndexLimits {
    pub(crate) fn new(
        max_blocks: u64,
        max_transactions: usize,
        max_outputs: usize,
        max_addresses: usize,
    ) -> Result<Self> {
        if max_blocks == 0 || max_transactions == 0 || max_outputs == 0 || max_addresses == 0 {
            bail!("fork address-index limits must all be greater than zero");
        }
        Ok(Self {
            max_blocks,
            max_transactions,
            max_outputs,
            max_addresses,
            max_block_bytes: DEFAULT_MAX_BLOCK_BYTES,
            max_script_bytes: DEFAULT_MAX_SCRIPT_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_work_units: DEFAULT_MAX_WORK_UNITS,
        })
    }

    #[cfg(test)]
    fn with_resource_limits(
        mut self,
        max_block_bytes: usize,
        max_script_bytes: usize,
        max_retained_bytes: usize,
        max_work_units: u64,
    ) -> Result<Self> {
        if max_block_bytes == 0
            || max_script_bytes == 0
            || max_retained_bytes == 0
            || max_work_units == 0
        {
            bail!("fork address-index resource limits must all be greater than zero");
        }
        self.max_block_bytes = max_block_bytes;
        self.max_script_bytes = max_script_bytes;
        self.max_retained_bytes = max_retained_bytes;
        self.max_work_units = max_work_units;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPreviousOutput {
    pub output: TxOut,
    pub inherited: bool,
}

#[derive(Debug, Clone)]
struct IndexedForkOutput {
    output: TxOut,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ForkUtxoOrderKey {
    height: Reverse<u64>,
    txid: String,
    vout: u32,
}

#[derive(Debug, Clone, Default)]
struct ForkAddressAccumulator {
    transaction_ids: BTreeSet<String>,
    funded_output_count: usize,
    funded_total_sats: u64,
    spent_output_count: usize,
    spent_total_sats: u64,
    inherited_input_count: usize,
    inherited_input_total_sats: u64,
    balance_sats: u64,
    first_seen_height: Option<u64>,
    last_seen_height: Option<u64>,
    transactions: Vec<ForkTransactionRef>,
    utxo_order_by_outpoint: BTreeMap<OutPoint, ForkUtxoOrderKey>,
    utxos_by_order: BTreeMap<ForkUtxoOrderKey, ForkUtxo>,
}

struct BlockAdmission {
    next_block_count: u64,
    next_transaction_count: usize,
    next_output_count: usize,
    next_accounted_retained_bytes: usize,
    next_work_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForkAddressIndexStats {
    pub coverage: String,
    pub first_indexed_height: u64,
    pub indexed_tip_height: u64,
    pub indexed_tip_hash: String,
    pub indexed_block_count: u64,
    pub transaction_count: usize,
    pub output_count: usize,
    pub address_count: usize,
    pub accounted_retained_bytes: usize,
    pub work_units: u64,
    pub limits: ForkAddressIndexLimits,
}

#[derive(Debug, Clone)]
pub(crate) struct ForkAddressIndex {
    first_height: u64,
    inherited_tip_hash: BlockHash,
    tip_height: Option<u64>,
    tip_hash: Option<BlockHash>,
    block_count: u64,
    transaction_count: usize,
    output_count: usize,
    accounted_retained_bytes: usize,
    work_units: u64,
    limits: ForkAddressIndexLimits,
    outputs: BTreeMap<OutPoint, IndexedForkOutput>,
    spends: BTreeMap<OutPoint, ForkOutputSpend>,
    addresses: BTreeMap<String, ForkAddressAccumulator>,
}

impl ForkAddressIndex {
    pub(crate) fn new(
        first_height: u64,
        inherited_tip_hash: BlockHash,
        limits: ForkAddressIndexLimits,
    ) -> Self {
        Self {
            first_height,
            inherited_tip_hash,
            tip_height: None,
            tip_hash: None,
            block_count: 0,
            transaction_count: 0,
            output_count: 0,
            accounted_retained_bytes: 0,
            work_units: 0,
            limits,
            outputs: BTreeMap::new(),
            spends: BTreeMap::new(),
            addresses: BTreeMap::new(),
        }
    }

    pub(crate) fn tip_height(&self) -> Option<u64> {
        self.tip_height
    }

    pub(crate) fn tip_hash(&self) -> Option<BlockHash> {
        self.tip_hash
    }

    pub(crate) fn output(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.outputs.get(outpoint).map(|indexed| &indexed.output)
    }

    pub(crate) fn append_block(
        &mut self,
        height: u64,
        block: &Block,
        previous_outputs: &BTreeMap<OutPoint, ResolvedPreviousOutput>,
    ) -> Result<()> {
        let expected_height = self
            .tip_height
            .map(|tip| tip.saturating_add(1))
            .unwrap_or(self.first_height);
        if height != expected_height {
            bail!("fork address index received a non-contiguous block height");
        }
        let expected_parent = self.tip_hash.unwrap_or(self.inherited_tip_hash);
        if block.header.prev_blockhash != expected_parent {
            bail!("fork address index received a block on a different branch");
        }
        let admission = self.preflight_block(block, previous_outputs)?;

        for (transaction_index, transaction) in block.txdata.iter().enumerate() {
            self.append_transaction(
                height,
                block.block_hash(),
                transaction_index,
                transaction,
                previous_outputs,
            )?;
        }
        self.block_count = admission.next_block_count;
        self.transaction_count = admission.next_transaction_count;
        self.output_count = admission.next_output_count;
        self.accounted_retained_bytes = admission.next_accounted_retained_bytes;
        self.work_units = admission.next_work_units;
        self.tip_height = Some(height);
        self.tip_hash = Some(block.block_hash());
        Ok(())
    }

    fn preflight_block(
        &self,
        block: &Block,
        previous_outputs: &BTreeMap<OutPoint, ResolvedPreviousOutput>,
    ) -> Result<BlockAdmission> {
        let block_bytes = block.total_size();
        if block_bytes > self.limits.max_block_bytes {
            bail!("fork address index exceeded its configured per-block byte limit");
        }

        let next_block_count = self
            .block_count
            .checked_add(1)
            .context("fork address-index block count overflow")?;
        if next_block_count > self.limits.max_blocks {
            bail!("fork address index exceeded its configured block limit");
        }
        let next_transaction_count = self
            .transaction_count
            .checked_add(block.txdata.len())
            .context("fork address-index transaction count overflow")?;
        if next_transaction_count > self.limits.max_transactions {
            bail!("fork address index exceeded its configured transaction limit");
        }

        let mut block_output_count = 0usize;
        let mut added_retained_bytes = 0usize;
        let mut added_work_units = 0u64;
        add_work_units(
            &mut added_work_units,
            work_units_for_bytes(block_bytes, BLOCK_WORK_CHUNK_BYTES)?,
        )?;
        add_work_units(&mut added_work_units, block.txdata.len())?;
        let mut new_addresses = BTreeSet::new();
        let mut seen_outputs = BTreeSet::new();
        let mut seen_spends = BTreeSet::new();

        for transaction in &block.txdata {
            let txid = transaction.compute_txid();
            let txid_string = txid.to_string();
            let mut related_addresses = BTreeSet::new();
            add_work_units(&mut added_work_units, transaction.input.len())?;
            add_work_units(&mut added_work_units, transaction.output.len())?;
            block_output_count = block_output_count
                .checked_add(transaction.output.len())
                .context("fork address-index output count overflow")?;

            if !transaction.is_coinbase() {
                for input in &transaction.input {
                    if self.spends.contains_key(&input.previous_output)
                        || !seen_spends.insert(input.previous_output)
                    {
                        bail!("fork address index observed a duplicate active-chain spend");
                    }
                    let resolved = previous_outputs
                        .get(&input.previous_output)
                        .context("fork address index is missing a previous output")?;
                    validate_script_size(&resolved.output, self.limits.max_script_bytes)?;
                    add_work_units(
                        &mut added_work_units,
                        script_work_units(resolved.output.script_pubkey.len())?,
                    )?;
                    add_accounted_bytes(&mut added_retained_bytes, accounted_spend_bytes())?;
                    if let Some(address) = output_address(&resolved.output) {
                        related_addresses.insert(address);
                    }
                }
            }

            for (vout, output) in transaction.output.iter().enumerate() {
                validate_script_size(output, self.limits.max_script_bytes)?;
                add_work_units(
                    &mut added_work_units,
                    script_work_units(output.script_pubkey.len())?,
                )?;
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).context("fork output index exceeds u32")?,
                };
                if self.outputs.contains_key(&outpoint) || !seen_outputs.insert(outpoint) {
                    bail!("fork address index observed a duplicate transaction output");
                }
                add_accounted_bytes(
                    &mut added_retained_bytes,
                    accounted_indexed_output_bytes(output)?,
                )?;
                if let Some(address) = output_address(output) {
                    related_addresses.insert(address);
                    add_accounted_bytes(&mut added_retained_bytes, accounted_utxo_bytes(output)?)?;
                }
            }

            for address in related_addresses {
                add_work_units(&mut added_work_units, 1)?;
                if !self.addresses.contains_key(&address) && new_addresses.insert(address.clone()) {
                    add_accounted_bytes(
                        &mut added_retained_bytes,
                        accounted_address_bytes(&address)?,
                    )?;
                }
                let already_related = self
                    .addresses
                    .get(&address)
                    .is_some_and(|entry| entry.transaction_ids.contains(&txid_string));
                if !already_related {
                    add_accounted_bytes(
                        &mut added_retained_bytes,
                        accounted_transaction_relation_bytes(),
                    )?;
                }
            }
        }

        let next_output_count = self
            .output_count
            .checked_add(block_output_count)
            .context("fork address-index output count overflow")?;
        if next_output_count > self.limits.max_outputs {
            bail!("fork address index exceeded its configured output limit");
        }
        let next_address_count = self
            .addresses
            .len()
            .checked_add(new_addresses.len())
            .context("fork address-index address count overflow")?;
        if next_address_count > self.limits.max_addresses {
            bail!("fork address index exceeded its configured address limit");
        }
        let next_accounted_retained_bytes = self
            .accounted_retained_bytes
            .checked_add(added_retained_bytes)
            .context("fork address-index retained-byte counter overflow")?;
        // Deliberately do not refund spent entries: churn cannot reopen either budget.
        if next_accounted_retained_bytes > self.limits.max_retained_bytes {
            bail!("fork address index exceeded its configured retained-byte budget");
        }
        let next_work_units = self
            .work_units
            .checked_add(added_work_units)
            .context("fork address-index work counter overflow")?;
        if next_work_units > self.limits.max_work_units {
            bail!("fork address index exceeded its configured cumulative work budget");
        }

        Ok(BlockAdmission {
            next_block_count,
            next_transaction_count,
            next_output_count,
            next_accounted_retained_bytes,
            next_work_units,
        })
    }

    fn append_transaction(
        &mut self,
        height: u64,
        block_hash: BlockHash,
        transaction_index: usize,
        transaction: &Transaction,
        previous_outputs: &BTreeMap<OutPoint, ResolvedPreviousOutput>,
    ) -> Result<()> {
        let txid = transaction.compute_txid();
        let txid_string = txid.to_string();
        let mut related_addresses = BTreeSet::new();
        let mut total_input_sats = 0u64;

        if !transaction.is_coinbase() {
            for (vin, input) in transaction.input.iter().enumerate() {
                let resolved = previous_outputs
                    .get(&input.previous_output)
                    .context("fork address index is missing a previous output")?;
                total_input_sats = total_input_sats
                    .checked_add(resolved.output.value.to_sat())
                    .context("fork address-index input total overflow")?;
                if self
                    .spends
                    .insert(
                        input.previous_output,
                        ForkOutputSpend {
                            txid: txid_string.clone(),
                            vin,
                            height,
                        },
                    )
                    .is_some()
                {
                    bail!("fork address index observed a duplicate active-chain spend");
                }
                let Some(address) = output_address(&resolved.output) else {
                    continue;
                };
                self.ensure_address_capacity(&address)?;
                related_addresses.insert(address.clone());
                let accumulator = self.addresses.entry(address).or_default();
                if resolved.inherited {
                    accumulator.inherited_input_count = accumulator
                        .inherited_input_count
                        .checked_add(1)
                        .context("fork inherited-input count overflow")?;
                    accumulator.inherited_input_total_sats = accumulator
                        .inherited_input_total_sats
                        .checked_add(resolved.output.value.to_sat())
                        .context("fork inherited-input total overflow")?;
                } else {
                    accumulator.spent_output_count = accumulator
                        .spent_output_count
                        .checked_add(1)
                        .context("fork spent-output count overflow")?;
                    accumulator.spent_total_sats = accumulator
                        .spent_total_sats
                        .checked_add(resolved.output.value.to_sat())
                        .context("fork spent-output total overflow")?;
                    accumulator.balance_sats = accumulator
                        .balance_sats
                        .checked_sub(resolved.output.value.to_sat())
                        .context("fork-created address balance underflow")?;
                    let order_key = accumulator
                        .utxo_order_by_outpoint
                        .remove(&input.previous_output)
                        .context("fork-created UTXO lookup is missing the spent outpoint")?;
                    accumulator
                        .utxos_by_order
                        .remove(&order_key)
                        .context("fork-created ordered UTXO entry is missing")?;
                }
                update_height_range(accumulator, height);
            }
        }

        for (vout, output) in transaction.output.iter().enumerate() {
            let vout = u32::try_from(vout).context("fork output index exceeds u32")?;
            let outpoint = OutPoint { txid, vout };
            let address = output_address(output);
            if self
                .outputs
                .insert(
                    outpoint,
                    IndexedForkOutput {
                        output: output.clone(),
                    },
                )
                .is_some()
            {
                bail!("fork address index observed a duplicate transaction output");
            }
            let Some(address) = address else {
                continue;
            };
            self.ensure_address_capacity(&address)?;
            related_addresses.insert(address.clone());
            let accumulator = self.addresses.entry(address).or_default();
            accumulator.funded_output_count = accumulator
                .funded_output_count
                .checked_add(1)
                .context("fork funded-output count overflow")?;
            accumulator.funded_total_sats = accumulator
                .funded_total_sats
                .checked_add(output.value.to_sat())
                .context("fork funded-output total overflow")?;
            accumulator.balance_sats = accumulator
                .balance_sats
                .checked_add(output.value.to_sat())
                .context("fork-created address balance overflow")?;
            let order_key = ForkUtxoOrderKey {
                height: Reverse(height),
                txid: txid_string.clone(),
                vout,
            };
            if accumulator
                .utxo_order_by_outpoint
                .insert(outpoint, order_key.clone())
                .is_some()
            {
                bail!("fork address index observed a duplicate UTXO outpoint");
            }
            if accumulator
                .utxos_by_order
                .insert(
                    order_key,
                    ForkUtxo {
                        txid: txid_string.clone(),
                        vout,
                        value_sats: output.value.to_sat(),
                        script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                        script_type: script_type(output),
                        height,
                        coinbase: transaction.is_coinbase(),
                    },
                )
                .is_some()
            {
                bail!("fork address index observed a duplicate ordered UTXO key");
            }
            update_height_range(accumulator, height);
        }

        let total_output_sats = transaction.output.iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.value.to_sat())
                .context("fork transaction output total overflow")
        })?;
        let fee_sats = (!transaction.is_coinbase())
            .then(|| {
                total_input_sats
                    .checked_sub(total_output_sats)
                    .context("fork transaction output exceeds its inputs")
            })
            .transpose()?;
        let transaction_ref = ForkTransactionRef {
            txid: txid_string.clone(),
            block_hash: block_hash.to_string(),
            height,
            active: true,
            transaction_index,
            coinbase: transaction.is_coinbase(),
            total_output_sats,
            fee_sats,
        };
        for address in related_addresses {
            let accumulator = self
                .addresses
                .get_mut(&address)
                .expect("related address was inserted before transaction indexing");
            if accumulator.transaction_ids.insert(txid_string.clone()) {
                accumulator.transactions.push(transaction_ref.clone());
            }
        }
        Ok(())
    }

    fn ensure_address_capacity(&self, address: &str) -> Result<()> {
        if !self.addresses.contains_key(address)
            && self.addresses.len() >= self.limits.max_addresses
        {
            bail!("fork address index exceeded its configured address limit");
        }
        Ok(())
    }

    pub(crate) fn address_summary(&self, address: &str) -> ForkAddressSummary {
        self.addresses
            .get(address)
            .map(|entry| ForkAddressSummary {
                address: address.to_string(),
                transaction_count: entry.transaction_ids.len(),
                funded_output_count: entry.funded_output_count,
                funded_total_sats: entry.funded_total_sats,
                spent_output_count: entry.spent_output_count,
                spent_total_sats: entry.spent_total_sats,
                inherited_input_count: entry.inherited_input_count,
                inherited_input_total_sats: entry.inherited_input_total_sats,
                balance_sats: entry.balance_sats,
                balance_scope: "fork_created_utxos".to_string(),
                first_seen_height: entry.first_seen_height,
                last_seen_height: entry.last_seen_height,
            })
            .unwrap_or_else(|| ForkAddressSummary {
                address: address.to_string(),
                transaction_count: 0,
                funded_output_count: 0,
                funded_total_sats: 0,
                spent_output_count: 0,
                spent_total_sats: 0,
                inherited_input_count: 0,
                inherited_input_total_sats: 0,
                balance_sats: 0,
                balance_scope: "fork_created_utxos".to_string(),
                first_seen_height: None,
                last_seen_height: None,
            })
    }

    pub(crate) fn address_transactions(
        &self,
        address: &str,
        cursor: usize,
        limit: usize,
    ) -> ForkAddressTransactionPage {
        let transactions = self
            .addresses
            .get(address)
            .map(|entry| entry.transactions.as_slice())
            .unwrap_or_default();
        let total = transactions.len();
        let items = transactions
            .iter()
            .rev()
            .skip(cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next = cursor.saturating_add(items.len());
        ForkAddressTransactionPage {
            address: address.to_string(),
            total,
            items,
            next_cursor: (next < total).then_some(next),
        }
    }

    pub(crate) fn address_utxos(&self, address: &str, cursor: usize, limit: usize) -> ForkUtxoPage {
        let utxos = self
            .addresses
            .get(address)
            .map(|entry| &entry.utxos_by_order);
        let total = utxos.map_or(0, BTreeMap::len);
        let items = utxos
            .into_iter()
            .flat_map(|entries| entries.values())
            .skip(cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next = cursor.saturating_add(items.len());
        ForkUtxoPage {
            address: address.to_string(),
            total,
            items,
            next_cursor: (next < total).then_some(next),
        }
    }

    pub(crate) fn spend(&self, outpoint: &OutPoint) -> Option<ForkOutputSpend> {
        self.spends.get(outpoint).cloned()
    }

    pub(crate) fn stats(&self) -> Result<ForkAddressIndexStats> {
        Ok(ForkAddressIndexStats {
            coverage: ADDRESS_INDEX_COVERAGE.to_string(),
            first_indexed_height: self.first_height,
            indexed_tip_height: self.tip_height.context("fork address index has no tip")?,
            indexed_tip_hash: self
                .tip_hash
                .context("fork address index has no tip")?
                .to_string(),
            indexed_block_count: self.block_count,
            transaction_count: self.transaction_count,
            output_count: self.output_count,
            address_count: self.addresses.len(),
            accounted_retained_bytes: self.accounted_retained_bytes,
            work_units: self.work_units,
            limits: self.limits,
        })
    }
}

fn validate_script_size(output: &TxOut, max_script_bytes: usize) -> Result<()> {
    if output.script_pubkey.len() > max_script_bytes {
        bail!("fork address index exceeded its configured script byte limit");
    }
    Ok(())
}

fn add_accounted_bytes(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .context("fork address-index retained-byte accounting overflow")?;
    Ok(())
}

fn add_work_units(total: &mut u64, amount: usize) -> Result<()> {
    let amount = u64::try_from(amount).context("fork address-index work does not fit u64")?;
    *total = total
        .checked_add(amount)
        .context("fork address-index work accounting overflow")?;
    Ok(())
}

fn work_units_for_bytes(bytes: usize, chunk_bytes: usize) -> Result<usize> {
    bytes
        .checked_add(chunk_bytes.saturating_sub(1))
        .map(|rounded| rounded / chunk_bytes)
        .context("fork address-index byte-work accounting overflow")
}

fn script_work_units(script_bytes: usize) -> Result<usize> {
    work_units_for_bytes(script_bytes, SCRIPT_WORK_CHUNK_BYTES)
}

fn accounted_sum(parts: &[usize]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(*part)
            .context("fork address-index retained-byte estimate overflow")
    })
}

fn accounted_indexed_output_bytes(output: &TxOut) -> Result<usize> {
    accounted_sum(&[
        ACCOUNTED_MAP_ENTRY_BYTES,
        ACCOUNTED_OUTPOINT_BYTES,
        std::mem::size_of::<u64>(),
        output.script_pubkey.len(),
    ])
}

fn accounted_spend_bytes() -> usize {
    ACCOUNTED_MAP_ENTRY_BYTES
        + ACCOUNTED_OUTPOINT_BYTES
        + ACCOUNTED_TXID_TEXT_BYTES
        + 2 * std::mem::size_of::<u64>()
}

fn accounted_address_bytes(address: &str) -> Result<usize> {
    accounted_sum(&[
        ACCOUNTED_MAP_ENTRY_BYTES,
        ACCOUNTED_ADDRESS_STATE_BYTES,
        address.len(),
    ])
}

fn accounted_utxo_bytes(output: &TxOut) -> Result<usize> {
    let script_hex_bytes = output
        .script_pubkey
        .len()
        .checked_mul(2)
        .context("fork address-index script hex estimate overflow")?;
    let order_key_bytes = accounted_sum(&[
        std::mem::size_of::<u64>(),
        ACCOUNTED_TXID_TEXT_BYTES,
        std::mem::size_of::<u32>(),
    ])?;
    accounted_sum(&[
        ACCOUNTED_MAP_ENTRY_BYTES,
        ACCOUNTED_OUTPOINT_BYTES,
        order_key_bytes,
        ACCOUNTED_MAP_ENTRY_BYTES,
        order_key_bytes,
        ACCOUNTED_TXID_TEXT_BYTES,
        script_hex_bytes,
        ACCOUNTED_SCRIPT_TYPE_BYTES,
        2 * std::mem::size_of::<u64>(),
        std::mem::size_of::<u32>(),
        std::mem::size_of::<bool>(),
    ])
}

fn accounted_transaction_relation_bytes() -> usize {
    2 * ACCOUNTED_MAP_ENTRY_BYTES
        + 2 * ACCOUNTED_TXID_TEXT_BYTES
        + ACCOUNTED_BLOCK_HASH_TEXT_BYTES
        + 4 * std::mem::size_of::<u64>()
        + 2 * std::mem::size_of::<bool>()
}

fn update_height_range(accumulator: &mut ForkAddressAccumulator, height: u64) {
    accumulator.first_seen_height = Some(
        accumulator
            .first_seen_height
            .map_or(height, |current| current.min(height)),
    );
    accumulator.last_seen_height = Some(
        accumulator
            .last_seen_height
            .map_or(height, |current| current.max(height)),
    );
}

fn output_address(output: &TxOut) -> Option<String> {
    Address::from_script(&output.script_pubkey, Network::Bitcoin)
        .ok()
        .map(|address| address.to_string())
}

fn script_type(output: &TxOut) -> String {
    let script = &output.script_pubkey;
    if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_p2wpkh() {
        "v0_p2wpkh"
    } else if script.is_p2wsh() {
        "v0_p2wsh"
    } else if script.is_p2tr() {
        "v1_p2tr"
    } else if script.is_p2pk() {
        "p2pk"
    } else if script.is_op_return() {
        "op_return"
    } else if script.is_witness_program() {
        "witness_unknown"
    } else {
        "nonstandard"
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TransactionVersion;
    use bitcoin::{Amount, Sequence, TxIn, Witness};

    fn p2pkh(byte: u8) -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([byte; 20]))
    }

    fn coinbase(value: u64, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn coinbase_with_outputs(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        }
    }

    fn spend(previous_output: OutPoint, value: u64, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn block(parent: BlockHash, time: u32, transactions: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: Header {
                version: BlockVersion::from_consensus(0x2000_0000),
                prev_blockhash: parent,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: transactions,
        };
        block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
        block
    }

    fn limits() -> ForkAddressIndexLimits {
        ForkAddressIndexLimits::new(10, 20, 40, 20).unwrap()
    }

    #[test]
    fn indexes_fork_outputs_spends_history_and_utxos() {
        let inherited = BlockHash::from_byte_array([1; 32]);
        let mut index = ForkAddressIndex::new(101, inherited, limits());
        let first_tx = coinbase(50, p2pkh(7));
        let first_outpoint = OutPoint {
            txid: first_tx.compute_txid(),
            vout: 0,
        };
        let first = block(inherited, 1, vec![first_tx.clone()]);
        index.append_block(101, &first, &BTreeMap::new()).unwrap();

        let second_tx = spend(first_outpoint, 40, p2pkh(8));
        let mut previous = BTreeMap::new();
        previous.insert(
            first_outpoint,
            ResolvedPreviousOutput {
                output: first_tx.output[0].clone(),
                inherited: false,
            },
        );
        let second = block(
            first.block_hash(),
            2,
            vec![coinbase(1, p2pkh(9)), second_tx],
        );
        index.append_block(102, &second, &previous).unwrap();

        let source = output_address(&first_tx.output[0]).unwrap();
        let source_summary = index.address_summary(&source);
        assert_eq!(source_summary.transaction_count, 2);
        assert_eq!(source_summary.funded_total_sats, 50);
        assert_eq!(source_summary.spent_total_sats, 50);
        assert_eq!(source_summary.balance_sats, 0);
        assert_eq!(index.address_utxos(&source, 0, 25).total, 0);
        let source_history = index.address_transactions(&source, 0, 25);
        assert_eq!(source_history.items[0].height, 102);
        assert_eq!(source_history.items[0].fee_sats, Some(10));
        assert!(index.spend(&first_outpoint).is_some());

        let destination = output_address(&second.txdata[1].output[0]).unwrap();
        let destination_summary = index.address_summary(&destination);
        assert_eq!(destination_summary.balance_sats, 40);
        assert_eq!(index.address_utxos(&destination, 0, 25).total, 1);
    }

    #[test]
    fn inherited_inputs_are_related_without_becoming_fork_created_balance() {
        let inherited = BlockHash::from_byte_array([2; 32]);
        let mut index = ForkAddressIndex::new(201, inherited, limits());
        let inherited_tx = coinbase(100, p2pkh(3));
        let inherited_outpoint = OutPoint {
            txid: inherited_tx.compute_txid(),
            vout: 0,
        };
        let fork_spend = spend(inherited_outpoint, 90, p2pkh(4));
        let fork_block = block(inherited, 3, vec![coinbase(1, p2pkh(5)), fork_spend]);
        let mut previous = BTreeMap::new();
        previous.insert(
            inherited_outpoint,
            ResolvedPreviousOutput {
                output: inherited_tx.output[0].clone(),
                inherited: true,
            },
        );
        index.append_block(201, &fork_block, &previous).unwrap();

        let source = output_address(&inherited_tx.output[0]).unwrap();
        let summary = index.address_summary(&source);
        assert_eq!(summary.transaction_count, 1);
        assert_eq!(summary.inherited_input_count, 1);
        assert_eq!(summary.inherited_input_total_sats, 100);
        assert_eq!(summary.funded_total_sats, 0);
        assert_eq!(summary.spent_total_sats, 0);
        assert_eq!(summary.balance_sats, 0);
    }

    #[test]
    fn rejects_non_contiguous_branches_and_resource_overrun() {
        let inherited = BlockHash::from_byte_array([6; 32]);
        let mut index = ForkAddressIndex::new(
            301,
            inherited,
            ForkAddressIndexLimits::new(1, 1, 1, 1).unwrap(),
        );
        let first = block(inherited, 4, vec![coinbase(1, p2pkh(1))]);
        index.append_block(301, &first, &BTreeMap::new()).unwrap();
        let second = block(first.block_hash(), 5, vec![coinbase(1, p2pkh(2))]);
        assert!(index
            .append_block(302, &second, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("block limit"));
        assert!(index
            .append_block(303, &second, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("non-contiguous"));
    }

    #[test]
    fn rejects_oversized_scripts_and_blocks_before_mutating_state() {
        let inherited = BlockHash::from_byte_array([7; 32]);
        let limits = ForkAddressIndexLimits::new(3, 3, 3, 3)
            .unwrap()
            .with_resource_limits(1024 * 1024, 100, 1024 * 1024, 10_000)
            .unwrap();
        let mut index = ForkAddressIndex::new(401, inherited, limits);
        let oversized_script = ScriptBuf::from_bytes(vec![0x51; 101]);
        let rejected = block(inherited, 6, vec![coinbase(1, oversized_script)]);
        assert!(index
            .append_block(401, &rejected, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("script byte limit"));
        assert_eq!(index.tip_height(), None);
        assert_eq!(index.accounted_retained_bytes, 0);
        assert_eq!(index.work_units, 0);

        let accepted = block(inherited, 7, vec![coinbase(1, p2pkh(1))]);
        index
            .append_block(401, &accepted, &BTreeMap::new())
            .unwrap();
        assert_eq!(index.tip_height(), Some(401));

        let block_limit = accepted.total_size().saturating_sub(1);
        let limits = ForkAddressIndexLimits::new(1, 1, 1, 1)
            .unwrap()
            .with_resource_limits(block_limit, 10_000, 1024 * 1024, 10_000)
            .unwrap();
        let mut block_limited = ForkAddressIndex::new(401, inherited, limits);
        assert!(block_limited
            .append_block(401, &accepted, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("per-block byte limit"));
        assert_eq!(block_limited.tip_height(), None);
    }

    #[test]
    fn cumulative_retained_byte_and_work_budgets_fail_closed() {
        let inherited = BlockHash::from_byte_array([8; 32]);
        let limits = ForkAddressIndexLimits::new(3, 3, 3, 3)
            .unwrap()
            .with_resource_limits(1024 * 1024, 10_000, 1024 * 1024, 10_000)
            .unwrap();
        let first = block(inherited, 8, vec![coinbase(1, p2pkh(2))]);
        let second = block(first.block_hash(), 9, vec![coinbase(1, p2pkh(3))]);
        let mut index = ForkAddressIndex::new(501, inherited, limits);
        index.append_block(501, &first, &BTreeMap::new()).unwrap();

        let mut retained_limited = index.clone();
        retained_limited.limits.max_retained_bytes = retained_limited.accounted_retained_bytes;
        assert!(retained_limited
            .append_block(502, &second, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("retained-byte budget"));
        assert_eq!(retained_limited.tip_height(), Some(501));

        index.limits.max_work_units = index.work_units;
        assert!(index
            .append_block(502, &second, &BTreeMap::new())
            .unwrap_err()
            .to_string()
            .contains("cumulative work budget"));
        assert_eq!(index.tip_height(), Some(501));
    }

    #[test]
    fn high_cardinality_utxo_pages_preserve_order_and_clone_only_the_page() {
        let inherited = BlockHash::from_byte_array([9; 32]);
        let script = p2pkh(4);
        let outputs = (0..1_024)
            .map(|_| TxOut {
                value: Amount::from_sat(1),
                script_pubkey: script.clone(),
            })
            .collect::<Vec<_>>();
        let first = block(inherited, 10, vec![coinbase_with_outputs(outputs)]);
        let second = block(first.block_hash(), 11, vec![coinbase(1, script.clone())]);
        let limits = ForkAddressIndexLimits::new(2, 2, 1_025, 1)
            .unwrap()
            .with_resource_limits(4 * 1024 * 1024, 10_000, 8 * 1024 * 1024, 1_000_000)
            .unwrap();
        let mut index = ForkAddressIndex::new(601, inherited, limits);
        index.append_block(601, &first, &BTreeMap::new()).unwrap();
        index.append_block(602, &second, &BTreeMap::new()).unwrap();

        let address = output_address(&second.txdata[0].output[0]).unwrap();
        let newest = index.address_utxos(&address, 0, 2);
        assert_eq!(newest.total, 1_025);
        assert_eq!(newest.items.len(), 2);
        assert_eq!(newest.items[0].height, 602);
        assert_eq!(newest.items[1].height, 601);

        let middle = index.address_utxos(&address, 501, 3);
        assert_eq!(middle.total, 1_025);
        assert_eq!(middle.items.len(), 3);
        assert_eq!(
            middle
                .items
                .iter()
                .map(|utxo| utxo.vout)
                .collect::<Vec<_>>(),
            vec![500, 501, 502]
        );
        assert_eq!(middle.next_cursor, Some(504));

        let tail = index.address_utxos(&address, 1_023, 10);
        assert_eq!(tail.items.len(), 2);
        assert_eq!(tail.next_cursor, None);
        let stats = index.stats().unwrap();
        assert!(stats.accounted_retained_bytes <= stats.limits.max_retained_bytes);
        assert!(stats.work_units <= stats.limits.max_work_units);
    }
}
