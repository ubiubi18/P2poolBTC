import { u128Safe as u128 } from "as-bignum/assembly";
import { currentBlock, currentEpoch, getString, hasKey, removeKey, setString } from "./host";
import { parseAmount, parseU16 } from "./math";

export const TOTAL_WEIGHT_KEY = "governance:total-weight";
export const WEIGHT_LAST_CHANGED_BLOCK_KEY = "governance:weight-last-changed-block";
export const WEIGHT_EPOCH_KEY = "governance:weight-epoch";
export const SCHEDULED_WEIGHT_EPOCH_KEY = "governance:scheduled-weight-epoch";
export const SCHEDULED_WEIGHT_DELTA_KEY = "governance:scheduled-weight-delta";

export function replaceGlobalWeight(oldWeight: u128, newWeight: u128): void {
  if (oldWeight == newWeight) return;
  const current = parseAmount(getString(TOTAL_WEIGHT_KEY));
  assert(current >= oldWeight, "global registered weight underflow");
  const base = current - oldWeight;
  const replacement = base + newWeight;
  assert(replacement >= base, "global registered weight overflow");
  setString(TOTAL_WEIGHT_KEY, replacement.toString());
  setString(WEIGHT_LAST_CHANGED_BLOCK_KEY, currentBlock().toString());
}

export function replaceScheduledWeightDelta(
  activationEpoch: u16,
  oldDelta: u128,
  newDelta: u128,
): void {
  if (activationEpoch <= storedU16(WEIGHT_EPOCH_KEY)) {
    const currentWeight = parseAmount(getString(TOTAL_WEIGHT_KEY));
    assert(currentWeight >= oldDelta, "replayed governance weight underflow");
    const base = currentWeight - oldDelta;
    const replacement = base + newDelta;
    assert(replacement >= base, "replayed governance weight overflow");
    setString(TOTAL_WEIGHT_KEY, replacement.toString());
    if (replacement != currentWeight) {
      setString(WEIGHT_LAST_CHANGED_BLOCK_KEY, currentBlock().toString());
    }
    return;
  }
  if (hasKey(SCHEDULED_WEIGHT_EPOCH_KEY)) {
    assert(
      storedU16(SCHEDULED_WEIGHT_EPOCH_KEY) == activationEpoch,
      "multiple unsettled governance weight epochs are not permitted",
    );
  } else {
    setString(SCHEDULED_WEIGHT_EPOCH_KEY, activationEpoch.toString());
  }
  const current = hasKey(SCHEDULED_WEIGHT_DELTA_KEY)
    ? parseAmount(getString(SCHEDULED_WEIGHT_DELTA_KEY))
    : u128.Zero;
  assert(current >= oldDelta, "scheduled governance weight underflow");
  const base = current - oldDelta;
  const replacement = base + newDelta;
  assert(replacement >= base, "scheduled governance weight overflow");
  setString(SCHEDULED_WEIGHT_DELTA_KEY, replacement.toString());
}

export function syncGlobalWeightEpoch(): void {
  const current = currentEpoch();
  const settled = storedU16(WEIGHT_EPOCH_KEY);
  // The production host is monotonic. Returning here keeps read-only replay
  // tools from mutating state at an older checkpoint.
  if (current < settled) return;
  if (hasKey(SCHEDULED_WEIGHT_EPOCH_KEY)) {
    const scheduledEpoch = storedU16(SCHEDULED_WEIGHT_EPOCH_KEY);
    assert(scheduledEpoch > settled, "scheduled governance weight epoch is stale");
    if (scheduledEpoch <= current) {
      const delta = parseAmount(getString(SCHEDULED_WEIGHT_DELTA_KEY));
      const currentWeight = parseAmount(getString(TOTAL_WEIGHT_KEY));
      const replacement = currentWeight + delta;
      assert(replacement >= currentWeight, "settled governance weight overflow");
      setString(TOTAL_WEIGHT_KEY, replacement.toString());
      if (!delta.isZero()) {
        setString(WEIGHT_LAST_CHANGED_BLOCK_KEY, currentBlock().toString());
      }
      removeKey(SCHEDULED_WEIGHT_EPOCH_KEY);
      removeKey(SCHEDULED_WEIGHT_DELTA_KEY);
    }
  }
  if (current != settled) setString(WEIGHT_EPOCH_KEY, current.toString());
}

export function settledGlobalWeightForEpoch(epoch: u16): string {
  assert(currentEpoch() == epoch, "governance weight snapshot uses another chain epoch");
  syncGlobalWeightEpoch();
  assert(storedU16(WEIGHT_EPOCH_KEY) == epoch, "global governance weight is not settled for this epoch");
  if (hasKey(SCHEDULED_WEIGHT_EPOCH_KEY)) {
    assert(
      storedU16(SCHEDULED_WEIGHT_EPOCH_KEY) > epoch,
      "global governance weight has an unsettled activation for this epoch",
    );
  }
  const weight = getString(TOTAL_WEIGHT_KEY);
  assert(weight.length > 0, "global governance weight is not initialized");
  parseAmount(weight);
  return weight;
}

function storedU16(key: string): u16 {
  const value = getString(key);
  assert(value.length > 0, "governance weight epoch is not initialized");
  return parseU16(value);
}
