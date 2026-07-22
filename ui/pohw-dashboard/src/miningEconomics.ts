export const SATS_PER_BTC = 100_000_000;

export type ProspectMode = "block-now" | "30d-ev";

export interface RewardEconomicsInput {
  blockSubsidyBtc: number;
  estimatedFeesBtc: number;
  combinedRewardWeight: number;
  expectedBlocks30d: number;
  directPayoutEligible: boolean;
  directRank: number;
  directLimit: number;
  minPayoutSats: number;
  estimatedWithdrawalFeeSats: number | null;
}

export interface RewardView {
  blockValueBtc: number;
  blockValueSats: number;
  blockGrossSats: number;
  blockFeeSats: number | null;
  blockNetSats: number | null;
  direct: boolean;
  feeSats: number | null;
  grossSats: number;
  netSats: number | null;
  vaultSats: number;
}

function clamp(value: number, minimum: number, maximum: number) {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}

export function calculateRewardView(
  input: RewardEconomicsInput,
  mode: ProspectMode
): RewardView {
  const blockValueBtc = Math.max(0, input.blockSubsidyBtc) + Math.max(0, input.estimatedFeesBtc);
  const blockValueSats = Math.round(blockValueBtc * SATS_PER_BTC);
  const rewardWeight = clamp(input.combinedRewardWeight, 0, 1);
  const blockGrossSats = Math.round(blockValueSats * rewardWeight);
  const direct =
    input.directPayoutEligible &&
    input.directRank <= input.directLimit &&
    blockGrossSats >= input.minPayoutSats;
  const blockVaultSats = direct ? 0 : blockGrossSats;
  const hasFeeEstimate = input.estimatedWithdrawalFeeSats !== null
    && Number.isFinite(input.estimatedWithdrawalFeeSats);
  const blockFeeSats = direct
    ? 0
    : blockVaultSats > 0 && hasFeeEstimate
      ? Math.min(Math.max(0, input.estimatedWithdrawalFeeSats ?? 0), blockVaultSats)
      : blockVaultSats > 0
        ? null
        : 0;
  const blockNetSats = blockFeeSats === null
    ? null
    : direct
      ? blockGrossSats
      : Math.max(0, blockVaultSats - blockFeeSats);
  const expectedBlocks30d = Number.isFinite(input.expectedBlocks30d)
    ? Math.max(0, input.expectedBlocks30d)
    : 0;
  const multiplier = mode === "30d-ev" ? expectedBlocks30d : 1;

  return {
    blockValueBtc,
    blockValueSats,
    blockGrossSats,
    blockFeeSats,
    blockNetSats,
    direct,
    feeSats: blockFeeSats === null ? null : Math.round(blockFeeSats * multiplier),
    grossSats: Math.round(blockGrossSats * multiplier),
    netSats: blockNetSats === null ? null : Math.round(blockNetSats * multiplier),
    vaultSats: Math.round(blockVaultSats * multiplier)
  };
}

export function expectedBlocksForChancePercent(chance30dPercent: number) {
  const probability30d = Math.min(
    clamp(chance30dPercent, 0, 100) / 100,
    1 - Number.EPSILON
  );
  return probability30d <= 0 ? 0 : -Math.log1p(-probability30d);
}

export function chancePercentForDays(chance30dPercent: number, days: number) {
  if (!Number.isFinite(days) || days <= 0) return 0;
  const probability30d = clamp(chance30dPercent, 0, 100) / 100;
  if (probability30d <= 0) return 0;
  if (probability30d >= 1) return 100;
  const expectedBlocks30d = expectedBlocksForChancePercent(chance30dPercent);
  return (1 - Math.exp((-expectedBlocks30d * days) / 30)) * 100;
}

export function acceptedSharePercent(acceptedShares: number, staleShares: number) {
  const accepted = Math.max(0, acceptedShares);
  const stale = Math.max(0, staleShares);
  const total = accepted + stale;
  return total > 0 ? (accepted / total) * 100 : 0;
}
