import assert from "node:assert/strict";
import test from "node:test";
import {
  acceptedSharePercent,
  calculateRewardView,
  chancePercentForDays,
  expectedBlocksForChancePercent
} from "../src/miningEconomics.ts";

const directInput = {
  blockSubsidyBtc: 3.125,
  estimatedFeesBtc: 0,
  combinedRewardWeight: 0.004,
  expectedBlocks30d: expectedBlocksForChancePercent(0.84),
  directPayoutEligible: true,
  directRank: 42,
  directLimit: 100,
  minPayoutSats: 10_000,
  estimatedWithdrawalFeeSats: 96
};

test("30 day EV preserves the payout route selected for an actual block", () => {
  const block = calculateRewardView(directInput, "block-now");
  const expected = calculateRewardView(directInput, "30d-ev");

  assert.equal(block.direct, true);
  assert.equal(block.netSats, 1_250_000);
  assert.equal(expected.direct, true);
  assert.equal(expected.netSats, 10_544);
  assert.equal(expected.feeSats, 0);
});

test("vault fees are deducted from the actual block claim before probability weighting", () => {
  const input = {
    ...directInput,
    combinedRewardWeight: 0.00001,
    directPayoutEligible: false
  };
  const block = calculateRewardView(input, "block-now");
  const expected = calculateRewardView(input, "30d-ev");

  assert.equal(block.grossSats, 3_125);
  assert.equal(block.feeSats, 96);
  assert.equal(block.netSats, 3_029);
  assert.equal(expected.netSats, Math.round(3_029 * expectedBlocksForChancePercent(0.84)));
});

test("vault net value stays unknown until a withdrawal fee is available", () => {
  const view = calculateRewardView({
    ...directInput,
    directPayoutEligible: false,
    estimatedWithdrawalFeeSats: null
  }, "block-now");

  assert.equal(view.direct, false);
  assert.equal(view.feeSats, null);
  assert.equal(view.netSats, null);
  assert.equal(view.grossSats, 1_250_000);
});

test("Poisson chance windows preserve the supplied 30 day chance", () => {
  assert.ok(Math.abs(chancePercentForDays(0.84, 30) - 0.84) < 1e-10);
  assert.ok(chancePercentForDays(0.84, 1) < chancePercentForDays(0.84, 7));
  assert.ok(chancePercentForDays(0.84, 7) < chancePercentForDays(0.84, 365));
  assert.equal(chancePercentForDays(0, 30), 0);
  assert.equal(chancePercentForDays(100, 30), 100);
});

test("expected value uses Poisson expected block count rather than at-least-one probability", () => {
  const probability = 0.84 / 100;
  const expectedBlocks = expectedBlocksForChancePercent(0.84);
  assert.ok(expectedBlocks > probability);
  assert.ok(Math.abs(expectedBlocks + Math.log1p(-probability)) < 1e-12);
});

test("share quality handles empty and mixed histories", () => {
  assert.equal(acceptedSharePercent(0, 0), 0);
  assert.equal(acceptedSharePercent(99, 1), 99);
});
