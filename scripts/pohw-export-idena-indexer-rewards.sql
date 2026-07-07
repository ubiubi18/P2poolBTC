-- Export exact PoHW reward replay events from the official idena-indexer Postgres schema.
--
-- Usage example:
--   psql -qAt "$IDENA_INDEXER_DATABASE_URL" \
--     -f scripts/pohw-export-idena-indexer-rewards.sql \
--     -o /mnt/ssd/p2pool/rewards/statscollector-replay.json
--
-- The output is accepted by:
--   python3 pohw_idena_rpc/idena_reward_indexer.py \
--     --db /mnt/ssd/p2pool/rewards/reward_ledger.sqlite3 \
--     import-statscollector-replay /mnt/ssd/p2pool/rewards/statscollector-replay.json
--
-- Source mapping follows official idena-indexer:
--   validation_rewards: indexer/rewards.go detectEpochRewards() from RewardsStats.Rewards
--   mining_rewards:    indexer/indexer.go convertIncomingData() from StatsCollector.MiningRewards
\set QUIET on
\pset tuples_only on
\pset format unaligned
\pset pager off

WITH exact_rewards AS (
  SELECT
    lower(a.address::text) AS idena_address,
    ei.epoch::bigint AS epoch,
    es.block_height::bigint AS source_height,
    lower(b.hash::text) AS source_hash,
    CASE
      WHEN vr.type IN (2, 5, 6, 7, 8) THEN 'Invitation'
      WHEN vr.type IN (13, 14, 15) THEN 'Invitee'
      WHEN vr.type IN (3, 4) THEN 'Other'
      ELSE 'Validation'
    END AS kind,
    (round((vr.balance + vr.stake) * 1000000000000000000))::numeric(78, 0)::text AS amount_atoms,
    (round(vr.balance * 1000000000000000000))::numeric(78, 0)::text AS balance_atoms,
    (round(vr.stake * 1000000000000000000))::numeric(78, 0)::text AS stake_atoms,
    b."timestamp"::bigint AS timestamp,
    'validation_rewards' AS source_table,
    vr.type::smallint AS reward_type
  FROM validation_rewards vr
  JOIN epoch_identities ei ON ei.address_state_id = vr.ei_address_state_id
  JOIN addresses a ON a.id = ei.address_id
  JOIN epoch_summaries es ON es.epoch = ei.epoch
  JOIN blocks b ON b.height = es.block_height
  WHERE vr.balance + vr.stake > 0

  UNION ALL

  SELECT
    lower(a.address::text) AS idena_address,
    b.epoch::bigint AS epoch,
    mr.block_height::bigint AS source_height,
    lower(b.hash::text) AS source_hash,
    CASE WHEN mr.proposer THEN 'Proposer' ELSE 'FinalCommittee' END AS kind,
    (round((mr.balance + mr.stake) * 1000000000000000000))::numeric(78, 0)::text AS amount_atoms,
    (round(mr.balance * 1000000000000000000))::numeric(78, 0)::text AS balance_atoms,
    (round(mr.stake * 1000000000000000000))::numeric(78, 0)::text AS stake_atoms,
    b."timestamp"::bigint AS timestamp,
    'mining_rewards' AS source_table,
    NULL::smallint AS reward_type
  FROM mining_rewards mr
  JOIN addresses a ON a.id = mr.address_id
  JOIN blocks b ON b.height = mr.block_height
  WHERE mr.balance + mr.stake > 0
)
SELECT coalesce(jsonb_pretty(jsonb_agg(to_jsonb(exact_rewards) ORDER BY source_height, idena_address, kind)), '[]'::text)
FROM exact_rewards;
