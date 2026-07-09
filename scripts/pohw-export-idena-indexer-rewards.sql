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

WITH completed_epochs AS (
  SELECT DISTINCT epoch::bigint AS epoch
  FROM epoch_summaries
),
invitee_reward_links AS (
  SELECT
    ri.block_height,
    lower(invite_tx.hash::text) AS liability_tx_hash,
    lower(inviter.address::text) AS inviter_address,
    lower(invitee.address::text) AS invitee_address,
    ri.epoch_height
  FROM rewarded_invitees ri
  JOIN transactions invite_tx ON invite_tx.id = ri.invite_tx_id
  JOIN addresses inviter ON inviter.id = invite_tx."from"
  JOIN addresses invitee ON invitee.id = invite_tx."to"
),
ordinary_validation_rewards AS (
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
    vr.type::smallint AS reward_type,
    'credit'::text AS direction,
    ''::text AS counterparty_address,
    ''::text AS tx_hash,
    ''::text AS liability_tx_hash,
    NULL::integer AS invite_epoch_height,
    NULL::integer AS reward_age,
    NULL::bigint AS liability_maturity_epoch,
    '0'::text AS locked_stake_atoms,
    NULL::bigint AS liability_event_epoch
  FROM validation_rewards vr
  JOIN epoch_identities ei ON ei.address_state_id = vr.ei_address_state_id
  JOIN addresses a ON a.id = ei.address_id
  JOIN epoch_summaries es ON es.epoch = ei.epoch
  JOIN blocks b ON b.height = es.block_height
  WHERE vr.balance + vr.stake > 0
    AND vr.type NOT IN (13, 14, 15)
),
invitee_reward_credits AS (
  SELECT
    lower(a.address::text) AS idena_address,
    ei.epoch::bigint AS epoch,
    es.block_height::bigint AS source_height,
    lower(b.hash::text) AS source_hash,
    'Invitee'::text AS kind,
    (round((vr.balance + vr.stake) * 1000000000000000000))::numeric(78, 0)::text AS amount_atoms,
    (round(vr.balance * 1000000000000000000))::numeric(78, 0)::text AS balance_atoms,
    (round(vr.stake * 1000000000000000000))::numeric(78, 0)::text AS stake_atoms,
    b."timestamp"::bigint AS timestamp,
    'validation_rewards'::text AS source_table,
    vr.type::smallint AS reward_type,
    'credit'::text AS direction,
    links.inviter_address AS counterparty_address,
    links.liability_tx_hash AS tx_hash,
    links.liability_tx_hash,
    links.epoch_height AS invite_epoch_height,
    coalesce(ra.age, 0)::integer AS reward_age,
    (ei.epoch + greatest(0, 10 - coalesce(ra.age, 0)))::bigint AS liability_maturity_epoch,
    (round(vr.stake * 1000000000000000000))::numeric(78, 0)::text AS locked_stake_atoms,
    ei.epoch::bigint AS liability_event_epoch
  FROM validation_rewards vr
  JOIN epoch_identities ei ON ei.address_state_id = vr.ei_address_state_id
  JOIN addresses a ON a.id = ei.address_id
  JOIN epoch_summaries es ON es.epoch = ei.epoch
  JOIN blocks b ON b.height = es.block_height
  JOIN invitee_reward_links links
    ON links.block_height = es.block_height
   AND links.invitee_address = lower(a.address::text)
  LEFT JOIN reward_ages ra ON ra.ei_address_state_id = vr.ei_address_state_id
  WHERE vr.balance + vr.stake > 0
    AND vr.type IN (13, 14, 15)
),
mining_reward_credits AS (
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
    'mining_rewards'::text AS source_table,
    NULL::smallint AS reward_type,
    'credit'::text AS direction,
    ''::text AS counterparty_address,
    ''::text AS tx_hash,
    ''::text AS liability_tx_hash,
    NULL::integer AS invite_epoch_height,
    NULL::integer AS reward_age,
    NULL::bigint AS liability_maturity_epoch,
    '0'::text AS locked_stake_atoms,
    NULL::bigint AS liability_event_epoch
  FROM mining_rewards mr
  JOIN addresses a ON a.id = mr.address_id
  JOIN blocks b ON b.height = mr.block_height
  JOIN completed_epochs ce ON ce.epoch = b.epoch
  WHERE mr.balance + mr.stake > 0
),
killed_stake AS (
  SELECT
    lower(a.address::text) AS idena_address,
    b.epoch::bigint AS epoch,
    bc.block_height::bigint AS source_height,
    lower(b.hash::text) AS source_hash,
    b."timestamp"::bigint AS timestamp,
    lower(coalesce(kill_tx.hash::text, '')) AS tx_hash,
    (round(bc.amount * 1000000000000000000))::numeric(78, 0) AS amount_atoms
  FROM burnt_coins bc
  JOIN addresses a ON a.id = bc.address_id
  JOIN blocks b ON b.height = bc.block_height
  JOIN completed_epochs ce ON ce.epoch = b.epoch
  LEFT JOIN transactions kill_tx ON kill_tx.id = bc.tx_id
  WHERE bc.reason = 4
    AND bc.amount > 0
),
invitee_reward_reversals AS (
  SELECT
    credits.idena_address,
    credits.epoch,
    burns.source_height,
    burns.source_hash,
    'Invitee'::text AS kind,
    sum(credits.locked_stake_atoms::numeric)::numeric(78, 0)::text AS amount_atoms,
    '0'::text AS balance_atoms,
    sum(credits.locked_stake_atoms::numeric)::numeric(78, 0)::text AS stake_atoms,
    burns.timestamp,
    'burnt_coins'::text AS source_table,
    NULL::smallint AS reward_type,
    'debit'::text AS direction,
    max(credits.counterparty_address) AS counterparty_address,
    burns.tx_hash,
    credits.liability_tx_hash,
    min(credits.invite_epoch_height)::integer AS invite_epoch_height,
    max(credits.reward_age)::integer AS reward_age,
    max(credits.liability_maturity_epoch)::bigint AS liability_maturity_epoch,
    sum(credits.locked_stake_atoms::numeric)::numeric(78, 0)::text AS locked_stake_atoms,
    burns.epoch::bigint AS liability_event_epoch
  FROM killed_stake burns
  JOIN invitee_reward_credits credits
    ON credits.idena_address = burns.idena_address
   AND credits.source_height < burns.source_height
   AND burns.epoch < credits.liability_maturity_epoch
  GROUP BY
    credits.idena_address,
    credits.liability_tx_hash,
    credits.epoch,
    burns.epoch,
    burns.source_height,
    burns.source_hash,
    burns.timestamp,
    burns.tx_hash,
    burns.amount_atoms
),
exact_rewards AS (
  SELECT * FROM ordinary_validation_rewards

  UNION ALL

  SELECT * FROM invitee_reward_credits

  UNION ALL

  SELECT * FROM mining_reward_credits

  UNION ALL

  SELECT * FROM invitee_reward_reversals
)
SELECT coalesce(jsonb_pretty(jsonb_agg(to_jsonb(exact_rewards) ORDER BY source_height, idena_address, kind)), '[]'::text)
FROM exact_rewards;
