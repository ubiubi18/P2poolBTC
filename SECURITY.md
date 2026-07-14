# Security Policy

P2poolBTC is experimental and must not be used with real funds.

## Private Reporting

Do not open a public issue for a suspected vulnerability or privacy leak. Open
the repository's [Security page](https://github.com/ubiubi18/P2poolBTC/security)
and select **Report a vulnerability** when private reporting is available. If
that option is unavailable, contact the repository owner through their GitHub
profile without sending technical evidence, and arrange a private channel
before sharing reproduction details.

Report the minimum information required to reproduce the problem:

- affected commit and component;
- impact and required attacker access;
- sanitized reproduction steps;
- whether fork or mining services were stopped;
- a minimal proof that contains no real keys, wallets, identities, addresses,
  API credentials, cookies, peer endpoints, or personal information.

Do not upload raw logs, `.env` files, databases, core dumps, identity keystores,
wallet files, report bundles, or screenshots until every field has been
reviewed. If a secret may have been exposed, revoke or rotate it before further
testing.

## Immediate Stop Conditions

Stop the affected service and preserve its datadir if you observe an activation
mismatch, replay-root divergence, invalid signature acceptance, unauthorized
RPC access, unexpected Bitcoin mainnet submission, or unintended disclosure of
participant data.

There is currently no production security guarantee or real-value bug bounty.
