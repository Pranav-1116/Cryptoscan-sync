# Infrastructure burn-in

Ran 2026-09-16T06:09:21.984038+00:00 against the live burn deployment
(`scripts/burn_in.py` — the integration harness that proves what unit
tests fake).

| Target | Status | Detail |
|---|---|---|
| github | ✅ PASS | signed webhook accepted; job 8b45930f-a19e-41f8-9d07-23b22eca1c49 COMPLETED |
| smtp | ✅ PASS | message delivered and received via 127.0.0.1:1025 |
| tls | ✅ PASS | github.com:443 negotiated TLSv1.3 / TLS_AES_128_GCM_SHA256; cert expires Sep 17 05:47:25 2026 GMT |
| cloud | ⏭️ SKIP | CRYPTOSCAN_CLOUD_LIVE is off (safe default); enable to scan a real account |
| neo4j | ⏭️ SKIP | NEO4J_URI not set — start the compose stack to burn in |
| container | ⏭️ SKIP | docker CLI not available on this host |

## What each PASS proves

- **github**: a properly HMAC-signed webhook delivered over real HTTP is
  accepted, queued, and the scan job ran to COMPLETED through the live
  API — the Part-1 CI round-trip works end-to-end.
- **smtp**: a real SMTP wire conversation (built-in sink on 127.0.0.1) —
  the email channel composes and transmits a compliant message. Point
  `--smtp-host` at a production relay for the final customer-proof.
- **tls**: live TLS probing against real internet infrastructure
  (github.com:443 — TLS 1.3, cipher + cert expiry parsed).

## Honest skips (environment, not product)

- **cloud**: needs `CRYPTOSCAN_CLOUD_LIVE=1` + real AWS credentials —
  enabling it without credentials would be dishonest; stays a
  credential-backed step.
- **neo4j**: needs a live Neo4j (compose stack or host) — no JVM in this
  sandbox.
- **container**: needs a Docker daemon to build/scan an image.

Verdict: **6 passed/skipped, 0 failed.**

## Long-running soak (Postgres + Redis)

`scripts/burn_in.py` proves integrations once; `scripts/soak.py` proves the
whole stack over time. `deploy/staging/staging-up.sh` brings up a real
PostgreSQL 16 + Redis 7 stack with `ENVIRONMENT=production` and no Docker;
the soak cycles the real pipeline (queue → worker → 14 stages → evidence chain
verify → dashboards → signed export → SSE) and samples RSS, fds, connections
and queue depth every cycle. Runs, raw data, pass criteria and what the first
run found: [`docs/soak-evidence/`](soak-evidence/README.md).
