# Event Stream, Live CBOM & Deterministic Correlation (r29)

## Why

CryptoScan previously ended each scan at "findings written to the DB". Round 29
turns the platform into a **streaming system**: every observation becomes an
immutable, signed event; deterministic processors enrich, deduplicate, judge and
correlate it; the Live CBOM is a continuously versioned, cryptographically
signed artifact that downstream systems can subscribe to. AI/LLM components are
explicitly absent: every verdict is reproducible from the code in this repo.

## Topology

```
collectors (network/container/cloud scanners, monitor daemon,
            telecom passive taps, external agents)
        │  POST /api/v1/stream/ingest        (or bus.publish_raw in-process)
        ▼
┌────────────────────────── StreamBus ──────────────────────────┐
│  8 topics × append-only JSONL logs, HMAC-SHA256 envelopes,    │
│  hash-addressed payloads, consumer-group cursors + lag,       │
│  torn-tail tolerant, replay from any offset                   │
└──────────────────────────────────────────────────────────────┘
        │ raw-events
        ▼
   StreamProcessor (services/eventstream/eventstream/stream/pipeline.py)
   normalize → dedup → policy → attack-detect → fan-out
        │            │            │           │
        ▼            ▼            ▼           ▼
 normalized    policy-results  audit-log  attack-detections + alerts
        │
        ▼
   CbomProjector → LiveCbomService (versioned, JWS-signed, hash-chained)
        │ cbom-updates                    │ graph-sync
        ▼                                 ▼
  /cbom/live/{system} (SSE)        graph engine sync
        │
        ▼
   Correlation Engine (priority × effort × replacement × plan)
```

## Topics (fixed contract, `eventstream.topics`)

| topic               | produced by              | consumed by                    |
|---------------------|--------------------------|--------------------------------|
| raw-events          | collectors, daemon       | stream-processor               |
| normalized-events   | stream-processor         | cbom-service, graph-sync       |
| policy-results      | stream-processor         | governance, alerts-bridge      |
| attack-detections   | stream-processor         | soc-console, correlation       |
| cbom-updates        | stream-processor         | live-cbom, subscribers         |
| graph-sync          | stream-processor         | graph-engine                   |
| audit-log           | stream-processor         | evidence-store                 |
| alerts              | stream-processor         | notification-router            |

Envelopes: `{v, topic, key, seq, source, ts, payload, payload_hash, hmac}`
(HMAC-SHA256 over the canonical JSON; constant-time verification of both the
signature and the payload hash). Tampered log lines are detected on load and
never delivered — the torn tail is skipped, corrupted middles raise.

## The 13 attack rules (deterministic, `eventstream.stream.attack_rules`)

| rule                  | severity | trigger                                             |
|-----------------------|----------|-----------------------------------------------------|
| crypto_downgrade      | ALERT    | TLS version below learned baseline                   |
| algorithm_downgrade   | CRITICAL | algorithm below baseline / in broken set             |
| key_size_reduction    | ALERT    | key size below learned baseline                      |
| mitm_indicator        | CRITICAL | cert fingerprint ≠ pinned fingerprint                |
| unexpected_ca         | HIGH     | issuer outside trusted CA set                        |
| key_reuse             | HIGH     | same cert fingerprint across systems                 |
| weak_entropy          | MEDIUM   | shannon entropy < 4.5 bits/byte                      |
| protocol_violation    | ALERT    | illegal state transition (DOWNGRADED→HANDSHAKE etc.) |
| rate_anomaly          | MEDIUM   | events/s > mean + 3σ of ≥8 baseline seconds          |
| new_endpoint          | MEDIUM   | first TLS handshake from an unseen endpoint          |
| cert_near_expiry      | MEDIUM   | ≤ 30 days validity remaining                         |
| revoked_cert_in_use   | CRITICAL | OCSP REVOKED on an in-use certificate                |
| hsm_kms_policy_change | HIGH     | KMS/HSM policy differs from baseline                 |

Baselines are learned only from clean observations and never auto-overwritten
(`setdefault`; `attach_baseline` lets an operator pin a value). `AttackState`
snapshots make the whole detector deterministic and replayable.

## Live CBOM (`eventstream.livecbom`)

Every material change of a system's asset set produces a new **version**:
`{system_id, version_no, generated_at, version_hash, prev_hash, asset_count,
jws, doc}`. `version_hash = SHA-256(canonical(doc) + prev_hash)` chains back to
genesis (`64×"0"`); the doc is served under a compact **JWS (HS256)**.
APIs: `GET /cbom/live/{system}`, `/cbom/versions/...`, `/cbom/diff`,
`/cbom/verify/{system}` (re-verifies every signature + the chain and reports
the exact version where it broke), `GET /cbom/stream/{system}` (SSE push on
every new version), plus freshness (`stale_after_seconds`, default 3600).

## Telecom passive collection (`telecom_scanner.passive`)

Offline parsers for crafted-or-captured wire bytes — zero active probing:
- **Diameter (RFC 6733)**: command codes (CER/DWR/CE/DWR/S6a/Gx/Gy/Rx/Cx/Sh),
  Origin-Host/Origin-Realm AVPs, 4-byte alignment, vendor flag.
- **GTP-C v2 (TS 29.274)**: TEID-present header (12 vs 8 bytes), Echo/
  Create/Modify/Delete/Bearer messages, 3-byte-header IE walk with CR flags.
- **SIP/IMS (TS 33.203)**: `Security-Server`/`Security-Verify`, ipsec-3gpp
  (alg, SPIs, ports) and TLS mechanisms, quote-aware comma splitting.

All three normalize into the same canonical schema, so telecom traffic flows
through the identical policy/attack/CBOM pipeline as TLS scans.

## Deterministic correlation (`correlation.engine`)

No AI anywhere. `analyze()` composes: `priority = revenue_impact × severity ×
agility`, `effort = asset_count × complexity × (2 − agility)`, a fixed
replacement rule table (e.g. 3DES→AES-256-GCM, RSA-2048→ML-KEM-768 hybrid /
ML-DSA-65), template explanations, plan templates (banking 4 phases, telecom
and default 3), and a cycle-safe BFS (`max_depth=4`) over the asset graph for
blast-radius. Same input ⇒ byte-identical report.

## Deployment notes

- Bus logs default to `$CRYPTOSCAN_SNAPSHOT_DIR/eventstream` (already a volume);
  override with `STREAM_LOG_DIR`. CBOM store: `$CRYPTOSCAN_SNAPSHOT_DIR/live_cbom`
  or `CBOM_STORE_DIR`. Signing secret: `CBOM_SIGNING_SECRET` (dev default, set a
  real secret in prod).
- The monitor daemon publishes every pass (`engine._publish_pass`); the API
  drains the pipeline synchronously on ingest/read paths. Single-host active/
  active multi-region: run N API+daemon replicas per region against region-local
  bus dirs and ship `*.jsonl` logs to the other region with any log shipper —
  envelopes verify anywhere (HMAC secret shared per estate).
