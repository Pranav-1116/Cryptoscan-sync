# Payment Cryptography Monitoring (HSM / PCI / TR-39)

The cryptography a bank's transactions actually depend on — ZMK/ZPK
hierarchies, PIN verification keys, CVKs, MAC keys, BDKs, EMV issuer keys —
lives in HSMs and TR-31 key blocks. Estate scanners cannot see it. This
module makes it inventory: keys, ceremonies, audit-trail telemetry and
PAY-xxx policy findings.

**Security invariant: key *material* never enters CryptoScan.** TR-31 blocks
are parsed for metadata only; nothing sensitive is stored or transmitted.

## Concepts

| Object | What it is |
|---|---|
| `PaymentKey` | One key by operator reference (`ZMK-PROD-01`): usage, algorithm, size, state (`PRE_ACTIVATION/ACTIVE/SUSPENDED/COMPROMISED/DESTROYED/EXPIRED`), TR-31 block version, activation/rotation dates, HSM device |
| `KeyCeremony` | Provenance: who held the parts (custodians), m-of-n, dual control, location, documentation |
| `HsmEvent` | One audit-trail line from your HSM/SIEM, normalized into a vendor-neutral taxonomy |
| `PaymentPolicyFinding` | Result of the PAY-xxx rule engine (severity 1–5, blocking flag, OPEN/ACCEPTED/RESOLVED) |

## Getting inventory in

1. **Paste / POST audit trails** (dashboard "Payment crypto" → Ingest, or
   `POST /api/v1/payment-crypto/hsm-events`). Three documented shapes:
   - **JSONL** (canonical): `{"occurred_at":"…","device":"hsm-1","event_type":"KEY_GENERATED","key_id":"…","actor":"…"}`
   - **syslog key=value**: `<30>2026-08-30T12:00:00Z hsm-1 crypto: event=clear_key key_id=ZMK-9`
   - **CSV with column map** — map your HSM export columns, no code.
   Lifecycle events (`KEY_GENERATED`, `KEY_IMPORTED`, `KEY_ROTATED`)
   auto-create/retire inventory rows — the inventory stays current by itself.
2. **Manual/TR-31**: `POST /api/v1/payment-crypto/keys` with a raw key block;
   the header is parsed (usage, algorithm, binding version) — `B0` blocks are
   flagged as legacy (no cryptographic binding).
3. **24/7 tailing**: add a monitor target `PAYMENT` with
   `{"path": "/var/log/hsm/audit.jsonl"}` — the daemon ingests new lines each
   hour (timestamp-deduped), refreshes inventory and re-runs policy.

## The rules (sources)

| Rule | Fires when | Source |
|---|---|---|
| PAY-001 | ACTIVE key on DES/3DES/RSA<2048/EC<224 | NIST SP 800-131A, PCI DSS 4.0 strong crypto |
| PAY-002 | key past rotation window (12 mo default; 24 for KEK/ZMK/BDK/IMK) | ANS X9.24 / TR-39 A.9 |
| PAY-003 | ceremony without dual control (<2 custodians) | PCI DSS 3.6.5/3.7 split knowledge |
| PAY-004 | clear-key export observed in audit trail | X9.24 clear key handling |
| PAY-005 | ACTIVE key with no ceremony record | TR-39 accountability |
| PAY-006 | ≥5 HSM auth failures on one device in window | PCI DSS 10/11 brute-force signal |
| PAY-007 | firmware change without change-control reference | change control |
| PAY-008 | TR-31 B0 key block still in service | X9.143 binding migration |
| PAY-009 | COMPROMISED/EXPIRED key still enabled | incident hygiene |
| PAY-010 | key block fails structural parse | data quality |

Risk acceptance is a first-class action (`POST /findings/{id}/status` with
`ACCEPTED`) and survives re-evaluation — accepted risks are never silently
re-opened.

## Alerts

Blocking findings in the monitor summary raise a monitor `ALERT`, which fans
out to your SIEM (CEF/UDP), a signed webhook, and email — see
[user-guide/live-monitoring.md](live-monitoring.md) sink configuration.

## Usage analytics & transaction correlation (the "10M/day" lens)

Feed daily transaction counts and let the audit trail speak:

```bash
curl -X POST …/api/v1/payment-crypto/transactions      -d '{"day":"2026-08-30","count":10000000,"source":"core-banking"}'
curl …/api/v1/payment-crypto/usage
```

- **PAY-011** ACTIVE key dormant > 90 days — retirement candidate
- **PAY-012** a COMPROMISED/DESTROYED key was *used* — must be impossible (blocking)
- **PAY-013** the HSM uses a key that is in no inventory — **shadow key**
- **PAY-014** crypto-ops-per-transaction deviates > 40% from the 30-day
  median — the classic signal that a software fallback is doing payment
  crypto outside the HSM (or a retry storm is hammering it). Requires both
  series; with < 14 overlapping days it reports `insufficient_data`, never a guess.

## 24/7 PAYMENT monitor target (feeds + transactions)

The monitor daemon can run the whole loop autonomously:

```json
{
  "name": "hsm-prod",
  "target_type": "PAYMENT",
  "config": {
    "url": "https://siem.bank.example/hsm/audit",     // or "path": "/var/log/hsm/audit.log"
    "token": "…",
    "transactions_path": "/dw-export/tx_daily.jsonl"  // optional: {"day":"2026-08-30","count":10000000}
  },
  "interval_seconds": 3600
}
```

Each sweep: poll the feed (cursor-based — nothing re-ingested), auto-inventory
keys from lifecycle events, ingest new transaction days, run policy + usage
analytics + correlation, and open/refresh findings. Feed errors degrade the
target honestly (`AUDIT_FEED_ERROR:…`), never silently skip.

One-shot daily push instead of a file:

```bash
curl -X POST …/api/v1/payment-crypto/transactions/bulk \
     -d '{"series":{"2026-08-30":10000000},"source":"dw-push"}'
```

## Connectors (audit feeds)

| Connector | Config | Notes |
|---|---|---|
| `HttpJsonlConnector` | `{"url": "https://siem/…", "token": "…"}` | polls any JSONL audit export; `?since=` cursor |
| `SyslogFileConnector` | `{"path": "/var/log/hsm/audit.log"}` | byte-offset cursor, rotation-safe |
| `PayshieldSimulator` | — | deterministic drill data, tagged `sim=hsm-simulator` — never production evidence |

PCI-DSS reports now include the payment picture: requirements 3.6.5-pay,
3.7-pay-rotation, 3.5.1-pay-inventory and 3.6-pay-usable evaluate from
PAY-xxx evidence, and the report carries a `payment_crypto` summary block.

## API quick reference

```bash
curl -X POST …/api/v1/payment-crypto/hsm-events -d '{"format":"syslog","text":"<30>… event=clear_key …"}'
curl -X POST …/api/v1/payment-crypto/keys -d '{"key_id":"ZMK-01","algorithm":"TRIPLE_DES","key_block":"B00401…","activation_at":"2024-01-01T00:00:00Z"}'
curl -X POST …/api/v1/payment-crypto/ceremonies -d '{"ceremony_id":"CER-42","key_id":"ZMK-01","custodians":["a","b","c"],"m_of_n":"2-of-3"}'
curl -X POST …/api/v1/payment-crypto/evaluate
curl …/api/v1/payment-crypto/summary
```

Writes require the **auditor** role. Honest rejections: unparsable lines are
reported line-by-line, never silently dropped; unknown TR-31 codes surface as
`UNKNOWN(code)` instead of being guessed.
