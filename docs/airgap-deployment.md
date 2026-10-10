# Air-Gapped Deployment Runbook

How to run CryptoScan with **zero outbound network calls** from the
gapped site, moving data in and out only through signed, verifiable
media. Every mechanism referenced here exists in the codebase — this
document is the operational path through them, not an aspiration.

> Audit trail: report 73 (air-gapped environments), round 27. The
> enforcement points are `services/governance/governance/airgap.py`
> (policy + signed bundles), `feed_store.py` (offline feed ingestion),
> `audit_attest.py` (tamper-evident audit + offline attestation), and
> the encrypted backup scripts.

---

## 1. What "air-gapped" means in this platform

| Concern | Mechanism | Default |
|---|---|---|
| Outbound calls | `AIRGAP_MODE` env — when on, every egress-capable operation is checked by `airgap.enforce_operation()` and refused | off |
| Egress exceptions | `AIRGAP_ALLOWLIST` — comma-separated internal mirror hosts still permitted | empty |
| Telemetry | The "telemetry heartbeat" publishes to the **in-process SSE event bus** for local subscribers; there is no external phone-home endpoint in the codebase | internal only |
| Updates | HMAC-signed offline bundles (§3) | manual |
| Exports | Signed exports via `/enterprise/airgap/bundle` (§4) | manual |
| Backups | AES-GCM encrypted via `scripts/backup_*.py --encrypt` | plaintext unless flagged |

## 2. Install (gapped site)

1. **Transfer the release artifacts** (container images / wheels) to the
   gapped site on media. Nothing in the install path requires network
   access; dependencies are vendored in the image.
2. **Set the mode before first start**:
   ```bash
   AIRGAP_MODE=true              # refuse egress-capable operations
   AIRGAP_ALLOWLIST=mirror.corp  # optional internal mirror, comma-separated
   ```
3. Run migrations (`alembic upgrade head`) against the on-site
   database. No migration, bootstrap, or scan step contacts an external
   service.
4. Verify the mode took effect: any egress-capable operation now
   returns an `AirgapError`-derived refusal naming the policy decision
   (`airgap.enforce_operation` → `{allowed: false, reason: ...}`).

## 3. Update vulnerability feeds offline

Feeds (NVD / OSV / registry / CT / CRL entries) move as **signed
bundles**: a tar of entries plus a manifest that lists each entry's
SHA-256, the whole manifest HMAC-SHA256-signed with a shared secret.

**On the connected side** (staging host with feed access):

```python
from governance.airgap import build_bundle

entries = [
    {"feed": "nvd", "id": "CVE-2026-1234", "payload": {...}},
    {"feed": "osv", "id": "GHSA-xxxx", "payload": {...}},
]
bundle = build_bundle(entries, secret=SHARED_SECRET, created_by="feed-operator")
# serialize bundle to JSON, move it on media
```

**On the gapped side**:

```python
from governance.airgap import import_bundle, AirgapError
from governance.feed_store import SqlVulnerabilityFeedSink

try:
    result = import_bundle(bundle, secret=SHARED_SECRET,
                           sink=SqlVulnerabilityFeedSink(session))
except AirgapError as exc:
    # signature or manifest mismatch — the import is refused whole,
    # nothing is partially applied
    raise
```

Properties you can rely on:

* A tampered or truncated bundle fails signature verification and is
  refused **before** any entry is ingested.
* Entries are de-duplicated on `(cve, package, version)` — re-importing
  an overlapping bundle is idempotent.
* Unknown feed names are namespaced, never silently dropped.
* The scanners read the same `vulnerabilities` table the sink writes —
  imported advisories affect findings immediately.

## 4. Move results OUT of the gapped site

`POST /api/v1/enterprise/airgap/bundle` (roles: superadmin / admin /
ciso / auditor) builds a **signed export** of real platform data — live
findings, compliance posture, controls — carrying a `content_hash` and
the exporting principal. The write is audited. The receiving side
verifies the signature before trusting the document; treat the secret
as site-specific and rotate it per transfer window.

## 5. Prove integrity without network access

* **Audit chain**: the platform's audit log is hash-chained (each entry
  links the previous hash). `governance/audit_attest.py` verifies the
  chain and produces a deterministic, HMAC-signed **attestation
  report** — an offline verifier with the secret can confirm the log
  has not been tampered with, no platform involvement required.
* **Backups**: `scripts/backup_crypto.py --encrypt` /
  `backup_evidence.py --encrypt` produce AES-GCM ciphertext with an
  Argon2-family KDF (salt + parameters embedded, MAGIC-prefixed
  format); SHA-256 and KDF parameters travel with the backup so
  restoration fails loudly on wrong keys instead of producing garbage.

## 6. Operating rules

* Keep `AIRGAP_MODE=true` on every gapped instance; the allowlist is
  for named internal mirrors only — never a wildcard.
* Move feed bundles on a fixed cadence; log every import's
  entry count and refuse counts.
* Rotate the bundle/export secrets per transfer window; secrets used
  for import and export should differ.
* Re-verify the audit attestation after every restore.

## 7. Known limits (honest)

* **No offline licensing** — there is no signed license-file
  subsystem; enforcement of entitlements on a disconnected site is an
  operational agreement, not code (report 73 P0 #1, open).
* Live TLS probing of external endpoints is by definition unavailable
  inside the gap; passive and artifact-based discovery
  (repo/image/config scans) are the working modes.
* External CT / CRL / OCSP checks do not run; feed bundles are the only
  path for that data, and revocation statuses age between imports
  (see the freshness decay model: `GET /api/v1/trust-model`).
