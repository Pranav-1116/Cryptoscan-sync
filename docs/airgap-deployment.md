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
| Exports | `cryptoscan bundle export` — stored evidence, the twin snapshot and the BOM projections, each signed by the operator (§4) | manual |
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

Use the operator CLI. It reads the control plane it is already authenticated
against and writes an evidence bundle:

```bash
cryptoscan bundle export --out ./bundle --sign-key operator-key.pem   # sign the manifest
cryptoscan bundle verify ./bundle --public-key trusted.pem            # on the receiving side
cryptoscan bundle import ./bundle.cse --into ./restored               # decrypt an envelope
```

What the bundle carries, and what it does not, is written into its own
`bundle.json`:

* **carries** stored evidence, the twin snapshot and the BOM projections, each
  with the endpoint that answered it under `sources`;
* **does not carry** collectors, their raw output, or the database — importing a
  bundle into another installation does not make its evidence that
  installation's, because every record keeps the estate it was observed under;
* `unavailable` lists any projection the control plane could not serve, and the
  export exits non-zero rather than shipping a bundle that reads as a complete
  estate;
* the manifest's hashes prove the files are unmodified relative to the manifest.
  Who produced them is proven only if the bundle was signed and you check it
  against a key you already trust; an unsigned bundle says `UNSIGNED`.

### The old transfer endpoints are withdrawn

`/api/v1/enterprise/airgap/{bundle,export,import}` answered 2xx until this
change. They are gone because they could not be an evidence path:

* the signing secret travelled in the *request body*, so the server never held a
  key it could trust — "signed" meant "signed by whoever called";
* `import` verified a signature and answered `{"accepted": true}` without
  writing anything. A success an operator cannot distinguish from a no-op is
  worse than an error;
* nothing in the payload was evidence, so the transfer could not be followed back
  to a collector.

The paths now answer **410 Gone** with the replacement named in the body
(`evidence_export`, `evidence_verify`, `feed_updates`, `docs`) rather than 404,
so an integration still wired to them says what happened. Advisory feeds keep
their own path: `POST /api/v1/resilience/airgap/build-bundle` on a connected
host and `POST /api/v1/resilience/airgap/import-feed` inside the gap, signed with
a **server-held** key (`governance/keys.signing_secret`) and ingested into the
live vulnerability store — see §3.

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
* Rotate the feed-bundle signing secret per transfer window, and keep it out of
  request payloads: the signing key is the server's, never the caller's.
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
