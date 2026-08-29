# Compliance Report Generator

Audit-ready reports from stored evidence — requirement by requirement, with
attestation and tamper detection. **Policy is the only source of pass/fail**;
nothing in the report is inferred or AI-generated.

## Templates

| Template | Source | Notes |
|---|---|---|
| `pci-dss-4.0` | native | PCI-DSS 4.0 requirements 3.5.1 / 4.2.1 / 8.3.2 / 12.3.3 |
| `nist-sp-800-131a` | native | SP 800-131A Rev. 2 transition requirements |
| `fips-140-3` | native | FIPS 140-3 approved-algorithm / key-size rules |
| `dora` | mapped | ICT risk → internal baseline; PQC timeline → CNSA 2.0 |
| `soc2` | mapped | CC6.1 / CC6.7 → internal baseline |
| `iso-27001` | mapped | Annex A.8.24 → internal baseline |
| `custom` | custom | pick requirement ids across templates |

`native` templates evaluate rules that cite the framework directly.
`mapped` templates map requirements onto the internal baseline — every
requirement row shows **which rule ids** produced it, so auditors can trace
the chain of evidence. A requirement with no matching rule evidence reports
`NOT_EVALUATED`, never a guessed PASS.

## Usage

```
GET /api/v1/report-templates                                  # list + requirement ids
GET /api/v1/scans/{id}/report?template=pci-dss-4.0            # JSON
GET /api/v1/scans/{id}/report.html?template=pci-dss-4.0       # printable HTML
GET /api/v1/scans/{id}/report?template=custom&requirements=4.2.1,CC6.1
```

Each templated report contains:

- `template_evaluation.requirements[]` — id, title, status
  (PASS/FAIL/NOT_EVALUATED), matched rule ids, failing evidence locations
- `template_evaluation.summary` — pass/fail/not-evaluated counts, compliant %
- `attestation` — scope, scan id, policy pack hash, evidence count,
  deterministic-generation statement
- `report_hash` — SHA-256 over the canonical JSON of the report body

## Integrity model (honest boundaries)

- **Tamper detection**: recompute the hash from any report body
  (`reporting.report_templates.canonical_hash`) — a single changed
  character breaks it.
- **Authenticity**: the attestation binds the report to a scan, a policy
  pack hash, and a timestamp. Full PKI digital signatures require a real
  certificate authority certificate; that integration point is intentionally
  left `signature: null` rather than faked.
- **Scheduling**: quarterly/automated generation is an ops cron away —
  the endpoint is deterministic and side-effect free. See
  `docs/admin-guide/production.md` for the recommended scheduler pattern.

## PKI signing (bring your own key)

Set `REPORT_SIGNING_KEY` to a path holding an RSA private key (PEM), and
optionally `REPORT_SIGNING_KEY_ID` (embedded as the JWS-style `kid`):

```bash
openssl genrsa -out /etc/cryptoscan/report-signing.pem 2048
REPORT_SIGNING_KEY=/etc/cryptoscan/report-signing.pem \
REPORT_SIGNING_KEY_ID=ciso-2026 ./scripts/run_api.sh
```

Every `GET /scans/{id}/report` then carries a **real RSASSA-PKCS1v15-SHA256
signature** over the canonical JSON of the report body:

```json
"signature": {"alg": "RS256", "key_id": "ciso-2026", "value": "<base64url>", ...}
```

Verification needs **no CryptoScan code** — plain OpenSSL validates it:

```bash
python -m reporting.signing canonicalize report.json > body.json
openssl base64 -d -A -in sig.b64 -out report.sig
openssl dgst -sha256 -verify pub.pem -signature report.sig body.json
```

Or in-band: `POST /api/v1/report/verify` with `{report, public_key}`.

When no key is configured the signature is simply absent — never an HMAC in
disguise. The key can live in an HSM-backed file or be swapped via rotation
(`key_id` tells verifiers which public key to use). Production deployments
should use a key issued by their own PKI; generating one with `openssl` above
is for pre-production.

## Scheduled reports and immutable snapshots (items 7–8)

Reports no longer exist only at request time:

```bash
# create a quarterly PCI report over the payments repo, mailed to auditors
curl -s -X POST $API/api/v1/report-schedules -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{
    "name": "Quarterly PCI report",
    "template_id": "pci-dss-4.0",
    "frequency": "quarterly",            # or "monthly"
    "scan_target": "https://github.com/org/payments.git",
    "recipients": ["auditor@corp.example.com"]}'

# what cron calls — generates every due schedule now
curl -s -X POST $API/api/v1/report-schedules/run-due -H "Authorization: Bearer $T"
```

Each run:

1. picks the **latest completed scan** of `scan_target` (none yet → honest
   `SKIPPED_NO_SCAN`, never a report over stale or missing data);
2. renders the template exactly as `GET /scans/{id}/report` would — including
   the tamper hash and the PKI signature when `REPORT_SIGNING_KEY` is set;
3. stores an **immutable snapshot** (`report_snapshots`) — the audit artifact
   stays byte-identical even as live findings change;
4. emails it when `SMTP_HOST` is configured; otherwise records
   `SKIPPED_NO_SMTP`. Every outcome is stored on the snapshot row.

`GET /report-snapshots` lists; `GET /report-snapshots/{id}` returns the stored
report with its snapshot metadata. Schedules reschedule +30/+91 days after
each run; `PATCH /report-schedules/{id}` pauses, `DELETE` removes (snapshots
survive, keeping the schedule name). Live SMTP delivery is proven by
`scripts/burn_in.py --target smtp`, not by unit tests.
