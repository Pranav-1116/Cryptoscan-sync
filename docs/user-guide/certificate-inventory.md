# Certificate inventory

Network scans store certificates by SHA-256 fingerprint. Each cert tracks subject, SAN, expiry status (`VALID`, `EXPIRING_SOON`, `EXPIRING_CRITICAL`, `EXPIRED`), OCSP/CRL revocation, and the endpoints that presented it. Open **TLS / Certificates** on the dashboard to see days remaining and usage.

## The persisted certificate estate (Certificates page)

The Certificates page carries two surfaces, labeled apart:

- **The live TLS-scan view** — what the most recent authorized scan observed.
- **The persisted estate** — `GET /certificates` rows deduplicated by SHA-256
  fingerprint, with their own totals and an UNKNOWN-OWNER count. An owner
  absent from the record renders as UNKNOWN, never inferred.

Each estate row opens a drawer with:

- **WHERE OBSERVED** — the recorded usage locations and last-seen times for
  that fingerprint. "No linked usage yet" is stated, not papered over.
- **Revocation check** — the OCSP/CRL probes render what they determined.
  Without AIA URLs the result is **UNDETERMINED**, never guessed good; a check
  that ran (even an inconclusive one) records `revocation_checked_at` so
  checked is distinguishable from never-checked.
- **Ownership assignment** — requires a mandatory audited reason; a 403
  renders as the `certificates.manage` refusal.

Remediation tasks bind to evidence records, not to certificates — the drawer
says so explicitly instead of inventing a task linkage.

## Verified OCSP status — 2026-10-22

An OCSP `good` line alone is insufficient. The current live-check classifier
requires explicit OpenSSL `Response verify OK`, and the executing command must
succeed, before returning **GOOD**. Missing/failed verification or a failed
command downgrades GOOD to **UNKNOWN** with a reason. An unverified REVOKED
response remains a conservative signal with its separate `response_verified`
state; do not call it independently authenticated revocation evidence.
Missing issuer/OpenSSL/AIA or an unreachable responder is not proof of good
standing. CRL freshness/serial checks remain separate.

This is a classifier/runtime contract, not activation of live certificate
collection under the controlled local-source/v1 profile. See
[current implementation status](../CURRENT-IMPLEMENTATION-STATUS.md).
