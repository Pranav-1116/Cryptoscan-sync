# Threat Model — CryptoScan Live Monitor & Payment Crypto Module

Scope: the 24/7 monitor daemon, `/api/v1/monitor/*`, `/api/v1/payment-crypto/*`,
alert routing (CEF/webhook/SMTP), and the HA edge (`deploy/ha`).
Method: STRIDE, one row per credible threat, each with the control that
exists today and what is explicitly **not** claimed.

| # | Threat (STRIDE) | Vector | Control today | Gap / honest status |
|---|---|---|---|---|
| 1 | Spoofing | Stolen admin token used for monitor writes | PBKDF2 password hashing, optional MFA (TOTP + recovery codes), OIDC SSO (RS256 vs JWKS), session expiry | No device trust / conditional access — pair with SOC VPN + mTLS at nginx |
| 2 | Spoofing | Forged SIEM/webhook alerts | Outbound webhook HMAC (`X-CryptoScan-Signature`, sha256); CEF recipients are inside the SOC network | Rotate `ALERT_WEBHOOK_SECRET`; no replay-protection timestamp window yet |
| 3 | Tampering | HSM audit lines forged before ingest | Lines stored raw + normalized; rejection is explicit; audit chain on API writes | Source integrity depends on the collector (syslog TLS is deployment-side) |
| 4 | Tampering | Report snapshot modified after the fact | Snapshots are hash + PKI-signed, immutable via API | Offline tampering detectable only by signature verify — schedule it |
| 5 | Repudiation | Operator denies pausing a target / accepting a PAY finding | Audit log (actor, action, ts) on every write; findings record `resolved_by` | Log shipping to SIEM is manual — CEF alerting covers alerts only |
| 6 | Information disclosure | Payment key inventory leak via API | RBAC (viewer read / auditor write), rate limits, nginx IP allow-list template for `/payment-crypto/` | **Key *material* never enters this system** (TR-31 metadata only); still treat as confidential |
| 7 | Information disclosure | Dashboard served over HTTP | nginx TLS 1.2/1.3 + HSTS; headers middleware | Cert management is operator's job |
| 8 | Denial of service | Scan-now flood | Rate-limit middleware; monitor backoff (2^n, cap 24h) so a dead target can't hammer | No per-tenant quotas (single-tenant deployment today) |
| 9 | Denial of service | Monitor daemon crash | Loop never raises; per-target try/except; container `restart: unless-stopped` | Single scheduler instance by design (one DB, idempotent ticks) |
| 10 | Elevation of privilege | Viewer crafts auditor call | `require_auditor` dependency on every write route, tested 403s | Keep OIDC role mapping reviewed |
| 11 | Supply chain | Malicious dependency | `requirements.lock.txt` pins; `pip-audit` report in this folder | No SLSA provenance / signed images yet |
| 12 | Supply chain | Malicious plugin (vendor/protocol) | Discovery plugins registered explicitly; plugin SDK documented | Runtime sandboxing not claimed |

## What this model does NOT claim

- No third-party penetration test has been performed (checklist: `hardening-checklist.md`).
- Multi-AZ/multi-site failover is a deployment property — the runbook states
  single-host RTO/RPO honestly.
- HSM **key material** is never imported, stored or transmitted by CryptoScan.
  Only metadata (usage, algorithm, size, state) and audit events — by design,
  so a CryptoScan compromise cannot leak payment keys.

## SSRF (OWASP A10) — one choke point, three consumers

All operator-supplied probe/sweep inputs pass `api/security/target_validation.py`:
`POST /network/discover` (CIDR), `POST /crypto-assurance/*` (probe host) and —
since the 2026-09-13 security round, found by live attack testing — monitor
NETWORK target configs (`POST/PATCH /monitor/targets`), which previously bypassed
the guard and would have let an authenticated user point the daemon's scan tick
at loopback or cloud-metadata addresses.

The guard refuses loopback, link-local (incl. `169.254.169.254` and
`fd00:ec2::254`), CGNAT, multicast/reserved ranges, URL schemes, embedded
credentials and shell metacharacters; it allows public hosts and RFC1918 ranges
(a TLS-audit product legitimately scans internal networks when the operator
asks). Monitor NETWORK configs are additionally re-checked at execution time in
the daemon runner (defense in depth for configs that predate the API gate):
blocked targets are never probed and surface as `SSRF_BLOCKED:*` issues.
