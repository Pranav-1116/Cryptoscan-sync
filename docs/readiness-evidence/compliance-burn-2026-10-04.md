# Compliance burn — evidence, attestation, WORM, auditor API over live HTTP

*Run:* `2026-10-04T14:02:08Z` against `http://127.0.0.1:8010`  |  *Verdict:* **PASS** (11/11 checks)

The evidence pack is collected from live state at request time (signed
audit chain re-verified, deployed schema inspected, rate limits read
from the running policy) — no canned evidence. Attestations are real
JWS compact signatures (HS256) over the pack snapshot and fail closed
on any mutation.

| # | Check | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | login | PASS | POST /auth/login -> 200 |
| 2 | evidence-pack | PASS | GET /compliance/evidence -> 200; controls={'access.session_config': 'pass', 'config.production_gate': 'pass', 'audit.chain_integrity': 'pass', 'deploy.schema_in_sync': 'pass', 'protection.rate_limits': 'pass', 'retention.worm_policy': 'pass'} sha256=5915ad15af4290bf… |
| 3 | evidence-rbac | PASS | unauthenticated GET /compliance/evidence -> 401 |
| 4 | attestation-sign | PASS | POST /compliance/attestations -> 200; jws_segments=2+1 |
| 5 | attestation-verify | PASS | POST /compliance/attestations/verify -> 200; valid=True |
| 6 | attestation-tamper-rejected | PASS | tampered JWS -> valid=False |
| 7 | worm-retention | PASS | GET /compliance/retention -> 200; audit_log_years=7 delete_allowed_now=False |
| 8 | auditor-wrong-key-401 | PASS | X-Auditor-Key wrong -> 401 |
| 9 | auditor-admin-session | PASS | admin session on /compliance/audit/evidence -> 200 |
| 10 | self-alerts-live | PASS | GET /ops/alerts -> 200; fired=1 (quiet platform = empty list) |
| 11 | capacity-forecast | PASS | GET /ops/capacity/forecast -> 200; months_of_data=[] (empty estate reports no trend, never invents one) |

**Burn verdict: PASS**
