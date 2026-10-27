# Registry webhook burn — signed E2E over live HTTP

*Run:* `2026-09-17T07:02:42Z` against `http://127.0.0.1:8010`  |  *Verdict:* **PASS** (9/9 checks)

Every count below is produced by the real container detector running
inside the live API process. The scan target is a harness fixture
(`data/burn/registry-image-root/`) with pinned real packages so the
detector has something true to find — never shipped as product data.

| # | Check | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | liveness | PASS | GET /health -> 401 (server responding) |
| 2 | login | PASS | POST /auth/login -> 200 |
| 3 | image-root | PASS | harness image root at data/burn/registry-image-root (requirements.txt + planted secret marker) |
| 4 | signed-push-scan | PASS | signed PUSH -> 200; scanned=True packages=3 libraries=1 vulnerabilities=0 |
| 5 | tampered-signature-401 | PASS | forged signature -> 401 (Invalid webhook signature) |
| 6 | alt-header-interop | PASS | X-Hub-Signature-256 signed PUSH -> 200 |
| 7 | missing-root-404 | PASS | signed event for absent root -> 404 (Container filesystem not found) |
| 8 | ops-metrics-live | PASS | GET /ops/metrics -> 200; prometheus exposition contains http_requests_total |
| 9 | slo-live | PASS | GET /ops/slo -> 200; window_requests=8 |

## Signature scheme

`X-ZELNX-Signature: sha256=HMAC_SHA256(REGISTRY_WEBHOOK_SECRET, raw_body)`
(the GitHub-style `X-Hub-Signature-256` is accepted interchangeably).
With a secret configured, a bad signature is a 401 in EVERY environment
(fail-closed); without any signature, production always rejects (401).

**Burn verdict: PASS**
