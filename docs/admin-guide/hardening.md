# Security hardening (W57-58) — rate limiting & tamper-evident audit

This guide covers what the product enforces **in-process** and what belongs to your
deployment. We do not claim cloud features the code doesn't ship.

## Rate limiting

In-process sliding-window middleware (`api/middleware/rate_limit.py`), active whenever
authentication is active (not in `ENVIRONMENT=test`):

| Endpoint class | Match | Limit |
|---|---|---|
| `login` | `POST /api/v1/auth/login` | 5 / minute **per source IP** |
| `scan_submit` | `POST /api/v1/scans*` | 100 / minute **per user** |
| `api` | every other `/api` route | 600 / minute per identity (user if authenticated, else IP) |

Behavior:

- Over the limit → `429` with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  and a body naming the exceeded scope.
- Buckets are independent: a throttled login source can still read scans; health probes
  (`/health`, `/ready`, `/metrics`, `/healthz`) are never throttled.
- Identity prefers the session token's subject, so one user's flood does not lock out
  others behind the same NAT.

**Honest scope**: the window state is per-process. For the single-process topology this
product ships, that is exact. If you run multiple API replicas, put a shared limiter
(WAF, ingress, or a Redis-backed gateway) in front and keep these rules as the inner
defense layer.

## Tamper-evident audit log

Every `audit()` write is chained (`db/repositories/user_repository.py`):

```
entry_hash(n) = SHA-256( previous_hash | actor | action | target | detail | ip | outcome | created_at )
```

- `chain_sequence` gives an explicit order; `previous_hash` links each entry to its
  predecessor (genesis `000…0`).
- Editing any stored entry breaks its own `entry_hash`; deleting or reordering an entry
  breaks the `previous_hash` of its successor — both are detected by re-walking the chain.

### Verify

```bash
curl -s $API/api/v1/auth/audit/verify -H "Authorization: Bearer $ADMIN_TOKEN"
# {"status": "OK", "checked": 412, "entry_count": 412, "chain_head": "9f3a…"}
# or: {"status": "TAMPERED", "break_at_sequence": 307, "reason": "entry content modified…"}
```

### Immutable export (WORM artifact)

```bash
curl -s $API/api/v1/auth/audit/export -H "Authorization: Bearer $ADMIN_TOKEN" \
     -o audit-$(date +%F).jsonl
```

Line 1 is a manifest (`entry_count`, `sha256` over the body, `chain_status`,
`generated_at`); the remaining lines are one JSON entry each with its chain fields, so
the export is independently verifiable. `X-Audit-Export-Sha256` carries the body digest.

Store exports under object lock / WORM retention (S3 Object Lock, Glacier Vault Lock,
or WORM tape). The in-product chain detects tampering with stored entries; the kept,
hashed export is the reference copy an auditor diffs against — the database cannot
retract what the export already attests.

**Honest scope**: immutability of the *storage medium* is a deployment property. We
provide detection (hash chain) and the WORM-ready artifact; we do not pretend a SQL
column is a WORM device.

## Related hardening already in the product

- Login lockout (5 failures → lockout window) and MFA/TOTP — see `test_production_hardening.py`
- Production config validation that fails closed on demo defaults
- Security headers middleware, request IDs, structured logging
- SSO/OIDC federation, PKI report signing, and WORM infrastructure integration require
  real credentials/providers and are intentionally not stubbed
