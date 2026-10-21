# 40 — Exact-estate HTTP job and network-run history

[Guide index](README.md) · [Bounded TCP discovery](39-bounded-tcp-monitor-discovery.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

## Subsequent socket increment

[Guide 41](41-exact-estate-websocket-history.md) subsequently qualifies the
binary-progress and event WebSocket routes with exact-estate checks, fresh
authority and filtered replay/queues. Other streams/exports and broad A02 remain
open. This guide’s historical HTTP delivery/test evidence is unchanged.

## Status — 2026-10-21

**Implemented locally: a bounded A02 history-isolation increment supporting A01.**
The generic job HTTP routes and stored network-run HTTP history now require an
exact selected estate, including the NULL/platform estate. This closes the
specific platform-history gap recorded in guide 39 for these routes. It does not
complete A01, A02 or all platform/tenant isolation across the product.

Previously, bank-to-bank reads were filtered by the tenant ORM guard, but an
unscoped platform operator could read every bank's history. Readable curated
NULL-tenant inventory could also be visible through that guard. Neither is an
appropriate implicit authorization rule for private scan logs/results/retries.

No schema migration, data ownership reassignment, immutable event rewrite,
workflow edit or change to curated-inventory sharing is included.

## 1. Protected HTTP surfaces

| Route | Exact-estate behavior |
|---|---|
| `GET /api/v1/jobs` | Owner predicate in SQL before sorting and page limit |
| `GET /api/v1/jobs/{id}` | Foreign or unknown ID returns 404 |
| `GET /api/v1/jobs/{id}/logs` | Same owner rule before logs/progress are returned |
| `POST /api/v1/jobs/{id}/retry` | Foreign or unknown ID returns 404 before enqueue/admission side effects |
| `GET /api/v1/network/runs` | Rows and full filtered count use the same owner and optional target kind |
| `GET /api/v1/network/runs/{id}` | Full result payload only from selected estate |
| `GET /api/v1/network/runs/{id}/metrics` | Same boundary before rendering Prometheus text |
| `GET /api/v1/network/drift/latest` | Both compared runs selected from the same estate and target kind |

The job list's existing `total_count` remains the number in the returned page;
it is not newly advertised as a database-wide total. Network-run `total` remains
the full filtered count, even when the requested page is smaller.

An estate with zero matching rows gets an empty list/count. Drift with fewer
than two matching runs reports insufficient history; it does not fill the
comparison with another estate's results. No global existence, payload, log or
metric content is returned for a foreign ID.

## 2. Trusted selection, not a client-supplied owner filter

The [history context](../../services/api/api/security/estate_history.py) uses the
existing authenticated `get_tenant_context` resolver and establishes tenant
context on the async request task. This works for sync handlers and async retry
paths, even without the optional tenant middleware.

| Caller state | Selected history |
|---|---|
| Bank A member | Bank A rows only; not Bank B or NULL/platform rows |
| Bank B member | Bank B rows only; not Bank A or NULL/platform rows |
| Platform administrator, no selected bank | NULL/platform-owned rows only |
| Platform administrator explicitly selecting Bank A under existing policy | Bank A rows only for that request |
| Anonymous, invalid/forged selection or refused tenant resolution | No history fallback to an unscoped view |

A principal cannot supply a JSON/query `tenant_id` to widen these endpoints.
The existing resolver authenticates memberships/API-key binding and privileged
platform selection. It rejects a bank member's forged `X-Tenant-ID` before a
history lookup. Selecting a bank as an already-authorized platform administrator
is retained; this delivery does not invent a new superadmin grant or membership
policy. Existing platform-selection auditing, regional/legal-entity controls,
API-key scope policy and role-specific retry permission remain separate review
areas, not certified by an owner predicate.

### Practical examples

For a Bank A session, these retrieve only Bank A's history:

```bash
# Use the application's existing authenticated session; do not paste secrets.
curl -b "$SESSION_COOKIE_FILE" "$BASE_URL/api/v1/jobs?limit=10"
curl -b "$SESSION_COOKIE_FILE" "$BASE_URL/api/v1/network/runs?limit=10&target_kind=monitor"
```

A platform session without a selected estate sees platform history, not every
bank's job/result rows. An authorized platform administrator can deliberately
select a bank using the existing header:

```bash
curl -b "$SESSION_COOKIE_FILE" -H 'X-Tenant-ID: a' \
  "$BASE_URL/api/v1/network/runs?limit=10"
```

That header is selection, not authentication or a grant for an ordinary bank
user. Removing it returns the platform session to platform-owned history, not a
cross-bank aggregate. A foreign job ID returns the same 404 shape as a missing ID.

## 3. Implementation boundary and internal compatibility

[JobRepository](../../services/database/db/repositories/job_repository.py) adds
an explicit `owner` keyword to ID reads and recent lists.
[ScanRunRepository](../../services/database/db/repositories/scan_run_repository.py)
adds it to ID, list, latest and count reads. Each affected API route supplies the
server-resolved `ctx.tenant_id` explicitly:

- `owner="a"` means `tenant_id = 'a'`;
- `owner=None` means `tenant_id IS NULL`, **not** all rows;
- omitting `owner` preserves the existing internal repository behavior and ORM
  tenant guards. It is not an API-supported request parameter.

Predicates are in SQL, not post-limit Python filtering. Identity-map objects
cannot satisfy a foreign SQL predicate merely because they were loaded earlier.
The job list also has deterministic ID tie-breaking for equal creation times.

Internal dispatchers, recovery/reaper routines and persistence helpers still
need their existing cross-estate administrative repository contract when run
unscoped. This change intentionally does not globally tighten `BaseRepository`,
change all ORM NULL-sharing rules or prevent a worker from finding its queued
job. Explicit-owner reads also do not override an already active ORM tenant
scope: owner B requested while scoped to A still yields no B rows.

The affected [job routes](../../services/api/api/routers/jobs.py) and
[network routes](../../services/api/api/routers/network.py) apply this boundary
before serialization or retry enqueue. Existing synchronous network retry stays
409 for the **owned** job: callers must resubmit to the original admitted route.
An owned queued retry preserves stored scan options and the selected tenant
context. Scope-qualified monitor jobs and ordinary TLS monitor jobs now have
explicit platform-denial assertions in their authenticated contract tests.

## 4. Controlled evidence

[33 new authenticated contract cases](../../services/api/tests/unit/test_estate_history_contract.py)
use actual session authentication, SQL records and Bank A/Bank B/platform
estates. They cover:

- the five ID/content/retry surfaces in each estate, rejecting both foreign estates;
- owned logs/results/metrics, limit-one lists with newer foreign rows, exact counts
  and same-estate drift pairs;
- no-middleware bank/platform requests, explicit trusted platform selection and
  rejection of a bank's forged selection;
- retry owner propagation and no enqueue for foreign requests;
- anonymous reads, membership removal, suspended-bank refusal and empty estates;
- cached ORM objects, target-kind counts and unchanged internal repository reads.

The existing fake network-run repository was updated to accept the explicit
owner keyword; actual isolation evidence comes from real SQL tests, not that
single-estate test double.

Final scoped backend regression on Python 3.11.2: **2,025 passed, 5 skipped,
7 deselected, 139 warnings**, 559.63 seconds. It includes worker unit tests,
network scanner, SQL database tests, the existing network/monitor admission
contracts, these history tests, binary retry, specialized/HSM/CT records,
network-run persistence, middleware tenancy and SaaS/trigger integration suites.
The skips/deselections are not successful executions. Existing warning classes
remain. Post-format contract validation passed **97 tests** (4 warnings). Changed-Python
F/E9 lint, new-file/repository formatting, whitespace and bank-guide local-link,
JSON and shell syntax checks passed; no live bank, PostgreSQL/Neo4j, production deployment or
frontend qualification is implied.

## 5. Remaining gaps and six-BOM integrity

This is **HTTP job and network-run history**, not a product-wide access audit.
WebSocket streams, other scanner-specific histories, graph/export/archive
surfaces, delegated support access and global administration dashboards require
their own exact-estate review. Other API callers of the repositories are not
implicitly fixed unless they supply the owner predicate or their own equivalent
boundary. No claim is made that packet/QPS limits, distributed reservation,
queue grant revalidation, versioned grants or plugin safety are solved.

NBOM, CBOM, SBOM, TechBOM, HBOM and VBOM observations retain their meanings and
provenance. Restricting who can read a scan receipt is not additional observation,
complete coverage or new crypto/software/hardware/vulnerability evidence.
No old NULL record is reassigned to a bank, and immutable receipts/events are
not rewritten. **A01 and A02 remain partial.**
