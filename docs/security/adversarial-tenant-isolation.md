# Adversarial review of tenant isolation — 2026-10-04

**Scope.** Independent adversarial review of the multi-tenant isolation
plane, performed as if by an external attacker-turned-auditor: assume the
documented guarantees (`db/tenancy.py`, the 44-test tenancy suite, the
middleware scope) are wrong until proven otherwise, and attack every other
layer a tenant request touches — the ORM statement machinery below the
repositories, the graph engine behind `/graph*`, the scan-transfer boundary,
and the SSE fan-out.

**Verdict.** Two real cross-tenant holes were found and fixed
(**§1**, **§2**), one second-order injection hole was found and fixed
(**§3**), and four surfaces were attacked and held. Regression coverage:
31 new adversarial database tests, 10 graph-plane tests, 13 API-boundary
tests — all green alongside the pre-existing 44-test tenancy suite and the
full API/worker/evidence suites (1, 993+ passing). A permanent source-level
audit (`scripts/tenant_isolation_audit.py`) now runs inside
`scripts/engineering_gate.py`.

---

## 1. The graph plane served every tenant the same global store (CRITICAL — fixed)

**Attack.** `resolve_graph()` in
`services/graph_engine/graph_engine/core/facade.py` preferred the Neo4j
store whenever Bolt answered a health ping. The store is process-global —
nodes carry no tenant property — and it was returned for *every* `/graph*`
route: blast radius, business impact, compliance inheritance, vendor
chains, hotspots, stats. A tenant-scoped request (payload correctly built
from tenant-filtered ORM rows) would hand the caller a graph engine whose
every query read **all tenants'** systems and assets. `sync_payload()` had
the write-side twin: a scoped sync wrote the tenant's inventory *into* the
shared store, and returned global `counts()` as a volume oracle
("this deployment has 12,431 systems" — every tenant's total).

**Fix.** `graph_engine.core.tenant_gate` imports `db.tenancy.isolation_active`
(degrading to "no tenants" only when the database plane is absent, i.e. a
standalone graph-engine deployment). While a scope is active:

- `resolve_graph()` returns the in-process `GraphEngine` built from the
  (already tenant-filtered) payload, marked `backend="memory-tenant-isolated"`,
  and **never touches the driver — not even a health probe**;
- `sync_payload()` performs no Neo4j writes and reports the scoped build's
  own counts with `reason: "tenant_isolated"`;
- `ensure_populated()` never seeds the global store from a scoped payload.

**Proof of fix.** `services/graph_engine/tests/test_tenant_isolation.py`
uses a recording fake driver that answers PING as healthy: scoped resolve,
sync and populate issue **zero** Bolt statements; `/api/v1/graph` and
`/api/v1/graph/sync` under a scope serve only the caller's slice with only
health PINGs reaching Bolt; unscoped behavior is unchanged (healthy Bolt
still serves Neo4j).

## 2. Raw SQL and pure-Core statements bypassed the ORM guard entirely (CRITICAL — fixed)

**Attack.** The guard's SELECT branch applies `with_loader_criteria`, and
its DML branch adds an exact-tenant predicate — but the DML branch
early-returns for statements with no mapper, and `text()` statements were
never inspected at all. Verified empirically against the real models with
the guard installed and `tenant_scope("B")` active:

| Statement under a tenant scope | Pre-fix behaviour |
|---|---|
| `session.execute(text("SELECT * FROM scans"))` | **all tenants' rows returned** |
| `session.execute(text("UPDATE scans SET ..."))` | **rowcount = 1 (other tenant's row rewritten)** |
| `select(Scan.__table__)` | all rows returned |
| `update(Scan.__table__).where(Scan.__table__.c.target_location == ...)` | rowcount = 1 (cross-tenant write) |
| `update(Scan.__table__).where(Scan.id == ...)` | rowcount = 0 (filtered — this shape is ORM-aware) |

The existing test `test_table_shaped_bulk_writes_are_filtered_too` passed
only because its WHERE clause used the ORM attribute `Scan.id`, which
promotes the statement to ORM-aware. That was false coverage: the same
repository-shaped statement written with `Table.c` columns wrote across
tenants.

**Fix.** The guard's `do_orm_execute` listener now branches on
`is_orm_statement`:

- **Non-ORM statements fail closed.** The compiled SQL of `text()` and
  pure-Core statements is matched (word-boundary, case-insensitive, so
  subqueries and aliases are caught) against the registry of tenant-scoped
  tables — populated automatically by `TenantScoped.__init_subclass__` —
  and a `TenantScopeViolation` is raised naming the table. Statements that
  touch only platform tables (`users`, `tenants`, `monitor_leases`, ...)
  execute normally; the greppable opt-out remains `platform_scope()`.
- **ORM bulk INSERTs are stamped.** `session.execute(insert(Model).values(
  rows))` bypasses `before_flush`, so unstamped rows landed as platform
  estate — i.e. **visible to every tenant** — on the PostgreSQL production
  path (`BulkInserter._insert_evidence_pg`). The guard now inspects the
  values at statement level: an omitted `tenant_id` is stamped from the
  active scope (mirroring `stamp_tenant`), an explicitly foreign claim is
  rejected. `BulkInserter._build_row` additionally stamps evidence rows
  from their parent scan explicitly, so the portable path documents its
  ownership too.

## 3. ORM-shaped statements could embed unfiltered Core subqueries (HIGH — fixed)

**Attack** (found while closing §2). `with_loader_criteria` propagates to
embedded **ORM** subqueries — verified — but never to fragments built from
`Table.c`:

```python
# under tenant_scope("A") — returned 3, i.e. every tenant's row count:
select(User.username,
       select(func.count(Scan.__table__.c.id)).scalar_subquery())
```

The outer statement is ORM-shaped (so §2's branch never sees it), the
embedded subquery is Core-constructed (so the loader criteria never reach
it): a per-row cross-tenant read, plus boolean-oracle variants via
`in_()`, `exists()` and `select_from(Table)` — including over the *same*
table as the outer entity, where the outer ORM reference masks the inner
Core reference.

**Fix.** ORM references materialize as annotated nodes
(`AnnotatedColumn`/`AnnotatedTable`); Core references do not. The guard now
analyses each select level (the statement plus every embedded select,
subquery, alias and exists) independently: a scoped table appearing in a
level's FROM clauses as a plain, non-annotated `Table` — with no ORM
reference to it at that level — is a reference the tenant filter cannot
reach, and raises. The same check covers ORM UPDATE/DELETE WHERE clauses
(rowcount oracles). Legitimate shapes are unaffected: `select(Model)`,
`select(func.count()).select_from(Model)` (the repositories' pagination
count), `select(Model.id)`, ORM joins, and embedded ORM subqueries all
still execute — filtered.

## 4. Attacked and held

- **`Session.get` identity-map poisoning** — load a row unscoped, then
  enter a scope on the same session: `Session.get` returns `None` for the
  foreign row (SQLAlchemy re-executes with the criteria). Pinned by test.
- **Scan-transfer import** — `SCAN_FIELDS`/`RECORD_FIELDS` carry no
  `tenant_id`, so a pack cannot claim ownership at all; the importer stamps
  the caller's tenant, and an attacker-claimed `tenant_id` key is silently
  dropped by the field restriction (digest stays valid). Foreign-id exports
  and every scan sub-resource answer 404-absence, not 403-confirmation.
- **SSE fan-out** — tenant filtering happens at the subscriber-queue
  boundary (so Redis fan-out cannot queue cross-tenant frames); owned
  events require an exact tenant match, unowned events are platform-wide,
  a payload-level `tenant_id` cannot override the frame's owner, and a
  platform-admin connection without a selected tenant sees platform
  traffic only. Matrix pinned by tests.
- **`filtered_get` / `import_scan_transfer` / relationship lazy-loads** —
  re-verified safe under the new guard.

## 5. Permanent controls

- `services/database/tests/adversarial/test_tenant_guard_bypasses.py` —
  31 tests: every statement shape from §2/§3, identity-map poisoning,
  no-false-positive shapes, registry conformance across **94** scoped
  models.
- `services/graph_engine/tests/test_tenant_isolation.py` — 10 tests with a
  recording driver: scoped = zero Bolt statements, unscoped = Neo4j
  unchanged.
- `services/api/tests/security/test_cross_tenant_adversarial.py` — 13
  tests over HTTP: graph routes, transfer import/export, absence-not-403,
  SSE predicate.
- `scripts/tenant_isolation_audit.py` (wired into
  `scripts/engineering_gate.py`): every `__tablename__` model must inherit
  `TenantScoped` or carry an in-source `# platform-scope: <reason>`
  marker (12 justified platform/identity-plane tables today); direct
  `session.get(SscopedModel, ...)` and `text()` naming scoped tables in
  request/worker code are violations; every `platform_scope()` site is
  inventoried (currently one: the platform auditor export).

## 6. Residual risks (explicit)

- `platform_scope()` remains the deliberate, greppable cross-tenant
  opt-out; its sites are inventoried by the audit but not semantically
  reviewed by it.
- `AuditLog`, `UserSession` and `AccessReviewRecord` are platform-plane by
  design; their reads are admin/auditor-gated at the router layer, not by
  the ORM guard. In a shared deployment, treat those routers as the
  remaining trust boundary.
- The Core-statement guard inspects statements executed through a
  `Session`. Engine/connection-level execution (schema bootstrap,
  migrations) is platform plumbing that never runs inside a request scope;
  the audit keeps `text()` out of request/worker code so this stays true.
- Standalone graph-engine deployments (no `db` package) have no tenant
  plane and therefore no isolation semantics — global by definition.

**Bottom line for the gap register:** *tenant isolation and request
scoping — closed in code, adversarially reviewed; the remaining condition
for shared multi-tenant operation is operational (per-tenant Neo4j or the
documented memory fallback, and the platform-plane router boundary above).*
