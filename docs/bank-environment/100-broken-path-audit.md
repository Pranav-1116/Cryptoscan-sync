# 100 — Broken-path audit: what is served, what is reachable, what is residue

**Status of this document.** It reports a measurement, not an assurance. It answers
the question "is a path *broken*?" — a path that exists but does not work end to
end — separately from "is a path *missing*?" — a capability that was never built.
The first is a defect; the second is a boundary. Confusing them is how a product
ends up claiming completeness.

Nothing here says the platform has zero broken paths. What it says is: the nine
checks below were run, here is what they saw, here is what they would have caught,
and here is the part they still cannot see.

---

## 1. The nine checks

Each check is a test, runnable on its own. Every one of them was written because
reading the tree turned up an inconsistency that no test covered, or because
running the product turned up a defect that reading the tree could not.

| # | Check | File | What a failure means |
|---|---|---|---|
| 1 | Every path a caller names is a path the app serves | `scripts/tests/test_api_route_contract.py` | A page, script or CLI command 404s in front of an operator |
| 2 | Every endpoint a router defines is mounted | `scripts/tests/test_router_reachability.py` | A handler exists, imports cleanly, and answers nothing |
| 3 | The bank-facing CLI speaks only HTTP | `scripts/tests/test_cli_architecture_boundary.py` | The CLI becomes a second front door that bypasses authorisation and tenancy |
| 4 | The withdrawn transfer family is refused and documented as refused | `scripts/tests/test_offline_transfer_path.py` | An integrator builds against a route that answers `410` |
| 5 | Models and the *migrated* schema agree, and Twin/CLI read paths run on it | `scripts/tests/test_database_contract.py` | Every test passes on `create_all` while the first read in a bank raises |
| 6 | Every route quoted as evidence ("check at", "measured by") is served | `scripts/tests/test_evidence_route_hints.py` | The product tells a reader how to verify a claim, and that route 404s |
| 7 | Every console page is reachable from the router | `scripts/tests/test_frontend_surface.py` | A page ships, its tests pass, and no URL renders it |
| 8 | Every operation is executed against a **live server** | `scripts/tests/test_live_route_smoke.py` | A handler raises, a dependency cannot resolve, a column is missing — the first thing a bank sees |
| 9 | Every operation that declares a response schema returns that schema | same file | The route answers `200` and the body is not what the contract promised |
| 10 | Every write operation accepts a body that matches its own request schema | same file | The handler is only reachable with a populated body, so `{}` proves nothing about it |
| 11 | Every operation's authority is classified, and every destructive route is guarded or reviewed | `scripts/tests/test_authorization_register.py` | A new state-changing route ships open to any signed-in caller |

```bash
export PYTHONPATH="scripts:shared/shared_models:services/api:shared/shared_config:$PYTHONPATH"
.venv/bin/python -m pytest scripts/tests/test_api_route_contract.py \
    scripts/tests/test_router_reachability.py \
    scripts/tests/test_cli_architecture_boundary.py \
    scripts/tests/test_offline_transfer_path.py \
    scripts/tests/test_database_contract.py \
    scripts/tests/test_evidence_route_hints.py \
    scripts/tests/test_frontend_surface.py -q

# checks 8 and 9 start a real server: opt in, ~60 s
CRYPTOSCAN_LIVE_SMOKE=1 .venv/bin/python -m pytest scripts/tests/test_live_route_smoke.py -q
```

Checks 5 and 8–10 need a PostgreSQL binary; they use `pgserver`'s unpacked
PostgreSQL on a unix socket and skip (loudly, via `importorskip`) when that is
unavailable. Checks 8 and 9 are opt-in because they start uvicorn and take about
a minute; they are not part of the hermetic gate.

---

## 2. What the checks measured

| Measurement | Value | Meaning |
|---|---|---|
| Served routes | **1134 paths / 1248 operations** | Read from the app's own OpenAPI document, not from a list |
| Console calls resolved | **637 → 0 unknown, 0 wrong verbs** | Every URL the browser builds exists, with the verb it uses |
| CLI / script calls resolved | **315 → 0 unknown** | Now includes the two shipped CLI files, which no scan read before |
| Router modules enumerated | **120 modules, 1246 routes, 0 unmounted HTTP routes** | The two WebSocket routes are the only ones outside the schema, by design |
| Console operations with a response model | **40 typed / 605 (6.6%)** | The TypeScript interface *is* the contract for the other 93% |
| ORM tables without a migration | **0** | Nothing the models read is missing from the migrated schema |
| Model columns without a migration | **0** | — |
| Columns in the database that no model maps | **16** | Residue from withdrawn writers; enumerated in check 5 |
| Routes quoted as proof that are not served | **0 of 8 hints** | Every "check at"/"measured by" route resolves, and accepts GET or POST |
| Console pages | **90 / 0 orphans** | Every page file is routed or embedded by a page the router reaches, transitively |
| Operations executed on a live server | **1248 / 1248, 0 × 5xx, 0 unanswered** | uvicorn over the migrated database, six privileged identities, 24 in flight |
| Operations that refused an anonymous caller | **1212 protected of 1212, 36 public** | Everything outside the session gate's declared public surface (health, docs, login/SSO, machine-signed webhooks) |
| Role-gated operations proven both ways | **306 admitted with the role, 273 refused without it** | Read from the dependency tree, then asked of the running server |
| Operations with a response schema that holds | **87 validated / 87 declared** | The other 1161 declare nothing (`§5`, limit a) |
| Model ↔ migrated-schema nullability | **0 disagreements, both directions** | At revision 0121 it was 148 columns the model treats as required and the database accepts as NULL, and 9 the reverse |

---

## 3. What was actually broken, and what fixed it

These are the defects this pass found. Each was a path that existed on both ends
and did not work; none was hypothetical.

1. **The shipped CLIs were outside the route contract.** `scripts/api_contract.py`
   walked `scripts/` and `integrations/` and never read
   `services/api/api/cli_remote.py` — the program an operator actually runs. 61
   literal API paths were unchecked. They all resolve today; the point is that
   nothing would have noticed if they had not. `CLI_SOURCES` now puts both CLI
   files inside the scan.

2. **Withdrawn routes were published as ordinary operations.** The generated
   `docs/api-reference/rest-api.md` and `docs/bank-environment/95-build-status-audit.md`
   listed `POST /api/v1/enterprise/airgap/{bundle,export,import}` like any other
   endpoint. They answer `410`. Both generators now read `WITHDRAWN_ROUTES` and
   mark the row, and the API reference carries a *Withdrawn routes* section naming
   the replacement per direction (export on the connected host, verification
   inside the gapped site).

3. **The response-contract parser read comments as fields.** A line reading
   `// Always served: …` inside `frontend/src/lib/api.ts` became a field named
   `served`, so the payload contract demanded a key no server sends — a green test
   would have turned red on a page that was fine, and the fix would have looked
   like "add the key". Members are now anchored to a line start and both comment
   styles are stripped; two tests keep prose out of the field set.

4. **The CLI split was documented as enforced and was not.** Guide 98 states that
   `cli_remote.py` "imports no estate/discovery module". No test read the module
   structure. It does now: the import allowlist is exactly
   `shared_models.release_signature`, `cryptography` and `yaml`, and a new import
   fails the build with the reason it is not allowed.

5. **No test had ever run the migration chain.** Every database test in this tree
   builds its schema from `Base.metadata.create_all`, which reads the same models
   the code does — so a model column with no migration passes every test and fails
   the first time a bank reads it. Check 5 now runs all 123 migrations on a real
   PostgreSQL and drives the twin store and `cryptoscan twin assets` against the
   result.

6. **The migration chain and the models disagreed about NULL, and nothing asked.**
   `POST /api/v1/hbom/snapshot` answered `500` on a live server for every
   estate-wide pin: `hbom_snapshots.tenant_id` was `NOT NULL` in the migration
   while the model declared it nullable, because a pin outside a tenancy request
   has no tenant. `create_all` builds from the model, so every test passed. An
   exact nullability comparison over all 155 mapped tables found 148 columns the
   model treats as required and the database accepted as NULL (a NULL that no
   reader expects, writable by any caller that leaves the field out) and 9 the
   reverse. Migrations 0122 and 0123 close both directions; four tenant-plane
   tables that must name an owner now use `TenantOwned` instead of being relaxed.

7. **Five compliance endpoints checked the username, not the role.** The gate was
   `if user != "admin": 403`. A provisioned superadmin under any other name was
   refused; an account *named* `admin` was admitted whatever its roles were. The
   auditor surface repeated the check and compared `X-Auditor-Key` with `==`.
   Found by the live sweep's authorization check, not by reading the router.

8. **A baselines endpoint called a repository method that does not exist.**
   `DELETE /api/v1/baselines/{baseline_id}/proposal` called `baselines.get(...)`;
   `BaselineRepository` has `get_by_id`. Every call raised `AttributeError` and
   answered `500`, so a clean-scan proposal could be listed and approved but never
   dismissed. Found by executing the route, not by importing it.

9. **Two `CHECK` constraints rejected rows the application writes.** The migrated
   schema's `scans_status_check` allowed `RUNNING/COMPLETED/FAILED/CANCELLED` while
   `Scan.status` defaults to `QUEUED` — every scan insert was a `CheckViolation` on
   a migrated PostgreSQL, and invisible everywhere else because `create_all` only
   creates the constraints the *model* declares, and the model declared none of
   them (migration 0124). The same comparison then caught
   `scans_target_type_check`, which allowed the three tree-scan types but not
   `HOST_SNAPSHOT_IMPORT` — the type the host-evidence intake writes for the row
   that anchors an imported snapshot. That import answered
   `409 Concurrent approval consumption` because the route translated *every*
   `IntegrityError` into a concurrency hint (migration 0125; the route now reports
   only a genuine uniqueness race as 409 and logs the rest). Both defects are
   found by declaring the constraints on the models in `db/models/scan.py`, so a
   `create_all` database and a migrated one reject the same rows.

---

## 4. What is classified as residue, and stayed

**The withdrawal is deliberate and visible.** The three `airgap` handlers remain
registered and answer `410` with the replacement, because a caller that finds a
404 cannot tell "removed" from "typo". That is the one place in this tree where a
route is intentionally not a path to integrate against, and it is the only one
marked `deprecated` in the schema.

**Sixteen database columns no model maps.** They belong to the pre-evidence-chain
writer:

| Table | Columns |
|---|---|
| `evidence_records` | `algorithm_family`, `highest_severity_failed`, `nist_designation`, `normalization_confidence`, `normalization_status`, `normalization_version`, `normalized_algorithm`, `policy_evaluated_at`, `policy_version`, `requires_review`, `rules_failed_count`, `rules_passed_count` |
| `verification_log` | `errors`, `findings_count_verified`, `manifest_valid` |
| `estate_daemons` | `tenant_id` (the table is deliberately platform-scoped, so the shared migration helper's tenant column is unused) |

Nothing reads them: no query, repository or model references them. They are
listed in the test as an exact set, so *new* residue fails the build, and the list
can only shrink. Dropping them is a separate release decision (a column drop is
not reversible in a running installation), not a prerequisite for any path here.

---

## 5. What this audit does **not** prove

Stated as limits, because each one is a place where a working path could still be
wrong. Each limit below records what has since been proven, what proved it, and
what is still open — the list is the same list, moved forward, not a new claim.

* **(a) Response correctness.** *Proven:* every operation that declares a 2xx JSON
  schema — **87 of 1248** — is called on a live server and its body validated
  against that schema (check 9). *Still open:* the other 1161 declare no response
  model. Their payload shape is asserted only by their TypeScript interface and,
  for seven payload families, by `scripts/tests/test_console_payload_contract.py`.
  A route returning the right fields in the wrong nesting for a page outside those
  families would still pass. Closing this is typing work on the routers, one
  `response_model=` at a time, and the count is pinned in check 9 so it can only
  grow.

* **(b) A live request for every route.** *Closed for execution and for write
  bodies.* All **1248** operations are executed against uvicorn over a real
  PostgreSQL at the migration tip: **0 returned 5xx**, **0 failed at the transport
  layer** (check 8). The first sweep sent `{}`, which proves a route is mounted and
  its dependencies resolve but answers `422` before the handler runs. A second
  sweep (**check 10**) therefore synthesises a body from each operation's own
  request schema — **496 of 567** write operations declare one — and executes the
  **581** mutation-safe writes (session killers and global switches excluded)
  against the throw-away database: **0 returned 5xx**; the only 5xx is
  `POST /resilience/backup/create`'s deliberate `503` naming a missing `pg_dump`,
  which is exempted only when its body says so.

  It paid for itself immediately. `BackupConfigRequest`/`BackupRunRequest` declared
  `databases: list[dict]`, so there was no schema to synthesise from and no reader
  of the contract could see that the handler does `c["database_id"]` — the
  documented body `[{}]` was a `500 KeyError`. `POST /cloud/accounts` accepted a
  provider longer than its `varchar(20)` column (`500` truncation), and
  `POST /business/processes/{id}/systems` inserted an unchecked `system_id`
  (`500` foreign-key violation). All three are now caller errors (`422`) or
  `404`s. A fourth was not a body problem at all: `POST /hardware/events/batch`
  could lose the atomic get-or-create race on `ix_hardware_assets_asset_id` and
  500 on a valid event; the insert now runs in a savepoint and adopts the winner's
  row.

  *Still open:* the synthesised body is schema-valid, not semantically meaningful —
  it proves the handler does not crash on its own contract, not that it computes
  the right answer. Where a body is a free-form `dict` the synthesizer still has
  nothing to work from, which is why the ratchet is to type them.

* **(c) Authorization per route.** *Proven per gated route.* Every route whose
  dependency tree carries a `require_roles` requirement — **306 operations** — is
  asked with a principal that holds the role (admitted, never `401`/`403`) and with
  one that does not (**273** of them, refused). The requirements are read from the
  route tree, not from a second list.

  *The classification is now written down.* `scripts/authorization_register.py`
  walks the same tree and, for all **1218** served operations, records which
  authority guard is actually in the dependency closure: **306** require a role,
  **71** a permission from the RBAC catalog (`hardware.ingest`, …), **12** a
  tenant role, and **829** nothing beyond a session —
  `docs/bank-environment/101-authorization-register.md` is that register, and
  `scripts/tests/test_authorization_register.py` (check 11) pins it: the gated
  counts may only grow, the **290** session-only *writes* may only shrink, and any
  `DELETE` that is neither guarded nor named in the reviewed list fails the build.

  *Still open:* the register makes the question tractable, it does not answer it.
  290 writes remain open to any signed-in operator. Six of them are deletions —
  removing a graph edge, an export schedule, a group entity, an expired vendor
  profile — and each simply mirrors the equally session-only create for the same
  registry, so gating the delete means deciding the policy for the whole family.
  That is a product decision this audit deliberately does not take.

* **(d) The database contract over all tables.** *Closed for schema parity.* All
  **155** mapped tables and every mapped column are compared with the migrated
  schema for existence, orphan tables, unmapped columns, and nullability in both
  directions (0 disagreements; the residue that remains is the 16 known legacy
  columns in §4). Platform-scope writes (`hbom_snapshots`, `algorithm_advisories`,
  topology) are executed against the migrated schema rather than assumed. *Still
  open:* the *read* paths of every table are not driven — the twin store and
  `cryptoscan twin assets` are. A table whose model matches the schema and whose
  query is wrong is invisible here. The live sweep covers whichever of those reads
  are exposed over HTTP.

* **The CLI boundary is a static import check.** It proves `cli_remote.py` cannot
  reach the estate modules; it does not prove a handler in `cli.py` that *is*
  allowed to reach them returns the right answer for every subcommand.

* **`twin` subcommands outside `REMOTE_TWIN_COMMANDS`** still run in-process and
  refuse without an explicit PostgreSQL estate. That is a legacy shape retained on
  purpose (guide 98 §4), it is tested, and it is not evidence that the remote
  equivalents exist.

* **One measured slow path, now fixed.** `GET
  /api/v1/findings/detectors/labeled-calibration` used to run the 842-file
  labeled accuracy corpus inside the request (1.9 s of scanning plus the scanner
  registry import; 6.9–10 s observed on a cold live server, once per worker
  process). `scripts/build_labeled_calibration.py` writes the report ahead of
  time, the image build runs it, and the endpoint reads the artifact and refuses
  one whose input fingerprint no longer matches the shipped corpus. Without an
  artifact the endpoint still computes and stores it, so a source checkout keeps
  working.

* **The live sweep is one deployment shape.** One server process, one PostgreSQL,
  no Redis, no cloud credentials, no HSM. A route that needs any of those answers
  from a configuration guard (`503`) or an honest empty result, and the sweep
  accepts neither as proof that the integrated path works.

## 6. The missingness axis, for contrast

These are *not* broken paths and are not counted as such. They are the declared
boundaries, served at `GET /api/v1/platform/scope` (`limited_capabilities`) and
printed in `/collector-depth` → Maturity and Simulation:

| Capability | Status | What is absent |
|---|---|---|
| Windows collector | `CANDIDATE` | A production Windows collector, universal admission, complete Windows BOM coverage |
| Hardware discovery | `FOUNDATION` | Complete hardware discovery across an estate |
| HSM | `FOUNDATION` | Proof that a key operation ran inside an HSM; custody and key-use assurance |
| Runtime crypto | `CANDIDATE` | Proof of which algorithms a process executed |
| Simulation | `FOUNDATION` | A generic enterprise engine — 1 of 10 scenarios computes, 7 are partial, 2 have no model |

Trust compromise and operator-authored custom scenarios have no model at all. A
page existing for either would be a broken path; a page that says so is not.
