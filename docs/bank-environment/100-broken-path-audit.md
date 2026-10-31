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
| 12 | Every operation that declares no response model is on a recorded list, and the list may only shrink | `scripts/tests/test_response_typing.py` | A new route returns `dict` by default and joins the unvalidated majority |
| 13 | Every write route is role-gated or recorded as authenticated-only with a reason | `scripts/tests/test_auth_write_inventory.py` | A new state-changing route silently chooses "no role" |

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
| Served routes | **1137 paths / 1251 operations** | Read from the app's own OpenAPI document, not from a list |
| Console calls resolved | **637 → 0 unknown, 0 wrong verbs** | Every URL the browser builds exists, with the verb it uses |
| CLI / script calls resolved | **315 → 0 unknown** | Now includes the two shipped CLI files, which no scan read before |
| Router modules enumerated | **120 modules, 1246 routes, 0 unmounted HTTP routes** | The two WebSocket routes are the only ones outside the schema, by design |
| Console operations with a response model (current) | **95 typed / 1251 (7.6%)** | Superseded the 40/605 figure below when four families were typed; see `103-untyped-response-operations.json` |
| Console operations with a response model | **40 typed / 605 (6.6%)** | The TypeScript interface *is* the contract for the other 93% |
| ORM tables without a migration | **0** | Nothing the models read is missing from the migrated schema |
| Model columns without a migration | **0** | — |
| Columns in the database that no model maps | **16** | Residue from withdrawn writers; enumerated in check 5 |
| Routes quoted as proof that are not served | **0 of 8 hints** | Every "check at"/"measured by" route resolves, and accepts GET or POST |
| Console pages | **90 / 0 orphans** | Every page file is routed or embedded by a page the router reaches, transitively |
| Operations executed on a live server | **1251 / 1251, 0 × 5xx, 0 unanswered** | uvicorn over the migrated database, six privileged identities, 24 in flight |
| Operations that refused an anonymous caller | **1212 protected of 1212, 36 public** | Everything outside the session gate's declared public surface (health, docs, login/SSO, machine-signed webhooks) |
| Role-gated operations proven both ways | **306 admitted with the role, 273 refused without it** | Read from the dependency tree, then asked of the running server |
| Operations with a response schema that holds | **95 validated / 95 declared** | The other 1156 declare nothing (`§5`, limit a) |
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

## 4a. The three capability gaps, as measured now

The vision names three gaps. Each is answered below by the artifact that measures
it, and each answer states what is **still** missing, because a gap that is
"closed" in prose is the failure mode this repository refuses.

### A. Collector families — measured, not claimed

`docs/bank-environment/105-collector-family-register.md` is generated from
`shared_models/collector_families.py`, and every status in it is computed by
**importing the family's declared entrypoints**. A family cannot be reported
shipped without code behind it. Of the twenty families the vision names:

| Measure | Count |
|---|---|
| Families in the register | **20** |
| Shipped (entrypoints import) | **20** |
| Production (shipped, live, **estate** scope) | **14** |

The six that are not production are named rather than implied:
**load balancers** and **network devices** (the parsers exist; nothing fetches the
config — records are imported), **message queues** (one MQTT record analyser, no
broker collector at all), **backup** (it protects *this platform's* database, not a
bank's backup estate), **legacy** (RACF/RACDCERT exports and COBOL source, not a
running CICS region) and **vendor** (a plugin framework and signatures, not
connectors). *Still open:* writing those six collectors, and the depth limits each
shipped row already states — a Kubernetes collector that reads Ingress blocks is
configuration evidence, not negotiated TLS.

### B. Runtime observation — the chain is now producible, and still narrow

The observer is an `LD_PRELOAD` shim over libcrypto's `EVP_*`/`SSL_CTX_*` calls,
recording the operation, algorithm, mode and key size and **never** key bytes, IVs
or plaintext. What was missing was the last hop into the graph: a traced call became
an evidence record and a crypto artefact, and never an edge.
`api/estate_runtime_edges.py` now emits application→library, application→algorithm
and library→algorithm on the `RUNTIME_OBSERVATION` basis, and refuses to fill gaps:
no named provider means no library edge (counted as `events_without_provider`), and
a traced provider name is never given an invented version.

The observer now interposes **two native stacks**: libcrypto/libssl (14 symbols)
and libgnutls (5 symbols — cipher, hash and hmac init, handshake, priority
setting). GnuTLS was not a completeness exercise: wget, exim, cups, libvirt and
many distro builds of curl and PHP link libgnutls and no libcrypto, so those
processes previously produced nothing and the absence read as inactivity. The
GnuTLS half is proven end to end against a stand-in library
(`test_gnutls_calls_are_forwarded_and_their_metadata_recorded`): the call is
forwarded with its arguments, the algorithm name comes from the library's own
getter, the key *length* is recorded, and the key bytes appear nowhere in the log.

That list is not a claim; it is a reading. `hook_symbols()` parses the shipped C
source, `/discovery/runtime-depth` serves it as `shim`, and a test compares it with
`nm -D` on the compiled object. A row whose hooks are missing from the shim
degrades to `ABSENT` by itself.

*Still open, and measured by* `/discovery/runtime-depth`: **JVM** and **.NET**
reach PROCESS_LIBRARY, **Go** and **Rust** are INGEST_ONLY, and interpreted
languages are ABSENT. The reason is structural, not a missing hook: Go's
`crypto/tls` and `ring`/`rustls` are statically linked and resolve no dynamic
symbol, so symbol interposition cannot reach them — a Go binary built with cgo
against system OpenSSL *is* caught by the openssl hooks instead. What remains
missing there is a linkage pre-flight (deciding which of the two a binary is
before a run), and an always-on observer: the shim still sees only a process
launched under it, inside an approved scope.

### C. Relationship discovery — the chain is walkable end to end

`shared_models/estate_chain.py` walks a pattern of hops over **established** edges
and reports the hop it could not take, with the graph's own refusal reason. It keeps
a frontier so the vision's shape is expressible (the application runs on a container
*and* terminates TLS at a load balancer), every hop carries the evidence ids that
established it, `weakest_hop` names the link that sets the strength, and
`unobserved_use_hops` marks hops that rest on configuration rather than an
observation — so "installed ≠ executed" survives the walk.

`GET /estate/evidence/twin/path` serves it from the stored snapshot, by asset id or
exact name (an ambiguous name is refused with candidates rather than guessed). It is
proven end to end in `test_estate_runtime_edges.py`: an approved runtime scope →
ingested events → the `RUNTIME` plane → a stored discovery → a walk that returns
`payments-api —uses_crypto_library→ OpenSSL —uses_algorithm→ AES-256-GCM` with both
hops on `RUNTIME_OBSERVATION`.

*Still open:* the chain is only as complete as the collectors that produced its
edges, which is why §4a and this section are read together.

---

## 4b. Attack correlation across the eleven planes

`docs/bank-environment/106-attack-correlation-planes.md` is generated from
`shared_models/attack_planes.py`, and each plane is measured on two axes that fail
differently:

| Axis | How it is measured | What failure means |
|---|---|---|
| **reading** | run `attack_patterns.correlate` with a canonical fact from the plane | the rule exists in prose and nothing consumes the fact |
| **supply** | import the `module:attribute` that would produce the fact | the rule can never fire on a real estate |

Measured now: **11 planes, 11 read, 11 supplied, 0 blind**, and **10 independent
witnesses** — the CBOM is a projection of other planes' evidence, so it is cited but
never counted as a second witness. Without that distinction, one source would
corroborate itself and every BOM-backed estate would look multi-plane.

Two rules join the planes on the subject a change names, and both stop at level 2:

- `MULTI_PLANE_AGREEMENT` — a change landed on a subject that two or more independent
  planes describe. Agreement is also what a correct estate looks like, so it raises
  review priority and never suspicion of intent.
- `PLANE_CONTRADICTION` — one plane holds evidence for a subject and another records it
  absent. That is a finding about the evidence, not about the estate: a scope or a moment
  differs. Neither plane is accusing the other.

Facts from a plane the engine does not know are counted as `unrecognised_plane_facts`
rather than relabelled, because *"a fact from the SIEM is a fact from the network"* is how
a correlator manufactures corroboration. The served register is
`GET /estate/evidence/threat/planes`; the change feed it joins is
`GET /estate/evidence/threat/patterns`.

*Still open:* correlation joins planes **on subject**, so it is only as good as subject
resolution — two collectors naming one asset differently will not be joined, and the
current mapping is by collector prefix, not by a resolved asset id. It does not model
causality, does not rank by likelihood, and never reaches `SECURITY_INCIDENT`.

### Remaining gaps D–G, stated

- **D (correlation depth)** — the plane layer above is what exists. Per-plane blind
  spots are in the register; subject resolution across planes is the next real limit.
- **E (generic simulation engine)** — simulation is still per-question (PQC planning,
  twin scenarios), not one engine that can run a subject-modification-recompute cycle
  over any BOM. Not started.
- **F (synthetic bank validation at 10/50/100/150 banks)** — the corpus and the
  accuracy harness exist; the four-point scale curve with precision, recall, false
  positives and negatives, coverage, memory, database growth and ingestion rate is not
  measured, and no number for it appears anywhere in this repository.
- **G (HA / disaster recovery)** — drills exist per failure (worker recovery, queue
  kill-9, PITR, region), but there is no single failure-mode matrix that names a
  deterministic recovery behaviour for all nine modes the vision lists. Not started.

---

## 5. What this audit does **not** prove

Stated as limits, because each one is a place where a working path could still be
wrong. Each limit below records what has since been proven, what proved it, and
what is still open — the list is the same list, moved forward, not a new claim.

* **(a) Response correctness.** *Proven:* every operation that declares a 2xx JSON
  schema — **94 of 1250** — is called on a live server and its body validated
  against that schema (check 9). *Still open:* the other 1156 declare no response
  model, and their payload shape is asserted only by their TypeScript interface
  and, for seven payload families, by
  `scripts/tests/test_console_payload_contract.py` — a route returning the right
  fields in the wrong nesting for a page outside those families would still pass.

  What has changed is that the gap can now only shrink. The exact list is
  `docs/bank-environment/103-untyped-response-operations.json`; check 12 requires
  it to equal the application's, so a **new** route that returns `dict` fails the
  build until someone writes it down, and a typed route left on the list fails
  until it is removed. Closing the gap itself is still typing work on the routers,
  one `response_model=` at a time — four families (cloud accounts, business
  processes, business owners, the backup routes) were typed in this pass.

* **(b) A live request for every route.** *Closed for execution and for write
  bodies.* All **1251** operations are executed against uvicorn over a real
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
  counts may only grow and any `DELETE` that is neither guarded nor named in the
  reviewed list fails the build.

  *The per-route decision is now recorded.* `scripts/auth_write_inventory.py`
  writes every write operation that is neither public nor role-gated — **294** of
  them — into `docs/bank-environment/102-authenticated-only-writes.json`, each with
  the policy reason for its prefix ("operator surface: estate curation",
  "machine-signed: HMAC, not a session role", "self-service: the caller's own
  account", …). Check 13 requires that list to equal the application's, so a new
  unguarded write fails the build until someone regenerates it and states a reason.
  The **286** role-gated writes are pinned separately; together the two sets
  partition the write surface.

  *Still open:* an entry says "authenticated-only is intended for this family", not
  "this specific route could not be abused". Six of the 294 are deletions that
  mirror an equally session-only create on the same registry — gating one means
  deciding the policy for the whole family, which is a product decision this audit
  deliberately does not take. What has changed is that the decision is now written
  down, reviewable, and enforced against regressions.

* **(d) The database contract over all tables.** *Closed for schema parity.* All
  **155** mapped tables and every mapped column are compared with the migrated
  schema for existence, orphan tables, unmapped columns, and nullability in both
  directions (0 disagreements; the residue that remains is the 16 known legacy
  columns in §4). Platform-scope writes (`hbom_snapshots`, `algorithm_advisories`,
  topology) are executed against the migrated schema rather than assumed. *Still
  open:* a table whose model matches the schema and whose *query* is wrong is
  invisible to a schema comparison. The queries are now driven too: the twin store
  and `cryptoscan twin assets`, and — check 5 — every public read-shaped method of
  every repository (**95 of 118**) is executed against the migrated schema with
  placeholder arguments, so a filter on a column that does not exist, an `ORDER BY`
  on a column with the wrong type, or a join whose foreign key disagrees fails
  here rather than in a bank. The 23 that are not driven need an argument shape the
  placeholder builder refuses to invent (a list of objects, a credential); the
  floor is pinned so that number cannot grow quietly. The live sweep covers
  whichever of those reads are exposed over HTTP.

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
