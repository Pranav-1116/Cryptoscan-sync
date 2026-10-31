# 100 — Broken-path audit: what is served, what is reachable, what is residue

**Status of this document.** It reports a measurement, not an assurance. It answers
the question "is a path *broken*?" — a path that exists but does not work end to
end — separately from "is a path *missing*?" — a capability that was never built.
The first is a defect; the second is a boundary. Confusing them is how a product
ends up claiming completeness.

Nothing here says the platform has zero broken paths. What it says is: the seven
tests below were run, here is what they saw, here is what they would have caught,
and here is the part they still cannot see.

---

## 1. The seven checks

Each check is a test, runnable on its own. Every one of them was written because
reading the tree turned up an inconsistency that no test covered.

| # | Check | File | What a failure means |
|---|---|---|---|
| 1 | Every path a caller names is a path the app serves | `scripts/tests/test_api_route_contract.py` | A page, script or CLI command 404s in front of an operator |
| 2 | Every endpoint a router defines is mounted | `scripts/tests/test_router_reachability.py` | A handler exists, imports cleanly, and answers nothing |
| 3 | The bank-facing CLI speaks only HTTP | `scripts/tests/test_cli_architecture_boundary.py` | The CLI becomes a second front door that bypasses authorisation and tenancy |
| 4 | The withdrawn transfer family is refused and documented as refused | `scripts/tests/test_offline_transfer_path.py` | An integrator builds against a route that answers `410` |
| 5 | Models and the *migrated* schema agree, and Twin/CLI read paths run on it | `scripts/tests/test_database_contract.py` | Every test passes on `create_all` while the first read in a bank raises |
| 6 | Every route quoted as evidence ("check at", "measured by") is served | `scripts/tests/test_evidence_route_hints.py` | The product tells a reader how to verify a claim, and that route 404s |
| 7 | Every console page is reachable from the router | `scripts/tests/test_frontend_surface.py` | A page ships, its tests pass, and no URL renders it |

```bash
export PYTHONPATH="scripts:shared/shared_models:services/api:shared/shared_config:$PYTHONPATH"
.venv/bin/python -m pytest scripts/tests/test_api_route_contract.py \
    scripts/tests/test_router_reachability.py \
    scripts/tests/test_cli_architecture_boundary.py \
    scripts/tests/test_offline_transfer_path.py \
    scripts/tests/test_database_contract.py \
    scripts/tests/test_evidence_route_hints.py \
    scripts/tests/test_frontend_surface.py -q
```

Check 5 needs a PostgreSQL binary; it uses `pgserver`'s unpacked PostgreSQL on a
unix socket and skips (loudly, via `importorskip`) when that is unavailable.

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
   the first time a bank reads it. Check 5 now runs all 121 migrations on a real
   PostgreSQL and drives the twin store and `cryptoscan twin assets` against the
   result.

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
wrong:

* **Route existence is not response correctness.** 93% of the operations the
  console calls declare no response model, so nothing but
  `scripts/tests/test_console_payload_contract.py` (7 payload families) checks the
  shape of what comes back. A route that returns the wrong fields for a page
  outside those families would pass every check here.
* **No request was executed against a live server for every route.** Checks 1–2
  are structural: they compare the caller's URL with the router table. They prove
  the route is registered and the verb is accepted; they do not prove the handler
  returns `200` with a valid body for a real tenant and a real credential.
* **Authorization is inventoried, not proven per route.** A separate test asserts
  that every route declares an authentication dependency. It does not prove each
  route's role set is the right one.
* **The database contract covers the Twin store and the catalogue read path**
  (`twin assets`), not every one of the 155 mapped tables' read paths.
* **The CLI boundary is a static import check.** It proves `cli_remote.py` cannot
  reach the estate modules; it does not prove a handler in `cli.py` that *is*
  allowed to reach them returns the right answer for every subcommand.
* **`twin` subcommands outside `REMOTE_TWIN_COMMANDS`** still run in-process and
  refuse without an explicit PostgreSQL estate. That is a legacy shape retained on
  purpose (guide 98 §4), it is tested, and it is not evidence that the remote
  equivalents exist.

---

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
