# CryptoScan Implementation Status

> **Historical status record:** the branch/date and local results below describe
> the original 2026-10-12 work, not the active session or a current deployment.
> The later `e9bfbef7` queue/SSH/Redis increment is documented in
> [Guides 44–45](docs/bank-environment/44-queued-authority-and-durable-ssh.md), with
> [current upgrade instructions](docs/runbooks/execution-and-replay-upgrade.md).
> Old measurements and branch provenance are retained rather than silently
> reassigned to this release.

**Date:** 2026-10-12  
**Branch:** `arena/01a106c8-cryproscan`  
**Scope:** 17 implementation commits after `aab86c39`, plus this status record; local verification, **not** a production qualification.  
**Status meanings:** DONE = implemented and specifically verified here; PARTIAL = a verified slice with remaining work; BLOCKED = an external prerequisite prevents completion; UNVERIFIED = no adequate execution evidence.

The repository audits were read before source edits. Historical report labels were checked against current code. No new audit report was created. The development stack remains running locally; it is not the production stack.

## 1. Bugs fixed — PARTIAL

- Legacy PostgreSQL upgrade from revision `0068` failed at migration `0078` on an existing index. `fbdfbf4` validates/adopts pre-existing indexes and records migration-owned indexes for safe rollback. A preserved-data clone upgraded to `0086`, downgraded to `0077`, and upgraded again; the original was subsequently migrated.
- Fact migration `0085` disagreed with platform-null tenancy and used global/NULL-distinct identity. `3991c85` added forward revision `0087`, tenant-local NULL-safe identity, full-rebuild staleness and a savepoint so failed fact materialization cannot roll back scan evidence.
- `b831f3d` removed a job-row self-lock that delayed each scan stage about 30 seconds and hid live progress; the first RUNNING timestamp is now retained.
- `ab18c40` fixed root-run normalization test paths and a lint error. `dd54505` stopped double parsing config findings. `c45baf1` accepts the real scalar-count cloud scanner report without inventing assets.
- `6f62b47` repaired invalid production Compose merges and removed direct production API/frontend host ports. `967d53a` removed predictable smoke-test token files and credential-bearing curl arguments.
- `6a9093d` and `033152f` project safe cloud/organization/binary job failures and cloud-stage metadata rather than raw error text. The latter was an in-memory/logging leak, **not** a confirmed `Scan.statistics` persistence leak.

## 2. Missing components implemented — PARTIAL

- `d2c753c` added SQL-filtered, tenant-visible fact counts and deterministic offset pagination with explicit page-scoped summaries and truncation.
- `0b97266` feeds stored network probes into the existing NBOM generator and projects actual hardware assets from the TechBOM HBOM layer into live cross-BOM queries. The HBOM layer is **not** an independent generator; absent sources are reported as absent.
- No new collector, scanner sandbox, provider integration, or fabricated data source was added.

## 3. Database changes — PARTIAL

- Revision `0087` is applied to the local PostgreSQL estate. A dedicated PostgreSQL migration test database passed 5 live chain/identity tests; platform and two tenant fact identities with unknown key size were inserted in a rolled-back PostgreSQL transaction, and duplicates were rejected.
- `c8274ca` keeps stamped schemas migration-owned: current schemas receive no metadata DDL; behind/error or unstamped PostgreSQL fails with an Alembic instruction; unstamped SQLite development/test bootstrap remains. The current-head stack restarted at `0087` with 123 tables and 584 indexes unchanged.
- `cryptoscan_pre0078_backup` is a local pre-upgrade database copy; `cryptoscan_legacy_upgrade_check` and `cryptoscan_fact_live_test` are local validation databases. They are **not** off-host encrypted backups. Do not delete them without inspecting their contents and confirming the recovery plan.
- Large-estate query performance and concurrent-write pagination stability have not been qualified. Offset pages can shift if data changes between requests.

## 4. Backend changes — PARTIAL

- Real queued scan progress is visible before the evidence transaction commits; the job-to-scan foreign key is attached after commit. Failed pipeline messages no longer expose raw SQL parameters to job clients in the repaired paths.
- The existing API smoke test passed after the latest restart: health, readiness, metrics, login, Technology BOM/assurance, banking and telecom routes.
- Other endpoints have not received a route-by-route authorization or error-shape proof. A cloud subscan can still report FAILED while an overall optional-source scan completes; that verdict needs explicit coverage policy.

## 5. Cryptographic discovery engine — PARTIAL

- Config scanner findings are counted once while named-config, AT-TLS and undiscovered-config fallback paths remain; actual scanner/pipeline tests passed.
- Offline Terraform → `CloudScanner` → `UniversalDiscoveryEngine` now maps only findings with explicit resource identity and provenance; a scalar resource count alone yields partial coverage, not synthetic assets.
- Cross-account/deployment resource identity and held-out detector accuracy remain unverified.

## 6. Evidence and provenance — PARTIAL

- `634e5c1` pins the existing pre-hash source-snippet minimization through SQLite persistence and chain verification using a synthetic non-secret sentinel.
- `3f83413` rejects unsupported **unhashed** provenance/integrity sidecars before DB insertion; 40 focused persistence tests passed. A real PostgreSQL scan after this guard completed with 16 evidence/policy records and only the fixed integrity descriptor fields in provenance.
- Earlier real scans had stored-chain verifier **PASS** (16 and 14 records). A fresh verifier invocation for the post-guard scan was denied by credential-safety permissions, so its chain result is **UNVERIFIED**, not claimed PASS.
- Historical evidence potentially containing raw source snippets was not rewritten or deleted. Operator-led inventory/disposition and reissue preserving chain history are still required.

## 7. BOM systems — PARTIAL

- `a71d2f7` retains every compared value with BOM/component-ref lineage, reports intra-BOM variation separately from unambiguous cross-BOM disagreement, and labels algorithm links as associations rather than physical-asset identity. 89 generated-document/API tests passed.
- `0b97266` adds real NBOM and TechBOM-derived HBOM coverage to live cross-links/query; 45 affected tests passed. Empty sources are not presented as independently observed BOMs.
- Single-generator consolidation, durable cross-BOM physical identity, and completeness at scan-run limits remain open. A match on an algorithm is not proof of the same key or device.

## 8. Knowledge graph — PARTIAL

- `e5a5a05` gives fact/code-graph projections tenant-local complete identities and stable IDs, avoiding same-path cross-tenant node collisions. Focused API/database regressions passed.
- No live Neo4j read-side tenancy, CALLS edges, or end-to-end graph-to-risk traversal was qualified in this pass. Do not infer real dependency paths from co-location.

## 9. Risk and PQC — UNVERIFIED

- Existing deterministic policy/risk/PQC stages ran during real scans; 16 evidence rows had policy results and one local gate reported PASS. This does **not** establish calibrated risk, HNDL exposure, migration-actuator operation or customer PQC readiness.
- No authoritative AI calculation or verdict was introduced.

## 10. Security changes — PARTIAL

- Production Compose now renders in plain and TLS variants with only nginx host ports (80, or 80/443); a CI checker enforces this. No production images or edge deployment were launched.
- Unhashed evidence sidecars and API-visible worker error projections fail closed or use fixed safe categories. Logs retain allowlisted type/frame locations, not raw exception strings/SQL parameters.
- Scanner subprocess/container isolation, real egress controls, infrastructure mTLS, independent penetration testing and historical evidence disposition remain BLOCKED/UNVERIFIED. Source-controlled seccomp/egress helpers alone are not proof of active confinement.

## 11. Frontend changes — UNVERIFIED

- No redesign or new frontend API wiring was implemented in this pass. The existing React frontend typechecked, built and passed **132 Vitest tests in 10 files** before the backend repairs; sandboxed Chromium rendered the sign-in page.
- Page-by-page live-data, navigation, browser interaction, accessibility and tenant-state verification remain open. Existing fragment-style links under BrowserRouter and scanner-choice wiring deserve a focused frontend pass. Do not substitute static metrics or fake findings.

## 12. UI changes — UNVERIFIED

- No claim is made that the current console meets the requested enterprise Cryptography Threat Intelligence finish gate. UI Designer, UX Architect and Frontend Developer implementation/visual verification are still pending. The product must not be presented as an AI chatbot.

## 13. Tests added — PARTIAL

- Added migration ownership/rollback, tenant-local facts, fact-store pagination, live job progress/first-start timing, scanner config deduplication, cloud report shape, evidence snippet/sidecar boundaries, production Compose ingress, worker failure sanitization, and generated/live cross-BOM tests.
- Tests use synthetic non-secret fixtures, actual parsers/generators or isolated databases. They are regression inputs, **not** fabricated production telemetry.

## 14. Tests passed — PARTIAL

- Initial full backend run: **7,187 passed, 20 skipped, 17 errors**. Sixteen errors were a normalization test's root-relative path (fixed); the remaining error was missing declared Hypothesis in this virtualenv. A complete rerun was not possible.
- Root-run normalization/policy focused tests: **34 passed**; full Ruff check passed after the lint fix.
- Migration-0078 focused tests: **13 passed**; fact-store focused tests: **19 passed**; dedicated PostgreSQL chain/identity tests: **5 passed**; subsequent fact API/read-path focused suites: **23** and **21 passed** in separate runs.
- Worker progress regression: **8 passed, 1 PostgreSQL skip locally**, plus agent disposable-PG tests; real source scan moved through visible stages and completed in **10.66 seconds**, with persisted duration **10.12 seconds** and chain verifier PASS for 14 records.
- Production Compose checker passed both overlays. Real `make smoke` passed all configured checks after the latest code restart.
- Scanner config focused pipeline: **12 passed locally**; cloud/platform offline integration: **11 passed locally**; evidence loader/transaction tests: **40 passed**; cloud-stage metadata: **16 passed**; worker failure paths: **32 passed, 1 skip**; cross-BOM generated/API: **89 passed**; live NBOM/HBOM bridge affected suites: **45 passed**; database ownership guard: **22 passed, 1 skip locally**, with one isolated PostgreSQL test passed by its agent.
- Counts are overlapping focused runs, **not** a sum of unique tests or a green full suite. Existing dependency and Pydantic/Alembic deprecation warnings remain.

## 15. Remaining failures — BLOCKED

- Hypothesis is declared in `requirements.txt` but absent from the project virtualenv. The original requirements install failed because optional `pgserver` could not be resolved; that optional root requirement was removed while the parity script retains Docker/CI PostgreSQL paths. A later external package installation was denied pending approval of a named source. **Do not claim the full backend suite passes.**
- `ruff format --check` reported pre-existing formatting in `session.py` and `schema_ensure.py`; Ruff lint and diff checks passed for touched changes. No formatting-only repository rewrite was done.
- A new agent stopped with **HTTP 402 insufficient credits** during the NBOM/HBOM bridge. Its partial changes were reviewed and the affected test set passed before commit. Further requested specialist work was not performed by routing around the billing block.

## 16. Remaining blockers — PARTIAL / BLOCKED

- Deterministic drift baseline/change/acknowledgement/resolution workflow needs dedicated implementation-level tests and an actual two-scan exercise.
- Full CBOM/HBOM/VBOM/NBOM/TechBOM → asset → graph → risk → remediation lineage is not verified; independent physical identity and source completeness remain open.
- Scanner hostile-input process isolation, provider/HSM qualification, end-user authorization coverage, UI real-data completion, and historical secret-bearing evidence disposition remain open.
- Local development copy/scratch databases and Docker volumes were retained rather than silently purged; an operator should decide their retention/removal.

## 17. Production readiness — BLOCKED

- The latest checked-in bank readiness gate is an **October 4, 2026 FAIL** for an earlier revision; engineering FAIL and HSM/closure/external attestations SKIP. No fresh gate was run on this HEAD.
- A local Compose validation, local PostgreSQL migrations, local real scans and local smoke test do **not** establish immutable release provenance, branch protection, real customer/provider corpora, independent pen test, multi-day soak, DR RPO/RTO, HSM qualification or production staffing.
- Do not mark production-ready without target-environment evidence and external sign-off.

## 18. Next implementation priorities

1. Obtain user approval for the named external package source before installing the declared missing test dependency; rerun the **entire** backend/frontend gate without excluding tests.
2. With specialist-agent credits available, implement and verify deterministic drift lifecycle (baseline → changed/reintroduced → acknowledge → resolve), then real-source BOM/graph dependency paths.
3. Redesign the frontend using its existing real API contracts: route/navigation repair, authenticated empty/loading/error states, traceable metrics, and enterprise security visual finish. Use UI/UX and accessibility checks; never add chatbot framing or sample production numbers.
4. Validate malicious-input scanner isolation, tenant/IDOR controls and historical evidence handling; then build and start production artifacts in a controlled target environment.
5. Execute the full real-input acceptance chain through remediation, rescan, verification, report and authenticated UI; record every failed or untested link rather than marking it DONE.
