# Historical CBOM increment — retained execution, 2026-10-24

**Bank approved: false. Whole-product production qualified: false.**

[Implemented contracts](../operations/historical-cbom-reconciliation.md) ·
[operator runbook](../runbooks/historical-cbom-reconciliation.md) ·
[artifact index / replay](historical-cbom-2026-10-24/README.md) ·
[hash manifest](historical-cbom-results-2026-10-24.json).

## Executed after restoring the interrupted workspace

The restored working files contained the implementation but the local Git baseline
and external scratch environment had reset. The published branch tip was fetched
and the local branch/index reconciled with a **mixed** reset, preserving working
files. This reduced the apparent 1,707-file patch back to the intended increment.
The Python environment, frontend dependencies, disposable PostgreSQL databases,
synthetic principals and browser were then freshly provisioned. The results below
come from this fresh run, not lost pre-interruption scratch logs.

| Check | Result | Retained record |
|---|---|---|
| Selected Python regression suite | **1,020 PASS**, 4 warnings, 157.22 s | [XML](historical-cbom-2026-10-24/python.xml), [text](historical-cbom-2026-10-24/python.txt) |
| Full frontend test suite | **568 PASS / 54 files**, 20 existing React `act` warnings, 140.57 s | [XML](historical-cbom-2026-10-24/frontend.xml), [text](historical-cbom-2026-10-24/frontend.txt) |
| Actual PostgreSQL source/audit/migration suite | **27 PASS**, 20.39 s | [XML](historical-cbom-2026-10-24/postgres.xml), [text](historical-cbom-2026-10-24/postgres.txt) |
| Actual Chromium historical workflow | **17 PASS** | [JSON](historical-cbom-2026-10-24/browser.json), [text](historical-cbom-2026-10-24/browser.txt), [screenshot](historical-cbom-2026-10-24/browser.png) |
| Existing real import/export/browser regression | **16 PASS** | [JSON](historical-cbom-2026-10-24/existing-browser.json), [text](historical-cbom-2026-10-24/existing-browser.txt) |
| Typecheck, compiled frontend build, Python lint, dependencies, diff | PASS | [typecheck](historical-cbom-2026-10-24/typecheck.txt), [build](historical-cbom-2026-10-24/build.txt), [quality](historical-cbom-2026-10-24/quality.txt) |
| Owned-service/data/credential cleanup | See explicit record | [cleanup](historical-cbom-2026-10-24/cleanup.json) |

Counts are not additive measures of coverage: the selected suite includes the
new API/SQLite provenance tests; the PostgreSQL suite separately includes thirteen
source-parity cases, four concurrency/isolation controls and ten migration cases.

## What the execution demonstrates

- Historical read projection and coverage correction without rewriting original
  confidence, timestamps, scanner metadata, finding data or evidence hashes.
- Tenant-scoped actual session authentication, foreign-system 404 and readonly 403.
- Reimport, source snapshot/fingerprint review, committed audit receipt, authenticated
  native export, reload and actual SQL readback. The page uses relative API URLs.
- Two simultaneous HTTP reconciliations: **one 200 and one stale-review 409**.
- Refusal of mixed-evidence, missing/incomplete replacement, stale, oversized and
  failed-commit/audit cases; shared rows are not globally archived by one system.
- Later evidence on an old archive reopens the current portfolio export block.
- The real PostgreSQL **unlocked negative control** commits eight sequence-1 audit
  entries in a separate owned scratch database; the chain verifier refuses it.
  With the transaction advisory lock, eight concurrent appends form one sequence
  1–8 and a valid chain. Rollback releases the lock without consuming a sequence;
  REPEATABLE READ is refused. Scratch audit databases are dropped by their fixtures.
- The managed application audit chain also verifies OK in the browser harness.
  This is not an independent external witness or DB-administrator tamper protection.
- SQL LIMIT is asserted on the portfolio payload query; count and bounded payload
  use one window-count statement. This is a functional bound, not latency evidence.

## Environment and caveats

Python 3.11 / repository locked dependencies, pgserver 0.1.4 PostgreSQL helper,
Playwright 1.64.1 and Chromium 153.0.8010.0. Actual app database migrated to **0107**;
migration tests destructively reset only the separately named owned
`cryptoscan_migration_test`. Audit concurrency controls create/drop only randomly
named owned `cryptoscan_e2e_audit_*` databases with the minimal audit table.

The browser uses a production-compiled frontend and a **development-settings API**,
local synthetic accounts, test-only cookies and local PostgreSQL. Chromium's
no-sandbox flag is confined to this disposable environment, not a production
browser-isolation recommendation. No credentials, raw uploaded document or saved
session cookies are retained in these artifacts.

The normal login limit is **five requests/minute/IP**. The two three-login browser
harnesses ran in separate owned API process sessions, leaving rate-limit code and
configuration intact. Do not disable security controls to make a combined run pass.

The pre-interruption test work exposed fixture/invocation mistakes (wrong import
path/environment key, ambiguous checkbox, normal login rate limit, and relative
PYTHONPATH during migration subprocesses). Those partial attempts are not counted
as passing evidence. The fresh run used exact checkbox scoping, absolute import
paths and explicit live-test selection; retained final XML has no skipped checks.

This is not a complete repository/CI/image/security/deployment gate. Performance
p95/p99 and the agreed relative improvement targets were not measured; no caching
was introduced. Mixed-source, unassigned and oversized historical review remain
controlled operator work, not automatically solved. No fresh DR/backup/PITR/HA,
provider discovery completeness, PQC/HSM interoperability, accessibility/Arabic,
independent bank acceptance, staffing or SLA qualification was performed. The
original-question acceptance register remains blocked and is not relabelled by
these tests.
