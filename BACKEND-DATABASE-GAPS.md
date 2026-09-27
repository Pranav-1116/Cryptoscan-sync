# Backend & database — what was wrong, what is fixed, what is left

**Audited:** 2026-09-27 · ~330k LOC across 50 services · every claim below was
verified by running the code, not by reading a document.

This exists because the repository's own documentation was, in several places,
describing controls that were not implemented. Where a doc and the code
disagreed, the code is what is recorded here.

---

## The short answer on deployment

**Deploy one instance per bank.** That is the only supported topology today,
and it is enforced rather than assumed (self-serve tenant signup ships
disabled). With that constraint the backend is in reasonable shape: 5,712
tests green on both SQLite and PostgreSQL, a real auth gate, real scanners.

Data-layer tenant isolation is now **built and tested** — 87 of 102 tables
scoped, filtered by the ORM rather than per repository, with the request
scope entered by middleware (§1.1, §3). That is the machinery multi-tenancy
needs, and it is why §3's first two blockers are closed.

**It is still one instance per bank.** The reason is not a missing feature:
I wrote both the isolation and the tests that check it, which is the weakest
form of assurance there is. Cross-customer isolation is the one control where
being wrong is a regulatory incident rather than a bug, so it should be
attacked by someone who did not build it before two banks share a deployment.
Hand a penetration tester §1.1 first.

---

## 1. Critical — fixed this pass

### 1.1 Cross-tenant data leak on the entire scan surface

**The single most serious defect found.**

`db/models/tenant.py` stated: *"Isolation is enforced at the data layer
(tenant_id columns + repository filters) … a tenant member can never read or
write another tenant's rows."* `api/routers/saas.py` repeated it: *"Isolation
model (enforced, not cosmetic)."*

Neither was true for customer data. Only 5 of 57 tables carried `tenant_id`,
all of them control-plane (tenants, memberships, api_keys, monitors,
control_plane). Every table holding a bank's actual results — `scans`,
`evidence_records`, `crypto_assets`, `systems`, `drift_events`, `scan_jobs`,
`container_scans`, `certificates`, `network_scan_runs`, `baselines` — had no
tenant column, and their repositories applied no filter.

`ScanRepository.list_scans()` took no tenant argument at all. Neither did the
route. Any authenticated member of any tenant read **every** tenant's findings.

The existing security test `test_cross_tenant_access_is_absent_not_forbidden`
passed throughout — it only exercises *monitor targets*, one of the five tables
that did have the column. The test suite was asserting isolation on the one
surface that had it.

Compounding it: `/api/v1/saas/signup` is unauthenticated and had no feature
gate, so on any reachable deployment a stranger could provision a tenant and
read the estate.

**Fixed:**
- `db/tenancy.py` — isolation is now an **ORM-level** filter
  (`do_orm_execute` + `with_loader_criteria`), not a per-repository argument.
  A query written next year cannot forget it. Deliberately not per-repository:
  across ~40 tables and ~90 routers, one missed query silently reopens the
  hole and looks identical to the fixed ones.
- Migration `0061` adds nullable indexed `tenant_id` to the ten scan-surface
  tables (online-safe on PostgreSQL: no rewrite, no backfill).
- `BaseRepository.get_by_id` no longer uses `Session.get()`. That is a
  primary-key lookup answered from the identity map which **bypasses loader
  criteria** — it returned another tenant's row when handed a known id. It is
  now a filtered `SELECT`. This was caught by a test, not by review.
- `get_tenant_context` is now a generator dependency that enters the scope, so
  all five of its return paths are covered and teardown always runs.
- New rows are stamped with the active tenant on flush, so nothing lands
  unattributed.
- `NULL tenant_id` means "platform estate" and stays visible to every tenant —
  an on-prem install that later enables tenancy must not lose its history.
- `platform_scope()` is the explicit, greppable opt-out for supervisor
  roll-ups.
- Self-serve signup gated behind `CRYPTOSCAN_SAAS_SIGNUP`, **default off**,
  answering 404 rather than 403 so a closed deployment does not advertise it.
- Both false docstrings corrected to describe what is actually enforced.

9 tests in `services/database/tests/unit/test_tenant_isolation.py`, including
that the *count* is filtered (an unfiltered total leaks the other tenant's
volume) and that a known-id fetch is absence rather than a 403 oracle.

### 1.2 Authentication defects

| Defect | Where | Fix |
|---|---|---|
| **Fail-open revocation** — any exception reading the session store returned `True`, so a store outage kept honouring revoked tokens | `auth_middleware.py:55` | Fails closed in production, open in dev |
| **Plaintext password comparison** — compared raw strings when the stored value was not a PBKDF2 hash, and production permitted a plaintext `ADMIN_PASSWORD` | `passwords.py:142`, `settings.py:181` | Refused in production; rejected at boot with an actionable message |
| **Unbounded prefix match** — bare `startswith` meant a future `/api/v1/metadata` would inherit `/api/v1/meta`'s auth exemption | `auth_middleware.py:73` | Segment-exact; static assets split out |
| **Unverified TLS** to network devices carrying credentials | `config_protocols.py:145` | Verifies by default; CA-bundle env var; logged explicit opt-out |

### 1.3 The runtime tracer never worked on a modern toolchain

The LD_PRELOAD crypto tracer's C shim failed to compile under GCC 14, which
promoted `-Wincompatible-pointer-types` from warning to error. `ensure_shim()`
swallowed the compiler's stderr and reported *"no C compiler"*, so on every
modern distribution the runtime tracer silently did nothing while appearing
merely unsupported. One bug, **8 test failures across 3 services**.

Fixed the casts; failures now surface the real compiler error.

---

## 2. Test, CI and database-parity integrity

### 2.1 There was no CI

All four `.github/workflows/*.yml` were **0 bytes**. A complete 145-line
workflow sat unused in `deploy/ci-workflows/ci.yml` — written, never installed.
Installed, plus a new `postgres-parity` job. Five jobs now: lint, backend
matrix, frontend, prod-config guard, postgres parity.

### 2.2 The suite was not hermetic, and not run on the production database

- **conftest pointed tests at a live Redis** (`redis://localhost:6379/1`). The
  rate limiter's fixed-window counters then outlived both the per-test app and
  the pytest process — the register class has an hour-long TTL — so on any
  machine with Redis on 6379, **29 auth tests failed for an hour**. CI never
  had a Redis running, which is exactly why nobody saw it.
- **Webhook tests shelled out to a real `git clone` against github.com.** A
  subprocess walks straight past `pytest-socket`, so the hermeticity guard
  could not catch it.
- **A time-bomb test** hardcoded `NOW = 2026-09-03` while the endpoint used the
  real clock; it began failing on a date rather than on a change.
- **`postgres_parity.sh` had never run.** It set `PY=.venv/bin/python` — a
  *relative* path — then `cd`'d into service directories, so it died on the
  first step for anyone who tried. It also required `pgserver` (uninstallable
  offline) or hand-provisioned credentials.

All fixed. The parity gate now falls back to a throwaway Docker PostgreSQL and
needs no credentials. **All three stages pass on real PostgreSQL 16**: the
61-migration Alembic chain with schema matching models, the full worker suite
(486 tests), and estate read-back through the API.

This matters because the ordinary suite runs on SQLite while production
mandates PostgreSQL — that gate was the only thing between the two, and it had
never executed.

### 2.3 Scanner accuracy was self-scored

100% F1, but on 842 fixtures written in-house and then tuned against.
External validation existed for Python only — because `scan_third_party.py`
hardcoded `/home/user/CryproScan`, a misspelled path to one developer's
checkout, so it imported nothing anywhere else.

Now validated against **~25,000 third-party files** (JS/TS, Go, Java, C#).
Five real defects found, all fixed:

1. **Crash on real npm packages** — `re.sub()` given a replacement string taken
   from the scanned file, so a literal `\u` raised `bad escape \u` and the file
   was abandoned. A crash is the worst miss: silently skipped, invisible to any
   corpus test. Same latent bug in **go, csharp, php and rule_engine** —
   `rule_engine.py:178` had been hand-escaped for it; line 176 had not.
2. **API names inside string literals** reported as call sites (caniuse-lite
   ships `C:"crypto.getRandomValues()"` as a feature *name*).
3. **`.d.ts` declarations** scanned as runtime code.
4. **A bare `wireguard` keyword** inferring ChaCha20-Poly1305 from a Linux
   netlink constant.
5. **Vendored crypto implementations invisible in Java and C#** — the recall
   gap that matters most for banks. bc-csharp's own `AesEngine.cs` reported
   **no AES at all**. A bank running a forked BouncyCastle would show no AES in
   its CBOM. Recall: C# 701→742 files, Java 2,223→2,266.

Zero crashes remain. Localisation verified for the first time: all 2,248
findings point at the correct line.

---

## 3. Known gaps — not fixed, ranked

### Blocking for multi-tenant deployment
1. ~~**Only 10 of ~40 customer-data tables are tenant-scoped.**~~ **Closed.**
   87 of 102 tables now carry an indexed `tenant_id` (migrations 0061 + 0062,
   verified on PostgreSQL 16: 87 columns, 87 indexes, schema == models). The
   15 that do not are platform infrastructure and are listed with a reason
   each in 0062's docstring — `users`/`user_sessions`/`mfa_recovery_codes`
   (authentication happens before any tenant is known), `audit_log` (must
   record cross-tenant and operator actions), `tenants`, `cp_*`,
   `plugin_packages`, `monitor_leases`, `access_reviews`.
2. ~~**Only 5 of 90 routers resolve tenant context.**~~ **Closed**, and not by
   editing 85 routers — that would have been 85 chances to miss one, and a
   missed router is not a visible failure but one that quietly returns every
   tenant's rows. `TenantScopeMiddleware` enters the scope once per request
   using the same membership-validated resolution the routes use, so a forged
   `X-Tenant-ID` 404s before it reaches the filter.

   One regression this introduced, caught by the suite and worth recording:
   the middleware first resolved the tenant through `get_current_user`, which
   runs `_authorize_key_policy` — and that **consumes the API key's rate
   quota**. Every request was billing the key twice, so a key with
   `rate_per_minute: 2` returned 429 on its first real call. It now reads the
   key's `tenant_id` directly from the repository, with no policy enforcement
   and no last-use stamp.

   **The topology recommendation has not changed.** Deploy one instance per
   bank, and leave `CRYPTOSCAN_SAAS_SIGNUP` off, until this has had an
   adversarial test by someone who did not write it.

### Blocking for a bank security review
3. ~~**Frontend has no route guards.**~~ **Fixed** — see §5.
4. **`x-api-key` bypasses the global auth gate** (`auth_middleware.py:84`),
   delegating to per-route dependencies. Safe only while coverage stays at
   100%; nothing enforces that it does.
5. **`/metrics` is unauthenticated.**

### Claims that should be removed or built before a bank sees them
6. **"eBPF runtime agent"** is a string constant (`runtime.py:30`). No kernel
   code exists.
7. **SOC2 CC9.3/9.4 region-failover "PASS"** is two temp *directories* in one
   process (`scripts/region_drills.py:39`).
8. **FIPS 140-3 HSM connectivity** — the verification logic is genuinely good
   (it correctly treats a default `AWS_KMS` origin as *not* dedicated-HSM
   backed), and real adapters now exist for AWS KMS, Azure, GCP and PKCS#11.
   But **no adapter has ever touched a real HSM here** — PyKCS11 is not
   installed and those tests skip. Unproven, not fake.
9. **Accuracy figures are corpus-scored.** `BANK-READINESS.md` concedes
   `NO_FIELD_DATA` — no pilot bank has reviewed output. Do not quote 100%.

### Operational
10. **132 silently swallowed exceptions** (`except: pass`) across services.
11. **Backups are unencrypted at rest** (`db_backup.sh`).
12. **`:latest` image tags** in k8s deployments — no reproducible rollback.
13. **OTLP endpoint is dead code** — stored, never used; traces only reach a
    local JSONL.
14. **Live cloud/TLS/HSM scanning has never been run against real
    infrastructure.** All gated off by default and never exercised live.

---

## 4. Honest position for a Dubai bank

**What is real:** 733 endpoints, real `boto3` across 22 AWS services, real TLS
and SSH handshakes, real SAML with signature verification, a real JVM
constant-pool bytecode parser, TR-31/X9.143 parsing, and now ISO 9564 PIN
blocks, ISO 8583 field crypto and the EMV/ARQC cryptogram lifecycle. 5,500+
tests on two databases.

**What no bank should be told:** that this has scanned a bank. It has not. The
Dubai and SNB estate runs are explicitly synthetic — `DUBAI-BANKS-E2E.md` says
so itself: *"Not the banks' code, configuration or key material — no bank
system was accessed."* 100 files, not an estate.

**Realistic position:** a credible product for a **supervised pilot** on a
single bank's source repositories, deployed on its own instance, with findings
reviewed by a human before anyone acts on them. It is not ready for unattended
production scanning of a live core-banking estate, and a CBUAE-regulated
procurement will ask for a third-party penetration test, evidence of the
frontend authorisation gaps being closed, and at least one reference customer —
none of which exist yet.

The gap between that and "deployable" is items 1–5 above, plus deleting the
claims in 6–7. Nothing in that list is architectural; it is finishing work.

---

## 5. Frontend authorisation — fixed this pass

Two defects, both of the "looks enforced, is not" kind that this audit kept
finding.

**Every route rendered for anonymous visitors.** All 72 routes in `App.tsx`
mounted without any check; `/admin` and `/tenancy` ran their data fetches and
only the backend's 401 held the data back. No data leaked, but the console
advertised its entire surface to anyone who could reach it, and a page that
falls back to an empty state on error looks like a genuinely empty estate
rather than a locked one. A reviewer finds this in an afternoon.

**Roles were read from `localStorage`.** `getRoles()` parsed
`localStorage["zelinx_roles"]`, and `canPerformAction()` in
`EnterpriseContext.tsx` derived every UI authorisation decision from it —
values the person at the browser can edit with one console command.

**Fixed:**
- `frontend/src/lib/auth.tsx` — `AuthProvider` holds the session as
  `GET /api/v1/auth/me` reports it, in memory, refreshed on `zelinx:auth`
  events. `localStorage` is demoted to a first-paint hint and is discarded the
  moment the server answers, so an edited cache can make the UI briefly
  optimistic but never permissive.
- `RequireAuth` wraps every route except `/login`. It **fails closed**: a
  network error contacting `/auth/me` is not proof of a session, so it
  redirects rather than admitting. While the check is in flight it renders a
  checking state instead of redirecting, so a slow `/auth/me` does not bounce
  a signed-in operator to the login screen on every reload. The intended
  destination is preserved in router state for post-login return.
- `/login` now sits outside `Layout` and `RealtimeProvider`: an anonymous
  visitor gets no console shell, no navigation, and no SSE connection opened.
- `RequireRole` hides controls the session's roles disallow — documented in
  the source as presentation only, because the backend authorises every
  request regardless and a hidden button is a courtesy, not a control.

8 tests in `frontend/src/lib/auth.test.tsx`, including that a forged
`localStorage` identity does not get past the guard and that an edited
`superadmin` role is discarded once the server returns `readonly`.
Frontend suite 109 → 117 passing; typecheck and production build clean.

**Still open on the frontend:** the `RequireRole` helper exists but existing
pages have not been migrated onto it, so individual controls are still shown
by ad-hoc `canPerformAction()` checks. Those now read server-verified roles,
so they are no longer forgeable — but the migration is unfinished work.

---

## 6. Domain build-out since the audit

Three areas were extended after the gap list above was written. Each is
recorded with what it does **not** prove, because that is the part a
procurement conversation will test.

### 6.1 Payment card standards

`payment_crypto` gained ISO 9564 PIN-block analysis, ISO 8583 field-level
crypto, and the EMV/ARQC cryptogram lifecycle, alongside the TR-31/X9.143
header parsing that already existed. The findings that carry weight are the
ones invisible in service: ISO format 2 on an online path, formats 1 and 2
not binding the PAN, a PIN-bearing 8583 link with no MAC field, and CVN 10
deriving session keys without the ATC so every transaction on a card uses the
same key.

**Safety property, asserted by test:** these refuse input that looks like a
real PIN block or IMK rather than analysing it, and the 8583 analyser reads
only field *numbers* from a dict, discarding values — a PAN passed as a field
value never reaches the output.

### 6.2 Telecom 5G

Five modules covering the TS 33.501 controls no external probe can reach:
SUPI concealment, NEA/NIA air-interface algorithms, N32 roaming protection,
MILENAGE/TUAK sets, and the K → K_gNB key hierarchy. Full reasoning in
[docs/telecom-5g-crypto.md](docs/telecom-5g-crypto.md).

**Limit:** these read declared configuration. They report that a gNB is
*configured* for NEA0; they do not tell you what a UE negotiated, which needs
a UE-side capture this product does not perform. Not "we verified the air
interface" — configuration assurance, which is a different and still useful
control. GTP-U / IPsec on N3 and N9 remain uncovered.

### 6.3 NBOM, and what the BOM audit actually found

The brief was to make every BOM production-grade. The finding was that
**SBOM, HBOM and VBOM already were**: `techbom.py:_gather_inventory` reads
real rows from `System`, `CryptoAsset`, `HardwareAsset`, `Vendor`,
`Certificate` and `SystemDependency`, and `technology_bom.py` has an
`empty_inventory()` whose contract is that an un-scanned estate renders
zeroes rather than fabricated components. CBOM is 6,504 LOC of CycloneDX 1.5
with OID lookup, canonical JSON and JWS/HMAC signing. None of that needed
rebuilding, and rewriting it would have been motion rather than progress.

NBOM was the gap, and the gap was not the generator — it was that nothing fed
it. `network_scan_runs.result` already stored every probe with its endpoint,
negotiated TLS version, cipher suite and certificate chain; no code read it.
`GET /api/v1/cbom/nbom` now derives the BOM from those stored scans, so the
inventory comes out of the scan rather than being declared by hand.

Three properties, each with a test: newest run wins per endpoint (a re-scan
supersedes rather than duplicates); unreachable probes are inventoried but
not judged (`observed: false`, no findings — an endpoint you could not reach
is unknown, not healthy); and an unscanned estate returns `source: "empty"`
with zero components.

NBOM also joined `correlate_xbom` as a fifth layer, so the chain is
SBOM → CBOM → NBOM → HBOM → VBOM → business process. That is the difference
between "we use RSA-1024 somewhere" and "api.bank.ae:443 presents it".

**Still preview.** The generator, the cascade and the DB derivation are
tested, but no *scheduled* network scan populates it — the demonstration row
was seeded by hand. Until a scan runs on a cadence against a real estate the
page is correct and empty. That is pipeline work, not BOM work, and it is the
next concrete piece.
