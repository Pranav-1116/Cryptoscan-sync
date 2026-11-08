# End-to-end data-path hardening — execution, 2026-10-24

**Result: implemented and locally exercised; whole-product/bank production approval remains BLOCKED.**

Baseline: `9afa6f6125b3b606c994e6620f1fe2e64683b394`, branch `arena/bb4b80dd-cryproscan`. No customer deployment or existing production database was changed. Publication uses `[skip ci]`; no workflow changes, remote CI/image execution or merge is claimed.

## What was executed

| Check | Actual result | Retained record |
|---|---|---|
| Expanded selected Python regression | **974 PASS**, 0 failures/errors/skips, 4 existing warnings, 141.42s pytest time | [JUnit](production-data-path-2026-10-24/python.xml), [output](production-data-path-2026-10-24/python.txt) |
| Full frontend Vitest suite | **561 PASS / 53 files**, 20 existing React `act` warnings, 131.13s | [JUnit](production-data-path-2026-10-24/frontend.xml), [output](production-data-path-2026-10-24/frontend.txt) |
| Real PostgreSQL migration chain | **10 PASS**, no skips, 18.36s | [JUnit](production-data-path-2026-10-24/postgres.xml), [output](production-data-path-2026-10-24/postgres.txt) |
| Real Chromium → built frontend → full API → PostgreSQL | **16 checks PASS**, no page errors | [results](production-data-path-2026-10-24/browser.json), [output](production-data-path-2026-10-24/browser.txt), [screenshot](production-data-path-2026-10-24/cbom-browser.png) |
| Controlled API/PostgreSQL restart and browser readback | **4 checks PASS**, saved session restored without a new login | [browser results](production-data-path-2026-10-24/restart-browser.json), [output](production-data-path-2026-10-24/restart-browser.txt), [database proof](production-data-path-2026-10-24/restart-database.json) |
| Frontend typecheck / production compilation | PASS; build 1.52s | [typecheck](production-data-path-2026-10-24/typecheck.txt), [build](production-data-path-2026-10-24/build.txt) |
| Changed Python Ruff F, dependency consistency, diff whitespace | PASS | [quality checks](production-data-path-2026-10-24/quality.txt) |
| Original-question register / strict review | Integrity PASS; strict expected exit **1 / BLOCKED** | [register](production-data-path-2026-10-24/register-review.json), [strict](production-data-path-2026-10-24/strict-review.json) |

Counts overlap in coverage, not in execution claims: 974 is the selected Python run, the 10 live PostgreSQL tests are separate, and the browser script's named assertions are **not** additional pytest tests or independent certifications. This is not all Python tests in the repository.

## Genuine end-to-end path

The browser used **Chromium 153.0.8010.0**, Playwright 1.64.1, a Vite **production build** served through its preview proxy, the normal full API application, and a newly created PostgreSQL database migrated from base to **0107**. There were **no mocked API responses, ASGI transports, auth dependency overrides or metadata `create_all`** in this browser run. API settings were **development**, with the normal durable user/session/tenant data path. This does not exercise activated production control-surface admission, TLS/Redis/HA or a production image.

Three synthetic, hashed-password users were provisioned: separate security analysts in `e2e-a` and `e2e-b`, and a readonly member of `e2e-a`. Credentials, application secret and saved cookie state stayed outside the repository. The script restricts its database to a `cryptoscan_e2e_` name and its HTTP target to loopback. Test tools were external to runtime dependencies: `pgserver 0.1.4` bundled PostgreSQL **16.2**, and `@sparticuz/chromium 153.0.0` supplied the browser. Those helper binaries are **not qualified production infrastructure**.

Executed flow:

1. Real browser password login and normal cookie authentication.
2. Native `File` upload on the existing CBOM page: synthetic ML-KEM-768/AES declarations, owner/classification/retention metadata and declared locations, **not a scan or customer sample**.
3. HTTP committed receipt; native export via the actual authenticated download button; official schema validation of downloaded bytes.
4. Hard browser reload; the live query still displays the persisted ML-KEM identity. A repeat import preserves the system and two asset/link rows.
5. Four simultaneous real HTTP imports to the existing system returned **200/200/200/200** with one system ID. Four simultaneous first-create requests returned **one 200 and three 409s** with one accepted system. Thread scheduling is not an acceptance requirement: an explicit conflict or a serialized matching success is permitted; silent duplicate systems or 500s are not.
6. Private-scope browser event clears the draft. This event test is a display fence, not proof of membership/authorization by itself.
7. Bank B imports the same business name into a different system ID; cross-bank reads return 404 both ways. The readonly browser submits the form, receives 403, shows “Import not confirmed”, and gets no success/export receipt.
8. New PostgreSQL connection verifies persisted rows, LOW declaration confidence, source hashes, PQC parameter `768` separate from reported size `1184`, business context, audit row, tenant-scoped links and unchanged scanner state.
9. API was stopped, then PostgreSQL stopped. A connection attempt failed while stopped. Both restarted with the same data; PostgreSQL postmaster timestamp changed from **2026-10-24T06:59:36.462854+00:00** to **2026-10-24T07:07:14.810780+00:00**. Ten synthetic systems from repeated scratch runs remained ten; this is not ten customer systems or a benchmark corpus.
10. Saved HTTP-only browser session authenticated after restart, exported the stored tenant portfolio and remained unable to read bank B. SQL readback still matched both selected import receipts.

This is **controlled stop/start durability**, not crash recovery, backup restoration, PITR, failover, partition tolerance, a measured RTO/RPO, 24/7 operation or a capacity/p95/p99 test. No agreed performance target is claimed met from these timings or four concurrent requests.

## Regression detail and red-test transparency

The new backend boundary modules contain **33 cases** across import/session/storage and wire limits. They exercise denied durable roles, duplicate bank-local names, declaration persistence and readback, refreshed mode/key size/padding, tampered JSF, rollback on mid-import failure, commit failure returning 503, source namespaces, field limits, nonfinite JSON, preserved failed scans, receipt/audit survival, scalar supplier context, malformed legacy metadata, nested/native unsupported profile rejection and chunked limits.

The frontend suite adds nine cases for authenticated upload/readback, invalid/oversized files, ambiguous write failure, draft/parse/receipt fences, stale snapshot selection and unknown coverage. The full suite retains its 20 pre-existing `act` warnings; new test warnings were corrected rather than suppressed.

Retained [initial red run](production-data-path-2026-10-24/initial-red.txt) has four genuine contract failures and two faulty test fixtures: the JSF call used the asymmetric default with a text secret, and the rollback test set an ineffective TestClient attribute instead of asserting the injected server exception. These fixtures were corrected. A preliminary signature-only baseline check also passed for the wrong reason: without a URI checker, the schema itself rejected HS256. That was not accepted as crypto-verification evidence. The final test first proves the signed native document is schema-valid; [rerunning it against the baseline ingest implementation](production-data-path-2026-10-24/corrected-signature-baseline-red.txt) then correctly fails with HTTP 200 instead of expected 422. The final hardened run passes.

One older coverage-prose assertion was intentionally updated from “unknown cryptography” to “unobserved cryptography”, matching the now-explicit distinction between imported declarations and scanner observations. One signature/transaction unit test explicitly grants its mocked writer dependency; actual durable-role denials are separately tested without that override.

Owned API/frontend/PostgreSQL processes were stopped after verification; the owned PostgreSQL directory and external synthetic credential/cookie-state files were removed. [Cleanup record](production-data-path-2026-10-24/cleanup.json). Retained records contain no login/session credentials.

## Limits and rollout

The [implementation/remaining-work matrix](../operations/production-data-path-hardening.md) is authoritative for scope. In particular, historical demo/import confidence stamps and lost original source context are **not retroactively repaired or authenticated**. Native import is a bounded flat algorithm-metadata profile, not lossless arbitrary CBOM/certificate/key/protocol import. Repeat import is append/refresh, not exactly-once processing or automatic retirement.

Follow the [0107 operator runbook](../runbooks/cbom-0107-upgrade.md). Independent security/accessibility/Arabic and supported infrastructure/CI/image/deployment approval, whole-bank discovery completeness, broader adapter engineering, measured PQC/HSM migration, commercial/corporate facts and real staffing/support remain outside these results. NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM are still six distinct BOMs. The original-question register remains open/blocked; these results do **not** complete all 45 capabilities or qualify the whole product for production.

[Replay prerequisites and commands](production-data-path-2026-10-24/README.md) · [Source/record manifest](production-data-path-results-2026-10-24.json)
