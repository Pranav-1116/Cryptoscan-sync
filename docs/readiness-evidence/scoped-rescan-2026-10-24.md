# Scoped rescan inspection execution — 2026-10-24

Baseline: published `ac2e96a85b3b6cbc812c0b9bb9cec29f2e101368`. This increment adds
an actual read-only inspection in the existing CBOM review workflow, not a
completion/production-readiness assertion. [Behavior and limits](../operations/scoped-rescan-inspection.md).

| Execution | Result | Artifact |
|---|---|---|
| Selected broad Python regression, including evidence and actual file-receipt tests | **1,185 passed**, six warnings, 259.25 s | [Transcript](scoped-rescan-2026-10-24/python.txt), [JUnit](scoped-rescan-2026-10-24/python.xml) |
| Complete frontend test invocation | **583 passed / 56 files** | [Transcript](scoped-rescan-2026-10-24/frontend.txt), [JUnit](scoped-rescan-2026-10-24/frontend.xml) |
| Final focused inspection contracts | **23 passed**, including refined NULL-estate/read-only-role checks | [Transcript](scoped-rescan-2026-10-24/focused.txt) |
| Final focused UI/legacy panel | **17 passed** | [Transcript](scoped-rescan-2026-10-24/ui.txt) |
| Real PostgreSQL | **37 passed**: 22 inspection contracts plus 15 existing controlled-history contracts | [Transcript](scoped-rescan-2026-10-24/postgres.txt), [JUnit](scoped-rescan-2026-10-24/postgres.xml) |
| Existing real-browser history workflow, rerun against current app | **15 passed** | [JSON](scoped-rescan-2026-10-24/history-setup.json) |
| New real parser → evidence pipeline/loader → PG → browser inspection | **6 passed**, no browser page errors | [JSON](scoped-rescan-2026-10-24/browser.json), [Screenshot](scoped-rescan-2026-10-24/browser.png) |
| Final typecheck/build/Ruff/pip-check | Passed | [Types](scoped-rescan-2026-10-24/typecheck.txt), [Build](scoped-rescan-2026-10-24/build.txt), [Quality](scoped-rescan-2026-10-24/quality.txt) |
| Owned sandbox cleanup | Services stopped, ports closed, private config/data removed | [JSON](scoped-rescan-2026-10-24/cleanup.json) |

The 23 API tests cover a valid rescan, wrong system/tenant/NULL estate, wrong
configured target/branch, requested commit identity, nonlocal method, old/future
scan, unfinished job, missing/unparsed/unmatched receipts, modified payload or
manifest, nonlatest scan, receipt/evidence bounds, empty commitments, mutable
metadata and actual local scanning/loading. PostgreSQL executes the same cases
apart from the test-only monkeypatched zero-record bound; SQLite covers that
bound. Current readonly access and NULL/platform exclusion were refined and
rerun after the broad invocation; no production grant was changed.

The browser run used an owned migrated 0107 schema, real password sessions,
actual MD5-positive and noncrypto source files, real parser receipts and evidence
hashes, actual PostgreSQL loading, current UI requests and deliberate tampering.
It confirmed that tampering receives 409 and removes the earlier visible proof,
foreign tenant reads receive 404, and clean grades remain blocked. The historical
15-check harness rerun also covers original asset/evidence preservation and audit.
The source fixture files contained no secrets and were removed.

**The job/system completion envelope was fixture-provisioned, not dispatched by
a production worker.** Actual scanner/evidence/loader execution is not full
worker admission, isolation, queue execution, signed source attestation or bank
qualification. The first browser attempt correctly rejected a NULL-owned fixture
scan because the standalone harness had not installed the normal tenant guard.
The harness was corrected; the successful run used normal tenant stamping and
was repeated without disabling login/rate-limit protections. That rejection was
not bypassed or converted into a permissive tenant rule.

The final UI also rejects contradictory/mismatched live-shaped HTTP200 responses
rather than manufacturing a verified badge. This final defensive check was added
after the recorded browser run and exercised by the full 583-test frontend run
and 17 focused panel tests; the browser artifact is not a rerun of that last
client-side refinement. Its recorded valid proof includes the required integrity
flags and scoped non-clearance fields.

No paired performance improvement, new capacity/SLO, accuracy denominator,
current external security review, deployed recovery or independent bank approval
is claimed. Previous recovery/capacity artifacts remain tied to the earlier
increment; they were not refreshed by this inspection work. Partial-history
clearance, full expected-scope validation and the rest of the original45 remain
open. Source/artifact [hashes](scoped-rescan-2026-10-24/manifest.json) aid inspection,
not independent signature verification. [Replay](scoped-rescan-2026-10-24/README.md).
