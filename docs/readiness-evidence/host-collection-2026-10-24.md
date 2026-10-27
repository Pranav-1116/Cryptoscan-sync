# Controlled offline host collection — implementation and execution evidence

**Date:** 2026-10-24 UTC. **Base:** `caa281339499c426576109fd372ff3863f7c093a`.
**Branch:** `arena/bb4b80dd-cryproscan`, PR34; no merge/deployment/bank approval implied.

## Delivered behavior

This is the first host-first slice of the ten-point request, not completion of
the joined bank estate. [Operator/data contract](../bank-environment/59-approved-offline-host-collection.md) ·
[Ten-point/six-BOM/estate acceptance ledger](../bank-environment/60-host-first-product-acceptance.md).

- Explicit offline manifest, no Git dependency, no recursive discovery, no shell,
  binary execution, network acquisition, automatic upload or elevation.
- Public certificate/configuration/binary-header/package metadata with bounded
  per-input receipts. Private material/raw configuration/certificate bodies are
  not uploaded. Root/capabilities, inaccessible/special/changed/oversized inputs
  are refused; an unavailable identity check is not labelled an observed elevation.
- Current admin/CISO exact-estate approval; analyst human intake; auditor/viewer
  inspection/export cannot modify a scan. One-use approval binds the exact
  manifest and permitted collection interval, not an attested physical host.
- Existing `EvidencePipeline`/`BulkInserter`/`Scan`/`EvidenceRecord` and append-only
  assurance records; atomic intake/audit with PostgreSQL concurrent consumption
  refusal/idempotency. Critical source/projection/ID/timestamp ownership closure
  is checked before host reads and exports.
- Server source is **IMPORTED**, not OBSERVED. Local metadata claims remain separate.
  Configuration is DECLARED, runtime/PQC UNKNOWN, policy NOT_EVALUATED.
  EC subject keys stay EC-family metadata; a separate certificate-signature OID
  does not establish ECDSA/ECDH application use (including an RSA-signed EC-key fixture). Missing
  collection is not a secure/insecure verdict. No complete-coverage stamp, crypto
  rollup adoption, policy assessment or inferred system/HSM dependency edge.
- Native CycloneDX1.6 uses the existing full pinned official offline schemas.
  Versioned strict host contracts and deterministic golden/property tests are
  committed. Host export derives facts from committed finding data, not mutable
  normalized/policy sidecars. Schema-valid is not independently interoperable,
  production-qualified or bank-approved.
- Existing CBOM page now provides explicit approval/import/inspection/export,
  honest limitations, private-scope fences and no sample/automatic retry path.
- Controlled production API admission deliberately remains **409** for this new
  surface. There is no positive isolated host scanner/worker execution witness.

## Final validation

Final run results and source/artifact hashes are retained alongside this report:
[replay instructions](host-collection-2026-10-24/README.md).

| Final check | Observed result | Evidence |
|---|---|---|
| Selected product/host/schema/evidence/database/API regression | **1,455 passed, 1 skipped**, 12 warnings, 134.98s; exit0 | [Transcript](host-collection-2026-10-24/regression.txt), [JUnit](host-collection-2026-10-24/regression.xml) |
| Actual authenticated API on owned PostgreSQL16.2, including concurrent one-use intake and atomic audit failures | **22 passed**, 6 warnings, 31.99s; exit0 | [Transcript](host-collection-2026-10-24/postgres.txt), [JUnit](host-collection-2026-10-24/postgres.xml) |
| Full frontend Vitest suite | **598 passed**, 57 files, 243.01s; exit0 | [Console transcript](host-collection-2026-10-24/frontend.txt) |
| TypeScript checking and production frontend build | Passed; build1.39s; exit0 | [Console transcript](host-collection-2026-10-24/frontend.txt) |
| Changed Python Ruff, dependency consistency, whitespace | Passed | [Quality](host-collection-2026-10-24/quality.txt) |
| Owned host-witness resources | No remaining witness directories or processes observed after cleanup | [Cleanup](host-collection-2026-10-24/cleanup.json) |

Counts overlap existing tests and are not summed as distinct bank validations.
The 15 new host-panel browser-shaped DOM cases are included in the598 frontend
checks; no native built-browser/site acceptance run was performed here. The
selected Python suite includes one skipped native Windows candidate; portable
path-string tests do not substitute for it. Warnings include existing Pydantic,
field-shadowing, Starlette and Alembic deprecations, retained in the transcripts.

The Windows native fixture is skipped on Linux. Portable Windows path checks and
unexecuted native code do not qualify Windows Server. Source/contract/native1.6
validation does not qualify rootless production execution, real TLS negotiation,
HSM/KMS behavior, complete scope, runtime crypto use, bank controls outside the
specified test harness, external-tool interoperability or full-bank readiness.

### Development failures resolved, not hidden as passes

An exploratory broad regression started before the final test fixture corrections
ended with one limiter-witness failure: the shared test application intentionally
omits production/development rate middleware. The final HTTP test explicitly
mounts the actual product limiter around the real authenticated application. The
subsequent final selection and PostgreSQL witness include this corrected case.
That earlier run's 2,878 passes/one failure are **not** included as a final gate or
represented as a clean full-regression result. Its pgserver atexit logging warning
also does not establish a product failure or successful cleanup by itself.

Review also identified that a valid finding hash cannot bless mutable enrichment
columns. Host CBOM construction now ignores those sidecars, critical projections
are checked against the source, and committed evidence IDs/import actor/scan times
are bound into the intake closure. Explicit tamper tests cover those boundaries.

## Boundaries and remaining work

Native Windows ACL/reparse/registry-link/privilege/sharing/race/filesystem behavior
is unexecuted and requires independent review. Do not deploy the Windows adapter
on the strength of this Linux run. The source has conservative native hooks,
not a Windows support certification. Inputs above current caps remain unknown;
there is no “scan everything” fallback.

The importer does not create fleet crypto rollups or join all six BOM graphs;
existing six-BOM code/console is reused without manufacturing host→HSM or
software→algorithm relationships. Actual joined Linux/Windows/container/HSM/TLS/
cloud-KMS tests, supported inventory profiles, isolated admission→worker→scanner,
source attestation, deployed TLS/secrets/monitoring, operations ownership and
independent bank approval remain open in the acceptance ledger.

No workflow was changed or run by this publication. Publication uses `[skip ci]`.
No performance, uptime, SLA, FIPS/PQC compatibility or production security claim
is derived from the functional tests. Existing warnings remain visible in the
retained logs; there is no zero-warning claim.
