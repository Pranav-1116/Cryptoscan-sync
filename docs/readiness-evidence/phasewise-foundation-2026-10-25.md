# Phase-wise build: foundation coverage increment — 2026-10-25

**Delivered: a concrete Phase 1 hardening increment and an ordered ten-phase build contract. Not claimed: completion of all ten phases, production admission or bank-native execution.** Starting point: `d929d4cb76bf3476efd137ca1b63e9a2706c3b40` on the existing session branch.

[Guide 69](../bank-environment/69-phasewise-universal-collection-build.md) maps the requested phases to actual implementation and advancement gates. The foundation/scoped Linux implementation is reused, Windows remains candidate-only, and unsupported universal adapters are not enabled. No new service, independent BOM database or speculative service-directory rewrite is introduced.

## Implemented

1. **Deterministic per-surface projection:** new strict `InputCoverage`, `SurfaceCoverage` and `CoverageReport` models in `shared_models.collection_coverage`. Exact authorized-manifest denominators, original errors/reasons, local OBSERVED/DECLARED counts, evidence references, claimed source window and all six BOM reference counts.
2. **Explicit unknowns:** NOT_REQUESTED has a null percentage and no denominator. FAILED/PARTIAL are not absence. PARSED_NO_FACTS is not absence. Even 100% parsing keeps complete-surface/whole-host coverage and asset-absence flags false. TechBOM/reference counts cannot manufacture extra facts.
3. **Read-only API:** `GET /api/v1/collection/jobs/{id}/coverage/surfaces`, with typed OpenAPI response. It reopens the existing committed evidence, validates source/target/input/hash/domain bindings and refuses corruption. The existing envelope commitment and flat coverage endpoint are unchanged.
4. **One collection, six views:** counts reference the same evidence used by SBOM, CBOM, NBOM, HBOM, VBOM and TechBOM projections. A positive fixture retains exactly one Scan and unchanged EvidenceRecord counts across repeated coverage reads. No collector is called, scan created or remote host contacted by the report.
5. **Catalog correction:** Linux NBOM/HBOM capability descriptions now identify the already implemented explicit TCP listener and kernel/DMI/TPM metadata scopes. They explicitly do not claim negotiated TLS, hardware attestation or cryptographic invocation. Future method admission is unchanged.
6. **Existing product UI:** a read-only “Phase 1 · Evidence-backed collection coverage” section in the existing CBOM approved-host evidence area. No sample data or automatic request; explicit job ID, original collection time, scoped ratios/gaps, provenance and all-six projection counts. Job/tenant/auth/storage/resume/history changes clear/fence old evidence. Non-cooperative reads time out at 20 seconds without retry or late success.
7. **Owned PostgreSQL replay:** optional `--include-surface-coverage` in the existing disposable validation harness. No customer URL, deployment configuration or migration is added.
8. **Phase documentation:** [ordered build/gates](../bank-environment/69-phasewise-universal-collection-build.md), [API contract](../api-reference/collection-surface-coverage.md) and updated foundation/index links. The plan differentiates existing legacy utilities, development adapters, native candidates and genuinely qualified deployment capabilities.

## Logical architecture retained

```text
existing selected-estate System
  → target / explicit manifest / current authorization (AssuranceRevision)
  → durable collection job and ordinary-user offline runtime
  → one original snapshot intake (Scan / EvidenceRecord / retained snapshot)
  → typed central CollectionResult and metadata-slot identity
  → shared six-domain evidence reference projections
  → read-only surface coverage / existing UI
```

Collectors do not write BOMs or manufacture edges. This increment does not add global physical-asset identity, automatic HSM/application linkage, vendor inference, drift-completeness claims or forced six-BOM coverage. Installed software, mapped libraries, crypto capability, actual invocation and negotiated network traffic remain distinct. Old evidence may be inspected after withdrawal; it never grants new work.

## Validation results

Separate runs overlap and **must not be summed**.

| Gate | Result |
|---|---|
| Shared models, inventory, collection foundation/surface coverage, worker and qualification regression | **1,066 passed, 3 genuine Windows-native skips**, zero failures/errors |
| Final new surface model/API contracts | **37 passed**: 14 schema/semantic cases + 23 API/projection cases |
| Broader owned PostgreSQL host/foundation/surface regression | **57 passed**, zero failures/errors |
| Final PostgreSQL host/surface replay | **25 passed**, zero failures/errors |
| Focused new coverage / host-evidence / qualification UI | **45 passed**, including 10 new coverage UI cases |
| Final full frontend (`--maxWorkers=2`) | **643 passed**, zero failures/errors |
| TypeScript / production frontend build | **PASS / PASS** |
| Ruff / installed Python dependency consistency | **PASS / PASS** |
| Three new model schemas | Draft 2020-12 schema checks pass; extra properties forbidden |
| Real bank host execution, native Windows qualification, bank acceptance | **Not performed / not supplied** |

The broad 1,066/57 runs preceded final schema-window/count reconciliation and typed-response hardening. Final 37/25 runs exercise the finalized coverage contracts/API; the full frontend/typecheck/build also use the finalized UI. No earlier published results are relabeled as new tests, and no claim is made that every API unit test or remote CI ran.

### Negatives and boundaries exercised

- Every current host input kind maps exactly once. Unapproved or duplicate errors, wrong approved denominator, wrong target system/environment, wrong source kind/path/host, modified fact hash, domain promotion, duplicate observations/ordinals and facts attributed to failed inputs refuse.
- All five non-parsed receipt statuses remain explicit FAILED inputs, not absent or unrequested scope. Unrequested hardware is null-denominator, not 0%. Parsed-with-no-facts cannot assert absence.
- Wrong BOM/surface keys, extra fields, invented/negative reference counts, false completeness/production/absence assertions, naive/reversed windows and fabricated denominators refuse model validation.
- A non-completed job has no coverage report. Tampered retained EvidenceRecord content returns 409 rather than reprojecting success. Withdrawal retains identical historical coverage without collection.
- Exact estate boundaries include tenant B and an unselected platform administrator. Authorized selected administration can inspect; readonly users can read without creating work. Repeated reads preserve Scan/EvidenceRecord counts and a valid audit chain.
- Browser cases cover no auto-load/no scan, selected tenant/auth headers, retained DENIED/provenance, malformed completeness flags, ID changes, delayed replies after tenant/auth/storage/resume/history changes, a 20-second non-cooperative timeout and no late proof/retry.

All test identities, certificate/binary/config inputs and positive records are **synthetic engineering fixtures**, not genuine bank evidence or external operator acceptance. The three skipped native Windows cases explicitly require Windows; Linux is not used to manufacture a pass. Owned PostgreSQL harness runs report cleanup; no customer deployment is modified. No private key or bank credential is delivered.

Logs/JUnit, schema checks and metadata are retained in [the evidence folder](phasewise-foundation-2026-10-25/validation.json). [Source/artifact SHA-256 commitments](phasewise-foundation-2026-10-25/manifest.json) are integrity/provenance records, not independent authentication, running-code attestation or bank signatures. Installed dependencies, frontend build outputs and temporary databases are not committed.

## Replay

In the approved local validation environment, repository root:

```bash
python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  shared/shared_models/tests services/inventory/tests \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_worker.py \
  services/api/tests/unit/test_qualification_workflow.py -q

python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-foundation --include-surface-coverage \
  --junitxml=/home/user/phasewise-postgres-replay.xml

cd frontend
npm run typecheck
npm test -- --maxWorkers=2
npm run build
```

The additional 14 new shared-model contract cases were added after the broad recorded regression; a fresh full selected replay includes those too. For the final focused model/API run, select `shared/shared_models/tests/test_surface_coverage_contract.py` and `services/api/tests/unit/test_collection_surface_coverage.py` through the same bootstrap runner.

## Next phase and unresolved operational gates

Proceed in order with the existing **Phase 2 Linux** work under approved resource/truth scope; do not skip to enabling Windows, containers, network/cloud/HSM/vendor adapters because an architecture diagram lists them. Guide 69 gives their bounded input, provenance, negative-test and qualification gates. Source hashes and imported operator assertions do not establish genuine execution, hardware origin or organizational independence.

No actual bank host/operator/channel approval or independent public decision has been supplied here. Those operational gates remain pending through the existing handoff and signed-review workflow. Production admission, all-six BOM provenance rules and UNKNOWN handling are unchanged. No full-bank coverage, uptime/SLA, performance-target improvement or PQC/production readiness is claimed. Publication retains `[skip ci]`; workflows are not edited. Do not send credentials, private keys or TPM authorization secrets.
