# Original45 bank questions — executed implementation follow-up

**2026-10-24 UTC. Baseline:731fbbcb2b1d200fd7cb13ecd61176688ea218ba.**
This pass responds to the bank's correction that the original45 questions still
contain gaps. The previous57-row register was not a completed product checklist.
This pass implements bounded changes in existing product paths, not another
claim that every capability now exists.

## What actually changed

1. **Standard CBOM output (O1).** Existing generator accepts explicit
   `spec_version="1.6"`; existing API renderers accept `fmt=cyclonedx16`; the
   scan export accepts `spec_version=1.6`. The pinned **full official CycloneDX
   1.6 JSON schema**, SPDX and JSF dependencies are validated offline through a
   deny-by-default local resource registry. Schema hashes are checked; missing
   or modified schemas fail closed. Format checks, duplicate references and
   dependency/composition reference integrity are exercised by negative tests.
   Invalid schema metadata is not subsequently parsed into a500 response.
2. **Business context (O4).** Allowlisted application, owner, classification,
   retention and criticality metadata are exported from records and persisted
   systems. The native profile merges one shared asset reference while retaining
   multiple declared business contexts; conflicting crypto identities fail.
   Import exposes multiple contexts rather than silently resolving one owner.
3. **Dependency meaning (O5).** Native record conversion does not promote the
   legacy default inventory fanout to observed dependencies. Retained source
   relationships are labelled as not runtime or replacement proof. Selected
   system native exports materialize authorized neighboring system components,
   preserving incoming/outgoing direction instead of exporting dangling IDs.
4. **Parameter correctness (M5/R1).** The existing registry had labelled
   ML-KEM/ML-DSA/HQC public-key byte lengths as `key_bits`. They now explicitly
   use `public_key_bytes`. All12 full SHA2/SHAKE FIPS205 SLH-DSA parameter names
   are recognized with their public-key lengths. Ambiguous legacy
   `SLH-DSA-128S` no longer invents an exact key size. FN-DSA/McEliece no longer
   receive automatic `ALLOWED` policy status from draft/selection descriptions;
   this is conservative review gating, not a current-publication assertion.
   Native parameter IDs such as `768`, `65`, `SHA2-128s` are not replaced by
   public-key byte counts. Caller-supplied PQC `key_size` units remain explicitly
   unestablished rather than guessed from a number.
5. **Legacy field metrics (M4).** Precision/recall/F1 with no denominator are
   nullable, not100%. Legacy workbook FPR stays null without a true-negative
   denominator. FNR is explicitly scoped to reviewed file/algorithm units.
   Malformed workbook shapes/verdicts return422. Existing triage CLI uses the
   same shared score for display and JSON, handles null, and does not recompute
   a contradictory “perfect” answer. These remain unfrozen legacy reviews,
   not the approved/frozen customer-sample workflow or a global accuracy claim.
6. **Existing screen behavior (I4/M4).** The CBOM button previously downloaded
   the catalog endpoint while calling it a CycloneDX export. It now downloads
   the authenticated native1.6 portfolio CBOM. The existing Accuracy page no
   longer substitutes zero for missing metrics, averages undefined values into
   measured results, claims CI release qualification, or calls algorithm names
   deployed-safe crypto. Its separate corpus evaluator is not globally changed
   or requalified by these legacy-field metric fixes.
7. **Export safety (D1/D2).** Native profile projects allowlisted metadata,
   not arbitrary finding payloads/snippets/key values. Scan CBOM exports through
   both existing route families obey quarantine; tenant session tests preserve
   foreign/missing404 and quarantined409 behavior. This is not a claim that all
   possible egress or historical deployment/backup data is secret-free.
8. **An actual sample (G2).** An eight-input synthetic banking-like CBOM and
   actual planning-engine report are committed and reproducible byte-for-byte.
   Their labels explicitly refuse comparable-customer, scanner-execution,
   accuracy, completeness, performance or bank-approval claims. The existing
   model's human summary now says “migration-review candidates” rather than
   labelling classically broken crypto as all Shor-vulnerable. Mosca prose,
   not only machine fields, describes the threat year as an assumption.

[Original45 engineering/acceptance matrix](../operations/bank-original45-engineering-gaps.md).
[Native CBOM and report example](../examples/bank-pqc-discovery/README.md).

## Executed negative baselines and regressions

These are retained **incremental implementation states**, not a claim that
all negative runs were made against the unchanged baseline commit. Test counts
are conditions, not a count of distinct defects.

| Retained phase | Actual result before the corresponding fix |
|---|---|
| Initial native-output/legacy-denominator contracts |34 failed,1 passed |
| API adapters before native format wiring (corrected response-shape test) |8 failed,1 passed |
| Shared asset context |1 failed,26 passed |
| Persisted owner/retention/system context |2 failed,11 passed |
| Null-metric CLI compatibility |3 failed,10 passed |
| Accuracy page missing-data and claim tests |3 failed |
| PQC units/full SLH parameters/native parameter IDs |26 failed,29 passed |
| Planning-summary/scenario prose |2 failed,15 passed |
| Broad run with old summary-wording assertion |1 failed,901 passed; assertion updated to the intentionally corrected wording, numeric cohort assertion retained |
| Schema-invalid API metadata |3 failed,13 passed; fixed before the final full selection |

### Final results

| Check | Executed outcome |
|---|---|
| Selected Python regression, including all CBOM/quantum tests and the current six-BOM matrix | **905 passed,4 warnings; zero failures/errors/skips** |
| Full frontend suite | **552 passed /53 files; zero failures/errors/skips** |
| Frontend typecheck and production build | PASS |
| Changed Python `ruff --select F` | PASS |
| Root constrained environment `pip check` | PASS; no broken requirements |
| Retained sample regeneration and byte comparison | PASS for CBOM and planning report |
| Register integrity | PASS; source references hashed |
| Strict bank acceptance | Expected exit1, **BLOCKED**, not malformed-data exit2 |

Python warnings are the existing auth Pydantic Config deprecation, network/cloud
field shadowing and Starlette TestClient/httpx deprecation. Frontend has **20
existing React act warnings** in CriticalScope/Tenancy. New focused Accuracy/CBOM
UI tests do not add act or jsdom navigation warnings. Warnings were not suppressed
and test isolation was not weakened to obtain a green result.

The selected Python set is reproducible with
[run-python-tests.sh](bank-original45-2026-10-24/run-python-tests.sh). It includes
native CBOM API tests with actual tenant sessions, legacy CBOM signing/snapshot/
ingest tests, field-accuracy API tests, registry/classification consumers, current
six-BOM boundaries, existing banking/quantum/agility/worker regressions and
selected universal-crypto registry/accuracy/analysis/protocol regressions.
It is **not all repository tests** or authenticated CI qualification.

Full frontend ran after its final code/test edits. Later changes were Python,
synthetic outputs, register and documentation only. The final905-case selection
ran after the last Python guard change. No live bank/cloud/HSM/network scan,
production database modification or native PQC key operation was executed.

## Compatibility and profile limits

- Legacy generator/API default remains1.5 for compatibility. It is a CryptoScan
  extension path, **not retroactively validated standard cryptographic CBOM**.
  Native1.6 JSON is explicit. Native1.6 XML is refused rather than silently
  serialized with a1.5 namespace.
- The native profile intentionally does **not** copy arbitrary input properties,
  vulnerability payloads, certificate bodies, related-material values or raw
  detector data. This is not a lossless arbitrary CycloneDX document converter.
  Source occurrences and business labels can themselves be sensitive and need
  bank authorization/redaction. No current deployment residency commitment is
  created by an export serializer.
- The profile's additional integrity checks cover local components, dependency
  links and composition members, not every kind of external BOM-Link or domain
  assertion. Structural validity is not implementation, FIPS module, signature
  trust, interoperability or independent schema approval.
- Shared assets have multiple source-declared contexts; callers must not flatten
  those into one resolved business owner. Unknown/conflicting references fail
  closed instead of becoming fabricated nodes or proven replacement edges.
- Public-key byte `parameter_kind`, restricted FN-DSA/McEliece policy status and
  null legacy field metrics are semantic changes. The selected consumer tests
  pass, but **all external/legacy consumers and historical recomputation are
  not qualified**. Existing catalog tables still require current source review.
- Five locked validator dependency pins were added (jsonschema and its new
  transitive dependencies); unrelated lock entries were not refreshed.
  Upstream schema provenance/license/hash records are retained. This does not
  attest to the supply-chain security of a built image or required CI run.

## Acceptance still open

The original45 matrix explicitly retains real engineering gaps: comprehensive
protocol/platform/version discovery, runtime observation, vendor/SaaS opacity,
fragile-device safety, product-specific integrations, independently denominated
completeness, actual PQC packet/certificate/latency/HSM benchmarks and PKI/hybrid
interoperability. This pass did not build or qualify all of those.

Real ISO/SOC/pentest evidence, customer references, partner agreements, pricing,
financial facts, agreed SLA/residency/exit terms and actual staffed support are
external facts/commitments; none was invented. Current legal/NIST applicability,
independent release approval, browser/AT acceptance and production/recovery
qualification were not established here. Earlier retained evidence stays
historical and was not rewritten to make it look current.

[Machine-readable results and source/record hashes](bank-original45-results-2026-10-24.json).
