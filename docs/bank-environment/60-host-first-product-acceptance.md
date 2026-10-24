# Ten-point product delivery and acceptance ledger

**2026-10-24 · host-first collection + reviewed association increments, not ten-point completion**

The [implemented host workflow](59-approved-offline-host-collection.md) is the
first new slice. The next [host-to-six-BOM association slice](61-host-to-six-bom-associations.md)
adds explicit two-human metadata associations, never inferred operational links. Existing six-BOM/policy/evidence/operational capabilities remain
subject to their own qualification boundaries. This ledger must not relabel code
presence as a measured bank deployment.

## Product contract

> CryptoScan discovers cryptographic assets across approved and supported
> collection surfaces within the bank's defined scope.

> Every finding retains provenance and evidence status, with unsupported or
> unobserved facts represented explicitly as unknown rather than inferred as secure.

Those statements constrain product behavior; they do not assert bank-wide
coverage, approved Windows deployment, HSM/PQC use or production isolation success.

## Ten requested outcomes

| # | Outcome | Delivered in this slice | Still required before acceptance |
|---|---|---|---|
| 1 | Controlled Linux/Windows non-Git host collection | Manifest-only offline collector; Linux synthetic execution; native Windows file/registry code; least-privilege refusal; bounded receipts; no shell/upload | Real Windows execution/security review, supported OS/filesystem/package profiles, signed release/host identity, independent scope approval and bank pilot |
| 2 | Evidence-grade CBOM | Source statuses distinct; imported snapshot bound to exact admin approval; per-input and cert/config evidence IDs/hashes; system/environment/time/location/algorithm/size retained; source revision/library/version/runtime/policy/PQC unknown or unevaluated where unproven | Qualified asset/fact projection and estate-rollup reconciliation; effective-use observations, policy/PQC applicability and independently verified completeness |
| 3 | Connected SBOM/CBOM/NBOM/HBOM/VBOM/TechBOM | Versioned host-to-existing SBOM/CBOM/NBOM/HBOM/VBOM/TechBOM metadata graph; per-edge provenance, exact package/original SBOM checks, independent admin/CISO review, stale/retraction exclusion; **no inferred runtime/HSM links** | Native joined bank-like operational witness, qualified endpoint/device/KMS identity and actual use; customer-reviewed metadata is not runtime proof |
| 4 | Isolated production execution | No privileged shortcut; all new host APIs deliberately refused under current controlled profile | Versioned host admission→queue→worker→isolated scanner→read-only stage→evidence adapter and positive/negative rootless isolation witness before allowlisting |
| 5 | Demonstrable bank controls | Real human sessions; admin/CISO approval, analyst intake, auditor/viewer inspection not modification; exact tenant reads/foreign-ID refusal; chained approve→intake→export audit; one-use transaction and rollback; HTTP rate/body caps | Deployed TLS/secrets/monitoring and DB grants/retention controls, shared limiter outage/load tests, independent security review and operations acceptance |
| 6 | Strict UNKNOWN semantics | Failed collection stays unknown; library presence not algorithm use; config not negotiation; unsupported public-key implementation not guessed; PQC names in config not deployment | Run handshake-failure, vendor-only declaration, HSM mechanism and KMS usage truth through the joined estate; preserve UNKNOWN in every downstream consumer |
| 7 | Exact CycloneDX validation | Pinned full official1.6 offline validation, versioned strict host schemas, golden export/property tests, no inferred dependency fanout | Independent importing-tool interoperability, agreed property vocabulary/version policy, review of complete certificate/profile semantics; no broad compliance claim |
| 8 | Bank-like controlled test estate | Synthetic Linux cert/config/library/package fixtures plus actual authenticated SQLite/PostgreSQL evidence path | Actual Windows/container/HSM/TLS/KMS fixtures, permissions/failed probes, vendor-only assertions and independent expected-truth review; distinguish simulation from native execution |
| 9 | Threat-intelligence console | Existing CBOM page approves/imports/inspects/exports host evidence and reviewed six-BOM metadata graph; source/target selection, provenance, stale/retraction state, private-scope fences, no AI chat/sample fallback | Estate-wide host assets/risk/PQC/drift/policy/graph/timeline integration with evidence filters and source uncertainty intact; not a new disconnected dashboard |
| 10 | Defensible messaging | Scoped contract in this guide and repository entry point; host/Windows/production limits shown in console | Review historical marketing/docs and all downstream labels against supported surfaces, qualifications and actual bank acceptance |

## Six-BOM relationship acceptance — no fictional joins

All six remain required, even when a particular scope has no evidence:

| BOM | Legitimate host evidence/link | What cannot create that link |
|---|---|---|
| SBOM | Approved package/binary identity plus revision/artifact evidence; deployment binding independently declared/observed | Matching `openssl` text does not bind a release, running process or crypto call |
| CBOM | Public-certificate metadata/config declarations with committed snapshot and evidence IDs | A loaded/installed library cannot establish AES/ML-KEM use |
| NBOM | Endpoint identity and actual bounded TLS/network observation with its receipt | Configuring TLS1.3 does not prove successful TLS1.3 negotiation; failed handshake is UNKNOWN |
| HBOM | Authenticated hardware/device identity and mechanism/operation evidence | Being on the same host/subnet cannot prove system→HSM use |
| VBOM | Supplier declaration with version/date/source and explicit DECLARED/IMPORTED status | Vendor ML-KEM support is not bank HSM ML-KEM use or certification |
| TechBOM | Scoped system/environment/deployment identity with author/provenance | Admin approval of a logical host label is not attestation of that physical host |

Each operational-use edge still needs tenant/scope, endpoint identities, a specific predicate,
evidence/reference IDs, timestamp, evidence basis, source revision/commitment and
unknown limitations. Approval provenance supports an **operator-declared scope
assignment only**. Do not turn the new report into an HSM dependency edge or
silently inherit an old system's clean grade.

## Required expected-truth estate

The table distinguishes cases actually executed by this slice from tests needed
for the requested estate. Existing unrelated tests are not counted as this
increment's native deployment witness.

| Case | Expected truth | Execution/qualification in this slice |
|---|---|---|
| RSA2048 / RSA3072 / ECDSA-P256 public cert | Parsed public-key metadata (EC family/curve, not inferred subject-key ECDSA use); IMPORTED on intake; runtime UNKNOWN | Synthetic Linux files executed |
| AES128-GCM / AES256-GCM named suites; TLS1.2 / TLS1.3 config | DECLARED tokens; not observed algorithms/session | Synthetic config executed |
| SHA256 certificate signature | Certificate metadata, not application hashing use | Synthetic cert parsing executed |
| SHA1 / AES128 non-GCM / SHA256 application calls | Facts only from a supported actual observation source, purpose/context retained | Not a native host-use witness here |
| Unsupported public-key implementation | Algorithm/key size UNKNOWN, no guessing | Unit shim executed; not a real PQC certificate qualification |
| Unknown-size/unknown algorithm metadata | Null/UNKNOWN, no assumed secure size | Strict model/unsupported-key tests; broader native fixtures still needed |
| Failed/denied input, unsupported file, file race | Explicit receipt; no facts/no security grade | Linux missing/permission refusal, symlink/hardlink/FIFO, parser/byte limits and mutation tests executed |
| Installed OpenSSL / ELF or PE header | Presence/database record only, algorithm/runtime UNKNOWN | Synthetic Linux package/header fixtures executed; header is not executable validation |
| ML-KEM / ML-DSA names in config | Unparsed/UNKNOWN, no PQC deployment | Synthetic config negative test executed |
| Native Windows file/registry/ACL/reparse/privileges | Same strict receipt/source semantics, real OS refusal evidence | Native case skipped on Linux; Windows release qualification OPEN |
| Container image/running workload | Scoped artifact vs runtime clearly distinguished | New host container estate NOT executed |
| Bank HSM classical and ML-KEM/ML-DSA mechanisms/operations | Authenticated mechanism/operation evidence; support ≠ use | NOT executed; vendor declarations cannot substitute |
| TLS failed endpoint / TLS1.2 / TLS1.3 negotiation | Failure UNKNOWN; observed protocol/cert only on success | New live endpoint estate NOT executed |
| Cloud KMS key metadata/usage; denied API | Provider evidence with scope/time/permission receipts; metadata ≠ usage | New cloud KMS estate NOT executed |
| Vendor-only PQC support | DECLARED/IMPORTED supplier claim, bank deployment UNKNOWN | Must be joined to current supplier quarantine/approval workflow; no new native witness here |

**Next engineering gate:** reviewed host-to-estate identity/edge projection and
Windows qualification, then an approved isolated host execution profile. The
controlled production allowlist stays closed until its own admission, worker,
sandbox, cleanup, evidence, export and negative-control proof exists. No caching,
new fleet service or performance claim is justified by this functional slice.


## Second increment: reviewed host-to-estate metadata associations

[Guide 61](61-host-to-six-bom-associations.md) implements the previously missing
host identity/reference adapter. It connects all six domains in a synthetic joined
witness and exposes their provenance in the existing CBOM console. This advances
#2/#3/#5/#6/#9, but does **not** close the native-operational acceptance gaps.

- SBOM requires exact versioned package, retained original bytes and same-system,
  same-environment active deployment; no matching-name release binding.
- NBOM uses a supported successful existing SSH host-key receipt with a checked
  job/hash/timestamp, not a failed handshake or an invented TLS-phase adapter.
- HBOM/VBOM are explicitly customer-reviewed metadata assertions. Firmware and
  vendor capability changes invalidate the committed association; ML-KEM use stays
  UNKNOWN. Metadata freshness is not refreshed device observation.
- Different admin/CISO review, scoped readers, audit/expected-revision controls,
  source closure, retained retractions and complete bounded graph/export are
  executable controls. Native Windows and production admission remain blocked.

Current-source results and replay boundaries are recorded in the
[second-increment evidence report](../readiness-evidence/host-estate-graph-2026-10-24.md).
The earlier host report remains historical evidence for its published source;
this update does not relabel those earlier logs as a graph qualification.


## Phase-wise universal foundation and Linux increment

[Phase 1](62-universal-collection-foundation.md) now provides the stable target
registry, authorization, offline handoff/job states, shared typed evidence envelope,
metadata-slot identity and reference-based six-domain materialization. It reuses
existing tables and evidence intake. [Phase 2](63-linux-collection-phase-two.md)
extends the Linux adapter with approved OS-release declarations and target-spec
CLI. **Phase 2 is not complete:** actual services/listeners, hardware/TPM/HSM and
runtime attribution remain unsupported here. Production and other collector phases
remain unqualified. [Current execution evidence](../readiness-evidence/collection-foundation-2026-10-24.md).
