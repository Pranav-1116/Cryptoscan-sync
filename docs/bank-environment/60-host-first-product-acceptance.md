# Ten-point product delivery and acceptance ledger

**2026-10-24 · host-first implementation, not a ten-point completion declaration**

The [implemented host workflow](59-approved-offline-host-collection.md) is the
first new slice. Existing six-BOM/policy/evidence/operational capabilities remain
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
| 3 | Connected SBOM/CBOM/NBOM/HBOM/VBOM/TechBOM | Reuses existing six-BOM console and native CBOM generator; **no invented host/HSM/dependency links** | Connect host evidence to existing identity/edge models with per-edge evidence, justified predicates and ownership; all six paths need a joined bank-like witness, not co-existence |
| 4 | Isolated production execution | No privileged shortcut; all new host APIs deliberately refused under current controlled profile | Versioned host admission→queue→worker→isolated scanner→read-only stage→evidence adapter and positive/negative rootless isolation witness before allowlisting |
| 5 | Demonstrable bank controls | Real human sessions; admin/CISO approval, analyst intake, auditor/viewer inspection not modification; exact tenant reads/foreign-ID refusal; chained approve→intake→export audit; one-use transaction and rollback; HTTP rate/body caps | Deployed TLS/secrets/monitoring and DB grants/retention controls, shared limiter outage/load tests, independent security review and operations acceptance |
| 6 | Strict UNKNOWN semantics | Failed collection stays unknown; library presence not algorithm use; config not negotiation; unsupported public-key implementation not guessed; PQC names in config not deployment | Run handshake-failure, vendor-only declaration, HSM mechanism and KMS usage truth through the joined estate; preserve UNKNOWN in every downstream consumer |
| 7 | Exact CycloneDX validation | Pinned full official1.6 offline validation, versioned strict host schemas, golden export/property tests, no inferred dependency fanout | Independent importing-tool interoperability, agreed property vocabulary/version policy, review of complete certificate/profile semantics; no broad compliance claim |
| 8 | Bank-like controlled test estate | Synthetic Linux cert/config/library/package fixtures plus actual authenticated SQLite/PostgreSQL evidence path | Actual Windows/container/HSM/TLS/KMS fixtures, permissions/failed probes, vendor-only assertions and independent expected-truth review; distinguish simulation from native execution |
| 9 | Threat-intelligence console | Existing CBOM page now approves/imports/inspects/exports host evidence; bounded private state, explicit unknowns, no AI chat or sample-data fallback | Estate-wide host assets/risk/PQC/drift/policy/graph/timeline integration with evidence filters and source uncertainty intact; not a new disconnected dashboard |
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

Each eventual edge needs tenant/scope, endpoint identities, a specific predicate,
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
