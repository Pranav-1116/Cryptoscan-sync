# 06 — Where the bank sees, exports and verifies the outputs

[Guide index](README.md) · Previous: [Worked pilot](05-practical-bank-walkthrough.md) ·
Next: [Operations](07-operations-and-acceptance.md)

## 1. Operator journey in the console

After installation and bank-approved authentication, a typical user follows:

1. **Onboarding / systems:** register the approved environment, scope and
   system ownership. This establishes declared context, not measured coverage.
2. **Operations / scans:** submit an authorized target and inspect the real job
   or network-run progress/result. A spinning widget is not durable completion.
3. **Findings and evidence:** inspect observation provenance, policy rationale,
   confidence, code origin, exclusions and failures.
4. **BOM views:** select the question—wire posture, crypto inventory, hardware,
   supplier dependency or the shared technology view.
5. **Capture / compare / export:** retain stable supported snapshots, exact run
   references and signed/hash metadata for an approved review period.
6. **Remediation / re-scan:** the bank changes its system, then obtains fresh
   evidence. Neither a ticket nor an alert acknowledgement proves a fix.

The SPA routes below are traced from `frontend/src/App.tsx`, not guessed from
product names. Menu labels and permission-visible actions can change with role.

| Console route | What it is useful for | Interpretation caution |
|---|---|---|
| `/onboarding`, `/cmdb`, `/assets` | Scope/context and system estate | Registration is not proof of discovery |
| `/scanners`, `/live-scanners` | Scan operations and job investigation | Different collectors have different result/ID paths |
| `/findings`, `/evidence`, `/crypto-assets` | Observations, evidence and deduplicated crypto inventory | A finding is not necessarily a distinct deployed key |
| `/cbom` | Crypto inventory/query/coverage and supported scan pins | Scope, origins and truncation matter |
| `/nbom`, `/network`, `/certificates` | Observed network components, transport and certificate details | No successful probe means unknown, not healthy |
| `/hbom`, `/hardware` | Independent persisted hardware estate, live hardware and pins/diffs | Do not confuse persisted estate with ephemeral engine state |
| `/live-asset-intelligence` | TechBOM layers, dependencies, snapshots, exports and vendor linkage | `/techbom` redirects here; no general `nbom` export layer |
| `/vendor`, `/vendor-due-diligence` | Vendor inventory and due-diligence work | No registered standalone `/vbom` SPA route |
| `/dependency-graph`, `/drift`, `/remediation` | Recorded dependency analysis, change review and owner workflow | Missing relationships and coverage limit conclusions |
| `/notifications` | Configured destinations and durable receipt inspection | HTTP acknowledgement is not downstream ingestion |

Confirm the installed release's route/menu definitions before training operators.
A UI role guard alone is not an authorization control; server-side scope and
permission enforcement must also be included in the bank's negative tests.

## 2. Read API reference for the five BOMs

All paths below include `/api/v1`. Use authenticated HTTPS through the bank's
internal ingress, not an exposed development server or public database port.

| Method and path | Meaning |
|---|---|
| `GET /api/v1/cbom/nbom` | NBOM derived from stored network-run probes; response contains `nbom`, `summary`, `source` |
| `POST /api/v1/cbom/nbom` | Build a document from supplied endpoint/tunnel/device inputs; not a network scan |
| `POST /api/v1/cbom/nbom/cascade?ref=...` | Analyze supplied NBOM inputs for the selected component's recorded dependents |
| `GET /api/v1/cbom/scan/{scan_id}` | CBOM for one scan; JSON default, XML selectable |
| `GET /api/v1/cbom/system/{system_id}` | CBOM associated with a registered system |
| `GET /api/v1/cbom/portfolio` | Bounded estate cryptographic aggregate; inspect truncation metadata |
| `GET /api/v1/technology-bom` | Live shared technology state; not a stored immutable capture |
| `GET /api/v1/technology-bom/vendor` | Vendor/system linkage projection, not the rich independent VBOM |
| `GET /api/v1/hbom?fmt=native` | Independent persisted-estate hardware document |
| `GET /api/v1/hbom?fmt=cyclonedx` | CycloneDX-style representation of that same estate document |
| `GET /api/v1/hardware/hbom` | Live controller's hardware document; different durability/scope |
| `GET /api/v1/vendor-bom?fmt=native` | Estate vendor document |
| `GET /api/v1/vendor-bom?fmt=cyclonedx` | Vendor crypto export in the implemented CycloneDX-style shape |
| `GET /api/v1/vendors/{vendor_id}/vbom` | One vendor's slice |

Do not silently treat different scope/format contracts as interchangeable. A
supplier's declared algorithm and a listener's observed suite can corroborate
each other only after product/deployment identity and provenance are established.

## 3. Snapshot, comparison and evidence APIs

| Method and path | Meaning |
|---|---|
| `GET /api/v1/jobs/{job_id}` | Durable job status, progress and committed scan linkage when present |
| `GET /api/v1/jobs/{job_id}/logs` | Job logs/progress; apply access and redaction policy |
| `GET /api/v1/scans/{scan_id}/coverage` | Source-scan coverage statements and limitations |
| `GET /api/v1/scans/{scan_id}/verify` | Stored scan/evidence verification result |
| `GET /api/v1/network/runs/{run_id}` | Persisted network run; not a source scan/job ID |
| `POST /api/v1/cbom/scan/{scan_id}/snapshot` | Pin a scan CBOM; auditor-capable identity required |
| `GET /api/v1/cbom/snapshots/{snapshot_id}` | Retrieve the stored CBOM pin and verification information |
| `POST /api/v1/hbom/snapshot` | Pin independent estate HBOM; auditor-capable identity required |
| `GET /api/v1/hbom/snapshots/{snapshot_id}` | Retrieve stored payload and `OK`/`MISMATCH` integrity result |
| `GET /api/v1/hbom/snapshots/{snapshot_id}/diff?against={baseline_id}` | Compare two hardware pins; `key_by=asset_id` excludes named observation churn, `bom_ref` is more exact |
| `POST /api/v1/technology-bom/snapshot` | Capture current shared-state version, or reuse unchanged latest fingerprint |
| `GET /api/v1/technology-bom/history` | Recorded shared-state history |
| `GET /api/v1/technology-bom/compare?from_version=1&to_version=2` | Compare actual recorded versions; numbers here are examples, not guaranteed existing IDs |
| `GET /api/v1/events/stream` | Authenticated refresh/event stream; not a substitute for durable reads |

Use IDs/verification paths returned by the installation. A screenshot or a
handwritten ID does not prove a persisted snapshot exists. NBOM and native VBOM
do not inherit an immutable pin merely because a TechBOM version was captured.

## 4. TechBOM export contract

`GET /api/v1/technology-bom/export` accepts:

- `version`: actual recorded version; omit for a current live rendering.
- `fmt`: `json`, `csv`, `cyclonedx`, `cyclonedx-xml`, `xml`, `spdx`, `pdf`.
- `layer`: `all`, `sbom`, `cbom`, `hbom`, `vendor`, `certificates`.
- Optional implemented filters such as `search`, `risk_level`, `key_size_min`,
  `type`, `include_certificates`.

There is no supported general `layer=nbom` or `layer=vbom` spelling. The supplier
layer is called `vendor`; the richer VBOM has its own endpoint.

JSON/CycloneDX/SPDX responses are manifest objects carrying the rendered `data`
and metadata. Raw CSV/XML/PDF responses are downloadable bytes with integrity/
signature/snapshot response headers. Preserve headers as well as the file when
required by the selected verification procedure. Live exports can carry a
scan-in-progress warning; do not hide it in a bank evidence package.

A full manifest commonly includes snapshot/state information, format/layer,
`data`, `integrity_sha256`, `signature_jws`, `signature_hmac`, `signature_alg` and
an audit-event reference where emitted. Inspect the exact response rather than
assuming an example contains every field or that an audit-event ID proves a
complete durable audit trail under every failure condition.

## 5. What signature and hash verification actually means

### Source evidence and CBOM

Use the stored-scan verifier and CBOM pin/verification contract, including the
canonical serialization. CBOM signing is optional on the relevant routes.
The current renderer uses `CRYPTOSCAN_CBOM_SECRET` or the configured application
secret for its shared-secret path. It also supports configured RS256/ES256 via
`CRYPTOSCAN_CBOM_SIGN_ALG` and protected private-key configuration, with key IDs
and distinct signature forms. These settings are not automatically equivalent
to similarly named secrets used by other event/report services.

Do not export private signing keys with the evidence. For independent auditor
verification, design the asymmetric public-key distribution/trust process and
verify the exact algorithm/form actually used. Never describe a shared-secret
HMAC as if the verifier needed only a public key.

### TechBOM export manifests

The export service emits a SHA-256 integrity value, compact JWS using HS256 and
legacy HMAC metadata. Its canonical export serialization can bind the snapshot
identity and rendered body; hashing pretty-printed downloaded JSON is not
necessarily the same operation. Use `canonical_export_payload` and the selected
format's serialization rules when building a verifier.

The service selects `EXPORT_SIGNING_SECRET`, then `GOVERNANCE_SIGNING_SECRET`,
then `SECRET_KEY`; its helper also has a weak development fallback when none are
set. **Explicitly supply and review production signing configuration.** Setting
a value in a host `.env` does not prove that Compose forwards it to the correct
service. Do not rely on the helper's fallback or assume a manifest is trustworthy
merely because a signature field exists.

### HBOM

Independent estate HBOM pins verify stored canonical content against the pinned
hash and embedded hash. `MISMATCH` is a stop condition, not a warning to suppress.
A matching hash means stored-content consistency under that verification model;
it does not attest physical hardware identity or firmware authenticity.

For all formats, validate interoperability with the bank's actual consumer.
Native formats/custom properties and CycloneDX-style version labels do not
constitute third-party schema certification, regulatory approval or trusted time.

## 6. Suggested evidence package

This is an **operator packaging checklist**, not a claim that one endpoint
atomically exports all five BOMs:

```text
bank-approved evidence location/
  scope-and-authorization
  collector-builds-config-versions-and-policy-versions
  source-job-result-and-coverage
  source-evidence-verification-and-cbom-pin
  network-run-results-and-nbom
  hardware-observations-and-hbom-pin
  vendor-bom-profile-revisions-and-supporting-evidence
  technology-snapshot-and-selected-export-manifest
  integrity-and-signature-verification-results
  exclusions-errors-staleness-and-owner-signoff
```

Record a cutoff window and the actual source/run/snapshot/version identities.
The five outputs can refer to different collection times. Retain unknowns and
failed scopes in the handoff rather than removing them to improve a dashboard.
Apply bank encryption, retention, access and transfer controls to the bundle.

## 7. Understanding unexpected screens

| Symptom | Investigation |
|---|---|
| Blank/zero NBOM after a scan | Did the selected route persist `network_scan_runs`? Is the correct tenant/scope selected? Did probes succeed? |
| Hardware in one panel but not another | Compare persisted estate, ephemeral controller and live-scan scope; inspect ingestion/persistence errors |
| Vendor exists but no crypto entries | Registration alone is not supplier evidence; validate questionnaire/import/profile paths |
| CBOM differs from network posture | Source and wire see different layers; check build/deployment/SNI/time/provenance before calling it a contradiction |
| TechBOM count lower than expected | Check per-collection caps, filters, selected scope and ingestion mapping; do not label bounded output complete |
| Live values change during review | Settle selected jobs and capture supported immutable states; retain separate network/vendor outputs |
| Download contains a wrapper | The endpoint returned an export manifest; extract `data` only while preserving the full verification metadata |
| No realtime update | Check event transport and permissions; reload durable job/result APIs; an event is not the database authority |
