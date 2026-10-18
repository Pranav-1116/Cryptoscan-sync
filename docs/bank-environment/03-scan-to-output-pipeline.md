# 03 — From a scan request to visible, evidence-backed output

[Guide index](README.md) · Previous: [Access](02-collection-and-access.md) ·
Next: [Six BOMs](04-six-boms.md)

## 1. There are several execution paths, not one magical universal scan

The repository has a queued source pipeline, cloud/binary job dispatch, direct
synchronous scanner routes, hardware-event ingestion and vendor-document
imports. They share parts of the inventory and presentation model, but do not
all execute the same stages or write identical evidence ledgers.

The following is the main **queued application/source** journey. The differences
for other paths are stated explicitly below.

## 2. Operator request and scope

An authenticated operator registers a system or selects an existing target.
The system carries ownership, business unit, environment and a scan target.
A registration can say “payments application in UAT”; its cryptographic posture
is still unknown until evidence arrives.

`POST /api/v1/systems/{system_id}/scan` retains system linkage.
`POST /api/v1/scans/trigger` accepts a direct target, branch/revision and optional
sector/mode. The platform resolves the current identity/tenant context;
authorized scope does not come from trusting an arbitrary client tenant field.

Queued triggers invoke admission: stop state, safe-scan policy, queue pressure
and relevant OT/active-probing conditions. Local source targets are contained to
authorized roots. A rejection means **no accepted scan**, not a zero-findings
success. This is not a guarantee that every legacy direct route is identical.

## 3. Durable acceptance, dispatch and progress

The trigger persists a `ScanJob`, then publishes queue work when Redis is
configured. Without a configured queue, the implementation can schedule an
in-process background run; this is not an equivalent HA production topology.

A 202 response means the source job was **accepted**, not completed. Read
`GET /api/v1/jobs/{job_id}` and its logs/progress. A job ID is not interchangeable
with a scan ID; the committed scan linkage is resolved separately.

Queue/database outages and worker crashes are real failure cases. Record their
visible outcome, reconcile accepted-but-unprocessed jobs, and qualify recovery.
Do not infer exactly-once execution from durable acceptance or a queue name.

## 4. Stage the exact input

The worker creates a workspace and clones/copies the requested source. It records
target, branch and commit when available. A shallow remote clone may not contain
an arbitrary historical commit; a checkout failure is an input/provenance issue,
not a successful scan of the requested revision.

The worker performs language discovery and other orchestration. For production
static parsing it launches the separately provisioned isolated parser with an
admitted staged tree. The parser sees read-only input and bounded scratch/output,
not worker credentials or network access. It must fail rather than fall back to
inline parsing if the isolation prerequisites are missing.

## 5. Detect cryptography and configuration facts

Detectors inspect supported source languages, configuration, libraries,
cryptographic material metadata and relevant declared dependencies. A finding
can carry algorithm, key size/mode/purpose, source file/line, detector provenance,
confidence and code origin. Some values remain unresolved because runtime
configuration or dynamic calls are not statically knowable.

Example, **illustrative human-readable summary, not an exact API payload**:

```text
System: Payments API / UAT
Revision: recorded release commit
Source: src/signing.py, line 42, application source
Observation: RSA public-key signing, key size resolved as 2048 bits
Evidence: detector/source references and stored evidence identifier
Confidence: use the detector's recorded value; do not invent a percentage
Unknown: whether this call ran in production and what key was used there
```

The same algorithm name in a library file and a production call site need not
mean two independent deployed keys. Test/generated/vendored origins and shared
key references need separate interpretation.

## 6. Evidence, persistence, normalization and policy

The source pipeline includes these responsibilities; stage names/order should
be checked against `pipeline_runner.py` and the progress model rather than an
old “eight stages” label:

| Responsibility | What the bank should retain/check |
|---|---|
| Evidence creation and hashing | Per-finding identity/provenance, canonical content and chain/manifest references |
| Scan/evidence database loading | Committed scan ID and durable rows, not just console output |
| Normalization | Comparable algorithm/mode/key-size fields; unresolved values remain unknown |
| Policy evaluation | Rule/control identifiers, policy version and rationale, not a generic compliance promise |
| Deduplication / asset resolution | Stable crypto asset identity and linkage, with source provenance retained |
| System / declared estate linkage | Correct application/business relationship; do not infer undocumented dependencies |
| Optional enrichment | Cloud/container/TLS/OT/graph/quantum/business stages where configured; inspect omissions/failures |
| Drift / decision / notifications | Changes and rule-based outcomes; message delivery is a separate concern |

Optional collector failures are recorded where supported; a completed source
job does not mean every cloud, container and network stage succeeded. Inspect
`optional_stage_failures`, parser statistics, coverage and per-collector telemetry.
A gate outcome such as PASS/BLOCK is scoped to the implemented rules and observed
input, not certification that the application is safe or production-complete.

Evidence hashing detects certain stored-content changes when verified with the
correct context. It does not establish that an input was authentic, an omitted
asset never existed, or a timestamp was independently witnessed. Sensitive
source/snippets require access controls and lifecycle review independently of
hash integrity.

## 7. Materialize BOMs from the correct stores

- **SBOM:** standalone software scanning parses supported manifests/lockfiles or
  inspects container/binary inputs, renders a software document and stores its
  own artifact. It is separate from TechBOM's registered-application layer.
- **CBOM:** scanner/crypto asset/evidence records become scan, system and estate
  cryptographic components. An imported supplier CBOM is a different provenance.
- **NBOM:** persisted `network_scan_runs.result` probes are mapped into endpoint,
  certificate and negotiated-transport components. Newest stored run wins per
  endpoint in the current bounded query.
- **HBOM:** the independent estate generator reads persisted `hardware_assets`;
  per-asset observation/evidence fields accompany the components.
- **VBOM:** vendor records, vendor crypto inventory, system-vendor links and
  profile revisions form the independent supplier document.
- **TechBOM:** a bounded inventory gather reads systems, crypto assets, hardware,
  vendor records, certificates and declared system dependencies, then projects
  its shared layers.

A materializer does not perform a new network scan simply because the browser
opens a BOM page. Different BOM counts are expected: components, physical
assets, relationships and observations are not the same unit.

## 8. Live view versus stable snapshot

A live TechBOM read can occur while a scan is updating inventory. Its API reports
scan-in-progress information; the operator should not call that a stable
baseline. TechBOM snapshot capture stores a version/fingerprint and avoids a
new version for an unchanged fingerprint. CBOM and estate HBOM have their own
pinning APIs and identifiers.

These independent captures are not automatically one atomic transaction across
all six products. For an audit, define a cutoff, settle selected scans, capture
the supported snapshots and SBOM artifacts, and retain NBOM/VBOM outputs, hashes,
source-run IDs and time boundaries in a bank-owned release manifest.

## 9. How results reach the screen

The React SPA calls same-origin `/api/v1/...` endpoints. The API applies
identity/scope rules and projects stored results. Pages can re-fetch after
operations, on polling intervals and on realtime refresh notifications.

The authenticated SSE endpoint is `/api/v1/events/stream`. Event-bus/tailer
behavior depends on deployed processes and federation; the standalone worker's
stage publisher can have no API bus. **Use durable job/result reads as the
recovery path**, not “I saw an event” as proof that the result was committed.

When the API is unavailable, unavailable/error is not an empty successful
inventory. Empty results, unobserved assets, stale observations and failed
collectors each need their own interpretation.

## 10. Other paths and their differences

| Path | Important difference from the queued source pipeline |
|---|---|
| Standalone source SBOM | Synchronous local-path manifest/lockfile scan through `/devsecops/sbom/scan`; not the queued crypto AST parser or its isolated runtime. Retains its own artifact ID. |
| Cloud job | Dispatches to cloud inventory/ingestion; does not clone a repository. Provider telemetry can show failed/partial scope. |
| Direct cloud filesystem route | Returns IaC/live findings and durable job telemetry; do not assume its response automatically became the same shared estate records as queued ingestion. |
| Network due-target execution | Performs synchronous probes and persists network runs/certificates; use network run IDs, not a source-pipeline scan ID. |
| Direct network aliases | Admission, job telemetry and NBOM-store persistence differ; consult the explicit route matrix before operational use. |
| Hardware event | Updates persistent hardware state/journal from a supplied observation; receiving it does not independently attest the collector's truth. |
| Vendor import | Stores supplied crypto declarations/profile evidence; it does not run the supplier's code or scan all customer deployments. |
| Binary/container | Has artifact/tool/feed-specific inputs and sidecars; candidate network capabilities are not observed live listeners. |

[Implementation map](08-implementation-map-and-limits.md) links these claims to
source files and identifies the operational gaps that remain open.
