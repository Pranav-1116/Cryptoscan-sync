# Phase 1 — universal collection foundation

**2026-10-24 · implemented development/offline foundation; not production clearance**

Engineering rule: **a BOM is a projection of evidence, not a source of truth.**
Facts, provenance, identity and justified relationships remain authoritative.
No AI output is accepted as an observed fact. Failure is not evidence of absence.

This implements the first adapter on the existing architecture rather than moving
services or creating independent SBOM/CBOM/NBOM/HBOM/VBOM databases.
[Phase 2 Linux increment](63-linux-collection-phase-two.md) ·
[Execution evidence](../readiness-evidence/collection-foundation-2026-10-24.md).

## What is implemented

```text
Scoped System (existing)
  → stable collection target + explicit manifest
  → current admin/CISO authorization + existing host approval
  → durable collection job: READY → AWAITING_EVIDENCE
  → ordinary-user OFFLINE Linux adapter (never an API subprocess)
  → existing one-use host intake → Scan / EvidenceRecords / manifest
  → job completion referencing that SAME intake
  → typed central evidence envelope + stable metadata-slot identities
  → SBOM / CBOM / NBOM / HBOM / VBOM / TechBOM reference projections
```

The universal boundary and strict schemas live in `shared_models.collection`.
`OfflineLinuxCollector` implements `validate_scope`, typed `collect` and `health`;
its first raw contract is the existing bounded `HostSnapshot`. Future adapter
families must add/version typed raw contracts rather than return unrestricted
JSON. Normalization, identity slots, coverage and BOM assignment happen centrally,
not in a collector emitting six unrelated BOMs.

Existing `System`, `AssuranceRevision`, `Scan`, `EvidenceRecord`, evidence pipeline,
audit repository and official-schema CBOM generator are reused. New assurance
kinds are `collection_target` and `collection_job`; no migration/new inventory or
network service is required. Existing source/network/other APIs retain their own
admission contracts; this is not a claim that every legacy collector has already
been migrated into the universal interface.

## Stable target and authorization

- A target ID is deterministic over the exact selected estate and `target_key`.
  The declared owner/contact label is **not** its security principal. Actual owner
  isolation comes from the current durable session, selected estate and system.
- Target holds system/environment, logical address, method, allowed operations,
  `not_before`, read-only flag, explicit host manifest/expiry and exclusions.
  Offline collection accepts **no credential reference**. Future methods can store
  a `vault://...` reference but cannot resolve it or execute in this adapter.
- Only `READ_APPROVED_METADATA` exists in v1. No command executor, broad-CIDR
  authorization, credential retrieval, SSH/WinRM or cloud invocation is enabled.
- Excluded input IDs must be removed from the allowlist, not merely displayed.
  An exclusion is not an unimplemented glob or a promise to filter arbitrary paths.
- Analyst/admin/CISO can register. Admin/CISO authorizes, updates or revokes using
  an expected revision, reference and rationale. Authorization binds the exact
  target revision and underlying host-approval hash, and expires within 24 hours.
- Updating a target preserves its stable key/system identity but resets it to
  `REGISTERED`; old jobs and old intake authority stop admitting new work. New
  authorization is required even when an update only changes the declared owner.
- Current system environment must match at authorization and new-work admission.
  No physical-host identity is attested by these administrative declarations.
- Future collector methods can be registered, but authorization returns 409 until
  an actual adapter is supported. Windows is not silently qualified by portable
  code. `GET /collectors` reports unavailable families, not fictional checkmarks.

Target states: `REGISTERED → AUTHORIZED`; authorized work can be withdrawn to
`REVOKED`. An explicit update creates a new `REGISTERED` revision. Histories are
append-only at API/ordinary ORM boundaries, with expected revisions and linked
content hashes. Each history read checks all predecessors, up to 100 revisions;
exhaustion is an explicit refusal, not silent truncation.

## Jobs and evidence lifecycle

1. Create a job against the exact authorized target revision. There is one job per
   target/authorization, not six jobs for six BOMs. A duplicate is 409.
2. Handoff changes `READY → AWAITING_EVIDENCE`. This truthfully describes an offline
   operator handoff, **not** a remotely running process or attested `COLLECTING`.
3. Export the actual authorized target payload, run the existing offline CLI with
   `--target-spec`, and transfer its metadata snapshot by a bank-approved channel.
4. Import through `/host-evidence/approvals/{approval_id}/intake`. This reuses the
   current one-use evidence pipeline rather than making a second evidence store.
5. Complete the job by expected revision. The platform reopens the exact imported
   snapshot/manifest/scan/evidence chain and commits its deterministic envelope hash.
6. Read the same evidence for any number of BOM projections. Reads do not trigger
   collection. Repeated reads do not create another scan, asset or observation.

`COMPLETED` means all **approved input receipts** parsed. Some failed inputs yield
`PARTIAL`; none parsed yields `FAILED`. None of these implies complete host or
bank coverage, acceptable policy posture, authenticated identity or crypto use.
There is no automatic resume/retry/recollection or timeout-to-no-assets conversion.

The intake commits independently before job completion. A failed completion/audit
leaves the original intake intact for inspection and an intentional completion
retry, never automatic recollection. Authorization plus its host approval is one
atomic transaction; each target/job transition and its audit is atomic.

### Revocation is not just a UI flag

New job admission, handoff, completion and registry-bound legacy intake share a
PostgreSQL row mutex on the target's original immutable revision. Revocation and
scope updates use the same mutex. An intake that wins before withdrawal may
commit first; an intake after withdrawal is refused. The older host-intake URL
cannot bypass a bound registry authorization. Replaying an already committed
identical intake can still inspect historical evidence; it does not add new data.

Previously committed envelopes remain inspectable after revocation or target
renewal, using the exact historical target revision. A job read separately reports
whether current authority admits new work. Withdrawal does not erase history.
The concurrency witness qualifies PostgreSQL; SQLite is not claimed to provide
this row-lock concurrency guarantee.

## Common evidence contract and identity

`CollectionResult` is strict/versioned, not arbitrary collector JSON:

- Target/job/revision/system/environment and collector/version.
- Collection timestamps, imported provenance and original evidence manifest.
- Typed observations: exact fact, input/ordinal, approved source path/kind/input
  digest, host label, collection time, original evidence ID/content hash/fact hash.
- Separate typed collection errors; every failure carries `asset_absence_proven:false`.
- Coverage numerator/denominator for approved inputs only. `whole_host_percent:null`;
  no guessed 98% package or 60% hardware coverage without a defensible denominator.
- Host attestation false, runtime/PQC use UNKNOWN, source revision null if unavailable.

Certificate/config observations reference their original fact EvidenceRecords.
Package/binary/OS observations reference the original per-input evidence anchor,
plus the individual fact hash and committed snapshot; this does not fabricate new
crypto EvidenceRecords for software or OS metadata.

Observation IDs identify a particular scan/fact. A separate stable metadata-slot ID
uses estate, stable target, input kind/path, fact kind and software name—**not its
version**. OpenSSL 3.0.13 → 3.0.17 therefore changes the observation/version, not the
same scoped metadata slot. This is not an authenticated asset merge, signed
package identity, purl assertion, image digest or physical host fingerprint.
Target/path/name changes can correctly create different slots. Cross-target or
cross-tenant equal names are never merged.

The same observation ID can contribute to more than one domain. Projections return
IDs referencing the one committed envelope rather than duplicating evidence:

| Evidence | Current contributions | What is NOT inferred |
|---|---|---|
| Package/database or binary-header metadata | SBOM + TechBOM | Loaded package, signed release or crypto invocation |
| Public certificate/TLS config metadata | CBOM + TechBOM | Served certificate, negotiated TLS or network endpoint |
| OS-release file declaration | TechBOM | Attested running kernel/OS or software dependency |
| No supported observation | NBOM/HBOM/VBOM empty, operational use UNKNOWN | No network/hardware/vendor risk |

Internal projection JSON is **not** a standard CycloneDX SBOM/CBOM. Existing native
host CBOM remains at the original schema-validated 1.6 export. Source evidence is
IMPORTED; local certificate/file observation and local declarations remain distinct.
The reviewed [six-BOM association adapter](61-host-to-six-bom-associations.md) remains
necessary for explicit external identity/relationship assertions. This foundation
does not automatically manufacture system→HSM, package→algorithm or vendor-use edges.

## API and reproducible operator sequence

All endpoints below use `/api/v1/collection` and the existing selected-estate session.

| Endpoint | Purpose |
|---|---|
| GET `/collectors` | Actual current/future adapter availability and capability boundaries |
| POST `/targets` | Register strict target spec |
| PUT `/targets/{id}` | Admin/CISO `expected_revision` + replacement `target`; resets authorization |
| POST `/targets/{id}/authorize`, `/revoke` | Admin/CISO revision/reference/rationale |
| GET `/targets`, `/targets/{id}` | Scoped paginated heads or verified full target history |
| POST `/jobs` | `target_id` + `expected_target_revision` |
| POST `/jobs/{id}/handoff`, `/complete` | Analyst/admin/CISO `expected_revision` |
| GET `/jobs`, `/jobs/{id}` | Scoped heads/job status and current admission indicator |
| GET `/jobs/{id}/evidence`, `/projections`, `/errors`, `/coverage` | Materialize stored evidence; no acquisition |

Lists return at most 50 heads with explicit `has_more`/`next_cursor`; page results
are not a complete-estate coverage assertion. Target history is bounded at 100
revisions; envelopes at 1,000 facts/100 receipts/4 MiB. Host wire/collector limits
still apply. Streaming 2 MiB strict JSON/no-store and shared host read/write rate
buckets cover these endpoints, including PUT. Auditors/viewers cannot write.

With actual inspected IDs and an authenticated scoped `client`:

```python
# target_spec contains the exact approved HostManifest, read_only=True,
# allowed_operations=["READ_APPROVED_METADATA"], and aware not_before/expiry.
target = client.post("/api/v1/collection/targets", json=target_spec).json()
# STOP: an admin/CISO authorizes this ID/revision with their own current session.
# Read the returned AUTHORIZED revision, not a made-up sample ID or digest.
auth = authorized_target_response
job = client.post("/api/v1/collection/jobs", json={
    "target_id": auth["subject_id"], "expected_target_revision": auth["revision"]
}).json()
client.post(f"/api/v1/collection/jobs/{job['subject_id']}/handoff",
            json={"expected_revision": job["revision"]})
```

Save **only** `auth["payload"]["target"]` to `approved-target.json` on the controlled
host, then run as its ordinary authorized OS user:

```sh
python scripts/collect_host.py --target-spec approved-target.json --output snapshot.json
```

Use the actual `auth["payload"]["approval_id"]` for the existing intentional intake.
Complete using the actual handoff revision. Never paste credentials into examples.
After an uncertain mutation response, inspect before deliberately retrying.

## Phase gates and limits

Phase 1's first 18 focused integration cases passed **before** beginning Phase 2.
The final combined gates add strict-envelope, Linux, schema, failure, rate/body,
identity-history and PostgreSQL concurrency witnesses; see the execution report.

This is a development/offline foundation, not a remote scheduler/worker rollout.
All `/collection` routes remain blocked by controlled production admission. No
privileged container, Docker socket, root/Domain Admin or shell shortcut was added.
Hashes bind local integrity, not authenticity. Host/clock/storage are not attested;
restricted DB grants/external audit anchors and independent review remain required.
Full global audit-chain verification is not performed on every read. The catalog
is not proof that future collector families have been implemented or migrated.
