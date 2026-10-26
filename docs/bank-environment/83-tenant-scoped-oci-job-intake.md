# 83. Tenant-scoped OCI authorization, handoff and durable intake

## Gap filled

The [standalone offline OCI reader](68-offline-oci-image-collection.md) supplied typed evidence and pure six-view materialization, but was not connected to tenant-scoped registry/jobs or durable platform intake. This increment builds that connection **using the existing assurance revision store**, not another database/service or an image-executing API.

The standalone instructions and initial [engineering record](../readiness-evidence/offline-oci-image-2026-10-25.md) describe an earlier local working-tree run. Their statements about missing API integration and not-yet-published work are historical. This guide and the [publication validation record](../readiness-evidence/oci-job-intake-2026-10-26.md) describe the new integration and tested publication tree. The earlier manifest fingerprints its original working-tree baseline; it is not a claim that all dependency paths still match the current GitHub tree.

## Product path

```text
Authenticated exact-estate target registration
  -> authorized current human approves immutable target revision
  -> one READY job per authorization revision
  -> explicit AWAITING_EVIDENCE handoff with random public challenge
  -> ordinary-user local CLI reads only approved OCI blobs
  -> original typed evidence wrapped with exact handoff binding
  -> authenticated intake rechecks current authority and commitments
  -> atomic consumption + original return + terminal job + audit
  -> stored-evidence reads and six-view materialization, never a new scan
```

Code:

- [Workflow contracts](../../shared/shared_models/shared_models/oci_intake.py)
- [Existing-store workflow implementation](../../services/api/api/assurance/oci_collection.py)
- [Authenticated HTTP router](../../services/api/api/routers/oci_collection.py)
- [Offline bound capture](../../services/inventory/inventory/oci_job_capture.py)
- [Bound CLI](../../scripts/capture_oci_job_evidence.py)
- [HTTP contracts](../api-reference/oci-job-intake.md)
- [Operator steps](../runbooks/oci-job-intake.md)

The existing standalone `OciTarget`, `OciEvidence`, reader and materializer remain unchanged. A new `OciJobReturn` wraps the **original** evidence with an `OciCaptureBinding`; it does not manufacture BOM observations or signatures. The existing host `TargetSpec -> HostSnapshot` contract and older OCI/TLS/native paths are not replaced.

## Authorization and identity

All routes live below `/api/v1/collection/oci`, inside the existing collection 2 MiB streaming body/duplicate-JSON/no-store boundary. Reads use the existing exact-estate session context/residency boundary. Writes additionally require a current durable human session and existing RBAC permission; API-key identity or a role supplied in a request body cannot act as the author.

- Registration, job creation, handoff, cancellation and intake use `assurance.manage`.
- Authorization, scope update and revocation use `assurance.trust`.
- No new role, credential store, API key or secret is introduced.
- This enforces permission separation, **not** an organizational two-independent-human acceptance ceremony. Independent customer/production review remains external.

Stable target identity uses the selected estate and the declared logical image-target key. Target updates cannot reassign that identity or its system. A referenced system must exist in the exact estate, be active and match the target environment. Scope updates return the target to `REGISTERED` and require fresh authorization. Authorization must expire within 24 hours of approval; a far-future registration is not a long-lived execution grant.

The server target `subject_id` is a UUID; the original `OciTarget.target_id` is an operator-scoped logical key. These are different fields and must not be substituted. Manifest SHA256 remains artifact identity; this workflow does not infer actual deployment from a system label.

## Public handoff challenge, not attestation

An authorized job's handoff supplies:

- exact job and server target UUIDs;
- authorized target revision and hash-covered target-record SHA256;
- canonical original target SHA256;
- fresh 256-bit random public nonce;
- server issue time and bounded expiry.

The CLI checks the independently supplied target and binding commitments **before opening image blobs**. Capture timestamps must lie after handoff issuance and before both handoff/target expiry. The server compares the original binding with its retained handoff, not merely with a digest supplied by the uploader.

The nonce and hashes bind context and prevent acceptance of a stale/different handoff. They do **not** prove a trusted producer, correct host clock, image authenticity, measured execution, protected key custody or physical hardware. A malicious producer can invent internally consistent metadata and times. `producer_authenticity_verified=false`, imported provenance, unknown runtime use and all original completeness limits remain non-promotable.

## Durable state and race handling

```text
Target: REGISTERED -> AUTHORIZED -> REVOKED
        update -> REGISTERED (fresh authorization required)

Job: READY -> AWAITING_EVIDENCE -> COMPLETED | PARTIAL | FAILED
     READY | AWAITING_EVIDENCE -> CANCELLED
```

There is one deterministic job per exact authorized revision. Handoff and intake require expected revisions; duplicate creation/handoff/intake cannot become another accepted operation. A terminal partial or failed collection is not silently retried into success.

All target mutations, admission, handoff, cancellation and intake share the immutable first target row as a PostgreSQL mutex. The target lock precedes the system lock consistently. Authorization checks and consumption happen while that mutex is held. Concurrent intake versus revoke/update/cancel has a serialized outcome: evidence committed before withdrawal, or withdrawal prevents intake. The database tests exercise actual row locking and races, not only mocks.

Intake performs one transaction containing:

1. exact-estate evidence-digest consumption record;
2. original bound return and its evidence/binding commitments;
3. terminal job revision linked to that original record;
4. existing audit entries.

An audit/storage failure rolls the transaction back. PostgreSQL uniqueness and the target mutex make duplicate intake one winner, not two snapshots. This is application hash-linked append-only storage, **not** externally signed WORM storage or resistance to full database/administrator compromise.

## Read and projection rules

Every retained read verifies complete bounded job/target revision chains, original evidence record, typed return, handoff, digest-consumption record and terminal job commitments. Corruption refuses instead of silently rematerializing changed evidence. Completed historical returns remain inspectable after revocation or expiry; that is not permission for new work.

The six views are still generated by the same pure materializer over stored evidence:

| View | Preserved meaning |
|---|---|
| SBOM | Selected package database/binary metadata; not full image or loaded production inventory |
| CBOM | Public certificate/config metadata; never crypto invocation inferred from package names |
| NBOM | Unknown for image-only capture; declared exposed ports are not observed sessions/listeners |
| HBOM | Unknown; image architecture is not observed physical hardware |
| VBOM | Allowlisted vendor label is declared-only, not verified supplier identity |
| TechBOM | Same evidence references and declared scope; no automatic operational/deployment edges |

No handler reads a layout path, contacts a registry/endpoint, launches a worker or executes an image. `graph_persisted=false`, `cyclonedx_export=false`, no automatic `USES_HSM`, and no AI-manufactured `OBSERVED` facts remain intact.

## Release and remaining gates

The earlier implementation was validated on a local baseline that differed from the GitHub tip. Publication is built as a **small additive patch on the existing published branch tip**, not a mass commit of the unrelated pending local edits/deletions. Required foundation/native capabilities already on GitHub are retained. Only the new OCI files and the two-line router inclusion are staged. No workflow edits, CI dispatch or customer deployment changes are included; the commit uses `[skip ci]`.

Actual test counts, public retained returns and source/artifact commitments are in the [publication validation record](../readiness-evidence/oci-job-intake-2026-10-26.md). The production execution-control boundary remains closed: controlled-production requests do not gain admission from these engineering tests.

Still open: independent expected truth for authorized customer images; parser/isolation release assessment; native Windows/customer-container/hardware/customer-app proof; authoritative estate coverage; independent bank acceptance and production admission. This fills the scoped offline intake gap, not all of those external gates.
