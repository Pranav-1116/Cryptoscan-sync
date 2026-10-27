# OCI metadata job API

Base path: `/api/v1/collection/oci`. Existing session authentication, selected-estate isolation, residency, durable human authority and RBAC apply. This is a development/offline metadata workflow; the existing controlled-production boundary refuses unqualified operation. It is **not** a remote image execution API.

## Endpoints

| Method / suffix | Body / response | Authority |
|---|---|---|
| `POST /targets` | `OciTarget` -> registered assurance row, 201 | `assurance.manage` |
| `PUT /targets/{id}` | `{expected_revision, target: OciTarget}` -> new registration revision | `assurance.trust` |
| `POST /targets/{id}/authorize` | `OciDecision` -> authorized revision | `assurance.trust` |
| `POST /targets/{id}/revoke` | `OciDecision` -> revoked revision | `assurance.trust` |
| `GET /targets` | bounded cursor list | selected-estate read |
| `GET /targets/{id}` | verified full bounded history | selected-estate read |
| `POST /jobs` | `{target_id: server UUID, expected_target_revision}` -> READY row, 201 | `assurance.manage` |
| `GET /jobs` | bounded cursor list | selected-estate read |
| `GET /jobs/{id}` | verified history | selected-estate read |
| `POST /jobs/{id}/handoff` | `{expected_revision}` -> AWAITING_EVIDENCE row with binding | `assurance.manage` |
| `POST /jobs/{id}/cancel` | `{expected_revision}` -> CANCELLED | `assurance.manage` |
| `POST /jobs/{id}/intake` | `OciIntakeRequest` -> terminal job, 201 | `assurance.manage` |
| `GET /jobs/{id}/evidence` | original validated `OciJobReturn` | selected-estate read |
| `GET /jobs/{id}/projections` | deterministic `OciProjection` over stored evidence | selected-estate read |

`OciDecision` contains `expected_revision`, a bounded public `evidence_ref`, and a 20–500-character reason. These are decision references, not private keys or evidence signatures. Reads do not execute collectors; the router's two-line app inclusion reuses the existing `/collection/` streaming JSON limit and no-store response behavior.

## Handoff and return

Handoff row payload includes `capture_binding` and its canonical `binding_sha256`. Export **that exact object**, not the whole assurance row, for the local capture CLI.

[Binding schema](../../shared/shared_models/shared_models/schemas/oci-capture-binding-v1.schema.json):

- `job_id`, `target_id`: canonical UUID strings;
- `target_revision`: exact authorized revision;
- `target_record_sha256`: hash-covered authorization row;
- `target_sha256`: canonical typed original `OciTarget`;
- `nonce`: server-generated 64-lowercase-hex public challenge;
- `issued_at`, `expires_at`: offset-aware, positive window of at most 24 hours.

[Job-return schema](../../shared/shared_models/shared_models/schemas/oci-job-return-v1.schema.json): `binding` plus original typed `evidence`. The standalone evidence contract is unchanged. The return cannot promote producer authenticity or runtime-use claims.

[Intake schema](../../shared/shared_models/shared_models/schemas/oci-intake-request-v1.schema.json):

```json
{
  "expected_revision": 2,
  "capture": {"schema_version": "cryptoscan.oci-job-return/v1", "binding": {}, "evidence": {}},
  "expected_evidence_sha256": "AGREED_CANONICAL_ORIGINAL_EVIDENCE_SHA256"
}
```

This is only a shape example; empty binding/evidence objects and the digest label are invalid. Use the actual CLI return and a reviewed canonical evidence digest. A raw pretty-JSON file SHA256 is not the canonical model digest.

The server verifies current authorization/revision/window/system, exact retained binding, capture times, agreed evidence commitment and no future finish time. It consumes the original evidence digest only in the same transaction as retained evidence, terminal job and audit. It does not re-open original image bytes or attest their producer. Do not describe accepted metadata as independently verified bank truth.

## State, errors and limits

- `REGISTERED -> AUTHORIZED`; update resets registration; revoke blocks old jobs' new intake.
- `READY -> AWAITING_EVIDENCE -> COMPLETED/PARTIAL/FAILED`; cancellation only from pending states.
- Every accepted authorization revision has at most one deterministic job. Terminal returns cannot be replayed into that job.
- Same public key/digest/label across different estates never grants cross-estate access. Missing/out-of-estate references return 404.
- Missing current human permission returns 403; stale revision/replay/revoked/expired/wrong binding returns 409; invalid typed input returns 422.
- Wire body above 2 MiB returns 413 before JSON parsing. Existing assurance payload cap is 1,500,000 canonical bytes; storage failure rolls back the whole intake rather than truncating evidence.
- Lists return at most 50 records plus `has_more`/`next_cursor`. Complete history verification has the existing 100-revision budget; exhaustion refuses, not partial validation.
- Public records use existing hash-linked assurance/audit storage. Application immutability and hashes do not prove authenticity or defeat a fully compromised database.

Historical evidence/projections remain readable after revocation, without new authorization or image access, unless the unqualified production boundary itself blocks the route. This does not admit new work. The result retains imported provenance, explicit gaps, unknown runtime/PQC use, `complete=false`, `graph_persisted=false` and `cyclonedx_export=false`.

See [Guide 83](../bank-environment/83-tenant-scoped-oci-job-intake.md), [operator runbook](../runbooks/oci-job-intake.md) and [engineering validation](../readiness-evidence/oci-job-intake-2026-10-26.md).
