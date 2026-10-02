# Vendor due-diligence profiles

CryptoScan stores vendor due diligence as a validated, versioned profile. It is
separate from the observed/self-reported cryptographic inventory: a vendor can
have an empty crypto inventory and still require a complete operational review.

## Lifecycle and truth model

- `DRAFT` is editable by submitting a new revision and is expected during
  collection.
- `IN_REVIEW` identifies a revision awaiting human review.
- `APPROVED` is allowed only when every required completeness item is present
  and `reviewed_by` is supplied.
- `EXPIRED` is retained for historical evidence that is no longer current.
- Revisions are append-only. History is exposed so an auditor can compare the
  exact JSON, completeness snapshot, source, reviewer, capture time, and
  SHA-256 content hash. A correction is a new revision, not an edit in place.

Unknown, unavailable, pending, and unverified values are represented explicitly.
They do not count as a pass and the risk response remains `UNKNOWN` while the
profile is incomplete. No vendor facts, certifications, incidents, financial
values, customer references, or assessments are fabricated by the system.

## API

All routes are under the existing API prefix and require the existing
application authentication and tenant context:

- `GET /api/v1/vendors/{vendor_id}/profile` — current profile or an explicit
  empty draft with completeness and `persisted: false`.
- `PUT /api/v1/vendors/{vendor_id}/profile` — validate and append a revision.
  The body is `{ "profile": <document>, "status": "DRAFT|IN_REVIEW|APPROVED|EXPIRED", "source": "...", "reviewed_by": "...", "review_notes": "..." }`.
- `GET /api/v1/vendors/{vendor_id}/profile/history` — newest-first immutable
  revisions.
- `GET /api/v1/vendors/{vendor_id}/profile/schema` — JSON Schema for clients.
- Existing `GET /api/v1/vendors/{vendor_id}/risk` and
  `GET /api/v1/vendor-risks` now include `due_diligence`. This is an
  explainable screening signal, not a certification or a replacement for a
  qualified risk decision.

Profile writes reject unknown fields and reject credential-like fields or
private-key/bearer-token values. Evidence is provenance metadata only: store a
reference or hash, never an uploaded secret, token, password, private key, or
credential.

## Coverage

The schema (`cryptoscan.vendor-profile/1`) has structured sections for identity
and contacts; components and services; contracts, SLAs and legal terms;
security assessments, findings, certifications and compliance; data flows,
residency, retention, privacy, DPO and subprocessors; financial stability and
succession risk; incident history and response; criticality, concentration,
single-point, fourth-party and cascading dependencies; access and personnel
controls; and exit, migration, portability, escrow and transition planning.

Migrations are applied through revision `0066`. Deployments must run the normal
migration process before enabling profile writes; `create_all` also registers
the model for local development. Existing questionnaire and crypto inventory
endpoints remain available and are not treated as a substitute for this
profile.
