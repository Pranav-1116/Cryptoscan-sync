# API — Linux traffic preflight / isolated validation

[Guide 87](../bank-environment/87-linux-traffic-preflight-and-isolated-control.md) · [Runbook](../runbooks/traffic-control.md)

Prefix `/api/v1/traffic-control`. Existing typed human sessions, exact selected estate, active system/environment, execution/residency controls and append-only assurance revisions apply. Success responses are `Cache-Control: no-store`; this is not a claim about all middleware/error responses. No remote execution, real-host apply or result-certification endpoint exists.

| Method/path | Body / result |
|---|---|
| `POST /proposals/{id}/preflight-requests` | `expected_proposal_record_sha256`, `management_ips`; 201 assurance record containing `spec` and `spec_sha256` |
| `GET /preflight-requests/{id}` | Historical request record, source closure verified |
| `GET /preflight-requests/{id}/specification` | Current `PreflightSpec`, directly downloadable without browser numeric reserialization |
| `POST /preflight-requests/{id}/captures` | `capture`, `expected_preflight_sha256`; 201 immutable capture/report record, at most one per request |
| `GET /preflights/{id}` | Historical capture/report, original request/proposal/measurement closure verified |
| `POST /validations` | `preflight_id`, `expected_preflight_record_sha256`, `reviewer_user_id`, `duration_seconds` 1–5, `reason` 20–500 characters; 201 isolated-validation proposal |
| `GET /validations/{id}` | Retained proposal/review history and source closure |
| `POST /validations/{id}/approve` | `expected_revision: 1`, `evidence_ref`, `reason`; assigned distinct current human reviewer only |
| `GET /validations/{id}/authorization` | Current namespace-only `DrillAuthorization`; rejects absent review, expired/revoked source, stale sample, inactive system or insufficient remaining time |

Mutations require `assurance.manage`; approval requires `assurance.review`. Request/capture/proposal/review operations serialize against the originating resource plan using existing row locks; a concurrent revocation must not be bypassed. Optimistic revision checks allow only one retained capture and one review. Unselected/wrong estates cannot read private source records; role alone does not inherit another estate's evidence. Reviewer eligibility is checked against current active human roles and membership at proposal/review/export.

Management destinations are 1–8 unique canonical IPv4/IPv6 unicast literals. Hostnames, unspecified/multicast/scoped/noncanonical addresses are rejected. The collector uses fixed family-specific `ip route get`, not a network probe. Readings explicitly distinguish `MEASURED`, `DENIED`, `INVALID`, `UNAVAILABLE`; no route/source failure can claim a clean policy or safe management path.

Source sample must remain at most five minutes old and currently approved; preflight expiry is bounded by sample freshness and the original scope. Recollect rather than extend a stale request. Canonical typed digests are **not** pretty-file SHA sums. Retained record `payload_sha256` is distinct from `digest(spec)` and `digest(capture)`.

Every export says `authorizes_real_host_change: false`, `source_authenticity_verified: false`, `target_interface: lo`, `profile: FRESH_USER_AND_NETWORK_NAMESPACE_ONLY`. The unsigned offline file cannot authenticate its reviewer/source and is not a production authorization. It can be replayed locally within its window; there is no one-time device redemption protocol. Local execution never promotes the source proposal, uploads a result automatically or asserts production qualification.

Contracts and five generated Draft 2020-12 schemas live in `shared/shared_models/shared_models/linux_traffic_control.py` and `schemas/linux-traffic-*-v1.schema.json`. API inputs are strict and reject extra fields; hashes/source closure are recomputed server-side. No caller-selected executable, qdisc handle, host interface write target or shell command is accepted.
