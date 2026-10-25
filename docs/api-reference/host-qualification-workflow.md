# Host qualification workflow API

Base: **`/api/v1/collection/qualification/campaigns`**. Existing service, human-session boundary, tenant selection, regional/residency policy and collection request middleware apply. There is no machine-dispatch or remote-host route. See [bank operator procedure](../bank-environment/68-assigned-operator-qualification-workflow.md).

## Authentication, tenancy and permissions

Use the existing authenticated browser/session flow and selected tenant (`X-Tenant-ID` where applicable). These are typed/current durable human-session routes, not legacy bearer, machine-credential or API-key execution surfaces. Generic assurance list/history reads for `kind=host_qualification` enforce the same typed-human boundary; they cannot bypass it. Other existing record kinds are unchanged. Role strings supplied in a request cannot appoint a human. A platform administrator must select the exact tenant; unselected platform scope does not inherit tenant records. Cross-estate record IDs are not lookup shortcuts.

| Operation | Required permission and extra authority |
|---|---|
| Create, assign, withdraw | `assurance.trust` (current superadmin/ciso authority); immutable policy approver recorded |
| Return original | `assurance.manage` **and** current campaign assignment; Linux vs Windows native responsibility enforced |
| Freeze index | `assurance.manage` **and** assigned verifier |
| Submit decision | `assurance.review` **and** matching assigned reviewer/key identity |
| Read/list/export public record | Current typed durable estate-scoped human access with `crypto.read` |
| Download original bytes | Existing `assurance.raw` privilege (superadmin/ciso), not granted by auditor assignment |

Current active users, estate membership/non-viewer ownership, tenant ACTIVE state and role permissions are checked for all five assignments before evidence/review mutations. GET status/export also rechecks assignment authority. Revocation cannot retroactively undo a completed request; this is a fresh admission/read check, not a globally serialized identity-provider transaction.

## Routes and bodies

All JSON models forbid extra fields. References are the existing bounded `Token`: 1–120 permitted characters, not arbitrary URLs/instructions or confidential secrets. Paths use existing bounded assurance subject identifiers (server-generated UUIDs).

| Method and suffix | Request | Result |
|---|---|---|
| `POST /` (base without trailing slash is supported) | `CampaignCreate` below | 201 campaign status |
| `GET /?cursor=<subject UUID>` | Optional lexicographic cursor | Up to 25 current campaign statuses + `next_cursor` |
| `GET /{id}` | — | Re-evaluated campaign status |
| `POST /{id}/assignments` | Revision/reference + `assignments` map | 200; replace map before first original |
| `POST /{id}/artifacts?...` | Exact original body; query below | 201; immutable blob + revision + audit |
| `POST /{id}/freeze` | Revision/reference + `index: EvidenceIndex` | 200; complete immutable index |
| `POST /{id}/reviews` | Revision/reference + `review: SignedReview` | 200; one immutable externally signed decision per reviewer role |
| `POST /{id}/withdraw` | Revision/reference | 200 WITHDRAWN; no further mutation |
| `GET /{id}/artifacts/{sha256}` | — | Exact retained bytes, raw privilege required |
| `GET /{id}/export` | — | Current public policy/index/decisions/status JSON attachment; **not** originals archive |

`CampaignCreate` fields:

```text
policy: AcceptancePolicy
return_channel_reference: Token
evidence_reference: Token
```

Policy must match the selected tenant and contain exactly two distinct pinned public reviewer keys, one `independent_assessor` and one `bank_acceptor`, plus all four preapproved native plan/source commitments and scope/release/campaign. A campaign subject is deterministically scoped to tenant/campaign identity. The policy, approver and return-channel approval reference cannot be overwritten; trust-authorized creation does not independently attest external organizational/channel approval.

Every mutation after creation requires:

```text
expected_revision: integer, 1..320
evidence_reference: Token
```

Assignments are `{role: {user_id: <actual UUID>, reviewer_id?: <pinned identity>}}`, 1–5 entries. Allowed roles: `linux_operator`, `windows_operator`, `verifier`, `independent_assessor`, `bank_acceptor`. Only reviewers require/allow `reviewer_id`. Both reviewer users must be distinct from each other, operators/verifier and original policy approver; users cannot be invented or assigned outside their estate/current authority. No organizational-independence attestation is implied.

### Original artifact query and exact media type

```text
expected_revision=<current integer>
kind=native | public_json | tpm_attest | tpm_signature
evidence_reference=<bounded reference>
```

- `native` / `public_json`: **`Content-Type: application/json`**, exact original UTF-8 JSON bytes. Duplicate keys, excessive nesting/size, invalid native contract or known private-material patterns refuse.
- `tpm_attest` / `tpm_signature`: **`Content-Type: application/octet-stream`**, bounded raw public TPMS_ATTEST/TPMT_SIGNATURE structures, not a general-purpose binary uploader. Parsing a quote structure at intake is **not** cryptographic TPM/enrollment verification; return the existing independent quote-verifier result as separate public evidence.
- Native uploads must match the policy's category plan/source-lock identifier. Assigned Linux operator only for systemd/DMI/TPM; assigned Windows operator only for Windows. Supporting public forms accept any assigned operator/verifier with manage permission.
- The raw stream is bounded to 2 MiB; campaign is bounded to 256 originals / 16 MiB aggregate / 320 revisions (the last revision is reserved for withdrawal). Assignments lock after the first artifact and all original intake locks after index freeze. Duplicate originals refuse with 409.
- Storage retains exact bytes and digest, immutable submitter/responsibility, imported-artifact provenance, native verdict and evidence reference. Reports remain imported assigned-operator assertions, not proof of genuine measured execution or host hardware identity.
- Known-pattern rejection is not a secret-free guarantee. Do not submit credentials/private keys, including encoded/renamed/disguised forms. No evidence/secret values are deliberately echoed by artifact validation errors.

### Index freeze and review

`index` uses the existing `EvidenceIndex` public schema. Its referenced artifact set must equal the retained set; all native originals must independently match approved plan/release/category and be positive under the native evaluator. It binds all fourteen native/worker/host/custody/recovery checks. Supporting JSON presence is not proof of actual worker tests. Freeze is verifier-only and irreversible within the campaign.

`review` uses existing `SignedReview`. It contains a canonical Ed25519 public signature over `ReviewStatement`, including exact tenant/campaign/policy/index/release/reviewer/check/time bindings. The signer stays outside the product. Validity is aware, current and no more than seven days. The assigned reviewer identity must match the pinned key/role and current authenticated human. A valid signed `REJECT` or unresolved `FAIL` / `NOT_RUN` is retained and blocks a positive state; it is **not** discarded as an invalid intake. Neither a positive nor negative decision can be overwritten.

Canonicalization and offline verification remain in `shared_models.qualification_acceptance` / `shared_models.tpm_quote_verification` and the existing `scripts/verify_independent_host_qualification.py`. The extraction of reusable evidence/signature verification preserves the combined CLI's stricter two-positive-review acceptance behavior. Intake contracts live in `shared_models.qualification_workflow`; enabled deployments expose them through their usual API schema.

## Status envelope and failure semantics

The response includes `record` (append-only assurance revision/payload), current resolved `assignees`, `evaluated_at`, `state`, `blockers`, limited `verification`, and explicit dispatch/channel/truth flags. The payload retains policy, approver, channel approval reference, assignments, original metadata, frozen index, separate signed decisions and withdrawal status. State meanings are documented in [guide 68](../bank-environment/68-assigned-operator-qualification-workflow.md#5-interpret-states-narrowly).

A verified scoped external record never sets host-attestation, full-worker-production-clearance or production-execution flags. Read-time expiry/authority checks can turn a previously verified record into BLOCKED. Corrupt hash-linked revisions or blob bytes refuse; no stale positive fallback is served. The export recomputes this status rather than returning a previously persisted green report. JSON attachments/originals use `Cache-Control: no-store`, `nosniff` and safe digest/fixed filenames; the browser uses authenticated downloads, not public anchor URLs.

Typical errors: **401/403** authentication/permission/assignment; **404** unknown or out-of-estate campaign/artifact; **409** revision conflict, immutable/frozen/withdrawn action, changed authority, missing/unqualified originals or integrity failure; **413** wire/artifact/campaign bound; **415** wrong original media type; **422** model, public artifact or signature/scope/time validation. Do not infer rollback solely from a browser abort or a lost response: GET current revision and reconcile before an explicit retry.

Every mutation locks the campaign's existing root row on PostgreSQL, rechecks `expected_revision`, appends a hash-linked revision and chains an audit entry in the **same transaction** as any new blob. Audit failure rolls back blob/revision together. This is application-level append-only/integrity checking, not DB-administrator-proof immutability or a performance/HA/retention certification. No migration or new storage service is introduced.
