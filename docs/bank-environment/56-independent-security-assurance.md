# 5.1 — Obtain independent security assurance, not a certification badge

## What is implemented, and what is not

The Preview **Launch readiness** console (`/launch-readiness`) and
`/api/v1/assurance/launch` API retain procurement scope, customer review of the
assessor's independence declaration, externally signed reports, findings,
approved changes, owner-reported work and later assessor retests. They reuse the
exact-estate, residency-admitted, append-only assurance store. No new live scan,
URL fetch, parser execution, private-key handling or external procurement is
performed by this workflow.

**No independent firm has been appointed by this implementation. No real
assessment, accreditation or certification is claimed.** A cloud, HSM or data
centre certificate applies only to its stated object and scope; it does not
certify CryproScan. An Ed25519 signature authenticates the report's origin and
integrity against a customer-approved public key, not assessor competence or
true independence. A different authorized human's approval retains their review
assertion; it cannot replace procurement/legal due diligence.

## Before issuing the statement of work

The bank sponsor and security procurement owner must obtain and retain:

1. A named external provider and lead tester; relevant application, multi-tenant,
   container and parser experience; references; independence/conflicts declaration;
   subcontractor and tool disclosure; liability, confidentiality and data-handling
   terms. Ask whether the provider implemented or operates the assessed controls.
2. A precise release/artifact digest, deployment-manifest bytes, environment,
   architecture, allowed data classes, two independent test estates plus the
   platform scope, role/principal matrix, parser/container boundaries and source
   commit/image inventory. Production safety approvals are separate.
3. Rules of engagement: exact endpoints, network ranges, permitted methods and
   rate/resource budgets, maintenance windows, prohibited destructive actions,
   emergency contact/stop, evidence residency, encryption, redaction, retention
   and deletion obligations. A report-intake API is **not** a collection permit.
4. Required negative tests, expected outcomes, reproducible steps, raw evidence
   locations, severity method, reporting time, remediation support and included
   retest windows. Agree what “not tested” and inconclusive mean.
5. Out-of-band public-key identity verification. Obtain the assessor's **public**
   Ed25519 key over an authenticated independent channel. Never paste a private
   key into the API, browser, repository or this documentation.

Retain redacted scoped evidence in `/api/v1/assurance/evidence-blobs` (bounded
raw bytes; 1 MiB each), or references to the separately governed assessor evidence
repository. Sensitive full reports must be classified before upload; ordinary
assurance record readers can see metadata, case evidence references and finding
text. Raw blob downloads have a separate elevated permission. These blobs are
not a replacement for a bank-approved large-file evidence vault.

## Minimum mandatory negative scope

Every engagement must contain all 13 case IDs in their specified area. The
assessor should expand them with estate-specific substeps and expected outcomes;
passing one example is not broad category coverage.

| Area | Mandatory case ID | Required practical investigation |
|---|---|---|
| Tenant/estate isolation | `tenant.cross_read` | Tenant A cannot read B's scans, exports, reports, artifacts, jobs, cursors or raw evidence, including guessed identifiers. |
| Tenant/estate isolation | `tenant.cross_write` | A cannot attach B's SBOM/deployment, approve B's change, import B's signed report, or mutate B's scope. |
| Tenant/estate isolation | `tenant.null_scope` | Platform/NULL estate is not a wildcard; selecting another estate never exposes platform-owned records. |
| Authentication/authorization | `auth.revoked_session` | Revocation, expiry, deactivation and role removal take effect on the next protected action; legacy/untyped and machine credentials cannot become human approvals. |
| Authentication/authorization | `auth.denied_role` | Scanner/API-key/readonly identities cannot grant trust, acknowledge human ownership, approve their own scope or perform a different-human review. |
| Upload/parser boundaries | `upload.traversal` | Archive traversal, symlinks, absolute paths, deceptive filenames and remote URL/file-path indirection cannot escape the admitted source/evidence root. |
| Upload/parser boundaries | `upload.resource_limits` | Archive expansion, nesting, oversized body, malformed and duplicate-key JSON, CPU/memory/time/output limits fail closed without partial success claims. |
| Upload/parser boundaries | `parser.no_privileged_fallback` | A parser failure cannot fall back into the API/worker privileged process or regain network, credentials or unmounted host files. |
| Secrets/evidence | `evidence.cross_estate_download` | Test raw report/fixture downloads separately from metadata, across estates and roles. |
| Secrets/evidence | `secrets.redaction` | Credentials, tokens, private keys and source secrets are absent from logs, errors, exports and externally retained test artifacts. Test configured exceptions and failures. |
| Supply chain/deployment | `supply.digest_tamper` | Altered release image, dependency lock, SBOM, supplier payload and report bytes are detected; an SBOM hash is not an executable hash. |
| Supply chain/deployment | `supply.untrusted_signature` | Unknown/withdrawn/expired keys, altered signed fields, wrong estate/build and replayed report sequences cannot grant assurance. |
| Supply chain/deployment | `deploy.secret_ca_mounts` | Inspect actual production pins, non-root/isolation settings, secret and CA mounts, SQL/Redis TLS and disabled optional services against the deployed manifest, not merely YAML examples. |

The five areas are `TENANT_ISOLATION`, `AUTHORIZATION`, `UPLOAD_PARSER`,
`SECRETS_EVIDENCE`, `SUPPLY_DEPLOYMENT`. Explicit exclusions are mandatory and
must identify unsupported workflows, environments, data sources and test methods.

## Record flow and authorization

All paths below are relative to `/api/v1/assurance/launch`. Use a current durable
human session and the exact selected estate (`X-Tenant-ID` where appropriate).
Existing controlled-execution residency/profile restrictions remain in force.
Request schemas reject extra fields, naive datetimes and non-finite numbers.
Every mutation uses optimistic `expected_revision`, except a new engagement,
which starts at revision 1 automatically.

1. `POST /engagements`: security manager proposes provider/key, baseline artifact,
   three retained blobs (independence declaration, agreed scope, deployment),
   negative cases, exclusions, environment and expiry. The scope hash also binds
   current estate execution policy and blob checksums. A proposal is not approval.
2. `POST /engagements/{id}/approve`: **different** trust-authorized human reviews
   scope and the external independence assertion. Typical roles are CISO or
   superadmin; the proposer cannot approve their own scope. Store rationale and
   procurement/evidence reference. Protect this role as a trust root.
3. Assessor performs the actual work **after approval**, using separately approved
   tools and rules of engagement. Reports explicitly list every scoped case as
   `PASSED`, `FAILED`, `NOT_TESTED` or `INCONCLUSIVE`; absence is never a pass.
4. Upload the original external report bytes as a blob. Prepare the typed public
   report payload and have the assessor sign its canonical representation outside
   this product. `POST /engagements/{id}/reports` imports the signed envelope.
5. `GET /engagements/{id}/status` recomputes current engagement/report/finding
   blockers. `POST /engagements/{id}/withdraw` removes authority for further imports
   (e.g. compromised key or scope withdrawal) without erasing retained reports.
   To change an approved scope/key, propose and review a new engagement.

See [launch templates](../templates/launch/README.md) and
[operator handoff](../runbooks/launch-assurance-handoff.md). The OpenAPI contract
at `/api/openapi.json` is authoritative for field names.

## Canonical external signing — no production keys generated here

Use the application's installed Python dependencies and the assessor-authored
`AssessmentReport` JSON. The helper validates and normalizes the typed model,
then emits UTF-8 JSON with sorted keys, no insignificant spaces, Unicode preserved
and non-finite numbers forbidden. Datetimes are Pydantic JSON-normalized; signing
pretty-printed input or PDF bytes is **not** signing the canonical manifest.
The manifest contains the original report blob ID and SHA-256.

```bash
python scripts/independent_report.py assessor-report.json --output report.canonical.json
# Give report.canonical.json to the assessor's independently managed Ed25519 signer.
# Obtain a detached raw 64-byte signature in report.signature.bin, then assemble:
python scripts/independent_report.py assessor-report.json \
  --signature-file report.signature.bin --expected-revision 0 --output signed-report.json
```

The helper never accesses a private key, will not overwrite existing outputs,
and rejects duplicate JSON keys and oversized input. Assembly alone does not
verify a signature or establish trust: the API verifies it against the reviewed
engagement key and exact scope/release/report sequence. A signature for an old
scope, wrong report checksum, changed estate or modified case result is refused.

## Findings, change and retest

Every failed case must have a tracked finding. A stable external `finding_ref`
produces a stable engagement-local finding ID; all history remains append-only.
Each subsequent report must explicitly rediscover or give a retest disposition
for **every** prior finding. Unknown and duplicate dispositions are refused.
Maximums are 100 cases, 100 discovered findings/report, 200 tracked findings per
engagement and 200 retests/report; partition and reapprove larger scopes rather
than silently truncating evidence.

For each finding:

1. `POST /findings/{id}/plan`: assign an active accountable User ID, replacement
   artifact, retained replacement deployment-manifest blob, change reference and
   verification criteria. A new proposal invalidates the prior approved plan.
2. `POST /findings/{id}/approve`: authorized reviewer must differ from **both** the
   proposer and remediation owner. The owner cannot certify their own plan.
3. `POST /findings/{id}/report-complete`: only that current owner reports the actual
   post-approval completion time and evidence blob. State is `REPORTED_COMPLETE`,
   never resolved merely because a ticket is closed.
4. The independent assessor tests **after** reported completion, on the exact
   approved replacement artifact and deployment-manifest checksum. A later signed
   report binds the current finding revision hash, all scoped case outcomes and
   an explicit finding disposition. `RESOLVED` requires every linked case passed.
   Wrong release, stale hash, pre-completion interval, missing disposition,
   unsigned result or inconclusive test cannot close the finding.

Resolution is named `RETEST_RECORDED_RESOLVED`, deliberately a report record, not
an invented runtime guarantee. Later PRESENT, INCONCLUSIVE or NOT_TESTED results
restore attention while preserving the previous resolution record. Rediscovery
requires a fresh plan/approval/completion before resolution again. A changed
report release requires a referenced approved and reported replacement change;
a free-form later report cannot silently change the assessed release.

## What the completion gate actually means

`SCOPED_SIGNED_TEST_RECORDS_COMPLETE` means current approved engagement authority,
a report within the configured `report_max_age_seconds` (default 30 days), all
scoped cases passed and no unresolved/untested tracked finding. Expired scope,
changed/stopped estate policy, withdrawn engagement, stale report, failed case
and missing retest remain blockers. The report's exact artifact/deployment and
exclusions remain visible. This state does **not** confer product certification,
regulatory compliance, whole-bank security, provider accreditation or approval
to deploy beyond the agreed test scope.
