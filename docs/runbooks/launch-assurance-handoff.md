# Launch assurance handoff — independent tests, operations, bounded pilot

**Maturity: Preview.** These workflows retain external assertions and explicit
gates. They are not a delivered independent assessment, staffed service,
certification, bank deployment qualification or contractual SLA.

## Install / upgrade / rollback boundary

- Follow [operator install/upgrade/recover](operator-install-upgrade-recover.md)
  and [evidence assurance upgrade](evidence-assurance-upgrade.md). Existing
  migration **0104** remains required; launch records reuse the existing
  assurance revisions/blob tables and require no new migration.
- Rebuild/deploy API and frontend together with the shared models package.
  Existing worker/parser/profile dependencies remain unchanged. No collector,
  production private key, seed owner, default customer or fake report is added.
- Release inventory includes this runbook, the three detailed bank notes,
  external-signing helper and editable launch templates. Inventory signatures
  describe package integrity, not independent security assurance.
- Test with separate estate A, estate B and platform scope. Confirm foreign IDs
  return not found, trust/review permissions cannot be manufactured by assignment,
  raw evidence is separately restricted and stale revisions return 409.
- Preserve all retained revisions/blobs during rollback. An older API/console may
  not expose new record kinds; that is not grounds to delete history or mark
  gates complete. Back up under the existing approved retention/residency policy.

## Preflight: actual people and evidence

The customer must supply the following; missing inputs are launch blockers:

| Requirement | Required external decision/evidence |
|---|---|
| Independent assessor | Procurement/contract, competence and independence due diligence, agreed scope/ROE and authenticated public key. |
| Independent security result | Actual after-approval tests, retained original report, externally signed manifest, tracked findings and after-fix retests. |
| Operating people | Real active primary/backup IDs for all nine duties, staffed service window and escalation reachability. |
| Procedures/exercises | Classified retained procedure bytes, separate owner acknowledgements, fresh actual exercise evidence and different-human review. |
| Site capability | Witnessed install/upgrade/recovery, measured performance/capacity and failure response on the intended deployment; legal approval before an SLA. |
| Pilot | Customer charter, one application/release, source+SBOM+deployment evidence, approved endpoint receipts, hardware metadata, vendor evidence and a current condition proof. |
| Acceptance | Technical owner review, different customer owner acceptance, exclusions and scoped evidence fingerprint. |

No production identity, provider or customer evidence is invented by the software.
Templates deliberately contain placeholders and NOT_TESTED case outcomes.

## Operator sequence

1. Read the detailed [security procurement/intake and retest procedure](../bank-environment/56-independent-security-assurance.md).
   Upload classified bounded redacted blobs. Propose scope as a security manager,
   review it as a different trust-authorized human, then commission the actual work.
2. Give the assessor the canonical manifest preparation instructions. The helper
   `scripts/independent_report.py` accepts public report JSON and optionally a
   detached externally produced signature; it never accesses a private key.
   Verify external key identity out of band. Import the signed report envelope.
3. Assign each finding to a real owner with an approved replacement release and
   deployment checksum. Separate plan approval from owner completion reporting;
   obtain a later externally signed retest. Missing/inconclusive evidence stays open.
4. Use the [nine-duty ownership procedure](../bank-environment/57-operational-ownership-and-demonstrated-service.md).
   Record current owner and backup acknowledgements under their individual human
   sessions, perform real site exercises and retain their limitations. A different
   reviewer reviews PASSED assertions. A signed statement is not a measured SLA.
5. Follow the [one-application pilot procedure](../bank-environment/58-focused-payments-customer-pilot.md).
   Build the independent expected-target register before viewing discoveries.
   Retain unresolved generic coverage rows rather than claiming all targets observed.
6. Read current gates, resolve blockers, obtain technical-owner review and different
   customer-owner acceptance. Archive the scoped evidence pack. Re-read readiness
   at handover: old acceptance remains historical when evidence/authority changes.

## API quick map

Prefix `/api/v1/assurance/launch`; all POST/PUT actions below return immutable
record receipts (201). GETs compute current status. Existing
`/api/v1/assurance/records?kind=...` and `/records/{kind}/{id}` provide paginated
exact-estate history; includes all revisions, not just current records.

| Endpoint | Intent / counter |
|---|---|
| `POST /engagements` | New proposed scope; no expected_revision body field. |
| `POST /engagements/{id}/approve` or `/withdraw` | Approval body; engagement revision. |
| `POST /engagements/{id}/reports` | SignedReport; report counter (first expected_revision=0), payload binds current approved engagement revision. |
| `GET /engagements/{id}/status` | Current scoped report and finding blockers; never certified. |
| `POST /findings/{id}/plan`, `/approve`, `/report-complete` | Finding counter; only signed external retest records resolution. |
| `POST /assignments` | Create/replace stable duty subject; assignment counter. |
| `POST /assignments/{id}/acknowledge` | Assignment counter; assigned primary and backup act separately. |
| `POST /assignments/{id}/exercises` | Exercise counter plus exact current assignment_revision. |
| `POST /assignments/{id}/review-exercise` | Exercise counter; different authorized reviewer. |
| `GET /operations` | Nine duty gates, no automatic SLA. |
| `POST /pilots`, `PUT /pilots/{id}` | Pilot counter; replacement resets reviews. |
| `POST /pilots/{id}/technical-review`, `/accept` | Pilot counter; technical then different designated customer owner. |
| `GET /pilots/{id}/status` | Current evidence loop, exclusions, unresolved coverage and acceptance currency. |

New record kinds: `security_engagement`, `security_report`, `security_finding`,
`operating_assignment`, `operating_exercise`, `customer_pilot`. Report signatures
bind normalized typed payloads; report/finding updates are committed together.
Review bodies contain `expected_revision`, `evidence_ref`, `reason`. See live
OpenAPI schemas (`/api/openapi.json`, if documentation is enabled) for all fields.

## Troubleshooting without weakening controls

- **403**: current durable human role/session missing, machine credential used,
  revoked user/session or readonly actor. Obtain correct independently authorized
  access; do not make an API key into a human or grant roles via a duty assignment.
- **404**: wrong selected estate or unavailable referenced evidence/identity.
  Reconfirm the application's exact IDs; do not broaden to a cross-tenant lookup.
- **409 revision conflict**: reload current record/counter and review new evidence.
  Do not auto-retry approval/acceptance with a guessed revision.
- **409 scope/release/sequence mismatch**: compare signed report estate, engagement
  revision, scope checksum, deployment checksum, artifact digest and sequence.
  Recommission/re-sign the correct scope; never patch a signed JSON object.
- **422 signature failure**: check raw 64-byte detached signature, authentic 32-byte
  public key and canonical typed bytes. No pretty-printing, mutation or datetime
  reformatting after signing. Do not disable verification.
- **Incomplete retest**: all tracked findings need explicit current dispositions;
  resolution requires the approved replacement, reported completion, later test
  interval and every linked case PASSED. Ticket closure is not proof.
- **Operating record stale**: a changed procedure/owner requires both new
  acknowledgements and an exercise under that exact assignment; reusing an old
  exercise or review cannot establish currency.
- **Pilot not ready**: inspect `issues`, `unresolved_targets` and the register.
  Generic external-export coverage remains incomplete until a qualified adapter
  exists; direct typed evidence checks are not a fake OBSERVED denominator.
- **Previously accepted pilot no longer current**: preserve history, fix the new
  blocker, replace changed manifest where needed, and repeat the technical and
  customer reviews. Do not suppress the blocker for a presentation.

## External release acceptance still open

Internal tests exercise synthetic keys, authenticated SQLite workflows and the
console; they cannot establish independent assessor execution, actual bank owners,
site restore/capacity/browser endurance, legal/SLA approval or customer acceptance.
Record these external results only after they happen and retain adverse evidence.
See [editable templates](../templates/launch/README.md).


## Retained engineering checks

The [2026-10-22 engineering record](../readiness-evidence/launch-engineering-2026-10-22.md)
separates the passing changed-code/frontend checks from two reproduced broader
legacy integration failures. It is not an external security or customer report.
