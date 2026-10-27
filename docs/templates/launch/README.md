# Editable launch templates — NOT acceptance evidence

These JSON documents are schema-valid starting points, **not usable procurement,
reports, owners, exercise results or pilot acceptance**. Replace every placeholder,
zero checksum, date/time, expected revision and declared exclusion with reviewed
actual values. Dates are examples only. No real provider/key/customer is supplied.
Do not change NOT_TESTED/INCONCLUSIVE to PASSED because a template was generated.

| Template | How to use |
|---|---|
| [engagement.json](engagement.json) | POST `/api/v1/assurance/launch/engagements` after uploading the three retained blobs and obtaining the assessor's authenticated public key. All 13 mandatory cases are included; expand actual procedures. Public-key placeholder deliberately fails the runtime base64/key-length gate. |
| [assessment-report.json](assessment-report.json) | Assessor authors actual results, original-report blob ID/hash, exact approved scope/release and real after-approval test interval. Run the external canonical-signing helper; this is the manifest, not a SignedReport envelope. All case outcomes start NOT_TESTED and there is no signature. |
| [finding-plan.json](finding-plan.json) | POST `/api/v1/assurance/launch/findings/{id}/plan` with actual active owner and replacement/deployment evidence. Different reviewer must approve before completion reporting. |
| [finding-completion.json](finding-completion.json) | Assigned owner POSTs `/api/v1/assurance/launch/findings/{id}/report-complete` with a real post-approval time and retained action evidence. This is not resolution. |
| [operating-assignment.json](operating-assignment.json) | POST `/api/v1/assurance/launch/assignments`. Repeat for all nine duties with real active primary/backup IDs and retained procedure. Each assignment revision resets acknowledgements. |
| [operating-exercise.json](operating-exercise.json) | POST `/api/v1/assurance/launch/assignments/{id}/exercises` only after both humans acknowledge. Exercise counter differs from assignment counter. Outcome starts INCONCLUSIVE, measured recovery is absent. Retain real evidence and mandatory limitations. |
| [payments-pilot.json](payments-pilot.json) | POST `/api/v1/assurance/launch/pilots` only after preparing one application's exact evidence. Expiry, real business value and exclusions need customer agreement. |
| [review.json](review.json) | Approval/acknowledgement/review/acceptance actions. Set the correct record counter and the actual actor's rationale/reference; roles and separation are checked server-side. |

## Independent assessor procurement attachment

Copy into the bank's statement-of-work process and complete each item:

- Sponsor, procurement owner, external organization/lead tester, relevant experience
  and independence/conflicts review, subcontractors and toolchain.
- Exact artifact digest/commit/images, deployment-manifest checksum, architecture,
  environments, tenant/platform test accounts, role/principal matrix and data classes.
- Agreed procedures/expected outcomes for every mandatory case plus additions;
  exclusions, production restrictions and untestable paths.
- Allowed endpoints/methods/windows/resource budgets, stop/incident contacts,
  evidence custody/residency/redaction/retention/deletion and disclosure deadlines.
- Deliverables: original report bytes, case-level outcomes/evidence, stable finding
  references/severity/reproduction, remediation advice, later replacement-release
  retest and canonical manifest with external Ed25519 signature.
- Public-key identity verification channel and compromise/withdrawal process.
- Customer security/procurement/legal review and sign-off, dates and evidence refs.

## Procedure and exercise attachment

For each duty, retain: purpose/scope; actual primary and backup User IDs; honest
staffed service window/timezone; intake/escalation thresholds and contacts;
prerequisites/least-privilege access; step-by-step action and rollback/stop;
retention/classification; review deadline and exercise cadence. The actual exercise
record needs environment/release/data scope, start/end clock, checks and retained
results, failures/limitations, measured recovery/data-loss basis where relevant,
follow-ups and different-human review. Never place live credentials/private keys
in a template or evidence log.

## Pilot charter attachment

Record one application's customer outcome, explicit source/build/release
assertions, separate artifact/SBOM digests, expected-target register, permitted
TLS/SSH endpoints and windows, hardware/vendor evidence provenance, one selected
condition/change/proof loop, success criteria, real customer/technical owners,
support expectations, stop/expiry and exclusions. Review adverse/inconclusive
results and uncovered targets as well as successful evidence. Technical review
and different customer-owner acceptance are separate gated actions.

Detailed procedures: [security](../../bank-environment/56-independent-security-assurance.md),
[operations](../../bank-environment/57-operational-ownership-and-demonstrated-service.md),
[pilot](../../bank-environment/58-focused-payments-customer-pilot.md),
[handoff](../../runbooks/launch-assurance-handoff.md).


## Retest disposition in a later assessor report

Keep every original case result, explicitly disclose untested cases, and use the
next report sequence/expected counter. Each prior finding must either be
rediscovered in `findings` or represented once in `retests`. For example, after
an actual approved/reported replacement and later independent execution:

```json
{
  "finding_id": "<EXISTING_FINDING_ID>",
  "expected_finding_sha256": "<EXACT_CURRENT_FINDING_REVISION_HASH>",
  "outcome": "INCONCLUSIVE",
  "evidence_ref": "REPLACE: actual assessor retest evidence and limitations"
}
```

This is one `retests` item, **not** a complete AssessmentReport. Set RESOLVED only
after the real assessor observes the approved replacement and all associated
cases PASSED. Re-sign the entire normalized report; do not reuse an old signature.
