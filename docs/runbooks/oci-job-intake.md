# Operator runbook — authorized offline OCI job intake

This adds authenticated platform intake to the [standalone OCI runbook](offline-oci-image-evidence.md). Read [Guide 83](../bank-environment/83-tenant-scoped-oci-job-intake.md) and [API contracts](../api-reference/oci-job-intake.md). Production admission remains closed; local engineering success is not bank acceptance.

## 1. Agree and register the target

Prepare the existing `OciTarget`: exact local OCI layout, immutable manifest digest, selected metadata paths, actual registered system ID/environment and an approved current time window. No credentials/private keys, broad CIDR, registry tag, Docker socket, arbitrary command or URL is accepted.

Using the bank's existing authenticated UI/API client, `POST /api/v1/collection/oci/targets` with that target. Do not paste session tokens into chat, put them in committed scripts or disable TLS/authentication for this workflow.

Retain the returned server `subject_id` and revision. The server UUID is different from the original logical `target_id`. A current human with `assurance.trust` must authorize the registration with its exact revision, public decision reference and reason. Authorization must expire within 24 hours; a future registration cannot authorize distant future execution in advance.

This is permission enforcement, not an independent two-person bank acceptance certificate. Approvers must actually assess scope and expected truth; a supplied reference string is not the review itself.

## 2. Create and hand off a job

`POST /jobs` under the OCI base path with the server target UUID and exact authorized target revision. The response is `READY`, not an executed scan.

`POST /jobs/{job-id}/handoff` with the expected job revision. The response is `AWAITING_EVIDENCE`, including `payload.capture_binding` and `payload.binding_sha256`. Export only the original binding object to an approved local file. Retain the original target and independently check the authorization's `target_sha256`.

The binding contains a public random challenge, job/target/revision commitments and a bounded server-issued window. It is safe public context, not a credential, hardware attestation, signature or proof that a collector executed honestly.

## 3. Capture on the approved offline Linux account

Use an ordinary Linux user and approved local image bytes. Existing no-follow reads and parser budgets apply; no image is pulled/extracted/executed.

```bash
python scripts/capture_oci_job_evidence.py \
  --target /approved/plans/payments-image-target.json \
  --binding /approved/plans/payments-image-binding.json \
  --approved-target-sha256 "$AUTHORIZED_CANONICAL_TARGET_SHA256" \
  --approved-binding-sha256 "$AUTHENTICATED_HANDOFF_BINDING_SHA256" \
  --output /approved/returns/payments-image-job-return.json
```

Use approved commitments obtained through the authenticated review/handoff process, not hashes self-selected from untrusted output. Both commitments and the active binding window are checked before image I/O. Output uses the standalone CLI's exclusive no-follow 0600 file creation. Existing outputs are never overwritten.

- Exit 0: all **selected** inputs parsed; not complete image coverage.
- Exit 2: original partial/failed metadata return retained; no absence claim.
- Exit 64: refused binding/scope/blob/format/budget/output. Do not reset/forge a binding to turn refusal into acceptance.

Do not reuse a standalone unbound return as a job-bound capture. Its bytes may be useful historical metadata but it was not captured under this handoff. If the window expires or scope changes, have the authorized operator register/re-authorize a new revision and create its new job. Do not blindly resubmit under a different job.

## 4. Review and submit original return

Review the original `OciJobReturn`, expected selected-file truth, source commitments and all receipts. Agree `digest(capture.evidence)` using the existing canonical typed-model function; `sha256sum` of pretty JSON is different.

`POST /jobs/{job-id}/intake` with:

- exact current expected job revision (normally 2);
- original complete `capture` object from the CLI;
- `expected_evidence_sha256` for its reviewed original evidence.

The server rechecks current target authorization, scope revision, system/environment, window, exact original handoff and server-relative finish time. It commits consumption/evidence/terminal job/audit together. An accepted response does not prove trusted producer clock, authenticity, runtime use or bank completeness.

For an ambiguous network failure, **read the job first**. If already terminal, inspect the retained evidence and its digest instead of repeating intake. If still awaiting evidence, review server/error state before any retry. A duplicated accepted return yields conflict, not another evidence record. Audit/storage failure rolls back the transaction; there is no automatic acceptance bypass.

## 5. Inspect, materialize, withdraw

`GET /jobs/{id}/evidence` returns the original bound return. `GET /jobs/{id}/projections` materializes all six internal views from that stored evidence. Neither accesses the image layout, scans an endpoint or writes operational graph edges. Images can be offline/unavailable after capture without changing the historical view.

Cancellation is available while pending, even after revocation. It is a metadata workflow cancellation, not a claim that the server killed an image process—it never started one. Revocation/update/expiry prevents new intake; already committed historical evidence remains readable with its original provenance and limitations.

Partial and failed terminal jobs remain partial and failed. Do not delete failed inputs, manufacture empty complete BOMs, infer HSM/crypto use from package names, or convert declared ports/vendor/base-image labels into live observations.

## Release gates

The [validation record](../readiness-evidence/oci-job-intake-2026-10-26.md) covers owned synthetic image returns, actual sessions/SQL, PostgreSQL row locks/races and selected regressions. Independent customer image truth, malicious-parser/isolation assessment, actual Windows/container/HSM/customer application evidence, authoritative estate completeness and production/bank acceptance remain separate gates. No private keys or credentials are requested for those public return packets.
