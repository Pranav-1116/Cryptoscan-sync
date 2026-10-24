# Inspecting a post-review source rescan

## What changed in the existing product

The existing CBOM → Historical import review panel now includes **Inspect
post-review rescan evidence**. Previously, a reconciled mixed history disappeared
from the pending-system list, leaving no corresponding rescan inspection in that
workflow. A separate bounded retained-history list now makes those systems
accessible without treating their disposition as fresh coverage.

This is a **read-only inspection**, not another declaration/approval mechanism.
It reuses durable scan jobs, existing source-file receipts, the existing stored
content/chain/manifest verifier, tenant/estate selection and residency admission.
No collector, dashboard, service, migration or cache was introduced. It does not
change existing discovery methods or automatically produce new scans.

## Operator example

1. Complete the [controlled mixed-source review](controlled-historical-cbom.md).
   Retained histories remain partial; clean posture grades remain blocked.
2. Run an authorized **local-source** scan through the existing scan workflow,
   for the selected system/configured target and branch. Wait for durable job
   completion. Copy that job's ID from the existing job history.
3. Open Historical import review → Review retained histories → Inspect rescan
   for the intended system. Supply **Completed source job ID**, then explicitly
   click **Verify scoped rescan evidence**.
4. The server requires:
   - the same exact estate for system, job and scan; NULL/platform records are
     not inherited by a tenant;
   - the selected system and its current configured target/branch, latest scan
     pointer, a completed MANUAL local-source job and valid observation interval;
   - scan start strictly after the immutable retained-history approval, with no
     future timestamps; no inferred/requested Git-commit identity;
   - bounded, unambiguous source-file hashes/parser receipts;
   - actual committed content-hash recomputation, contiguous/predecessor/chain
     validation and exact evidence-ID manifest verification, including tombstones;
   - each committed finding's **hash-verified source path**, not its mutable
     denormalized database path column, in a completed parser receipt.
5. The result displays completion time, counts, integrity and a source-state
   snapshot digest. Changing the job, refreshing history or switching private
   context removes prior proof. A failed/unavailable inspection removes the old
   result; contradictory/mismatched HTTP200 payloads are refused too. Nothing is
   automatically retried or written.

Requests use existing authenticated estate selection:

```text
GET /api/v1/cbom/retained-histories?page=1&page_size=50
GET /api/v1/cbom/system/{system_id}/rescan-inspection?job_id={job_id}
```

Page size is at most 200; inspection is capped at 1,000 file receipts and 10,000
committed evidence rows. It reads at most 10,001 rows to detect overflow and
refuses a verdict on the truncated prefix. Foreign/missing resources return 404;
contradictory, incomplete or unverified proof returns 409. Current read-only users
can inspect; this route does not grant write or approval authority.

## What a successful inspection does NOT prove

`VERIFIED_SCOPED_RESCAN` means the current database-backed job/file receipts and
stored scan commitments passed these checks. `VERIFIED_EMPTY_SCOPED_RESCAN`
means a valid empty committed scope, **not** proof that crypto is absent.

Every result explicitly returns false for:

```text
clears_partial_history
bank_approved
absence_proven
whole_system_coverage_verified
freshness_slo_qualified
```

A parser receipt covers particular primary files, not every expected repository,
archive, deployment, runtime channel, cloud account, protocol or bank system.
Matching before/after file hashes are not an atomic mutable-filesystem snapshot.
This check verifies **new scan content**, not the retained historical content or
all facts asserted by the detector. Source statistics remain current SQL receipts,
not an externally signed source attestation. Storage verification does not resist
an administrator who can rewrite all database commitments.

There is intentionally **no partial-history clearance endpoint**. A complete,
independently validated denominator, explicit source/old-history correspondence,
remediation evidence and policy-controlled reassessment are still required.
Operator declarations or a two-file parser demonstration cannot substitute for
those. The inspection is not a persistent approval, signed certificate, service
freshness SLO or guarantee against changes after the read.

NBOM, CBOM, TechBOM, HBOM, vendor VBOM and SBOM remain six distinct outputs. This
increment improves the source-evidence part of the original45; it does not
requalify all six or close the [remaining requirements](bank-original45-engineering-gaps.md).
See [execution evidence](../readiness-evidence/scoped-rescan-2026-10-24.md).
