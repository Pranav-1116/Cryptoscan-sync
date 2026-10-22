# 3.3 — Expected-estate coverage ledger

The new register exists independently of discovered assets/findings. An empty
scan can no longer shrink the expected denominator. Each version records scope,
register owner, `UNKNOWN`/`PARTIAL`/`OWNER_ATTESTED_COMPLETE`, evidence for that
assertion, and up to 1,000 unique expected collection targets.

Each target has a stable target key, exact optional existing system ID, owner
reference, kind (SOURCE/DEPLOYMENT/ENDPOINT/HARDWARE/SUPPLIER), source class,
opaque target reference, expected method/permission and freshness duration.
A source method cannot be declared as deployment coverage; SSH cannot establish
source/hardware coverage. Duplicate target IDs or duplicate kind/ref/method
entries are rejected rather than inflate denominators.

## Practical register entry

`POST /api/v1/assurance/registers`:

```json
{
  "expected_revision": 0,
  "scope_description": "Payments pilot; excludes subsidiaries and unregistered applications",
  "register_owner": "Payments inventory custodian",
  "completeness": "PARTIAL",
  "completeness_evidence_ref": "inventory-review/payments-pilot-17",
  "targets": [{
    "target_id": "payments-source",
    "owner_ref": "payments-domain-owner",
    "kind": "SOURCE",
    "source_class": "wrappers_config",
    "target_ref": "/approved/payments-source",
    "method": "LOCAL_SOURCE",
    "permission_ref": "approved-change/payments-17",
    "freshness_seconds": 86400
  }]
}
```

This example is a shape, not authorization to read that path or an assertion that
it exists. The register never fetches a target. Use the returned `subject_id` on
`GET /registers/{id}/coverage`. Register collection targets separately for source,
deployment and endpoints when they require different methods/permissions.

## Accounting and freshness

Every registered target is exactly one of **OBSERVED, STALE, BLOCKED, UNSUPPORTED,
NOT_ATTEMPTED**. Totals reconcile to the register denominator and are split by
kind. The response carries last attempted/successful time, expiry, underlying
receipt and whether collection completeness is known.

`PUT /registers/{id}/observations/{target_id}` records either:

- `RECEIPT`: exact-owner SQL job, matching source target or exact SSH endpoint and
  expected host-key/KEX phases. A completed source job additionally needs a
  completed exact-target Scan and parsed source-file receipts; an empty or legacy
  completed row alone is not fresh source evidence. SSH success requires the
  actual requested facts. Source collection completeness stays unknown rather
  than asserting the whole repository/register was processed.
- `BLOCKED`/`UNSUPPORTED`: explicit operator declaration, reason and evidence
  reference, not a fabricated successful collection. `reported_at` timestamps the
  declaration; it does **not** invent `last_attempted_at`. Last actual attempt/
  success times remain null or retain the previous SQL receipt. The `assertion`
  field distinguishes declarations from SQL receipts.

Re-submitting an old successful receipt cannot refresh its expiry: success time
comes from the stored scan/phase, not this HTTP request. Foreign/NULL estate IDs,
a source receipt for another target, absent required SSH phases, future-dated
success and older out-of-order attempts are rejected. A changed target/method/
permission/owner version invalidates old coverage by target-content hash.

External export-to-target coverage and independently verified deployment mapping
are **not inferred** from a supplier document or artifact name. Such targets stay
explicitly unattempted/unsupported/blocked until a qualified binding exists.

## Denominator example

If a customer's authoritative inventory really contains 500 applications, report
that application denominator separately from collection-target counts:

```text
Registered applications:                500 (customer inventory assertion)
Fresh source targets:                   420 / 500
No current source:                       80 / 500
Independently verified deployment maps: 300 / 500, ONLY if actual evidence exists
Whole-bank register completeness:       unknown/partial/owner-attested
```

Those numbers are an illustration, **not this repository's measured result**.
The ledger reports actual registered targets by kind, not a made-up 500-app
inventory. `whole_bank_verified` is always false: even an owner-attested complete
register is not independently proven to represent the whole bank.

See the [upgrade runbook](../runbooks/evidence-assurance-upgrade.md).


## Quality increment: validate source proof at intake and current read

The first quality increment after `69faec96` removes a false-coverage path:
a nonempty receipt value alone can no longer establish OBSERVED source evidence.
Eligible source proof needs a bounded list (at most 1,000) of unambiguous relative
primary-file identities, valid lowercase SHA-256 and typed parser outcomes, with
at least one actual completed parser. Job/scan/target identity and completed
nonfuture intervals must agree. Submission time cannot fill missing execution times.

Current source coverage reads recheck the exact-estate SQL job/scan evidence with
batched lookups. Invalid/missing/changed backing proof produces **409**, including
a dependent operator summary, rather than false green counts or a fabricated
empty success. Original immutable coverage revisions and hashes remain unchanged.
Read history and obtain an actual valid current observation; never repair a green
status by editing old receipts or resetting job states. Partial primary-file
observation still leaves `collection_complete` unknown and does not prove whole
source/bank coverage or runtime/deployment truth.

See [implementation status](../product-improvement/IMPLEMENTATION-STATUS.md) and
[actual local validation](../readiness-evidence/quality-increment-2026-10-22.md).
This is source-proof hardening, not a new collector, schema migration or bank-site
acceptance. Historical observations without eligible backing evidence are not
silently grandfathered into current qualified coverage.
