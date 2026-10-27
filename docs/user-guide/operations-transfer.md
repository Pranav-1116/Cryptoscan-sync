# Operations: air-gapped scan transfer and the 1.0 → 1.1 reissue

The cross-instance transfer format moved from **1.0** to **1.1** (see
`services/evidence/evidence/pack/scan_transfer.py`). Version 1.1 carries
stable evidence ids and verifies stored content, chain linkage, positions,
predecessors and the scan manifest on import; the importer **rejects 1.0
payloads** rather than certifying them from a recomputed transport digest —
a 1.0 payload only proves its own transport hash, not that the evidence
inside it is what the exporting instance committed to.

This page is the operator-controlled migration path. Nothing here rewrites
history on either instance.

## What a 1.0 payload is

- `transfer_version` is `"1.0"`
- records have no `evidence_id`
- verification covered the payload digest only

Attempting `POST /api/v1/scans/import` with one returns **400** with
`unsupported transfer_version: '1.0'`. This is deliberate: accepting a 1.0
payload by recomputing its digest would certify content that was never
content-committed.

## Reissue path (per scan, operator-controlled)

1. **On the exporting instance** (the one that produced the 1.0 payload):
   re-export the scan with current code:
   `GET /api/v1/scans/{scan_id}/transfer`.
   The new payload is version 1.1: every record carries its stable
   `evidence_id`, and the digests commit to the stored content.
2. **Carry it across the boundary** exactly as before (one-way media, signed
   channel — the file's handling does not change).
3. **On the importing instance**: `POST /api/v1/scans/import`.
   - If the scan was already imported from the 1.0 era, the import is
     idempotent and reports `{"imported": false, "reason":
     "scan_already_present"}`. The pre-existing rows are **not** overwritten.
   - To replace a legacy import, the operator deletes the previously imported
     scan **explicitly** (it is an audited, deliberate act) and imports the
     1.1 payload. The deletion is visible in the audit log; the reimport
     carries fresh verification.

## If the source instance is gone

A 1.0 payload whose exporting instance no longer exists cannot be upgraded:
there is no way to prove its records match what that instance committed.
The honest options are:

- keep the 1.0 file as **archival material only** (never re-import it), or
- re-scan the original target with a current instance and transfer the new
  scan as 1.1.

## Import refusals are controlled, never crashes

Malformed sections (`scan`/`digests`/`records` of the wrong shape, missing
digests, non-numeric counts, unsupported versions) all answer **400** with
the verifier's reason list. Tampered payloads (modified after export) answer
**400** with the digest mismatch. A payload that verifies but whose rows
contain raw, non-transferable finding fields is refused before import — see
the evidence confidentiality notes in
[the production gap handoff](../PRODUCTION-GAP-HANDOFF-2026-10-08.md).
