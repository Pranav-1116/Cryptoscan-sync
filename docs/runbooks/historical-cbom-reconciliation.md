# Operate historical CBOM reconciliation

**Scope:** the existing CBOM import/review workflow after migration 0107. This is an
operator procedure, not deployment authorization. See the [implemented contract](../operations/historical-cbom-reconciliation.md).

## Before rollout

1. Obtain normal change approval, retain a verified backup and verify the **whole
   existing audit chain** with the authorized audit tooling. A historical fork,
   hash mismatch or missing evidence stops rollout; preserve the originals and
   investigate. The advisory lock does not repair history.
2. Stop or drain old API, worker and collector versions. Advisory locks require
   every application audit writer to cooperate; old scanners can overwrite import
   metadata. Do not mix old and new writers during the transition.
3. Apply the [0107 procedure](cbom-0107-upgrade.md) if behind. This increment adds no
   migration: expected schema head remains 0107. Use the matching API, workers and
   compiled frontend. Supported audit concurrency here is PostgreSQL **READ COMMITTED**;
   retain the normal engine's finite statement timeout. SQLite is not qualified
   for concurrent audit appends.
4. Verify real authentication, tenant membership, writer/read roles, CSRF/session
   protections and authorized HTTPS access in the intended deployment. The retained
   browser evidence used disposable local development API settings, not these approvals.
5. Read coverage and historical-review counts without writing. Unexpected/missing
   counts or unavailable review is **not clearance**. Do not use ad-hoc SQL to set
   all confidences LOW, stamp scans, remove evidence links or rewrite findings.

## One system at a time

1. On **CBOM → Historical import review**, open the pending system. Read the linked
   evidence count and original reported confidence. No genuine observations can
   be inferred merely from an old HIGH/CURRENT label.
2. Locate and review the original document through the organization's approved
   evidence process. If unavailable, do not invent a replacement fingerprint or
   claim the old content was recovered.
3. Use the existing import form to import the reviewed replacement under the same
   tenant-local system name. This persists separate LOW-confidence declarations;
   absent components are not automatically retired.
4. Refresh historical review. Compare the replacement fingerprint to the committed
   import receipt; review every identity and declared parameter/context change.
   Enter an attributable rationale without credentials/key material. Acknowledge
   that reconciliation is not a scan or approval, then explicitly submit once.
5. Retain the committed audit receipt. Reload inventory, review, coverage and the
   native system export. Verify the corresponding audit action and source/replacement
   hashes through authorized audit tools. Original stored rows/labels remain; current
   projections must not regain fake CURRENT coverage.
6. If shared with another system, only this system's associations are detached.
   Review the other system separately; do not globally archive its rows.

## Refusals and uncertain outcomes

| Result | Operator action |
|---|---|
| 403 | Stop. Obtain the appropriate existing authorization; do not bypass roles. |
| 404 | Check current estate and authorized system ID; do not switch tenant headers to probe another estate. |
| 409 / changed snapshot | Reload and review again. A concurrent request may already have committed. No automatic replay. |
| 409 / linked evidence | Preserve finding data, signatures, hashes and links. Escalate to controlled mixed-source investigation with original scanner evidence; this flow will not detach those rows. |
| 409 / incomplete replacement | Review missing identities and source material. Do not replace a large historical inventory with a convenient partial document. |
| 413 | Review exceeds the bounded supported profile. Arrange controlled operator reconciliation; do not raise limits blindly or treat a page as the whole source. |
| 503, timeout, lost response, context switch | Outcome unconfirmed. Reconcile current inventory **and audit** before another intentional write. UI clearing is not server rollback. |
| Unassigned historical records | Controlled investigation is required. They still block current portfolio export; the per-system flow cannot automatically resolve them. |
| Old archive gains evidence | It becomes pending for current export again. Investigate; the old archival marker is not proof that evidence cannot exist. |

## Rollback / stop

Stop writes on unexpected coverage, source mutation, audit verification failure or
cross-estate exposure. Preserve logs and retained evidence. Do not blindly deploy an
older reader: it does not understand archive/source projections and may resurrect
old HIGH/CURRENT claims. Remain in controlled maintenance/read-only mode pending a
reviewed forward fix or approved backup recovery. There is no automatic undo that
rewrites committed evidence or deletes the audit decision.

## Post-change qualification still needed

Exercise intended production settings and providers, real mixed histories,
security/privilege/residency, representative failure/recovery/capacity, independent
accessibility/Arabic and bank acceptance. The distinct NBOM, CBOM, TechBOM, HBOM,
VBOM and SBOM sources require their own acceptance evidence. No customer rollout,
staffing, SLA, commercial claim or original-question acceptance is granted by this runbook.
