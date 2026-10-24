# Controlled historical CBOM decisions

This increment extends the **existing** CBOM import/review screen. It does not
add a collector, dashboard, service, database migration or bank-acceptance badge.
It closes two previously unsupported operator paths: unassigned historical
records and histories containing both imported declarations and scanner links.

## Unassigned records: responsibility is not proof

1. Sign in with a current durable human session, select the correct estate, open
   CBOM → Historical import review → Review unassigned records.
2. Inspect a record. Supply the destination system ID from the existing system
   inventory, a rationale of 20–500 characters and a 3–500-character evidence
   reference. Do not paste secrets or raw findings into these fields.
3. Confirm **Assign declared responsibility**. The server checks the exact
   estate (tenant A does not inherit NULL/platform records), source snapshot,
   current authority and absence of existing associations inside the transaction.
4. Retain the audit receipt. The resulting source basis is
   `OPERATOR_DECLARED_ASSIGNMENT_NOT_SCAN_OR_APPROVAL`. The record still requires
   source reconciliation; export/assessment blocks do not disappear.

Ownership changed while reviewing? Refresh and make a new intentional decision.
A repeated assignment cannot silently become another association.

## Mixed-source records: retain evidence, use two actual humans

1. Reimport the original CBOM through the existing upload form. This creates
   replacement **declarations**, not scan results. Every historical identity
   (algorithm, purpose, path and line) must have replacement coverage.
2. Select the system's historical review. Fast/automatic reconciliation stays
   disabled when scanner evidence is linked. Load the controlled mixed review.
3. Review the original evidence in the existing evidence/inventory workflows,
   the replacement fingerprint and source snapshot. Submit a rationale and
   reference. The immutable proposal records the authenticated human ID.
4. A **different current CISO or superadministrator** signs in, loads the case,
   reviews its immutable digest, proposer, rationale/reference and current source
   snapshot, and explicitly approves. A second account/profile for the same
   durable human ID is not separation of duties. This application check is not
   external independence or bank acceptance.
5. Approval atomically appends audit/revision records and detaches selected
   system associations. Original CryptoAsset rows, raw reported confidence,
   CryptoAssetEvidence links and EvidenceRecord content are not deleted or
   upgraded. Shared records stay pending until the last associated system has
   been reviewed.

Submission/assignment requires current durable `assurance.manage` authority
(superadministrator, CISO or security analyst); approval requires
`assurance.trust` (superadministrator/CISO). API keys, body-provided approvers,
revoked/downgraded sessions and self-approval do not supply human authority.
Existing estate/residency admission applies. These are estate-level controls,
not a newly introduced business-unit approval policy.

## Why the result stays partial

Excluded mixed histories receive `RETAINED_MIXED_EVIDENCE`, bound to the immutable
approved revision and its explicit asset/count map. Native exports disclose:

```text
cryptoscan:retained_mixed_evidence_assets = <count>
cryptoscan:inventory_completeness = PARTIAL_RETAINED_MIXED_EVIDENCE
```

System/portfolio clean posture assessments are refused. Reposting an exported
partial document to the inline assessment route is also refused. Fresh evidence,
evidence mutation, a same-count link swap or an invalid/unrelated review marker
reopens unresolved history rather than hiding it. Bounded source, replacement,
evidence and link locks protect decisions on PostgreSQL. This relies on normal
application/FK transactions, not resistance to a database administrator.

**There is no automatic “rescan clears partialness” endpoint in this increment.**
A retained count remains a conservative fence. A subsequent policy-controlled,
verified rescan/reassessment workflow and independent deployment qualification
are still required. Link preservation alone does not validate the scanner's
cryptographic evidence chain or establish completeness.

## API shape and failure handling

All paths below have prefix `/api/v1/cbom`; use existing session authentication
and estate selection. GETs are reads; nothing writes automatically.

| Path | Purpose |
|---|---|
| GET `/legacy-imports/unassigned?page=1&page_size=50` | Exact-estate bounded inventory; maximum page size 200 |
| GET `/legacy-assets/{id}/review` | Current source/evidence/association snapshot |
| POST `/legacy-assets/{id}/assign` | `expected_snapshot_sha256`, `system_id`, `reason`, `evidence_ref` |
| GET `/system/{id}/mixed-review` | Latest append-only case or null |
| POST `/system/{id}/mixed-review` | Source snapshot, `replacement_document_sha256`, reason/reference |
| POST `/system/{id}/mixed-review/approve` | `expected_case_sha256`, reason/reference; different current human |

Reviews are bounded to 2,000 assets/replacements and 10,000 evidence links.
Oversized histories fail closed for controlled investigation, not partial
approval. A 409 requires fresh review; authorization failures do not change
inventory. A 503/lost response is **outcome unconfirmed**: inspect inventory and
audit before submitting again. The UI clears reusable decision state and never
automatically retries. Session/estate/tab-resume changes discard drafts and fence
late responses; clearing a browser context is not rollback of a server write.

See [execution evidence](../readiness-evidence/controlled-history-2026-10-24.md)
and the still-open [original45 requirements](bank-original45-engineering-gaps.md).
