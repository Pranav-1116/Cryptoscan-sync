# 51_REARCHITECTING_CORE_PLATFORM.md
## ZELNX CryptoScan — Core Platform Rearchitecture Audit (51)

**Created:** 2026-10-12 (round 38)
**Scope:** the 51 rearchitecture — evidence as the single source of
truth, cryptographic facts and crypto assets as projections over the
evidence store, one writer. Progress to date is tracked in
`audit_reports/00_ROUND_STATUS.md` rows citing 51: the fact read model
(round 31), the fact store write side with `FactRepository.rebuild`
and migration 0085 (round 35), the observed-confidence read path with
migration 0086 and store==live equivalence (round 37). This file was
created in round 38 to carry the reconciliation addendum below.

---


## Round 38 addendum (2026-10-12) — drift made measurable

The full rearchitecture stays a multi-week cutover and is not claimed
done. This round delivers its prerequisite measurement:
`db/fact_projection.reconcile_assets_with_facts` + admin
`GET /facts/reconciliation` measure drift between the fused
`crypto_assets` write path and the evidence-derived fact store. Both
sides are indexed by the coarse drift key (algorithm, file path); the
parameter fields (key size / purpose / mode) are compared across sides
as value sets (a file can legitimately hold several parameterisations
of one algorithm); identities on only one side are listed separately.
The report judges nothing — evidence is the truth per this report —
it counts: `identities_matched`, `field_disagreements`,
`assets_without_facts`, `facts_without_assets`, and a single
`in_sync` boolean. The single-writer cutover needs this at zero before
the fused write path can be removed. Tests:
`services/api/tests/unit/test_fact_reconciliation.py` (pure
reconciliation semantics + live-drift endpoint, including the case
where a rebuild turns "asset without fact" into a parameter
disagreement). REMAINS OPEN: retiring the fused write path itself.
