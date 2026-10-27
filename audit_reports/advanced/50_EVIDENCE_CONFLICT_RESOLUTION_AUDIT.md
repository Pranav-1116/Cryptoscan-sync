
## Round 27 update (2026-10-10) — conflict system re-verified end to end

* **Conflict detection at query time (#1/#2 partial) — confirmed shipped**
  (round 15, re-verified): the deterministic detector classifies
  ALGORITHM/PARAMETER/STATUS mismatches over same-site observations,
  surfaced at `GET /findings/conflicts` (within-scan) and
  `?compare_scan_id=` (scan-vs-scan). Retracted evidence is excluded.
* **Authority-based resolution (#4) — confirmed shipped** (round 19):
  every conflict carries an `authority` annotation from the 6-tier
  hierarchy — best tier present, which observers hold it, and whether
  the preference is decisive (single highest tier) or a tie needing a
  human/policy decision.
* **Auto-resolution (#5) — deliberately not built, by design.** The
  shipped model annotates and never overrides; resolution stays a
  human/policy decision. This matches this report's own escalation
  guidance and is documented in both module docstrings.
* **Still open:** persisted `EvidenceConflict` rows (conflicts are
  computed on demand, not stored as first-class records), and conflict
  notifications/alerting (needs the persisted-conflict feed first).
  Both are product-scoped, tracked in 00_ROUND_STATUS.
