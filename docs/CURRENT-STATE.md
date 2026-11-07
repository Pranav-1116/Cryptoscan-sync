<!-- GENERATED FILE — do not edit by hand.
     Regenerate: .venv/bin/python scripts/gen_current_state.py --write
     Enforced byte-identical by scripts/tests/test_current_state_doc.py. -->

# Current state — generated from the tree

This is the repository's **one current-status document**. It exists because status
claims had scattered and drifted (a source-review date read as the present, three
migration heads in circulation, two surface counts). Every structural number below
is computed from the tree when this file is generated; the reviewed claims are
labelled as claims. Where older documents disagree with this one, the table says
which claim is stale — this document supersedes the number, and the older
documents are left in place as historical snapshots.

## Schema

- **Migration head (computed from alembic): `0135`**
- The operator-package contract (`scripts/operator_release.py`) pins the same head;
  `test_operator_release.py` fails if they ever disagree again.

Stale migration-head claims still visible in historical documents and scripts —
superseded, not silently edited:

| Where | Claim | Status |
|---|---|---|
| `README.md` (source-review line) | `0106` | stale — historical review snapshot |
| `docs/CURRENT-IMPLEMENTATION-STATUS.md` | `0106` | stale — historical snapshot |
| `docs/BANK-ON-PREMISES-DEPLOYMENT.md` | `0106` | stale — historical snapshot |
| `scripts/controlled_cbom_e2e.py`, `scripts/controlled_recovery_drill.py`, `scripts/legacy_cbom_e2e.py`, `scripts/production_cbom_e2e.py` | `0107` | stale pins in drill scripts |
| earlier review convention ("Guide 184") | `0107` | stale — external review artifact |

## Console surfaces

- **Computed from `shared/shared_models/capability_maturity.py`: 93 classified
  surfaces (93 GA / 0 Beta / 0 Preview).**

Stale surface-count claims superseded by the count above:

| Where | Claim | Status |
|---|---|---|
| `README.md` | 75 surfaces | stale |
| `docs/architecture/service-map.md` | 75 surfaces (33 GA / 32 beta / 10 preview) | stale |
| `docs/CURRENT-IMPLEMENTATION-STATUS.md` | 77 surfaces (33 GA / 32 Beta / 12 Preview) | stale |
| `docs/PLATFORM-STATUS.md` | 77 surfaces | stale |
| earlier review convention ("Guide 184") | 92 vs 87 surfaces | stale — external review artifact |

## Security-control plane

The critical-issue review's P0/P1 items are implemented and pinned by the dedicated
regression suite `services/api/tests/security/test_security_control_regressions.py`
(10 named suites):

1. cross-origin pagination and credential-leak tests
2. HTTP downgrade and redirect tests
3. snapshot canonical-hash tests (the v2 manifest binds identity, provenance, read
   outcome, counts and refusals, sorted controls, sorted child finding records and
   digests, and the previous hash; v1 history verifies under its own scheme and is
   never upgraded)
4. child finding tampering tests
5. evidence artifact digest verification (missing artifact = **unverifiable**, never valid)
6. cross-tenant evidence reference tests (path confinement: a body location never
   leaves its tenant's evidence directory)
7. cross-snapshot and cross-asset evidence tests (an id resolves only in its own
   snapshot's body; a fact class must support its state)
8. FileTail partial-line and truncation tests
9. file rotation and cursor recovery tests (persistent cursor + inode tracking)
10. concurrent snapshot sequence tests (in-process lock + retry; migration 0134
    makes the platform-estate sequence unique despite SQL's NULL-distinct rule)

## Driver coverage (computed)

- **9 live drivers** — code that reads real devices: api_gateway.kong, firewall.checkpoint, firewall.fortigate, firewall.paloalto, ids.suricata, ips.suricata_inline, load_balancer.f5, load_balancer.nginx, siem.splunk
- 22 fixture-only dialects (parsing proven, device unproven)
- Gap families named, not implied: rate_limit, vpn, waf — documented dialects with no live read.

## Open gaps — acknowledged, still open

These are the review's honesty items. None of them is closed by this document;
existence of a workflow file is not proof that it ran.

- **No real-device qualification** of the live drivers (the 9 above read
  recorded fixtures and test doubles in CI).
- **No bank PITR / backup-restore proof** on a bank system (drills run on lab hosts).
- **No frontend browser tests** (frontend typecheck and vitest unit suites only).
- **No bank acceptance** — banks that have run the readiness gate: 0.
- **No proof the scheduled workflows ran** on this build.
- External-only, never sandbox: bank triage feedback loop, two-instance DR/PITR/soak
  drills, third-party pen test, real HSM/CloudHSM run, SOC2/ISO process,
  release-manifest publishing + branch-protection verification.

## Reviewed claims (not computed — dated, and only refreshed by review)

- Production readiness (2026-11-06 review): **~55% headline** (engineering ~85%,
  supervised pilot ~70%, unattended ~40%); `scripts/bank_readiness.py` = **FAIL**;
  field data = **NO_FIELD_DATA**.
- The 2026-10-23 quality-workflow qualification and the migration-0106 era docs are
  historical snapshots. This generated document is the current state.

## How this document stays true

`scripts/tests/test_current_state_doc.py` regenerates this file and requires the
result to be byte-identical. A change to the migration head, the capability
registry or the driver table fails that test until this file is regenerated — so
the numbers above cannot drift behind the tree again.
