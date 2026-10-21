# Evidence assurance engineering record — 2026-10-21 UTC

## Scope and disposition

Source increment for the user's authoritative **3.1–3.7**, on
`arena/bb4b80dd-cryproscan`, extending parent
`74ba98f10717567e9263ed6b4bd0579c1673632b`. Publication and final commit identity are
recorded in PR 34. No CI workflow or main-branch change is part of this increment.

**Engineering contracts tested; external bank acceptance remains incomplete.**
This is not a new unified readiness-gate PASS, infrastructure certification,
customer accuracy claim, independent supplier attestation or live vendor support.

Read the [upgrade runbook](../runbooks/evidence-assurance-upgrade.md) before
migration/redeployment. Migration **0103**, current typed human sessions and a
rebuilt approved parser image are required. The controlled profile still only
executes local source; the added assurance surface is bounded evidence metadata,
quarantine/review and offline JSON contract validation, not live acquisition.

## Retained local test results

| Run | Result | Scope / limits |
|---|---|---|
| Broad regression, initial | **1,338 passed, 17 skipped, 8 deselected, 140 warnings; 395.43s** | Worker/database/SDK plus selected SSH/Redis/production/control/supply-chain/legacy-accuracy APIs, before final file-proof/review hardening |
| Broad regression, later | **1,374 passed, 17 skipped, 8 deselected, 144 warnings; 405.13s** | Whole worker/database/SDK suites plus new assurance, byte-capture/migration and selected existing APIs; precedes final engine-fingerprint/tied-measurement hardening and two extra Redis-caller tests |
| **Final changed-path acceptance** | **211 passed, 10 warnings; 44.28s** | Latest assurance workflows/control boundary/Redis callers, SSH receipts, legacy accuracy, 0103 round trip, real owned-source byte capture, verified Redis config, production hardening, dependency health, execution controls, static parser isolation contracts and SDK |

These suites overlap. **Do not add the counts.** Existing broad-suite exclusions
were not removed or relabeled as passing. Warnings remain; no claim of zero
warnings. Runtime/OS/container/provider integration tests requiring unavailable
infrastructure remain skipped or outside this scoped run.

Local logs retained in the agent workspace (not sensitive customer artifacts or
Git payloads): `/home/user/assurance-regression.log`,
`/home/user/assurance-final-regression.log`,
`/home/user/assurance-final-acceptance.log`.

### Exact final local command

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_assurance_redis_clients.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py \
  services/api/tests/unit/test_ssh_receipt_contract.py \
  services/api/tests/integration/test_field_accuracy_api.py \
  services/database/tests/unit/test_assurance_migration.py \
  services/scanner/tests/unit/test_file_observation_receipts.py \
  services/api/tests/unit/test_replay_redis_security.py \
  services/api/tests/unit/test_production_hardening.py \
  services/api/tests/unit/test_dependency_health.py \
  services/api/tests/unit/test_execution_controls.py \
  services/worker/tests/unit/test_static_scan_isolation.py \
  services/connector_sdk/tests \
  -q --disable-warnings --maxfail=1
```

The agent used `/home/user/ci-venv/bin/python` with the repository's installed
test dependencies. The command above is for an equivalent provisioned local test
environment, not an instruction to run tests against a customer's live Redis/SQL.

## Redis runtime checks actually performed

Disposable **Redis 8.10.2**, private local Unix socket, socket/directory mode 0700,
no TCP listener, persistence disabled, development transport only:

- All **eight** consumer command probes round-tripped, plus the full existing
  realtime transactional journal command probe.
- Probe-only database ended with **zero scratch keys**; no bank state was used.
- Portable observer no-fault smoke: **3 prior ACK IDs / 3 recovered**, **20 load
  operations**, one-second configured load. It retained an explicit no-fault
  witness label and `SEPARATE_HUMAN_REVIEW_REQUIRED`, not deployment acceptance.
- Runtime warned that memory overcommit was not enabled and that no Redis password
  was configured. This private Unix-socket command check is **not** production
  configuration/security/persistence qualification. No host tuning was changed.
- The disposable server was stopped; no external deployment or data was touched.

Result metadata: `/home/user/assurance-live-redis-commands.json` and protected
observer scratch artifacts outside Git. No credentials, private keys or customer
exports are committed. Earlier local TLS/Sentinel evidence remains separately
scoped; it is not upgraded into a bank-topology fault qualification by these tests.

Production TLS/hostname/non-default ACL/Sentinel tests cover every role's factory,
explicit role routing and forbidden URL overrides, including duplicate-query
verification bypasses. Credential/CA cache identities and actual API/worker
factory call sites are tested. Those are code contracts, not deployed credential
revocation or certificate rotation proof.

## Acceptance matrix

| Section | Implemented/tested now | External / deliberately unclaimed |
|---|---|---|
| 3.1 | Scope committed before contact; successful/failed/unknown/refused/untouched phases survive projection rollback; finalization refuses partial scope; four independent conclusions | SSH still unqualified for controlled execution; generic collectors need explicit phase wiring; actual process/host loss and retention/backup objectives |
| 3.2 | All eight consumers use verified configurable TLS/Sentinel routing; actual local commands; portable old-ACK observer; topology-specific objectives, evidence matching, loss/load calculation, separate review and expiring full matrix | Approved deployed rotation, partition/split brain, lag, disk/memory pressure, kill/power loss, backup/restore/failback and representative recovery evidence |
| 3.3 | Independent versioned target register; exact receipt matching/freshness; all five target states, honest kind denominators and completeness assertion; no old-receipt refresh | Whole-bank register completeness; actual bank counts; qualified external-target/deployment binding rather than inferred coverage |
| 3.4 | Existing identities reused; exact package/version and typed evidence edges; different reviewer; application→artifact→package→crypto trace with unresolved edges; six typed offline fact classes | Independent deployment/invocation/service/firmware/module-mode/supplier truth and actual customer source/profile coverage |
| 3.5 | Durable nominated domain-owner identity; approved/frozen sample, exact file-byte proofs, first-pass immutability, per-class scores/undefined rates, confirmed regression seeds and newer byte-bound result checking, disjoint held-out repeat | Actual approved representative customer corpora/review, all requested difficult source classes, full fixture/dependency/runtime-context binding, semantic leakage controls and executable customer regressions/held-out results |
| 3.6 | Context revisions never mutate observations; checksum/security/test/invocation distinctions, purpose-specific explanations, narrow PyPI applicability and exact-module/mode label uncertainty | Complete policy coverage for all consumers/ecosystems, independently validated certification/advisory/runtime facts |
| 3.7 | Exact manifest, trusted Ed25519 scope/customer/build/digest/expiry checks, opaque quarantine, raw-access restrictions, bounded offline adapter actually exercised against seven cases, current trust/expiry/engine fingerprint gating; registry ≠ support | Named real-vendor live authentication/permissions/pagination/rate/retry/load and independent supplier qualification; no live SUPPORTED claim |

## Documentation/static checks

- Changed Markdown: **13 files**, **120 relative links**, **2 Bash blocks**, no
  new link/fence/shell syntax errors.
- REST reference: **891 paths / 982 operations / 105 groups**; generator and
  schema comparison idempotent.
- Changed Python/new module Ruff **F/E9** and `git diff --check`: PASS.
- Engine-fingerprint smoke across three Python hash seeds produced the same
  result; this still does not replace a signed reproducible deployment image.

## Operational and evidence limits

- SQLite/auth/SQL fixtures verify scoped behavior; they do not replace PostgreSQL
  concurrency, failover, restore or every-store residency/ownership qualification.
- Per-file SHA equality does not prove identical surrounding dependency/config/
  native-provider/runtime context or absence of semantic hold-out leakage.
- Human review is durable and separate where required; the API cannot prove the
  semantic truth of an external witness, review note or operator-uploaded log.
- Revision/blob ORM guards and linked hashes are not WORM storage or protection
  from a database administrator rewriting history. Regional encrypted, quota-
  controlled storage, backups and audited retention remain deployment controls.
- Raw quarantine is not a generic parser/import bypass. Wrong-customer, stale,
  revoked or malformed supplier bytes cannot be downloaded through the raw API;
  approved raw access still requires a current CISO/admin human session.
- No customer representative samples, actual bank target topology or proprietary
  vendor credentials/exports were supplied. Missing evidence remains missing.
- The external readiness closure policy is unchanged and does not automatically
  accept these application records as external customer/provider attestation.
