# Resource monitoring — executed engineering evidence, 2026-10-26

## Delivery and decision

**Scoped engineering validation PASS.** Built ordinary-user Linux traffic/filesystem measurement, approved scope/intake/report APIs, a Network-page workflow and evidence-linked **non-executing** traffic-limit proposals. This is new product code, not just a monitoring design document.

[Guide 86](../bank-environment/86-network-traffic-storage-and-control.md) · [API](../api-reference/resource-monitoring.md) · [Operator runbook](../runbooks/resource-monitoring.md).

No bandwidth, firewall, routing, storage allocation or deletion setting was changed. No packet payload was captured. There is no apply endpoint, privileged executor or background resource daemon. Actual traffic enforcement, customer monitoring, Windows/router/cloud collectors, per-flow/app attribution, physical storage inventory and production qualification are outside this delivery.

## Source isolation

The additive publication candidate was assembled from published `9f53b198e9119ade6dd4f4b7d087dc7676aa6911` plus only this increment in `/home/user/.cache/resource-monitoring-release`. It includes the previously published dependency tree, rather than silently publishing the user's unrelated locally deleted modules. The current workspace also passed the final focused suite without restoring those deletions.

**4,878 outside-owned path fingerprints** were preserved and checked; all **499 unrelated tracked edits/deletions** remain excluded. Only router registration and two Network-page integration lines change existing clean product files; new modules/component/tests/contracts/docs are isolated. No workflow/main-branch, dependency manifest, migration or new-service change was made. `npm ci --ignore-scripts` installed only ignored local dependencies; no lockfile change was published.

## Completed gates

| Gate | Result | Retained evidence |
|---|---|---|
| Exact candidate: all shared-model and inventory suites | **1,777 passed / 22 skipped / 1 warning**, 70.06 s | [Log](resource-monitoring-2026-10-26/models-inventory.txt), [JUnit](resource-monitoring-2026-10-26/models-inventory.xml) |
| Exact candidate: resource HTTP, previous shared snapshots HTTP and foundation | **74 passed / 6 warnings**, 88.69 s | [Log](resource-monitoring-2026-10-26/workflow.txt), [JUnit](resource-monitoring-2026-10-26/workflow.xml) |
| Fresh owned PostgreSQL: selected source/estate/rollback and races | **9 passed / 6 warnings**, 28.81 s | [Log](resource-monitoring-2026-10-26/postgres-tests.txt), [JUnit](resource-monitoring-2026-10-26/postgres-tests.xml), [cleanup](resource-monitoring-2026-10-26/postgres-cleanup.txt) |
| Exact candidate: new frontend and existing API transport tests | **26 passed**, including 7 new panel tests | [Log](resource-monitoring-2026-10-26/frontend-tests.txt) |
| Exact candidate: TypeScript check / Vite production build | **PASS / PASS** | [Typecheck](resource-monitoring-2026-10-26/typecheck.txt), [build](resource-monitoring-2026-10-26/build.txt) |
| Final new contracts on current dirty workspace | **66 passed / 6 warnings**, 30.75 s | [Log](resource-monitoring-2026-10-26/workspace-focus.txt), [JUnit](resource-monitoring-2026-10-26/workspace-focus.xml) |
| New Python files lint/format, installed dependency consistency, four schemas and witness/source/hash/report verification | **PASS** | [Static output](resource-monitoring-2026-10-26/static-checks.txt) |

The two disjoint candidate Python groups total **1,851 passed / 22 skipped**. PostgreSQL and focused workspace gates repeat selected contracts: do not add them into a distinct capability or performance count. The new 66 focused contracts include real session/SQL authorization cases, pure synthetic counter/units/error tests, actual local CLI and an actual local capture-to-HTTP case. Fake counter cases are explicitly synthetic and do not demonstrate a customer link carrying a particular Mbps rate.

The 22 existing skips are actual Windows/interface gates, optional actual-hybrid-provider cases, an opt-in native namespace case and an optional PyOpenSSL adapter. They are not qualification passes. Existing deprecation/model-shadow and deliberately malformed-fixture serialization warnings remain. The PostgreSQL helper's runtime-directory fallback warning did not prevent actual DB execution. Full-repository/frontend/browser/device/HA/performance/SLA qualification was not run or claimed.

## What actually executed

- Explicit scope validation: active same-estate system/environment, unique exact interfaces/paths, bounded intervals/window, canonical no-traversal directory paths.
- Current human registration/import/proposal permissions and trust-role approval/revocation; readonly/auditor inspection without mutation; foreign and unselected administrator history hidden.
- Original scope revision/hash/nonce binding, capture after approval, no future finish, terminal capture consistency and canonical source digest checks.
- Exact Mbps/byte/reservation calculations; valid zero traffic distinguished from unavailable/reset/changed-index inputs. Failed storage remains unknown, never 0 GB.
- Read-only actual Linux proc counter reads and descriptor-bound `statvfs`, scope-only output, no-follow symlink gaps, non-root/expired/wrong-hash refusals, exclusive 0600 output and no-overwrite CLI reports.
- Every report rebuilt from the original typed capture; complete draft payload rebuilt from pinned source. Changed rate/management-safety flags fail after local resealing.
- Fresh measured interface required for draft; expired/revoked/stale/unknown inputs refused. Draft flags stay unapplied and unsupported for enforcement. `/apply` is nonexistent.
- API artifact/audit rollback and current controlled-production refusal.
- Real PostgreSQL duplicate capture: one successful new record/audit, one 409; intake-versus-revocation and draft-versus-revocation serialization with audit order checks.
- UI unknown/zero distinction, explicit draft-only labeling, current selected-estate transport headers, source failure clearing, stale-sample draft disabling, private form/state clearing and old-scope response refusal even if transport ignores abort.

The PostgreSQL helper created its own local server and per-case disposable databases, then stopped/removed only its resources. It did not use a customer database URL. There were no customer/device credentials and no live router/provider configuration requests.

## Actual sandbox witness — not customer evidence

Three original HTTP/collector artifacts are retained:

- [Original scope draft/approval history](resource-monitoring-2026-10-26/public-witness/resource-plan.json).
- [Actual Linux counter/filesystem capture](resource-monitoring-2026-10-26/public-witness/resource-capture.json).
- [Stored original capture and reconstructed report](resource-monitoring-2026-10-26/public-witness/resource-record.json).

The account/estate/system/host labels are synthetic test identities. The byte counters and capacity in this witness came from the **actual disposable sandbox's selected loopback interface and root-path filesystem**, sampled as an ordinary user for approximately one second. They are not the user's network/storage, a bank estate, a customer device or proof of independent custody. A valid idle/near-idle loopback sample must not be advertised as a throughput/capacity benchmark.

The [offline verifier](resource-monitoring-2026-10-26/verify-artifacts.py) checks all four typed schemas, both original plan revisions/hash links, exact authorization binding, original capture/record commitments and deterministic full report reconstruction. No passwords, keys, session credentials, packet payloads or directory contents are retained. The nonce and user UUIDs are public synthetic binding metadata, not secrets or real-person independence proof.

## Reproduction and remaining steps

The runbook lists focused Python, CLI, frontend and [owned PostgreSQL](resource-monitoring-2026-10-26/run-owned-postgres.py) commands. Broad candidate gates used:

```text
python -m pytest shared/shared_models/tests services/inventory/tests -q
python -m pytest services/api/tests/unit/test_resource_monitoring_api.py services/api/tests/unit/test_collection_views_api.py services/api/tests/unit/test_collection_foundation.py -q
```

[Environment](resource-monitoring-2026-10-26/test-environment.txt) and [integrity manifest](resource-monitoring-2026-10-26/evidence-manifest.json) retain versions and exact source/artifact commitments. The manifest/hashes are unsigned engineering integrity, not source authentication or protected custody. Trailing blank lines in the frontend/typecheck text logs were normalized before publication; diagnostic content is unchanged. Reproduction overwrites log/witness files; use a disposable copy.

Next execution work must identify the enforcement platform, enroll the actual device identity, agree management-path exclusions, define bounded change approval and verified rollback, and exercise a disposable target before any real traffic rule. A current unsigned metadata import or stored draft alone is insufficient execution authority. No external acceptance gate was manufactured to complete this increment.
