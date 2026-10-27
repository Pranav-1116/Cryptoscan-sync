# Engineering evidence — Linux preflight and isolated validation — 2026-10-26

[Guide 87](../bank-environment/87-linux-traffic-preflight-and-isolated-control.md) · [API](../api-reference/traffic-control.md) · [Runbook](../runbooks/traffic-control.md)

## Exact scope and qualification

This increment adds source-bound Linux read-only preflight, retained separate-human namespace-validation review, Network-page steps and an operator CLI restricted to loopback in fresh user/network namespaces. No parent/real target interface rule, module load, production executor or throughput measurement is included. Native TBF success is **not demonstrated** on this sandbox.

Publication candidate: published parent `da7302f126dff88ea8e79a6b81af82bec67f44d3` plus only this increment's owned paths. The exact additive candidate was unpacked outside the working tree and checked with the existing installed Python/Node dependencies. All existing workspace edits/deletions remain authoritative and untouched; the preservation helper retained **4,917 outside-owned fingerprints**, including 499 unrelated tracked changes. Only two existing implementation files changed: two lines each in API router registration and the Network page.

## Executed gates

| Gate | Actual result | Limits |
|---|---|---|
| Exact additive Python contracts/collector/HTTP plus source resource regressions | **64 passed** | Focused suites, synthetic source/API fixtures; not the whole repository |
| Owned PostgreSQL | **6 passed** | Separate review, duplicate review one winner, review/revocation audit ordering, audit-failure rollback; synthetic preflight facts |
| Exact additive frontend review/source panels | **11 passed** | Four new review tests and seven existing source-panel regressions |
| Exact additive frontend TypeScript + production build | **PASS** | Installed dependency environment, not a new frozen dependency install |
| Python Ruff and format | **PASS** | Owned Python implementation/tests/evidence helpers only |
| `pip check`, five generated JSON schemas, native artifact commitment/report verification | **PASS** | Engineering integrity, not authenticated source/custody |
| Ordinary-user native CLI preflight/report | **exit 0 / exit 0** | Declared checks resolved, host enforcement still blocked |
| Ordinary-user native namespace drill | **exit 2, REFUSED_OR_FAILED** | Distinct child namespace and loopback setup succeeded; kernel TBF unavailable |

Logs: [Python](traffic-control-2026-10-26/python-tests.txt), [PostgreSQL](traffic-control-2026-10-26/postgres-tests.txt), [PostgreSQL JUnit](traffic-control-2026-10-26/postgres-tests.xml), [cleanup](traffic-control-2026-10-26/postgres-cleanup.txt), [frontend](traffic-control-2026-10-26/frontend-tests.txt), [typecheck](traffic-control-2026-10-26/typecheck.txt), [build](traffic-control-2026-10-26/build.txt), [environment](traffic-control-2026-10-26/test-environment.txt).

Focused tests cover malformed/duplicate/budget-exceeding JSON; command timeout/output termination; denied inputs; changed interface/context; canonical declared IPs; executable symlink/mode/file-capability refusal; fixed read-only argv; parent privilege/context/hash refusal; isolation before writes; fixed child-loopback-only add/readback/remove; unsupported kernel refusal; no deletion of an unowned policy; exact estate/role denial; hash mismatch; assigned separate reviewer; immutable approval; source revocation; original JSON uint64 preservation; failed-download rejection; and private-scope late-response fencing. Positive kernel command behavior is **synthetically simulated**, never reported as an actual native apply.

The first owned PostgreSQL run exposed overlength assurance `kind` names, which SQLite did not enforce. Names were shortened to fit the existing `VARCHAR(30)` contract, a length regression test was added, and the fresh owned-server rerun passed all six tests. No schema migration or change to unrelated database code was made. Both owned runs stopped their temporary server and removed their temporary data directory. The retained successful runner/logs do not claim exhaustive concurrency coverage or production database acceptance.

## Actual native witness

- [Specification](traffic-control-2026-10-26/native-spec.json) and [preflight](traffic-control-2026-10-26/native-preflight.json): actual disposable sandbox `eth0`, ifindex 2, existing `pfifo_fast` root summary, and one explicitly declared `127.0.0.1` route through `lo`. This is not an agreed bank management inventory or customer host measurement.
- [Deterministic report](traffic-control-2026-10-26/native-preflight-report.json): declared checks complete; existing-policy, device-authenticity/enrollment, management-completeness and unsupported host-executor blockers remain. `host_enforcement_authorized` and `production_execution_qualified` are false.
- [Local test packet](traffic-control-2026-10-26/synthetic-local-drill-packet.json) pins that preflight digest, but proposal/request/reviewer record IDs/hashes are synthetic fixtures. It is **not** a retained independent human approval or an enrolled-device credential.
- [Drill result](traffic-control-2026-10-26/native-drill-result.json): parent namespace unchanged; child namespace distinct; no verified qdisc apply or rollback; `CHILD_REFUSED_OR_FAILED`. A separate same-kernel diagnostic returned `Error: Specified qdisc kind is unknown.` No module installation/load or host fallback was attempted.
- [Parent before](traffic-control-2026-10-26/parent-qdisc-before.json) and [parent after](traffic-control-2026-10-26/parent-qdisc-after.json) are byte-identical. The [native run](traffic-control-2026-10-26/native-run.json) retains CLI statuses/digests and context comparison.

The verifier checks all five generated schema definitions, typed native artifacts, exact specification/preflight/authorization/result binding, report recomputation, unchanged parent policy and every manifest file hash. Hashes/nonce/UUIDs are unsigned engineering commitments, not source authentication, protected custody or real-person independence proof. No credentials, private keys or packet contents are retained.

## Reproduction

Use a disposable checkout/import environment and new output names. Focused suites:

```text
python -m pytest shared/shared_models/tests/test_linux_traffic_control.py services/inventory/tests/test_linux_traffic_preflight.py services/inventory/tests/test_linux_traffic_drill.py services/api/tests/unit/test_traffic_control_api.py services/api/tests/unit/test_resource_monitoring_api.py -q
npm --prefix frontend test -- src/components/TrafficControlReview.test.tsx src/components/ResourceMonitoring.test.tsx
npm --prefix frontend run typecheck
npm --prefix frontend run build
python docs/readiness-evidence/traffic-control-2026-10-26/run-owned-postgres.py --root /absolute/disposable-checkout
python docs/readiness-evidence/traffic-control-2026-10-26/verify-artifacts.py
```

Configure canonical Python import roots with `scripts/_bootstrap.py`/the existing repository environment. The owned PostgreSQL runner ignores any existing database URL, creates a temporary database, and removes it; rerunning overwrites its evidence logs, so use a disposable copy. Terminal control sequences and trailing blank lines were removed from frontend/build/typecheck text logs without changing their diagnostic content. [Manifest](traffic-control-2026-10-26/evidence-manifest.json) pins the delivered files; it does not pin its own bytes.

## Remaining qualification

A supported owned Linux target must demonstrate native TBF readback/rollback and separately measured throughput before claiming an effective bandwidth limit. Actual host enforcement additionally needs enrolled/authenticated device identity, complete management exclusions, existing class/filter/ingress/firewall policy ownership, bounded online execution/withdrawal semantics, independent change acceptance and out-of-band recovery. Offline packets can be replayed locally inside their window and do not authenticate their approver. No 24/7 monitoring, customer acceptance, production SLA or engineering performance-target improvement is claimed.
