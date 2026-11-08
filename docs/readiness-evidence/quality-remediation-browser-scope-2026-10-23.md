# Eighth quality increment: remediation browser scope — 2026-10-23 UTC

## 1. Starting point and selected roadmap item

Starting HEAD/remote: `e5469967154f67d70f1d33b8e015f512c6227f32`, clean on
`arena/bb4b80dd-cryproscan`; PR #34 open. Continue
[guide 5](../product-improvement/05-user-workflow-and-frontend-quality.md) and
[roadmap C3 / B3 / B4](../product-improvement/08-execution-roadmap-and-acceptance.md):
existing browser state, forms and estate-race behavior, not feature breadth.

Only the existing `Remediation.tsx` application module changes. One regression
file is added. No API, server authorization, immutable history, schema/migration,
BOM, collector, dependency/lockfile, workflow, service or profile change. All six
BOMs keep their existing evidence requirements; this does not complete their
matrix. The latest prior source-proof publication is `08b48df0`; the intervening
DR pack is documentation, not an implementation of backup/failover services.

## 2. Problems reproduced before fixing

- The page did not subscribe to estate/auth changes: private tasks, counts,
  verification details, expanded forms, rescan IDs and notes stayed in the old
  view. A later request used the helper's current credentials/estate. These are
  client-state consistency/privacy defects, not a demonstrated backend bypass.
- Concurrent list reads had no generation guard. A late success could replace a
  newer filter; a late failure could hide it. Same-filter A→B→A and StrictMode
  remount ordering reproduced the problem too.
- Loading reused earlier rows/counts; failed replacement reads hid the table but
  left old per-status counts. Loading was not distinctly announced.
- Old lifecycle responses called the detached view's refresh callback, issuing
  an unnecessary request under the new current browser scope. An already-sent
  mutation itself is not undone by discarding its response.
- React busy state did not lock two same-turn clicks before a render. Two POSTs
  could be sent; this is not proof of two successful server-side effects.
- Network/HTTP failures were presented as `Refused` without an announced
  unconfirmed-outcome/history-review instruction. The existing helper retains
  only HTTP status for non-2xx responses, not the backend's detailed refusal body.
- Cross-window token/tenant storage events (and clear-all) had the same stale
  private-state issue. Unrelated preference changes already preserved drafts.

## 3. Actual diagnostic sequence

| Run | Actual result / interpretation |
|---|---|
| Existing Remediation + OperatorDecisions baseline | 10 passed; 9.05 s wall. Local synthetic DOM/API transport only. |
| Initial 20 new cases, unchanged application | 20 failed; 14.89 s wall. |
| Provisional correction plus existing pages | 30 passed; 12.12 s wall; includes those initial 20 new cases. |
| Expanded 25 cases against unchanged application | 25 failed. |
| Interim full DOM run, before storage follow-on | 423 passed / 46 files; 110.37 s wall. Superseded by final run below. |
| Final 29-case set against unchanged application | 28 failed / 1 passed; unrelated-storage control already passes. |
| Initial typecheck | Four TS7006 errors in newly added test callback parameters. Explicit string annotations correct the test typing; this was not a product failure. |
| Initial focused invocation from repository root | npm ENOENT (no root package.json); no test executed. Corrected invocation uses `frontend/`. |
| Final publication checks | **427 passed / 46 files**, 106.73 s wall; no failures/errors/skips. Includes all 29 new cases, not additive. Typecheck/build pass; 7 toolchain tests pass (no skips). |

For complete adverse reruns, the single page was temporarily replaced by
`git show HEAD:frontend/src/pages/Remediation.tsx` bytes. A `finally` restored the
corrected file and verified byte equality. No other source was reset; no live
services ran. The baseline page SHA-256 is
`4470f30a331834eb21f8599c2ed152b01c0705eec3158692477b64fed352ac7d`.

Run counts overlap and are not additive. Final source/test fingerprints below
bind publication inputs; interim runs are not relabeled as final qualification.

## 4. Small correction and why

1. A keyed private view is recreated on existing current-window estate/auth
   events and relevant storage events. All task IDs, counts, selection, filter,
   expansion and form drafts reset, including coincident IDs across estates.
2. Each list load clears the prior rows/counts and exposes loading. A monotonic
   request counter plus mounted guard refuses obsolete success/failure, including
   filter ABA and StrictMode. Failure does not substitute old success/zero safety.
3. A detached action form ignores its completion before callbacks or local state
   writes. A synchronous ref locks duplicate same-turn submission; release occurs
   in `finally`, preserving deliberate later work without automatic retries.
4. An unsuccessful/unconfirmed action has an alert and retained-history-before-
   retry guidance. Current-scope drafts and HTTP status remain inspectable.
5. Existing helper/API/timeout contracts are unchanged. UI reset is **not network
   cancellation, server rollback, exactly-once execution or durable reconciliation**.
   Inspect the original exact-estate task/history if a sent mutation's reply is lost.

No localStorage task/draft cache is added. Storage remains selection/session
transport only, not authorization. Current server authentication/membership,
exact-estate ownership, approval and revision checks remain authoritative.

## 5. New regression coverage

| Group | Cases |
|---|---:|
| Immediate current-window estate/auth clearing, coincident task IDs and drafts | 2 |
| Late initial success/failure after estate/auth switch | 4 |
| Superseded filter success/failure | 2 |
| Pending filter has no stale rows/premature empty success | 1 |
| Current failed read drops stale counts | 1 |
| Detached accept/complete/verify success/failure; original request headers retained | 6 |
| Mutation completion after page unmount | 1 |
| Same-turn double click produces one client POST | 1 |
| Current HTTP failure/disconnect: uncertainty, draft retention, no retry | 2 |
| StrictMode superseded mount | 1 |
| Same-filter ABA late success/failure | 2 |
| HTTP 403/409 status and useful draft retention | 2 |
| Cross-window tenant/token/clear-all storage events | 3 |
| Unrelated preference change preserves useful draft (baseline passing control) | 1 |
| **Total** | **29** |

These tests use real React components, existing API helpers/headers and synthetic
fetch responses. Deferred transport intentionally ignores abort signals so late
completion is deterministic. Storage events are dispatched in jsdom, not observed
between two real browser windows. No real customer source, user or server is used.

## 6. Commands and environment

From `frontend/`, using the committed package lock and Node 22.22.3:

```bash
npm ci --no-audit --no-fund
npm test -- src/pages/Remediation.test.tsx src/pages/OperatorDecisions.test.tsx
npm test -- src/pages/Remediation.scope.test.tsx
npm test -- --reporter=default --reporter=junit --outputFile.junit=/approved/evidence/frontend.xml
npm run typecheck
npm run build
npm run test:toolchain
```

The JUnit output path above is illustrative; an approved existing protected
evidence directory must be selected. Actual local outputs are named
`/home/user/quality-eighth-{baseline,red,complete-red,final-red,focused,frontend-interim,frontend-final,typecheck-final,build-final,toolchain-final}`
with the applicable `.log`/`.xml` suffix. Dependencies, build output and full raw
logs stay outside the tracked patch. No workflows were changed/dispatched;
publication uses `[skip ci]`. No GitHub Actions success is inferred.

The final DOM run retains **16 React `act(...)` warnings**: 2 TaskActions,
10 RealtimeProvider and 4 Tenancy. These are not silenced or relabeled clean
browser/async correctness. The JUnit root has 427 tests, zero failures/errors;
all cases are executed, with no skips. The `time` attribute sums test activity,
not the wall duration; **106.73 s** is the CLI's reported wall duration. The
production bundle's reported build phase is **1.39 s**, not a runtime latency
or bank-browser performance measurement.

## 7. Limits and remaining acceptance

This is not a whole-console isolation audit, real multi-window/browser/network
exercise, elapsed-time endurance measurement, accessibility/RTL/zoom certification,
PostgreSQL/Redis/server-authority test, actual site outage or production proof.
No Python/backend suite was rerun: server source did not change. Historical
API/auth/library results retain their original attribution, not this increment.

No supported collector/profile/route is enabled or promoted. No image was signed,
published or deployed. Different-human code/security review, intended workstation
practice, exact full-release verification and bank/customer acceptance remain open.
The original unidentified CI failure stays with its user-designated owner.

## 8. Documentation checks and source fingerprints

Repository documentation validation checks **507 Markdown files / 2,007 local
links**, no missing files or unresolved anchors; **57 external links counted,
not fetched**. All 9 changed Markdown files have balanced fences; the one shell
block passes syntax checking (not replayed by the documentation validator).
**84 retained SHA-256 entries** match: 47 earlier quality entries, 28 DR-plan
inputs and 9 current inputs below; entries are not necessarily distinct files.
Whitespace checks pass after removing the authoring-time extra EOF blank line.
No earlier report is rewritten to claim this increment's results.

Each block is repository-relative path followed by SHA-256. These bind local
inputs, not independent trust, deployed site state or acceptance.

```text
frontend/src/pages/Remediation.tsx
af21e4eaf10991772a01d59cf6f77e063f1572d43444597fa9fc9085c421113c
```

```text
frontend/src/pages/Remediation.scope.test.tsx
7fba202989fa0b204b2c52eeb5f1254605acc9fa137eb6a327bfaae71d3a9760
```

```text
frontend/src/pages/Remediation.test.tsx
ca1436022f3afc1adb641235ac161defbb077d57975b69ecb59c26c5ba260038
```

```text
frontend/src/lib/api.ts
98fd5cffbab0493ad1b0ed56665dc050a55ca013ebd0de6640759b16770edff6
```

```text
frontend/src/test/setup.ts
a761a8c4391c6fca4edbfb9abbaa72ac5a1581e477454c37cc126a3c3fb4be4c
```

```text
frontend/src/App.tsx
101babbba1e5ef28916eac7d69d64baf99b6838f0750be2bdb7a590fc265a1ca
```

```text
frontend/package.json
72beb49bfa4785cf45d1b7dae44a2ee80885999679538488233c57902a8ab9fc
```

```text
frontend/package-lock.json
94e58e21705e304238037cd7569bd6332fc9f73ae8d17a3b37ab205880fa839b
```

```text
frontend/vitest.config.ts
e9adf32aaa1e396a9d12559261ac61262f8f4eb211cec764080275c920792787
```
