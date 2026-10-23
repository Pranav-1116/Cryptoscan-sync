# Tenth quality increment: shared private read state — 2026-10-23 UTC

## Scope, provenance and observed gap

Starting published source: `8c1b2bcfed636c73addac4a62ae94ce3edabcbd2`, branch
`arena/bb4b80dd-cryproscan`, [PR #34](https://github.com/ZKChainForge/CryproScan/pull/34).
This continues browser-safety work beyond the three pages hardened in the
[ninth increment](quality-workflow-qualification-2026-10-23.md). It does not add
features, collectors, routes, services, dependencies, workflow changes or a schema
migration. Schema/package head remains **0106**.

Only the existing `useLive.tsx` application module changes. Its read-state lifecycle
is shared by existing pages; one 36-case regression file is added. The retained
real-browser harness gains Organization and Reports read-state checks and structured
failure reporting. These checks do not qualify those pages' forms/actions/exports.

Observed defects:

1. Refresh/path changes retained earlier private data until a response arrived.
   Estate/auth/storage/resume events did not revalidate this shared hook at all.
2. An old request/body could restore obsolete data after a context change. Path
   cleanup prevented some ordinary path races but was not a session/estate fence.
3. Disabling a path with `null` could retain private data or leave loading true.
4. A pending transport ignoring abort could keep loading indefinitely. Unmount did
   not abort the owned request. Captured reloads had no mounted-lifetime fence.
5. HTTP401,403,409,503 and malformed JSON all collapsed into `backend unreachable`;
   `LiveStatus` unconditionally called any error `backend offline`. An access denial
   is not evidence of a backend outage.

## Correction and why it is bounded

- Reuse `watchPrivateScope` for current-window estate/auth, relevant localStorage,
  clear-all, visible resume and persisted pageshow. Clear the hook's private data
  to its caller-provided **empty fallback**, error and loading state, then reissue
  only the hook's GET. Unrelated preferences/sessionStorage/hidden-tab/ordinary
  pageshow are controls and do not cause a read.
- Increment a request generation synchronously on reload/invalidation and abort
  the previous controller. Only the mounted current generation, current committed
  path and non-aborted request may publish a result or finish loading. Late body
  parsing is fenced too; A→B→A does not restore the first generation.
- Guard returned data against a different path during render, before effect cleanup.
  A null path clears data/errors/loading, cancels pending work and performs no GET.
  Keep latest committed path/fallback in a ref, without refetching on every inline
  fallback-object identity change or publishing from an uncommitted render.
- Own a **12-second** loading deadline in the hook. Abort and show `Read timed out`
  even if the transport ignores cancellation; a later result cannot revive it.
  Clear owned timers/listeners on cleanup and ignore captured reloads after unmount.
  Do not allocate a redundant default timeout when the hook supplies its own signal.
- Preserve safe failure categories: authentication/session401, permission403,
  other refusal409, service503, invalid JSON, empty response, transport failure and
  timeout. Do not expose a dependency's raw body/target/stack. `LiveStatus` displays
  the safe reason instead of claiming every refusal is an outage. Existing exported
  `liveGet` retains its nullable data contract.

**Why not apply this automatically to `useApi`?** Its callback may perform a write
(for example an existing benchmark action), unlike the GET-only `useLive` hook.
Automatic context replay there could duplicate an action. That read/action contract
needs a separate observed-defect-first review; this increment does not broaden it.

This is client display/read consistency, **not server authorization**, revocation
propagation assurance or a rollback of already-sent work. Hook consumers' local forms,
selected IDs, action callbacks and bespoke downloads are not automatically fenced.
Reports' schedule/pin/exit-report forms and its separate PDF path are not claimed
fixed by the shared GET change. Apply page-specific guards in subsequent increments.

## Thirty-six regressions

File: `frontend/src/lib/useLive.scope.test.tsx`.

| Group | Cases | Evidence |
|---|---:|---|
| Loaded-state invalidation | 9 | Estate/auth, four relevant storage keys, clear-all, visible resume and persisted pageshow clear before the new read resolves. |
| Stale response/selection | 6 | Old success/failure despite ignored abort, A/B/A, new path, overlapping manual reloads and StrictMode. |
| Disabled reads | 3 | Pending and previously loaded paths become null; initially null stays inactive across reload/scope events. |
| Lifetime/deadline/header/fallback | 5 | Unmount/captured reload, ignored-abort timeout, current credentials/estate, current fallback without fetch loop, timer/listener cleanup. |
| Unrelated-event controls | 4 | Preference storage, sessionStorage, hidden tab and nonpersisted pageshow. |
| Safe failure interpretation/compatibility | 8 | Four HTTP categories, malformed JSON, transport outage, visible refusal text and exported nullable compatibility. |
| Delayed response body | 1 | Headers have arrived, then context changes before JSON body completion. |

Final original-source comparison: **27 failures / 9 passes** out of36. Only
`useLive.tsx` was temporarily replaced with its starting-commit bytes. A finally
restored the corrected file and asserted exact byte equality. Existing passing
controls are not counted as newly fixed defects.

Diagnostic history is retained rather than relabeled: the initial26 cases produced
19 failures/7 passes against original source; a follow-on interpretation check
produced six failures/30 passes against the provisional scope correction. One
subsequent assertion expected `timeout` rather than `timed out`; the test was corrected
to the exact final message, not counted as another product defect. Final36-case
original-source comparison supersedes those smaller comparisons. A final full-suite
command wrapper lost its tool transport while Vitest continued; the process was
not duplicated. Its complete final log/JUnit confirms516 passes. Build/toolchain/
browser were then invoked separately and completed successfully.

## Actual built-browser evidence

The updated `frontend/scripts/critical-browser.mjs` runs the built production
console in actual Chromium153.0.8010.0 with externally installed Playwright1.64.1
and Sparticuz153.0.0. No product dependency/lockfile change. It still uses synthetic
identities and fully intercepted HTTP at `http://cryptoscan-quality.invalid`.
The container requires external NSS/NSPR libraries and lacks normal Chromium
sandbox qualification. See the [prior browser environment record](quality-critical-browser-2026-10-23.md).

Two new real cross-window tests change estate in another same-origin browser tab:

- **Organization:** its shared onboarding GET refreshes to the new estate, with no
  remaining old marker and no mutation request.
- **Reports:** its shared schedules GET does the same. This does not test creation,
  pinning, report rendering, export bytes or controlled-profile adapter admission.

The harness now counts **all non-read methods**, not only assurance POSTs, for the
no-mutation assertion. It emits partial PASS/FAIL records even on a failed exercise
and exits nonzero on failure. Captured browser page errors still fail qualification.

Against a build using the original hook, the **prior nine checks passed**, then
Organization failed to show the new estate and the process exited1. The Reports
check was not reached in that red run. Against the corrected final build, **all11
checks pass**, with zero captured page errors. Nine of those are retained prior
checks, not eleven new scenarios. Browser and DOM counts are not additive coverage.

## Final checks and retained records

The [machine-readable record](quality-shared-private-reads-results-2026-10-23.json)
retains exact suite/case results, browser success and adverse results, source/build
input hashes, external log hashes and local environment. It binds this publication
without inventing a self-referential containing-commit hash.

- Entire frontend: **516 passed / 49 files**, including all36 new regressions;
  130.79 s; no failures/errors/skips. Twenty pre-existing React act diagnostics remain in
  CriticalScope/Remediation/Tenancy/realtime tests, not the new hook test file.
- TypeScript typecheck and production build (1.34 s) pass; **seven toolchain tests pass**,
  no skips. Node harness syntax and whitespace checks pass.
- Local documentation/input validation: **408 Markdown files, 2,010 links,
  58 anchors**, zero errors; three changed shell blocks syntax-checked and
  107 current source/build/log hashes verified. External URLs are not fetched.
- No backend code changes. Native PostgreSQL16 and selected API507 results remain
  the **previous increment's historical executions**, not new tests claimed here.
- No CI dispatch/success inferred; publication uses `[skip ci]`. The user-owned
  unidentified CI failure is not changed or declared fixed.

Reproduce frontend checks from the root:

```bash
npm ci --prefix frontend --ignore-scripts
npm --prefix frontend test -- src/lib/useLive.scope.test.tsx
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend run test:toolchain
CRYPTOSCAN_BROWSER_TOOLS=/home/user/quality-browser-tools/node_modules \
LD_LIBRARY_PATH=/home/user/quality-browser-tools/runtime-libs/lib \
node frontend/scripts/critical-browser.mjs
```

The external tool paths are this workspace's qualification environment, not a bank
installation recipe. Browser-tool setup/executable overrides are in the prior browser
record. Raw local artifacts are `/home/user/quality-tenth-{red,frontend}.{log,xml}`,
`quality-tenth-browser{,-red}.{json,err}`, `quality-tenth-{typecheck,build,toolchain}.log`
and diagnostic logs. Logs, binaries, node_modules and datasets are not added to Git.

## Remaining gaps — not silently closed

1. Audit local forms/actions/bespoke exports, especially Reports, and classify
   generic `useApi` read versus mutation consumers before enabling automatic replay.
2. Exercise a real browser connected through the approved deployment/backend,
   intended bank workstations, SSO/session revocation, TLS/proxy policy and
   accessibility/long-lived tab behavior. Synthetic HTTP is not site acceptance.
3. Continue actual deployment-version/TLS PostgreSQL and Redis/Docker/daemon/fence
   fault exercises, full DB-plus-evidence recovery, HA/WAL/PITR and measured
   capacity/RPO/RTO. This frontend increment supplies none of those results.
4. Preserve separate SBOM, CBOM, NBOM, TechBOM, HBOM and VBOM acquisition/identity/
   freshness/estate requirements. Shared read-state correctness does not complete
   the six-BOM matrix or establish evidence compliance.
5. Obtain different-human review and actual technical/customer acceptance. No
   24/7 staffing, SLA, uptime, signed image release or bank deployment is implied.
