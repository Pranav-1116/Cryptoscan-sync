# Private browser safety beyond Remediation — 2026-10-23 UTC

Companion to the [ninth coordinated increment](quality-workflow-qualification-2026-10-23.md).
This record separates **53 new DOM/transport regressions** from **nine executed
real-Chromium checks**. Neither is intended-bank-workstation acceptance.

## Existing surfaces hardened

- **Operator Decisions:** clear inbox/results/drafts on estate/user changes and
  resume; synchronously fence the old view before React flushes; discard detached
  responses; one same-turn submit; retain uncertain-outcome/reconciliation guidance.
- **Launch Readiness:** same private-scope and single-flight fences. A 20-second
  abort deadline bounds an interrupted action; failures/timeouts are unconfirmed,
  with history review before retry. No automatic resend or new launch workflow.
- **Evidence:** clear scan/record selection, findings and old verification results;
  reject late record verdicts, including selecting away/back; lock duplicate
  verification clicks. Do not transform integrity verification into remediation.
- **Authenticated downloads:** abort on estate/auth/resume/unmount; compare token
  and estate plus an invalidation flag before/after response and after blob
  creation. Ignored abort cannot release old bytes. Revoke object URLs in finally.

`watchPrivateScope` watches existing current-window estate/auth events, relevant
cross-window localStorage events (including clear-all), visible-tab resume and
persisted pageshow/BFCache restoration. It ignores unrelated preference changes.
The keyed `PrivateScope` remount discards private state; the synchronous generation
predicate also stops an old handler during the interval before the new render.
A/B/A does not restore the original generation. Event listeners and pending
controllers are cleaned up. Draft loss on these context boundaries is deliberate
and announced, not silent carry-over to another user/estate.

A 401/403 still follows existing session handling; browser scope guards supplement,
not replace, backend authentication/authorization. Already-sent writes may commit.
A canceled fetch, timeout, hidden tab or discarded response **does not roll back**
server effects. Reconcile durable current history before manually trying again.

## Fifty-three new regressions and adverse comparison

`CriticalScope.test.tsx` contains 41 cases and
`AuthenticatedDownload.scope.test.tsx` contains 12. They cover estate/auth/storage
invalidation, clear-all, tab resume, persisted pageshow, stale responses despite
ignored abort, A/B/A, unrelated storage controls, detached submissions/receipts,
same-turn duplicate forms/verifications, uncertain writes, the interrupted Launch
deadline, late selection results, download headers/body timing, unmount and safe
filename/object-URL cleanup.

All 53 pass inside the **480-test / 48-file** complete frontend run (129.52 s).
They are not 53 additional passes beyond that total. The final 53-case set against
the five original application modules produced **48 failures / 5 passes**; unrelated
storage controls already passed. The comparison replaced only Evidence,
OperatorDecisions, LaunchReadiness, AuthenticatedDownload and lib/api bytes from
starting HEAD, then a finally restored and verified their exact corrected bytes.
It did not reset unrelated work. A separate pending-write test reproduced the
missing Launch deadline before the timer was added.

The full run emits 20 React act diagnostics: four in the new immediate-scope-fence
cases and 16 in existing Remediation/Tenancy/realtime tests. Tests pass, but this
is not a warning-free or accessibility-certified result. Typecheck and production
build pass; seven toolchain tests pass with no skips. No dependency or lockfile
change is used to bypass checks.

## Nine actual Chromium checks

Retained harness: `frontend/scripts/critical-browser.mjs`. It loads the **built**
production console from `frontend/dist`, not a replacement page. Playwright routes
HTTP at synthetic `http://cryptoscan-quality.invalid`, serves the actual built
assets, and supplies explicit synthetic API fixtures. Unexpected API paths return
503 rather than a happy default dataset; other origins are refused by the route
handler. Each case uses a fresh context. Browser page errors fail the run.

Actual environment: Node22.22.3, playwright-core1.64.1,
`@sparticuz/chromium`153.0.0, Chromium **153.0.8010.0**, Linux headless.

| Actual built-browser assertion | Result |
|---|---|
| Operator Decisions: another same-origin window changes estate; old private content clears and new-estate content arrives | PASS |
| Launch Readiness: same cross-window estate change | PASS |
| Evidence: same cross-window estate change | PASS |
| Operator: two native form submit events in one JS turn send exactly one POST | PASS |
| Launch: same native-form single-flight assertion | PASS |
| Operator: old pending write completes after estate change without reviving receipt/draft | PASS |
| Launch: HTTP503 write warns unconfirmed, with no automatic retry | PASS |
| Session401 refusal removes private console content | PASS |
| Audit export: estate change while response is pending prevents a browser download event | PASS |

**Final nine passed; zero captured page errors.** Actual result names/timings are
retained in [results JSON](quality-workflow-results-2026-10-23.json). The earlier
browser binary probe was only a launch check; the final results above come from
the retained full harness against the final build, after the Launch deadline fix.

### Reproduction

Tools intentionally stay outside product dependencies and lockfiles. In the
qualification workspace:

```bash
npm --prefix frontend run build
CRYPTOSCAN_BROWSER_TOOLS=/home/user/quality-browser-tools/node_modules \
LD_LIBRARY_PATH=/home/user/quality-browser-tools/runtime-libs/lib \
node frontend/scripts/critical-browser.mjs
```

For another approved Linux environment, install playwright-core1.64.1 externally,
provide `CRYPTOSCAN_BROWSER_TOOLS=/absolute/external/node_modules`, and either a
compatible actual Chromium path via `CRYPTOSCAN_BROWSER_EXECUTABLE` or the external
Sparticuz package. These are qualification tools, not product runtime dependencies.
The container needed externally extracted NSS/NSPR libraries to launch Chromium;
that workaround is not bank workstation installation guidance. Initial missing
library launch failures are not counted as browser passes.

The harness filters Sparticuz's web-security/site-isolation-disable, insecure
content and single-process flags, but the Lambda-style environment still runs
without normal Chromium sandbox qualification. This is **not browser hardening,
sandbox assurance or security certification**. There is no live server/preview,
production account, real backend, TLS, SSO, bank data or external service traffic.

## Qualification frontier

The browser and native-API workflows are **separate** complementary exercises,
not a full browser→ingress→queue→isolated parser→PostgreSQL bank journey. Actual
bank-managed Windows/Linux/browser versions, enterprise policy, SSO, session
revocation propagation, proxy/certificate behavior, BFCache/sleep/wake behavior,
long-lived tab/capacity endurance, keyboard/screen-reader accessibility, password
manager interactions and representative export sizes still require site evidence.
Only the three named pages and shared downloads are changed; other console pages
are not automatically qualified by sharing the same backend or navigation.
No independent-human review or customer acceptance is fabricated.
