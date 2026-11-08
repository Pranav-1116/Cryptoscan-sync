# Step 7 — make existing operator tasks understandable and recoverable

**2026-10-23 UTC.** No new screen. Changes concentrate on the existing Launch
readiness form, shared live-read feedback and authenticated shell. This is
executed engineering evidence, **not representative-user acceptance**.

## The existing task and its failure paths

An operator selects the correct bank estate, reads retained IDs/revisions,
examines a current gate, then submits a reviewed revision-checked JSON action.
They must know whether an action was refused, merely acknowledged, historically
verified, or still supported by current evidence. A short successful response
must not become a misleading green estate assessment.

| Situation | Current behavior | Why it matters for a bank operator |
|---|---|---|
| Select an estate | Visible selected-estate text next to the form; direction-isolated estate name. Scope/auth changes still fence old replies and clear private drafts. | Avoids submitting an old bank's body into a newly selected estate. Keeping useful input applies **within** the same authorized context, not across a scope switch. |
| An ID-bound read/action is disabled | Visible help says to enter the exact record ID; `aria-describedby` associates the explanation. Controls remain genuinely disabled. | Disabled is not silently treated as permission denial, backend outage or a completed action. |
| Invalid JSON / non-object input | No POST; safe feedback receives focus; record ID and textarea remain. Repeating the identical invalid submission focuses feedback again. | React's same-value state bailout used to leave repeated feedback unfocused; fixing it does not require destroying useful drafts. |
| HTTP400/422 validation refusal | Explicit validation rejection and correction guidance; useful input retained; server detail/body is never echoed. | Schema rejection is different from a possibly retained write. Sensitive server/JSON canaries are checked absent from feedback. |
| HTTP409 | Reconcile current history/authority and expected revision; do not blindly increment or retry. | A conflict can mean another authorized person changed the record, not that retrying is safe. |
| HTTP401/403 | Authentication/access refusal; retain the draft only while the existing context remains valid. | Re-establishing authority is not an automatic authorization bypass or write replay. |
| Transport error, uncertain HTTP result, invalid successful body | Outcome unconfirmed; reconcile retained history before retrying. | A server may have committed before the client lost the receipt. No mutation is automatically replayed. |
| Action/body never settles | Visible action state bounded at20seconds; abort, unlock, explicit uncertainty; ignore late success. | Abort is not rollback. A non-cooperative body reader cannot keep the console locked forever or display a late stale receipt. |
| Loading operating records | Explicit loading state; no old success substituted. | Loading must not look like an empty estate. |
| Empty successful response | No duties returned, explicitly not proof of coverage. | Zero returned records is not zero risk. |
| Dependency unavailable | Unavailable, not empty; old operating content cleared by the existing read fence. | A failed dependency must not create a green default. |
| Incomplete duties | Partial evidence with unresolved duties; underlying retained record still inspectable. | A few reviewed duties do not represent all nine. |
| Retained history / POST receipt / current gate | Separate labels: history is not current proof; accepted write is not independently verified success; current read can still report blockers. | Historical verification survives while current proof can expire, be withdrawn or become unavailable. |

Input is deliberately cleared when changing action type or private context, not
after an ordinary validation error. Private keys still do not belong in the
JSON form. This increment does not replace API schemas with a new wizard or
claim field-by-field validation coverage for every action.

## Keyboard, focus and actual browser execution

The retained [browser result](quality-usability-release-operations-2026-10-23/browser.json)
contains15 passing built-console Chromium cases with zero page errors. Four
added cases exercise:

1. Keyboard focus to the JSON field, native keyboard submission, safe feedback
   focus, retained draft and no malformed POST.
2. Disabled ID-bound action with visible reason; HTTP422 keeps the draft and
   makes exactly one POST, without raw server detail or automatic retry.
3. Arabic RTL surroundings, LTR IDs/JSON and2× device scale with640CSS-pixel reflow.
4. The same at4× device scale and320CSS-pixel reflow.

The other11 cases continue exercising existing private-scope, same-turn
single-flight and late-result/download fences. HTTP is stubbed and every
identity/value is synthetic. The suite is not a real tenant/backend, SSO,
workstation, screen reader or end-to-end bank integration test.

### Two real browser defects found and fixed

**The shell imported but never rendered the existing language switcher.**
The new shell integration test failed because the Arabic button was absent;
the browser could not select Arabic either. The fix renders the existing
component in the existing header. Its buttons now expose `lang`,
`aria-pressed`, `type=button` and grouped labeling. It does not create another
language-selection screen or mutate the selected bank estate.

**The CSS cascade broke narrow/zoom-equivalent layouts.** A later900px rail rule
reinstated a76px sidebar after the older phone rule, while main content remained
in column1. At320CSS pixels the actual Launch content measured **40px client /
241px scroll**, so the browser correctly failed. A late560px single-column
`minmax(0,1fr)` override, explicit main column, bounded sidebar, zero search
minimum width and non-sticky narrow header correct that conflict. No assertion
was loosened to accept the clipped form. See the preserved
[reflow failure](quality-usability-release-operations-2026-10-23/browser-reflow-red.json).

### What zoom and Arabic checks do not establish

The browser uses CDP viewport/device-scale emulation:2×/640 and4×/320. This is
**not native desktop browser-menu200%/400% zoom**. It does not establish OS font
scaling, every supported browser, Arabic glyph quality or manual accessibility
conformance.13 paired safety labels and existing dictionary fallback are used;
most existing action names/schema instructions remain English. Arabic is
**partial**, not a professionally reviewed complete translation. Native zoom,
RTL visual reading order, long names, focus visibility and assistive technology
must be checked on the bank's supported workstation matrix.

## Representative-user acceptance — not executed

Do not mark this step complete merely because automated tests pass. Have actual
bank operators, an independently authorized reviewer and Arabic-reading users
perform the existing tasks on an approved synthetic acceptance estate:

| Task | Required observation, including failure | Evidence to retain |
|---|---|---|
| Choose bank A, read retained revisions, inspect a current gate | User identifies the active estate and explains why history is not current proof. | Consented session identifier, role, build/digest and unprompted explanation. |
| Attempt an ID-required action without an ID | User understands the unavailable action and obtains the correct scoped ID. | Task outcome, confusion/errors and whether help was required. |
| Submit malformed JSON, then schema-invalid JSON | User corrects both without losing useful input and does not interpret refusal as success. | Validation path, focus/keyboard behavior, submitted request count. |
| Simulate a lost receipt after server acceptance | User reconciles current history before resubmitting. | History inspected, no blind duplicate write, final understood state. |
| Switch estate or expire authority with a request pending | No old private reply/draft appears in the new context; user recognizes the change. | Old/new scope, late-reply observation, subsequent authorized read. |
| Read empty, unavailable and partial operating evidence | User distinguishes all three and does not announce an all-clear. | Their interpretation and escalation decision. |
| Use keyboard, native zoom and Arabic/RTL | Task remains understandable and operable, technical fields readable in LTR. | Actual browser/OS/zoom/assistive technology, failures, remediation and retest. |

Agree participants, task success criteria, acceptable help, accessibility matrix
and evidence handling **before** running the sessions. Record attempts and
failures, not just successful demonstrations; obtain separate acceptance review.
No participants, success rate or sign-off is invented here.
