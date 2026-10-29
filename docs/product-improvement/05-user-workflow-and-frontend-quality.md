# 5. Make the existing workflow understandable and safe

[Pack index](README.md) · [Previous: reliability](04-reliability-performance-and-recovery.md) ·
[Next: testing and release](06-testing-maintainability-and-release.md)

## Implemented bounded follow-on — 2026-10-23

The [eighth quality increment](../readiness-evidence/quality-remediation-browser-scope-2026-10-23.md)
implements selected state-matrix/form safeguards in the existing Remediation page:

- Recreate private view/form state on estate/auth events and relevant cross-window
  storage events, even when task IDs coincide across responses.
- Ignore obsolete reads after filter/scope/unmount; distinguish loading from empty
  or unavailable and remove previous counts as well as rows.
- Lock same-turn duplicate lifecycle actions; discard detached replies/callbacks.
- Announce unsuccessful/unconfirmed outcomes and inspect retained history before
  retrying; preserve current-scope drafts and HTTP refusal status, no automatic retry.

**29 new local cases** cover these boundaries; the exact baseline, adverse and
final results are in the dated record/ledger. The requests use existing helper
contracts/timeouts: UI invalidation does not undo a mutation already sent. This
is not a new screen, complete page audit, all-console scope fix, real cross-window
or bank-browser test, accessibility certification or backend authorization result.
The remaining user-task/RTL/zoom/endurance/site requirements below stay open.

## 5.1 Objective: fewer mistakes, not more screens

Improve the existing Scan, evidence/BOM, Operator decisions, remediation and
Launch readiness journeys. Do not add dashboards, menu sections, summary scores
or alternate approval flows. The current console has five sidebar sections with
foldable groups;
use the [navigation reference](../NAVIGATION-FEATURE-REFERENCE.md) rather than
copying an older screenshot or reintroducing retired menu labels.

Useful improvements include clearer existing labels, consistent state rendering,
smaller bounded payloads, keyboard usability, safer form behavior and removal of
duplicate/conflicting instructions. Test them with actual users; visual polish
alone is not evidence of reduced operating error.

## 5.2 The five questions every critical existing view should answer

1. **Where am I?** Exact selected estate, application/release and relevant scope.
2. **What happened?** Durable result/status, observation time and freshness—not
   just the latest browser refresh time.
3. **Why should I trust it?** Evidence IDs, provenance, limitations and review state.
4. **What is missing?** Coverage, unavailable sources, partial results and unknowns.
5. **What may I do next?** Authorized action, required reviewer and refusal/conflict guidance.

Use the existing [Operator decisions contract](../bank-environment/53-operator-decision-workflow.md)
as the model. Keep its five decisions, bounded pages and periodic SQL reconciliation;
do not replace them with another aggregate score.

## 5.3 Walk the complete existing user journey

| Step | Improve/check on the current surface | User must not conclude |
|---|---|---|
| Sign in/select estate | Server-verified identity, visible scope, no old-estate content during transition | Local storage or a menu role authorizes an action. |
| Review coverage | Expected register, per-kind states, freshness, register-completeness assertion | The current page or discovered inventory is the whole bank. |
| Submit admitted source work | Clear supported input/limits, permission and durable job reference | HTTP acknowledgement means parsing finished. |
| Follow progress | Queued/deferred/running/partial/refused/failed/UNKNOWN are distinguishable | A spinning indicator means a collector is currently running. |
| Inspect six-BOM evidence | Distinguish observed, reviewed/declared, stale, unresolved and unqualified | All six layers independently verify deployment/runtime truth. |
| Assess a condition | Original finding versus contextual assessment and recommendation | A contextual edit rewrote the observation or closed a vulnerability. |
| Assign/propose change | Exact owner, approved predicate and current revision | Creating a ticket changes production. |
| Independent approval | Entitled different reviewer, scope and evidence visible before confirmation | The proposer can approve their own risk. |
| Report completion/verify | Separate actions; show actual completion time and later proof result | Completed ticket or no findings means VERIFIED. |
| Review/export/accept | Current evidence fingerprint, limitations and distinct technical/customer reviews | A downloaded report is current after evidence changes. |

## 5.4 Required state matrix

Run each selected critical surface through the relevant cases, with the backend
contract as authority. This is a recommended acceptance matrix, not a claim that
these states are currently broken.

| State | Required existing-view behavior |
|---|---|
| Initial loading | No previous-estate details or premature zero/safe values. |
| Genuine empty result | State that no retained observations exist in this scope; distinguish unattempted coverage. |
| Populated result | Counts, page limits, provenance and times agree with API/retained evidence. |
| Partial/truncated result | Show limitation and affected scope; do not claim completeness. |
| Stale evidence | Preserve historical observation but distinguish current validity/acceptance. |
| Denied/unauthenticated | Explain permitted reauthentication/access path without leaking foreign IDs. |
| Dependency unavailable | Clear or unmistakably invalidate a prior successful view; no zero-risk/demo substitute. |
| Revision conflict | Do not silently overwrite or retry; reload retained history and require fresh intent. |
| Estate/auth change during request | Abort/ignore old-generation responses; reset private evidence, forms and selections. |
| Mutation timeout/disconnect | Say outcome is not confirmed; inspect durable history before retrying. |
| Stream gap/reset/reconnect | Reconcile SQL-backed state and disclose the gap until refreshed; no event-only assumption. |
| Long-running/hidden tab | Bound requests/memory; reconcile on visibility return, without timer accumulation. |

The initial CBOM SSE `: connected` line is a transport comment, not a data record.
An idle connected stream must not fabricate observations or improve a coverage count.

## 5.5 Forms and actions: make a safe decision easier

Recommended improvements within current forms:

- Make required identity, evidence, expiry and revision inputs understandable with
  existing field descriptions; remove instructions that imply unsupported collection.
- Keep backend validation/refusal meaning intact; translate presentation, not authority.
- Before an approval, show the exact immutable revision/target/predicate being approved.
- Preserve useful nonsecret input after ordinary validation errors, but clear it
  on estate/auth changes; never persist sensitive drafts to browser storage.
- Disable duplicate submission while the current attempt is in flight. A timeout
  still requires durable-history reconciliation, not an automatic mutation retry.
- Do not expose a self-approval shortcut, default real owner or fabricated evidence.
- Show reported completion separately from verified condition and current acceptance.
- Use the existing review workflow for risk decisions; a dismiss button is not an audit exception.

Do not build a new guided wizard unless separately authorized; the scope here is
clarifying and correcting existing controls/actions.

## 5.6 Accessibility, language and responsive behavior

Exercise the existing critical journey using:

1. Keyboard-only navigation, visible focus, sensible order and no focus trap.
2. Screen-reader names for actions, fields, status/errors and current dialog context.
3. Status distinctions that do not depend on color, animation or icon alone.
4. Zoom/narrow viewport and long IDs/text without hiding evidence or confirmation actions.
5. English and Arabic/RTL placement, validation messages, timestamps and technical identifiers.
6. Reduced-motion preference; no essential information conveyed only by animation.
7. Drawer/dialog opening, closing and return focus, including a failed API request.

Use suitable browser/accessibility checks plus human task observation. A DOM
smoke test, build pass or Lighthouse-style score alone is not accessibility
certification or bank workstation qualification. Do not add a broad device-support
claim without retaining the browser/version/environment actually tested.

## 5.7 Real browser endurance and network behavior

The existing simulated long-timer tests are useful regressions, not elapsed-time
browser measurements. Rehearse the actual operating period on the intended
workstation/network. Record browser version, tabs, actions, dataset, heap/CPU,
pending requests, reconnects and any task failures.

Check repeated navigation, estate switching, session expiry, idle/resume and
intermittent permitted network loss. No unbounded list append, leaked listener,
background polling storm or old-estate render is acceptable. Use existing
visibility/bounded-poll patterns rather than remove periodic reconciliation for speed.

## 5.8 Usability measures without invented targets

Before changing a screen, observe representative authorized users completing the
same task. Record:

- whether they choose the intended estate and understand supported scope;
- task completion/errors and time, including denied/degraded cases;
- whether they distinguish observation, assertion, completion, verification and acceptance;
- number of avoidable retries/escalations and explanations they misunderstood;
- accessibility blockers and evidence they needed but could not find.

Agree success criteria before comparing the revised UI. Faster clicks are not an
improvement if the user approves the wrong target or mistakes UNKNOWN for safe.
Keep customer recordings/data under approved consent, access and retention.

## 5.9 Exit criteria

A representative operator and a separate reviewer complete the same supported
journey using the existing screens, interpret negative/unknown states correctly,
and can retrieve the exact proof. No new screen or unsafe shortcut is required.
Backend refusal, estate isolation and evidence semantics remain unchanged.
