# Frontend production hardening — behaviour, not reach

`cryptoscan.frontend-hardening/1` · generated 2026-11-01T02:37:44.149200+00:00 · **5 pass · 4 partial · 0 fail**

Each row reads `frontend/src` and grades one behaviour the review named. The counts that produced the verdict are in the table and in the JSON.

| Behaviour | Verdict | Measured |
|---|---|---|
| **how much of the API surface does the console reach, and how tightly is it typed?** | **PARTIAL** | 537/1141 endpoints (47.1%), 141 typed call sites, 0 with no route |
| **when a read fails, does the console say so rather than render an empty list?** | **PARTIAL** | 407 failure branches, 1 silent readers |
| **is an empty result explained, or shown as a blank panel?** | **PASS** | 164 explained empty states (103 as role=status), 3 asserted in tests |
| **is a large estate bounded on screen, and does the screen say it was bounded?** | **PASS** | 40 collection cuts in 23 files, 0 silent; 56 pagination sites |
| **does the live view resume after a disconnect, and say when it cannot?** | **PASS** | 2 stream, 2 resume |
| **does the console reflect what the signed-in operator is allowed to do?** | **PASS** | 68 gating sites in 5 files |
| **can an operator see who did what, and when, from the console?** | **PARTIAL** | 0 dedicated audit pages, 18 audit API calls in 6 files |
| **does a screen distinguish 'nothing there' from 'nothing observed'?** | **PASS** | 482 coverage mentions |
| **how many console pages have a rendered test?** | **PARTIAL** | 49/100 pages tested (49.0%) |

## Row by row

### `contract_coverage` — PARTIAL

*how much of the API surface does the console reach, and how tightly is it typed?*

- **Reading:** the console covers half the surface, which is expected: it is an operator console, not a complete API client, and the uncovered half is CLI and drill traffic
- **Limit:** reach is not correctness: a page that calls an endpoint and misreads the payload is counted here

```
{
  "served_paths": 1141,
  "distinct_paths_called": 536,
  "reachable_from_console": 537,
  "coverage_percent": 47.1,
  "calls_with_no_route": 0,
  "typed_call_sites": 141,
  "loose_record_types": 328
}
```

### `error_handling` — PARTIAL

*when a read fails, does the console say so rather than render an empty list?*

- **Reading:** most surfaces distinguish 'not read' from 'nothing there', which is the distinction that matters on a bank screen
- **Gap:** 1 component(s) read an API with no failure branch
- **Limit:** static: a branch that exists but is unreachable would still be counted

```
{
  "files_reading_an_api": 15,
  "error_render_sites": 407,
  "explicit_not_read_messages": 327,
  "alert_roles": 48,
  "files_that_read_without_a_failure_branch": [
    "frontend/src/lib/apiUi.tsx"
  ],
  "silent_count": 1
}
```

### `empty_states` — PASS

*is an empty result explained, or shown as a blank panel?*

- **Reading:** empty states carry their own test id so a rendered test can assert the wording
- **Limit:** a test id is a hook; it does not prove the sentence is accurate

```
{
  "empty_state_testids": 1,
  "status_roles": 103,
  "explanatory_copy_sites": 60,
  "explained_states_total": 164,
  "empty_state_assertions_in_tests": 3
}
```

### `large_graphs` — PASS

*is a large estate bounded on screen, and does the screen say it was bounded?*

- **Reading:** panels scroll, the busiest pages paginate, and every list that is cut to a fixed length says so — a partial estate that reads as a complete one is how a screen produces false assurance
- **Limit:** the collection/identifier distinction is a name heuristic: a list held in a variable called `algs` would be missed. No measurement of DOM cost at 100k nodes either: this proves the guards and their captions exist, not that a browser stays responsive behind them.

```
{
  "files_truncating_a_collection": 23,
  "collection_truncations": 40,
  "files_truncating_without_a_notice": [],
  "silent_truncation_count": 0,
  "silent_truncation_percent": 0.0,
  "scroll_bounds": 81,
  "pagination_sites": 56,
  "truncation_notices": 92
}
```

### `realtime` — PASS

*does the live view resume after a disconnect, and say when it cannot?*

- **Reading:** the stream resumes from the last event id, reconnects with backoff, and the API reports a replay gap rather than silently skipping events (guide 96)
- **Limit:** the browser path is exercised in a jsdom test, not in a real browser against a real proxy that may buffer the stream

```
{
  "stream_files": [
    "frontend/src/lib/realtime.test.tsx",
    "frontend/src/lib/realtime.tsx"
  ],
  "resume_files": [
    "frontend/src/lib/maturity.ts",
    "frontend/src/lib/realtime.tsx"
  ],
  "reconnect_files": [
    "frontend/src/lib/realtime.tsx"
  ],
  "gap_handling_files": [
    "frontend/src/lib/api.ts",
    "frontend/src/pages/LiveMonitor.viz.test.tsx"
  ],
  "realtime_tests": [
    "frontend/src/lib/realtime.channels.test.tsx",
    "frontend/src/lib/realtime.test.tsx"
  ]
}
```

### `authorization_views` — PASS

*does the console reflect what the signed-in operator is allowed to do?*

- **Reading:** visibility is derived from the session's roles and a refused request renders as a refusal rather than an empty table
- **Limit:** the API is the enforcement point; a hidden button is a usability choice, and this row does not prove every mutation is hidden from an unauthorised role

```
{
  "gating_sites": 68,
  "gated_files": [
    "frontend/src/components/EnterpriseModals.tsx",
    "frontend/src/components/EstateSchedulePanel.tsx",
    "frontend/src/lib/auth.tsx",
    "frontend/src/pages/InviteAccept.tsx",
    "frontend/src/pages/Tenancy.tsx"
  ],
  "denied_state_copy": 125
}
```

### `auditability` — PARTIAL

*can an operator see who did what, and when, from the console?*

- **Reading:** audit and approval surfaces read the API's own record rather than a client log
- **Gap:** no dedicated audit page; the trail is read inside the administration and evidence surfaces
- **Limit:** the audit rows themselves are produced server-side; this row only checks the console reads them

```
{
  "audit_surfaces": [],
  "audit_callers": [
    "frontend/src/App.navigation.test.tsx",
    "frontend/src/App.test.tsx",
    "frontend/src/App.tsx",
    "frontend/src/pages/Evidence.test.tsx",
    "frontend/src/pages/Evidence.tsx",
    "frontend/src/pages/Security.tsx"
  ],
  "audit_api_calls": 18,
  "actor_timestamp_fields": 100
}
```

### `degraded_coverage` — PASS

*does a screen distinguish 'nothing there' from 'nothing observed'?*

- **Reading:** coverage and UNKNOWN are rendered as their own states across the estate and BOM screens, which is the distinction the review asked for
- **Limit:** static counts: whether a specific panel labels a dark plane correctly is not verified per panel

```
{
  "coverage_mentions": 482,
  "unknown_copy_sites": 917
}
```

### `page_test_coverage` — PARTIAL

*how many console pages have a rendered test?*

- **Gap:** 51 page(s) have no rendered test

```
{
  "pages": 100,
  "test_files": 90,
  "pages_with_a_test": 49,
  "coverage_percent": 49.0,
  "pages_without_a_test": [
    "Agility",
    "Alerts",
    "AssuranceCoverage",
    "AssuranceQualification",
    "AssuranceRecords",
    "AssuranceSampling",
    "AssuranceTrace",
    "Automation",
    "Catalog",
    "Cloud",
    "CryptoAssets",
    "CryptoChanges",
    "Executive",
    "Hardware",
    "Identity"
  ]
}
```

## Negative control

the same graders run against a copy with failure branches, empty-state copy, gating, pagination, resume and tests removed.

Stripped run: **{'PASS': 0, 'PARTIAL': 6, 'FAIL': 3}**

| Behaviour | Real | Stripped |
|---|---|---|
| `contract_coverage` | PARTIAL | PARTIAL |
| `error_handling` | PARTIAL | PARTIAL |
| `empty_states` | PASS | PARTIAL |
| `large_graphs` | PASS | PARTIAL |
| `realtime` | PASS | PARTIAL |
| `authorization_views` | PASS | FAIL |
| `auditability` | PARTIAL | PARTIAL |
| `degraded_coverage` | PASS | FAIL |
| `page_test_coverage` | PARTIAL | FAIL |

## What this does not prove

- Static analysis of frontend/src. Nothing was rendered, and no browser was involved: a page whose failure branch exists but never triggers still passes.
- Reach is measured against the API's own schema; a console call that names a real path may still send the wrong body.
- Accessibility, internationalisation coverage and bundle size are not measured.

**The verdict this audit supports:** the console handles failure, emptiness, bounded lists, realtime resume and degraded coverage far better than the reach number suggested. What it does **not** do uniformly is reflect the operator's authority — gating exists, but it is not applied across the write surfaces — and about a third of the pages have no rendered test. Both are named above rather than folded into an average.
