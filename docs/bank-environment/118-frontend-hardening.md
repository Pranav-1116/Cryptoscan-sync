# Frontend production hardening — behaviour, not reach

`cryptoscan.frontend-hardening/1` · generated 2026-11-02T10:30:18.031198+00:00 · **8 pass · 1 partial · 0 fail**

Each row reads `frontend/src` and grades one behaviour the review named. The counts that produced the verdict are in the table and in the JSON.

| Behaviour | Verdict | Measured |
|---|---|---|
| **how much of the API surface does the console reach, and how tightly is it typed?** | **PARTIAL** | 537/1147 endpoints (46.8%), 141 typed call sites, 0 with no route |
| **when a read fails, does the console say so rather than render an empty list?** | **PASS** | 415 failure branches, 0 silent readers |
| **is an empty result explained, or shown as a blank panel?** | **PASS** | 171 explained empty states (109 as role=status), 3 asserted in tests |
| **is a large estate bounded on screen, and does the screen say it was bounded?** | **PASS** | 40 collection cuts in 23 files, 0 silent; 60 pagination sites |
| **does the live view resume after a disconnect, and say when it cannot?** | **PASS** | 2 stream, 2 resume |
| **does the console reflect what the signed-in operator is allowed to do?** | **PASS** | 68 gating sites in 5 files |
| **can an operator see who did what, and when, from the console?** | **PASS** | 1 dedicated audit pages, 26 audit API calls in 8 files |
| **does a screen distinguish 'nothing there' from 'nothing observed'?** | **PASS** | 482 coverage mentions |
| **how many console pages have a rendered test?** | **PASS** | 65/102 pages tested (63.7%) |

## Row by row

### `contract_coverage` — PARTIAL

*how much of the API surface does the console reach, and how tightly is it typed?*

- **Reading:** reach is a product decision, not a defect: this is an operator console, not a complete API client, and the uncovered half is CLI and drill traffic — every call it does make names a route the API serves
- **Limit:** the gap this row really measures is typing: a few hundred call sites return `Record<string, unknown>`, so most payloads the console reads are an unchecked claim; the percentage is reach and says nothing about whether a page misreads what it reached

```
{
  "served_paths": 1147,
  "distinct_paths_called": 537,
  "reachable_from_console": 537,
  "coverage_percent": 46.8,
  "calls_with_no_route": 0,
  "typed_call_sites": 141,
  "loose_record_types": 329
}
```

### `error_handling` — PASS

*when a read fails, does the console say so rather than render an empty list?*

- **Reading:** most surfaces distinguish 'not read' from 'nothing there', which is the distinction that matters on a bank screen
- **Limit:** static: a branch that exists but is unreachable would still be counted

```
{
  "files_reading_an_api": 15,
  "error_render_sites": 415,
  "explicit_not_read_messages": 335,
  "alert_roles": 52,
  "files_that_read_without_a_failure_branch": [],
  "silent_count": 0
}
```

### `empty_states` — PASS

*is an empty result explained, or shown as a blank panel?*

- **Reading:** empty states carry their own test id so a rendered test can assert the wording
- **Limit:** a test id is a hook; it does not prove the sentence is accurate

```
{
  "empty_state_testids": 1,
  "status_roles": 109,
  "explanatory_copy_sites": 61,
  "explained_states_total": 171,
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
  "pagination_sites": 60,
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
  "denied_state_copy": 126
}
```

### `auditability` — PASS

*can an operator see who did what, and when, from the console?*

- **Reading:** audit and approval surfaces read the API's own record rather than a client log
- **Limit:** the audit rows themselves are produced server-side; this row only checks the console reads them

```
{
  "audit_surfaces": [
    "frontend/src/pages/Audit.tsx"
  ],
  "audit_callers": [
    "frontend/src/App.navigation.test.tsx",
    "frontend/src/App.test.tsx",
    "frontend/src/App.tsx",
    "frontend/src/components/Layout.tsx",
    "frontend/src/pages/Audit.test.tsx",
    "frontend/src/pages/Audit.tsx",
    "frontend/src/pages/Evidence.test.tsx",
    "frontend/src/pages/Evidence.tsx"
  ],
  "audit_api_calls": 26,
  "actor_timestamp_fields": 122
}
```

### `degraded_coverage` — PASS

*does a screen distinguish 'nothing there' from 'nothing observed'?*

- **Reading:** coverage and UNKNOWN are rendered as their own states across the estate and BOM screens, which is the distinction the review asked for
- **Limit:** static counts: whether a specific panel labels a dark plane correctly is not verified per panel

```
{
  "coverage_mentions": 482,
  "unknown_copy_sites": 921
}
```

### `page_test_coverage` — PASS

*how many console pages have a rendered test?*

- **Gap:** 37 page(s) have no rendered test

```
{
  "pages": 102,
  "test_files": 108,
  "pages_with_a_test": 65,
  "coverage_percent": 63.7,
  "pages_without_a_test": [
    "Integrations",
    "InviteAccept",
    "Libraries",
    "LiveAssetIntelligence",
    "LiveEnvironment",
    "Migration",
    "Nbom",
    "Onboarding",
    "Organization",
    "PlatformP2",
    "Pqc",
    "PqcMap",
    "Protocols",
    "ResetPassword",
    "Resilience"
  ]
}
```

## Negative control

the same graders run against a copy with failure branches, empty-state copy, gating, pagination, resume and tests removed.

Stripped run: **{'PASS': 0, 'PARTIAL': 5, 'FAIL': 4}**

| Behaviour | Real | Stripped |
|---|---|---|
| `contract_coverage` | PARTIAL | PARTIAL |
| `error_handling` | PASS | PARTIAL |
| `empty_states` | PASS | PARTIAL |
| `large_graphs` | PASS | PARTIAL |
| `realtime` | PASS | PARTIAL |
| `authorization_views` | PASS | FAIL |
| `auditability` | PASS | FAIL |
| `degraded_coverage` | PASS | FAIL |
| `page_test_coverage` | PASS | FAIL |

## What this does not prove

- Static analysis of frontend/src. Nothing was rendered, and no browser was involved: a page whose failure branch exists but never triggers still passes.
- Reach is measured against the API's own schema; a console call that names a real path may still send the wrong body.
- Accessibility, internationalisation coverage and bundle size are not measured.

**The verdict this audit supports:** the console handles failure, emptiness, bounded lists, realtime resume, operator authority and the audit trail far better than the reach number suggested, and the audit trail now has a surface of its own instead of a redirect. What is **not** closed is typing: most payloads the console reads are still `Record<string, unknown>`, so the percentage above measures how much of the API it touches, not whether it reads the answer correctly. That, the pages without a rendered test, and a browser run at estate scale are named above rather than folded into an average.
