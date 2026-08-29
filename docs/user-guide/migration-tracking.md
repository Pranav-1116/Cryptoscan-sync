# Migration Project Tracking

Track crypto migrations end to end: projects → granular tasks → milestones,
with derived progress, velocity forecasting, roadblocks, and an honest
external-tracker boundary (GitHub Issues / JIRA).

## Concepts

- **Project** — a migration effort (`POST /api/v1/migrations`), e.g.
  "RSA → PQC for payments".
- **Task** — one concrete unit (usually one asset/site to move), with
  priority (P0–P3), effort, owner, status `TODO / IN_PROGRESS / DONE /
  SKIPPED / BLOCKED`. A `BLOCKED` task **requires** `blocked_reason` —
  roadblocks are first-class, not comments.
- **Milestone** — a dated target; status (`PLANNED / AT_RISK / ACHIEVED /
  MISSED`) is recomputed from real progress and the forecast, never set
  by hand.
- The project's `progress` and `status` are **derived from tasks** — they
  update automatically; hand-editing them is ignored on the next task change.

## Auto-create from a scan

```
POST /api/v1/migrations/from-scan
{"scan_id": "<id>", "owner": "platform-team"}
→ project + one prioritized task per failing finding
  (from the deterministic remediation engine; P0–P3, effort, replacement)
```

Every task carries its `evidence_id` back to the immutable evidence chain.

## Progress & forecasting

```
GET /api/v1/migrations/{id}/progress    # task-based + asset-based %, per-priority, roadblocks[]
GET /api/v1/migrations/{id}/forecast    # velocity (tasks/week from completed_at history),
                                        # weeks-to-completion, ETA vs milestone target,
                                        # ON_TRACK / AT_RISK / LATE-style recommendation
```

Velocity is measured, not guessed: tasks/week from actual `completed_at`
history. No target date → the forecast says so instead of inventing one.

## External trackers (GitHub Issues / JIRA)

There is no live two-way sync without real credentials — instead a clean,
scriptable boundary:

1. **Export** for bulk import:
   `GET /api/v1/migrations/{id}/export/github-issues`
   → `[{title, body, labels, external_id_hint}]` for `gh issue create -f …`
2. **Attach** the tracker's ids: `PATCH /api/v1/migrations/tasks/{task_id}`
   `{"external_ref": "ISSUE-42"}`
3. **Push back** status changes (webhook or cron):
   `POST /api/v1/migrations/{id}/sync`
   `{"updates": [{"external_ref": "ISSUE-42", "status": "DONE"}]}`
   → unknown refs and invalid statuses are reported, never silently dropped.

## Typical flow

```
from-scan → tasks (P0 first)
  → add milestone "DORA wave 1" (target date)
  → team works tasks; BLOCKED entries record vendor/infra roadblocks
  → forecast flags AT_RISK with "need X tasks/week vs current Y"
  → export issues → external tracker → sync completions back
  → milestone flips ACHIEVED (or MISSED) automatically
```
