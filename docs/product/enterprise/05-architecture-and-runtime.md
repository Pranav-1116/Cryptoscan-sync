# Architecture and runtime

## 1. Architectural intent

CryptoScan separates collection, integrity, inventory, assessment, analysis,
workflow, and presentation. The separation is important: the scanner collects
facts; the policy engine decides from versioned rules; the report explains the
stored result; no UI component is the source of truth.

```text
React console / API clients / CI / webhooks
                    |
             FastAPI API tier
      auth · RBAC · tenancy · rate · audit
                    |
       control plane · event stream · API routers
          |             |             |
       worker         monitor       connectors
          |             |             |
     collectors     schedules       external systems
          |
 evidence -> normalize -> inventory -> policy/analysis
          |         |          |          |
       PostgreSQL  Redis    optional graph  artifact storage
```

The repository's [system overview](../../architecture/system-overview.md),
[service map](../../architecture/service-map.md), and [end-to-end architecture](../../END-TO-END-ARCHITECTURE.md)
remain the detailed architecture authorities.

## 2. Runtime processes

### API and control plane

The API authenticates callers, resolves scope, validates payloads, applies role
and permission checks, records administrative activity, and invokes or queues
work. It should remain stateless between requests except for the session,
queue, database, and configured caches.

### Worker

The worker executes potentially long-running scans outside the request path.
The job payload must carry enough scope and ownership context for a worker with
no browser session to re-enter the correct tenant or customer estate. A worker
must not silently write unscoped rows when scope resolution fails.

### Monitor and scheduled work

The monitor evaluates configured targets and schedules. It should skip
suspended, disabled, or unauthorized targets and produce an attributable usage
or execution record for every actual run.

### Event stream

Events are persisted or recoverable before they are delivered to the console.
SSE, WebSocket, Redis federation, and database-tail behavior are delivery
mechanisms; they are not the record of what happened. A reconnecting client
must be able to refresh state from the API.

### Dashboard

The React application renders API state and maturity labels. It must not
manufacture data for empty, offline, skipped, or unavailable sources. A UI
number is meaningful only when its source query, scope, and freshness are
known.

## 3. Service boundaries

| Boundary | Responsibility | Failure isolation |
|---|---|---|
| Scanner | Parse and detect observations | Unsupported input becomes a warning or explicit skip |
| Evidence | Canonicalize, hash, chain, manifest, verify | Tampered or incomplete chain fails verification |
| Database | Persist transactional state | Migrations and constraints protect state shape |
| Queue | Decouple jobs and API | Job retry/lease/dead-letter behavior is observable |
| Policy | Evaluate declared rules | Unknown condition or missing scope does not become PASS |
| Graph | Reachability and dependency relationships | Optional graph failure must be visible and not erase relational data |
| Reporting | Render reports and exports | Export carries source and integrity metadata |
| Connector | Deliver approved payloads | Preview, idempotency, timeout, and retry are required |
| Identity | Authenticate and authorize | Fail closed on invalid or ambiguous scope |

## 4. Request and job path

For every request, the effective order is:

1. transport and request ID;
2. authentication or public-health exception;
3. session/API-key validation;
4. tenant or customer context resolution;
5. suspension and permission checks;
6. input and scope validation;
7. rate and quota checks;
8. database transaction or job enqueue;
9. audit record for sensitive action; and
10. response with a stable identifier and status.

For supported queued execution, distinguish transport from authority:

1. consume the untrusted descriptor using configured delivery/lease handling;
2. reconcile owner, target, actor, type, system and scan options against SQL
   **before** selecting scope; replace progress with database progress;
3. enter the persisted estate and run current execution-policy admission;
4. re-read the pinned current initiating user/key/config authority;
5. commit an exact-owner/version QUEUED-to-RUNNING claim;
6. invoke the collector and persist progress/evidence/outcomes; and
7. retain acknowledgement/dead-letter context without treating delivery recovery
   as permission to replay RUNNING side effects.

This is not a global distributed concurrency reservation or exactly-once external
execution guarantee. See [authority design](../../bank-environment/44-queued-authority-and-durable-ssh.md).

## 5. Storage model

PostgreSQL is the system of record for production-like deployments. SQLite is
a development convenience and must not be used as a production approval without
an explicit architecture decision. Redis supports queue and event behavior.
Neo4j is optional for graph workloads where configured.

Storage responsibilities should be kept separate:

- relational rows hold identity, ownership, job, policy, finding, and workflow
  state;
- evidence records hold canonical observations and chain links;
- object/artifact storage holds larger reports, packs, and release artifacts;
- Redis holds transient queue/event state according to retention policy; and
- graph storage materializes relationships that can be rebuilt or reconciled.

## 6. Security design principles

- authentication is separate from authorization;
- API keys are scoped to machine use and are revocable;
- tenant or customer context is established before data access;
- sensitive values are redacted before evidence leaves the collection boundary;
- audit events are chained and exportable;
- production guards reject unsafe development defaults;
- rate limiting is an inner defense and not a replacement for edge controls;
- database, queue, graph, and artifact storage are not directly public; and
- health endpoints reveal only the minimum status required for operations.

## 7. Scaling and failure model

Scale the API, worker, monitor, queue, database, graph, and artifact layers
independently only after measuring the actual bottleneck. Adding API replicas
does not automatically make in-process rate limits, scheduler locks, event
federation, or tenant isolation distributed.

When a dependency fails:

- preserve the job and last known state;
- make the failure visible to the operator;
- do not convert missing data into zero or PASS;
- retry only when the action is safe and idempotent; and
- record recovery and any period of incomplete coverage.

## Retained replay and primary changes

Unified streams read independent exact-estate journals; Pub/Sub/queues are only
wakeups. Opaque cursors freeze retained snapshot bounds and fresh authority is
checked on replay/live/idle paths. Production factory/Sentinel clients bind epochs
to the actual primary process. Promotion/restart requires explicit old-cursor
resynchronization, not silent frozen-snapshot continuation. Verified TLS/ACLs,
command readiness and subscriber reconnect are implemented for realtime/current
run; they do not migrate every Redis consumer or certify lossless replication.
See [current API semantics](../../api-reference/execution-and-replay.md).

## Current-reading update — 2026-10-22

Broad repository service diagrams are not the controlled production enablement list. Current local-source/v1 execution, isolated parser, external PostgreSQL and verified-TLS Redis are the operator-package contract; graph/other unqualified adapters remain refused.

See [current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md),
[CI/build contract](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
[operator install/upgrade/recover](../../runbooks/operator-install-upgrade-recover.md).
