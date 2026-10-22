# Controlled execution: approvals, isolation and unknown outcomes

**Engineering increment: 2026-10-21; migration `0102`. Not a production qualification.**

## Read this before upgrading — deliberately breaking production boundary

`ENVIRONMENT=production` requires execution controls; setting
`CRYPTOSCAN_EXECUTION_CONTROLS=false` does **not** bypass them. Development/test
can exercise the same boundary with the **exported environment variable**
`CRYPTOSCAN_EXECUTION_CONTROLS=true`. Existing non-production compatibility paths
are not a bank deployment profile.

The implemented controlled adapter is **`local-source/v1` only**. This is an
API/worker safety slice, **not full-product availability**. The production API
allowlist permits authentication/account administration, `/execution-controls/*`,
manual queued source scans, exact-owner job/scan history and eligible job retry.
Other API families return **409**; WebSockets close with **1008**. Graph,
materialized inventory, import/export, synchronous SSH/network/cloud/container,
webhook, realtime and notification interfaces are not enabled by this increment.
Realtime tailers/automation bridges are not started in the controlled profile.
The monitor engine refuses controlled-profile ticks and direct target execution
before watch probes, reports or collectors run. Direct scheduled-report/network
sweeps and the notification-dispatch loop also refuse this profile. Existing scheduled jobs without
trusted credential/configuration provenance are refused, not reconstructed from
an actor name. The ordinary dashboard is therefore **not a qualified UI for
this restricted profile**. Do not promise unchanged production functionality.

Local source is staged without Git execution or remote acquisition. The parent
skips language parsing, additional collectors, inventory/fact/graph/business
projection, baseline/drift/quantum enrichment and notification/provider status
updates. Coverage records say **NOT_REQUESTED**, not clean/full coverage. Source
scan evidence, normalization/policy evaluation and a JSON CBOM rendering remain
supported; none imply complete NBOM, SBOM, TechBOM, HBOM or VBOM coverage.

Unqualified paths need separate adapters and acceptance evidence before being
added to the allowlist. Do not delete the boundary or restore privileged inline
fallback to make an endpoint appear functional. Standalone development collector
CLIs/library calls are **not approved production entry points**; deploy only the
reviewed API and worker entry points, restrict command execution and do not run
optional monitor/report/notification daemons in this profile.

## What each P0 item actually delivers

| P0 | Repository implementation | Remaining acceptance work |
|---|---|---|
| 2.1 Positive approval | Durable immutable approval IDs/revision chain, separate human approver, exact estate/target/subject/profile, approved window, maximum parser launches, policy revision and destination snapshot; enqueue, claim and phase revalidation | Range/protocol/remote-acquisition adapters, scheduled execution identities and customer legal approval |
| 2.2 Typed provenance | Authentication-layer user/key incarnation ID, durable session ID bound to the original user ID or key ID plus verifier/policy digest, server request ID, bounded correlation ID, original method/path/client address, selected estate and execution destination; fresh ID-based authorization | External identity-provider and all non-HTTP producer lifecycle qualification |
| 2.3 Shared budgets/stop | SQL CAS estate/provider reservations, rolling one-second launch rate, approval lifetime launch/retry allowance, durable least-recently-served estate turn/FIFO scheduling, five-second publication backoff, lease deadline and live parser/staging checkpoints; estate/global stop | PostgreSQL multi-replica contention, clock/partition testing and deployment-specific hard stop SLO; no wire-request budget claim for refused collectors |
| 2.4 Ownership/residency | Exact-owner control/history predicates, selected-system exact-owner validation, node region/destination binding before execution and private history reads, SQL ownership-register review endpoint and fail-closed unreviewed consumers | Physical SQL/queue/storage location, backups, regional copies, graph/cache/search/export/notification/audit classification, retention and legal-entity acceptance |
| 2.5 Hostile input | Descriptor-relative bounded local staging, no links/devices/FIFOs, existing digest-pinned networkless parser launcher, no inline fallback, private staging cleanup; other input processors refused | Provision actual approved runtime/image, run real hostile fixtures/escape resistance and daemon-loss/orphan tests; reviewed host-side result validation/evidence rendering resource qualification |
| 2.6 Recovery | Same-transaction SQL outbox, at-least-once publication reconciliation, QUEUED claim plus durable fenced attempt, checkpoints/deadline, UNKNOWN outcomes retaining capacity, audited human settlement and new-job resubmission | Real PostgreSQL/Redis crash, ambiguous write, partition, restore/failback and external-effect recovery exercises |

**All six have engineering controls or explicit refusal boundaries; their full
original acceptance criteria are not all closed.** In particular, an ownership
register is not an ownership audit, a destination string is not physical
residency proof, and launcher tests are not isolation qualification.

## Coordinated upgrade

1. Quiesce API producers, schedules, monitor and workers. Drain or inventory the
   old queue. Back up the database and verify the backup's owner, encryption,
   region and restore procedure. Never use a live bank database for drills.
2. Review the API allowlist/product availability change with operations and the
   customer. Provision PostgreSQL, the regional queue and approved isolation
   runtime. Production execution rejects SQLite, including an otherwise enabled
   generic `ALLOW_SQLITE` override. Test SQLite evidence is not PostgreSQL proof.
3. Apply migrations using the deployment's normal authenticated environment:

   ```bash
   python -m alembic -c services/database/migrations/alembic.ini upgrade head
   ```

   Current head for this build is `0105`; the original `0102` increment creates six empty control tables and a nullable original-user
   incarnation field on session records; it does **not** approve legacy jobs, move ownership, reinterpret NULL history as
   shared, release reservations or reset RUNNING rows. Existing sessions have no trusted
   original user ID and **must sign in again**; the migration never backfills an
   incarnation from a reusable username. New sessions bind the actual user ID,
   preventing replacement users from inheriting old credentials. Downgrade removes the new
   control history: export/retain it first and obtain change approval.
4. Export consistent bindings on API/worker nodes. These are operator assertions,
   not proof of the physical topology:

   ```bash
   export ENVIRONMENT=production
   export CRYPTOSCAN_EXECUTION_REGION=in-south
   export CRYPTOSCAN_EVIDENCE_REGION=in-south
   export CRYPTOSCAN_EVIDENCE_DESTINATION=regional-sql-a
   export CRYPTOSCAN_STATIC_SCAN_MODE=container
   # Set CRYPTOSCAN_SCANNER_IMAGE to the actually approved image@sha256:digest.
   # No example digest is an approved image; do not copy a fabricated one.
   ```

   Existing database, Redis, authentication and worker runtime prerequisites
   still apply. See [source isolation](../dev/scanner-isolation.md). The stock
   Compose stack does not provision the Docker CLI/daemon/shared staging needed
   by this adapter. Do not mount the Docker socket into a parser or add privileged
   fallback. Provision the dispatcher/runtime through a separately reviewed
   deployment change. No such runtime was available in the implementation sandbox.
5. With a real human platform administrator, configure the provider budget in
   platform context, then the selected estate policy. Use normal session/Bearer
   authentication; no credentials belong in examples, tickets or these files.
   See the [API contract and examples](../api-reference/controlled-execution.md).
6. Create an approval for a **different active executing user**, an owned API
   key incarnation, or an owned repository configuration. Human self-approval
   is refused. Machine credentials cannot approve/reconcile. One currently
   matching approval must exist at enqueue. To revise, use `supersedes_id`, which
   revokes the previous immutable record in the same transaction. A policy
   revision change invalidates existing approval bindings; issue new approvals.
7. Start only updated API/workers together. Never mix legacy workers that do not
   enforce these records with new producers. Unpinned queued work must be
   explicitly resubmitted under current approval. A durable SQL enqueue is
   accepted even if its publication fails: maintenance reconciles the outbox.
8. Check the attempts/events endpoints, capacity, refused/deferred jobs and
   transport logs. Do not infer success from a queue ACK or a truthy collector
   return: success requires committed job completion/scan identity too.

## Budgets, fairness and stop semantics

- Provider budget is provisioned explicitly for `local-source/v1`; estate budget
  comes from its policy. Both reservations are acquired in one SQL transaction,
  in a consistent lock order, with optimistic versions. No per-process counter
  is accepted as a distributed limit.
- Reservations cover the whole attempt. Parser launches consume one approval
  request and both shared rolling request limits, using the database clock rather than
  individual worker clocks. **These are parser-launch
  budgets, not TCP packet/connection budgets**: this adapter has no network
  acquisition, and active collectors are refused. There is no automatic parser
  retry or hidden retry allowance.
- Scheduling chooses the least-recently-served eligible estate, then its oldest
  job, from the oldest 500 controlled SQL-queued records. Revoked, stopped,
  off-region and full estates are ineligible. The provider stores served turns.
  Capacity/fairness losers remain QUEUED and get durable five-second backoff;
  they are not stamped FAILED or executed without a reservation. This is bounded
  ready-set fairness, not a global latency/starvation guarantee at unlimited depth.
- Estate stop is a versioned policy update with `stopped=true`. Platform humans
  can `POST /execution-controls/emergency-stop`: provider capacity becomes zero,
  affecting new claims and live checkpoints across estates. Reservations remain
  held. Resumption requires an explicit human provider-budget update, and estate
  approvals must still be current. Stop does not hide incident history.
- Staging checks time on each entry/chunk and refreshes authorization at least
  every 0.25 seconds while making progress. Parser CLI I/O checks authorization
  on a one-second polling cadence. Pipeline phase boundaries revalidate too.
  The child watchdog is also capped by the absolute approval/attempt deadline,
  independently of a blocked parent SQL call. Deploy a newly built/approved
  scanner image supporting that deadline field; old images fail closed rather
  than ignoring it. A denial kills the CLI process group; daemon cleanup uses bounded 10-second
  calls and verifies absence when removal fails. Staging caps: 30 seconds,
  10,000 admitted entries, 64 MiB total, 4 MiB/file, depth 64. Files/directories
  named `.git`, `.ssh`, `.aws`, `.azure`, `.kube`, `.env` and certain build caches
  are excluded; this does not guarantee source contains no embedded secrets.
- These are **checkpoint/launcher bounds, not a certified end-to-end emergency
  stop latency**. SQL connection/statement delays, filesystem stalls, daemon
  transport failures, host death and network partitions need real measurement.
  Record policy/event timestamps, last heartbeat/checkpoint, refusal/cleanup logs
  and externally confirmed container termination. An unconfirmed stop is UNKNOWN,
  never a reason to free capacity automatically.

## Unknown outcomes and safe recovery

Attempt deadlines are absolute, capped by approval expiry and estate runtime
limit. Maintenance fences expired RUNNING attempts to **UNKNOWN** and marks the
job UNKNOWN. It does **not** release reservations, replay RUNNING work or assert
that an external effect did not happen. Exceptions, missing durable completion
and unconfirmed launcher cleanup similarly require reconciliation.

1. Read the exact-estate attempt and original job. Preserve source scan IDs,
   checkpoints, deadline, incident reference, queue/SQL evidence and host logs.
2. Independently establish that the old container/process/effects have stopped
   or completed. A missing worker heartbeat or Redis queue item is not proof.
3. A human platform administrator in the selected estate submits a reconciliation
   receipt with `CONFIRMED_STOPPED` or `CONFIRMED_COMPLETED`, an evidence reference,
   and explicit external-work-stopped confirmation. The CAS resolves once and
   releases each reservation once. Late old-worker checkpoints are fenced out.
4. The original job becomes FAILED/reconciled, **not fabricated COMPLETED** and
   never QUEUED again. Its evidence/history remains. A retry creates a new job,
   using the current retrier's identity and a current, unexpired approval with
   remaining launch allowance. UNKNOWN/QUEUED/RUNNING work cannot be retried.
5. Reconcile queue publication separately. A publish before SQL acknowledgment
   can be delivered twice; QUEUED-only claim prevents concurrent restart. Missing
   PUBLISHED-but-still-QUEUED deliveries can be returned to the outbox by the
   reaper. This is **not exactly-once external effects** or a SQL/Redis transaction.

## Required deployment evidence — still open

- Real PostgreSQL contention/fencing/rollback with multiple independent workers;
  regional Redis outage, outbox lease/ACK-loss and queue restoration exercises.
- Actual digest/image provenance and dependency review, denied egress, credential
  sentinels, malformed source/results, resource exhaustion, escape attempts,
  kill-9, dispatcher/daemon loss and orphan cleanup. No Docker execution was
  claimed by the local mock-runtime tests.
- Product ownership classification beyond SQL table counts, including raw and
  materialized data, curated shared inventory vs private NULL history, search,
  graph, caches, exports, notifications, audit, backups and regional replicas.
- Measured emergency-stop SLO under healthy/degraded SQL, runtime and storage;
  customer/operator acceptance of resumption and unknown-outcome procedures.
- Separate adapters and tests for remote repositories, schedules, monitor,
  webhook, import/report and active network/cloud/container/binary acquisition.

The [root readiness gate](../../PRODUCTION-READINESS.md) remains authoritative.
This engineering increment does not turn historical FAIL/SKIP artifacts into PASS.

## Operator package follow-on (4.1–4.4)

The newer [operator install/upgrade/recovery runbook](operator-install-upgrade-recover.md)
defines an explicit graph-disabled deployment profile, offline full-package
verification, dedicated dispatcher build/runtime recipe and current head 0105.
0103 adds retained assurance history; 0104 adds estate/page indexes; 0105
widens monitor event types without approving additional collectors. The
ordinary legacy dashboard remains restricted; `/operator-decisions` is the new
exact-estate assurance metadata view. It does not enable live TLS/SSH/cloud
collection or restore the refused privileged fallback paths.
