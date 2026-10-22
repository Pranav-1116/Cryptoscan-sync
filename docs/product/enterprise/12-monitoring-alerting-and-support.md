# Monitoring, alerting, and support

## 1. Monitoring objectives

Monitoring should answer three separate questions:

1. **Is the platform running?** — process, dependency, queue, and readiness health.
2. **Is collection working?** — job throughput, coverage, permissions, partial
   scans, and stale schedules.
3. **Is the estate changing?** — new findings, drift, expiring certificates,
   policy failures, anomalies, and migration progress.

Do not use a single green health check to represent all three.

## 2. Metrics and logs

Recommended telemetry includes:

- request count, error count, latency, and status by route class;
- login, MFA, SSO, API-key, and authorization outcomes;
- queue depth, job age, lease expiry, retries, and dead letters;
- scanner objects per second, duration, parser failures, and skipped objects;
- evidence chain failures, redaction failures, and manifest mismatches;
- policy results by rule, scope, and status;
- connector attempts, acknowledgements, retries, and idempotency outcomes;
- database query, connection, lock, storage, and migration metrics; and
- backup, restore, certificate, and key-lifecycle metrics.

Logs should be structured with request/job/tenant/customer correlation IDs.
Never log passwords, tokens, private keys, raw key material, unnecessary
Personal Data, or entire source files.

## 3. Alert design

An alert needs:

- condition and threshold;
- scope and customer/system;
- first observed and last observed time;
- severity and business impact;
- owner and escalation route;
- deduplication/correlation key;
- runbook link;
- acknowledgement and resolution state; and
- suppression or maintenance-window reason.

Good alert examples:

- evidence verification failed;
- production readiness changed to not-ready;
- scan target has been unreachable for the agreed interval;
- a critical policy finding is new or drifted;
- a certificate is within its configured expiry window;
- backup is late or manifest verification failed;
- queue age exceeds the operating target; or
- a connector repeatedly fails or emits duplicate risk.

A finding notification is not an incident declaration. Route security,
privacy, availability, and commercial issues through the appropriate process.

## 4. Support severity

Select response targets in the signed SLA and Order Form. The handbook should
use a severity model such as:

| Severity | Example | Handling |
|---|---|---|
| Critical | Service unavailable, evidence integrity concern, active security incident | Incident commander, immediate communications, executive/legal route |
| High | Material scan failure, major integration, broad incomplete coverage | Named owner, frequent updates, corrective action |
| Medium | Function degraded or limited scope failure | Normal engineering/support queue |
| Low | Documentation, cosmetic, or non-blocking enhancement | Planned backlog |

Do not advertise 24x7 support unless every shift has a trained, reachable
responder, escalation path, and tested channel.

## 5. Incident response handoff

At intake:

1. authenticate the requester;
2. record customer, deployment, region, job, and correlation ID;
3. classify support, security, privacy, data integrity, or billing;
4. preserve evidence and avoid destructive troubleshooting;
5. assign severity and incident owner;
6. state known facts and uncertainty;
7. set the next update time;
8. involve privacy/legal when Personal Data or notification may apply;
9. record containment, remediation, and verification; and
10. close with customer acceptance or contractually permitted timeout.

A support engineer must not declare regulatory breach status, customer fault, or
legal conclusion without the authorized owner.

## 6. Customer communication

Every update should contain:

- current status;
- affected scope and time window;
- observed impact;
- actions completed;
- next action and owner;
- known limitation or customer dependency;
- next update time; and
- whether the issue is being handled as security/privacy incident.

Avoid speculative root cause, unsupported recovery times, and claims that all
customers or regions are affected until the scope is verified.

## 7. Support access

Privileged support access must be named, authenticated, least-privilege,
time-bound, approved where required, logged, restricted to the agreed region
and data, revoked after the task, and reviewed after use. Use redacted logs and
customer-approved secure channels.

## 8. Service review

Monthly or quarterly service review should cover:

- tickets by severity and cause;
- response/resolution target performance;
- repeated incidents and corrective actions;
- scan coverage and stale targets;
- evidence integrity and export failures;
- access and key reviews;
- backup/restore result;
- security/privacy escalations;
- change and maintenance history; and
- open exceptions and expiry.

Use the [support handbook](../../company/support-handbook-and-escalation.md),
[on-call guide](../../ops/on-call-and-comms.md), and incident policy for
customer-facing operations.

## Current-reading update — 2026-10-22

Current monitor event types support 120 characters after migration **0105**. A CBOM SSE connection comment is transport readiness, not a new observation. Ownership/exercise gates require real people and independently reviewed evidence; **sla_authorized remains false**.

See [current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md),
[CI/build contract](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
[operator install/upgrade/recover](../../runbooks/operator-install-upgrade-recover.md).
