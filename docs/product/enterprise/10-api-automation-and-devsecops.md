# APIs, automation, and DevSecOps

## 1. API design

The REST API is the machine-readable contract for scans, assets, findings,
policy, reports, identity, administration, events, and integrations. The
[generated REST reference](../../api-reference/rest-api.md) is authoritative for
current paths and schemas; examples in narrative docs are illustrative.

API clients should:

- authenticate with a short-lived session or scoped API key;
- send a request ID or preserve the returned one;
- use pagination and stable identifiers;
- treat 2xx job submission as acceptance, not completion;
- poll or subscribe for state changes;
- retry only idempotent operations or use an idempotency key;
- honor rate-limit and `Retry-After` headers;
- handle `UNKNOWN`, `SKIP`, `BLOCKED`, and partial states; and
- store export manifests and verification responses.

## 2. Authentication patterns

### Human client

Use local/MFA or configured OIDC/SAML/LDAP flow. Keep session tokens out of
URLs, browser storage where the deployment prohibits it, logs, and support
screenshots.

### Machine client

Create a key with the narrowest available scope, store it in a secret manager,
attach it to a single connector or pipeline, rotate it on a schedule, and
revoke it on job or team ownership change.

### Webhook producer

Verify the configured HMAC signature, timestamp/replay protections where
supported, source repository, and event type before enqueueing a scan. A webhook
must not grant a broader scan scope than the configured repository or system.

## 3. Job automation pattern

```text
POST submit
  -> 202/201 with job id
  -> GET job or event stream
  -> completed / partial / blocked / failed
  -> GET findings and evidence
  -> GET verification / report / export
```

A robust client records the submission configuration, source revision, job ID,
completion state, coverage, and evidence manifest. It should not assume that a
missing finding means a clean source when the job was partial or blocked.

## 4. CI/CD gate

The CI gate should run against the commit or artifact that is actually being
built. A recommended pipeline is:

1. authenticate the runner with a scoped key;
2. identify repository, branch, commit, image, or release;
3. run the scan using a named profile;
4. apply applicable policy and severity thresholds;
5. upload SARIF or the approved native result;
6. publish a human-readable summary with limitations;
7. store the job/evidence identifiers; and
8. exit non-zero when the blocking rule is met.

The gate must distinguish "no findings" from "scan did not run" and "scan was
incomplete." A build should not pass because the API timed out or a source was
excluded.

## 5. Automation and approvals

Automation rules should use a safe structure:

```text
WHEN event matches declared scope
IF condition is satisfied and required evidence exists
THEN create a preview or action with an owner and approval requirement
```

Examples include notifying a team, opening a ticket, recalculating risk,
creating a migration task, or scheduling a scan. Destructive or externally
visible actions need an approval tier, idempotency key, dry-run/preview, and
rollback or closure procedure.

## 6. Events and real-time delivery

Events may be delivered through persisted monitor events, SSE, WebSocket,
Redis federation, webhooks, SIEM, or connector adapters. Delivery guarantees
must be documented separately:

- event persisted;
- delivery attempted;
- receiver acknowledged;
- receiver deduplicated;
- retry scheduled; and
- action completed or dead-lettered.

A browser event is not an audit record. Consumers should reconcile with the API
when reconnecting or when a sequence gap is detected.

## 7. Exports and signatures

For every export record:

- scope and query parameters;
- generating user or service;
- source and policy versions;
- generated timestamp;
- content hash;
- signature/JWS or HMAC metadata where enabled;
- artifact identifier and retention; and
- verification command or endpoint.

Do not treat a signature as proof that the content is correct; it proves the
signer or key produced the signed bytes. Review source coverage and scope too.

## 8. API error handling

Clients should group errors into:

- authentication/authorization: fix identity or scope;
- validation: fix payload or configuration;
- conflict/idempotency: reconcile existing state;
- rate/quota: wait or obtain approved capacity;
- dependency unavailable: retry according to policy;
- scan blocked/partial: review authorization, coverage, and safety; and
- server failure: preserve correlation ID and escalate with logs.

Never retry an unsafe mutation indefinitely or use retries to bypass a quota,
scope restriction, or approval gate.
