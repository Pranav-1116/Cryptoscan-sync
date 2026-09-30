# First scan and the operating loop

This is the operator's end-to-end procedure: define scope, authorize access,
run a safe scan, inspect evidence, remediate, verify, and repeat. It does not
assume that a successful HTTP request means a complete inventory.

## 1. Before the first scan

Create a short scan charter:

| Decision | Required value |
|---|---|
| Customer/entity | Legal entity and environment |
| System | System name, owner, criticality, and business process |
| Source | Repository, image, endpoint, cloud account, export, or target list |
| Authorization | Written owner approval and permitted scope |
| Mode | Repository, container, cloud, TLS, passive OT, telecom ingest, or metadata import |
| Data class | Expected source data and prohibited secrets/Personal Data |
| Credentials | Least privilege, expiry, rotation, and owner |
| Schedule | One-time, release-triggered, daily, or periodic |
| Policy | Baseline and applicable framework scopes |
| Retention | Evidence, logs, report, and deletion period |
| Success | Coverage, finding, evidence, and acceptance criteria |

Do not scan a target merely because it is technically reachable. The scan
scope must be authorized and recorded.

## 2. Source authorization

The operator must confirm:

- the repository or endpoint belongs to the customer or is expressly in scope;
- the credential has only the access needed to collect the requested data;
- rate limits and maintenance windows are agreed;
- production credentials and private keys are not supplied as source data;
- public network targets are explicitly listed;
- OT/ICS collection is passive or otherwise approved by the safety owner; and
- the customer knows what data will be retained and exported.

For cloud providers, the configured account is the boundary. CryptoScan does
not infer or scan the provider's entire infrastructure or another tenant's
resources.

## 3. Submit the scan

A scan may be started through the console, API, webhook, or CLI. The exact
route and payload are in the [REST API reference](../../api-reference/rest-api.md)
and the relevant admin guide. A normal job has these states:

```text
requested -> authorized -> queued -> running -> completed
                                  |             |
                                  +-> blocked  +-> failed / partial
```

The response that creates a job is not the result of the scan. Persist the job
identifier, source revision, configuration profile, owner, and submission
actor.

## 4. What the worker does

The worker pipeline typically:

1. resolves the tenant or single-customer estate;
2. checks authorization, privacy, scope, rate, and safety gates;
3. leases or receives a credential without persisting secret values in findings;
4. creates an isolated workspace where needed;
5. collects the configured source;
6. detects supported languages, formats, and scanners;
7. extracts observations and records warnings;
8. redacts sensitive values before evidence persistence;
9. hashes and chains canonical evidence;
10. normalizes algorithms, modes, sizes, certificates, and asset identity;
11. deduplicates observations while keeping source links;
12. evaluates policy and compliance scope;
13. updates inventory, drift, graph, risk, PQC, and agility views;
14. emits progress and completion events; and
15. closes or cleans the workspace according to retention policy.

The detailed [scan walkthrough](../05-scan-walkthrough.md) and [end-to-end
trace](../09-end-to-end.md) show the repository's current implementation.

## 5. Inspect the result

A reviewer should inspect in this order:

1. **Coverage:** source revision, files/objects, endpoint count, account scope,
   skipped paths, permission errors, and unsupported formats.
2. **Evidence:** chain status, manifest hash, source location, parser/scanner,
   timestamp, and redaction state.
3. **Asset identity:** canonical algorithm, mode, key size, certificate,
   library, system, and related observations.
4. **Verdict:** policy ID and version, result, severity, reason, and applicable
   compliance scope.
5. **Ownership:** system, business owner, technical owner, and criticality.
6. **Impact:** dependency reachability, business process, data retention, HNDL,
   and migration wave.
7. **Action:** remediation, exception, escalation, or additional collection.

A result with many skipped or blocked objects is partial coverage even if every
observed object passes policy.

## 6. Remediation loop

For each actionable finding:

- assign the owner and due date;
- identify the safe replacement and compatibility constraints;
- create a change or work item;
- avoid copying secret values into tickets or comments;
- record an exception only when the accountable risk owner accepts it;
- rescan the changed source or runtime; and
- close the finding only from verified evidence.

A manual status change, ticket closure, or dashboard refresh cannot prove that
the cryptographic use was removed. The next authorized scan is the verification
step.

## 7. Baselines and drift

A baseline is a versioned approved state, not the first scan by default. Before
approval, review scope, missing data, policy version, system owner, exceptions,
and expected change windows. When a later scan differs, classify the change as
added, removed, changed, or unknown and decide whether it is expected.

Do not approve a baseline to hide an unexplained finding. Record the approver,
reason, date, expiry, and scope.

## 8. Completion record

Archive:

- scan request and authorization;
- source revision or target list;
- credential and scope reference, not the secret;
- job and evidence identifiers;
- coverage and skipped-object report;
- policy and configuration versions;
- findings and ownership decisions;
- remediation/exception records;
- verification result; and
- exported report or evidence pack.

This record is what makes a scan useful to a future operator, auditor, or
incident responder.
