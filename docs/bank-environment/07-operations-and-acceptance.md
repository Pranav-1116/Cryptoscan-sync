# 07 — Operating the bank installation and deciding acceptance

[Guide index](README.md) · Previous: [Console and exports](06-console-apis-and-exports.md) ·
Next: [Implementation map](08-implementation-map-and-limits.md)

## 1. First-scan success is only the beginning

The operational loop is:

```text
approved scope -> collect -> persist -> inspect coverage and evidence
 -> generate/pin supported outputs -> assign owner -> bank-approved change
 -> re-collect -> compare -> verify -> record outcome and unresolved gaps
```

The product does not replace the bank's change process. A finding must not
silently trigger certificate replacement, HSM key rotation, firewall changes or
source-code modification. A proposed action or migration scenario is not an
executed and verified remediation.

## 2. Scheduled collection needs real executors

Target frequency, a stored export schedule and an enabled UI setting are
configuration, not proof of running automation. Confirm which service/process
actually claims work, its scope/region, credentials, supervision, heartbeat,
backlog and error visibility.

- Network due-target execution depends on registered enabled targets and the
  configured invocation of due scanning; a due date does not create a process.
- Source/cloud re-scan planning must have an operational queue/worker path and
  actual target access. Check stale or never-scanned systems separately.
- Export schedules need an executor calling their due/run path; stored schedule
  rows alone do not establish unattended exports.
- Hardware health depends on real collector heartbeats/observations and their
  delivery. A static imported row is not 24/7 live monitoring.
- Optional notification scheduling is separately enabled and explicitly scoped;
  it is not automatically deployed by this guide.

Use the current [notification delivery](../dev/notification-delivery.md),
[scheduler](../dev/notification-scheduler.md) and
[receipt inspection](../dev/notification-inspection.md) contracts. Webhook/HTTP
acknowledgement is not downstream ingestion or action completion. SMTP remains
unimplemented in that durable notification path; do not sell it as a qualified
bank email integration.

## 3. Daily operational questions

| Question | Evidence to inspect |
|---|---|
| Did accepted jobs actually run? | Durable job status, queue backlog, worker liveness, elapsed stage times |
| What failed or was skipped? | Source coverage, optional stage failures, provider telemetry and parser errors |
| What has become stale? | Observation/run times, declared frequency, last successful collection and current target access |
| Did scope change? | Approved scope revision, target registration/audit and operator sign-off |
| Is the inventory durable? | Post-restart reads from the authoritative database and supported pin verification |
| Did alerts arrive? | Delivery receipts plus receiver-side evidence; not just API success |
| Is evidence trustworthy? | Supported canonical verification, signer/key provenance and mismatch handling |
| Are records private? | Authorization tests, sanitized output review, storage/log/export access controls |

Failure messages, logs and raw exports can themselves be sensitive. Use
restricted support procedures, bounded retention and redaction rather than
forwarding arbitrary logs to a public tracker.

## 4. Change detection and closure

### Example: application digest change

The owner confirms that an obsolete digest is used in the production-relevant
source path. The bank approves and deploys a replacement. Scan the correct new
release, confirm the target/revision and comparable coverage, then compare
findings/CBOM evidence. A missing finding caused by scanner failure, excluded
files or a different branch cannot close the original issue.

### Example: gateway certificate renewal

The PKI/network owner renews and deploys the certificate using bank procedures.
An authorized re-probe of the same intended hostname/SNI/port records the new
fingerprint/expiry. Preserve the before/after network runs. A certificate row
imported from a file is not proof that the listener serves it.

### Example: HSM firmware update

The hardware owner performs the approved update. Fresh permitted observations
are ingested and the persisted estate HBOM is pinned again. Compare device-keyed
field drift and retain the exact baseline/target pins. Firmware version change
alone does not prove a FIPS validation, enabled PQC algorithm or safe migration.

## 5. Pre-production acceptance matrix

Agree pass/fail criteria with the bank **before** running the pilot. The table
is a proposed acceptance plan, not completed customer evidence.

| Gate | Positive proof | Negative / failure proof |
|---|---|---|
| Authorized scope | Selected repo/listener/account/device is collected in the approved window | Out-of-scope target denied; stop/window behavior and firewall containment verified |
| Authentication and authorization | Correct identities can read/operate their permitted surfaces | Revoked session, wrong role, wrong tenant/estate and forged context denied |
| Source isolation | Approved immutable parser image scans a real controlled input | Missing image/runtime, denied network/write access, timeout, resource limits and cleanup tested |
| Source provenance | Correct release/commit/export identity and evidence linkage | Wrong/missing input or parser failure is not shown as a clean pass |
| Network observation | Exact intended endpoint/SNI yields a stored run and correct NBOM | Timeout, failed handshake and unreachable service remain distinguishable from plaintext/healthy |
| Provider scope | Permitted cloud calls succeed for selected accounts/regions | Denied calls, partial results and missing regions are visible; no false empty success |
| Hardware persistence | Actual approved observations survive restart in independent HBOM | Missing collector, stale data and live-engine reset are visible |
| Vendor provenance | Supplier evidence, revision and system linkage can be traced | Unsubstantiated declarations stay declared/unverified, not measured capabilities |
| Inventory completeness | Reconcile outputs against a bank-owned scope baseline | Caps, exclusions, unknowns and missing mappings are retained |
| Integrity/export | Exact supported artifacts verify with correct serialization and trusted key handling | Altered payload, wrong signature/key and mismatched pins fail visibly |
| Durability/recovery | Approved database, backup/restore and restart procedures preserve evidence | Queue/DB/worker outages, orphan jobs and storage failures are investigated |
| Performance/safety | Bank-selected concurrency/rate and normal workload tolerance measured | Timeouts, throttling, large trees/artifacts and prohibited OT probes tested |

Test collectors and deployed services independently. Parser isolation does not
cover Git clone, all cloud/network collectors, database handling or the entire
worker. A unit mock is not a positive Docker, provider or bank runtime test.

## 6. Meaningful coverage reporting

Use a bank-owned list of approved targets and classify each one, for example:

```text
Illustrative pilot scope: 12 approved target entries
  7 collected successfully within agreed time window
  2 attempted but failed (retain reasons)
  2 awaiting credentials/owner approval
  1 deliberately excluded by approved safety policy
```

These are explanatory numbers, not results from this repository or a bank scan.
If reporting collection coverage as 7/12, state the denominator and criterion.
Do not substitute “seven BOM components” for “seven targets collected”, or
remove failed scopes from the denominator to inflate success.

Report per-output coverage separately: source evidence, observed listeners,
persisted hardware, supplier substantiation and shared-state mappings. One
successful network probe does not establish the other four BOMs.

## 7. Production handoff and security review

Retain a reviewed, sanitized evidence bundle with:

- approved scope and change records; executor/deployment topology;
- exact application, collector, parser image and policy versions;
- input/build/source provenance, job/run IDs and snapshot identities;
- collector permissions and reviewed egress paths, without embedding secrets;
- actual findings, negative tests, exclusions, coverage and known limits;
- integrity/signature verification, key ownership and rotation procedure;
- recovery, supervision, backup/restore, monitoring and incident runbooks;
- named bank owners and signed acceptance of unresolved risks.

Formal customer acceptance, regulatory compliance, cryptographic certification
and platform readiness are separate decisions. Do not change
[Bank FAIL / NO_FIELD_DATA or other readiness gates](../../PRODUCTION-READINESS.md)
merely because documentation, a demo or a non-customer test passed.

## 8. Offboarding or pilot completion

Revoke collector/service accounts and temporary sessions, remove temporary
network access, stop scheduled work, and follow agreed retention/deletion rules
for source staging, findings, databases, backups and exports. Preserve any
legally required audit material with bank authorization. Do not claim secure
irrecoverable deletion from every backup without a verified lifecycle process.
