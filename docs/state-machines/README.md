# State machines — the canonical register

**Decision: one canonical, machine-readable State Machine Register, projected
into every surface.** The product carried its state machines implicitly — status
columns written as magic strings, vocabularies re-declared per service, honesty
rules living in reviewers' heads and commit messages. That taxed every audience:
operators saw states that looked alike but weren't, developers re-typed strings
that could drift, and agents had no way to learn what a field may hold before
touching code. The register makes the implicit explicit **once**, and UX, DX and
AX all read it.

| audience | surface | what they get |
|---|---|---|
| **UX** | `/state-machines` console page | every state drawn with one tone per semantic class, observed transitions, honesty invariants, and honest empty states where a vocabulary is not yet known |
| **DX** | `shared_models.state_machines` (Python), `frontend/src/lib/stateMachines.ts` (TypeScript) | typed machines, `can_transition()`, `state_tone()`, field lookup; drift-guard tests force the register to learn new status columns |
| **AX** | [`state_machines.json`](../../shared/shared_models/shared_models/state_machines.json) + CLI | machine-readable vocabulary + `python -m shared_models.state_machines list\|show\|vocab\|validate` |

## The finding

A full sweep of `services/database/db/models` found **91 status-bearing columns**
(plus session/UI state in the console and shared enums across services). Among
them:

- **five separate `Severity` enums** (anomaly, automation, drift, policy,
  keyassure) re-declaring the same five words;
- vocabularies living only as **comments** (`# OPEN | ACCEPTED | RESOLVED`) or
  only as a **column default** with the rest of the states invented at write
  sites elsewhere;
- fields with **no observable vocabulary at all** (the column exists; nothing in
  the code says what it may hold) — 15 of them, now listed honestly as
  `vocabulary: "unobserved"` instead of being guessed;
- honesty rules — *unknown is never zero, a failed read never prints zeros,
  absence is never a clean result, capability is never usage, NOT_CONFIGURED ≠
  UNKNOWN* — enforced only by tests and memory, not by a shared vocabulary.

The register turns all of that into one asset: **100 machines, 306 states, every
state observed from code and never invented.**

## The rules the register enforces on itself

1. Every state is observed from code — model default, declared tuple, enum, model
   comment or write site. Nothing is invented.
2. `vocabulary: "partial"` means the observed vocabulary is a subset;
   `"unobserved"` means the field exists but its vocabulary is not yet known.
   Both are honest; guessing is not.
3. unknown is never zero. A failed read is a failure. Absence is never a clean
   result. Capability is never usage. A refusal is counted, never drawn as a
   truth. These invariants ride on the machines they govern (`invariants[]`).
4. Transitions exist only where code proves them. A state with no observed edges
   stays put by exhaustion, not by an implicit self-loop.

## Consumers

### Python

```python
from shared_models.state_machines import machine, can_transition, state_tone, machines_for_field

machine("scan.status").state_ids        # ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')
can_transition("scan.status", "QUEUED", "RUNNING")   # True — observed in Scan.start
can_transition("binary.usage_status", "capability_only", "runtime_confirmed")  # False — never
state_tone("scan.status", "FAILED")     # 'red' — the failure class tone
machines_for_field("scan.Scan.status")  # the machine that owns a model field
```

### TypeScript (console)

```ts
import { machine, statesOf, stateTone, canTransition } from "../lib/stateMachines";

stateTone("ui.performance_tile", "unknown")  // "slate" — unknown never renders as a pass
```

### CLI (agents)

```
python -m shared_models.state_machines list --domain collection
python -m shared_models.state_machines show binary.usage_status
python -m shared_models.state_machines vocab scan.Scan.status
python -m shared_models.state_machines validate
```

## Keeping it honest (the drift guards)

`shared/shared_models/tests/test_state_machines.py` fails when:

- a status column appears in `db.models` that the register does not know (the
  test discovers columns by AST — add a column, teach the register);
- a registered field disappears or a declared default is not one of its states;
- a declared tuple (`SCAN_STATUSES`, `FINDING_STATES`, …) or enum (`UsageStatus`,
  `EvidenceClass`) drifts from the register's states;
- the frontend mirror (`frontend/src/lib/stateMachines.json`) differs by one byte
  from the canonical file;
- capability gains any edge into usage, or an unobserved machine grows invented
  states.

The mirror must stay byte-identical to the canonical JSON: edit the canonical
file and copy it over the mirror (the two are written together), never one
alone.

## Adding a machine

1. Observe the vocabulary in code (default, tuple, enum, comment, write sites).
   Never invent states; if only part is observable mark `vocabulary: "partial"`;
   if none is, register the machine with `vocabulary: "unobserved"` and no states.
2. Classify each state (`progress|done|failure|stopped|warn|unknown|refused|
   absent|derived|capability|stale`) — the class decides its tone everywhere.
3. Declare transitions only where code proves them, with `observed_in` sources.
4. Attach the honesty invariants that govern the machine.
5. Regenerate both JSON files and run the drift guards.

## Inventory

100 machines · 306 states · 94 model fields · 15 vocabularies honestly unobserved.


### session

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `session.tenant_resolution` Tenant resolution | `unresolvable`(unknown), `resolving`(progress), `resolved`(done) | observed | — |
| `session.read_health` Read health | `ok`(done), `failed`(failure) | observed | — |
| `session.write_feedback` Write feedback | `confirmed`(done), `validation_rejected`(failure), `refused`(refused), `outcome_unconfirmed`(unknown) | observed | — |

### ui

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `ui.flow_stage` Flow stage | `done`(done), `active`(done), `pending`(progress), `unknown`(unknown), `failed`(failure) | observed | — |
| `ui.performance_tile` Performance tile state | `known`(unknown), `derived`(derived), `unknown`(unknown) | observed | — |
| `ui.tone` Tone vocabulary | `green`(unknown), `amber`(unknown), `orange`(unknown), `red`(unknown), `violet`(unknown), `slate`(unknown), `accent`(unknown) | observed | — |
| `maturity.surface` Surface maturity | `ga`(unknown), `beta`(unknown), `preview`(warn) | observed | — |

### collection

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `scan.status` Scan lifecycle | `QUEUED`(progress), `RUNNING`(progress), `COMPLETED`(done), `FAILED`(failure), `CANCELLED`(stopped) | observed | `scan.Scan.status` |
| `scan_job.status` Scan job outcome | `QUEUED`(progress), `RUNNING`(progress), `COMPLETED`(done), `FAILED`(failure), `UNKNOWN`(unknown) | partial | `scan_job.ScanJob.status` |
| `live_scan.status` Live scan session | `discovered`(progress), `running`(progress), `completed`(done), `failed`(failure), `cancelling`(progress), `cancelled`(stopped), `unavailable`(unknown) | partial | — |
| `estate_surface.progress` Collection surface progress | `NOT_ATTEMPTED`(absent), `PARTIAL`(warn), `COMPLETE`(done), `FAILED`(failure), `UNKNOWN`(unknown) | partial | `assurance.CollectionPhaseReceipt.state` |
| `collection.phase` Collection phase | `host_keys`(unknown) | partial | `assurance.CollectionPhaseReceipt.phase` |
| `collector.depth` Collector depth ladder | `partial`(warn), `exists`(capability), `ingest_only`(progress), `invocation`(done) | observed | — |
| `binary_scan.status` Binary scan lifecycle | `PENDING`(progress), `RUNNING`(progress), `COMPLETED`(done), `FAILED`(failure) | partial | `binary_scan.BinaryScanRecord.status`, `binary_intelligence.BinaryScanRun.status` |

### evidence

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `binary.usage_status` Capability vs usage | `capability_only`(capability), `configuration_only`(capability), `statically_referenced`(capability), `statically_supported`(capability), `runtime_confirmed`(done), `unresolved`(unknown) | observed | `binary_intelligence.BinaryCryptoFinding.usage_status` |
| `binary.evidence_class` Evidence class | `observed`(done), `strongly_supported`(derived), `indicated`(derived), `inferred`(derived), `unknown`(unknown), `not_detected`(unknown) | observed | — |
| `os.rule_evaluation` OS-CRYPTO rule evaluation | `evaluated`(done), `not_evaluable`(unknown) | observed | — |
| `os.rule_evidence_class` OS rule evidence class | `observed`(done), `indicated`(derived), `not_detected`(unknown) | partial | — |
| `os.record_state` OS record state | `loaded`(done), `present`(done), `unavailable`(unknown), `enabled`(unknown), `disabled`(stopped), `expired`(stale), `near_expiration`(stale) | partial | `os_intelligence.OSModuleRecord.state`, `os_intelligence.OSTrustFact.state` |
| `evidence.verification_result` Verification result | `PASS`(done), `FAIL`(failure), `PARTIAL`(warn), `EMPTY`(absent), `UNVERIFIABLE`(unknown), `MATCH`(done), `MISMATCH`(failure), `VERIFIED`(done) | partial | `verification_log.VerificationLog.result`, `remediation_task.RemediationVerification.result`, `container_scan.ContainerScan.result` |
| `system.coverage_status` System coverage status | _(not yet observed)_ | unobserved | `system.System.coverage_status` |
| `evidence_record.compliance_status` Evidence compliance status | _(not yet observed)_ | unobserved | `evidence_record.EvidenceRecord.compliance_status` |
| `identity.confidence` Identity confidence | `CONFIRMED`(done), `PROBABLE`(derived), `POSSIBLE`(derived), `UNKNOWN`(unknown), `CONFLICT`(unknown) | observed | — |

### findings

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `common.severity` Severity | `INFO`(unknown), `LOW`(unknown), `MEDIUM`(unknown), `HIGH`(unknown), `CRITICAL`(failure) | observed | — |
| `security_control.finding_state` Control finding state | `CONFIGURED`(done), `OBSERVED`(done), `WITHIN_LIMIT`(done), `OVER_LIMIT`(warn), `NOT_CONFIGURED`(absent), `POLICY_NOT_ATTACHED`(absent), `INCOMPARABLE_WINDOW`(unknown), `UNKNOWN`(unknown), `STALE_EVIDENCE`(stale), `REFUSED`(refused) | observed | `security_control.SecurityControlFinding.state` |
| `pentest_finding.status` Pentest finding status | `OPEN`(progress), `IN_PROGRESS`(progress), `REMEDIATED`(unknown), `ACCEPTED`(done), `WONT_FIX`(stopped) | observed | `pentest_finding.PentestFinding.status` |
| `remediation_task.status` Remediation task | `PROPOSED`(unknown), `ACCEPTED`(done), `COMPLETED`(done), `VERIFIED`(done) | partial | `remediation_task.RemediationTask.status` |
| `drift.resolution_status` Drift resolution | `OPEN`(progress), `ACKNOWLEDGED`(unknown), `RESOLVED`(done) | partial | `drift_event.DriftEvent.resolution_status` |
| `drift.verification_status` Drift verification | _(not yet observed)_ | unobserved | `drift_event.DriftEvent.verification_status` |
| `policy_exception.status` Policy exception | `PENDING`(progress), `APPROVED`(unknown), `REVOKED`(stopped) | partial | `policy_exception.PolicyException.status` |
| `baseline.status` Baseline | `ACTIVE`(done), `SUPERSEDED`(stale) | partial | `baseline.Baseline.status` |
| `runtime_finding.status` Runtime finding verdict | _(not yet observed)_ | unobserved | `runtime_finding.RuntimeFinding.status` |
| `runtime.collection_authorization` Runtime-before-collection authorization | `allowed`(unknown), `refused`(refused) | observed | — |

### payments

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `payment_crypto.key_state` Payment key state | `PRE_ACTIVATION`(progress), `ACTIVE`(done), `SUSPENDED`(warn), `COMPROMISED`(failure), `DESTROYED`(stopped), `EXPIRED`(stale) | observed | `payment_crypto.PaymentKey.state` |
| `payment_crypto.ceremony_status` Key ceremony | `PLANNED`(progress), `HELD`(done), `ABANDONED`(stopped) | observed | `payment_crypto.KeyCeremony.status` |
| `payment_crypto.finding_status` Payment policy finding | `OPEN`(progress), `ACCEPTED`(done), `RESOLVED`(done) | observed | `payment_crypto.PaymentPolicyFinding.status` |

### platform

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `tenant.status` Tenant status | `ACTIVE`(done), `SUSPENDED`(warn) | observed | `tenant.Tenant.status` |
| `monitor.target_status` Monitor target | `PENDING`(progress), `OK`(done), `DEGRADED`(warn), `FAILING`(failure), `BLOCKED`(refused), `PAUSED`(warn) | observed | `monitor.MonitorTarget.status` |
| `control_plane.credential_status` Credential reference | `pending`(progress), `active`(done), `rotating`(progress), `expired`(stale), `revoked`(stopped), `error`(failure) | observed | `control_plane.CredentialRef.status` |
| `control_plane.agent_status` Agent status | `enrolled`(progress), `connecting`(progress), `connected`(done), `offline`(unknown), `upgrading`(progress), `error`(failure), `retired`(stopped) | observed | `control_plane.Agent.status` |
| `control_plane.agent_link` Agent link | `disconnected`(done), `connecting`(progress), `encrypted`(done) | observed | `control_plane.Agent.link` |
| `control_plane.event_status` Control-plane event | `queued`(progress), `leased`(progress), `completed`(done), `dead`(failure) | observed | `control_plane.QueuedEvent.status` |
| `control_plane.benchmark_status` Benchmark run | `created`(progress), `scored`(done), `archived`(stopped) | observed | `control_plane.BenchmarkRun.status` |
| `control_plane.delivery_status` Delivery outcome | `delivered`(done), `failed`(failure), `skipped`(absent), `inflight`(progress), `legacy_unknown`(unknown) | partial | `control_plane.DeliveryLog.status` |
| `notification_delivery.status` Notification delivery | `pending`(progress), `delivered`(done), `failed`(failure), `skipped`(absent) | partial | `notification_delivery.NotificationDelivery.status` |
| `credential_lease.status` Credential lease | `ACTIVE`(done) | partial | `credential_lease.CredentialLease.status` |
| `onboarding.connector_status` Connector status | `pending`(progress), `configured`(done), `connected`(done), `error`(failure) | observed | `onboarding.Connector.status` |
| `onboarding.discovery_status` Discovery run | `planned`(progress), `running`(progress), `completed`(done), `failed`(failure) | partial | `onboarding.DiscoveryRun.status` |
| `estate_daemon.state` Estate daemon | `RUNNING`(progress), `STOPPED`(stopped) | partial | `estate_daemon.EstateDaemon.state` |
| `hardware.agent_status` Hardware agent row | `ONLINE`(done), `OFFLINE`(unknown) | partial | `hardware_live.HardwareAgentRow.agent_status` |
| `execution.status` Execution attempt | `RUNNING`(progress), `RESOLVED`(done), `UNKNOWN`(unknown) | partial | `execution_control.ExecutionAttempt.status` |
| `execution_outbox.state` Execution outbox item | `PENDING`(progress), `PUBLISHING`(progress), `PUBLISHED`(done), `CANCELLED`(stopped) | partial | `execution_control.ExecutionOutbox.state` |

### governance

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `gate.decision` Approval decision | `APPROVED`(unknown), `DENIED`(refused) | partial | `gate_evaluation.GateEvaluation.decision`, `p2.GovernanceApproval.decision` |
| `evidence_disposition.decision` Evidence disposition | `RETAIN`(done), `QUARANTINE_EXPORTS`(warn), `MARK_REDACTED`(done) | observed | `evidence_disposition.EvidenceDisposition.decision` |
| `scope_grant.effect` Scope grant effect | `allow`(done), `deny`(refused) | observed | `control_plane.ScopeGrant.effect` |
| `enterprise.ticket_state` ITSM ticket | `open`(progress), `triaged`(warn), `assigned`(progress), `in_progress`(progress), `in_migration`(warn), `validation`(warn), `resolved`(done), `closed`(stopped), `reopened`(warn) | observed | `enterprise.Ticket.state` |
| `enterprise.compliance_state` Compliance state | `COMPLIANT`(unknown), `GAP`(warn), `NOT_EVIDENCED`(unknown), `NOT_APPLICABLE`(absent) | observed | `enterprise.ComplianceStatus.status` |
| `enterprise.policy_verdict` Policy verdict | `PASS`(done), `FAIL`(failure), `WARN`(warn), `NOT_APPLICABLE`(absent) | observed | `enterprise.PolicyEvaluation.verdict` |
| `enterprise.sync_status` Integration sync | _(not yet observed)_ | unobserved | `enterprise.Integration.last_sync_status` |
| `enterprise.knowledge_status` Crypto knowledge entry | _(not yet observed)_ | unobserved | `enterprise.CryptoKnowledgeEntry.status` |
| `audit.outcome` Audit outcome | `SUCCESS`(unknown), `FAILURE`(failure), `DENIED`(refused), `LOCKED`(refused), `DISABLED`(stopped) | partial | `user.AuditLog.outcome` |
| `p2.plugin_state` Plugin package | `UPLOADED`(progress) | partial | `p2.PluginPackage.state` |
| `p2.export_status` Lake export batch | `SEALED`(done), `OPEN`(progress) | partial | `p2.LakeExportBatch.status` |
| `p2.anomaly_status` Anomaly flag | `OPEN`(progress), `PENDING`(progress) | partial | `p2.AnomalyFlag.status` |
| `p2.validation_stage` Migration validation stage | `PRE`(progress), `POST`(progress) | observed | `p2.MigrationValidation.stage` |
| `p2.validation_status` Migration validation | `PENDING`(progress) | partial | `p2.MigrationValidation.status` |
| `p2.approval_status` Governance approval | `PENDING`(progress) | partial | `p2.GovernanceApproval.status` |
| `ot_maintenance.status` OT maintenance window | `APPROVED`(unknown) | partial | `ot_maintenance.OtMaintenanceWindow.status` |
| `report_snapshot.email_status` Report email | `SENT`(done), `SKIPPED_NO_SMTP`(absent), `FAILED`(failure) | observed | `report_snapshot.ReportSnapshot.email_status` |
| `roadmap.deployment_status` Deployment attestation | `OK`(done), `FAILED`(failure) | partial | `roadmap_deployment.DeploymentAttestation.status` |
| `roadmap.gate_result` Gate filing result | `PASSED`(done), `FAILED`(failure) | partial | `roadmap_gates.GateFiling.result` |
| `roadmap.governance_state` Governance ticket | `OPEN`(progress) | partial | `roadmap_governance.GovernanceTicket.state` |
| `roadmap.qualification_state` Discovery qualification | _(not yet observed)_ | unobserved | `roadmap_qualification.DiscoveryQualification.state` |
| `roadmap.external_validation_result` External validation | `PASSED`(done), `FAILED`(failure) | partial | `roadmap_qualification.ExternalValidation.result` |

### estate

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `estate_catalog.status` Estate relationship | `ESTABLISHED`(done), `UNRESOLVED`(unknown) | partial | `estate_catalog.EstateRelationshipRecord.status` |
| `estate_remediation_work.status` Estate remediation work | `OPEN`(progress) | partial | `estate_remediation_work.EstateRemediationWork.status` |
| `estate_schedule.status` Schedule run | `OK`(done), `RUNNING`(progress), `ERROR`(failure), `SKIPPED`(absent) | observed | `estate_schedule.EstateScheduleRun.status` |
| `estate_schedule.verdict` Schedule run verdict | _(not yet observed)_ | unobserved | `estate_schedule.EstateScheduleRun.verdict` |
| `network_inventory.status` Network inventory revision | `DRAFT`(progress), `IN_SYNC`(done), `CHANGED`(warn) | partial | `network_inventory.NetworkInventoryRevision.status` |
| `vendor_profile.status` Vendor profile revision | `DRAFT`(progress) | partial | `vendor_profile.VendorProfileRevision.status` |
| `migration_task.status` Migration task | `TODO`(unknown), `NOT_STARTED`(absent), `IN_PROGRESS`(progress), `DONE`(done), `BLOCKED`(refused), `MISSED`(warn), `ACHIEVED`(done), `AT_RISK`(warn) | partial | `migration_project.MigrationTask.status` |
| `migration_project.status` Migration project / milestone | `PLANNED`(progress) | partial | `migration_project.MigrationProject.status`, `migration_project.MigrationMilestone.status` |

### certificates

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `certificate.expiry_status` Certificate expiry | `NOT_YET_VALID`(absent), `VALID`(done), `EXPIRING_SOON`(stale), `EXPIRING_CRITICAL`(stale), `EXPIRED`(stale), `UNKNOWN`(unknown) | partial | `certificate.Certificate.expiry_status` |
| `certificate.renewal_status` Certificate renewal | `NONE`(unknown) | partial | `certificate.Certificate.renewal_status` |
| `certificate.revocation_status` Certificate revocation | _(not yet observed)_ | unobserved | `certificate.Certificate.revocation_status` |

### cryptolog

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `cryptolog.investigation_status` CryptoLog investigation | `OBSERVED`(done) | partial | `cryptolog.CryptoLogEvent.investigation_status` |
| `cryptolog.alert_state` CryptoLog alert | `OPEN`(progress), `CHECKPOINTED`(unknown) | partial | `cryptolog.CryptoLogAlert.state` |

### performance

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `performance.quality_status` Metric quality | _(not yet observed)_ | unobserved | `performance.PerformanceMetric.quality_status` |
| `performance.collector_health` Collector health | _(not yet observed)_ | unobserved | `performance.PerformanceCollectorHealth.status` |
| `performance.incident_status` Performance incident | _(not yet observed)_ | unobserved | `performance.PerformanceIncident.status` |
| `performance.forecast_status` Capacity forecast | _(not yet observed)_ | unobserved | `performance.PerformanceCapacityForecast.status` |

### posture

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `pqc.readiness` PQC readiness verdict | `COMPATIBLE`(done), `MIGRATION_REQUIRED`(warn) | partial | — |
| `pqc.migration_stage` PQC claim ladder | `SUPPORT_ONLY`(capability), `SUPPORT_AVAILABLE`(capability), `MIGRATION_VALIDATED`(done), `CONFIGURED`(done) | partial | — |

### twin

| machine | states (class) | vocabulary | fields |
|---|---|---|---|
| `twin.snapshot_state` Twin snapshot state | _(not yet observed)_ | unobserved | `cascade_extensions.TwinSnapshot.state`, `technology_bom_snapshot.TechnologyBomSnapshot.state` |
| `cascade.verdict` Cascade verdict | _(not yet observed)_ | unobserved | `cascade_run.CascadeRun.verdict`, `network_scan_run.NetworkScanRun.verdict`, `estate_change_event.EstateChangeEvent.verdict` |
| `cascade.result` Cascade result | `COMPLETE`(done), `PARTIAL`(warn), `FAILED`(failure), `STALE`(stale), `MALFORMED`(failure) | partial | `cascade_run.CascadeRun.result`, `network_scan_run.NetworkScanRun.result`, `relationship_lifecycle.RelationshipCollection.result` |
| `relationship_lifecycle.outcome` Relationship collection outcome | `COMPLETE`(done), `FAILED`(failure), `PARTIAL`(warn) | partial | `relationship_lifecycle.RelationshipCollection.outcome` |
