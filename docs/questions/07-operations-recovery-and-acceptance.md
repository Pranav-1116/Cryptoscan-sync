# 07 — Operations, recovery, support and acceptance

[FAQ index](README.md) · Questions Q071–Q080.

## Q071. Will CryptoScan run 24/7 and scan the bank continuously?

Continuous **service availability** and continuous **authorized collection** are different. The intended operating model is a bank-hosted service that remains running, with named bank monitoring/operations owners and agreed support arrangements.

That does not enable unqualified scheduler/monitor/live-collection routes or promise every target is continuously observed. The current controlled local-source profile does not become a bank-wide realtime scanner because its pods stay up. Agree actual windows, freshness and supported schedules per workflow.

## Q072. Who monitors the tool, and what is the weekly support review?

The proposed model assigns bank SOC/security monitoring, platform/runtime operation to infrastructure owners, and database/Redis/recovery duties to those service owners. The CryptoScan team conducts an agreed weekly review of errors, release/security advisories, defects, evidence gaps and proposed changes.

Urgent incidents must not wait for the weekly meeting. Out-of-hours vendor response, escalation times and contacts must be staffed and contracted explicitly. This documentation does not establish a 24/7 vendor SOC, guaranteed uptime or automatic production updates.

## Q073. How are failed, partial, cancelled and UNKNOWN jobs handled?

Preserve the actual state and receipts. A request acknowledgement is not completion; a partial collection is not a clean success; a cancellation request is not proof of termination. UNKNOWN means execution/outcome cannot safely be concluded under the current durable evidence.

Inspect the exact attempt, authority, worker/runtime state, evidence and cleanup before retrying. Do not relabel uncertainty, release budgets or delete history merely to clear a dashboard. Use the applicable reconciliation/recovery procedure and retain any approved decision.

## Q074. Should the operator automatically retry every timeout or error?

No. A retry may repeat work, consume quota or run after scope/identity changed. Determine whether the operation is safe/idempotent, whether the original attempt terminated, what authority is current, and which retry contract exists.

Recent Windows module/CNG candidates deliberately refuse some changed-input conditions without indefinite retries. API rate responses provide retry information but do not authorize another scan or extend the approved window. Denied/unsupported interfaces usually need review, not repeated pressure on the target.

## Q075. How often should evidence be refreshed, and how is drift detected?

Agree refresh frequency based on change rate, criticality, exposure and method cost. A stable system may need release/change-triggered evidence; a separately qualified network workflow may have another schedule. There is no universal freshness interval that proves bank coverage.

Compare like-for-like scoped identities/revisions and retain before/after evidence. A changed package version, certificate fingerprint or reviewed relationship can support drift; a missing observation after failure does not prove removal. Freshness expiry and identity ambiguity must remain visible. Reading a BOM does not silently refresh its source.

## Q076. What should monitoring cover besides “the server is up”?

Monitor admitted-work failures/UNKNOWN age, authorization denials, queue/backlog, worker ownership/recovery, parser cleanup/resource pressure, database/Redis health, evidence-integrity failures, disk/quota growth, certificate expiry and backup/restore readiness.

Separate application health, evidence quality and business coverage. A healthy HTTP endpoint does not prove parsing succeeded or required bank targets were assessed. Route alerting through actual approved bank channels; do not claim a notification/SIEM adapter is deployed because a menu or configuration exists.

## Q077. What must be backed up, and how is disaster recovery proven?

Plan a consistent recoverable cohort: relevant PostgreSQL state, approved source/evidence storage, configuration, compatible release/schema, key/CA custody references, audit/review records and necessary Redis/queue reconciliation information. Protect sensitive backup contents and independent recovery access.

Prove recovery through an isolated restore, integrity/authorization checks, uncertain-work reconciliation, critical user journey and measured recovery time/data loss. A successful file copy, encrypted archive or local synthetic drill is not witnessed bank DR, PITR, automatic failover or an agreed RTO/RPO.

## Q078. Can CryptoScan repair firewall rules, patch libraries or rotate keys automatically?

Not as a default consequence of a finding. Those are separate high-impact changes with owners, approvals, compatibility tests and rollback/recovery requirements. The scanner must not turn an inventory permission into production mutation authority.

For PQC work, verify application/protocol interoperability, vendor/firmware support, key lifecycle and deployment dependencies. Recommendations or reviewed workflow records are not proof that a patch/key rotation/firmware update actually occurred or succeeded.

## Q079. What evidence is required for a bank pilot to pass?

Agree acceptance before execution. Include independently known positives, negatives and intentional gaps; correct provenance and identities; exact allowed and denied scope; cross-estate refusal; resource/timeout/cancellation/cleanup behavior; original tamper refusal; export permissions; and operator recovery.

For Windows, actual approved native fixtures and independent review remain necessary; portable fake-native tests or Linux skips do not satisfy that requirement. Document the exact release/site/profile and residual risks. A single “success” screenshot or aggregate test count is insufficient.

## Q080. What should be included in the handover and commercial/support agreement?

Hand over the exact release/profile, accepted scope, exclusions/gaps, configuration/secret custodians, asset/evidence ownership, operating runbooks, backup/recovery evidence, monitoring/escalation matrix, change/upgrade procedure and access/retention rules.

Agree service hours, urgent response process, maintenance windows, measurable objectives, responsibilities and vendor access terms explicitly. Do not infer price, capacity, accuracy, uptime, legal compliance or staffing guarantees from this FAQ. Operational promises must be supported by the actual people, infrastructure, tests and contract.

### References

[Operating model/weekly support](../BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md) · [operator recovery runbook](../runbooks/operator-install-upgrade-recover.md) · [recovery documentation](../disaster-recovery/README.md) · [acceptance ledger](../bank-environment/60-host-first-product-acceptance.md)
