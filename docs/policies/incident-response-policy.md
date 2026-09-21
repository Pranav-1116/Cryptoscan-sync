# Incident Response Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: CISO] · **Applies to:** all
personnel, contractors and automated systems · **Next review:**
[ORG: YYYY-MM-DD] · **Criteria:** TSC CC7.2, CC7.3, A1.4

## 1. Purpose

Define how CryptoScan detects, contains, eradicats and recovers from
security incidents, and how it meets its notification obligations.
Detection capability is a first-class control: the platform's alerting,
audit trail and tamper-evident evidence chain exist so that an incident
is *found by the system*, not discovered by a client.

## 2. Incident team

| Role | Person | Responsibility |
|------|--------|----------------|
| Incident commander | [ORG: on-call engineering lead] | coordinates, decides escalation |
| Technical lead | [ORG: on-call SRE] | containment, forensics |
| CISO | [ORG: CISO] | risk decisions, external comms approval |
| DPO | [ORG: DPO] | data-protection notification decisions |
| Legal/comms | [ORG: counsel] | regulator and client communications |

The names above are filled in and kept current in the working document
[`docs/ops/on-call-and-comms.md`](../ops/on-call-and-comms.md) — the
on-call roster, escalation tree and communication SLAs. A stale roster is
the most common incident-response failure; that document is reviewed at
every rotation and at the quarterly access recertification.

## 3. Severity

| Level | Definition | Response time | Example |
|-------|------------|---------------|---------|
| **SEV-1** | Active compromise, data exfiltration, or integrity failure of the evidence chain | immediate, < 1 h to contain | key theft, tenant-isolation bypass, evidence-chain break |
| **SEV-2** | Confirmed vulnerability exploited or available for exploitation; service degradation with security impact | < 4 h to contain | rate-limit bypass, auth bypass, sustained DoS |
| **SEV-3** | Suspicious activity, failed-control alarms, potential incidents | < 24 h triage | lockout storm, anomalous privileged access |
| **SEV-4** | Informational, policy observations | next business day | access-review finding, scan warning |

Escalation: SEV-2 auto-escalates to SEV-1 if containment is not achieved
within 4 hours.

## 4. Response phases

1. **Detection & triage.** Alerts arrive via the platform's alerting
   (the same pipeline that drives the dashboard) and the release/evidence
   guards: the evidence-chain verification step failing is by definition
   a SEV-1. Triage must determine scope, data classes affected
   (Data Classification Policy) and tenants affected.
2. **Containment.** Standard levers, in order of blast radius: revoke the
   suspect session/key (sessions and API keys are independently
   revocable), lock the account (account lockout is built-in), disable
   the endpoint or feature, and as a last resort take the service
   offline from client traffic while the pipeline continues on the
   recovery path.
3. **Eradication & recovery.** Remove the threat, patch or roll back
   under the Change Management Policy (emergency lane), restore from
   verified backups where integrity in doubt, and re-run the production
   evidence suite to prove the recovered state
   (`scripts/production_evidence.py`).
4. **Communication.** Internal per the comms tree; external per §5.
   All external statements are approved by the CISO; the DPO approves
   anything involving personal data.
5. **Post-incident review.** Within [ORG: 10 business days]: timeline,
   root cause, control gaps, action items with owners and due dates.
   The report is stored with the incident and its actions tracked to
   closure. Recurring root causes become change requests to the control
   itself.

## 5. Notification obligations

- **Data subjects / regulator:** the 72-hour clock under the UAE federal
  PDPL and the DIFC/ADGM laws runs from *confirmation* of a personal-data
  breach (Data Protection & Privacy Policy §2). The DPO decides
  notification content and timing.
- **Clients (tenants):** [ORG: define contractual notification SLA —
  recommended: written notice within 24 h of a confirmed SEV-1/SEV-2
  affecting the tenant, with a follow-up technical summary within 5
  business days.]
- **Supervisors (CBUAE / DORA context):** where CryptoScan supports a
  regulated payment institution, the *client institution* is the
  notifying party; CryptoScan provides the technical facts within
  [ORG: 24 h].

## 6. Exercises and evidence

1. The DR/incident drill (`deploy/ha/drill.sh`) is executed at least
   [ORG: semi-annually]; its output is captured into the production
   evidence chain when a docker host is available.
2. Each drill and each real incident produces a written record; the
   evidence for the SOC 2 window is the collection of these records plus
   the signed evidence runs in `docs/production-evidence.md`.
3. [ORG: table-top exercise for the full incident team at least annually,
   including one that simulates a personal-data breach to rehearse the
   72-hour notification path.]

## 7. Evidence and logging

All incident-relevant actions (session revocations, account locks,
rollbacks, restores) generate audit events. The tamper-evident nature of
the evidence chain means the incident timeline itself is an auditable
artifact.
