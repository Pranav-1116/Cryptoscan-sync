# On-Call Roster & Communication Tree

**Version:** 1.0 (template — fill in, then reference from the Incident
Response Policy §2) · **Owner:** [ORG: CISO] · **Next review:**
[ORG: YYYY-MM-DD]

This is the working document behind the Incident Response Policy's
severity model: who is called, in what order, and how fast external
parties hear from us. Keep it current — a stale roster is the most common
incident-response failure mode.

## 1. On-call roster

Rotation: [ORG: e.g. weekly, rotating Monday 06:00 UTC; tool: PagerDuty /
ops alerting] · Coverage target: 24×7 during business-critical hours,
8×5 otherwise [ORG: confirm].

| Period (UTC) | Primary | Secondary | Escalates to |
|--------------|---------|-----------|--------------|
| [ORG: 2026-Q4 wk 1–4] | [ORG: name] | [ORG: name] | [ORG: Engineering Director] |
| [ORG: 2026-Q4 wk 5–8] | [ORG: name] | [ORG: name] | [ORG: Engineering Director] |
| [ORG: …] | [ORG: name] | [ORG: name] | [ORG: Engineering Director] |

Backfill rule: if the primary does not acknowledge within
[ORG: 5] minutes, the pager escalates to the secondary; after
[ORG: 15] minutes, to the escalation owner.

## 2. Escalation tree (by severity)

| Severity | First call | Then | Involve immediately |
|----------|-----------|------|---------------------|
| SEV-1 | primary on-call | secondary → Engineering Director | CISO, DPO (if personal data), legal/comms |
| SEV-2 | primary on-call | Engineering Director within 1 h | CISO if containment not in 4 h (auto-SEV-1) |
| SEV-3 | primary on-call (next business-day triage queue) | security lead | — |
| SEV-4 | triage queue | security lead | — |

## 3. Communication SLAs (mirrors Incident Response Policy §5)

| Audience | Trigger | Clock | Owner of the message |
|----------|---------|-------|----------------------|
| Internal stakeholders | SEV-1/2 declaration | [ORG: 30 min] | incident commander |
| Affected tenant(s) | confirmed SEV-1/2 affecting the tenant | [ORG: 24 h written, per client contract] | CISO-approved comms |
| Tenant technical summary | after containment | [ORG: 5 business days] | engineering |
| Regulator / data subjects | confirmed personal-data breach | 72 h from confirmation (PDPL / DIFC / ADGM) | DPO decides content & timing |
| Supervisors (CBUAE/DORA context) | client institution notifies | technical facts within [ORG: 24 h] | CISO + client |

## 4. Channels

- War room / bridge: [ORG: channel + bridge number]
- Status updates cadence: [ORG: every 30 min for SEV-1, 1 h for SEV-2]
- Post-incident review: within [ORG: 10 business days], stored with the
  incident record (Incident Response Policy §4.5)

## 5. Maintenance

- Roster reviewed at the start of every rotation and at the quarterly
  access recertification (the same meeting reviews access — the people
  with pager access are the people being reviewed).
- Table-top drill using this roster: [ORG: at least annually, including
  one personal-data breach scenario] (Incident Response Policy §6.3).
