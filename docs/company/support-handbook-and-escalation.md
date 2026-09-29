# Support handbook and escalation matrix

**Status:** operations template; not a support commitment until attached to the
SLA/Order Form
**Owner:** `[SUPPORT OWNER]`
**Service:** CryptoScan `[SERVICE]`

An SLA states targets. This handbook explains how the service is actually
staffed, contacted, triaged, escalated, and measured.

## 1. Support model

| Tier | Coverage | Channel | Owner | Target |
|---|---|---|---|---|
| Standard | `[BUSINESS HOURS/TZ]` | Portal/email | Support desk | `[TARGET]` |
| Enhanced | `[EXTENDED HOURS]` | Portal/email/phone | Named technical contact | `[TARGET]` |
| Critical | `[24X7 IF STAFFED]` | Portal/phone/secure channel | On-call incident team | `[TARGET]` |

Do not advertise 24x7 unless every shift has a named, trained, reachable
responder and an escalation path.

## 2. Contact card

```text
Support portal: ___________________________
Support email: ____________________________
Security contact: __________________________
Privacy contact: ___________________________
Critical phone: ___________________________
Customer account owner: ___________________
Escalation manager: _______________________
Emergency secure channel: _________________
```

Test every channel before the customer receives it and at least quarterly.

## 3. Ticket content

Customer should provide:

- account, environment, and region;
- issue start time in UTC;
- impact and affected users/systems;
- last known good state;
- reproduction steps;
- request ID/job ID/report ID;
- relevant safe logs;
- recent change;
- customer-side dependencies; and
- customer contact and severity rationale.

Never attach passwords, private keys, tokens, or unnecessary Personal Data.

## 4. Triage procedure

1. acknowledge and authenticate the requester;
2. create a ticket and correlation ID;
3. classify support, outage, security, privacy, or billing;
4. assign severity from the SLA;
5. confirm customer scope and deployment;
6. preserve relevant evidence;
7. assign an owner and next-update time;
8. communicate facts, uncertainty, and workaround;
9. escalate when threshold or time is reached;
10. validate recovery with the customer;
11. document root/contributing cause; and
12. close only after review or customer timeout under the contract.

## 5. Escalation matrix

| Trigger | Primary | Secondary | Executive/legal |
|---|---|---|---|
| Core service outage | On-call/SRE | Engineering lead | Operations executive |
| Suspected security incident | Security lead | Incident commander | Legal/privacy executive |
| Personal Data concern | Privacy lead | Security lead | DPO/counsel |
| HSM/KMS failure | Crypto/platform lead | Provider | Security executive |
| Backup/restore failure | SRE/database | Security | Operations executive |
| Repeated SLA failure | Support manager | Account owner | Commercial executive |
| Customer risk dispute | Account owner | Product/security | Executive sponsor |
| Contract/legal issue | Account owner | Counsel | Authorized signatory |

## 6. Update rules

A status update should state:

- current status;
- impact and scope;
- actions completed;
- next action and owner;
- known limitation or dependency;
- next update time; and
- whether the event is a Security Incident or privacy matter.

Do not promise resolution time unless the SLA or incident leader approved it.
Do not speculate on root cause or legal breach status.

## 7. Support access

Support access must be:

- named and authenticated;
- least privilege;
- time-bounded;
- approved where required;
- logged;
- restricted to the agreed region and data;
- revoked after the task; and
- reviewed after use.

## 8. Metrics and review

Report monthly or quarterly:

- ticket count by severity;
- response and resolution times;
- reopen rate;
- SLA credits;
- recurring incidents;
- customer-impacting changes;
- security/privacy escalations;
- access events;
- support channel tests; and
- open corrective actions.

## 9. Runbook references

Attach the actual runbooks for authentication failure, connector failure,
worker backlog, database outage, HSM timeout, evidence verification,
backup/restore, incident response, and deletion. A handbook without runbooks
is a directory, not an operating process.
