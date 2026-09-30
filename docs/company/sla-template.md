# Service Level Agreement template

**Template status:** counsel and operations review required; not a commitment
until attached to a signed Order Form
**Version:** `SLA-DRAFT-1.0`
**Service:** CryptoScan `[DEPLOYMENT MODEL]`
**Customer:** `[CUSTOMER LEGAL NAME]`

This SLA provides a structure for availability, support, response, maintenance,
service credits, and measurement. The parties must choose values they can
actually staff and measure. The draft operational policy in the repository is
not an SLA.

## 1. Service scope

The SLA applies only to the Services, environments, regions, components, and
support tier identified in the Order Form. It does not automatically apply to
Customer-managed cloud, database, network, identity provider, HSM/KMS,
repository host, ticketing system, or other dependencies.

| Service item | Contracted value |
|---|---|
| Production environment | `[IDENTIFIER]` |
| Service region | `[REGION]` |
| Measurement window | `[UTC MONTH / 24X7 / BUSINESS HOURS]` |
| Support tier | `[STANDARD / ENHANCED / CRITICAL]` |
| Availability target | `[TARGET]` |
| Maintenance window | `[WINDOW]` |
| Support channel | `[PORTAL / EMAIL / PHONE]` |
| Severity matrix | See Section 5 |

## 2. Availability definition

**Monthly uptime percentage** is:

```text
(total minutes in the measurement month - qualifying downtime minutes)
/ total minutes in the measurement month × 100
```

A qualifying outage is a continuous period during which the contracted service
cannot perform its core agreed function, measured from the earlier of Vendor
monitoring detection or Customer ticket with sufficient evidence until service
is restored.

The Order Form must state whether the target is:

- platform availability;
- API availability;
- scan-job acceptance;
- completed scan processing;
- report/evidence export availability; or
- a combination with separate targets.

Do not describe a local development result, a pilot measurement, or a single
DR drill as a service availability guarantee.

## 3. Exclusions from uptime

Unless the Order Form says otherwise, downtime excludes:

- scheduled maintenance notified at least `[7]` days in advance;
- emergency maintenance reasonably necessary to prevent security or material
  operational harm;
- Customer systems, credentials, network, proxy, cloud, database, HSM/KMS,
  identity provider, or source-system failure;
- Customer's unauthorized or unsupported configuration;
- force majeure or internet-wide provider failure outside Vendor control;
- beta, preview, trial, or excluded features;
- suspension permitted by the MSA or Acceptable-Use Terms;
- denial-of-service or abuse caused by Customer or a third party targeting
  Customer; and
- downtime during a Customer-approved migration or change.

The parties should document how partial degradation, queue backlog, failed
connectors, and report-generation delay are measured.

## 4. Support channels and hours

| Tier | Coverage | Initial response | Target update |
|---|---|---:|---:|
| S1 critical | `[24X7 OR BUSINESS HOURS]` | `[15 min]` | `[60 min]` |
| S2 high | `[HOURS]` | `[60 min]` | `[4 hours]` |
| S3 normal | `[HOURS]` | `[1 business day]` | `[2 business days]` |
| S4 request | `[HOURS]` | `[2 business days]` | `[5 business days]` |

An initial response means acknowledgement, severity confirmation, owner
assignment, and next action. It does not guarantee resolution by that time.
Response targets apply only when Customer supplies the account, environment,
impact, logs, reproduction, and contact needed to investigate.

## 5. Severity matrix

| Severity | Example | Customer impact | Customer action |
|---|---|---|---|
| **S1 critical** | Complete service outage, confirmed serious security incident, material data-access event | Core service unavailable or material risk | Phone/portal immediately and maintain an incident contact |
| **S2 high** | Major feature unavailable, sustained scan failure, severe degradation | Important workflow blocked | Portal with impact, scope, and logs |
| **S3 normal** | Limited defect, connector issue, workaround available | Partial inconvenience | Portal with reproducible detail |
| **S4 request** | Question, enhancement, documentation, cosmetic issue | No material service impact | Normal support channel |

Severity may be reclassified as facts change. Customer must not classify every
finding or security question as an SLA outage.

## 6. Incident and security response

Security Incidents are handled under the MSA, DPA, Security Addendum, and
[Breach Notification Terms](breach-notification-terms.md). The SLA does not
replace the contractual incident-notification deadline.

A service ticket, outage, and Security Incident may have separate clocks and
owners. Vendor will preserve relevant logs and provide a factual status update
without speculating about legal conclusions.

## 7. Maintenance and changes

Vendor will provide notice of planned maintenance, expected impact, start/end
time, rollback plan, and customer action where practical. Emergency changes
may occur without the ordinary notice where necessary to protect security,
data, or availability.

Material changes to data processing, subprocessors, region, support boundary,
security controls, or service functionality are handled under the MSA, DPA,
Security Addendum, and applicable change-notice terms.

## 8. Service credits

If service credits are agreed, the Order Form should state:

| Monthly uptime | Credit against affected monthly fee |
|---|---:|
| `[99.9%]` to target | 5% |
| `[99.0%–99.89%]` | 10% |
| `[<99.0%]` | 20% |

The values above are examples only. Credits should:

- be the exclusive remedy for availability failure unless the MSA says
  otherwise;
- be claimed within `[30]` days after the measurement month;
- not be paid in cash;
- not exceed `[20%]` of the affected monthly fee unless negotiated; and
- not apply to excluded downtime.

Regulated or strategic customers may negotiate a different remedy structure,
including termination rights after repeated failure.

## 9. Measurement and reporting

Vendor will maintain monitoring and incident records sufficient to calculate
the target. On request, Vendor will provide a monthly service report containing:

- total minutes and excluded minutes;
- qualifying outages and timestamps;
- incident identifiers;
- response and restoration times;
- maintenance periods;
- credits calculated;
- major changes; and
- known limitations in measurement.

Customer may challenge a report within `[30]` days with reasonable evidence.
The parties will use synchronized UTC time for service records.

## 10. Customer dependencies

Customer will:

- maintain supported identity, network, cloud, database, HSM/KMS, and source
  configurations;
- provide correct permissions and contact information;
- avoid rate limits or scanning patterns outside the Order Form;
- maintain Customer-managed backups and disaster recovery where applicable;
- promptly notify Vendor of changes;
- participate in incident and recovery exercises when required; and
- not rely on CryptoScan as the sole control for a regulated obligation.

## 11. Business continuity and disaster recovery

The Order Form must state the service-level targets, not infer them from a
local drill:

| Target | Contract value |
|---|---|
| RPO | `[VALUE]` |
| RTO | `[VALUE]` |
| Recovery region/site | `[VALUE]` |
| Failover decision owner | `[VALUE]` |
| Customer dependencies | `[VALUE]` |
| Exercise frequency | `[VALUE]` |

The parties must define what is restored: service, database, evidence, audit
chain, configuration, integrations, and customer-specific secrets.

## 12. Termination for service failure

Repeated material failure of the availability or support commitments may give
Customer a termination right or service-credit remedy as stated in the MSA and
Order Form. Define the threshold, measurement period, notice, cure period, and
refund treatment.

## 13. Acceptance

This SLA becomes effective only when signed or incorporated into a signed
Order Form.

```text
[VENDOR LEGAL NAME]                 [CUSTOMER LEGAL NAME]

By: __________________________      By: __________________________
Name: ________________________      Name: ________________________
Title: _______________________      Title: _______________________
Date: ________________________      Date: ________________________
```
