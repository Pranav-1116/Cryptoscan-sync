# Customer security architecture package

**Status:** customer-specific architecture template
**Owner:** Security Architecture
**Review:** update for every deployment model, region, material release, and
subprocessor change

This document is the cover sheet for the architecture pack delivered under an
NDA. It must be completed from the actual deployment, not copied from a generic
diagram.

## 1. Scope and deployment identity

| Field | Value |
|---|---|
| Customer | `[CUSTOMER]` |
| Order Form | `[REFERENCE]` |
| Deployment | customer-managed / dedicated managed / private / air-gapped |
| Environment | pilot / staging / production |
| Release | `[VERSION AND COMMIT/DIGEST]` |
| Primary region | `[REGION]` |
| DR region | `[REGION OR NONE]` |
| Data classification | `[CLASSIFICATION]` |
| Architecture owner | `[OWNER]` |
| Review date | `[DATE]` |

## 2. Component inventory

Complete the actual version and trust boundary for each component.

| Component | Function | Data handled | Network zone | Identity | Customer/Vendor owner |
|---|---|---|---|---|---|
| Web/console | User interface | Session and result metadata | `[ZONE]` | SSO/local/API | `[OWNER]` |
| API | Authentication, queries, writes | Customer and scan metadata | `[ZONE]` | Service/user auth | `[OWNER]` |
| Worker | Scan and processing jobs | Source artifacts and findings | `[ZONE]` | Queue/service identity | `[OWNER]` |
| Scheduler/monitor | Scheduled jobs and health | Job and telemetry metadata | `[ZONE]` | Service identity | `[OWNER]` |
| PostgreSQL | System of record | Inventory, findings, audit | `[ZONE]` | DB role/secret | `[OWNER]` |
| Redis/queue | Cache and job coordination | Job metadata | `[ZONE]` | Service identity | `[OWNER]` |
| Evidence/object store | Reports and evidence | Customer evidence | `[ZONE]` | Scoped service role | `[OWNER]` |
| Graph store | Relationships and impact | Asset relationships | `[ZONE]` | Scoped service role | `[OWNER]` |
| HSM/KMS | Key/signing boundary | Key references and operations | `[ZONE]` | Provider identity | `[OWNER]` |
| Logging/SIEM | Audit and security events | Logs and alerts | `[ZONE]` | Log shipper | `[OWNER]` |
| Backup/DR | Recovery | Encrypted copies | `[ZONE]` | Backup role | `[OWNER]` |

## 3. Trust boundaries

The diagram and narrative must label:

1. customer users to console/API;
2. customer IdP to the service;
3. API to database, queue, graph, evidence, and monitoring;
4. worker to source repositories, clouds, networks, and artifacts;
5. evidence to signing/HSM/KMS boundary;
6. production to support access;
7. primary to backup/DR;
8. Vendor infrastructure to subprocessors; and
9. customer-managed to Vendor-managed responsibility.

For every boundary record protocol, authentication, authorization, encryption,
logging, allowed direction, and failure behavior.

## 4. Data-flow register

| Flow | From | To | Data | Protocol | Encryption | Auth | Region | Retention |
|---|---|---|---|---|---|---|---|---|
| F-01 | User | Console/API | Identity and query data | HTTPS | TLS `[VERSION]` | SSO/API key | `[REGION]` | `[PERIOD]` |
| F-02 | Source | Worker | Approved source metadata/artifact | `[METHOD]` | `[CONTROL]` | Read-only role | `[REGION]` | `[PERIOD]` |
| F-03 | Worker | Database | Inventory/findings | Private channel | `[CONTROL]` | Service identity | `[REGION]` | `[PERIOD]` |
| F-04 | Evidence | Object store | Reports and manifests | Private channel | `[CONTROL]` | Scoped role | `[REGION]` | `[PERIOD]` |
| F-05 | Service | SIEM/ticketing | Audit/events/findings | `[METHOD]` | `[CONTROL]` | Integration secret | `[REGION]` | `[PERIOD]` |
| F-06 | Primary | Backup/DR | Encrypted backup | `[METHOD]` | `[CONTROL]` | Backup role | `[REGION]` | `[PERIOD]` |
| F-07 | Support | Service | Approved support data | `[METHOD]` | `[CONTROL]` | Time-bound access | `[REGION]` | `[PERIOD]` |

Unknown or unapproved flows are a blocker before Personal Data processing.

## 5. Security controls

Complete evidence for:

- identity, MFA, SSO, API-key lifecycle, and break-glass;
- network ingress/egress and proxy;
- tenant and customer-scope isolation;
- secrets storage and rotation;
- HSM/KMS key controls;
- encryption in transit and at rest;
- database and object-store hardening;
- logging, monitoring, and alert routing;
- image and release integrity;
- vulnerability and patch management;
- backup, restore, and deletion;
- incident response and support access; and
- secure SDLC and change approval.

## 6. Responsibility matrix

| Control | Customer-managed | Vendor-managed | Evidence |
|---|---|---|---|
| Cloud account and network | Customer | Vendor/provider | `[ARTIFACT]` |
| Application release | Vendor | Vendor | `[ARTIFACT]` |
| Database operation | Customer | Vendor/provider | `[ARTIFACT]` |
| HSM/KMS | Customer or agreed provider | Agreed provider | `[ARTIFACT]` |
| Identity and MFA | Customer/IdP | Vendor integration | `[ARTIFACT]` |
| Backup/restore | Customer | Vendor | `[ARTIFACT]` |
| Source authorization | Customer | Customer | `[APPROVAL]` |
| Findings/remediation | Customer | Customer | `[WORKFLOW]` |
| Incident coordination | Shared | Shared | `[TERMS]` |

## 7. Review and evidence

The architecture pack must be reviewed by security architecture, privacy,
operations, and the customer owner. It must carry the release, environment,
regions, owner, reviewer, date, limitations, and document digest.
