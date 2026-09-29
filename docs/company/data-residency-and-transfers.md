# Data residency and international transfer terms

**Status:** deployment-specific template; privacy/legal review required  
**Customer:** `[CUSTOMER LEGAL NAME]`  
**Service:** CryptoScan `[DEPLOYMENT MODEL]`

A customer-selected hosting region is not, by itself, a complete residency
statement. The actual assessment must cover application, database, evidence,
logs, backups, monitoring, support access, subprocessors, incident response,
remote administration, and exports.

## 1. Residency decision

Complete this table for each customer deployment.

| Component or activity | Legal entity/operator | Physical region | Support access region | Data categories | Customer-controlled? |
|---|---|---|---|---|---|
| Application/API | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Database | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Evidence/object storage | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Logs/monitoring | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Backup/DR | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Support/ticketing | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Subprocessors | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |
| Customer export | `[ENTITY]` | `[REGION]` | `[REGION(S)]` | `[CATEGORIES]` | `[YES/NO]` |

## 2. Deployment models

### Customer-managed

Customer selects and operates compute, database, storage, network, backup,
identity, and many support controls. Vendor must still identify remote support,
updates, telemetry, subprocessors, and any copied evidence.

### Vendor-managed dedicated

Vendor operates an agreed dedicated deployment. Vendor must identify the
hosting legal entity, cloud region, support locations, backup region, failover
region, monitoring, and subprocessor paths.

### Air-gapped or offline

The deployment may avoid ordinary outbound transfers, but signed update
bundles, vulnerability feeds, support imports, certificate rotation, and
incident exports still require a documented path and transfer review.

### Shared service

Shared multi-tenant deployment requires independent qualification of tenant
isolation, every API and worker path, queues, caches, object storage, exports,
background jobs, support access, and backup/restore. It must not be represented
as the default bank posture solely because tenant filters exist.

## 3. International transfer mechanism

For every transfer of Personal Data across a legal or geographic boundary,
identify the lawful mechanism:

- adequacy decision or equivalent;
- EU Standard Contractual Clauses;
- UK International Data Transfer Agreement or Addendum;
- approved binding corporate rules;
- explicit consent where legally suitable;
- another statutory exception used narrowly; or
- another jurisdiction-specific mechanism approved by counsel.

Complete a transfer impact assessment when required. Consider government access,
provider access, encryption, key control, minimization, support routes, and
supplementary measures.

Do not state that a provider's generic regional availability proves a lawful
transfer mechanism.

## 4. Supplementary measures

Possible measures include:

- customer-controlled deployment and storage;
- regional data and support restrictions;
- encryption in transit and at rest;
- customer-controlled HSM/KMS keys;
- key non-exportability;
- pseudonymization or masking;
- minimized source paths and fields;
- no private-key ingestion;
- strict role and support access;
- access logging and review;
- legal request notification where permitted;
- restricted subprocessor access; and
- deletion and retention controls.

A measure must be technically and contractually real for the deployment. A
statement in this template is not proof that the measure operates.

## 5. Customer responsibilities

Customer must:

- identify applicable residency, outsourcing, banking, secrecy, and regulator
  rules;
- approve service region and support locations;
- classify sources and Personal Data;
- approve cross-border transfers and subprocessors;
- define backup and DR location requirements;
- ensure its own exports and downstream systems comply;
- approve remote-support process; and
- record customer/regulator residual-risk decisions.

## 6. Residency statement template

> For the `[SERVICE/ORDER FORM]` deployment, primary application, database, and
> evidence storage operate in `[REGION]`. Backups operate in `[REGION]` and
> disaster recovery operates in `[REGION]`. Vendor support may be accessed from
> `[LOCATIONS]`. Subprocessors are listed in `[REGISTER]`. Customer Data is
> transferred under `[MECHANISM]` with supplementary measures `[MEASURES]`.
> Customer has approved this topology for `[PURPOSE/TERM]`.

This statement must be completed from actual deployment configuration and
approved by the customer's privacy/security owner.

## 7. Change control

A region, support location, provider, backup, remote access, or transfer change
requires privacy/security review and customer notice under the DPA before it is
used for Customer Data. Emergency changes must be documented and reviewed
retrospectively.
