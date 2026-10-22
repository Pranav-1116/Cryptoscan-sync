# 7. Demonstrate operations and qualify the intended bank deployment

[Pack index](README.md) · [Previous: testing/release](06-testing-maintainability-and-release.md) ·
[Next: execution roadmap](08-execution-roadmap-and-acceptance.md)

## 7.1 Software quality and production acceptance are different

Improving code can make a parser correct, a job durable or a refusal consistent.
It cannot hire an assessor, assign real operators, authorize a network probe,
provide customer data, witness recovery or sign a service contract.

This guide uses the **existing** Launch readiness and operator-package workflows.
Do not add a second approval portal, compliance feature or dashboard. The missing
improvement is often exercising the existing process with real accountable people
and independently retained evidence.

## 7.2 Ownership: distinguish who fixes from who accepts

| Role | Responsibility | Cannot substitute for |
|---|---|---|
| Product owner | Freeze supported scope, prioritize quality, keep claims accurate | Customer acceptance or security independence |
| Engineering owner | Reproduce/fix/retest source behavior and maintain release contracts | Witnessed site operation or bank permission |
| QA owner | Execute coverage matrices, retain failures and reproduce results | Customer ground truth where none was supplied |
| Site/platform operator | Provision approved runtime/storage/CAs, deploy and rehearse recovery | Independent review of their own exercise |
| Bank technical/data owner | Authorize sources, expected target register and contextual/accuracy review | Evidence of unobserved systems or automatic production invocation |
| Security assessor/reviewer | Independently assess agreed scope and review remediation/retests | Origin signature alone proving independence |
| Customer decision owner | Review exact bounded outcome, exclusions and acceptance freshness | Whole-bank/commercial approval outside the charter |
| Legal/service owner | Agree actual support/notification/retention obligations | A software record automatically authorizing an SLA |

Actual assignments must follow existing permissions and segregation rules. One
person cannot silently fill conflicting proposer/operator/reviewer/customer roles.

## 7.3 Turn the nine existing duties into practiced capability

Follow [guide 57](../bank-environment/57-operational-ownership-and-demonstrated-service.md).
Its records require real active primary/backup humans, separate acknowledgements,
retained procedure bytes, fresh exercises and different-human review.

| Existing duty | Practical improvement/rehearsal | Evidence of a useful outcome |
|---|---|---|
| Vulnerability response | Exercise an advisory against exact current release/component identity, owner/change/retest | Exposure decision and verified response, including unresolved supplier delay |
| Incident response | Rehearse escalation, authorized containment/stop and evidence preservation | Actual decision timeline, missed escalation paths and independently reviewed follow-up |
| Backup/restore | Restore SQL, evidence, configuration and approved secret dependencies in isolation | Verifiable records/links, access checks, measured loss/recovery—not merely “backup completed” |
| Certificate rotation | Rehearse intended endpoint/trust change and rollback | Before/after exact fingerprints, affected/excluded paths and client checks |
| Credential rotation | Exercise new credential activation, revocation and failed old access | Secret-free proof that new access works and old access does not |
| Support escalation | Contact primary and backup through approved channels/service hours | Real acknowledgement/response times and failed-channel handling |
| Release approval | Rehearse reviewed package, migration, failed rollout and recovery | Exact artifact/signature/compatibility result and witnessed operating actions |
| Data retention | Rehearse expiry, legal hold, archive, derived data and backup dependencies | Allowed retained/deleted states, ownership and limitations |
| Customer offboarding | Rehearse authorized export, access/job/integration revocation and hold/deletion | Tenant-scoped completion plus cross-estate negative checks |

A beautifully written procedure is still unexercised until people demonstrate
it. Failed/INCONCLUSIVE exercises stay visible and create follow-up work. Changes
to owner, procedure, environment or evidence can invalidate the previous acceptance.
**`sla_authorized` remains false** in the implemented assertion workflow.

## 7.4 Qualify the exact site, not “Kubernetes in general”

Use the [operator install/upgrade/recover runbook](../runbooks/operator-install-upgrade-recover.md):

1. Identify legal estate, approved regions/destinations, namespace, hostnames,
   runtime/isolation configuration, actual images and dependency identities.
2. Have the site owner provision verified PostgreSQL/Redis, CA bundles, secrets,
   least-privilege runtime/migration roles, regional encrypted/quota-controlled storage
   and approved backup/retention. Configuration strings alone do not prove residency.
3. Verify package inventory and externally trusted release attestation before install.
4. Rehearse installation and coordinated 0105 upgrade on approved representative infrastructure.
5. Run the critical current journey with permitted non-production data and negative identities.
6. Rehearse isolation/resource limits, permitted fault scenarios and isolated restore;
   preserve pre-fault acknowledgements and actual observed recovery.
7. Run representative sustained workloads and real-browser task/endurance checks.
8. Have a different reviewer assess results, exclusions, failures and requalification triggers.

No shared hostile-tenant Docker-daemon isolation, HA, cross-region failover or
live-collector support is implied. If the bank needs a topology outside the
reviewed profile, that is a separately authorized scope—not a shortcut in this
no-feature program.

## 7.5 Obtain independent security results for the actual candidate

Use [guide 56](../bank-environment/56-independent-security-assurance.md), not a
self-written certificate. Procure/confirm assessor competence, independence,
confidentiality, scope and rules of engagement. Supply the exact intended artifact,
configuration and environment under approved access.

Retain the original report plus its authenticated signed release/estate/scope
binding, limitations and explicit untested areas. Track each actual finding to an
accountable owner, independently approved disposition/change and later exact
signed retest. An origin-verified manifest does not itself establish independence;
a closed internal ticket does not establish resolution of an assessor's finding.

Any signing/retest example in the repository is tooling/template material until
actual external actors and evidence are supplied. Never generate their identities,
private keys, completed test cases or report conclusions to satisfy a gate.

## 7.6 Validate value with one bounded customer workflow

Use [guide 58](../bank-environment/58-focused-payments-customer-pilot.md). The
quality objective is to prove useful existing behavior, not expand collection:

- one payments application/release with exact source, separately hashed SBOM,
  artifact and deployment provenance;
- independent expected SOURCE/ENDPOINT/DEPLOYMENT/HARDWARE/SUPPLIER targets;
- existing hardware/supplier evidence and authorized endpoint receipts with
  clear observed versus declared/reviewed provenance;
- one actual applicable condition, owner, separate approval, reported action and
  later exact-condition proof;
- customer-reviewed accuracy/held-out evidence for the source classes actually in scope;
- technical approval followed by a different customer-owner acceptance, bound to
  the current evidence fingerprint and explicit exclusions.

Live TLS/SSH acquisition is still refused in the controlled local-source profile.
Externally collected receipts require their own authorized qualified source and
existing intake/review contract; do not enable an unqualified internal collector
for the pilot. If required evidence cannot be legitimately supplied, acceptance
stays blocked/partial—not fabricated.

## 7.7 Required evidence handling

For every qualification record retain, in the approved evidence store:

- exact release/configuration/profile and actual source/fixture identities;
- UTC start/end and environment, command/procedure and operator;
- permission and approved impact boundaries;
- original output, expected versus actual result, failures and limitations;
- artifact digests and accountable custody/access/retention;
- different reviewer's identity/decision and recheck deadline/triggers.

A hash proves integrity, not origin or truth. Sensitive customer/provider material
must not be committed just because the gate accepts a local file path. Machine
artifacts retain their original results; an amended summary references new proof
rather than rewriting an earlier FAIL to PASS.

## 7.8 Decision and ongoing service

The [production-readiness gate](../../PRODUCTION-READINESS.md) remains the release
approval authority defined by its required categories. Missing mandatory evidence
is SKIP/blocking; an allowed exception process cannot masquerade as an all-PASS run.
HSM/provider requirements must follow the actual gate and scope—do not skip a
required category merely because this bounded pilot did not touch the device.

After an authorized acceptance, repeat relevant proof when release/dependencies,
parser/schema, policy/authority, identities, trust, topology, procedures, scope or
freshness changes. Preserve historical acceptance while distinguishing whether
it remains valid now. Do not promise perpetual qualification or 24/7 support
from one successful exercise.

**Exit:** an exact scoped decision, with current independently reviewed evidence,
actual operating capability and explicit exclusions. This document does not
supply that decision, certification or an SLA.


## 7.9 Continuous bank operation and weekly product-team support

The intended accepted deployment remains running 24/7. Bank SOC/security monitors
approved signals; bank platform/database owners and on-call backups operate the
infrastructure. Our team performs an agreed weekly preventive review, investigates
product errors and prepares tested corrections. This is quality/operating work,
not a new collector, scheduler or monitoring feature.

Critical incidents must escalate when detected, not wait until the weekly review.
Actual vendor after-hours availability and any response/service objectives require
separate staffed agreements. Weekly review does not authorize automatic updates,
permanent remote access or unreviewed production fixes. The existing supported
profile/refusals, independent review and `sla_authorized=false` remain unchanged.

Use the [detailed 24/7 and weekly-support procedure](../BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md)
for the daily/weekly duties, error-to-fix process, approved updates, access controls
and unexecuted review template. Rehearse it before claiming operational acceptance.
