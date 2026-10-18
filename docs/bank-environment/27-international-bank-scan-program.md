# 27 — International-bank scanning: program, scope and end-to-end design

[Bank guide index](README.md) · [Vendor onboarding](28-multi-vendor-access-and-evidence.md) ·
[Collection playbooks](29-system-by-system-collection-playbooks.md) ·
[Engineering priorities](33-international-bank-engineering-and-rollout.md)

**Planning baseline: 2026-10-18.** This guide describes the next improvement
program, not newly implemented functionality or a certification. Current code
references and unqualified boundaries are separated throughout guides 27–34.

## 1. The direct answer: what needs to improve next?

To assess a multinational, multi-vendor bank, prioritize these capabilities:

1. **One enforceable collection contract across every execution path.** The
   same scope, approval, window, stop, credential, budget and durable-receipt
   rules must apply to direct APIs, scheduled work, workers and imports.
2. **Regional and legal-entity boundaries.** A tenant boundary alone does not
   establish country-level residency, supplier segregation or permitted exports.
3. **Vendor evidence assurance.** Bind supplied documents to the exact product,
   build, deployment and customer environment; verify signer authority where
   available; retain declared, observed, stale and unknown states separately.
4. **Expected-estate reconciliation.** Compare what owners say should exist to
   what collectors could actually inspect, without claiming discovery is complete.
5. **Qualified adapters for the bank's actual versions.** Test specific HSMs,
   mainframe extracts, private clouds, network appliances and SaaS interfaces.
6. **Distributed safe scheduling.** Enforce fair, bounded regional work, provider
   API quotas, per-device concurrency, retries and restart-safe completion.
7. **End-to-end identity and evidence lineage.** Preserve source commit, artifact
   digest, deployment, listener, hardware partition and vendor contract identities.
8. **Independent production qualification.** Live databases, parser isolation,
   loss/retry tests, backup/restore, access/export tests and operational sign-off
   must supplement local unit tests.

The previous ten dependency-intelligence steps are locally delivered. They do
not automatically supply all eight enterprise controls above. See
[guide 26](26-bank-negative-tests-and-backend-qualification.md) for that boundary.

The [documentation center](../README.md) records the supported topology as one
deployment per customer. Local tenant-negative tests are not approval to launch
a pooled multi-bank service. Regional planes/federation in this pack are a target
design requiring separate bank-controlled qualification; they are not an
already-supported automatic federation feature.

## 2. What “the entire bank” can realistically mean

An international bank is not one IP range. It contains legal entities, acquired
banks, branches, data centers, cloud organizations, third-party services, payment
systems and shared platforms. One service can span several countries and owners.

The useful objective is:

> Account for every registered in-scope system and required evidence surface,
> collect only authorized facts, expose every unresolved gap, and preserve the
> ability to explain each conclusion for a particular assessment date.

It is **not** “a single scanner can read all vendors' internals” or “no findings
means the bank is secure.” CryproScan focuses on cryptographic inventory and
security configuration. Integrate complementary vulnerability management, EDR,
SAST/DAST, penetration testing, fraud and resilience processes where required;
do not rename crypto collection as those disciplines.

### Build an estate register before scheduling probes

For each service record:

- Bank/legal-entity ID, geography, environment, business owner and technical owner.
- Critical business service, dependencies, service hours and impact tolerance.
- Hosting accounts, network zones, clusters, physical sites and DR location.
- Supplier legal entity, product/version, implementation partner and operator.
- Data classification, approved evidence location and permissible recipients.
- Exact collection targets, methods, authorization expiry and exclusions.
- Expected inventories, freshness requirements and accepted collection windows.
- Relationship authority: who may assert a dependency or correct a deployment map.

These are proposed program fields, not a claim that one current API accepts
this complete record. Maintain a controlled register until an implementation is
reviewed. Never place credentials or customer account data in the register.

## 3. Why multiple vendors create structural blind spots

Consider a mobile-payment service:

```text
Bank mobile application
  -> bank edge/CDN/WAF -> bank API gateway -> vendor payment switch
  -> mainframe ledger interface -> bank ledger
  -> HSM service for selected signing/PIN/key-management operations
  -> external clearing or payment service
```

An arrow is an architectural hypothesis until supported by a bank declaration
or evidence. Different operations may take different paths. An API gateway TLS
certificate does not identify the switch's software packages, the mainframe's
key inventory or the HSM partition serving that transaction.

The bank may own the application but lease the switch, outsource the HSM and
consume the clearing interface as SaaS. It can inspect only its approved
boundary in some of those locations. Whole-service assessment therefore combines
bank observations, vendor evidence and explicitly unknown internal segments.

## 4. The end-to-end operating lifecycle

| Stage | Work and accountable owner | Required exit evidence |
|---|---|---|
| 1. Charter | Sponsor, risk and operations define objective and exclusions | Approved scope, critical services and risk ownership |
| 2. Legal/data review | Counsel, privacy, procurement and regional control owners | Right to inspect, supplier consent, data/export/retention rules |
| 3. Inventory baseline | CMDB, cloud, application and vendor owners reconcile registers | Versioned expected inventory; known unknowns, not a guessed denominator |
| 4. Collector design | Platform/security and each asset owner select least-invasive method | Target-specific permission, credential and data-flow review |
| 5. Qualification | Isolated test environment and vendor-approved samples | Positive/negative parser, safety, persistence and isolation evidence |
| 6. Canary | Operations authorize one low-risk representative target | Baseline metrics, observed load, correct stop behavior and receipt |
| 7. Bounded collection | Regional operators execute approved batches | Complete/partial/blocked/failed receipts with times and limits |
| 8. Reconciliation | Owners compare expected targets and accepted evidence | Missing, stale, unsupported and disputed items assigned to owners |
| 9. Analysis | Crypto, architecture and business owners review six BOMs and graph | Exact identity joins, provenance, coverage and qualified exposure |
| 10. Remediation | Change management and vendors plan corrections | Approved change, rollback and testing plan; no automatic key rotation |
| 11. Verification | Independent reviewer checks new facts against old scope | New observations, compatibility review and retained original history |
| 12. Continuous operation | Service owners manage freshness and events | Requalification after releases, credentials, scope or policy changes |

A queue acknowledgment proves stage 7 was requested, not completed. An exported
BOM proves a view was generated, not that every expected target was inspected.

## 5. Design regional collection, not global credential reach

A recommended target architecture is a regional execution and evidence plane:

```text
Approved global governance view (only permitted summaries)
                  ^ explicit disclosure/export decision
Regional control + evidence plane for each permitted boundary
                  ^ authenticated, scoped collection receipts
Zone-local collectors or controlled metadata-import workstations
                  ^ least-privilege, approved reads only
Bank systems / vendor-authorized interfaces / sanitized vendor packages
```

This is an architecture recommendation. The repository's local components do
not, by their existence, prove a complete federated multi-region product.

Keep source code, sensitive logs and detailed device evidence local where the
bank's rules require it. Even hostnames, dependency graphs and supplier counts
can be confidential. Do not assume that hashing a hostname, or sending only a
risk score, makes a cross-border transfer permissible.

A global coordinator must not hold every country's root/admin credentials.
Regional collectors should receive only the work and credentials they need.
Disconnection should produce delayed/unknown coverage, not bypass residency by
uploading everything to an unrestricted fallback region.

## 6. The six BOMs are complementary evidence views

| View | Question | Common invalid conclusion |
|---|---|---|
| **SBOM** | Which software components are declared or extracted for particular bytes/builds? | Every declared component is running in production |
| **NBOM** | Which approved network facts were observed at specified endpoints/times? | One listener handshake describes every backend or allowed protocol |
| **CBOM** | Which crypto primitives, uses and evidence were identified? | An algorithm name proves implementation safety or actual runtime use |
| **TechBOM** | How do registered technology/application layers relate? | Its system/package projection is a universal transitive software census |
| **HBOM** | Which hardware/model/firmware/capability facts are supported? | A product brochure attests the installed HSM or creates a system link |
| **VBOM** | Which suppliers/products/assertions and relationships are known? | Supplier assertions are independently observed bank configuration |

All six are required; none replaces SBOM. Use
[guide 30](30-evidence-pipeline-identity-and-coverage.md) for explicit joins.

## 7. Who must participate

- **Sponsor/CISO:** objective, unresolved-risk acceptance and escalation.
- **Service and application owners:** authoritative scope and deployment mapping.
- **SOC/network/SRE:** canaries, traffic approval, monitoring and emergency stop.
- **Regional privacy/legal/compliance:** transfer, retention and disclosure decisions.
- **Procurement/vendor management:** contractual evidence and subcontractor access.
- **HSM/key custodians and mainframe operators:** approved metadata extraction;
  never delegation of ceremony secrets to a general scanning platform.
- **Platform engineering:** isolation, credentials, storage, recovery and adapters.
- **Independent assurance:** challenge coverage, evidence and acceptance claims.

No team can substitute for the supplier's permission to inspect its property.
A bank administrator's role in CryproScan is not a legal right to scan a vendor.

## 8. Definition of an honest assessment handoff

Deliver a versioned scope register, per-target outcomes, six BOMs, evidence
references, dependency assumptions, gap register, supplier disputes, prioritized
actions and a signed-off acceptance record. State which conclusions are
observations, supplied declarations or modeled projections. State what failed,
what expired, what was excluded and what could not be supported.

“End to end” means this traceable lifecycle. It does not mean omniscient access
or a guarantee of operational continuity.
