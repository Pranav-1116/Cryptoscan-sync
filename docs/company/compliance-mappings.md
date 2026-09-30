# Compliance and control mappings

**Status:** mapping template; not certification
**Owner:** `[COMPLIANCE OWNER]`
**Review cycle:** `[QUARTERLY/ANNUAL OR CUSTOMER REQUIREMENT]`

A mapping connects a framework requirement to an owner, control, evidence,
test frequency, exception, and evidence tier. It does not mean the company is
certified or legally compliant.

## 1. Mapping fields

| Field | Requirement |
|---|---|
| Framework | GDPR, ISO 27001, SOC 2, PCI, NIST, customer framework, etc. |
| Version/jurisdiction | Exact version and applicable legal entity/region |
| Control ID | Framework control and local identifier |
| Applicability | Applicable, not applicable, partial, customer responsibility |
| Control statement | What must be achieved |
| CryptoScan control | Mechanism or process used |
| Owner | Accountable Vendor/customer owner |
| Evidence | Exact artifact and version |
| Tier | Repository control, operational record, customer attestation, external certification |
| Test frequency | Continuous, monthly, quarterly, annual, event-based |
| Last tested | Date and result |
| Exception | Owner, reason, compensating control, expiry |
| Reviewer | Independent reviewer and date |
| Limitation | What the evidence does not prove |

## 2. Starter mapping

| Domain | CryptoScan control/evidence | Tier today | Gap |
|---|---|---|---|
| Governance | Control register and readiness closure gate | Repository control | External/customer approval and operating duration |
| Access | RBAC, API authorization coverage, tenant-scope controls | Repository control | Customer IdP/PAM and access-review record |
| Authentication | SSO adapters, session and API-key controls | Repository control | Customer configuration and MFA enforcement |
| Secure SDLC | CI, tests, dependency lock, release gates | Repository control | Operating trend and independent review |
| Vulnerability | Policy draft, disclosure and release checks | Repository control | Dated remediation/adherence records |
| Incident response | Policy and notification templates | Repository control | Approved contacts, exercises, and customer contract |
| Privacy | DPA, privacy, retention, transfer templates | Repository control | Entity/jurisdiction approval and actual subprocessor list |
| Encryption | TLS, evidence-chain, HSM qualification tooling | Repository control | Actual HSM/provider qualification and certification where required |
| Backup/DR | Backup tooling, restore and local drill evidence | Operational record in scoped runs | Customer topology, off-host encryption, failback, recurring tests |
| Supply chain | Digest locks, release attestations, SBOM tooling | Repository control | Signed release and deployment admission records |
| Availability | SLA template and operational measurements | Repository control | Signed target and measured customer service |
| External assurance | Gap analysis and security tests | None/external required | Independent report/certificate |

## 3. Framework use rules

### SOC 2

Map Trust Services Criteria to the actual system description, control
activities, evidence period, complementary customer controls, and auditor
report. Do not call an internal mapping a SOC 2 report.

### ISO 27001

Map to the applicable ISMS scope, statement of applicability, risk treatment,
internal audit, management review, and certificate. Do not call a readiness
gap analysis an ISO certificate.

### PCI and payment frameworks

Separate Vendor's product controls from Customer's cardholder-data environment,
HSM, PIN, key ceremony, and payment-network responsibilities. Scope and
attestation must be customer-specific.

### CAIQ/CCM

Map each CCM question to provider, data, identity, application, infrastructure,
continuity, and privacy evidence. Record customer responsibility and provider
subprocessor evidence.

### Bank or regulatory framework

Identify legal entity, country, regulator, outsourcing category, resilience
requirements, audit rights, data location, incident notification, and customer
risk acceptance. A generic international-bank answer is not sufficient.

## 4. Exception record

```text
Framework/control: ________________________
Applicability: ____________________________
Exception: ________________________________
Reason: ___________________________________
Risk: _____________________________________
Compensating control: ______________________
Owner: ____________________________________
Approved by: _______________________________
Expires: __________________________________
Retest/closure: ____________________________
```

## 5. Review rule

Mappings must be refreshed after a material release, policy change, incident,
new jurisdiction, new subprocessor, new deployment model, external audit,
customer questionnaire change, or control failure.
