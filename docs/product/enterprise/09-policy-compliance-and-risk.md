# Policy, compliance, and risk

## 1. Policy model

CryptoScan policies are versioned rules evaluated against normalized evidence.
A policy should define:

- identifier and version;
- condition and required attributes;
- applicable source and scope;
- result vocabulary;
- severity and owner;
- remediation guidance;
- exception behavior;
- effective date and review date; and
- framework or contractual mapping.

The policy engine is deterministic. It does not use an AI model to choose a
verdict. If a required field is missing, the rule should return a declared
unknown/not-applicable state according to its contract, not infer compliance.

## 2. Scope and applicability

Separate universal product rules from framework-specific rules. A baseline may
apply to every scan; PCI-DSS, NIST, CNSA, FIPS, HIPAA, UAE, or customer rules
may require an explicit system or deployment scope.

For every result retain:

- policy pack and version;
- rule identifier;
- evidence identifiers;
- system and customer scope;
- evaluation timestamp;
- result and severity;
- required attributes;
- exception or exclusion reference; and
- remediation or next action.

A framework tag on a system is not proof that the organization is compliant
with the complete framework. It only selects relevant product mappings.

## 3. Result semantics

| Result | Interpretation |
|---|---|
| `PASS` | Evidence satisfies the selected rule for the evaluated scope |
| `WARN` | Evidence indicates a condition that needs attention but is not a hard fail |
| `FAIL` | Evidence violates the selected rule |
| `UNKNOWN` | Evidence is insufficient to decide |
| `NOT_APPLICABLE` | The rule does not apply and the reason is retained |
| `NOT_EVALUATED` | No evaluation was performed, with reason |
| `SKIP` | The object was intentionally excluded, with reason |

Do not map unknown, skip, blocked, or not-evaluated results to PASS in an
executive summary. Count coverage and uncertainty alongside findings.

## 4. Priority and business risk

Technical severity is one input. Priority should also consider:

- system criticality;
- data sensitivity and retention;
- internet exposure;
- payment, telecom, OT, or regulated role;
- dependency and blast radius;
- exploitability and active use;
- migration effort and replacement availability;
- HNDL/quantum exposure; and
- owner and deadline.

The product's priority, business-context, and graph calculations are decision
support. A risk owner can accept residual risk only through the approved
exception process.

## 5. Baselines and drift

A baseline is approved for a specific system, scope, policy set, and period.
Approval requires:

1. source and coverage review;
2. missing/unknown assessment;
3. policy/version capture;
4. owner and risk authority;
5. expected-change window;
6. expiry and reapproval date; and
7. signed or audited approval record.

Drift categories include newly observed assets, removed assets, changed
algorithm/mode/key size, certificate lifecycle change, policy change, and
missing evidence. An unexpected difference should create an investigation, not
be dismissed as noise without a reason.

## 6. Post-quantum and crypto agility

PQC readiness describes migration exposure, not a certificate of future
security. Inputs may include algorithm category, data retention, exposure,
replacement, dependency, owner, and migration status. If retention or exposure
is unknown, the result must say it is not computable.

Crypto agility measures whether a system can change cryptographic behavior with
controlled effort. Useful evidence includes abstraction, configuration,
dependency pinning, test coverage, ownership, and migration history. A high
score does not prove the replacement is safe; it indicates readiness to change.

## 7. Exceptions

An exception record must state:

- failed or missing control;
- affected scope and data;
- threat, likelihood, impact, and residual risk;
- compensating controls;
- owner and expiry;
- customer/regulator approval where required;
- whether it permits pilot or production processing; and
- closure evidence.

An exception preserves the fact that a control was not met. It must not change
FAIL or UNKNOWN into PASS, and a Vendor employee must not accept the customer's
regulatory or business risk without authority.

## 8. Compliance reporting

A defensible report contains:

- declared scope and period;
- source coverage and exclusions;
- policy packs and versions;
- control-to-evidence mapping;
- findings and exceptions;
- unresolved unknowns;
- owner and action status;
- report generation metadata;
- manifest/hash/signature where configured; and
- limitations and external evidence still required.

Use the company assurance package for customer-facing claims. Internal policy
mapping is not SOC 2, ISO 27001, PCI certification, FIPS validation, regulator
approval, or customer acceptance.
