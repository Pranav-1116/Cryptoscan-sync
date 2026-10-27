# 08 — Worked bank example and meeting checklist

[FAQ index](README.md) · Questions Q081–Q090.

**All names and outcomes below are illustrative.** They are not actual bank observations, approvals, addresses, credentials or promises that every method is currently admitted. Select a supported evaluation/deployment path before executing anything.

## Q081. What would a sensible first bank engagement look like?

Start with one representative UAT business service, for example “Payments API,” rather than “scan the entire bank.” Identify its application owner, release, two known hosts, known endpoint, relevant supplier and any alleged HSM dependency.

Decide what is already supported, what can be imported, which host candidates need evaluation and which interfaces remain blocked. If the production reference is used, restrict execution to its admitted local-source workflow; do not assume the broader example enables live host/network/HSM collection there.

## Q082. What might the pre-discovery scope register look like?

| Scope item | Owner-provided identity/input | Proposed evidence route | Initial status |
|---|---|---|---|
| Application release | Reviewed revision and artifact identity, if established | Admitted local-source workflow | Await exact release/scope approval |
| Linux host | Reviewed package/config/certificate inputs and exact runtime resources | Supported ordinary-user offline host evaluation | Await manifest and method qualification |
| Windows host | Reviewed OS/SCM/certificate/process/CNG inputs | Windows candidate evaluation on actual Windows | Native qualification pending; no universal execution admission |
| Payment endpoint | Exact bank-approved endpoint, port and SNI | Separately qualified network observation or approved existing receipt | No implicit active probe authorization |
| HSM dependency | Bank record/product/revision and declared application relationship | Approved public evidence/review | Application use UNKNOWN until supported evidence |
| Supplier | Exact product/build/revision and original declaration | Supported bounded supplier import/quarantine/review | Declaration, not observed PQC capability |

Do not insert arbitrary real IPs or secrets into a public register. Track unknown/unsupported items rather than dropping them from the expected scope.

## Q083. How would collection and BOM projection work in that example?

An illustrative, correctly limited outcome could be:

```text
approved source snapshot → source crypto facts for that revision
approved package database → installed package/version facts
approved public certificate → public key/certificate metadata
approved exact process → sampled process/module metadata
reviewed supplier document → imported/declared supplier claim

same retained evidence → supported software/crypto/network/hardware/vendor
                        projections and justified TechBOM associations
```

Each arrow depends on actual admitted inputs and evidence. No endpoint session, HSM use, software version from a DLL name or supplier authenticity is invented to complete the diagram. Separate collection sessions may be needed for independent systems; reuse each observation across projections instead of rescanning per BOM.

## Q084. What if package data shows OpenSSL, but no crypto operation was observed?

Report installed software metadata in its supported SBOM/evidence scope. Runtime use, specific algorithm, key parameters and production traffic remain UNKNOWN unless separately established.

Likewise, `libcrypto.dll` in a Windows module table does not prove RSA/AES invocation; an `AES` CNG registration label does not prove tested capability. A report should explicitly preserve those distinctions so the bank can plan the next approved evidence step rather than act on a fabricated high-confidence crypto dependency.

## Q085. What if the HSM team refuses access during the pilot?

Retain “not authorized/denied” for that surface and any separately supplied bank declaration. Show HSM/application relationship and actual key origin as UNKNOWN unless a supported reviewed declaration is explicitly represented as DECLARED—not OBSERVED operation.

Do not use host library presence or a vendor brochure as a substitute, report “no HSM,” or request a PIN/private key. The next action may be an approved public metadata export and independent relationship review, owned by the hardware/application teams.

## Q086. How would a truthful coverage statement read?

Example: “Of four explicitly approved certificate-file inputs, three parsed and one was unavailable: 75% approved-input parsing. Complete certificate estate coverage is not established. Hardware was not requested; its completeness percentage is unknown/null.”

That is not “75% of all bank certificates discovered.” The denominator must come from pre-discovery/authorization, not from what the scanner happened to find. If one fact feeds several BOMs, its reference counts do not become several distinct discovered assets.

## Q087. What network/security worksheet should be completed before a pilot?

| Decision | Bank-approved value to record |
|---|---|
| Source | Exact workstation/worker/collector identity and network zone |
| Destination | Exact application/dependency/endpoint identity; resolved-destination rules where applicable |
| Operation | Metadata read, local source parse, offline transfer or separately qualified probe |
| Path | Protocol/port/proxy and TLS trust owner; “no acquisition network” for offline-only paths |
| Window | Start/expiry, change reference, maintenance owner |
| Budget | Request/probe/concurrency/byte/resource limits for the actual method |
| Monitoring | SOC contact, IDS/IPS handling and event correlation |
| Stop | Trigger, authorized stop owner, termination verification and restart approval |
| Retention | Evidence/log classification, approved region, transfer and retention owner |
| Exclusions | Explicit prohibited targets/operations and enforcement method |

Leave unresolved items marked pending; do not replace them with permissive defaults. Firewall/IDS changes remain bank-owned and must not create blanket exceptions.

## Q088. What questions should CryptoScan ask the bank in the first meeting?

Use this as a nonsecret questionnaire:

1. What business decision should the pilot support, and who may accept it?
2. Which exact service, environment, release and regions are in scope?
3. What independent inventory/truth exists, including known missing systems?
4. Which acquisition/import methods and data classes are permitted?
5. Who owns application, network, IAM, host, cloud, hardware and supplier access?
6. Which systems/operations must never be contacted or changed?
7. Is the bank air-gapped, and what transfer/registry/PKI channels are approved?
8. What windows, limits, monitoring and stop criteria must be demonstrated?
9. What residency, raw-evidence, retention/legal-hold and export rules apply?
10. What acceptance, operating/support and recovery evidence is required?

Ask for decisions and references—not passwords, private keys or approval signatures created merely to satisfy a template.

## Q089. What questions should the bank ask CryptoScan before purchase or deployment?

Ask for the exact release/profile and support matrix; demonstrated versus candidate interfaces; raw data retained; why a finding/edge is believed; tests for wrong estate/scope/region; actual parser/worker isolation; resource limits; native platform evidence; dependency security; backup/restore results; and named support/escalation responsibilities.

Also ask which exports are standardized/validated, which percentages have independently known denominators, which capabilities are blocked in production and what still needs bank acceptance. Require scoped evidence rather than a blanket “all supported” response. Prices and contractual commitments need a separate agreed proposal.

## Q090. What is the final go/no-go decision template?

Record the following for the exact release/site/profile:

```text
Purpose and authorized scope:
Approving authority and change/reference:
Supported methods / explicitly blocked methods:
Expected inputs and independent truth:
Actual completed / partial / failed / unattempted inputs:
Positive and negative test evidence:
BOM/export formats and known relationship/coverage limits:
Isolation, access, resource and secret-handling evidence:
Backup/restore/reconciliation and operational ownership:
Residual risks, exclusions and required follow-up:
Independent/security/customer decisions and their real references:
Decision: APPROVE EXACT SCOPE / APPROVE WITH RECORDED LIMITS / BLOCK
```

This is a blank decision aid, not an acceptance record. Only actual entitled humans can supply their decisions. Block deployment when a required safety/control/qualification criterion is missing; do not alter UNKNOWN facts or manufacture approvals to pass.

### References

[Pre-discovery questions](02-bank-scan-and-pre-discovery.md) · [safety questions](03-firewall-ids-and-scan-safety.md) · [six-BOM semantics](04-six-boms-and-evidence.md) · [on-premises acceptance](05-on-prem-deployment.md) · [operator assignments](../bank-environment/68-assigned-operator-qualification-workflow.md)
