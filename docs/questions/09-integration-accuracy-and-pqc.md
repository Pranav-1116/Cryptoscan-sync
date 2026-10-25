# 09 — Integration, accuracy and PQC follow-up questions

[FAQ index](README.md) · Questions Q091–Q100.

## Q091. Can the bank use Active Directory, SSO and MFA?

Treat the bank's identity integration as an explicit deployment/qualification item. Existing authentication/security code or a generic integration setting does not prove that the bank's exact AD/IdP, federation protocol and MFA policy work in the controlled profile.

Agree supported login/session flows, group-to-role/estate mapping, privileged access, deprovisioning, session revocation, break-glass controls and audit. Test revoked/moved users and IdP outages. Do not open external IdP traffic or bypass current authentication guards solely to make a demo work; retain site-specific evidence before promising the integration.

## Q092. Does a crypto assessment require reading bank transactions or customer records?

That is not the default purpose of the scoped source/host metadata paths. Begin with approved source/artifact/configuration/public-certificate/package/runtime metadata relevant to the assessment, not transaction tables or database dumps.

However, source, configs, documents and logs can contain sensitive data. Review actual fields, minimize access and apply classification/retention controls. If a proposed database connector or trace requires customer data, it needs a separate necessity, method, access and privacy review—not an assumption that “read-only scan” permits it.

## Q093. Is scanning passive, active or offline?

It depends on the method. Reading an approved local artifact or imported snapshot is not a network handshake; host metadata collection still performs local reads/API queries. An active endpoint probe contacts a service and must have its own approved scope and budgets.

Do not call all collection passive or imply packet capture is running. Current host listeners describe local namespace metadata, not captured transactions. The controlled source parser is networkless; it does not gain active probing permission from a network-related finding.

## Q094. How are vulnerability/threat-intelligence feeds updated without internet access?

Agree an approved connected staging/mirror/offline transfer process for the exact supported feed/import format. Preserve origin, integrity, version, timestamp, review and regional storage. The installed profile must actually permit the chosen feed operation; legacy tooling does not automatically establish that.

Show feed freshness and failed/missing updates. A stale or absent feed is not evidence that a component has no vulnerabilities. No daily update frequency, external connection or feed-coverage guarantee is established by this FAQ; these require an actual configured and accepted process.

## Q095. How should the bank evaluate false positives and false negatives?

Agree a representative, independently labeled corpus before testing: supported languages/products/versions, known true/false cases, ambiguous and unsupported examples, and expected evidence/relationship boundaries. Include intentionally missing crypto so false negatives can be measured, not just attractive positive detections.

Review disputed results, retain reviewer decisions and add valid regression cases under the existing accuracy workflow. State the denominator, sample and uncertainty. A synthetic test count, golden digest or one successful application scan is not a bank-wide accuracy percentage or independent assessment.

## Q096. How should PQC migration priority be decided?

Use established crypto purpose and parameters, data sensitivity/lifetime, external exposure, deployment and dependency evidence, protocol/application interoperability, vendor/firmware support and business constraints. Distinguish harvest-now/decrypt-later concerns from signatures/authentication and from merely registered capability.

Do not rank an application as “RSA-2048 in production” because its package or certificate mentions RSA somewhere. Unknown context becomes a priority for further approved evidence, not fabricated certainty. Recommendations and AI explanations support human planning; they do not certify a successful PQC migration.

## Q097. Can CryptoScan prove that a system has no weak crypto or is fully PQC ready?

Not from finite or partial observations alone. One TLS session, scanned source revision, certificate, provider registration or supplier claim cannot establish every production path, key, client, fallback protocol and hardware configuration.

A defensible result states the exact assessed release/targets/interfaces/window, observed and declared facts, unsupported paths and independently accepted criteria. “No weak crypto found in assessed scope” is different from “no weak crypto exists anywhere.” A complete readiness claim requires evidence and authority beyond simply exporting six BOM views.

## Q098. Can one deployment assess several countries or business units?

Only within explicitly authorized ownership, residency, network, data-transfer and deployment boundaries. Separate legal estates/regions may need distinct storage/execution and operating arrangements. A regional label in configuration does not physically place workloads, replicas, backups or support access.

Verify current scope on new work and private history, and test wrong-estate/region denials. Do not infer globally qualified collection, multi-region HA or permitted cross-border export from a multi-tenant UI or target registry.

## Q099. Can results be sent to a SIEM, ticketing tool, email or webhook?

Only through an actually available, supported and approved integration for the selected deployment. A legacy connector/menu or endpoint is not permission to enable notifications or egress in the controlled local-source profile.

Review recipient/tenant binding, payload sensitivity, destination authentication, retry/deduplication, rate limits, secret custody, network path and outage behavior. Where no integration is admitted, use an approved permitted review/export process rather than inventing a live connector or promising alerts are delivered.

## Q100. What should a bank require in a product demonstration or RFP answer?

Require an exact release/profile and supported-scope matrix; a bounded authorized happy path; meaningful negative/gap cases; provenance for every material finding/edge; correctly labeled six-BOM views/formats; current access/isolation/resource/secret controls; native platform evidence where claimed; and recovery/operating responsibilities.

Ask the team to show what is refused as well as what succeeds. Capture exclusions, unresolved qualification and contractual assumptions. Do not accept “all systems,” “zero impact,” “100% accurate,” “PQC ready,” “air-gapped” or “24/7 support” without scope-specific evidence and the necessary actual service arrangements.

### References

[Customer-reviewed accuracy](../bank-environment/50-customer-reviewed-accuracy-workflow.md) · [purpose/applicability](../bank-environment/51-purpose-and-applicability-assessments.md) · [deployment/residency](../BANK-ON-PREMISES-DEPLOYMENT.md) · [legacy offline feed tooling and its dated scope](../airgap-deployment.md)
