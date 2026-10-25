# 02 — How bank scanning and pre-discovery work

[FAQ index](README.md) · Questions Q013–Q024.

## Q013. What does “pre-discovery” mean?

Pre-discovery is the **planning and evidence-reconciliation stage before technical collection**. Identify the business service, owners, environments, known assets, permitted interfaces, data classes, network zones, dependencies and exclusions. Define what is expected to be assessed before looking at scanner output.

It is not permission to run a ping sweep, port scan, credential search or unrestricted host crawl. This FAQ supplies a checklist, not a new automated pre-discovery collector.

## Q014. What information should the bank supply first?

Ask for nonsecret records through approved channels:

- Business service and criticality; UAT/production/DR distinction; accountable owner.
- CMDB/application inventory and approved architecture/data-flow diagrams.
- Exact release/source/artifact identifiers and known endpoint/port/SNI list.
- Operating system, appliance/cloud/provider and hardware interface information.
- Network zones, access route, approved maintenance window and prohibited operations.
- Data residency, retention, privacy and evidence-transfer requirements.
- Expected inventory/coverage denominator, independent reviewer and incident contacts.

Do not request production passwords, private keys or copied vault contents in the questionnaire. Identify required credential **references and custodians**, only if the selected qualified method needs them.

## Q015. How should pre-discovery be carried out step by step?

1. Select one bounded business service and environment.
2. Review existing inventories with its owner; record disagreements and missing records.
3. Classify each target by collector/import method and current admission status.
4. Specify exact inputs, operations, windows, exclusions and limits.
5. Agree independently known expected truth and success/stop criteria.
6. Obtain security, network and application-owner approvals as applicable.
7. Test on a representative non-production fixture.
8. Authorize only the reviewed scope; retain unresolved targets in the denominator.

If the evidence is insufficient, return to the owner for clarification. Do not silently discover additional targets to make the inventory look complete.

## Q016. What does a safe target record contain?

Record the selected estate/system, stable target key, environment, owner/contact, logical address or exact approved resource, collection method, allowed operations, not-before/expiry, exclusions and authorization reference/revision.

For the current offline host contract, a manifest enumerates specific inputs and accepts **no credential reference**. The API does not resolve a `vault://...` reference into a working SSH/WinRM session in this adapter. Examples of future remote target fields are architecture guidance, not executable access grants.

## Q017. How does an approved bank scan actually run end to end?

There are two distinct existing paths:

**Controlled local source:** approved transfer/staging → authorized job → worker rechecks authority → isolated bounded parser → retained results/evidence → permitted review/export.

**Development/offline host foundation:** register exact target/manifest → authorize current revision → create durable job → ordinary-user operator collection → approved one-use host intake → bind the same intake/evidence to job completion → central normalization/projection.

The host path is not implicitly enabled in the controlled production profile. Neither path starts an unrestricted bank-wide scan, and a read/export request must not trigger collection again.

## Q018. How do local, offline and remote modes differ?

| Mode | Who performs acquisition? | Boundary |
|---|---|---|
| Local | Approved collector runs on the authorized machine | Uses only implemented inputs and actual account permissions |
| Offline | Local acquisition plus bank-approved transfer/intake | Transfer provenance remains IMPORTED; integrity checks do not authenticate the host by themselves |
| Controlled remote | A qualified adapter would access approved targets through approved protocols/accounts | Not generically admitted by the current universal/controlled production paths; requires separate implementation/qualification |

An air-gapped bank can use approved offline evidence without opening remote management ports. Do not invent an always-on agent, SSH dispatcher or WinRM service merely because the architecture allows a future mode.

## Q019. Does CryptoScan install an agent on every bank server?

That is not the default or an established fleet-deployment capability of the current bounded host workflow. The existing approach includes explicitly executed ordinary-user local/offline collection and controlled worker execution for supported profiles.

A persistent agent would require its own packaging, enrollment, update, credential, communications, isolation, health and uninstall review. Do not describe an operator-run script as a production-managed endpoint agent.

## Q020. How are source code, installed packages and live processes different evidence?

Source analysis identifies constructs in an exact approved source snapshot; it does not prove deployment. A package database reports installation metadata; it does not prove a package is running. Process/module metadata reports scoped sampled runtime state; it does not prove a specific crypto operation.

Use distinct evidence and identities for source revision, build artifact, deployment, installed package, process incarnation and negotiated session. Join them only with supported evidence/rules. Matching an “OpenSSL” name across records is insufficient.

## Q021. What happens if a host is behind a firewall or has no route?

First choose a permitted method. Offline collection may avoid opening a remote scanner path, while active network observations require a separately admitted exact endpoint path and approval.

If acquisition fails, preserve its actual failure. A timeout may be caused by routing, DNS, policy, service state or other conditions; it does not prove a firewall blocked the request or that the host is absent. Ask the network team to correlate its own logs. Do not broaden scope, switch credentials or disable controls automatically.

## Q022. How do exclusions and maintenance windows work?

Exclusions must be enforced by the applicable admission/runtime contract, not merely displayed in a report. In the universal offline manifest, excluded input IDs must be removed from the input allowlist. This is not a generic wildcard path-exclusion engine.

Time windows must match the reviewed target and authorization. Changes require reauthorization under the relevant revision rules. Operators must agree what happens at expiry and cancellation; a native call that cannot yet be independently interrupted is a qualification gap, not a guaranteed instant stop.

## Q023. What if the scan discovers an unknown dependency or extra target?

Retain the supported observation and mark the unproven relationship or scope gap. Do not pivot automatically to another host, cloud account, URL, service executable or hardware endpoint.

For example, a package mentions a URL or a process reports a service name. That is not authorization to contact the URL or enumerate the service's environment. Ask the owner to review and, if appropriate, register/authorize a separate target or supported association.

## Q024. What should pre-discovery produce before the first pilot?

A reviewed scope register, target/input manifest, architecture/data-flow sketch, access/transfer plan, firewall flow matrix, budget/window/stop plan, independently known test truth, acceptance checklist and named owners.

Include a gap list: unattempted systems, unsupported interfaces, denied permissions, unresolved identities and unavailable evidence. Agree success criteria before measurement. “The scan completed” alone is not a pilot criterion; require correct positive findings, correct gaps, isolation, tenant access, evidence integrity and cleanup behavior.

### References

[Foundation/authorization](../bank-environment/62-universal-collection-foundation.md) · [operator-owned qualification](../bank-environment/68-assigned-operator-qualification-workflow.md) · [international bank playbooks](../bank-environment/29-system-by-system-collection-playbooks.md) · [controlled source flow](../BANK-ON-PREMISES-DEPLOYMENT.md)
