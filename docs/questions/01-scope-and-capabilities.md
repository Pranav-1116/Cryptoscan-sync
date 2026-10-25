# 01 — What is present, partial and not present?

[FAQ index](README.md) · Questions Q001–Q012 · Reviewed 2026-10-25.

## Q001. What is CryptoScan intended to do for a bank?

CryptoScan collects or accepts approved technology/cryptography evidence, preserves its provenance, and uses it for inventory, relationships, policy analysis, migration assessment and evidence-linked reporting. Its distinguishing rule is that a BOM is a **projection of evidence**, not an independent source of truth.

The intended estate can include source, hosts, endpoints, containers, cloud, hardware and suppliers. That intended architecture is larger than current qualified execution scope. Do not describe the product as an unrestricted scanner that already discovers every bank asset.

## Q002. What scope is present today, and what is absent or incomplete?

| Area | Present in the repository | Limit / what is not established |
|---|---|---|
| Source workflow | Approved local-source execution, worker/evidence and controlled-profile controls | Only the exact admitted workflow; not arbitrary repository/network access |
| Universal foundation | Scoped targets, authorization, durable jobs, typed evidence, central projections | Not every legacy acquisition module is a universally admitted adapter |
| Linux host metadata | Explicit OS/package/file/certificate/config/process/map/listener/service/hardware inputs | Partial interface coverage; native permissions and bank acceptance remain required |
| Linux software/relationships | Evidence-linked inventory, exact metadata joins and official-schema-validated incomplete CycloneDX 1.6 software export | No complete runtime dependency graph or package-to-loaded-file attribution |
| Windows | OS/uninstall/SCM, public-certificate, exact process/module and CNG-registration candidates | Native/security qualification open; universal Windows authorization blocked |
| Network | Separate network admission/monitor engineering and host listener metadata | Not blanket controlled-production live probing or a universally admitted network collector |
| Cloud/container/source utilities | Existing separate capabilities and future universal method names | Not proof that every cloud/image/source collector satisfies the universal contract |
| Hardware/HSM | Narrow kernel metadata, quote/review tooling and separate evidence paths | HSM operations, key origin and application relationships need separate evidence |
| Vendor | Declared/imported supplier evidence, quarantine/review and associations | Supplier statements do not become observed capability or independent truth |
| Six BOMs | Evidence paths, shared domain/reference projections and selected validated exports | Not six complete inventories from every target or six interchangeable standardized exports |
| Hardening | Access/audit/admission/resource/isolation/recovery controls and qualification tooling | No blanket bank approval, witnessed site HA/DR, guaranteed capacity or staffed SLA |

“Absent” can mean either **not implemented** or **implemented but not admitted/qualified**. Record which one applies; they are different delivery tasks.

## Q003. What is actually supported by the current controlled production reference profile?

The reference is `kubernetes-external-services/local-source-v1`: approved local-source acquisition, API, coordinated worker, frontend, isolated parser, regional external PostgreSQL and verified-TLS Redis. The site must still demonstrate its exact installation and obtain acceptance.

Unqualified live host/network/cloud/runtime collection, arbitrary graph/export/realtime surfaces and integrations are not unlocked by installing this profile. The production API allowlist may refuse a route that works in development. Never disable the guard or change production to development mode to “enable” an unqualified collector.

## Q004. Can the team scan a bank without access to its Git repositories?

**Yes, for supported explicitly approved evidence paths.** Offline host metadata does not require Git; operators can collect approved local files, package databases and supported runtime metadata, then transfer the typed snapshot through the bank's approved process.

That development/candidate host path is not automatically admitted by the controlled production source profile. The bank must agree the exact qualified route or use the approved evaluation environment. Source analysis itself still needs an authorized source snapshot; host metadata cannot reconstruct all application code or dependencies.

## Q005. What Linux scope can be collected without a privileged crawl?

Examples include explicit dpkg/APK or supported bounded RPM metadata inputs; literal OS-release fields; public certificate files; selected NGINX configuration literals; ELF/PE header presence; exact PID/process incarnation and mapped paths; current-namespace TCP listeners; named systemd status; and selected CPU/DMI/TPM kernel metadata.

Availability varies by host and account. No broad PID enumeration, arbitrary command execution, memory dump or automatic escalation is implied. A TPM major version is not a key inventory; a listener is not TLS; a mapped `.so` path is not a verified library version.

## Q006. What Windows scope is present now?

There are bounded candidates for OS/uninstall/SCM metadata, exact public-certificate lookup, exact PID plus creation-FILETIME process/module metadata, and fixed Microsoft Primitive Provider user-mode cipher/hash registration metadata.

Important limits:

- Windows execution/production admission is still not qualified.
- Module presence does not prove DLL classification, package version or crypto invocation.
- CNG registration labels do not prove working algorithm capability, application use or key parameters.
- Broad legacy CAPI/CNG coverage, TLS/listener attribution and TPM/firmware remain separate work/gates.

A Linux fake-native test is not evidence that a bank Windows server was scanned.

## Q007. Are container, network and cloud collection already complete?

No. Separate legacy/standalone functionality and engineering controls exist, but the ordered universal-adapter build still needs typed scope, original provenance, resource limits, negative tests and qualification for each family.

An image's declared exposed port is not a live listener. A TLS handshake cannot produce a full SBOM. Cloud KMS metadata does not identify physical HSM possession or prove an application's key use. Qualify the exact provider/account/resource/endpoint adapter rather than offering an unrestricted “cloud scan.”

## Q008. Does CryptoScan support mainframes, databases, appliances, firewalls and OT?

Do not promise generic authenticated access to every such system. First identify the exact supported import or approved metadata interface, product/version and available permissions. Vendor exports or approved offline artifacts may be suitable; otherwise record the surface as unsupported or awaiting an adapter.

An appliance may expose network evidence without exposing its internal software inventory. An OT device may prohibit active probes entirely. Separate product-specific scope and safety review is required; a collector family name is not a tested device compatibility list.

## Q009. Does installing CryptoScan give permission to scan every subnet?

No. Installation grants neither legal authorization nor network reachability. Scope must bind the bank estate, system, target, permitted operation/input, time window, exclusions, budgets and approving authority.

A target's owner label is a contact field, not the authorization principal. A CIDR entered in a form is not a signed mandate or a bank-wide exception. New targets, changed scope and expired authority require the applicable review and authorization again.

## Q010. Does “read-only” mean zero production risk?

No. Reads can consume CPU, disk, memory, database connections, API quota and network capacity; some vendor interfaces have side effects or fragile implementations. A parser can receive hostile input even when it writes nothing to the source.

Use bounded inputs, least privilege, representative pre-production trials, explicit exclusions, monitoring and agreed stop conditions. Describe **risk reduction and observed limits**, not “zero impact” or “cannot fail.”

## Q011. Can CryptoScan automatically fix findings or migrate the bank to PQC?

Do not equate detection/advice/workflow with authorized production remediation. A finding can inform review, policy and migration planning, but source/configuration changes, key rotation, HSM firmware updates and TLS rollout need separate bank approvals and compatibility testing.

AI may explain risk or suggest a sequence; it cannot turn a guess into OBSERVED evidence. No automatic firewall change, private-key operation, production patch or migration success is promised by this FAQ.

## Q012. How should missing scope be explained to management?

Use a gap ledger with: system/target, surface, status, exact reason, evidence, risk of missing information, responsible owner and next approval/action. Separate not requested, denied, unreachable, failed, unsupported, stale and awaiting review.

Example: “Hardware interface not authorized; hardware/application relationship UNKNOWN. Owner: hardware team. Next action: review a public metadata export.” Do not translate that into “no HSM” or invent a completion date, inventory percentage or bank acceptance.

### References

[Phase order/status](../bank-environment/69-phasewise-universal-collection-build.md) · [Linux scope](../bank-environment/63-linux-collection-phase-two.md) · [latest Windows candidate](../bank-environment/74-phase-three-windows-cng-registration-candidate.md) · [on-premises profile](../BANK-ON-PREMISES-DEPLOYMENT.md)
