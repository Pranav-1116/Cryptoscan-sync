# 29 — System-by-system bank collection playbooks

[Guide index](README.md) · [Program](27-international-bank-scan-program.md) ·
[Failures](32-bank-scan-failure-modes-and-qualification.md)

**Boundary:** the methods below are collection designs. A listed device or
protocol is not a claim that this checkout has a qualified live adapter for it.
Use an approved export where direct collection is unsupported. Never interpret
read-only access as permission to send arbitrary traffic or execute workloads.

## 1. Choose the least-invasive useful method

Prefer, in order appropriate to the system: existing authoritative metadata,
controlled offline exports, approved static artifact inspection, supported
read-only control-plane calls, then narrowly authorized live probes. Passive
traffic processing is only passive if the collector sends no packets into the
target network. A TLS connection or enumeration is active traffic.

The connector SDK's nonmutating `passive` mode is not a zero-packet guarantee:
an HTTP metadata read can be nonmutating and still generate network traffic.
Use precise action profiles rather than relying on the mode's name.

For every method record the operator, exact scope, time, permissions, tool
version, input/output digests, omissions and durable receipt. Validate that the
observed system is the intended production/DR/test instance before accepting it.

## 2. Application repositories and build systems

**Collect:** approved commit/tree, language/configuration files, dependency
manifests/lockfiles, build provenance and released artifact references.

**Sequence:** owner identifies the release; clone/stage only approved material;
apply parser isolation; inspect without executing builds/install hooks; create
source evidence and SBOM; independently bind the actual release digest to an
explicit deployment assertion. Keep source, test fixtures and generated code
distinct. A reference in dead code is not confirmed production execution.

**Problems:** monorepos, submodules, private package registries, generated code,
custom crypto wrappers, unresolved versions, symlinks, very large files and
secrets embedded in source. A lockfile may describe development tooling rather
than deployed packages. Restricted dependency resolution must not silently use
the public internet.

**Current basis:** [source execution](../../services/worker/worker/pipeline/pipeline_runner.py),
[isolation contract](../dev/scanner-isolation.md),
[SBOM](09-sbom-deep-dive.md). The isolated parser boundary does not cover every
other stage such as clone, image collection and reporting.

## 3. Containers, Kubernetes and serverless

**Collect:** image digest, registry/repository identity, admitted image layers,
package metadata, deployment/cluster/namespace/workload identity and approved
configuration. Separate image bytes from mutable running state.

**Problems:** tag movement, multi-architecture manifests, distroless images,
init/sidecar containers, downloaded plugins, runtime-mounted libraries, ephemeral
pods and restricted registries. An image tag or a pod name is not a durable
release identity. Registry image coverage does not establish which image ran.

**Improve:** digest-pinned intake, architecture-specific child-manifest binding,
admitted extraction with resource limits, deployment inventory reconciliation
and tested event/relist behavior. A deployment controller's desired state and
observed running digest may disagree; retain both. Do not create privileged
cluster agents merely to fill a dashboard.

## 4. Network edge, internal TLS and service mesh

**Collect:** approved endpoint/port, intended hostname/SNI, observation vantage,
DNS resolution context, protocol negotiation, certificate chain/fingerprint and
supported profile-specific checks. Treat IPv4/IPv6 and internal/external views
as distinct where routing differs.

**Sequence:** validate scope; confirm the resolved destination at execution;
probe one canary; monitor; expand within budget; persist each outcome. A domain
behind a CDN, WAF or load balancer may reveal only the terminating edge. Backend
TLS needs separate authorized evidence. Repeated probes can sample different
nodes; do not merge them into a single guaranteed backend configuration.

**Problems:** split-horizon DNS, NAT, anycast, virtual hosts, mTLS, WAF blocks,
STARTTLS variants, certificate rotation and network middleboxes. For TLS 1.3,
record key-exchange group, certificate/signature details and symmetric suite
separately; AES in a suite does not prove quantum-safe key establishment.

**Forbidden shortcut:** do not disable certificate verification, bypass pinning,
or broaden network ACLs to turn a failure into a green result. Review the
[known route differences](08-implementation-map-and-limits.md) first; not all
network aliases have uniform admission and persistence.

### Network/security appliance metadata

Routers, switches, firewalls, VPN gateways, SD-WAN, load balancers and dedicated
security appliances need product-specific management evidence. Prefer sanitized
configuration exports or qualified scoped API/SNMPv3/management reads as approved
by the owner. An available SSH port is not authorization to run arbitrary shell
commands. Management-plane crypto and data-plane tunnel crypto are different
surfaces; public TLS alone does not inventory IPsec policy or appliance firmware.

Exclude passwords, SNMP communities, VPN pre-shared keys, private certificate
keys and customer traffic from transferred exports. Qualify commands/API calls,
rate limits and exact firmware versions; these methods are not a claim that a
universal appliance connector exists in this checkout.

## 5. Mainframe and midrange: precise, bounded support

This checkout contains crypto-oriented parsers for COBOL, PL/I, RPG and other
legacy inputs, mainframe definitions and key/runtime metadata. It is incorrect
to infer either “no mainframe crypto parsing” or “complete live core-banking
scanning” from a one-line platform summary.

**Collect through the bank's operator:** approved source exports, relevant
CICS/IMS/AT-TLS configuration extracts, permitted RACF certificate/key-ring
metadata and ICSF public key-inventory metadata. Review each field before
transfer. Do not copy CKDS/PKDS/TKDS binary contents or secret tokens.

**Sequence:** identify the LPAR/subsystem/application context; create a sanitized
export under existing operator procedures; record source encoding; perform any
approved EBCDIC/text conversion; retain original/converted digest references and
conversion-tool details; validate representative records and parse offline.
Unsupported encoding/dialect must remain an explicit limitation.

**Problems:** fixed-format columns, copybooks, dynamic rule arrays, old compiler
extensions, missing operator context, shared cryptographic services, generated
configuration and day/night batch changes. A detected ICSF callable-service name
does not prove which algorithm a dynamically supplied rule array selected.
Static code cannot establish every executed batch path or key usage.

**Do not:** submit JCL, execute CICS transactions, issue administrative commands,
trigger key ceremonies or conduct live HSM load tests through a generic scanner.

**Inspected code:** [language registration](../../services/scanner/scanner/registry/language_scanners.py),
[COBOL parser](../../services/scanner/scanner/parsers/cobol_parser.py),
[mainframe definitions](../../services/scanner/scanner/parsers/mainframe_defs_parser.py),
[key metadata parser](../../services/scanner/scanner/parsers/key_inventory_parser.py).
Parser existence is not proof of complete exports, dialect accuracy, production
credential integration or downstream persistence for every bank workflow.

## 6. Payment switches, HSMs and key-management services

**Collect:** approved model/serial references, partition identity, firmware,
public capabilities, permitted key metadata, policies and sanitized audit facts.
Record application-to-partition mappings explicitly. Two applications using the
same HSM manufacturer are not necessarily using the same device or keys.

**Hard exclusions:** no private/symmetric key values, LMK/ZMK components, PINs,
PIN blocks, customer PAN data, ceremony secrets or complete wrapped key payloads.
For TR-31/X9.143-related inventory, request only approved header metadata, not
the whole encrypted key block merely because the parser can recognize a header.
Key labels and usage metadata may themselves need regional restriction.

**Problems:** payment vs general-purpose HSM differences, shared partitions,
dual control, firmware-specific APIs, session limits, maintenance windows and
contract restrictions. A catalog's PQC capability is not installed firmware,
licensed enablement, approved mode, certified use or a successful application
migration. Vendor cryptographic-module certification claims must be checked for
the exact module/version/configuration and applicable assurance purpose.

**Acceptance:** key custodians approve the metadata allowlist; vendor approves
the method; one canary proves no key operations or unintended state changes;
collection includes omissions and partition scope. Key rotation/remediation is
a separate approved operational process, never an automatic scanning action.

See [payment guide](../user-guide/payment-crypto.md) and
[hardware guide](../user-guide/hardware-catalog.md).

## 7. Cloud, private cloud and identity control planes

**Collect:** explicitly selected organization/account/subscription/project and
regions, inventory of relevant KMS/certificates/resources, approved configuration
and control-plane metadata. Bind provider resource IDs to tenant/account scope.

**Problems:** organization discovery denied while one account works; disabled or
unqueried regions; pagination errors; rate limits; eventual consistency; cross-
account roles; services using provider-managed keys with limited visibility.
IaC describes intent, not necessarily deployed state. A cloud KMS listing says
nothing by itself about all applications' actual encryption use.

**Improve:** permission manifests per API, short-lived identity, account/region
reconciliation, cursor/continuation receipts and explicit partial states. Private
cloud/OpenStack/VMware or appliance interfaces require their own supported,
qualified connectors; public-cloud adapters are not universal cloud support.

Identity/PKI configuration can contribute crypto facts. This does not turn the
platform into a complete Active Directory attack-path or identity-audit product.

## 8. Databases, queues, storage and backups

Prefer approved TLS/configuration metadata, keystore references, transparent-
encryption policy metadata, backup configuration and service-owner exports.
Do not query customer tables, dump databases or retrieve stored secrets to
prove encryption. An enabled setting is not proof every historical backup or
replica is encrypted under the intended policy.

Queues, file-transfer systems and batch interfaces need separate endpoint and
signing/encryption evidence. A database's external listener and replication link
can use different settings. Generic TCP/TLS support is not a qualified adapter
for every database or messaging protocol.

## 9. SaaS, external payments and messaging services

Collect contract-bound vendor evidence, the bank's tenant configuration and
explicitly permitted interface observations. External clearing, card-network
and SWIFT-related boundaries require service-specific authorization; never send
financial messages, authentication attempts or synthetic payments as a scanner
shortcut. Financial-function and settlement tests belong in separately approved
bank/vendor test programs.

The bank-facing endpoint may be observable while internal crypto is unknown.
Record that limitation in VBOM and the service assessment; do not equate a good
public TLS result with end-to-end provider assurance.

## 10. Branches, ATMs/POS, mobile and restricted operational zones

Use controlled firmware/application packages, management-system metadata,
public certificates and approved configuration exports. Treat ATM/POS fleets,
mobile binaries, branch appliances and building/OT systems as different classes.
No universal endpoint agent, firmware disassembly coverage or live device support
is established merely because an archive can be accepted.

Mobile findings can be obscured by obfuscation, native libraries and dynamic
loading. Do not bypass device security or production certificate pinning. For
OT, prefer authorized passive captures or exports; prove zero target packets
for a claimed passive collector. Do not reuse an IT sweep against fragile OT.

## 11. DR, offline and decommissioned systems

Inventory DR independently, including dormant certificates and different build
versions. Do not activate failover or restore customer backups solely to scan.
Use approved metadata or a separately authorized isolated restore exercise.

Offline targets receive a controlled import route and explicit evidence age.
Decommissioning needs an owner-approved lifecycle event; a timeout or disappearance
from a partial collection does not prove removal. The scan should reveal these
limits, not conceal them behind a global “completed” status.
