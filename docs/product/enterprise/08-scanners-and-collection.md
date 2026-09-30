# Scanners and collection

## 1. Collection contract

Every collector must answer five questions:

1. what source is read;
2. what permission is needed;
3. what data is extracted;
4. what the collector does not inspect; and
5. how it reports unsupported, unreachable, or unsafe conditions.

A collector is complete only when its output has source, scope, timestamp,
parser/scanner identity, revision or target, and a reason for every skipped or
blocked item.

## 2. Source-code and dependency scanning

The repository scanner handles supported source languages, configuration,
cryptographic API patterns, hard-coded key indicators, certificates, library
references, and lockfile/dependency evidence. The scanner should preserve file,
line, language, parser, commit, and rule context.

The code scanner does not prove runtime behavior. A call site may be dead code,
wrapped by another library, overridden by configuration, or unreachable in the
production build. Pair source evidence with binary, runtime, container, or
operator-supplied evidence where the question is operational behavior.

## 3. Binary, package, mobile, and firmware scanning

Supported bounded binary and archive paths may extract metadata, hardening
controls, embedded crypto indicators, package signatures, firmware headers,
checksums, and nested components. Current parsers include ELF, PE, Mach-O,
archives/packages, WASM, Android binary XML and selected iOS `Info.plist`/ATS
metadata, plus firmware container and device-tree identity. Mobile metadata is
not a proof of runtime behavior, and WASM modules are inspected but never
compiled or executed.

The binary bundle projects evidence into SBOM, CBOM, HBOM, static-only NBOM,
VBOM, a separate vulnerability BOM, and a deterministic technology snapshot.
NBOM candidates from a binary always carry `observed: false`; imported socket or
TLS APIs are not live network observations. Only an authorized network scan can
supply corroborating exposure evidence. VBOM remains the vendor/product and
supply-chain layer; the vulnerability BOM is the separate normalized findings
layer.

Every parser is bounded. It records confidence, unknown, partial, skipped,
refused, malformed, and truncated states instead of converting missing data to
zero or a clean result. Sidecars are tenant-scoped, retain artifact and scan
provenance, and can be compared as bundle diffs. A parser result does not
certify a binary's provenance, signature trust, malware status, or completeness
of reverse engineering. A package signature, registry record, source commit,
build attestation, and deployment record answer different questions and should
not be merged into one status.

## 4. TLS, network, and certificates

Network collection inspects explicitly configured endpoints and protocols. It
may include TLS version/cipher behavior, certificate chain, expiry, issuer,
key type, and protocol-specific observations. STARTTLS and other protocol
modes require correct target configuration.

The operator must define:

- hostname/IP and port;
- protocol and SNI;
- authorized scan window;
- source network and proxy path;
- rate and retry limits;
- certificate trust policy; and
- whether the endpoint is production, staging, or test.

A failed probe is not evidence that the endpoint is secure or insecure without
the failure reason. Network scanning is not a substitute for application
configuration review.

## 5. Cloud inventory

The AWS, Azure, and GCP paths are account- and permission-scoped. A typical
read-only inventory flow lists keys or certificates, obtains metadata, maps
provider algorithms and states, and writes normalized assets. It must not
retrieve private key material.

Before enabling cloud collection, document:

- account/subscription/project identifiers;
- regions and resource filters;
- IAM/service-principal/service-account role;
- allowed API calls;
- credential source and rotation;
- provider rate limits;
- unsupported provider states; and
- retention and export behavior.

Unknown provider algorithms, unavailable resources, disabled keys, and
permission errors should remain visible rather than silently omitted.

## 6. Containers and supply chain

Container and SBOM collection connects component metadata to image, digest,
source, lockfile, license, vulnerability, and release context. An image tag is
not immutable identity; use a digest and retain the registry and deployment
record.

The minimum release packet should include:

- source commit;
- lockfiles;
- first- and third-party component inventory;
- SBOM/CBOM;
- license/notice result;
- vulnerability/advisory snapshot;
- image digest;
- provenance/signature;
- exception and approval; and
- deployment/admission record.

Repository tooling alone does not prove the deployed digest.

## 7. OT/ICS, telecom, hardware, and payment domains

These domains need extra safety and ownership:

- OT/ICS paths should be passive or explicitly approved; do not probe a live
  control network as if it were a web endpoint.
- Telecom analysis may combine operator-supplied artifacts with permitted
  network observations; an ingest file is not proof of live network state.
- Hardware and HSM views should use metadata, configuration, certification
  references, and controlled provider evidence without extracting key material.
- Payment and mainframe inventories need customer adapters and domain owners;
  a simulator or sample export is not a production HSM qualification.

Use the domain guides under `docs/`, and record whether the input was live,
operator-supplied, simulated, synthetic, or historical.

## 8. Collector failure taxonomy

| State | Meaning | Required operator action |
|---|---|---|
| `UNREACHABLE` | Target could not be contacted | Check route, DNS, firewall, and window |
| `UNAUTHORIZED` | Credential or scope was rejected | Correct authorization; do not broaden blindly |
| `UNSUPPORTED` | Format or feature is outside collector scope | Use another collector or record a gap |
| `SKIPPED` | Intentionally excluded by policy or filter | Review scope and retain reason |
| `BLOCKED` | Safety, privacy, or policy gate stopped work | Obtain approval or change the plan |
| `PARTIAL` | Some objects collected and others failed | Investigate coverage before relying on result |
| `ERROR` | Unexpected processing failure | Preserve job, logs, and incident context |

## 9. Collection acceptance tests

Before onboarding a source type, use a fixture with:

- a known-good object;
- a known-bad object;
- an ambiguous/unknown object;
- a malformed or truncated object;
- a permission or reachability failure;
- a sensitive value that must be redacted; and
- an expected evidence, asset, and policy result.

The acceptance record should include scanner version, fixture hash, test
command, result, and limitations. It should never claim that fixture coverage
is customer-estate coverage.
