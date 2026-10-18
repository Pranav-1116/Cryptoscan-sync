# 10 — One bank release investigated across all six BOMs

[Guide index](README.md) · [SBOM detail](09-sbom-deep-dive.md) ·
[Rollout responsibilities](11-detailed-rollout-and-responsibilities.md)

## 1. Define the release before collecting anything

Consider an **illustrative** payments platform in UAT. The bank owns:

- a source release of `payments-api` with manifests and lockfiles;
- a built container image for that release;
- an internal gateway terminating TLS;
- an HSM observed through approved management metadata;
- a supplier of part of the payments platform;
- an approved system/ownership register and declared dependencies.

These are separate input objects. The application commit, SBOM artifact UUID,
container digest, certificate fingerprint, hardware asset ID and supplier ID are
not interchangeable. Record the actual values returned by bank systems; none
are invented as operational identifiers in this guide.

A bank-owned evidence worksheet might have columns:

| Identity/context | Source of truth | Why it matters |
|---|---|---|
| System ID and named owners | Approved application register | Accountability and scope |
| Source revision or export digest | Bank Git/build/export record | Which code was inspected |
| Build reference and image digest | Bank build and deployment records | Whether source and shipped artifact correspond |
| SBOM artifact ID | Generated software artifact store | Exact software document and verification |
| Crypto scan/job IDs and CBOM pins | Source pipeline/evidence store | Actual crypto observations and coverage |
| Endpoint, port, SNI, network run | Approved target and stored probes | What service was actually observed |
| Hardware asset ID and collector | Hardware estate observations | Which physical/security device was represented |
| Supplier/product/revision | Vendor evidence and procurement register | Which declarations apply to the installed release |
| Capture time/cutoff window | Bank evidence manifest | Whether outputs describe comparable periods |

This worksheet is a proposed operational control, not a claim that one API
currently fills every column or enforces all cross-store foreign keys.

## 2. Walk the complete release path

### Step A — Bank creates and admits the source input

The owner exports or stages the approved revision. The platform validates the
selected local path and executor access. Remote Git acquisition for the queued
crypto pipeline and local input for standalone SBOM generation are distinct.

**SBOM activity:** read supported manifests/lockfiles to determine declared and
resolved software components. Retain what was and was not covered.

**CBOM activity:** run the authorized crypto source pipeline against the matching
revision to identify supported algorithm/mode/key/library/source evidence.

Two operations can therefore be necessary. “I generated an SBOM” must not be
presented as “I ran a complete crypto AST scan”; neither alone proves deployed
runtime behavior.

### Step B — Inspect the actual release image

Have the bank supply the admitted image digest/archive and provenance. Inspect
it through the supported container/binary path with approved tools and limits.
Compare its software components with the source-derived SBOM.

Differences can be expected: test/dev dependencies excluded from a production
build, base-image packages not declared in the application lockfile, native
libraries supplied by the OS, bundled/static dependencies, or platform-specific
resolutions. Investigate rather than forcing two valid but differently scoped
SBOMs to have identical counts.

This step does not imply execution of the bank application inside the scanner,
nor proof that the inspected image is deployed. Reconcile the actual digest with
the bank's deployment inventory separately.

### Step C — Observe the gateway actually serving the application

The network owner approves the selected hostname/SNI/port and collection
window. An admitted, reviewed route collects and persists network evidence.
NBOM describes observed transport/certificate relationships from those runs.

A gateway can terminate TLS outside the application image. Therefore:

```text
Application source uses crypto library A
Image includes package A and base-image library B
Gateway negotiates transport using its own implementation C
```

These statements need not contradict one another. A source SBOM alone cannot
identify C; a network probe alone cannot reveal every algorithm invoked by A.
A TLS handshake cannot reliably identify an exact package version by itself.

### Step D — Obtain approved hardware observations

The hardware owner or qualified collector supplies actual model, firmware and
security-module metadata. Persist it and capture the independent HBOM.

If the bank says “Payments uses this HSM”, retain the source of that relationship
and confidence. The independent HBOM currently does not create hardware-to-system
edges. Do not draw a measured dependency simply because the HSM and application
appear in neighboring panels.

An HSM capability claim does not mean the application uses that capability.
For example, firmware documentation might advertise a feature that is not
licensed, enabled or used in the bank's workload. Those questions need separate
bank/vendor evidence.

### Step E — Substantiate the supplier dependency

Procurement/security obtains the vendor record, product/release, supplied BOM
or questionnaire and supporting evidence. The VBOM records vendor crypto
inventory, system links and due-diligence context where supplied.

A supplier SBOM answers software composition of the declared delivery. The
product's VBOM answers supplier/dependency/crypto-evidence questions. Importing
a supplier software BOM does not automatically establish its truth, deployed
match or successful ingestion into every other store.

### Step F — Materialize TechBOM and create a review bundle

Read the shared technology view, resolve known system dependencies, inspect
caps/missing mappings and capture supported snapshots after selected writes
settle. Retain the standalone SBOM artifact, CBOM pin, stored network run/NBOM,
independent HBOM pin and vendor evidence separately.

TechBOM's current `sbom` layer is a registered-application projection. Do not
replace the standalone package artifact with that projection and claim no
software detail was lost. Likewise, TechBOM is not an atomic capture of all six
independent output stores.

## 3. What a bank reviewer actually sees

The following is a **human-readable illustrative evidence table**, not a scan
result or an exact API response:

| Surface | Example useful fact | Owner's follow-up question |
|---|---|---|
| SBOM | A supported lockfile resolves a named software component/version | Is this included in the approved release image? Is scope dev/runtime known? |
| CBOM | A source location invokes RSA signing; other parameters may be resolved or unknown | Is this production-relevant, what is the policy context, and where is its key reference? |
| NBOM | Approved listener serves a certificate and negotiates a TLS suite | Is this the intended SNI/backend? Were weak-version checks actually authorized and performed? |
| HBOM | The selected HSM has collector-supplied firmware/security metadata | Is it fresh and substantiated? Is application-to-device linkage independently known? |
| VBOM | Supplier has a crypto declaration and a recorded system link | Does it apply to the installed product version, and what remains unverified? |
| TechBOM | Shared layers expose inventory and recorded dependency context | Are caps/missing edges visible, and what independent artifacts must accompany this view? |

The bank can use these together to plan a migration, but all evidence strength
must remain visible. The “unified” story means coordinated investigation, not
turning every declaration into a measured fact.

## 4. Example investigation: vulnerable software component

1. The bank supplies an approved advisory/feed identifying an affected software
   ecosystem/version range. Do not invent a CVE or treat an old sample version
   as necessarily vulnerable today.
2. Search relevant SBOM artifacts for the package identity and affected version.
   Determine which artifacts were actually checked against that feed.
3. Match an artifact to the deployed release through bank build/deployment
   evidence, not the package name alone.
4. Inspect application/CBOM evidence if crypto use matters to the advisory.
   A package-presence match is not exploitability or reachability proof.
5. Check vendor product evidence and obtain an upgrade/support statement where
   supplier changes are involved.
6. Let the bank approve/build/deploy its fix. Generate the new software artifact,
   re-scan relevant crypto input and repeat any approved network/hardware checks.
7. Compare supported artifacts/pins, verify integrity and retain unchanged gaps.
   A different version in a development lockfile alone does not prove the
   production image was fixed.

## 5. Example investigation: cryptographic migration

Suppose a bank plans to replace a production-relevant signing mechanism:

- **CBOM** identifies supported source/key/library evidence and policy context.
- **SBOM** helps identify the software libraries and versions that may need an
  upgrade; capability by package name is not proof of usage.
- **NBOM** identifies separately observed transport/certificate dependencies;
  an application signing change need not alter TLS termination.
- **HBOM** contributes actual device/firmware observations; advertised algorithm
  support is not evidence that keys/workloads were migrated.
- **VBOM** captures supplier dependencies and the substantiation still needed.
- **TechBOM** contributes recorded system context for planning, with unresolved
  relationships and limits retained.

The tool supports investigation and evidence. The bank still owns compatibility,
cryptographic design review, key ceremonies, rollout/rollback and live validation.
A PQC label does not certify a complete interoperable production migration.

## 6. Count and completeness example

An illustrative release may have many software package components, a few source
crypto usages, one observed listener, one hardware row, one supplier and several
registered applications/dependencies. **Do not add those counts to obtain a
number of “bank assets scanned”.**

Give each output its own denominator: admitted source inputs, discovered/resolved
packages, inspected image digest, approved observed listeners, inventoried
hardware, substantiated suppliers and mapped business systems. Distinguish
unscanned, unsupported, excluded, failed, stale and imported-only entries.

## 7. What constitutes a convincing demonstration

A good demonstration can follow one bank-approved release from source/build
identity to the relevant real outputs, show one true observation plus one honest
failure/unknown, retrieve supported stored artifacts after restart, verify them,
and explain one before/after change without erasing scope differences.

A poor demonstration substitutes sample data for a real bank scan, presents
TechBOM's application row as a complete package SBOM, invents an HSM relationship,
or calls an advisory-free document “secure” when no advisory feed was applied.
