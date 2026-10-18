# 04 — NBOM, CBOM, TechBOM, HBOM and VBOM in a bank

[Guide index](README.md) · Previous: [Pipeline](03-scan-to-output-pipeline.md) ·
Next: [Worked pilot](05-practical-bank-walkthrough.md)

## 1. Five products answer five different questions

These outputs are complementary evidence views, not five names for one report.
A bank should scope, review and accept each one independently.

| BOM | Primary evidence/store | Typical bank user | Decision supported |
|---|---|---|---|
| NBOM | Persisted network probes and supplied network inventory inputs | Network security / certificate operations | Which listeners/certificates/transport dependencies need attention? |
| CBOM | Cryptographic inventory and supporting scan/evidence records | AppSec / cryptographic governance | Where do algorithms, libraries and key usages need review or migration? |
| TechBOM | Shared system/crypto/hardware/vendor inventory and declared dependency rows | Enterprise architecture / CISO | How do inventory layers and recorded relationships fit together? |
| HBOM | Persisted hardware state and observation provenance | Infrastructure / HSM owners | What hardware/firmware/security-component posture has been observed? |
| VBOM | Vendor inventory, crypto declarations, system links and due-diligence revisions | Third-party risk / procurement | Which supplier dependencies and evidence gaps affect the bank? |

## 2. NBOM — Network Bill of Materials

### Inputs and generation

Authorized network collectors observe listeners. Stored probe records carry
endpoint, negotiated TLS/cipher and certificate details when available.
`GET /api/v1/cbom/nbom` builds the estate view from the bounded recent-run ledger,
keeping the newest encountered result per endpoint. It does not scan on GET.

The pure NBOM builder also accepts explicitly supplied endpoints, tunnels and
devices through a POST build route. A supplied tunnel declaration is not a
wire measurement, and building a document on POST is not proof it was persisted
as a real network scan.

### Illustrative bank output

```text
Listener: partner-gateway.bank.example:443
Observed session: TLS version and negotiated suite, with observation time/run
Served certificate: subject/issuer/fingerprint/expiry if obtained
Dependency: listener -> certificate and negotiated cipher component
Assessment: version/suite/certificate findings supported by observed facts
```

Network policy can distinguish an observed plaintext listener from an endpoint
never successfully probed. Do not infer plaintext from a timeout. Negotiating a
modern suite does not prove that the server rejects every weak suite; additional
enumeration is a separately authorized collection step.

**UI:** `/nbom`; related `/network` and `/certificates`.<br>
**Useful migration question:** “Which observed endpoints depend on the
certificate/component we intend to replace?” The cascade answer is limited to
recorded edges, not undocumented bank routing dependencies.

## 3. CBOM — Cryptographic Bill of Materials

### Inputs and generation

Source findings and supported ingested cryptographic records produce algorithm,
key-size, mode/purpose, library, location and provenance metadata. APIs expose
one scan, one registered system and an estate aggregate. Crypto inventory can
have multiple origins; do not define CBOM as exclusively source code if the
selected ingestion path supplies other cryptographic observations.

### Illustrative bank output

```text
System: payment-signing-service
Crypto use: RSA signing / resolved 2048-bit key reference
Location: src/signing.py:42, at the recorded revision
Evidence: stored finding ID and provenance
Classification: recorded policy/PQC findings, with unresolved fields visible
```

Classical acceptability and quantum-migration exposure are separate questions.
RSA-2048 being susceptible to a future cryptographically relevant quantum
computer is not proof that a bank's present signatures were compromised.
Similarly, finding AES does not reveal mode/key size if the code does not.

**UI:** `/cbom`, `/crypto-assets`, `/findings`, `/evidence`.<br>
**APIs:** `/api/v1/cbom/scan/{scan_id}`, `/api/v1/cbom/system/{system_id}` and
`/api/v1/cbom/portfolio`. Scan CBOMs support content-addressed pins.

An empty CBOM can mean no crypto was detected in admitted input, no inventory
was ingested, or relevant paths were unsupported/excluded. Reconcile it with
scan coverage and errors, not a “cryptography-free bank” conclusion.

## 4. TechBOM — Technology Bill of Materials

### What currently exists

The general materializer produces these projections:

| Internal layer | Current meaning |
|---|---|
| `sbom` | Registered application/system components, not automatically a complete package/OS SBOM |
| `cbom` | Crypto asset projection |
| `hbom` | Persisted hardware projection |
| `vendor` | Vendor inventory projection; not the entire rich independent VBOM document |
| `certificates` | Certificate metadata collection, with its own count |

System-dependency rows are canonicalized into shared-state relationships.
TechBOM is the integration view over supplied inventory, not a scanner that
obtains missing facts. The main gather currently defaults to 2,000 records per
collection; live GET accepts a limit up to 5,000. Snapshot/export gathers have
their own default behavior. **Do not use its headline count as proof that an
arbitrarily large bank estate was fully inventoried.**

### Illustrative bank output

```text
Application: Payments API
Crypto layer: observed signing/encryption usages
Hardware layer: inventoried payment HSM metadata
Vendor layer: registered payment platform supplier
Dependencies: only those supplied by persisted relationships
State: version, fingerprint, snapshot identity, layer counts and timestamp
```

This illustration is a review bundle, not a claim that all four facts have
already been automatically joined. In particular, the standalone HBOM explicitly
lacks hardware-to-system dependency collection today. Never draw a solid
“Payments API uses HSM-01” edge solely because both appear in one TechBOM.

**UI:** `/live-asset-intelligence`; `/techbom` redirects there.<br>
**APIs:** `/api/v1/technology-bom`, `/snapshot`, `/history`, `/compare`, `/export`.
General export layers do not include a `nbom` layer. Network and richer vendor
outputs remain separately queried; cross-BOM correlation is a distinct surface.

## 5. HBOM — Hardware Bill of Materials

### Independent estate document

`GET /api/v1/hbom` reads persisted `hardware_assets`, not merely the latest
in-memory controller state. Its native format is `Cryptoscan-HBOM` 1.0. It can
carry hardware identity, manufacturer/model, firmware, TPM/HSM posture,
capabilities and observation/evidence references when supplied.

Its deterministic anchor comes from observation timestamps. Supported snapshots
are content-addressed and served from stored payloads; comparing two pins can
show device additions/removals and field changes.

### Illustrative bank output

```text
Asset: bank-hsm-01
Model/firmware: what the approved collector actually supplied
HSM/TPM capability: observed or declared values, with provenance
First/last seen: stored observation times
Evidence: agent/source/fingerprint and recorded evidence references
```

### Three hardware surfaces that must not be confused

1. `/api/v1/hbom`: independent persisted-estate document.
2. `/api/v1/hardware/hbom`: live controller's document; ephemeral state can reset.
3. TechBOM `hbom` layer and live-scan hardware views: separate projections with
   their own scope.

The independent HBOM declares an empty dependency graph because collectors do
not currently record hardware-to-system links for it. It is also not a
manufacturer's exhaustive PCB/transistor/component supply-chain BOM.

**UI:** `/hbom` and `/hardware`. Pinning requires an authorized auditor-capable
identity as defined by the server dependency, not merely a visible button.

## 6. VBOM — Vendor Bill of Materials

The independent VBOM uses vendor records, `vendor_crypto_inventory`,
`system_vendors` and latest profile revisions. Its native document is
`ZELNX-VBOM`. An estate document and single-vendor slices are available.

### Illustrative bank output

```text
Vendor: Example Payments Supplier
Dependent bank systems: recorded system-vendor links
Product crypto inventory: supplied BOM/questionnaire/docs or observed inputs
Due diligence: profile revision/status and evidence completeness
Gaps: no validated deployment match / no firmware-specific support evidence
```

**APIs:** `/api/v1/vendor-bom`, `/api/v1/vendors/{vendor_id}/vbom`.<br>
**UI:** `/vendor`, `/vendor-due-diligence`; TechBOM's Vendor section provides
vendor/system linkage. Do not promise that every native VBOM field is rendered
in one dedicated `/vbom` screen; no such SPA route is registered today.

A native vendor BOM, a supplier-submitted SBOM, the TechBOM vendor layer and a
vulnerability report are four different objects. Maintain their provenance and
do not convert declared “PQC ready” into an independently verified capability.

## 7. Formats, integrity and interpretation

Code includes native JSON and CycloneDX-style exports, with routes whose output
identifies CycloneDX 1.5. TechBOM additionally supports CSV/XML/SPDX/PDF forms.
This documentation does **not** certify every custom crypto component/property
against a third-party CycloneDX schema or interoperability target. Validate the
actual document/version with the bank's consuming tool before contracting for
standards conformance.

Some exports are manifests wrapping `data`; some are raw downloadable bytes.
CBOM signatures, TechBOM export HMAC/JWS and HBOM content hashes have different
contracts. A hash is not a signature; a shared-secret HS256 signature is not
public-key non-repudiation; none automatically gives trusted time or completeness.

Five BOMs also cannot be added together to count physical assets: the same
certificate, supplier or application can occur in multiple projections. A
cross-BOM review should retain stable identities and distinguish measured,
imported, inferred and unknown facts rather than present artificial unanimity.

## 8. Representative JSON excerpts from the actual builders

The following are **partial excerpts generated with synthetic illustrative input
using the repository's pure builders**, not captured network responses or real
bank evidence. No collector ran and no application database was populated.
Timestamps/identifiers/signatures and other fields may be omitted. These excerpts
are not complete valid export documents or interoperability test artifacts.

### NBOM excerpt

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "device",
      "name": "partner-gateway.bank.example:443",
      "properties": [
        {
          "name": "cryptoscan:kind",
          "value": "endpoint"
        },
        {
          "name": "cryptoscan:host",
          "value": "partner-gateway.bank.example"
        },
        {
          "name": "cryptoscan:observed",
          "value": "True"
        },
        {
          "name": "cryptoscan:port",
          "value": "443"
        },
        {
          "name": "cryptoscan:tls_version",
          "value": "TLS1.3"
        }
      ]
    }
  ]
}
```

### CBOM excerpt

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "oid": "1.2.840.113549.1.1.1",
        "algorithmProperties": {
          "primitive": "pke",
          "algorithm": "RSA",
          "mode": null,
          "padding": null,
          "parameterSetIdentifier": "2048"
        },
        "nistDesignation": null,
        "quantumVulnerable": null
      }
    }
  ]
}
```

### TechBOM excerpt

```json
{
  "environment": "illustrative-uat",
  "state_version": 1,
  "total_components": 4,
  "components_by_layer": {
    "sbom": 1,
    "cbom": 1,
    "hbom": 1,
    "vendor": 1
  },
  "certificate_count": 0,
  "dependency_count": 0
}
```

### HBOM excerpt

```json
{
  "bomFormat": "Cryptoscan-HBOM",
  "specVersion": "1.0",
  "components": [
    {
      "asset_id": "PILOT-HSM-01",
      "name": "Illustrative Vendor Training HSM",
      "device_type": "HSM",
      "firmware": {
        "details": {
          "application": "1.0.0"
        },
        "last_checked": null
      }
    }
  ],
  "dependencies": []
}
```

### VBOM excerpt

```json
{
  "vbomFormat": "ZELNX-VBOM",
  "version": 1,
  "vendors": [
    {
      "name": "Illustrative Payments Supplier",
      "systems": [
        {
          "system_id": "illustrative-system",
          "system_name": "Payments API",
          "dependency_type": "supplier"
        }
      ],
      "crypto": [
        {
          "algorithm": "RSA",
          "key_size": 2048,
          "discovery_method": "sbom_import",
          "source_document": "illustrative-supplier.json",
          "pqc_ready": false
        }
      ]
    }
  ]
}
```

The TechBOM example deliberately has one component in each of four layers and
zero dependency edges; four components do not prove four physical devices or a
complete application SBOM. The HBOM excerpt likewise does not invent system
relationships. The vendor excerpt preserves imported-document provenance.
An `observed` label in an illustrative NBOM builder input is not a performed
handshake; the real collection/run ledger must substantiate it in deployment.

The vendor builder defaults a missing `pqc_ready` flag to `false`. In this
excerpt that means readiness was not established by the supplied input, not
that a collector proved the product incapable of PQC. Likewise the CBOM's
`quantumVulnerable: null` is not a clean quantum-risk verdict; this illustrative
record did not supply a populated assessment. Review provenance and the
relevant policy/assessment output instead of treating every default as a fact.
