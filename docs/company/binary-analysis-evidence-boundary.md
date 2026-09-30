# Binary analysis evidence boundary

**Document status:** proposed product and evidence description for supervised
pilot / pre-production evaluation. It is not a certification, attestation,
independent report, executed customer commitment, or regulator approval.

## What the product does

The DevSecOps → Binaries panel accepts an authorized static target and runs the
bounded binary parser. The parser can inventory, depending on the format and
available bytes:

- ELF, PE, Mach-O, WebAssembly, Java class, DEX/Python bytecode, archives,
  packages, firmware containers and selected mobile-package metadata;
- architecture, format, sections, imports/exports, dynamic libraries, package
  relationships, build fingerprints, hardening flags and parser coverage;
- crypto implementation/library markers, named algorithm evidence, selected
  constant-table evidence, weak/deprecated primitive indicators and PQC/ECC
  markers;
- PE delay imports and exports, Android APK Signing Block scheme IDs, package
  signature artifacts, and nested-file provenance; and
- bounded findings, advisory-feed matches when a feed is explicitly supplied,
  and the SBOM/CBOM/HBOM/static-NBOM/VBOM/vulnerability-BOM/technology views
  derived from the same scan.

A parser state is retained when it is meaningful: observed, partial, unsupported,
unknown, refused or truncated. The service must not turn a parser failure or an
empty sample into a clean result.

## End-to-end storage and retrieval

The synchronous API and worker use the same lifecycle:

1. `binary_scan` parses the authorized target inside depth, byte, file, member,
   string and observation budgets.
2. `store_binary_artifact()` creates and signs the manifest and BOM sidecars.
   The signed artifact remains the authoritative export.
3. In the same database transaction boundary, a savepoint-isolated hook projects
   the scan into migration `0063`'s tenant-scoped
   `binary_scan_records` and `binary_scan_observations` tables.
4. `GET /api/v1/devsecops/binary/scans` provides tenant-scoped history and
   `GET /api/v1/devsecops/binary/scans/{scan_id}` provides bounded detail.
5. The DevSecOps → Binaries panel sends the active tenant header and displays
   history, provenance, evidence, findings, coverage, partial/unsupported state
   and whether the database index is available.

If the optional read model cannot be written because migration `0063` is not
available or the database index fails, the artifact is not silently discarded.
The result says `database_indexed: false`, the API reports the index as
unavailable, and the signed manifest/BOM remains the source of truth.

## Evidence and tenancy controls

The read model is a redacted projection. It stores selected metadata, hashes,
parser state, coverage, finding excerpts, signature posture and crypto metadata;
it does not store executable bytes, private-key material, certificate blobs or
unbounded parser payloads. Records and API queries carry tenant ownership. A
tenant-bound request cannot read platform-estate rows or another tenant's rows.

Derived observations are not live observations. In particular, binary-derived
network names and static NBOM capability candidates have `observed: false` until
a separately authorized network scan supplies corroboration. Vendor/product
relationships remain the VBOM view; the vulnerability BOM is an explicit,
separate view and requires an advisory feed or other stated evidence for
vulnerability claims.

## What this does not prove

Static binary analysis does not prove execution, reachability, exploitability,
absence of vulnerabilities, signer trust, certificate validity, package
installation, runtime network exposure, or complete estate coverage. Detection
of an APK Signing Block or signature artifact does not perform Android trust
verification. Detection of a cryptographic API does not prove that a code path
executes it. A clean result means no finding was produced within the stated
scope and budgets; it does not mean the target is universally clean.

Runtime tracing, network probing, and other active evidence are separate,
explicitly authorized workflows. The feature is retained within the supervised
pilot / pre-production boundary until deployment-specific operational evidence,
coverage, security review, and acceptance records exist. No such evidence is
created by this document or by the presence of parser output alone.
