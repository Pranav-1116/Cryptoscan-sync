# Cryptographic Bill of Materials

CryptoScan treats a CycloneDX 1.5 **CBOM** as the estate inventory of
cryptographic assets. Every scanned system, imported vendor document, and
completed scan is a CBOM source.

## From the dashboard

Open **CBOM** to:

- see which systems already have a cryptographic bill of materials
- search an algorithm (AES, RSA, ML-KEM, …) across the estate
- inspect a system or scan CBOM without downloading it
- export the **portfolio** CBOM (all systems in one CycloneDX document)
- import a CycloneDX 1.4 / 1.5 / 1.6 file from Syft, cdxgen, or a vendor
- diff two system CBOMs

Scan detail still has **Export CBOM** (`cbom-<scan-id>.json`).

## From the API

```
GET  /api/v1/cbom
GET  /api/v1/cbom/search?q=RSA
GET  /api/v1/cbom/portfolio
GET  /api/v1/cbom/scan/{scan_id}?fmt=json
GET  /api/v1/cbom/scan/{scan_id}?fmt=xml&signed=true
GET  /api/v1/cbom/system/{system_id}
POST /api/v1/cbom/custom          {asset_ids, include_vulnerabilities?}
POST /api/v1/cbom/validate        {bom}
POST /api/v1/cbom/ingest          {bom, system_name?}
POST /api/v1/cbom/diff            {left:{system_id|scan_id|bom}, right:{…}}
GET  /api/v1/scans/{scan_id}/cbom
```

`GET /cbom` lists every system with component counts, algorithm mix, and
quantum-vulnerable / PQC-ready totals. `POST /cbom/ingest` creates (or
reuses) a system named from `metadata.component.name` and attaches the
cryptographic components as assets.

Signed exports attach an HMAC-SHA256 over the canonical JSON in
`metadata.properties` (`cryptoscan:signature`).

## From the CLI

```
python scripts/export_cbom.py <scan_id> --format json -o cbom.json
python scripts/export_cbom.py <system_id> --kind system --signed
python scripts/export_cbom.py --kind portfolio -o estate-cbom.json
```

Each component includes the algorithm OID when known, the primitive
(block-cipher, hash, mac, pke, kdf), evidence hashes, optional
`cryptoscan:system` properties on portfolio documents, and optional
vulnerability / dependency sections when container findings were loaded.
