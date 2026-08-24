# Exporting a Cryptographic Bill of Materials

CryptoScan emits a CycloneDX 1.5 CBOM for any completed scan.

## From the dashboard

Open a scan and choose **Export CBOM**. The file is `cbom-<scan-id>.json`.

## From the API

```
GET /api/v1/scans/{scan_id}/cbom
GET /api/v1/cbom/scan/{scan_id}?fmt=json
GET /api/v1/cbom/scan/{scan_id}?fmt=xml&signed=true
GET /api/v1/cbom/system/{system_id}
```

Signed exports attach an HMAC-SHA256 over the canonical JSON in
`metadata.properties` (`cryptoscan:signature`).

## From the CLI

```
python scripts/export_cbom.py <scan_id> --format json -o cbom.json
python scripts/export_cbom.py <system_id> --kind system --signed
```

Each component includes the algorithm OID when known, the primitive
(block-cipher, hash, mac, pke, kdf), evidence hashes, and optional
vulnerability / dependency sections when container findings were loaded.
