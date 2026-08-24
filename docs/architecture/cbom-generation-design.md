# CBOM generation design

`CbomGenerator.from_records` emits CycloneDX 1.5 JSON:

- `bomFormat: CycloneDX`, `specVersion: 1.5`
- one `cryptographic-asset` component per evidence/asset row
- OID + primitive mapped from the algorithm
- optional `vulnerabilities` and `dependencies`
- HMAC-SHA256 signature in `metadata.properties` when requested

API:

- `GET /api/v1/cbom/scan/{scan_id}`
- `GET /api/v1/cbom/system/{system_id}`
- `POST /api/v1/cbom/custom` `{asset_ids, include_vulnerabilities}`

`validate()` is a local structural check, not a download of the official XSD.
