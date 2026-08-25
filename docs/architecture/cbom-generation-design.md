# CBOM generation design

`CbomGenerator.from_records` emits CycloneDX 1.5 JSON:

- `bomFormat: CycloneDX`, `specVersion: 1.5`
- one `cryptographic-asset` component per evidence/asset row
- OID + primitive mapped from the algorithm
- optional `vulnerabilities` and `dependencies`
- HMAC-SHA256 signature in `metadata.properties` when requested

API:

- `GET /api/v1/cbom` estate catalog
- `GET /api/v1/cbom/search?q=`
- `GET /api/v1/cbom/portfolio`
- `GET /api/v1/cbom/scan/{scan_id}`
- `GET /api/v1/cbom/system/{system_id}`
- `POST /api/v1/cbom/custom` `{asset_ids, include_vulnerabilities}`
- `POST /api/v1/cbom/ingest` `{bom, system_name?}`
- `POST /api/v1/cbom/diff`

`cbom.inventory` summarizes, searches, ingests, and diffs documents.
`cbom.coverage` is the bank-scale rule: algorithms are unknown until a
system is scanned. Systems carry `scan_target` and `coverage_status`
(`NO_TARGET` / `NEVER_SCANNED` / `CURRENT` / `STALE` / `FAILED`). The
worker stamps coverage after CBOM generation. Catalog listing is
paginated and does not walk every asset on every request.

`validate()` is a local structural check, not a download of the official XSD.
