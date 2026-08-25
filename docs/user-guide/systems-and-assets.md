# Systems and cryptographic assets

A **finding** is one observation from one scanner. An **asset** is the
deduplicated cryptographic use (algorithm + purpose + file + line). A
**system** is the application or service that owns those assets.

## Deduplication

Two scanners that report the same location collapse into one asset.
Confidence becomes `VERIFIED` when two distinct `scanner_id`s agree.
Each asset stores `extra.dedup_key`, a SHA-256 of
`ALGORITHM|PURPOSE|file_path|line`.

## Auto-linking

After a scan, the worker creates (or reuses) a system named after the
repository and attaches every asset from that scan. You can also ingest a
CycloneDX CBOM (`POST /api/v1/cbom/ingest`) to register a system from an
external bill of materials. Set `compliance_scopes` on the system (for
example `PCI-DSS`) so scoped policy rules apply on the next scan.

## API

```
GET  /api/v1/assets
GET  /api/v1/assets/{id}
GET  /api/v1/systems
POST /api/v1/systems
POST /api/v1/systems/{id}/assets
POST /api/v1/systems/{id}/dependencies
```

```
python scripts/manage_systems.py create payments-api --scopes PCI-DSS,FIPS
python scripts/manage_systems.py show payments-api
```
