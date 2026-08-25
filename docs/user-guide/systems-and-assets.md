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

Register systems from the CMDB first (`POST /api/v1/systems/import`).
Give each a `scan_target`. Until that system is scanned, its coverage is
`NEVER_SCANNED` or `NO_TARGET` — the algorithms are unknown.

A scan (or a vendor CBOM ingest) is what produces the bill of materials
and stamps the system `CURRENT`. After a scan the worker attaches every
asset to that system. Set `compliance_scopes` (for example `PCI-DSS`) so
scoped policy rules apply on the next scan.

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
