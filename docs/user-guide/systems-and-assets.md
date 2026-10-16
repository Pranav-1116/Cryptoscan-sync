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

## Asset detail

The asset detail page joins the estate to its evidence by declared identity,
never similarity: the identity spine (`asset_key`), a **Facts** tab joined by
key, a **Dependencies** tab running the real blast-radius walk (404 renders
"not linked to any system — unknown, not zero"), and a **Remediation** tab
listing the tasks bound to the asset's evidence through the stored
`crypto_asset_evidence` join (honest empty state when none reference it).
Server-side estate search is `GET /api/v1/assets?q=` — observed estate
matches, distinct from the reference algorithm catalog.

## API

```
GET  /api/v1/assets
GET  /api/v1/assets?q=<term>
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
