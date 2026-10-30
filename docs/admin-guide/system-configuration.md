# System configuration

A **system** is the application or service that owns crypto assets.
The worker creates one per repository (named after the clone) and
attaches every asset from the scan.

## Required fields

| Field | Notes |
|---|---|
| name | Unique. Used as graph node id when no UUID is stored. |
| environment | `prod` / `staging` / `dev` |
| owner | Team or mailbox used by stakeholder alerts |
| compliance_scopes | `PCI-DSS`, `NIST-800-131A`, `CNSA`, `FIPS-140-3`, `HIPAA` |
| criticality | Drives P0 ranking (`CRITICAL` / `HIGH` / …) |

## Commands

```
python scripts/manage_systems.py create payments-api --scopes PCI-DSS,FIPS
python scripts/manage_systems.py show payments-api
```

## Attaching real context

No sample data ships, and no seeding script exists. Network targets, cloud
accounts, business processes, owners and vendors are created through the API
(`/api/v1/network`, `/api/v1/business`, `/api/v1/vendors`) or imported from your
own inventory export, so blast-radius and executive reports rank the systems you
actually run.
