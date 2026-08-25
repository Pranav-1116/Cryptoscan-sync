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

## Related seed data

```
python scripts/seed_network_targets.py
python scripts/seed_business_processes.py
```

Network targets, cloud accounts, business processes, and vendors attach
to systems so blast-radius and executive reports have owners and revenue.
