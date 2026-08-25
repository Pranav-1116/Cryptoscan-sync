# Graph data model

Eight node labels and nine relationship types:

| Label | Identity |
|---|---|
| `System` | `system_id` |
| `CryptoAsset` | `asset_id` |
| `BusinessProcess` | `process_id` |
| `BusinessOwner` | `owner_id` |
| `ComplianceScope` | `standard_name` |
| `Certificate` | `cert_id` |
| `CloudResource` | `resource_id` |
| `Vendor` | `vendor_id` |

| Type | Meaning |
|---|---|
| `USES` | system → crypto asset |
| `CALLS` | system → system |
| `SUPPORTS` | system → business process |
| `OWNED_BY` | system → owner |
| `MUST_COMPLY_WITH` | system → scope |
| `SECURED_BY` | system → certificate |
| `DEPLOYED_ON` | system → cloud resource |
| `DEPENDS_ON_VENDOR` | system → vendor |
| `PROTECTED_BY` | asset → wrapping asset |

Blast radius is `MATCH path = (s)-[:CALLS*1..12]->(downstream)` filtered by `length(path) <= $hops`. Variable-length max is fixed at 12 because Cypher does not accept a parameter there.
