# Graph data model

> **Two projections exist.** This page describes the legacy `cypher_writes` builder used by the
> earlier dashboards (eight labels, below). The Digital Twin's own projection is
> `shared_models.estate_twin.graph_export`, loaded by `services/api/api/estate_graph_loader.py`,
> and it emits every one of the 22 node labels the twin specification proposes — asset types,
> evidence types and the four placement levels (`Organization`, `Region`, `DataCenter`,
> `Environment`) as nodes joined by `CONTAINS` and `PART_OF`. See
> [the twin spec §7](../DIGITAL-TWIN-SPEC.md) and `twin.graph_label_coverage()`, which is served
> with every export and pinned by a test.

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
