# Multi-layer visibility

CryptoScan inventories cryptography at five layers and joins them on
**system**:

```
source code  →  container image  →  cloud control plane  →  TLS on the wire  →  business process
     │                │                     │                     │                    │
  parsers         fingerprints          live/IaC              cert inventory      revenue / owner
```

## Join keys

| Layer | Primary key | Attaches to system via |
|---|---|---|
| Source finding / asset | algorithm + file + line | repo name / `system_id` |
| Container library | package name or SHA-256 | image / scan |
| Cloud resource | ARN / bucket / function | cloud account `system_ids` |
| Certificate | SHA-256 fingerprint | endpoint `system_id` |
| Business process | process name | `system_business_processes` |

The graph engine (`GraphEngine` / `NodeBuilder`) stores `USES`,
`CALLS`, `SECURED_BY`, `DEPLOYED_ON`, `SUPPORTS`, and `OWNED_BY` edges
so blast-radius, vendor path, and executive impact walk one model.

## Pipeline stages

`clone → language_detect → scan → evidence → load → normalize → policy
→ dedup → systems → graph → cbom → drift → gate → alert`

Language detection selects parsers; CBOM generation writes CycloneDX 1.5
JSON next to the workspace after policy/graph have run.
