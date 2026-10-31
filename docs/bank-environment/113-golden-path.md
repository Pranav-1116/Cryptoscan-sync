# The five-family golden path — one payload, every hop

`cryptoscan.golden-path/1` · generated 2026-10-31T17:58:28.952447+00:00 · **5 / 5 families passed · 35 / 35 hops**

collector → API → evidence → DB → Twin → BOM → console, for five families, with the count and identity of what arrives asserted at each hop. `SKIPPED` is not a pass and fails the family's completeness.

| Family | What produced its input | Hops | Verdict |
|---|---|---|---|
| `runtime` | the agent's collect_runtime over a fake /proc tree | 7/7 | **PASS** |
| `static` | the API's collect_static over crypto_assets rows the static scanner writes | 7/7 | **PASS** |
| `network_tls` | the API's collect_network over a network scan run the TLS scanner writes | 7/7 | **PASS** |
| `pki` | the API's collect_pki over certificate inventory rows | 7/7 | **PASS** |
| `cloud` | collect_cloud over an injected AWS control plane (ELBv2 TLS policy) | 7/7 | **PASS** |

## Hop by hop

### `runtime` — PASS

| Hop | Verdict | What was asserted |
|---|---|---|
| `collect` | **PASS** | 3 assets, 3 evidence records, every record names its asset |
| `api` | **PASS** | one run persisted (3518ce53), 3 assets and 3 evidence records survived normalisation unchanged |
| `evidence` | **PASS** | 3 content-addressed evidence rows, each naming the collector's target and carrying its facts (10 keys) |
| `db` | **PASS** | 3 catalogue assets and 22 CURRENT facts, including attribute:process=nginx |
| `twin` | **PASS** | 3 assets readable with detail; 22 facts of history across them |
| `bom` | **PASS** | SBOM carries 1 of 1 components matching the planted identity, and all six BOMs share one projection id |
| `ui` | **PASS** | all 3 endpoints have a console client, a caller (CollectorDepth.tsx, DigitalTwinPanel.tsx, EstatePanel.tsx) and a rendered test; this payload is not rendered here |

### `static` — PASS

| Hop | Verdict | What was asserted |
|---|---|---|
| `collect` | **PASS** | 2 assets, 2 evidence records, every record names its asset |
| `api` | **PASS** | one run persisted (e552b8bf), 2 assets and 2 evidence records survived normalisation unchanged |
| `evidence` | **PASS** | 2 content-addressed evidence rows, each naming the collector's target and carrying its facts (8 keys) |
| `db` | **PASS** | 2 catalogue assets and 18 CURRENT facts, including crypto:algorithm=RSA |
| `twin` | **PASS** | 2 assets readable with detail; 18 facts of history across them |
| `bom` | **PASS** | CBOM carries 1 of 2 components matching the planted identity, and all six BOMs share one projection id |
| `ui` | **PASS** | all 3 endpoints have a console client, a caller (CollectorDepth.tsx, DigitalTwinPanel.tsx, EstatePanel.tsx) and a rendered test; this payload is not rendered here |

### `network_tls` — PASS

| Hop | Verdict | What was asserted |
|---|---|---|
| `collect` | **PASS** | 1 assets, 1 evidence records, every record names its asset |
| `api` | **PASS** | one run persisted (ebb540d4), 1 assets and 1 evidence records survived normalisation unchanged |
| `evidence` | **PASS** | 1 content-addressed evidence rows, each naming the collector's target and carrying its facts (9 keys) |
| `db` | **PASS** | 1 catalogue assets and 11 CURRENT facts, including attribute:protocol=TLS |
| `twin` | **PASS** | 1 assets readable with detail; 11 facts of history across them |
| `bom` | **PASS** | NBOM carries 1 of 1 components matching the planted identity, and all six BOMs share one projection id |
| `ui` | **PASS** | all 3 endpoints have a console client, a caller (CollectorDepth.tsx, DigitalTwinPanel.tsx, EstatePanel.tsx) and a rendered test; this payload is not rendered here |

### `pki` — PASS

| Hop | Verdict | What was asserted |
|---|---|---|
| `collect` | **PASS** | 1 assets, 1 evidence records, every record names its asset |
| `api` | **PASS** | one run persisted (64b7a75b), 1 assets and 1 evidence records survived normalisation unchanged |
| `evidence` | **PASS** | 1 content-addressed evidence rows, each naming the collector's target and carrying its facts (10 keys) |
| `db` | **PASS** | 1 catalogue assets and 6 CURRENT facts, including attribute:issuer=CN=Bank Issuing CA |
| `twin` | **PASS** | 1 assets readable with detail; 6 facts of history across them |
| `bom` | **PASS** | CBOM carries 1 of 1 components matching the planted identity, and all six BOMs share one projection id |
| `ui` | **PASS** | all 3 endpoints have a console client, a caller (CollectorDepth.tsx, DigitalTwinPanel.tsx, EstatePanel.tsx) and a rendered test; this payload is not rendered here |

### `cloud` — PASS

| Hop | Verdict | What was asserted |
|---|---|---|
| `collect` | **PASS** | 2 assets, 2 evidence records, every record names its asset |
| `api` | **PASS** | one run persisted (a4e23cf2), 2 assets and 2 evidence records survived normalisation unchanged |
| `evidence` | **PASS** | 2 content-addressed evidence rows, each naming the collector's target and carrying its facts (10 keys) |
| `db` | **PASS** | 2 catalogue assets and 12 CURRENT facts, including attribute:type=application |
| `twin` | **PASS** | 2 assets readable with detail; 12 facts of history across them |
| `bom` | **PASS** | NBOM carries 1 of 1 components matching the planted identity, and all six BOMs share one projection id |
| `ui` | **PASS** | all 3 endpoints have a console client, a caller (CollectorDepth.tsx, DigitalTwinPanel.tsx, EstatePanel.tsx) and a rendered test; this payload is not rendered here |

## Defects this path exposes

Found while walking the path, reported rather than fixed here. They do not change the verdicts above, and they are not the reason the path passes.

| Family | Defect | Asset | Detail |
|---|---|---|---|
| `static` | `asset-named-by-raw-identifier` | `application:9fed93b7621bb29ac2d0129e` | the catalogue names this asset '26fede90-2cdc-46f0-82a6-d712d988f25e' while its location is 'src/pay/Bulk.java' — a reader sees a row identifier where an application name belongs |
| `static` | `asset-named-by-raw-identifier` | `application:c7ea579b9ff411e1d0305bc4` | the catalogue names this asset '27406a29-fcb5-48bf-b7ad-7ff53cef5af9' while its location is 'src/pay/Sign.java' — a reader sees a row identifier where an application name belongs |

## What this does not prove

- The collector code is real, but the input it reads is not a bank's: /proc is a fixture, the AWS transport is injected, and the static/network/PKI rows are written in the scanner's own shape rather than produced by running the scanner.
- The UI stage proves a console caller and a rendered test exist for the endpoints the earlier hops read. It does not render this payload, and no browser was involved.
- Each family runs on its own empty SQLite database, so this is five single-family paths, not one estate where the families interact (identity merging across planes, conflicts, and change detection are covered by their own suites).
- Only the five families a first deployment runs are here. Kubernetes, CMDB, KMS, HSM, hardware and vendor planes are not part of this path.

A passing row means a payload of that family's shape survives every hop with its identity and its facts intact. It does not mean the collector was run against a bank's network, and it is not a substitute for the per-family qualification a deployment needs.
