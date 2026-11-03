# The questions a TechBOM has to answer

`cryptoscan.cbom-techbom-answers-guide/1` · generated 2026-11-03T01:43:15.501174+00:00 · **7 pass · 0 partial · 0 fail** · 35 probes

Guide 164 built the graph and its guard rails. This guide asks the graph the
questions an estate actually asks, and holds each answer to the same rules:
proven edges only, declared edges reported separately, and a refusal instead of
a guess.

```
roll-up     business system → technology counted by kind (proven / declared)
path        endpoint → WAF → LB → gateway → mesh → application → database
impact      who breaks, what has to change, and which sites block a migration
timeline    snapshots → typed changes, because one snapshot is not a series
context     live event → CORRELATED_PATTERN with the estate behind it
promotion   IMPORTED → OBSERVED on new evidence, with the old class kept
```

**Payments (CRITICAL): 2 applications, 1 service, 1 container, 1 pod, 1 process, 1 package, 1 crypto library, 2 crypto assets, 1 database, 1 network endpoint, 1 WAF, 1 load balancer, 1 API gateway, 1 service mesh, 1 certificate, 1 certificate authority, 1 HSM, 1 key reference, 1 firmware, 1 vendor product, 1 vendor, 1 host, 1 VM, 1 physical server, 1 TPM across 29 kind(s); 25 proven by observation or configuration, 6 declared only**

| kind | proven | declared only |
|---|---|---|
| `ALGORITHM` | 1 | 0 |
| `API_GATEWAY` | 1 | 0 |
| `APPLICATION` | 2 | 1 |
| `CERTIFICATE` | 1 | 0 |
| `CERTIFICATE_AUTHORITY` | 1 | 0 |
| `CONTAINER` | 1 | 0 |
| `CRYPTO_ASSET` | 2 | 1 |
| `CRYPTO_LIBRARY` | 1 | 1 |
| `DATABASE` | 1 | 0 |
| `DEPLOYMENT` | 1 | 0 |
| `FIRMWARE` | 1 | 0 |
| `HOST` | 1 | 0 |
| `HSM` | 1 | 0 |
| `IMAGE` | 1 | 0 |
| `KEY_REFERENCE` | 1 | 0 |
| `LOAD_BALANCER` | 1 | 0 |
| `NETWORK_ENDPOINT` | 1 | 0 |
| `PACKAGE` | 1 | 1 |
| `PHYSICAL_SERVER` | 1 | 0 |
| `POD` | 1 | 0 |
| `PROCESS` | 1 | 0 |
| `PUBLIC_KEY` | 1 | 0 |
| `SERVICE` | 1 | 0 |
| `SERVICE_MESH` | 1 | 0 |
| `TPM` | 1 | 0 |
| `VENDOR` | 1 | 1 |
| `VENDOR_PRODUCT` | 1 | 1 |
| `VM` | 1 | 0 |
| `WAF` | 1 | 0 |

**Request path**: payments.bank.example:443 → waf-01 → External-LB-01 → payments-gw → payments-mesh → Payments API

| hop | role | evidence | crypto | certificate |
|---|---|---|---|---|
| `payments.bank.example:443` | START | START | tls_version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, sni=payments.bank.example, alpn=h2, mtls=True | TECH-CERT-001 |
| `waf-01` | PROTECTED_BY | CONFIGURED | **NOT_RECORDED** | — |
| `External-LB-01` | FORWARDS_TO | CONFIGURED | tls_version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | — |
| `payments-gw` | FORWARDS_TO | CONFIGURED | tls_version=TLSv1.3 | — |
| `payments-mesh` | FORWARDS_TO | CONFIGURED | mtls=True | — |
| `Payments API` | ROUTES_TO | CONFIGURED | **NOT_RECORDED** | — |

**Impact** — AES-256-GCM: 1 API gateway, 1 application, 1 business system, 1 load balancer, 1 network endpoint, 1 service mesh, 1 WAF; 1 critical system(s); 2 blocker(s)

Migration sites: TECH-FW-001, TECH-HSM-001

| blocker | count | who acts |
|---|---|---|
| `FIRMWARE_UPGRADE_REQUIRED` | 1 | the firmware in place does not support a required algorithm |
| `HSM_PQC_CAPABILITY_UNKNOWN` | 1 | no evidence of what the HSM can do, so it is a blocker until someone reads its capability list |

*Declared, not counted* — RSA-2048: 1 HSM (9 asset(s) stay declared)

**Timeline** — 3 snapshot(s), 13 change(s): CERTIFICATE_CHANGED 4, NETWORK_CHANGED 2, SBOM_CHANGED 1, TECHNOLOGY_CHANGED 6

**Context** — tls downgrade on payments.bank.example:443 (TLSv1.3 → TLSv1.2); business system Payments; 3 related asset(s)

**Promotion** — Payments API USES_CRYPTO RSA-2048: IMPORTED → OBSERVED on runtime-probe (EVD-PROBE-9); the earlier class is kept in the history

Fixture: 36 technology asset(s) across 34 kind(s) and 38 evidenced relationship(s); 8 edge(s) not proven; 0 claim(s) refused

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `rollup` | does a business system know the technology it actually holds? | **PASS** | 5, 0 failing |
| `path` | what technology path does a request travel through? | **PASS** | 5, 0 failing |
| `impact` | what breaks, who has to change, and what is only declared? | **PASS** | 5, 0 failing |
| `time` | can the bom say what changed, not just what is? | **PASS** | 5, 0 failing |
| `context` | can a live event be placed in the estate it happened to? | **PASS** | 5, 0 failing |
| `promotion` | can a claim get stronger without being quietly rewritten? | **PASS** | 5, 0 failing |
| `honesty` | does each answer stop where the evidence stops? | **PASS** | 5, 0 failing |

## `rollup` — PASS

*does a business system know the technology it actually holds?* (review tc / 7 and 8)

- **PASS** `a-business-system-roll-up-counts-technology-by-kind` — Payments (CRITICAL): 2 applications, 1 service, 1 container, 1 pod, 1 process, 1 package, 1 crypto library, 2 crypto assets, 1 database, 1 network endpoint, 1 WAF, 1 load balancer, 1 API gateway, 1 service mesh, 1 certificate, 1 certificate authority, 1 HSM, 1 key reference, 1 firmware, 1 vendor product, 1 vendor, 1 host, 1 VM, 1 physical server, 1 TPM across 29 kind(s); 25 proven by observation or configuration, 6 declared only
- **PASS** `the-roll-up-carries-the-criticality-and-the-owner` — Payments · CRITICAL · Payments Platform
- **PASS** `a-declared-hop-is-counted-and-labelled-rather-than-hidden-or-flattened` — Payments Batch arrives by CMDB import: in the count, out of the proven number, and named in the split
- **PASS** `a-roll-up-refuses-something-that-is-not-a-business-system` — a scan target is not a business system
- **PASS** `the-portfolio-roll-up-lists-every-system-with-its-size` — 1 business system(s): Payments (25)

## `path` — PASS

*what technology path does a request travel through?* (review tc / 11)

- **PASS** `a-request-path-is-a-sequence-of-technology-not-a-list-of-endpoints` — payments.bank.example:443 → waf-01 → External-LB-01 → payments-gw → payments-mesh → Payments API
- **PASS** `each-hop-carries-the-crypto-it-negotiates` — TLS 1.3 at the edge, TLS 1.2 at the balancer, mTLS in the mesh
- **PASS** `a-hop-with-no-crypto-recorded-is-marked-not-drawn-clean` — crypto recorded on 4/6 hops
- **PASS** `the-hop-that-presents-a-certificate-names-it` — endpoint → CERT-9281
- **PASS** `a-path-refuses-an-asset-the-bom-does-not-hold` — a path is drawn from the graph or not at all

## `impact` — PASS

*what breaks, who has to change, and what is only declared?* (review tc / 12, 19 and 20)

- **PASS** `impact-answers-in-the-vocabulary-an-owner-asks-for` — AES-256-GCM: 1 API gateway, 1 application, 1 business system, 1 load balancer, 1 network endpoint, 1 service mesh, 1 WAF; 1 critical system(s); 2 blocker(s)
- **PASS** `impact-counts-only-what-the-graph-proves-and-lists-the-rest` — RSA-2048 reaches the estate through a manifest row, so nothing above it is proven
- **PASS** `a-blocker-names-who-has-to-act` — FIRMWARE_UPGRADE_REQUIRED · HSM_PQC_CAPABILITY_UNKNOWN
- **PASS** `a-migration-site-is-found-through-the-application-that-uses-it` — TECH-FW-001, TECH-HSM-001
- **PASS** `an-application-whose-crypto-is-unknown-is-a-blocker-of-its-own` — a migration cannot plan around an application nobody has read

## `time` — PASS

*can the bom say what changed, not just what is?* (review tc / 15)

- **PASS** `one-snapshot-is-a-state-and-says-so` — one snapshot is a state, not a series: nothing can be said about change from one point in time
- **PASS** `a-timeline-names-each-change-in-its-own-category` — 3 snapshot(s), 13 change(s): CERTIFICATE_CHANGED 4, NETWORK_CHANGED 2, SBOM_CHANGED 1, TECHNOLOGY_CHANGED 6
- **PASS** `a-version-change-carries-both-values-and-its-step` — openssl: 3.0.13 → 3.0.11
- **PASS** `the-series-shows-the-estate-size-at-each-snapshot` — [{"snapshot": 1, "assets": 36, "claims": 38}, {"snapshot": 2, "assets": 36, "claims": 38}, {"snapshot": 3, "assets": 36, "claims": 38}]
- **PASS** `a-timeline-refuses-a-document-that-is-not-a-snapshot` — a foreign document is rejected, not interpolated

## `context` — PASS

*can a live event be placed in the estate it happened to?* (review tc / 21)

- **PASS** `an-event-becomes-a-correlated-pattern-with-the-estate-behind-it` — tls downgrade on payments.bank.example:443 (TLSv1.3 → TLSv1.2); business system Payments; 3 related asset(s)
- **PASS** `the-pattern-names-the-change-not-just-the-event` — TLSv1.3 → TLSv1.2 on the endpoint that presents CERT-9281
- **PASS** `the-related-assets-come-from-the-graph` — EXPOSES, PRESENTS, PROTECTED_BY
- **PASS** `a-context-will-not-name-an-asset-the-bom-does-not-hold` — a fabricated context is worse than no context
- **PASS** `an-event-with-no-evidence-is-a-rumour-and-is-refused` — no evidence id, no pattern

## `promotion` — PASS

*can a claim get stronger without being quietly rewritten?* (review tc / 22)

- **PASS** `an-imported-relationship-becomes-observed-only-with-new-evidence` — Payments API USES_CRYPTO RSA-2048: IMPORTED → OBSERVED on runtime-probe (EVD-PROBE-9); the earlier class is kept in the history
- **PASS** `the-previous-class-is-kept-in-the-history` — the model does not rewrite what it used to believe
- **PASS** `a-promotion-needs-a-stronger-basis` — changing the label is not verification
- **PASS** `a-promotion-needs-evidence-the-claim-did-not-already-cite` — a belief restated is not an observation
- **PASS** `proximity-can-never-promote-anything` — the same rule that builds the graph keeps it honest

## `honesty` — PASS

*does each answer stop where the evidence stops?* (all of review tc)

- **PASS** `every-answer-carries-the-limits-it-cannot-cross` — each answer states what the graph cannot support
- **PASS** `reachability-is-never-reported-as-breakage` — an owner's impact assessment sits above the graph
- **PASS** `a-downgrade-is-not-called-an-attack` — a client negotiating lower is the usual explanation
- **PASS** `every-answer-refuses-a-document-that-is-not-a-techbom` — the answers cannot be asked of the wrong document
- **PASS** `the-whole-guide-runs-on-one-estate-build-not-a-copy` — 36 technology asset(s) across 34 kind(s) and 38 evidenced relationship(s); 8 edge(s) not proven; 0 claim(s) refused

## What this does not prove

- the estate is a fixture, not a bank: every asset and edge here is the shape of the argument, and none of it is an observation of a real network
- a roll-up is the system the graph proves, not the system on the org chart: an asset nobody connected belongs to no system here
- a request path is a path a source asserted. Load balancers route by rules this model does not read, and an unrecorded route is missing, not absent
- an impact count is exposure, not breakage, and a blocker is what the model can see on the path: a vendor roadmap is not on the path
- a timeline samples states. What happened between two snapshots is not in either of them
- a threat context is the estate an event happened to. It is not a causal chain, and a downgrade is more often a client than an attacker
- promotion changes a claim's class on new evidence; it does not re-derive the graph, so a promoted edge is a new claim and the old one stays in history
