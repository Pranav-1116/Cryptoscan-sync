# The SBOM chain, from the store: seventeen points

`cryptoscan.sbom-supply-guide/1` · generated 2026-11-03T08:19:43Z · **17 pass · 0 partial · 0 fail** · 46 probes

**17 of 17 points of the chain are present in a projection built from the store, across 46 probes; 44 assets, 52 claims, 7 row(s) skipped**

```
BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD
    → ARTIFACT → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST
    → PROCESS → SOFTWARE COMPONENT → CRYPTO CAPABILITY
```

| Level | Nodes |
|---|---|
| `system` | 1 |
| `application` | 2 |
| `repository` | 1 |
| `commit` | 1 |
| `build` | 1 |
| `artifact` | 4 |
| `image` | 3 |
| `deployment` | 4 |
| `pod` | 2 |
| `process` | 1 |
| `component` | 8 |
| `capability` | 7 |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `STORE-01` | a gathered inventory becomes the twelve levels, not a list of packages | **PASS** | 3, 0 failing |
| `STORE-02` | a row the store cannot place is reported with a reason, never repaired | **PASS** | 3, 0 failing |
| `STORE-03` | an edge that names a node the inventory does not hold is refused | **PASS** | 3, 0 failing |
| `STORE-04` | the chain says which revision built the SBOM, from stored rows | **PASS** | 2, 0 failing |
| `STORE-05` | a stored artifact with only a tag is refused rather than anchored | **PASS** | 2, 0 failing |
| `STORE-06` | the component names the application that owns it, through a release | **PASS** | 4, 0 failing |
| `STORE-07` | the image reaches its deployment, pod, node and host from the store | **PASS** | 2, 0 failing |
| `STORE-08` | installed, loaded and used stay three facts after the store mapping | **PASS** | 3, 0 failing |
| `STORE-09` | two stored sources disagree and both versions survive | **PASS** | 2, 0 failing |
| `STORE-10` | directness comes from the manifest and transitivity from the walk | **PASS** | 2, 0 failing |
| `STORE-11` | records join through an anchor and get one canonical id each | **PASS** | 2, 0 failing |
| `STORE-12` | a component reaches the product and the vendor behind it | **PASS** | 3, 0 failing |
| `STORE-13` | an upgrade of a crypto library is counted as a crypto change | **PASS** | 4, 0 failing |
| `STORE-14` | a superseded dependency keeps the row that replaced it | **PASS** | 3, 0 failing |
| `STORE-15` | every crypto dependency carries one of the eight evidence types | **PASS** | 3, 0 failing |
| `STORE-16` | the graph is a projection, and every node has a canonical id | **PASS** | 2, 0 failing |
| `STORE-17` | the store's crypto rows hand capability to the CBOM and decide nothing | **PASS** | 3, 0 failing |

## What the store could not place

- `COMPONENT` — (none): a software row with no coordinate or no evidence reference cannot be placed as a component
- `software` — pkg:generic/sneaky@1.0.0: it asks for 'runtime-probe', which only a probe may claim, and hands over no collector evidence reference: the class would be this adapter's, not the collector's (`PROBE_BASIS_WITHOUT_EVIDENCE`)
- `DEPENDENCY` — pkg:generic/openssl → pkg:generic/zlib@1.3: one end of the edge is not a component this inventory holds; an edge to an undeclared node is refused rather than invented
- `ARTIFACT` — payments-api:latest: payments-api:latest: an artifact dependency binds to a digest, not a name; (none) is not one (`ARTIFACT_WITHOUT_DIGEST`)
- `LAYER` — layer:ubuntu-22.04-base ships pkg:generic/not-in-inventory: the layer names a package this inventory does not hold
- `SBOM` — SBOM-18291 lists pkg:generic/never-installed@9.9.9: the SBOM lists a component this inventory does not hold; the list is not a place to invent a package
- `PROCESS` — payments-api[1821] loads libcrypto.so.3: the process loads something this inventory does not hold

## One canonical asset, several records

**44 record(s) resolve to 26 canonical asset(s); 2 carry more than one record; 23 are identified by a name alone and are not merged with anything**

| canonical | by | records |
|---|---|---|
| `APP-d34c3c3b` | evidence | APPLICATION:Payments API, ARTIFACT:payments-api-4.2.1.jar, BUILD:BUILD-18291, BUSINESS_SYSTEM:Payments System, CONTAINER:payments-api-ctr, CRYPTO_LIBRARY:pkg:generic/openssl, DEPLOYMENT:payments-api-deploy, IMAGE:payments-api:4.2.1, IMAGE_LAYER:layer:ubuntu-22.04-base, NAMESPACE:payments, PACKAGE:pkg:generic/http-core@1.2.0, PACKAGE:pkg:generic/payments-sdk@2.4.0, POD:payments-api-7d9f4c-x2m8p, PROCESS:payments-api[1821], RELEASE:payments-api 4.2.1, REPLICA_SET:payments-api-7d9f4c, REPOSITORY:git.bank.internal/payments/payments-api, SBOM:SBOM-18291 |
| `ART-597f2745` | evidence | ARTIFACT:payments-api-3.9.0.jar |
| `IMG-79f2cdf6` | evidence | IMAGE:reporting-api:1.0.0, PACKAGE:pkg:generic/openssl-dev |
| `APP-3313b929` | name | APPLICATION:Reporting API |
| `ASSET-028262c3` | name | ALGORITHM:ECDSA-256 |
| `ASSET-12aa35e4` | name | CRYPTO_OPERATION:SIGN-payments-api[1821] |
| `ASSET-1553543d` | name | CIPHER_SUITE:TLS_AES_256_GCM_SHA384 |
| `ASSET-176d93ae` | name | CRYPTO_CAPABILITY:pkg:generic/openssl:AES-256 |
| `ASSET-2a0800a8` | name | CLUSTER:prod-cluster |
| `ASSET-3fcaf57b` | name | COMMIT:a81f92c |
| `ASSET-4ba95152` | name | CRYPTO_CAPABILITY:pkg:generic/openssl:RSA-2048 |
| `ASSET-4d16256a` | name | ALGORITHM:RSA-2048 |

## `STORE-01` — PASS

*a gathered inventory becomes the twelve levels, not a list of packages* (guide 176, store)

- **PASS** `every-level-present` — system 1, application 2, repository 1, commit 1, build 1, artifact 4, image 3, deployment 4, pod 2, process 1, component 8, capability 7
- **PASS** `the-two-branches-are-both-there` — 31 kind(s) in the projection
- **PASS** `the-store-builds-through-techbom` — source_of_truth CANONICAL_ESTATE, projection True

## `STORE-02` — PASS

*a row the store cannot place is reported with a reason, never repaired* (guide 176, store)

- **PASS** `the-nameless-software-row-is-skipped` — 1 software row(s) skipped
- **PASS** `a-probe-class-needs-the-collectors-evidence` — ['ARTIFACT_WITHOUT_DIGEST', 'PROBE_BASIS_WITHOUT_EVIDENCE']
- **PASS** `nothing-was-invented-to-fill-the-gap` — 7 row(s) skipped, 44 asset(s) placed

## `STORE-03` — PASS

*an edge that names a node the inventory does not hold is refused* (guide 176, store)

- **PASS** `the-unknown-dependency-target-is-skipped` — one end of the edge is not a component this inventory holds; an edge to an undeclared node is refused rather than invented
- **PASS** `the-layer-does-not-invent-its-packages` — the layer names a package this inventory does not hold
- **PASS** `the-sbom-does-not-invent-its-components` — the SBOM lists a component this inventory does not hold; the list is not a place to invent a package

## `STORE-04` — PASS

*the chain says which revision built the SBOM, from stored rows* (guide 176, provenance)

- **PASS** `repository-commit-build-sbom` — payments-api-4.2.1.jar: git.bank.internal/payments/payments-api → a81f92c → BUILD-18291 → SBOM-18291
- **PASS** `the-artifact-is-bound-to-a-digest` — digest sha256:abc123def4567890abc123def4567890

## `STORE-05` — PASS

*a stored artifact with only a tag is refused rather than anchored* (guide 176, provenance)

- **PASS** `the-tag-only-artifact-is-refused` — payments-api:latest: an artifact dependency binds to a digest, not a name; (none) is not one
- **PASS** `the-tag-is-not-in-the-projection` — payments-api:latest is absent

## `STORE-06` — PASS

*the component names the application that owns it, through a release* (guide 176, ownership)

- **PASS** `the-owner-is-payments-api` — pkg:generic/openssl: owned by Payments API
- **PASS** `the-path-goes-through-a-release` — Payments API RELEASED_AS payments-api 4.2.1 → payments-api 4.2.1 BUNDLES payments-api-4.2.1.jar → payments-api-4.2.1.jar DESCRIBED_BY SBOM-18291 → SBOM-18291 LISTS pkg:generic/openssl
- **PASS** `a-component-nobody-owns-says-so` — pkg:generic/legacy-agent@0.4.2: no application owns it in this projection
- **PASS** `a-component-the-sbom-lists-is-owned-through-it` — pkg:generic/ghost@0.0.9: owned by Payments API

## `STORE-07` — PASS

*the image reaches its deployment, pod, node and host from the store* (guide 176, deployment)

- **PASS** `the-kubernetes-walk-has-its-kinds` — payments-api:4.2.1: cluster prod-cluster → container payments-api-ctr → deployment payments-api-deploy → kubernetes_node node-03 → namespace payments → physical_server srv-k8s-03 → pod payments-api-7d9f4c-x2m8p → process payments-api[1821] → replica_set payments-api-7d9f4c
- **PASS** `the-host-walk-reaches-the-physical-server` — payments-api-7d9f4c-x2m8p: 1 process(es), 6 component(s), 2 host(s), 0 hardware component(s)

## `STORE-08` — PASS

*installed, loaded and used stay three facts after the store mapping* (guide 176, runtime)

- **PASS** `the-component-is-listed-installed-and-loaded` — pkg:generic/openssl: SBOM_PRESENT, INSTALLED, LOADED, CONFIGURED, RUNTIME_USED; not STATIC_REFERENCED
- **PASS** `the-runtime-operation-is-a-use-not-a-capability` — pkg:generic/openssl: SBOM_PRESENT, INSTALLED, LOADED, CONFIGURED, RUNTIME_USED; not STATIC_REFERENCED
- **PASS** `a-build-only-package-is-installed-and-not-deployed` — pkg:generic/openssl-dev: EXISTS=no, INSTALLED=yes, DEPLOYED=no, RUNNING=no, LOADED=no

## `STORE-09` — PASS

*two stored sources disagree and both versions survive* (guide 176, runtime)

- **PASS** `declared-and-runtime-are-both-kept` — pkg:generic/openssl: DECLARED_VERSION=3.0.13, IMAGE_VERSION=—, RUNTIME_VERSION=3.0.11, VENDOR_VERSION=— — 2 versions, preserved
- **PASS** `the-conflict-is-named-not-resolved` — DEPENDENCY_VERSION_CONFLICT

## `STORE-10` — PASS

*directness comes from the manifest and transitivity from the walk* (guide 176, graph)

- **PASS** `the-sdk-is-direct-and-http-core-is-not` — Payments API: 2 direct, 2 transitive, 2 listed only; pkg:generic/http-core@1.2.0, pkg:generic/openssl reached through another component
- **PASS** `the-transitive-row-carries-its-path` — ['pkg:generic/payments-sdk@2.4.0', 'pkg:generic/http-core@1.2.0', 'pkg:generic/openssl']

## `STORE-11` — PASS

*records join through an anchor and get one canonical id each* (guide 176, identity)

- **PASS** `records-with-a-shared-digest-merge` — 44 record(s) resolve to 26 canonical asset(s); 2 carry more than one record; 23 are identified by a name alone and are not merged with anything
- **PASS** `ids-are-issued-per-asset-not-per-record` — {'canonical': 26, 'records': 44, 'merged': 2, 'by_evidence': 3, 'by_name_only': 23}

## `STORE-12` — PASS

*a component reaches the product and the vendor behind it* (guide 176, vendor)

- **PASS** `the-product-is-recorded` — pkg:generic/openssl → OpenSSL 3.x → OpenSSL Project; deployed in 2 deployment(s) across 1 application(s)
- **PASS** `the-deployments-behind-it-are-counted` — ['payments-api-7d9f4c', 'payments-api-deploy'] / ['Payments API']
- **PASS** `a-component-with-no-product-says-so` — pkg:generic/maven@3.9.6 → no product record; deployed in 2 deployment(s) across 1 application(s)

## `STORE-13` — PASS

*an upgrade of a crypto library is counted as a crypto change* (guide 176, remediation)

- **PASS** `the-application-and-system-are-counted` — upgrade pkg:generic/openssl 3.0.13 → 3.0.14: 1 application(s), 1 business system(s), 2 image(s), 1 process(es), 3 algorithm(s), 1 hardware, 1 certificate(s), 1 endpoint(s)
- **PASS** `the-algorithms-behind-it-are-named` — AES-256, ECDSA-256, RSA-2048
- **PASS** `the-hardware-and-the-certificate-are-in-the-blast-radius` — hardware ['HSM-001'], certificates ['CERT-001']
- **PASS** `the-regression-list-is-derived` — crypto module re-validation on HSM-001; certificate re-issue on CERT-001; TLS renegotiation against payments.bank.example:443; payment signature regression

## `STORE-14` — PASS

*a superseded dependency keeps the row that replaced it* (guide 176, history)

- **PASS** `the-superseded-edge-is-retained` — 49 supply edge(s): FIRST_SEEN 3, ACTIVE 45, SUPERSEDED 1; 1 superseded or removed edge(s) kept
- **PASS** `the-replacement-is-named` — pkg:generic/payments-sdk@2.4.0 DEPENDS_ON pkg:generic/http-core@1.2.0
- **PASS** `a-first-seen-edge-is-not-an-active-one` — {'ACTIVE': 45, 'FIRST_SEEN': 3, 'SUPERSEDED': 1}

## `STORE-15` — PASS

*every crypto dependency carries one of the eight evidence types* (guide 176, evidence)

- **PASS** `the-rows-carry-a-type-and-an-id` — 19 crypto dependency edge(s) across 4 evidence type(s); 3 proven by a runtime or network observation, 16 capability, static, configured or declared
- **PASS** `capability-and-usage-are-counted-apart` — proven 3, unproven 16
- **PASS** `no-row-is-promoted-to-a-stronger-type` — CAPABILITY 6, CONFIGURED 3, IMPORTED 7, RUNTIME_OBSERVED 3

## `STORE-16` — PASS

*the graph is a projection, and every node has a canonical id* (guide 176, projection)

- **PASS** `every-record-resolves-to-a-canonical-asset` — 44 record(s) resolve to 26 canonical asset(s); 2 carry more than one record; 23 are identified by a name alone and are not merged with anything
- **PASS** `there-is-one-store` — second_store False, canonical CANONICAL_ESTATE, derived from sbom-supply:production

## `STORE-17` — PASS

*the store's crypto rows hand capability to the CBOM and decide nothing* (guide 176, handoff)

- **PASS** `the-capabilities-arrive` — pkg:generic/openssl: 3 capability(ies) handed to the CBOM; 1 corroborated by runtime or network evidence
- **PASS** `only-a-caller-corroborates` — corroborated ['pkg:generic/openssl:RSA-2048']
- **PASS** `pqc-keeps-the-two-lists-apart` — pkg:generic/openssl: 2 quantum-sensitive capability(ies) and 1 observed use(s); the SBOM answers the first and the CBOM answers the second

## What this does not prove

- the inventory is a fixture: its shapes are the store's, its rows are not
- a stored row records what a collector saw when it ran; nothing here re-runs a collector, so a stale row stays a stale row and the class says so
- the chain is only as complete as the columns: a row that names no commit stops the provenance there, and the gap is printed rather than filled
- the twin is a CBOM projection with its own input shape, so this guide proves the SBOM nodes carry the canonical ids a twin is keyed by, not that a twin was rebuilt from them
