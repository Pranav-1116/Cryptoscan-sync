# The SBOM dependency chain, twenty-eight points

`cryptoscan.sbom-dependency-guide/1` · generated 2026-11-03T07:53:43Z · **28 pass · 0 partial · 0 fail** · 79 probes

**28 of 28 points of the chain are present in the built projection.**

```
BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD
    → ARTIFACT → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST
    → PROCESS → SOFTWARE COMPONENT → CRYPTO CAPABILITY
```

28 of 28 points of the SBOM dependency chain are present in the built projection, across 79 probes; 64 assets and 74 claims

| level | nodes |
|---|---|
| system | 1 |
| application | 3 |
| repository | 1 |
| commit | 1 |
| build | 1 |
| artifact | 8 |
| image | 4 |
| deployment | 4 |
| pod | 2 |
| process | 1 |
| component | 10 |
| capability | 9 |

## Where the artifact came from

**payments-api-4.2.1.jar: git.bank.internal/payments/payments-api → a81f92c → BUILD-18291 → SBOM-18291**

- repository: `git.bank.internal/payments/payments-api`
- commit: `a81f92c`
- build: `BUILD-18291`
- pipeline: `jenkins-payments-ci`
- artifact: `payments-api-4.2.1.jar`
- digest: `sha256:abc123def4567890abc123def4567890`
- sbom: `SBOM-18291`

## Four version layers

**pkg:generic/openssl: DECLARED_VERSION=3.0.13, IMAGE_VERSION=3.0.13, RUNTIME_VERSION=3.0.11, VENDOR_VERSION=3.0.13 — 2 versions, preserved**

- `DECLARED_VERSION` = 3.0.13 (row, sbom)
- `IMAGE_VERSION` = 3.0.13 (image-scan)
- `RUNTIME_VERSION` = 3.0.11 (process-map)
- `VENDOR_VERSION` = 3.0.13 (vendor-portal)

## What is true of the component

**pkg:generic/openssl: SBOM_PRESENT, INSTALLED, LOADED, CONFIGURED, STATIC_REFERENCED, RUNTIME_USED**

| state | holds | evidence |
|---|---|---|
| SBOM_PRESENT | yes | SBOM-18291 |
| INSTALLED | yes | layer:ubuntu-22.04-base |
| LOADED | yes | payments-api[1821] |
| CONFIGURED | yes | Ubuntu 22.04 LTS SUPPORTS |
| STATIC_REFERENCED | yes | src/main/java/bank/PaymentsCrypto.java:EVP_DigestSignInit USES_ALGORITHM |
| RUNTIME_USED | yes | OP-SIGN-001 |

## The handoff to the CBOM

**pkg:generic/openssl: 4 capability(ies) handed to the CBOM; 1 corroborated by runtime or network evidence**

| capability | algorithms | evidence types | verdict |
|---|---|---|---|
| libcrypto.so.3:AES-128 | AES-128 | CAPABILITY, IMPORTED | CAPABILITY_ONLY |
| libcrypto.so.3:AES-256-GCM | AES-256-GCM | CAPABILITY, IMPORTED | CAPABILITY_ONLY |
| libcrypto.so.3:RSA-2048 | RSA-2048 | CAPABILITY, RUNTIME_OBSERVED, IMPORTED | CORROBORATED |
| libcrypto.so.3:ECDSA-P256 | ECDSA-P256 | CAPABILITY, IMPORTED | CAPABILITY_ONLY |

## Direct and transitive

**Payments API: 2 direct, 2 transitive, 2 listed only; pkg:generic/http-core@1.2.0, pkg:generic/openssl reached through another component**

| component | kind | scope | version | path |
|---|---|---|---|---|
| pkg:generic/maven@3.9.6 | DIRECT | BUILD | 3.9.6 | pkg:generic/maven@3.9.6 |
| pkg:generic/payments-sdk@2.4.0 | DIRECT | RUNTIME | 2.4.0 | pkg:generic/payments-sdk@2.4.0 |
| pkg:generic/http-core@1.2.0 | TRANSITIVE | TRANSITIVE | 1.2.0 | pkg:generic/payments-sdk@2.4.0 → pkg:generic/http-core@1.2.0 |
| pkg:generic/openssl | TRANSITIVE | RUNTIME | 3.0.13 | pkg:generic/payments-sdk@2.4.0 → pkg:generic/http-core@1.2.0 → pkg:generic/openssl |

## Scope

**8 component(s) across 4 scope(s); 4 in production scope; 1 build-scope component(s) reach a running application**

| scope | components |
|---|---|
| RUNTIME | 4 |
| TEST | 1 |
| BUILD | 2 |
| TRANSITIVE | 1 |

## One asset, several names

**Payments API: 4 record(s) joined by digest:sha256:8af92c1d4e5f60718293a4b5c6d7e8f9, digest:sha256:abc123def4567890abc123def4567890, namespace:payments**

- `digest:sha256:abc123def4567890abc123def4567890` — Payments API, payments-api-4.2.1.jar
- `digest:sha256:8af92c1d4e5f60718293a4b5c6d7e8f9` — Payments API, payments-api-4.2.1.jar, payments-api:4.2.1
- `namespace:payments` — payments-api-4.2.1.jar, payments-api:4.2.1

## What a CVE reaches

**CVE-2026-0002: 3 component(s), 2 image(s), 2 deployment(s), 1 application(s), 1 business system(s) affected**


## What an upgrade touches

**upgrade pkg:generic/openssl 3.0.13 → 3.0.14: affects 1 application(s), 1 business system(s), 2 image(s), 1 process(es); regression: FIPS module re-validation, payment signature regression**


## The PQC handoff

**pkg:generic/openssl: 2 quantum-sensitive capability(ies) and 1 observed use(s); the SBOM answers the first and the CBOM answers the second**

- capabilities: ECDSA-P256, RSA-2048
- observed usage: RSA-2048

## What the count means

**2 component(s) discovered; 75/100 application(s) inspected (75.0%); SBOM completeness: PARTIAL**


## One graph

**64 node(s) of 40 kind(s), 74 edge(s), 34 of them on the supply chain; projection of CANONICAL_ESTATE, one store**


| Row | Question | Verdict | Probes |
|---|---|---|---|
| `SBOM-01` | an SBOM component names the application that owns it | **PASS** | 3, 0 failing |
| `SBOM-02` | the artifact names the repository, the commit and the build that produced it | **PASS** | 3, 0 failing |
| `SBOM-03` | an SBOM binds to a digest, and a tag is refused as an identity | **PASS** | 3, 0 failing |
| `SBOM-04` | existence in an SBOM is not a deployment | **PASS** | 3, 0 failing |
| `SBOM-05` | the declared version and the runtime version are both preserved | **PASS** | 3, 0 failing |
| `SBOM-06` | installed, loaded and used are three different facts | **PASS** | 3, 0 failing |
| `SBOM-07` | the SBOM hands capability to the CBOM and never asserts usage | **PASS** | 3, 0 failing |
| `SBOM-08` | every crypto dependency carries its evidence type | **PASS** | 3, 0 failing |
| `SBOM-09` | the image digest anchors the layers, the packages and the process | **PASS** | 3, 0 failing |
| `SBOM-10` | the image reaches its deployment, replica set, pod, container and node | **PASS** | 3, 0 failing |
| `SBOM-11` | a non-container workload reaches its host and the hardware under it | **PASS** | 3, 0 failing |
| `SBOM-12` | the dependency graph carries relationship, scope, version and evidence | **PASS** | 3, 0 failing |
| `SBOM-13` | a transitive dependency is reported with the path that makes it transitive | **PASS** | 3, 0 failing |
| `SBOM-14` | the scope a dependency was declared in stays on the dependency | **PASS** | 3, 0 failing |
| `SBOM-15` | a component reaches its product and the vendor behind it | **PASS** | 3, 0 failing |
| `SBOM-16` | a software dependency that relies on hardware crypto names the hardware | **PASS** | 2, 0 failing |
| `SBOM-17` | the application's listener and the crypto it negotiates join the same graph | **PASS** | 3, 0 failing |
| `SBOM-18` | the certificate's crypto is not the application's crypto | **PASS** | 2, 0 failing |
| `SBOM-19` | the SBOM is a projection of the canonical estate, not a second store | **PASS** | 2, 0 failing |
| `SBOM-20` | two names for one asset resolve through evidence, never through the name | **PASS** | 3, 0 failing |
| `SBOM-21` | four version layers disagree and the conflict is the finding | **PASS** | 2, 0 failing |
| `SBOM-22` | a dependency that moved keeps the version it had and the evidence for both | **PASS** | 3, 0 failing |
| `SBOM-23` | a superseded dependency is kept, not deleted | **PASS** | 2, 0 failing |
| `SBOM-24` | a count is reported against what was inspected, never against the bank | **PASS** | 3, 0 failing |
| `SBOM-25` | a vulnerability walks to the component, the deployment and the business system | **PASS** | 3, 0 failing |
| `SBOM-26` | an upgrade is counted after the walk, so the number is the systems it changes | **PASS** | 3, 0 failing |
| `SBOM-27` | the SBOM hands capability to the CBOM and never decides PQC readiness | **PASS** | 3, 0 failing |
| `SBOM-28` | the whole chain assembles into one graph, level by level | **PASS** | 3, 0 failing |

## `SBOM-01` — PASS

*an SBOM component names the application that owns it* (guide 175, the chain)

- **PASS** `the-component-resolves-to-its-application` — pkg:generic/openssl: owners ['Payments API']
- **PASS** `the-ownership-path-is-evidenced` — Payments API RELEASED_AS payments-api 4.2.1
- **PASS** `a-component-nobody-owns-says-so` — pkg:generic/ghost@0.0.9: pkg:generic/ghost@0.0.9: no application owns it in this projection

## `SBOM-02` — PASS

*the artifact names the repository, the commit and the build that produced it* (guide 175, the chain)

- **PASS** `the-provenance-chain-is-complete` — payments-api-4.2.1.jar: git.bank.internal/payments/payments-api → a81f92c → BUILD-18291 → SBOM-18291
- **PASS** `every-step-names-its-node` — repo git.bank.internal/payments/payments-api, commit a81f92c, build BUILD-18291, pipeline jenkins-payments-ci
- **PASS** `a-missing-step-is-reported-not-filled` — payments-api:latest: provenance is missing repository, commit, build

## `SBOM-03` — PASS

*an SBOM binds to a digest, and a tag is refused as an identity* (guide 175, the chain)

- **PASS** `the-sbom-binds-to-the-artifact-digest` — SBOM-18291 → payments-api-4.2.1.jar at sha256:abc123def4567890abc123def4567890 → payments-api:4.2.1 at sha256:8af92c1d4e5f60718293a4b5c6d7e8f9
- **PASS** `the-image-digest-is-carried-too` — image payments-api:4.2.1 at sha256:8af92c1d4e5f60718293a4b5c6d7e8f9
- **PASS** `a-tag-only-artifact-is-refused` — SBOM-latest → TAG_ONLY_IDENTITY

## `SBOM-04` — PASS

*existence in an SBOM is not a deployment* (guide 175, the chain)

- **PASS** `the-deployed-component-reaches-a-deployment` — pkg:generic/openssl: EXISTS=yes, INSTALLED=yes, DEPLOYED=yes, RUNNING=yes, LOADED=yes
- **PASS** `a-component-installed-nowhere-running-is-not-deployed` — pkg:generic/openssl-dev: EXISTS=no, INSTALLED=yes, DEPLOYED=no, RUNNING=no, LOADED=no
- **PASS** `the-strongest-state-is-named` — strongest LOADED of ['EXISTS', 'INSTALLED', 'DEPLOYED', 'RUNNING', 'LOADED']

## `SBOM-05` — PASS

*the declared version and the runtime version are both preserved* (guide 175, runtime)

- **PASS** `the-two-versions-disagree-and-both-survive` — pkg:generic/openssl: DECLARED_VERSION=3.0.13, IMAGE_VERSION=3.0.13, RUNTIME_VERSION=3.0.11, VENDOR_VERSION=3.0.13 — 2 versions, preserved
- **PASS** `the-conflict-is-NOT-silently-resolved` — code DEPENDENCY_VERSION_CONFLICT, distinct ['3.0.11', '3.0.13']
- **PASS** `the-image-and-vendor-layers-are-named` — DECLARED_VERSION=3.0.13, IMAGE_VERSION=3.0.13, RUNTIME_VERSION=3.0.11, VENDOR_VERSION=3.0.13

## `SBOM-06` — PASS

*installed, loaded and used are three different facts* (guide 175, runtime)

- **PASS** `the-loaded-component-carries-all-six-answers` — pkg:generic/openssl: SBOM_PRESENT, INSTALLED, LOADED, CONFIGURED, STATIC_REFERENCED, RUNTIME_USED
- **PASS** `a-build-only-component-is-present-and-never-loaded` — pkg:generic/maven@3.9.6: SBOM_PRESENT; not INSTALLED, LOADED, CONFIGURED, STATIC_REFERENCED, RUNTIME_USED
- **PASS** `the-configured-and-static-references-are-separated` — configured ['Ubuntu 22.04 LTS SUPPORTS'], static ['src/main/java/bank/PaymentsCrypto.java:EVP_DigestSignInit USES_ALGORITHM']

## `SBOM-07` — PASS

*the SBOM hands capability to the CBOM and never asserts usage* (guide 175, handoff)

- **PASS** `the-capabilities-reach-the-cbom` — pkg:generic/openssl: 4 capability(ies) handed to the CBOM; 1 corroborated by runtime or network evidence
- **PASS** `each-capability-names-the-algorithm-it-means` — libcrypto.so.3:AES-128→AES-128, libcrypto.so.3:AES-256-GCM→AES-256-GCM, libcrypto.so.3:RSA-2048→RSA-2048
- **PASS** `no-component-or-library-claims-to-USE-an-algorithm` — 0 USES edge(s) from a component

## `SBOM-08` — PASS

*every crypto dependency carries its evidence type* (guide 175, handoff)

- **PASS** `the-review-vocabulary-is-used` — types ['CAPABILITY', 'IMPORTED', 'RUNTIME_OBSERVED'] of ['CAPABILITY', 'STATIC_OBSERVED', 'CONFIGURED', 'RUNTIME_OBSERVED', 'NETWORK_OBSERVED', 'IMPORTED', 'VENDOR_DECLARED', 'UNKNOWN']
- **PASS** `capability-and-imported-are-distinct-from-runtime` — CAPABILITY=4, IMPORTED=4, RUNTIME_OBSERVED=1
- **PASS** `a-capability-with-no-collector-is-not-marked-used` — 1 of 4 corroborated

## `SBOM-09` — PASS

*the image digest anchors the layers, the packages and the process* (guide 175, container)

- **PASS** `the-image-carries-its-digest` — payments-api:4.2.1 at sha256:8af92c1d4e5f60718293a4b5c6d7e8f9
- **PASS** `the-base-layer-is-named-and-ships-the-package` — payments-api:4.2.1@sha256:8af92c1d4e5f60718293a4b5c6d7e8f9: 1 layer(s), 1 package(s), 1 process(es)
- **PASS** `the-process-that-loads-it-is-reached-from-the-image` — processes ['payments-api[1821]']

## `SBOM-10` — PASS

*the image reaches its deployment, replica set, pod, container and node* (guide 175, kubernetes)

- **PASS** `every-kubernetes-level-is-present` — payments-api:4.2.1: cluster prod-cluster → container payments-api-ctr → deployment payments-api-deploy → kubernetes_node node-03 → namespace payments → physical_server srv-k8s-03 → pod payments-api-7d9f4c-x2m8p → process payments-api[1821] → replica_set payments-api-7d9f4c
- **PASS** `the-replica-set-is-not-skipped` — replica sets ['payments-api-7d9f4c']
- **PASS** `the-node-sits-on-a-physical-host` — hosts ['srv-k8s-03']

## `SBOM-11` — PASS

*a non-container workload reaches its host and the hardware under it* (guide 175, hardware)

- **PASS** `the-process-reaches-its-host` — Payments API: 1 process(es), 7 component(s), 2 host(s), 2 hardware component(s)
- **PASS** `the-hardware-components-are-named` — hardware ['CPU-01', 'TPM-01']
- **PASS** `the-component-and-the-process-travel-together` — processes ['payments-api[1821]'], components 7

## `SBOM-12` — PASS

*the dependency graph carries relationship, scope, version and evidence* (guide 175, graph)

- **PASS** `the-tree-is-walked-from-the-application` — Payments API: 2 direct, 2 transitive, 2 listed only; pkg:generic/http-core@1.2.0, pkg:generic/openssl reached through another component
- **PASS** `every-row-carries-scope-version-and-evidence` — 4 row(s); scopes ['BUILD', 'RUNTIME', 'TRANSITIVE']
- **PASS** `each-row-carries-its-observation-window` — 1 row(s) with a first_seen

## `SBOM-13` — PASS

*a transitive dependency is reported with the path that makes it transitive* (guide 175, graph)

- **PASS** `the-sdk-is-direct-and-openssl-is-not` — direct ['pkg:generic/maven@3.9.6', 'pkg:generic/payments-sdk@2.4.0'], transitive ['pkg:generic/http-core@1.2.0', 'pkg:generic/openssl']
- **PASS** `the-path-names-the-component-it-came-through` — pkg:generic/payments-sdk@2.4.0 → pkg:generic/http-core@1.2.0 → pkg:generic/openssl
- **PASS** `the-statement-says-through-not-uses` — Payments API: 2 direct, 2 transitive, 2 listed only; pkg:generic/http-core@1.2.0, pkg:generic/openssl reached through another component

## `SBOM-14` — PASS

*the scope a dependency was declared in stays on the dependency* (guide 175, graph)

- **PASS** `the-scopes-are-counted-and-production-is-separated` — 8 component(s) across 4 scope(s); 4 in production scope; 1 build-scope component(s) reach a running application
- **PASS** `a-build-scope-component-is-not-production-surface` — production ['pkg:generic/ghost@0.0.9', 'pkg:generic/openssl', 'pkg:generic/orphan@0.1.0', 'pkg:generic/payments-sdk@2.4.0']; build-scope pkg:generic/maven@3.9.6
- **PASS** `an-unknown-scope-is-refused` — scope WHATEVER → UNKNOWN_SCOPE

## `SBOM-15` — PASS

*a component reaches its product and the vendor behind it* (guide 175, vendor)

- **PASS** `the-product-and-vendor-are-both-reached` — product edges ['OpenSSL 3.x']
- **PASS** `the-vendor-is-a-node-not-a-string` — VENDOR OpenSSL Project
- **PASS** `the-vendor-chain-answers-an-advisory` — SUPPLIED_BY edges ['OpenSSL 3.x→OpenSSL Project']

## `SBOM-16` — PASS

*a software dependency that relies on hardware crypto names the hardware* (guide 175, hardware)

- **PASS** `the-hardware-is-reached-through-the-host` — Payments API: 1 process(es), 7 component(s), 2 host(s), 2 hardware component(s)
- **PASS** `the-tpm-is-the-same-node-the-cbom-uses` — TPM-01 is one node, read by both projections

## `SBOM-17` — PASS

*the application's listener and the crypto it negotiates join the same graph* (guide 175, network)

- **PASS** `the-application-exposes-the-endpoint` — Payments API EXPOSES payments.bank.example:443
- **PASS** `the-negotiated-suite-is-a-node` — no hop was evidenced
- **PASS** `the-network-half-is-the-cboms-walk-not-a-copy` — 0 hop(s) read by cbom_dependency.endpoint_hops

## `SBOM-18` — PASS

*the certificate's crypto is not the application's crypto* (guide 175, network)

- **PASS** `the-certificate-algorithm-stays-in-its-domain` — certificate ['ECDSA-P256'], application ['RSA-2048']
- **PASS** `the-application-still-has-its-own` — application ['RSA-2048']

## `SBOM-19` — PASS

*the SBOM is a projection of the canonical estate, not a second store* (guide 175, canonical)

- **PASS** `the-projection-reads-the-canonical-estate` — canonical CANONICAL_ESTATE, projection SBOM, second store False
- **PASS** `the-levels-are-the-canonical-levels` — 64 node(s) of 40 kind(s), 74 edge(s), 34 of them on the supply chain; projection of CANONICAL_ESTATE, one store

## `SBOM-20` — PASS

*two names for one asset resolve through evidence, never through the name* (guide 175, canonical)

- **PASS** `the-alias-resolves-to-one-canonical-asset` — Payments API: 4 record(s) joined by digest:sha256:8af92c1d4e5f60718293a4b5c6d7e8f9, digest:sha256:abc123def4567890abc123def4567890, namespace:payments
- **PASS** `the-join-is-an-anchor-not-a-string` — anchors ['digest:sha256:8af92c1d4e5f60718293a4b5c6d7e8f9', 'digest:sha256:abc123def4567890abc123def4567890']
- **PASS** `a-name-only-match-is-refused` — settlement → NAME_ONLY_IDENTITY

## `SBOM-21` — PASS

*four version layers disagree and the conflict is the finding* (guide 175, versions)

- **PASS** `the-conflict-code-is-named` — DEPENDENCY_VERSION_CONFLICT: ['3.0.11', '3.0.13']
- **PASS** `every-source-is-preserved` — DECLARED_VERSION=['3.0.13', '3.0.13'], IMAGE_VERSION=['3.0.13'], RUNTIME_VERSION=['3.0.11'], VENDOR_VERSION=['3.0.13']

## `SBOM-22` — PASS

*a dependency that moved keeps the version it had and the evidence for both* (guide 175, time)

- **PASS** `the-openssl-move-is-detected` — 1 change(s) on pkg:generic/openssl: declared 3.0.11 → 3.0.13
- **PASS** `both-evidence-ids-are-kept` — before EVID-96003, after EVID-96003
- **PASS** `the-same-projection-compared-with-itself-shows-nothing` — 0 component version(s) moved, 0 added, 0 removed

## `SBOM-23` — PASS

*a superseded dependency is kept, not deleted* (guide 175, time)

- **PASS** `the-lifecycle-names-its-states` — 9 dependency edge(s): FIRST_SEEN 1, ACTIVE 2, CHANGED 2, REMOVED 1, UNKNOWN 3
- **PASS** `nothing-was-deleted-to-produce-the-comparison` — 9 row(s) kept; superseded 0, removed 1

## `SBOM-24` — PASS

*a count is reported against what was inspected, never against the bank* (guide 175, honesty)

- **PASS** `the-denominator-is-printed` — 2 component(s) discovered; 75/100 application(s) inspected (75.0%); SBOM completeness: PARTIAL
- **PASS** `the-count-is-not-quotable-as-the-estate` — 2 component(s) discovered, quotable as total False
- **PASS** `coverage-that-exceeds-the-estate-is-refused` — 100 expected, 100+ reported → COVERAGE_EXCEEDS_EXPECTED

## `SBOM-25` — PASS

*a vulnerability walks to the component, the deployment and the business system* (guide 175, impact)

- **PASS** `the-component-is-named` — CVE-2026-0002: 3 component(s), 2 image(s), 2 deployment(s), 1 application(s), 1 business system(s) affected
- **PASS** `the-deployment-and-the-application-are-reached` — applications ['Payments API'], deployments ['payments-api-7d9f4c', 'payments-api-deploy']
- **PASS** `the-business-system-is-the-end-of-the-walk` — systems ['Payments System']

## `SBOM-26` — PASS

*an upgrade is counted after the walk, so the number is the systems it changes* (guide 175, impact)

- **PASS** `the-plan-names-the-applications-and-systems` — upgrade pkg:generic/openssl 3.0.13 → 3.0.14: affects 1 application(s), 1 business system(s), 2 image(s), 1 process(es); regression: FIPS module re-validation, payment signature regression
- **PASS** `the-images-and-processes-are-counted` — images ['layer:ubuntu-22.04-base', 'payments-api:4.2.1'], processes ['payments-api[1821]']
- **PASS** `the-regression-work-is-part-of-the-plan` — regression ['FIPS module re-validation', 'payment signature regression']

## `SBOM-27` — PASS

*the SBOM hands capability to the CBOM and never decides PQC readiness* (guide 175, pqc)

- **PASS** `the-sensitive-capabilities-are-listed` — pkg:generic/openssl: 2 quantum-sensitive capability(ies) and 1 observed use(s); the SBOM answers the first and the CBOM answers the second
- **PASS** `the-observed-usage-is-a-different-list` — capabilities ['ECDSA-P256', 'RSA-2048'], usage ['RSA-2048']
- **PASS** `the-handoff-carries-the-rule-not-a-decision` — the SBOM hands capability to the CBOM and never decides readiness: a listed RSA is a question a migration asks, an observed RSA-2048 is the candidate

## `SBOM-28` — PASS

*the whole chain assembles into one graph, level by level* (guide 175, graph)

- **PASS** `every-level-of-the-review-is-present` — system 1, application 3, repository 1, commit 1, build 1, artifact 8, image 4, deployment 4, pod 2, process 1, component 10, capability 9
- **PASS** `the-supply-relations-are-a-whitelist` — 34 supply relation(s) of 47 used
- **PASS** `the-graph-states-its-source` — 64 node(s) of 40 kind(s), 74 edge(s), 34 of them on the supply chain; projection of CANONICAL_ESTATE, one store

## What this does not prove

- the estate is a fixture: every shape is the review's, the rows are not
- a repository, a commit and a build are three claims from three systems; the guide proves they are joined, not that any of them was re-executed
- an SBOM lists what a scanner found; a component the scanner missed is absent from every level of the chain below the artifact
- direct and transitive are read off the graph: a manifest whose dependency was declared but never resolved shows as transitive and cannot be fixed from here
- a version conflict is preserved, not resolved: which version is right is a question for the team that owns the image
- identity resolution joins on digests, repositories and namespaces; two applications with no shared anchor stay two applications, by design
- coverage is arithmetic on what the collectors reported; it cannot see an application that was never scanned
