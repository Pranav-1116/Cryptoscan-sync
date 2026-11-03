# Live collection: payloads, transports and the chain they build

`cryptoscan.sbom-live-guide/1` · generated 2026-11-03T10:44:41Z · **16 pass · 0 partial · 0 fail** · 48 probes

**16 of 16 points of live collection hold, across 48 probes; 28 row(s) from 10 transport(s), 6 refusal(s), 30 asset(s) in the chain**

```
payload → collector → inventory → estate → chain
BUSINESS SYSTEM → APPLICATION → REPOSITORY → COMMIT → BUILD → ARTIFACT
    → IMAGE → DEPLOYMENT → POD / HOST → PROCESS → COMPONENT → CAPABILITY
```

| Transport | Basis | Class | Rows | Freshness |
|---|---|---|---|---|
| `ci` | `api-poll` | `CONFIGURED` | artifacts 1, builds 1 | ci: read 2.0h ago, LIVE |
| `cmdb` | `cmdb-import` | `IMPORTED` | applications 3 | cmdb: read 2.0h ago, LIVE |
| `git` | `api-poll` | `CONFIGURED` | commits 1, repositories 1 | git: read 2.0h ago, LIVE |
| `host` | `agent-inventory` | `CONFIGURED` | hosts 1, software 2 | host: read 2.0h ago, LIVE |
| `kubernetes` | `deployment-metadata` | `CONFIGURED` | deployments 1 | kubernetes: read 2.0h ago, LIVE |
| `process` | `process-trace` | `OBSERVED` | crypto 2, processes 1, software 2 | process: read 0.0h ago, LIVE |
| `registry` | `api-poll` | `CONFIGURED` | images 1, layers 1 | registry: read 2.0h ago, LIVE |
| `sbom` | `sbom-import` | `IMPORTED` | dependencies 2, sboms 1, software 3 | sbom: read 2.0h ago, LIVE |
| `scan` | `binary-scan` | `STATIC_OBSERVED` | images 1, software 3 | scan: read 2.0h ago, LIVE |

| Level | Nodes |
|---|---|
| `system` | 1 |
| `application` | 3 |
| `repository` | 1 |
| `commit` | 1 |
| `build` | 1 |
| `artifact` | 2 |
| `image` | 2 |
| `deployment` | 4 |
| `pod` | 2 |
| `process` | 1 |
| `component` | 5 |
| `capability` | 4 |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `LIVE-01` | a repository and a commit are read from the git host's own answer | **PASS** | 3, 0 failing |
| `LIVE-02` | a build names its commit and an artifact anchors on its digest | **PASS** | 3, 0 failing |
| `LIVE-03` | the registry's digest is the identity and the tag is recorded beside it | **PASS** | 3, 0 failing |
| `LIVE-04` | a scanner says what is installed in a digest, one class above the SBOM | **PASS** | 3, 0 failing |
| `LIVE-05` | a Deployment is metadata, and it stops at the pod | **PASS** | 3, 0 failing |
| `LIVE-06` | a trace is the only transport that may say OBSERVED | **PASS** | 3, 0 failing |
| `LIVE-07` | an SBOM imports components at IMPORTED and refuses a range | **PASS** | 3, 0 failing |
| `LIVE-08` | an agent's inventory is a filesystem fact on a named host | **PASS** | 3, 0 failing |
| `LIVE-09` | no transport claims a class stronger than it can support | **PASS** | 3, 0 failing |
| `LIVE-10` | two transports describing one component are merged, not duplicated | **PASS** | 3, 0 failing |
| `LIVE-11` | a disagreement between two reads is a finding, not an overwrite | **PASS** | 3, 0 failing |
| `LIVE-12` | a stale read is imported and labelled, never called live | **PASS** | 3, 0 failing |
| `LIVE-13` | the payloads assemble into every level of the twelve-level chain | **PASS** | 3, 0 failing |
| `LIVE-14` | the chain answers the questions it exists for, from live rows | **PASS** | 3, 0 failing |
| `LIVE-15` | installed, loaded and used stay apart, and directness keeps its path | **PASS** | 3, 0 failing |
| `LIVE-16` | a refused row never becomes an asset, and the refusals are published | **PASS** | 3, 0 failing |

## What was refused while collecting

- `git` — main: a commit is named by its sha; a branch or tag name points at a commit that will not be the same commit tomorrow (`MUTABLE_IDENTITY`)
- `ci` — payments-api.jar: the pipeline reports a name and no digest: a jar called payments-api.jar is overwritten on the next build, so it cannot anchor an SBOM (`ARTIFACT_WITHOUT_DIGEST`)
- `kubernetes` — ghost-deploy: the Deployment names no image, so nothing in it can reach a component (`DEPLOYMENT_WITHOUT_IMAGE`)
- `sbom` — left-pad: the component carries ^1.3.0; a range is a manifest declaration and an SBOM that cannot say which version is in the artifact answers nothing (`UNPINNED_VERSION`)
- `sbom` — mystery: the component carries no version; a range is a manifest declaration and an SBOM that cannot say which version is in the artifact answers nothing (`UNPINNED_VERSION`)
- `spreadsheet` — spreadsheet: spreadsheet has no collector; the payload is not read and the inventory is missing a transport (`UNKNOWN_TRANSPORT`)

## Where two reads disagreed

- `payments-api:4.2.1` digest: kept `sha256:8af92c1d4e5f60718293a4b5c6d7e8f9` (registry), also reported `sha256:99999999aaaabbbbccccddddeeeeffff` (registry)

## `LIVE-01` — PASS

*a repository and a commit are read from the git host's own answer* (guide 177, source)

- **PASS** `the-repository-row-carries-its-name` — git:bank/payments-api
- **PASS** `the-commit-is-identified-by-its-sha` — git:bank/payments-api@a81f92c
- **PASS** `a-branch-name-is-not-an-identity` — a commit is named by its sha; a branch or tag name points at a commit that will not be the same commit tomorrow

## `LIVE-02` — PASS

*a build names its commit and an artifact anchors on its digest* (guide 177, build)

- **PASS** `the-build-names-the-commit` — ci:BUILD-18291
- **PASS** `the-artifact-carries-a-digest` — payments-api-4.2.1.jar
- **PASS** `an-artifact-with-only-a-name-is-refused` — the pipeline reports a name and no digest: a jar called payments-api.jar is overwritten on the next build, so it cannot anchor an SBOM

## `LIVE-03` — PASS

*the registry's digest is the identity and the tag is recorded beside it* (guide 177, image)

- **PASS** `the-image-is-anchored-on-its-digest` — oci:payments-api@sha256:8af92c1d4e5f60718293a4b5c6d7e8f9
- **PASS** `the-tag-is-kept-as-a-pointer-not-an-identity` — payments-api:4.2.1
- **PASS** `a-registry-that-returns-only-a-tag-is-refused` — IMAGE_WITHOUT_DIGEST

## `LIVE-04` — PASS

*a scanner says what is installed in a digest, one class above the SBOM* (guide 177, image)

- **PASS** `the-scan-lists-the-packages-it-found` — pkg:generic/openssl, pkg:generic/payments-sdk, pkg:generic/http-core
- **PASS** `the-scan-is-STATIC_OBSERVED` — class STATIC_OBSERVED
- **PASS** `the-image-row-names-what-is-installed` — ['pkg:generic/openssl', 'pkg:generic/payments-sdk', 'pkg:generic/http-core']

## `LIVE-05` — PASS

*a Deployment is metadata, and it stops at the pod* (guide 177, deployment)

- **PASS** `the-deployment-names-its-image-and-pods` — k8s:prod-cluster/payments/payments-api-deploy
- **PASS** `the-class-is-CONFIGURED-not-OBSERVED` — class CONFIGURED
- **PASS** `a-deployment-with-no-image-is-refused` — the Deployment names no image, so nothing in it can reach a component

## `LIVE-06` — PASS

*a trace is the only transport that may say OBSERVED* (guide 177, runtime)

- **PASS** `the-probe-is-OBSERVED` — class OBSERVED
- **PASS** `the-loaded-object-names-the-package-that-ships-it` — ['pkg:generic/openssl', 'pkg:generic/openssl']
- **PASS** `the-runtime-version-is-kept-as-a-runtime-source` — [{'source': 'process-map', 'value': '3.0.11', 'class': 'RUNTIME_OBSERVED', 'evidence_id': 'probe:node-03:1821'}]

## `LIVE-07` — PASS

*an SBOM imports components at IMPORTED and refuses a range* (guide 177, component)

- **PASS** `the-pinned-components-arrive` — pkg:generic/openssl, pkg:generic/payments-sdk, pkg:generic/http-core
- **PASS** `a-range-is-refused-as-a-version` — the component carries ^1.3.0; a range is a manifest declaration and an SBOM that cannot say which version is in the artifact answers nothing
- **PASS** `the-dependency-edges-travel-with-the-components` — [('pkg:generic/payments-sdk', 'pkg:generic/http-core'), ('pkg:generic/http-core', 'pkg:generic/openssl')]

## `LIVE-08` — PASS

*an agent's inventory is a filesystem fact on a named host* (guide 177, host)

- **PASS** `the-host-is-named` — host:srv-lb-01
- **PASS** `the-host-says-what-it-holds` — ['pkg:generic/openssl-dev', 'pkg:generic/nginx']
- **PASS** `an-inventory-with-no-host-is-refused` — NO_IDENTITY

## `LIVE-09` — PASS

*no transport claims a class stronger than it can support* (guide 177, evidence)

- **PASS** `only-the-probe-is-OBSERVED` — ['process']
- **PASS** `every-collector-states-its-basis` — ci api-poll, cmdb cmdb-import, git api-poll, host agent-inventory, kubernetes deployment-metadata, process process-trace, registry api-poll, sbom sbom-import, scan binary-scan
- **PASS** `an-unknown-transport-is-refused-by-name` — spreadsheet has no collector; the payload is not read and the inventory is missing a transport

## `LIVE-10` — PASS

*two transports describing one component are merged, not duplicated* (guide 177, merge)

- **PASS** `openssl-is-one-row-with-two-version-sources` — [[{'source': 'image-scan', 'value': '3.0.13', 'class': 'STATIC_OBSERVED', 'evidence_id': 'scan:payments-api:4.2.1@sha256:8af92c1d4e5f60718293a4b5c6d7e8f9'}, {'source': 'process-map', 'value': '3.0.11', 'class': 'RUNTIME_OBSERVED', 'evidence_id': 'probe:node-03:1821'}, {'source': 'sbom', 'value': '3.0.13', 'class': 'IMPORTED', 'evidence_id': 'sbom:SBOM-18291#pkg:generic/openssl'}]]
- **PASS** `the-observations-are-all-kept` — [('image-scan', '3.0.13'), ('process-map', '3.0.11'), ('sbom', '3.0.13')]
- **PASS** `the-merge-states-what-it-read` — 28 row(s) from 10 transport(s); 6 refusal(s); 1 stale transport(s): spreadsheet

## `LIVE-11` — PASS

*a disagreement between two reads is a finding, not an overwrite* (guide 177, merge)

- **PASS** `the-disagreement-is-recorded` — 1 row(s) from 1 transport(s); 1 disagreement(s) kept
- **PASS** `neither-read-wins` — sha256:8af92c1d4e5f60718293a4b5c6d7e8f9 vs sha256:99999999aaaabbbbccccddddeeeeffff
- **PASS** `only-one-row-survives-into-the-inventory` — 1

## `LIVE-12` — PASS

*a stale read is imported and labelled, never called live* (guide 177, freshness)

- **PASS** `a-read-this-morning-is-live` — git: read 2.0h ago, LIVE
- **PASS** `a-read-last-week-is-stale` — git: read 242.0h ago, STALE
- **PASS** `the-stale-rows-are-still-imported` — 2 row(s) from 1 transport(s); 2 refusal(s); 1 stale transport(s): git

## `LIVE-13` — PASS

*the payloads assemble into every level of the twelve-level chain* (guide 177, chain)

- **PASS** `every-level-is-populated` — system 1, application 3, repository 1, commit 1, build 1, artifact 2, image 2, deployment 4, pod 2, process 1, component 5, capability 4
- **PASS** `the-chain-builds-without-a-refusal` — 0 refusal(s)
- **PASS** `the-projection-says-where-it-came-from` — CANONICAL_ESTATE / live:production

## `LIVE-14` — PASS

*the chain answers the questions it exists for, from live rows* (guide 177, chain)

- **PASS** `provenance-reaches-the-commit-and-the-build` — payments-api-4.2.1.jar: bank/payments-api → a81f92c → BUILD-18291 → SBOM-18291
- **PASS** `the-component-names-the-application-that-owns-it` — pkg:generic/openssl: owned by Payments API
- **PASS** `two-transports-produce-a-version-conflict-not-a-winner` — pkg:generic/openssl: DECLARED_VERSION=3.0.13, IMAGE_VERSION=3.0.13, RUNTIME_VERSION=3.0.11, VENDOR_VERSION=— — 2 versions, preserved

## `LIVE-15` — PASS

*installed, loaded and used stay apart, and directness keeps its path* (guide 177, chain)

- **PASS** `the-component-is-installed-and-loaded` — pkg:generic/openssl: SBOM_PRESENT, INSTALLED, LOADED; not CONFIGURED, STATIC_REFERENCED, RUNTIME_USED
- **PASS** `the-component-reaches-its-deployment` — pkg:generic/openssl: EXISTS=yes, INSTALLED=yes, DEPLOYED=yes, RUNNING=yes, LOADED=yes
- **PASS** `the-transitive-path-is-printed` — Payments API: 1 direct, 2 transitive, 0 listed only; pkg:generic/http-core, pkg:generic/openssl reached through another component

## `LIVE-16` — PASS

*a refused row never becomes an asset, and the refusals are published* (guide 177, honesty)

- **PASS** `the-refused-artifact-is-not-in-the-chain` — payments-api.jar absent
- **PASS** `the-unpinned-component-is-not-in-the-chain` — left-pad and mystery absent
- **PASS** `every-refusal-names-its-transport` — 6 refusal(s) across 5 transport(s)

## What this does not prove

- the payloads are recorded answers from each system, not live calls: the collectors are proven against the shapes those systems return, not against a running estate
- a collector reads one answer at one moment; nothing here polls, retries or reconciles a partial read, and freshness is the only statement about age
- the class ceiling is stated per transport, so a collector cannot claim more than its transport — but a transport that lies is a trust question, not a code one
- an SBOM's declared version and a probe's runtime version are two rows: the chain keeps the conflict and does not decide which one the bank is running
