# CBOM → digital twin: one graph, three consumers

`cryptoscan.cbom-digital-twin-guide/1` · generated 2026-11-02T18:53:35.270515+00:00 · **5 pass · 0 partial · 0 fail** · 30 probes

Review item 20's architecture, implemented as a projection rather than a second inventory: the five evidence families feed one graph, the graph feeds the CBOM, and the twin is what three consumers read.

```
SBOM · STATIC · NETWORK · RUNTIME · HSM/KMS
                    ↓
               CRYPTO GRAPH → CBOM → DIGITAL TWIN
                    ↓
        DRIFT · PQC MIGRATION · THREAT INTELLIGENCE
```

bank-estate-2026-11: 15 twin node(s), 18 edge(s) from 5 of 5 evidence families. Claim levels in the twin: `CAPABILITY` 7, `IMPORTED` 0, `CONFIGURED` 1, `STATIC` 1, `NETWORK` 1, `RUNTIME` 5.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `one_graph` | does every evidence family connect into one graph? | **PASS** | 7, 0 failing |
| `no_upgrade` | can a projection or a consumer upgrade a claim? | **PASS** | 7, 0 failing |
| `drift` | what changed against policy, and what does that prove? | **PASS** | 5, 0 failing |
| `pqc_queue` | which crypto has to migrate, and how firmly is that known? | **PASS** | 5, 0 failing |
| `threat_intel` | which advisory touches code that is actually running? | **PASS** | 6, 0 failing |

## `one_graph` — PASS

*does every evidence family connect into one graph?* (review 20 / graph)

- **PASS** `all-five-evidence-families-reach-the-twin` — {"kms": 1, "network": 2, "runtime": 5, "sbom": 1, "static": 1}
- **PASS** `a-family-with-no-evidence-is-named-not-assumed` — bank-estate-2026-11: 13 twin node(s), 15 edge(s) from 4 of 5 evidence families; no evidence yet from network
- **PASS** `no-edge-dangles-so-the-graph-can-be-walked` — 18 edge(s), 0 dangling
- **PASS** `every-edge-carries-the-evidence-that-drew-it` — 18 edge(s) with evidence ids
- **PASS** `the-twin-is-projected-from-the-document-not-rebuilt` — cryptoscan.cbom-estate-chain/1
- **PASS** `a-declared-and-an-observed-value-are-resolved-by-precedence` — the version disagreement is precedence, not a conflict
- **PASS** `two-observers-disagreeing-survive-as-a-conflict-edge` — cipher_suite has two observed values and both are kept

## `no_upgrade` — PASS

*can a projection or a consumer upgrade a claim?* (review 20 / claims)

- **PASS** `a-library-is-a-capability-whatever-its-algorithms-do` — component:openssl: CAPABILITY
- **PASS** `an-algorithm-only-a-library-lists-stays-a-capability` — AES-192-CBC is declared by ['openssl'] and used by nothing
- **PASS** `a-source-tree-call-is-static-evidence-and-says-so` — AES-128-CBC STATIC from ['STATIC_OBSERVED']
- **PASS** `an-observed-algorithm-inherits-runtime-from-its-strongest-evidence` — RUNTIME from ['NETWORK_OBSERVED', 'RUNTIME_OBSERVED']
- **PASS** `a-key-is-configured-and-never-observed` — CONFIGURED, private_material=NOT STORED
- **PASS** `no-consumer-claims-more-than-the-node-it-read` — no consumer claims more than the node it read
- **PASS** `a-candidate-algorithm-never-reaches-a-consumer-report` — drift rows: AES-128-CBC, SHA-1

## `drift` — PASS

*what changed against policy, and what does that prove?* (review 20 / drift)

- **PASS** `an-algorithm-outside-policy-is-unattributed-not-silent` — AES-256-GCM is observed in use and no policy row mentions it
- **PASS** `a-policy-row-nobody-observed-is-not-called-drift` — policy lists this algorithm and nothing was observed using it; that is not evidence that
- **PASS** `a-forbidden-algorithm-seen-running-is-drift` — 2 drift finding(s) against 2 policy row(s): 1 unattributed, 1 unexpected use; a policy row nobody observed is reported as not observed, not as drift
- **PASS** `the-wrong-parameter-is-parameter-drift` — {'PARAMETER_DRIFT': 1, 'UNATTRIBUTED': 1}
- **PASS** `a-drift-finding-cites-the-evidence-on-both-counts` — every observed-side finding carries its evidence ids

## `pqc_queue` — PASS

*which crypto has to migrate, and how firmly is that known?* (review 20 / migration)

- **PASS** `an-observed-rsa-operation-is-immediate-migration` — RSA-2048 IMMEDIATE
- **PASS** `the-quantum-verdict-comes-from-the-registry-not-the-document` — {"AES-128-CBC": "REGISTRY_GROVER", "AES-256-GCM": "REGISTRY_GROVER_ACCEPTABLE_MARGIN", "RSA-2048": "REGISTRY_SHOR"}
- **PASS** `the-queue-is-ordered-by-urgency` — IMMEDIATE, LOW, NONE
- **PASS** `a-capability-only-estate-cannot-lead-with-immediate` — 2 algorithm(s) in the migration queue; nothing at IMMEDIATE priority; every verdict comes from the registry, never from the document
- **PASS** `each-row-keeps-the-claim-level-it-was-built-from` — RSA-2048 from RUNTIME evidence

## `threat_intel` — PASS

*which advisory touches code that is actually running?* (review 20 / threat)

- **PASS** `a-provider-a-process-loaded-is-executing-exposure` — a process has it loaded
- **PASS** `an-installed-component-is-present-not-executing` — installed, with nothing saying it is loaded
- **PASS** `a-component-with-no-version-is-neither-confirmed-nor-cleared` — the component is known and its version is not, so the advisory can be neither confirmed nor cleared
- **PASS** `an-advisory-for-something-absent-is-not-exposure` — 1 advisory match(es) over 1 advisory(ies): 1 not present; installed and running are different exposures
- **PASS** `a-capability-algorithm-is-never-an-exposure-on-its-own` — a supported-but-unused algorithm is not a running exposure
- **PASS** `the-report-keeps-installed-and-running-apart` — 3 advisory match(es) over 2 advisory(ies): 1 executing, 1 not present, 1 present; installed and running are different exposures

## The three consumers on the sample estate

bank-estate-2026-11: 15 node(s), 18 edge(s); drift clean=True, advisories exposed=2

| consumer | answer |
|---|---|
| drift | {"POLICY_NOT_OBSERVED": 1, "UNATTRIBUTED": 1} |
| PQC migration | {"IMMEDIATE": 1, "MONITOR": 0, "NEAR_TERM": 0, "PLANNED": 0} |
| threat intelligence | {"EXECUTING": 1, "NOT_PRESENT": 1, "PRESENT": 1} |

## Claim levels

| level | what it means |
|---|---|
| `CAPABILITY` | a library lists the algorithm; nothing used it |
| `IMPORTED` | a document or a vendor says so; nobody verified it |
| `CONFIGURED` | a key or setting exists in a store |
| `STATIC` | the source tree contains a call |
| `NETWORK` | an endpoint negotiated it |
| `RUNTIME` | a process performed it |

A consumer inherits the level of the node it read and may never exceed it. That is the check `no_upgrade` runs over every consumer row.

## What this does not prove

- the twin is a projection of the document and the evidence set behind it. Anything the collectors never saw is absent from the graph, not marked as unknown — the coverage block says how much was inspected, and that is the honest bound on the twin
- drift compares an observed algorithm with a policy row. It has no opinion about policy that does not exist yet: an algorithm seen in use with no policy row is reported as unattributed, not as drift
- the PQC queue orders what the twin *observed*. An estate that has not been traced yet produces a queue of capabilities, and every row says so
- threat intelligence matches advisories against component names and versions. It does not read CVE text, so a name mismatch (libcrypto vs openssl) is a miss, not a judgement
- a version range is read as numeric dotted parts. Vendors with their own versioning (or backported patches) need their fix to be expressed as a minimum version, and a backport is invisible here
- the three consumers are read-only by construction. Acting on them — quarantining a key, opening a migration ticket — happens outside the twin, where the claim level travels with the request
