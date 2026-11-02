# PQC readiness is not the CBOM, and a boolean is not a status

`cryptoscan.cbom-pqc-handoff-guide/1` · generated 2026-11-02T18:06:08.331947+00:00 · **5 pass · 0 partial · 0 fail** · 24 probes

The review's items 14 and 15. The CBOM chain the review asks for is:

```
CBOM (what cryptography exists)
  -> crypto inventory
  -> PQC engine (what needs migration, what depends on it, what blocks it)
  -> migration assessment
```

`quantumVulnerable: null` was the honest part of the old model — it refused to conclude. What it could never do was say **why**, or say *transitional*, or *hybrid*. `cbom.pqc_handoff` replaces it with the review's vocabulary:

| Status | Means |
|---|---|
| `NOT_ASSESSED` | no algorithm identity; no quantum claim |
| `CLASSICAL_ONLY` | no known quantum break, and not PQC |
| `TRANSITIONAL` | Grover weakens the margin (AES-128, SHA-256) |
| `QUANTUM_RESISTANT` | registry-recognised PQC |
| `HYBRID` | classical + PQC in one construction |
| `QUANTUM_SENSITIVE` | Shor breaks it |
| `UNKNOWN` | unrecognised algorithm; review required |

and keeps `algorithm_class`, `quantum_risk`, `migration_priority` and `migration_status` as separate fields, each with the basis that produced it.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `status_vocabulary` | can a status say what a boolean could not? | **PASS** | 6, 0 failing |
| `priority_from_evidence` | does migration priority follow risk and usage, not size of inventory? | **PASS** | 6, 0 failing |
| `the_seam` | does the document inventory while the engine decides? | **PASS** | 6, 0 failing |
| `conformance` | is the change a schema fix, not only a vocabulary change? | **PASS** | 3, 0 failing |
| `api_exposure` | can an operator ask what needs migrating, and why? | **PASS** | 3, 0 failing |

## `status_vocabulary` — PASS

*can a status say what a boolean could not?* (review 15)

- **PASS** `a-shor-vulnerable-key-is-quantum-sensitive` — RSA-2048: Shor breaks it, no boolean needed
- **PASS** `grover-impact-depends-on-size` — AES-128 is Grover-weakened; AES-256 keeps >=128 bits and is acceptable
- **PASS** `a-pqc-algorithm-is-resistant-and-a-hybrid-is-hybrid` — resistant and hybrid are different answers
- **PASS** `an-unregistered-algorithm-is-unknown-not-resistant` — resistance is never assumed from silence
- **PASS** `no-algorithm-is-not-assessed` — an asset with no algorithm produces no quantum claim
- **PASS** `classical-breakage-is-named-on-the-same-row` — a quantum status never hides a classical purge

## `priority_from_evidence` — PASS

*does migration priority follow risk and usage, not size of inventory?* (review 14 / 15)

- **PASS** `a-deployed-algorithm-outranks-a-capability` — capability MEDIUM vs runtime HIGH
- **PASS** `confidentiality-use-of-a-shor-vulnerable-key-is-immediate` — harvest-now-decrypt-later does not improve with waiting
- **PASS** `signature-use-is-not-an-hndl-escalation` — authenticity migration is a different register
- **PASS** `evidence-only-ever-escalates` — nothing in the handoff lowers a finding
- **PASS** `a-resistance-claim-needs-no-migration` — no work is invented for an algorithm already on the target
- **PASS** `the-replacement-is-specific-to-the-family` — a hash is not replaced by a cipher, and AES-128 by AES-256

## `the_seam` — PASS

*does the document inventory while the engine decides?* (review 14)

- **PASS** `the-document-carries-a-status-with-its-basis` — {"cryptoscan:algorithm_class": "PUBLIC_KEY", "cryptoscan:quantum_status": "QUANTUM_SENSITIVE", "cryptoscan:quantum_status_basis": "REGISTRY_SHOR"}
- **PASS** `the-document-does-not-carry-the-boolean` — the non-standard field is gone from the standard block
- **PASS** `a-document-without-usage-properties-is-unobserved` — a plain CycloneDX CBOM says nothing about deployment
- **PASS** `usage-properties-reach-the-handoff` — AES-256 observed in use still needs no PQC migration
- **PASS** `old-documents-are-read-not-ignored` — a pre-guide-144 document still yields a status
- **PASS** `a-boolean-is-only-derived-where-it-is-defensible` — Grover-weakened is not silently 'safe'

## `conformance` — PASS

*is the change a schema fix, not only a vocabulary change?* (review 15)

- **PASS** `the-xml-serializer-no-longer-writes-the-boolean` — CycloneDX 1.5 XML has no quantumVulnerable element
- **PASS** `the-1-5-json-builders-no-longer-write-it-either` — both 1.5 component builders emit namespaced properties instead
- **PASS** `the-readers-resolve-both-generations` — ingest and assessment do not depend on the field that was removed

## `api_exposure` — PASS

*can an operator ask what needs migrating, and why?* (review 14)

- **PASS** `the-handoff-route-exists-and-is-typed` — POST /cbom/pqc-handoff
- **PASS** `the-route-is-role-gated` — a migration register is not anonymous
- **PASS** `the-route-uses-the-module-and-accepts-a-document` — one implementation, usable straight from an uploaded CBOM

## What this does not prove

- status is classified from the algorithm registry, not from the deployment. A protocol negotiated with a PQC suite still reads as the suite it names, so 'the bank is hybrid on this TLS endpoint' needs the network evidence, not this module
- priority is a planning order, not a deadline. The platform's regulatory dates live in the quantum and banking registers; nothing here asserts one
- migration_status is caller-supplied and defaults to NOT_STARTED. The platform does not yet observe remediation, so a migrated asset keeps saying NOT_STARTED until an operator records it
- a hybrid asset is NONE priority because its classical half is covered by the PQC half. That is right for the negotiation and wrong for the component that still implements only X25519, which this seam cannot see
- the recommended replacement is the engine's answer for the algorithm family, not for this deployment: ML-KEM-768 may be unavailable in the HSM that holds the key, and that blocker is not modelled here
- the 1.6 path already refused quantumVulnerable; the 1.5 builders and the XML serializer were the ones that wrote it, and third-party documents may still carry it — the readers accept it, but its presence is a schema finding, not a credential of quality
