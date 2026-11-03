# TechBOM review, 2026-11-03 — as received, and what this round does with it

Guide 165 (`docs/bank-environment/165-techbom-answers.md`, `cbom.techbom_queries`) closes
the questions the first pass left open: roll-up, request paths, impact vocabulary, the
timeline, threat context and claim promotion. This is the TechBOM review as it arrived, kept as the record of the argument rather than a
summary of the answer. Guide 164 (`docs/bank-environment/164-techbom.md`,
`cbom.techbom`) is the implementation. The table below is ownership, not approval: where a
point was already built elsewhere, it says where.

## The line the review draws

```
                EVIDENCE
                   │
                   ▼
          CANONICAL ESTATE / DIGITAL TWIN
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
      SBOM       CBOM       HBOM
        │          │          │
      NBOM       VBOM     CERTIFICATES
        └──────────┼──────────┘
                   ▼
                TECHBOM          ← a projection, never a source
```

A TechBOM answers *what technology exists, where it is, how it is connected, who owns it,
what cryptography it depends on, and what evidence proves each relationship* — it is not
`SBOM + CBOM + HBOM + NBOM + VBOM` in one JSON file. That distinction is the whole review,
and guide 164 makes it enforceable rather than aspirational: `build()` takes a
`cryptoscan.techbom-estate/1` document, `from_document()` refuses a TechBOM, and every
edge carries a basis, a confidence class and an evidence id.

## Point by point

| # | Point | Where it lives now |
|---|---|---|
| 1 | TechBOM is not concatenation | guide 164 — a graph of typed assets and claims; the layers are inputs, not sections |
| 2 | SBOM/CBOM/HBOM/vendor are layers of one estate | already built: `cbom.technology_bom` (materializer), `routers/techbom.py` |
| 3 | The work is correlation, not more scanners | `cbom.techbom.build` — seven chains over the assets the collectors already produce |
| 4 | Explicit relationship set (`SYSTEM→…→CRYPTO_ASSET`, network path, HSM, vendor) | guide 164, 26 relations in `RELATIONS`, each bounded by allowed kinds |
| 5 | No relationships from co-occurrence; OBSERVED/CONFIGURED/IMPORTED/VENDOR_DECLARED/INFERRED/UNKNOWN | `BASES` + `NOT_A_BASIS`; a proximity basis is refused by name (`CO_OCCURRENCE_NOT_EVIDENCE`) |
| 6 | Stable asset ids and an asset model | `asset()` with `key` (content-addressed, durable) and `id` (`TECH-APP-001`, readable, renumbers) |
| 7 | System/application hierarchy; Payments is a business system, not a scan target | `BUSINESS_SYSTEM --CONTAINS--> APPLICATION`; a system is an asset with an owner, never a scan |
| 8 | Bridge from business to technical estate | hierarchy plus per-kind counts; **guide 165** `rollup()` — a system's technology by kind, criticality, proven vs declared |
| 9 | TechBOM → CBOM with separate evidence types | `USES_CRYPTO` + `CRYPTO_EVIDENCE_BASIS`: RUNTIME_OBSERVED, STATIC_OBSERVED and CERTIFICATE_OBSERVED may not evidence each other |
| 10 | TechBOM → HBOM depth (container → host → VM → physical → TPM; HSM → firmware → capability) | `SCHEDULED_ON`/`HOSTED_ON`/`RUNS_ON`/`CARRIES`, `RUNS_FIRMWARE`/`SUPPORTS` |
| 11 | TechBOM → NBOM as a path, not a list | **guide 165** `path()` — WAF and service mesh added to the chain, each hop carrying TLS version, cipher, certificate, SNI, ALPN and mTLS |
| 12 | TechBOM → VBOM and vendor firmware impact | `HAS_MODEL`/`SUPPLIED_BY`/`RUNS_FIRMWARE`; **guide 165** `impact()` names firmware and HSM sites as typed blockers |
| 13 | Certificate graph to issuer and key custodian | `PRESENTS`/`CONTAINS_KEY`/`USES_ALGORITHM`/`ISSUED_BY`/`KEY_HELD_BY` |
| 14 | Runtime deployment identity | `SOURCE→BUILD→ARTIFACT→SBOM→IMAGE→DEPLOYMENT→POD→PROCESS→LOADS` |
| 15 | Time: snapshots and typed change events | `diff()` plus **guide 165** `timeline()` — N snapshots in the review's nine categories, with "one snapshot is a state" stated |
| 16 | Completeness with a denominator and a reason | `completeness()` — per-kind observed/expected/coverage, UNMEASURED when there is no denominator |
| 17 | TechBOM is not a second Digital Twin | `projection: true`, `source_of_truth: CANONICAL_ESTATE`; a TechBOM is refused as input |
| 18 | Cross-BOM reconciliation keeps CONFLICT | `reconcile()` — multiple values preserved, resolution UNRESOLVED, agreement is not verification |
| 19 | Blast radius | `blast_radius()` and **guide 165** `impact()` — applications, systems, certificates, HSMs, vendors, network paths, critical and legacy, blockers |
| 20 | TechBOM powers PQC migration | **guide 165** `impact()` — blockers typed by who acts (HSM capability, firmware upgrade, certificate lifecycle, unknown legacy application), requirement-driven |
| 21 | TechBOM powers threat intelligence | **guide 165** `threat_context()` + `POST /cbom/techbom/context` — event → CORRELATED_PATTERN with system, technology, change and evidence, or a 422 |
| 22 | Security blockers: relationship poisoning | the basis ceiling is enforced in `claim()`; IMPORTED and VENDOR_DECLARED never become proven paths; **guide 165** `verify()` promotes only on new evidence, keeping the old class in history |

## Scope decisions taken here

- **The blast radius is deliberately conservative.** A path is *proven* only when every edge
  on it is OBSERVED or CONFIGURED. A vendor datasheet, a CMDB import and an inference are
  walked and reported as `possible`, because "the vendor says this firmware is in the HSM"
  is not the same statement as "the HSM reported its firmware". The consequence is visible
  in the guide's own fixture: an algorithm reaches the application through configuration and
  captures, and stops there, because the containment that would name the business system is
  a CMDB import.
- **Ids are two-part.** `TECH-APP-001` is what an operator quotes; `key` is what survives
  renumbering. Only `key` may be used as a durable reference, and `id` cannot be relied on
  across snapshots.
- **No new collectors.** Point 3 says the work is correlation, and this round added none:
  the estate is a fixture, and every asset in it is the shape a real collector would emit.
- **Point 21 is wired at the API, not inside the threat engine.** `POST
  /cbom/techbom/context` takes an event and returns the correlated pattern with the estate
  behind it, which is the handover an engine consumer needs. The threat engine's own
  ingestion is unchanged, so this is a route a consumer can call rather than a change to
  how it calls.
