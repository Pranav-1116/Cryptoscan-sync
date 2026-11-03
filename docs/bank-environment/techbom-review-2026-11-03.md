# TechBOM review, 2026-11-03 — as received, and what this round does with it

This is the TechBOM review as it arrived, kept as the record of the argument rather than a
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
| 8 | Bridge from business to technical estate | hierarchy plus per-kind counts; the blast radius reports the owning system only when the containment is proven |
| 9 | TechBOM → CBOM with separate evidence types | `USES_CRYPTO` + `CRYPTO_EVIDENCE_BASIS`: RUNTIME_OBSERVED, STATIC_OBSERVED and CERTIFICATE_OBSERVED may not evidence each other |
| 10 | TechBOM → HBOM depth (container → host → VM → physical → TPM; HSM → firmware → capability) | `SCHEDULED_ON`/`HOSTED_ON`/`RUNS_ON`/`CARRIES`, `RUNS_FIRMWARE`/`SUPPORTS` |
| 11 | TechBOM → NBOM as a path, not a list | `EXPOSES`/`FRONTED_BY`/`FORWARDS_TO`/`ROUTES_TO`; blast radius reports the network edges it walked |
| 12 | TechBOM → VBOM and vendor firmware impact | `VENDOR_PRODUCT --SUPPLIED_BY--> VENDOR`, `HSM --RUNS_FIRMWARE--> FIRMWARE`; the radius names vendor/firmware sites as migration blockers |
| 13 | Certificate graph to issuer and key custodian | `PRESENTS`/`CONTAINS_KEY`/`USES_ALGORITHM`/`ISSUED_BY`/`KEY_HELD_BY` |
| 14 | Runtime deployment identity | `SOURCE→BUILD→ARTIFACT→SBOM→IMAGE→DEPLOYMENT→POD→PROCESS→LOADS` |
| 15 | Time: snapshots and typed change events | `diff()` — TECHNOLOGY_VERSION_CHANGED with both values, plus per-layer categories |
| 16 | Completeness with a denominator and a reason | `completeness()` — per-kind observed/expected/coverage, UNMEASURED when there is no denominator |
| 17 | TechBOM is not a second Digital Twin | `projection: true`, `source_of_truth: CANONICAL_ESTATE`; a TechBOM is refused as input |
| 18 | Cross-BOM reconciliation keeps CONFLICT | `reconcile()` — multiple values preserved, resolution UNRESOLVED, agreement is not verification |
| 19 | Blast radius | `blast_radius()` — dependents by kind, systems, network paths, crypto assets, blockers |
| 20 | TechBOM powers PQC migration | radius names HSM/firmware/vendor blockers and quantum-sensitive algorithms |
| 21 | TechBOM powers threat intelligence | available as context (asset ids, chains, confidence per edge); the threat engine's consumer is unchanged in this round |
| 22 | Security blockers: relationship poisoning | the basis ceiling is enforced in `claim()`; IMPORTED and VENDOR_DECLARED never become proven dependency paths |

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
- **Point 21 is context, not integration.** The threat engine keeps its own consumer; what
  changed is that a TechBOM can now hand it asset ids, chain names and per-edge confidence
  instead of a flat inventory. Wiring that consumer is a separate increment and is not
  claimed here.
