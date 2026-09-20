# Policy rules

YAML rule packs under this directory are loaded at engine start
(`policy/rules/rule_loader.py` globs `**/*.yaml` and skips anything whose
path starts with `_`). They are the source of truth for compliance — not
the AI layer.

The engine is deterministic: every rule evaluates the cryptographic
evidence record (algorithm / mode / key size / purpose / scope tags). It
never guesses from free text, and `NOT_EVALUATED`/`NOT_APPLICABLE` are never
reported as `PASS`.

## Packs

| Pack | Rules | Scope |
|------|-------|-------|
| `baseline/` | BASELINE-001…004 | Applies to all evidence (estate-wide floor) |
| `cnsa/` | CNSA-001…004 | `CNSA` scope tag |
| `fips/` | FIPS-001…003 | `FIPS` scope tag |
| `hipaa/` | HIPAA-001…002 | `HIPAA` / `PHI` scope tags |
| `nist/` | NIST-001…006 | `NIST` scope tag |
| `pci_dss/` | PCIDSS-001…006 | `PCI-DSS` / `PAN` scope tags |
| `uae/` | CBUAE-001…005, DIFC-001…002, PDPL-001…002, ADGM-001 | `CBUAE`, `PAYMENT`/`CARD`/`SWIFT`, `DIFC`/`PERSONAL_DATA`, `PDPL`, `ADGM` scope tags |

## UAE pack — grounding

Grounded in the published UAE regulatory instruments (see the
`standard_reference` field of each rule for the exact citation):

- **CBUAE** Cybersecurity Framework (9 domains) + Information Security
  Standards (ISO/IEC 27001-aligned) — all licensed financial institutions.
- **DIFC** Data Protection Law No. 5 of 2020 (in force 2020-07-01),
  Art. 23 technical measures (pseudonymisation, encryption); 72h breach
  notification statutory; private right of action since 2025-07.
- **ADGM** Data Protection Regulations 2021 (in force 2021-08-14),
  GDPR Art. 32-equivalent technical measures.
- **UAE Federal PDPL** Decree-Law No. 45 of 2021 (in force 2022-01-02),
  Art. 20 — encryption and pseudonymisation are named in the statute.

Scope lists are OR-activated by design (an evidence record matching any one
required tag is in scope), mirroring how `PAN` activates the PCI-DSS pack.
`CBUAE-001` has no scope: it is the estate-wide forbidden-algorithm floor.
The pack asserts **no** post-quantum mandate — none has been published by
UAE regulators to date; NIST IR 8547 timelines are the de-facto reference.

## Conventions

- `rule_id` is unique across all packs and is prefixed by the standard
  (`CBUAE-001`, `PCIDSS-001`, …).
- `condition.type` is one of the registered condition classes in
  `policy/conditions/` (`ALGORITHM_IN_LIST`, `COMPLEX`,
  `KEY_SIZE_MINIMUM`, …); `COMPLEX` supports `required_scopes`,
  `if_purpose`/`if_algorithms` (both yield `NOT_APPLICABLE` on mismatch),
  `forbidden_algorithms`, `require_algorithms`, `require_modes`,
  `min_key_size`.
- `remediation` must be actionable and specific — it is surfaced verbatim
  in reports and the action plan.

Add a new file, open a PR, and the next worker restart picks it up. The
canonical pack hash (`GET /policy/pack` → `pack_hash`) changes whenever any
rule changes — reports pin it for reproducibility.
