# Normalization Rule Definitions

Detection rule catalog for the normalization service. YAML files here are
compiled into the in-memory `RuleRegistry` at service start
(`normalization.rules.rule_loader.RuleLoader` → `rule_validator` → `rule_registry`)
and map raw scanner findings onto normalized, policy-grade descriptors.

## Layout

```
rule_definitions/
├── asymmetric/    # RSA, ECDSA
├── hashing/       # MD5, SHA-1, SHA-2
├── signature/     # signature combos (e.g. SHA256withRSA)
└── symmetric/     # 3DES, AES, DES
```

Files are discovered recursively (`*.yaml`, multi-document streams supported;
files starting with `_` are skipped).

## Rule shape

```yaml
---
rule_id: "NORM-MD5"                 # unique — registry rejects duplicates
version: "1.0"
description: "MD5 — cryptographically broken"
raw_patterns:                       # exact-match aliases from the scanner
  - "MD5"
  - "MD5withRSA"
  - "1.2.840.113549.2.5"
normalized_output:                  # copied onto the NormalizedFinding
  algorithm: "MD5"                  # REQUIRED — rule is dropped without it
  algorithm_family: "hash"
  standard_name: "MD5"
  output_bits: 128
  purpose: "hashing"
  nist_designation: "DISALLOWED"
  nist_reference: "NIST SP 800-131A Rev 2"
  quantum_vulnerable: true
  pqc_replacement: null
  iana_id: "md5"
  cbom_component_type: "cryptographic-asset"
```

Loader specifics (`rule_loader.py`):

- A document may be a single rule or a mapping with a top-level `rules:` list.
- `raw_patterns` (or legacy `pattern`) are matched exactly against the raw
  finding's algorithm string; a pattern already owned by another `rule_id`
  raises on registration — patterns are globally unique.
- `normalized_output` (or legacy `output`) **must** contain `algorithm`.

## Adding a rule

1. Pick an unused `rule_id` (`NORM-<ALGO>[-<VARIANT>]`) and place the file in
   the matching family directory.
2. List every raw alias the scanner can emit (see `services/scanner` detectors)
   under `raw_patterns` — unknown aliases fall through unmatched.
3. Fill `normalized_output` completely; `nist_designation`, `quantum_vulnerable`
   and `pqc_replacement` drive policy and CBOM generation.
4. Run the normalization suite:

   ```bash
   cd services/normalization && pytest
   ```

5. Commit the rule together with a test that pins the new mapping.

## Rules of thumb

- One file per algorithm family; one YAML document per rule variant
  (e.g. `NORM-RSA-2048`, `NORM-RSA-4096`).
- Keep `rule_id`s immutable once released — CBOM evidence references them.
- OIDs (e.g. `1.2.840.113549.2.5`) make good patterns: they are unambiguous
  across languages and libraries.
- Never encode environment policy ("allowed in tests") here; that belongs in
  `services/policy` policy packs.
