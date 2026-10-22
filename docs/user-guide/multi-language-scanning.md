# Multi-language scanning

Point a job at a repository that contains more than one language. CryptoScan
detects `.java`, `.py`, `.js`/`.ts`, and `.cs` files and runs every matching
parser in one scan.

Try the bundled sample:

```
local://<authorized-source>
```

Findings keep a `source.language` field. The dashboard Findings and Assets
views mix languages in one table. Java-only trees still report scanner id
`static-java-scanner-v0.1` so historical Part 1 scans stay comparable.

## Source file observation receipts — 2026-10-22

The scanner result schema includes `file_observation_receipts`,
`file_receipts_complete` (default **false**) and `file_receipts_scope` (default
**PRIMARY_DISCOVERED_SOURCE_FILES_ONLY**). These agree with the scanner model;
consumers must not infer completeness from an empty list or older/missing fields.
A positive receipt describes its observed primary discovered source file, not all
imports, dependencies, binaries, runtime paths or the bank's independently
expected target register. Preserve partial/refused/unknown evidence and compare
against that independent scope before an acceptance claim.

See [current implementation status](../CURRENT-IMPLEMENTATION-STATUS.md) and the
[scanner JSON schema](../../services/scanner/scanner/output/schema/scan_result_schema.json).
