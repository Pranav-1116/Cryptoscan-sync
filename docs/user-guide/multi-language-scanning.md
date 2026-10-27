# Multi-language scanning

Point a job at a repository that contains more than one language. CryptoScan
detects `.java`, `.py`, `.js`/`.ts`, and `.cs` files and runs every matching
parser in one scan.

Try the bundled sample:

```
local://demo/polyglot-app
```

Findings keep a `source.language` field. The dashboard Findings and Assets
views mix languages in one table. Java-only trees still report scanner id
`static-java-scanner-v0.1` so historical Part 1 scans stay comparable.
