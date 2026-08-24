# Scanner design

The public API is `Scanner.scan(...) → ScanResult`.

## Languages

| Language   | Parser                         | Scanner id                     |
|------------|--------------------------------|--------------------------------|
| Java       | regex + optional JDT fallback  | `static-java-scanner-v0.1`     |
| Python     | stdlib `ast`                   | `static-python-scanner-v1.0`   |
| JS / TS    | regex (no tree-sitter)         | `static-js-scanner-v1.0`       |
| C#         | regex (no Roslyn)              | `static-csharp-scanner-v1.0`   |
| JAR        | zip string match               | `static-jar-string-scanner-v0.1` |

Java-only repositories keep the original scanner id so Part 1 seed scans stay
stable.

## Discovery

`FileDiscovery` walks a tree, skipping VCS / build / virtualenv directories.
`detect_languages_in_repo` looks at extensions and marker files (`pom.xml`,
`package.json`, `.csproj`, …).

## Output

Every detector produces the same `RawFinding` schema (`source`, `crypto`,
`metadata`, optional `git_context`). The evidence pipeline hashes that object
and does not care which language produced it.

Eclipse JDT sources still live under `services/scanner/jdt/` for a later
production parser. They are not a hard dependency.
