# Multi-language scanner design

`detect_languages_in_repo` + `scan_file` is the coordination layer:

1. Discover source files.
2. Dispatch by suffix (`.java`, `.py`, `.js`/`.ts`, `.cs`).
3. Catch parse errors per file (`safe_parse`) and continue.
4. Optionally scan `*.jar` for cryptographic API strings.
5. Attach Git context when the working tree is a repository.

Language-specific detectors under `scanner/detectors/{python,javascript,csharp,java}`
are thin filters over the parsers so individual libraries (hashlib, Node
`crypto`, `Aes.Create`, …) can be tested in isolation.

Hard dependencies on tree-sitter or Roslyn are intentionally avoided in Part 2.
