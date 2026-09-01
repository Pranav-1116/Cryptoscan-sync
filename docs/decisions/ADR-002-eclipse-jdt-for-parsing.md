# ADR-002 Eclipse JDT for parsing

## Status

Accepted for Part 1 production path; regex fallback is the supported default.
**Updated 2026-08-31:** an opt-in tree-sitter CST parser (`CRYPTOSCAN_TREE_SITTER=1`, `tree-sitter-scanner-v1.0`) now also covers Java alongside the regex default; the JDT/JVM runtime remains out of scope.

## Context

Java cryptographic APIs are stringly typed (`Cipher.getInstance("AES/ECB/...")`).
A full AST is nicer, but shipping a JRE + JDT is heavy for local/dev.

## Decision

Keep JDT sources under `services/scanner/jdt/` and use a deterministic regex
parser as the default. `parse_java_file` stays a module-level function.

## Consequences

Some aliased or generated Java will be missed. That is an accepted Part 1/2
limitation.
