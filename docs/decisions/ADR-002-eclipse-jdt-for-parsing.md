# ADR-002 Eclipse JDT for parsing

## Status

Accepted for Part 1 production path; regex fallback is the supported default.

## Context

Java cryptographic APIs are stringly typed (`Cipher.getInstance("AES/ECB/...")`).
A full AST is nicer, but shipping a JRE + JDT is heavy for local/dev.

## Decision

Keep JDT sources under `services/scanner/jdt/` and use a deterministic regex
parser as the default. `parse_java_file` stays a module-level function.

## Consequences

Some aliased or generated Java will be missed. That is an accepted Part 1/2
limitation.
