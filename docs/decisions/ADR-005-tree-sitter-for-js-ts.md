# ADR-005 tree-sitter for JS/TS

## Status

Deferred. Regex parser is the Part 2 implementation.
**Updated 2026-08-31:** tree-sitter shipped as an **opt-in deep parser** (`CRYPTOSCAN_TREE_SITTER=1`, `tree-sitter-scanner-v1.0`) for JS/TS and 8 further languages; the regex parser remains the default path and the RawFinding schema is unchanged.

## Context

logic-2.md recommended tree-sitter for JavaScript/TypeScript.

## Decision

Do **not** add tree-sitter as a hard dependency in Part 2. A regex parser
covers Node `crypto`, WebCrypto, crypto-js, jwt, and bcrypt well enough for
inventory.

## Consequences

Complex AST-aliased calls can be missed. A later part may add tree-sitter
without changing the RawFinding schema.
