# ADR-005 tree-sitter for JS/TS

## Status

Deferred. Regex parser is the Part 2 implementation.

## Context

logic-2.md recommended tree-sitter for JavaScript/TypeScript.

## Decision

Do **not** add tree-sitter as a hard dependency in Part 2. A regex parser
covers Node `crypto`, WebCrypto, crypto-js, jwt, and bcrypt well enough for
inventory.

## Consequences

Complex AST-aliased calls can be missed. A later part may add tree-sitter
without changing the RawFinding schema.
