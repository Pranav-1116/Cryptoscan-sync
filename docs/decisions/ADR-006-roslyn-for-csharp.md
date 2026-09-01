# ADR-006 Roslyn for C#

## Status

Deferred. Regex parser is the Part 2 implementation.
**Updated 2026-08-31:** tree-sitter (`CRYPTOSCAN_TREE_SITTER=1`) now provides the optional deep-parse pass for C#; Roslyn (.NET SDK) remains out of scope.

## Context

logic-2.md recommended a .NET Roslyn scanner.

## Decision

Do **not** require a .NET SDK. `csharp_parser.py` matches
`System.Security.Cryptography` APIs with regular expressions.

## Consequences

No semantic flow (key size set on another line). Acceptable for Part 2.
