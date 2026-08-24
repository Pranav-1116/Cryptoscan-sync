# ADR-006 Roslyn for C#

## Status

Deferred. Regex parser is the Part 2 implementation.

## Context

logic-2.md recommended a .NET Roslyn scanner.

## Decision

Do **not** require a .NET SDK. `csharp_parser.py` matches
`System.Security.Cryptography` APIs with regular expressions.

## Consequences

No semantic flow (key size set on another line). Acceptable for Part 2.
