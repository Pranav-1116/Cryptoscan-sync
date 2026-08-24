# ADR-007 library fingerprinting approach

## Status

Accepted.

## Context

Full binary disassembly is Part 3+ work. Containers still need a crypto
library inventory.

## Decision

Fingerprint known packages and shared-library names from a local JSON catalog.
Parse OS package databases and language manifests. JAR scanning is string
match only.

## Consequences

Unknown custom crypto libraries are reported as `UNKNOWN` / LOW confidence.
No live NVD/OSV calls.
