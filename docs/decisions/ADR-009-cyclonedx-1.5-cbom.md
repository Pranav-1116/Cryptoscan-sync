# ADR-009 CycloneDX 1.5 CBOM

## Status

Accepted.

## Decision

Export cryptographic inventory as CycloneDX 1.5 (`bomFormat=CycloneDX`,
`specVersion=1.5`) with `cryptographic-asset` components, OIDs, primitives,
optional vulnerabilities, and optional HMAC-SHA256 signature.

## Consequences

Interoperable with GRC tools that ingest CycloneDX. We validate structure
locally rather than vendoring the full official schema.
