# ADR-003 SHA-256 for evidence hash

## Status

Accepted.

## Context

Auditors need a tamper-evident record of each finding without introducing a
blockchain dependency.

## Decision

Canonical JSON + SHA-256 content hashes, then a linear chain hash keyed by
`scan_id`. HMAC-SHA256 is used only for optional CBOM signing.

## Consequences

Any edit to a finding or reordering of the chain fails `GET /scans/{id}/verify`.
