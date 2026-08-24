# ADR-004 Python for services

## Status

Accepted.

## Context

The platform is a set of small batch services (scan, hash, normalize, policy)
plus a FastAPI façade.

## Decision

All services are Python 3.11 packages under `services/`, sharing SQLAlchemy
models. The dashboard is a static `index.html` served by the API.

## Consequences

No separate Node backend. The unused React `src/` tree is not the runtime UI.
