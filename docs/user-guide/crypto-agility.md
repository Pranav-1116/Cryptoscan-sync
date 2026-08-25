# Crypto agility and migration readiness

Every system can be scored with a deterministic six-factor model:

1. Algorithm configurability
2. Key management
3. Abstraction layer
4. Deployment architecture
5. Testing
6. Documentation

Raw points are normalized to 0–100 and labeled EXCELLENT / GOOD / MODERATE /
POOR / CRITICAL. A separate five-factor readiness score places the system in
Wave 1 (ready now), Wave 2 (needs prep), or Wave 3 (blocked).

APIs:

- `GET /api/v1/agility`
- `GET /api/v1/systems/{id}/agility`
- `POST /api/v1/systems/{id}/agility/recalculate`
- `GET /api/v1/readiness`

The pipeline writes `system_agility_scores` after each scan.
