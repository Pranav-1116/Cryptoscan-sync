# Service map

| Service            | Path                         | Role                                      |
|--------------------|------------------------------|-------------------------------------------|
| scanner            | `services/scanner`           | Multi-language static + JAR strings       |
| evidence           | `services/evidence`          | Canonicalize, hash, chain, manifest       |
| normalization      | `services/normalization`     | Algorithm aliases → NIST / IANA / CBOM    |
| policy             | `services/policy`            | YAML rules, scoped advanced standards     |
| database           | `services/database`          | SQLAlchemy models + loaders               |
| worker             | `services/worker`            | Sync 8-stage pipeline                     |
| api                | `services/api`               | FastAPI `/api/v1` + dashboard host        |
| dashboard          | `services/dashboard`         | Single-page `index.html`                  |
| drift              | `services/drift`             | Baseline compare + email alert            |
| container_scanner  | `services/container_scanner` | Image-root inventory                      |
| deduplication      | `services/deduplication`     | Cross-scanner assets                      |
| cbom               | `services/cbom`              | CycloneDX 1.5 export                      |

Local entrypoints: `make api`, `make worker`, `make test`. Combined pytest
across services hits `ImportPathMismatchError` because several packages ship
a `tests.conftest` — always run per-service as `make test` does.
