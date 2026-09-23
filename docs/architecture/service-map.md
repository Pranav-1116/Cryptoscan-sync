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
| graph_engine       | `services/graph_engine`      | Neo4j Cypher graph + memory fallback      |
| agility            | `services/agility`           | 6-factor agility + migration readiness    |
| ot_scanner         | `services/ot_scanner`        | Passive OT/ICS crypto (never sends pkts)  |
| vendor_intel       | `services/vendor_intel`      | Questionnaire, CBOM, docs, vendor risk    |

Local entrypoints: `make api`, `make worker`, `make test`. `make test` runs the
whole tree in one hermetic, parallel pytest session (xdist, `--import-mode=importlib`
so duplicate test basenames no longer collide); see [dev/TESTING.md](../dev/TESTING.md).
