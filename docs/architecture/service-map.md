# Service map

| Package | Path | Role |
|---|---|---|
| scanner | `services/scanner` | Discover `.java`, emit `RawFinding` |
| evidence | `services/evidence` | Hash + chain |
| database | `services/database` | SQLAlchemy models, repos, loader |
| normalization | `services/normalization` | Canonical algorithm names |
| policy | `services/policy` | Deterministic compliance |
| drift | `services/drift` | Baseline delta |
| worker | `services/worker` | 8-stage job |
| api | `services/api` | FastAPI + dashboard host |
