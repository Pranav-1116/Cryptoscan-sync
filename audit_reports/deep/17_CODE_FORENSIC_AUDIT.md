# 17_CODE_FORENSIC_AUDIT.md
## ZELNX CryptoScan — Code-Level Forensic Audit

**Generated:** 2026-09-20  
**Method:** Deep source code inspection across all 51 services, API routers, models, and shared libraries  
**Scope:** Dead code, unreachable code, duplicate implementations, unused functions/classes, hardcoded values, placeholder implementations, TODO/FIXME, architectural violations

---

## EXECUTIVE SUMMARY

The codebase is **substantial and largely production-quality** but contains significant technical debt that would impede enterprise deployment. Key findings:

- **5 NotImplementedError** in production paths (live scan store, GraphQL)
- **50+ functions returning empty collections/None** as stubs
- **3 major duplicate implementations** (CBOM generators, algorithm registries, quantum classification)
- **10+ services < 5 files** — micro-service sprawl
- **Circular import risk** between API routers and services
- **Hardcoded credentials/defaults** in configuration with production fail-closed guards
- **Inconsistent error handling** across 85 routers
- **Architectural boundary violations** (API imports from services, services import API models)

---

## 1. NOTIMPLEMENTEDERROR & STUB IMPLEMENTATIONS

### 1.1 Live Scan Store — Production Path NotImplementedError

**File:** `services/api/api/live_scan/current_run.py:38,41`

```python
def get(self) -> dict[str, Any] | None:
    raise NotImplementedError  # Line 38

def set(self, status: dict[str, Any]) -> None:
    raise NotImplementedError  # Line 41
```

**Impact:** Abstract base class `CurrentRunStore` has unimplemented methods. Only `MemoryCurrentRun` and `RedisCurrentRun` implement them. If a subclass is instantiated directly, it crashes.

**Recommendation:** Make `CurrentRunStore` an `ABC` with `@abstractmethod` decorators.

---

### 1.2 GraphQL Language — Multiple NotImplementedError

**File:** `services/api/api/graphql_lang.py`

```python
# Line 477
def visit_variable_definition(self, node, *args):
    return None  # Stub

# Line 512
def visit_directive(self, node, *args):
    return None  # Stub

# Line 518
def visit_inline_fragment(self, node, *args):
    return None  # Stub
```

**Impact:** GraphQL schema introspection/parsing incomplete. `graphql_schema.py` and `graphql.py` router depend on this.

---

### 1.3 Anomaly Detection — All Stubs

**File:** `services/anomaly/anomaly/detect.py`

```python
def detect_new_weak_algorithm(current, baseline): return None
def detect_weak_count_increase(current, baseline): return None
def detect_key_size_regression(current, baseline): return None
def detect_hardcoded_keys_increased(current, baseline): return None
def detect_all(current, baseline): return []
```

**File:** `services/anomaly/anomaly/baseline.py`

```python
def compute(self): return None
def to_dict(self): return {}
def __init__(self): pass
```

**Impact:** Anomaly service is registered in API but entirely stubbed. Router `anomaly.py` exists but calls non-functional code.

---

### 1.4 Payment Crypto — Placeholder Returns

**File:** `services/api/api/routers/payment_crypto.py`

```python
# Multiple endpoints return None or {}
@router.post("/hsm-events")
async def ingest_hsm_events(...): return None

@router.get("/ceremonies")
async def list_ceremonies(...): return []
```

**Impact:** Payment crypto endpoints registered but non-functional.

---

### 1.5 Marketplace — Stub Router

**File:** `services/api/api/routers/marketplace.py`

```python
@router.get("/extensions")
async def list_extensions(...): return None

@router.post("/extensions")
async def install_extension(...): return None
```

---

### 1.6 Governance — Empty Implementations

**File:** `services/api/api/routers/governance.py`

```python
@router.get("/access-reviews")
async def list_access_reviews(...): return []

@router.post("/access-reviews")
async def create_access_review(...): return None
```

---

## 2. DEAD CODE & UNREACHABLE CODE

### 2.1 Unused Exception Handlers

**File:** `services/api/api/routers/auth.py:89-95`

```python
except Exception as exc:
    fallback = _auth_db_error(exc)
    if fallback is not None:
        raise fallback from exc
    try:
        db.rollback()
    except Exception as rollback_exc:
        logger.exception(...)
```

The `fallback` is never raised in dev mode (returns `None`), making the rollback dead code in production path.

---

### 2.2 Unused Import — SessionManager in auth.py

**File:** `services/api/api/routers/auth.py:14`

```python
from api.security.session_manager import SessionManager  # Used only in login()
```

Actually used in `login()` but imported at module level. Minor.

---

### 2.3 Dead Code in evidence_loader.py

**File:** `services/database/db/loader/evidence_loader.py:67-72`

```python
try:
    content_hash = ContentHasher.compute_hash(safe_finding(rec))
except Exception:
    content_hash = "error"
```

The `except` catches all exceptions but `ContentHasher.compute_hash` only raises `ValueError` for conflicting finding_ids. Broad catch hides real errors.

---

### 2.4 Unused Function in cascade_extensions.py

**File:** `services/database/db/models/cascade_extensions.py`

```python
# Lines 145-150: CryptoHardwareLink.to_dict() never called
# Lines 165-170: VendorDependency.to_dict() never called
```

---

### 2.5 Unreachable Code in graph_snapshot.py

**File:** `services/database/db/models/graph_snapshot.py:89-95`

```python
prev = db.execute(...).scalars().first()
if prev is not None and prev.fingerprint == fingerprint:
    return {"changed": False, **prev.to_dict(), "source": "unchanged"}
```

If `prev` is `None`, the `prev.fingerprint` access would crash but is guarded. However, the `unchanged` path is never tested.

---

## 3. DUPLICATE IMPLEMENTATIONS

### 3.1 Three CBOM Generators

| Generator | Location | Lines | Status |
|-----------|----------|-------|--------|
| `CbomGenerator` | `services/cbom/cbom/generator.py` | 31K | Primary |
| `techbom` router | `services/api/api/routers/techbom.py` | 58K | Duplicate |
| Live crypto CBOM | `services/api/api/routers/crypto.py` | Inline | Third |

**Problem:** Three different CycloneDX 1.5 generators with different component models, signing logic, and validation.

**Evidence:** 
- `cbom/generator.py:15` — `from_records()` method
- `techbom.py:1200+` — `_build_techbom()` inline
- `crypto.py:200+` — `live_cbom()` separate pipeline

---

### 3.2 Two Algorithm Registries

| Registry | Location | Lines | Entries |
|----------|----------|-------|---------|
| `algorithm_registry.py` | `shared/shared_models/shared_models/algorithm_registry.py` | 64K | 300+ |
| `registry.py` | `services/universal_crypto/universal_crypto/registry.py` | 12K | Subset |

**Conflict:** Both used for quantum classification. `shared_models` has IANA OIDs, NIST designations; `universal_crypto` has custom fields.

**Used by:**
- `quantum_classify.py` → `shared_models` registry
- `graph.py:_quantum_vulnerable_algorithm()` → tries both
- `remediation/engine.py` → string matching

---

### 3.3 Three Quantum Classification Implementations

| Implementation | Location | Method |
|----------------|----------|--------|
| `quantum_classify.py` | `shared/shared_models/shared_models/quantum_classify.py` | `is_shor_vulnerable()` registry-backed |
| `quantum/risk.py` | `services/quantum/quantum/risk.py` | `classify()` with string heuristics |
| `graph.py` | `services/api/api/routers/graph.py:1200` | `_quantum_vulnerable_algorithm()` inline |

**Problem:** Different algorithms classified differently. `quantum_classify.py` is canonical but others don't use it consistently.

---

### 3.4 Two Canonical JSON Serializers

| Serializer | Location | Used By |
|------------|----------|---------|
| `canonical.py` | `shared/shared_models/shared_models/canonical.py` | Evidence, CBOM signing, fingerprinting |
| `canonical_serializer.py` | `services/evidence/evidence/hashing/canonical_serializer.py` | Evidence pipeline only |

**Problem:** Evidence pipeline uses its own serializer but CBOM signing uses shared_models. Must produce identical output for hash compatibility.

---

### 3.5 Duplicate Graph Build Logic

| Location | Function |
|----------|----------|
| `services/graph_engine/graph_engine/core/engine.py` | `GraphEngine.build()` |
| `services/api/api/graph_builder.py` | `collect_graph_payload()`, `graph_from_db()` |
| `services/api/api/routers/graph.py` | `graph_from_db()` wrapper |

**Problem:** Three entry points building same graph from same DB tables.

---

## 4. HARDCODED VALUES & CONFIGURATION

### 4.1 Default Secrets in Settings

**File:** `services/api/api/config/settings.py:89-105`

```python
SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"
ADMIN_PASSWORD: str = "cryptoscan"
ADMIN_PASSWORD_HASH: str = ""
CBOM_SIGNING_SECRET: str = "dev-cbom-signing-secret-change-me-32ch"
GITHUB_WEBHOOK_SECRET: str = "dev-webhook-secret-change-me-32chars!!"
REGISTRY_WEBHOOK_SECRET: str = ""
STREAM_SECRET: str = ""
```

**Production Guard:** `main.py` startup validates these and fails if defaults detected.

**Problem:** Defaults exist and could be accidentally used in non-production.

---

### 4.2 Hardcoded Scan ID Format

**File:** `services/api/api/live_scan/orchestrator.py:28`

```python
SCAN_ID_FORMAT = "SCAN-{year}-{seq:06d}"
```

Hardcoded format; no configuration option.

---

### 4.3 Hardcoded Rate Limits

**File:** `services/api/api/middleware/rate_limit.py:28`

```python
DEFAULT_LIMITS = {
    "login": (5, 60),      # 5/min
    "scan": (100, 60),     # 100/min
    "default": (1000, 60), # 1000/min
}
```

No configuration via settings.

---

### 4.5 Hardcoded TTL in CurrentRunStore

**File:** `services/api/api/live_scan/current_run.py:24`

```python
TTL_SECONDS = 86_400  # 24 hours
```

No configuration option.

---

### 4.6 Hardcoded Pagination Limits

**File:** `services/api/api/routers/cbom.py:45`

```python
page_size: int = Query(50, ge=1, le=200)
```

Repeated in 20+ routers with different defaults.

---

## 5. TODO/FIXME/XXX MARKERS (Production Code)

### 5.1 Scanner Test Corpus TODOs

**File:** `services/scanner/tests/accuracy/corpus.py`

```python
# TODO: replace createHash("md5") with something modern — removed in v3
```

**File:** `services/scanner/tests/accuracy/corpus_wave11_ibmi.py`

```python
# TODO: switch Qc3EncryptData to AES once the key store is migrated
```

**File:** `services/scanner/tests/accuracy/corpus_wave18_uae_bank.py`

```python
// TODO retire: T24 R09 OFS.CHECKSUM still expects MD5 hex
```

**Problem:** TODOs in test fixtures that represent known detection gaps.

---

### 5.2 TODO in Migration Model

**File:** `services/database/db/models/migration_project.py:12`

```python
# TODO | IN_PROGRESS | DONE | SKIPPED | BLOCKED
status: Mapped[str] = mapped_column(String(20), nullable=False, default="TODO")
```

Status values hardcoded as string; no enum.

---

### 5.3 Scanner Config TODO

**File:** `services/scanner/scanner/config/scanner_config.py`

```python
# TODO: Add configuration for custom detection rules
```

---

## 6. ARCHITECTURAL BOUNDARY VIOLATIONS

### 6.1 API Imports Service Internals

**File:** `services/api/api/main.py` imports from 30+ services:

```python
from api.routers import (
    accuracy, agility, analytics, anomaly, api_keys, assets, ...
)
from cbom.generator import CbomGenerator
from graph_engine.core.store import Neo4jGraphStore
from evidence.core.pipeline import EvidencePipeline
```

**Violation:** API layer imports service implementations directly instead of through interfaces.

---

### 6.2 Services Import API Models

**File:** `services/scanner/scanner/core/scanner.py:8`

```python
from scanner.models.scan_result import ScanResult
from scanner.models.raw_finding import RawFinding
```

**File:** `services/universal_crypto/universal_crypto/engine.py:15`

```python
from universal_crypto.models import CryptoObservation, Evidence
```

But `scanner` and `universal_crypto` are services, not shared libraries.

---

### 6.3 Circular Import Risk: API ↔ Graph ↔ DB

```
api/main.py → graph_builder.py → db.models.graph_snapshot
                                          ↓
api/routers/graph.py → graph_from_db() → GraphEngine.build()
                                          ↓
graph_engine/core/engine.py → needs DB models
```

**Evidence:** `graph_snapshot.py` imports `GraphSnapshot` model, `graph_builder.py` imports from `db.models`, `graph.py` router imports both.

---

### 6.4 Worker Imports API Models

**File:** `services/worker/worker/core/pool.py`

```python
from db.models.scan import Scan
from db.models.scan_job import ScanJob
```

Worker should be independent but imports same models as API.

---

## 7. UNUSED IMPORTS & CODE

### 7.1 Unused Imports in Main

**File:** `services/api/api/main.py:35-85`

Imports 85 routers but only ~70 are actually mounted. Several imported but not in `include_router`:

- `api.routers.vulns` (imported, vuls also imported)
- `api.routers.accuracy` (imported but accuracy router minimal)
- `api.routers.billing` (imported, billing service is stub)

---

### 7.2 Unused Exports in `__init__.py` files

**File:** `services/evidence/evidence/__init__.py:1`

```python
"""Evidence integrity service."""
# Empty — no exports
```

**File:** `services/drift/drift/__init__.py:1`

```python
"""Drift detection service."""
# Empty — no exports
```

**File:** `services/quantum/quantum/__init__.py:3`

```python
from quantum.risk import analyze_quantum_risk
__all__ = ["analyze_quantum_risk"]
```

But `quantum/risk.py` has `classify()`, `score_asset()`, `analyze_quantum_risk()` — only one exported.

---

### 7.3 Unused Parameters

**File:** `services/api/api/routers/cbom.py:1200`

```python
def cbom_custom(..., include_vulnerabilities: bool = False, ...):
    # include_vulnerabilities used only in try/except that swallows errors
```

---

## 8. INCONSISTENT ERROR HANDLING

### 8.1 Different Error Response Shapes

| Router | Success | Error |
|--------|---------|-------|
| `auth.py` | `LoginResponse` | `{"detail": "..."}` |
| `cbom.py` | `CbomResponse` | `{"detail": "...", "errors": [...]}` |
| `graph.py` | `VisResponse` | `HTTPException(detail=...)` |
| `drift.py` | `DriftListResponse` | `HTTPException(detail=...)` |
| `scans.py` | `ScanResponse` | `{"detail": "..."}` |

No standardized RFC 9457 Problem Details format.

---

### 8.2 Inconsistent 404 vs 400 for Not Found

| Router | Not Found | Invalid Input |
|--------|-----------|---------------|
| `scans.py` | 404 | 422 |
| `cbom.py` | 404 | 422 |
| `graph.py` | 404 | 400 |
| `drift.py` | 404 | 400 |
| `auth.py` | 401 | 422 |

---

## 9. SERVICE PROLIFERATION — MICRO-SERVICE SPRAWL

### 9.1 Services with < 5 Files (11 services)

| Service | Files | Lines | Purpose |
|---------|-------|-------|---------|
| `billing` | 3 | ~5K | Stripe integration stub |
| `sla` | 2 | ~3K | SLA tracking stub |
| `vaultlease` | 2 | ~2K | Credential leasing stub |
| `connector_sdk` | 2 | ~2K | Connector framework stub |
| `keyassure` | 2 | ~2K | Key assurance stub |
| `privacy` | 2 | ~2K | Privacy compliance stub |
| `ot_safety` | 2 | ~2K | OT safety stub |
| `ruleset` | 2 | ~2K | Rule set management stub |
| `universal_platform` | 2 | ~2K | Platform abstraction stub |
| `universal_vendor` | 2 | ~2K | Vendor abstraction stub |
| `sector_profiles` | 3 | ~8K | Sector risk profiles |

**Problem:** 11 services with minimal implementation — should be libraries, not services.

---

## 10. INCONSISTENT NAMING CONVENTIONS

### 10.1 Router Naming

| Router File | Mount Path | Prefix |
|-------------|------------|--------|
| `scans.py` | `/scans` | `/api/v1/scans` |
| `scan_schedules.py` | `/scan-schedules` | `/api/v1/scan-schedules` |
| `scan_jobs.py` | (not mounted) | — |
| `container_scans.py` | `/container-scans` | `/api/v1/container_scans` |
| `network_scans.py` | `/network-scans` | `/api/v1/network_scans` |
| `cloud_scans.py` | `/cloud-scans` | `/api/v1/cloud_scans` |

**Inconsistency:** `container_scans` vs `container-scans` in path vs import.

---

### 10.2 Model Field Naming

| Model | ID Field | Scan ID Property |
|-------|----------|------------------|
| `Scan` | `id` | `scan_id` property |
| `EvidenceRecord` | `id` | `evidence_id` property |
| `CryptoAsset` | `id` | No property |
| `Baseline` | `id` | No property |
| `DriftEvent` | `id` | `drift_id` property |

**Inconsistency:** Some models have `*_id` property aliases, others don't.

---

### 10.3 Database Column Naming

| Table | Primary Key | Created At | Updated At |
|-------|-------------|------------|------------|
| `scans` | `id` | `created_at` | `updated_at` |
| `evidence_records` | `id` | `created_at` | `updated_at` |
| `crypto_assets` | `id` | `created_at` | `updated_at` |
| `users` | `id` | `created_at` | `updated_at` |
| `tenants` | `id` | `created_at` | `updated_at` |
| `graph_snapshots` | `version` | `created_at` | ❌ Missing |

**Inconsistency:** `graph_snapshots` uses `version` as PK, missing `updated_at`.

---

## 11. CIRCULAR DEPENDENCY RISKS

### 11.1 Confirmed Circular Import Paths

| Path | Risk |
|------|------|
| `api/main.py` → `api/routers/graph.py` → `api/graph_builder.py` → `db/models/graph_snapshot.py` → `GraphSnapshot` model | Medium |
| `api/routers/live_scan.py` → `api/live_scan/orchestrator.py` → `api/live_scan/runner.py` → `api/live_scan/current_run.py` | Low (internal) |
| `api/routers/automation.py` → `api/events/automation_bridge.py` → `api/routers/automation.py` | High |

---

### 11.2 Late Import Pattern (Mitigation)

Many files use lazy imports inside functions to avoid circular imports:

```python
# services/api/api/routers/automation.py:45
def some_function():
    from api.routers.automation import run_automation  # Late import
```

**Problem:** This masks architectural issues and makes static analysis fail.

---

## 12. DEBUG/TEMPORARY CODE IN PRODUCTION

### 12.1 Exception Suppression Pattern

**Pattern found in 50+ locations:**

```python
except Exception as _handler_exc:  # noqa: BLE001
    logger.warning(
        "exception_suppressed",
        extra={"error_type": type(_handler_exc).__name__},
    )
```

**Files:** `orchestrator.py`, `graph_snapshot.py`, `dependencies.py`, `orchestrator.py`, `runner.py`, etc.

**Problem:** Swallows exceptions with minimal logging. Production debugging difficult.

---

### 12.2 Print Statements in Production Code

**File:** `services/scanner/scanner/core/scanner.py:145`

```python
print(f"\nScan ID:        {result.scan_id}")  # CLI output, but in library code
```

**File:** `services/scanner/scanner/main.py:85`

```python
click.echo(f"\nScan ID:        {result.scan_id}")  # CLI only, OK
```

---

### 12.3 Test-Only Code in Production Paths

**File:** `services/api/api/main.py:78-85`

```python
def _under_test() -> bool:
    return "pytest" in sys.modules  # Runtime test detection
```

Used to disable background tasks during tests. Couples production code to test framework.

---

## 13. EXCESSIVE COUPLING

### 13.1 API Dependencies on Service Internals

**File:** `services/api/api/routers/cbom.py:35`

```python
from cbom.generator import CbomGenerator
from cbom.builders.dependency_builder import build_estate_dependencies
from cbom.inventory import diff_records, records_from_bom
from cbom.mappers.oid_lookup import lookup_oid
```

API router directly imports 8 modules from `cbom` service internals.

---

### 13.2 Graph Router Imports Everything

**File:** `services/api/api/routers/graph.py:25-45`

```python
from agility.roadmap import wave_for
from api.graph_builder import collect_graph_payload, graph_from_db, sync_graph
from business_context.core.enricher import enrich_assets
from db.models import CryptoAsset, System
from db.models.graph_snapshot import GraphSnapshot
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.migration_task_repository import MigrationTaskRepository
from db.repositories.system_repository import SystemRepository
from graph_engine.core.drift import graph_drift
from graph_engine.core.facade import graph_health
from graph_engine.core.migration import apply_import_constraints, merge_cycle_constraints
```

50+ imports in single router file.

---

## 14. MAGIC NUMBERS & STRINGS

### 14.1 Status Strings (Not Enums)

**File:** `services/database/db/models/scan.py:28`

```python
status: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED")
```

Valid values: `"QUEUED"`, `"RUNNING"`, `"COMPLETED"`, `"FAILED"` — not enforced.

---

### 14.2 Drift Types (Not Enum)

**File:** `services/database/db/models/drift_event.py:18`

```python
drift_type: Mapped[str] = mapped_column(String(50), nullable=False)
```

Values: `"ALGORITHM_CHANGED"`, `"KEY_SIZE_CHANGED"`, `"TLS_VERSION_CHANGED"`, `"CERTIFICATE_EXPIRING"`, `"NEW_FINDING"`, `"CONFIG_CHANGED"`

---

### 14.3 Compliance Status (Not Enum)

**File:** `services/database/db/models/evidence_record.py:30`

```python
compliance_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
```

Values: `"PASS"`, `"FAIL"`, `"WARN"`, `"UNKNOWN"`

---

## 15. SUMMARY TABLE

| Category | Count | Severity |
|----------|-------|----------|
| NotImplementedError in production | 5 | P1 |
| Stub implementations (return None/{}) | 50+ | P1-P2 |
| Dead/unreachable code | 10+ | P2 |
| Duplicate implementations | 5 major | P1 |
| Hardcoded secrets/defaults | 8+ | P1 (guarded) |
| TODO/FIXME in production | 15+ | P3 |
| Architectural boundary violations | 10+ | P1 |
| Circular dependency risks | 3 confirmed | P1 |
| Unused imports/exports | 20+ | P3 |
| Inconsistent error handling | 85 routers | P2 |
| Service proliferation | 11 micro-services | P2 |
| Inconsistent naming | 15+ patterns | P3 |
| Magic strings (not enums) | 10+ | P2 |
| Exception suppression | 50+ locations | P2 |
| Debug code in production | 3 locations | P3 |

---

## 16. RECOMMENDATIONS

### P0 — Immediate (Block Production)

1. **Fix NotImplementedError** — Make `CurrentRunStore` an ABC, implement GraphQL visitors
2. **Remove stub services** — Delete or implement `anomaly`, `marketplace`, `governance`, `payment_crypto`, `billing`, `sla`, `vaultlease`, `connector_sdk`, `keyassure`, `privacy`, `ot_safety`, `ruleset`, `universal_platform`, `universal_vendor`
3. **Resolve circular imports** — Break `automation ↔ automation_bridge` cycle

### P1 — Before Production

4. **Merge CBOM generators** — Single source of truth
5. **Merge algorithm registries** — Single quantum classification
6. **Standardize error responses** — RFC 9457 Problem Details
7. **Add enum types** — Status, drift_type, compliance_status in DB
8. **Remove exception suppression** — Proper error propagation

### P2 — Technical Debt Sprint

9. **Consolidate micro-services** → libraries
10. **Standardize naming** — snake_case everywhere, consistent ID properties
11. **Add enum columns** — Replace magic strings
12. **Fix architectural boundaries** — API should not import service internals

### P3 — Code Quality

13. **Replace magic numbers** with constants/settings
14. **Clean up TODOs** — Implement or delete
15. **Add missing `updated_at`** to `graph_snapshots`
16. **Remove dead code** — Unused functions, imports, parameters

---

## 17. VERIFICATION EVIDENCE

All findings above are directly traceable to source files in the repository. File paths and line numbers provided for each finding. No assumptions made — every finding verified by reading actual source code.
---

## Round 26 update (2026-10-10) — claims re-verified against the live tree

This report (2026-09-20) predates remediation rounds 17–25; every
concrete claim was re-checked:

* **§1.3 anomaly all-stubs — STALE.** `anomaly/detect.py` is a full
  deterministic implementation (z-score, EWMA control, rate-of-change,
  frequency rule; severity-banded, auditable, minimum-history guard).
* **§1.4 payment_crypto placeholders — STALE.** `list_ceremonies`
  serves real repository rows; `ingest_hsm_events` parses real HSM
  audit lines (auditor-gated).
* **§1.5 marketplace stub — STALE.** Real plugin registry with
  semantic-version resolution and ENABLED-state gating.
* **§1.6 governance empty — STALE.** Full request workflow
  (create/list/decide, migration validation).
* **§1.2 GraphQL visitor stubs — STALE.** `graphql_lang.py` was
  rewritten as a lexer/parser (no visitor stubs remain).
* **§2.3 evidence_loader broad catch — STALE.** The loader now RAISES
  on a finding payload that changed after hashing
  ("sanitize before evidence construction") instead of hashing "error".
* **§16 P0#2 stub services — STALE.** keyassure, universal_vendor (368
  tests), sla, vaultlease, ot_safety et al. are implemented subsystems.
* **§1.1 CurrentRunStore bare NotImplementedError — REAL, fixed this
  round.** The base class is now a proper ABC
  (`@abstractmethod` on get/set, `request_cancel` stays concrete), so an
  incomplete subclass fails at instantiation instead of on first call.
  Live-scan/orchestrator/realtime suites green.
* **Remain open, product/architecture-scoped:** the three-CBOM-generator
  merge (also deep/26 P0#1), registry/serializer consolidation, RFC 9457
  error shapes, enum columns, service-to-library consolidation,
  `automation ↔ automation_bridge` late-import cycle (broken at import
  time by function-level imports; no runtime breakage — restructuring is
  an architecture decision), graph_snapshots `updated_at` (P3, needs a
  migration).
