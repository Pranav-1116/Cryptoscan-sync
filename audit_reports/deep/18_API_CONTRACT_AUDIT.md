# 18_API_CONTRACT_AUDIT.md
## ZELNX CryptoScan — API Contract Audit

**Generated:** 2026-09-20  
**Method:** Complete inventory of all 85 registered API routers, their endpoints, authentication, authorization, validation, and error handling  
**Scope:** All endpoints under `/api/v1/` prefix

---

## EXECUTIVE SUMMARY

- **85 routers registered** in `services/api/api/main.py`
- **~500+ endpoints** estimated across all routers
- **Authentication:** Session (cookie) + API Key (header) — dual mode
- **Authorization:** 8-role RBAC + ABAC (opt-in) + tenant scoping
- **Validation:** Pydantic v2 models on all request/response
- **Rate Limiting:** Redis-backed, fail-closed in production
- **Tenant Isolation:** Middleware-enforced, but gaps in Neo4j and link tables

---

## 1. COMPLETE ENDPOINT INVENTORY

### 1.1 Authentication & Identity (`/api/v1/auth`)

| Method | Path | Auth | Roles | Input | Output | Errors |
|--------|------|------|-------|-------|--------|--------|
| POST | `/login` | None | — | `LoginRequest` | `LoginResponse` | 401, 422 |
| POST | `/login/mfa` | MFA token | — | `MfaLoginRequest` | `LoginResponse` | 401, 422 |
| POST | `/register` | None | — | `RegisterRequest` | `RegisterResponse` | 409, 422, 403 |
| POST | `/logout` | Session | Any | — | `{"message": "Logged out"}` | 401 |
| POST | `/logout/all` | Session | Any | — | `{"message": "All sessions revoked"}` | 401 |
| GET | `/me` | Session | Any | — | `UserResponse` | 401 |
| PATCH | `/me` | Session | Any | `UserUpdateRequest` | `UserResponse` | 401, 422 |
| POST | `/me/password` | Session | Any | `PasswordChangeRequest` | `{"message": "Password changed"}` | 401, 422 |
| POST | `/me/mfa/enable` | Session | Any | `MfaEnableRequest` | `{"secret": "...", "recovery_codes": [...]}` | 401, 422 |
| POST | `/me/mfa/disable` | Session | Any | `MfaDisableRequest` | `{"message": "MFA disabled"}` | 401, 422 |
| POST | `/invite` | Session | Admin | `InviteRequest` | `{"token": "..."}` | 401, 403, 422 |
| POST | `/invite/accept` | Token | — | `InviteAcceptRequest` | `LoginResponse` | 400, 422 |
| GET | `/users` | Session | Admin | Pagination | `UserListResponse` | 401, 403 |
| POST | `/users` | Session | Admin | `UserCreateRequest` | `UserResponse` | 401, 403, 409, 422 |
| PATCH | `/users/{username}` | Session | Admin | `UserUpdateRequest` | `UserResponse` | 401, 403, 404, 422 |
| DELETE | `/users/{username}` | Session | Admin | — | `{"message": "User deleted"}` | 401, 403, 404 |
| GET | `/audit` | Session | Admin/Auditor | Filters | `AuditLogResponse` | 401, 403 |
| GET | `/audit/verify` | Session | Admin | — | `{"valid": bool, "details": ...}` | 401, 403 |
| GET | `/audit/export` | Session | Admin | — | JSONL stream | 401, 403 |

**OAuth/OIDC:**
| POST | `/oidc/login` | None | — | `OidcLoginRequest` | `{"redirect_url": "..."}` | 422 |
| GET | `/oidc/callback` | State | — | Query params | `LoginResponse` | 400, 422 |
| POST | `/oidc/link` | Session | Any | `OidcLinkRequest` | `{"message": "Linked"}` | 401, 422 |

**SCIM:**
| GET | `/scim/v2/Users` | API Key | `scim` | Filters | SCIM List | 401, 403 |
| POST | `/scim/v2/Users` | API Key | `scim` | SCIM Create | SCIM User | 401, 403, 409 |
| GET | `/scim/v2/Users/{id}` | API Key | `scim` | — | SCIM User | 401, 403, 404 |
| PATCH | `/scim/v2/Users/{id}` | API Key | `scim` | SCIM Patch | SCIM User | 401, 403, 404 |
| DELETE | `/scim/v2/Users/{id}` | API Key | `scim` | — | 204 | 401, 403, 404 |

---

### 1.2 Scans & Findings (`/api/v1/scans`, `/api/v1/findings`, `/api/v1/evidence`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/scans` | Session | Any | Pagination, filters | `ScanListResponse` |
| POST | `/scans` | Session | Admin/Auditor/Developer/Scanner | `ScanCreateRequest` | `ScanResponse` |
| GET | `/scans/{scan_id}` | Session | Any | — | `ScanDetailResponse` |
| GET | `/scans/{scan_id}/report` | Session | Any | Format query | HTML/PDF/JSON |
| GET | `/scans/{scan_id}/evidence` | Session | Any | — | `EvidenceListResponse` |
| GET | `/scans/{scan_id}/baseline` | Session | Any | — | `BaselineResponse` |
| POST | `/scans/{scan_id}/baseline` | Session | Admin/Auditor | — | `BaselineResponse` |
| GET | `/scans/{scan_id}/cbom` | Session | Any | Format, signed | CBOM |
| GET | `/findings` | Session | Any | Filters, pagination | `FindingListResponse` |
| GET | `/findings/{finding_id}` | Session | Any | — | `FindingDetailResponse` |
| GET | `/evidence` | Session | Any | Scan ID filter | `EvidenceListResponse` |

---

### 1.3 CBOM (`/api/v1/cbom`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/cbom` | Session | Any | Pagination, coverage, q | `CbomCatalogResponse` |
| GET | `/cbom/coverage` | Session | Any | — | `CoverageSummary` |
| POST | `/cbom/scan-uncovered` | Session | Admin/Auditor | `ScanUncoveredRequest` | `ScanUncoveredResponse` |
| GET | `/cbom/portfolio` | Session | Any | Format, signed | CBOM |
| GET | `/cbom/search` | Session | Any | q, limit | `SearchResponse` |
| POST | `/cbom/validate` | Session | Any | `IngestCbomRequest` | `ValidateResponse` |
| POST | `/cbom/verify` | Session | Any | `IngestCbomRequest` | `VerifyReport` |
| POST | `/cbom/assess` | Session | Any | `CbomRef` | `AssessResponse` |
| POST | `/cbom/ingest` | Session | Any | `IngestCbomRequest` | `IngestResponse` |
| POST | `/cbom/diff` | Session | Any | `DiffCbomRequest` | `DiffResponse` |
| GET | `/cbom/scan/{scan_id}` | Session | Any | Format, signed | CBOM |
| GET | `/cbom/system/{system_id}` | Session | Any | Format, signed | CBOM |
| POST | `/cbom/custom` | Session | Any | `CustomCbomRequest` | CBOM |
| POST | `/cbom/nbom` | Session | Any | `NbomRequest` | `NbomResponse` |
| POST | `/cbom/nbom/cascade` | Session | Any | `NbomRequest` + ref | `CascadeResponse` |
| GET | `/cbom/nbom` | Session | Any | — | `NbomResponse` |

---

### 1.4 Graph (`/api/v1/graph`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/graph/health` | Session | Any | — | `GraphHealth` |
| POST | `/graph/sync` | Session | Admin | — | `SyncResponse` |
| GET | `/graph` | Session | Any | — | `VisResponse` |
| GET | `/graph/blast-radius` | Session | Any | system_id/asset_id, hops | `BlastRadiusResponse` |
| GET | `/graph/impact` | Session | Any | system_id/asset_id | `ImpactResponse` |
| GET | `/graph/compliance` | Session | Any | system_id, hops | `ComplianceResponse` |
| GET | `/graph/vendor-path` | Session | Any | system_id | `VendorPathResponse` |
| GET | `/graph/vendor-chain` | Session | Any | vendor_id | `VendorChainResponse` |
| GET | `/graph/vendor-chains` | Session | Any | Limit | `VendorChainsResponse` |
| GET | `/graph/dependents` | Session | Any | system_id, hops | `DependentsResponse` |
| GET | `/graph/path` | Session | Any | system_id, target_id, direction | `PathResponse` |
| GET | `/graph/hotspots` | Session | Any | — | `HotspotsResponse` |
| GET | `/graph/cycles` | Session | Any | — | `CyclesResponse` |
| GET | `/graph/certificates/exposure` | Session | Any | — | `CertExposureResponse` |
| GET | `/graph/stats` | Session | Any | — | `GraphStatsResponse` |
| GET | `/graph/drift` | Session | Any | — | `GraphDriftResponse` |
| GET | `/graph/migration-waves` | Session | Any | — | `MigrationWavesResponse` |
| GET | `/graph/crypto` | Session | Any | system_id | `CryptoInventoryResponse` |
| POST | `/graph/simulate` | Session | Admin | `SimulateRequest` | `SimulateResponse` |
| GET | `/graph/explain` | Session | Any | node_id | `ExplainResponse` |
| POST | `/graph/migration-plan` | Session | Admin | `MigrationPlanRequest` | `MigrationPlanResponse` |
| POST | `/graph/snapshot` | Session | Admin | — | `SnapshotResponse` |
| GET | `/graph/timeline` | Session | Any | Limit | `TimelineResponse` |
| GET | `/graph/compare` | Session | Any | from_version, to_version | `CompareResponse` |
| GET | `/graph/edges` | Session | Any | Relation, system_id, limit | `EdgesResponse` |
| POST | `/graph/edges` | Session | Admin | `EdgeRequest` | `EdgeResponse` |
| DELETE | `/graph/edges/{parent}/{child}` | Session | Admin | — | `DeleteResponse` |
| GET | `/graph/edges/discovered` | Session | Any | — | `DiscoveredEdgesResponse` |
| POST | `/graph/edges/adopt` | Session | Admin | `{"edges": [...]}` | `AdoptResponse` |
| GET | `/graph/hardware-links` | Session | Any | — | `HardwareLinksResponse` |
| POST | `/graph/hardware-links` | Session | Admin | `HardwareLinkRequest` | `LinkResponse` |
| DELETE | `/graph/hardware-links/{asset}/{hw}` | Session | Admin | — | `DeleteResponse` |
| GET | `/graph/vendor-edges` | Session | Any | — | `VendorEdgesResponse` |
| POST | `/graph/vendor-edges` | Session | Admin | `VendorEdgeRequest` | `EdgeResponse` |
| DELETE | `/graph/vendor-edges/{parent}/{child}` | Session | Admin | — | `DeleteResponse` |

---

### 1.5 Drift (`/api/v1/drift`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/drift` | Session | Any | Pagination, severity, status, scan_id, drift_type | `DriftListResponse` |
| GET | `/drift/digest` | Session | Any | Hours | `DriftDigestResponse` |
| POST | `/drift/{drift_id}/acknowledge` | Session | Auditor | `AckBody` | `DriftEventResponse` |
| POST | `/drift/{drift_id}/resolve` | Session | Auditor | `AckBody` | `DriftEventResponse` |
| POST | `/drift/{drift_id}/false-positive` | Session | Auditor | `AckBody` | `DriftEventResponse` |

---

### 1.6 Network & Cloud (`/api/v1/network`, `/api/v1/cloud`)

**Network:**
| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/network` | Session | Any | Pagination | `NetworkListResponse` |
| GET | `/network/{asset_id}` | Session | Any | — | `NetworkDetailResponse` |
| GET | `/network-scans` | Session | Any | Pagination | `NetworkScanListResponse` |
| POST | `/network-scans` | Session | Admin/Auditor | `NetworkScanRequest` | `NetworkScanResponse` |
| GET | `/network-scans/{scan_id}` | Session | Any | — | `NetworkScanDetailResponse` |
| GET | `/network-scans/{scan_id}/probes` | Session | Any | — | `ProbesResponse` |
| GET | `/network/targets` | Session | Any | — | `TargetsResponse` |
| POST | `/network/targets` | Session | Admin | `TargetRequest` | `TargetResponse` |

**Cloud:**
| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/cloud` | Session | Any | Pagination | `CloudListResponse` |
| GET | `/cloud/{account_id}` | Session | Any | — | `CloudDetailResponse` |
| GET | `/cloud-scans` | Session | Any | Pagination | `CloudScanListResponse` |
| POST | `/cloud-scans` | Session | Admin/Auditor | `CloudScanRequest` | `CloudScanResponse` |

---

### 1.7 Container & Binary (`/api/v1/container`, `/api/v1/binary`)

**Container:**
| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/container` | Session | Any | Pagination | `ContainerListResponse` |
| POST | `/container/scan` | Session | Admin/Auditor | `ContainerScanRequest` | `ContainerScanResponse` |
| GET | `/container-scans` | Session | Any | Pagination | `ContainerScanListResponse` |

**Binary:**
| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| POST | `/binary/scan` | Session | Admin/Auditor | `BinaryScanRequest` | `BinaryScanResponse` |
| GET | `/binary/scans` | Session | Any | Pagination | `BinaryScanListResponse` |
| GET | `/binary/scans/{scan_id}` | Session | Any | — | `BinaryScanDetailResponse` |
| POST | `/binary/batch` | Session | Admin | `BinaryBatchRequest` | `BinaryBatchResponse` |
| GET | `/binary/batch/{batch_id}` | Session | Any | — | `BinaryBatchStatusResponse` |
| POST | `/binary/dynamic` | Session | Admin | `BinaryDynamicRequest` | `BinaryDynamicResponse` |

---

### 1.8 Crypto Live Engine (`/api/v1/crypto`)

| Method | Path | Auth | Permission | Input | Output |
|--------|------|------|------------|-------|--------|
| POST | `/crypto/live/events` | API Key | `crypto.ingest` | `CryptoEventRequest` | `EventResponse` |
| GET | `/crypto/live/state` | Session/API Key | `crypto.read` | — | `LiveStateResponse` |
| GET | `/crypto/live/state/{asset_id}` | Session/API Key | `crypto.read` | — | `AssetStateResponse` |
| GET | `/crypto/live/risk-summary` | Session/API Key | `crypto.read` | — | `RiskSummaryResponse` |
| GET | `/crypto/live/timeline` | Session/API Key | `crypto.read` | Filters, pagination | `TimelineResponse` |
| GET | `/crypto/live/{asset_id}/cbom` | Session/API Key | `crypto.read` | — | CBOM |
| GET | `/crypto/accuracy` | Session | `crypto.read` | — | `AccuracyResponse` |
| POST | `/crypto/scan` | Session | `crypto.manage` | `ScanRequest` | `ScanResponse` |
| POST | `/crypto/simulate` | Session | `crypto.manage` | `SimulateRequest` | `SimulateResponse` |

---

### 1.9 DevSecOps (`/api/v1/devsecops`, `/api/v1/sbom`, `/api/v1/container`, `/api/v1/k8s`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| POST | `/container/scan` | Session | Admin/Auditor | `ContainerScanRequest` | `ContainerScanResponse` |
| POST | `/k8s/scan` | Session | Admin/Auditor | `K8sScanRequest` | `K8sScanResponse` |
| POST | `/cloud/posture` | Session | Admin/Auditor | `CloudPostureRequest` | `CloudPostureResponse` |
| POST | `/sbom/scan` | Session | Admin/Auditor | `SbomScanRequest` | `SbomScanResponse` |
| GET | `/sbom/artifacts` | Session | Any | Filters | `SbomArtifactsResponse` |
| POST | `/sbom/diff` | Session | Admin/Auditor | `SbomDiffRequest` | `SbomDiffResponse` |
| POST | `/sbom/validate` | Session | Any | `SbomValidateRequest` | `SbomValidateResponse` |
| POST | `/sbom/import` | Session | Admin/Auditor | `SbomImportRequest` | `SbomImportResponse` |
| POST | `/sbom/license` | Session | Any | `SbomLicenseRequest` | `SbomLicenseResponse` |
| GET | `/sbom/components` | Session | Any | Filters | `SbomComponentsResponse` |
| GET | `/sbom/advisories` | Session | Any | Filters | `SbomAdvisoriesResponse` |
| POST | `/sbom/gate` | Session | Admin/Auditor | `SbomGateRequest` | `SbomGateResponse` |
| POST | `/sbom/rescan` | Session | Admin/Auditor | `SbomRescanRequest` | `SbomRescanResponse` |
| POST | `/sbom/prune` | Session | Admin | `SbomPruneRequest` | `SbomPruneResponse` |
| POST | `/binary/scan` | Session | Admin/Auditor | `BinaryScanRequest` | `BinaryScanResponse` |
| POST | `/binary/batch` | Session | Admin | `BinaryBatchRequest` | `BinaryBatchResponse` |
| GET | `/binary/batch/{batch_id}` | Session | Any | — | `BinaryBatchStatusResponse` |

---

### 1.10 Compliance & Risk (`/api/v1/compliance`, `/api/v1/risk`, `/api/v1/security`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/compliance` | Session | Any | Pagination | `ComplianceListResponse` |
| GET | `/compliance/{system_id}` | Session | Any | — | `ComplianceDetailResponse` |
| GET | `/risk` | Session | Any | Filters | `RiskListResponse` |
| GET | `/risk/summary` | Session | Any | — | `RiskSummaryResponse` |
| GET | `/security` | Session | Any | — | `SecurityPostureResponse` |
| GET | `/security/alerts` | Session | Any | Filters | `AlertsResponse` |

---

### 1.11 Admin & Settings (`/api/v1/admin`, `/api/v1/settings`, `/api/v1/tenancy`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/admin` | Session | Admin | — | `AdminDashboardResponse` |
| GET | `/settings` | Session | Admin | — | `SettingsResponse` |
| PATCH | `/settings` | Session | Admin | `SettingsRequest` | `SettingsResponse` |
| GET | `/tenancy` | Session | Admin | Pagination | `TenancyListResponse` |
| POST | `/tenancy` | Session | Admin | `TenancyCreateRequest` | `TenancyResponse` |
| PATCH | `/tenancy/{tenant_id}` | Session | Admin | `TenancyUpdateRequest` | `TenancyResponse` |
| GET | `/tenancy/{tenant_id}/members` | Session | Admin | — | `MembersResponse` |
| POST | `/tenancy/{tenant_id}/members` | Session | Admin | `MemberRequest` | `MemberResponse` |

---

### 1.12 API Keys (`/api/v1/api-keys`)

| Method | Path | Auth | Roles | Input | Output |
|--------|------|------|-------|-------|--------|
| GET | `/api-keys` | Session | Admin/CISO | Pagination | `ApiKeyListResponse` |
| POST | `/api-keys` | Session | Admin/CISO | `ApiKeyCreateRequest` | `ApiKeyCreateResponse` |
| GET | `/api-keys/{key_id}` | Session | Admin/CISO | — | `ApiKeyDetailResponse` |
| PATCH | `/api-keys/{key_id}` | Session | Admin/CISO | `ApiKeyUpdateRequest` | `ApiKeyDetailResponse` |
| DELETE | `/api-keys/{key_id}` | Session | Admin/CISO | — | `{"message": "Revoked"}` |
| POST | `/api-keys/{key_id}/rotate` | Session | Admin/CISO | — | `ApiKeyRotateResponse` |

---

### 1.13 Metrics & Health (`/metrics`, `/health`, `/ready`)

| Method | Path | Auth | Roles | Output |
|--------|------|------|-------|--------|
| GET | `/health` | None | — | `{"status": "healthy", ...}` |
| GET | `/ready` | None | — | `{"ready": bool, "database": ..., "migrations": ...}` |
| GET | `/healthz` | None | — | Same as `/health` |
| GET | `/readyz` | None | — | Same as `/ready` |
| GET | `/metrics` | None | — | Prometheus text format |

---

## 2. AUTHENTICATION & AUTHORIZATION AUDIT

### 2.1 Authentication Methods

| Method | Header | Cookie | Used By |
|--------|--------|--------|---------|
| Session | `Authorization: Bearer <token>` | `cryptoscan_session` | UI, API |
| API Key | `X-API-Key: <key>` | — | CI/CD, SIEM, scripts |

**Dual-path resolution in `dependencies.py:_resolve_api_key()`**

---

### 2.2 Authorization Matrix (Permission → Roles)

| Permission | SuperAdmin | CISO | SecurityAnalyst | Developer | Auditor | BusinessOwner | Scanner | ReadOnly |
|------------|------------|------|-----------------|-----------|---------|---------------|---------|----------|
| `scan.trigger` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| `baseline.approve` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `drift.acknowledge` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `drift.resolve` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `crypto.ingest` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `crypto.manage` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `users.manage` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `audit.read` | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

---

### 2.3 Authorization Gaps

| Gap | Location | Risk |
|-----|----------|------|
| **No resource-level permissions** | All routers | Users can access any tenant's scans if middleware bypassed |
| **API key roles not validated against matrix** | `dependencies.py:_resolve_api_key()` | Key roles used directly, not checked against `PERMISSION_MATRIX` |
| **Legacy role aliases** | `normalize_roles()` | `admin`→`superadmin`, `viewer`→`readonly` — confusion |
| **No permission inheritance** | `require_permission()` | Each permission checked independently |

---

## 3. VALIDATION AUDIT

### 3.1 Request Validation

| Layer | Implementation |
|-------|----------------|
| Path params | FastAPI path converters (UUID, str, int) |
| Query params | `Query()` with `ge`, `le`, `pattern`, `min_length` |
| Request body | Pydantic v2 models (`BaseModel`, `Field()`) |
| File uploads | `python-multipart` with size limits |

**All endpoints use Pydantic models** — no raw `Request.body()` parsing.

---

### 3.2 Validation Gaps

| Gap | Location | Example |
|-----|----------|---------|
| **No cross-field validation** | `ScanCreateRequest` | `repo_url` + `branch` but no validation branch exists |
| **No uniqueness validation** | `UserCreateRequest` | Username/email uniqueness checked in repo, not schema |
| **Weak password policy** | `validate_password_policy()` | Only length + entropy, no breach check |
| **No XSS sanitization** | String fields | HTML/JS in display_name, email not sanitized |

---

## 4. ERROR HANDLING AUDIT

### 4.1 Error Response Formats

| Router | Success Shape | Error Shape |
|--------|---------------|-------------|
| `auth.py` | `LoginResponse` | `{"detail": "..."}` |
| `cbom.py` | `CbomResponse` | `{"detail": "...", "errors": [...]}` |
| `graph.py` | `VisResponse` | `HTTPException(detail=str)` |
| `drift.py` | `DriftListResponse` | `HTTPException(detail=str)` |
| `scans.py` | `ScanResponse` | `{"detail": "..."}` |
| `auth.py` (register) | `RegisterResponse` | `{"detail": "..."}` |

**Inconsistent:** Some return `{"detail": "..."}`, others `{"detail": "...", "errors": [...]}`, others raw `HTTPException`.

---

### 4.2 HTTP Status Code Consistency

| Scenario | Expected | Actual (Varies) |
|----------|----------|-----------------|
| Not found | 404 | 404 ✅ / 400 ❌ |
| Unauthorized | 401 | 401 ✅ |
| Forbidden | 403 | 403 ✅ |
| Validation error | 422 | 422 ✅ |
| Rate limited | 429 | 429 ✅ |
| Conflict | 409 | 409 ✅ / 400 ❌ |
| Server error | 500 | 500 ✅ / 503 ❌ |

---

### 4.3 Error Response Inconsistencies

| Issue | Example |
|-------|---------|
| **No error codes** | All errors return only `detail` string |
| **No structured details** | Validation errors sometimes in `errors` array, sometimes in `detail` |
| **No RFC 9457** | No `type`, `title`, `instance` fields |
| **Internal errors leak** | DB errors sometimes bubble as 500 with SQL details |

---

## 5. RATE LIMITING AUDIT

### 5.1 Implementation

**File:** `services/api/api/middleware/rate_limit.py`

```python
DEFAULT_LIMITS = {
    "login": (5, 60),      # 5 requests per 60 seconds
    "scan": (100, 60),     # 100 per minute
    "default": (1000, 60), # 1000 per minute
}
```

### 5.2 Rate Limiting Gaps

| Gap | Impact |
|-----|--------|
| **No WebSocket/SSE rate limiting** | `/ws/*`, `/events/*` unlimited |
| **Per-endpoint limits hardcoded** | Not configurable via settings |
| **No distributed rate limiting** | Redis single instance |
| **No WebSocket connection limits** | DoS via connection exhaustion |
| **API key quotas separate** | `apikeys.policy.KeyPolicy` separate system |

---

## 6. TENANT ISOLATION AUDIT

### 6.1 Middleware Enforcement

**File:** `services/api/api/middleware/tenant_scope.py`

```python
# Runs AFTER AuthMiddleware
# Sets request.state.tenant_id
# Scopes all queries via `filtered_get()` and `tenant_scope()`
```

### 6.3 Isolation Gaps

| Gap | Location | Risk |
|-----|----------|------|
| **Link tables no tenant_id** | `SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence` | Join-based bypass |
| **Neo4j no tenant isolation** | `Neo4jGraphStore` | All tenants share graph |
| **Event stream not tenant-scoped** | `EventBus` | Cross-tenant event leakage |
| **Redis keys not tenant-prefixed** | Rate limit, queue | Cross-tenant rate limit bypass |
| **Graph snapshots tenant filter** | `graph_snapshot.py:190` | Manual filter, not automatic |

---

## 7. PAGINATION, FILTERING, SORTING

### 7.1 Pagination Patterns

| Pattern | Implementation | Consistency |
|---------|----------------|-------------|
| Offset/limit | `page`, `page_size` Query params | ✅ Most routers |
| Cursor | Not implemented | ❌ Missing |
| Max page_size | 200 (scans), 500 (evidence) | Varies |

### 7.3 Sorting

| Router | Sort Support |
|--------|-------------|
| `scans.py` | `sort_by`, `sort_desc` |
| `cbom.py` | ❌ None |
| `graph.py` | ❌ None |
| `findings.py` | `sort_by`, `sort_desc` |
| `drift.py` | ❌ None |

---

## 8. API VERSIONING

### 8.1 Current State

- **Single version:** `/api/v1/` only
- **No versioning strategy** documented
- **No deprecation headers** (`Deprecation`, `Sunset`)
- **No backward compatibility** guarantees

### 8.2 Versioning Gaps

| Gap | Risk |
|-----|------|
| **No `/api/v2/` path** | Breaking changes require new endpoints |
| **No OpenAPI versioning** | Single `openapi.json` |
| **No client SDK versioning** | No SDK exists |

---

## 9. API NAMING INCONSISTENCIES

| Inconsistency | Examples |
|---------------|----------|
| **Hyphen vs underscore in paths** | `/container-scans` vs `/network_scans` (import) |
| **Singular vs plural** | `/graph/blast-radius` vs `/graph/vendor-chains` |
| **Verb placement** | `/graph/sync` (POST) vs `/cbom/scan-uncovered` (POST) |
| **Nested vs flat** | `/graph/edges` vs `/graph/hardware-links` |

---

## 10. BACKWARD COMPATIBILITY

### 10.1 Legacy Support

| Legacy | Current | Status |
|--------|---------|--------|
| Role `admin` | Alias for `superadmin` | Supported |
| Role `viewer` | Alias for `readonly` | Supported |
| Session cookie name | `cryptoscan_session` | Supported |
| `ADMIN_PASSWORD` env | Fallback for bootstrap | Supported |

### 10.2 Breaking Changes Not Versioned

| Change | Impact |
|--------|--------|
| Role catalog 3→8 roles | Old tokens may have old roles |
| CBOM signing JWS vs HMAC | Old verification fails |
| Graph snapshot versioning | Old clients expect no versions |

---

## 11. UNDOCUMENTED / HIDDEN ENDPOINTS

### 11.1 Endpoints Not in OpenAPI

| Endpoint | Router | Reason |
|----------|--------|--------|
| `/healthz` | `main.py` | Root alias, not in router |
| `/readyz` | `main.py` | Root alias |
| `/metrics` | `metrics_router.py` | Mounted without `/api/v1` prefix |
| `/ws/binary/jobs/{id}` | `ws.py` | WebSocket, not REST |
| `/ws/events` | `ws.py` | WebSocket |
| `/events/global` | `events.py` | SSE, not REST |
| `/events/{topic}` | `events.py` | SSE |
| `/graphql` | `graphql.py` | GraphQL endpoint |

---

### 11.2 Endpoints with Undocumented Parameters

| Endpoint | Undocumented Param |
|----------|-------------------|
| `GET /cbom/scan/{id}` | `fmt=xml`, `signed=true` |
| `GET /graph` | `format=vis` (default) |
| `POST /graph/simulate` | `change=migrate_pqc` (only option) |

---

## 12. AUDIT LOG COVERAGE

### 12.1 Audited Operations

| Operation | Audited | Detail Captured |
|-----------|---------|-----------------|
| Login/logout | ✅ | IP, user agent, MFA |
| Scan trigger | ✅ | User, repo, branch, job_id |
| Baseline approve | ✅ | User, scan_id |
| Drift ack/resolve/FP | ✅ | User, drift_id, notes |
| CBOM ingest/verify | ✅ | User, system, signature result |
| Graph sync/snapshot | ✅ | User, version, fingerprint |
| User management | ✅ | Actor, target user, role changes |
| API key ops | ✅ | Actor, key_id, scopes |

### 12.2 Missing Audit

| Operation | Missing |
|-----------|---------|
| Graph queries (blast-radius, vendor-chain) | No read audit |
| CBOM portfolio/nbom generation | No read audit |
| Config changes (settings, tenancy) | Partial |
| Report generation | No audit |

---

## 13. SUMMARY: API CONTRACT HEALTH

| Category | Score | Issues |
|----------|-------|--------|
| Authentication | 8/10 | Dual-mode works, MFA good |
| Authorization | 6/10 | No resource-level, API key gaps |
| Validation | 8/10 | Pydantic everywhere, minor gaps |
| Error Handling | 5/10 | Inconsistent formats, no RFC 9457 |
| Rate Limiting | 6/10 | Works for REST, missing WS/SSE |
| Tenant Isolation | 5/10 | Middleware only, gaps in graph/link tables |
| Pagination | 7/10 | Works, no cursor, inconsistent limits |
| Error Responses | 4/10 | Inconsistent shapes, no RFC 9457 |
| Versioning | 2/10 | No strategy, single version |
| Documentation | 3/10 | ~40% coverage in API reference |
| Audit Logging | 7/10 | Good for mutations, missing reads |
| Rate Limiting | 6/10 | REST only, no WS/SSE |

**Overall API Contract Score: 6/10** — Functional but inconsistent, not enterprise-grade without fixes.

---

## 14. RECOMMENDATIONS

### P0 — Critical

1. **Standardize error responses** — RFC 9457 Problem Details format
2. **Add resource-level authorization** — Check ownership on every mutating operation
3. **Fix API key authorization** — Check key roles against `PERMISSION_MATRIX`
4. **Implement tenant isolation in Neo4j** — Separate DBs or namespace

### P1 — High

5. **Standardize error response format** — All routers return RFC 9457
6. **Add cursor-based pagination** — For large datasets (CBOM portfolio, evidence)
7. **Add sorting to all list endpoints** — Consistent `sort_by`, `sort_desc`
8. **Document all endpoints in OpenAPI** — Generate from code, not manual

### P2 — Medium

9. **Implement API versioning strategy** — URL versioning + deprecation headers
10. **Add cursor pagination** — For CBOM portfolio, evidence, graph
11. **Rate limit WebSocket/SSE** — Connection limits + message rates
12. **Standardize path naming** — Hyphens only, consistent verbs

### P3 — Enhancement

13. **Add request/response examples** in OpenAPI
14. **Implement API deprecation headers** — `Deprecation`, `Sunset`
15. **Add client SDK generation** — From OpenAPI spec
16. **Add request ID correlation** — Already in middleware, expose in errors
---

## Round 26 update (2026-10-10) — claims re-verified

* **P0#2 (resource-level authorization) — STALE.** Resource-level grants
  shipped round 18 (migration 0076, per-system enforcement + admin
  endpoints); BU → System → Asset inheritance landed round 22.
* **P0#3 (API key authorization) — STALE.** Machine keys carry their own
  `role_list` from the key row (never the users table) and flow through
  the same `require_permission` matrix as sessions, with IP allow/deny
  policy and last-use stamping.
* **P1#8 (OpenAPI documentation) — STALE.** The spec is generated from
  code; operationId contract tests exist since round 17.
* **Remain open, product-scoped:** RFC 9457 error shapes, cursor
  pagination, API versioning/deprecation headers, WS/SSE rate limits,
  Neo4j tenant isolation, read-path auditing (a volume/policy decision).
