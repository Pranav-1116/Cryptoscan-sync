/* End-to-end API bridge — every call goes to the live backend through
   the Vite /api proxy (FastAPI control plane on :8010). There is no demo or
   fallback dataset: when the backend is unreachable the result is tagged
   source:"offline" with data:null and the UI renders zeros/empty. */

export type ApiSource = "live" | "offline";

export interface ApiResult<T = unknown> {
  source: ApiSource;
  data: T | null;
  error?: string;
  ok?: boolean;
  head?: string;
}

let backendLive: boolean | null = null;
let checked = false;
const TOKEN_KEY = "zelinx_token";

export function getToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

const ROLES_KEY = "zelinx_roles";
const USER_KEY = "zelinx_user";

export function getRoles(): string[] {
  try { return JSON.parse(localStorage.getItem(ROLES_KEY) || "[]"); } catch { return []; }
}

export function getUserName(): string | null {
  try { return localStorage.getItem(USER_KEY); } catch { return null; }
}

export function setUserName(name: string | null): void {
  try {
    if (name) localStorage.setItem(USER_KEY, name);
    else localStorage.removeItem(USER_KEY);
  } catch { /* ignore */ }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(ROLES_KEY); localStorage.removeItem(USER_KEY); }
  } catch { /* storage unavailable — session only */ }
  // realtime consumers (SSE stream) reconnect when auth changes
  try {
    window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: !!token } }));
  } catch { /* non-browser context */ }
}

export async function isBackendLive(): Promise<boolean> {
  if (backendLive !== null) return backendLive;
  if (!checked) {
    checked = true;
    try {
      const resp = await fetch("/api/v1/platform/scope", { signal: AbortSignal.timeout(2500) });
      // 200 = fully live · 401 = live but needs a token — both prove reachability
      backendLive = resp.status < 500;
    } catch {
      backendLive = false;
    }
  }
  return backendLive === true;
}

async function call<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(path, {
      signal: AbortSignal.timeout(8000),
      headers,
      // send the httpOnly session cookie too (server auth via cookie, not only
      // the XSS-readable Bearer token in localStorage)
      credentials: "include",
      ...init,
    });
    if (!resp.ok) return { source: "offline", data: null, error: `HTTP ${resp.status}` };
    return { source: "live", data: (await resp.json()) as T };
  } catch (e) {
    return { source: "offline", data: null, error: String(e) };
  }
}

export async function apiLogin(username: string, password: string): Promise<{ ok: boolean; error?: string; roles?: string[] }> {
  try {
    const resp = await fetch("/api/v1/auth/login", {
      method: "POST",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      credentials: "include",
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    }
    const body = (await resp.json()) as { token?: string; roles?: string[]; username?: string };
    if (body.token) {
      setToken(body.token);
      try {
        localStorage.setItem("zelinx_roles", JSON.stringify(body.roles || []));
        localStorage.setItem("zelinx_user", body.username || username);
      } catch { /* ignore */ }
    }
    return { ok: !!body.token, error: body.token ? undefined : "no token in response", roles: body.roles };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/* Self-service registration — picks one of the 8 RBAC roles
   (POST /api/v1/auth/register; superadmin is admin-assigned only). */
export async function apiRegister(input: {
  username: string;
  password: string;
  role: string;
  display_name?: string;
  email?: string;
}): Promise<{ ok: boolean; error?: string; username?: string; roles?: string[] }> {
  try {
    const resp = await fetch("/api/v1/auth/register", {
      method: "POST",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      credentials: "include",
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, username: body.username, roles: body.roles };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/* Server-truth session (security hardening): refresh the current user + roles
   from GET /auth/me (backed by the httpOnly session cookie) instead of trusting
   the XSS-readable token/roles cached in localStorage. localStorage remains a
   fast display cache only; authorization is always enforced server-side. */
export async function apiAuthMe(): Promise<{ username?: string; roles?: string[] } | null> {
  const r = await _rsGet<{ username?: string; roles?: string[] }>("/api/v1/auth/me");
  return r.ok && r.data ? r.data : null;
}

export async function syncSession(): Promise<{ user: string | null; roles: string[] }> {
  try {
    const me = await apiAuthMe();
    if (me && me.username) {
      const roles = me.roles || [];
      setUserName(me.username);
      try { localStorage.setItem(ROLES_KEY, JSON.stringify(roles)); } catch { /* ignore */ }
      try { window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: !!getToken() } })); } catch { /* non-browser */ }
      return { user: me.username, roles };
    }
    if (me && me.roles) {
      try { localStorage.setItem(ROLES_KEY, JSON.stringify(me.roles)); } catch { /* ignore */ }
    }
  } catch { /* session not available — fall back to cached profile */ }
  return { user: getUserName(), roles: getRoles() };
}

/* ── platform endpoints (contracts in api/routers/platform.py) ─────── */

export const apiScope = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/scope");

export const apiDiscover = (domains: Record<string, unknown>, intervalSeconds = 3600): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/discover", { method: "POST", body: JSON.stringify({ domains, interval_seconds: intervalSeconds }) });

export const apiBom = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/bom");

export const apiDrift = (baseline: Record<string, unknown>, live: Record<string, unknown>): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/drift", { method: "POST", body: JSON.stringify({ baseline, live }) });

export const apiRisk = (asset?: string): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/risk", { method: "POST", body: JSON.stringify(asset ? { asset } : {}) });

export const apiBlast = (seed: string, maxDepth = 10): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/blast", { method: "POST", body: JSON.stringify({ seed, max_depth: maxDepth }) });

export const apiWhatIf = (current: string, target: string, protocols?: string[]): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/whatif", { method: "POST", body: JSON.stringify({ current, target, protocols }) });

export const apiSecurity = (request: Record<string, unknown>): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/security", { method: "POST", body: JSON.stringify({ request }) });

export const apiEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/evidence");

/* ── sector layer (universal engine + sector profiles) ─────────────── */

export interface SectorProfile {
  id: string;
  name: string;
  description: string;
  policy_packs: string[];
  compliance_frameworks: string[];
  recommended_modes?: Array<{ id: string; name: string; ot_safe?: boolean }>;
  critical_asset_classes?: string[];
  required_evidence?: string[];
  integrations?: string[];
  environment_separation?: string[];
  scanning_notes?: string[];
}

export const apiListSectors = (): Promise<ApiResult<{ sectors: SectorProfile[]; count: number }>> =>
  call("/api/v1/sectors");

export const apiActiveSector = (): Promise<ApiResult<{ sector: string; profile: SectorProfile }>> =>
  call("/api/v1/sectors/organization/active");

export async function apiSetActiveSector(sector: string): Promise<{ ok: boolean; error?: string; sector?: string }> {
  try {
    const resp = await fetch("/api/v1/sectors/organization/active", {
      method: "PUT",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ sector }),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, sector: body.sector };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

export const apiSectorQuantumRisk = (sector?: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/sectors/quantum-risk${sector ? `?sector=${encodeURIComponent(sector)}` : ""}`);

export const apiSectorComplianceMap = (
  findings: Record<string, unknown>[],
  sector?: string,
): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sectors/compliance-map", {
    method: "POST",
    body: JSON.stringify({ sector, findings }),
  });

/* ----------------------------- onboarding ------------------------------- */
/* Enterprise setup journey: org -> sector -> environment -> authorized scope
   -> connections -> test access -> start discovery. Secrets are NEVER sent;
   connectors store non-secret references only (grant access out-of-band). */

export interface OnboardingOrg {
  id: string; name: string; sector: string; onboarding_stage: string;
  onboarding_complete?: boolean; industry?: string | null; regions?: string[];
}
export interface OnboardingEnv {
  id: string; name: string; env_type: string; scan_mode: string;
  active_probing: boolean; region?: string | null;
  maintenance_window_enabled?: boolean; maintenance_timezone?: string | null;
  maintenance_windows?: MaintenanceWindow[] | null;
}
export interface ScopeEntryItem { id: string; kind: string; target: string }
export interface OnboardingConn {
  id: string; kind: string; name: string; method: string; mode: string;
  status: string; agent_healthy?: boolean; agent_id?: string | null;
  agent_link?: string | null; agent_version?: string | null; agent_last_seen_at?: string | null;
  test_result?: { checks?: { check: string; ok: boolean; detail: string }[]; all_ok?: boolean } | null;
}
export interface OnboardingState {
  organization: OnboardingOrg | null;
  sector_context?: {
    sector: string; recommended_modes?: string[]; policy_packs?: string[];
    compliance_frameworks?: string[];
  } | null;
  environments: OnboardingEnv[];
  scope: { total: number; counts: Record<string, number>; entries?: ScopeEntryItem[] };
  connections: OnboardingConn[];
  connected_count: number;
  stage: string;
  ready: boolean;
  checklist: { step: string; label: string; done: boolean }[];
}
export interface MaintenanceWindow { day: string; start: string; duration_minutes: number }
export interface DiscoveryPlan {
  run_id: string; status: string; organization: string; sector: string;
  environments: number;
  plan: { domain: string; targets: number | string; mode: string }[];
  registered?: { cloud_accounts: number; network_targets: number; repo_configs: number };
  assets_estimate?: number;
  authorized_scope: Record<string, number>;
  connectors_used: string[];
  next_steps: string[];
}
export interface DiscoveryRun {
  id: string; status: string; run_type: string; assets_discovered: number;
  targets_registered: number; summary?: Record<string, unknown> | null;
  started_at?: string | null; finished_at?: string | null;
  plan?: { domains?: { domain: string; targets: number | string; mode: string }[] } | null;
  created_at: string;
}

export const apiOnboardingState = (): Promise<ApiResult<OnboardingState>> =>
  call("/api/v1/onboarding/state");

export const apiOnboardingScope = (): Promise<ApiResult<{ total: number; counts: Record<string, number> }>> =>
  call("/api/v1/onboarding/scope");

export const apiCreateOrg = (name: string, sector: string, industry?: string): Promise<ApiResult<OnboardingOrg>> =>
  call("/api/v1/onboarding/organization", {
    method: "POST",
    body: JSON.stringify({ name, sector, ...(industry ? { industry } : {}) }),
  });

export const apiAddEnv = (
  body: { name: string; env_type: string; scan_mode?: string; active_probing?: boolean; region?: string },
): Promise<ApiResult<OnboardingEnv>> =>
  call("/api/v1/onboarding/environments", { method: "POST", body: JSON.stringify(body) });

export const apiAddScope = (
  kind: string, target: string, env_id?: string,
): Promise<ApiResult<ScopeEntryItem>> =>
  call("/api/v1/onboarding/scope", {
    method: "POST",
    body: JSON.stringify({ kind, target, ...(env_id ? { env_id } : {}) }),
  });

export const apiAddConnection = (body: {
  kind: string; name: string; method?: string; mode?: string; config?: Record<string, string>; env_id?: string;
}): Promise<ApiResult<OnboardingConn>> =>
  call("/api/v1/onboarding/connections", { method: "POST", body: JSON.stringify(body) });

export const apiTestConnection = (
  id: string,
): Promise<ApiResult<{ connector_id: string; status: string; all_ok: boolean; checks: { check: string; ok: boolean; detail: string }[] }>> =>
  call(`/api/v1/onboarding/connections/${id}/test`, { method: "POST" });

export const apiStartDiscovery = (): Promise<ApiResult<DiscoveryPlan>> =>
  call("/api/v1/onboarding/discovery/start", { method: "POST" });

export const apiListDiscoveryRuns = (): Promise<ApiResult<{ runs: DiscoveryRun[] }>> =>
  call("/api/v1/onboarding/discovery/runs");

export const apiUpdateEnvironment = (
  id: string,
  body: {
    scan_mode?: string; active_probing?: boolean; enabled?: boolean;
    maintenance_window_enabled?: boolean; maintenance_timezone?: string;
    maintenance_windows?: MaintenanceWindow[];
  },
): Promise<ApiResult<OnboardingEnv>> =>
  call(`/api/v1/onboarding/environments/${id}`, { method: "PATCH", body: JSON.stringify(body) });

const deleteCall = async (path: string): Promise<{ ok: boolean; error?: string }> => {
  try {
    const resp = await fetch(path, {
      method: "DELETE",
      signal: AbortSignal.timeout(8000),
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
    });
    if (!resp.ok && resp.status !== 204) return { ok: false, error: `HTTP ${resp.status}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
};

export const apiDeleteScope = (id: string) => deleteCall(`/api/v1/onboarding/scope/${id}`);
export const apiDeleteConnection = (id: string) => deleteCall(`/api/v1/onboarding/connections/${id}`);

/* ── live control-plane / enterprise surfaces (realtime environment) ── */

/** Live dashboard summary from the database (scans/findings/drift/coverage). */
export const apiStatsSummary = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/stats/summary");

/** Most-recent runtime crypto findings (the live 24/7 engine). */
export const apiRuntimeFindings = (limit = 50): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/scans/runtime-findings?limit=${limit}`);

/* ── evidence findings (GET /api/v1/findings, /api/v1/findings/{evidence_id}) ── */

export interface Finding {
  evidence_id: string;
  scan_id: string;
  algorithm: string;
  key_size?: number | null;
  mode?: string | null;
  padding?: string | null;
  purpose?: string | null;
  confidence: string;
  is_hardcoded_key: boolean;
  file_path: string;
  line_number: number;
  class_name?: string | null;
  method_name?: string | null;
  compliance_status?: string | null;
  content_hash: string;
  chain_hash: string;
  normalized_crypto?: Record<string, unknown> | null;
  policy_evaluation?: Record<string, unknown> | null;
  finding_data?: Record<string, unknown> | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface FindingList {
  findings: Finding[];
  total_count: number;
  page: number;
  page_size: number;
}

/** Paginated list of evidence-chain findings. */
export const apiFindings = (params: {
  page?: number;
  page_size?: number;
  algorithm?: string;
  compliance_status?: string;
  scan_id?: string;
} = {}): Promise<ApiResult<FindingList>> => {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  if (params.algorithm) q.set("algorithm", params.algorithm);
  if (params.compliance_status) q.set("compliance_status", params.compliance_status);
  if (params.scan_id) q.set("scan_id", params.scan_id);
  const qs = q.toString();
  return call(`/api/v1/findings${qs ? `?${qs}` : ""}`);
};

/** A single finding (full detail incl. normalized_crypto / policy_evaluation). */
export const apiFindingDetail = (evidenceId: string): Promise<ApiResult<Finding>> =>
  call(`/api/v1/findings/${encodeURIComponent(evidenceId)}`);

/** Trigger a universal source scan (POST /api/v1/scans/trigger → 202).
    Requires one of the auditor/admin roles. Runs the worker pipeline and
    persists evidence-chain findings. */
export interface TriggerScanResult { job_id: string; status: string; created_at: string; message: string; }
export async function apiTriggerScan(input: {
  repo_url: string;
  branch?: string;
  sector?: string;
  scan_mode?: string;
}): Promise<{ ok: boolean; error?: string; job_id?: string; status?: string; message?: string }> {
  try {
    const resp = await fetch("/api/v1/scans/trigger", {
      method: "POST",
      signal: AbortSignal.timeout(15000),
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ repo_url: input.repo_url, branch: input.branch || "main", sector: input.sector, scan_mode: input.scan_mode }),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, job_id: body.job_id, status: body.status, message: body.message };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/** Live runtime findings from the 24/7 engine (GET /api/v1/scans/runtime-findings). */
export interface RuntimeFindingRow {
  id: string;
  hostname?: string | null;
  process_name?: string | null;
  pid?: number | null;
  tls_version?: string | null;
  cipher_suite?: string | null;
  algorithm?: string | null;
  key_size?: number | null;
  status?: string | null;
  quantum_impact?: string | null;
  weak_tls?: boolean;
  observation_count?: number;
  last_seen_at?: string | null;
}
export interface RuntimeFindingsResponse {
  summary?: Record<string, unknown>;
  total_count: number;
  findings: RuntimeFindingRow[];
}

// ── Realtime scanner control (runs the actual scanner CLIs server-side) ──
export interface LiveScanStatus {
  running: boolean;
  last_run_at: string | null;
  periodic: { enabled: boolean; interval_seconds: number };
  scanners: Record<string, {
    ok: boolean | null;
    elapsed_s?: number;
    summary?: Record<string, unknown>;
    error?: string;
  }>;
  ok_count: number;
  failed_count: number;
}

export const apiLiveScanStatus = (): Promise<ApiResult<LiveScanStatus>> =>
  call(`/api/v1/live-scan/status`);

export const apiLiveScanRun = (body: {
  scanners?: string[];
  network_target?: string;
  network_full?: boolean;
  container_target?: string;
  ot_logs?: string;
  cloud_live?: boolean;
  source_target?: string;
  universal_target?: string;
}): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/live-scan/run`, { method: "POST", body: JSON.stringify(body) });

export const apiLiveScanStart = (intervalSeconds = 900): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/live-scan/start`, { method: "POST", body: JSON.stringify({ interval_seconds: intervalSeconds }) });

export const apiLiveScanStop = (): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/live-scan/stop`, { method: "POST", body: JSON.stringify({}) });

// Page-ready live inventory for dashboards (hardware/network/libraries).
export interface LiveHardwareDevice {
  id: string; type: string; vendor: string; firmware: string;
  caps: string[]; host: string; status: string;
}
export interface LiveNetworkAsset {
  kind: string; id: string; ip: string; tls: string; certs: string[];
  os: string; status: string; cert_expiry_days?: number; chain_valid?: boolean;
}
export interface LiveLibrary {
  name: string | null; version: string | null; status: string | null;
  package: string | null; processes?: number | null;
}
export interface LiveCertificate {
  cn: string; sig: string; key: string; days: number | null;
  san: string; eku: string; owner: string; status: string;
  endpoint: string; chain_position: number; chain_length: number;
}
export interface LiveProcess {
  pid: number | null; process: string | null; runtime: string | null;
  tls_libraries: string[]; listening_ports: number[];
  containerized: boolean | null; status: string;
}
export interface LiveInventory {
  generated_at: string | null;
  host: string | null;
  counts: { hardware_devices: number; network_assets: number; libraries: number; certificates: number; processes: number };
  hardware: LiveHardwareDevice[];
  firmware: Array<{ device: string; kind: string; version: string; status: string }>;
  network: LiveNetworkAsset[];
  certificates: LiveCertificate[];
  cert_center: { expired: number; expiring30: number; weak_algorithm: number; unknown_owner: number; total: number };
  libraries: LiveLibrary[];
  processes: LiveProcess[];
  scans?: Record<string, { summary: Record<string, unknown>; elapsed_s?: number }>;
}
export const apiLiveInventory = (): Promise<ApiResult<LiveInventory>> =>
  call(`/api/v1/live-scan/inventory`);

// ── Unified Asset Inventory (CMDB) ──
// One authoritative, deduplicated inventory across systems, crypto assets,
// certificates, cloud, hardware, vendors, business processes, owners and
// network targets. Every row is persisted real data; missing fields read null.
export interface CmdbAsset {
  id: string;
  asset_type: string;
  name: string | null;
  risk: string | null;
  pqc: string | null;
  criticality?: string | null;
  environment?: string | null;
  owner?: string | null;
  business_unit?: string | null;
  cloud_provider?: string | null;
  algorithm?: string | null;
  purpose?: string | null;
  key_size?: number | null;
  confidence?: string | null;
  file_path?: string | null;
  source_language?: string | null;
  subject?: string | null;
  issuer?: string | null;
  public_key_algorithm?: string | null;
  public_key_size?: number | null;
  expiry_status?: string | null;
  days_until_expiry?: number | null;
  manufacturer?: string | null;
  model?: string | null;
  device_type?: string | null;
  serial_reference?: string | null;
  endpoint?: string | null;
  scan_frequency?: string | null;
  vendor_type?: string | null;
  process_type?: string | null;
  [k: string]: unknown;
}
export interface CmdbInventory {
  assets: CmdbAsset[];
  count: number;
  source: string;
}
export interface CmdbSummary {
  total: number;
  by_type: Record<string, number>;
  by_risk: Record<string, number>;
  by_pqc: Record<string, number>;
  source: string;
}
export const apiInventory = (): Promise<ApiResult<CmdbInventory>> =>
  call(`/api/v1/inventory/assets`);
export const apiInventorySummary = (): Promise<ApiResult<CmdbSummary>> =>
  call(`/api/v1/inventory/summary`);

// ── Unified Risk Engine (#3) ──
export interface UnifiedRiskAsset {
  id: string;
  name: string | null;
  asset_type: string;
  score: number;
  level: string;
  factors: Record<string, { level: number; points: number; weight: number }>;
  missing: string[];
}
export interface UnifiedRiskEstate {
  score: number;
  level: string;
  count: number;
  by_level: Record<string, number>;
}
export interface UnifiedRiskResponse {
  assets: UnifiedRiskAsset[];
  count: number;
  estate: UnifiedRiskEstate;
  factors: string[];
  source: string;
}
export const apiUnifiedRisk = (params?: { asset_type?: string; risk?: string }): Promise<ApiResult<UnifiedRiskResponse>> => {
  const q = new URLSearchParams();
  if (params?.asset_type) q.set("asset_type", params.asset_type);
  if (params?.risk) q.set("risk", params.risk);
  const qs = q.toString();
  return call(`/api/v1/risk/unified${qs ? `?${qs}` : ""}`);
};

// ── Scope & Authorization + Multi-Tenant isolation (#2, #11) ──
export interface ScopeEnvelope {
  org_id: string | null;
  tenant: string | null;
  allowed_targets: Record<string, string[]>;
  allowed_methods: string[];
  read_only: boolean;
  exclusions: string[];
  rate_limit: { max: number; window_seconds: number };
  scanner: string | null;
  maintenance_window_open: boolean;
}
export const apiScopeEnvelope = (): Promise<ApiResult<ScopeEnvelope>> =>
  call(`/api/v1/scope/envelope`);
export const apiScopeAuthorize = (target: string, kind?: string, method?: string, mutating = false): Promise<ApiResult<{ decision: { allowed: boolean; reason: string }; scope: ScopeEnvelope }>> => {
  const q = new URLSearchParams({ target });
  if (kind) q.set("kind", kind);
  if (method) q.set("method", method);
  if (mutating) q.set("mutating", "true");
  return call(`/api/v1/scope/authorize?${q.toString()}`);
};
export interface TenantIsolation {
  source: string;
  enforced: boolean;
  tenants: { id: string; name: string; sector: string }[];
  current_tenant: string;
  authorized_scope: ScopeEnvelope;
  scope_entry_count: number;
  connector_count: number;
  maintenance_window_open: boolean;
}
export const apiTenantIsolation = (): Promise<ApiResult<TenantIsolation>> =>
  call(`/api/v1/scope/tenant/isolation`);

// ── Connector Framework / SDK (#13) ──
export interface ConnectorRegistered {
  kind: string;
  method: string;
  mode: string;
  name: string;
}
export interface ConnectorCatalog {
  source: string;
  registered: ConnectorRegistered[];
  catalog_kinds: string[];
  catalog_methods: string[];
}
export const apiConnectorCatalog = (): Promise<ApiResult<ConnectorCatalog>> =>
  call(`/api/v1/connectors/sdk`);

// ── Live Scanning flow / SCAN ORCHESTRATOR (one product) ──
export interface LiveDomainCounts {
  network: number;
  hardware: number;
  vendor: number;
  crypto: number;
  certificate: number;
  application: number;
  total: number;
}
export interface LiveGraphSummary {
  node_count?: number;
  edge_count?: number;
  by_kind?: Record<string, number>;
  backend?: string | null;
  note?: string;
}
export interface OrchestratorScan {
  scan_id: string;
  org_id: string;
  org_name: string;
  phase: string;
  status: string;
  started_at: string;
  scope_validated: boolean;
  targets: Record<string, string[]>;
  credentials: Record<string, boolean>;
  progress: Record<string, number>;
  error: string | null;
  domain_counts: Record<string, number>;
}
export interface ScanRunSummary {
  scan_id: string;
  phase: string | null;
  status: string;
  started_at: string | null;
  ended_at: string | null;
  progress: Record<string, number>;
  error: string | null;
  scope_validated: boolean | null;
  events: string[];
}
export interface LiveEnvironmentResponse {
  source: string;
  domains: LiveDomainCounts;
  graph: LiveGraphSummary;
  events: { events: { id: number; ts: string; type: string; payload: Record<string, unknown> }[]; latest_id: number; subscribers: number };
  scan: OrchestratorScan | null;
  runner: { running: boolean } | null;
}
export const apiLiveEnvironment = (): Promise<ApiResult<LiveEnvironmentResponse>> =>
  call(`/api/v1/live/environment`);
export const apiLiveOrchestratorStatus = (): Promise<ApiResult<{ scan: OrchestratorScan | null; source: string; runner: { running: boolean } }>> =>
  call(`/api/v1/live/orchestrator/status`);
export const apiLiveOrchestratorStart = (scanners?: string[]): Promise<ApiResult<{ status: string; scan: OrchestratorScan }>> => {
  const q = scanners?.length ? `?${scanners.map((s) => `scanners=${encodeURIComponent(s)}`).join("&")}` : "";
  return call(`/api/v1/live/orchestrator/start${q}`, { method: "POST" });
};
export const apiLiveOrchestratorHistory = (): Promise<ApiResult<{ source: string; runs: ScanRunSummary[] }>> =>
  call(`/api/v1/live/orchestrator/history`);

// ── Security & Scanning Policy + unified scanner gate (§25 / §21) ──
export interface ScanPolicyView {
  mode: string;
  intensity: string;
  max_concurrent_jobs: number;
  max_targets_per_scan: number;
  max_connections: number;
  rate_limit_qps: number;
  rate_limit_per_minute: number;
  scan_timeout_seconds: number;
  retry_limit: number;
  production_protection: boolean;
  hsm_protection: boolean;
  require_special_approval: boolean;
  maintenance_window_start: string;
  maintenance_window_end: string;
}
export interface PrivacyPolicyView {
  collect_pii: boolean;
  collect_private_keys: boolean;
  collect_secrets: boolean;
  redact_secrets: boolean;
  mask_sensitive_fields: boolean;
  tokenize_identifiers: boolean;
  enforce_payload_limits: boolean;
  max_payload_bytes: number;
  retention_days: number;
  data_minimization: boolean;
  alert_on_private_key: boolean;
  allow_evidence_metadata: boolean;
}
export interface SecurityPolicy {
  scan: ScanPolicyView;
  privacy: PrivacyPolicyView;
}
export const apiSecurityPolicyGet = (): Promise<ApiResult<{ source: string; policy: SecurityPolicy; sector: string | null }>> =>
  _rsGet("/api/v1/security/policy");
export const apiSecurityPolicyPut = (policy: SecurityPolicy): Promise<ApiResult<{ source: string; updated: boolean; policy: SecurityPolicy; sector: string | null }>> =>
  _rsPut("/api/v1/security/policy", policy);
export const apiSecurityGate = (req: {
  actor?: string; tenant?: string; environment?: string; sector?: string;
  targets?: Record<string, string[]>; credentials?: Record<string, boolean>;
  scanners?: string[]; scope?: Record<string, unknown>;
}): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost("/api/v1/security/gate", req);

/* ── Security-intelligence decision engines (deterministic, read-mostly) ──
   These wrap the pure modules the backend exposes under /security/intelligence:
   universal asset identity (#1), scan profiles (#8), finding dedup + risk chain
   (#21/#22), verification/freshness state (#23/#24/#25) and scan triggers
   (#10/#11/#12). */

export interface ScanProfileView {
  id: string;
  name: string;
  description: string;
  mode: string;
  intensity: string;
  schedule: string;
  scope: Record<string, unknown>;
  data_collection: string;
  limit: Record<string, unknown>;
  sectors: string[];
}
export interface ScanProfileResolve {
  profile: ScanProfileView;
  policy: { scan: ScanPolicyView; privacy: PrivacyPolicyView };
  limits: Record<string, unknown>;
  sector: string | null;
}
export const apiScanProfiles = (): Promise<ApiResult<{ profiles: ScanProfileView[]; count: number }>> =>
  _rsGet("/api/v1/security/profiles");
export const apiScanProfileResolve = (req: {
  profile: string; sector?: string | null;
  scan?: Record<string, unknown>; privacy?: Record<string, unknown>; limits?: Record<string, unknown>;
}): Promise<ApiResult<ScanProfileResolve>> =>
  _rsPost("/api/v1/security/profiles/resolve", req);

export interface IdentityAsset {
  id: string;
  asset_type: string;
  source: string;
  aliases: string[];
  sources: string[];
  first_seen: string | null;
  last_seen: string | null;
}
export const apiIdentityResolve = (req: {
  observations: { source: string; ids: Record<string, string>; attrs?: Record<string, unknown>; observed_at?: string | null }[];
}): Promise<ApiResult<{ assets: IdentityAsset[]; aliases: Record<string, string>; merges: number; observations: number }>> =>
  _rsPost("/api/v1/security/intelligence/identity/resolve", req);

export const apiCorrelateFindings = (req: { findings: Record<string, unknown>[] }): Promise<ApiResult<{
  deduplicated: Record<string, unknown>[]; count: number; inputs: number; deduped_by: number; source: string;
}>> =>
  _rsPost("/api/v1/security/intelligence/correlate", req);

export const apiRiskChain = (req: {
  asset_id: string; findings: Record<string, unknown>[]; critical_asset?: boolean; business_value?: string;
}): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost("/api/v1/security/intelligence/chain", req);

export const apiAssetState = (req: {
  sources?: Record<string, string>; verification?: string; last_seen_epoch?: number | null; now?: number; verified?: boolean;
}): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost("/api/v1/security/intelligence/state", req);

export const apiScanSchedule = (req: {
  cadence?: string; event?: string; scan_type?: string; baseline_at?: number | null; now?: number; changed_assets?: string[];
}): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost("/api/v1/security/intelligence/schedule", req);

// ── Certificate expiry calendar (SLA-tiered, deterministic) ──
export interface ExpiryCalendarEntry {
  subject: string | null;
  fingerprint_sha256: string | null;
  issuer: string | null;
  not_after: string | null;
  days_until_expiry: number | null;
  severity: string;
  renewal_status: string | null;
  renewal_ticket: string | null;
  usages: unknown[];
}
export interface ExpiryCalendar {
  generated_at: string;
  sla_tiers: Record<string, string>;
  counts: Record<string, number>;
  total_tracked: number;
  actionable_count: number;
  healthy_count: number;
  buckets: Record<string, ExpiryCalendarEntry[]>;
}
export const apiExpiryCalendar = (): Promise<ApiResult<ExpiryCalendar>> =>
  call(`/api/v1/certificates/expiry-calendar`);

// ── Canonical catalogs (algorithms · network protocols · hardware) ──
export interface AlgorithmEntry {
  algorithm: string; family: string; status: string;
  key_size?: number | null; parameter_kind?: string | null;
  quantum_impact?: string | null; quantum_vulnerable?: boolean;
  notes?: string; recognized?: boolean;
}
export interface ProtocolEntry {
  protocol: string; category: string; status: string;
  port?: number | null; transport?: string; encrypted?: boolean;
  cleartext?: boolean; exposure?: string; notes?: string;
  risk_reason?: string; recognized?: boolean;
}
export interface HardwareEntry {
  device: string; category: string; status: string;
  manufacturer?: string; quantum_resistant?: boolean; attestation?: boolean;
  notes?: string; risk_reason?: string; recognized?: boolean;
}
export interface CatalogResult<T> {
  count: number;
  total_count?: number;
  status_counts: Record<string, number>;
  counts_by_status?: Record<string, number>;
  protocols?: T[]; devices?: T[]; algorithms?: T[];
  families?: string[];
}

export const apiAlgorithmCatalog = (params?: { family?: string; status?: string; q?: string }): Promise<ApiResult<CatalogResult<AlgorithmEntry> & { algorithms: AlgorithmEntry[] }>> => {
  const qs = new URLSearchParams();
  if (params?.family) qs.set("family", params.family);
  if (params?.status) qs.set("status", params.status);
  if (params?.q) qs.set("q", params.q);
  const s = qs.toString();
  return call(`/api/v1/algorithms${s ? `?${s}` : ""}`);
};
export const apiProtocolCatalog = (params?: { category?: string; status?: string }): Promise<ApiResult<CatalogResult<ProtocolEntry>>> => {
  const qs = new URLSearchParams();
  if (params?.category) qs.set("category", params.category);
  if (params?.status) qs.set("status", params.status);
  const s = qs.toString();
  return call(`/api/v1/network/protocols${s ? `?${s}` : ""}`);
};
export const apiHardwareCatalog = (params?: { category?: string; status?: string }): Promise<ApiResult<CatalogResult<HardwareEntry>>> => {
  const qs = new URLSearchParams();
  if (params?.category) qs.set("category", params.category);
  if (params?.status) qs.set("status", params.status);
  const s = qs.toString();
  return call(`/api/v1/hardware/catalog${s ? `?${s}` : ""}`);
};

// ── Cloud accounts (read-only; scans never write) ──
export interface CloudAccount {
  cloud_provider?: string; provider?: string;
  account_identifier?: string; account_id?: string;
  role_arn?: string; regions?: string[] | string; enabled?: boolean;
  status?: string; [k: string]: unknown;
}
export const apiCloudAccounts = (): Promise<ApiResult<{ accounts: CloudAccount[] }>> =>
  call(`/api/v1/cloud/accounts`);

export interface LiveAlert {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  scanner: string;
  kind: string;
  title: string;
  detail: string;
  asset: string;
  ts: string | null;
}
export interface LiveAlertsResponse {
  generated_at: string | null;
  counts: Record<string, number>;
  alerts: LiveAlert[];
  total: number;
}
export const apiLiveAlerts = (): Promise<ApiResult<LiveAlertsResponse>> =>
  call(`/api/v1/live-scan/alerts`);

export interface LiveDriftChange {
  severity: string; scanner: string; kind: string; title: string; detail: string; asset?: string;
}
export interface LiveDriftResponse {
  baseline: boolean;
  ts: string | null;
  previous_ts?: string | null;
  changes: LiveDriftChange[];
  change_count: number;
}
export const apiLiveDrift = (): Promise<ApiResult<LiveDriftResponse>> =>
  call(`/api/v1/live-scan/drift`);

export interface LiveBomComponent {
  type: string; name: string; version: string | null; ref?: string | null;
  quantum_status?: string | null; migration_priority?: string | null;
  classical_status?: string | null; status?: string | null;
  source: string; algorithms?: string[]; deprecated?: boolean; caps?: string[];
}
export interface LiveBomResponse {
  generated_at: string | null;
  cbom: { components: LiveBomComponent[]; counts: Record<string, number> };
  hbom: { components: LiveBomComponent[]; counts: Record<string, number> };
}
export const apiLiveBom = (): Promise<ApiResult<LiveBomResponse>> =>
  call(`/api/v1/live-scan/bom`);

/** The caller's effective ABAC scope (Region→BU→Environment→Asset grants). */
export const apiMyGrants = (): Promise<ApiResult<{ principal: string; roles: string[]; grants: Array<Record<string, unknown>>; count: number; abac_enforced: boolean }>> =>
  call("/api/v1/control/me/grants");

/** Registered SIEM/ITSM/CMDB integrations. */
export const apiIntegrations = (): Promise<ApiResult<{ integrations: Array<Record<string, unknown>> }>> =>
  call("/api/v1/enterprise/integrations");

/** Outbound webhook delivery audit trail (real SIEM/ITSM fan-out results). */
export const apiDeliveries = (): Promise<ApiResult<{ deliveries: Array<Record<string, unknown>>; stats: Record<string, number>; count: number }>> =>
  call("/api/v1/control/deliveries");

/** Fire a signed connectivity-test event at one integration (real HTTP). */
export async function apiTestIntegration(integrationId: string): Promise<{ ok: boolean; error?: string; status?: string; http_status?: number }> {
  try {
    const resp = await fetch(`/api/v1/enterprise/integrations/${integrationId}/test`, {
      method: "POST",
      signal: AbortSignal.timeout(15000),
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, status: body.status, http_status: body.http_status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/** Register an integration (no secrets — vault references only). */
export const apiRegisterIntegration = (body: {
  kind: string; provider: string; name: string; endpoint?: string; credential_id?: string;
}): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/enterprise/integrations", { method: "POST", body: JSON.stringify(body) });

/** Flush the durable SIEM/ITSM outbox — real signed HTTP delivery with retries. */
export async function apiFlushDeliveries(limit = 25): Promise<{ ok: boolean; error?: string; delivered?: number; failed?: number; events_flushed?: number }> {
  try {
    const resp = await fetch("/api/v1/control/deliveries/flush", {
      method: "POST",
      signal: AbortSignal.timeout(30000),
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ limit }),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, delivered: body.delivered, failed: body.failed, events_flushed: body.events_flushed };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/** Drive the orchestrator worker tick (drains the durable queue). */
export async function apiWorkerTick(batch = 10): Promise<{ ok: boolean; error?: string; processed?: number }> {
  try {
    const resp = await fetch("/api/v1/control/orchestrator/tick", {
      method: "POST",
      signal: AbortSignal.timeout(30000),
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ worker_id: "console", batch }),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, processed: body.processed };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/* React glue (useApi hook + LiveBadge) lives in apiUi.tsx */
export { useApi, LiveBadge } from "./apiUi.jsx";

/* ============================================================ P2 platform */
export async function apiP2Plugins(state?: string): Promise<ApiResult<any[]>> {
  try {
    const q = state ? `?state=${encodeURIComponent(state)}` : "";
    const resp = await fetch(`/api/v1/marketplace/plugins${q}`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: Array.isArray(body) ? body : body.plugins || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiP2AnomalyFlags(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch("/api/v1/anomaly/flags?limit=100", {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.flags || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiP2GovernanceRequests(status?: string): Promise<ApiResult<any[]>> {
  try {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    const resp = await fetch(`/api/v1/governance/requests${q}`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.requests || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiP2LakeBatches(lake = "primary"): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/datalake/batches?lake_id=${encodeURIComponent(lake)}`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.batches || [], head: body.head };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiP2ApiKeys(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/api-keys`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    const rows = Array.isArray(body) ? body : body.keys || body.items || [];
    return { source: "live", ok: true, data: rows };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/* ==================================================== OT safety + SLA + leases */
export async function apiOtMaintenanceWindows(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/ot/maintenance-windows`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.windows || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiSlaPosture(): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/sla/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json",
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ use_live: true }),
      signal: AbortSignal.timeout(20000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

export async function apiCredentialLeases(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/control/credential-leases`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.leases || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/* ============================================================ automation */
export async function apiAutomationRuns(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/automation/runs?limit=50`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.runs || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiAutomationRules(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/automation/rules`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.rules || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiAutomationCapabilities(): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/automation/capabilities`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

/* Create or update an automation rule (WHEN event · IF conditions · THEN actions). */
export async function apiAutomationSaveRule(body: Record<string, unknown>): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/automation/rules`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const rbody = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String((rbody as any).detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: rbody };
  } catch (e) { return { source: "live", ok: false, error: String(e) } as ApiResult<any>; }
}

/* Delete (disable) an automation rule. */
export async function apiAutomationDeleteRule(ruleId: string): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/automation/rules/${encodeURIComponent(ruleId)}`, {
      method: "DELETE",
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const rbody = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String((rbody as any).detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: rbody };
  } catch (e) { return { source: "live", ok: false, error: String(e) } as ApiResult<any>; }
}

export async function apiAutomationSectors(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/automation/sectors`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.sectors || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiCbomVersions(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/automation/cbom/versions?limit=20`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.versions || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

export async function apiHealthSweep(): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/automation/health/sweep`, {
      method: "POST",
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(20000),
      credentials: "include",
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

export async function apiPostMigrationValidate(payload: Record<string, unknown>): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/automation/post-migration/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(20000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

/* ── real detection benchmark (no AI; shipping detector vs ground truth) ── */
export async function apiRunRealBenchmark(): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/control/benchmark/run-real`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(60000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

export async function apiBenchmarkRuns(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/control/benchmark/runs`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`) } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.runs || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/* ============================================ P2 interactive action gates */
async function _postAction(path: string, body?: unknown): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(data.detail || `HTTP ${resp.status}`), data: null } as ApiResult<any>;
    return { source: "live", ok: true, data };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

/** Human approval gate: approve or deny a pending governance request (segregation of duties enforced server-side). */
export const apiGovernanceDecide = (requestPk: string, approve: boolean, note = "") =>
  _postAction(`/api/v1/governance/requests/${encodeURIComponent(requestPk)}/decide`, { approve, note });

/** Seal a new hash-chained lake batch from LIVE evidence findings. */
export const apiLakeExportLive = (lakeId = "primary", limit = 1000) =>
  _postAction(`/api/v1/datalake/export/live`, { lake_id: lakeId, kind: "findings", limit });

/** Cryptographically verify one lake batch + the whole hash chain. */
export const apiLakeVerify = (batchPk: string) =>
  _postAction(`/api/v1/datalake/verify/${encodeURIComponent(batchPk)}`);

/** Enable a marketplace plugin (fail-closed: quarantined/untrusted stays disabled). */
export const apiPluginEnable = (pluginPk: string) =>
  _postAction(`/api/v1/marketplace/plugins/${encodeURIComponent(pluginPk)}/enable`, {});

/** Disable a marketplace plugin. */
export const apiPluginDisable = (pluginPk: string) =>
  _postAction(`/api/v1/marketplace/plugins/${encodeURIComponent(pluginPk)}/disable`);

/** Acknowledge a statistical anomaly flag (human triage; deterministic flag stays on record). */
export const apiAnomalyAck = (flagPk: string) =>
  _postAction(`/api/v1/anomaly/flags/${encodeURIComponent(flagPk)}/ack`);

/** Live control-plane agent fleet (enrolled agents, version, heartbeat, health). */
export async function apiControlAgents(): Promise<ApiResult<any[]>> {
  try {
    const resp = await fetch(`/api/v1/control/agents`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`), data: [] } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.agents || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/** Schedule a deterministic signed-update / rollback / retire for an agent. */
export const apiAgentUpgrade = (agentId: string, action: "upgrade" | "rollback" | "retire", targetVersion?: string) =>
  _postAction(`/api/v1/control/agents/${encodeURIComponent(agentId)}/upgrade`, { action, target_version: targetVersion });

/** Authorize an OT/ICS operation against live devices + approved maintenance windows.
 *  Returns { allowed, decision, reason, ... } with HTTP 403 body carrying the deny detail. */
export async function apiOtAuthorize(operation: string, deviceId?: string): Promise<ApiResult<any>> {
  try {
    const resp = await fetch(`/api/v1/ot/safety/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify({ operation, device_id: deviceId || null }),
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    const detail = body.detail && typeof body.detail === "object" ? body.detail : body;
    // 403 is an authoritative DENY (fail-closed) — surface the decision, not a transport error
    if (resp.status === 403 && detail && typeof detail === "object" && "allowed" in detail) {
      return { source: "live", ok: true, data: detail };
    }
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`), data: null } as ApiResult<any>;
    return { source: "live", ok: true, data: body };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

/** Cancel an approved OT maintenance window. */
export const apiOtCancelWindow = (windowRef: string) =>
  _postAction(`/api/v1/ot/maintenance-windows/${encodeURIComponent(windowRef)}/cancel`);

/** Policy exceptions (risk-acceptance lifecycle). */
export async function apiExceptions(status?: string): Promise<ApiResult<any[]>> {
  try {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    const resp = await fetch(`/api/v1/exceptions${q}`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`), data: [] } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.exceptions || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/** Approve / reject / revoke a policy exception (HMAC-signed server-side on approve). */
export const apiExceptionDecision = (exceptionId: string, action: "approve" | "reject" | "revoke", notes?: string) =>
  _postAction(`/api/v1/exceptions/${encodeURIComponent(exceptionId)}/${action}`, { notes: notes || "" });

/* ========================================================================== */
/* Identity & access: SAML SSO, LDAP, SCIM provisioning, workload identity,   */
/* API-key IP allowlist + rotation. All calls hit the live backend; there is  */
/* no fallback dataset — offline/error renders as empty + a badge.           */
/* ========================================================================== */

async function _idReq<T>(method: string, path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    if (resp.status === 204) return { source: "live", ok: true, data: null as unknown as T };
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) {
    return { source: "offline", ok: false, error: String(e), data: null };
  }
}

function _idErr(data: any, status: number): string {
  if (data?.detail && typeof data.detail === "object") return String(data.detail.detail || data.detail.scimType || `HTTP ${status}`);
  return String(data?.detail || `HTTP ${status}`);
}

export interface ScimUser {
  id: string; userName: string; displayName?: string; active: boolean;
  emails?: { value: string }[]; roles?: { value: string }[];
}
export interface ScimList { totalResults: number; itemsPerPage: number; Resources: ScimUser[]; }

/** SSO feature flags (SAML/LDAP configured or not). */
export const apiSsoStatus = (): Promise<ApiResult<{ saml_enabled: boolean; ldap_enabled: boolean }>> =>
  _idReq("GET", "/api/v1/auth/saml/status");

/** SCIM directory listing (users provisioned via IdP sync). */
export const apiScimUsers = (): Promise<ApiResult<ScimList>> =>
  _idReq("GET", "/api/v1/scim/v2/Users?count=200");

/** Provision a user over SCIM 2.0. Roles are normalized server-side; the
 *  directory sync can never mint a superadmin. */
export const apiScimCreateUser = (payload: {
  userName: string; displayName?: string; email?: string;
  roles?: string[]; active?: boolean;
}): Promise<ApiResult<ScimUser>> =>
  _idReq("POST", "/api/v1/scim/v2/Users", {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: payload.userName,
    ...(payload.displayName ? { displayName: payload.displayName } : {}),
    ...(payload.email ? { emails: [{ value: payload.email, primary: true }] } : {}),
    ...(payload.roles ? { roles: payload.roles.map((r) => ({ value: r })) } : {}),
    active: payload.active ?? true,
  });

/** Deprovision = soft-deactivate (audit chain preserved; sessions revoked). */
export const apiScimDeactivate = (userName: string): Promise<ApiResult<null>> =>
  _idReq("DELETE", `/api/v1/scim/v2/Users/${encodeURIComponent(userName)}`);

/** Reactivate / role change via a SCIM PATCH op. */
export const apiScimSetActive = (userName: string, active: boolean): Promise<ApiResult<ScimUser>> =>
  _idReq("PATCH", `/api/v1/scim/v2/Users/${encodeURIComponent(userName)}`, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [{ op: "replace", path: "active", value: active }],
  });

export interface RotationKey {
  id: string; name?: string; key_prefix?: string;
  state?: string; age_days?: number; days_until_expiry?: number; recommended_action?: string;
  allowed_ips?: string[]; rotate_after_days?: number;
}
export interface RotationReport {
  total_active: number; counts: Record<string, number>; actionable: number; keys: RotationKey[];
}

/** API-key rotation posture (REVOKED/EXPIRED/EXPIRING_SOON/ROTATION_DUE/…). */
export const apiKeyRotationReport = (): Promise<ApiResult<RotationReport>> =>
  _idReq("GET", "/api/v1/api-keys/rotation/report");

/** Set per-IP allowlist (CIDR or exact) and rotation period on a key. */
export const apiUpdateKeyPolicy = (id: string, patch: {
  allowed_ips?: string[]; rotate_after_days?: number;
}): Promise<ApiResult<unknown>> =>
  _idReq("PATCH", `/api/v1/api-keys/${encodeURIComponent(id)}`, patch);

export interface Svid {
  spiffe_id: string; cert_pem: string; key_pem: string; ca_cert_pem: string; not_after: string;
}

/** Workload trust domain CA (public) for mTLS clients. */
export const apiWorkloadCa = (): Promise<ApiResult<{ trust_domain: string; ca_cert_pem: string }>> =>
  _idReq("GET", "/api/v1/workload/ca");

/** Mint a short-lived SPIFFE SVID for a scanner/worker workload. */
export const apiWorkloadIssueSvid = (workload: string, ttl_minutes = 60): Promise<ApiResult<Svid>> =>
  _idReq("POST", "/api/v1/workload/svid", { workload, ttl_minutes });

/** Verify a presented peer SVID against the CA + workload allowlist. */
export const apiWorkloadVerify = (cert_pem: string, allowed_workloads?: string[]): Promise<ApiResult<{ valid: boolean; spiffe_id?: string; workload?: string }>> =>
  _idReq("POST", "/api/v1/workload/verify", { cert_pem, ...(allowed_workloads ? { allowed_workloads } : {}) });

/* ========================================================================== */
/* Crypto assurance: active TLS audit, CT monitoring, expiry alerts + SLA,    */
/* HSM/KMS key residence, trust-store inventory, hybrid-PQC downgrade, and    */
/* deterministic weak-primitive code rules. Live backend only, no fallback.   */
/* ========================================================================== */

async function _ca<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

export const apiTlsAudit = (host: string, port = 443, sni?: string) =>
  _ca<any>("/api/v1/crypto-assurance/tls-audit", { host, port, ...(sni ? { sni } : {}) });

export const apiCtMonitor = (domains: string[], allowedIssuers: string[] = [], knownSerials: string[] = []) =>
  _ca<any>("/api/v1/crypto-assurance/ct-monitor", { domains, allowed_issuers: allowedIssuers, known_serials: knownSerials });

export const apiExpiryAlerts = (assets: Array<{ subject: string; not_after: string; sla_tier?: string; owner?: string }>) =>
  _ca<any>("/api/v1/crypto-assurance/expiry-alerts", { assets });

export const apiHsmCheck = (keys: Array<{ key_ref: string; provider: string; describe: Record<string, unknown> }>) =>
  _ca<any>("/api/v1/crypto-assurance/hsm-check", { keys });

export const apiTrustStore = (payload: { pem_bundle_b64?: string; path?: string; approved_subjects?: string[] }) =>
  _ca<any>("/api/v1/crypto-assurance/trust-store", payload);

export const apiPqcDowngrade = (host: string, port = 443, sni?: string) =>
  _ca<any>("/api/v1/crypto-assurance/pqc-downgrade-audit", { host, port, ...(sni ? { sni } : {}) });

export const apiCodeRuleScan = (filename: string, source: string) =>
  _ca<any>("/api/v1/crypto-assurance/code-rules/scan", { filename, source });

/* ========================================================================== */
/* DevSecOps pipeline: container CVE scan, K8s/IaC misconfig, cloud CIS       */
/* posture, SBOM CycloneDX/SPDX import+export + pinning, and outbound         */
/* connectors (ServiceNow/Jira, Splunk HEC/Elastic, Kafka/RabbitMQ, Slack/Teams). */
/* ========================================================================== */

async function _ds<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

export const apiContainerScan = (packages: any[], feed: any[], dockerfile?: string) =>
  _ds<any>("/api/v1/devsecops/container-scan", { packages, feed, dockerfile });

export const apiK8sScan = (manifestsYaml: string) =>
  _ds<any>("/api/v1/devsecops/k8s-manifest-scan", { manifests_yaml: manifestsYaml });

export const apiCloudPosture = (resources: any[]) =>
  _ds<any>("/api/v1/devsecops/cloud-posture", { resources });

export const apiSbomImport = (doc: any) =>
  _ds<any>("/api/v1/devsecops/sbom/import", { doc });

export const apiSbomExport = (components: any[], format: "cyclonedx" | "spdx") =>
  _ds<any>("/api/v1/devsecops/sbom/export", { components, format });

export const apiConnectorPreview = (provider: string, finding: any, target: Record<string, unknown>, deliverLive = false) =>
  _ds<any>("/api/v1/devsecops/connectors/preview", { provider, finding, target, deliver_live: deliverLive });

/* ========================================================================== */
/* Resilience / governance: signed compliance PDF, encrypted backup/restore,  */
/* audit hash-chain attestation, air-gap feed import, passive OT decode (21-27). */
/* ========================================================================== */

async function _rsPost<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

export const apiComplianceReport = (framework: string, org: string, evidence: Record<string, unknown>) =>
  _rsPost<any>("/api/v1/resilience/compliance-report", { framework, org, evidence, format: "json" });

export const apiRetentionPlan = (backups: any[], policy?: Record<string, number>) =>
  _rsPost<any>("/api/v1/resilience/backup/retention-plan", { backups, policy });

export const apiBackupCreate = (databaseId: string, engine = "reference", sequence = 1) =>
  _rsPost<any>("/api/v1/resilience/backup/create", { database_id: databaseId, engine, sequence });

export const apiBackupRestore = (databaseId: string, ciphertextB64: string, manifest: any, pit?: string) =>
  _rsPost<any>("/api/v1/resilience/backup/restore",
    { database_id: databaseId, ciphertext_b64: ciphertextB64, manifest, ...(pit ? { target_point_in_time: pit } : {}) });

export const apiAuditAttestation = () =>
  _rsGet<any>("/api/v1/resilience/audit/attestation");

export const apiAirgapStatus = () =>
  _rsGet<any>("/api/v1/resilience/airgap/status");

export const apiAirgapImportFeed = (bundle: any) =>
  _rsPost<any>("/api/v1/resilience/airgap/import-feed", { bundle });

export const apiOtDecode = (frames: any[]) =>
  _rsPost<any>("/api/v1/resilience/ot/decode", { frames });

/* --- Resilience last-mile: scheduled backups, feed bundle builder, pcap --- */
export const apiBackupRunScheduled = (databases: Array<{ database_id: string; engine: string; interval_hours?: number }>, applyRetention = true) =>
  _rsPost<any>("/api/v1/resilience/backup/run-scheduled", { databases, apply_retention: applyRetention });

export const apiBackupList = () =>
  _rsGet<any>("/api/v1/resilience/backup/list");

export const apiAirgapBuildBundle = (entries: any[], createdBy = "online-updater") =>
  _rsPost<any>("/api/v1/resilience/airgap/build-bundle", { entries, created_by: createdBy });

export const apiOtIngestPcap = (pcapB64: string) =>
  _rsPost<any>("/api/v1/resilience/ot/ingest-pcap", { pcap_b64: pcapB64 });

export const apiAirgapDecision = (payload: { url?: string; operation?: string }) =>
  _rsPost<any>("/api/v1/resilience/airgap/network-decision", payload);

export const apiBackupSweep = (applyRetention = true) =>
  _rsPost<any>("/api/v1/resilience/backup/sweep", { apply_retention: applyRetention });

export const apiBackupConfigSet = (databases: Array<{ database_id: string; engine: string; interval_hours?: number }>) =>
  _rsPost<any>("/api/v1/resilience/backup/config", { databases });

/* ========================================================================== */
/* Trust & key management: payment-crypto key inventory/rotation, HSM        */
/* ceremonies, workload SPIFFE/SVID identity, OT safe-scan policy (real ops). */
/* ========================================================================== */

export const apiPaymentKeys = () => _rsGet<any>("/api/v1/payment-crypto/keys");
export const apiPaymentSummary = () => _rsGet<any>("/api/v1/payment-crypto/summary");
export const apiPaymentForecast = () => _rsGet<any>("/api/v1/payment-crypto/forecast");
export const apiPaymentCeremonies = () => _rsGet<any>("/api/v1/payment-crypto/ceremonies");
export const apiPaymentHsmEvents = () => _rsGet<any>("/api/v1/payment-crypto/hsm-events");

export const apiApiKeyRotationReport = () => _rsGet<any>("/api/v1/api-keys/rotation/report");

export const apiSafeScanPolicy = () => _rsGet<any>("/api/v1/control/safe-scan/policy");
export const apiSafeScanEmergencyStop = (engaged: boolean) =>
  _rsPost<any>("/api/v1/control/safe-scan/emergency-stop", { engaged });

/* Immutable audit log (auth router): paged events + hash-chain integrity. */
export interface AuditEvent {
  id: string; actor: string; action: string; target_type?: string | null;
  target_id?: string | null; detail?: unknown; ip_address?: string | null;
  outcome: string; created_at?: string | null;
}
export interface AuditList { events: AuditEvent[]; page: number; page_size: number; }
export const apiAuditList = (params: { page?: number; page_size?: number; actor?: string; action?: string } = {}): Promise<ApiResult<AuditList>> => {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  if (params.actor) q.set("actor", params.actor);
  if (params.action) q.set("action", params.action);
  const qs = q.toString();
  return call(`/api/v1/auth/audit${qs ? `?${qs}` : ""}`);
};
export interface AuditChainStatus { status: string; checked: number; entry_count: number; chain_head?: string | null; break_at_sequence?: number | null; reason?: string | null; }
export const apiAuditVerify = (): Promise<ApiResult<AuditChainStatus>> => call("/api/v1/auth/audit/verify");

/* Control-plane observability: queue / fleet / credential / db / redis health. */
export const apiControlHealth = (): Promise<ApiResult<Record<string, unknown>>> => call("/api/v1/control/health");

/* ── Security posture (ZELNX Security Center, server-owned & durable) ── *
 * GET /api/v1/security/posture computes a deterministic 0-100 score from live
 * control-plane signals and persists a metadata-only snapshot for time-series.
 * The Security Center consumes this contract instead of recomputing a score
 * client-side. The score is honest: an unprovisioned store reads low.
 * ------------------------------------------------------------------- */
export interface PostureComponent {
  value: number;
  total?: number;
  good?: number;
  ok?: boolean;
  note?: string;
  valid_pct?: number | null;
}
export interface SecurityPostureSnapshot {
  id: string;
  score: number;
  agents_total: number;
  agents_healthy: number;
  plugins_total: number;
  plugins_verified: number;
  threats_open: number;
  threats_critical: number;
  failed_logins: number;
  cert_total: number;
  cert_valid_pct: number | null;
  audit_ok: boolean;
  credentials_active: number;
  credentials_total: number;
  source: string;
  created_at?: string | null;
}
export interface SecurityPosture {
  score: number;
  agents_total: number;
  agents_healthy: number;
  plugins_total: number;
  plugins_verified: number;
  threats_open: number;
  threats_critical: number;
  failed_logins: number;
  cert_total: number;
  cert_valid_pct: number | null;
  audit_ok: boolean;
  credentials_active: number;
  credentials_total: number;
  components: Record<string, PostureComponent>;
  source: string;
  snapshot_id: string;
  history: SecurityPostureSnapshot[];
}
export const apiSecurityPosture = (historyLimit = 60): Promise<ApiResult<SecurityPosture>> =>
  call(`/api/v1/security/posture?history_limit=${historyLimit}`);

/** Posture-over-time buckets for the SOC trend chart (score min/avg/max +
 *  per-signal average per time bucket). */
export interface PostureTrendBucket {
  start: string;
  count: number;
  score_avg: number | null;
  score_min: number | null;
  score_max: number | null;
  components: Record<string, number | null>;
}
export interface PostureTrend {
  window_hours: number;
  bucket_minutes: number;
  count: number;
  buckets: PostureTrendBucket[];
  latest: {
    id: string; score: number; created_at: string | null;
    delta: number | null; previous_score: number | null; dropped: boolean;
  } | null;
}
export const apiSecurityPostureTrend = (hours = 24, bucketMinutes = 30): Promise<ApiResult<PostureTrend>> =>
  call(`/api/v1/security/posture/trend?hours=${hours}&bucket_minutes=${bucketMinutes}`);

/** Unified live threat feed for 24/7 SOC triage (anomaly flags + live-scan
 *  alerts + critical/high runtime findings + failed logins). */
export interface SecurityAlert {
  id: string; severity: string; kind: string; title: string; detail: string;
  asset: string; ts: string | null; source: string; status: string;
  ack_href: string | null;
}
export interface SecurityAlertsResponse {
  alerts: SecurityAlert[]; count: number; counts: Record<string, number>;
  generated_at: string;
}
export const apiSecurityAlerts = (limit = 50): Promise<ApiResult<SecurityAlertsResponse>> =>
  call(`/api/v1/security/alerts?limit=${limit}`);

/* ══════════════════════ Dependency Graph (flagship) ══════════════════════
   Backend-produced knowledge graph. The frontend never discovers relationships —
   it renders what GET /api/v1/graph (and the blast-radius / trace / simulate /
   explain endpoints) return. Honest empty state when the store is unprovisioned. */

export interface GraphNode {
  id: string; label: string; group: string; kind?: string;
  name?: string; algorithm?: string; confidence?: string;
  environment?: string; owner?: string | null; criticality?: string;
  purpose?: string; file_path?: string; extra?: Record<string, unknown>;
  subject?: string; issuer?: string; expiry_status?: string; days_until_expiry?: number;
  [k: string]: unknown;
}
export interface GraphEdge { from: string; to: string; label: string; [k: string]: unknown; }
export interface GraphView {
  nodes: GraphNode[]; edges: GraphEdge[];
  backend?: string; health?: { ok?: boolean; error?: string; backend?: string; configured?: boolean };
}
export interface GraphStats {
  nodes: number; edges: number; systems: number;
  nodes_by_kind: Record<string, number>; edges_by_relation: Record<string, number>;
  orphan_system_count?: number; unlinked_asset_count?: number; backend?: string;
}
export interface BlastSystem { id: string; name?: string; criticality?: string | null; hops: number; }
export interface BlastRadiusResult {
  start?: string; systems: BlastSystem[]; nodes_visited: number; hops?: number; backend?: string;
}
export interface SimulateResult {
  node_id: string; change: string;
  affected: { assets: number; applications: number; certificates: number; services: number };
  compatibility_issues: number; migration_tasks: number;
  systems: { id: string; name?: string; crypto_assets: number }[];
  total_revenue_at_risk: number; backend?: string;
}
export interface ExplainStep {
  label: string; kind: string; detail?: string; confidence?: string | null;
  evidence?: string; file?: string | null; quantum_vulnerable?: boolean;
}
export interface ExplainResult {
  node_id: string; title: string; quantum_vulnerable: boolean; steps: ExplainStep[]; backend?: string;
}
export const apiGraph = (): Promise<ApiResult<GraphView>> => call("/api/v1/graph");
export const apiGraphStats = (): Promise<ApiResult<GraphStats>> => call("/api/v1/graph/stats");
export const apiGraphBlastRadius = (systemId: string, hops = 5): Promise<ApiResult<BlastRadiusResult>> =>
  call(`/api/v1/graph/blast-radius?system_id=${encodeURIComponent(systemId)}&hops=${hops}`);
export const apiGraphDependents = (systemId: string, hops = 5): Promise<ApiResult<BlastRadiusResult>> =>
  call(`/api/v1/graph/dependents?system_id=${encodeURIComponent(systemId)}&hops=${hops}`);
export const apiGraphSimulate = (nodeId: string, change = "migrate_pqc"): Promise<ApiResult<SimulateResult>> =>
  call("/api/v1/graph/simulate", { method: "POST", body: JSON.stringify({ node_id: nodeId, change }) });
export const apiGraphExplain = (nodeId: string): Promise<ApiResult<ExplainResult>> =>
  call(`/api/v1/graph/explain?node_id=${encodeURIComponent(nodeId)}`);
export interface MigrationPlanResult {
  created: boolean; project_id: string | null; project_name?: string; tasks_created: number;
  affected: { asset_id: string; algorithm_from: string; system_id: string; file?: string }[];
  backend?: string;
}
export const apiGraphMigrationPlan = (nodeId: string, change = "migrate_pqc", algorithmTo = "ML-KEM-768"): Promise<ApiResult<MigrationPlanResult>> =>
  call("/api/v1/graph/migration-plan", { method: "POST", body: JSON.stringify({ node_id: nodeId, change, algorithm_to: algorithmTo }) });
export interface GraphSnapshot {
  id: string; version: number; fingerprint: string; parent_fingerprint?: string | null;
  node_count: number; edge_count: number; nodes_by_kind: Record<string, number>;
  edges_by_relation: Record<string, number>;
  added_nodes: (string[] | { id: string; kind?: string })[];
  removed_nodes: (string[] | { id: string; kind?: string })[];
  added_edges: string[][]; removed_edges: string[][];
  new_quantum_vulnerable: { id: string; algorithm?: string }[];
  created_by?: string; created_at?: string;
}
export interface GraphTimeline { versions: GraphSnapshot[]; total_count: number; latest_version: number; }
export interface GraphCompare {
  from: { version: number; node_count: number; edge_count: number };
  to: { version: number; node_count: number; edge_count: number };
  added_nodes: { id: string; kind?: string; algorithm?: string }[];
  removed_nodes: { id: string; kind?: string; algorithm?: string }[];
  added_edges: string[][]; removed_edges: string[][];
  new_quantum_vulnerable: { id: string; algorithm?: string }[];
  changed: boolean; backend?: string;
}
export const apiGraphSnapshot = (): Promise<ApiResult<GraphSnapshot>> =>
  call("/api/v1/graph/snapshot", { method: "POST" });
export const apiGraphTimeline = (limit = 50): Promise<ApiResult<GraphTimeline>> =>
  call(`/api/v1/graph/timeline?limit=${limit}`);
export const apiGraphCompare = (fromVersion: number, toVersion: number): Promise<ApiResult<GraphCompare>> =>
  call(`/api/v1/graph/compare?from_version=${fromVersion}&to_version=${toVersion}`);
export const apiGraphVendorPath = (systemId: string): Promise<ApiResult<{ path: string[]; vendor?: string | null; hops: number }>> =>
  call(`/api/v1/graph/vendor-path?system_id=${encodeURIComponent(systemId)}`);
export interface VendorChainAsset {
  id: string; algorithm?: string | null; purpose?: string | null; confidence?: string | null;
  key_size?: number | null; file_path?: string | null; risk?: "vulnerable" | "ready" | null;
}
export interface VendorChainSystem {
  id: string; name?: string | null; criticality?: string | null;
  asset_count: number; assets: VendorChainAsset[];
  processes: { id: string }[];
}
export interface VendorChain {
  start: string; vendor: { id: string; name?: string | null } | null;
  product?: string | null; systems: VendorChainSystem[]; count: number;
  total_assets: number; backend?: string;
}
export interface VendorChains {
  chains: VendorChain[]; count: number; backend?: string;
}
export const apiGraphVendorChain = (vendorId: string): Promise<ApiResult<VendorChain>> =>
  call(`/api/v1/graph/vendor-chain?vendor_id=${encodeURIComponent(vendorId)}`);
export const apiGraphVendorChains = (): Promise<ApiResult<VendorChains>> =>
  call("/api/v1/graph/vendor-chains");

/* Notification routing (persisted per tenant). */
export const apiNotificationRoutingGet = () => _rsGet<any>("/api/v1/notifications/routing");
export const apiNotificationRoutingPut = (routing: Array<{ id: string; name: string; severity: string; channels: Record<string, boolean> }>) =>
  _rsPut<any>("/api/v1/notifications/routing", { routing });


/* PUT helper for persisted notification routing. */
export async function _rsPut<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: "HTTP " + resp.status, data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

async function _rsGet<T>(path: string): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(20000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: "HTTP " + resp.status, data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

/* Report templates + schedule creation. */
export const apiReportTemplates = () => _rsGet<any>("/api/v1/report-templates");
export const apiReportScheduleCreate = (body: { name: string; template_id: string; frequency: string; scan_target?: string; requirements?: string[]; recipients?: string[] }) =>
  _rsPost<any>("/api/v1/report-schedules", body);

/* OT maintenance windows (author + list + cancel) and operation classes. */
export const apiOtSafetyOperations = () => _rsGet<any>("/api/v1/ot/safety/operations");
export const apiOtCreateMaintenanceWindow = (body: {
  window_ref: string; title?: string; starts_at: string; ends_at: string;
  change_ticket: string; allowed_action_class?: string; device_ids?: string[]; zones?: string[]; sites?: string[]; operations?: string[];
}) => _rsPost<any>("/api/v1/ot/maintenance-windows", body);

/* Certificate lifecycle — CSR generation, issuance, renewal (key rotation),
   revocation (CRL), and the deterministic renewal queue. */
export const apiCertCsr = (body: { subject?: Record<string, string>; san?: string[]; key_size?: number }) =>
  _rsPost<any>("/api/v1/certificates/lifecycle/csr", body);
export const apiCertIssue = (body: { subject?: Record<string, string>; san?: string[]; csr_pem?: string; key_size?: number; validity_days?: number; signed_by_ca?: boolean }) =>
  _rsPost<any>("/api/v1/certificates/lifecycle/issue", body);
export const apiCertRenew = (fingerprint: string, body: { validity_days?: number; rotate_key?: boolean }) =>
  _rsPost<any>(`/api/v1/certificates/${encodeURIComponent(fingerprint)}/renew`, body);
export const apiCertRevoke = (fingerprint: string, reason: string) =>
  _rsPost<any>(`/api/v1/certificates/${encodeURIComponent(fingerprint)}/revoke`, { reason });
export const apiCertRenewalQueue = () => _rsGet<any>("/api/v1/certificates/lifecycle/renewal-queue");

/* Credential vault — vault-reference only (never inline secrets), short-lived
   leases with deterministic policy gates, rotation, and release. */
export const apiVaultCredentials = () => _rsGet<any>("/api/v1/control/credentials");
export const apiVaultCredentialCreate = (body: {
  name: string; kind: string; vault_provider?: string; secret_ref: string;
  least_privilege_scope?: string; region?: string; rotation_policy_days?: number;
}) => _rsPost<any>("/api/v1/control/credentials", body);
export const apiVaultCredentialLease = (credentialId: string, body: { component?: string; scope?: string[]; ttl_seconds?: number }) =>
  _rsPost<any>(`/api/v1/control/credentials/${encodeURIComponent(credentialId)}/lease`, body);
export const apiVaultLeaseRelease = (handle: string) =>
  _rsPost<any>(`/api/v1/control/credential-leases/${encodeURIComponent(handle)}/release`, {});
export const apiVaultCredentialRotate = (credentialId: string) =>
  _rsPost<any>(`/api/v1/control/credentials/${encodeURIComponent(credentialId)}/rotate`, {});
export const apiVaultLeases = () => _rsGet<any>("/api/v1/control/credential-leases");

/* ── Unified Technology BOM (Live Asset Intelligence) ──────────────────
   GET /technology-bom (live) · POST /snapshot (version) · /history */
export const apiTechBomLive = (limit = 2000): Promise<ApiResult<TechBomState>> =>
  call(`/api/v1/technology-bom?limit=${limit}`);

export const apiTechBomSnapshot = (): Promise<ApiResult<TechBomSnapshotResponse>> =>
  _rsPost<any>("/api/v1/technology-bom/snapshot");

export const apiTechBomHistory = (limit = 50): Promise<ApiResult<{ versions: TechBomVersion[]; total_count: number; latest_version: number }>> =>
  call(`/api/v1/technology-bom/history?limit=${limit}`);

export const apiTechBomVersions = (limit = 200): Promise<ApiResult<{ versions: TechBomVersion[]; total_count: number }>> =>
  call(`/api/v1/technology-bom/history/versions?limit=${limit}`);

export const apiTechBomCompare = (fromVersion: number, toVersion: number): Promise<ApiResult<TechBomDiff>> =>
  call(`/api/v1/technology-bom/compare?from_version=${fromVersion}&to_version=${toVersion}`);

export const apiTechBomExport = (params: { version?: number; fmt?: string; layer?: string }): Promise<ApiResult<TechBomExport>> => {
  const q = new URLSearchParams();
  if (params.version !== undefined) q.set("version", String(params.version));
  if (params.fmt) q.set("fmt", params.fmt);
  if (params.layer) q.set("layer", params.layer);
  return call(`/api/v1/technology-bom/export?${q.toString()}`);
};

export const apiTechBomExportCsv = (params: { version?: number; layer?: string }): Promise<Response> => {
  const q = new URLSearchParams();
  if (params.version !== undefined) q.set("version", String(params.version));
  if (params.layer) q.set("layer", params.layer);
  q.set("fmt", "csv");
  return fetch(`/api/v1/technology-bom/export?${q.toString()}`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
};

/* Time-based formatting for snapshot_id (TECHBOM-YYYYMMDD-HHMMSS). */
export function fmtSnapshotId(sid: string | null | undefined): string {
  if (!sid) return "—";
  const m = sid.match(/^TECHBOM-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/);
  if (!m) return sid;
  return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}`;
}

/* Technology BOM type contracts (mirror `services/cbom/.../technology_bom.py`). */
export interface TechBomComponent {
  "bom-ref"?: string;
  type?: string;
  name?: string;
  version?: string;
  supplier?: string;
  properties?: Record<string, unknown>;
}
export interface TechBomLayer {
  count: number;
  components: TechBomComponent[];
}
export interface TechBomState {
  source?: string;
  live?: boolean;
  snapshot_id: string;
  environment: string;
  state_version: number;
  generated_at?: string;
  total_components: number;
  components_by_layer: Partial<Record<"sbom" | "cbom" | "hbom" | "vendor" | "certificates", number>>;
  certificate_count?: number;
  dependency_count?: number;
  layers: Partial<Record<"sbom" | "cbom" | "hbom" | "vendor" | "certificates", TechBomLayer>>;
  scan?: Record<string, unknown>;
  fingerprint: string;
  scan_in_progress?: boolean;
  live_scan_note?: string | null;
  latest_snapshot_id?: string | null;
  previous_snapshot_id?: string | null;
}
export interface TechBomVersion {
  version: number;
  snapshot_id: string;
  environment: string;
  total_components: number;
  components_by_layer?: Partial<Record<"sbom" | "cbom" | "hbom" | "vendor" | "certificates", number>>;
  created_at?: string;
}
export interface TechBomSnapshotResponse {
  source: string;
  recorded: boolean;
  snapshot: TechBomVersion & { id?: string; fingerprint?: string; created_by?: string };
  diff?: TechBomDiff;
  note?: string;
}
export interface TechBomLayerDiff {
  added_count: number;
  removed_count: number;
  added: TechBomComponent[];
  removed: TechBomComponent[];
  from_count: number;
  to_count: number;
}
export interface TechBomDiff {
  from: { snapshot_id?: string; state_version?: number; total_components?: number };
  to: { snapshot_id?: string; state_version?: number; total_components?: number };
  changed: boolean;
  layers: Partial<Record<"sbom" | "cbom" | "hbom" | "vendor" | "certificates", TechBomLayerDiff>>;
}
export interface TechBomExport {
  snapshot_id: string;
  environment: string;
  state_version: number;
  generated_at?: string;
  layer: string;
  format: string;
  mime_type: string;
  integrity_sha256: string;
  data: unknown;
}

/* Raw (non-JSON) exports — CSV / XML / PDF are returned as download bodies. */
export const apiTechBomExportRaw = (params: { version?: number; fmt: string; layer?: string; filters?: Record<string, unknown> }): Promise<Response> => {
  const q = new URLSearchParams();
  if (params.version !== undefined) q.set("version", String(params.version));
  q.set("fmt", params.fmt);
  if (params.layer) q.set("layer", params.layer);
  if (params.filters) for (const [k, v] of Object.entries(params.filters)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  return fetch(`/api/v1/technology-bom/export?${q.toString()}`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
};

export const apiTechBomSchedules = (): Promise<ApiResult<{ schedules: TechBomSchedule[]; count: number }>> =>
  call("/api/v1/technology-bom/export-schedules");
export const apiTechBomScheduleCreate = (body: Partial<TechBomSchedule>): Promise<ApiResult<TechBomSchedule>> =>
  _rsPost<any>("/api/v1/technology-bom/export-schedules", body);
export const apiTechBomScheduleUpdate = (id: string, body: Partial<TechBomSchedule>): Promise<ApiResult<TechBomSchedule>> =>
  call(`/api/v1/technology-bom/export-schedules/${id}`, { method: "PUT", body: JSON.stringify(body) });
export const apiTechBomScheduleDelete = (id: string): Promise<ApiResult<{ deleted: boolean }>> =>
  call(`/api/v1/technology-bom/export-schedules/${id}`, { method: "DELETE" });
export const apiTechBomScheduleRun = (id: string): Promise<ApiResult<{ run: TechBomRun; schedule: TechBomSchedule }>> =>
  _rsPost<any>(`/api/v1/technology-bom/export-schedules/${id}/run`);
export const apiTechBomRunDue = (): Promise<ApiResult<{ ran_total: number; skipped_total: number; ran: unknown[]; skipped: { id: string; reason: string }[] }>> =>
  _rsPost<any>("/api/v1/technology-bom/export-schedules/run-due");
export const apiTechBomExportRuns = (limit = 50): Promise<ApiResult<{ runs: TechBomRun[]; count: number }>> =>
  call(`/api/v1/technology-bom/export-runs?limit=${limit}`);
export const apiTechBomEvidence = (version?: number, fmt = "json"): Promise<ApiResult<TechBomEvidence>> | Promise<Response> => {
  const q = new URLSearchParams();
  if (version !== undefined) q.set("version", String(version));
  q.set("fmt", fmt);
  if (fmt === "pdf") {
    return fetch(`/api/v1/technology-bom/evidence-package?${q.toString()}`, { credentials: "include", ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}) });
  }
  return call(`/api/v1/technology-bom/evidence-package?${q.toString()}`);
};
export const apiTechBomVendor = (): Promise<ApiResult<TechBomVendorInventory>> =>
  call("/api/v1/technology-bom/vendor");

export interface TechBomSchedule {
  id: string; name: string; frequency: string; fmt: string; layer: string;
  filters: Record<string, unknown>; environment: string; recipients: string[];
  active: boolean; last_run_at?: string | null; next_run_at?: string | null;
  last_snapshot_id?: string | null; created_by?: string | null;
}
export interface TechBomRun {
  schedule_id?: string | null; schedule_name?: string | null; version?: number | null;
  snapshot_id: string; environment: string; fmt: string; layer: string;
  filters: Record<string, unknown>; total_components: number; content_sha256: string;
  signature_hmac?: string | null; mime_type?: string | null; audit_event_id?: string | null;
  trigger?: string | null; created_at?: string | null;
}
export interface TechBomEvidence {
  kind: string; snapshot_id: string; environment: string; state_version: number;
  generated_at: string; generated_by?: string; bom: { total_components: number; components_by_layer: Record<string, number>; certificate_count: number; dependency_count: number; fingerprint: string };
  certificates: { total: number; expired: number; expiring: number; self_signed: number; revoked: number };
  scan_in_progress?: boolean; content_sha256: string; signature_hmac: string;
}
export interface TechBomVendorInventory {
  vendors: Array<{ id: string; name: string; vendor_type: string; criticality: string; contract_end_date?: string | null; last_assessment_date?: string | null; integration_type: string; systems: string[]; system_count: number }>;
  linkage: Array<{ vendor: string; vendor_id: string; system: string; system_id: string; dependency_type: string }>;
  vendor_count: number;
}


/* ── Assurance & Control (VEX · xBOM · admission · runtime verify) ──────
   GET /technology-bom/assurance (combined) + the individual surfaces.
   Mirrors services/cbom/.../assurance.py — pure engine, live backend only. */

export interface TechBomVexFinding {
  cve: string;
  package?: string | null;
  bom_ref?: string | null;
  severity: string;
  exploitability: number;
  exploitability_reasons: string[];
  vex_status: "not_affected" | "affected" | "fixed" | "under_review";
  priority: "P0" | "P1" | "P2" | "P3";
  component_used_in_production: boolean;
  component_is_blocking: boolean;
  component_is_weak: boolean;
  summary?: string;
}
export interface TechBomVex {
  total: number;
  affected: number;
  not_affected: number;
  fixed: number;
  under_review: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  top_p0: TechBomVexFinding[];
  findings: TechBomVexFinding[];
}
export interface TechBomXbomTrace {
  crypto: { "bom-ref"?: string; algorithm?: string; key_size?: number | null; purpose?: string; weak: boolean; blocking: boolean; asset?: string };
  applications: Array<{ "bom-ref"?: string; name?: string; version?: string; criticality?: string }>;
  hardware: { "bom-ref"?: string; model?: string; manufacturer?: string; device_type?: string } | null;
  vendor: { "bom-ref"?: string; name?: string; risk_level?: string; lifecycle?: string } | null;
  business_processes: Array<{ name?: string; process_type?: string; revenue_daily?: number; sla_uptime?: number }>;
  impact_count: { applications: number; hardware: number; vendors: number; business_processes: number };
}
export interface TechBomXbom {
  layer_set: string[];
  traces: TechBomXbomTrace[];
  count: number;
  deploy_relevant: number;
  highest_impact: number;
}
export interface TechBomAdmissionItem { bom_ref?: string | null; algorithm?: string; purpose?: string; key_size?: number | null; reason: string; }
export interface TechBomAdmission {
  decision: "PASS" | "WARN" | "FAIL";
  admitted: boolean;
  blocking_count: number;
  warn_count: number;
  blocking: TechBomAdmissionItem[];
  warnings: TechBomAdmissionItem[];
  snapshot_id?: string;
  state_version?: number;
  environment?: string;
  scan_in_progress?: boolean;
  source?: string;
}
export interface TechBomRuntimeRow {
  hostname?: string; process_name?: string; algorithm?: string; key_size?: string;
  tls_version?: string | null; cipher_suite?: string | null; weak: boolean; tls_weak: boolean;
  runtime_only: boolean; bom_has_weak: boolean; drift: boolean; drift_reason: string;
}
export interface TechBomRuntimeVerify {
  observed: number; drifted: number; runtime_only: number; weak_at_runtime: number;
  tls_below_1_2: number; drift_rows: TechBomRuntimeRow[]; halting: TechBomRuntimeRow[];
}
export interface TechBomAssurance {
  source: string;
  environment?: string;
  state_version?: number;
  snapshot_id?: string;
  scan_in_progress?: boolean;
  vex: TechBomVex | null;
  xbom: TechBomXbom;
  admission: TechBomAdmission;
  runtime_verify: TechBomRuntimeVerify | null;
}

export const apiTechBomAssurance = (version?: number): Promise<ApiResult<TechBomAssurance>> =>
  call(`/api/v1/technology-bom/assurance${version !== undefined ? `?version=${version}` : ""}`);
export const apiTechBomVex = (version?: number): Promise<ApiResult<{ source: string; scan_in_progress?: boolean; vex: TechBomVex | null; note?: string }>> =>
  call(`/api/v1/technology-bom/vex${version !== undefined ? `?version=${version}` : ""}`);
export const apiTechBomXbom = (bomRef?: string, version?: number): Promise<ApiResult<TechBomXbom & { source?: string; snapshot_id?: string; state_version?: number }>> => {
  const q = new URLSearchParams();
  if (bomRef) q.set("bom_ref", bomRef);
  if (version !== undefined) q.set("version", String(version));
  const qs = q.toString();
  return call(`/api/v1/technology-bom/xbom${qs ? `?${qs}` : ""}`);
};
export const apiTechBomAdmission = (version?: number, requireBaseline = false): Promise<ApiResult<TechBomAdmission>> =>
  call(`/api/v1/technology-bom/admission${version !== undefined ? `?version=${version}` : ""}${requireBaseline ? `${version !== undefined ? "&" : "?"}require_baseline=true` : ""}`);
export const apiTechBomRuntimeVerify = (version?: number): Promise<ApiResult<{ source: string; scan_in_progress?: boolean; runtime_verify: TechBomRuntimeVerify | null; note?: string }>> =>
  call(`/api/v1/technology-bom/runtime-verify${version !== undefined ? `?version=${version}` : ""}`);

/* ── Banking & Regulatory — supervisor-ready surfaces over the Tech BOM ── */
export interface BankHndlEntry {
  bom_ref?: string; algorithm?: string; key_size?: number | null; purpose?: string;
  application?: string; asset?: string; confidentiality_years?: number;
  transition?: string; deadline?: number; years_to_deadline?: number | null;
  exposure?: "critical" | "high"; reason?: string;
}
export interface BankHndl {
  threshold_years?: number; at_risk?: boolean; total?: number;
  by_exposure?: Record<string, number>; entries?: BankHndlEntry[]; source?: string;
}
export interface BankRoadmapItem {
  family?: string; key_size?: number | null; transition?: string; instances?: number;
  applications?: string[]; deadline?: number; years_left?: number | null; overdue?: boolean;
}
export interface BankRoadmapPhase {
  phase?: string; window?: string; deadline?: number | null; title?: string;
  action?: string; items?: BankRoadmapItem[]; instance_count?: number;
}
export interface BankRoadmap {
  anchor?: string; generated_for_year?: number; phases?: BankRoadmapPhase[];
  weak_legacy_instances?: number; total_in_scope?: number; source?: string;
}
export interface BankHsmRow {
  asset_id?: string; manufacturer?: string; model?: string; firmware?: string | { version?: string } | null;
  pqc_status?: string; pqc_evidence?: string; gap?: string;
  fips?: { module?: string; algorithm?: string; status?: string; cert?: string; note?: string; source?: string };
}
export interface BankHsmFleet {
  total?: number; pqc_ready?: number; pqc_gap?: number;
  fips_validated_family?: number; fips_unknown?: number; ready_share?: number; hsms?: BankHsmRow[];
}
export interface BankMainframeAsset {
  algorithm?: string; key_size?: number | null; purpose?: string; location?: string;
  source_language?: string; quantum?: { transition?: string; deadline?: number | null };
}
export interface BankOverview {
  source?: string; environment?: string; snapshot_id?: string; generated_at?: string;
  overview?: {
    hndl?: { at_risk?: boolean; total?: number; by_exposure?: Record<string, number> };
    roadmap?: { anchor?: string; total_in_scope?: number; weak_legacy_instances?: number;
                phases?: BankRoadmapPhase[] };
    hsm?: { total?: number; pqc_ready?: number; pqc_gap?: number };
    mainframe?: { total?: number; by_source?: Record<string, number> };
  };
}
export interface BankActionPlan {
  document?: string; framework?: string; institution?: string | null; generated_at?: string;
  references?: string[];
  evidence?: { snapshot_id?: string; fingerprint?: string; environment?: string; state_version?: number };
  assessment?: {
    total_crypto_instances?: number;
    admission?: { decision?: string; blocking?: number; warnings?: number };
    hndl?: { at_risk?: boolean; total?: number; by_exposure?: Record<string, number> };
    hsm_fleet?: { total?: number; pqc_ready?: number; pqc_gap?: number };
    mainframe_inventory?: { total?: number; by_source?: Record<string, number> };
  };
  hndl_register?: BankHndlEntry[]; phases?: BankRoadmapPhase[]; attestation?: string;
}
export interface BankIngestResult {
  kind?: string; parsed?: number; inserted?: number; duplicates?: number; persisted?: boolean;
  assets?: Array<Record<string, unknown>>;
}
export interface BankMainframeInventory {
  source?: string; total?: number; by_source?: Record<string, number>; assets?: BankMainframeAsset[];
}

export const apiBankingOverview = (version?: number): Promise<ApiResult<BankOverview>> =>
  call(`/api/v1/banking/overview${version !== undefined ? `?version=${version}` : ""}`);
export const apiBankingHndl = (horizonYears = 5): Promise<ApiResult<BankHndl>> =>
  call(`/api/v1/banking/hndl?horizon_years=${horizonYears}`);
export const apiBankingRoadmap = (): Promise<ApiResult<BankRoadmap>> =>
  call("/api/v1/banking/roadmap");
export const apiBankingHsm = (): Promise<ApiResult<{ source: string; fleet: BankHsmFleet }>> =>
  call("/api/v1/banking/hsm");
export const apiBankingActionPlan = (framework: string, institution = ""): Promise<ApiResult<BankActionPlan>> =>
  call(`/api/v1/banking/action-plan?framework=${encodeURIComponent(framework)}${institution ? `&institution=${encodeURIComponent(institution)}` : ""}`);
export const apiBankingMainframe = (): Promise<ApiResult<BankMainframeInventory>> =>
  call("/api/v1/banking/mainframe");
export const apiBankingMainframeIngest = (kind: string, content: string, persist = true): Promise<ApiResult<BankIngestResult>> =>
  call("/api/v1/banking/mainframe/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind, content, persist }),
  });
