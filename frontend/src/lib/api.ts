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
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    return { ok: true, username: body.username, roles: body.roles };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
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
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

async function _rsGet<T>(path: string): Promise<ApiResult<T>> {
  try {
    const resp = await fetch(path, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(20000),
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
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: "HTTP " + resp.status, data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}
