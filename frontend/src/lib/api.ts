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
export interface LiveInventory {
  generated_at: string | null;
  host: string | null;
  counts: { hardware_devices: number; network_assets: number; libraries: number };
  hardware: LiveHardwareDevice[];
  firmware: Array<{ device: string; kind: string; version: string; status: string }>;
  network: LiveNetworkAsset[];
  libraries: LiveLibrary[];
}
export const apiLiveInventory = (): Promise<ApiResult<LiveInventory>> =>
  call(`/api/v1/live-scan/inventory`);

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
