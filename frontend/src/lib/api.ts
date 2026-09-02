/* End-to-end API bridge — every call first tries the real backend through
   the Vite /api proxy (which forwards to the FastAPI control plane on
   :8010), and falls back to the deterministic demo dataset when it is
   offline. Each result is tagged with its source so pages can show
   LIVE API vs DEMO data badges. */

export type ApiSource = "live" | "demo";

export interface ApiResult<T = unknown> {
  source: ApiSource;
  data: T | null;
  error?: string;
}

let backendLive: boolean | null = null;
let checked = false;
const TOKEN_KEY = "zelinx_token";

export function getToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

const ROLES_KEY = "zelinx_roles";

export function getRoles(): string[] {
  try { return JSON.parse(localStorage.getItem(ROLES_KEY) || "[]"); } catch { return []; }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(ROLES_KEY); }
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
    if (!resp.ok) return { source: "demo", data: null, error: `HTTP ${resp.status}` };
    return { source: "live", data: (await resp.json()) as T };
  } catch (e) {
    return { source: "demo", data: null, error: String(e) };
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
    const body = (await resp.json()) as { token?: string; roles?: string[] };
    if (body.token) {
      setToken(body.token);
      try { localStorage.setItem("zelinx_roles", JSON.stringify(body.roles || [])); } catch { /* ignore */ }
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
}
export interface ScopeEntryItem { id: string; kind: string; target: string }
export interface OnboardingConn {
  id: string; kind: string; name: string; method: string; mode: string;
  status: string; agent_healthy?: boolean;
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
export interface DiscoveryPlan {
  run_id: string; status: string; organization: string; sector: string;
  environments: number;
  plan: { domain: string; targets: number | string; mode: string }[];
  authorized_scope: Record<string, number>;
  connectors_used: string[];
  next_steps: string[];
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

/* React glue (useApi hook + LiveBadge) lives in apiUi.tsx */
export { useApi, LiveBadge } from "./apiUi.jsx";
