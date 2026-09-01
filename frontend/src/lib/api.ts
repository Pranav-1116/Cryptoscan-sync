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

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
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

export async function apiLogin(username: string, password: string): Promise<{ ok: boolean; error?: string }> {
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
    const body = (await resp.json()) as { token?: string };
    if (body.token) setToken(body.token);
    return { ok: !!body.token, error: body.token ? undefined : "no token in response" };
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

/* React glue (useApi hook + LiveBadge) lives in apiUi.tsx */
export { useApi, LiveBadge } from "./apiUi.jsx";
