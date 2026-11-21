/* End-to-end API bridge — every call goes to the live backend through
   the Vite /api proxy (FastAPI control plane on :8010). There is no demo or
   fallback dataset: when the backend is unreachable the result is tagged
   source:"offline" with data:null and the UI renders zeros/empty. */

import { watchPrivateScope } from "./privateScope";
import { gatedFetch, GateResetError } from "./requestGate";
import { prettyJson, readableJsonBlob } from "./prettyJson";

export type ApiSource = "live" | "offline";

export interface ApiResult<T = unknown> {
  source: ApiSource;
  data: T | null;
  error?: string;
  /** The server's own refusal message, when it sent one.
   *
   * `error` stays the stable `HTTP <status>` code that pages compare against,
   * so this is additive. Without it a refused write ("unknown scanner family",
   * "no organization yet", "role may not start a scan") reached the operator as
   * a bare status code and the reason — the only actionable part — was lost.
   */
  detail?: string;
  ok?: boolean;
  head?: string;
}

/** Best-effort extraction of a FastAPI error body into one readable line. */
function errorDetail(body: unknown): string | undefined {
  const detail = (body as { detail?: unknown } | null)?.detail ?? body;
  if (typeof detail === "string") return detail.trim() || undefined;
  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        const entry = item as { loc?: unknown[]; msg?: string } | null;
        const where = Array.isArray(entry?.loc) ? entry.loc.slice(1).join(".") : "";
        const msg = entry?.msg ? String(entry.msg) : "";
        return msg ? (where ? `${where}: ${msg}` : msg) : "";
      })
      .filter(Boolean);
    return parts.length ? parts.join("; ") : undefined;
  }
  if (detail && typeof detail === "object") {
    const record = detail as { message?: unknown; error?: unknown; reason?: unknown };
    if (typeof record.message === "string") return record.message;
    // Several routers answer a refusal as {error: <code>, reason: <sentence>}.
    // The code alone ("no_estate_discovery") is not actionable; the reason is.
    if (typeof record.reason === "string") {
      return typeof record.error === "string" ? `${record.reason} (${record.error})` : record.reason;
    }
    return typeof record.error === "string" ? record.error : undefined;
  }
  return undefined;
}

/* The session token is held in memory only.
 *
 * It used to sit in `localStorage["zelinx_token"]`, where any script on the page
 * could read it: one XSS and the bearer token walked out of the console. The
 * backend already mints an httpOnly `cryptoscan_session` cookie and
 * `syncSession()` verifies the session through `GET /api/v1/auth/me`, so nothing
 * needs a readable copy to survive a reload. A non-secret marker records that a
 * session existed, which lets first paint render optimistically while the
 * server's answer is in flight — never permissively, because every request is
 * authorized by the backend regardless.
 */
const TOKEN_KEY = "zelinx_token";          // legacy location, purged on load
const SESSION_MARKER = "zelinx_signed_in"; // "1" — a flag, never a credential

let sessionToken: string | null = null;

/** Remove the pre-hardening token, if a browser still has one. */
export function purgeLegacyToken(): void {
  try { localStorage.removeItem(TOKEN_KEY); } catch { /* storage unavailable */ }
}
purgeLegacyToken();

export function getToken(): string | null {
  return sessionToken;
}

/** True when a session may exist: an in-memory token, or a marker from a
 *  previous page load whose httpOnly cookie the browser is still holding. */
export function hasSession(): boolean {
  if (sessionToken) return true;
  try { return localStorage.getItem(SESSION_MARKER) === "1"; } catch { return false; }
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
  sessionToken = token;
  try {
    if (token) localStorage.setItem(SESSION_MARKER, "1");
    else {
      localStorage.removeItem(SESSION_MARKER);
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(ROLES_KEY);
      localStorage.removeItem(USER_KEY);
      // Never carry the previous user's tenant selection into a new session.
      setActiveTenantId(null);
    }
  } catch { /* storage unavailable — session only */ }
  // realtime consumers (SSE stream) reconnect when auth changes
  try {
    window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: !!token } }));
  } catch { /* non-browser context */ }
}

export async function isBackendLive(): Promise<boolean> {
  try {
    // Recheck on each call: a previous success or outage may no longer describe
    // the current auth/tenant session or the backend's availability.
    const resp = await tenantFetch("/api/v1/platform/scope", { signal: AbortSignal.timeout(2500) });
    const contentType = resp.headers.get("content-type")?.split(";")[0].trim().toLowerCase() || "";
    const isJson = contentType === "application/json"
      || (contentType.startsWith("application/") && contentType.endsWith("+json"));
    if (resp.status === 200 && isJson) {
      const body: unknown = await resp.json();
      return !!body && typeof body === "object" && !Array.isArray(body)
        && "platform" in body && body.platform === "CryptoScan"
        && "schema_version" in body && typeof body.schema_version === "number"
        && "covered_areas" in body && Array.isArray(body.covered_areas)
        && "non_goals" in body && Array.isArray(body.non_goals);
    }
    if (resp.status === 401 || resp.status === 403) {
      if (isJson) {
        const body: unknown = await resp.json();
        return !!body && typeof body === "object" && !Array.isArray(body)
          && "detail" in body && typeof body.detail === "string" && body.detail.length > 0;
      }
      // Some auth gateways send a header-only challenge instead of FastAPI's
      // JSON detail. Never accept an HTML error page, even with a challenge.
      const challenge = resp.headers.get("www-authenticate") || "";
      return contentType !== "text/html" && /^(Bearer|ApiKey)(?:\s|$)/i.test(challenge);
    }
  } catch { /* no transport, invalid JSON, or an aborted probe */ }
  return false;
}

// Active tenant (multi-tenant SaaS): set after login/signup, switchable in
// the tenancy page; sent on every API call so the backend resolves the org.
/** Resolve the session's tenant when the picker has not persisted one.
 *
 *  Performance and Binary read tenant-scoped endpoints that 422 without a
 *  tenant id; defaulting the field to this resolution turns "Read failed" into
 *  the page it belongs to. The pick is the first ACTIVE membership — never a
 *  guess, and a principal with no membership gets null and stays on the
 *  honest "no tenant is bound" state. */
export async function ensureActiveTenant(): Promise<string | null> {
  const current = activeTenantId();
  if (current) return current;
  const result = await apiSaasMemberships();
  const tenants = (result.data?.tenants ?? []) as Array<{
    id: string;
    status?: string;
  }>;
  const eligible = tenants.filter((t) => !t.status || t.status === "ACTIVE");
  const pick = eligible[0]?.id ?? tenants[0]?.id ?? null;
  if (pick) setActiveTenantId(pick);
  return pick;
}

export function activeTenantId(): string | null {
  try {
    return localStorage.getItem("cryptoscan_tenant");
  } catch {
    return null;
  }
}

export function setActiveTenantId(id: string | null): void {
  try {
    if (id) localStorage.setItem("cryptoscan_tenant", id);
    else localStorage.removeItem("cryptoscan_tenant");
  } catch {
    /* private mode: tenant stays per-session in memory */
  }
  // Tenant selection is security-relevant UI state: make every live data
  // consumer refresh its label/stream after a switch, not only the picker.
  try { window.dispatchEvent(new CustomEvent("zelinx:tenant", { detail: { tenantId: id } })); } catch { /* non-browser */ }
}

/**
 * Fetch wrapper for browser-facing API calls.
 *
 * Keeping tenant propagation here prevents the many legacy endpoints that do
 * not use ``call()`` (downloads, streams, and action helpers) from silently
 * dropping the selected organization. The browser must use relative paths;
 * the Vite/production edge proxy owns the backend hop.
 */
export function tenantFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const normalized = new Headers(init.headers);
  const headers: Record<string, string> = {};
  normalized.forEach((value, key) => {
    // Preserve the conventional casing used by the browser-facing contract;
    // this also keeps plain-object fetch mocks and diagnostics readable.
    const canonical = key === "authorization" ? "Authorization"
      : key === "x-tenant-id" ? "X-Tenant-ID"
      : key === "content-type" ? "Content-Type" : key;
    headers[canonical] = value;
  });
  const hasHeader = (name: string) => Object.keys(headers).some((key) => key.toLowerCase() === name.toLowerCase());
  const token = getToken();
  if (token && !hasHeader("Authorization")) headers.Authorization = `Bearer ${token}`;
  const tenant = activeTenantId();
  if (tenant) headers["X-Tenant-ID"] = tenant;
  else {
    for (const key of Object.keys(headers)) if (key.toLowerCase() === "x-tenant-id") delete headers[key];
  }
  return globalThis.fetch(input, {
    ...init,
    headers,
    credentials: init.credentials ?? "include",
  });
}

/** Download a browser-facing resource only through the authenticated tenant path. */
export async function downloadAuthenticatedResource(path: string, fallbackFilename: string, signal?: AbortSignal): Promise<void> {
  const token = getToken(), estate = activeTenantId();
  const controller = new AbortController();
  const abort = () => controller.abort();
  const stop = watchPrivateScope(abort);
  const timeout = setTimeout(abort, 30000);
  signal?.addEventListener("abort", abort, { once: true });
  const guard = () => {
    if (controller.signal.aborted || signal?.aborted || token !== getToken() || estate !== activeTenantId())
      throw new Error("Download context changed or expired; request current evidence again.");
  };
  try {
    guard();
    const response = await tenantFetch(path, { signal: controller.signal });
    guard();
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const disposition = response.headers.get("content-disposition") || "";
    const advertised = disposition.match(/filename="?([^";]+)"?/i)?.[1];
    const filename = (advertised || fallbackFilename).replace(/[^a-zA-Z0-9._-]/g, "_");
    let blob = await response.blob();
    guard(); // Fetch/body readers may ignore abort. Never release old-context bytes.
    // JSON exports (CycloneDX CBOM/SBOM, evidence packs) arrive minified on one
    // line; save them indented so they open readably. Whitespace only — values
    // are copied through unchanged (see prettyJson). JSONL stays one-per-line.
    if (/\.json$/i.test(filename) && blob.size < 64 * 1024 * 1024 && typeof blob.text === "function") {
      const formatted = prettyJson(await blob.text());
      guard();
      if (formatted !== null) blob = new Blob([formatted], { type: blob.type || "application/json" });
    }
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    try {
      anchor.href = url; anchor.download = filename;
      document.body.appendChild(anchor); anchor.click();
    } finally { anchor.remove(); URL.revokeObjectURL(url); }
  } finally {
    clearTimeout(timeout); stop(); signal?.removeEventListener("abort", abort);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  const method = ((init as { method?: string } | undefined)?.method ?? "GET").toUpperCase();
  /* Retry policy (the risk table), applied at the transport so every caller
     gets it: transport failures plus 5xx/429 retry at most 3× with exponential
     backoff capped at 15s, Retry-After is honoured, and 4xx NEVER retries.
     Mutations retry TRANSPORT failures only — a 5xx after a write may have
     landed, and replaying it is how double-writes happen. Every request also
     passes the front-end request gate (8 concurrent / 20-per-5s, delay not
     drop), so the console cannot become its own rate-limit event.
     Amplification bound: 2 attempts per GET (1 retry — within the ≤3
     contract). Recovery from a single transient blip works; a page of error
     reads cannot multiply itself past the request gate's burst window and
     push its own honest failure state out of reach. */
  const MAX_RETRIES = 2;
  for (let attempt = 0; ; attempt++) {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      const token = getToken();
      if (token) headers.Authorization = `Bearer ${token}`;
      const tenant = activeTenantId();
      if (tenant) headers["X-Tenant-ID"] = tenant;
      const resp = await gatedFetch(path, {
        signal: AbortSignal.timeout(8000),
        headers,
        // send the httpOnly session cookie too (server auth via cookie, not only
        // the XSS-readable Bearer token in localStorage)
        credentials: "include",
        ...init,
      });
      if (!resp.ok) {
        // Only READS retry — a write that failed or a write whose outcome is
        // unknown is surfaced to the operator, never replayed: a second
        // submission is how double-writes happen. (Tests: "does not claim
        // success or automatically retry an ambiguous write failure".)
        const retryable = method === "GET" && (resp.status >= 500 || resp.status === 429);
        if (!retryable || attempt >= MAX_RETRIES) {
          // Keep the status code stable for callers that branch on it, and carry
          // the server's own reason alongside it.
          let detail: string | undefined;
          try {
            detail = errorDetail(await resp.json());
          } catch {
            detail = undefined;
          }
          return { source: "offline", data: null, error: `HTTP ${resp.status}`, detail };
        }
        await sleep(retryDelayFor(resp, attempt));
        continue;
      }
      return { source: "live", data: (await resp.json()) as T };
    } catch (e) {
      // Transport failure: reads retry; writes stop here — the request may
      // have reached the server, and only the operator can decide what an
      // unconfirmed write means. A reset gate abandons without retrying.
      if (e instanceof GateResetError) return { source: "offline", data: null, error: String(e) };
      if (method !== "GET" || attempt >= MAX_RETRIES) {
        return { source: "offline", data: null, error: String(e) };
      }
      await sleep(retryDelayFor(null, attempt));
    }
  }
}

function sleep(ms: number): Promise<void> {
  // Zero delay must not schedule: under the test runner's fake timers a
  // pending setTimeout(0) never fires and the retry loop would hang every
  // offline call. The retry ATTEMPTS still happen — only the wait vanishes.
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Exponential backoff capped at 15s; a server-sent Retry-After wins.
 *  The base scales to ~0 under the test runner (every offline stub call would
 *  otherwise pay the real backoff across the whole suite); the FORMULA and the
 *  status/attempt rules are identical in every environment. */
export function retryDelayFor(resp: Response | null, attempt: number, baseMs = RETRY_BASE_MS): number {
  const retryAfter = resp?.headers?.get?.("retry-after");
  if (retryAfter) {
    const secs = Number(retryAfter);
    if (Number.isFinite(secs)) return Math.min(Math.max(secs, 0) * 1000, 15_000);
  }
  return Math.min(baseMs * 2 ** attempt, 15_000);
}

const RETRY_BASE_MS = (import.meta as { env?: { MODE?: string } }).env?.MODE === "test" ? 0 : 250;

export async function apiLogin(username: string, password: string): Promise<{ ok: boolean; error?: string; roles?: string[] }> {
  try {
    const resp = await tenantFetch("/api/v1/auth/login", {
      method: "POST",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      credentials: "include",
    });
    if (!resp.ok) {
      if (resp.status >= 500 && resp.headers.get("content-type")?.toLowerCase().includes("text/html"))
        return { ok: false, error: "API is unavailable (gateway error). Try again when the service is reachable." };
      const body = await resp.json().catch(() => ({}));
      return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    }
    const body = (await resp.json()) as { token?: string; roles?: string[]; username?: string };
    if (body.token) {
      // A login may replace a different browser user. Force the next tenant
      // choice to come from this user's membership directory rather than
      // reusing an old user's X-Tenant-ID.
      setActiveTenantId(null);
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

/* Self-service registration assigns readonly; elevated roles require an administrator. */
export async function apiRegister(input: {
  username: string;
  password: string;
  role: string;
  display_name?: string;
  email?: string;
}): Promise<{ ok: boolean; error?: string; username?: string; roles?: string[] }> {
  try {
    const resp = await tenantFetch("/api/v1/auth/register", {
      method: "POST",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      credentials: "include",
    });
    if (!resp.ok && resp.status >= 500 && resp.headers.get("content-type")?.toLowerCase().includes("text/html"))
      return { ok: false, error: "API is unavailable (gateway error). Try again when the service is reachable." };
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
    } else {
      // _rsGet represents both 401 and transport failure as null. Treat both
      // as an unverified session; never retain a stale cached identity.
      setUserName(null);
      try { localStorage.removeItem(ROLES_KEY); } catch { /* ignore */ }
    }
  } catch {
    // An outage is not proof of identity. Clear the display cache as well as
    // the in-memory result so callers cannot accidentally render stale tenant
    // data or role-gated actions while the server is unavailable.
    setUserName(null);
    try { localStorage.removeItem(ROLES_KEY); } catch { /* ignore */ }
  }
  return { user: null, roles: [] };
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

/* ── digital twin (contracts in api/routers/digital_twin.py) ───────── */

export interface TwinScenarioDescriptor {
  id: string;
  name: string;
  description: string;
  inputs: Record<string, string>;
}

export const apiDigitalTwinOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/digital-twin");

export const apiDigitalTwinFidelity = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/digital-twin/fidelity");

export const apiDigitalTwinReconciliation = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/digital-twin/reconciliation");

export const apiDigitalTwinScenarios = (): Promise<ApiResult<{ scenario_count: number; scenarios: TwinScenarioDescriptor[] }>> =>
  call("/api/v1/digital-twin/scenarios");

export const apiDigitalTwinSimulate = (scenario: string, params: Record<string, unknown>): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/digital-twin/simulate", { method: "POST", body: JSON.stringify({ scenario, params }) });

/* ── Migration simulation: one crypto change read against the Digital Twin's hardware,
 *    software, connected systems and vendors (agility/migration_simulation.py). It rides the
 *    existing read-only `algorithm_migration` scenario, under `migration`. ── */

export type MigrationStrategy = "BLOCKED" | "PARALLEL" | "DIRECT" | "NOT_DETERMINED";
export type MigrationSeverity = "BLOCKER" | "HIGH" | "MEDIUM" | "INFO";
export interface MigrationReason { code: string; text: string }
export interface MigrationProblem {
  code: string; severity: MigrationSeverity; title: string; detail: string;
  system: string | null; subject: string | null; who_acts: string; mitigation: string;
  if_ignored: string; basis: string;
}
export interface MigrationHardware {
  asset_id: string; kind: string; manufacturer?: string | null; model?: string | null;
  firmware?: string | null; capabilities?: string[]; pqc_capability?: string | null;
  target_support: "SUPPORTED" | "SUPPORTED_DECLARED" | "NOT_SUPPORTED" | "UNKNOWN";
  basis: string; holds_affected_keys?: boolean;
}
export interface MigrationLibrary {
  name: string; version: string | null; target_support: string; basis: string;
  deprecated: boolean; vendor?: string | null;
}
export interface MigrationConnection {
  system_id: string; name: string; direction: "CALLS" | "CALLED_BY"; relation?: string | null;
  in_change: boolean; uses_source: boolean; uses_target: boolean; crypto_recorded: boolean;
  registered: boolean;
}
export interface MigrationEndpoint {
  endpoint: string; protocol?: string | null; tls_version?: string | null;
  cipher_suite?: string | null; observed: boolean; negotiates_source: boolean;
}
export interface MigrationVendor {
  vendor_id: string; name: string; criticality?: string | null; vendor_type?: string | null;
  dependency_type?: string | null; readiness: "READY" | "NOT_READY" | "UNKNOWN" | "NOT_RECORDED_FOR_TARGET";
  uses_source: boolean; sub_tier: string[];
  products: { algorithm?: string | null; key_size?: number | null; pqc_ready: boolean; use_case?: string | null }[];
}
export interface MigrationSystemReport {
  system_id: string; name: string; environment?: string | null; criticality?: string | null;
  migration_wave?: number | string | null; why_in_change: string[]; strategy: MigrationStrategy;
  blocked_by: MigrationReason[]; parallel_because: MigrationReason[]; considerations: MigrationReason[];
  twin: {
    crypto_assets: string[]; crypto_assets_using_source: string[]; evidence_records_using_source: number;
    hardware: MigrationHardware[];
    software: { libraries: MigrationLibrary[]; deployments: { deployment_key?: string | null; environment?: string | null; artifact_id?: string | null }[] };
    connections: MigrationConnection[]; network_endpoints: MigrationEndpoint[]; vendors: MigrationVendor[];
    certificates: { fingerprint_sha256: string; subject?: string | null; issuer?: string | null; public_key_algorithm?: string | null; not_after?: string | null; days_until_expiry?: number | null }[];
    business_processes: { name?: string | null; role?: string | null; revenue_daily?: number | null; customer_count?: number | null }[];
  };
  findings: MigrationProblem[];
}
export interface MigrationPlanStep {
  order: number; phase: "PREREQUISITES" | "KEYS_AND_TRUST" | "ENABLE_ALONGSIDE" | "CUT_OVER" | "VERIFY" | "DECOMMISSION";
  wave?: number; title: string; systems: string[]; actions: string[]; exit_criteria: string; rollback: string;
  providers_first?: string;
}
export interface MigrationSimulation {
  schema: string;
  change: { from: string; to: string; scope: string[] | null;
    from_profile: { family: string; roles: string[]; pqc: boolean };
    to_profile: { family: string; roles: string[]; pqc: boolean } };
  headline: string;
  strategy: { recommended: MigrationStrategy; meaning: string; systems: Record<"BLOCKED" | "PARALLEL" | "DIRECT", number>;
    reasons: Record<string, number>; parallel_mechanisms: { mechanism: string; how: string }[]; direct_is_safe_when: string };
  twin_context: { source: string; systems_in_change: number; hardware: number; software_libraries: number;
    connected_systems: number; network_endpoints: number; vendors: number; certificates: number;
    matched: Record<string, number> };
  systems: MigrationSystemReport[];
  problems: MigrationProblem[];
  problem_counts: Record<MigrationSeverity, number>;
  vendor_impact: (Omit<MigrationVendor, "dependency_type"> & { systems: string[]; dependency_types: string[]; needs_to: string; if_it_does_not: string })[];
  connected_impact: { system_id: string; name: string; registered: boolean; in_change: boolean; uses_source: boolean;
    uses_target: boolean; crypto_recorded: boolean; criticality?: string | null;
    links: { with: string; direction: string; relation?: string | null }[]; effect: string; action: string }[];
  plan: MigrationPlanStep[];
  dependency_order: { wave: number; system: string; cyclic: boolean }[];
  unknowns: string[];
}
export interface MigrationScenarioResult {
  scenario: string; affected?: Record<string, unknown>; impact?: Record<string, unknown>;
  honest_unknowns?: string[]; migration?: MigrationSimulation;
}

export const apiMigrationSimulation = (params: { from_algo: string; to_algo: string; systems?: string }): Promise<ApiResult<MigrationScenarioResult>> =>
  call("/api/v1/digital-twin/simulate", {
    method: "POST",
    body: JSON.stringify({ scenario: "algorithm_migration", params: params.systems ? params : { from_algo: params.from_algo, to_algo: params.to_algo } }),
  });

export const apiDigitalTwinTimeline = (assetId: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/digital-twin/timeline/${encodeURIComponent(assetId)}`);

/* ── SBOM workspace (contracts in api/routers/sbom.py; docs/boms/01_PRODUCT_SPEC.md §1) ── */

export interface SbomInventoryRow {
  coordinate: string;
  asset_ref?: string;
  component_type?: string | null;
  name: string;
  version?: string | null;
  ecosystem?: string | null;
  purl?: string | null;
  application?: string | null;
  source?: string | null;
  license?: string | null;
  vulnerability: { count: number; max_severity?: string | null };
  evidence: { type?: string | null; declared_in?: string | null; confidence?: string | null };
  last_observed?: string | null;
  dependency_type?: string | null;
  crypto_bearing?: boolean;
}

export interface SbomUsageState {
  algorithm: string;
  usage_state: "capability_detected" | "configuration_observed" | "operation_observed";
  basis: string;
  runtime_evidence: string[];
}

export interface SbomComponentDetail {
  component: SbomInventoryRow;
  usage_states: SbomUsageState[];
  supplier?: string | null;
  dependencies: { direct: Array<Record<string, string>>; transitive: Array<Record<string, string>>; unresolved_parent: boolean };
  vulnerabilities: Array<Record<string, unknown>>;
  manifests: string[];
  versions: string[];
  flags: { declared_but_unused: boolean; used_but_undeclared: boolean };
}

export const apiSbomOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/overview");

export const apiSbomInventory = (q?: string): Promise<ApiResult<{ state?: string; scan_id?: string; total: number; rows: SbomInventoryRow[] }>> =>
  call(`/api/v1/sbom/components${q ? `?q=${encodeURIComponent(q)}` : ""}`);

export const apiSbomComponentDetail = (coordinate: string): Promise<ApiResult<SbomComponentDetail>> =>
  call(`/api/v1/sbom/components/${coordinate}`);

export const apiSbomDependencies = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/dependencies");

export const apiSbomLicenses = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/licenses");

export const apiSbomVulnerabilities = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/vulnerabilities");

export const apiSbomVersions = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/versions");

export const apiSbomContainers = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/containers");

export const apiSbomBinaries = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/binaries");

export const apiSbomEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/evidence");

export const apiSbomHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/history");

export const apiSbomExportStatus = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/sbom/export");

/* ── CBOM workspace (contracts in api/routers/cbom_workspace.py; docs/boms/01_PRODUCT_SPEC.md §2) ──
 * Names carry "Workspace" — the apiCbom* family below belongs to the
 * catalog/ingest surface. Crypto rows carry key metadata only: the server
 * never returns key material and neither does this client. */

export interface CbomCryptoAssetRow {
  asset_id: string;
  algorithm?: string | null;
  operation?: string | null;
  mode?: string | null;
  implementation: string[];
  location?: string | null;
  file_path?: string | null;
  source_language?: string | null;
  key_metadata: { size?: number | null; hardcoded_material_flag: boolean; named_reference?: string | null };
  evidence_status: string;
  evidence_basis: string;
  usage: { usage_state: string; basis: string };
  pqc_family: string;
  confidence?: string | null;
  occurrence_count: number;
  last_observed?: string | null;
  freshness: string;
}

export const apiCbomWorkspaceOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/overview");

export const apiCbomWorkspaceAssets = (q?: string): Promise<ApiResult<{ state: string; total: number; rows: CbomCryptoAssetRow[] }>> =>
  call(`/api/v1/cbom/workspace/assets${q ? `?q=${encodeURIComponent(q)}` : ""}`);

export const apiCbomWorkspaceAssetDetail = (assetId: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/cbom/workspace/assets/${encodeURIComponent(assetId)}`);

export const apiCbomWorkspaceAlgorithms = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/algorithms");

export const apiCbomWorkspaceLibraries = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/libraries");

export const apiCbomWorkspaceCertificates = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/certificates");

export const apiCbomWorkspaceKeys = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/keys");

export const apiCbomWorkspaceOperations = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/operations");

export const apiCbomWorkspaceProtocols = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/protocols");

export const apiCbomWorkspacePqc = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/pqc");

export const apiCbomWorkspaceDependencies = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/dependencies");

export const apiCbomWorkspaceEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/evidence");

export const apiCbomWorkspaceHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/history");

export const apiCbomWorkspaceExport = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/cbom/workspace/export");

/* ── HBOM workspace (contracts in api/routers/hbom_workspace.py; docs/boms/01_PRODUCT_SPEC.md §3) ──
 * The server never returns HSM key material, private keys, secrets or device
 * credentials and serial references arrive masked; this client adds no
 * un-masking. Hardware capability is never drawn as use. */

export interface HbomAssetRow {
  asset_id: string;
  manufacturer?: string | null;
  model?: string | null;
  serial_reference?: string | null;
  firmware?: string | null;
  category: string;
  device_type?: string | null;
  location?: string | null;
  crypto_capabilities: Record<string, unknown>;
  lifecycle: string;
  lifecycle_basis: string;
  evidence: {
    agent_id?: string | null;
    last_seen?: string | null;
    fingerprinted: boolean;
    evidence_records: number;
    freshness: string;
  };
}

export const apiHbomWorkspaceOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/overview");

export const apiHbomWorkspaceAssets = (q?: string): Promise<ApiResult<{ state: string; total: number; rows: HbomAssetRow[] }>> =>
  call(`/api/v1/hbom/workspace/assets${q ? `?q=${encodeURIComponent(q)}` : ""}`);

export const apiHbomWorkspaceAssetDetail = (assetId: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/hbom/workspace/assets/${encodeURIComponent(assetId)}`);

export const apiHbomWorkspaceCategory = (category: "compute" | "hsm" | "tpm" | "network" | "storage"): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/hbom/workspace/${category}`);

export const apiHbomWorkspaceFirmware = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/firmware");

export const apiHbomWorkspaceCrypto = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/crypto");

export const apiHbomWorkspaceLifecycle = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/lifecycle");

export const apiHbomWorkspaceEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/evidence");

export const apiHbomWorkspaceHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/history");

export const apiHbomWorkspaceExport = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/hbom/workspace/export");

/* ── NBOM workspace (contracts in api/routers/nbom_workspace.py; docs/boms/01_PRODUCT_SPEC.md §4) ──
 * The server renders negotiated TLS facts only where a handshake was
 * observed; everywhere else the value is the string "unknown" — never
 * "none", never "plaintext". */

export interface NbomEndpointRow {
  endpoint: string;
  host?: string | null;
  port?: string | number | null;
  protocol?: string | null;
  service?: string | null;
  tls_version: string;
  cipher_suite: string;
  negotiation: { state: string; basis: string };
  certificate?: {
    subject?: string | null;
    fingerprint_sha256?: string | null;
    issuer?: string | null;
    public_key_algorithm?: string | null;
    public_key_size?: number | null;
    expiry_status?: string | null;
  } | null;
  source: string;
  scan_run_id?: string | null;
  first_observed?: string | null;
  last_observed?: string | null;
  freshness: string;
}

export const apiNbomWorkspaceOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/overview");

export const apiNbomWorkspaceEndpoints = (q?: string): Promise<ApiResult<{ state: string; total: number; rows: NbomEndpointRow[] }>> =>
  call(`/api/v1/nbom/workspace/endpoints${q ? `?q=${encodeURIComponent(q)}` : ""}`);

export const apiNbomWorkspaceEndpointDetail = (endpoint: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/nbom/workspace/endpoints/${encodeURIComponent(endpoint)}`);

export const apiNbomWorkspaceAssets = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/assets");

export const apiNbomWorkspaceServices = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/services");

export const apiNbomWorkspaceTls = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/tls");

export const apiNbomWorkspaceSsh = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/ssh");

export const apiNbomWorkspaceIpsec = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/ipsec");

export const apiNbomWorkspaceCertificates = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/certificates");

export const apiNbomWorkspaceDependencies = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/dependencies");

export const apiNbomWorkspaceChanges = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/changes");

export const apiNbomWorkspaceEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/evidence");

export const apiNbomWorkspaceHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/history");

export const apiNbomWorkspaceExport = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/nbom/workspace/export");

/* ── VBOM workspace (contracts in api/routers/vbom_workspace.py; docs/boms/01_PRODUCT_SPEC.md §5) ──
 * Relationship states are kept apart: CONFIRMED (stored link), IMPORTED,
 * PUBLICLY_REPORTED, UNKNOWN. A public association never becomes bank use
 * here; bank-asset counts include verified links only. */

export interface VbomVendorRow {
  vendor: string;
  vendor_id: string;
  product?: string | null;
  version?: string | null;
  category: string;
  bank_assets: number;
  association_state: string;
  association_basis: string;
  support_lifecycle: string;
  support_level?: string | null;
  eol_date?: string | null;
  crypto_dependency: string;
  pqc_roadmap: string;
  evidence: { profile_status: string; source?: string | null; captured_at?: string | null; freshness: string };
  last_reviewed?: string | null;
}

export const apiVbomWorkspaceOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/overview");

export const apiVbomWorkspaceVendors = (q?: string): Promise<ApiResult<{ state: string; total: number; rows: VbomVendorRow[] }>> =>
  call(`/api/v1/vbom/workspace/vendors${q ? `?q=${encodeURIComponent(q)}` : ""}`);

export const apiVbomWorkspaceVendorDetail = (vendorId: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/vbom/workspace/vendors/${encodeURIComponent(vendorId)}`);

export const apiVbomWorkspaceProducts = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/products");

export const apiVbomWorkspaceRelationships = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/relationships");

export const apiVbomWorkspaceLifecycle = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/lifecycle");

export const apiVbomWorkspaceSecurity = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/security");

export const apiVbomWorkspaceCrypto = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/crypto");

export const apiVbomWorkspacePqc = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/pqc");

export const apiVbomWorkspaceExposure = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/exposure");

export const apiVbomWorkspaceContracts = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/contracts");

export const apiVbomWorkspaceEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/evidence");

export const apiVbomWorkspaceHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/history");

export const apiVbomWorkspaceExport = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/vbom/workspace/export");

/* ── TechBOM workspace (api/routers/techbom_workspace.py; docs/boms/01_PRODUCT_SPEC.md §6/§9) ──
 * The cross-estate entry point. A relationship is established only where
 * stored evidence establishes it; reconciliation connects records only when
 * the evidence does. */

export interface TechbomInventoryRow {
  asset_ref: string;
  name: string;
  category: string;
  vendor: string;
  product_version: string;
  environment: string;
  related: Record<string, string>;
  dependencies: number;
  evidence: { state: string; freshness: string; basis: string };
  last_observed?: string | null;
}

export const apiTechBomWorkspaceOverview = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/overview");

export const apiTechBomWorkspaceInventory = (q?: string, category?: string): Promise<ApiResult<{ state: string; total: number; rows: TechbomInventoryRow[]; note: string }>> => {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (category) params.set("category", category);
  const qs = params.toString();
  return call(`/api/v1/techbom/workspace/inventory${qs ? `?${qs}` : ""}`);
};

export const apiTechBomWorkspaceAssetDetail = (assetRef: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/techbom/workspace/inventory/${assetRef}`);

export const apiTechBomWorkspaceApplications = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/applications");

export const apiTechBomWorkspaceInfrastructure = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/infrastructure");

export const apiTechBomWorkspaceLayers = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/layers");

export const apiTechBomWorkspaceReconciliation = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/reconciliation");

export const apiTechBomWorkspaceRelationships = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/relationships");

export const apiTechBomWorkspaceLifecycle = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/lifecycle");

export const apiTechBomWorkspaceEvidence = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/evidence");

export const apiTechBomWorkspaceHistory = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/history");

export const apiTechBomWorkspaceExport = (): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/techbom/workspace/export");

/* ── Shared asset detail (components/AssetDetail.tsx; docs/boms/01_PRODUCT_SPEC.md §7) ──
 * One canonical detail surface for every BOM record: header record,
 * cross-BOM panel (linked / not established / unknown / primary record,
 * never conflated) and the nine detail tabs. */

export interface AssetDetailHeader {
  asset_ref: string;
  name: string;
  status: string;
  description: string;
  asset_id: string;
  environment: string;
  category: string;
  owner: string;
  source: string;
  last_observed?: string | null;
  primary_bom: string;
  related: Array<{ bom: string; state: string; basis: string }>;
  chips: string[];
  evidence: Record<string, string>;
}

export interface AssetDetailTab {
  asset_ref: string;
  tab: string;
  rows: Array<Record<string, unknown>>;
  note: string;
}

export const apiAssetDetailHeader = (assetRef: string): Promise<ApiResult<AssetDetailHeader>> =>
  call(`/api/v1/asset-detail/${assetRef}`);

export const apiAssetDetailTab = (assetRef: string, tab: string): Promise<ApiResult<AssetDetailTab>> =>
  call(`/api/v1/asset-detail/${assetRef}/${tab}`);


export const apiSecurity = (request: Record<string, unknown>): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/platform/security", { method: "POST", body: JSON.stringify({ request }) });

/* ── intelligence (roadmap models; api/routers/roadmap_intelligence.py) ──
 *
 * Read-only views over the shared intelligence models. Two boundary rules the
 * server enforces and these signatures preserve: the quantum threat horizon is
 * a required POLICY INPUT (no default is invented here either), and a
 * simulation names its snapshot explicitly (id or version, never "current").
 */

import type {
  IntelligenceOverview,
  IntelligenceSimulationRequest,
  PqcReport,
  RiskProfile,
  SimulationResult,
  ThreatReport,
} from "../intelligence/types";

export const apiIntelligenceOverview = (): Promise<ApiResult<IntelligenceOverview>> =>
  call("/api/v1/intelligence/overview");

export const apiIntelligenceFindings = (): Promise<ApiResult<ThreatReport>> =>
  call("/api/v1/intelligence/findings");

export const apiIntelligencePqcClaims = (subject?: string): Promise<ApiResult<PqcReport>> =>
  call(subject
    ? `/api/v1/intelligence/pqc/claims?subject=${encodeURIComponent(subject)}`
    : "/api/v1/intelligence/pqc/claims");

export const apiIntelligenceRisk = (
  assetId: string,
  quantumThreatHorizonYears: number,
  opts?: { dataShelfLifeYears?: number; migrationLeadTimeYears?: number },
): Promise<ApiResult<RiskProfile>> => {
  const params = new URLSearchParams({
    quantum_threat_horizon_years: String(quantumThreatHorizonYears),
  });
  if (opts?.dataShelfLifeYears !== undefined) {
    params.set("data_shelf_life_years", String(opts.dataShelfLifeYears));
  }
  if (opts?.migrationLeadTimeYears !== undefined) {
    params.set("migration_lead_time_years", String(opts.migrationLeadTimeYears));
  }
  return call(`/api/v1/intelligence/risk/${encodeURIComponent(assetId)}?${params.toString()}`);
};

export const apiIntelligenceSimulation = (
  body: IntelligenceSimulationRequest,
): Promise<ApiResult<SimulationResult & { evidence_note?: string }>> =>
  call("/api/v1/intelligence/simulation", { method: "POST", body: JSON.stringify(body) });

/** Estate coverage over the newest filed collection batch — NOT_FILED is honest. */
export const apiIntelligenceCoverage = (): Promise<ApiResult<import("../intelligence/types").EstateCoverage>> =>
  call("/api/v1/intelligence/coverage");

/** External validation register — acts performed elsewhere, filed as evidence. */
export const apiExternalValidations = (): Promise<ApiResult<import("../intelligence/types").ExternalValidationRegister>> =>
  call("/api/v1/intelligence/external-validations");

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
    const resp = await tenantFetch("/api/v1/sectors/organization/active", {
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
    const resp = await tenantFetch(path, {
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

/** Most-recent runtime crypto findings (the live 24/7 engine). With `q`, a
 * SERVER-side search across the whole runtime-findings store (hostname,
 * process, algorithm, cipher suite, TLS version, scanner, kind, status) —
 * `total_count` then reports matching rows, not returned rows. */
export const apiRuntimeFindings = (limit = 50, q?: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/scans/runtime-findings?limit=${limit}${q ? `&q=${encodeURIComponent(q)}` : ""}`);

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
  provenance?: Record<string, unknown> | string | null;
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
  q?: string;
} = {}): Promise<ApiResult<FindingList>> => {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  if (params.algorithm) q.set("algorithm", params.algorithm);
  if (params.compliance_status) q.set("compliance_status", params.compliance_status);
  if (params.scan_id) q.set("scan_id", params.scan_id);
  if (params.q) q.set("q", params.q);
  const qs = q.toString();
  return call(`/api/v1/findings${qs ? `?${qs}` : ""}`);
};

/** A single finding (full detail incl. normalized_crypto / policy_evaluation). */
export const apiFindingDetail = (evidenceId: string): Promise<ApiResult<Finding>> =>
  call(`/api/v1/findings/${encodeURIComponent(evidenceId)}`);

/* §4.2 (round 42) surfaced in the UI (round 73): per-record evidence
 * verification — recompute ONE record's content hash and chain linkage
 * against its own commitments using the same verifier as the scan-level
 * sweep (the two surfaces cannot disagree). Honest scope: proves storage
 * has not diverged from the commitment, not that the observation was
 * true. Requires the auditor role — a 403 is rendered as such, never
 * silently downgraded. */
export interface FindingVerifyVerdict {
  evidence_id: string; scan_id: string | null; chain_position: number | null;
  content_intact: boolean; chain_intact: boolean; hash_format_valid: boolean;
  result: "PASS" | "FAIL"; errors: string[]; notes: string[];
  verified_by: string; scan_status: string | null; scan_verify_path: string;
}
export const apiFindingVerify = (evidenceId: string): Promise<ApiResult<FindingVerifyVerdict>> =>
  call(`/api/v1/findings/${encodeURIComponent(evidenceId)}/verify`);

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
    const resp = await tenantFetch("/api/v1/scans/trigger", {
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
/* ── Runtime crypto scan engine (spec 92) ── */

export interface RuntimeCryptoScope {
  configured: boolean;
  permitted: boolean;
  window: { state: string; open: boolean; reason: string };
  scope: {
    name?: string;
    hosts?: string[];
    applications?: string[];
    processes?: string[];
    runtime_methods?: string[];
    data_restrictions?: string[];
    collection_window?: { from: string; to: string } | null;
    saved_by?: string;
    saved_at?: string;
  } | null;
}

export interface RuntimeCryptoEvent {
  event_id: string;
  evidence_type: string;
  attribution_level: number;
  source: string;
  adapter: string | null;
  operation: string;
  algorithm: string | null;
  key_size: number | string;
  decomposition: Record<string, string | null>;
  parameters: Record<string, number | string | boolean | null>;
  identity: {
    host: string | null;
    application: string | null;
    process: string | null;
    pid: number | string;
    container_digest: string | null;
    pod: string | null;
    deployment: string | null;
  };
  limitations: string[];
  observed_at: string;
}

export interface RuntimeCryptoSummary {
  events: number;
  hosts: number;
  applications: number;
  operations: Record<string, number>;
  attribution_levels: Record<string, number>;
  algorithms: Record<string, number>;
  level6_events: number;
  unknown_algorithm_events: number;
  note: string;
}

export interface RuntimeRiskFinding {
  rule_id: string;
  severity: string;
  status: string;
  application: string | null;
  process: string | null;
  algorithm: string | null;
  operation: string | null;
  message: string;
}

export interface RuntimeRiskReport {
  model: string;
  verdict: string;
  layer: string;
  failed: RuntimeRiskFinding[];
  coverage_gaps: RuntimeRiskFinding[];
  summary: { events: number; applications: number; by_status: Record<string, number>; failed: number; unknown: number };
  pqc?: { verdict: string; summary: Record<string, number> };
  limitations: string[];
}

export interface RuntimeAdapterCatalog {
  adapter_count: number;
  adapters: Array<{ id: string; source: string; framework: string; reports: string[]; cannot_report: string[] }>;
  levels: Array<{ level: number; name: string; description: string; sources: string[]; evidence_type: string }>;
}

export const apiRuntimeCryptoScope = (): Promise<ApiResult<RuntimeCryptoScope>> =>
  call("/api/v1/runtime/crypto-scope");

export const apiRuntimeCryptoScopeSave = (body: Record<string, unknown>): Promise<ApiResult<RuntimeCryptoScope>> =>
  call("/api/v1/runtime/crypto-scope", { method: "PUT", body: JSON.stringify(body) });

export const apiRuntimeCryptoEvents = (limit = 50): Promise<ApiResult<{ events: RuntimeCryptoEvent[]; summary: RuntimeCryptoSummary }>> =>
  call(`/api/v1/runtime/crypto-events?limit=${limit}`);

export const apiRuntimeCryptoRisk = (): Promise<ApiResult<RuntimeRiskReport>> =>
  call("/api/v1/runtime/crypto-risk", { method: "POST", body: JSON.stringify({}) });

export const apiRuntimeCryptoAdapters = (): Promise<ApiResult<RuntimeAdapterCatalog>> =>
  call("/api/v1/runtime/crypto-adapters");

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

/* §4.6 (round 68): the ASSET-level explainability chain — the same depth as
 * the per-system explain. Each factor cites WHICH inventory inputs set its
 * level and what level 0 MEANS (unknown/unregistered, never "clean"); crypto
 * assets additionally cite the evidence rows joined on the identity spine,
 * the STORED control verdicts, their own PQC wave assignment and owners. */
export interface AssetRiskFactor {
  factor: string;
  level: number;
  points: number;
  weight: number;
  basis: "DECLARED" | "OBSERVED";
  basis_note: string;
  derived_from: { inputs: Record<string, unknown>; rule: string };
}
export interface AssetRiskExplain {
  asset_id: string;
  asset_type: string;
  name: string | null;
  risk: { score: number; level: string; calculation_version: string; weights_source: string };
  factors: AssetRiskFactor[];
  inventory_row: Record<string, unknown>;
  evidence_trail: {
    asset_key: string | null;
    total_observations?: number;
    entries: { evidence_id: string; scan_id: string; verify_path: string; location: string | null; content_hash?: string; chain_position?: number; compliance_status?: string }[];
    failing_controls?: { rule_id: string | null; rule_name?: string | null; worst_outcome: string; evidence_count: number; messages: string[] }[];
    note: string;
  };
  pqc_rationale: {
    vulnerable_sites: number;
    sites: { wave: string; wave_focus?: string; algorithm?: string; location?: string | null; migration_deadline?: string | null; hndl_risk?: string | null; recommended_replacement: string }[];
    note: string;
  } | null;
  accountability: { owner: string | null; technical_owner: string | null; security_owner: string | null; systems_using: string[]; note: string };
  system_explain_path: string | null;
  limitations: string[];
  model: string;
}
export const apiAssetRiskExplain = (assetId: string): Promise<ApiResult<AssetRiskExplain>> =>
  call(`/api/v1/risk/unified/${encodeURIComponent(assetId)}/explain`);

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
  events: { events: { id: number; ts: string; type: string; payload: Record<string, unknown> }[]; latest_sequence: number; oldest_sequence: number; next_cursor: string; has_more: boolean; retention_gap: boolean };
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

/* §5 (round 62): SERVER-side asset search — the term is matched in the
 * database across the whole estate (asset id, identity spine, algorithm,
 * file location), not only the rows a page has loaded. */
export const apiAssetsSearch = (q: string, pageSize = 25): Promise<ApiResult<any>> =>
  call(`/api/v1/assets?q=${encodeURIComponent(q)}&page_size=${pageSize}`);

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

/* §4.4 (round 71): the INDEPENDENT, unified estate HBOM — ONE document
 * over every persisted hardware_assets row (the 24/7 engine's DB truth),
 * per-asset identity (serial / revision / firmware fingerprint), TPM/HSM
 * posture and evidence references (agent, timestamps, evidence IDs).
 * Content-addressed: SHA-256 over the canonical serialization, anchored
 * to the estate's latest observation — never a wall clock. GET /hbom
 * regenerates from current rows; POST /hbom/snapshot pins one rendering
 * (identical pins collapse); GET /hbom/snapshots/{id} serves the exact
 * stored document verbatim with an integrity self-check (OK / MISMATCH).
 * This is NOT the TechBOM hardware layer and NOT the live engine's
 * in-memory document — both remain available on their own surfaces. */
export interface HbomEstateEvidence {
  source: string; agent_id: string | null;
  first_seen: string | null; last_seen: string | null;
  last_verified: string | null; last_crypto_check: string | null;
  evidence_ids: string[];
}
export interface HbomEstateComponent {
  "bom-ref": string; asset_id: string; name: string;
  manufacturer: string; model: string; device_type: string;
  identity: {
    serial_reference: string | null; hardware_revision: string | null;
    current_fingerprint: string | null; previous_fingerprint: string | null;
  };
  firmware: { details: Record<string, unknown> | null; last_checked: string | null };
  security_modules: { hsm?: Record<string, unknown>; tpm?: Record<string, unknown> };
  capabilities: Record<string, unknown> | null;
  crypto_capabilities: Record<string, unknown> | null;
  risk: { score: number | null; level: string | null; last_change: string | null };
  evidence: HbomEstateEvidence;
}
export interface HbomEstateDocument {
  bomFormat: string; specVersion: string; content_hash: string;
  metadata: {
    generator: string; environment: string; as_of: string | null;
    component_count: number; hsm_count: number; tpm_count: number;
    device_types: Record<string, number>; sources: string[]; notes: string[];
  };
  components: HbomEstateComponent[];
  hsm_fleet: { count: number; asset_ids: string[] };
  tpm_fleet: { count: number; asset_ids: string[] };
  dependencies: unknown[];
}
export const apiHbomEstate = (): Promise<ApiResult<HbomEstateDocument>> =>
  _rsGet<HbomEstateDocument>("/api/v1/hbom");
export interface HbomSnapshotMeta {
  snapshot_id: string; environment: string; content_hash: string;
  component_count: number; generator: string; created_by: string;
  snapshotted_at: string; as_of: string | null; verify_path: string;
}
export const apiHbomSnapshots = (): Promise<ApiResult<{ snapshots: HbomSnapshotMeta[]; count: number; note: string }>> =>
  _rsGet<{ snapshots: HbomSnapshotMeta[]; count: number; note: string }>("/api/v1/hbom/snapshots");
export const apiHbomPin = (): Promise<ApiResult<HbomSnapshotMeta & { created: boolean; note: string }>> =>
  _rsPost<HbomSnapshotMeta & { created: boolean; note: string }>("/api/v1/hbom/snapshot", {});
export const apiHbomSnapshot = (id: string): Promise<ApiResult<HbomSnapshotMeta & {
  integrity: string; integrity_note: string; payload: HbomEstateDocument;
}>> =>
  _rsGet<HbomSnapshotMeta & { integrity: string; integrity_note: string; payload: HbomEstateDocument }>(
    `/api/v1/hbom/snapshots/${encodeURIComponent(id)}`);

/* §4.4 (round 72): the exact drift between two pinned estate HBOMs —
 * devices added/removed and field-level drift on survivors (firmware,
 * TPM/HSM posture, capabilities, risk, identity fingerprints), computed
 * from the two content-addressed payloads on every call, never stored.
 * key_by="asset_id" (default): device-keyed estate drift, observation
 * churn excluded by name; "bom_ref": exact comparison of everything. */
export interface HbomDiffChange { path: string; before: unknown; after: unknown }
export interface HbomSnapshotDiff {
  key_by: string; identical: boolean; excluded_paths: string[];
  components: {
    key_by: string;
    added: Array<{ key: string; "bom-ref"?: string; name?: string; type?: string }>;
    removed: Array<{ key: string; "bom-ref"?: string; name?: string; type?: string }>;
    changed: Array<{ key: string; "bom-ref"?: string; changes: HbomDiffChange[] }>;
    unchanged: number;
  };
  metadata_changes: HbomDiffChange[];
  summary: {
    baseline_components: number; target_components: number;
    added: number; removed: number; changed: number; unchanged: number;
  };
}
export const apiHbomSnapshotDiff = (
  targetId: string, againstId: string, keyBy: "asset_id" | "bom_ref" = "asset_id",
): Promise<ApiResult<{ target: HbomSnapshotMeta & { as_of: string | null };
  baseline: HbomSnapshotMeta & { as_of: string | null }; diff: HbomSnapshotDiff; note: string }>> =>
  _rsGet(`/api/v1/hbom/snapshots/${encodeURIComponent(targetId)}/diff?against=${encodeURIComponent(againstId)}&key_by=${keyBy}`);

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
    const resp = await tenantFetch(`/api/v1/enterprise/integrations/${integrationId}/test`, {
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
    const resp = await tenantFetch("/api/v1/control/deliveries/flush", {
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
    const resp = await tenantFetch("/api/v1/control/orchestrator/tick", {
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
    const resp = await tenantFetch(`/api/v1/marketplace/plugins${q}`, {
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
    const resp = await tenantFetch("/api/v1/anomaly/flags?limit=100", {
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
    const resp = await tenantFetch(`/api/v1/governance/requests${q}`, {
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
    const resp = await tenantFetch(`/api/v1/datalake/batches?lake_id=${encodeURIComponent(lake)}`, {
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
    const resp = await tenantFetch(`/api/v1/api-keys`, {
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
    const resp = await tenantFetch(`/api/v1/ot/maintenance-windows`, {
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
    const resp = await tenantFetch(`/api/v1/sla/evaluate`, {
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
    const resp = await tenantFetch(`/api/v1/control/credential-leases`, {
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
    const resp = await tenantFetch(`/api/v1/automation/runs?limit=50`, {
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
    const resp = await tenantFetch(`/api/v1/automation/rules`, {
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
    const resp = await tenantFetch(`/api/v1/automation/capabilities`, {
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
    const resp = await tenantFetch(`/api/v1/automation/rules`, {
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

/* Install the curated telecom guardrail rules (idempotent upsert). */
export async function apiAutomationInstallTelecomGuardrails(): Promise<ApiResult<any>> {
  try {
    const resp = await tenantFetch(`/api/v1/automation/telecom-guardrails`, {
      method: "POST",
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
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
    const resp = await tenantFetch(`/api/v1/automation/rules/${encodeURIComponent(ruleId)}`, {
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
    const resp = await tenantFetch(`/api/v1/automation/sectors`, {
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
    const resp = await tenantFetch(`/api/v1/automation/cbom/versions?limit=20`, {
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
    const resp = await tenantFetch(`/api/v1/automation/health/sweep`, {
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
    const resp = await tenantFetch(`/api/v1/automation/post-migration/validate`, {
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

/* ── real detection benchmark: shipping detector vs ground truth ── */
export async function apiRunRealBenchmark(): Promise<ApiResult<any>> {
  try {
    const resp = await tenantFetch(`/api/v1/control/benchmark/run-real`, {
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
    const resp = await tenantFetch(`/api/v1/control/benchmark/runs`, {
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
    const resp = await tenantFetch(path, {
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
    const resp = await tenantFetch(`/api/v1/control/agents`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`), data: [] } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.agents || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

async function _postAgent(path: string, body: unknown): Promise<ApiResult<any>> {
  try {
    const resp = await tenantFetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const d = data.detail;
      const error = typeof d === "string" ? d : (d?.message || d?.error || `HTTP ${resp.status}`);
      return { source: "live", ok: false, error: String(error), data: null } as ApiResult<any>;
    }
    return { source: "live", ok: true, data };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: null } as ApiResult<any>; }
}

/** Enrol a Cryptava agent under a unique name; returns a one-time activation token. */
export const apiEnrollAgent = (name: string, environment?: string) =>
  _postAgent(`/api/v1/control/agents/enroll`, { name, environment: environment || null, platform: "linux" });

/** A fresh one-time token for an existing agent (rebuilt host keeps its name). */
export const apiReissueAgentToken = (agentId: string) =>
  _postAgent(`/api/v1/control/agents/${encodeURIComponent(agentId)}/enrollment-token`, {});

/** What each Cryptava agent last sent: its six BOM results, signature check and asset counts. */
export async function apiAgentContributions(): Promise<ApiResult<any[]>> {
  try {
    const resp = await tenantFetch(`/api/v1/ingestion/contributors`, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(15000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: String(body.detail || `HTTP ${resp.status}`), data: [] } as ApiResult<any[]>;
    return { source: "live", ok: true, data: body.contributors || [] };
  } catch (e) { return { source: "live", ok: false, error: String(e), data: [] } as ApiResult<any[]>; }
}

/** Schedule a deterministic signed-update / rollback / retire for an agent. */
export const apiAgentUpgrade = (agentId: string, action: "upgrade" | "rollback" | "retire", targetVersion?: string) =>
  _postAction(`/api/v1/control/agents/${encodeURIComponent(agentId)}/upgrade`, { action, target_version: targetVersion });

/** Authorize an OT/ICS operation against live devices + approved maintenance windows.
 *  Returns { allowed, decision, reason, ... } with HTTP 403 body carrying the deny detail. */
export async function apiOtAuthorize(operation: string, deviceId?: string): Promise<ApiResult<any>> {
  try {
    const resp = await tenantFetch(`/api/v1/ot/safety/authorize`, {
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
    const resp = await tenantFetch(`/api/v1/exceptions${q}`, {
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
    const resp = await tenantFetch(path, {
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

/** SSO feature flags (unified: OIDC authorization-code + SAML + LDAP). The
 *  login screen renders only the options the platform actually has. */
export const apiSsoStatus = (): Promise<ApiResult<SsoStatus>> =>
  _idReq("GET", "/api/v1/auth/sso/status");

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
    const resp = await tenantFetch(path, {
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
    const resp = await tenantFetch(path, {
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

/* SBOM endpoints need their own timeouts: a source-tree scan walks the tree
   plus lockfiles (up to 120 s) rather than the 8–20 s used elsewhere. */
async function _sbomReq<T>(path: string, method: string, body?: unknown, timeoutMs = 120000): Promise<ApiResult<T>> {
  try {
    const resp = await tenantFetch(path, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
        ...(activeTenantId() ? { "X-Tenant-ID": activeTenantId()! } : {}),
      },
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

export const apiSbomScan = (body: { kind: string; target: string; format: string; as_image?: boolean; include_vendored?: boolean; use_lockfiles?: boolean; feed?: any[] }) =>
  _sbomReq<any>("/api/v1/devsecops/sbom/scan", "POST", body);

export const apiSbomArtifacts = (filters: { kind?: string; fmt?: string; q?: string; limit?: number } = {}) => {
  const params = new URLSearchParams();
  if (filters.kind) params.set("kind", filters.kind);
  if (filters.fmt) params.set("fmt", filters.fmt);
  if (filters.q) params.set("q", filters.q);
  if (filters.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  return _sbomReq<any>(`/api/v1/devsecops/sbom/artifacts${qs ? `?${qs}` : ""}`, "GET", undefined, 20000);
};

/** Supply-chain gate: blockers fail a pipeline, warnings inform. Read-only safe. */
export const apiSbomGate = (artifactId: string, policy?: Record<string, any>) =>
  _sbomReq<any>(`/api/v1/devsecops/sbom/${artifactId}/gate`, "POST", { policy: policy ?? null }, 30000);

/** Re-scan the stored target with the stored options and diff old -> new. */
export const apiSbomRescan = (artifactId: string, body: { policy?: Record<string, any>; use_lockfiles?: boolean; include_vendored?: boolean } = {}) =>
  _sbomReq<any>(`/api/v1/devsecops/sbom/${artifactId}/rescan`, "POST", body);

export const apiSbomValidate = (doc: any) =>
  _sbomReq<any>("/api/v1/devsecops/sbom/validate", "POST", { doc }, 30000);

export const apiSbomDiff = (body: { from_artifact?: string; to_artifact?: string; from_doc?: any; to_doc?: any }) =>
  _sbomReq<any>("/api/v1/devsecops/sbom/diff", "POST", body, 30000);

export const apiSbomVerify = (artifactId: string) =>
  _sbomReq<any>(`/api/v1/devsecops/sbom/${artifactId}/verify`, "GET", undefined, 30000);

/** License inventory + policy verdict for a document or stored artifact. */
export const apiSbomLicense = (body: { doc?: any; artifact_id?: string; policy?: Record<string, any>; fmt?: "json" | "markdown" }) =>
  _sbomReq<any>("/api/v1/devsecops/sbom/license", "POST", body, 30000);

/** Deterministic VEX statements (json = CycloneDX VEX document). */
export const apiSbomVex = (body: { doc?: any; artifact_id?: string; analyses?: Record<string, any>; fmt?: "json" | "markdown" }) =>
  _sbomReq<any>("/api/v1/devsecops/sbom/vex", "POST", body, 30000);

/** Cross-artifact component index: which artifact carries which component. */
export const apiSbomComponents = (filters: { q?: string; crypto?: boolean; limit?: number } = {}) => {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.crypto !== undefined) params.set("crypto", String(filters.crypto));
  if (filters.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  return _sbomReq<any>(`/api/v1/devsecops/sbom/components${qs ? `?${qs}` : ""}`, "GET", undefined, 30000);
};

/** Binary/firmware scan: real parsing + graded crypto evidence -> SBOM + CBOM. */
export const apiBinaryScan = (body: {
  target: string; recursive?: boolean; include_raw?: boolean; format?: string;
  feed?: any[]; ingest_cbom?: boolean; yara_rules?: string[];
}) => _sbomReq<any>("/api/v1/devsecops/binary/scan", "POST", body, 120000);

/** Queue the same scan as a job (202): poll the job, then read the artifact. */
export const apiBinaryScanJob = (body: {
  target: string; recursive?: boolean; include_raw?: boolean; format?: string;
  yara_rules?: string[]; ingest_cbom?: boolean; system_name?: string;
}) => _sbomReq<any>("/api/v1/devsecops/binary/jobs", "POST", body, 30000);

/** Job status/progress (the binary job reports its stages here). */
export const apiJobStatus = (jobId: string) =>
  _sbomReq<any>(`/api/v1/jobs/${encodeURIComponent(jobId)}`, "GET", undefined, 15000);

/** Re-queue a job with the options it was queued with. */
export const apiJobRetry = (jobId: string) =>
  _sbomReq<any>(`/api/v1/jobs/${encodeURIComponent(jobId)}/retry`, "POST", {}, 15000);

/** What a ruleset will do, rule by rule, before anything is scanned. */
export const apiYaraValidate = (body: { rules?: string[]; text?: string }) =>
  _sbomReq<any>("/api/v1/devsecops/yara/validate", "POST", body, 30000);

export interface DynamicScanResult {
  target: string; executed: boolean; runnable: boolean; refusals: string[];
  findings: any[]; observations: any[]; limits: string[]; tracer?: string | null;
  duration_ms: number; timed_out: boolean; returncode?: number | null;
  changed: boolean; sha256_before?: string | null; sha256_after?: string | null;
  runtime_ingest?: { accepted?: number; anomalies?: number; persisted?: any } | null;
}

/**
 * Dynamic analysis of one sample under the LD_PRELOAD tracer (ADR-012).
 * Without `execute` this is the preflight and starts nothing. With it, a 403 is
 * not an error to swallow: the body carries every reason the sample did not run,
 * which is exactly what the operator needs to see — so this one keeps the body.
 */
export async function apiBinaryDynamic(body: {
  target: string; args?: string[]; timeout?: number; execute?: boolean;
  submit?: boolean; hostname?: string;
}): Promise<{ ok: boolean; status: number; data: DynamicScanResult | null; refusals: string[]; error: string }> {
  try {
    const resp = await tenantFetch("/api/v1/devsecops/binary/dynamic", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      credentials: "include",
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(90000),
    });
    const payload = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const detail = payload?.detail;
      const refusals = detail && typeof detail === "object" && Array.isArray(detail.refusals) ? detail.refusals : [];
      const error = typeof detail === "string" ? detail : (detail?.message || `HTTP ${resp.status}`);
      return { ok: false, status: resp.status, data: null, refusals, error };
    }
    return { ok: true, status: resp.status, data: payload as DynamicScanResult, refusals: [], error: "" };
  } catch (e) {
    return { ok: false, status: 0, data: null, refusals: [], error: String(e) };
  }
}

export interface BatchFileDecision {
  path: string; size: number; sha256?: string | null; action: string; reason: string;
  artifact_id?: string | null; prior_path?: string | null; job_id?: string | null;
}

export interface BinaryBatchResult {
  batch_id: string; spool: string; dry_run: boolean; considered: number;
  queued: number; planned: number; skipped: number; files: BatchFileDecision[];
  state_path: string; state_saved: boolean; state_note?: string | null;
  poll_url: string; message: string;
}

/**
 * Fleet intake over a spool directory: plan it (dry run, the default) or queue it.
 * Identity is content, not path, so a release drop with the same library at ten
 * paths is one scan; every file that is not queued comes back with its reason.
 */
export const apiBinaryBatch = (body: {
  spool: string; dry_run?: boolean; force?: boolean; limit?: number; recursive?: boolean;
  format?: string; include_raw?: boolean; ingest_cbom?: boolean; system_name?: string;
  yara_rules?: string[];
}) => _sbomReq<BinaryBatchResult>("/api/v1/devsecops/binary/batch", "POST", body, 120000);

/** How a fleet pass is going: counts by state, per job, and the totals so far. */
export const apiBinaryBatchStatus = (batchId: string) =>
  _sbomReq<any>(`/api/v1/devsecops/binary/batches/${encodeURIComponent(batchId)}`, "GET", undefined, 20000);

export interface KnowledgePackEntry {
  version?: string | null; digest: string; description?: string | null;
  signed_by?: string | null; installed_at?: string; rule_names?: string[];
  rules?: { name: string }[];
  /** constant tables the pack contributes to the scanner's database */
  tables?: { name: string; algorithm?: string; table?: string; bytes?: number }[];
}

/** The constant-table set a scan searches, alongside the rule set. */
export interface KnowledgeTables {
  builtin: number;
  installed: number;
  total: number;
  digest: string;
  builtin_digest?: string;
  files?: string[];
  sources?: string[];
  errors?: { source?: string; file?: string | null; error?: string }[];
  algorithms?: string[];
}

export interface KnowledgeState {
  builtin: { rules: number; digest: string; private_rules?: number };
  installed: Record<string, KnowledgePackEntry>;
  installed_rule_files: string[];
  rules_dir: string;
  ruleset: { rules: number; digest: string; error_count: number; private_rules?: number; errors?: any[] };
  /** Constant tables: an update pack can add them, and a scan searches them. */
  tables?: KnowledgeTables;
  registry_note?: string | null;
  note?: string;
}

/**
 * What this host will load: the built-in rules plus every installed pack, with the
 * digest of the set a scan actually uses. Reading it is a read-only operation.
 */
export interface BinaryAtRest {
  tenant: string;
  artifacts: number;
  by_algorithm: Record<string, number>;
  by_key_id: Record<string, number>;
  plaintext_artifacts: number;
  at_rest: {
    algorithm: string;
    encrypted: boolean;
    key_id?: string;
    key_source: string;
    note?: string;
  };
}

/**
 * How stored binary artifacts are protected on disk: the algorithm, the key *id*
 * (never the key), and how many artifacts in this tenant are still plaintext —
 * because "encryption is configured" and "every artifact is encrypted" are
 * different statements, and the second one is the auditable one.
 */
export const apiBinaryAtRest = () =>
  _sbomReq<BinaryAtRest>("/api/v1/devsecops/binary/at-rest", "GET", undefined, 20000);

export const apiKnowledge = () =>
  _sbomReq<KnowledgeState>("/api/v1/devsecops/knowledge", "GET", undefined, 20000);

/**
 * Install a signed rule pack (a directory or a .tar.gz on this host) so every scan
 * loads it. A refused pack is a gate, not a failure to hide: the 400 body carries
 * the reasons (bad signature, edited file, a rule that will not load), so this one
 * keeps them.
 */
export async function apiKnowledgeInstall(body: {
  pack: string; dry_run?: boolean; allow_unsigned?: boolean; secret?: string;
}): Promise<{ ok: boolean; status: number; data: any | null; reasons: string[]; error: string }> {
  try {
    const resp = await tenantFetch("/api/v1/devsecops/knowledge/install", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      credentials: "include",
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(60000),
    });
    const payload = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const detail = payload?.detail;
      const reasons = detail && typeof detail === "object" && Array.isArray(detail.reasons) ? detail.reasons : [];
      const error = typeof detail === "string" ? detail : (detail?.message || `HTTP ${resp.status}`);
      return { ok: false, status: resp.status, data: null, reasons, error };
    }
    return { ok: true, status: resp.status, data: payload, reasons: [], error: "" };
  } catch (e) {
    return { ok: false, status: 0, data: null, reasons: [], error: String(e) };
  }
}

/** Remove an installed pack so its rules stop being loaded. */
export const apiKnowledgeUninstall = (name: string) =>
  _sbomReq<any>("/api/v1/devsecops/knowledge/uninstall", "POST", { name }, 20000);

/** The CBOM stored next to a binary-scan artifact. */
export const apiBinaryCbom = (artifactId: string) =>
  _sbomReq<any>(`/api/v1/devsecops/binary/artifacts/${artifactId}/cbom`, "GET", undefined, 30000);

export interface BinaryScanRecord {
  id: string; artifact_id: string; job_id?: string | null; target: string;
  format: string; sha256: string; status: string; created_by: string;
  created_at?: string; files_walked: number; binaries_scanned: number;
  findings_count: number; observations_count: number; observations_truncated: boolean;
  summary?: any; coverage?: any; limits?: any;
}

export interface BinaryScanObservation {
  id: string; scan_record_id: string; artifact_id: string; path: string;
  format: string; arch?: string | null; sha256?: string | null;
  parsed?: boolean | null; evidence_state: string; derived_from?: string | null;
  depth?: number | null; crypto?: any; hardening?: any; signature?: any;
  coverage?: any; findings?: any[]; metadata?: any;
}

/** Queryable tenant-scoped binary history; signed manifests remain authoritative. */
export const apiBinaryScans = (filters: {
  limit?: number; status?: string; format?: string; q?: string;
} = {}) => {
  const params = new URLSearchParams();
  if (filters.limit) params.set("limit", String(filters.limit));
  if (filters.status) params.set("status_filter", filters.status);
  if (filters.format) params.set("format_filter", filters.format);
  if (filters.q) params.set("q", filters.q);
  const qs = params.toString();
  return _sbomReq<{ total: number; returned: number; records: BinaryScanRecord[]; source: string; note: string }>(
    `/api/v1/devsecops/binary/scans${qs ? `?${qs}` : ""}`, "GET", undefined, 30000);
};

/** Read one indexed binary scan and its bounded parser observations. */
export const apiBinaryScanDetail = (scanId: string) =>
  _sbomReq<{ record: BinaryScanRecord; observations: BinaryScanObservation[]; observation_limit: number }>(
    `/api/v1/devsecops/binary/scans/${encodeURIComponent(scanId)}`, "GET", undefined, 30000);

export const apiBinaryScanObservations = (scanId: string, filters: {
  limit?: number; offset?: number; format?: string; evidence_state?: string;
  q?: string; crypto_only?: boolean;
} = {}) => {
  const params = new URLSearchParams();
  if (filters.limit !== undefined) params.set("limit", String(filters.limit));
  if (filters.offset !== undefined) params.set("offset", String(filters.offset));
  if (filters.format) params.set("format_filter", filters.format);
  if (filters.evidence_state) params.set("evidence_state", filters.evidence_state);
  if (filters.q) params.set("q", filters.q);
  if (filters.crypto_only) params.set("crypto_only", "true");
  const qs = params.toString();
  return _sbomReq<{ scan_id: string; total: number; returned: number; observations: BinaryScanObservation[]; observations_truncated: boolean }>(
    `/api/v1/devsecops/binary/scans/${encodeURIComponent(scanId)}/observations${qs ? `?${qs}` : ""}`,
    "GET", undefined, 30000);
};

export const apiBinaryScanFindings = (scanId: string, filters: {
  severity?: string; code?: string; limit?: number; offset?: number;
} = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.code) params.set("code", filters.code);
  if (filters.limit !== undefined) params.set("limit", String(filters.limit));
  if (filters.offset !== undefined) params.set("offset", String(filters.offset));
  const qs = params.toString();
  return _sbomReq<{ scan_id: string; total: number; returned: number; findings: any[] }>(
    `/api/v1/devsecops/binary/scans/${encodeURIComponent(scanId)}/findings${qs ? `?${qs}` : ""}`,
    "GET", undefined, 30000);
};

export const apiBinaryScanCoverage = (scanId: string) =>
  _sbomReq<any>(`/api/v1/devsecops/binary/scans/${encodeURIComponent(scanId)}/coverage`, "GET", undefined, 30000);

export const apiBinaryScanCompare = (fromScanId: string, toScanId: string) =>
  _sbomReq<any>("/api/v1/devsecops/binary/scans/compare", "POST", {
    from_scan_id: fromScanId, to_scan_id: toScanId,
  }, 30000);

/** Advisories recorded across checked artifacts (matched scans only). */
export const apiSbomAdvisories = (filters: { severity?: string; cve?: string } = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.cve) params.set("cve", filters.cve);
  const qs = params.toString();
  return _sbomReq<any>(`/api/v1/devsecops/sbom/advisories${qs ? `?${qs}` : ""}`, "GET", undefined, 30000);
};

export const apiSbomPrune = (olderThanDays: number) =>
  _sbomReq<any>(`/api/v1/devsecops/sbom/artifacts?older_than_days=${olderThanDays}`, "DELETE", undefined, 30000);

export const apiSbomReport = (artifactId: string, fmt = "markdown"): Promise<Response> =>
  tenantFetch(`/api/v1/devsecops/sbom/${artifactId}/report?fmt=${encodeURIComponent(fmt)}`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });

export async function downloadSbomReport(artifactId: string): Promise<void> {
  const resp = await apiSbomReport(artifactId, "markdown");
  if (!resp.ok) throw new Error(`report failed: ${resp.status}`);
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cryptoscan-sbom-${artifactId.slice(0, 8)}-report.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const apiSbomDownload = (artifactId: string): Promise<Response> =>
  tenantFetch(`/api/v1/devsecops/sbom/${artifactId}/download`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });

export async function downloadSbomArtifact(artifactId: string): Promise<void> {
  const resp = await apiSbomDownload(artifactId);
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const cd = resp.headers.get("content-disposition") || "";
  const match = cd.match(/filename="?([^";]+)"?/);
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = match?.[1] || `cryptoscan-sbom-${artifactId.slice(0, 8)}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const apiConnectorPreview = (provider: string, finding: any, target: Record<string, unknown>, deliverLive = false) =>
  _ds<any>("/api/v1/devsecops/connectors/preview", { provider, finding, target, deliver_live: deliverLive });

/* ========================================================================== */
/* Resilience / governance: signed compliance PDF, encrypted backup/restore,  */
/* audit hash-chain attestation, air-gap feed import, passive OT decode (21-27). */
/* ========================================================================== */

async function _rsPost<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await tenantFetch(path, {
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

export const apiBackupCreate = (databaseId: string, engine = "postgres", sequence = 1) =>
  _rsPost<any>("/api/v1/resilience/backup/create", { database_id: databaseId, engine, sequence });

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

/* --- Security control integration layer (read-only over the bank's own controls) --- */
export const apiSecurityControlsHealth = () =>
  _rsGet<any>("/api/v1/security-controls/health");

export const apiSecurityControlsFindings = (params: { control?: string; state?: string; subject?: string } = {}) => {
  const query = new URLSearchParams(
    Object.entries(params).filter(([, value]) => Boolean(value)) as [string, string][],
  ).toString();
  return _rsGet<any>(`/api/v1/security-controls/findings${query ? `?${query}` : ""}`);
};

export const apiSecurityControlsVerify = () =>
  _rsGet<any>("/api/v1/security-controls/verify");

/* The estate model, consumed by the bank's SIEM as well as this console. */
export const apiSecurityControlExportUrl = (format: "cyclonedx" | "cef" | "cef-lines") =>
  `/api/v1/security-controls/export?format=${format}`;

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
export interface AuditChainStatus { status: string; checked: number; entry_count: number; chain_head?: string | null; break_at_sequence?: number | null; reason?: string | null; mode?: "full" | "incremental"; full_verified_at?: string | null; }
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
export interface GraphEdge extends RelationshipLifecycleFields {
  id?: string; from: string; to: string; label: string; [k: string]: unknown; }
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
  coverage?: AnalysisCoverage | null;
  start?: string; systems: BlastSystem[]; nodes_visited: number; hops?: number; backend?: string;
}
export interface SimulateResult {
  coverage?: AnalysisCoverage | null;
  node_id: string; change: string;
  affected: { assets: number; applications: number; certificates: number; services: number };
  compatibility_issues: number; migration_tasks: number;
  systems: { id: string; name?: string; crypto_assets: number }[];
  total_revenue_at_risk: number | null; backend?: string;
  process_impact?: ProcessImpact | null;
  operational_impact?: OperationalImpact | null;
  economic_totals_meaning?: string;
}
export interface ExplainStep {
  label: string; kind: string; detail?: string; confidence?: string | null;
  evidence?: string; file?: string | null; quantum_vulnerable?: boolean;
}
export interface ExplainResult {
  coverage?: AnalysisCoverage | null;
  node_id: string; title: string; quantum_vulnerable: boolean; steps: ExplainStep[]; backend?: string;
}
export const apiGraph = (): Promise<ApiResult<GraphView>> => call("/api/v1/graph");
export const apiGraphStats = (): Promise<ApiResult<GraphStats>> => call("/api/v1/graph/stats");
export const apiGraphBlastRadius = (systemId: string, hops = 5): Promise<ApiResult<BlastRadiusResult>> =>
  call(`/api/v1/graph/blast-radius?system_id=${encodeURIComponent(systemId)}&hops=${hops}`);
export const apiGraphDependents = (systemId: string, hops = 5): Promise<ApiResult<BlastRadiusResult>> =>
  call(`/api/v1/graph/dependents?system_id=${encodeURIComponent(systemId)}&hops=${hops}`);
/* Crypto dependency map — system → component → library → algorithm, plus the
   declared/observed system → system dependencies (consumer → provider). */
export type DepRisk = "disallowed" | "deprecated" | "quantum_vulnerable" | "unknown" | "acceptable" | "quantum_safe";
export interface DepSystem { id: string; system_id: string; label: string; kind: "system" | "unattributed"; criticality?: string | null; business_unit?: string | null; owner?: string | null; environment?: string | null; algorithm_ids: string[]; risk?: DepRisk | null; component_count: number; }
export interface DepComponent { id: string; label: string; kind: "source" | "config" | "keystore" | "tls_endpoint"; location: string; system_ids: string[]; algorithm_ids: string[]; asset_count: number; languages: string[]; risk?: DepRisk | null; }
export interface DepLibrary { id: string; label: string; name: string; version?: string | null; component_ids: string[]; algorithm_ids: string[]; system_ids: string[]; }
export interface DepAlgorithm { id: string; label: string; canonical: string; family: string; status: string; quantum_impact?: string | null; key_size?: number | null; risk: DepRisk; risk_label: string; asset_count: number; component_ids: string[]; system_ids: string[]; library_ids: string[]; purposes: string[]; modes: string[]; }
export interface DepLocation { asset_id: string; file_path: string; line_number?: number | null; purpose?: string | null; mode?: string | null; key_size?: number | null; confidence?: string | null; is_hardcoded_key: boolean; scanner_ids: string[]; }
export interface DepUseEdge { from: string; to: string; relation: "USES"; basis: string; locations: DepLocation[]; library_ids: string[]; }
export interface DepLinkEdge { from: string; to: string; relation: string; basis: string; asset_ids: string[]; }
export interface DepSystemEdge { id: string; from: string; to: string; relation: string; lifecycle_state: string; propagates: boolean; provenance?: string | null; source?: string | null; created_by?: string | null; evidence_ref?: string | null; confidence?: number | null; last_verified?: string | null; }
export interface DependencyMap {
  policy: { version: string; direction: string; meaning: string };
  generated_at: string;
  systems: DepSystem[]; components: DepComponent[]; libraries: DepLibrary[]; algorithms: DepAlgorithm[];
  edges: { contains: DepLinkEdge[]; uses: DepUseEdge[]; links: DepLinkEdge[]; provides: DepLinkEdge[]; depends_on: DepSystemEdge[] };
  coverage: { assets: number; attributed_assets: number; unattributed_assets: number; systems: number; systems_with_crypto: number; dependency_edges: number; propagating_edges: number };
}
export interface CascadeSystemRow { id: string; system_id: string; name: string; criticality?: string | null; risk?: DepRisk | null; algorithms: { id: string; label: string; risk: DepRisk }[]; weak_algorithms: string[]; hops?: number; direction?: "dependents" | "providers"; path?: string[]; chain?: string[]; path_names?: string[]; chain_names?: string[]; path_edges?: DepSystemEdge[]; reasons?: string[]; }
export interface CascadeResult {
  direction: "dependents" | "providers" | "both"; hops: number;
  seeds: CascadeSystemRow[]; impacted: CascadeSystemRow[];
  algorithm_seeds: { algorithm: string; id: string; risk: DepRisk; systems: string[]; locations: number }[];
  unknown_selections: string[];
  summary: { seed_systems: number; impacted_systems: number; max_depth: number; by_criticality: Record<string, number>; edges_considered: number; edges_not_propagating: number };
  not_propagating: { from: string; to: string; relation: string; lifecycle_state: string }[];
  semantics: string;
}
export const apiDependencyMap = (): Promise<ApiResult<DependencyMap>> => call("/api/v1/graph/dependency-map");
export const apiDependencyCascade = (body: { system_ids: string[]; algorithm_ids: string[]; direction: "dependents" | "providers" | "both"; hops: number }): Promise<ApiResult<CascadeResult>> =>
  call("/api/v1/graph/dependency-map/cascade", { method: "POST", body: JSON.stringify(body) });
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

/* Outward notification drain (§5 round 77): send NEW routed notifications to
 * the registered integrations their channel claims, over real signed HTTP.
 * Durable per-destination receipts provide at-least-once delivery; receivers
 * must deduplicate ambiguous retries using the stable Idempotency-Key. */
export interface DispatchAttempt {
  monitor_event_id: string; event_type: string; event_class: string;
  channels: string[];
  results: Array<{ integration_id: string; kind: string; endpoint: string;
    status: string; http_status: number | null; error: string | null; attempts: number; recorded?: boolean }>;
}
export interface DispatchResult {
  ok: boolean; window: number; examined: number; dispatched: number;
  registry_size: number; delivered: number; failed: number; skipped: number;
  email_routed: number; integrations: Record<string, number>;
  receipts?: Record<string, number>; enqueued?: number; destination_attempts?: number; lease_lost?: number;
  attempts: DispatchAttempt[]; note: string;
}
export const apiNotificationDispatch = (limit: number) =>
  _rsPost<DispatchResult>("/api/v1/notifications/dispatch", { limit });


/* PUT helper for persisted notification routing. */
export async function _rsPut<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const resp = await tenantFetch(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      // keep `error` the stable HTTP code pages compare against, and carry the
      // server's own reason alongside it (a 404 "no_estate_discovery" is a
      // different state from a refused read, and only the reason says which).
      const detail = errorDetail(data);
      return { source: "live", ok: false, error: "HTTP " + resp.status, data: null, ...(detail ? { detail } : {}) };
    }
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

async function _rsGet<T>(path: string): Promise<ApiResult<T>> {
  try {
    const resp = await tenantFetch(path, {
      headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      signal: AbortSignal.timeout(20000),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const detail = errorDetail(data);
      return { source: "live", ok: false, error: "HTTP " + resp.status, data: null, ...(detail ? { detail } : {}) };
    }
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

/* Report templates + schedule creation. */
export const apiReportTemplates = () => _rsGet<any>("/api/v1/report-templates");
export const apiReportScheduleCreate = (body: { name: string; template_id: string; frequency: string; scan_target?: string; requirements?: string[]; recipients?: string[] }) =>
  _rsPost<any>("/api/v1/report-schedules", body);

/* §4.4 (round 69): the report leg of scan-run → BOM → report. Pin THIS
 * scan's report on demand — content-addressed over the exact payload (signed
 * PDF + scan→BOM chain citation included), identical pins collapsing, served
 * verbatim with an integrity self-check by GET /report-snapshots/{id}. */
export interface ReportPinResult {
  id: string;
  scan_id: string;
  template_id: string;
  report_hash: string;
  payload_hash: string | null;
  generated_at: string | null;
  created: boolean;
  note: string;
}
export const apiReportSnapshotPin = (scanId: string, templateId: string, requirements?: string[]): Promise<ApiResult<ReportPinResult>> =>
  _rsPost<ReportPinResult>(`/api/v1/scans/${encodeURIComponent(scanId)}/report-snapshot`,
    { template_id: templateId, ...(requirements?.length ? { requirements } : {}) });

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

/* §5 (round 74): the persisted certificate ESTATE — `certificates` rows
 * deduped by SHA-256 fingerprint (owner, usages, revocation state,
 * renewal workflow), distinct from the live TLS-scan view which is one
 * ephemeral observation run. Owner absent stays absent ("unknown owner"
 * is a fact, not an inference); usages are the recorded locations where
 * the certificate was observed; the revocation check records that it
 * RAN and what the OCSP/CRL probes determined — never a guess. */
export interface CertificateEstateRow {
  id: string;
  fingerprint_sha256: string;
  subject: string | null; issuer: string | null; serial_number: string | null;
  not_before: string | null; not_after: string | null;
  public_key_algorithm: string | null; public_key_size: number | null;
  expiry_status: string | null; days_until_expiry: number | null;
  is_self_signed: boolean | null;
  owner: string | null; technical_contact: string | null;
  revocation_status: string | null; revocation_method: string | null;
  revocation_checked_at: string | null;
  renewal_status: string | null; renewal_ticket: string | null;
  san: string[] | null; usages: string[] | null;
}
export interface CertificateEstateList {
  certificates: CertificateEstateRow[]; total_count: number;
  page?: number; page_size?: number;
}
export const apiCertificateEstate = (q?: string): Promise<ApiResult<CertificateEstateList>> =>
  _rsGet<CertificateEstateList>(`/api/v1/certificates?page_size=200${q ? `&q=${encodeURIComponent(q)}` : ""}`);
export interface CertificateUsageRow {
  id: string; fingerprint_sha256: string;
  usage_type: string; location: string; last_seen: string | null;
}
export const apiCertificateUsages = (certId: string): Promise<ApiResult<{
  usages: CertificateUsageRow[]; certificate: CertificateEstateRow;
}>> =>
  _rsGet<{ usages: CertificateUsageRow[]; certificate: CertificateEstateRow }>(
    `/api/v1/certificates/${encodeURIComponent(certId)}/usages`);
export interface RevocationProbe {
  status: string | null; method: string | null; urls: string[] | null;
  checked_at?: string | null; [key: string]: unknown;
}
export const apiCertificateRevocationCheck = (certId: string): Promise<ApiResult<{
  ocsp: RevocationProbe; crl: RevocationProbe;
}>> =>
  _rsPost<{ ocsp: RevocationProbe; crl: RevocationProbe }>(
    `/api/v1/certificates/${encodeURIComponent(certId)}/revocation`, {});
export const apiCertificateOwnership = (fingerprint: string, body: {
  owner?: string; technical_contact?: string; reason: string;
}): Promise<ApiResult<{
  fingerprint_sha256: string; owner: string | null;
  technical_contact: string | null; reason: string;
}>> =>
  _rsPost(`/api/v1/certificates/${encodeURIComponent(fingerprint)}/ownership`, body);

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
  return tenantFetch(`/api/v1/technology-bom/export?${q.toString()}`, {
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
  /* CBOM-layer fields (`cbom.component_registry.crypto_layer_component`).
     Present on crypto components only; absent elsewhere — never defaulted. */
  algorithm?: string;
  key_type?: string;
  key_size?: number | string | null;
  purpose?: string;
  mode?: string;
  library?: string;
  asset?: string;
  application?: string;
  location?: string;
  pqc_status?: string;
  quantum_status?: string;
  confidence?: string;
  first_seen?: string | null;
  last_seen?: string | null;
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
  /** the edges themselves, canonical `[source, target, type]` (type may be "") */
  dependencies?: Array<string[]>;
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
  return tenantFetch(`/api/v1/technology-bom/export?${q.toString()}`, {
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
    return tenantFetch(`/api/v1/technology-bom/evidence-package?${q.toString()}`, { credentials: "include", ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}) });
  }
  return call(`/api/v1/technology-bom/evidence-package?${q.toString()}`);
};
export const apiTechBomVendor = (): Promise<ApiResult<TechBomVendorInventory>> =>
  call("/api/v1/technology-bom/vendor");

// ── Vendor due diligence ───────────────────────────────────────────────────
export interface VendorProfileCompleteness {
  score: number;
  status: "COMPLETE" | "INCOMPLETE";
  required_fields: number;
  present_fields: number;
  missing: string[];
  next_actions: string[];
  sections?: Record<string, {
    score: number;
    status: "COMPLETE" | "INCOMPLETE";
    required_fields: number;
    present_fields: number;
    missing: string[];
    next_actions: string[];
  }>;
}
export interface VendorRecord {
  id: string;
  name: string;
  criticality?: string | null;
  vendor_type?: string | null;
  integration_type?: string | null;
  data_classifications?: string[] | null;
  primary_contact?: string | null;
  security_contact?: string | null;
  system_ids?: string[];
  vendor_profile?: { status: string; revision: number | null; completeness: VendorProfileCompleteness };
  profile?: { status: string; revision: number | null; completeness: VendorProfileCompleteness | null };
  [key: string]: unknown;
}
export interface VendorProfileResponse {
  vendor_id: string;
  revision: number | null;
  persisted: boolean;
  status: string;
  profile: Record<string, unknown>;
  completeness: VendorProfileCompleteness;
  audit: { source: string; content_sha256?: string | null; captured_at?: string | null; created_by?: string | null; reviewed_by?: string | null; review_notes?: string | null };
}
export interface VendorProfileWriteResponse {
  vendor_id: string;
  revision: number;
  status: string;
  profile: Record<string, unknown>;
  completeness: VendorProfileCompleteness;
  audit?: { source?: string; content_sha256?: string; created_by?: string; captured_at?: string | null; reviewed_by?: string | null };
}
export const apiVendors = (q?: string): Promise<ApiResult<{ vendors: VendorRecord[]; total_count?: number; page?: number; page_size?: number }>> =>
  call(`/api/v1/vendors?page_size=200${q ? `&q=${encodeURIComponent(q)}` : ""}`);
export const apiVendorCreate = (body: { name: string; criticality?: string; vendor_type?: string; integration_type?: string; profile?: Record<string, unknown> }): Promise<ApiResult<VendorRecord>> =>
  call("/api/v1/vendors", { method: "POST", body: JSON.stringify(body) });
export const apiVendor = (vendorId: string): Promise<ApiResult<VendorRecord>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}`);
export const apiVendorProfile = (vendorId: string): Promise<ApiResult<VendorProfileResponse>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/profile`);
export interface VendorRiskResponse {
  vendor_id: string;
  vendor: string;
  due_diligence?: { risk_score: number; risk_rating: string; status: string; factors: Array<{ factor: string; points: number; reason: string }>; disclaimer: string };
  [key: string]: unknown;
}
export const apiVendorRisk = (vendorId: string): Promise<ApiResult<VendorRiskResponse>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/risk`);
export const apiVendorProfileHistory = (vendorId: string): Promise<ApiResult<{ vendor_id: string; revisions: VendorProfileResponse[] }>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/profile/history`);
export const apiVendorProfilePut = (vendorId: string, body: { profile: Record<string, unknown>; status?: string; source?: string; reviewed_by?: string; review_notes?: string }): Promise<ApiResult<VendorProfileWriteResponse>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/profile`, { method: "PUT", body: JSON.stringify(body) });
export const apiVendorProfileValidate = (vendorId: string, body: { profile: Record<string, unknown>; status?: string; reviewed_by?: string }): Promise<ApiResult<{ valid: boolean; status_allowed: boolean; completeness: VendorProfileCompleteness; approval_issues?: string[]; content_sha256: string; persisted: boolean }>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/profile/validate`, { method: "POST", body: JSON.stringify(body) });
export const apiVendorProfileEvidence = (vendorId: string, body: Record<string, unknown>): Promise<ApiResult<{ vendor_id: string; revision: number; status: string; evidence_id: string; completeness: VendorProfileCompleteness; content_sha256: string }>> =>
  call(`/api/v1/vendors/${encodeURIComponent(vendorId)}/profile/evidence`, { method: "POST", body: JSON.stringify(body) });

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
  threshold_years?: number; at_risk?: boolean | null; total?: number;
  by_exposure?: Record<string, number>; entries?: BankHndlEntry[]; source?: string;
  assessment_complete?: boolean; completeness_proven?: false;
  unassessed?: Array<{ bom_ref: string; algorithm: string | null; reason: string }>;
  horizon_basis?: string;
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
  deadline_basis?: string; regulatory_approval?: false;
}
export interface BankHsmRow {
  asset_id?: string; manufacturer?: string; model?: string; firmware?: string | { version?: string } | null;
  pqc_status?: string; pqc_evidence?: string; gap?: string;
  fips?: { module?: string; algorithm?: string; status?: string; declared_status?: string; validation_verified?: boolean; cert?: string; note?: string; source?: string };
}
export interface BankHsmFleet {
  total?: number; pqc_ready?: number; pqc_gap?: number;
  fips_validated_family?: number; fips_unknown?: number; ready_share?: number | null; hsms?: BankHsmRow[];
  pqc_declared_not_verified?: number; readiness_basis?: string;
}
export interface BankMainframeAsset {
  algorithm?: string; key_size?: number | null; purpose?: string; location?: string;
  source_language?: string; quantum?: { transition?: string; deadline?: number | null };
}
export interface BankOverview {
  source?: string; environment?: string; snapshot_id?: string; generated_at?: string;
  overview?: {
    hndl?: { at_risk?: boolean | null; total?: number; by_exposure?: Record<string, number> };
    roadmap?: { anchor?: string; total_in_scope?: number; weak_legacy_instances?: number;
                phases?: BankRoadmapPhase[] };
    hsm?: { total?: number; pqc_ready?: number; pqc_gap?: number };
    mainframe?: { total?: number; by_source?: Record<string, number> };
  };
}
export interface BankActionPlan {
  document?: string; framework?: string; institution?: string | null; generated_at?: string;
  jurisdiction?: string | null; jurisdiction_display?: string | null;
  milestones?: Array<{ label: string; date?: string | null; note?: string }>;
  references?: string[];
  evidence?: { snapshot_id?: string; fingerprint?: string; environment?: string; state_version?: number };
  assessment?: {
    total_crypto_instances?: number;
    admission?: { decision?: string; blocking?: number; warnings?: number };
    hndl?: { at_risk?: boolean | null; total?: number; by_exposure?: Record<string, number> };
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

/* ── Banking deep discovery, regulator exports, integrations (raw downloads) ── */
export const apiBankingMainframeAnalyze = (kind: string, content: string): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/banking/mainframe/analyze", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind, content, persist: false }),
  });
export const apiBankingHsmParse = (payload: { slots_text?: string; objects_text?: string; cex_text?: string; manufacturer?: string; model?: string }): Promise<ApiResult<Record<string, unknown>>> =>
  call("/api/v1/banking/hsm/parse", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
export const apiBankingFipsLookup = (module: string): Promise<ApiResult<Record<string, unknown>>> =>
  call(`/api/v1/banking/fips?module=${encodeURIComponent(module)}`);

/* Raw file downloads (HTML/CSV/JSON bodies returned as Response blobs). */
export const apiBankingDownload = (what: "action-plan" | "servicenow" | "qualys", fmt = ""): Promise<Response> => {
  const path = what === "action-plan"
    ? `/api/v1/banking/action-plan/export?format=${fmt || "html"}&framework=ecb`
    : what === "qualys"
      ? "/api/v1/banking/integrations/qualys"
      : "/api/v1/banking/integrations/servicenow";
  return tenantFetch(path, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
};

export async function downloadBankingArtifact(what: "action-plan" | "servicenow" | "qualys", fmt = ""): Promise<void> {
  const resp = await apiBankingDownload(what, fmt);
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const cd = resp.headers.get("content-disposition") || "";
  const match = cd.match(/filename="?([^";]+)"?/);
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = match?.[1] || `${what}-${fmt || "export"}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* ── International banking: jurisdictions, SWIFT CSP, key lifecycle ── */
export interface BankJurisdictionPack {
  code: string; display: string; region: string; regulators: string[];
  languages: string[]; milestones: Array<Record<string, unknown>>; artifacts: string[];
}
export interface BankKeyRow {
  label?: string; location?: string; algorithm?: string; key_size?: number | null;
  state?: string; klass?: string; expires?: string; rotation_status?: string; detail?: string;
  source?: string;
}
export interface BankKeyLifecycle {
  standard?: string; total?: number; by_state?: Record<string, number>;
  compromised?: number; expired?: number; rotation_overdue?: number;
  activation_dates_missing?: number; keys?: BankKeyRow[]; source?: string;
}
export interface BankCscfControl {
  theme: string; status: string; evidence: string; detail: string; endpoint: string;
}
export interface BankSwiftCsp {
  source?: string;
  cscf?: { programme: string; note: string; controls: BankCscfControl[];
           gaps: number; unknown: number; attestation_ready: boolean };
}

export const apiBankingJurisdictions = (): Promise<ApiResult<{ count: number; jurisdictions: BankJurisdictionPack[] }>> =>
  call("/api/v1/banking/jurisdictions");
export const apiBankingKeys = (source = ""): Promise<ApiResult<BankKeyLifecycle>> =>
  call(`/api/v1/banking/keys${source ? `?source=${encodeURIComponent(source)}` : ""}`);
export const apiBankingSwiftCsp = (): Promise<ApiResult<BankSwiftCsp>> =>
  call("/api/v1/banking/swift-csp");
export const apiBankingActionPlanJurisdiction = (jurisdiction: string, institution = ""): Promise<ApiResult<BankActionPlan>> =>
  call(`/api/v1/banking/action-plan?jurisdiction=${encodeURIComponent(jurisdiction)}${institution ? `&institution=${encodeURIComponent(institution)}` : ""}`);

/* Downloads with language + jurisdiction for regulator output. */
export async function downloadBankingArtifactIntl(
  what: "action-plan" | "servicenow" | "qualys",
  opts: { format?: string; lang?: string; jurisdiction?: string } = {},
): Promise<void> {
  const path = what === "action-plan"
    ? `/api/v1/banking/action-plan/export?format=${opts.format || "html"}`
      + (opts.jurisdiction ? `&jurisdiction=${encodeURIComponent(opts.jurisdiction)}` : "")
      + `&lang=${opts.lang || "en"}`
    : what === "qualys" ? "/api/v1/banking/integrations/qualys"
      : "/api/v1/banking/integrations/servicenow";
  const resp = await tenantFetch(path, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const cd = resp.headers.get("content-disposition") || "";
  const match = cd.match(/filename="?([^";]+)"?/);
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = match?.[1] || `${what}-export`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* ── Group governance: legal entities, cross-entity rollup, DORA register ── */
export interface GroupEntityRec {
  code: string; name: string; jurisdiction: string; lei?: string;
  regulator?: string; parent?: string; country?: string; notes?: string;
}
export interface GroupEntityRollup {
  entity: GroupEntityRec; systems: number; crypto_instances: number;
  weak_legacy_instances: number; quantum_vulnerable_public_key: number;
  top_families: Array<[string, number]>;
  worst_system?: { system?: string; system_id?: string; weak_instances?: number };
}
export interface GroupRollup {
  source?: string; generated_at?: string; registry_count?: number; unassigned_systems?: number;
  entities?: GroupEntityRollup[];
  group?: {
    totals?: Record<string, number>;
    by_jurisdiction?: Record<string, Record<string, number>>;
    exposure_ranking?: Array<{ entity: string; name?: string; jurisdiction?: string; weak: number; quantum: number }>;
    recurring_weak_families?: Array<{ family: string; entities: string[]; entity_count: number }>;
  };
}
export const apiGroupEntities = (): Promise<ApiResult<{ count: number; entities: GroupEntityRec[] }>> =>
  call("/api/v1/banking/group/entities");
export const apiGroupEntityAdd = (e: GroupEntityRec): Promise<ApiResult<{ ok: boolean; count: number }>> =>
  call("/api/v1/banking/group/entities", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(e),
  });
export const apiGroupEntityDelete = (code: string): Promise<ApiResult<{ ok: boolean }>> =>
  call(`/api/v1/banking/group/entities/${encodeURIComponent(code)}`, { method: "DELETE" });
export const apiGroupRollup = (): Promise<ApiResult<GroupRollup>> =>
  call("/api/v1/banking/group");
export async function downloadDoraRegister(format: "json" | "csv", entity = ""): Promise<void> {
  const resp = await tenantFetch(`/api/v1/banking/group/dora-register?format=${format}${entity ? `&entity=${encodeURIComponent(entity)}` : ""}`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const cd = resp.headers.get("content-disposition") || "";
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = cd.match(/filename="?([^";]+)"?/)?.[1] || `dora-register.${format}`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
export async function downloadGroupRoadmap(): Promise<void> {
  const resp = await tenantFetch("/api/v1/banking/group/roadmap?format=csv", {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const cd = resp.headers.get("content-disposition") || "";
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = cd.match(/filename="?([^";]+)"?/)?.[1] || "migration-roadmap.csv";
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export interface SupervisorPack {
  pack: { kind: string; version: string; generated_for: string };
  group_totals: Record<string, number>;
  by_jurisdiction: Record<string, Record<string, number>>;
  entities: Array<{ code: string; name: string; jurisdiction: string; lei: string }>;
  dora_register_summary: Record<string, number>;
  migration_roadmap_summary: {
    rows?: number;
    instances_by_bucket?: Record<string, number>;
    families_by_bucket?: Record<string, number>;
    entities_affected?: string[];
  };
  declared_limits: string[];
}
export interface SupervisorPackEnvelope {
  source: string;
  generated_at: string;
  registry_count: number;
  unassigned_systems: number;
  pack: SupervisorPack;
}
export interface GroupRoadmap {
  basis: string;
  generated_for: string;
  rows: Array<{
    entity_code: string; entity_name: string; jurisdiction: string;
    family: string; instances: number; bucket: string;
    deadline: string; action: string;
  }>;
  summary: {
    rows: number;
    instances_by_bucket: Record<string, number>;
    families_by_bucket: Record<string, number>;
    entities_affected: string[];
  };
  unassigned_systems?: number;
}
export interface TelecomVerdictRow {
  nf_id: string; nf_type: string; endpoint: string; carrier_code: string;
  environment: string; plane: string; status: string; severity: string;
  score: number; cert_not_after?: string | null;
  findings: Array<{ code: string; severity: string; message: string; ref?: string }>;
  pqc_kex: string[];
}
export interface TelecomRollup {
  totals: {
    targets: number; probed: number; reachable: number; unreachable: number;
    critical: number; expiring_certs: number; pqc_ready: number;
    worst_severity: string; avg_score: number;
  };
  by_carrier: Record<string, { name: string; country: string; plmn: string; legal_entity: string;
    targets: number; reachable: number; critical: number; worst_severity: string; avg_score: number }>;
  by_country: Record<string, { carriers: number; targets: number; critical: number }>;
  by_nf_type: Record<string, { targets: number; critical: number; avg_score: number }>;
  international: Record<string, { carriers: string[]; countries: string[]; targets: number;
    critical: number; worst_severity: string }>;
  roaming_edges: { sepp_targets: number; protected: number; unprotected: number };
  worst_targets: Array<{ nf_id: string; nf_type: string; severity: string; score: number;
    status: string; headline: string }>;
}
export interface TelecomPosture {
  has_data: boolean;
  message?: string;
  generated_at: string | null;
  scanner?: string;
  targets_registered?: number;
  rollup: TelecomRollup | null;
  rows?: TelecomVerdictRow[];
  events_summary?: Record<string, number>;
}
export interface TelecomRegistry {
  carriers: Record<string, { code: string; name: string; country: string; plmn: string; legal_entity: string }>;
  targets: Record<string, { nf_id: string; nf_type: string; endpoint: string;
    carrier_code: string; environment: string }>;
  counts: { carriers: number; targets: number };
  nf_catalog: Record<string, { name: string; transport: string; plane: string }>;
}
export interface TelecomEventRec {
  id: number; ts: string; type: string;
  payload: { kind: string; severity: string; message: string; nf_id?: string;
    nf_type?: string; carrier_code?: string; target?: string };
}
export const apiTelecomPosture = (): Promise<ApiResult<TelecomPosture>> =>
  call("/api/v1/telecom/posture");
export const apiTelecomRegistry = (): Promise<ApiResult<TelecomRegistry>> =>
  call("/api/v1/telecom/registry");
export const apiTelecomEvents = (): Promise<ApiResult<{ count: number; events: TelecomEventRec[] }>> =>
  call("/api/v1/telecom/events?limit=50");
export const apiTelecomCarrierAdd = (c: { code: string; name: string; country: string; plmn: string; legal_entity?: string }): Promise<ApiResult<{ ok: boolean }>> =>
  call("/api/v1/telecom/carriers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(c) });
export const apiTelecomTargetAdd = (t: { nf_id: string; nf_type: string; endpoint: string; carrier_code?: string; environment?: string }): Promise<ApiResult<{ ok: boolean }>> =>
  call("/api/v1/telecom/targets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(t) });
export interface TelecomRoamingRow {
  id: string; carrier_code: string; partner_plmn: string; partner_name: string;
  country: string; sepp_nf_id?: string | null; status: string; severity: string;
  sepp_status?: string | null; pqc_ready?: boolean; ref: string;
}
export const apiTelecomRoadmap = (): Promise<ApiResult<GroupRoadmap>> =>
  call("/api/v1/telecom/roadmap");
export const apiTelecomRoaming = (): Promise<ApiResult<{ generated_at: string | null;
  rows: TelecomRoamingRow[]; summary: { partners: number; protected: number; unprotected: number; unknown: number } }>> =>
  call("/api/v1/telecom/roaming");
export interface TelecomJourneyEra { from: string; until: string; pqc_ready: boolean; passes: number }
export interface TelecomJourney {
  generated_at: string | null;
  nf_tracked: number; pqc_ready_now: number; adoption_pct: number | null; transitions: number;
  per_nf: Record<string, { pqc_ready: boolean; since: string | null; eras: number; flips: number; passes: number; history: TelecomJourneyEra[] }>;
}
export const apiTelecomJourney = (): Promise<ApiResult<TelecomJourney>> =>
  call("/api/v1/telecom/journey");
export async function downloadTelecomPack(carrierCode: string, format: "json" | "csv" = "json"): Promise<void> {
  const resp = await tenantFetch(`/api/v1/telecom/pack?carrier=${encodeURIComponent(carrierCode)}&format=${format}`, {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  if (format === "json") {
    const blob = await readableJsonBlob(await resp.blob());
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `telecom-pack-${carrierCode}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    return;
  }
  const cd = resp.headers.get("content-disposition") || "";
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = cd.match(/filename="?([^";]+)"?/)?.[1] || `telecom-pack-${carrierCode}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export const apiTelecomPartnerAdd = (p: { carrier_code: string; partner_plmn: string; partner_name: string; country: string; sepp_nf_id?: string }): Promise<ApiResult<{ ok: boolean }>> =>
  call("/api/v1/telecom/roaming-partners", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p) });

export const apiTelecomScan = (only: string[] = [], timeout = 4.0): Promise<ApiResult<{ scanned: number; events: Array<{ kind: string; severity: string; message: string }>; rollup: TelecomRollup }>> =>
  call("/api/v1/telecom/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ only, timeout }) });

export const apiSupervisorPack = (): Promise<ApiResult<SupervisorPackEnvelope>> =>
  call("/api/v1/banking/group/supervisor-pack");
export const apiGroupRoadmap = (): Promise<ApiResult<GroupRoadmap>> =>
  call("/api/v1/banking/group/roadmap");
export async function downloadSupervisorPack(): Promise<void> {
  const resp = await tenantFetch("/api/v1/banking/group/supervisor-pack", {
    credentials: "include",
    ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
  });
  if (!resp.ok) throw new Error(`download failed: ${resp.status}`);
  const blob = await readableJsonBlob(await resp.blob());
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `supervisor-pack-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* ── SSO capabilities (login screen renders only what the platform has) ── */

export interface SsoStatus {
  oidc: { enabled: boolean; authorize_url: string | null };
  saml_enabled: boolean;
  ldap_enabled: boolean;
}

/* ── Cloud KMS key inventory (AWS KMS / Azure Key Vault → crypto assets) ── */

export interface CloudKeyAsset {
  id: string;
  algorithm: string;
  key_size: number | null;
  purpose: string | null;
  file_path: string;
  extra: Record<string, unknown> | null;
}
export interface CloudCollectResult {
  provider: string;
  seen: number;
  truncated: boolean;
  assets: CloudKeyAsset[];
  skipped: Array<{ ref: string; reason: string }>;
  dry_run: boolean;
  upserted: number;
  created: number;
}
export const apiCloudKeys = (): Promise<ApiResult<{ assets: CloudKeyAsset[]; total_count: number }>> =>
  call("/api/v1/inventory/cloud/assets");
export const apiCloudCollect = (
  provider: "aws-kms" | "azure-keyvault" | "gcp-kms" | "aws-acm",
  opts: { region?: string; vault_url?: string; project?: string; dry_run?: boolean } = {},
): Promise<ApiResult<CloudCollectResult>> =>
  call("/api/v1/inventory/cloud/collect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider, ...opts }),
  });

/* ── Automation → ITSM/SIEM delivery (ServiceNow incident, Splunk HEC) ──── */

export interface ConnectorStatus { configured: boolean; missing: string[]; }
export const apiConnectorsStatus = (): Promise<ApiResult<{
  connectors: Record<string, ConnectorStatus>;
  catalog: Record<string, { label: string; config: string[] }>;
}>> => call("/api/v1/automation/connectors");
export const apiAutomationConnectorPreview = (connector: string, runId: string): Promise<ApiResult<{
  connector: string; run_id: string; payload: Record<string, unknown>;
  delivered: boolean; note: string;
}>> => call("/api/v1/automation/connectors/preview", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ connector, run_id: runId }),
});
export const apiAutomationConnectorDispatch = (connector: string, runId: string): Promise<ApiResult<{
  connector: string; run_id: string; ok: boolean; delivered: boolean;
  status_code: number | null; detail: string;
}>> => call("/api/v1/automation/connectors/dispatch", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ connector, run_id: runId }),
});

/* ── PoC exit report (audit-export/exit-report) ────────────────────────── */

export interface ExitReportOpts {
  client?: string;
  window?: string;
  owner?: string;
  accepted_by?: string;
}

/** Generate the exit report. `format="json"` returns {report, hash} without
 *  downloading; `format="md"` downloads the markdown deliverable and returns
 *  its hash. Returns null with error in `error` on failure. */
export async function generateExitReport(
  format: "json" | "md",
  opts: ExitReportOpts = {},
): Promise<{ ok: boolean; hash?: string; error?: string }> {
  try {
    const params = new URLSearchParams({ format });
    for (const [k, v] of Object.entries(opts)) {
      if (v && v.trim()) params.set(k, v.trim());
    }
    const resp = await tenantFetch(`/api/v1/audit-export/exit-report?${params.toString()}`, {
      credentials: "include",
      ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
      signal: AbortSignal.timeout(20000),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    }
    if (format === "json") {
      const report = await resp.json();
      return { ok: true, hash: String(report.report_hash || "") };
    }
    const hash = resp.headers.get("X-Report-Hash") || "";
    const blob = await readableJsonBlob(await resp.blob());
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `poc-exit-report-${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { ok: true, hash };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/** Download the final engagement archive (audit pack + exit report + manifest)
 *  as one ZIP. Resolves the archive's file count on success. */
export async function downloadEngagementArchive(
  opts: ExitReportOpts = {},
): Promise<{ ok: boolean; files?: number; error?: string }> {
  try {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) {
      if (v && v.trim()) params.set(k, v.trim());
    }
    const qs = params.toString();
    const resp = await tenantFetch(`/api/v1/audit-export/engagement-archive${qs ? `?${qs}` : ""}`, {
      credentials: "include",
      ...(getToken() ? { headers: { Authorization: `Bearer ${getToken()}` } } : {}),
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { ok: false, error: String(body.detail || `HTTP ${resp.status}`) };
    }
    const files = Number(resp.headers.get("X-Archive-Files") || 0);
    const blob = await readableJsonBlob(await resp.blob());
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cryptoscan-engagement-${new Date().toISOString().slice(0, 10)}.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { ok: true, files };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// ---------------------------------------------------------------------------
// Multi-tenant SaaS control plane
// ---------------------------------------------------------------------------

export interface SaasUsageMeter {
  used: number;
  limit: number | null;
  remaining: number | null;
}
export interface SaasWhoami {
  username: string;
  tenant_id: string | null;
  tenant_name?: string;
  tenant_slug?: string;
  tenant_role: string | null;
  plan: string | null;
  tenant_status: string | null;
  is_platform_admin: boolean;
  usage?: Record<string, SaasUsageMeter>;
}
export interface SaasMember {
  username: string;
  tenant_role: string;
  added_at: string | null;
}
export interface SaasAdminTenant {
  id: string;
  name: string;
  slug: string;
  plan: string;
  status: string;
  created_at: string | null;
  members: number;
  targets: number;
  scans_this_month: number;
}

export async function apiSaasSignup(input: {
  org_name: string;
  username: string;
  password: string;
  email?: string;
}): Promise<{ ok: boolean; error?: string; tenant?: { id: string; name: string; slug: string; plan: string } }> {
  try {
    const resp = await tenantFetch("/api/v1/saas/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(8000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail ?? `HTTP ${resp.status}`) };
    return { ok: true, tenant: body.tenant };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

export const apiSaasWhoami = () => call<SaasWhoami>("/api/v1/saas/whoami");
export const apiSaasMemberships = () =>
  call<{ tenants: Array<{ id: string; name: string; slug: string; plan: string; status: string; tenant_role: string }> }>(
    "/api/v1/saas/memberships",
  );
export const apiSaasUsage = () =>
  call<{ plan: string; limits: Record<string, number | null>; meters: Record<string, SaasUsageMeter>; month_breakdown: Record<string, number> }>(
    "/api/v1/saas/usage",
  );
export const apiSaasMembers = () => call<{ members: SaasMember[] }>("/api/v1/saas/members");
export const apiSaasAddMember = (input: { username: string; tenant_role: string; password?: string }) =>
  call<{ username: string; tenant_role: string }>("/api/v1/saas/members", {
    method: "POST",
    body: JSON.stringify(input),
  });
export const apiSaasRemoveMember = (username: string) =>
  call<{ removed: string }>(`/api/v1/saas/members/${encodeURIComponent(username)}`, { method: "DELETE" });
export const apiSaasAdminTenants = () => call<{ tenants: SaasAdminTenant[] }>("/api/v1/saas/admin/tenants");
export const apiSaasSuspend = (id: string, reason: string) =>
  call<{ tenant_id: string; status: string }>(`/api/v1/saas/admin/tenants/${encodeURIComponent(id)}/suspend`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
export const apiSaasRestore = (id: string) =>
  call<{ tenant_id: string; status: string }>(`/api/v1/saas/admin/tenants/${encodeURIComponent(id)}/restore`, {
    method: "POST",
  });
export const apiSaasSetPlan = (id: string, plan: string) =>
  call<{ tenant_id: string; plan: string }>(`/api/v1/saas/admin/tenants/${encodeURIComponent(id)}/plan`, {
    method: "POST",
    body: JSON.stringify({ plan }),
  });

export interface SaasInvite {
  invite_id: string;
  username: string;
  tenant_role: string;
  invited_by: string | null;
  expires_at: string | null;
  accepted: boolean;
}

export const apiSaasInvites = () => call<{ invites: SaasInvite[] }>("/api/v1/saas/invites");
export async function apiSaasCreateInvite(input: {
  username: string;
  tenant_role: string;
  days?: number;
}): Promise<{ ok: boolean; error?: string; token?: string; username?: string; tenant_role?: string }> {
  try {
    const resp = await tenantFetch("/api/v1/saas/invites", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(activeTenantId() ? { "X-Tenant-ID": activeTenantId()! } : {}) },
      credentials: "include",
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(8000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail ?? `HTTP ${resp.status}`) };
    return { ok: true, token: body.token, username: body.username, tenant_role: body.tenant_role };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}
export const apiSaasRevokeInvite = (id: string) =>
  call<{ revoked: string }>(`/api/v1/saas/invites/${encodeURIComponent(id)}`, { method: "DELETE" });
export async function apiSaasAcceptInvite(input: {
  token: string;
  password?: string;
}): Promise<{ ok: boolean; error?: string; tenant_name?: string; tenant_role?: string }> {
  try {
    const resp = await tenantFetch("/api/v1/saas/invites/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(8000),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) return { ok: false, error: String(body.detail ?? `HTTP ${resp.status}`) };
    return { ok: true, tenant_name: body.tenant?.name, tenant_role: body.tenant_role };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/* ── Event stream + Live CBOM (r29) ─────────────────────────────────────── */

export interface StreamTopicStat {
  last_seq: number;
  in_memory: number;
  log_bytes: number;
  consumer_groups: Record<string, { cursor: number; lag: number }>;
}
export interface StreamStats {
  log_dir: string;
  topics: Record<string, StreamTopicStat>;
  chain_len?: number;
}
export interface AttackDetection {
  rule: string;
  severity: string;
  detail: string;
  detected_at: string;
  endpoint?: string;
  system?: string;
  evidence?: Record<string, unknown>;
}
export interface CbomVersion {
  system_id: string;
  version_no: number;
  generated_at: string;
  version_hash: string;
  prev_hash: string;
  asset_count: number;
  jws: string;
  freshness?: { seconds_since_update: number; stale_after_seconds: number; stale: boolean };
  doc?: { assets: Array<Record<string, unknown>> };
}

export const apiStreamStats = (): Promise<ApiResult<StreamStats>> =>
  call(`/api/v1/stream/stats`);

export const apiAttacks = (limit = 50): Promise<ApiResult<{ detections: AttackDetection[] }>> =>
  call(`/api/v1/attacks?limit=${limit}`);

export const apiAttackSummary = (): Promise<ApiResult<{ by_rule: Record<string, number>; by_severity: Record<string, number> }>> =>
  call(`/api/v1/attacks/summary`);

export const apiCbomLive = (system: string): Promise<ApiResult<CbomVersion>> =>
  call(`/api/v1/cbom/live/${encodeURIComponent(system)}`);

export const apiCbomVerify = (system: string): Promise<ApiResult<{ chain_valid: boolean; versions: number; broke_at: number | null; reason: string | null }>> =>
  call(`/api/v1/cbom/verify/${encodeURIComponent(system)}`);

export const apiCbomSystemVersions = (system: string, limit = 20): Promise<ApiResult<{ versions: CbomVersion[] }>> =>
  call(`/api/v1/cbom/versions/${encodeURIComponent(system)}?limit=${limit}`);

/* ── Remediation prioritization (r30) ───────────────────────────────────── */

export interface RankedItem {
  rank: number;
  ref_id: string | null;
  source: string;
  kind: string;
  severity_in: string;
  priority: number;
  effort: number;
  explanation: string;
  replacement: { replacement: string; reason?: string } | null;
  plan: { profile: string; phases: Array<{ phase: string; actions?: string[] }> } | null;
  correlated: string[];
}
export interface PriorityResponse {
  ranked: RankedItem[];
  counts_by_severity: Record<string, number>;
  coverage: {
    open_drift_events: number;
    runtime_findings: number;
    systems_with_agility: number;
    systems_with_revenue_mapping: number;
    graph_edges: number;
    processes_linked: number;
    profile: string;
  };
}

export const apiPriority = (limit = 100): Promise<ApiResult<PriorityResponse>> =>
  call(`/api/v1/priority?limit=${limit}`);

/* Remediation task lifecycle (§5, round 63): real tasks with owner,
 * status, rescan and verification — COMPLETED is a declared state;
 * VERIFIED means machine-verified against rescan evidence. */
export interface RemediationVerificationSummary {
  id: string; result: string; reason: string | null;
  rescan_id: string | null; verified_by: string; verified_at: string | null;
}
export interface RemediationTask {
  id: string; evidence_id: string; scan_id: string; rule_id: string;
  category?: string | null; priority?: string | null; replace_with?: string | null;
  original_finding: Record<string, any>;
  target_location?: string | null;
  status: string; owner?: string | null; notes?: string | null;
  created_by: string; source: string; source_ref?: string | null;
  completed_at?: string | null; completed_by?: string | null;
  latest_verification?: RemediationVerificationSummary;
}
export interface RemediationTaskList {
  tasks: RemediationTask[]; total: number; page: number; page_size: number;
}
export const apiRemediationTasks = (params: {
  status?: string; owner?: string; evidence_id?: string; asset_id?: string;
  page?: number; page_size?: number;
} = {}): Promise<ApiResult<RemediationTaskList>> => {
  const q = new URLSearchParams();
  if (params.status) q.set("status", params.status);
  if (params.owner) q.set("owner", params.owner);
  if (params.evidence_id) q.set("evidence_id", params.evidence_id);
  if (params.asset_id) q.set("asset_id", params.asset_id);
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  const qs = q.toString();
  return call(`/api/v1/remediation/tasks${qs ? `?${qs}` : ""}`);
};
export const apiRemediationAccept = (taskId: string): Promise<ApiResult<RemediationTask>> =>
  call(`/api/v1/remediation/tasks/${encodeURIComponent(taskId)}/accept`, { method: "POST" });
export const apiRemediationComplete = (
  taskId: string, rescanId: string, notes?: string,
): Promise<ApiResult<RemediationTask>> =>
  call(`/api/v1/remediation/tasks/${encodeURIComponent(taskId)}/complete`, {
    method: "POST",
    body: JSON.stringify({ rescan_id: rescanId || null, notes: notes || null }),
  });
export const apiRemediationVerify = (
  taskId: string, rescanId?: string,
): Promise<ApiResult<RemediationTask>> =>
  call(`/api/v1/remediation/tasks/${encodeURIComponent(taskId)}/verify`, {
    method: "POST",
    body: JSON.stringify({ rescan_id: rescanId || null }),
  });

/* Priority item → owned remediation task(s) (r42, §4.7). Drift-sourced items
   open tasks against their FAIL/WARN evidence; runtime-sourced items get an
   honest 422 — tasks require an evidence_id from the chain. Bespoke fetch
   (not call()) so the backend's refusal detail reaches the user verbatim. */
export interface PriorityTaskCreateResult {
  ref_id: string;
  source: "drift" | "runtime";
  owner: string | null;
  created: number;
  task_ids: string[];
  message: string;
}
export type PriorityTaskActionResult =
  | { ok: true; data: PriorityTaskCreateResult }
  | { ok: false; status: number; detail: string };
export async function apiPriorityCreateTasks(
  refId: string,
  owner?: string,
): Promise<PriorityTaskActionResult> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const tenant = activeTenantId();
    if (tenant) headers["X-Tenant-ID"] = tenant;
    const resp = await tenantFetch(`/api/v1/priority/${encodeURIComponent(refId)}/tasks`, {
      method: "POST",
      signal: AbortSignal.timeout(8000),
      headers,
      credentials: "include",
      body: JSON.stringify(owner ? { owner } : {}),
    });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return { ok: false, status: resp.status, detail: String(body.detail || `HTTP ${resp.status}`) };
    }
    return { ok: true, data: body as PriorityTaskCreateResult };
  } catch (e) {
    return { ok: false, status: 0, detail: String(e) };
  }
}


/* ── Per-system unified risk, explained (r42, §4.6) ────────────────────── */

export interface RiskFactorDetail {
  level: number;
  points: number;
  weight: number;
}
export interface SystemRiskSignals {
  evidence_rows: number;
  fail_rows: number;
  fail_ratio: number;
  quantum_weighted_ratio: number;
  unknown_algorithms: number;
  open_drift_events: number;
  worst_open_drift_severity: string | null;
  worst_cve_severity: string | null;
  outgoing_dependencies: number;
  environment: string | null;
  criticality: string | null;
  cloud_provider: string | null;
}
export interface SystemRiskAssessment {
  score: number;
  level: string;
  system_id: string;
  system_name: string;
  owner: string | null;
  technical_owner: string | null;
  security_owner: string | null;
  scan_id: string | null;
  evidence_count: number;
  levels: Record<string, number>;
  signals: SystemRiskSignals;
  open_drift_events: number;
  vulnerability_count: number;
  factors: Record<string, RiskFactorDetail>;
  weights: Record<string, number>;
  weights_source: string;
  calculation_version: string;
}
export interface SystemsRiskResponse {
  systems: SystemRiskAssessment[];
  count: number;
  total_systems: number;
  estate: { score: number; level: string; by_level: Record<string, number> };
  weights: Record<string, number>;
  weights_source: string;
  calculation_version: string;
  factors: string[];
}
export const apiRiskSystems = (limit = 200): Promise<ApiResult<SystemsRiskResponse>> =>
  call(`/api/v1/risk/systems?limit=${limit}`);


/* ── 24/7 Continuous Monitoring & System Health Endpoints ── */

export interface SystemServiceHealth {
  name: string;
  /** "Not measured" = no independent probe exists for this service;
   *  API liveness is not evidence that the service behind it is healthy. */
  status: "Operational" | "Degraded" | "Offline" | "Not measured";
  /** null = no independent latency measurement for this service. */
  latencyMs: number | null;
  lastHeartbeat: string;
  details?: string;
}

export interface ScannerEngineHealth {
  id: string;
  name: string;
  /** "On demand" = the collector runs when triggered; no continuous probe. */
  status: "Healthy" | "Degraded" | "Offline" | "Paused" | "On demand";
  lastObservation: string;
  eventsProcessed: number;
  /**
   * No per-engine discovery counter is exposed by the platform, so this is
   * `null` for every engine. It used to carry the estate's asset total on one
   * arbitrary engine, which read as "this scanner discovered N assets".
   */
  assetsDiscovered: number | null;
  /** The estate's measured asset total — one number, not an engine's result. */
  estateAssets: number | null;
  errors: number;
  avgLatencyMs: number;
}

export const apiSystemHealthStatus = async (): Promise<SystemServiceHealth[]> => {
  // Measured signals only (product vision §5, P0 trust bug): API liveness
  // with its real round-trip (/healthz), per-dependency probes
  // (/healthz/dependencies: database/redis/neo4j each independently ok,
  // down or skipped) and the ops SLO window when authenticated. Services
  // without an independent probe are reported "Not measured" — an
  // HTTP 200 from the API process is not evidence that the policy engine,
  // drift engine, WORM store, twin or worker pool is healthy, and a
  // missing SLO window is not 100% availability.
  const t0 = performance.now();
  let apiHealthy = false;
  let apiLatency = 0;
  try {
    const res = await tenantFetch("/healthz", { signal: AbortSignal.timeout(3000) });
    apiLatency = Math.round(performance.now() - t0);
    apiHealthy = res.ok;
  } catch {
    apiHealthy = false;
  }

  let sloData: any = null;
  try {
    const token = getToken();
    if (token) {
      const sloRes = await tenantFetch("/api/v1/ops/slo", {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(3000),
      });
      if (sloRes.ok) sloData = await sloRes.json();
    }
  } catch { /* SLO window unavailable -> availability stays not measured */ }

  let depChecks: Array<{ name: string; status: string; detail?: string }> = [];
  try {
    const depRes = await tenantFetch("/healthz/dependencies", { signal: AbortSignal.timeout(5000) });
    if (depRes.ok) {
      const body: unknown = await depRes.json();
      if (body && typeof body === "object" && Array.isArray((body as any).checks)) {
        depChecks = (body as any).checks;
      }
    }
  } catch { /* dependency probe unavailable -> rows stay Not measured */ }

  const p99 = sloData?.latency?.p99_ms ? Math.round(sloData.latency.p99_ms) : null;
  const avail = sloData?.availability?.achieved
    ? `${(sloData.availability.achieved * 100).toFixed(1)}%`
    : "not measured";

  const byName = new Map(depChecks.map((c) => [c.name, c]));
  const dependencyRow = (name: string, label: string): SystemServiceHealth => {
    const check = byName.get(name);
    if (!check) {
      return { name: label, status: "Not measured", latencyMs: null,
               lastHeartbeat: "No probe result",
               details: "Dependency probe did not report this component" };
    }
    if (check.status === "ok") {
      return { name: label, status: "Operational", latencyMs: null,
               lastHeartbeat: "Probed just now", details: check.detail };
    }
    if (check.status === "skipped") {
      return { name: label, status: "Not measured", latencyMs: null,
               lastHeartbeat: "Not configured",
               details: "Optional dependency is not configured in this deployment" };
    }
    return { name: label, status: "Degraded", latencyMs: null,
             lastHeartbeat: "Probe failed", details: check.detail };
  };

  const notMeasured = (label: string, why: string): SystemServiceHealth => ({
    name: label, status: "Not measured", latencyMs: null,
    lastHeartbeat: "No independent probe",
    details: why,
  });

  /* §5 (round 78): the queue / worker pool now HAS an independent probe —
   * GET /health/worker-fleet measures the durable records themselves
   * (job statuses, stuck running, event-queue depth, stale leases, the
   * worker monitor lease). Drain evidence is completions or a live lease,
   * never API liveness; no synthetic latency is claimed. */
  let fleet: any = null;
  try {
    const token = getToken();
    // A session may exist with no in-memory token: the httpOnly cookie carries
    // it after a reload. Only a browser with no session at all skips the probe.
    if (hasSession()) {
      const fleetRes = await tenantFetch("/api/v1/health/worker-fleet", {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(5000),
      });
      if (fleetRes.ok) fleet = await fleetRes.json();
    }
  } catch { /* fleet probe unavailable -> row stays Not measured */ }

  const fleetRow = (): SystemServiceHealth => {
    if (!fleet) {
      return notMeasured("Queue & Worker Pool",
                         "Worker-fleet probe unavailable (not authenticated or unreachable)");
    }
    const hb = fleet.worker_heartbeat ?? {};
    const jobParts = Object.entries(fleet.jobs?.by_status ?? {})
      .map(([k, v]: [string, any]) => `${v} ${String(k).toLowerCase()}`).join(" / ");
    const parts = [
      jobParts ? `jobs: ${jobParts}` : "no jobs observed",
      `events waiting: ${fleet.event_queue?.by_status?.queued ?? 0}`,
      hb.measured
        ? `heartbeat ${hb.heartbeat_age_s}s ago (${hb.lease_live ? "live" : "expired"})`
        : "no worker heartbeat source",
      fleet.detail,
    ];
    return {
      name: "Queue & Worker Pool",
      status: fleet.status === "Operational" ? "Operational"
        : fleet.status === "Degraded" ? "Degraded" : "Not measured",
      latencyMs: null, /* no synthetic latency — the probe reports state, not RTT */
      lastHeartbeat: hb.measured ? `${hb.heartbeat_age_s}s ago` : "No heartbeat source",
      details: parts.filter(Boolean).join(" · "),
    };
  };

  return [
    { name: "Core API", status: apiHealthy ? "Operational" : "Offline",
      latencyMs: apiHealthy ? apiLatency : null,
      lastHeartbeat: apiHealthy ? "Live probe" : "Unavailable",
      details: `Availability: ${avail}${p99 !== null ? ` · p99 ${p99} ms` : ""}` },
    dependencyRow("database", "PostgreSQL (evidence store)"),
    dependencyRow("redis", "Redis (events / queue transport)"),
    dependencyRow("realtime_events", "Realtime event journal"),
    dependencyRow("neo4j", "Neo4j (graph)"),
    notMeasured("Deterministic Policy Engine",
                "In-process engine: no independent heartbeat or metrics source exists yet"),
    notMeasured("Drift Engine",
                "Runs inside scan jobs: health = recent job outcomes, not probed here"),
    notMeasured("WORM Evidence Store",
                "Evidence retention is enforced per write; no independent store probe exists yet"),
    notMeasured("Digital Twin Engine",
                "Snapshot engine: no independent heartbeat or metrics source exists yet"),
    fleetRow(),
  ];
};

/* §4.8 (round 79): connector health measured from the outbound delivery
 * audit (cp_delivery_logs) — registration/enabled is configuration, not
 * health; a connector with no delivery history reports Not measured. */
export interface ConnectorHealth {
  integration_id: string; name: string; kind: string; provider: string;
  enabled: boolean; endpoint_configured: boolean;
  status: "Operational" | "Degraded" | "Outbox (air-gap)" | "Disabled" | "Not measured";
  detail: string;
  last_delivery: { status: string; http_status: number | null; attempts: number;
    age_s: number | null; event_type: string } | null;
  recent_counts: Record<string, number>;
}
export interface ConnectorsHealth {
  status: string; detail: string; connectors: ConnectorHealth[];
  count: number; note: string;
}
export const apiConnectorsHealth = async (): Promise<ConnectorsHealth | null> => {
  try {
    const token = getToken();
    if (!token) return null;
    const res = await tenantFetch("/api/v1/health/connectors", {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const body = await res.json();
    return Array.isArray(body?.connectors) ? body as ConnectorsHealth : null;
  } catch {
    return null; /* probe unavailable -> callers report Not measured */
  }
};

export const apiScannerEnginesHealth = async (): Promise<ScannerEngineHealth[]> => {
  // Scanners in this platform run ON DEMAND (queued jobs and admitted
  // direct routes), not as continuously-probed daemons — API liveness is
  // not evidence that any scanner is "Active" or error-free (product
  // vision §5, P0 trust bug). What is honestly known: whether the API
  // accepting the trigger is reachable, and the estate's measured asset
  // total. No fabricated event counts, latencies or zero-error claims.
  let apiReachable = false;
  try {
    const res = await tenantFetch("/healthz", { signal: AbortSignal.timeout(3000) });
    apiReachable = res.ok;
  } catch {
    apiReachable = false;
  }

  // The estate total is a single measurement, not any one engine's output. It is
  // `null` when it could not be read — never 0, which would read as "the estate
  // holds no assets".
  let totalAssets: number | null = null;
  try {
    const token = getToken();
    if (token) {
      const aRes = await tenantFetch("/api/v1/assets?page_size=1", { headers: { Authorization: `Bearer ${token}` } });
      if (aRes.ok) {
        const body = await aRes.json();
        const count = Number(body.total_count);
        totalAssets = Number.isFinite(count) ? count : null;
      }
    }
  } catch { /* estate count unavailable, stays null */ }

  const status: ScannerEngineHealth["status"] = apiReachable ? "On demand" : "Offline";
  const lastObservation = apiReachable
    ? "No continuous probe — runs when a scan is triggered"
    : "API unreachable";
  const engines: Array<[string, string]> = [
    ["net", "Network Scanner (JA3/JA3S/JARM)"],
    ["cloud", "Cloud Scanner (AWS/Azure/GCP KMS)"],
    ["app", "Application Scanner (Code AST & Config)"],
    ["cert", "Certificate Scanner (CT Log & TLS)"],
    ["hsm", "Hardware Scanner (FIPS 140-3 HSM)"],
  ];
  return engines.map(([id, name]) => ({
    id, name, status, lastObservation,
    eventsProcessed: 0,
    assetsDiscovered: null,
    estateAssets: totalAssets,
    errors: 0, avgLatencyMs: 0,
  }));
};

/* ── Authoritative CBOM API calls ── */
export const apiCbomIngest = (bom: Record<string, unknown>, systemName: string): Promise<ApiResult<any>> =>
  call("/api/v1/cbom/ingest", { method: "POST", body: JSON.stringify({ bom, system_name: systemName }) });

export const apiCbomCatalog = (page = 1, pageSize = 50): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom?page=${page}&page_size=${pageSize}`);

export const apiCbomCoverage = (): Promise<ApiResult<any>> =>
  call("/api/v1/cbom/coverage");

export const apiCbomSearch = (query: string): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom/search?q=${encodeURIComponent(query)}`);

/* Unified cross-BOM query (round 37). Matches are canonical identity
 * dossiers; `summary` is the estate-wide arithmetic the CBOM page's
 * headline cards show — counts every identity, never the filtered result.
 * Mirrors `services/cbom/cbom/bom_query.py`. */
export interface CbomQuerySummaryRow {
  kind?: string;
  bom?: string;
  identities: number;
}
export interface CbomQuerySummary {
  identities: number;
  linked: number;
  single_source: number;
  conflict_count: number;
  variation_count: number;
  by_kind: CbomQuerySummaryRow[];
  by_bom: CbomQuerySummaryRow[];
  scope?: string;
  asset_identity_confirmed?: boolean;
}
export interface CbomQueryMatch {
  identity: string;
  kind: string;
  label: string;
  boms: string[];
  bom_count: number;
  linked: boolean;
  relationship?: string;
  asset_identity_confirmed?: boolean;
  present_in: { bom: string; ref: string; values: Record<string, unknown> }[];
  conflicts: unknown[];
  variations: unknown[];
}
export interface CbomQueryResponse {
  model?: string;
  boms?: string[];
  identities_total?: number;
  identities_matching?: number;
  matches?: CbomQueryMatch[];
  summary?: CbomQuerySummary;
  conflict_count?: number;
  variation_count?: number;
  note?: string;
  error?: string;
}
export const apiCbomQuery = (limit = 2000): Promise<ApiResult<CbomQueryResponse>> =>
  call(`/api/v1/cbom/query?limit=${limit}`);

/* ── Governance, Drift & Compliance APIs ── */
export const apiComplianceEvidence = (): Promise<ApiResult<any>> =>
  call("/api/v1/compliance/evidence");

export const apiComplianceRetention = (): Promise<ApiResult<any>> =>
  call("/api/v1/compliance/retention");

/* Requirements register (§4.3): requirement → evidence / gaps / expiry /
 * reviewer sign-off, evaluated against the latest PINNED evidence pack. */
export const apiComplianceRequirements = (): Promise<ApiResult<any>> =>
  call("/api/v1/compliance/requirements");

export const apiCompliancePinEvidence = (): Promise<ApiResult<any>> =>
  call("/api/v1/compliance/evidence/packs", { method: "POST" });

export const apiComplianceSignOff = (
  scope: string,
  signedBy: string,
  packSha256: string,
): Promise<ApiResult<any>> =>
  call("/api/v1/compliance/attestations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope, signed_by: signedBy, pack_sha256: packSha256 }),
  });

export const apiDriftEvents = (page = 1, pageSize = 50): Promise<ApiResult<any>> =>
  call(`/api/v1/drift?page=${page}&page_size=${pageSize}`);

/* ── Enterprise MFA / Hardware Token API ── */
export const apiMfaEnroll = (): Promise<ApiResult<{ secret: string; otpauth_uri: string; digits: number; period: number; issuer: string; next: string }>> =>
  call("/api/v1/auth/mfa/enroll", { method: "POST" });

export const apiMfaEnable = (code: string): Promise<ApiResult<{ enabled: boolean; recovery_codes: string[]; warning: string }>> =>
  call("/api/v1/auth/mfa/enable", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });

export const apiMfaDisable = (password: string, code?: string, recoveryCode?: string): Promise<ApiResult<{ disabled: boolean }>> =>
  call("/api/v1/auth/mfa/disable", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, ...(code ? { code } : {}), ...(recoveryCode ? { recovery_code: recoveryCode } : {}) }),
  });

export const apiAuthMeDetails = (): Promise<ApiResult<{ username: string; roles: string[]; permissions: string[]; mfa_enabled: boolean; display_name: string; email: string | null; active_sessions: number }>> =>
  call("/api/v1/auth/me");

// ---------------------------------------------------------------- code-level dependency & cascade (per scan)
export type CascadeProvider = { file: string; algorithms: string[]; findings: number; direct_dependents: number; transitive_dependents: number; wave: number; rank: number; code_origin?: string | null };
export type CascadeReport = {
  scan_id: string;
  summary: Record<string, any> | null;
  files_in_graph?: number;
  edges?: number;
  providers: CascadeProvider[];
  libraries: { library: string; versions: string[]; files_using: number; findings: number; declared_but_unused: boolean; used_but_undeclared: boolean; manifests: string[] }[];
  shared_keys: { kind: string; identifier: string; files: string[]; algorithms: string[] }[];
  weak_parameters: { file: string; line: number; algorithm: string; key_size: number; minimum: number }[];
  migration_waves: { wave: number; why: string; providers: string[]; dependents_affected: number }[];
  systems: { system: string; criticality?: string | null; providers: number; algorithms: string[]; weak_parameters: number; dependent_systems: string[]; depends_on_systems: string[]; earliest_wave?: number | null }[] | null;
  truncated?: Record<string, number>;
};
export type ScanSummaryRow = { scan_id: string; status: string; target_location: string; scan_end?: string | null; statistics?: Record<string, any> | null };
export interface ScanListPage { scans: ScanSummaryRow[]; total_count: number; page: number; page_size: number }
export const apiScansPage = (page = 1, pageSize = 20): Promise<ApiResult<ScanListPage>> =>
  call(`/api/v1/scans?page=${page}&page_size=${pageSize}`);
export const apiScansRecent = (pageSize = 20): Promise<ApiResult<ScanListPage>> => apiScansPage(1, pageSize);

/* Pinned CBOM snapshots (§4.4, round 45): one content-addressed rendering
 * per pin, served verbatim with an integrity self-check. The live CBOM
 * routes regenerate from current evidence; a snapshot does not. */
export const apiCbomScanSnapshots = (scanId: string): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom/scan/${encodeURIComponent(scanId)}/snapshots`);

export const apiCbomPinSnapshot = (scanId: string, signed: boolean): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom/scan/${encodeURIComponent(scanId)}/snapshot?signed=${signed}`, { method: "POST" });

export const apiCbomSnapshot = (snapshotId: string): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom/snapshots/${encodeURIComponent(snapshotId)}`);

/* §4.4/§5 (round 62): diff two pinned snapshots. key_by=asset_key (default)
 * joins components by the identity spine — stable across re-scans — so the
 * diff shows ESTATE drift, not per-scan evidence churn; key_by=bom_ref is
 * the exact per-scan evidence identity (same-scan mutations visible). */
export const apiCbomSnapshotDiff = (
  snapshotId: string,
  againstId: string,
  keyBy: "asset_key" | "bom_ref" = "asset_key",
): Promise<ApiResult<any>> =>
  call(`/api/v1/cbom/snapshots/${encodeURIComponent(snapshotId)}/diff`
       + `?against=${encodeURIComponent(againstId)}&key_by=${keyBy}`);
/** Verifies persisted content, ordering, and manifest for one scan; not a per-finding verdict. */
export interface ScanVerification {
  scan_id: string; records: number; result: "PASS" | "FAIL" | "EMPTY" | "UNVERIFIABLE";
  chain_intact: boolean; content_intact: boolean; hash_format_valid: boolean;
  manifest_intact: boolean; manifest_hash: string | null; errors: string[];
  verified_by?: string; content_hasher?: string;
}
export const apiVerifyStoredScan = (scanId: string): Promise<ApiResult<ScanVerification>> =>
  call(`/api/v1/scans/${encodeURIComponent(scanId)}/verify`);
export const apiScanCascade = (scanId: string, system?: string): Promise<ApiResult<CascadeReport>> =>
  call(`/api/v1/scans/${encodeURIComponent(scanId)}/cascade${system ? `?system=${encodeURIComponent(system)}` : ""}`);
export type KeyReconciliation = {
  scan_id: string;
  source_scans: { scan_id: string; target_location: string }[];
  summary: { inventory_keys: number; consumers: number; orphans: number; not_in_inventory: number; source_key_references: number };
  consumers: { system: string; label: string; algorithm?: string; key_size?: number; key_store?: string; state?: string; not_after?: string; references: { kind: string; identifier: string; files: number; sample_files: string[]; scan_id: string }[] }[];
  orphans: { system: string; label: string; algorithm?: string; key_size?: number; key_store?: string; state?: string; not_after?: string }[];
  not_in_inventory: { kind: string; identifier: string; files: number; sample_files: string[]; scan_id: string }[];
};
export const apiKeyReconciliation = (scanId: string): Promise<ApiResult<KeyReconciliation>> =>
  call(`/api/v1/scans/${encodeURIComponent(scanId)}/key-reconciliation`);

/** Estate CBOM (CycloneDX 1.5) — root → systems → assets + system-to-system edges. */
export type PortfolioCbom = {
  metadata: { component: { name: string; "bom-ref"?: string }; properties?: { name: string; value: string }[] };
  components: { type: string; name: string; "bom-ref": string; properties?: { name: string; value: string }[]; cryptoProperties?: any }[];
  dependencies?: { ref: string; dependsOn: string[] }[];
};
export const apiCbomPortfolio = (): Promise<ApiResult<PortfolioCbom>> => call("/api/v1/cbom/portfolio");

/* ── NBOM — Network Bill of Materials ────────────────────────────────── */
/* What is exposed on the wire (listeners, the certificates and suites they
   serve, site-to-site tunnels) plus the dependency graph that answers what
   breaks when one component is replaced. Distinct from the CBOM, which
   inventories cryptography in the estate's source. */

export interface NbomComponent {
  type: string;
  "bom-ref": string;
  name: string;
  properties: Array<{ name: string; value: string }>;
  "cryptoscan:findings": Array<{ code: string; severity: string; message: string; ref?: string }>;
}

export interface NbomCascadeEntry {
  ref: string;
  found: boolean;
  name?: string;
  affected: Array<{ ref: string; name: string; kind: string | null }>;
  affected_count: number;
  by_kind?: Record<string, number>;
  worst_severity?: string | null;
}

export interface NbomSummary {
  components: number;
  by_kind: Record<string, number>;
  unobserved: number;
  findings: number;
  by_severity: Record<string, number>;
  migration_priority: NbomCascadeEntry[];
}

export interface NbomResponse {
  nbom: {
    bomFormat: string;
    specVersion: string;
    serialNumber: string;
    metadata: Record<string, unknown>;
    components: NbomComponent[];
    dependencies: Array<{ ref: string; dependsOn: string[] }>;
  };
  summary: NbomSummary;
}

/* The estate's NBOM, derived from stored network scans. This is the one the
   page uses: a bank does not declare its listeners, the scanner finds them. */
export const apiNbomLive = (): Promise<ApiResult<NbomResponse & { source: string }>> =>
  call(`/api/v1/cbom/nbom`);

/* Ad-hoc / what-if: build a BOM from a hand-supplied estate without storing it. */
export const apiNbomBuild = (body: {
  endpoints?: unknown[]; tunnels?: unknown[]; devices?: unknown[]; estate?: string;
}): Promise<ApiResult<NbomResponse>> =>
  call(`/api/v1/cbom/nbom`, { method: "POST", body: JSON.stringify(body) });

export const apiNbomCascade = (
  ref: string,
  body: { endpoints?: unknown[]; tunnels?: unknown[]; devices?: unknown[]; estate?: string },
): Promise<ApiResult<NbomCascadeEntry>> =>
  call(`/api/v1/cbom/nbom/cascade?ref=${encodeURIComponent(ref)}`,
       { method: "POST", body: JSON.stringify(body) });

// Structured network inventory is intentionally typed as an evidence-backed
// snapshot: absent values remain absent/unknown and are never filled by UI
// defaults. The backend validates the complete Pydantic contract.
export interface NetworkInventoryCompleteness {
  status: "COMPLETE" | "INCOMPLETE";
  score: number;
  missing: string[];
  missing_sections?: string[];
  next_actions: string[];
}

export interface NetworkInventoryResponse {
  inventory_id: string;
  revision: number | null;
  persisted: boolean;
  status: "DRAFT" | "IN_REVIEW" | "APPROVED" | "EXPIRED";
  inventory: Record<string, any>;
  completeness: NetworkInventoryCompleteness;
  audit: Record<string, any>;
}

export interface NetworkInventoryRiskResponse {
  inventory_id: string;
  revision: number | null;
  profile_status: string;
  posture: "GREEN" | "AMBER" | "RED";
  reasons: string[];
  unknowns: string[];
  next_actions: string[];
  risk_score?: number;
  risk_rating?: string;
  status?: string;
}

export const apiNetworkInventory = (): Promise<ApiResult<NetworkInventoryResponse>> =>
  call("/api/v1/network/inventory");

export const apiNetworkInventoryRisk = (): Promise<ApiResult<NetworkInventoryRiskResponse>> =>
  call("/api/v1/network/inventory/risk");

export const apiNetworkInventorySchema = (): Promise<ApiResult<Record<string, any>>> =>
  call("/api/v1/network/inventory/schema");

export const apiValidateNetworkInventory = (inventory: Record<string, any>): Promise<ApiResult<Record<string, any>>> =>
  call("/api/v1/network/inventory/validate", {
    method: "POST",
    body: JSON.stringify({ inventory }),
  });

export const apiSaveNetworkInventory = (
  inventory: Record<string, any>,
  options: { inventory_id?: string; status?: "DRAFT" | "IN_REVIEW" | "APPROVED" | "EXPIRED"; source?: string; reviewed_by?: string; review_notes?: string } = {},
): Promise<ApiResult<NetworkInventoryResponse>> =>
  call("/api/v1/network/inventory", {
    method: "PUT",
    body: JSON.stringify({ inventory, ...options }),
  });

export const apiNetworkInventoryHistory = (inventoryId = "default"): Promise<ApiResult<{ inventory_id: string; revisions: NetworkInventoryResponse[] }>> =>
  call(`/api/v1/network/inventory/history?inventory_id=${encodeURIComponent(inventoryId)}`);

export interface NetworkInventoryTopologyResponse {
  inventory_id: string;
  revision: number | null;
  graph: { nodes: string[]; edges: Array<Record<string, any>> };
  edge_counts: Record<string, number>;
  node_count: number;
  edge_count: number;
  unlinked_devices: string[];
  unknown_endpoints: string[];
  unverified_edges: number;
  neo4j_cypher: string;
}

export interface NetworkConfigurationDriftResponse {
  inventory_id?: string;
  revision?: number | null;
  status: "IN_SYNC" | "DRIFTED" | "UNKNOWN";
  devices: Array<{ device_id: string; comparisons: Array<{ comparison: string; status: string; reason: string }> }>;
  drifted_comparisons: number;
  unknown_comparisons: number;
  raw_configuration_stored: false;
}

export const apiNetworkInventoryTopology = (): Promise<ApiResult<NetworkInventoryTopologyResponse>> =>
  call("/api/v1/network/inventory/topology");

export const apiNetworkConfigurationDrift = (): Promise<ApiResult<NetworkConfigurationDriftResponse>> =>
  call("/api/v1/network/inventory/configuration/drift");

export const apiNetworkInventoryCoverage = (): Promise<ApiResult<Record<string, any>>> =>
  call("/api/v1/network/inventory/coverage");

export interface NetworkCryptoScope {
  name: string;
  type: "network";
  destinations: string[];
  protocols: string[];
  allowed_operations: string[];
  traffic_budget: { max_connections: number; max_bytes: number };
  valid_until: string | null;
  inventory_id: string;
  saved_at?: string;
  saved_by?: string;
}

export interface NetworkCryptoScopeResponse {
  inventory_id: string;
  scope: NetworkCryptoScope | null;
  status: { state: "APPROVED" | "EXPIRED" | "NOT_CONFIGURED" | "INVALID"; expired: boolean; reason: string };
  model: string;
}

export const apiNetworkCryptoScope = (inventoryId = "default"): Promise<ApiResult<NetworkCryptoScopeResponse>> =>
  call(`/api/v1/network/crypto-scope?inventory_id=${encodeURIComponent(inventoryId)}`);

export const apiPutNetworkCryptoScope = (scope: NetworkCryptoScope): Promise<ApiResult<NetworkCryptoScopeResponse>> =>
  call("/api/v1/network/crypto-scope", { method: "PUT", body: JSON.stringify(scope) });

export const apiValidateNetworkCryptoScope = (scope: NetworkCryptoScope): Promise<ApiResult<{ valid: boolean; issues: string[]; status: NetworkCryptoScopeResponse["status"] }>> =>
  call("/api/v1/network/crypto-scope/validate", { method: "POST", body: JSON.stringify(scope) });

export interface NetworkEvidenceRecord {
  schema: string;
  evidence_type: "NETWORK_ACTIVE_OBSERVED" | "NETWORK_PASSIVE_OBSERVED" | "NETWORK_CONFIGURED" | "CERTIFICATE_OBSERVED" | "VENDOR_DECLARED" | "IMPORTED" | "UNKNOWN";
  evidence_id: string | null;
  target: { endpoint: string | null; host: string | null; port: number; ip_address: string | null };
  protocol: string;
  observation_status: string;
  tls_version: string | null;
  cipher_suite: string | null;
  decomposition: { key_exchange: string | null; authentication: string | null; encryption: string | null; mode: string | null; mac_or_prf: string | null; key_size_bits: number | null };
  certificate: { fingerprint_sha256: string | null; subject: string | null; issuer: string | null; public_key_algorithm: string | null; public_key_bits: number | null; curve: string | null; signature_algorithm: string | null };
  certificate_chain: { length: number; structural_status: string | null; trust_status: string | null; completeness: string | null };
  mutual_tls: string;
  mtls_evidence: string;
  policy_issues: string[];
  observed_at: string | null;
  scope_name: string | null;
  confidence: string;
  limitations: string[];
}

export interface NetworkEvidenceSummary {
  records: number;
  observed: number;
  not_observed: number;
  evidence_types: Record<string, number>;
  tls_versions: Record<string, number>;
  cipher_suites: Record<string, number>;
  key_exchange: Record<string, number>;
  signature_algorithms: Record<string, number>;
  policy_issues: Record<string, number>;
  unknown_note: string;
}

export interface NetworkEvidenceResponse {
  model: string;
  count: number;
  evidence: NetworkEvidenceRecord[];
  summary: NetworkEvidenceSummary;
  runs: Array<{ run_id: string | null; job_id: string | null; status: string | null; captured_at: string | null; target_kind: string | null }>;
  note: string;
}

export const apiNetworkCryptoEvidence = (limit = 5): Promise<ApiResult<NetworkEvidenceResponse>> =>
  call(`/api/v1/network/crypto-evidence?limit=${limit}`);

export interface NetworkCbomAsset {
  asset_id: string;
  algorithm: string;
  role: string;
  key_size: number | null;
  curve: string | null;
  mode: string | null;
  layer: "NETWORK_TRANSPORT";
  context: { host: string | null; port: number | null; ip_address: string | null; endpoint: string | null; protocol: string | null; tls_version: string | null; cipher_suite: string | null; certificate_fingerprint_sha256: string | null };
  evidence: { evidence_id: string | null; evidence_type: string; observed_at: string | null; confidence: string | null; scope_name: string | null };
  policy_issues: string[];
  quantum_impact: string | null;
}

export interface NetworkCbomResponse {
  model: string;
  layer: string;
  asset_count: number;
  assets: NetworkCbomAsset[];
  algorithms: Record<string, number>;
  roles: Record<string, number>;
  not_observed: string[];
  boundary: string;
}

export const apiNetworkCryptoCbom = (limit = 5): Promise<ApiResult<NetworkCbomResponse>> =>
  call(`/api/v1/network/crypto-cbom?limit=${limit}`);

export interface NetworkHopAttribution {
  model: string;
  roles: Record<string, string>;
  role_sources: Record<string, string>;
  segments: Array<{ from: string; to: string; kind: string; from_role: string; to_role: string; crypto: { evidence_type: string; evidence_mode: string | null; tls_version: string | null; cipher_suite: string | null; mutual_tls: string | null; certificate_fingerprint_sha256: string | null; evidence_id: string | null }; attack_surface_note: string | null }>;
  segment_kinds: Record<string, number>;
  termination_points: Array<{ node: string; role: string; role_source: string | null; client_side_from: string | null; internal_side_to: string | null; client_facing_observed: boolean; internal_observed: boolean; verdict: string; reason: string; certificate_comparison: string }>;
  terminating_nodes: string[];
  sidecars: Array<{ node: string; role: string; note: string; observed: boolean }>;
  unattributed_nodes: string[];
  nodes_observed: number;
  nodes_declared: number;
  complete: boolean;
  limitations: string[];
  boundary: string;
}

export interface NetworkCryptoPathResponse {
  model: string;
  nodes: Array<{ id: string; label: string; observed: boolean; evidence_type: string; role?: string; role_source?: string; role_inferred?: boolean }>;
  edges: Array<{ from: string; to: string; layer: string; evidence_type: string; evidence_id: string | null; tls_version: string | null; cipher_suite: string | null; decomposition: Record<string, unknown>; mutual_tls: string | null; observed_at: string | null; note: string | null; segment?: string; from_role?: string; to_role?: string }>;
  node_count: number;
  edge_count: number;
  observed_edges: number;
  unknown_edges: number;
  complete: boolean;
  boundary: string;
  attribution?: NetworkHopAttribution;
}

export const apiNetworkCryptoPath = (hops: Array<{ from: string; to: string; label?: string }>, options: { use_inventory_topology?: boolean; inventory_id?: string } = {}): Promise<ApiResult<NetworkCryptoPathResponse>> =>
  call("/api/v1/network/crypto-path", { method: "POST", body: JSON.stringify({ hops, ...options }) });

export interface NetworkEvidenceIntegrity {
  schema: string;
  verified: boolean;
  entries: number;
  checked_records: number;
  seq: number | null;
  head_hash: string;
  anchored_prev_hash: string;
  truncated: boolean;
  complete_from_seq: number | null;
  problems: Array<{ problem: string; seq?: number; detail?: string }>;
  tampered_records: Array<{ seq: number; evidence_id: string; expected: string; actual: string; problem: string }>;
  missing_records: Array<{ seq: number; evidence_id: string; run_id: string | null }>;
  unverifiable_entries: Array<{ seq: number; evidence_id: string; reason: string }>;
  unchained_records: string[];
  reason: string | null;
  distributed: boolean;
  anchoring: string;
  boundary: string;
}

export const apiNetworkCryptoIntegrity = (): Promise<ApiResult<NetworkEvidenceIntegrity>> =>
  call("/api/v1/network/crypto-evidence/integrity");

/* §28/§31 — signed anchor receipts for the evidence chain head. A receipt is a
 * claim until it leaves this database, so the UI keeps `external` visible. */
export interface NetworkAnchorReceipt {
  schema: string;
  anchor_id: string;
  tenant: string;
  created_at: string;
  created_by: string | null;
  note: string | null;
  chain: { namespace: string; seq: number; head: string; entries: number; truncated: boolean };
  signature_scheme: string;
  signature: string;
  key_source: string;
  external: boolean;
  export_hint: string;
  boundary: string;
}

export interface NetworkAnchorStatus {
  schema: string;
  anchoring: string;
  distributed: boolean;
  external: boolean;
  anchors: number;
  last_anchor: NetworkAnchorReceipt | null;
  key: { configured: boolean; source: string; variable: string; scheme: string; note: string };
  limitations: string[];
}

export interface NetworkAnchorVerification {
  schema: string;
  anchor_id: string | null;
  status: "HEAD_INTACT" | "ADVANCED" | "HISTORY_REWRITTEN" | "SIGNATURE_INVALID" | "UNKNOWN";
  signature_valid: boolean | null;
  rewritten: boolean | null;
  anchored_seq?: number;
  anchored_head?: string;
  current_seq?: number;
  current_head?: string;
  reason: string;
  external?: boolean;
  limitations?: string[];
}

export const apiNetworkAnchorStatus = (): Promise<ApiResult<NetworkAnchorStatus>> =>
  call("/api/v1/network/crypto-evidence/anchor");

export const apiNetworkAnchors = (): Promise<ApiResult<{ count: number; anchors: NetworkAnchorReceipt[]; key: NetworkAnchorStatus["key"]; note: string }>> =>
  call("/api/v1/network/crypto-evidence/anchors");

export const apiNetworkCreateAnchor = (note?: string): Promise<ApiResult<{ model: string; receipt: NetworkAnchorReceipt }>> =>
  call("/api/v1/network/crypto-evidence/anchor", { method: "POST", body: JSON.stringify({ note: note ?? null }) });

export const apiNetworkVerifyAnchor = (receipt: NetworkAnchorReceipt): Promise<ApiResult<NetworkAnchorVerification>> =>
  call("/api/v1/network/crypto-evidence/anchor/verify", { method: "POST", body: JSON.stringify({ receipt }) });

/* §30/§31 — single-writer observation lease: two replicas must not spend one budget. */
export interface NetworkWatchLease {
  schema: string;
  mode: string;
  distributed: boolean;
  lease: { held: boolean; holder: string | null; expires_at: string | null; expired: boolean; expires_in_seconds: number };
  limitations?: string[];
}

export interface NetworkLeaseDecision extends NetworkWatchLease {
  acquired?: boolean;
  released?: boolean;
  outcome: string;
  owner?: string;
  reason?: string;
}

export const apiNetworkWatchLease = (): Promise<ApiResult<NetworkWatchLease>> =>
  call("/api/v1/network/crypto-watch/lease");

export const apiNetworkAcquireWatchLease = (owner?: string): Promise<ApiResult<NetworkLeaseDecision>> =>
  call("/api/v1/network/crypto-watch/lease", { method: "POST", body: JSON.stringify({ owner: owner ?? null }) });

export const apiNetworkReleaseWatchLease = (owner: string): Promise<ApiResult<NetworkLeaseDecision>> =>
  call("/api/v1/network/crypto-watch/lease", { method: "POST", body: JSON.stringify({ owner, release: true }) });

export interface MessageLayerRecord {
  evidence_id: string;
  evidence_type: string;
  layer: string;
  protocol: string;
  observation_status: string;
  target: { endpoint: string | null; host: string | null; port: number | null; broker: string | null; service: string | null };
  listener: { security: string; name: string | null; transport_encrypted: boolean | null };
  tls_version: string | null;
  cipher_suite: string | null;
  certificate: { fingerprint_sha256: string | null; public_key_algorithm: string | null; signature_algorithm: string | null; not_after: string | null };
  sasl: { mechanism: string; authenticates: string; encrypts_messages: boolean; mechanism_is_crypto: boolean };
  client_authentication: string;
  authorization: string | null;
  payload_encryption: { status: string; algorithm: string | null; source: string; observed: boolean; note: string };
  policy_issues: string[];
  confidence: string;
}

export interface MessageLayerSummary {
  records: number;
  observed: number;
  configured: number;
  unknown: number;
  transport_encrypted: number;
  transport_plaintext: number;
  client_authenticated: number;
  protocols: Record<string, number>;
  listeners: Record<string, number>;
  sasl_mechanisms: Record<string, number>;
  payload_encryption_states: Record<string, number>;
  policy_issues: Record<string, number>;
  boundary: string;
}

export interface MessageLayerResponse {
  model: string;
  count: number;
  evidence: MessageLayerRecord[];
  summary: MessageLayerSummary;
  cbom: { asset_count: number; layers: Record<string, number>; roles: Record<string, number>; boundary: string };
  runs: Array<{ run_id: string | null; job_id: string | null; captured_at: string | null }>;
  note: string;
}

export const apiNetworkMessageLayer = (limit = 5): Promise<ApiResult<MessageLayerResponse>> =>
  call(`/api/v1/network/message-layer-evidence?limit=${limit}`);

export const apiObserveNetworkMessageLayer = (
  brokers: Array<Record<string, unknown>>,
): Promise<ApiResult<{ stored: number; evidence: MessageLayerRecord[]; summary: MessageLayerSummary; cbom: { asset_count: number; layers: Record<string, number> }; active_packets: number; note: string }>> =>
  call("/api/v1/network/message-layer-observe", { method: "POST", body: JSON.stringify({ brokers }) });

export interface CrossLayerComparison {
  kind: string;
  meaning: string | null;
  result: "MATCH" | "MISMATCH" | "NOT_COMPARABLE";
  reason: string | null;
  left: { layer: string; value: unknown; role: string; source: string | null; evidence_id: string | null };
  right: { layer: string; value: unknown; role: string; source: string | null; evidence_id: string | null };
}

export interface NetworkCorrelationResponse {
  model: string;
  services: Array<{
    service: string;
    layers_present: string[];
    layers_missing: string[];
    layers: Record<string, { present: boolean; facts: Array<Record<string, unknown>> }>;
    comparisons: CrossLayerComparison[];
    risk_hints: Array<Record<string, unknown>>;
    coverage: { complete: boolean; note: string };
  }>;
  summary: { services: number; services_with_all_layers: number; services_without_network_evidence: number; comparisons: number; matches: number; mismatches: number; not_comparable: number; unattributed_facts: number; risk_hints: number };
  unattributed_facts: Array<Record<string, unknown>>;
  limitations: string[];
  boundary: string;
  sources?: Record<string, unknown>;
}

export const apiNetworkCryptoCorrelate = (payload: {
  services: Array<{ name: string; hosts?: string[]; endpoints?: string[] }>;
  static?: Array<Record<string, unknown>>;
  runtime?: Array<Record<string, unknown>>;
  network?: Array<Record<string, unknown>>;
  use_latest_network_evidence?: boolean;
}): Promise<ApiResult<NetworkCorrelationResponse>> =>
  call("/api/v1/network/crypto-correlate", { method: "POST", body: JSON.stringify(payload) });

export interface ProtocolDetection {
  host: string;
  port: number;
  endpoint?: string;
  detected: string;
  detection_method: string;
  confidence: string;
  service_guess: { name: string; source: string };
  port_matches_protocol: boolean | null;
  tls_capable: boolean;
  tls: { tls_version?: string | null; cipher_suite?: string | null } | null;
  attempts: Array<{ probe: string; result: string }>;
  details?: Record<string, unknown>;
  limitations: string[];
}

export interface CryptoProbeResponse {
  model: string;
  run_id: string;
  scan_id: string | null;
  detections: ProtocolDetection[];
  detection_summary: { endpoints: number; by_protocol: Record<string, number>; unknown: number; port_protocol_mismatches: Array<{ endpoint: string; detected: string; port_guess: string | null }>; note: string };
  scope_refusals: Array<{ endpoint: string; protocol: string; error: string; reason: string }>;
  network_summary: { observed: number; not_observed: number };
  cbom: { asset_count: number; roles: Record<string, number>; algorithms: Record<string, number>; boundary?: string };
  evidence: Array<{ evidence_id: string; protocol: string; evidence_type: string; target: { endpoint: string | null }; tls_version: string | null; cipher_suite: string | null; policy_issues: string[] }>;
  evidence_chain?: { appended: number; head: string } | null;
  note: string;
}

export const apiNetworkCryptoProbe = (
  endpoints: string[],
  options: { protocol?: string; detect_only?: boolean; timeout?: number } = {},
): Promise<ApiResult<CryptoProbeResponse>> =>
  call("/api/v1/network/crypto-probe", { method: "POST", body: JSON.stringify({ endpoints, ...options }) });

/* Live TLS scan of operator-supplied host:port targets (POST /network-scans).
   The response carries the raw findings plus the persisted certificate
   inventory; the workspace renders counts only — never key material. */
export interface NetworkTlsScanResult {
  findings?: Array<Record<string, unknown>>;
  certificates?: Array<Record<string, unknown>>;
  alerts?: Array<Record<string, unknown>>;
  probe_telemetry?: Record<string, unknown>;
  job_id?: string;
  run_id?: string;
}

export const apiNetworkTlsScan = (
  hosts: string[],
  options: { scan_versions?: boolean; scan_ciphers?: boolean; check_chain_sent?: boolean; starttls?: string } = {},
): Promise<ApiResult<NetworkTlsScanResult>> =>
  call("/api/v1/network-scans", { method: "POST", body: JSON.stringify({ hosts, ...options }) });

export interface NetworkRiskFinding {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "FAIL" | "PASS" | "UNKNOWN" | "NOT_APPLICABLE";
  layer: string;
  protocol: string | null;
  endpoint: string | null;
  evidence_id: string | null;
  evidence_type: string | null;
  observed: unknown;
  expected: unknown;
  message: string;
  reference: string | null;
}

export interface NetworkPqcReport {
  verdict: string;
  summary: { endpoints: number; observed: number; not_observed: number; hybrid_kex: number; classical_only: number };
  endpoints: Array<{
    endpoint: string | null;
    readiness: string;
    key_exchange: string | null;
    certificate_signature: string | null;
    harvest_now_decrypt_later_exposed: boolean;
    note: string;
  }>;
  limitations: string[];
}

export interface NetworkRiskReport {
  model: string;
  verdict: string;
  policy: { policy_id: string; version: string; min_tls_version: string; require_forward_secrecy: boolean };
  layer: string;
  findings: NetworkRiskFinding[];
  failed: NetworkRiskFinding[];
  coverage_gaps: NetworkRiskFinding[];
  summary: { endpoints: number; records: number; protocols: Record<string, number>; by_severity: Record<string, number>; by_status: Record<string, number>; failed: number; unknown: number; rules: string[] };
  limitations: string[];
  pqc?: NetworkPqcReport;
}

export const apiNetworkCryptoRisk = (body: { policy?: Record<string, unknown> } = {}): Promise<ApiResult<NetworkRiskReport>> =>
  call("/api/v1/network/crypto-risk", { method: "POST", body: JSON.stringify(body) });

/* ── Unified estate evidence graph (spec 93) ───────────────────────────────
   One discovery job, six BOM projections of ONE evidence graph. Coverage is
   attempted/expected per plane — never "percent of crypto discovered" — and a
   failed plane arrives as FAILED with an impact statement, not as empty. */

export interface EstateCoverageRow {
  target: string; expected: number; collected: number; status: string;
  reason: string | null; impact: string | null; note: string | null;
}

export interface EstateCoverage {
  schema: string;
  targets: EstateCoverageRow[];
  summary: {
    target_classes: number; expected: number; collected: number;
    coverage_percent: number | null; by_status: Record<string, number>; failed_targets: string[];
  };
  meaning: string;
  not_observed: string[];
}

export interface EstateCollectorOutcome {
  plane: string; status: string; expected: number; collected: number;
  reason: string | null; impact: string | null; is_failure: boolean;
}

export interface EstateBom {
  bom: string; projection_id: string; components: Array<Record<string, unknown>>;
  counts: Record<string, number>;
}

export interface EstateBomAnchor {
  schema: string; anchor_id: string; projection_id: string; run_id: number | null;
  bom_count: number; bom_digests: Record<string, string>; bom_set_digest: string;
  created_at: string; created_by: string | null; note: string | null;
  signature_scheme: string; key_source: string; external: boolean; signature: string;
  export_hint: string; boundary: string;
}

export interface EstateAnchorVerify {
  anchor_id: string; projection_id: string; status: string; signature_valid: boolean | null;
  changed_boms: string[]; added_boms: string[]; removed_boms: string[]; reason: string; note?: string;
}

export interface EstateDriftReport {
  model: string; verdict: string; reason?: string; note?: string;
  baseline_projection_id?: string; current_projection_id?: string; same_snapshot?: boolean;
  boms?: Record<string, { status: string; reason: string | null; counts: { added: number; removed: number; changed: number } }>;
  coverage?: Record<string, { status: string; delta_expected?: number; delta_collected?: number; note: string | null }>;
  changed_boms?: string[]; changed_coverage?: string[]; degraded_planes?: string[];
  summary?: string; meaning?: string; runs_compared?: Array<number | null>;
}

export const apiEstateBomAnchor = (note?: string): Promise<ApiResult<EstateBomAnchor>> =>
  _rsPost<EstateBomAnchor>("/api/v1/estate/evidence/boms/anchor", { note: note ?? null });

export const apiEstateBomAnchorVerify = (anchor_id?: string): Promise<ApiResult<EstateAnchorVerify>> =>
  _rsPost<EstateAnchorVerify>("/api/v1/estate/evidence/boms/anchor/verify", { anchor_id: anchor_id ?? null });

export const apiEstateDrift = (): Promise<ApiResult<EstateDriftReport>> =>
  _rsGet<EstateDriftReport>("/api/v1/estate/evidence/drift");

export interface EstateScanReport {
  model: string;
  run_id: number | null;
  estate: string;
  scope: string | null;
  projection_id: string;
  collectors: EstateCollectorOutcome[];
  lifecycle: Array<{ phase: string; status: string; detail: unknown }>;
  summary: { assets: number; evidence: number; relationships: number; projection_id: string } & Record<string, unknown>;
  coverage: EstateCoverage;
  unknown: Record<string, unknown>;
  unknown_workflow: {
    by_state: Record<string, number>;
    open_work: number;
    stages: Array<{ state: string; meaning: string; count: number; next_action: string; truncated: boolean }>;
    unresolved_relationships: Array<Record<string, unknown>>;
    failed_collectors: Array<Record<string, unknown>>;
    note: string;
  };
  conflicts: unknown[];
  failed_planes: string[];
  partial_planes: string[];
  skipped_planes: string[];
  coverage_gaps: string[];
  verdict: string;
  verdict_detail: string;
  boms?: Record<string, EstateBom>;
  bom_counts?: Record<string, number>;
  consistency?: unknown;
  meaning: string;
  limitations: string[];
}

export interface EstatePlan {
  model: string;
  planes: Array<{ plane: string; source: string; boms: string; limitation: string; enabled: boolean; status: string; impact: string | null }>;
  enabled: string[];
  skipped: string[];
  note: string;
}

export const apiEstatePlan = (): Promise<ApiResult<EstatePlan>> =>
  _rsGet<EstatePlan>("/api/v1/estate/evidence/plan");

export interface EstateRealtime {
  schema: string;
  at: string;
  verdict: "NOT_RUNNING" | "IDLE_NO_SCHEDULES" | "RUNNING" | "DEGRADED" | "WAITING";
  reason: string;
  next_action: string | null;
  daemon: {
    heartbeat: {
      worker: string;
      state: string;
      last_cycle_at: string | null;
      next_wake_at: string | null;
      cycles: number;
      runs: number;
      failures: number;
      last_error: string | null;
      idle_reason: string | null;
    } | null;
    liveness: { state: "LIVE" | "STALE" | "STOPPED" | "NEVER_STARTED"; age_seconds: number | null; meaning: string; next_action: string | null };
  };
  schedules: { total: number; enabled: number; next_due_at: string | null; seconds_until_due: number | null; leases: Array<{ name: string; worker: string | null; until: string | null }> };
  runs: { recent: Array<{ schedule_id: string; started_at: string | null; finished_at: string | null; status: string; verdict: string | null; coverage_state: string | null; run_id: string | null; detail: string | null }>; last_finished_at: string | null; last_run_age_seconds: number | null };
  meaning: string;
}

export const apiEstateRealtime = (): Promise<ApiResult<EstateRealtime>> =>
  _rsGet<EstateRealtime>("/api/v1/estate/evidence/realtime");

export interface EstateScheduleRow {
  id: string; name: string; tenant_id: string | null; enabled: boolean;
  planes: string[] | null; next_run_at: string; consecutive_failures: number;
  cadence: { every?: string; interval_minutes?: number; cron?: string; timezone?: string };
  last_run: { at: string | null; run_id: string | null; verdict: string | null; coverage_state: string | null };
}
export interface EstateSchedules { model: string; schedules: EstateScheduleRow[]; note: string }
export const apiEstateSchedules = (): Promise<ApiResult<EstateSchedules>> =>
  _rsGet<EstateSchedules>("/api/v1/estate/evidence/schedules");
export const apiEstateCreateSchedule = (body: { name: string; every: string; planes: string[];
  enabled: boolean; scope: string; estate: string }): Promise<ApiResult<EstateScheduleRow>> =>
  _rsPost<EstateScheduleRow>("/api/v1/estate/evidence/schedules", body);

export const apiEstateScan = (body: { estate?: string; scope?: string | null; planes?: string[]; include_boms?: boolean; persist?: boolean } = {}): Promise<ApiResult<EstateScanReport>> =>
  _rsPost<EstateScanReport>("/api/v1/estate/evidence/scan", body);

/** Whether this tenant has a stored estate-discovery run at all.
 *
 * Every ``/estate/evidence/*`` read 404s with ``no_estate_discovery`` until one
 * job has run, and a payload-less client cannot invent the evidence that job
 * reads. This probe lets a page tell "nothing has been discovered yet" apart
 * from "the read failed", so it can offer the one action that fixes it instead
 * of blaming the operator's scope.
 */
export const apiEstateSummary = (): Promise<ApiResult<Record<string, unknown>>> =>
  _rsGet<Record<string, unknown>>("/api/v1/estate/evidence/summary");

/* Discovery surface coverage (GET /estate/evidence/discovery/surfaces).
 *
 * The registry is compiled in the backend from detectors that actually resolve
 * there, so this payload — not the console — is the source of any coverage claim.
 * `kind`, `maturity` and `observed` are three separate axes on purpose.
 */
export interface DiscoverySurfaceDetector {
  ref: string;
  present: boolean;
  reason: string | null;
}
export interface DiscoverySurface {
  id: string;
  label: string;
  planes: string[];
  kind: string;
  kind_meaning: string;
  maturity: string;
  maturity_ceiling: string;
  maturity_meaning: string;
  declared_maturity: string;
  reads: string;
  cannot_claim: string;
  gaps: string[];
  detectors: DiscoverySurfaceDetector[];
  configuration: { state: string; reason: string | null };
  observed: {
    state: string;
    planes: string[];
    statuses?: Record<string, string>;
    collected?: number;
    reason: string | null;
  };
  notes: string[];
}
export interface DiscoverySurfaces {
  schema: string;
  surfaces: DiscoverySurface[];
  rollup: {
    surfaces: number;
    by_maturity: Record<string, number>;
    by_kind: Record<string, number>;
    credentials_resolved: number;
    no_credentials_needed: number;
    observed_in_last_run: number;
  };
  kinds: Record<string, string>;
  maturities: Record<string, string>;
  claim: string;
  note: string;
  run_id?: string | null;
}
export const apiDiscoverySurfaces = (): Promise<ApiResult<DiscoverySurfaces>> =>
  _rsGet<DiscoverySurfaces>("/api/v1/estate/evidence/discovery/surfaces");

/* Collector depth — four matrices that answer "how far does discovery actually
   reach", each computed by the server from the collectors present in this build.

   runtime-depth      installed ≠ executed: which families have call-level
                      instrumentation, and what the store has actually observed.
   network-protocols  per-protocol readers, including the protocols with none.
   windows-collector  layer-by-layer Windows reach, with the server's own verdict
                      on whether it is a complete collector (it is not).
   bom-maturity       how deep each of the six BOMs is on the stored snapshot.

   None of these returns a percentage or a score, and the console computes none. */
export interface CollectorDetectorRef {
  ref: string;
  present: boolean;
  reason?: string | null;
}

export interface RuntimeDepthPath {
  id: string;
  label: string;
  family: string;
  depth: string;
  declared_depth: string;
  depth_meaning: string;
  producers: CollectorDetectorRef[];
  producers_present: number;
  ingest_only: string[];
  reads: string;
  cannot_claim: string;
  gaps: string[];
  notes: string[];
}

export interface RuntimeObserved {
  state: string;
  reason: string | null;
  rows: number | null;
  invocation_rows?: number;
  invocation_calls?: number;
  wire_rows?: number;
  library_risk_rows?: number;
  host_count?: number;
  sampled?: boolean;
}

export interface RuntimeShimCoverage {
  schema: string;
  source: string;
  symbols: Record<string, string[]>;
  counts: Record<string, number>;
  total: number;
  note: string;
}

export interface RuntimeDepth {
  schema: string;
  paths: RuntimeDepthPath[];
  depths: string[];
  depth_meaning: Record<string, string>;
  rollup: {
    paths: number;
    by_depth: Record<string, number>;
    call_level_paths: number;
    ingest_only_paths: number;
    absent_paths: number;
  };
  observed: RuntimeObserved | null;
  /* The interposed symbols the tracer carries, read from the C source. The
   * gnutls half is why this exists: it decides whether the GnuTLS row's
   * INVOCATION claim is real in *this* build, so the console can say which
   * stacks are visible instead of describing the design. */
  shim?: RuntimeShimCoverage;
  axiom: string;
  claim: string;
  note: string;
}

export const apiRuntimeDepth = (): Promise<ApiResult<RuntimeDepth>> =>
  _rsGet<RuntimeDepth>("/api/v1/estate/evidence/discovery/runtime-depth");

export interface NetworkProtocolRow {
  id: string;
  label: string;
  layer: string;
  strength: string;
  declared_strength: string;
  strength_meaning: string;
  producers: CollectorDetectorRef[];
  producers_present: number;
  reads: string;
  cannot_claim: string;
  gaps: string[];
  targets: string[];
  /* Engines that accept this protocol's observations without this build
   * producing them (`JVM_JCE`, `OPENSSL_TRACE`, …). The server has always sent
   * this for protocols, exactly as it does for runtime paths; the interface
   * omitted it, so the console could not show it. */
  ingest_only: string[];
  notes: string[];
}

export interface NetworkProtocols {
  schema: string;
  protocols: NetworkProtocolRow[];
  strengths: string[];
  strength_meaning: Record<string, string>;
  rollup: { protocols: number; by_strength: Record<string, number>; negotiated: number; offered_only: number; absent: number };
  measured: {
    state: string;
    reason?: string | null;
    run_id?: string | null;
    projection_id?: string;
    by_asset_class?: Record<string, { assets: number; with_network_evidence: number }>;
    note?: string;
  } | null;
  claim: string;
  note: string;
  port_table?: {
    ports: Array<{ port: number; protocol: string; label: string; classification: string; source: string; message_layer: string; plaintext_variant: boolean }>;
    counts: { ports: number; iana: number; convention: number };
    claim: string;
  } | null;
}

export const apiNetworkProtocols = (): Promise<ApiResult<NetworkProtocols>> =>
  _rsGet<NetworkProtocols>("/api/v1/estate/evidence/discovery/network-protocols");

export interface WindowsLayer {
  id: string;
  label: string;
  state: string;
  declared_state: string;
  state_meaning: string;
  establishes: string;
  establishes_meaning: string;
  producers: CollectorDetectorRef[];
  producers_present: number;
  reads: string;
  cannot_claim: string;
  gaps: string[];
  requires: string | null;
  notes: string[];
}

export interface WindowsCollector {
  schema: string;
  layers: WindowsLayer[];
  states: string[];
  state_meaning: Record<string, string>;
  evidence_classes: Record<string, string>;
  rollup: { layers: number; by_state: Record<string, number>; by_evidence: Record<string, number>; invocation_layers: number; substrate_layers: number };
  measured: {
    state: string;
    reason?: string | null;
    run_id?: string | null;
    windows_hosts?: number;
    windows_hosts_with_evidence?: number;
  } | null;
  verdict: { complete_collector: boolean; answer: string; reason: string };
  claim: string;
  note: string;
}

export const apiWindowsCollector = (): Promise<ApiResult<WindowsCollector>> =>
  _rsGet<WindowsCollector>("/api/v1/estate/evidence/discovery/windows-collector");

export interface BomMaturityRow {
  kind: string;
  label: string;
  question: string;
  consumes: string;
  ceiling: string;
  ceiling_meaning: string;
  cannot_claim: string;
  components: number;
  relationships: number;
  evidence_ids: number;
  by_component_depth: Record<string, number>;
  observed_components: number;
  configured_components: number;
  declared_components: number;
  unbacked_components: number;
  depth: string;
  depth_meaning: string;
  at_ceiling: boolean;
}

export interface BomMaturity {
  schema?: string;
  state?: string;
  reason?: string;
  run_id?: string;
  estate?: string;
  projection_id?: string;
  boms: BomMaturityRow[];
  depths?: string[];
  depth_meaning?: Record<string, string>;
  rollup?: { boms: number; by_depth: Record<string, number>; observed: number; at_ceiling: number };
  deepest?: string[];
  shallowest?: string[];
  claim: string;
  note?: string;
}

export const apiBomMaturity = (): Promise<ApiResult<BomMaturity>> =>
  _rsGet<BomMaturity>("/api/v1/estate/evidence/discovery/bom-maturity");

/* Where each capability reaches, surface by surface. States, not scores: a
 * SUBSTANTIAL surface may have nothing left to list, every other state must name
 * what is missing — the server rejects its own register if it does not. */
export interface MaturitySurface {
  id: string;
  label: string;
  state: string;
  state_meaning: string;
  collector: string | null;
  note: string;
  missing: string[];
}

export interface MaturityArea {
  id: string;
  label: string;
  state: string;
  /* OPERATIONAL / CANDIDATE / FOUNDATION — what may be said about the area,
   * kept separate from its coverage state. */
  readiness: string;
  readiness_meaning: string;
  summary: string;
  surfaces: MaturitySurface[];
  missing: string[];
  measured_by: string[];
  claim: string;
  /* Sentences a deck is not allowed to make about this area. */
  must_not_be_presented_as: string[];
}

/* The five capabilities that may be demonstrated but not sold as operational. */
export interface CapabilityBoundary {
  id: string;
  area: string;
  capability: string;
  status: string;
  says: string;
  not_operational: string;
  what_is_real: string;
  check_at: string;
}

export interface MaturityRegister {
  schema?: string;
  areas: MaturityArea[];
  /* Always served: the five capabilities this build does not present as
   * operational, each with the artefact that is real and the sentence it does
   * not entitle anyone to. Optional in the type only for older payloads. */
  boundaries?: CapabilityBoundary[];
  claims: { may_claim: string; may_not_claim: string[]; why: string };
  routes?: string[];
  note?: string;
}

export const apiMaturityRegister = (): Promise<ApiResult<MaturityRegister>> =>
  _rsGet<MaturityRegister>("/api/v1/estate/evidence/discovery/maturity");

/* The ten scenarios a bank expects an enterprise simulation engine to answer,
 * each with what this build can and cannot compute. Scenarios are not a
 * checklist of simulations performed: an ABSENT row is absent. */
export interface EnterpriseSimulationCoverage {
  engine: string;
  scenario: string;
  present?: boolean;
}

export interface EnterpriseSimulationScenario {
  id: string;
  label: string;
  status: string;
  status_meaning: string;
  covered_by: EnterpriseSimulationCoverage[];
  cannot: string[];
  requires: string[];
  note: string;
}

export interface EnterpriseSimulationCatalogue {
  schema?: string;
  statuses: Record<string, string>;
  scenarios: EnterpriseSimulationScenario[];
  rollup: Record<string, number>;
  executable?: Record<string, string[]>;
  unresolved?: string[];
  cannot_claim: string[];
  note?: string;
}

export const apiSimulationScenarios = (): Promise<ApiResult<EnterpriseSimulationCatalogue>> =>
  _rsGet<EnterpriseSimulationCatalogue>("/api/v1/estate/evidence/twin/simulation-scenarios");

export const apiEstateBoms = (bom?: string): Promise<ApiResult<Record<string, unknown>>> =>
  _rsGet<Record<string, unknown>>(`/api/v1/estate/evidence/boms${bom ? `?bom=${encodeURIComponent(bom)}` : ""}`);

/* One BOM's components, from the stored observation. The shapes differ per BOM
 * (a CBOM component carries algorithm/usage_state, an SBOM component a package
 * name), so the row types stay loose and the page prints what the server sent
 * rather than filling gaps of its own. */
export interface EstateBomComponent {
  bom_ref?: string;
  artifact_id?: string;
  component_id?: string;
  algorithm?: string;
  name?: string;
  version?: string | null;
  type?: string;
  role?: string | null;
  usage_state?: string | null;
  evidence_type?: string | null;
  asset_name?: string | null;
  asset_type?: string | null;
  layer?: string | null;
  location?: string | null;
  evidence_ids?: string[];
}

export interface EstateBomDocument {
  schema: string;
  bom: string;
  question?: string;
  estate: string | null;
  run_id: string | null;
  projection_id?: string;
  generated_at?: string;
  components: EstateBomComponent[];
  relationships?: Array<Record<string, unknown>>;
  counts?: Record<string, number>;
  evidence_refs?: Record<string, unknown>;
  unknowns?: Record<string, unknown>;
  boundary?: Record<string, unknown>;
}

export const apiEstateBomComponents = (bom: string): Promise<ApiResult<EstateBomDocument>> =>
  _rsGet<EstateBomDocument>(`/api/v1/estate/evidence/boms?bom=${encodeURIComponent(bom)}`);

/* Live estate (spec 100): connection state, change-only storage, attack patterns.
 *
 * The screen behind these calls must not turn a quiet estate into a green one: the
 * connection state is computed by the platform from the age of the last observation,
 * and these types carry the platform's own words for what each state means.
 */
export interface LiveConnectionState {
  schema: string;
  state: "LIVE" | "STALE" | "NEVER_CONNECTED";
  last_observation: string | null;
  seconds_since: number | null;
  interval_seconds: number;
  stale_after_seconds: number;
  meaning: string;
}

export interface LiveEstateStatus {
  schema: string;
  connection: LiveConnectionState;
  twin:
    | { state: "OBSERVED"; run_id: string; projection_id: string; assets: number; evidence: number;
        relationships: number; coverage: Record<string, unknown>; unknown: Record<string, unknown>;
        recorded_at: string }
    | { state: "NOT_OBSERVED"; reason: string }
    | { state: "UNREADABLE"; run_id: string; reason: string };
  boms: { projection_id: string | null; counts?: Record<string, number>;
          kinds?: Record<string, { available: boolean; download: string }>; reason?: string };
  changes_today: { count: number; by_severity: Record<string, number>; by_verdict: Record<string, number>;
                   unacknowledged: number; note: string };
  trust: { signatures_required: boolean; trust_keys_configured: number; findings: string[] };
  note: string;
  limits: string[];
}

export const apiLiveEstateStatus = (): Promise<ApiResult<LiveEstateStatus>> =>
  _rsGet<LiveEstateStatus>("/api/v1/ingestion/live/status");

export interface AttackPatternSignal {
  event_id: string | null; run_id: string | null; kind: string; severity: string | null;
  subject: string | null; detail: string | null; at: string | null; evidence_ids: string[];
}

export interface AttackPatternCorroboration {
  collectors: string[]; independent_sources: number; single_source: boolean;
  signals_total: number; signals_with_provenance: number; unmapped_evidence_ids: string[];
  note: string; does_not_change_level: string;
}

export interface AttackPattern {
  pattern_id: string; name: string; level: number; level_name: string; level_meaning: string;
  headline: string; why: string; subjects: string[]; change_kinds: string[];
  signals: AttackPatternSignal[]; first_seen: string | null; last_seen: string | null;
  not_proven: string[]; next_action: string; corroboration: AttackPatternCorroboration;
}

export interface AttackPatterns {
  schema: string; window_seconds: number; window: { from: string; to: string };
  events_considered: number; signals_considered: number; undated_signals: number;
  patterns: AttackPattern[]; count: number; by_level: Record<string, number>;
  highest_level: number;
  level_definitions: Record<string, { name: string; meaning: string }>;
  corroboration: {
    evidence_mapped: number; subjects_mapped: number; single_source_patterns: number; note: string;
  };
  summary: { total: number; by_level: Record<string, number>; level_names: Record<string, string>; note: string };
  note: string; limits: string[];
}

export const apiThreatPatterns = (windowSeconds = 3600): Promise<ApiResult<AttackPatterns>> =>
  _rsGet<AttackPatterns>(`/api/v1/estate/evidence/threat/patterns?window_seconds=${windowSeconds}`);

export interface LiveObservations {
  schema: string; count: number;
  observations: Array<{ run_id: string; recorded_at: string; estate: string | null; scope: string | null;
                        projection_id: string | null; assets: number | null; evidence: number | null;
                        relationships: number | null }>;
  note: string;
}

export const apiLiveObservations = (limit = 20): Promise<ApiResult<LiveObservations>> =>
  _rsGet<LiveObservations>(`/api/v1/ingestion/observations?limit=${limit}`);

/* A BOM download is a fetch + blob write, so it carries the session (and the tenant)
 * the same way every other call does, and a failed download leaves no file behind. */
export async function downloadBom(kind: string, fmt: "cyclonedx" | "json" = "cyclonedx"): Promise<{ ok: boolean; error?: string; filename?: string }> {
  try {
    const resp = await tenantFetch(`/api/v1/estate/evidence/boms/${encodeURIComponent(kind)}/export?fmt=${fmt}`, {
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    if (!resp.ok) return { ok: false, error: `HTTP ${resp.status}` };
    const disposition = resp.headers.get("content-disposition") || "";
    const match = /filename="([^"]+)"/.exec(disposition);
    const filename = match ? match[1] : `cryptoscan-${kind.toLowerCase()}.${fmt === "cyclonedx" ? "cdx.json" : "json"}`;
    const blob = await readableJsonBlob(await resp.blob());
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    return { ok: true, filename };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

export interface DeviceInventoryResponse {
  model: string;
  stored: number;
  summary: { devices: number; surfaces: number; by_plane: Record<string, number>; issues: Record<string, number>; telnet_devices: string[]; legacy_snmp_devices: string[]; declared: number; observed: number; not_observed: number; read_only: boolean; configuration_changes: number };
  read_only: boolean;
  configuration_changes: number;
  note: string;
}

export const apiNetworkDeviceInventory = (devices: Array<Record<string, unknown>>): Promise<ApiResult<DeviceInventoryResponse>> =>
  call("/api/v1/network/device-inventory", { method: "POST", body: JSON.stringify({ devices }) });

export interface NetworkSafetyState {
  schema: string;
  engaged: boolean;
  reason: string | null;
  engaged_by: string | null;
  engaged_at: string | null;
  released_by: string | null;
  released_at: string | null;
  release_note: string | null;
  active_observation_permitted: boolean;
  passive_ingest_permitted: boolean;
  config_import_permitted: boolean;
  distributed: boolean;
  boundary: string;
}

export const apiNetworkCryptoSafety = (): Promise<ApiResult<NetworkSafetyState>> =>
  call("/api/v1/network/crypto-safety");

export const apiNetworkCryptoStop = (engage: boolean, reason?: string): Promise<ApiResult<NetworkSafetyState>> =>
  call("/api/v1/network/crypto-stop", { method: "POST", body: JSON.stringify({ engage, reason }) });

export interface NetworkIpsecObservation {
  model: string;
  scope: Record<string, unknown>;
  results: Array<{ endpoint: string; status: string; proposals?: Array<Record<string, unknown>>; issues?: string[]; detail?: string; ike?: Record<string, unknown> | null; esp?: Record<string, unknown> | null; notifies?: Array<Record<string, unknown>> }>;
  observed: number;
  not_observed: number;
  evidence_type: string;
  esp_observed?: boolean;
  boundary: string;
  evidence?: NetworkEvidenceRecord[];
  run_id?: string;
  scan_id?: string;
}

export const apiIpsecObserve = (endpoints: string[], options: { timeout?: number; inventory_id?: string } = {}): Promise<ApiResult<NetworkIpsecObservation>> =>
  call("/api/v1/network/ipsec-observe", { method: "POST", body: JSON.stringify({ endpoints, ...options }) });

export const apiNetworkCryptoObserve = (endpoints: string[], options: { protocol?: string; operations?: string[]; scan_versions?: boolean; scan_ciphers?: boolean } = {}): Promise<ApiResult<{ model: string; scope: Record<string, unknown>; evidence: NetworkEvidenceRecord[]; summary: NetworkEvidenceSummary; certificates: unknown[] }>> =>
  call("/api/v1/network/crypto-observe", { method: "POST", body: JSON.stringify({ endpoints, ...options }) });

export interface NetworkBudgetResponse {
  schema: string;
  inventory_id: string;
  configured: boolean;
  reason?: string;
  window_started_at?: string;
  window_seconds?: number;
  connections_used?: number;
  bytes_used?: number;
  runs?: number;
  max_connections?: number;
  max_bytes?: number;
  connections_remaining?: number | null;
  bytes_remaining?: number | null;
  exhausted?: boolean;
  distributed?: boolean;
}

export const apiNetworkCryptoBudget = (inventoryId = "default"): Promise<ApiResult<NetworkBudgetResponse>> =>
  call(`/api/v1/network/crypto-budget?inventory_id=${encodeURIComponent(inventoryId)}`);

export interface PassiveObservationInput {
  timestamp?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip: string;
  dst_port: number;
  protocol?: string;
  server_name?: string;
  tls_version?: string;
  cipher_suite?: string;
  certificate_fingerprint_sha256?: string;
  certificate_public_key_algorithm?: string;
  certificate_signature_algorithm?: string;
  certificate_curve?: string;
  ja3?: string;
  ja4?: string;
  alpn?: string;
  bytes?: number;
  sensor_id?: string;
  capture_point?: string;
  direction?: string;
}

export interface ScopeImportPreview {
  schema: string;
  source: string;
  source_description: string;
  generated_at: string;
  candidates: Array<{ endpoint: string; evidence_type: string; source: string; declared: boolean; observed: boolean }>;
  accepted_count: number;
  rejected: Array<{ endpoint: string; reason: string }>;
  duplicate_count: number;
  truncated: boolean;
  probing_performed: false;
  note: string;
}

export interface ScopeImportResponse {
  preview: ScopeImportPreview;
  applied: boolean;
  probing_performed: false;
  apply_blocked?: string;
  merge?: { destinations: string[]; added: string[]; already_present: string[]; dropped_over_limit: string[]; total: number };
  scope?: NetworkCryptoScope;
}

/** §4 declared/imported scope candidates — importing never probes. */
export const apiImportNetworkScope = (body: { source: string; text?: string; entries?: Array<Record<string, unknown>>; apply?: boolean; inventory_id?: string }): Promise<ApiResult<ScopeImportResponse>> =>
  call("/api/v1/network/crypto-scope/import", { method: "POST", body: JSON.stringify(body) });

export interface NetworkWatchStatus {
  schema: string;
  running: boolean;
  interval_seconds: number;
  inventory_id: string;
  started_at: string | null;
  last_tick_at: string | null;
  last_result: { status: string; reason?: string; observed?: number; summary?: NetworkEvidenceSummary } | null;
  ticks: number;
  observed_ticks: number;
  skipped_ticks: number;
  failed_ticks: number;
  distributed: boolean;
  boundary: string;
  scope?: { state: string; expired: boolean; reason: string };
  note?: string;
}

export const apiNetworkCryptoWatch = (): Promise<ApiResult<NetworkWatchStatus>> =>
  call("/api/v1/network/crypto-watch");

export const apiStartNetworkCryptoWatch = (intervalSeconds: number, inventoryId = "default"): Promise<ApiResult<NetworkWatchStatus>> =>
  call("/api/v1/network/crypto-watch", { method: "POST", body: JSON.stringify({ interval_seconds: intervalSeconds, inventory_id: inventoryId }) });

export const apiStopNetworkCryptoWatch = (): Promise<ApiResult<NetworkWatchStatus>> =>
  call("/api/v1/network/crypto-watch", { method: "DELETE" });

export const apiTickNetworkCryptoWatch = (): Promise<ApiResult<{ status: string; reason?: string; observed?: number; run_id?: string }>> =>
  call("/api/v1/network/crypto-watch/tick", { method: "POST" });

/** Metadata-only sensor intake (§22): payload/password/private-key fields are refused server-side. */
export const apiNetworkCryptoPassive = (observations: PassiveObservationInput[], options: { inventory_id?: string; scope_name?: string } = {}): Promise<ApiResult<{ model: string; stored: number; evidence: NetworkEvidenceRecord[]; summary: NetworkEvidenceSummary; active_packets: number; note: string }>> =>
  call("/api/v1/network/crypto-passive", { method: "POST", body: JSON.stringify({ observations, ...options }) });

export const apiDiscoverNetworkInventory = (body: {
  scope_specs: Array<string | Record<string, unknown>>;
  inventory_id?: string;
  authorization_scope?: string;
  plugins?: string[];
}): Promise<ApiResult<NetworkInventoryResponse & { scan_metadata?: Record<string, unknown>; asset_summary?: Record<string, number> }>> =>
  call("/api/v1/network/inventory/discover", {
    method: "POST",
    body: JSON.stringify(body),
  });

// ---------------------------------------------------------------------------
// Cross-BOM cascade (unified) + dependency-edge management
// ---------------------------------------------------------------------------

/** Disjoint modeled-system buckets, not confirmed outage counts.
 * Direct seeds take precedence over consumers, then forward-only context. */
export interface CascadeScopeCounts {
  schema: "cryptoscan.cascade-system-scope/1";
  direct_exposure: { count: number };
  dependent_consumers: { count: number };
  supporting_context: { count: number };
  exposure_system_count: number;
  review_system_count: number;
}

export interface CascadeSystemScope extends CascadeScopeCounts {
  direct_exposure: { systems: string[]; count: number };
  dependent_consumers: { systems: string[]; count: number };
  supporting_context: { systems: string[]; count: number };
  exposure_systems: string[];
  review_systems: string[];
}

export interface CascadeScopeDelta {
  added: string[]; removed: string[];
  unchanged_count: number; before: number; after: number;
}

export interface DependencyRelationshipPolicy {
  version: string;
  direction: "consumer_to_provider";
  propagating_relations: string[];
  context_relations: string[];
  unknown_relations: "non_propagating";
  unspecified_relation: "CALLS";
  max_system_hops: number;
}

export interface RelationshipLifecycleFields {
  lifecycle_state?: string;
  effective_state?: string;
  lifecycle_source?: string;
  lifecycle_revision?: number;
  valid_until?: string | null;
  last_confirmed_at?: string | null;
}

export interface RelationshipLifecycleSummary {
  schema: string;
  as_of: string;
  counts: Record<string, number>;
  excluded_count: number;
  excluded_records: Array<RelationshipLifecycleFields & { id?: string | null; kind?: string | null; state: string }>;
  excluded_records_truncated: boolean;
  unbounded_active_count: number;
  note: string;
}

export interface CascadeSoftwareContext {
  schema: string;
  artifacts: { id: string; digest: string; identity_source: string; evidence_ref: string; byte_count?: number | null }[];
  sbom_bindings: (RelationshipLifecycleFields & { id: string; artifact_id: string; sbom_artifact_id: string; sbom_sha256: string; assertion_source: string; evidence_ref: string; unresolved_component_count: number })[];
  packages: { purl?: string | null; package_identity?: string | null; name?: string; version?: string | null; sbom_binding_id: string; artifact_id: string }[];
  deployments: (RelationshipLifecycleFields & { id: string; artifact_id: string; system_id: string; deployment_key: string; environment: string; assertion_source: string; evidence_ref: string })[];
  systems: string[];
  unlinked_deployment_ids: string[];
  unbound_artifact_ids: string[];
  deployment_evidence: string;
  coverage?: { truncated: boolean; collections: Record<string, { total: number; returned: number; truncated: boolean }> } | null;
}

export interface TraversalEdgeEvidence extends RelationshipLifecycleFields {
  operational_condition?: OperationalDependencyCondition;
  record_id?: string;
  from: string; to: string; relation: string; provenance: string; source?: string;
  evidence_references: unknown[]; evidence_missing: boolean; references_truncated: boolean;
  confidence?: number | string | null; confidence_meaning: string;
  references_verified_by_traversal: false;
  identity?: Record<string, unknown>;
  freshness: { as_of: string; eligibility: string; validity: string;
    observation: EvidenceTimestamp; confirmation: EvidenceTimestamp; verification_timestamp: EvidenceTimestamp; note: string };
}
export interface EvidenceTimestamp { value: string | null; status: string; age_seconds: number | null }
export interface TraversalPathEvidence {
  schema: string; available: boolean; nodes: string[]; edges: TraversalEdgeEvidence[]; hops: number;
  direction: string; scope: string; provenance_classes: string[]; mixed_provenance: boolean;
  evidence_gap_count: number; unbounded_edge_count: number; note: string;
}
export interface TraversalEvidenceEnvelope {
  schema: string; as_of: string; paths: (TraversalPathEvidence & { system_id: string })[];
  requested_count: number; returned_count: number; limit: number; missing_witness_count: number;
  missing_system_ids: string[]; missing_system_ids_truncated: boolean; truncated: boolean;
  complete_for_requested_systems: boolean; all_paths: false; note: string;
}
export interface CascadeSeedEvidence {
  system_id: string; kind: string; basis: string; path?: TraversalPathEvidence;
  records?: Record<string, unknown>[]; record_count?: number; record_listing_truncated: boolean;
  complete_chain_verified?: false; note?: string;
}
export interface CascadeTraversalEvidence {
  schema: string; direct: CascadeSeedEvidence[]; direct_count: number; direct_truncated: boolean;
  potential_direct: CascadeSeedEvidence[]; potential_direct_count: number; potential_direct_truncated: boolean;
  dependent_consumers: TraversalEvidenceEnvelope; supporting_context: TraversalEvidenceEnvelope;
  potential: TraversalEvidenceEnvelope; vendor_subtiers?: TraversalEvidenceEnvelope; note: string;
}

export interface ProcessImpact {
  schema: string; as_of: string;
  counts: { review: number; exposure: number; context_only: number; potential_only: number };
  review_processes: { id: string; name: string | null }[];
  processes: { id: string; name: string | null; name_conflict: boolean; scopes: string[];
    exposed: boolean; context_only: boolean; potential_only: boolean; reason_count: number; reasons_truncated: boolean;
    reasons: { system_id: string; system_scope: string; certainty: string; role: string | null;
      support_link: TraversalEdgeEvidence; system_explanation: { group: string; system_id: string; available: boolean; note: string } }[];
    declared_business_context: { revenue_daily: number | null; customer_count: number | null } }[];
  coverage: { source_coverage?: { processes_truncated: boolean; support_links_truncated: boolean } | null;
    requested_system_count: number; systems_without_recorded_links: string[]; systems_without_recorded_links_count: number;
    missing_system_list_truncated: boolean; unresolved_or_invalid_link_count: number; terminal_link_count: number;
    returned_process_count: number; total_process_count: number; process_limit: number; processes_truncated: boolean; reason_limit_per_process: number };
  economic_context: { revenue_daily: ProcessMetric; customer_count: ProcessMetric; unmapped_exposed_system_count: number; scope: string; note: string };
  note: string;
}
export interface ProcessMetric { known_sum: number | null; complete_sum: number | null; missing_or_conflicting_process_count: number }

export interface CascadeTargetCandidate {
  kind: string; canonical_target: string | null; label: string; matched_by: string;
  selectable: boolean; conflicting_records?: boolean;
}
export interface CascadeTargetResolution {
  schema: string; status: string; method: string; input: string; requested_kind: string | null;
  allow_name_search: boolean; selected: CascadeTargetCandidate | null;
  candidate_count: number; candidates: CascadeTargetCandidate[]; candidate_limit: number;
  candidates_truncated: boolean; reason?: string | null; note: string;
  coverage?: Record<string, unknown> | null;
}
export type OperationalMode = "UNKNOWN" | "HARD" | "OPTIONAL" | "FAILOVER" | "ASYNC_BUFFERED";
export interface OperationalDependencyAssertion {
  mode: OperationalMode; assumptions?: string[]; evidence_ref?: string;
  failover_system_ids?: string[]; buffer_capacity_messages?: number; buffer_retention_seconds?: number;
}
export interface OperationalDependencyCondition {
  schema: string; mode: OperationalMode; assertion_status: string;
  assertion: OperationalDependencyAssertion; conditional_outcome: string; gaps: string[];
  failover_references: { resolution: string; loaded_system_ids: string[]; not_in_loaded_registry: string[]; invalid_self_or_provider_ids: string[] };
  verified: false; safe_delay_seconds: null; failure_probability: null; note: string;
}
export interface OperationalImpact {
  schema: string; as_of: string; analysis_kind: string; provider_disruption_assumed: false;
  mode_counts: Record<OperationalMode, number>; edge_count: number; edge_limit: number; edges_truncated: boolean;
  non_current_edge_count: number; scope: string; note: string; source_coverage?: unknown;
  edges: { from: string; to: string; relation: string; record_id: string | null;
    consumer_scope: string; provider_scope: string; condition: OperationalDependencyCondition; relationship_evidence: TraversalEdgeEvidence }[];
}
export interface OperationalComparison {
  comparable: boolean; reason?: string; changed_edges?: string[]; added_edges?: string[]; removed_edges?: string[];
}
export interface AnalysisCoverage {
  schema: string; status: "GAPS_REPORTED" | "UNKNOWN" | "BOUNDED_REVIEW";
  analysis_performed: boolean; source_metadata_available: boolean;
  known_input_truncation: boolean; known_horizon_omission: boolean;
  horizon_extension_unknown: boolean; explanation_truncation: boolean;
  estate_completeness: "UNKNOWN"; note: string; dependency_source?: string;
  collections: Record<string, { returned: number | null; limit: number | null; truncated: boolean;
    known_total?: number | null; observed_lower_bound?: number; unit: string; scope?: string; status?: string }>;
  traversals: { scope: string; unit: string; direction: string; max_depth: number;
    extension_check: string; more_loaded_systems?: boolean | null; more_loaded_entities?: boolean | null;
    unvisited_neighbour_count: number | null; note: string }[];
  missing_links: { name: string; count: number | null; denominator: number | null; scope: string; status: string }[];
  explanations: { name: string; requested?: number | null; returned?: number | null; limit?: number | null;
    truncated: boolean; missing_within_selected_count?: number | null; scope: string }[];
}
export type AnalysisCoverageSummary = Pick<AnalysisCoverage, "schema" | "status" | "known_input_truncation" |
  "known_horizon_omission" | "horizon_extension_unknown" | "explanation_truncation" | "source_metadata_available" | "estate_completeness">;

export interface UnifiedCascadeResult {
  coverage?: AnalysisCoverage | null;
  target_resolution?: CascadeTargetResolution | null;
  analysis_performed?: boolean;
  traversal_evidence?: CascadeTraversalEvidence | null;
  schema: string;
  relationship_policy?: DependencyRelationshipPolicy | null;
  relationship_lifecycle?: RelationshipLifecycleSummary | null;
  verdict: "AFFECTED" | "NOT_FOUND" | "INSUFFICIENT_DATA" | "UNRESOLVED";
  run_id?: string;
  target: { input: string; kind: string; matched?: Record<string, any> | null };
  layers: Record<string, any> & { software?: CascadeSoftwareContext };
  impact: {
    affected_systems: string[];
    /** Legacy full review union, including supporting context. */
    affected_system_count: number;
    system_classification?: CascadeSystemScope | null;
    lifecycle_uncertainty?: {
      possible_additional_systems: string[];
      count: number;
      possible_direct_systems: string[];
      note: string;
    };
    affected_processes?: { id?: string; name?: string }[];
    process_impact?: ProcessImpact | null;
    operational_impact?: OperationalImpact | null;
    migration_waves?: Record<string, string[]>;
    twin_assets?: string[];
    libraries?: string[];
    certificate?: Record<string, any> | null;
    max_propagation_depth?: number;
  };
  honest_unknowns: string[];
  as_of: string;
  max_depth_limit?: number;
}

export interface CascadeRunSummary {
  coverage?: AnalysisCoverageSummary | null;
  analysis_performed?: boolean;
  target_resolution?: CascadeTargetResolution | null;
  id: string;
  target: string;
  target_kind: string | null;
  max_depth: number;
  verdict: string;
  affected_system_count?: number | null;
  system_classification?: CascadeScopeCounts | null;
  relationship_policy?: DependencyRelationshipPolicy | null;
  created_by: string | null;
  created_at: string | null;
}

export interface CascadeRunDiff {
  coverage_comparison?: { comparable: boolean; reason: string | null; note: string };
  operational_comparison?: OperationalComparison;
  target_comparison?: { comparable: boolean; reason: string | null };
  process_comparison?: { comparable: boolean; run_schema: string | null; against_schema: string | null; reason: string | null };
  policy_comparison?: { comparable: boolean; run_version: string | null; against_version: string | null };
  system_classification?: {
    available: boolean;
    reason?: string;
    direct_exposure?: CascadeScopeDelta;
    dependent_consumers?: CascadeScopeDelta;
    supporting_context?: CascadeScopeDelta;
  };
  target: string;
  verdict_changed: boolean;
  run: { id: string; created_at: string | null; verdict: string };
  against: { id: string; created_at: string | null; verdict: string };
  affected_systems: {
    available?: boolean; reason?: string;
    added: string[]; removed: string[];
    unchanged_count: number | null; before: number | null; after: number | null;
  };
  affected_processes: { added: string[]; removed: string[]; before: number | null; after: number | null };
}

export const apiUnifiedCascade = (
  target: string,
  kind?: string,
  maxDepth = 6,
  allowNameSearch = false,
): Promise<ApiResult<UnifiedCascadeResult>> =>
  call("/api/v1/technology-bom/cascade", {
    method: "POST",
    body: JSON.stringify({ target, kind: kind || undefined, max_depth: maxDepth, allow_name_search: allowNameSearch }),
  });

export const apiCascadeRuns = (
  limit = 20,
): Promise<ApiResult<{ runs: CascadeRunSummary[]; count: number }>> =>
  call(`/api/v1/technology-bom/cascade/runs?limit=${limit}`);

export const apiCascadeRunDiff = (
  runId: string,
  against?: string,
): Promise<ApiResult<CascadeRunDiff>> =>
  call(
    `/api/v1/technology-bom/cascade/runs/${encodeURIComponent(runId)}/diff` +
    (against ? `?against=${encodeURIComponent(against)}` : ""),
  );

export interface RegisteredDependencyEdge extends RelationshipLifecycleFields {
  operational_dependency?: OperationalDependencyAssertion | null;
  operational_condition?: OperationalDependencyCondition;
  source?: string;
  id?: string;
  parent_id: string;
  child_id: string;
  parent_name: string | null;
  child_name: string | null;
  relation: string;
  evidence_ref?: string | null;
  confidence_meaning?: string | null;
}

export const apiGraphEdges = (
  systemId?: string,
  limit = 200,
): Promise<ApiResult<{ edges: RegisteredDependencyEdge[]; count: number }>> =>
  call(
    `/api/v1/graph/edges` +
    `?limit=${encodeURIComponent(String(limit))}` +
    (systemId ? `&system_id=${encodeURIComponent(systemId)}` : ""),
  );

export const apiGraphRegisterEdge = (
  parentId: string,
  childId: string,
  relation = "CALLS",
  evidence?: { evidence_ref?: string; confidence_meaning?: string; operational_dependency?: OperationalDependencyAssertion },
): Promise<ApiResult<{ registered: boolean; edge: RegisteredDependencyEdge }>> =>
  call("/api/v1/graph/edges", {
    method: "POST",
    body: JSON.stringify({ parent_id: parentId, child_id: childId, relation, ...evidence }),
  });

export const apiGraphDeleteEdge = (
  parentId: string,
  childId: string,
  retirement: { expected_revision: number; reason: string; evidence_ref: string },
): Promise<ApiResult<{ deleted: boolean; retained: boolean }>> =>
  call(
    `/api/v1/graph/edges/${encodeURIComponent(parentId)}/${encodeURIComponent(childId)}?${new URLSearchParams({ expected_revision: String(retirement.expected_revision), reason: retirement.reason, evidence_ref: retirement.evidence_ref })}`,
    { method: "DELETE" },
  );

/** Blast radius from a crypto asset: unions the walk over every using system. */
export const apiGraphBlastRadiusFromAsset = (
  assetId: string,
  hops = 5,
): Promise<ApiResult<BlastRadiusResult & { start_kind?: string; owning_systems?: string[] }>> =>
  call(`/api/v1/graph/blast-radius?asset_id=${encodeURIComponent(assetId)}&hops=${hops}`);

/* Fact store read (§5, round 64): the materialised fact projection over
 * evidence. Every row carries the §4.2 identity spine (asset_key) — the
 * canonical join from a crypto asset to its fact row. The store is
 * derived and rebuildable; GET /facts/crypto remains the live reference. */
export interface FactStoreRow {
  tenant_id?: string | null;
  asset_key?: string | null;
  fact: {
    algorithm: string | null;
    purpose?: string | null;
    file_path?: string | null;
    key_size?: number | null;
    mode?: string | null;
  };
  observation_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
  scanners?: string[];
  confidences?: string[];
  hardcoded_key_observations?: number;
  evidence_ids?: string[];
  evidence_count?: number;
  evidence_truncated?: boolean;
  fresh?: boolean;
}
export interface FactStoreResponse {
  model: string;
  freshness?: string;
  stale_rows?: number;
  facts: FactStoreRow[];
  facts_returned: number;
  facts_matching: number;
  truncated?: boolean;
}
export const apiFactStore = (params: {
  algorithm?: string; file_prefix?: string; limit?: number;
} = {}): Promise<ApiResult<FactStoreResponse>> => {
  const q = new URLSearchParams();
  if (params.algorithm) q.set("algorithm", params.algorithm);
  if (params.file_prefix) q.set("file_prefix", params.file_prefix);
  if (params.limit) q.set("limit", String(params.limit));
  const qs = q.toString();
  return call(`/api/v1/facts/store${qs ? `?${qs}` : ""}`);
};


export interface NotificationReceiptSummary {
  observed_at: string; counts: Record<string, number>; total: number; pending: number;
  time_eligible: number; expired_claims: number; oldest_pending_at: string | null; note: string;
}
export interface NotificationReceipt {
  id: string; event_id: string; integration_id: string; channel: string; event_class: string;
  status: string; attempt_count: number; http_status: number | null; created_at: string;
  delivered_at: string | null; next_attempt_at: string | null; lease_expires_at: string | null;
  has_error: boolean; time_eligible: boolean;
}
export interface NotificationReceiptPage {
  items: NotificationReceipt[]; next_cursor: string | null; observed_at: string; note: string;
}


/** Manual-owned operational annotation; a declaration, never a freshness confirmation. */
export const apiGraphUpdateOperationalDependency = (parentId: string, childId: string, body: {
  expected_revision: number; operational_dependency: OperationalDependencyAssertion | null; reason: string; evidence_ref: string;
}): Promise<ApiResult<{ updated: boolean; edge: RegisteredDependencyEdge }>> =>
  call(`/api/v1/graph/edges/${encodeURIComponent(parentId)}/${encodeURIComponent(childId)}/operational-dependency`, {
    method: "PATCH", body: JSON.stringify(body),
  });

export interface LegacyImportPage {
  systems: { id: string; name: string }[];
  total: number; page: number; page_size: number; unassigned_review_required: number;
}
export interface LegacyImportReview {
  system_id: string; system_name: string; snapshot_sha256: string;
  replacement_document_sha256: string | null; pending_assets: number; mixed_evidence_assets: number;
  assets: { id: string; algorithm: string; reported_confidence: string; linked_evidence_count: number }[];
  limit: number; message: string;
}
export const apiCbomLegacyImports = (page = 1): Promise<ApiResult<LegacyImportPage>> =>
  call(`/api/v1/cbom/legacy-imports?page=${page}&page_size=50`);
export const apiCbomLegacyReview = (systemId: string): Promise<ApiResult<LegacyImportReview>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(systemId)}/legacy-imports`);
export const apiCbomReconcileLegacy = (systemId: string, body: {
  expected_snapshot_sha256: string; replacement_document_sha256: string; reason: string;
}): Promise<ApiResult<{ audit_id: string; detached_assets: number; archived_declarations: number }>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(systemId)}/reconcile-legacy`, { method: "POST", body: JSON.stringify(body) });

export interface LegacyOrphanPage {
  total: number; page: number; page_size: number;
  assets: Array<{ id: string; algorithm: string; confidence: string; source_basis: string }>;
}
export interface LegacyOrphanReview {
  asset_id: string; algorithm: string; snapshot_sha256: string; linked_evidence_count: number; unassigned: boolean;
}
export interface LegacyMixedCase {
  payload_sha256: string;
  payload: { state: string; submitted_by: string; reason: string; evidence_ref: string; expected_snapshot_sha256: string };
}
export const apiLegacyOrphans = (page = 1): Promise<ApiResult<LegacyOrphanPage>> =>
  call(`/api/v1/cbom/legacy-imports/unassigned?page=${page}&page_size=50`);
export const apiLegacyOrphanReview = (id: string): Promise<ApiResult<LegacyOrphanReview>> =>
  call(`/api/v1/cbom/legacy-assets/${encodeURIComponent(id)}/review`);
export const apiLegacyAssign = (id: string, body: { expected_snapshot_sha256: string; system_id: string; reason: string; evidence_ref: string }): Promise<ApiResult<{ audit_id: string }>> =>
  call(`/api/v1/cbom/legacy-assets/${encodeURIComponent(id)}/assign`, { method: "POST", body: JSON.stringify(body) });
export const apiLegacyMixedCase = (id: string): Promise<ApiResult<{ case: LegacyMixedCase | null }>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(id)}/mixed-review`);
export const apiLegacyMixedPropose = (id: string, body: { expected_snapshot_sha256: string; replacement_document_sha256: string; reason: string; evidence_ref: string }): Promise<ApiResult<LegacyMixedCase>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(id)}/mixed-review`, { method: "POST", body: JSON.stringify(body) });
export const apiLegacyMixedApprove = (id: string, body: { expected_case_sha256: string; reason: string; evidence_ref: string }): Promise<ApiResult<{ audit_id: string }>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(id)}/mixed-review/approve`, { method: "POST", body: JSON.stringify(body) });

export interface RescanInspection {
  system_id: string; job_id: string; scan_id: string; source_snapshot_sha256: string;
  retained_case_sha256: string; result: string; completed_at: string; inspected_at: string;
  parsed_files: number; unparsed_files: number;
  integrity: { result: string; records: number; content_intact: boolean; chain_intact: boolean; manifest_intact: boolean; hash_format_valid: boolean };
  clears_partial_history: false; bank_approved: false; whole_system_coverage_verified: false; absence_proven: false;
}
export const apiRetainedHistories = (page = 1): Promise<ApiResult<{systems: Array<{id: string; name: string}>; total: number; page: number; page_size: number}>> =>
  call(`/api/v1/cbom/retained-histories?page=${page}&page_size=50`);
export const apiRescanInspection = (systemId: string, jobId: string): Promise<ApiResult<RescanInspection>> =>
  call(`/api/v1/cbom/system/${encodeURIComponent(systemId)}/rescan-inspection?job_id=${encodeURIComponent(jobId)}`);

/** Offline host metadata is imported evidence, not authenticated host observation. */
export type HostImportReceipt = {
  approval_id: string; scan_id: string; system_id: string; snapshot_sha256: string;
  evidence_count: number; source_basis: "IMPORTED"; runtime_use: "UNKNOWN";
  policy_result: "NOT_EVALUATED"; pqc_assessment: "UNKNOWN";
  whole_host_coverage_verified: false; host_identity_attested: false;
};
export interface HostMetadataFact {
  kind: string; algorithm: string; key_size: number | null; local_basis: string;
  runtime_use: string; software_name: string | null; software_version: string | null;
  purpose?: string; operation_use?: string; policy_result?: string; pqc_assessment?: string;
  interface?: string; interface_sha256?: string | null; identity_key?: string;
  capture_basis?: string; capabilities_observed?: boolean;
  address?: string | null; address_family?: string; port?: number | null;
  sni?: string; tls_version?: string; cipher_suite?: string; cipher_bits?: number;
  reviewed_target_sha256?: string; authorized_operation?: string;
  negotiated_session_observed?: boolean; peer_fingerprint_matched?: boolean;
  certificate_chain_validated?: boolean; hostname_validated?: boolean;
  revocation_checked?: boolean; all_tls_versions_tested?: boolean;
  application_data_sent?: boolean; application_identity_verified?: boolean;
  peer_der_bytes?: number; wire_bytes_sent?: number; wire_bytes_received?: number;
  key_exchange_group?: string; server_signature_scheme?: string;
  certificate?: { algorithm: string; certificate_signature_oid: string; curve: string;
    fingerprint_sha256: string; key_size: number | null; signature_hash: string };
  selected_group_id?: number; group_classification?: string; group_classification_basis?: string;
  server_hello_hex?: string; server_hello_sha256?: string;
  hello_retry_request_seen?: boolean; pqc_implementation_verified?: boolean;
  pqc_readiness_verified?: boolean; all_groups_tested?: boolean;
  hybrid_session_completed?: boolean; tls_provider?: string; openssl_version?: string;
  pyopenssl_version?: string; cryptography_version?: string; provider_identity_basis?: string;
  listener_count?: number; listeners?: { address: string; port: number; scope_id: number; owning_pid: number }[];
  process_identity_verified?: boolean; tls_observed?: boolean; asset_absence_proven?: boolean;
  layout_sha256?: string; index_sha256?: string; manifest_sha256?: string; manifest_size?: number;
  config_sha256?: string; config_size?: number; image_os?: string; image_architecture?: string;
  image_variant?: string | null; layers?: { diff_id: string; digest: string; media_type: string; size: number }[];
  declared_ports?: string[]; declared_base_digest?: string | null; configuration_basis?: string;
  layer_contents_verified?: boolean; filesystem_materialized?: boolean;
  package_inventory_verified?: boolean; deployment_verified?: boolean; vendor_identity_verified?: boolean;
  image?: HostMetadataFact; final_filesystem_view_verified?: boolean; rootfs_view_sha256?: string;
  packages?: { manager: string; name: string; version: string | null; basis: string;
    source_path: string; source_sha256: string; layer_index: number }[];
  databases?: { manager: string; path: string; status: string; sha256: string | null; layer_index: number | null }[];
  complete_inventory_verified?: boolean; unsupported_package_surfaces?: string;
  runtime?: string; container_id?: string; image_manifest_sha256?: string;
  image_binding_basis?: string; runtime_image_verified?: boolean; process_observed?: boolean;
  process?: HostMetadataFact; source_sha256?: string; cgroup_sha256?: string;
  pid?: number | null; process_start_ticks?: number; boot_id?: string;
  process_name?: string | null; library_path?: string | null; service_name?: string | null;
  service_state?: string | null; hardware_type?: string | null; manufacturer?: string | null;
  model?: string | null; tpm_major_version?: number | null;
  provider_context?: string; provider_type?: number; provider_name?: string;
  api_structure_version?: number; tpm_specification?: string;
  registration_mode?: string; registration_interface?: string; registration_flags?: number;
  registered_functions?: string[]; creation_filetime?: string; image_path?: string;
}
export type HostSnapshotInspection = HostImportReceipt & {
  integrity: { result: string; content_intact: boolean; chain_intact: boolean; manifest_intact: boolean; hash_format_valid: boolean };
  snapshot: { manifest: { host_id: string; environment: string }; finished_at: string;
    receipts: { input_id: string; status: string; reason: string; facts: HostMetadataFact[] }[] };
};
export const apiApproveHostScope = (systemId: string, manifest: unknown) =>
  _rsPost<{ subject_id: string; payload_sha256: string }>("/api/v1/host-evidence/approvals", { system_id: systemId, manifest });
export const apiImportHostSnapshot = (approvalId: string, snapshot: unknown) =>
  _rsPost<HostImportReceipt>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/intake`, { snapshot });
export const apiInspectHostSnapshot = (approvalId: string) =>
  _rsGet<HostSnapshotInspection>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/snapshot`);
export const apiHostCbom = (approvalId: string) =>
  _rsGet<Record<string, unknown>>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/cbom`);
export const apiHostOciSbom = (approvalId: string) =>
  _rsGet<Record<string, unknown>>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/oci-image/cyclonedx-1.6`);
export const apiHostContainerSbom = (approvalId: string) =>
  _rsGet<Record<string, unknown>>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/container/cyclonedx-1.6`);
export const apiHostTlsSessionBom = (approvalId: string) =>
  _rsGet<Record<string, unknown>>(`/api/v1/host-evidence/approvals/${encodeURIComponent(approvalId)}/tls-session/cyclonedx-1.6`);

/** Reviewed metadata associations, never CycloneDX operational dependencies. */
export type HostAssociationTargetType = "sbom_binding" | "phase_receipt" | "hardware" | "vendor" | "deployment";
export type HostAssociationTarget = { target_type: HostAssociationTargetType; target_id: string; target_sha256: string; bom: string; evidence_status: "DECLARED"; runtime_use: "UNKNOWN" };
export type HostAssociation = { id: string; revision: number; state: "PROPOSED" | "REVIEWED" | "RETRACTED" | "STALE"; reason: string | null; target_type: HostAssociationTargetType; target_id: string; package_identity: string | null; bom: string; input_id: string; fact_ordinal: number; evidence_status: "DECLARED"; proposal_reason: string; evidence_ref: string; expires_at: string; proposed_by: string; reviewed_by: string | null; decision_reason: string | null; payload_sha256: string };
export type HostEstateGraph = { schema_version: "cryptoscan.host-estate-graph/v1"; approval_id: string; system_id: string; snapshot_sha256: string; graph_sha256: string; evaluated_at: string;
  whole_host_coverage_verified: false; host_identity_attested: false; operational_dependency_verified: false; pqc_use: "UNKNOWN";
  nodes: { id: string; bom: string; kind: string; evidence_status: "DECLARED" | "IMPORTED" }[];
  edges: { from: string; to: string; predicate: string; evidence_status: "DECLARED" | "IMPORTED"; runtime_use: "UNKNOWN"; operational_dependency_verified: false; provenance: Record<string, unknown> }[];
  associations: HostAssociation[]; domains: Record<string, { represented: boolean; operational_use: "UNKNOWN" }> };
const hostGraphPath = (approval: string) => `/api/v1/host-evidence/approvals/${encodeURIComponent(approval)}`;
export const apiHostAssociationTarget = (approval: string, type: HostAssociationTargetType, id: string, purl?: string) => {
  const params = new URLSearchParams({ target_type: type, target_id: id }); if (purl) params.set("package_identity", purl);
  return _rsGet<HostAssociationTarget>(`${hostGraphPath(approval)}/association-target?${params}`);
};
export const apiProposeHostAssociation = (approval: string, body: { input_id: string; fact_ordinal: number; target_type: HostAssociationTargetType; target_id: string; package_identity: string | null; expected_target_sha256: string; expires_at: string; evidence_ref: string; reason: string }) =>
  _rsPost<{ subject_id: string; revision: number }>(`${hostGraphPath(approval)}/associations`, body);
export const apiDecideHostAssociation = (approval: string, id: string, action: "review" | "retract", revision: number, evidenceRef: string, reason: string) =>
  _rsPost<{ subject_id: string; revision: number }>(`${hostGraphPath(approval)}/associations/${encodeURIComponent(id)}/${action}`, { expected_revision: revision, evidence_ref: evidenceRef, reason });
export const apiHostEstateGraph = (approval: string) => _rsGet<HostEstateGraph>(`${hostGraphPath(approval)}/graph`);

/* ── Digital Twin (spec 94) ────────────────────────────────────────────────
   The twin is the correlated model the six BOMs are projected from. These calls
   read the latest stored snapshot: placement, completeness, one asset's
   investigation, search, blast radius, and simulation.

   Two contract details the UI must respect:
   * `completeness` measures how completely the estate is DESCRIBED — never
     crypto readiness — and an unmeasured dimension arrives with percent: null;
   * `impact`/`simulate` answer NO_MATCH rather than an empty result, because
     "nothing matched" and "nothing is affected" are different claims. */

export interface EstateTwinDimension {
  dimension: string; numerator: number; denominator: number;
  percent: number | null; state: string; meaning: string; reason?: string | null;
}

export interface EstateTwinCompleteness {
  schema: string; projection_id: string;
  dimensions: EstateTwinDimension[];
  visibility: EstateTwinDimension[];
  measured: number;
  unmeasured: Array<{ dimension: string; state: string; reason?: string | null }>;
  overall_percent: number | null; overall_state: string; overall_label: string;
  weakest_dimension?: { dimension: string; percent: number | null; reason: string } | null;
  overall_note?: string;
  is_posture_score: boolean; meaning: string;
  why_not_100: Array<{ reason: string; count: number; next_action: string }>;
}

export interface EstateTwinPlacement {
  environments: Array<{
    name: string; assets: number; by_type: Record<string, number>;
    business_systems: string[]; locations: Array<{ name: string; assets: number }>;
  }>;
  unplaced_count: number;
  business_systems: string[];
}

export interface EstateTwinOverview {
  model: string; projection_id: string; estate: string | null;
  summary: Record<string, unknown>;
  placement: EstateTwinPlacement;
  completeness: EstateTwinCompleteness;
  note: string;
}

export interface EstateTwinSearchResult {
  query: string; status: string;
  assets: Array<{ asset_id: string; name: string; type: string; environment?: string | null; owner?: string | null }>;
  artifacts: Array<Record<string, unknown>>;
  by_asset_type: Record<string, number>;
  by_usage_state: Record<string, number>;
  counts: { assets: number; artifacts: number };
  truncated: boolean;
  note: string;
}

export interface EstateTwinImpact {
  status: string; selector: Record<string, unknown>; detail?: string;
  counts?: { seed?: number; direct?: number; transitive?: number; total?: number; business_systems?: number };
  by_type?: Record<string, number>;
  direct?: Array<Record<string, unknown>>;
  transitive?: Array<Record<string, unknown>>;
  paths?: Array<{ asset_id: string; path: Array<{ asset_id: string; name: string; type: string; via: unknown }> }>;
  blockers?: Array<Record<string, unknown>>;
  unknown?: Record<string, unknown>;
  note?: string;
}

export interface EstateTwinSimulation {
  status: string; kind?: string; detail?: string;
  simulation_id?: string; base_projection_id?: string; simulated_projection_id?: string;
  live_state_modified?: boolean; live_projection_unchanged?: boolean;
  matched_evidence?: number;
  affected_assets?: Array<{ asset_id: string; name: string; type: string }>;
  impact?: { counts?: Record<string, number>; by_type?: Record<string, number> };
  bom_diff?: Record<string, { counts: Record<string, number> }>;
  bom_changes?: boolean;
  blockers?: Array<Record<string, unknown>>;
  unknown?: Record<string, unknown>;
  note?: string;
}

/* The twin's chain, link by link: Estate → Assets → Relationships → Crypto graph →
   Evidence graph → History → Impact → Simulation. Each stage is computed by the
   server from the stored snapshot; the console prints the status it was given and
   never infers one. A stage the server could not read arrives as NOT_EVALUATED
   with its reason — it is not rendered as empty. */
export type TwinChainStatus = "POPULATED" | "EMPTY" | "NOT_EVALUATED" | "AWAITING_INPUT";

export interface TwinChainStage {
  index: number;
  stage: string;
  label: string;
  question: string;
  status: TwinChainStatus;
  status_meaning: string;
  detail: Record<string, unknown>;
  reason: string | null;
  endpoint: string;
}

export interface EstateTwinChain {
  run_id?: string;
  schema: string;
  estate: string;
  projection_id: string;
  stages: TwinChainStage[];
  order: string[];
  status_meaning: Record<string, string>;
  first_incomplete_stage: string | null;
  claim: string;
  note: string;
}

export const apiEstateTwinChain = (): Promise<ApiResult<EstateTwinChain>> =>
  _rsGet<EstateTwinChain>("/api/v1/estate/evidence/twin/chain");

export const apiEstateTwin = (): Promise<ApiResult<EstateTwinOverview>> =>
  _rsGet<EstateTwinOverview>("/api/v1/estate/evidence/twin");

export interface EstateTwinAssetView {
  asset: { asset_id: string; name: string; type: string; environment?: string | null; owner?: string | null; location?: string | null };
  placement: { environment?: string | null; location?: string | null; owner?: string | null; placed: boolean };
  attributes: Record<string, unknown>;
  crypto: {
    artifacts: Array<Record<string, unknown>>;
    by_usage_state: Record<string, number>;
    observed: Array<Record<string, unknown>>;
    capability_only: Array<Record<string, unknown>>;
    note: string;
  };
  relationships: {
    /* `direction` says which side of this asset the edge leaves from: an incoming
       edge's subject is the other asset, which is what an edge-first "why" needs. */
    outgoing: Array<{ predicate: string; asset_id: string; name?: string; type?: string; basis?: string; confidence?: string; direction?: "in" | "out"; evidence_ids?: string[] }>;
    incoming: Array<{ predicate: string; asset_id: string; name?: string; type?: string; basis?: string; confidence?: string; direction?: "in" | "out"; evidence_ids?: string[] }>;
    dependencies: Array<{ predicate: string; name?: string; type?: string; basis?: string }>;
    count: number;
  };
  evidence: {
    count: number; by_type: Record<string, number>; strongest: string;
    records: Array<{ evidence_id: string; evidence_type: string; collector?: string | null; source?: string | null; observed_at?: string | null; confidence?: string; hash: string; facts: Record<string, unknown> }>;
  };
  unknown: {
    unresolved_relationships: Array<Record<string, unknown>>;
    conflicts: Array<Record<string, unknown>>;
    no_evidence: boolean;
  };
  neighbourhood: { depth: number; reached: number; assets: Array<{ asset_id: string; name?: string; type?: string; hops: number }>; truncated: boolean };
}

export const apiEstateTwinAsset = (ref: string): Promise<ApiResult<EstateTwinAssetView>> =>
  _rsGet<EstateTwinAssetView>(`/api/v1/estate/evidence/twin/assets/${encodeURIComponent(ref)}`);

export const apiEstateTwinSearch = (q: string): Promise<ApiResult<EstateTwinSearchResult>> =>
  _rsGet<EstateTwinSearchResult>(`/api/v1/estate/evidence/twin/search?q=${encodeURIComponent(q)}`);

/* §28 "why" — the answer to "why does CryptoScan believe this relationship
   exists", or the reason the edge was refused. The refusal is the interesting
   case: an UNKNOWN edge is the absence of a relationship, not a weak one. */
export interface EstateTwinWhyEdge {
  edge: { subject: string; subject_name?: string | null; predicate: string; object: string;
    object_name?: string | null; basis?: string | null; confidence?: string | null };
  answer: string;
  evidence: Array<{ evidence_id: string; evidence_type: string; collector?: string | null;
    source?: string | null; observed_at?: string | null; confidence?: string | null; hash: string }>;
}

export interface EstateTwinWhy {
  schema: string;
  status: "ESTABLISHED" | "ASSERTED_UNCITED" | "NOT_ESTABLISHED" | "NO_SUCH_RELATIONSHIP" | "UNKNOWN_ASSET"
    | "EVIDENCE" | "NO_SUCH_EVIDENCE";
  matches?: EstateTwinWhyEdge[];
  refused?: Array<{ subject?: string; predicate?: string; object?: string; reason?: string }>;
  answer?: string;
  detail?: string;
  note?: string;
}

export const apiEstateTwinWhy = (query: {
  subject?: string; predicate?: string; object?: string; evidence_id?: string;
}): Promise<ApiResult<EstateTwinWhy>> => {
  const params = new URLSearchParams();
  if (query.subject) params.set("subject", query.subject);
  if (query.predicate) params.set("predicate", query.predicate);
  if (query.object) params.set("object", query.object);
  if (query.evidence_id) params.set("evidence_id", query.evidence_id);
  return _rsGet<EstateTwinWhy>(`/api/v1/estate/evidence/twin/why?${params.toString()}`);
};

export const apiEstateTwinImpact = (selector: Record<string, unknown>): Promise<ApiResult<EstateTwinImpact>> =>
  _rsPost<EstateTwinImpact>("/api/v1/estate/evidence/twin/impact", selector);

export const apiEstateTwinSimulate = (scenario: Record<string, unknown>): Promise<ApiResult<EstateTwinSimulation>> =>
  _rsPost<EstateTwinSimulation>("/api/v1/estate/evidence/twin/simulate", scenario);

/* ── Collection: targets, jobs, worker control ─────────────────────────────
   The collection surface was API-only: an operator could not see which targets
   are authorised, which jobs exist, or what a job's coverage and errors are.
   These calls are reads plus two reversible operations (enqueue / cancel); target
   registration stays an API/CLI flow because a target is an authorisation
   document, not a form field.

   Honesty rule carried from the backend: an empty list is "nothing registered",
   never "no crypto in the estate", and a collector that is not qualified for
   production stands as such instead of reading like an available one. */

export interface CollectionCollector {
  id: string; method: string; state: string;
  production_execution_qualified: boolean; server_execution: boolean;
  capabilities: Record<string, string>;
}

export interface CollectionTarget {
  id: string; kind?: string; revision?: number; created_at?: string;
  [key: string]: unknown;
}

export interface CollectionJob {
  id: string; kind?: string; revision?: number; state?: string;
  created_at?: string; [key: string]: unknown;
}

export interface CollectionJobEvidence {
  coverage?: Record<string, unknown>; errors?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export const apiCollectionCollectors = (): Promise<ApiResult<{ collectors: CollectionCollector[] }>> =>
  _rsGet<{ collectors: CollectionCollector[] }>("/api/v1/collection/collectors");

export const apiCollectionTargets = (): Promise<ApiResult<{ items: CollectionTarget[]; has_more: boolean }>> =>
  _rsGet<{ items: CollectionTarget[]; has_more: boolean }>("/api/v1/collection/targets");

export const apiCollectionTargetHistory = (id: string): Promise<ApiResult<{ history: CollectionTarget[] }>> =>
  _rsGet<{ history: CollectionTarget[] }>(`/api/v1/collection/targets/${encodeURIComponent(id)}`);

export const apiCollectionAuthorize = (id: string, expected_revision: number, body?: Record<string, unknown>): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost<Record<string, unknown>>(`/api/v1/collection/targets/${encodeURIComponent(id)}/authorize`, {
    expected_revision, ...(body ?? {}),
  });

export const apiCollectionRevoke = (id: string, expected_revision: number, reason: string): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost<Record<string, unknown>>(`/api/v1/collection/targets/${encodeURIComponent(id)}/revoke`, {
    expected_revision, reason,
  });

export const apiCollectionJobs = (): Promise<ApiResult<{ items: CollectionJob[]; has_more: boolean }>> =>
  _rsGet<{ items: CollectionJob[]; has_more: boolean }>("/api/v1/collection/jobs");

export const apiCollectionJob = (id: string): Promise<ApiResult<CollectionJob>> =>
  _rsGet<CollectionJob>(`/api/v1/collection/jobs/${encodeURIComponent(id)}`);

export const apiCollectionJobCoverage = (id: string): Promise<ApiResult<Record<string, unknown>>> =>
  _rsGet<Record<string, unknown>>(`/api/v1/collection/jobs/${encodeURIComponent(id)}/coverage`);

export const apiCollectionJobErrors = (id: string): Promise<ApiResult<{ errors: Array<Record<string, unknown>>; asset_absence_proven: boolean }>> =>
  _rsGet<{ errors: Array<Record<string, unknown>>; asset_absence_proven: boolean }>(
    `/api/v1/collection/jobs/${encodeURIComponent(id)}/errors`,
  );

export const apiCollectionJobEvidence = (id: string): Promise<ApiResult<CollectionJobEvidence>> =>
  _rsGet<CollectionJobEvidence>(`/api/v1/collection/jobs/${encodeURIComponent(id)}/evidence`);

export const apiCollectionJobProjections = (id: string): Promise<ApiResult<Record<string, unknown>>> =>
  _rsGet<Record<string, unknown>>(`/api/v1/collection/jobs/${encodeURIComponent(id)}/projections`);

export const apiCollectionEnqueue = (id: string, expected_revision: number): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost<Record<string, unknown>>(`/api/v1/collection/jobs/${encodeURIComponent(id)}/enqueue`, { expected_revision });

export const apiCollectionCancel = (id: string, expected_revision: number): Promise<ApiResult<Record<string, unknown>>> =>
  _rsPost<Record<string, unknown>>(`/api/v1/collection/jobs/${encodeURIComponent(id)}/cancel`, { expected_revision });

/* ── Digital Twin: history, compare, crypto graph, graph export ────────────
   `compare` is not a BOM diff: its verdict is worst-first, so COVERAGE_DEGRADED
   outranks CRYPTO_CHANGED — once a plane stopped collecting, everything below it
   is unreliable. The crypto graph keeps capability, configuration, runtime and
   wire facts on separate planes because merging them is the CBOM bug. */

export interface EstateTwinSnapshotSummary {
  id: string; snapshot_id: string; projection_id: string;
  estate: string | null; scope: string | null;
  assets: number; evidence: number; relationships: number; unresolved_relationships: number;
  completeness_percent: number | null; observations: number;
  first_seen_at: string | null; last_seen_at: string | null;
  /* §19: which build of the rules read this evidence, and which collector builds made it */
  policy_version?: string | null; collector_versions?: string[];
  captured_by: string | null; note: string | null; source_run_id?: string | null;
}

export interface EstateTwinSnapshotList {
  model: string; persisted: boolean; snapshots: EstateTwinSnapshotSummary[]; count: number; note: string;
}

export interface EstateTwinCompare {
  schema: string; verdict: string; reason: string;
  before_snapshot?: EstateTwinSnapshotSummary;
  after_snapshot?: EstateTwinSnapshotSummary;
  before?: Record<string, unknown>; after?: Record<string, unknown>;
  sameness?: boolean;
  assets?: {
    added: Array<Record<string, unknown>>; removed: Array<Record<string, unknown>>;
    changed: Array<{ name?: string; changed_fields: string[]; before: Record<string, unknown>; after: Record<string, unknown> }>;
    counts: Record<string, number>;
  };
  relationships?: { established: Array<Record<string, unknown>>; lost: Array<Record<string, unknown>>; counts: Record<string, number> };
  crypto?: { added: Array<Record<string, unknown>>; removed: Array<Record<string, unknown>>; promoted: Array<Record<string, unknown>>; demoted: Array<Record<string, unknown>>; counts: Record<string, number>; note: string };
  coverage?: { degraded: Array<Record<string, unknown>>; improved: Array<Record<string, unknown>>; counts: Record<string, number> };
  evidence?: Record<string, unknown>;
  unknown?: Record<string, number>;
  note?: string;
}

export interface EstateTwinCryptoPlaneItem {
  label: string; algorithm?: string | null; protocol?: string | null; key_size?: number | null;
  layer: string; usage_state: string; evidence_type: string; confidence: string;
  asset_id: string; asset_name?: string | null; asset_type?: string | null;
}

export interface EstateTwinCryptoGraph {
  schema: string; projection_id: string;
  planes: Record<string, EstateTwinCryptoPlaneItem[]>;
  plane_meanings: Record<string, string>;
  counts: Record<string, number>;
  nodes: Array<{ node_id: string; kind: string; name?: string | null; type?: string | null; planes: Record<string, string[]> }>;
  edges: Array<{ from: string; to: string; predicate: string; plane: string; layer: string; evidence_ids: string[] }>;
  coexistence: Array<{ asset_name?: string | null; capability: string[]; in_use: string[]; supported_but_not_observed: string[]; explanation: string }>;
  conflicts: Array<Record<string, unknown>>;
  explained_disagreements: Array<Record<string, unknown>>;
  conflict_counts: { real: number; explained: number };
  note: string;
}

export interface EstateTwinGraphExport {
  schema: string; projection_id: string; generated_at: string;
  counts: Record<string, number>;
  nodes: Array<{ id: string; labels: string[]; properties: Record<string, unknown> }>;
  relationships: Array<{ type: string; from: string; to: string; properties: Record<string, unknown> }>;
  unresolved: Array<Record<string, unknown>>;
  load_notes: Record<string, unknown>;
  /* the specification's 22 graph labels, each mapped to the label(s) this build
     emits — served with every export so "the projection covers the spec" is read,
     not taken on trust */
  label_coverage?: Record<string, string[]>;
  /* Bounded export (the bank rule: never load the estate whole): counts of
     what the server left out and the frontier of nodes to expand into next. */
  bounded?: boolean;
  omitted_nodes?: number;
  omitted_edges?: number;
  frontier?: string[];
}

export const apiEstateTwinSnapshots = (): Promise<ApiResult<EstateTwinSnapshotList>> =>
  _rsGet<EstateTwinSnapshotList>("/api/v1/estate/evidence/twin/snapshots");

export const apiEstateTwinCapture = (note?: string): Promise<ApiResult<{ created: boolean; snapshot: EstateTwinSnapshotSummary; note: string }>> =>
  _rsPost<{ created: boolean; snapshot: EstateTwinSnapshotSummary; note: string }>(
    "/api/v1/estate/evidence/twin/snapshots", { note: note ?? null },
  );

export const apiEstateTwinCompare = (before?: string, after?: string): Promise<ApiResult<EstateTwinCompare>> => {
  const query = [before ? `before=${encodeURIComponent(before)}` : "", after ? `after=${encodeURIComponent(after)}` : ""]
    .filter(Boolean).join("&");
  return _rsGet<EstateTwinCompare>(`/api/v1/estate/evidence/twin/compare${query ? `?${query}` : ""}`);
};

export const apiEstateTwinCryptoGraph = (): Promise<ApiResult<EstateTwinCryptoGraph>> =>
  _rsGet<EstateTwinCryptoGraph>("/api/v1/estate/evidence/twin/crypto-graph");

export const apiEstateTwinGraph = (bounds?: {
  seed?: string;
  depth?: number;
  limit?: number;
}): Promise<ApiResult<EstateTwinGraphExport>> => {
  const params = new URLSearchParams();
  if (bounds?.seed) params.set("seed", bounds.seed);
  if (bounds?.depth !== undefined) params.set("depth", String(bounds.depth));
  if (bounds?.limit !== undefined) params.set("limit", String(bounds.limit));
  const qs = params.toString();
  return _rsGet<EstateTwinGraphExport>(
    `/api/v1/estate/evidence/twin/graph${qs ? `?${qs}` : ""}`);
};

/* A graph-store load is a side effect on a bank's graph, so the panel can only
   ever ask for the *plan*: the request is sent with dry_run pinned to true, and the
   response is the statements and counts that *would* run. Writing is a deliberate
   CLI/API action (`cryptoscan twin graph-load --apply`), not a click.

   The simulation list is the opposite case: it is a read of stored answers, and
   every one of them says `is_estate_state: false` on the row, so a screenshot of
   this list cannot be mistaken for a record of the estate. */
export interface EstateTwinGraphLoad {
  schema: string; projection_id: string; estate?: string | null;
  dry_run: boolean; statements: number;
  expected: { nodes: number; relationships: number; unresolved: number; projection_id: string; estate?: string | null };
  written: Record<string, number>;
  verification: "DRY_RUN" | "NOT_CONNECTED" | "VERIFIED" | "MISMATCH" | "NOT_RUN";
  ok?: boolean; error?: string | null; source_of_truth: string; note?: string;
}

export interface EstateTwinSimulationRecord {
  id?: number; simulation_id: string; kind: string;
  scenario: Record<string, unknown>;
  label?: string | null; base_projection_id?: string | null;
  computed_against?: string | null; superseded_by?: string | null;
  superseded: boolean; freshness: string;
  matched_evidence: number; affected_assets: string[];
  impact: Record<string, unknown>; blockers: Array<Record<string, unknown>>;
  live_state_modified: boolean; observations: number;
  first_run_at?: string | null; last_run_at?: string | null;
  quarantined: boolean; is_estate_state: false;
}

export interface EstateTwinSimulationList {
  model: string; count: number; quarantined: boolean; is_estate_state: false;
  counting_rule: string; note: string; simulations: EstateTwinSimulationRecord[];
}

export const apiEstateTwinGraphLoadPlan = (): Promise<ApiResult<EstateTwinGraphLoad>> =>
  _rsPost<EstateTwinGraphLoad>("/api/v1/estate/evidence/twin/graph/load", { dry_run: true });

export const apiEstateTwinSimulations = (): Promise<ApiResult<EstateTwinSimulationList>> =>
  _rsGet<EstateTwinSimulationList>("/api/v1/estate/evidence/twin/simulations");

/* Live change detection, as a feed of what moved.

   The distinction the type carries is the one that matters operationally: an event
   is a set of named claims derived from two observations of the estate (`before` →
   `after`, with `means` saying what the movement does *not* prove). Nothing here can
   be a simulation — what-if runs live in `/twin/simulations` and are quarantined. */
export interface EstateChange {
  kind: string; severity: "CRITICAL" | "WARNING" | "INFO";
  subject: string; before: unknown; after: unknown;
  detail: string; means?: string | null; evidence_ids: string[];
}

export interface EstateChangeEvent {
  schema: string; event_id: string;
  verdict: string; severity: "CRITICAL" | "WARNING" | "INFO" | "BASELINE" | "NONE";
  severity_meaning?: string | null; changed: boolean | null;
  headline: string; reason?: string | null; next_action?: string | null;
  changes: EstateChange[]; counts: Record<string, number>;
  baseline_projection_id?: string | null; current_projection_id?: string | null;
  run_id?: string | null; trigger: string; detected_by?: string | null;
  observations: number; first_detected_at?: string | null; last_detected_at?: string | null;
  acknowledged: boolean; acknowledged_at?: string | null; acknowledged_by?: string | null;
  acknowledgement_note?: string | null; is_estate_state: true; note: string;
}

export interface EstateChangeFeed {
  schema: string; count: number; unacknowledged: number; filtered?: boolean;
  by_severity: Record<string, number>; by_kind: Record<string, number>;
  events: EstateChangeEvent[]; meaning: string; limits: string[];
}

export const apiEstateChanges = (params?: { severity?: string; kind?: string; unacknowledgedOnly?: boolean }):
Promise<ApiResult<EstateChangeFeed>> => {
  const query = [
    params?.severity ? `severity=${encodeURIComponent(params.severity)}` : "",
    params?.kind ? `kind=${encodeURIComponent(params.kind)}` : "",
    params?.unacknowledgedOnly ? "unacknowledged_only=true" : "",
  ].filter(Boolean).join("&");
  return _rsGet<EstateChangeFeed>(`/api/v1/estate/evidence/changes${query ? `?${query}` : ""}`);
};

export const apiEstateChangesDetect = (): Promise<ApiResult<EstateChangeEvent & { stored: Record<string, unknown> }>> =>
  _rsPost<EstateChangeEvent & { stored: Record<string, unknown> }>("/api/v1/estate/evidence/changes/detect", {});

export const apiEstateChangeAcknowledge = (eventId: string, note?: string):
Promise<ApiResult<EstateChangeEvent>> =>
  _rsPost<EstateChangeEvent>(
    `/api/v1/estate/evidence/changes/${encodeURIComponent(eventId)}/acknowledge`,
    { note: note ?? null },
  );

/* The durable catalogue — the twin's memory across observations.

   `lifecycle_state` is the load-bearing field: STALE means "observed before, absent
   from the latest observation", which is not the same as decommissioned and is
   certainly not the same as never having existed. The UI must show it rather than
   filter it away. */
export interface EstateCatalogAsset {
  asset_id: string; asset_type: string; name: string;
  environment?: string | null; owner?: string | null; location?: string | null;
  source?: string | null; identity: Record<string, unknown>; attributes: Record<string, unknown>;
  evidence_ids: string[]; evidence_count: number;
  lifecycle_state: "ACTIVE" | "STALE";
  first_seen_at?: string | null; last_seen_at?: string | null;
  observation_count: number; is_estate_state: true;
}

export interface EstateCatalogRelationship {
  relationship_id: string; subject_id: string; subject_name?: string | null;
  predicate: string; object_id: string; object_name?: string | null;
  basis?: string | null; confidence?: string | null;
  /* §8: what kind of evidence established the edge, and when it was observed */
  evidence_type?: string | null; observed_at?: string | null;
  status: "ESTABLISHED" | "UNRESOLVED"; reason?: string | null;
  evidence_ids: string[]; lifecycle_state: "ACTIVE" | "STALE";
  observation_count: number; note: string;
}

export interface EstateCatalogCryptoRow {
  artifact_id: string; asset_id: string; asset_name?: string | null; asset_type?: string | null;
  algorithm?: string | null; protocol?: string | null; curve?: string | null;
  key_size?: number | null; mode?: string | null; role?: string | null; layer?: string | null;
  usage_state: string; evidence_type?: string | null; confidence?: string | null;
  evidence_ids: string[]; source?: string | null;
  lifecycle_state: "ACTIVE" | "STALE"; observation_count: number; note?: string | null;
}

export interface EstateCatalogDetail {
  schema: string; asset: EstateCatalogAsset; crypto: EstateCatalogCryptoRow[];
  crypto_by_usage_state: Record<string, number>;
  relationships: EstateCatalogRelationship[];
  unresolved_candidates: EstateCatalogRelationship[];
  counts: { crypto: number; relationships: number; unresolved: number; evidence: number };
  note: string;
}

export interface EstateCatalogSummary {
  schema: string; assets: number;
  assets_by_type: Record<string, number>; assets_by_lifecycle: Record<string, number>;
  note: string;
}

export interface EstateCryptoRegistry {
  schema: string; query?: string | null; algorithm_count: number; record_count: number;
  algorithms: Array<{
    algorithm: string; asset_count: number; evidence: number; stale: number;
    usage_states: Record<string, number>; asset_types: Record<string, number>;
    assets: Array<{ asset_id: string; asset_name?: string | null; asset_type?: string | null;
      usage_state: string; layer?: string | null; lifecycle_state: string; evidence_ids: string[] }>;
  }>;
  meaning: string; limits: string[];
}

export const apiEstateCatalog = (): Promise<ApiResult<EstateCatalogSummary>> =>
  _rsGet<EstateCatalogSummary>("/api/v1/estate/evidence/catalog");

export const apiEstateCatalogAssets = (params?: { assetType?: string; lifecycle?: string; q?: string }):
Promise<ApiResult<{ count: number; assets: EstateCatalogAsset[]; note: string }>> => {
  const query = [
    params?.assetType ? `asset_type=${encodeURIComponent(params.assetType)}` : "",
    params?.lifecycle ? `lifecycle=${encodeURIComponent(params.lifecycle)}` : "",
    params?.q ? `q=${encodeURIComponent(params.q)}` : "",
  ].filter(Boolean).join("&");
  return _rsGet<{ count: number; assets: EstateCatalogAsset[]; note: string }>(
    `/api/v1/estate/evidence/catalog/assets${query ? `?${query}` : ""}`,
  );
};

export const apiEstateCatalogAsset = (identifier: string): Promise<ApiResult<EstateCatalogDetail>> =>
  _rsGet<EstateCatalogDetail>(`/api/v1/estate/evidence/catalog/assets/${encodeURIComponent(identifier)}`);

export const apiEstateCryptoRegistry = (q?: string): Promise<ApiResult<EstateCryptoRegistry>> =>
  _rsGet<EstateCryptoRegistry>(
    `/api/v1/estate/evidence/catalog/crypto${q ? `?q=${encodeURIComponent(q)}` : ""}`,
  );

/* §4 placement. The upper levels are present only where a collector asserted them;
   `unassigned` says how many assets no evidence places at a level, so "we do not
   know the region" is visible instead of being drawn as an empty box. */
export interface EstatePlacementLevelRow { name: string; assets: number }

export interface EstatePlacement {
  schema: string; model: string; levels: string[];
  levels_observed: string[]; levels_unobserved: string[];
  bank: string | null;
  /* the organisation chart above the infrastructure: an entity owns departments,
     a department owns assets. Absent on older payloads, so readers guard. */
  organizations?: Array<{ name: string; assets: number; by_type: Record<string, number>;
    departments: EstatePlacementLevelRow[]; environments: EstatePlacementLevelRow[] }>;
  departments?: Array<{ name: string; organization?: string | null; assets: number;
    by_type: Record<string, number>; owners: EstatePlacementLevelRow[];
    environments: EstatePlacementLevelRow[] }>;
  environments: Array<{ name: string; assets: number; by_type: Record<string, number>;
    business_systems: string[]; locations: Array<{ name: string; assets: number }> }>;
  regions: Array<{ name: string; assets: number; by_type: Record<string, number>;
    environments: EstatePlacementLevelRow[] }>;
  data_centers: Array<{ name: string; assets: number; regions: EstatePlacementLevelRow[];
    environments: EstatePlacementLevelRow[] }>;
  cloud_environments: Array<{ name: string; provider?: string | null; account?: string | null;
    assets: number; by_type: Record<string, number>; regions: EstatePlacementLevelRow[] }>;
  unassigned: Array<{ level: string; assets: number; reason: string }>;
  business_systems: string[];
  unplaced: Array<Record<string, unknown>>; unplaced_count: number; placeable: number;
  note: string;
}

export const apiEstateTwinPlacement = (): Promise<ApiResult<EstatePlacement>> =>
  _rsGet<EstatePlacement>("/api/v1/estate/evidence/twin/placement");

/* §19/§28: what a fact said over time. A fact is a value with a window — a change
   retires the previous value instead of overwriting it, and two values still asserted
   are a CONFLICT the console shows rather than a choice it makes. */
export interface EstateFactWindow {
  observation_id: string; value: string | null; value_kind: string | null;
  state: "CURRENT" | "HISTORICAL"; evidence_id: string | null;
  evidence_type: string | null; layer: string | null;
  first_seen_at: string | null; last_seen_at: string | null; observation_count: number;
}

export interface EstateFactHistory {
  fact_type: string; provenance: string; state: "CURRENT" | "HISTORICAL" | "CONFLICT";
  current_values: string[]; timeline: EstateFactWindow[];
}

export interface EstateAssetHistory {
  schema: string; asset_id: string; fact_count: number; fact_types: string[];
  conflicted_facts: string[]; facts: EstateFactHistory[]; meaning: string;
}

export interface EstateHistorySummary {
  schema: string;
  evidence: { total: number; active: number; stale: number; collectors: string[]; by_type: Record<string, number> };
  observations: {
    total: number; current: number; historical: number; assets: number;
    changed_facts: number; disputed_facts: number;
  };
  disputes: Array<{ asset_id: string; fact_type: string }>;
  meaning: string;
}

export const apiEstateAssetHistory = (identifier: string): Promise<ApiResult<EstateAssetHistory>> =>
  _rsGet<EstateAssetHistory>(`/api/v1/estate/evidence/history/assets/${encodeURIComponent(identifier)}`);

export const apiEstateHistorySummary = (): Promise<ApiResult<EstateHistorySummary>> =>
  _rsGet<EstateHistorySummary>("/api/v1/estate/evidence/history/summary");

/* §26: one search across everything recorded. Results come back grouped by kind and
   are never merged into one list, because a capability row and a runtime observation
   are different claims about the same algorithm. */
export interface EstateSearchHit {
  kind: string; id: string; label: string;
  asset_type?: string | null; environment?: string | null; owner?: string | null;
  lifecycle_state?: string | null; observation_count?: number;
  usage_states?: Record<string, number>; status?: string | null; basis?: string | null;
  confidence?: string | null; evidence_ids?: string[]; reason?: string | null;
  target?: string | null; layer?: string | null; observed_at?: string | null;
  asset_id?: string | null; state?: string | null; evidence_id?: string | null;
  severity?: string | null; verdict?: string | null; first_detected_at?: string | null;
  acknowledged?: boolean; detail?: string | null;
}

export interface EstateSearchGroup {
  count: number; hits: EstateSearchHit[]; truncated?: boolean; limit?: number;
  usage_states?: Record<string, number>; asset_types?: Record<string, number>;
  algorithms?: Record<string, number>; note?: string;
}

export interface EstateSearchResult {
  schema: string; query: string; kinds: string[]; matched: number;
  groups: Record<string, EstateSearchGroup>; by_kind: Record<string, number>;
  meaning: string; limits: string[];
}

export type EstateSearchKind = "ASSETS" | "CRYPTO" | "RELATIONSHIPS" | "EVIDENCE" | "FACTS" | "CHANGES";

export const apiEstateSearch = (
  query: string,
  kinds?: EstateSearchKind[],
): Promise<ApiResult<EstateSearchResult>> => {
  const params = new URLSearchParams({ q: query });
  if (kinds && kinds.length) params.set("kinds", kinds.join(","));
  return _rsGet<EstateSearchResult>(`/api/v1/estate/evidence/search?${params.toString()}`);
};

/* §23: conflicts are reported, never resolved. REAL means two sources on one plane
   disagree; EXPLAINED means the values come from different planes and can both be true. */
export interface EstateConflictValue {
  value: unknown; source?: string | null; evidence_type?: string | null;
  layer?: string | null; evidence_scope?: string; evidence_id?: string | null;
  observed_at?: string | null;
}

export interface EstateConflict {
  asset_id: string; asset_name?: string | null; field: string; fact_type?: string;
  values: EstateConflictValue[]; classification: "REAL" | "EXPLAINED" | "UNKNOWN";
  reason: string; status: string; source_of_conflict: string; next_action: string;
  seen_by: string[];
}

export interface EstateConflictSurvey {
  schema: string; conflicts: EstateConflict[]; count: number;
  by_classification: Record<string, number>; real_count: number; explained_count: number;
  assets_affected: number; meaning: string; limits: string[];
}

export const apiEstateConflicts = (): Promise<ApiResult<EstateConflictSurvey>> =>
  _rsGet<EstateConflictSurvey>("/api/v1/estate/evidence/twin/conflicts");

/* §2: the loop, phase by phase. NOT_STARTED means nothing has run yet — not that the
   phase is wired — and REMEDIATE reports NOT_CONNECTED because the twin opens no work. */
export interface EstateLifecyclePhase {
  phase: string; status: "CONNECTED" | "PARTIAL" | "NOT_CONNECTED" | "NOT_STARTED";
  question: string; detail: string; backed_by: string;
  observed: Record<string, unknown>; gap?: string | null;
}

export interface EstateLifecycle {
  schema: string; phases: EstateLifecyclePhase[];
  by_status: Record<string, number>; loop_closed: boolean; first_break: string | null;
  phase_order: string[]; meaning: string; limits: string[];
}

export const apiEstateLifecycle = (): Promise<ApiResult<EstateLifecycle>> =>
  _rsGet<EstateLifecycle>("/api/v1/estate/evidence/twin/lifecycle");

/* §12/§24: capability is counted apart from use, and a verdict names its source. */
export interface EstateCryptoFinding {
  asset_id: string; asset_name?: string | null; asset_type?: string | null;
  algorithm: string; canonical?: string | null; status: string; layer?: string | null;
  usage_state: string; in_use: boolean; evidence_type?: string | null;
  quantum_impact?: string | null; quantum_vulnerable?: boolean;
  verdict_source?: string; reading?: string; note?: string; notes?: string | null;
  evidence_ids?: string[];
}

export interface EstateCryptoIntel {
  schema: string;
  artifacts_examined: number;
  weak: {
    count: number; in_use_count: number; capability_only_count: number;
    by_status: Record<string, number>; by_asset_type: Record<string, number>;
    assets: Array<{ asset_id: string; asset_name?: string | null; asset_type?: string | null;
      algorithms: string[]; in_use: boolean; vendor_bound: boolean }>;
    capability_only: Array<{ asset_id: string; asset_name?: string | null; algorithm: string;
      status: string; note: string }>;
    entries: EstateCryptoFinding[]; meaning: string;
  };
  unknown: {
    count: number; unrecognised_count: number; mislabelled_count: number;
    assets: Array<{ asset_id: string; asset_name?: string | null; algorithms: string[] }>;
    entries: EstateCryptoFinding[]; meaning: string;
  };
  pqc: {
    vulnerable_artifacts: number; vulnerable_in_use: number;
    by_algorithm: Record<string, number>; by_asset_type: Record<string, number>;
    affected_assets: Array<{ asset_id: string; asset_name?: string | null;
      asset_type?: string | null; algorithms: string[] }>;
    vendor_bound_blockers: Array<{ asset_id: string; asset_name?: string | null;
      asset_type?: string | null; algorithms: string[] }>;
    vendor_bound_blocker_count: number; pqc_algorithms_present: string[];
    pending_migration_count: number; meaning: string;
  };
  next_action: string; limits: string[];
}

export interface EstateAlgorithmView {
  schema: string; query: string; algorithm: string; family?: string | null;
  status: string; quantum_impact?: string | null; quantum_vulnerable: boolean;
  recognized: boolean; found: boolean; artifacts: number; in_use: number;
  capability_only: number; by_asset_type: Record<string, number>;
  by_asset_type_in_use: Record<string, number>; by_usage_state: Record<string, number>;
  by_layer: Record<string, number>;
  assets: Array<{ asset_id: string; asset_name?: string | null; asset_type?: string | null;
    algorithms: string[]; in_use: boolean }>;
  next_action?: string; limits: string[];
}

export const apiEstateIntel = (): Promise<ApiResult<EstateCryptoIntel>> =>
  _rsGet<EstateCryptoIntel>("/api/v1/estate/evidence/twin/intel");

export const apiEstateAlgorithm = (name: string): Promise<ApiResult<EstateAlgorithmView>> =>
  _rsGet<EstateAlgorithmView>(`/api/v1/estate/evidence/twin/algorithm/${encodeURIComponent(name)}`);

/* §24 "trust paths": where each certificate's chain stops, and what that does not prove. */
export interface EstateTrustStep {
  asset_id?: string | null; asset_name?: string | null; asset_type?: string | null;
  present: boolean; evidence_ids: string[]; basis?: string | null; confidence?: string | null;
}

export interface EstateTrustChain {
  asset_id: string; asset_name?: string | null; asset_type?: string | null;
  status: "ROOTED" | "SELF_SIGNED" | "BROKEN" | "CYCLE" | "UNKNOWN_ISSUER";
  length: number; chain: EstateTrustStep[]; reason: string;
}

export interface EstateTrustPaths {
  schema: string; chains: EstateTrustChain[]; count: number;
  by_status: Record<string, number>; rooted_count: number; broken_count: number;
  unjudged_count: number; longest_chain: number; meaning: string; limits: string[];
}

export const apiEstateTrustPaths = (): Promise<ApiResult<EstateTrustPaths>> =>
  _rsGet<EstateTrustPaths>("/api/v1/estate/evidence/twin/trust-paths");

/* §7/§9 "protocol floor": if this were the weakest accepted protocol, what is already
   below it? A GET because it asks a question of the observed handshakes and writes
   nothing. Unrecognised protocol values and assets with no handshake evidence are
   published as their own buckets — neither is compliance. */
export interface EstateTwinProtocolFloorRow {
  asset_id: string; asset_name?: string | null; asset_type?: string | null;
  evidence_id?: string | null; evidence_type?: string | null;
  collector?: string | null; observed_at?: string | null;
  negotiated?: unknown;
  position?: "BELOW_FLOOR" | "AT_FLOOR" | "ABOVE_FLOOR" | "UNRECOGNISED" | "CONFLICT"
    | "OFFERS_BELOW_FLOOR" | "OFFERS_AT_OR_ABOVE_FLOOR";
  field?: string | null;
  stated?: Record<string, string>;
}

export interface EstateTwinProtocolFloor {
  schema: string;
  status: "BELOW_FLOOR_PRESENT" | "BELOW_FLOOR_DECLARED" | "BELOW_FLOOR_OFFERED" | "AT_OR_ABOVE_FLOOR"
    | "UNRANKED_EVIDENCE_ONLY" | "INSUFFICIENT_EVIDENCE" | "INVALID_SCENARIO";
  floor?: string | null; floor_rank?: number | null; projection_id?: string | null;
  counts?: {
    below_floor?: number; at_floor?: number; above_floor?: number; unrecognised?: number;
    conflicts?: number; unranked_records?: number;
    protocol_records?: number; assets_below_floor?: number;
    assets_with_negotiated_evidence?: number; assets_without_negotiated_evidence?: number;
    assets_in_scope?: number;
    client_offer_records?: number; clients_with_offer_evidence?: number;
    clients_offering_below_floor?: number;
  };
  below_floor?: EstateTwinProtocolFloorRow[];
  at_floor?: EstateTwinProtocolFloorRow[];
  above_floor?: EstateTwinProtocolFloorRow[];
  unrecognised?: EstateTwinProtocolFloorRow[];
  conflicts?: EstateTwinProtocolFloorRow[];
  without_negotiated_evidence?: string[];
  declared?: EstateTwinProtocolFloorDeclared;
  client_offers?: EstateTwinProtocolFloorClientOffers;
  unresolved_targets?: string[];
  live_state_modified?: boolean;
  note?: string | null;
  blind_spots?: string[];
  limits?: string[];
  choices?: string[];
  detail?: string | null;
}

/** The DECLARED axis: what a TLS configuration *allows*, which is a different claim from
 *  what a handshake produced. Kept in its own object so no client can merge the two. */
export interface EstateTwinProtocolFloorDeclared {
  basis: "DECLARED";
  meaning: string;
  counts: {
    assets_with_declaration?: number;
    declares_below_floor?: number;
    declared_ceiling_below_floor?: number;
    declared_without_a_rankable_floor?: number;
    partially_parsed?: number;
  };
  declares_below_floor?: Array<EstateTwinProtocolFloorRow & {
    declared?: string[]; declared_floor?: string | null; field?: string | null;
    partially_parsed?: boolean;
  }>;
  declared_ceiling_below_floor?: Array<EstateTwinProtocolFloorRow & {
    declared_ceiling?: string | null; edges?: string[]; position_ceiling?: string;
  }>;
  declared_without_a_rankable_floor?: Array<EstateTwinProtocolFloorRow & {
    declared?: string[]; unrecognised?: string[];
  }>;
  partially_parsed?: Array<{
    asset_id: string; asset_name?: string | null; evidence_id?: string | null; field?: string | null;
  }>;
}

/* §4/§11: the denominator the platform cannot compute. A bank declares what it believes
   is there; the estate is measured against it. Collected > declared is a disagreement to
   resolve, never a ratio above 100%, and a class with no declared count prints no
   percentage at all. */
export interface EstateGroundTruthPopulationRow {
  asset_type: string;
  declared: number | null;
  collected: number;
  evidenced: number;
  unevidenced: number;
  status: "COMPLETE" | "PARTIAL" | "EMPTY" | "OVER_DECLARED" | "NOT_DECLARED";
  note: string;
  collected_percent: number | null;
}

export interface EstateGroundTruthClaimResult {
  claim_id: string | null;
  type: string;
  declared?: Record<string, unknown>;
  verdict: "MATCHED" | "CONTRADICTED" | "MISSING_FROM_ESTATE" | "NOT_CHECKABLE";
  reason: string;
  evidence?: Array<Record<string, unknown>>;
  note?: string | null;
}

export interface EstateGroundTruthMeasurement {
  schema: string;
  status: "MEASURED" | "INVALID_DECLARATION";
  declared_by?: string;
  basis?: string;
  projection_id?: string;
  population?: {
    rows: EstateGroundTruthPopulationRow[];
    declared_classes: number;
    classes_with_a_denominator: number;
    classes_not_declared: number;
    disagreements: EstateGroundTruthPopulationRow[];
    meaning: string;
  };
  claims?: {
    results: EstateGroundTruthClaimResult[];
    by_type: Record<string, {
      declared: number; MATCHED: number; CONTRADICTED: number;
      MISSING_FROM_ESTATE: number; NOT_CHECKABLE: number;
      agreement_rate: number | null; basis: string;
    }>;
    meaning: string;
  };
  counts?: Record<string, number>;
  live_state_modified?: boolean;
  limits?: string[];
  detail?: string;
}

export interface EstateGroundTruthDeclaration {
  declared_by: string;
  declared_at?: string;
  basis?: string;
  asset_population: Record<string, number>;
  claims: Array<Record<string, unknown>>;
}

export const apiEstateTwinGroundTruth = (
  body: EstateGroundTruthDeclaration,
): Promise<ApiResult<EstateGroundTruthMeasurement>> =>
  _rsPost<EstateGroundTruthMeasurement>("/api/v1/estate/evidence/twin/ground-truth", body);

/** The client-offer axis: what connecting clients *offered* at an approved probe.
 *  An offer is runtime acceptance evidence — stronger than a declaration — but it is
 *  not a negotiation: nothing here completed a handshake. */
export interface EstateTwinProtocolFloorClientOffers {
  basis: "OBSERVED";
  meaning: string;
  counts: {
    offer_records?: number;
    clients_with_offer_evidence?: number;
    clients_offering_below_floor?: number;
    clients_offering_at_or_above_floor?: number;
    unrecognised?: number;
    clients_without_offer_evidence?: number;
  };
  clients_offering_below_floor?: Array<EstateTwinProtocolFloorRow & {
    offered?: string[]; offers_below_floor?: string[]; offers_at_floor?: string[];
    offers_above_floor?: string[]; sni?: string | null;
  }>;
  clients_offering_at_or_above_floor?: Array<EstateTwinProtocolFloorRow & { offered?: string[] }>;
  unrecognised?: Array<EstateTwinProtocolFloorRow & { unrecognised?: string[] }>;
  clients_without_offer_evidence?: string[];
}

export const apiEstateTwinProtocolFloor = (
  floor: string,
  targets?: string[],
): Promise<ApiResult<EstateTwinProtocolFloor>> => {
  const query = [`floor=${encodeURIComponent(floor)}`,
    ...(targets ?? []).map((target) => `target=${encodeURIComponent(target)}`)].join("&");
  return _rsGet<EstateTwinProtocolFloor>(`/api/v1/estate/evidence/twin/protocol-floor?${query}`);
};

/* ---------------------------------------------------------------------------
 * Evidence assurance (the `/api/v1/assurance` workflows).
 *
 * Reads return the server's payload without derived percentages or cached
 * success. Registered source scope can be declared here, but only a later
 * durable collection receipt can make a target OBSERVED.
 * ------------------------------------------------------------------------- */

export interface AssuranceRecord {
  id: string;
  kind: string;
  subject_id: string;
  revision: number;
  payload: Record<string, unknown>;
  payload_sha256: string;
  previous_sha256: string | null;
  created_by?: string;
  created_at?: string | null;
}
export interface AssuranceRecords {
  records: AssuranceRecord[];
  has_more: boolean;
  next_offset: number | null;
  includes_all_revisions: boolean;
}
export const apiAssuranceKinds: string[] = [
  "estate_register", "coverage_observation", "bom_relationship", "accuracy_sample",
  "accuracy_review", "accuracy_repeat", "evidence_blob", "supplier_evidence",
  "adapter_manifest", "adapter_qualification", "redis_objectives", "redis_measurement",
  "finding_assessment", "signer", "remediation_change", "remediation_task", "operator_decision",
];
export const apiAssuranceRecords = (kind: string, offset = 0, limit = 100): Promise<ApiResult<AssuranceRecords>> =>
  _rsGet<AssuranceRecords>(
    `/api/v1/assurance/records?kind=${encodeURIComponent(kind)}&offset=${offset}&limit=${limit}`);
export const apiAssuranceHistory = (kind: string, identifier: string, after = 0): Promise<ApiResult<{ revisions: AssuranceRecord[]; has_more: boolean }>> =>
  _rsGet<{ revisions: AssuranceRecord[]; has_more: boolean }>(
    `/api/v1/assurance/records/${encodeURIComponent(kind)}/${encodeURIComponent(identifier)}?after_revision=${after}`);

export interface AssuranceSourceRegister {
  expected_revision: 0;
  scope_description: string;
  register_owner: string;
  completeness: "UNKNOWN";
  completeness_evidence_ref: string;
  targets: [{
    target_id: string; owner_ref: string; kind: "SOURCE"; source_class: "source";
    target_ref: string; method: "LOCAL_SOURCE"; permission_ref: string;
    freshness_seconds: number;
  }];
}
export const apiAssuranceCreateRegister = (body: AssuranceSourceRegister): Promise<ApiResult<AssuranceRecord>> =>
  call<AssuranceRecord>("/api/v1/assurance/registers", { method: "POST", body: JSON.stringify(body) });

export interface CoverageCounts { OBSERVED: number; STALE: number; BLOCKED: number; UNSUPPORTED: number; NOT_ATTEMPTED: number }
export interface CoverageTarget {
  target_id: string; target_ref: string; kind: string; method: string;
  state: keyof CoverageCounts; freshness_seconds: number;
  expires_at: string | null; last_attempted_at: string | null; last_successful_at: string | null;
}
export interface AssuranceCoverage {
  register_id: string; revision: number; registered_targets: number;
  register_completeness: string; scope_description: string; completeness_evidence_ref: string;
  whole_bank_verified: false; denominator_basis: string; completeness_basis: string;
  counts: CoverageCounts; by_kind: Record<string, Record<string, number>>;
  targets: CoverageTarget[]; as_of: string;
}
export const apiAssuranceCoverage = (registerId: string): Promise<ApiResult<AssuranceCoverage>> =>
  _rsGet<AssuranceCoverage>(`/api/v1/assurance/registers/${encodeURIComponent(registerId)}/coverage`);

export interface TracePath {
  application_id: string; deployment_id: string; deployment_basis: string; deployment_evidence_ref: string;
  artifact_id: string; artifact_digest: string; artifact_identity_source: string;
  sbom_binding_id: string; sbom_sha256: string; package_identity: string | null;
  crypto_evidence_id: string | null; algorithm: string | null; purpose: string | null;
  location: { file: string | null; line: number | null } | null;
  relationship_id: string; relationship_sha256: string; evidence_ids: string[]; trust: unknown;
  deployed_verified: false; invocation_verified: false;
}
export interface TraceUnresolved { reason: string; deployment_id?: string; sbom_binding_id?: string; artifact_id?: string; package_identity?: string | null; bom_ref?: string }
export interface AssuranceTrace {
  application_id: string; paths: TracePath[]; unresolved: TraceUnresolved[];
  complete: false; runtime_verified: false; note: string;
}
export const apiAssuranceTrace = (applicationId: string): Promise<ApiResult<AssuranceTrace>> =>
  _rsGet<AssuranceTrace>(`/api/v1/assurance/applications/${encodeURIComponent(applicationId)}/trace`);

export interface SampleUnit {
  unit_id: string; split: string; prediction?: unknown; package_identity?: string | null;
  truth_label?: string; explanation?: string | null;
}
export interface AssuranceWorkbook {
  sample_id: string; sample_sha256: string; phase: "FIRST_PASS" | "HOLDOUT";
  domain_owner: string; scope: string; units: SampleUnit[];
  truth_labels: string[]; note: string;
}
export const apiAssuranceWorkbook = (sampleId: string, phase: "FIRST_PASS" | "HOLDOUT" = "FIRST_PASS"): Promise<ApiResult<AssuranceWorkbook>> =>
  _rsGet<AssuranceWorkbook>(
    `/api/v1/assurance/samples/${encodeURIComponent(sampleId)}/workbook?phase=${phase}`);

export interface AdapterStatus {
  manifest: AssuranceRecord; qualification: AssuranceRecord | null;
  offline_profile_exercised: boolean; live_vendor_supported: false;
  support_status: "OFFLINE_PROFILE_EXERCISED" | "NOT_QUALIFIED";
}
export const apiAssuranceAdapter = (adapterId: string): Promise<ApiResult<AdapterStatus>> =>
  _rsGet<AdapterStatus>(`/api/v1/assurance/adapters/${encodeURIComponent(adapterId)}`);
export interface SupplierObservations {
  source_evidence_id: string; source_sha256: string; artifact_id: string; build_digest: string;
  qualification_id: string; automatic_identity_joins: false; live_vendor_supported: false;
  independent_truth_verified: false; facts?: unknown[];
}
export const apiAssuranceSupplierObservations = (adapterId: string, evidenceId: string): Promise<ApiResult<SupplierObservations>> =>
  _rsGet<SupplierObservations>(
    `/api/v1/assurance/adapters/${encodeURIComponent(adapterId)}/supplier-evidence/${encodeURIComponent(evidenceId)}/observations`);

export interface RedisQualification {
  objectives: AssuranceRecord;
  matrix: { role: string; scenario: string; measurement_id: string | null; accepted: boolean; state: string }[];
  unqualified_roles: string[];
  deployment_evidence_meets_objectives: boolean;
  whole_infrastructure_qualified: boolean;
  qualification_basis: string;
  local_sentinel_promotion_is_deployment_qualification: false;
}
export const apiAssuranceRedisQualification = (objectivesId: string): Promise<ApiResult<RedisQualification>> =>
  _rsGet<RedisQualification>(`/api/v1/assurance/redis-objectives/${encodeURIComponent(objectivesId)}/qualification`);

/* ── simulation workspace (contracts in api/routers/estate_graph.py) ──────────
 * A scenario is a question asked of a *copy* of the twin. Two calls exist because the
 * operator needs them separately: `plan` answers "would this match anything" before the
 * copy is made and the six BOMs are projected, and `run` answers what actually changes.
 * Both carry the projection id they were measured against, so a stale answer is visible. */

export interface SimulationSelectorValue { value: string; count: number }
export interface SimulationSelectorTarget { asset_id: string; name: string; type: string }
export interface SimulationSelector {
  algorithms: SimulationSelectorValue[]; protocols: SimulationSelectorValue[];
  components: SimulationSelectorValue[]; targets: SimulationSelectorTarget[];
  truncated_to: number; note: string;
}
export type SimulationMode = "SCENARIO" | "CASCADE";

export interface SimulationKind {
  kind: string; mode: SimulationMode; name: string; question: string; inputs: string[];
  optional: string[]; answers: string[]; does_not_answer: string[];
}
export interface SimulationModeInfo {
  mode: SimulationMode; name: string; blurb: string;
  changes_evidence: boolean; has_bom_diff: boolean;
}
export interface SimulationPreset {
  id: string; label: string; mode: SimulationMode; kind: string;
  scenario: SimulationScenario; why: string;
}
export interface SimulationCatalog {
  schema: string; run_id: string; base_projection_id: string | null;
  estate: { assets: number; evidence: number; relationships: number; coverage_state: string;
            attempted: number | null; collected: number | null };
  modes: SimulationModeInfo[]; kinds: SimulationKind[]; presets: SimulationPreset[];
  selector: SimulationSelector; note: string; limits: string[];
}

export interface SimulationPerformanceInput {
  tenant_id: string; asset_ref: string; metric_name: string;
  source_id: string; change_event_id: string;
  before_start: string; before_end: string;
  after_start: string; after_end: string;
  baseline_benchmark_run_id?: string; candidate_benchmark_run_id?: string;
}

export interface SimulationScenario {
  kind: string; from?: string; to?: string; key_size?: number | null;
  performance_context?: SimulationPerformanceInput;
  targets?: string[]; depth?: number; label?: string | null;
  /* CUSTOM only: the scenario as data — a condition tree plus assignments. It is
     validated by the engine, which refuses a provenance write and refuses a program. */
  expression?: Record<string, unknown>;
  /* COMPOSITE only: up to five primitive scenarios, applied to one copy in order.
     Cascades and composites do not nest, and the engine refuses a longer list. */
  steps?: Array<Record<string, unknown>>;
}

/** One hop of a cascade: where it came from, over which predicate, and why that predicate
 *  carries a failure at all. */
export interface SimulationVia {
  from_asset: string; from_name: string | null; predicate: string; meaning: string | null;
  edge: { subject: string; predicate: string; object: string; basis: string | null;
          confidence: string | null; evidence_ids: string[] | null };
}
export interface SimulationSeed {
  asset_id: string; name: string; type: string; reason: string;
}
export interface SimulationWave {
  depth: number; count: number; truncated: number;
  assets: Array<{ asset_id: string; name: string; type: string; via: SimulationVia }>;
}
export interface SimulationRule {
  predicate: string; direction: string; meaning: string;
}
export interface SimulationCascadePathHop {
  asset_id: string; name: string | null; type: string | null;
  via_predicate: string | null; via_asset: string | null;
}
export interface SimulationBusinessSystem {
  asset_id: string; name: string; hops: number; path: SimulationCascadePathHop[];
}

export interface SimulationAffectedAsset {
  asset_id: string; name: string; type: string; evidence_matched: number;
}
export interface SimulationPreview {
  schema: string; status: "WOULD_MATCH" | "WOULD_NOT_MATCH"; kind: string;
  mode?: SimulationMode; engine?: "CASCADE"; depth?: number;
  scenario: SimulationScenario; base_projection_id: string | null;
  live_state_modified: false; evidence_considered: number; matched_evidence: number;
  affected_assets: Array<SimulationAffectedAsset & { hops?: number; via_predicate?: string | null }>;
  affected_asset_count: number;
  by_layer: Record<string, number>; unresolved_targets: string[];
  coverage: {
    target_classes: number; expected: number; collected: number;
    coverage_percent: number; coverage_state: string; by_status: Record<string, number>;
    failed_targets: string[];
  };
  /* cascade previews carry these instead of a BOM projection */
  seeds?: SimulationSeed[]; unresolved_seeds?: string[];
  wave_counts?: Array<{ depth: number; count: number }>;
  business_systems_reached?: number; rules?: SimulationRule[];
  note: string; limits: string[];
}

export interface SimulationEffect {
  evidence_id: string; asset_id: string; asset_name: string; layer: string;
  evidence_type: string; before: Record<string, unknown>; after: Record<string, unknown>;
}
export interface SimulationBomDiff {
  added: string[]; removed: string[]; changed: string[];
  counts: { added: number; removed: number; changed: number; unchanged: number };
}
export interface SimulationRecord {
  id: string; simulation_id: string; kind: string; scenario: SimulationScenario;
  label: string | null; base_snapshot_id: string | null; base_projection_id: string | null;
  simulated_projection_id: string | null; computed_against: string | null;
  superseded_by: string | null; superseded: boolean; freshness: string;
  matched_evidence: number; affected_assets: SimulationAffectedAsset[];
  impact: Record<string, unknown>; bom_diff: Record<string, SimulationBomDiff>;
  blockers: unknown[]; live_state_modified: boolean; observations: number;
  first_run_at: string | null; last_run_at: string | null; quarantined?: boolean;
  is_estate_state?: boolean;
}
export interface SimulationRun {
  status: string; run_id: string; schema: string; kind: string;
  mode?: SimulationMode; engine?: "CASCADE"; depth?: number;
  seeds?: SimulationSeed[]; unresolved_seeds?: string[];
  waves?: SimulationWave[]; wave_count?: number;
  rules?: SimulationRule[]; limits?: string[];
  bom_diff_note?: string; estate_copy?: null;
  detail?: string;
  scenario: SimulationScenario; base_snapshot: string | null;
  base_projection_id: string | null; simulated_projection_id: string | null;
  matched_evidence: number; evidence_considered?: number;
  affected_assets: SimulationAffectedAsset[]; effects: SimulationEffect[];
  bom_diff: Record<string, SimulationBomDiff>; bom_changes?: unknown;
  impact: { counts?: Record<string, number>; by_type?: Record<string, number>;
            blind_spots?: unknown[]; [key: string]: unknown };
  blockers: Array<Record<string, unknown>>; unknown: Record<string, unknown>;
  live_state_modified: boolean; live_projection_unchanged: boolean;
  plan: SimulationPreview | null; simulation_id: string | null;
  persisted: boolean; simulation_record: SimulationRecord | null;
  persist_refused_because?: string | null; persist_note?: string | null;
  performance_context?: (SimulationPerformanceContext & {
    link: { state: string; twin_asset_id: string | null; reason: string };
    role: "MEASURED_CONTEXT_ONLY"; note: string;
  }) | { state: "NOT_APPLICABLE"; purpose: "SIMULATION_INPUT"; reason: string };
  note: string;
}
export interface SimulationRuns {
  model: string; run_id: string; current_projection_id: string | null;
  count: number; simulations: SimulationRecord[]; quarantined: boolean; note: string;
}

async function _simPost<T>(path: string, body: unknown, timeoutMs: number): Promise<ApiResult<T>> {
  try {
    const resp = await tenantFetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
      credentials: "include",
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) return { source: "live", ok: false, error: _idErr(data, resp.status), data: null };
    return { source: "live", ok: true, data: data as T };
  } catch (e) { return { source: "offline", ok: false, error: String(e), data: null }; }
}

export const apiSimulationCatalog = (): Promise<ApiResult<SimulationCatalog>> =>
  _rsGet<SimulationCatalog>("/api/v1/estate/evidence/simulation/catalog");

/** "Would this scenario match?" — answered without projecting the six BOMs. */
export const apiSimulationPlan = (scenario: SimulationScenario): Promise<ApiResult<SimulationPreview>> =>
  _simPost<SimulationPreview>("/api/v1/estate/evidence/simulation/plan", scenario, 30000);

/** Apply the scenario to a copy of the twin. Longer timeout: a run projects six BOMs. */
export const apiSimulationRun = (scenario: SimulationScenario): Promise<ApiResult<SimulationRun>> =>
  _simPost<SimulationRun>("/api/v1/estate/evidence/simulation/run", scenario, 90000);

export const apiSimulationRuns = (): Promise<ApiResult<SimulationRuns>> =>
  _rsGet<SimulationRuns>("/api/v1/estate/evidence/simulation/runs");

/* ---- CryptoLog (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 6) ---- */

export interface CryptologEventRow {
  event_id: string;
  event_schema?: string;
  tenant_id?: string;
  event_type: string;
  category: string;
  logging_kind: string;
  severity: string;
  investigation_status: string;
  asset_id: string;
  business_system_id?: string | null;
  source: Record<string, unknown>;
  cryptographic_context: Record<string, unknown>;
  observation: Record<string, unknown>;
  evidence: Record<string, unknown>;
  relationships: Record<string, unknown>;
  processing: Record<string, unknown>;
  telemetry_mode?: string;
  approval_ref?: string | null;
  attributes: Record<string, unknown>;
}

export interface CryptologEventPage {
  events: CryptologEventRow[];
  next_cursor: string | null;
  returned: number;
}

export interface CryptologCorrection {
  corrects_event_id: string;
  original_hash: string;
  corrected_event: Record<string, unknown>;
  reason: string;
  actor: string;
  evidence_ids: string[];
}

export interface CryptologEventParams {
  cursor?: string | null;
  limit?: number;
  category?: string;
  severity?: string;
  event_type?: string;
  asset_id?: string;
  investigation_status?: string;
  tenant_id?: string;
}

export const apiCryptologEvents = (params: CryptologEventParams = {}): Promise<ApiResult<CryptologEventPage>> => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value) !== "") query.set(key, String(value));
  }
  const suffix = query.toString();
  return call<CryptologEventPage>(`/api/v1/cryptolog/events${suffix ? `?${suffix}` : ""}`);
};

export const apiCryptologEvent = (eventId: string): Promise<ApiResult<CryptologEventRow>> =>
  call<CryptologEventRow>(`/api/v1/cryptolog/events/${encodeURIComponent(eventId)}`);

export const apiCryptologCorrections = (eventId: string): Promise<ApiResult<{ event_id: string; corrections: CryptologCorrection[]; returned: number }>> =>
  call(`/api/v1/cryptolog/events/${encodeURIComponent(eventId)}/corrections`);

/* CryptoLog alerts (Phase 5 storage surface) and integrity (section 5):
   totals come from the server; a failed read is a failure, never zeros. */

export interface CryptologAlertTransition {
  action: string;
  actor: string;
  at: string;
  note?: string | null;
  resolution?: string | null;
  evidence_ids?: string[];
  state?: string;
}

export interface CryptologAlert {
  alert_id: string;
  rule_id: string;
  event_id: string;
  asset_id: string;
  severity: string;
  state: string;
  title: string;
  basis: Record<string, unknown>;
  what_is_proven: string[];
  what_is_not_proven: string[];
  evidence_ids: string[];
  occurred_at: string;
  transitions: CryptologAlertTransition[];
}

export interface CryptologAlertPage {
  rows: CryptologAlert[];
  total_count: number;
  next_cursor: string | null;
  has_more: boolean;
}

export interface CryptologAlertParams {
  state?: string;
  severity?: string;
  rule_id?: string;
  event_id?: string;
  limit?: number;
  cursor?: string;
}

export const apiCryptologAlerts = (params: CryptologAlertParams = {}): Promise<ApiResult<CryptologAlertPage>> => {
  const qs = new URLSearchParams();
  if (params.state) qs.set("state", params.state);
  if (params.severity) qs.set("severity", params.severity);
  if (params.rule_id) qs.set("rule_id", params.rule_id);
  if (params.event_id) qs.set("event_id", params.event_id);
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.cursor) qs.set("cursor", params.cursor);
  const suffix = qs.toString();
  return call<CryptologAlertPage>(`/api/v1/cryptolog/alerts${suffix ? `?${suffix}` : ""}`);
};

export const apiCryptologAlert = (alertId: string): Promise<ApiResult<CryptologAlert>> =>
  call<CryptologAlert>(`/api/v1/cryptolog/alerts/${encodeURIComponent(alertId)}`);

export interface CryptologCheckpoint {
  checkpoint_ref: string;
  schema?: string;
  partition_id?: string;
  sequence?: number;
  chain_hash?: string;
  merkle_root_hash?: string;
  event_count?: number;
  created_at?: string;
  signer_id?: string;
  signature?: string;
  retention_ref?: string;
  window?: Record<string, unknown>;
}

export interface CryptologCheckpointPage {
  rows: CryptologCheckpoint[];
  total_count: number;
}

export const apiCryptologCheckpoints = (): Promise<ApiResult<CryptologCheckpointPage>> =>
  call<CryptologCheckpointPage>("/api/v1/cryptolog/integrity/checkpoints");

export interface CryptologVerifyResult {
  schema?: string;
  partition_id?: string;
  results: Array<{ event_id: string; state: string; note: string }>;
  overall_state: string;
  note: string;
  checkpoint_used: boolean;
  input?: { event_count?: number; checkpoint_ref?: string | null; checkpoint_signature_verified?: boolean | null };
}

export const apiCryptologVerify = (body: {
  checkpoint_ref?: string;
  start_occurred?: string;
  end_occurred?: string;
} = {}): Promise<ApiResult<CryptologVerifyResult>> =>
  call<CryptologVerifyResult>("/api/v1/cryptolog/integrity/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export interface CryptologMerkleProof {
  event_id: string;
  event_hash: string;
  index: number;
  checkpoint_ref: string;
  merkle_root_hash: string;
  proof: Array<Record<string, string>>;
  verified: boolean;
}

export const apiCryptologMerkleProof = (eventId: string, checkpointRef: string): Promise<ApiResult<CryptologMerkleProof>> =>
  call<CryptologMerkleProof>(`/api/v1/cryptolog/integrity/merkle-proof?event_id=${encodeURIComponent(eventId)}&checkpoint_ref=${encodeURIComponent(checkpointRef)}`);

/* CryptoLog insights (§9 overview + timeline): server-side aggregation,
   every count names what it counts. */

export interface CryptologTimelineBucket {
  bucket_start: string;
  total: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  critical_changes: number;
}

export interface CryptologTimeline {
  bucket: string;
  window: { start_occurred?: string | null; end_occurred?: string | null; asset_id?: string | null };
  event_count: number;
  buckets: CryptologTimelineBucket[];
  note: string;
}

export const apiCryptologTimeline = (params: {
  bucket?: "day" | "hour";
  asset_id?: string;
  start_occurred?: string;
  end_occurred?: string;
} = {}): Promise<ApiResult<CryptologTimeline>> => {
  const qs = new URLSearchParams();
  if (params.bucket) qs.set("bucket", params.bucket);
  if (params.asset_id) qs.set("asset_id", params.asset_id);
  if (params.start_occurred) qs.set("start_occurred", params.start_occurred);
  if (params.end_occurred) qs.set("end_occurred", params.end_occurred);
  const suffix = qs.toString();
  return call<CryptologTimeline>(`/api/v1/cryptolog/timeline${suffix ? `?${suffix}` : ""}`);
};

export interface CryptologCollectorHealth {
  collector_id: string;
  event_count: number;
  telemetry_modes: Record<string, number>;
}

export interface CryptologOverview {
  event_total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_logging_kind: Record<string, number>;
  critical_changes: number;
  alerts_total: number;
  alerts_open: number;
  collectors: CryptologCollectorHealth[];
  integrity: {
    state: string;
    checkpoint_count: number;
    latest_checkpoint_ref?: string | null;
    latest_created_at?: string | null;
    note: string;
  };
  note: string;
}

export const apiCryptologOverview = (): Promise<ApiResult<CryptologOverview>> =>
  call<CryptologOverview>("/api/v1/cryptolog/overview");

/* CryptoLog reports (§9): the auditor pack is a binary archive. It still
   uses the authenticated tenant transport (not the JSON decoder); a tenant
   switch before body read must never release the prior estate's bytes. */

export interface CryptologReportExportResult {
  ok: boolean;
  blob?: Blob;
  reportId?: string;
  fileCount?: string;
  error?: string;
}

export const apiCryptologReportExport = async (filters: {
  start_occurred?: string;
  end_occurred?: string;
  severity?: string;
  category?: string;
} = {}): Promise<CryptologReportExportResult> => {
  const body: Record<string, string> = {};
  if (filters.start_occurred) body.start_occurred = filters.start_occurred;
  if (filters.end_occurred) body.end_occurred = filters.end_occurred;
  if (filters.severity) body.severity = filters.severity;
  if (filters.category) body.category = filters.category;
  const token = getToken(), estate = activeTenantId();
  const controller = new AbortController();
  const stop = watchPrivateScope(() => controller.abort());
  const guard = () => !controller.signal.aborted && token === getToken() && estate === activeTenantId();
  try {
    if (!guard()) return { ok: false, error: "context changed" };
    const response = await tenantFetch("/api/v1/cryptolog/reports/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!guard()) return { ok: false, error: "context changed" };
    if (!response.ok) return { ok: false, error: `HTTP ${response.status}` };
    const blob = await response.blob();
    if (!guard()) return { ok: false, error: "context changed" };
    return {
      ok: true,
      blob,
      reportId: response.headers.get("X-Report-Id") || undefined,
      fileCount: response.headers.get("X-Archive-Files") || undefined,
    };
  } catch {
    return { ok: false, error: guard() ? "offline" : "context changed" };
  } finally {
    stop();
  }
};

/* CryptoLog retention (§10): policy in the open, plans as projections. */

export interface CryptologRetentionPolicy {
  schema?: string;
  activity_retention_days: number;
  change_retention_days: number;
  audit_retention_days: number;
  archive_after_days: number;
  require_disposition_ref: boolean;
  note: string;
}

export const apiCryptologRetentionPolicy = (): Promise<ApiResult<CryptologRetentionPolicy>> =>
  call<CryptologRetentionPolicy>("/api/v1/cryptolog/retention/policy");

export interface CryptologRetentionPlan {
  schema?: string;
  generated_at: string;
  policy: Record<string, unknown>;
  counts: Record<string, number>;
  rows: Array<{
    event_id: string;
    retention_class: string;
    observed_at?: string | null;
    age_days?: number | null;
    action: string;
    reason: string;
  }>;
  proven: string[];
  not_proven: string[];
  note: string;
}

export const apiCryptologRetentionPlan = (filters: {
  start_occurred?: string;
  end_occurred?: string;
} = {}): Promise<ApiResult<CryptologRetentionPlan>> =>
  call<CryptologRetentionPlan>("/api/v1/cryptolog/retention/plan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      start_occurred: filters.start_occurred,
      end_occurred: filters.end_occurred,
    }),
  });

// ── CryptoLog Phase-5 reads: rules catalogue and event correlation ──
export interface CryptologRule {
  rule_id: string; detection: string; suggested_severity: string;
  investigation: string;
}
export interface CryptologRuleCatalogue {
  rules: CryptologRule[]; note: string;
}
export interface CryptologCorrelationGroup {
  basis: "shared_evidence" | "shared_asset" | "shared_algorithm" | string;
  key: string; event_ids: string[]; asset_ids: string[];
  event_count: number; evidence_backed: boolean; note: string;
}
export interface CryptologCorrelation {
  groups: CryptologCorrelationGroup[]; event_count: number;
  groups_truncated: boolean; note: string;
}

export const apiCryptologRules = (): Promise<ApiResult<CryptologRuleCatalogue>> =>
  call<CryptologRuleCatalogue>("/api/v1/cryptolog/rules");

export const apiCryptologCorrelation = (params: {
  tenant_id?: string; start_occurred?: string; end_occurred?: string;
} = {}): Promise<ApiResult<CryptologCorrelation>> => {
  const query = new URLSearchParams();
  if (params.tenant_id) query.set("tenant_id", params.tenant_id);
  if (params.start_occurred) query.set("start_occurred", params.start_occurred);
  if (params.end_occurred) query.set("end_occurred", params.end_occurred);
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return call<CryptologCorrelation>(`/api/v1/cryptolog/correlation${suffix}`);
};

/* ZELNX Performance Intelligence (docs/performance/01_PRODUCT_SPEC.md).
   Every query is tenant-scoped and time-bounded; a failed read is a
   failure, never zeros; an unknown tile is unknown, never zero. */

export interface PerformanceTile {
  value: number | null;
  unit: string;
  state: string;
  derived?: boolean;
  note?: string | null;
}

export interface PerformanceSummary {
  sample_count: number;
  value_count: number;
  unknown_count: number;
  coverage: string;
  average: number | null;
  minimum: number | null;
  maximum: number | null;
  p50: number | null;
  p95: number | null;
  p99: number | null;
}

export interface PerformanceServiceRow {
  service: string;
  p95_latency_ms?: number | null;
  error_rate_pct?: number | null;
  requests_per_sec?: number | null;
  sample_count: number;
}

export interface PerformanceOverview {
  storage_usage_pct: PerformanceTile;
  network_throughput_mbps: PerformanceTile;
  api_p95_latency_ms: PerformanceTile;
  requests_per_sec: PerformanceTile;
  /** UI brief headline cards (docs/performance/03_UI_SPEC.md §1). */
  cpu_utilization_pct?: PerformanceTile;
  memory_utilization_pct?: PerformanceTile;
  app_p95_latency_ms?: PerformanceTile;
  error_rate_pct?: PerformanceTile;
  services?: PerformanceServiceRow[];
  note: string;
}

export interface InfraCategory {
  state: string;
  metrics: Record<string, PerformanceSummary>;
  basis: string;
}

export interface InfraServerRow {
  asset_id: string;
  link?: string | null;
  link_state: string;
  cpu_pct?: number | null;
  memory_pct?: number | null;
  load?: number | null;
  disk_latency_ms?: number | null;
  families: string[];
  samples: number;
  last_observed?: string | null;
}

export interface AppServiceRow {
  service: string;
  p50_latency_ms?: number | null;
  p95_latency_ms?: number | null;
  p99_latency_ms?: number | null;
  error_rate_pct?: number | null;
  timeout_rate_pct?: number | null;
  requests_per_sec?: number | null;
  samples: number;
  last_observed?: string | null;
}

export interface AppEndpointRow {
  service: string;
  endpoint: string;
  metric_name: string;
  latest?: number | null;
  unit: string;
  observed_at: string;
}

export interface AppCapability {
  state: string;
  basis: string;
}

export interface DbArea {
  state: string;
  metrics: Record<string, PerformanceSummary>;
  missing: string[];
}

export interface DbRow {
  database: string;
  platform: string;
  connections_active?: number | null;
  query_time_ms?: number | null;
  size_bytes?: number | null;
  replication_lag_seconds?: number | null;
  samples: number;
  last_observed?: string | null;
}

export interface DbAdapter {
  platform: string;
  adapter?: string | null;
  state: string;
}

export interface DbCollector {
  collector_id: string;
  status: string;
  last_report_at?: string | null;
  detail?: string | null;
}

export interface PerformanceDbWorkspace {
  areas: Record<string, DbArea>;
  databases: DbRow[];
  adapters: DbAdapter[];
  collectors: DbCollector[];
  note: string;
}

export interface PerformanceAppWorkspace {
  metrics: Record<string, PerformanceTile>;
  services: AppServiceRow[];
  endpoints: AppEndpointRow[];
  capabilities: Record<string, AppCapability>;
  regression?: PerformanceSummary | null;
  note: string;
}

export interface PerformanceInfraWorkspace {
  categories: Record<string, InfraCategory>;
  inventory: InfraServerRow[];
  trends: Record<string, PerformanceSummary>;
  hardware_health: { state: string; metrics: Record<string, PerformanceSummary>; basis: string };
  note: string;
}

export interface PerformanceHsm {
  devices: Array<{
    device: string;
    operation_latency_ms?: number | null;
    p95_latency_ms?: number | null;
    queue_depth?: number | null;
    utilization_pct?: number | null;
    provider_errors?: number | null;
    availability_pct?: number | null;
    operations_per_sec?: number | null;
    samples: number;
    last_observed?: string | null;
    trend?: Array<{ bucket: string; value: number | null; samples: number }>;
  }>;
  families: Record<string, PerformanceSummary>;
  /** UI brief §7 the eleven measurements (docs/performance/03_UI_SPEC.md §7). */
  measurements?: Record<string, { state: string; metrics: Record<string, PerformanceSummary>; basis: string }>;
  measurement_kind: string;
  note: string;
}

export interface PerformanceWorkloads {
  workload_metrics: Record<string, PerformanceSummary>;
  /** UI brief §8 (docs/performance/03_UI_SPEC.md §8). */
  categories?: Record<string, { state: string; metrics: Record<string, PerformanceSummary>; basis: string }>;
  measurements?: Record<string, { state: string; metrics: Record<string, PerformanceSummary>; basis: string }>;
  peak_offpeak?: Record<string, unknown>;
  correlation_candidates: Array<Record<string, unknown>>;
  causation: string;
  note: string;
}

export interface PerformanceNetwork {
  bandwidth_capacity_mbps: PerformanceTile;
  observed_throughput_mbps: PerformanceTile;
  rtt_ms: PerformanceSummary | null;
  /** UI brief §5 twelve measurements (docs/performance/03_UI_SPEC.md §5). */
  jitter_ms?: PerformanceTile;
  packet_loss_pct?: PerformanceTile;
  retransmissions?: PerformanceTile;
  dns_resolution_ms?: PerformanceTile;
  connection_establish_ms?: PerformanceTile;
  tcp_connections?: PerformanceTile;
  interface_errors?: PerformanceTile;
  tunnel_health?: PerformanceTile;
  tls_handshake_ms?: PerformanceTile;
  load_balancer_response_ms?: PerformanceTile;
  metrics: Record<string, PerformanceSummary>;
  cipher_suite_note?: string;
  note: string;
}

export interface PerformanceStorage {
  tiles: Record<string, PerformanceTile>;
  metrics: Record<string, PerformanceSummary>;
  note: string;
}

export interface PerformanceApplications {
  requests_per_sec: PerformanceTile;
  latency_p50_ms: PerformanceTile;
  latency_p95_ms: PerformanceTile;
  latency_p99_ms: PerformanceTile;
  error_rate_pct: PerformanceTile;
  metrics: Record<string, PerformanceSummary>;
  note: string;
}

export interface PerformanceDatabases {
  connections_active: PerformanceTile;
  query_time_ms: PerformanceSummary | null;
  metrics: Record<string, PerformanceSummary>;
  note: string;
}

export interface PerformanceCryptography {
  tls_handshake_ms: PerformanceSummary | null;
  hsm_operation_latency_ms: PerformanceSummary | null;
  metrics: Record<string, PerformanceSummary>;
  /** UI brief §6 ten categories (docs/performance/03_UI_SPEC.md §6). */
  categories?: Record<string, { state: string; metrics: Record<string, PerformanceSummary>; basis: string }>;
  measurement_kind: string;
  note: string;
}

export interface PerformanceDomain {
  domain: string;
  metrics: Record<string, PerformanceSummary>;
  note: string;
}

export interface PerformanceAsset {
  asset_id: string;
  identity: Record<string, unknown> | null;
  metrics: Record<string, PerformanceSummary>;
  note: string;
}

export interface PerformanceAlert {
  metric_name: string;
  severity: string;
  severity_factors: Record<string, unknown>;
  proven: string[];
  not_proven: string[];
  supporting_measurements: PerformanceSummary;
  window_start: string;
  window_end: string;
}

export interface PerformanceBaseline {
  metric_name: string;
  asset_id: string | null;
  method: string;
  window_start: string;
  window_end: string;
  sample_count: number;
  median: number | null;
  p95: number | null;
  mad: number | null;
  note: string;
}

export interface PerformanceCapacity {
  metric_name: string;
  status: string;
  method: string;
  sample_count: number;
  growth_per_second: number | null;
  estimated_seconds_to_exhaustion: number | null;
  disclaimer: string;
  note: string;
  /** UI brief §9 forecast metadata (docs/performance/03_UI_SPEC.md §9). */
  observation_period?: string | null;
  coverage?: string | null;
  assumptions?: string | null;
  uncertainty?: string | null;
}

export interface PerformanceInvestigation {
  investigation: string;
  conclusion: string;
  change: Record<string, unknown>;
  before: PerformanceSummary;
  after: PerformanceSummary;
  difference_p95: number | null;
  affected_assets: string[];
  evidence: { proven: string[]; not_proven: string[] };
  note: string;
}

export interface PerformanceBenchmarkRun {
  run_id: string;
  measurement_kind: string;
  approved: boolean;
  method: Record<string, unknown>;
  results: Array<{ operation: string; mean_ms: number; min_ms: number; max_ms: number; samples: number }>;
  executed_at: string | null;
  note?: string;
}

export interface PerformanceHealth {
  engine: string;
  status: string;
  collectors: Array<{ collector_id: string; status: string; last_report_at: string | null; detail: string | null }>;
  checked_at: string;
  note: string;
}

export interface PerformanceWindow {
  tenant_id: string;
  window_start: string;
  window_end: string;
}

const performanceQuery = (params: object): string => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value !== undefined && value !== null && String(value) !== "") query.set(key, String(value));
  }
  const suffix = query.toString();
  return suffix ? `?${suffix}` : "";
};

/** Live systems: servers a Cryptava agent reports from, newest signed figures
 *  (GET /api/v1/performance/live-systems). A figure the agent could not read is in
 *  `missing` with its reason — never a zero. */
export interface LiveSystemMetric { value: number; unit: string; labels?: Record<string, string> }
export interface LiveSystem {
  agent: string;
  agent_id?: string | null;
  asset_id: string;
  host?: string | null;
  system?: string | null;
  ip?: string | null;
  scope?: "host" | "workload" | string | null;
  state: "live" | "stale" | "no_samples";
  last_sample_at?: string | null;
  age_seconds?: number | null;
  interval_seconds?: number | null;
  signed: boolean;
  metrics: Record<string, LiveSystemMetric>;
  tls: Array<{ port?: string | null; ms: number; tls_version?: string | null; algorithm?: string | null }>;
  missing: Array<{ metric: string; reason: string }>;
  trend: Record<string, Array<{ t: string; v: number }>>;
  samples: number;
}
export interface LiveSystems {
  tenant_id: string;
  generated_at: string;
  window_minutes: number;
  systems: LiveSystem[];
  counts: { systems: number; live: number; stale: number; no_samples: number };
  truncated: boolean;
  note: string;
}

export const apiPerformanceLiveSystems = (p: { tenant_id?: string; minutes?: number } = {}): Promise<ApiResult<LiveSystems>> =>
  call<LiveSystems>(`/api/v1/performance/live-systems${performanceQuery(p)}`);

export const apiPerformanceOverview = (p: PerformanceWindow): Promise<ApiResult<PerformanceOverview>> =>
  call<PerformanceOverview>(`/api/v1/performance/overview${performanceQuery(p)}`);

export const apiPerformanceDbWorkspace = (p: PerformanceWindow): Promise<ApiResult<PerformanceDbWorkspace>> =>
  call<PerformanceDbWorkspace>(`/api/v1/performance/databases/workspace${performanceQuery(p)}`);

export const apiPerformanceAppWorkspace = (p: PerformanceWindow): Promise<ApiResult<PerformanceAppWorkspace>> =>
  call<PerformanceAppWorkspace>(`/api/v1/performance/applications/workspace${performanceQuery(p)}`);

export const apiPerformanceInfraWorkspace = (p: PerformanceWindow): Promise<ApiResult<PerformanceInfraWorkspace>> =>
  call<PerformanceInfraWorkspace>(`/api/v1/performance/infrastructure/workspace${performanceQuery(p)}`);

export const apiPerformanceHsm = (p: PerformanceWindow): Promise<ApiResult<PerformanceHsm>> =>
  call<PerformanceHsm>(`/api/v1/performance/hsm${performanceQuery(p)}`);

export const apiPerformanceWorkloads = (p: PerformanceWindow): Promise<ApiResult<PerformanceWorkloads>> =>
  call<PerformanceWorkloads>(`/api/v1/performance/workloads${performanceQuery(p)}`);

export const apiPerformanceSamples = (p: PerformanceWindow & { metric_name?: string; limit?: number }): Promise<ApiResult<{ samples?: Array<Record<string, unknown>>; note?: string }>> =>
  call(`/api/v1/performance/samples${performanceQuery(p)}`);

export const apiPerformanceNetwork = (p: PerformanceWindow): Promise<ApiResult<PerformanceNetwork>> =>
  call<PerformanceNetwork>(`/api/v1/performance/network${performanceQuery(p)}`);

export const apiPerformanceStorage = (p: PerformanceWindow): Promise<ApiResult<PerformanceStorage>> =>
  call<PerformanceStorage>(`/api/v1/performance/storage${performanceQuery(p)}`);

export const apiPerformanceApplications = (p: PerformanceWindow): Promise<ApiResult<PerformanceApplications>> =>
  call<PerformanceApplications>(`/api/v1/performance/applications${performanceQuery(p)}`);

export const apiPerformanceDatabases = (p: PerformanceWindow): Promise<ApiResult<PerformanceDatabases>> =>
  call<PerformanceDatabases>(`/api/v1/performance/databases${performanceQuery(p)}`);

export const apiPerformanceCryptography = (p: PerformanceWindow): Promise<ApiResult<PerformanceCryptography>> =>
  call<PerformanceCryptography>(`/api/v1/performance/cryptography${performanceQuery(p)}`);

export const apiPerformanceInfrastructure = (p: PerformanceWindow): Promise<ApiResult<PerformanceDomain>> =>
  call<PerformanceDomain>(`/api/v1/performance/infrastructure${performanceQuery(p)}`);

export const apiPerformanceCloud = (p: PerformanceWindow): Promise<ApiResult<PerformanceDomain>> =>
  call<PerformanceDomain>(`/api/v1/performance/cloud${performanceQuery(p)}`);

export const apiPerformanceAsset = (assetId: string, p: PerformanceWindow): Promise<ApiResult<PerformanceAsset>> =>
  call<PerformanceAsset>(`/api/v1/performance/assets/${encodeURIComponent(assetId)}${performanceQuery(p)}`);

export const apiPerformanceAlerts = (p: PerformanceWindow & { metric_name?: string }): Promise<ApiResult<PerformanceAlert[]>> =>
  call<PerformanceAlert[]>(`/api/v1/performance/alerts${performanceQuery(p)}`);

export const apiPerformanceBaselines = (p: PerformanceWindow & { metric_name?: string }): Promise<ApiResult<PerformanceBaseline[]>> =>
  call<PerformanceBaseline[]>(`/api/v1/performance/baselines${performanceQuery(p)}`);

export const apiPerformanceCapacity = (p: PerformanceWindow & { metric_name?: string; capacity_value?: number }): Promise<ApiResult<PerformanceCapacity[]>> =>
  call<PerformanceCapacity[]>(`/api/v1/performance/capacity${performanceQuery(p)}`);

export const apiPerformanceInvestigation = (p: {
  tenant_id: string; metric_name: string; change_time: string;
  change_description: string; evidence_ids?: string;
}): Promise<ApiResult<PerformanceInvestigation>> =>
  call<PerformanceInvestigation>(`/api/v1/performance/reports${performanceQuery(p)}`);

export interface SimulationPerformanceContext {
  schema: string;
  purpose: "SIMULATION_INPUT";
  status: string;
  asset_ref: string;
  metric_name: string;
  unit: string;
  source_id: string;
  change: { event_id: string; observed_at: string; event_type: string;
    evidence_refs_unverified: string[]; provenance_note: string };
  before: { received: number; valid: number; signed_capture_samples: number; partial_quality: number;
    missing_or_stale: number; p95: number | null; metric_ids: string[];
    metric_ids_truncated: boolean };
  after: { received: number; valid: number; signed_capture_samples: number; partial_quality: number;
    missing_or_stale: number; p95: number | null; metric_ids: string[];
    metric_ids_truncated: boolean };
  delta_p95: number | null;
  delta_percent: number | null;
  causation: string;
  benchmark: { status: string; note: string; operations?: Array<{
    operation: string; baseline_mean_ms: number; candidate_mean_ms: number;
    delta_percent: number }> };
  not_proven: string[];
}

export const apiPerformanceBenchmarks = (p: { tenant_id: string }): Promise<ApiResult<{ runs: PerformanceBenchmarkRun[]; note: string }>> =>
  call<{ runs: PerformanceBenchmarkRun[]; note: string }>(`/api/v1/performance/benchmarks${performanceQuery(p)}`);

export const apiPerformanceRunBenchmark = (body: {
  tenant_id: string; algorithm: string; sample_count?: number;
}): Promise<ApiResult<PerformanceBenchmarkRun>> =>
  call<PerformanceBenchmarkRun>("/api/v1/performance/benchmarks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export const apiPerformanceHealth = (p: { tenant_id?: string }): Promise<ApiResult<PerformanceHealth>> =>
  call<PerformanceHealth>(`/api/v1/performance/health${performanceQuery(p)}`);

export const apiPerformanceSlo = (p: PerformanceWindow): Promise<ApiResult<Array<{
  policy_key: string; metric_name: string; objective: number;
  window_seconds: number; comparator: string; compliance: string; note: string;
}>>> =>
  call(`/api/v1/performance/slo${performanceQuery(p)}`);

/* --- Binary Intelligence (docs/binary-intelligence/01_PRODUCT_SPEC.md §12)
   --- */

export interface BinaryArtifact {
  artifact_id: string;
  sha256: string;
  file_size: number;
  detected_format: string;
  format_reason: string;
  original_filename: string;
  source_type: string;
  source_location?: string | null;
  uploaded_by: string;
  received_at?: string | null;
}

export interface BinaryEvidence {
  type: string;
  location: string;
  description: string;
  excerpt: string;
}

export interface BinaryFinding {
  finding_id: string;
  subject: string;
  finding_type: string;
  algorithm: string;
  variant: string;
  operation: string;
  mode_or_padding: string;
  key_size_bits: number | null;
  library: string;
  detection_method: string;
  evidence: BinaryEvidence[];
  confidence: string;
  usage_status: string;
  runtime_confirmed: boolean;
  quantum_vulnerable: boolean;
  pqc_family: boolean;
  limitations: string[];
  scanner_version: string;
  signature_database_version: string;
}

export interface BinaryCoverage {
  total_bytes: number;
  bytes_inspected: number;
  coverage_fraction: number;
  sections_total: number;
  sections_inspected: number;
  executable_sections: number;
  symbols_found: number;
  symbols_stripped: boolean;
  unresolved_dependencies: string[];
  unsupported_regions: string[];
  extraction_failures: string[];
  deep_analysis_completed: boolean;
  packed_or_encrypted_suspected: boolean;
  analysis_timeouts: number;
  note: string;
}

export interface BinaryPqcAssessment {
  quantum_vulnerable_algorithm_indicators: string;
  quantum_vulnerable_algorithms: string[];
  pqc_implementation_indicators: string;
  pqc_algorithms: string[];
  migration_blockers: string[];
  cryptographic_library: string;
  static_linking: string;
  source_availability: string;
  vendor_replacement_dependency: string;
  migration_readiness: string;
  limitations: string[];
  note: string;
}

export interface BinaryBomRelationship {
  source: string;
  relationship_type: string;
  target: string;
  provenance: string;
  evidence_class: string;
  limitations: string[];
}

export interface BinaryBom {
  schema: string;
  artifact_id: string;
  artifact_sha256: string;
  subject: string;
  components: Array<{ type: string; name: string; version: string; properties: Record<string, unknown> }>;
  relationships: BinaryBomRelationship[];
  sbom_components: Array<Record<string, unknown>>;
  cbom_assets: Array<Record<string, unknown>>;
  limitations: string[];
}

export interface BinaryScanResult {
  scan_id: string;
  artifact: BinaryArtifact;
  scan_profile: string;
  status: string;
  scanner_version: string;
  signature_database_version: string;
  finding_count: number;
  findings: BinaryFinding[];
  certificates: Array<Record<string, unknown>>;
  private_key_events: Array<Record<string, unknown>>;
  coverage: BinaryCoverage;
  pqc_assessment: BinaryPqcAssessment;
  notes: string[];
}

export interface BinaryComparison {
  base_artifact_id: string;
  against_artifact_id: string;
  deltas: Array<{ change: string; algorithm: string; variant: string; detail: string; caveat: string }>;
  summary: Record<string, number>;
  note: string;
}

const binaryQuery = performanceQuery;

export const apiBinaryArtifactScan = (body: {
  tenant_id: string;
  artifact_base64: string;
  original_filename: string;
  source_type?: string;
  scan_profile?: string;
}): Promise<ApiResult<BinaryScanResult>> =>
  call<BinaryScanResult>("/api/v1/binary/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const apiBinaryArtifact = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<BinaryArtifact>> =>
  call<BinaryArtifact>(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}${binaryQuery(p)}`);

export const apiBinaryFindings = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ artifact_id: string; findings: Array<BinaryFinding & { evidence: BinaryEvidence[] }>; note: string }>> =>
  call(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/findings${binaryQuery(p)}`);

export const apiBinaryCoverage = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<BinaryCoverage>> =>
  call<BinaryCoverage>(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/coverage${binaryQuery(p)}`);

export const apiBinaryPqc = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ findings: Array<{ quantum_vulnerable: boolean; pqc_family: boolean; algorithm: string; variant: string; confidence: string; usage_status: string; limitations: string[] }>; note: string }>> =>
  call(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/findings${binaryQuery(p)}`);

export const apiBinaryBom = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ artifact_id: string; bom: BinaryBom; note: string }>> =>
  call(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/bom${binaryQuery(p)}`);

export const apiBinaryComparison = (
  artifactId: string,
  p: { tenant_id: string; against_artifact_id: string },
): Promise<ApiResult<BinaryComparison>> =>
  call<BinaryComparison>(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/comparison${binaryQuery(p)}`);

export interface BinaryDriftPoint {
  artifact_id: string;
  sha256: string;
  received_at: string | null;
  original_filename: string;
  source_type: string;
  source_location: string | null;
  detected_format: string;
  scan_count: number;
  delta_vs_previous: {
    summary: Record<string, number>;
    deltas: Array<{ change: string; algorithm: string; variant: string; detail: string; caveat: string }>;
  } | null;
}

export interface BinaryDriftSeries {
  subject: string;
  points: BinaryDriftPoint[];
  summary: Record<string, number>;
  limitations: string[];
  note: string;
}

export interface BinaryHistory {
  artifact_id: string;
  runs: Array<Record<string, unknown>>;
  finding_timeline: Array<{
    finding_type: string;
    algorithm: string;
    variant: string;
    first_seen: string | null;
    first_scan: string;
    last_seen: string | null;
    last_scan: string;
    observations: Array<Record<string, unknown>>;
  }>;
  limitations: string[];
  note: string;
}

export interface BinaryEstate {
  findings_total: number;
  by_format: Record<string, number>;
  by_source_type: Record<string, number>;
  by_library: Record<string, number>;
  by_algorithm: Record<string, number>;
  quantum_vulnerable_findings: number;
  pqc_family_findings: number;
  note: string;
}

export const apiBinaryDrift = (
  p: { tenant_id: string; subject?: string; source_location?: string },
): Promise<ApiResult<BinaryDriftSeries>> =>
  call<BinaryDriftSeries>(`/api/v1/binary/drift${binaryQuery(p)}`);

export const apiBinaryHistory = (
  artifactId: string,
  p: { tenant_id: string },
): Promise<ApiResult<BinaryHistory>> =>
  call<BinaryHistory>(`/api/v1/binary/artifacts/${encodeURIComponent(artifactId)}/history${binaryQuery(p)}`);

export const apiBinaryEstate = (
  p: { tenant_id: string },
): Promise<ApiResult<BinaryEstate>> =>
  call<BinaryEstate>(`/api/v1/binary/estate${binaryQuery(p)}`);


export interface BinaryFirmwareLead {
  offset: number;
  kind: string;
  description: string;
  validated: boolean;
  validation_note: string;
}

export interface BinaryFirmwareReport {
  tool_name: string;
  tool_version: string;
  tool_available: boolean;
  analysis_completed: boolean;
  leads: BinaryFirmwareLead[];
  carved: Array<{
    index: number; offset: number; size: number; sha256: string; kind: string;
    findings: Array<{ subject: string; algorithm: string; variant: string; confidence: string; usage_status: string; key_size_bits: number | null }>;
    notes: string[];
  }>;
  limitations: string[];
  notes: string[];
  note: string;
}

export const apiBinaryFirmwareScan = (body: {
  tenant_id: string;
  artifact_base64: string;
  original_filename?: string;
  source_type?: string;
}): Promise<ApiResult<BinaryFirmwareReport>> =>
  call<BinaryFirmwareReport>("/api/v1/binary/firmware/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });

/* ── OS & Kernel Intelligence (docs/os-kernel-intelligence/01_PRODUCT_SPEC.md) ──
 * Read-only collection packages: the API records and serves what the
 * collector observed. Every capability row carries
 * runtime_usage_confirmed — a registered kernel implementation is
 * never proof of application usage (§2.2). */

export interface OSAssetRecord {
  asset_id: string;
  collection_id: string;
  kernel_name: string;
  kernel_release: string;
  kernel_version: string;
  machine: string;
  os_pretty_name: string;
  os_id: string;
  os_version_id: string;
  arch: string;
  cmdline: string;
  tainted_flags: string;
  tainted_meanings: string[];
  environment_development_only: boolean;
  qualification_note: string | null;
  collector_version: string;
  notes: string[];
  collected_at: string;
}

export interface OSCapability {
  algorithm: string;
  driver: string | null;
  type: string | null;
  module: string | null;
  priority: number | null;
  blocksize: number | null;
  digestsize: number | null;
  key_size_range: Array<number | null> | null;
  selftest: string | null;
  hardware_accelerated: boolean | null;
  runtime_usage_confirmed: boolean;
  parse_notes: string[];
}

export interface OSModule {
  name: string;
  size: number | null;
  refcount: number | null;
  used_by: string[];
  state: string;
}

export interface OSConfigFlag {
  flag: string;
  value: string;
  explicitly_disabled: boolean;
}

export interface OSStorageFact {
  device: string;
  fstype: string;
  metadata: Record<string, string>;
  notes: string[];
}

export interface OSTrustFact {
  subject: string;
  state: string;
  evidence_class: string;
  metadata: Record<string, string>;
  notes: string[];
}

export interface OSFindingRecord {
  finding_type: string;
  host_id: string | null;
  algorithm: string;
  implementation: string;
  evidence_source: string;
  observation_type: string;
  runtime_usage_confirmed: boolean;
  evidence_class: string;
  severity_label: string | null;
  severity_factors: { factors: Record<string, string>; derivation: string[] } | null;
  risk_model_version: string | null;
  details: Record<string, unknown>;
  limitations: string[];
}

export interface OSCoverage {
  sources_attempted: string[];
  sources_collected: string[];
  sources_unavailable: Array<{ source: string; reason: string }>;
  source_digests: Record<string, string>;
  note: string | null;
}

export interface OSRuleResult {
  rule_id: string;
  detection: string;
  potential_impact: string;
  status: "evaluated" | "not_evaluable";
  evaluation_note: string;
  findings: OSFindingRecord[];
}

export interface OSRuleEvaluation {
  rule_model_version: string;
  results: OSRuleResult[];
  note: string;
}

const osQuery = (p: { tenant_id: string }) =>
  `?tenant_id=${encodeURIComponent(p.tenant_id)}`;

export const apiOSAssets = (
  p: { tenant_id: string },
): Promise<ApiResult<{ assets: OSAssetRecord[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets${osQuery(p)}`);

export const apiOSAsset = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<OSAssetRecord>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}${osQuery(p)}`);

export const apiOSCapabilities = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ capabilities: OSCapability[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/crypto-capabilities${osQuery(p)}`);

export const apiOSModules = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ modules: OSModule[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/modules${osQuery(p)}`);

export const apiOSConfigFlags = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ flags: OSConfigFlag[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/config-flags${osQuery(p)}`);

export const apiOSStorage = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ storage: OSStorageFact[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/storage${osQuery(p)}`);

export const apiOSHardwareTrust = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ hardware_trust: OSTrustFact[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/hardware-trust${osQuery(p)}`);

export const apiOSFindings = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ findings: OSFindingRecord[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/findings${osQuery(p)}`);

export const apiOSCoverage = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<OSCoverage>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/coverage${osQuery(p)}`);

export const apiOSRules = (): Promise<ApiResult<{
  rules: Array<{ rule_id: string; detection: string; potential_impact: string }>;
  note: string;
}>> => call("/api/v1/os-intelligence/rules");

export const apiOSRuleEvaluation = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<OSRuleEvaluation>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/rule-evaluation${osQuery(p)}`);

export interface OSBomComponent {
  type: string;
  name: string;
  version: string;
  properties: Record<string, unknown> & {
    runtime_usage_confirmed?: boolean;
    key_size_bits?: number[] | null;
    limitations?: string[];
  };
}

export interface OSBomRelationship {
  source: string;
  relationship: string;
  target: string;
  provenance: string;
  limitations: string[];
}

export interface OSBom {
  schema: string;
  kind: string;
  subject: string;
  components: OSBomComponent[];
  relationships: OSBomRelationship[];
  coverage: Record<string, unknown>;
  note: string;
}

export const apiOSBom = (
  assetId: string,
  p: { tenant_id: string; kind: string },
): Promise<ApiResult<OSBom>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/bom?tenant_id=${encodeURIComponent(p.tenant_id)}&kind=${encodeURIComponent(p.kind)}`);

export interface OSCertificate {
  certificate_id: string;
  collection_id: string;
  subject: string;
  issuer: string;
  not_before: string | null;
  not_after: string | null;
  thumbprint_sha256: string | null;
  public_key_algorithm: string | null;
  public_key_bits: number | null;
  evidence_class: string;
  evidence_source: string | null;
  limitations: string[];
  collected_at: string;
}

export interface OSRuntimeSession {
  session_id: string;
  boot_id: string | null;
  collection_profile: string;
  evidence_source: string | null;
  started_at: string | null;
  ended_at: string | null;
  attached_points: string[];
  events_accepted: number;
  events_lost: number;
  refusals: Array<{ where: string; reason: string }>;
  notes: string[];
  collected_at: string;
}

export interface OSRuntimeEvent {
  event_id: string;
  session_id: string;
  boot_id: string | null;
  process_id: string | null;
  process_start_time: string | null;
  executable_digest: string | null;
  operation_category: string;
  algorithm_identifier: string | null;
  provider_identifier: string | null;
  kernel_or_userspace: string | null;
  interface: string | null;
  timestamp: string | null;
  evidence_source: string | null;
  collection_profile: string | null;
  collected_at: string;
}

export interface OSRuntimeUsage {
  algorithm: string;
  implementation: string;
  runtime_usage_confirmed: boolean;
  evidence_class: string;
  observed_processes: string[];
  confirmed_by_events: string[];
  note: string;
}

export const apiOSRuntimeSessions = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ sessions: OSRuntimeSession[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/runtime-sessions?tenant_id=${encodeURIComponent(p.tenant_id)}`);

export const apiOSRuntimeEvents = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ events: OSRuntimeEvent[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/runtime-events?tenant_id=${encodeURIComponent(p.tenant_id)}`);

export const apiOSRuntimeUsage = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ confirmations: OSRuntimeUsage[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/runtime-usage?tenant_id=${encodeURIComponent(p.tenant_id)}`);

export const apiOSCertificates = (
  assetId: string,
  p: { tenant_id: string },
): Promise<ApiResult<{ certificates: OSCertificate[]; note: string }>> =>
  call(`/api/v1/os-intelligence/assets/${encodeURIComponent(assetId)}/certificates?tenant_id=${encodeURIComponent(p.tenant_id)}`);

/* ── PQC Migration Intelligence (api/routers/pqc_migration.py) ─────────────
   The persisted plan state behind the migration workspace: waves, blockers,
   interoperability notes and verified progress. Verified is written only by an
   explicit verification action with an evidence reference — a recorded claim is
   never progress proven. State moves only along the canonical state machine
   register (pqc.wave_status / pqc.blocker_state / pqc.progress_verification). */

export interface PqcMigrationWaveRow {
  id: string; wave_key: string; title: string; scope_note: string;
  planned_window: string | null; status: string; status_note: string | null;
  created_at?: string | null; updated_at?: string | null;
}
export interface PqcMigrationBlockerRow {
  id: string; wave_id: string; title: string; detail: string; state: string;
  raised_by: string; raised_at: string | null; resolved_by: string | null;
  resolved_at: string | null; resolution_note: string | null;
}
export interface PqcInteropNoteRow {
  id: string; wave_id: string; peer_system: string; protocol: string; note: string;
  evidence_ids: string[]; recorded_by: string;
}
export interface PqcProgressRow {
  id: string; wave_id: string; claim: string; evidence_ids: string[];
  recorded_by: string; verification_status: string; verified_by: string | null;
  verified_at: string | null; verification_note: string | null;
  claim_is_not_proof: boolean;
}
export interface PqcMigrationSummary {
  wave_count: number; waves_verified: number; waves_blocked: number;
  blockers_open: number; blockers_accepted: number;
  progress_recorded: number; progress_verified: number;
  progress_refuted: number; progress_stale: number; honesty: string;
}
export interface PqcMigrationWorkspace {
  waves: PqcMigrationWaveRow[]; blockers: PqcMigrationBlockerRow[];
  interop: PqcInteropNoteRow[]; progress: PqcProgressRow[];
  summary: PqcMigrationSummary;
}

export const apiPqcMigrationWorkspace = (): Promise<ApiResult<PqcMigrationWorkspace>> =>
  call("/api/v1/pqc-migration/workspace");
export const apiPqcMigrationCreateWave = (body: {
  wave_key: string; title: string; scope_note?: string; planned_window?: string | null;
}): Promise<ApiResult<PqcMigrationWaveRow>> =>
  call("/api/v1/pqc-migration/waves", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationTransitionWave = (waveKey: string, body: {
  to: string; note?: string | null;
}): Promise<ApiResult<PqcMigrationWaveRow>> =>
  call(`/api/v1/pqc-migration/waves/${encodeURIComponent(waveKey)}/transition`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationRecordProgress = (waveKey: string, body: {
  claim: string; evidence_ids?: string[];
}): Promise<ApiResult<PqcProgressRow>> =>
  call(`/api/v1/pqc-migration/waves/${encodeURIComponent(waveKey)}/progress`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationTransitionProgress = (recordId: string, body: {
  to: string; note?: string | null; evidence_ids?: string[];
}): Promise<ApiResult<PqcProgressRow>> =>
  call(`/api/v1/pqc-migration/progress/${encodeURIComponent(recordId)}/transition`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationRaiseBlocker = (waveKey: string, body: {
  title: string; detail?: string;
}): Promise<ApiResult<PqcMigrationBlockerRow>> =>
  call(`/api/v1/pqc-migration/waves/${encodeURIComponent(waveKey)}/blockers`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationTransitionBlocker = (blockerId: string, body: {
  to: string; note?: string | null;
}): Promise<ApiResult<PqcMigrationBlockerRow>> =>
  call(`/api/v1/pqc-migration/blockers/${encodeURIComponent(blockerId)}/transition`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const apiPqcMigrationRecordInterop = (waveKey: string, body: {
  peer_system: string; protocol?: string; note?: string; evidence_ids?: string[];
}): Promise<ApiResult<PqcInteropNoteRow>> =>
  call(`/api/v1/pqc-migration/waves/${encodeURIComponent(waveKey)}/interop`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
