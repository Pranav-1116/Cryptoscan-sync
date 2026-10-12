/* The API bridge: the contract every page relies on.
 * Offline → { source: "offline", data: null }; never throws; auth headers
 * and tenant header travel on every call; tokens live in localStorage. */
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import {
  activeTenantId, apiLogin, apiScope, getRoles, getToken, getUserName,
  isBackendLive, setActiveTenantId, setToken, setUserName, syncSession,
} from "./api";

describe("api bridge — offline contract", () => {
  it("returns an offline result instead of throwing when the backend is down", async () => {
    offlineFetch();
    const result = await apiScope();
    expect(result.source).toBe("offline");
    expect(result.data).toBeNull();
    expect(result.error).toMatch(/fetch/i);
  });

  it("maps a non-2xx status to offline with the HTTP code", async () => {
    mockFetch({}, 503);
    const result = await apiScope();
    expect(result).toMatchObject({ source: "offline", data: null, error: "HTTP 503" });
  });

  it("returns live data on 200", async () => {
    mockFetch({ "/api/v1/platform/scope": { does: ["scan"], does_not: ["malware"] } });
    const result = await apiScope();
    expect(result.source).toBe("live");
    expect(result.data).toEqual({ does: ["scan"], does_not: ["malware"] });
  });
});

describe("backend reachability — scope response truth", () => {
  const scope = { platform: "CryptoScan", schema_version: 2, covered_areas: [], non_goals: [] };
  const route = "/api/v1/platform/scope";
  const response = (body: string, status: number, headers: Record<string, string>) =>
    new Response(body, { status, headers });

  it("rejects Vite's HTML SPA fallback even when it answers 200", async () => {
    mockFetch({ [route]: response("<!doctype html><html></html>", 200, { "Content-Type": "text/html" }) });
    expect(await isBackendLive()).toBe(false);
  });

  it("accepts only a scope-shaped JSON 200, not arbitrary JSON or malformed JSON", async () => {
    mockFetch({ [route]: scope });
    expect(await isBackendLive()).toBe(true);
    mockFetch({ [route]: { detail: "proxy ready" } });
    expect(await isBackendLive()).toBe(false);
    mockFetch({ [route]: { platform: "CryptoScan", schema_version: 2 } });
    expect(await isBackendLive()).toBe(false);
    mockFetch({ [route]: response("not json", 200, { "Content-Type": "application/json" }) });
    expect(await isBackendLive()).toBe(false);
  });

  it.each([401, 403])("recognizes a real JSON %i auth response, but not HTML", async (status) => {
    mockFetch({ [route]: response(JSON.stringify({ detail: "Authentication required" }), status, { "Content-Type": "application/json" }) });
    expect(await isBackendLive()).toBe(true);
    mockFetch({ [route]: response("<html>upstream error</html>", status, { "Content-Type": "text/html" }) });
    expect(await isBackendLive()).toBe(false);
  });

  it("recognizes a Bearer challenge without JSON, not a proxy's Basic challenge", async () => {
    mockFetch({ [route]: response("", 401, { "WWW-Authenticate": "Bearer" }) });
    expect(await isBackendLive()).toBe(true);
    mockFetch({ [route]: response("", 401, { "WWW-Authenticate": "Basic realm=proxy" }) });
    expect(await isBackendLive()).toBe(false);
    mockFetch({ [route]: response("<html>proxy</html>", 401, { "Content-Type": "text/html", "WWW-Authenticate": "Bearer" }) });
    expect(await isBackendLive()).toBe(false);
  });

  it("rejects 404, 5xx and network failures", async () => {
    mockFetch({}, 404);
    expect(await isBackendLive()).toBe(false);
    mockFetch({ [route]: response(JSON.stringify(scope), 502, { "Content-Type": "application/json" }) });
    expect(await isBackendLive()).toBe(false);
    offlineFetch();
    expect(await isBackendLive()).toBe(false);
  });

  it("retries after a failure and rechecks after success with current auth and tenant", async () => {
    offlineFetch();
    expect(await isBackendLive()).toBe(false);
    const fetchSpy = mockFetch({ [route]: scope });
    expect(await isBackendLive()).toBe(true);
    setToken("new-session");
    setActiveTenantId("new-tenant");
    const nextFetch = mockFetch({ [route]: response("<html>offline</html>", 200, { "Content-Type": "text/html" }) });
    expect(await isBackendLive()).toBe(false);
    const [, init] = nextFetch.mock.calls[0] as [string, RequestInit];
    expect(init.headers).toMatchObject({ Authorization: "Bearer new-session", "X-Tenant-ID": "new-tenant" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

describe("api bridge — auth + tenancy headers", () => {
  it("sends the bearer token and the active tenant on every call", async () => {
    setToken("tok-123");
    setActiveTenantId("tenant-a");
    const fetchSpy = mockFetch({ "/api/v1/platform/scope": {} });
    await apiScope();
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok-123");
    expect(headers["X-Tenant-ID"]).toBe("tenant-a");
    expect(init.credentials).toBe("include");
  });

  it("omits auth headers when signed out", async () => {
    const fetchSpy = mockFetch({ "/api/v1/platform/scope": {} });
    await apiScope();
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(headers["X-Tenant-ID"]).toBeUndefined();
  });

  it("clearing the token also forgets roles and user name", () => {
    setToken("t");
    setUserName("alice");
    localStorage.setItem("zelinx_roles", JSON.stringify(["auditor"]));
    expect(getRoles()).toEqual(["auditor"]);
    setToken(null);
    expect(getToken()).toBeNull();
    expect(getRoles()).toEqual([]);
    expect(getUserName()).toBeNull();
  });

  it("tenant selection round-trips through storage", () => {
    expect(activeTenantId()).toBeNull();
    setActiveTenantId("t-9");
    expect(activeTenantId()).toBe("t-9");
    setActiveTenantId(null);
    expect(activeTenantId()).toBeNull();
  });
});

describe("apiLogin", () => {
  it("stores token + roles on success", async () => {
    mockFetch({ "/api/v1/auth/login": { token: "jwt-1", roles: ["superadmin"], username: "admin" } });
    const result = await apiLogin("admin", "pw");
    expect(result.ok).toBe(true);
    expect(getToken()).toBe("jwt-1");
    expect(getRoles()).toEqual(["superadmin"]);
  });

  it("surfaces the server's detail on a 401 and stores nothing", async () => {
    mockFetch({ "/api/v1/auth/login": () => new Response(JSON.stringify({ detail: "Invalid credentials" }), { status: 401 }) });
    const result = await apiLogin("admin", "wrong");
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Invalid credentials");
    expect(getToken()).toBeNull();
  });

  it("does not throw when the backend is unreachable", async () => {
    offlineFetch();
    const result = await apiLogin("admin", "pw");
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe("syncSession", () => {
  it("adopts the server profile when /auth/me answers", async () => {
    mockFetch({ "/api/v1/auth/me": { username: "bob", roles: ["viewer"] } });
    const session = await syncSession();
    expect(session).toEqual({ user: "bob", roles: ["viewer"] });
    expect(getUserName()).toBe("bob");
  });

  it("clears the cached profile when offline instead of authorizing stale state", async () => {
    setUserName("cached");
    localStorage.setItem("zelinx_roles", JSON.stringify(["auditor"]));
    offlineFetch();
    const session = await syncSession();
    expect(session).toEqual({ user: null, roles: [] });
    expect(getUserName()).toBeNull();
    expect(getRoles()).toEqual([]);
  });
});
