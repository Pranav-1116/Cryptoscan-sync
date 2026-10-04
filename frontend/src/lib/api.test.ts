/* The API bridge: the contract every page relies on.
 * Offline → { source: "offline", data: null }; never throws; auth headers
 * and tenant header travel on every call; tokens live in localStorage. */
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import {
  activeTenantId, apiLogin, apiScope, getRoles, getToken, getUserName,
  setActiveTenantId, setToken, setUserName, syncSession,
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
