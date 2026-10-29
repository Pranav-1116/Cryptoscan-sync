/* Governance + Administration console contracts.
 *
 * These screens are read-outs of one control-plane source each, so the tests
 * pin the two failure modes an operator hits:
 *   1. one refused endpoint must not blank the other sources on the page
 *      (Identity reads /auth/me, /auth/users, /auth/roles, /auth/sso/status);
 *   2. a value the backend did not report must not be rendered as a number
 *      (delivery counters, engine asset counts, sessions).
 */
import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockFetch } from "../test/setup";
import Identity from "./Identity";
import Integrations from "./Integrations";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const me = {
  username: "admin", roles: ["superadmin"], permissions: ["users.manage"],
  mfa_enabled: false, display_name: "Bootstrap Admin", email: null,
  active_sessions: 5, is_active: true,
};
const users = [
  { username: "admin", display_name: "Bootstrap Admin", email: null, roles: ["superadmin"], is_active: true },
];
// The role catalogue is a name -> description map on the wire.
const roles = {
  roles: {
    superadmin: "Full access (platform configuration)",
    auditor: "Read-only access to all reports",
  },
};

function identityRoutes(overrides: Record<string, unknown> = {}) {
  return mockFetch({
    "/api/v1/auth/me": me,
    "/api/v1/auth/users": users,
    "/api/v1/auth/roles": roles,
    "/api/v1/auth/sso/status": { oidc: { enabled: false, authorize_url: null }, saml_enabled: false, ldap_enabled: false },
    ...overrides,
  });
}

describe("Identity & access governance", () => {
  it("renders the role catalogue the backend returns instead of treating the map as a list", async () => {
    identityRoutes();
    render(<Identity />);

    expect((await screen.findAllByText("superadmin")).length).toBeGreaterThan(0);
    expect(screen.getByText("Full access (platform configuration)")).toBeTruthy();
    expect(screen.getByText("Read-only access to all reports")).toBeTruthy();
    // active_sessions is echoed, not defaulted
    expect(screen.getByText("5")).toBeTruthy();
  });

  it("keeps roles and the signed-in user when one source is refused", async () => {
    identityRoutes({
      "/api/v1/auth/users": new Response(JSON.stringify({ detail: "directory unavailable" }), { status: 503 }),
    });
    render(<Identity />);

    // the signed-in identity still renders…
    expect((await screen.findAllByText("admin")).length).toBeGreaterThan(0);
    // …and so does the role catalogue, even though the directory read failed
    expect((await screen.findAllByText("auditor")).length).toBeGreaterThan(0);
    expect(await screen.findByText(/User list not read/)).toBeTruthy();
    // the whole page is not marked unavailable
    expect(screen.queryByText(/Identity data unavailable/)).toBeNull();
  });

  it("does not offer SP metadata when SAML is not configured", async () => {
    identityRoutes();
    render(<Identity />);

    await screen.findAllByText("superadmin");
    // No anchor: the endpoint 404s ("SAML SSO is not configured"), so the page
    // shows an aria-disabled affordance that explains why.
    expect(screen.queryByRole("link", { name: "SAML Metadata" })).toBeNull();
    const affordance = screen.getByText("SAML Metadata");
    expect(affordance.getAttribute("aria-disabled")).toBe("true");
    expect(affordance.getAttribute("title")).toMatch(/SAML is not configured/);
  });
});

function integrationRoutes(overrides: Record<string, unknown> = {}) {
  return mockFetch({
    "/api/v1/enterprise/integrations": { integrations: [] },
    "/api/v1/control/deliveries": { deliveries: [], stats: {}, count: 0 },
    "/api/v1/control/credentials": { credentials: [] },
    "/api/v1/control/credential-leases": { leases: [] },
    ...overrides,
  });
}

describe("Integrations console", () => {
  it("reports delivery counters as not reported rather than zero", async () => {
    integrationRoutes();
    render(<Integrations />);

    expect(await screen.findByText("DELIVERED — NOT REPORTED")).toBeTruthy();
    expect(screen.getByText("FAILED — NOT REPORTED")).toBeTruthy();
    expect(screen.queryByText("0 DELIVERED")).toBeNull();
  });

  it("registers a destination through the endpoint the copy promises", async () => {
    const fetchMock = integrationRoutes();
    render(<Integrations />);

    expect(await screen.findByText(/No integrations registered yet/)).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText("splunk / servicenow"), { target: { value: "splunk" } });
    fireEvent.change(screen.getByPlaceholderText("SIEM prod"), { target: { value: "SIEM prod" } });
    fireEvent.change(screen.getByPlaceholderText("https://siem.internal/ingest"), { target: { value: "https://siem.example/ingest" } });
    fireEvent.click(screen.getByRole("button", { name: "Register destination" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/enterprise/integrations",
      expect.objectContaining({ method: "POST" })));
    const call = fetchMock.mock.calls.find(([url, init]) =>
      String(url).endsWith("/api/v1/enterprise/integrations") && (init as RequestInit | undefined)?.method === "POST");
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toMatchObject({
      kind: "siem", provider: "splunk", name: "SIEM prod", endpoint: "https://siem.example/ingest",
    });
  });

  it("surfaces a refused registration verbatim", async () => {
    integrationRoutes({
      "/api/v1/enterprise/integrations": (url: string, init?: RequestInit) =>
        init?.method === "POST"
          ? new Response(JSON.stringify({ detail: "unsafe integration endpoint: private address 10.0.0.4" }), { status: 422 })
          : { integrations: [] },
    });
    render(<Integrations />);

    await screen.findByText(/No integrations registered yet/);
    fireEvent.change(screen.getByPlaceholderText("splunk / servicenow"), { target: { value: "siem" } });
    fireEvent.change(screen.getByPlaceholderText("SIEM prod"), { target: { value: "SIEM" } });
    fireEvent.click(screen.getByRole("button", { name: "Register destination" }));

    expect(await screen.findByText(/registration refused: unsafe integration endpoint/)).toBeTruthy();
  });
});
