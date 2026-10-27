/* OrgSwitcher (Tenancy page) — the frontend half of the tenant_id chain.
 *
 * The picker lists exactly what GET /saas/memberships returns (derived from
 * the membership table), picking an org stores it via setActiveTenantId,
 * and every subsequent API call carries it as X-Tenant-ID. These tests pin
 * the connect contract: render from memberships, switch on click, notify
 * the page, and stay hidden for single-org users.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { activeTenantId, setActiveTenantId } from "../lib/api";
import Tenancy from "./Tenancy";

const ROUTES = {
  "/api/v1/saas/memberships": { tenants: [
    { id: "acme", name: "Acme Bank", slug: "acme", plan: "ENTERPRISE", status: "ACTIVE", tenant_role: "member" },
    { id: "globex", name: "Globex", slug: "globex", plan: "TEAM", status: "ACTIVE", tenant_role: "owner" },
  ] },
  "/api/v1/saas/whoami": { username: "dual", tenant_id: "acme", tenant_name: "Acme Bank",
    tenant_slug: "acme", tenant_role: "member", plan: "ENTERPRISE", tenant_status: "ACTIVE",
    is_platform_admin: false },
  "/api/v1/saas/usage": { meters: {} },
};

describe("OrgSwitcher — the tenant picker on the tenancy page", () => {
  beforeEach(() => {
    setActiveTenantId("acme");
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(() => {
    setActiveTenantId(null);
    vi.useRealTimers();
  });

  it("renders one button per membership and marks the active org", async () => {
    mockFetch(ROUTES);
    renderWithProviders(<Tenancy />);
    // whoami panel and the switcher both name the active org — that is fine
    await waitFor(() => expect(screen.getAllByText("Acme Bank").length).toBeGreaterThan(0));
    expect(screen.getByText("Globex")).toBeTruthy();
    // the active org is labeled in the switcher
    expect(screen.getByText("ACTIVE")).toBeTruthy();
  });

  it("switching stores the org and every later call carries it as X-Tenant-ID", async () => {
    const spy = mockFetch(ROUTES);
    renderWithProviders(<Tenancy />);
    await waitFor(() => screen.getByText("Globex"));
    fireEvent.click(screen.getByText("Globex"));
    expect(activeTenantId()).toBe("globex");
    expect(localStorage.getItem("cryptoscan_tenant")).toBe("globex");
    // the next API call carries the switched header
    await waitFor(() => {
      const calls = spy.mock.calls.filter(([p]) => String(p).includes("/api/v1/saas/"));
      const last = calls[calls.length - 1] as [string, RequestInit];
      const headers = last[1].headers as Record<string, string>;
      expect(headers["X-Tenant-ID"]).toBe("globex");
    });
  });

  it("hides the platform estate option for non-admin members", async () => {
    mockFetch(ROUTES);
    renderWithProviders(<Tenancy />);
    await waitFor(() => screen.getByText("Globex"));
    expect(screen.queryByText("Platform estate (no organization)")).toBeNull();
  });

  it("offers the platform estate to platform admins and clears the header", async () => {
    mockFetch({
      ...ROUTES,
      "/api/v1/saas/whoami": { ...ROUTES["/api/v1/saas/whoami"], is_platform_admin: true },
    });
    renderWithProviders(<Tenancy />);
    await waitFor(() => screen.getByText("Platform estate (no organization)"));
    fireEvent.click(screen.getByText("Platform estate (no organization)"));
    expect(activeTenantId()).toBeNull();
    expect(localStorage.getItem("cryptoscan_tenant")).toBeNull();
  });

  it("stays hidden when the user belongs to no organization", async () => {
    mockFetch({ ...ROUTES, "/api/v1/saas/memberships": { tenants: [] } });
    renderWithProviders(<Tenancy />);
    await waitFor(() => screen.getByText("Acme Bank")); // whoami panel renders
    expect(screen.queryByText("Switch organization")).toBeNull();
  });
});
