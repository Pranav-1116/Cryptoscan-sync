import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { AuthProvider } from "../lib/auth";
import { activeTenantId } from "../lib/api";
import { mockFetch } from "../test/setup";
import { EnterpriseProvider, useEnterprise } from "./EnterpriseContext";

function Selected() {
  const { org } = useEnterprise();
  return <output data-testid="estate">{activeTenantId() || "none"} · {org.name}</output>;
}

function mount() {
  render(<AuthProvider><MemoryRouter><EnterpriseProvider><Selected /></EnterpriseProvider></MemoryRouter></AuthProvider>);
}

const profile = { username: "reader", roles: ["readonly"] };

describe("single-tenant session display", () => {
  it("selects exactly one active server membership and uses its real name", async () => {
    mockFetch({
      "/api/v1/auth/me": profile,
      "/api/v1/saas/memberships": { tenants: [{ id: "lab-id", name: "Synthetic Sandbox", slug: "synthetic-lab", status: "ACTIVE", tenant_role: "viewer" }] },
      "/api/v1/scope/tenant/isolation": { tenants: [{ id: "lab-id", name: "Synthetic Sandbox", sector: "lab" }] },
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("estate")).toHaveTextContent("lab-id · Synthetic Sandbox"));
  });

  it("does not guess a tenant when the session has multiple memberships", async () => {
    mockFetch({
      "/api/v1/auth/me": profile,
      "/api/v1/saas/memberships": { tenants: [
        { id: "a", name: "A", status: "ACTIVE" }, { id: "b", name: "B", status: "ACTIVE" },
      ] },
    });
    mount();
    await waitFor(() => expect(screen.getByTestId("estate")).toHaveTextContent("none · Platform"));
    expect(activeTenantId()).toBeNull();
  });
});
