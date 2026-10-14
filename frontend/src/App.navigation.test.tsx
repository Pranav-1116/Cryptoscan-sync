import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

// Exercise the real BrowserRouter route table with authentication already
// satisfied; auth itself is covered separately and must remain fail-closed.
vi.mock("./lib/auth.js", () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  RequireAuth: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock("./lib/realtime.js", () => ({
  RealtimeProvider: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock("./components/Layout.jsx", () => ({
  default: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock("./pages/SecurityCenter", () => ({ default: () => <h1>Audit workspace</h1> }));
vi.mock("./pages/Remediation", () => ({ default: () => <h1>Remediation tasks workspace</h1> }));
vi.mock("./pages/LiveAssetIntelligence", () => ({ default: () => <h1>Technology BOM workspace</h1> }));
vi.mock("./pages/CommandCenter", () => ({ default: () => <h1>Command center workspace</h1> }));

import App from "./App";

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("authenticated legacy deep links", () => {
  it.each([
    ["/audit", "/security-center", "Audit workspace"],
    ["/techbom", "/live-asset-intelligence", "Technology BOM workspace"],
  ])("redirects %s to %s without a duplicate implementation", async (entry, destination, title) => {
    window.history.replaceState(null, "", entry);
    render(<App />);
    expect(await screen.findByRole("heading", { name: title })).toBeInTheDocument();
    expect(window.location.pathname).toBe(destination);
  });

  it("serves /remediation as its own workspace, not a priorities redirect", async () => {
    window.history.replaceState(null, "", "/remediation");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Remediation tasks workspace" })).toBeInTheDocument();
    expect(window.location.pathname).toBe("/remediation");
  });

  it("does not expose the retired Merkle screen as a working route", async () => {
    window.history.replaceState(null, "", "/audit-merkle");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Command center workspace" })).toBeInTheDocument();
    expect(window.location.pathname).toBe("/command-center");
  });
});
