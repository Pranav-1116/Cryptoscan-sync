/**
 * SBOM workspace (docs/boms/01_PRODUCT_SPEC.md §1):
 * the twelve-section shell, the spec's inventory columns, the component
 * detail with the essential usage-state distinction, and honest empty
 * states — an unread or empty inventory is never a fabricated package list.
 */
import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, afterEach } from "vitest";
import { mockFetch } from "../test/setup";
import Sbom from "../pages/Sbom";

const inRouter = (ui: React.ReactElement) =>
  render(<MemoryRouter initialEntries={["/sbom"]}>{ui}</MemoryRouter>);

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const SPEC_TABS = [
  "SBOM Overview", "Software Inventory", "Package & Component Explorer",
  "Dependency Tree", "License Intelligence", "Vulnerability Intelligence",
  "Version & Lifecycle", "Container SBOM", "Binary SBOM",
  "SBOM Evidence", "SBOM History", "Export & Validation",
];

const ROW = {
  coordinate: "pypi/cryptography@42.0.0", name: "cryptography", version: "42.0.0",
  ecosystem: "pypi", purl: "pkg:pypi/cryptography@42.0.0", source: "MANIFEST_DECLARED",
  license: null, vulnerability: { count: 0, max_severity: null },
  evidence: { type: "MANIFEST" }, last_observed: "2026-11-13T00:00:00",
};

const DETAIL = {
  component: ROW,
  usage_states: [{ algorithm: "RSA", usage_state: "capability_detected", basis: "MANIFEST_DECLARED", runtime_evidence: [] }],
  supplier: null, dependencies: { direct: [], transitive: [], unresolved_parent: false },
  vulnerabilities: [], manifests: ["requirements.txt"], versions: ["42.0.0"],
  flags: { declared_but_unused: false, used_but_undeclared: false },
};

describe("SBOM workspace shell", () => {
  it("draws the twelve spec sections", () => {
    mockFetch({});
    inRouter(<Sbom />);
    for (const label of SPEC_TABS) expect(screen.getByRole("tab", { name: label })).toBeTruthy();
  });

  it("renders the spec's inventory columns and opens the component detail", async () => {
    mockFetch({
      "/api/v1/sbom/components": { state: "OBSERVED", total: 1, rows: [ROW] },
      "/api/v1/sbom/components/*": DETAIL,
      "/api/v1/technology-bom": {},
    });
    inRouter(<Sbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Software Inventory" }));
    await waitFor(() => expect(screen.getByText("cryptography")).toBeTruthy());
    for (const column of ["Component", "Version", "Ecosystem", "Application", "Source",
                         "License", "Vulnerability", "Evidence", "Last observed"]) {
      expect(screen.getByText(column)).toBeTruthy();
    }
    // a missing license is labelled, never assumed permissive
    expect(screen.getAllByText("NOT_COLLECTED").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("cryptography"));
    await waitFor(() => expect(screen.getAllByText(/pkg:pypi\/cryptography@42.0.0/).length).toBeGreaterThan(0));
    // the essential distinction is drawn as state badges, not flattened
    expect(screen.getAllByText("capability_detected").length).toBeGreaterThan(0);
  });

  it("keeps unread inventories honest", async () => {
    mockFetch({});
    inRouter(<Sbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Dependency Tree" }));
    await waitFor(() => expect(screen.getAllByText(/not read/i).length).toBeGreaterThan(0));
  });

  it("keeps empty inventories honest — placeholders, never zeros", async () => {
    mockFetch({ "/api/v1/sbom/dependencies": { state: "OBSERVED", edges: [], roots: [], unresolved: 0 } });
    inRouter(<Sbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Dependency Tree" }));
    await waitFor(() => expect(screen.getAllByText(/Nothing stored yet/).length).toBeGreaterThan(0));
    expect(screen.queryByText(/^0$/)).toBeNull();
  });
});
