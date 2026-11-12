// TechBOM workspace pins (docs/boms/01_PRODUCT_SPEC.md §6 + §9).
// The working rule: a relationship exists only where stored evidence
// establishes it — Related BOMs cite primary records and verified links
// only, reconciliation connects records only when the evidence does, and
// evidence states (Measured/Imported/Inferred/Unknown/Contradicted) are
// never collapsed into a generic green.
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import LiveAssetIntelligence from "./LiveAssetIntelligence";
import { mockFetch } from "../test/setup";

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/live-asset-intelligence"]}>
      <LiveAssetIntelligence />
    </MemoryRouter>,
  );
}

const SYSTEM_ROW = {
  asset_ref: "app:sys-pay", name: "payments", category: "SOFTWARE", vendor: "",
  product_version: "", environment: "Production",
  related: { SBOM: "PRIMARY_RECORD", CBOM: "LINKED", HBOM: "NOT_ESTABLISHED", NBOM: "NOT_ESTABLISHED", VBOM: "LINKED", TechBOM: "NOT_ESTABLISHED" },
  dependencies: 3,
  evidence: { state: "UNKNOWN", freshness: "NOT_COLLECTED", basis: "registration only — no collector evidence recorded for this system" },
  last_observed: "2026-11-01T00:00:00Z",
};

const HSM_ROW = {
  asset_ref: "hw:hsm-1", name: "payHSM", category: "HARDWARE", vendor: "Thales",
  product_version: "hsm", environment: "",
  related: { SBOM: "NOT_ESTABLISHED", CBOM: "NOT_ESTABLISHED", HBOM: "PRIMARY_RECORD", NBOM: "NOT_ESTABLISHED", VBOM: "NOT_ESTABLISHED", TechBOM: "NOT_ESTABLISHED" },
  dependencies: 0,
  evidence: { state: "MEASURED", freshness: "CURRENT", basis: "agent verification or stored fingerprint" },
  last_observed: "2026-11-10T00:00:00Z",
};

const DETAIL = {
  asset_ref: "app:sys-pay", name: "payments", category: "SOFTWARE", environment: "Production",
  owner: "", source: "Software record", last_observed: "2026-11-01T00:00:00Z",
  related: [
    { bom: "SBOM", state: "PRIMARY_RECORD", basis: "this asset is a record of that BOM" },
    { bom: "CBOM", state: "LINKED", basis: "a stored relationship establishes this link" },
    { bom: "HBOM", state: "NOT_ESTABLISHED", basis: "no stored relationship establishes this link" },
  ],
  dependencies: [{ to: "crypto:cr-linked", type: "system_asset", evidence: "stored system_assets link" }],
  evidence: { state: "UNKNOWN", freshness: "NOT_COLLECTED", basis: "registration only" },
};

describe("TechBOM workspace", () => {
  it("pins the 11-section navigation and the technology inventory columns", async () => {
    mockFetch({
      "/api/v1/techbom/workspace/inventory": { state: "techbom-inventory", total: 0, rows: [], note: "canonical technology inventory — Related BOMs cite primary records and verified links only" },
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: "Technology Inventory" }));
    await waitFor(() => {
      ["Asset ID", "Asset name", "Category", "Vendor", "Product/version", "Environment",
        "Related BOMs", "Dependencies", "Evidence", "Last observed"].forEach((h) =>
        expect(screen.getAllByText(h).length).toBeGreaterThan(0));
      expect(screen.getByText("Nothing stored yet")).toBeTruthy();
    });
    ["TechBOM Overview", "Application & Service Registry", "Infrastructure Inventory",
      "Technology Layers", "Six-BOM Reconciliation", "Technology Relationships",
      "Lifecycle Intelligence", "Evidence & Provenance", "TechBOM History", "Export & Validation"]
      .forEach((label) => expect(screen.getByRole("tab", { name: label })).toBeTruthy());
  });

  it("keeps the cross-BOM relationship states apart — linked, primary record and not established never collapse", async () => {
    mockFetch({
      "/api/v1/techbom/workspace/inventory": { state: "techbom-inventory", total: 2, rows: [SYSTEM_ROW, HSM_ROW], note: "n" },
      "/api/v1/techbom/workspace/inventory/app:sys-pay": DETAIL,
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: "Technology Inventory" }));
    await waitFor(() => expect(screen.getByText("payments")).toBeTruthy());
    expect(screen.getAllByText("primary record").length).toBeGreaterThan(0);
    expect(screen.getAllByText("linked").length).toBeGreaterThan(0);
    // evidence states render as their own words
    expect(screen.getAllByText("MEASURED").length).toBeGreaterThan(0);
    expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(0);
    // opening the asset shows the cross-BOM panel — including the honest
    // "not established": the hardware row is NOT linked to the SBOM because
    // no stored mapping exists, and none is invented.
    fireEvent.click(screen.getByText("payments"));
    await waitFor(() => {
      expect(screen.getAllByText("CROSS-BOM RELATIONSHIPS").length).toBeGreaterThan(0);
      expect(screen.getAllByText("not established").length).toBeGreaterThan(0);
      expect(screen.getAllByText(/a stored relationship establishes this link/).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/stored system_assets link/).length).toBeGreaterThan(0);
    });
  });

  it("reconciles only on evidence — the ten screens render and a shared name is not a relationship", async () => {
    mockFetch({
      "/api/v1/techbom/workspace/reconciliation": {
        state: "techbom-reconciliation",
        rule: "records are connected only where stored evidence establishes the relationship; a component's capability is never taken as proof the application performs the operation",
        screens: [
          { screen: "duplicate_asset_detection", question: "Duplicate asset detection", count: 0, rows: [] },
          { screen: "unmatched_sbom_components", question: "Unmatched SBOM components", count: 1, rows: [{ asset_ref: "app:sys-lone", name: "lone-app" }] },
          { screen: "cbom_assets_without_owner", question: "CBOM assets without a mapped software or hardware owner", count: 0, rows: [] },
          { screen: "hbom_devices_without_mapping", question: "HBOM devices without an approved system mapping", count: 1, rows: [{ asset_ref: "hw:hsm-1", name: "payHSM" }] },
          { screen: "nbom_endpoints_without_owner", question: "NBOM endpoints without a known service owner", count: 0, rows: [] },
          { screen: "vbom_products_without_relationship", question: "VBOM products without a verified bank-asset relationship", count: 0, rows: [] },
          { screen: "conflicting_versions", question: "Conflicting versions and metadata", count: 0, rows: [] },
          { screen: "missing_evidence", question: "Missing evidence", count: 0, rows: [] },
          { screen: "stale_records", question: "Stale BOM records", count: 0, rows: [] },
          { screen: "relationship_validation", question: "Cross-BOM relationship validation", count: 2, rows: [] },
        ],
      },
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: "Six-BOM Reconciliation" }));
    await waitFor(() => {
      ["Duplicate asset detection", "Unmatched SBOM components",
        "CBOM assets without a mapped software or hardware owner",
        "HBOM devices without an approved system mapping",
        "NBOM endpoints without a known service owner",
        "VBOM products without a verified bank-asset relationship",
        "Conflicting versions and metadata", "Missing evidence", "Stale BOM records",
        "Cross-BOM relationship validation"].forEach((name) =>
        expect(screen.getAllByText(name).length).toBeGreaterThan(0));
    });
    expect(screen.getAllByText(/never taken as proof/).length).toBeGreaterThan(0);
  });

  it("draws the not-read state instead of an empty inventory when the read fails", async () => {
    mockFetch({});
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: "Technology Relationships" }));
    await waitFor(() => {
      expect(screen.getByText(/not read/)).toBeTruthy();
      expect(screen.queryByText("Nothing stored yet")).toBeNull();
    });
  });
});
