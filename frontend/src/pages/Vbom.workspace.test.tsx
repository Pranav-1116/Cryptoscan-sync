// VBOM workspace pins (docs/boms/01_PRODUCT_SPEC.md §5).
// The working rule: a vendor's public association never implies bank use —
// CONFIRMED / IMPORTED / PUBLICLY_REPORTED / UNKNOWN are kept apart and a
// publicly reported vendor shows zero bank assets.
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Vbom from "./Vbom";
import { mockFetch } from "../test/setup";

function renderVbom() {
  return render(
    <MemoryRouter initialEntries={["/vbom"]}>
      <Vbom />
    </MemoryRouter>,
  );
}

const TECH_BOM = {
  "/api/v1/technology-bom": { state_version: 1 },
  "/api/v1/technology-bom/vendor": { vendor_count: 2, vendors: [], linkage: [], notes: [] },
  "/api/v1/vbom/workspace/overview": {},
};

const THALES_ROW = {
  vendor: "Thales", vendor_id: "11111111-1111-1111-1111-111111111111",
  product: "payHSM", version: "7.4", category: "HSM",
  bank_assets: 1, association_state: "CONFIRMED", association_basis: "verified system link",
  support_lifecycle: "SUPPORTED", crypto_dependency: "RSA-2048", pqc_roadmap: "CONFIRMED",
  evidence: { profile_status: "DRAFT", freshness: "CURRENT", source: "operator" },
  last_reviewed: "2026-10-30T00:00:00Z",
};

const PRESS_ROW = {
  vendor: "PressVendor", vendor_id: "22222222-2222-2222-2222-222222222222",
  product: "SecureBox", version: null, category: "GATEWAY",
  bank_assets: 0, association_state: "PUBLICLY_REPORTED",
  association_basis: "publicly reported — never bank use",
  support_lifecycle: "UNKNOWN", crypto_dependency: "NOT_COLLECTED", pqc_roadmap: "REPORTED",
  evidence: { profile_status: "DRAFT", freshness: "NOT_COLLECTED", source: "operator" },
  last_reviewed: null,
};

describe("VBOM workspace", () => {
  it("pins the 13-section navigation and the registry columns", async () => {
    mockFetch({
      ...TECH_BOM,
      "/api/v1/vbom/workspace/vendors": { state: "vbom-vendors", total: 0, rows: [] },
    });
    renderVbom();
    // The overview content is pin-locked in DiscoveryHonesty (reads the same mocks).
    fireEvent.click(screen.getByRole("tab", { name: "Vendor Registry" }));
    await waitFor(() => {
      ["Vendor", "Product", "Version", "Category", "Bank assets", "Support lifecycle",
        "Crypto dependency", "PQC roadmap", "Evidence", "Last reviewed"].forEach((h) =>
        expect(screen.getAllByText(h).length).toBeGreaterThan(0));
      expect(screen.getByText("Nothing stored yet")).toBeTruthy();
    });
    ["VBOM Overview", "Vendor Product Inventory", "Supplier Relationships", "Product & Version Lifecycle",
      "Vendor Security Intelligence", "Vendor Crypto Dependencies", "Vendor PQC Roadmaps",
      "Supply Chain Exposure", "Contract & Support Metadata", "Evidence & Provenance",
      "VBOM History", "Export & Validation"].forEach((label) =>
      expect(screen.getByRole("tab", { name: label })).toBeTruthy());
  });

  it("keeps the relationship states apart — a publicly reported vendor shows zero bank assets and never CONFIRMED", async () => {
    mockFetch({
      ...TECH_BOM,
      "/api/v1/vbom/workspace/vendors": { state: "vbom-vendors", total: 2, rows: [THALES_ROW, PRESS_ROW] },
    });
    renderVbom();
    fireEvent.click(screen.getByRole("tab", { name: "Vendor Registry" }));
    await waitFor(() => {
      expect(screen.getByText("Thales")).toBeTruthy();
      expect(screen.getAllByText("CONFIRMED").length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText("PUBLICLY_REPORTED").length).toBeGreaterThan(0);
    expect(screen.getByText("0 verified")).toBeTruthy();
    // REPORTED ≠ CONFIRMED for PQC as well
    expect(screen.getAllByText("REPORTED").length).toBeGreaterThan(0);
  });

  it("shows the honest UNKNOWN where a product's support was never collected", async () => {
    mockFetch({
      ...TECH_BOM,
      "/api/v1/vbom/workspace/products": {
        state: "vbom-products", total: 1,
        rows: [{ vendor: "Thales", name: "payHSM", version: "7.4", component_type: "software", license_model: null, support_level: null, eol_date: null, replacement_product: null }],
      },
    });
    renderVbom();
    fireEvent.click(screen.getByRole("tab", { name: "Vendor Product Inventory" }));
    await waitFor(() => {
      expect(screen.getByText("payHSM")).toBeTruthy();
      expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(0); // support level not collected
    });
  });

  it("draws the not-read state instead of an empty inventory when the read fails", async () => {
    mockFetch({ ...TECH_BOM });
    renderVbom();
    fireEvent.click(screen.getByRole("tab", { name: "VBOM History" }));
    await waitFor(() => {
      expect(screen.getByText(/not read/)).toBeTruthy();
      expect(screen.queryByText("Nothing stored yet")).toBeNull();
    });
  });
});
