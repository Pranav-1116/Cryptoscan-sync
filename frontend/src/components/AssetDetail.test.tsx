// Shared asset detail pins (docs/boms/01_PRODUCT_SPEC.md §7).
// One canonical detail surface: header record, asset information fields,
// the cross-BOM relationships panel (linked / not established / unknown /
// primary record — never conflated) and the nine detail tabs. Usage
// states are never equated; unobserved network crypto is `unknown`; a
// failed read draws the not-read state, never an empty inventory.
import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import AssetDetail, { CanonicalDetailLink } from "./AssetDetail";
import { mockFetch } from "../test/setup";

const HEADER = {
  asset_ref: "app:sys-pay", name: "payments", status: "UNKNOWN · NOT_COLLECTED",
  description: "Payment API Server", asset_id: "app:sys-pay",
  environment: "Production", category: "SOFTWARE", owner: "payments-team",
  source: "System registry", last_observed: "2026-11-01T00:00:00Z",
  primary_bom: "TechBOM",
  related: [
    { bom: "TechBOM", state: "PRIMARY_RECORD", basis: "the canonical asset record lives in the technology inventory" },
    { bom: "SBOM", state: "LINKED", basis: "this system materializes into the SBOM layer" },
    { bom: "CBOM", state: "LINKED", basis: "a stored relationship establishes this link" },
    { bom: "HBOM", state: "NOT_ESTABLISHED", basis: "no stored relationship establishes this link" },
    { bom: "NBOM", state: "NOT_ESTABLISHED", basis: "no stored relationship establishes this link" },
    { bom: "VBOM", state: "LINKED", basis: "a stored SystemVendor link establishes this link" },
  ],
  chips: ["TechBOM primary record", "SBOM linked", "CBOM linked", "VBOM linked"],
  evidence: { state: "UNKNOWN", freshness: "NOT_COLLECTED", basis: "registration only" },
};

describe("shared asset detail", () => {
  it("opens the common detail only when selected and never invents a missing reference", async () => {
    mockFetch({
      "/api/v1/asset-detail/app:sys-pay": HEADER,
      "/api/v1/asset-detail/app:sys-pay/overview": {
        asset_ref: "app:sys-pay", tab: "overview", rows: [], note: "n",
      },
    });
    render(<CanonicalDetailLink assetRef="app:sys-pay" />);
    expect(screen.queryByText("payments")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Open shared asset detail" }));
    await waitFor(() => expect(screen.getByText("payments")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Close shared asset detail" }));
    expect(screen.queryByText("payments")).toBeNull();
  });

  it("shows an unlinked state instead of an invented canonical record", () => {
    render(<CanonicalDetailLink assetRef={null} />);
    expect(screen.getByText(/No canonical asset reference was recorded/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Open shared asset detail" })).toBeNull();
  });

  it("pins the header record, the asset information fields and the cross-BOM panel states", async () => {
    mockFetch({
      "/api/v1/asset-detail/app:sys-pay": HEADER,
      "/api/v1/asset-detail/app:sys-pay/overview": {
        asset_ref: "app:sys-pay", tab: "overview", note: "the asset information fields as stored",
        rows: [{ field: "Asset ID", value: "app:sys-pay" }, { field: "Environment", value: "Production" }],
      },
    });
    render(<AssetDetail assetRef="app:sys-pay" />);
    await waitFor(() => {
      expect(screen.getByText("payments")).toBeTruthy();
      expect(screen.getByText("Payment API Server")).toBeTruthy();
    });
    // asset information fields (spec: Asset ID · Environment · Category · Owner · Source · Last observed)
    ["Asset ID", "Environment", "Category", "Owner", "Source", "Last observed"].forEach((f) =>
      expect(screen.getAllByText(f).length).toBeGreaterThan(0));
    // cross-BOM panel — states never conflated
    ["TechBOM", "SBOM", "CBOM", "HBOM", "NBOM", "VBOM"].forEach((bom) =>
      expect(screen.getAllByText(bom).length).toBeGreaterThan(0));
    expect(screen.getAllByText("primary record").length).toBeGreaterThan(0);
    expect(screen.getAllByText("linked").length).toBeGreaterThan(0);
    expect(screen.getAllByText("not established").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/a stored relationship establishes this link/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/no stored relationship establishes this link/).length).toBeGreaterThan(0);
  });

  it("renders the nine detail tabs and keeps usage states apart", async () => {
    mockFetch({
      "/api/v1/asset-detail/app:sys-pay": HEADER,
      "/api/v1/asset-detail/app:sys-pay/overview": { asset_ref: "app:sys-pay", tab: "overview", rows: [], note: "n" },
      "/api/v1/asset-detail/app:sys-pay/cryptography": {
        asset_ref: "app:sys-pay", tab: "cryptography",
        note: "usage states are never equated: capability_detected ≠ configuration_observed ≠ operation_observed",
        rows: [
          { crypto_ref: "crypto:cr-linked", algorithm: "AES", key_size: 256, mode: "GCM", purpose: "encrypt", usage_state: "operation_observed", basis: "runtime observation named this algorithm" },
          { crypto_ref: "crypto:cr-2", algorithm: "RSA", key_size: 2048, mode: "", purpose: "sign", usage_state: "capability_detected", basis: "inventory record only — capability is never operation" },
        ],
      },
      "/api/v1/asset-detail/app:sys-pay/network": {
        asset_ref: "app:sys-pay", tab: "network",
        note: "observed handshakes report negotiated facts; everything else reports unknown",
        rows: [{ endpoint: "dark-1:443", protocol: "tls", service: "", tls_version: "unknown", cipher_suite: "unknown", certificate_subject: "", observed: false, basis: "a port scan alone does not prove the negotiated cryptographic configuration" }],
      },
    });
    render(<AssetDetail assetRef="app:sys-pay" />);
    await waitFor(() => expect(screen.getByText("payments")).toBeTruthy());
    ["Overview", "Components", "Cryptography", "Hardware", "Network", "Vendors",
      "Dependencies", "Evidence", "History"].forEach((label) =>
      expect(screen.getByRole("tab", { name: label })).toBeTruthy());
    fireEvent.click(screen.getByRole("tab", { name: "Cryptography" }));
    await waitFor(() => {
      expect(screen.getAllByText("operation_observed").length).toBeGreaterThan(0);
      expect(screen.getAllByText("capability_detected").length).toBeGreaterThan(0);
    });
    // the unobserved endpoint reports `unknown` — never "none", never "plaintext"
    fireEvent.click(screen.getByRole("tab", { name: "Network" }));
    await waitFor(() => {
      expect(screen.getAllByText("unknown").length).toBeGreaterThan(0);
      expect(screen.queryByText("plaintext")).toBeNull();
    });
  });

  it("draws the not-read state instead of an empty record when the read fails", async () => {
    mockFetch({});
    render(<AssetDetail assetRef="app:sys-pay" />);
    await waitFor(() => {
      expect(screen.getAllByText(/not read|could not be read/).length).toBeGreaterThan(0);
    });
  });
});
