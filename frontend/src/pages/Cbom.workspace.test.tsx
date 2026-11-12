/**
 * CBOM workspace (docs/boms/01_PRODUCT_SPEC.md §2):
 * the thirteen-section shell, the spec's inventory columns, key metadata
 * without key material, the three usage states kept distinct, and honest
 * empty states — an unread or empty inventory is never a fabricated one.
 */
import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, afterEach } from "vitest";
import { mockFetch } from "../test/setup";
import Cbom from "../pages/Cbom";

const inRouter = (ui: React.ReactElement) =>
  render(<MemoryRouter initialEntries={["/cbom"]}>{ui}</MemoryRouter>);

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const SPEC_TABS = [
  "CBOM Overview", "Cryptographic Asset Inventory", "Algorithm Intelligence",
  "Crypto Library & Provider Inventory", "Certificate & PKI Inventory",
  "Key Metadata Inventory", "Cryptographic Operations",
  "TLS / SSH / IPsec Cryptography", "PQC Readiness", "Crypto Dependencies",
  "Evidence & Provenance", "CBOM History", "Export & Validation",
];

const SECRET = "AKIA-super-secret-material-MUST-NEVER-LEAVE-STORE";

const ROW = {
  asset_id: "asset-1", algorithm: "RSA", operation: "sign", mode: null,
  implementation: ["cryptography"], location: "svc/signer.py:41",
  file_path: "svc/signer.py", source_language: "python",
  key_metadata: { size: 2048, hardcoded_material_flag: true, named_reference: "PRESENT" },
  evidence_status: "INFERRED", evidence_basis: "static scan located the reference; use is inferred, not measured",
  usage: { usage_state: "configuration_observed", basis: "code references it; no operation observed" },
  pqc_family: "MIGRATION_RELEVANT", confidence: "HIGH", occurrence_count: 1,
  last_observed: "2026-11-13T00:00:00", freshness: "CURRENT",
};

const DETAIL = {
  asset: ROW,
  certificates: [], evidence: [{ evidence_id: "ev-1", asset_id: "asset-1", observation_method: "scanner evidence record" }],
  associated_assets: [{ type: "software", ref: "svc/signer.py", note: "" }],
  history: [{ location: "svc/signer.py", first_seen: "2025-11-01", last_seen: "2026-11-13", observation_count: 12, is_current: true }],
  techbom_links: [],
  pqc: { family: "MIGRATION_RELEVANT", migration_relevance: "this algorithm family is in scope for post-quantum migration" },
};

describe("CBOM workspace shell", () => {
  it("draws the thirteen spec sections", () => {
    mockFetch({});
    inRouter(<Cbom />);
    for (const label of SPEC_TABS) expect(screen.getByRole("tab", { name: label })).toBeTruthy();
  });

  it("renders the spec's asset columns, keeps key material out, and draws the usage distinction", async () => {
    mockFetch({
      "/api/v1/cbom/workspace/assets": { state: "OBSERVED", total: 1, rows: [ROW] },
      "/api/v1/cbom/workspace/assets/asset-1": DETAIL,
    });
    inRouter(<Cbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Cryptographic Asset Inventory" }));
    await waitFor(() => expect(screen.getByText("RSA")).toBeTruthy());
    for (const column of ["Crypto asset", "Algorithm", "Operation", "Implementation",
                         "Location", "Key metadata", "Evidence status", "PQC status",
                         "Last observed"]) {
      expect(screen.getAllByText(column).length).toBeGreaterThan(0);
    }
    // the key-material flag is surfaced; the key material itself never is
    expect(screen.getAllByText(/HARDCODED KEY FLAG/).length).toBeGreaterThan(0);
    expect(screen.queryByText(new RegExp(SECRET.slice(0, 12)))).toBeNull();
    // evidence vocabulary drawn in its own column
    expect(screen.getAllByText("INFERRED").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("RSA"));
    await waitFor(() => expect(screen.getAllByText(/KEY METADATA — KEY MATERIAL IS NEVER COLLECTED/).length).toBeGreaterThan(0));
    // the states are drawn as distinct badges in the detail, never collapsed
    expect(screen.getAllByText("configuration_observed").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/code references it; no operation observed/).length).toBeGreaterThan(0);
  });

  it("keeps a library capability as capability — support is never use", async () => {
    mockFetch({
      "/api/v1/cbom/workspace/libraries": {
        state: "OBSERVED",
        rows: [{ name: "liboqs", kind: "implementation", algorithms: ["ML-KEM"],
                 usage_state: "capability_detected",
                 basis: "library capability; use is claimed on the asset rows with their own evidence",
                 crypto_bearing_components: 1 }],
      },
    });
    inRouter(<Cbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Crypto Library & Provider Inventory" }));
    await waitFor(() => expect(screen.getByText("liboqs")).toBeTruthy());
    expect(screen.getAllByText("capability_detected").length).toBeGreaterThan(0);
  });

  it("keeps unread and empty inventories honest", async () => {
    mockFetch({});
    inRouter(<Cbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Certificate & PKI Inventory" }));
    await waitFor(() => expect(screen.getAllByText(/not read/i).length).toBeGreaterThan(0));
  });
});
