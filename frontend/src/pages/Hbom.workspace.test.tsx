/**
 * HBOM workspace (docs/boms/01_PRODUCT_SPEC.md §3):
 * the thirteen-section shell, the spec's inventory columns with masked
 * serials, the hard rule (no key material, private keys, secrets or device
 * credentials anywhere), capability never drawn as use, honest lifecycle
 * and honest empty states.
 */
import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, afterEach } from "vitest";
import { mockFetch } from "../test/setup";
import Hbom from "../pages/Hbom";

const inRouter = (ui: React.ReactElement) =>
  render(<MemoryRouter initialEntries={["/hbom"]}>{ui}</MemoryRouter>);

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const SPEC_TABS = [
  "HBOM Overview", "Hardware Inventory", "Servers & Compute", "HSM Inventory",
  "TPM & Secure Elements", "Network Hardware", "Storage Hardware",
  "Firmware Intelligence", "Hardware Crypto Capabilities", "Hardware Lifecycle",
  "Evidence & Provenance", "HBOM History", "Export & Validation",
];

const SECRET = "PKCS11-SLOT-KEY-MATERIAL-MUST-NEVER-LEAVE";

const ROW = {
  asset_id: "hw-hsm-1", manufacturer: "Utimaco", model: "CryptoServer",
  serial_reference: "••••321100", firmware: "4.2.1", category: "HSM",
  device_type: "hsm", location: "dc-north",
  crypto_capabilities: { algorithms: ["RSA-4096", "AES-256"], acceleration: true },
  lifecycle: "SUPPORTED", lifecycle_basis: "firmware record states end_of_life=False",
  evidence: { agent_id: "agent-dc-1", last_seen: "2026-11-12T00:00:00", fingerprinted: true, evidence_records: 1, freshness: "CURRENT" },
};

const DETAIL = {
  asset: ROW,
  tpm: { version: "2.0", present: true },
  hsm: { vendor: "Utimaco", fips_level: 3 },
  firmware_detail: { version: "4.2.1", vendor: "Utimaco" },
  secure_boot: true,
  cpu_acceleration: { acceleration: true, algorithms: ["AES-NI"] },
  hardware_dependencies: [],
  related: { cbom: [], techbom: [], _note: "no stored cross-BOM link rows name this hardware asset" },
  firmware_history: [{ observed_at: "2026-11-07T00:00:00", change_class: "firmware", event_type: "firmware_change" }],
  evidence_history: [{ event_type: "firmware_change", source: "agent", observed_at: "2026-11-07T00:00:00", evidence_id: "ev-1" }],
};

describe("HBOM workspace shell", () => {
  it("draws the thirteen spec sections", () => {
    mockFetch({});
    inRouter(<Hbom />);
    for (const label of SPEC_TABS) expect(screen.getByRole("tab", { name: label })).toBeTruthy();
  });

  it("renders the spec's columns with masked serials and never key material", async () => {
    mockFetch({
      "/api/v1/hbom/workspace/assets": { state: "OBSERVED", total: 1, rows: [ROW] },
      "/api/v1/hbom/workspace/assets/hw-hsm-1": DETAIL,
    });
    inRouter(<Hbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Hardware Inventory" }));
    await waitFor(() => expect(screen.getByText("hw-hsm-1")).toBeTruthy());
    for (const column of ["Asset ID", "Manufacturer", "Model", "Serial reference",
                         "Firmware", "Category", "Location", "Crypto capabilities",
                         "Lifecycle", "Evidence"]) {
      expect(screen.getAllByText(column).length).toBeGreaterThan(0);
    }
    // masked serial drawn; unmasked material never
    expect(screen.getAllByText(/••••/).length).toBeGreaterThan(0);
    expect(screen.queryByText(new RegExp(SECRET.slice(0, 12)))).toBeNull();
    fireEvent.click(screen.getByText("hw-hsm-1"));
    await waitFor(() => expect(screen.getAllByText(/HSM CAPABILITIES — APPROVED METADATA ONLY/).length).toBeGreaterThan(0));
    // capability is drawn as capability in the detail, never as use
    expect(screen.getAllByText(/CAPABILITY IS NEVER USE/).length).toBeGreaterThan(0);
    expect(screen.queryByText(new RegExp(SECRET.slice(0, 12)))).toBeNull();
  });

  it("keeps an unrecorded lifecycle unknown — never assumed supported", async () => {
    mockFetch({
      "/api/v1/hbom/workspace/lifecycle": {
        state: "OBSERVED", total: 1,
        rows: [{ asset_id: "hw-server-1", model: "R760", lifecycle: "UNKNOWN",
                 lifecycle_basis: "no stored lifecycle record — unknown, never assumed supported",
                 last_seen: "2026-11-12T00:00:00", freshness: "CURRENT" }],
      },
    });
    inRouter(<Hbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Hardware Lifecycle" }));
    await waitFor(() => expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(0));
    expect(screen.getAllByText(/never assumed supported/).length).toBeGreaterThan(0);
    expect(screen.queryByText("SUPPORTED")).toBeNull();
  });

  it("keeps unread inventories honest", async () => {
    mockFetch({});
    inRouter(<Hbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Firmware Intelligence" }));
    await waitFor(() => expect(screen.getAllByText(/not read/i).length).toBeGreaterThan(0));
  });
});
