/**
 * NBOM workspace (docs/boms/01_PRODUCT_SPEC.md §4):
 * the thirteen-section shell, the spec's inventory columns, and the
 * working rule pinned as rendering behaviour — a port scan or endpoint
 * inventory alone does not prove the negotiated cryptographic
 * configuration; unobserved negotiation renders `unknown`, never "none",
 * never "plaintext", never an empty cell that reads as healthy.
 */
import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, afterEach } from "vitest";
import { mockFetch } from "../test/setup";
import Nbom from "../pages/Nbom";

const inRouter = (ui: React.ReactElement) =>
  render(<MemoryRouter initialEntries={["/nbom"]}>{ui}</MemoryRouter>);

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const SPEC_TABS = [
  "NBOM Overview", "Network Asset Inventory", "Endpoint Inventory",
  "Service & Port Inventory", "TLS Intelligence", "SSH Intelligence",
  "IPsec / VPN Intelligence", "Certificate Exposure", "Network Dependencies",
  "Network Change History", "Evidence & Provenance", "NBOM History",
  "Export & Validation",
];

const OBSERVED = {
  endpoint: "payments-1:443", host: "payments-1", port: 443, protocol: "tls",
  service: "h2", tls_version: "TLSv1.3", cipher_suite: "TLS_AES_256_GCM_SHA384",
  negotiation: { state: "OBSERVED", basis: "a successful handshake was recorded by the collector" },
  certificate: { subject: "CN=payments", fingerprint_sha256: "ab".repeat(32), issuer: "CN=ca",
                 public_key_algorithm: "RSA", public_key_size: 2048, expiry_status: "VALID" },
  source: "network-scanner", scan_run_id: "run-1",
  first_observed: "2026-11-01T00:00:00", last_observed: "2026-11-13T00:00:00", freshness: "CURRENT",
};

const UNOBSERVED = {
  endpoint: "legacy-1:443", host: "legacy-1", port: 443, protocol: "tls",
  service: null, tls_version: "unknown", cipher_suite: "unknown",
  negotiation: { state: "unknown", basis: "no successful handshake recorded — a port scan or endpoint inventory alone does not prove the negotiated cryptographic configuration" },
  certificate: null, source: "network-scanner", scan_run_id: "run-1",
  first_observed: "2026-11-01T00:00:00", last_observed: "2026-11-13T00:00:00", freshness: "CURRENT",
};

const DETAIL = {
  endpoint: OBSERVED,
  observations: [],
  dependencies: [{ type: "served_by", target: "certificate:" + "ab".repeat(32) }],
  certificate_detail: { subject: "CN=payments", issuer: "CN=ca" },
  related: { cbom: [], techbom: [], _note: "no stored cross-BOM link rows name this endpoint" },
  evidence: { source: "network-scanner", method: "active probe (handshake attempted; only OK/TLS_OK counts as observed)", runs: 1 },
};

describe("NBOM workspace shell", () => {
  it("draws the thirteen spec sections", () => {
    mockFetch({});
    inRouter(<Nbom />);
    for (const label of SPEC_TABS) expect(screen.getByRole("tab", { name: label })).toBeTruthy();
  });

  it("renders the spec's columns and draws unknown where no handshake was observed", async () => {
    mockFetch({
      "/api/v1/nbom/workspace/endpoints": { state: "OBSERVED", total: 2, rows: [OBSERVED, UNOBSERVED] },
      "/api/v1/nbom/workspace/endpoints/payments-1%3A443": DETAIL,
    });
    inRouter(<Nbom />);
    fireEvent.click(screen.getByRole("tab", { name: "Endpoint Inventory" }));
    await waitFor(() => expect(screen.getByText("payments-1:443")).toBeTruthy());
    for (const column of ["Endpoint", "Port", "Protocol", "Service", "TLS version",
                         "Cipher suite", "Certificate", "Source", "First / last observed"]) {
      expect(screen.getAllByText(column).length).toBeGreaterThan(0);
    }
    // the observed handshake renders its negotiated facts
    expect(screen.getAllByText("TLSv1.3").length).toBeGreaterThan(0);
    // the unobserved endpoint renders `unknown` — not "none", not "plaintext", not blank
    expect(screen.getAllByText("unknown").length).toBeGreaterThan(0);
    expect(screen.queryByText("plaintext")).toBeNull();
    fireEvent.click(screen.getByText("payments-1:443"));
    await waitFor(() => expect(screen.getAllByText(/NEGOTIATED CRYPTOGRAPHY/).length).toBeGreaterThan(0));
    expect(screen.getAllByText(/only OK\/TLS_OK counts as observed/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("observed").length).toBeGreaterThan(0);
  });

  it("keeps unread inventories honest", async () => {
    mockFetch({});
    inRouter(<Nbom />);
    fireEvent.click(screen.getByRole("tab", { name: "TLS Intelligence" }));
    await waitFor(() => expect(screen.getAllByText(/not read/i).length).toBeGreaterThan(0));
  });
});
