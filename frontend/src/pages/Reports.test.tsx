/* Reports page truth (§4.4, round 69): the report leg of scan-run → BOM →
 * report. A pinned report is a content-addressed authority — the exact
 * payload (signed PDF + scan→BOM chain citation) hashed with SHA-256,
 * identical pins collapsing — and the page says which rows are and which
 * are legacy-unhashed. The pin form names the EXACT scan; a failed pin
 * renders the error, never a fabricated success. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import Reports from "./Reports";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () => render(<Reports />);

const baseRoutes = {
  "/api/v1/report-snapshots": {
    snapshots: [
      { id: "snap-new", scan_id: "scan-1", template_id: "pci-dss-4.0",
        report_hash: "a".repeat(64), payload_hash: "b".repeat(64),
        generated_at: "2026-10-15T10:00:00", email_status: "SENT",
        title: "Q4 PCI report" },
      { id: "snap-old", scan_id: "scan-0", template_id: "pci-dss-4.0",
        report_hash: "c".repeat(64), payload_hash: null,
        generated_at: "2026-01-01T10:00:00", email_status: "SENT",
        title: "Legacy report" },
    ],
    total: 2,
  },
  "/api/v1/report-schedules": { schedules: [] },
  "/api/v1/report-templates": { templates: [{ template_id: "pci-dss-4.0" }] },
};

describe("Reports — report version authority (§4.4)", () => {
  it("marks content-addressed snapshots and names legacy rows honestly", async () => {
    mockFetch(baseRoutes);
    renderPage();
    await waitFor(() => expect(screen.getByText("Q4 PCI report")).toBeTruthy());
    expect(screen.getByText(/content-addressed b{10}…/)).toBeTruthy();
    expect(screen.getByText("Legacy report")).toBeTruthy();
    expect(screen.getByText(/legacy row — payload not content-addressed/)).toBeTruthy();
  });

  it("pins the EXACT scan: form calls the pin endpoint with the named template", async () => {
    const fn = mockFetch({
      ...baseRoutes,
      "/api/v1/scans/scan-42/report-snapshot": (url: string, init?: RequestInit) => {
        expect(String(url)).toContain("/api/v1/scans/scan-42/report-snapshot");
        expect(JSON.parse(String(init?.body)).template_id).toBe("pci-dss-4.0");
        return {
          id: "d".repeat(36), scan_id: "scan-42", template_id: "pci-dss-4.0",
          report_hash: "e".repeat(64), payload_hash: "f".repeat(64),
          generated_at: null, created: true, note: "Report pinned and content-addressed",
        };
      },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Q4 PCI report")).toBeTruthy());
    fireEvent.change(screen.getByPlaceholderText("scan id"), { target: { value: "scan-42" } });
    fireEvent.click(screen.getByRole("button", { name: "Pin report" }));
    await waitFor(() => expect(screen.getByText(/pinned — d{8}…/)).toBeTruthy());
    expect(fn.mock.calls.some((c) => String(c[0]).includes("/api/v1/scans/scan-42/report-snapshot"))).toBe(true);
  });

  it("a failed pin renders the error, never a fabricated success", async () => {
    mockFetch({
      ...baseRoutes,
      "/api/v1/scans/scan-nope/report-snapshot": () =>
        new Response(JSON.stringify({ detail: "Scan not found" }),
                     { status: 404, headers: { "Content-Type": "application/json" } }),
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Q4 PCI report")).toBeTruthy());
    fireEvent.change(screen.getByPlaceholderText("scan id"), { target: { value: "scan-nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Pin report" }));
    await waitFor(() => expect(screen.getByText(/Scan not found/)).toBeTruthy());
    expect(screen.queryByText(/pinned —/)).toBeNull();
  });
});
