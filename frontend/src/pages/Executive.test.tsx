import { describe, expect, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import Executive from "./Executive";

describe("Executive", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(Executive);
  });
});

import { screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";

const dataRoutes = {
  "/api/v1/stats/summary": {
    total_findings: 40, compliant: 30,
    coverage: {
      coverage_pct: 85, systems: 20, with_cbom: 15, unknown_crypto: 5,
      counts: { CURRENT: 15, STALE: 3, FAILED: 1, NEVER_SCANNED: 1, NO_TARGET: 0 },
    },
    open_drift: { CRITICAL: 1, HIGH: 2 },
  },
  "/api/v1/live-scan/bom": { cbom: { counts: { total: 100, quantum_vulnerable: 12 } } },
  "/api/v1/live-scan/drift": { change_count: 7 },
  "/api/v1/live-scan/alerts": { counts: { CRITICAL: 1, HIGH: 2 } },
};

describe("Executive — every metric links to its underlying records (gap analysis §A)", () => {
  it("posture inputs link to their record surfaces, including the PQC status share", async () => {
    mockFetch(dataRoutes);
    renderWithProviders(<Executive />);
    expect(await screen.findByText(/Estate coverage \(85%\)/)).toHaveAttribute(
      "href", "/assurance-coverage");
    expect(screen.getByText(/Quantum-safe crypto share/)).toHaveAttribute("href", "/pqc");
    expect(screen.getByText(/Compliant findings/)).toHaveAttribute("href", "/findings");
  });

  it("every board KPI tile is a link to the records behind the number", async () => {
    mockFetch(dataRoutes);
    renderWithProviders(<Executive />);
    const checks: Array<[string, string]> = [
      ["crypto components", "/crypto-assets"],
      ["quantum vulnerable", "/pqc"],
      ["total findings", "/findings"],
      ["estate coverage", "/assurance-coverage"],
      ["crypto drift changes", "/crypto-changes"],
    ];
    for (const [label, href] of checks) {
      const tile = screen.getByText(label).closest("a");
      expect(tile, label).not.toBeNull();
      expect(tile!, label).toHaveAttribute("href", href);
    }
  });

  it("coverage counts link to the systems behind them, never bare numbers", async () => {
    mockFetch(dataRoutes);
    renderWithProviders(<Executive />);
    // a state count in the legend is a link to the technology estate records
    const legendLink = await screen.findByTitle(/the stale systems are the records behind this count/);
    expect(legendLink).toHaveAttribute("href", "/live-asset-intelligence");
    // footer metrics link too (scoped — bare numbers collide elsewhere)
    const foot = within(screen.getByTestId("coverage-foot"));
    expect(foot.getByText("20").closest("a")).toHaveAttribute("href", "/live-asset-intelligence");
    expect(foot.getByText("15").closest("a")).toHaveAttribute("href", "/cbom");
    expect(foot.getByText("5").closest("a")).toHaveAttribute("href", "/cbom");
  });
});
