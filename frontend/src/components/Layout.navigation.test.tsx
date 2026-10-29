/* The familiar six-section sidebar, backed by real routes rather than a second UI. */
import { describe, expect, it } from "vitest";

import { PRIMARY_SECTIONS } from "./Layout";

const items = PRIMARY_SECTIONS.flatMap((section) =>
  section.items.map((item) => ({ ...item, section: section.title })),
);
const routes = items.map((item) => item.to);

describe("classic sidebar navigation", () => {
  it("keeps the six original sections in their familiar order", () => {
    expect(PRIMARY_SECTIONS.map((section) => section.title)).toEqual([
      "Overview", "Discovery", "Intelligence", "Governance", "Output", "Administration",
    ]);
  });

  it("places existing and new workspaces where an operator expects them", () => {
    const sectionOf = (route: string) => items.find((item) => item.to === route)?.section;
    expect(sectionOf("/live-monitor")).toBe("Overview");
    expect(sectionOf("/certificates")).toBe("Discovery");
    for (const bom of ["/cbom", "/sbom", "/hbom", "/nbom", "/vbom", "/live-asset-intelligence"])
      expect(sectionOf(bom)).toBe("Intelligence");
    for (const assurance of ["/assurance-records", "/assurance-coverage", "/assurance-trace",
      "/assurance-sampling", "/assurance-qualification"])
      expect(sectionOf(assurance)).toBe("Governance");
    expect(sectionOf("/digital-twin")).toBe("Output");
  });

  it("keeps every prior sidebar route and the added BOM and assurance pages", () => {
    for (const route of [
      "/assets", "/dev-sec-ops", "/cloud", "/hardware", "/network", "/certificates",
      "/vendor", "/dependency-graph", "/crypto", "/crypto-assets", "/cbom", "/hbom",
      "/nbom", "/sbom", "/vbom", "/live-asset-intelligence", "/digital-twin", "/graph",
      "/findings", "/pqc", "/agility", "/drift", "/scanners", "/live-scanners", "/reports",
      "/assurance-coverage", "/assurance-trace", "/assurance-sampling", "/assurance-qualification",
    ]) expect(routes).toContain(route);
    expect(routes).toHaveLength(50);
    expect(new Set(routes).size).toBe(49);
    expect(routes.filter((route) => route === "/security-center")).toHaveLength(2);
  });

  it("never lists the same route twice inside one section", () => {
    for (const section of PRIMARY_SECTIONS) {
      const paths = section.items.map((item) => item.to);
      expect(new Set(paths).size, section.title).toBe(paths.length);
    }
  });
});
