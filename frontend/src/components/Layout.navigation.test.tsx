import { describe, expect, it } from "vitest";

import { PRIMARY_SECTIONS } from "./Layout";

/* §24 — the sidebar is the estate tree, not a list of fourteen screens.
 *
 * These are data assertions on the same constant the sidebar renders: a nav that groups
 * items cannot be checked by clicking each one, and the failure that matters is not "the
 * label is wrong" but "a route moved into a group where nobody will look for it, or fell
 * out of the nav entirely while still being served".
 */

const items = PRIMARY_SECTIONS.flatMap((section) =>
  section.items.map((item) => ({ ...item, section: section.title })),
);
const routes = new Set(items.map((item) => item.to));

describe("sidebar groups (§24)", () => {
  it("keeps the estate tree in the order a bank reads it", () => {
    const estate = PRIMARY_SECTIONS.find((section) => section.title === "Estate");
    expect(estate).toBeDefined();
    const groups = estate!.items.map((item) => item.group);

    expect(groups[0]).toBe("Estate");
    expect(groups).toContain("Cryptography");
    expect(groups).toContain("Network");
    expect(groups).toContain("Supply chain");
    expect(groups).toContain("BOM");
    expect(groups).toContain("Digital twin");
    expect(groups).toContain("Intelligence");
    // the groups appear in the spec's order, not the order they were typed
    const order = ["Estate", "Network", "Supply chain", "Cryptography", "BOM", "Digital twin", "Intelligence"];
    const seen = groups.filter((group, index) => index === 0 || group !== groups[index - 1]);
    expect(seen).toEqual(order);
  });

  it("puts each screen where a reader would look for it", () => {
    const byLabel = new Map(items.map((item) => [item.label, item]));

    expect(byLabel.get("Certificates")?.group).toBe("Network");
    expect(byLabel.get("Algorithm Catalog")?.group).toBe("Cryptography");
    expect(byLabel.get("Crypto Inventory (CBOM)")?.group).toBe("Cryptography");
    expect(byLabel.get("Vendors")?.group).toBe("Supply chain");
    expect(byLabel.get("Digital Twin")?.group).toBe("Digital twin");
    expect(byLabel.get("PQC Readiness")?.group).toBe("Intelligence");
    expect(byLabel.get("Crypto Drift")?.group).toBe("Intelligence");
  });

  it("still serves every route that has a screen, each from one place", () => {
    for (const route of [
      "/assets", "/dev-sec-ops", "/cloud", "/hardware", "/network", "/certificates",
      "/vendor", "/dependency-graph", "/crypto", "/crypto-assets", "/cbom", "/hbom",
      "/nbom", "/live-asset-intelligence", "/digital-twin", "/graph", "/findings",
      "/pqc", "/agility", "/drift", "/scanners", "/live-scanners", "/reports",
    ]) {
      expect(routes.has(route)).toBe(true);
    }
  });

  it("does not list the same route twice inside the estate tree", () => {
    const estate = PRIMARY_SECTIONS.find((section) => section.title === "Estate")!;
    const seen = estate.items.map((item) => item.to);

    expect(new Set(seen).size).toBe(seen.length);
  });

  it("collapses a section with no groups without inventing headings", () => {
    const collection = PRIMARY_SECTIONS.find((section) => section.title === "Collection")!;

    expect(collection.items.every((item) => item.group === undefined)).toBe(true);
  });
});
