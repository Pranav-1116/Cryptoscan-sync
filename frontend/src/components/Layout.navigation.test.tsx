/* The sidebar is a two-level tree: five sections, and a group wherever several pages answer
   the same question. Nothing is removed — every route stays reachable — but the operator sees
   a handful of rows instead of fifty. */
import { describe, expect, it } from "vitest";

import { PRIMARY_SECTIONS, navRoutes } from "./Layout";

const items = PRIMARY_SECTIONS.flatMap((section) =>
  section.items.map((item) => ({ ...item, section: section.title })),
);
const leaves = PRIMARY_SECTIONS.flatMap((section) =>
  section.items.flatMap((item) => [
    { ...item, section: section.title, group: null as string | null },
    ...(item.children || []).map((child) => ({ ...child, section: section.title, group: item.label })),
  ]),
);
const routes = navRoutes();
const sectionOf = (route: string) => leaves.find((item) => item.to === route)?.section;
/** The group a page sits in, searched inside groups first: a group's own page also appears
 *  as the group's `to`, and answering "no group" for it would be the wrong half of the tree. */
const groupOf = (route: string) =>
  leaves.find((item) => item.to === route && item.group)?.group ?? null;

describe("classic sidebar navigation", () => {
  it("keeps five sections in their familiar order", () => {
    expect(PRIMARY_SECTIONS.map((section) => section.title)).toEqual([
      "Overview", "Discovery", "Intelligence", "Governance", "Administration",
    ]);
  });

  it("shows a handful of rows per section, not one row per page", () => {
    // the whole point of the tree: no section may grow into a wall of links again
    for (const section of PRIMARY_SECTIONS) {
      expect(section.items.length, section.title).toBeLessThanOrEqual(7);
    }
    expect(items.length).toBeLessThanOrEqual(30);
    expect(routes.length).toBeGreaterThanOrEqual(45);
  });

  it("places every page where an operator expects to find it", () => {
    // live activity and monitoring are one operational workspace under Overview
    expect(sectionOf("/live-monitor")).toBe("Overview");
    expect(groupOf("/live-monitor")).toBe("Operations");
    expect(groupOf("/live-stream")).toBe("Operations");
    expect(groupOf("/runtime")).toBe("Operations");
    // one asset discovery workspace: the domains are tabs of the same question
    expect(sectionOf("/certificates")).toBe("Discovery");
    expect(groupOf("/network")).toBe("Asset discovery");
    expect(groupOf("/assets")).toBe("Asset discovery");
    expect(groupOf("/hardware")).toBe("Asset discovery");
    // one inventory workspace, TechBOM as the broader technology inventory view
    for (const bom of ["/cbom", "/sbom", "/hbom", "/nbom", "/vbom", "/live-asset-intelligence"])
      expect(groupOf(bom)).toBe("Inventory");
    // one cryptographic intelligence workspace
    for (const crypto of ["/crypto", "/crypto-assets", "/findings", "/pqc", "/crypto-assurance",
      "/agility", "/drift", "/intelligence"])
      expect(groupOf(crypto)).toBe("Crypto intelligence");
    // binary and OS/kernel intelligence are visible destinations, not children of posture
    expect(sectionOf("/binary-intelligence")).toBe("Intelligence");
    expect(groupOf("/binary-intelligence")).toBeNull();
    expect(sectionOf("/os-kernel-intelligence")).toBe("Intelligence");
    expect(groupOf("/os-kernel-intelligence")).toBeNull();
    // one twin & dependency workspace: replica, graph and simulations together
    for (const twin of ["/digital-twin", "/dependency-graph", "/graph", "/estate-twin",
      "/twin-walkthrough", "/simulation", "/what-if"])
      expect(groupOf(twin)).toBe("Twin & dependencies");
    for (const assurance of ["/assurance-records", "/assurance-coverage", "/assurance-trace",
      "/assurance-sampling", "/assurance-qualification"])
      expect(groupOf(assurance)).toBe("Assurance");
    expect(groupOf("/remediation")).toBe("Remediation");
    // the governance workflows are promoted out of deep-link obscurity
    expect(sectionOf("/governance")).toBe("Governance");
    expect(groupOf("/governance")).toBeNull();
    expect(sectionOf("/trust")).toBe("Governance");
    expect(groupOf("/trust")).toBeNull();
  });

  it("keeps every prior sidebar route reachable", () => {
    for (const route of [
      "/assets", "/dev-sec-ops", "/cloud", "/hardware", "/network", "/certificates",
      "/vendor", "/dependency-graph", "/crypto", "/crypto-assets", "/cbom", "/hbom",
      "/nbom", "/sbom", "/vbom", "/live-asset-intelligence", "/digital-twin", "/graph",
      "/findings", "/pqc", "/agility", "/drift", "/scanners", "/live-scanners", "/reports",
      "/simulation", "/what-if", "/assurance-records", "/assurance-coverage", "/assurance-trace",
      "/assurance-sampling", "/assurance-qualification", "/launch-readiness",
      "/operator-decisions", "/remediation", "/priorities", "/migration",
      "/system-health", "/settings", "/identity", "/integrations",
      // workflows promoted out of deep-link obscurity
      "/runtime", "/crypto-assurance", "/governance", "/trust",
    ]) expect(routes, route).toContain(route);
  });

  it("never lists the same route twice", () => {
    // a route listed twice is a page an operator can reach two ways and update one of
    expect(new Set(routes).size).toBe(routes.length);
  });

  it("gives every group at least two pages — a group of one is a click for nothing", () => {
    for (const item of items.filter((entry) => entry.children?.length)) {
      expect(item.children!.length, item.label).toBeGreaterThanOrEqual(2);
    }
  });

  it("keeps the group's own page inside the group, so the parent is reachable", () => {
    for (const item of items.filter((entry) => entry.children?.length)) {
      expect(item.children!.map((child) => child.to), item.label).toContain(item.to);
    }
  });
});
