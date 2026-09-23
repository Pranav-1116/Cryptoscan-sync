/* Maturity labels: the console can never promote a page the backend does
 * not declare. Route → tier, unknown → preview, retired nav gone. */
import { describe, expect, it } from "vitest";
import { CAPABILITIES_JSON, RETIRED_NAV_ROUTES, tierCounts, tierOf } from "./maturity";
// Vite serves the sources as raw strings — no node:fs, works in jsdom.
import appTsx from "../App.tsx?raw";
import layoutTsx from "../components/Layout.tsx?raw";

const routes = new Set(Array.from(appTsx.matchAll(/path="\/([a-z0-9-]+)"/g), (m: RegExpMatchArray) => m[1]));

describe("capability maturity", () => {
  it("classifies every route App.tsx serves", () => {
    const missing = [...routes].filter((r) => !(r in CAPABILITIES_JSON));
    expect(missing).toEqual([]);
  });

  it("does not classify routes that do not exist", () => {
    const orphans = Object.keys(CAPABILITIES_JSON).filter((r) => !routes.has(r));
    expect(orphans).toEqual([]);
  });

  it("unknown routes default down to preview; query strings and sub-paths are ignored", () => {
    expect(tierOf("/no-such-page")).toBe("preview");
    expect(tierOf("/cbom?tab=export")).toBe("ga");
    expect(tierOf("dev-sec-ops/binaries")).toBe("ga");
    expect(tierOf("/what-if")).toBe("preview");
  });

  it("is not all GA", () => {
    const c = tierCounts();
    expect(c.beta).toBeGreaterThan(0);
    expect(c.preview).toBeGreaterThan(0);
    expect(c.ga).toBeLessThan(Object.keys(CAPABILITIES_JSON).length * 0.6);
  });

  it("retired sidebar routes are gone and every sidebar link has a page", () => {
    for (const dead of RETIRED_NAV_ROUTES) expect(layoutTsx.includes(`"${dead}"`)).toBe(false);
    const linked = Array.from(layoutTsx.matchAll(/(?:to=|to: )"\/([a-z0-9-]+)"/g), (m: RegExpMatchArray) => m[1]);
    const broken = linked.filter((r) => !routes.has(r));
    expect(broken).toEqual([]);
  });
});
