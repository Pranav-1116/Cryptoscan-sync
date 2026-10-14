/* Maturity labels: the console can never promote a page the backend does
 * not declare. Route → tier, unknown → preview, retired nav gone. */
import { describe, expect, it } from "vitest";
import { CAPABILITIES_JSON, RETIRED_NAV_ROUTES, tierCounts, tierOf } from "./maturity";
// Vite serves the sources as raw strings — no node:fs, works in jsdom.
import appTsx from "../App.tsx?raw";
import layoutTsx from "../components/Layout.tsx?raw";

const routes = new Set(Array.from(appTsx.matchAll(/path="\/([a-z0-9-]+)"/g), (m: RegExpMatchArray) => m[1]));

describe("capability maturity", () => {
  it("classifies every page route; aliases redirect to classified destinations", () => {
    const redirects = Array.from(appTsx.matchAll(/<Route path="\/([a-z0-9-]+)" element={<Navigate to="\/([a-z0-9-]+)" replace \/>} \/>/g));
    const aliases = new Map(redirects.map((m) => [m[1], m[2]]));
    expect([...aliases.entries()]).toEqual([
      ["audit", "security-center"],
      ["techbom", "live-asset-intelligence"],
    ]);
    const missing = [...routes].filter((r) => !(r in CAPABILITIES_JSON) && !aliases.has(r));
    expect(missing).toEqual([]);
    expect([...aliases.values()].every((destination) => destination in CAPABILITIES_JSON)).toBe(true);
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

  it("keeps visible page CTAs on BrowserRouter paths, never hash-only destinations", () => {
    const pages = import.meta.glob("../pages/*.tsx", { query: "?raw", import: "default", eager: true });
    const components = import.meta.glob("../components/*.tsx", { query: "?raw", import: "default", eager: true });
    for (const [filename, source] of Object.entries({ ...pages, ...components })) {
      if (filename.endsWith(".test.tsx")) continue;
      const text = String(source);
      expect(text, filename).not.toContain('"#/');
      expect(text, filename).not.toContain("'#/");
      const targets = [...text.matchAll(/\b(?:to|verifyLink)[:=]\s*"(\/[a-z0-9-]+)"/g)].map((m) => m[1]);
      const anchors = [...text.matchAll(/<(?:a|Link)\b[^>]*\bhref="(\/[a-z0-9-]+)"/g)].map((m) => m[1]);
      const broken = [...targets, ...anchors].filter((path) => !routes.has(path.slice(1)));
      expect(broken, filename).toEqual([]);
    }
  });
});
