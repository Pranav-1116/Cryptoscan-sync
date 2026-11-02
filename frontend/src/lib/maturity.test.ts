/* Support status: the console can never promote a page the backend does not
 * declare. Every shipped route is supported, unknown → preview (down, never
 * up), the limitation stays with the surface, and the shell renders no label. */
import { describe, expect, it } from "vitest";
import { CAPABILITIES_JSON, CAPABILITY_LIMITS, RETIRED_NAV_ROUTES, tierCounts, tierOf } from "./maturity";
// Vite serves the sources as raw strings — no node:fs, works in jsdom.
import appTsx from "../App.tsx?raw";
import layoutTsx from "../components/Layout.tsx?raw";

const routes = new Set(Array.from(appTsx.matchAll(/path="\/([a-z0-9-]+)"/g), (m: RegExpMatchArray) => m[1]));

describe("capability maturity", () => {
  it("classifies every page route; aliases redirect to classified destinations", () => {
    const redirects = Array.from(appTsx.matchAll(/<Route path="\/([a-z0-9-]+)" element={<Navigate to="\/([a-z0-9-]+)" replace \/>} \/>/g));
    const aliases = new Map(redirects.map((m) => [m[1], m[2]]));
    // /audit used to redirect to the security centre; it is its own page now
    // (guide 118), so only the technology-BOM alias is left
    expect([...aliases.entries()]).toEqual([
      ["techbom", "live-asset-intelligence"],
    ]);
    const missing = [...routes].filter((r) => !(r in CAPABILITIES_JSON) && !aliases.has(r));
    expect(missing).toEqual([]);
    expect([...aliases.values()].every((destination) => destination in CAPABILITIES_JSON)).toBe(true);
  });

  it("keeps raw API paths out of register prose — the console prints this text verbatim", () => {
    // /scope renders every capability's statement, so a path that leaks into a
    // description becomes a raw API path on a bank screen; this assertion has
    // caught that twice now
    const leaks = Object.values(CAPABILITY_LIMITS)
      .filter((entry) => /\/api\/(?:v\d+\b|docs\b)|\b(?:GET|POST|PUT|PATCH|DELETE|SSE)\s+\/[a-z]/i.test(entry.limit))
      .map((entry) => entry.limit.slice(0, 80));
    expect(leaks).toEqual([]);
  });

  it("does not classify routes that do not exist", () => {
    const orphans = Object.keys(CAPABILITIES_JSON).filter((r) => !routes.has(r));
    expect(orphans).toEqual([]);
  });

  it("unknown routes default down to preview; query strings and sub-paths are ignored", () => {
    expect(tierOf("/no-such-page")).toBe("preview");
    expect(tierOf("/cbom?tab=export")).toBe("ga");
    expect(tierOf("dev-sec-ops/binaries")).toBe("ga");
    expect(tierOf("/live-monitor")).toBe("ga");
    expect(tierOf("/assurance-coverage")).toBe("ga");
  });

  it("carries a stated limit for every shipped surface instead of a beta badge", () => {
    const c = tierCounts();
    expect(c).toEqual({ ga: Object.keys(CAPABILITIES_JSON).length, beta: 0, preview: 0 });
    const slugs = Object.keys(CAPABILITIES_JSON);
    expect(Object.keys(CAPABILITY_LIMITS).sort()).toEqual([...slugs].sort());
    const thin = Object.entries(CAPABILITY_LIMITS)
      .filter(([, entry]) => !entry.area || entry.limit.length < 20)
      .map(([slug]) => slug);
    expect(thin).toEqual([]);
  });

  it("renders no maturity label in the shell: the navigation is not a status board", () => {
    expect(layoutTsx).not.toContain("TierPill");
    expect(layoutTsx).not.toContain("MaturityBanner");
    expect(layoutTsx).not.toContain("tierOf");
    expect(layoutTsx).not.toContain("tier-pill");
    const pages = import.meta.glob("../pages/*.tsx", { query: "?raw", import: "default", eager: true });
    const labelled = Object.entries(pages)
      .filter(([file]) => !file.endsWith(".test.tsx"))
      .filter(([, source]) => /TIER_LABEL|MaturityBanner|TierPill/.test(String(source)))
      .map(([file]) => file);
    expect(labelled).toEqual([]);
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
