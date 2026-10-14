/* §5 (round 66): the global accessibility pass, pinned.
 *
 * What is asserted here:
 *   - a skip link is the first focusable element and lands on a focusable
 *     main landmark (keyboard users don't tab through 39 nav links)
 *   - the active nav link carries aria-current="page" (screen readers
 *     announce where you are; the .active class is visual only)
 *   - the first-visit theme honors the OS prefers-color-scheme, and an
 *     explicit stored choice still wins
 *   - every text token in BOTH themes meets WCAG AA (4.5:1) on every
 *     surface it can appear on — computed from the real global.css, not
 *     hand-checked: a token regression fails this test
 *   - the un-overridable keyboard focus ring and the skip-link styles
 *     exist in the stylesheet
 */
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { I18nProvider } from "../i18n/I18n";
import { RealtimeProvider } from "../lib/realtime";
import Layout from "./Layout";

// vitest runs with `css: false`, so a ?raw CSS import comes back empty —
// read the stylesheet straight from disk instead (tests execute in Node;
// vitest always runs from the frontend/ root where this config lives).
const globalCss = readFileSync(
  resolve(process.cwd(), "src/styles/global.css"), "utf8");

const shell = (route: string) =>
  render(
    <I18nProvider><RealtimeProvider>
      <MemoryRouter initialEntries={[route]}>
        <Layout><div data-testid="page">page body</div></Layout>
      </MemoryRouter>
    </RealtimeProvider></I18nProvider>,
  );

afterEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("keyboard: skip link and main landmark", () => {
  it("renders the skip link as the first focusable element, targeting a focusable main", async () => {
    shell("/command-center");
    const skip = await screen.findByRole("link", { name: "Skip to main content" });
    expect(skip.getAttribute("href")).toBe("#main-content");
    // it is the FIRST link in the DOM — before the 39 nav links
    const firstLink = document.querySelector("a");
    expect(firstLink).toBe(skip);
    // and its target exists as a focusable landmark
    const main = document.getElementById("main-content");
    expect(main).not.toBeNull();
    expect(main?.tagName).toBe("MAIN");
    expect(main?.getAttribute("tabindex")).toBe("-1");
  });
});

describe("screen readers: navigation state", () => {
  it("marks the active nav link with aria-current=page and only that link", async () => {
    shell("/findings");
    const active = await screen.findByRole("link", { name: /findings/i });
    expect(active.getAttribute("aria-current")).toBe("page");
    const other = screen.getAllByRole("link").find(
      (l) => l.getAttribute("href") === "/pqc");
    expect(other).toBeTruthy();
    expect(other?.getAttribute("aria-current")).toBeNull();
  });
});

describe("theme: the OS preference is honored on first visit", () => {
  const originalMatchMedia = window.matchMedia;
  afterEach(() => {
    window.matchMedia = originalMatchMedia;
  });

  // A matchMedia double that answers "light" for the color-scheme query
  // and "no" for everything else (reduced motion etc. keep their defaults).
  const osLight = ((q: string) => ({
    matches: q.includes("prefers-color-scheme: light"),
    media: q,
    onchange: null,
    addListener() {}, removeListener() {},
    addEventListener() {}, removeEventListener() {},
    dispatchEvent() { return false; },
  })) as unknown as typeof window.matchMedia;

  it("defaults to light when the OS prefers light and nothing is stored", async () => {
    window.matchMedia = osLight;
    shell("/command-center");
    await screen.findByTestId("page");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("an explicit stored choice beats the OS preference", async () => {
    window.matchMedia = osLight;
    localStorage.setItem("zelnx-theme", "dark");
    shell("/command-center");
    await screen.findByTestId("page");
    expect(document.documentElement.getAttribute("data-theme")).toBeNull(); // dark = no data-theme
  });
});

describe("contrast: every text token passes WCAG AA in both themes", () => {
  const lum = (hex: string): number => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
    const lin = c.map((x) => (x <= 0.04045 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4)));
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
  };
  const ratio = (fg: string, bg: string): number => {
    const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
    return (a + 0.05) / (b + 0.05);
  };

  /* Cascade-aware token resolution: the stylesheet declares :root and
   * :root[data-theme="light"] MORE THAN ONCE (the later "enterprise
   * refresh" blocks override the design-system blocks), so the effective
   * value of a token is its LAST declaration. Light additionally inherits
   * anything it does not define from the effective dark set — exactly how
   * CSS custom properties resolve. */
  const declarations = (re: RegExp): Array<[string, string]> =>
    [...globalCss.matchAll(re)]
      .flatMap((m) => [...m[1].matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})/g)])
      .map((m) => [m[1], m[2]] as [string, string]);
  const resolve = (pairs: Array<[string, string]>): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const [k, v] of pairs) out[k] = v; // later declarations win
    return out;
  };
  const dark = resolve(declarations(/:root\s*\{([^}]*)\}/g));
  const light = { ...dark, ...resolve(declarations(/:root\[data-theme="light"\]\s*\{([^}]*)\}/g)) };

  it("has the expected tokens in both effective themes", () => {
    for (const t of ["bg", "bg-2", "panel", "panel-2", "text", "dim", "faint",
                     "green", "amber", "orange", "red", "cyan", "accent", "on-accent"]) {
      expect(dark[t], `dark --${t}`).toBeTruthy();
      expect(light[t], `light --${t}`).toBeTruthy();
    }
  });

  it.each(["dark", "light"])("%s theme: text/dim/faint hold 4.5:1 on every surface", (name) => {
    const t = name === "dark" ? dark : light;
    for (const fg of ["text", "dim", "faint"]) {
      for (const surf of ["bg", "bg-2", "panel", "panel-2"]) {
        expect(ratio(t[fg], t[surf]),
          `${name} --${fg} ${t[fg]} on --${surf} ${t[surf]}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it.each(["dark", "light"])("%s theme: status hues hold 4.5:1 as text on the base surfaces", (name) => {
    const t = name === "dark" ? dark : light;
    for (const fg of ["green", "amber", "orange", "red", "cyan"]) {
      for (const surf of ["bg", "bg-2", "panel", "panel-2"]) {
        expect(ratio(t[fg], t[surf]),
          `${name} --${fg} ${t[fg]} on --${surf} ${t[surf]}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it.each(["dark", "light"])("%s theme: text on the accent meets 4.5:1", (name) => {
    const t = name === "dark" ? dark : light;
    expect(ratio(t["on-accent"], t.accent)).toBeGreaterThanOrEqual(4.5);
  });
});

describe("stylesheet contracts", () => {
  it("keeps the un-overridable keyboard focus ring", () => {
    expect(globalCss).toContain(":focus-visible");
    expect(globalCss).toContain("outline: 2px solid var(--accent) !important");
  });

  it("keeps the skip-link styles (hidden until focused)", () => {
    expect(globalCss).toContain(".skip-link {");
    expect(globalCss).toContain(".skip-link:focus { top: 8px; }");
  });

  it("declares color-scheme for both themes so native controls follow", () => {
    expect(globalCss).toContain("color-scheme: dark");
    expect(globalCss).toContain("color-scheme: light");
  });

  it("collapses to a single column with a horizontal nav bar at phone width (<=560px)", () => {
    const phone = globalCss.slice(globalCss.indexOf("@media (max-width: 560px)"));
    expect(phone).toContain(".shell { grid-template-columns: 1fr; }");
    expect(phone).toContain(".sidebar { position: static;");
    expect(phone).toContain(".searchov .groups { grid-template-columns: 1fr; }");
  });
});
