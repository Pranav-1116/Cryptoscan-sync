/* Every page renders with the backend unreachable.
 *
 * The console's contract is "no fabricated data": with no backend, every page
 * must still mount and show its honest empty/offline state — not a blank
 * screen, not an uncaught error. This one file covers all 75 pages; a page
 * that throws on mount fails here by name. */
import { describe, expect, it } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";

// mirror App.tsx: one entry per page file, discovered at build time
const modules = import.meta.glob("./*.tsx", { eager: false });
const pages = Object.keys(modules)
  .filter((p) => !p.endsWith(".test.tsx"))
  .map((p) => p.replace("./", "").replace(".tsx", ""))
  .sort();

describe("pages render offline", () => {
  it("discovers the page files App.tsx routes to", () => {
    expect(pages.length).toBeGreaterThan(60);
    expect(pages).toContain("CommandCenter");
    expect(pages).toContain("Login");
  });

  for (const name of pages) {
    it(`${name} mounts without throwing and paints something`, async () => {
      const mod = (await modules[`./${name}.tsx`]()) as { default: React.ComponentType };
      const Page = mod.default;
      expect(typeof Page).toBe("function");
      const errors: unknown[] = [];
      const onError = (e: ErrorEvent) => { errors.push(e.error ?? e.message); e.preventDefault(); };
      window.addEventListener("error", onError);
      let container: HTMLElement;
      try {
        await act(async () => {
          ({ container } = renderWithProviders(<Page />, { route: `/${name.toLowerCase()}` }));
        });
        await waitFor(() => expect(container.textContent?.trim().length ?? 0).toBeGreaterThan(0), { timeout: 5000 });
      } finally {
        window.removeEventListener("error", onError);
      }
      expect(errors, `uncaught error while rendering ${name}`).toEqual([]);
    });
  }
});
