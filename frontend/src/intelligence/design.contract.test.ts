import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

// Design contract for the intelligence workbench (roadmap item 11):
// dark navy / charcoal, dense tables, and none of the banned decoration —
// no gradients, no glow effects, no chatbot panels. This test reads the real
// source files so a future edit cannot quietly reintroduce them.

const here = path.dirname(fileURLToPath(import.meta.url));

function sources(): Array<{ name: string; body: string }> {
  return readdirSync(here)
    .filter((f) => (f.endsWith(".tsx") || f.endsWith(".css")) && !f.includes(".test."))
    .map((name) => ({ name, body: readFileSync(path.join(here, name), "utf8") }));
}

const BANNED: Array<[string, RegExp]> = [
  ["gradients", /gradient/i],
  ["glow effects", /glow/i],
  ["chatbot panels", /chatbot/i],
  ["text shadows", /text-shadow/i],
  ["drop shadows", /drop-shadow/i],
];

describe("intelligence workbench design contract", () => {
  it("bans gradients, glow and chatbot surfaces in every source file", () => {
    for (const { name, body } of sources()) {
      for (const [label, pattern] of BANNED) {
        expect(
          pattern.test(body),
          `${name} must not introduce ${label}`,
        ).toBe(false);
      }
    }
  });

  it("the stylesheet is loaded by the workbench, not just filed", () => {
    // The theme existed for weeks without an import: every chip, banner and
    // dense table rendered as bare text. The import is now pinned.
    const workbench = readFileSync(
      path.join(here, "IntelligenceWorkbench.tsx"),
      "utf8",
    );
    expect(workbench).toMatch(/import ["']\.\/intelligence\.css["']/);
  });

  it("pins the navy/charcoal palette", () => {
    const css = readFileSync(path.join(here, "intelligence.css"), "utf8");
    expect(css).toContain("#0b1220"); // dark navy
    expect(css).toContain("#1a2332"); // charcoal
    expect(css).toContain("--intel-navy");
    expect(css).toContain("--intel-charcoal");
  });

  it("the tables are dense, not decorative", () => {
    const css = readFileSync(path.join(here, "intelligence.css"), "utf8");
    expect(css).toMatch(/\.intel th,\s*\n\.intel td \{[^}]*padding: 3px 6px/s);
  });
});
