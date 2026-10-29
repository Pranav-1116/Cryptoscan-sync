/* Tone resolution shared by every chart primitive.
 *
 * Pages state a state ("ok", "warn", "critical") or a colour. Before the alias
 * table existed only colour names resolved, so a critical state painted in the
 * neutral accent — a status screen that could not show red. */
import { describe, expect, it } from "vitest";
import { toneColor } from "./viz";

describe("toneColor", () => {
  it.each([
    ["ok", "var(--green)"],
    ["good", "var(--green)"],
    ["pass", "var(--green)"],
    ["live", "var(--green)"],
    ["warn", "var(--amber)"],
    ["warning", "var(--amber)"],
    ["medium", "var(--amber)"],
    ["critical", "var(--red)"],
    ["fail", "var(--red)"],
    ["bad", "var(--red)"],
    ["high", "var(--orange)"],
    ["muted", "var(--slate)"],
    ["unknown", "var(--slate)"],
    ["green", "var(--green)"],
    ["amber", "var(--amber)"],
    ["red", "var(--red)"],
  ])("maps %s to %s", (tone, expected) => {
    expect(toneColor(tone)).toBe(expected);
  });

  it("is case-insensitive and tolerant of padding", () => {
    expect(toneColor(" CRITICAL ")).toBe("var(--red)");
    expect(toneColor("Warn")).toBe("var(--amber)");
  });

  it("falls back to the neutral accent rather than an undefined token", () => {
    expect(toneColor("not-a-tone")).toBe("var(--accent)");
    expect(toneColor("")).toBe("var(--accent)");
    expect(toneColor()).toBe("var(--accent)");
  });
});
