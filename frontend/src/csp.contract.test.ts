/* Content Security Policy contract (Critical: reduces script-injection
 * risk). The backend serves a strict CSP (no third-party CDNs, no inline
 * event handlers, no <object>/<embed>); this test pins the frontend half:
 * nothing in the source may demand an inline-script exception.
 *
 * The policy in api/middleware/security_headers.py allows 'self' only —
 * so the source must never contain the patterns that would silently force
 * a CSP relaxation the day someone runs the built console. */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC = join(__dirname, "..", "src");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

describe("CSP source contract", () => {
  // The checker names the patterns it forbids — never scan yourself.
  const files = walk(SRC).filter((f) => !f.endsWith("csp.contract.test.ts"));

  it("scans a real source tree (the checker is not vacuous)", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  it("never injects raw HTML (no dangerouslySetInnerHTML)", () => {
    const offenders = files.filter((f) => readFileSync(f, "utf8").includes("dangerouslySetInnerHTML"));
    expect(offenders).toEqual([]);
  });

  it("never evals or compiles strings (no eval / new Function)", () => {
    const offenders = files.filter((f) => {
      const src = readFileSync(f, "utf8");
      return /(^|[^.\w])eval\s*\(/.test(src) || /new\s+Function\s*\(/.test(src);
    });
    expect(offenders).toEqual([]);
  });

  it("never writes inline HTML event handlers (onX=\"code\")", () => {
    // JSX onClick={fn} is a React prop — it compiles away and is never an
    // inline handler; the CSP violation is an HTML handler VALUE in quotes
    // (onX="code"), which would need an inline-script exception.
    const offenders = files.filter((f) =>
      /\son(click|load|error|mouseover|focus|change)\s*=\s*["']/i.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("the shipped index.html loads external scripts only", () => {
    const html = readFileSync(join(__dirname, "..", "index.html"), "utf8");
    const inline = html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) ?? [];
    expect(inline).toEqual([]);
  });
});
