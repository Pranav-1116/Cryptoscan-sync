/* The regression test for review item 18.

   `Resilience.tsx` renders through `t()` but had quietly grown hardcoded English: labels,
   help paragraphs, table headers and error messages that no translator would ever see and
   that rendered in English inside an Arabic, right-to-left console.

   A single test cannot prove translation quality. It can prove two things that keep the page
   translatable: every key the page asks for exists in both dictionaries, and no English
   sentence is spelled out inline. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import en from "../i18n/en.json";
import ar from "../i18n/ar.json";

// jsdom gives `import.meta.url` an http origin, so the path is resolved from the project root.
const source = readFileSync(resolve(process.cwd(), "src/pages/Resilience.tsx"), "utf8");
const dictionaries: Record<string, Record<string, string>> = { en, ar };

const usedKeys = [...source.matchAll(/\bt\("([^"]+)"\)/g)].map((match) => match[1]);

/* Terms that stay Latin in both languages: protocol names, digest field names and the word
   "sha", which an Arabic-speaking engineer reads in Latin script too. */
const KEPT_IN_LATIN = new Set([
  "resilience.colSha256",
  "resilience.sha",
  "resilience.protocolTcp",
  "resilience.protocolUdp",
]);

/* Text nodes and attributes that are allowed to stay literal: protocol identifiers, the
   names of environment variables, and separators. Anything else is English. */
const LITERAL_ALLOWED = [
  /^[\s·,…—–/|-]*$/,
  /^AIRGAP_[A-Z_]+$/,
  /^\(S7comm/,
  /^[{}()[\];:,.]+$/,
];

function hardcodedEnglish(): string[] {
  const offenders: string[] = [];
  // A JSX text node: no quotes, parens or braces, because those mean code, not prose.
  const jsxText = [...source.matchAll(/>([^<>{}()",;=]*[A-Za-z]{3,}[^<>{}()",;=]*)</g)]
    .map((match) => match[1].trim());
  for (const text of jsxText) {
    if (!text || LITERAL_ALLOWED.some((pattern) => pattern.test(text))) continue;
    offenders.push(text);
  }
  const attributes = [...source.matchAll(/(?:placeholder|aria-label|title)="([^"]+)"/g)].map((m) => m[1]);
  for (const value of attributes) offenders.push(`attribute: ${value}`);
  for (const match of source.matchAll(/setErr\("([^"]{4,})"/g)) offenders.push(`error: ${match[1]}`);
  return offenders;
}

describe("Resilience console internationalisation", () => {
  it("asks only for keys that exist in English and Arabic", () => {
    const missing: string[] = [];
    for (const key of new Set(usedKeys)) {
      for (const [lang, dictionary] of Object.entries(dictionaries)) {
        if (!(key in dictionary)) missing.push(`${key} (${lang})`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("keeps no English sentence inline in the page", () => {
    expect(hardcodedEnglish()).toEqual([]);
  });

  it("translates every added key instead of copying the English through", () => {
    const untranslated = [...new Set(usedKeys)].filter(
      (key) => key.startsWith("resilience.") && !KEPT_IN_LATIN.has(key) && en[key as keyof typeof en] === ar[key as keyof typeof ar],
    );
    expect(untranslated).toEqual([]);
  });

  it("does not let a lookup fall back to the key itself", () => {
    // `t()` returns the key when a dictionary lacks it, which silently renders
    // "resilience.something" in the console. Every used key must resolve.
    const unresolved = [...new Set(usedKeys)].filter((key) => !(key in en) || en[key as keyof typeof en] === key);
    expect(unresolved).toEqual([]);
  });
});
