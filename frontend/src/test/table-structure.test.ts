import { describe, expect, it } from "vitest";
import ts from "typescript";

/* A panel placed inside a <tbody> (or straight inside a <table>/<tr>) is invalid
   HTML: the browser squeezes it into the table's first column, so the page draws
   only on the left and the right side stays empty. This happened on the CBOM page
   (Import / host evidence / historical review inside the inventory table). */

const sources = import.meta.glob("../{pages,components}/**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const ALLOWED: Record<string, string[]> = {
  table: ["caption", "colgroup", "thead", "tbody", "tfoot", "tr"],
  thead: ["tr"],
  tbody: ["tr"],
  tfoot: ["tr"],
  tr: ["td", "th"],
};

describe("table structure", () => {
  it("never puts panels or other elements directly inside table sections", () => {
    const violations: string[] = [];
    for (const [file, source] of Object.entries(sources)) {
      if (file.endsWith(".test.tsx")) continue;
      const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      const tag = (node: ts.JsxElement | ts.JsxSelfClosingElement) =>
        (ts.isJsxElement(node) ? node.openingElement.tagName : node.tagName).getText(ast);
      const visit = (node: ts.Node) => {
        if (ts.isJsxElement(node)) {
          const parent = tag(node);
          const allowed = ALLOWED[parent];
          if (allowed) {
            for (const child of node.children) {
              if (!ts.isJsxElement(child) && !ts.isJsxSelfClosingElement(child)) continue;
              const name = tag(child);
              if (name === "React.Fragment" || name === "Fragment") continue;
              // a lower-case tag must be valid here; a component directly inside
              // <table>/<thead>/<tbody> is almost always a panel in the wrong place
              const bad = /^[a-z]/.test(name) ? !allowed.includes(name) : parent !== "tr";
              if (bad) {
                const { line } = ast.getLineAndCharacterOfPosition(child.getStart(ast));
                violations.push(`${file}:${line + 1}: <${name}> directly inside <${parent}>`);
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(ast);
    }
    expect(violations).toEqual([]);
  });
});
