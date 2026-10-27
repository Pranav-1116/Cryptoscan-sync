import { describe, expect, it } from "vitest";
import ts from "typescript";

const sources = import.meta.glob("../{pages,components}/**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const endpoint = /\/api\/(?:v\d+\b|docs\b)|\b(?:GET|POST|PUT|PATCH|DELETE|SSE)(?:\/(?:GET|POST|PUT|PATCH|DELETE))*\s+\/[a-z]/i;
const copyAttributes = new Set(["title", "sub", "label", "placeholder", "aria-label", "aria-description", "alt"]);

// Inspect authored display copy, not request URLs, hrefs or source comments.
// Paths must remain in transport code; hiding them is a presentation change,
// not a security control or an API change.
describe("operator-facing copy", () => {
  it("does not display raw API endpoints in text or descriptive props", () => {
    const violations: string[] = [];
    for (const [file, source] of Object.entries(sources)) {
      if (file.endsWith(".test.tsx")) continue;
      const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      const check = (node: ts.Node, text: string) => {
        if (!endpoint.test(text)) return;
        const { line } = ast.getLineAndCharacterOfPosition(node.getStart(ast));
        violations.push(`${file}:${line + 1}: ${text.trim()}`);
      };
      const visit = (node: ts.Node) => {
        if (ts.isJsxText(node)) check(node, node.text);
        if (ts.isJsxAttribute(node) && copyAttributes.has(node.name.getText(ast)) && node.initializer) {
          const inspectCopy = (part: ts.Node) => {
            if (ts.isStringLiteralLike(part) || ts.isTemplateHead(part) || ts.isTemplateMiddle(part) || ts.isTemplateTail(part)) {
              check(part, part.text);
            }
            ts.forEachChild(part, inspectCopy);
          };
          inspectCopy(node.initializer);
        }
        ts.forEachChild(node, visit);
      };
      visit(ast);
    }
    expect(Object.keys(sources).length).toBeGreaterThan(60);
    expect(violations).toEqual([]);
  });
});
