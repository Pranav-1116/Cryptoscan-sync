import { describe, expect, it } from "vitest";
import { prettyJson } from "./prettyJson";

describe("prettyJson", () => {
  it("indents a minified CycloneDX document", () => {
    const min = '{"$schema":"http://cyclonedx.org/schema/bom-1.6.schema.json","bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"RSA-2048","tags":[]}],"metadata":{}}';
    const out = prettyJson(min)!;
    expect(out).toContain('\n  "bomFormat": "CycloneDX",\n');
    expect(out).toContain('"tags": []');
    expect(out).toContain('"metadata": {}');
    expect(JSON.parse(out)).toEqual(JSON.parse(min));
  });

  it("changes whitespace only — numbers and escapes are copied verbatim", () => {
    const min = '{"n":12345678901234567890,"f":1.0,"e":1E3,"s":"a, b: {c} [d] \\"q\\" \\\\"}';
    const out = prettyJson(min)!;
    expect(out.replace(/\s+(?=(?:[^"\\]|\\.|"(?:[^"\\]|\\.)*")*$)/g, "")).toBe(min);
    expect(out).toContain("12345678901234567890");
    expect(out).toContain('"f": 1.0');
    expect(out).toContain('"s": "a, b: {c} [d] \\"q\\" \\\\"');
  });

  it("leaves invalid or non-container input alone", () => {
    expect(prettyJson("not json")).toBeNull();
    expect(prettyJson('"just a string"')).toBeNull();
    expect(prettyJson('{\n  "already": "pretty"\n}')).toBeNull();
  });
});
