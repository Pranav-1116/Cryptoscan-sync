import { describe, expect, it } from "vitest";
import { readFailure, writeFailure } from "./requestFeedback";

describe("Safe feedback preserves refusal and uncertainty boundaries", () => {
  it.each([[401, "Session expired"], [403, "Access refused"], [409, "Read refused"], [422, "Read refused"], [429, "Read refused"], [503, "Service unavailable"]] as const)("categorizes read HTTP %s without server detail", (status, category) => {
    expect(readFailure(status)).toBe(`${category === "Session expired" ? "Session expired or authentication required" : category} (HTTP ${status})`);
  });
  it.each([400, 422])("calls HTTP %s a rejected validation and retains the draft", status => {
    expect(writeFailure(status)).toMatch(/^Validation rejected/);
    expect(writeFailure(status)).toContain("Draft retained");
    expect(writeFailure(status)).not.toContain("outcome not confirmed");
  });
  it.each([undefined, 200, 404, 408, 429, 500, 503])("does not infer a write outcome from transport/HTTP %s", status => {
    expect(writeFailure(status)).toContain("Action outcome not confirmed");
    expect(writeFailure(status)).toContain("reconcile current history before retrying");
  });
  it("requires revision reconciliation instead of advising a blind conflict retry", () => {
    expect(writeFailure(409)).toMatch(/revision conflict.*reconcile current history.*Do not blindly retry/);
  });
});
