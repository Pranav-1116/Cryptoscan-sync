import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import AssuranceCoverage from "./AssuranceCoverage";

describe("AssuranceCoverage", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(AssuranceCoverage);
  });
});
