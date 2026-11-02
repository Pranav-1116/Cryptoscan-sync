import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import AssuranceQualification from "./AssuranceQualification";

describe("AssuranceQualification", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(AssuranceQualification);
  });
});
