import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import AssuranceRecords from "./AssuranceRecords";

describe("AssuranceRecords", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(AssuranceRecords);
  });
});
