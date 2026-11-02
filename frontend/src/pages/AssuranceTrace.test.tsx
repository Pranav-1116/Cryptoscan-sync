import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import AssuranceTrace from "./AssuranceTrace";

describe("AssuranceTrace", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(AssuranceTrace);
  });
});
