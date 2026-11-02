import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import AssuranceSampling from "./AssuranceSampling";

describe("AssuranceSampling", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(AssuranceSampling);
  });
});
