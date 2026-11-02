import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import Cloud from "./Cloud";

describe("Cloud", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(Cloud);
  });
});
