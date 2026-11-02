import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import Identity from "./Identity";

describe("Identity", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(Identity);
  });
});
