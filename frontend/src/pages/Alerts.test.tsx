import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import Alerts from "./Alerts";

describe("Alerts", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(Alerts);
  });
});
