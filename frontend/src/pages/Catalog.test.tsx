import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import Catalog from "./Catalog";

describe("Catalog", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(Catalog);
  });
});
