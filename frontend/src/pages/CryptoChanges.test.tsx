import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import CryptoChanges from "./CryptoChanges";

describe("CryptoChanges", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(CryptoChanges);
  });
});
