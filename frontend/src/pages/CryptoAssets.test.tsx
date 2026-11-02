import { describe, it } from "vitest";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import CryptoAssets from "./CryptoAssets";

describe("CryptoAssets", () => {
  it("mounts against an empty API and shows a state, not a blank panel", async () => {
    await rendersAnHonestEmptyState(CryptoAssets);
  });
});
