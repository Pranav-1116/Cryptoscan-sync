/* Application state: shared filters, selection and graph level-of-detail. */

import { beforeEach, describe, expect, it } from "vitest";
import { useConsoleStore } from "./appStore.js";

beforeEach(() => {
  useConsoleStore.setState({
    filters: {}, selectedAssetId: null, graphExpansion: {}, graphDepth: 1, scans: {},
  });
});

describe("console store", () => {
  it("holds cross-page filters and selection", () => {
    useConsoleStore.getState().setFilter("assetsEnv", "prod");
    useConsoleStore.getState().selectAsset("a-1");
    expect(useConsoleStore.getState().filters.assetsEnv).toBe("prod");
    expect(useConsoleStore.getState().selectedAssetId).toBe("a-1");
    useConsoleStore.getState().clearFilters();
    expect(useConsoleStore.getState().filters).toEqual({});
  });

  it("tracks graph expansion for progressive disclosure, bounded depth", () => {
    const s = useConsoleStore.getState();
    s.expandNode("n1", true);
    s.expandNode("n2", true);
    s.expandNode("n1", false);
    expect(Object.keys(useConsoleStore.getState().graphExpansion)).toEqual(["n2"]);
    useConsoleStore.getState().setGraphDepth(9);
    expect(useConsoleStore.getState().graphDepth).toBe(3); // clamped: LOD stays bounded
    useConsoleStore.getState().resetGraph();
    expect(useConsoleStore.getState().graphExpansion).toEqual({});
    expect(useConsoleStore.getState().graphDepth).toBe(1);
  });

  it("mirrors scan progress from the live stream", () => {
    useConsoleStore.getState().ingestScanEvent("scan-1", { stage: "evidence", status: "RUNNING" });
    useConsoleStore.getState().ingestScanEvent("scan-1", { stage: "alert", status: "COMPLETED", findings: 12 });
    expect(useConsoleStore.getState().scans["scan-1"]).toEqual(
      { stage: "alert", status: "COMPLETED", findings: 12 },
    );
  });
});
