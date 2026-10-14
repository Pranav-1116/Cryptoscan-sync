/* §5 (round 62): full search covers OBSERVED assets via server-side
 * estate search — not only the reference algorithm catalog — and the
 * groups say which is which. */

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import SearchResults from "./SearchResults";

const renderAt = (q: string) =>
  render(
    <MemoryRouter initialEntries={[`/search-results?q=${encodeURIComponent(q)}`]}>
      <SearchResults />
    </MemoryRouter>,
  );

describe("SearchResults — observed assets, server-side", () => {
  it("shows estate assets from the server-side search, labeled as observed", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/algorithms": { algorithms: [{ name: "RSA", family: "asymmetric", status: "ALLOWED" }] },
      "/api/v1/protocols": { protocols: [] },
      "/api/v1/hardware": { devices: [] },
      "/api/v1/runtime-findings": { findings: [] },
      "/api/v1/assets": { assets: [
        { id: "asset-1", algorithm: "RSA-2048", file_path: "src/Keys.java", asset_key: "fact:v1:abc", lifecycle_state: "DISCOVERED" },
        { id: "asset-2", algorithm: "RSA-4096", file_path: "src/Backup.java", asset_key: "fact:v1:def", lifecycle_state: "ACTIVE" },
      ], total_count: 2, page: 1, page_size: 25 },
    });
    renderAt("RSA");
    await waitFor(() => expect(screen.getByText(/Assets \(estate, 2 matches\)/)).toBeTruthy());
    expect(screen.getByText("RSA-2048 · Keys.java")).toBeTruthy();
    expect(screen.getByText("RSA-4096 · Backup.java")).toBeTruthy();
    // the request went to the server with the term, not a page-local filter
    const assetCall = fetchSpy.mock.calls.find(([p]) => String(p).includes("/api/v1/assets?q=RSA"));
    expect(assetCall).toBeTruthy();
    // reference catalog results stay labeled as reference, not observed usage
    expect(screen.getByText("Algorithms")).toBeTruthy();
  });

  it("shows an honest empty state when nothing matches — no invented rows", async () => {
    mockFetch({
      "/api/v1/algorithms": { algorithms: [] },
      "/api/v1/protocols": { protocols: [] },
      "/api/v1/hardware": { devices: [] },
      "/api/v1/runtime-findings": { findings: [] },
      "/api/v1/assets": { assets: [], total_count: 0, page: 1, page_size: 25 },
    });
    renderAt("nope-xyz");
    await waitFor(() => expect(screen.getByText("No matches")).toBeTruthy());
    expect(screen.queryByText(/Assets \(estate/)).toBeNull();
  });
});
