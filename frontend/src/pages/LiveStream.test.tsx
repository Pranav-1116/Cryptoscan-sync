import React from "react";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { activity, event } from "../test/opsFixtures";
import LiveStream from "./LiveStream";

const change = event("change:chg_1", {
  kind: "change", severity: "MEDIUM", title: "Crypto changed", detail: "2 change(s): 1× crypto added, 1× asset changed",
  acknowledged: false, ref: "chg_1", item_total: 2, next_action: "review the affected BOM",
  items: [{ kind: "CRYPTO_ADDED", severity: "MEDIUM", subject: "RSA-2048 on swiftgw01", before: null, after: "ACTIVE", detail: null },
          { kind: "ASSET_CHANGED", severity: "LOW", subject: "nginx", before: "1.22", after: "1.24", detail: null }],
});
const pattern = event("pattern:P1", { kind: "pattern", severity: "HIGH", title: "Correlated activity", agents: ["mrdn-sbx-dc1-coredb01"], systems: ["Core Banking"] });
const enrolled = event("audit:1", { title: "Agent enrolled" });

describe("activity timeline", () => {
  it("lists changes, patterns and agent events newest first with their systems", async () => {
    mockFetch({ "/api/v1/operations/activity": activity([change, pattern, enrolled]) });
    renderWithProviders(<LiveStream />, { route: "/live-stream" });
    const list = await screen.findByRole("list", { name: "Events" });
    expect(within(list).getAllByRole("listitem").filter((li) => li.getAttribute("aria-label")?.startsWith("Event"))).toHaveLength(3);
    expect(screen.getByLabelText("Event Correlated activity")).toHaveTextContent("Core Banking");
    expect(screen.getByLabelText("Event Crypto changed")).toHaveTextContent("unreviewed");
    expect(screen.getByLabelText("Unreviewed changes")).toHaveTextContent("1");
  });

  it("filters by kind and opens a change's itemised detail", async () => {
    mockFetch({ "/api/v1/operations/activity": activity([change, pattern, enrolled]) });
    renderWithProviders(<LiveStream />, { route: "/live-stream" });
    await screen.findByRole("list", { name: "Events" });
    fireEvent.click(screen.getByRole("button", { name: "Show Estate changes" }));
    expect(screen.queryByLabelText("Event Correlated activity")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Details of Crypto changed/ }));
    const row = screen.getByLabelText("Event Crypto changed");
    expect(row).toHaveTextContent("RSA-2048 on swiftgw01");
    expect(row).toHaveTextContent("1.22 → 1.24");
    expect(row).toHaveTextContent("review the affected BOM");
  });

  it("acknowledges a change through the change feed and re-reads", async () => {
    const spy = mockFetch({
      "/api/v1/operations/activity": activity([change]),
      "/api/v1/estate/evidence/changes/chg_1/acknowledge": { id: "chg_1", acknowledged: true },
    });
    renderWithProviders(<LiveStream />, { route: "/live-stream" });
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge chg_1" }));
    await waitFor(() => {
      const posts = spy.mock.calls.filter(([u, init]) => String(u).includes("/changes/chg_1/acknowledge") && (init as RequestInit | undefined)?.method === "POST");
      expect(posts).toHaveLength(1);
    });
  });

  it("says nothing has happened when the feed is empty", async () => {
    mockFetch({ "/api/v1/operations/activity": activity([]) });
    renderWithProviders(<LiveStream />, { route: "/live-stream" });
    expect(await screen.findByText(/Nothing has happened yet/)).toBeInTheDocument();
  });
});
