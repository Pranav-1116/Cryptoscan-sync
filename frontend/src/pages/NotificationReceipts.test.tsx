import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import NotificationReceipts from "./NotificationReceipts";

const summary = {
  observed_at: "2026-10-17T10:00:00+00:00", total: 5, pending: 3, time_eligible: 2,
  expired_claims: 1, oldest_pending_at: "2026-10-16T10:00:00+00:00",
  counts: { pending: 1, failed: 1, inflight: 1, delivered: 1, legacy_unknown: 1 }, note: "",
};
const item = {
  id: "receipt-new", event_id: "event-new", integration_id: "receiver-1", channel: "siem",
  event_class: "remediation_verification", status: "failed", attempt_count: 3, http_status: 503,
  created_at: "2026-10-17T09:00:00+00:00", delivered_at: null,
  next_attempt_at: "2026-10-17T10:01:00+00:00", lease_expires_at: null,
  has_error: true, time_eligible: false,
};
const page = (items = [item], next_cursor: string | null = null) => ({ items, next_cursor, observed_at: summary.observed_at, note: "" });

function setup(overrides = {}) {
  return mockFetch({
    "/api/v1/notifications/delivery-summary": summary,
    "/api/v1/notifications/deliveries": page(),
    ...overrides,
  });
}

describe("Read-only notification receipt inspection", () => {
  it("shows existing backlog without dispatch and never equates legacy unknown with delivery", async () => {
    const fetch = setup();
    render(<NotificationReceipts />);
    expect(await screen.findByText("Pending receipts: 3")).toBeTruthy();
    expect(screen.getByText("Legacy unknown: 1")).toBeTruthy();
    expect(screen.getByText("Expired claims: 1")).toBeTruthy();
    expect(await screen.findByText("receipt-new")).toBeTruthy();
    expect(screen.getByText(/Error recorded; details withheld/)).toBeTruthy();
    expect(screen.getByTitle(/HTTP acknowledgement is not downstream ingestion or scheduler liveness/)).toBeTruthy();
    expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === "GET")).toBe(true);
  });

  it("navigates keyset pages and returns to newest without appending duplicates", async () => {
    const fetch = setup({
      "/api/v1/notifications/deliveries": (url: string) => new URL(url, "http://test").searchParams.has("cursor")
        ? page([{ ...item, id: "receipt-old" }]) : page([item], "opaque-cursor"),
    });
    render(<NotificationReceipts />);
    fireEvent.click(await screen.findByRole("button", { name: "Older receipts" }));
    expect(await screen.findByText("receipt-old")).toBeTruthy();
    expect(screen.queryByText("receipt-new")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Newest receipts" }));
    expect(await screen.findByText("receipt-new")).toBeTruthy();
    expect(screen.queryByText("receipt-old")).toBeNull();
    expect(fetch.mock.calls.some(([url]) => String(url).includes("cursor=opaque-cursor"))).toBe(true);
  });

  it("resets pagination on filtering and never lets an old page overwrite the new filter", async () => {
    let resolveOld!: (value: ReturnType<typeof page>) => void;
    const pending = new Promise<ReturnType<typeof page>>((resolve) => { resolveOld = resolve; });
    const fetch = setup({
      "/api/v1/notifications/deliveries": (url: string) => {
        const params = new URL(url, "http://test").searchParams;
        if (params.get("status") === "legacy_unknown") return page([{ ...item, id: "legacy-receipt", status: "legacy_unknown" }]);
        if (params.has("cursor")) return pending;
        return page([item], "older");
      },
    });
    render(<NotificationReceipts />);
    fireEvent.click(await screen.findByRole("button", { name: "Older receipts" }));
    expect(screen.queryByText("receipt-new")).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Receipt status" }), { target: { value: "legacy_unknown" } });
    expect(await screen.findByText("legacy-receipt")).toBeTruthy();
    resolveOld(page([{ ...item, id: "stale-old-receipt" }]));
    await waitFor(() => expect(screen.queryByText("stale-old-receipt")).toBeNull());
    expect(fetch.mock.calls.some(([url]) => String(url).includes("status=legacy_unknown") && !String(url).includes("cursor="))).toBe(true);
  });

  it("does not turn unavailable counts or ledger data into zero/healthy outcomes", async () => {
    setup({
      "/api/v1/notifications/delivery-summary": new Response("", { status: 503 }),
      "/api/v1/notifications/deliveries": new Response("", { status: 503 }),
    });
    render(<NotificationReceipts />);
    expect(await screen.findByText("Receipt counts unavailable — not measured.")).toBeTruthy();
    expect(await screen.findByTitle(/Receipt ledger unavailable — not measured/)).toBeTruthy();
    expect(screen.queryByText("Pending receipts: 0")).toBeNull();
    expect(screen.queryByText(/No receipts match this view/)).toBeNull();
  });

  it("keeps empty observed data distinct from proof of delivered events", async () => {
    setup({
      "/api/v1/notifications/delivery-summary": { ...summary, total: 0, pending: 0, counts: {}, time_eligible: 0, expired_claims: 0 },
      "/api/v1/notifications/deliveries": page([]),
    });
    render(<NotificationReceipts />);
    expect(await screen.findByText("Pending receipts: 0")).toBeTruthy();
    expect(await screen.findByTitle(/No receipts match this view. This is not proof all events were delivered/)).toBeTruthy();
  });

  it("refreshes both reads without issuing a write or retaining the older-page cursor", async () => {
    const fetch = setup();
    render(<NotificationReceipts />);
    await screen.findByText("receipt-new");
    fireEvent.click(screen.getByRole("button", { name: "Refresh receipt view" }));
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).includes("delivery-summary")).length).toBe(2));
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).includes("/deliveries?")).length).toBe(2));
    expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === "GET")).toBe(true);
  });
});
