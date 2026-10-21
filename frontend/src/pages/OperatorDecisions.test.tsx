import React from "react";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render } from "@testing-library/react";
import { mockFetch } from "../test/setup";
import OperatorDecisions from "./OperatorDecisions";

const rt = { replayIssue: null as string | null };
vi.mock("../lib/realtime", () => ({ useRealtime: () => rt }));
const body = (owner = "payments") => ({ estate_id: "a", as_of: "2026-10-21T12:00:00Z", uncertainty: "Partial register, not bank completeness", sections: {
  tasks: { items: [{ id: "task-1", status: "COMPLETED", owner, reported_complete: true, next_action: "Independent rescan required", evidence_freshness: "UNKNOWN" }], has_more: false, next_offset: null },
  coverage: { items: [], has_more: false, next_offset: null },
} });
const draw = () => render(<MemoryRouter><OperatorDecisions /></MemoryRouter>);
afterEach(() => { localStorage.clear(); rt.replayIssue = null; vi.useRealTimers(); });

describe("Operator decisions", () => {
  it("distinguishes reported action, unknown coverage and verification decisions", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": body() }); draw();
    expect(await screen.findByText("payments")).toBeInTheDocument();
    expect(screen.getByText(/Next decision: Independent rescan required/)).toBeInTheDocument();
    expect(screen.getByText(/Every section is paginated/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Coverage & freshness — independent registered denominators"));
    expect(screen.getByText(/does not prove no risk/)).toBeInTheDocument();
  });
  it("drops old estate results and fields when selection changes", async () => {
    let resolveOld: (value: unknown) => void = () => {};
    let calls = 0;
    mockFetch({ "/api/v1/assurance/operator-decisions": () => ++calls === 1 ? new Promise(resolve => { resolveOld = resolve; }) : body("new-estate-owner") });
    draw(); await waitFor(() => expect(calls).toBe(1));
    await act(async () => { window.dispatchEvent(new Event("zelinx:tenant")); });
    expect(await screen.findByText("new-estate-owner")).toBeInTheDocument();
    await act(async () => resolveOld(body("old-estate-owner")));
    expect(screen.queryByText("old-estate-owner")).not.toBeInTheDocument();
  });
  it("does not substitute cached success on polling errors", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": body() }); draw();
    await screen.findByText("payments");
    mockFetch({}, 503); fireEvent.click(screen.getByText("Reconcile now"));
    expect(await screen.findByRole("alert")).toHaveTextContent("503");
    expect(screen.queryByText("payments")).not.toBeInTheDocument();
  });
  it("shows replay reset until a fresh SQL read is acknowledged", async () => {
    rt.replayIssue = "retention gap";
    mockFetch({ "/api/v1/assurance/operator-decisions": body() }); draw();
    expect(await screen.findByText("payments")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("retention gap");
    fireEvent.click(screen.getByText("Acknowledge fresh SQL reconciliation"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("bounds a long polling session without growing history or overlapping reads", async () => {
    vi.useFakeTimers();
    const fetch = mockFetch({ "/api/v1/assurance/operator-decisions": body() });
    const view = draw();
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    // 24 simulated hours exercises lifecycle scheduling, NOT browser endurance.
    for (let i = 0; i < 2880; i++) await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
    expect(screen.getAllByText("payments")).toHaveLength(1);
    expect(fetch.mock.calls.length).toBeLessThanOrEqual(2882);
    view.unmount();
    const calls = fetch.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
    expect(fetch.mock.calls.length).toBe(calls);
  }, 30000);
});
