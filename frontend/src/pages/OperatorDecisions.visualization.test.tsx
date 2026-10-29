/* Operator decisions — the drawing contract.
 *
 * The inbox is a page of a register, so the screen must show counts per section,
 * a duration bar scaled to its own page, a register composition for coverage,
 * and a hatched "not measured" rail where the read supplies no denominator.
 */
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import OperatorDecisions from "./OperatorDecisions";

const rt = { replayIssue: null as string | null };
vi.mock("../lib/realtime", () => ({ useRealtime: () => rt }));
const draw = () => render(<MemoryRouter><OperatorDecisions /></MemoryRouter>);

const inbox = (overrides: Record<string, unknown> = {}) => ({
  estate_id: "estate-a",
  as_of: "2026-10-24T09:15:00Z",
  page_is_whole_estate: false,
  uncertainty: "Registered scope only",
  sections: {
    tasks: { items: [{ id: "task-1", status: "OPEN", owner: "payments", priority: "HIGH", needs_attention: true, current_condition_verified: false, next_action: "Independent rescan required" }], has_more: true, next_offset: 25 },
    jobs: { items: [{ id: "job-1", status: "FAILED", queue_wait_seconds: 42, execution_seconds: 3, stage: "collect" }, { id: "job-2", status: "QUEUED", queue_wait_seconds: 7 }], has_more: false, next_offset: null },
    coverage: {
      items: [{ register_id: "reg-1", registered_targets: 12, register_completeness: "PARTIAL", counts: { OBSERVED: 6, STALE: 2, BLOCKED: 1, UNSUPPORTED: 1, NOT_ATTEMPTED: 2 } }],
      has_more: false, next_offset: null,
    },
    ...overrides,
  },
});
afterEach(() => { localStorage.clear(); rt.replayIssue = null; });

describe("Operator decisions visualization", () => {
  it("draws one cell per section with the count from this page", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": inbox() });
    draw();
    expect(await screen.findByText("tasks")).toBeInTheDocument();
    expect(screen.getByText("next page at 25")).toBeInTheDocument(); // has_more is drawn, not claimed
    expect(screen.getAllByText("page complete").length).toBeGreaterThan(0);
    // page scope is stated as a measurement, not a footnote
    expect(screen.getByText("ONE PAGE")).toBeInTheDocument();
    expect(screen.getByText("whole-estate completeness")).toBeInTheDocument();
    expect(screen.getByText("not measured")).toBeInTheDocument();
  });

  it("scales a job duration against the longest duration in the same page", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": inbox() });
    draw();
    fireEvent.click(await screen.findByText("Failed, unsettled & waiting jobs"));
    expect(await screen.findByText("42s")).toBeInTheDocument();
    expect(screen.getByText("3.0s")).toBeInTheDocument();
    expect(screen.getAllByText(/scaled to the longest wait in this page/)).toHaveLength(2);
    expect(screen.getByText("collect")).toBeInTheDocument();
  });

  it("draws coverage as the register's own counts, never as a percentage of a target", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": inbox() });
    draw();
    expect(await screen.findByText("reg-1")).toBeInTheDocument();
    expect(screen.getByText("not attempted")).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("keeps a task's declaration and its unverified condition visibly apart", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": inbox() });
    draw();
    expect(await screen.findByText("payments")).toBeInTheDocument();
    expect(screen.getByText(/Needs attention/)).toBeInTheDocument();
    expect(screen.getByText("NOT VERIFIED / stale or unavailable")).toBeInTheDocument();
    expect(screen.getByText("Next decision: Independent rescan required")).toBeInTheDocument();
  });

  it("draws an unmeasured coverage register as unknown, not as zero risk", async () => {
    mockFetch({ "/api/v1/assurance/operator-decisions": inbox({ coverage: { items: [], has_more: false, next_offset: null } }) });
    draw();
    expect(await screen.findByText(/no current register in this page/)).toBeInTheDocument();
    expect(screen.queryByText("observed")).not.toBeInTheDocument();
  });
});
