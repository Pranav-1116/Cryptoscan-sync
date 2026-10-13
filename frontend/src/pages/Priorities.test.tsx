import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Priorities from "./Priorities";

/* §4.7 — the ranked queue is actionable: a drift item opens owned remediation
   task(s) that point at evidence records; a runtime item is refused honestly
   by the API and the refusal text is shown verbatim. */

const item = (overrides: Record<string, unknown> = {}) => ({
  rank: 1, ref_id: "drift-1", source: "drift", kind: "ALGORITHM_WEAKENED",
  severity_in: "HIGH", priority: 62.5, effort: 12.0,
  explanation: "3DES reintroduced in payments-core", replacement: null, plan: null,
  correlated: [], ...overrides,
});

const priorityResponse = (ranked: unknown[]) => ({
  ranked,
  counts_by_severity: ranked.length ? { HIGH: 1 } : {},
  coverage: {
    open_drift_events: 0, runtime_findings: 0, systems_with_agility: 0,
    systems_with_revenue_mapping: 0, graph_edges: 0, processes_linked: 0, profile: "default",
  },
});

describe("priority item → owned remediation task (§4.7)", () => {
  it("opens tasks for a drift item and reports what was created", async () => {
    mockFetch({
      "/api/v1/priority": priorityResponse([item()]),
      "/api/v1/priority/drift-1/tasks": {
        ref_id: "drift-1", source: "drift", owner: "crypto-team", created: 2,
        task_ids: ["task-1", "task-2"],
        message: "2 remediation task(s) opened from drift event drift-1 (status PROPOSED, source=drift).",
      },
    });
    renderWithProviders(<Priorities />);
    fireEvent.click(await screen.findByText(/3DES reintroduced in payments-core/));
    const input = await screen.findByPlaceholderText("owner (optional)");
    fireEvent.change(input, { target: { value: "crypto-team" } });
    fireEvent.click(screen.getByText("Open remediation task(s)"));
    expect(await screen.findByText("2 task(s)")).toBeInTheDocument();
    expect(screen.getByText(/2 remediation task\(s\) opened from drift event drift-1/)).toBeInTheDocument();
    expect(screen.getByText(/task-1, task-2/)).toBeInTheDocument();
  });

  it("shows the honest no-op when the drift has no failing evidence", async () => {
    mockFetch({
      "/api/v1/priority": priorityResponse([item()]),
      "/api/v1/priority/drift-1/tasks": {
        ref_id: "drift-1", source: "drift", owner: null, created: 0, task_ids: [],
        message: "No task opened: drift event drift-1 has no FAIL/WARN evidence records in its current scan to remediate.",
      },
    });
    renderWithProviders(<Priorities />);
    fireEvent.click(await screen.findByText(/3DES reintroduced in payments-core/));
    fireEvent.click(await screen.findByText("Open remediation task(s)"));
    expect(await screen.findByText("0 task(s)")).toBeInTheDocument();
    expect(screen.getByText(/No task opened/)).toBeInTheDocument();
  });

  it("shows the API's 422 refusal verbatim for runtime items — never papers over it", async () => {
    mockFetch({
      "/api/v1/priority": priorityResponse([item({ ref_id: "rf-1", source: "runtime", kind: "runtime_finding" })]),
      "/api/v1/priority/rf-1/tasks": new Response(JSON.stringify({
        detail: "Runtime findings cannot open remediation tasks: a task requires an evidence_id from the hash chain for later verification, and runtime findings are observations without one. Re-scan the host to produce chain-verified evidence, then create the task from the finding.",
      }), { status: 422 }),
    });
    renderWithProviders(<Priorities />);
    fireEvent.click(await screen.findByText(/3DES reintroduced in payments-core/));
    // runtime rows warn before the click
    expect(screen.getByText(/runtime findings have no evidence record/)).toBeInTheDocument();
    fireEvent.click(await screen.findByText("Open remediation task(s)"));
    expect(await screen.findByText(/Refused \(honest\):/)).toBeInTheDocument();
    expect(screen.getByText(/a task requires an evidence_id from the hash chain/)).toBeInTheDocument();
    expect(screen.getByText(/Re-scan the host to produce chain-verified evidence/)).toBeInTheDocument();
  });

  it("flags rows without a backing record id instead of offering a dead button", async () => {
    mockFetch({ "/api/v1/priority": priorityResponse([item({ ref_id: null })]) });
    renderWithProviders(<Priorities />);
    fireEvent.click(await screen.findByText(/3DES reintroduced in payments-core/));
    expect(await screen.findByText(/No backing record id — cannot open a task/)).toBeInTheDocument();
    expect(screen.queryByText("Open remediation task(s)")).toBeNull();
  });
});
