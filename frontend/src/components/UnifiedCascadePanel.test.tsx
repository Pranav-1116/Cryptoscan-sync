import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import UnifiedCascadePanel from "./UnifiedCascadePanel";
import { apiCascadeRunDiff, apiCascadeRuns, apiUnifiedCascade, UnifiedCascadeResult } from "../lib/api";

vi.mock("../lib/api", () => ({
  apiCascadeRunDiff: vi.fn(), apiCascadeRuns: vi.fn(), apiUnifiedCascade: vi.fn(),
}));

function answer(): UnifiedCascadeResult {
  return {
    schema: "cryptoscan.unified-cascade/1", verdict: "AFFECTED", run_id: "run-1",
    target: { input: "payments", kind: "system" }, as_of: "2026-10-18T00:00:00Z",
    layers: {}, honest_unknowns: ["Registered links only"],
    impact: {
      affected_systems: ["ledger", "mobile", "payments"], affected_system_count: 3,
      system_classification: {
        schema: "cryptoscan.cascade-system-scope/1",
        direct_exposure: { systems: ["payments"], count: 1 },
        dependent_consumers: { systems: ["mobile"], count: 1 },
        supporting_context: { systems: ["ledger"], count: 1 },
        exposure_systems: ["mobile", "payments"], exposure_system_count: 2,
        review_systems: ["ledger", "mobile", "payments"], review_system_count: 3,
      },
    },
  };
}

async function runCascade() {
  fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "payments" } });
  fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
  await screen.findByText("Modeled exposure: 2");
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { runs: [], count: 0 } });
  vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: answer() });
});

describe("cascade disjoint system classification", () => {
  it("renders direct, consumer and context lists separately and labels both totals", async () => {
    render(<UnifiedCascadePanel />);
    await runCascade();
    const direct = within(screen.getByRole("region", { name: "Direct exposure" }));
    const consumers = within(screen.getByRole("region", { name: "Dependent consumers" }));
    const context = within(screen.getByRole("region", { name: "Supporting context" }));
    expect(direct.getByText("payments")).toBeInTheDocument();
    expect(consumers.getByText("mobile")).toBeInTheDocument();
    expect(consumers.queryByText("ledger")).not.toBeInTheDocument();
    expect(context.getByText("ledger")).toBeInTheDocument();
    expect(screen.getByText("Review scope: 3")).toBeInTheDocument();
    expect(screen.queryByText("Affected systems")).not.toBeInTheDocument();
    expect(screen.getByText(/not confirmed failures\. Zero linked systems/)).toBeInTheDocument();
  });

  it("does not invent a classification for an older answer", async () => {
    const legacy = answer();
    delete legacy.impact.system_classification;
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: legacy });
    render(<UnifiedCascadePanel />);
    fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "payments" } });
    fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
    expect(await screen.findByText("Legacy review scope: 3")).toBeInTheDocument();
    expect(screen.getByText(/Classification unavailable for this answer/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Direct exposure" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Modeled exposure:/)).not.toBeInTheDocument();
  });

  it("keeps inventory-only zero counts explicitly unknown rather than safe", async () => {
    const inventory = answer();
    inventory.layers = { hardware: { inventory_only: true } };
    inventory.impact.affected_systems = [];
    inventory.impact.affected_system_count = 0;
    inventory.impact.system_classification = {
      schema: "cryptoscan.cascade-system-scope/1",
      direct_exposure: { systems: [], count: 0 }, dependent_consumers: { systems: [], count: 0 },
      supporting_context: { systems: [], count: 0 }, exposure_systems: [], exposure_system_count: 0,
      review_systems: [], review_system_count: 0,
    };
    vi.mocked(apiUnifiedCascade).mockResolvedValue({ source: "live", data: inventory });
    render(<UnifiedCascadePanel />);
    fireEvent.change(screen.getByRole("textbox", { name: "cascade target" }), { target: { value: "hsm" } });
    fireEvent.click(screen.getByRole("button", { name: "Run cascade" }));
    expect(await screen.findByText("Modeled exposure: 0")).toBeInTheDocument();
    expect(screen.getByText(/Hardware linkage is inventory-only/)).toBeInTheDocument();
    expect(screen.getByText("AFFECTED")).toBeInTheDocument();
  });

  it("labels legacy history and unavailable mixed-version comparisons honestly", async () => {
    vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { count: 1, runs: [{
      id: "old", target: "payments", target_kind: "system", max_depth: 6, verdict: "AFFECTED",
      affected_system_count: 3, created_by: "auditor", created_at: null,
    }] } });
    vi.mocked(apiCascadeRunDiff).mockResolvedValue({ source: "live", data: {
      target: "payments", verdict_changed: false,
      run: { id: "old", created_at: null, verdict: "AFFECTED" },
      against: { id: "older", created_at: null, verdict: "AFFECTED" },
      affected_systems: { before: 3, after: 3, added: [], removed: [], unchanged_count: 3 },
      affected_processes: { before: 0, after: 0, added: [], removed: [] },
      system_classification: { available: false },
    } });
    render(<UnifiedCascadePanel />);
    expect(await screen.findByText(/legacy review scope: 3 · breakdown unavailable/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "diff vs previous" }));
    expect(await screen.findByText("Classification comparison unavailable for these stored runs.")).toBeInTheDocument();
  });
  it("shows per-category moves even when the review total stays unchanged", async () => {
    vi.mocked(apiCascadeRuns).mockResolvedValue({ source: "live", data: { count: 1, runs: [{
      id: "new", target: "payments", target_kind: "system", max_depth: 6, verdict: "AFFECTED",
      affected_system_count: 3, created_by: "auditor", created_at: null,
      system_classification: answer().impact.system_classification,
    }] } });
    const unchanged = { before: 1, after: 1, added: [], removed: [], unchanged_count: 1 };
    vi.mocked(apiCascadeRunDiff).mockResolvedValue({ source: "live", data: {
      target: "payments", verdict_changed: false,
      run: { id: "new", created_at: null, verdict: "AFFECTED" },
      against: { id: "old", created_at: null, verdict: "AFFECTED" },
      affected_systems: { before: 3, after: 3, added: [], removed: [], unchanged_count: 3 },
      affected_processes: { before: 0, after: 0, added: [], removed: [] },
      system_classification: { available: true, direct_exposure: unchanged,
        dependent_consumers: { before: 1, after: 2, added: ["ledger"], removed: [], unchanged_count: 1 },
        supporting_context: { before: 1, after: 0, added: [], removed: ["ledger"], unchanged_count: 0 } },
    } });
    render(<UnifiedCascadePanel />);
    expect(await screen.findByText(/1 direct \/ 1 consumers \/ 1 context · 3 review/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "diff vs previous" }));
    expect(await screen.findByText(/Dependent consumers: 1 → 2 · added: ledger/)).toBeInTheDocument();
    expect(screen.getByText(/Supporting context: 1 → 0 · removed: ledger/)).toBeInTheDocument();
  });

});
