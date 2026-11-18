import React from "react";
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AnalysisCoveragePanel from "./AnalysisCoveragePanel";
import type { AnalysisCoverage } from "../lib/api";
import { withTitles } from "../test/withTitles";

function report(): AnalysisCoverage {
  return { schema: "cryptoscan.analysis-coverage/1", status: "BOUNDED_REVIEW", analysis_performed: true,
    source_metadata_available: true, known_input_truncation: false, known_horizon_omission: false,
    explanation_truncation: false, horizon_extension_unknown: false, estate_completeness: "UNKNOWN",
    collections: {}, traversals: [], missing_links: [], explanations: [], note: "Loaded modeled evidence only; not a safety claim." };
}

describe("prominent coverage qualifications", () => {
  it("does not reconstruct old stored coverage", () => {
    render(<AnalysisCoveragePanel />);
    expect(screen.getByText("Coverage unavailable for this stored answer")).toBeInTheDocument();
    expect(withTitles(screen.getByText(/today's graph/))).toContain("not zero exposure");
  });
  it("separates source omission and lower bounds from exact totals", () => {
    const c = report();
    c.status = "GAPS_REPORTED"; c.known_input_truncation = true;
    c.collections.dependencies = { returned: 5, limit: 5, truncated: true, unit: "rows", known_total: null, observed_lower_bound: 6 };
    render(<AnalysisCoveragePanel coverage={c} />);
    expect(screen.getByText(/Source input truncated/)).toBeInTheDocument();
    expect(screen.getByText(/Observed lower bound: 6; exact total unknown/)).toBeInTheDocument();
    expect(screen.queryByText(/100%/)).not.toBeInTheDocument();
  });
  it("keeps native horizon unknown rather than showing zero additional systems", () => {
    const c = report(); c.horizon_extension_unknown = true; c.source_metadata_available = false;
    c.traversals = [{ scope: "current", unit: "systems", direction: "upstream", max_depth: 2,
      extension_check: "NOT_EVALUATED", more_loaded_systems: null, unvisited_neighbour_count: null, note: "No horizon probe." }];
    render(<AnalysisCoveragePanel coverage={c} />);
    expect(screen.getByText(/Unknown is not zero additional systems/)).toBeInTheDocument();
    expect(screen.queryByText(/unvisited next-hop neighbours: 0/)).not.toBeInTheDocument();
  });
  it("distinguishes explanation-only limits and individual missing-link denominators", () => {
    const c = report(); c.explanation_truncation = true;
    c.explanations = [{ name: "process_details", requested: 600, returned: 500, limit: 500, truncated: true, scope: "compact counts independent" }];
    c.missing_links = [{ name: "systems_without_process_support", count: 2, denominator: 8, scope: "loaded review", status: "GAP_REPORTED" }];
    render(<AnalysisCoveragePanel coverage={c} />);
    const panel = within(screen.getByRole("region", { name: "Coverage and limitations" }));
    expect(panel.getByTitle(/compact membership counts are independent/)).toBeInTheDocument();
    expect(panel.getByText(/systems without process support: 2 of 8/)).toBeInTheDocument();
    expect(panel.queryByText(/Source input truncated/)).not.toBeInTheDocument();
    expect(panel.getByText(/not additive/)).toBeInTheDocument();
  });
  it("remains visible when no impact analysis was performed", () => {
    const c = report(); c.analysis_performed = false;
    render(<AnalysisCoveragePanel coverage={c} />);
    expect(screen.getByText(/No traversal performed for this unresolved selection/)).toBeInTheDocument();
    expect(screen.getByText(/Estate completeness: unknown/)).toBeInTheDocument();
  });
});
