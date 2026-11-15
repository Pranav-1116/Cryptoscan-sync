import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import FindingsTable from "./FindingsTable";
import RiskDimensionsPanel from "./RiskDimensionsPanel";
import PqcClaimsLadder from "./PqcClaimsLadder";
import CoverageIntelligencePanel from "./CoverageIntelligencePanel";
import SimulationPanel from "./SimulationPanel";
import type {
  CoverageIntelligence,
  PqcSubject,
  RiskDimension,
  SimulationResult,
  ThreatFinding,
} from "./types";

const finding: ThreatFinding = {
  class: "CRYPTO_REGRESSION",
  asset: "payments-api",
  what_changed: "the observed algorithm dropped from AES-256 to AES-128",
  why_it_matters: "weaker traffic protection",
  evidence_ids: ["E1"],
  not_proven: "this does not prove an attack",
  investigate: "who changed the configuration",
  compromise_declared: false,
};

describe("FindingsTable", () => {
  it("shows all six mandated answers and links evidence", async () => {
    const onEvidence = vi.fn();
    render(<FindingsTable findings={[finding]} onEvidence={onEvidence} />);
    expect(screen.getByText("what is NOT proven")).toBeInTheDocument();
    expect(screen.getByText("this does not prove an attack")).toBeInTheDocument();
    await userEvent.click(screen.getByText("E1"));
    expect(onEvidence).toHaveBeenCalledWith("E1");
  });

  it("filters by search and says an empty result is not a clean estate", async () => {
    render(<FindingsTable findings={[finding]} />);
    await userEvent.type(screen.getByLabelText("Search findings"), "no-such-thing");
    expect(
      screen.getByText(/an empty result, not a\s+clean estate/),
    ).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("Search findings"));
    expect(screen.getByText(/1 of 1 shown/)).toBeInTheDocument();
  });
});

const unknownDimension: RiskDimension = {
  dimension: "QUANTUM_URGENCY",
  score: null,
  band: "UNKNOWN",
  sense: "risk",
  factors: [],
  evidence_ids: [],
  reason: "urgency cannot be dated without an explicit threat horizon",
  known: false,
};

const scoredDimension: RiskDimension = {
  dimension: "CRYPTO_RISK",
  score: 90,
  band: "CRITICAL",
  sense: "risk",
  factors: [{ rule: "CR-1", input: "registry status DISALLOWED", contribution: 50, evidence_ids: ["E1"] }],
  evidence_ids: ["E1"],
  reason: null,
  known: true,
};

describe("RiskDimensionsPanel", () => {
  it("draws an unknown dimension as unknown, never zero", () => {
    render(<RiskDimensionsPanel dimensions={[unknownDimension]} />);
    expect(screen.getByText("UNKNOWN — not zero")).toBeInTheDocument();
    expect(screen.getByText(/unknown, not zero/)).toBeInTheDocument();
  });

  it("expands factors with rule ids and contributions", async () => {
    render(<RiskDimensionsPanel dimensions={[scoredDimension]} />);
    await userEvent.click(screen.getByText("1 factor(s)"));
    const factors = screen.getByLabelText("CRYPTO_RISK factors");
    expect(within(factors).getByText("CR-1")).toBeInTheDocument();
    expect(within(factors).getByText("+50")).toBeInTheDocument();
  });

  it("marks the confidence dimension as higher-is-better", () => {
    const confidence: RiskDimension = {
      ...unknownDimension,
      dimension: "EVIDENCE_CONFIDENCE",
      sense: "confidence",
    };
    render(<RiskDimensionsPanel dimensions={[confidence]} />);
    expect(screen.getByText("higher is better")).toBeInTheDocument();
  });
});

const subject: PqcSubject = {
  subject: "payments-api",
  stages: {
    SUPPORT_AVAILABLE: { state: "CLAIMED" },
    CONFIGURED: { state: "NOT_CLAIMED", reason: "never 'fine'" },
    RUNTIME_OBSERVED: { state: "NOT_CLAIMED" },
    NETWORK_NEGOTIATED: { state: "NOT_CLAIMED" },
    MIGRATION_VALIDATED: { state: "NOT_CLAIMED" },
  },
  readiness: "SUPPORT_ONLY",
  readiness_reason: "a library supporting ML-KEM is not PQC readiness",
  contradictions: [],
};

describe("PqcClaimsLadder", () => {
  it("says support is not readiness and shows the five stages apart", () => {
    render(<PqcClaimsLadder subjects={[subject]} />);
    expect(
      screen.getByText(/A library supporting ML-KEM is not PQC readiness/),
    ).toBeInTheDocument();
    expect(screen.getByText("SUPPORT AVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("MIGRATION VALIDATED")).toBeInTheDocument();
    expect(screen.getByText("SUPPORT_ONLY")).toBeInTheDocument();
  });

  it("an empty ladder is unknown, neither ready nor fine", () => {
    render(<PqcClaimsLadder subjects={[]} />);
    expect(screen.getByText(/neither\s+ready nor fine/)).toBeInTheDocument();
  });
});

const coverage: CoverageIntelligence = {
  verdict: "COVERAGE_INCOMPLETE",
  reason: "collection has gaps",
  authorized_targets: 10,
  discovered_assets: 7,
  unknown_assets: 1,
  stale_evidence: 2,
  access_denied_targets: 1,
  unverified_relationships: 3,
  gaps: [
    {
      kind: "UNKNOWN_ASSET",
      count: 1,
      detail: "a missing asset must never silently become a clean security result",
      is_clean_result: false,
    },
  ],
  coverage_percent: null,
  percent_note: "the denominator includes planes that were never read",
};

describe("CoverageIntelligencePanel", () => {
  it("a missing asset is never silently clean", () => {
    render(<CoverageIntelligencePanel coverage={coverage} />);
    expect(
      screen.getByText(/A missing asset must never silently become a clean security result/),
    ).toBeInTheDocument();
    expect(screen.getByText("never")).toBeInTheDocument();
  });

  it("a refused percentage is drawn as refused, not estimated", () => {
    render(<CoverageIntelligencePanel coverage={coverage} />);
    expect(screen.getByText(/REFUSED —/)).toBeInTheDocument();
  });
});

const simulation: SimulationResult = {
  scenario: "CA_COMPROMISE",
  description: "a certificate authority is compromised",
  hypothetical: true,
  snapshot: { snapshot_id: "SNAP-1", version: 12, captured_at: "2026-11-07" },
  proven_dependencies: [
    {
      asset: "load-balancer",
      chain: [
        {
          from: "load-balancer",
          predicate: "uses",
          to: "tls-cert",
          provenance: "PROVEN",
          evidence_ids: ["E2"],
        },
      ],
    },
  ],
  assumed_dependencies: [
    {
      asset: "reporting-svc",
      chain: [
        {
          from: "reporting-svc",
          predicate: "uses",
          to: "tls-cert",
          provenance: "UNKNOWN",
          evidence_ids: [],
        },
      ],
      why_assumed: "UNKNOWN",
    },
  ],
  approvals_required: ["certificate authority / PKI owner approval"],
  rollback_plan: ["re-pin the previous trust path from the snapshot"],
};

describe("SimulationPanel", () => {
  it("labels the run hypothetical and never a real change", () => {
    render(<SimulationPanel result={simulation} />);
    expect(screen.getByText(/HYPOTHETICAL/)).toBeInTheDocument();
    expect(screen.getByText(/Never shown as a\s+real production change/)).toBeInTheDocument();
    expect(screen.getByText(/SNAP-1 v\s*12/)).toBeInTheDocument();
  });

  it("keeps proven and assumed dependencies apart", () => {
    render(<SimulationPanel result={simulation} />);
    expect(screen.getByText("proven dependencies")).toBeInTheDocument();
    expect(screen.getByText(/assumed dependencies \(not proven\)/)).toBeInTheDocument();
    expect(screen.getByText("reporting-svc")).toBeInTheDocument();
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });
});

describe("FindingsTable windowing (the virtual-scroll row)", () => {
  it("renders a window of a large report, not every row, and says so", () => {
    const many = Array.from({ length: 500 }, (_, i) => ({
      ...finding,
      asset: `asset-${i}`,
      evidence_ids: [`E${i}`],
    }));
    render(<FindingsTable findings={many} />);
    // first window only (200), never all 500 — a report's rows must not all
    // land in the DOM at once
    expect(document.querySelectorAll("tbody tr").length).toBe(200);
    expect(screen.getByRole("status")).toHaveTextContent(/Showing 200 of 500 findings/);
  });
});
