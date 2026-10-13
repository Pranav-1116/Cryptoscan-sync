import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Risk from "./Risk";

/* §4.6 — per-system risk must be explainable: levels, the signals they were
   derived from, the owners accountable, and the scan that is the evidence
   lineage. Unscanned systems say so; nothing is invented. */

const factor = (level: number, points: number, weight: number) => ({ level, points, weight });

const systemsResponse = {
  systems: [
    {
      score: 78.4, level: "HIGH", system_id: "sys-1", system_name: "payments-core",
      owner: "payments-team", technical_owner: "alice", security_owner: null,
      scan_id: "scan-abc123", evidence_count: 12, open_drift_events: 2, vulnerability_count: 1,
      levels: { technical: 3, crypto: 4, pqc: 2, exposure: 4, business_criticality: 4, dependency_impact: 1, evidence_confidence: 4, threat: 3 },
      signals: {
        evidence_rows: 12, fail_rows: 3, fail_ratio: 0.25, quantum_weighted_ratio: 0.167,
        unknown_algorithms: 1, open_drift_events: 2, worst_open_drift_severity: "HIGH",
        worst_cve_severity: "HIGH", outgoing_dependencies: 1, environment: "prod",
        criticality: "TIER-1", cloud_provider: "AWS",
      },
      factors: {
        technical: factor(3, 13.5, 0.18), crypto: factor(4, 16, 0.16), pqc: factor(2, 8, 0.16),
        exposure: factor(4, 12, 0.12), business_criticality: factor(4, 14, 0.14),
        dependency_impact: factor(1, 2.5, 0.1), evidence_confidence: factor(4, 6, 0.06),
        threat: factor(3, 6, 0.08),
      },
      weights: {}, weights_source: "default", calculation_version: "unified-risk-v1",
    },
    {
      score: 0, level: "LOW", system_id: "sys-2", system_name: "sandbox",
      owner: null, technical_owner: null, security_owner: null,
      scan_id: null, evidence_count: 0, open_drift_events: 0, vulnerability_count: 0,
      levels: {}, signals: null as unknown as Record<string, never>,
      factors: {}, weights: {}, weights_source: "default", calculation_version: "unified-risk-v1",
    },
  ],
  count: 2, total_systems: 2,
  estate: { score: 39.2, level: "LOW", by_level: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 1 } },
  weights: { technical: 0.18 }, weights_source: "default",
  calculation_version: "unified-risk-v1",
  factors: ["technical", "crypto", "pqc", "exposure", "business_criticality", "dependency_impact", "evidence_confidence", "threat"],
};

const ok = { "/api/v1/platform/risk": { score: 42.5, level: "MEDIUM" }, "/api/v1/stats/summary": { open_drift: {}, total_findings: 0 } };

describe("per-system risk explainability (§4.6)", () => {
  it("ranks systems with score, owner, evidence count, lineage and top driver", async () => {
    mockFetch({ ...ok, "/api/v1/risk/systems": systemsResponse });
    renderWithProviders(<Risk />);
    expect(await screen.findByText("payments-core")).toBeInTheDocument();
    expect(screen.getByText("78.4")).toBeInTheDocument();
    expect(screen.getByText("payments-team")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("Crypto strength (+16.0)")).toBeInTheDocument();
    // unscanned system is labeled, not assumed
    expect(screen.getByText("never scanned")).toBeInTheDocument();
  });

  it("opens a full decomposition: factor levels, weights, signals, owners, verify path", async () => {
    mockFetch({ ...ok, "/api/v1/risk/systems": systemsResponse });
    renderWithProviders(<Risk />);
    fireEvent.click(await screen.findByText("payments-core"));
    expect(await screen.findByText(/score decomposition/)).toBeInTheDocument();
    // the eight blueprint factors with level bars and live weights
    expect(screen.getByText("Technical (failing findings + drift)")).toBeInTheDocument();
    expect(screen.getByText("PQC exposure")).toBeInTheDocument();
    expect(screen.getByText("Dependency impact (blast radius)")).toBeInTheDocument();
    // raw derivation signals travel with the response
    expect(screen.getByText(/Shor=1.0 \/ Grover=0.5 weighted ratio → pqc factor/)).toBeInTheDocument();
    expect(screen.getByText("FAIL compliance rows")).toBeInTheDocument();
    // accountability, honest null for the unassigned security owner
    expect(screen.getByText(/security:/)).toBeInTheDocument();
    // evidence lineage + how to verify it
    expect(screen.getByText(/GET \/api\/v1\/scans\/scan-abc123\/verify/)).toBeInTheDocument();
  });

  it("shows the honest empty state when no systems are scored", async () => {
    mockFetch({
      ...ok,
      "/api/v1/risk/systems": {
        systems: [], count: 0, total_systems: 0,
        estate: { score: 0, level: "LOW", by_level: {} },
        weights: {}, weights_source: "default", calculation_version: "unified-risk-v1", factors: [],
      },
    });
    renderWithProviders(<Risk />);
    expect(await screen.findByText(/No systems scored yet/)).toBeInTheDocument();
    expect(screen.getByText(/factor levels derive from each system's persisted observations/)).toBeInTheDocument();
  });

  it("says the engine is unavailable rather than showing an invented table", async () => {
    mockFetch({
      ...ok,
      "/api/v1/risk/systems": new Response(JSON.stringify({ detail: "down" }), { status: 500 }),
    });
    renderWithProviders(<Risk />);
    expect(await screen.findByText(/Live risk engine unavailable/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("payments-core")).toBeNull());
  });
});
