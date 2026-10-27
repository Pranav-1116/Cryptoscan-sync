import React from "react";
import { expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import OperationalImpactPanel from "./OperationalImpactPanel";
import { OperationalImpact, TraversalEdgeEvidence } from "../lib/api";

function projection(): OperationalImpact {
  return { schema: "cryptoscan.operational-impact/1", as_of: "2026-10-18", analysis_kind: "conditional_dependency_review", provider_disruption_assumed: false,
    mode_counts: { UNKNOWN: 1, HARD: 0, OPTIONAL: 0, FAILOVER: 1, ASYNC_BUFFERED: 1 }, edge_count: 3, edge_limit: 500, edges_truncated: false,
    non_current_edge_count: 2, scope: "Loaded review edges only", note: "Not a system failure simulation", edges: [{
      from: "payments", to: "hsm", relation: "CALLS", record_id: "e", consumer_scope: "dependent_consumers", provider_scope: "direct_exposure",
      relationship_evidence: { evidence_references: ["change/8"] } as TraversalEdgeEvidence,
      condition: { schema: "cryptoscan.operational-dependency/1", mode: "FAILOVER", assertion_status: "DECLARED", assertion: { mode: "FAILOVER", failover_system_ids: ["standby"], assumptions: ["Independent routing"] },
        conditional_outcome: "Continuity depends on verified routing and capacity", gaps: ["Alternative health unverified"],
        failover_references: { resolution: "loaded_registry_only", loaded_system_ids: ["standby"], not_in_loaded_registry: [], invalid_self_or_provider_ids: [] },
        verified: false, failure_probability: null, safe_delay_seconds: null, note: "Unverified declaration" },
    }] };
}

it("does not silently classify old answers as hard dependency or safe operation", () => {
  render(<OperationalImpactPanel />);
  expect(screen.getByText(/Missing metadata is unknown/)).toBeInTheDocument();
  expect(screen.queryByText(/HARD: 0/)).not.toBeInTheDocument();
});

it("shows declared failover identities without claiming healthy alternatives or shrinking exposure", () => {
  render(<OperationalImpactPanel impact={projection()} />);
  expect(screen.getByText(/failover and buffered edges remain in exposure/)).toBeInTheDocument();
  expect(screen.getByText(/Declared alternatives: standby/)).toBeInTheDocument();
  expect(screen.getByText(/identity is not health or successful switchover/)).toBeInTheDocument();
  expect(screen.getByText(/Alternative health unverified/)).toBeInTheDocument();
  expect(screen.getByText(/Source completeness unknown/)).toBeInTheDocument();
});

it("keeps zero declared queue capacity distinct from missing and refuses a buffering guarantee", () => {
  const result = projection();
  const condition = result.edges[0].condition;
  condition.mode = "ASYNC_BUFFERED";
  condition.assertion = { mode: "ASYNC_BUFFERED", buffer_capacity_messages: 0, buffer_retention_seconds: 60 };
  render(<OperationalImpactPanel impact={result} />);
  expect(screen.getByText(/Declared capacity: 0 messages/)).toBeInTheDocument();
  expect(screen.getByText(/No safe buffering duration or time-to-impact/)).toBeInTheDocument();
});

it("reports bounded details without deriving counts from the displayed subset", () => {
  const result = projection();
  result.edges_truncated = true; result.edge_count = 700;
  render(<OperationalImpactPanel impact={result} />);
  expect(screen.getByText(/showing 1 of 700 loaded records/)).toBeInTheDocument();
  expect(screen.getByText(/Counts are not calculated from this preview/)).toBeInTheDocument();
});
