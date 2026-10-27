import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import TraversalEvidencePanel from "./TraversalEvidencePanel";
import { CascadeTraversalEvidence, TraversalEvidenceEnvelope, TraversalPathEvidence } from "../lib/api";

const empty: TraversalEvidenceEnvelope = { schema: "cryptoscan.traversal-evidence/1", as_of: "2026-10-18", paths: [], requested_count: 0, returned_count: 0,
  limit: 500, missing_witness_count: 0, missing_system_ids: [], missing_system_ids_truncated: false, truncated: false, complete_for_requested_systems: true, all_paths: false, note: "" };
const path: TraversalPathEvidence & { system_id: string } = { schema: empty.schema, system_id: "mobile", available: true,
  nodes: ["pay", "mobile"], hops: 1, direction: "upstream", scope: "current", provenance_classes: ["DECLARED", "OBSERVED"], mixed_provenance: true,
  evidence_gap_count: 1, unbounded_edge_count: 1, note: "", edges: [{ from: "mobile", to: "pay", relation: "CALLS", provenance: "DECLARED", source: "change manifest",
    record_id: "edge-1", evidence_references: ["change:42"], evidence_missing: false, references_truncated: true, references_verified_by_traversal: false,
    confidence: .7, confidence_meaning: "operator rating, not failure probability", freshness: { as_of: "2026-10-18", eligibility: "ACTIVE", validity: "UNBOUNDED",
      observation: { value: null, status: "MISSING", age_seconds: null }, confirmation: { value: "2026-10-17", status: "DATED", age_seconds: 86400 },
      verification_timestamp: { value: null, status: "MISSING", age_seconds: null }, note: "Declaration, not observed runtime use." } }] };
const answer: CascadeTraversalEvidence = { schema: empty.schema, direct: [], direct_count: 0, direct_truncated: false, potential_direct: [], potential_direct_count: 0, potential_direct_truncated: false,
  dependent_consumers: { ...empty, requested_count: 501, returned_count: 1, paths: [path], missing_witness_count: 499, missing_system_ids: ["legacy"], truncated: true, complete_for_requested_systems: false }, supporting_context: empty, potential: empty, note: "" };

it("does not reconstruct old stored evidence from the current graph", () => {
  render(<TraversalEvidencePanel />);
  expect(screen.getByText(/Traversal evidence unavailable for this stored answer/)).toBeInTheDocument();
  expect(screen.getByText(/No aggregate confidence or failure probability/)).toBeInTheDocument();
});

it("shows bounded missing witnesses and preserves physical arrows and timestamp meanings", () => {
  render(<TraversalEvidencePanel evidence={answer} />);
  fireEvent.click(screen.getByText(/Dependent-consumer paths:/));
  expect(screen.getByText(/Incomplete witness coverage/)).toHaveTextContent("Exposure counts unchanged");
  expect(screen.getByText(/Missing witnesses: legacy/)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/pay → mobile · current/));
  expect(screen.getByText(/mobile → pay · CALLS · DECLARED/)).toBeInTheDocument();
  expect(screen.getByText(/mixed provenance/)).toBeInTheDocument();
  expect(screen.getByText(/No expiry deadline — not verified freshness/)).toBeInTheDocument();
  expect(screen.getByText(/Observation: MISSING/)).toBeInTheDocument();
  expect(screen.getByText(/Confirmation: DATED/)).toBeInTheDocument();
  expect(screen.getByText("change:42")).toBeInTheDocument();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
  expect(screen.getByText("Reference list truncated.")).toBeInTheDocument();
});

it("labels legacy direct context unverified without inventing an edge", () => {
  render(<TraversalEvidencePanel evidence={{ ...answer, direct: [{ system_id: "pay", kind: "algorithm", basis: "legacy compact linkage", records: [], record_count: 0, record_listing_truncated: false, complete_chain_verified: false }], direct_count: 1 }} />);
  fireEvent.click(screen.getByText(/Direct seed context:/));
  expect(screen.getByText(/Seed chain not verified/)).toBeInTheDocument();
});
