import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import ProcessImpactPanel from "./ProcessImpactPanel";
import { ProcessImpact, TraversalEdgeEvidence } from "../lib/api";

const timestamp = { status: "MISSING", value: null, age_seconds: null };
const link: TraversalEdgeEvidence = { from: "mobile", to: "process:p", relation: "SUPPORTS", provenance: "DECLARED", source: "system_business_process mapping",
  record_id: "sp-1", evidence_references: ["change:42"], evidence_missing: false, references_truncated: false, references_verified_by_traversal: false,
  confidence_meaning: "not a failure probability", freshness: { as_of: "2026-10-18", eligibility: "ACTIVE", validity: "UNBOUNDED", observation: timestamp, confirmation: timestamp, verification_timestamp: timestamp, note: "" } };
const process: ProcessImpact["processes"][number] = { id: "p", name: "Payments", name_conflict: false, scopes: ["dependent_consumers"], exposed: true, context_only: false, potential_only: false,
  reason_count: 1, reasons_truncated: false, declared_business_context: { revenue_daily: 100, customer_count: 10 }, reasons: [{ system_id: "mobile", system_scope: "dependent_consumers", certainty: "current", role: "FRONTEND", support_link: link,
    system_explanation: { group: "dependent_consumers", system_id: "mobile", available: true, note: "not independently verified" } }] };
const result: ProcessImpact = { schema: "cryptoscan.business-process-impact/1", as_of: "2026-10-18", counts: { review: 2, exposure: 1, context_only: 1, potential_only: 1 },
  review_processes: [{ id: "p", name: "Payments" }, { id: "c", name: "Reconciliation" }], processes: [process,
    { ...process, id: "c", name: "Reconciliation", exposed: false, context_only: true, reasons: [] },
    { ...process, id: "u", name: "Potential", exposed: false, potential_only: true, reasons: [] }],
  coverage: { requested_system_count: 4, systems_without_recorded_links: ["missing"], systems_without_recorded_links_count: 1, missing_system_list_truncated: false,
    unresolved_or_invalid_link_count: 0, terminal_link_count: 0, returned_process_count: 3, total_process_count: 3, process_limit: 500, processes_truncated: false, reason_limit_per_process: 200 },
  economic_context: { revenue_daily: { known_sum: 100, complete_sum: null, missing_or_conflicting_process_count: 0 }, customer_count: { known_sum: 10, complete_sum: null, missing_or_conflicting_process_count: 0 },
    unmapped_exposed_system_count: 1, scope: "distinct exposed process IDs only", note: "Declared context, not predicted loss. Customer populations may overlap." }, note: "Recorded support is not proof of failure." };

it("preserves legacy names without inventing a scoped process projection", () => {
  render(<ProcessImpactPanel legacy={[{ id: "p", name: "Payments" }]} />);
  expect(screen.getByText(/Process projection unavailable for this stored answer/)).toBeInTheDocument();
  expect(screen.getByText("Payments")).toBeInTheDocument();
  expect(screen.queryByText(/Modeled process exposure:/)).not.toBeInTheDocument();
});

it("distinguishes exposure context and potential, with real mapping and system reason", () => {
  render(<ProcessImpactPanel impact={result} />);
  expect(screen.getByText(/Modeled process exposure: 1/)).toBeInTheDocument();
  expect(screen.getByText(/Context-only processes: 1 · Potential-only processes: 1/)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/Payments \(p\)/));
  expect(screen.getByText("mobile → process:p")).toBeInTheDocument();
  expect(screen.getByText(/Mapping record: sp-1/)).toBeInTheDocument();
  expect(screen.getByText(/Declared role: FRONTEND · DECLARED/)).toBeInTheDocument();
  expect(screen.getByText(/No support expiry deadline — not verified freshness/)).toBeInTheDocument();
  expect(screen.getByText("change:42")).toBeInTheDocument();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
  expect(screen.getByText(/unknown coverage, not zero impact/)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/Declared business context — not predicted loss/));
  expect(screen.getByText(/Not a count of unique people/)).toBeInTheDocument();
  expect(screen.getByText(/Recorded revenue\/day known sum: 100; incomplete/)).toBeInTheDocument();
});

it("shows bounds separately from full process/reason counts", () => {
  render(<ProcessImpactPanel impact={{ ...result, processes: [{ ...process, reason_count: 202, reasons_truncated: true }],
    coverage: { ...result.coverage, total_process_count: 502, returned_process_count: 500, processes_truncated: true } }} />);
  expect(screen.getByText(/500 returned of 502/)).toBeInTheDocument();
  fireEvent.click(screen.getByText(/Payments \(p\)/));
  expect(screen.getByText(/202 recorded inclusion reasons/)).toBeInTheDocument();
  expect(screen.getByTitle(/process remains counted once by ID/)).toBeInTheDocument();
});
