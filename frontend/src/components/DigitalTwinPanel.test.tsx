import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import DigitalTwinPanel from "./DigitalTwinPanel";
import { mockFetch } from "../test/setup";

/* The twin panel's four views, and the three honesty rules that travel with them:

* a coverage loss outranks a crypto change in the compare verdict, because once a
  plane stopped collecting everything under it is unreliable;
* capability is never shown as use — the crypto graph keeps the planes apart;
* "not comparable" is a state, not an empty diff;
* a graph-store load is only ever *planned* from the console, and a stored
  simulation is shown as a question asked of a copy — never as estate state. */

const TWIN = "/api/v1/estate/evidence/twin";
const CRYPTO = `${TWIN}/crypto-graph`;
const GRAPH = `${TWIN}/graph`;
const GRAPH_LOAD = `${TWIN}/graph/load`;
const SIMULATIONS = `${TWIN}/simulations`;
const CHANGES = "/api/v1/estate/evidence/changes";
const SNAPSHOTS = `${TWIN}/snapshots`;

function overview() {
  return {
    model: "cryptoscan.estate-twin-overview/1",
    projection_id: "a".repeat(32),
    estate: "Synthetic Bank",
    summary: {},
    placement: { environments: [], unplaced_count: 2, business_systems: [] },
    completeness: {
      schema: "x", projection_id: "a".repeat(32), dimensions: [], visibility: [], measured: 0,
      unmeasured: [], overall_percent: 55.5, overall_state: "MEASURED",
      overall_label: "twin completeness", is_posture_score: false, meaning: "description, not readiness",
      why_not_100: [],
    },
    note: "",
  };
}

it("renders the twin views", async () => {
  mockFetch({ [TWIN]: overview() });
  render(<DigitalTwinPanel />);
  expect(await screen.findByText(/twin completeness/)).toHaveTextContent("55.5%");
  for (const label of ["Live estate", "Crypto graph", "Changes", "History & compare", "Graph export"]) {
    expect(screen.getByText(label)).toBeInTheDocument();
  }
});

it("keeps capability and use on separate planes", async () => {
  mockFetch({
    [TWIN]: overview(),
    [CRYPTO]: {
      schema: "cryptoscan.estate-crypto-graph/1",
      projection_id: "b".repeat(32),
      planes: {
        CAPABILITY: [{ label: "AES-128", layer: "APPLICATION", usage_state: "SUPPORTED", evidence_type: "STATIC_OBSERVED", confidence: "MEDIUM", asset_id: "l1", asset_name: "OpenSSL" }],
        CONFIGURED: [],
        RUNTIME_OBSERVED: [{ label: "AES-256-GCM", layer: "APPLICATION", usage_state: "OBSERVED", evidence_type: "RUNTIME_OBSERVED", confidence: "HIGH", asset_id: "a1", asset_name: "Payment API" }],
        NETWORK_OBSERVED: [],
      },
      plane_meanings: { CAPABILITY: "what it can do — never proof of use", CONFIGURED: "", RUNTIME_OBSERVED: "", NETWORK_OBSERVED: "" },
      counts: {},
      nodes: [], edges: [],
      coexistence: [{
        asset_name: "OpenSSL",
        capability: ["AES-128", "AES-256"],
        in_use: ["AES-256-GCM"],
        supported_but_not_observed: ["AES-128"],
        explanation: "this asset can do more than it was seen doing",
      }],
      conflicts: [], explained_disagreements: [],
      conflict_counts: { real: 0, explained: 1 },
      note: "",
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Crypto graph")).click();
  await waitFor(() => expect(screen.getByText("CAPABILITY IS NOT USE")).toBeInTheDocument());
  expect(screen.getByText(/Supported but not observed/)).toHaveTextContent("AES-128");
  expect(screen.getByText(/never proof of use/)).toBeInTheDocument();
  expect(screen.getByText("0 real conflict(s)")).toBeInTheDocument();
});

it("shows a degraded plane above the crypto movement it explains", async () => {
  mockFetch({
    [TWIN]: overview(),
    [SNAPSHOTS]: {
      model: "x", persisted: true, count: 2, note: "",
      snapshots: [
        { id: "2", snapshot_id: "twin:b", projection_id: "b".repeat(32), estate: "x", scope: null, assets: 3, evidence: 4, relationships: 2, unresolved_relationships: 0, completeness_percent: 50, observations: 1, first_seen_at: null, last_seen_at: null, captured_by: null, note: null },
        { id: "1", snapshot_id: "twin:a", projection_id: "a".repeat(32), estate: "x", scope: null, assets: 3, evidence: 5, relationships: 2, unresolved_relationships: 0, completeness_percent: 70, observations: 1, first_seen_at: null, last_seen_at: null, captured_by: null, note: null },
      ],
    },
    [`${TWIN}/compare`]: {
      schema: "cryptoscan.estate-twin-compare/1",
      verdict: "COVERAGE_DEGRADED",
      reason: "a plane stopped being observed",
      assets: { added: [], removed: [], changed: [], counts: { added: 0, removed: 0, changed: 0 } },
      relationships: { established: [], lost: [], counts: {} },
      crypto: { added: [], removed: [], promoted: [], demoted: [], counts: { added: 0, removed: 0 }, note: "" },
      coverage: { degraded: [{ plane: "HSM", before: "COMPLETE", after: "FAILED", reason: "API unavailable" }], improved: [], counts: { degraded: 1, improved: 0 } },
      note: "NO_CHANGE is not a safety statement",
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("History & compare")).click();
  await waitFor(() => expect(screen.getByText("2 persisted")).toBeInTheDocument());
  screen.getByText("Compare two newest").click();
  await waitFor(() => expect(screen.getByText("COVERAGE_DEGRADED")).toBeInTheDocument());
  expect(screen.getByText(/HSM: COMPLETE → FAILED/)).toHaveTextContent("API unavailable");
  expect(screen.getByText("1 plane(s) degraded")).toBeInTheDocument();
});

it("treats a missing snapshot set as an error rather than an empty history", async () => {
  globalThis.fetch = (() => Promise.reject(new Error("offline"))) as unknown as typeof fetch;
  render(<DigitalTwinPanel />);
  (await screen.findByText("History & compare")).click();
  await waitFor(() =>
    expect(screen.getByText(/snapshot history unavailable/)).toHaveTextContent("not 'no history'"),
  );
});

it("plans a graph-store load without writing anything", async () => {
  mockFetch({
    [TWIN]: overview(),
    [GRAPH]: {
      schema: "cryptoscan.estate-graph-export/1", projection_id: "c".repeat(32), generated_at: null,
      counts: { asset_nodes: 3, evidence_nodes: 4, relationships: 2, unresolved: 1 },
      nodes: [], relationships: [], unresolved: [],
      load_notes: { not_source_of_truth: "the store is a copy", edge_identity: "edges are (from,to,type)" },
    },
    [GRAPH_LOAD]: {
      schema: "cryptoscan.estate-graph-load/1", projection_id: "c".repeat(32), estate: "Synthetic Bank",
      dry_run: true, statements: 5,
      expected: { nodes: 7, relationships: 2, unresolved: 1, projection_id: "c".repeat(32) },
      written: {}, verification: "DRY_RUN",
      source_of_truth: "the evidence wins and the store is rebuilt", note: "nothing written",
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Graph export")).click();
  (await screen.findByText("Plan the graph-store load")).click();
  await waitFor(() => expect(screen.getByText(/DRY RUN — nothing written/)).toBeInTheDocument());
  expect(screen.getByText("5 statement(s)")).toBeInTheDocument();
  expect(screen.getByText("1 unresolved candidate(s)")).toBeInTheDocument();
  expect(screen.getByText(/the evidence wins and the store is rebuilt/)).toBeInTheDocument();
});

it("lists stored simulations as quarantined questions, with a stale one marked", async () => {
  mockFetch({
    [TWIN]: overview(),
    [SNAPSHOTS]: { model: "x", persisted: true, count: 0, note: "", snapshots: [] },
    [SIMULATIONS]: {
      model: "cryptoscan.estate-simulations/1", count: 2,
      quarantined: true, is_estate_state: false,
      counting_rule: "a simulation is never counted as an observation",
      note: "stored for the audit trail",
      simulations: [
        {
          simulation_id: "sim-current", kind: "REPLACE_ALGORITHM",
          scenario: { from: "RSA", to: "ML-DSA" }, label: "pqc-2027",
          superseded: false, freshness: "CURRENT — computed against the live projection id",
          matched_evidence: 4, affected_assets: ["Payment API", "HSM-03"],
          impact: {}, blockers: [], live_state_modified: false, observations: 1,
          quarantined: true, is_estate_state: false,
        },
        {
          simulation_id: "sim-old", kind: "DISABLE_PROTOCOL",
          scenario: {}, label: null,
          superseded: true, freshness: "STALE — the estate has moved since this was simulated; re-run before quoting it",
          matched_evidence: 2, affected_assets: ["LB-07"],
          impact: {}, blockers: [], live_state_modified: false, observations: 2,
          quarantined: true, is_estate_state: false,
        },
      ],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("History & compare")).click();
  await waitFor(() => expect(screen.getByText("2 stored")).toBeInTheDocument());
  expect(screen.getByText(/never estate state/)).toBeInTheDocument();
  expect(screen.getByText("STALE")).toBeInTheDocument();
  expect(screen.getByText(/re-run before quoting it/)).toBeInTheDocument();
  expect(screen.getByText("asked 2×")).toBeInTheDocument();
});

it("shows what changed, not merely that something changed", async () => {
  mockFetch({
    [TWIN]: overview(),
    [CHANGES]: {
      schema: "cryptoscan.estate-change-feed/1",
      count: 2, unacknowledged: 1, filtered: false,
      by_severity: { CRITICAL: 1, WARNING: 1 },
      by_kind: { COVERAGE_DEGRADED: 1, CRYPTO_DEMOTED: 1 },
      meaning: "the feed records movement between observations",
      limits: [
        "detection compares observations; it never re-collects to confirm a change",
        "a quiet feed cannot distinguish a stable estate from a scheduler that stopped running",
      ],
      events: [
        {
          schema: "cryptoscan.estate-change-event/1", event_id: "chg_1",
          verdict: "COVERAGE_DEGRADED", severity: "CRITICAL",
          severity_meaning: "a plane stopped answering",
          changed: true,
          headline: "coverage lost: HSM",
          next_action: "restore the plane: check its credentials",
          counts: { COVERAGE_DEGRADED: 1 },
          changes: [{
            kind: "COVERAGE_DEGRADED", severity: "CRITICAL", subject: "HSM",
            before: "COMPLETE", after: "FAILED",
            detail: "HSM went COMPLETE → FAILED — API unavailable",
            means: "the estate under this plane is UNKNOWN now, not absent",
          }],
          trigger: "schedule", observations: 2, acknowledged: false,
          is_estate_state: true as const,
          note: "a change event is a statement about two observations",
        },
        {
          schema: "cryptoscan.estate-change-event/1", event_id: "chg_2",
          verdict: "CRYPTO_CHANGED", severity: "WARNING",
          changed: true, headline: "1 change(s): 1× crypto demoted",
          counts: { CRYPTO_DEMOTED: 1 },
          changes: [{
            kind: "CRYPTO_DEMOTED", severity: "WARNING", subject: "Payment API",
            before: "OBSERVED", after: "CONFIGURED",
            detail: "AES-256-GCM on Payment API: OBSERVED → CONFIGURED",
            means: "proof was lost, not necessarily the cryptography",
          }],
          trigger: "ingest", observations: 1, acknowledged: true,
          is_estate_state: true as const,
          note: "a change event is a statement about two observations",
        },
      ],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Changes")).click();
  await waitFor(() => expect(screen.getByText("2 recorded")).toBeInTheDocument());
  expect(screen.getByText("1 not acknowledged")).toBeInTheDocument();
  expect(screen.getByText(/HSM went COMPLETE → FAILED/)).toBeInTheDocument();
  expect(screen.getByText(/UNKNOWN now, not absent/)).toBeInTheDocument();
  expect(screen.getByText(/proof was lost, not necessarily/)).toBeInTheDocument();
  expect(screen.getByText("Acknowledge")).toBeInTheDocument();
  expect(screen.getByText("acknowledged")).toBeInTheDocument();
});
