import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import DigitalTwinPanel from "./DigitalTwinPanel";
import { mockFetch } from "../test/setup";

/* The twin panel's four views, and the three honesty rules that travel with them:

* a coverage loss outranks a crypto change in the compare verdict, because once a
  plane stopped collecting everything under it is unreliable;
* capability is never shown as use — the crypto graph keeps the planes apart;
* "not comparable" is a state, not an empty diff. */

const TWIN = "/api/v1/estate/evidence/twin";
const CRYPTO = `${TWIN}/crypto-graph`;
const GRAPH = `${TWIN}/graph`;
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

it("renders the four twin views", async () => {
  mockFetch({ [TWIN]: overview() });
  render(<DigitalTwinPanel />);
  expect(await screen.findByText(/twin completeness/)).toHaveTextContent("55.5%");
  for (const label of ["Live estate", "Crypto graph", "History & compare", "Graph export"]) {
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
