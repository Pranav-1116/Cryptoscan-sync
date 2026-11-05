import React from "react";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import TwinWalkthrough, { WALKTHROUGH_STEPS } from "./TwinWalkthrough";
import { mockFetch } from "../test/setup";

/* The walkthrough's honesty rules, in the order they matter:

* it is all thirteen screens, in the specification's order, on one canvas — a
  twelve-step walkthrough is not the thing §9 asked for;
* every step explains itself for the asset the investigator picked, because
  "carry one asset through thirteen investigations" is the point of the canvas;
* an unread twin prints the failure, never a zero — a panel of zeros over an
  estate nobody looked at reads as a finding;
* a gap the twin can see (no network relationship, no HSM, no change event) is
  worded as a gap in the twin's evidence, never as a property of the estate. */

const TWIN = "/api/v1/estate/evidence/twin";
// the ref is encoded on the wire: ":" becomes %3A
const ASSET = "/api/v1/estate/evidence/twin/assets/application%3Aaaa";
const SEARCH = "/api/v1/estate/evidence/twin/search";
const CHANGES = "/api/v1/estate/evidence/changes";
const INTEL_ROUTE = "/api/v1/estate/evidence/twin/intel";
const GRAPH = "/api/v1/estate/evidence/twin/graph";

const ASSET_VIEW = {
  asset: { asset_id: "application:aaa", name: "Payment API", type: "APPLICATION",
    environment: "production", owner: "payments-platform", location: "UAE-DC1" },
  placement: { environment: "production", location: "UAE-DC1", owner: "payments-platform", placed: true },
  attributes: {},
  crypto: {
    artifacts: [{ id: "a1" }, { id: "a2" }],
    by_usage_state: { IN_USE: 1, SUPPORTED_BUT_NOT_OBSERVED: 1 },
    observed: [{ id: "a1" }],
    capability_only: [{ id: "a2" }],
    note: "capability is not use",
  },
  relationships: {
    outgoing: [
      { predicate: "runs_on", asset_id: "host:bbb", name: "payments-host-01", type: "HOST", basis: "RUNTIME_OBSERVED", direction: "out" as const },
      { predicate: "uses_hsm", asset_id: "hsm:ccc", name: "HSM-03", type: "HSM", basis: "PKCS11_REFERENCE", direction: "out" as const },
      { predicate: "built_from", asset_id: "library:ddd", name: "openssl", type: "LIBRARY", basis: "MANIFEST", direction: "out" as const },
    ],
    incoming: [],
    dependencies: [],
    count: 3,
  },
  evidence: {
    count: 1,
    by_type: { RUNTIME_OBSERVED: 1 },
    strongest: "RUNTIME_OBSERVED",
    records: [{
      evidence_id: "ev-1", evidence_type: "RUNTIME_OBSERVED", collector: "linux-static",
      source: "/etc/payment/config.yaml", observed_at: "2026-11-01T09:00:00Z",
      confidence: "HIGH", hash: "f".repeat(64), facts: {},
    }],
  },
  unknown: { unresolved_relationships: [], conflicts: [], no_evidence: false },
  neighbourhood: {
    depth: 2, reached: 2, truncated: false,
    assets: [
      { asset_id: "host:bbb", name: "payments-host-01", type: "HOST", hops: 1 },
      { asset_id: "hsm:ccc", name: "HSM-03", type: "HSM", hops: 2 },
    ],
  },
};

const TWIN_OVERVIEW = {
  model: "cryptoscan.estate-twin/1",
  projection_id: "0123456789abcdef0123456789abcdef",
  estate: "Synthetic Bank",
  summary: { assets: 12, evidence: 40 },
  placement: { environments: [], unplaced_count: 0, business_systems: [] },
  completeness: {
    schema: "cryptoscan.estate-twin-completeness/1", projection_id: "p",
    dimensions: [], visibility: [], measured: 3, unmeasured: [],
    overall_percent: 62, overall_state: "PARTIAL", overall_label: "partially covered",
    weakest_dimension: { dimension: "runtime", percent: 40, reason: "no runtime collector ran" },
    is_posture_score: false, meaning: "", why_not_100: [],
  },
  note: "",
};

const CHANGES_FEED = {
  schema: "cryptoscan.estate-changes/1", count: 1, unacknowledged: 1,
  by_severity: { WARNING: 1 }, by_kind: { ALGORITHM: 1 },
  events: [{
    schema: "cryptoscan.estate-change-event/1", event_id: "evt-1", verdict: "CHANGED",
    severity: "WARNING" as const, changed: true, headline: "Payment API moved to RSA-2048",
    changes: [{ kind: "ALGORITHM", severity: "WARNING" as const, subject: "application:aaa",
      before: "RSA-4096", after: "RSA-2048", detail: "", evidence_ids: [] }],
    counts: {}, trigger: "schedule", observations: 2, acknowledged: false, is_estate_state: true as const,
    note: "",
  }],
  meaning: "", limits: [],
};

const INTEL_DOC = {
  schema: "cryptoscan.estate-crypto-intel/1", artifacts_examined: 2,
  weak: { count: 0, in_use_count: 0, capability_only_count: 0, by_status: {}, by_asset_type: {}, assets: [], capability_only: [], entries: [], meaning: "" },
  unknown: { count: 0, unrecognised_count: 0, mislabelled_count: 0, assets: [], entries: [], meaning: "" },
  pqc: {
    vulnerable_artifacts: 1, vulnerable_in_use: 1, by_algorithm: { RSA: 1 }, by_asset_type: {},
    affected_assets: [{ asset_id: "application:aaa", asset_name: "Payment API", asset_type: "APPLICATION", algorithms: ["RSA-2048"] }],
    vendor_bound_blockers: [], vendor_bound_blocker_count: 0, pqc_algorithms_present: ["ML-KEM-768"],
    pending_migration_count: 0, meaning: "quantum-vulnerable means the algorithm is broken by Shor's algorithm",
  },
  next_action: "", limits: [],
};

const GRAPH_DOC = {
  schema: "cryptoscan.estate-graph-export/1",
  projection_id: "d".repeat(32),
  generated_at: "2026-11-05T00:00:00Z",
  counts: { nodes: 3, asset_nodes: 2, evidence_nodes: 0, relationships: 1, unresolved: 1 },
  nodes: [
    { id: "application:aaa", labels: ["Asset", "APPLICATION"], properties: { name: "Payment API" } },
    { id: "hsm:ccc", labels: ["Asset", "HSM"], properties: { name: "HSM-03" } },
    { id: "placement:environment:eee", labels: ["PLACEMENT", "ENVIRONMENT"], properties: { name: "production" } },
  ],
  relationships: [
    { type: "USES_HSM", from: "application:aaa", to: "hsm:ccc", properties: { evidence_ids: ["ev-1"] } },
  ],
  unresolved: [{ type: "UNRESOLVED", from: "application:aaa", to: "hsm:ccc", properties: {} }],
  load_notes: {},
};

function routes() {
  return {
    [TWIN]: TWIN_OVERVIEW,
    [ASSET]: ASSET_VIEW,
    [SEARCH]: { query: "payment", status: "FOUND", assets: [ASSET_VIEW.asset], artifacts: [] },
    [CHANGES]: CHANGES_FEED,
    [INTEL_ROUTE]: INTEL_DOC,
    [GRAPH]: GRAPH_DOC,
  };
}

const stepButton = (name: string) => screen.getByRole("button", { name: new RegExp(name) });

async function pickAsset() {
  fireEvent.click(screen.getByRole("button", { name: /Asset Explorer/ }));
  fireEvent.change(screen.getByLabelText("Find an asset"), { target: { value: "payment" } });
  fireEvent.click(screen.getByRole("button", { name: "Find" }));
  fireEvent.click(await screen.findByRole("button", { name: /Payment API/ }));
  await waitFor(() => expect(screen.getByText(/selected asset/)).toBeInTheDocument());
}

it("is the thirteen screens, in the specification's order", () => {
  mockFetch(routes());
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);

  expect(WALKTHROUGH_STEPS).toHaveLength(13);
  expect(WALKTHROUGH_STEPS.map((step) => step.title)).toEqual([
    "Twin Overview", "Asset Explorer", "Relationship Graph", "Cryptographic Graph",
    "Network Topology", "Hardware & HSM", "Vendor Dependencies", "Evidence Explorer",
    "Historical Twin", "Drift Analysis", "Blast Radius", "Simulation Lab", "PQC Impact",
  ]);
  for (const step of WALKTHROUGH_STEPS) expect(screen.getByText(step.title)).toBeInTheDocument();
  expect(screen.getByText("step 1 of 13")).toBeInTheDocument();
});

it("carries one asset through the steps, and every step links to its own screen", async () => {
  mockFetch(routes());
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);

  await waitFor(() => expect(screen.getByText(/62%/)).toBeInTheDocument());
  await pickAsset();

  fireEvent.click(stepButton("Relationship Graph"));
  expect(screen.getByText("runs_on")).toBeInTheDocument();
  expect(screen.getByText("HSM-03")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Relationship Graph/ })).toHaveAttribute("href", "/graph");

  fireEvent.click(stepButton("Evidence Explorer"));
  expect(screen.getByText("linux-static")).toBeInTheDocument();
  expect(screen.getByText("/etc/payment/config.yaml")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Evidence Explorer/ })).toHaveAttribute("href", "/evidence");
});

it("words an absent relationship as a gap in the twin, not a property of the estate", async () => {
  mockFetch({
    ...routes(),
    [ASSET]: { ...ASSET_VIEW, relationships: { outgoing: [], incoming: [], dependencies: [], count: 0 } },
  });
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);
  await pickAsset();

  fireEvent.click(stepButton("Network Topology"));
  expect(screen.getByText(/not "the asset is not on a network"/)).toBeInTheDocument();

  fireEvent.click(stepButton("Hardware & HSM"));
  expect(screen.getByText(/that gap is the finding/)).toBeInTheDocument();
});

it("prints an unreadable twin as a failure, never as a zero", async () => {
  mockFetch({});
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);

  expect(await screen.findByText(/that is not 'the estate holds nothing'/)).toBeInTheDocument();
  fireEvent.click(stepButton("Drift Analysis"));
  expect(screen.getByText(/that is not 'nothing changed'/)).toBeInTheDocument();
});

it("reports a failed asset read as a failed read", async () => {
  mockFetch({ ...routes(), [ASSET]: new Response(JSON.stringify({ detail: "tier unavailable" }), { status: 503 }) });
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: /Asset Explorer/ }));
  fireEvent.change(screen.getByLabelText("Find an asset"), { target: { value: "payment" } });
  fireEvent.click(screen.getByRole("button", { name: "Find" }));
  fireEvent.click(await screen.findByRole("button", { name: /Payment API/ }));

  fireEvent.click(stepButton("Evidence Explorer"));
  expect(await screen.findByText(/that is not 'it has no evidence'/)).toBeInTheDocument();
});

it("names the asset's own drift and PQC exposure", async () => {
  mockFetch(routes());
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);
  await pickAsset();

  fireEvent.click(stepButton("Drift Analysis"));
  expect(await screen.findByText("Payment API moved to RSA-2048")).toBeInTheDocument();

  fireEvent.click(stepButton("PQC Impact"));
  expect(screen.getByText("RSA-2048")).toBeInTheDocument();
  expect(screen.getByText(/present is not the same as deployed/)).toBeInTheDocument();
});

it("never runs a scenario from the walkthrough", async () => {
  const fetchSpy = mockFetch(routes());
  render(<MemoryRouter><TwinWalkthrough /></MemoryRouter>);
  await pickAsset();

  fireEvent.click(stepButton("Simulation Lab"));
  expect(screen.getByText(/Nothing is run here/)).toBeInTheDocument();
  const posts = fetchSpy.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === "POST");
  expect(posts).toHaveLength(0);
});
