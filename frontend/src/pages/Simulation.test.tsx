import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Simulation from "./Simulation";

const BASE = "/api/v1/estate/evidence/simulation";
const FROM = "From (the value the evidence holds today)";
const TO = "To (the value the scenario would use instead)";

const kinds = [
  {
    kind: "REPLACE_ALGORITHM", mode: "SCENARIO", name: "Replace an algorithm",
    question: "If every use of {from} became {to}, what changes and what breaks?",
    inputs: ["from", "to"], optional: ["key_size", "targets"],
    answers: ["which evidence records would change"],
    does_not_answer: ["whether the target algorithm is supported by a library"],
  },
  {
    kind: "RETIRE_ALGORITHM", mode: "SCENARIO", name: "Retire an algorithm",
    question: "If every use of {from} were removed, what stops working?",
    inputs: ["from"], optional: ["targets"],
    answers: ["which records lose a value"], does_not_answer: ["what replaces it"],
  },
  {
    kind: "CASCADE_ASSET_UNAVAILABLE", mode: "CASCADE", name: "Asset goes down",
    question: "If {seeds} stopped serving, what breaks, wave by wave?",
    inputs: ["targets"], optional: ["depth"],
    answers: ["each wave of reached assets and the edge that carried the failure to it"],
    does_not_answer: ["that service stops: redundancy is evidence the twin does not hold"],
  },
  {
    kind: "CASCADE_ALGORITHM_BREAK", mode: "CASCADE", name: "An algorithm breaks everywhere",
    question: "If {from} became untrustworthy tonight, what is reached from every use of it?",
    inputs: ["from"], optional: ["depth", "targets"],
    answers: ["every asset using it, as the seeds of one event"],
    does_not_answer: ["harvest-now-decrypt-later"],
  },
];

const catalog = {
  schema: "cryptoscan.simulation-workspace/1",
  run_id: "run-1",
  base_projection_id: "2b1b8b8ac7193c2a07bc707b97b584dc",
  estate: { assets: 3, evidence: 2, relationships: 1, coverage_state: "MEASURED", attempted: null, collected: 6 },
  modes: [
    { mode: "SCENARIO", name: "Change the estate", blurb: "apply a change to a copy of the twin", changes_evidence: true, has_bom_diff: true },
    { mode: "CASCADE", name: "Cascade a failure", blurb: "propagate a failure through the established dependency edges", changes_evidence: false, has_bom_diff: false },
  ],
  kinds,
  presets: [
    { id: "retire:AES", label: "Retire AES", mode: "SCENARIO", kind: "RETIRE_ALGORITHM",
      scenario: { kind: "RETIRE_ALGORITHM", from: "AES" }, why: "2 artefact(s) in this estate use it" },
    { id: "down:application:abc", label: "If payments-api goes down", mode: "CASCADE",
      kind: "CASCADE_ASSET_UNAVAILABLE",
      scenario: { kind: "CASCADE_ASSET_UNAVAILABLE", targets: ["application:abc"] },
      why: "2 established edge(s) rest on it" },
  ],
  selector: {
    algorithms: [{ value: "AES", count: 2 }, { value: "RSA", count: 1 }],
    protocols: [{ value: "TLSv1.3", count: 1 }],
    components: [{ value: "OpenSSL 3.0.13", count: 1 }],
    targets: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION" }],
    truncated_to: 40, note: "these are the values this estate holds",
  },
  note: "a scenario is applied to a copy of this twin",
  limits: ["a simulation is a question asked of a copy"],
};

const rules = [
  { predicate: "depends_on", direction: "object_to_subject", meaning: "a declared dependency on a stopped service is unmet" },
  { predicate: "contains", direction: "both", meaning: "a system holding a stopped component is degraded" },
];

function preview(overrides: Record<string, unknown> = {}) {
  return {
    schema: "cryptoscan.estate-twin-simulation-preview/1",
    status: "WOULD_MATCH", kind: "REPLACE_ALGORITHM",
    scenario: { kind: "REPLACE_ALGORITHM", from: "AES", to: "ML-KEM" },
    base_projection_id: "2b1b8b8ac7193c2a07bc707b97b584dc",
    live_state_modified: false, evidence_considered: 2, matched_evidence: 2,
    affected_assets: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION", evidence_matched: 2 }],
    affected_asset_count: 1, by_layer: { APPLICATION: 2 }, unresolved_targets: [],
    coverage: {
      target_classes: 4, expected: 6, collected: 6, coverage_percent: 100,
      coverage_state: "MEASURED", by_status: {}, failed_targets: [],
    },
    note: "2 evidence record(s) on 1 asset(s) would change",
    limits: ["a preview counts the evidence records a scenario would touch"],
    ...overrides,
  };
}

function cascadePreview(overrides: Record<string, unknown> = {}) {
  return preview({
    status: "WOULD_MATCH", kind: "CASCADE_ASSET_UNAVAILABLE", mode: "CASCADE", engine: "CASCADE",
    depth: 3, matched_evidence: 1, evidence_considered: 1,
    seeds: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION", reason: "named by the scenario" }],
    unresolved_seeds: [],
    affected_assets: [
      { asset_id: "host:1", name: "host-01", type: "HOST", hops: 1, via_predicate: "runs_on" },
      { asset_id: "system:1", name: "Payments", type: "SYSTEM", hops: 2, via_predicate: "contains" },
    ],
    affected_asset_count: 2,
    wave_counts: [{ depth: 1, count: 1 }, { depth: 2, count: 1 }],
    business_systems_reached: 1,
    rules,
    note: "2 asset(s) would be reached from 1 seed(s) within 3 hop(s)",
    limits: ["a cascade propagates over established edges only"],
    ...overrides,
  });
}

const zeroDiff = { added: [], removed: [], changed: [], counts: { added: 0, removed: 0, changed: 0, unchanged: 0 } };

function run(overrides: Record<string, unknown> = {}) {
  return {
    status: "SIMULATED", run_id: "run-1", schema: "cryptoscan.estate-twin-simulation/1",
    kind: "REPLACE_ALGORITHM", mode: "SCENARIO",
    scenario: { kind: "REPLACE_ALGORITHM", from: "AES", to: "ML-KEM" },
    base_snapshot: "twin:2b1b", base_projection_id: "2b1b",
    simulated_projection_id: "9999", matched_evidence: 2,
    affected_assets: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION" }],
    effects: [{
      evidence_id: "ev-1", asset_id: "application:abc", asset_name: "payments-api",
      layer: "APPLICATION", evidence_type: "STATIC_OBSERVED",
      before: { algorithm: "AES", key_size: 128 }, after: { algorithm: "ML-KEM", key_size: 768 },
    }],
    bom_diff: { SBOM: zeroDiff, CBOM: zeroDiff, HBOM: zeroDiff, NBOM: zeroDiff, VBOM: zeroDiff, TECHBOM: zeroDiff },
    impact: { counts: { seed: 1, direct: 0, transitive: 0, total: 1 }, by_type: { APPLICATION: 1 } },
    blockers: [], unknown: { affected_assets_without_evidence: 0 },
    live_state_modified: false, live_projection_unchanged: true,
    plan: preview(), simulation_id: "sim:abc", persisted: true,
    simulation_record: { quarantined: true, is_estate_state: false },
    persist_note: "stored as a new quarantined run", note: "the scenario was applied to a copy of the twin",
    ...overrides,
  };
}

function cascadeRun(overrides: Record<string, unknown> = {}) {
  return run({
    status: "SIMULATED", kind: "CASCADE_ASSET_UNAVAILABLE", mode: "CASCADE", engine: "CASCADE",
    scenario: { kind: "CASCADE_ASSET_UNAVAILABLE", targets: ["application:abc"], depth: 3 },
    depth: 3,
    seeds: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION", reason: "named by the scenario" }],
    waves: [
      { depth: 1, count: 1, truncated: 0, assets: [{ asset_id: "host:1", name: "host-01", type: "HOST",
        via: { from_asset: "application:abc", from_name: "payments-api", predicate: "runs_on",
               meaning: "a workload on a stopped host stops with it", edge: { subject: "application:abc",
               predicate: "runs_on", object: "host:1", basis: "DEPLOYMENT_CONFIG", confidence: "HIGH",
               evidence_ids: ["ev-1"] } } }] },
      { depth: 2, count: 1, truncated: 0, assets: [{ asset_id: "system:1", name: "Payments", type: "SYSTEM",
        via: { from_asset: "host:1", from_name: "host-01", predicate: "contains",
               meaning: "a system holding a stopped component is degraded", edge: { subject: "system:1",
               predicate: "contains", object: "host:1", basis: "APPROVED_MAPPING", confidence: "HIGH",
               evidence_ids: ["ev-1"] } } }] },
    ],
    wave_count: 2,
    matched_evidence: 1,
    affected_assets: [
      { asset_id: "host:1", name: "host-01", type: "HOST", hops: 1, via_predicate: "runs_on" },
      { asset_id: "system:1", name: "Payments", type: "SYSTEM", hops: 2, via_predicate: "contains" },
    ],
    impact: {
      counts: { seed: 1, direct: 1, transitive: 1, total: 2 },
      by_type: { HOST: 1, SYSTEM: 1 },
      business_systems: [{ asset_id: "system:1", name: "Payments", hops: 2,
        path: [{ asset_id: "application:abc", name: "payments-api", via_predicate: null, via_asset: null },
               { asset_id: "host:1", name: "host-01", via_predicate: "runs_on", via_asset: "application:abc" },
               { asset_id: "system:1", name: "Payments", via_predicate: "contains", via_asset: "host:1" }] }],
    },
    bom_diff: {},
    bom_diff_note: "a cascade changes no evidence fact, so the six BOMs are identical before and after",
    rules,
    limits: ["a cascade propagates over established edges only", "redundancy is not modelled"],
    unknown: { unresolved_relationships_in_radius: 0, reached_assets_without_evidence: 0 },
    simulation_id: "sim:cascade", persisted: true,
    note: "the cascade was computed over the live topology and read it only",
    ...overrides,
  });
}

const history = {
  model: "cryptoscan.simulation-workspace/1", run_id: "run-1",
  current_projection_id: "2b1b", count: 1, quarantined: true,
  simulations: [{
    id: "row-1", simulation_id: "sim:abc", kind: "REPLACE_ALGORITHM",
    scenario: { kind: "REPLACE_ALGORITHM", from: "AES", to: "ML-KEM" }, label: "PQC pilot",
    computed_against: "2b1b", superseded_by: null, superseded: false,
    freshness: "CURRENT", matched_evidence: 2,
    affected_assets: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION" }],
    observations: 1, last_run_at: "2026-10-29T10:00:00Z",
  }],
  note: "stored runs are quarantined",
};

const emptyHistory = { ...history, count: 0, simulations: [] };

describe("simulation workspace", () => {
  it("builds the scenario out of the values this estate actually reports", async () => {
    mockFetch({ [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: emptyHistory });
    renderWithProviders(<Simulation />);

    expect(await screen.findByRole("heading", { name: "Simulation workspace" })).toBeInTheDocument();
    // the two families are offered separately, each with what it does
    expect(screen.getByText("apply a change to a copy of the twin")).toBeInTheDocument();
    expect(screen.getByText("propagate a failure through the established dependency edges")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Replace an algorithm/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Asset goes down/ })).toBeInTheDocument();
    // the vocabulary is the estate's, not a hardcoded list of algorithms
    expect(screen.getByRole("button", { name: /^AES · 2$/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /payments-api · APPLICATION/ })).toBeInTheDocument();
    // the estate the answer is measured against is on screen
    expect(screen.getByText("3 assets · 2 evidence")).toBeInTheDocument();
    expect(screen.getByText(/no stored runs yet/i)).toBeInTheDocument();
  });

  it("offers the questions this estate can already be asked, and loads one into the form", async () => {
    mockFetch({ [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: emptyHistory });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    const preset = screen.getByRole("button", { name: /Retire AES/ });
    expect(preset).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(preset);

    expect(preset).toHaveAttribute("aria-pressed", "true");
    // the preset selects its kind and fills the value, rather than asking the operator to retype it
    expect(screen.getByRole("button", { name: /Retire an algorithm/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText(FROM)).toHaveValue("AES");
  });

  it("refuses to run before a preview, and says a no-match preview is not no impact", async () => {
    const plan = preview({
      status: "WOULD_NOT_MATCH", matched_evidence: 0, affected_assets: [], affected_asset_count: 0,
      by_layer: {}, note: "nothing matched — this is not 'no impact', it is 'nothing was found to change'",
    });
    const fetchSpy = mockFetch({
      [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: emptyHistory, [`${BASE}/plan`]: plan,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    const runButton = screen.getByRole("button", { name: "Run simulation" });
    expect(runButton).toBeDisabled();
    // the form says what it is still missing before it says what to do next
    expect(screen.getByText("Still needed: from, to")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(FROM), { target: { value: "AES" } });
    fireEvent.change(screen.getByLabelText(TO), { target: { value: "ML-KEM" } });
    expect(screen.getByText(/Preview first —/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Preview match" }));

    expect(await screen.findByText(/this is not 'no impact'/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run simulation" })).toBeDisabled();
    const planned = fetchSpy.mock.calls.find(([url]) => String(url).includes("/simulation/plan"));
    expect(JSON.parse(String(planned?.[1]?.body))).toEqual({ kind: "REPLACE_ALGORITHM", from: "AES", to: "ML-KEM" });
  });

  it("reports a run as a copy: live state untouched, six BOMs re-projected, storage quarantined", async () => {
    mockFetch({
      [`${BASE}/catalog`]: catalog, [`${BASE}/plan`]: preview(),
      [`${BASE}/run`]: run(), [`${BASE}/runs`]: history,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    fireEvent.change(screen.getByLabelText(FROM), { target: { value: "AES" } });
    fireEvent.change(screen.getByLabelText(TO), { target: { value: "ML-KEM" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview match" }));
    const runButton = await screen.findByRole("button", { name: "Run simulation" });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);

    expect(await screen.findByText("LIVE STATE UNTOUCHED")).toBeInTheDocument();
    expect(screen.getByText("PROJECTION ID UNCHANGED")).toBeInTheDocument();
    expect(screen.getByText("SIMULATED")).toBeInTheDocument();
    // the effect is shown as before → after, not as a count
    expect(screen.getByText(/algorithm:/)).toHaveTextContent("AES → ML-KEM");
    // six BOM projections, each with its own diff
    for (const bom of ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"])
      expect(screen.getByText(bom)).toBeInTheDocument();
    // storage is stated, and so is the quarantine
    expect(screen.getByText(/sim:abc/)).toBeInTheDocument();
    expect(screen.getByText(/stored as a new quarantined run/)).toBeInTheDocument();
    // the history refreshes after a run and keeps the quarantine statement
    expect(await screen.findByText("PQC pilot")).toBeInTheDocument();
    expect(screen.getByText(/none of these rows counts as estate state/)).toBeInTheDocument();
    // an empty blocker list is not a clean bill of health
    expect(screen.getByText(/an empty list is not evidence that the change is safe/)).toBeInTheDocument();
  });

  it("does not present a run that matched nothing as a finding", async () => {
    mockFetch({
      [`${BASE}/catalog`]: catalog,
      [`${BASE}/plan`]: preview({ status: "WOULD_MATCH" }),
      [`${BASE}/run`]: run({
        status: "NO_MATCH", matched_evidence: 0, effects: [], affected_assets: [],
        simulation_id: null, persisted: false, simulation_record: null,
        persist_refused_because: "a result that matched nothing is not a simulation result",
        bom_diff: {}, impact: { counts: {} }, note: "the selector matched no evidence",
      }),
      [`${BASE}/runs`]: emptyHistory,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    fireEvent.change(screen.getByLabelText(FROM), { target: { value: "AES" } });
    fireEvent.change(screen.getByLabelText(TO), { target: { value: "ML-KEM" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview match" }));
    const runButton = await screen.findByRole("button", { name: "Run simulation" });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);

    expect(await screen.findByText("NO MATCH")).toBeInTheDocument();
    expect(screen.getByText(/not stored: a result that matched nothing/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Nothing to simulate" })).toBeInTheDocument();
    expect(screen.getByText(/not a statement that the change is safe/)).toBeInTheDocument();
  });

  it("switches to seeds and hops for a cascade, and needs a seed before anything is previewed", async () => {
    mockFetch({ [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: emptyHistory });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    fireEvent.click(screen.getByRole("button", { name: /Asset goes down/ }));

    expect(screen.getByText(/Where the failure starts/)).toBeInTheDocument();
    expect(screen.getByLabelText("Hops to walk")).toHaveValue("3");
    // a cascade with no starting point has nothing to propagate, so the button explains itself
    expect(screen.getByRole("button", { name: "Preview reach" })).toBeDisabled();
    expect(screen.getByText(/Pick at least one seed asset/)).toBeInTheDocument();
    // no vocabulary chips: a cascade starts from an asset, not from an algorithm value
    expect(screen.queryByText(/algorithms in this estate/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /payments-api · APPLICATION/ }));
    expect(screen.getByRole("button", { name: "Preview reach" })).toBeEnabled();
  });

  it("runs a cascade as a route map, wave by wave, and says there is no BOM diff", async () => {
    const fetchSpy = mockFetch({
      [`${BASE}/catalog`]: catalog,
      [`${BASE}/plan`]: cascadePreview(),
      [`${BASE}/run`]: cascadeRun(),
      [`${BASE}/runs`]: history,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    fireEvent.click(screen.getByRole("button", { name: /Asset goes down/ }));
    fireEvent.click(screen.getByRole("button", { name: /payments-api · APPLICATION/ }));
    fireEvent.change(screen.getByLabelText("Hops to walk"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview reach" }));

    expect(await screen.findByText(/2 asset\(s\) would be reached from 1 seed\(s\)/)).toBeInTheDocument();
    // the preview states the seeds and the waves before the run
    expect(screen.getByText("seed assets")).toBeInTheDocument();
    expect(screen.getByText("waves")).toBeInTheDocument();
    const planned = fetchSpy.mock.calls.find(([url]) => String(url).includes("/simulation/plan"));
    expect(JSON.parse(String(planned?.[1]?.body))).toEqual({
      kind: "CASCADE_ASSET_UNAVAILABLE", targets: ["application:abc"], depth: 4,
    });

    const runButton = screen.getByRole("button", { name: "Run cascade" });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);

    expect(await screen.findByText("NO BOM DIFF — NOTHING CHANGED")).toBeInTheDocument();
    // the waves are shown as routes: what arrived, by which edge
    expect(screen.getByText("wave 1")).toBeInTheDocument();
    expect(screen.getByText("wave 2")).toBeInTheDocument();
    expect(screen.getByText("runs_on ← payments-api")).toBeInTheDocument();
    expect(screen.getByText("contains ← host-01")).toBeInTheDocument();
    // the business system reached is shown with its path, not only counted
    expect(screen.getByText(/business systems reached, with the route/)).toBeInTheDocument();
    expect(document.body.textContent).toContain(
      "payments-api → (runs_on) host-01 → (contains) Payments");
    // the rules that carried the failure are inspectable
    expect(screen.getByText(/the 2 edge rules this cascade followed/)).toBeInTheDocument();
    // and the limits travel with the result
    expect(screen.getByText(/redundancy is not modelled/)).toBeInTheDocument();
    expect(screen.getByText(/a cascade changes no evidence fact/)).toBeInTheDocument();
  });

  it("does not store a cascade that reached nothing", async () => {
    mockFetch({
      [`${BASE}/catalog`]: catalog,
      [`${BASE}/plan`]: cascadePreview({ status: "WOULD_MATCH" }),
      [`${BASE}/run`]: cascadeRun({
        status: "NO_MATCH", waves: [], wave_count: 0, affected_assets: [], persisted: false,
        simulation_id: null, unknown: {}, blockers: [],
        impact: { counts: { seed: 1, direct: 0, transitive: 0, total: 0 } },
        detail: "1 seed asset(s) resolved, but no established edge carries this failure out of them within 3 hop(s).",
        persist_refused_because: "a result that matched nothing is not a simulation result",
      }),
      [`${BASE}/runs`]: emptyHistory,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    fireEvent.click(screen.getByRole("button", { name: /Asset goes down/ }));
    fireEvent.click(screen.getByRole("button", { name: /payments-api · APPLICATION/ }));
    fireEvent.click(screen.getByRole("button", { name: "Preview reach" }));
    const runButton = await screen.findByRole("button", { name: "Run cascade" });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);

    expect(await screen.findByRole("heading", { name: "Nothing reached" })).toBeInTheDocument();
    expect(screen.getByText(/not a clean bill of health/)).toBeInTheDocument();
    expect(screen.getByText(/not stored: a result that matched nothing/)).toBeInTheDocument();
  });

  it("says there is no twin instead of simulating over nothing", async () => {
    mockFetch({ [`${BASE}/catalog`]: new Response(JSON.stringify({ detail: { error: "no_estate_discovery" } }), { status: 404 }) });
    renderWithProviders(<Simulation />);

    expect(await screen.findByRole("heading", { name: "No twin to simulate against" })).toBeInTheDocument();
    expect(screen.getByText(/Nothing has been discovered yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run discovery" })).toHaveAttribute("href", "/scanners");
  });
});
