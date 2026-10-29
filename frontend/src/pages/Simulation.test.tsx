import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Simulation from "./Simulation";

const BASE = "/api/v1/estate/evidence/simulation";
const FROM = "From (the value the evidence holds today)";
const TO = "To (the value the scenario would use instead)";

const catalog = {
  schema: "cryptoscan.simulation-workspace/1",
  run_id: "run-1",
  base_projection_id: "2b1b8b8ac7193c2a07bc707b97b584dc",
  estate: { assets: 3, evidence: 2, relationships: 1, coverage_state: "MEASURED", attempted: null, collected: 6 },
  kinds: [
    {
      kind: "REPLACE_ALGORITHM", name: "Replace an algorithm",
      question: "If every use of {from} became {to}, what changes and what breaks?",
      inputs: ["from", "to"], optional: ["key_size", "targets"],
      answers: ["which evidence records would change"],
      does_not_answer: ["whether the target algorithm is supported by a library"],
    },
    {
      kind: "RETIRE_ALGORITHM", name: "Retire an algorithm",
      question: "If every use of {from} were removed, what stops working?",
      inputs: ["from"], optional: ["targets"],
      answers: ["which records lose a value"], does_not_answer: ["what replaces it"],
    },
  ],
  selector: {
    algorithms: [{ value: "AES", count: 2 }, { value: "RSA", count: 1 }],
    protocols: [{ value: "TLSv1.3", count: 1 }],
    components: [{ value: "OpenSSL 3.0.13", count: 1 }],
    targets: [{ asset_id: "application:abc", name: "payments-api", type: "APPLICATION" }],
    truncated_to: 40,
    note: "these are the values this estate holds",
  },
  note: "a scenario is applied to a copy of this twin",
  limits: ["a simulation is a question asked of a copy"],
};

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

const zeroDiff = { added: [], removed: [], changed: [], counts: { added: 0, removed: 0, changed: 0, unchanged: 0 } };

function run(overrides: Record<string, unknown> = {}) {
  return {
    status: "SIMULATED", run_id: "run-1", schema: "cryptoscan.estate-twin-simulation/1",
    kind: "REPLACE_ALGORITHM", scenario: { kind: "REPLACE_ALGORITHM", from: "AES", to: "ML-KEM" },
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

describe("simulation workspace", () => {
  it("builds the scenario out of the values this estate actually reports", async () => {
    mockFetch({ [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: { ...history, count: 0, simulations: [] } });
    renderWithProviders(<Simulation />);

    expect(await screen.findByRole("heading", { name: "Simulation workspace" })).toBeInTheDocument();
    // both kinds are offered, with the question each one answers
    expect(screen.getByRole("button", { name: /Replace an algorithm/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retire an algorithm/ })).toBeInTheDocument();
    // the vocabulary is the estate's, not a hardcoded list of algorithms
    expect(screen.getByRole("button", { name: /AES/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /payments-api/ })).toBeInTheDocument();
    // the estate the answer is measured against is on screen
    expect(screen.getByText("3 assets · 2 evidence")).toBeInTheDocument();
    expect(screen.getByText(/no stored runs yet/i)).toBeInTheDocument();
  });

  it("refuses to run before a preview, and says a no-match preview is not no impact", async () => {
    const plan = preview({
      status: "WOULD_NOT_MATCH", matched_evidence: 0, affected_assets: [], affected_asset_count: 0,
      by_layer: {}, note: "nothing matched — this is not 'no impact', it is 'nothing was found to change'",
    });
    const fetchSpy = mockFetch({
      [`${BASE}/catalog`]: catalog, [`${BASE}/runs`]: { ...history, count: 0, simulations: [] },
      [`${BASE}/plan`]: plan,
    });
    renderWithProviders(<Simulation />);
    await screen.findByRole("heading", { name: "Simulation workspace" });

    const runButton = screen.getByRole("button", { name: "Run simulation" });
    expect(runButton).toBeDisabled();
    // the form says what it is still missing before it says what to do next
    expect(screen.getByText("Still needed: from, to")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(FROM), { target: { value: "AES" } });
    fireEvent.change(screen.getByLabelText(TO), { target: { value: "ML-KEM" } });
    expect(screen.getByText(/Preview first/)).toBeInTheDocument();
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
      [`${BASE}/runs`]: { ...history, count: 0, simulations: [] },
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

  it("says there is no twin instead of simulating over nothing", async () => {
    mockFetch({ [`${BASE}/catalog`]: new Response(JSON.stringify({ detail: { error: "no_estate_discovery" } }), { status: 404 }) });
    renderWithProviders(<Simulation />);

    expect(await screen.findByRole("heading", { name: "No twin to simulate against" })).toBeInTheDocument();
    expect(screen.getByText(/Nothing has been discovered yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run discovery" })).toHaveAttribute("href", "/scanners");
  });
});
