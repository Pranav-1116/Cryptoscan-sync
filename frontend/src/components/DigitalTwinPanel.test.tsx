import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
const CATALOG = "/api/v1/estate/evidence/catalog";
const PLACEMENT = `${TWIN}/placement`;
const HISTORY = "/api/v1/estate/evidence/history";
const SEARCH = "/api/v1/estate/evidence/search";
// mockFetch matches on the path without a query string
const SEARCH_KEY = SEARCH;
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
  for (const label of ["Live estate", "Crypto graph", "Catalogue", "Changes", "History & compare", "Graph export"]) {
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
      counts: { asset_nodes: 3, evidence_nodes: 4, placement_nodes: 6, relationships: 2, unresolved: 1 },
      nodes: [], relationships: [], unresolved: [],
      load_notes: { not_source_of_truth: "the store is a copy", edge_identity: "edges are (from,to,type)" },
      label_coverage: { Organization: ["ORGANIZATION"], DataCenter: ["DATA_CENTER"], KMS: ["KMS_KEY"] },
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
  // the organisation chart is in the projection, and the panel says so rather than
  // leaving a reader to infer that a data centre is only a string on an asset
  expect(await screen.findByText("6 placement nodes")).toBeInTheDocument();
  expect(screen.getByText("3 spec labels covered")).toBeInTheDocument();
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

it("shows stale catalogue rows instead of hiding what stopped being observed", async () => {
  mockFetch({
    [TWIN]: overview(),
    [CATALOG]: {
      schema: "cryptoscan.estate-catalog/1", assets: 2,
      assets_by_type: { HSM: 2 }, assets_by_lifecycle: { ACTIVE: 1, STALE: 1 },
      note: "the catalogue is what has been observed",
    },
    [`${HISTORY}/summary`]: {
      schema: "cryptoscan.estate-observations/1",
      evidence: { total: 7, active: 6, stale: 1, collectors: ["linux-static"], by_type: { CONFIGURED: 7 } },
      observations: { total: 9, current: 8, historical: 1, assets: 2, changed_facts: 1, disputed_facts: 0 },
      disputes: [], meaning: "the twin remembers every value it has asserted",
    },
    [`${CATALOG}/assets`]: {
      count: 2,
      note: "empty means nothing matching has been observed",
      assets: [
        {
          asset_id: "asset:hsm:1", asset_type: "HSM", name: "HSM-03",
          environment: "production", owner: null, location: null, source: null,
          identity: {}, attributes: {}, evidence_ids: ["ev-2"], evidence_count: 1,
          lifecycle_state: "ACTIVE" as const, first_seen_at: "2026-10-20T00:00:00Z",
          last_seen_at: "2026-10-27T00:00:00Z", observation_count: 4,
          is_estate_state: true as const,
        },
        {
          asset_id: "asset:hsm:2", asset_type: "HSM", name: "HSM-04",
          environment: "production", owner: null, location: null, source: null,
          identity: {}, attributes: {}, evidence_ids: [], evidence_count: 3,
          lifecycle_state: "STALE" as const, first_seen_at: "2026-09-01T00:00:00Z",
          last_seen_at: "2026-10-20T00:00:00Z", observation_count: 2,
          is_estate_state: true as const,
        },
      ],
    },
    [`${CATALOG}/crypto`]: {
      schema: "cryptoscan.estate-crypto-registry/1", algorithm_count: 1, record_count: 2,
      algorithms: [{
        algorithm: "AES-256-GCM", asset_count: 2, evidence: 2, stale: 0,
        usage_states: { OBSERVED: 1, NEGOTIATED: 1 }, asset_types: { APPLICATION: 1, LOAD_BALANCER: 1 },
        assets: [],
      }],
      meaning: "per usage state: capability is not use",
      limits: ["counts come from the catalogue"],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Catalogue")).click();
  await waitFor(() => expect(screen.getByText("2 asset record(s)")).toBeInTheDocument());
  expect(screen.getByText("STALE")).toBeInTheDocument();
  expect(screen.getByText(/never deleted/)).toBeInTheDocument();
  expect(screen.getByText(/1 active/)).toBeInTheDocument();
  expect(screen.getByText("AES-256-GCM")).toBeInTheDocument();
  expect(screen.getByText(/capability never counts as use/)).toBeInTheDocument();
  expect(screen.getByText("8 current fact(s)")).toBeInTheDocument();
  expect(screen.getByText("1 superseded")).toBeInTheDocument();
});

it("shows a fact as a window that closed, not a value that was overwritten", async () => {
  mockFetch({
    [TWIN]: overview(),
    [CATALOG]: {
      schema: "cryptoscan.estate-catalog/1", assets: 1,
      assets_by_type: { APPLICATION: 1 }, assets_by_lifecycle: { ACTIVE: 1 },
      note: "the catalogue is what has been observed",
    },
    [`${HISTORY}/summary`]: {
      schema: "cryptoscan.estate-observations/1",
      evidence: { total: 2, active: 2, stale: 0, collectors: ["linux-static"], by_type: { CONFIGURED: 2 } },
      observations: { total: 4, current: 3, historical: 1, assets: 1, changed_facts: 1, disputed_facts: 1 },
      disputes: [{ asset_id: "asset:api", fact_type: "relationship:USES_HSM" }],
      meaning: "the twin remembers every value it has asserted",
    },
    [`${CATALOG}/assets`]: {
      count: 1,
      note: "",
      assets: [{
        asset_id: "asset:api", asset_type: "APPLICATION", name: "Payment API",
        environment: "production", owner: "Payments", location: null, source: null,
        identity: {}, attributes: {}, evidence_ids: ["ev-1"], evidence_count: 1,
        lifecycle_state: "ACTIVE" as const, first_seen_at: "2026-10-20T00:00:00Z",
        last_seen_at: "2026-10-27T00:00:00Z", observation_count: 4, is_estate_state: true as const,
      }],
    },
    [`${CATALOG}/assets/asset%3Aapi`]: {
      asset: {
        asset_id: "asset:api", asset_type: "APPLICATION", name: "Payment API",
        environment: "production", owner: "Payments", location: null, source: null,
        identity: {}, attributes: {}, evidence_ids: ["ev-1"], evidence_count: 1,
        lifecycle_state: "ACTIVE", first_seen_at: "2026-10-20T00:00:00Z",
        last_seen_at: "2026-10-27T00:00:00Z", observation_count: 4, is_estate_state: true,
      },
      crypto: [], relationships: [], unresolved_candidates: [],
      evidence: [], counts: { evidence: 1, relationships: 0, unresolved: 0, crypto: 0 },
    },
    [`${HISTORY}/assets/asset%3Aapi`]: {
      schema: "cryptoscan.estate-observations/1", asset_id: "asset:api",
      fact_count: 1, fact_types: ["attribute:region"], conflicted_facts: [],
      meaning: "a fact is a value with a window",
      facts: [{
        fact_type: "attribute:region", provenance: "ASSET", state: "CURRENT" as const,
        current_values: ["me-west-1"],
        timeline: [
          { observation_id: "obs-1", value: "me-central-1", value_kind: "text",
            state: "HISTORICAL" as const, evidence_id: "ev-1", evidence_type: "CONFIGURED",
            layer: "APPLICATION", first_seen_at: "2026-10-20T00:00:00Z",
            last_seen_at: "2026-10-24T00:00:00Z", observation_count: 3 },
          { observation_id: "obs-2", value: "me-west-1", value_kind: "text",
            state: "CURRENT" as const, evidence_id: "ev-1", evidence_type: "CONFIGURED",
            layer: "APPLICATION", first_seen_at: "2026-10-24T00:00:00Z",
            last_seen_at: "2026-10-27T00:00:00Z", observation_count: 1 },
        ],
      }],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Catalogue")).click();
  await waitFor(() => expect(screen.getByText("3 current fact(s)")).toBeInTheDocument());
  expect(screen.getByText("1 superseded")).toBeInTheDocument();
  expect(screen.getByText("1 disputed fact(s) — nothing chosen")).toBeInTheDocument();
  await waitFor(() => screen.getByRole("button", { name: /Payment API/ }).click());
  await waitFor(() => expect(screen.getByText(/FACT HISTORY · 1 fact/)).toBeInTheDocument());
  expect(screen.getByText("me-west-1")).toBeInTheDocument();
  expect(screen.getByText(/was me-central-1 until 2026-10-24/)).toBeInTheDocument();
});

it("draws the estate hierarchy only where evidence puts something", async () => {
  mockFetch({
    [TWIN]: overview(),
    [PLACEMENT]: {
      schema: "x", model: "cryptoscan.estate-placement/2",
      levels: ["BANK", "REGION", "DATA_CENTER", "CLOUD_ENVIRONMENT", "ENVIRONMENT", "BUSINESS_SYSTEM"],
      levels_observed: ["BANK", "REGION", "ENVIRONMENT", "BUSINESS_SYSTEM"],
      levels_unobserved: ["DATA_CENTER", "CLOUD_ENVIRONMENT"],
      bank: "Synthetic Bank",
      environments: [], regions: [{ name: "me-central-1", assets: 2, by_type: {}, environments: [] }],
      data_centers: [], cloud_environments: [],
      unassigned: [{ level: "REGION", assets: 4, reason: "no evidence asserts a region for these assets" }],
      business_systems: [], unplaced: [], unplaced_count: 0, placeable: 2, note: "",
    },
  });
  render(<DigitalTwinPanel />);
  await waitFor(() => expect(screen.getByText(/HIERARCHY · BANK → REGION/)).toBeInTheDocument());
  expect(screen.getByText(/region me-central-1 · 2 asset/)).toBeInTheDocument();
  expect(screen.getByText(/4 asset\(s\) with no region in any evidence/)).toBeInTheDocument();
  expect(screen.getByText(/not observed at all: DATA_CENTER, CLOUD_ENVIRONMENT/)).toBeInTheDocument();
});

it("draws the organisation chart, with a department that has no parent left parentless", async () => {
  mockFetch({
    [TWIN]: overview(),
    [PLACEMENT]: {
      schema: "x", model: "cryptoscan.estate-placement/3",
      levels: ["BANK", "ORGANIZATION", "DEPARTMENT", "REGION", "DATA_CENTER",
        "CLOUD_ENVIRONMENT", "ENVIRONMENT", "BUSINESS_SYSTEM"],
      levels_observed: ["BANK", "ORGANIZATION", "DEPARTMENT", "ENVIRONMENT"],
      levels_unobserved: ["REGION", "DATA_CENTER", "CLOUD_ENVIRONMENT", "BUSINESS_SYSTEM"],
      bank: "Synthetic Bank",
      organizations: [{ name: "Bank UAE PJSC", assets: 2, by_type: {},
        departments: [{ name: "Payments", assets: 2 }], environments: [] }],
      departments: [
        { name: "Payments", organization: "Bank UAE PJSC", assets: 2, by_type: {},
          owners: [{ name: "Payments Team", assets: 2 }], environments: [] },
        { name: "Retail", organization: null, assets: 1, by_type: {}, owners: [], environments: [] },
      ],
      environments: [], regions: [], data_centers: [], cloud_environments: [],
      unassigned: [{ level: "ORGANIZATION", assets: 1, reason: "no evidence names the legal entity" }],
      business_systems: [], unplaced: [], unplaced_count: 0, placeable: 3, note: "",
    },
  });
  render(<DigitalTwinPanel />);
  await waitFor(() => expect(screen.getByText(/HIERARCHY · BANK → ORGANIZATION/)).toBeInTheDocument());
  expect(screen.getByText(/entity Bank UAE PJSC · 2 asset/)).toBeInTheDocument();
  expect(screen.getByText(/department Payments \(Bank UAE PJSC\) · 2 asset/)).toBeInTheDocument();
  // a department whose evidence asserts no organisation is drawn without one
  expect(screen.getByText(/department Retail · 1 asset/)).toBeInTheDocument();
  expect(screen.getByText(/1 asset\(s\) with no organization in any evidence/)).toBeInTheDocument();
});

it("searches the durable record and keeps capability away from use", async () => {
  mockFetch({
    [TWIN]: overview(),
    [SEARCH_KEY]: {
      schema: "cryptoscan.estate-search/1", query: "RSA-2048",
      kinds: ["ASSETS", "CRYPTO", "RELATIONSHIPS", "EVIDENCE", "FACTS", "CHANGES"],
      matched: 3,
      by_kind: { ASSETS: 1, CRYPTO: 2, RELATIONSHIPS: 0, EVIDENCE: 0, FACTS: 0, CHANGES: 0 },
      groups: {
        ASSETS: { count: 1, hits: [{ kind: "ASSET", id: "application:api", label: "Payment API (APPLICATION)" }] },
        CRYPTO: {
          count: 2, hits: [], usage_states: { OBSERVED: 1, SUPPORTED: 1 },
          note: "grouped per usage_state: SUPPORTED is capability, OBSERVED is a runtime operation. They are not added together, because capability is not use",
        },
        RELATIONSHIPS: { count: 0, hits: [] },
        EVIDENCE: { count: 0, hits: [] },
        FACTS: { count: 0, hits: [] },
        CHANGES: { count: 0, hits: [] },
      },
      meaning: "one search across the recorded estate",
      limits: ["search reads the durable catalogue"],
    },
  });
  render(<DigitalTwinPanel />);
  const box = await screen.findByLabelText("search the twin");
  fireEvent.change(box, { target: { value: "RSA-2048" } });
  fireEvent.click(screen.getByText("Search the record"));

  await waitFor(() => expect(screen.getByText("record · RSA-2048")).toBeInTheDocument());
  expect(screen.getByText("3 match(es) across 6 kind(s)")).toBeInTheDocument();
  expect(screen.getByText("1 assets")).toBeInTheDocument();
  expect(screen.getByText("2 crypto")).toBeInTheDocument();
  expect(screen.getByText(/OBSERVED 1 · SUPPORTED 1/)).toBeInTheDocument();
  expect(screen.getByText(/capability is not use/)).toBeInTheDocument();
  expect(screen.getByText("Payment API (APPLICATION)")).toBeInTheDocument();
});

it("says a record search that found nothing is a gap in observation, not a denial", async () => {
  mockFetch({
    [TWIN]: overview(),
    [SEARCH_KEY]: {
      schema: "cryptoscan.estate-search/1", query: "Kyber-1024",
      kinds: ["ASSETS", "CRYPTO"], matched: 0, by_kind: { ASSETS: 0, CRYPTO: 0 },
      groups: { ASSETS: { count: 0, hits: [] }, CRYPTO: { count: 0, hits: [] } },
      meaning: "one search across the recorded estate", limits: [],
    },
  });
  render(<DigitalTwinPanel />);
  fireEvent.change(await screen.findByLabelText("search the twin"), { target: { value: "Kyber-1024" } });
  fireEvent.click(screen.getByText("Search the record"));

  await waitFor(() => expect(screen.getByText("record · Kyber-1024")).toBeInTheDocument());
  expect(screen.getByText(/not proof the bank has none of it/)).toBeInTheDocument();
});

it("shows a held conflict with its evidence and refuses to resolve it", async () => {
  mockFetch({
    [TWIN]: overview(),
    "/api/v1/estate/evidence/twin/conflicts": {
      schema: "cryptoscan.estate-conflicts/1",
      count: 2, real_count: 1, explained_count: 1, assets_affected: 1,
      by_classification: { REAL: 1, EXPLAINED: 1, UNKNOWN: 0 },
      meaning: "a conflict is reported, never resolved",
      limits: ["an empty list is not 'no conflicts in the bank'"],
      conflicts: [
        {
          asset_id: "application:api", asset_name: "Payment API", field: "engine",
          values: [
            { value: "OpenSSL 3.0.13", source: "sbom", layer: "PLATFORM" },
            { value: "OpenSSL 3.0.11", source: "container", layer: "PLATFORM" },
          ],
          classification: "REAL" as const,
          reason: "two observations on the same plane (PLATFORM) disagree; one of them is wrong",
          status: "CONFLICT", source_of_conflict: "observation",
          next_action: "decide which observation is correct", seen_by: ["observation"],
        },
        {
          asset_id: "application:api", asset_name: "Payment API", field: "algorithm",
          values: [
            { value: "AES-128", layer: "PLATFORM" },
            { value: "AES-256-GCM", layer: "APPLICATION" },
          ],
          classification: "EXPLAINED" as const,
          reason: "the values come from different planes (APPLICATION, PLATFORM) and can both be true at once",
          status: "CONFLICT", source_of_conflict: "observation",
          next_action: "nothing needs fixing", seen_by: ["observation"],
        },
      ],
    },
  });
  render(<DigitalTwinPanel />);

  await waitFor(() => expect(screen.getByText("CONFLICTS · 1 real, 1 explained")).toBeInTheDocument());
  expect(screen.getByText("REAL")).toBeInTheDocument();
  expect(screen.getByText(/OpenSSL 3.0.13 vs OpenSSL 3.0.11/)).toBeInTheDocument();
  expect(screen.getByText(/one of them is wrong/)).toBeInTheDocument();
  expect(screen.getByText("EXPLAINED")).toBeInTheDocument();
  expect(screen.getByText(/can both be true at once/)).toBeInTheDocument();
  expect(screen.getByText(/nothing here is resolved for you/)).toBeInTheDocument();
});

it("draws the loop with its break named rather than every box the same colour", async () => {
  const phases = [
    ["DISCOVER", "CONNECTED", "has anything looked at the estate?"],
    ["IDENTIFY", "CONNECTED", "does an asset keep its identity?"],
    ["MODEL", "CONNECTED", "is there one canonical model?"],
    ["MONITOR", "NOT_CONNECTED", "does discovery re-run without a human?"],
    ["REMEDIATE", "NOT_CONNECTED", "does the twin open work?"],
    ["RE_DISCOVER", "PARTIAL", "does a new observation prove the fix?"],
  ].map(([phase, status, question]) => ({
    phase, status, question,
    detail: `${phase} detail`,
    backed_by: "somewhere.ts",
    observed: {},
    gap: status === "CONNECTED" ? null : `${phase} gap is named`,
  }));

  mockFetch({
    [TWIN]: overview(),
    "/api/v1/estate/evidence/twin/lifecycle": {
      schema: "cryptoscan.estate-lifecycle/1", phases,
      by_status: { CONNECTED: 3, PARTIAL: 1, NOT_CONNECTED: 2, NOT_STARTED: 0 },
      loop_closed: false, first_break: "MONITOR",
      phase_order: phases.map((entry) => entry.phase),
      meaning: "the loop is reported as closed only when every phase is CONNECTED",
      limits: ["NOT_STARTED is not a defect"],
    },
  });
  render(<DigitalTwinPanel />);

  fireEvent.click(await screen.findByRole("button", { name: "Loop" }));

  await waitFor(() => expect(screen.getByText("BREAKS AT MONITOR")).toBeInTheDocument());
  expect(screen.getByText("3 connected")).toBeInTheDocument();
  expect(screen.getByText("1 partial")).toBeInTheDocument();
  expect(screen.getByText("2 not connected")).toBeInTheDocument();
  expect(screen.getAllByText("NOT_CONNECTED").length).toBe(2);
  expect(screen.getByText(/REMEDIATE gap is named/)).toBeInTheDocument();
  expect(screen.getByText(/only when every phase is CONNECTED/)).toBeInTheDocument();
});

it("keeps weak capability apart from weak use, and an invented algorithm apart from a real one", async () => {
  mockFetch({
    [TWIN]: overview(),
    "/api/v1/estate/evidence/twin/intel": {
      schema: "cryptoscan.estate-crypto-intel/1",
      artifacts_examined: 9,
      weak: {
        count: 3, in_use_count: 2, capability_only_count: 1,
        by_status: { DISALLOWED: 2, DEPRECATED: 1 },
        by_asset_type: { APPLICATION: 1, LOAD_BALANCER: 1 },
        assets: [],
        capability_only: [
          { asset_id: "library:ossl", asset_name: "OpenSSL", algorithm: "DES",
            status: "DISALLOWED", note: "Capability is not use" },
        ],
        entries: [
          { asset_id: "application:legacy", asset_name: "Legacy Ledger", algorithm: "DES",
            status: "DISALLOWED", layer: "APPLICATION", usage_state: "OBSERVED",
            in_use: true, verdict_source: "algorithm_registry" },
          { asset_id: "library:ossl", asset_name: "OpenSSL", algorithm: "DES",
            status: "DISALLOWED", layer: "APPLICATION", usage_state: "SUPPORTED",
            in_use: false, verdict_source: "algorithm_registry" },
        ],
        meaning: "counted separately by whether the estate is recorded as doing it",
      },
      unknown: {
        count: 2, unrecognised_count: 1, mislabelled_count: 1, assets: [],
        entries: [
          { asset_id: "application:api", asset_name: "Payment API", algorithm: "OpenSSL 3.0.13",
            status: "UNKNOWN", usage_state: "SUPPORTED", in_use: false, reading: "NOT_AN_ALGORITHM" },
          { asset_id: "application:legacy", asset_name: "Legacy Ledger", algorithm: "cryptomodule-v2",
            status: "UNKNOWN", usage_state: "OBSERVED", in_use: true, reading: "UNRECOGNIZED" },
        ],
        meaning: "unknown, never compliant",
      },
      pqc: {
        vulnerable_artifacts: 2, vulnerable_in_use: 1,
        by_algorithm: { RSA: 1, ECDSA: 1 }, by_asset_type: { HSM: 1, APPLICATION: 1 },
        affected_assets: [],
        vendor_bound_blockers: [{ asset_id: "hsm:04", asset_name: "HSM-04", asset_type: "HSM",
          algorithms: ["RSA-2048"], in_use: true }],
        vendor_bound_blocker_count: 1, pqc_algorithms_present: [],
        pending_migration_count: 1,
        meaning: "not a readiness score: readiness is which of these need the vendor to ship a version",
      },
      next_action: "start with the in-use weak algorithms",
      limits: ["a verdict comes from this product's algorithm registry"],
    },
    "/api/v1/estate/evidence/twin/trust-paths": {
      schema: "cryptoscan.estate-trust-paths/1",
      count: 2, rooted_count: 1, broken_count: 1, unjudged_count: 0, longest_chain: 3,
      by_status: { ROOTED: 1, SELF_SIGNED: 0, BROKEN: 1, CYCLE: 0, UNKNOWN_ISSUER: 0 },
      chains: [
        { asset_id: "cert:api", asset_name: "api.example.com", asset_type: "CERTIFICATE",
          status: "ROOTED", length: 3,
          chain: [
            { asset_id: "cert:api", asset_name: "api.example.com", present: true, evidence_ids: [] },
            { asset_id: "ca:issuing", asset_name: "Bank Issuing CA", present: true, evidence_ids: ["ev-cert"] },
            { asset_id: "ca:root", asset_name: "Bank Root CA", present: true, evidence_ids: ["ev-cert"] },
          ],
          reason: "a root as far as this evidence goes" },
        { asset_id: "cert:legacy", asset_name: "legacy.example.com", asset_type: "CERTIFICATE",
          status: "BROKEN", length: 2,
          chain: [
            { asset_id: "cert:legacy", asset_name: "legacy.example.com", present: true, evidence_ids: [] },
            { asset_id: "vendor:thales", asset_name: "Thales", asset_type: "VENDOR", present: true, evidence_ids: ["ev-old"] },
          ],
          reason: "Thales is named as the issuer, but it is a VENDOR, which cannot vouch for a certificate" },
      ],
      meaning: "where the walk stops, not a judgement",
      limits: ["no signature is verified", "no expiry is checked"],
    },
  });
  render(<DigitalTwinPanel />);

  fireEvent.click(await screen.findByRole("button", { name: "Intelligence" }));

  await waitFor(() => expect(screen.getByText("2 weak in use")).toBeInTheDocument());
  expect(screen.getByText("1 capability only")).toBeInTheDocument();
  expect(screen.getByText("IN USE")).toBeInTheDocument();
  expect(screen.getByText("CAPABILITY")).toBeInTheDocument();
  expect(screen.getByText(/a version string, not an algorithm/)).toBeInTheDocument();
  expect(screen.getByText(/unrecognised/)).toBeInTheDocument();
  expect(screen.getByText(/blocker: HSM-04/)).toBeInTheDocument();
  expect(screen.getByText(/start with the in-use weak algorithms/)).toBeInTheDocument();
  expect(screen.getByText("TRUST PATHS")).toBeInTheDocument();
  expect(screen.getByText("1 rooted")).toBeInTheDocument();
  expect(screen.getByText("1 broken")).toBeInTheDocument();
  expect(screen.getByText(/cannot vouch for a certificate/)).toBeInTheDocument();
  expect(screen.getByText(/no signature is verified/)).toBeInTheDocument();
});

it("answers why the twin believes an edge, from the edge itself", async () => {
  /* §9's most important action: select a relationship and open its evidence.
     The selected edge must answer with a collector, a source, a timestamp and a
     hash — or with the reason the edge was refused. */
  mockFetch({
    [TWIN]: overview(),
    [`${TWIN}/search`]: {
      schema: "cryptoscan.estate-twin-search/1", query: "AES-256", status: "MATCHED",
      counts: { assets: 1, artifacts: 1 },
      by_asset_type: { APPLICATION: 1 }, by_artifact_asset_type: {}, by_usage_state: {},
      assets: [{ asset_id: "asset:api", name: "Payment API", type: "APPLICATION" }],
      artifacts: [{ asset_id: "asset:api", algorithm: "AES-256-GCM", usage_state: "OBSERVED" }],
      note: "",
    },
    [`${TWIN}/assets/asset%3Aapi`]: {
      schema: "cryptoscan.estate-asset-view/1", model: "cryptoscan.estate-asset-view/1",
      projection_id: "a".repeat(32), estate: "Synthetic Bank",
      asset: {
        asset_id: "asset:api", type: "APPLICATION", name: "Payment API",
        environment: "production", owner: "Payments", location: null,
      },
      attributes: {},
      placement: { environment: "production", location: null, owner: "Payments", placed: true },
      crypto: {
        artifacts: [], by_usage_state: { SUPPORTED: 0, CONFIGURED: 0, NEGOTIATED: 0, OBSERVED: 0 },
        observed: [], capability_only: [], note: "capability is not use",
      },
      relationships: {
        outgoing: [{
          predicate: "uses_hsm", direction: "out" as const, asset_id: "asset:hsm",
          name: "HSM-03", type: "HSM", basis: "PKCS11_REFERENCE", confidence: "HIGH",
          evidence_ids: ["ev-4"],
        }],
        incoming: [], dependencies: [], count: 1,
      },
      evidence: {
        count: 1, by_type: { CONFIGURED: 1 }, strongest: "CONFIGURED",
        records: [{
          evidence_id: "ev-4", evidence_type: "CONFIGURED", collector: "linux-static",
          source: "/etc/payment/pkcs11.conf", observed_at: "2026-11-01T09:00:00Z",
          hash: "b".repeat(64),
        }],
      },
      unknown: { unresolved_relationships: [], conflicts: [], no_evidence: false },
      neighbourhood: { depth: 3, reached: 0, assets: [], truncated: false },
    },
    [`${TWIN}/why`]: {
      schema: "cryptoscan.estate-twin-why/1", status: "ESTABLISHED",
      matches: [{
        edge: {
          subject: "asset:api", subject_name: "Payment API", predicate: "uses_hsm",
          object: "asset:hsm", object_name: "HSM-03", basis: "PKCS11_REFERENCE",
          confidence: "HIGH",
        },
        answer: "uses hsm is established by PKCS11_REFERENCE evidence at HIGH confidence",
        evidence: [{
          evidence_id: "ev-4", evidence_type: "CONFIGURED", collector: "linux-static",
          source: "/etc/payment/pkcs11.conf", observed_at: "2026-11-01T09:00:00Z",
          confidence: "HIGH", hash: "b".repeat(64),
        }],
      }],
      note: "every edge answers why with a collector, a source, a timestamp and a hash",
    },
  });
  render(<DigitalTwinPanel />);
  fireEvent.click(await screen.findByText("Search twin"));
  await waitFor(() => expect(screen.getByText("Payment API")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Payment API"));
  await waitFor(() => expect(screen.getByText("RELATIONSHIPS")).toBeInTheDocument());
  fireEvent.click(screen.getByText("uses_hsm"));
  await waitFor(() => expect(
    screen.getByText(/established by PKCS11_REFERENCE evidence at HIGH confidence/),
  ).toBeInTheDocument());
  // the edge's own evidence line, not only the asset-level evidence list
  expect(screen.getAllByText(/linux-static/).length).toBeGreaterThan(1);
  expect(screen.getAllByText(/bbbbbbbbbbbb/).length).toBeGreaterThan(0);
});

it("says the loaded graph is a bounded subgraph, never the estate whole", async () => {
  mockFetch({
    [TWIN]: overview(),
    [GRAPH]: {
      schema: "cryptoscan.estate-graph-export/1", projection_id: "c".repeat(32), generated_at: null,
      counts: { asset_nodes: 90, evidence_nodes: 8, placement_nodes: 2, relationships: 120, unresolved: 0 },
      nodes: [
        { id: "a", labels: ["Asset"], properties: {} },
        { id: "b", labels: ["Asset"], properties: {} },
        { id: "c", labels: ["Asset"], properties: {} },
      ],
      relationships: [
        { type: "USES", from: "a", to: "b", properties: {} },
        { type: "USES", from: "b", to: "c", properties: {} },
        { type: "USES", from: "c", to: "a", properties: {} },
        { type: "USES", from: "a", to: "c", properties: {} },
      ],
      unresolved: [],
      load_notes: { not_source_of_truth: "the store is a copy", edge_identity: "edges are (from,to,type)" },
      label_coverage: {},
      bounded: true, omitted_nodes: 97, omitted_edges: 117, frontier: ["a", "z"],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Graph export")).click();
  // the disclosure counts what is NOT loaded and names the frontier
  expect(await screen.findByText(/bounded subgraph loaded: 3 of 100 nodes/)).toBeInTheDocument();
  expect(screen.getByText(/97 not loaded/)).toBeInTheDocument();
  expect(screen.getByText(/117 edge\(s\) connect unloaded nodes/)).toBeInTheDocument();
  expect(screen.getByText(/frontier: a, z/)).toBeInTheDocument();
  // the JSON preview is labelled as a preview of the loaded subset
  expect(screen.getByText(/preview shows the first 2 of 3 loaded node\(s\)/)).toBeInTheDocument();
});

it("says the catalogue list is a bounded page when the filter matches more", async () => {
  const row = {
    asset_id: "asset:app:1", asset_type: "APPLICATION", name: "payments-api",
    environment: "production", owner: null, location: null, source: null,
    identity: {}, attributes: {}, evidence_ids: [], evidence_count: 1,
    lifecycle_state: "ACTIVE" as const, first_seen_at: null,
    last_seen_at: null, observation_count: 1,
    is_estate_state: true as const,
  };
  mockFetch({
    [TWIN]: overview(),
    [CATALOG]: {
      schema: "cryptoscan.estate-catalog/1", assets: 120,
      assets_by_type: { APPLICATION: 120 }, assets_by_lifecycle: { ACTIVE: 120 },
      note: "the catalogue is what has been observed",
    },
    [`${CATALOG}/assets`]: {
      count: 120, note: "server-capped page",
      assets: [row, { ...row, asset_id: "asset:app:2", name: "auth-api" }],
    },
  });
  render(<DigitalTwinPanel />);
  (await screen.findByText("Catalogue")).click();
  // the page loaded 2 rows; the catalogue holds 120 for this filter — the UI
  // says so (an uncounted cap reads as complete)
  expect(await screen.findByText(/showing 2 of 120 asset record\(s\) for this filter/)).toBeInTheDocument();
});
