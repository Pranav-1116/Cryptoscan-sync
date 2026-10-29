/* Live estate screen: draw the connection and the changes, never the optimism. */
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import LiveEstate from "./LiveEstate";

const statusPath = "/api/v1/ingestion/live/status";
const patternsPath = "/api/v1/estate/evidence/threat/patterns";

const status = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.live-ingest/1",
  connection: {
    schema: "cryptoscan.live-estate/1",
    state: "LIVE",
    last_observation: "2026-10-29T12:00:00+00:00",
    seconds_since: 30,
    interval_seconds: 300,
    stale_after_seconds: 600,
    meaning: "an observation arrived within the expected interval",
  },
  twin: {
    state: "OBSERVED",
    run_id: "run-1",
    projection_id: "abcdef0123456789",
    assets: 1248,
    evidence: 9817,
    relationships: 4021,
    coverage: { state: "PARTIAL" },
    unknown: {},
    recorded_at: "2026-10-29T12:00:00+00:00",
  },
  boms: {
    projection_id: "abcdef0123456789",
    counts: { SBOM: 4892, CBOM: 736, HBOM: 42, NBOM: 8219, VBOM: 61, TECHBOM: 1104 },
    kinds: {},
  },
  changes_today: {
    count: 184,
    by_severity: { CRITICAL: 3, WARNING: 41, INFO: 140 },
    by_verdict: { ESTATE_CHANGED: 184 },
    unacknowledged: 12,
    note: "counts of stored change events detected today (UTC), not of open risk",
  },
  trust: { signatures_required: false, trust_keys_configured: 0, findings: ["NO_TRUSTED_COLLECTOR_KEY: nothing can be authenticated here"] },
  note: "the twin is the live state",
  limits: ["NO_CHANGE means the normalised state hash did not move"],
  ...overrides,
});

const patterns = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.attack-patterns/1",
  window_seconds: 3600,
  window: { from: "2026-10-29T11:00:00+00:00", to: "2026-10-29T12:00:00+00:00" },
  events_considered: 3,
  signals_considered: 4,
  undated_signals: 0,
  patterns: [
    {
      pattern_id: "PAT-abc123",
      name: "TRUST_PATH_MUTATION",
      level: 2,
      level_name: "SUSPICIOUS_ACTIVITY",
      level_meaning: "several related changes in one window",
      headline: "trust path mutation: payments-api",
      why: "a cryptographic artefact and the graph edge that reached it moved together",
      subjects: ["payments-api"],
      change_kinds: ["CRYPTO_ADDED", "RELATIONSHIP_ESTABLISHED"],
      signals: [],
      first_seen: "2026-10-29T11:20:00+00:00",
      last_seen: "2026-10-29T11:21:00+00:00",
      not_proven: ["a pattern is not proof of compromise"],
      next_action: "walk the affected asset's relationships in the twin",
    },
  ],
  count: 1,
  by_level: { "0": 0, "1": 0, "2": 1, "3": 0, "4": 0 },
  highest_level: 2,
  level_definitions: {
    "0": { name: "NORMAL_CHANGE", meaning: "" },
    "1": { name: "UNEXPECTED_CHANGE", meaning: "" },
    "2": { name: "SUSPICIOUS_ACTIVITY", meaning: "" },
    "3": { name: "SECURITY_INCIDENT", meaning: "never set by this engine" },
    "4": { name: "CORRELATED_PATTERN", meaning: "" },
  },
  summary: { total: 1, by_level: { "2": 1 }, level_names: {}, note: "" },
  note: "an empty result means nothing in this window met a correlation rule",
  limits: ["only changes that were stored can be correlated"],
  ...overrides,
});

describe("live estate", () => {
  it("draws the connection as measured and offers the six current BOMs", async () => {
    mockFetch({ [statusPath]: status(), [patternsPath]: patterns() });
    renderWithProviders(<LiveEstate />);

    expect((await screen.findAllByText("LIVE")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/stale after/i)).toBeInTheDocument();
    expect(screen.getByText("CBOM")).toBeInTheDocument();
    expect(screen.getByText("736")).toBeInTheDocument();
    expect(screen.getAllByRole("button").length).toBeGreaterThanOrEqual(12);
    expect(await screen.findByText("PAT-abc123")).toBeInTheDocument();
    expect(screen.getByText(/L3 SECURITY_INCIDENT is never assigned/)).toBeInTheDocument();
  });

  it("never turns a missing observation into an empty estate or a zero metric", async () => {
    mockFetch({
      [statusPath]: status({
        connection: {
          ...status().connection,
          state: "NEVER_CONNECTED",
          last_observation: null,
          seconds_since: null,
          meaning: "no observation has been accepted for this estate",
        },
        twin: { state: "NOT_OBSERVED", reason: "no observation has been accepted for this estate" },
        boms: { projection_id: null, kinds: {}, reason: "nothing to project" },
        changes_today: { count: 0, by_severity: {}, by_verdict: {}, unacknowledged: 0, note: "" },
      }),
      [patternsPath]: patterns({ patterns: [], count: 0, highest_level: 0, by_level: { "2": 0 } }),
    });
    renderWithProviders(<LiveEstate />);

    expect((await screen.findAllByText("NEVER_CONNECTED")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/no age to draw/i)).toBeInTheDocument();
    expect(screen.getByText(/no BOM to download/i)).toBeInTheDocument();
    expect(screen.queryByText("CycloneDX")).toBeNull();
    expect(screen.getByText(/not a statement that the estate is safe/i)).toBeInTheDocument();
  });

  it("a failed read is an alert, and the screen shows no stale figures", async () => {
    mockFetch({
      [statusPath]: new Response("nope", { status: 503 }),
      [patternsPath]: new Response("nope", { status: 503 }),
    });
    renderWithProviders(<LiveEstate />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/live state unavailable/i);
    expect(screen.getByText(/No connection read/i)).toBeInTheDocument();
    expect(screen.queryByText("1,248")).toBeNull();
  });

  it("states that an unconfigured trust key authenticates nothing", async () => {
    mockFetch({ [statusPath]: status(), [patternsPath]: patterns() });
    renderWithProviders(<LiveEstate />);

    expect(await screen.findByText(/NO_TRUSTED_COLLECTOR_KEY/)).toBeInTheDocument();
    expect(screen.getByText(/What this screen cannot say/i)).toBeInTheDocument();
  });
});
