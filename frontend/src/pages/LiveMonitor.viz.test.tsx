import React from "react";
import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setActiveTenantId } from "../lib/api";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import LiveMonitor from "./LiveMonitor";

/* The live monitor is a measurement screen. These tests pin the two things that
 * can silently turn it into a decoration: numbers that were not read, and an
 * absence rendered as a zero. */

const realtime = "/api/v1/estate/evidence/realtime";
const environment = "/api/v1/live/environment";

const emptyEstate = {
  schema: "cryptoscan.estate-realtime/1",
  at: "2026-10-29T06:00:00Z",
  verdict: "NOT_RUNNING",
  reason: "no estate daemon has ever written a heartbeat",
  next_action: "start one — cryptoscan serve",
  daemon: {
    heartbeat: null,
    liveness: { state: "NEVER_STARTED", age_seconds: null, meaning: "nothing is running", next_action: null },
  },
  schedules: { total: 0, enabled: 0, next_due_at: null, seconds_until_due: null, leases: [] },
  runs: { recent: [], last_finished_at: null, last_run_age_seconds: null },
  meaning: "no collection",
};

const emptyEnvironment = {
  source: "live",
  domains: { network: 0, hardware: 0, vendor: 0, crypto: 0, certificate: 0, application: 0, total: 0 },
  graph: { node_count: 0, edge_count: 0, by_kind: {}, backend: "memory" },
  events: { events: [], latest_sequence: 0, oldest_sequence: 0, next_cursor: "", has_more: false, retention_gap: false },
  scan: null,
  runner: null,
};

describe("live monitor visualisations", () => {
  it("renders an absence as an absence, not as zero, when nothing has been read", async () => {
    setActiveTenantId("a");
    mockFetch({ [realtime]: emptyEstate, [environment]: emptyEnvironment });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    expect(await screen.findByText(/Total estate assets per read — no samples/)).toBeInTheDocument();
    expect(await screen.findByText("Nothing to compose")).toBeInTheDocument();
    // The environment read succeeds but reports zero for all eight domains: the
    // rows are measurements of 0, and the panel says so instead of pretending
    // the data has not arrived.
    expect(await screen.findByText(/All eight domains measured 0 in this read/)).toBeInTheDocument();
    expect(screen.queryByText("No domain returned a count")).toBeNull();
    expect(await screen.findByText("No delta yet")).toBeInTheDocument();
  });

  it("plots the counts the API returned and labels them with their source", async () => {
    setActiveTenantId("a");
    mockFetch({
      [realtime]: emptyEstate,
      [environment]: {
        ...emptyEnvironment,
        domains: { network: 12, hardware: 4, vendor: 2, crypto: 7, certificate: 3, application: 1, total: 29 },
        graph: { node_count: 42, edge_count: 61, by_kind: { asset: 29, service: 13 }, backend: "postgres" },
      },
    });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    // Estate composition is drawn from the read; the legend carries the numbers.
    await waitFor(() => expect(screen.getAllByText("29").length).toBeGreaterThan(0));
    expect(screen.getByText(/asset\(s\) attributed to a domain/)).toHaveTextContent("29");
    expect(screen.getByText("Graph nodes")).toBeInTheDocument();
    expect(screen.getAllByText("42").length).toBeGreaterThan(0);
    // Domain rows name what they measured instead of showing a bare percentage.
    expect(screen.getAllByTitle("Network").length).toBeGreaterThan(0);
    expect(screen.queryByText("No domain returned a count")).toBeNull();
  });

  it("keeps a failed read visible as a gap and never prints a stale figure as current", async () => {
    setActiveTenantId("a");
    mockFetch({ [realtime]: emptyEstate, [environment]: () => new Response(JSON.stringify({ detail: "denied" }), { status: 403 }) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    // The header says the API is unreachable rather than showing a green engine state.
    expect(await screen.findByText("API UNREACHABLE")).toBeInTheDocument();
    expect(screen.getByText(/Total estate assets per read — no samples/)).toBeInTheDocument();
  });
});
