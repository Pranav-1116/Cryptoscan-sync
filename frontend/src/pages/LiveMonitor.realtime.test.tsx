import React from "react";
import { act, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setActiveTenantId } from "../lib/api";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import LiveMonitor from "./LiveMonitor";
import { withTitles } from "../test/withTitles";

const path = "/api/v1/estate/evidence/realtime";
const idle = {
  schema: "cryptoscan.estate-realtime/1", at: "2026-10-28T16:00:00Z",
  verdict: "IDLE_NO_SCHEDULES", reason: "daemon alive; nothing is being re-scanned",
  next_action: "select an authorized persisted-evidence plane",
  daemon: { heartbeat: { worker: "local", cycles: 2, runs: 0, failures: 0 },
    liveness: { state: "LIVE", age_seconds: 2, meaning: "cycle completed", next_action: null } },
  schedules: { total: 0, enabled: 0, next_due_at: null, seconds_until_due: null, leases: [] },
  runs: { recent: [], last_finished_at: null, last_run_age_seconds: null },
};

describe("live monitor collection authority", () => {
  it("shows a live daemon as idle, not evidence of continuous coverage", async () => {
    mockFetch({ [path]: idle });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const status = await screen.findByRole("status", { name: "Estate collection status" });
    expect(status).toHaveTextContent("Scheduled collection: IDLE_NO_SCHEDULES");
    expect(status).toHaveTextContent("0 enabled schedule(s)");
    expect(status).toHaveTextContent("last completed run none");
    expect(status).toHaveTextContent("reprojects stored observations");
    expect(withTitles(status)).toContain("not proof that a collector acquired new evidence");
  });

  it("quotes an incomplete scheduled run as degraded, not healthy", async () => {
    mockFetch({ [path]: { ...idle, verdict: "DEGRADED",
      reason: "a scheduled projection reported an error or incomplete coverage",
      schedules: { ...idle.schedules, enabled: 1 },
      runs: { ...idle.runs, last_finished_at: "2026-10-28T16:00:00Z" } } });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const status = await screen.findByRole("status", { name: "Estate collection status" });
    expect(status).toHaveTextContent("Scheduled collection: DEGRADED");
    expect(status).toHaveTextContent("incomplete coverage");
    expect(status).toHaveTextContent("1 enabled schedule(s)");
  });

  it("does not replace a refused status read with a green coverage claim", async () => {
    mockFetch({ [path]: () => new Response(JSON.stringify({ detail: "denied" }), { status: 403 }) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const status = await screen.findByRole("status", { name: "Estate collection status" });
    expect(status).toHaveTextContent("Scheduled collection: UNKNOWN");
    expect(status).toHaveTextContent("API connectivity is not collection coverage");
  });

  it("discards the prior estate verdict on tenant switch", async () => {
    setActiveTenantId("a");
    mockFetch({ [path]: (_url: string, init?: RequestInit) =>
      new Headers(init?.headers).get("X-Tenant-ID") === "a" ? idle : {
        ...idle, verdict: "NOT_RUNNING", reason: "no daemon has run this estate",
        daemon: { ...idle.daemon, liveness: { ...idle.daemon.liveness, state: "NEVER_STARTED" } },
      },
    });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    expect(await screen.findByRole("status", { name: "Estate collection status" })).toHaveTextContent("IDLE_NO_SCHEDULES");
    act(() => setActiveTenantId("b"));
    expect(screen.queryByText(/Scheduled collection: IDLE_NO_SCHEDULES/)).toBeNull();
    expect(await screen.findByRole("status", { name: "Estate collection status" })).toHaveTextContent("NOT_RUNNING");
  });
});
