import { describe, expect, it } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { RealtimeProvider } from "../lib/realtime";
import { mockFetch } from "../test/setup";
import CommandCenter from "./CommandCenter";

const scope = { platform: "CryptoScan", schema_version: 1, covered_areas: [], non_goals: [] };
const scan = { running: false, last_run_at: null, periodic: { enabled: false, interval_seconds: 900 }, scanners: {}, ok_count: 0, failed_count: 0 };
const inventory = { generated_at: null, host: null, counts: { hardware_devices: 0, network_assets: 0, libraries: 0, certificates: 0, processes: 0 }, hardware: [], network: [], libraries: [], certificates: [], processes: [] };
const bom = { generated_at: null, cbom: { components: [], counts: { total: 0, quantum_vulnerable: 0 } }, hbom: { components: [], counts: { total: 0 } } };
const drift = { baseline: false, changes: [], change_count: 0 };

function serve(routes: Record<string, unknown> = {}) {
  mockFetch({
    "/api/v1/platform/scope": scope,
    "/api/v1/live-scan/inventory": inventory,
    "/api/v1/live-scan/status": scan,
    "/api/v1/live-scan/bom": bom,
    "/api/v1/live-scan/drift": drift,
    "/api/v1/stats/summary": { total_scans: 0, total_findings: 0, compliant: 0, non_compliant: 0, open_drift: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 }, coverage: { with_cbom: 0, coverage_pct: 0 } },
    "/api/v1/live-scan/alerts": { counts: { CRITICAL: 0, HIGH: 0 }, alerts: [], total: 0 },
    "/api/v1/events/recent": { events: [] },
    ...routes,
  });
}

async function mount() {
  await act(async () => {
    render(<RealtimeProvider><MemoryRouter><CommandCenter /></MemoryRouter></RealtimeProvider>);
  });
  await waitFor(() => expect(screen.getByRole("link", { name: /Crypto assets/ })).toBeInTheDocument());
}

function tile(label: RegExp) {
  return screen.getByRole("link", { name: label });
}

describe("CommandCenter source truth", () => {
  it("does not substitute zero or healthy/readiness claims when all endpoints are offline", async () => {
    await mount();
    await screen.findByText(/CONTROL PLANE: OFFLINE/);
    expect(tile(/Host hardware/)).toHaveTextContent("Not observed");
    expect(tile(/Crypto assets/)).toHaveTextContent("Not measured");
    expect(tile(/CBOM components/)).toHaveTextContent("Not observed");
    expect(tile(/Open critical drift/)).toHaveTextContent("Not available");
    expect(tile(/Changes vs prior scan/)).toHaveTextContent("Not observed");
    expect(screen.getByText("PQC READINESS: NOT MEASURED")).toBeInTheDocument();
    expect(screen.queryByText(/ALL SCANNERS NOMINAL|critical findings|events \/ sec.*0/i)).not.toBeInTheDocument();
    expect(document.querySelector(".bar")).toBeNull();
  });

  it("distinguishes a live empty response with no scan baseline from measured zeros", async () => {
    serve();
    await mount();
    await screen.findByRole("button", { name: /Scan this host now/ });
    expect(tile(/Host hardware/)).toHaveTextContent("Not observed");
    expect(tile(/CBOM components/)).toHaveTextContent("Not observed");
    expect(tile(/Changes vs prior scan/)).toHaveTextContent("no comparison baseline");
    expect(tile(/Scan cycle/)).toHaveTextContent("no completed cycle");
    expect(screen.getByText("PQC READINESS: NOT MEASURED")).toBeInTheDocument();
    expect(screen.getByText("No comparison baseline yet")).toBeInTheDocument();
    expect(screen.queryByText(/PQC 0% OBSERVED|^24h window$|critical findings/i)).not.toBeInTheDocument();
  });

  it("keeps missing fields unavailable even when neighboring fields and coverage are returned", async () => {
    serve({
      "/api/v1/stats/summary": { total_scans: 9, total_findings: 2, open_drift: { CRITICAL: 3 }, coverage: { coverage_pct: 72 } },
      "/api/v1/live-scan/inventory": { generated_at: "2026-10-12T11:00:00Z", counts: { hardware_devices: 2 } },
      "/api/v1/live-scan/bom": { generated_at: "2026-10-12T11:00:00Z", cbom: { counts: {} }, hbom: { counts: {} } },
      "/api/v1/live-scan/drift": { baseline: true, ts: "2026-10-12T11:00:00Z", changes: [] },
      "/api/v1/live-scan/status": { ...scan, last_run_at: "2026-10-12T11:00:00Z", ok_count: undefined, failed_count: undefined },
    });
    await mount();
    await waitFor(() => expect(tile(/Open critical drift/)).toHaveTextContent("3"));
    expect(tile(/Host hardware/)).toHaveTextContent("2");
    expect(tile(/CBOM components/)).toHaveTextContent("Not available");
    expect(tile(/Changes vs prior scan/)).toHaveTextContent("Not available");
    expect(tile(/Crypto assets/)).toHaveTextContent("Not measured");
    expect(screen.getByText("LAST SCAN CYCLE: RESULT UNAVAILABLE")).toBeInTheDocument();
    expect(screen.queryByText(/72%|PQC 72%|critical findings/i)).not.toBeInTheDocument();
    expect(within(screen.getByText("events / sec").closest(".kpi")!).getByText("Not measured")).toBeInTheDocument();
  });

  it("renders only correctly scoped values from populated responses", async () => {
    serve({
      "/api/v1/stats/summary": { total_scans: 11, total_findings: 19, compliant: 6, non_compliant: 7, open_drift: { CRITICAL: 4, HIGH: 5, MEDIUM: 1, INFO: 2 }, coverage: { systems: 8, with_cbom: 5, coverage_pct: 62.5 } },
      "/api/v1/live-scan/inventory": { ...inventory, generated_at: "2026-10-12T11:00:00Z", counts: { hardware_devices: 2, network_assets: 3, libraries: 5, certificates: 4, processes: 7 } },
      "/api/v1/live-scan/bom": { ...bom, generated_at: "2026-10-12T11:00:00Z", cbom: { components: [], counts: { total: 12, quantum_vulnerable: 2 } } },
      "/api/v1/live-scan/drift": { baseline: true, ts: "2026-10-12T11:00:00Z", previous_ts: "2026-10-11T11:00:00Z", change_count: 3, changes: [{ severity: "HIGH", scanner: "network", kind: "added", title: "New endpoint", detail: "observed" }] },
      "/api/v1/live-scan/status": { ...scan, last_run_at: "2026-10-12T11:00:00Z", ok_count: 2, failed_count: 1 },
      "/api/v1/events/recent": { events: Array.from({ length: 8 }, (_, i) => ({ ts: "2026-10-12T11:00:00Z", type: `event.${i}`, payload: {} })) },
    });
    await mount();
    await waitFor(() => expect(tile(/CBOM components/)).toHaveTextContent("12"));
    expect(tile(/Host hardware/)).toHaveTextContent("2");
    expect(tile(/Crypto assets/)).toHaveTextContent("Not measured");
    expect(tile(/Open critical drift/)).toHaveTextContent("4");
    expect(tile(/Changes vs prior scan/)).toHaveTextContent("3");
    expect(screen.getByText("LAST SCAN CYCLE: 1 FAILED")).toBeInTheDocument();
    expect(within(screen.getByText("CBOM components flagged vulnerable").closest(".kpi")!).getByText("2")).toBeInTheDocument();
    expect(within(screen.getByText("systems with CBOM").closest(".kpi")!).getByText("5")).toBeInTheDocument();
    expect(within(screen.getByText("events / sec").closest(".kpi")!).getByText("Not measured")).toBeInTheDocument();
    expect(screen.queryByText(/total assets|critical findings|evidence health|PQC 62/i)).not.toBeInTheDocument();
    expect(tile(/Crypto assets/)).toHaveAttribute("href", "/cbom");
  });

  it("does not call an unscanned domain zero observed just because another scanner ran", async () => {
    serve({
      "/api/v1/live-scan/inventory": { ...inventory, generated_at: "2026-10-12T11:00:00Z" },
      "/api/v1/live-scan/status": { ...scan, last_run_at: "2026-10-12T11:00:00Z", ok_count: 1, scanners: { runtime: { ok: true, summary: {} } } },
    });
    await mount();
    await waitFor(() => expect(tile(/Host hardware/)).toHaveTextContent("snapshot"));
    expect(tile(/Host hardware/)).toHaveTextContent("Not observed");
    expect(within(screen.getByText("libraries").closest(".kpi")!).getByText("0")).toBeInTheDocument();
    expect(within(screen.getByText("network assets").closest(".kpi")!).getByText("Not observed")).toBeInTheDocument();
  });

  it("shows a measured zero only after a completed snapshot or comparison", async () => {
    serve({
      "/api/v1/live-scan/inventory": { ...inventory, generated_at: "2026-10-12T11:00:00Z" },
      "/api/v1/live-scan/bom": { ...bom, generated_at: "2026-10-12T11:00:00Z" },
      "/api/v1/live-scan/drift": { baseline: true, ts: "2026-10-12T11:00:00Z", previous_ts: "2026-10-11T11:00:00Z", changes: [], change_count: 0 },
      "/api/v1/live-scan/status": { ...scan, last_run_at: "2026-10-12T11:00:00Z", ok_count: 2, scanners: { hardware: { ok: true, summary: {} }, runtime: { ok: true, summary: {} } } },
    });
    await mount();
    await waitFor(() => expect(tile(/Host hardware/)).toHaveTextContent("snapshot"));
    expect(within(tile(/Host hardware/)).getByText("0")).toBeInTheDocument();
    expect(within(tile(/CBOM components/)).getByText("0")).toBeInTheDocument();
    expect(within(tile(/Changes vs prior scan/)).getByText("0")).toBeInTheDocument();
    expect(tile(/Crypto assets/)).toHaveTextContent("Not measured");
    expect(screen.getByText("LAST SCAN CYCLE: 0 FAILED (BLOCKED/UNCONFIGURED EXCLUDED)")).toBeInTheDocument();
    expect(screen.queryByText(/ALL SCANNERS NOMINAL/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Scan this host now/ })).not.toBeInTheDocument();
  });
});

/* The console's charts are only worth having if they refuse to draw what was
 * not measured. These pin the difference between a measured zero, a missing
 * field, and a metric the platform does not produce at all. */
describe("CommandCenter measurement drawing", () => {
  it("splits findings only from the counts the summary returned", async () => {
    serve({
      "/api/v1/stats/summary": { total_scans: 4, total_findings: 13, compliant: 6, non_compliant: 7, open_drift: {}, coverage: {} },
    });
    await mount();
    expect(await screen.findByText(/Split of the 13 persisted findings/)).toBeInTheDocument();
  });

  it("says a split is unavailable rather than drawing an empty or zero bar", async () => {
    serve({ "/api/v1/stats/summary": { total_scans: 4, total_findings: 13, open_drift: {}, coverage: {} } });
    await mount();
    expect(await screen.findByText("No PASS/FAIL verdict recorded")).toBeInTheDocument();
    expect(screen.queryByText(/Split of the/)).toBeNull();
  });

  it("marks readiness metrics the platform does not produce as unmeasured", async () => {
    serve();
    await mount();
    // Three readiness figures have no measurement behind them; each renders an
    // explicitly unmeasured line, never a 0.
    expect(screen.getByText("PQC readiness")).toBeInTheDocument();
    expect(screen.getAllByText("not measured").length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("draws a scanner tile from its reported result and elapsed time", async () => {
    serve({
      "/api/v1/live-scan/status": { ...scan, last_run_at: "2026-10-12T11:00:00Z", ok_count: 1, failed_count: 1,
        scanners: { hardware: { ok: true, elapsed_s: 2.5, summary: {} }, runtime: { ok: false, elapsed_s: 9, error: "collector denied" } } },
    });
    await mount();
    expect(await screen.findByText("hardware")).toBeInTheDocument();
    expect(screen.getByText("2.5s")).toBeInTheDocument();
    expect(screen.getByText("9s")).toBeInTheDocument();
    expect(screen.getByText("collector denied")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
  });

  it("draws certificate posture from the certificate centre only", async () => {
    serve({
      "/api/v1/live-scan/inventory": { ...inventory, generated_at: "2026-10-12T11:00:00Z",
        counts: { hardware_devices: 0, network_assets: 0, libraries: 0, certificates: 9, processes: 0 },
        cert_center: { expired: 2, expiring30: 1, weak_algorithm: 0, unknown_owner: 4, total: 9 } },
    });
    await mount();
    expect(await screen.findByText("expiring ≤30d")).toBeInTheDocument();
    expect(screen.getByText(/of 9 certificate\(s\) read/)).toBeInTheDocument();
  });

  it("does not draw certificate columns when the snapshot carries no certificate centre", async () => {
    serve({ "/api/v1/live-scan/inventory": { ...inventory, generated_at: "2026-10-12T11:00:00Z" } });
    await mount();
    expect(await screen.findByText("Certificate posture not observed")).toBeInTheDocument();
    expect(screen.queryByText("expiring ≤30d")).toBeNull();
  });

  it("classifies CBOM components without calling the result PQC readiness", async () => {
    serve({
      "/api/v1/live-scan/bom": { ...bom, generated_at: "2026-10-12T11:00:00Z",
        cbom: { counts: { total: 3, quantum_vulnerable: 2 }, components: [
          { type: "algorithm", name: "RSA-2048", source: "runtime", quantum_status: "QUANTUM_VULNERABLE" },
          { type: "algorithm", name: "RSA-4096", source: "runtime", quantum_status: "QUANTUM_VULNERABLE" },
          { type: "algorithm", name: "aes-256-gcm", source: "runtime", quantum_status: "QUANTUM_SAFE" },
        ] } },
    });
    await mount();
    expect(await screen.findByText(/Classification of the components in the latest local CBOM/)).toBeInTheDocument();
    expect(screen.getByText("quantum vulnerable")).toBeInTheDocument();
    expect(screen.getByText("quantum safe")).toBeInTheDocument();
    // The classification is not a readiness claim.
    expect(screen.getByText("PQC READINESS: NOT MEASURED")).toBeInTheDocument();
    expect(screen.queryByText(/PQC 100|PQC 66/)).toBeNull();
  });
});
