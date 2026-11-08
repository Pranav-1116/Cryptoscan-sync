/* ZELNX Performance Intelligence (docs/performance/01_PRODUCT_SPEC.md, §7):
   the honesty rules are display rules: an unknown tile renders "—" and
   says "unknown, never zero"; bandwidth capacity is never shown as
   throughput; benchmark results always say "never production"; the
   investigation's conclusion never upgrades correlation to causation. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Performance from "./Performance";

const unknownTile = { value: null, unit: "percent", state: "unknown", note: "no delivered telemetry in window — unknown, never zero" };
const tile = (value: number, unit: string) => ({ value, unit, state: "known", derived: false, note: null });

const summary = (over: Record<string, unknown> = {}) => ({
  sample_count: 8, value_count: 6, unknown_count: 2, coverage: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60, ...over,
});

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/performance"]}>
      <Performance />
    </MemoryRouter>,
  );

const selectView = (label: string) => {
  fireEvent.change(screen.getByLabelText("Performance view"), { target: { value: label } });
};

const setTenant = () => {
  fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "tenant_001" } });
};

describe("ZELNX Performance Intelligence (§7)", () => {
  it("renders overview tiles as unknown, never zero", async () => {
    mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile,
        network_throughput_mbps: tile(840, "Mbps"),
        api_p95_latency_ms: tile(42, "ms"),
        requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
    });
    renderPage();
    expect(await screen.findByText("840")).toBeInTheDocument();
    const dashes = await screen.findAllByText("—");
    expect(dashes.length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/unknown, never zero/).length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps bandwidth capacity and observed throughput apart", async () => {
    mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile, network_throughput_mbps: unknownTile,
        api_p95_latency_ms: unknownTile, requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
      "/api/v1/performance/network": {
        bandwidth_capacity_mbps: tile(10000, "Mbps"),
        observed_throughput_mbps: tile(840, "Mbps"),
        rtt_ms: null,
        metrics: {},
        note: "bandwidth capacity and actual throughput are different: capacity is never presented as observed throughput",
      },
    });
    renderPage();
    selectView("network");
    expect(await screen.findByText("10000")).toBeInTheDocument();
    expect(screen.getByText("840")).toBeInTheDocument();
    expect(screen.getAllByText(/different/).length).toBeGreaterThan(0);
  });

  it("shows alerts with proven AND not-proven sections", async () => {
    mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile, network_throughput_mbps: unknownTile,
        api_p95_latency_ms: unknownTile, requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
      "/api/v1/performance/alerts": [{
        metric_name: "db.query_time_ms",
        severity: "CRITICAL",
        severity_factors: { magnitude_pct: 158, samples_over_threshold: 12, evidence_completeness: "complete" },
        proven: ["p95 82 vs baseline 32 = +158% (threshold 25%)"],
        not_proven: ["the cause of the threshold crossing is not proven"],
        supporting_measurements: summary(),
        window_start: "2026-11-08T06:00:00Z",
        window_end: "2026-11-08T07:00:00Z",
      }],
    });
    renderPage();
    selectView("alerts");
    expect(await screen.findByText("db.query_time_ms")).toBeInTheDocument();
    expect(screen.getAllByText("Proven").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Not proven").length).toBeGreaterThan(0);
    expect(screen.getByText(/the cause of the threshold crossing is not proven/)).toBeInTheDocument();
    expect(screen.getByText(/severity computed from factors/)).toBeInTheDocument();
  });

  it("labels capacity forecasts forecast, not fact", async () => {
    mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile, network_throughput_mbps: unknownTile,
        api_p95_latency_ms: unknownTile, requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
      "/api/v1/performance/baselines": [],
      "/api/v1/performance/capacity": [{
        metric_name: "storage.used_bytes",
        status: "forecast",
        method: "linear-extrapolation",
        sample_count: 5,
        growth_per_second: 0.1,
        estimated_seconds_to_exhaustion: 51600,
        disclaimer: "forecast, not fact — a linear extrapolation of the window's growth rate, not a promise about the future",
        note: "",
      }],
    });
    renderPage();
    selectView("capacity");
    expect(await screen.findByText(/Estimated exhaustion in 51600 s/)).toBeInTheDocument();
    expect(screen.getByText(/forecast, not fact/)).toBeInTheDocument();
  });

  it("records benchmarks as controlled benchmark performance, never production", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile, network_throughput_mbps: unknownTile,
        api_p95_latency_ms: unknownTile, requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
      "/api/v1/performance/benchmarks": {
        runs: [{
          run_id: "bench-abc123", measurement_kind: "controlled_benchmark",
          approved: true, method: { algorithm: "Ed25519" },
          results: [{ operation: "sign", mean_ms: 0.06, min_ms: 0.05, max_ms: 0.09, samples: 50 }],
          executed_at: "2026-11-08T07:00:00Z",
        }],
        note: "every run is controlled benchmark performance — never production traffic performance (docs/performance/01_PRODUCT_SPEC.md §2.F)",
      },
    });
    renderPage();
    setTenant();
    selectView("benchmarks");
    expect(await screen.findByText("bench-abc123")).toBeInTheDocument();
    expect(screen.getByText(/controlled_benchmark/)).toBeInTheDocument();
    expect(screen.getByText(/never production traffic performance/)).toBeInTheDocument();

    fireEvent.click(screen.getByText("Run approved benchmark"));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    const post = fetchSpy.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "POST");
    expect(post).toBeTruthy();
  });

  it("never upgrades a time correlation to causation", async () => {
    mockFetch({
      "/api/v1/performance/overview": {
        storage_usage_pct: unknownTile, network_throughput_mbps: unknownTile,
        api_p95_latency_ms: unknownTile, requests_per_sec: unknownTile,
        note: "tiles show delivered values only; an unknown tile is unknown, never zero",
      },
      "/api/v1/performance/reports": {
        investigation: "performance regression investigation",
        conclusion: "Correlation detected — causation unproven",
        change: { time: "10:30", description: "TLS configuration changed", evidence_ids: ["ev-001"] },
        before: summary({ p95: 35 }), after: summary({ p95: 82 }), difference_p95: 47,
        affected_assets: ["asset_gateway_001"],
        evidence: {
          proven: ["the recorded change carries 1 evidence reference(s)"],
          not_proven: [
            "A time correlation alone does not prove that the change caused the latency increase",
            "Other possible causes still need investigation",
          ],
        },
        note: "illustrative or real, this report never upgrades correlation to causation",
      },
    });
    renderPage();
    setTenant();
    selectView("reports");
    fireEvent.click(screen.getByText("Investigate"));
    expect(await screen.findByText("Correlation detected — causation unproven")).toBeInTheDocument();
    expect(screen.getByText(/A time correlation alone does not prove/)).toBeInTheDocument();
    expect(screen.getByText(/Other possible causes still need investigation/)).toBeInTheDocument();
  });

  it("names failed reads instead of printing zeros", async () => {
    mockFetch({});
    renderPage();
    expect(await screen.findByText("Read failed")).toBeInTheDocument();
    expect(screen.getByText(/never prints zeros/)).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
});
