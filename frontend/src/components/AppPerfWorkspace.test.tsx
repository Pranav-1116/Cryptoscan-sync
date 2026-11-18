/* Application Performance (docs/performance/03_UI_SPEC.md §3): the ten
   metrics with unknowns as unknown, never zero; the eight capabilities as
   measured or named gaps; trace collection governed by controlled
   attributes and redaction — payment credentials, authorization tokens
   and sensitive request payloads are never collected. */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AppPerfWorkspace from "./AppPerfWorkspace";
import type { PerformanceAppWorkspace, PerformanceTile } from "../lib/api";

const tile = (value: number, unit: string): PerformanceTile => ({ value, unit, state: "known" });
const unknown: PerformanceTile = { value: null, unit: "count", state: "unknown", note: "no delivered telemetry in window — unknown, never zero" };

const summary = {
  sample_count: 8, value_count: 6, unknown_count: 2,
  coverage: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
};

const data: PerformanceAppWorkspace = {
  metrics: {
    requests_per_sec: tile(520, "requests/sec"),
    throughput_bytes: unknown,
    latency_p50_ms: tile(28, "ms"),
    latency_p95_ms: tile(210, "ms"),
    latency_p99_ms: tile(460, "ms"),
    error_rate_pct: tile(0.6, "percent"),
    timeout_rate_pct: unknown,
    availability_pct: tile(99.95, "percent"),
    queue_depth: unknown,
    saturation: unknown,
  },
  services: [
    {
      service: "svc-payments", p50_latency_ms: 28, p95_latency_ms: 210, p99_latency_ms: null,
      error_rate_pct: 0.6, timeout_rate_pct: null, requests_per_sec: 520,
      samples: 12, last_observed: "2026-10-16T10:00:00+00:00",
    },
  ],
  endpoints: [
    { service: "svc-payments", endpoint: "POST /v1/payments", metric_name: "api.latency_p95_ms", latest: 210, unit: "ms", observed_at: "2026-10-16T10:00:00+00:00" },
  ],
  capabilities: {
    service_level: { state: "measured", basis: "per-service percentiles computed from delivered samples" },
    api_endpoints: { state: "measured", basis: "endpoint rows project controlled label keys only" },
    distributed_tracing: {
      state: "not_collected",
      basis: "distributed tracing has no authorized collector — trace collection is governed by controlled attributes and redaction; payment credentials, authorization tokens and sensitive request payloads are never collected",
    },
    request_waterfall: { state: "not_collected", basis: "a request waterfall is drawn from traces — no traces are stored, so no waterfall is drawn" },
    slow_transactions: { state: "not_collected", basis: "transaction records have no authorized collector — a slow transaction cannot be named without stored transactions" },
    dependency_latency: { state: "not_collected", basis: "dependency links carry no latency measurements in this window — a link is not a latency" },
    regression: { state: "not_collected", basis: "no regression measurements are stored in the window" },
    slo: { state: "not_collected", basis: "no SLO compliance measurements are stored in the window — policies are tracked separately and a policy is not proof of compliance" },
  },
  regression: null,
  note: "percentiles are computed from delivered samples in the window; missing telemetry is unknown, never zero",
};

const renderWs = (over: Partial<PerformanceAppWorkspace> = {}) =>
  render(<AppPerfWorkspace data={{ ...data, ...over }} />);

describe("Application Performance workspace (§3)", () => {
  it("renders the ten metrics with unknowns as unknown, never zero", () => {
    renderWs();
    for (const label of ["RPS", "Throughput", "p50 latency", "p95 latency", "p99 latency",
      "Error rate", "Timeout rate", "Availability", "Queue depth", "Saturation"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.getAllByText("520").length).toBeGreaterThanOrEqual(1);
    // queue depth has no collector — the card is unknown, never a zero
    expect(screen.getAllByText(/unknown, never zero/).length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps the eight capabilities measured-or-gap apart", () => {
    renderWs();
    expect(screen.getAllByText("Distributed transaction tracing").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Request waterfall visualization").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Slow transaction detection").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Service dependency latency").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("measured").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("not collected").length).toBeGreaterThanOrEqual(4);
  });

  it("names the trace redaction contract instead of drawing traces", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Distributed transaction tracing" }));
    expect(screen.getAllByText(/payment credentials, authorization tokens and sensitive request payloads are never collected/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/no traces are stored, so no waterfall is drawn/).length).toBeGreaterThanOrEqual(1);
  });

  it("shows service and endpoint rows with unread columns unknown", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Service-level performance" }));
    expect(screen.getAllByText("svc-payments").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("210").length).toBeGreaterThanOrEqual(1);
    fireEvent.click(screen.getByRole("tab", { name: "API endpoint performance" }));
    expect(screen.getAllByText("POST /v1/payments").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/request payloads are never read/)).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("keeps empty reads as gaps, not clean results", () => {
    renderWs({ services: [], endpoints: [], regression: null });
    fireEvent.click(screen.getByRole("tab", { name: "Service-level performance" }));
    expect(screen.getByTitle(/collection gap, not a healthy service/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "API endpoint performance" }));
    expect(screen.getByTitle(/unlabelled requests are not attributed to endpoints/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Regression & SLA/SLO" }));
    expect(screen.getByTitle(/not proof of no regression/)).toBeInTheDocument();
  });
});
