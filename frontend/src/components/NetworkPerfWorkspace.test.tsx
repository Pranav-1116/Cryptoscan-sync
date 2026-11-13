/* Network Performance (docs/performance/03_UI_SPEC.md §5): bandwidth
   capacity and observed throughput are different measurements; the
   twelve metrics render undelivered families as unknown, never zero;
   network telemetry does not automatically reveal the negotiated TLS
   cipher suite — that requires an appropriate authorized endpoint or
   protocol observation. */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import NetworkPerfWorkspace from "./NetworkPerfWorkspace";
import type { PerformanceNetwork, PerformanceTile } from "../lib/api";

const tile = (value: number, unit: string): PerformanceTile => ({ value, unit, state: "known" });

const full: PerformanceNetwork = {
  bandwidth_capacity_mbps: tile(10000, "Mbps"),
  observed_throughput_mbps: tile(840, "Mbps"),
  rtt_ms: {
    sample_count: 8, value_count: 6, unknown_count: 2,
    coverage: "partial — 6/8 delivered",
    average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
  },
  jitter_ms: tile(2.5, "ms"),
  packet_loss_pct: tile(0.1, "percent"),
  retransmissions: tile(12, "count"),
  dns_resolution_ms: tile(18, "ms"),
  connection_establish_ms: tile(34, "ms"),
  tcp_connections: tile(420, "count"),
  interface_errors: { value: null, unit: "count", state: "unknown", note: "no delivered telemetry in window — unknown, never zero" },
  tunnel_health: tile(1, "state"),
  tls_handshake_ms: tile(41, "ms"),
  metrics: {},
  cipher_suite_note:
    "network telemetry can establish that a connection exists or measure its " +
    "performance — it does not automatically reveal the negotiated TLS cipher " +
    "suite; that requires an appropriate authorized endpoint or protocol observation",
  note: "bandwidth capacity and actual throughput are different: capacity is never presented as observed throughput",
};

describe("Network Performance workspace (§5)", () => {
  it("keeps capacity and observed throughput apart and names gaps", () => {
    render(<NetworkPerfWorkspace data={full} />);
    expect(screen.getByText("10000")).toBeInTheDocument();
    expect(screen.getByText("840")).toBeInTheDocument();
    expect(screen.getAllByText(/different/).length).toBeGreaterThan(0);
    // the not-collected strip names the gap — never a zero
    expect(screen.getByText(/not collected in this window: Interface errors, Load-balancer response/)).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("never claims network telemetry reveals the cipher suite", () => {
    render(<NetworkPerfWorkspace data={full} />);
    expect(screen.getByText(/does not automatically reveal the negotiated TLS cipher suite/)).toBeInTheDocument();
    expect(screen.getByText(/authorized endpoint or protocol observation/)).toBeInTheDocument();
  });

  it("renders an old-shape payload as unknown cards, never fabricated values", () => {
    const legacy = {
      bandwidth_capacity_mbps: tile(10000, "Mbps"),
      observed_throughput_mbps: tile(840, "Mbps"),
      rtt_ms: null,
      metrics: {},
      note: "bandwidth capacity and actual throughput are different: capacity is never presented as observed throughput",
    } as unknown as PerformanceNetwork;
    render(<NetworkPerfWorkspace data={legacy} />);
    expect(screen.getByText("10000")).toBeInTheDocument();
    expect(screen.getAllByText(/unknown, never zero/).length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText(/No round-trip telemetry is stored/)).toBeInTheDocument();
    // even without a server note, the honesty contract renders
    expect(screen.getByText(/does not automatically reveal the negotiated TLS cipher suite/)).toBeInTheDocument();
  });
});
