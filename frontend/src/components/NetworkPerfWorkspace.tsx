/**
 * Network Performance (docs/performance/03_UI_SPEC.md §5): the twelve
 * measurements with bandwidth capacity and observed throughput kept
 * apart, and the TLS honesty — network telemetry can establish that a
 * connection exists or measure its performance; it does not automatically
 * reveal the negotiated TLS cipher suite, which requires an appropriate
 * authorized endpoint or protocol observation. Unknowns render "—",
 * never zeros.
 */
import React from "react";
import { Panel } from "./ui.jsx";
import { MetricCard } from "./AppPerfWorkspace";
import { SummaryTable } from "./InfraWorkspace";
import type { PerformanceNetwork, PerformanceTile } from "../lib/api";

const CIPHER_FALLBACK =
  "network telemetry can establish that a connection exists or measure its " +
  "performance — it does not automatically reveal the negotiated TLS cipher " +
  "suite; that requires an appropriate authorized endpoint or protocol observation";

const GAP_CARDS: Array<{ tile: PerformanceTile | undefined; label: string }> = [];

export default function NetworkPerfWorkspace({ data }: { data: PerformanceNetwork | null | undefined }) {
  const missing: string[] = [];
  const card = (tile: PerformanceTile | undefined, label: string) => {
    if (!tile || tile.state !== "known" || tile.value === null) missing.push(label);
    return <MetricCard key={label} tile={tile} label={label} />;
  };
  return (
    <div>
      <Panel title="Bandwidth and throughput" sub="capacity and observed throughput are different measurements">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
          <MetricCard tile={data?.bandwidth_capacity_mbps} label="Bandwidth capacity" />
          <MetricCard tile={data?.observed_throughput_mbps} label="Observed throughput" />
        </div>
        <div style={{ fontSize: 11, opacity: 0.75, marginTop: 8 }}>{data?.note ?? ""}</div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, margin: "14px 0" }}>
        {card(data?.jitter_ms, "Jitter")}
        {card(data?.packet_loss_pct, "Packet loss")}
        {card(data?.retransmissions, "Retransmissions")}
        {card(data?.dns_resolution_ms, "DNS resolution")}
        {card(data?.connection_establish_ms, "Connection establishment")}
        {card(data?.tcp_connections, "TCP connection state")}
        {card(data?.interface_errors, "Interface errors")}
        {card(data?.tunnel_health, "Tunnel health")}
        {card(data?.tls_handshake_ms, "TLS handshake latency")}
        {card(data?.load_balancer_response_ms, "Load-balancer response")}
      </div>

      {missing.length > 0 && (
        <div style={{ fontSize: 11.5, opacity: 0.75, marginBottom: 12 }}>
          not collected in this window: {missing.join(", ")} — unknown, never zero
        </div>
      )}

      <Panel title="Round-trip time" sub="percentiles over delivered samples">
        {data?.rtt_ms ? (
          <SummaryTable metrics={{ "network.rtt_ms": data.rtt_ms }} />
        ) : (
          <div style={{ fontSize: 12, opacity: 0.75 }}>
            No round-trip telemetry is stored in this window — unknown, never zero.
          </div>
        )}
      </Panel>

      <Panel title="Negotiated TLS cipher suite" sub="what network telemetry can and cannot establish">
        <div style={{ fontSize: 12, opacity: 0.85 }}>{data?.cipher_suite_note ?? CIPHER_FALLBACK}</div>
      </Panel>

      {Object.keys(data?.metrics ?? {}).length > 0 && (
        <div style={{ marginTop: 12 }}>
          <SummaryTable metrics={data?.metrics ?? {}} />
        </div>
      )}
    </div>
  );
}
