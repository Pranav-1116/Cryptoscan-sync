/**
 * Application Performance (docs/performance/03_UI_SPEC.md §3): the ten
 * metrics, per-service and per-endpoint performance, and the eight
 * capabilities each as measured or as a named gap. Traces and waterfalls
 * stay named gaps — collection is governed by controlled attributes and
 * redaction; payment credentials, authorization tokens and sensitive
 * request payloads are never collected. Unknowns render "—", never zeros.
 */
import React, { useState } from "react";
import { Panel } from "./ui.jsx";
import type { PerformanceAppWorkspace, PerformanceTile } from "../lib/api";

const APP_TABS = [
  { key: "services", label: "Service-level performance" },
  { key: "endpoints", label: "API endpoint performance" },
  { key: "tracing", label: "Distributed transaction tracing" },
  { key: "slow", label: "Slow transactions & dependencies" },
  { key: "regression", label: "Regression & SLA/SLO" },
] as const;

type AppTab = (typeof APP_TABS)[number]["key"];

const CAPABILITY_LABELS: Record<string, string> = {
  service_level: "Service-level performance",
  api_endpoints: "API endpoint performance",
  distributed_tracing: "Distributed transaction tracing",
  request_waterfall: "Request waterfall visualization",
  slow_transactions: "Slow transaction detection",
  dependency_latency: "Service dependency latency",
  regression: "Performance regression comparison",
  slo: "SLA/SLO tracking",
};

/** One honest metric card: an undelivered metric is unknown, never zero. */
export function MetricCard({ tile, label }: { tile: PerformanceTile | undefined; label: string }) {
  const unknown = !tile || tile.state !== "known" || tile.value === null;
  return (
    <div style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: 8, borderTop: `2px solid ${unknown ? "var(--slate, #64748b)" : "var(--green, #3ecf8e)"}` }}
      title={tile?.note ?? "no delivered telemetry in window — unknown, never zero"}>
      <div style={{ fontSize: 11, opacity: 0.75 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700 }}>
        <span>{unknown ? "—" : String(tile?.value)}</span>
        {!unknown && <span style={{ fontSize: 11, fontWeight: 400 }}> {tile?.unit}</span>}
      </div>
      <div style={{ fontSize: 10, opacity: 0.7 }}>{unknown ? "unknown, never zero" : tile?.state ?? "known"}</div>
    </div>
  );
}

export default function AppPerfWorkspace({ data }: { data: PerformanceAppWorkspace | null | undefined }) {
  const [tab, setTab] = useState<AppTab>("services");
  const metrics = data?.metrics ?? {};
  const capabilities = data?.capabilities ?? {};
  const services = data?.services ?? [];
  const endpoints = data?.endpoints ?? [];
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 14 }}>
        <MetricCard tile={metrics.requests_per_sec} label="RPS" />
        <MetricCard tile={metrics.throughput_bytes} label="Throughput" />
        <MetricCard tile={metrics.latency_p50_ms} label="p50 latency" />
        <MetricCard tile={metrics.latency_p95_ms} label="p95 latency" />
        <MetricCard tile={metrics.latency_p99_ms} label="p99 latency" />
        <MetricCard tile={metrics.error_rate_pct} label="Error rate" />
        <MetricCard tile={metrics.timeout_rate_pct} label="Timeout rate" />
        <MetricCard tile={metrics.availability_pct} label="Availability" />
        <MetricCard tile={metrics.queue_depth} label="Queue depth" />
        <MetricCard tile={metrics.saturation} label="Saturation" />
      </div>

      <Panel title="Capabilities" sub="each capability is measured or a named gap — never drawn as used when it is not collected">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 10 }}>
          {Object.keys(CAPABILITY_LABELS).map((key) => {
            const cap = capabilities[key];
            const measured = cap?.state === "measured";
            return (
              <div key={key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{CAPABILITY_LABELS[key]}</span>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, whiteSpace: "nowrap",
                    border: `1px solid ${measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
                    color: measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
                  }}>{measured ? "measured" : "not collected"}</span>
                </div>
                <div style={{ fontSize: 10.5, opacity: 0.7, marginTop: 4 }}>{cap?.basis ?? ""}</div>
              </div>
            );
          })}
        </div>
      </Panel>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "14px 0 12px" }} role="tablist" aria-label="Application performance tabs">
        {APP_TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            style={{
              padding: "6px 12px", borderRadius: 8, cursor: "pointer", fontSize: 11.5,
              border: `1px solid ${tab === t.key ? "var(--accent)" : "var(--line-strong)"}`,
              background: tab === t.key ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent",
              color: tab === t.key ? "var(--accent)" : "var(--dim)",
            }}>{t.label}</button>
        ))}
      </div>

      {tab === "services" && (
        <Panel title="Service-level performance" sub="per-service percentiles as delivered">
          {!services.length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No service telemetry is stored in this window — a missing service is a collection gap, not a healthy service."}>{"No service telemetry is stored in this window"}</span>
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 6 }}>Service</th>
                  <th style={{ textAlign: "left", padding: 6 }}>p50</th>
                  <th style={{ textAlign: "left", padding: 6 }}>p95</th>
                  <th style={{ textAlign: "left", padding: 6 }}>p99</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Errors</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Timeouts</th>
                  <th style={{ textAlign: "left", padding: 6 }}>RPS</th>
                </tr>
              </thead>
              <tbody>
                {services.map((r) => (
                  <tr key={r.service}>
                    <td style={{ padding: 6 }}>{r.service}</td>
                    <td style={{ padding: 6 }}>{r.p50_latency_ms ?? "—"}</td>
                    <td style={{ padding: 6 }}>{r.p95_latency_ms ?? "—"}</td>
                    <td style={{ padding: 6 }}>{r.p99_latency_ms ?? "—"}</td>
                    <td style={{ padding: 6 }}>{r.error_rate_pct ?? "—"}</td>
                    <td style={{ padding: 6 }}>{r.timeout_rate_pct ?? "—"}</td>
                    <td style={{ padding: 6 }}>{r.requests_per_sec ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === "endpoints" && (
        <Panel title="API endpoint performance" sub="controlled label keys only — request payloads are never read">
          {!endpoints.length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No endpoint-attributed telemetry is stored in this window — unlabelled requests are not attributed to endpoints."}>{"No endpoint-attributed telemetry is stored in this window"}</span>
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 6 }}>Service</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Endpoint</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Metric</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Latest</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Observed</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((e, i) => (
                  <tr key={`${e.service}-${e.endpoint}-${e.metric_name}-${i}`}>
                    <td style={{ padding: 6 }}>{e.service}</td>
                    <td style={{ padding: 6 }}>{e.endpoint}</td>
                    <td style={{ padding: 6 }}>{e.metric_name}</td>
                    <td style={{ padding: 6 }}>{e.latest ?? "—"} {e.unit}</td>
                    <td style={{ padding: 6 }}>{e.observed_at.slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === "tracing" && (
        <Panel title="Distributed transaction tracing" sub="a named gap where no authorized collector exists">
          <div style={{ fontSize: 12, opacity: 0.8 }}>
            {capabilities.distributed_tracing?.basis ?? ""}
          </div>
          <div style={{ fontSize: 12, opacity: 0.8, marginTop: 10 }}>
            {capabilities.request_waterfall?.basis ?? ""}
          </div>
        </Panel>
      )}

      {tab === "slow" && (
        <Panel title="Slow transactions & service dependency latency" sub="named gaps — a link is not a latency">
          <div style={{ fontSize: 12, opacity: 0.8 }}>{capabilities.slow_transactions?.basis ?? ""}</div>
          <div style={{ fontSize: 12, opacity: 0.8, marginTop: 10 }}>{capabilities.dependency_latency?.basis ?? ""}</div>
        </Panel>
      )}

      {tab === "regression" && (
        <Panel title="Regression & SLA/SLO" sub="comparisons and compliance as delivered">
          {data?.regression ? (
            <table style={{ width: "100%", fontSize: 12 }}>
              <tbody>
                <tr><td style={{ padding: 6 }}>performance.regression_ms</td><td style={{ padding: 6 }}>{data.regression.coverage ?? "—"}</td>
                  <td style={{ padding: 6 }}>p95 {data.regression.p95 ?? "—"}</td><td style={{ padding: 6 }}>max {data.regression.maximum ?? "—"}</td></tr>
              </tbody>
            </table>
          ) : (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No regression measurements are stored in this window — absence of regression telemetry is not proof of no regression."}>{"No regression measurements are stored in this window"}</span>
            </div>
          )}
          <div style={{ fontSize: 12, opacity: 0.8, marginTop: 10 }}>{capabilities.slo?.basis ?? ""}</div>
        </Panel>
      )}

      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
    </div>
  );
}
