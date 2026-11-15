import React, { useCallback, useEffect, useState } from "react";
import {
  PerformanceServiceRow, activeTenantId, ensureActiveTenant } from "../lib/api";
import { Badge, Panel, PageHead } from "../components/ui.jsx";
import InfraWorkspace from "../components/InfraWorkspace";
import AppPerfWorkspace from "../components/AppPerfWorkspace";
import DbPerfWorkspace from "../components/DbPerfWorkspace";
import NetworkPerfWorkspace from "../components/NetworkPerfWorkspace";
import CryptoWorkspace from "../components/CryptoWorkspace";
import HsmWorkspace from "../components/HsmWorkspace";
import WorkloadWorkspace from "../components/WorkloadWorkspace";
import { comparabilityGate, comparisonRows, metadataChecklist, type BenchmarkRunLike } from "../lib/benchmarkLab";
import { CAPACITY_FEATURES, capacityQuestions, featureState, type CapacityForecastRow } from "../lib/capacityBrief";
import {
  apiPerformanceAlerts, apiPerformanceBaselines,
  apiPerformanceHsm, apiPerformanceWorkloads, apiPerformanceSamples,
  apiPerformanceInfraWorkspace, PerformanceInfraWorkspace,
  apiPerformanceAppWorkspace,
  apiPerformanceDbWorkspace,
  apiPerformanceBenchmarks, apiPerformanceCapacity, apiPerformanceCloud,
  apiPerformanceCryptography, apiPerformanceHealth,
 apiPerformanceInvestigation,
  apiPerformanceNetwork, apiPerformanceOverview, apiPerformanceRunBenchmark,
  apiPerformanceSlo, apiPerformanceStorage,
  type ApiResult, type PerformanceAlert, type PerformanceBaseline,
  type PerformanceBenchmarkRun, type PerformanceCapacity,
  type PerformanceDomain,

  type PerformanceHealth, type PerformanceInvestigation,
  type PerformanceNetwork, type PerformanceOverview, type PerformanceStorage,
  type PerformanceSummary, type PerformanceTile,
} from "../lib/api.js";

/* ZELNX Performance Intelligence (docs/performance/01_PRODUCT_SPEC.md, §7):
   the fourteen screens of the performance section. The honesty rules are
   display rules here: an unknown tile renders "—" and says "unknown, never
   zero"; bandwidth capacity and observed throughput are separate figures;
   benchmark results always carry "controlled benchmark — never production";
   and the investigation's fixed conclusion is "Correlation detected —
   causation unproven". No gradients, no glow, no assistant panel. */

type View =
  | "overview" | "infrastructure" | "storage" | "network" | "applications"
  | "databases" | "cryptography" | "hsm" | "workloads" | "cloud" | "alerts"
  | "capacity" | "benchmarks" | "reports" | "collectors" | "slo";

const VIEWS: Array<{ key: View; label: string }> = [
  { key: "overview", label: "Performance Overview" },
  { key: "infrastructure", label: "Infrastructure Performance" },
  { key: "storage", label: "Storage Performance" },
  { key: "network", label: "Network Performance" },
  { key: "applications", label: "Application Performance" },
  { key: "databases", label: "Database Performance" },
  { key: "cryptography", label: "Cryptographic Performance" },
  { key: "hsm", label: "HSM & KMS Performance" },
  { key: "workloads", label: "Workload & Transaction Intelligence" },
  { key: "cloud", label: "Cloud & Container Performance" },
  { key: "alerts", label: "Performance Alerts" },
  { key: "capacity", label: "Capacity & Forecasting" },
  { key: "benchmarks", label: "Cryptographic Benchmark Laboratory" },
  { key: "reports", label: "Historical Reports" },
  { key: "collectors", label: "Collector Health" },
  { key: "slo", label: "SLO and SLA Management" },
];

const CONTROL_STYLE: React.CSSProperties = {
  background: "transparent", color: "inherit", border: "1px solid var(--rule)",
  borderRadius: 6, padding: "5px 8px", fontSize: 12, fontFamily: "var(--mono)",
};

const ALGORITHMS = ["Ed25519", "ECDSA-P256", "RSA-2048", "RSA-3072"];

function defaultWindow(): { window_start: string; window_end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 60 * 60 * 1000);
  return { window_start: start.toISOString(), window_end: end.toISOString() };
}

/* An unknown value is unknown, never a fabricated zero. */
const TILE_TONE: Record<string, string> = {
  known: "var(--green, #3ecf8e)",
  derived: "var(--violet, #8b7cf6)",
  unknown: "var(--slate, #64748b)",
};

export function TileView({ tile, label }: { tile: PerformanceTile | undefined; label: string }) {
  if (!tile) {
    return (
      <div style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: 8, borderTop: "2px solid var(--slate, #64748b)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, opacity: 0.75 }}>{label}</div>
          <span title="no telemetry in window — unknown, never zero" style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed var(--slate, #64748b)" }} />
        </div>
        <div style={{ fontSize: 22, fontWeight: 700 }}><span>—</span></div>
        <div style={{ fontSize: 10, opacity: 0.7 }}>unknown, never zero</div>
      </div>
    );
  }
  const unknown = tile.state !== "known" || tile.value === null;
  const tone = unknown ? "unknown" : tile.derived ? "derived" : "known";
  return (
    <div
      title={tile.note || `${label}: ${tile.state}${tile.derived ? " (derived)" : ""}`}
      style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: 8, borderTop: `2px solid ${TILE_TONE[tone]}` }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: 11, opacity: 0.75 }}>{label}</div>
        <span
          aria-hidden
          style={{ width: 8, height: 8, borderRadius: 99, background: unknown ? "transparent" : TILE_TONE[tone], border: unknown ? `1.5px dashed ${TILE_TONE[tone]}` : "none" }}
        />
      </div>
      <div style={{ fontSize: 11, opacity: 0.75 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700 }}>
        <span>{unknown ? "—" : tile.value}</span>
        <span style={{ fontSize: 11, fontWeight: 400 }}>{unknown ? "" : ` ${tile.unit}`}</span>
      </div>
      <div style={{ fontSize: 10, opacity: 0.7 }}>
        {unknown ? (tile.note ?? "unknown, never zero") : (tile.derived ? "derived" : tile.state)}
      </div>
    </div>
  );
}

export function SummaryTable({ metrics }: { metrics: Record<string, PerformanceSummary> }) {
  const names = Object.keys(metrics).sort();
  if (names.length === 0) return <div style={{ fontSize: 12, opacity: 0.75 }}>No telemetry in window — absence is unknown, never zero.</div>;
  return (
    <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
      <thead>
        <tr style={{ textAlign: "left", borderBottom: "1px solid var(--rule)" }}>
          <th style={{ padding: 6 }}>Metric</th>
          <th style={{ padding: 6 }}>p50</th>
          <th style={{ padding: 6 }}>p95</th>
          <th style={{ padding: 6 }}>p99</th>
          <th style={{ padding: 6 }}>Delivered</th>
          <th style={{ padding: 6 }}>Coverage</th>
        </tr>
      </thead>
      <tbody>
        {names.map((name) => {
          const s = metrics[name];
          return (
            <tr key={name} style={{ borderBottom: "1px solid var(--rule)" }}>
              <td style={{ padding: 6, fontFamily: "var(--mono)" }}>{name}</td>
              <td style={{ padding: 6 }}>{s.p50 ?? "—"}</td>
              <td style={{ padding: 6 }}>{s.p95 ?? "—"}</td>
              <td style={{ padding: 6 }}>{s.p99 ?? "—"}</td>
              <td style={{ padding: 6 }}>{s.value_count}/{s.sample_count}</td>
              <td style={{ padding: 6 }}>{s.coverage}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Delivered trend samples as a labelled list — a missing series stays
 *  missing; the shape never draws a fabricated flat line. */
export function TrendList({ samples }: { samples: Array<Record<string, unknown>> }) {
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {samples.slice(0, 12).map((s, i) => (
        <div key={i} style={{ display: "flex", gap: 10, fontSize: 12, alignItems: "baseline" }}>
          <span style={{ opacity: 0.7, minWidth: 130 }}>{String(s.observed_at ?? "").slice(0, 19).replace("T", " ")}</span>
          <span style={{ fontWeight: 600 }}>{String(s.metric_name ?? "")}</span>
          <span>{s.metric_value === null || s.metric_value === undefined ? "—" : `${String(s.metric_value)} ${String(s.unit ?? "")}`}</span>
          <span style={{ opacity: 0.65 }}>{String(s.asset_id ?? "")}</span>
        </div>
      ))}
    </div>
  );
}

/** Per-service latency/errors as delivered — an unread column stays "—". */
export function ServiceTable({ services }: { services: PerformanceServiceRow[] }) {
  if (!services.length) {
    return (
      <div style={{ fontSize: 12, opacity: 0.75 }}>
        No service telemetry is stored in this window — a missing service is a
        collection gap, not a healthy service.
      </div>
    );
  }
  return (
    <table style={{ width: "100%", fontSize: 12 }}>
      <thead>
        <tr>
          <th style={{ textAlign: "left", padding: 6 }}>Service</th>
          <th style={{ textAlign: "left", padding: 6 }}>p95 latency</th>
          <th style={{ textAlign: "left", padding: 6 }}>Errors</th>
          <th style={{ textAlign: "left", padding: 6 }}>Requests/sec</th>
        </tr>
      </thead>
      <tbody>
        {services.map((row) => (
          <tr key={row.service}>
            <td style={{ padding: 6 }}>{row.service}</td>
            <td style={{ padding: 6 }}>{row.p95_latency_ms ?? "—"}</td>
            <td style={{ padding: 6 }}>{row.error_rate_pct ?? "—"}</td>
            <td style={{ padding: 6 }}>{row.requests_per_sec ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11, opacity: 0.75, marginTop: 8 }}>{children}</div>;
}

function ErrorNote({ error }: { error: string }) {
  return (
    <Panel title="Read failed">
      <div style={{ fontSize: 12 }}>{error}</div>
      <Note>A failed read is a failure — it never prints zeros.</Note>
    </Panel>
  );
}

function useAsync<T>(loader: () => Promise<ApiResult<T>>, deps: React.DependencyList, enabled = true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const run = useCallback(() => {
    setLoading(true);
    loader()
      .then((result) => {
        if (result.data !== null) { setData(result.data); setError(null); }
        else { setError(result.error ?? "read failed"); setData(null); }
      })
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "read failed"))
      .then(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { if (enabled) run(); }, [run, enabled]);
  return { data, error, loading, reload: run };
}

export default function Performance() {
  const [view, setView] = useState<View>("overview");
  // Resolve the session's tenant (the header picker owns tenancy). Reads
  // wait for the resolution: a blank tenant used to 422 every call on load,
  // and "Read failed" hid the page it belonged to.
  const [tenant, setTenant] = useState(activeTenantId() ?? "");
  const [tenantResolving, setTenantResolving] = useState(!activeTenantId());
  useEffect(() => {
    if (tenant) {
      setTenantResolving(false);
      return;
    }
    let alive = true;
    void ensureActiveTenant().then((resolved) => {
      if (!alive) return;
      if (resolved) setTenant(resolved);
      setTenantResolving(false);
    });
    return () => {
      alive = false;
    };
  }, [tenant]);
  const [window, setWindow] = useState(defaultWindow);

  const reloadKey = `${tenant}|${window.window_start}|${window.window_end}`;
  const w = { tenant_id: tenant, ...window };

  // Reads wait for tenant resolution — exactly once, never twice: a batch
  // fired with a blank tenant is thrown away when the real tenant arrives,
  // and double batches blow the request gate's burst window for nothing.
  const readsReady = !tenantResolving;
  const overview = useAsync(() => apiPerformanceOverview(w), [reloadKey], readsReady);
  const network = useAsync(() => apiPerformanceNetwork(w), [reloadKey], readsReady);
  const storage = useAsync(() => apiPerformanceStorage(w), [reloadKey], readsReady);
  const applications = useAsync(() => apiPerformanceAppWorkspace(w), [reloadKey], readsReady);
  const databases = useAsync(() => apiPerformanceDbWorkspace(w), [reloadKey], readsReady);
  const cryptography = useAsync(() => apiPerformanceCryptography(w), [reloadKey], readsReady);
  const infrastructure = useAsync(() => apiPerformanceInfraWorkspace(w), [reloadKey], readsReady);
  const cloud = useAsync(() => apiPerformanceCloud(w), [reloadKey], readsReady);
  const alerts = useAsync(() => apiPerformanceAlerts(w), [reloadKey], readsReady);
  // No measured capacity ceiling is configured by this page. Request the
  // recorded series as-is; the backend must say no-capacity, not forecast.
  const capacity = useAsync(() => apiPerformanceCapacity(w), [reloadKey], readsReady);
  const baselines = useAsync(() => apiPerformanceBaselines(w), [reloadKey], readsReady);
  const benchmarks = useAsync(() => apiPerformanceBenchmarks({ tenant_id: tenant }), [reloadKey], readsReady);
  const health = useAsync(() => apiPerformanceHealth({ tenant_id: tenant }), [reloadKey], readsReady);
  const slo = useAsync(() => apiPerformanceSlo(w), [reloadKey], readsReady);
  const hsm = useAsync(() => apiPerformanceHsm(w), [reloadKey], readsReady);
  const workloads = useAsync(() => apiPerformanceWorkloads(w), [reloadKey], readsReady);
  const trends = useAsync(() => apiPerformanceSamples({ ...w, limit: 240 }), [reloadKey], readsReady);

  return (
    <div>
      <PageHead
        crumb="Performance"
        title="ZELNX Performance Intelligence"
        sub="Infrastructure • Network • Application • Database • Cryptographic performance"
      />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14, alignItems: "center" }}>
        <select
          aria-label="Performance view"
          style={CONTROL_STYLE}
          value={view}
          onChange={(e) => setView(e.target.value as View)}
        >
          {VIEWS.map((v) => <option key={v.key} value={v.key}>{v.label}</option>)}
        </select>
        <input
          aria-label="Tenant"
          style={CONTROL_STYLE}
          placeholder="tenant_id"
          value={tenant}
          onChange={(e) => setTenant(e.target.value)}
        />
        <input
          aria-label="Window start"
          style={CONTROL_STYLE}
          value={window.window_start}
          onChange={(e) => setWindow({ ...window, window_start: e.target.value })}
        />
        <input
          aria-label="Window end"
          style={CONTROL_STYLE}
          value={window.window_end}
          onChange={(e) => setWindow({ ...window, window_end: e.target.value })}
        />
      </div>

      {tenantResolving && (
        <div
          role="status"
          style={{
            display: "flex", gap: 10, alignItems: "center",
            border: "1px dashed var(--rule)", borderRadius: 8,
            padding: "8px 12px", marginBottom: 12, fontSize: 11.5, opacity: 0.85,
          }}
        >
          <span
            aria-hidden
            style={{ width: 9, height: 9, borderRadius: 99, border: "2px dashed var(--slate, #64748b)", flex: "0 0 auto" }}
          />
          Resolving this session's tenant — reads with a blank tenant are
          failures, never zeros; the moment the tenant lands, every read re-runs.
        </div>
      )}

      {view === "overview" && (
        overview.error ? <ErrorNote error={overview.error} /> : (
          <Panel title="Performance Overview">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              <TileView tile={overview.data?.storage_usage_pct} label="Storage usage" />
              <TileView tile={overview.data?.network_throughput_mbps} label="Network throughput" />
              <TileView tile={overview.data?.api_p95_latency_ms} label="API p95 latency" />
              <TileView tile={overview.data?.requests_per_sec} label="Requests/sec" />
            </div>
            <Note>{overview.data?.note ?? "Tiles show delivered values only."}</Note>
          </Panel>
        )
      )}

      {view === "overview" && !overview.error && (
        <Panel title="Headline metrics" sub="the brief's four cards — CPU, memory, application p95 and error rate">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
            <TileView tile={overview.data?.cpu_utilization_pct} label="CPU utilization" />
            <TileView tile={overview.data?.memory_utilization_pct} label="Memory utilization" />
            <TileView tile={overview.data?.app_p95_latency_ms} label="Application p95 latency" />
            <TileView tile={overview.data?.error_rate_pct} label="Error rate" />
          </div>
        </Panel>
      )}

      {view === "overview" && !overview.error && (
        <Panel title="Infrastructure trends" sub="CPU and memory utilisation over the selected window">
          {trends.error || !(trends.data?.samples ?? []).length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              No trend samples are stored in this window — a missing trend is a
              collection gap, not a flat line.
            </div>
          ) : (
            <TrendList samples={trends.data?.samples ?? []} />
          )}
        </Panel>
      )}

      {view === "overview" && !overview.error && (
        <Panel title="Service performance" sub="per-service latency and errors as delivered">
          <ServiceTable services={overview.data?.services ?? []} />
        </Panel>
      )}

      {view === "overview" && !overview.error && (
        <Panel title="Performance alerts" sub="warning and critical performance conditions">
          {alerts.error ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>Alerts could not be read — an unread alert list is not an empty one.</div>
          ) : (alerts.data ?? []).length === 0 ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>No performance alerts are recorded in this window.</div>
          ) : (
            <div style={{ display: "grid", gap: 6 }}>
              {(alerts.data ?? []).slice(0, 5).map((a, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999,
                    border: `1px solid ${a.severity === "CRITICAL" ? "var(--red, #ef4444)" : "var(--amber, #f59e0b)"}`,
                    color: a.severity === "CRITICAL" ? "var(--red, #ef4444)" : "var(--amber, #f59e0b)",
                  }}>{a.severity === "CRITICAL" ? "Critical" : "Warning"}</span>
                  <span style={{ fontWeight: 600 }}>{a.metric_name}</span>
                  <span style={{ opacity: 0.7 }}>{(a.not_proven ?? [])[0] ?? ""}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      {view === "infrastructure" && (
        infrastructure.error ? <ErrorNote error={infrastructure.error} /> : (
          <InfraWorkspace data={infrastructure.data} />
        )
      )}

      {view === "storage" && (
        storage.error ? <ErrorNote error={storage.error} /> : (
          <Panel title="Storage Intelligence">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              <TileView tile={storage.data?.tiles?.capacity_bytes} label="Total capacity" />
              <TileView tile={storage.data?.tiles?.used_bytes} label="Used" />
              <TileView tile={storage.data?.tiles?.available_bytes} label="Available" />
              <TileView tile={storage.data?.tiles?.utilization_pct} label="Utilization" />
            </div>
            <SummaryTable metrics={storage.data?.metrics ?? {}} />
            <Note>{storage.data?.note}</Note>
          </Panel>
        )
      )}

      {view === "network" && (
        network.error ? <ErrorNote error={network.error} /> : (
          <NetworkPerfWorkspace data={network.data} />
        )
      )}

      {view === "applications" && (
        applications.error ? <ErrorNote error={applications.error} /> : (
          <AppPerfWorkspace data={applications.data} />
        )
      )}

      {view === "databases" && (
        databases.error ? <ErrorNote error={databases.error} /> : (
          <DbPerfWorkspace data={databases.data} />
        )
      )}

      {view === "cryptography" && (
        cryptography.error ? <ErrorNote error={cryptography.error} /> : (
          <CryptoWorkspace data={cryptography.data} />
        )
      )}

      {view === "hsm" && (
        hsm.error ? <ErrorNote error={hsm.error} /> : (
          <HsmWorkspace data={hsm.data} />
        )
      )}

      {view === "workloads" && (
        workloads.error ? <ErrorNote error={workloads.error} /> : (
          <WorkloadWorkspace data={workloads.data} />
        )
      )}

      {view === "cloud" && (
        cloud.error ? <ErrorNote error={cloud.error} /> : (
          <Panel title="Cloud and Container Performance">
            <SummaryTable metrics={cloud.data?.metrics ?? {}} />
            <Note>{cloud.data?.note}</Note>
          </Panel>
        )
      )}

      {view === "alerts" && (
        alerts.error ? <ErrorNote error={alerts.error} /> : <AlertsView alerts={alerts.data ?? []} />
      )}

      {view === "capacity" && (
        capacity.error ? <ErrorNote error={capacity.error} /> : (
          <Panel title="Capacity & Forecasting" sub="planning features and the brief's questions answered from real forecast rows only">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 10, marginBottom: 12 }}>
            {CAPACITY_FEATURES.map((feature) => {
              const state = featureState((capacity.data ?? []) as CapacityForecastRow[], feature);
              const present = state.state === "forecast present";
              return (
                <div key={feature.key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 12, fontWeight: 600 }}>{feature.label}</span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, whiteSpace: "nowrap",
                      border: `1px solid ${present ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
                      color: present ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
                    }}>{present ? "forecast present" : "not derivable"}</span>
                  </div>
                  <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 4 }}>
                    {state.metrics.length ? state.metrics.join(", ") : "no forecast row in this window"}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: "grid", gap: 8, marginBottom: 12 }}>
            {capacityQuestions((capacity.data ?? []) as CapacityForecastRow[]).map((qa) => (
              <div key={qa.question} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px", fontSize: 12 }}>
                <div style={{ fontWeight: 600 }}>{qa.question}</div>
                <div style={{ marginTop: 3 }}>{qa.answer}</div>
                <div style={{ opacity: 0.7, marginTop: 2, fontSize: 11 }}>{qa.basis}</div>
              </div>
            ))}
          </div>
            <BaselinesTable baselines={baselines.data ?? []} />
            <CapacityTable rows={capacity.data ?? []} />
          </Panel>
        )
      )}

      {view === "benchmarks" && (
        <BenchmarkLab
          tenant={tenant}
          runs={benchmarks.data?.runs ?? []}
          note={benchmarks.data?.note}
          onRun={benchmarks.reload}
        />
      )}

      {view === "reports" && <InvestigationPanel tenant={tenant} />}

      {view === "collectors" && (
        health.error ? <ErrorNote error={health.error} /> : <CollectorHealth data={health.data} />
      )}

      {view === "slo" && (
        slo.error ? <ErrorNote error={slo.error} /> : (
          <Panel title="SLO and SLA Management">
            {(slo.data ?? []).length === 0 ? (
              <div style={{ fontSize: 12, opacity: 0.75 }}>
                No SLO policies are recorded — absence of policy is not compliance.
              </div>
            ) : (
              <table style={{ width: "100%", fontSize: 12 }}>
                <tbody>
                  {(slo.data ?? []).map((p) => (
                    <tr key={p.policy_key}>
                      <td style={{ padding: 6 }}>{p.policy_key}</td>
                      <td style={{ padding: 6 }}>{p.metric_name}</td>
                      <td style={{ padding: 6 }}>{p.comparator} {p.objective}</td>
                      <td style={{ padding: 6 }}>{p.compliance}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <Note>
              A policy match is not automatically proof of compliance — evaluation
              compares the stated window only.
            </Note>
          </Panel>
        )
      )}
    </div>
  );
}

export function AlertsView({ alerts }: { alerts: PerformanceAlert[] }) {
  return (
    <Panel title="Performance Alerts">
      {alerts.length === 0 ? (
        <div style={{ fontSize: 12, opacity: 0.75 }}>
          No alert conditions in this window. Absence of alerts is not proof of health.
        </div>
      ) : alerts.map((alert, index) => (
        <div key={`${alert.metric_name}-${index}`} style={{ borderBottom: "1px solid var(--rule)", padding: "10px 0" }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Badge>{alert.severity}</Badge>
            <strong style={{ fontSize: 13 }}>{alert.metric_name}</strong>
            <span style={{ fontSize: 11, opacity: 0.7 }}>severity computed from factors</span>
          </div>
          <div style={{ fontSize: 12, marginTop: 6 }}>
            <div style={{ fontWeight: 600 }}>Proven</div>
            <ul style={{ margin: "4px 0 6px 18px" }}>
              {alert.proven.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
            <div style={{ fontWeight: 600 }}>Not proven</div>
            <ul style={{ margin: "4px 0 0 18px" }}>
              {alert.not_proven.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
          </div>
          <Note>
            Supporting measurements: {alert.supporting_measurements.value_count} delivered
            of {alert.supporting_measurements.sample_count} samples ({alert.supporting_measurements.coverage}).
          </Note>
        </div>
      ))}
    </Panel>
  );
}

export function BaselinesTable({ baselines }: { baselines: PerformanceBaseline[] }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <h3 style={{ fontSize: 13, margin: "0 0 6px" }}>Baselines</h3>
      {baselines.length === 0 ? (
        <div style={{ fontSize: 12, opacity: 0.75 }}>No baseline is computable in this window.</div>
      ) : (
        <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid var(--rule)" }}>
              <th style={{ padding: 6 }}>Metric</th><th style={{ padding: 6 }}>Method</th>
              <th style={{ padding: 6 }}>Samples</th><th style={{ padding: 6 }}>Median</th>
              <th style={{ padding: 6 }}>p95</th>
            </tr>
          </thead>
          <tbody>
            {baselines.map((b, i) => (
              <tr key={`${b.metric_name}-${i}`} style={{ borderBottom: "1px solid var(--rule)" }}>
                <td style={{ padding: 6 }}>{b.metric_name}</td>
                <td style={{ padding: 6 }}>{b.method}</td>
                <td style={{ padding: 6 }}>{b.sample_count}</td>
                <td style={{ padding: 6 }}>{b.median ?? "—"}</td>
                <td style={{ padding: 6 }}>{b.p95 ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function CapacityTable({ rows }: { rows: PerformanceCapacity[] }) {
  return (
    <div>
      <h3 style={{ fontSize: 13, margin: "0 0 6px" }}>Capacity forecasts</h3>
      {rows.length === 0 ? (
        <div style={{ fontSize: 12, opacity: 0.75 }}>No forecast is computable in this window.</div>
      ) : rows.map((row, i) => (
        <div key={`${row.metric_name}-${i}`} style={{ borderBottom: "1px solid var(--rule)", padding: "8px 0" }}>
          <div style={{ fontSize: 13, fontFamily: "var(--mono)" }}>{row.metric_name}</div>
          <div style={{ fontSize: 12 }}>
            {row.status === "forecast"
              ? `Estimated exhaustion in ${Math.round(row.estimated_seconds_to_exhaustion ?? 0)} s (${row.method})`
              : `${row.status} — ${row.note}`}
          </div>
          <div style={{ fontSize: 11, opacity: 0.75, marginTop: 2 }}>
            observation {row.observation_period ?? "not recorded"} · coverage {row.coverage ?? "not recorded"}
          </div>
          <div style={{ fontSize: 11, opacity: 0.75 }}>
            assumptions: {row.assumptions ?? "not recorded"} · uncertainty: {row.uncertainty ?? "not recorded"}
          </div>
          <Note>{row.disclaimer}</Note>
        </div>
      ))}
    </div>
  );
}

export function BenchmarkLab({ tenant, runs, note, onRun }: {
  tenant: string;
  runs: PerformanceBenchmarkRun[];
  note?: string;
  onRun: () => void;
}) {
  const [algorithm, setAlgorithm] = useState(ALGORITHMS[0]);
  const [samples, setSamples] = useState("50");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);
  const run = () => {
    setBusy(true);
    setOutcome(null);
    apiPerformanceRunBenchmark({
      tenant_id: tenant, algorithm, sample_count: Number(samples) || 50,
    })
      .then((result) => {
        if (result.data !== null) {
          setOutcome(`Recorded ${result.data.run_id} — controlled benchmark, never production.`);
          onRun();
        } else {
          setOutcome(result.error ?? "benchmark refused");
        }
      })
      .catch((cause: unknown) => setOutcome(cause instanceof Error ? cause.message : "benchmark refused"))
      .then(() => setBusy(false));
  };
  return (
    <Panel title="Cryptographic Benchmark Laboratory" sub="controlled benchmark results with their full reproducibility record">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
        <select aria-label="Algorithm" style={CONTROL_STYLE} value={algorithm}
          onChange={(e) => setAlgorithm(e.target.value)}>
          {ALGORITHMS.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input aria-label="Sample count" style={CONTROL_STYLE} value={samples}
          onChange={(e) => setSamples(e.target.value)} />
        <button className="btn sm" disabled={busy || !tenant} onClick={run}>
          Run approved benchmark
        </button>
      </div>
      {outcome && <Note>{outcome}</Note>}
      <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ textAlign: "left", borderBottom: "1px solid var(--rule)" }}>
            <th style={{ padding: 6 }}>Run</th><th style={{ padding: 6 }}>Algorithm</th>
            <th style={{ padding: 6 }}>Kind</th><th style={{ padding: 6 }}>Results</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((runRow) => (
            <tr key={runRow.run_id} style={{ borderBottom: "1px solid var(--rule)" }}>
              <td style={{ padding: 6, fontFamily: "var(--mono)" }}>{runRow.run_id}</td>
              <td style={{ padding: 6 }}>{String((runRow.method as { algorithm?: string }).algorithm ?? "?")}</td>
              <td style={{ padding: 6 }}>{runRow.measurement_kind}</td>
              <td style={{ padding: 6 }}>
                {runRow.results.map((r) => `${r.operation} ${r.mean_ms} ms`).join(", ")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {(() => {
        const asLabRuns = runs as unknown as BenchmarkRunLike[];
        const gate = comparabilityGate(asLabRuns);
        const rows = comparisonRows(asLabRuns);
        return (
          <>
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Algorithm comparison — mean latency</div>
              {!rows.length ? (
                <div style={{ fontSize: 12, opacity: 0.75 }}>
                  No benchmark results are recorded — an absent benchmark is a
                  gap, not a fast algorithm.
                </div>
              ) : (
                <>
                  <table style={{ width: "100%", fontSize: 12 }}>
                    <thead>
                      <tr>
                        <th style={{ textAlign: "left", padding: 6 }}>Algorithm</th>
                        <th style={{ textAlign: "left", padding: 6 }}>Operation</th>
                        <th style={{ textAlign: "left", padding: 6 }}>Mean latency</th>
                        <th style={{ textAlign: "left", padding: 6 }}>Comparison</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((r) => (
                        <tr key={`${r.run_id}-${r.algorithm}-${r.operation}`}>
                          <td style={{ padding: 6 }}>{r.algorithm}</td>
                          <td style={{ padding: 6 }}>{r.operation}</td>
                          <td style={{ padding: 6 }}>{r.mean_ms} ms · {r.samples} samples</td>
                          <td style={{ padding: 6 }}>
                            {gate.comparable ? (
                              <span style={{ display: "inline-block", height: 8, borderRadius: 4, background: "var(--accent)", width: Math.max(8, Math.min(180, r.mean_ms * 8)) }} />
                            ) : (
                              <span style={{ opacity: 0.65 }}>comparison withheld</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!gate.comparable && (
                    <div style={{ fontSize: 11.5, opacity: 0.75, marginTop: 6 }}>{gate.basis}</div>
                  )}
                </>
              )}
            </div>

            {asLabRuns.map((runRow) => (
              <div key={`meta-${runRow.run_id}`} style={{ marginTop: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                  Benchmark metadata — {runRow.run_id}
                </div>
                <table style={{ width: "100%", fontSize: 12 }}>
                  <tbody>
                    {metadataChecklist(runRow).map((field) => (
                      <tr key={field.key}>
                        <td style={{ padding: 6, width: 220, opacity: 0.75 }}>{field.label}</td>
                        <td style={{ padding: 6 }}>{field.value ?? "not recorded"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </>
        );
      })()}

      <Note>
        {note ?? "Every run is controlled benchmark performance — never production traffic performance."}
      </Note>
    </Panel>
  );
}

export function InvestigationPanel({ tenant }: { tenant: string }) {
  const [metricName, setMetricName] = useState("crypto.tls_handshake_ms");
  const [changeTime, setChangeTime] = useState(new Date().toISOString());
  const [description, setDescription] = useState("TLS configuration changed");
  const [evidenceIds, setEvidenceIds] = useState("");
  const [report, setReport] = useState<PerformanceInvestigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const investigate = () => {
    setError(null);
    apiPerformanceInvestigation({
      tenant_id: tenant, metric_name: metricName, change_time: changeTime,
      change_description: description, evidence_ids: evidenceIds,
    })
      .then((result) => {
        if (result.data !== null) setReport(result.data);
        else setError(result.error ?? "investigation failed");
      })
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "investigation failed"));
  };
  return (
    <Panel title="Performance Regression Investigation">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <input aria-label="Metric name" style={CONTROL_STYLE} value={metricName}
          onChange={(e) => setMetricName(e.target.value)} />
        <input aria-label="Change time" style={CONTROL_STYLE} value={changeTime}
          onChange={(e) => setChangeTime(e.target.value)} />
        <input aria-label="Change description" style={CONTROL_STYLE} value={description}
          onChange={(e) => setDescription(e.target.value)} />
        <input aria-label="Evidence ids" style={CONTROL_STYLE} placeholder="ev-001,ev-002" value={evidenceIds}
          onChange={(e) => setEvidenceIds(e.target.value)} />
        <button className="btn sm" disabled={!tenant} onClick={investigate}>Investigate</button>
      </div>
      {error && <ErrorNote error={error} />}
      {report && (
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8 }}>{report.conclusion}</div>
          <div style={{ fontSize: 12 }}>
            p95 before: {report.before.p95 ?? "—"} · p95 after: {report.after.p95 ?? "—"} ·
            difference: {report.difference_p95 ?? "—"}
          </div>
          <div style={{ fontSize: 12, marginTop: 8 }}>
            <div style={{ fontWeight: 600 }}>Proven</div>
            <ul style={{ margin: "4px 0 6px 18px" }}>
              {report.evidence.proven.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
            <div style={{ fontWeight: 600 }}>Not proven</div>
            <ul style={{ margin: "4px 0 0 18px" }}>
              {report.evidence.not_proven.map((line, i) => <li key={i}>{line}</li>)}
            </ul>
          </div>
          <Note>{report.note}</Note>
        </div>
      )}
    </Panel>
  );
}

export function CollectorHealth({ data }: { data: PerformanceHealth | null }) {
  return (
    <Panel title="Collector Health">
      {data == null ? (
        <Note>Collector state is unknown — unknown is never zero.</Note>
      ) : (
        <div>
          <div style={{ fontSize: 12, marginBottom: 8 }}>
            Engine: {data.engine} · {data.status}
          </div>
          {data.collectors.length === 0 ? (
            <Note>{data.note}</Note>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <tbody>
                {data.collectors.map((c) => (
                  <tr key={c.collector_id}>
                    <td style={{ padding: 6 }}>{c.collector_id}</td>
                    <td style={{ padding: 6 }}>{c.status}</td>
                    <td style={{ padding: 6 }}>{c.last_report_at ?? "not reported"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <Note>{data.note}</Note>
        </div>
      )}
    </Panel>
  );
}
