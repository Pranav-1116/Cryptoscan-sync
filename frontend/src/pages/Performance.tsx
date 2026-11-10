import React, { useCallback, useEffect, useState } from "react";
import { activeTenantId, ensureActiveTenant } from "../lib/api";
import { Badge, Panel, PageHead } from "../components/ui.jsx";
import {
  apiPerformanceAlerts, apiPerformanceApplications, apiPerformanceBaselines,
  apiPerformanceBenchmarks, apiPerformanceCapacity, apiPerformanceCloud,
  apiPerformanceCryptography, apiPerformanceDatabases, apiPerformanceHealth,
  apiPerformanceInfrastructure, apiPerformanceInvestigation,
  apiPerformanceNetwork, apiPerformanceOverview, apiPerformanceRunBenchmark,
  apiPerformanceSlo, apiPerformanceStorage,
  type ApiResult, type PerformanceAlert, type PerformanceBaseline,
  type PerformanceBenchmarkRun, type PerformanceCapacity,
  type PerformanceDomain,
  type PerformanceDatabases, type PerformanceApplications,
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
  | "databases" | "cryptography" | "cloud" | "alerts" | "capacity"
  | "benchmarks" | "reports" | "collectors" | "slo";

const VIEWS: Array<{ key: View; label: string }> = [
  { key: "overview", label: "Performance Overview" },
  { key: "infrastructure", label: "Infrastructure Monitoring" },
  { key: "storage", label: "Storage Intelligence" },
  { key: "network", label: "Network Intelligence" },
  { key: "applications", label: "Application Performance" },
  { key: "databases", label: "Database Performance" },
  { key: "cryptography", label: "Cryptographic Performance" },
  { key: "cloud", label: "Cloud & Container Performance" },
  { key: "alerts", label: "Performance Alerts" },
  { key: "capacity", label: "Capacity Planning" },
  { key: "benchmarks", label: "Benchmark Lab" },
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

function useAsync<T>(loader: () => Promise<ApiResult<T>>, deps: React.DependencyList) {
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
  useEffect(() => { run(); }, [run]);
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

  const overview = useAsync(() => apiPerformanceOverview(w), [reloadKey]);
  const network = useAsync(() => apiPerformanceNetwork(w), [reloadKey]);
  const storage = useAsync(() => apiPerformanceStorage(w), [reloadKey]);
  const applications = useAsync(() => apiPerformanceApplications(w), [reloadKey]);
  const databases = useAsync(() => apiPerformanceDatabases(w), [reloadKey]);
  const cryptography = useAsync(() => apiPerformanceCryptography(w), [reloadKey]);
  const infrastructure = useAsync(() => apiPerformanceInfrastructure(w), [reloadKey]);
  const cloud = useAsync(() => apiPerformanceCloud(w), [reloadKey]);
  const alerts = useAsync(() => apiPerformanceAlerts(w), [reloadKey]);
  const capacity = useAsync(() => apiPerformanceCapacity({ ...w, capacity_value: undefined }), [reloadKey]);
  const baselines = useAsync(() => apiPerformanceBaselines(w), [reloadKey]);
  const benchmarks = useAsync(() => apiPerformanceBenchmarks({ tenant_id: tenant }), [reloadKey]);
  const health = useAsync(() => apiPerformanceHealth({ tenant_id: tenant }), [reloadKey]);
  const slo = useAsync(() => apiPerformanceSlo(w), [reloadKey]);

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

      {view === "infrastructure" && (
        infrastructure.error ? <ErrorNote error={infrastructure.error} /> : (
          <Panel title="Infrastructure Monitoring">
            <SummaryTable metrics={infrastructure.data?.metrics ?? {}} />
            <Note>{infrastructure.data?.note}</Note>
          </Panel>
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
          <Panel title="Network Intelligence">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              <TileView tile={network.data?.bandwidth_capacity_mbps} label="Bandwidth capacity" />
              <TileView tile={network.data?.observed_throughput_mbps} label="Observed throughput" />
            </div>
            <SummaryTable metrics={network.data?.metrics ?? {}} />
            <Note>{network.data?.note}</Note>
          </Panel>
        )
      )}

      {view === "applications" && (
        applications.error ? <ErrorNote error={applications.error} /> : (
          <Panel title="Application Performance">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 }}>
              <TileView tile={applications.data?.requests_per_sec} label="Requests/sec" />
              <TileView tile={applications.data?.latency_p50_ms} label="p50 latency" />
              <TileView tile={applications.data?.latency_p95_ms} label="p95 latency" />
              <TileView tile={applications.data?.latency_p99_ms} label="p99 latency" />
              <TileView tile={applications.data?.error_rate_pct} label="Error rate" />
            </div>
            <SummaryTable metrics={applications.data?.metrics ?? {}} />
            <Note>{applications.data?.note}</Note>
          </Panel>
        )
      )}

      {view === "databases" && (
        databases.error ? <ErrorNote error={databases.error} /> : (
          <Panel title="Database Performance">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              <TileView tile={databases.data?.connections_active} label="Active connections" />
            </div>
            <SummaryTable metrics={databases.data?.metrics ?? {}} />
            <Note>{databases.data?.note}</Note>
          </Panel>
        )
      )}

      {view === "cryptography" && (
        cryptography.error ? <ErrorNote error={cryptography.error} /> : (
          <Panel title="Cryptographic Performance">
            <Badge tone="gray">{cryptography.data?.measurement_kind ?? "observed-production"}</Badge>
            <SummaryTable metrics={cryptography.data?.metrics ?? {}} />
            <Note>{cryptography.data?.note}</Note>
          </Panel>
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
          <Panel title="Capacity Planning">
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
    <Panel title="Benchmark Lab">
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
