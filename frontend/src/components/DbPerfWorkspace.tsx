/**
 * Database Performance (docs/performance/03_UI_SPEC.md §4): the nine
 * metric areas over delivered telemetry, per-database rows, and honest
 * adapter states. The collection contract is statistics only — query
 * fingerprints and normalized statistics; query parameters and customer
 * records are never collected, and SQL statements containing customer
 * data are never collected. Unknowns render "—", never zeros.
 */
import React, { useState } from "react";
import { Panel } from "./ui.jsx";
import { SummaryTable } from "./InfraWorkspace";
import type { PerformanceDbWorkspace } from "../lib/api";

const AREA_LABELS: Record<string, string> = {
  connections: "Connections",
  queries: "Queries",
  locks: "Locks",
  cache: "Cache",
  storage: "Storage",
  replication: "Replication",
  transactions: "Transactions",
  backup: "Backup",
  availability: "Availability",
};

const DB_TABS = [
  { key: "areas", label: "Metric areas" },
  { key: "databases", label: "Databases" },
  { key: "adapters", label: "Adapters & collectors" },
] as const;

type DbTab = (typeof DB_TABS)[number]["key"];

export default function DbPerfWorkspace({ data }: { data: PerformanceDbWorkspace | null | undefined }) {
  const [tab, setTab] = useState<DbTab>("areas");
  const areas = data?.areas ?? {};
  const databases = data?.databases ?? [];
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10, marginBottom: 14 }}>
        {Object.keys(AREA_LABELS).map((key) => {
          const area = areas[key];
          const measured = area?.state === "measured";
          const count = Object.keys(area?.metrics ?? {}).length;
          return (
            <div key={key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{AREA_LABELS[key]}</span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999,
                  border: `1px solid ${measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
                  color: measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
                }}>{measured ? "measured" : "not collected"}</span>
              </div>
              <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>
                {count ? `${count} metric famil${count === 1 ? "y" : "ies"} delivered` : "no families delivered"}
              </div>
              {(area?.missing ?? []).length > 0 && (
                <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 3 }}>
                  not collected: {area?.missing?.join(", ")}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }} role="tablist" aria-label="Database performance tabs">
        {DB_TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            style={{
              padding: "6px 12px", borderRadius: 8, cursor: "pointer", fontSize: 11.5,
              border: `1px solid ${tab === t.key ? "var(--accent)" : "var(--line-strong)"}`,
              background: tab === t.key ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent",
              color: tab === t.key ? "var(--accent)" : "var(--dim)",
            }}>{t.label}</button>
        ))}
      </div>

      {tab === "areas" && (
        <Panel title="Metric areas" sub="delivered families with their window statistics">
          {Object.keys(areas).every((k) => Object.keys(areas[k]?.metrics ?? {}).length === 0) ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No database telemetry is stored in this window — missing telemetry is a collection gap, never zeros."}>{"No database telemetry is stored in this window"}</span>
            </div>
          ) : (
            Object.keys(AREA_LABELS).map((key) => (
              (areas[key]?.state === "measured") ? (
                <div key={key} style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{AREA_LABELS[key]}</div>
                  <SummaryTable metrics={areas[key]?.metrics ?? {}} />
                </div>
              ) : null
            ))
          )}
        </Panel>
      )}

      {tab === "databases" && (
        <Panel title="Databases" sub="per-database figures as delivered — a platform is never invented">
          {!databases.length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No database telemetry is stored in this window — a missing database is a collection gap, not a healthy estate."}>{"No database telemetry is stored in this window"}</span>
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 6 }}>Database</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Platform</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Connections</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Query time</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Size</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Replication lag</th>
                </tr>
              </thead>
              <tbody>
                {databases.map((d) => (
                  <tr key={d.database}>
                    <td style={{ padding: 6 }}>{d.database}</td>
                    <td style={{ padding: 6 }}>{d.platform === "not recorded" ? "not recorded — the engine never invents a platform" : d.platform}</td>
                    <td style={{ padding: 6 }}>{d.connections_active ?? "—"}</td>
                    <td style={{ padding: 6 }}>{d.query_time_ms ?? "—"}</td>
                    <td style={{ padding: 6 }}>{d.size_bytes ?? "—"}</td>
                    <td style={{ padding: 6 }}>{d.replication_lag_seconds ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === "adapters" && (
        <Panel title="Adapters & collectors" sub="adapter availability is capability — it is not a claim of use">
          <table style={{ width: "100%", fontSize: 12, marginBottom: 12 }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: 6 }}>Platform</th>
                <th style={{ textAlign: "left", padding: 6 }}>Adapter</th>
                <th style={{ textAlign: "left", padding: 6 }}>State</th>
              </tr>
            </thead>
            <tbody>
              {(data?.adapters ?? []).map((a) => (
                <tr key={a.platform}>
                  <td style={{ padding: 6 }}>{a.platform}</td>
                  <td style={{ padding: 6 }}>{a.adapter ?? "—"}</td>
                  <td style={{ padding: 6 }}>{a.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(data?.collectors ?? []).length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              <span title={"No collector health is recorded — an unread collector is not a healthy collector."}>{"No collector health is recorded"}</span>
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 6 }}>Collector</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Status</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Last report</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {(data?.collectors ?? []).map((c) => (
                  <tr key={c.collector_id}>
                    <td style={{ padding: 6 }}>{c.collector_id}</td>
                    <td style={{ padding: 6 }}>{c.status}</td>
                    <td style={{ padding: 6 }}>{c.last_report_at ? String(c.last_report_at).slice(0, 10) : "—"}</td>
                    <td style={{ padding: 6 }}>{c.detail ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
    </div>
  );
}
