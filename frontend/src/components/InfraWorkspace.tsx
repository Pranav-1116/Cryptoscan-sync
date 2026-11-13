/**
 * Infrastructure Performance (docs/performance/03_UI_SPEC.md §2): the eight
 * interface tabs over one workspace projection. A server row opens its
 * Technology BOM record, dependencies and Digital Twin history; a server
 * without a verified canonical identity stays unlinked — the engine never
 * invents asset identities. Gaps are named, never zero-filled.
 */
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Panel } from "./ui.jsx";
import type { PerformanceInfraWorkspace } from "../lib/api";

const INFRA_TABS = [
  { key: "overview", label: "Infrastructure Overview" },
  { key: "inventory", label: "Server Inventory" },
  { key: "cpu", label: "CPU & Memory" },
  { key: "storage", label: "Storage Performance" },
  { key: "virtualization", label: "Virtualization" },
  { key: "containers", label: "Container Performance" },
  { key: "hardware", label: "Hardware Health" },
  { key: "trends", label: "Historical Trends" },
] as const;

type InfraTab = (typeof INFRA_TABS)[number]["key"];

function StateChip({ state }: { state: string }) {
  const measured = state === "measured";
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999,
      border: `1px solid ${measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)"}`,
      color: measured ? "var(--green, #3ecf8e)" : "var(--slate, #64748b)",
    }}>{measured ? "measured" : "not collected"}</span>
  );
}

export function SummaryTable({ metrics }: { metrics: Record<string, { sample_count?: number; value_count?: number; unknown_count?: number; coverage?: string; average?: number | null; minimum?: number | null; maximum?: number | null; p50?: number | null; p95?: number | null; p99?: number | null }> }) {
  const names = Object.keys(metrics);
  if (!names.length) return null;
  return (
    <table style={{ width: "100%", fontSize: 12, marginBottom: 10 }}>
      <thead>
        <tr>
          <th style={{ textAlign: "left", padding: 6 }}>Metric</th>
          <th style={{ textAlign: "left", padding: 6 }}>State</th>
          <th style={{ textAlign: "left", padding: 6 }}>p50</th>
          <th style={{ textAlign: "left", padding: 6 }}>p95</th>
          <th style={{ textAlign: "left", padding: 6 }}>p99</th>
          <th style={{ textAlign: "left", padding: 6 }}>min–max</th>
          <th style={{ textAlign: "left", padding: 6 }}>delivered</th>
        </tr>
      </thead>
      <tbody>
        {names.map((name) => {
          const m = metrics[name];
          return (
            <tr key={name}>
              <td style={{ padding: 6 }}>{name}</td>
              <td style={{ padding: 6 }}>{m.coverage ?? "—"}</td>
              <td style={{ padding: 6 }}>{m.p50 ?? "—"}</td>
              <td style={{ padding: 6 }}>{m.p95 ?? "—"}</td>
              <td style={{ padding: 6 }}>{m.p99 ?? "—"}</td>
              <td style={{ padding: 6 }}>{m.minimum ?? "—"}–{m.maximum ?? "—"}</td>
              <td style={{ padding: 6 }}>{m.value_count ?? "—"}/{m.sample_count ?? "—"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default function InfraWorkspace({ data }: { data: PerformanceInfraWorkspace | null | undefined }) {
  const [tab, setTab] = useState<InfraTab>("overview");
  const cat = (key: string) => data?.categories?.[key];
  const inventory = data?.inventory ?? [];
  return (
    <div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }} role="tablist" aria-label="Infrastructure tabs">
        {INFRA_TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            style={{
              padding: "6px 12px", borderRadius: 8, cursor: "pointer", fontSize: 11.5,
              border: `1px solid ${tab === t.key ? "var(--accent)" : "var(--line-strong)"}`,
              background: tab === t.key ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent",
              color: tab === t.key ? "var(--accent)" : "var(--dim)",
            }}>{t.label}</button>
        ))}
      </div>

      {tab === "overview" && (
        <Panel title="Infrastructure Overview" sub="the brief's categories as measured or as named gaps">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
            {(["cpu", "memory", "storage", "disk", "processes", "virtualization", "containers", "kubernetes"] as const).map((k) => {
              const metrics = cat(k)?.metrics ?? {};
              const count = Object.keys(metrics).length;
              return (
                <div key={k} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 600, textTransform: "capitalize" }}>{k}</span>
                    <StateChip state={cat(k)?.state ?? "not_collected"} />
                  </div>
                  <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>
                    {count ? `${count} metric famil${count === 1 ? "y" : "ies"} in window` : "no families delivered"}
                  </div>
                  {cat(k)?.basis ? <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 3 }}>{cat(k)?.basis}</div> : null}
                </div>
              );
            })}
          </div>
          <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
        </Panel>
      )}

      {tab === "inventory" && (
        <Panel title="Server Inventory" sub="open a server's Technology BOM record, dependencies and Digital Twin history">
          {!inventory.length ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              No server telemetry is stored in this window — a missing server
              is a collection gap, not an empty estate.
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 6 }}>Server</th>
                  <th style={{ textAlign: "left", padding: 6 }}>CPU</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Memory</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Load</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Disk latency</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Identity</th>
                  <th style={{ textAlign: "left", padding: 6 }}>Record</th>
                </tr>
              </thead>
              <tbody>
                {inventory.map((row) => (
                  <tr key={row.asset_id}>
                    <td style={{ padding: 6 }}>{row.asset_id}</td>
                    <td style={{ padding: 6 }}>{row.cpu_pct ?? "—"}</td>
                    <td style={{ padding: 6 }}>{row.memory_pct ?? "—"}</td>
                    <td style={{ padding: 6 }}>{row.load ?? "—"}</td>
                    <td style={{ padding: 6 }}>{row.disk_latency_ms ?? "—"}</td>
                    <td style={{ padding: 6 }}>{row.link ? row.link : "not established — no canonical record"}</td>
                    <td style={{ padding: 6 }}>
                      {row.link ? (
                        <span style={{ display: "flex", gap: 8 }}>
                          <Link to={`/live-asset-intelligence?asset=${encodeURIComponent(row.link)}`}>TechBOM record</Link>
                          <Link to={`/live-asset-intelligence?asset=${encodeURIComponent(row.link)}&detail_tab=dependencies`}>Dependencies</Link>
                          <Link to={`/live-asset-intelligence?asset=${encodeURIComponent(row.link)}&detail_tab=history`}>Twin history</Link>
                        </span>
                      ) : (
                        <span style={{ opacity: 0.65 }}>no verified link — the engine never invents asset identities</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === "cpu" && (
        <Panel title="CPU & Memory" sub="utilisation and load as delivered — per-server distribution is in the Server Inventory">
          {Object.keys(cat("cpu")?.metrics ?? {}).length + Object.keys(cat("memory")?.metrics ?? {}).length === 0 ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>No CPU or memory telemetry is stored in this window — unknown, never zero.</div>
          ) : (
            <>
              <SummaryTable metrics={cat("cpu")?.metrics ?? {}} />
              <SummaryTable metrics={cat("memory")?.metrics ?? {}} />
            </>
          )}
        </Panel>
      )}

      {tab === "storage" && (
        <Panel title="Storage Performance" sub="capacity, I/O and latency as delivered">
          {Object.keys({ ...(cat("storage")?.metrics ?? {}), ...(cat("disk")?.metrics ?? {}) }).length === 0 ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>No storage telemetry is stored in this window — unknown, never zero.</div>
          ) : (
            <>
              <SummaryTable metrics={cat("storage")?.metrics ?? {}} />
              <SummaryTable metrics={cat("disk")?.metrics ?? {}} />
            </>
          )}
        </Panel>
      )}

      {tab === "virtualization" && (
        <Panel title="Virtualization" sub="a named gap where no authorized collector exists">
          <div style={{ fontSize: 12, opacity: 0.8 }}>
            <StateChip state={cat("virtualization")?.state ?? "not_collected"} />
            <div style={{ marginTop: 8 }}>{cat("virtualization")?.basis ?? ""}</div>
          </div>
        </Panel>
      )}

      {tab === "containers" && (
        <Panel title="Container Performance" sub="containers and Kubernetes as measured">
          {Object.keys({ ...(cat("containers")?.metrics ?? {}), ...(cat("kubernetes")?.metrics ?? {}) }).length === 0 ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              No container telemetry is stored in this window — absence of
              telemetry is not a healthy cluster.
            </div>
          ) : (
            <>
              <SummaryTable metrics={cat("containers")?.metrics ?? {}} />
              <SummaryTable metrics={cat("kubernetes")?.metrics ?? {}} />
            </>
          )}
        </Panel>
      )}

      {tab === "hardware" && (
        <Panel title="Hardware Health" sub="process health where delivered; environmental telemetry is a named gap">
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
            <StateChip state={data?.hardware_health?.state ?? "not_collected"} />
          </div>
          {Object.keys(data?.hardware_health?.metrics ?? {}).length > 0 && (
            <SummaryTable metrics={data?.hardware_health?.metrics ?? {}} />
          )}
          <div style={{ fontSize: 11, opacity: 0.75 }}>{data?.hardware_health?.basis ?? ""}</div>
        </Panel>
      )}

      {tab === "trends" && (
        <Panel title="Historical Trends" sub="window statistics over the delivered samples">
          {Object.keys(data?.trends ?? {}).length === 0 ? (
            <div style={{ fontSize: 12, opacity: 0.75 }}>
              No trend telemetry is stored in this window — a missing trend is
              a collection gap, not a flat line.
            </div>
          ) : (
            <SummaryTable metrics={data?.trends ?? {}} />
          )}
        </Panel>
      )}
    </div>
  );
}
