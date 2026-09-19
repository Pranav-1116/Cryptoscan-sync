import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Stat, Tabs } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, useRealtimeRefresh, RealtimeChip, severityOf, isSystemEvent, type RealtimeState } from "../lib/realtime.js";
import { apiInventory, apiInventorySummary, apiUnifiedRisk, CmdbAsset, CmdbInventory, CmdbSummary, UnifiedRiskResponse } from "../lib/api.js";

/* Unified Asset Inventory / CMDB — one authoritative, deduplicated view of the
   estate across systems, crypto assets, certificates, cloud, hardware, vendors,
   business processes, owners and network targets. Every row is persisted real
   data from the backend; nothing is fabricated. Backend-offline reads empty. */

function timeAgo(ts: number): string {
  const d = Math.max(0, Date.now() - ts);
  if (d < 1000) return "now";
  if (d < 60_000) return `${Math.floor(d / 1000)}s`;
  if (d < 3600_000) return `${Math.floor(d / 60_000)}m`;
  return `${Math.floor(d / 3600_000)}h`;
}

const SEV_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "amber", MEDIUM: "amber", LOW: "green" };

function LiveActivity({ rt }: { rt: RealtimeState }) {
  const items = rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 6);
  return (
    <Panel title="Live activity" sub={rt.connected ? `SSE live · ${rt.subscribers} subscribers · ${rt.eps} ev/s` : "no live events stream yet"} frame={false}>
      {items.length ? (
        <div className="feed">
          {items.map((e) => (
            <div key={e.id} className="feed-row" style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0", fontSize: 13 }}>
              <Badge tone={SEV_TONE[severityOf(e.type)] ?? ""}>{severityOf(e.type)}</Badge>
              <span className="mono" style={{ flex: 0 }}>{e.type}</span>
              <span className="dim" style={{ marginLeft: "auto", fontSize: 12 }}>{timeAgo(new Date(e.ts).getTime())}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="dim" style={{ fontSize: 13 }}>
          {rt.backend === false ? "Backend offline — start the control plane to stream events." : "No live events yet — run a scan to see realtime inventory changes here."}
        </div>
      )}
    </Panel>
  );
}

const TONE: Record<string, string> = {
  CRITICAL: "red",
  HIGH: "amber",
  MEDIUM: "amber",
  LOW: "green",
};

const PQC_TONE: Record<string, string> = {
  vulnerable: "red",
  ready: "green",
  unknown: "",
};

const riskTone = (level: string) => (level === "CRITICAL" ? "red" : level === "HIGH" ? "amber" : level === "MEDIUM" ? "amber" : "green");
const riskRank = (level: string) => ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[level] ?? 4);

const TYPE_ORDER = ["Application", "Crypto", "Certificate", "Cloud", "Hardware", "Vendor", "BusinessService", "Owner", "NetworkTarget"];

export default function Cmdb() {
  const rt = useRealtime();
  const assets = usePollingApi(apiInventory, 9000);
  const summary = usePollingApi(apiInventorySummary, 12000);
  const riskU = usePollingApi(apiUnifiedRisk, 15000);
  useRealtimeRefresh(assets.run, summary.run, riskU.run);

  const live = assets.source === "live";
  const data: CmdbInventory | null = assets.data ?? null;
  const sum: CmdbSummary | null = summary.data ?? null;

  const [typeFilter, setTypeFilter] = useState("All");
  const [riskFilter, setRiskFilter] = useState("All");
  const [q, setQ] = useState("");

  const rows: CmdbAsset[] = useMemo(() => {
    if (!data) return [];
    let out = data.assets;
    if (typeFilter !== "All") out = out.filter((a) => a.asset_type === typeFilter);
    if (riskFilter !== "All") out = out.filter((a) => a.risk === riskFilter);
    if (q.trim()) {
      const s = q.trim().toLowerCase();
      out = out.filter(
        (a) =>
          String(a.name ?? "").toLowerCase().includes(s) ||
          String(a.algorithm ?? "").toLowerCase().includes(s) ||
          String(a.endpoint ?? "").toLowerCase().includes(s) ||
          String(a.serial_reference ?? "").toLowerCase().includes(s) ||
          String(a.subject ?? "").toLowerCase().includes(s)
      );
    }
    return out;
  }, [data, typeFilter, riskFilter, q]);

  const types = useMemo(() => {
    const present = new Set((data?.assets ?? []).map((a) => a.asset_type));
    return ["All", ...TYPE_ORDER.filter((t) => present.has(t))];
  }, [data]);
  const risks = useMemo(() => {
    const present = new Set((data?.assets ?? []).map((a) => a.risk).filter((x): x is string => Boolean(x)));
    return ["All", ...[...present].sort()];
  }, [data]);

  const filterTabs = types.length > 2 ? types : ["All"];

  return (
    <>
      <PageHead
        crumb="inventory / cmdb"
        title="Enterprise Asset & CMDB"
        sub="One authoritative inventory — systems, crypto, certificates, cloud, hardware, vendors, business services, owners and network targets"
        right={
          <>
            <RealtimeChip />
            <Badge tone={live && rows.length ? "green" : ""}><span className="dot" /> {rows.length.toLocaleString()} ROWS</Badge>
          </>
        }
      />

      <div className="stats-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        <Panel title="Asset types" sub="persisted, per source" frame={false}>
          <div className="kpi-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
            {TYPE_ORDER.filter((t) => (sum?.by_type[t] ?? 0) > 0).map((t) => (
              <Stat key={t} label={t} value={sum?.by_type[t] ?? 0} />
            ))}
            {!sum?.total && <div className="dim" style={{ gridColumn: "1 / -1", fontSize: 13 }}>No assets yet — run a scan to populate the CMDB.</div>}
          </div>
        </Panel>
        <Panel title="Unified risk" sub="criticality + PQC + expiry" frame={false}>
          <div className="kpi-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
            {(Object.entries(sum?.by_risk ?? {}).sort((a, b) => a[0].localeCompare(b[0]))).map(([k, v]) => (
              <Stat key={k} label={k} value={v} tone={TONE[k] ?? ""} />
            ))}
          </div>
        </Panel>
        <Panel title="PQC posture" sub="vulnerable vs ready vs unknown" frame={false}>
          <div className="kpi-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
            {(Object.entries(sum?.by_pqc ?? {}).sort((a, b) => a[0].localeCompare(b[0]))).map(([k, v]) => (
              <Stat key={k} label={k} value={v} tone={PQC_TONE[k] ?? ""} />
            ))}
          </div>
        </Panel>
      </div>

      <Panel
        title="Unified risk engine"
        sub={riskU.source === "live" ? "Technical + Crypto + PQC + Exposure + Business Criticality + Dependency + Evidence Confidence + Threat → one score per asset" : "unified risk unavailable — backend offline"}
      >
        {riskU.data ? (
          <div className="row" style={{ gap: 18, flexWrap: "wrap", alignItems: "flex-start" }}>
            <div style={{ minWidth: 160 }}>
              <Stat label="Estate score" value={riskU.data.estate.score} tone={riskTone(riskU.data.estate.level)} />
              <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>{riskU.data.estate.level} · {riskU.data.estate.count} assets</div>
            </div>
            <div className="kpi-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10, flex: 1 }}>
              {(Object.entries(riskU.data.estate.by_level).sort((a, b) => riskRank(b[0]) - riskRank(a[0]))).map(([k, v]) => (
                <Stat key={k} label={k} value={v} tone={riskTone(k)} />
              ))}
            </div>
            <Table
              head={["asset", "type", "score", "level", "top factors"]}
              rows={riskU.data.assets.slice(0, 12).map((a) => {
                const top = Object.entries(a.factors).filter(([, f]) => f.level > 0).sort((a, b) => b[1].level - a[1].level).slice(0, 3).map(([k, f]) => `${k}:${f.level}`).join(", ");
                return [
                  <span className="mono">{a.name ?? a.id}</span>,
                  <Badge tone="cyan">{a.asset_type}</Badge>,
                  <span className="num">{a.score}</span>,
                  <Badge tone={riskTone(a.level)}>{a.level}</Badge>,
                  <span className="dim mono" style={{ fontSize: 12 }}>{top || "no factors > 0"}</span>,
                ];
              })}
            />
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>{riskU.source === "offline" ? "Backend offline — unified risk unavailable." : "No assets yet — run a scan to compute unified risk."}</div>
        )}
      </Panel>

      <Panel
        title="Unified inventory"
        sub={rows.length ? `filtered from ${data?.count ?? 0} assets across ${Object.keys(sum?.by_type ?? {}).length} sources` : "no assets yet — start a scan to populate the estate"}
      >
        <div className="toolbar" style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
          <input
            className="search-input"
            style={{ flex: "0 0 220px" }}
            placeholder="Search name / algo / endpoint / serial…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <Tabs tabs={filterTabs} active={Math.max(0, filterTabs.indexOf(typeFilter))} onChange={(i) => setTypeFilter(filterTabs[i] ?? "All")} />
          <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            {risks.map((r) => (
              <button
                key={r}
                className={`btn ${riskFilter === r ? "btn-primary" : ""}`}
                style={{ padding: "4px 10px", fontSize: 12 }}
                onClick={() => setRiskFilter(r)}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        <Table
          head={["type", "name", "risk", "pqc", "criticality", "owner", "env / provider", "detail", "relationships"]}
          rows={rows.map((a) => {
            const rel = (a.relationships as Record<string, string[]> | undefined) ?? {};
            const rels = Object.entries(rel).flatMap(([k, v]) => (v?.length ? [`${k}:${v.length}`] : []));
            return [
              <Badge tone="cyan">{a.asset_type}</Badge>,
              <span className="mono">{a.name ?? "—"}</span>,
              <Badge tone={TONE[a.risk ?? "LOW"] ?? ""}>{a.risk ?? "LOW"}</Badge>,
              <Badge tone={PQC_TONE[a.pqc ?? "unknown"] ?? ""}>{a.pqc ?? "unknown"}</Badge>,
              a.criticality ?? "—",
              a.owner ?? "—",
              a.environment ?? a.cloud_provider ?? "—",
              <span className="dim mono" style={{ fontSize: 12 }}>{(a.algorithm ?? a.public_key_algorithm ?? a.manufacturer ?? a.endpoint ?? "") || "—"}</span>,
              rels.length ? <span className="num" style={{ fontSize: 12 }}>{rels.join(", ")}</span> : <span className="dim">—</span>,
            ];
          })}
        />
        {!rows.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No assets match the current filters — clear the search or start a scan." : "Backend offline — unified inventory unavailable."}
          </div>
        )}
      </Panel>

      <div className="stats-grid" style={{ gridTemplateColumns: "2fr 1fr" }}>
        <Panel title="Asset provenance" sub="Relationships the backend has actually resolved — from persisted SystemAsset / Dependency / BusinessProcess / CertificateUsage links">
          <Table
            head={["asset", "type", "criticality", "uses", "supports", "depends_on", "owned_by", "protected_by"]}
            rows={rows.map((a) => {
              const rel = (a.relationships as Record<string, string[]> | undefined) ?? {};
              const fmt = (v: string[] | undefined) => (v?.length ? <span className="mono" style={{ fontSize: 12 }}>{v.length}</span> : <span className="dim">—</span>);
              return [
                <span className="mono">{a.name ?? "—"}</span>,
                <Badge tone="cyan">{a.asset_type}</Badge>,
                a.criticality ?? "—",
                fmt(rel.uses),
                fmt(rel.supports),
                fmt(rel.depends_on),
                fmt(rel.owned_by),
                fmt(rel.protected_by),
              ];
            })}
          />
        </Panel>
        <LiveActivity rt={rt} />
      </div>
    </>
  );
}
