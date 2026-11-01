import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Stat, Tabs } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, useChannelRefresh, RealtimeChip, severityOf, isSystemEvent, type RealtimeState } from "../lib/realtime.js";
import { apiAssetRiskExplain, apiInventory, apiInventorySummary, apiUnifiedRisk, AssetRiskExplain, CmdbAsset, CmdbInventory, CmdbSummary, UnifiedRiskResponse } from "../lib/api.js";

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
    <Panel title="Live activity" sub={rt.connected ? "Estate stream connected" : "no live events stream yet"} frame={false}>
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

/* §4.6 (round 68): per-asset risk explainability. Renders the chain the
   backend assembled from persisted state: per-factor provenance (inputs +
   rule + what level 0 means), the evidence rows joined on the identity
   spine (crypto assets), stored control verdicts, the asset's own PQC wave
   and its owners. Every "no data" state is rendered as what it is —
   unknown or unregistered — never as clean. */
function AssetExplainPanel({ data, onClose }: { data: AssetRiskExplain; onClose: () => void }) {
  const basisTone = (b: string) => (b === "OBSERVED" ? "cyan" : "");
  return (
    <div style={{ marginTop: 14, borderTop: "1px solid var(--line)", paddingTop: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
        <span className="mono" style={{ fontSize: 13 }}>{data.asset_id}</span>
        <Badge tone={riskTone(data.risk.level)}>{data.risk.level} · {data.risk.score}</Badge>
        <Badge tone="cyan">{data.asset_type}</Badge>
        <span className="dim" style={{ fontSize: 12 }}>{data.risk.calculation_version} · weights: {data.risk.weights_source}</span>
        <button className="btn sm outline" onClick={onClose} style={{ marginLeft: "auto", fontSize: 11.5, padding: "4px 10px" }}>Close</button>
      </div>
      <Table
        head={["factor", "level", "points", "weight", "basis", "why this level"]}
        rows={data.factors.map((f) => [
          <span className="mono" style={{ fontSize: 12 }}>{f.factor}</span>,
          <span className="num">{f.level}</span>,
          <span className="num">{f.points}</span>,
          <span className="num dim">{f.weight}</span>,
          <Badge tone={basisTone(f.basis)}>{f.basis}</Badge>,
          <span className="dim" style={{ fontSize: 12 }}>
            {f.derived_from.rule}
            <div className="mono" style={{ fontSize: 11, marginTop: 2 }}>
              inputs: {Object.entries(f.derived_from.inputs).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" · ")}
            </div>
          </span>,
        ])}
      />
      <div className="row" style={{ gap: 18, flexWrap: "wrap", alignItems: "flex-start", marginTop: 10 }}>
        <div style={{ flex: 2, minWidth: 260 }}>
          <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>Where the observation came from</div>
          {data.evidence_trail.entries.length ? (
            <>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>
                identity spine {data.evidence_trail.asset_key?.slice(0, 18)}… · {data.evidence_trail.total_observations ?? data.evidence_trail.entries.length} observation(s)
              </div>
              <Table
                head={["location", "scan", "chain", "status"]}
                rows={data.evidence_trail.entries.map((e) => [
                  <span className="mono" style={{ fontSize: 12 }}>{e.location ?? "—"}</span>,
                  <span className="mono dim" style={{ fontSize: 11 }}>{e.scan_id}</span>,
                  <span className="num">{e.chain_position ?? "—"}</span>,
                  <Badge tone={e.compliance_status === "FAIL" ? "red" : e.compliance_status === "WARN" ? "amber" : "green"}>{e.compliance_status ?? "—"}</Badge>,
                ])}
              />
              {(data.evidence_trail.failing_controls ?? []).length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>Why controls fail — the stored verdicts</div>
                  {(data.evidence_trail.failing_controls ?? []).map((c) => (
                    <div key={c.rule_id ?? "?"} style={{ fontSize: 12, marginBottom: 4 }}>
                      <Badge tone="red">{c.worst_outcome}</Badge> <span className="mono">{c.rule_id}</span>{" "}
                      <span className="dim">{c.messages[0] ?? c.rule_name ?? ""} · {c.evidence_count} evidence row(s)</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="dim" style={{ fontSize: 12 }}>{data.evidence_trail.note}</div>
          )}
        </div>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>Who owns it</div>
          <div style={{ fontSize: 12 }}>
            <div>owner: <span className="mono">{data.accountability.owner ?? "—"}</span></div>
            <div>technical: <span className="mono">{data.accountability.technical_owner ?? "—"}</span></div>
            <div>security: <span className="mono">{data.accountability.security_owner ?? "—"}</span></div>
            {data.accountability.systems_using.length > 0 && (
              <div className="dim" style={{ marginTop: 2 }}>used by: <span className="mono">{data.accountability.systems_using.join(", ")}</span></div>
            )}
          </div>
          {data.pqc_rationale && data.pqc_rationale.sites.length > 0 && (
            <>
              <div className="dim" style={{ fontSize: 12, marginTop: 10, marginBottom: 4 }}>PQC wave for this asset</div>
              {data.pqc_rationale.sites.slice(0, 3).map((site, i) => (
                <div key={i} style={{ fontSize: 12, marginBottom: 4 }}>
                  <Badge tone="amber">wave {site.wave}</Badge> <span className="mono">{site.algorithm}</span>
                  <div className="dim">deadline {site.migration_deadline ?? "—"} · replace with {site.recommended_replacement}</div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
      <div style={{ marginTop: 10 }}>
        <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>Honest limitations</div>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }} className="dim">
          {data.limitations.map((lim, i) => <li key={i}>{lim}</li>)}
        </ul>
      </div>
    </div>
  );
}

export default function Cmdb() {
  const rt = useRealtime();
  const assets = usePollingApi(apiInventory, 9000, [], { channels: ["inventory"] });
  const summary = usePollingApi(apiInventorySummary, 12000, [], { channels: ["inventory"] });
  const riskU = usePollingApi(apiUnifiedRisk, 15000, [], { channels: ["inventory"] });
  useChannelRefresh(["inventory"], [assets.run, summary.run, riskU.run]);

  const live = assets.source === "live";
  const data: CmdbInventory | null = assets.data ?? null;
  const sum: CmdbSummary | null = summary.data ?? null;

  const [typeFilter, setTypeFilter] = useState("All");
  const [riskFilter, setRiskFilter] = useState("All");
  const [q, setQ] = useState("");

  /* per-asset explain chain (§4.6, round 68) */
  const [explainFor, setExplainFor] = useState<string | null>(null);
  const [explainData, setExplainData] = useState<AssetRiskExplain | null>(null);
  const [explainBusy, setExplainBusy] = useState(false);
  const loadExplain = async (assetId: string) => {
    if (explainFor === assetId) {
      setExplainFor(null);
      setExplainData(null);
      return;
    }
    setExplainBusy(true);
    const r = await apiAssetRiskExplain(assetId);
    setExplainBusy(false);
    if (r.data) {
      setExplainFor(assetId);
      setExplainData(r.data);
    } else {
      setExplainFor(null);
      setExplainData(null);
    }
  };

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
              head={["asset", "type", "score", "level", "top factors", ""]}
              total={riskU.data.assets.length} rows={riskU.data.assets.slice(0, 12).map((a) => {
                const top = Object.entries(a.factors).filter(([, f]) => f.level > 0).sort((a, b) => b[1].level - a[1].level).slice(0, 3).map(([k, f]) => `${k}:${f.level}`).join(", ");
                return [
                  <span className="mono">{a.name ?? a.id}</span>,
                  <Badge tone="cyan">{a.asset_type}</Badge>,
                  <span className="num">{a.score}</span>,
                  <Badge tone={riskTone(a.level)}>{a.level}</Badge>,
                  <span className="dim mono" style={{ fontSize: 12 }}>{top || "no factors > 0"}</span>,
                  <button
                    className="btn sm outline"
                    disabled={explainBusy}
                    onClick={() => void loadExplain(a.id)}
                    style={{ fontSize: 11.5, padding: "4px 10px" }}
                    title={"Why this score — which inputs set each factor, where the observation came from, and what is unknown rather than clean."}
                  >
                    {explainFor === a.id ? "Hide why" : "Why?"}
                  </button>,
                ];
              })}
            />
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>{riskU.source === "offline" ? "Backend offline — unified risk unavailable." : "No assets yet — run a scan to compute unified risk."}</div>
        )}
        {explainData && explainFor && (
          <AssetExplainPanel
            data={explainData}
            onClose={() => {
              setExplainFor(null);
              setExplainData(null);
            }}
          />
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
