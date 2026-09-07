import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiDiscover, apiControlAgents, ApiResult } from "../lib/api.js";
import { useLive, LiveStatus } from "../lib/useLive.js";

interface Plugin { plugin_id: string; plugin_version?: string; capabilities?: string[]; health?: { ok?: boolean; detail?: string }; }
interface MonitorStatus { overview?: { targets_total?: number; by_type?: Record<string, number>; enabled?: number }; needs_attention?: any[]; }

export default function Scanners() {
  const plugins = useLive<{ plugins: Plugin[] }>("/api/v1/discovery/plugins", { plugins: [] });
  const monitor = useLive<MonitorStatus>("/api/v1/monitor/status", {});
  const [agents, setAgents] = useState<any[]>([]);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { void apiControlAgents().then((r) => { if (r.ok && r.data) setAgents((r.data as any).agents ?? (Array.isArray(r.data) ? r.data : [])); }); }, []);

  const runDiscovery = async () => {
    setBusy(true);
    setLive(await apiDiscover({ network: {}, cloud: {}, vendor: {}, hardware: {}, crypto: {} }));
    setBusy(false);
  };

  const plugs = plugins.data.plugins ?? [];
  const healthy = plugs.filter((p) => p.health?.ok !== false).length;
  const targets = monitor.data.overview?.targets_total ?? 0;

  return (
    <>
      <PageHead
        crumb="operate / scanners"
        title="Scanner control center"
        sub="Registered discovery/scanner plugins · agents · monitor targets — start discovery live"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> {healthy}/{plugs.length} PLUGINS OK</Badge>
            <button className="btn sm primary" onClick={() => void runDiscovery()} disabled={busy}>
              {busy ? "Discovering…" : "Run discovery (live)"}
            </button>
          </div>
        }
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={plugins.loading} error={plugins.error} /></div>

      {live?.data && (
        <Panel title="POST /api/v1/platform/discover — live response" sub="unified discovery across all five domains" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}

      <Panel title="Registered scanner plugins" sub={`${plugs.length} plugins discovered · ${targets} monitor target(s)`} className="mt">
        <Table
          head={["plugin", "version", "capabilities", "health"]}
          rows={plugs.map((p) => [
            <span className="mono" style={{ fontWeight: 600 }}>{p.plugin_id}</span>,
            <span className="num">{p.plugin_version ?? "—"}</span>,
            <span style={{ fontSize: 12.5 }}>{(p.capabilities ?? []).join(" · ")}</span>,
            <Badge tone={p.health?.ok === false ? "red" : "green"}>{p.health?.ok === false ? (p.health?.detail ?? "unhealthy") : "ok"}</Badge>,
          ])}
        />
        {plugs.length === 0 && !plugins.loading && <p className="dim" style={{ fontSize: 13 }}>No scanner plugins registered yet.</p>}
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Agents" sub={`${agents.length} registered`}>
          <Table
            head={["agent", "host", "version", "status"]}
            rows={agents.map((a) => [
              <span className="mono">{a.agent_id ?? a.id ?? "—"}</span>,
              <span className="mono">{a.host ?? a.hostname ?? "—"}</span>,
              <span className="num">{a.version ?? "—"}</span>,
              <Badge tone={a.status === "HEALTHY" || a.healthy ? "green" : "amber"}>{a.status ?? (a.healthy ? "HEALTHY" : "unknown")}</Badge>,
            ])}
          />
          {agents.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No agents connected.</p>}
        </Panel>
        <Panel title="Monitor & scan policy" sub="safe by default — read-only, scoped, scheduled">
          <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">targets monitored:</span> {targets}</div>
            <div><span className="faint">enabled:</span> {monitor.data.overview?.enabled ?? 0}</div>
            <div><span className="faint">needs attention:</span> {(monitor.data.needs_attention ?? []).length}</div>
            <div><span className="faint">policy:</span> SAFE · READ_ONLY · SCOPED</div>
            <div><span className="faint">OT:</span> PASSIVE-FIRST · SIS/ESD NEVER PROBED</div>
            <div><Badge tone="green">CREDENTIALS IN VAULT · NEVER STORED IN STATE</Badge></div>
          </div>
        </Panel>
      </div>
    </>
  );
}
