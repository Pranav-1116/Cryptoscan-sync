import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Bar, Panel } from "./ui.jsx";
import { apiPerformanceLiveSystems, type LiveSystem, type LiveSystems } from "../lib/api.js";

/* Live systems — every bank server a Cryptava agent reports from, with the newest
   signed performance figures (docs/performance/01_PRODUCT_SPEC.md honesty rules):
   an unread figure is "—" with its reason, never a zero; a server whose agent went
   quiet is STALE, not idle; bandwidth (link capacity) is never shown as traffic. */

export const LIVE_REFRESH_MS = 15000;

const STATE_LABEL: Record<LiveSystem["state"], { text: string; tone: string }> = {
  live: { text: "LIVE", tone: "green" },
  stale: { text: "STALE", tone: "amber" },
  no_samples: { text: "NO SAMPLES YET", tone: "slate" },
};

const SCOPE_NOTE: Record<string, string> = {
  host: "whole machine",
  workload: "the server's own processes (agent runs beside it)",
};

function num(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return value.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: 0 });
}

function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${num(v, v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function ago(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "never";
  if (seconds < 60) return `${Math.round(seconds)} s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
}

function value(s: LiveSystem, name: string): number | null {
  return s.metrics[name]?.value ?? null;
}

function missingReason(s: LiveSystem, name: string): string | undefined {
  return s.missing.find((m) => m.metric === name)?.reason;
}

function Spark({ points, label }: { points: Array<{ v: number }> | undefined; label: string }) {
  if (!points || points.length < 2) return null;
  const w = 90;
  const h = 22;
  const max = Math.max(...points.map((p) => p.v), 1e-9);
  const step = w / (points.length - 1);
  const d = points.map((p, i) => `${(i * step).toFixed(1)},${(h - (p.v / max) * (h - 2) - 1).toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} role="img" aria-label={`${label} trend`} style={{ display: "block" }}>
      <polyline points={d} fill="none" stroke="var(--cyan, #22d3ee)" strokeWidth={1.4} />
    </svg>
  );
}

function Row({ k, v, title, children }: { k: string; v: React.ReactNode; title?: string; children?: React.ReactNode }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "118px 1fr auto", gap: 8, alignItems: "center", fontSize: 12, padding: "3px 0" }}>
      <span style={{ opacity: 0.7 }}>{k}</span>
      <span title={title} style={{ fontFamily: "var(--mono)" }}>{v}</span>
      <span>{children}</span>
    </div>
  );
}

function SystemCard({ s }: { s: LiveSystem }) {
  const state = STATE_LABEL[s.state] ?? STATE_LABEL.no_samples;
  const cpu = value(s, "cpu.utilization_pct");
  const ram = value(s, "ram.utilization_pct");
  const disk = value(s, "storage.utilization_pct");
  const procs = s.metrics["process.health"];
  const hsm = value(s, "crypto.hsm_operation_latency_ms");
  return (
    <div
      data-testid={`live-system-${s.agent}`}
      style={{ border: "1px solid var(--rule)", borderRadius: 10, padding: "12px 14px", display: "grid", gap: 6 }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "flex-start" }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 13.5, overflowWrap: "anywhere" }}>{s.host || s.agent}</div>
          <div style={{ fontSize: 11.5, opacity: 0.75 }}>
            {s.system ?? "no business system mapped"}{s.ip ? ` · ${s.ip}` : ""}
          </div>
        </div>
        <Badge tone={state.tone}>{state.text}</Badge>
      </div>
      <div style={{ fontSize: 11, opacity: 0.75 }}>
        {s.state === "no_samples"
          ? "Enrolled, but no performance sample has arrived — a gap, not an idle server."
          : <>last sample {ago(s.age_seconds)}{s.signed ? " · signature verified" : " · unsigned"}{s.scope ? ` · ${SCOPE_NOTE[s.scope] ?? s.scope}` : ""}</>}
      </div>
      {s.state !== "no_samples" && (
        <div>
          <Row k="CPU" v={cpu === null ? "—" : `${num(cpu)} %`} title={missingReason(s, "cpu.utilization_pct")}>
            <Spark points={s.trend["cpu.utilization_pct"]} label={`${s.agent} CPU`} />
          </Row>
          {cpu !== null && <Bar value={cpu / 100} tone={cpu >= 85 ? "red" : cpu >= 70 ? "amber" : "cyan"} />}
          <Row k="Memory" v={ram === null ? "—" : `${num(ram, 2)} %`} title={missingReason(s, "ram.utilization_pct")}>
            {s.metrics["container.memory_bytes"] && <span style={{ fontSize: 11, opacity: 0.7 }}>{bytes(value(s, "container.memory_bytes"))} resident</span>}
          </Row>
          <Row k="Disk used" v={disk === null ? "—" : `${num(disk)} %`} title={missingReason(s, "storage.utilization_pct")}>
            <span style={{ fontSize: 11, opacity: 0.7 }}>
              {s.metrics["storage.available_bytes"] ? `${bytes(value(s, "storage.available_bytes"))} free of ${bytes(value(s, "storage.capacity_bytes"))}` : ""}
            </span>
          </Row>
          <Row k="Disk I/O" v={s.metrics["disk.throughput_mbps"] ? `${num(value(s, "disk.throughput_mbps"), 3)} MB/s` : "—"} title={missingReason(s, "disk.throughput_mbps")}>
            {s.metrics["disk.iops"] && <span style={{ fontSize: 11, opacity: 0.7 }}>{num(value(s, "disk.iops"))} IOPS</span>}
          </Row>
          <Row k="Network" v={s.metrics["network.throughput_mbps"] ? `${num(value(s, "network.throughput_mbps"), 3)} Mbps` : "—"} title={missingReason(s, "network.throughput_mbps")}>
            <Spark points={s.trend["network.throughput_mbps"]} label={`${s.agent} network`} />
          </Row>
          {s.metrics["network.bandwidth_mbps"] && (
            <Row k="Link capacity" v={`${num(value(s, "network.bandwidth_mbps"), 0)} Mbps`} title="interface link speed — capacity, not traffic" />
          )}
          <Row k="Connections" v={num(value(s, "network.connections"), 0)}>
            {s.metrics["network.tcp_retransmissions"] && (
              <span style={{ fontSize: 11, opacity: 0.7 }}>{num(value(s, "network.tcp_retransmissions"), 0)} retransmits</span>
            )}
          </Row>
          <Row
            k="Processes"
            v={procs ? (procs.value >= 1 ? "healthy" : "unhealthy") : "—"}
            title={missingReason(s, "process.health")}
          >
            {procs?.labels && (
              <span style={{ fontSize: 11, opacity: 0.7 }}>
                {procs.labels.processes ?? "?"} running · {procs.labels.zombies ?? "?"} zombie
              </span>
            )}
          </Row>
          <Row
            k="TLS handshake"
            v={s.tls.length ? s.tls.map((t) => `${num(t.ms, 2)} ms`).join(" · ") : "—"}
            title={s.tls.length ? undefined : "no TLS listener answered on this server"}
          >
            <Spark points={s.trend["crypto.tls_handshake_ms"]} label={`${s.agent} TLS`} />
          </Row>
          {s.tls.map((t) => (
            <div key={String(t.port)} style={{ fontSize: 11, opacity: 0.75, paddingLeft: 126, fontFamily: "var(--mono)" }}>
              :{t.port} · {t.tls_version ?? "?"} · {t.algorithm ?? "?"}
            </div>
          ))}
          {(hsm !== null || missingReason(s, "crypto.hsm_operation_latency_ms")) && (
            <Row k="HSM response" v={hsm === null ? "—" : `${num(hsm, 2)} ms`} title={missingReason(s, "crypto.hsm_operation_latency_ms")} />
          )}
          {s.missing.length > 0 && (
            <div style={{ fontSize: 11, opacity: 0.8, marginTop: 4 }}>
              {s.missing.map((m) => (
                <div key={m.metric}>unknown · {m.metric} — {m.reason}</div>
              ))}
            </div>
          )}
        </div>
      )}
      <div style={{ fontSize: 11, opacity: 0.7, display: "flex", gap: 10, flexWrap: "wrap", borderTop: "1px solid var(--rule)", paddingTop: 6 }}>
        <span style={{ fontFamily: "var(--mono)" }}>{s.agent}</span>
        <Link to="/cryptava">agent →</Link>
      </div>
    </div>
  );
}

function useLiveSystems(tenant: string, enabled: boolean) {
  const [data, setData] = useState<LiveSystems | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    apiPerformanceLiveSystems({ tenant_id: tenant || undefined })
      .then((r) => {
        if (r.data) { setData(r.data); setError(null); } else { setError(r.error ?? "read failed"); }
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "read failed"));
  }, [tenant]);
  useEffect(() => {
    if (!enabled) return undefined;
    load();
    const t = setInterval(load, LIVE_REFRESH_MS);
    return () => clearInterval(t);
  }, [load, enabled]);
  return { data, error, reload: load };
}

export default function LiveSystemsPanel({ tenant, enabled = true, compact = false, onOpen }: {
  tenant: string;
  enabled?: boolean;
  compact?: boolean;
  onOpen?: () => void;
}) {
  const { data, error } = useLiveSystems(tenant, enabled);
  const title = "Live systems · Cryptava agents";
  if (error && !data) {
    return (
      <Panel title={title}>
        <div style={{ fontSize: 12, opacity: 0.8 }}>
          Live systems could not be read ({error}) — an unread fleet is not an idle one.
        </div>
      </Panel>
    );
  }
  const systems = data?.systems ?? [];
  const counts = data?.counts;
  const sub = counts
    ? `${counts.systems} server${counts.systems === 1 ? "" : "s"} · ${counts.live} live · ${counts.stale} stale · ${counts.no_samples} waiting — refreshes every ${LIVE_REFRESH_MS / 1000} s`
    : "loading…";
  if (data && systems.length === 0) {
    return (
      <Panel title={title} sub="no Cryptava agent has reported performance yet">
        <div style={{ fontSize: 12, opacity: 0.8 }}>
          No server is sending live metrics in tenant <code>{data.tenant_id}</code>. Each Cryptava agent sends a
          signed sample every minute once it is enrolled — in the sandbox:{" "}
          <code>bash sandbox/run_sandbox.sh agents</code>, then <code>bash sandbox/run_sandbox.sh agents check</code>.
        </div>
      </Panel>
    );
  }
  if (compact) {
    return (
      <Panel title={title} sub={sub}>
        <table style={{ width: "100%", fontSize: 12 }}>
          <thead>
            <tr>
              {["Server", "State", "CPU", "Memory", "Disk used", "Network", "TLS handshake", "Last sample"].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: 6 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {systems.map((s) => {
              const state = STATE_LABEL[s.state] ?? STATE_LABEL.no_samples;
              const cpu = value(s, "cpu.utilization_pct");
              const ram = value(s, "ram.utilization_pct");
              const disk = value(s, "storage.utilization_pct");
              const net = value(s, "network.throughput_mbps");
              return (
                <tr key={s.agent}>
                  <td style={{ padding: 6 }}>
                    <div style={{ fontWeight: 600 }}>{s.host || s.agent}</div>
                    <div style={{ fontSize: 11, opacity: 0.7 }}>{s.system ?? s.agent}</div>
                  </td>
                  <td style={{ padding: 6 }}><Badge tone={state.tone}>{state.text}</Badge></td>
                  <td style={{ padding: 6 }} title={missingReason(s, "cpu.utilization_pct")}>{cpu === null ? "—" : `${num(cpu)} %`}</td>
                  <td style={{ padding: 6 }} title={missingReason(s, "ram.utilization_pct")}>{ram === null ? "—" : `${num(ram, 2)} %`}</td>
                  <td style={{ padding: 6 }}>{disk === null ? "—" : `${num(disk)} %`}</td>
                  <td style={{ padding: 6 }}>{net === null ? "—" : `${num(net, 3)} Mbps`}</td>
                  <td style={{ padding: 6 }}>{s.tls.length ? s.tls.map((t) => `${num(t.ms, 2)} ms`).join(" · ") : "—"}</td>
                  <td style={{ padding: 6 }}>{ago(s.age_seconds)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {onOpen && (
          <div style={{ marginTop: 8 }}>
            <button type="button" className="btn ghost" onClick={onOpen} style={{ fontSize: 12 }}>
              Open live systems →
            </button>
          </div>
        )}
      </Panel>
    );
  }
  return (
    <Panel title={title} sub={sub}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(310px, 1fr))", gap: 12 }}>
        {systems.map((s) => <SystemCard key={s.agent} s={s} />)}
      </div>
      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>
        {data?.note}
        {data?.truncated ? " · showing the newest 5000 samples of the window" : ""}
      </div>
    </Panel>
  );
}
