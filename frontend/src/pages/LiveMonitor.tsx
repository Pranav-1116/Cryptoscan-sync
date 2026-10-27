import { Link } from "react-router-dom";
import React, { useEffect, useRef, useState, useMemo } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, useRealtimeRefresh, severityOf, isSystemEvent } from "../lib/realtime.js";
import {
  IconNetwork,
  IconHardware,
  IconTenant,
  IconCrypto,
  IconCode,
  IconCertificate,
  IconEstate,
  IconCloud,
  IconLive,
  IconTarget,
  IconClock,
  IconSecurity,
  IconComponent,
  IconInfo,
  IconTrendUp,
  IconTrendDown,
  IconTrendFlat,
  type Icon,
} from "../components/icons";
import {
  apiLiveEnvironment,
  apiLiveOrchestratorStatus,
  apiLiveOrchestratorHistory,
  apiLiveOrchestratorStart,
  apiTechBomLive,
  LiveEnvironmentResponse,
  OrchestratorScan,
  ScanRunSummary,
} from "../lib/api.js";

// helpers
function timeAgo(ts: string): string {
  if (!ts) return "—";
  const d = Math.max(0, Date.now() - new Date(ts).getTime());
  if (Number.isNaN(d)) return "—";
  if (d < 1000) return "now";
  if (d < 60_000) return `${Math.floor(d / 1000)}s`;
  if (d < 3600_000) return `${Math.floor(d / 60_000)}m`;
  if (d < 86400_000) return `${Math.floor(d / 3600_000)}h`;
  return `${Math.floor(d / 86400_000)}d`;
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

type ChangeRecord = {
  id: string;
  ts: string;
  domain: string;
  delta: number;
  from: number;
  to: number;
  severity: "info" | "warn" | "critical";
};

const DOMAIN_META: Record<
  string,
  { label: string; icon: Icon; color: string; tone: string; to: string; desc: string }
> = {
  network: { label: "Network", icon: IconNetwork, color: "var(--cyan)", tone: "cyan", to: "/network", desc: "Endpoints, segments, exposed services" },
  hardware: { label: "Hardware", icon: IconHardware, color: "var(--amber)", tone: "amber", to: "/hardware", desc: "HSMs, servers, OT/ICS, fleet" },
  vendor: { label: "Vendors", icon: IconTenant, color: "var(--violet)", tone: "violet", to: "/vendor", desc: "Supply chain, attestations" },
  crypto: { label: "Cryptography", icon: IconCrypto, color: "var(--green)", tone: "green", to: "/crypto", desc: "Algorithms, keys, protocols" },
  certificate: { label: "Certificates", icon: IconCertificate, color: "var(--red)", tone: "red", to: "/certificates", desc: "X.509, expiry, trust" },
  application: { label: "Applications", icon: IconCode, color: "var(--accent)", tone: "cyan", to: "/dev-sec-ops", desc: "Codebases, SBOM packages" },
  software: { label: "Software (SBOM)", icon: IconComponent, color: "var(--accent)", tone: "cyan", to: "/sbom", desc: "SBOM components, deps" },
  techbom: { label: "TechBOM", icon: IconEstate, color: "var(--violet)", tone: "violet", to: "/live-asset-intelligence", desc: "Unified SBOM+CBOM+HBOM+NBOM" },
  cloud: { label: "Cloud", icon: IconCloud, color: "var(--cyan)", tone: "cyan", to: "/cloud", desc: "Accounts, resources" },
};

const phaseTone = (phase: string) =>
  phase === "live_monitoring" ? "green" : phase === "completed" ? "green" : phase === "failed" ? "red" : "amber";

const sevTone = (s: string) =>
  s === "CRITICAL" ? "red" : s === "HIGH" ? "amber" : s === "MEDIUM" ? "amber" : "green";

export default function LiveMonitor() {
  // interval control — 3s = real-time, 6s = balanced default
  const [intervalMs, setIntervalMs] = useState<number>(3000);
  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(() => {
    try {
      return localStorage.getItem("live-monitor-sound") !== "false";
    } catch {
      return true;
    }
  });
  const [uptimeSec, setUptimeSec] = useState(0);
  const [changes, setChanges] = useState<ChangeRecord[]>([]);
  const [lastPollAt, setLastPollAt] = useState<string | null>(null);

  // refs for delta detection
  const prevDomainsRef = useRef<Record<string, number> | null>(null);
  const prevTechBomRef = useRef<number | null>(null);

  // live data — effective interval is paused ? 600000 : intervalMs
  const effectiveInterval = isPaused ? 600000 : intervalMs;
  const lt = usePollingApi(apiLiveEnvironment, effectiveInterval);
  const status = usePollingApi(apiLiveOrchestratorStatus, isPaused ? 600000 : Math.max(6000, intervalMs * 2));
  const history = usePollingApi(apiLiveOrchestratorHistory, isPaused ? 600000 : 15000);
  const techBom = usePollingApi(() => apiTechBomLive(500), isPaused ? 600000 : intervalMs);
  const rt = useRealtime();
  useRealtimeRefresh(lt.run, status.run, history.run, techBom.run);

  const env: LiveEnvironmentResponse | null = (lt.data as LiveEnvironmentResponse | null) ?? null;
  const scan: OrchestratorScan | null = env?.scan ?? (status.data as any)?.scan ?? null;
  const domains = env?.domains ?? { network: 0, hardware: 0, vendor: 0, crypto: 0, certificate: 0, application: 0, total: 0 };
  const graph = env?.graph ?? {};
  const events = (env?.events?.events ?? []).filter((e) => !isSystemEvent(e.type)).slice(0, 8);
  const runs: ScanRunSummary[] = (history.data as any)?.runs ?? [];
  const live = lt.source === "live";
  const techBomState: any = techBom.data ?? null;
  const techBomTotal: number = techBomState?.total_components ?? 0;
  const techBomLayers = techBomState?.layers ?? {};
  const byLayer: Record<string, number> = techBomState?.components_by_layer ?? {};

  // uptime ticker
  useEffect(() => {
    const t = setInterval(() => setUptimeSec((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // fullscreen handling — add class to body
  useEffect(() => {
    if (isFullscreen) document.documentElement.setAttribute("data-live-fullscreen", "true");
    else document.documentElement.removeAttribute("data-live-fullscreen");
    return () => document.documentElement.removeAttribute("data-live-fullscreen");
  }, [isFullscreen]);

  // sound toggle persist
  useEffect(() => {
    try {
      localStorage.setItem("live-monitor-sound", String(soundEnabled));
    } catch {}
  }, [soundEnabled]);

  // change detection — compare current domains to previous
  useEffect(() => {
    if (!env || lt.source !== "live") return;
    const now = new Date().toISOString();
    setLastPollAt(now);

    const curr: Record<string, number> = {
      network: domains.network,
      hardware: domains.hardware,
      vendor: domains.vendor,
      crypto: domains.crypto,
      certificate: domains.certificate,
      application: domains.application,
      total: domains.total,
      techbom: techBomTotal,
      // derived software = sbom + application (approx)
      software: (byLayer["sbom"] ?? techBomLayers?.sbom?.count ?? 0) + domains.application,
    };

    const prev = prevDomainsRef.current;
    if (prev) {
      const newChanges: ChangeRecord[] = [];
      for (const k of Object.keys(curr)) {
        const from = prev[k] ?? 0;
        const to = curr[k] ?? 0;
        if (from !== to) {
          const delta = to - from;
          const abs = Math.abs(delta);
          const severity: ChangeRecord["severity"] =
            k === "crypto" || k === "certificate" ? (abs >= 3 ? "critical" : "warn") : abs >= 5 ? "warn" : "info";
          newChanges.push({
            id: `${now}-${k}-${from}-${to}`,
            ts: now,
            domain: k,
            delta,
            from,
            to,
            severity,
          });
          // sound for critical changes
          if (severity === "critical" && soundEnabled) {
            try {
              const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
              const o = ctx.createOscillator();
              const g = ctx.createGain();
              o.type = "sine";
              o.frequency.value = 880;
              g.gain.value = 0.08;
              o.connect(g).connect(ctx.destination);
              o.start();
              setTimeout(() => {
                o.stop();
                ctx.close();
              }, 180);
            } catch {}
          }
        }
      }
      if (newChanges.length) {
        setChanges((prevChanges) => [...newChanges, ...prevChanges].slice(0, 40));
      }
    }
    prevDomainsRef.current = curr;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domains.network, domains.hardware, domains.vendor, domains.crypto, domains.certificate, domains.application, domains.total, techBomTotal]);

  // keyboard shortcuts: Space = pause, F = fullscreen
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.code === "Space") {
        e.preventDefault();
        setIsPaused((p) => !p);
      }
      if (e.key.toLowerCase() === "f") setIsFullscreen((f) => !f);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const [starting, setStarting] = useState(false);
  const startScan = async () => {
    setStarting(true);
    try {
      await apiLiveOrchestratorStart();
      setTimeout(() => {
        lt.run();
        status.run();
      }, 600);
    } finally {
      setStarting(false);
    }
  };

  const uptimeLabel = useMemo(() => {
    const h = Math.floor(uptimeSec / 3600);
    const m = Math.floor((uptimeSec % 3600) / 60);
    const s = uptimeSec % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }, [uptimeSec]);

  const hasData = domains.total > 0 || (graph.node_count ?? 0) > 0;
  const liveDots = live && !isPaused;

  // domain tiles config — unified coverage
  const domainTiles: Array<{
    key: string;
    value: number;
    prevValue?: number;
    active: boolean;
    delta?: number;
  }> = [
    { key: "network", value: domains.network, active: domains.network > 0, delta: prevDomainsRef.current ? domains.network - (prevDomainsRef.current.network ?? 0) : 0 },
    { key: "hardware", value: domains.hardware, active: domains.hardware > 0, delta: prevDomainsRef.current ? domains.hardware - (prevDomainsRef.current.hardware ?? 0) : 0 },
    { key: "crypto", value: domains.crypto, active: domains.crypto > 0, delta: prevDomainsRef.current ? domains.crypto - (prevDomainsRef.current.crypto ?? 0) : 0 },
    { key: "vendor", value: domains.vendor, active: domains.vendor > 0, delta: prevDomainsRef.current ? domains.vendor - (prevDomainsRef.current.vendor ?? 0) : 0 },
    { key: "techbom", value: techBomTotal, active: techBomTotal > 0, delta: prevDomainsRef.current ? techBomTotal - (prevDomainsRef.current.techbom ?? 0) : 0 },
    { key: "software", value: (byLayer["sbom"] ?? 0) + domains.application, active: (byLayer["sbom"] ?? 0) + domains.application > 0, delta: prevDomainsRef.current ? (byLayer["sbom"] ?? 0) + domains.application - (prevDomainsRef.current.software ?? 0) : 0 },
    { key: "certificate", value: domains.certificate, active: domains.certificate > 0, delta: prevDomainsRef.current ? domains.certificate - (prevDomainsRef.current.certificate ?? 0) : 0 },
    { key: "application", value: domains.application, active: domains.application > 0, delta: prevDomainsRef.current ? domains.application - (prevDomainsRef.current.application ?? 0) : 0 },
  ];

  const recentChangesCount = changes.filter((c) => Date.now() - new Date(c.ts).getTime() < 300_000).length; // last 5m

  return (
    <div
      className={isFullscreen ? "live-monitor-fullscreen" : ""}
      style={{
        maxWidth: isFullscreen ? "100%" : "1280px",
        margin: "0 auto",
        padding: isFullscreen ? "8px 12px 40px" : "10px 0 60px",
      }}
    >
      {/* fullscreen bar */}
      {isFullscreen && (
        <div
          style={{
            position: "sticky",
            top: 0,
            zIndex: 5,
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "8px 12px",
            margin: "-8px -12px 12px",
            background: "var(--bg)",
            borderBottom: "1px solid var(--line)",
          }}
        >
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 800, fontSize: 13 }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: 999,
                background: liveDots ? "var(--green)" : "var(--amber)",
                boxShadow: liveDots ? "0 0 10px var(--green)" : "none",
                animation: liveDots ? "pulse 1.2s infinite" : "none",
              }}
            />
            LIVE MONITOR — FULLSCREEN 24/7
          </span>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>Press F or Esc to exit · Space to pause</span>
          <span style={{ marginLeft: "auto" }} />
          <button onClick={() => setIsFullscreen(false)} className="btn btn-primary" style={{ padding: "6px 12px" }}>
            Exit fullscreen
          </button>
        </div>
      )}

      {/* HERO — immersive 24/7 header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 16,
          flexWrap: "wrap",
          padding: "14px 16px",
          marginBottom: 14,
          background: liveDots
            ? "linear-gradient(135deg, color-mix(in srgb, var(--green) 8%, var(--bg)) 0%, var(--bg) 55%, color-mix(in srgb, var(--accent) 6%, var(--bg)) 100%)"
            : "var(--panel)",
          border: `1px solid ${liveDots ? "color-mix(in srgb, var(--green) 30%, var(--line))" : "var(--line)"}`,
          borderRadius: "var(--r)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* subtle grid overlay */}
        <div
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            opacity: 0.06,
            backgroundImage:
              "linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px)",
            backgroundSize: "22px 22px",
          }}
        />
        <div style={{ position: "relative", flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "3px 10px",
                borderRadius: 999,
                background: liveDots ? "var(--green)" : "var(--amber)",
                color: "#fff",
                fontSize: 11,
                fontWeight: 800,
                letterSpacing: "0.06em",
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 999,
                  background: "#fff",
                  opacity: 0.95,
                  boxShadow: "0 0 8px rgba(255,255,255,0.9)",
                  animation: liveDots ? "pulse 1s infinite" : "none",
                }}
              />
              LIVE MONITOR · 24/7
            </span>
            <Badge tone={live ? "green" : "amber"}>
              <span className="dot" /> {isPaused ? "PAUSED" : live ? (rt.connected ? "SSE LIVE" : "POLL LIVE") : "OFFLINE"}
            </Badge>
            {scan?.scope_validated ? (
              <Badge tone="green">SCOPE: AUTHORIZED</Badge>
            ) : (
              <Badge tone="amber">SCOPE: EMPTY</Badge>
            )}
            <span style={{ fontSize: 11, color: "var(--dim)" }}>
              Uptime {uptimeLabel} · Interval {intervalMs / 1000}s · Last poll {lastPollAt ? timeAgo(lastPollAt) : "—"}
            </span>
          </div>

          <h1
            style={{
              fontSize: 22,
              fontWeight: 800,
              letterSpacing: "-0.02em",
              margin: "8px 0 6px",
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
          >
            <span
              style={{
                width: 32,
                height: 32,
                borderRadius: 10,
                display: "grid",
                placeItems: "center",
                background: liveDots ? "var(--green)" : "var(--amber)",
                color: "#fff",
                boxShadow: liveDots ? "0 0 14px color-mix(in srgb, var(--green) 50%, transparent)" : "none",
              }}
            >
              <IconLive size={18} />
            </span>
            Live Infrastructure Monitor
          </h1>
          <p style={{ margin: 0, color: "var(--dim)", fontSize: 13, lineHeight: 1.5, maxWidth: 680 }}>
            Continuous 24/7 estate monitoring — <b style={{ color: "var(--text)" }}>network · hardware · cryptography · vendors · TechBOM · software · infra</b> — one graph, one scan id, real-time change detection. Every tick diffs the estate and surfaces what changed.
          </p>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
            <Link to="/live-environment" className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>
              live environment →
            </Link>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <Link to="/live-asset-intelligence" className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>
              TechBOM →
            </Link>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <Link to="/live-stream" className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>
              live stream →
            </Link>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <Link to="/graph" className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>
              dependency graph →
            </Link>
          </div>
        </div>

        {/* right hero controls */}
        <div style={{ position: "relative", display: "flex", flexDirection: "column", gap: 10, minWidth: 280, alignItems: "stretch" }}>
          {/* interval + pause */}
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              flexWrap: "wrap",
              padding: "8px 10px",
              background: "color-mix(in srgb, var(--bg) 80%, transparent)",
              border: "1px solid var(--line)",
              borderRadius: "var(--r)",
            }}
          >
            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)" }}>Refresh</span>
            {[3000, 6000, 15000, 30000].map((ms) => (
              <button
                key={ms}
                onClick={() => setIntervalMs(ms)}
                style={{
                  padding: "4px 8px",
                  borderRadius: 999,
                  fontSize: 11,
                  fontWeight: 700,
                  border: `1px solid ${intervalMs === ms ? "var(--accent)" : "var(--line)"}`,
                  background: intervalMs === ms ? "var(--accent)" : "transparent",
                  color: intervalMs === ms ? "#fff" : "var(--text)",
                  cursor: "pointer",
                }}
              >
                {ms / 1000}s
              </button>
            ))}
            <button
              onClick={() => setIsPaused((p) => !p)}
              style={{
                marginLeft: "auto",
                padding: "4px 10px",
                borderRadius: 999,
                fontSize: 11,
                fontWeight: 700,
                border: `1px solid ${isPaused ? "var(--red)" : "var(--line-strong)"}`,
                background: isPaused ? "var(--red)" : "var(--panel)",
                color: isPaused ? "#fff" : "var(--text)",
                cursor: "pointer",
              }}
              title="Space to toggle"
            >
              {isPaused ? "▶ Resume" : "⏸ Pause"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={() => setIsFullscreen((f) => !f)}
              style={{
                flex: 1,
                padding: "7px 10px",
                borderRadius: "var(--r)",
                border: "1px solid var(--line-strong)",
                background: isFullscreen ? "var(--accent)" : "var(--panel)",
                color: isFullscreen ? "#fff" : "var(--text)",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
              }}
              title="F to toggle"
            >
              {isFullscreen ? "Exit Fullscreen" : "⛶ Fullscreen"}
            </button>
            <button
              onClick={() => setSoundEnabled((s) => !s)}
              style={{
                padding: "7px 10px",
                borderRadius: "var(--r)",
                border: "1px solid var(--line)",
                background: "var(--panel)",
                fontSize: 12,
                cursor: "pointer",
              }}
              title="Sound on critical changes"
            >
              {soundEnabled ? "🔔 Sound" : "🔕 Muted"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11, color: "var(--dim)" }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: 999,
                  background: recentChangesCount ? "var(--red)" : "var(--green)",
                  boxShadow: recentChangesCount ? "0 0 8px var(--red)" : "none",
                  animation: recentChangesCount ? "pulse 1s infinite" : "none",
                }}
              />
              {recentChangesCount ? `${recentChangesCount} change(s) in last 5m` : "No recent changes"}
            </span>
            <span style={{ marginLeft: "auto" }}>{changes.length ? `Total ${changes.length} detected` : "Watching…"}</span>
          </div>

          <Panel
            frame={false}
            style={{
              padding: "8px 10px",
              display: "flex",
              gap: 10,
              alignItems: "center",
              background: "color-mix(in srgb, var(--bg) 90%, transparent)",
            }}
          >
            <Ring
              pct={Math.min(1, domains.total / 200)}
              label={formatNumber(domains.total)}
              sub="estate"
              tone={hasData ? "green" : "cyan"}
            />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", letterSpacing: "0.06em" }}>TOTAL ESTATE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", lineHeight: 1.4 }}>
                {domains.total} assets · {graph.node_count ?? 0} graph nodes / {graph.edge_count ?? 0} edges
              </div>
              <div style={{ marginTop: 6 }}>
                <Bar value={hasData ? Math.min(1, domains.total / 150) : 0} tone={hasData ? "green" : "cyan"} />
              </div>
              <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>
                {scan ? `${scan.scan_id.slice(0, 8)}… · ${scan.phase.replace(/_/g, " ")}` : "No active scan"}
              </div>
            </div>
          </Panel>
        </div>
      </div>

      {/* KPI STRIP — 4 key health cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginBottom: 12 }}>
        <Panel
          style={{ padding: "12px 14px", borderLeft: `3px solid ${liveDots ? "var(--green)" : "var(--amber)"}` }}
          frame={false}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", color: "var(--faint)" }}>LIVE ENGINE</span>
            <Badge tone={liveDots ? "green" : "amber"}>{liveDots ? "24/7 RUNNING" : isPaused ? "PAUSED" : "IDLE"}</Badge>
          </div>
          <div style={{ fontSize: 18, fontWeight: 800, marginTop: 6, display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: 999,
                background: liveDots ? "var(--green)" : "var(--amber)",
                animation: liveDots ? "pulse 1.2s infinite" : "none",
              }}
            />
            {liveDots ? "Monitoring" : "Standby"}
          </div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>
            Uptime {uptimeLabel} · {rt.connected ? "SSE connected" : "Polling fallback"} · {intervalMs / 1000}s tick
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 999, background: "var(--line)", color: "var(--dim)" }}>
              {events.length} live events
            </span>
            <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 999, background: "var(--line)", color: "var(--dim)" }}>
              {changes.length} changes tracked
            </span>
          </div>
        </Panel>

        <Panel
          style={{ padding: "12px 14px", borderLeft: `3px solid ${scan?.phase === "live_monitoring" ? "var(--green)" : "var(--accent)"}` }}
          frame={false}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", color: "var(--faint)" }}>ORCHESTRATOR</span>
            {scan ? <Badge tone={phaseTone(scan.phase)}>{scan.phase.replace(/_/g, " ")}</Badge> : <Badge tone="">NO SCAN</Badge>}
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, marginTop: 6, fontFamily: "var(--mono)" }}>{scan?.scan_id ?? "—"}</div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>
            {scan ? `${scan.org_name || "—"} · ${timeAgo(scan.started_at)} ago · ${scan.status}` : "Start a scan to begin 24/7 monitoring"}
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
            {scan?.error ? (
              <span style={{ fontSize: 10, color: "var(--red)" }}>{scan.error}</span>
            ) : scan ? (
              <span style={{ fontSize: 10, color: "var(--green)" }}>Scope {scan.scope_validated ? "validated" : "pending"}</span>
            ) : null}
          </div>
        </Panel>

        <Panel
          style={{
            padding: "12px 14px",
            borderLeft: `3px solid ${recentChangesCount ? "var(--red)" : "var(--green)"}`,
          }}
          frame={false}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", color: "var(--faint)" }}>CHANGE DETECTION</span>
            <Badge tone={recentChangesCount ? "red" : "green"}>{recentChangesCount ? `${recentChangesCount} NEW` : "STABLE"}</Badge>
          </div>
          <div style={{ fontSize: 18, fontWeight: 800, marginTop: 6 }}>
            {changes.length === 0 ? "No changes" : `${changes.length} change(s)`}
          </div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>
            {changes[0] ? `Last: ${changes[0].domain} ${changes[0].delta > 0 ? "+" : ""}${changes[0].delta} · ${timeAgo(changes[0].ts)} ago` : "Watching all domains for deltas"}
          </div>
          <div style={{ marginTop: 8 }}>
            <Bar value={Math.min(1, changes.length / 10)} tone={recentChangesCount ? "red" : "green"} />
          </div>
        </Panel>

        <Panel
          style={{ padding: "12px 14px", borderLeft: "3px solid var(--violet)" }}
          frame={false}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", color: "var(--faint)" }}>TECHBOM LIVE</span>
            <Badge tone={techBomTotal ? "green" : ""}>{techBomTotal ? `${formatNumber(techBomTotal)} assets` : "—"}</Badge>
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, marginTop: 6 }}>
            {techBomTotal ? `${Object.keys(techBomLayers).length} layers active` : "Waiting for inventory"}
          </div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>
            {Object.entries(byLayer)
              .map(([k, v]) => `${k} ${v}`)
              .join(" · ") || "No TechBOM yet"}
          </div>
          <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
            {Object.keys(techBomLayers).length ? (
              Object.keys(techBomLayers).map((k) => (
                <span key={k} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 999, background: "var(--line)", color: "var(--dim)" }}>
                  {k}
                </span>
              ))
            ) : (
              <span style={{ fontSize: 10, color: "var(--faint)" }}>TechBOM populates from estate scans</span>
            )}
          </div>
        </Panel>
      </div>

      {/* DOMAIN GRID — 8 live tiles */}
      <Panel title="Infrastructure coverage — live per domain" sub="Every tile is a live domain. Delta badges appear the moment a count changes. Click to inspect.">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
          {domainTiles.map(({ key, value, active, delta = 0 }) => {
            const meta = DOMAIN_META[key] ?? { label: key, icon: IconEstate, color: "var(--faint)", tone: "", to: "#", desc: "" };
            const deltaTone = (delta ?? 0) > 0 ? "green" : (delta ?? 0) < 0 ? "red" : "";
            const DeltaIcon = (delta ?? 0) > 0 ? IconTrendUp : (delta ?? 0) < 0 ? IconTrendDown : IconTrendFlat;
            return (
              <Link
                key={key}
                to={meta.to}
                style={{
                  textDecoration: "none",
                  color: "inherit",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                  padding: "12px 12px",
                  border: `1px solid ${active ? "var(--line-strong)" : "var(--line)"}`,
                  borderRadius: "var(--r)",
                  background: active ? "color-mix(in srgb, var(--bg) 70%, transparent)" : "transparent",
                  opacity: active ? 1 : 0.6,
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                {/* accent top bar */}
                <span
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    right: 0,
                    height: 2,
                    background: meta.color,
                    opacity: active ? 1 : 0.4,
                  }}
                />
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: meta.color, lineHeight: 0 }}>
                    <meta.icon size={20} />
                  </span>
                  <span style={{ fontWeight: 700, fontSize: 12 }}>{meta.label}</span>
                  <span
                    style={{
                      marginLeft: "auto",
                      width: 7,
                      height: 7,
                      borderRadius: 999,
                      background: active ? "var(--green)" : "var(--faint)",
                      boxShadow: active && liveDots ? "0 0 6px var(--green)" : "none",
                    }}
                  />
                </div>
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <span style={{ fontSize: 22, fontWeight: 800, fontFamily: "var(--mono)" }}>{formatNumber(value)}</span>
                  {delta !== 0 && delta !== undefined && (
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        padding: "1px 6px",
                        borderRadius: 999,
                        background: deltaTone === "green" ? "color-mix(in srgb, var(--green) 18%, transparent)" : "color-mix(in srgb, var(--red) 18%, transparent)",
                        color: deltaTone === "green" ? "var(--green)" : "var(--red)",
                        border: `1px solid ${deltaTone === "green" ? "var(--green)" : "var(--red)"}`,
                      }}
                    >
                      <DeltaIcon size={12} /> {delta > 0 ? `+${delta}` : delta}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.4 }}>{meta.desc}</div>
                <div style={{ marginTop: "auto", display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "var(--dim)" }}>
                  <span style={{ width: 6, height: 6, borderRadius: 999, background: active ? "var(--green)" : "var(--line-strong)" }} />
                  {active ? "LIVE" : "IDLE"} · {value ? "tracked" : "awaiting data"}
                </div>
              </Link>
            );
          })}
        </div>

        {/* estate composition bar */}
        <div style={{ marginTop: 14, padding: "10px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, fontWeight: 600, color: "var(--dim)", marginBottom: 6 }}>
            <span>ESTATE COMPOSITION</span>
            <span style={{ fontFamily: "var(--mono)" }}>{domains.total} total</span>
          </div>
          <div style={{ display: "flex", height: 10, borderRadius: 999, overflow: "hidden", background: "var(--line)" }}>
            {[
              { k: "network", v: domains.network, c: "var(--cyan)" },
              { k: "hardware", v: domains.hardware, c: "var(--amber)" },
              { k: "crypto", v: domains.crypto, c: "var(--green)" },
              { k: "vendor", v: domains.vendor, c: "var(--violet)" },
              { k: "application", v: domains.application, c: "var(--accent)" },
              { k: "certificate", v: domains.certificate, c: "var(--red)" },
            ].map((s) => {
              const pct = domains.total ? (s.v / domains.total) * 100 : 0;
              if (!pct) return null;
              return <span key={s.k} title={`${s.k} ${s.v}`} style={{ width: `${pct}%`, background: s.c }} />;
            })}
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 6, fontSize: 10, color: "var(--dim)" }}>
            {[
              { k: "Network", c: "var(--cyan)" },
              { k: "Hardware", c: "var(--amber)" },
              { k: "Crypto", c: "var(--green)" },
              { k: "Vendor", c: "var(--violet)" },
              { k: "Software", c: "var(--accent)" },
              { k: "Certs", c: "var(--red)" },
            ].map((l) => (
              <span key={l.k} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: l.c }} /> {l.k}
              </span>
            ))}
          </div>
        </div>
      </Panel>

      {/* SCAN ORCHESTRATOR — expanded */}
      <Panel title="Scan orchestrator — 24/7 runner" sub="One global scan id · phase state machine · per-scanner progress · survives restarts">
        {scan ? (
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-start" }}>
            <div style={{ minWidth: 200 }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", color: "var(--faint)" }}>GLOBAL SCAN ID</div>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 800, fontSize: 16, marginTop: 2 }}>{scan.scan_id}</div>
              <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>{scan.org_name || "—"} · started {timeAgo(scan.started_at)} ago</div>
              <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                <Badge tone={phaseTone(scan.phase)}>{scan.phase.replace(/_/g, " ")}</Badge>
                <Badge tone={scan.status === "running" ? "green" : scan.status === "completed" ? "green" : "amber"}>{scan.status}</Badge>
                {scan.scope_validated && <Badge tone="green">scope validated</Badge>}
              </div>
            </div>

            <div style={{ flex: "1 1 320px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 10 }}>
              {Object.entries(scan.progress || {}).length ? (
                Object.entries(scan.progress)
                  .slice(0, 12)
                  .map(([k, v]) => (
                    <div key={k} style={{ padding: "8px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel)" }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--faint)", textTransform: "uppercase" }}>{k}</div>
                      <div style={{ height: 6, background: "var(--line)", borderRadius: 999, overflow: "hidden", marginTop: 6 }}>
                        <div style={{ width: `${v}%`, height: "100%", background: v >= 100 ? "var(--green)" : "var(--accent)", transition: "width 400ms ease" }} />
                      </div>
                      <div style={{ fontSize: 11, fontWeight: 700, marginTop: 4, fontFamily: "var(--mono)" }}>{v}%</div>
                    </div>
                  ))
              ) : (
                <div style={{ fontSize: 12, color: "var(--dim)", padding: "10px 0" }}>Awaiting first scanner heartbeat…</div>
              )}
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 160 }}>
              <button onClick={startScan} disabled={starting} className="btn btn-primary" style={{ padding: "8px 14px", opacity: starting ? 0.6 : 1 }}>
                {starting ? "Starting…" : "Restart scan"}
              </button>
              <div style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.4, textAlign: "center" }}>Runner {scan ? (status.data as any)?.runner?.running ? "● running" : "○ idle" : "—"} · History {runs.length} runs</div>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ flex: 1, fontSize: 13, color: "var(--dim)" }}>
              {(status as any)?.source === "live"
                ? "No integrated scan yet — start one to discover the authorized scope in one pass and enter live_monitoring."
                : "Backend offline — orchestrator unavailable."}
            </div>
            <button onClick={startScan} disabled={starting} className="btn btn-primary" style={{ padding: "8px 14px" }}>
              {starting ? "Starting…" : "Start integrated scan"}
            </button>
          </div>
        )}
      </Panel>

      {/* MAIN GRID — changes + live events + graph */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 12, marginTop: 12 }}>
        {/* CHANGE TIMELINE */}
        <Panel
          title={`Change detection — live timeline`}
          sub={`${changes.length} change(s) tracked · deltas computed every ${intervalMs / 1000}s · most recent first`}
        >
          {changes.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto", paddingRight: 4 }}>
              {changes.map((c) => {
                const meta = DOMAIN_META[c.domain] ?? { label: c.domain, icon: IconEstate, color: "var(--faint)", tone: "", to: "#", desc: "" };
                return (
                  <div
                    key={c.id}
                    style={{
                      display: "flex",
                      gap: 10,
                      alignItems: "center",
                      padding: "8px 10px",
                      border: "1px solid var(--line)",
                      borderRadius: "var(--r)",
                      background:
                        c.severity === "critical"
                          ? "color-mix(in srgb, var(--red) 8%, var(--panel))"
                          : c.severity === "warn"
                            ? "color-mix(in srgb, var(--amber) 6%, var(--panel))"
                            : "var(--panel)",
                    }}
                  >
                    <span style={{ color: meta.color, lineHeight: 0 }}>
                      <meta.icon size={16} />
                    </span>
                    <span style={{ fontWeight: 700, fontSize: 12, minWidth: 80 }}>{meta.label}</span>
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: 11,
                        padding: "2px 7px",
                        borderRadius: 999,
                        background: c.delta > 0 ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--red) 14%, transparent)",
                        color: c.delta > 0 ? "var(--green)" : "var(--red)",
                        border: `1px solid ${c.delta > 0 ? "var(--green)" : "var(--red)"}`,
                        fontWeight: 700,
                      }}
                    >
                      {c.delta > 0 ? `+${c.delta}` : c.delta} · {c.from} → {c.to}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--dim)", marginLeft: "auto" }}>{timeAgo(c.ts)} ago</span>
                    <Badge tone={c.severity === "critical" ? "red" : c.severity === "warn" ? "amber" : "green"}>{c.severity}</Badge>
                  </div>
                );
              })}
            </div>
          ) : (
            <div
              style={{
                padding: "18px 12px",
                textAlign: "center",
                color: "var(--faint)",
                fontSize: 12,
                border: "1px dashed var(--line)",
                borderRadius: "var(--r)",
                background: "var(--panel)",
              }}
            >
              No deltas yet — estate is stable. New assets, certs, crypto, or vendor entries will appear here within {intervalMs / 1000}s of being observed.
            </div>
          )}
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 8, textAlign: "center" }}>
            Tip: Press <b>Space</b> to pause · <b>F</b> for fullscreen · Change detection is local delta (poll-to-poll), not just server events.
          </div>
        </Panel>

        {/* LIVE EVENTS */}
        <Panel title="Live events — real state changes streamed over SSE" sub={`${events.length} newest · backend ${rt.connected ? "SSE LIVE" : "polling"} · topology below`}>
          {events.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {events.map((e: any) => (
                <div key={e.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "7px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel)" }}>
                  <Badge tone={sevTone(severityOf(e.type))}>{severityOf(e.type)}</Badge>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.type}</span>
                  <span style={{ fontSize: 11, color: "var(--dim)" }}>{timeAgo(e.ts)}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: "var(--faint)", padding: "14px", textAlign: "center", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
              {rt.connected ? "No live events yet — run a scan." : "Backend offline — no event stream."}
            </div>
          )}
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 8 }}>
            {(env as any)?.events?.events?.length ? `${(env as any).events.events.length} retained estate events sampled${(env as any).events.has_more ? " · more pages available" : ""}` : "All estate changes are persisted to the event log"}
          </div>

          <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--faint)", letterSpacing: "0.06em", marginBottom: 8 }}>DEPENDENCY TOPOLOGY</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 6, fontSize: 11 }}>
              {Object.entries(graph.by_kind ?? {}).map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 8px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                  <span style={{ fontFamily: "var(--mono)", color: "var(--dim)" }}>{k}</span>
                  <span style={{ fontWeight: 700 }}>{String(v)}</span>
                </div>
              ))}
              {!Object.keys(graph.by_kind ?? {}).length && <span style={{ fontSize: 11, color: "var(--faint)", gridColumn: "1 / -1" }}>No graph yet — populate via onboarding scope + discovery.</span>}
            </div>
            <Link to="/graph" style={{ fontSize: 11, display: "inline-block", marginTop: 8, color: "var(--accent)", fontFamily: "var(--mono)" }}>
              open full dependency graph →
            </Link>
          </div>
        </Panel>
      </div>

      {/* HISTORY + TECHBOM FOOTER */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 12, marginTop: 12 }}>
        <Panel title="Scan run history — durable 24/7 log" sub={`${runs.length} runs · survives restarts · visible from any worker`}>
          {runs.length ? (
            <div style={{ maxHeight: 280, overflowY: "auto" }}>
              <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ color: "var(--faint)", textAlign: "left" }}>
                    <th style={{ padding: "6px 6px", fontWeight: 600 }}>Run</th>
                    <th style={{ padding: "6px 6px", fontWeight: 600 }}>Phase</th>
                    <th style={{ padding: "6px 6px", fontWeight: 600 }}>Status</th>
                    <th style={{ padding: "6px 6px", fontWeight: 600 }}>Started</th>
                    <th style={{ padding: "6px 6px", fontWeight: 600 }}>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(0, 8).map((r) => (
                    <tr key={r.scan_id} style={{ borderTop: "1px solid var(--line)" }}>
                      <td style={{ padding: "6px 6px", fontFamily: "var(--mono)", fontWeight: 600 }}>{r.scan_id.slice(0, 12)}…</td>
                      <td style={{ padding: "6px 6px" }}>
                        <Badge tone={phaseTone(r.phase ?? "completed")}>{(r.phase ?? "—").replace(/_/g, " ")}</Badge>
                      </td>
                      <td style={{ padding: "6px 6px" }}>
                        <Badge tone={r.status === "completed" ? "green" : r.status === "failed" ? "red" : "amber"}>{r.status}</Badge>
                      </td>
                      <td style={{ padding: "6px 6px", color: "var(--dim)" }}>{r.started_at ? timeAgo(r.started_at) : "—"}</td>
                      <td style={{ padding: "6px 6px", color: "var(--dim)" }}>
                        {r.started_at && r.ended_at ? `${Math.max(0, Math.round((new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()) / 1000))}s` : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: "var(--faint)", padding: "10px", textAlign: "center", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
              {(history as any)?.source === "live" ? "No integrated scans yet — start one above to record history." : "Backend offline — run history unavailable."}
            </div>
          )}
        </Panel>

        <Panel title="TechBOM live — unified asset truth" sub={`${techBomTotal} total components · ${Object.keys(techBomLayers).length} layers · poll ${intervalMs / 1000}s · click to open`}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(100px, 1fr))", gap: 8 }}>
            {[
              { k: "sbom", label: "Software", to: "/sbom" },
              { k: "cbom", label: "Crypto", to: "/cbom" },
              { k: "hbom", label: "Hardware", to: "/hbom" },
              { k: "nbom", label: "Network", to: "/nbom" },
              { k: "vendor", label: "Vendors", to: "/vbom" },
              { k: "certificates", label: "Certs", to: "/certificates" },
            ].map((l) => {
              const v = byLayer[l.k] ?? techBomLayers[l.k]?.count ?? 0;
              return (
                <Link
                  key={l.k}
                  to={l.to}
                  style={{
                    textDecoration: "none",
                    padding: "8px 10px",
                    border: "1px solid var(--line)",
                    borderRadius: "var(--r)",
                    background: (v as number) > 0 ? "var(--panel)" : "transparent",
                    opacity: (v as number) > 0 ? 1 : 0.6,
                  }}
                >
                  <div style={{ fontSize: 10, fontWeight: 700, color: "var(--faint)", letterSpacing: "0.06em" }}>{l.label.toUpperCase()}</div>
                  <div style={{ fontSize: 16, fontWeight: 800, fontFamily: "var(--mono)", marginTop: 2 }}>{String(v)}</div>
                  <div style={{ height: 3, background: "var(--line)", borderRadius: 999, marginTop: 6, overflow: "hidden" }}>
                    <span style={{ display: "block", width: `${techBomTotal ? (Math.min(100, ((v as number) / Math.max(1, techBomTotal)) * 100)) : 0}%`, height: "100%", background: "var(--violet)" }} />
                  </div>
                </Link>
              );
            })}
          </div>
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 8, textAlign: "center" }}>
            Correlation graph · {graph.node_count ?? 0} nodes / {graph.edge_count ?? 0} edges · {graph.backend ? `backend ${graph.backend}` : "backend (in-memory)"} · {graph.by_kind ? Object.entries(graph.by_kind).map(([k, v]) => `${k} ${v}`).join(" · ") : "no by_kind yet"}
          </div>
          {!hasData && (
            <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 8, padding: "8px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel)" }}>
              Hierarchy populates from onboarding scope and discovery. Configure your estate in <Link to="/onboarding">Onboarding</Link>, then run an integrated scan.
            </div>
          )}
        </Panel>
      </div>

      <style>{`@keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(1.08); } 100% { opacity: 1; transform: scale(1); } }`}</style>
    </div>
  );
}
