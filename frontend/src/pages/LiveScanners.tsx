import React, { useEffect, useMemo, useRef, useState } from "react";
import { Panel, Badge, Table, PageHead, Kpi } from "../components/ui.jsx";
import {
  apiLiveScanStatus, apiLiveScanRun, apiLiveScanStart, apiLiveScanStop,
  LiveScanStatus,
} from "../lib/api.js";
import { useRealtime } from "../lib/realtime.jsx";

/* Realtime scanners — drives the actual CryptoScan scanner CLIs server-side
   and shows them live. Every number comes from a real scan (hardware /
   runtime / network / container / OT). Progress streams over SSE as
   live_scan.* events; the snapshot also polls as a backstop. There is no
   simulated data: scanners that cannot run show an honest error. */

interface LogLine { ts: string; text: string; tone: "start" | "ok" | "fail" | "info" }

const SCANNER_LABEL: Record<string, string> = {
  hardware: "Hardware (CPU / TPM / HSM)",
  runtime: "Runtime host crypto",
  network: "Network TLS probe",
  container: "Container / image",
  ot: "OT / ICS (passive logs)",
  cloud: "Cloud (read-only live)",
  source: "Static source (crypto API)",
  universal: "Universal crypto",
};

const HOST_SCANNERS = ["hardware", "runtime"];
// services that only run when a target/flag is supplied
const TARGET_SCANNERS = ["network", "container", "ot", "cloud", "source", "universal"];

function kv(summary: Record<string, unknown> | undefined): Array<[string, unknown]> {
  if (!summary) return [];
  return Object.entries(summary).filter(([, v]) => v !== null && v !== undefined && v !== "");
}

function TgtInput({ label, value, onChange, ph }: {
  label: string; value: string; onChange: (v: string) => void; ph?: string;
}) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12 }}>
      {label}
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} />
    </label>
  );
}

export default function LiveScanners() {
  const realtime = useRealtime();
  const [status, setStatus] = useState<LiveScanStatus | null>(null);
  const [source, setSource] = useState<"live" | "offline">("offline");
  const [netTarget, setNetTarget] = useState("");
  const [netFull, setNetFull] = useState(true);
  const [cloudLive, setCloudLive] = useState(false);
  const [containerTarget, setContainerTarget] = useState("");
  const [otTarget, setOtTarget] = useState("");
  const [sourceTarget, setSourceTarget] = useState("");
  const [universalTarget, setUniversalTarget] = useState("");
  const [intervalS, setIntervalS] = useState(900);
  const [log, setLog] = useState<LogLine[]>([]);
  const logRef = useRef<LogLine[]>([]);
  const seenIds = useRef<Set<number>>(new Set());

  const pushLog = (text: string, tone: LogLine["tone"]) => {
    const line = { ts: new Date().toLocaleTimeString(), text, tone };
    logRef.current = [...logRef.current.slice(-80), line];
    setLog(logRef.current);
  };

  const refresh = async () => {
    const r = await apiLiveScanStatus();
    setSource(r.source);
    if (r.data) setStatus(r.data as LiveScanStatus);
  };

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, []);

  // Stream live_scan.* events from SSE into the activity log + trigger refresh.
  useEffect(() => {
    for (const ev of realtime.events) {
      if (seenIds.current.has(ev.id)) continue;
      // Accept both direct events (live_scan.*) and the durable/tailer-federated
      // form from other API workers (monitor.live_scan_*).
      let type = ev.type;
      if (type.startsWith("monitor.live_scan_")) {
        type = "live_scan." + type.slice("monitor.live_scan_".length);
      }
      if (!type.startsWith("live_scan.")) continue;
      seenIds.current.add(ev.id);
      const p = ev.payload || {};
      if (type === "live_scan.started") {
        pushLog(`scan started (${p.trigger || "?"}) — ${((p.scanners as string[]) || []).join(", ")}`, "start");
      } else if (type === "live_scan.scanner_started") {
        pushLog(`▶ ${SCANNER_LABEL[p.scanner as string] || p.scanner} …`, "info");
      } else if (type === "live_scan.scanner_completed") {
        if (p.ok) pushLog(`✓ ${SCANNER_LABEL[p.scanner as string] || p.scanner} in ${p.elapsed_s}s`, "ok");
        else pushLog(`✗ ${SCANNER_LABEL[p.scanner as string] || p.scanner}: ${p.error || "failed"}`, "fail");
      } else if (type === "live_scan.completed") {
        pushLog(`cycle complete — ${p.ok} ok, ${p.failed} failed in ${p.elapsed_s}s`, p.failed ? "fail" : "ok");
        refresh();
      } else if (type === "live_scan.error") {
        pushLog(`error: ${p.error}`, "fail");
      }
    }
  }, [realtime.events]);

  const runNow = async () => {
    const scanners = [...HOST_SCANNERS];
    if (netTarget.trim()) scanners.push("network");
    if (cloudLive) scanners.push("cloud");
    if (containerTarget.trim()) scanners.push("container");
    if (otTarget.trim()) scanners.push("ot");
    if (sourceTarget.trim()) scanners.push("source");
    if (universalTarget.trim()) scanners.push("universal");
    pushLog(`requesting scan: ${scanners.join(", ")} …`, "start");
    const r = await apiLiveScanRun({
      scanners,
      network_target: netTarget.trim() || undefined,
      network_full: netFull,
      cloud_live: cloudLive || undefined,
      container_target: containerTarget.trim() || undefined,
      ot_logs: otTarget.trim() || undefined,
      source_target: sourceTarget.trim() || undefined,
      universal_target: universalTarget.trim() || undefined,
    });
    if (r.source === "offline") pushLog(`could not start: ${r.error || "backend unreachable"}`, "fail");
  };

  const startLoop = async () => {
    const r = await apiLiveScanStart(intervalS);
    pushLog(r.source === "live" ? `periodic loop started (every ${intervalS}s)` : `start failed: ${r.error}`,
      r.source === "live" ? "ok" : "fail");
    refresh();
  };
  const stopLoop = async () => {
    await apiLiveScanStop();
    pushLog("periodic loop stopping", "info");
    refresh();
  };

  const scannerRows = useMemo(() => {
    const keys = new Set([
      ...Object.keys(status?.scanners || {}),
      ...HOST_SCANNERS, ...TARGET_SCANNERS,
    ]);
    return Array.from(keys).map((key) => {
      const s = status?.scanners?.[key];
      return {
        key,
        label: SCANNER_LABEL[key] || key,
        ok: s?.ok,
        elapsed: s?.elapsed_s,
        summary: s?.summary,
        error: s?.error,
      };
    });
  }, [status]);

  const toneFor = (ok: boolean | null | undefined): "green" | "red" | "amber" | "" =>
    ok === true ? "green" : ok === false ? "red" : "";

  return (
    <>
      <PageHead
        crumb="Operations / Realtime scanners"
        title="Realtime scanners"
        sub="Live, deterministic scan execution. Results stream over SSE as the real scanners run — no simulated data."
        right={
          <Badge tone={realtime.connected ? "green" : "amber"}>
            {realtime.connected ? "● SSE connected" : source === "live" ? "○ SSE offline (polling)" : "○ backend offline"}
          </Badge>
        }
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, margin: "14px 0" }}>
        <Kpi k="Cycle running" v={status?.running ? "yes" : "idle"} tone={status?.running ? "cyan" : ""} />
        <Kpi k="Last cycle" v={status?.last_run_at ? new Date(status.last_run_at).toLocaleTimeString() : "—"} />
        <Kpi k="Scanners OK" v={status?.ok_count ?? 0} tone="green" />
        <Kpi k="Scanners failed" v={status?.failed_count ?? 0} tone={(status?.failed_count ?? 0) ? "red" : ""} />
      </div>

      <Panel
        title="Run a live scan"
        sub="Hardware + runtime always run. Fill a target to include that service; leave blank to skip."
      >
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          <TgtInput label="Network TLS target" value={netTarget} onChange={setNetTarget} ph="example.com:443" />
          <TgtInput label="Container / image / rootfs" value={containerTarget} onChange={setContainerTarget} ph="nginx:latest or /host/rootfs" />
          <TgtInput label="OT / ICS passive logs" value={otTarget} onChange={setOtTarget} ph="/var/log/ot  (file or dir)" />
          <TgtInput label="Static source dir" value={sourceTarget} onChange={setSourceTarget} ph="/path/to/source" />
          <TgtInput label="Universal crypto source" value={universalTarget} onChange={setUniversalTarget} ph="/path/to/source" />
          <label style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12, justifyContent: "flex-end" }}>
            <span style={{ opacity: 0.8 }}>Options</span>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={netFull} onChange={(e) => setNetFull(e.target.checked)} />
              network full (OCSP + renegotiation)
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={cloudLive} onChange={(e) => setCloudLive(e.target.checked)} />
              cloud live (read-only, needs creds)
            </label>
          </label>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginTop: 14 }}>
          <button className="btn" onClick={runNow} disabled={status?.running}>
            {status?.running ? "scan running…" : "Run scan now"}
          </button>
          <span style={{ flex: 1 }} />
          <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12 }}>
            Interval (s)
            <input type="number" value={intervalS} min={30}
              onChange={(e) => setIntervalS(Number(e.target.value) || 900)} style={{ width: 100 }} />
          </label>
          <button className="btn" onClick={startLoop} disabled={status?.periodic?.enabled}>
            {status?.periodic?.enabled ? `loop on (${status.periodic.interval_seconds}s)` : "Start live loop"}
          </button>
          <button className="btn sm" onClick={stopLoop} disabled={!status?.periodic?.enabled}>Stop</button>
        </div>
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 14, marginTop: 14 }}>
        <Panel title="Scanner results" sub="From the most recent live cycle.">
          <Table
            head={["Scanner", "Status", "Elapsed", "Key facts"]}
            rows={scannerRows.map((r) => [
              r.label,
              <Badge tone={toneFor(r.ok)}>
                {r.ok === true ? "OK" : r.ok === false ? "FAILED" : "not run yet"}
              </Badge>,
              r.elapsed != null ? `${r.elapsed}s` : "—",
              r.ok === false
                ? <span style={{ color: "var(--red,#d36a6a)" }}>{r.error}</span>
                : <span style={{ fontSize: 12, opacity: 0.85 }}>
                    {kv(r.summary).map(([k, v]) => `${k}=${String(v)}`).join("  ·  ") || "—"}
                  </span>,
            ])}
          />
        </Panel>

        <Panel title="Live activity" sub="Streamed from the scanners via SSE.">
          <div style={{ fontFamily: "monospace", fontSize: 12, lineHeight: 1.7, maxHeight: 320, overflowY: "auto" }}>
            {log.length === 0 && <div style={{ opacity: 0.6 }}>No scan activity yet — run a scan.</div>}
            {log.map((l, i) => (
              <div key={i} style={{
                color: l.tone === "ok" ? "var(--green,#6abf8a)"
                  : l.tone === "fail" ? "var(--red,#d36a6a)"
                  : l.tone === "start" ? "var(--cyan,#6ab0d3)" : "inherit",
              }}>
                <span style={{ opacity: 0.5 }}>{l.ts}</span>  {l.text}
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  );
}
