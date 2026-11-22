import React, { useEffect, useMemo, useRef, useState } from "react";
import { parseWhen } from "./opsUi";
import { Panel, Badge, PageHead } from "./ui.jsx";
import { RequireRole } from "../lib/auth.jsx";
import { SCAN_OPERATE_ROLES } from "../lib/rbac.jsx";
import {
  apiLiveScanStatus, apiLiveScanRun, apiLiveScanStart, apiLiveScanStop,
  LiveScanStatus,
} from "../lib/api.js";
import { useRealtime } from "../lib/realtime.jsx";
import { ICON_SM, IconRunning, StatusMark } from "./icons";
import { HBars, Sparkline, StackedBar, StateCell, TickStrip, VizEmpty } from "./viz";

/* Realtime scanners — drives the actual CryptoScan scanner CLIs server-side
   and shows them live. Every number comes from a real scan (hardware /
   runtime / network / container / OT). Progress streams over SSE as
   live_scan.* events; the snapshot also polls as a backstop. There is no
   simulated data: scanners that cannot run show an honest error.

   Visualisation rule: the fleet view draws each scanner's own reported result
   and its own reported elapsed seconds, scaled to the slowest scanner *in that
   cycle*. The cycle record below it only holds cycles this screen actually
   observed — it is not a back-filled history, and it says so. */

interface LogLine { ts: string; text: string; tone: "start" | "ok" | "fail" | "info" }

/** One completed cycle, as observed by this screen (SSE event or poll delta). */
interface ObservedCycle {
  key: string;
  ts: string;
  ok: number | null;
  failed: number | null;
  elapsed: number | null;
}

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
      <input className="inp" value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} />
    </label>
  );
}

export default function ServerScanners({ embedded = false }: { embedded?: boolean } = {}) {
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
  const [cycles, setCycles] = useState<ObservedCycle[]>([]);
  const logRef = useRef<LogLine[]>([]);
  const seenIds = useRef<Set<number>>(new Set());
  const seenCycleKeys = useRef<Set<string>>(new Set());

  const pushLog = (text: string, tone: LogLine["tone"]) => {
    const line = { ts: new Date().toLocaleTimeString(), text, tone };
    logRef.current = [...logRef.current.slice(-80), line];
    setLog(logRef.current);
  };

  const pushCycle = (cycle: ObservedCycle) => {
    if (seenCycleKeys.current.has(cycle.key)) return;
    seenCycleKeys.current.add(cycle.key);
    setCycles((prev) => [...prev, cycle].slice(-60));
  };

  const refresh = async () => {
    const r = await apiLiveScanStatus();
    setSource(r.source);
    if (r.data) {
      const next = r.data as LiveScanStatus;
      setStatus(next);
      // A new last_run_at is a cycle this screen did not see the event for
      // (opened late, or the stream was down). Record it as observed-without-
      // event, with no elapsed time — the snapshot does not carry one.
      if (next.last_run_at) {
        pushCycle({
          key: `poll-${next.last_run_at}`,
          ts: next.last_run_at,
          ok: typeof next.ok_count === "number" ? next.ok_count : null,
          failed: typeof next.failed_count === "number" ? next.failed_count : null,
          elapsed: null,
        });
      }
    }
  };

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 4000);
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
        pushCycle({
          key: `sse-${ev.ts ?? ev.id}`,
          ts: ev.ts ?? new Date().toISOString(),
          ok: typeof p.ok === "number" ? p.ok : null,
          failed: typeof p.failed === "number" ? p.failed : null,
          elapsed: typeof p.elapsed_s === "number" ? p.elapsed_s : null,
        });
        void refresh();
      } else if (type === "live_scan.error") {
        pushLog(`error: ${p.error}`, "fail");
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    /* A 202 is the only proof the cycle was accepted. The old branch logged
       nothing on success, and a refused request (422 for an unknown family,
       403 for a role that may not start scans) looked identical to a start
       that had silently done nothing. */
    if (r.source === "offline") {
      pushLog(`could not start: ${r.detail || r.error || "backend unreachable"}`, "fail");
    } else {
      const st = String((r.data as { status?: string } | null)?.status ?? "started");
      pushLog(
        st === "already_running"
          ? "a cycle is already running — this request did not start a second one"
          : `accepted (${st}) — the runner reports progress over SSE`,
        st === "already_running" ? "info" : "ok",
      );
    }
  };

  const startLoop = async () => {
    const r = await apiLiveScanStart(intervalS);
    pushLog(r.source === "live" ? `periodic loop started (every ${intervalS}s)` : `start failed: ${r.error}`,
      r.source === "live" ? "ok" : "fail");
    void refresh();
  };
  const stopLoop = async () => {
    const r = await apiLiveScanStop();
    pushLog(
      r.source === "live" ? "periodic loop stopping" : `stop failed: ${r.detail || r.error || "backend unreachable"}`,
      r.source === "live" ? "info" : "fail",
    );
    void refresh();
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
        ok: s?.ok as boolean | null | undefined,
        elapsed: typeof s?.elapsed_s === "number" ? s.elapsed_s : null,
        summary: s?.summary,
        error: s?.error,
      };
    });
  }, [status]);

  // Fleet split for the last cycle: reported ok, reported failed, and the
  // scanners that returned no result at all (not the same as passing).
  const fleet = useMemo(() => {
    const ok = scannerRows.filter((r) => r.ok === true).length;
    const failed = scannerRows.filter((r) => r.ok === false).length;
    const silent = scannerRows.filter((r) => r.ok === undefined || r.ok === null).length;
    return { ok, failed, silent, total: scannerRows.length };
  }, [scannerRows]);

  const slowest = Math.max(1, ...scannerRows.map((r) => r.elapsed ?? 0));
  const okCount = status && typeof status.ok_count === "number" ? status.ok_count : null;
  const failedCount = status && typeof status.failed_count === "number" ? status.failed_count : null;

  // Which scanners this form will actually request, given the current inputs.
  const requested = [
    ...HOST_SCANNERS,
    ...(netTarget.trim() ? ["network"] : []),
    ...(cloudLive ? ["cloud"] : []),
    ...(containerTarget.trim() ? ["container"] : []),
    ...(otTarget.trim() ? ["ot"] : []),
    ...(sourceTarget.trim() ? ["source"] : []),
    ...(universalTarget.trim() ? ["universal"] : []),
  ];

  const cycleOk = cycles.map((c) => c.ok);
  const cycleFailed = cycles.map((c) => c.failed);
  const cycleElapsed = cycles.map((c) => c.elapsed);
  const worst = cycles.reduce<"info" | "warn" | "critical">((acc, c) => {
    if (c.failed === null) return acc;
    if (c.failed > 0) return "warn";
    return acc;
  }, "info");

  return (
    <>
      {!embedded && (
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
      )}

      {/* ── cycle state board ─────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, margin: "14px 0" }}>
        <StateCell
          label="Cycle"
          value={status ? (status.running ? "RUNNING" : "idle") : "Not observed"}
          tone={status ? (status.running ? "green" : "slate") : "slate"}
          note={status?.periodic?.enabled ? `loop every ${status.periodic.interval_seconds}s` : "no periodic loop"}
        />
        <StateCell
          label="Last cycle"
          value={parseWhen(status?.last_run_at)?.toLocaleTimeString() ?? "—"}
          tone={status?.last_run_at ? "accent" : "slate"}
          note={parseWhen(status?.last_run_at)?.toLocaleDateString() ?? "no completed cycle"}
        />
        <StateCell label="Scanners OK" value={okCount ?? "—"} tone={okCount ? "green" : "slate"} note="last cycle, reported" />
        <StateCell label="Scanners failed" value={failedCount ?? "—"} tone={failedCount ? "red" : "slate"} note="blocked/unconfigured excluded" />
        <StateCell label="Cycles observed here" value={cycles.length} tone={cycles.length ? "accent" : "slate"} note="since this screen opened" />
      </div>

      {/* ── fleet + cycle record ──────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 12 }}>
        <Panel
          title="Scanner fleet"
          sub={status?.running
            ? "cycle in progress — bars are the last reported elapsed time"
            : "from the most recent live cycle; bar length is relative to the slowest scanner in it"}
        >
          <div style={{ marginBottom: 10 }}>
            <StackedBar
              segments={[
                { key: "ok", label: "reported ok", value: fleet.ok, tone: "green" },
                { key: "failed", label: "reported failed", value: fleet.failed, tone: "red" },
                { key: "silent", label: "no result", value: fleet.silent, tone: "slate" },
              ]}
              note="Runner result for every scanner this page can drive. “No result” means the scanner reported nothing — it is not a pass."
            />
          </div>

          {scannerRows.filter((r) => r.ok !== undefined && r.ok !== null).length === 0 && !status?.running ? (
            <VizEmpty
              title="No scanner result recorded"
              note="Hardware and runtime run without a target; add a target below to include network / container / OT / source scans."
              height={72}
            />
          ) : (
            <div className="scan-prog">
              {scannerRows.map((r) => {
                const isRunning = status?.running && (r.ok === undefined || r.ok === null);
                const failed = r.ok === false;
                const cls = isRunning ? "is-running" : failed ? "is-failed" : r.ok === true ? "is-ok" : "";
                const facts = r.ok === false
                  ? r.error
                  : kv(r.summary).map(([k, v]) => `${k}=${String(v)}`).join("  ·  ");
                return (
                  <div key={r.key} className={`scan-row ${cls}`} style={{ alignItems: "stretch" }}>
                    <div className="s-ico">{isRunning ? <IconRunning size={ICON_SM} /> : <StatusMark ok={failed ? false : r.ok === true ? true : null} muted />}</div>
                    <div className="s-meta" style={{ flex: 1, minWidth: 0 }}>
                      <div className="s-name">{r.label}</div>
                      {facts && <div className="s-detail">{facts}</div>}
                      {/* elapsed bar: only when the runner reported seconds */}
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 5 }}>
                        <span style={{ flex: 1, height: 5, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1, overflow: "hidden" }}>
                          <span
                            style={{
                              display: "block",
                              height: "100%",
                              width: r.elapsed === null ? "0%" : `${Math.max(2, (r.elapsed / slowest) * 100)}%`,
                              background: failed ? "var(--red)" : r.ok === true ? "var(--green)" : "var(--slate)",
                            }}
                          />
                        </span>
                        <span className="mono" style={{ fontSize: 10, color: "var(--faint)", minWidth: 46, textAlign: "right" }}>
                          {r.elapsed === null ? "no time" : `${r.elapsed.toFixed(2)}s`}
                        </span>
                      </div>
                    </div>
                    <div className="s-right">
                      {isRunning
                        ? <Badge tone="cyan"><span className="dot pulse" /> scanning</Badge>
                        : r.ok === false
                          ? <Badge tone="red">failed</Badge>
                          : r.ok === true
                            ? <Badge tone="green">ok</Badge>
                            : <Badge tone="slate">no result</Badge>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <div>
          <Panel
            title="Cycle record"
            sub={`${cycles.length} cycle(s) observed since this screen opened · not a stored history`}
          >
            <div style={{ marginBottom: 10 }}>
              <TickStrip
                ticks={cycles.map((c) => ({
                  ts: parseWhen(c.ts)?.toLocaleTimeString() ?? "—",
                  severity: c.failed && c.failed > 0 ? "warn" : "info",
                }))}
                label="Cycles by outcome"
                emptyNote="No cycle has completed while this screen was open."
              />
            </div>
            {cycles.length >= 2 ? (
              <Sparkline
                series={cycleElapsed}
                label="Cycle duration (s)"
                tone="accent"
                height={54}
                format={(n) => `${n}s`}
                emptyNote="Duration comes from the cycle-completed event; cycles seen only through the status snapshot carry no duration."
              />
            ) : (
              <VizEmpty
                title="Cycle duration — no samples"
                note="Two completed cycles are needed before a duration line means anything."
                height={54}
              />
            )}
            <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--line)" }}>
              <HBars
                rows={[
                  { key: "ok", label: "best cycle ok", value: cycleOk.reduce<number>((a, b) => Math.max(a, b ?? 0), 0), tone: "green" },
                  { key: "failed", label: "worst cycle failed", value: cycleFailed.reduce<number>((a, b) => Math.max(a, b ?? 0), 0), tone: cycleFailed.some((f) => (f ?? 0) > 0) ? "red" : "slate" },
                ]}
                emptyTitle="No cycle to compare"
                emptyNote="Nothing has completed in this session yet."
              />
              <p style={{ margin: "8px 0 0", fontSize: 10.5, color: "var(--faint)" }}>
                <span title={"Only cycles this screen observed are counted. An empty record means nothing ran while you were watching, not that the estate is healthy."}>{"Only cycles this screen observed are counted."}</span>
              </p>
            </div>
          </Panel>

          <Panel title="Live activity" sub={`${log.length} line(s) streamed from the scanners over SSE`} className="mt">
            <div style={{ maxHeight: 300, overflowY: "auto" }}>
              {log.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No scan activity yet — run a scan.</div>}
              <div className="feed">
                {log.slice().reverse().map((l, i) => (
                  <div className="ev" key={i}>
                    <span className="t">{l.ts}</span>
                    <span className="tag" style={{
                      color: l.tone === "ok" ? "var(--green)"
                        : l.tone === "fail" ? "var(--red)"
                        : l.tone === "start" ? "var(--accent)" : "var(--dim)",
                      borderColor: "currentColor",
                    }}>
                      {l.tone === "ok" ? "ok" : l.tone === "fail" ? "err" : l.tone === "start" ? "run" : "info"}
                    </span>
                    <span className="txt" style={{
                      color: l.tone === "fail" ? "var(--red)" : l.tone === "start" ? "var(--text)" : undefined,
                    }}>{l.text}</span>
                  </div>
                ))}
              </div>
            </div>
          </Panel>
        </div>
      </div>

      {/* ── run form ──────────────────────────────────────────────────── */}
      <Panel
        title="Run a live scan"
        sub="Hardware + runtime always run. Fill a target to include that service; leave blank to skip."
        className="mt"
      >
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 12, alignItems: "center" }}>
          <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase", marginRight: 4 }}>
            will request
          </span>
          {[...HOST_SCANNERS, ...TARGET_SCANNERS].map((key) => {
            const on = requested.includes(key);
            return (
              <span
                key={key}
                className="mono"
                style={{
                  fontSize: 10.5,
                  padding: "2px 6px",
                  borderRadius: 2,
                  border: `1px solid ${on ? "var(--accent)" : "var(--line)"}`,
                  color: on ? "var(--accent)" : "var(--faint)",
                  background: on ? "color-mix(in srgb, var(--accent) 10%, transparent)" : "transparent",
                }}
                title={SCANNER_LABEL[key] ?? key}
              >
                {key}
              </span>
            );
          })}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
          <TgtInput label="Network TLS target" value={netTarget} onChange={setNetTarget} ph="example.com:443" />
          <TgtInput label="Container / image / rootfs" value={containerTarget} onChange={setContainerTarget} ph="nginx:latest or /host/rootfs" />
          <TgtInput label="OT / ICS passive logs" value={otTarget} onChange={setOtTarget} ph="/var/log/ot  (file or dir)" />
          <TgtInput label="Static source dir" value={sourceTarget} onChange={setSourceTarget} ph="/path/to/source" />
          <TgtInput label="Universal crypto source" value={universalTarget} onChange={setUniversalTarget} ph="/path/to/source" />
          <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12, justifyContent: "flex-end" }}>
            <span style={{ opacity: 0.8 }}>Options</span>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={netFull} onChange={(e) => setNetFull(e.target.checked)} />
              network full (OCSP + renegotiation)
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
              <input type="checkbox" checked={cloudLive} onChange={(e) => setCloudLive(e.target.checked)} />
              cloud live (read-only, needs creds)
            </label>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap", marginTop: 14 }}>
          <button className="btn" onClick={() => void runNow()} disabled={status?.running}>
            {status?.running ? "scan running…" : "Run scan now"}
          </button>
          <span style={{ flex: 1 }} />
          <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12 }}>
            Interval (s)
            <input className="inp" type="number" value={intervalS} min={30}
              onChange={(e) => setIntervalS(Number(e.target.value) || 900)} style={{ width: 100 }} />
          </label>
          <RequireRole anyOf={[...SCAN_OPERATE_ROLES]}>
            <button className="btn" onClick={() => void startLoop()} disabled={status?.periodic?.enabled}>
              {status?.periodic?.enabled ? `loop on (${status.periodic.interval_seconds}s)` : "Start live loop"}
            </button>
            <button className="btn sm" onClick={() => void stopLoop()} disabled={!status?.periodic?.enabled}>Stop</button>
          </RequireRole>
        </div>
      </Panel>

      <p style={{ margin: "10px 0 0", fontSize: 11, color: "var(--faint)" }}>
        <span title={"Scanner results are the runner's own report. A cycle with zero failures still excludes blocked and unconfigured scanners, and none of these counts measures estate coverage."}>{"Scanner results are the runner's own report."}</span>
      </p>
    </>
  );
}
