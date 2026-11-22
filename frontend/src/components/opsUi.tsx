/* Shared pieces of the Operations pages (Live estate, Activity, Live monitor, Live scanners,
 * Runtime hosts). All of them read /api/v1/operations/* — the agent-fed estate — so they share
 * one live-polling hook, one status vocabulary and one set of small charts. */
import React, { useCallback, useEffect, useRef, useState } from "react";
import type { ApiResult, OpsLivenessState, OpsSeverity } from "../lib/api.js";

export const LIVENESS_COLOR: Record<OpsLivenessState | string, string> = {
  LIVE: "var(--green)", LATE: "var(--amber)", OFFLINE: "var(--red)", NEVER_REPORTED: "var(--faint)",
  RETIRED: "var(--faint)", UNREGISTERED: "var(--orange)",
};
export const LIVENESS_LABEL: Record<OpsLivenessState | string, string> = {
  LIVE: "Live", LATE: "Late", OFFLINE: "Offline", NEVER_REPORTED: "Never reported", RETIRED: "Retired",
  UNREGISTERED: "Unregistered",
};
export const OPS_SEVERITIES: OpsSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const OPS_SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--orange)", MEDIUM: "var(--amber)", LOW: "var(--cyan)", INFO: "var(--faint)",
};
export const PLANE_COLOR: Record<string, string> = {
  COMPLETE: "var(--green)", PARTIAL: "var(--amber)", FAILED: "var(--red)", UNKNOWN: "var(--faint)",
  NOT_ATTEMPTED: "var(--faint)", NOT_OBSERVED: "var(--faint)",
};
export const SOURCE_COLOR: Record<string, string> = {
  READ: "var(--green)", EMPTY: "var(--cyan)", ABSENT: "var(--faint)", DISABLED: "var(--faint)",
  NOT_CONFIGURED: "var(--amber)", ERROR: "var(--red)", FAILED: "var(--red)", DENIED: "var(--red)", TIMEOUT: "var(--red)",
};
export const SOURCE_MEANING: Record<string, string> = {
  READ: "read, and it yielded data",
  EMPTY: "read, and it held nothing",
  ABSENT: "not present on this host",
  DISABLED: "turned off in the agent configuration",
  NOT_CONFIGURED: "needs a file or setting the bank has not supplied",
  ERROR: "could not be read",
};

export const kicker: React.CSSProperties = { fontSize: 9.5, letterSpacing: ".08em", color: "var(--faint)", fontFamily: "var(--mono)", textTransform: "uppercase" };
export const card: React.CSSProperties = {
  padding: "14px 16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)",
};
export const inputStyle: React.CSSProperties = {
  padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)",
  color: "var(--text)", fontSize: 12.5,
};
export const chip = (active: boolean, color = "var(--cyan)"): React.CSSProperties => ({
  padding: "4px 10px", fontSize: 11.5, borderRadius: 999, cursor: "pointer",
  border: `1px solid ${active ? color : "var(--line)"}`,
  background: active ? `color-mix(in srgb, ${color} 14%, transparent)` : "transparent",
  color: active ? "var(--text)" : "var(--dim)", fontWeight: active ? 700 : 500,
});

/** "12s", "4m 05s", "2h 10m", "3d 4h" — the age of something, never a guess. */
export function fmtAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return s % 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s / 60}m`;
  if (s < 86400) {
    const m = Math.floor((s % 3600) / 60);
    return m ? `${Math.floor(s / 3600)}h ${String(m).padStart(2, "0")}m` : `${Math.floor(s / 3600)}h`;
  }
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

export function parseWhen(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? "" : "Z"));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtWhen(iso: string | null | undefined): string {
  const d = parseWhen(iso);
  return d ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

export function agoFrom(iso: string | null | undefined, now: number): number | null {
  const d = parseWhen(iso);
  return d ? Math.max(0, (now - d.getTime()) / 1000) : null;
}

export type LiveState = "loading" | "ready" | "none" | "error";

/**
 * Poll one operations read. A transient failure keeps the last good read on screen and
 * says so (a monitor that blanks on one dropped request is worse than useless); a 404
 * means "nothing reported yet".
 */
export function useLive<T>(read: () => Promise<ApiResult<T>>, initialInterval = 10000) {
  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LiveState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [paused, setPaused] = useState(false);
  const [intervalMs, setIntervalMs] = useState(initialInterval);
  const [now, setNow] = useState(() => Date.now());
  const [reads, setReads] = useState(0);
  const latest = useRef(0);
  const hasData = useRef(false);

  const refresh = useCallback(async () => {
    const id = ++latest.current;
    const response = await read();
    if (id !== latest.current) return;
    setReads((n) => n + 1);
    if (response.data) {
      hasData.current = true;
      setData(response.data);
      setState("ready");
      setError(null);
      setUpdatedAt(Date.now());
    } else if (String(response.error || "").includes("404")) {
      setState(hasData.current ? "ready" : "none");
    } else {
      setError(response.detail || response.error || "the platform did not answer");
      if (!hasData.current) setState("error");
    }
    // read is a module-level function at every call site
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { void refresh(); return () => { latest.current += 1; }; }, [refresh]);
  // A tenant switch is a security boundary: drop the previous tenant's answer at once
  // (never show it under the new tenant's name) and read again.
  useEffect(() => {
    const onTenant = () => {
      latest.current += 1;
      hasData.current = false;
      setData(null); setState("loading"); setError(null); setUpdatedAt(null);
      void refresh();
    };
    window.addEventListener("zelinx:tenant", onTenant);
    return () => window.removeEventListener("zelinx:tenant", onTenant);
  }, [refresh]);
  useEffect(() => {
    if (paused) return undefined;
    const t = setInterval(() => { void refresh(); }, intervalMs);
    return () => clearInterval(t);
  }, [paused, intervalMs, refresh]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const stale = updatedAt !== null && !paused && now - updatedAt > intervalMs * 3;
  return { data, state, error, updatedAt, paused, setPaused, intervalMs, setIntervalMs, refresh, now, stale, reads };
}

export interface LiveControl {
  updatedAt: number | null; error: string | null; paused: boolean; setPaused: (p: boolean) => void;
  intervalMs: number; setIntervalMs: (ms: number) => void; refresh: () => Promise<void>; now: number; stale: boolean;
}

/** The live/refresh control every Operations page carries. */
export function LiveBar({ live }: { live: LiveControl }) {
  const { updatedAt, error, paused, setPaused, intervalMs, setIntervalMs, refresh, now, stale } = live;
  const age = updatedAt === null ? null : (now - updatedAt) / 1000;
  const color = error || stale ? "var(--amber)" : paused ? "var(--faint)" : "var(--green)";
  const label = paused ? "Paused" : error ? "Retrying" : stale ? "Stale" : "Live";
  return (
    <div role="group" aria-label="Live refresh" style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
      <span aria-label="Refresh state" style={{
        display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 999, fontSize: 11.5,
        fontWeight: 700, border: `1px solid color-mix(in srgb, ${color} 40%, var(--line))`,
        background: `color-mix(in srgb, ${color} 12%, transparent)`, color,
      }}>
        <span className={!paused && !error ? "ops-pulse" : undefined} style={{ width: 7, height: 7, borderRadius: 99, background: color }} />
        {label}
      </span>
      <span style={{ fontSize: 11.5, color: "var(--dim)", fontFamily: "var(--mono)" }} title={error ?? undefined}>
        {age === null ? "not read yet" : `updated ${fmtAge(age)} ago`}
        {error ? " · last read failed, showing the previous one" : ""}
      </span>
      <select aria-label="Refresh every" value={intervalMs} onChange={(e) => setIntervalMs(Number(e.target.value))}
        style={{ ...inputStyle, padding: "4px 6px", fontSize: 11.5 }}>
        {[5000, 10000, 30000, 60000].map((ms) => <option key={ms} value={ms}>every {ms / 1000}s</option>)}
      </select>
      <button className="btn" style={{ padding: "4px 10px", fontSize: 11.5 }} onClick={() => setPaused(!paused)}>
        {paused ? "Resume" : "Pause"}
      </button>
      <button className="btn" style={{ padding: "4px 10px", fontSize: 11.5 }} onClick={() => void refresh()}>Refresh</button>
      <style>{`@keyframes opsPulse{0%{box-shadow:0 0 0 0 color-mix(in srgb, var(--green) 60%, transparent)}70%{box-shadow:0 0 0 6px transparent}100%{box-shadow:0 0 0 0 transparent}}.ops-pulse{animation:opsPulse 2s infinite}`}</style>
    </div>
  );
}

export function OpsHeader({ crumb, title, sub, icon, right }: {
  crumb: string; title: string; sub: React.ReactNode; icon: React.ReactNode; right?: React.ReactNode;
}) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 16 }}>
      <div style={{ flex: "1 1 460px", minWidth: 280 }}>
        <div style={kicker}>{crumb}</div>
        <h1 style={{ fontSize: 26, fontWeight: 800, margin: "6px 0 4px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--cyan)", color: "#fff" }}>{icon}</span>
          {title}
        </h1>
        <div style={{ fontSize: 13, color: "var(--dim)", lineHeight: 1.5, maxWidth: 720 }}>{sub}</div>
      </div>
      {right}
    </div>
  );
}

export function LivenessPill({ state, age }: { state: string; age?: number | null }) {
  const color = LIVENESS_COLOR[state] ?? "var(--faint)";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5, padding: "2px 8px", borderRadius: 999, fontSize: 11,
      fontWeight: 700, color, border: `1px solid color-mix(in srgb, ${color} 40%, var(--line))`,
      background: `color-mix(in srgb, ${color} 10%, transparent)`, whiteSpace: "nowrap",
    }}>
      <span style={{ width: 6, height: 6, borderRadius: 99, background: color }} />
      {LIVENESS_LABEL[state] ?? state}{age !== undefined && age !== null ? ` · ${fmtAge(age)}` : ""}
    </span>
  );
}

export function SevBadge({ severity }: { severity: string }) {
  const color = OPS_SEV_COLOR[severity] ?? "var(--faint)";
  return (
    <span style={{
      display: "inline-block", minWidth: 62, textAlign: "center", padding: "2px 7px", borderRadius: 6, fontSize: 10.5,
      fontWeight: 800, letterSpacing: ".04em", color, border: `1px solid color-mix(in srgb, ${color} 45%, var(--line))`,
      background: `color-mix(in srgb, ${color} 12%, transparent)`, fontFamily: "var(--mono)",
    }}>{severity}</span>
  );
}

/** Age against the offline threshold, with the "late" mark drawn on the track. */
export function AgeBar({ age, late, offline, label }: { age: number | null; late: number; offline: number; label: string }) {
  const pct = age === null ? 100 : Math.min(100, (age / Math.max(1, offline)) * 100);
  const color = age === null ? "var(--faint)" : age <= late ? "var(--green)" : age <= offline ? "var(--amber)" : "var(--red)";
  return (
    <div role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={offline} aria-valuenow={age ?? undefined}
      title={`${age === null ? "never" : fmtAge(age)} of ${fmtAge(offline)} before offline · late after ${fmtAge(late)}`}
      style={{ position: "relative", height: 6, borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", overflow: "hidden" }}>
      <div style={{ width: `${Math.max(2, pct)}%`, height: "100%", background: color, transition: "width .6s ease" }} />
      <div style={{ position: "absolute", top: 0, bottom: 0, left: `${(late / Math.max(1, offline)) * 100}%`, width: 1, background: "var(--line-strong)" }} />
    </div>
  );
}

/** A compact inline line chart of real samples; fewer than two points draws nothing. */
export function MiniSpark({ points, color = "var(--cyan)", width = 120, height = 28, label, max }: {
  points: number[]; color?: string; width?: number; height?: number; label: string; max?: number;
}) {
  if (points.length < 2) {
    return <span aria-label={`${label}: not enough samples`} style={{ fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)" }}>collecting samples…</span>;
  }
  const hi = max ?? Math.max(...points);
  const lo = max !== undefined ? 0 : Math.min(...points);
  const span = hi - lo || 1;
  const step = width / (points.length - 1);
  const xy = points.map((v, i) => `${(i * step).toFixed(1)},${(height - ((v - lo) / span) * (height - 2) - 1).toFixed(1)}`).join(" ");
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
      aria-label={`${label}: ${points.length} samples, latest ${points[points.length - 1]}`} style={{ display: "block" }}>
      <polyline points={`0,${height} ${xy} ${width},${height}`} fill={`color-mix(in srgb, ${color} 14%, transparent)`} stroke="none" />
      <polyline points={xy} fill="none" stroke={color} strokeWidth={1.4} />
    </svg>
  );
}

export function KpiTile({ label, value, sub, color = "var(--text)", onClick, active, ariaLabel }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; color?: string; onClick?: () => void; active?: boolean; ariaLabel?: string;
}) {
  const body = (
    <>
      <div style={kicker}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color, margin: "4px 0 2px", fontVariantNumeric: "tabular-nums" }}>{value}</div>
      {sub ? <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.4 }}>{sub}</div> : null}
    </>
  );
  const style: React.CSSProperties = {
    ...card, flex: "1 1 170px", minWidth: 150, textAlign: "left",
    borderColor: active ? color : "var(--line)", boxShadow: active ? `inset 0 0 0 1px ${color}` : undefined,
  };
  return onClick ? (
    <button type="button" aria-label={ariaLabel ?? label} aria-pressed={!!active} onClick={onClick} style={{ ...style, cursor: "pointer", color: "inherit", font: "inherit" }}>{body}</button>
  ) : (
    <div aria-label={ariaLabel ?? label} style={style}>{body}</div>
  );
}

/** A section whose content mounts only when opened — closed, it costs no requests. */
export function Disclosure({ title, sub, children }: { title: string; sub?: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <section style={{ ...card, marginTop: 16, padding: 0 }}>
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)}
        style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, padding: "12px 16px",
                 background: "transparent", border: 0, color: "inherit", cursor: "pointer", textAlign: "left", font: "inherit" }}>
        <span>
          <span style={{ fontWeight: 700, fontSize: 13.5 }}>{title}</span>
          {sub ? <span style={{ display: "block", fontSize: 11.5, color: "var(--dim)", marginTop: 2 }}>{sub}</span> : null}
        </span>
        <span style={{ fontSize: 12, color: "var(--dim)" }}>{open ? "Hide" : "Show"}</span>
      </button>
      {open ? <div style={{ padding: "0 16px 16px" }}>{children}</div> : null}
    </section>
  );
}

export function OpsLoadStates({ state, error, refresh, what }: {
  state: LiveState; error: string | null; refresh: () => void; what: string;
}) {
  if (state === "loading") {
    return <div style={{ ...card, fontSize: 12.5, color: "var(--dim)" }}>Reading what the agents reported…</div>;
  }
  if (state === "none") {
    return (
      <div style={card}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>No agent has reported yet</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>
          {what} fills in when Cryptava agents report. Enrol one per bank server (or start the sandbox agents).
        </div>
      </div>
    );
  }
  if (state === "error") {
    return (
      <div style={card}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>The platform could not be read</div>
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>{error} — this is not "everything is fine".</div>
        <button className="btn" style={{ marginTop: 10 }} onClick={() => void refresh()}>Retry</button>
      </div>
    );
  }
  return null;
}

export function metricValue(latest: Record<string, unknown> | undefined, key: string): number | null {
  const m = latest?.[key] as { value?: number } | undefined;
  return m && typeof m.value === "number" ? m.value : null;
}

export function pctColor(v: number | null, warn = 75, crit = 90): string {
  if (v === null) return "var(--faint)";
  return v >= crit ? "var(--red)" : v >= warn ? "var(--amber)" : "var(--green)";
}
