/* Shared pieces of the three Remediation pages (Tasks, Priorities, Migration). All three read
 * the agents' estate graph, so they share one load hook and one set of load states. */
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Panel } from "./ui";
import EstateDiscoveryCta from "./EstateDiscoveryCta";
import type { ApiResult, RemediationSeverity } from "../lib/api.js";

export const SEVERITIES: RemediationSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const SEV_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "orange", MEDIUM: "amber", LOW: "slate" };
export const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--orange)", MEDIUM: "var(--amber)", LOW: "var(--faint)",
};
export const TASK_TONE: Record<string, string> = {
  PROPOSED: "slate", ACCEPTED: "cyan", COMPLETED: "amber", VERIFIED: "green", PARTIAL: "amber", FAILED: "red", REGRESSION: "red",
};

export const kicker: React.CSSProperties = { fontSize: 9.5, letterSpacing: ".08em", color: "var(--faint)", fontFamily: "var(--mono)" };
export const tile: React.CSSProperties = {
  padding: "14px 16px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)",
};
export const inputStyle: React.CSSProperties = {
  padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)",
  color: "var(--text)", fontSize: 12.5,
};
export const chip = (active: boolean, color = "var(--violet)"): React.CSSProperties => ({
  padding: "4px 10px", fontSize: 11.5, borderRadius: 999, cursor: "pointer",
  border: `1px solid ${active ? color : "var(--line)"}`,
  background: active ? `color-mix(in srgb, ${color} 14%, transparent)` : "transparent",
  color: active ? "var(--text)" : "var(--dim)", fontWeight: active ? 700 : 500,
});

export type LoadState = "loading" | "ready" | "none" | "error";

/** Load one estate read; a 404 means "nothing discovered yet", never "nothing wrong". */
export function useEstateRead<T>(read: () => Promise<ApiResult<T>>, ok: (d: T) => boolean) {
  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);
  const load = useCallback(async () => {
    const id = ++latest.current;
    setState("loading");
    const response = await read();
    if (id !== latest.current) return;
    if (response.data && ok(response.data)) {
      setData(response.data);
      setState("ready");
    } else if (String(response.error || "").includes("404")) {
      setData(null);
      setState("none");
    } else {
      setData(null);
      setError(response.detail || response.error || "the estate could not be read");
      setState("error");
    }
    // read/ok are module-level functions at every call site
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => { void load(); return () => { latest.current += 1; }; }, [load]);
  return { data, state, error, load };
}

export function EstateLoadStates({ state, error, load, what }: {
  state: LoadState; error: string | null; load: () => void; what: string;
}) {
  if (state === "loading") return <Panel title="Reading the estate"><div style={{ fontSize: 12, color: "var(--dim)" }}>Loading what the agents observed…</div></Panel>;
  if (state === "none") {
    return (
      <Panel title="No estate yet" sub={`${what} is read from the estate the agents report`}>
        <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 10 }}>
          Nothing has been discovered yet. Run a discovery (or let the sandbox agents report) and this page fills in.
        </div>
        <EstateDiscoveryCta onDiscovered={load} compact />
      </Panel>
    );
  }
  if (state === "error") {
    return (
      <Panel title="The estate could not be read">
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>{error} — that is not "nothing to fix".</div>
        <button className="btn" style={{ marginTop: 10 }} onClick={() => void load()}>Retry</button>
      </Panel>
    );
  }
  return null;
}

export function PageHeader({ kickerText, title, icon, children, color = "var(--amber)" }: {
  kickerText: string; title: string; icon: React.ReactNode; children?: React.ReactNode; color?: string;
}) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{
        display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999,
        background: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 35%, var(--line))`,
        fontSize: 11, fontFamily: "var(--mono)", color, letterSpacing: ".06em",
      }}>
        <span style={{ width: 6, height: 6, borderRadius: 99, background: color }} /> {kickerText}
      </div>
      <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: color, color: "#fff" }}>{icon}</span>
        {title}
      </h1>
      {children}
    </div>
  );
}

export function observedLine(runId?: string | null, observedAt?: string | null): string {
  const when = observedAt ? new Date(observedAt.replace(" ", "T")).toLocaleString() : "unknown time";
  return `agent report ${runId ? runId.slice(0, 8) : "?"} · observed ${when}`;
}
