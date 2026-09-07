/* Live ticker + alert toasts — fed by the realtime event store when the
   SSE stream is connected (source "live"), deterministic simulation
   otherwise (source "sim"). No polling. */

import React, { useEffect, useState } from "react";
import { useRealtime, severityOf } from "../lib/realtime.js";

const SEVERITY_CLASS: Record<string, string> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };

export function useLiveTicker() {
  const rt = useRealtime();
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const lastEventAt = rt.lastEventAt;
  const ago = lastEventAt ? Math.max(0, Math.round((now - lastEventAt) / 1000)) : null;

  return {
    ago,
    eps: rt.eps,
    backend: rt.backend,
    connected: rt.connected,
    conn: rt.conn,
    source: rt.source,
    subscribers: rt.subscribers,
    eventCount: rt.events.length,
  };
}

export function useAlertToasts() {
  const rt = useRealtime();
  const [toasts, setToasts] = useState<{ id: number; severity: string; title: string; detail: string }[]>([]);
  const seen = React.useRef<Set<number>>(new Set());

  useEffect(() => {
    const fresh = rt.events.filter((e) => !seen.current.has(e.id));
    if (fresh.length === 0) return;
    for (const e of fresh) seen.current.add(e.id);
    const important = fresh
      .filter((e) => {
        const sev = severityOf(e.type);
        return sev === "CRITICAL" || sev === "HIGH";
      })
      .slice(0, 3)
      .map((e) => ({
        id: e.id,
        severity: severityOf(e.type),
        title: e.type.replace(/^(platform|monitor|demo)\./, "").replace(/_/g, " "),
        detail: String(e.payload?.detail || e.payload?.target || ""),
      }));
    if (important.length === 0) return;
    setToasts((prev) => {
      const next = [...prev, ...important].slice(-3);
      // auto-dismiss each toast after 7s
      setTimeout(() => {
        setToasts((cur) => cur.filter((t) => !important.some((it) => it.id === t.id)));
      }, 7000);
      return next;
    });
  }, [rt.events]);

  return toasts;
}

export function Toasts({ toasts }: { toasts: { id: number; severity: string; title: string; detail: string }[] }) {
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div className={`toast ${SEVERITY_CLASS[t.severity] || ""}`} key={t.id}>
          <div className="t">
            <span className={`badge ${t.severity === "CRITICAL" || t.severity === "HIGH" ? "red" : "amber"}`}>
              <span className="dot" /> {t.severity === "CRITICAL" ? "CRITICAL ALERT" : t.severity === "HIGH" ? "HIGH ALERT" : "ALERT"}
            </span>
          </div>
          <div className="d">{t.title}{t.detail ? ` — ${t.detail}` : ""}</div>
        </div>
      ))}
    </div>
  );
}
