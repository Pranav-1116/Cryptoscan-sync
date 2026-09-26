/* Realtime event store — connects the console to the backend SSE stream
   (GET /api/v1/events/stream) with Last-Event-ID resume, auto-reconnect
   with backoff, a stale-connection watchdog, network up/down awareness, and
   auth-change handling. There is NO simulated/fake event stream: when the
   backend is unreachable or the user is signed out, the store stays empty
   (source: "off") and the UI shows zeros. Real scan/discovery events appear
   only when the platform actually emits them.

   Architecture per spec §42: Backend → SSE stream → frontend event store →
   relevant UI components (ticker, toasts, live pages). No polling.

   Production hardening:
   - The server sends a heartbeat comment every ~15s. A watchdog aborts a
     connection that yields no frame (event OR ping) within STALE_AFTER, so a
     silently-dropped TCP/proxy link reconnects instead of hanging forever.
   - browser online/offline events drive immediate connect / back-off.
   - every (re)connect aborts the previous reader so sockets do not leak.
   - the server's `retry:` hint sets the base reconnect delay. */

import React, {
  createContext, useCallback, useContext, useEffect, useRef, useState,
} from "react";
import { getToken, isBackendLive } from "./api.js";

export interface StreamEvent {
  id: number;
  ts: string;
  type: string;
  source: string;
  payload: Record<string, unknown>;
}

export interface Telemetry {
  eventsPerSec: number;
  subscribers: number;
  eventsBuffered: number;
  latestId: number;
}

export type StreamSource = "live" | "off";
/** coarse connection lifecycle for the UI indicator */
export type ConnState = "connecting" | "live" | "stalled" | "offline";

export interface RealtimeState {
  connected: boolean;
  conn: ConnState;
  source: StreamSource;
  backend: boolean | null;
  events: StreamEvent[];        // newest first, capped
  latestId: number;
  lastEventAt: number | null;   // epoch ms of last real event frame
  eps: number;
  subscribers: number;
  telemetry: Telemetry | null;
}

const EMPTY: RealtimeState = {
  connected: false, conn: "offline", source: "off", backend: null, events: [],
  latestId: 0, lastEventAt: null, eps: 0, subscribers: 0, telemetry: null,
};

const Ctx = createContext<RealtimeState>(EMPTY);

export const useRealtime = (): RealtimeState => useContext(Ctx);

/** Compact per-page indicator: is this page being fed by the live SSE stream,
 *  or falling back to polling? Mirrors the global livehead but on the page. */
export function RealtimeChip({ compact = false }: { compact?: boolean }) {
  const rt = useRealtime();
  const tone = rt.connected ? "green" : rt.backend === false ? "red" : "amber";
  const label = rt.connected
    ? compact ? "LIVE"
      : `SSE live · ${rt.subscribers} sub${rt.eps ? ` · ${rt.eps} ev/s` : ""}`
    : rt.backend === false ? "OFFLINE"
    : "POLLING FALLBACK";
  return (
    <span className="badge" style={{ borderColor: `var(--${tone})`, color: `var(--${tone})`, display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span className="dot" style={{ background: `var(--${tone})` }} /> {label}
    </span>
  );
}

/**
 * Live refresh: reload the given resources whenever a real (non-system) event
 * lands on the SSE stream, throttled so a burst never hammers the backend.
 *
 * Pages with fixed polling can pass their data hooks' `.run` functions here so
 * they update the moment the platform changes, instead of waiting out their
 * poll interval. When the SSE stream is down this is a no-op and the page keeps
 * its own polling fallback (honest offline state).
 */
export function useRealtimeRefresh(...runs: Array<() => unknown>) {
  const rt = useRealtime();
  const lastRef = useRef(0);
  useEffect(() => {
    const last = rt.events[0];
    if (!last || !rt.connected) return;
    if (isSystemEvent(last.type)) return;
    const now = Date.now();
    if (now - lastRef.current < 4000) return; // throttle
    lastRef.current = now;
    const t = setTimeout(() => {
      for (const run of runs) {
        try { void run(); } catch { /* a failed refresh is non-fatal */ }
      }
    }, 150);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rt.events, rt.connected]);
}

const EVENT_CAP = 200;
const BASE_BACKOFF_MS = 3000;    // matches the server `retry:` hint
const MAX_BACKOFF_MS = 15000;
// Server heartbeat is 15s; three missed beats with zero bytes means the link
// is dead even though the socket never signalled close.
const STALE_AFTER_MS = 45000;
const WATCHDOG_MS = 5000;

export function severityOf(type: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  const t = type.toLowerCase();
  if (/(expired|failed|blocked|critical|denied)/.test(t)) return "CRITICAL";
  if (/(alert|drift|vulnerable|new_device|high)/.test(t)) return "HIGH";
  if (/(changed|removed|evaluated|analyzed|scored|enforced|served|verified|ok)/.test(t)) return "LOW";
  return "MEDIUM";
}

/** System bookkeeping events (subscribe/dropped) — hidden from UI feeds. */
export function isSystemEvent(type: string): boolean {
  return type.startsWith("events.") || type === "telemetry.snapshot";
}

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<RealtimeState>(EMPTY);
  const lastIdRef = useRef(0);
  const retryRef = useRef(0);
  const retryMsRef = useRef(BASE_BACKOFF_MS);
  const abortRef = useRef<AbortController | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef = useRef(false);

  const scheduleReconnect = useCallback(() => {
    if (stoppedRef.current) return;
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
    const backoff = Math.min(retryMsRef.current * 2 ** retryRef.current, MAX_BACKOFF_MS);
    retryRef.current += 1;
    reconnectTimerRef.current = setTimeout(() => void connectRef.current(), backoff);
  }, []);

  const connect = useCallback(async () => {
    if (stoppedRef.current) return;
    const token = getToken();
    if (!token) {
      setState((s) => ({ ...s, connected: false, conn: "offline", source: "off" }));
      return;
    }
    if (typeof navigator !== "undefined" && navigator.onLine === false) {
      setState((s) => ({ ...s, connected: false, conn: "offline", source: "off" }));
      return; // the 'online' listener will trigger a connect
    }

    // tear down any in-flight stream before opening a new one
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setState((s) => ({ ...s, connected: false, conn: s.conn === "live" ? "stalled" : "connecting" }));

    let watchdog: ReturnType<typeof setInterval> | null = null;
    let misses = 0;
    try {
      const resume = lastIdRef.current > 0 ? lastIdRef.current : 0;
      const resp = await fetch(`/api/v1/events/stream?last_event_id=${resume}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: ac.signal,
      });
      if (!resp.ok || !resp.body) {
        setState((s) => ({ ...s, connected: false, conn: "offline", source: "off" }));
        throw new Error(`stream http ${resp.status}`);
      }
      retryRef.current = 0;
      setState((s) => ({ ...s, connected: true, conn: "live", source: "live", backend: true }));

      // ── stale watchdog: inbound bytes (event OR heartbeat ping) reset it.
      // Three missed windows (~45s, >2× the 15s heartbeat) with zero bytes
      // means a silently-dropped link → abort so we reconnect below.
      misses = 0;
      watchdog = setInterval(() => {
        misses += 1;
        if (misses >= STALE_AFTER_MS / WATCHDOG_MS) ac.abort();
      }, WATCHDOG_MS);

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      const handleFrame = (frame: string) => {
        let eventType = "message";
        let data = "";
        let sseId: number | null = null;
        for (const line of frame.split("\n")) {
          if (line.startsWith(":")) continue; // comment / heartbeat ping
          if (line.startsWith("event:")) eventType = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
          else if (line.startsWith("id:")) sseId = parseInt(line.slice(3).trim(), 10);
          else if (line.startsWith("retry:")) {
            const ms = parseInt(line.slice(6).trim(), 10);
            if (!Number.isNaN(ms) && ms > 0) retryMsRef.current = ms;
          }
        }
        // a heartbeat (": ping") frame carries no data but proves liveness;
        // handleFrame is only called on data frames, so pings reset the
        // watchdog via the byte-reader below.
        if (!data) return;
        let parsed: StreamEvent;
        try { parsed = JSON.parse(data) as StreamEvent; } catch { return; }
        if (sseId !== null && sseId > lastIdRef.current) lastIdRef.current = sseId;
        misses = 0; // real data frame
        if (parsed.type === "telemetry.snapshot") {
          const p = (parsed.payload || {}) as Record<string, unknown>;
          setState((s) => ({
            ...s, conn: "live", connected: true,
            eps: Number(p.events_per_sec ?? 0),
            subscribers: Number(p.subscribers ?? 0),
            telemetry: {
              eventsPerSec: Number(p.events_per_sec ?? 0),
              subscribers: Number(p.subscribers ?? 0),
              eventsBuffered: Number(p.events_buffered ?? 0),
              latestId: Number(p.latest_id ?? 0),
            },
          }));
          return;
        }
        setState((s) => ({
          ...s, connected: true, conn: "live",
          events: [parsed, ...s.events].slice(0, EVENT_CAP),
          latestId: Math.max(s.latestId, parsed.id),
          lastEventAt: Date.now(),
        }));
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        misses = 0; // any inbound bytes (incl. heartbeat comments) = alive
        buf += decoder.decode(value, { stream: true });
        const frames = buf.split("\n\n");
        buf = frames.pop() ?? "";
        for (const f of frames) handleFrame(f);
      }
      // stream closed cleanly by server
      setState((s) => ({ ...s, connected: false, conn: "connecting", source: "off" }));
      scheduleReconnect();
    } catch (err) {
      if ((err as Error)?.name === "AbortError") {
        // either superseded by a newer connect() or the watchdog fired; only
        // reconnect if this controller is still the active one.
        if (abortRef.current !== ac) return;
        setState((s) => ({ ...s, connected: false, conn: "stalled", source: "off" }));
      } else {
        setState((s) => ({ ...s, connected: false, conn: "offline", source: "off" }));
      }
      if (abortRef.current === ac) scheduleReconnect();
    } finally {
      if (watchdog) clearInterval(watchdog);
    }
  }, [scheduleReconnect]);

  const connectRef = useRef(connect);
  connectRef.current = connect;

  useEffect(() => {
    stoppedRef.current = false;
    void isBackendLive().then((up) =>
      setState((s) => ({ ...s, backend: up, conn: up ? s.conn : "offline" })));
    void connect();

    const onAuth = () => {
      lastIdRef.current = 0;
      retryRef.current = 0;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      void connect();
    };
    const onOnline = () => {
      retryRef.current = 0;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      void connect();
    };
    const onOffline = () => {
      abortRef.current?.abort();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      setState((s) => ({ ...s, connected: false, conn: "offline", source: "off" }));
    };
    const onVisible = () => { if (document.visibilityState === "visible") void connect(); };

    window.addEventListener("zelinx:auth", onAuth);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stoppedRef.current = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      abortRef.current?.abort();
      window.removeEventListener("zelinx:auth", onAuth);
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [connect]);

  // No simulated fallback: when the backend is unreachable or the user is
  // signed out, the store stays empty (source: "off") and the console shows
  // zeros until a real discovery/scan actually emits events.

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
