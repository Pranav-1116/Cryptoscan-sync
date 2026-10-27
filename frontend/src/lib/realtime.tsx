/* Realtime event store — connects the console to the backend SSE stream
   (GET /api/v1/events/stream) with Last-Event-ID resume, auto-reconnect
   with backoff, a stale-connection watchdog, network up/down awareness, and
   auth-change handling. There is NO simulated/fake event stream: when the
   backend is unreachable or the user is signed out, the store stays empty
   (source: "off") and unavailable rates/counters stay unknown. Real scan/discovery events appear
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
import { getToken, isBackendLive, tenantFetch } from "./api.js";

export interface StreamEvent {
  id: number;
  ts: string;
  type: string;
  source: string;
  payload: Record<string, unknown>;
}

export interface Telemetry {
  eventsPerSec: number | null;
  subscribers: number | null;
  eventsBuffered: number | null;
  latestId: number | null;
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
  eps: number | null;
  subscribers: number | null;
  replayIssue: string | null;
  telemetry: Telemetry | null;
}

const EMPTY: RealtimeState = {
  connected: false, conn: "offline", source: "off", backend: null, events: [],
  latestId: 0, lastEventAt: null, eps: null, subscribers: null, replayIssue: null, telemetry: null,
};

const Ctx = createContext<RealtimeState>(EMPTY);

export const useRealtime = (): RealtimeState => useContext(Ctx);

/** Compact per-page indicator: is this page being fed by the live SSE stream,
 *  or falling back to polling? Mirrors the global livehead but on the page. */
/** Seconds since the last real event, or null when nothing has arrived yet. */
function useSecondsSince(at: number | null): number | null {
  const [, tick] = useState(0);
  useEffect(() => {
    // One timer, not one per consumer: this only drives an age readout.
    const id = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return at === null ? null : Math.max(0, Math.round((Date.now() - at) / 1000));
}

/**
 * Connection state for the header.
 *
 * Reports the stream's own four states rather than collapsing them to
 * connected/not. The one that matters is **stalled**: the socket is open, so
 * a two-state indicator shows green, while no events have arrived for a
 * while and every number on screen is quietly going out of date. An operator
 * acting on a frozen screen is the failure this is here to prevent, so the
 * age of the last event is shown as soon as it is old enough to matter.
 */
export function RealtimeChip({ compact = false }: { compact?: boolean }) {
  const rt = useRealtime();
  const age = useSecondsSince(rt.lastEventAt);

  const tone =
    rt.replayIssue ? "amber"
    : rt.conn === "live" ? "green"
    : rt.conn === "stalled" ? "amber"
    : rt.conn === "connecting" ? "slate"
    : "red";

  const state =
    rt.replayIssue ? "RESYNC REQUIRED"
    : rt.conn === "live" ? "LIVE"
    : rt.conn === "stalled" ? "STALLED"
    : rt.conn === "connecting" ? "CONNECTING"
    : rt.backend === false ? "OFFLINE"
    : "POLLING";

  // Only surface the age once it is old enough to mean something; a counter
  // ticking 0s…1s…2s beside a healthy stream is noise.
  const stale = age !== null && age >= 10 ? `${age < 90 ? `${age}s` : `${Math.round(age / 60)}m`} ago` : null;

  const detail = compact
    ? stale
    : [
        rt.conn === "live" && rt.subscribers ? `${rt.subscribers} sub` : null,
        rt.conn === "live" && rt.eps ? `${rt.eps} ev/s` : null,
        stale,
      ].filter(Boolean).join(" · ");

  return (
    <span
      className="badge"
      title={rt.replayIssue || (rt.conn === "stalled"
        ? "The stream is connected but no events have arrived recently — figures on screen may be out of date."
        : `Event stream: ${rt.conn}`)}
      style={{ borderColor: `var(--${tone})`, color: `var(--${tone})`, display: "inline-flex", alignItems: "center", gap: 5 }}
    >
      <span className="dot" style={{ background: `var(--${tone})` }} />
      {state}{detail ? ` · ${detail}` : ""}
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
  const lastCursorRef = useRef<string | null>(null);
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
      const resume = lastCursorRef.current;
      const path = "/api/v1/events/stream" + (resume ? `?last_event_id=${encodeURIComponent(resume)}` : "");
      const resp = await tenantFetch(path, {
        headers: { Authorization: `Bearer ${token}` },
        signal: ac.signal,
      });
      if (abortRef.current !== ac || ac.signal.aborted) return;
      if (resp.status === 409) {
        setState((s) => ({ ...s, connected: false, conn: "offline", source: "off",
          replayIssue: "Retained replay cursor refused or reset. Resynchronize application state and reselect the estate to start a new stream." }));
        return;
      }
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
        if (abortRef.current !== ac || ac.signal.aborted) return;
        let eventType = "message";
        let data = "";
        let sseId: string | null = null;
        for (const line of frame.split("\n")) {
          if (line.startsWith(":")) continue; // comment / heartbeat ping
          if (line.startsWith("event:")) eventType = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
          else if (line.startsWith("id:")) sseId = line.slice(3).trim();
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
        if (sseId) lastCursorRef.current = sseId;
        misses = 0;
        if (eventType === "events.gap") {
          setState((s) => ({ ...s, replayIssue: "Retained history was lost. Resynchronize application state; this stream is not a complete historical archive." }));
          return;
        }
        if (eventType === "events.refused" || eventType === "events.unavailable") throw new Error(eventType);
        if (eventType.startsWith("events.")) return;
        if (!Number.isFinite(parsed.id) || !parsed.type) return;
        if (parsed.type === "telemetry.snapshot") {
          const p = (parsed.payload || {}) as Record<string, unknown>;
          setState((s) => ({
            ...s, conn: "live", connected: true,
            eps: (typeof p.events_per_sec === "number" && Number.isFinite(p.events_per_sec) ? p.events_per_sec : null),
            subscribers: (typeof p.subscribers === "number" ? p.subscribers : null),
            telemetry: {
              eventsPerSec: (typeof p.events_per_sec === "number" && Number.isFinite(p.events_per_sec) ? p.events_per_sec : null),
              subscribers: (typeof p.subscribers === "number" ? p.subscribers : null),
              eventsBuffered: (typeof p.events_buffered === "number" ? p.events_buffered : null),
              latestId: (typeof p.latest_sequence === "number" ? p.latest_sequence : null),
            },
          }));
          return;
        }
        setState((s) => ({
          ...s, connected: true, conn: "live",
          events: [parsed, ...s.events.filter((old) => old.id !== parsed.id)].slice(0, EVENT_CAP),
          latestId: Math.max(s.latestId, parsed.id),
          lastEventAt: Date.now(),
        }));
      };

      while (true) {
        const { done, value } = await reader.read();
        if (abortRef.current !== ac || ac.signal.aborted) return;
        if (done) break;
        misses = 0; // any inbound bytes (incl. heartbeat comments) = alive
        buf += decoder.decode(value, { stream: true });
        if (buf.length > 1_048_576) throw new Error("SSE frame exceeds client buffer budget");
        const frames = buf.split("\n\n");
        buf = frames.pop() ?? "";
        for (const f of frames) handleFrame(f);
      }
      if (abortRef.current !== ac) return;
      // stream closed cleanly by server
      setState((s) => ({ ...s, connected: false, conn: "connecting", source: "off" }));
      scheduleReconnect();
    } catch (err) {
      if (abortRef.current !== ac) return;
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
      abortRef.current?.abort();
      abortRef.current = null;
      lastCursorRef.current = null;
      setState(EMPTY); // clear private feed immediately on estate change/sign-out
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
    window.addEventListener("zelinx:tenant", onAuth);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stoppedRef.current = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      abortRef.current?.abort();
      window.removeEventListener("zelinx:auth", onAuth);
      window.removeEventListener("zelinx:tenant", onAuth);
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [connect]);

  // No simulated fallback: when the backend is unreachable or the user is
  // signed out, the store stays empty (source: "off") and the console shows
  // unknown counters until a measured estate-local value arrives.

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
