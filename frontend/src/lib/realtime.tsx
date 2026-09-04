/* Realtime event store — connects the console to the backend SSE stream
   (GET /api/v1/events/stream) with Last-Event-ID resume, auto-reconnect
   with backoff, and auth-change awareness. There is NO simulated/fake
   event stream: when the backend is unreachable or the user is signed out,
   the store stays empty (source: "off") and the UI shows zeros. Real scan
   and discovery events appear only when the platform actually emits them.

   Architecture per spec §42: Backend → SSE stream → frontend event store →
   relevant UI components (ticker, toasts, live pages). No polling. */

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

export interface RealtimeState {
  connected: boolean;
  source: StreamSource;
  backend: boolean | null;
  events: StreamEvent[];        // newest first, capped
  latestId: number;
  lastEventAt: number | null;   // epoch ms
  eps: number;
  subscribers: number;
  telemetry: Telemetry | null;
}

const EMPTY: RealtimeState = {
  connected: false, source: "off", backend: null, events: [],
  latestId: 0, lastEventAt: null, eps: 0, subscribers: 0, telemetry: null,
};

const Ctx = createContext<RealtimeState>(EMPTY);

export const useRealtime = (): RealtimeState => useContext(Ctx);

const EVENT_CAP = 200;
const MAX_BACKOFF_MS = 15000;

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

  /* ── live SSE connection ─────────────────────────────────────────── */
  const connect = useCallback(async () => {
    const token = getToken();
    if (!token) {
      setState((s) => ({ ...s, connected: false, source: "off", backend: s.backend }));
      return;
    }
    try {
      const resume = lastIdRef.current >= 0 ? lastIdRef.current : 0;
      const resp = await fetch(`/api/v1/events/stream?last_event_id=${resume}`, {
        headers: { Authorization: `Bearer ${token}` },
        // no signal: the stream must stay open indefinitely
      });
      if (!resp.ok || !resp.body) {
        setState((s) => ({ ...s, connected: false, source: "off" }));
        throw new Error(`stream http ${resp.status}`);
      }
      retryRef.current = 0;
      setState((s) => ({ ...s, connected: true, source: "live" }));

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
          else if (line.startsWith("retry:")) { /* backoff hint — unused */ }
        }
        if (!data) return;
        let parsed: StreamEvent;
        try { parsed = JSON.parse(data) as StreamEvent; } catch { return; }
        if (sseId !== null && sseId > lastIdRef.current) lastIdRef.current = sseId;
        if (parsed.type === "telemetry.snapshot") {
          const p = (parsed.payload || {}) as Record<string, unknown>;
          setState((s) => ({
            ...s,
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
          ...s,
          connected: true,
          events: [parsed, ...s.events].slice(0, EVENT_CAP),
          latestId: Math.max(s.latestId, parsed.id),
          lastEventAt: Date.now(),
        }));
      };

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const frames = buf.split("\n\n");
        buf = frames.pop() ?? "";
        for (const f of frames) handleFrame(f);
      }
      // stream closed by server — reconnect
      setState((s) => ({ ...s, connected: false, source: "off" }));
      throw new Error("stream closed");
    } catch {
      setState((s) => ({ ...s, connected: false, source: "off" }));
      const backoff = Math.min(1000 * 2 ** retryRef.current, MAX_BACKOFF_MS);
      retryRef.current += 1;
      setTimeout(() => void connect(), backoff);
    }
  }, []);

  useEffect(() => {
    void isBackendLive().then((up) => setState((s) => ({ ...s, backend: up })));
    void connect();
    const onAuth = () => {
      lastIdRef.current = 0;
      retryRef.current = 0;
      void connect();
    };
    window.addEventListener("zelinx:auth", onAuth);
    return () => window.removeEventListener("zelinx:auth", onAuth);
  }, [connect]);

  // No simulated fallback: when the backend is unreachable or the user is
  // signed out, the store stays empty (source: "off") and the console shows
  // zeros until a real discovery/scan actually emits events.

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
