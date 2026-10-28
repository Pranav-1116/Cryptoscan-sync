/* React glue for the API bridge — the hook and the source badge live in
   a .tsx module (they render JSX). */

import { useEffect, useState } from "react";
import { ApiResult, ApiSource } from "./api.js";

export function useApi<T>(fn: () => Promise<ApiResult<T>>, deps: unknown[] = []) {
  const [result, setResult] = useState<ApiResult<T>>({ source: "offline", data: null });
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    const res = await fn();
    setResult(res);
    setRunning(false);
    return res;
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/exhaustive-deps
    void run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { ...result, running, run };
}

export function LiveBadge({ source, label }: { source: ApiSource; label?: string }) {
  return source === "live" ? (
    <span className="badge green"><span className="dot" /> {label || "LIVE API DATA"}</span>
  ) : (
    <span className="badge amber"><span className="dot" /> {label || "BACKEND OFFLINE"}</span>
  );
}

/**
 * Polling variant of useApi — re-fetches on an interval so operations pages
 * (integrations/delivery, scanners) reflect the running platform without a
 * manual refresh. Complements the SSE realtime stream for request/response
 * state (delivery logs, integration health) that the event feed does not carry.
 */
export function usePollingApi<T>(fn: () => Promise<ApiResult<T>>, intervalMs = 15000, deps: unknown[] = []) {
  const r = useApi<T>(fn, deps);
  useEffect(() => {
    const t = setInterval(() => { void r.run(); }, intervalMs);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);
  return r;
}

/**
 * Live estate events. The SSE stream is the platform's realtime authority (the
 * durable journal, replayable from `Last-Event-ID`); this hook is a thin
 * subscriber that hands each `estate.*` frame to the caller. It never throws
 * into React: a dead stream means "no live updates", not a broken page, and the
 * panel's polling fallback keeps working.
 */
export function useEstateEvents(onEvent: (type: string, payload: Record<string, unknown>) => void, enabled = true) {
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return undefined;
    const base = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_API_BASE_URL ?? "";
    const stream = new EventSource(`${base}/api/v1/events/stream`, { withCredentials: true });
    const handler = (frame: MessageEvent) => {
      try {
        const body = JSON.parse(frame.data) as { payload?: Record<string, unknown> };
        onEvent(frame.type, body.payload ?? {});
      } catch {
        /* a malformed frame is not a reason to break the page */
      }
    };
    const types = ["estate.run.started", "estate.plane.finished", "estate.run.finished", "estate.run.failed", "estate.change.detected"];
    types.forEach((type) => stream.addEventListener(type, handler as EventListener));
    stream.onopen = () => setConnected(true);
    stream.onerror = () => setConnected(false);
    return () => {
      types.forEach((type) => stream.removeEventListener(type, handler as EventListener));
      stream.close();
      setConnected(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);
  return { connected };
}
