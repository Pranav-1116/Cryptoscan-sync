/* React glue for the API bridge — the hook and the source badge live in
   a .tsx module (they render JSX). */

import { useEffect, useRef, useState } from "react";
import { ApiResult, ApiSource } from "./api.js";
import { CHANNELS_ALL, channelOf, kindOf, useChannelRefresh, useRealtime } from "./realtime.js";

export function useApi<T>(fn: () => Promise<ApiResult<T>>, deps: unknown[] = []) {
  const [result, setResult] = useState<ApiResult<T>>({ source: "offline", data: null });
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    try {
      const res = await fn();
      setResult(res);
      return res;
    } catch (err) {
      // api.ts already turns an HTTP failure into a result, but not every reader
      // goes through it: a hook given a function that throws would leave `running`
      // true for ever and keep the previous data on screen, so the panel showed a
      // stale estate with no indication that the read had failed.
      const message = err instanceof Error ? err.message : String(err);
      const res: ApiResult<T> = {
        source: "offline",
        data: null,
        error: "REQUEST_FAILED",
        detail: `the request did not complete: ${message}`,
      };
      setResult(res);
      return res;
    } finally {
      setRunning(false);
    }
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

export interface PollingOptions {
  /**
   * The product channel(s) this resource lives on. When given *and* the stream is
   * connected, the hook refetches the moment something on those channels changes and
   * pushes its timer out to `liveIntervalMs`.
   */
  channels?: string[] | null;
  /** Optional narrowing to particular kinds on those channels. */
  kinds?: string[];
  /**
   * The interval kept while the stream is live. Default 120s, deliberately not `0`:
   * a screen must not depend on a push it cannot verify. A missed frame becomes a
   * two-minute lag instead of a permanently wrong number.
   */
  liveIntervalMs?: number;
  /** Floor between two event-driven refetches, so a burst cannot storm the API. */
  minIntervalMs?: number;
}

export interface PollingState {
  /** true when this resource is being refreshed by the stream rather than the timer */
  live: boolean;
  /** the interval actually in force */
  intervalMs: number;
  /** epoch ms of the last refresh triggered by an event, null if none yet */
  lastEventRefreshAt: number | null;
}

/**
 * Polling variant of useApi — re-fetches on an interval so operations pages
 * (integrations/delivery, scanners) reflect the running platform without a
 * manual refresh. Complements the SSE realtime stream for request/response
 * state (delivery logs, integration health) that the event feed does not carry.
 *
 * Pass `channels` to make it event-driven: same hook, same rendering, but the refetch
 * that matters is triggered by the change instead of by the clock. The timer does not
 * disappear — it slows down. That is the honest trade: an event is a hint to re-read,
 * the initial and periodic read is what makes the screen correct after a reconnect,
 * and a product that only ever pushed could not tell you it had missed something.
 */
export function usePollingApi<T>(
  fn: () => Promise<ApiResult<T>>,
  intervalMs = 15000,
  deps: unknown[] = [],
  options: PollingOptions = {},
) {
  const r = useApi<T>(fn, deps);
  const rt = useRealtime();
  const channels = options.channels ?? null;
  const eventDriven = !!channels && channels.length > 0 && rt.connected;
  const effectiveInterval = eventDriven ? (options.liveIntervalMs ?? 120000) : intervalMs;
  const [lastEventRefreshAt, setLastEventRefreshAt] = useState<number | null>(null);

  useEffect(() => {
    const t = setInterval(() => { void r.run(); }, effectiveInterval);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveInterval, ...deps]);

  useChannelRefresh(
    channels ?? CHANNELS_ALL,
    // When no channel is declared this hook keeps its old behaviour: no event-driven
    // refetch at all, because an undeclared channel would be a guess.
    channels ? [() => { setLastEventRefreshAt(Date.now()); return r.run(); }] : [],
    { kinds: options.kinds, minIntervalMs: options.minIntervalMs },
  );

  return {
    ...r,
    live: eventDriven,
    intervalMs: effectiveInterval,
    lastEventRefreshAt,
  };
}

/**
 * Live estate events, read from the **shared** realtime store.
 *
 * This used to open its own `EventSource`, which meant the estate panel and the global
 * chip each held a separate connection to the same stream: two server subscriptions,
 * two replay cursors, two tenant re-checks, and an estate panel whose "connected" light
 * could disagree with the header's. It now hands the caller events out of the single
 * provider connection, so there is exactly one socket, one cursor and one truth.
 *
 * The callback still receives `(type, payload)`; `payload.channel`/`payload.kind` are
 * present on every event the backend classified, which is what makes it possible to
 * react to "any estate change" without listing type names here.
 */
export function useEstateEvents(onEvent: (type: string, payload: Record<string, unknown>) => void, enabled = true) {
  const rt = useRealtime();
  const newest = rt.events[0];
  const seenId = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled || !rt.connected || !newest) return;
    if (seenId.current === newest.id) return;
    seenId.current = newest.id;
    const channel = channelOf(newest);
    if (channel !== null && channel !== "estate") return; // another surface's change
    onEvent(newest.type, (newest.payload ?? {}) as Record<string, unknown>);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newest, rt.connected, enabled]);

  return { connected: rt.connected && rt.conn === "live", kind: newest ? kindOf(newest) : null };
}
