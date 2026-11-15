/* React glue for the API bridge — the hook and the source badge live in
   a .tsx module (they render JSX). */

import { useEffect, useMemo, useRef, useState } from "react";
import { ApiResult, ApiSource } from "./api.js";
import { queryClient, queryKeys, inFlight } from "./serverState.js";
import { CHANNELS_ALL, channelOf, kindOf, useChannelRefresh, useRealtime } from "./realtime.js";

/** How long a cached answer is served without hitting the network. Mirrors the
 *  Query client's staleTime (30s): inventories and dashboard summaries are
 *  re-used across panels and remounts instead of refetched per keystroke /
 *  per render. The realtime channels invalidate early on real changes. */
const STALE_MS = 30_000;
const GC_MS = 5 * 60_000;

function failureEnvelope(err: unknown): ApiResult<never> {
  // api.ts already turns an HTTP failure into a result, but not every reader
  // goes through it: a hook given a function that throws would leave `running`
  // true for ever and keep the previous data on screen, so the panel showed a
  // stale estate with no indication that the read had failed.
  const message = err instanceof Error ? err.message : String(err);
  return {
    source: "offline",
    data: null,
    error: "REQUEST_FAILED",
    detail: `the request did not complete: ${message}`,
  };
}

export function useApi<T>(fn: () => Promise<ApiResult<T>>, deps: unknown[] = []) {
  /* Server-state caching (TanStack Query) is the cache STORE, bound through
     its imperative client so every existing call-site and test keeps its
     contract without provider plumbing. The key is [domain, tenant, closure
     source, ...deps]: identical closures across components share ONE in-flight
     fetch and ONE cached answer; the tenant is part of the key AND flushed on
     switch (isolation by eviction — see flushTenantCaches). */
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const key = useMemo(() => [...queryKeys.root("api-ui"), fn.toString(), ...deps], deps);
  const cacheKey = JSON.stringify(key);
  const [result, setResult] = useState<ApiResult<T>>({ source: "offline", data: null });
  const [running, setRunning] = useState(false);

  const run = async (): Promise<ApiResult<T>> => {
    setRunning(true);
    try {
      // `run` is an explicit refresh (timer tick, Refresh button): always
      // reach the network. fn() starts SYNCHRONOUSLY — the transport call is
      // on the wire before the first await (tests capture the request's
      // deferred resolver right after render) — and concurrent runs with the
      // same key join one in-flight request instead of stampeding.
      let pending = inFlight.get(cacheKey) as Promise<ApiResult<T>> | undefined;
      if (!pending) {
        pending = (async () => {
          try {
            return await fn();
          } catch (err) {
            return failureEnvelope(err);
          }
        })();
        inFlight.set(cacheKey, pending as Promise<unknown>);
        void (pending as Promise<unknown>).finally(() => inFlight.delete(cacheKey));
      }
      const res = await pending;
      // Prune answers older than the gc window (the cache's eviction contract).
      for (const q of queryClient.getQueryCache().getAll()) {
        if (Date.now() - (q.state.dataUpdatedAt ?? 0) > GC_MS) queryClient.getQueryCache().remove(q);
      }
      queryClient.setQueryData(key, res);
      setResult(res);
      return res;
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    const cached = queryClient.getQueryData<ApiResult<T>>(key);
    const updatedAt = queryClient.getQueryState(key)?.dataUpdatedAt ?? 0;
    if (cached && Date.now() - updatedAt < STALE_MS) {
      // Cache paints instantly — no blank flash on remounts ("avoid repeatedly
      // fetching the same inventory and dashboard data"). But the cache is a
      // PAINT, not a truth: the network is always revalidated in the
      // background, and its answer replaces the paint — an honest console
      // never presents a stale live answer over a dead backend (the
      // "stays honest offline" contract). Simultaneous mounts share one
      // revalidate via the in-flight dedupe.
      setResult(cached);
    }
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
