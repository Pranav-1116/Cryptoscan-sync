/* useLive — fetch data from the LIVE control plane on mount (and on demand).
 *
 * There is no demo / sample / seed data. Consumers call real GET endpoints;
 * this fence owns read state, not their forms, actions or entire page lifecycle:
 *   - while loading: old data is cleared, including context/resume reloads.
 *   - on success:  `data` holds the live payload (possibly an empty list /
 *      zero counts when nothing has run yet — that is the honest state).
 *   - on failure:  `error` is set and `data` stays the empty fallback, so the
 *      page never fabricates content.
 *
 * The fallback MUST be the empty/zero shape (matching data/initial.ts) so an
 * unreachable backend renders an empty console, never fake numbers.
 */
import { useEffect, useState, useCallback, useRef, useLayoutEffect } from "react";
import { tenantFetch } from "./api.js";
import { readFailure } from "./requestFeedback";
import { watchPrivateScope } from "./privateScope";

export interface LiveState<T> {
  data: T;
  loading: boolean;
  error?: string;
  reload: () => void;
}

async function readLive<T>(path: string, init?: RequestInit): Promise<{ data: T | null; error?: string }> {
  try {
    const resp = await tenantFetch(path, { ...init, signal: init?.signal ?? AbortSignal.timeout(12000) });
    if (!resp.ok) {
      return { data: null, error: readFailure(resp.status) };
    }
    try {
      const data = await resp.json() as T | null;
      return { data, ...(data === null ? { error: "Empty response" } : {}) };
    } catch { return { data: null, error: "Invalid response" }; }
  } catch { return { data: null, error: "backend unreachable" }; }
}

export async function liveGet<T>(path: string, init?: RequestInit): Promise<T | null> {
  return (await readLive<T>(path, init)).data;
}

export function useLive<T>(path: string | null, fallback: T): LiveState<T> {
  const [data, setData] = useState<T>(fallback);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [error, setError] = useState<string | undefined>();
  const [tick, setTick] = useState(0);
  const [readPath, setReadPath] = useState(path);
  const latest = useRef({ path, fallback });
  useLayoutEffect(() => { latest.current = { path, fallback }; }, [path, fallback]);
  const mounted = useRef(false);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  // This hook only issues GETs. Never apply automatic context replay to the
  // generic action hook: its callback may perform a write.
  const reload = useCallback(() => {
    if (!mounted.current) return;
    generation.current++;
    controller.current?.abort();
    setData(latest.current.fallback);
    setError(undefined);
    setLoading(latest.current.path !== null);
    setTick(n => n + 1);
  }, []);

  useEffect(() => {
    mounted.current = true;
    const stop = watchPrivateScope(reload);
    return () => {
      mounted.current = false;
      generation.current++;
      controller.current?.abort();
      stop();
    };
  }, [reload]);

  useEffect(() => {
    const current = ++generation.current;
    setReadPath(path);
    setData(latest.current.fallback);
    setError(undefined);
    setLoading(path !== null);
    if (path === null) return;
    const abort = new AbortController();
    controller.current = abort;
    const active = () => mounted.current && current === generation.current
      && path === latest.current.path && !abort.signal.aborted;
    // Bound visible loading even if a transport/body reader ignores abort.
    const deadline = window.setTimeout(() => {
      if (!active()) return;
      abort.abort();
      setData(latest.current.fallback);
      setError("Read timed out");
      setLoading(false);
    }, 12000);
    void readLive<T>(path, { signal: abort.signal }).then(({ data: d, error: reason }) => {
      if (!active()) return;
      setData(d === null ? latest.current.fallback : d);
      setError(reason);
    }).finally(() => {
      window.clearTimeout(deadline);
      if (active()) setLoading(false);
    });
    return () => {
      if (current === generation.current) generation.current++;
      window.clearTimeout(deadline);
      abort.abort();
    };
    // Inline empty fallback objects must not create a fetch/render loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick]);

  // Do not expose old-path data during the render before effect cleanup runs.
  return { data: readPath === path ? data : fallback,
    loading: readPath === path ? loading : path !== null,
    error: readPath === path ? error : undefined, reload };
}

/* Small inline status line used by live-wired pages. */
export function LiveStatus({ loading, error }: { loading?: boolean; error?: string }) {
  if (loading) return <span className="dim" style={{ fontSize: 12 }}>● loading live data…</span>;
  if (error)
    return (
      <span className="badge" style={{ background: "color-mix(in srgb, var(--red) 10%, transparent)", color: "var(--red)", fontSize: 11 }}>
        {error} — showing empty state
      </span>
    );
  return (
    <span className="badge" style={{ background: "color-mix(in srgb, var(--green) 12%, transparent)", color: "var(--green)", fontSize: 11 }}>
      <span className="dot" /> LIVE
    </span>
  );
}
