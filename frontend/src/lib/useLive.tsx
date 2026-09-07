/* useLive — fetch data from the LIVE control plane on mount (and on demand).
 *
 * There is no demo / sample / seed data. Every page that shows operational
 * data uses this hook to call a real endpoint:
 *   - while loading: `loading` is true and the page renders its empty shell.
 *   - on success:  `data` holds the live payload (possibly an empty list /
 *      zero counts when nothing has run yet — that is the honest state).
 *   - on failure:  `error` is set and `data` stays the empty fallback, so the
 *      page never fabricates content.
 *
 * The fallback MUST be the empty/zero shape (matching data/initial.ts) so an
 * unreachable backend renders an empty console, never fake numbers.
 */
import { useEffect, useState, useCallback } from "react";
import { getToken } from "./api.js";

export interface LiveState<T> {
  data: T;
  loading: boolean;
  error?: string;
  reload: () => void;
}

export async function liveGet<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(path, { signal: AbortSignal.timeout(12000), headers, ...init });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

export function useLive<T>(path: string | null, fallback: T): LiveState<T> {
  const [data, setData] = useState<T>(fallback);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [error, setError] = useState<string | undefined>();
  const [tick, setTick] = useState(0);

  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    if (path === null) return;
    let cancelled = false;
    setLoading(true);
    setError(undefined);
    liveGet<T>(path)
      .then((d) => {
        if (cancelled) return;
        if (d === null) {
          setError("backend unreachable");
          setData(fallback);
        } else {
          setData(d);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick]);

  return { data, loading, error, reload };
}

/* Small inline status line used by live-wired pages. */
export function LiveStatus({ loading, error }: { loading?: boolean; error?: string }) {
  if (loading) return <span className="dim" style={{ fontSize: 12 }}>● loading live data…</span>;
  if (error)
    return (
      <span className="badge" style={{ background: "rgba(224,30,90,0.10)", color: "var(--red)", fontSize: 11 }}>
        backend offline — showing empty state
      </span>
    );
  return (
    <span className="badge" style={{ background: "rgba(34,197,94,0.12)", color: "var(--green)", fontSize: 11 }}>
      <span className="dot" /> LIVE
    </span>
  );
}
