/* serverState — TanStack Query as the console's server-state layer.
 *
 * The bank rule this enforces: the same inventory or dashboard summary is
 * never fetched twice while it is fresh. Every query key is TENANT-SCOPED:
 * switching estates must never surface another tenant's cached rows (the
 * frontend cache obeys the same isolation rule as the backend — isolation
 * is enforced, never assumed from a key shape).
 *
 * Retry policy — "recover from temporary API failures" without hammering
 * the API:
 *   - network failures and 5xx: up to 3 attempts, exponential backoff;
 *   - 429: retried, honouring the server's Retry-After when present;
 *   - 401/403/404/422 and other 4xx: NEVER retried — they are answers,
 *     not outages. (A refused write retried blind is a duplicate write.)
 *
 * Fetching goes through tenantFetch (auth + tenant headers) behind the
 * request gate (frontend rate limiting).
 */

import { QueryClient, type QueryKey } from "@tanstack/react-query";
import { activeTenantId, tenantFetch } from "./api.js";
import { gatedFetch } from "./requestGate.js";

export class QueryError extends Error {
  status: number;
  /** Present on 429s that carried Retry-After; drives retryDelay. */
  retryAfterMs?: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "QueryError";
    this.status = status;
  }
}

/** All cache keys start with [domain, tenant]: an estate switch flushes
 *  foreign data through `flushTenantCaches`, never by hoping keys differ. */
export const queryKeys = {
  root: (domain: string): QueryKey => [domain, activeTenantId() ?? "*"],
  assets: (page: number, q: string, sort: string, order: string): QueryKey =>
    [...queryKeys.root("assets"), { page, q, sort, order }],
  asset: (id: string): QueryKey => [...queryKeys.root("asset"), id],
  findings: (filters: Record<string, string>): QueryKey =>
    [...queryKeys.root("findings"), filters],
  dashboard: (): QueryKey => queryKeys.root("dashboard"),
  subgraph: (seed: string, depth: number): QueryKey =>
    [...queryKeys.root("subgraph"), seed, depth],
  nodeDetail: (nodeId: string): QueryKey => [...queryKeys.root("node-detail"), nodeId],
};

/** Retry only what a retry can fix. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 3) return false;
  const status = (error as QueryError | undefined)?.status;
  if (status === undefined) return true;              // network failure
  if (status === 429) return true;                    // throttled: Retry-After
  return status >= 500;                               // outage, not an answer
}

/** Exponential backoff; honour the server's Retry-After on 429. */
export function retryDelay(attemptIndex: number, error: unknown): number {
  const retryAfter = (error as QueryError | undefined)?.retryAfterMs;
  if (retryAfter !== undefined) return retryAfter;
  return Math.min(1000 * 2 ** attemptIndex, 15000);
}

/** fetch for queryFn: tenant-aware, gated, and throws QueryError so the
 *  retry policy can tell an outage from an answer. */
export async function queryFetch(path: string, init?: RequestInit): Promise<unknown> {
  const res = await gatedFetch(path, init);
  if (!res.ok) {
    let message = `request failed (${res.status})`;
    let retryAfterMs: number | undefined;
    const retryAfter = res.headers.get("retry-after");
    if (retryAfter) {
      const seconds = Number(retryAfter);
      if (Number.isFinite(seconds)) retryAfterMs = seconds * 1000;
    }
    try {
      const body = (await res.json()) as { detail?: unknown };
      if (typeof body?.detail === "string") message = body.detail;
    } catch { /* the status already describes the failure */ }
    const err = new QueryError(res.status, message);
    err.retryAfterMs = retryAfterMs;
    throw err;
  }
  return res.json();
}

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        retryDelay,
        // Inventory pages stay fresh briefly; summaries a little longer.
        // The realtime channel invalidates early on real changes.
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
      },
      mutations: {
        // A refused write retried blind is a duplicate write. Mutations
        // retry only transport failures.
        retry: (failureCount, error) =>
          failureCount < 2 && (error as QueryError | undefined)?.status === undefined,
      },
    },
  });
}

/** Tenant switch: everything cached for the previous estate is dropped —
 *  isolation is enforced by eviction, never by key-shape luck. */
export function flushTenantCaches(client: QueryClient): void {
  client.clear();
}

/** The one client the app mounts. Tests build their own via makeQueryClient. */
export const queryClient = makeQueryClient();
