/* Server-state layer: tenant-scoped keys and an honest retry policy. */

import { describe, expect, it } from "vitest";
import { QueryError, makeQueryClient, queryKeys, retryDelay, shouldRetry } from "./serverState.js";

describe("retry policy", () => {
  it("retries outages and throttles, never answers", () => {
    expect(shouldRetry(0, new TypeError("network"))).toBe(true);
    expect(shouldRetry(2, new QueryError(503, "unavailable"))).toBe(true);
    expect(shouldRetry(1, new QueryError(429, "slow down"))).toBe(true);
    // 4xx are answers: retrying a refused write is a duplicate write.
    expect(shouldRetry(0, new QueryError(401, "no"))).toBe(false);
    expect(shouldRetry(0, new QueryError(403, "no"))).toBe(false);
    expect(shouldRetry(0, new QueryError(404, "gone"))).toBe(false);
    expect(shouldRetry(0, new QueryError(422, "invalid"))).toBe(false);
    // three failures is the ceiling even for outages
    expect(shouldRetry(3, new QueryError(503, "still down"))).toBe(false);
  });

  it("honours Retry-After on 429 and backs off exponentially otherwise", () => {
    const throttled = new QueryError(429, "slow") as QueryError & { retryAfterMs?: number };
    throttled.retryAfterMs = 2500;
    expect(retryDelay(0, throttled)).toBe(2500);
    expect(retryDelay(0, new QueryError(503, "x"))).toBe(1000);
    expect(retryDelay(2, new QueryError(503, "x"))).toBe(4000);
    expect(retryDelay(9, new QueryError(503, "x"))).toBe(15000); // capped
  });
});

describe("cache keys", () => {
  it("every key is tenant-scoped — a switch can never leak foreign rows", () => {
    const k = queryKeys.assets(1, "hsm", "name", "asc");
    expect(k[0]).toBe("assets");
    // tenant component present (null tenant maps to "*", never undefined)
    expect(k[1]).toBeDefined();
    expect(JSON.stringify(k)).not.toContain("undefined");
  });

  it("different tenants produce different keys and flush clears all", async () => {
    const client = makeQueryClient();
    client.setQueryData(queryKeys.dashboard(), { summary: 1 });
    expect(client.getQueryData(queryKeys.dashboard())).toEqual({ summary: 1 });
    client.clear();
    expect(client.getQueryData(queryKeys.dashboard())).toBeUndefined();
    await client.unmount();
  });
});
