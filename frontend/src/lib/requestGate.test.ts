/* The request gate delays floods; it never drops a request. */

import { afterEach, describe, expect, it } from "vitest";
import { gatedFetch, resetGate, type Clock } from "./requestGate.js";

afterEach(() => resetGate());

describe("request gate", () => {
  it("caps concurrency at 8 in flight; every request still completes", async () => {
    let active = 0;
    let peak = 0;
    const fetchImpl = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= 1;
      return new Response("{}", { status: 200 });
    };
    const results = await Promise.all(
      Array.from({ length: 12 }, () =>
        gatedFetch("/api/v1/x", {}, { clock: () => 0, fetchImpl }),
      ),
    );
    expect(peak).toBeLessThanOrEqual(8);
    expect(results).toHaveLength(12);
    expect(results.every((r) => r.status === 200)).toBe(true);
  });

  it("burst-limits within a window: delayed until the window slides, never dropped", async () => {
    let clockNow = 0;
    const clock: Clock = () => clockNow;
    let started = 0;
    const fetchImpl = () => {
      started += 1;
      return Promise.resolve(new Response("{}", { status: 200 }));
    };
    // 20 sequential requests at the same instant: the full burst window.
    await Promise.all(
      Array.from({ length: 20 }, () =>
        gatedFetch("/api/v1/y", {}, { clock, fetchImpl }),
      ),
    );
    expect(started).toBe(20);
    // The 21st at the same instant queues (delayed, not dropped).
    const waiting = gatedFetch("/api/v1/y", {}, { clock, fetchImpl });
    await new Promise((r) => setTimeout(r, 40));
    expect(started).toBe(20); // still queued while the window is full
    clockNow = 6000;          // the window slid on the next poll
    await waiting;
    expect(started).toBe(21); // admitted
  });
});
