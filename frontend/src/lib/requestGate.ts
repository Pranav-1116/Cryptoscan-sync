/* requestGate — frontend rate limiting: "prevent accidental request
 * flooding". A runaway effect or a burst of keystrokes must not turn into
 * a request storm against a bank API.
 *
 * Two limits, both generous enough to be invisible in normal use:
 *   - concurrency: at most MAX_CONCURRENT in flight; excess waits its turn;
 *   - burst: at most BURST requests per WINDOW_MS; excess is delayed, not
 *     dropped (a dropped request is a wrong answer; a delayed one is just
 *     slow).
 *
 * The gate wraps tenantFetch so auth/tenant headers stay centralized.
 * Fetch and clock are injectable for tests only.
 */

import { tenantFetch } from "./api.js";

const MAX_CONCURRENT = 8;
const BURST = 20;
const WINDOW_MS = 5_000;

export type Clock = () => number;
export type FetchImpl = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

let inFlight = 0;
let recent: number[] = []; // request start times within the current window
const waiters: (() => void)[] = [];

const defaultClock: Clock = () => Date.now();

/** Test hook: reset module state between tests. */
export function resetGate(): void {
  inFlight = 0;
  recent = [];
  waiters.length = 0;
}

async function acquire(clock: Clock): Promise<void> {
  const now = clock();
  recent = recent.filter((t) => now - t < WINDOW_MS);
  if (inFlight >= MAX_CONCURRENT || recent.length >= BURST) {
    await new Promise<void>((resolve) => {
      waiters.push(resolve);
      // Backstop: a queued request re-checks on a short interval with a
      // FRESH clock read, so a slid burst window admits it without waiting
      // on an unrelated release. Bounded poll; release() still wakes the
      // queue instantly in the common concurrency case.
      const poll = setInterval(() => {
        const t = clock();
        if (t - (recent[0] ?? t) >= WINDOW_MS || inFlight < MAX_CONCURRENT) {
          clearInterval(poll);
          resolve();
        }
      }, 25);
    });
    return acquire(clock);
  }
  inFlight += 1;
  recent.push(now);
}

function release(): void {
  inFlight -= 1;
  const next = waiters.shift();
  if (next) next();
}

/** tenantFetch behind the gate. Same contract as tenantFetch. */
export async function gatedFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  deps: { clock?: Clock; fetchImpl?: FetchImpl } = {},
): Promise<Response> {
  const clock = deps.clock ?? defaultClock;
  await acquire(clock);
  try {
    return await (deps.fetchImpl ?? tenantFetch)(input, init);
  } finally {
    release();
  }
}
