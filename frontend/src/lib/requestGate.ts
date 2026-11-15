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
let epoch = 0;
const pendingPolls = new Set<ReturnType<typeof setInterval>>();

const defaultClock: Clock = () => Date.now();

/** Test hook: reset module state between tests. */
export function resetGate(): void {
  inFlight = 0;
  recent = [];
  epoch += 1;
  for (const poll of pendingPolls) clearInterval(poll);
  pendingPolls.clear();
  // Wake every queued waiter; their acquire sees the epoch change and throws
  // GateResetError — a finished test's zombie request must never leak into
  // the next test's queue, slots, or wire traffic.
  const orphaned = waiters.splice(0, waiters.length);
  for (const wake of orphaned) wake();
}

// Test-only hook: a mockFetch scenario swap starts a fresh rate-limit budget
// (each fixture = a fresh backend session). Exposed on globalThis so the test
// harness needs no static import of this module (that would break vi.mock).
(globalThis as unknown as { __resetRequestGate?: () => void }).__resetRequestGate = resetGate;

/** Synchronous admission: takes a slot if one is free, else tells the caller
 *  to wait. The sync fast-path matters — callers rely on the request being on
 *  the wire in the same turn (tests capture the request's deferred resolver
 *  right after render). */
function tryAcquire(clock: Clock): boolean {
  const now = clock();
  recent = recent.filter((t) => now - t < WINDOW_MS);
  if (inFlight >= MAX_CONCURRENT || recent.length >= BURST) return false;
  inFlight += 1;
  recent.push(now);
  return true;
}

/** Thrown to abandon waiters whose test/request context was reset. Never
 *  retried — a reset zombie must not re-enter the queue in the next test. */
export class GateResetError extends Error {
  constructor() {
    super("request gate reset");
    this.name = "GateResetError";
  }
}

async function acquire(clock: Clock): Promise<void> {
  const myEpoch = epoch;
  if (tryAcquire(clock)) return;
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
        pendingPolls.delete(poll);
        resolve();
      }
    }, 25);
    pendingPolls.add(poll);
  });
  // The gate was reset while we waited: abandon — do NOT acquire a slot in
  // the new context and do NOT recurse into its queue.
  if (epoch !== myEpoch) throw new GateResetError();
  return acquire(clock);
}

function release(): void {
  inFlight -= 1;
  const next = waiters.shift();
  if (next) next();
}

/** tenantFetch behind the gate. Same contract as tenantFetch. */
export function gatedFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  deps: { clock?: Clock; fetchImpl?: FetchImpl } = {},
): Promise<Response> {
  const clock = deps.clock ?? defaultClock;
  const fetchImpl = deps.fetchImpl ?? tenantFetch;
  // Fast path: a free slot admits the request SYNCHRONOUSLY — fetch is called
  // in the same turn. Only a full gate queues.
  if (tryAcquire(clock)) {
    return fetchImpl(input, init).finally(release);
  }
  return (async () => {
    await acquire(clock);
    try {
      return await fetchImpl(input, init);
    } finally {
      release();
    }
  })();
}
