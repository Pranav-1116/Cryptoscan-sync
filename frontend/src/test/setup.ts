/* Test environment: a browser-shaped sandbox with the backend unreachable.
 *
 * `fetch` is replaced by a stub that rejects every call, so:
 *   - the API bridge returns { source: "offline", data: null } everywhere
 *   - pages must render their offline/empty state without throwing
 *   - nothing can accidentally reach a real server from the test runner
 * Individual tests override `globalThis.fetch` with `mockFetch(...)` when
 * they need a live-shaped response.
 */
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

export type FetchRoute = (url: string, init?: RequestInit) => unknown | Response | Promise<unknown>;

/** Build a fetch stub from a path → payload map (or resolver). */
export function mockFetch(routes: Record<string, unknown | FetchRoute>, fallbackStatus = 404) {
  // A new fixture = a fresh backend scenario = a fresh rate-limit budget.
  (globalThis as unknown as { __resetRequestGate?: () => void }).__resetRequestGate?.();
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
    for (const [pattern, handler] of Object.entries(routes)) {
      if (path === pattern || (pattern.endsWith("*") && path.startsWith(pattern.slice(0, -1)))) {
        const body = typeof handler === "function" ? await (handler as FetchRoute)(url, init) : handler;
        if (body instanceof Response) return body;
        return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      }
    }
    return new Response(JSON.stringify({ detail: "not found" }), { status: fallbackStatus, headers: { "Content-Type": "application/json" } });
  });
  globalThis.fetch = fn as unknown as typeof fetch;
  return fn;
}

/** The default: the backend is down. */
export function offlineFetch() {
  // A new scenario = a fresh rate-limit budget (same as mockFetch above).
  (globalThis as unknown as { __resetRequestGate?: () => void }).__resetRequestGate?.();
  const fn = vi.fn(async () => { throw new TypeError("Failed to fetch"); });
  globalThis.fetch = fn as unknown as typeof fetch;
  return fn;
}

// jsdom lacks a few browser APIs the console touches
if (!("EventSource" in globalThis)) {
  class FakeEventSource {
    url: string; readyState = 0; onopen: unknown = null; onmessage: unknown = null; onerror: unknown = null;
    constructor(url: string) { this.url = url; }
    addEventListener() { /* noop */ }
    removeEventListener() { /* noop */ }
    close() { this.readyState = 2; }
  }
  (globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;
}
if (!("matchMedia" in window)) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({ matches: false, media: query, onchange: null,
      addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } }),
  });
}
if (!("ResizeObserver" in globalThis)) {
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
}
if (!("IntersectionObserver" in globalThis)) {
  (globalThis as unknown as { IntersectionObserver: unknown }).IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } };
}
if (!HTMLCanvasElement.prototype.getContext || String(HTMLCanvasElement.prototype.getContext).includes("not implemented")) {
  HTMLCanvasElement.prototype.getContext = (() => null) as unknown as typeof HTMLCanvasElement.prototype.getContext;
}
if (!("scrollTo" in window) || typeof window.scrollTo !== "function") {
  window.scrollTo = () => {};
}
if (!("scrollIntoView" in Element.prototype)) {
  (Element.prototype as unknown as { scrollIntoView: () => void }).scrollIntoView = () => {};
}
if (!("createObjectURL" in URL)) {
  (URL as unknown as { createObjectURL: () => string }).createObjectURL = () => "blob:test";
  (URL as unknown as { revokeObjectURL: () => void }).revokeObjectURL = () => {};
}
if (!("AbortSignal" in globalThis) || typeof AbortSignal.timeout !== "function") {
  (AbortSignal as unknown as { timeout: (ms: number) => AbortSignal }).timeout = () => new AbortController().signal;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();

  offlineFetch();
});

afterEach(async () => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  // The server-state cache and the request gate are app-level singletons;
  // without this, one test's answer (or throttling window) leaks into the next.
  // Imported lazily: a STATIC import here would load lib/api.js before a test
  // file's own vi.mock factory can install its bridge — the mock would lose.
  const [{ queryClient, inFlight }, { resetGate }] = await Promise.all([
    import("../lib/serverState.js"),
    import("../lib/requestGate.js"),
  ]);
  queryClient.clear();
  inFlight.clear();
  resetGate();
});
