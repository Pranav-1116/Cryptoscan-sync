import React, { StrictMode } from "react";
import { act, renderHook, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockFetch } from "../test/setup";
import { useLive, liveGet, LiveStatus } from "./useLive";

const empty: string[] = [];
const deferred = <T,>() => { let resolve!: (value: T) => void; let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const settle = async () => { await act(async () => { await Promise.resolve(); }); };
const changes: [string, () => void][] = [
  ["current-window estate", () => window.dispatchEvent(new Event("zelinx:tenant"))],
  ["current-window auth", () => window.dispatchEvent(new Event("zelinx:auth"))],
  ...["cryptoscan_tenant", "zelinx_token", "zelinx_roles", "zelinx_user", null].map(key =>
    [`storage ${key}`, () => window.dispatchEvent(new StorageEvent("storage", { key, storageArea: localStorage }))] as [string, () => void]),
  ["visible resume", () => { vi.spyOn(document, "hidden", "get").mockReturnValue(false); document.dispatchEvent(new Event("visibilitychange")); }],
  ["persisted pageshow", () => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }))],
];

describe("useLive private read scope", () => {
  it.each(changes)("clears loaded data and revalidates on %s", async (_name, change) => {
    const next = deferred<unknown>(); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? ["old-private"] : next.promise });
    const { result } = renderHook(() => useLive("/private", empty));
    await settle(); expect(result.current.data).toEqual(["old-private"]);
    await act(async () => { change(); });
    expect(result.current.data).toEqual([]); expect(result.current.loading).toBe(true); expect(reads).toBe(2);
    await act(async () => next.resolve(["current-private"]));
    expect(result.current.data).toEqual(["current-private"]); expect(result.current.loading).toBe(false);
  });

  it.each(["success", "failure"])("ignores old-context %s even when abort is ignored", async kind => {
    const old = deferred<unknown>(); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? old.promise : ["current-private"] });
    const { result } = renderHook(() => useLive("/private", empty));
    await act(async () => { changes[0][1](); });
    expect(result.current.data).toEqual(["current-private"]);
    await act(async () => { if (kind === "success") old.resolve(["old-private"]); else old.reject(new Error("old-context failure")); });
    expect(result.current.data).toEqual(["current-private"]); expect(result.current.error).toBeUndefined();
  });

  it("does not resurrect an A/B/A response", async () => {
    const old = deferred<unknown>(); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? old.promise : [`generation-${reads}`] });
    const { result } = renderHook(() => useLive("/private", empty));
    await act(async () => { localStorage.setItem("cryptoscan_tenant", "b"); changes[0][1](); });
    await act(async () => { localStorage.removeItem("cryptoscan_tenant"); changes[0][1](); });
    await act(async () => old.resolve(["old-private"]));
    expect(result.current.data).toEqual(["generation-3"]);
  });

  it("clears the old path immediately while its replacement is pending", async () => {
    const next = deferred<unknown>();
    mockFetch({ "/a": ["old-private"], "/b": () => next.promise });
    const { result, rerender } = renderHook(({ path }) => useLive(path, empty), { initialProps: { path: "/a" } });
    await settle(); rerender({ path: "/b" });
    expect(result.current.data).toEqual([]); expect(result.current.loading).toBe(true);
    await act(async () => next.resolve(["new-private"])); expect(result.current.data).toEqual(["new-private"]);
  });

  it("a null path clears data and cancels the previous request", async () => {
    const old = deferred<unknown>(); const fetch = mockFetch({ "/private": () => old.promise });
    const { result, rerender } = renderHook(({ path }: { path: string | null }) => useLive(path, empty), { initialProps: { path: "/private" as string | null } });
    await settle(); const signal = fetch.mock.calls[0][1]?.signal;
    rerender({ path: null });
    expect(signal?.aborted).toBe(true); expect(result.current.loading).toBe(false); expect(result.current.data).toEqual([]);
    await act(async () => old.resolve(["old-private"])); expect(result.current.data).toEqual([]);
  });

  it("disabling a previously loaded path clears its data and error state", async () => {
    mockFetch({ "/private": ["old-private"] });
    const { result, rerender } = renderHook(({ path }: { path: string | null }) => useLive(path, empty), { initialProps: { path: "/private" as string | null } });
    await settle(); expect(result.current.data).toEqual(["old-private"]);
    rerender({ path: null }); expect(result.current.data).toEqual([]); expect(result.current.error).toBeUndefined();
  });

  it("null reads never fetch, even on resume or reload", async () => {
    const fetch = mockFetch({}); const { result } = renderHook(() => useLive(null, empty));
    await act(async () => { result.current.reload(); changes[0][1](); });
    expect(fetch).not.toHaveBeenCalled(); expect(result.current.loading).toBe(false);
  });

  it("manual reload clears old data, and latest reload wins", async () => {
    const middle = deferred<unknown>(); const newest = deferred<unknown>(); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? ["old-private"] : reads === 2 ? middle.promise : newest.promise });
    const { result } = renderHook(() => useLive("/private", empty)); await settle();
    await act(async () => result.current.reload()); expect(result.current.data).toEqual([]);
    await act(async () => result.current.reload());
    await act(async () => newest.resolve(["new-private"]));
    await act(async () => middle.resolve(["superseded"]));
    expect(result.current.data).toEqual(["new-private"]); expect(result.current.loading).toBe(false);
  });

  it("aborts on unmount and ignores a captured reload after unmount", async () => {
    const pending = deferred<unknown>(); const fetch = mockFetch({ "/private": () => pending.promise });
    const { result, unmount } = renderHook(() => useLive("/private", empty)); await settle();
    const reload = result.current.reload; const signal = fetch.mock.calls[0][1]?.signal; unmount();
    expect(signal?.aborted).toBe(true); reload();
    await act(async () => pending.resolve(["detached"])); expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("bounds an ignored-abort transport and discards its late success", async () => {
    vi.useFakeTimers(); const pending = deferred<unknown>(); const fetch = mockFetch({ "/private": () => pending.promise });
    const { result } = renderHook(() => useLive("/private", empty)); await settle();
    await act(async () => { await vi.advanceTimersByTimeAsync(12001); });
    expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(result.current.loading).toBe(false); expect(result.current.error).toBe("Read timed out");
    await act(async () => pending.resolve(["late-private"])); expect(result.current.data).toEqual([]);
  });

  it("refreshes using the current token and estate rather than cached headers", async () => {
    const fetch = mockFetch({ "/private": [] }); renderHook(() => useLive("/private", empty)); await settle();
    await act(async () => { localStorage.setItem("zelinx_token", "new-token"); localStorage.setItem("cryptoscan_tenant", "b"); changes[0][1](); });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1][1]?.headers).toMatchObject({ Authorization: "Bearer new-token", "X-Tenant-ID": "b" });
  });

  it("uses the current fallback on reload without fetching on fallback identity alone", async () => {
    const fetch = mockFetch({}, 503);
    const { result, rerender } = renderHook(({ fallback }) => useLive("/private", fallback), { initialProps: { fallback: ["empty-v1"] } }); await settle();
    rerender({ fallback: ["empty-v2"] }); expect(fetch).toHaveBeenCalledTimes(1);
    await act(async () => result.current.reload()); expect(result.current.data).toEqual(["empty-v2"]);
  });

  it("StrictMode remount rejects the first mount's late reply", async () => {
    const old = deferred<unknown>(); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? old.promise : ["current-private"] });
    const { result } = renderHook(() => useLive("/private", empty), { wrapper: ({ children }) => <StrictMode>{children}</StrictMode> });
    await settle(); await act(async () => old.resolve(["old-private"])); expect(result.current.data).toEqual(["current-private"]);
  });

  it.each(["unrelated storage", "session storage", "hidden tab", "ordinary pageshow"])("does not refetch for %s", async event => {
    const fetch = mockFetch({ "/private": ["current-private"] }); const { result } = renderHook(() => useLive("/private", empty)); await settle();
    await act(async () => {
      if (event === "unrelated storage") window.dispatchEvent(new StorageEvent("storage", { key: "theme", storageArea: localStorage }));
      if (event === "session storage") window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_token", storageArea: sessionStorage }));
      if (event === "hidden tab") { vi.spyOn(document, "hidden", "get").mockReturnValue(true); document.dispatchEvent(new Event("visibilitychange")); }
      if (event === "ordinary pageshow") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: false }));
    });
    expect(fetch).toHaveBeenCalledTimes(1); expect(result.current.data).toEqual(["current-private"]);
  });
  it.each([[401, /authentication|session/i], [403, /access refused/i], [409, /read refused/i], [503, /service unavailable/i]] as const)(
    "distinguishes HTTP %s refusal/outage and clears earlier data", async (status, reason) => {
      let reads = 0;
      mockFetch({ "/private": () => ++reads === 1 ? ["old-private"] : new Response('{"detail":"synthetic-sensitive-detail"}', { status }) });
      const { result } = renderHook(() => useLive("/private", empty)); await settle();
      await act(async () => result.current.reload());
      expect(result.current.data).toEqual([]); expect(result.current.error).toMatch(reason);
      expect(result.current.error).not.toContain("synthetic-sensitive-detail"); expect(result.current.loading).toBe(false);
    });

  it("distinguishes malformed JSON from live or transport failure", async () => {
    mockFetch({ "/private": new Response("not-json", { headers: { "Content-Type": "application/json" } }) });
    const { result } = renderHook(() => useLive("/private", empty)); await settle();
    expect(result.current.data).toEqual([]); expect(result.current.error).toMatch(/invalid response/i);
  });

  it("keeps transport outage empty and never invents data", async () => {
    const { result } = renderHook(() => useLive("/private", empty)); await settle();
    expect(result.current.data).toEqual([]); expect(result.current.error).toMatch(/backend unreachable/i);
    expect(result.current.loading).toBe(false);
  });

  it("guards a late response body after headers have already arrived", async () => {
    const body = deferred<string[]>(); const response = new Response("synthetic-body");
    vi.spyOn(response, "json").mockReturnValue(body.promise); let reads = 0;
    mockFetch({ "/private": () => ++reads === 1 ? response : ["current-private"] });
    const { result } = renderHook(() => useLive("/private", empty)); await settle();
    await act(async () => changes[0][1]());
    await act(async () => body.resolve(["old-private"]));
    expect(result.current.data).toEqual(["current-private"]);
  });

  it("cleans its owned deadline and scope listeners on unmount", async () => {
    vi.useFakeTimers(); const pending = deferred<unknown>();
    mockFetch({ "/private": () => pending.promise });
    const add = vi.spyOn(window, "addEventListener"), remove = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() => useLive("/private", empty));
    expect(vi.getTimerCount()).toBe(1);
    const callbacks = add.mock.calls.filter(call => ["storage", "zelinx:auth", "zelinx:tenant", "pageshow"].includes(call[0]));
    expect(callbacks).toHaveLength(4); unmount(); expect(vi.getTimerCount()).toBe(0);
    for (const [type, callback] of callbacks) expect(remove).toHaveBeenCalledWith(type, callback);
    await act(async () => pending.resolve([]));
  });

  it("shows the safe refusal reason rather than falsely calling it an outage", () => {
    render(<LiveStatus error="Access refused (HTTP 403)" />);
    expect(screen.getByText(/Access refused/)).toBeInTheDocument();
    expect(screen.queryByText(/backend offline/i)).toBeNull();
  });

  it("preserves the exported liveGet nullable compatibility contract", async () => {
    mockFetch({ "/private": [] }); expect(await liveGet("/private")).toEqual([]);
    mockFetch({}, 403); expect(await liveGet("/private")).toBeNull();
  });

});
