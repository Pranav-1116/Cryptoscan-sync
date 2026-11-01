import React from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RealtimeChip, RealtimeProvider, useRealtime } from "./realtime.js";

const bridge = vi.hoisted(() => ({ fetch: vi.fn(), token: vi.fn(), live: vi.fn() }));
vi.mock("./api.js", () => ({
  tenantFetch: (...args: unknown[]) => bridge.fetch(...args),
  getToken: () => bridge.token(),
  hasSession: () => !!bridge.token(),
  isBackendLive: () => bridge.live(),
}));

function Probe() {
  const state = useRealtime();
  return <><pre data-testid="state">{JSON.stringify(state)}</pre><RealtimeChip /></>;
}
function state() { return JSON.parse(screen.getByTestId("state").textContent!); }
function mount() { return render(<RealtimeProvider><Probe /></RealtimeProvider>); }

function connection() {
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({ start(c) { controller = c; } });
  return {
    response: new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    send(frame: string) { controller.enqueue(new TextEncoder().encode(frame)); },
    bind(signal?: AbortSignal) { signal?.addEventListener("abort", () => { try { controller.error(new DOMException("Aborted", "AbortError")); } catch { /* already closed */ } }); },
  };
}
function scan(id: number, privateValue: string, cursor: string) {
  return `id: ${cursor}\nevent: scan.own\ndata: ${JSON.stringify({ id, ts: "2026-10-21T00:00:00Z", type: "scan.own", source: "test", payload: { private: privateValue } })}\n\n`;
}

beforeEach(() => {
  bridge.fetch.mockReset(); bridge.token.mockReset(); bridge.live.mockReset();
  bridge.token.mockReturnValue("token"); bridge.live.mockResolvedValue(true);
});

describe("estate SSE client", () => {
  it("resumes opaque checkpoint cursors, ignores control frames and deduplicates replay", async () => {
    const a = connection(), b = connection();
    bridge.fetch.mockImplementationOnce(async (_path: string, init: RequestInit) => { a.bind(init.signal!); return a.response; })
      .mockImplementationOnce(async (_path: string, init: RequestInit) => { b.bind(init.signal!); return b.response; });
    mount();
    await waitFor(() => expect(state().connected).toBe(true));
    expect(bridge.fetch.mock.calls[0][0]).toBe("/api/v1/events/stream");
    await act(async () => { a.send(scan(1, "a", "opaque-ONE")); });
    await waitFor(() => expect(state().events).toHaveLength(1));
    await act(async () => { a.send('id: opaque-CHECKPOINT\nevent: events.checkpoint\ndata: {"next_cursor":"opaque-CHECKPOINT","complete":true}\n\n'); });
    expect(state().events).toHaveLength(1);
    await act(async () => { window.dispatchEvent(new Event("online")); });
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalledTimes(2));
    expect(bridge.fetch.mock.calls[1][0]).toBe("/api/v1/events/stream?last_event_id=opaque-CHECKPOINT");
    await act(async () => { b.send(scan(1, "a", "opaque-ONE")); });
    expect(state().events).toHaveLength(1);
    expect(state().latestId).toBe(1);
    expect(state().subscribers).toBeNull();
    expect(state().eps).toBeNull();
  });

  it("clears the old estate immediately and ignores a late old-estate response", async () => {
    let resolveOld: (value: Response) => void;
    const old = connection(), current = connection();
    bridge.fetch.mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveOld = resolve; }))
      .mockResolvedValueOnce(current.response);
    mount();
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalledTimes(1));
    await act(async () => { window.dispatchEvent(new Event("zelinx:tenant")); });
    expect(state().events).toEqual([]);
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalledTimes(2));
    await act(async () => { current.send(scan(2, "bank-b", "cursor-B")); });
    await waitFor(() => expect(state().events[0].payload.private).toBe("bank-b"));
    await act(async () => { old.send(scan(1, "bank-a-secret", "cursor-A")); resolveOld!(old.response); });
    expect(state().events.map((e: { payload: { private: string } }) => e.payload.private)).toEqual(["bank-b"]);
    expect(bridge.fetch.mock.calls[1][0]).toBe("/api/v1/events/stream");
  });

  it("erases private feed and aborts on sign-out", async () => {
    const stream = connection();
    bridge.fetch.mockImplementation(async (_path: string, init: RequestInit) => { stream.bind(init.signal!); return stream.response; });
    mount();
    await waitFor(() => expect(state().connected).toBe(true));
    await act(async () => { stream.send(scan(1, "private", "cursor")); });
    await waitFor(() => expect(state().events).toHaveLength(1));
    bridge.token.mockReturnValue(null);
    await act(async () => { window.dispatchEvent(new Event("zelinx:auth")); });
    expect(state().events).toEqual([]);
    expect(state().connected).toBe(false);
    expect(bridge.fetch.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it("shows retention loss rather than treating a gap as a scan event", async () => {
    const stream = connection(); bridge.fetch.mockResolvedValue(stream.response);
    mount();
    await waitFor(() => expect(state().connected).toBe(true));
    await act(async () => { stream.send('event: events.gap\ndata: {"advice":"resynchronize"}\n\n'); });
    await waitFor(() => expect(screen.getByText("RESYNC REQUIRED")).toBeTruthy());
    expect(state().events).toEqual([]);
    expect(state().replayIssue).toContain("Retained history was lost");
  });

  it("keeps unmeasured telemetry unknown but preserves a measured zero", async () => {
    const stream = connection(); bridge.fetch.mockResolvedValue(stream.response);
    mount();
    await waitFor(() => expect(state().connected).toBe(true));
    const telemetry = (payload: Record<string, unknown>) =>
      `event: telemetry.snapshot\ndata: ${JSON.stringify({ id: 1, type: "telemetry.snapshot", payload })}\n\n`;
    await act(async () => { stream.send(telemetry({ events_per_sec: null })); });
    expect(state().eps).toBeNull();
    expect(state().telemetry).toEqual({ eventsPerSec: null, subscribers: null, eventsBuffered: null, latestId: null });
    await act(async () => { stream.send(telemetry({ events_per_sec: 0, events_buffered: 0, latest_sequence: 0 })); });
    expect(state().eps).toBe(0);
    expect(state().telemetry.eventsPerSec).toBe(0);
    expect(state().telemetry.eventsBuffered).toBe(0);
    expect(state().telemetry.latestId).toBe(0);
    expect(state().subscribers).toBeNull();
    expect(state().events).toEqual([]);
  });

  it("does not silently reset a refused cursor to fresh successful history", async () => {
    bridge.fetch.mockResolvedValue(new Response('{"detail":"epoch changed"}', { status: 409 }));
    mount();
    await waitFor(() => expect(state().replayIssue).toContain("cursor refused or reset"));
    expect(state().connected).toBe(false);
    expect(state().events).toEqual([]);
    expect(screen.getByText("RESYNC REQUIRED")).toBeTruthy();
    expect(bridge.fetch).toHaveBeenCalledTimes(1);
  });
});
