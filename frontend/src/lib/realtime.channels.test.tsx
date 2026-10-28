/* Channel subscriptions: the console stops polling by naming the surface it reads.
 *
 * These tests pin the three properties that make that safe:
 *   - an event for another channel does not refresh this panel;
 *   - a burst of events produces one trailing refetch, not zero (the old throttle
 *     dropped them) and not one per event;
 *   - with the stream down, the hook says so instead of claiming to be live.
 */
import React from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ChannelLiveBadge, RealtimeProvider, useChannelRefresh, useChannelSignal, channelOf, kindOf } from "./realtime.js";
import { useEstateEvents, usePollingApi } from "./apiUi.js";

const bridge = vi.hoisted(() => ({ fetch: vi.fn(), token: vi.fn(), live: vi.fn() }));
vi.mock("./api.js", async (orig) => {
  const actual = await orig<typeof import("./api.js")>();
  return {
    ...actual,
    tenantFetch: (...args: unknown[]) => bridge.fetch(...args),
    getToken: () => bridge.token(),
    isBackendLive: () => bridge.live(),
  };
});

function connection() {
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({ start(c) { controller = c; } });
  return {
    response: new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    send(frame: string) { controller.enqueue(new TextEncoder().encode(frame)); },
    bind(signal?: AbortSignal) { signal?.addEventListener("abort", () => { try { controller.error(new DOMException("Aborted", "AbortError")); } catch { /* closed */ } }); },
  };
}

function frame(id: number, type: string, payload: Record<string, unknown>) {
  return `id: c-${id}\nevent: ${type}\ndata: ${JSON.stringify({ id, ts: "2026-10-28T00:00:00Z", type, source: "test", payload })}\n\n`;
}

const estateChange = (id: number) => frame(id, "estate.change.detected", { channel: "estate", kind: "change_detected", asset: `db-${id}` });
const findingChange = (id: number) => frame(id, "findings.status_changed", { channel: "findings", kind: "status_changed" });

function Signal({ channels }: { channels: string[] }) {
  const signal = useChannelSignal(channels);
  return (
    <pre data-testid="signal">{JSON.stringify({
      live: signal.live, kinds: signal.seen, lastKind: signal.lastKind, has: signal.lastAt !== null,
    })}</pre>
  );
}
const signal = () => JSON.parse(screen.getByTestId("signal").textContent!);

function Refreshable({ channels }: { channels: string[] }) {
  const [n, setN] = React.useState(0);
  useChannelRefresh(channels, [() => setN((v) => v + 1)], { minIntervalMs: 0 });
  return <pre data-testid="refreshes">{n}</pre>;
}
const refreshes = () => Number(screen.getByTestId("refreshes").textContent);

function Polled({ channels }: { channels: string[] | null }) {
  const r = usePollingApi(async () => ({ source: "live" as const, data: null }), 500, [], { channels });
  return <pre data-testid="polled">{JSON.stringify({ live: r.live, intervalMs: r.intervalMs, afterEvent: r.lastEventRefreshAt !== null })}</pre>;
}
const polled = () => JSON.parse(screen.getByTestId("polled").textContent!);

function EstateConsumer() {
  const [events, setEvents] = React.useState<string[]>([]);
  const { connected } = useEstateEvents((type) => setEvents((prev) => [...prev, type]));
  return <pre data-testid="estate">{JSON.stringify({ connected, events })}</pre>;
}
const estate = () => JSON.parse(screen.getByTestId("estate").textContent!);

async function mountWith(children: React.ReactNode) {
  const stream = connection();
  bridge.fetch.mockImplementation(async (_path: string, init: RequestInit) => { stream.bind(init.signal!); return stream.response; });
  const view = render(<RealtimeProvider>{children}</RealtimeProvider>);
  await waitFor(() => expect(bridge.fetch).toHaveBeenCalled());
  return { stream, view };
}

beforeEach(() => {
  bridge.fetch.mockReset(); bridge.token.mockReset(); bridge.live.mockReset();
  bridge.token.mockReturnValue("token"); bridge.live.mockResolvedValue(true);
});

describe("channel classification on the wire", () => {
  it("reads the channel and kind the backend stamped, and nothing else", () => {
    const e = { id: 1, ts: "", type: "estate.change.detected", source: "test", payload: { channel: "estate", kind: "change_detected" } };
    expect(channelOf(e)).toBe("estate");
    expect(kindOf(e)).toBe("change_detected");
    expect(channelOf({ ...e, payload: {} })).toBeNull();
    expect(channelOf({ ...e, payload: { channel: "" } })).toBeNull();
    expect(channelOf(undefined)).toBeNull();
    expect(kindOf(null)).toBeNull();
  });
});

describe("useChannelSignal", () => {
  it("only counts events on the channels it asked for", async () => {
    const { stream } = await mountWith(<Signal channels={["findings"]} />);
    await waitFor(() => expect(signal().live).toBe(true));
    await act(async () => { stream.send(estateChange(1)); });
    expect(signal().kinds).toBe(0);
    expect(signal().has).toBe(false);
    await act(async () => { stream.send(findingChange(2)); });
    await waitFor(() => expect(signal().kinds).toBe(1));
    expect(signal().lastKind).toBe("status_changed");
  });

  it("does not claim to be live when the stream is not connected", async () => {
    bridge.token.mockReturnValue(null);
    render(<RealtimeProvider><Signal channels={["findings"]} /></RealtimeProvider>);
    await waitFor(() => expect(signal().live).toBe(false));
    expect(signal().has).toBe(false);
  });
});

describe("useChannelRefresh", () => {
  it("refetches on a matching channel", async () => {
    const { stream } = await mountWith(<Refreshable channels={["findings"]} />);
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalled());
    await act(async () => { stream.send(findingChange(1)); });
    await waitFor(() => expect(refreshes()).toBe(1));
  });

  it("ignores another surface entirely", async () => {
    const { stream } = await mountWith(<Refreshable channels={["findings"]} />);
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalled());
    await act(async () => { stream.send(estateChange(1)); });
    await act(async () => { await new Promise((r) => setTimeout(r, 200)); });
    expect(refreshes()).toBe(0);
  });

  it("coalesces a burst into one trailing refresh instead of dropping it", async () => {
    const { stream } = await mountWith(<Refreshable channels={["estate"]} />);
    await waitFor(() => expect(bridge.fetch).toHaveBeenCalled());
    await act(async () => {
      stream.send(estateChange(1));
      stream.send(estateChange(2));
      stream.send(estateChange(3));
    });
    await waitFor(() => expect(refreshes()).toBeGreaterThanOrEqual(1));
    // a trailing timer always lands, so the screen settles on post-burst data
    await waitFor(() => expect(refreshes()).toBe(1));
  });
});

describe("usePollingApi with a channel", () => {
  it("slows its timer while the stream is live, and keeps a timer", async () => {
    const { stream } = await mountWith(<Polled channels={["findings"]} />);
    await waitFor(() => expect(polled().live).toBe(true));
    // 500ms requested, 120s in force: the push is the primary path, the timer a net
    expect(polled().intervalMs).toBe(120000);
    await act(async () => { stream.send(findingChange(1)); });
    await waitFor(() => expect(polled().afterEvent).toBe(true));
  });

  it("keeps its own interval when no channel is declared", async () => {
    await mountWith(<Polled channels={null} />);
    await waitFor(() => expect(polled().live).toBe(false));
    expect(polled().intervalMs).toBe(500);
  });
});

describe("useEstateEvents", () => {
  it("rides the shared connection instead of opening a second one", async () => {
    const opened = vi.fn();
    const original = globalThis.EventSource;
    (globalThis as unknown as { EventSource: unknown }).EventSource = class {
      constructor(url: string) { opened(url); }
      addEventListener() {}
      removeEventListener() {}
      close() {}
    };
    try {
      const { stream } = await mountWith(<EstateConsumer />);
      await waitFor(() => expect(estate().connected).toBe(true));
      expect(opened).not.toHaveBeenCalled();
      await act(async () => { stream.send(estateChange(1)); });
      await waitFor(() => expect(estate().events).toEqual(["estate.change.detected"]));
      await act(async () => { stream.send(findingChange(2)); });
      await act(async () => { await new Promise((r) => setTimeout(r, 100)); });
      expect(estate().events).toHaveLength(1);
    } finally {
      (globalThis as unknown as { EventSource: unknown }).EventSource = original;
    }
  });
});

describe("ChannelLiveBadge", () => {
  it("says QUIET before anything has happened on the channel, never LIVE", async () => {
    await mountWith(<ChannelLiveBadge channels={["findings"]} label="findings" />);
    await waitFor(() => expect(screen.getByText(/QUIET/)).toBeTruthy());
    expect(screen.queryByText(/^LIVE/)).toBeNull();
  });

  it("says LIVE once a matching change arrives, with the age of that change", async () => {
    const { stream } = await mountWith(<ChannelLiveBadge channels={["findings"]} label="findings" />);
    await waitFor(() => expect(screen.getByText(/QUIET/)).toBeTruthy());
    await act(async () => { stream.send(findingChange(1)); });
    await waitFor(() => expect(screen.getByText(/LIVE · findings · \d+s ago/)).toBeTruthy());
  });

  it("says POLLING when there is no stream at all", async () => {
    bridge.token.mockReturnValue(null);
    render(<RealtimeProvider><ChannelLiveBadge channels={["estate"]} /></RealtimeProvider>);
    await waitFor(() => expect(screen.getByText(/POLLING/)).toBeTruthy());
  });
});
