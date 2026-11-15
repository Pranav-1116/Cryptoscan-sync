/* Server-state caching + retry + rate-limit wiring — the rows delivered at
 * the DATA LAYER so all 52 hook consumers get them:
 *   - identical queries share ONE fetch and ONE cached answer (TanStack Query
 *     cache engine; keys are [domain, tenant, closure source, ...deps]);
 *   - a remount within the stale window serves the cache, no network;
 *   - run() is an explicit refresh and always reaches the network;
 *   - GET retries transport failures + 5xx/429 ≤3× (4xx NEVER); mutations
 *     retry TRANSPORT failures only (a 5xx after a write may have landed);
 *   - every request passes the front-end gate (8 concurrent / 20-per-5s). */

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import React from "react";
import { useApi } from "./apiUi";
import { apiGraphEdges, apiGraphRegisterEdge, retryDelayFor } from "./api";
import { mockFetch } from "../test/setup";

function Probe({ label }: { label: string }) {
  const r = useApi(() => apiGraphEdges(), []);
  return (
    <div>
      <span data-testid={`${label}-source`}>{r.source}</span>
      <button onClick={() => void r.run()}>refresh {label}</button>
    </div>
  );
}

describe("server-state caching at the hook layer", () => {
  it("identical queries across components share ONE fetch (dedupe by key)", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return { edges: [], count: 0 };
      },
    });
    render(
      <div>
        <Probe label="a" />
        <Probe label="b" />
      </div>,
    );
    await waitFor(() => expect(screen.getByTestId("a-source")).toHaveTextContent("live"));
    expect(screen.getByTestId("b-source")).toHaveTextContent("live");
    expect(calls).toBe(1);
  });

  it("serves a remount from the cache within the stale window — no refetch", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return { edges: [], count: 0 };
      },
    });
    const first = render(<Probe label="a" />);
    await waitFor(() => expect(screen.getByTestId("a-source")).toHaveTextContent("live"));
    first.unmount();
    render(<Probe label="a" />);
    await waitFor(() => expect(screen.getByTestId("a-source")).toHaveTextContent("live"));
    expect(calls).toBe(1); // the second mount paid nothing
  });

  it("run() is an explicit refresh — it reaches the network", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return { edges: [], count: 0 };
      },
    });
    render(<Probe label="a" />);
    await waitFor(() => expect(screen.getByTestId("a-source")).toHaveTextContent("live"));
    fireEvent.click(screen.getByRole("button", { name: "refresh a" }));
    await waitFor(() => expect(calls).toBe(2));
  });
});

describe("retry policy at the transport", () => {
  it("GET retries 5xx ≤3× and succeeds on the first good response", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return calls < 4 ? new Response("{}", { status: 500 }) : { edges: [], count: 0 };
      },
    });
    const res = await apiGraphEdges();
    expect(res.source).toBe("live");
    expect(calls).toBe(4); // initial + 3 retries
  });

  it("GET treats 4xx as final — a 404 never retries", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return new Response("{}", { status: 404 });
      },
    });
    const res = await apiGraphEdges();
    expect(res.error).toBe("HTTP 404");
    expect(calls).toBe(1);
  });

  it("mutations retry transport failures only — a 5xx is never replayed", async () => {
    let calls = 0;
    mockFetch({
      "/api/v1/graph/edges": () => {
        calls += 1;
        return new Response("{}", { status: 500 });
      },
    });
    const res = await apiGraphRegisterEdge("parent", "child");
    expect(res.error).toBe("HTTP 500");
    expect(calls).toBe(1); // the write may have landed — replaying is double-writing
  });

  it("backoff is exponential, capped at 15s, and Retry-After wins", () => {
    expect(retryDelayFor(null, 0, 250)).toBe(250);
    expect(retryDelayFor(null, 1, 250)).toBe(500);
    expect(retryDelayFor(null, 9, 250)).toBe(15_000); // cap
    const tooMany = new Response(null, { status: 429, headers: { "retry-after": "2" } });
    expect(retryDelayFor(tooMany, 0, 250)).toBe(2000); // server-specified wins
  });
});

describe("front-end rate limiting on every call", () => {
  it("holds concurrency at the gate (8 in flight, the rest delayed not dropped)", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    mockFetch({
      "/api/v1/graph/edges": async () => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 30));
        inFlight -= 1;
        return { edges: [], count: 0 };
      },
    });
    const results = await Promise.all(Array.from({ length: 12 }, () => apiGraphEdges()));
    expect(maxInFlight).toBeLessThanOrEqual(8);
    expect(results.every((r) => r.source === "live")).toBe(true); // delayed, not dropped
  });
});
