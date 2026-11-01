/* The hook's failure path. `api.ts` turns an HTTP failure into a result, but the
   hook also accepts any function that returns a promise: if that function throws,
   the panel used to keep its previous data and stay "running" for ever. These
   tests hold the hook to the same discipline the API bridge already keeps. */

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useApi } from "./apiUi.js";

function Probe({ fn }: { fn: () => Promise<any> }) {
  const read = useApi(fn, []);
  return (
    <div>
      <span data-testid="source">{read.source}</span>
      <span data-testid="running">{String(read.running)}</span>
      <span data-testid="error">{read.error ?? "none"}</span>
      <span data-testid="detail">{read.detail ?? "none"}</span>
      <span data-testid="data">{read.data === null ? "null" : JSON.stringify(read.data)}</span>
    </div>
  );
}

describe("useApi failure path", () => {
  it("reports a rejected read instead of keeping the last data", async () => {
    const fn = vi.fn(async () => {
      throw new Error("network down");
    });
    render(<Probe fn={fn} />);

    await waitFor(() => expect(screen.getByTestId("error").textContent).toBe("REQUEST_FAILED"));
    expect(screen.getByTestId("data").textContent).toBe("null");
    expect(screen.getByTestId("source").textContent).toBe("offline");
    expect(screen.getByTestId("detail").textContent).toContain("network down");
  });

  it("stops running when the read throws", async () => {
    const fn = vi.fn(async () => {
      throw new Error("timeout");
    });
    render(<Probe fn={fn} />);

    await waitFor(() => expect(screen.getByTestId("running").textContent).toBe("false"));
  });

  it("passes a good result through untouched", async () => {
    const fn = vi.fn(async () => ({ source: "live" as const, data: { assets: 3 } }));
    render(<Probe fn={fn} />);

    await waitFor(() => expect(screen.getByTestId("source").textContent).toBe("live"));
    expect(screen.getByTestId("data").textContent).toBe('{"assets":3}');
    expect(screen.getByTestId("error").textContent).toBe("none");
    expect(screen.getByTestId("running").textContent).toBe("false");
  });
});
