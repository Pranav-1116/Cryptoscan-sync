import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { useApi } from "./apiUi.js";
import type { ApiResult } from "./api.js";

/* The failure branch of the read hook, executed.
 *
 * `useApi` is the one place a throwing reader becomes a result a page can render.
 * Guide 118's `error_handling` row used to flag this module as a "component that
 * reads an API with no failure branch" — a false positive, because the branch *is*
 * the `catch` that builds `{error, detail}`. Retiring a false positive means
 * proving the behaviour rather than deleting the check, so this test drives the
 * hook with a reader that throws and with one that succeeds. */

function Probe({ reader }: { reader: () => Promise<ApiResult<string>> }) {
  const { data, error, detail, running } = useApi(reader, []);
  return (
    <div>
      <p>running: {String(running)}</p>
      <p>data: {String(data)}</p>
      <p>error: {error ?? "none"}</p>
      <p>detail: {detail ?? "none"}</p>
    </div>
  );
}

describe("useApi failure branch", () => {
  it("turns a throwing reader into an explicit failure, not a stale panel", async () => {
    render(<Probe reader={async () => { throw new Error("socket hang up"); }} />);
    expect(await screen.findByText("error: REQUEST_FAILED")).toBeInTheDocument();
    expect(screen.getByText(/the request did not complete: socket hang up/)).toBeInTheDocument();
    // no data is invented, and the hook is not left running for ever
    expect(screen.getByText("data: null")).toBeInTheDocument();
    expect(screen.getByText("running: false")).toBeInTheDocument();
  });

  it("passes a successful result through unchanged", async () => {
    render(<Probe reader={async () => ({ source: "live", data: "ok" })} />);
    expect(await screen.findByText("data: ok")).toBeInTheDocument();
    expect(screen.getByText("error: none")).toBeInTheDocument();
    expect(screen.getByText("running: false")).toBeInTheDocument();
  });
});
