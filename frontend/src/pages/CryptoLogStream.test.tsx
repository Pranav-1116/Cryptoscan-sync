/* Workspace 1 — Crypto Event Stream: the chronological stream only. The
   architecture, detection example and data-flow are rules this workspace
   works by — never copy shown to the operator. The stream counts what the
   store returned: never an invented total, never events invented from
   silence. */
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import CryptoLogStream from "./CryptoLogStream";

const eventRow = (over: Record<string, unknown> = {}) => ({
  event_id: "clog_01ABC",
  event_type: "TLS_NEGOTIATION_OBSERVED",
  category: "TLS",
  logging_kind: "ACTIVITY",
  severity: "INFO",
  investigation_status: "OBSERVED",
  asset_id: "asset_gateway_001",
  source: { collector_id: "collector_nbom_01" },
  cryptographic_context: { protocol: "TLS" },
  observation: { observed_at: "2026-11-12T10:00:00Z" },
  evidence: { evidence_ids: ["evidence_001"] },
  relationships: {},
  processing: {},
  attributes: {},
  ...over,
});

const renderStream = () =>
  render(
    <MemoryRouter>
      <CryptoLogStream />
    </MemoryRouter>,
  );

describe("Crypto Event Stream", () => {
  it("works by the architecture rules without narrating them to the operator", async () => {
    mockFetch({ "/api/v1/cryptolog/events": { events: [], returned: 0, next_cursor: null } });
    renderStream();
    // the design rules are internal: the pipeline, the illustrative example
    // and the product data flow are never rendered as UI copy
    expect(screen.queryByText(/How CryptoLog works/)).toBeNull();
    expect(screen.queryByTestId("stream-illustrative-label")).toBeNull();
    expect(screen.queryByText(/Illustrative timeline/)).toBeNull();
    expect(screen.queryByText(/How the data moves between pages/)).toBeNull();
    expect(screen.queryByText(/event intelligence pipeline/)).toBeNull();
  });

  it("streams recorded events newest first with an honest loaded count", async () => {
    mockFetch({
      "/api/v1/cryptolog/events": {
        events: [
          eventRow(),
          eventRow({ event_id: "clog_02DEF", event_type: "HSM_KEY_METADATA_CHANGE",
            observation: { observed_at: "2026-11-12T11:30:00Z" } }),
        ],
        returned: 2, next_cursor: null,
      },
    });
    renderStream();
    const line = await screen.findByTestId("stream-loaded");
    expect(line).toHaveTextContent(/2 loaded/);
    expect(line).toHaveTextContent(/the store may hold more/);
    const rows = screen.getAllByTestId("stream-row-time");
    expect(rows[0]).toHaveTextContent("2026-11-12T11:30:00Z");
    expect(rows[1]).toHaveTextContent("2026-11-12T10:00:00Z");
  });

  it("holds a pending read apart from a genuinely empty stream", async () => {
    let release!: (value: unknown) => void;
    mockFetch({
      "/api/v1/cryptolog/events": () => new Promise((resolve) => { release = resolve; }),
    });
    renderStream();
    expect(screen.getByTestId("stream-loading")).toHaveTextContent(/no absence can be claimed/);
    expect(screen.queryByTestId("stream-empty")).not.toBeInTheDocument();
    await act(async () => release({ events: [], returned: 0, next_cursor: null }));
    expect(await screen.findByTestId("stream-empty")).toBeInTheDocument();
  });

  it("an empty stream is absence of recorded events — never a quiet estate", async () => {
    mockFetch({ "/api/v1/cryptolog/events": { events: [], returned: 0, next_cursor: null } });
    renderStream();
    const empty = await screen.findByTestId("stream-empty");
    expect(empty).toHaveTextContent(/No events recorded/);
  });

  it("a failed read is named — not a source with no events", async () => {
    mockFetch({
      "/api/v1/cryptolog/events": () =>
        new Response(JSON.stringify({ detail: "boom" }), { status: 500 }),
    });
    renderStream();
    const failure = await screen.findByTestId("stream-failure");
    expect(failure).toHaveTextContent(/not a source with no events/);
    expect(screen.queryByTestId("stream-rows")).not.toBeInTheDocument();
  });
});
