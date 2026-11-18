/* CryptoLog workspace (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 6):
   server-side filters, honest counts, named failures — a source that could
   not be read is not a source with no events, and this screen never invents
   events, evidence or totals. */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import CryptoLog from "./CryptoLog";
import { withTitles } from "../test/withTitles";

const AS_OF = "2026-11-07T04:00:00Z";

const eventRow = (over: Record<string, unknown> = {}) => ({
  event_id: "clog_01ABC",
  tenant_id: "tenant_001",
  event_type: "TLS_NEGOTIATION_OBSERVED",
  category: "TLS",
  logging_kind: "ACTIVITY",
  severity: "INFO",
  investigation_status: "OBSERVED",
  asset_id: "asset_gateway_001",
  business_system_id: "system_payments",
  source: { collector_id: "collector_nbom_01", source_type: "NETWORK_OBSERVATION" },
  cryptographic_context: { protocol: "TLS", protocol_version: "TLS1.2", evidence_level: "NETWORK_NEGOTIATED" },
  observation: { observed_at: AS_OF },
  evidence: { evidence_ids: ["evidence_001"], integrity_status: "VERIFIED", signature_status: "VALID" },
  relationships: { related_asset_ids: ["asset_payments_001"], relationship_evidence_ids: ["evidence_002"] },
  processing: { normalization_version: "1.0" },
  telemetry_mode: "EVENT",
  attributes: {},
  ...over,
});

const renderPage = () => {
  render(
    <MemoryRouter initialEntries={["/cryptolog"]}>
      <CryptoLog />
    </MemoryRouter>,
  );
  // the shell opens on the Crypto Event Stream; these tests cover the explorer
  fireEvent.click(screen.getByTestId("cryptolog-view-explorer"));
};

describe("CryptoLog workspace (§9, Phase 6)", () => {
  it("loads events and sends filters to the store, never a page-local filter", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/cryptolog/events": {
        events: [eventRow(), eventRow({ event_id: "clog_02DEF", event_type: "HSM_KEY_METADATA_CHANGE", category: "HSM_KMS", severity: "HIGH", asset_id: "hsm-04", evidence: { evidence_ids: ["evidence_002"] } })],
        next_cursor: "clog_02DEF",
        returned: 2,
      },
    });
    renderPage();
    expect(await screen.findByText("TLS_NEGOTIATION_OBSERVED")).toBeInTheDocument();
    expect(screen.getByText("HSM_KEY_METADATA_CHANGE")).toBeInTheDocument();
    expect(screen.getAllByText(/2 events loaded/).length).toBeGreaterThan(0);
    expect(screen.getByTestId("cryptolog-loaded-line")).toHaveTextContent(/more available/);

    fireEvent.change(screen.getByLabelText("category"), { target: { value: "TLS" } });
    fireEvent.click(screen.getByTestId("apply-filters"));
    await waitFor(() => {
      expect(fetchSpy.mock.calls.some(([p]) =>
        String(p).includes("/api/v1/cryptolog/events") && String(p).includes("category=TLS"))).toBeTruthy();
    });
  });

  it("a failed read is named and never drawn as an empty truth", async () => {
    mockFetch({
      "/api/v1/cryptolog/events": () =>
        new Response(JSON.stringify({ detail: "boom" }), {
          status: 500, headers: { "Content-Type": "application/json" },
        }),
    });
    renderPage();
    const failure = await screen.findByTestId("cryptolog-failure");
    expect(failure).toHaveTextContent(/Unable to read the CryptoLog event store \(HTTP 500\)/);
    expect(failure).toHaveTextContent(/not a source with no events/);
    expect(screen.queryByTestId("cryptolog-rows")).not.toBeInTheDocument();
    expect(screen.getByText(/0 events loaded/)).toBeInTheDocument();
  });

  it("does not turn a pending explorer read into empty-estate evidence", async () => {
    let release!: (value: unknown) => void;
    mockFetch({
      "/api/v1/cryptolog/events": () => new Promise((resolve) => { release = resolve; }),
    });
    renderPage();
    expect(screen.getByTestId("cryptolog-loading")).toHaveTextContent(/no absence can be claimed/);
    expect(screen.queryByTestId("cryptolog-empty")).not.toBeInTheDocument();
    await act(async () => release({ events: [], next_cursor: null, returned: 0 }));
    expect(await screen.findByTestId("cryptolog-empty")).toBeInTheDocument();
  });

  it("an empty store says so plainly and invents no events", async () => {
    mockFetch({
      "/api/v1/cryptolog/events": { events: [], next_cursor: null, returned: 0 },
    });
    renderPage();
    const empty = await screen.findByTestId("cryptolog-empty");
    expect(withTitles(empty)).toMatch(/never invents events/);
    expect(screen.queryByTestId("cryptolog-row")).not.toBeInTheDocument();
  });

  it("event details carry the five views, evidence and corrections", async () => {
    mockFetch({
      "/api/v1/cryptolog/events": {
        events: [eventRow()], next_cursor: null, returned: 1,
      },
      "/api/v1/cryptolog/events/clog_01ABC": eventRow(),
      "/api/v1/cryptolog/events/clog_01ABC/corrections": {
        event_id: "clog_01ABC",
        corrections: [{
          corrects_event_id: "clog_01ABC", original_hash: "ab12",
          corrected_event: {}, reason: "severity understated after triage",
          actor: "analyst-7", evidence_ids: ["ev-triage"],
        }],
        returned: 1,
      },
    });
    renderPage();
    fireEvent.click(await screen.findByTestId("cryptolog-row"));
    expect(await screen.findByTestId("detail-metadata")).toHaveTextContent(/clog_01ABC/);
    expect(screen.getByTestId("detail-parameters")).toHaveTextContent(/TLS1\.2/);
    expect(screen.getByTestId("detail-evidence")).toHaveTextContent(/evidence_001/);
    expect(screen.getByTestId("detail-evidence")).toHaveTextContent(/integrity: VERIFIED/);
    expect(screen.getByTestId("detail-relationships")).toHaveTextContent(/asset_payments_001/);
    expect(withTitles(screen.getByTestId("detail-assessment"))).toMatch(/never automatically becomes a confirmed compromise/);
    expect(screen.getByTestId("detail-corrections")).toHaveTextContent(/analyst-7/);
    expect(screen.getByTestId("detail-corrections")).toHaveTextContent(/ab12/);
  });

  it("load more follows the cursor and keeps the loaded count honest", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/cryptolog/events": (url: string) => {
        if (url.includes("cursor=")) {
          return { events: [eventRow({ event_id: "clog_03GHI", asset_id: "asset-2" })], next_cursor: null, returned: 1 };
        }
        return { events: [eventRow()], next_cursor: "clog_01ABC", returned: 1 };
      },
    });
    renderPage();
    fireEvent.click(await screen.findByTestId("cryptolog-load-more"));
    await waitFor(() => {
      expect(screen.getByTestId("cryptolog-loaded-line")).toHaveTextContent(/2 events loaded/);
    });
    expect(fetchSpy.mock.calls.some(([p]) => String(p).includes("cursor=clog_01ABC"))).toBeTruthy();
    expect(screen.getByTestId("cryptolog-loaded-line")).toHaveTextContent(/end of results/);
    expect(screen.queryByTestId("cryptolog-load-more")).not.toBeInTheDocument();
  });
});
