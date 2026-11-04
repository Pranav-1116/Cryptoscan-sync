/* The console has one job the review cared about: it must never render a refusal, a gap or a
   silence as a green line. These tests assert the three states stay distinguishable on the
   page, because "no findings" is four different facts. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import SecurityControls from "./SecurityControls";

const health = {
  schema: "cryptoscan.security-control-health/1",
  snapshot: { id: "s1", sequence: 4, captured_at: "2026-11-04T00:00:00Z", read_state: "PARTIAL", partial: true },
  taxonomy: {
    OK: { meaning: "read and nothing to report", action: "none" },
    REFUSED: { meaning: "the device refused the read", action: "ask the bank for a read-only account" },
    NOT_CONFIGURED: { meaning: "a decision the bank has not made", action: "decide whether to integrate" },
    UNSUPPORTED_DIALECT: { meaning: "documented, nothing reads it", action: "record the dialect gap" },
  },
  controls: [
    { control: "WAF", state: "OK", detail: "read" },
    { control: "IPS", state: "REFUSED", detail: "device refused a read-only account" },
    { control: "RATE_LIMIT", state: "NOT_CONFIGURED", detail: "no facade configured" },
  ],
  coverage: { total: 3, statement: "1 of 3 controls read; 1 refused" },
};

const findings = {
  findings: [{
    finding_id: "f1", control: "WAF", vendor: "F5", subject: "api.bank", state: "OK",
    evidence_ids: ["EVID-v1-waf-1"], reason: null,
  }],
  summary: { OK: 1 },
};

function mockAll(extra: Record<string, unknown> = {}) {
  return mockFetch({
    "/api/v1/security-controls/health": health,
    "/api/v1/security-controls/findings": findings,
    "/api/v1/security-controls/verify": { snapshots: 4, verified: true, problems: [], head: "abc" },
    ...extra,
  });
}

describe("security control console", () => {
  it("names the state of every control instead of showing a green list", async () => {
    mockAll();
    render(<SecurityControls />);
    expect(await screen.findByText("IPS")).toBeTruthy();
    expect(screen.getByText("device refused a read-only account")).toBeTruthy();
    expect(screen.getByText("a decision the bank has not made")).toBeTruthy();
    expect(screen.getByText(/1 of 3 controls read/)).toBeTruthy();
  });

  it("keeps refusals and unintegrated controls out of the findings tab", async () => {
    mockAll();
    render(<SecurityControls />);
    fireEvent.click(await screen.findByRole("button", { name: /^refused$/i }));
    await waitFor(() => expect(screen.getByText("IPS")).toBeTruthy());
    expect(screen.getByText(/Not integrated/)).toBeTruthy();
    expect(screen.getByText("RATE_LIMIT")).toBeTruthy();
  });

  it("shows the evidence id beside every finding", async () => {
    mockAll();
    render(<SecurityControls />);
    fireEvent.click(await screen.findByRole("button", { name: /^findings$/i }));
    await waitFor(() => expect(screen.getByText("EVID-v1-waf-1")).toBeTruthy());
  });

  it("says the estate is unread rather than empty when no snapshot exists", async () => {
    mockFetch({
      "/api/v1/security-controls/health": { ...health, snapshot: null, controls: [] },
      "/api/v1/security-controls/findings": { findings: [], summary: {} },
    });
    render(<SecurityControls />);
    await waitFor(() => expect(screen.getByText(/No control has been read yet/i)).toBeTruthy());
  });

  it("surfaces a broken chain as a problem, not a footnote", async () => {
    mockAll({
      "/api/v1/security-controls/verify": {
        snapshots: 3, verified: false, head: "x",
        problems: [{ code: "SEQUENCE_GAP", at: "digest-2" }],
      },
    });
    render(<SecurityControls />);
    fireEvent.click(await screen.findByRole("button", { name: /^chain$/i }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("SEQUENCE_GAP"));
    expect(screen.getByText(/chain problem detected/i)).toBeTruthy();
  });

  it("offers the bank's two export formats and no write action", async () => {
    mockAll();
    render(<SecurityControls />);
    fireEvent.click(await screen.findByRole("button", { name: /^export$/i }));
    expect(screen.getByRole("button", { name: /CycloneDX/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /CEF/i })).toBeTruthy();
    for (const write of [/restore/i, /apply/i, /delete/i, /probe/i]) {
      expect(screen.queryByRole("button", { name: write })).toBeNull();
    }
  });
});
