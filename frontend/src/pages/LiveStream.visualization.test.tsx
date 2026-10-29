/* Live stream — the drawing contract.
 *
 * A bus with no topics, a detector that has never fired and a CBOM nobody has
 * inspected are three different absences, and each must be drawn as one. When
 * data does arrive the strip is per observation tick, the bar is per topic, and
 * a broken hash chain is stated with the version it broke at.
 */
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import LiveStream from "./LiveStream";

const draw = () => render(<MemoryRouter><LiveStream /></MemoryRouter>);
const stats = {
  log_dir: "/var/stream",
  chain_len: 42,
  topics: {
    "crypto.tls": { last_seq: 120, in_memory: 120, consumer_groups: { audit: { lag: 0 } } },
    "crypto.estate": { last_seq: 30, in_memory: 30, consumer_groups: { audit: { lag: 4 } } },
  },
};
const detections = [
  { rule: "TLS_DOWNGRADE", severity: "CRITICAL", detail: "TLS 1.0 negotiated", detected_at: "2026-10-24T09:00:00Z", endpoint: "10.0.0.5:443" },
  { rule: "CERT_PIN_MISMATCH", severity: "HIGH", detail: "pinned fingerprint changed", detected_at: "2026-10-24T09:05:00Z", system: "core-1" },
];

describe("Live stream visualization", () => {
  it("draws an uninitialised bus, an unfired detector and an uninspected CBOM separately", async () => {
    mockFetch({});
    draw();
    expect(await screen.findByText("No topics in the bus")).toBeInTheDocument();
    expect(screen.getByText("No detections observed")).toBeInTheDocument();
    expect(screen.getByText("No rule has fired")).toBeInTheDocument();
    expect(screen.getByText("No system inspected")).toBeInTheDocument();
    // absence is never rendered as a measured zero
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("bars each topic against the busiest topic and reads lag from the payload", async () => {
    mockFetch({ "/api/v1/stream/stats": stats, "/api/v1/attacks": { detections }, "/api/v1/attacks/summary": { by_rule: { TLS_DOWNGRADE: 1 }, by_severity: { CRITICAL: 1, HIGH: 1 } } });
    draw();
    expect(await screen.findByText("crypto.tls")).toBeInTheDocument();
    expect(screen.getByText("crypto.estate")).toBeInTheDocument();
    expect(screen.getByText("lag 0")).toBeInTheDocument();
    expect(screen.getByText("lag 4")).toBeInTheDocument();
    expect(screen.getByText(/bar = last sequence relative to the busiest topic in this read/)).toBeInTheDocument();
  });

  it("draws one tick per detection and one severity cell per returned severity", async () => {
    mockFetch({ "/api/v1/stream/stats": stats, "/api/v1/attacks": { detections }, "/api/v1/attacks/summary": { by_rule: { TLS_DOWNGRADE: 1, CERT_PIN_MISMATCH: 1 }, by_severity: { CRITICAL: 1, HIGH: 1 } } });
    draw();
    expect(await screen.findByText("2 tick(s)")).toBeInTheDocument();
    expect(screen.getAllByText("TLS_DOWNGRADE").length).toBeGreaterThan(0);
    expect(screen.getByText("10.0.0.5:443")).toBeInTheDocument();
    expect(screen.getByText("detections read")).toBeInTheDocument();
    expect(screen.getByText(/A share of detections is not a share of exposure/)).toBeInTheDocument();
  });

  it("states a broken hash chain with the version it broke at", async () => {
    mockFetch({
      "/api/v1/cbom/live/core-1": { system_id: "core-1", version_no: 3, generated_at: "2026-10-24T09:00:00Z", version_hash: "abcdef1234567890", prev_hash: "x", asset_count: 12, jws: "jws", freshness: { stale: false, seconds_since_update: 30, stale_after_seconds: 600 } },
      "/api/v1/cbom/verify/core-1": { chain_valid: false, broke_at: 2, versions: 3, reason: null },
      "/api/v1/cbom/versions/core-1": { versions: [{ version_no: 2, generated_at: "2026-10-24T08:00:00Z", version_hash: "deadbeefdeadbeef", asset_count: 8 }, { version_no: 3, generated_at: "2026-10-24T09:00:00Z", version_hash: "abcdef1234567890", asset_count: 12 }] },
    });
    draw();
    fireEvent.change(screen.getByPlaceholderText("system id (e.g. core-1)"), { target: { value: "core-1" } });
    fireEvent.click(screen.getByText("Inspect"));
    expect(await screen.findByText("BROKEN @2")).toBeInTheDocument();
    expect(screen.getByText(/first break at version 2/)).toBeInTheDocument();
    expect(screen.getByText("chain does not verify")).toBeInTheDocument();
    expect(screen.getByText("30s")).toBeInTheDocument(); // the record's own age, verbatim
    expect(screen.getByText(/#3 · abcdef123456…/)).toBeInTheDocument();
    expect(screen.getByText(/bar = asset count relative to the largest version/)).toBeInTheDocument();
  });

  it("keeps a failed CBOM read as an error, not as a last-good document", async () => {
    mockFetch({ "/api/v1/cbom/live/gone": new Response(JSON.stringify({ detail: "no such system" }), { status: 404 }) });
    draw();
    fireEvent.change(screen.getByPlaceholderText("system id (e.g. core-1)"), { target: { value: "gone" } });
    fireEvent.click(screen.getByText("Inspect"));
    expect(await screen.findByText(/HTTP 404/)).toBeInTheDocument();
    expect(screen.queryByText("version")).not.toBeInTheDocument();
    expect(screen.queryByText("No system inspected")).not.toBeInTheDocument();
  });
});
