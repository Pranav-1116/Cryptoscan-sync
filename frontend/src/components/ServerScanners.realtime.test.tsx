/* Realtime scanners: the fleet view must draw the runner's own report, and the
 * cycle record must only ever count cycles this screen watched. */
import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import ServerScanners from "./ServerScanners";

const statusPath = "/api/v1/live-scan/status";

const idle = {
  running: false,
  last_run_at: null as string | null,
  periodic: { enabled: false, interval_seconds: 900 },
  scanners: {} as Record<string, unknown>,
  ok_count: 0,
  failed_count: 0,
};

describe("realtime scanner visualisation", () => {
  it("shows an empty fleet as an absence, not as eight silent passes", async () => {
    mockFetch({ [statusPath]: idle });
    renderWithProviders(<ServerScanners />, { route: "/live-scanners" });
    expect(await screen.findByText("No scanner result recorded")).toBeInTheDocument();
    // “no result” is counted separately from ok and failed
    expect(screen.getByText("no result")).toBeInTheDocument();
    expect(screen.getByText(/it is not a pass/)).toBeInTheDocument();
    expect(screen.getByText("Cycle duration — no samples")).toBeInTheDocument();
    expect(screen.getByText("No cycle has completed while this screen was open.")).toBeInTheDocument();
  });

  it("draws each scanner's reported elapsed time and marks the silent ones", async () => {
    mockFetch({
      [statusPath]: {
        ...idle,
        last_run_at: "2026-10-29T06:00:00Z",
        ok_count: 1,
        failed_count: 1,
        scanners: {
          hardware: { ok: true, elapsed_s: 2.5, summary: { tpm: "present" } },
          runtime: { ok: false, elapsed_s: 9, error: "collector denied" },
        },
      },
    });
    renderWithProviders(<ServerScanners />, { route: "/live-scanners" });
    await waitFor(() => expect(screen.getByText("2.50s")).toBeInTheDocument());
    expect(screen.getByText("9.00s")).toBeInTheDocument();
    expect(screen.getByText("collector denied")).toBeInTheDocument();
    expect(screen.getByText("tpm=present")).toBeInTheDocument();
    // scanners the cycle did not report carry no time and say so
    expect(screen.getAllByText("no time").length).toBeGreaterThan(0);
  });

  it("records a new last_run_at as one observed cycle without inventing a duration", async () => {
    mockFetch({
      [statusPath]: { ...idle, last_run_at: "2026-10-29T06:00:00Z", ok_count: 2, failed_count: 0, scanners: { hardware: { ok: true } } },
    });
    renderWithProviders(<ServerScanners />, { route: "/live-scanners" });
    await waitFor(() => expect(screen.getByText("Cycles observed here")).toBeInTheDocument());
    // one cycle seen through the status snapshot
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
    expect(screen.getByText(/1 cycle\(s\) observed since this screen opened/)).toBeInTheDocument();
    // the snapshot carries no elapsed time, so no duration line is drawn
    expect(screen.getByText("Cycle duration — no samples")).toBeInTheDocument();
  });

  it("marks which scanners the current form would request", async () => {
    mockFetch({ [statusPath]: idle });
    renderWithProviders(<ServerScanners />, { route: "/live-scanners" });
    await screen.findByText("will request");
    // hardware + runtime always, every target scanner is off until a target is given
    expect(screen.getByTitle("Hardware (CPU / TPM / HSM)")).toBeInTheDocument();
    expect(screen.getByTitle("Network TLS probe")).toBeInTheDocument();
  });
});
