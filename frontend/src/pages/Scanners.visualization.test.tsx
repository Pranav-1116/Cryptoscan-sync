/* The scanner screens have to show work in progress without inventing it.
 *
 * Three things are easy to fake here and are pinned below: a progress
 * percentage the server never sent, timing for phases the record does not
 * timestamp, and a cycle history the screen never observed. */
import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { setActiveTenantId, setToken } from "../lib/api";
import Scanners from "./Scanners";

const trigger = "/api/v1/scans/trigger";
const job = "/api/v1/jobs/job-viz-1";

function queueSourceScan() {
  fireEvent.click(screen.getByRole("button", { name: /Source Repository AST/ }));
  fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
  fireEvent.change(screen.getByLabelText(/Repository URL/), { target: { value: "/workspace/project" } });
  fireEvent.click(screen.getByRole("button", { name: "Queue Source Scan" }));
}

const stages = [
  { name: "clone", index: 1, state: "COMPLETED" },
  { name: "language_detect", index: 2, state: "COMPLETED" },
  { name: "scan", index: 3, state: "RUNNING" },
  { name: "evidence", index: 4, state: "PENDING" },
];

describe("scanner run visualisation", () => {
  it("draws the pipeline stages and the record's own percentage verbatim", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: () => ({
        job_id: "job-viz-1", status: "RUNNING", job_type: "MANUAL",
        created_at: "2026-10-29T06:00:00Z", started_at: "2026-10-29T06:00:04Z",
        progress: { current_stage: "scan", percent: 43, stages_complete: 2, total_stages: 14, stages,
          logs: [{ ts: "2026-10-29T06:00:05Z", stage: "scan", level: "INFO", message: "scanning 12 files" }] },
      }),
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    await waitFor(() => expect(screen.getByText("Pipeline stages · scan")).toBeInTheDocument());
    // the server's figure, labelled as the record's
    expect(screen.getByText("43%")).toBeInTheDocument();
    expect(screen.getByText(/2\/14 stages complete/)).toBeInTheDocument();
    expect(screen.getByText(/Stages complete \(as reported by the run record\)/)).toBeInTheDocument();
    // each stage keeps its reported state
    expect(screen.getByTitle("1. clone — COMPLETED")).toBeInTheDocument();
    expect(screen.getByTitle("3. scan — RUNNING")).toBeInTheDocument();
    expect(screen.getByTitle("4. evidence — PENDING")).toBeInTheDocument();
  });

  it("reports no percentage when the record carries none", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: { job_id: "job-viz-1", status: "RUNNING", progress: { stages, current_stage: "scan" } },
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    await waitFor(() => expect(screen.getByText("Pipeline stages · scan")).toBeInTheDocument());
    expect(screen.queryByText("Stages complete (as reported by the run record)")).toBeNull();
    expect(screen.queryByText(/% reported/)).toBeNull();
  });

  it("draws phase timing from the record's timestamps", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: {
        job_id: "job-viz-1", status: "COMPLETED",
        created_at: "2026-10-29T06:00:00Z", started_at: "2026-10-29T06:00:02Z", completed_at: "2026-10-29T06:00:12Z",
        progress: { coverage: { files: 3, findings_count: 0 } },
      },
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    await waitFor(() => expect(screen.getByText("Run phases")).toBeInTheDocument());
    // The run interval is the record's: started 06:00:02 → completed 06:00:12.
    expect(screen.getByText("submitted → worker start")).toBeInTheDocument();
    expect(screen.getByText("10.0s")).toBeInTheDocument();
    // The queue interval cannot be computed from a record whose timestamps
    // predate the submission this screen made; it stays "unknown" rather than
    // being drawn as a negative or zero wait.
    expect(screen.getAllByText("unknown").length).toBe(1);
    expect(screen.queryByText("-")).toBeNull();
    expect(screen.getByTitle(/the console adds no estimate/)).toBeInTheDocument();
  });

  it("says the timing is unknown instead of drawing a zero-length phase", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: { job_id: "job-viz-1", status: "RUNNING", progress: { stages } },
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    expect(await screen.findByText("No phase timing recorded")).toBeInTheDocument();
    expect(screen.queryByText("0.0s")).toBeNull();
  });

  it("renders the worker's own log entries, errors in red", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: { job_id: "job-viz-1", status: "FAILED", error_message: "Pipeline failed at stage scan",
        progress: { logs: [
          { ts: "2026-10-29T06:00:05Z", stage: "clone", level: "INFO", message: "clone ok" },
          { ts: "2026-10-29T06:00:09Z", stage: "scan", level: "ERROR", message: "collector refused" },
        ] } },
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    await waitFor(() => expect(screen.getByText("Run log")).toBeInTheDocument());
    expect(screen.getByText("clone ok")).toBeInTheDocument();
    expect(screen.getByText("collector refused")).toBeInTheDocument();
    expect(screen.getByText("2 entries")).toBeInTheDocument();
  });

  it("draws coverage counts as bars and keeps them labelled as a summary", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      [trigger]: { job_id: "job-viz-1", status: "QUEUED" },
      [job]: { job_id: "job-viz-1", status: "COMPLETED", progress: { coverage: { files: 3, findings_count: 0 } } },
    });
    renderWithProviders(<Scanners />);
    queueSourceScan();
    await waitFor(() => expect(screen.getByText("Coverage counts in this run")).toBeInTheDocument());
    expect(screen.getByText("findings count")).toBeInTheDocument();
    expect(screen.getAllByText(/summarize the scan result/).length).toBeGreaterThan(0);
  });

  it("groups a sweep's open endpoints by port and counts what it could not parse", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    mockFetch({
      "/api/v1/network/discover": {
        hosts_checked: 3,
        endpoints: ["10.0.1.1:443", "10.0.1.2:443", "10.0.1.3:8443", "no-port-here"],
      },
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText("Authorized network IP / CIDR"), { target: { value: "10.0.1.0/24" } });
    fireEvent.change(screen.getByLabelText("Execution mode"), { target: { value: "active" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /I authorize active probes/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start Authorized Sweep" }));
    await waitFor(() => expect(screen.getByText("port 443")).toBeInTheDocument());
    expect(screen.getByText("port 8443")).toBeInTheDocument();
    expect(screen.getByText("Hosts checked")).toBeInTheDocument();
    expect(screen.getByText("No port parsed")).toBeInTheDocument();
  });
});
