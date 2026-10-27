/* System Health page (§5, round 78): the Queue & Worker Pool row now has an
 * INDEPENDENT probe — GET /health/worker-fleet measures the durable records
 * (job statuses, stuck running, event-queue depth, stale leases, the worker
 * monitor lease). Drain evidence is completions or a live lease, never API
 * liveness; the row never claims a synthetic latency. */
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import SystemHealth from "./SystemHealth";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const fleetOperational = {
  status: "Operational",
  detail: "drain observed: 2 completion(s) in the last hour, live monitor lease (worker-1)",
  jobs: { by_status: { QUEUED: 1, COMPLETED: 2 }, total: 3, oldest_queued_s: 94,
          stuck_running: 0, completed_last_hour: 2, failed_last_hour: 0 },
  event_queue: { by_status: { queued: 3, completed: 5 }, total: 8,
                 oldest_queued_s: 40, stale_leases: 0, completed_last_hour: 0 },
  worker_heartbeat: { measured: true, holder: "worker-1", heartbeat_age_s: 5, lease_live: true },
  drain_evidence: { completions_last_hour: 2, lease_live: true },
  note: "",
};

function renderPage() {
  render(
    <MemoryRouter>
      <SystemHealth />
    </MemoryRouter>,
  );
}

function mockBackend(fleet: unknown, connectors?: unknown) {
  mockFetch({
    "/healthz": { status: "ok" },
    "/api/v1/ops/slo": {},
    "/healthz/dependencies": {
      status: "ok", down: [],
      checks: [
        { name: "database", status: "ok", detail: "sqlite" },
        { name: "redis", status: "skipped", detail: "not configured" },
      ],
    },
    "/api/v1/health/worker-fleet": fleet,
    "/api/v1/health/connectors": connectors ?? {
      status: "Not measured", detail: "", count: 2,
      connectors: [
        { integration_id: "c1", name: "soc", kind: "siem", provider: "webhook",
          enabled: true, endpoint_configured: true, status: "Operational",
          detail: "last delivery delivered (HTTP 200) 1 attempt(s)",
          last_delivery: { status: "delivered", http_status: 200, attempts: 1, age_s: 30, event_type: "notification.remediation_verification" },
          recent_counts: { delivered: 3 } },
        { integration_id: "c2", name: "ops", kind: "itsm", provider: "webhook",
          enabled: true, endpoint_configured: true, status: "Not measured",
          detail: "registered but no delivery attempt recorded — registration is not health evidence",
          last_delivery: null, recent_counts: {} },
      ],
      note: "",
    },
    "/api/v1/assets": { total_count: 4 },
  });
}

describe("SystemHealth worker-fleet probe", () => {
  it("renders the measured queue & worker pool row — drain evidence, live heartbeat, no synthetic latency", async () => {
    localStorage.setItem("zelinx_token", "test-token");
    localStorage.setItem("cryptoscan_tenant", "test-tenant");
    mockBackend(fleetOperational);
    renderPage();

    // the row reports the MEASURED facts, not API liveness
    expect(await screen.findByText("Queue & Worker Pool")).toBeTruthy();
    expect(await screen.findByText(/jobs: 1 queued \/ 2 completed/)).toBeTruthy();
    expect(screen.getByText(/events waiting: 3/)).toBeTruthy();
    expect(screen.getByText(/heartbeat 5s ago \(live\)/)).toBeTruthy();
    expect(screen.getByText(/drain observed: 2 completion/)).toBeTruthy();
    // dependency rows still render from the infra probe
    expect(screen.getByText("PostgreSQL (evidence store)")).toBeTruthy();
    // §4.8: connector health measured from the delivery audit — Operational
    // for the delivered one, Not measured (never "connected") for the
    // registered-but-never-delivered one
    expect(screen.getByText("Connectors & Outbound Integrations")).toBeTruthy();
    expect(screen.getByText(/last delivery delivered \(HTTP 200\)/)).toBeTruthy();
    expect(screen.getByText(/registration is not health evidence/)).toBeTruthy();
    expect(screen.getAllByText("Operational").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Not measured").length).toBeGreaterThan(0);
    expect(screen.queryByText("CONNECTED")).toBeNull();
  });

  it("surfaces stuck work as Degraded with the exact measured reason", async () => {
    localStorage.setItem("zelinx_token", "test-token");
    localStorage.setItem("cryptoscan_tenant", "test-tenant");
    mockBackend({
      ...fleetOperational,
      status: "Degraded",
      detail: "1 running job(s) stuck (no update in 15 min)",
      jobs: { ...fleetOperational.jobs, by_status: { RUNNING: 1 }, stuck_running: 1 },
    });
    renderPage();

    expect(await screen.findByText("Queue & Worker Pool")).toBeTruthy();
    expect(await screen.findByText(/1 running job\(s\) stuck/)).toBeTruthy();
  });

  it("stays honestly Not measured when the probe is unreachable or unauthenticated", async () => {
    // no token set -> the authenticated fleet probe is never issued
    mockBackend(fleetOperational);
    renderPage();

    expect(await screen.findByText("Queue & Worker Pool")).toBeTruthy();
    expect(await screen.findByText(/Worker-fleet probe unavailable/)).toBeTruthy();
  });
});
