/* Live systems — the bank servers Cryptava agents report from. The honesty rules
   (docs/performance/01_PRODUCT_SPEC.md) are display rules here too: a figure the
   agent could not read is "—" with its reason, never 0; a quiet agent is STALE;
   link capacity is labelled capacity, not traffic. */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import LiveSystemsPanel from "./LiveSystemsPanel";
import Performance from "../pages/Performance";

const m = (value: number, unit: string, labels?: Record<string, string>) => ({ value, unit, labels });

const swift = {
  agent: "mrdn-sbx-dc1-swiftgw01",
  agent_id: "a-1",
  asset_id: "mrdn-sbx-dc1-swiftgw01::host",
  host: "swift-gateway",
  system: "SWIFT gateway",
  ip: "10.210.0.4",
  scope: "workload",
  state: "live",
  last_sample_at: "2026-11-16T08:00:00Z",
  age_seconds: 20,
  interval_seconds: 60,
  signed: true,
  metrics: {
    "cpu.utilization_pct": m(12.5, "percent"),
    "network.throughput_mbps": m(0.042, "Mbps"),
    "network.bandwidth_mbps": m(10000, "Mbps"),
    "network.connections": m(14, "count"),
    "process.health": m(1, "ratio", { processes: "3", zombies: "0" }),
  },
  tls: [{ port: "443", ms: 3.21, tls_version: "TLSv1.3", algorithm: "TLS_AES_256_GCM_SHA384" }],
  missing: [{ metric: "ram.utilization_pct", reason: "no cgroup memory limit is set" }],
  trend: { "cpu.utilization_pct": [{ t: "a", v: 10 }, { t: "b", v: 12.5 }] },
  samples: 4,
};

const legacy = {
  agent: "mrdn-sbx-br0142-legacy01", asset_id: "mrdn-sbx-br0142-legacy01::host",
  host: "legacy-branch", system: null, ip: "10.210.0.5", scope: "host",
  state: "stale", age_seconds: 900, signed: true, metrics: {}, tls: [], missing: [], trend: {}, samples: 1,
};

const waiting = {
  agent: "mrdn-sbx-dc1-hsmsim01", asset_id: "mrdn-sbx-dc1-hsmsim01::host",
  host: "hsm-sim", state: "no_samples", age_seconds: null, signed: false,
  metrics: {}, tls: [], missing: [], trend: {}, samples: 0,
};

const live = (systems: unknown[]) => ({
  tenant_id: "default",
  generated_at: "2026-11-16T08:00:20Z",
  window_minutes: 30,
  systems,
  counts: { systems: 3, live: 1, stale: 1, no_samples: 1 },
  truncated: false,
  note: "figures are what each agent measured and signed",
});

const renderPanel = (props: Partial<React.ComponentProps<typeof LiveSystemsPanel>> = {}) =>
  render(
    <MemoryRouter>
      <LiveSystemsPanel tenant="default" {...props} />
    </MemoryRouter>,
  );

describe("Live systems (Cryptava agents)", () => {
  it("shows each reporting server with its signed figures", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([swift, legacy, waiting]) });
    renderPanel();
    const card = await screen.findByTestId("live-system-mrdn-sbx-dc1-swiftgw01");
    expect(within(card).getByText(/signature verified/)).toBeInTheDocument();
    expect(screen.getByText("swift-gateway")).toBeInTheDocument();
    expect(screen.getByText(/SWIFT gateway · 10\.210\.0\.4/)).toBeInTheDocument();
    expect(screen.getByText("12.5 %")).toBeInTheDocument();
    expect(screen.getByText("3.21 ms")).toBeInTheDocument();
    expect(screen.getByText(/TLSv1\.3/)).toBeInTheDocument();
    expect(screen.getByText(/1 live · 1 stale · 1 waiting/)).toBeInTheDocument();
  });

  it("renders an unread figure as unknown with its reason, never zero", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([swift]) });
    renderPanel();
    expect(await screen.findByText(/ram\.utilization_pct — no cgroup memory limit is set/)).toBeInTheDocument();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(screen.queryByText("0 %")).not.toBeInTheDocument();
  });

  it("labels link speed as capacity, separate from traffic", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([swift]) });
    renderPanel();
    expect(await screen.findByText("Link capacity")).toBeInTheDocument();
    expect(screen.getByText("10,000 Mbps")).toBeInTheDocument();
    expect(screen.getByText("0.042 Mbps")).toBeInTheDocument();
  });

  it("marks a quiet agent stale and a silent one as a gap", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([legacy, waiting]) });
    renderPanel();
    expect(await screen.findByText("STALE")).toBeInTheDocument();
    expect(screen.getByText(/15 min ago/)).toBeInTheDocument();
    expect(screen.getByText("NO SAMPLES YET")).toBeInTheDocument();
    expect(screen.getByText(/a gap, not an idle server/)).toBeInTheDocument();
  });

  it("explains how to connect agents when none report", async () => {
    mockFetch({ "/api/v1/performance/live-systems": { ...live([]), counts: { systems: 0, live: 0, stale: 0, no_samples: 0 } } });
    renderPanel();
    expect(await screen.findByText(/no Cryptava agent has reported performance yet/)).toBeInTheDocument();
    expect(screen.getByText("bash sandbox/run_sandbox.sh agents check")).toBeInTheDocument();
  });

  it("names a failed read instead of showing an empty fleet", async () => {
    mockFetch({});
    renderPanel();
    expect(await screen.findByText(/Live systems could not be read/)).toBeInTheDocument();
  });

  it("shows the compact table on the overview", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([swift, legacy]) });
    renderPanel({ compact: true, onOpen: () => undefined });
    expect(await screen.findByText("Last sample")).toBeInTheDocument();
    expect(screen.getByText("20 s ago")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open live systems/ })).toBeInTheDocument();
  });

  it("opens straight on the live view from ?view=live", async () => {
    mockFetch({ "/api/v1/performance/live-systems": live([swift]) });
    render(
      <MemoryRouter initialEntries={["/performance?view=live"]}>
        <Performance />
      </MemoryRouter>,
    );
    expect(await screen.findByTestId("live-system-mrdn-sbx-dc1-swiftgw01")).toBeInTheDocument();
    expect((screen.getByLabelText("Performance view") as HTMLSelectElement).value).toBe("live");
  });
});
