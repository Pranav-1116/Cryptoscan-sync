/* Infrastructure Performance (docs/performance/03_UI_SPEC.md §2): the eight
   interface tabs; a server row opens its TechBOM record, dependencies and
   Digital Twin history only when the identity is verified — and the gaps
   (virtualization, environmental hardware) are named, never zero-filled. */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import InfraWorkspace from "./InfraWorkspace";
import type { PerformanceInfraWorkspace } from "../lib/api";

const summary = {
  sample_count: 8, value_count: 6, unknown_count: 2,
  state: "partial — 6/8 delivered",
  average: 42, minimum: 30, maximum: 60, p50: 40, p95: 58, p99: 60,
};

const data: PerformanceInfraWorkspace = {
  categories: {
    cpu: { state: "measured", metrics: { "cpu.utilization_pct": summary }, basis: "" },
    memory: { state: "measured", metrics: { "ram.utilization_pct": summary }, basis: "" },
    storage: { state: "not_collected", metrics: {}, basis: "no storage telemetry is stored in the window" },
    disk: { state: "not_collected", metrics: {}, basis: "no disk telemetry is stored in the window" },
    processes: { state: "not_collected", metrics: {}, basis: "no processes telemetry is stored in the window" },
    virtualization: {
      state: "not_collected", metrics: {},
      basis: "virtualization telemetry (CPU ready, memory ballooning, host contention) has no authorized collector — a named gap, not a healthy host",
    },
    containers: { state: "not_collected", metrics: {}, basis: "no containers telemetry is stored in the window" },
    kubernetes: { state: "not_collected", metrics: {}, basis: "no kubernetes telemetry is stored in the window" },
  },
  inventory: [
    {
      asset_id: "srv-a", link: "hw:srv-a", link_state: "linked",
      cpu_pct: 61.5, memory_pct: null, load: 2.4, disk_latency_ms: null,
      families: ["cpu.utilization_pct", "system.load"], samples: 12,
      last_observed: "2026-10-16T10:00:00+00:00",
    },
    {
      asset_id: "srv-b", link: null, link_state: "not established",
      cpu_pct: null, memory_pct: null, load: null, disk_latency_ms: null,
      families: ["cpu.utilization_pct"], samples: 3, last_observed: null,
    },
  ],
  trends: { "cpu.utilization_pct": summary },
  hardware_health: {
    state: "not_collected", metrics: {},
    basis: "environmental telemetry (temperature, fans, power supplies) has no authorized collector — reported as a gap, never as healthy readings",
  },
  note: "one workspace projection for the eight interface tabs — delivered telemetry only; a gap is named, never filled with zeros",
};

const renderWs = () =>
  render(
    <MemoryRouter>
      <InfraWorkspace data={data} />
    </MemoryRouter>,
  );

describe("Infrastructure Performance workspace (§2)", () => {
  it("draws the eight interface tabs and the honest virtualization gap", () => {
    renderWs();
    for (const label of [
      "Infrastructure Overview", "Server Inventory", "CPU & Memory",
      "Storage Performance", "Virtualization", "Container Performance",
      "Hardware Health", "Historical Trends",
    ]) {
      expect(screen.getByRole("tab", { name: label })).toBeInTheDocument();
    }
    fireEvent.click(screen.getByRole("tab", { name: "Virtualization" }));
    expect(screen.getByText(/a named gap, not a healthy host/)).toBeInTheDocument();
    expect(screen.getAllByText("not collected").length).toBeGreaterThan(0);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("opens verified server rows into TechBOM, dependencies and twin history", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Server Inventory" }));
    expect(screen.getByText("srv-a")).toBeInTheDocument();
    const techbom = screen.getByRole("link", { name: "TechBOM record" });
    expect(techbom).toHaveAttribute("href", "/live-asset-intelligence?asset=hw%3Asrv-a");
    expect(screen.getByRole("link", { name: "Dependencies" })).toHaveAttribute(
      "href", "/live-asset-intelligence?asset=hw%3Asrv-a&detail_tab=dependencies");
    expect(screen.getByRole("link", { name: "Twin history" })).toHaveAttribute(
      "href", "/live-asset-intelligence?asset=hw%3Asrv-a&detail_tab=history");
  });

  it("keeps unverified identities unlinked instead of inventing records", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Server Inventory" }));
    expect(screen.getByText(/not established — no canonical record/)).toBeInTheDocument();
    expect(screen.getByText(/never invents asset identities/)).toBeInTheDocument();
    // exactly one set of record links — the verified row only
    expect(screen.getAllByRole("link", { name: "TechBOM record" }).length).toBe(1);
    // unread columns stay unknown
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThan(0);
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("names the hardware-health gap instead of drawing healthy readings", () => {
    renderWs();
    fireEvent.click(screen.getByRole("tab", { name: "Hardware Health" }));
    expect(screen.getByText(/temperature, fans, power supplies/)).toBeInTheDocument();
    expect(screen.getByText(/never as healthy readings/)).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("draws an empty estate as a collection gap, not an empty list", () => {
    render(
      <MemoryRouter>
        <InfraWorkspace data={{ ...data, inventory: [], trends: {}, hardware_health: { state: "not_collected", metrics: {}, basis: "" } }} />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Server Inventory" }));
    expect(screen.getByText(/collection gap, not an empty estate/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Historical Trends" }));
    expect(screen.getByText(/collection gap, not a flat line/)).toBeInTheDocument();
  });
});
