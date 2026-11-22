import React from "react";
import { act, fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setActiveTenantId } from "../lib/api";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { agent, monitor } from "../test/opsFixtures";
import LiveMonitor from "./LiveMonitor";

const PATH = "/api/v1/operations/monitor";

describe("live monitor", () => {
  it("states the overall status and every agent's heartbeat against its thresholds", async () => {
    mockFetch({ [PATH]: monitor([agent("mrdn-sbx-dc1-swiftgw01"), agent("mrdn-sbx-dc1-coredb01", { age: 300, system: { name: "Core Banking", criticality: "tier-0" } })]) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const banner = await screen.findByRole("region", { name: "Estate status" });
    expect(banner).toHaveTextContent("Operational");
    expect(banner).toHaveTextContent("Every agent is reporting");
    const grid = screen.getByRole("region", { name: "Agent freshness" });
    expect(grid).toHaveTextContent("late after 3m, offline after 10m");
    expect(within(grid).getByLabelText("Agent mrdn-sbx-dc1-coredb01")).toHaveTextContent("Late");
    expect(within(grid).getByLabelText("Agent mrdn-sbx-dc1-swiftgw01")).toHaveTextContent("CPU 25%");
    expect(screen.getByLabelText("Collection coverage")).toHaveTextContent("84.2%");
  });

  it("lists each alert with its rule and next action, and filters by severity", async () => {
    const offline = agent("mrdn-sbx-dc1-swiftgw01", { age: 900 });
    mockFetch({ [PATH]: monitor([offline], {
      status: { state: "DEGRADED", headline: "1 agent is not reporting", meaning: "" },
      alerts: [
        { id: "a1", rule: "AGENT_OFFLINE", severity: "CRITICAL", subject: offline.name, title: "SWIFT Gateway agent is offline",
          detail: "no heartbeat for 15m", next_action: "check the agent service on the host", since: new Date().toISOString(),
          agent: offline.name, system: "SWIFT Gateway", link: "/live-scanners" },
        { id: "a2", rule: "CHANGES_UNREVIEWED", severity: "LOW", subject: "estate", title: "6 estate changes are unreviewed",
          detail: "", next_action: "review them in Activity", since: null, agent: null, system: null, link: "/live-stream" },
      ],
      alert_counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1 },
    }) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const list = await screen.findByRole("list", { name: "Alert list" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByLabelText("Alert SWIFT Gateway agent is offline")).toHaveTextContent("AGENT_OFFLINE · SWIFT Gateway");
    expect(screen.getByLabelText("Alert SWIFT Gateway agent is offline")).toHaveTextContent("check the agent service on the host");
    expect(screen.getByRole("region", { name: "Estate status" })).toHaveTextContent("Degraded");
    fireEvent.click(screen.getByRole("button", { name: "Only LOW" }));
    expect(within(screen.getByRole("list", { name: "Alert list" })).getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByRole("list", { name: "Alert list" })).toHaveTextContent("6 estate changes are unreviewed");
  });

  it("shows a host with no performance sample as not sampled, never as idle", async () => {
    mockFetch({ [PATH]: monitor([agent("mrdn-sbx-br0142-legacy01", { cpu: null })]) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    const card = await screen.findByLabelText("Agent mrdn-sbx-br0142-legacy01");
    expect(card).toHaveTextContent("CPU —");
    expect(card).toHaveTextContent("not sampled");
    expect(card).not.toHaveTextContent("0%");
  });

  it("a failed read is not 'everything is fine'", async () => {
    mockFetch({ [PATH]: () => new Response(JSON.stringify({ detail: "denied" }), { status: 403 }) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    expect(await screen.findByText("The platform could not be read")).toBeInTheDocument();
    expect(screen.queryByText("Operational")).not.toBeInTheDocument();
  });

  it("drops the previous tenant's status on a tenant switch", async () => {
    setActiveTenantId("a");
    mockFetch({ [PATH]: (_url: string, init?: RequestInit) =>
      new Headers(init?.headers).get("X-Tenant-ID") === "a"
        ? monitor([agent("tenant-a-agent")])
        : monitor([], { status: { state: "NOT_CONNECTED", headline: "No agent is enrolled", meaning: "" } }) });
    renderWithProviders(<LiveMonitor />, { route: "/live-monitor" });
    expect(await screen.findByLabelText("Agent tenant-a-agent")).toBeInTheDocument();
    await act(async () => { setActiveTenantId("b"); });
    expect(await screen.findByText("No agent is enrolled")).toBeInTheDocument();
    expect(screen.queryByLabelText("Agent tenant-a-agent")).not.toBeInTheDocument();
    setActiveTenantId(null);
  });
});
