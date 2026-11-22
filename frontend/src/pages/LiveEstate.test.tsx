import React from "react";
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { agent, fleet, host, hosts, monitor } from "../test/opsFixtures";
import LiveEstate from "./LiveEstate";

function serve(agents: ReturnType<typeof agent>[], mon = monitor(agents)) {
  return mockFetch({
    "/api/v1/operations/monitor": mon,
    "/api/v1/operations/fleet": fleet(agents),
    "/api/v1/operations/hosts": hosts(agents.map((a) => host(a))),
  });
}

describe("live estate", () => {
  it("groups hosts under the business system their agent declares, most critical first", async () => {
    const swift = agent("mrdn-sbx-dc1-swiftgw01");
    const branch = agent("mrdn-sbx-br0142-legacy01", { age: 400, system: { name: "Branch Banking", criticality: "tier-2" } });
    const loose = agent("mrdn-sbx-dc1-lab01", { system: null });
    serve([branch, loose, swift]);
    renderWithProviders(<LiveEstate />, { route: "/live" });
    const systems = await screen.findByLabelText("Systems");
    const names = within(systems).getAllByRole("region").map((r) => r.getAttribute("aria-label"));
    expect(names).toEqual(["System SWIFT Gateway", "System Branch Banking", "System No system declared"]);
    expect(screen.getByRole("region", { name: "System Branch Banking" })).toHaveTextContent("Late");
    expect(screen.getByRole("region", { name: "System SWIFT Gateway" })).toHaveTextContent("Q-vulnerable1");
    expect(screen.getByLabelText("Systems watched")).toHaveTextContent("2");
  });

  it("attaches an alert to the system it names and keeps the rest estate-wide", async () => {
    const swift = agent("mrdn-sbx-dc1-swiftgw01");
    serve([swift], monitor([swift], {
      alerts: [
        { id: "x", rule: "HOST_CPU_HIGH", severity: "MEDIUM", subject: swift.name, title: "SWIFT Gateway CPU at 92%", detail: "",
          next_action: "look at the process list", since: null, agent: swift.name, system: "SWIFT Gateway", link: null },
        { id: "y", rule: "NO_TRUSTED_COLLECTOR_KEY", severity: "LOW", subject: "ingestion", title: "No collector key is trusted", detail: "",
          next_action: "pin the agents' signing keys", since: null, agent: null, system: null, link: null },
      ],
      alert_counts: { MEDIUM: 1, LOW: 1 },
    }));
    renderWithProviders(<LiveEstate />, { route: "/live" });
    expect(await screen.findByRole("region", { name: "System SWIFT Gateway" })).toHaveTextContent("SWIFT Gateway CPU at 92%");
    expect(screen.getByRole("region", { name: "Estate-wide alerts" })).toHaveTextContent("No collector key is trusted");
    expect(screen.getByRole("region", { name: "Estate-wide alerts" })).not.toHaveTextContent("CPU at 92%");
  });

  it("says no system is watched when no agent is enrolled", async () => {
    serve([], monitor([], { connection: { state: "NOT_CONNECTED", last_observation: null, seconds_since: null, interval_seconds: 300, stale_after_seconds: 600, meaning: "" } }));
    renderWithProviders(<LiveEstate />, { route: "/live" });
    expect(await screen.findByText(/No agent is enrolled, so no system is being watched/)).toBeInTheDocument();
    expect(screen.getByLabelText("Estate connection")).toHaveTextContent("no observation yet");
  });

  it("a failed read shows no figures", async () => {
    mockFetch({ "/api/v1/operations/monitor": () => new Response("{}", { status: 500 }) });
    renderWithProviders(<LiveEstate />, { route: "/live" });
    expect(await screen.findByText("The platform could not be read")).toBeInTheDocument();
    expect(screen.queryByLabelText("Systems")).not.toBeInTheDocument();
  });
});
