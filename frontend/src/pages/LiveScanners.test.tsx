import React from "react";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { agent, fleet } from "../test/opsFixtures";
import LiveScanners from "./LiveScanners";

describe("live scanners", () => {
  it("lists every agent with its heartbeat, delivery and the planes it collected", async () => {
    mockFetch({ "/api/v1/operations/fleet": fleet([agent("mrdn-sbx-dc1-swiftgw01"), agent("mrdn-sbx-dc1-coredb01", { age: 900, buffered: 4 })]) });
    renderWithProviders(<LiveScanners />, { route: "/live-scanners" });
    const table = await screen.findByRole("table", { name: "Agents" });
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(table).toHaveTextContent("Offline");
    expect(table).toHaveTextContent("4 buffered");
    expect(screen.getByLabelText("Planes of mrdn-sbx-dc1-swiftgw01")).toHaveTextContent("CBOM");
    expect(screen.getByLabelText("Not reporting")).toHaveTextContent("1");
  });

  it("opens an agent's collectors and states each source's outcome", async () => {
    mockFetch({ "/api/v1/operations/fleet": fleet([agent("mrdn-sbx-dc1-swiftgw01")]) });
    renderWithProviders(<LiveScanners />, { route: "/live-scanners" });
    fireEvent.click(await screen.findByRole("button", { name: "Collectors for mrdn-sbx-dc1-swiftgw01" }));
    const plane = screen.getByLabelText("Plane Cryptographic (CBOM)");
    expect(plane).toHaveTextContent("tls-config");
    expect(plane).toHaveTextContent("READ · 3");
    expect(plane).toHaveTextContent("NOT_CONFIGURED");
    expect(plane).toHaveTextContent("no HSM module path");
  });

  it("filters to agents that are not reporting", async () => {
    mockFetch({ "/api/v1/operations/fleet": fleet([agent("a-live"), agent("b-gone", { age: 900 })]) });
    renderWithProviders(<LiveScanners />, { route: "/live-scanners" });
    await screen.findByRole("table", { name: "Agents" });
    fireEvent.click(screen.getByRole("button", { name: "Only Offline" }));
    const table = screen.getByRole("table", { name: "Agents" });
    expect(table).toHaveTextContent("b-gone");
    expect(table).not.toHaveTextContent("a-live");
  });

  it("does not call the server scanners until their section is opened", async () => {
    const spy = mockFetch({ "/api/v1/operations/fleet": fleet([agent("a-live")]) });
    renderWithProviders(<LiveScanners />, { route: "/live-scanners" });
    await screen.findByRole("table", { name: "Agents" });
    const liveScan = () => spy.mock.calls.filter(([u]) => String(u).includes("/live-scan/"));
    expect(liveScan()).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: /Scanners on the CryptoScan server/ }));
    await waitFor(() => expect(liveScan().length).toBeGreaterThan(0));
  });
});
