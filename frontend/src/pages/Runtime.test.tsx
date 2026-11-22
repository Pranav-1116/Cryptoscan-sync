import React from "react";
import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { agent, host, hosts } from "../test/opsFixtures";
import Runtime from "./Runtime";

describe("runtime hosts", () => {
  it("shows what runs on the selected host and which process loaded each crypto library", async () => {
    mockFetch({ "/api/v1/operations/hosts": hosts([host(agent("mrdn-sbx-dc1-swiftgw01"))]) });
    renderWithProviders(<Runtime />, { route: "/runtime" });
    expect(await screen.findByRole("list", { name: "Services" })).toHaveTextContent("nginx");
    expect(screen.getByRole("list", { name: "Libraries" })).toHaveTextContent("loaded by nginx");
    expect(screen.getByRole("table", { name: "Listeners" })).toHaveTextContent("8443/tcp");
    expect(screen.getByRole("table", { name: "Listeners" })).toHaveTextContent("exposed · TLSv1.3");
    expect(screen.getByLabelText("Algorithms")).toHaveTextContent("RSA · quantum-vulnerable");
    expect(screen.getByRole("list", { name: "Certificates and keys" })).toHaveTextContent("expires in 20 days");
    expect(screen.getByLabelText("CPU 25%")).toBeInTheDocument();
  });

  it("switches host and keeps an unsampled host unknown, not idle", async () => {
    const a = agent("mrdn-sbx-dc1-swiftgw01");
    const b = agent("mrdn-sbx-br0142-legacy01", { cpu: null, system: { name: "Branch Banking" } });
    mockFetch({ "/api/v1/operations/hosts": hosts([host(a), host(b, { libraries: [{ name: "OpenSSL 1.1.1", version: "1.1.1", path: "/lib/libssl.so.1.1", loaded: false, loaded_by: [] }] })]) });
    renderWithProviders(<Runtime />, { route: "/runtime" });
    fireEvent.click(await screen.findByRole("button", { name: "Select legacy01" }));
    const detail = screen.getByRole("region", { name: /Host mrdn-sbx-br0142-legacy01\.mrdn\.bank|Host legacy01/ });
    expect(detail).toHaveTextContent("no performance sample");
    expect(screen.getByLabelText("CPU not sampled")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Libraries" })).toHaveTextContent("installed, not seen loaded");
  });
});
