/* Network — the drawing contract.
 *
 * The posture bar is made of counted endpoints: chain valid, chain invalid, and
 * chain not reported. An endpoint whose chain the scan never reported is drawn
 * as its own segment, and the screen never prints "x% healthy".
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Network from "./Network";

const draw = () => render(<MemoryRouter><Network /></MemoryRouter>);
const inventory = {
  generated_at: "2026-10-24T09:00:00Z", host: "core-1",
  counts: { hardware_devices: 0, network_assets: 3, libraries: 0, certificates: 2, processes: 0 },
  hardware: [], firmware: [],
  network: [
    { kind: "tls_endpoint", id: "web-1", ip: "10.0.0.5", tls: "TLS1.3", certs: ["c1"], os: "", status: "OK", cert_expiry_days: 40, chain_valid: true },
    { kind: "tls_endpoint", id: "web-2", ip: "10.0.0.6", tls: "TLS1.2", certs: ["c2"], os: "", status: "EXPIRED", cert_expiry_days: 2, chain_valid: false },
    { kind: "tls_endpoint", id: "web-3", ip: "10.0.1.7", tls: "TLS1.2", certs: [], os: "", status: "OK" },
  ],
  certificates: [], cert_center: { expired: 0, expiring30: 0, weak_algorithm: 0, unknown_owner: 0, total: 0 }, libraries: [], processes: [],
};
const structured = {
  inventory_id: "inv-1", revision: 4, persisted: true, status: "DRAFT",
  inventory: { devices: [{ device_id: "sw-1" }, { device_id: "sw-2" }], evidence: [{ id: "e1" }] },
  completeness: { status: "INCOMPLETE", score: 0.5, missing: ["routes"], next_actions: ["register routes"], },
  audit: {},
};
const topology = { inventory_id: "inv-1", revision: 4, graph: { nodes: [], edges: [] }, edge_counts: {}, node_count: 5, edge_count: 4, unlinked_devices: [], unknown_endpoints: ["10.0.9.9"] };
const drift = { inventory_id: "inv-1", revision: 4, status: "DRIFTED", devices: [], drifted_comparisons: 3, unknown_comparisons: 1, raw_configuration_stored: false as const };

describe("Network visualization", () => {
  it("draws the empty fabric as an absence, not a zeroed posture", async () => {
    mockFetch({});
    draw();
    expect((await screen.findAllByText(/No network data yet/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/drawn from observed endpoints only/)).toBeInTheDocument();
    // no posture composition is drawn when nothing was observed
    expect(screen.queryByText("chain not reported")).not.toBeInTheDocument();
  });

  it("composes posture from counted endpoints and keeps the unreported chains separate", async () => {
    mockFetch({ "/api/v1/live-scan/inventory": inventory });
    draw();
    expect(await screen.findByText("chain not reported")).toBeInTheDocument();
    expect(screen.getByText("chain valid")).toBeInTheDocument();
    expect(screen.getByText("chain invalid")).toBeInTheDocument();
    expect(screen.getByText(/A share of observed endpoints is not a share of the network/)).toBeInTheDocument();
    expect(screen.getByText("1 of 3 observed endpoints")).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("draws the structured register's own figures instead of a prose summary", async () => {
    mockFetch({ "/api/v1/live-scan/inventory": inventory, "/api/v1/network/inventory": structured, "/api/v1/network/inventory/topology": topology, "/api/v1/network/inventory/configuration/drift": drift, "/api/v1/network/inventory/risk": { inventory_id: "inv-1", revision: 4, profile_status: "DRAFT", posture: "AMBER", reasons: [], unknowns: ["owner not registered"], next_actions: [] } });
    draw();
    expect(await screen.findByText("graph nodes")).toBeInTheDocument();
    expect(screen.getByText("unknown endpoints")).toBeInTheDocument();
    expect(screen.getByText("DRIFTED")).toBeInTheDocument();
    expect(screen.getByText("3 drifted · 1 unknown comparisons")).toBeInTheDocument();
    expect(screen.getByText("register routes")).toBeInTheDocument();
    expect(screen.getByText("inventory risk unknowns")).toBeInTheDocument();
  });
});
