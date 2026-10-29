/* Cryptography — the drawing contract.
 *
 * The catalog is a composition of verdicts, not a score. Live library and
 * certificate counts exist only after a runtime scan; without one they are
 * drawn hatched with a reason, never as a zero.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import Crypto from "./Crypto";

const draw = () => render(<MemoryRouter><Crypto /></MemoryRouter>);
const algorithms = [
  { algorithm: "RSA-2048", family: "rsa", status: "RESTRICTED", key_size: 2048, quantum_vulnerable: true },
  { algorithm: "SHA-1", family: "sha1", status: "DISALLOWED", key_size: 160, quantum_vulnerable: true },
  { algorithm: "ML-KEM-768", family: "pqc", status: "ALLOWED", key_size: 768, quantum_vulnerable: false },
];
const catalog = { count: 3, status_counts: { ALLOWED: 1, RESTRICTED: 1, DISALLOWED: 1 }, counts_by_status: { ALLOWED: 1, RESTRICTED: 1, DISALLOWED: 1 }, algorithms };
const protocols = { count: 2, status_counts: { ALLOWED: 1, DEPRECATED: 1 }, protocols: [
  { protocol: "https", category: "web", status: "ALLOWED", port: 443, encrypted: true },
  { protocol: "telnet", category: "remote", status: "DISALLOWED", port: 23, encrypted: false },
] };
const inventory = {
  generated_at: "2026-10-24T09:00:00Z", host: "core-1",
  counts: { hardware_devices: 0, network_assets: 0, libraries: 2, certificates: 2, processes: 4 },
  hardware: [], firmware: [], network: [],
  certificates: [
    { cn: "core-1.example", sig: "sha256WithRSA", key: "rsa2048", days: 12, san: "", eku: "", owner: "payments", status: "EXPIRING", endpoint: "10.0.0.5:443", chain_position: 1, chain_length: 2 },
    { cn: "old.example", sig: "sha1WithRSA", key: "rsa1024", days: 400, san: "", eku: "", owner: "", status: "OK", endpoint: "10.0.0.6:443", chain_position: 1, chain_length: 1 },
  ],
  cert_center: { expired: 0, expiring30: 1, weak_algorithm: 1, unknown_owner: 1, total: 2 },
  libraries: [
    { name: "openssl", version: "3.0.9", status: "SUPPORTED", package: "debian", processes: 4 },
    { name: "libgcrypt", version: "1.10", status: "DEPRECATED", package: "debian", processes: 1 },
  ],
  processes: [],
};

describe("Cryptography visualization", () => {
  it("composes the catalog by status and by quantum verdict, with no score", async () => {
    mockFetch({ "/api/v1/algorithms": catalog, "/api/v1/network/protocols": protocols });
    draw();
    expect(await screen.findByText("disallowed")).toBeInTheDocument();
    expect(screen.getByText("restricted")).toBeInTheDocument();
    expect(screen.getByText("Shor-vulnerable")).toBeInTheDocument();
    expect(screen.getByText("PQC family")).toBeInTheDocument();
    expect(screen.getByText(/PQC presence is not a migration plan/)).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("draws unrun live inventory as hatched gaps rather than zeros", async () => {
    mockFetch({ "/api/v1/algorithms": catalog, "/api/v1/network/protocols": protocols });
    draw();
    expect(await screen.findByText("certificate health")).toBeInTheDocument();
    expect(screen.getByText(/Not measured is not zero/)).toBeInTheDocument();
    expect(screen.getByText(/An unrun scan is not an empty host/)).toBeInTheDocument();
    expect(screen.getByText("crypto libraries")).toBeInTheDocument();
    expect(screen.getAllByText("not measured").length).toBe(2);
  });

  it("draws the scan's own certificate counters and expiry bars", async () => {
    mockFetch({ "/api/v1/algorithms": catalog, "/api/v1/network/protocols": protocols, "/api/v1/live-scan/inventory": inventory });
    draw();
    expect((await screen.findAllByText("expiring ≤30d")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("weak algorithm").length).toBeGreaterThan(0);
    expect(screen.getByText("12d")).toBeInTheDocument();
    expect(screen.getByText("400d")).toBeInTheDocument();
    expect(screen.getByText(/days remaining relative to the longest-lived certificate/)).toBeInTheDocument();
    expect(screen.getByText(/bar = processes using the library/)).toBeInTheDocument();
  });

  it("labels a scan that observed nothing as the scan's own zero, not as an empty host", async () => {
    mockFetch({
      "/api/v1/algorithms": catalog,
      "/api/v1/network/protocols": protocols,
      "/api/v1/live-scan/inventory": { ...inventory, host: "e2b.local", libraries: [], certificates: [], cert_center: { expired: 0, expiring30: 0, weak_algorithm: 0, unknown_owner: 0, total: 0 }, counts: { hardware_devices: 1, network_assets: 0, libraries: 0, certificates: 0, processes: 1 } },
    });
    draw();
    expect(await screen.findByText("No certificate in the last scan")).toBeInTheDocument();
    expect(screen.getByText(/not proof the estate has none/)).toBeInTheDocument();
    expect(screen.getByText("No library in the last scan")).toBeInTheDocument();
    expect(screen.getByText(/not proof the host loads none/)).toBeInTheDocument();
  });

  it("names cleartext services instead of counting them as encrypted", async () => {
    mockFetch({ "/api/v1/algorithms": catalog, "/api/v1/network/protocols": protocols });
    draw();
    expect((await screen.findAllByText("cleartext")).length).toBeGreaterThan(0);
    expect(screen.getByText("telnet")).toBeInTheDocument();
    expect(screen.getByText(/Service counts from the registry/)).toBeInTheDocument();
  });
});
