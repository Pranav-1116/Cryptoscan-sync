import React from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import CollectionCoveragePanel from "./CollectionCoveragePanel";
import { mockFetch } from "../test/setup";
const ID = "a".repeat(36), PATH = `/api/v1/collection/jobs/${ID}/coverage/surfaces`;
function report() {
  const surfaces = Object.fromEntries(["os", "software", "certificates", "crypto_configuration", "processes_and_libraries", "services", "network_listeners", "hardware_metadata"].map(k => [k, { approved_inputs: 0, parsed_inputs: 0, failed_inputs: 0, fact_count: 0, outcome: "NOT_REQUESTED", approved_input_parse_percent: null, complete_surface_coverage_verified: false, inputs: [] }]));
  return { finished_at: "2026-10-25T00:00:00Z", schema_version: "cryptoscan.collection-surface-coverage/v1", job_id: ID, envelope_sha256: "b".repeat(64), surfaces, bom_observation_counts: { SBOM: 0, CBOM: 0, NBOM: 0, HBOM: 0, VBOM: 0, TechBOM: 0 }, whole_host_percent: null, whole_host_coverage_verified: false, asset_absence_proven: false, materialized_without_collection: true, production_execution_qualified: false };
}
function read() { fireEvent.change(screen.getByLabelText("Collection job ID"), { target: { value: ID } }); fireEvent.click(screen.getByText("Inspect collection coverage")); }
it("never scans/loads automatically and labels unknown scope instead of zero coverage", async () => {
  const fetch = mockFetch({ [PATH]: report() }); render(<CollectionCoveragePanel />);
  expect(fetch).not.toHaveBeenCalled(); read();
  expect(await screen.findAllByText("— / — · not requested")).toHaveLength(8);
  expect(screen.getByText(/SBOM:/).closest("span")).toHaveTextContent("SBOM: 0");
  expect(screen.getByText(/VBOM:/).closest("span")).toHaveTextContent("VBOM: 0");
  expect(screen.getByText(/zero ≠ absence/)).toBeInTheDocument();
  expect(fetch.mock.calls[0][1]?.method).toBeUndefined();
});
it("preserves failure and declared provenance without a complete-host percentage", async () => {
  const value = report();
  Object.assign(value.surfaces.certificates, { approved_inputs: 2, parsed_inputs: 1, failed_inputs: 1, fact_count: 1, outcome: "PARTIAL", approved_input_parse_percent: 50, inputs: [{ input_id: "cert", status: "PARSED", reason: "PARSED_RECEIPT_NOT_ABSENCE_PROOF", fact_count: 1, local_basis_counts: { OBSERVED: 0, DECLARED: 1 } }, { input_id: "denied", status: "DENIED", reason: "ACCESS_DENIED", fact_count: 0, local_basis_counts: { OBSERVED: 0, DECLARED: 0 } }] });
  mockFetch({ [PATH]: value }); render(<CollectionCoveragePanel />); read();
  expect(await screen.findByText("1/2 · 50%")).toBeInTheDocument();
  expect(screen.getByText(/denied:/)).toHaveTextContent("DENIED ACCESS_DENIED · OBS 0 / DECL 0");
  expect(screen.getByText(/cert:/)).toHaveTextContent("PARSED PARSED_RECEIPT_NOT_ABSENCE_PROOF · OBS 0 / DECL 1");
  expect(screen.getByText(/not whole-host completeness/)).toBeInTheDocument();
});
it.each(["tenant", "auth", "storage", "resume", "history"])("discards old evidence/IDs after %s even when fetch ignores abort", async change => {
  let resolve!: (r: Response) => void; globalThis.fetch = vi.fn(() => new Promise<Response>(r => { resolve = r; }));
  render(<CollectionCoveragePanel />); read();
  act(() => {
    if (change === "storage") window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_token" }));
    else if (change === "resume") document.dispatchEvent(new Event("visibilitychange"));
    else if (change === "history") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    else window.dispatchEvent(new Event(`zelinx:${change}`));
  });
  await act(async () => resolve(new Response(JSON.stringify(report()))));
  expect(screen.getByLabelText("Collection job ID")).toHaveValue("");
  expect(screen.queryByText("IMPORTED evidence")).not.toBeInTheDocument();
});
it("rejects fabricated completeness flags instead of rendering a green fallback", async () => {
  mockFetch({ [PATH]: { ...report(), whole_host_coverage_verified: true } }); render(<CollectionCoveragePanel />); read();
  expect(await screen.findByRole("alert")).toHaveTextContent("inconsistent");
  expect(screen.queryByText("IMPORTED evidence")).not.toBeInTheDocument();
});
it("clears prior data when a different ID is entered and propagates tenant/auth on GET", async () => {
  localStorage.setItem("cryptoscan_tenant", "synthetic-bank"); localStorage.setItem("zelinx_token", "synthetic-session");
  const fetch = mockFetch({ [PATH]: report() }); render(<CollectionCoveragePanel />); read();
  await screen.findByText("IMPORTED evidence");
  expect(screen.getByText(/^envelope /)).toHaveTextContent(report().envelope_sha256.slice(0,16));
  expect(fetch.mock.calls[0][1]?.headers).toMatchObject({ "X-Tenant-ID": "synthetic-bank", Authorization: "Bearer synthetic-session" });
  fireEvent.change(screen.getByLabelText("Collection job ID"), { target: { value: "another-job" } });
  expect(screen.queryByText("IMPORTED evidence")).not.toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(1);
});
it("bounds a non-cooperative read at 20 seconds without retry or late proof", async () => {
  vi.useFakeTimers(); let resolve!: (r: Response) => void;
  const fetch = vi.fn(() => new Promise<Response>(r => { resolve = r; })); globalThis.fetch = fetch;
  render(<CollectionCoveragePanel />); read();
  await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
  expect(screen.getByRole("alert")).toHaveTextContent("timed out");
  await act(async () => resolve(new Response(JSON.stringify(report()))));
  expect(screen.queryByText("IMPORTED evidence")).not.toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(1);
});
