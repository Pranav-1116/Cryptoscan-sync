import React from "react";
import { setToken } from "../lib/api";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import LinuxEvidenceOutputs from "./LinuxEvidenceOutputs";
import { mockFetch } from "../test/setup";
const job = "a".repeat(36), envelope = "b".repeat(64), graphPath = `/api/v1/collection/jobs/${job}/relationships/linux`, exportPath = `/api/v1/collection/jobs/${job}/software/linux/cyclonedx-1.6`;
function graph() {
  const nodes = ["PROCESS", "LOADED_LIBRARY"].map((kind, i) => ({ observation_id: `obs-${i}`, evidence_id: `evidence-${i}`, fact_sha256: envelope, provenance: "IMPORTED", fact: { kind, local_basis: "OBSERVED" } }));
  return { schema_version: "cryptoscan.linux-relationships/v1", coverage: { job_id: job, envelope_sha256: envelope, bom_observation_counts: { TechBOM: 2 } }, nodes,
    edges: [{ edge_id: envelope, relation: "PROCESS_HAS_MAPPED_PATH", source_observation_id: "obs-0", target_observation_id: "obs-1", supporting_observation_ids: ["obs-0", "obs-1"], evidence_ids: ["evidence-0", "evidence-1"], basis: "EXACT_CAPTURED_FIELDS_NOT_ATTESTED_USAGE", local_basis: "INFERRED", runtime_use: "UNKNOWN", production_traffic_proven: false }], unresolved: [],
    unsupported_relationships: ["SERVICE_MAINPID_TO_PROCESS_INCARNATION", "LISTENER_TO_PROCESS", "CONFIGURATION_TO_SERVICE", "CERTIFICATE_TO_LISTENER", "HARDWARE_TO_APPLICATION_OR_KEY", "PACKAGE_TO_BINARY_OR_LIBRARY"], provenance: "IMPORTED", identity_basis: "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET", relationship_completeness_proven: false, host_identity_attested: false, production_execution_qualified: false, materialized_without_collection: true };
}
function click() { fireEvent.click(screen.getByText("Read Linux evidence relationships")); }
it("reads only explicitly and presents proof references as metadata, not runtime use", async () => {
  const fetch = mockFetch({ [graphPath]: graph() }); render(<LinuxEvidenceOutputs job={job} envelope={envelope} />);
  expect(fetch).not.toHaveBeenCalled(); click();
  expect(await screen.findByText(/2 original observation nodes/)).toBeInTheDocument();
  expect(screen.getByText(/PROCESS_HAS_MAPPED_PATH:/)).toHaveTextContent("evidence-0, evidence-1 · runtime use UNKNOWN");
  expect(screen.getByText(/Unsupported with captured fields/)).toHaveTextContent("CERTIFICATE_TO_LISTENER");
  expect(fetch.mock.calls[0][1]?.method).toBeUndefined();
});
it.each(["envelope", "job", "promotion", "proof", "endpoint", "unsupported", "count"])("rejects inconsistent %s", async change => {
  const value = graph();
  if (change === "envelope") value.coverage.envelope_sha256 = "c".repeat(64);
  else if (change === "job") value.coverage.job_id = "other";
  else if (change === "promotion") Object.assign(value, { relationship_completeness_proven: true });
  else if (change === "proof") value.edges[0].evidence_ids = ["forged"];
  else if (change === "endpoint") value.edges[0].target_observation_id = "forged";
  else if (change === "unsupported") value.unsupported_relationships = [];
  else value.coverage.bom_observation_counts.TechBOM = 3;
  mockFetch({ [graphPath]: value }); render(<LinuxEvidenceOutputs job={job} envelope={envelope} />); click();
  expect(await screen.findByRole("alert")).toHaveTextContent("inconsistent");
  expect(screen.queryByText(/original observation nodes/)).not.toBeInTheDocument();
});
it.each(["tenant", "auth", "storage", "resume", "history", "job"])("discards non-cooperative late graph after %s", async change => {
  let resolve!: (r: Response) => void; globalThis.fetch = vi.fn(() => new Promise<Response>(r => { resolve = r; }));
  const view = render(<LinuxEvidenceOutputs job={job} envelope={envelope} />); click();
  act(() => {
    if (change === "job") view.rerender(<LinuxEvidenceOutputs job="another" envelope={envelope} />);
    else if (change === "storage") window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_signed_in" }));
    else if (change === "resume") document.dispatchEvent(new Event("visibilitychange"));
    else if (change === "history") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    else window.dispatchEvent(new Event(`zelinx:${change}`));
  });
  await act(async () => resolve(new Response(JSON.stringify(graph()))));
  expect(screen.queryByText(/original observation nodes/)).not.toBeInTheDocument();
});
it("bounds stalled graph reads at 20 seconds without retry", async () => {
  vi.useFakeTimers(); globalThis.fetch = vi.fn(() => new Promise<Response>(() => {}));
  render(<LinuxEvidenceOutputs job={job} envelope={envelope} />); click();
  await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
  expect(screen.getByRole("alert")).toHaveTextContent("timed out"); expect(globalThis.fetch).toHaveBeenCalledTimes(1);
});
it("downloads via the existing authenticated export path, never a public anchor", async () => {
  localStorage.setItem("cryptoscan_tenant", "synthetic-bank"); setToken("synthetic-token");
  const fetch = mockFetch({ [exportPath]: { bomFormat: "CycloneDX", specVersion: "1.6" } });
  const clickAnchor = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  const objectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:synthetic-sbom");
  const revoke = vi.spyOn(URL, "revokeObjectURL");
  render(<LinuxEvidenceOutputs job={job} envelope={envelope} />);
  fireEvent.click(screen.getByText("Download Linux CycloneDX 1.6 SBOM"));
  await vi.waitFor(() => expect(clickAnchor).toHaveBeenCalledOnce());
  expect(fetch.mock.calls[0][1]?.headers).toMatchObject({ "X-Tenant-ID": "synthetic-bank", Authorization: "Bearer synthetic-token" });
  expect(objectURL).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledWith("blob:synthetic-sbom");
});
it("does not download a refused schema export", async () => {
  const objectURL = vi.spyOn(URL, "createObjectURL"); mockFetch({ [exportPath]: new Response(JSON.stringify({ detail: "validation refused" }), { status: 503 }) });
  render(<LinuxEvidenceOutputs job={job} envelope={envelope} />);
  fireEvent.click(screen.getByText("Download Linux CycloneDX 1.6 SBOM"));
  expect(await screen.findByRole("alert")).toHaveTextContent("503"); expect(objectURL).not.toHaveBeenCalled();
});
