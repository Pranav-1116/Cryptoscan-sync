import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import PrivateScope from "./PrivateScope";
import HostAssociationsPanel from "./HostAssociationsPanel";
import { HostSnapshotInspection } from "../lib/api";
import { mockFetch, offlineFetch } from "../test/setup";
const id = "a".repeat(36), P = `/api/v1/host-evidence/approvals/${id}`, hash = "b".repeat(64);
const detail = { approval_id: id, system_id: "system-a", snapshot_sha256: hash, snapshot: { receipts: [
  { input_id: "cert", status: "PARSED", facts: [{ kind: "CERTIFICATE" }] }, { input_id: "denied", status: "DENIED", facts: [] },
] } } as unknown as HostSnapshotInspection;
const target = { target_type: "hardware", target_id: "hardware-a", target_sha256: "c".repeat(64), bom: "HBOM", evidence_status: "DECLARED", runtime_use: "UNKNOWN" };
const assertion = { id: "association-a", revision: 1, state: "PROPOSED", target_type: "hardware", target_id: "hardware-a", bom: "HBOM", input_id: "cert", fact_ordinal: 0, evidence_status: "DECLARED", payload_sha256: hash, proposal_reason: "Independent metadata association evidence", evidence_ref: "review/propose-1", expires_at: "2026-10-25T00:00:00Z", proposed_by: "analyst-a", reviewed_by: null };
const graph = { schema_version: "cryptoscan.host-estate-graph/v1", approval_id: id, system_id: "system-a", snapshot_sha256: hash, graph_sha256: hash, evaluated_at: "2026-10-24T00:00:00Z", whole_host_coverage_verified: false, host_identity_attested: false, operational_dependency_verified: false, pqc_use: "UNKNOWN",
  nodes: [{ id: "system-a", bom: "TechBOM", kind: "SYSTEM_SCOPE", evidence_status: "DECLARED" }, { id: "report-a", bom: "TechBOM", kind: "IMPORTED_HOST_REPORT", evidence_status: "IMPORTED" }],
  edges: [{ from: "system-a", to: "report-a", predicate: "APPROVED_COLLECTION_SCOPE", evidence_status: "DECLARED", runtime_use: "UNKNOWN", operational_dependency_verified: false, provenance: { approval_id: id } }],
  domains: Object.fromEntries(["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"].map(d => [d, { represented: d === "TechBOM", operational_use: "UNKNOWN" }])), associations: [assertion] };
function mount() { return render(<PrivateScope><HostAssociationsPanel detail={detail} /></PrivateScope>); }
function metadata() {
  fireEvent.change(screen.getByLabelText("Association evidence reference"), { target: { value: "review/customer-2" } });
  fireEvent.change(screen.getByLabelText("Association rationale"), { target: { value: "Independent reviewer checked the customer metadata association" } });
}
async function resolve() {
  fireEvent.change(screen.getByLabelText("Association target ID"), { target: { value: "hardware-a" } });
  fireEvent.click(screen.getByRole("button", { name: "Inspect association target" }));
  await screen.findByText(/Current HBOM identity SHA-256/);
}

describe("host six-BOM provenance associations", () => {
  it("does not fetch, collect or link coexisting assets on mount", () => {
    const fetcher = mockFetch({}); mount(); expect(fetcher).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Propose metadata association" })).toBeDisabled();
    expect(screen.queryByRole("option", { name: /denied/ })).toBeNull();
    expect(screen.getByText(/No relationship is created from matching names/)).toBeTruthy();
  });
  it("requires an explicitly selected fact, checked target and rationale before proposing", async () => {
    const fetcher = mockFetch({ [`${P}/association-target`]: target, [`${P}/associations`]: { subject_id: "association-a", revision: 1 } }); mount();
    await resolve(); metadata(); expect(screen.getByRole("button", { name: "Propose metadata association" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Association source fact"), { target: { value: "1" } });
    // A different fact selection invalidates the previous target proof.
    expect(screen.getByRole("button", { name: "Propose metadata association" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Inspect association target" })); await screen.findByText(/Current HBOM/);
    fireEvent.click(screen.getByRole("button", { name: "Propose metadata association" }));
    await screen.findByText(/Proposal recorded, not an active edge/);
    const call = fetcher.mock.calls.find(c => String(c[0]) === `${P}/associations`)!;
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({ input_id: "cert", fact_ordinal: 0, target_type: "hardware", target_id: "hardware-a", expected_target_sha256: target.target_sha256, package_identity: null, evidence_ref: "review/customer-2" });
    expect(screen.getByRole("button", { name: "Propose metadata association" })).toBeDisabled();
  });
  it("loads six domains without calling missing metadata secure and submits exact review revision", async () => {
    const fetcher = mockFetch({ [`${P}/graph`]: graph, [`${P}/associations/association-a/review`]: { subject_id: "association-a", revision: 2 } }); mount();
    fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" }));
    await screen.findByText("HBOM: no resolved metadata · operational use UNKNOWN");
    expect(screen.getByRole("button", { name: "Review association association-a" })).toBeDisabled(); metadata();
    fireEvent.click(screen.getByRole("button", { name: "Review association association-a" }));
    await screen.findByText(/Decision recorded/);
    const call = fetcher.mock.calls.find(c => String(c[0]).endsWith("/review"))!;
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({ expected_revision: 1, evidence_ref: "review/customer-2" });
    expect(screen.queryByRole("table")).toBeNull(); expect(fetcher.mock.calls).toHaveLength(2);
  });
  it("shows stale/retracted history but never offers stale review or retracted mutation", async () => {
    mockFetch({ [`${P}/graph`]: { ...graph, associations: [{ ...assertion, state: "STALE", revision: 2 }, { ...assertion, id: "withdrawn", state: "RETRACTED", revision: 3 }] } }); mount();
    fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" })); await screen.findByText(/STALE · revision 2/);
    expect(screen.queryByRole("button", { name: /Review association/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Retract association withdrawn" })).toBeNull();
    expect(screen.getByRole("button", { name: "Retract association association-a" })).toBeTruthy();
  });
  it.each([{ ...graph, approval_id: "other" }, { ...graph, operational_dependency_verified: true }, { ...graph, pqc_use: "OBSERVED" },
    { ...graph, edges: [{ ...graph.edges[0], runtime_use: "OBSERVED" }] }, { ...graph, associations: [{ ...assertion, state: "APPROVED" }] }, { ...graph, domains: {} },
  ])("rejects malformed, mismatched or promoted graph", async bad => {
    mockFetch({ [`${P}/graph`]: bad }); mount(); fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" }));
    await screen.findByText(/No complete or secure estate assumed/); expect(screen.queryByRole("table")).toBeNull();
  });
  it("does not submit stale target proof after changing identity", async () => {
    mockFetch({ [`${P}/association-target`]: target }); mount(); await resolve();
    fireEvent.change(screen.getByLabelText("Association target ID"), { target: { value: "different" } });
    expect(screen.queryByText(/Current HBOM/)).toBeNull(); expect(screen.getByRole("button", { name: "Propose metadata association" })).toBeDisabled();
  });
  it("discards pending graph and drafts on tenant switch without replay", async () => {
    let finish!: (value: unknown) => void;
    const fetcher = mockFetch({ [`${P}/graph`]: () => new Promise(resolve => { finish = resolve; }) }); mount(); metadata();
    fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" })); await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant", newValue: "other" })));
    await act(async () => finish(graph)); expect(screen.queryByRole("table")).toBeNull(); expect(fetcher.mock.calls).toHaveLength(1);
    expect(screen.getByLabelText("Association rationale")).toHaveValue("");
  });
  it("discards pending review on logout without treating it as committed", async () => {
    let finish!: (value: unknown) => void;
    const fetcher = mockFetch({ [`${P}/graph`]: graph, [`${P}/associations/association-a/review`]: () => new Promise(resolve => { finish = resolve; }) }); mount();
    fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" })); await screen.findByText(/HBOM: no resolved/); metadata();
    fireEvent.click(screen.getByRole("button", { name: "Review association association-a" })); await waitFor(() => expect(finish).toBeTypeOf("function"));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_signed_in", newValue: null })));
    await act(async () => finish({ subject_id: "association-a", revision: 2 })); expect(screen.queryByText(/Decision recorded/)).toBeNull(); expect(fetcher.mock.calls).toHaveLength(2);
  });
  it("shows 403/409 refusal without replay or sample edges", async () => {
    const fetcher = mockFetch({ [`${P}/graph`]: () => new Response('{"detail":"Current authority or production admission refused"}', { status: 409 }) }); mount();
    fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" })); await screen.findByText(/No complete or secure estate assumed/); expect(fetcher.mock.calls).toHaveLength(1);
  });
  it("does not infer a graph while offline", async () => {
    offlineFetch(); mount(); fireEvent.click(screen.getByRole("button", { name: "Load six-BOM graph" })); await screen.findByText(/No complete or secure estate assumed/); expect(screen.queryByRole("table")).toBeNull();
  });
});
