import React from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import EdgeManagerPanel from "./EdgeManagerPanel";
import { apiGraphDeleteEdge, apiGraphEdges, apiGraphRegisterEdge, apiGraphUpdateOperationalDependency } from "../lib/api";
vi.mock("../lib/api", () => ({ apiGraphDeleteEdge: vi.fn(), apiGraphEdges: vi.fn(), apiGraphRegisterEdge: vi.fn(), apiGraphUpdateOperationalDependency: vi.fn() }));
// These tests exercise the WRITE-FLOW fidelity (revision CAS, retirement
// evidence) as an operator who holds the role. RBAC presentation itself is
// covered by lib/rbac.test.tsx; the gate is mocked open here so the flows
// under test stay the subject.
vi.mock("../lib/auth", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  RequireRole: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(apiGraphEdges).mockResolvedValue({ source: "live", data: { count: 1, edges: [{
    id: "edge-1", parent_id: "web", child_id: "pay", parent_name: "Web", child_name: "Payments", relation: "CALLS",
    lifecycle_revision: 3, effective_state: "STALE",
  }] } });
  vi.mocked(apiGraphDeleteEdge).mockResolvedValue({ source: "live", data: { deleted: true, retained: true } });
});
it("requires retirement evidence and sends a revision instead of erasing rows", async () => {
  render(<EdgeManagerPanel />);
  const retire = await screen.findByRole("button", { name: "Retire" });
  expect(retire).toBeDisabled();
  expect(screen.getByText(/STALE · no expiry · rev 3/)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "retirement reason" }), { target: { value: "Approved replacement" } });
  fireEvent.change(screen.getByRole("textbox", { name: "retirement evidence reference" }), { target: { value: "change/BANK-456" } });
  fireEvent.click(retire);
  expect(apiGraphDeleteEdge).toHaveBeenCalledWith("web", "pay", { expected_revision: 3, reason: "Approved replacement", evidence_ref: "change/BANK-456" });
  expect(await screen.findByText(/Retired \(evidence retained\)/)).toBeInTheDocument();
});
it("does not offer to silently reactivate or re-delete terminal evidence", async () => {
  vi.mocked(apiGraphEdges).mockResolvedValue({ source: "live", data: { count: 1, edges: [{
    parent_id: "web", child_id: "pay", parent_name: "Web", child_name: "Payments", relation: "CALLS",
    lifecycle_revision: 4, effective_state: "DELETED",
  }] } });
  render(<EdgeManagerPanel />);
  fireEvent.change(screen.getByRole("textbox", { name: "retirement reason" }), { target: { value: "Approved replacement" } });
  fireEvent.change(screen.getByRole("textbox", { name: "retirement evidence reference" }), { target: { value: "change/BANK-456" } });
  expect(await screen.findByRole("button", { name: "Retire" })).toBeDisabled();
  expect(screen.getByText(/DELETED · no expiry · rev 4/)).toBeInTheDocument();
  expect(apiGraphDeleteEdge).not.toHaveBeenCalled();
});


it("saves a manually-owned operational annotation with revision and reason, without refreshing evidence", async () => {
  const edge = { id: "e", parent_id: "web", child_id: "pay", parent_name: "Web", child_name: "Payments", relation: "CALLS", lifecycle_source: "manual", lifecycle_revision: 3, effective_state: "STALE" };
  vi.mocked(apiGraphEdges).mockResolvedValue({ source: "live", data: { count: 1, edges: [edge] } });
  vi.mocked(apiGraphUpdateOperationalDependency).mockResolvedValue({ source: "live", data: { updated: true, edge } });
  render(<EdgeManagerPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "Edit mode" }));
  expect(screen.getByRole("button", { name: "Save operational mode" })).toBeDisabled();
  fireEvent.change(screen.getByRole("combobox", { name: "operational mode" }), { target: { value: "FAILOVER" } });
  fireEvent.change(screen.getByRole("textbox", { name: "failover alternative system IDs" }), { target: { value: "backup" } });
  fireEvent.change(screen.getByRole("textbox", { name: "operational evidence reference" }), { target: { value: "test/8" } });
  fireEvent.change(screen.getByRole("textbox", { name: "operational change reason" }), { target: { value: "Approved failover review" } });
  fireEvent.click(screen.getByRole("button", { name: "Save operational mode" }));
  expect(apiGraphUpdateOperationalDependency).toHaveBeenCalledWith("web", "pay", {
    expected_revision: 3, operational_dependency: { mode: "FAILOVER", evidence_ref: "test/8", assumptions: [], failover_system_ids: ["backup"] },
    reason: "Approved failover review", evidence_ref: "test/8",
  });
  expect(await screen.findByText(/no observation or confirmation refreshed/)).toBeInTheDocument();
});

it("does not allow operational edits on collector-owned or terminal edges", async () => {
  vi.mocked(apiGraphEdges).mockResolvedValue({ source: "live", data: { count: 1, edges: [{
    parent_id: "web", child_id: "pay", parent_name: "Web", child_name: "Payments", relation: "CALLS",
    lifecycle_revision: 4, lifecycle_source: "collector-bank", effective_state: "ACTIVE",
  }] } });
  render(<EdgeManagerPanel />);
  expect(await screen.findByRole("button", { name: "Edit mode" })).toBeDisabled();
  expect(screen.getByText(/Missing modes remain/)).toHaveTextContent("UNKNOWN");
  expect(screen.getByText(/Not a failure or safety guarantee/)).toBeInTheDocument();
});
