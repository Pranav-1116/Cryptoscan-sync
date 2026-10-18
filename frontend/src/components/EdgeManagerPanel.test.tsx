import React from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import EdgeManagerPanel from "./EdgeManagerPanel";
import { apiGraphDeleteEdge, apiGraphEdges, apiGraphRegisterEdge } from "../lib/api";
vi.mock("../lib/api", () => ({ apiGraphDeleteEdge: vi.fn(), apiGraphEdges: vi.fn(), apiGraphRegisterEdge: vi.fn() }));
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
  const retire = await screen.findByRole("button", { name: "retire" });
  expect(retire).toBeDisabled();
  expect(screen.getByText(/STALE/)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "retirement reason" }), { target: { value: "Approved replacement" } });
  fireEvent.change(screen.getByRole("textbox", { name: "retirement evidence reference" }), { target: { value: "change/BANK-456" } });
  fireEvent.click(retire);
  expect(apiGraphDeleteEdge).toHaveBeenCalledWith("web", "pay", { expected_revision: 3, reason: "Approved replacement", evidence_ref: "change/BANK-456" });
  expect(await screen.findByText(/retired \(evidence retained\)/)).toBeInTheDocument();
});
it("does not offer to silently reactivate or re-delete terminal evidence", async () => {
  vi.mocked(apiGraphEdges).mockResolvedValue({ source: "live", data: { count: 1, edges: [{
    parent_id: "web", child_id: "pay", parent_name: "Web", child_name: "Payments", relation: "CALLS",
    lifecycle_revision: 4, effective_state: "DELETED",
  }] } });
  render(<EdgeManagerPanel />);
  fireEvent.change(screen.getByRole("textbox", { name: "retirement reason" }), { target: { value: "Approved replacement" } });
  fireEvent.change(screen.getByRole("textbox", { name: "retirement evidence reference" }), { target: { value: "change/BANK-456" } });
  expect(await screen.findByRole("button", { name: "retire" })).toBeDisabled();
  expect(screen.getByText(/DELETED/)).toBeInTheDocument();
  expect(apiGraphDeleteEdge).not.toHaveBeenCalled();
});
