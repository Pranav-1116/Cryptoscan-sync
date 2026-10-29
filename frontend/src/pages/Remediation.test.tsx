/* Remediation Tasks (§5, round 63) — the task LIFECYCLE view: real tasks
 * with owner/status/rescan/verification, declared states kept distinct
 * from machine verdicts, and status-aware action availability. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import { renderWithProviders } from "../test/render";
import Remediation from "./Remediation";

afterEach(() => {
  localStorage.clear();
});

const task = (over: Record<string, unknown> = {}) => ({
  id: "task-1",
  evidence_id: "ev-77",
  scan_id: "scan-9",
  rule_id: "BASELINE-001",
  category: "weak-crypto",
  priority: "P1",
  replace_with: "AES-256-GCM",
  original_finding: { algorithm: "3DES", file_path: "src/LegacyPad.java", line_number: 4, key_size: 112 },
  target_location: "local://estate",
  status: "ACCEPTED",
  owner: "alice",
  notes: null,
  created_by: "auditor",
  source: "drift",
  source_ref: "drift-event-42",
  completed_at: null,
  completed_by: null,
  ...over,
});

describe("Remediation — task lifecycle", () => {
  it("renders tasks with owner, source and the latest machine verification", async () => {
    mockFetch({
      "/api/v1/remediation/tasks": {
        tasks: [
          task(),
          task({
            id: "task-2", rule_id: "UAE-001", status: "VERIFIED", owner: "bob",
            source: "manual", source_ref: null, completed_at: "2026-10-12T00:00:00Z", completed_by: "bob",
            latest_verification: {
              id: "ver-1", result: "VERIFIED",
              reason: "No 3DES evidence in rescan; replacement AES-256-GCM observed.",
              rescan_id: "scan-12", verified_by: "system", verified_at: "2026-10-12T01:00:00Z",
            },
          }),
          task({
            id: "task-3", rule_id: "SAMA-002", status: "COMPLETED", owner: null,
            source: "manual", source_ref: null, latest_verification: {
              id: "ver-2", result: "FAILED", reason: "Rescan still shows 3DES at src/LegacyPad.java.",
              rescan_id: "scan-11", verified_by: "system", verified_at: "2026-10-11T01:00:00Z",
            },
          }),
        ],
        total: 3, page: 1, page_size: 100,
      },
    });
    renderWithProviders(<Remediation />);
    await screen.findByText("BASELINE-001");
    // bound finding from the snapshot (every task carries it)
    expect(screen.getAllByText(/LegacyPad\.java:4/).length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText("alice")).toBeTruthy();
    expect(screen.getByText("unassigned")).toBeTruthy(); // honest unowned task
    // drift-sourced task shows its event ref (id truncated for display)
    expect(screen.getByText("drift-even…")).toBeTruthy();
    // the declared-vs-verified distinction is stated on the page
    expect(screen.getByText(/COMPLETED is a declaration — VERIFIED is a machine verdict/)).toBeTruthy();
    expect(screen.getByText("work declared done — awaiting/failed verification, NOT closure")).toBeTruthy();
    expect(screen.getByText("machine-verified from rescan evidence")).toBeTruthy();
    // verification reasons are shown verbatim with their rescan
    expect(screen.getByText("No 3DES evidence in rescan; replacement AES-256-GCM observed.")).toBeTruthy();
    expect(screen.getByText("Rescan still shows 3DES at src/LegacyPad.java.")).toBeTruthy();
    // Both machine verdicts retain their exact rescan IDs; the subtitle explains the boundary.
    expect(screen.getByText("rescan scan-12")).toBeTruthy();
    expect(screen.getByText("rescan scan-11")).toBeTruthy();
    expect(screen.getAllByText(/against rescan/)).toHaveLength(1);
    // a task without verification says so honestly
    expect(screen.getByText("No verification yet — completion is a declaration, not proof.")).toBeTruthy();
  });

  it("expands a task and drives the lifecycle: complete calls the endpoint with the rescan id", async () => {
    let completed = false;
    const fetchSpy = mockFetch({
      "/api/v1/remediation/tasks": () => ({
        tasks: [completed ? task({
          id: "task-1", status: "VERIFIED", completed_at: "2026-10-14T00:00:00Z", completed_by: "auditor",
          latest_verification: { id: "ver-3", result: "VERIFIED", reason: "clean", rescan_id: "scan-12", verified_by: "system", verified_at: "2026-10-14T00:00:00Z" },
        }) : task()], total: 1, page: 1, page_size: 100,
      }),
      "/api/v1/remediation/tasks/task-1/complete": () => {
        completed = true;
        return task({ id: "task-1", status: "VERIFIED", completed_at: "2026-10-14T00:00:00Z", completed_by: "auditor",
                      latest_verification: { id: "ver-3", result: "VERIFIED", reason: "clean", rescan_id: "scan-12", verified_by: "system", verified_at: "2026-10-14T00:00:00Z" } });
      },
    });
    renderWithProviders(<Remediation />);
    await screen.findByText("BASELINE-001");
    fireEvent.click(screen.getByRole("button", { name: /Expand task task-1/ }));
    const rescanInput = await screen.findByLabelText("Rescan id for task task-1");
    fireEvent.change(rescanInput, { target: { value: "scan-12" } });
    fireEvent.click(screen.getByRole("button", { name: /Mark complete \+ verify/ }));
    await waitFor(() => {
      const call = fetchSpy.mock.calls.find(
        ([p, init]) => String(p).includes("/remediation/tasks/task-1/complete") && init?.method === "POST");
      expect(call).toBeTruthy();
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ rescan_id: "scan-12", notes: null });
    });
    // the refreshed list shows the verified state (status badge + verdict badge)
    await waitFor(() => expect(screen.getAllByText("VERIFIED").length).toBeGreaterThanOrEqual(2));
    expect(screen.getByText(/scan-12/)).toBeTruthy();
  });

  it("hides the PROPOSED-only accept action on an ACCEPTED task", async () => {
    mockFetch({
      "/api/v1/remediation/tasks": { tasks: [task()], total: 1, page: 1, page_size: 100 },
    });
    renderWithProviders(<Remediation />);
    await screen.findByText("BASELINE-001");
    fireEvent.click(screen.getByRole("button", { name: /Expand task task-1/ }));
    // PROPOSED-only action hidden on an ACCEPTED task — status-aware UI
    expect(screen.queryByRole("button", { name: /Accept/ })).toBeNull();
  });

  it("filters by status server-side and renders the honest empty state", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/remediation/tasks": (url: string) =>
        url.includes("status=REGRESSION")
          ? { tasks: [], total: 0, page: 1, page_size: 100 }
          : { tasks: [task()], total: 1, page: 1, page_size: 100 },
    });
    renderWithProviders(<Remediation />);
    await screen.findByText("BASELINE-001");
    fireEvent.click(screen.getByRole("button", { name: /REGRESSION/ }));
    await waitFor(() => expect(fetchSpy.mock.calls.some(([p]) => String(p).includes("status=REGRESSION"))).toBeTruthy());
    expect(await screen.findByText("No tasks in status REGRESSION.")).toBeTruthy();
  });

  it("renders the offline state without inventing tasks", async () => {
    mockFetch({}, 503);
    renderWithProviders(<Remediation />);
    await screen.findByText(/Tasks unavailable/);
    expect(screen.queryByText("BASELINE-001")).toBeNull();
  });
});
