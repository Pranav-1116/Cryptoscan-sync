import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";

import { renderWithProviders } from "../test/render";
import { mockFetch, offlineFetch } from "../test/setup";
import PqcMap, { MigrationPlanRegister } from "./PqcMap";

const EMPTY_WORKSPACE = {
  waves: [], blockers: [], interop: [], progress: [],
  summary: {
    wave_count: 0, waves_verified: 0, waves_blocked: 0, blockers_open: 0,
    blockers_accepted: 0, progress_recorded: 0, progress_verified: 0,
    progress_refuted: 0, progress_stale: 0,
    honesty: "verified is written only by an explicit verification action with an evidence reference; a recorded claim is not progress proven",
  },
};

const POPULATED = {
  waves: [{
    id: "w1", wave_key: "wave-1", title: "Consolidate TLS terminators",
    scope_note: "edge TLS", planned_window: "2027 H1", status: "active", status_note: null,
  }],
  blockers: [{
    id: "b1", wave_id: "w1", title: "HSM firmware lacks ML-KEM", detail: "",
    state: "open", raised_by: "auditor", raised_at: "2026-11-11T10:00:00Z",
    resolved_by: null, resolved_at: null, resolution_note: null,
  }],
  interop: [{
    id: "n1", wave_id: "w1", peer_system: "CLS settlement gateway",
    protocol: "TLS 1.3 hybrid", note: "handshake OK in lab", evidence_ids: ["ev-4"],
    recorded_by: "auditor",
  }],
  progress: [{
    id: "p1", wave_id: "w1", claim: "six terminators on ML-KEM",
    evidence_ids: [], recorded_by: "auditor", verification_status: "recorded",
    verified_by: null, verified_at: null, verification_note: null,
    claim_is_not_proof: true,
  }],
  summary: { ...EMPTY_WORKSPACE.summary, wave_count: 1, progress_recorded: 1, blockers_open: 1 },
};

const workspaceRoute = (payload: unknown) => ({ "/api/v1/pqc-migration/workspace": payload });

describe("PQC migration plan register", () => {
  it("draws absence honestly — no rows is never a safe plan", async () => {
    mockFetch(workspaceRoute(EMPTY_WORKSPACE));
    renderWithProviders(<MigrationPlanRegister />);
    await screen.findByText("No migration waves registered.");
    expect(screen.getByText(/Absence of rows is absence of a plan — never a plan that is safe/)).toBeInTheDocument();
    // the honesty rule is on the screen before any claim exists
    expect(screen.getByText(/a recorded claim is not progress proven/)).toBeInTheDocument();
  });

  it("shows a recorded claim as asserted, not proven", async () => {
    mockFetch(workspaceRoute(POPULATED));
    renderWithProviders(<MigrationPlanRegister />);
    await screen.findByText("six terminators on ML-KEM");
    expect(screen.getByText("recorded")).toBeInTheDocument();
    expect(screen.getByText("none — unverified")).toBeInTheDocument();
    expect(screen.getByText("HSM firmware lacks ML-KEM")).toBeInTheDocument();
    expect(screen.getByText("CLS settlement gateway")).toBeInTheDocument();
  });

  it("posts the verdict with its evidence and reports the outcome", async () => {
    const fetchMock = mockFetch({
      ...workspaceRoute(POPULATED),
      "/api/v1/pqc-migration/progress/p1/transition": (url: string, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body ?? "{}"));
        expect(body.to).toBe("verified");
        expect(body.evidence_ids).toEqual(["ev-9"]);
        return { ...POPULATED.progress[0], verification_status: "verified", verified_by: "auditor", evidence_ids: ["ev-9"] };
      },
    });
    renderWithProviders(<MigrationPlanRegister />);
    await screen.findByText("six terminators on ML-KEM");
    fireEvent.change(screen.getByLabelText("verify record id"), { target: { value: "p1" } });
    fireEvent.change(screen.getByLabelText("verify evidence ids"), { target: { value: "ev-9" } });
    fireEvent.click(screen.getByRole("button", { name: "Write verdict" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("claim -> verified"));
    const posts = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/transition"));
    expect(posts.length).toBeGreaterThanOrEqual(1);
  });

  it("keeps the draft and states the outcome when a write is refused", async () => {
    mockFetch({
      ...workspaceRoute(POPULATED),
      "/api/v1/pqc-migration/progress/p1/transition": () =>
        new Response(JSON.stringify({ detail: "verified requires an evidence reference" }), { status: 422 }),
    });
    renderWithProviders(<MigrationPlanRegister />);
    await screen.findByText("six terminators on ML-KEM");
    const evidence = screen.getByLabelText("verify evidence ids");
    fireEvent.change(evidence, { target: { value: "claimed-but-unsupplied" } });
    fireEvent.click(screen.getByRole("button", { name: "Write verdict" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Draft retained/));
    // the draft is not erased by the failure
    expect((evidence as HTMLInputElement).value).toBe("claimed-but-unsupplied");
  });

  it("states the refusal rule on the screen, in full", async () => {
    mockFetch(workspaceRoute(EMPTY_WORKSPACE));
    renderWithProviders(<MigrationPlanRegister />);
    expect(screen.getByText(/verified requires an evidence reference — a verdict without evidence is refused\./)).toBeInTheDocument();
  });

  it("renders the live inventory half without inventing counts", async () => {
    mockFetch({
      "/api/v1/quantum/plan": {
        inventory: { total_sites: 0, vulnerable_sites: 0, pqc_ready_sites: 0, by_family: {} },
        waves: {},
      },
      ...workspaceRoute(EMPTY_WORKSPACE),
    });
    renderWithProviders(<PqcMap />);
    await screen.findByText("Migration path");
    expect(screen.getByText(/No inventory yet/)).toBeInTheDocument();
    // candidates are declared reference data, labelled as such
    expect(screen.getByTitle(/declared reference data, not estate observations/)).toBeInTheDocument();
    expect(screen.getByText("ML-KEM-768")).toBeInTheDocument();
  });

  it("does not silently pass when the register read fails", async () => {
    offlineFetch();
    renderWithProviders(<MigrationPlanRegister />);
    await screen.findByText(/The plan register did not load\. A failed read is a failure — never an empty plan\./);
  });
});

describe("PqcMap page", () => {
  it("stays offline-safe end to end", () => {
    offlineFetch();
    vi.useFakeTimers();
    renderWithProviders(<PqcMap />);
    vi.useRealTimers();
    expect(screen.getByText("PQC migration map")).toBeInTheDocument();
  });
});
