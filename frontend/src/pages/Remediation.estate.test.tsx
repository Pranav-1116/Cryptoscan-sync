/* Remediation tasks opened from the agents' estate: the urgent weaknesses in one click, and the
 * work of a simulated migration (pre-filled from ?from=&to=, as the Migration page links). */
import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Remediation from "./Remediation";
import fixtures from "../test/fixtures/estateRemediation.json";

const FINDINGS = "/api/v1/estate/evidence/remediation/findings";
const MIGRATION = "/api/v1/estate/evidence/remediation/migration";
const OPEN = "/api/v1/estate/evidence/remediation/tasks";
const opened = { created: 2, task_ids: ["t-1", "t-2"], already_open: [], not_found: [], message: "2 task(s) opened", run_id: "run-meridian-0001" };
const estateTask = {
  id: "task-e1", evidence_id: fixtures.findings.findings[0].id, scan_id: "run-meridian-0001", rule_id: "WEAK_KEY",
  category: "CBOM", priority: "P1", replace_with: "ML-DSA-65", status: "COMPLETED", owner: "pki", notes: null,
  created_by: "admin", source: "estate", source_ref: fixtures.findings.findings[0].id, completed_at: null, completed_by: null,
  target_location: "Branch Banking · legacy-branch",
  original_finding: { ...fixtures.findings.findings[0] },
  latest_verification: { id: "v-1", result: "INCONCLUSIVE", reason: "no agent report has arrived since the work was marked done", rescan_id: "run-meridian-0001", verified_by: "admin", verified_at: "2026-11-20T10:00:00Z" },
};
const bodyOf = (spy: ReturnType<typeof mockFetch>, path: string) => {
  const call = spy.mock.calls.find(([url, init]) => String(url).includes(path) && (init as RequestInit | undefined)?.method === "POST");
  return call ? JSON.parse(String((call[1] as RequestInit).body)) : null;
};

describe("Remediation tasks from the estate", () => {
  it("opens tasks for the critical and high weaknesses in one click", async () => {
    const spy = mockFetch({ "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 100 }, [FINDINGS]: fixtures.findings, [OPEN]: opened });
    renderWithProviders(<Remediation />);
    const card = await screen.findByLabelText("Tasks from estate weaknesses");
    const urgent = fixtures.findings.findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    fireEvent.click(await within(card).findByRole("button", { name: `Open tasks for ${urgent.length} critical & high` }));
    await screen.findByText("2 task(s) opened");
    expect(bodyOf(spy, OPEN)).toEqual({ source: "estate", ids: urgent.map((f) => f.id) });
  });

  it("shows the work of a linked migration and opens it as tasks", async () => {
    const spy = mockFetch({ "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 100 }, [FINDINGS]: fixtures.findings, [MIGRATION]: fixtures.rsa_candidates, [OPEN]: opened });
    renderWithProviders(<Remediation />, { route: "/remediation?from=RSA&to=ML-KEM-768" });
    const list = await screen.findByRole("list", { name: "Migration work" });
    expect(within(list).getByText(/library OpenSSL 3.3.2 does not implement ML-KEM-768/)).toBeInTheDocument();
    expect(bodyOf(spy, MIGRATION)).toEqual({ from_algo: "RSA", to_algo: "ML-KEM-768" });
    const n = fixtures.rsa_candidates.candidates.length;
    fireEvent.click(screen.getByRole("button", { name: `Open ${n} migration tasks` }));
    await screen.findByText("2 task(s) opened");
    expect(bodyOf(spy, OPEN)).toMatchObject({ source: "migration", from_algo: "RSA", to_algo: "ML-KEM-768" });
    expect(bodyOf(spy, OPEN).ids).toHaveLength(n);
  });

  it("an estate task shows its finding and is verified against the agents' next report", async () => {
    mockFetch({ "/api/v1/remediation/tasks": { tasks: [estateTask], total: 1, page: 1, page_size: 100 }, [FINDINGS]: fixtures.findings });
    renderWithProviders(<Remediation />);
    expect(await screen.findByText("legacy-branch has an RSA-1024 key")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand task task-e1" }));
    expect(screen.getByLabelText("Work for task task-e1")).toHaveTextContent(/reissue the certificate/);
    expect(screen.getByRole("button", { name: "Re-verify against the latest agent report" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Rescan id for task task-e1")).toBeNull();
  });
});
