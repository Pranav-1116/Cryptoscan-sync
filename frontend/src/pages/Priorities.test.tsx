/* Remediation priorities — the estate's weaknesses, ranked, read from the agents' estate graph
 * (fixture produced by agility.estate_remediation_plan on the Meridian-shaped estate). */
import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Priorities from "./Priorities";
import fixtures from "../test/fixtures/estateRemediation.json";

const FINDINGS = "/api/v1/estate/evidence/remediation/findings";
const TASKS = "/api/v1/estate/evidence/remediation/tasks";
const posts = (spy: ReturnType<typeof mockFetch>) =>
  spy.mock.calls.filter(([url, init]) => String(url).includes(TASKS) && (init as RequestInit | undefined)?.method === "POST");

describe("Remediation priorities", () => {
  it("ranks the estate's weaknesses, most urgent first, with the cause and the fix", async () => {
    mockFetch({ [FINDINGS]: fixtures.findings });
    renderWithProviders(<Priorities />);
    const table = await screen.findByRole("table", { name: "Ranked findings" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("legacy-branch has an RSA-1024 key");
    expect(rows[0]).toHaveTextContent("CRITICAL");
    expect(rows[0]).toHaveTextContent("Branch Banking");
    expect(within(table).getByText("10.210.0.5:443 negotiates TLSv1")).toBeInTheDocument();
    expect(within(table).getByText("3DES-112 is deprecated on payShield-10K-sim")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Details of legacy-branch has an RSA-1024 key" }));
    expect(screen.getByText(/can be factored with today's computers/)).toBeInTheDocument();
    expect(screen.getByText(/the PKI team/)).toBeInTheDocument();
  });

  it("filters by severity and BOM", async () => {
    mockFetch({ [FINDINGS]: fixtures.findings });
    renderWithProviders(<Priorities />);
    const table = await screen.findByRole("table", { name: "Ranked findings" });
    fireEvent.click(screen.getByRole("button", { name: "Show CRITICAL" }));
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Show CRITICAL" }));
    fireEvent.click(screen.getByRole("button", { name: "Only HBOM" }));
    const hbom = within(screen.getByRole("table", { name: "Ranked findings" })).getAllByRole("row").slice(1);
    expect(hbom.every((r) => r.textContent?.includes("HBOM"))).toBe(true);
  });

  it("opens a task for one finding, server-side re-checked", async () => {
    const spy = mockFetch({
      [FINDINGS]: fixtures.findings,
      [TASKS]: { created: 1, task_ids: ["t-1"], already_open: [], not_found: [], message: "1 task(s) opened", run_id: "run-meridian-0001" },
    });
    renderWithProviders(<Priorities />);
    fireEvent.change(await screen.findByLabelText("Task owner"), { target: { value: "pki-team" } });
    fireEvent.click(screen.getByRole("button", { name: "Open task for legacy-branch has an RSA-1024 key" }));
    await screen.findByText("1 task(s) opened");
    const body = JSON.parse(String((posts(spy)[0][1] as RequestInit).body));
    expect(body).toEqual({ source: "estate", ids: [fixtures.findings.findings[0].id], owner: "pki-team" });
  });

  it("shows an open task instead of offering a second one", async () => {
    const withTask = { ...fixtures.findings, findings: fixtures.findings.findings.map((f, i) => (i === 0 ? { ...f, task: { id: "t-1", status: "ACCEPTED", owner: "pki" } } : f)) };
    mockFetch({ [FINDINGS]: withTask });
    renderWithProviders(<Priorities />);
    await screen.findByRole("table", { name: "Ranked findings" });
    expect(screen.queryByRole("button", { name: "Open task for legacy-branch has an RSA-1024 key" })).toBeNull();
    expect(screen.getByText("ACCEPTED")).toBeInTheDocument();
  });

  it("says there is no estate yet instead of an empty list", async () => {
    mockFetch({});
    renderWithProviders(<Priorities />);
    expect(await screen.findByText("No estate yet")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("table", { name: "Ranked findings" })).toBeNull());
  });
});
