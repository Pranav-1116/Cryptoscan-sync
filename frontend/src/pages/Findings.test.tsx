/* Findings page (§5, round 73): the finding record is not a dead end —
 * the detail drawer surfaces PER-RECORD verification (§4.2 round 42
 * endpoint: recompute this record's content + chain hashes against its
 * own commitments; auditor-only, a 403 renders as the role refusal) and
 * the finding→task cross-link (which remediation tasks reference this
 * finding). No fabricated verdicts, no fabricated tasks. */
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Findings from "./Findings";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Findings />
    </MemoryRouter>,
  );

const finding = {
  evidence_id: "ev-3des-payroll-1", scan_id: "scan-77", algorithm: "3DES",
  key_size: 112, mode: "CBC", padding: "PKCS7", purpose: "ENCRYPTION",
  confidence: "HIGH", is_hardcoded_key: false,
  file_path: "src/legacy/PaymentUtil.java", line_number: 42,
  compliance_status: "NON_COMPLIANT",
  content_hash: "c0ffee".padEnd(64, "0"),
  chain_hash: "deadbeef".padEnd(64, "0"),
  normalized_crypto: null, policy_evaluation: null, finding_data: null,
  created_at: "2026-10-10T10:00:00+00:00", updated_at: "2026-10-10T10:00:00+00:00",
};

const verdict = {
  evidence_id: finding.evidence_id, scan_id: "scan-77", chain_position: 3,
  content_intact: true, chain_intact: true, hash_format_valid: true,
  result: "PASS", errors: [], notes: [],
  verified_by: "auditor", scan_status: "COMPLETED",
  scan_verify_path: "/api/v1/scans/scan-77/verify",
};

const task = {
  id: "task-9f01", evidence_id: finding.evidence_id, scan_id: "scan-77",
  rule_id: "P019", category: "weak_cipher", priority: "P0",
  replace_with: "AES-256-GCM", original_finding: {}, target_location: "repo",
  status: "VERIFIED", owner: "crypto-team", notes: null,
  created_by: "analyst", source: "manual", source_ref: null,
  completed_at: "2026-10-12T10:00:00+00:00", completed_by: "crypto-team",
  latest_verification: null,
};

const baseRoutes = {
  "/api/v1/findings": { findings: [finding], total_count: 1, page: 1, page_size: 50 },
  [`/api/v1/findings/${finding.evidence_id}`]: finding,
  "/api/v1/scans/runtime-findings": { findings: [], summary: {}, total_count: 0 },
};

async function openDetail(routes: Record<string, unknown>) {
  const fetchMock = mockFetch(routes);
  renderPage();
  // wait for the evidence list, then click the first row's algorithm
  // cell (the algorithm ALSO renders as a filter chip, so target the
  // one inside the table row) to open the detail drawer
  const cell = await screen.findAllByText("3DES").then(
    (els) => els.find((el) => el.closest("tr")) ?? els[els.length - 1]);
  fireEvent.click(cell);
  await waitFor(() => expect(screen.getByText("Record verification")).toBeTruthy());
  return fetchMock;
}

describe("Findings page", () => {
  it("verifies one record against its own commitments and shows the verdict", async () => {
    await openDetail({
      ...baseRoutes,
      [`/api/v1/findings/${finding.evidence_id}/verify`]: verdict,
      "/api/v1/remediation/tasks": { tasks: [task], total: 1, page: 1, page_size: 20 },
    });

    // before verifying, no verdict is shown — none is invented
    expect(screen.queryByText("PASS")).toBeNull();

    fireEvent.click(screen.getByText("Verify this record"));
    expect(await screen.findByText("PASS")).toBeTruthy();
    expect(screen.getByText("content intact")).toBeTruthy();
    expect(screen.getByText("chain intact")).toBeTruthy();
    expect(screen.getByText("verified by")).toBeTruthy();
    expect(screen.getByText("auditor")).toBeTruthy();
    expect(screen.getByText(/\/api\/v1\/scans\/scan-77\/verify/)).toBeTruthy();
  });

  it("renders a FAIL verdict with its exact errors — never a softened pass", async () => {
    await openDetail({
      ...baseRoutes,
      [`/api/v1/findings/${finding.evidence_id}/verify`]: {
        ...verdict, result: "FAIL", content_intact: false,
        errors: ["content hash mismatch — stored finding_data no longer matches its commitment"],
      },
      "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 20 },
    });

    fireEvent.click(screen.getByText("Verify this record"));
    expect(await screen.findByText("FAIL")).toBeTruthy();
    expect(screen.getByText(/content hash mismatch/i)).toBeTruthy();
  });

  it("renders the auditor-role refusal honestly on 403", async () => {
    const fetchMock = await openDetail({
      ...baseRoutes,
      [`/api/v1/findings/${finding.evidence_id}/verify`]: (
        _url: string, _init?: RequestInit) =>
        new Response(JSON.stringify({ detail: "Requires one of roles: admin, auditor" }),
          { status: 403, headers: { "Content-Type": "application/json" } }),
      "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 20 },
    });

    fireEvent.click(screen.getByText("Verify this record"));
    expect(await screen.findByText(/Requires auditor role/i)).toBeTruthy();
    expect(screen.queryByText("PASS")).toBeNull();
    expect(screen.queryByText("FAIL")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v1/findings/${finding.evidence_id}/verify`, expect.anything());
  });

  it("cross-links the remediation tasks that reference this finding", async () => {
    await openDetail({
      ...baseRoutes,
      [`/api/v1/findings/${finding.evidence_id}/verify`]: verdict,
      "/api/v1/remediation/tasks": { tasks: [task], total: 1, page: 1, page_size: 20 },
    });

    // the referencing task renders with its status, rule and owner
    expect(await screen.findByText("P019")).toBeTruthy();
    expect(screen.getByText("VERIFIED")).toBeTruthy();
    expect(screen.getByText(/crypto-team/)).toBeTruthy();
    // and the lifecycle view is one click away
    expect(screen.getByRole("link", { name: /Open task lifecycle/ })).toHaveAttribute("href", "/remediation");
    expect(screen.getByText(/COMPLETED = declaration/i)).toBeTruthy();
  });

  it("states honestly when no remediation task references the finding", async () => {
    await openDetail({
      ...baseRoutes,
      [`/api/v1/findings/${finding.evidence_id}/verify`]: verdict,
      "/api/v1/remediation/tasks": { tasks: [], total: 0, page: 1, page_size: 20 },
    });

    expect(await screen.findByText(/No tasks reference this/)).toBeTruthy();
  });

  it("keeps the drawer honest when the backend is unreachable", async () => {
    offlineFetch();
    renderPage();
    expect(await screen.findAllByText(/Backend offline/i)).not.toHaveLength(0);
    expect(screen.queryByText("Record verification")).toBeNull();
  });
});
