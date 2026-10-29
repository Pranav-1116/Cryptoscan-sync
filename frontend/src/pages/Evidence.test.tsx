import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { setActiveTenantId } from "../lib/api";
import Evidence from "./Evidence";

const scanPath = "/api/v1/scans";
const findingsPath = "/api/v1/findings";
const auditPath = "/api/v1/auth/audit";
const scan = (id: string) => ({ scan_id: id, status: "COMPLETED", target_location: "source-repo" });
const scans = (ids: string[], total = ids.length) => ({ scans: ids.map(scan), total_count: total, page: 1, page_size: 20 });
const observation = (id: string, scanId: string, extra = {}) => ({
  evidence_id: id, scan_id: scanId, algorithm: "AES-256", file_path: "src/crypto.ts", line_number: 17,
  content_hash: "abc123", chain_hash: "def456", finding_data: { scanner_id: "static-scanner", code_origin: "source", snippet: "SECRET_EXAMPLE_DO_NOT_DISPLAY" }, ...extra,
});
const findings = (records: unknown[], total = records.length) => ({ findings: records, total_count: total, page: 1, page_size: 50 });
const verified = (id: string, result: "PASS" | "FAIL" | "EMPTY" | "UNVERIFIABLE") => ({
  scan_id: id, result, records: 1, chain_intact: result !== "FAIL", content_intact: result !== "FAIL",
  hash_format_valid: true, manifest_intact: result !== "FAIL", errors: result === "FAIL" ? ["chain hash mismatch"] : [],
});
const refused = (status: number) => new Response(JSON.stringify({ detail: "denied" }), { status });

describe("Evidence workflow", () => {
  it("shows sparse server facts, not per-record seals or invented audit IPs", async () => {
    mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([observation("ev-a", "scan-a", { algorithm: null, file_path: null, line_number: null, finding_data: null, content_hash: null, chain_hash: null })]),
      [auditPath]: { events: [{ id: "audit-a", actor: "alice", action: "login", outcome: "SUCCESS", ip_address: null }], page: 1, page_size: 50 },
      "/api/v1/auth/audit/verify": { status: "OK", checked: 1 },
    });
    renderWithProviders(<Evidence />);
    expect(await screen.findByText("Evidence ID: ev-a")).toBeInTheDocument();
    const detail = screen.getByText("Evidence ID: ev-a").closest("article")!;
    expect(within(detail).getAllByText("Not supplied").length).toBeGreaterThan(0);
    expect(screen.getByText(/the scan-level verdict appears here once requested/)).toBeInTheDocument();
    expect(screen.queryByText(/Integrity Sealed|SECRET_EXAMPLE_DO_NOT_DISPLAY|127\.0\.0\.1/)).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Audit Ledger" }));
    expect(await screen.findByRole("button", { name: /audit-a/ })).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Audit event detail" })).getAllByText("Not supplied").length).toBeGreaterThan(0);
    expect(screen.queryByText("127.0.0.1")).toBeNull();
  });

  it("renders server-confirmed scan PASS only after the exact scan verification response", async () => {
    let finish!: (body: unknown) => void;
    const pending = new Promise(resolve => { finish = resolve; });
    localStorage.setItem("zelinx_token", "bearer-a");
    setActiveTenantId("tenant-a");
    const fetchSpy = mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([observation("ev-a", "scan-a")]),
      "/api/v1/scans/scan-a/verify": () => pending });
    renderWithProviders(<Evidence />);
    await screen.findByText("Evidence ID: ev-a");
    expect(screen.getByText("Scanner").parentElement).toHaveTextContent("static-scanner");
    expect(screen.queryByText("SECRET_EXAMPLE_DO_NOT_DISPLAY")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(screen.getByRole("button", { name: "Verifying…" })).toBeDisabled();
    expect(screen.queryByText("Server scan verification: PASS", { exact: false })).toBeNull();
    const call = fetchSpy.mock.calls.find(([path]) => String(path) === "/api/v1/scans/scan-a/verify");
    expect(call?.[1]).toMatchObject({ credentials: "include", headers: { Authorization: "Bearer bearer-a", "X-Tenant-ID": "tenant-a" } });
    await act(async () => finish(verified("scan-a", "PASS")));
    expect(await screen.findByText(/Server scan verification: PASS/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify this record" })).toBeInTheDocument();
    expect(screen.getByText("0/1 verified")).toBeInTheDocument();
    expect(screen.getByText(/Unverified ≠ sealed/)).toBeInTheDocument();
  });

  it("reports a server FAIL and refuses missing or mismatched scan verdicts", async () => {
    let response: unknown = verified("scan-a", "FAIL");
    mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([]), "/api/v1/scans/scan-a/verify": () => response });
    renderWithProviders(<Evidence />);
    await screen.findByText("No evidence observations returned for this scan.");
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(await screen.findByText(/Server scan verification: FAIL/)).toBeInTheDocument();
    response = { ...verified("other-scan", "PASS") };
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("verdict unavailable");
    expect(screen.queryByText(/Server scan verification: PASS/)).toBeNull();
    response = {};
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("verdict unavailable");
  });

  it.each([401, 403, 503])("keeps HTTP %i failure distinct from empty evidence", async status => {
    mockFetch({ [scanPath]: refused(status) });
    renderWithProviders(<Evidence />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(status === 401 ? "Authentication required" : status === 403 ? "Access denied" : "HTTP 503");
    expect(screen.queryByText("No scans returned for this tenant.")).toBeNull();
  });

  it("reports offline service as unknown instead of no scans", async () => {
    renderWithProviders(<Evidence />);
    expect(await screen.findByRole("alert")).toHaveTextContent("offline or unreachable");
    expect(screen.queryByText("No scans returned for this tenant.")).toBeNull();
  });

  it("does not retain a verified verdict if the verification request is later denied", async () => {
    let deny = false;
    mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([]),
      "/api/v1/scans/scan-a/verify": () => deny ? refused(403) : verified("scan-a", "PASS") });
    renderWithProviders(<Evidence />);
    await screen.findByText("No evidence observations returned for this scan.");
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(await screen.findByText(/Server scan verification: PASS/)).toBeInTheDocument();
    deny = true;
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Access denied");
    expect(screen.queryByText(/Server scan verification: PASS/)).toBeNull();
  });

  it("paginates scans and selected scan evidence without inventing IDs", async () => {
    const firstScans = Array.from({ length: 20 }, (_, i) => `scan-${i}`);
    const firstFindings = Array.from({ length: 50 }, (_, i) => observation(`ev-${i}`, "scan-0"));
    const fetchSpy = mockFetch({
      [scanPath]: (url: string) => url.includes("page=2") ? scans(["scan-20"], 21) : scans(firstScans, 21),
      [findingsPath]: (url: string) => url.includes("scan-20") ? findings([]) : url.includes("page=2") ? findings([observation("ev-50", "scan-0")], 51) : findings(firstFindings, 51),
    });
    renderWithProviders(<Evidence />);
    expect(await screen.findByText("Loaded 50 of 51 observations")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
    expect(await screen.findByText("Loaded 51 of 51 observations")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more scans" }));
    expect(await within(screen.getByRole("region", { name: "Scan selection" })).findByText("Loaded 21 of 21 scans")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /scan-20/ }));
    expect(await screen.findByText("No evidence observations returned for this scan.")).toBeInTheDocument();
    expect(screen.queryByText("Evidence ID: ev-50")).toBeNull();
    expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith(findingsPath) && String(url).includes("page=2&page_size=50") && String(url).includes("scan_id=scan-0"))).toBe(true);
  });

  it("clears old scan, findings and verdict on tenant switch and rejects late old-tenant responses", async () => {
    setActiveTenantId("tenant-a");
    let finish!: (body: unknown) => void;
    const pending = new Promise(resolve => { finish = resolve; });
    const fetchSpy = mockFetch({
      [scanPath]: (url: string, init?: RequestInit) => init?.headers && (init.headers as Record<string, string>)["X-Tenant-ID"] === "tenant-b" ? scans(["scan-b"]) : scans(["scan-a"]),
      [findingsPath]: (url: string) => url.includes("scan-b") ? findings([observation("ev-b", "scan-b")]) : findings([observation("ev-a", "scan-a")]),
      "/api/v1/scans/scan-a/verify": () => pending,
    });
    renderWithProviders(<Evidence />);
    await screen.findByText("Evidence ID: ev-a");
    fireEvent.click(screen.getByRole("button", { name: "Verify selected scan" }));
    act(() => setActiveTenantId("tenant-b"));
    expect(await screen.findByText("Evidence ID: ev-b")).toBeInTheDocument();
    await act(async () => finish(verified("scan-a", "PASS")));
    expect(screen.queryByText("Evidence ID: ev-a")).toBeNull();
    expect(screen.queryByText(/Server scan verification: PASS/)).toBeNull();
    expect(fetchSpy.mock.calls.some(([url, init]) => String(url).startsWith(findingsPath) && String(url).includes("scan-b") && (init?.headers as Record<string, string>)["X-Tenant-ID"] === "tenant-b")).toBe(true);
  });

  it("shows audit permission failure rather than an empty or verified ledger", async () => {
    mockFetch({ [scanPath]: scans([]), [auditPath]: refused(403), "/api/v1/auth/audit/verify": refused(403) });
    renderWithProviders(<Evidence />);
    fireEvent.click(screen.getByRole("tab", { name: "Audit Ledger" }));
    const alerts = await screen.findAllByRole("alert");
    expect(alerts).toHaveLength(2);
    expect(alerts.every(alert => alert.textContent?.includes("Access denied"))).toBe(true);
    expect(screen.queryByText("No audit events returned.")).toBeNull();
    expect(screen.queryByText("Audit chain verification ·", { exact: false })).toBeNull();
  });

  it("retains audit export, chain verification, event selection and pagination across tab switches", async () => {
    const first = Array.from({ length: 50 }, (_, i) => ({ id: `audit-${i}`, actor: "alice", action: "login", outcome: "SUCCESS", ip_address: null }));
    const fetchSpy = mockFetch({ [scanPath]: scans([]), [auditPath]: (url: string) => url.includes("page=2") ? { events: [{ id: "audit-50", actor: "bob", action: "logout", outcome: "SUCCESS" }], page: 2, page_size: 50 } : { events: first, page: 1, page_size: 50 },
      "/api/v1/auth/audit/verify": { status: "TAMPERED", checked: 50, mode: "incremental" } });
    renderWithProviders(<Evidence />);
    fireEvent.click(screen.getByRole("tab", { name: "Audit Ledger" }));
    expect(await screen.findByText(/Audit chain verification · 50 suffix entries checked/)).toBeInTheDocument();
    expect(screen.getByText(/discrepancy was reported/)).toBeInTheDocument();
    expect(screen.getByText("Export JSONL")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more audit events" }));
    const later = await screen.findByRole("button", { name: /audit-50/ });
    fireEvent.click(later);
    expect(screen.getByRole("region", { name: "Audit event detail" })).toHaveTextContent("bob");
    fireEvent.click(screen.getByRole("tab", { name: "Scan Evidence" }));
    fireEvent.click(screen.getByRole("tab", { name: "Audit Ledger" }));
    expect(screen.getByRole("region", { name: "Audit event detail" })).toHaveTextContent("audit-50");
    expect(fetchSpy.mock.calls.filter(([path]) => String(path).startsWith("/api/v1/auth/audit?")).length).toBe(2);
  });
});

describe("Evidence — completed scans disclose failed optional stages (§4.8)", () => {
  it("marks a COMPLETED scan whose optional stages failed as observation-incomplete", async () => {
    mockFetch({
      [scanPath]: { scans: [
        { scan_id: "scan-partial", status: "COMPLETED", target_location: "source-repo",
          statistics: { total_findings: 2, optional_stage_failures: [
            { stage: "inventory_drift", outcome: "failed", detail: "Key-inventory drift comparison failed" },
            { stage: "email_alert", outcome: "failed", detail: "Drift email alert could not be sent" },
          ] } },
        { scan_id: "scan-clean", status: "COMPLETED", target_location: "source-repo", statistics: { total_findings: 5 } },
      ], total_count: 2, page: 1, page_size: 20 },
      [findingsPath]: findings([]),
    });
    renderWithProviders(<Evidence />);
    const partial = await screen.findByRole("button", { name: /scan-partial/ });
    expect(within(partial).getByText(/2 optional stages failed — observation incomplete/)).toBeInTheDocument();
    const clean = screen.getByRole("button", { name: /scan-clean/ });
    expect(within(clean).queryByText(/optional stage/)).toBeNull();
  });

  it("claims no failure marker when statistics are absent or malformed", async () => {
    mockFetch({
      [scanPath]: { scans: [
        { scan_id: "scan-nostats", status: "COMPLETED", target_location: "source-repo" },
        { scan_id: "scan-badstats", status: "COMPLETED", target_location: "source-repo", statistics: { optional_stage_failures: "yes" } },
      ], total_count: 2, page: 1, page_size: 20 },
      [findingsPath]: findings([]),
    });
    renderWithProviders(<Evidence />);
    await screen.findByRole("button", { name: /scan-nostats/ });
    expect(screen.queryByText(/optional stage/)).toBeNull();
  });

  it("verifies a single evidence record on demand and counts only what was checked", async () => {
    let verdict: unknown = {
      evidence_id: "ev-a", scan_id: "scan-a", chain_position: 1,
      content_intact: true, chain_intact: true, hash_format_valid: true,
      result: "PASS", errors: [], notes: [], verified_by: "verifier-1",
      scan_status: "COMPLETED", scan_verify_path: "/scans/scan-a/verify",
    };
    mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([observation("ev-a", "scan-a")]),
      "/api/v1/findings/ev-a/verify": () => verdict });
    renderWithProviders(<Evidence />);
    await screen.findByText("Evidence ID: ev-a");
    // honest starting coverage: nothing individually verified yet
    expect(screen.getByText("0/1 verified")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Verify this record" }));
    expect(await screen.findByText(/content intact · chain intact · hash format valid/)).toBeInTheDocument();
    expect(screen.getByText(/verified by verifier-1/)).toBeInTheDocument();
    expect(screen.queryByText("SECRET_EXAMPLE_DO_NOT_DISPLAY")).toBeNull();
    expect(screen.getByText("1/1 verified")).toBeInTheDocument();
    expect(screen.getByText(/1 PASS · 0 FAIL/)).toBeInTheDocument();
    // a mismatched verdict body is refused, never rendered as a seal
    verdict = { ...verdict as object, evidence_id: "other-ev", result: "PASS" };
    fireEvent.click(screen.getByRole("button", { name: "Verify this record" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("verify this record");
  });

  it("filters the audit ledger server-side and keeps the export the full WORM ledger", async () => {
    const allEvents = [
      { id: "audit-a", actor: "alice", action: "auth.login", outcome: "SUCCESS" },
      { id: "audit-b", actor: "bob", action: "scan.trigger", outcome: "SUCCESS" },
    ];
    const fetchSpy = mockFetch({ [scanPath]: scans(["scan-a"]), [findingsPath]: findings([]),
      [auditPath]: (url: string) => String(url).includes("actor=alice")
        ? { events: allEvents.filter(e => e.actor === "alice"), page: 1, page_size: 50 }
        : { events: allEvents, page: 1, page_size: 50 },
      "/api/v1/auth/audit/verify": { status: "OK", checked: 2 } });
    renderWithProviders(<Evidence />);
    await screen.findByRole("button", { name: /scan-a/ });
    fireEvent.click(screen.getByRole("tab", { name: "Audit Ledger" }));
    expect(await screen.findByRole("button", { name: /audit-b/ })).toBeInTheDocument();
    // apply the actor filter — the server-side query carries it
    fireEvent.change(screen.getByLabelText("Filter by actor"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await screen.findByText(/Filtered view · actor=alice/);
    expect(screen.queryByRole("button", { name: /audit-b/ })).toBeNull();
    const filteredCall = fetchSpy.mock.calls.find(([path]) => String(path).includes("actor=alice"));
    expect(filteredCall).toBeTruthy();
    // the export note keeps the WORM contract explicit
    expect(screen.getByText(/full unfiltered WORM ledger/)).toBeInTheDocument();
    // clearing restores the unfiltered ledger
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("button", { name: /audit-b/ })).toBeInTheDocument();
    expect(screen.queryByText(/Filtered view/)).toBeNull();
  });
});
