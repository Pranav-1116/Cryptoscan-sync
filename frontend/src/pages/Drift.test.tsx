import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import {setToken, setActiveTenantId} from "../lib/api";
import Drift from "./Drift";

const driftPath = "/api/v1/drift";
const scansPath = "/api/v1/scans";
const response = (status: number) => new Response(JSON.stringify({ detail: "restricted" }), { status });
const event = (id: string, overrides = {}) => ({
  drift_id: id, current_scan_id: "scan-1", baseline_id: "base-1", drift_type: "CONFIG_CHANGED",
  severity: "CRITICAL", detected_at: "2026-01-02T03:04:00Z", resolution_status: "OPEN",
  drift_details: { reason: "Suite changed", baseline_finding: { algorithm: "AES", file_path: "a.py" }, current_finding: { algorithm: "RSA" } },
  acknowledged_at: null, acknowledged_by: null, resolved_at: null, resolved_by: null, resolution_notes: null,
  ...overrides,
});
const list = (events: unknown[], total_count = events.length) => ({ events, total_count, page: 1, page_size: 50 });
const scans = (baseline_comparison?: string) => ({ scans: [{ scan_id: "scan-1", status: "COMPLETED", scan_end: "2026-01-02T04:00:00Z", statistics: baseline_comparison ? { baseline_comparison } : {} }], total_count: 1 });

describe("drift feed and disposition truth", () => {
  it("does not turn a successful empty feed or missing per-scan comparison into an all-clear", async () => {
    mockFetch({ [driftPath]: list([]), [scansPath]: scans() });
    renderWithProviders(<Drift />);
    expect(await screen.findByText("No drift events")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByTitle(/Not evidence of baseline approval or clean comparison/)).toBeInTheDocument();
    expect(screen.queryByText(/TimescaleDB|primitives match|Zero cryptographic drift detected/)).toBeNull();
    expect(screen.getByText("No events returned — comparison unproven")).toBeInTheDocument();
  });

  it("reports actual scan comparison states without extrapolating to the estate", async () => {
    mockFetch({ [driftPath]: list([]), [scansPath]: scans("NO_APPROVED_BASELINE") });
    renderWithProviders(<Drift />);
    expect(await screen.findByText("No approved baseline")).toBeInTheDocument();
    expect(screen.getByText(/Per-scan · not estate verdict/)).toBeInTheDocument();
  });

  it.each([401, 403])("distinguishes HTTP %i refusal from a known empty feed", async status => {
    mockFetch({ [driftPath]: response(status), [scansPath]: response(status) });
    renderWithProviders(<Drift />);
    expect(await screen.findByRole("alert")).toHaveTextContent(status === 401 ? "Authentication required" : "Access denied");
    expect(screen.queryByText("No drift events")).toBeNull();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
  });

  it("treats an unreachable backend as unknown, not zero events", async () => {
    renderWithProviders(<Drift />);
    expect(await screen.findByRole("alert")).toHaveTextContent("offline or unreachable");
    expect(screen.getByText("Event count unavailable")).toBeInTheDocument();
    expect(screen.queryByText("No drift events")).toBeNull();
  });

  it("shows source and observed fields and loads beyond the first 50 while scoping counts", async () => {
    const first = Array.from({ length: 50 }, (_, i) => event(`event-${i}`));
    const fetchSpy = mockFetch({
      [driftPath]: (url: string) => url.includes("page=2") ? list([event("event-50", { severity: "HIGH" })], 51) : list(first, 51),
      [scansPath]: scans("PARTIAL_CONFIG_UNAVAILABLE"),
    });
    renderWithProviders(<Drift />);
    expect(await screen.findByText("Loaded 50 of 51 events")).toBeInTheDocument();
    expect(screen.getByText("Partial: configuration unavailable")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL DRIFT").parentElement).toHaveTextContent("50");
    expect(screen.getByText(/Source: persisted drift events/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("/api/v1/");
    expect(screen.getByText("AES · a.py")).toBeInTheDocument();
    expect(screen.queryByText(/TLS 1\.3|ML-KEM-768|WORM Proof/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Load more — 1 remaining/ }));
    expect(await screen.findByText("Loaded 51 of 51 events")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Load more/ })).toBeNull();
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === "/api/v1/drift?page=2&page_size=50")).toBe(true);
  });

  it("shows paging failure without discarding loaded rows, then permits retry", async () => {
    let second = 0;
    mockFetch({
      [driftPath]: (url: string) => url.includes("page=2") ? ++second === 1 ? response(503) : list([event("later")], 51) : list(Array.from({ length: 50 }, (_, i) => event(`first-${i}`)), 51),
      [scansPath]: scans("COMPARED"),
    });
    renderWithProviders(<Drift />);
    await screen.findByText("Loaded 50 of 51 events");
    fireEvent.click(screen.getByRole("button", { name: /Load more — 1 remaining/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("HTTP 503");
    expect(screen.getByText("Loaded 50 of 51 events")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Load more — 1 remaining/ }));
    expect(await screen.findByText("Loaded 51 of 51 events")).toBeInTheDocument();
  });

  it("acknowledges only on server response, with audit authorization and no resolution claim", async () => {
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>(resolve => { finish = resolve; });
    setToken("token-a");
    localStorage.setItem("cryptoscan_tenant", "tenant-a");
    const fetchSpy = mockFetch({ [driftPath]: list([event("evt-1")]), [scansPath]: scans("COMPARED"),
      "/api/v1/drift/evt-1/acknowledge": () => pending });
    renderWithProviders(<Drift />);
    await screen.findByText("Loaded 1 of 1 events");
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    expect(screen.getByRole("button", { name: "Acknowledging…" })).toBeDisabled();
    expect(screen.getByText(/Disposition:/).parentElement).toHaveTextContent("OPEN");
    const call = fetchSpy.mock.calls.find(([url]) => String(url).endsWith("/evt-1/acknowledge"));
    expect(call?.[1]).toMatchObject({ method: "POST", credentials: "include", headers: { Authorization: "Bearer token-a", "X-Tenant-ID": "tenant-a" } });
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ notes: null });
    await act(async () => finish(event("evt-1", { resolution_status: "ACKNOWLEDGED", acknowledged_at: "2026-01-02T05:00:00Z", acknowledged_by: "auditor" })));
    expect(await screen.findByRole("status")).toHaveTextContent("This does not resolve or verify remediation");
    expect(screen.getByText(/Disposition:/).parentElement).toHaveTextContent("ACKNOWLEDGED");
    expect(screen.getByText(/Analyst triage — neither resolves nor verifies remediation/)).toBeInTheDocument();
  });

  it("does not mark rejected actions successful and labels resolution as administrative, never verified", async () => {
    let deny = true;
    const fetchSpy = mockFetch({ [driftPath]: list([event("evt-1")]), [scansPath]: scans("COMPARED"),
      "/api/v1/drift/evt-1/resolve": (_url: string, init?: RequestInit) => deny ? response(403) : event("evt-1", { resolution_status: "RESOLVED", resolved_at: "2026-01-02T05:00:00Z", resolved_by: "admin", resolution_notes: JSON.parse(String(init?.body)).notes }),
    });
    renderWithProviders(<Drift />);
    await screen.findByText("Loaded 1 of 1 events");
    const resolve = screen.getByRole("button", { name: "Administratively resolve" });
    expect(resolve).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Disposition notes"), { target: { value: "Reviewed change" } });
    fireEvent.click(resolve);
    expect(await screen.findByRole("alert")).toHaveTextContent("Access denied");
    expect(screen.getByText(/Disposition:/).parentElement).toHaveTextContent("OPEN");
    deny = false;
    fireEvent.click(resolve);
    expect(await screen.findByRole("status")).toHaveTextContent("Remediation has not been verified");
    expect(screen.getByText(/Administrative closure — not remediation VERIFIED/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Administratively resolve" })).toBeNull();
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).endsWith("/evt-1/resolve"))).toHaveLength(2);
  });

  it("ignores acknowledgement responses from a previous tenant after switching", async () => {
    setActiveTenantId("tenant-a");
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>(resolve => { finish = resolve; });
    mockFetch({
      [driftPath]: (_url: string, init?: RequestInit) => (init?.headers as Record<string, string>)?.["X-Tenant-ID"] === "tenant-a" ? list([event("tenant-a-event")]) : list([event("tenant-b-event")]),
      [scansPath]: scans(),
      "/api/v1/drift/tenant-a-event/acknowledge": () => pending,
    });
    renderWithProviders(<Drift />);
    await screen.findByText("Loaded 1 of 1 events");
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    act(() => setActiveTenantId("tenant-b"));
    expect(await screen.findByText(/tenant-b-event · baseline/)).toBeInTheDocument();
    await act(async () => finish(event("tenant-a-event", { resolution_status: "ACKNOWLEDGED" })));
    expect(screen.queryByText(/tenant-a-event · baseline/)).toBeNull();
    expect(screen.queryByText(/Acknowledged by the server/)).toBeNull();
    expect(screen.getByText(/Disposition:/).parentElement).toHaveTextContent("OPEN");
  });

  it("clears old tenant events immediately and ignores late old-tenant responses", async () => {
    setActiveTenantId("tenant-a");
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>(resolve => { finish = resolve; });
    const fetchSpy = mockFetch({
      [driftPath]: (_url: string, init?: RequestInit) => (init?.headers as Record<string, string>)?.["X-Tenant-ID"] === "tenant-a" ? pending : list([event("tenant-b-event")]),
      [scansPath]: scans(),
    });
    renderWithProviders(<Drift />);
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith(driftPath))).toBe(true));
    act(() => setActiveTenantId("tenant-b"));
    expect(await screen.findByText("Loaded 1 of 1 events")).toBeInTheDocument();
    expect(screen.getAllByText(/tenant tenant-b/).length).toBeGreaterThan(0);
    await act(async () => finish(list([event("tenant-a-event")])));
    expect(screen.queryByText("tenant-a-event")).toBeNull();
  });
});

describe("Drift — condition-level verification display (§4.7)", () => {
  it("shows evidence-backed VERIFIED separately from the administrative RESOLVED caveat", async () => {
    mockFetch({
      [driftPath]: list([event("evt-verified", {
        resolution_status: "RESOLVED", resolved_at: "2026-01-02T05:00:00Z", resolved_by: "admin",
        verification_status: "VERIFIED", verified_by_scan_id: "scan-2", verified_at: "2026-01-03T05:00:00Z",
      })]),
      [scansPath]: scans("COMPARED"),
    });
    renderWithProviders(<Drift />);
    expect(await screen.findByText(/Condition verified by rescan scan-2/)).toBeInTheDocument();
    expect(screen.getByText(/gone from evidence/)).toBeInTheDocument();
    // the administrative caveat stays — verification supplements, never replaces it
    expect(screen.getByText(/Administrative closure — not remediation VERIFIED/)).toBeInTheDocument();
  });

  it("says the closure closed nothing when the rescan still sees the condition", async () => {
    mockFetch({
      [driftPath]: list([event("evt-present", {
        resolution_status: "RESOLVED", resolved_at: "2026-01-02T05:00:00Z", resolved_by: "admin",
        verification_status: "CONDITION_PRESENT", verified_by_scan_id: "scan-2", verified_at: "2026-01-03T05:00:00Z",
      })]),
      [scansPath]: scans("COMPARED"),
    });
    renderWithProviders(<Drift />);
    expect(await screen.findByText(/CONDITION STILL PRESENT in rescan scan-2/)).toBeInTheDocument();
    expect(screen.getByText(/closure closed nothing/)).toBeInTheDocument();
  });

  it("claims no verification line when none is recorded", async () => {
    mockFetch({
      [driftPath]: list([event("evt-unverified", { resolution_status: "RESOLVED", resolved_at: "2026-01-02T05:00:00Z", resolved_by: "admin" })]),
      [scansPath]: scans("COMPARED"),
    });
    renderWithProviders(<Drift />);
    await screen.findByText(/Disposition:/);
    expect(screen.queryByText(/Condition verified by rescan/)).toBeNull();
    expect(screen.queryByText(/Condition still present/)).toBeNull();
  });
});
