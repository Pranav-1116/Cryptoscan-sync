import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { setActiveTenantId, setToken } from "../lib/api";
import Scanners from "./Scanners";

const startPath = "/api/v1/onboarding/discovery/start";
const statusPath = "/api/v1/onboarding/discovery/run-1";
const networkPath = "/api/v1/network/discover";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function selectEstate() {
  fireEvent.click(screen.getByRole("button", { name: /Register Authorized Scope/ }));
  fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
  fireEvent.click(screen.getByRole("button", { name: "Register Authorized Scope" }));
}

function configureNetwork() {
  fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
  fireEvent.change(screen.getByLabelText("Authorized network IP / CIDR"), { target: { value: "10.0.1.0/24" } });
}

describe("scanner workflow truth", () => {
  it("does not treat an accepted discovery run as completed until its ID status is terminal", async () => {
    let finish!: (value: unknown) => void;
    const status = new Promise<unknown>((resolve) => { finish = resolve; });
    const fetchSpy = mockFetch({
      [startPath]: { run_id: "run-1", status: "complete", assets_estimate: 400 },
      [statusPath]: () => status,
    });
    renderWithProviders(<Scanners />);
    selectEstate();
    expect(await screen.findByRole("heading", { name: "Checking Run Status" })).toBeInTheDocument();
    expect(screen.getByText(/Run ID:/)).toHaveTextContent("run-1");
    expect(screen.queryByRole("heading", { name: "Scope Registration Complete" })).toBeNull();
    expect(screen.queryByText(/400 asset/)).toBeNull();
    await waitFor(() => expect(fetchSpy.mock.calls.some(([path]) => String(path) === statusPath)).toBe(true));
    await act(async () => finish({ id: "run-1", status: "complete", summary: { assets_estimate: 12 } }));
    expect(await screen.findByRole("heading", { name: "Scope Registration Complete" })).toBeInTheDocument();
    expect(screen.getByText(/12 asset\(s\) estimated.*not a completed asset scan/i)).toBeInTheDocument();
  });

  it("keeps a queued run pending until its returned ID resolves to completed", async () => {
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>((resolve) => { finish = resolve; });
    mockFetch({ [startPath]: { run_id: "run-1", status: "queued" }, [statusPath]: () => pending });
    renderWithProviders(<Scanners />);
    selectEstate();
    expect(await screen.findByRole("heading", { name: "Discovery Run Queued" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Scope Registration Complete" })).toBeNull();
    await act(async () => finish({ id: "run-1", status: "completed", summary: { assets_estimate: 5 } }));
    expect(await screen.findByRole("heading", { name: "Scope Registration Complete" })).toBeInTheDocument();
  });

  it.each(["failed", "cancelled"])('reports terminal %s with the backend error rather than success', async (status) => {
    mockFetch({ [startPath]: { run_id: "run-1", status: "running" }, [statusPath]: { id: "run-1", status, error: "worker refused scope" } });
    renderWithProviders(<Scanners />);
    selectEstate();
    expect(await screen.findByRole("alert")).toHaveTextContent("worker refused scope");
    expect(screen.getByRole("heading", { name: status === "failed" ? "Request Failed" : "Run Cancelled" })).toBeInTheDocument();
    expect(screen.queryByText(/asset\(s\) estimated/)).toBeNull();
  });

  it("never routes passive network selection to an active sweep; requires explicit authorization", async () => {
    const fetchSpy = mockFetch({ [networkPath]: { hosts_checked: 3, endpoints: ["10.0.1.1:443"] } });
    renderWithProviders(<Scanners />);
    configureNetwork();
    const start = screen.getByRole("button", { name: "Start Authorized Sweep" });
    expect(start).toBeDisabled();
    fireEvent.click(start);
    expect(fetchSpy.mock.calls.filter(([path]) => [networkPath, startPath].includes(String(path)))).toHaveLength(0);
    fireEvent.change(screen.getByLabelText("Execution mode"), { target: { value: "active" } });
    expect(start).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /I authorize active probes/ }));
    fireEvent.click(start);
    expect(await screen.findByRole("heading", { name: "Network Sweep Complete" })).toBeInTheDocument();
    const calls = fetchSpy.mock.calls.filter(([path]) => String(path) === networkPath);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual({ cidr: "10.0.1.0/24", scan: true, register: false });
    expect(fetchSpy.mock.calls.some(([path]) => String(path) === startPath)).toBe(false);
  });

  it.each([403, 409, 503])("preserves HTTP %s safety refusals without fallback or fabricated completion", async (code) => {
    const fetchSpy = mockFetch({ [networkPath]: json({ detail: { reason: "not permitted now" } }, code) });
    renderWithProviders(<Scanners />);
    configureNetwork();
    fireEvent.change(screen.getByLabelText("Execution mode"), { target: { value: "active" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /I authorize active probes/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start Authorized Sweep" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(`not permitted now (HTTP ${code})`);
    expect(screen.getByRole("heading", { name: "Request Failed" })).toBeInTheDocument();
    expect(fetchSpy.mock.calls.filter(([path]) => String(path) === networkPath)).toHaveLength(1);
  });

  it("labels unsupported scanner selections and prevents a different scan from being queued", async () => {
    // cloud and container left this list in r44 (durable per-run job
    // contract); source left in r46 (execution-time safety gate at the
    // worker) — see the tests below
    const fetchSpy = mockFetch({ [startPath]: { run_id: "run-1" } });
    renderWithProviders(<Scanners />);
    await act(async () => {});
    for (const label of ["Hardware & HSM Fleet", "Certificates & CT Logs"]) {
      fireEvent.click(screen.getByRole("button", { name: new RegExp(label) }));
      expect(screen.getByRole("button", { name: "Configure Target →" })).toBeDisabled();
      expect(screen.getAllByText(/Unavailable: /).length).toBeGreaterThanOrEqual(1);
    }
    expect(fetchSpy.mock.calls.filter(([path]) => [networkPath, startPath].includes(String(path)))).toHaveLength(0);
  });

  it("queues a source scan with a job id and tracks it through the durable job record", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/scans/trigger": { job_id: "job-src-1", status: "QUEUED", message: "Scan queued. Poll /api/v1/jobs/job-src-1 for status." },
      "/api/v1/jobs/job-src-1": { job_id: "job-src-1", status: "COMPLETED", job_type: "MANUAL" },
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: /Source Repository AST/ }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText(/Repository URL/), { target: { value: "/workspace/project" } });
    fireEvent.change(screen.getByLabelText("Branch"), { target: { value: "release" } });
    fireEvent.click(screen.getByRole("button", { name: "Queue Source Scan" }));
    const post = fetchSpy.mock.calls.find(([path]) => String(path) === "/api/v1/scans/trigger");
    expect(post).toBeTruthy();
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ repo_url: "/workspace/project", branch: "release" });
    // 202 + job id → poll this run's own record, not a shared listing
    expect(await screen.findByRole("heading", { name: "Source Scan Queued" })).toBeInTheDocument();
    expect(await waitFor(() => fetchSpy.mock.calls.some(([path]) => String(path) === "/api/v1/jobs/job-src-1")));
    expect(await screen.findByRole("heading", { name: "Source Scan Complete" })).toBeInTheDocument();
    expect(screen.getByText(/Run ID:/)).toHaveTextContent("job-src-1");
  });

  it("reports an execution-gate refusal from the job record verbatim", async () => {
    mockFetch({
      "/api/v1/scans/trigger": { job_id: "job-src-2", status: "QUEUED" },
      "/api/v1/jobs/job-src-2": {
        job_id: "job-src-2", status: "FAILED",
        error_message: "execution gate: safe-scan policy refuses execution: emergency stop is engaged — all scanning halted",
      },
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: /Source Repository AST/ }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText(/Repository URL/), { target: { value: "/workspace/project" } });
    fireEvent.click(screen.getByRole("button", { name: "Queue Source Scan" }));
    expect(await screen.findByRole("heading", { name: "Request Failed" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("execution gate: safe-scan policy refuses execution: emergency stop is engaged");
  });

  it("runs a cloud scan behind its durable job record and shows the run's own coverage", async () => {
    const fetchSpy = mockFetch({
      "/api/v1/cloud-scans": { job_id: "job-cloud-1", resources: 2, findings: [], admission: { mode: "standard" } },
      "/api/v1/jobs/job-cloud-1": {
        job_id: "job-cloud-1", status: "COMPLETED", job_type: "CLOUD_SCAN",
        progress: { execution: "synchronous", coverage: { resources: 2, findings_count: 0 } },
      },
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: /Cloud KMS Scanner/ }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText(/IaC tree path/), { target: { value: "/workspace/infra" } });
    fireEvent.click(screen.getByRole("button", { name: "Start Cloud Scan" }));
    // the POST must carry the configured path
    const post = fetchSpy.mock.calls.find(([path]) => String(path) === "/api/v1/cloud-scans");
    expect(post).toBeTruthy();
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ path: "/workspace/infra", live: false });
    // a 200 response is not the status record: verify against GET /jobs/{id}
    expect(await screen.findByRole("heading", { name: "Checking Run Status" })).toBeInTheDocument();
    expect(await waitFor(() => fetchSpy.mock.calls.some(([path]) => String(path) === "/api/v1/jobs/job-cloud-1")));
    expect(await screen.findByRole("heading", { name: "Cloud Scan Complete" })).toBeInTheDocument();
    expect(screen.getByText(/Run ID:/)).toHaveTextContent("job-cloud-1");
    expect(screen.getByText(/Coverage: resources: 2 · findings count: 0/)).toBeInTheDocument();
    expect(screen.getByText(/full findings live in the scanner's own surfaces/)).toBeInTheDocument();
  });

  it("runs a container scan and reports the run's recorded failure reason verbatim", async () => {
    mockFetch({
      "/api/v1/container-scans": json({ detail: "Container filesystem not found" }, 404),
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: /Container Registry/ }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText(/Container filesystem path/), { target: { value: "/workspace/missing" } });
    fireEvent.click(screen.getByRole("button", { name: "Start Container Scan" }));
    expect(await screen.findByRole("heading", { name: "Request Failed" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Container filesystem not found (HTTP 404)");
  });

  it("does not accept a job status record that identifies a different run", async () => {
    mockFetch({
      "/api/v1/cloud-scans": { job_id: "job-cloud-2", resources: 0 },
      "/api/v1/jobs/job-cloud-2": { job_id: "some-other-run", status: "COMPLETED" },
    });
    renderWithProviders(<Scanners />);
    fireEvent.click(screen.getByRole("button", { name: /Cloud KMS Scanner/ }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Target →" }));
    fireEvent.change(screen.getByLabelText(/IaC tree path/), { target: { value: "/workspace/infra" } });
    fireEvent.click(screen.getByRole("button", { name: "Start Cloud Scan" }));
    expect(await screen.findByRole("heading", { name: "Outcome Unknown" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("did not identify the requested run");
  });

  it("does not claim a failed onboarding precondition or an accepted run without ID completed", async () => {
    const fetchSpy = mockFetch({ [startPath]: json({ detail: "Define authorized scope before discovery" }, 409) });
    renderWithProviders(<Scanners />);
    selectEstate();
    expect(await screen.findByRole("alert")).toHaveTextContent("Define authorized scope before discovery (HTTP 409)");
    expect(screen.getByRole("heading", { name: "Request Failed" })).toBeInTheDocument();
    expect(fetchSpy.mock.calls.some(([path]) => String(path).includes("/discovery/run-"))).toBe(false);
  });

  it("marks an accepted discovery response without a run ID as unknown", async () => {
    mockFetch({ [startPath]: { status: "complete", assets_estimate: 100 } });
    renderWithProviders(<Scanners />);
    selectEstate();
    expect(await screen.findByRole("heading", { name: "Outcome Unknown" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("accepted without a run ID");
    expect(screen.queryByText(/100 asset/)).toBeNull();
  });

  it("stops tracking on auth replacement without accepting a late completion", async () => {
    setToken("session-a");
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>((resolve) => { finish = resolve; });
    const fetchSpy = mockFetch({ [startPath]: { run_id: "run-1", status: "queued" }, [statusPath]: () => pending });
    renderWithProviders(<Scanners />);
    selectEstate();
    await waitFor(() => expect(fetchSpy.mock.calls.some(([path]) => String(path) === statusPath)).toBe(true));
    act(() => setToken(null));
    expect(await screen.findByRole("heading", { name: "Outcome Unknown" })).toBeInTheDocument();
    await act(async () => finish({ id: "run-1", status: "complete", summary: { assets_estimate: 99 } }));
    expect(screen.queryByRole("heading", { name: "Scope Registration Complete" })).toBeNull();
  });

  it("uses auth and tenant on start/status, and ignores a prior tenant's late result", async () => {
    setToken("session-a");
    setActiveTenantId("tenant-a");
    let finish!: (value: unknown) => void;
    const pending = new Promise<unknown>((resolve) => { finish = resolve; });
    const fetchSpy = mockFetch({ [startPath]: { run_id: "run-1", status: "running" }, [statusPath]: () => pending });
    renderWithProviders(<Scanners />);
    selectEstate();
    await waitFor(() => expect(fetchSpy.mock.calls.some(([path]) => String(path) === statusPath)).toBe(true));
    for (const [path, init] of fetchSpy.mock.calls.filter(([path]) => [startPath, statusPath].includes(String(path)))) {
      expect(path).toMatch(/discovery/);
      expect(init?.headers).toMatchObject({ Authorization: "Bearer session-a", "X-Tenant-ID": "tenant-a" });
      expect(init?.credentials).toBe("include");
    }
    act(() => setActiveTenantId("tenant-b"));
    expect(await screen.findByRole("heading", { name: "Outcome Unknown" })).toBeInTheDocument();
    await act(async () => finish({ id: "run-1", status: "complete", summary: { assets_estimate: 99 } }));
    expect(screen.queryByText(/99 asset/)).toBeNull();
    expect(screen.queryByRole("heading", { name: "Scope Registration Complete" })).toBeNull();
  });
});
