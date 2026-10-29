import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import ResourceMonitoring from "./ResourceMonitoring";

const ID = "11111111-1111-1111-1111-111111111111";
const sample = () => ({ subject_id: ID, payload: {
  capture: { finished_at: new Date().toISOString(), network_namespace_inode: 42, mount_namespace_inode: 43, authorization: { scope: { host_label: "synthetic-linux" } } },
  report: { sample_seconds: 5, network: [{ interface: "lo", status: "MEASURED", rx_mbps: 0, tx_mbps: 8, delta: { rx_packets: 0, tx_packets: 100, rx_dropped: 0, tx_dropped: 0, rx_errors: 0, tx_errors: 0 } }],
    storage: [{ path: "/data", status: "UNAVAILABLE", total_bytes: null, used_bytes: null, available_bytes: null, used_percent: null, filesystem_device: null }] },
} });
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
let fetcher: ReturnType<typeof vi.fn>;
beforeEach(() => {
  localStorage.clear(); localStorage.setItem("cryptoscan_tenant", "a"); localStorage.setItem("zelinx_token", "synthetic-test-token");
  fetcher = vi.fn(async (path: string) => {
    if (path.endsWith("/plans")) return response({ items: [], next_cursor: null });
    if (path.endsWith("/captures")) return response({ items: [{ capture_id: ID, host_label: "synthetic-linux", finished_at: "recent" }], next_cursor: null });
    if (path.includes("/captures/")) return response(sample());
    if (path.endsWith("/traffic-proposals")) return response({ subject_id: ID, payload: { state: "DRAFT_REQUIRES_DEVICE_ADAPTER_AND_CHANGE_APPROVAL", applied: false } }, 201);
    return response({ detail: "Not found" }, 404);
  });
  vi.stubGlobal("fetch", fetcher);
});
afterEach(() => vi.unstubAllGlobals());

async function load() {
  fireEvent.click(screen.getByRole("button", { name: "Refresh scopes and samples" }));
  await screen.findByRole("option", { name: /synthetic-linux — recent/ });
  fireEvent.change(screen.getByLabelText("Retained sample"), { target: { value: ID } });
  await screen.findByText("synthetic-linux", { selector: "div" });
}

it("starts honestly empty and does not collect or poll targets", () => {
  render(<ResourceMonitoring />);
  expect(screen.getAllByText(/not continuous live monitoring/)).toHaveLength(2);
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(fetcher).not.toHaveBeenCalled();
});

it("renders real zero traffic but unavailable capacity as Unknown without adding filesystems", async () => {
  render(<ResourceMonitoring />); await load();
  expect(screen.getAllByText("0.000")).toHaveLength(2);
  expect(screen.getAllByText("Unknown").length).toBeGreaterThanOrEqual(4);
  expect(screen.getByText(/Do not add these rows/)).toBeInTheDocument();
  expect(screen.getByText(/source authenticity unverified/)).toBeInTheDocument();
  const [path, init] = fetcher.mock.calls[0];
  expect(String(path)).toMatch(/^\/api\/v1\/resource-monitoring\//);
  expect((init as RequestInit).headers).toMatchObject({ "X-Tenant-ID": "a", Authorization: "Bearer synthetic-test-token" });
});

it("saves only a draft and never calls an apply endpoint", async () => {
  render(<ResourceMonitoring />); await load();
  fireEvent.change(screen.getByLabelText("Egress limit (Mbps)"), { target: { value: "10" } });
  fireEvent.change(screen.getByLabelText("Change reason"), { target: { value: "Approved review of a proposed traffic limit" } });
  fireEvent.click(screen.getByRole("button", { name: "Save draft limit (not apply)" }));
  await screen.findByText(/NOT APPLIED; no enforcement adapter/);
  expect(fetcher.mock.calls.some(([p]) => String(p).includes("/apply"))).toBe(false);
});

it("does not keep a previous successful report after a backend refusal", async () => {
  render(<ResourceMonitoring />); await load();
  fetcher.mockImplementation(async () => response({ detail: "Original source integrity changed" }, 409));
  fireEvent.click(screen.getByRole("button", { name: "Refresh scopes and samples" }));
  await screen.findByText("Original source integrity changed");
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
});

it("clears private forms and records on an estate switch", async () => {
  render(<ResourceMonitoring />); await load();
  fireEvent.change(screen.getByLabelText("Operator host label"), { target: { value: "private-host-a" } });
  act(() => { localStorage.setItem("cryptoscan_tenant", "b"); window.dispatchEvent(new Event("zelinx:tenant")); });
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Operator host label")).toHaveValue("");
  expect(screen.queryByRole("option", { name: /synthetic-linux — recent/ })).not.toBeInTheDocument();
});

it("discards an old-scope response even if the transport ignores abort", async () => {
  render(<ResourceMonitoring />);
  fireEvent.click(screen.getByRole("button", { name: "Refresh scopes and samples" }));
  await screen.findByRole("option", { name: /synthetic-linux — recent/ });
  let resolve!: (value: Response) => void;
  fetcher.mockImplementationOnce(() => new Promise<Response>((r) => { resolve = r; }));
  fireEvent.change(screen.getByLabelText("Retained sample"), { target: { value: ID } });
  await waitFor(() => expect(resolve).toBeDefined());
  act(() => window.dispatchEvent(new Event("zelinx:tenant")));
  await act(async () => { resolve(response(sample())); });
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  expect(screen.queryByText("synthetic-linux", { selector: "div" })).not.toBeInTheDocument();
});

it("marks stale data and disables drafting instead of claiming a current live reading", async () => {
  fetcher.mockImplementation(async (path: string) => {
    if (path.endsWith("/plans")) return response({ items: [] });
    if (path.endsWith("/captures")) return response({ items: [{ capture_id: ID, host_label: "synthetic-linux", finished_at: "old" }] });
    const old = sample(); old.payload.capture.finished_at = "2020-01-01T00:00:00Z"; return response(old);
  });
  render(<ResourceMonitoring />);
  fireEvent.click(screen.getByRole("button", { name: "Refresh scopes and samples" }));
  await screen.findByRole("option", { name: /synthetic-linux — old/ });
  fireEvent.change(screen.getByLabelText("Retained sample"), { target: { value: ID } });
  await screen.findByText(/Stale or invalid capture time/);
  expect(screen.getByRole("button", { name: "Save draft limit (not apply)" })).toBeDisabled();
});
