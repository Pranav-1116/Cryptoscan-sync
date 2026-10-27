import { StrictMode } from "react";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { setActiveTenantId, setToken } from "../lib/api";
import { mockFetch } from "../test/setup";
import { renderWithProviders } from "../test/render";
import Remediation from "./Remediation";

const path = "/api/v1/remediation/tasks";
const task = (owner: string, status = "ACCEPTED") => ({
  id: "shared-task-id", evidence_id: "evidence", scan_id: "scan", rule_id: `rule-${owner}`,
  status, owner, notes: `private-${owner}`, source: "manual", created_by: owner,
  original_finding: { algorithm: "3DES", file_path: `private-${owner}.java` },
  latest_verification: { result: "FAILED", reason: `proof-${owner}`, rescan_id: `scan-${owner}` },
});
const list = (owner: string, status = "ACCEPTED") => ({ tasks: [task(owner, status)], total: 1 });
function deferred() {
  let resolve!: (value: unknown) => void;
  const promise = new Promise<unknown>(done => { resolve = done; });
  return { promise, resolve };
}
const change = (event: "tenant" | "auth") => {
  if (event === "tenant") setActiveTenantId("estate-b");
  else setToken("synthetic-new-principal");
};
async function expand() {
  fireEvent.click(screen.getByRole("button", { name: "Expand task shared-task-id" }));
  return screen.findByLabelText("Rescan id for task shared-task-id");
}
const listCalls = (fetch: ReturnType<typeof mockFetch>) => fetch.mock.calls.filter(
  ([url, init]) => String(url).split("?")[0] === path && init?.method !== "POST",
);

describe("Remediation scope and asynchronous outcomes", () => {
  it.each(["tenant", "auth"] as const)("clears rows, counts and private drafts immediately on %s change", async event => {
    const next = deferred(); let calls = 0;
    mockFetch({ [path]: () => ++calls === 1 ? list("old") : next.promise });
    renderWithProviders(<Remediation />);
    await screen.findByText("rule-old");
    const input = await expand();
    fireEvent.change(input, { target: { value: "private-old-rescan" } });
    fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "private-old-draft" } });
    act(() => change(event));
    expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
    expect(screen.queryByText("proof-old")).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("private-old-draft")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "ACCEPTED · 1" })).not.toBeInTheDocument();
    await act(async () => next.resolve(list("new")));
    await screen.findByText("rule-new");
    expect(await expand()).toHaveValue("scan-new");
    expect(screen.getByLabelText("Completion notes for task shared-task-id")).toHaveValue("");
  });

  for (const event of ["tenant", "auth"] as const) {
    it.each(["success", "failure"])(`ignores late initial %s after ${event} change`, async outcome => {
      const old = deferred(); let calls = 0;
      mockFetch({ [path]: () => ++calls === 1 ? old.promise : list("new") });
      renderWithProviders(<Remediation />);
      await waitFor(() => expect(calls).toBe(1));
      act(() => change(event));
      await screen.findByText("rule-new");
      await act(async () => old.resolve(outcome === "success" ? list("old") : new Response("unavailable", { status: 503 })));
      expect(screen.getByText("rule-new")).toBeInTheDocument();
      expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
      expect(screen.queryByText("Tasks unavailable")).not.toBeInTheDocument();
    });
  }

  it.each(["success", "failure"])("ignores a superseded filter read's late %s", async outcome => {
    const old = deferred();
    mockFetch({ [path]: (url: string) => url.includes("status=REGRESSION") ? list("current", "REGRESSION") : old.promise });
    renderWithProviders(<Remediation />);
    fireEvent.click(screen.getByRole("button", { name: "REGRESSION" }));
    await screen.findByText("rule-current");
    await act(async () => old.resolve(outcome === "success" ? list("old") : new Response("unavailable", { status: 503 })));
    expect(screen.getByText("rule-current")).toBeInTheDocument();
    expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
    expect(screen.queryByText("Tasks unavailable")).not.toBeInTheDocument();
  });

  it("does not show old rows or premature empty success while a filter read is pending", async () => {
    const next = deferred();
    mockFetch({ [path]: (url: string) => url.includes("status=REGRESSION") ? next.promise : list("old") });
    renderWithProviders(<Remediation />); await screen.findByText("rule-old");
    fireEvent.click(screen.getByRole("button", { name: "REGRESSION" }));
    expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
    expect(screen.queryByText("No remediation tasks")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loading remediation tasks");
    await act(async () => next.resolve({ tasks: [], total: 0 }));
    expect(await screen.findByText("No tasks in status REGRESSION.")).toBeInTheDocument();
  });

  it("drops old counts and findings when the current read fails", async () => {
    mockFetch({ [path]: (url: string) => url.includes("status=REGRESSION") ? new Response("unavailable", { status: 503 }) : list("old") });
    renderWithProviders(<Remediation />); await screen.findByText("rule-old");
    fireEvent.click(screen.getByRole("button", { name: "REGRESSION" }));
    await screen.findByText("Tasks unavailable");
    expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "ACCEPTED · 1" })).not.toBeInTheDocument();
  });

  for (const action of ["accept", "complete", "verify"] as const) {
    it.each(["success", "failure"])(`does not let old ${action} %s reload or clear the new scope`, async outcome => {
      setActiveTenantId("estate-a"); setToken("synthetic-old-principal");
      const pending = deferred(); let reads = 0;
      const fetch = mockFetch({
        [path]: () => ++reads === 1 ? list("old", action === "accept" ? "PROPOSED" : action === "verify" ? "COMPLETED" : "ACCEPTED") : list("new"),
        [`${path}/shared-task-id/${action}`]: () => pending.promise,
      });
      renderWithProviders(<Remediation />); await screen.findByText("rule-old"); await expand();
      fireEvent.click(screen.getByRole("button", { name: action === "accept" ? "Accept (take ownership)" : action === "complete" ? "Mark complete + verify" : "Re-verify against rescan" }));
      await waitFor(() => expect(fetch.mock.calls.some(([url, init]) => String(url).endsWith(`/${action}`) && init?.method === "POST")).toBe(true));
      const sent = fetch.mock.calls.find(([url, init]) => String(url).endsWith(`/${action}`) && init?.method === "POST");
      expect(sent?.[1]?.headers).toMatchObject({ "X-Tenant-ID": "estate-a", Authorization: "Bearer synthetic-old-principal" });
      act(() => change(action === "complete" ? "auth" : "tenant"));
      await screen.findByText("rule-new"); await expand();
      fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "new-scope-draft" } });
      const before = listCalls(fetch).length;
      await act(async () => pending.resolve(outcome === "success" ? task("old") : new Response("unavailable", { status: 503 })));
      expect(listCalls(fetch)).toHaveLength(before);
      expect(screen.getByText("rule-new")).toBeInTheDocument();
      expect(screen.getByDisplayValue("new-scope-draft")).toBeInTheDocument();
      expect(screen.queryByText(/HTTP 503/)).not.toBeInTheDocument();
    });
  }

  it("does not refresh after an action completes on an unmounted page", async () => {
    const pending = deferred();
    const fetch = mockFetch({ [path]: list("old"), [`${path}/shared-task-id/complete`]: () => pending.promise });
    const view = renderWithProviders(<Remediation />); await screen.findByText("rule-old"); await expand();
    fireEvent.click(screen.getByRole("button", { name: "Mark complete + verify" }));
    const before = listCalls(fetch).length;
    view.unmount();
    await act(async () => pending.resolve(task("old")));
    expect(listCalls(fetch)).toHaveLength(before);
  });

  it("prevents two same-turn lifecycle submissions", async () => {
    const pending = deferred();
    const fetch = mockFetch({ [path]: list("old"), [`${path}/shared-task-id/complete`]: () => pending.promise });
    renderWithProviders(<Remediation />); await screen.findByText("rule-old"); await expand();
    const button = screen.getByRole("button", { name: "Mark complete + verify" });
    act(() => { button.click(); button.click(); });
    expect(fetch.mock.calls.filter(([url, init]) => String(url).endsWith("/complete") && init?.method === "POST")).toHaveLength(1);
    await act(async () => pending.resolve(task("old")));
  });

  it.each(["HTTP failure", "network disconnect"])("keeps %s outcome uncertain without automatic retry", async failure => {
    const fetch = mockFetch({ [path]: list("old"), [`${path}/shared-task-id/complete`]: () => {
      if (failure === "network disconnect") throw new TypeError("synthetic disconnect after send");
      return new Response("unavailable", { status: 503 });
    } });
    renderWithProviders(<Remediation />); await screen.findByText("rule-old"); await expand();
    fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "retain-for-review" } });
    fireEvent.click(screen.getByRole("button", { name: "Mark complete + verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/outcome.*not confirmed/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/history before retrying/i);
    expect(screen.getByDisplayValue("retain-for-review")).toBeInTheDocument();
    expect(fetch.mock.calls.filter(([url, init]) => String(url).endsWith("/complete") && init?.method === "POST")).toHaveLength(1);
  });

  it("keeps StrictMode's superseded mount read out of the current view", async () => {
    const old = deferred(); let calls = 0;
    mockFetch({ [path]: () => ++calls === 1 ? old.promise : list("current") });
    renderWithProviders(<StrictMode><Remediation /></StrictMode>);
    await screen.findByText("rule-current");
    await act(async () => old.resolve(list("obsolete-mount")));
    expect(screen.getByText("rule-current")).toBeInTheDocument();
    expect(screen.queryByText("rule-obsolete-mount")).not.toBeInTheDocument();
  });

  it.each(["success", "failure"])("does not accept an old %s after switching back to the same filter", async outcome => {
    const old = deferred(); let calls = 0;
    mockFetch({ [path]: (url: string) => {
      ++calls;
      if (calls === 1) return old.promise;
      return list(url.includes("status=REGRESSION") ? "intermediate" : "current");
    } });
    renderWithProviders(<Remediation />);
    fireEvent.click(screen.getByRole("button", { name: "REGRESSION" }));
    await screen.findByText("rule-intermediate");
    fireEvent.click(screen.getByRole("button", { name: "All statuses" }));
    await screen.findByText("rule-current");
    await act(async () => old.resolve(outcome === "success" ? list("obsolete") : new Response("unavailable", { status: 503 })));
    expect(screen.getByText("rule-current")).toBeInTheDocument();
    expect(screen.queryByText("rule-obsolete")).not.toBeInTheDocument();
    expect(screen.queryByText("Tasks unavailable")).not.toBeInTheDocument();
  });

  it.each([403, 409])("preserves status and draft on HTTP %s without retrying", async status => {
    const fetch = mockFetch({ [path]: list("current"), [`${path}/shared-task-id/complete`]: () => new Response("refused", { status }) });
    renderWithProviders(<Remediation />); await screen.findByText("rule-current"); await expand();
    fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "review-this-draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Mark complete + verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(`HTTP ${status}`);
    expect(screen.getByDisplayValue("review-this-draft")).toBeInTheDocument();
    expect(fetch.mock.calls.filter(([url, init]) => String(url).endsWith("/complete") && init?.method === "POST")).toHaveLength(1);
  });

  it.each(["cryptoscan_tenant", "zelinx_token", null])("clears private state on cross-window storage change %s", async key => {
    let calls = 0;
    mockFetch({ [path]: () => ++calls === 1 ? list("old") : list("new") });
    renderWithProviders(<Remediation />); await screen.findByText("rule-old"); await expand();
    fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "old-private-draft" } });
    act(() => {
      if (key === null) localStorage.clear(); else localStorage.setItem(key, "new-scope");
      window.dispatchEvent(new StorageEvent("storage", { key, storageArea: localStorage }));
    });
    expect(screen.queryByText("rule-old")).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("old-private-draft")).not.toBeInTheDocument();
    await screen.findByText("rule-new"); await expand();
    expect(screen.getByLabelText("Completion notes for task shared-task-id")).toHaveValue("");
  });

  it("does not reset drafts for unrelated storage preferences", async () => {
    const fetch = mockFetch({ [path]: list("current") });
    renderWithProviders(<Remediation />); await screen.findByText("rule-current"); await expand();
    fireEvent.change(screen.getByLabelText("Completion notes for task shared-task-id"), { target: { value: "useful-draft" } });
    const before = listCalls(fetch).length;
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: "zelinx_theme", storageArea: localStorage })));
    expect(screen.getByDisplayValue("useful-draft")).toBeInTheDocument();
    expect(listCalls(fetch)).toHaveLength(before);
  });
});
