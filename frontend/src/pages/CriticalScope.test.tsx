import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { mockFetch } from "../test/setup";
import OperatorDecisions from "./OperatorDecisions";
import LaunchReadiness from "./LaunchReadiness";
import Evidence from "./Evidence";

vi.mock("../lib/realtime", () => ({ useRealtime: () => ({ replayIssue: null }) }));
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
const inbox = (marker: string) => ({ estate_id: "a", as_of: "2026-10-23T00:00:00Z", uncertainty: "UNKNOWN coverage", sections: { tasks: { items: [{ id: "synthetic-task", owner: marker, status: "COMPLETED", reported_complete: true, current_condition_verified: false, evidence_freshness: "UNKNOWN" }], has_more: false, next_offset: null } } });
const scans = (marker: string) => ({ scans: [{ scan_id: marker, status: "COMPLETED", target_location: "synthetic-source" }], total_count: 1, page: 1, page_size: 20 });
const pages = [
  { name: "Operator decisions", Page: OperatorDecisions, path: "/api/v1/assurance/operator-decisions", body: inbox },
  { name: "Launch readiness", Page: LaunchReadiness, path: "/api/v1/assurance/launch/operations", body: (marker: string) => ({ marker }) },
  { name: "Evidence", Page: Evidence, path: "/api/v1/scans", body: scans },
];
const changes = ["cryptoscan_tenant", "zelinx_signed_in", "zelinx_roles", "zelinx_user", null, "resume", "bfcache"];
function invalidate(key: string | null) {
  if (key === "bfcache") { window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })); return; }
  if (key === "resume") { document.dispatchEvent(new Event("visibilitychange")); return; }
  if (key === null) localStorage.clear();
  else localStorage.setItem(key, key === "zelinx_roles" ? '["readonly"]' : "changed");
  window.dispatchEvent(new StorageEvent("storage", { key, storageArea: localStorage }));
}

for (const page of pages) describe(`${page.name} private scope`, () => {
  it.each(changes)("clears retained evidence/drafts after %s", async key => {
    const next = deferred<unknown>(); let reads = 0;
    mockFetch({ [page.path]: () => ++reads === 1 ? page.body("private-old-marker") : next.promise,
      "/api/v1/findings": { findings: [], total_count: 0 } });
    render(<MemoryRouter><page.Page /></MemoryRouter>);
    await screen.findAllByText(/private-old-marker/);
    if (page.name === "Launch readiness") fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{"private":"draft"}' } });
    await act(async () => invalidate(key));
    expect(screen.queryAllByText(/private-old-marker/)).toHaveLength(0);
    if (page.name === "Launch readiness") expect(screen.getByLabelText("Typed JSON body")).toHaveValue("");
    await act(async () => next.resolve(page.body("current-marker")));
    expect((await screen.findAllByText(/current-marker/)).length).toBeGreaterThan(0);
  });

  it("discards an old read even if abort is ignored, including A→B→A", async () => {
    const old = deferred<unknown>(); let reads = 0;
    mockFetch({ [page.path]: () => ++reads === 1 ? old.promise : page.body("current-marker"),
      "/api/v1/findings": { findings: [], total_count: 0 } });
    render(<MemoryRouter><page.Page /></MemoryRouter>);
    await waitFor(() => expect(reads).toBe(1));
    await act(async () => { invalidate("cryptoscan_tenant"); localStorage.removeItem("cryptoscan_tenant"); invalidate("zelinx_signed_in"); });
    await screen.findAllByText(/current-marker/);
    await act(async () => old.resolve(page.body("private-old-marker")));
    expect(screen.queryAllByText(/private-old-marker/)).toHaveLength(0);
  });

  it("ignores unrelated storage changes", async () => {
    let reads = 0;
    mockFetch({ [page.path]: () => { reads++; return page.body("current-marker"); }, "/api/v1/findings": { findings: [], total_count: 0 } });
    render(<MemoryRouter><page.Page /></MemoryRouter>);
    await screen.findAllByText(/current-marker/);
    await act(async () => invalidate("unrelated-preference"));
    expect(reads).toBe(1);
  });
});

for (const name of ["Operator decisions", "Launch readiness"]) describe(`${name} mutation lock`, () => {
  async function setup() {
    const pending = deferred<unknown>();
    const fetch = mockFetch({ "/api/v1/assurance/operator-decisions": inbox("current-marker"), "/api/v1/assurance/launch/operations": {},
      "/api/v1/assurance/remediation-tasks": () => pending.promise, "/api/v1/assurance/launch/engagements": () => pending.promise });
    render(<MemoryRouter>{name === "Operator decisions" ? <OperatorDecisions /> : <LaunchReadiness />}</MemoryRouter>);
    if (name === "Operator decisions") {
      await screen.findAllByText(/current-marker/);
      fireEvent.change(screen.getByLabelText("Workflow step"), { target: { value: "create-task" } });
      fireEvent.change(screen.getByLabelText("Original finding evidence ID"), { target: { value: "synthetic-id" } });
      fireEvent.change(screen.getByLabelText("Accountable owner reference"), { target: { value: "payments" } });
    } else {
      await screen.findByText("{}");
      fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: "{}" } });
    }
    const form = screen.getByText(name === "Operator decisions" ? "Submit bounded workflow action" : "Submit bounded action").closest("form")!;
    return { pending, fetch, form };
  }
  it("admits only one same-turn submit", async () => {
    const { form, fetch } = await setup();
    act(() => { form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
  });
  it("does not restore a late receipt across a scope reset", async () => {
    const { pending, form } = await setup();
    fireEvent.submit(form);
    await act(async () => invalidate("zelinx_signed_in"));
    await act(async () => pending.resolve({ kind: "task", id: "private-old-write", receipt: "private-old-write" }));
    expect(screen.queryByText(/private-old-write/)).toBeNull();
  });
  it("warns that a failed write has an uncertain outcome, without automatic retry", async () => {
    const { form, fetch, pending } = await setup();
    fireEvent.submit(form);
    await act(async () => pending.resolve(new Response('{}', { status: 503 })));
    expect(await screen.findByText(/outcome.*not.*(confirmed|assumed)|outcome.*uncertain/i)).toBeInTheDocument();
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
  });
});

it("deduplicates record verification before React flushes a second click", async () => {
  const pending = deferred<unknown>();
  const fetch = mockFetch({ "/api/v1/scans": scans("scan-a"), "/api/v1/findings": { findings: [{ evidence_id: "ev-a", scan_id: "scan-a" }], total_count: 1 },
    "/api/v1/findings/ev-a/verify": () => pending.promise });
  render(<MemoryRouter><Evidence /></MemoryRouter>);
  const button = await screen.findByRole("button", { name: "Verify this record" });
  act(() => { button.click(); button.click(); });
  expect(fetch.mock.calls.filter(call => String(call[0]).includes("ev-a/verify"))).toHaveLength(1);
});

it("does not revive a record verdict after selecting away and back", async () => {
  const pending = deferred<unknown>();
  mockFetch({ "/api/v1/scans": { scans: [{ scan_id: "scan-a" }, { scan_id: "scan-b" }], total_count: 2 },
    "/api/v1/findings": (url: string) => ({ findings: [{ evidence_id: url.includes("scan-a") ? "ev-a" : "ev-b", scan_id: url.includes("scan-a") ? "scan-a" : "scan-b" }], total_count: 1 }),
    "/api/v1/findings/ev-a/verify": () => pending.promise });
  render(<MemoryRouter><Evidence /></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: "Verify this record" }));
  fireEvent.click(screen.getByRole("button", { name: /scan-b/ }));
  await screen.findByText("Evidence ID: ev-b");
  await act(async () => pending.resolve({ evidence_id: "ev-a", result: "PASS", content_intact: true, chain_intact: true, hash_format_valid: true, errors: [], notes: [], verified_by: "old-verifier" }));
  fireEvent.click(screen.getByRole("button", { name: /scan-a/ }));
  await screen.findByText("Evidence ID: ev-a");
  expect(screen.queryByText(/old-verifier/)).toBeNull();
  expect(screen.getByRole("button", { name: "Verify this record" })).toBeEnabled();
});

for (const page of pages.filter(p => p.name !== "Evidence")) it(`${page.name} fences an old form synchronously before scope-reset rendering`, async () => {
  const fetch = mockFetch({ [page.path]: page.body("current-marker"), "/api/v1/assurance/launch/engagements": {} });
  render(<MemoryRouter><page.Page /></MemoryRouter>);
  await screen.findAllByText(/current-marker/);
  if (page.name === "Launch readiness") fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: "{}" } });
  else {
    fireEvent.change(screen.getByLabelText("Workflow step"), { target: { value: "create-task" } });
    fireEvent.change(screen.getByLabelText("Original finding evidence ID"), { target: { value: "synthetic-id" } });
    fireEvent.change(screen.getByLabelText("Accountable owner reference"), { target: { value: "payments" } });
  }
  const form = document.querySelector("form")!;
  act(() => { invalidate("zelinx_signed_in"); form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(0);
});

it.each([
  { content_intact: undefined }, { content_intact: false }, { errors: ["mismatch"] },
])("rejects inconsistent record PASS responses: %j", async invalid => {
  mockFetch({ "/api/v1/scans": scans("scan-a"), "/api/v1/findings": { findings: [{ evidence_id: "ev-a", scan_id: "scan-a" }], total_count: 1 },
    "/api/v1/findings/ev-a/verify": { evidence_id: "ev-a", result: "PASS", content_intact: true, chain_intact: true, hash_format_valid: true, errors: [], notes: [], verified_by: "verifier", ...invalid } });
  render(<MemoryRouter><Evidence /></MemoryRouter>);
  fireEvent.click(await screen.findByRole("button", { name: "Verify this record" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("verify this record");
  expect(screen.queryByText(/verified by verifier/)).toBeNull();
});

it("bounds an interrupted launch write and requires reconciliation before retry", async () => {
  vi.useFakeTimers();
  const fetch = mockFetch({ "/api/v1/assurance/launch/operations": {},
    "/api/v1/assurance/launch/engagements": (_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("deadline", "AbortError")), { once: true });
    }) });
  render(<MemoryRouter><LaunchReadiness /></MemoryRouter>);
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: "{}" } });
  fireEvent.submit(screen.getByText("Submit bounded action").closest("form")!);
  await act(async () => { await vi.advanceTimersByTimeAsync(20001); });
  expect(screen.queryByRole("alert")).toHaveTextContent(/outcome not confirmed.*Reconcile/i);
  expect(screen.getByText("Submit bounded action")).toBeEnabled();
  expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
});
