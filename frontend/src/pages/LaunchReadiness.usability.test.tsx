import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { I18nProvider } from "../i18n/I18n";
import { mockFetch } from "../test/setup";
import { setActiveTenantId } from "../lib/api";
import LaunchReadiness from "./LaunchReadiness";
const P = "/api/v1/assurance/launch/";
const draw = () => render(<I18nProvider><MemoryRouter><LaunchReadiness /></MemoryRouter></I18nProvider>);

describe("Existing launch operator task safety", () => {
  it("names the selected estate next to the form and explains why an ID-bound action is unavailable", async () => {
    setActiveTenantId("bank-a"); mockFetch({ [P + "operations"]: {} }); draw();
    await screen.findByText("{}");
    expect(screen.getByLabelText("Selected estate")).toHaveTextContent("bank-a");
    fireEvent.change(screen.getByLabelText("Launch action"), { target: { value: "Acknowledge assigned duty" } });
    expect(screen.getByRole("button", { name: "Submit bounded action" })).toBeDisabled();
    await waitFor(() => expect(screen.getByText("Enter the exact record ID before this action is available.")).toBeVisible());
  });
  it("preserves the draft and record ID, focuses safe validation feedback, and sends no malformed JSON", async () => {
    const fetch = mockFetch({ [P + "operations"]: {} }); draw(); await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Exact record ID"), { target: { value: "kept-id" } });
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{"secret":"do-not-echo",' } });
    fireEvent.click(screen.getByRole("button", { name: "Submit bounded action" }));
    const feedback = await screen.findByRole("alert");
    expect(feedback).toHaveFocus(); expect(feedback).not.toHaveTextContent("do-not-echo");
    screen.getByLabelText("Typed JSON body").focus();
    fireEvent.click(screen.getByRole("button", { name: "Submit bounded action" }));
    expect(feedback).toHaveFocus(); // identical feedback must be re-announced/focused too
    expect(screen.getByLabelText("Typed JSON body")).toHaveValue('{"secret":"do-not-echo",');
    expect(screen.getByLabelText("Exact record ID")).toHaveValue("kept-id");
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(0);
  });
  it.each([400, 422])("treats HTTP %s as an ordinary rejected validation, not an ambiguous accepted write, without leaking raw detail", async status => {
    const fetch = mockFetch({ [P + "operations"]: {}, [P + "engagements"]: () => new Response(JSON.stringify({ detail: "sensitive-server-canary" }), { status }) });
    draw(); await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{"expected_revision":0}' } });
    fireEvent.click(screen.getByRole("button", { name: "Submit bounded action" }));
    const feedback = await screen.findByRole("alert");
    expect(feedback).toHaveTextContent("Validation rejected");
    expect(feedback).not.toHaveTextContent(/not confirmed|sensitive-server-canary/);
    expect(screen.getByLabelText("Typed JSON body")).toHaveValue('{"expected_revision":0}');
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
  });
  it("keeps a server outage ambiguous and never retries a write automatically", async () => {
    const fetch = mockFetch({ [P + "operations"]: {}, [P + "engagements"]: () => new Response("upstream-private-canary", { status: 503 }) });
    draw(); await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{}' } });
    fireEvent.click(screen.getByRole("button", { name: "Submit bounded action" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Action outcome not confirmed");
    expect(screen.queryByText(/upstream-private-canary/)).not.toBeInTheDocument();
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
  });
  it("separates loading, unavailable, empty and partial operating reads instead of displaying a green default", async () => {
    let release!: (body: unknown) => void;
    mockFetch({ [P + "operations"]: () => new Promise(resolve => { release = resolve; }) }); draw();
    await waitFor(() => expect(screen.getByText("Loading operating records…")).toBeVisible());
    await waitFor(() => expect(release).toBeTypeOf("function"));
    await act(async () => release({ duties: [], all_owner_reviewed_records_current: false }));
    expect(await screen.findByText("No operating duties returned. This is not proof of coverage.")).toBeVisible();
    mockFetch({ [P + "operations"]: { duties: [{ duty: "BACKUP_RESTORE", issues: ["UNASSIGNED"] }], all_owner_reviewed_records_current: false } });
    fireEvent.click(screen.getByText("Refresh operating records"));
    expect(await screen.findByText("Partial operating evidence — unresolved duties remain.")).toBeVisible();
    mockFetch({}, 503); fireEvent.click(screen.getByText("Refresh operating records"));
    expect(await screen.findByText("Operating records unavailable — not an empty estate.")).toBeVisible();
    expect(screen.queryByText(/UNASSIGNED/)).not.toBeInTheDocument();
  });
  it("labels retained history separately from an acknowledged write and a newly read current gate", async () => {
    mockFetch({ [P + "operations"]: {}, "/api/v1/assurance/records": { records: [], has_more: false } });
    draw(); await screen.findByText("{}"); fireEvent.click(screen.getByText("Read 50 retained revisions"));
    expect(await screen.findByText("Retained history — not current proof")).toBeVisible();
    expect(screen.getByText(/Reported completion is a declaration/)).toBeVisible();
  });
  it("isolates technical IDs and JSON as LTR while the surrounding Arabic task context is RTL", async () => {
    localStorage.setItem("zelnx_lang", "ar"); setActiveTenantId("مصرف-أ");
    mockFetch({ [P + "operations"]: {} }); draw(); await screen.findByText("{}");
    expect(document.documentElement).toHaveAttribute("dir", "rtl");
    expect(screen.getByLabelText("Selected estate")).toHaveTextContent("البيئة المحددة");
    expect(screen.getByLabelText("Exact record ID")).toHaveAttribute("dir", "ltr");
    expect(screen.getByLabelText("Typed JSON body")).toHaveAttribute("dir", "ltr");
  });
});

it("bounds a non-cooperative action body at 20 seconds and ignores its late success without retrying", async () => {
  const { vi } = await import("vitest");
  mockFetch({ [P + "operations"]: {} }); draw(); await screen.findByText("{}");
  let release!: (body: unknown) => void;
  const writes = mockFetch({ [P + "engagements"]: () => new Promise(resolve => { release = resolve; }) });
  vi.useFakeTimers();
  try {
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{}' } });
    fireEvent.click(screen.getByRole("button", { name: "Submit bounded action" }));
    await act(async () => { await Promise.resolve(); });
    expect(release).toBeTypeOf("function");
    await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
    expect(screen.getByRole("alert")).toHaveTextContent("Action outcome not confirmed");
    expect(screen.getByRole("button", { name: "Submit bounded action" })).not.toBeDisabled();
    await act(async () => release({ private_late_receipt: "must-not-be-shown" }));
    expect(screen.queryByText(/private_late_receipt/)).not.toBeInTheDocument();
    expect(writes.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(1);
  } finally { vi.useRealTimers(); }
});
