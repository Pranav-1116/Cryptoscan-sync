import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import HostQualification from "./HostQualification";
import CryptoAssurance from "../pages/CryptoAssurance";
import { mockFetch } from "../test/setup";
const BASE = "/api/v1/collection/qualification/campaigns";
const ID = "11111111-1111-1111-1111-111111111111";
const campaign = () => ({
  state: "WAITING_FOR_OPERATOR_EVIDENCE", evaluated_at:"synthetic-test-time", blockers: [], dispatch: "NOT_DISPATCHED_NO_REMOTE_EXECUTION",
  channel: "AUTHENTICATED_API_REQUIRES_BANK_APPROVED_TRANSPORT",
  assignees: { linux_operator: { user_id: "synthetic-user-id", username: "synthetic-operator", display_name: "Synthetic test operator" } },
  record: { subject_id: ID, revision: 2, payload: { policy: { campaign_id: "synthetic-only" }, return_channel_reference:"synthetic/channel-reference-only", index: null, withdrawn: false, artifacts: {}, reviews: {} } },
});
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
async function open() {
  fireEvent.change(screen.getByLabelText("Campaign record ID"), { target: { value: ID } });
  fireEvent.click(screen.getByText("Open / refresh"));
  await screen.findByText(/synthetic-only · revision 2/);
}
function reference() { fireEvent.change(screen.getByLabelText("Change / evidence reference"), { target: { value: "approved/test-only" } }); }

describe("Assigned-human qualification product controls", () => {
  it("is reachable from the existing page, empty/offline, without synthetic acceptance or dispatch", async () => {
    render(<CryptoAssurance />);
    fireEvent.click(screen.getByText("Host qualification"));
    expect(screen.getByText(/No campaign list loaded/)).toBeInTheDocument();
    expect(screen.getByText(/not proof of bank-approved secure transport/)).toBeInTheDocument();
    expect(screen.queryByText("SCOPED_EXTERNAL_RECORD_VERIFIED")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Load campaigns"));
    await screen.findByRole("alert");
  });

  it("sends selected tenant/auth, renders real response names, and does not generate PASS reviews", async () => {
    localStorage.setItem("cryptoscan_tenant", "bank-a"); localStorage.setItem("zelinx_token", "synthetic-session");
    const fetch = mockFetch({ [BASE + "/" + ID]: campaign(), [BASE + "/" + ID + "/assignments"]: campaign() });
    render(<HostQualification />); await open();
    expect(screen.getByText(/Synthetic test operator/, { selector: "li" })).toBeInTheDocument();
    expect(screen.getByLabelText("Signed review JSON")).toHaveValue("");
    reference();
    const assignment = { linux_operator: { user_id: "synthetic-user-id" } };
    fireEvent.change(screen.getByLabelText("Assignments JSON"), { target: { value: JSON.stringify(assignment) } });
    fireEvent.click(screen.getByText("Save assignments"));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    const init = fetch.mock.calls[1][1]!;
    expect(init.headers).toMatchObject({ "X-Tenant-ID": "bank-a", Authorization: "Bearer synthetic-session" });
    expect(JSON.parse(init.body as string)).toEqual({ expected_revision: 2, evidence_reference: "approved/test-only", assignments: assignment });
  });

  it.each(["tenant", "auth", "storage", "resume", "bfcache"])("discards delayed campaign data and drafts after %s", async change => {
    const pending = deferred<Response>();
    globalThis.fetch = vi.fn(() => pending.promise);
    render(<HostQualification />);
    reference(); fireEvent.change(screen.getByLabelText("Return channel approval reference"), { target: { value: "bank-a-private-channel-reference" } }); fireEvent.change(screen.getByLabelText("Approved policy JSON"), { target: { value: "private-bank-draft" } });
    fireEvent.change(screen.getByLabelText("Campaign record ID"), { target: { value: ID } });
    fireEvent.click(screen.getByText("Open / refresh"));
    act(() => {
      if (change === "storage") window.dispatchEvent(new StorageEvent("storage", { key: "cryptoscan_tenant" }));
      else if (change === "resume") document.dispatchEvent(new Event("visibilitychange"));
      else if (change === "bfcache") window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
      else window.dispatchEvent(new Event(`zelinx:${change}`));
    });
    await act(async () => pending.resolve(new Response(JSON.stringify(campaign()))));
    expect(screen.queryByText(/synthetic-only · revision/)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Approved policy JSON")).toHaveValue("");
    expect(screen.getByLabelText("Return channel approval reference")).toHaveValue("");
    expect(screen.getByLabelText("Change / evidence reference")).toHaveValue("");
    expect(screen.getByLabelText("Campaign record ID")).toHaveValue("");
  });

  it("returns unchanged original bytes and reports rejected requests without calling them accepted", async () => {
    const c = campaign();
    const fetch = mockFetch({ [BASE + "/" + ID]: c, [BASE + "/" + ID + "/artifacts"]: new Response(JSON.stringify({ detail: "Native plan not approved" }), { status: 409 }) });
    render(<HostQualification />); await open(); reference();
    const bytes = new TextEncoder().encode('{ "original_spacing":true }\n').buffer;
    const file = new File([bytes], "public-native.json");
    Object.defineProperty(file, "arrayBuffer", { value: async () => bytes });
    fireEvent.change(screen.getByLabelText("Original public artifact"), { target: { files: [file] } });
    fireEvent.click(screen.getByText("Return original"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Native plan not approved");
    expect(fetch.mock.calls[1][1]!.body).toBe(bytes);
    expect(fetch.mock.calls[1][1]!.headers).toMatchObject({ "Content-Type": "application/json" });
    expect(String(fetch.mock.calls[1][0])).toContain("expected_revision=2&kind=native&evidence_reference=approved%2Ftest-only");
    expect(screen.getByText("WAITING_FOR_OPERATOR_EVIDENCE")).toBeInTheDocument();
  });

  it("does not submit a delayed local file read under a newly selected tenant", async () => {
    const fetch = mockFetch({ [BASE + "/" + ID]: campaign() });
    render(<HostQualification />); await open(); reference();
    const bytes = deferred<ArrayBuffer>();
    const file = new File(["{}"], "public.json");
    Object.defineProperty(file, "arrayBuffer", { value: () => bytes.promise });
    fireEvent.change(screen.getByLabelText("Original public artifact"), { target: { files: [file] } });
    fireEvent.click(screen.getByText("Return original"));
    act(() => { localStorage.setItem("cryptoscan_tenant", "bank-b"); window.dispatchEvent(new Event("zelinx:tenant")); });
    await act(async () => bytes.resolve(new ArrayBuffer(2)));
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText("Original public artifact")).not.toBeInTheDocument();
  });

  it("does not manufacture JSON for malformed index/review drafts or silently resubmit stale revisions", async () => {
    const fetch = mockFetch({ [BASE + "/" + ID]: campaign() });
    render(<HostQualification />); await open(); reference();
    fireEvent.change(screen.getByLabelText("Evidence index JSON"), { target: { value: "bad-json" } });
    fireEvent.click(screen.getByText("Freeze evidence"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid index JSON. No submission made.");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("removes pending results after unmount even if fetch ignores abort", async () => {
    const pending = deferred<Response>(); globalThis.fetch = vi.fn(() => pending.promise);
    const view = render(<HostQualification />);
    fireEvent.click(screen.getByText("Load campaigns")); view.unmount();
    await act(async () => pending.resolve(new Response(JSON.stringify({ campaigns: [campaign()], next_cursor: null }))));
    expect(screen.queryByText("synthetic-only")).not.toBeInTheDocument();
  });
  it("records a supplied channel approval reference without inventing policy, users or signatures", async () => {
    const c = campaign();
    const fetch = mockFetch({ [BASE]: c });
    render(<HostQualification />); reference();
    const supplied = { synthetic_only: "approved public policy supplied by user" };
    fireEvent.change(screen.getByLabelText("Approved policy JSON"), { target: { value: JSON.stringify(supplied) } });
    expect(screen.getByText("Create campaign")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Return channel approval reference"), { target: { value: "approved/channel-reference" } });
    fireEvent.click(screen.getByText("Create campaign"));
    await screen.findByText(/synthetic-only · revision/);
    expect(JSON.parse(fetch.mock.calls[0][1]!.body as string)).toEqual({ policy: supplied, evidence_reference: "approved/test-only", return_channel_reference: "approved/channel-reference" });
    expect(screen.getByLabelText("Signed review JSON")).toHaveValue("");
    expect(screen.getByLabelText("Return channel approval reference")).toHaveValue("");
  });

  it("retains a server-verified signed rejection instead of displaying acceptance or generating another decision", async () => {
    const c = campaign();
    const proof = { statement: { decision: "REJECT", synthetic_only: true }, signature: "synthetic-ui-contract-not-a-signature" };
    const source = { ...c, state: "WAITING_FOR_SEPARATE_SIGNED_REVIEWS", record: { ...c.record, payload: { ...c.record.payload, index: { synthetic_only: true } } } };
    const result = { ...source, state: "BLOCKED", blockers: ["A signed review rejects or has unresolved checks"], record: { ...source.record, revision: 3, payload: { ...source.record.payload, reviews: { independent_assessor: proof } } } };
    const fetch = mockFetch({ [BASE + "/" + ID]: source, [BASE + "/" + ID + "/reviews"]: result });
    render(<HostQualification />); await open(); reference();
    fireEvent.change(screen.getByLabelText("Signed review JSON"), { target: { value: JSON.stringify(proof) } });
    act(() => { screen.getByText("Submit signed review").click(); screen.getByText("Submit signed review").click(); });
    await screen.findByText("BLOCKED");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(JSON.parse(fetch.mock.calls[1][1]!.body as string)).toEqual({ expected_revision: 2, evidence_reference: "approved/test-only", review: proof });
    expect(screen.getByText("independent_assessor: REJECT")).toBeInTheDocument();
    expect(screen.getByLabelText("Signed review JSON")).toHaveValue("");
    expect(screen.queryByText("SCOPED_EXTERNAL_RECORD_VERIFIED")).not.toBeInTheDocument();
  });

});
