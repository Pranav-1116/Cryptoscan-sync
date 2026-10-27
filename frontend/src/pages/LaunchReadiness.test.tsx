import React from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch } from "../test/setup";
import LaunchReadiness from "./LaunchReadiness";

const P = "/api/v1/assurance/launch/";
const draw = () => render(<MemoryRouter><LaunchReadiness /></MemoryRouter>);
afterEach(() => localStorage.clear());

describe("Launch readiness", () => {
  it("preserves external assurance, SLA and bounded coverage limitations", async () => {
    mockFetch({ [P + "operations"]: { duties: [], sla_authorized: false } }); draw();
    expect(await screen.findByText(/sla_authorized/)).toBeInTheDocument();
    expect(screen.getByText(/Certified infrastructure does not certify this product/)).toBeInTheDocument();
    expect(screen.getByText(/not an SLA/)).toBeInTheDocument();
    expect(screen.getByText(/No private keys belong in this form/)).toBeInTheDocument();
  });
  it("does not keep operating success after a failed refresh", async () => {
    mockFetch({ [P + "operations"]: { marker: "prior-operating-success" } }); draw();
    await screen.findByText(/prior-operating-success/);
    mockFetch({}, 503); fireEvent.click(screen.getByText("Refresh operating records"));
    expect(await screen.findByRole("alert")).toHaveTextContent("503");
    expect(screen.queryByText(/prior-operating-success/)).not.toBeInTheDocument();
  });
  it("rejects malformed JSON without submitting a write", async () => {
    const fetch = mockFetch({ [P + "operations"]: {} }); draw();
    await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: "not json" } });
    fireEvent.click(screen.getByText("Submit bounded action"));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(fetch.mock.calls.filter(call => call[1]?.method === "POST")).toHaveLength(0);
  });
  it("imports an external envelope and presents an immutable receipt", async () => {
    const fetch = mockFetch({ [P + "operations"]: {}, [P + "engagements/eng-1/reports"]: { revision: 1, payload: { origin_verified: true } } }); draw();
    await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Launch action"), { target: { value: "Import externally signed report / retest" } });
    fireEvent.change(screen.getByLabelText("Exact record ID"), { target: { value: "eng-1" } });
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{"expected_revision":0,"payload":{},"signature_base64":"EXTERNAL"}' } });
    fireEvent.click(screen.getByText("Submit bounded action"));
    expect(await screen.findByText(/origin_verified/)).toBeInTheDocument();
    const call = fetch.mock.calls.find(call => String(call[0]).includes("eng-1/reports"));
    expect(call?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ expected_revision: 0, payload: {}, signature_base64: "EXTERNAL" });
  });
  it("clears drafts and ignores delayed responses after an estate change", async () => {
    let resolve: (value: unknown) => void = () => {};
    let reads = 0;
    mockFetch({ [P + "operations"]: () => ++reads === 1 ? new Promise(r => { resolve = r; }) : { marker: "new-estate" } }); draw();
    await waitFor(() => expect(reads).toBe(1));
    fireEvent.change(screen.getByLabelText("Typed JSON body"), { target: { value: '{"old":"estate"}' } });
    fireEvent.change(screen.getByLabelText("Exact record ID"), { target: { value: "old-id" } });
    await act(async () => { window.dispatchEvent(new Event("zelinx:tenant")); });
    expect(await screen.findByText(/new-estate/)).toBeInTheDocument();
    expect(screen.getByLabelText("Typed JSON body")).toHaveValue("");
    expect(screen.getByLabelText("Exact record ID")).toHaveValue("");
    await act(async () => resolve({ marker: "old-estate-response" }));
    expect(screen.queryByText(/old-estate-response/)).not.toBeInTheDocument();
  });
  it("shows missing pilot evidence rather than accepted cached data", async () => {
    mockFetch({ [P + "operations"]: {}, [P + "pilots/pilot-1/status"]: { state: "PROPOSED", issues: ["INDEPENDENT_SECURITY_RECORDS_INCOMPLETE"], evidence_loop_ready: false } }); draw();
    await screen.findByText("{}");
    fireEvent.change(screen.getByLabelText("Exact record ID"), { target: { value: "pilot-1" } });
    fireEvent.click(screen.getByText("Read bounded pilot status"));
    expect(await screen.findByText(/INDEPENDENT_SECURITY_RECORDS_INCOMPLETE/)).toBeInTheDocument();
  });
});

it("browses bounded exact-estate record revisions without inventing a current result", async () => {
  const fetch = mockFetch({ [P + "operations"]: {}, "/api/v1/assurance/records": { records: [{ subject_id: "eng-1", revision: 2 }], has_more: true, next_offset: 50 } });
  draw(); await screen.findByText("{}");
  fireEvent.change(screen.getByLabelText("Record kind"), { target: { value: "security_report" } });
  fireEvent.change(screen.getByLabelText("Record offset"), { target: { value: "50" } });
  fireEvent.click(screen.getByText("Read 50 retained revisions"));
  expect(await screen.findByText(/next_offset/)).toBeInTheDocument();
  expect(fetch.mock.calls.some(call => String(call[0]).includes("kind=security_report&limit=50&offset=50"))).toBe(true);
  expect(screen.getByText(/Lists contain all revisions/)).toBeInTheDocument();
});
