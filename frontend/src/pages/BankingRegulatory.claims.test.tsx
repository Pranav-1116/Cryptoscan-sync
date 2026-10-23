import React from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/setup";
import { setActiveTenantId } from "../lib/api";
import BankingRegulatory from "./BankingRegulatory";

const P = "/api/v1/banking/";
const draw = () => render(<MemoryRouter><BankingRegulatory /></MemoryRouter>);
function fixture(hndl: unknown, jurisdictions: unknown[] = []) {
  return mockFetch({ [P + "overview"]: {}, [P + "hndl"]: hndl, [P + "roadmap"]: {},
    [P + "hsm"]: { fleet: { total: 1, pqc_ready: 0, pqc_declared_not_verified: 1, fips_validated_family: 0 } },
    [P + "jurisdictions"]: { jurisdictions }, [P + "swift-csp"]: {}, [P + "action-plan"]: {} });
}

describe("Existing banking view does not manufacture bank-ready claims", () => {
  it("separates unavailable evidence from zero risk and invented jurisdiction coverage", async () => {
    mockFetch({}, 503); draw();
    expect(await screen.findByText("HNDL evidence unavailable — not zero risk.")).toBeInTheDocument();
    expect(screen.queryByText("Zero vulnerable data classes observed")).toBeNull();
    const card = screen.getByText("Jurisdiction mappings returned").parentElement!;
    expect(within(card).getByText("Unavailable")).toBeInTheDocument();
    expect(card).not.toHaveTextContent("10");
  });
  it("keeps unknown HNDL explicit and declarations separate from verified readiness", async () => {
    fixture({ at_risk: null, total: 0, assessment_complete: false }); draw();
    expect(await screen.findByText("HNDL risk unknown — unresolved or unclassified evidence.")).toBeInTheDocument();
    expect(screen.getByText(/HSM declarations are not verified PQC readiness/)).toBeInTheDocument();
  });
  it("does not promote an empty returned cohort to discovery completeness", async () => {
    fixture({ at_risk: false, total: 0, assessment_complete: true }); draw();
    expect(await screen.findByText("No HNDL candidates in returned scope — not proof of completeness.")).toBeInTheDocument();
  });
  it("shows an actual zero jurisdiction mapping response without substituting ten", async () => {
    fixture({ at_risk: false, total: 0, assessment_complete: true }); draw();
    await screen.findByText("No HNDL candidates in returned scope — not proof of completeness.");
    const card = screen.getByText("Jurisdiction mappings returned").parentElement!;
    expect(within(card).getByText("0")).toBeInTheDocument();
    expect(card).not.toHaveTextContent("10");
  });
  it("clears old-bank evidence when the private scope changes", async () => {
    setActiveTenantId("bank-a"); fixture({ at_risk: true, total: 37 }); draw();
    await screen.findByText("37"); mockFetch({}, 503);
    await act(async () => setActiveTenantId("bank-b"));
    await waitFor(() => expect(screen.queryByText("37")).toBeNull());
    expect(await screen.findByText("HNDL evidence unavailable — not zero risk.")).toBeInTheDocument();
  });
  it("passes a selected jurisdiction as a jurisdiction rather than an unsupported framework", async () => {
    const fetch = fixture({ at_risk: true, total: 1 }); draw();
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).includes("action-plan?jurisdiction=eu"))).toBe(true));
  });
});
