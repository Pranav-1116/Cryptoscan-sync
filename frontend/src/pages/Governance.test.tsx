import React from "react";
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Governance from "./Governance";

const routes = (over: Record<string, unknown> = {}) => ({
  "/api/v1/exceptions": {
    exceptions: [{
      id: "EX-1", asset: "payments-api", reason: "RSA-2048 till HSM upgrade",
      expires: "2026-12-31", approved_by: "ciso",
    }],
  },
  "/api/v1/business/owners": {
    owners: [{ asset: "payments-api", owner: "payments-team", role: "technical" }],
  },
  "/api/v1/governance/requests": {
    requests: [{
      request_pk: "REQ-1", type: "change", subject: "rotate CA",
      state: "pending", requested_by: "alice",
    }],
  },
  "/api/v1/events/recent": {
    events: [{ id: "EV-1", ts: "2026-11-07T05:00:00Z", source: "alice",
               action: "exception.approve", payload: { target: "EX-1" } }],
  },
  ...over,
});

describe("Governance — all actions are audited (gap analysis §A)", () => {
  it("ownership, exceptions and approvals render beside the audit trail", async () => {
    mockFetch(routes());
    renderWithProviders(<Governance />);
    expect(await screen.findByText("payments-team")).toBeInTheDocument();
    expect(screen.getByText("EX-1")).toBeInTheDocument();
    expect(screen.getByText("REQ-1")).toBeInTheDocument();
    const auditPanel = screen.getByText("append-only · hash-chained · live event bus")
      .closest(".panel")! as HTMLElement;
    expect(within(auditPanel).getByText(/exception\.approve \(EX-1\)/)).toBeInTheDocument();
  });

  it("the page states that every action lands in the append-only trail", async () => {
    mockFetch(routes());
    renderWithProviders(<Governance />);
    const note = await screen.findByTestId("governance-audited");
    expect(note).toHaveTextContent(/Every ownership change, approval, exception and risk acceptance/);
    expect(within(note).getByRole("link", { name: /open the full audit ledger/ }))
      .toHaveAttribute("href", "/audit");
  });

  it("an offline audit source is announced, never drawn as an empty trail", async () => {
    mockFetch(routes({
      "/api/v1/events/recent": new Response(
        JSON.stringify({ detail: "denied" }), { status: 403 }),
    }));
    renderWithProviders(<Governance />);
    // the failure is announced beside the panel …
    expect(await screen.findByText(/— showing empty state/)).toBeInTheDocument();
    // … and the trail shows no invented events
    const auditPanel = screen.getByText("append-only · hash-chained · live event bus")
      .closest(".panel")! as HTMLElement;
    expect(within(auditPanel).getByText("No audit events yet.")).toBeInTheDocument();
  });
});
