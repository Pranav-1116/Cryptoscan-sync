import React from "react";
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Pqc from "./Pqc";

const ROADMAP = {
  anchor: "Historical NIST IR 8547 draft planning model; current applicability requires review",
  total_in_scope: 100,
  weak_legacy: 25,
  phases: [
    {
      phase: "P1",
      deadline: 2027,
      instance_count: 2,
      items: [
        {
          family: "RSA",
          key_size: 2048,
          transition: "GROVER_IMPACTED",
          instances: 2,
          applications: ["payments-api", "ledger-svc"],
          deadline: 2027,
          years_left: 1,
          overdue: false,
        },
      ],
    },
  ],
};

describe("PQC migration — plans are traceable to assets and rules (gap analysis §A)", () => {
  it("every migration line names its rule and links its applications to the inventory", async () => {
    mockFetch({
      "/api/v1/technology-bom": { components: [], counts: {} },
      "/api/v1/banking/roadmap": ROADMAP,
      "/api/v1/banking/hndl": { at_risk: 0, total: 0, by_exposure: {}, entries: [] },
    });
    renderWithProviders(<Pqc />);
    const items = await screen.findByTestId("phase-items-P1");
    expect(items).toHaveTextContent("RSA 2048");
    expect(items).toHaveTextContent("rule: GROVER_IMPACTED");
    expect(items).toHaveTextContent("2 instance(s)");
    const payLink = within(items).getByRole("link", { name: "payments-api" });
    expect(payLink).toHaveAttribute("href", "/assets?q=payments-api");
    const ledgerLink = within(items).getByRole("link", { name: "ledger-svc" });
    expect(ledgerLink).toHaveAttribute("href", "/assets?q=ledger-svc");
    // the family links through to the CBOM view with the same focus
    const familyLink = within(items).getByRole("link", { name: "RSA 2048" });
    expect(familyLink).toHaveAttribute("href", "/cbom?focus=RSA");
  });

  it("the plan keeps its anchor: a historical draft planning model, not a mandate", async () => {
    mockFetch({
      "/api/v1/technology-bom": { components: [], counts: {} },
      "/api/v1/banking/roadmap": ROADMAP,
      "/api/v1/banking/hndl": { at_risk: 0, total: 0, by_exposure: {}, entries: [] },
    });
    renderWithProviders(<Pqc />);
    expect(
      await screen.findByText(/current applicability requires review/),
    ).toBeInTheDocument();
  });
});
