/* Compliance page truth (product vision §4.3, P0 trust gap): an empty or
 * failed controls response must never become a green 100%; retention is
 * only shown when configured; "unknown" is distinct from FAIL; framework
 * buttons filter honestly and say when a framework is unmapped. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { mockFetch, offlineFetch } from "../test/setup";
import Compliance from "./Compliance";

afterEach(() => {
  localStorage.clear();
});

const renderPage = () =>
  render(
    <MemoryRouter>
      <Compliance />
    </MemoryRouter>,
  );

const controls = [
  { control: "access.session_config", status: "pass", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
  { control: "audit.chain_integrity", status: "fail", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
  { control: "deploy.schema_in_sync", status: "unknown", evidence: {}, checked_at: "2026-10-13T00:00:00Z" },
];

describe("Compliance — no false green", () => {
  it("shows 100% only from real passing controls, with the denominator", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls: [
        { control: "access.session_config", status: "pass", evidence: {}, checked_at: null },
        { control: "audit.chain_integrity", status: "pass", evidence: {}, checked_at: null },
      ] },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("100%")).toBeTruthy());
    expect(screen.getByText(/2 passing out of 2 evaluated controls/)).toBeTruthy();
    expect(screen.getByText("3 Years")).toBeTruthy();
  });

  it("an empty controls response is NOT a 100% score", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls: [] },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/Not evaluated — the engine returned no controls/)).toBeTruthy());
    expect(screen.queryByText("100%")).toBeNull();
  });

  it("an unreachable evidence source shows no score and no violation claim", async () => {
    offlineFetch();
    renderPage();
    await waitFor(() => expect(screen.getByText(/Compliance evidence is unavailable/i)).toBeTruthy());
    expect(screen.queryByText("100%")).toBeNull();
    await waitFor(() => expect(screen.getByText(/No evaluation — no violation claim/)).toBeTruthy());
  });

  it("counts fails and unknowns separately; unknown is not a violation", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("33%")).toBeTruthy()); // 1/3 passing
    expect(screen.getByText(/1 failed · 1 not evaluable/)).toBeTruthy();
    expect(screen.getByText("UNKNOWN")).toBeTruthy(); // distinct badge, not FAIL
  });

  it("retention shows Not configured when the policy is absent, never a default 7", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": {},
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Not configured")).toBeTruthy());
    expect(screen.queryByText("7 Years")).toBeNull();
  });

  it("an unmapped framework says nothing was evaluated instead of showing all rows", async () => {
    mockFetch({
      "/api/v1/compliance/evidence": { controls },
      "/api/v1/compliance/retention": { policy: { audit_log_years: 3 } },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("access.session_config")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /PCI-DSS/ }));
    expect(screen.queryByText("access.session_config")).toBeNull();
    expect(screen.getByText(/no control mapping for this framework/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /SOC 2/ }));
    await waitFor(() => expect(screen.getByText("access.session_config")).toBeTruthy());
  });
});
