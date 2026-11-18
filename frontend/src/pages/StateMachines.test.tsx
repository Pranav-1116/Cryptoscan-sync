/* The state machine register on screen: honest vocabulary, honest empties.
 * Multi-match discipline: state ids repeat across machines, so queries target
 * unique invariant wording or use getAllBy. */
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "../test/render";
import stateMachinesJson from "../lib/stateMachines.json";
import StateMachines from "./StateMachines";

describe("State machines explorer", () => {
  it("states the register's rules up front", () => {
    renderWithProviders(<StateMachines />);
    expect(screen.getByRole("heading", { name: "State machines" })).toBeInTheDocument();
    expect(screen.getByTitle(/observed from code, never invented/)).toBeInTheDocument();
    expect(screen.getByText(/unknown is never zero/)).toBeInTheDocument();
    expect(screen.getByText(/Capability is never usage/)).toBeInTheDocument();
  });

  it("draws the class legend with the honest meanings", () => {
    renderWithProviders(<StateMachines />);
    expect(screen.getByTitle(/NEVER means used/)).toBeInTheDocument();
    expect(screen.getByTitle(/NEVER zero, never clean/)).toBeInTheDocument();
    expect(screen.getByTitle(/undeclared state must never render as a pass/)).toBeInTheDocument();
  });

  it("shows the scan lifecycle with its observed edges and its invariant", async () => {
    renderWithProviders(<StateMachines />);
    await userEvent.click(screen.getByRole("tab", { name: "Collection & scans" }));
    expect(screen.getByText("Scan lifecycle")).toBeInTheDocument();
    expect(screen.getByText(/never evidence that the estate is clean/)).toBeInTheDocument();
    expect(screen.getAllByText("QUEUED").length).toBeGreaterThan(0);
    expect(screen.getAllByText("QUEUED → RUNNING").length).toBe(1);
  });

  it("capability never gains an edge into usage — the register draws it that way", async () => {
    renderWithProviders(<StateMachines />);
    await userEvent.click(screen.getByRole("tab", { name: "Evidence & honesty" }));
    expect(screen.getByText("Capability never promotes to usage.")).toBeInTheDocument();
    expect(screen.getAllByText("runtime_confirmed").length).toBeGreaterThan(0);
    expect(screen.queryByText("capability_only → runtime_confirmed")).not.toBeInTheDocument();
  });

  it("a machine whose vocabulary is not observed says so instead of inventing states", async () => {
    renderWithProviders(<StateMachines />);
    await userEvent.click(screen.getByRole("tab", { name: "Findings & remediation" }));
    const notices = screen.getAllByText(/Vocabulary not yet observed — states are never guessed/);
    expect(notices.length).toBeGreaterThan(0);
    expect(screen.getByText("Drift verification")).toBeInTheDocument();
  });

  it("every domain tab renders its machines without error", async () => {
    renderWithProviders(<StateMachines />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.length).toBeGreaterThanOrEqual(12);
    for (const tab of tabs) {
      await userEvent.click(tab);
      const status = screen.getByText(/machine(s)? in this domain/);
      expect(status).toBeInTheDocument();
    }
  });

  it("counts are echoed from the register, never invented", () => {
    renderWithProviders(<StateMachines />);
    const summary = screen.getByText(/Total: \d+ machines across \d+ domains\./);
    const register = stateMachinesJson as { machines: Array<{ domain: string }> };
    const domains = new Set(register.machines.map((m) => m.domain)).size;
    expect(summary.textContent).toContain(
      `Total: ${register.machines.length} machines across ${domains} domains.`,
    );
  });

  it("the unobserved note is scoped to machines that carry no states", async () => {
    renderWithProviders(<StateMachines />);
    await userEvent.click(screen.getByRole("tab", { name: "Session & reads" }));
    // the session machines all carry states — no invented-state notice here
    expect(screen.queryByText(/Vocabulary not yet observed/)).not.toBeInTheDocument();
    expect(screen.getByText("Tenant resolution")).toBeInTheDocument();
    expect(screen.getByText("A tenant is resolved or it is not: there is no guessed tenant.")).toBeInTheDocument();
  });
});
