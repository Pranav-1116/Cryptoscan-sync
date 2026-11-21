import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import MigrationSimulationPanel from "./MigrationSimulationPanel";
// produced by agility.migration_simulation on the backend test estate
// (services/agility/tests/test_migration_simulation.py::_estate, RSA → ML-KEM-768)
import scenario from "../test/fixtures/migrationSimulation.json";

const SIMULATE = "/api/v1/digital-twin/simulate";

describe("migration simulation panel", () => {
  it("asks nothing until the operator simulates", () => {
    const fetchSpy = mockFetch({ [SIMULATE]: scenario });
    renderWithProviders(<MigrationSimulationPanel />);
    expect(screen.getByLabelText("Current algorithm")).toHaveValue("RSA");
    expect(screen.getByLabelText("Target algorithm")).toHaveValue("ML-KEM-768");
    expect(fetchSpy.mock.calls.some(([url]) => String(url).includes(SIMULATE))).toBe(false);
  });

  it("runs the twin's algorithm_migration scenario and shows strategy, plan, problems and impact", async () => {
    const fetchSpy = mockFetch({ [SIMULATE]: scenario });
    renderWithProviders(<MigrationSimulationPanel />);
    fireEvent.change(screen.getByLabelText("Only these systems"), { target: { value: "Payments" } });
    fireEvent.click(screen.getByRole("button", { name: "Simulate migration" }));

    const result = await screen.findByLabelText("Migration simulation result");
    const call = fetchSpy.mock.calls.find(([url]) => String(url).includes(SIMULATE));
    const sent = JSON.parse(String(call?.[1]?.body));
    expect(sent).toEqual({ scenario: "algorithm_migration",
                           params: { from_algo: "RSA", to_algo: "ML-KEM-768", systems: "Payments" } });

    // the verdict, with its reasons
    expect(within(result).getByText("BLOCKED — CLEAR PREREQUISITES FIRST")).toBeInTheDocument();
    expect(within(result).getByText(/hardware cannot run target · 1/)).toBeInTheDocument();
    expect(within(result).getByText("HYBRID_KEY_EXCHANGE")).toBeInTheDocument();
    // the plan starts with what blocks it and ends by retiring the old algorithm
    const plan = within(result).getByRole("list", { name: "Migration plan" });
    const steps = within(plan).getAllByRole("listitem").filter((li) => li.parentElement === plan);
    expect(within(steps[0]).getByText("PREREQUISITES")).toBeInTheDocument();
    expect(within(steps[steps.length - 1]).getByText("RETIRE OLD")).toBeInTheDocument();
    // problems name who acts and what to do
    const problems = within(result).getByRole("table", { name: "Migration problems" });
    expect(within(problems).getByText("HSM hsm-1 cannot run ML-KEM-768")).toBeInTheDocument();
    expect(within(problems).getByText("Acme Switch has no ML-KEM-768 support on record")).toBeInTheDocument();
    // impact on vendors and on systems outside the change
    const vendors = within(result).getByRole("table", { name: "Vendor impact" });
    expect(within(vendors).getByText("Acme Switch")).toBeInTheDocument();
    expect(within(vendors).getByText("NOT READY")).toBeInTheDocument();
    const connected = within(result).getByRole("table", { name: "Connected system impact" });
    expect(within(connected).getByText("Ledger")).toBeInTheDocument();
    expect(within(connected).getByText("OUTSIDE CHANGE")).toBeInTheDocument();
    // and what the twin could not see
    expect(within(result).getByText("WHAT THE TWIN COULD NOT SEE")).toBeInTheDocument();
  });

  it("offers the scenario form's from/to and the estate's own algorithms", () => {
    mockFetch({});
    renderWithProviders(<MigrationSimulationPanel algorithms={["AES", "RSA"]} suggested={{ from: "AES", to: "ML-KEM" }} />);
    fireEvent.click(screen.getByRole("button", { name: "Use AES → ML-KEM" }));
    expect(screen.getByLabelText("Current algorithm")).toHaveValue("AES");
    expect(screen.getByLabelText("Target algorithm")).toHaveValue("ML-KEM");
    fireEvent.click(screen.getByRole("button", { name: "RSA → ML-DSA-65" }));
    expect(screen.getByLabelText("Target algorithm")).toHaveValue("ML-DSA-65");
    expect(screen.getByRole("button", { name: "from AES" })).toBeInTheDocument();
  });

  it("says so when the backend returns no migration answer", async () => {
    mockFetch({ [SIMULATE]: { scenario: "algorithm_migration", affected: {}, impact: {} } });
    renderWithProviders(<MigrationSimulationPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Simulate migration" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/no migration answer/);
  });
});
