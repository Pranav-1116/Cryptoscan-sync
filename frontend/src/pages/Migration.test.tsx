/* PQC migration plan — waves in dependency order, read from the agents' estate graph. */
import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Migration from "./Migration";
import fixtures from "../test/fixtures/estateRemediation.json";

const WAVES = "/api/v1/estate/evidence/remediation/waves";

describe("PQC migration plan", () => {
  it("puts the payment HSM before the SWIFT gateway that calls it", async () => {
    mockFetch({ [WAVES]: fixtures.waves });
    renderWithProviders(<Migration />);
    const waves = await screen.findByLabelText("Migration waves");
    const hsm = within(waves).getByLabelText("System Payment HSM");
    const swift = within(waves).getByLabelText("System SWIFT Gateway");
    expect(hsm.compareDocumentPosition(swift) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(swift).getByText(/waits for Payment HSM/)).toBeInTheDocument();
    expect(within(within(swift).getByRole("list", { name: "What moves in SWIFT Gateway" })).getByText("RSA")).toBeInTheDocument();
    // Core Banking holds no weak crypto: it is listed as needing no migration, not placed in a wave
    expect(within(waves).queryByLabelText("System Core Banking")).toBeNull();
    expect(screen.getByText("No migration needed")).toBeInTheDocument();
  });

  it("links each workstream to the simulation and to task planning", async () => {
    mockFetch({ [WAVES]: fixtures.waves });
    renderWithProviders(<Migration />);
    const table = await screen.findByRole("table", { name: "Migration workstreams" });
    expect(within(table).getByRole("link", { name: "Simulate RSA to ML-KEM-768" })).toHaveAttribute("href", "/simulation?from=RSA&to=ML-KEM-768");
    expect(within(table).getByRole("link", { name: "Plan tasks for RSA to ML-KEM-768" })).toHaveAttribute("href", "/remediation?from=RSA&to=ML-KEM-768");
    expect(screen.getByLabelText("Systems to migrate")).toHaveTextContent("3");
  });

  it("says there is no estate yet", async () => {
    mockFetch({});
    renderWithProviders(<Migration />);
    expect(await screen.findByText("No estate yet")).toBeInTheDocument();
  });
});
