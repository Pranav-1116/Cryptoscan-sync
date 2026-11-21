/* Migration what-if: the go / no-go answer, read from the same live estate graph and the
 * same engine as the Simulation page. */
import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import WhatIf from "./WhatIf";
// produced by agility.bom_migration_impact on the Meridian-shaped estate graph
import fixtures from "../test/fixtures/twinBomImpact.json";

const URL = "/api/v1/estate/evidence/simulation/twin-boms";

function backend() {
  return mockFetch({
    [URL]: (_url: string, init?: RequestInit) => {
      if (init?.method !== "POST") return fixtures.inventory;
      const body = JSON.parse(String(init.body));
      return String(body.from_algo).startsWith("3DES") ? fixtures.tdes_to_aes : fixtures.rsa_to_mlkem;
    },
  });
}
const posts = (spy: ReturnType<typeof mockFetch>) =>
  spy.mock.calls.filter(([url, init]) => String(url).includes(URL) && (init as RequestInit | undefined)?.method === "POST");

describe("Migration what-if", () => {
  it("offers the algorithms the estate holds and asks nothing until checked", async () => {
    const spy = backend();
    renderWithProviders(<WhatIf />);
    expect(await screen.findByRole("button", { name: "Use 3DES-112" })).toBeInTheDocument();
    expect(screen.getByLabelText("Current algorithm")).toHaveValue("RSA");
    expect(screen.getByLabelText("Target algorithm")).toHaveValue("ML-KEM-768");
    // no hard-coded fixed answers before a check
    expect(screen.queryByLabelText("Feasibility verdict")).toBeNull();
    expect(posts(spy)).toHaveLength(0);
  });

  it("checks RSA → ML-KEM-768 against the estate: verdict, checks and plan", async () => {
    const spy = backend();
    renderWithProviders(<WhatIf />);
    fireEvent.click(await screen.findByRole("button", { name: "Check feasibility" }));
    const verdict = await screen.findByLabelText("Feasibility verdict");
    expect(JSON.parse(String((posts(spy)[0][1] as RequestInit).body))).toEqual({ from_algo: "RSA", to_algo: "ML-KEM-768" });
    expect(within(verdict).getByText("FEASIBLE — PARALLEL RUN")).toBeInTheDocument();
    // libraries: OpenSSL 3.3.2 lacks ML-KEM, from its own capability evidence
    const libs = screen.getByLabelText("Check Crypto libraries");
    expect(within(libs).getByText("action needed")).toBeInTheDocument();
    expect(within(libs).getByText("OpenSSL 3.3.2")).toBeInTheDocument();
    // the certificate and its CA must be reissued / issue the target
    expect(within(screen.getByLabelText("Check Certificates & CAs")).getByText("swift-gateway.bank.sandbox")).toBeInTheDocument();
    // connections touched by the change are named
    expect(within(screen.getByLabelText("Check Connected systems")).getByText("SWIFT Gateway → Core Banking")).toBeInTheDocument();
    // the plan comes from the engine, providers first, ending with retiring the old algorithm
    const plan = screen.getByRole("list", { name: "Migration plan" });
    expect(within(plan).getByText("Retire RSA")).toBeInTheDocument();
    // the full answer is one click away, with the change carried over
    expect(screen.getByRole("link", { name: /See every component/ })).toHaveAttribute("href", "/simulation?from=RSA&to=ML-KEM-768");
  });

  it("a payment-HSM key with unknown capability is unknown, never ready", async () => {
    backend();
    renderWithProviders(<WhatIf />);
    fireEvent.click(await screen.findByRole("button", { name: "Use 3DES-112" }));
    expect(screen.getByLabelText("Target algorithm")).toHaveValue("AES-256-GCM");
    fireEvent.click(screen.getByRole("button", { name: "Check feasibility" }));
    await screen.findByLabelText("Feasibility verdict");
    const hsm = screen.getByLabelText("Check HSMs & key stores");
    expect(within(hsm).getByText("unknown")).toBeInTheDocument();
    expect(within(hsm).getByText("payShield-10K-sim")).toBeInTheDocument();
  });

  it("says when there is no estate instead of showing a verdict", async () => {
    mockFetch({});
    renderWithProviders(<WhatIf />);
    expect(await screen.findByText("No estate to check against")).toBeInTheDocument();
  });
});
