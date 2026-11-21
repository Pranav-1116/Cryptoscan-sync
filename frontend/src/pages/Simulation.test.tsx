/* The Simulation page: the Digital Twin's six BOMs, the migration impact over every layer,
 * and the effect of the change on each system-to-system connection. */
import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import Simulation from "./Simulation";
// produced by agility.bom_migration_impact on the Meridian-shaped estate graph
// (services/agility/tests/test_bom_migration_impact.py): inventory, RSA → ML-KEM-768, 3DES → AES-256
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

describe("Simulation — Digital Twin BOMs and migration impact", () => {
  it("shows every BOM and every system of the twin before anything is simulated", async () => {
    const spy = backend();
    renderWithProviders(<Simulation />);
    expect(await screen.findByRole("heading", { name: "Migration simulation" })).toBeInTheDocument();
    const tabs = await screen.findByRole("tablist", { name: "Bills of materials" });
    const names = within(tabs).getAllByRole("tab").map((t) => t.textContent ?? "");
    expect(names.map((n) => n.split(" ")[0])).toEqual(["CBOM", "NBOM", "SBOM", "HBOM", "VBOM", "Tech"]);
    // the systems with their per-BOM make-up and their connections
    const swift = screen.getByRole("button", { name: "System SWIFT Gateway" });
    expect(within(swift).getByText(/calls → Core Banking, Payment HSM/)).toBeInTheDocument();
    // the CBOM lists certificates with the systems they belong to; no statuses yet
    const cbom = screen.getByRole("table", { name: "CBOM components" });
    expect(within(cbom).getAllByText("swift-gateway.bank.sandbox").length).toBeGreaterThan(0);
    expect(within(cbom).queryByText("Affected")).toBeNull();
    // the connections are drawn and listed
    expect(screen.getByRole("img", { name: "System connection map" })).toBeInTheDocument();
    expect(within(screen.getByLabelText("Connection effects")).getAllByText("SWIFT Gateway").length).toBeGreaterThan(0);
    expect(posts(spy)).toHaveLength(0);
  });

  it("runs a migration and files issues, causes and actions under each BOM", async () => {
    const spy = backend();
    renderWithProviders(<Simulation />);
    await screen.findByRole("tablist", { name: "Bills of materials" });
    fireEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    const summary = await screen.findByLabelText("Migration result");
    expect(JSON.parse(String((posts(spy)[0][1] as RequestInit).body))).toEqual({ from_algo: "RSA", to_algo: "ML-KEM-768" });
    expect(within(summary).getByText("Parallel run")).toBeInTheDocument();

    // CBOM: the certificate is affected, with the reason and the action
    const cbom = screen.getByRole("table", { name: "CBOM components" });
    expect(within(cbom).getAllByText("Affected").length).toBeGreaterThan(0);
    expect(within(cbom).getAllByText(/reissue with a ML-KEM-768 key/).length).toBeGreaterThan(0);
    expect(within(screen.getByLabelText("CBOM issues")).getAllByText(/ML-KEM-768/).length).toBeGreaterThan(0);

    // SBOM: OpenSSL does not implement the target; the issue says why and what to do
    fireEvent.click(screen.getByRole("tab", { name: /^SBOM/ }));
    const sbomIssues = await screen.findByLabelText("SBOM issues");
    expect(within(sbomIssues).getByText("library OpenSSL 3.3.2 does not implement ML-KEM-768")).toBeInTheDocument();
    expect(within(sbomIssues).getAllByText("CAUSE").length).toBeGreaterThan(0);
    expect(within(sbomIssues).getAllByText("WHAT TO DO").length).toBeGreaterThan(0);

    // NBOM: the TLS 1.0 endpoint and the clients the twin cannot see
    fireEvent.click(screen.getByRole("tab", { name: /^NBOM/ }));
    const nbom = await screen.findByRole("table", { name: "NBOM components" });
    expect(within(nbom).getByText(/key exchange needs TLS 1.3/)).toBeInTheDocument();

    // VBOM: declared, not observed
    fireEvent.click(screen.getByRole("tab", { name: /^VBOM/ }));
    const vbom = await screen.findByRole("table", { name: "VBOM components" });
    expect(within(vbom).getAllByText(/declared, not observed/).length).toBeGreaterThan(0);
  });

  it("shows which side of each connection changes and what happens to the other", async () => {
    backend();
    renderWithProviders(<Simulation />);
    await screen.findByRole("tablist", { name: "Bills of materials" });
    fireEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    await screen.findByLabelText("Migration result");
    const effects = screen.getByLabelText("Connection effects");
    expect(within(effects).getAllByText("Caller changes").length).toBeGreaterThan(0);
    expect(within(effects).getAllByText("EFFECT ON CORE BANKING").length).toBeGreaterThan(0);
    expect(within(effects).getAllByText(/keep RSA enabled on SWIFT Gateway's connection to Core Banking/).length).toBeGreaterThan(0);
    const ripple = screen.getByLabelText("Ripple through connections");
    expect(within(ripple).getByText("Core Banking")).toBeInTheDocument();
  });

  it("scopes the change to chosen systems and filters the BOMs by system", async () => {
    const spy = backend();
    renderWithProviders(<Simulation />);
    await screen.findByRole("tablist", { name: "Bills of materials" });
    fireEvent.click(screen.getByRole("button", { name: "From 3DES-112" }));
    fireEvent.change(screen.getByLabelText("Migrate to"), { target: { value: "AES-256" } });
    fireEvent.click(screen.getByRole("button", { name: "Payment HSM", pressed: false }));
    fireEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    await screen.findByLabelText("Migration result");
    expect(JSON.parse(String((posts(spy)[0][1] as RequestInit).body)))
      .toEqual({ from_algo: "3DES-112", to_algo: "AES-256", systems: ["Payment HSM"] });
    const effects = screen.getByLabelText("Connection effects");
    expect(within(effects).getAllByText("Provider changes").length).toBeGreaterThan(0);

    // selecting a system narrows the BOM tables to its components
    fireEvent.click(screen.getByRole("tab", { name: /^Tech BOM/ }));
    fireEvent.click(screen.getByRole("button", { name: "System Payment HSM" }));
    const tech = await screen.findByRole("table", { name: "Tech BOM components" });
    await waitFor(() => expect(within(tech).queryByText("SWIFT Gateway")).toBeNull());
    expect(within(tech).getByText("payShield-10K-sim")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear system filter" }));
    expect(within(screen.getByRole("table", { name: "Tech BOM components" })).getAllByText("SWIFT Gateway").length).toBeGreaterThan(0);
  });

  it("says when there is no estate to read instead of drawing empty BOMs", async () => {
    mockFetch({});
    renderWithProviders(<Simulation />);
    expect(await screen.findByText("No twin to simulate against")).toBeInTheDocument();
    expect(screen.queryByRole("tablist", { name: "Bills of materials" })).toBeNull();
  });
});
