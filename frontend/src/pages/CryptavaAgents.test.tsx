import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { renderWithProviders } from "../test/render";
import { mockFetch } from "../test/setup";
import { rendersAnHonestEmptyState } from "../test/pageSmoke";
import CryptavaAgents, { agentState, ago, planeOf, installCommand, HOW_COLLECTED, BOMS } from "./CryptavaAgents";

const NOW = Date.parse("2026-11-18T12:00:00Z");
const iso = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString();

const PLANES = [
  { plane: "HBOM · hardware", status: "PARTIAL", reason: "no DMI tables",
    sources: [
      { source: "/sys/class/dmi/id", reads: "platform vendor, model, serial, UUID, BIOS", state: "ABSENT" },
      { source: "/etc/cryptava/asset-record.json", reads: "hardware record", state: "NOT_CONFIGURED", note: "supply it from the CMDB" },
      { source: "/proc/cpuinfo", reads: "CPU model, vendor, cores, crypto extensions", state: "READ", found: 8 },
    ] },
  { plane: "SBOM · software", status: "COMPLETE", reason: "283 packages from dpkg" },
  { plane: "CBOM · cryptography", status: "COMPLETE", reason: "5 crypto libraries" },
  { plane: "NBOM · network", status: "COMPLETE", reason: "8 listeners" },
  { plane: "VBOM · vendors", status: "PARTIAL", reason: "import contracts from the CMDB" },
  { plane: "TechBOM · topology", status: "COMPLETE", reason: "39 technology assets" },
];

function fleet() {
  return {
    "/api/v1/control/agents": {
      agents: [
        { id: "a1", name: "mrdn-sbx-dc1-swiftgw01", status: "connected", version: "1.0.0",
          last_seen: iso(20), last_seen_ip: "10.210.0.4", cert_serial: "ed25519:be51882ec4057215",
          config: { identity: { hostname: "swift-gateway" } } },
        { id: "a2", name: "mrdn-sbx-dc1-coredb01", status: "connected", version: "1.0.0", last_seen: iso(900) },
        { id: "a3", name: "mrdn-sbx-dc1-new01", status: "enrolled", last_seen: null },
      ],
    },
    "/api/v1/ingestion/contributors": {
      contributors: [
        { contributor: "mrdn-sbx-dc1-swiftgw01", assets: 339, evidence: 370, relationships: 361,
          asset_types: { PACKAGE: 283, CERTIFICATE: 1 }, planes: PLANES, authenticity: "VALID",
          received_at: iso(120) },
      ],
    },
  };
}

describe("agent state", () => {
  it("is online only with a heartbeat in the last three minutes", () => {
    expect(agentState({ status: "connected", last_seen: new Date(NOW - 60_000).toISOString() }, NOW)).toBe("online");
    expect(agentState({ status: "connected", last_seen: new Date(NOW - 240_000).toISOString() }, NOW)).toBe("offline");
    expect(agentState({ status: "enrolled", last_seen: null }, NOW)).toBe("waiting");
    expect(agentState({ status: "retired", last_seen: new Date(NOW).toISOString() }, NOW)).toBe("retired");
  });

  it("reads planes by BOM name and prints relative times", () => {
    expect(planeOf(PLANES, "TechBOM")?.status).toBe("COMPLETE");
    expect(planeOf(PLANES, "HBOM")?.reason).toBe("no DMI tables");
    expect(ago(null, NOW)).toBe("never");
    expect(ago(new Date(NOW - 125_000).toISOString(), NOW)).toBe("2 min ago");
  });
});

describe("Cryptava agents page", () => {
  it("mounts against an empty API and says how to start agents", async () => {
    await rendersAnHonestEmptyState(CryptavaAgents);
    expect(screen.getByText("No agents yet.")).toBeInTheDocument();
    expect(screen.getByText("bash sandbox/run_sandbox.sh agents")).toBeInTheDocument();
  });

  it("lists the fleet with status, report check and counts", async () => {
    mockFetch(fleet());
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    const row = (await screen.findByText("mrdn-sbx-dc1-swiftgw01")).closest("tr")!;
    expect(within(row).getByText("online")).toBeInTheDocument();
    expect(within(row).getByText("verified")).toBeInTheDocument();
    expect(within(row).getByText("339")).toBeInTheDocument();
    const stale = screen.getByText("mrdn-sbx-dc1-coredb01").closest("tr")!;
    expect(within(stale).getByText("offline")).toBeInTheDocument();
    expect(within(stale).getByText("no report yet")).toBeInTheDocument();
    const fresh = screen.getByText("mrdn-sbx-dc1-new01").closest("tr")!;
    expect(within(fresh).getByText("waiting")).toBeInTheDocument();
  });

  it("opens an agent's last report: six BOMs with status, reason and a link", async () => {
    mockFetch(fleet());
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    fireEvent.click(await screen.findByText("mrdn-sbx-dc1-swiftgw01"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("signature verified")).toBeInTheDocument();
    for (const bom of ["HBOM", "SBOM", "CBOM", "NBOM", "VBOM", "TechBOM"]) {
      expect(within(dialog).getByText(bom)).toBeInTheDocument();
    }
    expect(within(dialog).getByText("import contracts from the CMDB")).toBeInTheDocument();
    expect(within(dialog).getByText("swift-gateway")).toBeInTheDocument();
    const links = within(dialog).getAllByRole("link", { name: "open" }).map((a) => a.getAttribute("href"));
    expect(links).toEqual(["/hbom", "/sbom", "/cbom", "/nbom", "/vbom", "/live-asset-intelligence"]);
  });

  it("enrols a server and shows the install command once", async () => {
    const routes: Record<string, unknown> = {
      ...fleet(),
      "/api/v1/control/agents/enroll": (_url: string, init?: RequestInit) => {
        expect(JSON.parse(String(init?.body)).name).toBe("mrdn-prod-dc1-ibank02");
        return { agent_id: "a9", name: "mrdn-prod-dc1-ibank02", enrollment_token: "tok-123456789012345678" };
      },
    };
    mockFetch(routes);
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    fireEvent.change(await screen.findByLabelText("agent name"), { target: { value: "mrdn-prod-dc1-ibank02" } });
    fireEvent.click(screen.getByRole("button", { name: "enrol" }));
    await waitFor(() => expect(screen.getByText(/--agent-id a9 --token tok-123456789012345678/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "done" }));
    expect(screen.queryByText(/tok-123456789012345678/)).toBeNull();
  });

  it("explains a taken name instead of failing silently", async () => {
    mockFetch({
      ...fleet(),
      "/api/v1/control/agents/enroll": () => new Response(JSON.stringify({
        detail: { error: "agent_name_taken", message: "An agent named 'x' already exists." },
      }), { status: 409 }),
    });
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    fireEvent.change(await screen.findByLabelText("agent name"), { target: { value: "mrdn-sbx-dc1-swiftgw01" } });
    fireEvent.click(screen.getByRole("button", { name: "enrol" }));
    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
  });
});

describe("how the BOMs are collected", () => {
  it("documents all six BOMs", () => {
    expect(BOMS.map((b) => b.key).every((k) => HOW_COLLECTED[k]?.reads && HOW_COLLECTED[k]?.complete)).toBe(true);
    expect(HOW_COLLECTED.HBOM.supplied).toMatch(/asset register/i);
    expect(HOW_COLLECTED.VBOM.supplied).toMatch(/contracts/i);
  });

  it("shows every source an agent read for a BOM, with what came back", async () => {
    mockFetch(fleet());
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    fireEvent.click(await screen.findByText("mrdn-sbx-dc1-swiftgw01"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByText("how it was collected · 3 sources"));
    expect(within(dialog).getByText("/sys/class/dmi/id")).toBeInTheDocument();
    expect(within(dialog).getByText("not on host")).toBeInTheDocument();
    expect(within(dialog).getByText("not supplied")).toBeInTheDocument();
    expect(within(dialog).getByText("read")).toBeInTheDocument();
    expect(within(dialog).getByText(/supply it from the CMDB/)).toBeInTheDocument();
  });

  it("has a reference table on the page", async () => {
    mockFetch(fleet());
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    expect(await screen.findByText("How each BOM is collected")).toBeInTheDocument();
    expect(screen.getByText(HOW_COLLECTED.VBOM.complete)).toBeInTheDocument();
  });
});

describe("install targets", () => {
  const issued = { agent_id: "a9", enrollment_token: "tok-1" };

  it("builds the command for each place an agent can run", () => {
    expect(installCommand("linux", issued, "https://cs.bank")).toBe("sudo ./install.sh --server https://cs.bank --agent-id a9 --token tok-1");
    expect(installCommand("sandbox", issued, "https://cs.bank", "hsm-sim")).toBe("bash sandbox/run_sandbox.sh agents add hsm-sim a9 tok-1");
    expect(installCommand("container", issued, "https://cs.bank")).toContain("CRYPTAVA_ENROLLMENT_TOKEN=tok-1");
  });

  it("configures a sandbox bank server from Add a server", async () => {
    mockFetch({
      ...fleet(),
      "/api/v1/control/agents/enroll": () => ({ agent_id: "a9", name: "mrdn-sbx-dc1-mobileapi01", enrollment_token: "tok-999" }),
    });
    await act(async () => { renderWithProviders(<CryptavaAgents />); });
    fireEvent.change(await screen.findByLabelText("agent name"), { target: { value: "mrdn-sbx-dc1-mobileapi01" } });
    fireEvent.click(screen.getByRole("button", { name: "enrol" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Sandbox bank server" }));
    expect(screen.getByText("bash sandbox/run_sandbox.sh agents add mobile-api a9 tok-999")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("sandbox bank server"), { target: { value: "legacy-branch" } });
    expect(screen.getByText("bash sandbox/run_sandbox.sh agents add legacy-branch a9 tok-999")).toBeInTheDocument();
  });
});
